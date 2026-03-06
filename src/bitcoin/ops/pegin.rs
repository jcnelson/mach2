// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::{HashSet, HashMap};

use stacks_common::deps_common::bitcoin::blockdata::block::{Block, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as btc_opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Instruction, Script, Builder, read_scriptint};
use stacks_common::deps_common::bitcoin::blockdata::transaction::{TxIn, TxOut, OutPoint, Transaction};
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey, MessageSignature};
use stacks_common::types::PublicKey;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::DoubleSha256;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::to_hex;

use crate::bitcoin::blocks::BitcoinHashExtensions;
use crate::bitcoin::signer::BitcoinOpSigner;
use crate::bitcoin::wallet::{UTXO, UTXOSet, DUST_UTXO_LIMIT};

use crate::contracts::{execute_in_witness_contract, execute_in_scbtc_contract};

use crate::bitcoin::ops::TransactionExtensions;

use crate::bitcoin::ops::Error;

pub struct OpPegIn {
    locktime: u32,
    safety_margin: u32,
    user_pubkey: Secp256k1PublicKey,
    user_signature_witness: Vec<u8>,    // one user signature for now
    cosigner_pubkeys: Vec<Secp256k1PublicKey>,
    cosigner_signature_witness: Vec<Vec<u8>>,
    provider: StacksAddress,
    amount: u64,
    signature_hashes: HashMap<usize, Sha256dHash>
}

impl OpPegIn {
    pub fn new(locktime: u32, safety_margin: u32, user_pubkey: &Secp256k1PublicKey, cosigner_pubkeys: &[Secp256k1PublicKey], provider: StacksAddress, amount: u64) -> Self {
        Self {
            locktime,
            safety_margin,
            user_pubkey: user_pubkey.clone(),
            user_signature_witness: vec![],
            cosigner_pubkeys: cosigner_pubkeys.to_vec(),
            cosigner_signature_witness: vec![],
            provider,
            amount,
            signature_hashes: HashMap::new(),
        }
    }

    pub fn make_initial_witness_stack(witness_script: &Script) -> Vec<Script> {
        let mut scripts = vec![];
        scripts.push(Script::from(vec![]));
        scripts.push(witness_script.clone());
        scripts
    }

    pub fn make_witness_script(&self) -> Result<Script, Error> {
        let recipient_principal = self.provider.to_string();
        let user_pubkey_hex = self.user_pubkey.to_hex();
        let locktime = self.locktime;
        let safety_margin = self.safety_margin;

        let cosigner_keys_hex : Vec<_> = self.cosigner_pubkeys.iter()
            .map(|pubk| format!("0x{}", &pubk.to_hex()))
            .collect();

        let cosigner_keys_list = format!("(list {})", &cosigner_keys_hex.join(" "));

        let witness_tuple = format!(
        r#"{{
            recipient-principal: '{recipient_principal},
            user-pubkey: 0x{user_pubkey_hex},
            locktime: u{locktime},
            safety-margin: u{safety_margin}
        }}"#);

        let cosigner_program = format!("(make-cosigner-multisig-script {cosigner_keys_list})");
        let cosigner_dag_script_value = execute_in_witness_contract(&cosigner_program)
            .map_err(|e| Error::EvalFailed(format!("Failed to run Clarity program '{cosigner_program}': {e:?}")))?
            .ok_or_else(|| Error::EvalFailed(format!("Clarity program did not complete: '{cosigner_program}'")))?;
                
        let cosigner_dag_buff = cosigner_dag_script_value
            .expect_buff(1376)
            .map_err(|e| Error::WrongType(format!("Failed to get (buff 1376): {e:?}")))?;

        let cosigner_dag_buff_hex = to_hex(&cosigner_dag_buff);

        let witness_script_program = format!("(make-pegin-witness-script 0x{cosigner_dag_buff_hex} {witness_tuple})");
        let witness_script_value = execute_in_witness_contract(&witness_script_program)
            .map_err(|e| Error::EvalFailed(format!("Failed to run Clarity program {witness_script_program}: {e:?}")))?
            .ok_or_else(|| Error::EvalFailed(format!("Clarity program did not complete: {witness_script_program}")))?;

        let witness_script_buff_value = witness_script_value
            .expect_result()
            .map_err(|e| Error::WrongType(format!("Did not get response from '{witness_script_program}': {e:?}")))?
            .map_err(|e| Error::WrongType(format!("Did not get (ok witness-script) from '{witness_script_program}': got (err {e:?})")))?;

        let witness_script_buff = witness_script_buff_value
            .expect_buff(1376)
            .map_err(|e| Error::WrongType(format!("Did not get (buff 1376) from '{witness_script_program}': {e:?}")))?;

        Ok(witness_script_buff.into())
    }

    /// Check the signatures we generated in the Clarity VM
    pub fn check_signatures(&self, tx: &Transaction, input_index: usize) -> Result<(), Error> {
        let segwit_sighash = self.signature_hashes.get(&input_index)
            .ok_or(Error::InputNotSigned)?;

        let input = tx.input.get(input_index).ok_or(Error::NoSuchInput)?;
        let witness_list : Vec<_> = input.witness
            .iter()
            .map(|w| format!("0x{}", &to_hex(w)))
            .collect();
        let sighash = format!("0x{}", &to_hex(&segwit_sighash.0));
        let user_pubkey = format!("0x{}", &self.user_pubkey.to_hex());
        let cosigner_dag_keys_list : Vec<_> = self.cosigner_pubkeys
            .iter()
            .map(|cspk| format!("0x{}", &cspk.to_hex()))
            .collect();

        let witness = format!("(list {})", witness_list.join(" "));
        let cosigner_dag_keys = format!("(list {})", &cosigner_dag_keys_list.join(" "));
        let program = format!("(check-signatures {witness} {sighash} {user_pubkey} {cosigner_dag_keys})");
        let result_value = execute_in_scbtc_contract(&program)
            .map_err(|e| Error::EvalFailed(format!("Failed to run Clarity program '{program}': {e:?}")))?
            .ok_or_else(|| Error::EvalFailed(format!("Clarity program did not complete: '{program}'")))?;
        
        let _ = result_value
            .expect_result()
            .map_err(|e| Error::WrongType(format!("Did not get ersponse from '{program}': {e:?}")))
            .map_err(|e| Error::WrongType(format!("Did not get (ok true) from '{program}': got (err {e:?})")))?;

        Ok(())
    }

    pub fn p2wsh_pegin_script_pubkey(&self) -> Result<Script, Error> {
        let prog = self.make_witness_script()?;
        Ok(prog.to_v0_p2wsh())
    }

    /// Make a TxIn which spends a UTXO whose witness program matches the witness script code we'd
    /// generate
    pub fn make_pegin_spend_txin(utxo: &UTXO, witness_script: &Script) -> TxIn {
        let witness : Vec<Vec<u8>> = Self::make_initial_witness_stack(witness_script)
            .into_iter()
            .map(|s| s.to_bytes())
            .collect();

        let input = TxIn {
            previous_output: OutPoint {
                txid: Sha256dHash(utxo.txid.clone().0),
                vout: utxo.vout
            },
            script_sig: Script::new(),
            sequence: 0xfffffffd,   // allow RBF
            witness,
        };
        input
    }

    pub fn user_p2wpkh(&self) -> Script {
        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);
        
        let pubkey_hash = Hash160::from_data(&public_key.to_bytes());

        let pubkey_v0_p2wpkh = Builder::new()
            .push_int(0)
            .push_slice(&pubkey_hash.0)
            .into_script();
        pubkey_v0_p2wpkh
    }

    /// NOTE: this is only really needed for the scBTC CLI client.
    ///
    /// All you really need to do is create a UTXO on the Bitcoin chain that has the p2wsh
    /// output that commits to the pegin witness script.  This function is just for creating a
    /// peg-in transaction from an existing p2wpkh spendable by the user key.
    ///
    /// ------
    /// Create an unsigned peg-in transaction, which consumes some or all of the `utxo_set`.
    /// Spends p2wkh UTXOs that the user can spend.
    ///
    /// Returns Ok((tx, consumed_utxos)) on success
    /// Returns Err(..) on failure
    pub fn make_unsigned_pegin_transaction(
        &self,
        tx_fee: u64,
        utxos_set: &UTXOSet,
    ) -> Result<(Transaction, UTXOSet), Error> {
        let tx_cost = tx_fee + self.amount;
        let user_p2wpkh = self.user_p2wpkh();
        let pegin_p2wsh = self.p2wsh_pegin_script_pubkey()?;
        
        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);

        // select UTXOs until we have enough to cover the cost.
        // This reduces `utxos_set` to only the UTXOs which will be spent.
        let mut total_consumed = 0;
        let mut consumed_utxos = vec![];
        for utxo in utxos_set.utxos.iter() {
            // only consider compatible UTXOs
            if utxo.script_pub_key != user_p2wpkh {
                continue;
            }

            m2_debug!("Consume UTXO {}: {}", &utxo.script_pub_key, utxo.amount);
            total_consumed += utxo.amount;
            consumed_utxos.push(utxo.clone());

            if total_consumed >= tx_cost {
                break;
            }
        }

        if total_consumed < tx_cost {
            // NOTE: this will have pushed all utxos back into utxos_set
            m2_warn!("Consumed total {total_consumed} is less than intended spend: {tx_cost}");
            return Err(Error::InsufficientFunds);
        }

        // Append the change output
        let value = total_consumed - tx_cost;
        m2_debug!(
            "Payments value: {value:?}, total_consumed: {total_consumed:?}, total_spent: {tx_cost:?}"
        );

        let mut tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![
                TxOut {
                    value: self.amount,
                    script_pubkey: pegin_p2wsh.clone(),
                }
            ]
        };
        
        if value >= DUST_UTXO_LIMIT {
            tx.output.push(TxOut {
                value,
                script_pubkey: user_p2wpkh.clone(),
            });
        } else {
            // Instead of leaving that change to the BTC miner, we could / should bump the sortition fee
            m2_debug!("Not enough change to clear dust limit. Not adding change address.");
        }

        for utxo in consumed_utxos.iter() {
            if utxo.script_pub_key != user_p2wpkh {
                // should be unreachable
                return Err(Error::UnsolvableUTXO);
            }
            
            // spending a p2wpkh
            let input = TxIn {
                previous_output: OutPoint {
                    txid: Sha256dHash(utxo.txid.clone().0),
                    vout: utxo.vout,
                },
                script_sig: Script::from(vec![]),
                sequence: 0xFFFFFFFD, // allow RBF
                witness: vec![public_key.to_bytes()]
            };
            tx.input.push(input);
        }

        Ok((tx, UTXOSet { utxos: consumed_utxos }))
    }
   
    /// Create an unsigned peg-in spending transaction.  This transaction, when fully signed, would
    /// spend a set of pegin UTXOs and UTXOs for the user's public key.
    ///
    /// UTXOs in `utxo_set` will be spent to cover the fee.  Only p2wpkh UTXOs for the user's
    /// public key will be considered.  Leave empty if you intend to pay the tx fee with the pegin.
    ///
    /// UTXOs in `pegin_utxos` are pegin UTXOs will be spent if they have p2wsh scriptPubKeys that
    /// commit to this OpPegIn's witness script.
    ///
    /// Returns Ok((tx, consumed_utxos)) on success
    /// Returns Err(..) on error, and leaves `utxos_set` unchanged.
    pub fn make_unsigned_pegin_spend_transaction(
        &self,
        tx_fee: u64,
        utxos_set: &UTXOSet,
        pegin_utxos: &[UTXO],
        recipient_scriptPubKey: Script
    ) -> Result<(Transaction, UTXOSet), Error> {
        let pegin_p2wsh = self.p2wsh_pegin_script_pubkey()?;
        let user_p2wpkh = self.user_p2wpkh();

        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);

        // select UTXOs until we have enough to cover the cost.
        // This reduces `utxos_set` to only the UTXOs which will be spent.
        let mut total_consumed = 0;
        let mut consumed_utxos = vec![];
        for pegin_utxo in pegin_utxos.iter() {
            if pegin_utxo.script_pub_key != pegin_p2wsh {
                m2_debug!("UTXO is not a pegin UTXO ({} != {})", &pegin_utxo.script_pub_key, &pegin_p2wsh);
                continue;
            }
            total_consumed += pegin_utxo.amount;
            consumed_utxos.push(pegin_utxo.clone());
        }

        for utxo in utxos_set.utxos.iter() {
            if utxo.script_pub_key != user_p2wpkh {
                continue;
            }
            total_consumed += utxo.amount;
            consumed_utxos.push(utxo.clone());

            if total_consumed >= tx_fee {
                break;
            }
        }

        if total_consumed < tx_fee {
            m2_warn!("Consumed total {total_consumed} is less than intended fee spend: {tx_fee}");
            return Err(Error::InsufficientFunds);
        }

        // Append the change output
        let value = total_consumed - tx_fee;
        m2_debug!(
            "Payments value: {value:?}, total_consumed: {total_consumed:?}, total_spent: {tx_fee}"
        );

        let mut tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value,
                script_pubkey: recipient_scriptPubKey
            }]
        };

        for utxo in consumed_utxos.iter() {
            let input = if utxo.script_pub_key == pegin_p2wsh {
                // spending a previously-locked peg-in 
                Self::make_pegin_spend_txin(utxo, &self.make_witness_script()?)
            }
            else if utxo.script_pub_key == user_p2wpkh {
                // spending a user p2wpkh
                TxIn {
                    previous_output: OutPoint {
                        txid: Sha256dHash(utxo.txid.clone().0),
                        vout: utxo.vout,
                    },
                    script_sig: Script::from(vec![]),
                    sequence: 0xFFFFFFFD, // allow RBF
                    witness: vec![public_key.to_bytes()]
                }
            }
            else {
                // should be unreachable
                m2_warn!("Unsolvable UTXO: {:?}", &utxo.script_pub_key);
                return Err(Error::UnsolvableUTXO);
            };
            tx.input.push(input);
        }

        Ok((tx, UTXOSet { utxos: consumed_utxos }))
    }

    pub fn is_user_signer(&self, user_signer: &mut BitcoinOpSigner) -> bool {
        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);

        let mut signer_public_key = user_signer.get_public_key();
        signer_public_key.set_compressed(true);

        // sanity check -- this signer must be for this user
        public_key == signer_public_key
    }
    
    /// Sign the pegin spend transaction for the user or cosigner.
    /// Inputs in `utxos_set` can be spending inputs to fund the transaction (i.e. p2wpkh UTXOs
    /// for the user public key), or they can be previous peg-in transactions.
    /// Typically, `utxos_set` is the value returned from
    /// `make_unsigned_pegin_spend_transaction()`.
    fn sign_pegin_spend_transaction(
        &mut self,
        signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction,
        is_cosigner: bool,
        null_cosigner: bool,
    ) -> Result<(), Error> {
        let mut public_key = signer.get_public_key();
        public_key.set_compressed(true);
       
        if !is_cosigner && !self.is_user_signer(signer) {
            return Err(Error::WrongSigner);
        }

        let user_p2wpkh = self.user_p2wpkh();
        let pegin_p2wsh = self.p2wsh_pegin_script_pubkey()?;
        let witness_script = self.make_witness_script()?;

        for (i, utxo) in utxos_set.utxos.iter().enumerate() {
            let sig_hash_all = 0x01;
            let sig_hash_res = if !is_cosigner && utxo.script_pub_key == user_p2wpkh && self.is_user_signer(signer) {
                // spending on-chain p2pwkh UTXO from user
                tx.make_segwit_signature_hash(i, &user_p2wpkh, utxo.amount)
            }
            else if utxo.script_pub_key == pegin_p2wsh && (is_cosigner || self.is_user_signer(signer)) {
                // spending a prior pegin witness script
                if tx.lock_time == 0 {
                    m2_warn!("Cannot spend a pegin UTXO without a positive locktime");
                    return Err(Error::BadLocktime);
                }
                tx.make_segwit_signature_hash(i, &witness_script, utxo.amount)
            }
            else {
                continue;
            };

            let sig_hash = match sig_hash_res {
                Ok(sig_hash) => sig_hash,
                Err(e) => {
                    m2_warn!("Failed to produce segwit sighash: {e:?}");
                    return Err(e);
                }
            };

            let sig1_der = {
                let message = signer
                    .sign_message(sig_hash.as_bytes())?;
                message
                    .to_secp256k1_recoverable()
                    .ok_or(Error::FailedToSign("Failed to recover public key from signature".to_string()))?
                    .to_standard()
                    .serialize_der()
            };

            let mut signed_pegin = false;

            if !is_cosigner && utxo.script_pub_key == user_p2wpkh && self.is_user_signer(signer) {
                // spending on-chain p2wpkh UTXO from user (i.e. which pays a tx fee)
                m2_debug!("User {} signs: {:?}", &public_key.to_hex(), &sig1_der);
                tx.input[i].script_sig = Script::from(vec![]);
                tx.input[i].witness = vec![
                    [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec(),
                    public_key.to_bytes(),
                ];
            }
            else if utxo.script_pub_key == pegin_p2wsh && (is_cosigner || self.is_user_signer(signer)) {
                tx.input[i].script_sig = Script::from(vec![]);

                // spending a pegin
                if tx.lock_time == 0 {
                    m2_warn!("Cannot spend a pegin UTXO without a positive locktime");
                    return Err(Error::BadLocktime);
                }

                // Is the signer the user, or cosigner?
                if is_cosigner {
                    if null_cosigner {
                        // user is reclaiming locked BTC without the cosigner, so push a
                        // segwit-compatible invalid signature
                        m2_debug!("Null cosigner signs");
                        self.cosigner_signature_witness.push(vec![]);
                    }
                    else {
                        // cosigner spends
                        // leading witness stack items are the cosigner threshold
                        m2_debug!("Cosigner {} signs: {:?}", &public_key.to_hex(), &sig1_der);
                        self.cosigner_signature_witness.push([&*sig1_der, &[sig_hash_all as u8]][..].concat().to_vec());
                    }
                    signed_pegin = true;
                }
                else {
                    // user spends
                    // must be the second-to-last item on the stack before the program
                    m2_debug!("User {} signs: {:?}", &public_key.to_hex(), &sig1_der);
                    self.user_signature_witness = [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec();
                    signed_pegin = true;
                }
            }
            else {
                // should be unreachable
                m2_warn!("Could not sign UTXO: {:?}", &utxo);
                return Err(Error::UnsolvableUTXO);
            }

            if signed_pegin {
                // compute new witness stack for pegin witness program
                let mut pegin_witness = vec![];
                pegin_witness.push(vec![]);
                for sig_wit in self.cosigner_signature_witness.iter() {
                    pegin_witness.push(sig_wit.to_vec());
                }
                pegin_witness.push(self.user_signature_witness.clone());
                pegin_witness.push(witness_script.to_bytes());
                tx.input[i].witness = pegin_witness;
            }

            // save sighash
            self.signature_hashes.insert(i, sig_hash);
        }
        Ok(())
    }

    /// sign the transaction for the user.
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_user(
        &mut self,
        user_signer: &mut BitcoinOpSigner,
        utxos_set: &mut UTXOSet,
        tx: &mut Transaction
    ) -> Result<(), Error> {
        if !self.is_user_signer(user_signer) {
            m2_warn!("sign_user: invalid signer");
            return Err(Error::WrongSigner);
        }
        self.sign_pegin_spend_transaction(user_signer, utxos_set, tx, false, false)
    }
    
    /// sign the transaction for the cosigner.
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_cosigner(
        &mut self,
        cosigner_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction
    ) -> Result<(), Error> {
        self.sign_pegin_spend_transaction(cosigner_signer, utxos_set, tx, true, false)
    }
    
    /// sign the transaction for the user as part of fulfilling the clawback condition
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_null_cosigner(
        &mut self,
        noop_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction
    ) -> Result<(), Error> {
        self.sign_pegin_spend_transaction(noop_signer, utxos_set, tx, true, true)
    }

    /// Get the pegin p2wsh UTXOs from a transaction, if any exist
    pub fn get_pegin_utxos(&self, tx: &Transaction, confirmations: u32) -> Result<Vec<UTXO>, Error> {
        let mut ret = vec![];

        let pegin = self.p2wsh_pegin_script_pubkey()?;
        for (i, out) in tx.output.iter().enumerate() {
            if out.script_pubkey == pegin {
                ret.push(UTXO {
                    txid: DoubleSha256(tx.txid().0),
                    vout: i as u32,
                    script_pub_key: pegin.clone(),
                    amount: out.value,
                    confirmations
                })
            }
        }
        Ok(ret)
    }

    /// Reset witness state
    pub fn clear_witness(&mut self) {
        self.user_signature_witness.clear();
        self.cosigner_signature_witness.clear();
    }
}
