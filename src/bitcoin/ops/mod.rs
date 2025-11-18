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

use stacks_common::deps_common::bitcoin::blockdata::block::{Block, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as btc_opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Instruction, Script, Builder};
use stacks_common::deps_common::bitcoin::blockdata::transaction::{TxIn, TxOut, OutPoint, Transaction};
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::util::secp256k1::{Secp256k1PublicKey, MessageSignature};
use stacks_common::types::PublicKey;
use stacks_common::util::hash::DoubleSha256;
use stacks_common::util::hash::Hash160;

use crate::bitcoin::blocks::BitcoinHashExtensions;
use crate::bitcoin::signer::BitcoinOpSigner;
use crate::bitcoin::wallet::{UTXO, UTXOSet, DUST_UTXO_LIMIT};

#[cfg(test)]
pub mod tests;

/// witness stack, from bottom to top:
///
/// <>
/// <cosigner-sig1>
/// <cosigner-sig2>
/// ...
/// <cosigner-sigK>
/// <user-sig>
/// 
/// witness-script:
///
/// <user-pubk> OP_CHECKSIGVERIFY
/// <cosigner-num-sigs> <cosigner-pk1> <cosigner-pk2> ... <cosigner-pkN> <cosigner-num-keys> OP_CHECKMULTISIG
/// OP_IF
///    <M2_PEGIN_MARKER> OP_DROP OP_TRUE
/// OP_ELSE
///    <locktime> OP_CHECKLOCKTIMEVERIFY
/// OP_ENDIF
pub struct M2PegIn {
    locktime: u32,
    spender_pubkey: Secp256k1PublicKey,
    user_pubkey: Secp256k1PublicKey,
    user_signature_witness: Vec<u8>,    // one user signature for now
    cosigner_pubkeys: Vec<Secp256k1PublicKey>,
    cosigner_threshold: u8,
    cosigner_signature_witness: Vec<Vec<u8>>,
    amount: u64
}

// 'mach2-pegin'
pub const M2_PEGIN_MARKER: &'static [u8] = &[109, 97, 99, 104, 50, 45, 112, 101, 103, 105, 110];

pub enum Error {
    NonmatchingUtxo
}

impl M2PegIn {
    pub fn new(locktime: u32, user_pubkey: &Secp256k1PublicKey, cosigner_pubkeys: &[Secp256k1PublicKey], cosigner_threshold: u8, amount: u64) -> Self {
        Self {
            locktime,
            user_pubkey: user_pubkey.clone(),
            user_signature_witness: vec![],
            spender_pubkey: user_pubkey.clone(),
            cosigner_pubkeys: cosigner_pubkeys.to_vec(),
            cosigner_threshold,
            cosigner_signature_witness: vec![],
            amount
        }
    }

    fn with_spender(mut self, pubk: &Secp256k1PublicKey) -> Self {
        self.spender_pubkey = pubk.clone();
        self
    }

    pub fn make_initial_witness_stack(&self) -> Vec<Script> {
        let mut scripts = vec![];
        scripts.push(Script::from(vec![]));
        scripts.push(self.make_witness_script());
        scripts
    }

    pub fn make_witness_script(&self) -> Script {
        let mut builder = Builder::new()
            .push_slice(&self.user_pubkey.to_bytes_compressed())
            .push_opcode(btc_opcodes::OP_CHECKSIGVERIFY)
            .push_int(self.cosigner_threshold.into());

        for pubk in self.cosigner_pubkeys.iter() {
            builder = builder.push_slice(&pubk.to_bytes_compressed());
        }
        builder = builder
            .push_int(self.cosigner_pubkeys.len() as i64)
            .push_opcode(btc_opcodes::OP_CHECKMULTISIG);

        builder
            .push_opcode(btc_opcodes::OP_IF)
            .push_slice(&M2_PEGIN_MARKER)
            .push_opcode(btc_opcodes::OP_DROP)
            .push_opcode(btc_opcodes::OP_PUSHNUM_1)
            .push_opcode(btc_opcodes::OP_ELSE)
            .push_int(self.locktime.into())
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(btc_opcodes::OP_ENDIF)
            .into_script()
    }

    pub fn p2wsh_script_pubkey(&self) -> Script {
        let prog = self.make_witness_script();
        prog.to_v0_p2wsh()
    }

    /// Make a TxIn which spends a UTXO whose witness program matches the witness script code we'd
    /// generate
    pub fn make_pegin_spend_txin(&self, utxo: &UTXO) -> TxIn {
        let mut witness : Vec<Vec<u8>> = self.make_initial_witness_stack().into_iter().map(|s| s.to_bytes()).collect();

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

    pub fn spender_p2wpkh(&self) -> Script {
        let mut public_key = self.spender_pubkey.clone();
        public_key.set_compressed(true);
        
        let pubkey_hash = Hash160::from_data(&public_key.to_bytes());

        let pubkey_v0_p2wpkh = Builder::new()
            .push_int(0)
            .push_slice(&pubkey_hash.0)
            .into_script();
        pubkey_v0_p2wpkh
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

    /// Create an unsigned mach2 peg-in transaction, which consumes some or all of the `utxo_set`.
    /// Spends p2wkh UTXOs that the spender can spend
    ///
    /// Returns Some(tx) on success, and reduces `utxos_set` to the UTXOs which will be consumed
    /// Returns None on error, and leaves `utxos_set` unchanged.
    pub fn make_unsigned_pegin_transaction(
        &self,
        tx_fee: u64,
        utxos_set: &mut UTXOSet,
    ) -> Option<Transaction> {
        let tx_cost = tx_fee + self.amount;
        let spender_p2wpkh = self.spender_p2wpkh();
        let pegin_p2wsh = self.p2wsh_script_pubkey();
        
        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);

        // select UTXOs until we have enough to cover the cost.
        // This reduces `utxos_set` to only the UTXOs which will be spent.
        let mut total_consumed = 0;
        let mut available_utxos = vec![];
        available_utxos.append(&mut utxos_set.utxos);
        for utxo in available_utxos.into_iter() {
            // only consider compatible UTXOs
            if utxo.script_pub_key != spender_p2wpkh {
                continue;
            }

            m2_debug!("Consume UTXO {}: {}", &utxo.script_pub_key, utxo.amount);
            total_consumed += utxo.amount;
            utxos_set.utxos.push(utxo);

            if total_consumed >= tx_cost {
                break;
            }
        }

        if total_consumed < tx_cost {
            // NOTE: this will have pushed all utxos back into utxos_set
            m2_warn!("Consumed total {total_consumed} is less than intended spend: {tx_cost}");
            return None;
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
                script_pubkey: spender_p2wpkh.clone(),
            });
        } else {
            // Instead of leaving that change to the BTC miner, we could / should bump the sortition fee
            m2_debug!("Not enough change to clear dust limit. Not adding change address.");
        }

        for utxo in utxos_set.utxos.iter() {
            if utxo.script_pub_key != spender_p2wpkh {
                continue;
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

        Some(tx)
    }
    
    /// Create an unsigned mach2 peg-in spending transaction, which consumes some or all of the `utxo_set`.
    /// Spends p2wkh UTXOs that the spender can spend, as well as previously mined peg-in UTXOs
    ///
    /// Returns Some(tx) on success, and reduces `utxos_set` to the UTXOs which will be consumed
    /// Returns None on error, and leaves `utxos_set` unchanged.
    pub fn make_unsigned_pegin_spend_transaction(
        &self,
        tx_fee: u64,
        utxos_set: &mut UTXOSet,
        pegin_utxos: &[UTXO],
        relock: bool,
    ) -> Option<Transaction> {
        let tx_cost = if relock {
            tx_fee + self.amount
        }
        else {
            tx_fee
        };
        let spender_p2wpkh = self.spender_p2wpkh();
        let pegin_p2wsh = self.p2wsh_script_pubkey();
        
        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);

        // select UTXOs until we have enough to cover the cost.
        // This reduces `utxos_set` to only the UTXOs which will be spent.
        let mut total_consumed = 0;
        let mut available_utxos = vec![];
        available_utxos.append(&mut utxos_set.utxos);

        for pegin_utxo in pegin_utxos.iter() {
            if pegin_utxo.script_pub_key != pegin_p2wsh {
                m2_debug!("UTXO is not a pegin UTXO ({} != {})", &pegin_utxo.script_pub_key, &pegin_p2wsh);
                return None;
            }
            total_consumed += pegin_utxo.amount;
            utxos_set.utxos.push(pegin_utxo.clone());
        }

        for utxo in available_utxos.into_iter() {
            if utxo.script_pub_key != spender_p2wpkh {
                continue;
            }
            total_consumed += utxo.amount;
            utxos_set.utxos.push(utxo);

            if total_consumed >= tx_cost {
                break;
            }
        }

        if total_consumed < tx_cost {
            // NOTE: this will have pushed all utxos back into utxos_set
            m2_warn!("Consumed total {total_consumed} is less than intended spend: {tx_cost}");
            return None;
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
            output: vec![],
        };

        if relock {
            tx.output.push(TxOut {
                value: self.amount,
                script_pubkey: pegin_p2wsh.clone(),
            });
        }

        if value >= DUST_UTXO_LIMIT {
            tx.output.push(TxOut {
                value,
                script_pubkey: spender_p2wpkh.clone(),
            });
        } else {
            // Instead of leaving that change to the BTC miner, we could / should bump the sortition fee
            m2_debug!("Not enough change to clear dust limit. Not adding change address.");
        }

        for utxo in utxos_set.utxos.iter() {
            let input = if utxo.script_pub_key == pegin_p2wsh {
                // spending a previously-locked peg-in 
                self.make_pegin_spend_txin(utxo)
            }
            else if utxo.script_pub_key == spender_p2wpkh {
                // spending a p2wpkh
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
                return None;
            };
            tx.input.push(input);
        }

        Some(tx)
    }

    pub fn is_user_signer(&self, user_signer: &mut BitcoinOpSigner) -> bool {
        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);

        let mut signer_public_key = user_signer.get_public_key();
        signer_public_key.set_compressed(true);

        // sanity check -- this signer must be for this user
        public_key == signer_public_key
    }
    
    pub fn is_spender_signer(&self, spender_signer: &mut BitcoinOpSigner) -> bool {
        let mut public_key = self.spender_pubkey.clone();
        public_key.set_compressed(true);

        let mut signer_public_key = spender_signer.get_public_key();
        signer_public_key.set_compressed(true);

        // sanity check -- this signer must be for this user
        public_key == signer_public_key
    }

    /// sign the transaction for the user or cosigner.
    /// Inputs in `utxos_set` can be spending inputs to fund the transaction, or they can be
    /// previous peg-in transactions.
    /// If spending a funding UTXO, then `spender_p2wpkh` is Some(..) and matches UTXOs that can fund
    /// this transaction. Otherwise, it's None.
    fn sign_pegin(
        &mut self,
        signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction,
        is_cosigner: bool,
        null_cosigner: bool,
    ) -> bool {
        let mut public_key = signer.get_public_key();
        public_key.set_compressed(true);
        
        let spender_p2wpkh = self.spender_p2wpkh();
        let user_p2wpkh = self.user_p2wpkh();
        let prev_pegin_p2wsh = self.p2wsh_script_pubkey();
        let witness_script = self.make_witness_script();

        for (i, utxo) in utxos_set.utxos.iter().enumerate() {
            let sig_hash_all = 0x01;
            let sig_hash = if !is_cosigner && utxo.script_pub_key == spender_p2wpkh && self.is_spender_signer(signer) {
                // spending p2pwkh UTXO
                tx.segwit_signature_hash(i, &spender_p2wpkh, utxo.amount, sig_hash_all)
            }
            else if !is_cosigner && utxo.script_pub_key == user_p2wpkh && self.is_user_signer(signer) {
                // spending p2pwkh UTXO
                tx.segwit_signature_hash(i, &user_p2wpkh, utxo.amount, sig_hash_all)
            }
            else if utxo.script_pub_key == prev_pegin_p2wsh && (is_cosigner || self.is_user_signer(signer)) {
                // spending the pegin witness script
                tx.segwit_signature_hash(i, &witness_script, utxo.amount, sig_hash_all)
            }
            else {
                continue;
            };

            let sig1_der = {
                let message = signer
                    .sign_message(sig_hash.as_bytes())
                    .expect("Unable to sign message");
                message
                    .to_secp256k1_recoverable()
                    .expect("Unable to get recoverable signature")
                    .to_standard()
                    .serialize_der()
            };

            let mut signed_pegin = false;

            if !is_cosigner && utxo.script_pub_key == spender_p2wpkh && self.is_spender_signer(signer) {
                // spending p2wpkh UTXO
                m2_debug!("Spender {} signs: {}", &public_key.to_hex(), &sig1_der);
                tx.input[i].script_sig = Script::from(vec![]);
                tx.input[i].witness = vec![
                    [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec(),
                    public_key.to_bytes(),
                ];
            }
            else if !is_cosigner && utxo.script_pub_key == user_p2wpkh && self.is_user_signer(signer) {
                // spending p2wpkh UTXO
                m2_debug!("User {} signs: {}", &public_key.to_hex(), &sig1_der);
                tx.input[i].script_sig = Script::from(vec![]);
                tx.input[i].witness = vec![
                    [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec(),
                    public_key.to_bytes(),
                ];
            }
            else if utxo.script_pub_key == prev_pegin_p2wsh && (is_cosigner || self.is_user_signer(signer)) {
                tx.input[i].script_sig = Script::from(vec![]);

                // spending a pegin.  Is the signer the user, or cosigner?
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
                        m2_debug!("Cosigner {} signs: {}", &public_key.to_hex(), &sig1_der);
                        self.cosigner_signature_witness.push([&*sig1_der, &[sig_hash_all as u8]][..].concat().to_vec());
                    }
                    signed_pegin = true;
                }
                else {
                    // user spends
                    // must be the second-to-last item on the stack before the program
                    m2_debug!("User {} signs: {}", &public_key.to_hex(), &sig1_der);
                    self.user_signature_witness = [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec();
                    signed_pegin = true;
                }
            }
            else {
                continue;
            }

            if signed_pegin {
                let mut pegin_witness = vec![];
                pegin_witness.push(vec![]);
                for sig_wit in self.cosigner_signature_witness.iter() {
                    pegin_witness.push(sig_wit.to_vec());
                }
                pegin_witness.push(self.user_signature_witness.clone());
                pegin_witness.push(self.make_witness_script().to_bytes());
                tx.input[i].witness = pegin_witness;
            }
        }
        true
    }

    /// sign the transaction for the user.
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_user(
        &mut self,
        user_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction
    ) -> bool {
        if !self.is_user_signer(user_signer) {
            m2_warn!("sign_user: invalid signer");
            return false;
        }
        self.sign_pegin(user_signer, utxos_set, tx, false, false)
    }
    
    /// sign the transaction for the spender.
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_spender(
        &mut self,
        spender_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction
    ) -> bool {
        if !self.is_spender_signer(spender_signer) {
            m2_warn!("sign_spender: invalid signer");
            return false;
        }
        self.sign_pegin(spender_signer, utxos_set, tx, false, false)
    }
    
    /// sign the transaction for the cosigner.
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_cosigner(
        &mut self,
        cosigner_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction
    ) -> bool {
        self.sign_pegin(cosigner_signer, utxos_set, tx, true, false)
    }
    
    /// sign the transaction for the user as part of fulfilling the clawback condition
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_null_cosigner(
        &mut self,
        noop_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        tx: &mut Transaction
    ) -> bool {
        self.sign_pegin(noop_signer, utxos_set, tx, true, true)
    }

    /// Get the pegin p2wsh UTXO from a transaction, if one exists
    pub fn get_pegin_utxos(&self, tx: &Transaction, confirmations: u32) -> Vec<UTXO> {
        let mut ret = vec![];

        let pegin = self.p2wsh_script_pubkey();
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
        ret
    }

    /// Reset witness state
    pub fn clear_witness(&mut self) {
        self.user_signature_witness.clear();
        self.cosigner_signature_witness.clear();
    }
}
