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

use std::collections::HashMap;

use stacks_common::deps_common::bitcoin::blockdata::block::{Block, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as btc_opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Instruction, Script, Builder, read_scriptint};
use stacks_common::deps_common::bitcoin::blockdata::transaction::{TxIn, TxOut, OutPoint, Transaction};
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey, MessageSignature};
use stacks_common::types::PublicKey;
use stacks_common::util::hash::DoubleSha256;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::to_hex;

use crate::bitcoin::blocks::BitcoinHashExtensions;
use crate::bitcoin::signer::BitcoinOpSigner;
use crate::bitcoin::wallet::{UTXO, UTXOSet, DUST_UTXO_LIMIT};

use crate::bitcoin::ops::{M2Ops, M2Marker, M2PegIn, witness};

pub struct M2Transfer {
    safety_margin: u32,
    user_pubkey: Secp256k1PublicKey,
    user_signature_witness: Vec<u8>,    // one user signature for now
    cosigner_pubkeys: Vec<Secp256k1PublicKey>,
    cosigner_threshold: u8,
    cosigner_signature_witness: Vec<Vec<u8>>,
    payload: Vec<u8>
}

impl M2Transfer {
    pub fn new(safety_margin: u32, user_pubkey: &Secp256k1PublicKey, cosigner_pubkeys: &[Secp256k1PublicKey], cosigner_threshold: u8, payload: Vec<u8>) -> Self {
        Self {
            safety_margin,
            user_pubkey: user_pubkey.clone(),
            user_signature_witness: vec![],
            cosigner_pubkeys: cosigner_pubkeys.to_vec(),
            cosigner_threshold,
            cosigner_signature_witness: vec![],
            payload
        }
    }

    pub fn make_initial_witness_stack(&self) -> Vec<Script> {
        witness::make_initial_witness_stack_from_script(&self.make_witness_script())
    }

    pub fn make_witness_script(&self) -> Script {
        witness::make_witness_script_for_transfer(&self.user_pubkey, self.cosigner_threshold, &self.cosigner_pubkeys, self.payload.clone(), self.safety_margin)
    }

    pub fn make_recipient_witness_script(&self, recipient_pubkey: &Secp256k1PublicKey, recipient_payload: Vec<u8>) -> Script {
        witness::make_witness_script_for_transfer(recipient_pubkey, self.cosigner_threshold, &self.cosigner_pubkeys, recipient_payload, self.safety_margin)
    }

    pub fn make_recipient_script_pubkey(&self, recipient_pubkey: &Secp256k1PublicKey, recipient_payload: Vec<u8>) -> Script {
        let prog = self.make_recipient_witness_script(recipient_pubkey, recipient_payload);
        prog.to_v0_p2wsh()
    }

    pub fn make_user_script_pubkey(&self) -> Script {
        let prog = self.make_witness_script();
        prog.to_v0_p2wsh()
    }

    pub fn make_transfer_spend_txin(utxo: &UTXO, witness_script: &Script, safety_margin: u32) -> TxIn {
        let witness : Vec<Vec<u8>> = witness::make_initial_witness_stack_from_script(&witness_script)
            .into_iter()
            .map(|s| s.to_bytes())
            .collect();

        let input = TxIn {
            previous_output: OutPoint {
                txid: Sha256dHash(utxo.txid.clone().0),
                vout: utxo.vout
            },
            script_sig: Script::new(),
            sequence: safety_margin,
            witness,
        };
        input
    }

    /// Create an unsigned mach2 transfer spending transaction, which consumes some or all of the `utxo_set`.
    /// Spends p2wsh UTXOs in `utxos_set` whose script_pub_keys either match the user's script
    /// pubkey (a p2wsh) or one of the p2wsh script pubkeys derived from `pegin_witness_scripts`
    ///
    /// Returns Some(tx) on success, and reduces `utxos_set` to the UTXOs which will be consumed
    /// Returns None on error, and leaves `utxos_set` unchanged.
    pub fn make_unsigned_transfer_spend_transaction(
        &self,
        tx_fee: u64,
        utxos_set: &mut UTXOSet,
        pegin_witness_scripts: &[Script],
        recipient: Script,
        recipient_amount: u64,
    ) -> Option<Transaction> {
        let tx_cost = tx_fee + recipient_amount;

        let pegin_p2wshs : HashMap<_, _> = pegin_witness_scripts
            .iter()
            .map(|s| (s.to_v0_p2wsh(), s))
            .collect();
        
        let user_p2wsh = self.make_user_script_pubkey();
        
        let mut public_key = self.user_pubkey.clone();
        public_key.set_compressed(true);

        // select UTXOs until we have enough to cover the cost.
        // This reduces `utxos_set` to only the UTXOs which will be spent.
        let mut total_consumed = 0;
        let mut available_utxos = vec![];
        available_utxos.append(&mut utxos_set.utxos);

        for utxo in available_utxos.into_iter() {
            if !pegin_p2wshs.contains_key(&utxo.script_pub_key) && utxo.script_pub_key != user_p2wsh {
                m2_test_debug!("Skip {}", &utxo.script_pub_key);
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
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value: recipient_amount,
                script_pubkey: recipient
            }]
        };

        if value >= DUST_UTXO_LIMIT {
            tx.output.push(TxOut {
                value,
                script_pubkey: user_p2wsh.clone(),
            });
        } else {
            // Instead of leaving that change to the BTC miner, we could / should bump the sortition fee
            m2_debug!("Not enough change to clear dust limit. Not adding change address.");
        }

        for utxo in utxos_set.utxos.iter() {
            let input = if let Some(pegin_witness_script) = pegin_p2wshs.get(&utxo.script_pub_key) {
                // spending a previously-locked peg-in 
                M2PegIn::make_pegin_spend_txin(utxo, pegin_witness_script)
            }
            else if utxo.script_pub_key == user_p2wsh {
                // spending a previous transfer UTXO
                Self::make_transfer_spend_txin(utxo, &self.make_witness_script(), self.safety_margin)
            }
            else {
                continue;
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
    
    /// sign the transfer transaction for the user or cosigner.
    /// Spends only UTXOs in `utxos_set`, which must have script pubkeys that match either our
    /// transfer p2wsh, or one of the p2wsh scripts computed from `pegin_witness_scripts`. In other
    /// words, this only spends peg-in or transfer UTXOs
    fn sign_transfer(
        &mut self,
        signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        pegin_witness_scripts: &[Script],
        tx: &mut Transaction,
        is_cosigner: bool,
        null_cosigner: bool,
    ) -> bool {
        if !is_cosigner && !self.is_user_signer(signer) {
            // nothing to do
            return false;
        }

        let mut public_key = signer.get_public_key();
        public_key.set_compressed(true);
        
        let user_p2wsh = self.make_user_script_pubkey();
        let pegin_p2wshs : HashMap<_, _> = pegin_witness_scripts
            .iter()
            .map(|s| (s.to_v0_p2wsh(), s))
            .collect();

        for (i, utxo) in utxos_set.utxos.iter().enumerate() {
            let sig_hash_all = 0x01;
            let sig_hash = if utxo.script_pub_key == user_p2wsh {
                // spending a transfer UTXO for this user
                tx.segwit_signature_hash(i, &self.make_witness_script(), utxo.amount, sig_hash_all)
            }
            else if let Some(pegin_witness_script) = pegin_p2wshs.get(&utxo.script_pub_key) {
                // spending a pegin UTXO
                tx.segwit_signature_hash(i, pegin_witness_script, utxo.amount, sig_hash_all)
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

            let witness_script;
            if utxo.script_pub_key == user_p2wsh {
                // spending a transfer UTXO
                if is_cosigner {
                    if null_cosigner {
                        m2_debug!("Null cosigner signs for transfer {}: {}", &to_hex(&user_p2wsh.to_bytes()), &sig1_der);
                        self.cosigner_signature_witness.push(vec![]);
                    }
                    else {
                        // cosigner is spending a transfer UTXO
                        m2_debug!("Cosigner {} signs for transfer {}: {}", &public_key.to_hex(), &to_hex(&user_p2wsh.to_bytes()), &sig1_der);
                        self.cosigner_signature_witness.push([&*sig1_der, &[sig_hash_all as u8]][..].concat().to_vec());
                    }
                }
                else {
                    // user is spending a transfer UTXO
                    m2_debug!("User {} signs for transfer {}: {}", &public_key.to_hex(), &to_hex(&user_p2wsh.to_bytes()), &sig1_der);
                    self.user_signature_witness = [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec();
                }
                witness_script = self.make_witness_script();
            }
            else if let Some(pegin_witness_script) = pegin_p2wshs.get(&utxo.script_pub_key) {
                // spending a pegin UTXO
                if tx.lock_time == 0 {
                    m2_warn!("Cannot spend a pegin UTXO without a positive locktime");
                    return false;
                }

                if is_cosigner {
                    if null_cosigner {
                        m2_debug!("Null cosigner signs for transfer {}: {}", &to_hex(&user_p2wsh.to_bytes()), &sig1_der);
                        self.cosigner_signature_witness.push(vec![]);
                    }
                    else {
                        // cosigner is spending a pegin UTXO
                        m2_debug!("Cosigner {} signs pegin {}: {}", &public_key.to_hex(), &to_hex(&utxo.script_pub_key.to_bytes()), &sig1_der);
                        self.cosigner_signature_witness.push([&*sig1_der, &[sig_hash_all as u8]][..].concat().to_vec());
                    }
                }
                else {
                    // user is spending a pegin UTXO
                    m2_debug!("User {} signs pegin {}: {}", &public_key.to_hex(), &to_hex(&utxo.script_pub_key.to_bytes()), &sig1_der);
                    self.user_signature_witness = [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec();
                }
                witness_script = (*pegin_witness_script).clone();
            }
            else {
                continue;
            };

            // re-compute witness
            let mut witness = vec![];
            witness.push(vec![]);
            for sig_wit in self.cosigner_signature_witness.iter() {
                witness.push(sig_wit.to_vec());
            }
            witness.push(self.user_signature_witness.clone());
            witness.push(witness_script.to_bytes());
            tx.input[i].script_sig = Script::from(vec![]);
            tx.input[i].witness = witness;
        }
        true
    }

    /// sign the transaction for the user.
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_user(
        &mut self,
        user_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        pegin_witness_scripts: &[Script],
        tx: &mut Transaction
    ) -> bool {
        if !self.is_user_signer(user_signer) {
            m2_warn!("sign_user: invalid signer");
            return false;
        }
        self.sign_transfer(user_signer, utxos_set, pegin_witness_scripts, tx, false, false)
    }
    
    /// sign the transaction for the cosigner.
    /// The given `utxos_set` must be the same `utxos_set` used to produce the transaction.
    pub fn sign_cosigner(
        &mut self,
        cosigner_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        pegin_witness_scripts: &[Script],
        tx: &mut Transaction
    ) -> bool {
        self.sign_transfer(cosigner_signer, utxos_set, pegin_witness_scripts, tx, true, false)
    }
    
    /// sign with the "null" cosigner (i.e. done by the user) in order to spend a time-locked UTXO.
    /// no signature will be generated
    pub fn sign_null_cosigner(
        &mut self,
        noop_signer: &mut BitcoinOpSigner,
        utxos_set: &UTXOSet,
        pegin_witness_scripts: &[Script],
        tx: &mut Transaction
    ) -> bool {
        self.sign_transfer(noop_signer, utxos_set, pegin_witness_scripts, tx, true, true)
    }
    
    /// Get the transfer p2wsh UTXOs from a transaction, if any exists
    pub fn get_transfer_utxos(&self, tx: &Transaction, confirmations: u32, recipient: &Script) -> Vec<UTXO> {
        let mut ret = vec![];

        for (i, out) in tx.output.iter().enumerate() {
            if out.script_pubkey == *recipient {
                ret.push(UTXO {
                    txid: DoubleSha256(tx.txid().0),
                    vout: i as u32,
                    script_pub_key: out.script_pubkey.clone(),
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
