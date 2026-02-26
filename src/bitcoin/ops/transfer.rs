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

use crate::bitcoin::ops::{OpPegIn, witness};

pub struct OpTransfer {
    cosigner_signature_witness: Vec<Vec<u8>>,
    pegin_user_pubkey: Secp256k1PublicKey,
    pegin_signature_witness: Vec<u8>
}

impl OpTransfer {
    pub fn new(pegin_user_pubkey: Secp256k1PublicKey) -> Self {
        Self {
            pegin_user_pubkey,
            pegin_signature_witness: vec![],
            cosigner_signature_witness: vec![],
        }
    }

    /// Is the given signer the signer for the user?  I.e. the public key the user committed to on
    /// peg-in that will be used to authorize this transfer?
    pub fn is_user_signer(&self, user_signer: &mut BitcoinOpSigner) -> bool {
        let mut public_key = self.pegin_user_pubkey.clone();
        public_key.set_compressed(true);

        let mut signer_public_key = user_signer.get_public_key();
        signer_public_key.set_compressed(true);

        // sanity check -- this signer must be for this user
        public_key == signer_public_key
    }
    
    /// sign the transfer transaction for the user or cosigner.
    /// Spends only UTXOs in `utxos_set`, which must have script pubkeys that match
    /// one of the p2wsh scripts computed from `pegin_witness_scripts`. In other
    /// words, this only spends peg-in UTXOs.
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
        
        let pegin_p2wshs : HashMap<_, _> = pegin_witness_scripts
            .iter()
            .map(|s| (s.to_v0_p2wsh(), s))
            .collect();

        for (i, utxo) in utxos_set.utxos.iter().enumerate() {
            let sig_hash_all = 0x01;
            let sig_hash = if let Some(pegin_witness_script) = pegin_p2wshs.get(&utxo.script_pub_key) {
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

            let witness_script = if let Some(pegin_witness_script) = pegin_p2wshs.get(&utxo.script_pub_key) {
                // spending a pegin UTXO
                if tx.lock_time == 0 {
                    m2_warn!("Cannot spend a pegin UTXO without a positive locktime");
                    return false;
                }

                if is_cosigner {
                    if null_cosigner {
                        m2_debug!("Null cosigner signs for transfer");
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
                    self.pegin_signature_witness = [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec();
                }
                (*pegin_witness_script).clone()
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
            witness.push(self.pegin_signature_witness.clone());
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
    
    /// Reset witness state
    pub fn clear_witness(&mut self) {
        self.pegin_signature_witness.clear();
        self.cosigner_signature_witness.clear();
    }
}
