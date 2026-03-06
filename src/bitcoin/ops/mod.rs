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

use clarity::vm::Value;

pub mod pegin;

pub use crate::bitcoin::ops::pegin::OpPegIn;

use crate::contracts::execute_in_segwit_contract;

// constants from segwit.clar
pub const MAX_TX_INPUTS : usize = 16;
pub const MAX_TX_OUTPUTS : usize = 50;
pub const MAX_WITNESS_STACK_LEN : usize = 13;
pub const MAX_WITNESS_STACK_ELEMENT_LEN : usize = 1376;

#[cfg(test)]
pub mod tests;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    EvalFailed(String),
    MissingField(String),
    WrongType(String),
    TxTooBig,
    InsufficientFunds,
    UnsolvableUTXO,
    WrongSigner,
    BadLocktime,
    FailedToSign(String),
    NoSuchInput,
    InputNotSigned,
}

pub trait StacksAddressExtensions {
    fn to_pushdata(&self) -> [u8; 21];
}

impl StacksAddressExtensions for StacksAddress {
    fn to_pushdata(&self) -> [u8; 21] {
        let version = self.version();
        let hash160 = self.bytes().0;
        let mut ret = [0u8; 21];
        ret[0] = version;
        ret[1..21].copy_from_slice(&hash160);
        ret
    }
}

pub trait TransactionExtensions {
    fn is_tx_small_enough(tx: &Transaction) -> bool {
        if tx.input.len() > MAX_TX_INPUTS {
            return false;
        }
        if tx.output.len() > MAX_TX_OUTPUTS {
            return false;
        }
        for inp in tx.input.iter() {
            if inp.witness.len() > MAX_WITNESS_STACK_LEN {
                return false;
            }
            for wit in inp.witness.iter() {
                if wit.len() > MAX_WITNESS_STACK_ELEMENT_LEN {
                    return false;
                }
            }
        }
        true
    }

    fn inputs_to_clarity(tx: &Transaction) -> String {
        let ins : Vec<_> = tx.input
            .iter()
            .map(|inp| {
                let outpoint_hash = format!("{}", &to_hex(&inp.previous_output.txid.0));
                let outpoint_index = format!("{}", &inp.previous_output.vout);
                let outpoint = format!(r#"{{ hash: 0x{outpoint_hash}, index: u{outpoint_index} }}"#);
                let script_sig = format!("{}", &to_hex(inp.script_sig.as_bytes()));
                let sequence = format!("{}", &inp.sequence);
                let witness_stack_items : Vec<_> = inp
                    .witness
                    .iter()
                    .map(|wit| format!("0x{}", &to_hex(wit)))
                    .collect();

                let witness_stack = witness_stack_items.join(" ");

                format!(r#"{{ outpoint: {outpoint}, scriptSig: 0x{script_sig}, sequence: u{sequence}, witness: (list {witness_stack}) }}"#)
            })
            .collect();

        let in_code = ins.join(" ");
        format!("(list {in_code})")
    }

    fn outputs_to_clarity(tx: &Transaction) -> String {
        let outs : Vec<_> = tx.output
            .iter()
            .map(|outp| {
                let out_value = format!("{}", outp.value);
                let out_script = format!("{}", to_hex(&outp.script_pubkey.as_bytes()));
                
                format!(r#"{{ value: u{out_value}, scriptPubKey: 0x{out_script} }}"#)
            })
            .collect();

        let out_code = outs.join(" ");
        format!("(list {out_code})")
    }

    fn get_precomputed_segwit_sighash_data(precomputed_hashes_value: Value) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let precomputed_hashes_tuple = precomputed_hashes_value
            .expect_result()
            .map_err(|e| Error::EvalFailed(format!("Failed to produce precomputed segwit signature hash data: {e:?}")))?
            .map_err(|e| Error::EvalFailed(format!("Failed to compute segwit signature hash data: (err {e:?})")))?
            .expect_tuple()
            .map_err(|e| Error::WrongType(format!("Expected tuple for precompute-segwit-signature-hash: {e:?}")))?;

        let version_hash_prevouts_hash_sequence = precomputed_hashes_tuple
            .get("version-hash-prevouts-hash-sequence")
            .cloned()
            .map_err(|e| Error::MissingField(format!("tuple does not have version-hash-prevouts-hash-seqeunce: {e:?}")))?
            .expect_buff(68)
            .map_err(|e| Error::WrongType(format!("version-hash-prevouts-hash-sequence is not a (buff 68): {e:?}")))?;

        let hash_outputs_locktime_sighash = precomputed_hashes_tuple
            .get("hash-outputs-locktime-sighash")
            .cloned()
            .map_err(|e| Error::MissingField(format!("tuple does not have hash-outputs-locktime-sighash: {e:?}")))?
            .expect_buff(44)
            .map_err(|e| Error::WrongType(format!("hash-outputs-locktime-sighash is not a (buff 44): {e:?}")))?;

        Ok((version_hash_prevouts_hash_sequence, hash_outputs_locktime_sighash))
    }

    fn make_segwit_signature_hash(&self, i: usize, spender_script: &Script, amount: u64) -> Result<Sha256dHash, Error>;
}

impl TransactionExtensions for Transaction {
    fn make_segwit_signature_hash(&self, i: usize, spender_script: &Script, amount: u64) -> Result<Sha256dHash, Error> {
        if !Self::is_tx_small_enough(self) {
            return Err(Error::TxTooBig);
        }
       
        let version = format!("{}", &self.version);
        let ins = Self::inputs_to_clarity(self);
        let outs = Self::outputs_to_clarity(self);
        let locktime = format!("{}", &self.lock_time);

        let precompute_code = format!(r#"(precompute-segwit-signature-hash u{version} {ins} {outs} u{locktime})"#);

        let precomputed_hashes_value = execute_in_segwit_contract(&precompute_code)
            .map_err(|e| Error::EvalFailed(format!("Failed to execute segwit sighash precompute code '{precompute_code}': {e:?}")))?
            .ok_or_else(|| Error::EvalFailed("Failed to compute the precomputed sighash values".to_string()))?;

        let (version_hash_prevouts_hash_sequence, hash_outputs_locktime_sighash) = 
            Self::get_precomputed_segwit_sighash_data(precomputed_hashes_value)?;

        let version_hash_prevouts_hash_sequence = to_hex(&version_hash_prevouts_hash_sequence);
        let hash_outputs_locktime_sighash = to_hex(&hash_outputs_locktime_sighash);

        let spend_script_hex = to_hex(&spender_script.as_bytes());
        let segwit_sighash_code = format!(r#"
            (segwit-signature-hash
            {ins}
            {outs}
             {{ version-hash-prevouts-hash-sequence: 0x{version_hash_prevouts_hash_sequence}, hash-outputs-locktime-sighash: 0x{hash_outputs_locktime_sighash} }}
             u{i}
             0x{spend_script_hex}
             u{amount})"#);
        
        let segwit_signature_hash_value = execute_in_segwit_contract(&segwit_sighash_code)
            .map_err(|e| Error::EvalFailed(format!("Failed to execute segwit sighash code '{segwit_sighash_code}': {e:?}")))?
            .ok_or_else(|| Error::EvalFailed(format!("Failed to get a return value for segwit sighash code '{segwit_sighash_code}'")))?;

        let segwit_sighash_result = segwit_signature_hash_value
            .expect_result()
            .map_err(|e| Error::WrongType(format!("did not get result from segwit-signature-hash: {e:?}")))?
            .map_err(|e| Error::EvalFailed(format!("got an error for segwit-signature-hash: {e:?}")))?;

        let segwit_sighash = segwit_sighash_result
            .expect_buff(32)
            .map_err(|e| Error::WrongType(format!("did not get (ok (buff 32)) from segwit-signature-hash: {e:?}")))?;

        let mut segwit_sighash_bytes = [0u8; 32];
        segwit_sighash_bytes.copy_from_slice(&segwit_sighash[..]);
        
        let sighash = Sha256dHash(segwit_sighash_bytes);

        if cfg!(test) {
            let rust_sighash = self.segwit_signature_hash(i, spender_script, amount, 0x01);
            m2_debug!("clarity sighash = {}, Rust sighash = {}", &to_hex(&sighash.0), &to_hex(&rust_sighash.0));
            assert_eq!(rust_sighash, sighash, "{}", segwit_sighash_code);
        }

        Ok(sighash)
    }
} 
