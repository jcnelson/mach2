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
use stacks_common::util::hash::DoubleSha256;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::hash::Hash160;

use crate::bitcoin::blocks::BitcoinHashExtensions;
use crate::bitcoin::signer::BitcoinOpSigner;
use crate::bitcoin::wallet::{UTXO, UTXOSet, DUST_UTXO_LIMIT};

pub mod pegin;
pub mod transfer;

pub use crate::bitcoin::ops::pegin::M2PegIn;
pub use crate::bitcoin::ops::transfer::M2Transfer;

#[cfg(test)]
pub mod tests;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(C)]
pub enum M2Ops {
    PegIn = 80, // ASCII 'P'
    Transfer = 84, // ASCII 'T'
}

impl TryFrom<u8> for M2Ops {
    type Error = ();
    fn try_from(chr: u8) -> Result<Self, Self::Error> {
        match chr {
            x if x == M2Ops::PegIn as u8 => Ok(M2Ops::PegIn),
            x if x == M2Ops::Transfer as u8 => Ok(M2Ops::Transfer),
            _ => Err(())
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct M2Marker(pub M2Ops, pub [u8; 32]);
impl M2Marker {
    pub fn new(op: M2Ops, code_hash: &Sha512Trunc256Sum) -> Self {
        Self(op, code_hash.0.clone())
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        let mut ret = [0u8; 33];
        ret[0] = self.0 as u8;
        ret[1..33].copy_from_slice(&self.1);
        ret
    }
}

impl TryFrom<[u8; 33]> for M2Marker {
    type Error = ();
    fn try_from(buff: [u8; 33]) -> Result<Self, Self::Error> {
        let op = M2Ops::try_from(buff[0])?;
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&buff[1..33]);
        Ok(Self(op, code_hash))
    }
}

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
///
/// <M2_PEGIN_MARKER> is M2Ops-byte + sha512/256-of-code
pub mod witness {
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

    use crate::bitcoin::blocks::BitcoinHashExtensions;
    use crate::bitcoin::signer::BitcoinOpSigner;
    use crate::bitcoin::wallet::{UTXO, UTXOSet, DUST_UTXO_LIMIT};

    use super::*;

    pub fn make_initial_witness_stack_from_script(witness_script: &Script) -> Vec<Script> {
        let mut scripts = vec![];
        scripts.push(Script::from(vec![]));
        scripts.push(witness_script.clone());
        scripts
    }

    pub fn make_witness_script_for_op(op: M2Ops, user_pubkey: &Secp256k1PublicKey, cosigner_threshold: u8, cosigner_pubkeys: &[Secp256k1PublicKey], code_hash: &Sha512Trunc256Sum, locktime: u32) -> Script {
        let marker = M2Marker::new(op, code_hash);
        let mut builder = Builder::new()
            .push_slice(&user_pubkey.to_bytes_compressed())
            .push_opcode(btc_opcodes::OP_CHECKSIGVERIFY)
            .push_int(cosigner_threshold.into());

        for pubk in cosigner_pubkeys.iter() {
            builder = builder.push_slice(&pubk.to_bytes_compressed());
        }
        builder
            .push_int(cosigner_pubkeys.len() as i64)
            .push_opcode(btc_opcodes::OP_CHECKMULTISIG)
            .push_opcode(btc_opcodes::OP_IF)
            .push_slice(&marker.to_bytes())
            .push_opcode(btc_opcodes::OP_DROP)
            .push_opcode(btc_opcodes::OP_PUSHNUM_1)
            .push_opcode(btc_opcodes::OP_ELSE)
            .push_int(locktime.into())
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(btc_opcodes::OP_ENDIF)
            .into_script()
    }

    /// Make a TxIn which spends a UTXO whose witness program matches the witness script code we'd
    /// generate
    pub fn make_txin_from_witness_script(utxo: &UTXO, witness_script: &Script) -> TxIn {
        let witness : Vec<Vec<u8>> = make_initial_witness_stack_from_script(witness_script)
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
    
    /// Inspect a witness script and determine when the unlock height is
    pub fn unlock_height(witness_script: &Script, num_cosigner_keys: u8, cosigner_threshold: u8) -> Option<u64> {
        let dummy_user_key = Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random());
        let mut dummy_cosigner_keys = vec![];
        for _ in 0..num_cosigner_keys {
            dummy_cosigner_keys.push(Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random()));
        }
        let dummy_code_hash = Sha512Trunc256Sum([0u8; 32]);
        let dummy_script = make_witness_script_for_op(M2Ops::PegIn, &dummy_user_key, cosigner_threshold, &dummy_cosigner_keys, &dummy_code_hash, 256);

        let mut last_push : Option<&[u8]> = None;
        for (dummy_inst, inst) in dummy_script.iter(false).zip(witness_script.iter(false)) {
            match (dummy_inst, inst) {
                (Instruction::PushBytes(..), Instruction::PushBytes(bytes)) => {
                    last_push = Some(bytes);
                    continue;
                }
                (Instruction::Op(dummy_op), Instruction::Op(op)) => {
                    if dummy_op != op {
                        // different script
                        return None;
                    }
                    if op == opcodes::OP_CLTV {
                        let Some(last_push) = last_push else {
                            return None;
                        };

                        // `last_push` is a varint containing the locktime
                        let locktime_i64 = read_scriptint(&last_push).ok()?;
                        let locktime = u64::try_from(locktime_i64).ok()?;
                        return Some(locktime);
                    }
                    continue;
                }
                (Instruction::Error(..), _)
                | (_, Instruction::Error(..)) => {
                    return None;
                },
                (_, _) => {
                    return None;
                }
            }
        }
        None
    }
    
    /// Inspect a witness script and determine what the code hash is
    pub fn code_hash(witness_script: &Script, num_cosigner_keys: u8, cosigner_threshold: u8) -> Option<Sha512Trunc256Sum> {
        let dummy_user_key = Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random());
        let mut dummy_cosigner_keys = vec![];
        for _ in 0..num_cosigner_keys {
            dummy_cosigner_keys.push(Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random()));
        }
        let dummy_code_hash = Sha512Trunc256Sum([0u8; 32]);
        let dummy_script = make_witness_script_for_op(M2Ops::PegIn, &dummy_user_key, cosigner_threshold, &dummy_cosigner_keys, &dummy_code_hash, 256);

        let mut last_push : Option<&[u8]> = None;
        for (dummy_inst, inst) in dummy_script.iter(false).zip(witness_script.iter(false)) {
            match (dummy_inst, inst) {
                (Instruction::PushBytes(..), Instruction::PushBytes(bytes)) => {
                    last_push = Some(bytes);
                    continue;
                }
                (Instruction::Op(dummy_op), Instruction::Op(op)) => {
                    if dummy_op != op {
                        // different script
                        return None;
                    }
                    if op == btc_opcodes::OP_DROP {
                        let Some(last_push) = last_push else {
                            return None;
                        };

                        // `last_push` is the marker + code-hash
                        if last_push.len() != 33 {
                            return None;
                        }
                        let mut hash_bytes = [0u8; 32];
                        hash_bytes.copy_from_slice(&last_push[1..33]);
                        return Some(Sha512Trunc256Sum(hash_bytes));
                    }
                    continue;
                }
                (Instruction::Error(..), _)
                | (_, Instruction::Error(..)) => {
                    return None;
                },
                (_, _) => {
                    return None;
                }
            }
        }
        None
    }
}
