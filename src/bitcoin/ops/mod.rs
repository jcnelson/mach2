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

use crate::bitcoin::blocks::BitcoinHashExtensions;
use crate::bitcoin::signer::BitcoinOpSigner;
use crate::bitcoin::wallet::{UTXO, UTXOSet, DUST_UTXO_LIMIT};

pub mod pegin;
pub mod transfer;

pub use crate::bitcoin::ops::pegin::OpPegIn;
pub use crate::bitcoin::ops::pegin::StacksAddressExtensions;

#[cfg(test)]
pub mod tests;

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
    
    pub fn make_witness_script_for_pegin(user_pubkey: &Secp256k1PublicKey, cosigner_threshold: u8, cosigner_pubkeys: &[Secp256k1PublicKey], provider_stacks_address: &StacksAddress, locktime: u32, safety_margin: u32) -> Script {
        let reclaim_locktime = locktime + safety_margin;
        let mut builder = Builder::new()
            .push_opcode(btc_opcodes::OP_DROP)
            .push_slice(&user_pubkey.to_bytes_compressed())
            .push_opcode(btc_opcodes::OP_CHECKSIGVERIFY)
            .push_int(cosigner_threshold.into());
        
        for pubk in cosigner_pubkeys.iter() {
            builder = builder.push_slice(&pubk.to_bytes_compressed());
        }

        builder
            .push_int(cosigner_pubkeys.len() as i64)
            .push_opcode(btc_opcodes::OP_CHECKMULTISIG)
            .push_opcode(btc_opcodes::OP_0NOTEQUAL)
            .push_opcode(btc_opcodes::OP_IF)
            .push_int(locktime.into())
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(btc_opcodes::OP_ELSE)
            .push_int(reclaim_locktime.into())
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(btc_opcodes::OP_ENDIF)
            .into_script()
    }
    
    /// Inspect a pegin pegin witness script and determine when the unlock height is.
    /// This is the third item back from the end of the script
    pub fn get_pegin_unlock_height(witness_script: &Script) -> Option<u32> {
        // TODO: we really want a DoubleEndedIterator for Script
        let script_parts : Vec<_> = witness_script.iter(false).collect();
        let mut iter = script_parts.iter().rev();
        let Some(Instruction::Op(btc_opcodes::OP_ENDIF)) = iter.next() else {
            return None;
        };
        let Some(Instruction::Op(opcode)) = iter.next() else {
            return None;
        };
        if *opcode != opcodes::OP_CLTV {
            return None;
        }
        let Some(Instruction::PushBytes(bytes)) = iter.next() else {
            return None;
        };
        let locktime_i64 = read_scriptint(bytes).ok()?;
        let locktime = u32::try_from(locktime_i64).ok()?;
        return Some(locktime);
    }
    
    /// Inspect a transfer witness script and determine what the safety margin is.
    /// This is the third item back from the end of the script
    pub fn get_transfer_safety_margin(witness_script: &Script) -> Option<u32> {
        // TODO: we really want a DoubleEndedIterator for Script
        let script_parts : Vec<_> = witness_script.iter(false).collect();
        let mut iter = script_parts.iter().rev();
        let Some(Instruction::Op(btc_opcodes::OP_ENDIF)) = iter.next() else {
            return None;
        };
        let Some(Instruction::Op(opcode)) = iter.next() else {
            return None;
        };
        if *opcode != opcodes::OP_CSV {
            return None;
        }
        let Some(Instruction::PushBytes(bytes)) = iter.next() else {
            return None;
        };
        let safety_margin_i64 = read_scriptint(bytes).ok()?;
        let safety_margin = u32::try_from(safety_margin_i64).ok()?;
        return Some(safety_margin);
    }
    
    /// Inspect a witness script and determine what the user public key is
    pub fn get_user_public_key(witness_script: &Script) -> Option<Secp256k1PublicKey> {
        let mut iter = witness_script.iter(false);

        // public key
        let Some(Instruction::PushBytes(bytes)) = iter.next() else {
            return None;
        };
        Secp256k1PublicKey::from_slice(bytes).ok()
    }
}
