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

pub use crate::bitcoin::ops::pegin::M2PegIn;
pub use crate::bitcoin::ops::transfer::M2Transfer;
pub use crate::bitcoin::ops::pegin::StacksAddressExtensions;

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

#[derive(Debug, PartialEq, Clone)]
pub struct M2Marker(pub M2Ops, pub Vec<u8>);
impl M2Marker {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = vec![self.0 as u8];
        ret.extend_from_slice(&self.1);
        ret
    }
}

impl TryFrom<&[u8]> for M2Marker {
    type Error = ();
    fn try_from(buff: &[u8]) -> Result<Self, Self::Error> {
        let Some(op_byte) = buff.get(0) else {
            return Err(());
        };
        let op = M2Ops::try_from(*op_byte)?;
        let Some(payload_slice) = buff.get(1..) else {
            return Err(());
        };
        Ok(Self(op, payload_slice.to_vec()))
    }
}

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

    pub struct WitnessData {
        pub witness_script: Script,
        pub user_public_key: Secp256k1PublicKey,
        pub marker: M2Marker,
        pub expiry: u32,
        pub num_cosigner_keys: u8,
        pub cosigner_threshold: u8,
    }

    impl WitnessData {
        /// Extract metadata from the witness script
        pub fn try_from_witness_script(witness_script: &Script, num_cosigner_keys: u8, cosigner_threshold: u8, expiry: u32) -> Option<Self> {
            let marker = get_marker(witness_script)?;
            let user_public_key = get_user_public_key(witness_script)?;
            Some(Self {
                witness_script: witness_script.clone(),
                user_public_key,
                marker,
                expiry,
                num_cosigner_keys,
                cosigner_threshold
            })
        }

        /// Get the p2wpkh script pubkey for the user public key
        pub fn user_p2wpkh(&self) -> Script {
            let pubkey_hash = Hash160::from_data(&self.user_public_key.to_bytes());
            let pubkey_v0_p2wpkh = Builder::new()
                .push_int(0)
                .push_slice(&pubkey_hash.0)
                .into_script();
            pubkey_v0_p2wpkh
        }
    }

    pub fn make_initial_witness_stack_from_script(witness_script: &Script) -> Vec<Script> {
        let mut scripts = vec![];
        scripts.push(Script::from(vec![]));
        scripts.push(witness_script.clone());
        scripts
    }
    
    /// peg-in witness stack, from bottom to top:
    ///
    /// <>
    /// <cosigner-sig1>
    /// <cosigner-sig2>
    /// ...
    /// <cosigner-sigK>
    /// <user-sig>
    /// 
    /// peg-in witness-script:
    ///
    /// <marker> OP_DROP
    /// <user-pubk> OP_CHECKSIGVERIFY
    /// <cosigner-num-sigs> <cosigner-pk1> <cosigner-pk2> ... <cosigner-pkN> <cosigner-num-keys> OP_CHECKMULTISIG OP_0NOTEQUAL
    /// OP_IF
    ///    <locktime - safety-margin> OP_CHECKLOCKTIMEVERIFY
    /// OP_ELSE
    ///    <locktime> OP_CHECKLOCKTIMEVERIFY
    /// OP_ENDIF
    ///
    /// <marker> is M2Ops-byte + Stacks address of recipient
    pub fn make_witness_script_for_pegin(user_pubkey: &Secp256k1PublicKey, cosigner_threshold: u8, cosigner_pubkeys: &[Secp256k1PublicKey], recipient_stacks_address: &StacksAddress, locktime: u32, safety_margin: u32) -> Script {
        let marker = M2Marker(M2Ops::PegIn, recipient_stacks_address.to_pushdata().to_vec());
        let reclaim_locktime = locktime + safety_margin;
        let mut builder = Builder::new()
            .push_slice(&marker.to_bytes())
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
    
    /// transfer witness stack, from bottom to top:
    ///
    /// <>
    /// <cosigner-sig1>
    /// <cosigner-sig2>
    /// ...
    /// <cosigner-sigK>
    /// <user-sig>
    /// 
    /// transfer witness-script:
    ///
    /// <marker> OP_DROP
    /// <user-pubk> OP_CHECKSIGVERIFY
    /// <cosigner-num-sigs> <cosigner-pk1> <cosigner-pk2> ... <cosigner-pkN> <cosigner-num-keys> OP_CHECKMULTISIG OP_0NOTEQUAL
    /// OP_IF
    ///    OP_TRUE
    /// OP_ELSE
    ///    <safety-margin> OP_CHECKSEQUENCEVERIFY
    /// OP_ENDIF
    ///
    /// <marker> is M2Ops-byte + whatever the smart contract or sender wanted as a memo
    pub fn make_witness_script_for_transfer(user_pubkey: &Secp256k1PublicKey, cosigner_threshold: u8, cosigner_pubkeys: &[Secp256k1PublicKey], op_payload: Vec<u8>, safety_margin: u32) -> Script {
        let marker = M2Marker(M2Ops::Transfer, op_payload);
        let mut builder = Builder::new()
            .push_slice(&marker.to_bytes())
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
            .push_opcode(opcodes::OP_TRUE)
            .push_opcode(btc_opcodes::OP_ELSE)
            .push_int(safety_margin.into())
            .push_opcode(opcodes::OP_CSV)
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
    
    /// Inspect a witness script and extract is M2Marker.
    /// In all witness scripts we support, this will be the payload associated with the first
    /// OP_PUSHDATA (which itself will be the first operation)
    pub fn get_marker(witness_script: &Script) -> Option<M2Marker> {
        let mut iter = witness_script.iter(false);
        let Some(Instruction::PushBytes(bytes)) = iter.next() else {
            return None;
        };
        M2Marker::try_from(bytes).ok()
    }

    /// Inspect a witness script and determine what the user public key is
    pub fn get_user_public_key(witness_script: &Script) -> Option<Secp256k1PublicKey> {
        let mut iter = witness_script.iter(false);

        // marker
        let Some(Instruction::PushBytes(_)) = iter.next() else {
            return None;
        };
        let Some(Instruction::Op(btc_opcodes::OP_DROP)) = iter.next() else {
            return None;
        };
        // public key
        let Some(Instruction::PushBytes(bytes)) = iter.next() else {
            return None;
        };
        Secp256k1PublicKey::from_slice(bytes).ok()
    }
}
