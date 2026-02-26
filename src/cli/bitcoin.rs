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

use std::fs;

use stacks_common::util::hash::hex_bytes;
use stacks_common::deps_common::bitcoin::blockdata::block::Block as BitcoinBlock;
use stacks_common::deps_common::bitcoin::blockdata::block::BlockHeader as BitcoinBlockHeader;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize as BtcDeserialize;
use stacks_common::deps_common::bitcoin::network::serialize::serialize as BtcSerialize;
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;

use stacks_common::util::hash::to_hex;
use stacks_common::util::hash::DoubleSha256;

use crate::bitcoin::{Txid, Wtxid};
use crate::bitcoin::blocks::{TransactionExtensions, BlockExtensions, BitcoinHashExtensions, bitcoin_merkle_tree};

use crate::util::vm::vm_execute;

use clarity::vm::ClarityVersion;

use crate::cli::Error;
use crate::cli::usage;
use crate::cli::load_from_file_or_stdin;

use crate::contracts::execute_in_bitcoin_contract;

use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BitcoinSegwitMerkleProof {
    pub block_height: u32,
    #[serde(
        serialize_with = "btc_tx_serialize",
        deserialize_with = "btc_tx_deserialize",
    )]
    pub transaction: BitcoinTransaction,
    #[serde(
        serialize_with = "btc_header_serialize",
        deserialize_with = "btc_header_deserialize",
    )]
    pub block_header: BitcoinBlockHeader,
    pub tx_index: usize,
    pub tree_depth: u16,
    pub tx_proof: Vec<DoubleSha256>,
    pub witness_merkle_root: DoubleSha256,
    pub witness_reserved: DoubleSha256,
    #[serde(
        serialize_with = "btc_tx_serialize",
        deserialize_with = "btc_tx_deserialize",
    )]
    pub coinbase_tx: BitcoinTransaction,
    pub coinbase_tx_proof: Vec<DoubleSha256>
}

fn btc_tx_serialize<S: serde::Serializer>(
    tx: &BitcoinTransaction,
    s: S,
) -> Result<S::Ok, S::Error> {
    let bytes = BtcSerialize(tx).expect("infallible");
    let inst = to_hex(&bytes);
    s.serialize_str(inst.as_str())
}

fn btc_tx_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BitcoinTransaction, D::Error> {
    let inst_str = String::deserialize(d)?;
    let inst_bytes = hex_bytes(&inst_str).map_err(serde::de::Error::custom)?;
    let tx : BitcoinTransaction = BtcDeserialize(&inst_bytes).map_err(serde::de::Error::custom)?;
    Ok(tx)
}

fn btc_header_serialize<S: serde::Serializer>(
    hdr: &BitcoinBlockHeader,
    s: S,
) -> Result<S::Ok, S::Error> {
    let bytes = BtcSerialize(hdr).expect("infallible");
    let inst = to_hex(&bytes);
    s.serialize_str(inst.as_str())
}

fn btc_header_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BitcoinBlockHeader, D::Error> {
    let inst_str = String::deserialize(d)?;
    let inst_bytes = hex_bytes(&inst_str).map_err(serde::de::Error::custom)?;
    let hdr : BitcoinBlockHeader = BtcDeserialize(&inst_bytes).map_err(serde::de::Error::custom)?;
    Ok(hdr)
}

impl BitcoinSegwitMerkleProof {
    pub fn new(block: &BitcoinBlock, block_height: u32, tx_index: usize) -> Option<Self> {
        let Some(transaction) = block.txdata.get(tx_index).cloned() else {
            return None;
        };
        let coinbase_tx = block.get_coinbase()?;
        let coinbase_tx_proof = block
            .compute_merkle_proof(0)?
            .into_iter()
            .map(|h| DoubleSha256(h.0))
            .collect();
        let tx_proof : Vec<DoubleSha256> = block
            .compute_witness_merkle_proof(tx_index)?
            .into_iter()
            .map(|h| DoubleSha256(h.0))
            .collect();
        let tree_depth = u16::try_from(tx_proof.len()).ok()?;
        let block_header = block.header.clone();
        let witness_merkle_root = DoubleSha256(block.compute_witness_merkle_root().0);
        let witness_reserved = DoubleSha256(block.get_witness_reserved()?.0);
        Some(Self {
            block_height,
            transaction,
            block_header,
            tx_index,
            tree_depth,
            tx_proof,
            witness_merkle_root,
            witness_reserved,
            coinbase_tx,
            coinbase_tx_proof
        })
    }

    pub fn check(&self) -> bool {
        let block_hash = format!("0x{}", &self.block_header.bitcoin_hash().to_string());
        let block_header = format!("0x{}", &to_hex(&BtcSerialize(&self.block_header).expect("infallible")));
        let coinbase_tx = format!("0x{}", &to_hex(&BtcSerialize(&self.coinbase_tx).expect("infallible")));
        let witness_root = format!("0x{}", self.witness_merkle_root.be_hex_string());
        let witness_reserved = format!("0x{}", self.witness_reserved.be_hex_string());
        
        let coinbase_proof_hashes = self.coinbase_tx_proof
            .iter()
            .map(|h| format!("0x{}", &h.be_hex_string()))
            .collect::<Vec<_>>().join(" ");
        let coinbase_proof_list = format!("(list {coinbase_proof_hashes})");

        let tx_proof_hashes = self.tx_proof
            .iter()
            .map(|h| format!("0x{}", &h.be_hex_string()))
            .collect::<Vec<_>>().join(" ");
        let tx_proof_list = format!("(list {tx_proof_hashes})");
        
        let tx_str = format!("0x{}", &to_hex(&BtcSerialize(&self.transaction).expect("infallible")));
        let tx_index = self.tx_index;
        let tree_depth = self.tree_depth;

        let invocation = format!("
            (unwrap-panic (mock-add-burnchain-block-header-hash u123 {block_hash}))
            (was-segwit-tx-mined-compact
                u123
                {tx_str}
                {block_header}
                u{tx_index}
                u{tree_depth}
                {tx_proof_list}
                {witness_root}
                {witness_reserved}
                {coinbase_tx}
                {coinbase_proof_list})");

        let Ok(Some(result)) = execute_in_bitcoin_contract(&invocation)
            .inspect_err(|e| m2_warn!("Failed to check Merkle proof: {e:?}"))
        else {
            return false;
        };
        result.expect_result_ok().is_ok()
    }
}

pub fn handle_bitcoin_command(cmd: &str, argv: &mut Vec<String>) -> Result<String, Error> {
    let subcmd = "btc";
    if cmd == "decode-block" {
        if argv.len() < 1 {
            return Err(Error::Failed(format!("Usage: {subcmd} block-or-path-or-stdin"), 1));
        }
        let block_path = &argv[0];
        let block_bytes = if let Ok(bytes) = hex_bytes(block_path) {
            bytes
        }
        else {
            load_from_file_or_stdin(block_path)?
        };

        let decoded_block : BitcoinBlock = BtcDeserialize(&block_bytes) 
            .map_err(|e| Error::Failed(format!("Failed to decode Bitcoin block: {e:?}"), 2))?;

        return Ok(format!("{:#?}", &decoded_block));
    }
    else if cmd == "prove" {
        if argv.len() < 3 {
            return Err(Error::Failed(format!("Usage: {subcmd} txid block-or-path-or-stdin block-height"), 1));
        }
        let reversed_txid = Txid::from_hex(&argv[0])
            .map_err(|e| Error::Failed(format!("Failed to decode txid: {e:?}"), 1))?;
        let txid = {
            // code uses 256-bit integers, which are reversed from what explorers and bitcoin-cli show
            let mut bytes = reversed_txid.0.clone();
            bytes.reverse();
            Txid(bytes)
        };
        let block_path = &argv[1];
        let block_height : u32 = argv[2].parse()
            .map_err(|_e| Error::Failed(format!("Unable to parse '{}' as a block height", &argv[2]), 1))?;
        
        let block_bytes = if let Ok(bytes) = hex_bytes(block_path) {
            bytes
        }
        else {
            load_from_file_or_stdin(block_path)?
        };

        let decoded_block : BitcoinBlock = BtcDeserialize(&block_bytes) 
            .map_err(|e| Error::Failed(format!("Failed to decode Bitcoin block: {e:?}"), 2))?;

        let wtxids : Vec<_> = decoded_block.txdata.iter().map(|tx| Txid(tx.wtxid().0)).collect();
        let txids : Vec<_> = decoded_block.txdata.iter().map(|tx| Txid(tx.txid().0)).collect();
        let tx_index = if let Some(tx_index) = wtxids.iter().position(|id| id == &txid) {
            tx_index
        }
        else if let Some(tx_index) = txids.iter().position(|id| id == &txid) {
            tx_index
        }
        else {
            return Err(Error::Failed(format!("Txid {reversed_txid} not found in block"), 1));
        };

        let proof = BitcoinSegwitMerkleProof::new(&decoded_block, block_height, tx_index)
            .ok_or_else(|| Error::Failed(format!("Unable to build Merkle proof for {reversed_txid}"), 2))?;

        if !proof.check() {
            return Err(Error::Failed(format!("Failed to check that {reversed_txid} belongs to the block"), 2))?;
        }

        return Ok(serde_json::to_string(&proof).map_err(|e| Error::Failed(format!("Failed to serialize proof to JSON: {e:?}"), 2))?);
    }

    Err(Error::Failed(format!("Unrecognized subcommand '{cmd}'"), 1))
}

