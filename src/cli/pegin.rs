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

use stacks_common::deps_common::bitcoin::blockdata::block::Block as BitcoinBlock;
use stacks_common::deps_common::bitcoin::blockdata::block::BlockHeader as BitcoinBlockHeader;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize as BtcDeserialize;
use stacks_common::deps_common::bitcoin::network::serialize::serialize as BtcSerialize;
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;

use stacks_common::util::hash::{to_hex, hex_bytes, DoubleSha256};
use stacks_common::util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey, MessageSignature};
use stacks_common::types::{PrivateKey, PublicKey};

use crate::bitcoin::{Txid, Wtxid};
use crate::bitcoin::blocks::{TransactionExtensions, BlockExtensions, BitcoinHashExtensions, bitcoin_merkle_tree};

use crate::bitcoin::ops::M2PegIn;
use crate::bitcoin::wallet::UTXOSet;
use crate::cli::Error;
use crate::cli::usage;
use crate::cli::load_from_file_or_stdin;
use crate::cli::crypto::load_secret_key;
use crate::cli::crypto::load_public_key;
use crate::cli::consume_arg;

use serde::{Serialize, Deserialize};
use serde_json;

fn load_utxos(user_pubkey: &Secp256k1PublicKey, path: Option<String>) -> Result<UTXOSet, Error> {
    if let Some(path) = path {
        let bytes = fs::read(&path)
            .map_err(|e| Error::Failed(format!("Failed to read '{path}': {e:?}"), 1))?;

        let utxos: UTXOSet = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Failed(format!("Failed to read UTXO set from '{path}': {e:?}"), 1))?;

        Ok(utxos)
    }
    else {
        Err(Error::Failed("Fetching UTXOs from bitcoind is not yet implemented".to_string(), 1))
    }
}

pub fn handle_pegin_command(cmd: &str, argv: &mut Vec<String>) -> Result<String, Error> {
    todo!()
    /*
    let subcmd = "pegin";
    if cmd == "new" {
        if argv.len() < 4 {
            return Err(Error::Failed(format!("Usage: {subcmd} {cmd} [--utxos /path/to/utxos.json] [--locktime locktime] [--amount amount] user-pubkey cosigner-threshold cosigner-pubkey [cosigner-pubkey...]"), 1));
        }

        let locktime : u32 = argv[0].parse()
            .map_err(|e| Error::Failed(format!("Invalid locktime '{}'", &argv[0]), 1))?;

        let user_pubkey = load_public_key(&argv[1])?;

        let amount : u64 = argv[2].parse()
            .map_err(|e| Error::Failed(format!("Invalid amount '{}'", &argv[2]), 1))?;

        let cosigner_threshold: u8 = argv[3].parse()
            .map_err(|e| Error::Failed(format!("Invalid cosigner threshold '{}': expected u8", &argv[1]), 1))?;
       
        let mut cosigner_pubkeys = vec![];
        for i in 4..argv.len() {
            cosigner_pubkeys.push(load_public_key(&argv[i])?);
        }

        if usize::from(cosigner_threshold) > cosigner_pubkeys.len() {
            return Err(Error::Failed(format!("Cosigner threshold too large: {cosigner_threshold} > {}", cosigner_pubkeys.len()), 1))?;
        }

        let utxo_path_opt = consume_arg(argv, ["utxos"], true)
            .map_err(|e| Error::Failed(e, 1))?;

        let mut utxos = load_utxos(&user_pubkey, &utxo_path_opt)?;

        let pegin = M2PegIn::new(locktime, &user_pubkey, &cosigner_pubkeys, cosigner_threshold, amount);
        let Some(tx) = pegin.make_unsigned_transaction(amount, &mut utxo_set) else {
            return Err(Error::Failed("Failed to produce unsigned transaction from available UTXOs".to_string(), 2));
        };

        // TODO: return witness script, etc. so sign-user can work
        return Ok(to_hex(serialize(&tx).expect("infallible")));
    }
    else if cmd == "sign-user" {
        if argv.len() < 2 {
            return Err(Error::Failed(format!("Usage: {subcmd} {cmd} user-secret-key pegin-psbt"), 1));
        }

        let user_secret_key = load_secret_key(&argv[0])?;
        let pegin_psbt_bytes = hex_bytes(&argv[1])
            .map_err(|e| Error::Failed(format!("Invalid PSBT hex: {e:?}"), 1)))?;

        let pegin_psbt : Transaction = deserialize(&pegin_psbt_bytes)
            .map_err(|e| Error::Failed(format!("Invalid PSBT: {e:?}"), 1)))?;

        let pegin = M2PegIn::from_psbt(&pegin_psbt)
            .map_err(|e| Error::Failed(format!("Invalid pegin PSBT: {e:?}", 1)));
    */
}
