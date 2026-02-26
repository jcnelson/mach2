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

use std::io;
use std::io::ErrorKind;
use std::fs;
use std::process;

use stacks_common::util::hash::{to_hex, hex_bytes, DoubleSha256};
use stacks_common::util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey, MessageSignature};
use stacks_common::types::{PrivateKey, PublicKey};

use crate::cli::*;

/// Load a hex string as a secret key
pub fn load_secret_key(sk: &str) -> Result<Secp256k1PrivateKey, Error> {
    let sk_bytes = hex_bytes(&sk)
        .map_err(|e| Error::Failed(format!("Invalid hex string: {e}"), 2))?;
    let sk = Secp256k1PrivateKey::from_slice(&sk_bytes)
        .map_err(|e| Error::Failed(format!("Failed to load private key: {}", &e), 2))?;

    Ok(sk)
}
        
/// Load a hex string as a public key
pub fn load_public_key(pk: &str) -> Result<Secp256k1PublicKey, Error> {    
    let pubkey_bytes = hex_bytes(pk)
        .map_err(|e| Error::Failed(format!("Invalid public key hex: {e:?}"), 1))?;
    let pubkey = Secp256k1PublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| Error::Failed(format!("Invalid public key: {e:?}"), 1))?;
    Ok(pubkey)
}

/// Handle a crypto subcommand
pub fn handle_crypto_command(cmd: &str, argv: &mut Vec<String>) -> Result<String, Error> {
    let subcmd = "crypto";
    if cmd == "generate-sk" {
        let pk = Secp256k1PrivateKey::random();
        let secret_key_str = pk.to_hex();
        let pubkey_str = Secp256k1PublicKey::from_private(&pk).to_hex();
        let key_json = json!({
            "secret": secret_key_str,
            "public": pubkey_str
        });
        return Ok(format!("{}", &key_json));
    }
    if cmd == "public-key" {
        if argv.len() < 1 {
            return Err(Error::Failed(format!("Usage: {} {cmd} PRIVATE_KEY", &subcmd), 1));
        }
        let sk = load_secret_key(&argv[0])?;
        let pubk_str = Secp256k1PublicKey::from_private(&sk).to_hex();
        return Ok(pubk_str);
    }
    if cmd == "sign-btc" {
        // Sign with double-sha256 message hash
        if argv.len() < 2 {
            return Err(Error::Failed(format!("Usage: {} {cmd} PRIVKEY_OR_FILE DATA_OR_FILE", &subcmd), 1));
        }
        if argv[0] == "-" && argv[1] == "-" {
            return Err(Error::Failed("Usage: only one argument can be '-'".into(), 1));
        }

        let sk = match load_secret_key(&argv[0]) {
            Ok(sk) => sk,
            Err(_) => {
                let str_bytes = load_from_file_or_stdin(&argv[0])?;
                load_secret_key(str::from_utf8(&str_bytes).map_err(|e| Error::Failed(format!("Failed to load private key as hex string: {e}"), 2))?)?
            }
        };
        let data = match fs::metadata(&argv[1]) {
            Ok(_) => load_from_file_or_stdin(&argv[1])?,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    // literal
                    argv[1].as_bytes().to_vec()
                },
                _ => {
                    return Err(Error::Failed(format!("Failed to load data: {e}"), 2));
                }
            }
        };

        let sha256d = DoubleSha256::from_data(&data);
        let sig = sk.sign(&sha256d.into_bytes())
            .map_err(|e| Error::Failed(format!("Failed to sign: {}", e), 2))?;
        let rsv = sig.to_rsv();
        return Ok(to_hex(&rsv));
    }
    Err(Error::Failed(format!("Unrecognized subcommand '{cmd}'"), 1))
}
