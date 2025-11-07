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

#![allow(deprecated)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

#[macro_use]
pub mod util;

extern crate bitcoin;
extern crate clarity_types;
extern crate lzma_rs;
extern crate rand;
extern crate regex;
extern crate rusqlite;
#[macro_use]
extern crate stacks_common;
extern crate toml;
extern crate url;

pub mod core;
pub mod net;
pub mod storage;
pub mod vm;

use std::io;
use std::io::ErrorKind;
use std::fs;
use std::env;
use std::process;
use std::io::{stdin, Read};

use crate::core::with_global_config;
use crate::storage::mock::LocalStackerDBConfig;
use crate::storage::mock::LocalStackerDBClient;

use stacks_common::util::hash::{to_hex, hex_bytes, DoubleSha256};
use stacks_common::util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey, MessageSignature};
use stacks_common::types::{PrivateKey, PublicKey};

use clarity_types::types::QualifiedContractIdentifier;

pub enum Error {
    Failed(String, i32)
}

/// Consume a string and an optional argument (if `has_optarg` is true) from `args`.
/// `argnames` contains the list of argument names to search for
pub fn consume_arg(
    args: &mut Vec<String>,
    argnames: &[&str],
    has_optarg: bool,
) -> Result<Option<String>, String> {
    if let Some(ref switch) = args
        .iter()
        .find(|ref arg| argnames.iter().find(|ref argname| argname == arg).is_some())
    {
        let idx = args
            .iter()
            .position(|ref arg| arg == switch)
            .expect("BUG: did not find the thing that was just found");
        let argval = if has_optarg {
            // following argument is the argument value
            if idx + 1 < args.len() {
                Some(args[idx + 1].clone())
            } else {
                // invalid usage -- expected argument
                return Err("Expected argument".to_string());
            }
        } else {
            // only care about presence of this option
            Some("".to_string())
        };

        args.remove(idx);
        if has_optarg {
            // also clear the argument
            args.remove(idx);
        }
        Ok(argval)
    } else {
        // not found
        Ok(None)
    }
}

/// get data from stdin or a file
pub fn load_from_file_or_stdin(path: &str) -> Result<Vec<u8>, Error> {
    let data = if path == "-" {
        let mut fd = stdin();
        let mut bytes = vec![];
        fd.read_to_end(&mut bytes)
            .map_err(|e| {
                Error::Failed(format!("Failed to load from stdin: {e:?}"), 127)
            })?;
        bytes
    } else {
        if let Err(e) = fs::metadata(path) {
            return Err(Error::Failed(format!("Failed to open '{path}': {e:?}"), 127));
        }
        fs::read(path)
            .map_err(|e| {
                Error::Failed(format!("Failed to read from '{path}': {e:?}"), 127)
            })?
    };
    Ok(data)
}

pub fn usage(msg: &str, code: i32) {
    let args: Vec<_> = env::args().collect();
    if msg.len() > 0 {  
        eprintln!("{}", msg);
    }
    else {
        eprintln!("Usage: {} command [options]", &args[0]);
    }
    process::exit(code);
}

/// Load a hex string as a secret key
/// Returns whether or not it is compressed
pub fn load_secret_key(sk: &str) -> Result<Secp256k1PrivateKey, Error> {
    let sk_bytes = hex_bytes(&sk)
        .map_err(|e| Error::Failed(format!("Invalid hex string: {e}"), 2))?;
    let sk = Secp256k1PrivateKey::from_slice(&sk_bytes)
        .map_err(|e| Error::Failed(format!("Failed to load private key: {}", &e), 2))?;

    Ok(sk)
}

/// Handle a crypto subcommand
fn handle_crypto_command(cmd: &str, argv: &mut Vec<String>) -> Result<String, Error> {
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
    if cmd == "pubk" {
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

/// get the contract ID from either argv or from the config file
fn stackerdb_get_address(argv: &mut Vec<String>) -> Result<QualifiedContractIdentifier, Error> {
    let addr_str = if let Some(addr_str) = consume_arg(argv, &["-s", "--stackerdb_addr"], true)
        .map_err(|_e| {
            Error::Failed("Missing -s|--stackerdb_addr".into(), 1)
        })?
    {
        addr_str
    } else {
        with_global_config(|cfg| cfg.default_storage_addr().to_string())
            .ok_or_else(|| {
                Error::Failed("Failed to load default storage address -- not initialized".into(), 2)
            })?
    };

    let addr = QualifiedContractIdentifier::parse(&addr_str)
        .map_err(|_e| {
            Error::Failed(format!("Invalid contract address '{}'", addr_str), 1)
        })?;

    Ok(addr)
}

/// Handle a StackerDB command
fn handle_stackerdb_command(cmd: &str, argv: &mut Vec<String>) -> Result<String, Error> {
    let subcmd = "stackerdb";
    if cmd == "mock" {
        if argv.len() < 2 {
            eprintln!(
                "Usage: {subcmd} {cmd} /path/to/config.json /path/to/db.sqlite",
            );
            process::exit(1);
        }

        let json = &argv[1];
        let path = &argv[2];
        let config_json = load_from_file_or_stdin(json)?;
        let config: LocalStackerDBConfig =
            serde_json::from_slice(&config_json)
                .map_err(|e| Error::Failed(format!("Failed to decode config: {e:?}"), 2))?;

        if std::fs::metadata(path).is_ok() {
            let _ = std::fs::remove_file(path)
                .map_err(|e| Error::Failed(format!("Failed to remove '{path}': {e:?}"), 2))?;
        }

        let _ = LocalStackerDBClient::open_or_create(path, config)
            .map_err(|e| Error::Failed(format!("Failed to create mock StackerDB at {path}: {e:?}"), 2))?;

        return Ok("Database created".into());
    }
    else if cmd == "get-chunk" {
        let storage_addr = stackerdb_get_address(argv)?;
        if argv.len() < 1 {
            eprintln!(
                "Usage: {subcmd} {cmd} [-s stackerdb_addr] SLOT_NUM",
            );
            process::exit(1);
        }
        let slot_num: u32 = argv[0]
            .parse()
            .map_err(|e| Error::Failed(format!("Could not parse slot '{}': {:?}", &argv[0], &e), 1))?;

        /*
        wrbpod_open_session(&wrbpod_addr)
            .map_err(|e| {
                eprintln!("FATAL: {}", &e);
                process::exit(1);
            })
            .unwrap();

        let slot = with_globals(|globals| {
            let wrbpod_session = globals.get_wrbpod_session_by_address(&wrbpod_addr).unwrap();
            let chunk_data_opt = wrbpod_session
                .get_and_verify_raw_chunk(slot_num)
                .map_err(|e| {
                    eprintln!("FATAL: failed to fetch chunk: {:?}", &e);
                    process::exit(1);
                })
                .unwrap();

            chunk_data_opt
        });

        if let Some(slot) = slot {
            println!("{}", &to_hex(&slot));
        } else {
            eprintln!("No such slot");
        }
        return;
        */
        return Ok("".to_string());
    }
    Err(Error::Failed(format!("Unrecognized command '{cmd}'"), 1))
}


fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        usage("", 1);
    }

    let cmd = argv[1].clone();
    let res = if cmd == "crypto" {
        if argv.len() < 3 {
            usage("", 1);
        }
        let subcommand = argv[2].clone();
        handle_crypto_command(&subcommand, &mut argv[3..].to_vec())
    }
    else if cmd == "stackerdb" {
        if argv.len() < 3 {
            usage("", 1);
        }
        let subcommand = argv[2].clone();
        handle_stackerdb_command(&subcommand, &mut argv[3..].to_vec())
    }
    else {
        usage(&format!("Unrecognized command '{cmd}'"), 1);
        unreachable!();
    };

    match res {
        Ok(res) => {
            println!("{}", res);
            process::exit(0);
        }
        Err(Error::Failed(msg, exit_code)) => {
            usage(&msg, exit_code);
        }
    }
}
