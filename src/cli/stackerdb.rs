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
use std::process;

use crate::core::with_global_config;
use crate::storage::mock::LocalStackerDBConfig;
use crate::storage::mock::LocalStackerDBClient;

use stacks_common::util::hash::{to_hex, DoubleSha256};

use clarity_types::types::QualifiedContractIdentifier;

use crate::cli::*;

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
pub fn handle_stackerdb_command(cmd: &str, argv: &mut Vec<String>) -> Result<String, Error> {
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

        if fs::metadata(path).is_ok() {
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

