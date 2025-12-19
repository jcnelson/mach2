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

extern crate clarity_types;
extern crate lzma_rs;
extern crate rand;
extern crate regex;
extern crate rusqlite;

#[macro_use]
extern crate stacks_common;
extern crate toml;
extern crate url;

pub mod bitcoin;
pub mod cli;
pub mod core;
pub mod events;
pub mod net;
pub mod storage;
#[cfg(test)]
pub mod tests;

use std::env;
use std::process;

use crate::cli::{
    Error,
    handle_bitcoin_command,
    handle_crypto_command,
    handle_pegin_command,
    handle_stackerdb_command,
    usage
};

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        usage("", 1);
    }

    let cmd = argv[1].clone();

    let res = if cmd == "btc" {
        if argv.len() < 3 {
            usage("", 1);
        }
        let subcommand = argv[2].clone();
        handle_bitcoin_command(&subcommand, &mut argv[3..].to_vec())
    }
    else if cmd == "crypto" {
        if argv.len() < 3 {
            usage("", 1);
        }
        let subcommand = argv[2].clone();
        handle_crypto_command(&subcommand, &mut argv[3..].to_vec())
    }
    else if cmd == "pegin" {
        if argv.len() < 3 {
            usage("", 1);
        }
        let subcommand = argv[2].clone();
        handle_pegin_command(&subcommand, &mut argv[3..].to_vec())
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
