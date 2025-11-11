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

pub mod config;
pub mod globals;

use crate::core::globals::{Globals, GLOBALS};

pub use crate::core::config::Config;

/// Initialize global config
pub fn init(mainnet: bool, node_host: &str, node_port: u16) {
    match GLOBALS.lock() {
        Ok(mut globals) => {
            globals.set_config(Config::new(mainnet, node_host.to_string(), node_port));
        }
        Err(_e) => {
            m2_error!("FATAL: global mutex poisoned");
            panic!();
        }
    }
}

/// Initialize global config with config
pub fn init_config(conf: Config) {
    match GLOBALS.lock() {
        Ok(mut globals) => {
            globals.set_config(conf);
        }
        Err(_e) => {
            m2_error!("FATAL: global mutex poisoned");
            panic!();
        }
    }
}

pub fn with_globals<F, R>(func: F) -> R
where
    F: FnOnce(&mut Globals) -> R,
{
    match GLOBALS.lock() {
        Ok(mut globals) => func(&mut (*globals)),
        Err(_e) => {
            m2_error!("FATAL: global mutex poisoned");
            panic!();
        }
    }
}

pub fn with_global_config<F, R>(func: F) -> Option<R>
where
    F: FnOnce(&Config) -> R,
{
    with_globals(|globals| globals.config.as_ref().map(|cfg| func(cfg)))
}
