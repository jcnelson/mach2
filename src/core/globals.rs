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

use crate::core::config::Config;
use std::sync::Mutex;

/// Globally-accessible state that is hard to pass around otherwise
pub struct Globals {
    pub config: Option<Config>,
}

impl Default for Globals {
    fn default() -> Globals {
        Globals {
            config: None,
        }
    }
}

impl Globals {
    pub fn new() -> Globals {
        Globals::default()
    }

    pub fn get_config(&self) -> Config {
        self.config.clone().expect("FATAL: config not initialized")
    }

    pub fn config_ref(&self) -> &Config {
        self.config.as_ref().expect("FATAL: config not initialized")
    }

    pub fn config_mut(&mut self) -> &mut Config {
        self.config.as_mut().expect("FATAL: config not initialized")
    }

    pub fn set_config(&mut self, conf: Config) {
        self.config = Some(conf);
    }
}

lazy_static! {
    pub static ref GLOBALS: Mutex<Globals> = Mutex::new(Globals {
        config: None,
    });
}

