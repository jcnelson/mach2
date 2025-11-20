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

#[macro_use]
pub mod log;
#[macro_use]
pub mod sqlite;
pub mod string;
pub mod tx;

use clarity::vm::types::StandardPrincipalData;
use stacks_common::util::hash::Hash160;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

/// convert a private key into a standard principal
pub fn privkey_to_principal(privk: &Secp256k1PrivateKey, version: u8) -> StandardPrincipalData {
    let pubk = Secp256k1PublicKey::from_private(privk);
    let h = Hash160::from_node_public_key(&pubk);
    StandardPrincipalData::new(version, h.0).expect("FATAL: invalid version")
}

