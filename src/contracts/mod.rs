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

use clarity::vm::Value;
use clarity::vm::ClarityVersion;

use crate::util::vm::vm_execute;
use crate::util::vm::Error as VmError;

pub const BITCOIN_CONTRACT : &'static str = include_str!("./bitcoin.clar");
pub const SEGWIT_CONTRACT : &'static str = include_str!("./segwit.clar");
pub const WITNESS_SCRIPT_CONTRACT : &'static str = include_str!("./witness.clar");
pub const MAIN_CONTRACT : &'static str = include_str!("./mach2.clar");

pub const DEFAULT_CLARITY_VERSION : ClarityVersion = ClarityVersion::Clarity4;

pub fn execute_in_bitcoin_contract(code: &str) -> Result<Option<Value>, VmError> {
    let full_program = format!("{}\n{}", BITCOIN_CONTRACT, code);
    vm_execute(&full_program, DEFAULT_CLARITY_VERSION)
}

pub fn execute_in_segwit_contract(code: &str) -> Result<Option<Value>, VmError> {
    let full_program = format!("{}\n{}", SEGWIT_CONTRACT, code);
    vm_execute(&full_program, DEFAULT_CLARITY_VERSION)
}

pub fn execute_in_witness_contract(code: &str) -> Result<Option<Value>, VmError> {
    let full_program = format!("{}\n{}", WITNESS_SCRIPT_CONTRACT, code);
    vm_execute(&full_program, DEFAULT_CLARITY_VERSION)
}
