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

use std::fmt;

use clarity::{
    vm::ast,
    vm::costs::LimitedCostTracker,
    vm::types::QualifiedContractIdentifier,
};
use clarity::vm::ClarityVersion;
use clarity::vm::ContractContext;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::eval_all;
use clarity::vm::types::Value;
use clarity::vm::errors::Error as clarity_error;

use stacks_common::types::StacksEpochId;
use stacks_common::consts::CHAIN_ID_MAINNET;

pub const DEFAULT_M2_EPOCH: StacksEpochId = StacksEpochId::Epoch33;
pub const DEFAULT_CHAIN_ID: u32 = CHAIN_ID_MAINNET;

#[derive(Debug)]
pub enum Error {
    Clarity(String),
    InvalidInput(String),
    NotInitialized,
    ContractAlreadyExists,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Clarity(ref e) => write!(f, "Clarity: {}", &e),
            Error::InvalidInput(ref e) => write!(f, "Invalid input: {}", &e),
            Error::NotInitialized => write!(f, "System not initialized"),
            Error::ContractAlreadyExists => write!(f, "Contract already exists"),
        }
    }
}

impl From<clarity_error> for Error {
    fn from(e: clarity_error) -> Self {
        Self::Clarity(format!("{:?}", &e))
    }
}

/// Execute program in a transient environment.
pub fn vm_execute(program: &str, clarity_version: ClarityVersion) -> Result<Option<Value>, Error> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone(), clarity_version);
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(
        true,
        DEFAULT_CHAIN_ID,
        conn,
        LimitedCostTracker::new_free(),
        DEFAULT_M2_EPOCH,
    );
    Ok(global_context.execute(|g| {
        let parsed = ast::build_ast(
            &contract_id,
            program,
            &mut (),
            clarity_version,
            DEFAULT_M2_EPOCH,
        )?
        .expressions;
        eval_all(&parsed, &mut contract_context, g, None)
    })?)
}
