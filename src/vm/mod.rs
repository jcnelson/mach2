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

use std::error;
use std::fmt;

use crate::vm::storage::M2HeadersDB;
use clarity::vm::analysis::AnalysisDatabase;
use clarity::vm::database::BurnStateDB;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::database::HeadersDB;

use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;
use stacks_common::consts::CHAIN_ID_MAINNET;

use clarity::boot_util::boot_code_addr;
use clarity::vm::errors::Error as clarity_error;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ContractName;
use clarity::vm::ClarityVersion;

use crate::vm::storage::Error as DBError;
use crate::vm::storage::M2DB;

pub const STACKS_M2_EPOCH: StacksEpochId = StacksEpochId::Epoch33;

pub mod clarity_vm;
pub mod contracts;
pub mod special;
pub mod storage;

pub use contracts::m2_link_app;

#[cfg(test)]
pub mod tests;

pub const DEFAULT_M2_EPOCH: StacksEpochId = StacksEpochId::Epoch33;
pub const DEFAULT_M2_CLARITY_VERSION: ClarityVersion = ClarityVersion::Clarity4;
pub const DEFAULT_CHAIN_ID: u32 = CHAIN_ID_MAINNET;

pub trait ClarityStorage {
    fn get_clarity_db<'a>(
        &'a mut self,
        headers_db: &'a dyn HeadersDB,
        burn_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a>;
    fn get_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a>;
}

pub struct ClarityVM {
    db: M2DB,
}

#[derive(Debug)]
pub enum Error {
    DB(DBError),
    Clarity(String),
    InvalidInput(String),
    NotInitialized,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::DB(ref e) => write!(f, "DB: {:?}", &e),
            Error::Clarity(ref e) => write!(f, "Clarity: {}", &e),
            Error::InvalidInput(ref e) => write!(f, "Invalid input: {}", &e),
            Error::NotInitialized => write!(f, "System not initialized"),
        }
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Self {
        Self::DB(e)
    }
}

impl From<clarity_error> for Error {
    fn from(e: clarity_error) -> Self {
        Self::Clarity(format!("{:?}", &e))
    }
}

pub const BOOT_BLOCK_ID: StacksBlockId = StacksBlockId([0xff; 32]);
pub const GENESIS_BLOCK_ID: StacksBlockId = StacksBlockId([0x00; 32]);

