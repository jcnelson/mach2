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

use std::convert::From;
use std::error;
use std::fmt;
use std::io::Error as io_error;

use sha2::{Digest, Sha256};

use clarity::{
    vm::analysis,
    vm::analysis::{errors::CheckError, ContractAnalysis},
    vm::ast::build_ast,
    vm::contexts::OwnedEnvironment,
    vm::costs::LimitedCostTracker,
    vm::database::NULL_BURN_STATE_DB,
    vm::errors::{Error as ClarityVMError, RuntimeErrorType},
    vm::representations::ClarityName,
    vm::types::{QualifiedContractIdentifier, StandardPrincipalData},
    vm::ContractName,
    vm::SymbolicExpression,
};
use rusqlite::Connection;
use rusqlite::Error as sqlite_error;

use stacks_common::util::log;

use crate::vm::BOOT_BLOCK_ID;
use crate::vm::GENESIS_BLOCK_ID;
use crate::vm::storage;

use crate::vm::{DEFAULT_M2_CLARITY_VERSION, DEFAULT_M2_EPOCH, DEFAULT_CHAIN_ID};

use clarity::boot_util::boot_code_addr;
use clarity::vm::analysis::AnalysisDatabase;
use clarity::vm::ast;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::database::BurnStateDB;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::database::HeadersDB;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::eval_all;
use clarity::vm::ClarityVersion;
use clarity::vm::ContractContext;
use clarity::vm::Value;

use crate::vm::storage::util::*;
use crate::vm::storage::ReadOnlyM2Store;
use crate::vm::storage::WritableM2Store;
use crate::vm::storage::{M2DB, M2HeadersDB};
use crate::vm::ClarityStorage;
use crate::vm::ClarityVM;

use crate::vm::Error;

use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::hash::to_hex;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::Sha256Sum;

use crate::vm::contracts::M2_LL_CODE;
use crate::vm::m2_link_app;

/// Parse contract code, given the identifier.
/// TODO: add pass(es) to remove unusable Clarity keywords
pub fn parse(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
) -> Result<Vec<SymbolicExpression>, ClarityVMError> {
    let ast = build_ast(
        contract_identifier,
        source_code,
        &mut (),
        DEFAULT_M2_CLARITY_VERSION,
        DEFAULT_M2_EPOCH,
    )
    .map_err(|e| RuntimeErrorType::ASTError(Box::new(e)))?;
    Ok(ast.expressions)
}

/// Analyze parsed contract code, without cost limits
pub fn run_analysis_free<C: ClarityStorage>(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    clarity_kv: &mut C,
    save_contract: bool,
) -> Result<ContractAnalysis, Box<(CheckError, LimitedCostTracker)>> {
    analysis::run_analysis(
        contract_identifier,
        expressions,
        &mut clarity_kv.get_analysis_db(),
        save_contract,
        LimitedCostTracker::new_free(),
        DEFAULT_M2_EPOCH,
        DEFAULT_M2_CLARITY_VERSION,
        false,
    )
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

impl ClarityStorage for WritableM2Store<'_> {
    fn get_clarity_db<'a>(
        &'a mut self,
        headers_db: &'a dyn HeadersDB,
        burn_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        self.as_clarity_db(headers_db, burn_db)
    }

    fn get_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
        self.as_analysis_db()
    }
}

impl ClarityStorage for ReadOnlyM2Store<'_> {
    fn get_clarity_db<'a>(
        &'a mut self,
        headers_db: &'a dyn HeadersDB,
        burn_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        self.as_clarity_db(headers_db, burn_db)
    }

    fn get_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
        self.as_analysis_db()
    }
}

impl ClarityVM {
    pub fn new(db_path: &str, contract_id: &QualifiedContractIdentifier) -> Result<ClarityVM, Error> {
        let m2db = M2DB::open(db_path, contract_id, None)?;

        let vm = ClarityVM {
            db: m2db,
        };
        Ok(vm)
    }

    /// Start working on the next m2 contract-call
    pub fn begin_m2_contract_call<'a>(&'a mut self) -> Result<WritableM2Store<'a>, Error> {
        let cur_tip = get_m2_chain_tip(self.db.conn());
        let cur_height = get_m2_block_height(self.db.conn(), &cur_tip).expect(&format!(
            "FATAL: failed to determine height of {}",
            &cur_tip
        ));
        let next_tip = make_m2_chain_tip(cur_height + 1);

        m2_debug!(
            "Begin contract call {},{} -> {},{}",
            &cur_tip,
            cur_height,
            &next_tip,
            cur_height + 1
        );

        let write_tx = self.db.begin(&cur_tip, &next_tip);
        Ok(write_tx)
    }

    /// Start working on the next m2 contract-call, but in a read-only manner
    pub fn begin_read_only<'a>(&'a mut self) -> ReadOnlyM2Store<'a> {
        let cur_tip = get_m2_chain_tip(self.db.conn());
        self.db.begin_read_only(Some(&cur_tip))
    }

    /// Instantiate a HeadersDB
    pub fn headers_db(&self) -> M2HeadersDB {
        self.db.headers_db()
    }

    /// Set up a mach2 smart contract
    pub fn initialize_m2_contract(&mut self, name: &str, m2_code: &str) -> Result<QualifiedContractIdentifier, Error> {
        let linked_m2_code = m2_link_app(m2_code);

        let m2_contract_id = QualifiedContractIdentifier::new(
            boot_code_addr(true).into(),
            ContractName::try_from(name)
                .map_err(|_| Error::Clarity("Invalid contract name".into()))?
        );

        let ll_contract_id = QualifiedContractIdentifier::new(
            boot_code_addr(true).into(),
            ContractName::try_from("m2-ll".to_string()).unwrap(),
        );

        let headers_db = self.headers_db();
        let mut write_tx = self.db.begin(&BOOT_BLOCK_ID, &GENESIS_BLOCK_ID);

        // sanity check -- don't do this more than once
        let mut db = write_tx.get_clarity_db(&headers_db, &NULL_BURN_STATE_DB);
        db.begin();
        let has_ll_contract = db.has_contract(&ll_contract_id);
        let has_m2_contract = db.has_contract(&m2_contract_id);
        db.roll_back()?;

        if !has_ll_contract {
            m2_debug!(
                "Instantiate m2-ll code to contract '{}' ({} bytes)...",
                &m2_contract_id,
                linked_m2_code.len(),
            );

            let mut ast = parse(&ll_contract_id, &M2_LL_CODE)?;

            m2_debug!("Analyze m2-ll contract {}", &ll_contract_id);
            run_analysis_free(&ll_contract_id, &mut ast, &mut write_tx, true)
                .map_err(|boxed_error| Error::Clarity(format!("Analysis: {:?}", &boxed_error.0)))?;

            let mut db = write_tx.get_clarity_db(&headers_db, &NULL_BURN_STATE_DB);
            db.begin();
            let mut vm_env =
                OwnedEnvironment::new_free(true, DEFAULT_CHAIN_ID, db, DEFAULT_M2_EPOCH);

            m2_debug!("Deploy m2-ll contract {}", &ll_contract_id);
            vm_env.initialize_versioned_contract(
                ll_contract_id.clone(),
                DEFAULT_M2_CLARITY_VERSION,
                &M2_LL_CODE,
                None,
            )?;

            let (mut db, _) = vm_env
                .destruct()
                .expect("Failed to recover database reference after executing transaction");

            db.commit()?;
        }

        if !has_m2_contract {
            m2_debug!(
                "Instantiate mach2 code to contract '{}' ({} bytes)...",
                &m2_contract_id,
                linked_m2_code.len(),
            );

            let mut ast = parse(&m2_contract_id, &linked_m2_code)?;

            m2_debug!("Analyze linked Mach2 contract {}", &m2_contract_id);
            run_analysis_free(&m2_contract_id, &mut ast, &mut write_tx, true)
                .map_err(|boxed_error| Error::Clarity(format!("Analysis: {:?}", &boxed_error.0)))?;

            let mut db = write_tx.get_clarity_db(&headers_db, &NULL_BURN_STATE_DB);
            db.begin();
            let mut vm_env =
                OwnedEnvironment::new_free(true, DEFAULT_CHAIN_ID, db, DEFAULT_M2_EPOCH);

            m2_debug!("Deploy linked mach2 contract {}", &m2_contract_id);
            vm_env.initialize_versioned_contract(
                m2_contract_id.clone(),
                DEFAULT_M2_CLARITY_VERSION,
                &linked_m2_code,
                None,
            )?;

            let (mut db, _) = vm_env
                .destruct()
                .expect("Failed to recover database reference after executing transaction");
            db.commit()?;
        }

        write_tx.commit_to(&GENESIS_BLOCK_ID)?;

        m2_debug!("Initialized mach2 code to contract '{}'", &m2_contract_id);

        Ok(m2_contract_id)
    }
}

