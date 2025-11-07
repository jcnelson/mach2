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

use std::sync::LazyLock;
use std::sync::Mutex;

use crate::vm::storage::M2DB;
use crate::vm::storage::M2HeadersDB;
use crate::core::with_global_config;
use crate::storage::M2Storage;

use std::ops::Deref;
use std::str;

use crate::util::privkey_to_principal;
use crate::net::stackerdb::run_call_readonly;

use clarity::boot_util::boot_code_addr;
use clarity::boot_util::boot_code_id;
use clarity::vm::contexts::{CallStack, Environment, EventBatch, GlobalContext};
use clarity::vm::contracts::Contract;
use clarity::vm::errors::{Error, InterpreterError};
use clarity::vm::representations::{ClarityName, SymbolicExpression, SymbolicExpressionType};
use clarity::vm::types::{
    ASCIIData, BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData,
    SequenceData, StandardPrincipalData, TupleData, TypeSignature, Value,
};
use clarity::vm::ClarityVersion;
use clarity::vm::ContractContext;

use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::util::hash::{to_hex, Hash160};

pub const M2_ERR_READONLY_FAILURE: u128 = 2000;

pub const M2_ERR_BUFF_TO_UTF8_FAILURE: u128 = 3000;

pub const M2_ERR_STRING_ASCII_TO_STRING_UTF8_FAILURE: u128 = 4000;

fn env_with_global_context<F, A, E>(
    global_context: &mut GlobalContext,
    sender: PrincipalData,
    sponsor: Option<PrincipalData>,
    contract_context: &ContractContext,
    f: F,
) -> std::result::Result<A, E>
where
    E: From<clarity::vm::errors::Error>,
    F: FnOnce(&mut Environment) -> std::result::Result<A, E>,
{
    global_context.begin();

    let result = {
        let mut callstack = CallStack::new();
        let mut exec_env = Environment::new(
            global_context,
            contract_context,
            &mut callstack,
            Some(sender.clone()),
            Some(sender),
            sponsor,
        );
        f(&mut exec_env)
    };
    let _ = global_context.commit()?;
    result
}

/// Make an (err { code: uint, message: (string-ascii 512) })
fn err_ascii_512(code: u128, msg: &str) -> Value {
    Value::error(Value::Tuple(
        TupleData::from_data(vec![
            ("code".into(), Value::UInt(code)),
            (
                "message".into(),
                Value::string_ascii_from_bytes(msg.as_bytes().to_vec())
                    .expect("FATAL: failed to construct value from string-ascii"),
            ),
        ])
        .expect("FATAL: failed to build valid tuple"),
    ))
    .expect("FATAL: failed to construct error tuple")
}

/// Trampoline code for contract-call to `.m2-ll call-readonly`
fn handle_m2_call_readonly(
    global_context: &mut GlobalContext,
    sender: PrincipalData,
    sponsor: Option<PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    args: &[Value],
    m2_lowlevel_contract: Contract,
) -> Result<(), Error> {
    // must be 3 arguments -- contract ID, function name, and the serialized list
    if args.len() != 3 {
        return Err(InterpreterError::InterpreterError(format!(
            "Expected 3 arguments, got {}",
            args.len()
        ))
        .into());
    }

    let contract_id_value = args[0].clone().expect_principal()?;
    let function_name = args[1].clone().expect_ascii()?;
    let args_buff = to_hex(&args[2].clone().expect_buff(102400)?);
    let args_list_value = Value::try_deserialize_hex_untyped(&args_buff).map_err(|e| {
        InterpreterError::InterpreterError(format!("Failed to decode args list: {:?}", &e))
    })?;

    let args_list = args_list_value.expect_list()?;
    let mut args = vec![];
    for (i, arg) in args_list.into_iter().enumerate() {
        let Value::Sequence(SequenceData::Buffer(buff_data)) = arg else {
            return Err(InterpreterError::InterpreterError(format!(
                "Value argument {} is not a serialized value",
                i
            ))
            .into());
        };
        let val_hex = to_hex(&buff_data.data);
        let val = Value::try_deserialize_hex_untyped(&val_hex).map_err(|e| {
            InterpreterError::InterpreterError(
                format!("Failed to decode argument {}: {:?}", i, &e).into(),
            )
        })?;

        m2_debug!("arg: {:?}", &val);
        args.push(val);
    }

    let PrincipalData::Contract(target_contract_id) = contract_id_value else {
        return Err(
            InterpreterError::InterpreterError("Expected contract principal".into()).into(),
        );
    };

    let node_sockaddr_optres = with_global_config(|cfg| {
        M2Storage::resolve_config_node(cfg)
    })
    .expect("FATAL: system not initialized");

    let value = match node_sockaddr_optres {
        Ok(Some(addr)) => {
            // carry out the RPC
            match run_call_readonly(&addr, &target_contract_id, &function_name, &args) {
                Ok(value) => Value::okay(Value::buff_from(value.serialize_to_vec()?).unwrap()).unwrap(),
                Err(e) => err_ascii_512(
                    M2_ERR_READONLY_FAILURE,
                    &format!("mach2: failed call-readonly: {:?}", &e),
                ),
            }
        }
        Ok(None) => {
            // didn't resolve
            err_ascii_512(
                M2_ERR_READONLY_FAILURE,
                "mach2: failed call-readonly: failed to resolve node address".into()
            )
        }
        Err(e) => {
            // some other error
            err_ascii_512(
                M2_ERR_READONLY_FAILURE,
                &format!("mach2: failed call-readonly: {e:?}")
            )
        }
    };

    env_with_global_context(
        global_context,
        sender,
        sponsor,
        &m2_lowlevel_contract.contract_context,
        |env| {
            env.execute_contract_allow_private(
                &contract_id,
                "m2-ll-set-last-call-readonly",
                &[SymbolicExpression::atom_value(value)],
                false,
            )
        },
    )
    .expect("FATAL: failed to set read-only call result");
    Ok(())
}

/// Trampoline code for contract-call to `.m2-ll buff-to-string-utf8`
fn handle_buff_to_string_utf8(
    global_context: &mut GlobalContext,
    sender: PrincipalData,
    sponsor: Option<PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    args: &[Value],
    m2_lowlevel_contract: Contract,
) -> Result<(), Error> {
    // must be one argument
    if args.len() != 1 {
        return Err(InterpreterError::InterpreterError(format!(
            "Expected 1 argument, got {}",
            args.len()
        ))
        .into());
    }

    let hex_buff = args[0].clone().expect_buff(102400)?;
    let value = match std::str::from_utf8(&hex_buff) {
        Ok(s) => Value::okay(Value::string_utf8_from_string_utf8_literal(s.to_string()).unwrap())
            .unwrap(),
        Err(e) => err_ascii_512(
            M2_ERR_BUFF_TO_UTF8_FAILURE,
            &format!("mach2: failed to decode buffer to UTF-8: {:?}", &e),
        ),
    };

    env_with_global_context(
        global_context,
        sender,
        sponsor,
        &m2_lowlevel_contract.contract_context,
        |env| {
            env.execute_contract_allow_private(
                contract_id,
                "m2-ll-set-last-m2-buff-to-string-utf8",
                &[SymbolicExpression::atom_value(value)],
                false,
            )
        },
    )
    .expect("FATAL: failed to set last m2-to-utf8 request");
    Ok(())
}

/// Trampoline code for contract-call to `.m2-ll string-ascii-to-string-utf8`
fn handle_string_ascii_to_string_utf8(
    global_context: &mut GlobalContext,
    sender: PrincipalData,
    sponsor: Option<PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    args: &[Value],
    m2_lowlevel_contract: Contract,
) -> Result<(), Error> {
    // must be one argument
    if args.len() != 1 {
        return Err(InterpreterError::InterpreterError(format!(
            "Expected 1 argument, got {}",
            args.len()
        ))
        .into());
    }

    let ascii_str = args[0].clone().expect_ascii()?;
    let value = if ascii_str.len() < 25600 {
        Value::okay(Value::string_utf8_from_string_utf8_literal(ascii_str).unwrap()).unwrap()
    } else {
        err_ascii_512(
            M2_ERR_STRING_ASCII_TO_STRING_UTF8_FAILURE,
            "m2: failed to convert ASCII to UTF-8: too big",
        )
    };

    env_with_global_context(
        global_context,
        sender,
        sponsor,
        &m2_lowlevel_contract.contract_context,
        |env| {
            env.execute_contract_allow_private(
                contract_id,
                "m2-ll-set-last-m2-string-ascii-to-string-utf8",
                &[SymbolicExpression::atom_value(value)],
                false,
            )
        },
    )
    .expect("FATAL: failed to set last m2-to-utf8 request");
    Ok(())
}

fn get_m2_lowlevel_contract(global_context: &mut GlobalContext) -> Result<Contract, Error> {
    let contract_id = boot_code_id("m2-ll", true);
    let m2_lowlevel_contract = global_context
        .database
        .get_contract(&contract_id)
        .expect("FATAL: could not load mach2 contract metadata (infallible -- this contract is a system contract which should always exist)");

    Ok(m2_lowlevel_contract)
}

pub fn handle_m2_contract_call_special_cases(
    global_context: &mut GlobalContext,
    sender: Option<&PrincipalData>,
    sponsor: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    result: &Value,
) -> Result<(), Error> {
    if *contract_id != boot_code_id("m2-ll", true) {
        return Ok(());
    }

    m2_debug!(
        "Run special-case handler for {}.{}: {:?} --> {:?}",
        contract_id,
        function_name,
        args,
        result
    );

    let sender = match sender {
        Some(s) => s.clone(),
        None => boot_code_addr(true).into(),
    };
    let sponsor = sponsor.cloned();

    match function_name {
        "m2-ll-call-readonly" => {
            let m2_lowlevel_contract = get_m2_lowlevel_contract(global_context)?;
            handle_m2_call_readonly(
                global_context,
                sender,
                sponsor,
                contract_id,
                args,
                m2_lowlevel_contract,
            )?;
        }
        "m2-ll-buff-to-string-utf8" => {
            let m2_lowlevel_contract = get_m2_lowlevel_contract(global_context)?;
            handle_buff_to_string_utf8(
                global_context,
                sender,
                sponsor,
                contract_id,
                args,
                m2_lowlevel_contract,
            )?;
        }
        "m2-ll-string-ascii-to-string-utf8" => {
            let m2_lowlevel_contract = get_m2_lowlevel_contract(global_context)?;
            handle_string_ascii_to_string_utf8(
                global_context,
                sender,
                sponsor,
                contract_id,
                args,
                m2_lowlevel_contract,
            )?;
        }
        _ => {}
    }
    Ok(())
}

