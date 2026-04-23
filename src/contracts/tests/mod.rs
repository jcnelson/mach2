// Copyright (C) 2026 Trust Machines
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
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use clarity_types::Value;
use serde::Deserialize;
use serde_json;

use crate::contracts::{
    execute_in_bitcoin_contract,
    execute_in_segwit_contract,
    execute_in_witness_contract,
    execute_in_scbtc_contract
};

use crate::contracts::{
    BITCOIN_CONTRACT,
    SEGWIT_CONTRACT,
    WITNESS_SCRIPT_CONTRACT,
    OUTCOMES_CONTRACT,
    MAIN_CONTRACT,
};

mod check_utxo_exists_and_is_claimable;
mod decode_wtx;
mod inner_add_contract_transfer_outcome;
mod inner_complete_transfer;
mod inner_create_contract_transfer_outcome;
mod inner_register_pegin;
mod inner_register_pegin_utxo;
mod parse_and_store_wtx;

const DUMMY_CONTRACT_ADDRESS: &'static str = "ST31C544NBN85PKN6MXS59SFDVR5XTN1GZKG7KTPT";

#[test]
fn test_segwit_hello_world() {
    let value = execute_in_segwit_contract(false, "u1").unwrap();
    assert_eq!(value.unwrap().expect_u128().unwrap(), 1u128);
}

#[test]
fn test_bitcoin_hello_world() {
    let value = execute_in_bitcoin_contract(false, "u1").unwrap();
    assert_eq!(value.unwrap().expect_u128().unwrap(), 1u128);
}

#[test]
fn test_witness_hello_world() {
    let value = execute_in_witness_contract(false, "u1").unwrap();
    assert_eq!(value.unwrap().expect_u128().unwrap(), 1u128);
}

#[test]
fn test_scbtc_hello_world() {
    let value = execute_in_scbtc_contract(false, "u1").unwrap();
    assert_eq!(value.unwrap().expect_u128().unwrap(), 1u128);
}

pub struct ClarityTester {
    clarity_cli: String,
    db_dir: String
}

pub struct ClarityTest {
    test_name: String,
    test_code: String,
    db_path: String,
    clarity_cli: String,
}

impl ClarityTester {
    pub fn new(clarity_cli: &str, db_dir: &str) -> Self {
        Self {
            clarity_cli: clarity_cli.to_string(),
            db_dir: db_dir.to_string()
        }
    }

    pub fn load(&self, test_name: &str, test_code: &str) -> ClarityTest {
        let test = ClarityTest {
            clarity_cli: self.clarity_cli.clone(),
            test_name: test_name.to_string(),
            test_code: test_code.to_string(),
            db_path: format!("{}/{}.db", self.db_dir, test_name)
        };
        if fs::metadata(&test.db_path).is_ok() {
            fs::remove_dir_all(&test.db_path).unwrap();
        }
        test
    }
}

fn err_or_debug(error: bool, msg: &str) {
    if error {
        m2_error!("{}", msg);
    }
    else {
        m2_debug!("{}", msg);
    }
}

#[derive(Debug, Deserialize)]
struct ClarityExecOutput {
    message: String,
    success: bool,
    output_serialized: String
}

#[derive(Debug, Deserialize)]
struct ClarityEvents {
    events: Vec<ClarityTransactionResult>,
    message: String,
    success: bool,
    output_serialized: String
}

#[derive(Debug, Deserialize)]
struct ClarityTransactionResult {
    committed: bool,
    contract_event: ClarityContractEvent,
    event_index: usize,
    txid: String,
    r#type: String
}

#[derive(Debug, Deserialize)]
struct ClarityContractEvent {
    contract_identifier: String,
    raw_value: String,
    topic: String,
    // omit value, since we can deserialize it ourselves
}

impl ClarityTest {
    fn check_aborted(s: &str) -> Option<ClarityExecOutput> {
        let output : ClarityExecOutput = serde_json::from_str(s).ok()?;
        if output.success {
            return None;
        }
        if output.message != "Aborted" {
            return None;
        }
        Some(output)
    }

    fn try_extract_print_events(s: &str) -> Option<Vec<String>> {
        let events : ClarityEvents = serde_json::from_str(s).ok()?;
        let mut print_events = vec![];
        for event in events.events.iter() {
            if event.r#type != "contract_event" {
                continue;
            }
            if event.contract_event.topic != "print" {
                continue;
            }
            let val = Value::try_deserialize_hex_untyped(&event.contract_event.raw_value)
                .map_err(|e| {
                    m2_warn!("Failed to decode `print` value {}: {e:?}", &event.contract_event.raw_value);
                })
                .ok()?;

            print_events.push(val.to_string());
        }

        if print_events.len() > 0 {
            Some(print_events)
        }
        else {
            None
        }
    }

    fn check_output(out_buf: &[String], err_buf: &[String]) -> Option<ClarityEvents> {
        for out in out_buf.iter().chain(err_buf.iter()) {
            if Self::check_aborted(out).is_some() {
                panic!("clarity-cli aborted: {out}");
            }
            if let Some(events) = serde_json::from_str(out).ok() {
                return Some(events);
            }
        }
        None
    }

    fn dump_output(error: bool, out_buf: &[String], err_buf: &[String]) {
        err_or_debug(error, "Stdout:");
        for out_line in out_buf.iter() {
            if let Some(print_events) = Self::try_extract_print_events(out_line) {
                err_or_debug(error, "- Print events:");
                for print_event in print_events.into_iter() {
                    err_or_debug(error, &format!("   {print_event}"));
                }
                err_or_debug(error, "");
                err_or_debug(error, "- Raw output:");
                err_or_debug(error, &format!("   {out_line}"));
            }
            else {
                err_or_debug(error, &format!("   {out_line}"));
            }
        }

        err_or_debug(error, "");
        err_or_debug(error, "Stderr:");
        for err_line in err_buf.iter() {
            if let Some(print_events) = Self::try_extract_print_events(err_line) {
                err_or_debug(error, "- Print events:");
                for print_event in print_events.into_iter() {
                    err_or_debug(error, &format!("   {print_event}"));
                }
                err_or_debug(error, "");
                err_or_debug(error, "- Raw output:");
                err_or_debug(error, &format!("   {err_line}"));
            }
            else {
                err_or_debug(error, &format!("   {err_line}"));
            }
        }

        err_or_debug(error, "");
    }

    fn run_clarity_cli(&self, args: &[&str]) -> Option<ClarityEvents> {
        let mut command = Command::new(&self.clarity_cli);
        command.args(args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        m2_debug!("Run: `{command:?}`");

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                m2_error!("Failed to run `{command:?}`: {e:?}");
                panic!();
            }
        };

        let mut out_reader = BufReader::new(process.stdout.take().unwrap());
        let mut err_reader = BufReader::new(process.stderr.take().unwrap());

        let mut out_buf = vec![];
        let mut err_buf = vec![];

        loop {
            let mut out_line = String::new();
            let mut err_line = String::new();

            let out_bytes_read = match out_reader.read_line(&mut out_line) {
                Ok(nr) => nr,
                Err(e) => {
                    m2_error!("Failed to read stdout from `{command:?}`: {e:?}");
                    panic!();
                }
            };

            if out_bytes_read > 0 {
                out_buf.push(out_line);
            }

            let err_bytes_read = match err_reader.read_line(&mut err_line) {
                Ok(nr) => nr,
                Err(e) => {
                    m2_error!("Failed to read stderr from `{command:?}`: {e:?}");
                    panic!();
                }
            };
            
            if err_bytes_read > 0 {
                err_buf.push(err_line);
            }

            if let Some(exit_code) = process.try_wait().unwrap_or_else(|e| {
                m2_error!("try_wait() failed on `{command:?}`: {e:?}");
                panic!()
            }) {
                if exit_code.code().is_none() {
                    m2_error!("Command terminated by signal: `{command:?}`");
                    Self::dump_output(true, &out_buf, &err_buf);
                    panic!();
                }
                else if exit_code.code() != Some(0) {
                    m2_error!("Command failed with exit code {exit_code:?}: `{command:?}`");
                    Self::dump_output(true, &out_buf, &err_buf);
                    panic!();
                }
                break;
            }

            if out_bytes_read == 0 && err_bytes_read == 0 {
                break;
            }
        }

        Self::dump_output(false, &out_buf, &err_buf);
        Self::check_output(&out_buf, &err_buf)
    }

    fn dummy_contract_id(name: &str) -> String {
        format!("{DUMMY_CONTRACT_ADDRESS}.{name}")
    }

    fn deploy(&self) {
        self.run_clarity_cli(&["initialize", "--testnet", &self.db_path]);

        let bitcoin_code_path = format!("{}/bitcoin.clar", &self.db_path);
        let mut f = fs::File::create(&bitcoin_code_path).unwrap();
        f.write_all(BITCOIN_CONTRACT.as_bytes()).unwrap();
        drop(f);
        
        let bitcoin_contract = Self::dummy_contract_id("bitcoin");
        let mach2_contract = Self::dummy_contract_id("mach2");

        self.run_clarity_cli(&["check", &bitcoin_code_path, "--contract-id", &bitcoin_contract, &self.db_path]);
        self.run_clarity_cli(&["launch", &bitcoin_contract, &bitcoin_code_path, &self.db_path]);

        let full_code = format!("{}\n{}\n{}\n{}\n\n;; ============= Test begin =============\n\n{}",
            SEGWIT_CONTRACT,
            WITNESS_SCRIPT_CONTRACT,
            OUTCOMES_CONTRACT,
            MAIN_CONTRACT,
            &self.test_code
        );

        let test_code_path = format!("{}/code.clar", &self.db_path);
        let mut f = fs::File::create(&test_code_path).unwrap();
        f.write_all(full_code.as_bytes()).unwrap();
        drop(f);

        self.run_clarity_cli(&["check", &test_code_path, "--contract-id", &mach2_contract, &self.db_path]);
        self.run_clarity_cli(&["launch", &mach2_contract, &test_code_path, &self.db_path]);
    }

    fn execute_test(&self, tx_sender: Option<&str>) {
        let dummy_contract = Self::dummy_contract_id("mach2");
        self.run_clarity_cli(&["execute", &dummy_contract, "test", tx_sender.unwrap_or(DUMMY_CONTRACT_ADDRESS), &self.db_path]);
        let events = self.run_clarity_cli(&["execute", &dummy_contract, "check-success?", tx_sender.unwrap_or(DUMMY_CONTRACT_ADDRESS), &self.db_path]).unwrap();
        if events.output_serialized != "03" {
            // "0x03" means "true"
            panic!("Test failed: {:?}", &events);
        }
    }

    pub fn run(&self, tx_sender: Option<&str>) {
        self.deploy();
        self.execute_test(tx_sender)
    }
}

fn run_clarity_test(test_name: &str, test_code: &str) {
    let tester = ClarityTester::new("clarity-cli", "/tmp/mach2-tests/clarity");
    let test = tester.load(test_name, test_code);
    test.run(None);
}

#[macro_export]
macro_rules! clarity_test {
    ($FuncName:ident, $Generator:expr) => {
        #[test]
        fn $FuncName() {
            let generated_code = $Generator;
            let test_harness = r#"
(define-data-var test-success__ bool true)
(define-data-var test-fail-msg__ (string-ascii 1024) "")

(define-private (test-success!) (var-set test-success__ true))
(define-private (test-fail! (msg (string-ascii 1024)))
(begin
    (print msg)
    (var-set test-fail-msg__ msg)
    (var-set test-success__ false)
    true))

(define-public (check-success?)
(begin
    (if (var-get test-success__)
        (print "ok")
        (print (var-get test-fail-msg__)))
    (ok (var-get test-success__))))
"#;
            let test_code = format!("\n\n;; =============== Begin Test Harness ==============\n\n{}\n\n;; ============== Begin Test Code =================\n\n{}", &test_harness, &generated_code);
            let test_name : &str = stringify!($FuncName);
            run_clarity_test(test_name, &test_code);
        }
    }
}

// santiy checks
clarity_test!(test_clarity_hello_world, {
    let generated_code = "(print \"hello world!\")";
    generated_code
});

