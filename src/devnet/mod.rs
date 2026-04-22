// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

pub mod db;
pub mod pegin;
pub mod sip018;
pub mod pox;
pub mod tx;

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::net::SocketAddr;

use regex::Regex;

use serde_json;

use clarity::vm::types::PrincipalData;
use clarity::vm::Value;
use clarity_types::types::StacksAddressExtensions;

use stacks_common::address::AddressHashMode;
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::types::Address;
use stacks_common::types::StacksEpochId;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::{get_epoch_time_secs, sleep_ms};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::to_hex;
use stacks_common::deps_common::bitcoin::network::serialize::serialize as btc_serialize;
use crate::stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;

use crate::bitcoin::Txid;
use crate::bitcoin::rpc::BitcoinRpcClient;
use crate::bitcoin::signer::BitcoinOpSigner;
use crate::bitcoin::wallet::{BitcoinClient, UTXOSet};

use crate::core::Config;

use crate::net::session;
use crate::net::RPCPeerInfoData;
use crate::net::RPCPoxInfoData;
use crate::net::RPCContractSrc;
use crate::net::Error as NetError;

use crate::devnet::sip018::pox4::Pox4SignatureTopic;
use crate::devnet::pox::PoxAddress;

use crate::util::sqlite::Error as SqliteError;

use crate::tx::StacksTransaction;

use crate::devnet::tx::make_contract_call_tx;

pub const SYSTEM_START_HEIGHT : usize = 101;
pub const DEVNET_START_HEIGHT : usize = 126;

pub const MINING_KEY : &str = "c97f705b698beb6a7fa71e7db0cf30a93030d14776301e62514f27232b444d10";

/// Singleton Stacks node config template
pub const NAKAMOTO_NODE_CONFIG_TEMPLATE: &str = r#"
[node]
rpc_bind = "0.0.0.0:@@STACKS_RPC_PORT@@"
p2p_bind = "0.0.0.0:@@STACKS_P2P_PORT@@"
data_url = "http://127.0.0.1:@@STACKS_RPC_PORT@@"
p2p_address = "127.0.0.1:@@STACKS_P2P_PORT@@"
bootstrap_node = ""
# echo -n 'naka3-seed' | sha256sum 
seed = "c97f705b698beb6a7fa71e7db0cf30a93030d14776301e62514f27232b444d10"
# echo -n 'naka3-local-seed' | sha256sum
local_peer_seed = "e2a6e24aa72b197c8fc8e136ffc0f090610ee0820885cb42ef549b95ef1479aa"
miner = true
stacker = true
working_dir = "@@STACKS_DATA_DIR@@"
wait_time_for_microblocks = 0
mine_microblocks = false

use_test_genesis_chainstate = true
pox_sync_sample_secs = 0
wait_time_for_blocks = 200
microblock_frequency = 1000

[miner]
first_attempt_time_ms = 180_000
subsequent_attempt_time_ms = 360_000
microblock_attempt_time_ms = 10
mining_key = "c97f705b698beb6a7fa71e7db0cf30a93030d14776301e62514f27232b444d10"
segwit = true

[connection_options]
public_ip_address = "127.0.0.1:@@STACKS_P2P_PORT@@"
auth_token = "mach2"
timeout = 15
connect_timeout = 15
handshake_timeout = 15
idle_timeout = 15
dns_timeout = 15
private_neighbors = true

[burnchain]
chain = "bitcoin"
mode = "nakamoto-neon"
poll_time_secs = 1
magic_bytes = "T3"
pox_prepare_length = 5
pox_reward_length = 20
burn_fee_cap = 20_000
peer_host = "127.0.0.1"
username = "mach2"
password = "mach2"
rpc_port = @@BITCOIN_RPC_PORT@@
peer_port = @@BITCOIN_P2P_PORT@@
wallet_name = "@@STACKS_BTC_WALLET@@"

[[burnchain.epochs]]
epoch_name = "1.0"
start_height = 0

[[burnchain.epochs]]
epoch_name = "2.0"
start_height = 0

[[burnchain.epochs]]
epoch_name = "2.05"
start_height = 99

[[burnchain.epochs]]
epoch_name = "2.1"
start_height = 100

[[burnchain.epochs]]
epoch_name = "2.2"
start_height = 105

[[burnchain.epochs]]
epoch_name = "2.3"
start_height = 106

[[burnchain.epochs]]
epoch_name = "2.4"
start_height = 107

[[burnchain.epochs]]
epoch_name = "2.5"
start_height = 108

[[burnchain.epochs]]
epoch_name = "3.0"
start_height = 122

[[burnchain.epochs]]
epoch_name = "3.1"
start_height = 123

[[burnchain.epochs]]
epoch_name = "3.2"
start_height = 124

[[burnchain.epochs]]
epoch_name = "3.3"
start_height = 125

[[burnchain.epochs]]
epoch_name = "3.4"
start_height = 126

[[ustx_balance]]
address = "@@DEVNET_CONTROLLER_ADDRESS@@"
amount = 1000000000000000

##### Event Observers ######
"#;

pub const SIGNER_EVENT_OBSERVER_TEMPLATE : &str = r#"
# signer balance and config
[[ustx_balance]]
amount = 1000000000000000
address = "@@SIGNER_ADDRESS@@"

[[events_observer]]
endpoint = "127.0.0.1:@@SIGNER_PORT@@"
events_keys = ["stackerdb", "block_proposal", "burn_blocks"]
"#;

pub const SIGNER_CONFIG_TEMPLATE : &str = r#"
stacks_private_key = "@@SIGNER_KEY@@"
node_host = "127.0.0.1:@@STACKS_RPC_PORT@@"
endpoint = "127.0.0.1:@@SIGNER_PORT@@"
network = "testnet"
auth_password = "mach2"
db_path = "@@SIGNER_DB@@"
reward_cycle = "1"
first_proposal_burn_block_timing = 5
"#;

/// Errors that can occur when managing a `bitcoind` process.
#[derive(Debug)]
pub enum BitcoinCoreError {
    /// Returned when the `bitcoind` process fails to start.
    SpawnFailed(String),
    /// Returned when an attempt to stop the `bitcoind` process fails.
    StopFailed(String),
    /// Returned when an attempt to forcibly kill the `bitcoind` process fails.
    KillFailed(String),
    /// RPC failed
    RPCError(String),
}

type BitcoinResult<T> = Result<T, BitcoinCoreError>;

/// Represents a managed `bitcoind` process instance.
pub struct BitcoinCoreController {
    /// Handle to the spawned `bitcoind` process.
    bitcoind_process: Option<Child>,
    /// Command-line arguments used to launch the process.
    args: Vec<String>,
    /// Path to the data directory used by `bitcoind`.
    data_path: String,
    /// RPC client for communicating with the `bitcoind` instance.
    rpc_client: BitcoinRpcClient,
}

impl BitcoinCoreController {
    /// Create a [`BitcoinCoreController`] from Stacks Configuration
    pub fn from_config(config: &Config) -> Self {
        let client =
            BitcoinRpcClient::from_config(config).expect("rpc client creation failed!");
        Self::from_config_and_client(config, client)
    }

    /// Create a [`BitcoinCoreController`] from configuration (mainly using [`core::config::ConfigBitcoin`])
    /// and an rpc client [`BitcoinRpcClient`]
    pub fn from_config_and_client(config: &Config, client: BitcoinRpcClient) -> Self {
        let mut result = BitcoinCoreController {
            bitcoind_process: None,
            args: vec![],
            data_path: config.get_bitcoin_config().datadir.clone(),
            rpc_client: client,
        };

        result.add_arg("-regtest");
        // result.add_arg("-nodebug");
        // result.add_arg("-nodebuglogfile");
        result.add_arg("-rest");
        result.add_arg("-persistmempool=1");
        result.add_arg("-dbcache=100");
        result.add_arg("-txindex=1");
        result.add_arg("-server=1");
        result.add_arg("-listenonion=0");
        result.add_arg("-rpcbind=127.0.0.1");
        result.add_arg(format!("-datadir={}", result.data_path));

        let peer_port = config.get_bitcoin_config().peer_port;
        if peer_port == 0 {
            m2_info!("Peer Port is disabled. So `-listen=0` flag will be used");
            result.add_arg("-listen=0");
        } else {
            result.add_arg(format!("-port={peer_port}"));
        }

        result.add_arg(format!("-rpcport={}", config.get_bitcoin_config().rpc_port));

        if let Some(username) = config.bitcoin.username.as_ref() {
            result.add_arg(format!("-rpcuser={}", username));
            if let Some(password) = config.bitcoin.password.as_ref() {
                result.add_arg(format!("-rpcpassword={}", password));
            }
        }

        result
    }

    /// Add argument (like "-name=value") to be used to run bitcoind process
    pub fn add_arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    /// Start Bitcoind process
    pub fn start(&mut self) -> BitcoinResult<()> {
        fs::create_dir_all(&self.data_path)
            .map_err(|e| BitcoinCoreError::SpawnFailed(format!("Failed to create {}: {e:?}", &self.data_path)))?;

        let mut command = Command::new("bitcoind");
        command.stdout(Stdio::piped());

        command.args(self.args.clone());

        m2_info!("bitcoind spawn: {command:?}");

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(BitcoinCoreError::SpawnFailed(format!("{e:?}"))),
        };

        let mut out_reader = BufReader::new(process.stdout.take().expect("infallible"));

        let mut line = String::new();
        while let Ok(bytes_read) = out_reader.read_line(&mut line) {
            if bytes_read == 0 {
                return Err(BitcoinCoreError::SpawnFailed(
                    "Bitcoind closed before spawning network".into(),
                ));
            }
            if line.contains("Done loading") {
                break;
            }
            if process.try_wait().map_err(|e| BitcoinCoreError::SpawnFailed(format!("try_wait() failed to query bitcoind pid: {e:?}")))?.is_some() {
                return Err(BitcoinCoreError::SpawnFailed("bitcoind died unexpectedly".to_string()));
            }
        }

        m2_info!("bitcoind startup finished");

        self.bitcoind_process = Some(process);

        Ok(())
    }

    /// Gracefully stop bitcoind process
    pub fn stop(&mut self) -> BitcoinResult<()> {
        if let Some(mut bitcoind_process) = self.bitcoind_process.take() {
            let res = self
                .rpc_client
                .stop()
                .map_err(|e| BitcoinCoreError::StopFailed(format!("{e:?}")))?;
            m2_info!("bitcoind stop started with message: '{res}'");
            bitcoind_process
                .wait()
                .map_err(|e| BitcoinCoreError::StopFailed(format!("{e:?}")))?;
            m2_info!("bitcoind stop finished");
        }
        Ok(())
    }

    /// Kill bitcoind process
    pub fn kill(&mut self) -> BitcoinResult<()> {
        if let Some(mut bitcoind_process) = self.bitcoind_process.take() {
            m2_info!("bitcoind kill started");
            bitcoind_process
                .kill()
                .map_err(|e| BitcoinCoreError::KillFailed(format!("{e:?}")))?;
            m2_info!("bitcoind kill finished");
        }
        Ok(())
    }

    /// Check if bitcoind process is running
    pub fn is_running(&self) -> bool {
        self.bitcoind_process.is_some()
    }
}

impl Drop for BitcoinCoreController {
    fn drop(&mut self) {
       let _ =  self.kill();
    }
}

/// Errors that can occur when managing a `stacks-core` process.
#[derive(Debug)]
pub enum NakamotoNodeError {
    /// Returned when the `stacks-core` process fails to start.
    SpawnNodeFailed(String),
    /// Returned when the `stacks-signer` process fails to start.
    SpawnSignerFailed(String),
    /// Returned when an attempt to stop the `stacks-core` process fails.
    StopNodeFailed(String),
    /// Returned when an attempt to stop the `stacks-signer` process fails.
    StopSignerFailed(String),
    /// Returned when an attempt to forcibly kill the `stacks-core` process fails.
    KillNodeFailed(String),
    /// Returned when an attempt to forcibly kill the `stacks-signer` process fails.
    KillSignerFailed(String),
    /// A timeout happened
    TimedOut(String),
    /// RPC error
    RPCError(String),
    /// OS error
    OSError(String),
    /// Bitcoin error
    Bitcoin(BitcoinCoreError),
    /// Networking error
    Net(NetError),
    /// Database error
    DBError(SqliteError),
}

impl From<BitcoinCoreError> for NakamotoNodeError {
    fn from(bce: BitcoinCoreError) -> Self {
        Self::Bitcoin(bce)
    }
}

impl From<NetError> for NakamotoNodeError {
    fn from(ne: NetError) -> Self {
        Self::Net(ne)
    }
}

impl From<SqliteError> for NakamotoNodeError {
    fn from(se: SqliteError) -> Self {
        Self::DBError(se)
    }
}

type NakamotoResult<T> = Result<T, NakamotoNodeError>;

/// Represents a managed `stacks-signer` process instance
pub struct NakamotoSigner {
    signer_id: u16,
    signer_process: Option<Child>,
    private_key: Secp256k1PrivateKey,
    db_path: String,
    config_toml: String,
    auth_id: u128,
}

impl NakamotoSigner {
    pub fn from_config(config: &Config, data_dir: &str, signer_port: u16) -> Self {
        let db_path = format!("{}/signer-{}/signer.db", data_dir, signer_port);
        let private_key = BitcoinOpSigner::make_secret_key_from_bytes(&signer_port.to_le_bytes());
        
        let re_signer_key = Regex::new("@@SIGNER_KEY@@").expect("infallible");
        let re_rpc_port = Regex::new("@@STACKS_RPC_PORT@@").expect("infallible");
        let re_signer_port = Regex::new("@@SIGNER_PORT@@").expect("infallible");
        let re_db_path = Regex::new("@@SIGNER_DB@@").expect("infallible");

        let template = SIGNER_CONFIG_TEMPLATE.to_string();
        let template = re_signer_key.replace_all(&template, &private_key.to_hex());
        let template = re_rpc_port.replace_all(&template, &format!("{}", config.node_port));
        let template = re_signer_port.replace_all(&template, &format!("{}", signer_port));
        let template = re_db_path.replace_all(&template, &db_path);

        Self {
            signer_id: signer_port,
            signer_process: None,
            private_key,
            db_path,
            config_toml: template.to_string(),
            auth_id: 0
        }
    }

    /// Start the signer process
    pub fn start(&mut self) -> NakamotoResult<()> {
        let signer_dir = Path::new(&self.db_path)
            .parent()
            .ok_or_else(|| NakamotoNodeError::SpawnSignerFailed(format!("Invalid db path: {}", &self.db_path)))?
            .to_str()
            .ok_or_else(|| NakamotoNodeError::SpawnSignerFailed(format!("Invalid db path: {}", &self.db_path)))?
            .to_string();

        if fs::metadata(&signer_dir).is_ok() {
            fs::remove_dir_all(&signer_dir)
                .map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to remove {}: {e:?}", &signer_dir)))?;
        }

        fs::create_dir_all(&signer_dir)
            .map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to create {}: {e:?}", &signer_dir)))?;
        
        let log_path = format!("{}/signer.log", &signer_dir);
        let conf_path = format!("{}/signer.toml", &signer_dir);

        let logfile_stdout = fs::File::create(&log_path)
            .map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to create logfile {log_path}: {e:?}")))?;

        let logfile_stderr = logfile_stdout.try_clone()
            .map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to create logfile stderr on {log_path}: {e:?}")))?;

        let mut conf_file = fs::File::create(&conf_path)
            .map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to create config file {conf_path}: {e:?}")))?;

        conf_file.write_all(&self.config_toml.as_bytes())
            .map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to write config file to {conf_path}: {e:?}")))?;

        m2_debug!("Wrote signer {} config file to {conf_path}", self.signer_id);
        drop(conf_file);

        // run a check-config first
        {
            let mut command = Command::new("stacks-signer");
            command.stdout(Stdio::null());
            command.env("RUST_BACKTRACE", "full");
            command.args(vec!["check-config", "-c", &conf_path]);

            let mut check_proc = match command.spawn() {
                Ok(child) => child,
                Err(e) => {
                    return Err(NakamotoNodeError::SpawnSignerFailed(format!("Failed to check config: {e:?}")));
                }
            };
        
            let exit_status = check_proc.wait()
                .map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to wait on check-config: {e:?}")))?;

            if !exit_status.success() {
                return Err(NakamotoNodeError::SpawnSignerFailed(format!("Signer check-config failed on {conf_path}")));
            }
        }

        // now spawn the signer
        let mut command = Command::new("stacks-signer");
        command.stdout(logfile_stdout);
        command.stderr(logfile_stderr);
        command.env("RUST_BACKTRACE", "full");
        command.args(vec!["run", "-c", &conf_path]);

        m2_info!("stacks-signer {} spawn: {command:?}", self.signer_id);

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(NakamotoNodeError::SpawnSignerFailed(format!("{e:?}"))),
        };

        // wait for it to boot up
        let mut out_reader = BufReader::new(fs::File::open(&log_path).map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("Failed to open {log_path}: {e:?}")))?);

        let mut line = String::new();
        while let Ok(bytes_read) = out_reader.read_line(&mut line) {
            if bytes_read == 0 {
                if process.try_wait().map_err(|e| NakamotoNodeError::SpawnSignerFailed(format!("try_wait() failed to query signer pid: {e:?}")))?.is_some() {
                    return Err(NakamotoNodeError::SpawnSignerFailed(
                        "signer closed before spawning".into(),
                    ));
                }
            }
            if line.contains("Signer runloop begin") {
                break;
            }
        }

        self.signer_process = Some(process);
        Ok(())
    }
    
    /// kill the signer
    pub fn kill(&mut self) -> NakamotoResult<()> {
        if let Some(mut signer_process) = self.signer_process.take() {
            m2_info!("Signer {} kill started", self.signer_id);
            signer_process
                .kill()
                .map_err(|e| NakamotoNodeError::KillSignerFailed(format!("{e:?}")))?;
            m2_info!("Signer {} kill finished", self.signer_id);
        }
        Ok(())
    }

    /// Check if the signer process is running
    pub fn is_running(&self) -> bool {
        self.signer_process.is_some()
    }
    
    /// Compute the StacksAddress for the private key
    pub fn stacks_address(&self) -> StacksAddress {
        tx::to_addr(&self.private_key)
    }
    
    /// Compute the PoX address for this signer
    pub fn pox_address(&self) -> PoxAddress {
        let stacks_addr = self.stacks_address();
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            stacks_addr.bytes().clone(),
        )
    }

    /// Generate a 12-cycle stack-stx transaction for this signer.
    /// Stacks the full amount of STX, minus a tx fee.
    pub fn make_stack_stx_transaction(&mut self, node_addr: &SocketAddr) -> NakamotoResult<StacksTransaction> {
        let auth_id = self.auth_id;
        self.auth_id += 1;

        let info = session::run_get_info(node_addr)
            .map_err(|e| NakamotoNodeError::RPCError(format!("Failed to query {node_addr:?} on /v2/info: {e:?}")))?;

        let pox_info = session::run_get_pox(node_addr)
            .map_err(|e| NakamotoNodeError::RPCError(format!("Failed to query {node_addr:?} on /v2/pox: {e:?}")))?;

        let chain_id = info.network_id;
        let acct = session::run_get_account(node_addr, &self.stacks_address().to_account_principal())
            .map_err(|e| NakamotoNodeError::RPCError(format!("Failed to query {node_addr:?} on /v2/accounts: {e:?}")))?;

        let fee = 1000u64;
        let stacking_amount = acct.balance.checked_sub(u128::from(fee))
            .ok_or(NakamotoNodeError::RPCError(format!("Failed to compute stacking amount due to insufficient funds on {}", &self.stacks_address())))?;

        let stacker_nonce = acct.nonce;
        let signer_pubk = Value::buff_from(Secp256k1PublicKey::from_private(&self.private_key).to_bytes_compressed()).expect("infallible -- failed to create (buff 33)");
        let pox_addr = self.pox_address();
        let pox_addr_tuple: Value = pox_addr.clone().as_clarity_tuple().expect("infallible -- failed to create Clarity tuple from PoX address").into();
        let signature_bytes = sip018::pox4::make_pox_4_signer_key_signature(
            &pox_addr,
            &self.private_key,
            pox_info.current_cycle.id.into(),
            &Pox4SignatureTopic::StackStx,
            chain_id,
            12_u128,
            u128::MAX,
            auth_id,
        )
        .expect("infallible: failed to create PoX-4 signer key signature")
        .to_rsv();

        let signature = Value::some(Value::buff_from(signature_bytes).expect("infallible -- failed to create (buff 65)")).expect("infallible -- failed to create (optional (buff 65))");
        let stack_tx = make_contract_call_tx(
            &self.private_key,
            stacker_nonce,
            fee as u64,
            chain_id,
            &StacksAddress::burn_address(false),
            "pox-4",
            "stack-stx",
            &[
                Value::UInt(stacking_amount),
                pox_addr_tuple,
                Value::UInt(info.burn_block_height as u128),
                Value::UInt(12),
                signature,
                signer_pubk,
                Value::UInt(u128::MAX),
                Value::UInt(auth_id),
            ],
        );
        Ok(stack_tx)
    }
}

impl Drop for NakamotoSigner {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Represents a managed `stacks-core` process instance, along with its `stacks-signer` instances
pub struct NakamotoController {
    /// Handle to the spawned `stacks-core` process.
    stacks_core_process: Option<Child>,
    /// Handle to the spanwed `stacks-signer` processes.
    stacks_signer_processes: Vec<NakamotoSigner>,
    /// Complete stacks node toml
    stacks_node_toml: String,
    /// Path to the top-level chainstate data directory shared by `stacks-core` and `stacks-signer`
    data_path: String,
    /// Node socket address
    node_addr: SocketAddr,
    /// STX key for funding various things
    stx_key: Secp256k1PrivateKey,
}

impl NakamotoController {
    pub fn from_config(config: &Config, data_dir: &str, signer_ports: &[u16]) -> Self {
        // synthesize a Stacks node config
        let re_rpc_port = Regex::new("@@STACKS_RPC_PORT@@").expect("infallible");
        let re_p2p_port = Regex::new("@@STACKS_P2P_PORT@@").expect("infallible");
        let re_data_dir = Regex::new("@@STACKS_DATA_DIR@@").expect("infallible");
        let re_btc_rpc_port = Regex::new("@@BITCOIN_RPC_PORT@@").expect("infallible");
        let re_btc_p2p_port = Regex::new("@@BITCOIN_P2P_PORT@@").expect("infallible");
        let re_stacks_btc_wallet = Regex::new("@@STACKS_BTC_WALLET@@").expect("infallible");

        let re_signer_key = Regex::new("@@SIGNER_KEY@@").expect("infallible");
        let re_signer_addr = Regex::new("@@SIGNER_ADDRESS@@").expect("infallible");
        let re_signer_port = Regex::new("@@SIGNER_PORT@@").expect("infallible");

        let re_devnet_controller_address = Regex::new("@@DEVNET_CONTROLLER_ADDRESS@@").expect("infallible");

        let stacks_data_dir = format!("{}/stacks", &data_dir);

        let stx_key = Secp256k1PrivateKey::from_hex("cb3df38053d132895220b9ce471f6b676db5b9bf0b4adefb55f2118ece2478df01").expect("infallible");
        let devnet_controller_address = tx::to_addr(&stx_key); 

        let mut stacks_toml = {
            let template = NAKAMOTO_NODE_CONFIG_TEMPLATE.to_string();
            let template = re_rpc_port.replace_all(&template, &format!("{}", config.node_port));
            let template = re_p2p_port.replace_all(&template, &format!("{}", config.node_p2p_port));
            let template = re_data_dir.replace_all(&template, &stacks_data_dir);
            let template = re_btc_rpc_port.replace_all(&template, &format!("{}", config.bitcoin.rpc_port));
            let template = re_btc_p2p_port.replace_all(&template, &format!("{}", config.bitcoin.peer_port));
            let template = re_stacks_btc_wallet.replace_all(&template, &config.bitcoin.wallet_name);
            let template = re_devnet_controller_address.replace_all(&template, &format!("{}", &devnet_controller_address));
            template.to_string()
        };
        assert!(stacks_toml.find("@@").is_none());

        let signers : Vec<_> = signer_ports
            .iter()
            .map(|signer_port| NakamotoSigner::from_config(config, &stacks_data_dir, *signer_port))
            .collect();

        // add event observe entries to the node config
        for signer in signers.iter() {
            let event_template = SIGNER_EVENT_OBSERVER_TEMPLATE.to_string();
            let event_template = re_signer_key.replace_all(&event_template, signer.private_key.to_hex());
            let event_template = re_signer_addr.replace_all(&event_template, &format!("{}", signer.stacks_address()));
            let event_template = re_signer_port.replace_all(&event_template, &format!("{}", signer.signer_id));

            assert!(event_template.find("@@").is_none());

            stacks_toml.extend(event_template.to_string().chars());
        }

        let node_addr = SocketAddr::from(([127, 0, 0, 1], config.node_port));
        
        Self {
            stacks_core_process: None,
            stacks_signer_processes: signers,
            stacks_node_toml: stacks_toml,
            data_path: stacks_data_dir,
            node_addr,
            stx_key
        }
    }

    /// Start the stacks core process and its signers
    pub fn start(&mut self) -> NakamotoResult<()> {
        if fs::metadata(&self.data_path).is_ok() {
            fs::remove_dir_all(&self.data_path)
                .map_err(|e| NakamotoNodeError::SpawnNodeFailed(format!("Failed to remove {}: {e:?}", &self.data_path)))?;
        }

        fs::create_dir_all(&self.data_path)
            .map_err(|e| NakamotoNodeError::SpawnNodeFailed(format!("Failed to create {}: {e:?}", &self.data_path)))?;

        let config_path = format!("{}/stacks-core.toml", &self.data_path);
        let mut config_file = fs::File::create(&config_path)
            .map_err(|e| NakamotoNodeError::SpawnNodeFailed(format!("Failed to write config path at {config_path}: {e:?}")))?;

        config_file.write_all(&self.stacks_node_toml.as_bytes())
            .map_err(|e| NakamotoNodeError::SpawnNodeFailed(format!("Failed to save config file at {config_path}: {e:?}")))?;

        drop(config_file);

        let logfile_path = format!("{}/stacks-core.log", &self.data_path);
        let logfile_stdout = fs::File::create(&logfile_path)
            .map_err(|e| NakamotoNodeError::SpawnNodeFailed(format!("Failed to create node logfile at {logfile_path}: {e:?}")))?;

        let logfile_stderr = logfile_stdout.try_clone()
            .map_err(|e| NakamotoNodeError::SpawnNodeFailed(format!("Failed to dup logfile at {logfile_path}: {e:?}")))?;

        for signer in self.stacks_signer_processes.iter_mut() {
            signer.start()?;
        }

        let mut command = Command::new("stacks-node");
        command.stdout(logfile_stdout);
        command.stderr(logfile_stderr);
        command.args(vec!["start", "--config", &config_path]);

        m2_info!("stacks-core spawn: {command:?}");

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(NakamotoNodeError::SpawnNodeFailed(format!("{e:?}"))),
        };

        let deadline = get_epoch_time_secs() + 60;
        let mut booted = false;
        while get_epoch_time_secs() < deadline && !booted {
            if process.try_wait().map_err(|e| NakamotoNodeError::SpawnNodeFailed(format!("try_wait() failed to query stacks-core pid: {e:?}")))?.is_some() {
                return Err(NakamotoNodeError::SpawnNodeFailed("stacks-core died unexpectedly".to_string()));
            }
            if session::run_get_info(&self.node_addr).is_ok() {
                booted = true;
                break;
            }
            sleep_ms(1000);
        }
        if !booted {
            return Err(NakamotoNodeError::SpawnNodeFailed(format!("Failed to boot node -- unresponsive to /v2/info")));
        }

        m2_info!("stacks-core startup finished");

        self.stacks_core_process = Some(process);
        
        Ok(())
    }

    /// Kill stacks-core and its signers
    pub fn kill(&mut self) -> NakamotoResult<()> {
        for signer in self.stacks_signer_processes.iter_mut() {
            let _ = signer.kill().inspect_err(|e| m2_error!("Failed to kill signer {}: {e:?}", signer.signer_id));
        }
        if let Some(mut stacks_core_process) = self.stacks_core_process.take() {
            m2_info!("stacks-core kill started");
            stacks_core_process
                .kill()
                .map_err(|e| NakamotoNodeError::KillNodeFailed(format!("{e:?}")))?;
            m2_info!("stacks-core kill finished");
        }
        Ok(())
    }

    /// Check if bitcoind process is running
    pub fn is_running(&self) -> bool {
        self.stacks_core_process.is_some()
    }
}


impl Drop for NakamotoController {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Manage bitcoind, stacks-core, and stacks-signers
pub struct DevnetController {
   pub bitcoind: BitcoinCoreController,
   pub nakamoto: NakamotoController,
   pub config: Config,
   pub data_path: String,
}

impl DevnetController {
    pub fn new(config: &Config, test_name: &str) -> Self {
        let data_path = format!("/tmp/mach2-tests/{test_name}");
        let mut config = config.clone();
        config.bitcoin.datadir = format!("{data_path}/bitcoin");

        let bitcoin_controller = BitcoinCoreController::from_config(&config);
        let nakamoto_controller = NakamotoController::from_config(&config, &data_path, &[3000, 3001, 3002]);

        Self {
            bitcoind: bitcoin_controller,
            nakamoto: nakamoto_controller,
            config,
            data_path,
        }
    }

    pub fn start(&mut self) -> bool {
        if fs::metadata(&self.data_path).is_ok() {
            if let Err(e) = fs::remove_dir_all(&self.data_path) {
                m2_warn!("Failed to remove {}: {e:?}", &self.data_path);
                return false;
            }
        }
        if let Err(e) = self.bitcoind.start() {
            m2_error!("Failed to start Bitcoin controller: {e:?}");
            return false;
        }
        if let Err(e) = self.nakamoto.start() {
            m2_error!("Failed to start Nakamoto controller: {e:?}");
            let _ = self.bitcoind.kill();
            return false;
        }
        true
    }

    pub fn kill(&mut self) {
        let _ = self.nakamoto.kill();
        let _ = self.bitcoind.kill();
    }

    /// Get /v2/info from the stacks node
    pub fn get_stacks_chain_info(&self) -> NakamotoResult<RPCPeerInfoData> {
        session::run_get_info(&self.nakamoto.node_addr)
            .map_err(|e| NakamotoNodeError::RPCError(format!("{e:?}")))
    }
    
    /// Get /v2/pox from the stacks node
    pub fn get_stacks_pox_info(&self) -> NakamotoResult<RPCPoxInfoData> {
        session::run_get_pox(&self.nakamoto.node_addr)
            .map_err(|e| NakamotoNodeError::RPCError(format!("{e:?}")))
    }

    /// Get a contract from the stacks node
    pub fn get_contract(&self, contract_addr: &StacksAddress, contract_name: &str) -> NakamotoResult<RPCContractSrc> {
        session::run_get_contract_code(&self.nakamoto.node_addr, contract_addr, contract_name)
            .map_err(|e| NakamotoNodeError::RPCError(format!("{e:?}")))
    }

    /// Submit a transaction 
    pub fn submit_tx(&self, tx: &StacksTransaction) -> NakamotoResult<Txid> {
        session::run_post_transaction(&self.nakamoto.node_addr, tx)
            .map_err(|e| NakamotoNodeError::RPCError(format!("{e:?}")))
    }

    fn wait_for<F>(event_desc: &str, timeout: u64, mut f: F) -> NakamotoResult<()>
    where
        F: FnMut() -> NakamotoResult<bool>
    {
        m2_info!("Wait for: {}", event_desc);
        let deadline = get_epoch_time_secs() + timeout;
        while get_epoch_time_secs() < deadline {
            if f()? {
                m2_info!("Successfully waited: {}", event_desc);
                return Ok(());
            }
        }
        Err(NakamotoNodeError::TimedOut(format!("Timed out after {timeout}s: {event_desc}")))
    }

    pub fn next_tenure(&self, client: &BitcoinClient) -> NakamotoResult<()> {
        let old_info = self.get_stacks_chain_info()?;
        client.bootstrap_chain(1);

        // wait for tenure height to advance
        Self::wait_for(&format!("tenure #{} to begin", old_info.tenure_height + 1), 60, || {
            sleep_ms(2000);
            let Ok(info) = self.get_stacks_chain_info().inspect_err(|e| m2_warn!("Failed to query node /v2/info: {e:?}")) else {
                return Ok(false);
            };
            m2_debug!("Tenure height is currently {} (old is {})", info.tenure_height, old_info.tenure_height);
            Ok(info.tenure_height > old_info.tenure_height)
        })?;

        Ok(())
    }

    pub fn send_stacking_tx(&mut self, signer_index: usize) -> NakamotoResult<Txid> {
        let Some(stacker) = self.nakamoto.stacks_signer_processes.get_mut(signer_index) else {
            return Err(NakamotoNodeError::RPCError(format!("No such signer {signer_index}")));
        };
        let stacking_tx = stacker.make_stack_stx_transaction(&self.nakamoto.node_addr)?;
        self.submit_tx(&stacking_tx)
    }

    fn wait_for_miner_activity<F>(client: &BitcoinClient, wait_msg: &str, timeout: u64, changer: F) -> NakamotoResult<()>
    where
        F: FnOnce() -> NakamotoResult<()>
    {
        let btc_key = Secp256k1PrivateKey::from_hex(&MINING_KEY).unwrap();
        let btc_pub = Secp256k1PublicKey::from_private(&btc_key);
        let utxos_before = client.get_utxos(&btc_pub, 21_000_000, None)
            .ok_or_else(|| NakamotoNodeError::Bitcoin(BitcoinCoreError::RPCError(format!("Failed to get UTXOs for {}", &btc_pub.to_hex()))))?;
        let utxos_before_set : HashSet<_> = utxos_before.utxos.into_iter().collect();

        changer()?;

        Self::wait_for(wait_msg, timeout, || {
            sleep_ms(1000);
            let utxos = client.get_utxos(&btc_pub, 21_000_000, None)
                .ok_or_else(|| NakamotoNodeError::Bitcoin(BitcoinCoreError::RPCError(format!("Failed to get UTXOs for {}", &btc_pub.to_hex()))))?;
            let utxos_set : HashSet<_> = utxos.utxos.into_iter().collect();
            Ok(utxos_set != utxos_before_set)
        })
    }

    pub fn bootup(&mut self, recipient_key: Secp256k1PublicKey) -> NakamotoResult<BitcoinClient> {
        self.bootup_multi(&[recipient_key])
    }

    pub fn bootup_multi(&mut self, recipient_keys: &[Secp256k1PublicKey])  -> NakamotoResult<BitcoinClient> {
        if fs::metadata(&self.data_path).is_ok() {
            fs::remove_dir_all(&self.data_path)
                .map_err(|e| NakamotoNodeError::OSError(format!("Failed to rm -rf {}: {e:?}", &self.data_path)))?;
        }
        if !self.bitcoind.is_running() {
            self.bitcoind.start()?;
        }

        let client = BitcoinClient::new(self.config.clone());
        client.bootstrap_chain_to_pks(SYSTEM_START_HEIGHT as u64, recipient_keys);

        if !self.nakamoto.is_running() {
            self.nakamoto.start()?;
        }

        // wait for /v2/info to report SYSTEM_START_HEIGHT
        Self::wait_for(&format!("Stacks to reach SYSTEM_START_HEIGHT = {SYSTEM_START_HEIGHT}"), 60, || {
            sleep_ms(1000);
            let Ok(info) = self.get_stacks_chain_info().inspect_err(|e| m2_warn!("Failed to query node /v2/info: {e:?}")) else {
                return Ok(false);
            };
            m2_debug!("System is at burn height {}", info.burn_block_height);
            Ok(info.burn_block_height >= (SYSTEM_START_HEIGHT as u64))
        })?;

        let old_info = self.get_stacks_chain_info()?;
        Self::wait_for(&format!("Leader key register to be confirmed"), 60, || {
            sleep_ms(2000);
            client.bootstrap_chain(1);
            
            let chain_info = self.get_stacks_chain_info()?;
            if old_info.burn_block_height + 10 < chain_info.burn_block_height {
                return Err(NakamotoNodeError::SpawnNodeFailed("Could not confirm a leader key register".into()));
            }
            Ok(db::get_num_leader_keys(&self.data_path)? > 0)
        })?;

        // mine an epoch 2.x block
        let old_info = self.get_stacks_chain_info()?;
        Self::wait_for("Stacks to mine a single Stacks block", 60, || {
            sleep_ms(2000);
            client.bootstrap_chain(1);
            let chain_info = self.get_stacks_chain_info()?;
            if old_info.burn_block_height + 10 < chain_info.burn_block_height {
                return Err(NakamotoNodeError::SpawnNodeFailed("Could not mine an Epoch 2.x block".into()));
            }
            Ok(chain_info.stacks_tip_height > 0)
        })?;
        
        // wait for pox-4 to become active
        let old_info = self.get_stacks_chain_info()?;
        Self::wait_for("Stacks PoX-4 to become active", 60, || {
            sleep_ms(2000);
            client.bootstrap_chain(1);

            // only try for 10 Bitcoin blocks. If pox-4 doesn't activate by then, then give up
            let chain_info = self.get_stacks_chain_info()?;
            if old_info.burn_block_height + 10 < chain_info.burn_block_height {
                return Err(NakamotoNodeError::SpawnNodeFailed("Failed to activate pox-4".to_string()));
            }

            let Ok(_) = self.get_contract(&StacksAddress::burn_address(false), "pox-4").inspect_err(|e| {
                if let NakamotoNodeError::RPCError(msg) = e {
                    if msg.find("HttpError(404").is_none() {
                        m2_warn!("Failed to query node /v2/contracts for pox-4: {msg}")
                    }
                }
                else {
                    m2_warn!("Failed to query node /v2/contracts for pox-4: {e:?}")
                }
            })
            else {
                m2_info!("At Bitcoin height {}, Stacks height {}, tenure height {}", chain_info.burn_block_height, chain_info.stacks_tip_height, chain_info.tenure_height);
                return Ok(false);
            };

            Ok(true)
        })?;

        let mut account_nonces_before = vec![];
        for signer in self.nakamoto.stacks_signer_processes.iter() {
            let nonce = session::run_get_account(&self.nakamoto.node_addr, &signer.stacks_address().to_account_principal())?.nonce;
            account_nonces_before.push(nonce);
        }

        // wait for there to be at least one unconfirmed miner UTXO (would correspond to a block-commit)
        Self::wait_for_miner_activity(&client, "Block-commit to hit the mempool", 60, || {
            // send stacking transactions for all signers
            for i in 0..self.nakamoto.stacks_signer_processes.len() {
                m2_info!("Sending Stacking transaction for signer {}", i);
                self.send_stacking_tx(i)?;
            }
            Ok(())
        })?;

        // wait for the corresponding block to get mined
        Self::wait_for("STX lock-ups to confirm", 60, || {
            // wait for the next block-commit to be broadcast
            Self::wait_for_miner_activity(&client, "Block-commit to hit the mempool", 60, || {
                client.bootstrap_chain(1);
                Ok(())
            })?;
            let mut locked = true;
            for (i, signer) in self.nakamoto.stacks_signer_processes.iter().enumerate() {
                let acct = session::run_get_account(&self.nakamoto.node_addr, &signer.stacks_address().to_account_principal())?;
                if account_nonces_before[i] < acct.nonce {
                    assert!(acct.locked > 0);
                    assert!(acct.balance < acct.locked);
                }
                else {
                    locked = false;
                }
            }

            Ok(locked)
        })?;

        let info = self.get_stacks_chain_info()?;
        m2_info!("Booting into Nakamoto from Bitcoin height {} to {}", info.burn_block_height, DEVNET_START_HEIGHT);

        for _i in info.burn_block_height..=(DEVNET_START_HEIGHT as u64) {
            client.bootstrap_chain(1);
            sleep_ms(2000);
            let info = self.get_stacks_chain_info()?;
            m2_info!("At Bitcoin height {}, Stacks height {}, tenure height {}", info.burn_block_height, info.stacks_tip_height, info.tenure_height);
        }

        m2_info!("Booted devnet!");
        Ok(client)
    }

    pub fn default_config(test_name: &str) -> Config {
        let mut config = Config::new(false, "localhost".into(), 50443);
        config.storage = format!("/tmp/mach2-tests/{test_name}/storage-db");
        config.bitcoin.username = Some("mach2".to_string());
        config.bitcoin.password = Some("mach2".to_string());
        config
    }

}

impl Drop for DevnetController {
    fn drop(&mut self) {
        self.kill()
    }
}

#[test]
fn test_devnet_start_stop() {
    if std::env::var("BITCOIND_TEST") != Ok("1".to_string()) {
        return;
    }

    let config = DevnetController::default_config("test_devnet_start_stop");
    let mut devnet = DevnetController::new(&config, "test_devnet_start_stop");

    let btc_key = Secp256k1PrivateKey::from_hex(&MINING_KEY).unwrap();
    let btc_pub = Secp256k1PublicKey::from_private(&btc_key);
    let client = devnet.bootup(btc_pub).unwrap();

    let old_info = devnet.get_stacks_chain_info().unwrap();
    for _i in 0..5 {
        devnet.next_tenure(&client).unwrap();
    }
    let new_info = devnet.get_stacks_chain_info().unwrap();
    assert_eq!(old_info.tenure_height + 5, new_info.tenure_height);

    devnet.kill();
}

#[test]
fn test_devnet_make_pegin_test_vector() {
    if std::env::var("BITCOIND_TEST") != Ok("1".to_string()) {
        return;
    }

    use crate::devnet::pegin::PeginTest;
    
    let config = DevnetController::default_config("test_devnet_make_pegin_test_vector");
    let mut devnet = DevnetController::new(&config, "test_devnet_make_pegin_test_vector");
    
    let btc_key = Secp256k1PrivateKey::from_hex(&MINING_KEY).unwrap();
    let btc_pub = Secp256k1PublicKey::from_private(&btc_key);
    let client = devnet.bootup(btc_pub).unwrap();

    let locktime = 1000;
    let safety_margin = 30;
    let mut pegin_test = PeginTest::new(btc_key, vec![0x02], 3, &devnet.config)
        .begin(locktime, safety_margin, StacksAddress::from_string("ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD").unwrap(), 50 * 100_000_000, 40000);

    m2_info!("cosigner_pubkeys: {:?}", &pegin_test.get_cosigner_pubkeys().into_iter().map(|pubk| pubk.to_hex()).collect::<Vec<_>>());
    m2_info!("witness script: {}", to_hex(&pegin_test.op().make_witness_script().unwrap().into_bytes()));
    m2_info!("decoded transaction: {:?}", &pegin_test.tx());

    let raw_tx = to_hex(&pegin_test.tx_bytes());
    m2_info!("raw transaction: {}", &raw_tx);
   
    let proof = pegin_test.proof.clone().unwrap();
    let block_header = to_hex(&btc_serialize(&proof.block_header).unwrap());
    let block_height = proof.block_height;
    let block_hash = to_hex(&proof.block_header.bitcoin_hash().0);
    let tx_index = proof.tx_index;
    let tree_depth = proof.tree_depth;
    let tx_proof = proof.tx_proof
        .iter()
        .map(|h| format!("(reverse-buff32 0x{})", h.to_hex()))
        .collect::<Vec<_>>()
        .join(" ");
    let witness_merkle_root = proof.witness_merkle_root.to_hex();
    let witness_reserved = proof.witness_reserved.to_hex();
    let coinbase_tx = to_hex(&btc_serialize(&proof.coinbase_tx).unwrap());
    let coinbase_tx_proof = proof.coinbase_tx_proof
        .iter()
        .map(|h| format!("(reverse-buff32 0x{})", h.to_hex()))
        .collect::<Vec<_>>()
        .join(" ");

    let pegin_utxos = pegin_test.op().get_pegin_utxos(pegin_test.tx(), 1).unwrap();
    let user_p2wpkh = pegin_test.op().user_p2wpkh();

    let empty_utxos = UTXOSet::empty();

    pegin_test.op_mut().clear_witness();

    let (mut pegin_spend_tx, mut pegin_spend_utxoset) = pegin_test
        .op()
        .make_unsigned_pegin_spend_transaction(1000, &empty_utxos, &pegin_utxos, user_p2wpkh)
        .expect("Failed to create joint spend transaction");

    pegin_spend_tx.lock_time = 500;

    // user signs
    let mut user_signer = pegin_test.get_user_signer().dup();
    assert!(pegin_test.op_mut().sign_user(&mut user_signer, &mut pegin_spend_utxoset, &mut pegin_spend_tx).is_ok());

    let partially_signed_user_tx = to_hex(&btc_serialize(&pegin_spend_tx).unwrap());

    m2_info!("user-signed off-chain transaction: {}", &partially_signed_user_tx);

    m2_info!("
(define-constant WTX 0x{raw_tx})

(define-constant PARTIALLY_SIGNED_OUTCOME_WTX 0x{partially_signed_user_tx})

(define-constant WTXID (sha256 (sha256 WTX)))

(define-constant COSIGNER_ADDR 'ST2D7JNTKA11T11QYCXEQPJQ97TETW7MKKWPJT770)
(define-constant COSIGNER_KEYS (list
    0x03fe11e4e59b6c3c2a5a5760df9d4a903f7b478a146fc2947a9f04518419fa6387
    0x031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a
    0x03fc17d6b3fb08855ff1bdefd68fa8fa9a5b4b9708fcad2c72cde4371088aaceea
))

;; register the cosigner for this pegin
(asserts! (is-ok (inner-register-cosigner COSIGNER_ADDR COSIGNER_KEYS))
    (begin
        (test-fail! \"Failed to register cosigner\")
        (err u1234567890)))

(define-constant OWNER 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD)
(define-constant USER_PUBKEY 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f)
(define-constant PROVIDER (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 USER_PUBKEY))))

;; carry out this pegin
(let (
    (pegin {{
        cosigner: COSIGNER_ADDR,
        tx: WTX,
        block-header: (reverse-buff32 0x{block_header}),
        block-height: u{block_height},
        block-hash: 0x{block_hash},
        tx-index: u{tx_index},
        tree-depth: u{tree_depth},
        tx-proof: (list {tx_proof}),
        witness-merkle-root: (reverse-buff32 0x{witness_merkle_root}),
        witness-reserved: 0x{witness_reserved},
        coinbase-tx: 0x{coinbase_tx},
        coinbase-tx-proof: (list {coinbase_tx_proof}),
        pegin-output: u0,
        witness-data: {{
            recipient-principal: OWNER,
            user-pubkey: USER_PUBKEY,
            locktime: u{locktime},
            safety-margin: u{safety_margin}
        }}
    }})
)
(asserts! (is-ok (contract-call? .bitcoin mock-add-burnchain-block-header-hash (get block-height pegin) (get block-hash pegin)))
    (begin
        (test-fail! \"Failed to mock bitcoin block header hash\")
        (err u11111)))

(asserts! (is-ok (inner-register-pegin
        (get cosigner pegin)
        (get tx pegin)
        (get block-header pegin)
        (get block-height pegin)
        (get tx-index pegin)
        (get tree-depth pegin)
        (get tx-proof pegin)
        (get witness-merkle-root pegin)
        (get witness-reserved pegin)
        (get coinbase-tx pegin)
        (get coinbase-tx-proof pegin)
        (get pegin-output pegin)
        (get witness-data pegin)))
    (begin
        (test-fail! \"Failed to peg in\")
        (err u22222)))
)
"
    ); 
}

