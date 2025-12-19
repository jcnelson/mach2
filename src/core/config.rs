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

use clarity_types::types::QualifiedContractIdentifier;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::types::chainstate::StacksAddress;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};

use crate::bitcoin::BitcoinNetworkType;
use crate::bitcoin::MagicBytes;
use serde::Deserialize;
use serde::Serialize;
use toml;

pub const DEFAULT_SATS_PER_VB: u64 = 50;

#[derive(Debug, Clone, PartialEq)]
pub enum PrivateKeyType {
    User,
    Cosigner,
    Spender
}

impl PrivateKeyType {
    pub fn to_string(&self) -> String {
        match self {
            Self::User => "user".into(),
            Self::Cosigner => "cosigner".into(),
            Self::Spender => "spender".into()
        }
    }
}

impl TryFrom<&str> for PrivateKeyType {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "user" => Ok(Self::User),
            "cosigner" => Ok(Self::Cosigner),
            "spender" => Ok(Self::Spender),
            _ => Err(())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigPrivateKey {
    /// type of private key 
    pub key_type: PrivateKeyType,
    /// key itself
    pub key: Secp256k1PrivateKey
}

impl ConfigPrivateKey {
    pub fn new_user(key: Secp256k1PrivateKey) -> Self {
        Self {
            key_type: PrivateKeyType::User,
            key
        }
    }

    pub fn new_cosigner(key: Secp256k1PrivateKey) -> Self {
        Self {
            key_type: PrivateKeyType::Cosigner,
            key
        }
    }

    pub fn new_spender(key: Secp256k1PrivateKey) -> Self {
        Self {
            key_type: PrivateKeyType::Spender,
            key
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigBitcoin {
    /// magic bytes to scan for
    pub magic_bytes: MagicBytes,
    /// mainnet, testnet, or regtest
    pub network_id: BitcoinNetworkType,
    /// bitcoin host 
    pub peer_host: String,
    /// bitcoin p2p port
    pub peer_port: u16,
    /// bitcoin rpc port
    pub rpc_port: u16,
    /// username
    pub username: Option<String>,
    /// password
    pub password: Option<String>,
    /// timeout
    pub timeout: u64,
    /// satoshis per byte fee
    pub satoshis_per_byte: u64,
    /// RBF fee increment
    pub rbf_fee_increment: u64,
    /// maximum RBF 
    pub max_rbf: u64,
    /// name of wallet to ues
    pub wallet_name: String,
    /// data path for bitcoin state (only needed for testing)
    pub datadir: String,
    /// mining key for block building (used in integration tests)
    pub local_mining_public_key: Option<String>,
    /// maximum number of UTXOs to create while mining (only needed for testing)
    pub max_unspent_utxos: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// mainnet or testnet
    mainnet: bool,
    /// stacks node host
    node_host: String,
    /// stacks node port
    node_port: u16,
    /// identity key for storing data in stackerdb
    storage_private_key: Secp256k1PrivateKey,
    /// location where we store local DBs
    /// (relative or absolute)
    storage: String,
    /// our stackerdb contract address
    storage_addr: QualifiedContractIdentifier,
    /// Path to mocked stackerdb databases
    mock_stackerdb_paths: HashMap<QualifiedContractIdentifier, String>,
    /// Cosigner private key(s)
    cosigner_private_keys: Vec<Secp256k1PrivateKey>,
    /// User private key
    user_private_key: Secp256k1PrivateKey,
    /// Spender private key
    spender_private_key: Option<Secp256k1PrivateKey>,

    /// bitcoin config (visible to tests)
    #[cfg(test)]
    pub bitcoin: ConfigBitcoin,
    #[cfg(not(test))]
    bitcoin: ConfigBitcoin,
    
    /// Path from which we loaded this (visible to tests)
    #[cfg(test)]
    pub __path: String,
    #[cfg(not(test))]
    __path: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigFilePrivateKey {
    /// private key type
    key_type: String,
    /// key 
    key: String
}

#[derive(Serialize, Deserialize)]
pub struct ConfigFileMockStackerDB {
    /// address to mock
    contract_id: String,
    /// DB on disk
    path: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigFileBitcoin {
    /// mainnet, testnet, regtest
    network_id: Option<String>,
    /// magic bytes for OP_RETURN
    magic_bytes: Option<String>,
    /// bitcoin host
    peer_host: String,
    /// bitcoin p2p port
    peer_port: u16,
    /// bitcoin rpc port
    rpc_port: u16,
    /// bitcoin username
    username: Option<String>,
    /// bitcoin password
    password: Option<String>,
    /// connection / transport timeout, in seconds
    timeout: u64,
    /// satoshis per byte fee
    satoshis_per_byte: u64,
    /// RBF fee increment
    rbf_fee_increment: u64,
    /// maximum RBF 
    max_rbf: u64,
    /// wallet name
    wallet_name: Option<String>,
    /// bitcoin storage dir (only needed for testing)
    datadir: Option<String>,
    /// mining key for controlling a bitcoin regtest node (only needed for testing)
    local_mining_public_key: Option<String>,
    /// maximum number of unspent UTXOs to allow (only needed for testing) 
    max_unspent_utxos: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    /// mainnet or testnet
    mainnet: bool,
    /// node host
    node_host: String,
    /// node port
    node_port: u16,
    /// identity key for stackerdb
    storage_private_key: String,
    /// location where we store local DBs
    /// (relative or absolute)
    storage: Option<String>,
    /// our stackerdb contract address
    storage_addr: String,
    /// Bitcoin config
    bitcoin: Option<ConfigFileBitcoin>,
    /// Private keys
    private_keys: Vec<ConfigFilePrivateKey>,
    /// Path to mocked stackerdb databases
    mocked_stackerdb: Option<Vec<ConfigFileMockStackerDB>>,
}

impl ConfigFile {
    pub fn from_str(content: &str) -> Result<Self, String> {
        let config = toml::from_str(content).map_err(|e| format!("Invalid toml: {}", e))?;
        Ok(config)
    }
}

impl TryFrom<ConfigFileBitcoin> for ConfigBitcoin {
    type Error = String;
    fn try_from(config_file: ConfigFileBitcoin) -> Result<Self, Self::Error> {
        let magic_bytes = if let Some(magic_bytes_str) = config_file.magic_bytes.as_ref() {
            MagicBytes::try_from(magic_bytes_str.as_str())?
        }
        else {
            MagicBytes::default()
        };

        let network_id = if let Some(network_id_str) = config_file.network_id.as_ref() {
            BitcoinNetworkType::try_from(network_id_str.as_str())?
        }
        else {
            BitcoinNetworkType::Mainnet
        };

        Ok(Self {
            network_id,
            magic_bytes,
            peer_host: config_file.peer_host,
            peer_port: config_file.peer_port,
            rpc_port: config_file.rpc_port,
            username: config_file.username,
            password: config_file.password,
            timeout: config_file.timeout,
            satoshis_per_byte: config_file.satoshis_per_byte,
            rbf_fee_increment: config_file.rbf_fee_increment,
            max_rbf: config_file.max_rbf,
            wallet_name: config_file.wallet_name.unwrap_or("".to_string()),
            datadir: config_file.datadir.unwrap_or("/tmp/mach2-bitcoin-datadir".to_string()),
            local_mining_public_key: config_file.local_mining_public_key,
            max_unspent_utxos: config_file.max_unspent_utxos,
        })
    }
}

impl TryFrom<ConfigFilePrivateKey> for ConfigPrivateKey {
    type Error = String;
    fn try_from(config_file: ConfigFilePrivateKey) -> Result<Self, Self::Error> {
        let key_type = PrivateKeyType::try_from(config_file.key_type.as_str())
            .map_err(|_| format!("Unrecognized key type '{}'", &config_file.key_type))?;
        let key = Secp256k1PrivateKey::from_hex(&config_file.key)
            .map_err(|e| format!("Unparseable private key: {e:?}"))?;
        Ok(Self {
            key_type,
            key
        })
    }
}

impl TryFrom<ConfigFile> for Config {
    type Error = String;
    fn try_from(config_file: ConfigFile) -> Result<Self, Self::Error> {
        let default_storage = QualifiedContractIdentifier::parse(&config_file.storage_addr).map_err(|_e| {
            format!(
                "Failed to decode '{}': expected <addr>.<name>",
                &config_file.storage_addr
            )
        })?;

        let mut mock_stackerdb_paths: HashMap<QualifiedContractIdentifier, String> = HashMap::new();
        if let Some(mocked_stackerdbs) = config_file.mocked_stackerdb {
            for mocked_stackerdb_path in mocked_stackerdbs.iter() {
                let addr = QualifiedContractIdentifier::parse(&mocked_stackerdb_path.contract_id)
                    .map_err(|e| {
                    format!(
                        "Failed to decode '{}': expected <addr>.<name> ({})",
                        &mocked_stackerdb_path.path, &e
                    )
                })?;
                mock_stackerdb_paths.insert(addr, mocked_stackerdb_path.path.clone());
            }
        }

        let mut user_private_key = None;
        let mut spender_private_key = None;
        let mut cosigner_private_keys = vec![];
        for privk in config_file.private_keys.into_iter() {
            let key_info = ConfigPrivateKey::try_from(privk)?;
            match key_info.key_type {
                PrivateKeyType::User => {
                    if user_private_key.is_some() {
                        return Err("More than one user private key".into());
                    }
                    user_private_key.replace(key_info.key);
                }
                PrivateKeyType::Spender => {
                    if spender_private_key.is_some() {
                        return Err("More than one spender private key".into());
                    }
                    spender_private_key.replace(key_info.key);
                }
                PrivateKeyType::Cosigner => {
                    cosigner_private_keys.push(key_info.key);
                }
            }
        }

        let Some(user_private_key) = user_private_key.take() else {
            return Err("Missing [private_key] section with `key_type = \"user\"`".into());
        };

        Ok(Config {
            mainnet: config_file.mainnet,
            node_host: config_file.node_host,
            node_port: config_file.node_port,
            storage_private_key: Secp256k1PrivateKey::from_hex(&config_file.storage_private_key)
                .map_err(|e| format!("Failed to parse `private_key`: {:?}", &e))?,
            storage: config_file.storage.unwrap_or("./db".into()),
            storage_addr: default_storage,
            mock_stackerdb_paths,
            user_private_key,
            spender_private_key,
            cosigner_private_keys,
            bitcoin: config_file.bitcoin.map(|btc_cfg| btc_cfg.try_into()).unwrap_or(Ok(ConfigBitcoin::default()))?,
            __path: "".into(),
        })
    }
}

impl From<ConfigBitcoin> for ConfigFileBitcoin {
    fn from(config: ConfigBitcoin) -> Self {
        Self {
            magic_bytes: Some(config.magic_bytes.to_string()),
            network_id: Some(config.network_id.to_string()),
            peer_host: config.peer_host,
            peer_port: config.peer_port,
            rpc_port: config.rpc_port,
            username: config.username,
            password: config.password, 
            timeout: config.timeout,
            satoshis_per_byte: config.satoshis_per_byte,
            rbf_fee_increment: config.rbf_fee_increment,
            max_rbf: config.max_rbf,
            wallet_name: Some(config.wallet_name),
            datadir: Some(config.datadir),
            local_mining_public_key: config.local_mining_public_key,
            max_unspent_utxos: config.max_unspent_utxos,
        }
    }
}

impl From<ConfigPrivateKey> for ConfigFilePrivateKey {
    fn from(config: ConfigPrivateKey) -> Self {
        Self {
            key_type: config.key_type.to_string(),
            key: config.key.to_hex()
        }
    }
}

impl From<Config> for ConfigFile {
    fn from(config: Config) -> Self {
        let mut private_keys = vec![];
        private_keys.push(ConfigPrivateKey::new_user(config.user_private_key).into());
        if let Some(spender_key) = config.spender_private_key {
            private_keys.push(ConfigPrivateKey::new_spender(spender_key).into());
        }
        private_keys.extend(config
            .cosigner_private_keys
            .into_iter()
            .map(|k| ConfigPrivateKey::new_cosigner(k).into())
        );
        Self {
            mainnet: config.mainnet,
            node_host: config.node_host.clone(),
            node_port: config.node_port,
            storage_private_key: config.storage_private_key.to_hex(),
            storage: Some(config.storage),
            storage_addr: config.storage_addr.to_string(),
            bitcoin: Some(config.bitcoin.into()),
            private_keys,
            mocked_stackerdb: Some(
                config
                    .mock_stackerdb_paths
                    .into_iter()
                    .map(|(addr, path)| ConfigFileMockStackerDB {
                        contract_id: addr.to_string(),
                        path,
                    })
                    .collect(),
            ),
        }
    }
}

impl ConfigBitcoin {
    pub fn default() -> Self {
        Self {
            magic_bytes: MagicBytes::default(),
            network_id: BitcoinNetworkType::Mainnet,
            peer_host: "localhost".to_string(),
            peer_port: 8333,
            rpc_port: 8332,
            username: None,
            password: None,
            timeout: 30,
            satoshis_per_byte: DEFAULT_SATS_PER_VB, 
            rbf_fee_increment: 0,
            max_rbf: 0,
            wallet_name: "".to_string(),
            datadir: "/tmp/mach2-bitcoin-datadir".to_string(),
            // this is "0b6945219066768aaafb9ed2025893f03f4b5269f27881bc93e3b01332bee95501"
            local_mining_public_key: Some("03b5315b9e444eb982c32834c0d1f83e4546ebbf17cabc089511c48d547fb2d251".to_string()),
            max_unspent_utxos: None,
        }
    }
}

impl Config {
    pub fn default() -> Config {
        Config {
            mainnet: true,
            node_host: "localhost".into(),
            node_port: 20443,
            storage_private_key: Secp256k1PrivateKey::random(),
            storage: "./db".into(),
            storage_addr:
                QualifiedContractIdentifier::parse(
                    "SP000000000000000000002Q6VF78.you-need-to-set-up-your-cosigner",
                )
                .unwrap(),
            mock_stackerdb_paths: HashMap::new(),
            bitcoin: ConfigBitcoin::default(),
            user_private_key: Secp256k1PrivateKey::random(),
            spender_private_key: None,
            cosigner_private_keys: vec![],
            __path: "".into(),
        }
    }
    
    pub fn new(mainnet: bool, node_host: String, node_port: u16) -> Config {
        Config {
            mainnet,
            node_host,
            node_port,
            storage_private_key: Secp256k1PrivateKey::random(),
            storage: "./db".into(),
            storage_addr:
                QualifiedContractIdentifier::parse(
                    "SP000000000000000000002Q6VF78.you-need-to-set-up-your-cosigner",
                )
                .unwrap(),
            mock_stackerdb_paths: HashMap::new(),
            bitcoin: ConfigBitcoin::default(),
            user_private_key: Secp256k1PrivateKey::random(),
            spender_private_key: None,
            cosigner_private_keys: vec![],
            __path: "".into(),
        }
    }

    fn abspath(&self, path: &str) -> String {
        if let Some('/') = path.chars().next() {
            // absolute path
            path.to_string()
        } else {
            // relative path
            if let Some(dirname) = Path::new(&self.__path).parent() {
                format!("{}/{}", dirname.display(), path)
            } else {
                path.to_string()
            }
        }
    }

    pub fn from_path(path: &str) -> Result<Config, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Invalid path: {}", &e))?;
        let config_file = ConfigFile::from_str(&content)?;
        let mut c = Config::try_from(config_file)?;
        c.__path = path.into();

        // fix up mock stackerdb paths
        let mut abs_stackerdb_paths = HashMap::new();
        for (addr, path) in c.mock_stackerdb_paths.iter() {
            abs_stackerdb_paths.insert(addr.clone(), c.abspath(path));
        }
        c.mock_stackerdb_paths = abs_stackerdb_paths;
        Ok(c)
    }

    pub fn mainnet(&self) -> bool {
        self.mainnet
    }

    pub fn get_node_addr(&self) -> (String, u16) {
        (self.node_host.clone(), self.node_port)
    }

    pub fn storage_private_key(&self) -> &Secp256k1PrivateKey {
        &self.storage_private_key
    }

    pub fn default_storage_addr(&self) -> &QualifiedContractIdentifier {
        &self.storage_addr
    }

    pub fn mock_stackerdb_paths(&self) -> &HashMap<QualifiedContractIdentifier, String> {
        &self.mock_stackerdb_paths
    }

    pub fn get_bitcoin_config(&self) -> ConfigBitcoin {
        let Ok(config_file) = Config::from_path(&self.__path) else {
            return self.bitcoin.clone();
        };
        config_file.bitcoin
    }

    pub fn user_private_key(&self) -> &Secp256k1PrivateKey {
        &self.user_private_key
    }
    
    pub fn spender_private_key(&self) -> Option<&Secp256k1PrivateKey> {
        self.spender_private_key.as_ref()
    }
    
    pub fn cosigner_private_keys(&self) -> &[Secp256k1PrivateKey] {
        &self.cosigner_private_keys
    }

    pub fn db_root(&self) -> String {
        self.abspath(&self.storage)
    }

    pub fn dag_db_path(&self) -> String {
        format!("{}/dag.db", &self.db_root())
    }
}
