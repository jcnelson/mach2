// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::cmp;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use stacks_common::types::{Address, PublicKey, PrivateKey};
use crate::bitcoin::address::{
    BitcoinAddress, SegwitBitcoinAddress,
};
use crate::bitcoin::{BitcoinNetworkType, Error};
use crate::bitcoin::Txid;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Builder, Script};
use stacks_common::deps_common::bitcoin::blockdata::transaction::{
    OutPoint, Transaction, TxIn, TxOut,
};
use stacks_common::deps_common::bitcoin::network::serialize::{serialize, serialize_hex};
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::hash::{DoubleSha256, Hash160};
use stacks_common::util::hash::{to_hex, hex_bytes};
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use stacks_common::util::sleep_ms;

use crate::bitcoin::signer::BitcoinOpSigner;
use crate::core::config::Config;

use crate::bitcoin::rpc::{
    BitcoinRpcClient, BitcoinRpcClientError, BitcoinRpcClientResult, ImportDescriptorsRequest,
    Timestamp,
};

use serde::{Serialize, Deserialize};
use crate::bitcoin::MagicBytes;


pub const DUST_UTXO_LIMIT: u64 = 5500;

#[cfg(test)]
// Used to inject invalid block commits during testing.
pub static TEST_MAGIC_BYTES: std::sync::Mutex<Option<[u8; 2]>> = std::sync::Mutex::new(None);

pub struct BitcoinClient {
    network_id: BitcoinNetworkType,
    magic_bytes: MagicBytes,
    wallet_name: String,
    config: Config,
    rpc_client: BitcoinRpcClient,
}

pub fn get_satoshis_per_byte(config: &Config) -> u64 {
    config.get_bitcoin_config().satoshis_per_byte
}

pub fn get_rbf_fee_increment(config: &Config) -> u64 {
    config.get_bitcoin_config().rbf_fee_increment
}

pub fn get_max_rbf(config: &Config) -> u64 {
    config.get_bitcoin_config().max_rbf
}

/// Extension methods for working with [`BitcoinRpcClient`] result
/// that log failures and panic.
#[cfg(test)]
trait BitcoinRpcClientResultExt<T> {
    /// Unwraps the result, returning the value if `Ok`.
    ///
    /// If the result is an `Err`, it logs the error with the given context
    /// using the [`error!`] macro and then panics.
    fn unwrap_or_log_panic(self, context: &str) -> T;
    /// Ensure the result is `Ok`, ignoring its value.
    ///
    /// If the result is an `Err`, it logs the error with the given context
    /// using the [`error!`] macro and then panics.
    fn ok_or_log_panic(self, context: &str);
}

#[cfg(test)]
impl<T> BitcoinRpcClientResultExt<T> for Result<T, BitcoinRpcClientError> {
    fn unwrap_or_log_panic(self, context: &str) -> T {
        match self {
            Ok(val) => val,
            Err(e) => {
                m2_error!("Bitcoin RPC failure: {context} {e:?}");
                panic!();
            }
        }
    }

    fn ok_or_log_panic(self, context: &str) {
        _ = self.unwrap_or_log_panic(context);
    }
}

/// Represents errors that can occur when using [`BitcoinClient`].
#[derive(Debug)]
pub enum BitcoinClientError {
    /// Error related to Bitcoin RPC failures.
    Rpc(BitcoinRpcClientError),
    /// Error related to invalid or malformed [`Secp256k1PublicKey`].
    InvalidPublicKey(Error),
}

impl From<BitcoinRpcClientError> for BitcoinClientError {
    fn from(e: BitcoinRpcClientError) -> Self {
        Self::Rpc(e)
    }
}

/// Alias for results returned from [`BitcoinClient`] operations.
pub type BitcoinClientResult<T> = Result<T, BitcoinClientError>;

impl BitcoinClient {
    pub fn new(config: Config) -> Self {
        let rpc_client = Self::create_rpc_client_unchecked(&config);
        let btc_config = config.get_bitcoin_config();
        Self {
            network_id: btc_config.network_id,
            magic_bytes: btc_config.magic_bytes,
            wallet_name: btc_config.wallet_name,
            config,
            rpc_client,
        }
    }

    /// Attempt to create a new [`BitcoinRpcClient`] from the given [`Config`].
    ///
    /// If the provided config indicates that the node is a **miner**,
    /// tries to instantiate it or **panics** otherwise.
    /// If the node is **not** a miner, returns None (e.g. follower node).
    fn create_rpc_client_unchecked(config: &Config) -> BitcoinRpcClient {
        BitcoinRpcClient::from_config(&config)
            .expect("unable to instantiate the RPC client for miner node!")
    }

    /// Get a reference to the underlying [`BitcoinRpcClient`].
    fn get_rpc_client(&self) -> &BitcoinRpcClient {
        &self.rpc_client
    }

    /// Retrieves all UTXOs associated with the given public key.
    ///
    /// Automatically imports descriptors into the wallet for the public_key
    #[cfg(test)]
    pub fn get_all_utxoset(&self, public_key: &Secp256k1PublicKey) -> UTXOSet {
        let address = self.get_wallet_address(public_key);
        m2_test_debug!("Import public key '{}'", &public_key.to_hex());
        self.import_public_key(&public_key)
            .unwrap_or_else(|error| {
                panic!(
                    "Import public key '{}' failed: {error:?}",
                    public_key.to_hex()
                )
            });

        sleep_ms(1000);

        self.retrieve_utxo_set(&address, true, 1, &None)
            .unwrap_or_log_panic("retrieve all utxos")
    }
    
    /// Retrieves all UTXOs associated with the given public key.
    ///
    /// Automatically imports descriptors into the wallet for the public_key
    #[cfg(test)]
    pub fn get_all_utxos(&self, public_key: &Secp256k1PublicKey) -> Vec<UTXO> {
        self.get_all_utxoset(public_key).utxos
    }

    /// Retrieve all loaded wallets.
    pub fn list_wallets(&self) -> BitcoinClientResult<Vec<String>> {
        Ok(self.get_rpc_client().list_wallets()?)
    }

    /// Checks if the config-supplied wallet exists.
    /// If it does not exist, this function creates it.
    pub fn create_wallet_if_dne(&self) -> BitcoinClientResult<()> {
        let wallets = self.list_wallets()?;
        let wallet = self.get_wallet_name();
        if !wallets.contains(wallet) {
            self.get_rpc_client().create_wallet(wallet, Some(true))?
        }
        Ok(())
    }

    pub fn get_utxos(
        &self,
        public_key: &Secp256k1PublicKey,
        total_required: u64,
        utxos_to_exclude: Option<UTXOSet>,
    ) -> Option<UTXOSet> {
        // Configure UTXO filter
        let address = self.get_wallet_address(&public_key);
        m2_test_debug!("Get UTXOs for {} ({address})", public_key.to_hex());

        let mut utxos = loop {
            let result = self.retrieve_utxo_set(
                &address,
                false,
                total_required,
                &utxos_to_exclude,
            );

            // Perform request
            match result {
                Ok(utxos) => {
                    break utxos;
                }
                Err(e) => {
                    m2_error!("Bitcoin RPC failure: error listing utxos {e:?}");
                    sleep_ms(5000);
                    continue;
                }
            };
        };

        let utxos = if utxos.is_empty() {
            let network = self.network_id;
            loop {
                if let BitcoinNetworkType::Regtest = network {
                    // Performing this operation on Mainnet / Testnet is very expensive, and can be longer than bitcoin block time.
                    // Assuming that miners are in charge of correctly operating their bitcoind nodes sounds
                    // reasonable to me.
                    // $ bitcoin-cli importaddress mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk
                    let result = self.import_public_key(&public_key);
                    if let Err(error) = result {
                        m2_warn!(
                            "Import public key '{}' failed: {error:?}",
                            &public_key.to_hex()
                        );
                    }
                    sleep_ms(1000);
                }

                let result = self.retrieve_utxo_set(
                    &address,
                    false,
                    total_required,
                    &utxos_to_exclude,
                );

                utxos = match result {
                    Ok(utxos) => utxos,
                    Err(e) => {
                        m2_error!("Bitcoin RPC failure: error listing utxos {e:?}");
                        sleep_ms(5000);
                        continue;
                    }
                };

                m2_test_debug!("Unspent for {address:?}: {utxos:?}");

                if utxos.is_empty() {
                    return None;
                } else {
                    break utxos;
                }
            }
        } else {
            m2_debug!("Got {} UTXOs for {address:?}", utxos.utxos.len());
            utxos
        };

        let total_unspent = utxos.total_available();
        if total_unspent < total_required {
            m2_warn!(
                "Total unspent {total_unspent} < {total_required} for {:?}",
                &public_key.to_hex()
            );
            return None;
        }

        Some(utxos)
    }

    fn magic_bytes(&self) -> Vec<u8> {
        #[cfg(test)]
        {
            if let Some(set_bytes) = *TEST_MAGIC_BYTES
                .lock()
                .expect("FATAL: test magic bytes mutex poisoned")
            {
                return set_bytes.to_vec();
            }
        }
        self.magic_bytes.as_bytes().to_vec()
    }

    pub fn get_wallet_address(
        &self,
        public_key: &Secp256k1PublicKey,
    ) -> BitcoinAddress {
        let network_id = self.network_id;

        let hash160 = Hash160::from_data(&public_key.to_bytes_compressed());
        BitcoinAddress::from_bytes_segwit_p2wpkh(network_id, &hash160.0)
            .expect("Public key incorrect")
    }

    /// Broadcast a signed raw [`Transaction`] to the underlying Bitcoin node.
    ///
    /// The transaction is submitted with following parameters:
    /// - `max_fee_rate = 0.0` (uncapped, accept any fee rate),
    /// - `max_burn_amount = 1_000_000` (in sats).
    ///
    /// # Arguments
    /// * `transaction` - A fully signed raw [`Transaction`] to broadcast.
    ///
    /// # Returns
    /// On success, returns the [`Txid`] of the broadcasted transaction.
    pub fn send_transaction(&self, tx: &Transaction) -> Result<Txid, Error> {
        m2_debug!(
            "Sending raw transaction: {}",
            serialize_hex(tx).unwrap_or("SERIALIZATION FAILED".to_string())
        );

        const UNCAPPED_FEE: f64 = 0.0;
        const MAX_BURN_AMOUNT: u64 = 1_000_000;
        self.get_rpc_client()
            .send_raw_transaction(tx, Some(UNCAPPED_FEE), Some(MAX_BURN_AMOUNT))
            .map(|txid| {
                m2_debug!("Transaction {txid} sent successfully");
                txid
            })
            .map_err(|e| {
                m2_error!("Bitcoin RPC error: transaction submission failed - {e:?}");
                Error::TransactionSubmissionFailed(format!("{e:?}"))
            })
    }

    /// Instruct a regtest Bitcoin node to build the next block.
    #[cfg(test)]
    pub fn build_next_block(&self, num_blocks: u64) {
        m2_debug!("Generate {num_blocks} block(s)");
        let public_key_bytes = match &self.config.get_bitcoin_config().local_mining_public_key {
            Some(public_key) => hex_bytes(public_key).expect("Invalid byte sequence"),
            None => panic!("Unable to make new block, mining public key"),
        };

        let mut public_key = Secp256k1PublicKey::from_slice(&public_key_bytes)
            .expect("FATAL: invalid public key bytes");
        public_key.set_compressed(true);

        let address = self.get_wallet_address(&public_key);

        let result = self
            .get_rpc_client()
            .generate_to_address(num_blocks, &address);
        match result {
            Ok(_) => {}
            Err(e) => {
                m2_error!("Bitcoin RPC failure: error generating block {e:?}");
                panic!();
            }
        }
    }

    /// Instruct a regtest Bitcoin node to build an empty block.
    #[cfg(test)]
    pub fn build_empty_block(&self) {
        m2_info!("Generate empty block");
        let public_key_bytes = match &self.config.get_bitcoin_config().local_mining_public_key {
            Some(public_key) => hex_bytes(public_key).expect("Invalid byte sequence"),
            None => panic!("Unable to make new block, mining public key"),
        };

        let mut public_key = Secp256k1PublicKey::from_slice(&public_key_bytes)
            .expect("FATAL: invalid public key bytes");
        public_key.set_compressed(true);

        let address = self.get_wallet_address(&public_key);

        self.get_rpc_client()
            .generate_block(&address, &[])
            .ok_or_log_panic("generating block")
    }

    /// Invalidate a block given its hash as a [`BurnchainHeaderHash`].
    #[cfg(test)]
    pub fn invalidate_block(&self, block: &BurnchainHeaderHash) {
        m2_info!("Invalidating block {block}");
        self.get_rpc_client()
            .invalidate_block(block)
            .ok_or_log_panic("invalidate block")
    }

    /// Retrieve the hash (as a [`BurnchainHeaderHash`]) of the block at the given height.
    #[cfg(test)]
    pub fn get_block_hash(&self, height: u64) -> BurnchainHeaderHash {
        self.get_rpc_client()
            .get_block_hash(height)
            .unwrap_or_log_panic("retrieve block")
    }

    #[cfg(test)]
    pub fn get_mining_pubkey(&self) -> Option<String> {
        self.config.get_bitcoin_config().local_mining_public_key.clone()
    }

    #[cfg(test)]
    pub fn set_mining_pubkey(&mut self, pubkey: String) -> Option<String> {
        let old_key = self.config.bitcoin.local_mining_public_key.take();
        self.config.bitcoin.local_mining_public_key = Some(pubkey);
        old_key
    }

    /// Produce `num_blocks` regtest bitcoin blocks, sending the bitcoin coinbase rewards
    ///  to the bitcoin single sig addresses corresponding to `pks` in a round robin fashion.
    #[cfg(test)]
    pub fn bootstrap_chain_to_pks(&self, num_blocks: u64, pks: &[Secp256k1PublicKey]) {
        m2_info!("Creating wallet if it does not exist");
        if let Err(e) = self.create_wallet_if_dne() {
            m2_error!("Error when creating wallet: {e:?}");
        }

        for pk in pks {
            m2_debug!("Import public key '{}'", &pk.to_hex());
            if let Err(e) = self.import_public_key(pk) {
                m2_warn!("Error when importing pubkey: {e:?}");
            }
        }

        if pks.len() == 1 {
            // if we only have one pubkey, just generate all the blocks at once
            let address = self.get_wallet_address(&pks[0]);
            m2_debug!(
                "Generate to address '{address}' for public key '{}'",
                &pks[0].to_hex()
            );
            self.get_rpc_client()
                .generate_to_address(num_blocks, &address)
                .ok_or_log_panic("generating block");
            return;
        }

        // otherwise, round robin generate blocks
        let num_blocks = num_blocks as usize;
        for i in 0..num_blocks {
            let pk = &pks[i % pks.len()];
            let address = self.get_wallet_address(pk);
            if i < pks.len() {
                m2_debug!(
                    "Generate to address '{}' for public key '{}'",
                    address.to_string(),
                    &pk.to_hex(),
                );
            }
            self.get_rpc_client()
                .generate_to_address(1, &address)
                .ok_or_log_panic("generating block");
        }
    }

    #[cfg(test)]
    pub fn bootstrap_chain(&self, num_blocks: u64) {
        let btc_config = self.config.get_bitcoin_config();
        let Some(local_mining_pubkey) = btc_config.local_mining_public_key.as_ref() else {
            m2_warn!("No local mining pubkey while bootstrapping bitcoin regtest, will not generate bitcoin blocks");
            return;
        };

        // NOTE: miner address is whatever the miner's segwit setting says it is here
        let mut local_mining_pubkey = Secp256k1PublicKey::from_hex(local_mining_pubkey).unwrap();
        local_mining_pubkey.set_compressed(true);

        self.bootstrap_chain_to_pks(num_blocks, &[local_mining_pubkey])
    }

    /// Checks whether a transaction has been confirmed by the burnchain
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction ID to check (in big-endian order)
    ///
    /// # Returns
    ///
    /// * `true` if the transaction is confirmed (has at least one confirmation).
    /// * `false` if the transaction is unconfirmed or could not be found.
    pub fn is_transaction_confirmed(&self, txid: &Txid) -> bool {
        match self
            .get_rpc_client()
            .get_transaction(self.get_wallet_name(), txid)
        {
            Ok(info) => info.confirmations > 0,
            Err(e) => {
                m2_error!("Bitcoin RPC failure: checking tx confirmation {e:?}");
                false
            }
        }
    }

    /// Returns the configured wallet name from [`Config`].
    fn get_wallet_name(&self) -> &String {
        &self.wallet_name
    }

    /// Imports a public key into configured wallet by registering its
    /// corresponding addresses as descriptors.
    pub fn import_public_key(
        &self,
        public_key: &Secp256k1PublicKey,
    ) -> BitcoinClientResult<()> {
        let mut compressed_pubkey = public_key.clone();
        compressed_pubkey.set_compressed(true);

        let compressed_pkh = Hash160::from_data(&compressed_pubkey.to_bytes())
            .to_bytes()
            .to_vec();

        let network_id = self.network_id;

        let address = BitcoinAddress::from_bytes_segwit_p2wpkh(network_id, &compressed_pkh)
            .map_err(BitcoinClientError::InvalidPublicKey)?;

        m2_debug!(
            "Import address {address} for public key {}",
            compressed_pubkey.to_hex()
        );

        let descriptor = format!("addr({address})");
        let info = self.get_rpc_client().get_descriptor_info(&descriptor)?;

        let descr_req = ImportDescriptorsRequest {
            descriptor: format!("addr({address})#{}", info.checksum),
            timestamp: Timestamp::Time(0),
            internal: Some(true),
        };

        self.get_rpc_client()
            .import_descriptors(self.get_wallet_name(), &[&descr_req])?;

        Ok(())
    }

    /// Retrieves the set of UTXOs for a given address at a specific block height.
    ///
    /// This method queries all unspent outputs belonging to the provided address:
    /// 1. Using a confirmation window of `0..=9_999_999` for the RPC call.
    /// 2. Filtering out UTXOs that:
    ///    - Are present in the optional exclusion set (matched by transaction ID).
    ///    - Have an amount below the specified `minimum_sum_amount`.
    ///
    /// # Arguments
    /// - `address`: The Bitcoin address whose UTXOs should be retrieved.  
    /// - `include_unsafe`: Whether to include unsafe UTXOs.  
    /// - `minimum_sum_amount`: Minimum amount (in satoshis) that a UTXO must have to be included in the final set.  
    /// - `utxos_to_exclude`: Optional set of UTXOs to exclude from the final result.  
    ///
    /// # Returns
    /// A [`UTXOSet`] containing the filtered UTXOs
    fn retrieve_utxo_set(
        &self,
        address: &BitcoinAddress,
        include_unsafe: bool,
        minimum_sum_amount: u64,
        utxos_to_exclude: &Option<UTXOSet>,
    ) -> BitcoinRpcClientResult<UTXOSet> {
        const MIN_CONFIRMATIONS: u64 = 0;
        const MAX_CONFIRMATIONS: u64 = 9_999_999;
        let unspents = self.get_rpc_client().list_unspent(
            &self.get_wallet_name(),
            Some(MIN_CONFIRMATIONS),
            Some(MAX_CONFIRMATIONS),
            Some(&[address]),
            Some(include_unsafe),
            Some(minimum_sum_amount),
            self.config.get_bitcoin_config().max_unspent_utxos.clone(),
        )?;

        let txids_to_exclude = utxos_to_exclude.as_ref().map_or_else(HashSet::new, |set| {
            set.utxos
                .iter()
                .map(|utxo| Txid::from_bitcoin_tx_hash(&utxo.txid))
                .collect()
        });

        let utxos = unspents
            .into_iter()
            .filter(|each| !txids_to_exclude.contains(&each.txid))
            .filter(|each| each.amount >= minimum_sum_amount)
            .map(|each| UTXO {
                txid: Txid::to_bitcoin_tx_hash(&each.txid),
                vout: each.vout,
                script_pub_key: each.script_pub_key,
                amount: each.amount,
                confirmations: each.confirmations,
            })
            .collect::<Vec<_>>();
        Ok(UTXOSet { utxos })
    }

    pub fn get_raw_transaction(&self, txid: &Txid) -> BitcoinRpcClientResult<Transaction> {
        self.get_rpc_client().get_raw_transaction(txid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOSet {
    pub utxos: Vec<UTXO>,
}

impl UTXOSet {
    pub fn new() -> Self {
        Self {
            utxos: vec![]
        }
    }

    pub fn is_empty(&self) -> bool {
        self.utxos.len() == 0
    }

    pub fn total_available(&self) -> u64 {
        self.utxos.iter().map(|o| o.amount).sum()
    }

    pub fn num_utxos(&self) -> usize {
        self.utxos.len()
    }

    pub fn add(&mut self, mut utxos: Vec<UTXO>) {
        self.utxos.append(&mut utxos);
    }

    pub fn len(&self) -> usize {
        self.num_utxos()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UTXO {
    pub txid: DoubleSha256,
    pub vout: u32,
    #[serde(
        serialize_with = "btc_script_serialize",
        deserialize_with = "btc_script_deserialize",
    )]
    pub script_pub_key: Script,
    pub amount: u64,
    pub confirmations: u32,
}

fn btc_script_serialize<S: serde::Serializer>(
    script: &Script,
    s: S,
) -> Result<S::Ok, S::Error> {
    let bytes = script.to_bytes();
    let inst = to_hex(&bytes);
    s.serialize_str(inst.as_str())
}

fn btc_script_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Script, D::Error> {
    let inst_str = String::deserialize(d)?;
    let inst_bytes = hex_bytes(&inst_str).map_err(serde::de::Error::custom)?;
    let script = Script::from(inst_bytes);
    Ok(script)
}

#[cfg(test)]
pub mod tests {
    use std::env::{self, temp_dir};
    use std::fs::File;
    use std::io::Write;
    use std::panic::{self, AssertUnwindSafe};

    use crate::core::config::DEFAULT_SATS_PER_VB;
    use stacks_common::deps_common::bitcoin::blockdata::script::Builder;
    use stacks_common::types::chainstate::{BlockHeaderHash, StacksAddress, VRFSeed};
    use stacks_common::util::hash::to_hex;
    use stacks_common::util::secp256k1::Secp256k1PrivateKey;

    use super::*;
    use crate::tests::BitcoinCoreController;

    pub mod utils {
        use std::net::TcpListener;

        use crate::bitcoin::MagicBytes;

        use super::*;
       
        use rand::Rng;
        use rand::RngCore;
        use rand::thread_rng;
        use std::env::temp_dir;
        
        pub fn create_cosigner_config() -> Config {
            let mut config = Config::default();
            config.bitcoin.network_id = BitcoinNetworkType::Regtest;
            config.bitcoin.magic_bytes = "T3".as_bytes().into();
            config.bitcoin.username = Some(String::from("user"));
            config.bitcoin.password = Some(String::from("12345"));
            // overriding default "0.0.0.0" because doesn't play nicely on Windows.
            config.bitcoin.peer_host = String::from("127.0.0.1");
            // avoiding peer port biding to reduce the number of ports to bind to.
            config.bitcoin.peer_port = 0;

            let random_bytes_16 : [u8; 16] = [thread_rng().gen(); 16];
            config.bitcoin.datadir = format!("{}/mach2-bitcoin-datadir-{}", temp_dir().display(), to_hex(&random_bytes_16));

            //Ask the OS for a free port. Not guaranteed to stay free,
            //after TcpListner is dropped, but good enough for testing
            //and starting bitcoind right after config is created
            let tmp_listener =
                TcpListener::bind("127.0.0.1:0").expect("Failed to bind to get a free port");
            let port = tmp_listener.local_addr().unwrap().port();

            config.bitcoin.rpc_port = port;

            config
        }

        pub fn create_keychain() -> BitcoinOpSigner {
            create_keychain_with_seed(1)
        }

        pub fn create_keychain_with_seed(value: u8) -> BitcoinOpSigner {
            let seed = vec![value; 4];
            let keychain = BitcoinOpSigner::default(seed);
            keychain
        }

        pub fn create_miner1_pubkey() -> Secp256k1PublicKey {
            create_keychain_with_seed(1).get_public_key()
        }

        pub fn create_miner2_pubkey() -> Secp256k1PublicKey {
            create_keychain_with_seed(2).get_public_key()
        }

        pub fn to_address_segwit_p2wpkh(pub_key: &Secp256k1PublicKey) -> BitcoinAddress {
            // pub_key.to_byte_compressed() equivalent to pub_key.set_compressed(true) + pub_key.to_bytes()
            let hash160 = Hash160::from_data(&pub_key.to_bytes_compressed());
            BitcoinAddress::from_bytes_segwit_p2wpkh(BitcoinNetworkType::Regtest, &hash160.0)
                .expect("Public key incorrect")
        }

        pub fn mine_tx(btc_controller: &BitcoinClient, tx: &Transaction) {
            btc_controller
                .send_transaction(tx)
                .expect("Tx should be sent to the burnchain!");
            btc_controller.build_next_block(1); // Now tx is confirmed
        }

        pub fn txout_opreturn<T: StacksMessageCodec>(
            op: &T,
            magic: &MagicBytes,
            value: u64,
        ) -> TxOut {
            let op_bytes = {
                let mut buffer = vec![];
                let mut magic_bytes = magic.as_bytes().to_vec();
                buffer.append(&mut magic_bytes);
                op.consensus_serialize(&mut buffer)
                    .expect("FATAL: invalid operation");
                buffer
            };

            TxOut {
                value,
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::All::OP_RETURN)
                    .push_slice(&op_bytes)
                    .into_script(),
            }
        }
    }

    /*
    FIXME: generate a valid config file
    #[test]
    fn test_get_satoshis_per_byte() {
        let dir = temp_dir();
        let file_path = dir.as_path().join("config.toml");

        let mut config = Config::default();

        let satoshis_per_byte = get_satoshis_per_byte(&config);
        assert_eq!(satoshis_per_byte, DEFAULT_SATS_PER_VB);

        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "[bitcoin]").unwrap();
        writeln!(file, "satoshis_per_byte = 51").unwrap();
        config.__path = file_path.to_str().unwrap().to_string();

        assert_eq!(get_satoshis_per_byte(&config), 51);
    }
    */

    #[test]
    fn test_get_wallet_address() {
        let config = utils::create_cosigner_config();
        let pub_key = utils::create_miner1_pubkey();

        let btc_controller = BitcoinClient::new(config.clone());

        let expected = utils::to_address_segwit_p2wpkh(&pub_key);
        let address = btc_controller.get_wallet_address(&pub_key);
        assert_eq!(
            expected, address,
        );
    }

    #[test]
    #[ignore]
    fn test_create_wallet_from_default_empty_name() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let config = utils::create_cosigner_config();

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());

        let wallets = btc_controller.list_wallets().unwrap();
        assert_eq!(0, wallets.len());

        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should now exists!");

        let wallets = btc_controller.list_wallets().unwrap();
        assert_eq!(1, wallets.len());
        assert_eq!("".to_owned(), wallets[0]);
    }

    #[test]
    #[ignore]
    fn test_create_wallet_from_custom_name() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let mut config = utils::create_cosigner_config();
        config.bitcoin.wallet_name = String::from("mywallet");

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());

        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should now exists!");

        let wallets = btc_controller.list_wallets().unwrap();
        assert_eq!(1, wallets.len());
        assert_eq!("mywallet".to_owned(), wallets[0]);
    }

    #[test]
    #[ignore]
    fn test_retrieve_utxo_set_with_all_utxos() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("Failed starting bitcoind");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller.bootstrap_chain(150); //produces 50 spendable utxos

        let address = utils::to_address_segwit_p2wpkh(&miner_pubkey);
        let utxo_set = btc_controller
            .retrieve_utxo_set(&address, false, 0, &None)
            .expect("Failed to get utxos");

        assert_eq!(50, utxo_set.num_utxos());
    }

    #[test]
    #[ignore]
    fn test_retrive_utxo_set_excluding_some_utxo() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("Failed starting bitcoind");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller.bootstrap_chain(150); //produces 50 spendable utxos

        let address = utils::to_address_segwit_p2wpkh(&miner_pubkey);
        let mut all_utxos = btc_controller
            .retrieve_utxo_set(&address, false, 0, &None)
            .expect("Failed to get utxos (50)");

        let filtered_utxos = btc_controller
            .retrieve_utxo_set(&address, false, 0, &Some(all_utxos.clone()))
            .expect("Failed to get utxos");
        assert_eq!(0, filtered_utxos.num_utxos(), "all utxos filtered out!");

        all_utxos.utxos.drain(0..10);
        let filtered_utxos = btc_controller
            .retrieve_utxo_set(&address, false, 0, &Some(all_utxos))
            .expect("Failed to get utxos");
        assert_eq!(10, filtered_utxos.num_utxos(), "40 utxos filtered out!");
    }

    #[test]
    #[ignore]
    fn test_list_unspent_with_max_utxos_config() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());
        config.bitcoin.max_unspent_utxos = Some(10);

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("Failed starting bitcoind");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller.bootstrap_chain(150); //produces 50 spendable utxos

        let address = utils::to_address_segwit_p2wpkh(&miner_pubkey);
        let utxos = btc_controller
            .retrieve_utxo_set(&address, false, 1, &None)
            .expect("Failed to get utxos");
        assert_eq!(10, utxos.num_utxos());
    }

    #[test]
    #[ignore]
    fn test_get_all_utxos_with_confirmation() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());

        btc_controller.bootstrap_chain(100);
        let utxos = btc_controller.get_all_utxos(&miner_pubkey);
        assert_eq!(0, utxos.len());

        btc_controller.build_next_block(1);
        let utxos = btc_controller.get_all_utxos(&miner_pubkey);
        assert_eq!(1, utxos.len());
        assert_eq!(101, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);

        btc_controller.build_next_block(1);
        let mut utxos = btc_controller.get_all_utxos(&miner_pubkey);
        utxos.sort_by(|a, b| b.confirmations.cmp(&a.confirmations));

        assert_eq!(2, utxos.len());
        assert_eq!(102, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);
        assert_eq!(101, utxos[1].confirmations);
        assert_eq!(5_000_000_000, utxos[1].amount);
    }

    #[test]
    #[ignore]
    fn test_get_all_utxos_for_other_pubkey() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner1_pubkey = utils::create_miner1_pubkey();
        let miner2_pubkey = utils::create_miner2_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner1_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let miner1_btc_controller = BitcoinClient::new(config.clone());
        miner1_btc_controller.bootstrap_chain(1); // one utxo for miner_pubkey related address

        config.bitcoin.local_mining_public_key = Some(miner2_pubkey.to_hex());
        config.bitcoin.wallet_name = "miner2_wallet".to_string();
        let miner2_btc_controller = BitcoinClient::new(config);
        miner2_btc_controller.bootstrap_chain(102); // two utxo for other_pubkeys related address

        let utxos = miner1_btc_controller.get_all_utxos(&miner1_pubkey);
        assert_eq!(1, utxos.len(), "miner1 see its own utxos");

        let utxos = miner2_btc_controller.get_all_utxos(&miner2_pubkey);
        assert_eq!(2, utxos.len(), "miner2 see its own utxos");

        let utxos = miner1_btc_controller.get_all_utxos(&miner2_pubkey);
        assert_eq!(2, utxos.len(), "miner1 see miner2 utxos");

        let utxos = miner2_btc_controller.get_all_utxos(&miner1_pubkey);
        assert_eq!(1, utxos.len(), "miner2 see miner1 own utxos");
    }

    #[test]
    #[ignore]
    fn test_get_utxos_ok_with_confirmation() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller.bootstrap_chain(101);

        let utxos_opt =
            btc_controller.get_utxos(&miner_pubkey, 1, None);
        let uxto_set = utxos_opt.expect("Shouldn't be None at height 101!");

        assert_eq!(1, uxto_set.num_utxos());
        assert_eq!(5_000_000_000, uxto_set.total_available());
        let utxos = uxto_set.utxos;
        assert_eq!(101, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);

        btc_controller.build_next_block(1);

        let utxos_opt =
            btc_controller.get_utxos(&miner_pubkey, 1, None);
        let uxto_set = utxos_opt.expect("Shouldn't be None at height 102!");

        assert_eq!(2, uxto_set.num_utxos());
        assert_eq!(10_000_000_000, uxto_set.total_available());
        let mut utxos = uxto_set.utxos;
        utxos.sort_by(|a, b| b.confirmations.cmp(&a.confirmations));
        assert_eq!(102, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);
        assert_eq!(101, utxos[1].confirmations);
        assert_eq!(5_000_000_000, utxos[1].amount);
    }

    #[test]
    #[ignore]
    fn test_get_utxos_none_due_to_filter_total_required() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller.bootstrap_chain(101); // one utxo exists

        let too_much_required = 10_000_000_000;
        let utxos = btc_controller.get_utxos(
            &miner_pubkey,
            too_much_required,
            None,
        );
        assert!(utxos.is_none(), "None because too much required");
    }

    #[test]
    #[ignore]
    fn test_get_utxos_none_due_to_filter_pubkey() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller.bootstrap_chain(101); // one utxo exists

        let other_pubkey = utils::create_miner2_pubkey();
        let utxos = btc_controller.get_utxos(&other_pubkey, 1, None);
        assert!(
            utxos.is_none(),
            "None because utxos for other pubkey don't exist"
        );
    }

    #[test]
    #[ignore]
    fn test_get_utxos_none_due_to_filter_utxo_exclusion() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller.bootstrap_chain(101); // one utxo exists

        let existent_utxo = btc_controller
            .get_utxos(&miner_pubkey, 0, None)
            .expect("utxo set should exist");
        let utxos = btc_controller.get_utxos(
            &miner_pubkey,
            0,
            Some(existent_utxo),
        );
        assert!(
            utxos.is_none(),
            "None because filtering exclude existent utxo set"
        );
    }

    #[test]
    #[ignore]
    fn test_tx_confirmed_from_utxo_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());

        btc_controller.bootstrap_chain(101);
        let utxos = btc_controller.get_all_utxos(&miner_pubkey);
        assert_eq!(1, utxos.len(), "One UTXO should be confirmed!");

        let txid = Txid::from_bitcoin_tx_hash(&utxos[0].txid);
        assert!(
            btc_controller.is_transaction_confirmed(&txid),
            "UTXO tx should be confirmed!"
        );
    }

    #[test]
    #[ignore]
    fn test_import_public_key_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let config = utils::create_cosigner_config();

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should be created!");

        let result = btc_controller.import_public_key(&miner_pubkey);
        assert!(
            result.is_ok(),
            "Should be ok, got err instead: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    #[ignore]
    fn test_import_public_key_twice_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let config = utils::create_cosigner_config();

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should be created!");

        btc_controller
            .import_public_key(&miner_pubkey)
            .expect("Import should be ok: first time!");

        //ok, but it is basically a no-op
        let result = btc_controller.import_public_key(&miner_pubkey);
        assert!(
            result.is_ok(),
            "Should be ok, got err instead: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    #[ignore]
    fn test_import_public_key_segwit_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();
        let config = utils::create_cosigner_config();

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinClient::new(config.clone());
        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should be created!");

        let result = btc_controller.import_public_key(&miner_pubkey);
        assert!(
            result.is_ok(),
            "Should be ok, got err instead: {:?}",
            result.unwrap_err()
        );
    }
}

