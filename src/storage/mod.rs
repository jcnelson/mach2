// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
// Copyright (C) 2023 Jude Nelson
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

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use rusqlite::Error as sqlite_error;

use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use stacks_common::codec::Error as CodecError;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::codec::{read_next, read_next_at_most, write_next};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::{hex_bytes, to_hex};
use stacks_common::types::chainstate::StacksPrivateKey;

use clarity_types::types::QualifiedContractIdentifier;

use crate::util::sqlite::Error as DBError;
use crate::net::Error;

use libstackerdb::{SlotMetadata, StackerDBChunkAckData, StackerDBChunkData};

use serde;
use serde::de::SeqAccess;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};

use crate::net::session::*;
use crate::net::stackerdb::*;
use crate::storage::mock::{MockStackerDBClient, LocalStackerDBClient};

use crate::core::config::Config;

pub mod mock;
pub mod stackerdb;

/// Instantiated handle to mach2 stackerdb storage
pub struct M2Storage {
    /// home node address
    node: Option<SocketAddr>,
    /// connection to a node with a replica
    replica_client: Box<dyn StackerDBClient>,
    /// connection to the home node
    home_client: Box<dyn StackerDBClient>,
    /// signing key
    privkey: Secp256k1PrivateKey,
    /// cached chunks
    chunks: HashMap<u32, Vec<u8>>,
    /// cached copy of the signers in the DB
    signers: Option<Vec<StacksAddress>>,
}

impl M2Storage {
    pub fn resolve_config_node(config: &Config) -> Result<Option<SocketAddr>, Error> {
        let mut addrs: Vec<_> = config.get_node_addr()
            .to_socket_addrs()
            .map_err(Error::IO)?
            .into_iter()
            .collect();
        return Ok(addrs.pop());
    }

    pub fn resolve_home_node(&mut self, config: &Config) -> Result<Option<SocketAddr>, Error> {
        if self.node.is_none() {
            let addr = Self::resolve_config_node(config)?;
            if let Some(addr) = addr.as_ref() {
                self.node = Some(addr.clone());
            }
            return Ok(addr);
        }
        Ok(self.node.clone())
    }

    #[cfg(test)]
    pub fn get_home_stackerdb_client(
        _config: &Config,
        _contract: QualifiedContractIdentifier,
        privkey: StacksPrivateKey,
    ) -> Result<Box<dyn StackerDBClient>, Error> {
        Ok(Box::new(MockStackerDBClient::new(privkey, 16)))
    }

    #[cfg(test)]
    pub fn get_replica_stackerdb_client(
        _config: &Config,
        _contract: QualifiedContractIdentifier,
        privkey: StacksPrivateKey,
    ) -> Result<Box<dyn StackerDBClient>, Error> {
        Ok(Box::new(MockStackerDBClient::new(privkey, 16)))
    }

    #[cfg(not(test))]
    pub fn get_home_stackerdb_client(
        config: &Config,
        contract: QualifiedContractIdentifier,
        _ignored: StacksPrivateKey,
    ) -> Result<Box<dyn StackerDBClient>, Error> {
        if let Some(db_path) = config.mock_stackerdb_paths().get(&contract) {
            // use DB on disk instead
            if let Err(e) = std::fs::metadata(db_path) {
                return Err(Error::SessionError(
                    format!(
                        "Failed to connect to mock StackerDB at '{}': {:?}",
                        db_path, &e
                    ),
                ));
            }
            let mock_client = LocalStackerDBClient::open(db_path)?;
            return Ok(Box::new(mock_client));
        }

        let home_node_addr = Self::resolve_config_node(config)?
            .ok_or(Error::LookupError("Unable to resolve node".to_string()))?;

        Ok(Box::new(StackerDBSession::new(home_node_addr, contract)))
    }

    #[cfg(not(test))]
    pub fn get_replica_stackerdb_client(
        config: &Config,
        contract: QualifiedContractIdentifier,
        _ignored: StacksPrivateKey,
    ) -> Result<Box<dyn StackerDBClient>, Error> {
        if let Some(db_path) = config.mock_stackerdb_paths().get(&contract) {
            // use DB on disk instead
            if let Err(e) = std::fs::metadata(db_path) {
                return Err(Error::SessionError(
                    format!(
                        "Failed to connect to mock StackerDB at '{}': {:?}",
                        db_path, &e
                    )
                ));
            }
            let mock_client = LocalStackerDBClient::open(db_path)?;
            return Ok(Box::new(mock_client));
        }
        let home_node_addr = Self::resolve_config_node(config)?
            .ok_or_else(|| Error::LookupError("Unable to resolve node".to_string()))?;

        let replica_node_addr = run_find_stackerdb(&home_node_addr, &contract).map_err(|e| {
            Error::SessionError(
                format!("Unable to find replica for {}: {:?}", &contract, &e),
            )
        })?;

        Ok(Box::new(StackerDBSession::new(replica_node_addr, contract)))
    }

    pub fn open_session(config: &Config, stackerdb_addr: &QualifiedContractIdentifier) -> Result<Self, Error> {
        let privkey = config.private_key().clone();
        let home_stackerdb_client = Self::get_home_stackerdb_client(config, stackerdb_addr.clone(), privkey.clone())?;
        let replica_stackerdb_client = Self::get_replica_stackerdb_client(config, stackerdb_addr.clone(), privkey.clone())?;
        let session = Self::open(home_stackerdb_client, replica_stackerdb_client, privkey)?;
        Ok(session)
    }
}

