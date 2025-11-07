// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
// Copyright (C) 2022 Jude Nelson
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

use std::convert::TryFrom;
use std::error;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::net::TcpStream;

use clarity_types::types::QualifiedContractIdentifier;
use clarity_types::types::Value;
use clarity_types::types::PrincipalData;

use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::util::hash::Hash160;

use crate::storage::mock::LocalStackerDBClient;
use crate::net::Error;

use crate::net::run_http_request;
use crate::net::NeighborAddress;
use crate::net::{CallReadOnlyResponse, CallReadOnlyRequestBody};
use crate::net::session::{NodeSession, run_get_info};
use crate::net::HandshakeData;

use libstackerdb::*;

const STACKERDB_SLOTS_FUNCTION: &str = "stackerdb-get-signer-slots";
const STACKERDB_INV_MAX: u32 = 4096;

/// StackerDB client trait (so we can mock it in testing)
pub trait StackerDBClient: Send {
    /// Address of the stackerdb host we're talking to
    fn get_host(&self) -> SocketAddr;

    /// List all chunk metadata for the stackerdb
    fn list_chunks(&mut self) -> Result<Vec<SlotMetadata>, Error>;

    /// Get one or more chunks with specific versions.
    /// The ith entry in slots_and_versions corresponds to the ith item in the returned list.  A
    /// Some(..) value indicates that the chunk with that version exists.  A None value indicates
    /// that a chunk with that version does not exist.
    fn get_chunks(
        &mut self,
        slots_and_versions: &[(u32, u32)],
    ) -> Result<Vec<Option<Vec<u8>>>, Error>;

    /// Get one or more chunks regardless of what their versions are.
    /// The ith entry in slots_ids corresponds to the ith item in the returned list.  A
    /// Some(..) value indicates that the chunk exists.  A None value indicates
    /// that a chunk does not exist.
    fn get_latest_chunks(&mut self, slot_ids: &[u32])
        -> Result<Vec<Option<Vec<u8>>>, Error>;

    /// Upload a given chunk to the stackerdb
    fn put_chunk(
        &mut self,
        chunk: StackerDBChunkData,
    ) -> Result<StackerDBChunkAckData, Error>;

    /// Find a list of nodes that host this stackerdb.  These will be p2p addresses.
    fn find_replicas(&mut self) -> Result<Vec<SocketAddr>, Error>;

    /// Get the list of signers for the replica.
    fn get_signers(&mut self) -> Result<Vec<StacksAddress>, Error>;
}

pub struct StackerDBSession {
    /// host we're talking to
    pub host: SocketAddr,
    /// contract we're talking to
    pub stackerdb_contract_id: QualifiedContractIdentifier,
    /// connection to the replica
    sock: Option<TcpStream>,
}

impl StackerDBSession {
    /// instantiate but don't connect
    pub fn new(
        host: SocketAddr,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> StackerDBSession {
        StackerDBSession {
            host,
            stackerdb_contract_id,
            sock: None,
        }
    }

    /// connect or reconnect to the node
    fn connect_or_reconnect(&mut self) -> Result<(), Error> {
        m2_debug!("connect to {}", &self.host);
        self.sock = Some(TcpStream::connect(self.host).map_err(Error::IO)?);
        Ok(())
    }

    /// Do something with the connected socket
    fn with_socket<F, R>(&mut self, todo: F) -> Result<R, Error>
    where
        F: FnOnce(&mut StackerDBSession, &mut TcpStream) -> R,
    {
        self.connect_or_reconnect()?;
        let mut sock = if let Some(s) = self.sock.take() {
            s
        } else {
            return Err(Error::NotConnected);
        };

        let res = todo(self, &mut sock);

        self.sock = Some(sock);
        Ok(res)
    }

    /// send an HTTP RPC request and receive a reply.
    /// Return the HTTP reply, decoded if it was chunked
    fn rpc_request(
        &mut self,
        verb: &str,
        path: &str,
        content_type: Option<&str>,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.with_socket(|session, sock| {
            run_http_request(sock, &session.host, verb, path, content_type, payload)
        })?
    }

    /// connect to the replica
    pub fn connect(
        &mut self,
        host: SocketAddr,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> Result<(), Error> {
        self.host = host;
        self.stackerdb_contract_id = stackerdb_contract_id;
        self.connect_or_reconnect()
    }
}

impl StackerDBClient for StackerDBSession {
    fn get_host(&self) -> SocketAddr {
        self.host.clone()
    }

    /// query the replica for a list of chunks
    fn list_chunks(&mut self) -> Result<Vec<SlotMetadata>, Error> {
        let bytes = self.rpc_request(
            "GET",
            &stackerdb_get_metadata_path(self.stackerdb_contract_id.clone()),
            None,
            &[],
        )?;
        let metadata: Vec<SlotMetadata> =
            serde_json::from_slice(&bytes).map_err(|e| Error::DeserializeError(format!("{:?}", &e)))?;
        Ok(metadata)
    }

    /// query the replica for zero or more chunks
    fn get_chunks(
        &mut self,
        slots_and_versions: &[(u32, u32)],
    ) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let mut payloads = vec![];
        for (slot_id, slot_version) in slots_and_versions.iter() {
            let path = stackerdb_get_chunk_path(
                self.stackerdb_contract_id.clone(),
                *slot_id,
                Some(*slot_version),
            );
            let chunk = match self.rpc_request("GET", &path, None, &[]) {
                Ok(body_bytes) => Some(body_bytes),
                Err(Error::HttpError(code, headers, offset)) => {
                    if code != 404 {
                        return Err(Error::HttpError(code, headers, offset));
                    }
                    None
                }
                Err(e) => {
                    return Err(e);
                }
            };
            payloads.push(chunk);
        }
        Ok(payloads)
    }

    /// query the replica for zero or more latest chunks
    fn get_latest_chunks(&mut self, slot_ids: &[u32]) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let mut payloads = vec![];
        for slot_id in slot_ids.iter() {
            let path = stackerdb_get_chunk_path(self.stackerdb_contract_id.clone(), *slot_id, None);
            let chunk = match self.rpc_request("GET", &path, None, &[]) {
                Ok(body_bytes) => Some(body_bytes),
                Err(Error::HttpError(code, headers, offset)) => {
                    if code != 404 {
                        return Err(Error::HttpError(code, headers, offset));
                    }
                    None
                }
                Err(e) => {
                    return Err(e);
                }
            };
            payloads.push(chunk);
        }
        Ok(payloads)
    }

    /// upload a chunk
    fn put_chunk(&mut self, chunk: StackerDBChunkData) -> Result<StackerDBChunkAckData, Error> {
        let body =
            serde_json::to_vec(&chunk).map_err(|e| Error::DeserializeError(format!("{:?}", &e)))?;
        let path = stackerdb_post_chunk_path(self.stackerdb_contract_id.clone());
        let resp_bytes = self.rpc_request("POST", &path, Some("application/json"), &body)?;
        let ack: StackerDBChunkAckData = serde_json::from_slice(&resp_bytes)
            .map_err(|e| Error::DeserializeError(format!("{:?}", &e)))?;
        Ok(ack)
    }

    /// Find the list of replicas
    fn find_replicas(&mut self) -> Result<Vec<SocketAddr>, Error> {
        run_get_stackerdb_replicas(&self.host, &self.stackerdb_contract_id)
    }

    /// Get the signers for a StackerDB.
    /// Return the list of addresses for each slot
    fn get_signers(&mut self) -> Result<Vec<StacksAddress>, Error> {
        run_get_stackerdb_signers(&self.host, &self.stackerdb_contract_id)
    }
}

pub fn run_get_stackerdb_replicas(
    node_addr: &SocketAddr,
    contract_id: &QualifiedContractIdentifier,
) -> Result<Vec<SocketAddr>, Error> {
    let mut sock = TcpStream::connect(node_addr).map_err(Error::IO)?;
    let stacks_address = StacksAddress::new(
        contract_id.issuer.version(),
        Hash160(contract_id.issuer.1.clone()),
    )
    .map_err(|e| Error::SerializeError(format!("Failed to build a Stacks address: {:?}", &e)))?;

    m2_debug!(
        "Get all StackerDB replicas of {} from {}",
        contract_id,
        node_addr
    );
    let bytes = run_http_request(
        &mut sock,
        node_addr,
        "GET",
        &format!(
            "/v2/stackerdb/{}/{}/replicas",
            &stacks_address, &contract_id.name
        ),
        None,
        &[],
    )?;

    let response: Vec<NeighborAddress> = serde_json::from_slice(&bytes)
        .map_err(|_| Error::DeserializeError("Failed to decode replica list".into()))?;

    Ok(response
        .into_iter()
        .map(|na| na.addrbytes.to_socketaddr(na.port))
        .collect())
}

/// Run a read-only function call on the node, given a resolved socket address to the node
pub fn run_call_readonly(
    node_addr: &SocketAddr,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    function_args: &[Value],
) -> Result<Value, Error> {
    let mut sock = TcpStream::connect(node_addr).map_err(Error::IO)?;

    let mut arguments = vec![];
    for arg in function_args.iter() {
        let v = arg.serialize_to_hex()?;
        arguments.push(v);
    }

    let payload = CallReadOnlyRequestBody {
        sender: format!("{}", &contract_id.issuer),
        sponsor: None,
        arguments,
    };
    let payload_json = serde_json::to_string(&payload)
        .map_err(|_| Error::RPCError("Could not serialize call-read-only request".into()))?;

    m2_debug!(
        "call-readonly {} {}: {}",
        &contract_id,
        function_name,
        &payload_json
    );
    let bytes = run_http_request(
        &mut sock,
        node_addr,
        "POST",
        &format!(
            "/v2/contracts/call-read/{}/{}/{}",
            &contract_id.issuer, &contract_id.name, function_name
        ),
        Some("application/json"),
        payload_json.as_bytes(),
    )?;

    // try to convert into the response
    let response: CallReadOnlyResponse = serde_json::from_slice(&bytes).map_err(|_| {
        Error::DeserializeError("Failed to decode call-read-only response bytes".into())
    })?;
    if !response.okay {
        return Err(Error::RPCError(format!(
            "reason: {}",
            &response.cause.unwrap_or("(no cause given)".into())
        )));
    }

    let Some(result) = response.result else {
        return Err(Error::RPCError("No result given".into()));
    };

    let result = result
        .strip_prefix("0x")
        .map(|s| s.to_string())
        .unwrap_or(result);
    let value = Value::try_deserialize_hex_untyped(&result).map_err(|_| {
        Error::DeserializeError(format!(
            "Failed to decode hex string into clarity value: {}",
            &result
        ))
    })?;
    Ok(value)
}

/// Decode `{signer: principal, num-slots: uint}`
/// Cribbed from the Stacks blockchain (https://github.com/stacks-network/stacks-core)
fn parse_stackerdb_signer_slot_entry(
    entry: Value,
    contract_id: &QualifiedContractIdentifier,
) -> Result<(StacksAddress, u32), String> {
    let Value::Tuple(slot_data) = entry else {
        let reason = format!(
            "StackerDB fn `{contract_id}.{STACKERDB_SLOTS_FUNCTION}` returned non-tuple slot entry",
        );
        return Err(reason);
    };

    let Ok(Value::Principal(signer_principal)) = slot_data.get("signer") else {
        let reason = format!(
            "StackerDB fn `{contract_id}.{STACKERDB_SLOTS_FUNCTION}` returned tuple without `signer` entry of type `principal`",
        );
        return Err(reason);
    };

    let Ok(Value::UInt(num_slots)) = slot_data.get("num-slots") else {
        let reason = format!(
            "StackerDB fn `{contract_id}.{STACKERDB_SLOTS_FUNCTION}` returned tuple without `num-slots` entry of type `uint`",
        );
        return Err(reason);
    };

    let num_slots = u32::try_from(*num_slots)
        .map_err(|_| format!("Contract `{contract_id}` set too many slots for one signer (max = {STACKERDB_INV_MAX})"))?;
    if num_slots > STACKERDB_INV_MAX {
        return Err(format!("Contract `{contract_id}` set too many slots for one signer (max = {STACKERDB_INV_MAX})"));
    }

    let PrincipalData::Standard(standard_principal) = signer_principal else {
        return Err(format!(
            "StackerDB contract `{contract_id}` set a contract principal as a writer, which is not supported"
        ));
    };
    let addr = StacksAddress::from(standard_principal.clone());
    Ok((addr, num_slots))
}

/// Attempt to decode the value returned from `stackerdb-get-signer-slots` into a list of
/// signers and the number of slots they got.
///
/// Cribbed from the Stacks blockchain (https://github.com/stacks-network/stacks-core)
fn eval_signer_slots(
    contract_id: &QualifiedContractIdentifier,
    value: Value,
) -> Result<Vec<(StacksAddress, u32)>, Error> {
    let result = value.expect_result()?;
    let slot_list = match result {
        Err(err_val) => {
            let err_code = err_val.expect_u128()?;
            let reason = format!(
                "Contract {} failed to run `stackerdb-get-signer-slots`: error u{}",
                contract_id, &err_code
            );
            m2_warn!("{}", &reason);
            return Err(Error::DeserializeError(reason));
        }
        Ok(ok_val) => ok_val.expect_list()?,
    };

    let mut total_num_slots = 0u32;
    let mut ret = vec![];
    for slot_value in slot_list.into_iter() {
        let (addr, num_slots) =
            parse_stackerdb_signer_slot_entry(slot_value, contract_id).map_err(|e| {
                let msg = format!("Failed to parse StackerDB slot entry: {}", &e);
                m2_warn!("{}", &msg);
                Error::DeserializeError(msg)
            })?;

        if num_slots > STACKERDB_INV_MAX {
            let reason = format!(
                "Contract {} stipulated more than maximum number of slots for one signer ({})",
                contract_id, STACKERDB_INV_MAX
            );
            m2_warn!("{}", &reason);
            return Err(Error::DeserializeError(reason));
        }

        total_num_slots = total_num_slots
            .checked_add(num_slots)
            .ok_or(Error::DeserializeError(format!(
                "Contract {} stipulates more than u32::MAX slots",
                &contract_id
            )))?;

        if total_num_slots > STACKERDB_INV_MAX.into() {
            let reason = format!(
                "Contract {} stipulated more than the maximum number of slots",
                contract_id
            );
            m2_warn!("{}", &reason);
            return Err(Error::DeserializeError(reason));
        }

        ret.push((addr, num_slots));
    }
    Ok(ret)
}

/// Get the (uncompressed) list of signers for a stackerdb
pub fn run_get_stackerdb_signers(
    node_addr: &SocketAddr,
    contract_id: &QualifiedContractIdentifier,
) -> Result<Vec<StacksAddress>, Error> {
    let slots_val =
        run_call_readonly(node_addr, contract_id, STACKERDB_SLOTS_FUNCTION, &[])?;
    let slots_runs = eval_signer_slots(contract_id, slots_val)?;

    // decompress
    let mut slots = vec![];
    for (signer_addr, num_slots) in slots_runs {
        for _ in 0..num_slots {
            slots.push(signer_addr.clone());
        }
    }
    Ok(slots)
}

/// Run a node handshake
pub fn run_node_handshake(
    node_data_addr: &SocketAddr,
    p2p_node_addr: &SocketAddr,
) -> Result<HandshakeData, Error> {
    let session =
        NodeSession::begin(node_data_addr.clone(), p2p_node_addr.clone())?;

    Ok(session.handshake_accept_data.ok_or(Error::SessionError(format!("Failed to handshake with {}", p2p_node_addr)))?)
}

/// resolve a StackerDB p2p address to its data address
pub fn run_resolve_stackerdb_host(
    node_addr: &SocketAddr,
    replica_p2p_addr: &SocketAddr,
) -> Result<SocketAddr, Error> {
    // resolve its data port
    let handshake_data = run_node_handshake(node_addr, &replica_p2p_addr)?;
    let replica_addr = handshake_data
        .data_url
        .try_get_socketaddr()
        .map_err(Error::IO)?
        .ok_or_else(|| Error::LookupError(handshake_data.data_url.to_string()))?;

    Ok(replica_addr)
}


/// Given the address of a local Stacks node, find the address of a node that can serve a given
/// replica.
/// Note that the address will be the p2p address, not the rpc address.
/// Use `run_node_handshake()` to get the rpc address (among other things)
pub fn run_find_stackerdb(
    node_addr: &SocketAddr,
    contract_id: &QualifiedContractIdentifier,
) -> Result<SocketAddr, Error> {
    // does this node replicate it?
    let mut rpc_info = run_get_info(node_addr)?;
    let Some(stacker_dbs) = rpc_info.stackerdbs.take() else {
        // this node doesn't support stackerdbs
        return Err(Error::RPCError(format!(
            "Node {} does not support StackerDBs",
            node_addr
        )));
    };

    let contract_str = contract_id.to_string();
    for db in stacker_dbs {
        if db == contract_str {
            // this node replicates this DB
            return Ok(node_addr.clone());
        }
    }

    m2_debug!(
        "Find stackerdb replica for {} from {}",
        contract_id,
        node_addr
    );

    // this node does not replicate this DB, so ask it for one that does
    let mut replicas = run_get_stackerdb_replicas(node_addr, contract_id)?;
    let Some(replica) = replicas.pop() else {
        return Err(Error::RPCError(format!(
            "Node {} cannot find a replica for StackerDB {}",
            node_addr, contract_id
        )));
    };

    // resolve its data port
    Ok(run_resolve_stackerdb_host(node_addr, &replica)?)
}

