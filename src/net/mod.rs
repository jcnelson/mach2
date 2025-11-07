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

pub mod codec;
pub mod http;
pub mod session;
pub mod stackerdb;

#[cfg(test)]
pub mod tests;

use std::fmt;
use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::collections::HashMap;

use rusqlite::Error as RusqliteError;

use clarity_types::types::{QualifiedContractIdentifier};

use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{Hash160, Sha256Sum};
use stacks_common::util::serde_serializers::prefix_opt_hex;
use stacks_common::util::serde_serializers::prefix_hex;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::types::net::PeerAddress;

use serde::Deserialize;
use serde::Serialize;

use libstackerdb::Error as LibstackerdbError;

use crate::util::sqlite::Error as DBError;

use stacks_common::codec::Error as CodecError;

use clarity_types::errors::InterpreterError as ClarityInterpreterError;
use clarity_types::Error as ClarityError;

pub use http::run_http_request;

use crate::util::string::UrlString;

#[derive(Debug)]
pub enum Error {
    /// Failed to encode
    SerializeError(String),
    /// Failed to read
    ReadError(io::Error),
    /// Failed to decode
    DeserializeError(String),
    /// Failed to write
    WriteError(io::Error),
    /// Underflow -- not enough bytes to form the message
    UnderflowError(String),
    /// Overflow -- message too big
    OverflowError(String),
    /// Catch-all I/O error
    IO(io::Error),
    /// Wrong protocol family
    WrongProtocolFamily,
    /// Array is too big
    ArrayTooLong,
    /// Receive timed out
    RecvTimeout,
    /// Error signing a message
    SigningError(String),
    /// Error verifying a message
    VerifyingError(String),
    /// Read stream is drained.  Try again
    TemporarilyDrained,
    /// Read stream has reached EOF (socket closed, end-of-file reached, etc.)
    PermanentlyDrained,
    /// Failed to read from the FS
    FilesystemError,
    /// Socket mutex was poisoned
    SocketMutexPoisoned,
    /// Socket not instantiated
    SocketNotConnectedToPeer,
    /// Not connected to peer
    ConnectionBroken,
    /// Connection could not be (re-)established
    ConnectionError,
    /// Too many outgoing messages
    OutboxOverflow,
    /// Too many incoming messages
    InboxOverflow,
    /// Send error
    SendError(String),
    /// Recv error
    RecvError(String),
    /// Invalid message
    InvalidMessage,
    /// Invalid network handle
    InvalidHandle,
    /// Network handle is full
    FullHandle,
    /// Invalid handshake
    InvalidHandshake,
    /// Stale neighbor
    StaleNeighbor,
    /// No such neighbor
    NoSuchNeighbor,
    /// Failed to bind
    BindError,
    /// Failed to poll
    PollError,
    /// Failed to accept
    AcceptError,
    /// Failed to register socket with poller
    RegisterError,
    /// Failed to query socket metadata
    SocketError,
    /// server is not bound to a socket
    NotConnected,
    /// Remote peer is not connected
    PeerNotConnected,
    /// Too many peers
    TooManyPeers,
    /// Message already in progress
    InProgress,
    /// Peer is denied
    Denied,
    /// Data URL is not known
    NoDataUrl,
    /// Peer is transmitting too fast
    PeerThrottled,
    /// Error resolving a DNS name
    LookupError(String),
    /// Coordinator hung up
    CoordinatorClosed,
    /// view of state is stale (e.g. from the sortition db)
    StaleView,
    /// Tried to connect to myself
    ConnectionCycle,
    /// Requested data not found
    NotFoundError,
    /// Transient error (akin to EAGAIN)
    Transient(String),
    /// Expected end-of-stream, but had more data
    ExpectedEndOfStream,
    /// chunk is stale
    StaleChunk {
        supplied_version: u32,
        latest_version: u32,
    },
    /// no such slot
    NoSuchSlot(QualifiedContractIdentifier, u32),
    /// no such DB
    NoSuchStackerDB(QualifiedContractIdentifier),
    /// stacker DB exists
    StackerDBExists(QualifiedContractIdentifier),
    /// slot signer is wrong
    BadSlotSigner(StacksAddress, u32),
    /// too many writes to a slot
    TooManySlotWrites {
        supplied_version: u32,
        max_writes: u32,
    },
    /// too frequent writes to a slot
    TooFrequentSlotWrites(u64),
    /// Invalid control smart contract for a Stacker DB
    InvalidStackerDBContract(QualifiedContractIdentifier, String),
    /// state machine step took too long
    StepTimeout,
    /// stacker DB chunk is too big
    StackerDBChunkTooBig(usize),
    /// Invalid state machine state reached
    InvalidState,
    /// Network request was bad
    MalformedRequest(String),
    /// Network respones was bad
    MalformedResponse(String),
    /// HTTP error
    HttpError(u32, HashMap<String, String>, usize),
    /// RPC error
    RPCError(String),
    /// DB error
    DBError(DBError),
    /// Clarity Interpreter Error
    ClarityInterpreterError(ClarityInterpreterError),
    /// Clarity top-level Error
    ClarityError(ClarityError),
    /// Local storage error
    StorageError(String),
    /// GetChunk error
    GetChunk(String),
    /// PutChunk error
    PutChunk(String),
    /// no such chunk
    NoSuchChunk,
    /// nod esession error
    SessionError(String),
}

impl From<LibstackerdbError> for Error {
    fn from(e: LibstackerdbError) -> Self {
        match e {
            LibstackerdbError::SigningError(s) => Error::SigningError(s),
            LibstackerdbError::VerifyingError(s) => Error::VerifyingError(s),
        }
    }
}

impl From<CodecError> for Error {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::SerializeError(s) => Error::SerializeError(s),
            CodecError::ReadError(e) => Error::ReadError(e),
            CodecError::DeserializeError(s) => Error::DeserializeError(s),
            CodecError::WriteError(e) => Error::WriteError(e),
            CodecError::UnderflowError(s) => Error::UnderflowError(s),
            CodecError::OverflowError(s) => Error::OverflowError(s),
            CodecError::ArrayTooLong => Error::ArrayTooLong,
            CodecError::SigningError(s) => Error::SigningError(s),
            CodecError::GenericError(_) => Error::InvalidMessage,
        }
    }
}

impl From<ClarityInterpreterError> for Error {
    fn from(e: ClarityInterpreterError) -> Self {
        Self::ClarityInterpreterError(e)
    }
}

impl From<ClarityError> for Error {
    fn from(e: ClarityError) -> Self {
        Self::ClarityError(e)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Self {
        Self::DBError(e)
    }
}

impl From<RusqliteError> for Error {
    fn from(e: RusqliteError) -> Self {
        Self::DBError(DBError::SqliteError(e))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::SerializeError(ref s) => fmt::Display::fmt(s, f),
            Error::DeserializeError(ref s) => fmt::Display::fmt(s, f),
            Error::ReadError(ref io) => fmt::Display::fmt(io, f),
            Error::WriteError(ref io) => fmt::Display::fmt(io, f),
            Error::UnderflowError(ref s) => fmt::Display::fmt(s, f),
            Error::OverflowError(ref s) => fmt::Display::fmt(s, f),
            Error::IO(ref e) => fmt::Display::fmt(e, f),
            Error::WrongProtocolFamily => write!(f, "Improper use of protocol family"),
            Error::ArrayTooLong => write!(f, "Array too long"),
            Error::RecvTimeout => write!(f, "Packet receive timeout"),
            Error::SigningError(ref s) => fmt::Display::fmt(s, f),
            Error::VerifyingError(ref s) => fmt::Display::fmt(s, f),
            Error::TemporarilyDrained => {
                write!(f, "Temporarily out of bytes to read; try again later")
            }
            Error::PermanentlyDrained => write!(f, "Out of bytes to read"),
            Error::FilesystemError => write!(f, "Disk I/O error"),
            Error::SocketMutexPoisoned => write!(f, "socket mutex was poisoned"),
            Error::SocketNotConnectedToPeer => write!(f, "not connected to peer"),
            Error::ConnectionBroken => write!(f, "connection to peer node is broken"),
            Error::ConnectionError => write!(f, "connection to peer could not be (re-)established"),
            Error::OutboxOverflow => write!(f, "too many outgoing messages queued"),
            Error::InboxOverflow => write!(f, "too many messages pending"),
            Error::SendError(ref s) => fmt::Display::fmt(s, f),
            Error::RecvError(ref s) => fmt::Display::fmt(s, f),
            Error::InvalidMessage => write!(f, "invalid message (malformed or bad signature)"),
            Error::InvalidHandle => write!(f, "invalid network handle"),
            Error::FullHandle => write!(f, "network handle is full and needs to be drained"),
            Error::InvalidHandshake => write!(f, "invalid handshake from remote peer"),
            Error::StaleNeighbor => write!(f, "neighbor is too far behind the chain tip"),
            Error::NoSuchNeighbor => write!(f, "no such neighbor"),
            Error::BindError => write!(f, "Failed to bind to the given address"),
            Error::PollError => write!(f, "Failed to poll"),
            Error::AcceptError => write!(f, "Failed to accept connection"),
            Error::RegisterError => write!(f, "Failed to register socket with poller"),
            Error::SocketError => write!(f, "Socket error"),
            Error::NotConnected => write!(f, "Not connected to peer network"),
            Error::PeerNotConnected => write!(f, "Remote peer is not connected to us"),
            Error::TooManyPeers => write!(f, "Too many peer connections open"),
            Error::InProgress => write!(f, "Message already in progress"),
            Error::Denied => write!(f, "Peer is denied"),
            Error::NoDataUrl => write!(f, "No data URL available"),
            Error::PeerThrottled => write!(f, "Peer is transmitting too fast"),
            Error::LookupError(ref s) => fmt::Display::fmt(s, f),
            Error::CoordinatorClosed => write!(f, "Coordinator hung up"),
            Error::StaleView => write!(f, "State view is stale"),
            Error::ConnectionCycle => write!(f, "Tried to connect to myself"),
            Error::NotFoundError => write!(f, "Requested data not found"),
            Error::Transient(ref s) => write!(f, "Transient network error: {}", s),
            Error::ExpectedEndOfStream => write!(f, "Expected end-of-stream"),
            Error::StaleChunk {
                supplied_version,
                latest_version,
            } => {
                write!(
                    f,
                    "Stale DB chunk (supplied={},latest={})",
                    supplied_version, latest_version
                )
            }
            Error::NoSuchSlot(ref addr, ref slot_id) => {
                write!(f, "No such DB slot ({},{})", addr, slot_id)
            }
            Error::NoSuchStackerDB(ref addr) => {
                write!(f, "No such StackerDB {}", addr)
            }
            Error::StackerDBExists(ref addr) => {
                write!(f, "StackerDB already exists: {}", addr)
            }
            Error::BadSlotSigner(ref addr, ref slot_id) => {
                write!(f, "Bad DB slot signer ({},{})", addr, slot_id)
            }
            Error::TooManySlotWrites {
                supplied_version,
                max_writes,
            } => {
                write!(
                    f,
                    "Too many slot writes (max={},given={})",
                    max_writes, supplied_version
                )
            }
            Error::TooFrequentSlotWrites(ref deadline) => {
                write!(f, "Too frequent slot writes (deadline={})", deadline)
            }
            Error::InvalidStackerDBContract(ref contract_id, ref reason) => {
                write!(
                    f,
                    "Invalid StackerDB control smart contract {}: {}",
                    contract_id, reason
                )
            }
            Error::StepTimeout => write!(f, "State-machine step took too long"),
            Error::StackerDBChunkTooBig(ref sz) => {
                write!(f, "StackerDB chunk size is too big ({})", sz)
            }
            Error::InvalidState => write!(f, "Invalid state-machine state reached"),
            Error::MalformedRequest(ref s) => write!(f, "Malformed request: {}", s),
            Error::MalformedResponse(ref s) => write!(f, "Malformed response: {}", s),
            Error::HttpError(ref code, ref _headers, ref _body_offset) => {
                write!(f, "Bad HTTP code: {}", code)
            }
            Error::RPCError(ref msg) => write!(f, "RPC error: {}", msg),
            Error::ClarityInterpreterError(ref e) => write!(f, "Clarity interpeter error: {:?}", e),
            Error::ClarityError(ref e) => write!(f, "Clarity error: {:?}", e),
            Error::DBError(ref e) => write!(f, "DB error: {}", e),
            Error::StorageError(ref s) => write!(f, "Storage error: {}", s),
            Error::GetChunk(ref s) => write!(f, "StackerDB get-chunk failed: {}", s),
            Error::PutChunk(ref s) => write!(f, "StackerDB put-chunk failed: {}", s),
            Error::NoSuchChunk => write!(f, "No such StackerDB chunk"),
            Error::SessionError(ref s) => write!(f, "Node p2p session error: {}", s),
        }
    }
}


/// The response to GET /v2/info, omitting things like the anchor block and affirmation maps (since
/// we don't have the structs for them available in stacks_common).
/// Cribbed from the Stacks blockchain (https://github.com/stacks-network/stacks-core)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCPeerInfoData {
    pub peer_version: u32,
    pub pox_consensus: ConsensusHash,
    pub burn_block_height: u64,
    pub stable_pox_consensus: ConsensusHash,
    pub stable_burn_block_height: u64,
    pub server_version: String,
    pub network_id: u32,
    pub parent_network_id: u32,
    pub stacks_tip_height: u64,
    pub stacks_tip: BlockHeaderHash,
    pub stacks_tip_consensus_hash: ConsensusHash,
    pub genesis_chainstate_hash: Sha256Sum,
    pub unanchored_tip: Option<StacksBlockId>,
    pub unanchored_seq: Option<u16>,
    pub exit_at_block_height: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_public_key: Option<StacksPublicKeyBuffer>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_public_key_hash: Option<Hash160>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stackerdbs: Option<Vec<String>>,
}

/// Struct for sortition information returned via the GetSortition API call
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct RPCSortitionInfo {
    /// The burnchain header hash of the block that triggered this event.
    #[serde(with = "prefix_hex")]
    pub burn_block_hash: BurnchainHeaderHash,
    /// The burn height of the block that triggered this event.
    pub burn_block_height: u64,
    /// The burn block time of the sortition
    pub burn_header_timestamp: u64,
    /// This sortition ID of the block that triggered this event. This incorporates
    ///  PoX forking information and the burn block hash to obtain an identifier that is
    ///  unique across PoX forks and burnchain forks.
    #[serde(with = "prefix_hex")]
    pub sortition_id: SortitionId,
    /// The parent of this burn block's Sortition ID
    #[serde(with = "prefix_hex")]
    pub parent_sortition_id: SortitionId,
    /// The consensus hash of the block that triggered this event. This incorporates
    ///  PoX forking information and burn op information to obtain an identifier that is
    ///  unique across PoX forks and burnchain forks.
    #[serde(with = "prefix_hex")]
    pub consensus_hash: ConsensusHash,
    /// Boolean indicating whether or not there was a succesful sortition (i.e. a winning
    ///  block or miner was chosen).
    ///
    /// This will *also* be true if this sortition corresponds to a shadow block.  This is because
    /// the signer does not distinguish between shadow blocks and blocks with sortitions, so until
    /// we can update the signer and this interface, we'll have to report the presence of a shadow
    /// block tenure in a way that the signer currently understands.
    pub was_sortition: bool,
    /// If sortition occurred, and the miner's VRF key registration
    ///  associated a nakamoto mining pubkey with their commit, this
    ///  will contain the Hash160 of that mining key.
    #[serde(with = "prefix_opt_hex")]
    pub miner_pk_hash160: Option<Hash160>,
    /// If sortition occurred, this will be the consensus hash of the burn block corresponding
    /// to the winning block commit's parent block ptr. In 3.x, this is the consensus hash of
    /// the tenure that this new burn block's miner will be building off of.
    #[serde(with = "prefix_opt_hex")]
    pub stacks_parent_ch: Option<ConsensusHash>,
    /// If sortition occurred, this will be the consensus hash of the most recent sortition before
    ///  this one.
    #[serde(with = "prefix_opt_hex")]
    pub last_sortition_ch: Option<ConsensusHash>,
    #[serde(with = "prefix_opt_hex")]
    /// In Stacks 2.x, this is the winning block.
    /// In Stacks 3.x, this is the first block of the parent tenure.
    pub committed_block_hash: Option<BlockHeaderHash>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CallReadOnlyRequestBody {
    pub sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sponsor: Option<String>,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallReadOnlyResponse {
    pub okay: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

/// P2P message preamble -- included in all p2p network messages
#[derive(Debug, Clone, PartialEq)]
pub struct Preamble {
    pub peer_version: u32,                           // software version
    pub network_id: u32,                             // mainnet, testnet, etc.
    pub seq: u32, // message sequence number -- pairs this message to a request
    pub burn_block_height: u64, // last-seen block height (at chain tip)
    pub burn_block_hash: BurnchainHeaderHash, // hash of the last-seen burn block
    pub burn_stable_block_height: u64, // latest stable block height (e.g. chain tip minus 7)
    pub burn_stable_block_hash: BurnchainHeaderHash, // latest stable burnchain header hash.
    pub additional_data: u32, // RESERVED; pointer to additional data (should be all 0's if not used)
    pub signature: MessageSignature, // signature from the peer that sent this
    pub payload_len: u32,     // length of the following payload, including relayers vector
}

/// A descriptor of a peer
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NeighborAddress {
    #[serde(rename = "ip")]
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub public_key_hash: Hash160, // used as a hint; useful for when a node trusts another node to be honest about this
}

impl fmt::Display for NeighborAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}://{:?}",
            &self.public_key_hash,
            &self.addrbytes.to_socketaddr(self.port)
        )
    }
}

impl fmt::Debug for NeighborAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}://{:?}",
            &self.public_key_hash,
            &self.addrbytes.to_socketaddr(self.port)
        )
    }
}

impl NeighborAddress {
    pub fn clear_public_key(&mut self) {
        self.public_key_hash = Hash160([0u8; 20]);
    }

    pub fn to_socketaddr(&self) -> SocketAddr {
        self.addrbytes.to_socketaddr(self.port)
    }
}

/// Handshake request -- this is the first message sent to a peer.
/// The remote peer will reply a HandshakeAccept with just a preamble
/// if the peer accepts.  Otherwise it will get a HandshakeReject with just
/// a preamble.
///
/// To keep peer knowledge fresh, nodes will send handshakes to each other
/// as heartbeat messages.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeData {
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub services: u16, // bit field representing services this node offers
    pub node_public_key: StacksPublicKeyBuffer,
    pub expire_block_height: u64, // burn block height after which this node's key will be revoked,
    pub data_url: UrlString,
}

#[repr(u8)]
pub enum ServiceFlags {
    RELAY = 0x01,
    RPC = 0x02,
    STACKERDB = 0x04,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeAcceptData {
    pub handshake: HandshakeData, // this peer's handshake information
    pub heartbeat_interval: u32,  // hint as to how long this peer will remember you
}

/// Inform the remote peer of (a page of) the list of stacker DB contracts this node supports
#[derive(Debug, Clone, PartialEq)]
pub struct StackerDBHandshakeData {
    /// current reward cycle consensus hash (i.e. the consensus hash of the Stacks tip in the
    /// current reward cycle, which commits to both the Stacks block tip and the underlying PoX
    /// history).
    pub rc_consensus_hash: ConsensusHash,
    /// list of smart contracts that we index.
    /// there can be as many as 256 entries.
    pub smart_contracts: Vec<QualifiedContractIdentifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NackData {
    pub error_code: u32,
}
pub mod NackErrorCodes {
    /// A handshake has not yet been completed with the requester
    /// and it is required before the protocol can proceed
    pub const HandshakeRequired: u32 = 1;
    /// The request depends on a burnchain block that this peer does not recognize
    pub const NoSuchBurnchainBlock: u32 = 2;
    /// The remote peer has exceeded local per-peer bandwidth limits
    pub const Throttled: u32 = 3;
    /// The request depends on a PoX fork that this peer does not recognize as canonical
    pub const InvalidPoxFork: u32 = 4;
    /// The message received is not appropriate for the ongoing step in the protocol being executed
    pub const InvalidMessage: u32 = 5;
    /// The StackerDB requested is not known or configured on this node
    pub const NoSuchDB: u32 = 6;
    /// The StackerDB chunk request referred to an older copy of the chunk than this node has
    pub const StaleVersion: u32 = 7;
    /// The remote peer's view of the burnchain is too out-of-date for the protocol to continue
    pub const StaleView: u32 = 8;
    /// The StackerDB chunk request referred to a newer copy of the chunk that this node has
    pub const FutureVersion: u32 = 9;
    /// The referenced StackerDB state view is stale locally relative to the requested version
    pub const FutureView: u32 = 10;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayData {
    pub peer: NeighborAddress,
    pub seq: u32,
}

/// All P2P message types supported in the wrb client
#[derive(Debug, Clone, PartialEq)]
pub enum StacksMessageType {
    Handshake(HandshakeData),
    HandshakeAccept(HandshakeAcceptData),
    HandshakeReject,
    Nack(NackData),
    StackerDBHandshakeAccept(HandshakeAcceptData, StackerDBHandshakeData),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StacksMessageID {
    Handshake = 0,
    HandshakeAccept = 1,
    HandshakeReject = 2,
    Nack = 14,
    StackerDBHandshakeAccept = 19,
}

/// Message type for all P2P Stacks network messages
#[derive(Debug, Clone, PartialEq)]
pub struct StacksMessage {
    pub preamble: Preamble,
    pub relayers: Vec<RelayData>,
    pub payload: StacksMessageType,
}

