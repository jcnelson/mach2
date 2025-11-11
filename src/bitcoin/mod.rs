// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

// This module is concerned with the implementation of the BitcoinIndexer
// structure and its methods and traits.

use std::{error, fmt, io};

use stacks_common::util::secp256k1;
use stacks_common::deps_common::bitcoin::network::serialize::Error as BtcSerializeError;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::HexError as btc_hex_error;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;

use serde::{Serialize, Deserialize};

use crate::bitcoin::address::BitcoinAddress;
use crate::util::sqlite::Error as DBError;

pub mod address;
pub mod bits;
pub mod blocks;
pub mod rpc;
pub mod signer;
pub mod wallet;

pub type BitcoinPublicKey = secp256k1::Secp256k1PublicKey;

pub struct Txid(pub [u8; 32]);
impl_array_newtype!(Txid, u8, 32);
impl_array_hexstring_fmt!(Txid);
impl_byte_array_newtype!(Txid, u8, 32);
impl_byte_array_message_codec!(Txid, 32);
impl_byte_array_serde!(Txid);
pub const TXID_ENCODED_SIZE: u32 = 32;

impl Txid {
    /// Create a [`Txid`] from the tx hash bytes used in bitcoin.
    /// This just reverses the inner bytes of the input.
    pub fn from_bitcoin_tx_hash(tx_hash: &Sha256dHash) -> Txid {
        let mut txid_bytes = tx_hash.0;
        txid_bytes.reverse();
        Self(txid_bytes)
    }

    /// Create a [`Sha256dHash`] from a [`Txid`]
    /// This assumes the inner bytes are stored in "big-endian" (following the hex bitcoin string),
    /// so just reverse them to properly create a tx hash.
    pub fn to_bitcoin_tx_hash(txid: &Txid) -> Sha256dHash {
        let mut txid_bytes = txid.0;
        txid_bytes.reverse();
        Sha256dHash(txid_bytes)
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Copy)]
pub struct MagicBytes([u8; 2]);
impl_array_newtype!(MagicBytes, u8, 2);
impl MagicBytes {
    pub fn default() -> MagicBytes {
        MACH2_MAGIC_MAINNET
    }
}

impl TryFrom<&str> for MagicBytes {
    type Error = String;
    fn try_from(bytes: &str) -> Result<Self, Self::Error> {
        if bytes.len() != 2 {
            return Err(format!("Magic bytes '{bytes}' must be two characters long"));
        }
        if !bytes.is_ascii() {
            return Err(format!("Magic bytes '{bytes}' must be ASCII"));
        }
        let mut buff = [0u8; 2];
        let mut next = 0;
        for chr in bytes.chars() {
            if next >= 2 {
                break;
            }
            buff[next] = chr as u8;
            next += 1;
        }
        Ok(MagicBytes(buff))
    }
}

impl fmt::Display for MagicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", str::from_utf8(&self.0).unwrap_or("<invalid UTF-8>"))
    }
}

pub const MACH2_MAGIC_MAINNET: MagicBytes = MagicBytes([77, 50]); // 'M2'
pub const MAGIC_BYTES_LENGTH: usize = 2;

/// Network error
#[derive(Debug)]
pub enum Error {
    /// Serialization error
    BtcSerializationError(BtcSerializeError),
    /// Invalid magic
    InvalidMagic,
    /// general filesystem error
    FilesystemError(io::Error),
    /// Database error
    DBError(DBError),
    /// Hashing error
    HashError(btc_hex_error),
    /// Wrong number of bytes for constructing an address
    InvalidByteSequence,
    /// Configuration error
    ConfigError(String),
    /// maximum fee exceeded
    MaxFeeRateExceeded,
    /// identical operation, won't resubmit
    IdenticalOperation,
    /// no UTXOs available
    NoUTXOs,
    /// transaction submission failed (contains bitcoind error message)
    TransactionSubmissionFailed(String),
    /// network I/O error
    NetworkError(io::Error),
    /// network resolution failure
    ResolutionFailed,
    /// Parsing error
    ParseError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BtcSerializationError(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidMagic => write!(f, "invalid network magic"),
            Error::FilesystemError(ref e) => fmt::Display::fmt(e, f),
            Error::DBError(ref e) => fmt::Display::fmt(e, f),
            Error::HashError(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidByteSequence => write!(f, "Invalid sequence of bytes"),
            Error::ConfigError(ref e_str) => fmt::Display::fmt(e_str, f),
            Error::MaxFeeRateExceeded => write!(f, "Maximum fee rate exceeded"),
            Error::IdenticalOperation => write!(f, "Identical operation"),
            Error::NoUTXOs => write!(f, "No UTXOs available"),
            Error::TransactionSubmissionFailed(ref msg) => write!(f, "Transaction submission failed: {msg}"),
            Error::NetworkError(ref e) => write!(f, "Network failure: {e:?}"),
            Error::ResolutionFailed => write!(f, "Network resolution failed"),
            Error::ParseError(ref s) => write!(f, "Parse error: {s}"),
        }
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Self::DBError(e)
    }
}

impl From<BtcSerializeError> for Error {
    fn from(e: BtcSerializeError) -> Self {
        Self::BtcSerializationError(e)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitcoinNetworkType {
    Mainnet,
    Testnet,
    Regtest,
}

impl BitcoinNetworkType {
    /// Returns `true` if this network type is [`BitcoinNetworkType::Mainnet`].
    pub fn is_mainnet(&self) -> bool {
        match *self {
            BitcoinNetworkType::Mainnet => true,
            _ => false,
        }
    }
}

impl TryFrom<&str> for BitcoinNetworkType {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(format!("Unrecognized network id '{s}'"))
        }
    }
}

impl fmt::Display for BitcoinNetworkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Regtest => write!(f, "regtest")
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct BitcoinTxOutput {
    pub address: BitcoinAddress,
    pub units: u64,
}

/// Legacy Bitcoin address input type, based on scriptSig.
#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub enum BitcoinInputType {
    Standard,
    SegwitP2SH,
}

/// Bitcoin input state
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTxInput {
    pub scriptSig: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
    pub tx_ref: (Txid, u32),
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub txid: Txid,
    pub vtxindex: u32,
    pub opcode: u8,
    pub data: Vec<u8>,
    /// how much BTC was sent to the data output
    pub data_amt: u64,
    pub inputs: Vec<BitcoinTxInput>,
    pub outputs: Vec<BitcoinTxOutput>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BitcoinBlock {
    pub block_height: u64,
    pub block_hash: BurnchainHeaderHash,
    pub parent_block_hash: BurnchainHeaderHash,
    pub txs: Vec<BitcoinTransaction>,
    pub timestamp: u64,
}

impl BitcoinBlock {
    pub fn new(
        height: u64,
        hash: &BurnchainHeaderHash,
        parent: &BurnchainHeaderHash,
        txs: Vec<BitcoinTransaction>,
        timestamp: u64,
    ) -> BitcoinBlock {
        BitcoinBlock {
            block_height: height,
            block_hash: hash.clone(),
            parent_block_hash: parent.clone(),
            txs,
            timestamp,
        }
    }
}
