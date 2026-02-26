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

use stacks_common::deps_common::bitcoin::network::serialize::Error as BtcSerializeError;
use stacks_common::util::secp256k1;
use stacks_common::util::HexError as btc_hex_error;
use stacks_common::util::hash::DoubleSha256;

use serde::{Serialize, Deserialize};

use crate::bitcoin::address::BitcoinAddress;
use crate::util::sqlite::Error as DBError;

pub mod address;
pub mod blocks;
pub mod ops;
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
impl_byte_array_from_column!(Txid);
pub const TXID_ENCODED_SIZE: u32 = 32;

impl Txid {
    /// Create a [`Txid`] from the tx hash bytes used in bitcoin.
    /// This just reverses the inner bytes of the input.
    pub fn from_bitcoin_tx_hash(tx_hash: &DoubleSha256) -> Self {
        let mut txid_bytes = tx_hash.0;
        txid_bytes.reverse();
        Self(txid_bytes)
    }

    /// Create a [`DoubleSha256`] from a [`Txid`]
    /// This assumes the inner bytes are stored in "big-endian" (following the hex bitcoin string),
    /// so just reverse them to properly create a tx hash.
    pub fn to_bitcoin_tx_hash(txid: &Self) -> DoubleSha256 {
        let mut txid_bytes = txid.0;
        txid_bytes.reverse();
        DoubleSha256(txid_bytes)
    }
}

pub struct Wtxid(pub [u8; 32]);
impl_array_newtype!(Wtxid, u8, 32);
impl_array_hexstring_fmt!(Wtxid);
impl_byte_array_newtype!(Wtxid, u8, 32);
impl_byte_array_message_codec!(Wtxid, 32);
impl_byte_array_serde!(Wtxid);
impl_byte_array_from_column!(Wtxid);
pub const WTXID_ENCODED_SIZE: u32 = 32;

impl Wtxid {
    /// Create a [`Wtxid`] from the tx hash bytes used in bitcoin.
    /// This just reverses the inner bytes of the input.
    pub fn from_bitcoin_tx_hash(tx_hash: &DoubleSha256) -> Self {
        let mut txid_bytes = tx_hash.0;
        txid_bytes.reverse();
        Self(txid_bytes)
    }
    
    /// Create a [`DoubleSha256`] from a [`Wtxid`]
    /// This assumes the inner bytes are stored in "big-endian" (following the hex bitcoin string),
    /// so just reverse them to properly create a tx hash.
    pub fn to_bitcoin_tx_hash(wtxid: &Self) -> DoubleSha256 {
        let mut wtxid_bytes = wtxid.0;
        wtxid_bytes.reverse();
        DoubleSha256(wtxid_bytes)
    }
}

#[derive(Debug)]
pub enum Error {
    /// Serialization error
    BtcSerializationError(BtcSerializeError),
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

