// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! This is lifted verbatim from stacks-core 

use clarity::vm::types::{SequenceData, TupleData, Value};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use stacks_common::address::{b58, AddressHashMode};
use stacks_common::deps_common::bitcoin::blockdata::transaction::TxOut;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::{to_hex, Hash160};

use crate::bitcoin::address::{
    BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType,
    SegwitBitcoinAddress,
};
use crate::bitcoin::BitcoinNetworkType;

// PoX 20-byte address types that do not have a StacksAddress representation
define_u8_enum!(PoxAddressType20 {
    // ADDRESS_VERSION_P2WPKH in pox-2.clar
    P2WPKH = 0x04
});

// PoX 32-byte address types that do not have a StacksAddress representation
define_u8_enum!(PoxAddressType32 {
    // ADDRESS_VERSION_P2WSH in pox-2.clar
    P2WSH = 0x05,
    // ADDRESS_VERSION_P2TR in pox-2.clar
    P2TR = 0x06
});

/// A PoX address as seen by the .pox and .pox-2 contracts.
/// Used by the sortition DB and chains coordinator to extract addresses from the PoX contract to
/// build the reward set and to validate block-commits.
/// Note that this comprises a larger set of possible addresses than StacksAddress
#[derive(Debug, PartialEq, PartialOrd, Ord, Clone, Hash, Eq, Serialize, Deserialize)]
pub enum PoxAddress {
    /// Represents a { version: (buff 1), hashbytes: (buff 20) } tuple that has a Stacks
    /// representation.  Not all 20-byte hashbyte addresses do (such as Bitcoin p2wpkh)
    /// The address hash mode is optional because if we decode a legacy bitcoin address, we won't
    /// be able to determine the hash mode since we can't distinguish segwit-p2sh from p2sh
    Standard(StacksAddress, Option<AddressHashMode>),
    /// Represents { version: (buff 1), hashbytes: (buff 20) } that does not have a Stacks
    /// representation.  This includes Bitcoin p2wpkh.
    /// Fields are (mainnet, address type ID, bytes)
    Addr20(bool, PoxAddressType20, [u8; 20]),
    /// Represents { version: (buff 1), hashbytes: (buff 32) } that does not have a Stacks
    /// representation.  This includes Bitcoin p2wsh and p2tr.
    /// Fields are (mainnet, address type ID, bytes)
    Addr32(bool, PoxAddressType32, [u8; 32]),
}

impl PoxAddress {
    /// Obtain the address hash mode used for the PoX address, if applicable.  This identifies the
    /// address as p2pkh, p2sh, p2wpkh-p2sh, or p2wsh-p2sh
    #[cfg(test)]
    pub fn hashmode(&self) -> Option<AddressHashMode> {
        match *self {
            PoxAddress::Standard(_, hm) => hm,
            _ => None,
        }
    }

    /// Get the version byte representation of the hash mode.  Used only in testing, where the test
    /// knows that it will only use Bitcoin legacy addresses (i.e. so this method is infallable).
    #[cfg(test)]
    pub fn version(&self) -> u8 {
        self.hashmode()
            .expect("FATAL: tried to load the hashmode of a PoxAddress which has none known")
            as u8
    }

    /// Get the Hash160 portion of this address.  Only applies to legacy Bitcoin addresses.
    /// Used only in tests, and even then, only in ones that expect a legacy Bitcoin address.
    #[cfg(test)]
    pub fn hash160(&self) -> Hash160 {
        match self {
            PoxAddress::Standard(addr, _) => addr.bytes().clone(),
            _ => panic!("Called hash160 on a non-standard PoX address"),
        }
    }

    /// Get the data portion of this address.  This does not include the address or witness
    /// version.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            PoxAddress::Standard(addr, _) => addr.bytes().0.to_vec(),
            PoxAddress::Addr20(_, _, bytes) => bytes.to_vec(),
            PoxAddress::Addr32(_, _, bytes) => bytes.to_vec(),
        }
    }

    /// Try to convert a Clarity value representation of the PoX address into a
    /// PoxAddress::Standard.
    fn try_standard_from_pox_tuple(
        mainnet: bool,
        hashmode_u8: u8,
        hashbytes: &[u8],
    ) -> Option<PoxAddress> {
        let hashmode: AddressHashMode = hashmode_u8.try_into().ok()?;

        // this is a valid AddressHashMode, so there must be exactly 20 bytes
        if hashbytes.len() != 20 {
            return None;
        }

        let hashbytes_20: &[u8; 20] = hashbytes.try_into().ok()?;
        let bytes = Hash160(*hashbytes_20);

        let version = if mainnet {
            hashmode.to_version_mainnet()
        } else {
            hashmode.to_version_testnet()
        };

        Some(PoxAddress::Standard(
            StacksAddress::new(version, bytes).ok()?,
            Some(hashmode),
        ))
    }

    /// Try to convert a Clarity value representation of the PoX address into a
    /// PoxAddress::Addr20.
    fn try_addr20_from_pox_tuple(
        mainnet: bool,
        hashmode_u8: u8,
        hashbytes: &[u8],
    ) -> Option<PoxAddress> {
        let addrtype = PoxAddressType20::from_u8(hashmode_u8)?;

        // this is a valid PoxAddressType20, so there must be exactly 20 bytes
        if hashbytes.len() != 20 {
            return None;
        }

        let hashbytes_20: &[u8; 20] = hashbytes.try_into().ok()?;

        Some(PoxAddress::Addr20(mainnet, addrtype, *hashbytes_20))
    }

    /// Try to convert a Clarity value representation of the PoX address into a
    /// PoxAddress::Addr32.
    fn try_addr32_from_pox_tuple(
        mainnet: bool,
        hashmode_u8: u8,
        hashbytes: &[u8],
    ) -> Option<PoxAddress> {
        let addrtype = PoxAddressType32::from_u8(hashmode_u8)?;

        // this is a valid PoxAddressType32, so there must be exactly 32 bytes
        if hashbytes.len() != 32 {
            return None;
        }

        let hashbytes_32: &[u8; 32] = hashbytes.get(0..32)?.try_into().ok()?;

        Some(PoxAddress::Addr32(mainnet, addrtype, *hashbytes_32))
    }

    /// Try to convert a Clarity value representation of the PoX address into a PoxAddress.
    /// `value` must be `{ version: (buff 1), hashbytes: (buff 32) }`
    pub fn try_from_pox_tuple(mainnet: bool, value: &Value) -> Option<PoxAddress> {
        let tuple_data = match value {
            Value::Tuple(data) => data.clone(),
            _ => {
                return None;
            }
        };

        let hashmode_value = tuple_data.get("version").ok()?.to_owned();

        let hashmode_u8 = match hashmode_value {
            Value::Sequence(SequenceData::Buffer(data)) => {
                if data.data.len() == 1 {
                    *data.data.first()?
                } else {
                    return None;
                }
            }
            _ => {
                return None;
            }
        };

        let hashbytes_value = tuple_data.get("hashbytes").ok()?.to_owned();
        let hashbytes_vec = match hashbytes_value {
            Value::Sequence(SequenceData::Buffer(data)) => data.data,
            _ => {
                return None;
            }
        };

        // try to decode
        if let Some(addr) =
            PoxAddress::try_standard_from_pox_tuple(mainnet, hashmode_u8, &hashbytes_vec)
        {
            return Some(addr);
        }
        if let Some(addr) =
            PoxAddress::try_addr20_from_pox_tuple(mainnet, hashmode_u8, &hashbytes_vec)
        {
            return Some(addr);
        }
        if let Some(addr) =
            PoxAddress::try_addr32_from_pox_tuple(mainnet, hashmode_u8, &hashbytes_vec)
        {
            return Some(addr);
        }
        None
    }

    /// Serialize this structure to a string that we can store in the sortition DB
    pub fn to_db_string(&self) -> String {
        serde_json::to_string(self).expect("FATAL: failed to serialize JSON value")
    }

    /// Decode a db string back into a PoxAddress
    pub fn from_db_string(db_string: &str) -> Option<PoxAddress> {
        serde_json::from_str(db_string).ok()?
    }

    /// What is the burnchain representation of this address?
    /// Used for comparing addresses from block-commits, where certain information (e.g. the hash
    /// mode) can't be used since it's not stored there.  The resulting string encodes all of the
    /// information that is present on the burnchain, and it does so in a _stable_ way.
    pub fn to_burnchain_repr(&self) -> String {
        match *self {
            PoxAddress::Standard(ref addr, _) => {
                format!("{:02x}-{}", &addr.version(), &addr.bytes())
            }
            PoxAddress::Addr20(_, ref addrtype, ref addrbytes) => {
                format!("{:02x}-{}", addrtype.to_u8(), to_hex(addrbytes))
            }
            PoxAddress::Addr32(_, ref addrtype, ref addrbytes) => {
                format!("{:02x}-{}", addrtype.to_u8(), to_hex(addrbytes))
            }
        }
    }

    /// Make a standard burn address, i.e. as a legacy p2pkh address comprised of all 0's.
    /// NOTE: this is used to represent both PoB outputs, as well as to back-fill reward set data
    /// when storing a reward cycle's sortition for which there are no output slots.  This means
    /// that the behavior of this method is *consensus critical*
    pub fn standard_burn_address(mainnet: bool) -> PoxAddress {
        PoxAddress::Standard(
            StacksAddress::burn_address(mainnet),
            Some(AddressHashMode::SerializeP2PKH),
        )
    }

    /// Convert this PoxAddress into a Clarity value.
    /// Returns None if the address hash mode is not known (i.e. this only works for PoxAddresses
    /// constructed from a PoX tuple in the PoX contract).
    pub fn as_clarity_tuple(&self) -> Option<TupleData> {
        match *self {
            PoxAddress::Standard(ref addr, ref hm) => {
                let hm = match hm {
                    Some(hm) => hm,
                    None => {
                        return None;
                    }
                };
                let version = Value::buff_from_byte(*hm as u8);
                let hashbytes = Value::buff_from(Vec::from(addr.bytes().0))
                    .expect("FATAL: hash160 does not fit into a Clarity value");

                let tuple_data = TupleData::from_data(vec![
                    ("version".into(), version),
                    ("hashbytes".into(), hashbytes),
                ])
                .expect("FATAL: cannot encode PoxAddress::Standard as a Clarity tuple");

                Some(tuple_data)
            }
            PoxAddress::Addr20(ref _mainnet, ref addrtype, ref addrbytes) => {
                let version = Value::buff_from_byte(*addrtype as u8);
                let hashbytes = Value::buff_from(Vec::from(*addrbytes))
                    .expect("FATAL: could not create a 20-byte buffer");

                let tuple_data = TupleData::from_data(vec![
                    ("version".into(), version),
                    ("hashbytes".into(), hashbytes),
                ])
                .expect("FATAL: Cannot fit PoxAddress::Addr20 as a Clarity tuple");

                Some(tuple_data)
            }
            PoxAddress::Addr32(ref _mainnet, ref addrtype, ref addrbytes) => {
                let version = Value::buff_from_byte(*addrtype as u8);
                let hashbytes = Value::buff_from(Vec::from(*addrbytes))
                    .expect("FATAL: could not create a 32-byte buffer");

                let tuple_data = TupleData::from_data(vec![
                    ("version".into(), version),
                    ("hashbytes".into(), hashbytes),
                ])
                .expect("FATAL: Cannot fit PoxAddress::Addr32 as a Clarity tuple");

                Some(tuple_data)
            }
        }
    }

    /// Coerce a hash mode for this address if it is standard.
    ///
    /// WARNING
    /// The hash mode may not reflect the true nature of the address, since segwit-p2sh and p2sh
    /// are indistinguishable.  Use with caution.
    pub fn coerce_hash_mode(self) -> PoxAddress {
        match self {
            PoxAddress::Standard(addr, _) => {
                let hm = AddressHashMode::from_version(addr.version());
                PoxAddress::Standard(addr, Some(hm))
            }
            _ => self,
        }
    }

    /// Try to convert this into a standard StacksAddress.
    /// With Bitcoin, this means a legacy address
    pub fn try_into_stacks_address(self) -> Option<StacksAddress> {
        match self {
            PoxAddress::Standard(addr, _) => Some(addr),
            _ => None,
        }
    }

    /// Fallback to convert `mainnet` bool to a BitcoinNetworkType
    /// preserving previous behaviour where a method was expecting the
    /// `mainnet' flag
    fn network_type_from_mainnet_fallback(mainnet: bool) -> BitcoinNetworkType {
        if mainnet {
            BitcoinNetworkType::Mainnet
        } else {
            BitcoinNetworkType::Testnet
        }
    }

    /// Construct from hash mode and hash160
    #[cfg(test)]
    pub fn from_legacy(hash_mode: AddressHashMode, hash_bytes: Hash160) -> PoxAddress {
        PoxAddress::Standard(
            StacksAddress::new(hash_mode.to_version_testnet(), hash_bytes).unwrap(),
            Some(hash_mode),
        )
    }
}

