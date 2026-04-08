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

use clarity::vm::types::TupleData;
use clarity::vm::Value;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::types::PrivateKey;
use stacks_common::util::hash::Sha256Sum;
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};

use crate::devnet::pox::PoxAddress;

/// Message prefix for signed structured data. "SIP018" in ascii
pub const STRUCTURED_DATA_PREFIX: [u8; 6] = [0x53, 0x49, 0x50, 0x30, 0x31, 0x38];

pub fn structured_data_hash(value: Value) -> Sha256Sum {
    let mut bytes = vec![];
    value.serialize_write(&mut bytes).unwrap();
    Sha256Sum::from_data(bytes.as_slice())
}

/// Generate a message hash for signing structured Clarity data.
/// Reference [SIP018](https://github.com/stacksgov/sips/blob/main/sips/sip-018/sip-018-signed-structured-data.md) for more information.
pub fn structured_data_message_hash(structured_data: Value, domain: Value) -> Sha256Sum {
    let message = [
        STRUCTURED_DATA_PREFIX.as_ref(),
        structured_data_hash(domain).as_bytes(),
        structured_data_hash(structured_data).as_bytes(),
    ]
    .concat();

    Sha256Sum::from_data(&message)
}

/// Sign structured Clarity data with a given private key.
/// Reference [SIP018](https://github.com/stacksgov/sips/blob/main/sips/sip-018/sip-018-signed-structured-data.md) for more information.
pub fn sign_structured_data(
    structured_data: Value,
    domain: Value,
    private_key: &Secp256k1PrivateKey,
) -> Result<MessageSignature, &str> {
    let msg_hash = structured_data_message_hash(structured_data, domain);
    private_key.sign(msg_hash.as_bytes())
}

// Helper function to generate domain for structured data hash
pub fn make_structured_data_domain(name: &str, version: &str, chain_id: u32) -> Value {
    Value::Tuple(
        TupleData::from_data(vec![
            (
                "name".into(),
                Value::string_ascii_from_bytes(name.into()).unwrap(),
            ),
            (
                "version".into(),
                Value::string_ascii_from_bytes(version.into()).unwrap(),
            ),
            ("chain-id".into(), Value::UInt(chain_id.into())),
        ])
        .unwrap(),
    )
}

pub mod pox4 {
    use super::{
        make_structured_data_domain, structured_data_message_hash, MessageSignature, PoxAddress,
        PrivateKey, Sha256Sum, StacksPrivateKey, TupleData, Value,
    };
    define_named_enum!(Pox4SignatureTopic {
        StackStx("stack-stx"),
        AggregationCommit("agg-commit"),
        AggregationIncrease("agg-increase"),
        StackExtend("stack-extend"),
        StackIncrease("stack-increase"),
    });

    pub fn make_pox_4_signed_data_domain(chain_id: u32) -> Value {
        make_structured_data_domain("pox-4-signer", "1.0.0", chain_id)
    }

    pub fn make_pox_4_signer_key_message_hash(
        pox_addr: &PoxAddress,
        reward_cycle: u128,
        topic: &Pox4SignatureTopic,
        chain_id: u32,
        period: u128,
        max_amount: u128,
        auth_id: u128,
    ) -> Sha256Sum {
        let domain_tuple = make_pox_4_signed_data_domain(chain_id);
        let data_tuple = Value::Tuple(
            TupleData::from_data(vec![
                (
                    "pox-addr".into(),
                    pox_addr
                        .clone()
                        .as_clarity_tuple()
                        .expect("Error creating signature hash - invalid PoX Address")
                        .into(),
                ),
                ("reward-cycle".into(), Value::UInt(reward_cycle)),
                ("period".into(), Value::UInt(period)),
                (
                    "topic".into(),
                    Value::string_ascii_from_bytes(topic.get_name_str().into()).unwrap(),
                ),
                ("auth-id".into(), Value::UInt(auth_id)),
                ("max-amount".into(), Value::UInt(max_amount)),
            ])
            .expect("Error creating signature hash"),
        );
        structured_data_message_hash(data_tuple, domain_tuple)
    }

    impl Into<Pox4SignatureTopic> for &'static str {
        fn into(self) -> Pox4SignatureTopic {
            match self {
                "stack-stx" => Pox4SignatureTopic::StackStx,
                "agg-commit" => Pox4SignatureTopic::AggregationCommit,
                "stack-extend" => Pox4SignatureTopic::StackExtend,
                "stack-increase" => Pox4SignatureTopic::StackIncrease,
                _ => panic!("Invalid pox-4 signature topic"),
            }
        }
    }

    pub fn make_pox_4_signer_key_signature(
        pox_addr: &PoxAddress,
        signer_key: &StacksPrivateKey,
        reward_cycle: u128,
        topic: &Pox4SignatureTopic,
        chain_id: u32,
        period: u128,
        max_amount: u128,
        auth_id: u128,
    ) -> Result<MessageSignature, &'static str> {
        let msg_hash = make_pox_4_signer_key_message_hash(
            pox_addr,
            reward_cycle,
            topic,
            chain_id,
            period,
            max_amount,
            auth_id,
        );
        signer_key.sign(msg_hash.as_bytes())
    }
}

