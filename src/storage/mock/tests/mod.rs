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

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;

use crate::storage::StackerDBClient;

use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::util::hash::Sha512Trunc256Sum;

use libstackerdb::{SlotMetadata, StackerDBChunkAckData, StackerDBChunkData};

use crate::core::config::Config;

use crate::storage::mock::LocalStackerDBClient;
use crate::storage::mock::LocalStackerDBConfig;
use crate::storage::mock::Signer;
use crate::storage::mock::MockStackerDBClient;

#[test]
fn test_local_stackerdb() {
    let pk = StacksPrivateKey::random();
    let pubk = StacksPublicKey::from_private(&pk);
    let addr = StacksAddress::p2pkh(true, &pubk);

    let config = LocalStackerDBConfig {
        mainnet: true,
        rpc_latency: 100,
        max_slots: 3,
        signers: vec![Signer {
            address: addr,
            num_slots: 3,
        }],
    };

    let mut mock_stackerdb = LocalStackerDBClient::open_or_create(":memory:", config).unwrap();

    assert_eq!(
        mock_stackerdb.list_chunks().unwrap(),
        vec![
            SlotMetadata::new_unsigned(0, 0, Sha512Trunc256Sum([0x00; 32])),
            SlotMetadata::new_unsigned(1, 0, Sha512Trunc256Sum([0x00; 32])),
            SlotMetadata::new_unsigned(2, 0, Sha512Trunc256Sum([0x00; 32])),
        ]
    );
    assert_eq!(
        mock_stackerdb
            .get_chunks(&[(0, 0), (1, 0), (2, 0)])
            .unwrap(),
        vec![None, None, None]
    );
    assert_eq!(
        mock_stackerdb.get_latest_chunks(&[0, 1, 2]).unwrap(),
        vec![None, None, None]
    );

    let mut chunk = StackerDBChunkData::new(0, 0, vec![1, 2, 3, 4, 5]);
    chunk.sign(&pk).unwrap();

    assert_eq!(
        mock_stackerdb.put_chunk(chunk.clone()).unwrap(),
        StackerDBChunkAckData {
            accepted: true,
            reason: None,
            metadata: None,
            code: None
        }
    );

    assert_eq!(
        mock_stackerdb.list_chunks().unwrap(),
        vec![
            chunk.get_slot_metadata(),
            SlotMetadata::new_unsigned(1, 0, Sha512Trunc256Sum([0x00; 32])),
            SlotMetadata::new_unsigned(2, 0, Sha512Trunc256Sum([0x00; 32])),
        ]
    );
    assert_eq!(
        mock_stackerdb
            .get_chunks(&[(0, 0), (1, 0), (2, 0)])
            .unwrap(),
        vec![Some(chunk.data.clone()), None, None]
    );
    assert_eq!(
        mock_stackerdb
            .get_chunks(&[(0, 1), (1, 0), (2, 0)])
            .unwrap(),
        vec![None, None, None]
    );
    assert_eq!(
        mock_stackerdb.get_latest_chunks(&[0, 1, 2]).unwrap(),
        vec![Some(chunk.data.clone()), None, None]
    );
}

#[test]
fn test_mock_stackerdb() {
    let mut mock_stackerdb = MockStackerDBClient::new(StacksPrivateKey::random(), 3);
    assert_eq!(
        mock_stackerdb.list_chunks().unwrap(),
        vec![
            SlotMetadata::new_unsigned(0, 0, Sha512Trunc256Sum([0x00; 32])),
            SlotMetadata::new_unsigned(1, 0, Sha512Trunc256Sum([0x00; 32])),
            SlotMetadata::new_unsigned(2, 0, Sha512Trunc256Sum([0x00; 32])),
        ]
    );
    assert_eq!(
        mock_stackerdb
            .get_chunks(&[(0, 0), (1, 0), (2, 0)])
            .unwrap(),
        vec![None, None, None]
    );
    assert_eq!(
        mock_stackerdb.get_latest_chunks(&[0, 1, 2]).unwrap(),
        vec![None, None, None]
    );

    let privk = StacksPrivateKey::random();
    let mut chunk = StackerDBChunkData::new(0, 0, vec![1, 2, 3, 4, 5]);
    chunk.sign(&privk).unwrap();

    assert_eq!(
        mock_stackerdb.put_chunk(chunk.clone()).unwrap(),
        StackerDBChunkAckData {
            accepted: true,
            reason: None,
            metadata: None,
            code: None
        }
    );

    assert_eq!(
        mock_stackerdb.list_chunks().unwrap(),
        vec![
            chunk.get_slot_metadata(),
            SlotMetadata::new_unsigned(1, 0, Sha512Trunc256Sum([0x00; 32])),
            SlotMetadata::new_unsigned(2, 0, Sha512Trunc256Sum([0x00; 32])),
        ]
    );
    assert_eq!(
        mock_stackerdb
            .get_chunks(&[(0, 0), (1, 0), (2, 0)])
            .unwrap(),
        vec![Some(chunk.data.clone()), None, None]
    );
    assert_eq!(
        mock_stackerdb
            .get_chunks(&[(0, 1), (1, 0), (2, 0)])
            .unwrap(),
        vec![None, None, None]
    );
    assert_eq!(
        mock_stackerdb.get_latest_chunks(&[0, 1, 2]).unwrap(),
        vec![Some(chunk.data.clone()), None, None]
    );
}

