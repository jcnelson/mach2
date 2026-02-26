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

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::net::stackerdb::StackerDBClient;

use clarity_types::types::QualifiedContractIdentifier;

use stacks_common::codec::Error as CodecError;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;

use libstackerdb::SlotMetadata;
use libstackerdb::StackerDBChunkData;

use crate::storage::Storage;

use crate::net::Error;

impl Storage {
    /// given a list of signers and a private key, find the slot IDs this private key can access.
    fn find_available_slots(signers: &[StacksAddress], privkey: &Secp256k1PrivateKey) -> Vec<u32> {
        let mut available = vec![];
        let addr = StacksAddress::p2pkh(true, &StacksPublicKey::from_private(privkey));
        for (i, signer) in signers.iter().enumerate() {
            let Ok(slot_id) = u32::try_from(i) else {
                break;
            };

            if signer.bytes() == addr.bytes() {
                available.push(slot_id);
            }
        }
        available
    }

    /// open an existing cosigner storage
    /// `privkey` is the key that can sign and upload slots
    pub fn open(
        home_client: Box<dyn StackerDBClient>,
        replica_client: Box<dyn StackerDBClient>,
        privkey: Secp256k1PrivateKey,
    ) -> Result<Self, Error> {
        let mut cosigner_storage = Storage {
            privkey: privkey.clone(),
            home_client,
            replica_client,
            chunks: HashMap::new(),
            signers: None,
            node: None,
        };
        cosigner_storage.refresh_signers()?;
        m2_test_debug!(
            "Opened cosigner storage for signer {}",
            &StacksAddress::p2pkh(true, &StacksPublicKey::from_private(&privkey)),
        );
        Ok(cosigner_storage)
    }

    /// Update the list of signers.
    /// We ask the *home client* for this, since it's trusted.
    fn refresh_signers(&mut self) -> Result<(), Error> {
        let signers = self.home_client.get_signers()?;
        self.signers = Some(signers);
        Ok(())
    }

    /// Save a chunk directly.  Used for low-level things.
    pub(crate) fn put_chunk(&mut self, mut chunk: StackerDBChunkData) -> Result<(), Error> {
        loop {
            chunk
                .sign(&self.privkey)
                .map_err(|_| CodecError::SerializeError("Failed to sign".into()))?;

            m2_test_debug!(
                "Signed with {} ({}): {:?}",
                &self.privkey.to_hex(),
                StacksAddress::p2pkh(true, &StacksPublicKey::from_private(&self.privkey)),
                &chunk
            );

            let result = self.replica_client.put_chunk(chunk.clone())?;
            if result.accepted {
                break;
            }

            let reason = result.reason.unwrap_or("(reason not given)".to_string());
            m2_warn!(
                "Failed to save chunk ({},{}): reason was '{}'",
                chunk.slot_id,
                chunk.slot_version,
                &reason
            );

            if let Some(metadata) = result.metadata {
                // newer version
                chunk.slot_version = metadata.slot_version + 1;
                continue;
            }

            return Err(Error::PutChunk(reason));
        }
        Ok(())
    }

    /// List all chunks in the StackerDB.  Used for low-level things.
    pub(crate) fn list_chunks(&mut self) -> Result<Vec<SlotMetadata>, Error> {
        Ok(self.replica_client.list_chunks()?)
    }

    /// Get a raw chunk.
    /// `slot_id` is a StackerDB chunk ID.
    /// The signature of the chunk will *not* be checked; use `fetch_chunk` for that.
    /// Returns true if we got chunk data
    /// Returns false if there is no chunk data
    /// Returns an error on network errors or codec errors.
    /// In particular, NoSuchChunk means that the node reported that this chunk doesn't exist yet.
    pub fn get_raw_chunk(
        &mut self,
        slot_id: u32,
        data_hash: &Sha512Trunc256Sum,
    ) -> Result<Vec<u8>, Error> {
        let chunks = self.replica_client.get_latest_chunks(&[slot_id])?;
        let Some(chunk_opt) = chunks.get(0) else {
            m2_debug!("No such StackerDB chunk {}", slot_id);
            return Err(Error::NoSuchChunk);
        };
        let Some(chunk) = chunk_opt else {
            m2_debug!("No data for StackerDB chunk {}", slot_id);
            return Err(Error::NoSuchChunk);
        };
        if data_hash != &Sha512Trunc256Sum::from_data(&chunk) {
            return Err(Error::GetChunk("chunk hash mismatch".into()));
        }
        Ok(chunk.clone())
    }

    /// Get and authenticate raw chunk.
    /// `slot_id` is a StackerDB chunk ID.
    /// Returns true if we got chunk data
    /// Returns false if there is no chunk data
    /// Returns an error on network errors or codec errors.
    /// In particular, NoSuchChunk means that the node reported that this chunk doesn't exist yet.
    pub fn get_and_verify_raw_chunk(&mut self, slot_id: u32) -> Result<Option<Vec<u8>>, Error> {
        if self.signers.is_none() {
            self.refresh_signers()?;
        }
        let Some(signers) = self.signers.as_ref() else {
            return Err(Error::GetChunk("Unable to load signer list".into()));
        };
        let Some(signer_addr) = signers.get(slot_id as usize).cloned() else {
            return Err(Error::GetChunk(format!(
                "No such signer for chunk ID {}",
                slot_id
            )));
        };

        let all_slot_metadata = self.replica_client.list_chunks()?;
        let slot_md = all_slot_metadata
            .get(slot_id as usize)
            .ok_or(Error::GetChunk(
                "no app chunk defined in slot metadata".into(),
            ))?;

        if slot_md.slot_version == 0 && slot_md.data_hash == Sha512Trunc256Sum([0x00; 32]) {
            // no chunk at all
            return Ok(None);
        }
        if !slot_md.verify(&signer_addr).map_err(|e| {
            Error::GetChunk(format!(
                "Failed to verify signature on {:?}: {:?}",
                &slot_md, &e
            ))
        })? {
            m2_warn!(
                "Slot not signed by signer; signer_addr = {}, metadata = {:?}",
                &signer_addr,
                &slot_md
            );
            return Err(Error::GetChunk("Invalid chunk signature".into()));
        }

        // hash is authentic
        let chunk = self.get_raw_chunk(slot_id, &slot_md.data_hash)?;
        Ok(Some(chunk))
    }

    /// Get a chunk (a bundle of slices) and cache it locally.
    /// `slot_id` is a StackerDB chunk ID.
    /// The signature of the chunk will *not* be checked; use `fetch_chunk` for that.
    /// Returns true if we got chunk data
    /// Returns false if there is no chunk data
    /// Returns an error on network errors or codec errors.
    /// In particular, NoSuchChunk means that the node reported that this chunk doesn't exist yet.
    pub fn get_chunk(&mut self, slot_id: u32, data_hash: &Sha512Trunc256Sum) -> Result<(), Error> {
        let chunk = self.get_raw_chunk(slot_id, data_hash)?;
        self.chunks.insert(slot_id, chunk);
        Ok(())
    }

    /// Get the digest to sign that authenticates this chunk data and metadata
    fn chunk_auth_digest(
        slot_id: u32,
        slot_version: u32,
        data_hash: &Sha512Trunc256Sum,
    ) -> Sha512Trunc256Sum {
        let mut data = vec![];
        data.extend_from_slice(&slot_id.to_be_bytes());
        data.extend_from_slice(&slot_version.to_be_bytes());
        data.extend_from_slice(&data_hash.0);
        Sha512Trunc256Sum::from_data(&data)
    }

    /// Fetch a chunk and cache it locally.
    /// Returns the chunk version and signer public key.
    pub fn fetch_chunk(
        &mut self,
        chunk_id: u32,
    ) -> Result<(u32, Option<StacksPublicKey>), Error> {
        let mut refreshed_signers = false;
        loop {
            let all_slot_metadata = self.replica_client.list_chunks()?;
            let slot_md = all_slot_metadata
                .get(chunk_id as usize)
                .ok_or(Error::GetChunk(
                    "no app chunk defined in slot metadata".into(),
                ))?;

            if self.signers.is_none() {
                self.refresh_signers()?;
                refreshed_signers = true;
            }
            let Some(signers) = self.signers.as_ref() else {
                return Err(Error::GetChunk("Unable to load signer list".into()));
            };
            let Some(signer_addr) = signers.get(chunk_id as usize).cloned() else {
                return Err(Error::GetChunk(format!(
                    "No such signer for chunk ID {}",
                    chunk_id
                )));
            };

            if slot_md.slot_version == 0 && slot_md.data_hash == Sha512Trunc256Sum([0x00; 32]) {
                // this slot is empty, so pass a null signer
                return Ok((0, None));
            }

            if !slot_md.verify(&signer_addr).map_err(|e| {
                Error::GetChunk(format!(
                    "Failed to verify signature on {:?}: {:?}",
                    &slot_md, &e
                ))
            })? {
                if !refreshed_signers {
                    // try again after refreshing the signers
                    self.refresh_signers()?;
                    refreshed_signers = true;
                    continue;
                }

                // already refreshed signers
                m2_warn!(
                    "Slot not signed by signer; signer_addr = {}, metadata = {:?}",
                    &signer_addr,
                    &slot_md
                );
                return Err(Error::GetChunk("Invalid chunk signature".into()));
            }

            self.get_chunk(chunk_id, &slot_md.data_hash)?;

            let sigh = Self::chunk_auth_digest(chunk_id, slot_md.slot_version, &slot_md.data_hash);
            let pubk = StacksPublicKey::recover_to_pubkey(sigh.as_bytes(), &slot_md.signature)
                .map_err(|_| Error::GetChunk("failed to recover public key".into()))?;

            return Ok((slot_md.slot_version, Some(pubk)));
        }
    }
}

