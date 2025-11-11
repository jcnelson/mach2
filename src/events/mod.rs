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

use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::StacksAddress;

use crate::bitcoin::Txid;

/// Event details for a pegin
#[derive(Clone, PartialEq, Debug)]
pub struct BitcoinPegIn {
    pub block_hash: BurnchainHeaderHash,
    pub txid: Txid,
    pub block_height: u32,
    pub txindex: u32,
    pub recipient: StacksAddress,
    pub amount: u64
}

