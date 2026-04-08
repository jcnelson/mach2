// Copyright (C) 2026 Trust Machines
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

use rusqlite;

use crate::util::sqlite::{Error as DBError, sqlite_open, query_count};
use crate::devnet::{NakamotoNodeError, NakamotoResult};

/// Compute the sortition DB path from the data dir
fn sortdb_path(data_dir: &str) -> String {
    format!("{data_dir}/stacks/nakamoto-neon/burnchain/sortition/marf.sqlite")
}

/// Determine how many leader keys have been registered in the devnet
pub fn get_num_leader_keys(data_dir: &str) -> NakamotoResult<u64> {
    let path = sortdb_path(data_dir);
    let conn = sqlite_open(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY, true)
        .map_err(|e| NakamotoNodeError::DBError(e.into()))?;

    let count_i64 = query_count(&conn, "SELECT COUNT(sortition_id) FROM leader_keys", rusqlite::params![])?;
    Ok(u64::try_from(count_i64).map_err(|_| NakamotoNodeError::DBError(DBError::Other(format!("Cannot convert to u64: {count_i64}"))))?)
}

