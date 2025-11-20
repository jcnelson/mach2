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

use std::fs;
use std::io;
use std::ops::Deref;
use std::io::{Read, Write};
use std::io::ErrorKind;
use std::collections::HashSet;
use std::collections::HashMap;

use stacks_common::deps_common::bitcoin::network::serialize::Error as BtcSerializeError;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize as btc_deserialize;
use stacks_common::deps_common::bitcoin::network::serialize::serialize as btc_serialize;
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
use stacks_common::deps_common::bitcoin::blockdata::script::{Instruction, Script, Builder};
use stacks_common::deps_common::bitcoin::blockdata::transaction::{TxIn, TxOut, OutPoint, Transaction as BtcTransaction};
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::codec::{StacksMessageCodec, read_next, write_next, Error as CodecError};

use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::Error as SqliteError;
use rusqlite::OpenFlags;
use rusqlite::OptionalExtension;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::params;

use crate::bitcoin::ops::M2PegIn;
use crate::bitcoin::blocks::TransactionExtensions;
use crate::bitcoin::ops::witness;
use crate::util::sqlite::Error as DBError;
use crate::util::sqlite::{
    query_row, query_rows, query_expect_row, query_row_panic, query_row_columns, query_int, tx_begin_immediate, sqlite_open, FromRow, table_exists
};

pub const SCHEMA_VERSION: u32 = 1;

const DAG_DB_SCHEMA_1 : &'static [&'static str] = &[
    r#"
    CREATE TABLE btc_outputs(
        -- recipient address
        script_pubkey TEXT NOT NULL,
        -- amount in satoshis
        amount INTEGER NOT NULL,
        -- transaction ID that created this
        txid TEXT NOT NULL,
        -- identifier in this transaction
        vout INTEGER NOT NULL,
        -- Bitcoin block at which this BTC output can be spent on-chain (and thus would not count towards anyone's balance)
        expiry INTEGER NOT NULL,
        -- Hash of the Mach2 code which encumbers this output
        code_hash TEXT NOT NULL,
        
        PRIMARY KEY(txid,vout),
       
        -- links to btc_transactions
        FOREIGN KEY (txid) REFERENCES btc_transactions (txid) ON DELETE CASCADE ON UPDATE CASCADE
    );
    CREATE INDEX btc_outputs_by_txid ON btc_outputs(txid);
    CREATE INDEX btc_outputs_by_expiry ON btc_outputs(expiry);
    CREATE INDEX btc_outputs_by_code_hash ON btc_outputs(code_hash);
    "#,
    r#"
    CREATE TABLE btc_inputs(
        -- script sig body (raw bytes)
        script_sig BLOB,
        -- witness body (SIP-003 encoded Vec<Vec<u8>>)
        witness BLOB,
        -- transaction ID that created this
        txid TEXT NOT NULL,
        -- transaction ID of the transaction whose output was consumed
        prev_txid TEXT NOT NULL,
        -- which UTXO was consumed
        vout INTEGER NOT NULL,
        -- identifier in this transaction
        vin INTEGER NOT NULL,
        -- sequence
        sequence INTEGER NOT NULL,

        PRIMARY KEY(txid,vin),

        -- links to btc_transactions
        FOREIGN KEY(txid) REFERENCES btc_transactions (txid) ON DELETE CASCADE ON UPDATE CASCADE,
        -- links to btc_outputs
        FOREIGN KEY(txid,vout) REFERENCES btc_outputs (txid,vout) ON DELETE CASCADE ON UPDATE CASCADE
    );
    CREATE INDEX btc_inputs_by_txid ON btc_inputs(txid);
    "#,
    r#"
    -- peg-in and off-chain transactions
    CREATE TABLE btc_transactions(
        -- transaction ID 
        txid TEXT PRIMARY KEY NOT NULL,
        -- witness transaction ID
        wtxid TEXT NOT NULL, 
        -- 2PC round that produced this transaction
        round_id INTEGER NOT NULL,
        -- transaction body
        body BLOB NOT NULL
    );
    CREATE INDEX btc_transactions_by_wtxid ON btc_transactions(wtxid);
    CREATE INDEX btc_transactions_by_round_id ON btc_transactions(round_id);
    "#,
    r#"
    CREATE TABLE db_config(
        schema_version INTEGER NOT NULL
    );
    "#,
    r#"
    INSERT INTO db_config (schema_version) VALUES (1);
    "#,
];

#[derive(Debug)]
pub enum Error {
    DBError(DBError),
    SqliteError(SqliteError),
    IOError(io::Error),
    NotInstantiated,
    ReadOnly,
    BtcCodec(BtcSerializeError),
    Overflow,
    MissingUTXO,
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Self {
        Self::DBError(e)
    }
}

impl From<SqliteError> for Error {
    fn from(e: SqliteError) -> Self {
        Self::SqliteError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IOError(e)
    }
}

impl From<BtcSerializeError> for Error {
    fn from(e: BtcSerializeError) -> Self {
        Self::BtcCodec(e)
    }
}

pub struct DagDB {
    conn: Connection,
    pub path: String,
}

pub struct DagConn<'a> {
    conn: &'a Connection
}

impl<'a> Deref for DagConn<'a> {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        self.conn
    }
}

pub struct DagTx<'a> {
    tx: Transaction<'a>
}

impl FromRow<TxIn> for TxIn {
    fn from_row(row: &Row) -> Result<Self, DBError> {
        let witness_sip003: Vec<u8> = row.get("witness")?;
        let witness : Vec<Vec<u8>> = read_next(&mut &witness_sip003[..])
            .map_err(|_e| DBError::ParseError)?;
        let outpoint_txid: Sha256dHash = row.get("prev_txid")?;
        let vout: u32 = row.get("vout")?;
        let script_sig: Vec<u8> = row.get("script_sig")?;
        let sequence : u32 = row.get("sequence")?;

        Ok(TxIn {
            previous_output: OutPoint {
                txid: outpoint_txid,
                vout,
            },
            script_sig: Script::from(script_sig),
            sequence,
            witness
        })
    }
}

impl FromRow<TxOut> for TxOut {
    fn from_row(row: &Row) -> Result<Self, DBError> {
        let value_i64 : i64 = row.get("amount")?;
        let value = u64::try_from(value_i64).map_err(|_e| DBError::ParseError)?;
        let script_pubkey: Vec<u8> = row.get("script_pubkey")?;
        Ok(TxOut {
            value,
            script_pubkey: Script::from(script_pubkey)
        })
    }
}

impl DagDB {
    fn instantiate(tx: &Transaction) -> Result<(), Error> {
        for row in DAG_DB_SCHEMA_1.iter() {
            m2_debug!("{}", row);
            tx.execute(row, params![])?;
        }
        Ok(())
    }

    pub fn get_schema_version(conn: &Connection) -> Result<u32, Error> {
        if !table_exists(conn, "db_config")? {
            m2_debug!("No table 'db_config'");
            return Ok(0);
        }
        let result : u32 = query_row(conn, "SELECT schema_version FROM db_config", params![])?
            .unwrap_or_else(|| {
                m2_debug!("No schema_version in db_config");
                0
            });
        Ok(result)
    }

    pub fn instantiate_or_migrate(conn: &mut Connection, target_schema: u32) -> Result<(), Error> { 
        let mut schema_version = Self::get_schema_version(conn)?;
        m2_debug!("Current Dag DB schema is {}", schema_version);
        while schema_version < target_schema {
            match schema_version {
                0 => {
                    let tx = tx_begin_immediate(conn)?;
                    Self::instantiate(&tx)?;
                    tx.commit()?;
                }
                _ => {
                    panic!("Unsupported schema {}", schema_version);
                }
            }
            let next_schema_version = Self::get_schema_version(conn)?;
            m2_debug!("Migrated to schema {}", next_schema_version);
            assert_eq!(schema_version + 1, next_schema_version);
            schema_version = next_schema_version;
        }
        Ok(())
    }

    pub fn open(path: &str, readwrite: bool) -> Result<Self, Error> {
        let create_flag = if let Err(e) = fs::metadata(path) {
            if e.kind() == ErrorKind::NotFound {
                if readwrite {
                    true
                }
                else {
                    return Err(Error::ReadOnly);
                }
            }
            else {
                return Err(e.into());
            }
        }
        else {
            false
        };
        let flags = if create_flag {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        }
        else if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        }
        else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let mut conn = sqlite_open(path, flags, true)?;
        if create_flag {
            Self::instantiate_or_migrate(&mut conn, SCHEMA_VERSION)?;
        }
        Ok(Self {
            conn,
            path: path.to_string()
        })
    }

    pub fn conn<'a>(&'a self) -> DagConn<'a> {
        DagConn {
            conn: &self.conn
        }
    }

    pub fn tx_begin<'a>(&'a mut self) -> Result<DagTx<'a>, Error> {
        Ok(DagTx {
            tx: tx_begin_immediate(&mut self.conn)?
        })
    }
}


impl<'a> DagConn<'a> {
    /// Get a Bitcoin transaction by txid if it exists
    pub fn get_bitcoin_tx(&self, txid: &Sha256dHash) -> Result<Option<BtcTransaction>, Error> {
        let Some(tx_body): Option<Vec<u8>> = query_row(&self.conn, "SELECT body FROM btc_transactions WHERE txid = ?1", params![&txid])? else {
            return Ok(None);
        };
        let tx = btc_deserialize(&tx_body)?;
        Ok(Some(tx))
    }
    
    pub fn get_utxo_expiry(&self, txid: &Sha256dHash, vout: u32) -> Result<Option<u64>, Error> {
        let res : Option<i64> = query_row(&self.conn, "SELECT 1 FROM btc_inputs WHERE prev_txid = ?1 AND vout = ?2", params![&txid, &vout])?;
        if res.is_some() {
            // TXO was already spent
            return Ok(None);
        }

        let expiry_opt : Option<i64> = query_row(&self.conn, "SELECT expiry FROM btc_outputs WHERE txid = ?1 AND vout = ?2", params![&txid, &vout])?;
        let Some(expiry_i64) = expiry_opt else {
            // TXO not present in the DB
            return Ok(None);
        };
        let Ok(expiry) = u64::try_from(expiry_i64) else {
            // corruption
            return Err(DBError::Corruption.into())
        };

        Ok(Some(expiry))
    }

    /// Get the unexpired balance of a recipient.
    /// `recipient` is the script_pubkey
    pub fn get_balance(&self, recipient: &[u8], cur_bitcoin_height: u64) -> Result<u64, Error> {
        let cur_bitcoin_height_i64 = i64::try_from(cur_bitcoin_height).map_err(|_| Error::Overflow)?;
        let balance_i64 = query_int(&self.conn, "SELECT IFNULL(SUM(amount),0) FROM btc_outputs WHERE script_pubkey = ?1 AND ?2 < expiry", params![&recipient, cur_bitcoin_height_i64])?;
        let Ok(balance) = u64::try_from(balance_i64) else {
            return Err(DBError::Corruption.into());
        };
        Ok(balance)
    }
}

impl<'a> DagTx<'a> {
    pub fn conn(&'a self) -> DagConn<'a> {
        DagConn {
            conn: self.tx.deref()
        }
    }
    
    pub fn commit(self) -> Result<(), Error> {
        Ok(self.tx.commit()?)
    }

    /// Store a transaction with a Bitcoin peg-in
    /// Only store the inputs and outputs that are meaningful (`retain_ins` and
    /// `retain_outs_and_metadata`)
    fn inner_store_bitcoin_tx(&self, round_id: u64, tx: &BtcTransaction, retain_ins: &[usize], retain_outs_and_metadata: &[(usize, u64, &Sha512Trunc256Sum)]) -> Result<(), Error> {
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        let round_id = i64::try_from(round_id).map_err(|_| Error::Overflow)?;
        let tx_bytes = btc_serialize(tx)?;

        let in_set : HashSet<_> = retain_ins.iter().map(|i| *i).collect();
        let out_map : HashMap<_, _> = retain_outs_and_metadata.iter().map(|(i, exp, code_hash)| (*i, (*exp, code_hash))).collect();
        self.tx.execute("INSERT OR REPLACE INTO btc_transactions (txid, wtxid, round_id, body) VALUES (?1, ?2, ?3, ?4)",
                        params![&txid, &wtxid, &round_id, &tx_bytes])?;

        for (i, inp) in tx.input.iter().enumerate() {
            if !in_set.contains(&i) {
                continue;
            }
            let witness_sip003 = inp.witness.serialize_to_vec();
            self.tx.execute("INSERT OR REPLACE INTO btc_inputs (script_sig, witness, txid, prev_txid, vout, vin, sequnce) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            params![&inp.script_sig.to_bytes(), &witness_sip003, &txid, &inp.previous_output.txid, &inp.previous_output.vout, i, inp.sequence])?;
        }

        for (i, out) in tx.output.iter().enumerate() {
            let Some((expiry, code_hash)) = out_map.get(&i) else {
                continue;
            };
            let expiry_i64 = i64::try_from(*expiry).map_err(|_| Error::Overflow)?;
            let value_i64 = i64::try_from(out.value).map_err(|_| Error::Overflow)?;
            self.tx.execute("INSERT OR REPLACE INTO btc_outputs (script_pubkey, amount, txid, vout, expiry, code_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![&out.script_pubkey.to_bytes(), &value_i64, &txid, &i, &expiry_i64, code_hash])?;
        }
        Ok(())
    }

    /// Store a peg-in or transfer transaction with one or more UTXOs which pegin or transfer.
    /// Match each UTXO in tx to its witness script, and extract the expiry and code hash
    /// from the witness script.
    pub fn store_bitcoin_offchain_transaction(&self, round_id: u64, tx: &BtcTransaction, num_cosigner_keys: u8, cosigner_threshold: u8, witness_scripts: &[Script]) -> Result<(), Error> {
        let p2wsh_to_script : HashMap<_, _> = witness_scripts
            .iter()
            .map(|witness_script| (witness_script.to_v0_p2wsh(), witness_script))
            .collect();

        let p2wsh_to_metadata : HashMap<_, _> = witness_scripts
            .iter()
            .filter_map(|witness_script| {
                let Some(unlock_height) = witness::unlock_height(witness_script, num_cosigner_keys, cosigner_threshold) else {
                    return None;
                };
                let Some(code_hash) = witness::code_hash(witness_script, num_cosigner_keys, cosigner_threshold) else {
                    return None;
                };
                Some((witness_script.to_v0_p2wsh(), (unlock_height, code_hash)))
            })
            .collect();

        let retain_outs_and_metadata : Vec<(_, _, _)> = tx.output
            .iter()
            .enumerate()
            .filter_map(|(i, output)| {
                let Some(_script) = p2wsh_to_script.get(&output.script_pubkey) else {
                    return None;
                };
                let Some((expiry, code_hash)) = p2wsh_to_metadata.get(&output.script_pubkey) else {
                    return None;
                };
                Some((i, *expiry, code_hash))
            })
            .collect();

        // determine peg-out expiries
        self.inner_store_bitcoin_tx(round_id, tx, &[], &retain_outs_and_metadata)
    }
    
    /// Store an on-chain pegin transaction
    pub fn store_bitcoin_pegin_transaction(&self, round_id: u64, tx: &BtcTransaction, num_cosigner_keys: u8, cosigner_threshold: u8, pegin_witness_scripts: &[Script]) -> Result<(), Error> {
        self.store_bitcoin_offchain_transaction(round_id, tx, num_cosigner_keys, cosigner_threshold, pegin_witness_scripts)
    }

    /// Store an off-chain transfer transaction
    /// All inputs must match existing outputs.
    /// All outputs retained must have witness scripts
    pub fn store_bitcoin_transfer_transaction(&self, round_id: u64, tx: &BtcTransaction, num_cosigner_keys: u8, cosigner_threshold: u8, witness_scripts: &[Script]) -> Result<(), Error> {
        let conn = self.conn(); 
        // funds expire when the last-expiring UTXO expires
        for inp in tx.input.iter() {
            // each input must consume an offchain UTXO
            if conn.get_utxo_expiry(&inp.previous_output.txid, inp.previous_output.vout)?.is_none() {
                // UTXO doesn't exist
                return Err(Error::MissingUTXO);
            }
        }
        self.store_bitcoin_offchain_transaction(round_id, tx, num_cosigner_keys, cosigner_threshold, witness_scripts)
    }
}
