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
use stacks_common::util::hash::DoubleSha256;
use stacks_common::types::PublicKey;
use stacks_common::codec::{StacksMessageCodec, read_next, write_next, Error as CodecError};

use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::Error as SqliteError;
use rusqlite::OpenFlags;
use rusqlite::OptionalExtension;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::params;

use crate::bitcoin::Txid;
use crate::bitcoin::wallet::{UTXOSet, UTXO};
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
        -- user's public key
        user_pubkey TEXT NOT NULL,
        -- user's p2wpkh output
        user_p2wpkh TEXT NOT NULL,
        -- witness script that hashes to the script_pubkey
        witness_script TEXT NOT NULL,
        
        PRIMARY KEY(txid,vout),
       
        -- links to btc_transactions
        FOREIGN KEY (txid) REFERENCES btc_transactions (txid) ON DELETE CASCADE ON UPDATE CASCADE
    );
    CREATE INDEX btc_outputs_by_txid ON btc_outputs(txid);
    CREATE INDEX btc_outputs_by_expiry ON btc_outputs(expiry);
    CREATE INDEX btc_outputs_by_user_p2wpkh ON btc_outputs(user_p2wpkh);
    CREATE INDEX btc_outputs_by_script_pubkey ON btc_outputs(script_pubkey);
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
        -- transaction body
        body BLOB NOT NULL
    );
    CREATE INDEX btc_transactions_by_wtxid ON btc_transactions(wtxid);
    "#,
    r#"
    CREATE TABLE dag_db_config(
        schema_version INTEGER NOT NULL
    );
    "#,
    r#"
    INSERT INTO dag_db_config (schema_version) VALUES (1);
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
    InvalidPeginWitness(Script),
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
        if !table_exists(conn, "dag_db_config")? {
            m2_debug!("No table 'dag_db_config'");
            return Ok(0);
        }
        let result : u32 = query_row(conn, "SELECT schema_version FROM dag_db_config", params![])?
            .unwrap_or_else(|| {
                m2_debug!("No schema_version in dag_db_config");
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
    
    pub fn get_utxo_expiry(&self, txid: &Sha256dHash, vout: u32) -> Result<Option<u32>, Error> {
        let res : Option<i64> = query_row(&self.conn, "SELECT 1 FROM btc_inputs WHERE prev_txid = ?1 AND vout = ?2", params![&txid, &vout])?;
        if res.is_some() {
            // TXO was already spent
            return Ok(None);
        }

        let expiry_opt : Option<u32> = query_row(&self.conn, "SELECT expiry FROM btc_outputs WHERE txid = ?1 AND vout = ?2", params![&txid, &vout])?;
        Ok(expiry_opt)
    }

    /// Get the unexpired balance of a scriptpubkey.
    /// `recipient` is the script_pubkey
    pub fn get_balance(&self, recipient_scriptpubkey: &[u8], cur_bitcoin_height: u64) -> Result<u64, Error> {
        let cur_bitcoin_height_i64 = i64::try_from(cur_bitcoin_height).map_err(|_| Error::Overflow)?;
        let balance_i64 = query_int(&self.conn,
            "SELECT IFNULL(SUM(btc_outputs.amount),0)
            FROM btc_outputs LEFT OUTER JOIN btc_inputs ON btc_outputs.txid = btc_inputs.prev_txid
            WHERE btc_inputs.prev_txid IS NULL AND btc_outputs.script_pubkey = ?1 AND ?2 < btc_outputs.expiry"
            , params![recipient_scriptpubkey, cur_bitcoin_height_i64])?;
        let Ok(balance) = u64::try_from(balance_i64) else {
            return Err(DBError::Corruption.into());
        };
        Ok(balance)
    }
    
    /// Get the unexpired balance of a user, who may own many different UTXOs with different
    /// scriptpubkeys (since they'll all be p2wsh scriptpubkeys that commit to different code
    /// hashes and thus different witness scripts)
    pub fn get_user_balance(&self, user_p2wpkh: &Script, cur_bitcoin_height: u64) -> Result<u64, Error> {
        let cur_bitcoin_height_i64 = i64::try_from(cur_bitcoin_height).map_err(|_| Error::Overflow)?;
        let user_p2wpkh_bytes = user_p2wpkh.to_bytes();
        let balance_i64 = query_int(&self.conn,
            "SELECT IFNULL(SUM(btc_outputs.amount),0)
            FROM btc_outputs LEFT OUTER JOIN btc_inputs ON btc_outputs.txid = btc_inputs.prev_txid
            WHERE btc_inputs.prev_txid IS NULL AND btc_outputs.user_p2wpkh = ?1 AND ?2 < btc_outputs.expiry",
            params![&user_p2wpkh_bytes, cur_bitcoin_height_i64])?;
        let Ok(balance) = u64::try_from(balance_i64) else {
            return Err(DBError::Corruption.into());
        };
        Ok(balance)
    }

    fn read_utxos_and_witness_scripts<P>(&self, sql: &str, args: P) -> Result<(UTXOSet, Vec<Script>), Error>
    where
        P: IntoIterator + rusqlite::Params,
        P::Item: ToSql
    {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query(args)?;
        let mut utxos = vec![];
        let mut witness_scripts = vec![];
        while let Some(row) = rows.next()? {
            // HACK: ToSql isn't implemented for DoubleSha256, so load it as a TXID and convert
            let txid : Txid = row.get("txid")?;
            let txid = DoubleSha256(txid.0);
            let vout : u32 = row.get("vout")?;
            let script_pubkey_bytes : Vec<u8> = row.get("script_pubkey")?;
            let script_pub_key = Script::from(script_pubkey_bytes);
            let witness_script_bytes : Vec<u8> = row.get("witness_script")?;
            let witness_script = Script::from(witness_script_bytes);
            let amount_i64 : i64 = row.get("amount")?;
            let amount = u64::try_from(amount_i64).map_err(|_| Error::DBError(DBError::Corruption))?;
            
            utxos.push(UTXO {
                txid,
                vout,
                script_pub_key,
                amount,
                confirmations: 0
            });
            witness_scripts.push(witness_script);
        }
        Ok((UTXOSet::new(utxos), witness_scripts))
    }

    /// Get the UTXOSet spendable by a given user, given the user's p2wpkh.
    /// In addition to each UTXO loaded, obtain its corresponding witness script.
    /// TODO: paginate
    pub fn get_user_utxos_and_witness_scripts(&self, user_p2wpkh: &Script, cur_bitcoin_height: u64) -> Result<(UTXOSet, Vec<Script>), Error> {
        let cur_bitcoin_height_i64 = i64::try_from(cur_bitcoin_height).map_err(|_| Error::Overflow)?;
        let user_p2wpkh_bytes = user_p2wpkh.to_bytes();
        let sql =
            "SELECT txid, vout, script_pubkey, amount, witness_script
            FROM btc_outputs LEFT OUTER JOIN btc_inputs ON btc_outputs.txid = btc_inputs.prev_txid
            WHERE btc_inputs.prev_txid IS NULL AND user_p2wpkh = ?1 AND ?2 < expiry";
        let args = params![&user_p2wpkh_bytes, cur_bitcoin_height_i64];
        self.read_utxos_and_witness_scripts(sql, args)
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

    /// Store a transaction with one or more UTXOs which pegin or transfer.
    /// Match each UTXO in tx to its witness script and expiry.
    /// Only outputs with matching witness scripts will be stored to form UTXOSets
    fn store_bitcoin_offchain_transaction(&self, tx: &BtcTransaction, retain_ins: &[usize], num_cosigner_keys: u8, cosigner_threshold: u8, witness_scripts: &[(Script, u32)]) -> Result<(), Error> {
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        let tx_bytes = btc_serialize(tx)?;

        // map witness p2wsh scriptpubkey to its metadata
        let p2wsh_to_metadata : HashMap<_, _> = witness_scripts
            .iter()
            .filter_map(|(witness_script, utxo_expiry)| {
                let witness_data = witness::WitnessData::try_from_witness_script(witness_script, num_cosigner_keys, cosigner_threshold, *utxo_expiry)?;
                Some((witness_script.to_v0_p2wsh(), witness_data))
            })
            .collect();

        let in_set : HashSet<_> = retain_ins.iter().map(|i| *i).collect();

        // match tx output indexes to their witness metadata
        let out_map : HashMap<_, _> = tx.output
            .iter()
            .enumerate()
            .filter_map(|(i, output)| {
                let metadata = p2wsh_to_metadata.get(&output.script_pubkey)?;
                Some((i, metadata))
            })
            .collect();
        
        // store transaction
        self.tx.execute("INSERT OR REPLACE INTO btc_transactions (txid, wtxid, body) VALUES (?1, ?2, ?3)",
                        params![&txid, &wtxid, &tx_bytes])?;

        // store inputs
        for (i, inp) in tx.input.iter().enumerate() {
            if !in_set.contains(&i) {
                continue;
            }
            let witness_sip003 = inp.witness.serialize_to_vec();
            self.tx.execute("INSERT OR REPLACE INTO btc_inputs (script_sig, witness, txid, prev_txid, vout, vin, sequnce) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            params![&inp.script_sig.to_bytes(), &witness_sip003, &txid, &inp.previous_output.txid, &inp.previous_output.vout, i, inp.sequence])?;
        }

        // store outputs
        for (i, out) in tx.output.iter().enumerate() {
            let Some(witness_data) = out_map.get(&i) else {
                continue;
            };
            let value_i64 = i64::try_from(out.value).map_err(|_| Error::Overflow)?;
            self.tx.execute("INSERT OR REPLACE INTO btc_outputs (script_pubkey, amount, txid, vout, expiry, user_pubkey, user_p2wpkh, witness_script) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![&out.script_pubkey.to_bytes(), &value_i64, &txid, &i, &witness_data.expiry, &witness_data.user_public_key.to_bytes(), &witness_data.user_p2wpkh().to_bytes(), &witness_data.witness_script.to_bytes()])?;
        }
        Ok(())
    }
    
    /// Store an on-chain pegin transaction.
    /// No transaction inputs will be retained.
    /// Only outputs with pegin p2wsh scriptPubKeys will be retained; they must correspond to the
    /// given list of pegin witness scripts.
    ///
    /// TODO: have the cosigner check that each input to a pegin it will cosign does NOT have an
    /// unexpired output in the DB!
    pub fn store_bitcoin_pegin_transaction(&self, tx: &BtcTransaction, num_cosigner_keys: u8, cosigner_threshold: u8, pegin_witness_scripts: &[Script]) -> Result<(), Error> {
        // no inputs will be retained for a peg-in.
        let mut pegin_witness_scripts_and_expiries = vec![];
        for witness_script in pegin_witness_scripts.iter() {
            let Some(expiry) = witness::get_pegin_unlock_height(witness_script) else {
                return Err(Error::InvalidPeginWitness(witness_script.clone()));
            };
            pegin_witness_scripts_and_expiries.push((witness_script.clone(), expiry));
        }

        self.store_bitcoin_offchain_transaction(tx, &[], num_cosigner_keys, cosigner_threshold, &pegin_witness_scripts_and_expiries)
    }

    /// Store an off-chain transfer transaction
    /// All inputs must match existing outputs.
    /// All outputs retained must have witness scripts given in `witness_scripts` -- they can be
    /// pegin witnesses or transfer witnesses.
    pub fn store_bitcoin_transfer_transaction(&self, tx: &BtcTransaction, num_cosigner_keys: u8, cosigner_threshold: u8, witness_scripts: &[Script]) -> Result<(), Error> {
        let conn = self.conn(); 

        // find the earliest expiry of each input of this transaction
        let mut input_expiry = u32::MAX;
        for inp in tx.input.iter() {
            // each input must consume an offchain UTXO
            // TODO: exclude the cancellation input, once it is developed
            let Some(utxo_expiry) = conn.get_utxo_expiry(&inp.previous_output.txid, inp.previous_output.vout)? else {
                // UTXO doesn't exist
                return Err(Error::MissingUTXO);
            };
            input_expiry = input_expiry.min(utxo_expiry);
        }

        // Find the expiry for each witness.
        // The witness could be a pegin witness, or a transfer witness.
        // A pegin witness encodes its expiry -- it's the locktime.
        // A transfer witness inherits earliest expiry of each input this transaction spends.
        let mut witnesses_and_expiries = vec![];
        for witness in witness_scripts.iter() {
            let expiry = if let Some(expiry) = witness::get_pegin_unlock_height(witness) {
                // pegin witness
                expiry
            }
            else {
                // transfer witness -- inherits earliest expiry of each pegin or transfer UTXO this
                // transaction consumes
                input_expiry
            };
            witnesses_and_expiries.push((witness.clone(), expiry));
        }

        let inp_range : Vec<_> = (0..tx.input.len()).collect();
        self.store_bitcoin_offchain_transaction(tx, &inp_range, num_cosigner_keys, cosigner_threshold, &witnesses_and_expiries)
    }
}
