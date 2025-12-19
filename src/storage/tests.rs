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

use crate::storage::dag::*;
use crate::bitcoin::wallet::tests::utils;
use crate::bitcoin::ops::M2PegIn;

use crate::bitcoin::wallet::{UTXO, UTXOSet};

use stacks_common::util::hash::DoubleSha256;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::hash::to_hex;
use stacks_common::types::PublicKey;
use stacks_common::deps_common::bitcoin::blockdata::script::{Builder, Script};
use stacks_common::types::chainstate::StacksAddress;

#[test]
fn test_dag_db_instantiation() {
    let path = "/tmp/test_dag_db_instantiation.sqlite";
    if fs::metadata(path).is_ok() {
        fs::remove_file(path).unwrap();
    }

    let dag_db = DagDB::open(path, true).unwrap();
    assert_eq!(DagDB::get_schema_version(&dag_db.conn()).unwrap(), SCHEMA_VERSION);
}

#[test]
fn test_store_pegin_transaction() {
    let path = "/tmp/test_dag_db_store_pegin_transaction.sqlite";
    if fs::metadata(path).is_ok() {
        fs::remove_file(path).unwrap();
    }
    
    let mut dag_db = DagDB::open(path, true).unwrap();
    
    let mut user_signer = utils::create_keychain_with_seed(1);
    let mut user_pubkey = user_signer.get_public_key();
    user_pubkey.set_compressed(true);

    let mut cosigner_signer_1 = utils::create_keychain_with_seed(2);
    let cosigner_pubkey_1 = cosigner_signer_1.get_public_key();
    
    let mut cosigner_signer_2 = utils::create_keychain_with_seed(4);
    let cosigner_pubkey_2 = cosigner_signer_2.get_public_key();

    let mut m2_user_signer = utils::create_keychain_with_seed(3);
    let m2_user_pubkey = m2_user_signer.get_public_key();

    let mut spender_utxos = UTXOSet::empty();
    spender_utxos.add(vec![
        UTXO {
            txid: DoubleSha256([0x11; 32]),
            vout: 0,
            script_pub_key: Builder::new()
                .push_int(0)
                .push_slice(&Hash160::from_data(&user_pubkey.to_bytes()).0)
                .into_script(),
            amount: 1500000000,
            confirmations: 1
        }
    ]);

    let mut cosigner_utxos = UTXOSet::empty();

    // lock until height 110
    let mut pegin = M2PegIn::new(110, 10, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, StacksAddress::new(0, Hash160([0x11; 20])).unwrap(), 1000000000)
        .with_spender(&user_pubkey);
    
    let mut pegin_tx = pegin.make_unsigned_pegin_transaction(2000, &mut spender_utxos).expect("Failed to create pegin transaction");
   
    // spending user signs
    assert!(pegin.sign_spender(&mut user_signer, &mut spender_utxos, &mut pegin_tx));
    
    // cosigner signs
    assert!(pegin.sign_cosigner(&mut cosigner_signer_1, &mut cosigner_utxos, &mut pegin_tx));
    assert!(pegin.sign_cosigner(&mut cosigner_signer_2, &mut cosigner_utxos, &mut pegin_tx));

    pegin.clear_witness();
    let witness_script = pegin.make_witness_script();
    let recipient = witness_script.to_v0_p2wsh().to_bytes();

    m2_debug!("Recipient is {}", to_hex(&recipient));
    let tx = dag_db.tx_begin().unwrap();
    tx.store_bitcoin_pegin_transaction(&pegin_tx, 2, 2, &[witness_script]).unwrap();
    tx.commit().unwrap();

    let balance = dag_db.conn().get_balance(&recipient, 109).unwrap();
    assert_eq!(balance, 1000000000);
    
    let balance = dag_db.conn().get_balance(&recipient, 110).unwrap();
    assert_eq!(balance, 0);
}
