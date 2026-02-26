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

use std::env;

use stacks_common::deps_common::bitcoin::blockdata::block::{Block, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as btc_opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Instruction, Script, Builder};
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::serialize as btc_serialize;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::secp256k1::{Secp256k1PublicKey, MessageSignature};
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::hash::to_hex;
use stacks_common::util::sleep_ms;

use crate::bitcoin::Txid;
use crate::bitcoin::blocks::TransactionExtensions;
use crate::bitcoin::wallet::BitcoinClient;
use crate::tests::*;
use crate::bitcoin::ops::*;
use crate::bitcoin::wallet::tests::utils;

fn pubkey_to_p2wpkh(pubkey: &Secp256k1PublicKey) -> Script {
    let pubkey_hash = Hash160::from_data(&pubkey.to_bytes());
    let pubkey_v0_p2wpkh = Builder::new()
        .push_int(0)
        .push_slice(&pubkey_hash.0)
        .into_script();

    pubkey_v0_p2wpkh
}

#[test]
#[ignore]
fn test_send_pegin_tx_and_joint_spend() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut user_signer = utils::create_keychain_with_seed(1);
    let user_pubkey = user_signer.get_public_key();

    let mut cosigner_signer_1 = utils::create_keychain_with_seed(2);
    let cosigner_pubkey_1 = cosigner_signer_1.get_public_key();
    
    let mut cosigner_signer_2 = utils::create_keychain_with_seed(4);
    let cosigner_pubkey_2 = cosigner_signer_2.get_public_key();

    let mut m2_user_signer = utils::create_keychain_with_seed(3);
    let m2_user_pubkey = m2_user_signer.get_public_key();

    let mut config = utils::create_cosigner_config();
    config.bitcoin.local_mining_public_key = Some(user_pubkey.to_hex());

    let mut btcd_controller = BitcoinCoreController::from_config(&config);
    btcd_controller
        .start_bitcoind()
        .expect("bitcoind should be started!");

    let user_btc_controller = BitcoinClient::new(config.clone());
    user_btc_controller.bootstrap_chain(1); // one utxo for miner_pubkey related address

    config.bitcoin.local_mining_public_key = Some(cosigner_pubkey_1.to_hex());
    config.bitcoin.wallet_name = "cosigner_wallet".to_string();
    let cosigner_btc_controller = BitcoinClient::new(config);
    cosigner_btc_controller.bootstrap_chain(102); // two utxo for other_pubkeys related address
    
    let mut spender_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
    let mut cosigner_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_1);

    // lock until height 110, with clawback at 120
    let mut pegin = OpPegIn::new(110, 10, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], StacksAddress::new(1, Hash160([0x01; 20])).unwrap(), 1000000000)
        .with_spender(&user_pubkey);

    let mut pegin_tx = pegin.make_unsigned_pegin_transaction(2000, &mut spender_utxos).expect("Failed to create pegin transaction");
    eprintln!("unsigned pegin: {}", &pegin_tx.display());

    // check structure
    assert_eq!(pegin_tx.input.len(), 1);
    assert_eq!(pegin_tx.input[0].witness.len(), 1);
    assert_eq!(pegin_tx.input[0].script_sig, Script::new());
    assert_eq!(pegin_tx.output.len(), 2);
    assert_eq!(pegin_tx.output[0].value, 1000000000);

    // spending user signs
    assert!(pegin.sign_spender(&mut user_signer, &mut spender_utxos, &mut pegin_tx));
    
    // cosigner signs
    assert!(pegin.sign_cosigner(&mut cosigner_signer_1, &mut cosigner_utxos, &mut pegin_tx));
    assert!(pegin.sign_cosigner(&mut cosigner_signer_2, &mut cosigner_utxos, &mut pegin_tx));

    pegin.clear_witness();
    
    // broadcast
    let txid = user_btc_controller.send_transaction(&pegin_tx).expect("Failed to send transaction");

    // mine it
    let mut btc_height = 103;
    let mut mined = false;
    for _i in 0..100 {
        user_btc_controller.bootstrap_chain(1);
        btc_height += 1;
        if user_btc_controller.is_transaction_confirmed(&txid) {
            mined = true;
            break;
        }
    }
    assert!(btc_height < 110);
    assert!(mined, "transaction not mined");
    m2_debug!("Send peg-in {}", &txid);
    
    // this transaction is now spendable
    let spender_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
    let cosigner_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_1);
    let pegin_utxos = pegin.get_pegin_utxos(&pegin_tx, 1);

    let mut utxos = UTXOSet::empty();
    utxos.add(spender_utxos.utxos);
    utxos.add(cosigner_utxos.utxos);

    assert_eq!(pegin_utxos.len(), 1, "m2 user has no UTXOs");

    // cosigner and user both sign to spend 
    let mut pegin_spend = pegin.make_unsigned_pegin_spend_transaction(2000, &mut utxos, &pegin_utxos, false).expect("Failed to create joint spend transaction");
    eprintln!("unsigned pegin spend: {}", &pegin_spend.display());
    
    pegin_spend.lock_time = 110;

    // m2 user signs
    assert!(pegin.sign_user(&mut m2_user_signer, &mut utxos, &mut pegin_spend));
    eprintln!("user-signed pegin spend: {}", &pegin_spend.display());
    
    // spender signs
    assert!(pegin.sign_spender(&mut user_signer, &mut utxos, &mut pegin_spend));
    eprintln!("spender-signed pegin spend: {}", &pegin_spend.display());
    
    // cosigner signs
    assert!(pegin.sign_cosigner(&mut cosigner_signer_1, &mut utxos, &mut pegin_spend));
    eprintln!("cosigner1-signed pegin spend: {}", &pegin_spend.display());
    assert!(pegin.sign_cosigner(&mut cosigner_signer_2, &mut utxos, &mut pegin_spend));
    eprintln!("cosigner2-signed pegin spend: {}", &pegin_spend.display());

    pegin.clear_witness();

    user_btc_controller.bootstrap_chain(110 - btc_height);
    let txid = user_btc_controller.send_transaction(&pegin_spend).expect("Failed to send transaction");

    // mine it
    let mut mined = false;
    for _i in 0..100 {
        user_btc_controller.bootstrap_chain(1);
        if user_btc_controller.is_transaction_confirmed(&txid) {
            mined = true;
            break;
        }
    }
    assert!(mined, "transaction not mined");
}

#[test]
#[ignore]
fn test_send_pegin_tx_and_clawback() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut user_signer = utils::create_keychain_with_seed(1);
    let user_pubkey = user_signer.get_public_key();

    let mut cosigner_signer_1 = utils::create_keychain_with_seed(2);
    let cosigner_pubkey_1 = cosigner_signer_1.get_public_key();
    
    let mut cosigner_signer_2 = utils::create_keychain_with_seed(4);
    let cosigner_pubkey_2 = cosigner_signer_2.get_public_key();

    let mut m2_user_signer = utils::create_keychain_with_seed(3);
    let m2_user_pubkey = m2_user_signer.get_public_key();

    let mut config = utils::create_cosigner_config();
    config.bitcoin.local_mining_public_key = Some(user_pubkey.to_hex());

    let mut btcd_controller = BitcoinCoreController::from_config(&config);
    btcd_controller
        .start_bitcoind()
        .expect("bitcoind should be started!");

    let user_btc_controller = BitcoinClient::new(config.clone());
    user_btc_controller.bootstrap_chain(1); // one utxo for miner_pubkey related address

    config.bitcoin.local_mining_public_key = Some(cosigner_pubkey_1.to_hex());
    config.bitcoin.wallet_name = "cosigner_wallet".to_string();
    let cosigner_btc_controller = BitcoinClient::new(config);
    cosigner_btc_controller.bootstrap_chain(102); // two utxo for other_pubkeys related address
    
    let mut spender_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
    let mut cosigner_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_1);

    // lock until height 120
    let mut pegin = OpPegIn::new(110, 10, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], StacksAddress::new(1, Hash160([0x12; 20])).unwrap(), 1000000000)
        .with_spender(&user_pubkey);

    let mut pegin_tx = pegin.make_unsigned_pegin_transaction(2000, &mut spender_utxos).expect("Failed to create pegin transaction");
    eprintln!("unsigned pegin: {}", &pegin_tx.display());

    // check structure
    assert_eq!(pegin_tx.input.len(), 1);
    assert_eq!(pegin_tx.input[0].witness.len(), 1);
    assert_eq!(pegin_tx.input[0].script_sig, Script::new());
    assert_eq!(pegin_tx.output.len(), 2);
    assert_eq!(pegin_tx.output[0].value, 1000000000);

    // spending user signs
    assert!(pegin.sign_spender(&mut user_signer, &mut spender_utxos, &mut pegin_tx));
    
    // cosigner signs
    assert!(pegin.sign_cosigner(&mut cosigner_signer_1, &mut cosigner_utxos, &mut pegin_tx));
    assert!(pegin.sign_cosigner(&mut cosigner_signer_2, &mut cosigner_utxos, &mut pegin_tx));

    pegin.clear_witness();
    
    // broadcast
    let txid = user_btc_controller.send_transaction(&pegin_tx).expect("Failed to send transaction");

    // mine it
    let mut mined = false;
    for _i in 0..100 {
        user_btc_controller.bootstrap_chain(1);
        if user_btc_controller.is_transaction_confirmed(&txid) {
            mined = true;
            break;
        }
    }
    assert!(mined, "transaction not mined");
    m2_debug!("Send peg-in {}", &txid);
   
    // advance to clawback condition
    cosigner_btc_controller.bootstrap_chain(20);
    
    // this transaction is now spendable
    let spender_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
    let cosigner_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_1);
    let pegin_utxos = pegin.get_pegin_utxos(&pegin_tx, 1);

    let mut utxos = UTXOSet::empty();
    utxos.add(spender_utxos.utxos);
    utxos.add(cosigner_utxos.utxos);

    assert_eq!(pegin_utxos.len(), 1, "m2 user has no UTXOs");

    let mut pegin_spend = pegin.make_unsigned_pegin_spend_transaction(2000, &mut utxos, &pegin_utxos, false).expect("Failed to create joint spend transaction");
    eprintln!("unsigned pegin spend: {}", &pegin_spend.display());
    
    // set locktime
    pegin_spend.lock_time = 120;

    // m2 user signs
    assert!(pegin.sign_user(&mut m2_user_signer, &mut utxos, &mut pegin_spend));
    eprintln!("user-signed pegin spend: {}", &pegin_spend.display());
    
    // spender signs
    assert!(pegin.sign_spender(&mut user_signer, &mut utxos, &mut pegin_spend));
    eprintln!("spender-signed pegin spend: {}", &pegin_spend.display());
    
    // null cosigner signs
    assert!(pegin.sign_null_cosigner(&mut user_signer, &mut utxos, &mut pegin_spend));
    eprintln!("null-cosigner1-signed pegin spend: {}", &pegin_spend.display());
    assert!(pegin.sign_null_cosigner(&mut user_signer, &mut utxos, &mut pegin_spend));
    eprintln!("null-cosigner2-signed pegin spend: {}", &pegin_spend.display());

    pegin.clear_witness();

    // broadcast
    let txid = user_btc_controller.send_transaction(&pegin_spend).expect("Failed to send transaction");

    // mine it
    let mut mined = false;
    for _i in 0..100 {
        user_btc_controller.bootstrap_chain(1);
        if user_btc_controller.is_transaction_confirmed(&txid) {
            mined = true;
            break;
        }
    }
    assert!(mined, "transaction not mined");
}

#[test]
fn test_pegin_witness_script_unlock_height() {
    let mut user_signer = utils::create_keychain_with_seed(1);
    let user_pubkey = user_signer.get_public_key();

    let mut cosigner_signer_1 = utils::create_keychain_with_seed(2);
    let cosigner_pubkey_1 = cosigner_signer_1.get_public_key();
    
    let mut cosigner_signer_2 = utils::create_keychain_with_seed(4);
    let cosigner_pubkey_2 = cosigner_signer_2.get_public_key();

    let mut m2_user_signer = utils::create_keychain_with_seed(3);
    let m2_user_pubkey = m2_user_signer.get_public_key();

    // lock until height 110
    let pegin = OpPegIn::new(110, 10, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], StacksAddress::new(1, Hash160([0x23; 20])).unwrap(), 1000000000)
        .with_spender(&user_pubkey);
   
    let witness_script = pegin.make_witness_script();
    assert_eq!(witness::get_pegin_unlock_height(&witness_script).unwrap(), 120);
}

/*
#[test]
#[ignore]
fn test_send_pegin_and_transfer() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut user_signer = utils::create_keychain_with_seed(1);
    let user_pubkey = user_signer.get_public_key();

    let mut cosigner_signer_1 = utils::create_keychain_with_seed(2);
    let cosigner_pubkey_1 = cosigner_signer_1.get_public_key();
    
    let mut cosigner_signer_2 = utils::create_keychain_with_seed(4);
    let cosigner_pubkey_2 = cosigner_signer_2.get_public_key();

    let mut m2_user_signer = utils::create_keychain_with_seed(3);
    let m2_user_pubkey = m2_user_signer.get_public_key();
    
    let mut recipient_signer = utils::create_keychain_with_seed(5);
    let recipient_pubkey = recipient_signer.get_public_key();
    
    let mut recipient_2_signer = utils::create_keychain_with_seed(6);
    let recipient_2_pubkey = recipient_2_signer.get_public_key();
  
    // user_signer pays to send a peg-in which is spendalbe by m2_user
    // peg-in UTXO gets spent by m2_user via a transfer to give m2_user 10 BTC, with 2000 sats fee
    // m2_user sends 3 BTC to recipient, and keeps 7 BTC, with 2000 sats fee
    // recipient sends 2 BTC to recipient_2, and keeps 1 BTC, with 2000 stats fee
    // recipient_2 has 2 BTC

    let mut config = utils::create_cosigner_config();
    config.bitcoin.local_mining_public_key = Some(user_pubkey.to_hex());

    let mut btcd_controller = BitcoinCoreController::from_config(&config);
    btcd_controller
        .start_bitcoind()
        .expect("bitcoind should be started!");

    let user_btc_controller = BitcoinClient::new(config.clone());
    user_btc_controller.bootstrap_chain(1); // one utxo for miner_pubkey related address

    config.bitcoin.local_mining_public_key = Some(cosigner_pubkey_1.to_hex());
    config.bitcoin.wallet_name = "cosigner_wallet".to_string();
    let cosigner_btc_controller = BitcoinClient::new(config);
    cosigner_btc_controller.bootstrap_chain(102); // two utxo for other_pubkeys related address
    let mut btc_height = 103;
    
    let mut spender_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
    let cosigner_utxos_1 = user_btc_controller.get_all_utxoset(&cosigner_pubkey_1);
    let cosigner_utxos_2 = user_btc_controller.get_all_utxoset(&cosigner_pubkey_2);
    let mut cosigner_utxos = cosigner_utxos_1;
    cosigner_utxos.add(cosigner_utxos_2.utxos);

    // lock until height 110
    let mut pegin = OpPegIn::new(110, 10, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, StacksAddress::new(1, Hash160([0x01; 20])).unwrap(), 1000000000)
        .with_spender(&user_pubkey);

    let mut pegin_tx = pegin.make_unsigned_pegin_transaction(2000, &mut spender_utxos).expect("Failed to create pegin transaction");
    eprintln!("unsigned pegin: {}", &pegin_tx.display());

    // check structure
    assert_eq!(pegin_tx.input.len(), 1);
    assert_eq!(pegin_tx.input[0].witness.len(), 1);
    assert_eq!(pegin_tx.input[0].script_sig, Script::new());
    assert_eq!(pegin_tx.output.len(), 2);
    assert_eq!(pegin_tx.output[0].value, 1000000000);

    // spending user signs
    assert!(pegin.sign_spender(&mut user_signer, &mut spender_utxos, &mut pegin_tx));
    
    // cosigner signs
    assert!(pegin.sign_cosigner(&mut cosigner_signer_1, &mut cosigner_utxos, &mut pegin_tx));
    assert!(pegin.sign_cosigner(&mut cosigner_signer_2, &mut cosigner_utxos, &mut pegin_tx));

    pegin.clear_witness();
    
    // broadcast
    let txid = user_btc_controller.send_transaction(&pegin_tx).expect("Failed to send transaction");
    eprintln!("Sent {}: {:?}", &pegin_tx.display(), &txid);
    
    // mine it
    let mut mined = false;
    for _i in 0..100 {
        user_btc_controller.bootstrap_chain(1);
        btc_height += 1;
        if user_btc_controller.is_transaction_confirmed(&txid) {
            mined = true;
            break;
        }
    }
    assert!(mined, "transaction not mined");
    m2_debug!("Send peg-in {}", &Txid::to_bitcoin_tx_hash(&txid));
    
    // this transaction is now spendable
    let pegin_utxos = pegin.get_pegin_utxos(&pegin_tx, 1);
    let mut pegin_utxoset = UTXOSet::empty();
    pegin_utxoset.add(pegin_utxos);

    let pegin_witnesses = vec![pegin.make_witness_script()];

    assert_eq!(pegin_utxoset.len(), 1, "m2 user has no UTXOs");

    // make an off-chain transfer, with safety margin 10 (so, unilterally spendable at 120)
    let mut transfer = OpTransfer::new(10, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, vec![0x02; 32]);
    let m2_user_reclaim_p2wsh = transfer.make_user_script_pubkey();
    let recipient_payload = vec![0x01; 32];
    let recipient_p2wsh = transfer.make_recipient_script_pubkey(&recipient_pubkey, recipient_payload.clone());
    let mut transfer_tx = transfer.make_unsigned_transfer_spend_transaction(2000, &mut pegin_utxoset, &pegin_witnesses, recipient_p2wsh.clone(), 300000000)
        .expect("Failed to produce a transfer transaction");
    transfer_tx.lock_time = 110;

    eprintln!("unsigned transfer tx: {}", &transfer_tx.display());
    assert_eq!(pegin_utxoset.len(), 1);

    // m2 user signs
    assert!(transfer.sign_user(&mut m2_user_signer, &mut pegin_utxoset, &pegin_witnesses, &mut transfer_tx));
    eprintln!("user-signed transfer tx: {}", &transfer_tx.display());
    assert_eq!(pegin_utxoset.len(), 1);

    // cosigner signs
    assert!(transfer.sign_cosigner(&mut cosigner_signer_1, &mut pegin_utxoset, &pegin_witnesses, &mut transfer_tx));
    assert_eq!(pegin_utxoset.len(), 1);
    assert!(transfer.sign_cosigner(&mut cosigner_signer_2, &mut pegin_utxoset, &pegin_witnesses, &mut transfer_tx));
    assert_eq!(pegin_utxoset.len(), 1);
    eprintln!("cosigner-signed transfer tx: {}", &transfer_tx.display());

    pegin.clear_witness();
    transfer.clear_witness();

    // cannot currently broadcast
    let err = user_btc_controller.send_transaction(&transfer_tx);
    eprintln!("Tried to broadcast post-dated transfer: {:?}", &err);
    assert!(err.is_err());

    let transfer_utxos = transfer.get_transfer_utxos(&transfer_tx, 1, &recipient_p2wsh);
    let m2_user_reclaim_utxos = transfer.get_transfer_utxos(&transfer_tx, 1, &m2_user_reclaim_p2wsh);
    assert_eq!(transfer_utxos.len(), 1);
    assert_eq!(m2_user_reclaim_utxos.len(), 1);

    let mut transfer_utxoset = UTXOSet::empty();
    transfer_utxoset.add(transfer_utxos);

    m2_test_debug!("transfer_utxoset: {:?}", &transfer_utxoset);
    m2_test_debug!("m2_user_reclaim_utxos: {:?}", &m2_user_reclaim_utxos);
    let mut transfer_txs = vec![transfer_tx];
    
    // make another off-chain transfer which spends this last transfer
    let recipient_2_p2wsh = transfer.make_recipient_script_pubkey(&recipient_2_pubkey, vec![0x20; 32]);
    let mut transfer = OpTransfer::new(10, &recipient_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, recipient_payload.clone());
    let mut transfer_tx = transfer.make_unsigned_transfer_spend_transaction(2000, &mut transfer_utxoset, &[], recipient_2_p2wsh.clone(), 200000000)
        .expect("Failed to produce a transfer transaction");
    eprintln!("unsigned transfer 2 tx: {}", &transfer_tx.display());

    transfer_tx.lock_time = 110;

    // recipient signs
    assert!(transfer.sign_user(&mut recipient_signer, &mut transfer_utxoset, &[], &mut transfer_tx));
    eprintln!("user-signed transfer 2 tx: {}", &transfer_tx.display());
    assert_eq!(transfer_utxoset.len(), 1);

    // cosigner signs
    assert!(transfer.sign_cosigner(&mut cosigner_signer_1, &mut transfer_utxoset, &[], &mut transfer_tx));
    assert_eq!(transfer_utxoset.len(), 1);
    assert!(transfer.sign_cosigner(&mut cosigner_signer_2, &mut transfer_utxoset, &[], &mut transfer_tx));
    assert_eq!(transfer_utxoset.len(), 1);
    eprintln!("cosigner-signed transfer 2 tx: {}", &transfer_tx.display());

    // cannot currently broadcast
    let err = user_btc_controller.send_transaction(&transfer_tx);
    eprintln!("Tried to broadcast post-dated transfer 2: {:?}", &err);
    assert!(err.is_err());

    let recipient_reclaim_utxos = transfer.get_transfer_utxos(&transfer_tx, 1, &recipient_p2wsh);
    let recipient_2_reclaim_utxos = transfer.get_transfer_utxos(&transfer_tx, 1, &recipient_2_p2wsh);
    
    transfer_txs.push(transfer_tx);

    // advance the chain tip to height 110
    while btc_height < 110 {
        for tx in transfer_txs.iter() {
            let err = user_btc_controller.send_transaction(tx);
            assert!(err.is_err(), "sent unintentionally at {}: {}", btc_height, tx.display());
        }
        user_btc_controller.bootstrap_chain(1);
        btc_height += 1;
    }

    let mut txids = vec![];

    // should work at or after 110
    for tx in transfer_txs.iter() {
        let res = user_btc_controller.send_transaction(tx);
        eprintln!("Sent at {} {}: {:?}", btc_height, &tx.display(), &res);
        assert!(res.is_ok());
        txids.push(res.unwrap());

        user_btc_controller.bootstrap_chain(10);
        btc_height += 10;
    }

    let mut all_mined = false;
    
    // make sure they're all mined
    for _i in 0..6 {
        user_btc_controller.bootstrap_chain(1);
        let mut mined = true;
        for txid in txids.iter() {
            let res = user_btc_controller.get_raw_transaction(&txid);
            eprintln!("for {}: {:?}", &txid, &res);
            if res.is_err() {
                mined = false;
                break;
            }
        }
        if mined {
            all_mined = true;
            break;
        }
        sleep_ms(1000);
    }

    assert!(all_mined);

    // can now spend them on-chain without the cosigner
    // have the m2 user acquire their UTXO.
    // They gave 3 BTC to recipient, and kept 7 BTC with 2000 sats feee.
    // Spend another 2000 stats to reclaim that 7 BTC - 4000 sats
    let mut user_utxoset = UTXOSet::empty();
    user_utxoset.add(m2_user_reclaim_utxos);
    let mut transfer = OpTransfer::new(10, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, vec![0x02; 32]);
    let mut transfer_tx = transfer.make_unsigned_transfer_spend_transaction(2000, &mut user_utxoset, &[], pubkey_to_p2wpkh(&m2_user_pubkey), 700000000 - (2000 * 2)).unwrap();
    
    transfer_tx.lock_time = 120;
    
    // m2 user signs
    assert!(transfer.sign_user(&mut m2_user_signer, &mut user_utxoset, &[], &mut transfer_tx));
    eprintln!("user-signed transfer reclaim tx: {}", &transfer_tx.display());
    assert_eq!(user_utxoset.len(), 1);

    // null cosigner signs
    assert!(transfer.sign_null_cosigner(&mut cosigner_signer_1, &mut user_utxoset, &[], &mut transfer_tx));
    assert!(transfer.sign_null_cosigner(&mut cosigner_signer_2, &mut user_utxoset, &[], &mut transfer_tx));
    eprintln!("null-cosigner-signed transfer reclaim tx: {}", &transfer_tx.display());

    transfer.clear_witness();

    let txid = user_btc_controller.send_transaction(&transfer_tx).expect("Failed to send transaction");
    eprintln!("Sent m2-user-reclaim {}: {:?}", &transfer_tx.display(), &txid);

    // have recipient acquire their UTXO
    // They got 3 BTC from m2_user, sent 2 BTC to recipient_2 for 2000 sats, and are now trying to
    // claim the remaining 1 BTC - 4000 sats
    let mut recipient_utxoset = UTXOSet::empty();
    recipient_utxoset.add(recipient_reclaim_utxos);

    let mut transfer = OpTransfer::new(10, &recipient_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, recipient_payload.clone());
    let mut transfer_tx = transfer.make_unsigned_transfer_spend_transaction(2000, &mut recipient_utxoset, &[], pubkey_to_p2wpkh(&recipient_pubkey), 100000000 - (2000 * 2)).unwrap();
    
    transfer_tx.lock_time = 120;
    
    // recipient signs
    assert!(transfer.sign_user(&mut recipient_signer, &mut recipient_utxoset, &[], &mut transfer_tx));
    eprintln!("recipient-signed transfer reclaim tx: {}", &transfer_tx.display());
    assert_eq!(recipient_utxoset.len(), 1);

    // null cosigner signs
    assert!(transfer.sign_null_cosigner(&mut cosigner_signer_1, &mut recipient_utxoset, &[], &mut transfer_tx));
    assert!(transfer.sign_null_cosigner(&mut cosigner_signer_2, &mut recipient_utxoset, &[], &mut transfer_tx));
    eprintln!("null-cosigner-signed recipient transfer reclaim tx: {}", &transfer_tx.display());

    transfer.clear_witness();
    
    let txid = user_btc_controller.send_transaction(&transfer_tx).expect("Failed to send transaction");
    eprintln!("Sent recipient-reclaim {}: {:?}", &transfer_tx.display(), &txid);

    // have recipient 2 acquire their UTXO
    // They got 2 BTC from recipient
    let mut recipient_2_utxoset = UTXOSet::empty();
    recipient_2_utxoset.add(recipient_2_reclaim_utxos);

    m2_test_debug!("recipient_2_utxoset: {:?}", &recipient_2_utxoset);

    let mut transfer = OpTransfer::new(10, &recipient_2_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, vec![0x20; 32]);
    let mut transfer_tx = transfer.make_unsigned_transfer_spend_transaction(2000, &mut recipient_2_utxoset, &[], pubkey_to_p2wpkh(&recipient_2_pubkey), 200000000 - 2000).unwrap();
    
    transfer_tx.lock_time = 120;

    // recipient signs
    assert!(transfer.sign_user(&mut recipient_2_signer, &mut recipient_2_utxoset, &[], &mut transfer_tx));
    eprintln!("recipient-signed transfer reclaim tx: {}", &transfer_tx.display());
    assert_eq!(recipient_utxoset.len(), 1);

    // null cosigner signs
    assert!(transfer.sign_null_cosigner(&mut cosigner_signer_1, &mut recipient_2_utxoset, &[], &mut transfer_tx));
    assert!(transfer.sign_null_cosigner(&mut cosigner_signer_2, &mut recipient_2_utxoset, &[], &mut transfer_tx));
    eprintln!("null-cosigner-signed recipient transfer reclaim tx: {}", &transfer_tx.display());

    transfer.clear_witness();
    
    let txid = user_btc_controller.send_transaction(&transfer_tx).expect("Failed to send transaction");
    eprintln!("Sent recipient-2-reclaim {}: {:?}", &transfer_tx.display(), &txid);

    // update tracked UTXOs
    let cosigner_1_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_2);
    let cosigner_2_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_2);
    let m2_user_utxos = user_btc_controller.get_all_utxoset(&m2_user_pubkey);
    let recipient_utxos = user_btc_controller.get_all_utxoset(&recipient_pubkey);
    let recipient_2_utxos = user_btc_controller.get_all_utxoset(&recipient_2_pubkey);

    // peg-in UTXO was spent by m2_user via a transfer to give m2_user 10 BTC, with 2000 sats fee
    // m2_user sent 3 BTC to recipient, and kept 7 BTC, with 2000 sats fee
    // recipient sent 2 BTC to recipient_2, and kept 1 BTC, with 2000 stats fee
    // recipient_2 has 2 BTC
    
    m2_debug!("m2_user_utxos: {:?}", &m2_user_utxos);
    m2_debug!("recipient_utxos: {:?}", &recipient_utxos);
    m2_debug!("recipient_2_utxos: {:?}", &recipient_2_utxos);

    assert_eq!(cosigner_1_utxos.total_available(), 0);
    assert_eq!(cosigner_2_utxos.total_available(), 0);
    assert_eq!(m2_user_utxos.total_available(), 700000000 - (2 * 2000));
    assert_eq!(recipient_utxos.total_available(), 100000000 - (2 * 2000));
    assert_eq!(recipient_2_utxos.total_available(), 200000000 - 2000);
}
*/
