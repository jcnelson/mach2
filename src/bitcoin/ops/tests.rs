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
use stacks_common::util::secp256k1::{Secp256k1PublicKey, MessageSignature};

use crate::bitcoin::blocks::TransactionExtensions;
use crate::bitcoin::wallet::BitcoinClient;
use crate::tests::*;
use crate::bitcoin::ops::*;
use crate::bitcoin::wallet::tests::utils;

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
    config.bitcoin.segwit = true;

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

    // lock until height 110
    let mut pegin = M2PegIn::new(110, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, 1000000000)
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
    for i in 0..100 {
        user_btc_controller.bootstrap_chain(1);
        if user_btc_controller.is_transaction_confirmed(&txid) {
            mined = true;
            break;
        }
    }
    assert!(mined, "transaction not mined");
    m2_debug!("Send peg-in {}", &txid);
    
    // this transaction is now spendable
    let mut spender_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
    let mut cosigner_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_1);
    let pegin_utxos = pegin.get_pegin_utxos(&pegin_tx, 1);

    let mut utxos = UTXOSet::new();
    utxos.add(spender_utxos.utxos);
    utxos.add(cosigner_utxos.utxos);

    assert_eq!(pegin_utxos.len(), 1, "m2 user has no UTXOs");

    // cosigner and user both sign to spend 
    let mut pegin_spend = pegin.make_unsigned_pegin_spend_transaction(2000, &mut utxos, &pegin_utxos, false).expect("Failed to create joint spend transaction");
    eprintln!("unsigned pegin spend: {}", &pegin_spend.display());
    
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

    // broadcast
    let txid = user_btc_controller.send_transaction(&pegin_spend).expect("Failed to send transaction");

    // mine it
    let mut mined = false;
    for i in 0..100 {
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
    config.bitcoin.segwit = true;

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

    // lock until height 110
    let mut pegin = M2PegIn::new(110, &m2_user_pubkey, &[cosigner_pubkey_1.clone(), cosigner_pubkey_2.clone()], 2, 1000000000)
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
    for i in 0..100 {
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
    let mut spender_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
    let mut cosigner_utxos = user_btc_controller.get_all_utxoset(&cosigner_pubkey_1);
    let pegin_utxos = pegin.get_pegin_utxos(&pegin_tx, 1);

    let mut utxos = UTXOSet::new();
    utxos.add(spender_utxos.utxos);
    utxos.add(cosigner_utxos.utxos);

    assert_eq!(pegin_utxos.len(), 1, "m2 user has no UTXOs");

    let mut pegin_spend = pegin.make_unsigned_pegin_spend_transaction(2000, &mut utxos, &pegin_utxos, false).expect("Failed to create joint spend transaction");
    eprintln!("unsigned pegin spend: {}", &pegin_spend.display());
    
    // set locktime
    pegin_spend.lock_time = 110;

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
    for i in 0..100 {
        user_btc_controller.bootstrap_chain(1);
        if user_btc_controller.is_transaction_confirmed(&txid) {
            mined = true;
            break;
        }
    }
    assert!(mined, "transaction not mined");
}

