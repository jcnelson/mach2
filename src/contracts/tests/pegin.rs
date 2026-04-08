// Copyright (C) 2026 Stacks Open Internet Foundation
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

use crate::core::config::Config;

use crate::bitcoin::blocks::TransactionExtensions;
use crate::bitcoin::wallet::BitcoinClient;
use crate::bitcoin::ops::OpPegIn;
use crate::bitcoin::signer::BitcoinOpSigner;

use stacks_common::types::chainstate::StacksAddress;
use stacks_common::deps_common::bitcoin::blockdata::script::Script;

use crate::devnet::BitcoinCoreController;
use crate::bitcoin::wallet::tests::utils;

pub struct PeginTest {
    user_signer: BitcoinOpSigner,
    cosigner_signers: Vec<BitcoinOpSigner>,
    cosigner_config: Config,
    btcd_controller: BitcoinCoreController,
    user_btc_controller: BitcoinClient,
    cosigner_btc_controller: BitcoinClient,
    pegin: OpPegIn,
}

impl PeginTest {
    pub fn begin(locktime: u32, safety_margin: u32, num_cosigners: usize, provider: StacksAddress, amount: u64, tx_fee: u64) -> Self {
        let mut user_signer = utils::create_keychain_with_seed(1);
        let user_pubkey = user_signer.get_public_key();

        let mut cosigner_signers = vec![];
        let mut cosigner_pubkeys = vec![];
        for i in 0..num_cosigners {
            let mut cosigner_signer = utils::create_keychain_with_seed(2 + (i as u8));
            let cosigner_pubkey = cosigner_signer.get_public_key();

            cosigner_signers.push(cosigner_signer);
            cosigner_pubkeys.push(cosigner_pubkey);
        }

        let mut config = utils::create_cosigner_config();
        config.bitcoin.local_mining_public_key = Some(user_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_config(&config);
        btcd_controller
            .start()
            .expect("bitcoind should be started!");

        let user_btc_controller = BitcoinClient::new(config.clone());
        user_btc_controller.bootstrap_chain(1); // one utxo for miner_pubkey related address

        config.bitcoin.local_mining_public_key = Some(user_pubkey.to_hex());
        config.bitcoin.wallet_name = "user_wallet".to_string();
        let cosigner_btc_controller = BitcoinClient::new(config.clone());
        cosigner_btc_controller.bootstrap_chain(102); // two utxo for other_pubkeys related address
        
        let mut user_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);

        // instantiate the pegin
        let mut pegin = OpPegIn::new(locktime, safety_margin, &user_pubkey, &cosigner_pubkeys, provider, amount);

        let (mut pegin_tx, mut pegin_utxos) = pegin.make_unsigned_pegin_transaction(tx_fee, &mut user_utxos).expect("Failed to create pegin transaction");
        m2_info!("unsigned pegin: {}", &pegin_tx.display());

        // check structure
        assert!(pegin_tx.input.len() >= 1 && pegin_tx.input.len() <= user_utxos.len());
        for inp in pegin_tx.input.iter() {
            assert_eq!(inp.witness.len(), 1);
            assert_eq!(inp.script_sig, Script::new());
        }
        assert_eq!(pegin_tx.output.len(), 2);
        assert_eq!(pegin_tx.output[0].value, amount);

        // spending user signs
        assert!(pegin.sign_user(&mut user_signer, &mut pegin_utxos, &mut pegin_tx).is_ok());
        
        // cosigner signs
        for cosigner_signer in cosigner_signers.iter_mut() {
            assert!(pegin.sign_cosigner(cosigner_signer, &mut pegin_utxos, &mut pegin_tx).is_ok());
        }
       
        // signatures are all valid
        for i in 0..pegin_tx.input.len() {
            pegin.check_signatures(&pegin_tx, i).unwrap_or_else(|e| panic!("Failed to check signature on input {i}: {e:?}"));
        }

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
        assert!(btc_height < locktime);
        assert!(mined, "transaction not mined");
        m2_debug!("Send peg-in {}", &txid);

        // this transaction is now spendable
        let user_utxos = user_btc_controller.get_all_utxoset(&user_pubkey);
        let pegin_utxos = pegin.get_pegin_utxos(&pegin_tx, 1).unwrap();

        assert_eq!(pegin_utxos.len(), 1, "User has no UTXOs");
        assert!(user_utxos.utxos.iter().find(|utxo| *utxo == &pegin_utxos[0]).is_some(), "user_utxos does not have the pegin UTXO");

        PeginTest {
            user_signer,
            cosigner_signers,
            cosigner_config: config,
            btcd_controller,
            user_btc_controller,
            cosigner_btc_controller,
            pegin
        }
    }
}
