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

use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::types::Address;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::deps_common::bitcoin::blockdata::block::Block as BitcoinBlock;
use stacks_common::deps_common::bitcoin::blockdata::script::Script;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::serialize as btc_serialize;

use crate::cli::bitcoin::BitcoinSegwitMerkleProof;
use crate::devnet::BitcoinCoreController;
use crate::bitcoin::wallet::tests::utils;

pub struct PeginTest {
    user_signer: BitcoinOpSigner,
    cosigner_signers: Vec<BitcoinOpSigner>,
    config: Config,
    user_btc_controller: BitcoinClient,
    pegin: OpPegIn,
    pegin_tx: Transaction,
    seed: Vec<u8>,
    pub proof: Option<BitcoinSegwitMerkleProof>,
}

impl PeginTest {
    pub fn new(user_privkey: Secp256k1PrivateKey, seed: Vec<u8>, num_cosigners: usize, config: &Config) -> Self {
        let mut user_signer = BitcoinOpSigner::new(user_privkey);
        let user_pubkey = user_signer.get_public_key();
        let mut cosigner_signers = vec![];
        let mut cosigner_pubkeys = vec![];
        for i in 0..num_cosigners {
            let mut cosigner_seed = seed.clone();
            cosigner_seed.push(i as u8);
            let mut signer = BitcoinOpSigner::default(cosigner_seed);
            cosigner_pubkeys.push(signer.get_public_key());
            cosigner_signers.push(signer);
        }

        let user_config = config.clone();
        let user_btc_controller = BitcoinClient::new(user_config);

        Self {
            user_signer,
            cosigner_signers,
            config: config.clone(),
            user_btc_controller,
            pegin: OpPegIn::new(false, 100, 100, &user_pubkey, &cosigner_pubkeys, StacksAddress::burn_address(false), 0),
            pegin_tx: Transaction { version: 0, lock_time: 0, input: vec![], output: vec![] },
            seed: seed,
            proof: None,
        }
    }

    pub fn tx(&self) -> &Transaction {
        &self.pegin_tx
    }
    
    pub fn tx_bytes(&self) -> Vec<u8> {
        btc_serialize(&self.pegin_tx).unwrap()
    }

    pub fn get_cosigner_pubkeys(&mut self) -> Vec<Secp256k1PublicKey> {
        self.cosigner_signers
            .iter_mut()
            .map(|signer| signer.get_public_key())
            .collect()
    }

    pub fn get_user_pubkey(&mut self) -> Secp256k1PublicKey {
        self.user_signer.get_public_key()
    }

    pub fn get_user_signer(&mut self) -> &mut BitcoinOpSigner {
        &mut self.user_signer
    }

    pub fn op(&self) -> &OpPegIn {
        &self.pegin
    }
    
    pub fn op_mut(&mut self) -> &mut OpPegIn {
        &mut self.pegin
    }

    pub fn begin(self, locktime: u32, safety_margin: u32, provider: StacksAddress, amount: u64, tx_fee: u64) -> Self {
        self.begin_ex(locktime, safety_margin, provider, amount, tx_fee, true)
    }

    pub fn begin_tx_only(self, locktime: u32, safety_margin: u32, provider: StacksAddress, amount: u64, tx_fee: u64) -> Self {
        self.begin_ex(locktime, safety_margin, provider, amount, tx_fee, false)
    }

    pub fn checked_broadcast(&mut self) {
        // broadcast and confirm this tx
        let user_pubkey = self.user_signer.get_public_key();
        let txid = self.user_btc_controller.send_transaction(&self.pegin_tx).expect("Failed to send transaction");

        // mine it
        let mut btc_height = 103;
        let mut mined = false;
        let mut tx_info = None;
        for _i in 0..100 {
            self.user_btc_controller.bootstrap_chain(1);
            btc_height += 1;
            if let Ok(info) = self.user_btc_controller.get_transaction(&txid) {
                if info.confirmations > 0 {
                    tx_info = Some(info);
                    mined = true;
                    break;
                }
            }
        }

        assert!(btc_height < self.pegin.locktime);
        assert!(mined, "transaction not mined");
        
        let tx_info = tx_info.expect("failed to mine transaction");
        let tx_block = tx_info.block_hash.expect("failed to find block in which pegin was mined");

        m2_debug!("Send peg-in {}", &txid);

        // this transaction is now spendable
        let user_utxos = self.user_btc_controller.get_all_utxoset(&user_pubkey);
        let pegin_utxos = self.pegin.get_pegin_utxos(&self.pegin_tx, 1).unwrap();

        assert_eq!(pegin_utxos.len(), 1, "User has no UTXOs");
        // assert!(user_utxos.utxos.iter().find(|utxo| *utxo == &pegin_utxos[0]).is_some(), "user_utxos does not have the pegin UTXO");

        // get the corresponding block
        let block = self.user_btc_controller.get_block(&tx_block)
            .expect("failed to get corresponding bitcoin block");
        
        // get the corresponding block's height
        let block_stats = self.user_btc_controller.get_block_stats(&tx_block)
            .expect("failed to get corresponding bitcoin block");

        // make the merkle proof
        let proof = BitcoinSegwitMerkleProof::from_block(&txid, &block, block_stats.height as u32).unwrap();
        self.proof = Some(proof);
    }

    pub fn begin_ex(mut self, locktime: u32, safety_margin: u32, provider: StacksAddress, amount: u64, tx_fee: u64, broadcast: bool) -> Self {
        let user_pubkey = self.user_signer.get_public_key();
        let mut user_utxos = self.user_btc_controller.get_all_utxoset(&user_pubkey);

        // instantiate the pegin
        let mut pegin = OpPegIn::new(false, locktime, safety_margin, &user_pubkey, &self.get_cosigner_pubkeys(), provider, amount);

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
        assert!(pegin.sign_user(&mut self.user_signer, &mut pegin_utxos, &mut pegin_tx).is_ok());
        
        // cosigner signs
        for cosigner_signer in self.cosigner_signers.iter_mut() {
            assert!(pegin.sign_cosigner(cosigner_signer, &mut pegin_utxos, &mut pegin_tx).is_ok());
        }
       
        // signatures are all valid
        for i in 0..pegin_tx.input.len() {
            pegin.check_signatures(&pegin_tx, i).unwrap_or_else(|e| panic!("Failed to check signature on input {i}: {e:?}"));
        }

        self.pegin = pegin;
        self.pegin_tx = pegin_tx;

        if broadcast {
            self.checked_broadcast();
        }

        self
    }
}
