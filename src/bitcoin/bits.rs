// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use stacks_common::deps_common::bitcoin::blockdata::opcodes::{All as btc_opcodes, Class};
use stacks_common::deps_common::bitcoin::blockdata::script::{Instruction, Script};
use stacks_common::deps_common::bitcoin::blockdata::transaction::{
    TxIn as BtcTxIn, TxOut as BtcTxOut,
};
#[cfg(test)]
use stacks_common::util::hash::hex_bytes;

use crate::bitcoin::address::{BitcoinAddress, LegacyBitcoinAddressType};
use crate::bitcoin::BitcoinPublicKey;
use crate::bitcoin::{
    BitcoinInputType, BitcoinNetworkType, BitcoinTxInput,
    BitcoinTxOutput
};
use crate::bitcoin::Txid;
use crate::bitcoin::Error;

/// Parse a script into its structured constituant opcodes and data and collect them
pub fn parse_script(script: &Script) -> Vec<Instruction<'_>> {
    // we will have to accept non-minimial pushdata since there's at least one OP_RETURN
    // in the transaction stream that has this property already.
    script.iter(false).collect()
}

impl BitcoinTxInput {
    #[cfg(test)]
    pub fn from_hex_parts(scriptsig: &str, witness: &[&str]) -> Self {
        let witness_bytes: Vec<_> = witness.iter().map(|w| hex_bytes(w).unwrap()).collect();
        Self {
            scriptSig: hex_bytes(scriptsig).unwrap(),
            witness: witness_bytes,
            tx_ref: (Txid([0u8; 32]), 0),
        }
    }

    pub fn from_bitcoin_witness_script_sig(
        script_sig: &Script,
        witness: Vec<Vec<u8>>,
        input_txid: (Txid, u32),
    ) -> Self {
        Self {
            scriptSig: script_sig.clone().into_bytes(),
            witness,
            tx_ref: input_txid,
        }
    }

    /// parse a Bitcoin transaction input into a raw BitcoinTxInput.
    /// Always succeeds
    pub fn from_bitcoin_txin(txin: &BtcTxIn) -> Self {
        Self {
            scriptSig: txin.script_sig.clone().into_bytes(),
            witness: txin.witness.clone(),
            tx_ref: to_txid(txin),
        }
    }

    pub fn tx_ref(&self) -> &(Txid, u32) {
        &self.tx_ref
    }
}

fn to_txid(txin: &BtcTxIn) -> (Txid, u32) {
    // bitcoin-rs library (which stacks_common::deps_common::bitcoin is based on)
    //   operates in a different endian-ness for txids than the rest of
    //   the codebase. so this method reverses the txid bits.
    let mut bits = txin.previous_output.txid.0;
    bits.reverse();
    (Txid(bits), txin.previous_output.vout)
}

impl BitcoinTxOutput {
    /// Parse a BitcoinTxOutput from a Bitcoin scriptpubkey and its value in satoshis.
    /// Only supports legacy (p2pkh, p2sh) addresses.
    /// WARNING: Cannot distinguish between p2sh and segwit-p2sh
    fn from_bitcoin_script_pubkey_legacy(
        network_id: BitcoinNetworkType,
        script_pubkey: &Script,
        amount: u64,
    ) -> Option<BitcoinTxOutput> {
        let script_bytes = script_pubkey.to_bytes();
        let address = if script_pubkey.is_p2pkh() {
            BitcoinAddress::from_bytes_legacy(
                network_id,
                LegacyBitcoinAddressType::PublicKeyHash,
                &script_bytes.get(3..23)?,
            )
        } else if script_pubkey.is_p2sh() {
            BitcoinAddress::from_bytes_legacy(
                network_id,
                LegacyBitcoinAddressType::ScriptHash,
                &script_bytes.get(2..22)?,
            )
        } else {
            Err(Error::InvalidByteSequence)
        };

        match address {
            Ok(addr) => Some(BitcoinTxOutput {
                address: addr,
                units: amount,
            }),
            Err(_e) => None,
        }
    }

    /// Parse a BitcoinTxOutput from a Bitcoin scriptpubkey and its value in satoshis.
    /// Supports segwit (p2wpkh, p2wsh, p2tr) and legacy (p2wpkh, p2sh) addresses.
    /// WARNING: Cannot distinguish between p2sh and segwit-p2sh
    fn from_bitcoin_script_pubkey(
        network_id: BitcoinNetworkType,
        script_pubkey: &Script,
        amount: u64,
    ) -> Option<BitcoinTxOutput> {
        let script_bytes = script_pubkey.to_bytes();
        let address = BitcoinAddress::from_scriptpubkey(network_id, &script_bytes)?;
        Some(BitcoinTxOutput {
            address,
            units: amount,
        })
    }

    /// Parse a bitcoin tx output from a bitcoin output.
    /// Only succeeds if the output is a legacy output.
    pub fn from_bitcoin_txout_legacy(
        network_id: BitcoinNetworkType,
        txout: &BtcTxOut,
    ) -> Option<BitcoinTxOutput> {
        BitcoinTxOutput::from_bitcoin_script_pubkey_legacy(
            network_id,
            &txout.script_pubkey,
            txout.value,
        )
    }

    /// Parse a bitcoin tx output from a bitcoin output.
    /// Output may be a segwit, taproot, or legacy output.
    pub fn from_bitcoin_txout(
        network_id: BitcoinNetworkType,
        txout: &BtcTxOut,
    ) -> Option<BitcoinTxOutput> {
        BitcoinTxOutput::from_bitcoin_script_pubkey(network_id, &txout.script_pubkey, txout.value)
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::deps_common::bitcoin::blockdata::script::{Builder, Script};
    use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
    use stacks_common::deps_common::bitcoin::network::serialize::deserialize as bitcoinlib_deserialize;
    use stacks_common::util::hash::hex_bytes;

    use super::{
        to_txid, BitcoinTxInput, BitcoinTxOutput,
    };
    use crate::bitcoin::address::{
        BitcoinAddress, LegacyBitcoinAddressType, SegwitBitcoinAddress,
    };
    use crate::bitcoin::BitcoinPublicKey;
    use crate::bitcoin::{BitcoinInputType, BitcoinNetworkType};
    use crate::bitcoin::Txid;

    struct ScriptFixture<T> {
        script: Script,
        result: T,
    }

    struct ScriptWitnessFixture<T> {
        script: Script,
        witness: Vec<Vec<u8>>,
        result: T,
    }

    #[test]
    fn tx_input_strange_raw() {
        // all of these should decode
        let tx_fixtures_strange_scriptsig : Vec<ScriptFixture<Option<BitcoinTxInput>>> = vec![
            ScriptFixture {
                // 0-of-0 multisig
                // taken from 970b435253b69cde8207b3245d7723bb24861fd7ab3cfe361f45ae8de085ac52
                script: Builder::from(hex_bytes("00000001ae").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("00000001ae", &[])),
            },
            ScriptFixture {
                // segwit p2sh p2wsh redeem script by itself
                script: Builder::from(hex_bytes("2200200db5e96eaf886fab2f1a20f00528f293e9fc9fb202d2c68c2f57a41eba47b5bf").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("2200200db5e96eaf886fab2f1a20f00528f293e9fc9fb202d2c68c2f57a41eba47b5bf", &[])),
            },
            ScriptFixture {
                // segwit p2sh p2wpkh redeem script by itself
                script: Builder::from(hex_bytes("160014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("160014751e76e8199196d454941c45d1b3a323f1433bd6", &[])),
            },
            ScriptFixture {
                // nonsensical 4-of-3 multisig, wth 2 signatures
                script: Builder::from(hex_bytes("004730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014c69542103310188e911026cf18c3ce274e0ebb5f95b007f230d8cb7d09879d96dbeab1aff210243930746e6ed6552e03359db521b088134652905bd2d1541fa9124303a41e95621029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c7725553ae").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("004730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014c69542103310188e911026cf18c3ce274e0ebb5f95b007f230d8cb7d09879d96dbeab1aff210243930746e6ed6552e03359db521b088134652905bd2d1541fa9124303a41e95621029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c7725553ae", &[])),
            },
            ScriptFixture {
                // nonsensical 4-of-3 multisig, with 3 signatures 
                script: Builder::from(hex_bytes("004730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea01483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e014c69542103310188e911026cf18c3ce274e0ebb5f95b007f230d8cb7d09879d96dbeab1aff210243930746e6ed6552e03359db521b088134652905bd2d1541fa9124303a41e95621029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c7725553ae").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("004730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea01483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e014c69542103310188e911026cf18c3ce274e0ebb5f95b007f230d8cb7d09879d96dbeab1aff210243930746e6ed6552e03359db521b088134652905bd2d1541fa9124303a41e95621029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c7725553ae", &[]))
            },
            ScriptFixture {
                // nonsensical 4-of-3 multisig, with 4 signatures 
                script: Builder::from(hex_bytes("004730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea01483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e01483045022100fd9c04b330810694cb4bfef793b193f9cbfaa07325700f217b9cb03e5207005302202f07e7c9c6774c5619a043752444f6da6fd81b9d9d008ec965796d87271598de014c69542103310188e911026cf18c3ce274e0ebb5f95b007f230d8cb7d09879d96dbeab1aff210243930746e6ed6552e03359db521b088134652905bd2d1541fa9124303a41e95621029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c7725553ae").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("004730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea014730440220338862b4a13d67415fdaac35d408bd2a6d86e4c3be03b7abc92ee769b254dbe1022043ba94f304aff774fdb957af078c9b302425976370cc66f42ae05382c84ea5ea01483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e01483045022100fd9c04b330810694cb4bfef793b193f9cbfaa07325700f217b9cb03e5207005302202f07e7c9c6774c5619a043752444f6da6fd81b9d9d008ec965796d87271598de014c69542103310188e911026cf18c3ce274e0ebb5f95b007f230d8cb7d09879d96dbeab1aff210243930746e6ed6552e03359db521b088134652905bd2d1541fa9124303a41e95621029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c7725553ae", &[])),
            },
            ScriptFixture {
                // pushdata 64-byte 0's
                script: Builder::from(hex_bytes("4e404000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("4e404000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", &[])),
            },
            ScriptFixture {
                // scriptsig from mainnet transaction 09f691b2263260e71f363d1db51ff3100d285956a40cc0e4f8c8c2c4a80559b1
                script: Builder::from(hex_bytes("4c500100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("4c500100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c", &[]))
            },
            ScriptFixture {
                // scriptsig from mainnet transaction 8d31992805518fd62daa3bdd2a5c4fd2cd3054c9b3dca1d78055e9528cff6adc
                script: Builder::from(hex_bytes("4d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a14d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1086e879169a77ca787").unwrap()).into_script(),
                result: Some(BitcoinTxInput::from_hex_parts("4d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a14d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1086e879169a77ca787", &[]))
            }
        ];

        for script_fixture in tx_fixtures_strange_scriptsig {
            let tx_input = BitcoinTxInput::from_bitcoin_witness_script_sig(
                &script_fixture.script,
                vec![],
                (Txid([0; 32]), 0),
            );
            assert_eq!(Some(tx_input), script_fixture.result);
        }
    }

    /// Make sure we can decode taproot scripts with the current vendored version of bitcoin-rs
    #[test]
    fn test_input_taproot() {
        let txs : Vec<(&str, Vec<BitcoinTxInput>, Vec<BitcoinTxOutput>)> = vec![
            // 37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8 on mainnet.
            // "the first transaction with both a P2TR scriptpath and a P2TR keypath input"
            // results obtained from bitcoind
            (
                "020000000001027bc0bba407bc67178f100e352bf6e047fae4cbf960d783586cb5e430b3b700e70000000000feffffff7bc0bba407bc67178f100e352bf6e047fae4cbf960d783586cb5e430b3b700e70100000000feffffff01b4ba0e0000000000160014173fd310e9db2c7e9550ce0f03f1e6c01d833aa90140134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c03407b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca2220f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac41c0d9dfdf0fe3c83e9870095d67fff59a8056dad28c6dfb944bb71cf64b90ace9a7776b22a1185fb2dc9524f6b178e2693189bf01655d7f38f043923668dc5af45bffd30a00",
                vec![
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b").unwrap(), 0)
                    },
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca").unwrap(),
                            hex_bytes("20f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac").unwrap(),
                            hex_bytes("c0d9dfdf0fe3c83e9870095d67fff59a8056dad28c6dfb944bb71cf64b90ace9a7776b22a1185fb2dc9524f6b178e2693189bf01655d7f38f043923668dc5af45b").unwrap(),
                        ],
                        tx_ref: (Txid::from_hex("e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b").unwrap(), 1)
                    }
                ],
                vec![
                    BitcoinTxOutput {
                        address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WPKH(BitcoinNetworkType::Mainnet, [0x17, 0x3f, 0xd3, 0x10, 0xe9, 0xdb, 0x2c, 0x7e, 0x95, 0x50, 0xce, 0x0f, 0x03, 0xf1, 0xe6, 0xc0, 0x1d, 0x83, 0x3a, 0xa9])),
                        units: 965300
                    }
                ]
            ),
            // 33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036 is the first-ever
            // taproot transaction on mainnet.
            (
                "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00",
                vec![
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174a").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("5849051cf3ce36257a1d844e28959f368a35adc9520fb9679175f6cdf8c1f1d1").unwrap(), 1),
                    },
                ],
                vec![
                    // first op-return is omitted by our parser
                    BitcoinTxOutput {
                        address: BitcoinAddress::from_segwit(true, "5120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f9"),
                        units: 67230
                    }
                ]
            ),
            // 83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82 has multiple p2tr
            // keypath inputs
            (
                "020000000001041ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890000000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890100000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890200000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890300000000ffffffff01007ea60000000000225120a457d0c0399b499ed2df571d612ba549ae7f199387edceac175999210f6aa39d0141b23008b3e044d16078fc93ae4f342b6e5ba44241c598503f80269fd66e7ce484e926b2ff58ac5633be79857951b3dc778082fd38a9e06a1139e6eea41a8680c7010141be98ba2a47fce6fbe4f7456e5fe0c2381f38ed3ae3b89d0748fdbfc6936b68019e01ff60343abbea025138e58aed2544dc8d3c0b2ccb35e2073fa2f9feeff5ed010141466d525b97733d4733220694bf747fd6e9d4b0b96ea3b2fb06b7486b4b8e864df0057481a01cf10f7ea06849fb4717d62b902fe5807a1cba03a46bf3a7087e940101418dbfbdd2c164005eceb0de04c317b9cae62b0c97ed33da9dcec6301fa0517939b9024eba99e22098a5b0d86eb7218957883ea9fc13b737e1146ae2b95185fcf90100000000",
                vec![
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("b23008b3e044d16078fc93ae4f342b6e5ba44241c598503f80269fd66e7ce484e926b2ff58ac5633be79857951b3dc778082fd38a9e06a1139e6eea41a8680c701").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e").unwrap(), 0),
                    },
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("be98ba2a47fce6fbe4f7456e5fe0c2381f38ed3ae3b89d0748fdbfc6936b68019e01ff60343abbea025138e58aed2544dc8d3c0b2ccb35e2073fa2f9feeff5ed01").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e").unwrap(), 1),
                    },
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("466d525b97733d4733220694bf747fd6e9d4b0b96ea3b2fb06b7486b4b8e864df0057481a01cf10f7ea06849fb4717d62b902fe5807a1cba03a46bf3a7087e9401").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e").unwrap(), 2),
                    },
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("8dbfbdd2c164005eceb0de04c317b9cae62b0c97ed33da9dcec6301fa0517939b9024eba99e22098a5b0d86eb7218957883ea9fc13b737e1146ae2b95185fcf901").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e").unwrap(), 3),
                    },
                ],
                vec![
                    BitcoinTxOutput {
                        address: BitcoinAddress::from_segwit(true, "5120a457d0c0399b499ed2df571d612ba549ae7f199387edceac175999210f6aa39d"),
                        units: 10911232
                    }
                ]
            ),
            // 905ecdf95a84804b192f4dc221cfed4d77959b81ed66013a7e41a6e61e7ed530
            // scriptpath 2-of-2 multisig
            (
                "02000000000101b41b20295ac85fd2ae3e3d02900f1a1e7ddd6139b12e341386189c03d6f5795b0000000000fdffffff0100000000000000003c6a3a546878205361746f7368692120e2889e2f32316d696c20466972737420546170726f6f74206d756c7469736967207370656e64202d426974476f044123b1d4ff27b16af4b0fcb9672df671701a1a7f5a6bb7352b051f461edbc614aa6068b3e5313a174f90f3d95dc4e06f69bebd9cf5a3098fde034b01e69e8e788901400fd4a0d3f36a1f1074cb15838a48f572dc18d412d0f0f0fc1eeda9fa4820c942abb77e4d1a3c2b99ccf4ad29d9189e6e04a017fe611748464449f681bc38cf394420febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4ad20d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15ac41c02e44c9e47eaeb4bb313adecd11012dfad435cd72ce71f525329f24d75c5b9432774e148e9209baf3f1656a46986d5f38ddf4e20912c6ac28f48d6bf747469fb100000000",
                vec![
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("23b1d4ff27b16af4b0fcb9672df671701a1a7f5a6bb7352b051f461edbc614aa6068b3e5313a174f90f3d95dc4e06f69bebd9cf5a3098fde034b01e69e8e788901").unwrap(),
                            hex_bytes("0fd4a0d3f36a1f1074cb15838a48f572dc18d412d0f0f0fc1eeda9fa4820c942abb77e4d1a3c2b99ccf4ad29d9189e6e04a017fe611748464449f681bc38cf39").unwrap(),
                            hex_bytes("20febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4ad20d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15ac").unwrap(),
                            hex_bytes("c02e44c9e47eaeb4bb313adecd11012dfad435cd72ce71f525329f24d75c5b9432774e148e9209baf3f1656a46986d5f38ddf4e20912c6ac28f48d6bf747469fb1").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("5b79f5d6039c188613342eb13961dd7d1e1a0f90023d3eaed25fc85a29201bb4").unwrap(), 0)
                    },
                ],
                vec![
                    // only contains an OP_RETURN
                ]
            ),
            // 2eb8dbaa346d4be4e82fe444c2f0be00654d8cfd8c4a9a61b11aeaab8c00b272
            // uses OP_CHECKSIGADD
            (
                "010000000001022373cf02ce7df6500ae46a4a0fbbb1b636d2debed8f2df91e2415627397a34090000000000fdffffff88c23d928893cd3509845516cf8411b7cab2738c054cc5ce7e4bde9586997c770000000000fdffffff0200000000000000002b6a29676d20746170726f6f7420f09fa5952068747470733a2f2f626974636f696e6465766b69742e6f72676e9e1100000000001976a91405070d0290da457409a37db2e294c1ffbc52738088ac04410adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000104414636070d21adc8280735383102f7a0f5978cea257777a23934dd3b458b79bf388aca218e39e23533a059da173e402c4fc5e3375e1f839efb22e9a5c2a815b07301004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000100000000",
                vec![
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("0adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01").unwrap(),
                            vec![],
                            hex_bytes("20c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c").unwrap(),
                            hex_bytes("c00000000000000000000000000000000000000000000000000000000000000001").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("09347a39275641e291dff2d8beded236b6b1bb0f4a6ae40a50f67dce02cf7323").unwrap(), 0),
                    },
                    BitcoinTxInput {
                        scriptSig: vec![],
                        witness: vec![
                            hex_bytes("4636070d21adc8280735383102f7a0f5978cea257777a23934dd3b458b79bf388aca218e39e23533a059da173e402c4fc5e3375e1f839efb22e9a5c2a815b07301").unwrap(),
                            vec![],
                            hex_bytes("20c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c").unwrap(),
                            hex_bytes("c00000000000000000000000000000000000000000000000000000000000000001").unwrap()
                        ],
                        tx_ref: (Txid::from_hex("777c998695de4b7ecec54c058c73b2cab71184cf1655840935cd9388923dc288").unwrap(), 0)
                    }
                ],
                vec![
                    // first output is an OP_RETURN
                    BitcoinTxOutput {
                        address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Mainnet, &hex_bytes("76a91405070d0290da457409a37db2e294c1ffbc52738088ac").unwrap()).unwrap(),
                        units: 1154670
                    }
                ]
            )
        ];

        for (tx_str, inputs, outputs) in txs.iter() {
            let tx_bytes = hex_bytes(tx_str).unwrap();
            let tx: Transaction = bitcoinlib_deserialize(&tx_bytes).unwrap();

            assert_eq!(tx.input.len(), inputs.len());
            for (i, txin) in tx.input.iter().enumerate() {
                let raw_in = BitcoinTxInput::from_bitcoin_witness_script_sig(
                    &txin.script_sig,
                    txin.witness.clone(),
                    to_txid(txin),
                );
                assert_eq!(raw_in, inputs[i]);
            }

            let mut j = 0;
            for (_i, txout) in tx.output.iter().enumerate() {
                if txout.script_pubkey.is_op_return() {
                    // our parser doesn't treat op_returns as first-class outputs
                    continue;
                }

                let segwit_out =
                    BitcoinTxOutput::from_bitcoin_txout(BitcoinNetworkType::Mainnet, txout)
                        .unwrap();
                assert_eq!(segwit_out, outputs[j]);
                j += 1;
            }
        }
    }

    #[test]
    fn tx_output_p2pkh() {
        let amount = 123;
        let tx_fixtures_p2pkh = vec![
            ScriptFixture {
                script: Builder::from(
                    hex_bytes("76a914395f3643cea07ec4eec73b4d9a973dcce56b9bf188ac").unwrap(),
                )
                .into_script(),
                result: BitcoinTxOutput {
                    units: amount,
                    address: BitcoinAddress::from_bytes_legacy(
                        BitcoinNetworkType::Mainnet,
                        LegacyBitcoinAddressType::PublicKeyHash,
                        &hex_bytes("395f3643cea07ec4eec73b4d9a973dcce56b9bf1").unwrap(),
                    )
                    .unwrap(),
                },
            },
            ScriptFixture {
                script: Builder::from(
                    hex_bytes("76a914000000000000000000000000000000000000000088ac").unwrap(),
                )
                .into_script(),
                result: BitcoinTxOutput {
                    units: amount,
                    address: BitcoinAddress::from_bytes_legacy(
                        BitcoinNetworkType::Mainnet,
                        LegacyBitcoinAddressType::PublicKeyHash,
                        &hex_bytes("0000000000000000000000000000000000000000").unwrap(),
                    )
                    .unwrap(),
                },
            },
        ];

        for script_fixture in tx_fixtures_p2pkh {
            let tx_output_opt = BitcoinTxOutput::from_bitcoin_script_pubkey_legacy(
                BitcoinNetworkType::Mainnet,
                &script_fixture.script,
                amount,
            );
            assert!(tx_output_opt.is_some());
            assert_eq!(tx_output_opt.unwrap(), script_fixture.result);
        }
    }

    #[test]
    fn tx_output_p2sh() {
        let amount = 123;
        let tx_fixtures_p2sh = vec![
            ScriptFixture {
                script: Builder::from(
                    hex_bytes("a914eb1881fb0682c2eb37e478bf918525a2c61bc40487").unwrap(),
                )
                .into_script(),
                result: BitcoinTxOutput {
                    units: amount,
                    address: BitcoinAddress::from_bytes_legacy(
                        BitcoinNetworkType::Mainnet,
                        LegacyBitcoinAddressType::ScriptHash,
                        &hex_bytes("eb1881fb0682c2eb37e478bf918525a2c61bc404").unwrap(),
                    )
                    .unwrap(),
                },
            },
            ScriptFixture {
                script: Builder::from(
                    hex_bytes("a914000000000000000000000000000000000000000087").unwrap(),
                )
                .into_script(),
                result: BitcoinTxOutput {
                    units: amount,
                    address: BitcoinAddress::from_bytes_legacy(
                        BitcoinNetworkType::Mainnet,
                        LegacyBitcoinAddressType::ScriptHash,
                        &hex_bytes("0000000000000000000000000000000000000000").unwrap(),
                    )
                    .unwrap(),
                },
            },
        ];

        for script_fixture in tx_fixtures_p2sh {
            let tx_output_opt = BitcoinTxOutput::from_bitcoin_script_pubkey_legacy(
                BitcoinNetworkType::Mainnet,
                &script_fixture.script,
                amount,
            );
            assert!(tx_output_opt.is_some());
            assert_eq!(tx_output_opt.unwrap(), script_fixture.result);
        }
    }

    #[test]
    fn tx_output_strange_legacy() {
        let tx_fixtures_strange: Vec<ScriptFixture<Option<BitcoinTxOutput>>> = vec![
            ScriptFixture {
                // script pubkey for segwit p2wpkh
                script: Builder::from(
                    hex_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap(),
                )
                .into_script(),
                result: None,
            },
            ScriptFixture {
                // script pubkey for a segwit p2wsh
                script: Builder::from(
                    hex_bytes(
                        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                    )
                    .unwrap(),
                )
                .into_script(),
                result: None,
            },
        ];

        for script_fixture in tx_fixtures_strange {
            let tx_output_opt = BitcoinTxOutput::from_bitcoin_script_pubkey_legacy(
                BitcoinNetworkType::Mainnet,
                &script_fixture.script,
                123,
            );
            assert!(tx_output_opt.is_none());
        }
    }

    #[test]
    fn tx_output_segwit() {
        let amount = 123;
        let tx_fixtures_segwit: Vec<ScriptFixture<Option<BitcoinTxOutput>>> = vec![
            ScriptFixture {
                // script pubkey for segwit p2wpkh
                script: Builder::from(
                    hex_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap(),
                )
                .into_script(),
                result: Some(BitcoinTxOutput {
                    address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WPKH(
                        BitcoinNetworkType::Mainnet,
                        [
                            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
                            0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                        ],
                    )),
                    units: amount,
                }),
            },
            ScriptFixture {
                // script pubkey for a segwit p2wsh
                script: Builder::from(
                    hex_bytes(
                        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                    )
                    .unwrap(),
                )
                .into_script(),
                result: Some(BitcoinTxOutput {
                    address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(
                        BitcoinNetworkType::Mainnet,
                        [
                            0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19, 0x20,
                            0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
                            0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62,
                        ],
                    )),
                    units: amount,
                }),
            },
            ScriptFixture {
                // script pubkey from a segwit p2tr
                script: Builder::from(
                    hex_bytes(
                        "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0",
                    )
                    .unwrap(),
                )
                .into_script(),
                result: Some(BitcoinTxOutput {
                    address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2TR(
                        BitcoinNetworkType::Mainnet,
                        [
                            0x33, 0x9c, 0xe7, 0xe1, 0x65, 0xe6, 0x7d, 0x93, 0xad, 0xb3, 0xfe, 0xf8,
                            0x8a, 0x6d, 0x4b, 0xee, 0xd3, 0x3f, 0x01, 0xfa, 0x87, 0x6f, 0x05, 0xa2,
                            0x25, 0x24, 0x2b, 0x82, 0xa6, 0x31, 0xab, 0xc0,
                        ],
                    )),
                    units: amount,
                }),
            },
            // NOTE: parsing failures are handled by tests for BitcoinAddress already, so they are
            // not duplicated here.
        ];

        for script_fixture in tx_fixtures_segwit {
            let tx_output_opt = BitcoinTxOutput::from_bitcoin_script_pubkey(
                BitcoinNetworkType::Mainnet,
                &script_fixture.script,
                amount,
            );
            assert_eq!(tx_output_opt, script_fixture.result);
        }
    }
}
