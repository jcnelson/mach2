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

use stacks_common::deps_common::bitcoin::blockdata::block::{Block, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as btc_opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Instruction, Script};
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::blockdata::transaction::OutPoint;
use stacks_common::deps_common::bitcoin::blockdata::transaction::TxOut;
use stacks_common::deps_common::bitcoin::blockdata::transaction::TxIn;
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
use stacks_common::deps_common::bitcoin::util::hash::bitcoin_merkle_root;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::hash::to_hex;
use stacks_common::util::hash::DoubleSha256;

use crate::bitcoin::address::BitcoinAddress;
use crate::bitcoin::{
    bits, BitcoinBlock, BitcoinNetworkType, BitcoinTransaction, BitcoinTxInput, BitcoinTxOutput,
};
use crate::bitcoin::{MagicBytes, MAGIC_BYTES_LENGTH, Txid, Wtxid};

/// Compute a Merkle tree out of leaf hashes, in the Bitcoin style.
/// Intermediate nodes are Sha256dHash.
/// The returned tree is a list of rows, where the topmost row (last item) is a 1-item list
/// containing the root.
pub fn bitcoin_merkle_tree(leaves: &[Sha256dHash]) -> Vec<Vec<Sha256dHash>> {
    let mut tree = vec![leaves.to_vec()];
    let mut last_row = tree.last().expect("infallible");
    while last_row.len() > 1 {
        let iterations = last_row.len().div_ceil(2);
        let mut next_row = Vec::with_capacity(iterations);
        for i in 0..iterations {
            let idx1 = 2 * i;
            let idx2 = (idx1 + 1).min(last_row.len() - 1);
            let mut buff = [0u8; 64];
            buff[0..32].copy_from_slice(&last_row[idx1].0);
            buff[32..64].copy_from_slice(&last_row[idx2].0);
            let h = Sha256dHash::from_data(&buff);
            next_row.push(h);
        }
        tree.push(next_row);
        last_row = tree.last().expect("infallible");
    }
    tree
}

/// Compute a Merkle proof for an item in a list
pub fn bitcoin_merkle_proof(leaves: &[Sha256dHash], tx_index: usize) -> Option<Vec<Sha256dHash>> {
    let tree = bitcoin_merkle_tree(leaves);
    let mut cursor = tx_index;
    let mut proof = vec![];
    for row in tree.iter() {
        if row.len() == 1 {
            break;
        }
        if cursor >= row.len() {
            return None;
        }
        let idx = if cursor % 2 == 1 {
            // SAFETY: cursor > 0
            cursor - 1
        }
        else {
            cursor + 1
        };
        let idx = idx.min(row.len() - 1);
        proof.push(row[idx].clone());
        cursor /= 2;
    }
    Some(proof)
}

pub trait TransactionExtensions {
    fn wtxid(&self) -> Wtxid;
    fn display(&self) -> String;
}

impl TransactionExtensions for Transaction {
    fn wtxid(&self) -> Wtxid {
        if self.is_coin_base() {
            return Wtxid([0x00; 32])
        }
        let bh = self.bitcoin_hash();
        Wtxid(bh.0)
    }

    fn display(&self) -> String {
        #[derive(Debug)]
        struct DisplayTxIn {
            previous_output: OutPoint,
            script_sig: Script,
            sequence: u32,
            witness: Vec<String>
        }

        #[derive(Debug)]
        struct DisplayTransaction {
            version: u32,
            lock_time: u32,
            input: Vec<DisplayTxIn>,
            output: Vec<TxOut>
        }

        impl From<&TxIn> for DisplayTxIn {
            fn from(txin: &TxIn) -> Self {
                Self {
                    previous_output: txin.previous_output.clone(),
                    script_sig: txin.script_sig.clone(),
                    sequence: txin.sequence,
                    witness: txin.witness.iter().map(|w| to_hex(w)).collect()
                }
            }
        }

        impl From<&Transaction> for DisplayTransaction {
            fn from(tx: &Transaction) -> Self {
                Self {
                    version: tx.version,
                    lock_time: tx.lock_time,
                    input: tx.input.iter().map(|inp| DisplayTxIn::from(inp)).collect(),
                    output: tx.output.clone()
                }
            }
        }
               
        format!("{:#?}", DisplayTransaction::from(self))
    }
}

pub trait BlockExtensions {
    fn compute_witness_merkle_root(&self) -> Sha256dHash;
    fn compute_merkle_root(&self) -> Sha256dHash;
    fn compute_witness_merkle_proof(&self, tx_index: usize) -> Option<Vec<Sha256dHash>>;
    fn compute_merkle_proof(&self, tx_index: usize) -> Option<Vec<Sha256dHash>>;
    fn get_witness_commitment(&self) -> Option<Sha256dHash>;
    fn get_witness_reserved(&self) -> Option<Sha256dHash>;
    fn get_witness_coinbase(&self) -> Option<&Transaction>;

    fn is_segwit_block(&self) -> bool {
        self.get_witness_commitment().is_some()
    }

    fn get_coinbase(&self) -> Option<Transaction> {
        let Some(cb) = self.get_witness_coinbase() else {
            return None;
        };
        let mut coinbase = cb.clone();

        for input in coinbase.input.iter_mut() {
            (*input).witness = vec![];
        }
        Some(coinbase)
    }
}

impl BlockExtensions for Block {
    fn compute_witness_merkle_root(&self) -> Sha256dHash {
        let mut wtxids : Vec<_> = self.txdata.iter().map(|tx| Sha256dHash(tx.wtxid().0)).collect();
        
        // coinbase wtxid is always 0x0000...0000
        if wtxids.len() > 0 {
            wtxids[0] = Sha256dHash([0x00; 32]);
        }
        bitcoin_merkle_root(wtxids).to_bitcoin_hash()
    }

    fn compute_merkle_root(&self) -> Sha256dHash {
        let txids : Vec<_> = self.txdata.iter().map(|tx| Sha256dHash(tx.txid().0)).collect();
        bitcoin_merkle_root(txids)
    }

    fn compute_witness_merkle_proof(&self, tx_index: usize) -> Option<Vec<Sha256dHash>> {
        let mut wtxids : Vec<_> = self.txdata.iter().map(|tx| Sha256dHash(tx.wtxid().0)).collect();
        
        // coinbase wtxid is always 0x0000...0000
        if wtxids.len() > 0 {
            wtxids[0] = Sha256dHash([0x00; 32]);
        }
        Some(bitcoin_merkle_proof(&wtxids, tx_index)?
            .into_iter()
            .map(|h| h.to_bitcoin_hash())
            .collect())
    }
    
    fn compute_merkle_proof(&self, tx_index: usize) -> Option<Vec<Sha256dHash>> {
        let txids : Vec<_> = self.txdata.iter().map(|tx| Sha256dHash(tx.txid().0)).collect();
        Some(bitcoin_merkle_proof(&txids, tx_index)?
            .into_iter()
            .map(|h| h.to_bitcoin_hash())
            .collect())
    }

    fn get_witness_commitment(&self) -> Option<Sha256dHash> {
        let Some(coinbase) = self.get_coinbase() else {
            return None;
        };
        // NOTE: per BIP-141, the highest matching null output is the one to use
        for coin_out in coinbase.output.iter().rev() {
            let coin_script_pubkey = coin_out.script_pubkey.as_bytes();
            if coin_script_pubkey.len() < 38 {
                continue;
            }
            let Some(coin_script_prefix) = coin_script_pubkey.get(0..6) else {
                continue;
            };
            if coin_script_prefix != &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed] {
                continue;
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&coin_script_pubkey[6..38]);
            return Some(Sha256dHash(bytes));
        }
        None
    }

    fn get_witness_reserved(&self) -> Option<Sha256dHash> {
        let Some(coinbase) = self.get_witness_coinbase() else {
            return None;
        };
        let Some(coin_input) = coinbase.input.get(0) else {
            return None;
        };
        if coin_input.witness.len() != 1 {
            return None;
        }
        let Some(coin_witness) = coin_input.witness.get(0) else {
            return None;
        };
        if coin_witness.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&coin_witness[0..32]);
        Some(Sha256dHash(bytes))
    }

    fn get_witness_coinbase(&self) -> Option<&Transaction> {
        let Some(coinbase) = self.txdata.get(0) else {
            return None;
        };
        if !coinbase.is_coin_base() {
            return None;
        }
        Some(coinbase)
    }
}

pub trait BitcoinHashExtensions {
    fn to_bitcoin_hash(&self) -> Self;
}

impl BitcoinHashExtensions for Sha256dHash {
    fn to_bitcoin_hash(&self) -> Self {
        let mut bytes = self.0.clone();
        bytes.reverse();
        Self(bytes)
    }
}

impl BitcoinHashExtensions for DoubleSha256 {
    fn to_bitcoin_hash(&self) -> Self {
        let mut bytes = self.0.clone();
        bytes.reverse();
        Self(bytes)
    }
}

pub struct BitcoinBlockParser {
    network_id: BitcoinNetworkType,
    magic_bytes: MagicBytes,
}

impl BitcoinBlockParser {
    /// New block parser
    pub fn new(network_id: BitcoinNetworkType, magic_bytes: MagicBytes) -> BitcoinBlockParser {
        BitcoinBlockParser {
            network_id,
            magic_bytes,
        }
    }

    /// Verify that a block matches a header
    pub fn check_block(block: &Block, header: &LoneBlockHeader) -> bool {
        if header.header.bitcoin_hash() != block.bitcoin_hash() {
            return false;
        }

        // block transactions must match header merkle root
        let tx_merkle_root = bitcoin_merkle_root(block.txdata.iter().map(|tx| tx.txid()).collect());

        if block.header.merkle_root != tx_merkle_root {
            return false;
        }

        true
    }

    /// Parse the data output to get a byte payload
    fn parse_data(&self, data_output: &Script) -> Option<(u8, Vec<u8>)> {
        if !data_output.is_op_return() {
            m2_test_debug!("Data output is not an OP_RETURN");
            return None;
        }

        if data_output.len() <= self.magic_bytes.len() {
            m2_test_debug!("Data output is too short to carry an operation");
            return None;
        }

        let script_pieces = bits::parse_script(data_output);
        if script_pieces.len() != 2 {
            // not OP_RETURN <data>
            m2_test_debug!("Data output does not encode a valid OP_RETURN");
            return None;
        }

        match (script_pieces.get(0)?, script_pieces.get(1)?) {
            (Instruction::Op(ref opcode), Instruction::PushBytes(data)) => {
                if *opcode != btc_opcodes::OP_RETURN {
                    m2_test_debug!("Data output does not use a standard OP_RETURN");
                    return None;
                }
                if data.len() <= MAGIC_BYTES_LENGTH {
                    return None;
                }
                if !data.starts_with(self.magic_bytes.as_bytes()) {
                    m2_test_debug!("Data output does not start with magic bytes");
                    return None;
                }

                let opcode = *data.get(MAGIC_BYTES_LENGTH)?;
                let data = data.get(MAGIC_BYTES_LENGTH + 1..)?.to_vec();
                Some((opcode, data))
            }
            (_, _) => {
                m2_test_debug!("Data output is not OP_RETURN <data>");
                None
            }
        }
    }

    /// Is this an acceptable transaction?  It must have
    /// * an OP_RETURN output at output 0
    /// * only supported outputs 1...n
    fn maybe_mach2_tx(&self, tx: &Transaction) -> bool {
        let Some(output_0) = tx.output.get(0) else {
            return false;
        };
        if self.parse_data(&output_0.script_pubkey).is_none() {
            m2_test_debug!("Tx {:?} has no valid OP_RETURN", tx.txid());
            return false;
        }

        for (j, tx_output) in tx.output.iter().skip(1).enumerate() {
            let _i = j.saturating_add(1);
            if BitcoinAddress::from_scriptpubkey(
                BitcoinNetworkType::Mainnet,
                &tx_output.script_pubkey.to_bytes(),
            )
            .is_none()
            {
                m2_test_debug!(
                    "Tx {:?} has unrecognized output type in output {}",
                    tx.txid(),
                    _i
                );
                return false;
            }
        }

        return true;
    }

    /// Parse a transaction's inputs into bitcoin tx inputs.
    fn parse_inputs(tx: &Transaction) -> Vec<BitcoinTxInput> {
        let mut ret = vec![];
        for inp in &tx.input {
            ret.push(BitcoinTxInput::from_bitcoin_txin(inp));
        }
        ret
    }

    /// Parse a transaction's outputs into burnchain tx outputs.
    /// Does not parse the first output -- this is the OP_RETURN
    fn parse_outputs(
        &self,
        tx: &Transaction,
    ) -> Option<Vec<BitcoinTxOutput>> {
        if tx.output.is_empty() {
            return None;
        }

        let mut ret = vec![];
        for outp in tx.output.iter().skip(1) {
            let out_opt = BitcoinTxOutput::from_bitcoin_txout(self.network_id, outp);
            match out_opt {
                None => {
                    m2_test_debug!("Failed to parse output");
                    return None;
                }
                Some(o) => {
                    ret.push(o);
                }
            };
        }
        Some(ret)
    }

    /// Parse a Bitcoin transaction into a Burnchain transaction.
    /// The scriptSigs will not be decoded.
    pub fn parse_tx(
        &self,
        tx: &Transaction,
        vtxindex: usize,
    ) -> Option<BitcoinTransaction> {
        if !self.maybe_mach2_tx(tx) {
            m2_test_debug!("Not a burnchain tx");
            return None;
        }

        let Some((opcode, data)) = self.parse_data(&tx.output.get(0)?.script_pubkey) else {
            m2_test_debug!("No OP_RETURN script");
            return None;
        };

        let data_amt = tx.output.get(0)?.value;

        let inputs = BitcoinBlockParser::parse_inputs(tx);
        let outputs_opt = self.parse_outputs(tx);

        match outputs_opt {
            Some(outputs) => {
                Some(BitcoinTransaction {
                    txid: Txid::from_vec_be(tx.txid().as_bytes()).unwrap(), // this *should* panic if it fails
                    wtxid: Wtxid::from_vec_be(tx.wtxid().as_bytes()).unwrap(), // this *should* panic if it fails
                    vtxindex: vtxindex as u32,
                    opcode,
                    data,
                    data_amt,
                    inputs,
                    outputs,
                })
            }
            None => {
                m2_test_debug!("Failed to parse outputs");
                None
            }
        }
    }

    /// Given a Bitcoin block, extract the transactions that have OP_RETURN <magic>.
    /// Uses the internal epoch id to determine whether or not to parse segwit outputs, and whether
    /// or not to decode scriptSigs.
    pub fn parse_block(
        &self,
        block: &Block,
        block_height: u64,
    ) -> BitcoinBlock {
        let mut accepted_txs = vec![];
        for (i, tx) in block.txdata.iter().enumerate() {
            match self.parse_tx(tx, i) {
                Some(bitcoin_tx) => {
                    accepted_txs.push(bitcoin_tx);
                }
                None => {
                    continue;
                }
            }
        }

        BitcoinBlock {
            block_height,
            block_hash: BurnchainHeaderHash::from_bitcoin_hash(&block.bitcoin_hash()),
            parent_block_hash: BurnchainHeaderHash::from_bitcoin_hash(&block.header.prev_blockhash),
            txs: accepted_txs,
            timestamp: block.header.time as u64,
        }
    }

    /// Return true if we handled the block, and we can receive the next one.  Update internal
    /// state, extract the BitcoinTransactions we care about
    ///
    /// Return false if the block we got did not match the next expected block's header
    /// (in which case, we should re-start the conversation with the peer and try again).
    pub fn process_block(
        &self,
        block: &Block,
        header: &LoneBlockHeader,
        height: u64,
    ) -> Option<BitcoinBlock> {
        // block header contents must match
        if !BitcoinBlockParser::check_block(block, header) {
            m2_error!(
                "Expected block {} does not match received block {}",
                header.header.bitcoin_hash(),
                block.bitcoin_hash()
            );
            return None;
        }

        // parse it
        let burn_block = self.parse_block(block, height);
        Some(burn_block)
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::deps_common::bitcoin::blockdata::block::{Block, LoneBlockHeader};
    use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
    use stacks_common::deps_common::bitcoin::network::encodable::VarInt;
    use stacks_common::deps_common::bitcoin::network::serialize::deserialize;
    use stacks_common::deps_common::bitcoin::network::serialize::serialize;
    use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
    use stacks_common::types::chainstate::BurnchainHeaderHash;
    use stacks_common::types::Address;
    use stacks_common::util::hash::hex_bytes;
    use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
    use stacks_common::util::hash::to_hex;

    use crate::bitcoin::blocks::BlockExtensions;
    use crate::bitcoin::blocks::TransactionExtensions;
    use crate::bitcoin::blocks::BitcoinHashExtensions;

    use super::BitcoinBlockParser;
    use crate::bitcoin::address::{BitcoinAddress, LegacyBitcoinAddressType};
    use crate::bitcoin::BitcoinPublicKey;
    use crate::bitcoin::{
        BitcoinBlock, BitcoinInputType, BitcoinNetworkType, BitcoinTransaction, BitcoinTxInput,
        BitcoinTxOutput,
    };
    use crate::bitcoin::{MagicBytes, Txid, Wtxid};
    use crate::bitcoin::blocks::bitcoin_merkle_tree;

    use crate::util::vm::vm_execute;

    use clarity::vm::ClarityVersion;

    struct TxFixture {
        txstr: String,
        result: Option<BitcoinTransaction>,
    }

    struct TxParseFixture {
        txstr: String,
        result: bool,
    }

    struct BlockFixture {
        block: String,
        header: String,
        height: u64,
        result: Option<BitcoinBlock>,
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex")?;
        let tx = deserialize(&tx_bin.to_vec()).map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    fn make_block(hex_str: &str) -> Result<Block, &'static str> {
        let block_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex")?;
        let block = deserialize(&block_bin.to_vec()).map_err(|_e| "failed to deserialize block")?;
        Ok(block)
    }

    fn make_block_header(hex_str: &str) -> Result<LoneBlockHeader, &'static str> {
        let header_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex")?;
        let header =
            deserialize(&header_bin.to_vec()).map_err(|_e| "failed to deserialize header")?;
        Ok(LoneBlockHeader {
            header,
            tx_count: VarInt(0),
        })
    }

    fn to_txid(inp: &[u8]) -> Txid {
        let mut ret = [0; 32];
        let bytes = &inp[..inp.len()];
        ret.copy_from_slice(bytes);
        Txid(ret)
    }

    fn to_wtxid(inp: &[u8]) -> Wtxid {
        let mut ret = [0; 32];
        let bytes = &inp[..inp.len()];
        ret.copy_from_slice(bytes);
        Wtxid(ret)
    }

    fn to_block_hash(inp: &[u8]) -> BurnchainHeaderHash {
        let mut ret = [0; 32];
        let bytes = &inp[..inp.len()];
        ret.copy_from_slice(bytes);
        BurnchainHeaderHash(ret)
    }

    #[test]
    fn test_maybe_mach2_tx() {
        let tx_fixtures = vec![
            TxParseFixture {
                // valid
                txstr: "010000000320a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542020000008b483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542010000008b483045022100fd9c04b330810694cb4bfef793b193f9cbfaa07325700f217b9cb03e5207005302202f07e7c9c6774c5619a043752444f6da6fd81b9d9d008ec965796d87271598de0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542040000008a47304402205e24943a40b8ef876cc218a7e8994f4be7afb7aa02403bb73510fac01b33ead3022033e5fb811c396b2fb50a825cd1d86e82eb83483901a1793d0eb15e3e9f1d1c5b814104c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0bebc8ce28d61aa86b414aa91ecb29823b11aeed06098fcd97fee4bc73d54b1e96feffffff030000000000000000296a2769642bfae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe6c6b0000000000001976a914395f3643cea07ec4eec73b4d9a973dcce56b9bf188acc5120100000000001976a9149f2660e75380675206b6f1e2b4f106ae33266be488ac00000000".to_owned(),
                result: true
            },
            TxParseFixture {
                // invalid magic
                txstr: "0100000001d8b97932f097b9fbf0c7584f29515862911ac830826fdfd72d06402c21543e38000000006a47304402202801bc5d11eefddc586b1171bf607cc2be1c661d22e215153f2630316f973a200220628cc08858bba3f0cda661dbef2f007e48f8cb531edc0b54edb573226816f253012103d6967618e0159c9bfcd03ea33d368c8b2a98af5a054364c6b5e7215d7d809169ffffffff030000000000000000356a336469240efa29f955c6ae3bb5037039d89dba5e00000000000000000000000000535441434b5300000000000003e854455354217c150000000000001976a914cfd25e09f2d33e1aec73bfcc5b608ec513bbe6c088ac34460200000000001976a9144cb912533a6935880df7647fd5232e40aca07b8088ac00000000".to_owned(),
                result: false
            },
            TxParseFixture {
                // no OP_RETURN 
                txstr: "0200000003620f7bc1087b0111f76978ef747001e3ae0a12f254cbfb858f028f891c40e5f6010000006a47304402207f5dfc2f7f7329b7cc731df605c83aa6f48ec2218495324bb4ab43376f313b840220020c769655e4bfcc54e55104f6adc723867d9d819266d27e755e098f646f689d0121038c2d1cbe4d731c69e67d16c52682e01cb70b046ead63e90bf793f52f541dafbdfefffffff15fe7d9e0815853738ce47deadee69339e027a1dfcfb6fa887cce3a72626e7b010000006a47304402203202e6c640c063989623fc782ac1c9dc3c6fcaed996d852ec876749ba63db63b02207ef86e262ad4b4bc9cebfadb609f52c35b0105e15d58a5ecbecc5e536d3a8cd8012103dc526ca188418ab128d998bf80942d66f1b3be585d0c89bd61c533bddbdaa729feffffff84e6431db86833897bab333d844486c183dd01e69862edea442e480c2d8cb549010000006a47304402200320bc83f35ceab4a7ef0f8181eedb5f54e3f617626826cc49c8c86efc9be0b302203705889d6aed50f716b81b0f3f5769d72d1b8a6b59d1b0b73bcf94245c283b8001210263591c21ce8ee0d96a617108d7c278e2e715ac6d8afd3fcd158bee472c590068feffffff02ca780a00000000001976a914811fb695e46e2386501bcd70e5c869fe6c0bb33988ac10f59600000000001976a9140f2408a811f6d24ab1833924d98d884c44ecee8888ac6fce0700".to_owned(),
                result: false
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, MagicBytes([105, 100])); // "id"
        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let res = parser.maybe_mach2_tx(&tx);
            assert_eq!(res, tx_fixture.result);
        }
    }

    /// Parse transactions
    #[test]
    fn test_parse_tx() {
        let vtxindex = 4;
        let tx_fixtures = vec![
            TxFixture {
                // NAME_UPDATE transaction with 3 singlesig inputs
                txstr: "010000000320a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542020000008b483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542010000008b483045022100fd9c04b330810694cb4bfef793b193f9cbfaa07325700f217b9cb03e5207005302202f07e7c9c6774c5619a043752444f6da6fd81b9d9d008ec965796d87271598de0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542040000008a47304402205e24943a40b8ef876cc218a7e8994f4be7afb7aa02403bb73510fac01b33ead3022033e5fb811c396b2fb50a825cd1d86e82eb83483901a1793d0eb15e3e9f1d1c5b814104c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0bebc8ce28d61aa86b414aa91ecb29823b11aeed06098fcd97fee4bc73d54b1e96feffffff030000000000000000296a2769642bfae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe6c6b0000000000001976a914395f3643cea07ec4eec73b4d9a973dcce56b9bf188acc5120100000000001976a9149f2660e75380675206b6f1e2b4f106ae33266be488ac00000000".to_owned(),
                result: Some(BitcoinTransaction {
                    data_amt: 0,
                    txid: to_txid(&hex_bytes("185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1").unwrap()),
                    wtxid: to_wtxid(&hex_bytes("185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1").unwrap()),
                    vtxindex,
                    opcode: b'+',
                    data: hex_bytes("fae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe").unwrap(),
                    inputs: vec![
                        BitcoinTxInput {
                            scriptSig: hex_bytes("483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                            witness: vec![],
                            tx_ref: (Txid::from_hex("420577d5f81b5430badcb64cd71e417842c89dd263f845199c0da8d1bc81a020").unwrap(), 2),
                        }.into(),
                        BitcoinTxInput {
                            scriptSig: hex_bytes("483045022100fd9c04b330810694cb4bfef793b193f9cbfaa07325700f217b9cb03e5207005302202f07e7c9c6774c5619a043752444f6da6fd81b9d9d008ec965796d87271598de0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                            witness: vec![],
                            tx_ref: (Txid::from_hex("420577d5f81b5430badcb64cd71e417842c89dd263f845199c0da8d1bc81a020").unwrap(), 1),
                        }.into(),
                        BitcoinTxInput {
                            scriptSig: hex_bytes("47304402205e24943a40b8ef876cc218a7e8994f4be7afb7aa02403bb73510fac01b33ead3022033e5fb811c396b2fb50a825cd1d86e82eb83483901a1793d0eb15e3e9f1d1c5b814104c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0bebc8ce28d61aa86b414aa91ecb29823b11aeed06098fcd97fee4bc73d54b1e96").unwrap(),
                            witness: vec![],
                            tx_ref: (Txid::from_hex("420577d5f81b5430badcb64cd71e417842c89dd263f845199c0da8d1bc81a020").unwrap(), 4),
                        }.into()
                    ],
                    outputs: vec![
                        BitcoinTxOutput {
                            units: 27500,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("395f3643cea07ec4eec73b4d9a973dcce56b9bf1").unwrap()).unwrap()
                        },
                        BitcoinTxOutput {
                            units: 70341,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("9f2660e75380675206b6f1e2b4f106ae33266be4").unwrap()).unwrap()
                        }
                    ]
                })
            },
            TxFixture {
                // NAME_REVOKE with 2 2-of-3 multisig inputs
                txstr: "0100000002b4c2c2fede361654f0f6b65dd8ba385f3a4b05c76cd573f3689b09b7298b142201000000fd5c010047304402203537b5ded3716553b6f3fc7ccc7e55bc42b6caa1c069c9b2ce068d57f9024de7022026eb81e226b0de30448732835424eef52a3b9d67020c62b48df75974c5fe09870147304402201cc22e43302688d975df3bcad70065c8dad497b092a58e97c6c306b65176c70802200b9c3a62b22865e957331578d6e5d684cad87279fd8b852fcc2d34d3911e8643014cc9524104ff897d48c25c48c598aea0d6b1e835008e6679bddbc8d41d7d9f73e6a0dc2b8fe1402487ce2ba1e5365ee28fed024093499c11b8485fb6758a357c75730557674104f9478048ce8ff9cfc188a184c8c8c0a3e3dee68f96f6c3bc6f0f7e043ca8d241d5a03ab50157422ad43e9ee1a0a80b0dd17f0b0023f891dbd85daa3069554e2b41046fd8c7330fbe307a0fad0bf9472ca080f4941f4b6edea7ab090e3e26075e7277a0bd61f42eff54daf3e6141de46a98a5a8265c9e8d58bd1a86cf36d418788ab853aeffffffffb4c2c2fede361654f0f6b65dd8ba385f3a4b05c76cd573f3689b09b7298b142202000000fd5d0100473044022070cfd1e13d9844db995111ed5cc0578ca4d03504fdec1cf1636cd0054dffeeed022046c8d87291367402f4b54c2ef985a0171e400fe079da5234c912103cf2dd683b0148304502210099f092b12000dc78074934135443656091c606b40c7925bae30a6285946e36b9022062b5fa5e28986e0c27aad11f8fdb1409eb87a169972dc1ebbd91aa45810f9d9a014cc95241046097f22211c1f4832e54f0cc76c06b80a4e1fcf237ea487561c80bd5b28b6a483706a04d99038cb434eee82306902193e7b1a368dba33ad14b3f30e004c95e6e41048e264f76559020fdf50d3a7d9f57ccd548f3dfb962837f958e446add48429951d61e99a109cded2ba9812ee152ebba53a2a6c7b6dfb3c61fcba1b0852928374941044c9f30b4546c1f30087001fa6450e52c645bd49e91a18c9c16965b72f5153f0e4b04712218b42b2bc578017b471beaa7d8c0a9eb69174ad50714d7ef4117863d53aeffffffff030000000000000000176a1569647e7061747269636b7374616e6c6579322e6964f82a00000000000017a914eb1881fb0682c2eb37e478bf918525a2c61bc404876dbd13000000000017a914c26afc6cb80ca477c280780902b40cbef8cd804d8700000000".to_owned(),
                result: Some(BitcoinTransaction {
                    data_amt: 0,
                    txid: to_txid(&hex_bytes("eb2e84a45cf411e528185a98cd5fb45ed349843a83d39fd4dff2de47adad8c8f").unwrap()),
                    wtxid: to_wtxid(&hex_bytes("eb2e84a45cf411e528185a98cd5fb45ed349843a83d39fd4dff2de47adad8c8f").unwrap()),
                    vtxindex,
                    opcode: b'~',
                    data: hex_bytes("7061747269636b7374616e6c6579322e6964").unwrap(),
                    inputs: vec![
                        BitcoinTxInput {
                            scriptSig: hex_bytes("0047304402203537b5ded3716553b6f3fc7ccc7e55bc42b6caa1c069c9b2ce068d57f9024de7022026eb81e226b0de30448732835424eef52a3b9d67020c62b48df75974c5fe09870147304402201cc22e43302688d975df3bcad70065c8dad497b092a58e97c6c306b65176c70802200b9c3a62b22865e957331578d6e5d684cad87279fd8b852fcc2d34d3911e8643014cc9524104ff897d48c25c48c598aea0d6b1e835008e6679bddbc8d41d7d9f73e6a0dc2b8fe1402487ce2ba1e5365ee28fed024093499c11b8485fb6758a357c75730557674104f9478048ce8ff9cfc188a184c8c8c0a3e3dee68f96f6c3bc6f0f7e043ca8d241d5a03ab50157422ad43e9ee1a0a80b0dd17f0b0023f891dbd85daa3069554e2b41046fd8c7330fbe307a0fad0bf9472ca080f4941f4b6edea7ab090e3e26075e7277a0bd61f42eff54daf3e6141de46a98a5a8265c9e8d58bd1a86cf36d418788ab853ae").unwrap(),
                            witness: vec![],
                            tx_ref: (Txid::from_hex("22148b29b7099b68f373d56cc7054b3a5f38bad85db6f6f0541636defec2c2b4").unwrap(), 1),
                        }.into(),
                        BitcoinTxInput {
                            scriptSig: hex_bytes("00473044022070cfd1e13d9844db995111ed5cc0578ca4d03504fdec1cf1636cd0054dffeeed022046c8d87291367402f4b54c2ef985a0171e400fe079da5234c912103cf2dd683b0148304502210099f092b12000dc78074934135443656091c606b40c7925bae30a6285946e36b9022062b5fa5e28986e0c27aad11f8fdb1409eb87a169972dc1ebbd91aa45810f9d9a014cc95241046097f22211c1f4832e54f0cc76c06b80a4e1fcf237ea487561c80bd5b28b6a483706a04d99038cb434eee82306902193e7b1a368dba33ad14b3f30e004c95e6e41048e264f76559020fdf50d3a7d9f57ccd548f3dfb962837f958e446add48429951d61e99a109cded2ba9812ee152ebba53a2a6c7b6dfb3c61fcba1b0852928374941044c9f30b4546c1f30087001fa6450e52c645bd49e91a18c9c16965b72f5153f0e4b04712218b42b2bc578017b471beaa7d8c0a9eb69174ad50714d7ef4117863d53ae").unwrap(),
                            witness: vec![],
                            tx_ref: (Txid::from_hex("22148b29b7099b68f373d56cc7054b3a5f38bad85db6f6f0541636defec2c2b4").unwrap(), 2),
                        }.into(),
                    ],
                    outputs: vec![
                        BitcoinTxOutput {
                            units: 11000,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::ScriptHash, &hex_bytes("eb1881fb0682c2eb37e478bf918525a2c61bc404").unwrap()).unwrap()
                        },
                        BitcoinTxOutput {
                            units: 1293677,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::ScriptHash, &hex_bytes("c26afc6cb80ca477c280780902b40cbef8cd804d").unwrap()).unwrap()
                        }
                    ]
                })
            },
            TxFixture {
                // NAME_REGISTRATION with p2wpkh-p2sh segwit input
                txstr: "01000000000101a7ef2b09722ad786c569c0812005a731ce19290bb0a2afc16cb91056c2e4c19e0100000017160014393ffec4f09b38895b8502377693f23c6ae00f19ffffffff0300000000000000000d6a0b69643a666f6f2e746573747c1500000000000017a9144b85301ba8e42bf98472b8ed4939d5f76b98fcea87144d9c290100000017a91431f8968eb1730c83fb58409a9a560a0a0835027f8702483045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b012102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e8100000000".to_owned(),
                result: Some(BitcoinTransaction {
                    data_amt: 0,
                    txid: to_txid(&hex_bytes("b908952b30ccfdfa59985dc1ffdd2a22ef054d20fa253510d2af7797dddee459").unwrap()),
                    wtxid: to_wtxid(&hex_bytes("d4b4292f08ac1f66a7a470c4d8d3f5c5096fce1048638233858416566c483d83").unwrap()),
                    vtxindex,
                    opcode: b':',
                    data: hex_bytes("666f6f2e74657374").unwrap(),
                    inputs: vec![
                        BitcoinTxInput {
                            scriptSig: hex_bytes("160014393ffec4f09b38895b8502377693f23c6ae00f19").unwrap(),
                            witness: vec![
                                hex_bytes("3045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b01").unwrap(),
                                hex_bytes("02d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e81").unwrap()
                            ],
                            tx_ref: (Txid::from_hex("9ec1e4c25610b96cc1afa2b00b2919ce31a7052081c069c586d72a72092befa7").unwrap(), 1),
                        }.into(),
                    ],
                    outputs: vec![
                        BitcoinTxOutput {
                            units: 5500,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::ScriptHash, &hex_bytes("4b85301ba8e42bf98472b8ed4939d5f76b98fcea").unwrap()).unwrap()
                        },
                        BitcoinTxOutput {
                            units: 4993076500,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::ScriptHash, &hex_bytes("31f8968eb1730c83fb58409a9a560a0a0835027f").unwrap()).unwrap()
                        }
                    ]
                })
            },
            TxFixture {
                // NAME_PREORDER with a 2-of-3 p2wsh-p2sh multisig segwit input 
                txstr: "01000000000101e411dc967b8503a27450c614a5cd984698762a6b4bf547293ffdf846ed4ebd22010000002322002067091a41e9871c5ae20b0c69a786f02df5d3c7aa632689b608069181b43a28a2ffffffff030000000000000000296a2769643f9fab7f294936ddb6524a48feff691ecbd0ca9e8f107d845c417a5438d1cb441e827c5126b01ba0290100000017a91487a0487869af70b6b1cc79bd374b75ba1be5cff98700a86100000000001976a914000000000000000000000000000000000000000088ac0400473044022064c5b5f61baad8bb8ecad98666b99e09f1777ef805df41a1c7926f8468b6b6df02205eac177c77f274acb670cd24d504f01b27de767e0241c818c91e479cb0ddcf18014730440220053ce777bc7bb842d8eef83769a027797567624ab9eed5722889ed3192f431b30220256e8aaef8de2a571198acde708fcbca02fb18780ac470c0d7f811734af729af0169522102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e812102f21b29694df4c2188bee97103d10d017d1865fb40528f25589af9db6e0786b6521028791dc45c049107fb99e673265a38a096536aacdf78aa90710a32fff7750f9f953ae00000000".to_owned(),
                result: Some(BitcoinTransaction {
                    data_amt: 0,
                    txid: to_txid(&hex_bytes("16751ca54407b922e3072830cf4be58c5562a6dc350f6703192b673c4cc86182").unwrap()),
                    wtxid: to_wtxid(&hex_bytes("a2cc51fd2f9601d36ac72131fbf3c42a73436b9c6d399540788b550c3e1ed384").unwrap()),
                    vtxindex,
                    opcode: b'?',
                    data: hex_bytes("9fab7f294936ddb6524a48feff691ecbd0ca9e8f107d845c417a5438d1cb441e827c5126").unwrap(),
                    inputs: vec![
                        BitcoinTxInput {
                            scriptSig: hex_bytes("22002067091a41e9871c5ae20b0c69a786f02df5d3c7aa632689b608069181b43a28a2").unwrap(),
                            witness: vec![
                                vec![],
                                hex_bytes("3044022064c5b5f61baad8bb8ecad98666b99e09f1777ef805df41a1c7926f8468b6b6df02205eac177c77f274acb670cd24d504f01b27de767e0241c818c91e479cb0ddcf1801").unwrap(),
                                hex_bytes("30440220053ce777bc7bb842d8eef83769a027797567624ab9eed5722889ed3192f431b30220256e8aaef8de2a571198acde708fcbca02fb18780ac470c0d7f811734af729af01").unwrap(),
                                hex_bytes("522102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e812102f21b29694df4c2188bee97103d10d017d1865fb40528f25589af9db6e0786b6521028791dc45c049107fb99e673265a38a096536aacdf78aa90710a32fff7750f9f953ae").unwrap()
                            ],
                            tx_ref: (Txid::from_hex("22bd4eed46f8fd3f2947f54b6b2a76984698cda514c65074a203857b96dc11e4").unwrap(), 1),
                        }.into(),
                    ],
                    outputs: vec![
                        BitcoinTxOutput {
                            units: 4993326000,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::ScriptHash, &hex_bytes("87a0487869af70b6b1cc79bd374b75ba1be5cff9").unwrap()).unwrap()
                        },
                        BitcoinTxOutput {
                            units: 6400000,
                            address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Mainnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap()
                        },
                    ]
                })
            },
            TxFixture {
                // NAMESPACE_REVEAL with a segwit p2wpkh script pubkey
                txstr: "0100000001fde2146ec3ecf037ad515c0c1e2ba8abee348bd2b3c6a576bf909d78b0b18cd2010000006a47304402203ec06f11bc5b7e79fad54b2d69a375ba78576a2a0293f531a082fcfe13a9e9e802201afcf0038d9ccb9c88113248faaf812321b65d7b09b4a6e2f04f463d2741101e012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3ffffffff0300000000000000001a6a186964260000cd73fa046543210000000000aa0001746573747c1500000000000016001482093b62a3699282d926981bed7665e8384caa552076fd29010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac00000000".to_owned(),
                result: Some(BitcoinTransaction {
                    data_amt: 0,
                    txid: to_txid(&hex_bytes("8b8a12909d48fd86c06e92270133d320498fb36caa0fdcb3292a8bba99669ebd").unwrap()),
                    wtxid: to_wtxid(&hex_bytes("8b8a12909d48fd86c06e92270133d320498fb36caa0fdcb3292a8bba99669ebd").unwrap()),
                    vtxindex,
                    opcode: b'&',
                    data: hex_bytes("0000cd73fa046543210000000000aa000174657374").unwrap(),
                    inputs: vec![
                        BitcoinTxInput {
                            scriptSig: hex_bytes("47304402203ec06f11bc5b7e79fad54b2d69a375ba78576a2a0293f531a082fcfe13a9e9e802201afcf0038d9ccb9c88113248faaf812321b65d7b09b4a6e2f04f463d2741101e012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3").unwrap(),
                            witness: vec![],
                            tx_ref: (Txid::from_hex("d28cb1b0789d90bf76a5c6b3d28b34eeaba82b1e0c5c51ad37f0ecc36e14e2fd").unwrap(), 1),
                        }.into()
                    ],
                    outputs: vec![
                        BitcoinTxOutput {
                            units: 5500,
                            address: BitcoinAddress::from_string("bc1qsgynkc4rdxfg9kfxnqd76an9aquye2j4kdnk7c").unwrap(),
                        },
                        BitcoinTxOutput {
                            units: 4999444000,
                            address: BitcoinAddress::from_string("1BaqZJqwt2dcdxt6oa3mwSK4DiEyfXCgnZ").unwrap(),
                        },
                    ],
                }),
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Mainnet, MagicBytes([105, 100])); // "id"
        for tx_fixture in tx_fixtures {
            m2_test_debug!("parse {}", &tx_fixture.txstr);
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize);
            assert!(burnchain_tx.is_some());
            assert_eq!(burnchain_tx, tx_fixture.result);
        }
    }

    #[test]
    fn test_compute_merkle_root() {
        let block_bytes = hex_bytes("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000").unwrap();

        let block : Block = deserialize(&block_bytes).unwrap();
        let merkle_root = block.compute_merkle_root();
        let expected_merkle_root =
            hex_bytes("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c").unwrap();
        assert_eq!(merkle_root.0.to_vec(), expected_merkle_root.to_vec());
    }

    #[test]
    fn test_compute_merkle_proof() {
        let block_bytes = hex_bytes("00a0762294de8a2471f3932698b71c13350e147d2ec4a5ee5fa101000000000000000000b50236405a2f4ba1363d7d35cfae06d00c5dc38aacd948480fb6fc885303c4cded02166936d9011784bdcb9626010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff600349170e192f5669614254432f4d696e656420627920776d33326232352f2cfabe6d6da5e2966653a4a44e8715054f4d1934149a6abf894d8950d069f8f6bd5fd22b0c100000000000000010a33dbe0215e363f71a70c63dcb00000000000000ffffffff06f340a112000000001976a914fb37342f6275b13936799def06f2eb4c0f20151588ac0000000000000000296a277379732bfdbed6b2813e5f02a3ff1d4aff4bb57f533a81adfce62aaabfc6548117edc5a09420000000000000000000146a124558534154011508000113021b1a1f12001300000000000000002f6a2d434f52450164db24a662e20bbdf72d1cc6e973dbb2d12897d56a931d9de30a5f313a566775a135cf47d40c0ccd00000000000000002b6a2952534b424c4f434b3a114b986e942afc55d8bc595579fdbd2898265fd674bd7f1baa967510007d2cd80000000000000000266a24aa21a9ed41ea3402e4111b29fb5ff06b354f53382a4f15fc60e35b9407712fff16b095d9012000000000000000000000000000000000000000000000000000000000000000000000000002000000000104fa74ef1cd9d13d1d8d398bcd0fb151764197c4669b4541bce0df5d90878b6db10100000000fdffffff6ff3dbccf8cc7fb2e0cc3182ef1c0385720ecb226a21631157fd50863ab8c9820000000000fdffffffce086796dc8c6cf72ab6a053091afa6d813feea57f87a2d2922f78da9972e77e0700000000fdffffffa8e4be71f57a9b194458b1eeda7bab0efc9c1332f29208cb0ba8ad9291bbdebf0100000000fdffffff06065903000000000016001443177ce6f002d840472ef245c0fb0aca9361c951bcfa75000000000016001441c4bf637aa52b675d0f4bcd1184d69fb0fb0b20a74bbe00000000001600148fed4999f3ac6fd538243f5d97a440f1866edf8fb6fd1100000000001600144626ddc86e2fa70927c794595f5449dcbf9f70e0fb5907000000000017a9141d9839ebdb8acbbec6166b9e8b0e018ec90e5006878bad04000000000017a914bad4efbfb82e1cc5f61693f6d4fcdb01042d5f5e87024730440220736bd4de06647a7eeb8575fb4a84a851a773420eb573f47009227673ec8d7d2702201a2ef69c37f3d6f403dc82aa53a3e2f79d858341eb26727e2205844aa2d2141f012102143c191b625aa8c5151a983442d6212936527a4bf4aba76e28b9a6ac899e1f900247304402204019edf8a6c7e95c9cebb59263d96eae271b52dff0eef5818f6a6461e11f0e2b02200a67a42ca31a6790c266571ebe2f3ee54612fdb898425090fbaaefc50c69ed4c0121024c5e277a25b3311172c2f7b0fe843f01088c7d855094fdc03f201646ba5585af0247304402204573000e31fa7b9109eaa106f5b6be482c57431ce7249091564275ef78b12eca022027dceae143cdd7f8349c0a6aa227cce907cf543e5150da76720c20e09aa5fc67012102e29ec38a3a153d85cf1a2787dc3a5a05f9659f080968f4afb6aedf62f945a78d02473044022060599c5fde8c6555b7cd01c1e1449cce1f3047f0b358753d5bd1a651987ad315022009cb934b55366d641df6e44f47d39f5a2be35be763de6a91e42fc608e434da690121022773b82fbffe87606b3f952ef0bf9a4ff56f2080682025b9cc413c5452b4743e47170e00020000000001029a61144dba23cd18eb3d95779c2c5b2215ed876e82b167f0f0d626cb29d66ae30100000000ffffffff6f67fa3be1bc6064ba6aaa97272dfa68e0d46168300d1137a4e10981d0928a860000000000ffffffff010b7003000000000017a9141b7da00045a8a07eb8dd91b8679f07d3c0b9a78e87024730440220463a31ebe086a9365a6621474cfd4b7340d18fc977b5aa50accab573046981ed0220111f7d4eceb4480240fb4e64c9b019bc092ba20216c40c791671ab295d34470401210389ab51cc2a96396698693be418e17d716ec37bce727e68edee3c9e1e9600a20302483045022100e3b033da098c01763f60374f91232b97e4f05e289898c2a1073047439e3a7919022066eb0de32f6d3c1b3e2fcf0fe527516f56fd760428d607d6ce587356e7c2c07001210389ab51cc2a96396698693be418e17d716ec37bce727e68edee3c9e1e9600a2030000000002000000000101f8b974b0e375cf345b9476091f2d1c226f602093bc0443ca81bab7e15130e4b20000000000ffffffff0117b4650b0000000016001499b879d2300eab45d73ffca1dcec8cc7545d7e2803483045022100f507c761ea021f35fc08046cfa40951a03778a6f24d1bdc5d6ee77a008ceae6c02204bcc33fbdb48945d0e8bd66bb84e23186c26ec391ec8a64e452be06d783abe1c01483045022100eaac1b301fe53b76fe520d489d3897c14e844fc43cb16430c3f7cb891cdd70fa02206ce735b5bdae12a0d57631ad9266a4569474c9fdef5badb8a62ebae5502a4802014621031dc0d928248db93a1e32606262337e0843e217940c7477af19db1c502754f4e4ad2102d0f844bba9781b9204458e16955cb43f72145ef23218e02099ace82a4f3dabe1ac00000000020000000187ee874aa96b6a74249ca06f8ef008821be96ebb43cf9433eaa2a3472108a254010000006a47304402201c7bb146f3fd74803a7a5b0447e9d25b41a51ec9fb919ce134f6a4f502430b59022013099af5f9464f685996675ffece74a20d09b75354081b78447b243bf5d4ff4a012103cefd60024c4196bade293827ac51eda155f4b80064d24a763d933cb3b34d6fd3ffffffff0200879303000000001600143e1ed7cd451396b8213e2581e5167f0f751140bfe053ff0f000000001976a914295e81662b67a1ee95759081049a38bbb379336e88ac0000000001000000000101ebd35ab6b52408e6bac4ff194e1685c712975f5dae6514de2d5ab45910cd408a01000000171600141e41581abee2c9e1de78f83c4884c3fddc54d74effffffff020050d6dc0100000017a914eac7b6827479cafd805aa35eb00374daad09e673879ca235d00000000017a914dcfbeddd8daafa20221169eab5a2356500cbc9168702483045022100bcd9446a738f59f06de78b3794b351ebd04ad4254d3138aede9b8de3ff99c23302206caf344f5b264363edb79bd7a6631d08b36d8559c147aa1e30ba5ada05e1057c01210398b299b41cb7a0e412b2de7eb450e99e42621608902a91a3ac47d0d15495f6250000000002000000021e11bb0040ce8cd5eef78de705b3e09b6655664386f82e790a63ac2a401dba4f000000006a4730440220097ff953eb64c2599b73675f2c91359ed33d5fca6b1b6617ebfc51b6a2e011d7022076a713492e0bd01d75999f3d98f64cc11bf8e10de2f289533b98df84461d7eeb0121030f9f0e247edfa015eed76559fab0cd5d0ca3d7b5f3984a31a62af96ef319de4cfdffffff8d13d5d4d74ca0f92431c45eeb1b075b1e494b5074c474275371b8a84528cf0c000000006a473044022037879df1f76c32f3c6811a3751f8a5117101e5e72bc7448345161b44b1a9bcf402202a9e09986bc2dbbc490364db76e76c5f7bcf699076203921099d6b7997a0016d0121030f9f0e247edfa015eed76559fab0cd5d0ca3d7b5f3984a31a62af96ef319de4cfdffffff01307e0d00000000001600141a52cc7b04eca5fb75c661e74555672ed5c7e07f0000000002000000000101456951f4993291f0fcf51c486471178a82728ed4e51a45fbe9659380b537c5630200000000ffffffff03f517010000000000160014dc5f5e4bceae6b258df4fbd7cfbeb4520617734cd0070000000000001600148d293466e94c0aec153b49835ad78068433745ee531c12000000000022512053fe191848e1e02be55b0b3d0348ea45b8b8c98bfbcb17651a483d2fa799fc0701400dd18588946593aed839bddffc3a3803bb2f84bfbfd6169d8eced575691b22bfdfafe9cabf321753dbfcb919616d2080165172ef669aafdee6a519700ade1b01000000000100000000010cba46c8e457c003814721d94daa3a3c021cff641f064366beb88b0378570651d70000000000ffffffffe7b65d2a8ce7bf6de96c828a890ddce81f68c0a9004b993af8df482fc1d6e7c30000000000ffffffffc2283dc8358f38d7fed745faf507b3985fc5c1854a6051cd12bee3b596fcacb10000000000ffffffff57fc6487b56500015acadd85fb3f7e48f8881dd993153151268c7fafb57d000c0000000000ffffffff85b4cf194f97be4424a4f7c2880c61a46878daa90cbded5489ac2633cf3934770000000000ffffffff9db6ffef44181f9d1099ad3a118d9c6a741be4ac7639efe055d7cf9a265052fc0000000000ffffffff9b7148f317d052d4f10e49178503caf2c03c3253effe889cb425532daf0096a00000000000fffffffff0769cb785be1bd37d030e2f2e56d01349347464db5f982075a0ef818c7c66a80000000000ffffffff17178c8a0cd5710de121704091bfaa61115469cd0a473926f766bcfb234cefc80000000000ffffffff93caa3bd19863e370da164757ece51100b369ab7552c440f270e617177afdd8f0000000000ffffffff98d7e617c56e58a7370c6fc5ec01ad921ba08a334e6c7a865f29257fdf965fea0000000000ffffffffabf4ebd583ef5a5e46bb7828fb4c7ac9768d2ca1467420222c78615f78a103c50000000000ffffffff01fc7e8300000000001976a9145b2fcf6aad21ff7770d1673f51825ca8d089503488ac0247304402203c6731098bc0d2cac4c54aeab7d9bb7adcc0a499a3cc2a4f644dfb440bc9722d02200abb6643f04c67ad0e312c1f9d2bfda85e7d9d8093e68a752c61ee09c5085c0b012102deda55b820ad97f92accc1f85eacbc7997cfdbc45ef93019a83098f9dc4ddff902483045022100ac0306a9d595013e9f5d2d3dec5dbcfb273234575a92b5d08428b6960ace7f2402207e1d518baafa4adfd21c67c610c59edf1f13b13cb90af6036669e2b459d44d87012102f921f398308d73d1ddf61f23fcb4977e6fc500280cec07e9a02c8d3d85ac5d5402483045022100d7e7fe163cf65de1974491255ed452e4548e7a2bd1a349cbec7194197b6393bc02201c50cb39beeb045612be7dff8be430d45aad1250bc1799d9b76473af2ad210b1012102f921f398308d73d1ddf61f23fcb4977e6fc500280cec07e9a02c8d3d85ac5d54024730440220419a7a63a066e84231d55202e4e5013e14dc5b17c7bd3abfc2d52105e2f54a0702200788ba46d7d2d470abf8c85d219ed85359717fb9cf7b958cc3e8dcfe366bc375012102deda55b820ad97f92accc1f85eacbc7997cfdbc45ef93019a83098f9dc4ddff90247304402203b43168b77fa1f8331aea3d09b5ff873733ec8b9c4e00aae4b6f6fd584c3b6ae0220595d3485a422e068611e97b7c48f9f42ee253b8e373236ca92dda645481b81f8012102deda55b820ad97f92accc1f85eacbc7997cfdbc45ef93019a83098f9dc4ddff90247304402205ec2698b42bf2e16fda85525929b2d4f32db54a5fc27a00cdba7aaa9e6fac07f0220079ca7bca5c30c08b35073839bb03008b1308dc75423ecbbfd67178c6379ce71012102f921f398308d73d1ddf61f23fcb4977e6fc500280cec07e9a02c8d3d85ac5d5402483045022100ff691c413eab98d117c1fffc2ee969dfb7dc8a053d2b715f6639061c5bc0bc710220570b4081f5a3526bd353a51d4ce80911b2095c4db615a951ce5879f90b86781f012102f921f398308d73d1ddf61f23fcb4977e6fc500280cec07e9a02c8d3d85ac5d5402483045022100b2f9ef0dc53c8f7f192c7ba8556f97c63330b8166d25737c580b2bd09b1770d902200effb7b66a660cf7994e84addee63c97526c3203dc70d37b56a373404335c1e0012102f921f398308d73d1ddf61f23fcb4977e6fc500280cec07e9a02c8d3d85ac5d54024730440220543a834fa2eba05b07ed0c0bb15c0223eb8ceca58b8248b59f61510c9d2a455102204f5f4faae9cba840a114ddd4fa2c947119eb251e57adccc460e3bf7c3ff1b53f012102deda55b820ad97f92accc1f85eacbc7997cfdbc45ef93019a83098f9dc4ddff90248304502210082d7aab164a1947725f27cf50193579f151bbfbe8ae2457e02873ff8b715740402201c7da81132590d5c389b44536322c23d7b700741baf1819692718409f67c1d3e012102deda55b820ad97f92accc1f85eacbc7997cfdbc45ef93019a83098f9dc4ddff9024830450221008b3691a99a6463b89b5afe8ce782ca3e451f071f2af250fadc8c3628d064473b02201eec814ac805f0e0648c87a19fba31e1939d866bffe0f0ebc51859f137dba91b012102f921f398308d73d1ddf61f23fcb4977e6fc500280cec07e9a02c8d3d85ac5d5402483045022100cb3b37e33c392a89f672ba0da716521639e21cf73973f559ed63481a00adb1d302204cfea0704081144b96cc56d0bc3e730c20d3bb4fd5def7186bf85453bca910f7012102f921f398308d73d1ddf61f23fcb4977e6fc500280cec07e9a02c8d3d85ac5d540000000002000000000102808b5ee6b2a4185590703cb3b172eb43a507576babb4721135bd8121502ab0460800000000ffffffffb4a036c681524dd5e2e5a2a6b3f617cba8700d5f54a8f880526918b6ad8f81ec0100000000ffffffff01595f6300000000001976a914458e6faab899a8bf196a9406ee0ddbe85c932fda88ac024730440220752cdca771240c2683a164942d4230945b50a812fa06c913c0a988062502f90f022028c15ea322512c1c629877246ee09db01519092c664e29a50c0c33543961315c012102394b133eae4d37b726f4ad5d25eebc21de0354ab2a0da807a8d9fb2c72f1ccf102483045022100b49fb066f5255cd1b5125b3b3f20bd775169f7cea9cd3d3e88d3f50c6ec63fda02201ec4711b3241bda0fb5c3ce026937764433ea86736997d78d98f0c7b8b4ba18e012102394b133eae4d37b726f4ad5d25eebc21de0354ab2a0da807a8d9fb2c72f1ccf1000000000100000001454fcc39ac020837720bb580dd8452f335b6578c492d4215f516ea1267db114c030000006a4730440220399414230adcdac13a9cfc76b00fb8a2d5115e5760ecf8a40371def9dff43c6c02205e74c91d944e6401e332803447df07bd0c4c3c8a344a9621026c67cbad410bcf012103f3f44c9e80e2cedc1a2909631a3adea8866ee32187f74d0912387359b0ff36a200000000059735110000000000160014fba586074e4a754928e43d8731df15002499eb4bf12e280000000000160014b7138ee53e6eaf5f41db012a7454f886df225809bdd90000000000001600148382d1bbac59a24bdc685cb81b0c8c8ad7d126f64897e111000000001976a91404d74a79567b709a756ad9e2e4fa91903771815a88aca6e8b12d010000001976a914a520c86a08366941cd90d22e11ac1c7eefa2db3788ac00000000010000000001024c8e831fedb9df8e55f608f26b09a44e6202b27dd9f194cc507eb4506c7642060000000000fdffffff661f42cc70894c0db815db555161ca6b0d0ff72d2d3ce8c53b522beb7ee83d101800000000fdffffff22445f000000000000160014db5cbaf32f3c7467e3bc30a1c133fc2b41d5a76a2ae3000000000000160014adadb24180237d6d7dc2e6500bd3a83c4b50e501318c010000000000160014bb55b1c94d947bcdb51b05a6aeec36aec323e8db7793000000000000160014f2516b9f5d0ef64b197d6e61c6c85cd04e431a0ecb550000000000001600144da83424c4831a67f1e87a04d30e2b6378dc53a73de9000000000000160014b5ea5cdfe267cfff82618407ae9ca25a13da654c6382000000000000160014786522a9abc44b696a922f5bfec814ea89f17dd73296000000000000160014c4af2570d5f67fc1c5965c99d11a03a9a7ddc86ec7630000000000001600148e6478cc500eb71112a1d021e620af750f97585e596400000000000016001420928b3ea861831f0ff5333d7db41eff7d0374bcb5240100000000001600145e27f1a34ae8c5555b8325e4225f387714ed664f219b00000000000016001423eda3a675d96d647f4764b4bfd4384923b031b2a269000000000000160014c288f54b850f4d739472ad42ad721bd50c0ed75f90610000000000001600149fe398852c359fa9771bd29fce4b17e7a540366eef8b000000000000160014dbffd31dfdc2beb37e82dca984b930b3cb0f419fb4930000000000001600148f65e93c663e0aba8436e99207c70f6c714ff33f0d4b000000000000160014837e79cab3222db2079117521487008790dcf1f2695e000000000000160014eb5e39b0e6f2843a6ece6c52dfe4a368756e1ac5ab280000000000001600141bda807edcbbc3a2ffc0e2e5996469c8bd84e49f2fdd000000000000160014e2f9edd8fbae3428da00ea8b1d2e6d94d3c41c48a0460000000000001600143b787cf25e8cc03dfbd3f38123645061f94b68dffcbb0000000000001600143a262471b7f4d24c41ff86ca48f8684c69c42529149c0000000000001600148eb7baa5b1abe44ef86e7239c8546c479a517ba0a08c0000000000001600145545e271ff0bbe4f64a39c4824a7ba0599428808f027000000000000160014bf572c4562406b429ebebe4d4a41e91f9eb460610b910000000000001600146f59988775fa0bc424e2aff837207c7934b225e4fd8d000000000000160014adffb9b34e10733dff7b6442d4bd66c1af278d1c0462000000000000160014e2a99480ade980c43f50265f6bea4f60f02487e2a265000000000000160014e817e8ffb1edf45009b4e6b9d9bacb1656e7bfec2e8d00000000000016001432fece59d4d9889b7db7c869c8d2bd9c1a2cbdab1879000000000000160014c5bc240b1f8abd1978bdb13d33df6364d5c28c89c0b30000000000001600145887be6880ccd9f275990a3709e2205e1e02fa356eb5000000000000160014a10927393f03f3be169737b018b185e6a791a2e85c01e60500000000160014e44138ffd44c1d577311755dadb540fb735c3a190247304402201f8adc6e13bfc97a91b95876a9613834e19aaafe662da569c6378bca57a6c8d5022034c785b0891cdf35e922d8b99e7a4e52aad8fad42ddbe4f6e75ff079817d3fc00121021a8a9b0f6e1562c7a0fdae59366a61cb4910b5dcf318bfdad83285d86607d38502483045022100e088bf345f0407a40c57fd695d99012b64e7360b7cbb62b884a489f66973b82802207b6bccae8177a4ade4ca535781e51f1a2aa825b5e8bc3c078caedaa43be504340121021a8a9b0f6e1562c7a0fdae59366a61cb4910b5dcf318bfdad83285d86607d3850000000002000000000103904cac1228022c8acea9e5edf9b7298ef18b558ce2638dbc4edef8e050910e4501000000000000000042b0b3142ead82a5b59956b13174985ca21b81bf462e47e21d910229e71108d00000000000000000000d6c5d493c14b62250aed883d12284af4291ec34f27ee135ec9b85966b25e93300000000000000000002c66f200000000000160014995eb2b49eaf602e60e4127137588e24a727668473a222000000000016001498040acb314ab1afbd42e2423268cd147d68657802483045022100a6ef702bce228fc076c8b979a9b2a50240f34ff59726c074e909bb8445f58f420220609f89d6f2398374157b1ea63cd8328a6b37add19c925b6089aaca8c856cb9190121027bf8b06fcd1ad4f001103c952f95c346df5c783a0af057c35fcb7c028d5d2c750248304502210090c62680b7fb4230ec5cb14d0236c9feadf91c79d83d911649e42420914031fa022034256b477f2684614a7b6f8067d91425424a2880d292767f0b02433a0980defa012103b4c2d9ed23e35ac9cb8935550805586fa2f204d3e4b3e671943ea169d0b7cc46024830450221009aad41fb443bf1369e6c6f8b65c8bacdfa618bb72684fd12a075431decb926960220743f6edd395fa7594c5c1c86628b57fda4670ddae188750f4b73c49a7b77a599012103c362135b005cd317fc0345659ab48e3ff89651e8fb927d1b637fce19da4c9dd00000000001000000000101ece6354fb2f77c6242a4996bdd3f6955a4b0d056a2bf8642771d9156f35f77fa0100000000ffffffff01e1e103000000000022002062d801a01fb59df4227d0f49f094b74672b75344d75e28e4b6c63d259ec0de9602483045022100e10ad1e3017ad3ecd493360bf06c7ad1ab0bbee66dbc6a24fb745b75ae1f6ac20220356af23193399214501feb497143e44bfce673f94c87e7e9d9a684a1065bae58012102a6dba0793b273863026d17ded7e34635d68fd182828ca4e2cc2eb3ba11ed2a5600000000010000000001016f37f9b03880a3075b1267fc24acc3ab1c81aa2bc453d5bccde2d930f4321b690100000000ffffffff02b8070000000000001976a9149b7132884612f8182fbe3383daec0630deac8a9888ac5e270000000000001600149f452c5e1925fc282906c75bc056f234cccbb37602483045022100e41999b804f7d33098bd020fc7a4943cad7c482b2ce3f610e245f8fd39e3a30d0220549ee3a36f6d94fa3a7f76e50edfdbfbd7f30e77c3f6d5605a6bef2ee2de48ce012102aba72bc9154f25dc7aaf4344d33413101859bad1ac02b79b8d8cb1d7f201aee8000000000200000001b35e1b7a7be5d51e2b6c12015c11e11b30734a9a09bc00f90b6d6b751d58c6dd010000006b4830450221008603bbfc04c348cb4934f9fbd654f6a3d83ed729c2ef787d63b6217d351aee750220524f0d0be82c4a8ff7e64ad0e122fd75c6308ac32cfb0b4dca88ffd370e721c5012102fa7ac394915cff168adb508fd376bf8eb4fd73e5d0af8faa11f01f79ba0722fdfdffffff010a90020000000000160014dfdbee6408f7bf0c0cd0df581a12ef73b2369e050000000002000000000101ce1aaa52efd3b001950386042f208d72e8679aee3dd5684865683d9a7b7202eb0000000000ffffffff01af6d0100000000001600144f0c67b16acc90e3476e79d531d7d987c4fb96de02483045022100a48a3859595a8351e356e8aa5addb69a5ac1af7f88e8a7d0e6ae71bc11af0bce02205a7ca9c1ea2d672911685886a3bfe71f2ece80bee2f0aa3db2277196a44c6c9e012103e033b6ecfacb7a5cf832da98dbeb084074d51c369147636f53df0f46bab972dc0000000002000000000102a44c2ae85cb66f63ecffe06ee0dd2ab19a78759945e9cd5293998f8104272ad70100000000ffffffff018079f0fd9db58246d155babd86d3dba2e0979535bf84813d7afc5c481d0c220000000000ffffffff029f97560000000000160014f230b0ea1113ac6fca159429f8616c8d1ea76ea8fe140b00000000001600142fb25436451d2d4a6c6117a9a5314b5ebfd1ba3c0247304402201b8a50fc36cdf662d0d5c7de8cf722e2bece49ef62f6547e18861fd290e3084802202e3943da0db8abc51ebe83e76d1f3d95dd6daf46497e2812fa23a15e409a3e030121030821236b39267017fc27760a518023018ae841bdf7317712303e9484c4bbce640247304402207887954e2946c8aa71603bb6579c558b744d36dec577ce68230e2ea9eb6acd71022012f3b7183bbdb1fb38c74265a55938e8bbd355b5853cc6dc58560f2dac10d05c0121030821236b39267017fc27760a518023018ae841bdf7317712303e9484c4bbce640000000002000000000102293f03aa11c524e1fb90cd3e8ee4cc6fe38070cdb624e6706975c56fa66855c50100000000ffffffff5652d650b4c6741e39c3ae0817ace42c14092082f9d9dca46111720e9c466a500000000000ffffffff0228b90000000000001600144637bbb39f4f2fc7f0862ab29b673e2bf3ea60436b74030000000000160014919e8f3f0f82dc1f8f920cabab964e3f2ce8d2550247304402207366a8c478cfab79a8bdf09de2622be4d3ab51fdbee2f8ed226697f5ddfa13fa0220175ae6fa9d4cb16e49487f12fff732a9da36aaab0935e52e80485d7932a3216f0121026799186d5f6366db2e5a688d4a3a888d1fadd61906706cbbde2a61416d9fb0e902483045022100f363244a0f6d44be5614e79359d8655420251b4713fe597d830fe28664d2b4cb02201c4f4924c9227e5163637f9a02f8d07f8e8d50f7a1109e20d7eff59ad6eba2fd0121026799186d5f6366db2e5a688d4a3a888d1fadd61906706cbbde2a61416d9fb0e900000000010000000001014a5548f1c0d40aa1d3c13ab3c5ecf11eb4cb53abb923d8f69786bc66046fa1790100000000fdffffff02d54a0100000000001976a914ea4174eeb44d1f6240f23cbec2865ea149d8f41388ac1dcf2c000000000022002002543070883100a2e5474b8f4a145e71aa83a4ab0564697f77b70da1986745740400473044022026b4a48605ee2aaaf2535a7ea3d043a4298bcc7fb3daf644551d1aca77834662022075e0103939d59b0a492e9773bd08b3e341ffb63c30fd4afa27ed6d42bc20a787014730440220524c2049625d48446216e20caa5093e49c1eb37e16e4217883b718aeafe3d2e60220600a217324ec7b22a54be84b0ab289fa146e6fbe69fcb5cd50067647974ebba80169522103cc1d799e2dd8cefd79e0d7e5ca4a75bfd2d1163884085319b7c4cb7f9e0407ec2102cb129d9550f65477212f2607fc440e7367225d622f78a997cdd1af8992af0fa02102a8aa7f36e2ec1a720dacac67ec14e028a8460a7d913a3fe11f8cd2b3331309c553ae47170e000100000000017a50399c8599cf449470cb8b664282284e5b8bf3c656e43b76cf85926228a71d100b00000017160014815b16b0564e1da5b9c6c3415fe0d827d13efdf3ffffffff16728a252cea7b99a741d7c5f080727a2069de8fa633ff12e6ef24c52b455e0a08000000171600144c92a7e60898552dad941d87992af8c256ba3c3ffffffffff0997218e3caa15aef797b3a5df4caa80cd04d9e30696681029622860e6876f30100000017160014256ac250fcaee71352faf8d809ec18d3da14c55dffffffff16728a252cea7b99a741d7c5f080727a2069de8fa633ff12e6ef24c52b455e0aa30000001716001421c5007d1f8c018bedbf41fa086b2aa74c582989ffffffffe14170278c84e9362e4b5f7346e8eff5c16b68e06326a32d9ab9b6e03223856b000000001716001476d989978deea83bf7d638b1cfff06f1b7bda8aaffffffff50399c8599cf449470cb8b664282284e5b8bf3c656e43b76cf85926228a71d100100000017160014450ef57632d756be7e9653eb9112522197aef24cffffffff5c99fb96ee3860b4b293f42d2115b4f37f2b44ce407343cf6cd7829f4bfbc799000000001716001436f1bc8237497edb7f76c75d9e2e97f742d7ce40ffffffffaf9d163dc703dd75b594198ce2a6c0a93536456d76c1c43d048ea6dd561a0db200000000171600144a71f4630b8fe4f7f992d945b3ba3017ee83d361ffffffffb9969894893a59d193a03b267acf437aa89c9cf5795097f3babe971c8b6e3aa401000000171600149f487e46463e0c78a70205f511b6ce0fd8c76136ffffffff6469a245ac14ae09846558aa74b7398758f50b1d1b11817f96443d2a22505c6c7900000017160014f99413287b2efc2215307bea3a8bc273011438ceffffffff14648f32f9de9bc4bc9e7c415e67c038b6a7c7e5dda9f7afbd576572b2a443350000000017160014a4dd661da20a1d75c736b4ef3aa38b952d75ba04ffffffffd141bae239f70c346191ea4f88cc3a53c073cd34c09695a521bff3eaa7397fbc0000000017160014dea16857b873476d831879d6b407723279a5ca07ffffffff808b5ee6b2a4185590703cb3b172eb43a507576babb4721135bd8121502ab0461200000000ffffffff1dc901244fa121dd67e09b678b704250b8564cfd1f9a2fb4083b58f5e6063eff000000006a4730440220794ce393ea9b5d9b8ac9313f7a10fbca1c8e9efa6917e94147fefa12d6a975b90220026f3aef4b5641e2bd00dfde91b107d053cbeae3f4c86881e77fff94ab21ca64012103c1d817aea7783f47c2abedc6840861eeb7bcf099deb5164b84bdd82add70c86fffffffff3454f956263cde1d43356c6f1f3bc044ee1002b529405067b9af6bb3c7c2b1a10500000017160014092428f0d046bfbebb5dfcfe83f8214159b79854ffffffff1ec361e77e8d04ad3e29350121304c5582627c936c2b8541724e3608efd8e0a00100000017160014a93ca33f7f4c1d8ee22fb957e2963b1efbdf0d47ffffffff83636691ee149b267d90c4da07fdb9022131b604cdba104114498246841043240300000017160014ec741142a4785b8a8c985ffac6e3dfc477c66233ffffffff8f7f3848dbadcb521d08cc95881c3f593115d92987c1317a191956a3463e2b090800000017160014b9c131180dee3d66b8b3c5149ba943811a18e73effffffff83ffc03c1c7d9e2563e1ffade49b949103e01c921fbbb8f31f51ffe3381f005600000000171600143bba4c1a6ac504be77daf1207ae1d5baf62b4109ffffffff8791815fbe200777cfa338e61421c54f0e234def34aa371dbf466fb88370903200000000171600145887898b81d708f4a883c07cc82efd571eb73aa2ffffffff2605d8c26f6e62ce2d6ddeff077d706d67e70695c5e797a91b8900539043fc1b00000000171600146c2cb2d89e0d89a33416fb44326a15c8ef1d9c9affffffff638976e82be2cdad2155dd11ea24ac71861cb9c6acf2ed3a487ed556d160118701000000171600142ce4c360cd9001172234161f5d4d2d9672f2a50affffffff703919600686664beb903966c65d87fc0c48a29834a3b9adc9b167793ee250d1000000001716001488f3efb4796c5119e0876ab1fc3df4362984e417ffffffff967794ea74471166a15d16542d8fc1e76c49b4da251bc728340622b2886a808a00000000171600141b11b155e7d7d6e6d94a9df2e7fdaeb607af1630ffffffff3a5061173cc159b8074c36007a96421cb73d59a24747327d3b7694f9ad55266b01000000171600145a6437241f157c152ee26a23d9d9af46ca2c7ecfffffffffb61918639b03d2d6a60cf081597bde6ddfd1bc92f0d8a7afcbfa29be2e4da989010000001716001455d4ed8cc472a2a63a2a77d46c61dc37a1a4f648fffffffff6fe0533f21d1d43b5f490279734b1400d63b29463b66de8939815606b4a36a40100000017160014936216e5b3cf3c377cf143d205836d3f3c923bcdffffffff3578f43fc3e7c82c532c90ff6b89c904b176122e0ffb1961444e4cf0c70eda8300000000171600143b026a0c1af1b558d9c0279887cf914ae83415e7ffffffff03ade754255f9ef01607dacbff19dbfc3d2ad3668215f3d106fe3f033c0b4d670f00000017160014b8efc81d59fa0548effd925da9b0e3b7f4e29fb4ffffffff0978880d7a43e5172c7ad9ae39fe2043dd1673ef11e891db91bcb56dc074594400000000171600145eb29f8668d08a2538c23836cc087a256cfcb39cffffffff2cba9314790bbccbfbe8e16428216bd4d1fb07e077f292cdac6c8ea07fca051e1a00000017160014551b23c96aeb8e714898d42b7c2d9eab184cab7effffffffac59cff970303bcb14334eeb451bcc3660dc9ef25b48e7715beeabca724e96440000000017160014888dad2ecd7ea3ad9dda66d1bc295bc461514540ffffffff1f14c74f7419622d02c226d7580d9e6a5465ca6f0df63d6f737261572156a96800000000171600149370c2a3cd55f29855ffb0aefeb8a96b29f76898ffffffff9476f8b8e06c0af37ff2f196cb5747cc96dd740a85026d22b477e9fdcbc4f7da00000000171600146c2cb2d89e0d89a33416fb44326a15c8ef1d9c9affffffff3c4fbc146e9f33cd96ffae87e908ede25295a072382ec9e9781f8fdd1aa448e10000000017160014d09eba569a9aaba941caf63d55eb0d0670e4dd25ffffffff8a81406b8fc611db03111ff639082877821426cb06b7d105be513a14d803cb8701000000171600146da234b748fa82584178c4acf8d460fab389faeeffffffff9f937a8d54b94402dbcc600fd7dcf6ef2b34a9ae87c7c1a80b51126e1357e0280000000017160014b977c1776c546bf74ee23c175b2d24fbe910d297ffffffffdd48ecd03dfb75c08334127a0322812b56ba34f6328c8001949d2536cf1fc9600000000017160014b316b5b8f0b2ceaf9d808f2bab3464bcd9dd3447ffffffff40907ae856e9642ce23d3c212a1df898663e02ab50b4fc918aef8120e97747b2000000006a47304402206dc7e82fdcbed186dc42c6942b450eb14221521864ddf8b11f57ca0fdd1dd322022028b218d7934d579dfdf24e0a4a4e7a08b55a08fce2eb7f93ff7bd4beea64b050012102a5ffe743c1db01f0d51071514871b561b9ddeadfcafb46d9691cf28f89c2f8b2ffffffff12a0981528d80fd9d68db5f5c2c1cea8073d1910acd499c7ce8e42a23452ae7000000000171600140a454e225ccee8b2b87029f530e5aae3631ae98affffffff7b49047bc868d050d9c37bf0259a7c2aa83a090ebde30fb77774a36cb00fecf900000000171600146f2dea8d08e6342852614eb27d06263fb306bcd6ffffffffe237cc387d8001d7b6dd71ad1970a09fc1964d90f6028ea5e2e0aa0d7beb0e170e00000017160014dbfbe5793053f90a2f6a9fe59a5fd9515fa987b3ffffffffc9133b186f0967213203d0157175bcf5bb95c0be9be189d5fcef91ad94ca5697010000001716001415aebd0fc31ee22422d47ab08888ac2cab48da22fffffffffae62c586e3889235f51106ddf8bbe73c7b546ca78275109567eaf8c165ed14701000000171600143e50107aa64c82b0d608bafd871df342a41d0594ffffffff19925f1903ddbd1be5cdf123d125f3e50f3eced2785fc2ed331d1fa8394e34b80000000017160014cc45a69fea5f7758a78e08406aa94fa830e8b904ffffffff493541e3af8b43062e731dfd44eaefc4cd51051e0bb873e7e646f35a4b19f71e0000000017160014e454c411652af59ee8fe3ccc678af2c46e143356ffffffff8b214fb38ba185fa7c56194789ab0e90247c3c8318f34febdc0cc6c2902fde650100000017160014cd0a7e418ac34a3258aea1afd3390579710fd89cffffffff3c1ce3a03051709100308795edece51e3d2122b67651756b22542ac27c6671de00000000171600148aeb94af021e258d9855270f165056474b31a683ffffffffd2acb1c2a3258ba502f03c35a392029c137cfd3aa4de1697c6cc1ea96c512d921d000000171600146b2724373bb7c1322607fd80cf19dad0923967b3ffffffff88f0e217793667716dda46b9438eb89a9b6201c94dbcea29dbe6db2613e008b101000000171600148245302143df7b9497f13fe97ba2a933d3585b98ffffffff48e4ca98fb25c8112f1ae213c195af145ce8d31a27d0e0c1b5c60adb306339370000000017160014195a34e8ac4e477d14289469493cb1bf79a67fd5ffffffff4176e3cc71443ef53c656cfea6799e07f6d32d4c14a80be5bb639c75fe5a5a1501000000171600147f53dbf9de6806253cb91e3684e7938b91bb1eebffffffffbecc8aebf042290b7756b401c874c49b267d809b759a4869c011b6d64493a9021c00000000ffffffff264c49940265c4d0caa56aa26e506aceb9cbd4d70eb42c8e3c991c9a103e53550600000017160014f5ffc91ae218ff7c2748bb21ae1d6608605f43aaffffffff407334cd5de9fba8a3da8d37ca42604df3f47f5c363fe627b3d30f1a0179c9bb00000000171600149e3faab7fd90bb63a55c5198ed712df3869eb935fffffffff5bafe39805bd37e5f900d208cf51e8a6c487dc1cee1381eb5b056de35277b2f30000000171600147a2407e26533f90cb3afe7d0e949695c8f03e4a0fffffffff5bafe39805bd37e5f900d208cf51e8a6c487dc1cee1381eb5b056de35277b2f350000001716001488d32d7848d2f02288d169e5f244caa86c12f2e7ffffffffe2733d72eb5f6622fff6364a027c24a6b8380221fd0131cc449a545be8ba00d90000000017160014cf3d2106178d88bbfd642f7431b494163af45e9effffffff2069c30c1a070a85d738c048fe1df3afe7d087c66450e07f3d8bcbc9c475f54906000000171600141dd912614b57767b54f5bceb04dec9944f6fdc8dffffffff508e3a0b4321976cd5ff59f9c8ee85cc0f308aebf0eca313ca50bfe0977087510000000017160014e7f61cc7cbe6cc7111a74a94e3e1108633e3004effffffffed7301edc3882cee01550dcd9bba4d2818d60b06c4760c1f4162cc0856a1a1760100000017160014cdb697b925f24b2c3e4aebfa0aaa617aa9d63baeffffffffaf99ec4034dd4b007029314f48ea75fc0c37d50702f0ef8c8bbfd2a59e4727001b00000017160014fd10ddc965131eaa75f161167814f47f7ba04565ffffffff724adb490b4237d2d80ebfd1374afa1a0afd700064587e31316e95cdadcba3930c0000006b483045022100eadb40706187c8a2add2c06113459bcee9c313963ce7a0cfa8ec48505dd89eb802203cfa3b215cb0f18c0c8e17edfaa4100830e7e763bd434c39f4e2e7a98e1967ed012103c44d0911c31146d3725d899d108e3d8bd6f0485f327ec8cdfb0553b0ee4575d1ffffffff16728a252cea7b99a741d7c5f080727a2069de8fa633ff12e6ef24c52b455e0aa900000017160014b8bb64eb3cd7bda973133be673c42179adda9c9dffffffff509626e545d2bc3acd5cbfb602743ed366e6097b7fd94717c9733710b7136231010000001716001465e026b399e36d5b83a69b9ddd61645c7cf05559ffffffff2b8ad698b36899a2b0e2b637718603cf535222328117776a7c8e7fb4ca6f7de1010000001716001416dc24f4bd837b279ee4fe6c0c0b3e976641c81dffffffff6469a245ac14ae09846558aa74b7398758f50b1d1b11817f96443d2a22505c6c180000001716001415ba4dc8f0791c6c65ed0f387a865211c38345afffffffffd2721768135dceefa42717c18da6a630406ee162f3e54884ca7bf1f78e8d421102000000171600149fdd4bd047b33b47c67329a9b100a4775f41c9a6ffffffff90ed5ab0f1496dc4d244e1afe103d66b31093a4494e86064591b002fd7362a8d00000000171600140ca84f32f4d5ab9a7d9d8e319d52aa186248995effffffff50399c8599cf449470cb8b664282284e5b8bf3c656e43b76cf85926228a71d100a0000001716001465e893fcc1dc28aff0556448b1ec5c8477b2a24dffffffff00e43596067d73b04dc36203701395e4b224ef1d5cff5fc084ba7f27e2ebb09e000000001716001427ab3d6ec60231cbf53cffdc1ecba00d70d49744ffffffff9d128cda7343229ecd1e45e48d48b350eb367932efd2835e607e3c748aad15320000000017160014a86531c242a168cdc387da17b339e9720eb80544ffffffffa6fe71d5915b0f43202367b2425af16e57f1b30e55df6804e128595d4455a7b60000000017160014e37e29266d8da2c6a62452ff2b03a3b5825d0227ffffffff46cf43b54f056565bde6a1858cc8261006486db49f0ffa75114f10defe10473901000000171600149292c61c9aa1d7eff436406dbe71cdf165169eb0ffffffff546a41f3d2662a70904d5134b426aeb8d1a9e5943985357d978ed6741efd64fb0000000017160014f5238e05b7bde399bab967a6c16516d08220594cffffffff41dfc2b68365a51070f531fd079daba7299ee9e8703847ca0d2a15bff011839d000000001716001437b9bc3a420fa985466114ef5b2256c309fccad9ffffffff3cca4252f9a948ea5c547b586d3b897b627d5ec093bf1ab9959c8a055c8cedc5010000001716001452622a6479edb0511922db5fb5d57eee6b4d82cfffffffffebdb83f9def81b5ed5396f8f11820750e0edea25427a827feae3d0d99c9c689d0000000017160014bfbf713482b7b19f513eda45e5715f0aefc452b8ffffffffd2acb1c2a3258ba502f03c35a392029c137cfd3aa4de1697c6cc1ea96c512d921800000000ffffffff50399c8599cf449470cb8b664282284e5b8bf3c656e43b76cf85926228a71d100800000017160014e3e92c3940921a94944d79b3641632c258c7ecd5ffffffffc83337a595cca853f5caeffdeec081426ab4567bc1b585187101fcbe9a2fcecd01000000171600140992af2edbfa7b0d762a5a35975b975eb595582fffffffff7f3169bf13cd9b75bcea316870803ea31a208eaa6d7c2e073498bab0e661dfd10000000017160014dbb5e7a699ba288f11046fc77a0f865d194ee87cffffffff4ca4e03eedd48b3921376f180b34ce19f0edb8b4f16db2eae4a7b86169ee71541e00000000ffffffffca76be9acdc815dd1d8b31bbe5182bb5b7662bd9b1afe23ff9d514ac8097803f0000000017160014e9b8b47c1019701386360fba42220dd1acf9a6abffffffffeeb8dddd68c6829f4b309201dfeeb2eff98135db9a6754999c61bc1033464ab4000000001716001431879e740610284b90ddb3f9825897c31bd4dc70fffffffffa285bb6712fbf6ebb754c75986281fa6e8cee9438213bb3b3136f8ee55a85d0020000001716001421bbf816520a4bbe45955a0ccb693c00adeb9ba6ffffffff16728a252cea7b99a741d7c5f080727a2069de8fa633ff12e6ef24c52b455e0a5c00000017160014fdb522ae147b441aefebd146b3fa0d1048093befffffffff35536370f838a88023cb0ee4c15d98b71b0686976cdfca8a9e3400ebbcccf59d0000000017160014cc45a69fea5f7758a78e08406aa94fa830e8b904ffffffffb0c4995c2dd4f91a44cdc233ee6cd4baf46f2c6df41ea0c92fe5b49bc19e047c0300000017160014d661f27a955c83bbbbd2c45dd54c989ed3a851ebffffffff8f564e6bedaa5494fa9209cb7466ac21541e680e09d3c6f88db9df85f1bff8a40000000017160014b58549ce50d7c01f7490eb44482f711b41ca3374ffffffffb3bec8cda0694241e61bde0d7900a9a1ad5cd91a4b0ced7b32bfe4d1913f27ac01000000171600143aa35cee131c906db66b1ee175fbc790cd50f578ffffffffca0e76669885b2c9ead3e8590556836633bad093078a253f0aa057d0a13bdecd0000000017160014522af2fcb00ea2b4f53d87463944ec33f040b50bffffffff8f7f3848dbadcb521d08cc95881c3f593115d92987c1317a191956a3463e2b0919000000171600149950ed69c9dff2c356cec105a781714e71cd1c3bffffffffb055ec77403c922a3ce91f9772f8c09fbddae90a054adb6545ce5790e2be02f4010000001716001470ab806ec6f7f8d90dc2ab066ec4a672b44b2156ffffffff72563301cb750892032bbee792c7b5646a9b2150334dab97c8d20cf6b2760dd50300000017160014af6b115f698515a4afe9c8945610aba96d8869a2ffffffff18f3d52586f75025b1f300a7ff051ecf7a677f95ea95f918b1a659ee23b70b590100000017160014118389c43ab9a5ceb0daf2b53248572607e9f8f6ffffffff2a62c9e46b9713a578fe8323a5d08cf279a7426576da1bedd40bf307593d3aa11000000000ffffffffcd902befc0076befbce467a87f73ab33d553c2eaae20f7658816a1c69e2daf970000000017160014886ad2a76703e26b7ef45127a5e4865d40663c6cffffffffea6691a65a9e19c8eb346510fbefd70318f4aa84cd269085ff06d34cc310d9d7000000001716001401b0745e6c9c92ca9fd8393a17a6966647c41280ffffffffbba9bfa290a320a67d8b7431de36a019a654b5deaeb4bb046a1ac2bbb91ff7dc0000000017160014704949f02105b9a875c994c46bbcdf779bb7e9e5ffffffff394533054c22a64cdfa5bb210ce41312810079dc36ff14f76c0575a123f7af6a00000000171600140c6c88f2e131e716f25e99c673c406709ceee57fffffffff81ec8f863b9337c01e75d48d11ad7e95dfd8558a5a5102255ee6f8aae4c5c7f1000000001716001425f125c63ecc306bcf8d72ece445e01f4c4c7c67ffffffffe1b0dae3e3e679a19e38de1108d3650501b78995672bbb897c4ba95629ed30400000000017160014480812decc875b98f8fa75a018d8798790944b20ffffffffb9b722ecb4dbb940796611490ba8a1044d99abd81b83688eb8abe23e35cabad505000000171600143c373f0594b58eb9d2eecb765c338d80faecfb84ffffffffed2b316691050e6744e6b41d0c77c6faa3424a67ce1d5bbdbb932f681e899b19000000006a47304402206509d46f5d8fa2d811268aaaf84af637216b37f294244caa72b12e89276c2895022060c6cbd5010ce817bbdf48ab2a62ba163e514136fc6161423733241448ce0b56012102a5ffe743c1db01f0d51071514871b561b9ddeadfcafb46d9691cf28f89c2f8b2ffffffff2b35afd03442179a1f87eb737edc1003ac1896a24fe30e35dee714429bf14ef10000000017160014a035a35c835842d088153e9aca093e283eaad394ffffffff4e9c7e80385ee9616b3dbe6ee2641082ff4c41cdf37d3585abb111045762572500000000171600146c6051b2a08e6e603209ac5117cb1ca8b546ecd8ffffffff65182fbe1be6da7c5d2b33f0bf6b17d4630b6e571a2314576cb670ad974903a60100000017160014af0be2b0bf073cde1af662629480b9401190acccffffffff82a118148ddd006b8139ebc8149bc7af6fcfe905954b52a1df648ada57f3525b000000001716001499e5014457f9241941982e7483427ac8fa4308a2ffffffff2e88826fbc8123d89ef0f103348d15aa42e8365a53fe91372256e790b9c6c6a6000000001716001429e6778804fe93a60228b27ebd90e4c93f43405affffffff94e09ca78e22f2b07c782ededa8dbc5745d3dbbe5a65e336dfa328b88b10b6371000000017160014c9679b00b191581340187021e2e4d905d38cc7d1ffffffffd75bd7021f1643993ee9c477ff2402d246763a73c2d046cca8ef9d405248e6db0100000017160014181d64fcfc1f554201392d1bbb652a15e67d954dffffffff4a420250543ed8332d9a3f0c59668461b9f0b6516c132bbe396ed975d72fb19400000000171600142300b4530bbe9a1cd6d2214ee6c1e1ca927a7b86ffffffffcee354f005901264ba4a3b9a88331debd5cc31d5d1ba5ea3fe4488f964431ad900000000171600145d649f1523979e509b77bf1ab8a074ce4d95dd26ffffffff0290d4204da926762bdb806dd1e25a3ed9f1b649753c79537882d2d4e6e2faa670000000171600144b90cdab51f287b31df2f6ca7574a2609a93452affffffffb7f765bbcd85733e729fe6226cb11bf80cf70d891bf01b21f08219be61d4fc850100000017160014e64a652990e260d51e5e9d14ec5ba3daf127d86affffffff2afa78b32b459a04157bb5f72517464b09ecbb21d9e625e054c159709d8c02490200000017160014eb5089138231350d756e80eb233dc1b9c3745794ffffffff0446a42a9eb765860b17d1f4a23e009e3bd518c1c7cf3a17ebf85dd4b368cf3e01000000171600149556f79aa1e3a443d44b2cc3248aad84c5e3c984fffffffffe3a5e693f0642b3f10c1d3f145f6cc20e911e837835b24030d6006a305d110c00000000171600147824d4a86aba85454d6e8d0400e0c65b28fab508ffffffffea57b60946b53b3701ba7409956ec5793eb41264daf61db6bccf27076ed0906401000000171600141404a425995cdfbe02cabdb8dd0334b01c94d1e5ffffffffdbefe138f12fba64c9c4cee3ccf88d1ac3ddac50bab14296c38952a44022607900000000171600143bec741c33ca2ce0b58624a346908441e67ff0b0ffffffffb7f765bbcd85733e729fe6226cb11bf80cf70d891bf01b21f08219be61d4fc85000000001716001436fac2530b720850b53a146d9035fcf0476b87caffffffff0172596a0f00000000160014e92f0bf6babae43343bad16e7599a3b63d2b505c02473044022014d53db9f2e2b507eabee6ca6e941c8e296f3932c781c2b1639b9bdfd86ed37b022013f9b3466f46a2f1d0efb5b8548fe522f6e142c5fa192c316b8c8a2a21fd51d001210308ff2e36d7e496037326c28118ab2e206b47800e8d0576f8354df6f3e1023ef6024730440220570591ec5aea8fb6561a561d4b01077dc828effdaa3c7e766b2261577d6a1f3f0220375da17be9fdfab0b823d5f979233dcd0d757c233442ad198528b4cc316ac7e40121022963f16448fef9910df4627b1789af51a1cea3e2cc3e2660119e7bd4824e4c7702483045022100c86fde9b8c53a080a4eb4935bf48bfd45f444498abca51a124e0bfed9b9fdf9402206e39d9c607c406dbc63bfa866c30ebd5c578a27da9a4f274f7d49aabfdd23fbb012103395eabd92639b34890f3678cf601112a25bfd9910a68338a0f67fc90c513e0c80248304502210092f99c0bd499b0a2d37fd216a4126f586f3bad6144e5baad50aa1f79940926d502202f83c0d514fc8a80237f43132c46120c5ed4c4df4514bb310423597a6c5230bb01210259e92be43a2e63ea4a64994c660f40847298dd7cc64a7d022f8c94bdc970b68802483045022100b596cb0d3771179cb5601060c1ae6a0e26398c4f8a028cd7c423c49fba60a658022059d2743eda21028a52f27f02bdcc219fd7f94866742a8b36b7657f1b2056219f012102878542a6494b381bf1573abf343cd17a9bec2920a9392a272960f4449b7247ca02483045022100b812b7f10fa65570d378951a29aef85c492f8867b37f23bd962e9efa0c25bc9202202708f09f19c260ae93791347b2ffc7b897c791d1be64906440480c4460a06a30012102f010a554cb196b4e8090c924f86c50f77b5e2770bd830cadda310c1b2553a86602483045022100db2064a68a23c88feb26cf6c4a71b8f646a4369071e047f05bf19869053b062102200b5701ba772851ae098d3b7b4334e0f9d5f5eb858ff61b268e25f2e4694a925b01210271ddbaeed6b342df1cc5e87288fed61917578d90ef2194109ad5bccf2d24836102473044022010fbe53e2ed34d2b8d935ff83ba5116ac764950040976098536e06cea79eb13a02203ccb41ac1a7ac9602de4dfec6e9e7c9604b1d4f2e84885d0c02477ad958469dd0121023c49fedbabfa99e01623ce2fec5c5d5b37390648ea290c991267db3a79dcf7ad02483045022100a54f35ca11697fd263b3ad7e0ff57c6ce80449b1d5f4adb14a7d38166442b29d02204ae9e20581c1721df102fd4c0d52a9d194e3353998f8c9d63d08f26b797b739f012102ead5b6f7591ea0ad46f64f433bdc9bfc9684e04d224a76f47ff07a6e32c32e920247304402202e609879341ca3b9e4f4a632b0152082b60968171bb0c8495b3034e9fc5b5812022044efe948a741fdf7bbcc307e641770f00d055db287479d4e272354ed82b74a72012102d6932676bd4a6ef8325c7065ead760116b54772845cf19b65c6ab8bcfb9640400247304402206b140702ce6dd6a04cbea780f7d22096c5f103c2d8d081cbbbc7bf0fb9c1a965022068899b6ea7f70b88817c6716844f904d3b820c186709eb768dfaacf42cd77073012103a100423b366c6a7a68589c33f8accdd2ebe3489a675d838f3f2a3044b845b137024730440220421593c5e33a970323e87483f189a6a546de42d9ba32a363baec5c53811cdf46022017d6ead3d339f5dcf9a8b96e494dc64b55b3a67d0aefe67b189f011e6530595e012103316a08496dec27755cff6e3a801a563df413be181d458bcc3ba027ffc8fcc79002483045022100d3a8034a689b32af2388dc55a7c273df583d0df781b9ab17aee308a169d029fd02201e9018161320e99d6403a814975c013a2f00b289418447aa7da2d1c93a25f05a0121021d22600447fb690b15522ff7731475723c0d01187db97d5d43ee9af43ea4bb21000247304402205ac58cad2c14035d7674587d052724044c0071c4d79b3f0716c2e84e227de63d0220560de7a87d318943b99fcb12a1a6ba56829573c97d31a03f4157f3e3c6ed1c5701210329c7cba1b8498ca5f24c793df799fd15913f9966ab619ccf77d4de1de04ebd4a02483045022100ae05155f2c7d98643af9a05a380536204099ba7fb55e0e58b981b8b33c8ead6902206fa7f3dac8cff6c7cb84a6e8e6701374e9d0c8a519993fc4ad809afad1b8bded012103f2216b88b1e240346f4337010640912500d1db05ccc4854a41cd49926df8edff02473044022065d6459337f45dc0dbc745c6dca24a8da7150b145d81f9f81e85991a591e2dc402203a7bcd7a58d272fd830f85805a24f85182324e3b25bc32d95f8b7d28cf85231a012103211e96e3dbb5e7ebdb75cbb726a812a6bdec866d2554301bf79a543e3dbdc71c024730440220798f28565dd4a662418fcddfdf0a9912564075c5c3b9dcfc36bb4859da86d7690220456fa932fbcd70d4a9b9540ee1d5cc9e6d1b2eabf2148d528f6e82922897328f01210373847983d3c2ce437fdbefe671cc021e483a087f6d9e587a413b571837b7e7b802473044022028236dab2743bf7f5a5c04549237e594ce4e110d6d3b9c30e36f42f08748fa4f022003657d71282fb6313b3a91ff5439eaeff044dbdf17cfba453e35feb76f983f61012102776d43aacdf9b16a96126357d35ec71a57273ee674b6cea2d65ac45becfdb7a802473044022004f20edb7c4c3b79967c53a89655b19e09c246df3f4f94926eff0836944d3c1402200c5b64f7537585eb05e0a0e3a5d5e8efccdcef4e8448a2f7090c45a87feba2b90121032fe75bc44bc5c8a7c5a75dc2c2330a69534b681cb9c6e0d515fd9053260d20960247304402205ccfe88e83e80299bf3332089785a1abf2db2935397f0499d2773f43269c4817022061d4b4cb27e873dd71aa6670d404e30e63115f22402bd839a80bce50f1521b80012102501bd72ac850ca8754066f6ced709b60bb4b479db7ddcbd52789210898f17fb90247304402203da71d63ca1546b703d44b8ac196e98ac77cf85c687d40cb3858188d99e9681902201165bf2bde79c162ab24bcd55dda856b416e44edcfa91a22f162065c4a170e38012102fe30bdaaa858108107c5fcbe200d40494e661c82e5cb46d6098e9c059a32f59702483045022100c6ac1f83bd17e208fb71bcb0f608f6644067e21b5a335acc56a84a991e1b162702200f5a3f89d0c54e9556fffae32e78937bfa769a0be2c52e8ecbd66c0d023b33c80121030c30bbfb22cb96daf6e6dc13742a325fe3940fe195adc72196479355387f82190248304502210089cf0d591096e0b622bdc758eef84dce2b2ce0e0db753bb2ba4c8523065107ca02200b4fd948a1ecd48f140efa626aa0d80b963a64c5671c1303f6503a2380c36bad0121027096322862c819bf45eb4c27f33f26961468f863cd46f89bce24be1c571684f902483045022100f39826e33b4c458b602ebe7a5e718cad73c0fd5ddea164bfdccd088f12e0f88f0220680bbaf4997ee59ed1514ecfce8635b45b11a35e4a01311cdc992b308cd498ed012102c2a64c5b7a98074c19599f5f1f416b4ff90971252c4d9ea525557cd8d6822d4302483045022100d9e2992926755e4457d3cee55a652b2304f98ba8864aa537623f1f7b65f900da02203984ed493f47c163b71f626c6cd0a5389785c4b4e35116fded4ddabb72eec9d8012103ec81b4d4f987b02fda706639136f86d603452e57b6ef756ae1c76b71badd048102473044022022e49bcc0dbd906c7148ade9499bc15af1079336a51b4f0c4595f6986e5c4f3e022001c2ee849e87ef35dd60f898ce18fe8972da06076e5a74b6c8c3dda6bd567a860121034c0ada023f0a2dc43e08610f10e0325296dfa0b082ee6dbbafef2ff8d458328a024830450221009a066596c2975b3824f9fa67a708e9d4a7df328466f32068d29dbcf44a21209502206e40f9c663ae72c2a44729d83d8a81005520be9e32c1fd1ad7fb43cbd9eff5090121025dc8d121df8c979e67868f94ada041ad7f5cd0cb18cbf0b892b52c4b702a065b024730440220148c82f0bea167ae43ebf940238b28607e280ad4cde21de606d0a7f26771e0bb022076d82e83d24a5fba9070b83ca51c3d38d44f0e9dd31a80ed66f3c0222ab1c292012103585ed1c2a809d996b1bc1dc32d1a25699178f5e3cb360f1f4112821b3c14a58202483045022100c8bb8954b789016ad8135894acfe7af3ef87eb97515d9c5c0698019d4f34346402203c94bdea790246c089a036b1644b8faa4466ea7618d37e904ba1e7a789e89ecb01210330c55b9ad68338da8eec08f3ae18114fb3d5a034aaeee10b36f0de79f1b283d9024830450221009bfc2d5b9e85b8875d6a81b88bfc43edb80f86e82d98418165beaabda824d366022017d21d7413fbfbd2fa753712eec31cb684244f4b1eaa70058dd1f42c47ac5e36012102014ed4b2f63220d35cd5ca93ccab2dcc3c9529adfd42083750f95c08df1b84220248304502210090b81c20695d954ab9ab093eeda111f00fe0c2451a25c4fdf8265fddc5d2b4a602202b1dad93c205d4b2d8d523a92f64d1441ecef5d159f01b3b7b5fdb9e2180db9a01210244176aa6cc005d4fcec4d71e4ef79d6624035c8fa2b9e76083ed3fe4e8c7f3b602483045022100f307bb335cf1c90c3a2e75133b321a2cbeb1617a1dab5a081a978acc0fa3e6ba02202d6645edce08d92909b6b507912819b7727bb98810bae57418cbc032fd075a410121039f391f9ec0844cb8209c3259a35edbd31a6ffb06054112efa48691b2e5bd8f1902483045022100ecd210e6ce239901a428b2d05e50dba4f9451c0d62edb2a96b636a1a8076a1bd02201f3acdfd265462c8a21aa8ca1854109c2e2e60859c05e3515f112d1a18a5c9db012102501bd72ac850ca8754066f6ced709b60bb4b479db7ddcbd52789210898f17fb9024630430220495fb53bf49e6cc953db5ec5722101e47ba75fdbb1dcf805dab7941f4620c82d021f59b32fceab391b22ce88265d33bef2f01a022630a596c953226ac8327d4a4a0121036f2506fae6cd4764eb307535a5bc683f9c4a5149103b3ed2829728e1e718f5860247304402205c2dfd203fdf970c51e329e9bcf8c7d6e6dcdb24b04902429fac6b661313515f0220223c24708a45037672b72c2f989806b22e43e51558909323f1b6710f83095ba00121021cfd5831cc3b3381c18f7828d1f839e0abf5c316df5c73c1c6dee200874405b602483045022100c895868eb797d9a86312d2db534c540bef43c176b0808766482584cb52507ad1022011ac9f493dbf538c496dc5fc1226cfe35e8c0627855b319a54b6135b62dddaa201210323db8f65816c4e9265690c4953ed9fb54e0b5c3cfb59849ee450c51576e3b1050247304402203c36f1430a6d170042e2c3a889ca02df8d690324f1034c860f577d2a7bfdb87d02207bab4aeb37bced501acbd13bdea7f7335ea748c24bc2743a778783dc9ea9371201210302fcb58b028b3912c2337c43c985dc3bcd180e1181b855477517ad459aca0e7a000247304402207e1fe926381d35a13289d21c031e0c8ac7fa84fda324066cd8db3873d5686de502204d366da56a183214c861f5d41defb3dad494a377c147dde56c1a3b84ec51f47201210264ee5944ed3c74009c085ac182a2b4ec4e73c791ac8e9242cc9f9d79d63870b10247304402201ff1bf6f65e30b7e461e80f4eb4650e3bd3797e270561084cc6894b8b3cfc0d9022056f8788851058c9bcd7f88290f303eae3e520eda38146d5048df81b7df8b43bd012103567e4ee92470a2bd4645e82a59aa1bf5dcd281e2a23261af190917700f31ba2502483045022100a9bcb0f42e679669d08fc792306efd633e12b6fd77105a030646be159efca33602206ac551d7f08f62f4bf736c6f073ac3c1ab4fb2c940939f1c5e049a60462846e50121033d5e434832ae6d0f8b6fbb576928486fca494a8550238fd80d83e5fd5352323e0248304502210098477104652fa3f518cac69b393c3f802c3d12fef494cd6a018fc0e98eefa60302200b9d3e01d012240f6a030b989ebb79814f1c0ac827cc1008b2d22572fbb36ed30121034b646d4635ffee86fb875df76cdd1594690155ecfd0744b4ccd7ad4648e951a202473044022055549dc26ac1dd2dd09bd1cc8a6883749eff2a96e124a22a13ef1bb40b17972a02202864537b98182570ce17ccdd0652775acacaa0cb1c48d38050c74109ce97f95701210209e09ce07784ada23dbc478940902729e1c9f9ffbd7d1ced2a93ad5c55fe54b00247304402207caf999886adb90a010b9508e6676f66630300d12adf951a59f2f3fb8af56b42022064581bc3f33253cf85bfe0293c6c1b0ff1e9ffe766bd98a07640282a9160f520012103270b2fa17afe6f208f5d9c2faf295ee62e6be193ddc593d1d9fee3827d7dc3a80247304402203bb77fec20222e007c7507ad59e454c3a2ca3c541ff967d05f04969ff0dff8da02202cc8472222b7f3335890a5b682474e7dd0881959b893a5a174de6ac991d3c364012102a5d43936370c71639b38c8978429737940d073ff185fdf9ed8862ae2f7aeba3602473044022012ddb0e4e76734ebf2cb799afbee4fa9cad43312c86b49bc7ef1ba2821a7f0cf02201223002de1921e10528e5a84417aa4bdf5e62629b8e89b829dde61838439af7701210278dcc7cea540aad1262db70f78132c6a8d9f4ac18d01aaff0b77f232765688f802483045022100d19d0d7ef09fa119f4810f5416e1855d7ac40efde8adf240db860856c2270d1202201b1598279ff00c134dfd650b69a469177dc204e444e81ddcde2c3be8257f974c012103784d65506a63d3e78337392642b2a3ac693d5011d21ceffd3c666582b3e98a0d0248304502210092397dc3997785f6b60890a1757d234a2b4d70bff996bb363e04a8a8ce8a564302207b7719d3d957f7d5aad6b41e766096ded39d631c31c966821fbb4f4613a84a000121027ce713cf3614e86b73cd1820d375529a0d4fa7d12e3ec9c684e706671268150802483045022100e8b0dde4496cc19b3605a13541404896fa94abaf40bfb28789740441c6cec35d02205072ef5a660a3e243dbcef2721088aba6adaa76a66527a72a6eb6da87b5bbd5301210345055fb8d2f78566bfdd93169aa981578ddf68a82d6d8edd9310027262d356bb024730440220706e0392f7e1a8f921aec01f4fb3358c3b44ff2f97877c5f1bba7c4fbe5b004c022036c8f42639bf8efc2e818244dbdccb72e3e6914b1981008c29c3257d2364b2b2012103b1398bb1dda52210c50650b75db20fa5b1e62b2b33deddfdd7f673dbba041fad0247304402203e8ce5f348546a83e5097e5a757862ba5a35c75a61847012ba720884238c91e202202194eadc0ad0567e304602b1b5ab608e07869df80caa618d6934b56607052a29012102dbd4b250d570b0baf4fa036c4ae54a43ae69fdba53bdc8f40f645195c66c705d02483045022100d7491490313d77e282e145b8e4d514a82c724877b9bcb3dfb6cd393dcb7fa2a10220167c5d2d4352406af3816603252d09683d975a2c83b83b8a00688674354c87c00121034e2e68040cca587439095038236095cbfc83835401b9ce9450e17b2e784529c40247304402204f17e851adbbd5d539ecebeaa6b450ce927ae253b575d2baaad700377a5fc414022058ea7b141bb52633f746b12e786e7afd35b79c7e64b5e6172ed510154297789d012102ee84c4f98d579b61bb9ae284f648633309e9320c7dc98a8bec5b9d608b51119d02483045022100dd9f0fc06afbd564c2fc131f049e8fb2863493946a66e6c65282385a0d8eb72902206b1860f098354147a85b076ded26d6828023971f0d3adc85c760430bb73ed8d7012103beb107ff2189bd2703c0e176d5630dfc048a58295d30b865c61f4803547e582102483045022100e8e4c9bbf226fb24bba5aafa332410247c4a93bd3f52100054db962458b229f102207c0d1286d583909117cec9fb02e3cb8d6131e8eac5f80beba4195c9bfaaaec9001210247fe143825e2e4c1c8e6545c63df740a70a97be4761d374f8b30f5b1e005623202473044022047a095ee589f2b1d88778a55cf11469105a784f156754f49d8653ebe3e941f0602202d4d5cac2f0229ce53293148b20229902af2f33c7a303fd65ba3ab276d4cef28012103b9071bf1bfb33d657fe5b7f64a4df48a1c5f87b66cdf26996037c75cdc5cdc9c024730440220394c9c2177998ef35fc365e699a30c0664bd8e7a6c29ed956cb7016cecb1dde802206f660ab13382d11957090cdee0e6d161364051b3aec26de3d67b196b49ca431d012103a1a0889196d737e75be595f2d8d257b52c6a992e8ea5a61da117886dcb8bd30e02473044022073c857eae34c2a525e31bc46ae9fb3ccba41b9582aca644fe31ddaa6190cfae502206f81596cbe771af6b068cd8a4f05966a47d473a16b0239cd786101778bc0f686012102863ad1d7e2fe035e89da355051cd823cd5be82b8f3c0e6b4d4df6182825db99e0247304402204e6a3411eba783a3a51a4d1b807ab815edde816e6408b9bce5303f3edfd337b102201837693fb3827d180efd0785ff2f82de63754b7fb33a8dcd02850d0dba2ce3a4012102f68a86dc936b5371fe0c8cd4aac7425d8793005265c8649e31df4ecb23e1dfe7024730440220487915a69c01dd95b5aa6ed5d08a944a29e910be2c1e6ed7c8f4eaafb4e6401102203e3c6d03bfc135cff5691b0251925612eccd89ea851c1c09b174febe2dfdf3cd012103c1480cd7def56add9c15c8615dd8054118c18c644a70ee91d915f0caf1b9570c0248304502210085d610ffeda8510cdd36b4c8dcc1864ebfeb5ef4e7a5744c9dee8907e8c0ec2602204b5200130c047adc22c0dec6b947b0c79deece99a15f8301c724e96a055615a80121020d70467a2d30bdd11790d98cf205e0f4213db76ea540f375972326f9c3ac16a7000248304502210082920223708661808dd162ca540cf87886478e76e423e458d3ca94fd2719abfc02200c3705b063008b38dfedaa2d8e218a9171035cfa048a5d31abb753b520b7dff70121025963d123af79fbd5f910d45f26e9534fe5d5811e182f382a17fe71745d520e62024730440220679090b03c74ded5fd52d3c2a359b0d53512ba1369123bbc752e4819567320660220083c06548827e097f3d8a0eabfa438d4c98b278fe40715f2678ce9477ac15ae4012103f2c38e916c8a27e647420cdc665d48453901787df2cce002fb5b5d18ca2863ae024830450221008f3e0ba0035b657d9a73db7843b6632f3074ee2a684ebef90d6050f81b42186a02200270ed7deafa3c936816b75560b69cca38ab90cf89a433b199e0b656f25012490121020d6614d0bd4b46900101e0b4413abad0f5fc9b1b6efe4b26bf1afadcf06cd74b02473044022047dd20125e74acca92918d4de42402b0ea031f7617a5a669df41c3c55a4d6a3a022007cb0f5d3b9c51db83d9c2cf74341bbcd6e135eaa91803ce9dec42335fccd5dd012103e7ffdfb93d945c42ea553b23aa336afcc1353baab0c44b73df83c139b9689afb02483045022100d2e2ad6de146828d087a6e1e211ed7ebc2df5dde95336fb736c19840cf0adf22022074b882e25c3dccd2b319eb7d96786a1cfbdd53edfb2319bead54b88e67767809012102881f4851470d4cbf7f438ad72af73723190b5f54472349515f4f7c8caacc41f102473044022043b6adf5984226dae20bddee630946bcab1877478d196510d4c727b7a0ea258b022009e2fd0c2afc0394c0069653309bba588c564ab26454c2c80ff0e77dc5e6fe6a01210337ae78aaa63d0a29fd0832b0be85c552c4f680897c294ca3b1cd1fe979a6b09b024830450221009298d471254b12977dc6d5882bc4fc7df40f0f7844ac1412531845ef2355056a02206c729480705f6baef1b45d3fdeded139c66e8904c996e4a7f5dd2ee0e0c5a788012102aec5343087b9c122ed91e4f55177603f031106cde961876b4fe2b4b85e9ce625024730440220107fb3105fd9bc923d619e10e21662777a1571a7d35afb70dcb3dd0ea0d92bc90220215af593fdfc2570744fc2f14a085140d33698d2f8afe5d6a178594f781e5ca001210367552932b72bd5c26c04def0d32fddab3c85ad5f9090a77a4928f628006acdf50247304402204861f65ce8f38e9c346142b80401c13c693de6f41d171da2be66f49a5d66bebe0220621f1f456a96e0fc6d1767fdf5e47242bc5a799c06b735a7a0149977058229f70121028fbd20041b085782e4edc914afcef753ab75be0a4425461b085f3e3642cde4e1024730440220376a143f1438e1eb03d53f22a2a39402de0d6991ec5bfe60017cf6d1275f361502205ee4085303d86413baa9f21c35b31aa3208d56ff328cd362324fa6076b61832b0121029d7a122f6cd86e3ebd80566a9b4b11dab357abd55c5f6d5b7e90caaaec20658202483045022100a65b27012984949e9713af45cac9599e48e393644d78dd9debbc5c96e99a313402205eb909cb36e28a89e1e19418cf2d35ba030a4e5a24e6302e25e8e1e6168b2f670121039abcc3aa1010780e10ec8174930eeb1275356bad88f833856be8cde8dc5c943f02483045022100af27f09a9899428f3f90178c8dc58ef8b471745bdb9f65f4c4eb2ba079367070022038227817aad79d9926d9cf9e5936f05f24d23cb582539d83d9f79afa7080250701210228540c1ec00e2abdec57f20c8c9de63abaa9c84df05021c34e9ee39f5938e7fb024730440220302926d5dddefc7ca7f06014d5f9308f62adfa0d1f99035e8b1f2238c0309c0702206e44682a0fef71d130eb4b0e14075b94c4ae3bb7032a6187caa6b637d7c7471e012103dda33a6f2da4fc7749764ed0e9a87f70fd695ea49e7599bb02da2540d9061a6202483045022100dc758a39215887f2a57d1de3b67478f9509d5465908f04af0b66157c47914a1b022006e74258effc4ed55f53b410d5082d6b7d6e4c4f49f951313fb50e5eff0d79460121033e4a0a4ae5970ea4b6dfe78c0fb9d6382db3a2922c1685747763eaa44ab7d61902483045022100fac3d53d60f1866c979ce8d53d0f092da3c9a46baf6a9232d9a6626d06114f500220327e0fc7e2de774f99a603b14fe27171fc158c3e8ccfb476bd773a0fbcd5490e012103538418261407bb3ec3b7233aa3e153f4caa33dad3f5b772e83c4db7602983515024730440220792db10cff7ca14fe4f5350c3e0b580d91bd3fe7967eaaed1f95430d13f2b67002201f9b6a3488eb31031f99dadd83e98c3aa040fe49c09930f376aa02b0dc793f78012102a7c77383fa75597873ab4c89b04ec195a16ccd9f2e3e6ca767552b7abe4d87df02483045022100ee4a0869364f4d65e44c579a1586d3d8cfad114bab7d1d8c7860b3540b7fd42902206dd00bb81a606e49a95eb20d2e2fd1efc43c19c0727daa85692323777254345b012103500f802287793d257d212ec849952709039330f6219940c2dea0b840b2cbe1100247304402206f6d7aa9aea1362c19d6453a3b7272bf0ab806dfe6d020bf11df8a3af7cadc75022002adeaa7595148d5ee1358b12150a89169e146034d6731ed9a5e8803af3699a2012102e586650887c5f3598785c434f2fd9f88461cafacdb1a53c5114f48b303526c2a0247304402200fe63b1ff1a9c20fd9e32438278b72031b6c72244eccfa1e1f83d3c640680efd022054b6c887284e0108f57e6cf4f0053031bb0432007b35833136bb9d31bb068b0401210294be3b15731dd817078e640fdab0e6b20e67bd006a2e8ca4fca6af0711a1886b0247304402204cdd0f1e0988cd2c6fb8b3b28089da6657366cb42b28ae35622e1afadeed47e302205daad69532270bbc20b24c03e4006effe92c189ffdd395506b84547d18c7ecd6012103656be6d1bd16319b6f7bdc9e4ffcb280e4e1aa10fc9b1f4d6e23c7c822ad853f0247304402200ba9248e59c623a253d1e93690ed42ad6ec4beb1c852170348765d58a8d2c5fd0220308dd17be70245dc3cdc592c691c943d55677997247a2ad9ab5387b85b5299a0012103b19db9fbcc572859b9aadc9898bb06544d855f2414cb28e1ac9e75fd2fb790be02483045022100cc495df352daf402074fbfb29b01c7193b806284eb6f5de3f57f95369d1b3cf602206cd6616323c502c2eb92e31fb32a2b6fd6a1be6591cc9dabe6cfd03c9d41f1660121029a569cb45f347d5bf9da430829bfc1feef25733cf6751068b47fa03afb82559302483045022100a369a0599e90174826a9e5c2d7aee5ed76312f2a1004c74bb3bdd3ea51e881bb022010bf50e71ba76264e67a43388d259588b30979fe1c64a72783710e0b6b730db101210380dcc1cd11a072b51781207d30cac8f6a7874ce4113a66f17585b3f21e72534102483045022100de0ef3f3f0d45eb80334a68b2e04c97102b285c98cd990c81911259fbd43fa70022001a10e4853dedf003aade8b4882e7aed29c70c68173cbfabfcaf59466d499d17012102e75a6abddb32e13d48f0a5a329c2dbe7c94b082d1b60d03c34932a043abac90d024830450221009e9c5891f60caa7c8a71b8b4c0470fc3ccc6fdc999df9ee9f581c251eb31473a02205ed090809965d5eec64d947ed962c82d304071dd828ac86858cb7665f13df282012103270b2fa17afe6f208f5d9c2faf295ee62e6be193ddc593d1d9fee3827d7dc3a802483045022100bbb8aba5b50e43c5b7bad594cb81771416226eb5888d085e6742995a8cdc7475022079557a9e4df895d1b2d2287b68d73e67cb79ae3b0f4b9a1d23228084554eaa8b01210219cc54028d9ed3a630f130b5abddc8ae1a3ffae6c22fd7e87840a55d950eed9f0247304402207377fabd99b68978febfb0de4e147d267c82979202af613b6bfe30d249d9711c0220766a72bde2e1c8aaaeddd759829064b28896a37006b20fe49ce17185410860e00121026d3178bddff1529e27851422b08f6059e9f66980f7d2aea1edb4544d91f7ca4702473044022078458b33083a4e42ef16d40b5a8c48025f320918e4b447bed1a740d0a0cd4da50220494c680db5ef7a2338f5eb0de3ceaf6e0192ad9be7d981543d5159d72937fcc5012103c9ac87dd5f591543693edaa32430fd5e41b43ac023f813d3b8e977d818ffb9070247304402200a0c925e331feb6e6ad78c39ed75920654974f6973cb474336dc5a514c9a05870220325caff1c67a4aa42c565c794ee735ac9c7fcf5e01102375054b7a1a62c2ef8001210341d2a7f66011f91d4b41f79fa77c6823ae2dd4af8b0cb30d0ba345cc3fc6470d024830450221009a607879dafd8bd72da34127af4eb9c3d8549843953708346402dd2494132238022023965653c79f3576e7f726699a5674e1e5bb167a50d76774eb6e2bac9c8a7aea012103210233829c79c08776e84faccf2b25266690e336ca656102a1da74d398ebb4b002483045022100f201ecc866e92931b0355d8a6c9d7943523ad3c471cda0c4206301f38834ab9f02206339131856a1555e2cc10c617d83d99d65925ea757a2e19bc366942872d50593012103cb54959e995924607f3e41e8d9d4343913ee1d64c5491b8286e4efd0f9eb8dd602473044022026e25f308dee453ace36cdad208a6eed6eb5f3e904aa5413c34d2cf44155929c02201fb71971f7cc6a7bde4256a01d5f8054f3ac493e6ad0b44cc66dac895d9132c0012102f5564bc08bd3d5301639de75074e89e516fd9fc62fa134ebb2229b49cf014d8202483045022100b03cfae11db544fc9795cf5b0a6f3c9dceca43e2a67439edf14caf1a0832954a022078c42689f74a55cb612a16661394abcfe2032edf4fc535ac707baf19468ff6800121035a29cceb160120def257d8041b0596a4c839280c7b138382ca978fa1b02e6bdb02483045022100d9bb25e8b4fbfc5010bbe9d7ac2ba8d4f95cb03a662c483483e8bd86955bfa70022000da4c4d9c5418c7c9b17aeabc83f4caaeb48f4cca80881bc1870eaf52cff5380121037f247b984f0f2528cfca6698bbc20f3cc72728e18d7398347d7ef13cabc6983c024830450221008eb66b002ba9ee1950b3dd136f77bc1501bea34657d31069704e074f0de66e8d02206f1cf6f1760afd61d2c2b34e6ef2346551303ad5f897781a3eb9cc6ff10e1a1701210337d90bfc04e80369b1138a6d65e0a6a85c84f17362b52e8d2937aacddb98a4430247304402206526323284def6a25ce50b6c08e7b46e67b2f8e10825de3a3970db2f6c5d9c010220522ac400bec946c5270c493cf4380dc16dc3cfad302e6456194b2c88dba82aaa0121021231e4ef3dc73533956e54a2372baa1e360ba5af54790f7756b0ea81b079400602473044022042d9344eaae6b005f3c1543600cb798abacb65361d3e30b5f74317547a65ee5a022056d02c63a33f7e1d737f9b52b35f958a59a6f4464324ca8bd7c9dde856694fd2012102028e177de16b0ca1c9aa9209596c962bec0036c03b68873cb14f5b438642919c02483045022100c841f303b959a594b3a2dc1bd08327263f04ac56074f600202e969b34393696c022023d566dd37927fdd4068ec8ec5091e4870679dd4ac78ae20d9907e262fe20f510121033c964caca1410752a84c73b7f68f3b072265d8b8fb31494cdebc84da596f99e302483045022100abd9f17c46ead0855f5b7d2d1bd16a95ce7b6c41f26ffaf4a83f7e394544a1cf02202b35ab9a84067b56d1c5d5e591727bfd1a2233a67b246bfe029bf8095795a0b401210238cdfcdfabbe463bac9e200f75d5cab963bbafbaa907375f47984b404033d50a0247304402206d5e97b4e3b58b6301b79e61d3715dfcb804384805f9477ba11ce5fbb27dd766022046b183429c7e2dd30f8bb6c7cba144d67c4864452456d4bf17ffb17e86bbda470121033bca48ffd8c7f83e2b398e21af283c9a2912f4bbe3cbb5649b364fed57e877030247304402202b618fc4cd7751bfbfddbdc23acb4db944a158a48064fe72e0f8e044b05d0132022033654f7e0e2862961a0acf82a7fe2739c6e17c952f2f5db59a5e89a6cd0ff24e0121020336a8d872eb3186d9693df3a0eb06f40950e1f969ac5ec2d54b6fe25217d9c4000247304402204fd583205029e9cf37f80eb8f08b1665b91029c8a4e057d209299ad137e06745022061baa825dcd11e24af3d38d64eda3c55d165f03657cc1c6f4457c7281c51a08f01210364fa22342cd13a98df5f63285ca37d2b04b0e2b427a3cf540d9ff31668cfa31d02483045022100b46bd3b13d7a4a74b6328d9375d3bf75c72b5defefc4f12ca5f089fb14e9132302205294ae98fbb4fbf0119c5fa6dddb613406eb4d054019a66a24aeb225f6ece8fc012102fff44ea2872a83c98bc5d92989942ea5c1c8671e0d9770620a02696bec6a8bb70247304402204325c1122abee2da774145763ffc178118ed1cdd639b6b2f1005e4ce2f744e690220590dc5f59b46a4f4d2420bc8d8996524bbc1a543200a87336065976d59ad29bf0121036a84a44912ee4bdf10756cc66f514c4fd1d7c3cac73b9b2858c12788f4fc86920247304402205f41d56189dc7bbdb2bcc49797814d4e6b92384400dac69ed7d60f743fff86d202204e836772ac4ccafcad9c4f570aea5b4201bf639e18bffc902af5bb45c1c01f6e0121024e4b4fbd49255fb6cd69e84b75ecf432e9c089c4de4ea06432df18f88cf0fcd102473044022004efafaa0d74dcc6932789a2d49c2c8574e2f1b56b041c80320c76ee04759eac02205a947da51eab5697e441c111e4ca79d19ae2012438b3ba0cfa75f25a429e9d5c012102caf7487f599ad80db7095552572354b77c83b8d97e11def53dc7765b95a1384a02483045022100cb6d67f49f5170243edc2791019148971789b82ec515ce7d2f7b4cb47dbea929022013d3b55e7a3719ea161a920e9efc6be93b54fa7846a04b1e39f22e33b152e36a012102bf8ca31ebb62b3a1b26a31c3204272221c23ce0dd7912f6e3e3ec7c50adfa11602483045022100aeb6be673bbe805b7a9a4839216ebc043b55b3c30e4d1e48b3d3760583a7c06c022035cdbad9d51c89be854c9978a527628b2be98f4dc2de08cd6367dc970c8a1f660121031031b2942d224b53905591becc2a1818f6f82d0c82e36a7e85e03ee0e2b00e3c02473044022004996811bf704c685459d4b5536692ebdeaadf923633717bd0385bdf7185aa540220693f9b0cde55a4d77b13561abda0e02be69003f450835573d2e87e357601516b012102e71ccb3fea7f7b1e2722188ac0e042fd4ba103eddfa599179fe2ab1dc3177bc602483045022100c159d21aee08e58a1041525f555612a9d4f9a956f85d69e3094f1865c8bced2d02202f3165dea251e794cfdb2566a2e4e45cc92620d96a948c7e5d2fb463ca19fe8d012102164a18a1b541b4a9af617b712bd9147dff1ac23d79e8360d86496062a79cbe070247304402205174e4598d97988018d9e2983dcaab69edc11531e6c74ecb7a58fd4e89c0552602206cefedbb21cb20c4b6a73f771540c5374388928b4eeb29089ebd3d54b03230a1012103250fdc45ad4c2b8e676dd115eb19aca2d3a4e8b28cc65baabc9dd0812868968a0248304502210099f92d18bec263ef0c56aff199a0bff68d5809d76f2bdb244c788de7e214723702205c4e1f7165d751429c5b5c3ca5d234319da9e6f1f9141bd31e481d49cb26b5ad012102028c7f2a9d341b162e1b911f50acb2aa9ce51be08fe9086934251ab76fe3063c0248304502210086c2b5258e650d6b6f4bbc174dff70eea6601b73d489892b6228ca5d5b08413f0220189eda01391e6e46dd0a7c406fbed6558d2cb59fb24d91351a20218a48c0627a012102d494011ca5e164b0ed1b0fbff2f866b786d187069a8369908ed42596dc4b3c7f02483045022100828ab55e671a5a7d5f8163761b18d909e8fb7289a5529ea7d9f7fb88704b0e9f02206e1bfa0ee1800976089ba116ad7ea8a5bd4716494a65c2f3a866939fd405fde80121033593cf4d30e5c45af3f3e13b15d3cce1814588cb7e02b02f3d32f7fa16945c0502483045022100d2b14ebe8b0c99bc60c9af5458d8c97fa2e0b6bb398efe945035d450bf85973402205eb925af30c712384ba72d9140207cda0bf633c30b44cb89c25c5fb61481cc09012103a3887c5276169bdcb07a3a5cb0bc253b7cae81b8615acc21444c655f34cb735802473044022039302919372b5a0ada302d383fd7524ee79e41b2b190c06831afc31fdae2ce820220436a79706d688d3ea5531d476ec056f6ffb7fbc31962828ec1fd15759a0f6bed01210352dd443d48941d7cecbe433ca9e93e8b61b8d370292953948b9cc3f5980281f9024830450221008173d573570e866ecad23e8c11b773a312c7419d699419d4e00717f405f53b93022008f6fb019e0b93718d5f9d820ee98798b169e852222d94bed3555595aaa8242601210222390296151d01d1713214520f8a07b522ffc4c95b72d17daf0ce7bc2837a929024730440220213d3b2476175706471f324ab181325e5ab1274c53e81ecd551edb77638b29a302203d22cf2171a9dad1c6b97d7b8fb6c6e00c44081bd3c03290998b8ee20a16e7520121025e5f8440662a6a768dd4b8ce5b6b0f1a5e11f76a829e57b84e773002841d27aa0000000001000000000101dc49074f66bf493226a9f414104d414f699f576fe577591b3bbc5b4911ae68bd0100000000fdffffff02e2280f000000000017a914f419375a93bebf1a941a019ea6ef564b27ad540f87e87a07000000000016001404f60164db6cc0fd51adc79ddc1dcbce8fa7f66902473044022070f51fc01eab876e8fc1b9c9c7aa65004e1612118a7bd431fd77096d494c4a9d02205202ed9d682486571fc8cdcf5e02147a83685f992165fb1ec2051e2227303a5201210295dbf563308405278a84194111444ed0a25bd60331db14bcec266f3a6756725700000000020000000001047ee4643957af5cc2ecc8a2cf8d3e9ccd11f5a64fe8452b217f1065482adf48380300000000fdffffff2afbd9f3734a49c08360a4c5dfc4f3450d36195b6972cddf308416d23dcac6c80000000000fdffffff9d13e1041e6189989b5b280de5a932a2c20489da76e40dbbdce60a6b26cc3c1d0100000000fdffffff80c58e75248b4331a38e19402cbb066523d91fa022f9d8cf118ea97760fbc3930000000000fdffffff02280b00000000000017a914c1dee84bbd4d091f72f23d8006bd1f7ba8271aad8741c400000000000017a91435541cecd1cf46cd0acff08aab4396bc1c66fdb887024730440220642e98328babbaa14c23fff02ff1c5628e27d30036f62ac43b8359ca2c31da6d022027a18ec9955d39ce7f832a7334914e82521dca3b1b301346e36bf7e85350a67d012103d0b1a97b14f81c347e0d2de5ab141e0ea5a80339776810b3f250703f5fdbdbd6024730440220748a537d7eb144adffcb8553751667c264cad2ab94746e5ca7ce0e5a96c0713a02207c20c9de5a784ae1bdabe8e29c0ca80bd9760ffde21219d036b06fd313d005590121024dad609f44f056baff3385f11bea0c1bfb9fb94db70beb7f049051bef61ec1d202473044022017bcf0ad330bbeaba695f1a4a90ed2d993ef6692a92acb935a4f0165ecaf6e4c0220015668e905bf163129d42bbc9609e1e70e65cace90effa2208ac308de00f0619012102937673a5216e95fcf6e1486a1ce858d26a5f38f4336a384fa8d6fa6ac55b312a0247304402207b24a9d80016a0071dec61cf290be8aae9bf45c51b936cec231781d10c15b9420220611e79502c63c519b59d92bd2121bcaf264e6b8f7dd11a447d739b22ceb554ab0121024dad609f44f056baff3385f11bea0c1bfb9fb94db70beb7f049051bef61ec1d247170e000200000000010163b4c18c8309cbbd71edecfc165a98d05f651102a26c0b4299ba6561d8f8e13d0000000000fdffffff02c64700000000000016001411254476f74e7600b3f117261261bc7c654e13b62a8e020000000000160014bc61df7ae4dffdd660f1baf2e6d9f7fcbf2c7cec02473044022005c77e0d59c27c2dca1b9c5f8cf7b2e6281f937111a2bcdd8f60e5630fc895dd0220529baf7b0439c923d653a292ddc7be9d4fe1bc6b0c3c31156dbaefc3f0347676012103329d370348cd8701cb45a100dd628c5c3594eee0a67a7db350b0b223f4b173fa47170e0001000000000101b59dcec759e1dc61954eec54cdc0792ca3e4d57b1920fd7b1abd47bf0b0fe17a2000000000ffffffff01d3861d0000000000220020bd9fa90b78867cbd00de37f031043e2faf284e89cc95bf4e62b5c2028023605e02483045022100f7228e92436aa184fd3f5f5ada2cc8c1ec38419f1c79a5bb93dc2053e3c2de71022046e68e1200d515fb5b51c62272523f8cb04a80de6d6a2c25ee1994f7263680d10121037da8b0e908dd7ca9b6f2da4c87f94acc18ca304cd32b25c625514665fed42adc00000000010000000001014d66083fd2e2e37eacbc1054044258f4af896e9a2670f5dd98ab3c91131ff4763e00000000ffffffff01d949070000000000160014b22280b6a7708290782b5802444a557e50d6203802483045022100ccea46905143d978150b30be3adf16da345720cba88c446434eecddf6f3cb14f0220539ca292344a0ed3e18c1ba81373bb5795543c57eca59db8f2bac60814ae33780121024d9e9fa0a7781eb6fcaee34468b5e80be1c1857fe1a3d08e1de490a97ebc0e1000000000010000000001010290d4204da926762bdb806dd1e25a3ed9f1b649753c79537882d2d4e6e2faa60a00000000ffffffff01019f150000000000160014b22280b6a7708290782b5802444a557e50d62038024830450221009f207ac5eeafd80b0e2c23cdc48970bc8c800234c5d96c6564a04cff84d2a5620220762dabc436fb525f4c8ec841fbebc083acd47e724ece2842f480346098a59121012102a4b7c54adbda35668920130de619cc22fdeaff8e49d50fdb26568cec73ab152700000000010000000001018f7f3848dbadcb521d08cc95881c3f593115d92987c1317a191956a3463e2b090000000000ffffffff0120bb010000000000160014b22280b6a7708290782b5802444a557e50d620380247304402201c6dfd0fe4c7b702afad4d759a79f2e6532a1c88b8963395c5df3187e114271f0220734b963605243159c813d91d172e174b028430fab855d03a0903888a5f4cf3d70121033ec67925ea522fb525067d5d4ca7e1794fd07483c51696c194c1de494fc4d2cf00000000010000000001016469a245ac14ae09846558aa74b7398758f50b1d1b11817f96443d2a22505c6c6800000000ffffffff012760040000000000160014b22280b6a7708290782b5802444a557e50d6203802483045022100ff356a90c80f2518dfa60e8ad50cadb5c0f091a0bf09fdb0e77652189724668f022038801f9a87a9eb607d42a3316516d3207dd86807bc1c0f764c0272637afa753a012102b319d89543038785c2c54c0b83c33563ca502892130cc859cc07bd224b5b845300000000020000000001014d79cb0343146b8ac29ddf06dce39a15bc926ce09c1efa0554e2731203fa577f0100000000ffffffff02ff05000000000000225120309d9f5ce086e8959f0defadf411a60e0f2bfe5fd8e3604c7f7865d18aa5de862da100000000000022512085f75b6cb9b7600a0f0ce84ac998c1cb0594b799b520c3acaf2b3176daabedc0014026f0c1f1f18fb6d652371ebc114f65c00e63f7141fac14f3b48be80af3d7b7dae5b73191a40b75f0a74b34ea47224817f5c1f2e065e7869d51f4e4b7bfa1742f0000000002000000000105c25e68002bc222c793f5f298c54332d07206c82ffc78307bc2f9befb23b0efd50300000000ffffffff2bee5aa3061bce29aae813432f9683b5835bfce1aa48854b08b08ef2fcd1bd210300000000ffffffffc38fe320b69cf474e936a6362a594baf7a39aba04bbff34add93939e5b3dd22c0000000000ffffffffaa16598a54dc47971e9b4a48b40da8989d2bcfbe837c60e35df4cac59b0011580200000000ffffffff0b3f0703a7727ef47b326c7cecaf5ce68479033768169a712c6f4bdf570881780500000000ffffffff06b0040000000000002251200e51d7c7937669f0f97ae7174f8261ac9a54b9e03e306450506362a30f6011b74a010000000000002251200e51d7c7937669f0f97ae7174f8261ac9a54b9e03e306450506362a30f6011b7002d310100000000225120efc162d5459a87ee45df39224678de13a3856ddd7bee20aa6e5ae4204171862358020000000000002251200e51d7c7937669f0f97ae7174f8261ac9a54b9e03e306450506362a30f6011b758020000000000002251200e51d7c7937669f0f97ae7174f8261ac9a54b9e03e306450506362a30f6011b77c0f0300000000002251200e51d7c7937669f0f97ae7174f8261ac9a54b9e03e306450506362a30f6011b7014075a3329f58ec01233603147cfe44994007df863ef1a23c6a50b7fdb907a3851b95091f7d7ee1186a0b8e0c68d2aab560162a4e98f4e54ba6537536c46816794301400da98708a4f55bfe88d19192112cc1867d1dc2ea215c4ff1f3c57a11af5be1a74e88ac5755922f9d671f1cd7cbf7d19ab295b4e880bce2e9969087d2282e9b6b014123be50c2de4f686737dc6c8fed7b17d4e960853ee348f519ec44937517aed5d7fff117101f397888dac4fb076278fcf542aed2b55b7924846ed776651a48ba1783014051cc558c5b106221a18b1247aa3d910245aa3612d58bfd3436442cf3d7d70d7f7b5fcf242b7e77a5c2813d2af875e5b9ad1b9980ea67b96c7814faffe790af72014008431a7e8b6ce7010ae9eab10c00f91b2a9cc11d2e78a66662b173e9511b1d289ae5e7196fe7afbb8fa2ec26f24fb43847d26d6517ca1807f3c92952d5037ae9000000000200000000010429fbfb4db361db0665fa45cd50021afff4c5b40a92e04efb3b27aa3f6e92e0530300000000ffffffff29fbfb4db361db0665fa45cd50021afff4c5b40a92e04efb3b27aa3f6e92e0530400000000ffffffffc10dd6a92325a03e91446c1a5a4948c02d871451b941b6f05c13e42bb4e46a540000000000ffffffff0597841e7d6fe501c10c74fb3bd206a8fabe30235a4d19d4dbdbb383c8397b8b0200000000ffffffff06b004000000000000225120b5cf3f99fa093d4faf177ef8b89e41ed0fa6c3ec20f11e7aa6eb81ec01289b642202000000000000225120b5cf3f99fa093d4faf177ef8b89e41ed0fa6c3ec20f11e7aa6eb81ec01289b64a0a70800000000002251207add1a05d755c07b9438453a3ac2efe3eebbdc942556f73debc8f5ac5549adf05802000000000000225120b5cf3f99fa093d4faf177ef8b89e41ed0fa6c3ec20f11e7aa6eb81ec01289b645802000000000000225120b5cf3f99fa093d4faf177ef8b89e41ed0fa6c3ec20f11e7aa6eb81ec01289b649ac1030000000000225120b5cf3f99fa093d4faf177ef8b89e41ed0fa6c3ec20f11e7aa6eb81ec01289b64014008928efcf2ab551ebad035b456d320eec561dc72a388ea260e16d7bdc348854d0d80ff7af62976a91f8482927f5b4eca064e86e5eab4d08ffd57d283b13111e001402090c90292a3da9a7d548b5f56d00a7edc1146d140b8e30b1c35739a2c9c8d9c03357c88877e1ae1cf1f976fd8a5a1dce3677c992f043bfc9979b7b3a73f437b0141360c21d6d7fd1f20045f48ed035ca120542fdeddc79243dcbd5afdd062ab03a1afb250e0bfe6e151a555bf8d2703dc02eb36e6697eb4416d3811e2d0658f523f8301402d154428a5089073d518cf2d779145ede93ea3ba891679ed0140bcbe1fb603667c1c4823f3d3ffed273da341d40f67bdb8effdafa68ebcadafdb357b1018ddb600000000010000000105a4a82b883a7dffdd7af78e44202a4ad602b65582a965873e86e9d5fb4f767f150000006a47304402204da742d56c2b11ce624496ac02dc7667523ad3e04c7b4d5359cf65a79f602f5e02205be2d3f3ae2e723d8188add248eb48d11762bb6481788c40a80deb769afe1df9012103b25e882437d9871531c811e50a811f70b958a9d38fa3247663f3480c489bd026ffffffff0169880100000000001976a914ffb7c2f9bf48b00e47ed6fbbc3f1b3b17f72d15d88ac00000000020000000001030080c12ca778c30ef38d502268e07fc84f412728ae8422d0b61d19cfde1945ee1200000000fdffffff8dbedd4429e994f3c9ef8d4988d627db984f4d78742ece063b8abe543ff9ca7f1600000000fdffffff3a276d71afc7d0f34c169cca2e4e3107d9ea3f4d1c050e8b6afcafa0a8724ae30c00000000fdffffff0284420f00000000001600147c5c0a145fd5dd0f720c9aec941acfe746dfd2c4b2ad000000000000160014c8e7ee19032331ec99f32b145d205ed6676dc77d0247304402200649e9a48378b762b2803ba71d52e2bd519c6df0c0e0a02c59d4c51820943f440220749cb8d1bce1bc7ea9b540cb058f69bd1e442ff37db456d886da332541b46ba0012102d6c78b806475c702a882f7a0e606d327b55ae0103b5fdd80600de2753b2550fd0247304402205c59b6172b12caf309cb5adee52637283479228ae2c8491f50b5abf3350b1f3102200112afcb73074b28e9d98ab4bbb24c8116a512ce4b1f6b144e310ef97bb8f4cd0121028b17ca2c80d6e5e5fb0eebc7441bb422960ceb162562306f07c607fbfc1a48b9024730440220287ea0e303670d112bb3e74dc29d4a322ec404e85dc20a7ce521df87ddb116ce02204b90bfe433e2cfb0a910c7bd9658dc9832d18ce7b0b40ba33522df5f3bd4a603012103b368d8cd1a9fb99a974f9c61363a96878cbce075f7967b3638bd8165aa0adace0000000001000000000101bbf1cba1d8cce7979539db944a81c404a94d4721efaa599675888c00042fd46d0100000000ffffffff02f82a00000000000016001478ebe4193ac087d1ce7b047a8ef4a510439c7a0e38c0020000000000160014a8e1ce0652f530b7d3e83be7c81ba766aab1614002483045022100e6e0d8ed0e16d044e2f76c2be0281cac0f91403780282b5af86d09a5e1c53b4902206cff60c4d66c49cdc28dad5f3bbea891eb71422a92979319a2f063968cd705ab012103b14575b6126d41d8abbec12473dc22816930cda4bd0d7ab2807a9872877dbcf60000000001000000000101a7c5d3e84c0c28570ca16b5b13c68dd4f8f42e0a5f48a7bef68df79174f042021500000000ffffffff01dfc40300000000001976a914221d7c4edb5f9e85434f861ffcfa6f63d56ac02588ac0247304402203612462e373a03ec59c2196f9eb934518e8bd9470d7778bc80eb1efb7c37c67602204f7f8a8a61042840c2f56d07b80eff6c7d0509cdec4c4bd18d24968e718f9d180121023336c4bddf320a4a276d1b55bb87ad85b4457630015a634dc0f1ae3ce37e0e570000000001000000000101b0f2ef2dcbab9787d33ffdccfe7b5d1ec4e887e741326787c4b97689e614235f1b00000000ffffffff01c274000000000000160014dd985f67c8d8a5c60c9cfe3867af5b71c6f243420247304402207bf8ec375d482e0569d2afe02b781494b746762ceff33a876824ebe98b914f4002201d8f766948d46c2639394e652c876c5a57400ee939562029939bb956d37fa8a20121022b4ff02df3315659d372e507edd9c9f2d76047615135582e3223e14c4872b15c000000000100000000010101837c9c5fc37a93025f443b02a0e61b3754a0a6191b56650718dd75e4b32be50000000000ffffffff016639000000000000160014ed0209f8b75e63bc62ca73c744c2918eb676f3ae02473044022017f2200b2e782a73c96b0910e4850e15258b374042ac1f1017c71bd7f844581302203700e0defe358c7473b5cc445e0d9313d35da95010849df7517abb75281376dc01210353428649d0e9ce1958c683296d951085655fe73a96cf0440b3ee595b8317e78c00000000").unwrap();

        let block : Block = deserialize(&block_bytes).unwrap();
        m2_test_debug!("block coinbase: {:#?}", &block.get_witness_coinbase());

        let merkle_root = block.compute_merkle_root();
        assert_eq!(merkle_root, block.header.merkle_root);

        let block_hash = format!("0x{}", block.bitcoin_hash().to_string());
        let block_header = format!("0x{}", to_hex(&serialize(&block.header).unwrap()));
        let coinbase_tx = format!("0x{}", to_hex(&serialize(&block.get_coinbase().unwrap()).unwrap()));
        let txids : Vec<_> = block.txdata.iter().map(|tx| Sha256dHash(tx.txid().0)).collect();
        let wtxids : Vec<_> = block.txdata
            .iter()
            .enumerate()
            .map(|(i, tx)| if i == 0 { Sha256dHash([0x00; 32]) } else { Sha256dHash(tx.wtxid().0) })
            .collect();
        let wtree = bitcoin_merkle_tree(&wtxids);
        for row in wtree.iter() {
            println!("wtree: {:?}", &row);
        }
        let tree = bitcoin_merkle_tree(&txids);
        println!("----------------------------");
        for row in tree.iter() {
            println!("tree: {:?}", &row);
        }
        let tree_depth = tree.len() - 1;
        let witness_root = format!("0x{}", block.compute_witness_merkle_root().to_string());
        let witness_reserved = format!("0x{}", block.get_witness_reserved().unwrap().to_string());
        let coinbase_proof = block.compute_merkle_proof(0).unwrap();
        println!("coinbase_proof = {:?}", &coinbase_proof);

        let coinbase_proof_hashes = coinbase_proof.iter().map(|h| format!("0x{}", &h.to_string())).collect::<Vec<_>>().join(" ");
        let coinbase_proof_list = format!("(list {coinbase_proof_hashes})");
        let bitcoin_code = include_str!("../contracts/bitcoin.clar");

        for (i, tx) in block.txdata.iter().enumerate() {
            let tx_str = format!("0x{}", &to_hex(&serialize(tx).unwrap()));
            if tx_str.len() >= 8194 {
                continue;
            }
            let proof = block.compute_witness_merkle_proof(i).unwrap();
            let proof_hashes = proof.iter().map(|h| format!("0x{}", &h.to_string())).collect::<Vec<_>>().join(" ");
            let proof_list = format!("(list {proof_hashes})");
            let invocation = format!("
(unwrap-panic (mock-add-burnchain-block-header-hash u123 {block_hash}))
(was-segwit-tx-mined-compact u123 {tx_str} {block_header} u{i} u{tree_depth} {proof_list} {witness_root} {witness_reserved} {coinbase_tx} {coinbase_proof_list})");

            eprintln!("{invocation}");
            let full_code = format!("{bitcoin_code}\n{invocation}");
            let result = vm_execute(&full_code, ClarityVersion::latest()).unwrap();
            assert!(result.is_some());
            eprintln!("{result:?}");

            let res = result.unwrap().expect_result_ok().unwrap();
            let buff_32 = res.expect_buff(32).unwrap();
            assert_eq!(buff_32.as_slice(), &Sha256dHash(tx.wtxid().0).to_bitcoin_hash().0)
        }
    }


    /*
    #[test]
    fn test_parse_block() {
        let block_fixtures = vec![
            BlockFixture {
                // block with one NAME_REGISTRATION and one coinbase 
                block: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6930aff462fc5bffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b5020101ffffffff024018a41200000000232103f51f0c868fd99a4a3a14fe2153fba3c5f635c31bf0a588545627134b49609097ac0000000000000000266a24aa21a9ed18a09ae86261d6802bff7fa705afa558764ed3750c2273bfae5b5136c44d14d6012000000000000000000000000000000000000000000000000000000000000000000000000001000000000101a7ef2b09722ad786c569c0812005a731ce19290bb0a2afc16cb91056c2e4c19e0100000017160014393ffec4f09b38895b8502377693f23c6ae00f19ffffffff0300000000000000000d6a0b69643a666f6f2e746573747c1500000000000017a9144b85301ba8e42bf98472b8ed4939d5f76b98fcea87144d9c290100000017a91431f8968eb1730c83fb58409a9a560a0a0835027f8702483045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b012102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e8100000000".to_owned(),
                header: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6930aff462fc5bffff7f2000000000".to_owned(),
                height: 32,
                result: Some(BitcoinBlock {
                    block_height: 32,
                    parent_block_hash: to_block_hash(&hex_bytes("1dbc979696b7a853a962a6c0d42c41b47f57d9b6aa62c7d54d29f419cd4cef9c").unwrap()),
                    block_hash: to_block_hash(&hex_bytes("7483b1104341d596c1d0d2499cb1821b0e078329deabc4e7504c016a5b393e08").unwrap()),
                    txs: vec![
                        BitcoinTransaction {
                            data_amt: 0,
                            // NAME_REGISTRATION with segwit p2wpkh-p2sh input
                            txid: to_txid(&hex_bytes("b908952b30ccfdfa59985dc1ffdd2a22ef054d20fa253510d2af7797dddee459").unwrap()),
                            vtxindex: 1,
                            opcode: b':',
                            data: hex_bytes("666f6f2e74657374").unwrap(),
                            inputs: vec![
                                BitcoinTxInputStructured {
                                    keys: vec![
                                        BitcoinPublicKey::from_hex("02d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e81").unwrap()
                                    ],
                                    num_required: 1,
                                    in_type: BitcoinInputType::SegwitP2SH,
                                    tx_ref: (Txid::from_hex("9ec1e4c25610b96cc1afa2b00b2919ce31a7052081c069c586d72a72092befa7").unwrap(), 1),
                                }.into(),
                            ],
                            outputs: vec![
                                BitcoinTxOutput {
                                    units: 5500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::ScriptHash, &hex_bytes("4b85301ba8e42bf98472b8ed4939d5f76b98fcea").unwrap()).unwrap()
                                },
                                BitcoinTxOutput {
                                    units: 4993076500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::ScriptHash, &hex_bytes("31f8968eb1730c83fb58409a9a560a0a0835027f").unwrap()).unwrap()
                                }
                            ]
                        }
                    ],
                    timestamp: 1543267060,
                })
            },
            BlockFixture {
                // a block with 5 TOKEN_TRANSFERs and a bunch of non-OP_RETURN transactions
                block: "00000020ad98a2888b7c69f4187ef5ee1b5921a6fb62803aa8bd35826f7fb751714baf250cb5ef03478d35ed7f6582ab40232ee39744471b2bcb40b91db0f29102d695123379fc5bffff7f20020000001402000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b7020101ffffffff024023b71200000000232103ecfa5bcaa0d2b7dd3a705342be2e144f66293be99488c8e5c9bc3d843036f1bfac0000000000000000266a24aa21a9ed620a2609f2f58ea62134d1c54bf73cb6e0cf194cfbdf25ae32b55dd167ee64bb00000000010000000169cdf5fb51781758c7e77dc8e86c99248bb4decd3dd39ac782270b120a77d5d2000000006a47304402201db67a44a12472e8e555efbe826927fd1b67cbc5db42ba43a31edd2177fc32cc02206ee9c8f42629fbd988dc6091f46c1f7921cd58366531529ea2b91a36b2cbba9a012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a91441a349571d89decfac52ffecd92300b6a97b284188ac74a73729010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac000000000100000001c517ff49a374f8a41dd7a5d4028315374f875bd483a4e56bf946d76a0ec441f7010000006a473044022079f4cf76c0ce6da1c01beff79521817561f98dff27f63ce394a22fa645aa2c6502204343f6f7ed1a06e01a8b1d379ae11e5a4a6214c8056d68cde1946458960d5a46012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3ffffffff030000000000000000306a2e6964247c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b5300000000000000647c150000000000001976a91441a349571d89decfac52ffecd92300b6a97b284188ac80403329010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac00000000010000000128877bb55365102a106d3150dec58e23c4e38fa6d19f6cedd6d4e3bb4dc5f213020000006a4730440220515a2ad1c809a519edd17103bdb53578366b44b56983576e2bb96eab7571a54f02201b86aa94a34374e20a1d3f50d257e4da91a59e91af385bd7672f4866b2d2d65b012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a91441a349571d89decfac52ffecd92300b6a97b284188ace4892b29010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac0000000001000000019311d3968c1529d7c88df93518af051a28967c2e40f7a9d71581d1b3d5c153ba000000008a4730440220491ed78e9b5b6654d811d4d2586b95488b04914cdcde68ab5b3320e946fce23f02202bf2d772438b777008a0107c5ce5aff252bc96f613febb6eaa1997007c0afcb1014104ef29f16c10aa2d0468d7841cfedb8b5729689ebca4db38fb8f3fc9ab158e799b6d6dfc2bca52fe490f7acd38e351bf1d28b8f1f48736a0b022f806dd107a8385ffffffff030000000000000000306a2e6964247c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b5300000000000000647c150000000000001976a914e1762290e3f035ea4e7f8cbf72a9d9386c4020ab88ac2c3a0300000000001976a91441a349571d89decfac52ffecd92300b6a97b284188ac0000000001000000019311d3968c1529d7c88df93518af051a28967c2e40f7a9d71581d1b3d5c153ba010000006a4730440220707c69e458fe9e2325fd5861d66f71d79226466999a96e9c10184fd8c14830ae02207165850443badce9957b10e967bdd1e0eb6b47bb9f3e30ef4e1d7dfc762b40c6012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a914e1762290e3f035ea4e7f8cbf72a9d9386c4020ab88ac48d32329010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac000000000100000001ca544deb6c248c68a56d86e3e9fa2f93fcf35d6055acb116962421eb4041e896010000006a47304402206218d746f7d4b788362ba33557c1a57de815fe1d024b3a7cf2a45c12595db4a502205bc66b5817530820e5b572e9f8ce702b3c2beae89c836aac297b727b4f2fef79012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a914e1762290e3f035ea4e7f8cbf72a9d9386c4020ab88acac1c1c29010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac000000000100000001f433cac39fa99d6621e10148fdba962a98c0647214fb6a050c742cc423528cbb000000008b483045022100d27598ea9e8fde498f94d645e6ee805cc58c256163dd7e0bcb074b6f3498fd4d02204582fc8f281707f2229606d7c7287309addb6f21b44cbe1b846f3a447d78238f01410479ff722ee4dfd880e307d06fc50a248a9f73a57998a65fd95c48436400280372cf9e99a9952ded7723a68118d4dcf658efbaed2a73265fc63b44789d2d459637ffffffff030000000000000000306a2e6964247c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b5300000000000000647c150000000000001976a914f3c49407d41b82f30636f5180718bb658ce7fe9488ac2c3a0300000000001976a914e1762290e3f035ea4e7f8cbf72a9d9386c4020ab88ac000000000100000001f433cac39fa99d6621e10148fdba962a98c0647214fb6a050c742cc423528cbb010000006a473044022043cbd8b3a1a7f3eb6add66c3af952d27556afc700c48719792ea16c0b553b7ca02204c9c7254d64a58f3bf8b1820bcb97a177ced97f9458fbe3e1039110560d2da7e012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a914f3c49407d41b82f30636f5180718bb658ce7fe9488ac10661429010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac0000000001000000012ee074f816ebb800d5b3e8497498a8be0b7a578d831b7a4617090f224d20387c010000006a473044022037a59ae75fd04216cf466b49aa22b2f13b9138009d2a399199a1add8dcedc102022032d50e8fe0b0004dd191686fe4e7b15e523a1816616ef9cf1362059941d8cdfd012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a914f3c49407d41b82f30636f5180718bb658ce7fe9488ac74af0c29010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac000000000100000001b4963d5c40a849f865a884e68a837d7629cfbdca449f53131ee1f54c8517e3a8000000008a473044022057c1bb8264ea497db03388d6ffd7db0e0e9649b9c26c38b0fac52384b8d0582102201520db2bc33b3dfa850e2d53f82495cdbfb4fc48f7fa3f30182ed17b397effd5014104447019ded953edd1bcecffbc66a555f822675257bacc0d357c1dc5194849367354c551e2c2e2048cb927985c8528e24120addd9aa0a2c68b23b462f337caaebcffffffff030000000000000000306a2e6964247c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b5300000000000000647c150000000000001976a914afc75a8f8fbcb922248a663dec927b33dccaed3788ac2c3a0300000000001976a914f3c49407d41b82f30636f5180718bb658ce7fe9488ac000000000100000001b4963d5c40a849f865a884e68a837d7629cfbdca449f53131ee1f54c8517e3a8010000006a47304402207d0349a5ef65a42694fedc2baff5baab8154466c8e8942787c6b1476fddbbba902204f6147a332adaa1313195e6a2ca9e545d00d233e5365ff4e7476c6b69a1808bb012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a914afc75a8f8fbcb922248a663dec927b33dccaed3788acd8f80429010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac0000000001000000011420e72c7cf93746e3a51c79798dfc3d92efcc5c035bfb6e25c573b34651fd2d010000006a473044022011d7c5e4326e3f1d469c93795627473b78a7db9fd2a0ef5a89c1640a7cd35c9b0220573811fb6831fa031ea5396c39e3a8bf72ec90accbcc22e63e07c3c197894eeb012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a914afc75a8f8fbcb922248a663dec927b33dccaed3788ac3c42fd28010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac00000000010000000104c89617c9100361301adc113cc8420f0a2884465879612e2c3e7702c18e8bbe000000008b483045022100c83dc003151b3dfec89c1d6a51be38f226754c57139fbdd01bbd73db06fece19022047a130601c35db08603c0e28c8ad0bee6f69b881a61cf5285ffd816d09d53889014104a96a8355b6c3597bb9425c2ef264ab8179ca8acd3032b62980d2067261b37666b66510983e6d60d49bbd28129f0bae4dbcaa97c2bc61a6b2e48ca1625ce81335ffffffff030000000000000000306a2e6964247c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b5300000000000000647c150000000000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac2c3a0300000000001976a914afc75a8f8fbcb922248a663dec927b33dccaed3788ac00000000010000000104c89617c9100361301adc113cc8420f0a2884465879612e2c3e7702c18e8bbe010000006a4730440220577b2b6b1fd42425e6cb6d10076c3312253c0ba4d511a253d252474fb4f13e3f022013b0404d190e7d1b13c3d9003425ac80dc5b0f80375cbc3a71ebff849fed4b63012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff0220a10700000000001976a91474178497e927ff3ff1428a241be454d393c3c91c88aca08bf528010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac000000000100000003738deab0751512cd7c580f748a56e801a88e4b929efbe1944a51304f0f416989000000006a47304402205675beb7b57e0b97a8688dedd291a553fa189d018e4ce4b781aed9736578c4f402207849244e504863fb80904da0de12a76a409c827cc70af8a537389f7c11299ec6012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff738deab0751512cd7c580f748a56e801a88e4b929efbe1944a51304f0f416989010000006b4830450221008bb5d50aac7becf4a6b2207778c2061e54bc99648d9afb28bde4f6789d417f1002202359a08ec2bc1f56807f4c25996fe4d0f282b9e266631b6026f544620259d9f7012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffffe863dfc5fbf69280d9f9c93d861440d2e1eee329eccf5545213f73a809560378010000006a473044022037c9f5df920dbf550c7cc92ad1aa1627851bb9af492563716bd0da060cecb5590220715b5d0b73e108fdc6264e67fb56a77d409e6ec185b93de5219695368ee4292f012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3feffffff01c02cfd28010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac0000000001000000031420e72c7cf93746e3a51c79798dfc3d92efcc5c035bfb6e25c573b34651fd2d000000008a47304402202c963a8bd001257aefc0853e0dfda571dcde127be9b7a1221c352776b411032e022009d154b93ee42d8c2ca9c24a5cf9e0185d097240c7f7986ea3eb527ca92d78f2014104a96a8355b6c3597bb9425c2ef264ab8179ca8acd3032b62980d2067261b37666b66510983e6d60d49bbd28129f0bae4dbcaa97c2bc61a6b2e48ca1625ce81335feffffffbdb21912e44ba0d0219b15fb1ba735ea2c698930a13575a8db352a48dbd1fe12010000008a47304402201e084a2b11eed752ac476f31f92a979936f7f2915d644bd9485dc06fa1b80d9e02202b3e288ff9501938882ed932280f06204eead8aa41b8ecb5c4d3eecbe25192c6014104a96a8355b6c3597bb9425c2ef264ab8179ca8acd3032b62980d2067261b37666b66510983e6d60d49bbd28129f0bae4dbcaa97c2bc61a6b2e48ca1625ce81335feffffffc1918a15bce400ef116e57af1142857ce2e652d73314628d07cbec67793599c1000000008b483045022100eeebccac3625b93f9c1b404599b02f57868a62b49184c0818125fcff6775ca9f0220768cae6e58346127a85e38ba031a2f7732d1c051d9afed0d3a6c53fcc9d15b55014104a96a8355b6c3597bb9425c2ef264ab8179ca8acd3032b62980d2067261b37666b66510983e6d60d49bbd28129f0bae4dbcaa97c2bc61a6b2e48ca1625ce81335feffffff0190f22700000000001976a914afc75a8f8fbcb922248a663dec927b33dccaed3788ac0000000001000000041c18a687e19c484387daff4b136d2e35f8a4ff74e9901a985f422316e0d33789020000008a47304402202c36873b52b4c042326562fc6442b94f03078ac62cb15c79849fd62ac4abb2a20220022333118b124beda77fa54e07d785d57f2603f9517d4980cf26d4f4ce680140014104ef29f16c10aa2d0468d7841cfedb8b5729689ebca4db38fb8f3fc9ab158e799b6d6dfc2bca52fe490f7acd38e351bf1d28b8f1f48736a0b022f806dd107a8385feffffff28877bb55365102a106d3150dec58e23c4e38fa6d19f6cedd6d4e3bb4dc5f213010000008a47304402204f6cab3fce36ea750538ffe165713bdedc44e8ea5089420634954f9efb8022ff022006c2812283b40fd6e8f26be8ac7261333b90b76c1722df1f9485e3e1e0795053014104ef29f16c10aa2d0468d7841cfedb8b5729689ebca4db38fb8f3fc9ab158e799b6d6dfc2bca52fe490f7acd38e351bf1d28b8f1f48736a0b022f806dd107a8385feffffffc517ff49a374f8a41dd7a5d4028315374f875bd483a4e56bf946d76a0ec441f7000000008b483045022100b74cfc519a6ce6510143072b5bd879fac7eed1415d0df52620a54a40f17470fa022072ffaa0216a9d57d59714e0f01c173097bf9d9558cbdcc77d19152ed8a328932014104ef29f16c10aa2d0468d7841cfedb8b5729689ebca4db38fb8f3fc9ab158e799b6d6dfc2bca52fe490f7acd38e351bf1d28b8f1f48736a0b022f806dd107a8385feffffffe77c28db26558695fbc66172878412cb2694db40ff360b55d3740a44ba2b3238000000008a47304402203e427cc1990a299295554579f30974f83ba05ddf187482140928018e4938d96602204799d8c12cb696eacfd951198d35f0c6a65ecb67b717f55a20afa6677f4bafc4014104ef29f16c10aa2d0468d7841cfedb8b5729689ebca4db38fb8f3fc9ab158e799b6d6dfc2bca52fe490f7acd38e351bf1d28b8f1f48736a0b022f806dd107a8385feffffff0104332800000000001976a91441a349571d89decfac52ffecd92300b6a97b284188ac0000000001000000042ee074f816ebb800d5b3e8497498a8be0b7a578d831b7a4617090f224d20387c000000008a47304402207d9b6519328111fb1ccbf64632a404bd000fbd4e0086204f4853297ddc119fb202206e2b52c5a5c96376a0f95dba0bd086e6bade504c13af7a79aba33e1bd3024193014104447019ded953edd1bcecffbc66a555f822675257bacc0d357c1dc5194849367354c551e2c2e2048cb927985c8528e24120addd9aa0a2c68b23b462f337caaebcfeffffff58ac7561601d65f73a329c291970d755da1923458a8197de4dc9d47061fe5cc4020000008a47304402205c742445dac4de43bc5568b8f00e855fdc454b33ecae730c4be8d01a4479e7ba022061d0d274ba1fdecff47a9d0e1614d710c0e746ab22b5d0bd0ae4fab921e64e99014104447019ded953edd1bcecffbc66a555f822675257bacc0d357c1dc5194849367354c551e2c2e2048cb927985c8528e24120addd9aa0a2c68b23b462f337caaebcfeffffff6c1828ac45acb5040e9a8eb3f228942d562bde81923158da6425276b27e62155000000008b483045022100cb803162888cb25f25c2f1fa7340b27ffc50c2aba869e9bddcb97b43c3feed470220501807396b9d48508cf31efaa212358615b241493134811dac43e6a372987c51014104447019ded953edd1bcecffbc66a555f822675257bacc0d357c1dc5194849367354c551e2c2e2048cb927985c8528e24120addd9aa0a2c68b23b462f337caaebcfeffffffb4a2a1a056cddf86c811ab41f4b2dfd8f29feec73d34c796ea28cf12b8f81cae010000008b483045022100d0711f0295c01fe8856e8e38b37fd922b8aa0352b6d13616c621fa0f7d4b5ff1022059aafb91eea435e797d0d27477a63f06454c470a0d8ef8e5e8d496fb62c1efd3014104447019ded953edd1bcecffbc66a555f822675257bacc0d357c1dc5194849367354c551e2c2e2048cb927985c8528e24120addd9aa0a2c68b23b462f337caaebcfeffffff0104332800000000001976a914f3c49407d41b82f30636f5180718bb658ce7fe9488ac000000000100000004910223cea04cb252e6e6699bb38e77e63336680f1da01d35ebda1786ae607c7c010000008b483045022100961a28548fc3e53962e1b4039b383b0cf441c3ff76433e7652840c5cc8f711fd022074f177613090d1d1d8149eaa71f1f72531c4b0b8136be4bdb852e0ebf94fdeda01410479ff722ee4dfd880e307d06fc50a248a9f73a57998a65fd95c48436400280372cf9e99a9952ded7723a68118d4dcf658efbaed2a73265fc63b44789d2d459637feffffff9e3b6d11ace91dab509d257da4f54a637a38f188b13f8fe4a3a5b0fce6af2ac5020000008b483045022100a0c9d78f7b3db154d8c9c437b087be2e8f1adb01c40148307e8c986c0855192402201f9cfa8a422f39125cd5e90b0128558f30daa6e339da95d93673ed8331bdceab01410479ff722ee4dfd880e307d06fc50a248a9f73a57998a65fd95c48436400280372cf9e99a9952ded7723a68118d4dcf658efbaed2a73265fc63b44789d2d459637feffffffca544deb6c248c68a56d86e3e9fa2f93fcf35d6055acb116962421eb4041e896000000008a47304402202274c0b8b6634494b65309d4e2a0a91d6a55051000485c427d1c05d5cca810f002204f5eeb5c202b2e7c4ef1b1f61e3a9928fa8b2014f09a2735305ec1a2a1cb2dd501410479ff722ee4dfd880e307d06fc50a248a9f73a57998a65fd95c48436400280372cf9e99a9952ded7723a68118d4dcf658efbaed2a73265fc63b44789d2d459637feffffffd3600cc4caa4d7719a1f7b78f8d66e09cd84a6e4e7ee4cceff44921a314502ec000000008b4830450221008b7a7d15efa590a750ac917cad343abbaf432858de0df37bd3d0e660bcd515800220360cb45eb1a77cb4ad90d595f91f4018aa5662e36add18b7131ea99b3dd9071101410479ff722ee4dfd880e307d06fc50a248a9f73a57998a65fd95c48436400280372cf9e99a9952ded7723a68118d4dcf658efbaed2a73265fc63b44789d2d459637feffffff0104332800000000001976a914e1762290e3f035ea4e7f8cbf72a9d9386c4020ab88ac00000000".to_owned(),
                header: "00000020ad98a2888b7c69f4187ef5ee1b5921a6fb62803aa8bd35826f7fb751714baf250cb5ef03478d35ed7f6582ab40232ee39744471b2bcb40b91db0f29102d695123379fc5bffff7f2002000000".to_owned(),
                height: 32,
                result: Some(BitcoinBlock {
                    block_height: 32,
                    block_hash: to_block_hash(&hex_bytes("4f3757bc236e58b87d6208aa795115002b739bf39268cf69640f0b092e8cdafe").unwrap()),
                    parent_block_hash: to_block_hash(&hex_bytes("25af4b7151b77f6f8235bda83a8062fba621591beef57e18f4697c8b88a298ad").unwrap()),
                    timestamp: 1543272755,
                    txs: vec![
                        BitcoinTransaction {
                            data_amt: 0,
                            // TOKEN_TRANSFER
                            txid: to_txid(&hex_bytes("13f2c54dbbe3d4d6ed6c9fd1a68fe3c4238ec5de50316d102a106553b57b8728").unwrap()),
                            vtxindex: 2,
                            opcode: b'$',
                            data: hex_bytes("7c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b530000000000000064").unwrap(),
                            inputs: vec![
                                BitcoinTxInputStructured {
                                    keys: vec![
                                        BitcoinPublicKey::from_hex("03d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3").unwrap()
                                    ],
                                    num_required: 1,
                                    in_type: BitcoinInputType::Standard,
                                    tx_ref: (Txid::from_hex("f741c40e6ad746f96be5a483d45b874f37158302d4a5d71da4f874a349ff17c5").unwrap(), 1),
                                }.into()
                            ],
                            outputs: vec![
                                BitcoinTxOutput {
                                    units: 5500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("41a349571d89decfac52ffecd92300b6a97b2841").unwrap()).unwrap()
                                },
                                BitcoinTxOutput {
                                    units: 4986192000,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("74178497e927ff3ff1428a241be454d393c3c91c").unwrap()).unwrap()
                                }
                            ]
                        },
                        BitcoinTransaction {
                            data_amt: 0,
                            // TOKEN_TRANSFER 
                            txid: to_txid(&hex_bytes("7c7c60ae8617daeb351da01d0f683633e6778eb39b69e6e652b24ca0ce230291").unwrap()),
                            vtxindex: 4,
                            opcode: b'$',
                            data: hex_bytes("7c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b530000000000000064").unwrap(),
                            inputs: vec![
                                BitcoinTxInputStructured {
                                    keys: vec![
                                        BitcoinPublicKey::from_hex("04ef29f16c10aa2d0468d7841cfedb8b5729689ebca4db38fb8f3fc9ab158e799b6d6dfc2bca52fe490f7acd38e351bf1d28b8f1f48736a0b022f806dd107a8385").unwrap()
                                    ],
                                    num_required: 1,
                                    in_type: BitcoinInputType::Standard,
                                    tx_ref: (Txid::from_hex("ba53c1d5b3d18115d7a9f7402e7c96281a05af1835f98dc8d729158c96d31193").unwrap(), 0),
                                }.into()
                            ],
                            outputs: vec![
                                BitcoinTxOutput {
                                    units: 5500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("e1762290e3f035ea4e7f8cbf72a9d9386c4020ab").unwrap()).unwrap()
                                },
                                BitcoinTxOutput {
                                    units: 211500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("41a349571d89decfac52ffecd92300b6a97b2841").unwrap()).unwrap()
                                }
                            ]
                        },
                        BitcoinTransaction {
                            data_amt: 0,
                            // TOKEN_TRANSFER 
                            txid: to_txid(&hex_bytes("ae1cf8b812cf28ea96c7343dc7ee9ff2d8dfb2f441ab11c886dfcd56a0a1a2b4").unwrap()),
                            vtxindex: 7,
                            opcode: b'$',
                            data: hex_bytes("7c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b530000000000000064").unwrap(),
                            inputs: vec![
                                BitcoinTxInputStructured {
                                    keys: vec![
                                        BitcoinPublicKey::from_hex("0479ff722ee4dfd880e307d06fc50a248a9f73a57998a65fd95c48436400280372cf9e99a9952ded7723a68118d4dcf658efbaed2a73265fc63b44789d2d459637").unwrap()
                                    ],
                                    num_required: 1,
                                    in_type: BitcoinInputType::Standard,
                                    tx_ref: (Txid::from_hex("bb8c5223c42c740c056afb147264c0982a96bafd4801e121669da99fc3ca33f4").unwrap(), 0),
                                }.into()
                            ],
                            outputs: vec![
                                BitcoinTxOutput {
                                    units: 5500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("f3c49407d41b82f30636f5180718bb658ce7fe94").unwrap()).unwrap()
                                },
                                BitcoinTxOutput {
                                    units: 211500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("e1762290e3f035ea4e7f8cbf72a9d9386c4020ab").unwrap()).unwrap()
                                }
                            ]
                        },
                        BitcoinTransaction {
                            data_amt: 0,
                            // TOKEN_TRANSFER
                            txid: to_txid(&hex_bytes("12fed1db482a35dba87535a13089692cea35a71bfb159b21d0a04be41219b2bd").unwrap()),
                            vtxindex: 10,
                            opcode: b'$',
                            data: hex_bytes("7c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b530000000000000064").unwrap(),
                            inputs: vec![
                                BitcoinTxInputStructured {
                                    keys: vec![
                                        BitcoinPublicKey::from_hex("04447019ded953edd1bcecffbc66a555f822675257bacc0d357c1dc5194849367354c551e2c2e2048cb927985c8528e24120addd9aa0a2c68b23b462f337caaebc").unwrap()
                                    ],
                                    num_required: 1,
                                    in_type: BitcoinInputType::Standard,
                                    tx_ref: (Txid::from_hex("a8e317854cf5e11e13539f44cabdcf29767d838ae684a865f849a8405c3d96b4").unwrap(), 0),
                                }.into()
                            ],
                            outputs: vec![
                                BitcoinTxOutput {
                                    units: 5500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("afc75a8f8fbcb922248a663dec927b33dccaed37").unwrap()).unwrap()
                                },
                                BitcoinTxOutput {
                                    units: 211500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("f3c49407d41b82f30636f5180718bb658ce7fe94").unwrap()).unwrap()
                                }
                            ]
                        },
                        BitcoinTransaction {
                            data_amt: 0,
                            // TOKEN_TRANSFER 
                            txid: to_txid(&hex_bytes("78035609a8733f214555cfec29e3eee1d24014863dc9f9d98092f6fbc5df63e8").unwrap()),
                            vtxindex: 13,
                            opcode: b'$',
                            data: hex_bytes("7c503a2e30a905cb515cfbc291766dfa00000000000000000000000000535441434b530000000000000064").unwrap(),
                            inputs: vec![
                                BitcoinTxInputStructured {
                                    keys: vec![
                                        BitcoinPublicKey::from_hex("04a96a8355b6c3597bb9425c2ef264ab8179ca8acd3032b62980d2067261b37666b66510983e6d60d49bbd28129f0bae4dbcaa97c2bc61a6b2e48ca1625ce81335").unwrap()
                                    ],
                                    num_required: 1,
                                    in_type: BitcoinInputType::Standard,
                                    tx_ref: (Txid::from_hex("be8b8ec102773e2c2e6179584684280a0f42c83c11dc1a30610310c91796c804").unwrap(), 0),
                                }.into()
                            ],
                            outputs: vec![
                                BitcoinTxOutput {
                                    units: 5500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("74178497e927ff3ff1428a241be454d393c3c91c").unwrap()).unwrap()
                                },
                                BitcoinTxOutput {
                                    units: 211500,
                                    address: BitcoinAddress::from_bytes_legacy(BitcoinNetworkType::Testnet, LegacyBitcoinAddressType::PublicKeyHash, &hex_bytes("afc75a8f8fbcb922248a663dec927b33dccaed37").unwrap()).unwrap()
                                }
                            ]
                        }
                    ]
                })
            },
            BlockFixture {
                // invalid data -- merkle root won't match transactions (so header won't match)
                block: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6930aff462fc5bffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b5020101ffffffff024018a41200000000232103f51f0c868fd99a4a3a14fe2153fba3c5f635c31bf0a588545627134b49609097ac0000000000000000266a24aa21a9ed18a09ae86261d6802bff7fa705afa558764ed3750c2273bfae5b5136c44d14d6012000000000000000000000000000000000000000000000000000000000000000000000000001000000000101a7ef2b09722ad786c569c0812005a731ce19290bb0a2afc16cb91056c2e4c19e0100000017160014393ffec4f09b38895b8502377693f23c6ae00f19ffffffff0300000000000000000d6a0b69643a666f6f2e746573747c1500000000000017a9144b85301ba8e42bf98472b8ed4939d5f76b98fcea87144d9c290100000017a91431f8968eb1730c83fb58409a9a560a0a0835027f8702483045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b012102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e8100000000".to_owned(),
                header: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6931aff462fc5bffff7f2000000000".to_owned(),
                height: 32,
                result: None,
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, MagicBytes([105, 100])); // "id"
        for block_fixture in block_fixtures {
            let block = make_block(&block_fixture.block).unwrap();
            let header = make_block_header(&block_fixture.header).unwrap();
            let height = block_fixture.height;

            let parsed_block_opt =
                parser.process_block(&block, &header, height, StacksEpochId::Epoch2_05);
            assert_eq!(parsed_block_opt, block_fixture.result);
        }
    }
    */
}
