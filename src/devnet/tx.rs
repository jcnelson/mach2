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

use std::io::Cursor;

use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};

use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};

use crate::tx::*;

#[allow(clippy::too_many_arguments)]
pub fn sign_sponsored_sig_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: &StacksPrivateKey,
    sender_nonce: u64,
    payer_nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> StacksTransaction {
    sign_tx_anchor_mode_version(
        payload,
        sender,
        Some(payer),
        sender_nonce,
        Some(payer_nonce),
        tx_fee,
        chain_id,
        anchor_mode,
        version,
    )
}

pub fn sign_standard_single_sig_tx(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
) -> StacksTransaction {
    sign_standard_single_sig_tx_anchor_mode(
        payload,
        sender,
        nonce,
        tx_fee,
        chain_id,
        TransactionAnchorMode::OnChainOnly,
    )
}

pub fn sign_standard_single_sig_tx_anchor_mode(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
) -> StacksTransaction {
    sign_standard_single_sig_tx_anchor_mode_version(
        payload,
        sender,
        nonce,
        tx_fee,
        chain_id,
        anchor_mode,
        TransactionVersion::Testnet,
    )
}

pub fn sign_standard_single_sig_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> StacksTransaction {
    sign_tx_anchor_mode_version(
        payload,
        sender,
        None,
        nonce,
        None,
        tx_fee,
        chain_id,
        anchor_mode,
        version,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn make_unsigned_tx(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: Option<&StacksPrivateKey>,
    sender_nonce: u64,
    payer_nonce: Option<u64>,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> StacksTransaction {
    let mut sender_spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
    sender_spending_condition.set_nonce(sender_nonce);

    let auth = match (payer, payer_nonce) {
        (Some(payer), Some(payer_nonce)) => {
            let mut payer_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
                StacksPublicKey::from_private(payer),
            )
            .expect("Failed to create p2pkh spending condition from public key.");
            payer_spending_condition.set_nonce(payer_nonce);
            payer_spending_condition.set_tx_fee(tx_fee);
            TransactionAuth::Sponsored(sender_spending_condition, payer_spending_condition)
        }
        _ => {
            sender_spending_condition.set_tx_fee(tx_fee);
            TransactionAuth::Standard(sender_spending_condition)
        }
    };
    let mut unsigned_tx = StacksTransaction::new(version, auth, payload);
    unsigned_tx.anchor_mode = anchor_mode;
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
    unsigned_tx.chain_id = chain_id;
    unsigned_tx
}

#[allow(clippy::too_many_arguments)]
pub fn sign_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: Option<&StacksPrivateKey>,
    sender_nonce: u64,
    payer_nonce: Option<u64>,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> StacksTransaction {
    let unsigned_tx = make_unsigned_tx(
        payload,
        sender,
        payer,
        sender_nonce,
        payer_nonce,
        tx_fee,
        chain_id,
        anchor_mode,
        version,
    );

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(sender).unwrap();
    if let (Some(payer), Some(_)) = (payer, payer_nonce) {
        tx_signer.sign_sponsor(payer).unwrap();
    }

    tx_signer.get_tx().unwrap()
}

#[allow(clippy::too_many_arguments)]
pub fn serialize_sign_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: Option<&StacksPrivateKey>,
    sender_nonce: u64,
    payer_nonce: Option<u64>,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> Vec<u8> {
    let tx = sign_tx_anchor_mode_version(
        payload,
        sender,
        payer,
        sender_nonce,
        payer_nonce,
        tx_fee,
        chain_id,
        anchor_mode,
        version,
    );

    let mut buf = vec![];
    tx.consensus_serialize(&mut buf).unwrap();
    buf
}

pub fn make_contract_publish_tx(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_name: &str,
    contract_content: &str,
    version: Option<ClarityVersion>,
) -> StacksTransaction {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload =
        TransactionPayload::SmartContract(TransactionSmartContract { name, code_body }, version);

    sign_standard_single_sig_tx(payload, sender, nonce, tx_fee, chain_id)
}

pub fn make_contract_publish_versioned(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_name: &str,
    contract_content: &str,
    version: Option<ClarityVersion>,
) -> Vec<u8> {
    make_contract_publish_tx(
        sender,
        nonce,
        tx_fee,
        chain_id,
        contract_name,
        contract_content,
        version,
    )
    .serialize_to_vec()
}

pub fn make_contract_publish(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_name: &str,
    contract_content: &str,
) -> Vec<u8> {
    make_contract_publish_versioned(
        sender,
        nonce,
        tx_fee,
        chain_id,
        contract_name,
        contract_content,
        None,
    )
}

pub fn to_addr(sk: &StacksPrivateKey) -> StacksAddress {
    StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sk))
}

pub fn make_stacks_transfer_tx(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    recipient: &PrincipalData,
    amount: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    sign_standard_single_sig_tx(payload, sender, nonce, tx_fee, chain_id)
}

/// Make a stacks transfer transaction, returning the serialized transaction bytes
pub fn make_stacks_transfer_serialized(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let tx = make_stacks_transfer_tx(sender, nonce, tx_fee, chain_id, recipient, amount);
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

#[allow(clippy::too_many_arguments)]
pub fn make_sponsored_stacks_transfer_on_testnet(
    sender: &StacksPrivateKey,
    payer: &StacksPrivateKey,
    sender_nonce: u64,
    payer_nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    let tx = sign_sponsored_sig_tx_anchor_mode_version(
        payload,
        sender,
        payer,
        sender_nonce,
        payer_nonce,
        tx_fee,
        chain_id,
        TransactionAnchorMode::OnChainOnly,
        TransactionVersion::Testnet,
    );
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

#[allow(clippy::too_many_arguments)]
pub fn make_contract_call_tx(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_addr: &StacksAddress,
    contract_name: &str,
    function_name: &str,
    function_args: &[Value],
) -> StacksTransaction {
    let contract_name = ContractName::from(contract_name);
    let function_name = ClarityName::from(function_name);

    let payload = TransactionContractCall {
        address: contract_addr.clone(),
        contract_name,
        function_name,
        function_args: function_args.to_vec(),
    };

    sign_standard_single_sig_tx(payload.into(), sender, nonce, tx_fee, chain_id)
}

#[allow(clippy::too_many_arguments)]
pub fn make_contract_call(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_addr: &StacksAddress,
    contract_name: &str,
    function_name: &str,
    function_args: &[Value],
) -> Vec<u8> {
    make_contract_call_tx(
        sender,
        nonce,
        tx_fee,
        chain_id,
        contract_addr,
        contract_name,
        function_name,
        function_args,
    )
    .serialize_to_vec()
}

