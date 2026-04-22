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

use crate::clarity_test;

use crate::contracts::tests::*;


clarity_test!(test_clarity_check_utxo_exists_and_is_claimable, {
    let generated_code = r#"

(define-constant USER_PUBKEY 0x031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a)
(define-constant PROVIDER (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 USER_PUBKEY))))
(define-constant OWNER 'ST3BCQ764SM8Z65QSHVPWP5T2YRNBBR0XZM6QC7M0)

(define-constant ALT_OWNER 'ST2VAT594GNDG58C8BM04SP2H1VMHKV0Y632AMPCR)
(define-constant ALT_USER_PUBKEY 0x03fa6775b16d1b853dd0c0368fbcc6e612e2b8863f358cbfafac5d53d4f1700b1d)

;; populate reserved utxo map
;; (* .test-0, 0) has three UTXOs created by transactions 0x00, 0x01, 0x02, and they all expire at u100.
(map-insert utxos
    { txid: 0x00, vout: u0 }
    {
        owner: OWNER,
        provider: PROVIDER,
        amount: u1000,
        expires: u1030,
        user-pubkey: USER_PUBKEY,
        witness-script: 0x
    })

(map-insert utxos
    { txid: 0x01, vout: u0 }
    {
        owner: OWNER,
        provider: PROVIDER,
        amount: u2000,
        expires: u1030,
        user-pubkey: USER_PUBKEY,
        witness-script: 0x
    })

(map-insert utxos
    { txid: 0x03, vout: u0 }
    {
        owner: OWNER,
        provider: PROVIDER,
        amount: u3000,
        expires: u1030,
        user-pubkey: USER_PUBKEY,
        witness-script: 0x
    })

;; not reserved yet
(map-insert utxos
    { txid: 0x04, vout: u0 }
    {
        owner: OWNER,
        provider: PROVIDER,
        amount: u4000,
        expires: u1030,
        user-pubkey: USER_PUBKEY,
        witness-script: 0x
    })

;; reserved by someone else
(map-insert utxos
    { txid: 0x04, vout: u0 }
    {
        owner: ALT_OWNER,
        provider: PROVIDER,
        amount: u4000,
        expires: u1030,
        user-pubkey: USER_PUBKEY,
        witness-script: 0x
    })

;; reserved by a voided outcome
(map-insert utxos
    { txid: 0x06, vout: u0 }
    {
        owner: OWNER,
        provider: PROVIDER,
        amount: u6000,
        expires: u1030,
        user-pubkey: USER_PUBKEY,
        witness-script: 0x
    })

(map-insert contract-reserved-utxos
    { txid: 0x00, vout: u0 }
    { outcome-id: { contract: .test-0, id: u0 }, expires: u1030 })

(map-insert contract-reserved-utxos
    { txid: 0x01, vout: u0 }
    { outcome-id: { contract: .test-0, id: u0 }, expires: u1030 })

(map-insert contract-reserved-utxos
    { txid: 0x02, vout: u0 }
    { outcome-id: { contract: .test-0, id: u0 }, expires: u1030 })

;; alternative reservation
(map-insert contract-reserved-utxos
    { txid: 0x05, vout: u0 }
    { outcome-id: { contract: .test-1, id: u0 }, expires: u1030 })

;; alternative reservation that was voided
(map-insert contract-reserved-utxos
    { txid: 0x06, vout: u0 }
    { outcome-id: { contract: .test-2, id: u0 }, expires: u1030 })

(map-insert contract-transfer-outcomes
    { contract: .test-0, id: u0 }
    {
        utxo-ptrs: (list
            { txid: 0x00, vout: u0 }
            { txid: 0x01, vout: u0 }
            { txid: 0x02, vout: u0 }
        ),
        wtxids: (list ),
        provider: PROVIDER,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        closed: false,
        voided: false
    })

(map-insert contract-transfer-outcomes
    { contract: .test-1, id: u0 }
    {
        utxo-ptrs: (list
            { txid: 0x05, vout: u0 }
        ),
        wtxids: (list ),
        provider: PROVIDER,
        owner: ALT_OWNER,
        user-pubkey: USER_PUBKEY,
        closed: false,
        voided: false
    })

(map-insert contract-transfer-outcomes
    { contract: .test-2, id: u0 }
    {
        utxo-ptrs: (list
            { txid: 0x06, vout: u0 }
        ),
        wtxids: (list ),
        provider: PROVIDER,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        closed: false,
        voided: true
    })

(define-map test-vectors uint
    {
        utxo-ptr: { txid: (buff 32), vout: uint },
        provider: (optional principal),
        owner: principal,
        user-pubkey: (buff 33),
        outcome-id: { contract: principal, id: uint },
        cur-btc-height: uint,
        expected-result: (response bool uint)
    })

(define-data-var test-vector-index (list 256 uint)
    (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9))

;; fails because the UTXO is already reserved
(map-insert test-vectors u0 
    {
        utxo-ptr: { txid: 0x00, vout: u0 },
        provider: none,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (err ERR_UTXO_RESERVED_OR_EXPIRED)
    })

;; fails because the UTXO doesn't exist
(map-insert test-vectors u1 
    {
        utxo-ptr: { txid: 0xff, vout: u0 },
        provider: none,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (err ERR_TX_NO_UTXO)
    })

;; fails because the UTXO would have expired
(map-insert test-vectors u2 
    {
        utxo-ptr: { txid: 0x04, vout: u0 },
        provider: none,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u1030,
        expected-result: (err ERR_BTC_EXPIRED)
    })

;; succeeds because the UTXO is ours and is not reserved
(map-insert test-vectors u3
    {
        utxo-ptr: { txid: 0x04, vout: u0 },
        provider: none,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (ok true)
    })

;; fails because the UTXO is reserved and not by us
(map-insert test-vectors u4
    {
        utxo-ptr: { txid: 0x05, vout: u0 },
        provider: none,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (err ERR_UTXO_RESERVED_OR_EXPIRED)
    })

;; fails because the provider is wrong
(map-insert test-vectors u5 
    {
        utxo-ptr: { txid: 0x04, vout: u0 },
        provider: (some OWNER),
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (err ERR_TX_UTXO_WRONG_PROVIDER)
    })

;; fails because the owner is wrong
(map-insert test-vectors u6 
    {
        utxo-ptr: { txid: 0x04, vout: u0 },
        provider: none,
        owner: ALT_OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (err ERR_TX_UTXO_WRONG_OWNER)
    })

(map-insert test-vectors u7
    {
        utxo-ptr: { txid: 0x04, vout: u0 },
        provider: none,
        owner: OWNER,
        user-pubkey: ALT_USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (err ERR_TX_UTXO_WRONG_USER_PUBKEY)
    })

;; this passes, even though the UTXO is already reserved, and even though the provider is set
(map-insert test-vectors u8 
    {
        utxo-ptr: { txid: 0x04, vout: u0 },
        provider: (some PROVIDER),
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (ok true)
    })

;; this passes because the outcome that reserved this UTXO is voided
(map-insert test-vectors u9
    {
        utxo-ptr: { txid: 0x06, vout: u0 },
        provider: none,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .test-0, id: u0 },
        cur-btc-height: u100,
        expected-result: (ok true)
    })

(define-private (run-test (test-id uint) (test-result (response bool uint)))
    (if (is-err test-result)
        test-result
        (let (
            (test-vector (try! (match (map-get? test-vectors test-id)
                test-vec (ok test-vec)
                (begin
                    (test-fail! (concat "Failed to load test vector #" (int-to-ascii test-id)))
                    (err u0)))))

            (utxo-ptr (get utxo-ptr test-vector))
            (provider-opt (get provider test-vector))
            (owner (get owner test-vector))
            (user-pubkey (get user-pubkey test-vector))
            (outcome-id (get outcome-id test-vector))
            (cur-btc-height (get cur-btc-height test-vector))
            (expected-result (get expected-result test-vector))

            (res (get result (check-utxo-exists-and-is-claimable
                utxo-ptr
                {
                    provider: provider-opt,
                    owner: owner,
                    user-pubkey: user-pubkey,
                    result: (ok true),
                    outcome-id: outcome-id,
                    cur-btc-height: cur-btc-height
                })))
        )
        (print (concat "Running test vector #" (int-to-ascii test-id)))
        (if (not (is-eq res expected-result))
            (begin
                (test-fail! (concat "Did not get expected result for test #" (int-to-ascii test-id)))
                (print "expected:")
                (match expected-result
                    ok-res (begin (print "ok") (print ok-res) true)
                    err-res (begin (print "err") (print err-res) true))
                (print "got:")
                (match res
                    ok-res (begin (print "ok") (print ok-res) true)
                    err-res (begin (print "err") (print err-res) true))
                (err u11))
            (ok true)))))


(define-public (test)
    (let (
        (final-result (fold run-test (var-get test-vector-index) (ok true)))
    )
    (print "Final result:")
    (match (print final-result)
        ok-res true
        err-res true)
    (ok true)))
"#;


    generated_code
});
