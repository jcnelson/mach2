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

// TODO add more!
clarity_test!(test_clarity_inner_create_contract_transfer_outcome, {
    let generated_code = r#"

(define-constant WTX 0x0100000000010253b11c2429e749a6a175c14a5037a4ee66f435d26a568fbd6652481c2705e9b80300000000fdffffff1e3b4b20e62fa361c688ee724f8a3eb30c9991546b8afbdadc2c270b3a0807560000000000fdffffff0200f2052a01000000220020d20c2b12e7b42e0ce3b7334db8e76faeafabef54802cfb3d410a319a74331adfe645f7290100000016001492654bb92c6ead4303d85b8f5cb915ce019b24730247304402203272964194a3120c0d0c811bbf907e1d7bf73c95ab28561af006c4c93ef429cf02203864f8472c606db74abeff4168f31defbe0e004d62835c006ca3da03821c8e5f012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f02483045022100c0c5b7e5452c79156d6b5e53f1ec175ed33068b92578d3fba282258a9e70c9380220089683c3349e21e9dde0e382b8ee4af5976c452f8c008e173160c7d4dfd86dd2012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000)

(define-constant WTXID (sha256 (sha256 WTX)))

(define-constant COSIGNER_ADDR 'ST2D7JNTKA11T11QYCXEQPJQ97TETW7MKKWPJT770)
(define-constant COSIGNER_KEYS (list
    0x03fe11e4e59b6c3c2a5a5760df9d4a903f7b478a146fc2947a9f04518419fa6387
    0x031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a
    0x03fc17d6b3fb08855ff1bdefd68fa8fa9a5b4b9708fcad2c72cde4371088aaceea
))

;; register the cosigner for this pegin
(asserts! (is-ok (inner-register-cosigner COSIGNER_ADDR COSIGNER_KEYS))
    (begin
        (test-fail! "Failed to register cosigner")
        (err u100)))

(define-constant OWNER 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD)
(define-constant USER_PUBKEY 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f)
(define-constant PROVIDER (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 USER_PUBKEY))))

;; carry out this pegin
(let (
    (cosigner COSIGNER_ADDR)
    (wtx WTX)
    (btc-block-header 0x00000020d23d78bc98a60193fbc4220300c60232363d1bca96eda55f54d0212937d0764f73c4e0b11c97ddd49432fc2cc28ad27fb901e8e3f1591052eeaead920ebdac5f3998de69ffff7f2000000000)
    (btc-block-height u128)
    (btc-block-hash 0x3b628825bfd97075499dc08bf456453196faa2db91ef960b4c6aed78372ba6ff)
    (btc-tx-index u2)
    (tree-depth u2)
    (tx-proof (list
        (reverse-buff32 0xb9e3a2ef750167a163c88ab9bbc7435ba6030bf77905fd4565d34f2cdb455906)
        (reverse-buff32 0x6cc139a2c1be93a52784f274180be5fbaab44089a77dd8a16dbd82898f473fdd)
    ))
    (witness-merkle-root (reverse-buff32 0x02ccb378fd29a529ef6a7d211cb75915cb3258460e05bb8834479558fc09bb0a))
    (witness-reserved 0x0000000000000000000000000000000000000000000000000000000000000000)
    (coinbase-tx 0x02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0402800000ffffffff0261e1062a01000000160014916f8c456f282ec7c14d40de0a7ff5af74abc1950000000000000000266a24aa21a9edf78f2a2b234e17778b4fe3ce0f8cf7113431854fb089fa51e54ecc9b4ae6847700000000)
    (coinbase-tx-proof (list
        (reverse-buff32 0xb8e905271c485266bd8f566ad235f466eea437504ac175a1a649e729241cb153)
        (reverse-buff32 0xed04bfcab0cf233be775537151604fea6c9e4c77ab6674a6696c9e8dda8e6e8c)
    ))
    (pegin-output u0)
    (witness-data {
        recipient-principal: OWNER,
        user-pubkey: USER_PUBKEY,
        locktime: u1000,
        safety-margin: u30
    })
)
(asserts! (is-ok (contract-call? .bitcoin mock-add-burnchain-block-header-hash btc-block-height btc-block-hash))
    (begin
        (test-fail! "Failed to mock bitcoin block header hash")
        (err u0)))

(asserts! (is-ok (inner-register-pegin
        cosigner
        wtx
        btc-block-header
        btc-block-height
        btc-tx-index
        tree-depth
        tx-proof
        witness-merkle-root
        witness-reserved
        coinbase-tx
        coinbase-tx-proof
        pegin-output
        witness-data))
    (begin
        (test-fail! "Failed to peg in")
        (err u0)))
)

;; mock UTXOs with different owners
(define-constant MOCK_OWNER 'ST2VAT594GNDG58C8BM04SP2H1VMHKV0Y632AMPCR)
(define-constant MOCK_USER_PUBKEY 0x03fa6775b16d1b853dd0c0368fbcc6e612e2b8863f358cbfafac5d53d4f1700b1d)
(define-constant MOCK_PROVIDER (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 USER_PUBKEY))))

(map-insert utxos
    { txid: 0x00, vout: u0 }
    {
        owner: MOCK_OWNER,
        provider: MOCK_PROVIDER,
        amount: u1000,
        expires: u1030,
        user-pubkey: MOCK_USER_PUBKEY,
        witness-script: 0x
    })

;; has same owner, user, provider as peg-in, but expires later
(map-insert utxos
    { txid: 0x01, vout: u0 }
    {
        owner: OWNER,
        provider: PROVIDER,
        amount: u2000,
        expires: u2060,
        user-pubkey: USER_PUBKEY,
        witness-script: 0x
    })

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-map test-vectors uint
    {
        owner: principal,
        user-pubkey: (buff 33),
        outcome-id: { contract: principal, id: uint },
        utxo-ptrs: (list 256 { txid: (buff 32), vout: uint }),
        cur-btc-height: uint,
        expected-result: (response bool uint)
    })

(define-data-var test-vector-index (list 256 uint)
    (list u0 u1 u2 u3 u4 u5))

;; bad owner
(map-insert test-vectors u0
    {
        owner: COSIGNER_ADDR,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .mach2, id: u0 },
        utxo-ptrs: (list { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 }),
        cur-btc-height: u128,
        expected-result: (err ERR_TX_UTXO_WRONG_OWNER)
    })

;; bad user pubkey
(map-insert test-vectors u1
    {
        owner: OWNER,
        user-pubkey: MOCK_USER_PUBKEY,
        outcome-id: { contract: .mach2, id: u0 },
        utxo-ptrs: (list { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 }),
        cur-btc-height: u128,
        expected-result: (err ERR_TX_UTXO_WRONG_USER_PUBKEY)
    })

;; not giving UTXOs fails
(map-insert test-vectors u2
    {
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .mach2, id: u0 },
        utxo-ptrs: (list ),
        cur-btc-height: u128,
        expected-result: (err ERR_TX_NO_UTXO)
    })

;; inconsistent provider
(map-insert test-vectors u3
    {
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .mach2, id: u0 },
        utxo-ptrs: (list
            { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 }
            { txid: 0x00, vout: u0 }
        ),
        cur-btc-height: u128,
        expected-result: (err ERR_TX_UTXO_WRONG_OWNER)
    })

;; one of the UTXOs expires
(map-insert test-vectors u4
    {
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .mach2, id: u0 },
        utxo-ptrs: (list
            { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 }
            { txid: 0x01, vout: u0 }
        ),
        cur-btc-height: u1031,
        expected-result: (err ERR_BTC_EXPIRED)
    })

;; success!
(map-insert test-vectors u5
    {
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        outcome-id: { contract: .mach2, id: u0 },
        utxo-ptrs: (list { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 }),
        cur-btc-height: u128,
        expected-result: (ok true)
    })


;; registered outcomes
(define-map registered-outcomes
    ;; outcome ID
    { contract: principal, id: uint }
    bool)


;; check that a UTXO is reserved for the given outcome and expiration 
(define-private (check-reserved-utxo
    (ptr { txid: (buff 32), vout: uint })
    (ctx {
        check-result: (response bool uint),
        outcome-id: { contract: principal, id: uint },
        expires: uint
    }))

    (if (is-ok (get check-result ctx))
        (match (map-get? contract-reserved-utxos ptr)
            reserved-utxo
                (if (not (is-eq (get outcome-id reserved-utxo) (get outcome-id ctx)))
                    (begin
                        (test-fail! "Failed to check that a UTXO was reserved to the given outcome")
                        (print "ptr.txid")
                        (print (unwrap-panic (to-ascii? (get txid ptr))))
                        (print "ptr.vout")
                        (print (int-to-ascii (get vout ptr)))
                        (merge ctx { check-result: (err u20) }))
                (if (not (is-eq (get expires reserved-utxo) (get expires ctx)))
                    (begin
                        (test-fail! "Failed to check that a UTXO was reserved with the given expiry")
                        (print "ptr.txid")
                        (print (unwrap-panic (to-ascii? (get txid ptr))))
                        (print "ptr.vout")
                        (print (int-to-ascii (get vout ptr)))
                        (merge ctx { check-result: (err u21) }))
                    ctx))

            (begin
                (test-fail! "UTXO is not registered")
                (print "ptr.txid")
                (print (unwrap-panic (to-ascii? (get txid ptr))))
                (print "ptr.vout")
                (print (int-to-ascii (get vout ptr)))
                (merge ctx { check-result: (err u22) })))

        ctx))


(define-private (run-test (test-id uint) (test-result (response bool uint)))
    (if (is-err test-result)
    test-result
    (let (
        (test-vector (try! (match (map-get? test-vectors test-id)
            vec (ok vec)
            (begin
                (test-fail! (concat "No such test vector #" (int-to-ascii test-id)))
                (err u2)))))

        (owner (get owner test-vector))
        (user-pubkey (get user-pubkey test-vector))
        (outcome-id (get outcome-id test-vector))
        (utxo-ptrs (get utxo-ptrs test-vector))
        (cur-btc-height (get cur-btc-height test-vector))
        (provider (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 user-pubkey))))
        (expected-result (get expected-result test-vector))

        (res (inner-create-contract-transfer-outcome
            owner
            user-pubkey
            outcome-id
            utxo-ptrs
            cur-btc-height))

    )
    (print (concat "Run test #" (int-to-ascii test-id)))
    (asserts! (is-eq res expected-result)
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
            (err u11)))

    (if (is-ok res)
        ;; verify that the contract transfer outcome exists, if this was successful 
        (begin
            (try! (match (map-get? contract-transfer-outcomes outcome-id)
                outcome (begin
                    (asserts! (is-eq (get wtxids outcome) (list))
                        (begin
                            (test-fail! (concat "Incorrect transfer outcome for wtxids in test #" (int-to-ascii test-id)))
                            (err u12)))

                    (asserts! (is-eq (get utxo-ptrs outcome) utxo-ptrs)
                        (begin
                            (test-fail! (concat "Incorrect transfer outcome for utxo-ptrs in test #" (int-to-ascii test-id)))
                            (err u13)))

                    (asserts! (is-eq (get provider outcome) provider)
                        (begin
                            (test-fail! (concat "Incorrect transfer outcome for provider in test #" (int-to-ascii test-id)))
                            (err u14)))

                    (asserts! (is-eq (get owner outcome) owner)
                        (begin
                            (test-fail! (concat "Incorrect transfer outcome for owner in test #" (int-to-ascii test-id)))
                            (err u15)))

                    (asserts! (is-eq (get user-pubkey outcome) user-pubkey)
                        (begin
                            (test-fail! (concat "Incorrect transfer outcome for user-pubkey in test #" (int-to-ascii test-id)))
                            (err u16)))

                    (asserts! (is-eq (get closed outcome) false)
                        (begin
                            (test-fail! (concat "Incorrect transfer outcome for closed in test #" (int-to-ascii test-id)))
                            (err u17)))

                    (asserts! (is-eq (get voided outcome) false)
                        (begin
                            (test-fail! (concat "Incorrect transfer outcome for voided in test #" (int-to-ascii test-id)))
                            (err u18)))

                    (ok true))
                (begin
                    (test-fail! (concat "Transfer outcome not registered for test #" (int-to-ascii test-id)))
                    (err u19))))

            ;; verify that each UTXO in our UTXO list was reserved
            (try! (match
                (get check-result (fold check-reserved-utxo utxo-ptrs { check-result: (ok true), outcome-id: outcome-id, expires: u1030 }))
                    ok-res (ok ok-res)
                    err-res
                        (begin
                            (test-fail! (concat "Failed to check reserved UTXOs for test #" (int-to-ascii test-id)))
                            (print (concat "check failure: err " (int-to-ascii err-res)))
                            (err err-res))))

            true)
        ;; otherwise, verify that there has been no change
        true)
        
    (ok true))))

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
