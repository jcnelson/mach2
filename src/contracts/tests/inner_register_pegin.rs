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
clarity_test!(test_clarity_store_wtx_and_register_pegin, {
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
(print (inner-register-cosigner COSIGNER_ADDR COSIGNER_KEYS))

(define-map test-vectors uint
    {
        cosigner: principal,
        tx: (buff 4096),
        block-header: (buff 80),
        block-height: uint,
        block-hash: (buff 32),
        tx-index: uint,
        tree-depth: uint,
        tx-proof: (list 14 (buff 32)),
        witness-merkle-root: (buff 32),
        witness-reserved: (buff 32),
        coinbase-tx: (buff 4096),
        coinbase-tx-proof: (list 14 (buff 32)),
        pegin-output: uint,
        witness-data: {
            recipient-principal: principal,
            user-pubkey: (buff 33),
            locktime: uint,
            safety-margin: uint
        },
        expected-result: (response (buff 32) uint)
    })

(define-data-var test-vector-index (list 256 uint)
    (list u0))

(map-insert test-vectors u0
    {
        cosigner: COSIGNER_ADDR,
        tx: WTX,
        block-header: 0x00000020d23d78bc98a60193fbc4220300c60232363d1bca96eda55f54d0212937d0764f73c4e0b11c97ddd49432fc2cc28ad27fb901e8e3f1591052eeaead920ebdac5f3998de69ffff7f2000000000,
        block-height: u128,
        block-hash: 0x3b628825bfd97075499dc08bf456453196faa2db91ef960b4c6aed78372ba6ff,
        tx-index: u2,
        tree-depth: u2,
        tx-proof: (list
            (reverse-buff32 0xb9e3a2ef750167a163c88ab9bbc7435ba6030bf77905fd4565d34f2cdb455906)
            (reverse-buff32 0x6cc139a2c1be93a52784f274180be5fbaab44089a77dd8a16dbd82898f473fdd)
        ),
        witness-merkle-root: (reverse-buff32 0x02ccb378fd29a529ef6a7d211cb75915cb3258460e05bb8834479558fc09bb0a),
        witness-reserved: 0x0000000000000000000000000000000000000000000000000000000000000000,
        coinbase-tx: 0x02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0402800000ffffffff0261e1062a01000000160014916f8c456f282ec7c14d40de0a7ff5af74abc1950000000000000000266a24aa21a9edf78f2a2b234e17778b4fe3ce0f8cf7113431854fb089fa51e54ecc9b4ae6847700000000,
        coinbase-tx-proof: (list
            (reverse-buff32 0xb8e905271c485266bd8f566ad235f466eea437504ac175a1a649e729241cb153)
            (reverse-buff32 0xed04bfcab0cf233be775537151604fea6c9e4c77ab6674a6696c9e8dda8e6e8c)
        ),
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        },
        expected-result: (ok WTXID)
    })

(define-private (run-test (test-id uint) (test-result (response bool uint)))
    (if (is-err test-result)
        test-result
        (let (
            (test-vector (try! (match (map-get? test-vectors test-id)
                tv (ok tv)
                (begin
                    (test-fail! (concat "No such test vector #" (int-to-ascii test-id)))
                    (err u0)))))

            (cosigner (get cosigner test-vector))
            (wtx (get tx test-vector))
            (btc-block-height (get block-height test-vector))
            (btc-block-hash (get block-hash test-vector))
            (btc-header (get block-header test-vector))
            (btc-tx-index (get tx-index test-vector))
            (tree-depth (get tree-depth test-vector))
            (wproof (get tx-proof test-vector))
            (witness-merkle-root (get witness-merkle-root test-vector))
            (witness-reserved (get witness-reserved test-vector))
            (btc-coinbase-tx (get coinbase-tx test-vector))
            (btc-coinbase-proof (get coinbase-tx-proof test-vector))
            (pegin-output (get pegin-output test-vector))
            (witness-data (get witness-data test-vector))

            (precheck (match (get expected-result test-vector)
                ok-wtxid
                (begin
                    ;; not stored yet
                    (asserts! (is-none (map-get? decoded-transactions ok-wtxid))
                        (begin
                            (test-fail! (concat "Already have tranasaction for test vector #" (int-to-ascii test-id)))
                            (err u1)))

                    ;; no mapping yet
                    (asserts! (not (has-transaction? ok-wtxid))
                        (begin
                            (test-fail! (concat "Already have wtxid mapping for test vector #" (int-to-ascii test-id)))
                            (err u2)))

                    ;; mock the bitcoin header
                    (asserts! (is-ok (contract-call? .bitcoin mock-add-burnchain-block-header-hash btc-block-height btc-block-hash))
                        (begin
                            (test-fail! (concat "Failed to mock bitcoin block header hash for test vector #" (int-to-ascii test-id)))
                            (err u10)))

                    ;; check that .bitcoin's get-bc-h-hash works correctly when mocked
                    (asserts! (is-eq (contract-call? .bitcoin get-bc-h-hash btc-block-height) (some btc-block-hash))
                        (begin
                            (test-fail! (concat "Failed to store mock bitcoin block header hash for test vector #" (int-to-ascii test-id)))
                            (err u11)))

                    ;; check that we can verify a block header
                    (asserts! (is-eq (contract-call? .bitcoin verify-block-header btc-header btc-block-height) true)
                        (begin
                            (test-fail! (concat "Failed to verify block header for test vector #" (int-to-ascii test-id)))
                            (err u12)))

                    ;; check that we can verify that the coinbase was mined, using mocked state
                    (match (contract-call? .bitcoin was-tx-mined-internal
                            btc-block-height
                            btc-coinbase-tx
                            btc-header
                            (get merkle-root (unwrap-panic (contract-call? .bitcoin parse-block-header btc-header)))
                            { tx-index: u0, hashes: btc-coinbase-proof, tree-depth: tree-depth})

                        ok-txid (begin
                            (print "got txid from was-tx-mined-internal")
                            true)

                        err-val (begin
                            (test-fail! (concat "was-tx-mined-internal failed: " (int-to-ascii err-val)))
                            (asserts! false (err u14))))

                    ;; check that we can verify that the whole tx was mined, using mocked state
                    (match (contract-call? .bitcoin was-segwit-tx-mined-compact
                            btc-block-height
                            wtx
                            btc-header
                            btc-tx-index
                            tree-depth
                            wproof
                            witness-merkle-root
                            witness-reserved
                            btc-coinbase-tx
                            btc-coinbase-proof)

                        ok-txid (begin
                            (print "got txid from was-segwit-tx-mined-compact")
                            true)

                        err-val (begin
                            (test-fail! (concat "was-segwit-tx-mined-compact failed: " (int-to-ascii err-val)))
                            (asserts! false (err u15))))
                        
                    true)
                err-code
                    true))

            (test-res (inner-register-pegin
                cosigner
                wtx
                btc-header
                btc-block-height
                btc-tx-index
                tree-depth
                wproof
                witness-merkle-root
                witness-reserved
                btc-coinbase-tx
                btc-coinbase-proof
                pegin-output
                witness-data))
        )

        (asserts! (is-eq (get expected-result test-vector) test-res)
            (begin
                (test-fail! (concat "Did not get expected result for test vector #" (int-to-ascii test-id)))
                (print "expected-result")
                (match (get expected-result test-vector)
                    ok-expected-res (begin (print "ok") (print ok-expected-res) true)
                    err-expected-res (begin (print "err") (print err-expected-res) true))
                (print "test-res")
                (match test-res
                    ok-test-res (begin (print "ok") (print ok-test-res) true)
                    err-test-res (begin (print "err") (print err-test-res) true))
                (err u3)))

        (match test-res
            ok-wtxid
            (begin
                ;; transaction is now stored
                (asserts! (is-some (map-get? decoded-transactions ok-wtxid))
                    (begin
                        (test-fail! (concat "Failed to store transaction in test vector #" (int-to-ascii test-id)))
                        (err u4)))

                ;; mapped to txid
                (asserts! (has-transaction? ok-wtxid)
                    (begin
                        (test-fail! (concat "Did not map wtxid to txid for test vector #" (int-to-ascii test-id)))
                        (err u5)))

                true)
            err-code
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

