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


clarity_test!(test_clarity_inner_complete_transfer, {
    let generated_code = r#"

(define-constant WTX 0x01000000000102f0ab4e2daa6ba6ce679eba4cc40a9db01c1b320515eb12264099225eba53f7390300000000fdffffff1e3b4b20e62fa361c688ee724f8a3eb30c9991546b8afbdadc2c270b3a0807560000000000fdffffff0200f2052a01000000220020d20c2b12e7b42e0ce3b7334db8e76faeafabef54802cfb3d410a319a74331adfe645f7290100000016001492654bb92c6ead4303d85b8f5cb915ce019b247302483045022100b7e7dc39ada00b2882c896c422ca8875af12ddecbb96b448ca4f68f76ae4f49802204960c39086b62301ace214f3d2a53232ace1051b64f8f845b9c7a8a1f9a9dbaa012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f02483045022100ba3873a8c34046b39961b5f1b31ac5ddd7279318a783aded108905d38063f39002206a094f6dafcbd731197b03307fe8fbef72db53709c155d455b1fce505f2afa61012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000)

(define-constant PARTIALLY_SIGNED_OUTCOME_WTX 0x0100000000010122973bf6b5b4a007ba749352bd310c98ace6d8f662c487c5c773232bfc5874980000000000fdffffff0118ee052a0100000016001492654bb92c6ead4303d85b8f5cb915ce019b247303004830450221008a4ddaa0ff6676588810fb6ba9ee5158b954274eca90e9e1e40388e856f43279022024337368b6b247e0942639bbed864282a1ac2038114d4ab97ac4f3783a87cc5001b216051ae716b3111ec352064810a84ae2a2eb65954cb09a750203cab1752103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393fad532103fe11e4e59b6c3c2a5a5760df9d4a903f7b478a146fc2947a9f04518419fa638721031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a2103fc17d6b3fb08855ff1bdefd68fa8fa9a5b4b9708fcad2c72cde4371088aaceea53ae92640203e8b1675168f4010000)

(define-constant WTXID (sha256 (sha256 WTX)))

(define-constant PARTIALLY_SIGNED_WTXID (sha256 (sha256 PARTIALLY_SIGNED_OUTCOME_WTX)))

(define-constant COSIGNER_ADDR 'ST2D7JNTKA11T11QYCXEQPJQ97TETW7MKKWPJT770)
(define-constant COSIGNER_KEYS (list
    0x03fe11e4e59b6c3c2a5a5760df9d4a903f7b478a146fc2947a9f04518419fa6387
    0x031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a
    0x03fc17d6b3fb08855ff1bdefd68fa8fa9a5b4b9708fcad2c72cde4371088aaceea
))

(define-constant COSIGNER_SIGS
    (list 
        (list
            0x3045022100dc4dd04235360f2424e013b8517164b87d23cc20999dab7684f13ba489cc824b0220490240eee4c65886b7fcb66c956bbc37a5c745cd24c79377d2372ab799cb3b8101
            0x3045022100c012b3f28667305f18ea226de332db288738f35a1dd11600c31b49b89e2d9c4402206189948b912fe02797079cf7d8cb1af2d073b1340c39231ec609b7b2eb3a21cf01
            0x304402203353a74b52fae3835584536b769533268207aa81eb46cf99abe4c65aa30c4b4302206607061f54087dcf3a35c8ba2ab1b62ad00ddfbad1290618e948119d6777ed9501
        )
    )
)

;; register the cosigner for this pegin
(asserts! (is-ok (inner-register-cosigner COSIGNER_ADDR COSIGNER_KEYS))
    (begin
        (test-fail! "Failed to register cosigner")
        (err u1234567890)))

(define-constant OWNER 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD)
(define-constant USER_PUBKEY 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f)
(define-constant PROVIDER (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 USER_PUBKEY))))

;; carry out this pegin
(let (
    (pegin {
        cosigner: COSIGNER_ADDR,
        tx: WTX,
        block-header: 0x00000020d685b9df61afe35320d2822dd13a7bd4a28dbb4951869f278ac439e49311a70cb1c90a8e80a41e5277eb5e511df65bb9b7f9dda79b9a049767169c3edfeaa08aec5bea69ffff7f2000000000,
        block-height: u128,
        block-hash: (reverse-buff32 0x9f963c4494c7da57cb3d588228d79afb2d5edd0b1042c4f5a1ccdae56e00a26e),
        tx-index: u2,
        tree-depth: u2,
        tx-proof: (list (reverse-buff32 0xa5785c168cea29ba811bf17799a39ae286ecd7305f2befd9e927e7ad7861ecb2) (reverse-buff32 0xc7cdc64aafa74a3504d69faaf4fbe8c428043e08a4ec0bb247e19cca2e9ae41e)),
        witness-merkle-root: (reverse-buff32 0x04efd75ff54a63499909b9c81005cf25c557727e13b97f059452175f82ec243b),
        witness-reserved: 0x0000000000000000000000000000000000000000000000000000000000000000,
        coinbase-tx: 0x02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0402800000ffffffff0261e1062a01000000160014916f8c456f282ec7c14d40de0a7ff5af74abc1950000000000000000266a24aa21a9edc420d19607f1caad2251af17f941354adb56aac79123a25c0c84c219f59e429100000000,
        coinbase-tx-proof: (list (reverse-buff32 0x39f753ba5e2299402612eb1505321b1cb09d0ac44cba9e67cea66baa2d4eabf0) (reverse-buff32 0xb0ad207a140e6fa3e10663e4583e479641003a43dbdd9959c860e9c774666a48)),
        pegin-output: u0,
        witness-data: {
            recipient-principal: OWNER,
            user-pubkey: USER_PUBKEY,
            locktime: u1000,
            safety-margin: u30
        }
    })
)
(asserts! (is-ok (contract-call? .bitcoin mock-add-burnchain-block-header-hash (get block-height pegin) (get block-hash pegin)))
    (begin
        (test-fail! "Failed to mock bitcoin block header hash")
        (err u11111)))

(asserts! (is-ok (inner-register-pegin
        (get cosigner pegin)
        (get tx pegin)
        (get block-header pegin)
        (get block-height pegin)
        (get tx-index pegin)
        (get tree-depth pegin)
        (get tx-proof pegin)
        (get witness-merkle-root pegin)
        (get witness-reserved pegin)
        (get coinbase-tx pegin)
        (get coinbase-tx-proof pegin)
        (get pegin-output pegin)
        (get witness-data pegin)))
    (begin
        (test-fail! "Failed to peg in")
        (err u22222)))
)

;; create an outcome for this pegin transaction's pegin UTXO
(asserts! (is-ok (inner-create-contract-transfer-outcome
        OWNER
        USER_PUBKEY
        { contract: .mach2, id: u0 }
        (list { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 })
        u128))
    (begin
        (test-fail! "Failed to create transfer outcome")
        (err u3333333)))

;; add an outcome for this pegin transaction's pegin UTXO.
;; This will be outcome #0
(let (
    (outcome {
        owner: OWNER,
        outcome-id: { contract: .mach2, id: u0 },
        partially-signed-wtx: PARTIALLY_SIGNED_OUTCOME_WTX,
        cur-btc-height: u200,
    })
)
(asserts! (is-ok (inner-add-contract-transfer-outcome
        (get owner outcome)
        (get outcome-id outcome)
        (get partially-signed-wtx outcome)
        (get cur-btc-height outcome)))
    (begin
        (test-fail! "Failed to add a transfer outcome")
        (err u444444444)))
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; mock UTXOs with different owners
(define-constant MOCK_OWNER 'ST2VAT594GNDG58C8BM04SP2H1VMHKV0Y632AMPCR)
(define-constant MOCK_USER_PUBKEY 0x03fa6775b16d1b853dd0c0368fbcc6e612e2b8863f358cbfafac5d53d4f1700b1d)
(define-constant MOCK_PROVIDER (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 MOCK_USER_PUBKEY))))

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

(map-insert contract-reserved-utxos
    { txid: 0x01, vout: u0 }
    { outcome-id: { contract: .test-missing-btc-tx, id: u0 }, expires: u1030 })

(map-insert contract-reserved-utxos
    { txid: 0x00, vout: u0 }
    { outcome-id: { contract: .test-no-provider, id: u0 }, expires: u1030 })

(map-insert contract-transfer-outcomes
    { contract: .test-missing-btc-tx, id: u0 }
    {
        utxo-ptrs: (list
            { txid: 0x01, vout: u0 }
        ),
        wtxids: (list 0x),
        provider: PROVIDER,
        owner: OWNER,
        user-pubkey: USER_PUBKEY,
        closed: false,
        voided: false
    })

(map-insert contract-transfer-outcomes
    { contract: .test-no-provider, id: u0 }
    {
        utxo-ptrs: (list
            { txid: 0x00, vout: u0 }
        ),
        wtxids: (list PARTIALLY_SIGNED_WTXID),
        provider: MOCK_PROVIDER,
        owner: MOCK_OWNER,
        user-pubkey: MOCK_USER_PUBKEY,
        closed: false,
        voided: false
    })

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-map test-vectors uint
{
    cosigner-addr: principal,
    outcome-id: { contract: principal, id: uint },
    wtxid-index: uint,
    cosigner-sigs: (list 16 (list 10 (buff 73))),
    cur-btc-height: uint,
    expected-result: (response bool uint)
})

(define-data-var test-vector-index (list 256 uint)
    (list u0 u1 u2 u20 u3 u30 u4 u5))

;; no such outcome
(map-insert test-vectors u0 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .mach2, id: u1 },
    wtxid-index: u0,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u201,
    expected-result: (err ERR_NO_SUCH_TRANSFER_OUTCOME)
})

;; no such wtxid
(map-insert test-vectors u1 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .mach2, id: u0 },
    wtxid-index: u1,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u201,
    expected-result: (err ERR_NO_SUCH_WTXID)
})

;; no such cosigner
(map-insert test-vectors u2 {
    cosigner-addr: OWNER,
    outcome-id: { contract: .mach2, id: u0 },
    wtxid-index: u0,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u201,
    expected-result: (err ERR_NO_SUCH_COSIGNER)
})

;; no such BTC transaction
(map-insert test-vectors u20 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .test-missing-btc-tx, id: u0 },
    wtxid-index: u0,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u201,
    expected-result: (err ERR_NO_BTC_TRANSACTION)
})

;; wrong cosigner signature length
(map-insert test-vectors u3 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .mach2, id: u0 },
    wtxid-index: u0,
    cosigner-sigs: (append COSIGNER_SIGS (list 0x 0x 0x)),
    cur-btc-height: u201,
    expected-result: (err ERR_WRONG_SIGNATURE_COUNT)
})

;; no such provider -- did not create any utxos
(map-insert test-vectors u30 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .test-no-provider, id: u0 },
    wtxid-index: u0,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u201,
    expected-result: (err ERR_NO_PROVIDER)
})

;; no such provider -- btc expired
(map-insert test-vectors u4 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .mach2, id: u0 },
    wtxid-index: u0,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u2001,
    expected-result: (err ERR_BTC_EXPIRED)
})

;; TODO: transaction spends at most the amount of its UTXOs

;; SUCCESS
(map-insert test-vectors u5 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .mach2, id: u0 },
    wtxid-index: u0,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u201,
    expected-result: (ok true)
})

;; closed outcome
(map-insert test-vectors u6 {
    cosigner-addr: COSIGNER_ADDR,
    outcome-id: { contract: .mach2, id: u0 },
    wtxid-index: u0,
    cosigner-sigs: COSIGNER_SIGS,
    cur-btc-height: u201,
    expected-result: (err ERR_NO_SUCH_TRANSFER_OUTCOME)
})

(define-private (run-test (test-id uint) (test-result (response bool uint)))
    (let (
        (test-vector (try! (match (map-get? test-vectors test-id)
            test-vec (ok test-vec)
            (begin
                (test-fail! (concat "No test vector #" (int-to-ascii test-id)))
                (err u555555555)))))

        (cosigner-addr (get cosigner-addr test-vector))
        (outcome-id (get outcome-id test-vector))
        (wtxid-index (get wtxid-index test-vector))
        (cosigner-sigs (get cosigner-sigs test-vector))
        (cur-btc-height (get cur-btc-height test-vector))
        (expected-result (get expected-result test-vector))

        (res (inner-complete-transfer
            cosigner-addr
            outcome-id
            wtxid-index
            cosigner-sigs
            cur-btc-height
        ))
    )
    (asserts! (is-eq res expected-result)
        (begin
            (test-fail! (concat "Did not get expected result for test #" (int-to-ascii test-id)))
            (print "expected")
            (match expected-result
                ok-res (begin (print ok-res) true)
                err-res (begin (print err-res) true))

            (print "got")
            (match res
                ok-res (begin (print ok-res) true)
                err-res (begin (print err-res) true))

            (err u2)))
           
    (if (is-ok res)
        (let (
            ;; outcome must exist
            (outcome (try! (match (map-get? contract-transfer-outcomes outcome-id)
                xfer-outcome (ok xfer-outcome)
                (begin
                    (test-fail! (concat "No transfer outcome for test #" (int-to-ascii test-id)))
                    (err u3)))))

            ;; outcome must be closed
            (outcome-closed (try! (if (get closed outcome)
                (ok true)
                (begin
                    (test-fail! (concat "Transfer outcome not closed for test #" (int-to-ascii test-id)))
                    (err u4)))))

            ;; owner's balance set to 0
            (balance-is-zero (try! (if (is-eq (get-balance OWNER cur-btc-height) u0)
                (ok true)
                (begin
                    (test-fail! (concat "Transfer did not zero balance in test #" (int-to-ascii test-id)))
                    (err u5)))))

            ;; owner's UTXOs are deleted
            (utxo-is-none (try! (if (is-none (map-get? utxos { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 }))
                (ok true)
                (begin
                    (test-fail! (concat "Transfer did not delete UTXOs for test #" (int-to-ascii test-id)))
                    (err u6)))))
        )
        (ok true))
        (ok true))
    )
)

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
