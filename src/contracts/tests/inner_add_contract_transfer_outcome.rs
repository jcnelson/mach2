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


clarity_test!(test_clarity_inner_add_contract_transfer_outcome, {
    let generated_code = r#"

(define-constant WTX 0x0100000000010214738744b88c2fa124bbb4d4e826f1012c4d567516636df5b3f8e7750142e8c50300000000fdffffffa2cee89b5f829d06079c038f2359d929b21e66bf558745e30aa126b5f8b7399a0000000000fdffffff0200f2052a01000000220020d20c2b12e7b42e0ce3b7334db8e76faeafabef54802cfb3d410a319a74331adfcf4ef7290100000016001492654bb92c6ead4303d85b8f5cb915ce019b247302473044022026a2e2f2827fe9ed4399fcf6f5232711e67ac0c69708191e5eb4d8582b1b5733022027beeff2cca8958052da98d478e2bedc6a288c7c5edcce9920ae38d2532315c3012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f0247304402200a3a435831e47a4256537d9c7fb7eed2d3591a5e017603eacbc063afc772cf400220549ccb8ea842896e93b41a280903e9bfcd31595bb3f62fe523f4641194566d67012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000) 

(define-constant PARTIALLY_SIGNED_OUTCOME_WTX 0x01000000000101885d5892f43439c0251330df9d836137e9c6da92666e9614a183e9ec681423df0000000000fdffffff0118ee052a0100000016001492654bb92c6ead4303d85b8f5cb915ce019b24730300473044022078c72e9350533032633923e0bb83e080e38d5b9eb4d14a8da34066205e0cda8e022049a0d06eb181f9037cdb435b31c2026a31a5e0e531974345bcdc08ffa926876201b216051ae716b3111ec352064810a84ae2a2eb65954cb09a750203cab1752103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393fad532103fe11e4e59b6c3c2a5a5760df9d4a903f7b478a146fc2947a9f04518419fa638721031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a2103fc17d6b3fb08855ff1bdefd68fa8fa9a5b4b9708fcad2c72cde4371088aaceea53ae92640203e8b1675168f4010000)

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
        (err u1234567890)))

(define-constant OWNER 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD)
(define-constant USER_PUBKEY 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f)
(define-constant PROVIDER (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 USER_PUBKEY))))

;; carry out this pegin
(let (
    (pegin {
        cosigner: COSIGNER_ADDR,
        tx: 0x0100000000010214738744b88c2fa124bbb4d4e826f1012c4d567516636df5b3f8e7750142e8c50300000000fdffffffa2cee89b5f829d06079c038f2359d929b21e66bf558745e30aa126b5f8b7399a0000000000fdffffff0200f2052a01000000220020d20c2b12e7b42e0ce3b7334db8e76faeafabef54802cfb3d410a319a74331adfcf4ef7290100000016001492654bb92c6ead4303d85b8f5cb915ce019b247302473044022026a2e2f2827fe9ed4399fcf6f5232711e67ac0c69708191e5eb4d8582b1b5733022027beeff2cca8958052da98d478e2bedc6a288c7c5edcce9920ae38d2532315c3012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f0247304402200a3a435831e47a4256537d9c7fb7eed2d3591a5e017603eacbc063afc772cf400220549ccb8ea842896e93b41a280903e9bfcd31595bb3f62fe523f4641194566d67012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000,
        block-header: 0x0000002045574dcbec10fd7c62b025a434e56fece177367897f121c36f235b1d3d8c6f41e20f94b373da65ef1e45a2394add5c6de8652e18b9ddfb6f3688663bb6b62e69c6f4e769ffff7f2000000000,
        block-height: u128,
        block-hash: (reverse-buff32 0xc8d29e5b24dd507edc6001e56280f949b4f6ccd2f44ca0319c55c3a8c80ce673),
        tx-index: u2,
        tree-depth: u2,
        tx-proof: (list (reverse-buff32 0x4b2f31cf8576f9f240d36955317b9fd148bb95f1957c73ed64b3ff2f6f96d443) (reverse-buff32 0xde9ac63861e30ff49fc78c287ac401f7b5e5dd6917d73ba5a6a8a3aebe56ffd1)),
        witness-merkle-root: (reverse-buff32 0xb32a60543aebd0fc3d7448ff1a2d764d6dbb248c6f69012c4e30e338c5d9de5f),
        witness-reserved: 0x0000000000000000000000000000000000000000000000000000000000000000,
        coinbase-tx: 0x02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0402800000ffffffff0278d8062a01000000160014916f8c456f282ec7c14d40de0a7ff5af74abc1950000000000000000266a24aa21a9eda02218ecd179b2e9c51c6e53b1e19ada2ee960fff1a2897b0854dbb572eaca8000000000,
        coinbase-tx-proof: (list (reverse-buff32 0xc5e8420175e7f8b3f56d631675564d2c01f126e8d4b4bb24a12f8cb844877314) (reverse-buff32 0xb75c90c94ca305ba10907f6f3d1f10227165b06bf24d8e49ad9fabec86618482)),
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

;; create this outcome
(asserts! (is-ok (inner-create-contract-transfer-outcome
        OWNER
        USER_PUBKEY
        { contract: .mach2, id: u0 }
        (list { txid: (unwrap-panic (map-get? wtxid-to-txid WTXID)), vout: u0 })
        u128))
    (begin
        (test-fail! "Failed to create transfer outcome")
        (err u3333333)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-map test-vectors uint
{
    owner: principal,
    outcome-id: { contract: principal, id: uint },
    partially-signed-wtx: (buff 4096),
    cur-btc-height: uint,
    expected-result: (response uint uint)
})

(define-data-var test-vector-index (list 256 uint)
    (list u0))

;; TODO: no such outcome
;; TODO: not the owner
;; TODO: can't register a PSBT twice
;; TODO: can't store the same PSBT twice
;; TODO: transaction can't spend an unreserved UTXO
;; TODO: transaction can't spend an expired UTXO
;; TODO: tried to spend UTXO that was not reserved for this outcome
;; TODO: tried to spend a reserved UTXO that was expired
;; TODO: check that inputs are well-formed
;; TODO: test that check-consumed-utxos only flagged reserved, unexpired UTXOs for this outcome
;; TODO: transaction tries to spend too much

(map-insert test-vectors u0 
{
    owner: OWNER,
    outcome-id: { contract: .mach2, id: u0 },
    partially-signed-wtx: PARTIALLY_SIGNED_OUTCOME_WTX,
    cur-btc-height: u200,
    expected-result: (ok u0)
})
    
(define-private (run-test (test-id uint) (test-result (response bool uint)))
    (if (is-err test-result)
    test-result
    (let (
        (test-vector (try! (match (map-get? test-vectors test-id)
            test-vec (ok test-vec)
            (begin
                (test-fail! (concat "No such test vector #" (int-to-ascii test-id)))
                (err u1)))))

        (owner (get owner test-vector))
        (outcome-id (get outcome-id test-vector))
        (partially-signed-wtx (get partially-signed-wtx test-vector))
        (cur-btc-height (get cur-btc-height test-vector))
        (expected-result (get expected-result test-vector))

        (partially-signed-wtxid (sha256 (sha256 partially-signed-wtx)))

        (decoded-tx (try! (match (decode-bitcoin-wtx partially-signed-wtx)
            ok-tx (ok ok-tx)
            err-code
                (begin
                    (test-fail! (concat "Did not decode transaction for test #" (int-to-ascii test-id)))
                    (print (concat "got err " (int-to-ascii err-code)))
                    (err u4444444)))))

        (decoded-ins (get ins decoded-tx))

        (test-0-checks (if (is-eq test-id u0)
            (let (
                (inp-0 (try! (match (element-at? decoded-ins u0)
                    ins (ok ins)
                    (begin
                        (test-fail! (concat "Did not get inputs for partially-signed wtx in test #" (int-to-ascii test-id)))
                        (err u444444445)))))

                (check-inp-0 (try! (match (get result (check-spends-reserved-utxo-iter inp-0
                        { cur-btc-height: cur-btc-height, outcome-id: outcome-id, result: (ok true) }))
                    ok-res
                        (begin
                            (print "Checked inp 0")
                            (ok true))
                    err-res
                        (begin
                            (test-fail! (concat "Did not check input #0 for test #" (int-to-ascii test-id)))
                            (print (concat "got err " (int-to-ascii err-res)))
                            (err u55555555)))))
                
                (check-inp-0-witness (try! (match (check-txin-has-wellformed-witness inp-0 (ok true))
                    ok-res
                        (begin
                            (print "witness in inp 0 is well-formed")
                            (ok true))
                    err-res
                        (begin
                            (test-fail! (concat "Did not check input #0 witness for test #" (int-to-ascii test-id)))
                            (print (concat "got err " (int-to-ascii err-res)))
                            (print inp-0)
                            (err u5555555556)))))

                (decode-sig-result (try! (match (decode-sig-der-to-rs 0x3045022100cec8aa2f443a2159a225ef37d0f0940d344140a44f16868aedc475aa161050e9022073135db4b029bc59d1828628f5e88ad2ebae34153a25030ef0708a88dbae55d301 none)
                    ok-sig (begin
                        (print "decoded signature:")
                        (print ok-sig)
                        (asserts! (is-eq ok-sig 0xcec8aa2f443a2159a225ef37d0f0940d344140a44f16868aedc475aa161050e973135db4b029bc59d1828628f5e88ad2ebae34153a25030ef0708a88dbae55d300) (err u55555557))
                        (ok ok-sig))
                    err-code (begin
                        (print "decoded signature failure:")
                        (print err-code)
                        (err err-code)))))

                (check-user-sig (match (get result (check-sig-iter 0x3045022100cec8aa2f443a2159a225ef37d0f0940d344140a44f16868aedc475aa161050e9022073135db4b029bc59d1828628f5e88ad2ebae34153a25030ef0708a88dbae55d301 { keys: (list USER_PUBKEY), used: (list false), signature-hash: 0x4e10e5b08067dc38edcbdc1ffd1d1878084868220c4724caf0b01ec44adfc549, result: (ok true) }))
                    ok-res (begin
                        (print "signature valid for user sig")
                        (ok true))
                    err-val (begin
                        (print (concat "signature invalid for user sig: err " (int-to-ascii err-val)))
                        (err err-val))))

                (found-key (try! (if (get found (check-pubkey-on-sig-iter USER_PUBKEY { sig: decode-sig-result, signature-hash: 0x4e10e5b08067dc38edcbdc1ffd1d1878084868220c4724caf0b01ec44adfc549, found: false, i: u0 }))
                    (begin
                        (print "verified signature!")
                        (ok true))
                    (begin
                        (print "failed to verify signature!")
                        (err u66666666666)))))
            )
            true)
            false))

        (res (inner-add-contract-transfer-outcome
            owner
            outcome-id
            partially-signed-wtx
            cur-btc-height))
    )
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
            (print (map-get? wtxid-to-txid WTXID))
            (err u2)))

    (if (is-ok res)
        (begin
            ;; partially-signed transaction got stored
            (asserts! (is-some (map-get? decoded-transactions partially-signed-wtxid))
                (begin
                    (test-fail! (concat "No partially-signed transaction stored for test #" (int-to-ascii test-id)))
                    (err u3)))

            ;; outcome gained the wtx
            (let (
                (new-outcome (try! (match (map-get? contract-transfer-outcomes outcome-id)
                    outcome (ok outcome)
                    (begin
                        (test-fail! (concat "Transfer outcome not stored for test #" (int-to-ascii test-id)))
                        (err u4)))))

            )
            (asserts! (is-some (index-of? (get wtxids new-outcome) partially-signed-wtxid))
                (begin
                    (test-fail! (concat "Partially-signed wTxid not added to outcome in test #" (int-to-ascii test-id)))
                    (err u5))))

            (ok true))

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

