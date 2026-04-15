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

// transaction decode and store
// TODO: add more!
clarity_test!(test_clarity_parse_and_store_wtx, {
    let generated_code = r#"
(define-map test-vectors uint {
    wtx: (buff 4096),
    result: (response (buff 32) uint)
})

(define-data-var test-vector-index (list 4096 uint)
    (list u0 u1))

;; first insert works
(map-insert test-vectors u0 {
    wtx: 0x010000000001020d63e9daa0f5de4d40032d4bd4340bfbe91eb59340186851e8776c1a1c46a0830300000000fdffffff5fc66606ba2c6ac156ea0be93a1b2bc1ed6689875bfa4a8e81c264c73ac0eddf0000000000fdffffff0200f2052a010000002200201e2b7391c749b0bc6532ac4d3d088e97b9bc463d674d4dd2261d3c4da3bd4075fd3cf7290100000016001492654bb92c6ead4303d85b8f5cb915ce019b24730247304402200d464dc1e3737cfb5c1452b210480d61d5e9b47cbd97c38321a6d47d6476913602202a986420ce95b8ce463f1b8f05a7f79433e16615a8163674d31139b51ef66b51012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f0247304402200fe9861b468282a9c8fbf57363382483ab5af886b8e46c0c6b69e9503d46ec64022050ef2ff3afbacbfc500c60abec6d5dfe2b8b9336301ec9e57bb11f1ba7b99aac012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000,
    result: (ok 0x0d4ff68a4d55702048f53c6339033aa5c62fd66498c914731661b2a76aa395a4)
})

;; subsequent insert of the same tx fails
(map-insert test-vectors u1 {
    wtx: 0x010000000001020d63e9daa0f5de4d40032d4bd4340bfbe91eb59340186851e8776c1a1c46a0830300000000fdffffff5fc66606ba2c6ac156ea0be93a1b2bc1ed6689875bfa4a8e81c264c73ac0eddf0000000000fdffffff0200f2052a010000002200201e2b7391c749b0bc6532ac4d3d088e97b9bc463d674d4dd2261d3c4da3bd4075fd3cf7290100000016001492654bb92c6ead4303d85b8f5cb915ce019b24730247304402200d464dc1e3737cfb5c1452b210480d61d5e9b47cbd97c38321a6d47d6476913602202a986420ce95b8ce463f1b8f05a7f79433e16615a8163674d31139b51ef66b51012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f0247304402200fe9861b468282a9c8fbf57363382483ab5af886b8e46c0c6b69e9503d46ec64022050ef2ff3afbacbfc500c60abec6d5dfe2b8b9336301ec9e57bb11f1ba7b99aac012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000,
    result: (err ERR_TX_ALREADY_EXISTS)
})

(define-private (test-parse-and-store-wtx (index uint) (test-result (response bool uint)))
    (let (
        (test-tx (try! (match (map-get? test-vectors index)
            vector (ok vector)
            (begin
                (test-fail! (concat "No such test vector #" (int-to-ascii index)))
                (err u1)))))

        (precheck (match (get result test-tx)
            wtxid
            (begin
                ;; must not be stored
                (asserts! (is-none (map-get? decoded-transactions wtxid))
                    (begin
                        (test-fail! (concat "Transaction already stored: " (unwrap-panic (to-ascii? wtxid))))
                        (err u3)))
                
                ;; must not be mappped
                (asserts! (is-none (map-get? wtxid-to-txid wtxid))
                    (begin
                        (test-fail! (concat "Transaction wtxid-to-txid already mapped: " (unwrap-panic (to-ascii? wtxid))))
                        (err u4)))

                true)
            err-wtxid
                true))

        (res (parse-and-store-wtx (get wtx test-tx)))
    )
    (print (concat "Test vector #" (int-to-ascii index)))
    (if (is-ok test-result)
        (begin
        (asserts! (is-eq res (get result test-tx))
            (begin
                (test-fail! (concat "Failed to correctly process test vector #" (int-to-ascii index)))
                (match res
                    ok-res (begin (print ok-res) true)
                    err-res (begin (print err-res) true))
                (err u2)))

        ;; postcheck
        (match (get result test-tx)
            wtxid
            (begin
                ;; must now be stored
                (asserts! (is-some (map-get? decoded-transactions wtxid))
                    (begin
                        (test-fail! (concat "Transaction decoded but not stored: " (unwrap-panic (to-ascii? wtxid))))
                        (err u5)))
                
                ;; must now be mappped
                (asserts! (is-some (map-get? wtxid-to-txid wtxid))
                    (begin
                        (test-fail! (concat "Transaction wtxid-to-txid decoded but not mapped: " (unwrap-panic (to-ascii? wtxid))))
                        (err u6)))

                true)
            err-wtxid
                true)

        (ok true))
        test-result)))

(define-public (test)
    (let (
        (final-result (fold test-parse-and-store-wtx (var-get test-vector-index) (ok true)))
    )
    (print "Final result:")
    (match (print final-result)
        ok-res true
        err-res true)
    (ok true)))
"#;
    generated_code
});
