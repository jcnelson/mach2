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

// transaction decode
// TODO: add more!
clarity_test!(test_clarity_decode_bitcoin_wtx, {
    let generated_code = r#"
(define-map test-vectors uint {
    wtx: (buff 4096),
    result: (response
        {
            version: uint,
            segwit-marker: uint,
            segwit-version: uint,
            txid: (buff 32),
            ins: (list 16 {
                outpoint: { hash: (buff 32), index: uint },
                scriptSig: (buff 1376),
                sequence: uint,
                witness: (list 13 (buff 1376)),
            }),
            outs: (list 50 {
                value: uint,
                scriptPubKey: (buff 1376)
            }),
            locktime: uint,
            signature-hash: {
                version-hash-prevouts-hash-sequence: (buff 68),
                hash-outputs-locktime-sighash: (buff 40)
            }
        }
        uint)
})

(define-data-var test-vector-index (list 4096 uint)
    (list u0))

(map-insert test-vectors u0 {
    wtx: 0x010000000001020d63e9daa0f5de4d40032d4bd4340bfbe91eb59340186851e8776c1a1c46a0830300000000fdffffff5fc66606ba2c6ac156ea0be93a1b2bc1ed6689875bfa4a8e81c264c73ac0eddf0000000000fdffffff0200f2052a010000002200201e2b7391c749b0bc6532ac4d3d088e97b9bc463d674d4dd2261d3c4da3bd4075fd3cf7290100000016001492654bb92c6ead4303d85b8f5cb915ce019b24730247304402200d464dc1e3737cfb5c1452b210480d61d5e9b47cbd97c38321a6d47d6476913602202a986420ce95b8ce463f1b8f05a7f79433e16615a8163674d31139b51ef66b51012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f0247304402200fe9861b468282a9c8fbf57363382483ab5af886b8e46c0c6b69e9503d46ec64022050ef2ff3afbacbfc500c60abec6d5dfe2b8b9336301ec9e57bb11f1ba7b99aac012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000,
    result: (ok {
        version: u1,
        segwit-marker: u0,
        segwit-version: u1,
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        ins: (list
            {
                outpoint: {
                    hash: 0x83a0461c1a6c77e85168184093b51ee9fb0b34d44b2d03404ddef5a0dae9630d,
                    index: u3
                },
                scriptSig: 0x,
                sequence: u4294967293,
                witness: (list
                    0x304402200d464dc1e3737cfb5c1452b210480d61d5e9b47cbd97c38321a6d47d6476913602202a986420ce95b8ce463f1b8f05a7f79433e16615a8163674d31139b51ef66b5101
                    0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f
                )
            }
            {
                outpoint: {
                    hash: 0xdfedc03ac764c2818e4afa5b878966edc12b1b3ae90bea56c16a2cba0666c65f,
                    index: u0
                },
                scriptSig: 0x,
                sequence: u4294967293,
                witness: (list
                    0x304402200fe9861b468282a9c8fbf57363382483ab5af886b8e46c0c6b69e9503d46ec64022050ef2ff3afbacbfc500c60abec6d5dfe2b8b9336301ec9e57bb11f1ba7b99aac01
                    0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f
                )
            }
        ),
        outs: (list
            {
                value: u5000000000,
                scriptPubKey: 0x00201e2b7391c749b0bc6532ac4d3d088e97b9bc463d674d4dd2261d3c4da3bd4075,
            }
            {
                value: u4999036157,
                scriptPubKey: 0x001492654bb92c6ead4303d85b8f5cb915ce019b2473
            }
        ),
        locktime: u0,
        signature-hash: {
            hash-outputs-locktime-sighash: 0x28c60842cef906988c38e1cf702e43dfd6f6a085ca0b07ef54b6e62ebcc680590000000001000000,
            version-hash-prevouts-hash-sequence: 0x01000000186577930ce4fea61419a638e8cdaaf60b180c92e52dc20ea89ff52984c21ddf957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098
        }
    })
})

(define-private (test-decode-bitcoin-wtx (index uint) (test-result (response bool uint)))
    (let (
        (test-tx (try! (match (map-get? test-vectors index)
            vector (ok vector)
            (begin
                (test-fail! (concat "No such test vector #" (int-to-ascii index)))
                (err u1)))))
        (decoded-tx-res (decode-bitcoin-wtx (get wtx test-tx)))
    )
    (print (concat "Test vector #" (int-to-ascii index)))
    (if (is-ok test-result)
        (begin
        (asserts! (is-eq decoded-tx-res (get result test-tx))
            (begin
                (test-fail! (concat "Failed to correctly process test vector #" (int-to-ascii index)))
                (match decoded-tx-res
                    ok-res (begin (print ok-res) true)
                    err-res (begin (print err-res) true))
                (err u2)))

        (ok true))
        test-result)))

(define-public (test)
    (let (
        (final-result (fold test-decode-bitcoin-wtx (var-get test-vector-index) (ok true)))
    )
    (print "Final result:")
    (match (print final-result)
        ok-res true
        err-res true)
    (ok true)))
"#;

    generated_code
});


