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

// register a pegin tx 
// TODO: add more!
clarity_test!(test_clarity_inner_register_pegin_utxo, {
    let generated_code = r#"

;; store a pegin transaction
(define-constant WTX 0x01000000000102a5c17d7f48a85a0d992cbe83c677b8bb7d35c0f6e1e5169c6be676e927921ae30000000000fdffffff3f6a894225818a9c1bf84b7b3f36bdeaa92212e9df59b4dc50573f83ec96f0aa0000000000fdffffff0200f2052a01000000220020d20c2b12e7b42e0ce3b7334db8e76faeafabef54802cfb3d410a319a74331adfc055052a0100000016001492654bb92c6ead4303d85b8f5cb915ce019b247302483045022100840a692bdd477fec4fc73451bccb114e71c1ab284f56794dd16c5e6ac4a88c6d0220308574fc53adfc5dae4435efd45e082b41b5a0e41d256d28380fbf5270757767012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f0247304402203a6c5cb48afa4debaebbe3a556b4b88eddd724584e23ea029d65896a9113cdba02205092938c053c931b8aaa0052d48de61be5c1eba5481b74e8ecfac29f6c0e9f7e012103deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f00000000)

(define-constant PEGIN_WTXID (unwrap-panic (parse-and-store-wtx WTX)))

(define-constant COSIGNER_ADDR 'ST2D7JNTKA11T11QYCXEQPJQ97TETW7MKKWPJT770)
(define-constant COSIGNER_KEYS (list
    0x03fe11e4e59b6c3c2a5a5760df9d4a903f7b478a146fc2947a9f04518419fa6387
    0x031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a
    0x03fc17d6b3fb08855ff1bdefd68fa8fa9a5b4b9708fcad2c72cde4371088aaceea
))

(define-map test-vectors uint {
    inputs: {
        cosigner-addr: principal,
        cur-btc-height: uint,
        wtxid: (buff 32),
        pegin-output: uint,
        witness-data: {
            recipient-principal: principal,
            user-pubkey: (buff 33),
            locktime: uint,
            safety-margin: uint
        }
    },
    outputs: {
        txid: (buff 32),
        balance-increase: uint,
        result: (response (buff 33) uint)
    }
})

(define-data-var test-vector-index (list 4096 uint)
    (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11))

;; insert of the UTXO fails if we change the user key,
;; since changing the user public key would lead to an invalid witness script.
(map-insert test-vectors u0 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x031c3141781be53e2abee5d0a64b15bb6e5decceb10e8c519b146d8e4effd5621a,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_TX_INVALID_PEGIN_P2WSH)
    }
})

;; insert of the UTXO fails if we change the recipient,
;; since changing the recipient would lead to an invalid witness script.
(map-insert test-vectors u1 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST2D7JNTKA11T11QYCXEQPJQ97TETW7MKKWPJT770,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_TX_INVALID_PEGIN_P2WSH)
    }
})

;; insert of the UTXO fails if we change the locktime,
;; since changing the locktime would lead to an invalid witness script.
(map-insert test-vectors u2 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1001,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_TX_INVALID_PEGIN_P2WSH)
    }
})

;; insert of the UTXO fails if we change the safety-margin,
;; since changing the safety-margin would lead to an invalid witness script.
(map-insert test-vectors u3 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u31
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_TX_INVALID_PEGIN_P2WSH)
    }
})

;; insert of the UTXO fails if the safety margin is equal to or exceeds the locktime
(map-insert test-vectors u4 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u1000
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_WITNESS_BAD_LOCKTIME)
    }
})

;; insert of the UTXO fails if the `locktime - safety-margin` value is not postdated
(map-insert test-vectors u5 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u1030,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_WITNESS_BAD_LOCKTIME)
    }
})

;; insert of the UTXO fails if the transaction does not exist
(map-insert test-vectors u6 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee93,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_NO_BTC_TRANSACTION)
    }
})

;; insert of a UTXO fails if the cosigner isn't registered
(map-insert test-vectors u7 {
    inputs: {
        cosigner-addr: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_NO_SUCH_COSIGNER)
    }
})

;; insert of a UTXO fails if the pegin output index isn't mapped
(map-insert test-vectors u8 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u10,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_NO_PEGIN_UTXO)
    }
})

;; insert of a UTXO fails if the pegin's scriptPubKey isn't the witness script hash
(map-insert test-vectors u9 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u1,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u5000000000,
        result: (err ERR_TX_INVALID_PEGIN_P2WSH)
    }
})

;; This insert works
(map-insert test-vectors u10 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u5000000000,
        result: (ok PEGIN_WTXID)
    }
})

;; subsequent insert of the same UTXO fails, since the provider is already registered with the given key.
(map-insert test-vectors u11 {
    inputs: {
        cosigner-addr: COSIGNER_ADDR,
        cur-btc-height: u50,
        wtxid: PEGIN_WTXID,
        pegin-output: u0,
        witness-data: {
            recipient-principal: 'ST3KHDCRH3V1N41J822M4NRN2XDJSAK5GK9CFYZWD,
            user-pubkey: 0x03deef1f0aa19e1a91c960cb0007be1ebe1309017ddfca7996b89a81ed31c4393f,
            locktime: u1000,
            safety-margin: u30
        }
    },
    outputs: {
        txid: 0x40b390e3bf0ec432407ba5260266c51629fc9de9de7b0908728059309d69ee92,
        balance-increase: u0,
        result: (err ERR_PROVIDER_EXISTS)
    }
})

;; providers we registered UTXOs for
(define-map registered-providers principal uint)

;; register the cosigner for this pegin
(print (inner-register-cosigner COSIGNER_ADDR COSIGNER_KEYS))

(define-private (test-inner-register-pegin-utxo (index uint) (test-result (response bool uint)))
    (if (is-ok test-result)
        (begin
        (let (
            (test-vector (try! (match (map-get? test-vectors index)
                vector (ok vector)
                (begin
                    (test-fail! (concat "No such test vector #" (int-to-ascii index)))
                    (err u1)))))

            (test-inputs (get inputs test-vector))

            (cosigner-addr (get cosigner-addr test-inputs))
            (cur-btc-height (get cur-btc-height test-inputs))
            (wtxid (get wtxid test-inputs))
            (pegin-output (get pegin-output test-inputs))
            (witness-data (get witness-data test-inputs))
            (recipient (get recipient-principal witness-data))
            (expires (+ (get safety-margin witness-data) (get locktime witness-data)))

            (expected-outputs (get outputs test-vector))
            
            (recipient-balance-before (get-balance recipient cur-btc-height))
            (provider (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 (get user-pubkey witness-data)))))

            (precheck (match (get result expected-outputs)
                ok-wtxid
                (begin
                    (asserts! (is-eq ok-wtxid wtxid)
                        (begin
                            (test-fail! (concat "Invalid wtxid for test vector #" (int-to-ascii index)))
                            (err u10)))

                    ;; UTXO must not be registered
                    (asserts! (is-none (map-get? utxos { txid: (get txid expected-outputs), vout: u0 }))
                        (begin
                            (test-fail! (concat "UTXO exists for test vector #" (int-to-ascii index)))
                            (err u2)))
                   
                    ;; BTC provider must not be present if we haven't registered it yet
                    (asserts! (is-eq (is-none (map-get? registered-providers provider)) (is-none (map-get? btc-providers provider)))
                        (begin
                            (test-fail! (concat "Principal exists for test vector #" (int-to-ascii index)))
                            (err u3)))

                    true)
                err-wtxid
                    true))

            (res (inner-register-pegin-utxo cosigner-addr cur-btc-height wtxid pegin-output witness-data))
        )
        (print (concat "Test vector #" (int-to-ascii index)))
        (asserts! (is-eq res (get result expected-outputs))
            (begin
                (test-fail! (concat "Failed to correctly process test vector #" (int-to-ascii index)))
                (match res
                    ok-res (begin (print "ok") (print ok-res) true)
                    err-res (begin (print "err") (print err-res) true))
                (err u2)))

        ;; postcheck
        (match (get result expected-outputs)
            ok-wtxid
            (begin
                ;; UTXO must now be registered
                (asserts! (is-none (map-get? utxos { txid: (get txid expected-outputs), vout: u0 }))
                    (begin
                        (test-fail! (concat "UTXO does not exist for test vector #" (int-to-ascii index)))
                        (err u5)))
                
                ;; BTC provider is present
                (asserts! (is-some (map-get? btc-providers provider))
                    (begin
                        (test-fail! (concat "Principal does not exist for test vector #" (int-to-ascii index)))
                        (err u6)))

                ;; balance of user principal increased
                (asserts! (is-eq (get-balance recipient cur-btc-height) (+ (get balance-increase expected-outputs) recipient-balance-before))
                    (begin
                        (test-fail! (concat "Balance is wrong for test vector #" (int-to-ascii index)))
                        (err u7)))

                ;; model update
                (map-set registered-providers provider u1)
                true)
            err-wtxid
                true)

        (ok true)))

        test-result))

(define-public (test)
    (let (
        (final-result (fold test-inner-register-pegin-utxo (var-get test-vector-index) (ok true)))
    )
    (print "Final result:")
    (match (print final-result)
        ok-res true
        err-res true)
    (ok true)))
"#;
    generated_code
});
