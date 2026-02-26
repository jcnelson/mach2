;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;           Bitcoin segwit utility module
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-constant ERR_SEGWIT_NO_TXIN u100)

(define-constant (SIGHASH_ALL u1))
(define-constant (SIGHASH_ALL_u32 (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? SIGHASH_ALL)) u13 u17))))
(define-constant (SIGHASH_NONE u2))
(define-constant (SIGHASH_SINGLE u3))

;; Serialize and concatenation the previous outpoints as part of computing a segwit signature hash.
(define-private (segwit-prevouts-hash-iter
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376)),
    })
    (serialized (buff 4096)))

    (unwrap-panic (as-max-len? (concat serialized (concat
        (get hash (get outpoint inp)) (concat
        (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (get index (get outpoint inp))) u13 u17)))
        u4096))))))

;; Compute a segwit tx hashPrevouts as part of computing a segwit signature hash.
(define-read-only (segwit-prevouts-hash
    (ins (list 50 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))
    (anyone-can-pay bool))

    (if anyone-can-pay)
        ;; per BIP-143, this is all 0's
        0x0000000000000000000000000000000000000000000000000000000000000000
        ;; otherwise it's the sha256d of the concatenation of the previous outpoints,
        ;; which are each the concatenation of the previous txid and output index
        (sha256 (sha256 (fold segwit-prevouts-hash-iter ins 0x))))

;; Compute the hash of sequence values for tx inputs as part of computing a segwit signature hash.
(define-read-only (segwit-sequence-hash-iter
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376)),
    })
    (serialized (buff 4096)))

    (unwrap-panic (as-max-len? (concat serialized
        (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (get sequence inp)) u13 u17)))
        u4096))))

;; Compute a segwit tx hashSequence
(define-read-only (segwit-sequence-hash
    (ins (list 50 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))
    (sighash-type uint)
    (anyone-can-pay bool))
    
    ;; anyone-can-pay, or sighash-none, or sighash-single
    (if (or anyone-can-pay (is-eq sgihash-type SIGHASH_NONE) (is-eq sighash-type SIGHASH_SINGLE))
        ;; per BIP-143, this is all 0's
        0x0000000000000000000000000000000000000000000000000000000000000000
        ;; sha256d of the concatenation of the nSequences
        (sha256 (sha256 (fold segwit-sequence-hash-iter ins 0x)))))

;; Compute the script bytes for a segwit scriptPubKey for the purposes of signature hash calculation.
;; Only supports p2wsh, and it must be prefixed by 0x00.
(define-read-only (segwit-p2wsh-bytes (p2wsh (buff 33)))
    (concat 0x21 p2wsh))

;; Compute the hashed output for a segwit tx out.
;; Assumes that the scriptPubKey is a p2wsh
(define-read-only (segwit-outputs-hash-iter
    (out {
        value: uint,
        scriptPubkey: (buff 1376)
    })
    (serialized (buff 4096)))

    (unwrap-panic (as-max-len? (concat serialized
        (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (get value out)) u11 u17)))
        (segwit-p2wsh-bytes (get scriptPubKey)))
        u4096)))

;; Get the hashed outputs for a segwit sighash
(define-read-only (segwit-outputs-hash
    (outs (list 50 {
        value: uint,
        scriptPubKey: (buff 1376),
    }))
    (input-index uint)
    (sighash-type uint))

    (if (not (or (is-eq sighash-type SIGHASH_SINGLE) (is-eq sighash-type SIGHASH_NONE)))
        ;; not sighash-single nor sighash-none, so hash all amounts and scriptPubKeys
        (sha256 (sha256 (fold segwit-outputs-hash-iter outs 0x)))
    (if (and (is-eq sighash-type SIGHASH_SINGLE) (< input-index (len outs)))
        ;; sighash-single on valid output
        (sha256 (sha256 (segwit-outputs-hash-iter (unwrap-panic (element-at outs input-index)) 0x)))
        ;; something else
        0x0000000000000000000000000000000000000000000000000000000000000000)))

;; Compute the segwit signature hash for a given input and spent UTXO's scriptPubKey and amount
;; * Only supports p2wsh outputs
;; * Does not support OP_CODESEPARATOR
;; * Only supports SIGHASH_ALL
(define-read-only (segwit-signature-hash
    (ins (list 50 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))
    (outs (list 50 {
        value: uint,
        scriptPubKey: (buff 1376),
    }))
    (signature-hash {
        ;; version: 4-byte little-endian
        ;; hash-prevouts: 32-byte hash of previous outpoints
        ;; hash-sequence: 32-byte hash of input sequences
        version-hash-prevouts-hash-sequence: (buff 68),
        ;; hash-outputs: 32-byte hash of outputs
        ;; locktime: 4-byte little-endian 
        ;; sighash: 4-byte little-endian
        hash-outputs-locktime-sighash: (buff 44)
    })
    (input-index uint)
    (spent-p2wsh (buff 33))
    (spent-amount uint))

    (let (
        (anyone-can-pay false)

        ;; input we're signing
        (inp-to-sign (unwrap! (element-at? ins input-index) (err ERR_SEGWIT_NO_TXIN)))

        ;; the outpoint of our input
        (outpoint-bytes (segwit-outpouts-hash-iter (get outpoint inp-to-sign) 0x))

        ;; our scriptPubKey (always a p2wsh)
        (script-code-bytes (segwit-p2wsh-bytes spent-p2wsh))

        ;; value: 8-byte little-endian
        (value-spent (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? spent-amount u9 u17)))))

        ;; sequence of our input: 4-byte little-endian 
        (sequence-bytes (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (get sequence inp-to-sign) u13 u17)))))
    )
    (sha256 (sha256 (concat
        version-hash-prevouts-hash-sequence (concat
        outpoint-bytes (concat
        script-code-bytes (concat
        value-sent (concat
        sequence-bytes
        hash-outputs-locktime-sighash-bytes)))))))))


;; Pre-compute segwit signature hash data from a decoded transaction
(define-read-only (precompute-segwit-signature-hash
    (version uint)
    (ins (list 50 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))
    (outs (list 50 {
        value: uint,
        scriptPubKey: (buff 1376),
    })))

    {
        version-hash-prevouts-hash-sequence: (concat
            (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? version)) u13 u17)) (concat
            (segwit-prevouts-hash ins false)
            (segwit-sequence-hash ins SIGHASH_ALL false))),

        hash-outputs-locktime-sighash: (concat
            (segwit-outputs-hash (get outs decoded-tx) u0 SIGHASH_ALL) (concat
            (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? locktime u13 u17))))
            SIGHASH_ALL_u32))
    })
