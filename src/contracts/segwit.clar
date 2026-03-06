;; TODO: check sequence
;; TODO: check version -- must be 2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;           Bitcoin segwit utility module
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-constant ERR_SEGWIT_NO_TXIN u100)
(define-constant ERR_SEGWIT_BAD_VERSION u101)
(define-constant ERR_SEGWIT_BAD_LOCKTIME u102)

(define-constant SIGHASH_ALL u1)
(define-constant SIGHASH_ALL_u32 (uint32-to-buff-le SIGHASH_ALL))
(define-constant SIGHASH_NONE u2)
(define-constant SIGHASH_SINGLE u3)

;; Convert a u16 to a little-endian (buff 2)
;; Upper bits are dropped.
(define-read-only (uint16-to-buff-le (val uint))
    (let (
        (val-be (bit-or
            (bit-shift-left (bit-and val u255) u8)
            (bit-shift-right (bit-and val u65280) u8)))
    )
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val-be)) u15 u17)) u2))))

;; Convert a u32 to a little-endian (buff 4)
;; Upper bits are dropped.
(define-read-only (uint32-to-buff-le (val uint))
    (let (
        (val-be (bit-or
            (bit-shift-left (bit-and val u255) u24)
            (bit-shift-left (bit-and val u65280) u8)
            (bit-shift-right (bit-and val u16711680) u8)
            (bit-shift-right (bit-and val u4278190080) u24)))
    )
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val-be)) u13 u17)) u4))))

;; Convert a u64 to a little-endian (buff 8)
;; Upper bits are dropped.
(define-read-only (uint64-to-buff-le (val uint))
    (let (
        (val-be (bit-or
            (bit-shift-left (bit-and val u255) u56)
            (bit-shift-left (bit-and val u65280) u40)
            (bit-shift-left (bit-and val u16711680) u24)
            (bit-shift-left (bit-and val u4278190080) u8)
            (bit-shift-right (bit-and val u1095216660480) u8)
            (bit-shift-right (bit-and val u280375465082880) u24)
            (bit-shift-right (bit-and val u71776119061217280) u40)
            (bit-shift-right (bit-and val u18374686479671623680) u56)))
    )
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val-be)) u9 u17)) u8))))

;; Serialize and concatenation the previous outpoints as part of computing a segwit signature hash.
(define-private (segwit-prevouts-hash-iter
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376)),
    })
    (serialized (buff 4096)))

    (unwrap-panic (as-max-len? (concat
        serialized (concat
        (get hash (get outpoint inp))
        (uint32-to-buff-le (get index (get outpoint inp)))))
        u4096)))

;; Compute a segwit tx hashPrevouts as part of computing a segwit signature hash.
(define-read-only (segwit-prevouts-hash
    (ins (list 16 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))
    (anyone-can-pay bool))

    (if anyone-can-pay
        ;; per BIP-143, this is all 0's
        0x0000000000000000000000000000000000000000000000000000000000000000
        ;; otherwise it's the sha256d of the concatenation of the previous outpoints,
        ;; which are each the concatenation of the previous txid and output index
        (sha256 (sha256 (fold segwit-prevouts-hash-iter ins 0x)))))

;; Compute the hash of sequence values for tx inputs as part of computing a segwit signature hash.
(define-read-only (segwit-sequence-hash-iter
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376)),
    })
    (serialized (buff 4096)))

    (unwrap-panic (as-max-len? (concat
        serialized
        (uint32-to-buff-le (get sequence inp)))
        u4096)))

;; Compute a segwit tx hashSequence
(define-read-only (segwit-sequence-hash
    (ins (list 16 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))
    (sighash-type uint)
    (anyone-can-pay bool))
    
    ;; anyone-can-pay, or sighash-none, or sighash-single
    (if (or anyone-can-pay (is-eq sighash-type SIGHASH_NONE) (is-eq sighash-type SIGHASH_SINGLE))
        ;; per BIP-143, this is all 0's
        0x0000000000000000000000000000000000000000000000000000000000000000
        ;; sha256d of the concatenation of the nSequences
        (sha256 (sha256 (fold segwit-sequence-hash-iter ins 0x)))))

;; Compute the varint-prefixed script
(define-read-only (segwit-varint-prefixed-script (script (buff 1376)))
    ;; length -- 1-byte or 2-byte varint
    (concat
        (if (<= (len script) u252)
            ;; length itself suffices
            (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (len script))) u16 u17))
            ;; 0xfd + 2-byte length
            (concat 0xfd (uint16-to-buff-le (len script))))
        ;; script itself
        script))

;; Compute the script bytes for a segwit witness script for the purposes of signature hash calculation.
(define-read-only (segwit-script-bytes (script (buff 1376)))
    (if (and (is-eq (len script) u22) (is-eq (unwrap-panic (slice? script u0 u2)) 0x0014))
        ;; p2wpkh --> length-prefixed p2pkh
        (concat 0x1976a914 (concat
            (unwrap-panic (slice? script u2 u22))
            0x88ac))

        ;; p2wsh or p2tr input script (we don't support code separators)
        ;; prefix the script bytes with a varint length
        (segwit-varint-prefixed-script script)))

;; Compute the hashed output for a segwit tx out.
;; Assumes that the scriptPubKey is a p2wsh. Panics otherwise.
(define-read-only (segwit-outputs-hash-iter
    (out {
        value: uint,
        scriptPubKey: (buff 1376)
    })
    (serialized (buff 4096)))

    (unwrap-panic (as-max-len? (concat
        serialized (concat
        (uint64-to-buff-le (get value out))
        (segwit-varint-prefixed-script (get scriptPubKey out))))
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

;; TODO: remove
(define-data-var last-outpoint-bytes (buff 4096) 0x)
(define-data-var last-script-code-bytes (buff 4096) 0x)
(define-data-var last-value-spent (buff 4096) 0x)
(define-data-var last-sequence-bytes (buff 4096) 0x)

;; TODO: make read-only
;; Compute the segwit signature hash for a given input and spent UTXO's scriptPubKey and amount
;; * Only supports p2wsh outputs
;; * Does not support OP_CODESEPARATOR
;; * Only supports SIGHASH_ALL
(define-public (segwit-signature-hash
    (ins (list 16 {
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
    (input-script (buff 1376))
    (spent-amount uint))

    (let (
        (anyone-can-pay false)

        ;; input we're signing
        (inp-to-sign (unwrap! (element-at? ins input-index) (err ERR_SEGWIT_NO_TXIN)))

        ;; the outpoint of our input
        (outpoint-bytes (concat
            (get hash (get outpoint inp-to-sign))
            (uint32-to-buff-le (get index (get outpoint inp-to-sign)))))

        ;; our input script (a witness script)
        (script-code-bytes (segwit-script-bytes input-script))

        ;; value: 8-byte little-endian
        (value-spent (uint64-to-buff-le spent-amount))

        ;; sequence of our input: 4-byte little-endian 
        (sequence-bytes (uint32-to-buff-le (get sequence inp-to-sign)))
    )
    (var-set last-outpoint-bytes outpoint-bytes)
    (var-set last-script-code-bytes script-code-bytes)
    (var-set last-value-spent value-spent)
    (var-set last-sequence-bytes sequence-bytes)
    (ok (sha256 (sha256 (concat
        (get version-hash-prevouts-hash-sequence signature-hash) (concat
        outpoint-bytes (concat
        script-code-bytes (concat
        value-spent (concat
        sequence-bytes
        (get hash-outputs-locktime-sighash signature-hash)))))))))))

;; Pre-compute segwit signature hash data from a decoded transaction
(define-read-only (precompute-segwit-signature-hash
    (version uint)
    (ins (list 16 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))
    (outs (list 50 {
        value: uint,
        scriptPubKey: (buff 1376),
    }))
    (locktime uint))

    (begin
    (asserts! (< version u4294967296) (err ERR_SEGWIT_BAD_VERSION))
    (asserts! (< locktime u4294967296) (err ERR_SEGWIT_BAD_LOCKTIME))
    (ok {
        version-hash-prevouts-hash-sequence: (concat
            (uint32-to-buff-le version) (concat
            (segwit-prevouts-hash ins false)
            (segwit-sequence-hash ins SIGHASH_ALL false))),

        hash-outputs-locktime-sighash: (concat
            (segwit-outputs-hash outs u0 SIGHASH_ALL) (concat
            (uint32-to-buff-le locktime)
            SIGHASH_ALL_u32))
    })))


