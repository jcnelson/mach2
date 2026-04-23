;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                  Pegin witness script module
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-constant ERR_PEGIN_WITNESS_BAD_LOCKTIME u200)
(define-constant ERR_PEGIN_WITNESS_BAD_PRINCIPAL u201)
(define-constant ERR_PEGIN_WITNESS_INTEGER_RANGE u202)

;; BTC opcodes
(define-constant OP_DROP 0x75)
(define-constant OP_PUSHDATA1 0x4c)
(define-constant OP_PUSHDATA2 0x4d)
(define-constant OP_PUSHDATA4 0x4e)
(define-constant OP_CHECKSIGVERIFY 0xad)
(define-constant OP_NOTIF 0x64)
(define-constant OP_0NOTEQUAL 0x92)
(define-constant OP_0NOTEQUAL_OP_NOTIF (concat OP_0NOTEQUAL OP_NOTIF))
(define-constant OP_CLTV 0xb1)
(define-constant OP_CLTV_OP_DROP (concat OP_CLTV OP_DROP))
(define-constant OP_ELSE 0x67)
(define-constant OP_TRUE 0x51)
(define-constant OP_ENDIF 0x68)
(define-constant OP_CLTV_OP_ELSE_OP_TRUE_OP_ENDIF (concat
    OP_CLTV (concat
    OP_ELSE (concat
    OP_TRUE
    OP_ENDIF))))
(define-constant OP_CHECKMULTISIG 0xae)

;; Iterator to build up a multisig script
(define-private (make-multisig-script-iter
    (key (buff 33))
    (script (buff 1376)))

    (unwrap-panic (as-max-len? (concat script (concat 0x21 key)) u1376)))


;; Convert a value between 0 and 16 (inclusive) to its opcode
(define-private (uint-to-op (val uint))
    (if (is-eq val u0)
        (some 0x00)
    (if (<= u16 val)
        none
        (some (uint8-to-buff (+ u80 val))))))


;; Create a multisig script out of keys for a cosigner.
;; It must have at least 2/3 threshold.
(define-private (make-cosigner-multisig-script (keys (list 10 (buff 33))))
    (let (
        (threshold (if (< (len keys) u4)
            (len keys)
            (+ u1 (/ (* u2 (len keys)) u3))))

        ;; SAFETY: the list can be no more than 10, so this is always (some ..)
        (threshold-op (unwrap-panic (uint-to-op threshold)))
        (total-op (unwrap-panic (uint-to-op (len keys))))
    )
    (unwrap-panic
        (as-max-len? (concat
            (fold make-multisig-script-iter keys threshold-op) (concat
            total-op
            OP_CHECKMULTISIG))
        u1376))))


;; Turn the lower 4 bytes of an integer into a (buff 4)
(define-private (uint32-to-buff-be (val uint))
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val)) u13 u17)) u4)))


;; Convert a u24 to a big-endian (buff 3).
;; Upper bits are dropped
(define-private (uint24-to-buff-be (val uint))
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val)) u14 u17)) u3)))


;; Convert a u16 to a big-endian (buff 2).
;; Upper bits are dropped
(define-private (uint16-to-buff-be (val uint))
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val)) u15 u17)) u2)))


;; Convert an u8 into a (buff 1)
;; Upper bits are dropped
(define-private (uint8-to-buff (val uint))
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val)) u16 u17)) u1)))


;; Convert a uint to a CScriptNum -- an OP_PUSHDATA followed by its big-endian byte representation.
;; Only works for up to 4-byte numbers.
(define-private (make-script-num (val uint))
    (if (<= val u255)
        (some (concat 0x01 (uint8-to-buff val)))
    (if (<= val u65535)
        (some (concat 0x02 (uint16-to-buff-be val)))
    (if (<= val u16777215)
        (some (concat 0x03 (uint24-to-buff-be val)))
    (if (<= val u4294967295)
        (some (concat 0x04 (uint32-to-buff-be val)))
    none)))))


;; Compute a PUSHDATA for a slice
(define-private (op-push-slice (bytes (buff 1376)))
    (if (< (len bytes) u75)
        (concat (uint8-to-buff (len bytes)) bytes)
    (if (< (len bytes) u255)
        (concat OP_PUSHDATA1 (concat (uint8-to-buff (len bytes)) bytes))
    (if (< (len bytes) u65536)
        (concat OP_PUSHDATA2 (concat (uint16-to-buff-be (len bytes)) bytes))
        (concat OP_PUSHDATA4 (concat (uint32-to-buff-be (len bytes)) bytes))))))


;; Compute the pegin witness script from the decoded pegin witness script
;; Compose witness script as:
;;
;; 1.  0x05 <recipient-principal> OP_DROP
;; 2.  <locktime - safety-margin> OP_CLTV OP_DROP
;; 3.  <user-pubkey> OP_CHECKSIGVERIFY
;; 4.  <cosigner-dag-spend-script> OP_0NOTEQUAL
;; 5.  OP_NOTIF
;; 6.       <locktime> OP_CLTV
;; 7.  OP_ENDIF
;; 
(define-private (make-pegin-witness-script
    (cosigner-dag-spend-script (buff 1376))
    (witness-data {
        recipient-principal: principal,
        user-pubkey: (buff 33),
        locktime: uint,
        safety-margin: uint
    }))

    (begin
    (asserts! (>= (get locktime witness-data) (get safety-margin witness-data))
        (err ERR_PEGIN_WITNESS_BAD_LOCKTIME))

    (asserts! (is-standard (get recipient-principal witness-data))
        (err ERR_PEGIN_WITNESS_BAD_PRINCIPAL))
    
    (let (
        (principal-bytes (try! (match (principal-destruct? (get recipient-principal witness-data))
            parts (ok (concat (get version parts) (get hash-bytes parts)))
            err (err ERR_PEGIN_WITNESS_BAD_PRINCIPAL))))

        (recipient-to-cosigner (concat
            (op-push-slice (concat 0x05 principal-bytes)) (concat
            OP_DROP (concat
            (unwrap! (make-script-num (- (get locktime witness-data) (get safety-margin witness-data))) (err ERR_PEGIN_WITNESS_INTEGER_RANGE)) (concat
            OP_CLTV_OP_DROP (concat
            (op-push-slice (get user-pubkey witness-data))
            OP_CHECKSIGVERIFY))))))
            
        (cosigner-to-end (concat
            cosigner-dag-spend-script (concat
            OP_0NOTEQUAL_OP_NOTIF (concat
            (unwrap! (make-script-num (get locktime witness-data)) (err ERR_PEGIN_WITNESS_INTEGER_RANGE))
            OP_CLTV_OP_ELSE_OP_TRUE_OP_ENDIF))))

    )
    (ok (unwrap-panic (as-max-len? (concat recipient-to-cosigner cosigner-to-end) u1376))))))


