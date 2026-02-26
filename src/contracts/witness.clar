;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                  Pegin witness script module
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-constant ERR_PEGIN_WITNESS_BAD_LOCKTIME u200)
(define-constant ERR_PEGIN_WITNESS_BAD_PRINCIPAL u201)
(define-constant ERR_PEGIN_WITNESS_INTEGER_RANGE u202)

;; Iterator to build up a multisig script
(define-private (make-multisig-script-iter
    (key (buff 33))
    (script (buff 1376)))

    (unwrap-panic (as-max-len? (concat script (concat 0x21 key)) u1376)))

;; Convert a value between 0 and 16 (inclusive) to its opcode
(define-read-only (uint-to-op (val uint))
    (if (is-eq val u0)
        (some 0x00)
    (if (> u16 val)
        none
        (some (uint8-to-buff (+ u50 val))))))

;; Create a multisig script out of keys for a cosigner.
;; It must have at least 2/3 threshold.
(define-read-only (make-cosigner-multisig-script (keys (list 11 (buff 33))))
    (let (
        (threshold (if (< (len keys) u4)
            (len keys)
            (+ u1 (/ (* u2 (len keys)) u3))))

        ;; SAFETY: the list can be no more than 11, so this is always (some ..)
        (threshold-op (unwrap-panic (uint-to-op threshold)))
        (total-op (unwrap-panic (uint-to-op (len keys))))
    )
    (concat (fold make-multisig-script-iter keys threshold-op) (concat total-op OP_CHECKMULTISIG))))

;; Convert a u32 to a big-endian (buff 4)
;; Upper bits are dropped.
(define-read-only (uint32-to-buff-be (val uint))
    (let (
        (val-be (bit-or
            (bit-shift-left (bit-and val u255) u24)
            (bit-shift-left (bit-and val u65280) u8)
            (bit-shift-right (bit-and val u16711680) u8)
            (bit-shift-right (bit-and val u4278190080) u24)))
    )
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val-be)) u13 u17)) u4))))

;; Convert a u24 to a big-endian (buff 3).
;; Upper bits are dropped
(define-read-only (uint24-to-buff-be (val uint))
    (let (
       (val-be (bit-and u16777215 (bit-or
            (bit-shift-left (bit-and val u255) u16)
            (bit-shift-right (bit-and val u16711680) u16))))
    )
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val-be)) u14 u17)) u3))))

;; Convert a u16 to a big-endian (buff 2).
;; Upper bits are dropped
(define-read-only (uint16-to-buff-be (val uint))
    (let (
       (val-be (bit-and u65535 (bit-or
            (bit-shift-left (bit-and val u255) u8)
            (bit-shift-right (bit-and val u65280) u8))))
    )
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val-be)) u15 u17)) u2))))

;; Convert an u8 into a (buff 1)
;; Upper bits are dropped
(define-read-only (uint8-to-buff (val uint))
    (unwrap-panic (as-max-len? (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? val)) u16 u17)) u1)))

;; Convert a uint to a CScriptNum -- an OP_PUSHDATA followed by its big-endian byte representation.
;; Only works for up to 4-byte numbers.
(define-read-only (make-script-num (val uint))
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
(define-read-only (op-push-slice (bytes (buff 1376)))
    (if (< (len bytes) u75)
        (concat (uint8-to-buff (len bytes)) bytes)
    (if (< (len bytes) u255)
        (concat OP_PUSHDATA1 (concat (uint8-to-buff (len bytes)) bytes))
    (if (< (len bytes) u65536)
        (concat OP_PUSHDATA2 (concat (uint16-to-buff (len bytes))) bytes)
        (concat OP_PUSHDATA4 (concat (uint32-to-buff (len bytes))) bytes)))))

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
(define-read-only (make-pegin-witness-script
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
        (principal-bytes (try! (match (principal-destruct? (get recipient-principal witness))
            parts (ok (concat (get version parts) (get hashbytes parts)))
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
            (unwrap! (make-script-num (- (get locktime witness-data) (get safety-margin witness-data))) (err ERR_INEGER_RANGE))
            OP_ENDIF))))

    )
    (ok (unwrap-panic (as-max-len? (concat recipient-to-cosigner cosigner-to-end) u1376))))))
