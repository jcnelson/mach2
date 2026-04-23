;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;           Contract-controlled Bitcoin Transactions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-constant ERR_TRANSFER_OUTCOME_EXISTS u300)
(define-constant ERR_NO_SUCH_TRANSFER_OUTCOME u301)
(define-constant ERR_UTXO_RESERVED u302)
(define-constant ERR_CALLER_MISMATCH u303)
(define-constant ERR_CALLER_NOT_OWNER u304)
(define-constant ERR_UTXO_NOT_RESERVED u305)
(define-constant ERR_UTXO_OUTCOME_MISMATCH u306)
(define-constant ERR_TOO_MANY_OUTCOMES u307)
(define-constant ERR_TX_SENDER_IS_CONTRACT u308)
(define-constant ERR_PSBT_HAS_BAD_WITNESS u309)
(define-constant ERR_WRONG_SIGNATURE_COUNT u310)
(define-constant ERR_NO_SUCH_WTXID u311)
(define-constant ERR_UTXO_RESERVED_OR_EXPIRED u312)
(define-constant ERR_DUPLICATE_TRANSFER_OUTCOME u313)

;; Map contract transfer outcome ID to list of transactions.
;; Each transaction can spend up to 256 UTXOs, as long as:
;; * they're all from the same provider,
;; * they're all spendable by the same user-pubkey
;; * they're all owned by the same principal
;; Each group can have at most 1024 members.
(define-map contract-transfer-outcomes
    { contract: principal, id: uint }
    {
        utxo-ptrs: (list 256 { txid: (buff 32), vout: uint }),
        wtxids: (list 1024 (buff 32)),
        provider: principal,
        owner: principal,
        user-pubkey: (buff 33),
        closed: bool,
        voided: bool,
    })


;; Reservations for potentially-spendable UTXOs.
;; New contract-transfer outcomes can only spend UTXOs in the same outcome,
;; or unclaimed UTXOs.
;; The reservation is voided once the outcome is closed or the UTXO expires.
(define-map contract-reserved-utxos
    { txid: (buff 32), vout: uint }
    {
        outcome-id: { contract: principal, id: uint },
        expires: uint
    })


;; Iterator to search through a list of utxo pointers to find UTXOs.
;; They must all have the same provider and must be unexpired.
(define-private (get-utxos-for-tx-iter
    (vout uint)
    (ctx {
        txid: (buff 32),
        utxo-ptrs: (list 50 { txid: (buff 32), vout: uint }),
        provider: (optional principal),
        result: (response bool uint),
        cur-btc-height: uint,
    }))

    (let (
        (ptr { txid: (get txid ctx), vout: vout })
        (utxo-res (get-utxo ptr (get cur-btc-height ctx)))
    )
    (match utxo-res
        utxo (match (get provider ctx)
            existing-provider
                (if (is-eq existing-provider (get provider utxo))
                    (merge ctx { utxo-ptrs: (unwrap-panic (as-max-len? (append (get utxo-ptrs ctx) ptr) u50)) })
                    (merge ctx { result: (err ERR_MULTIPLE_PROVIDERS) }))
            (merge ctx { provider: (some (get provider utxo)), utxo-ptrs: (list ptr) }))
        err-utxo
            ;; UTXO not found or is expired
            (merge ctx { result: (err ERR_TX_NO_UTXO) }))))


;; Get the list of UTXOs registered by a specific transaction, given its litte-endian wtxid.
;; The transaction must have already been stored to `decoded-transactions` -- specifically,
;; the given `wtxid` must be mapped to its `txid`.
;;
;; Returns (ok (list { txid: (buff 32), vout: uint })) on success
;; Returns (err uint) on failure
(define-private (get-utxos-for-tx (wtxid (buff 32)) (cur-btc-height uint))
    (let (
        (txid (unwrap! (map-get? wtxid-to-txid wtxid) (err ERR_NO_SUCH_TX)))
        (found-utxos (fold get-utxos-for-tx-iter
            (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9
                  u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 
                  u20 u21 u22 u23 u24 u25 u26 u27 u28 u29 
                  u30 u31 u32 u33 u34 u35 u36 u37 u38 u39 
                  u40 u41 u42 u43 u44 u45 u46 u47 u48 u49)
            {
                txid: txid,
                utxo-ptrs: (list ),
                provider: none,
                result: (ok true),
                cur-btc-height: cur-btc-height
            }))
    )
    (try! (get result found-utxos))
    (ok (get utxo-ptrs found-utxos))))


;; Check that a UTXO can be claimed:
;; * it must exist
;; * it must not be expired
;; * it must not be reserved by anyone else (or if it is reserved, it is expired or already reserved by us)
;; * they must all have the same provider
;; * they must all have the same owner
;; * they must all have the same user public key
(define-private (check-utxo-exists-and-is-claimable
    (utxo-ptr { txid: (buff 32), vout: uint })
    (ctx {
        provider: (optional principal),
        owner: principal,
        user-pubkey: (buff 33),
        result: (response bool uint),
        outcome-id: { contract: principal, id: uint },
        cur-btc-height: uint
    }))

    (if (is-err (get result ctx))
        ;; already had a problem
        ctx

        ;; maybe available. check reservation
        (if (match (map-get? contract-reserved-utxos utxo-ptr)
            reservation
                ;; utxo is reserved by an existing outcome.
                ;; we can only spend it if its reservation is voided.
                (match (map-get? contract-transfer-outcomes (get outcome-id reservation))
                    existing-outcome
                        (get voided existing-outcome)

                    ;; should be unreachable, but defensively return an error
                    false)
            true)

            ;; UTXO is unreserved
            (match (get-utxo utxo-ptr (get cur-btc-height ctx))
                ;; UTXO exists and is unexpired. Check provider and owner,
                ;; and set them in ctx.
                utxo
                    (let (
                        (provider-res (match (get provider ctx)
                            provider
                                (if (is-eq (get provider utxo) provider)
                                    ;; UTXO has the same provider as we've seen so far
                                    (ok (get provider utxo))
                                    ;; UTXO has a different provider than those we've seen so far
                                    (err ERR_TX_UTXO_WRONG_PROVIDER))
                            ;; this is the first UTXO queried, so its provider must match the rest
                            (ok (get provider utxo))))

                        (owner-res
                            (if (is-eq (get owner utxo) (get owner ctx))
                                ;; UTXO has the right owner
                                (ok (get owner utxo))
                                ;; UTXO has the wrong owner
                                (err ERR_TX_UTXO_WRONG_OWNER)))

                        (user-pubkey-res
                            (if (is-eq (get user-pubkey utxo) (get user-pubkey ctx))
                                ;; UTXO has the right user signer
                                (ok (get user-pubkey utxo))
                                ;; UTXO has the wrong owner
                                (err ERR_TX_UTXO_WRONG_USER_PUBKEY)))
                    )
                    (if (is-err provider-res)
                        (merge ctx { result: (err (unwrap-err-panic provider-res)) })
                    (if (is-err owner-res)
                        (merge ctx { result: (err (unwrap-err-panic owner-res)) })
                    (if (is-err user-pubkey-res)
                        (merge ctx { result: (err (unwrap-err-panic user-pubkey-res)) })
                    (merge ctx {
                        provider: (some (unwrap-panic provider-res))
                    })))))

                ;; this UTXO does not exist or is expired
                err-utxo
                    (merge ctx { result: (err err-utxo) }))

            ;; UTXO is already taken or spent
            (merge ctx { result: (err ERR_UTXO_RESERVED_OR_EXPIRED) }))))


;; Reserve UTXOs for a particular outcome.
;; Panics if already reserved
;; Panics if the UTXO does not exist or is expired
(define-private (reserve-utxo
    (utxo-ptr { txid: (buff 32), vout: uint })
    (ctx {
        outcome-id: { contract: principal, id: uint },
        cur-btc-height: uint
    }))

    (let (
        (utxo (unwrap-panic (get-utxo utxo-ptr (get cur-btc-height ctx))))
        (inserted (unwrap-panic
            (if (map-insert contract-reserved-utxos
                    utxo-ptr
                    { outcome-id: (get outcome-id ctx), expires: (get expires utxo) })
                (ok true)
                (err ERR_UTXO_RESERVED))))
    )
    ctx))


;; Set up a group of mutually-exclusive contract-transfer transactions.
;; At most one of this group can be co-signed.
(define-private (inner-create-contract-transfer-outcome
    (owner principal)
    (user-pubkey (buff 33))
    (outcome-id { contract: principal, id: uint })
    (utxo-ptrs (list 256 { txid: (buff 32), vout: uint }))
    (cur-btc-height uint))

    (let (
        (has-utxos (try!
            (if (< u0 (len utxo-ptrs))
                (ok true)
                (err ERR_TX_NO_UTXO))))

        (utxo-checks
            (fold check-utxo-exists-and-is-claimable utxo-ptrs {
                provider: none,
                owner: owner,
                user-pubkey: user-pubkey,
                result: (ok true),
                outcome-id: outcome-id,
                cur-btc-height: cur-btc-height }))

        ;; bail early if this failed
        (utxo-checks-passed (try! (get result utxo-checks)))

        ;; should never fail, but be defensive
        (provider (unwrap! (get provider utxo-checks) (err ERR_TX_UTXO_WRONG_PROVIDER)))
    )
    (asserts! (map-insert contract-transfer-outcomes
        outcome-id
        {
            wtxids: (list ),
            utxo-ptrs: utxo-ptrs,
            provider: provider,
            owner: owner,
            user-pubkey: user-pubkey,
            closed: false,
            voided: false,
        })
        (err ERR_TRANSFER_OUTCOME_EXISTS))

    (fold reserve-utxo utxo-ptrs { outcome-id: outcome-id, cur-btc-height: cur-btc-height }) 
    (ok true)))


;; Create a transfer outcome with the given UTXO pointers.
;; The caller (tx-sender, a standard principal) must own the UTXOs.
;; Furthermore, they must all be spendable by the same `user-pubkey`.
;; As a result, this can only be successfully called by a standard principal.
;; The caller should subsequently register PSBTs which encode an outcome, and which spend a subset of the
;; given UTXOs
(define-public (create-contract-transfer-outcome
    (id uint)
    (user-pubkey (buff 33))
    (utxo-ptrs (list 256 { txid: (buff 32), vout: uint })))

    (if (is-standard tx-sender)
        (inner-create-contract-transfer-outcome 
            tx-sender
            user-pubkey
            { contract: contract-caller, id: id }
            utxo-ptrs
            burn-block-height)

        (err ERR_TX_SENDER_IS_CONTRACT)))


;; Get a UTXO reservation if it is unexpired.
;; Otherwise returns none.
(define-private (get-unexpired-utxo-reservation
    (ptr { txid: (buff 32), vout: uint })
    (cur-btc-height uint))

    (match (map-get? contract-reserved-utxos ptr)
        reservation
            (if (>= (get expires reservation) cur-btc-height)
                (some reservation)
                none)
        none))


;; Check that a txin spends a reserved txout
(define-private (check-spends-reserved-utxo-iter
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    })
    (ctx {
        cur-btc-height: uint,
        outcome-id: { contract: principal, id: uint },
        result: (response bool uint)
    }))

    (if (is-err (get result ctx))
        ;; already failed
        ctx

        ;; check this UTXO
        (match (get-unexpired-utxo-reservation
                { txid: (get hash (get outpoint inp)), vout: (get index (get outpoint inp)) }
                (get cur-btc-height ctx))
            reservation
                (if (is-eq (get outcome-id reservation) (get outcome-id ctx))
                    ctx
                    (merge ctx { result: (err ERR_UTXO_RESERVED) }))
            (merge ctx { result: (err ERR_TX_NO_UTXO) }))))


;; Check that a UTXO (augmented with its ptr) is reserved.
;; (i.e. check the output of `get-consumed-utxos` against reservations)
(define-private (check-consumed-utxo-spends-reserved-utxo-iter
    (utxo {
        pointer: { txid: (buff 32), vout: uint },
        owner: principal,
        provider: principal,
        amount: uint,
        expires: uint,
        user-pubkey: (buff 33),
        witness-script: (buff 1376)
    })
    (ctx {
        cur-btc-height: uint,
        outcome-id: { contract: principal, id: uint },
        result: (response bool uint)
    }))

    (match (get result ctx)
        ok-res (match (get-unexpired-utxo-reservation (get pointer utxo) (get cur-btc-height ctx))
            reservation
                (if (is-eq (get outcome-id reservation) (get outcome-id ctx))
                    ;; this UTXO is unexpired and reserved by this outcome-id
                    ctx
                    ;; this UTXO is unexpired, but NOT reserved by this outcome-id
                    (merge ctx { result: (err ERR_UTXO_OUTCOME_MISMATCH) }))
            ;; no reservation
            (merge ctx { result: (err ERR_UTXO_NOT_RESERVED) }))

        err-res
            ;; no-op -- already in error
            ctx))


;; Check and see if the witness of an PSBT input well-formed.
;; * It must have the user signature
;; * It must have the witness script
(define-private (check-txin-has-wellformed-witness
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    })
    (resp (response bool uint)))

    (if (and
        ;; still possibly good
        (is-ok resp)
        ;; witness has three items
        (is-eq (len (get witness inp)) u3)
        ;; first item is empty
        (is-eq (len (unwrap-panic (element-at? (get witness inp) u0))) u0)
        ;; second item is user signature and a sighash byte
        (and
            (>= (len (unwrap-panic (element-at? (get witness inp) u1))) u65)
            (<= (len (unwrap-panic (element-at? (get witness inp) u1))) u72)))

        ;; well-formed!
        resp

        ;; not well-formed!
        (err ERR_PSBT_HAS_BAD_WITNESS)))


;; Add a contract-transfer transaction to an existing outcome group.
;; This is a partially-signed Bitcoin transaction, signed by the user.
;; The cosigner will sign later.
;; Returns (ok wtxid-index) on success, which can be fed into `complete-transfer-otucome` 
(define-private (inner-add-contract-transfer-outcome
    (owner principal)
    (outcome-id { contract: principal, id: uint })
    (partially-signed-wtx (buff 4096))
    (cur-btc-height uint))

    (let (
        ;; outcome must be defined
        (transfer-outcome (unwrap! (map-get? contract-transfer-outcomes outcome-id) (err ERR_NO_SUCH_TRANSFER_OUTCOME)))

        ;; only the owner can send this
        (is-owner (try! (if (is-eq (get owner transfer-outcome) owner)
            (ok true)
            (err ERR_CALLER_NOT_OWNER)))) 

        ;; NOTE: This is the little-endian PSBT wtxid
        (partially-signed-wtxid (sha256 (sha256 partially-signed-wtx)))
        
        ;; this WTXID is not already present in this listing
        (is-novel-wtxid (try! (if (is-none (index-of? (get wtxids transfer-outcome) partially-signed-wtxid))
            (ok true)
            (err ERR_DUPLICATE_TRANSFER_OUTCOME))))

        ;; we must have space for the outcome
        (new-wtxids (unwrap! (as-max-len? (append (get wtxids transfer-outcome) partially-signed-wtxid) u1024)
            (err ERR_TOO_MANY_OUTCOMES)))

        ;; must not be stored yet
        (is-new-transaction (try! (if (has-transaction? partially-signed-wtxid)
            (err ERR_TX_ALREADY_EXISTS)
            (ok true))))

        ;; decode the PSBT
        (decoded-tx (try! (decode-bitcoin-wtx partially-signed-wtx)))

        ;; must spend unexpired UTXOs reserved by this id
        (spends-reserved-check (try! (get result
            (fold check-spends-reserved-utxo-iter (get ins decoded-tx) {
                cur-btc-height: cur-btc-height,
                outcome-id: outcome-id,
                result: (ok true)
            }))))

        ;; each witness vector in each input must have exactly three items:
        ;; the empty element, the user signature (65 bytes), and the witness script.
        (inputs-well-formed (try!
            (fold check-txin-has-wellformed-witness (get ins decoded-tx) (ok true))))

        ;; check user signatures, and load up the list of consumed UTXOs
        (consumed-utxos (try! (get-consumed-utxos
            (get ins decoded-tx)
            (get outs decoded-tx)
            (get signature-hash decoded-tx)
            (get owner transfer-outcome)
            (get user-pubkey transfer-outcome)
            (list )
            (get provider transfer-outcome)
            cur-btc-height)))

        ;; compute total UTXO spend
        (total-consumed (fold sum-utxo-spend-iter consumed-utxos u0))

        ;; defensive check:
        ;; check that each *consumed* UTXO was reserved for this outcome and is unexpired
        (all-reserved-and-unexpired (try! (get result
            (fold check-consumed-utxo-spends-reserved-utxo-iter
                consumed-utxos
                { cur-btc-height: cur-btc-height, outcome-id: outcome-id, result: (ok true) }))))
    )

    ;; transaction spends at most total-consumed
    (asserts! (>= total-consumed (fold get-txout-spend-iter (get outs decoded-tx) u0))
        (err ERR_TX_SPENDS_TOO_MUCH))
   
    ;; store parsed tx
    (try! (store-parsed-wtx partially-signed-wtxid decoded-tx))

    ;; store updated outcome
    (map-set contract-transfer-outcomes outcome-id (merge transfer-outcome { wtxids: new-wtxids })) 
    (ok (- (len new-wtxids) u1))))


;; Add a contract-transfer outcome to an existing outcome group.
;; This is a partially-signed Bitcoin transaction, signed by the user.
;; The cosigner will sign later.
;; The UTXOs' owner must be `tx-sender`, and the `contract-caller` must be the contract the owner is using.
(define-public (add-contract-transfer-outcome
    (id uint)
    (partially-signed-wtx (buff 4096)))

    (inner-add-contract-transfer-outcome tx-sender { contract: contract-caller, id: id } partially-signed-wtx burn-block-height))


;; Add a list of cosigner signatures to the witness stack for an input.
;; The witness for each input currently has just the user signature and witness script.
;; Panics if cosiner-sigs and ins aren't the same length.
;; Panics if the witness is malformed (e.g. doesn't have two entries)
(define-private (add-cosigner-sigs-to-txin
    (cosigner-sig (list 10 (buff 73)))
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376))
    }))

    (let (
        (witness (get witness inp))

        ;; current witness stack must have two items: user signature and witness script
        (witness-user-sig (unwrap-panic (element-at? witness (- (len witness) u2))))
        (witness-script (unwrap-panic (element-at? witness (- (len witness) u1))))

        ;; cosigner signatures go at the top of the witness stack.
        ;; The first witness stack item is an empty item, due to how OP_CHECKMULTISIG works.
        (witness-stack (concat
            ;; OP_0 for multisig
            (list 0x) (concat
            cosigner-sig
            (list witness-user-sig witness-script))))

        (new-inp (merge inp { witness: witness-stack }))
    )
    new-inp))


;; Complete a contract transfer.
;; `wtxid-index` refers to the wtxid in the idenified transfer outcome's `wtxids` list.
;; The corresponding `wtxid` corresponds to a partially-signed decoded tx.
;; This will add the cosigner signatures, validate each input's now-complete signatures,
;; and remove the UTXOs, update balances, and clear out the outcome.
;; The cosigner (or anyone) calls this to supply its signatures.
(define-private (inner-complete-transfer
    (cosigner-addr principal)
    (outcome-id { contract: principal, id: uint }) 
    (wtxid-index uint)
    (cosigner-sigs (list 16 (list 10 (buff 73))))
    (btc-block-height uint))

    (let (
        ;; load up the outcome (it must exist and must still be open)
        (outcome-rec (unwrap! (map-get? contract-transfer-outcomes outcome-id) (err ERR_NO_SUCH_TRANSFER_OUTCOME)))
        (outcome-is-open (try! (if (get closed outcome-rec)
            (err ERR_NO_SUCH_TRANSFER_OUTCOME)
            (ok true))))

        (wtxid (unwrap! (element-at? (get wtxids outcome-rec) wtxid-index) (err ERR_NO_SUCH_WTXID)))

        ;; load up the cosigner (it must exist)
        (cosigner-rec (unwrap! (map-get? cosigner-info cosigner-addr) (err ERR_NO_SUCH_COSIGNER)))
    
        ;; load up the partially-signed transaction
        (decoded-tx (unwrap! (map-get? decoded-transactions wtxid) (err ERR_NO_BTC_TRANSACTION)))

        ;; lengths must match
        (lengths-match (try! (if (is-eq (len (get ins decoded-tx)) (len cosigner-sigs))
            (ok true)
            (err ERR_WRONG_SIGNATURE_COUNT))))

        (fully-signed-tx (merge decoded-tx {
            ins: (map add-cosigner-sigs-to-txin cosigner-sigs (get ins decoded-tx))
        }))
    )

    ;; validate all signatures, and if successful, remove all UTXOs and debit all balances 
    (try! (process-contract-transfer
        fully-signed-tx
        cosigner-rec
        (get owner outcome-rec)
        (get user-pubkey outcome-rec)
        (get provider outcome-rec)
        btc-block-height))

    ;; close out the outcome
    (map-set contract-transfer-outcomes outcome-id (merge outcome-rec { closed: true }))
    (ok true)))


;; Called by the cosigner (or anyone) to complete a transfer.
;; `wtxid-index` refers to the wtxid in the idenified transfer outcome's `wtxids` list.
(define-public (complete-transfer
    (cosigner-addr principal)
    (outcome-id { contract: principal, id: uint }) 
    (wtxid-index uint)
    (cosigner-sigs (list 16 (list 10 (buff 73)))))

    (inner-complete-transfer
        cosigner-addr
        outcome-id
        wtxid-index
        cosigner-sigs
        burn-block-height))
