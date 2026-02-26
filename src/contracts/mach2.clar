;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                      Main module
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-constant ERR_NO_PROVIDER u1)
(define-constant ERR_NOT_TOPLEVEL u2)
(define-constant ERR_BTC_EXPIRED u3)
(define-constant ERR_TX_NO_UTXO u4)
(define-constant ERR_TX_INVALID_PEGIN_P2WSH u5)
(define-constant ERR_TX_NO_WITNESS_DATA u6)
(define-constant ERR_DUPLICATE_UTXO u8) 
(define-constant ERR_NO_PEGIN_UTXO u9)
(define-constant ERR_WITNESS_BAD_LOCKTIME u10)
(define-constant ERR_TOO_MANY_PROVIDERS u11)
(define-constant ERR_NO_BTC_TRANSACTION u12)
(define-constant ERR_TX_ALREADY_EXISTS u13)
(define-constant ERR_TX_DECODE_ERROR u15)
(define-constant ERR_TX_UTXO_WITNESS_MISMATCH u16)
(define-constant ERR_TX_NO_TXIN u17)
(define-cosntant ERR_TX_DUPLICATE_SIG u18)
(define-constant ERR_TX_MALFORMED_WITNESS u19)
(define-constant ERR_TX_INVALID_COSIGNER_SIGNATURE u20)
(define-constant ERR_TX_INVALID_USER_SIGNATURE u21)
(define-constant ERR_TX_UTXO_CHECK_FAILED u22)
(define-constant ERR_TX_UTXO_WRONG_PROVIDER u23)
(define-constant ERR_TX_UTXO_WRONG_USER u24)
(define-constant ERR_PROVIDER_EXISTS u25)
(define-constant ERR_TX_SPENDS_TOO_MUCH u26)
(define-constant ERR_NO_SUCH_COSIGNER u27)
(define-constant ERR_COSIGNER_KEY_ALREADY_USED u28)
(define-constant ERR_INSUFFICIENT_BALANCE u29)
(define-constant ERR_COSIGNER_EXISTS u30)

(define-constant SINGLESIG_ADDRESS_VERSION_BYTE (if is-in-mainnet 0x16 0x1a))
(define-constant MULTISIG_ADDRESS_VERSION_BYTE (if is-in-mainnet 0x14 0x15))

;; BTC opcodes
(define-constant (OP_DROP 0x75))
(define-constant (OP_PUSHDATA1 0x4c))
(define-constant (OP_PUSHDATA2 0x4d))
(define-constant (OP_PUSHDATA4 0x4e))
(define-constant (OP_CHECKSIGVERIFY 0xad))
(define-constant (OP_IF 0x63))
(define-constant (OP_NOTIF 0x64))
(define-constant (OP_0NOTEQUAL 0x92))
(define-constant (OP_0NOTEQUAL_OP_NOTIF (concat OP_0NOTEQUAL OP_NOTIF)))
(define-constant (OP_CLTV 0xb1))
(define-constant (OP_CLTV_OP_DROP (concat OP_CLTV OP_DROP)))
(define-constant (OP_ENDIF 0x68))
(define-constant (OP_8 0x58))
(define-constant (OP_11 0x5b))
(define-constant (OP_CHECKMULTISIG 0xae))
(define-constant (OP_11_OP_CHECKMULTISIG (concat OP_11 OP_CHECKMULTISIG)))

;; type of redemption DAG tx
(define-constant DAG_TX_PEGIN u1)
(define-constant DAG_TX_CONTRACT_TRANSFER u2)

;; Registry of cosigners.
;; Maps the cosigner's Stacks principal to its list of signing keys
;; and derived spend script.  The Stacks principal is unrelated to the
;; keys or signing script.
(define-map cosigner-info
    principal
    {
        dag-spend-script: (buff 1376),
        dag-keys: (list 11 (buff 33)),
    })

;; All cosigner keys in use (since they cannot be reused across registrations).
(define-map cosigner-keys
    (buff 33)
    principal)

;; placeholder
(map-insert cosigner-info 
    'SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45
    {
        dag-spend-script: 0x,
        dag-keys: (list )
    })

;; Get tx-sender if it is a standard principal and is the contract caller.
;; Return (err ERR_NOT_TOPLEVEL) if the caller isn't top-level
(define-read-only (get-toplevel-addr)
    (try!
        (if (and (is-standard tx-sender) (is-eq contract-caller tx-sender))
            (ok tx-sender)
            (err ERR_NOT_TOPLEVEL))))

;; Iterator to determine if a cosigner key is used
(define-private (check-cosigner-keys-used
    (key (buff 33))
    (result bool))

    (if result
        (and result (is-none (map-get? cosigner-keys key)))
        result))

;; Iterator to mark a cosigner key as used
(define-private (set-cosigner-keys-used
    (key (buff 33))
    (cosigner-addr principal))

    (map-set cosigner-keys key cosigner-addr)) 

;; Top-level function to register a cosigner.
;; All keys in `dag-keys` must be heretofor unused.
;; This can only be called via a top-level contract-call.
;; The caller will be the cosigner principal.
(define-public (register-cosigner (dag-keys (list 11 (buff 33))))
    (let (
        (cosigner-addr (try! (get-toplevel-addr)))
        (dag-keys-unused (try! (fold check-cosigner-keys-used dag-keys true) (err ERR_COSIGNER_KEY_ALREADY_USED)))
        (cosigner-dag-script (make-cosigner-multisig-script dag-keys))
    )

    (asserts! (map-insert cosigner-info
        cosigner-addr
        {
            dag-spend-script: cosigner-dag-script,
            dag-keys: dag-keys,
        })
        (err ERR_COSIGNER_EXISTS))

    (fold set-cosigner-keys-used dag-keys tx-sender)
    (ok true)))

;; All decoded transactions.
;; * for peg-ins, these are transactions that have been confirmed to have been mined
;; * for contract transfers, these are decoded off-chain transactions which correspond to entries in the DAG.
;; Keyed by the little-endian wtxid (the reverse of what you see on an explorer)
(define-map decoded-transactions
    (buff 32)
    {
        version: uint,
        segwit-marker: uint,
        segwit-version: uint,
        txid: (buff 32),
        ins: (list 50 {
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
        ;; pre-computed signature hash data, so we can check
        ;; signatures on off-chain transactions.
        signature-hash: {
            ;; version: 4-byte little-endian
            ;; hash-prevouts: 32-byte hash of previous outpoints
            ;; hash-sequence: 32-byte hash of input sequences
            version-hash-prevouts-hash-sequence: (buff 68),
            ;; hash-outputs: 32-byte hash of outputs
            ;; locktime: 4-byte little-endian 
            ;; sighash: 4-byte little-endian
            hash-outputs-locktime-sighash: (buff 44)
        }
    })

;; All DAG UTXOs, keyed by outpoint.
;; Deleted when spent.
(define-map utxos
    { txid: (buff 32), vout: uint }
    {
        provider: principal,
        amount: uint,
        expires: uint,
        user-pubkey: (buff 33),
        witness-script: (buff 1376), 
    })

;; All processed peg-ins and transfers.
;; Indexed by other maps.
(define-map redemption-dag
    ;; Little-endian wtxid, the reverse of what you see on explorers.
    ;; For contract transfers, this is the wtxid of the user-signed but *not*
    ;; cosigner-signed transaction.
    (buff 32)
    {
        ;; type of transaction -- peg-in or contract-transfer
        tx-type: uint,
        ;; BTC provider of this transaction's BTC.
        provider: principal
    })

;; Time-series index of DAG operations (peg-ins and transfers).
;; Used by cosigner replicas to audit this contract's materialized views.
(define-map redemption-log
    ;; the ith peg-in or transfer
    uint
    ;; pointer into redemption-dag for the corresponding wtx.
    ;; for partially-signed transfers, this is the little-endian wtxid of the user-signed PSBT (i.e. missing cosigner signatures)
    (buff 32)
)

(define-data-var redemption-log-length uint u0)

;; Materialized view of scBTC provider state
(define-map btc-providers
    ;; Stacks principal identified in the witness script of the peg-in (i.e. from its marker payload).
    ;; Providers are never deleted; subsequent peg-ins must use a new key.
    principal
    ;; info
    {
        ;; pointer to the peg-in transaction info, stored in redemption-dag
        wtxid: (buff 32),
        ;; when this provider's BTC expires
        expires: uint
    })  
 
;; Materialized view of scBTC balances
(define-map balances
    ;; Stacks principal who owns the scBTC
    principal
    ;; balances from each provider (indexes btc-providers)
    (list 1024 { provider: principal, amount: uint, expires: uint }))

;; Store a partially-signed contract transfer.
;; One transfer per provider.
;; The provider must already be defined.
;; NOTE: the `wtxid` will not commit to the cosigner signatures; these are provided separately
(define-private (store-contract-transfer-psbt
    (wtxid (buff 32))
    (provider principal)
    (btc-block-height uint))

    (let (
        (provider-info (unwrap! (map-get? btc-providers provider) (err ERR_NO_PROVIDER)))
        (log-len (var-get redemption-log-length))
        (new-log-len (+ u1 log-len))
    )
    (map-set redemption-dag wtxid {
        tx-type: DAG_TX_CONTRACT_TRANSFER,
        provider: provider
    })
    (map-set redemption-log new-log-len wtxid)
    (var-set redemption-log-length new-log-len)
    (ok true)))

(define-read-only (balance-adder
    (balance-item { provider: principal, amount: uint, expires: uint })
    (ctx { btc-block-height: uint, sum: uint }))

    (if (< (get expires balance-item) (get btc-block-height ctx))
        (merge ctx { sum: (+ (get amount balance-item) (get sum ctx)) })
        ctx))

;; Get the balance of a user at a particular Bitcoin block height
(define-read-only (get-balance (user principal) (btc-block-height uint))
    (let (
        (user-balances (default-to (list ) (map-get? balances user)))
    )
    (get sum
        (fold balance-adder
            user-balances
            { btc-block-height: btc-block-height, sum: u0 }))))

;; Look up a BTC provider's information at a given bitcoin block height
;; Returns (err ERR_BTC_EXPIRED) if the provider record exists, but it expired before the given height.
;; Returns (err ERR_NO_PROVIDER) if the provider never existed.
(define-read-only (get-provider-info (provider principal) (btc-block-height uint))
    ;; provider must exist and must be unexpired
    (try! (match (map-get? btc-providers provider)
        ;; have provider
        provider-info
            (if (< btc-block-height (get expires provider-info))
                (ok provider-info)
                (err ERR_BTC_EXPIRED))
        ;; do not have provider
        (err ERR_NO_PROVIDER))))

;; Iterator to search a list of keys to find if it produced the given signature over the given message.
;; If found, update `ctx` to have `found = true`.
;; If a signature is invalid, update `ctx` to have `valid = false`.
;; As long as `ctx`'s `valid` is true, then `i` will increment on each call in the iteration (so `i` points to the found key).
(define-private (check-pubkey-on-sig-iter
    (pubkey (buff 33))
    (ctx { sig: (buff 65), signature-hash: (buff 32), found: bool, valid: bool, i: uint }))

    (if (or (not (get valid ctx)) (get found ctx))
        ctx
        (match (secp256k1-recover? (get signature-hash ctx) (get sig ctx))
            ok-pubkey
            (let (
                (found (is-eq ok-pubkey pubkey))
            )
            (if found
                (merge ctx { found: found })
                (merge ctx { i: (+ u1 (get i ctx)) })))
            err-code (merge ctx { valid: false }))))

;; Check a signature against a script hash, as part of verifying that a given key signed a given transaction segwit signature hash.
(define-private (check-sig-iter
    (witness-sig (buff 1376))
    (ctx { keys: (list 11 (buff 33)), used: (list 11 bool), signature-hash: (buff 32), valid: bool }))
    
    (if (not (get valid ctx))
        ;; already failed
        ctx

        ;; maybe still valid
        (let (
            (result (fold check-pubkey-on-sig-iter
                (get keys ctx)
                { sig: witness-sig, siganture-hash: (get signature-hash ctx), found: false, valid: true, i: u0 }))
        )
        (if (or (not (get found result)) (not (get valid result)))
            ;; failed
            (merge ctx { valid: false })
            ;; succeeded, as long as it's not already used
            (begin
                (asserts! (not (unwrap-panic (element-at? (get i result) (get used ctx))))
                    (err ERR_TX_DUPLICATE_SIG))

                (merge ctx { used: (unwrap-panic (replace-at? (get used ctx) (get i result) true)) }))))))

;; Authenticate a particular txin
;; * The input has to have a corresponding UTXO in the `utxos` map
;; * The input's witness script must exist and must match the UTXO's computed witness script
;; * The cosigner must have signed it with its DAG transfer keys
;; * The given user key must have signed each input
;; * The UTXO must have the given provider 
(define-read-only (inner-check-consumed-utxo
    (txdata {
        ins: (list 50 {
            outpoint: { hash: (buff 32), index: uint },
            scriptSig: (buff 1376),
            sequence: uint,
            witness: (list 13 (buff 1376)),
        }),
        outs: (list 50 {
            value: uint,
            scriptPubKey: (buff 1376),
        }),
        signature-hash: {
            version-hash-prevouts-hash-sequence: (buff 68),
            hash-outputs-locktime-sighash: (buff 44)
        }
    })
    (input-index uint)
    (user-pubkey (buff 33))
    (cosigner-keys (list 11 (buff 33)))
    (provider principal)
    (cur-btc-height uint))
    
    (let (
        (in (unwrap! (element-at? (get ins txdata) input-index)
            (err ERR_TX_NO_TXIN)))

        (witness (try! (if >= (len (get witness in)) u4)
            (if (is-eq (unwrap-panic (element-at? (get witness in) u0)) 0x00)
                (ok (get witness in))
                (err ERR_TX_MALFORMED_WITNESS))
            (err ERR_TX_NO_WITNESS_DATA)))

        (outpoint (get outpoint in))
        (utxo-pointer { txid: (get hash outpoint), vout: (get index outpoint) })
        (utxo (unwrap! (map-get? utxos utxo-pointer)
            (err ERR_TX_NO_UTXO)))

        ;; bail early if the UTXO is expired
        (is-expired (try!
            (if (< (get expired utxo) cur-btc-height)
                (ok true)
                (err ERR_BTC_EXPIRED))))

        ;; bail early if the provider is wrong
        (provider-valid (try!
            (if (is-eq (get provider utxo) provider)
                (ok true)
                (err ERR_TX_UTXO_WRONG_PROVIDER))))

        ;; bail early if the user public key is wrong
        (user-pubkey-valid (try!
            (if (is-eq (get user-pubkey utxo) user-pubkey)
                (ok true)
                (err ERR_TX_UTXO_WRONG_USER))))

        ;; final witness item (witness script)
        (witness-script (unwrap-panic (element-at (- u1 (len witness)) witness)))

        ;; bail early if the witness script is wrong
        (witness-script-valid (try!
            (if (is-eq (get witness-script utxo) witness-script)
                (ok true)
                (err ERR_TX_UTXO_WITNESS_MISMATCH))))

        ;; witness stack:
        ;; 0.   0x00
        ;; 1-N. cosigner witness signatures
        ;; N.   user signature
        (cosigner-witness-sigs (unwrap-panic (slice? witness u1 (- u2 (len witness)))))
        (user-witness-sig (unwrap-panic (element-at? witness (- u1 (len witness)))))
        (spent-p2wsh (concat 0x00 (sha256 (get witnes-script utxo))))
        (spent-amount (get amount utxo))

        ;; signature hash for this input
        (segwit-sighash (segwit-signature-hash
            (get ins txdata)
            (get outs txdata)
            (get signature-hash txdata)
            input-index
            spent-p2wsh
            spent-amount))

        ;; cosigner signature check
        (cosigner-dag-sig-check
            (fold check-sig-iter cosigner-witness-sigs {
                keys: cosigner-keys,
                used: (list false false false false false false false false false false false),
                signature-hash: segwit-sighash,
                valid: true
            }))

        ;; bail early if the cosigner signature is invalid
        (cosigner-sig-valid (try!
            (if (get valid cosigner-dag-check)
                (ok true)
                (err ERR_TX_INVALID_COSIGNER_SIGNATURE))))

        ;; user signature check
        (user-sig-check (check-sig-iter (list user-witness-sig) {
            keys: (list user-pubkey),
            used: (list false),
            signature-hash: segwit-sighash,
            valid: true
        }))
    )

    ;; the user signature is valid
    (asserts! (get valid user-dag-sig-check)
        (err ERR_TX_INVALID_USER_SIGNATURE))

    (ok (some (merge utxo { pointer: utxo-pointer })))))

;; Check that a given input in txdata has been signed by the cosigner DAG keys and the user key
;; obtained from the input's corresponding UTXO.  Check also that the input is well-formed -- i.e.
;; its witness script matches the UTXO's scriptPubKey, and its witness stack is well-formed, etc.
(define-read-only (check-consumed-utxo
    (input-index uint)
    (txdata {
        ins: (list 50 {
            outpoint: { hash: (buff 32), index: uint },
            scriptSig: (buff 1376),
            sequence: uint,
            witness: (list 13 (buff 1376)),
        }),
        outs: (list 50 {
            value: uint,
            scriptPubKey: (buff 1376),
        }),
        signature-hash: {
            version-hash-prevouts-hash-sequence: (buff 68),
            hash-outputs-locktime-sighash: (buff 44)
        },
        utxos: (list 50 (optional {
            pointer: { txid: (buff 32), vout: uint },
            recipient: principal,
            provider: principal,
            amount: uint,
            expires: uint,
            user-pubkey: (buff 33),
            witness-script: (buff 1376), 
        })),
        user-pubkey: (buff 33),
        cosigner-keys: (list 11 (buff 33)),
        provider: principal,
        valid: bool,
        cur-btc-height: uint
    }))

    (if (get valid txdata)
        (match (inner-check-consumed-utxo txdata input-index user-pubkey cosigner-keys provider (get cur-btc-height txdata))
            ok-utxo-opt (merge txdata { utxos: (unwrap-panic (as-max-len? (append (get utxos txdata) ok-utxo-opt) u50)) })
            err-val
                (if (is-eq err-val ERR_TX_NO_TXIN)
                    ;; input-index has exceeded txin len, which is okay and expected
                    (merge txdata { utxos: (unwrap-panic (as-max-len? (append (get utxos txdata) none) u50)) })
                    (merge txdata { valid: false })))
        txdata))

;; Find and authenticate the senders of a given transfer transaction
;; * Each input has to have a UTXO
;; * The input must consume the UTXO
;; * The given signatures must match the transaction
;; * Each UTXO must match the given expected provider
(define-read-only (check-consumed-utxos
    (ins (list 50 {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint,
        witness: (list 13 (buff 1376)),
    }))
    (outs (list 50 {
        value: uint,
        scriptPubKey: (buff 1376),
    }))
    (signature-hash {
        version-hash-prevouts-hash-sequence: (buff 68),
        hash-outputs-locktime-sighash: (buff 44)
    })
    (user-pubkey (buff 33))
    (cosigner-keys (list 11 (buff 33)))
    (provider principal)
    (cur-btc-height uint))

    (let (
        (checked-utxos
            (fold check-consumed-utxo (list
                    u0 u1 u2 u3 u4 u5 u6 u7 u8 u9
                    u10 u11 u12 u13 u14 u15 u16 u17 u18 u19
                    u20 u21 u22 u23 u24 u25 u26 u27 u28 u29
                    u30 u31 u32 u33 u34 u35 u36 u37 u38 u39
                    u40 u41 u42 u43 u44 u45 u46 u47 u48 u49)
                {
                    ins: ins,
                    outs: outs,
                    signature-hash: signature-hash,
                    utxos: (list ),
                    user-pubkey: user-pubkey,
                    cosigner-keys: cosigner-keys,
                    provider: provider,
                    valid: true,
                    cur-btc-height: cur-btc-height
                }))
    )
    (asserts! (get valid checked-utxos)
        (err ERR_TX_UTXO_CHECK_FAILED))
    (ok (filter is-some (get utxos checked-utxos)))))

;; Sum spend amounts for a list of UTXOs
(define-private (sum-utxo-spend-iter
    (utxo {
        provider: principal,
        amount: uint,
        expires: uint,
        user-pubkey: (buff 33),
        witness-script: (buff 1376), 
    })
    (sum uint))

    (+ sum (get amount utxo)))

;; Determine how much a transaction's outputs spend
(define-private (get-txout-spend-iter
    (outp {
        scriptPubKey: (buff 1376),
        value: uint
    })
    (sum uint))

    (+ sum (get value outp)))

;; Deduct a provider's amount from a user's balance, as part of removing a UTXO.
;; Return the new balance vector with `provider`'s entry removed.
;;
;; Returns (ok (list { balance-rec })) on success
;; Returns (err ERR_INSUFFICIENT_BALANCE) if (somehow) the UTXO exceeds the balance
(define-read-only (deduct-provider-balance
    (recipient principal)
    (provider principal)
    (amount uint))

    (let (
        (user-balances (fold retain-fresh-balances (default-to (list ) (map-get? balances recipient)) (list )))
        (provider-index-opt (get found (fold find-provider-balance-index balances { i: u0, found: none, provider: provider })))
    )
    (ok (match provider-index-opt
        provider-index (let (
            (before (if (> provider-index u0)
                (unwrap-panic (slice? user-balances u0 provider-index))
                (list )))

            (after (if (< provider-index (len user-balances))
                (unwrap-panic (slice? (+ u1 provider-index) (len user-balances)))
                (list )))

            (balance-rec (unwrap-panic (element-at? user-balances provider-index)))
            (balance-has-amount (try!
                (if (<= amount (get amount balance-rec))
                    (ok true)
                    (err ERR_INSUFFICIENT_BALANCE))))

            (new-balance-rec-opt (if (< u0 (- (get amount balance-rec) amount))
                (some (merge balance-rec { amount: (- (get amount-balance-rec) amount) }))
                none))
        )
        (match new-balance-rec-opt
            new-balance-rec
                (unwrap-panic (as-max-len? (concat (append before balance-rec) after) u1024))
            (unwrap-panic (as-max-len? (concat before after) u1024))))
        (list )))))

;; Delete UTXOs and deduct the correspoding balance from the user's balance vector
;; Panics if the user's balance is less than the UTXO.
(define-private (delete-utxo-iter
    (utxo {
        pointer: { txid: (buff 32), vout: uint },
        provider: principal,
        amount: uint,
        expires: uint,
        user-pubkey: (buff 33),
        witness-script: (buff 1376), 
    }))

    (let (
        (recipient (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 (get user-pubkey utxo)))))
        (provider (get provider utxo))
        (new-balances (unwrap-panic (deduct-provider-balance recipient provider (get amount utxo))))
    )
    (map-set balances recipient new-balances)
    (map-delete utxos (get pointer utxo))))

;; Execute a fully-signed scBTC transfer.
;; The transaction must already be decoded and stored.
;; All UTXOs the transaction consumes will be removed, and all
;; affected user balances will be docked.
;;
;; No new UTXOs will be created; these transfers are considered "final."
;;
;; Constraints:
;; * All UTXOs consumed must be spent by the same user and cosigner
;; * All UTXOs consumed must be p2wsh UTXOs for transfer witness scripts
;; * All UTXOs consumed must be from the same provider
;;
;; Only a cosigner can call this, and will call this potentially after the user 
;; has published the decoded tx to `decoded-transactions`
(define-private (inner-contract-transfer
    (wtxid (buff 32))       ;; NOTE: this is the little-endian wtxid (reversed of what you see on an explorer)
    (user-pubk (buff 33))
    (provider principal)
    (btc-block-height uint))

    (let (
        ;; only a cosigner can call this
        (cosigner-addr (try! (get-toplevel-addr)))
        (cosigner-rec (unwrap! (map-get? cosigner-info cosigner-addr) (err ERR_NO_SUCH_COSIGNER)))

        (decoded-tx (unwrap! (map-get? decoded-transactions wtxid) (err ERR_NO_BTC_TRANSACTION)))
        (txid (get txid decoded-tx))

        ;; provider must exist and must be unexpired
        (provider-info (try! (get-provider-info provider btc-block-height)))

        ;; each input to this transaction must:
        ;; * have been signed by user-pubk
        ;; * have been signed by the given cosigner
        ;; * have the same, given provider
        ;; * have not expired at the given btc-block-height
        (consumed-utxos (try! (check-consumed-utxos
            (get ins decoded-tx)
            (get outs decoded-tx)
            (get signature-hash decoded-tx)
            user-pubk
            (get dag-keys cosigner-rec)
            provider
            btc-block-height)))

        (total-consumed (fold sum-utxo-spend-iter consumed-utxos))
    )

    ;; transaction spends at most total-consumed
    (asserts! (>= total-consumed (fold get-txout-spend-iter (get outs decoded-tx) u0))
        (err ERR_TX_SPENDS_TOO_MUCH))

    ;; clear consumed UTXOs and adjust user balances
    (map consumed-utxos delete-utxos-iter)

    (ok true)))

;; from bitcoin.clar
(define-private (reverse-buff16 (input (buff 16)))
   (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (buff-to-uint-le input))) u1 u17)))

;; from bitcoin.clar
(define-read-only (reverse-buff32 (input (buff 32)))
   (unwrap-panic (as-max-len? (concat
   (reverse-buff16 (unwrap-panic (as-max-len? (unwrap-panic (slice? input u16 u32)) u16)))
   (reverse-buff16 (unwrap-panic (as-max-len? (unwrap-panic (slice? input u0 u16)) u16)))) u32)))

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
(define-read-only (compute-pegin-witness-script
    (cosigner-addr principal)
    (witness-data {
        recipient-principal: principal,
        user-pubkey: (buff 33),
        locktime: uint,
        safety-margin: uint
    }))

    (let (
        (cosigner-rec (unwrap! (map-get? cosigner-addr cosigner-info) (ERR_NO_SUCH_COSIGNER)))
        (cosigner-dag-spend-script (get dag-spend-script cosigner-rec))
    )

    (make-pegin-witness-script cosigner-dag-spend-script witness-data)))

;; Last failure for contract-call to pasre-wtx
(define-data-var last-btc-decode-error uint u0)

(define-private (merge-witness-and-txin
    (inp {
        outpoint: { hash: (buff 32), index: uint },
        scriptSig: (buff 1376),
        sequence: uint
    })
    (witness (list 13 (buff 1376))))

    {
        outpoint: (get outpoint inp),
        scriptSig: (get scriptSig inp),
        sequence: (get sequence inp),
        witness: witness
    })

;; Decode a Bitcoin tx and its witness data
(define-read-only (decode-bitcoin-wtx (wtx (buff 4096)))
    (match (contract-call? .bitcoin parse-wtx wtx true)
        decoded-tx
            (let (
                (ins (map merge-witness-and-txin (get ins decoded-tx) (get witness decoded-tx)))
            )
            (ok {
                version: (get version decoded-tx),
                segwit-marker: (get segwit-marker decoded-tx),
                segwit-version: (get segwit-version decoded-tx),
                txid: (unwrap-panic (get txid decoded-tx)),
                ins: ins,
                outs: (get outs decoded-tx),
                locktime: (get locktime decoded-tx),
                signature-hash: (precompute-segwit-signature-hash
                    (get version decoded-tx)
                    ins
                    (get outs decoded-tx))
            }))
        err-decode (begin
            (var-set last-btc-decode-error err-decode)
            (err ERR_TX_DECODE_ERROR))))

;; Authenticate and store an on-chain segwit transaction for a peg-in.
;; Anyone can call this, but only cosigner-approved transactions will be added to the DAG.
;;
;; Returns (ok true) on success
;; Returns (err uint) on failure, and sets last-btc-decode-error if the error was due to a decoding failure
(define-private (inner-auth-and-store-pegin-tx
    (btc-height uint)
    (wtx (buff 4096))
    (btc-header (buff 80))
    (btc-tx-index uint)
    (tree-depth uint)
    (wproof (list 14 (buff 32)))
    (witness-merkle-root (buff 32))
    (witness-reserved-value (buff 32))
    (btc-coinbase-tx (buff 4096))
    (btc-coinbase-proof (list 14 (buff 32))))

    (let (
        ;; the tx must be mined on this fork
        (wtxid-be (try! (contract-call? .bitcoin was-segwit-tx-mined-compact
                btc-height
                wtx
                btc-header
                btc-tx-index
                tree-depth
                wproof
                witness-merkle-root
                witness-reserved-value
                btc-coinbase-tx
                btc-coinbase-proof)))

        ;; little-endian wtxid, which we use in this system
        (wtxid (reverse-buff32 wtxid-be))
        (decoded-tx (try! (decode-bitcoin-wtx wtx)))
    )
    (asserts! (map-insert decoded-transactions wtxid decoded-tx)
        (err ERR_TX_ALREADY_EXISTS))

    (ok true)))

;; Authenticate and store an off-chain segwit transaction for a transfer (either for users or contracts)
;; Anyone can call this, but only cosigner-approved transactions will be added to the DAG.
;; Returns (ok true) on success
;; Returns (err uint) on failure, and sets last-btc-decode-error if the error was due to a decoding failure
(define-private (inner-store-transfer (wtx (buff 4096)))
    (let (
        (wtxid (sha256 (sha256 wtx)))
        (decoded-tx (try! (decode-bitcoin-wtx wtx)))
    )
    (asserts! (map-insert decoded-transactions wtxid decoded-tx)
        (err ERR_TX_ALREADY_EXISTS))

    (ok true)))

;; Remove all balance items that are expired
(define-private (retain-fresh-balances
    (balance-item { provider: principal, amount: uint, expires: uint })
    (ctx { fresh: (list 1024 { provider: principal, amount: uint, expires: uint }), cur-btc-height: uint }))

    (if (< (get expires balance-item) (get cur-btc-height ctx))
        (merge ctx {
            fresh: (unwrap-panic (as-max-len? (append (get fresh ctx) balance-item) u1024))
        })
        ctx))

;; Find the index of a provider balance
(define-private (find-provider-balance-index
    (balance-item { provider: principal, amount: uint, expires: uint })
    (ctx { i: uint, found: (optional uint), provider: principal }))

    (if (get found ctx)
        ctx
        (merge ctx {
            i: (+ u1 (get i ctx)),
            found: (if (is-eq (get provider ctx) (get provider balance-item)) (some (get i ctx)) none)
        })))
 
;; Insert or update a new balance into a given recipient's balance vector.
;; Do not store it; return the balance vector instead so the caller can store it.
(define-read-only (make-user-balance-vec
    (recipient principal)
    (provider principal)
    (amount uint)
    (cur-btc-height uint)
    (expires uint))

    (let (
        (user-balances (fold retain-fresh-balances (default-to (list ) (map-get? balances recipient)) (list )))
        (have-space (try! (if (< (len balances) u1024) (ok true) (err ERR_TOO_MANY_PROVIDERS))))
        (provider-index-opt (get found (fold find-provider-balance-index balances { i: u0, found: none, provider: provider })))
        (cur-provider-balance (match provider-index-opt
            provider-index
                ;; SAFETY: (some ..) implies that a match was found
                (unwrap-panic (element-at? balances provider-index))
            { provider: provider, expires: u0, balance: u0 }))

        (new-provider-balance (merge cur-provider-balance {
            amount: amount,
            expires: expires
        }))
    )

    ;; SAFETY: checked with have-space
    (unwrap-panic (as-max-len? (append user-balances new-provider-balance) u1024))

    (ok new-provider-balance)))

;; Materialize the UTXO for an already-authenticated and stored pegin transaction.
;; This is only called by the cosigner.
;; Caller must check that only the cosigner can call this.
(define-private (inner-register-pegin-utxo
    (cur-btc-height uint)
    (wtxid (buff 32))
    (pegin-output uint)
    (witness-data {
        recipient-principal: principal,
        user-pubkey: (buff 33),
        locktime: uint,
        safety-margin: uint
    }))

    (let (
        (cosigner-addr (try! (get-toplevel-addr)))
        (recipient-principal (get recipient-principal witness-data))
        (locktime (get locktime witness-data))
        (safety-margin (get safety-margin witness-data))
        (expires (+ (get locktime witness-data) (get safety-margin witness-data)))
        (provider (unwrap-panic (principal-construct? SINGLESIG_ADDRESS_VERSION_BYTE (hash160 (get user-pubkey witness-data))))) 
    )

    ;; witness data safety margin must be well-formed
    (asserts! (< safety-margin locktime)
        (err ERR_WITNESS_BAD_LOCKTIME))
 
    ;; witness data lock-times must be post-dated relative to `cur-btc-height`
    (asserts! (> (- locktime safety-margin) cur-btc-height)
        (err ERR_WITNESS_BAD_LOCKTIME))

    ;; this must be a never-before-seen provider
    (asserts! (is-none (map-get? btc-providers provider))
        (err ERR_PROVIDER_EXISTS))

    (let (
        ;; load the authenticated tx
        (decoded-tx (unwrap! (map-get? decoded-transactions wtxid) (err ERR_NO_BTC_TRANSACTION)))
        (txid (get txid decoded-tx))

        ;; witness script and its hash
        (pegin-witness-script (try! (compute-pegin-witness-script cosigner-addr witness-data)))
        (pegin-witness-script-hash (sha256 pegin-witness-script))

        ;; claimed pegin output
        (pegin-out (unwrap! (element-at (get outs decoded-tx) pegin-output)
            (err ERR_NO_PEGIN_UTXO)))

        ;; updated balance
        (new-user-balance-vec (try! (make-user-balance-vec recipient-principal provider (get amount pegin-out) cur-btc-height expires)))
    )

    ;; UTXO scriptPubKey must match witness script
    (asserts! (is-eq (get scriptPubKey pegin-out) (concat 0x00 pegin-witness-script-hash))
        (err ERR_TX_INVALID_PEGIN_P2WSH))

    ;; create the peg-in UTXO, if it doesn't exist already
    (asserts! (map-insert utxos
        { txid: txid, vout: pegin-output }
        {
            recipient: recipient-principal,
            amount: (get amount pegin-out),
            expires: expires,
            user-pubkey: (get user-pubkey witness-data),
            witness-script: pegin-witness-script,
        })
        (err ERR_DUPLICATE_UTXO))

    ;; SAFETY: infallible since we checked above
    (unwrap-panic (map-insert btc-providers
        provider
        { wtxid: wtxid, expires: expires }))

    (map-set balances provider-recipient new-user-balance-vec)

    ;; store peg-in tx in DAG
    ;; (append-dag-pegin wtxid recipient-principal amount cur-btc-height)
    (ok true))))

;; Carry out a peg-in on an already-stored authenticated witness transaction.
;; Called only by the cosigner.
(define-public (register-pegin-utxo
    (wtxid (buff 32))
    (pegin-output uint)
    (witness-data {
        recipient-principal: principal,
        user-pubkey: (buff 33),
        locktime: uint,
        safety-margin: uint
    }))

    (let (
        (cosigner-addr (try! (get-toplevel-addr)))
    )

    (inner-register-pegin-utxo burn-block-height wtxid pegin-output witness-data)))
