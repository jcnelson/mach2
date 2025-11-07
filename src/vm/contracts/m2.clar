;; Runtime Mach2 library that gets linked with Mach2 smart contracts.
;; Mainly wraps m2-ll

(define-constant M2_ERR_READONLY_FAILURE u2000)

(define-constant M2_ERR_BUFF_TO_UTF8_FAILURE u3000)

(define-constant M2_ERR_ASCII_TO_UTF8_FAILURE u4000)

;;;;;;;;;;;;;;;;;;;;;;;;;; Mach2 Node RPC ;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Call a read-only function 
;; The caller needs to consensus-encode the list of Values and pass it as `function-args-list`
;; Runtime panics if the RPC call fails.
(define-private (m2-call-readonly? (contract principal) (function-name (string-ascii 128)) (function-args-list (buff 102400)))
   (begin
       (unwrap-panic (contract-call? .m2-ll m2-ll-call-readonly contract function-name function-args-list))
       (ok (unwrap-panic (match (contract-call? .m2-ll m2-ll-get-last-call-readonly)
           ok-res (ok ok-res)
           err-res (begin
               (print (get message err-res))
               (err err-res)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;; Mach2 String Utils ;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Tries to convert a buff to a string-utf8
(define-private (m2-buff-to-string-utf8? (arg (buff 102400)))
   (begin
       (unwrap-panic (contract-call? .m2-ll m2-ll-buff-to-string-utf8 arg))
       (contract-call? .m2-ll m2-ll-get-last-m2-buff-to-string-utf8)))

;; Tries to convert a string-ascii to a string-utf8
(define-private (m2-string-ascii-to-string-utf8? (arg (string-ascii 25600)))
   (begin
       (unwrap-panic (contract-call? .m2-ll m2-ll-string-ascii-to-string-utf8 arg))
       (contract-call? .m2-ll m2-ll-get-last-m2-string-ascii-to-string-utf8)))

