;; Code that the mach2 special case handler uses to load and store a call-readonly result
;; into the boot code, for consumption via the public API.  This function is intercepted.
(define-data-var m2-ll-last-call-readonly (response (buff 102400) { code: uint, message: (string-ascii 512) }) (ok 0x))
(define-public (m2-ll-call-readonly (contract principal) (function-name (string-ascii 128)) (function-args-list (buff 102400)))
   (ok 0x))
(define-private (m2-ll-set-last-call-readonly (result (response (buff 102400) { code: uint, message: (string-ascii 512) })))
   (ok (var-set m2-ll-last-call-readonly result)))
(define-read-only (m2-ll-get-last-call-readonly)
   (var-get m2-ll-last-call-readonly))

;; Code that the mach2 special case handler uses to load and store a buff-to-string-utf8 value
;; into the boot code, for consumption by the public API.  This function is intercepted
(define-public (m2-ll-buff-to-string-utf8 (arg (buff 102400)))
   (ok true))

(define-data-var m2-ll-last-m2-buff-to-string-utf8 (response (string-utf8 25600) { code: uint, message: (string-ascii 512) }) (ok u""))
(define-private (m2-ll-set-last-m2-buff-to-string-utf8 (conv-res (response (string-utf8 25600) { code: uint, message: (string-ascii 512) })))
   (ok (var-set m2-ll-last-m2-buff-to-string-utf8 conv-res)))
(define-read-only (m2-ll-get-last-m2-buff-to-string-utf8)
   (var-get m2-ll-last-m2-buff-to-string-utf8))

;; Code that the mach2 special case handler uses to load and store a string-ascii-to-string-utf8 value
;; into the boot code, for consumption by the public API.  This function is intercepted
(define-public (m2-ll-string-ascii-to-string-utf8 (arg (string-ascii 25600)))
   (ok true))

(define-data-var m2-ll-last-m2-string-ascii-to-string-utf8 (response (string-utf8 25600) { code: uint, message: (string-ascii 512) }) (ok u""))
(define-private (m2-ll-set-last-m2-string-ascii-to-string-utf8 (conv-res (response (string-utf8 25600) { code: uint, message: (string-ascii 512) })))
   (ok (var-set m2-ll-last-m2-string-ascii-to-string-utf8 conv-res)))
(define-read-only (m2-ll-get-last-m2-string-ascii-to-string-utf8)
   (var-get m2-ll-last-m2-string-ascii-to-string-utf8))

