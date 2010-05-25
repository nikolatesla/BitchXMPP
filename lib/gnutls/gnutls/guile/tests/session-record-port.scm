;;; GnuTLS --- Guile bindings for GnuTLS.
;;; Copyright (C) 2007, 2010 Free Software Foundation, Inc.
;;;
;;; GnuTLS is free software; you can redistribute it and/or
;;; modify it under the terms of the GNU Lesser General Public
;;; License as published by the Free Software Foundation; either
;;; version 2.1 of the License, or (at your option) any later version.
;;;
;;; GnuTLS is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Lesser General Public License for more details.
;;;
;;; You should have received a copy of the GNU Lesser General Public
;;; License along with GnuTLS; if not, write to the Free Software
;;; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

;;; Written by Ludovic Court�s <ludo@chbouib.org>.


;;;
;;; Test session establishment using anonymous authentication.  Exercise the
;;; `session-record-port' API.
;;;

(use-modules (gnutls)
             (srfi srfi-4))


;; TLS session settings.
(define %protos  (list protocol/tls-1.0))
(define %certs   '())
(define %ciphers (list cipher/null cipher/arcfour cipher/aes-128-cbc
                       cipher/aes-256-cbc))
(define %kx      (list kx/anon-dh))
(define %macs    (list mac/sha1 mac/rmd160 mac/md5))

;; Message sent by the client.
(define %message (apply u8vector (iota 256)))

;; Debugging.
;; (set-log-level! 100)
;; (set-log-procedure! (lambda (level str)
;;                       (format #t "[~a|~a] ~a" (getpid) level str)))

(dynamic-wind
    (lambda ()
      #t)

    (lambda ()
      ;; Stress the GC.  In 0.0, this triggered an abort due to
      ;; "scm_unprotect_object called during GC".
      (let ((sessions (map (lambda (i)
                             (make-session connection-end/server))
                           (iota 123))))
        (for-each session-record-port sessions)
        (gc)(gc)(gc))

      ;; Stress the GC.  The session associated to each port in PORTS should
      ;; remain reachable.
      (let ((ports (map session-record-port
                        (map (lambda (i)
                               (make-session connection-end/server))
                             (iota 123)))))
        (gc)(gc)(gc)
        (for-each (lambda (p)
                    (catch 'gnutls-error
                      (lambda ()
                        (read p))
                      (lambda (key . args)
                        #t)))
                  ports))

      ;; Try using the record port for I/O.
      (let ((socket-pair (socketpair PF_UNIX SOCK_STREAM 0))
            (pid         (primitive-fork)))
        (if (= 0 pid)

            (let ((client (make-session connection-end/client)))
              ;; client-side (child process)
              (set-session-default-priority! client)
              (set-session-certificate-type-priority! client %certs)
              (set-session-kx-priority! client %kx)
              (set-session-protocol-priority! client %protos)
              (set-session-cipher-priority! client %ciphers)
              (set-session-mac-priority! client %macs)

              (set-session-transport-port! client (car socket-pair))
              (set-session-credentials! client (make-anonymous-client-credentials))
              (set-session-dh-prime-bits! client 1024)

              (handshake client)
              (uniform-vector-write %message (session-record-port client))
              (bye client close-request/rdwr)

              (exit))

            (let ((server (make-session connection-end/server)))
              ;; server-side
              (set-session-default-priority! server)
              (set-session-certificate-type-priority! server %certs)
              (set-session-kx-priority! server %kx)
              (set-session-protocol-priority! server %protos)
              (set-session-cipher-priority! server %ciphers)
              (set-session-mac-priority! server %macs)

              (set-session-transport-port! server (cdr socket-pair))
              (let ((cred (make-anonymous-server-credentials))
                    (dh-params (make-dh-parameters 1024)))
                ;; Note: DH parameter generation can take some time.
                (set-anonymous-server-dh-parameters! cred dh-params)
                (set-session-credentials! server cred))
              (set-session-dh-prime-bits! server 1024)

              (handshake server)
              (let* ((buf (make-u8vector (u8vector-length %message)))
                     (amount
                      (uniform-vector-read! buf (session-record-port server))))
                (bye server close-request/rdwr)

                ;; Make sure we got everything right.
                (exit (eq? (session-record-port server)
                           (session-record-port server))
                      (= amount (u8vector-length %message))
                      (equal? buf %message)
                      (eof-object?
                       (read-char (session-record-port server)))))))))

    (lambda ()
      ;; failure
      (exit 1)))

;;; arch-tag: e873226a-d0b6-4a93-87ec-a1b5ad2ae8a2
