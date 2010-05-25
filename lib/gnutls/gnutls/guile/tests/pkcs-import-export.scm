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
;;; Exercise the DH/RSA PKCS3/PKCS1 export/import functions.
;;;

(use-modules (gnutls)
             (srfi srfi-4))

(dynamic-wind

    (lambda ()
      #t)

    (lambda ()
      (exit
       (let* ((dh-params (make-dh-parameters 1024))
              (export
               (pkcs3-export-dh-parameters dh-params
                                           x509-certificate-format/pem)))
         (and (u8vector? export)
              (let ((import
                     (pkcs3-import-dh-parameters export
                                                 x509-certificate-format/pem)))
                (dh-parameters? import))))))

    (lambda ()
      ;; failure
      (exit 1)))

;;; arch-tag: adff0f07-479e-421e-b47f-8956e06b9902
