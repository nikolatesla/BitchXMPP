/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Free
 * Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This file contains functions to handle X.509 certificate generation.
 */

#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include "x509_int.h"
#include <libtasn1.h>

static void disable_optional_stuff (gnutls_x509_crt_t cert);

/**
 * gnutls_x509_crt_set_dn_by_oid:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @oid: holds an Object Identifier in a null terminated string
 * @raw_flag: must be 0, or 1 if the data are DER encoded
 * @name: a pointer to the name
 * @sizeof_name: holds the size of @name
 *
 * This function will set the part of the name of the Certificate
 * subject, specified by the given OID. The input string should be
 * ASCII or UTF-8 encoded.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * With this function you can only set the known OIDs. You can test
 * for known OIDs using gnutls_x509_dn_oid_known(). For OIDs that are
 * not known (by gnutls) you should properly DER encode your data,
 * and call this function with @raw_flag set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_dn_by_oid (gnutls_x509_crt_t crt, const char *oid,
			       unsigned int raw_flag, const void *name,
			       unsigned int sizeof_name)
{
  if (sizeof_name == 0 || name == NULL || crt == NULL)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_set_dn_oid (crt->cert, "tbsCertificate.subject",
				  oid, raw_flag, name, sizeof_name);
}

/**
 * gnutls_x509_crt_set_issuer_dn_by_oid:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @oid: holds an Object Identifier in a null terminated string
 * @raw_flag: must be 0, or 1 if the data are DER encoded
 * @name: a pointer to the name
 * @sizeof_name: holds the size of @name
 *
 * This function will set the part of the name of the Certificate
 * issuer, specified by the given OID.  The input string should be
 * ASCII or UTF-8 encoded.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * With this function you can only set the known OIDs. You can test
 * for known OIDs using gnutls_x509_dn_oid_known(). For OIDs that are
 * not known (by gnutls) you should properly DER encode your data,
 * and call this function with @raw_flag set.
 *
 * Normally you do not need to call this function, since the signing
 * operation will copy the signer's name as the issuer of the
 * certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_issuer_dn_by_oid (gnutls_x509_crt_t crt,
				      const char *oid,
				      unsigned int raw_flag,
				      const void *name,
				      unsigned int sizeof_name)
{
  if (sizeof_name == 0 || name == NULL || crt == NULL)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_set_dn_oid (crt->cert, "tbsCertificate.issuer", oid,
				  raw_flag, name, sizeof_name);
}

/**
 * gnutls_x509_crt_set_proxy_dn:
 * @crt: a gnutls_x509_crt_t structure with the new proxy cert
 * @eecrt: the end entity certificate that will be issuing the proxy
 * @raw_flag: must be 0, or 1 if the CN is DER encoded
 * @name: a pointer to the CN name, may be NULL (but MUST then be added later)
 * @sizeof_name: holds the size of @name
 *
 * This function will set the subject in @crt to the end entity's
 * @eecrt subject name, and add a single Common Name component @name
 * of size @sizeof_name.  This corresponds to the required proxy
 * certificate naming style.  Note that if @name is %NULL, you MUST
 * set it later by using gnutls_x509_crt_set_dn_by_oid() or similar.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_proxy_dn (gnutls_x509_crt_t crt, gnutls_x509_crt_t eecrt,
			      unsigned int raw_flag, const void *name,
			      unsigned int sizeof_name)
{
  int result;

  if (crt == NULL || eecrt == NULL)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = asn1_copy_node (crt->cert, "tbsCertificate.subject",
			   eecrt->cert, "tbsCertificate.subject");
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  if (name && sizeof_name)
    {
      return _gnutls_x509_set_dn_oid (crt->cert, "tbsCertificate.subject",
				      GNUTLS_OID_X520_COMMON_NAME,
				      raw_flag, name, sizeof_name);
    }

  return 0;
}

/**
 * gnutls_x509_crt_set_version:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @version: holds the version number. For X.509v1 certificates must be 1.
 *
 * This function will set the version of the certificate.  This must
 * be one for X.509 version 1, and so on.  Plain certificates without
 * extensions must have version set to one.
 *
 * To create well-formed certificates, you must specify version 3 if
 * you use any certificate extensions.  Extensions are created by
 * functions such as gnutls_x509_crt_set_subject_alt_name()
 * or gnutls_x509_crt_set_key_usage().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_version (gnutls_x509_crt_t crt, unsigned int version)
{
  int result;
  unsigned char null = version;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (null > 0)
    null--;

  result = asn1_write_value (crt->cert, "tbsCertificate.version", &null, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crt_set_key:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @key: holds a private key
 *
 * This function will set the public parameters from the given
 * private key to the certificate. Only RSA keys are currently
 * supported.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 **/
int
gnutls_x509_crt_set_key (gnutls_x509_crt_t crt, gnutls_x509_privkey_t key)
{
  int result;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_encode_and_copy_PKI_params (crt->cert,
						    "tbsCertificate.subjectPublicKeyInfo",
						    key->pk_algorithm,
						    key->params,
						    key->params_size);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crt_set_crq:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @crq: holds a certificate request
 *
 * This function will set the name and public parameters as well as
 * the extensions from the given certificate request to the certificate. 
 * Only RSA keys are currently supported.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_crq (gnutls_x509_crt_t crt, gnutls_x509_crq_t crq)
{
  int result;

  if (crt == NULL || crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = asn1_copy_node (crt->cert, "tbsCertificate.subject",
			   crq->crq, "certificationRequestInfo.subject");
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result =
    asn1_copy_node (crt->cert, "tbsCertificate.subjectPublicKeyInfo",
		    crq->crq, "certificationRequestInfo.subjectPKInfo");
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crt_set_crq_extensions:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @crq: holds a certificate request
 *
 * This function will set extensions from the given request to the
 * certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crt_set_crq_extensions (gnutls_x509_crt_t crt,
				    gnutls_x509_crq_t crq)
{
  size_t i;

  if (crt == NULL || crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  for (i = 0;; i++)
    {
      int result;
      char oid[MAX_OID_SIZE];
      size_t oid_size;
      opaque *extensions;
      size_t extensions_size;
      unsigned int critical;
      gnutls_datum_t ext;

      oid_size = sizeof (oid);
      result = gnutls_x509_crq_get_extension_info (crq, i, oid,
						   &oid_size, &critical);
      if (result < 0)
	{
	  if (result == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	    break;

	  gnutls_assert ();
	  return result;
	}

      extensions_size = 0;
      result = gnutls_x509_crq_get_extension_data (crq, i, NULL,
						   &extensions_size);
      if (result < 0)
	{
	  gnutls_assert ();
	  return result;
	}

      extensions = gnutls_malloc (extensions_size);
      if (extensions == NULL)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}

      result = gnutls_x509_crq_get_extension_data (crq, i, extensions,
						   &extensions_size);
      if (result < 0)
	{
	  gnutls_assert ();
	  gnutls_free (extensions);
	  return result;
	}

      ext.data = extensions;
      ext.size = extensions_size;

      result = _gnutls_x509_crt_set_extension (crt, oid, &ext, critical);
      gnutls_free (extensions);
      if (result < 0)
	{
	  gnutls_assert ();
	  return result;
	}
    }

  if (i > 0)
    crt->use_extensions = 1;

  return 0;
}

/**
 * gnutls_x509_crt_set_extension_by_oid:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @oid: holds an Object Identified in null terminated string
 * @buf: a pointer to a DER encoded data
 * @sizeof_buf: holds the size of @buf
 * @critical: should be non zero if the extension is to be marked as critical
 *
 * This function will set an the extension, by the specified OID, in
 * the certificate.  The extension data should be binary data DER
 * encoded.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_extension_by_oid (gnutls_x509_crt_t crt,
				      const char *oid, const void *buf,
				      size_t sizeof_buf,
				      unsigned int critical)
{
  int result;
  gnutls_datum_t der_data;

  der_data.data = (void *) buf;
  der_data.size = sizeof_buf;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_crt_set_extension (crt, oid, &der_data, critical);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  crt->use_extensions = 1;

  return 0;

}

/**
 * gnutls_x509_crt_set_basic_constraints:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @ca: true(1) or false(0). Depending on the Certificate authority status.
 * @pathLenConstraint: non-negative values indicate maximum length of path,
 *   and negative values indicate that the pathLenConstraints field should
 *   not be present.
 *
 * This function will set the basicConstraints certificate extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_basic_constraints (gnutls_x509_crt_t crt,
				       unsigned int ca, int pathLenConstraint)
{
  int result;
  gnutls_datum_t der_data;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* generate the extension.
   */
  result = _gnutls_x509_ext_gen_basicConstraints (ca, pathLenConstraint,
						  &der_data);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_x509_crt_set_extension (crt, "2.5.29.19", &der_data, 1);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  crt->use_extensions = 1;

  return 0;
}

/**
 * gnutls_x509_crt_set_ca_status:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @ca: true(1) or false(0). Depending on the Certificate authority status.
 *
 * This function will set the basicConstraints certificate extension.
 * Use gnutls_x509_crt_set_basic_constraints() if you want to control
 * the pathLenConstraint field too.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_ca_status (gnutls_x509_crt_t crt, unsigned int ca)
{
  return gnutls_x509_crt_set_basic_constraints (crt, ca, -1);
}

/**
 * gnutls_x509_crt_set_key_usage:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @usage: an ORed sequence of the GNUTLS_KEY_* elements.
 *
 * This function will set the keyUsage certificate extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_key_usage (gnutls_x509_crt_t crt, unsigned int usage)
{
  int result;
  gnutls_datum_t der_data;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* generate the extension.
   */
  result = _gnutls_x509_ext_gen_keyUsage ((uint16_t) usage, &der_data);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_x509_crt_set_extension (crt, "2.5.29.15", &der_data, 1);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  crt->use_extensions = 1;

  return 0;
}

/**
 * gnutls_x509_crt_set_subject_alternative_name:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @type: is one of the gnutls_x509_subject_alt_name_t enumerations
 * @data_string: The data to be set, a zero terminated string
 *
 * This function will set the subject alternative name certificate
 * extension. This function assumes that data can be expressed as a null
 * terminated string.
 *
 * The name of the function is unfortunate since it is incosistent with
 * gnutls_x509_crt_get_subject_alt_name().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_subject_alternative_name (gnutls_x509_crt_t crt,
					      gnutls_x509_subject_alt_name_t
					      type, const char *data_string)
{
  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* only handle text extensions */
  if (type != GNUTLS_SAN_DNSNAME && type != GNUTLS_SAN_RFC822NAME &&
      type != GNUTLS_SAN_URI)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return gnutls_x509_crt_set_subject_alt_name (crt, type, data_string,
					       strlen (data_string),
					       GNUTLS_FSAN_SET);
}

/**
 * gnutls_x509_crt_set_subject_alt_name:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @type: is one of the gnutls_x509_subject_alt_name_t enumerations
 * @data: The data to be set
 * @data_size: The size of data to be set
 * @flags: GNUTLS_FSAN_SET to clear previous data or GNUTLS_FSAN_APPEND to append. 
 *
 * This function will set the subject alternative name certificate
 * extension. It can set the following types:
 *
 * &GNUTLS_SAN_DNSNAME: as a text string
 *
 * &GNUTLS_SAN_RFC822NAME: as a text string
 *
 * &GNUTLS_SAN_URI: as a text string
 *
 * &GNUTLS_SAN_IPADDRESS: as a binary IP address (4 or 16 bytes)
 * 
 * Other values can be set as binary values with the proper DER encoding.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.6.0
 **/
int
gnutls_x509_crt_set_subject_alt_name (gnutls_x509_crt_t crt,
				      gnutls_x509_subject_alt_name_t type,
				      const void *data,
				      unsigned int data_size,
				      unsigned int flags)
{
  int result;
  gnutls_datum_t der_data = { NULL, 0 };
  gnutls_datum_t prev_der_data = { NULL, 0 };
  unsigned int critical = 0;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Check if the extension already exists.
   */

  if (flags == GNUTLS_FSAN_APPEND)
    {
      result = _gnutls_x509_crt_get_extension (crt, "2.5.29.17", 0,
					       &prev_der_data, &critical);
      if (result < 0 && result != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	{
	  gnutls_assert ();
	  return result;
	}
    }

  /* generate the extension.
   */
  result = _gnutls_x509_ext_gen_subject_alt_name (type, data, data_size,
						  &prev_der_data, &der_data);

  if (flags == GNUTLS_FSAN_APPEND)
    _gnutls_free_datum (&prev_der_data);

  if (result < 0)
    {
      gnutls_assert ();
      goto finish;
    }

  result = _gnutls_x509_crt_set_extension (crt, "2.5.29.17", &der_data,
					   critical);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  crt->use_extensions = 1;

  return 0;

finish:
  _gnutls_free_datum (&prev_der_data);
  return result;
}

/**
 * gnutls_x509_crt_set_proxy:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @pathLenConstraint: non-negative values indicate maximum length of path,
 *   and negative values indicate that the pathLenConstraints field should
 *   not be present.
 * @policyLanguage: OID describing the language of @policy.
 * @policy: opaque byte array with policy language, can be %NULL
 * @sizeof_policy: size of @policy.
 *
 * This function will set the proxyCertInfo extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_proxy (gnutls_x509_crt_t crt,
			   int pathLenConstraint,
			   const char *policyLanguage,
			   const char *policy, size_t sizeof_policy)
{
  int result;
  gnutls_datum_t der_data;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* generate the extension.
   */
  result = _gnutls_x509_ext_gen_proxyCertInfo (pathLenConstraint,
					       policyLanguage,
					       policy, sizeof_policy,
					       &der_data);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_x509_crt_set_extension (crt, "1.3.6.1.5.5.7.1.14",
					   &der_data, 1);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  crt->use_extensions = 1;

  return 0;
}

/**
 * gnutls_x509_crt_sign2:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @issuer: is the certificate of the certificate issuer
 * @issuer_key: holds the issuer's private key
 * @dig: The message digest to use, %GNUTLS_DIG_SHA1 is a safe choice
 * @flags: must be 0
 *
 * This function will sign the certificate with the issuer's private key, and
 * will copy the issuer's information into the certificate.
 *
 * This must be the last step in a certificate generation since all
 * the previously set parameters are now signed.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_sign2 (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer,
		       gnutls_x509_privkey_t issuer_key,
		       gnutls_digest_algorithm_t dig, unsigned int flags)
{
  int result;

  if (crt == NULL || issuer == NULL || issuer_key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* disable all the unneeded OPTIONAL fields.
   */
  disable_optional_stuff (crt);

  result = _gnutls_x509_pkix_sign (crt->cert, "tbsCertificate",
				   dig, issuer, issuer_key);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crt_sign:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @issuer: is the certificate of the certificate issuer
 * @issuer_key: holds the issuer's private key
 *
 * This function is the same a gnutls_x509_crt_sign2() with no flags,
 * and SHA1 as the hash algorithm.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_sign (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer,
		      gnutls_x509_privkey_t issuer_key)
{
  return gnutls_x509_crt_sign2 (crt, issuer, issuer_key, GNUTLS_DIG_SHA1, 0);
}

/**
 * gnutls_x509_crt_set_activation_time:
 * @cert: a certificate of type #gnutls_x509_crt_t
 * @act_time: The actual time
 *
 * This function will set the time this Certificate was or will be
 * activated.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_activation_time (gnutls_x509_crt_t cert, time_t act_time)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_set_time (cert->cert,
				"tbsCertificate.validity.notBefore",
				act_time);
}

/**
 * gnutls_x509_crt_set_expiration_time:
 * @cert: a certificate of type #gnutls_x509_crt_t
 * @exp_time: The actual time
 *
 * This function will set the time this Certificate will expire.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_expiration_time (gnutls_x509_crt_t cert, time_t exp_time)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
  return _gnutls_x509_set_time (cert->cert,
				"tbsCertificate.validity.notAfter", exp_time);
}

/**
 * gnutls_x509_crt_set_serial:
 * @cert: a certificate of type #gnutls_x509_crt_t
 * @serial: The serial number
 * @serial_size: Holds the size of the serial field.
 *
 * This function will set the X.509 certificate's serial number.
 * Serial is not always a 32 or 64bit number.  Some CAs use large
 * serial numbers, thus it may be wise to handle it as something
 * opaque.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_serial (gnutls_x509_crt_t cert, const void *serial,
			    size_t serial_size)
{
  int ret;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret =
    asn1_write_value (cert->cert, "tbsCertificate.serialNumber", serial,
		      serial_size);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (ret);
    }

  return 0;

}

/* If OPTIONAL fields have not been initialized then
 * disable them.
 */
static void
disable_optional_stuff (gnutls_x509_crt_t cert)
{

  asn1_write_value (cert->cert, "tbsCertificate.issuerUniqueID", NULL, 0);

  asn1_write_value (cert->cert, "tbsCertificate.subjectUniqueID", NULL, 0);

  if (cert->use_extensions == 0)
    {
      _gnutls_x509_log ("Disabling X.509 extensions.\n");
      asn1_write_value (cert->cert, "tbsCertificate.extensions", NULL, 0);
    }

  return;
}

/**
 * gnutls_x509_crt_set_crl_dist_points:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @type: is one of the gnutls_x509_subject_alt_name_t enumerations
 * @data_string: The data to be set
 * @reason_flags: revocation reasons
 *
 * This function will set the CRL distribution points certificate extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_crl_dist_points (gnutls_x509_crt_t crt,
				     gnutls_x509_subject_alt_name_t type,
				     const void *data_string,
				     unsigned int reason_flags)
{
  return gnutls_x509_crt_set_crl_dist_points2 (crt, type, data_string,
					       strlen (data_string),
					       reason_flags);
}

/**
 * gnutls_x509_crt_set_crl_dist_points2:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @type: is one of the gnutls_x509_subject_alt_name_t enumerations
 * @data: The data to be set
 * @data_size: The data size
 * @reason_flags: revocation reasons
 *
 * This function will set the CRL distribution points certificate extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.6.0
 **/
int
gnutls_x509_crt_set_crl_dist_points2 (gnutls_x509_crt_t crt,
				      gnutls_x509_subject_alt_name_t type,
				      const void *data,
				      unsigned int data_size,
				      unsigned int reason_flags)
{
  int result;
  gnutls_datum_t der_data = { NULL, 0 };
  gnutls_datum_t oldname = { NULL, 0 };
  unsigned int critical;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Check if the extension already exists.
   */
  result =
    _gnutls_x509_crt_get_extension (crt, "2.5.29.31", 0, &oldname, &critical);

  _gnutls_free_datum (&oldname);

  if (result != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* generate the extension.
   */
  result =
    _gnutls_x509_ext_gen_crl_dist_points (type, data, data_size,
					  reason_flags, &der_data);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_x509_crt_set_extension (crt, "2.5.29.31", &der_data, 0);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  crt->use_extensions = 1;

  return 0;

}

/**
 * gnutls_x509_crt_cpy_crl_dist_points:
 * @dst: a certificate of type #gnutls_x509_crt_t
 * @src: the certificate where the dist points will be copied from
 *
 * This function will copy the CRL distribution points certificate
 * extension, from the source to the destination certificate.
 * This may be useful to copy from a CA certificate to issued ones.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_cpy_crl_dist_points (gnutls_x509_crt_t dst,
				     gnutls_x509_crt_t src)
{
  int result;
  gnutls_datum_t der_data;
  unsigned int critical;

  if (dst == NULL || src == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Check if the extension already exists.
   */
  result =
    _gnutls_x509_crt_get_extension (src, "2.5.29.31", 0, &der_data,
				    &critical);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result =
    _gnutls_x509_crt_set_extension (dst, "2.5.29.31", &der_data, critical);
  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  dst->use_extensions = 1;

  return 0;
}

/**
 * gnutls_x509_crt_set_subject_key_id:
 * @cert: a certificate of type #gnutls_x509_crt_t
 * @id: The key ID
 * @id_size: Holds the size of the serial field.
 *
 * This function will set the X.509 certificate's subject key ID
 * extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_subject_key_id (gnutls_x509_crt_t cert,
				    const void *id, size_t id_size)
{
  int result;
  gnutls_datum_t old_id, der_data;
  unsigned int critical;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Check if the extension already exists.
   */
  result =
    _gnutls_x509_crt_get_extension (cert, "2.5.29.14", 0, &old_id, &critical);

  if (result >= 0)
    _gnutls_free_datum (&old_id);
  if (result != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* generate the extension.
   */
  result = _gnutls_x509_ext_gen_key_id (id, id_size, &der_data);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_x509_crt_set_extension (cert, "2.5.29.14", &der_data, 0);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  cert->use_extensions = 1;

  return 0;
}

/**
 * gnutls_x509_crt_set_authority_key_id:
 * @cert: a certificate of type #gnutls_x509_crt_t
 * @id: The key ID
 * @id_size: Holds the size of the serial field.
 *
 * This function will set the X.509 certificate's authority key ID extension.
 * Only the keyIdentifier field can be set with this function.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_authority_key_id (gnutls_x509_crt_t cert,
				      const void *id, size_t id_size)
{
  int result;
  gnutls_datum_t old_id, der_data;
  unsigned int critical;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Check if the extension already exists.
   */
  result =
    _gnutls_x509_crt_get_extension (cert, "2.5.29.35", 0, &old_id, &critical);

  if (result >= 0)
    _gnutls_free_datum (&old_id);
  if (result != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* generate the extension.
   */
  result = _gnutls_x509_ext_gen_auth_key_id (id, id_size, &der_data);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_x509_crt_set_extension (cert, "2.5.29.35", &der_data, 0);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  cert->use_extensions = 1;

  return 0;
}

/**
 * gnutls_x509_crt_set_key_purpose_oid:
 * @cert: a certificate of type #gnutls_x509_crt_t
 * @oid: a pointer to a null terminated string that holds the OID
 * @critical: Whether this extension will be critical or not
 *
 * This function will set the key purpose OIDs of the Certificate.
 * These are stored in the Extended Key Usage extension (2.5.29.37)
 * See the GNUTLS_KP_* definitions for human readable names.
 *
 * Subsequent calls to this function will append OIDs to the OID list.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (zero) is returned,
 *   otherwise an error code is returned.
 **/
int
gnutls_x509_crt_set_key_purpose_oid (gnutls_x509_crt_t cert,
				     const void *oid, unsigned int critical)
{
  int result;
  gnutls_datum_t old_id, der_data;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = asn1_create_element
    (_gnutls_get_pkix (), "PKIX1.ExtKeyUsageSyntax", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  /* Check if the extension already exists.
   */
  result =
    _gnutls_x509_crt_get_extension (cert, "2.5.29.37", 0, &old_id, NULL);

  if (result >= 0)
    {
      /* decode it.
       */
      result = asn1_der_decoding (&c2, old_id.data, old_id.size, NULL);
      _gnutls_free_datum (&old_id);

      if (result != ASN1_SUCCESS)
	{
	  gnutls_assert ();
	  asn1_delete_structure (&c2);
	  return _gnutls_asn2err (result);
	}

    }

  /* generate the extension.
   */
  /* 1. create a new element.
   */
  result = asn1_write_value (c2, "", "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  /* 2. Add the OID.
   */
  result = asn1_write_value (c2, "?LAST", oid, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_der_encode (c2, "", &der_data, 0);
  asn1_delete_structure (&c2);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_crt_set_extension (cert, "2.5.29.37",
					   &der_data, critical);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  cert->use_extensions = 1;

  return 0;

}

#endif /* ENABLE_PKI */
