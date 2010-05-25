/*
 * Copyright (C) 2003, 2004, 2005, 2008, 2009, 2010 Free Software
 * Foundation, Inc.
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

/* This file contains functions to handle PKCS #10 certificate
   requests, see RFC 2986.
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

/**
 * gnutls_x509_crq_init:
 * @crq: The structure to be initialized
 *
 * This function will initialize a PKCS#10 certificate request
 * structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_init (gnutls_x509_crq_t * crq)
{
  int result;

  *crq = gnutls_calloc (1, sizeof (gnutls_x509_crq_int));
  if (!*crq)
    return GNUTLS_E_MEMORY_ERROR;

  result = asn1_create_element (_gnutls_get_pkix (),
				"PKIX1.pkcs-10-CertificationRequest",
				&((*crq)->crq));
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (*crq);
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crq_deinit:
 * @crq: The structure to be initialized
 *
 * This function will deinitialize a PKCS#10 certificate request
 * structure.
 **/
void
gnutls_x509_crq_deinit (gnutls_x509_crq_t crq)
{
  if (!crq)
    return;

  if (crq->crq)
    asn1_delete_structure (&crq->crq);

  gnutls_free (crq);
}

#define PEM_CRQ "NEW CERTIFICATE REQUEST"
#define PEM_CRQ2 "CERTIFICATE REQUEST"

/**
 * gnutls_x509_crq_import:
 * @crq: The structure to store the parsed certificate request.
 * @data: The DER or PEM encoded certificate.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded certificate
 * request to a #gnutls_x509_crq_t structure.  The output will be
 * stored in @crq.
 *
 * If the Certificate is PEM encoded it should have a header of "NEW
 * CERTIFICATE REQUEST".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_import (gnutls_x509_crq_t crq,
			const gnutls_datum_t * data,
			gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  gnutls_datum_t _data;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _data.data = data->data;
  _data.size = data->size;

  /* If the Certificate is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      /* Try the first header */
      result = _gnutls_fbase64_decode (PEM_CRQ, data->data, data->size, &out);

      if (result <= 0)		/* Go for the second header */
	result =
	  _gnutls_fbase64_decode (PEM_CRQ2, data->data, data->size, &out);

      if (result <= 0)
	{
	  if (result == 0)
	    result = GNUTLS_E_INTERNAL_ERROR;
	  gnutls_assert ();
	  return result;
	}

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  result = asn1_der_decoding (&crq->crq, _data.data, _data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      result = _gnutls_asn2err (result);
      gnutls_assert ();
      goto cleanup;
    }

  result = 0;

cleanup:
  if (need_free)
    _gnutls_free_datum (&_data);
  return result;
}



/**
 * gnutls_x509_crq_get_dn:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @buf: a pointer to a structure to hold the name (may be %NULL)
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will copy the name of the Certificate request subject
 * to the provided buffer.  The name will be in the form
 * "C=xxxx,O=yyyy,CN=zzzz" as described in RFC 2253. The output string
 * @buf will be ASCII or UTF-8 encoded, depending on the certificate
 * data.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 *   long enough, and in that case the *@sizeof_buf will be updated with
 *   the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crq_get_dn (gnutls_x509_crq_t crq, char *buf, size_t * sizeof_buf)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn (crq->crq,
				"certificationRequestInfo.subject.rdnSequence",
				buf, sizeof_buf);
}

/**
 * gnutls_x509_crq_get_dn_by_oid:
 * @crq: should contain a gnutls_x509_crq_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the RDN, this specifies
 *   which to send. Use zero to get the first one.
 * @raw_flag: If non zero returns the raw DER data of the DN part.
 * @buf: a pointer to a structure to hold the name (may be %NULL)
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will extract the part of the name of the Certificate
 * request subject, specified by the given OID. The output will be
 * encoded as described in RFC2253. The output string will be ASCII
 * or UTF-8 encoded, depending on the certificate data.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * If raw flag is zero, this function will only return known OIDs as
 * text. Other OIDs will be DER encoded, as described in RFC2253 --
 * in hex format with a '\#' prefix.  You can check about known OIDs
 * using gnutls_x509_dn_oid_known().
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 *   not long enough, and in that case the *@sizeof_buf will be
 *   updated with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crq_get_dn_by_oid (gnutls_x509_crq_t crq, const char *oid,
			       int indx, unsigned int raw_flag,
			       void *buf, size_t * sizeof_buf)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn_oid
    (crq->crq,
     "certificationRequestInfo.subject.rdnSequence",
     oid, indx, raw_flag, buf, sizeof_buf);
}

/**
 * gnutls_x509_crq_get_dn_oid:
 * @crq: should contain a gnutls_x509_crq_t structure
 * @indx: Specifies which DN OID to send. Use zero to get the first one.
 * @oid: a pointer to a structure to hold the name (may be %NULL)
 * @sizeof_oid: initially holds the size of @oid
 *
 * This function will extract the requested OID of the name of the
 * certificate request subject, specified by the given index.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 *   not long enough, and in that case the *@sizeof_oid will be
 *   updated with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crq_get_dn_oid (gnutls_x509_crq_t crq,
			    int indx, void *oid, size_t * sizeof_oid)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_get_dn_oid (crq->crq,
				  "certificationRequestInfo.subject.rdnSequence",
				  indx, oid, sizeof_oid);
}

/* Parses an Attribute list in the asn1_struct, and searches for the
 * given OID. The index indicates the attribute value to be returned.
 *
 * If raw==0 only printable data are returned, or
 * GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE.
 *
 * asn1_attr_name must be a string in the form
 * "certificationRequestInfo.attributes"
 *
 */
static int
parse_attribute (ASN1_TYPE asn1_struct,
		 const char *attr_name, const char *given_oid, int indx,
		 int raw, char *buf, size_t * sizeof_buf)
{
  int k1, result;
  char tmpbuffer1[ASN1_MAX_NAME_SIZE];
  char tmpbuffer3[ASN1_MAX_NAME_SIZE];
  char value[200];
  char oid[MAX_OID_SIZE];
  int len, printable;

  k1 = 0;
  do
    {

      k1++;
      /* create a string like "attribute.?1"
       */
      if (attr_name[0] != 0)
	snprintf (tmpbuffer1, sizeof (tmpbuffer1), "%s.?%u", attr_name, k1);
      else
	snprintf (tmpbuffer1, sizeof (tmpbuffer1), "?%u", k1);

      len = sizeof (value) - 1;
      result = asn1_read_value (asn1_struct, tmpbuffer1, value, &len);

      if (result == ASN1_ELEMENT_NOT_FOUND)
	{
	  gnutls_assert ();
	  break;
	}

      if (result != ASN1_VALUE_NOT_FOUND)
	{
	  gnutls_assert ();
	  result = _gnutls_asn2err (result);
	  goto cleanup;
	}

      /* Move to the attibute type and values
       */
      /* Read the OID
       */
      _gnutls_str_cpy (tmpbuffer3, sizeof (tmpbuffer3), tmpbuffer1);
      _gnutls_str_cat (tmpbuffer3, sizeof (tmpbuffer3), ".type");

      len = sizeof (oid) - 1;
      result = asn1_read_value (asn1_struct, tmpbuffer3, oid, &len);

      if (result == ASN1_ELEMENT_NOT_FOUND)
	break;
      else if (result != ASN1_SUCCESS)
	{
	  gnutls_assert ();
	  result = _gnutls_asn2err (result);
	  goto cleanup;
	}

      if (strcmp (oid, given_oid) == 0)
	{			/* Found the OID */

	  /* Read the Value
	   */
	  snprintf (tmpbuffer3, sizeof (tmpbuffer3), "%s.values.?%u",
		    tmpbuffer1, indx + 1);

	  len = sizeof (value) - 1;
	  result = asn1_read_value (asn1_struct, tmpbuffer3, value, &len);

	  if (result != ASN1_SUCCESS)
	    {
	      gnutls_assert ();
	      result = _gnutls_asn2err (result);
	      goto cleanup;
	    }

	  if (raw == 0)
	    {
	      printable = _gnutls_x509_oid_data_printable (oid);
	      if (printable == 1)
		{
		  if ((result =
		       _gnutls_x509_oid_data2string
		       (oid, value, len, buf, sizeof_buf)) < 0)
		    {
		      gnutls_assert ();
		      goto cleanup;
		    }
		  return 0;
		}
	      else
		{
		  gnutls_assert ();
		  return GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE;
		}
	    }
	  else
	    {			/* raw!=0 */
	      if (*sizeof_buf >= (size_t) len && buf != NULL)
		{
		  *sizeof_buf = len;
		  memcpy (buf, value, len);

		  return 0;
		}
	      else
		{
		  *sizeof_buf = len;
		  return GNUTLS_E_SHORT_MEMORY_BUFFER;
		}
	    }
	}

    }
  while (1);

  gnutls_assert ();

  result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

cleanup:
  return result;
}

/**
 * gnutls_x509_crq_get_challenge_password:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @pass: will hold a zero-terminated password string
 * @sizeof_pass: Initially holds the size of @pass.
 *
 * This function will return the challenge password in the request.
 * The challenge password is intended to be used for requesting a
 * revocation of the certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_get_challenge_password (gnutls_x509_crq_t crq,
					char *pass, size_t * sizeof_pass)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return parse_attribute (crq->crq, "certificationRequestInfo.attributes",
			  "1.2.840.113549.1.9.7", 0, 0, pass, sizeof_pass);
}

/* This function will attempt to set the requested attribute in
 * the given X509v3 certificate.
 *
 * Critical will be either 0 or 1.
 */
static int
add_attribute (ASN1_TYPE asn, const char *root, const char *attribute_id,
	       const gnutls_datum_t * ext_data)
{
  int result;
  char name[ASN1_MAX_NAME_SIZE];

  snprintf (name, sizeof (name), "%s", root);

  /* Add a new attribute in the list.
   */
  result = asn1_write_value (asn, name, "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  snprintf (name, sizeof (name), "%s.?LAST.type", root);

  result = asn1_write_value (asn, name, attribute_id, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  snprintf (name, sizeof (name), "%s.?LAST.values", root);

  result = asn1_write_value (asn, name, "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  snprintf (name, sizeof (name), "%s.?LAST.values.?LAST", root);

  result = _gnutls_x509_write_value (asn, name, ext_data, 0);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/* Overwrite the given attribute (using the index)
 * index here starts from one.
 */
static int
overwrite_attribute (ASN1_TYPE asn, const char *root, unsigned int indx,
		     const gnutls_datum_t * ext_data)
{
  char name[ASN1_MAX_NAME_SIZE], name2[ASN1_MAX_NAME_SIZE];
  int result;

  snprintf (name, sizeof (name), "%s.?%u", root, indx);

  _gnutls_str_cpy (name2, sizeof (name2), name);
  _gnutls_str_cat (name2, sizeof (name2), ".values.?LAST");

  result = _gnutls_x509_write_value (asn, name2, ext_data, 0);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }


  return 0;
}

static int
set_attribute (ASN1_TYPE asn, const char *root,
	       const char *ext_id, const gnutls_datum_t * ext_data)
{
  int result;
  int k, len;
  char name[ASN1_MAX_NAME_SIZE], name2[ASN1_MAX_NAME_SIZE];
  char extnID[MAX_OID_SIZE];

  /* Find the index of the given attribute.
   */
  k = 0;
  do
    {
      k++;

      snprintf (name, sizeof (name), "%s.?%u", root, k);

      len = sizeof (extnID) - 1;
      result = asn1_read_value (asn, name, extnID, &len);

      /* move to next
       */

      if (result == ASN1_ELEMENT_NOT_FOUND)
	{
	  break;
	}

      do
	{

	  _gnutls_str_cpy (name2, sizeof (name2), name);
	  _gnutls_str_cat (name2, sizeof (name2), ".type");

	  len = sizeof (extnID) - 1;
	  result = asn1_read_value (asn, name2, extnID, &len);

	  if (result == ASN1_ELEMENT_NOT_FOUND)
	    {
	      gnutls_assert ();
	      break;
	    }
	  else if (result != ASN1_SUCCESS)
	    {
	      gnutls_assert ();
	      return _gnutls_asn2err (result);
	    }

	  /* Handle Extension
	   */
	  if (strcmp (extnID, ext_id) == 0)
	    {
	      /* attribute was found
	       */
	      return overwrite_attribute (asn, root, k, ext_data);
	    }


	}
      while (0);
    }
  while (1);

  if (result == ASN1_ELEMENT_NOT_FOUND)
    {
      return add_attribute (asn, root, ext_id, ext_data);
    }
  else
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }


  return 0;
}

/**
 * gnutls_x509_crq_set_attribute_by_oid:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @oid: holds an Object Identified in zero-terminated string
 * @buf: a pointer to a structure that holds the attribute data
 * @sizeof_buf: holds the size of @buf
 *
 * This function will set the attribute in the certificate request
 * specified by the given Object ID.  The attribute must be be DER
 * encoded.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_set_attribute_by_oid (gnutls_x509_crq_t crq,
				      const char *oid, void *buf,
				      size_t sizeof_buf)
{
  gnutls_datum_t data;

  data.data = buf;
  data.size = sizeof_buf;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return set_attribute (crq->crq, "certificationRequestInfo.attributes",
			oid, &data);
}

/**
 * gnutls_x509_crq_get_attribute_by_oid:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @oid: holds an Object Identified in zero-terminated string
 * @indx: In case multiple same OIDs exist in the attribute list, this
 *   specifies which to send, use zero to get the first one
 * @buf: a pointer to a structure to hold the attribute data (may be %NULL)
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will return the attribute in the certificate request
 * specified by the given Object ID.  The attribute will be DER
 * encoded.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_get_attribute_by_oid (gnutls_x509_crq_t crq,
				      const char *oid, int indx, void *buf,
				      size_t * sizeof_buf)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return parse_attribute (crq->crq, "certificationRequestInfo.attributes",
			  oid, indx, 1, buf, sizeof_buf);
}

/**
 * gnutls_x509_crq_set_dn_by_oid:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @oid: holds an Object Identifier in a zero-terminated string
 * @raw_flag: must be 0, or 1 if the data are DER encoded
 * @data: a pointer to the input data
 * @sizeof_data: holds the size of @data
 *
 * This function will set the part of the name of the Certificate
 * request subject, specified by the given OID.  The input string
 * should be ASCII or UTF-8 encoded.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * With this function you can only set the known OIDs.  You can test
 * for known OIDs using gnutls_x509_dn_oid_known().  For OIDs that are
 * not known (by gnutls) you should properly DER encode your data, and
 * call this function with raw_flag set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_set_dn_by_oid (gnutls_x509_crq_t crq, const char *oid,
			       unsigned int raw_flag, const void *data,
			       unsigned int sizeof_data)
{
  if (sizeof_data == 0 || data == NULL || crq == NULL)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_set_dn_oid (crq->crq,
				  "certificationRequestInfo.subject", oid,
				  raw_flag, data, sizeof_data);
}

/**
 * gnutls_x509_crq_set_version:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @version: holds the version number, for v1 Requests must be 1
 *
 * This function will set the version of the certificate request.  For
 * version 1 requests this must be one.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_set_version (gnutls_x509_crq_t crq, unsigned int version)
{
  int result;
  unsigned char null = version;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (null > 0)
    null--;

  result =
    asn1_write_value (crq->crq, "certificationRequestInfo.version", &null, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crq_get_version:
 * @crq: should contain a #gnutls_x509_crq_t structure
 *
 * This function will return the version of the specified Certificate
 * request.
 *
 * Returns: version of certificate request, or a negative value on
 *   error.
 **/
int
gnutls_x509_crq_get_version (gnutls_x509_crq_t crq)
{
  opaque version[8];
  int len, result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = sizeof (version);
  if ((result =
       asn1_read_value (crq->crq, "certificationRequestInfo.version",
			version, &len)) != ASN1_SUCCESS)
    {

      if (result == ASN1_ELEMENT_NOT_FOUND)
	return 1;		/* the DEFAULT version */
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return (int) version[0] + 1;
}

/**
 * gnutls_x509_crq_set_key:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @key: holds a private key
 *
 * This function will set the public parameters from the given private
 * key to the request.  Only RSA keys are currently supported.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_set_key (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_encode_and_copy_PKI_params
    (crq->crq,
     "certificationRequestInfo.subjectPKInfo",
     key->pk_algorithm, key->params, key->params_size);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crq_get_key_rsa_raw:
 * @crq: Holds the certificate
 * @m: will hold the modulus
 * @e: will hold the public exponent
 *
 * This function will export the RSA public key's parameters found in
 * the given structure.  The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_key_rsa_raw (gnutls_x509_crq_t crq,
				 gnutls_datum_t * m, gnutls_datum_t * e)
{
  int ret;
  bigint_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_size = MAX_PUBLIC_PARAMS_SIZE;
  int i;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = gnutls_x509_crq_get_pk_algorithm (crq, NULL);
  if (ret != GNUTLS_PK_RSA)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_x509_crq_get_mpis (crq, params, &params_size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_mpi_dprint (params[0], m);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_mpi_dprint (params[1], e);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (m);
      goto cleanup;
    }

  ret = 0;

cleanup:
  for (i = 0; i < params_size; i++)
    {
      _gnutls_mpi_release (&params[i]);
    }
  return ret;
}

/**
 * gnutls_x509_crq_set_key_rsa_raw:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @m: holds the modulus
 * @e: holds the public exponent
 *
 * This function will set the public parameters from the given private
 * key to the request. Only RSA keys are currently supported.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.6.0
 **/
int
gnutls_x509_crq_set_key_rsa_raw (gnutls_x509_crq_t crq,
				 const gnutls_datum_t * m,
				 const gnutls_datum_t * e)
{
  int result, ret;
  size_t siz = 0;
  bigint_t temp_params[RSA_PUBLIC_PARAMS];

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  memset (temp_params, 0, sizeof (temp_params));

  siz = m->size;
  if (_gnutls_mpi_scan_nz (&temp_params[0], m->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto error;
    }

  siz = e->size;
  if (_gnutls_mpi_scan_nz (&temp_params[1], e->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto error;
    }

  result = _gnutls_x509_encode_and_copy_PKI_params
    (crq->crq,
     "certificationRequestInfo.subjectPKInfo",
     GNUTLS_PK_RSA, temp_params, RSA_PUBLIC_PARAMS);

  if (result < 0)
    {
      gnutls_assert ();
      ret = result;
      goto error;
    }

  ret = 0;

error:
  _gnutls_mpi_release (&temp_params[0]);
  _gnutls_mpi_release (&temp_params[1]);
  return ret;
}

/**
 * gnutls_x509_crq_set_challenge_password:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @pass: holds a zero-terminated password
 *
 * This function will set a challenge password to be used when
 * revoking the request.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_set_challenge_password (gnutls_x509_crq_t crq,
					const char *pass)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Add the attribute.
   */
  result = asn1_write_value (crq->crq, "certificationRequestInfo.attributes",
			     "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_encode_and_write_attribute
    ("1.2.840.113549.1.9.7", crq->crq,
     "certificationRequestInfo.attributes.?LAST", pass, strlen (pass), 1);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crq_sign2:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @key: holds a private key
 * @dig: The message digest to use, i.e., %GNUTLS_DIG_SHA1
 * @flags: must be 0
 *
 * This function will sign the certificate request with a private key.
 * This must be the same key as the one used in
 * gnutls_x509_crt_set_key() since a certificate request is self
 * signed.
 *
 * This must be the last step in a certificate request generation
 * since all the previously set parameters are now signed.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
 *   %GNUTLS_E_ASN1_VALUE_NOT_FOUND is returned if you didn't set all
 *   information in the certificate request (e.g., the version using
 *   gnutls_x509_crq_set_version()).
 *
 **/
int
gnutls_x509_crq_sign2 (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key,
		       gnutls_digest_algorithm_t dig, unsigned int flags)
{
  int result;
  gnutls_datum_t signature;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Make sure version field is set. */
  if (gnutls_x509_crq_get_version (crq) == GNUTLS_E_ASN1_VALUE_NOT_FOUND)
    {
      result = gnutls_x509_crq_set_version (crq, 1);
      if (result < 0)
	{
	  gnutls_assert ();
	  return result;
	}
    }

  /* Step 1. Self sign the request.
   */
  result =
    _gnutls_x509_sign_tbs (crq->crq, "certificationRequestInfo",
			   dig, key, &signature);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  /* Step 2. write the signature (bits)
   */
  result =
    asn1_write_value (crq->crq, "signature", signature.data,
		      signature.size * 8);

  _gnutls_free_datum (&signature);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  /* Step 3. Write the signatureAlgorithm field.
   */
  result = _gnutls_x509_write_sig_params (crq->crq, "signatureAlgorithm",
					  key->pk_algorithm, dig, key->params,
					  key->params_size);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crq_sign:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @key: holds a private key
 *
 * This function is the same a gnutls_x509_crq_sign2() with no flags,
 * and SHA1 as the hash algorithm.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_sign (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key)
{
  return gnutls_x509_crq_sign2 (crq, key, GNUTLS_DIG_SHA1, 0);
}

/**
 * gnutls_x509_crq_export:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a certificate request PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the certificate request to a PEM or DER
 * encoded PKCS10 structure.
 *
 * If the buffer provided is not long enough to hold the output, then
 * %GNUTLS_E_SHORT_MEMORY_BUFFER will be returned and
 * *@output_data_size will be updated.
 *
 * If the structure is PEM encoded, it will have a header of "BEGIN
 * NEW CERTIFICATE REQUEST".
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 **/
int
gnutls_x509_crq_export (gnutls_x509_crq_t crq,
			gnutls_x509_crt_fmt_t format, void *output_data,
			size_t * output_data_size)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_export_int (crq->crq, format, PEM_CRQ,
				  output_data, output_data_size);
}

/**
 * gnutls_x509_crq_get_pk_algorithm:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @bits: if bits is non-%NULL it will hold the size of the parameters' in bits
 *
 * This function will return the public key algorithm of a PKCS#10
 * certificate request.
 *
 * If bits is non-%NULL, it should have enough size to hold the
 * parameters size in bits.  For RSA the bits returned is the modulus.
 * For DSA the bits returned are of the public exponent.
 *
 * Returns: a member of the #gnutls_pk_algorithm_t enumeration on
 *   success, or a negative value on error.
 **/
int
gnutls_x509_crq_get_pk_algorithm (gnutls_x509_crq_t crq, unsigned int *bits)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_get_pk_algorithm
    (crq->crq, "certificationRequestInfo.subjectPKInfo", bits);
  if (result < 0)
    {
      gnutls_assert ();
    }

  return result;
}

/**
 * gnutls_x509_crq_get_attribute_info:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @indx: Specifies which attribute OID to send. Use zero to get the first one.
 * @oid: a pointer to a structure to hold the OID
 * @sizeof_oid: initially holds the maximum size of @oid, on return
 *   holds actual size of @oid.
 *
 * This function will return the requested attribute OID in the
 * certificate, and the critical flag for it.  The attribute OID will
 * be stored as a string in the provided buffer.  Use
 * gnutls_x509_crq_get_attribute_data() to extract the data.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@sizeof_oid is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will be
 * returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative value in case of an error.  If your have reached the
 *   last extension available %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 *   will be returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_attribute_info (gnutls_x509_crq_t crq, int indx,
				    void *oid, size_t * sizeof_oid)
{
  int result;
  char name[ASN1_MAX_NAME_SIZE];
  int len;

  if (!crq)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (name, sizeof (name),
	    "certificationRequestInfo.attributes.?%u.type", indx + 1);

  len = *sizeof_oid;
  result = asn1_read_value (crq->crq, name, oid, &len);
  *sizeof_oid = len;

  if (result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else if (result < 0)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;

}

/**
 * gnutls_x509_crq_get_attribute_data:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @indx: Specifies which attribute OID to send. Use zero to get the first one.
 * @data: a pointer to a structure to hold the data (may be null)
 * @sizeof_data: initially holds the size of @oid
 *
 * This function will return the requested attribute data in the
 * certificate request.  The attribute data will be stored as a string in the
 * provided buffer.
 *
 * Use gnutls_x509_crq_get_attribute_info() to extract the OID.
 * Use gnutls_x509_crq_get_attribute_by_oid() instead,
 * if you want to get data indexed by the attribute OID rather than
 * sequence.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative value in case of an error.  If your have reached the
 *   last extension available %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 *   will be returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_attribute_data (gnutls_x509_crq_t crq, int indx,
				    void *data, size_t * sizeof_data)
{
  int result, len;
  char name[ASN1_MAX_NAME_SIZE];

  if (!crq)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (name, sizeof (name),
	    "certificationRequestInfo.attributes.?%u.values.?1", indx + 1);

  len = *sizeof_data;
  result = asn1_read_value (crq->crq, name, data, &len);
  *sizeof_data = len;

  if (result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else if (result < 0)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crq_get_extension_info:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @indx: Specifies which extension OID to send. Use zero to get the first one.
 * @oid: a pointer to a structure to hold the OID
 * @sizeof_oid: initially holds the maximum size of @oid, on return
 *   holds actual size of @oid.
 * @critical: output variable with critical flag, may be NULL.
 *
 * This function will return the requested extension OID in the
 * certificate, and the critical flag for it.  The extension OID will
 * be stored as a string in the provided buffer.  Use
 * gnutls_x509_crq_get_extension_data() to extract the data.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@sizeof_oid is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will be
 * returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative value in case of an error.  If your have reached the
 *   last extension available %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 *   will be returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_extension_info (gnutls_x509_crq_t crq, int indx,
				    void *oid, size_t * sizeof_oid,
				    int *critical)
{
  int result;
  char str_critical[10];
  char name[ASN1_MAX_NAME_SIZE];
  char *extensions = NULL;
  size_t extensions_size = 0;
  ASN1_TYPE c2;
  int len;

  if (!crq)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* read extensionRequest */
  result = gnutls_x509_crq_get_attribute_by_oid (crq, "1.2.840.113549.1.9.14",
						 0, NULL, &extensions_size);
  if (result == GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      extensions = gnutls_malloc (extensions_size);
      if (extensions == NULL)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}

      result = gnutls_x509_crq_get_attribute_by_oid (crq,
						     "1.2.840.113549.1.9.14",
						     0, extensions,
						     &extensions_size);
    }
  if (result < 0)
    {
      gnutls_assert ();
      goto out;
    }

  result = asn1_create_element (_gnutls_get_pkix (), "PKIX1.Extensions", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto out;
    }

  result = asn1_der_decoding (&c2, extensions, extensions_size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      result = _gnutls_asn2err (result);
      goto out;
    }

  snprintf (name, sizeof (name), "?%u.extnID", indx + 1);

  len = *sizeof_oid;
  result = asn1_read_value (c2, name, oid, &len);
  *sizeof_oid = len;

  if (result == ASN1_ELEMENT_NOT_FOUND)
    {
      asn1_delete_structure (&c2);
      result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
      goto out;
    }
  else if (result < 0)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      result = _gnutls_asn2err (result);
      goto out;
    }

  snprintf (name, sizeof (name), "?%u.critical", indx + 1);
  len = sizeof (str_critical);
  result = asn1_read_value (c2, name, str_critical, &len);

  asn1_delete_structure (&c2);

  if (result < 0)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto out;
    }

  if (critical)
    {
      if (str_critical[0] == 'T')
	*critical = 1;
      else
	*critical = 0;
    }

  result = 0;

out:
  gnutls_free (extensions);
  return result;
}

/**
 * gnutls_x509_crq_get_extension_data:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @indx: Specifies which extension OID to send. Use zero to get the first one.
 * @data: a pointer to a structure to hold the data (may be null)
 * @sizeof_data: initially holds the size of @oid
 *
 * This function will return the requested extension data in the
 * certificate.  The extension data will be stored as a string in the
 * provided buffer.
 *
 * Use gnutls_x509_crq_get_extension_info() to extract the OID and
 * critical flag.  Use gnutls_x509_crq_get_extension_by_oid() instead,
 * if you want to get data indexed by the extension OID rather than
 * sequence.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative value in case of an error.  If your have reached the
 *   last extension available %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 *   will be returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_extension_data (gnutls_x509_crq_t crq, int indx,
				    void *data, size_t * sizeof_data)
{
  int result, len;
  char name[ASN1_MAX_NAME_SIZE];
  unsigned char *extensions;
  size_t extensions_size = 0;
  ASN1_TYPE c2;

  if (!crq)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* read extensionRequest */
  result = gnutls_x509_crq_get_attribute_by_oid (crq, "1.2.840.113549.1.9.14",
						 0, NULL, &extensions_size);
  if (result != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      gnutls_assert ();
      if (result == 0)
	return GNUTLS_E_INTERNAL_ERROR;
      return result;
    }

  extensions = gnutls_malloc (extensions_size);
  if (extensions == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = gnutls_x509_crq_get_attribute_by_oid (crq, "1.2.840.113549.1.9.14",
						 0, extensions,
						 &extensions_size);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = asn1_create_element (_gnutls_get_pkix (), "PKIX1.Extensions", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (extensions);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, extensions, extensions_size, NULL);
  gnutls_free (extensions);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  snprintf (name, sizeof (name), "?%u.extnValue", indx + 1);

  len = *sizeof_data;
  result = asn1_read_value (c2, name, data, &len);
  *sizeof_data = len;

  asn1_delete_structure (&c2);

  if (result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else if (result < 0)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crq_get_key_usage:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @key_usage: where the key usage bits will be stored
 * @critical: will be non zero if the extension is marked as critical
 *
 * This function will return certificate's key usage, by reading the
 * keyUsage X.509 extension (2.5.29.15).  The key usage value will
 * ORed values of the: %GNUTLS_KEY_DIGITAL_SIGNATURE,
 * %GNUTLS_KEY_NON_REPUDIATION, %GNUTLS_KEY_KEY_ENCIPHERMENT,
 * %GNUTLS_KEY_DATA_ENCIPHERMENT, %GNUTLS_KEY_KEY_AGREEMENT,
 * %GNUTLS_KEY_KEY_CERT_SIGN, %GNUTLS_KEY_CRL_SIGN,
 * %GNUTLS_KEY_ENCIPHER_ONLY, %GNUTLS_KEY_DECIPHER_ONLY.
 *
 * Returns: the certificate key usage, or a negative value in case of
 *   parsing error.  If the certificate does not contain the keyUsage
 *   extension %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be
 *   returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_key_usage (gnutls_x509_crq_t crq,
			       unsigned int *key_usage,
			       unsigned int *critical)
{
  int result;
  uint16_t _usage;
  opaque buf[128];
  size_t buf_size = sizeof (buf);

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.15", 0,
						 buf, &buf_size, critical);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_x509_ext_extract_keyUsage (&_usage, buf, buf_size);

  *key_usage = _usage;

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crq_get_basic_constraints:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @critical: will be non zero if the extension is marked as critical
 * @ca: pointer to output integer indicating CA status, may be NULL,
 *   value is 1 if the certificate CA flag is set, 0 otherwise.
 * @pathlen: pointer to output integer indicating path length (may be
 *   NULL), non-negative values indicate a present pathLenConstraint
 *   field and the actual value, -1 indicate that the field is absent.
 *
 * This function will read the certificate's basic constraints, and
 * return the certificates CA status.  It reads the basicConstraints
 * X.509 extension (2.5.29.19).
 *
 * Return value: If the certificate is a CA a positive value will be
 *   returned, or zero if the certificate does not have CA flag set.
 *   A negative value may be returned in case of errors.  If the
 *   certificate does not contain the basicConstraints extension
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_basic_constraints (gnutls_x509_crq_t crq,
				       unsigned int *critical,
				       int *ca, int *pathlen)
{
  int result;
  int tmp_ca;
  opaque buf[256];
  size_t buf_size = sizeof (buf);

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.19", 0,
						 buf, &buf_size, critical);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result =
    _gnutls_x509_ext_extract_basicConstraints (&tmp_ca,
					       pathlen, buf, buf_size);
  if (ca)
    *ca = tmp_ca;

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return tmp_ca;
}

static int
get_subject_alt_name (gnutls_x509_crq_t crq,
		      unsigned int seq, void *ret,
		      size_t * ret_size, unsigned int *ret_type,
		      unsigned int *critical, int othername_oid)
{
  int result;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  gnutls_x509_subject_alt_name_t type;
  gnutls_datum_t dnsname = { NULL, 0 };
  size_t dns_size = 0;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  /* Extract extension.
   */
  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.17", 0,
						 NULL, &dns_size, critical);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  dnsname.size = dns_size;
  dnsname.data = gnutls_malloc (dnsname.size);
  if (dnsname.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.17", 0,
						 dnsname.data, &dns_size,
						 critical);
  if (result < 0)
    {
      gnutls_assert ();
      gnutls_free (dnsname.data);
      return result;
    }

  result = asn1_create_element
    (_gnutls_get_pkix (), "PKIX1.SubjectAltName", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (dnsname.data);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, dnsname.data, dnsname.size, NULL);
  gnutls_free (dnsname.data);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  result = _gnutls_parse_general_name (c2, "", seq, ret, ret_size,
				       ret_type, othername_oid);
  asn1_delete_structure (&c2);
  if (result < 0)
    {
      return result;
    }

  type = result;

  return type;
}

/**
 * gnutls_x509_crq_get_subject_alt_name:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @seq: specifies the sequence number of the alt name, 0 for the
 *   first one, 1 for the second etc.
 * @ret: is the place where the alternative name will be copied to
 * @ret_size: holds the size of ret.
 * @ret_type: holds the #gnutls_x509_subject_alt_name_t name type
 * @critical: will be non zero if the extension is marked as critical
 *   (may be null)
 *
 * This function will return the alternative names, contained in the
 * given certificate.  It is the same as
 * gnutls_x509_crq_get_subject_alt_name() except for the fact that it
 * will return the type of the alternative name in @ret_type even if
 * the function fails for some reason (i.e.  the buffer provided is
 * not enough).
 *
 * Returns: the alternative subject name type on success, one of the
 *   enumerated #gnutls_x509_subject_alt_name_t.  It will return
 *   %GNUTLS_E_SHORT_MEMORY_BUFFER if @ret_size is not large enough to
 *   hold the value.  In that case @ret_size will be updated with the
 *   required size.  If the certificate request does not have an
 *   Alternative name with the specified sequence number then
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_subject_alt_name (gnutls_x509_crq_t crq,
				      unsigned int seq, void *ret,
				      size_t * ret_size,
				      unsigned int *ret_type,
				      unsigned int *critical)
{
  return get_subject_alt_name (crq, seq, ret, ret_size, ret_type, critical,
			       0);
}

/**
 * gnutls_x509_crq_get_subject_alt_othername_oid:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the otherName OID will be copied to
 * @ret_size: holds the size of ret.
 *
 * This function will extract the type OID of an otherName Subject
 * Alternative Name, contained in the given certificate, and return
 * the type as an enumerated element.
 *
 * This function is only useful if
 * gnutls_x509_crq_get_subject_alt_name() returned
 * %GNUTLS_SAN_OTHERNAME.
 *
 * Returns: the alternative subject name type on success, one of the
 *   enumerated gnutls_x509_subject_alt_name_t.  For supported OIDs,
 *   it will return one of the virtual (GNUTLS_SAN_OTHERNAME_*) types,
 *   e.g. %GNUTLS_SAN_OTHERNAME_XMPP, and %GNUTLS_SAN_OTHERNAME for
 *   unknown OIDs.  It will return %GNUTLS_E_SHORT_MEMORY_BUFFER if
 *   @ret_size is not large enough to hold the value.  In that case
 *   @ret_size will be updated with the required size.  If the
 *   certificate does not have an Alternative name with the specified
 *   sequence number and with the otherName type then
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_subject_alt_othername_oid (gnutls_x509_crq_t crq,
					       unsigned int seq,
					       void *ret, size_t * ret_size)
{
  return get_subject_alt_name (crq, seq, ret, ret_size, NULL, NULL, 1);
}

/**
 * gnutls_x509_crq_get_extension_by_oid:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the extensions, this
 *   specifies which to send. Use zero to get the first one.
 * @buf: a pointer to a structure to hold the name (may be null)
 * @sizeof_buf: initially holds the size of @buf
 * @critical: will be non zero if the extension is marked as critical
 *
 * This function will return the extension specified by the OID in
 * the certificate.  The extensions will be returned as binary data
 * DER encoded, in the provided buffer.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative value in case of an error.  If the certificate does not
 *   contain the specified extension
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_extension_by_oid (gnutls_x509_crq_t crq,
				      const char *oid, int indx,
				      void *buf, size_t * sizeof_buf,
				      unsigned int *critical)
{
  int result;
  unsigned int i;
  char _oid[MAX_OID_SIZE];
  size_t oid_size;

  for (i = 0;; i++)
    {
      oid_size = sizeof (_oid);
      result =
	gnutls_x509_crq_get_extension_info (crq, i, _oid, &oid_size,
					    critical);
      if (result < 0)
	{
	  gnutls_assert ();
	  return result;
	}

      if (strcmp (oid, _oid) == 0)
	{			/* found */
	  if (indx == 0)
	    return gnutls_x509_crq_get_extension_data (crq, i, buf,
						       sizeof_buf);
	  else
	    indx--;
	}
    }


  return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

}

/**
 * gnutls_x509_crq_set_subject_alt_name:
 * @crq: a certificate request of type #gnutls_x509_crq_t
 * @nt: is one of the #gnutls_x509_subject_alt_name_t enumerations
 * @data: The data to be set
 * @data_size: The size of data to be set
 * @flags: %GNUTLS_FSAN_SET to clear previous data or
 *   %GNUTLS_FSAN_APPEND to append.
 *
 * This function will set the subject alternative name certificate
 * extension.  It can set the following types:
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
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_set_subject_alt_name (gnutls_x509_crq_t crq,
				      gnutls_x509_subject_alt_name_t nt,
				      const void *data,
				      unsigned int data_size,
				      unsigned int flags)
{
  int result = 0;
  gnutls_datum_t der_data = { NULL, 0 };
  gnutls_datum_t prev_der_data = { NULL, 0 };
  unsigned int critical = 0;
  size_t prev_data_size = 0;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Check if the extension already exists.
   */
  if (flags == GNUTLS_FSAN_APPEND)
    {
      result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.17", 0,
						     NULL, &prev_data_size,
						     &critical);
      prev_der_data.size = prev_data_size;

      switch (result)
	{
	case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
	  /* Replacing non-existing data means the same as set data. */
	  break;

	case GNUTLS_E_SUCCESS:
	  prev_der_data.data = gnutls_malloc (prev_der_data.size);
	  if (prev_der_data.data == NULL)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_MEMORY_ERROR;
	    }

	  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.17", 0,
							 prev_der_data.data,
							 &prev_data_size,
							 &critical);
	  if (result < 0)
	    {
	      gnutls_assert ();
	      gnutls_free (prev_der_data.data);
	      return result;
	    }
	  break;

	default:
	  gnutls_assert ();
	  return result;
	}
    }

  /* generate the extension.
   */
  result = _gnutls_x509_ext_gen_subject_alt_name (nt, data, data_size,
						  &prev_der_data, &der_data);
  gnutls_free (prev_der_data.data);
  if (result < 0)
    {
      gnutls_assert ();
      goto finish;
    }

  result = _gnutls_x509_crq_set_extension (crq, "2.5.29.17", &der_data,
					   critical);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;

finish:
  return result;
}

/**
 * gnutls_x509_crq_set_basic_constraints:
 * @crq: a certificate request of type #gnutls_x509_crq_t
 * @ca: true(1) or false(0) depending on the Certificate authority status.
 * @pathLenConstraint: non-negative values indicate maximum length of path,
 *   and negative values indicate that the pathLenConstraints field should
 *   not be present.
 *
 * This function will set the basicConstraints certificate extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_set_basic_constraints (gnutls_x509_crq_t crq,
				       unsigned int ca, int pathLenConstraint)
{
  int result;
  gnutls_datum_t der_data;

  if (crq == NULL)
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

  result = _gnutls_x509_crq_set_extension (crq, "2.5.29.19", &der_data, 1);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crq_set_key_usage:
 * @crq: a certificate request of type #gnutls_x509_crq_t
 * @usage: an ORed sequence of the GNUTLS_KEY_* elements.
 *
 * This function will set the keyUsage certificate extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_set_key_usage (gnutls_x509_crq_t crq, unsigned int usage)
{
  int result;
  gnutls_datum_t der_data;

  if (crq == NULL)
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

  result = _gnutls_x509_crq_set_extension (crq, "2.5.29.15", &der_data, 1);

  _gnutls_free_datum (&der_data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crq_get_key_purpose_oid:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @indx: This specifies which OID to return, use zero to get the first one
 * @oid: a pointer to a buffer to hold the OID (may be %NULL)
 * @sizeof_oid: initially holds the size of @oid
 * @critical: output variable with critical flag, may be %NULL.
 *
 * This function will extract the key purpose OIDs of the Certificate
 * specified by the given index.  These are stored in the Extended Key
 * Usage extension (2.5.29.37).  See the GNUTLS_KP_* definitions for
 * human readable names.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 *   not long enough, and in that case the *@sizeof_oid will be
 *   updated with the required size.  On success 0 is returned.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_key_purpose_oid (gnutls_x509_crq_t crq,
				     int indx, void *oid, size_t * sizeof_oid,
				     unsigned int *critical)
{
  char tmpstr[ASN1_MAX_NAME_SIZE];
  int result, len;
  gnutls_datum_t prev = { NULL, 0 };
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  size_t prev_size = 0;

  if (oid)
    memset (oid, 0, *sizeof_oid);
  else
    *sizeof_oid = 0;

  /* Extract extension.
   */
  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.37", 0,
						 NULL, &prev_size, critical);
  prev.size = prev_size;

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  prev.data = gnutls_malloc (prev.size);
  if (prev.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.37", 0,
						 prev.data, &prev_size,
						 critical);
  if (result < 0)
    {
      gnutls_assert ();
      gnutls_free (prev.data);
      return result;
    }

  result = asn1_create_element
    (_gnutls_get_pkix (), "PKIX1.ExtKeyUsageSyntax", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (prev.data);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, prev.data, prev.size, NULL);
  gnutls_free (prev.data);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  indx++;
  /* create a string like "?1"
   */
  snprintf (tmpstr, sizeof (tmpstr), "?%u", indx);

  len = *sizeof_oid;
  result = asn1_read_value (c2, tmpstr, oid, &len);

  *sizeof_oid = len;
  asn1_delete_structure (&c2);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      if (result != ASN1_MEM_ERROR)
	gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crq_set_key_purpose_oid:
 * @crq: a certificate of type #gnutls_x509_crq_t
 * @oid: a pointer to a zero-terminated string that holds the OID
 * @critical: Whether this extension will be critical or not
 *
 * This function will set the key purpose OIDs of the Certificate.
 * These are stored in the Extended Key Usage extension (2.5.29.37)
 * See the GNUTLS_KP_* definitions for human readable names.
 *
 * Subsequent calls to this function will append OIDs to the OID list.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_set_key_purpose_oid (gnutls_x509_crq_t crq,
				     const void *oid, unsigned int critical)
{
  int result;
  gnutls_datum_t prev = { NULL, 0 }, der_data;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  size_t prev_size = 0;

  /* Read existing extension, if there is one.
   */
  result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.37", 0,
						 NULL, &prev_size, &critical);
  prev.size = prev_size;

  switch (result)
    {
    case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
      /* No existing extension, that's fine. */
      break;

    case GNUTLS_E_SUCCESS:
      prev.data = gnutls_malloc (prev.size);
      if (prev.data == NULL)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}

      result = gnutls_x509_crq_get_extension_by_oid (crq, "2.5.29.37", 0,
						     prev.data, &prev_size,
						     &critical);
      if (result < 0)
	{
	  gnutls_assert ();
	  gnutls_free (prev.data);
	  return result;
	}
      break;

    default:
      gnutls_assert ();
      return result;
    }

  result = asn1_create_element (_gnutls_get_pkix (),
				"PKIX1.ExtKeyUsageSyntax", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (prev.data);
      return _gnutls_asn2err (result);
    }

  if (prev.data)
    {
      /* decode it.
       */
      result = asn1_der_decoding (&c2, prev.data, prev.size, NULL);
      gnutls_free (prev.data);
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

  result = _gnutls_x509_crq_set_extension (crq, "2.5.29.37",
					   &der_data, critical);
  _gnutls_free_datum (&der_data);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

static int
rsadsa_crq_get_key_id (gnutls_x509_crq_t crq, int pk,
		       unsigned char *output_data, size_t * output_data_size)
{
  bigint_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_size = MAX_PUBLIC_PARAMS_SIZE;
  int i, result = 0;
  gnutls_datum_t der = { NULL, 0 };
  digest_hd_st hd;

  result = _gnutls_x509_crq_get_mpis (crq, params, &params_size);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  if (pk == GNUTLS_PK_RSA)
    {
      result = _gnutls_x509_write_rsa_params (params, params_size, &der);
      if (result < 0)
	{
	  gnutls_assert ();
	  goto cleanup;
	}
    }
  else if (pk == GNUTLS_PK_DSA)
    {
      result = _gnutls_x509_write_dsa_public_key (params, params_size, &der);
      if (result < 0)
	{
	  gnutls_assert ();
	  goto cleanup;
	}
    }
  else
    return GNUTLS_E_INTERNAL_ERROR;

  result = _gnutls_hash_init (&hd, GNUTLS_MAC_SHA1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  _gnutls_hash (&hd, der.data, der.size);

  _gnutls_hash_deinit (&hd, output_data);
  *output_data_size = 20;

  result = 0;

cleanup:

  _gnutls_free_datum (&der);

  /* release all allocated MPIs
   */
  for (i = 0; i < params_size; i++)
    {
      _gnutls_mpi_release (&params[i]);
    }
  return result;
}

/**
 * gnutls_x509_crq_get_key_id:
 * @crq: a certificate of type #gnutls_x509_crq_t
 * @flags: should be 0 for now
 * @output_data: will contain the key ID
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will return a unique ID the depends on the public key
 * parameters.  This ID can be used in checking whether a certificate
 * corresponds to the given private key.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.  The output will normally be a SHA-1 hash output,
 * which is 20 bytes.
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crq_get_key_id (gnutls_x509_crq_t crq, unsigned int flags,
			    unsigned char *output_data,
			    size_t * output_data_size)
{
  int pk, result = 0;
  gnutls_datum_t pubkey;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (*output_data_size < 20)
    {
      *output_data_size = 20;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  pk = gnutls_x509_crq_get_pk_algorithm (crq, NULL);
  if (pk < 0)
    {
      gnutls_assert ();
      return pk;
    }

  if (pk == GNUTLS_PK_RSA || pk == GNUTLS_PK_DSA)
    {
      /* This is for compatibility with what GnuTLS has printed for
         RSA/DSA before the code below was added.  The code below is
         applicable to all types, and it would probably be a better
         idea to use it for RSA/DSA too, but doing so would break
         backwards compatibility.  */
      return rsadsa_crq_get_key_id (crq, pk, output_data, output_data_size);
    }

  pubkey.size = 0;
  result =
    asn1_der_coding (crq->crq, "certificationRequestInfo.subjectPKInfo", NULL,
		     &pubkey.size, NULL);
  if (result != ASN1_MEM_ERROR)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  pubkey.data = gnutls_malloc (pubkey.size);
  if (pubkey.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result =
    asn1_der_coding (crq->crq, "certificationRequestInfo.subjectPKInfo",
		     pubkey.data, &pubkey.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (pubkey.data);
      return _gnutls_asn2err (result);
    }

  result = gnutls_fingerprint (GNUTLS_DIG_SHA1, &pubkey,
			       output_data, output_data_size);

  gnutls_free (pubkey.data);

  return result;
}


#endif /* ENABLE_PKI */
