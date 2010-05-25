/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
 * Free Software Foundation, Inc.
 *
 * Author: Timo Schulz, Nikos Mavrogiannopoulos
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

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_mpi.h"
#include "gnutls_num.h"
#include "gnutls_cert.h"
#include "gnutls_datum.h"
#include "gnutls_global.h"
#include "gnutls_openpgp.h"
#include "read-file.h"
#include <gnutls_str.h>
#include <gnutls_sig.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

#define datum_append(x, y, z) _gnutls_datum_append_m (x, y, z, gnutls_realloc)

/* Map an OpenCDK error type to a GnuTLS error type. */
int
_gnutls_map_cdk_rc (int rc)
{
  switch (rc)
    {
    case CDK_Success:
      return 0;
    case CDK_Too_Short:
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    case CDK_General_Error:
      return GNUTLS_E_INTERNAL_ERROR;
    case CDK_File_Error:
      return GNUTLS_E_FILE_ERROR;
    case CDK_MPI_Error:
      return GNUTLS_E_MPI_SCAN_FAILED;
    case CDK_Error_No_Key:
      return GNUTLS_E_OPENPGP_GETKEY_FAILED;
    case CDK_Armor_Error:
      return GNUTLS_E_BASE64_DECODING_ERROR;
    case CDK_Inv_Value:
      return GNUTLS_E_INVALID_REQUEST;
    default:
      return GNUTLS_E_INTERNAL_ERROR;
    }
}

/*-
 * _gnutls_openpgp_raw_crt_to_gcert - Converts raw OpenPGP data to GnuTLS certs
 * @cert: the certificate to store the data.
 * @raw: the buffer which contains the whole OpenPGP key packets.
 *
 * The RFC2440 (OpenPGP Message Format) data is converted to a GnuTLS
 * specific certificate.
 -*/
int
_gnutls_openpgp_raw_crt_to_gcert (gnutls_cert * gcert,
				  const gnutls_datum_t * raw,
				  const gnutls_openpgp_keyid_t keyid)
{
  gnutls_openpgp_crt_t pcrt;
  int ret;

  ret = gnutls_openpgp_crt_init (&pcrt);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = gnutls_openpgp_crt_import (pcrt, raw, GNUTLS_OPENPGP_FMT_RAW);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_crt_deinit (pcrt);
      return ret;
    }

  if (keyid != NULL)
    {
      ret = gnutls_openpgp_crt_set_preferred_key_id (pcrt, keyid);
      if (ret < 0)
	{
	  gnutls_assert ();
	  gnutls_openpgp_crt_deinit (pcrt);
	  return ret;
	}
    }

  ret = _gnutls_openpgp_crt_to_gcert (gcert, pcrt);
  gnutls_openpgp_crt_deinit (pcrt);

  return ret;
}

/**
 * gnutls_certificate_set_openpgp_key:
 * @res: is a #gnutls_certificate_credentials_t structure.
 * @key: contains an openpgp public key
 * @pkey: is an openpgp private key
 *
 * This function sets a certificate/private key pair in the
 * gnutls_certificate_credentials_t structure.  This function may be
 * called more than once (in case multiple keys/certificates exist
 * for the server).
 *
 * With this function the subkeys of the certificate are not used.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (zero) is returned,
 *   otherwise an error code is returned.
 **/
int
gnutls_certificate_set_openpgp_key (gnutls_certificate_credentials_t res,
				    gnutls_openpgp_crt_t crt,
				    gnutls_openpgp_privkey_t pkey)
{
  int ret;

  /* this should be first */

  res->pkey = gnutls_realloc_fast (res->pkey,
				   (res->ncerts + 1) *
				   sizeof (gnutls_privkey));
  if (res->pkey == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = _gnutls_openpgp_privkey_to_gkey (&res->pkey[res->ncerts], pkey);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  res->cert_list = gnutls_realloc_fast (res->cert_list,
					(1 +
					 res->ncerts) *
					sizeof (gnutls_cert *));
  if (res->cert_list == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list_length = gnutls_realloc_fast (res->cert_list_length,
					       (1 +
						res->ncerts) * sizeof (int));
  if (res->cert_list_length == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list[res->ncerts] = gnutls_calloc (1, sizeof (gnutls_cert));
  if (res->cert_list[res->ncerts] == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list_length[res->ncerts] = 1;

  ret = _gnutls_openpgp_crt_to_gcert (res->cert_list[res->ncerts], crt);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  res->ncerts++;

  /* FIXME: Check if the keys match. */

  return 0;
}

/*-
 * gnutls_openpgp_get_key:
 * @key: the destination context to save the key.
 * @keyring: the datum struct that contains all keyring information.
 * @attr: The attribute (keyid, fingerprint, ...).
 * @by: What attribute is used.
 *
 * This function can be used to retrieve keys by different pattern
 * from a binary or a file keyring.
 -*/
int
gnutls_openpgp_get_key (gnutls_datum_t * key,
			gnutls_openpgp_keyring_t keyring, key_attr_t by,
			opaque * pattern)
{
  cdk_kbnode_t knode = NULL;
  unsigned long keyid[2];
  unsigned char *buf;
  void *desc;
  size_t len;
  int rc = 0;
  cdk_keydb_search_t st;

  if (!key || !keyring || by == KEY_ATTR_NONE)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  memset (key, 0, sizeof *key);

  if (by == KEY_ATTR_SHORT_KEYID)
    {
      keyid[0] = _gnutls_read_uint32 (pattern);
      desc = keyid;
    }
  else if (by == KEY_ATTR_KEYID)
    {
      keyid[0] = _gnutls_read_uint32 (pattern);
      keyid[1] = _gnutls_read_uint32 (pattern + 4);
      desc = keyid;
    }
  else
    desc = pattern;
  rc = cdk_keydb_search_start (&st, keyring->db, by, desc);
  if (!rc)
    rc = cdk_keydb_search (st, keyring->db, &knode);

  cdk_keydb_search_release (st);

  if (rc)
    {
      rc = _gnutls_map_cdk_rc (rc);
      goto leave;
    }

  if (!cdk_kbnode_find (knode, CDK_PKT_PUBLIC_KEY))
    {
      rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
      goto leave;
    }

  /* We let the function allocate the buffer to avoid
     to call the function twice. */
  rc = cdk_kbnode_write_to_mem_alloc (knode, &buf, &len);
  if (!rc)
    datum_append (key, buf, len);
  gnutls_free (buf);

leave:
  cdk_kbnode_release (knode);
  return rc;
}

/**
 * gnutls_certificate_set_openpgp_key_mem:
 * @res: the destination context to save the data.
 * @cert: the datum that contains the public key.
 * @key: the datum that contains the secret key.
 * @format: the format of the keys
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS credential 
 * structure. The files should contain non encrypted keys.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_certificate_set_openpgp_key_mem (gnutls_certificate_credentials_t res,
					const gnutls_datum_t * cert,
					const gnutls_datum_t * key,
					gnutls_openpgp_crt_fmt_t format)
{
  return gnutls_certificate_set_openpgp_key_mem2 (res, cert, key,
						  NULL, format);
}

/**
 * gnutls_certificate_set_openpgp_key_file:
 * @res: the destination context to save the data.
 * @certfile: the file that contains the public key.
 * @keyfile: the file that contains the secret key.
 * @format: the format of the keys
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS
 * credentials structure.  The files should only contain one key which
 * is not encrypted.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_certificate_set_openpgp_key_file (gnutls_certificate_credentials_t res,
					 const char *certfile,
					 const char *keyfile,
					 gnutls_openpgp_crt_fmt_t format)
{
  return gnutls_certificate_set_openpgp_key_file2 (res, certfile,
						   keyfile, NULL, format);
}

static int
get_keyid (gnutls_openpgp_keyid_t keyid, const char *str)
{
  size_t keyid_size = sizeof (keyid);

  if (strlen (str) != 16)
    {
      _gnutls_debug_log
	("The OpenPGP subkey ID has to be 16 hexadecimal characters.\n");
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (_gnutls_hex2bin (str, strlen (str), keyid, &keyid_size) < 0)
    {
      _gnutls_debug_log ("Error converting hex string: %s.\n", str);
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;
}

/**
 * gnutls_certificate_set_openpgp_key_mem2:
 * @res: the destination context to save the data.
 * @cert: the datum that contains the public key.
 * @key: the datum that contains the secret key.
 * @subkey_id: a hex encoded subkey id
 * @format: the format of the keys
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS
 * credentials structure.  The files should only contain one key which
 * is not encrypted.
 *
 * The special keyword "auto" is also accepted as @subkey_id.  In that
 * case the gnutls_openpgp_crt_get_auth_subkey() will be used to
 * retrieve the subkey.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.4.0
 **/
int
gnutls_certificate_set_openpgp_key_mem2 (gnutls_certificate_credentials_t res,
					 const gnutls_datum_t * cert,
					 const gnutls_datum_t * key,
					 const char *subkey_id,
					 gnutls_openpgp_crt_fmt_t format)
{
  gnutls_openpgp_privkey_t pkey;
  gnutls_openpgp_crt_t crt;
  int ret;

  ret = gnutls_openpgp_privkey_init (&pkey);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = gnutls_openpgp_privkey_import (pkey, key, format, NULL, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_privkey_deinit (pkey);
      return ret;
    }

  ret = gnutls_openpgp_crt_init (&crt);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_privkey_deinit (pkey);
      return ret;
    }

  ret = gnutls_openpgp_crt_import (crt, cert, format);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_privkey_deinit (pkey);
      gnutls_openpgp_crt_deinit (crt);
      return ret;
    }

  if (subkey_id != NULL)
    {
      gnutls_openpgp_keyid_t keyid;

      if (strcasecmp (subkey_id, "auto") == 0)
	ret = gnutls_openpgp_crt_get_auth_subkey (crt, keyid, 1);
      else
	ret = get_keyid (keyid, subkey_id);

      if (ret >= 0)
	{
	  ret = gnutls_openpgp_crt_set_preferred_key_id (crt, keyid);
	  if (ret >= 0)
	    ret = gnutls_openpgp_privkey_set_preferred_key_id (pkey, keyid);
	}

      if (ret < 0)
	{
	  gnutls_assert ();
	  gnutls_openpgp_privkey_deinit (pkey);
	  gnutls_openpgp_crt_deinit (crt);
	  return ret;
	}
    }

  ret = gnutls_certificate_set_openpgp_key (res, crt, pkey);

  gnutls_openpgp_privkey_deinit (pkey);
  gnutls_openpgp_crt_deinit (crt);

  return ret;
}

/**
 * gnutls_certificate_set_openpgp_key_file2:
 * @res: the destination context to save the data.
 * @certfile: the file that contains the public key.
 * @keyfile: the file that contains the secret key.
 * @subkey_id: a hex encoded subkey id
 * @format: the format of the keys
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS credential 
 * structure. The files should contain non encrypted keys.
 *
 * The special keyword "auto" is also accepted as @subkey_id.  In that
 * case the gnutls_openpgp_crt_get_auth_subkey() will be used to
 * retrieve the subkey.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.4.0
 **/
int
gnutls_certificate_set_openpgp_key_file2 (gnutls_certificate_credentials_t
					  res, const char *certfile,
					  const char *keyfile,
					  const char *subkey_id,
					  gnutls_openpgp_crt_fmt_t format)
{
  struct stat statbuf;
  gnutls_datum_t key, cert;
  int rc;
  size_t size;

  if (!res || !keyfile || !certfile)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (stat (certfile, &statbuf) || stat (keyfile, &statbuf))
    {
      gnutls_assert ();
      return GNUTLS_E_FILE_ERROR;
    }

  cert.data = read_binary_file (certfile, &size);
  cert.size = (unsigned int) size;
  if (cert.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_FILE_ERROR;
    }

  key.data = read_binary_file (keyfile, &size);
  key.size = (unsigned int) size;
  if (key.data == NULL)
    {
      gnutls_assert ();
      free (cert.data);
      return GNUTLS_E_FILE_ERROR;
    }

  rc =
    gnutls_certificate_set_openpgp_key_mem2 (res, &cert, &key, subkey_id,
					     format);

  free (cert.data);
  free (key.data);

  if (rc < 0)
    {
      gnutls_assert ();
      return rc;
    }

  return 0;
}


int
gnutls_openpgp_count_key_names (const gnutls_datum_t * cert)
{
  cdk_kbnode_t knode, p, ctx;
  cdk_packet_t pkt;
  int nuids;

  if (cert == NULL)
    {
      gnutls_assert ();
      return 0;
    }

  if (cdk_kbnode_read_from_mem (&knode, cert->data, cert->size))
    {
      gnutls_assert ();
      return 0;
    }

  ctx = NULL;
  for (nuids = 0;;)
    {
      p = cdk_kbnode_walk (knode, &ctx, 0);
      if (!p)
	break;
      pkt = cdk_kbnode_get_packet (p);
      if (pkt->pkttype == CDK_PKT_USER_ID)
	nuids++;
    }

  cdk_kbnode_release (knode);
  return nuids;
}

/**
 * gnutls_certificate_set_openpgp_keyring_file:
 * @c: A certificate credentials structure
 * @file: filename of the keyring.
 * @format: format of keyring.
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenPGP functions. For example to find a key when it
 * is needed for an operations. The keyring will also be used at the
 * verification functions.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_certificate_set_openpgp_keyring_file (gnutls_certificate_credentials_t
					     c, const char *file,
					     gnutls_openpgp_crt_fmt_t format)
{
  gnutls_datum_t ring;
  size_t size;
  int rc;

  if (!c || !file)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ring.data = read_binary_file (file, &size);
  ring.size = (unsigned int) size;
  if (ring.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_FILE_ERROR;
    }

  rc =
    gnutls_certificate_set_openpgp_keyring_mem (c, ring.data, ring.size,
						format);

  free (ring.data);

  return rc;
}

/**
 * gnutls_certificate_set_openpgp_keyring_mem:
 * @c: A certificate credentials structure
 * @data: buffer with keyring data.
 * @dlen: length of data buffer.
 * @format: the format of the keyring
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenPGP functions. For example to find a key when it
 * is needed for an operations. The keyring will also be used at the
 * verification functions.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_certificate_set_openpgp_keyring_mem (gnutls_certificate_credentials_t
					    c, const opaque * data,
					    size_t dlen,
					    gnutls_openpgp_crt_fmt_t format)
{
  gnutls_datum_t ddata;
  int rc;

  ddata.data = (void *) data;
  ddata.size = dlen;

  if (!c || !data || !dlen)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  rc = gnutls_openpgp_keyring_init (&c->keyring);
  if (rc < 0)
    {
      gnutls_assert ();
      return rc;
    }

  rc = gnutls_openpgp_keyring_import (c->keyring, &ddata, format);
  if (rc < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_keyring_deinit (c->keyring);
      return rc;
    }

  return 0;
}

/*-
 * _gnutls_openpgp_request_key - Receives a key from a database, key server etc
 * @ret - a pointer to gnutls_datum_t structure.
 * @cred - a gnutls_certificate_credentials_t structure.
 * @key_fingerprint - The keyFingerprint
 * @key_fingerprint_size - the size of the fingerprint
 *
 * Retrieves a key from a local database, keyring, or a key server. The
 * return value is locally allocated.
 *
 -*/
int
_gnutls_openpgp_request_key (gnutls_session_t session, gnutls_datum_t * ret,
			     const gnutls_certificate_credentials_t cred,
			     opaque * key_fpr, int key_fpr_size)
{
  int rc = 0;

  if (!ret || !cred || !key_fpr)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (key_fpr_size != 16 && key_fpr_size != 20)
    return GNUTLS_E_HASH_FAILED;	/* only MD5 and SHA1 are supported */

  rc = gnutls_openpgp_get_key (ret, cred->keyring, KEY_ATTR_FPR, key_fpr);

  if (rc >= 0)			/* key was found */
    {
      rc = 0;
      goto error;
    }
  else
    rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;

  /* If the callback function was set, then try this one. */
  if (session->internals.openpgp_recv_key_func != NULL)
    {
      rc = session->internals.openpgp_recv_key_func (session,
						     key_fpr,
						     key_fpr_size, ret);
      if (rc < 0)
	{
	  gnutls_assert ();
	  rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
	  goto error;
	}
    }

error:

  return rc;
}

/**
 * gnutls_openpgp_set_recv_key_function:
 * @session: a TLS session
 * @func: the callback
 *
 * This funtion will set a key retrieval function for OpenPGP keys. This
 * callback is only useful in server side, and will be used if the peer
 * sent a key fingerprint instead of a full key.
 *
 **/
void
gnutls_openpgp_set_recv_key_function (gnutls_session_t session,
				      gnutls_openpgp_recv_key_func func)
{
  session->internals.openpgp_recv_key_func = func;
}


/* Copies a gnutls_openpgp_privkey_t to a gnutls_privkey structure. */
int
_gnutls_openpgp_privkey_to_gkey (gnutls_privkey * dest,
				 gnutls_openpgp_privkey_t src)
{
  int ret = 0;
  gnutls_openpgp_keyid_t keyid;
  char err_buf[33];

  if (dest == NULL || src == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  dest->params_size = MAX_PRIV_PARAMS_SIZE;

  ret = gnutls_openpgp_privkey_get_preferred_key_id (src, keyid);

  if (ret == 0)
    {
      int idx;
      uint32_t kid32[2];

      _gnutls_debug_log
	("Importing Openpgp key and using openpgp sub key: %s\n",
	 _gnutls_bin2hex (keyid, sizeof (keyid), err_buf, sizeof (err_buf)));

      KEYID_IMPORT (kid32, keyid);

      idx = gnutls_openpgp_privkey_get_subkey_idx (src, keyid);
      if (idx < 0)
	{
	  gnutls_assert ();
	  return idx;
	}

      dest->pk_algorithm =
	gnutls_openpgp_privkey_get_subkey_pk_algorithm (src, idx, NULL);

      ret =
	_gnutls_openpgp_privkey_get_mpis (src, kid32, dest->params,
					  &dest->params_size);
    }
  else
    {
      _gnutls_debug_log
	("Importing Openpgp key and using main openpgp key.\n");

      dest->pk_algorithm =
	gnutls_openpgp_privkey_get_pk_algorithm (src, NULL);
      ret =
	_gnutls_openpgp_privkey_get_mpis (src, NULL, dest->params,
					  &dest->params_size);
    }


  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;

}

/* Converts a parsed gnutls_openpgp_crt_t to a gnutls_cert structure.
 */
int
_gnutls_openpgp_crt_to_gcert (gnutls_cert * gcert, gnutls_openpgp_crt_t cert)
{
  int ret;
  gnutls_openpgp_keyid_t keyid;
  char err_buf[33];

  memset (gcert, 0, sizeof (gnutls_cert));
  gcert->cert_type = GNUTLS_CRT_OPENPGP;
  gcert->sign_algo = GNUTLS_SIGN_UNKNOWN;	/* N/A here */

  gcert->version = gnutls_openpgp_crt_get_version (cert);
  gcert->params_size = MAX_PUBLIC_PARAMS_SIZE;

  ret = gnutls_openpgp_crt_get_preferred_key_id (cert, keyid);

  if (ret == 0)
    {
      int idx;
      uint32_t kid32[2];

      _gnutls_debug_log
	("Importing Openpgp cert and using openpgp sub key: %s\n",
	 _gnutls_bin2hex (keyid, sizeof (keyid), err_buf, sizeof (err_buf)));

      KEYID_IMPORT (kid32, keyid);

      idx = gnutls_openpgp_crt_get_subkey_idx (cert, keyid);
      if (idx < 0)
	{
	  gnutls_assert ();
	  return idx;
	}

      gcert->subject_pk_algorithm =
	gnutls_openpgp_crt_get_subkey_pk_algorithm (cert, idx, NULL);

      gnutls_openpgp_crt_get_subkey_usage (cert, idx, &gcert->key_usage);
      gcert->use_subkey = 1;

      memcpy (gcert->subkey_id, keyid, sizeof (keyid));

      ret =
	_gnutls_openpgp_crt_get_mpis (cert, kid32, gcert->params,
				      &gcert->params_size);
    }
  else
    {
      _gnutls_debug_log
	("Importing Openpgp cert and using main openpgp key\n");
      gcert->subject_pk_algorithm =
	gnutls_openpgp_crt_get_pk_algorithm (cert, NULL);

      gnutls_openpgp_crt_get_key_usage (cert, &gcert->key_usage);
      ret =
	_gnutls_openpgp_crt_get_mpis (cert, NULL, gcert->params,
				      &gcert->params_size);
      gcert->use_subkey = 0;
    }

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  {				/* copy the raw certificate */
#define SMALL_RAW 512
    opaque *raw;
    size_t raw_size = SMALL_RAW;

    /* initially allocate a bogus size, just in case the certificate
     * fits in it. That way we minimize the DER encodings performed.
     */
    raw = gnutls_malloc (raw_size);
    if (raw == NULL)
      {
	gnutls_assert ();
	return GNUTLS_E_MEMORY_ERROR;
      }

    ret =
      gnutls_openpgp_crt_export (cert, GNUTLS_OPENPGP_FMT_RAW, raw,
				 &raw_size);
    if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
      {
	gnutls_assert ();
	gnutls_free (raw);
	return ret;
      }

    if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
      {
	raw = gnutls_realloc (raw, raw_size);
	if (raw == NULL)
	  {
	    gnutls_assert ();
	    return GNUTLS_E_MEMORY_ERROR;
	  }

	ret =
	  gnutls_openpgp_crt_export (cert, GNUTLS_OPENPGP_FMT_RAW, raw,
				     &raw_size);
	if (ret < 0)
	  {
	    gnutls_assert ();
	    gnutls_free (raw);
	    return ret;
	  }
      }

    gcert->raw.data = raw;
    gcert->raw.size = raw_size;
  }

  return 0;

}

/**
 * gnutls_openpgp_privkey_sign_hash:
 * @key: Holds the key
 * @hash: holds the data to be signed
 * @signature: will contain newly allocated signature
 *
 * This function will sign the given hash using the private key.  You
 * should use gnutls_openpgp_privkey_set_preferred_key_id() before
 * calling this function to set the subkey to use.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_openpgp_privkey_sign_hash (gnutls_openpgp_privkey_t key,
				  const gnutls_datum_t * hash,
				  gnutls_datum_t * signature)
{
  int result, i;
  bigint_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_size = MAX_PUBLIC_PARAMS_SIZE;
  int pk_algorithm;
  gnutls_openpgp_keyid_t keyid;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = gnutls_openpgp_privkey_get_preferred_key_id (key, keyid);
  if (result == 0)
    {
      uint32_t kid[2];

      KEYID_IMPORT (kid, keyid);
      result = _gnutls_openpgp_privkey_get_mpis (key, kid,
						 params, &params_size);
    }
  else
    {
      result = _gnutls_openpgp_privkey_get_mpis (key, NULL,
						 params, &params_size);
    }

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  pk_algorithm = gnutls_openpgp_privkey_get_pk_algorithm (key, NULL);

  result = _gnutls_sign (pk_algorithm, params, params_size, hash, signature);

  for (i = 0; i < params_size; i++)
    _gnutls_mpi_release (&params[i]);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}
