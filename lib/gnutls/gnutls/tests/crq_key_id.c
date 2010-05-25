/*
 * Copyright (C) 2008, 2009, 2010 Free Software Foundation, Inc.
 *
 * Author: David Marín Carreño
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h"

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "%s |<%d>| %s", "crq_key_id", level, str);
}

void
doit (void)
{
  gnutls_x509_privkey_t pkey;
  gnutls_x509_crq_t crq;

  size_t pkey_key_id_len;
  unsigned char *pkey_key_id = NULL;

  size_t crq_key_id_len;
  unsigned char *crq_key_id = NULL;

  gnutls_pk_algorithm_t algorithm;

  int ret;

  ret = gnutls_global_init ();
  if (ret < 0)
    fail ("gnutls_global_init: %d\n", ret);

  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  gnutls_global_set_log_function (tls_log_func);
  if (debug)
    gnutls_global_set_log_level (4711);

  for (algorithm = GNUTLS_PK_RSA; algorithm <= GNUTLS_PK_DSA; algorithm++)
    {
      ret = gnutls_x509_crq_init (&crq);
      if (ret < 0)
	fail ("gnutls_x509_crq_init: %d\n", ret);

      ret = gnutls_x509_privkey_init (&pkey);
      if (ret < 0)
	{
	  fail ("gnutls_x509_privkey_init: %d\n", ret);
	}

      ret = gnutls_x509_privkey_generate (pkey, algorithm, 1024, 0);
      if (ret < 0)
	{
	  fail ("gnutls_x509_privkey_generate (rsa): %d\n", ret);
	}
      else if (debug)
	{
	  success ("Key[%s] generation ok: %d\n",
		   gnutls_pk_algorithm_get_name (algorithm), ret);
	}

      pkey_key_id_len = 0;
      ret = gnutls_x509_privkey_get_key_id (pkey, 0, pkey_key_id,
					    &pkey_key_id_len);
      if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
	{
	  fail ("gnutls_x509_privkey_get_key_id incorrectly returns %d\n",
		ret);
	}

      pkey_key_id = malloc (sizeof (unsigned char) * pkey_key_id_len);
      ret = gnutls_x509_privkey_get_key_id (pkey, 0, pkey_key_id,
					    &pkey_key_id_len);
      if (ret != GNUTLS_E_SUCCESS)
	{
	  fail ("gnutls_x509_privkey_get_key_id incorrectly returns %d\n",
		ret);
	}

      ret = gnutls_x509_crq_set_version (crq, 1);
      if (ret < 0)
	{
	  fail ("gnutls_x509_crq_set_version: %d\n", ret);
	}

      ret = gnutls_x509_crq_set_key (crq, pkey);
      if (ret < 0)
	{
	  fail ("gnutls_x509_crq_set_key: %d\n", ret);
	}

      ret = gnutls_x509_crq_set_dn_by_oid (crq, GNUTLS_OID_X520_COMMON_NAME,
					   0, "CN-Test", 7);
      if (ret < 0)
	{
	  fail ("gnutls_x509_crq_set_dn_by_oid: %d\n", ret);
	}

      ret = gnutls_x509_crq_sign (crq, pkey);
      if (ret)
	{
	  fail ("gnutls_x509_crq_sign: %d\n", ret);
	}

      crq_key_id_len = 0;
      ret = gnutls_x509_crq_get_key_id (crq, 0, crq_key_id, &crq_key_id_len);
      if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
	{
	  fail ("gnutls_x509_crq_get_key_id incorrectly returns %d\n", ret);
	}

      crq_key_id = malloc (sizeof (unsigned char) * crq_key_id_len);
      ret = gnutls_x509_crq_get_key_id (crq, 0, crq_key_id, &crq_key_id_len);
      if (ret != GNUTLS_E_SUCCESS)
	{
	  fail ("gnutls_x509_crq_get_key_id incorrectly returns %d\n", ret);
	}

      if (crq_key_id_len == pkey_key_id_len)
	{
	  ret = memcmp (crq_key_id, pkey_key_id, crq_key_id_len);
	  if (ret == 0)
	    {
	      if (debug)
		success ("Key ids are identical. OK.\n");
	    }
	  else
	    {
	      fail ("Key ids differ incorrectly: %d\n", ret);
	    }
	}
      else
	{
	  fail ("Key_id lengths differ incorrectly: %d - %d\n",
		(int) crq_key_id_len, (int) pkey_key_id_len);
	}


      if (pkey_key_id)
	{
	  free (pkey_key_id);
	  pkey_key_id = NULL;
	}

      if (crq_key_id)
	{
	  free (crq_key_id);
	  crq_key_id = NULL;
	}

      gnutls_x509_crq_deinit (crq);
      gnutls_x509_privkey_deinit (pkey);
    }

  gnutls_global_deinit ();
}
