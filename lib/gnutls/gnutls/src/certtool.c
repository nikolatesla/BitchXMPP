/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/x509.h>
#include <gnutls/openpgp.h>
#include <gnutls/pkcs12.h>

#include <gcrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <error.h>

/* Gnulib portability files. */
#include <read-file.h>
#include <progname.h>
#include <version-etc.h>

#include <certtool-cfg.h>
#include "certtool-gaa.h"
#include "certtool-common.h"

static void print_crl_info (gnutls_x509_crl_t crl, FILE * out);
int generate_prime (int bits, int how);
void pkcs7_info (void);
void crq_info (void);
void smime_to_pkcs7 (void);
void pkcs12_info (void);
void generate_pkcs12 (void);
void generate_pkcs8 (void);
void verify_chain (void);
void verify_crl (void);
void pgp_privkey_info (void);
void pgp_ring_info (void);
gnutls_x509_privkey_t load_private_key (int mand);
gnutls_x509_crq_t load_request (void);
gnutls_x509_privkey_t load_ca_private_key (void);
gnutls_x509_crt_t load_ca_cert (void);
gnutls_x509_crt_t load_cert (int mand);
void certificate_info (void);
void pgp_certificate_info (void);
void crl_info (void);
void privkey_info (void);
static void print_certificate_info (gnutls_x509_crt_t crt, FILE * out,
				    unsigned int);
static void gaa_parser (int argc, char **argv);
void generate_self_signed (void);
void generate_request (void);
gnutls_x509_crt_t *load_cert_list (int mand, size_t * size);

static void print_hex_datum (gnutls_datum_t * dat);


static gaainfo info;
FILE *outfile;
FILE *infile;
gnutls_digest_algorithm_t dig = GNUTLS_DIG_SHA1;

/* non interactive operation if set
 */
int batch;

unsigned char buffer[64 * 1024];
const int buffer_size = sizeof (buffer);

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

int
main (int argc, char **argv)
{
  set_program_name (argv[0]);
  cfg_init ();
  gaa_parser (argc, argv);

  return 0;
}

static const char *
raw_to_string (const unsigned char *raw, size_t raw_size)
{
  static char buf[1024];
  size_t i;
  if (raw_size == 0)
    return NULL;

  if (raw_size * 3 + 1 >= sizeof (buf))
    return NULL;

  for (i = 0; i < raw_size; i++)
    {
      sprintf (&(buf[i * 3]), "%02X%s", raw[i],
	       (i == raw_size - 1) ? "" : ":");
    }
  buf[sizeof (buf) - 1] = '\0';

  return buf;
}

static void
print_dsa_pkey (gnutls_datum_t * x, gnutls_datum_t * y, gnutls_datum_t * p,
		gnutls_datum_t * q, gnutls_datum_t * g)
{
  fprintf (outfile, "private key:");
  print_hex_datum (x);
  fprintf (outfile, "public key:");
  print_hex_datum (y);
  fprintf (outfile, "p:");
  print_hex_datum (p);
  fprintf (outfile, "q:");
  print_hex_datum (q);
  fprintf (outfile, "g:");
  print_hex_datum (g);
}

static void
print_rsa_pkey (gnutls_datum_t * m, gnutls_datum_t * e, gnutls_datum_t * d,
		gnutls_datum_t * p, gnutls_datum_t * q, gnutls_datum_t * u)
{
  fprintf (outfile, "modulus:");
  print_hex_datum (m);
  fprintf (outfile, "public exponent:");
  print_hex_datum (e);
  fprintf (outfile, "private exponent:");
  print_hex_datum (d);
  fprintf (outfile, "prime1:");
  print_hex_datum (p);
  fprintf (outfile, "prime2:");
  print_hex_datum (q);
  fprintf (outfile, "coefficient:");
  print_hex_datum (u);
}

static gnutls_x509_privkey_t
generate_private_key_int (void)
{
  gnutls_x509_privkey_t key;
  int ret, key_type;

  if (info.dsa)
    {
      key_type = GNUTLS_PK_DSA;
      /* FIXME: Remove me once we depend on 1.3.x */
      if (info.bits > 1024 && gcry_check_version ("1.3.1") == NULL)
	info.bits = 1024;
    }
  else
    key_type = GNUTLS_PK_RSA;

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "privkey_init: %s", gnutls_strerror (ret));

  fprintf (stderr, "Generating a %d bit %s private key...\n", info.bits,
	   gnutls_pk_algorithm_get_name (key_type));

  if (info.quick_random == 0)
    fprintf (stderr,
	     "This might take several minutes depending on availability of randomness"
	     " in /dev/random.\n");

  ret = gnutls_x509_privkey_generate (key, key_type, info.bits, 0);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "privkey_generate: %s", gnutls_strerror (ret));

  return key;
}

static void
print_private_key (gnutls_x509_privkey_t key)
{
  int ret;
  size_t size;

  if (!key)
    return;

  if (!info.pkcs8)
    {
      size = sizeof (buffer);
      ret = gnutls_x509_privkey_export (key, info.outcert_format,
					buffer, &size);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "privkey_export: %s", gnutls_strerror (ret));
    }
  else
    {
      unsigned int flags;
      const char *pass;

      if (info.export)
	flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
      else
	flags = GNUTLS_PKCS_USE_PKCS12_3DES;

      if ((pass = get_confirmed_pass (true)) == NULL || *pass == '\0')
	flags = GNUTLS_PKCS_PLAIN;

      size = sizeof (buffer);
      ret =
	gnutls_x509_privkey_export_pkcs8 (key, info.outcert_format, pass,
					  flags, buffer, &size);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "privkey_export_pkcs8: %s",
	       gnutls_strerror (ret));
    }

  fwrite (buffer, 1, size, outfile);
}

static void
generate_private_key (void)
{
  gnutls_x509_privkey_t key;

  key = generate_private_key_int ();

  print_private_key (key);

  gnutls_x509_privkey_deinit (key);
}


static gnutls_x509_crt_t
generate_certificate (gnutls_x509_privkey_t * ret_key,
		      gnutls_x509_crt_t ca_crt, int proxy)
{
  gnutls_x509_crt_t crt;
  gnutls_x509_privkey_t key = NULL;
  size_t size;
  int ret;
  int client;
  int days, result, ca_status = 0, path_len;
  int vers;
  unsigned int usage = 0, server;
  gnutls_x509_crq_t crq;	/* request */

  ret = gnutls_x509_crt_init (&crt);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crt_init: %s", gnutls_strerror (ret));

  crq = load_request ();

  if (crq == NULL)
    {

      key = load_private_key (1);

      if (!batch)
	fprintf (stderr,
		 "Please enter the details of the certificate's distinguished name. "
		 "Just press enter to ignore a field.\n");

      /* set the DN.
       */
      if (proxy)
	{
	  result = gnutls_x509_crt_set_proxy_dn (crt, ca_crt, 0, NULL, 0);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "set_proxy_dn: %s",
		   gnutls_strerror (result));

	  get_cn_crt_set (crt);
	}
      else
	{
	  get_country_crt_set (crt);
	  get_organization_crt_set (crt);
	  get_unit_crt_set (crt);
	  get_locality_crt_set (crt);
	  get_state_crt_set (crt);
	  get_cn_crt_set (crt);
	  get_uid_crt_set (crt);
	  get_oid_crt_set (crt);
	  get_key_purpose_set (crt);

	  if (!batch)
	    fprintf (stderr,
		     "This field should not be used in new certificates.\n");

	  get_pkcs9_email_crt_set (crt);
	}

      result = gnutls_x509_crt_set_key (crt, key);
      if (result < 0)
	error (EXIT_FAILURE, 0, "set_key: %s", gnutls_strerror (result));
    }
  else
    {
      result = gnutls_x509_crt_set_crq (crt, crq);
      if (result < 0)
	error (EXIT_FAILURE, 0, "set_crq: %s", gnutls_strerror (result));
    }


  {
    int serial = get_serial ();
    char bin_serial[5];

    bin_serial[4] = serial & 0xff;
    bin_serial[3] = (serial >> 8) & 0xff;
    bin_serial[2] = (serial >> 16) & 0xff;
    bin_serial[1] = (serial >> 24) & 0xff;
    bin_serial[0] = 0;

    result = gnutls_x509_crt_set_serial (crt, bin_serial, 5);
    if (result < 0)
      error (EXIT_FAILURE, 0, "serial: %s", gnutls_strerror (result));
  }

  if (!batch)
    fprintf (stderr, "\n\nActivation/Expiration time.\n");

  gnutls_x509_crt_set_activation_time (crt, time (NULL));

  days = get_days ();

  result =
    gnutls_x509_crt_set_expiration_time (crt,
					 time (NULL) + days * 24 * 60 * 60);
  if (result < 0)
    error (EXIT_FAILURE, 0, "set_expiration: %s", gnutls_strerror (result));

  if (!batch)
    fprintf (stderr, "\n\nExtensions.\n");

  /* do not allow extensions on a v1 certificate */
  if (crq && get_crq_extensions_status () != 0)
    {
      result = gnutls_x509_crt_set_crq_extensions (crt, crq);
      if (result < 0)
	error (EXIT_FAILURE, 0, "set_crq: %s", gnutls_strerror (result));
    }

  /* append additional extensions */
  if (info.v1_cert == 0)
    {

      if (proxy)
	{
	  const char *policylanguage;
	  char *policy;
	  size_t policylen;
	  int proxypathlen = get_path_len ();

	  if (!batch)
	    {
	      printf ("1.3.6.1.5.5.7.21.1 ::= id-ppl-inheritALL\n");
	      printf ("1.3.6.1.5.5.7.21.2 ::= id-ppl-independent\n");
	    }

	  policylanguage = get_proxy_policy (&policy, &policylen);

	  result =
	    gnutls_x509_crt_set_proxy (crt, proxypathlen, policylanguage,
				       policy, policylen);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "set_proxy: %s",
		   gnutls_strerror (result));
	}

      if (!proxy)
	ca_status = get_ca_status ();
      if (ca_status)
	path_len = get_path_len ();
      else
	path_len = -1;

      result =
	gnutls_x509_crt_set_basic_constraints (crt, ca_status, path_len);
      if (result < 0)
	error (EXIT_FAILURE, 0, "basic_constraints: %s",
	       gnutls_strerror (result));

      client = get_tls_client_status ();
      if (client != 0)
	{
	  result = gnutls_x509_crt_set_key_purpose_oid (crt,
							GNUTLS_KP_TLS_WWW_CLIENT,
							0);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "key_kp: %s", gnutls_strerror (result));
	}

      server = get_tls_server_status ();
      if (server != 0)
	{
	  result = 0;

	  if (!proxy)
	    {
	      get_dns_name_set (TYPE_CRT, crt);
	      get_ip_addr_set (TYPE_CRT, crt);
	    }

	  result =
	    gnutls_x509_crt_set_key_purpose_oid (crt,
						 GNUTLS_KP_TLS_WWW_SERVER, 0);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "key_kp: %s", gnutls_strerror (result));
	}
      else if (!proxy)
	{
	  get_email_set (TYPE_CRT, crt);
	}

      if (!ca_status || server)
	{
	  int pk;


	  pk = gnutls_x509_crt_get_pk_algorithm (crt, NULL);

	  if (pk != GNUTLS_PK_DSA)
	    {			/* DSA keys can only sign.
				 */
	      result = get_sign_status (server);
	      if (result)
		usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;

	      result = get_encrypt_status (server);
	      if (result)
		usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
	    }
	  else
	    usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;
	}


      if (ca_status)
	{
	  result = get_cert_sign_status ();
	  if (result)
	    usage |= GNUTLS_KEY_KEY_CERT_SIGN;

	  result = get_crl_sign_status ();
	  if (result)
	    usage |= GNUTLS_KEY_CRL_SIGN;

	  result = get_code_sign_status ();
	  if (result)
	    {
	      result =
		gnutls_x509_crt_set_key_purpose_oid (crt,
						     GNUTLS_KP_CODE_SIGNING,
						     0);
	      if (result < 0)
		error (EXIT_FAILURE, 0, "key_kp: %s",
		       gnutls_strerror (result));
	    }

	  result = get_ocsp_sign_status ();
	  if (result)
	    {
	      result =
		gnutls_x509_crt_set_key_purpose_oid (crt,
						     GNUTLS_KP_OCSP_SIGNING,
						     0);
	      if (result < 0)
		error (EXIT_FAILURE, 0, "key_kp: %s",
		       gnutls_strerror (result));
	    }

	  result = get_time_stamp_status ();
	  if (result)
	    {
	      result =
		gnutls_x509_crt_set_key_purpose_oid (crt,
						     GNUTLS_KP_TIME_STAMPING,
						     0);
	      if (result < 0)
		error (EXIT_FAILURE, 0, "key_kp: %s",
		       gnutls_strerror (result));
	    }
	}

      if (usage != 0)
	{
	  result = gnutls_x509_crt_set_key_usage (crt, usage);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "key_usage: %s",
		   gnutls_strerror (result));
	}

      /* Subject Key ID.
       */
      size = sizeof (buffer);
      result = gnutls_x509_crt_get_key_id (crt, 0, buffer, &size);
      if (result >= 0)
	{
	  result = gnutls_x509_crt_set_subject_key_id (crt, buffer, size);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "set_subject_key_id: %s",
		   gnutls_strerror (result));
	}

      /* Authority Key ID.
       */
      if (ca_crt != NULL)
	{
	  size = sizeof (buffer);
	  result = gnutls_x509_crt_get_subject_key_id (ca_crt, buffer,
						       &size, NULL);
	  if (result < 0)
	    {
	      size = sizeof (buffer);
	      result = gnutls_x509_crt_get_key_id (ca_crt, 0, buffer, &size);
	    }
	  if (result >= 0)
	    {
	      result =
		gnutls_x509_crt_set_authority_key_id (crt, buffer, size);
	      if (result < 0)
		error (EXIT_FAILURE, 0, "set_authority_key_id: %s",
		       gnutls_strerror (result));
	    }
	}
    }

  /* Version.
   */
  if (info.v1_cert != 0)
    vers = 1;
  else
    vers = 3;
  result = gnutls_x509_crt_set_version (crt, vers);
  if (result < 0)
    error (EXIT_FAILURE, 0, "set_version: %s", gnutls_strerror (result));

  *ret_key = key;
  return crt;

}

static gnutls_x509_crl_t
generate_crl (gnutls_x509_crt_t ca_crt)
{
  gnutls_x509_crl_t crl;
  gnutls_x509_crt_t *crts;
  size_t size;
  int days, result;
  unsigned int i;
  time_t now = time (NULL);

  result = gnutls_x509_crl_init (&crl);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crl_init: %s", gnutls_strerror (result));

  crts = load_cert_list (0, &size);

  for (i = 0; i < size; i++)
    {
      result = gnutls_x509_crl_set_crt (crl, crts[i], now);
      if (result < 0)
	error (EXIT_FAILURE, 0, "crl_set_crt: %s", gnutls_strerror (result));
    }

  result = gnutls_x509_crl_set_this_update (crl, now);
  if (result < 0)
    error (EXIT_FAILURE, 0, "this_update: %s", gnutls_strerror (result));

  fprintf (stderr, "Update times.\n");
  days = get_crl_next_update ();

  result = gnutls_x509_crl_set_next_update (crl, now + days * 24 * 60 * 60);
  if (result < 0)
    error (EXIT_FAILURE, 0, "next_update: %s", gnutls_strerror (result));

  result = gnutls_x509_crl_set_version (crl, 2);
  if (result < 0)
    error (EXIT_FAILURE, 0, "set_version: %s", gnutls_strerror (result));

  /* Authority Key ID.
   */
  if (ca_crt != NULL)
    {
      size = sizeof (buffer);
      result = gnutls_x509_crt_get_subject_key_id (ca_crt, buffer,
						   &size, NULL);
      if (result < 0)
	{
	  size = sizeof (buffer);
	  result = gnutls_x509_crt_get_key_id (ca_crt, 0, buffer, &size);
	}
      if (result >= 0)
	{
	  result = gnutls_x509_crl_set_authority_key_id (crl, buffer, size);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "set_authority_key_id: %s",
		   gnutls_strerror (result));
	}
    }

  {
    unsigned int number = get_crl_number ();
    char bin_number[5];

    bin_number[4] = number & 0xff;
    bin_number[3] = (number >> 8) & 0xff;
    bin_number[2] = (number >> 16) & 0xff;
    bin_number[1] = (number >> 24) & 0xff;
    bin_number[0] = 0;

    result = gnutls_x509_crl_set_number (crl, bin_number, 5);
    if (result < 0)
      error (EXIT_FAILURE, 0, "set_number: %s", gnutls_strerror (result));
  }

  return crl;
}

void
generate_self_signed (void)
{
  gnutls_x509_crt_t crt;
  gnutls_x509_privkey_t key;
  size_t size;
  int result;
  const char *uri;

  fprintf (stderr, "Generating a self signed certificate...\n");

  crt = generate_certificate (&key, NULL, 0);

  if (!key)
    key = load_private_key (1);

  uri = get_crl_dist_point_url ();
  if (uri)
    {
      result = gnutls_x509_crt_set_crl_dist_points (crt, GNUTLS_SAN_URI,
						    uri,
						    0 /* all reasons */ );
      if (result < 0)
	error (EXIT_FAILURE, 0, "crl_dist_points: %s",
	       gnutls_strerror (result));
    }

  print_certificate_info (crt, stderr, 0);

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, crt, key, dig, 0);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_sign: %s", gnutls_strerror (result));

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, info.outcert_format, buffer, &size);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_export: %s", gnutls_strerror (result));

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
  gnutls_x509_privkey_deinit (key);
}

static void
generate_signed_certificate (void)
{
  gnutls_x509_crt_t crt;
  gnutls_x509_privkey_t key;
  size_t size;
  int result;
  gnutls_x509_privkey_t ca_key;
  gnutls_x509_crt_t ca_crt;

  fprintf (stderr, "Generating a signed certificate...\n");

  ca_key = load_ca_private_key ();
  ca_crt = load_ca_cert ();

  crt = generate_certificate (&key, ca_crt, 0);

  /* Copy the CRL distribution points.
   */
  gnutls_x509_crt_cpy_crl_dist_points (crt, ca_crt);
  /* it doesn't matter if we couldn't copy the CRL dist points.
   */

  print_certificate_info (crt, stderr, 0);

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, ca_crt, ca_key, dig, 0);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_sign: %s", gnutls_strerror (result));

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, info.outcert_format, buffer, &size);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_export: %s", gnutls_strerror (result));

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
  gnutls_x509_privkey_deinit (key);
}

static void
generate_proxy_certificate (void)
{
  gnutls_x509_crt_t crt, eecrt;
  gnutls_x509_privkey_t key, eekey;
  size_t size;
  int result;

  fprintf (stderr, "Generating a proxy certificate...\n");

  eekey = load_ca_private_key ();
  eecrt = load_cert (1);

  crt = generate_certificate (&key, eecrt, 1);

  print_certificate_info (crt, stderr, 0);

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, eecrt, eekey, dig, 0);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_sign: %s", gnutls_strerror (result));

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, info.outcert_format, buffer, &size);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_export: %s", gnutls_strerror (result));

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
  gnutls_x509_privkey_deinit (key);
}

static void
generate_signed_crl (void)
{
  gnutls_x509_crl_t crl;
  int result;
  gnutls_x509_privkey_t ca_key;
  gnutls_x509_crt_t ca_crt;

  fprintf (stderr, "Generating a signed CRL...\n");

  ca_key = load_ca_private_key ();
  ca_crt = load_ca_cert ();
  crl = generate_crl (ca_crt);

  fprintf (stderr, "\n");

  result = gnutls_x509_crl_sign (crl, ca_crt, ca_key);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crl_sign: %s", gnutls_strerror (result));

  print_crl_info (crl, stderr);

  gnutls_x509_crl_deinit (crl);
}

static void
update_signed_certificate (void)
{
  gnutls_x509_crt_t crt;
  size_t size;
  int result;
  gnutls_x509_privkey_t ca_key;
  gnutls_x509_crt_t ca_crt;
  int days;
  time_t tim = time (NULL);

  fprintf (stderr, "Generating a signed certificate...\n");

  ca_key = load_ca_private_key ();
  ca_crt = load_ca_cert ();
  crt = load_cert (1);

  fprintf (stderr, "Activation/Expiration time.\n");
  gnutls_x509_crt_set_activation_time (crt, tim);

  days = get_days ();

  result =
    gnutls_x509_crt_set_expiration_time (crt, tim + days * 24 * 60 * 60);
  if (result < 0)
    error (EXIT_FAILURE, 0, "set_expiration: %s", gnutls_strerror (result));

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, ca_crt, ca_key, dig, 0);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_sign: %s", gnutls_strerror (result));

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, info.outcert_format, buffer, &size);
  if (result < 0)
    error (EXIT_FAILURE, 0, "crt_export: %s", gnutls_strerror (result));

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
}

static FILE *
safe_open_rw (const char *file)
{
  mode_t omask = 0;
  FILE *fh;

  if (info.privkey_op != 0)
    {
      omask = umask (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    }

  fh = fopen (file, "wb");

  if (info.privkey_op != 0)
    {
      umask (omask);
    }

  return fh;
}

void
gaa_parser (int argc, char **argv)
{
  int ret;

  if (gaa (argc, argv, &info) != -1)
    {
      fprintf (stderr, "Try `%s --help' for more information.\n",
	       program_name);
      exit (1);
    }

  if (info.outfile)
    {
      outfile = safe_open_rw (info.outfile);
      if (outfile == NULL)
	error (EXIT_FAILURE, errno, "%s", info.outfile);
    }
  else
    outfile = stdout;

  if (info.infile)
    {
      infile = fopen (info.infile, "rb");
      if (infile == NULL)
	error (EXIT_FAILURE, errno, "%s", info.infile);
    }
  else
    infile = stdin;

  if (info.incert_format)
    info.incert_format = GNUTLS_X509_FMT_DER;
  else
    info.incert_format = GNUTLS_X509_FMT_PEM;

  if (info.outcert_format)
    info.outcert_format = GNUTLS_X509_FMT_DER;
  else
    info.outcert_format = GNUTLS_X509_FMT_PEM;

  if (info.hash != NULL)
    {
      if (strcasecmp (info.hash, "md5") == 0)
	{
	  fprintf (stderr,
		   "Warning: MD5 is broken, and should not be used any more for digital signatures.\n");
	  dig = GNUTLS_DIG_MD5;
	}
      else if (strcasecmp (info.hash, "sha1") == 0)
	dig = GNUTLS_DIG_SHA1;
      else if (strcasecmp (info.hash, "sha256") == 0)
	dig = GNUTLS_DIG_SHA256;
      else if (strcasecmp (info.hash, "sha384") == 0)
	dig = GNUTLS_DIG_SHA384;
      else if (strcasecmp (info.hash, "sha512") == 0)
	dig = GNUTLS_DIG_SHA512;
      else if (strcasecmp (info.hash, "rmd160") == 0)
	dig = GNUTLS_DIG_RMD160;
      else
	error (EXIT_FAILURE, 0, "invalid hash: %s", info.hash);
    }

  batch = 0;
  if (info.template)
    {
      batch = 1;
      template_parse (info.template);
    }

#ifdef gcry_fips_mode_active
  /* Libgcrypt manual says that gcry_version_check must be called
     before calling gcry_fips_mode_active. */
  gcry_check_version (NULL);
  if (gcry_fips_mode_active ())
    {
      ret = gnutls_register_md5_handler ();
      if (ret)
	fprintf (stderr, "gnutls_register_md5_handler: %s\n",
		 gnutls_strerror (ret));
    }
#endif

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (info.debug);
  if (info.debug > 1)
    printf ("Setting log level to %d\n", info.debug);

  if ((ret = gnutls_global_init ()) < 0)
    error (EXIT_FAILURE, 0, "global_init: %s", gnutls_strerror (ret));

  if ((ret = gnutls_global_init_extra ()) < 0)
    error (EXIT_FAILURE, 0, "global_init_extra: %s", gnutls_strerror (ret));

  if (info.quick_random != 0)
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  switch (info.action)
    {
    case ACTION_SELF_SIGNED:
      generate_self_signed ();
      break;
    case ACTION_GENERATE_PRIVKEY:
      generate_private_key ();
      break;
    case ACTION_CERT_INFO:
      certificate_info ();
      break;
    case ACTION_GENERATE_REQUEST:
      generate_request ();
      break;
    case ACTION_GENERATE_CERTIFICATE:
      generate_signed_certificate ();
      break;
    case ACTION_VERIFY_CHAIN:
      verify_chain ();
      break;
    case ACTION_PRIVKEY_INFO:
      privkey_info ();
      break;
    case ACTION_UPDATE_CERTIFICATE:
      update_signed_certificate ();
      break;
    case ACTION_TO_PKCS12:
      generate_pkcs12 ();
      break;
    case ACTION_PKCS12_INFO:
      pkcs12_info ();
      break;
    case ACTION_GENERATE_DH:
      generate_prime (info.bits, 1);
      break;
    case ACTION_GET_DH:
      generate_prime (info.bits, 0);
      break;
    case ACTION_CRL_INFO:
      crl_info ();
      break;
    case ACTION_P7_INFO:
      pkcs7_info ();
      break;
    case ACTION_GENERATE_CRL:
      generate_signed_crl ();
      break;
    case ACTION_VERIFY_CRL:
      verify_crl ();
      break;
    case ACTION_SMIME_TO_P7:
      smime_to_pkcs7 ();
      break;
    case ACTION_GENERATE_PROXY:
      generate_proxy_certificate ();
      break;
    case ACTION_GENERATE_PKCS8:
      generate_pkcs8 ();
      break;
#ifdef ENABLE_OPENPGP
    case ACTION_PGP_INFO:
      pgp_certificate_info ();
      break;
    case ACTION_PGP_PRIVKEY_INFO:
      pgp_privkey_info ();
      break;
    case ACTION_RING_INFO:
      pgp_ring_info ();
      break;
#endif
    case ACTION_REQUEST:
      crq_info ();
      break;
    default:
      gaa_help ();
      exit (0);
    }
  fclose (outfile);
}

#define MAX_CRTS 500
void
certificate_info (void)
{
  gnutls_x509_crt_t crt[MAX_CRTS];
  size_t size;
  int ret, i, count;
  gnutls_datum_t pem;
  unsigned int crt_num;

  pem.data = fread_file (infile, &size);
  pem.size = size;

  crt_num = MAX_CRTS;
  ret =
    gnutls_x509_crt_list_import (crt, &crt_num, &pem, info.incert_format,
				 GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
  if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      error (0, 0, "too many certificates (%d); "
	     "will only read the first %d", crt_num, MAX_CRTS);
      crt_num = MAX_CRTS;
      ret = gnutls_x509_crt_list_import (crt, &crt_num, &pem,
					 info.incert_format, 0);
    }
  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  free (pem.data);

  count = ret;

  if (count > 1 && info.outcert_format == GNUTLS_X509_FMT_DER)
    {
      error (0, 0, "cannot output multiple certificates in DER format; "
	     "using PEM instead");
      info.outcert_format = GNUTLS_X509_FMT_PEM;
    }

  for (i = 0; i < count; i++)
    {
      if (i > 0)
	fprintf (outfile, "\n");

      if (info.outcert_format == GNUTLS_X509_FMT_PEM)
	print_certificate_info (crt[i], outfile, 1);

      size = sizeof (buffer);
      ret = gnutls_x509_crt_export (crt[i], info.outcert_format, buffer,
				    &size);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));
      fwrite (buffer, 1, size, outfile);

      gnutls_x509_crt_deinit (crt[i]);
    }
}

#ifdef ENABLE_OPENPGP

void
pgp_certificate_info (void)
{
  gnutls_openpgp_crt_t crt;
  size_t size;
  int ret;
  gnutls_datum_t pem, out_data;
  unsigned int verify_status;

  pem.data = fread_file (infile, &size);
  pem.size = size;

  ret = gnutls_openpgp_crt_init (&crt);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "openpgp_crt_init: %s", gnutls_strerror (ret));

  ret = gnutls_openpgp_crt_import (crt, &pem, info.incert_format);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  free (pem.data);

  if (info.outcert_format == GNUTLS_OPENPGP_FMT_BASE64)
    {
      ret = gnutls_openpgp_crt_print (crt, 0, &out_data);

      if (ret == 0)
	{
	  fprintf (outfile, "%s\n", out_data.data);
	  gnutls_free (out_data.data);
	}
    }


  ret = gnutls_openpgp_crt_verify_self (crt, 0, &verify_status);
  if (ret < 0)
    {
      error (EXIT_FAILURE, 0, "verify signature error: %s",
	     gnutls_strerror (ret));
    }

  if (verify_status & GNUTLS_CERT_INVALID)
    {
      fprintf (outfile, "Self Signature verification: failed\n\n");
    }
  else
    {
      fprintf (outfile, "Self Signature verification: ok (%x)\n\n",
	       verify_status);
    }

  size = sizeof (buffer);
  ret = gnutls_openpgp_crt_export (crt, info.outcert_format, buffer, &size);
  if (ret < 0)
    {
      error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));
      fwrite (buffer, 1, size, outfile);
    }

  fprintf (outfile, "%s\n", buffer);
  gnutls_openpgp_crt_deinit (crt);
}

void
pgp_privkey_info (void)
{
  gnutls_openpgp_privkey_t key;
  gnutls_openpgp_keyid_t keyid;
  size_t size;
  int ret, i, subkeys;
  gnutls_datum_t pem;
  const char *cprint;

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  gnutls_openpgp_privkey_init (&key);

  pem.data = buffer;
  pem.size = size;

  ret = gnutls_openpgp_privkey_import (key, &pem, info.incert_format,
				       NULL, 0);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  /* Public key algorithm
   */
  subkeys = gnutls_openpgp_privkey_get_subkey_count (key);
  if (subkeys < 0)
    error (EXIT_FAILURE, 0, "privkey_get_subkey_count: %s",
	   gnutls_strerror (subkeys));

  for (i = -1; i < subkeys; i++)
    {

      if (i != -1)
	fprintf (outfile, "Subkey[%d]:\n", i);

      fprintf (outfile, "Public Key Info:\n");

      if (i == -1)
	ret = gnutls_openpgp_privkey_get_pk_algorithm (key, NULL);
      else
	ret = gnutls_openpgp_privkey_get_subkey_pk_algorithm (key, i, NULL);

      fprintf (outfile, "\tPublic Key Algorithm: ");
      cprint = gnutls_pk_algorithm_get_name (ret);
      fprintf (outfile, "%s\n", cprint ? cprint : "Unknown");

      /* Print the raw public and private keys
       */

      if (ret == GNUTLS_PK_RSA)
	{
	  gnutls_datum_t m, e, d, p, q, u;

	  if (i == -1)
	    ret =
	      gnutls_openpgp_privkey_export_rsa_raw (key, &m, &e, &d, &p,
						     &q, &u);
	  else
	    ret =
	      gnutls_openpgp_privkey_export_subkey_rsa_raw (key, i, &m,
							    &e, &d, &p,
							    &q, &u);
	  if (ret < 0)
	    fprintf (stderr, "Error in key RSA data export: %s\n",
		     gnutls_strerror (ret));
	  else
	    print_rsa_pkey (&m, &e, &d, &p, &q, &u);

	}
      else if (ret == GNUTLS_PK_DSA)
	{
	  gnutls_datum_t p, q, g, y, x;

	  if (i == -1)
	    ret =
	      gnutls_openpgp_privkey_export_dsa_raw (key, &p, &q, &g, &y, &x);
	  else
	    ret =
	      gnutls_openpgp_privkey_export_subkey_dsa_raw (key, i, &p,
							    &q, &g, &y, &x);
	  if (ret < 0)
	    fprintf (stderr, "Error in key DSA data export: %s\n",
		     gnutls_strerror (ret));
	  else
	    print_dsa_pkey (&x, &y, &p, &q, &g);
	}

      fprintf (outfile, "\n");

      size = sizeof (buffer);
      if (i == -1)
	ret = gnutls_openpgp_privkey_get_key_id (key, keyid);
      else
	ret = gnutls_openpgp_privkey_get_subkey_id (key, i, keyid);

      if (ret < 0)
	{
	  fprintf (stderr, "Error in key id calculation: %s\n",
		   gnutls_strerror (ret));
	}
      else
	{
	  fprintf (outfile, "Public Key ID: %s\n", raw_to_string (keyid, 8));
	}

    }

  size = sizeof (buffer);
  ret = gnutls_openpgp_privkey_export (key, GNUTLS_OPENPGP_FMT_BASE64,
				       NULL, 0, buffer, &size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));

  fprintf (outfile, "\n%s\n", buffer);

  gnutls_openpgp_privkey_deinit (key);
}

void
pgp_ring_info (void)
{
  gnutls_openpgp_keyring_t ring;
  gnutls_openpgp_crt_t crt;
  size_t size;
  int ret, i, count;
  gnutls_datum_t pem;

  pem.data = fread_file (infile, &size);
  pem.size = size;

  ret = gnutls_openpgp_keyring_init (&ring);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "openpgp_keyring_init: %s",
	   gnutls_strerror (ret));

  ret = gnutls_openpgp_keyring_import (ring, &pem, info.incert_format);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  free (pem.data);

  count = gnutls_openpgp_keyring_get_crt_count (ring);
  if (count > 0)
    fprintf (outfile, "Keyring contains %d OpenPGP certificates\n\n", count);
  else
    error (EXIT_FAILURE, 0, "keyring error: %s", gnutls_strerror (count));

  for (i = 0; i < count; i++)
    {
      ret = gnutls_openpgp_keyring_get_crt (ring, i, &crt);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));

      size = sizeof (buffer);
      ret = gnutls_openpgp_crt_export (crt, info.outcert_format,
				       buffer, &size);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));

      fwrite (buffer, 1, size, outfile);
      fprintf (outfile, "\n\n");

      gnutls_openpgp_crt_deinit (crt);


    }

  gnutls_openpgp_keyring_deinit (ring);
}


#endif

static void
print_hex_datum (gnutls_datum_t * dat)
{
  unsigned int j;
#define SPACE "\t"
  fprintf (outfile, "\n" SPACE);
  for (j = 0; j < dat->size; j++)
    {
      fprintf (outfile, "%.2x:", (unsigned char) dat->data[j]);
      if ((j + 1) % 15 == 0)
	fprintf (outfile, "\n" SPACE);
    }
  fprintf (outfile, "\n");
}


static void
print_certificate_info (gnutls_x509_crt_t crt, FILE * out, unsigned int all)
{
  gnutls_datum_t cinfo;
  int ret;

  if (all)
    ret = gnutls_x509_crt_print (crt, GNUTLS_CRT_PRINT_FULL, &cinfo);
  else
    ret = gnutls_x509_crt_print (crt, GNUTLS_CRT_PRINT_UNSIGNED_FULL, &cinfo);
  if (ret == 0)
    {
      fprintf (out, "%s\n", cinfo.data);
      gnutls_free (cinfo.data);
    }

  if (out == stderr && batch == 0)	/* interactive */
    if (read_yesno ("Is the above information ok? (Y/N): ") == 0)
      {
	exit (1);
      }
}

static void
print_crl_info (gnutls_x509_crl_t crl, FILE * out)
{
  gnutls_datum_t cinfo;
  int ret;
  size_t size;

  ret = gnutls_x509_crl_print (crl, GNUTLS_CRT_PRINT_FULL, &cinfo);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crl_print: %s", gnutls_strerror (ret));

  fprintf (out, "%s\n", cinfo.data);

  gnutls_free (cinfo.data);

  size = sizeof (buffer);
  ret = gnutls_x509_crl_export (crl, GNUTLS_X509_FMT_PEM, buffer, &size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crl_export: %s", gnutls_strerror (ret));

  fwrite (buffer, 1, size, outfile);
}

void
crl_info (void)
{
  gnutls_x509_crl_t crl;
  int ret;
  size_t size;
  gnutls_datum_t pem;

  ret = gnutls_x509_crl_init (&crl);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crl_init: %s", gnutls_strerror (ret));

  pem.data = fread_file (infile, &size);
  pem.size = size;

  if (!pem.data)
    error (EXIT_FAILURE, errno, "%s", info.infile ? info.infile :
	   "standard input");

  ret = gnutls_x509_crl_import (crl, &pem, info.incert_format);

  free (pem.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  print_crl_info (crl, outfile);

  gnutls_x509_crl_deinit (crl);
}

static void
print_crq_info (gnutls_x509_crq_t crq, FILE * out)
{
  gnutls_datum_t cinfo;
  int ret;
  size_t size;

  if (info.outcert_format == GNUTLS_X509_FMT_PEM)
    {
      ret = gnutls_x509_crq_print (crq, GNUTLS_CRT_PRINT_FULL, &cinfo);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "crq_print: %s", gnutls_strerror (ret));

      fprintf (out, "%s\n", cinfo.data);

      gnutls_free (cinfo.data);
    }

  size = sizeof (buffer);
  ret = gnutls_x509_crq_export (crq, info.outcert_format, buffer, &size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crq_export: %s", gnutls_strerror (ret));

  fwrite (buffer, 1, size, outfile);
}

void
crq_info (void)
{
  gnutls_x509_crq_t crq;
  int ret;
  size_t size;
  gnutls_datum_t pem;

  ret = gnutls_x509_crq_init (&crq);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crq_init: %s", gnutls_strerror (ret));

  pem.data = fread_file (infile, &size);
  pem.size = size;

  if (!pem.data)
    error (EXIT_FAILURE, errno, "%s", info.infile ? info.infile :
	   "standard input");

  ret = gnutls_x509_crq_import (crq, &pem, info.incert_format);

  free (pem.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  print_crq_info (crq, outfile);

  gnutls_x509_crq_deinit (crq);
}

void
privkey_info (void)
{
  gnutls_x509_privkey_t key;
  size_t size;
  int ret;
  gnutls_datum_t pem;
  const char *cprint;
  const char *pass;

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  gnutls_x509_privkey_init (&key);

  pem.data = buffer;
  pem.size = size;

  ret = 0;
  if (!info.pkcs8)
    ret = gnutls_x509_privkey_import (key, &pem, info.incert_format);

  /* If we failed to import the certificate previously try PKCS #8 */
  if (info.pkcs8 || ret == GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR)
    {
      /* first try to import the key without asking any password */
      ret = gnutls_x509_privkey_import_pkcs8 (key, &pem,
					      info.incert_format,
					      NULL, GNUTLS_PKCS_PLAIN);
      if (ret < 0)
	{
	  if (info.pass)
	    pass = info.pass;
	  else
	    pass = get_pass ();
	  ret = gnutls_x509_privkey_import_pkcs8 (key, &pem,
						  info.incert_format,
						  pass, 0);
	}
    }
  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  /* Public key algorithm
   */
  fprintf (outfile, "Public Key Info:\n");
  ret = gnutls_x509_privkey_get_pk_algorithm (key);
  fprintf (outfile, "\tPublic Key Algorithm: ");

  cprint = gnutls_pk_algorithm_get_name (ret);
  fprintf (outfile, "%s\n", cprint ? cprint : "Unknown");

  /* Print the raw public and private keys
   */
  if (ret == GNUTLS_PK_RSA)
    {
      gnutls_datum_t m, e, d, p, q, u;

      ret = gnutls_x509_privkey_export_rsa_raw (key, &m, &e, &d, &p, &q, &u);
      if (ret < 0)
	fprintf (stderr, "Error in key RSA data export: %s\n",
		 gnutls_strerror (ret));
      else
	{
	  print_rsa_pkey (&m, &e, &d, &p, &q, &u);
	  gnutls_free (m.data);
	  gnutls_free (e.data);
	  gnutls_free (d.data);
	  gnutls_free (p.data);
	  gnutls_free (q.data);
	  gnutls_free (u.data);
	}
    }
  else if (ret == GNUTLS_PK_DSA)
    {
      gnutls_datum_t p, q, g, y, x;

      ret = gnutls_x509_privkey_export_dsa_raw (key, &p, &q, &g, &y, &x);
      if (ret < 0)
	fprintf (stderr, "Error in key DSA data export: %s\n",
		 gnutls_strerror (ret));
      else
	{
	  print_dsa_pkey (&x, &y, &p, &q, &g);
	  gnutls_free (x.data);
	  gnutls_free (y.data);
	  gnutls_free (p.data);
	  gnutls_free (q.data);
	  gnutls_free (g.data);
	}
    }

  fprintf (outfile, "\n");

  size = sizeof (buffer);
  if ((ret = gnutls_x509_privkey_get_key_id (key, 0, buffer, &size)) < 0)
    {
      fprintf (stderr, "Error in key id calculation: %s\n",
	       gnutls_strerror (ret));
    }
  else
    {
      fprintf (outfile, "Public Key ID: %s\n", raw_to_string (buffer, size));
    }

  if (info.fix_key != 0)
    {
      ret = gnutls_x509_privkey_fix (key);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "privkey_fix: %s", gnutls_strerror (ret));
    }

  size = sizeof (buffer);
  ret = gnutls_x509_privkey_export (key, GNUTLS_X509_FMT_PEM, buffer, &size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));

  fprintf (outfile, "\n%s\n", buffer);

  gnutls_x509_privkey_deinit (key);
}


/* Load the private key.
 * @mand should be non zero if it is required to read a private key.
 */
gnutls_x509_privkey_t
load_private_key (int mand)
{
  gnutls_x509_privkey_t key;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  if (!info.privkey && !mand)
    return NULL;

  if (info.privkey == NULL)
    error (EXIT_FAILURE, 0, "missing --load-privkey");

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "privkey_init: %s", gnutls_strerror (ret));

  dat.data = read_binary_file (info.privkey, &size);
  dat.size = size;

  if (!dat.data)
    error (EXIT_FAILURE, errno, "reading --load-privkey: %s", info.privkey);

  if (info.pkcs8)
    {
      const char *pass = get_pass ();
      ret =
	gnutls_x509_privkey_import_pkcs8 (key, &dat, info.incert_format,
					  pass, 0);
    }
  else
    ret = gnutls_x509_privkey_import (key, &dat, info.incert_format);

  free (dat.data);

  if (ret == GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR)
    {
      error (EXIT_FAILURE, 0,
	     "import error: could not find a valid PEM header; "
	     "check if your key is PKCS #8 or PKCS #12 encoded");
    }

  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing --load-privkey: %s: %s",
	   info.privkey, gnutls_strerror (ret));

  return key;
}

/* Load the Certificate Request.
 */
gnutls_x509_crq_t
load_request (void)
{
  gnutls_x509_crq_t crq;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  if (!info.request)
    return NULL;

  ret = gnutls_x509_crq_init (&crq);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crq_init: %s", gnutls_strerror (ret));

  dat.data = read_binary_file (info.request, &size);
  dat.size = size;

  if (!dat.data)
    error (EXIT_FAILURE, errno, "reading --load-request: %s", info.request);

  ret = gnutls_x509_crq_import (crq, &dat, info.incert_format);
  if (ret == GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR)
    {
      error (EXIT_FAILURE, 0,
	     "import error: could not find a valid PEM header");
    }

  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing --load-request: %s: %s",
	   info.request, gnutls_strerror (ret));

  return crq;
}

/* Load the CA's private key.
 */
gnutls_x509_privkey_t
load_ca_private_key (void)
{
  gnutls_x509_privkey_t key;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  if (info.ca_privkey == NULL)
    error (EXIT_FAILURE, 0, "missing --load-ca-privkey");

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "privkey_init: %s", gnutls_strerror (ret));

  dat.data = read_binary_file (info.ca_privkey, &size);
  dat.size = size;

  if (!dat.data)
    error (EXIT_FAILURE, errno, "reading --load-ca-privkey: %s",
	   info.ca_privkey);

  if (info.pkcs8)
    {
      const char *pass = get_pass ();
      ret =
	gnutls_x509_privkey_import_pkcs8 (key, &dat, info.incert_format,
					  pass, 0);
    }
  else
    ret = gnutls_x509_privkey_import (key, &dat, info.incert_format);
  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing --load-ca-privkey: %s: %s",
	   info.ca_privkey, gnutls_strerror (ret));

  return key;
}

/* Loads the CA's certificate
 */
gnutls_x509_crt_t
load_ca_cert (void)
{
  gnutls_x509_crt_t crt;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  if (info.ca == NULL)
    error (EXIT_FAILURE, 0, "missing --load-ca-certificate");

  ret = gnutls_x509_crt_init (&crt);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crt_init: %s", gnutls_strerror (ret));

  dat.data = read_binary_file (info.ca, &size);
  dat.size = size;

  if (!dat.data)
    error (EXIT_FAILURE, errno, "reading --load-ca-certificate: %s", info.ca);

  ret = gnutls_x509_crt_import (crt, &dat, info.incert_format);
  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing --load-ca-certificate: %s: %s",
	   info.ca, gnutls_strerror (ret));

  return crt;
}

/* Loads the certificate
 * If mand is non zero then a certificate is mandatory. Otherwise
 * null will be returned if the certificate loading fails.
 */
gnutls_x509_crt_t
load_cert (int mand)
{
  gnutls_x509_crt_t *crt;
  size_t size;

  crt = load_cert_list (mand, &size);

  return crt ? crt[0] : NULL;
}

#define MAX_CERTS 256

/* Loads a certificate list
 */
gnutls_x509_crt_t *
load_cert_list (int mand, size_t * crt_size)
{
  FILE *fd;
  static gnutls_x509_crt_t crt[MAX_CERTS];
  char *ptr;
  int ret, i;
  gnutls_datum_t dat;
  size_t size;
  int ptr_size;

  *crt_size = 0;
  fprintf (stderr, "Loading certificate list...\n");

  if (info.cert == NULL)
    {
      if (mand)
	error (EXIT_FAILURE, 0, "missing --load-certificate");
      else
	return NULL;
    }

  fd = fopen (info.cert, "r");
  if (fd == NULL)
    error (EXIT_FAILURE, errno, "%s", info.cert);

  size = fread (buffer, 1, sizeof (buffer) - 1, fd);
  buffer[size] = 0;

  fclose (fd);

  ptr = buffer;
  ptr_size = size;

  for (i = 0; i < MAX_CERTS; i++)
    {
      ret = gnutls_x509_crt_init (&crt[i]);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "crt_init: %s", gnutls_strerror (ret));

      dat.data = ptr;
      dat.size = ptr_size;

      ret = gnutls_x509_crt_import (crt[i], &dat, info.incert_format);
      if (ret < 0 && *crt_size > 0)
	break;
      if (ret < 0)
	error (EXIT_FAILURE, 0, "crt_import: %s", gnutls_strerror (ret));

      ptr = strstr (ptr, "---END");
      if (ptr == NULL)
	break;
      ptr++;

      ptr_size = size;
      ptr_size -=
	(unsigned int) ((unsigned char *) ptr - (unsigned char *) buffer);

      if (ptr_size < 0)
	break;

      (*crt_size)++;
    }
  fprintf (stderr, "Loaded %d certificates.\n", (int) *crt_size);

  return crt;
}


/* Generate a PKCS #10 certificate request.
 */
void
generate_request (void)
{
  gnutls_x509_crq_t crq;
  gnutls_x509_privkey_t key;
  int ret, ca_status, path_len;
  const char *pass;
  unsigned int usage = 0;

  fprintf (stderr, "Generating a PKCS #10 certificate request...\n");

  ret = gnutls_x509_crq_init (&crq);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crq_init: %s", gnutls_strerror (ret));

  /* Load the private key.
   */
  key = load_private_key (0);
  if (!key)
    {
      key = generate_private_key_int ();

      print_private_key (key);
    }

  /* Set the DN.
   */
  get_country_crq_set (crq);
  get_organization_crq_set (crq);
  get_unit_crq_set (crq);
  get_locality_crq_set (crq);
  get_state_crq_set (crq);
  get_cn_crq_set (crq);
  get_uid_crq_set (crq);
  get_oid_crq_set (crq);

  get_dns_name_set (TYPE_CRQ, crq);
  get_ip_addr_set (TYPE_CRQ, crq);
  get_email_set (TYPE_CRQ, crq);

  pass = get_challenge_pass ();

  if (pass != NULL && pass[0] != 0)
    {
      ret = gnutls_x509_crq_set_challenge_password (crq, pass);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "set_pass: %s", gnutls_strerror (ret));
    }

  if (info.crq_extensions != 0)
    {
      ca_status = get_ca_status ();
      if (ca_status)
	path_len = get_path_len ();
      else
	path_len = -1;

      ret = gnutls_x509_crq_set_basic_constraints (crq, ca_status, path_len);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "set_basic_constraints: %s",
	       gnutls_strerror (ret));

      ret = get_sign_status (1);
      if (ret)
	usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;

      ret = get_encrypt_status (1);
      if (ret)
	usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
      else
	usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;

      if (ca_status)
	{
	  ret = get_cert_sign_status ();
	  if (ret)
	    usage |= GNUTLS_KEY_KEY_CERT_SIGN;

	  ret = get_crl_sign_status ();
	  if (ret)
	    usage |= GNUTLS_KEY_CRL_SIGN;

	  ret = get_code_sign_status ();
	  if (ret)
	    {
	      ret = gnutls_x509_crq_set_key_purpose_oid
		(crq, GNUTLS_KP_CODE_SIGNING, 0);
	      if (ret < 0)
		error (EXIT_FAILURE, 0, "key_kp: %s", gnutls_strerror (ret));
	    }

	  ret = get_ocsp_sign_status ();
	  if (ret)
	    {
	      ret = gnutls_x509_crq_set_key_purpose_oid
		(crq, GNUTLS_KP_OCSP_SIGNING, 0);
	      if (ret < 0)
		error (EXIT_FAILURE, 0, "key_kp: %s", gnutls_strerror (ret));
	    }

	  ret = get_time_stamp_status ();
	  if (ret)
	    {
	      ret = gnutls_x509_crq_set_key_purpose_oid
		(crq, GNUTLS_KP_TIME_STAMPING, 0);
	      if (ret < 0)
		error (EXIT_FAILURE, 0, "key_kp: %s", gnutls_strerror (ret));
	    }
	}

      ret = gnutls_x509_crq_set_key_usage (crq, usage);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "key_usage: %s", gnutls_strerror (ret));

      ret = get_tls_client_status ();
      if (ret != 0)
	{
	  ret = gnutls_x509_crq_set_key_purpose_oid
	    (crq, GNUTLS_KP_TLS_WWW_CLIENT, 0);
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "key_kp: %s", gnutls_strerror (ret));
	}

      ret = get_tls_server_status ();
      if (ret != 0)
	{
	  ret = gnutls_x509_crq_set_key_purpose_oid
	    (crq, GNUTLS_KP_TLS_WWW_SERVER, 0);
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "key_kp: %s", gnutls_strerror (ret));
	}
    }

  ret = gnutls_x509_crq_set_key (crq, key);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "set_key: %s", gnutls_strerror (ret));

  ret = gnutls_x509_crq_sign (crq, key);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "sign: %s", gnutls_strerror (ret));

  print_crq_info (crq, outfile);

  gnutls_x509_crq_deinit (crq);
  gnutls_x509_privkey_deinit (key);

}

static void print_verification_res (gnutls_x509_crt_t crt,
				    gnutls_x509_crt_t issuer,
				    gnutls_x509_crl_t * crl_list,
				    int crl_list_size, unsigned int flags);

#define CERT_SEP "-----BEGIN CERT"
#define CRL_SEP "-----BEGIN X509 CRL"
static int
_verify_x509_mem (const void *cert, int cert_size)
{
  const char *ptr;
  int ret, i;
  char name[256];
  char issuer_name[256];
  size_t name_size;
  size_t issuer_name_size;
  gnutls_datum_t tmp;
  gnutls_x509_crt_t *x509_cert_list = NULL;
  gnutls_x509_crl_t *x509_crl_list = NULL;
  int x509_ncerts, x509_ncrls;


  /* Decode the CA certificate
   */

  /* Decode the CRL list
   */
  ptr = cert;

  i = 1;

  if (strstr (ptr, CRL_SEP) != NULL)	/* if CRLs exist */
    do
      {
	x509_crl_list =
	  (gnutls_x509_crl_t *) realloc (x509_crl_list,
					 i * sizeof (gnutls_x509_crl_t));
	if (x509_crl_list == NULL)
	  error (EXIT_FAILURE, 0, "memory error");

	tmp.data = (char *) ptr;
	tmp.size = cert_size;
	tmp.size -=
	  (unsigned int) ((unsigned char *) ptr - (unsigned char *) cert);

	ret = gnutls_x509_crl_init (&x509_crl_list[i - 1]);
	if (ret < 0)
	  error (EXIT_FAILURE, 0, "error parsing CRL[%d]: %s", i,
		 gnutls_strerror (ret));

	ret = gnutls_x509_crl_import (x509_crl_list[i - 1], &tmp,
				      GNUTLS_X509_FMT_PEM);
	if (ret < 0)
	  error (EXIT_FAILURE, 0, "error parsing CRL[%d]: %s", i,
		 gnutls_strerror (ret));

	/* now we move ptr after the pem header */
	ptr = strstr (ptr, CRL_SEP);
	if (ptr != NULL)
	  ptr++;

	i++;
      }
    while ((ptr = strstr (ptr, CRL_SEP)) != NULL);

  x509_ncrls = i - 1;


  /* Decode the certificate chain. 
   */
  ptr = cert;

  i = 1;

  do
    {
      x509_cert_list =
	(gnutls_x509_crt_t *) realloc (x509_cert_list,
				       i * sizeof (gnutls_x509_crt_t));
      if (x509_cert_list == NULL)
	error (EXIT_FAILURE, 0, "memory error");


      tmp.data = (char *) ptr;
      tmp.size = cert_size;
      tmp.size -=
	(unsigned int) ((unsigned char *) ptr - (unsigned char *) cert);

      ret = gnutls_x509_crt_init (&x509_cert_list[i - 1]);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "error parsing certificate[%d]: %s", i,
	       gnutls_strerror (ret));

      ret =
	gnutls_x509_crt_import (x509_cert_list[i - 1], &tmp,
				GNUTLS_X509_FMT_PEM);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "error parsing certificate[%d]: %s", i,
	       gnutls_strerror (ret));


      if (i - 1 != 0)
	{
	  /* verify the previous certificate using this one 
	   * as CA.
	   */

	  name_size = sizeof (name);
	  ret =
	    gnutls_x509_crt_get_dn (x509_cert_list[i - 2], name, &name_size);
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "get_dn: %s", gnutls_strerror (ret));

	  fprintf (outfile, "Certificate[%d]: %s\n", i - 2, name);

	  /* print issuer 
	   */
	  issuer_name_size = sizeof (issuer_name);
	  ret =
	    gnutls_x509_crt_get_issuer_dn (x509_cert_list[i - 2],
					   issuer_name, &issuer_name_size);
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "get_issuer_dn: %s",
		   gnutls_strerror (ret));

	  fprintf (outfile, "\tIssued by: %s\n", issuer_name);

	  /* Get the Issuer's name
	   */
	  name_size = sizeof (name);
	  ret =
	    gnutls_x509_crt_get_dn (x509_cert_list[i - 1], name, &name_size);
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "get_dn: %s", gnutls_strerror (ret));

	  fprintf (outfile, "\tVerifying against certificate[%d].\n", i - 1);

	  if (strcmp (issuer_name, name) != 0)
	    {
	      fprintf (stderr, "Error: Issuer's name: %s\n", name);
	      error (EXIT_FAILURE, 0,
		     "issuer name does not match the next certificate");
	    }

	  fprintf (outfile, "\tVerification output: ");
	  print_verification_res (x509_cert_list[i - 2],
				  x509_cert_list[i - 1], x509_crl_list,
				  x509_ncrls,
				  GNUTLS_VERIFY_DO_NOT_ALLOW_SAME);
	  fprintf (outfile, ".\n\n");

	}


      /* now we move ptr after the pem header 
       */
      ptr = strstr (ptr, CERT_SEP);
      if (ptr != NULL)
	ptr++;

      i++;
    }
  while ((ptr = strstr (ptr, CERT_SEP)) != NULL);

  x509_ncerts = i - 1;

  /* The last certificate in the list will be used as
   * a CA (should be self signed).
   */
  name_size = sizeof (name);
  ret = gnutls_x509_crt_get_dn (x509_cert_list[x509_ncerts - 1], name,
				&name_size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "get_dn: %s", gnutls_strerror (ret));

  fprintf (outfile, "Certificate[%d]: %s\n", x509_ncerts - 1, name);

  /* print issuer 
   */
  issuer_name_size = sizeof (issuer_name);
  ret =
    gnutls_x509_crt_get_issuer_dn (x509_cert_list[x509_ncerts - 1],
				   issuer_name, &issuer_name_size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "get_issuer_dn: %s", gnutls_strerror (ret));

  fprintf (outfile, "\tIssued by: %s\n", name);

  if (strcmp (issuer_name, name) != 0)
    error (EXIT_FAILURE, 0, "the last certificate is not self signed");

  fprintf (outfile, "\tVerification output: ");
  print_verification_res (x509_cert_list[x509_ncerts - 1],
			  x509_cert_list[x509_ncerts - 1], x509_crl_list,
			  /* we add GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT since it is
			   * self signed. */
			  x509_ncrls,
			  GNUTLS_VERIFY_DO_NOT_ALLOW_SAME |
			  GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

  fprintf (outfile, ".\n\n");

  /* Verify using internal algorithm too. */
  {
    int verify_status;

    ret = gnutls_x509_crt_list_verify (x509_cert_list, x509_ncerts,
				       &x509_cert_list[x509_ncerts - 1], 1,
				       x509_crl_list,
				       x509_ncrls,
				       GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT |
				       GNUTLS_VERIFY_DO_NOT_ALLOW_SAME,
				       &verify_status);
    if (ret < 0)
      error (EXIT_FAILURE, 0, "gnutls_x509_crt_list_verify: %s",
	     gnutls_strerror (ret));

    fprintf (outfile, "Chain verification output: ");

    if (verify_status & GNUTLS_CERT_INVALID)
      {
	fprintf (outfile, "Not verified");
      }
    else
      {
	fprintf (outfile, "Verified");
      }

    if (verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
      {
	fprintf (outfile, ", ");
	fprintf (outfile, "Issuer is not a CA");
      }

    if (verify_status & GNUTLS_CERT_INSECURE_ALGORITHM)
      {
	fprintf (outfile, ", ");
	fprintf (outfile, "Insecure algorithm");
      }

    fprintf (outfile, ".\n");
  }

  for (i = 0; i < x509_ncerts; i++)
    gnutls_x509_crt_deinit (x509_cert_list[i]);

  for (i = 0; i < x509_ncrls; i++)
    gnutls_x509_crl_deinit (x509_crl_list[i]);

  free (x509_cert_list);
  free (x509_crl_list);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "verification error: %s", gnutls_strerror (ret));

  return 0;
}

static void
print_verification_res (gnutls_x509_crt_t crt,
			gnutls_x509_crt_t issuer,
			gnutls_x509_crl_t * crl_list, int crl_list_size,
			unsigned int flags)
{
  unsigned int output;
  int comma = 0;
  int ret;

  ret = gnutls_x509_crt_verify (crt, &issuer, 1, flags, &output);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "verification error: %s", gnutls_strerror (ret));

  if (output & GNUTLS_CERT_INVALID)
    {
      fprintf (outfile, "Not verified");
      comma = 1;
    }
  else
    {
      fprintf (outfile, "Verified");
      comma = 1;
    }

  if (output & GNUTLS_CERT_SIGNER_NOT_CA)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Issuer is not a CA");
      comma = 1;
    }

  if (output & GNUTLS_CERT_INSECURE_ALGORITHM)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Insecure algorithm");
      comma = 1;
    }

  if (output & GNUTLS_CERT_NOT_ACTIVATED)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Not activated");
      comma = 1;
    }

  if (output & GNUTLS_CERT_EXPIRED)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Expired");
      comma = 1;
    }

  ret = gnutls_x509_crt_check_revocation (crt, crl_list, crl_list_size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "revocation check: %s", gnutls_strerror (ret));

  if (ret == 1)
    {				/* revoked */
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "Revoked");
    }
}

void
verify_chain (void)
{
  char *buf;
  size_t size;

  buf = fread_file (infile, &size);
  if (buf == NULL)
    error (EXIT_FAILURE, errno, "reading chain");

  buf[size] = 0;

  _verify_x509_mem (buf, size);

}

void
verify_crl (void)
{
  size_t size, dn_size;
  char dn[128];
  unsigned int output;
  int comma = 0;
  int ret;
  gnutls_datum_t pem;
  gnutls_x509_crl_t crl;
  time_t now = time (0);
  gnutls_x509_crt_t issuer;

  issuer = load_ca_cert ();

  fprintf (outfile, "\nCA certificate:\n");

  dn_size = sizeof (dn);
  ret = gnutls_x509_crt_get_dn (issuer, dn, &dn_size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crt_get_dn: %s", gnutls_strerror (ret));

  fprintf (outfile, "\tSubject: %s\n\n", dn);

  ret = gnutls_x509_crl_init (&crl);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crl_init: %s", gnutls_strerror (ret));

  pem.data = fread_file (infile, &size);
  pem.size = size;

  ret = gnutls_x509_crl_import (crl, &pem, info.incert_format);
  free (pem.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (ret));

  print_crl_info (crl, outfile);

  fprintf (outfile, "Verification output: ");
  ret = gnutls_x509_crl_verify (crl, &issuer, 1, 0, &output);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "verification error: %s", gnutls_strerror (ret));

  if (output & GNUTLS_CERT_INVALID)
    {
      fprintf (outfile, "Not verified");
      comma = 1;
    }
  else
    {
      fprintf (outfile, "Verified");
      comma = 1;
    }

  if (output & GNUTLS_CERT_SIGNER_NOT_CA)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Issuer is not a CA");
      comma = 1;
    }

  if (output & GNUTLS_CERT_INSECURE_ALGORITHM)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Insecure algorithm");
      comma = 1;
    }

  /* Check expiration dates.
   */

  if (gnutls_x509_crl_get_this_update (crl) > now)
    {
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "Issued in the future!");
    }

  if (gnutls_x509_crl_get_next_update (crl) < now)
    {
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "CRL is not up to date");
    }

  fprintf (outfile, "\n");
}

static int
cipher_to_flags (const char *cipher)
{
  if (strcasecmp (cipher, "3des") == 0)
    {
      return GNUTLS_PKCS_USE_PBES2_3DES;
    }
  else if (strcasecmp (cipher, "aes-128") == 0)
    {
      return GNUTLS_PKCS_USE_PBES2_AES_128;
    }
  else if (strcasecmp (cipher, "aes-192") == 0)
    {
      return GNUTLS_PKCS_USE_PBES2_AES_192;
    }
  else if (strcasecmp (cipher, "aes-256") == 0)
    {
      return GNUTLS_PKCS_USE_PBES2_AES_256;
    }
  else if (strcasecmp (cipher, "rc2-40") == 0)
    {
      return GNUTLS_PKCS_USE_PKCS12_RC2_40;
    }

  error (EXIT_FAILURE, 0, "Unknown cipher %s\n", cipher);
  return -1;
}

void
generate_pkcs8 (void)
{
  gnutls_x509_privkey_t key;
  int result;
  size_t size;
  int flags = 0;
  const char *password;

  fprintf (stderr, "Generating a PKCS #8 key structure...\n");

  key = load_private_key (1);

  if (info.pass)
    password = info.pass;
  else
    password = get_pass ();

  if (info.export)
    flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
  else
    flags = cipher_to_flags (info.pkcs_cipher);

  if (password == NULL || password[0] == 0)
    {
      flags = GNUTLS_PKCS_PLAIN;
    }

  size = sizeof (buffer);
  result =
    gnutls_x509_privkey_export_pkcs8 (key, info.outcert_format,
				      password, flags, buffer, &size);

  if (result < 0)
    error (EXIT_FAILURE, 0, "key_export: %s", gnutls_strerror (result));

  fwrite (buffer, 1, size, outfile);

}


#include <gnutls/pkcs12.h>
#include <unistd.h>

void
generate_pkcs12 (void)
{
  gnutls_pkcs12_t pkcs12;
  gnutls_x509_crt_t *crts;
  gnutls_x509_privkey_t key;
  int result;
  size_t size;
  gnutls_datum_t data;
  const char *pass;
  const char *name;
  unsigned int flags, i;
  gnutls_datum_t key_id;
  unsigned char _key_id[20];
  int indx;
  size_t ncrts;

  fprintf (stderr, "Generating a PKCS #12 structure...\n");

  key = load_private_key (0);
  crts = load_cert_list (0, &ncrts);

  name = get_pkcs12_key_name ();

  result = gnutls_pkcs12_init (&pkcs12);
  if (result < 0)
    error (EXIT_FAILURE, 0, "pkcs12_init: %s", gnutls_strerror (result));

  if (info.pass)
    pass = info.pass;
  else
    pass = get_pass ();

  for (i = 0; i < ncrts; i++)
    {
      gnutls_pkcs12_bag_t bag;

      result = gnutls_pkcs12_bag_init (&bag);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_init: %s", gnutls_strerror (result));

      result = gnutls_pkcs12_bag_set_crt (bag, crts[i]);
      if (result < 0)
	error (EXIT_FAILURE, 0, "set_crt[%d]: %s", i,
	       gnutls_strerror (result));

      indx = result;

      result = gnutls_pkcs12_bag_set_friendly_name (bag, indx, name);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_set_friendly_name: %s",
	       gnutls_strerror (result));

      size = sizeof (_key_id);
      result = gnutls_x509_crt_get_key_id (crts[i], 0, _key_id, &size);
      if (result < 0)
	error (EXIT_FAILURE, 0, "key_id[%d]: %s", i,
	       gnutls_strerror (result));

      key_id.data = _key_id;
      key_id.size = size;

      result = gnutls_pkcs12_bag_set_key_id (bag, indx, &key_id);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_set_key_id: %s",
	       gnutls_strerror (result));

      if (info.export)
	flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
      else
	flags = cipher_to_flags (info.pkcs_cipher);

      result = gnutls_pkcs12_bag_encrypt (bag, pass, flags);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_encrypt: %s", gnutls_strerror (result));

      result = gnutls_pkcs12_set_bag (pkcs12, bag);
      if (result < 0)
	error (EXIT_FAILURE, 0, "set_bag: %s", gnutls_strerror (result));
    }

  if (key)
    {
      gnutls_pkcs12_bag_t kbag;

      result = gnutls_pkcs12_bag_init (&kbag);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_init: %s", gnutls_strerror (result));

      if (info.export)
	flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
      else
	flags = cipher_to_flags (info.pkcs_cipher);

      size = sizeof (buffer);
      result =
	gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_DER,
					  pass, flags, buffer, &size);
      if (result < 0)
	error (EXIT_FAILURE, 0, "key_export: %s", gnutls_strerror (result));

      data.data = buffer;
      data.size = size;
      result =
	gnutls_pkcs12_bag_set_data (kbag,
				    GNUTLS_BAG_PKCS8_ENCRYPTED_KEY, &data);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_set_data: %s", gnutls_strerror (result));

      indx = result;

      result = gnutls_pkcs12_bag_set_friendly_name (kbag, indx, name);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_set_friendly_name: %s",
	       gnutls_strerror (result));

      size = sizeof (_key_id);
      result = gnutls_x509_privkey_get_key_id (key, 0, _key_id, &size);
      if (result < 0)
	error (EXIT_FAILURE, 0, "key_id: %s", gnutls_strerror (result));

      key_id.data = _key_id;
      key_id.size = size;

      result = gnutls_pkcs12_bag_set_key_id (kbag, indx, &key_id);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_set_key_id: %s",
	       gnutls_strerror (result));

      result = gnutls_pkcs12_set_bag (pkcs12, kbag);
      if (result < 0)
	error (EXIT_FAILURE, 0, "set_bag: %s", gnutls_strerror (result));
    }

  result = gnutls_pkcs12_generate_mac (pkcs12, pass);
  if (result < 0)
    error (EXIT_FAILURE, 0, "generate_mac: %s", gnutls_strerror (result));

  size = sizeof (buffer);
  result = gnutls_pkcs12_export (pkcs12, info.outcert_format, buffer, &size);
  if (result < 0)
    error (EXIT_FAILURE, 0, "pkcs12_export: %s", gnutls_strerror (result));

  fwrite (buffer, 1, size, outfile);

}

static const char *
BAGTYPE (gnutls_pkcs12_bag_type_t x)
{
  switch (x)
    {
    case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
      return "PKCS #8 Encrypted key";
    case GNUTLS_BAG_EMPTY:
      return "Empty";
    case GNUTLS_BAG_PKCS8_KEY:
      return "PKCS #8 Key";
    case GNUTLS_BAG_CERTIFICATE:
      return "Certificate";
    case GNUTLS_BAG_ENCRYPTED:
      return "Encrypted";
    case GNUTLS_BAG_CRL:
      return "CRL";
    case GNUTLS_BAG_SECRET:
      return "Secret";
    default:
      return "Unknown";
    }
}

static void
print_bag_data (gnutls_pkcs12_bag_t bag)
{
  int result;
  int count, i, type;
  gnutls_datum_t cdata, id;
  const char *str, *name;
  gnutls_datum_t out;

  count = gnutls_pkcs12_bag_get_count (bag);
  if (count < 0)
    error (EXIT_FAILURE, 0, "get_count: %s", gnutls_strerror (count));

  fprintf (outfile, "\tElements: %d\n", count);

  for (i = 0; i < count; i++)
    {
      type = gnutls_pkcs12_bag_get_type (bag, i);
      if (type < 0)
	error (EXIT_FAILURE, 0, "get_type: %s", gnutls_strerror (type));

      fprintf (stderr, "\tType: %s\n", BAGTYPE (type));

      name = NULL;
      result = gnutls_pkcs12_bag_get_friendly_name (bag, i, (char **) &name);
      if (result < 0)
	error (EXIT_FAILURE, 0, "get_friendly_name: %s",
	       gnutls_strerror (type));
      if (name)
	fprintf (outfile, "\tFriendly name: %s\n", name);

      id.data = NULL;
      id.size = 0;
      result = gnutls_pkcs12_bag_get_key_id (bag, i, &id);
      if (result < 0)
	error (EXIT_FAILURE, 0, "get_key_id: %s", gnutls_strerror (type));
      fprintf (outfile, "\tKey ID: %s\n", raw_to_string (id.data, id.size));

      result = gnutls_pkcs12_bag_get_data (bag, i, &cdata);
      if (result < 0)
	error (EXIT_FAILURE, 0, "get_data: %s", gnutls_strerror (result));

      switch (type)
	{
	case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
	  str = "ENCRYPTED PRIVATE KEY";
	  break;
	case GNUTLS_BAG_PKCS8_KEY:
	  str = "PRIVATE KEY";
	  break;
	case GNUTLS_BAG_CERTIFICATE:
	  str = "CERTIFICATE";
	  break;
	case GNUTLS_BAG_CRL:
	  str = "CRL";
	  break;
	case GNUTLS_BAG_ENCRYPTED:
	case GNUTLS_BAG_EMPTY:
	default:
	  str = NULL;
	}

      if (str != NULL)
	{
	  gnutls_pem_base64_encode_alloc (str, &cdata, &out);
	  fprintf (outfile, "%s\n", out.data);

	  gnutls_free (out.data);
	}

    }
}

void
pkcs12_info (void)
{
  gnutls_pkcs12_t pkcs12;
  gnutls_pkcs12_bag_t bag;
  int result;
  size_t size;
  gnutls_datum_t data;
  const char *pass;
  int indx;

  result = gnutls_pkcs12_init (&pkcs12);
  if (result < 0)
    error (EXIT_FAILURE, 0, "p12_init: %s", gnutls_strerror (result));

  data.data = fread_file (infile, &size);
  data.size = size;

  result = gnutls_pkcs12_import (pkcs12, &data, info.incert_format, 0);
  free (data.data);
  if (result < 0)
    error (EXIT_FAILURE, 0, "p12_import: %s", gnutls_strerror (result));

  if (info.pass)
    pass = info.pass;
  else
    pass = get_pass ();

  result = gnutls_pkcs12_verify_mac (pkcs12, pass);
  if (result < 0)
    error (0, 0, "verify_mac: %s", gnutls_strerror (result));

  for (indx = 0;; indx++)
    {
      result = gnutls_pkcs12_bag_init (&bag);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_init: %s", gnutls_strerror (result));

      result = gnutls_pkcs12_get_bag (pkcs12, indx, bag);
      if (result < 0)
	break;

      result = gnutls_pkcs12_bag_get_count (bag);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_count: %s", gnutls_strerror (result));

      fprintf (outfile, "BAG #%d\n", indx);

      result = gnutls_pkcs12_bag_get_type (bag, 0);
      if (result < 0)
	error (EXIT_FAILURE, 0, "bag_init: %s", gnutls_strerror (result));

      if (result == GNUTLS_BAG_ENCRYPTED)
	{
	  fprintf (stderr, "\tType: %s\n", BAGTYPE (result));
	  fprintf (stderr, "\n\tDecrypting...\n");

	  result = gnutls_pkcs12_bag_decrypt (bag, pass);

	  if (result < 0)
	    {
	      error (0, 0, "bag_decrypt: %s", gnutls_strerror (result));
	      continue;
	    }

	  result = gnutls_pkcs12_bag_get_count (bag);
	  if (result < 0)
	    error (EXIT_FAILURE, 0, "encrypted bag_count: %s",
		   gnutls_strerror (result));
	}

      print_bag_data (bag);

      gnutls_pkcs12_bag_deinit (bag);
    }
}

void
pkcs7_info (void)
{
  gnutls_pkcs7_t pkcs7;
  int result;
  size_t size;
  gnutls_datum_t data, b64;
  int indx, count;

  result = gnutls_pkcs7_init (&pkcs7);
  if (result < 0)
    error (EXIT_FAILURE, 0, "p7_init: %s", gnutls_strerror (result));

  data.data = fread_file (infile, &size);
  data.size = size;

  result = gnutls_pkcs7_import (pkcs7, &data, info.incert_format);
  free (data.data);
  if (result < 0)
    error (EXIT_FAILURE, 0, "import error: %s", gnutls_strerror (result));

  /* Read and print the certificates.
   */
  result = gnutls_pkcs7_get_crt_count (pkcs7);
  if (result < 0)
    error (EXIT_FAILURE, 0, "p7_crt_count: %s", gnutls_strerror (result));

  count = result;

  if (count > 0)
    fprintf (outfile, "Number of certificates: %u\n", count);

  for (indx = 0; indx < count; indx++)
    {
      fputs ("\n", outfile);

      size = sizeof (buffer);
      result = gnutls_pkcs7_get_crt_raw (pkcs7, indx, buffer, &size);
      if (result < 0)
	break;

      data.data = buffer;
      data.size = size;

      result = gnutls_pem_base64_encode_alloc ("CERTIFICATE", &data, &b64);
      if (result < 0)
	error (EXIT_FAILURE, 0, "encoding: %s", gnutls_strerror (result));

      fputs (b64.data, outfile);
      gnutls_free (b64.data);
    }

  /* Read the CRLs now.
   */
  result = gnutls_pkcs7_get_crl_count (pkcs7);
  if (result < 0)
    error (EXIT_FAILURE, 0, "p7_crl_count: %s", gnutls_strerror (result));

  count = result;

  if (count > 0)
    fprintf (outfile, "\nNumber of CRLs: %u\n", count);

  for (indx = 0; indx < count; indx++)
    {
      fputs ("\n", outfile);

      size = sizeof (buffer);
      result = gnutls_pkcs7_get_crl_raw (pkcs7, indx, buffer, &size);
      if (result < 0)
	break;

      data.data = buffer;
      data.size = size;

      result = gnutls_pem_base64_encode_alloc ("X509 CRL", &data, &b64);
      if (result < 0)
	error (EXIT_FAILURE, 0, "encoding: %s", gnutls_strerror (result));

      fputs (b64.data, outfile);
      gnutls_free (b64.data);
    }
}

void
smime_to_pkcs7 (void)
{
  size_t linesize = 0;
  char *lineptr = NULL;
  ssize_t len;

  /* Find body.  FIXME: Handle non-b64 Content-Transfer-Encoding.
     Reject non-S/MIME tagged Content-Type's? */
  do
    {
      len = getline (&lineptr, &linesize, infile);
      if (len == -1)
	error (EXIT_FAILURE, 0, "cannot find RFC 2822 header/body separator");
    }
  while (strcmp (lineptr, "\r\n") != 0 && strcmp (lineptr, "\n") != 0);

  do
    {
      len = getline (&lineptr, &linesize, infile);
      if (len == -1)
	error (EXIT_FAILURE, 0, "message has RFC 2822 header but no body");
    }
  while (strcmp (lineptr, "\r\n") == 0 && strcmp (lineptr, "\n") == 0);

  fprintf (outfile, "%s", "-----BEGIN PKCS7-----\n");

  do
    {
      while (len > 0
	     && (lineptr[len - 1] == '\r' || lineptr[len - 1] == '\n'))
	lineptr[--len] = '\0';
      if (strcmp (lineptr, "") != 0)
	fprintf (outfile, "%s\n", lineptr);
      len = getline (&lineptr, &linesize, infile);
    }
  while (len != -1);

  fprintf (outfile, "%s", "-----END PKCS7-----\n");

  free (lineptr);
}

void
certtool_version (void)
{
  const char *p = PACKAGE_NAME;
  if (strcmp (gnutls_check_version (NULL), PACKAGE_VERSION) != 0)
    p = PACKAGE_STRING;
  version_etc (stdout, program_name, p, gnutls_check_version (NULL),
	       "Nikos Mavrogiannopoulos", "Simon Josefsson", (char *) NULL);
}
