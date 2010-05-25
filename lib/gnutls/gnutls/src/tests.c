/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2006, 2007, 2008, 2009,
 * 2010  Free Software Foundation, Inc.
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

#ifndef _WIN32
# include <unistd.h>
# include <signal.h>
#else
# include <errno.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <common.h>
#include <tests.h>

extern gnutls_srp_client_credentials_t srp_cred;
extern gnutls_anon_client_credentials_t anon_cred;
extern gnutls_certificate_credentials_t xcred;

extern int verbose;

int tls1_ok = 0;
int ssl3_ok = 0;
int tls1_1_ok = 0;
int tls1_2_ok = 0;

/* keep session info */
static char *session_data = NULL;
static char session_id[32];
static size_t session_data_size = 0, session_id_size = 0;
static int sfree = 0;
static int handshake_output = 0;

static int
do_handshake (gnutls_session_t session)
{
  int ret, alert;

  do
    {
      ret = gnutls_handshake (session);
    }
  while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

  handshake_output = ret;

  if (ret < 0 && verbose > 1)
    {
      if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
	  || ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
	{
	  alert = gnutls_alert_get (session);
	  printf ("\n");
	  printf ("*** Received alert [%d]: %s\n",
		  alert, gnutls_alert_get_name (alert));
	}
    }

  if (ret < 0)
    return TEST_FAILED;

  gnutls_session_get_data (session, NULL, &session_data_size);

  if (sfree != 0)
    {
      free (session_data);
      sfree = 0;
    }
  session_data = malloc (session_data_size);
  sfree = 1;
  if (session_data == NULL)
    {
      fprintf (stderr, "Memory error\n");
      exit (1);
    }
  gnutls_session_get_data (session, session_data, &session_data_size);

  session_id_size = sizeof (session_id);
  gnutls_session_get_id (session, session_id, &session_id_size);

  return TEST_SUCCEED;
}

char protocol_str[] = "+VERS-TLS1.0:+VERS-SSL3.0";
char prio_str[256] = "";

#define ALL_CIPHERS "+3DES-CBC:+ARCFOUR-128:+ARCFOUR-40"
#define ALL_COMP "+COMP-NULL"
#define ALL_MACS "+SHA1:+MD5"
#define ALL_CERTTYPES "+CTYPE-X509"
#define REST "%%UNSAFE_RENEGOTIATION"
#define ALL_KX "+RSA:+DHE-RSA:+DHE-DSS:+ANON-DH:+RSA-EXPORT"
#define INIT_STR "NONE:"

static inline void
_gnutls_priority_set_direct (gnutls_session_t session, const char *str)
{
  const char *err;
  int ret = gnutls_priority_set_direct (session, str, &err);

  if (ret < 0)
    {
      fprintf (stderr, "Error in %s\n", err);
      exit (1);
    }
}

test_code_t
test_server (gnutls_session_t session)
{
  int ret, i = 0;
  char buf[5 * 1024];
  char *p;
  const char snd_buf[] = "GET / HTTP/1.0\n\n";

  if (verbose == 0)
    return TEST_UNSURE;

  buf[sizeof (buf) - 1] = 0;

  sprintf (prio_str,
	   ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS ":"
	   ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret != TEST_SUCCEED)
    return TEST_FAILED;

  gnutls_record_send (session, snd_buf, sizeof (snd_buf) - 1);
  ret = gnutls_record_recv (session, buf, sizeof (buf) - 1);
  if (ret < 0)
    return TEST_FAILED;

  p = strstr (buf, "Server:");
  if (p != NULL)
    p = strchr (p, ':');
  if (p != NULL)
    {
      p++;
      while (*p != 0 && *p != '\r' && *p != '\n')
	{
	  putc (*p, stdout);
	  p++;
	  i++;
	  if (i > 128)
	    break;
	}
    }

  return TEST_SUCCEED;
}


static int export_true = 0;
static gnutls_datum_t exp = { NULL, 0 }, mod =

{
NULL, 0};

test_code_t
test_export (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   "+ARCFOUR-40:+RSA-EXPORT:" ALL_COMP ":" ALL_CERTTYPES ":%s:"
	   ALL_MACS ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);

  if (ret == TEST_SUCCEED)
    {
      export_true = 1;
      gnutls_rsa_export_get_pubkey (session, &exp, &mod);
    }

  return ret;
}

test_code_t
test_export_info (gnutls_session_t session)
{
  int ret2, ret;
  gnutls_datum_t exp2, mod2;
  const char *print;

  if (verbose == 0 || export_true == 0)
    return TEST_IGNORE;

  sprintf (prio_str,
	   "+ARCFOUR-40:+RSA-EXPORT:" ALL_COMP ":" ALL_CERTTYPES ":%s:"
	   ALL_MACS ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);

  if (ret == TEST_SUCCEED)
    {
      ret2 = gnutls_rsa_export_get_pubkey (session, &exp2, &mod2);
      if (ret2 >= 0)
	{
	  printf ("\n");

	  print = raw_to_string (exp2.data, exp2.size);
	  if (print)
	    printf (" Exponent [%d bits]: %s\n", exp2.size * 8, print);

	  print = raw_to_string (mod2.data, mod2.size);
	  if (print)
	    printf (" Modulus [%d bits]: %s\n", mod2.size * 8, print);

	  if (mod2.size != mod.size || exp2.size != exp.size ||
	      memcmp (mod2.data, mod.data, mod.size) != 0 ||
	      memcmp (exp2.data, exp.data, exp.size) != 0)
	    {
	      printf
		(" (server uses different public keys per connection)\n");
	    }
	}
    }

  return ret;

}

static gnutls_datum_t pubkey = { NULL, 0 };

test_code_t
test_dhe (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":+DHE-RSA:+DHE-DSS:" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);

  gnutls_dh_get_pubkey (session, &pubkey);

  return ret;
}


test_code_t
test_safe_renegotiation (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS ":"
	   ALL_KX ":%%INITIAL_SAFE_RENEGOTIATION", protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);

  return ret;
}

test_code_t
test_safe_renegotiation_scsv (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":+VERS-SSL3.0:"
	   ALL_MACS ":" ALL_KX ":%%INITIAL_SAFE_RENEGOTIATION");
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);

  return ret;
}

test_code_t
test_dhe_group (gnutls_session_t session)
{
  int ret, ret2;
  gnutls_datum_t gen, prime, pubkey2;
  const char *print;

  if (verbose == 0 || pubkey.data == NULL)
    return TEST_IGNORE;

  sprintf (prio_str,
	   ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":+DHE-RSA:+DHE-DSS:" REST, protocol_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);

  ret2 = gnutls_dh_get_group (session, &gen, &prime);
  if (ret2 >= 0)
    {
      printf ("\n");

      print = raw_to_string (gen.data, gen.size);
      if (print)
	printf (" Generator [%d bits]: %s\n", gen.size * 8, print);

      print = raw_to_string (prime.data, prime.size);
      if (print)
	printf (" Prime [%d bits]: %s\n", prime.size * 8, print);

      gnutls_dh_get_pubkey (session, &pubkey2);
      print = raw_to_string (pubkey2.data, pubkey2.size);
      if (print)
	printf (" Pubkey [%d bits]: %s\n", pubkey2.size * 8, print);

      if (pubkey2.data && pubkey2.size == pubkey.size &&
	  memcmp (pubkey.data, pubkey2.data, pubkey.size) == 0)
	{
	  printf (" (public key seems to be static among sessions)\n");
	}
    }
  return ret;
}

test_code_t
test_ssl3 (gnutls_session_t session)
{
  int ret;
  sprintf (prio_str,
	   ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":+VERS-SSL3.0:"
	   ALL_MACS ":" ALL_KX ":" REST);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_SUCCEED)
    ssl3_ok = 1;

  return ret;
}

static int alrm = 0;
static void
got_alarm (int k)
{
  alrm = 1;
}

test_code_t
test_bye (gnutls_session_t session)
{
  int ret;
  char data[20];
  int old, secs = 6;

#ifndef _WIN32
  signal (SIGALRM, got_alarm);
#endif

  sprintf (prio_str,
	   ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS ":"
	   ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_FAILED)
    return ret;

  ret = gnutls_bye (session, GNUTLS_SHUT_WR);
  if (ret < 0)
    return TEST_FAILED;

#ifndef _WIN32
  old = siginterrupt (SIGALRM, 1);
  alarm (secs);
#else
  setsockopt ((int) gnutls_transport_get_ptr (session), SOL_SOCKET,
	      SO_RCVTIMEO, (char *) &secs, sizeof (int));
#endif

  do
    {
      ret = gnutls_record_recv (session, data, sizeof (data));
    }
  while (ret > 0);

#ifndef _WIN32
  siginterrupt (SIGALRM, old);
#else
  if (WSAGetLastError () == WSAETIMEDOUT ||
      WSAGetLastError () == WSAECONNABORTED)
    alrm = 1;
#endif
  if (ret == 0)
    return TEST_SUCCEED;

  if (alrm == 0)
    return TEST_UNSURE;

  return TEST_FAILED;
}



test_code_t
test_aes (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR "+AES-128-CBC:" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}

#ifdef	ENABLE_CAMELLIA
test_code_t
test_camellia (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR "+CAMELLIA-128-CBC:" ALL_COMP ":" ALL_CERTTYPES ":%s:"
	   ALL_MACS ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}
#endif

test_code_t
test_openpgp1 (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":+CTYPE-OPENPGP:%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_FAILED)
    return ret;

  if (gnutls_certificate_type_get (session) == GNUTLS_CRT_OPENPGP)
    return TEST_SUCCEED;

  return TEST_FAILED;
}

test_code_t
test_unknown_ciphersuites (gnutls_session_t session)
{
  int ret;


#ifdef	ENABLE_CAMELLIA
  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
#else
  sprintf (prio_str,
	   INIT_STR "+AES-128-CBC:" ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES
	   ":%s:" ALL_MACS ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
#endif

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}

test_code_t
test_md5 (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR "+AES-128-CBC:" ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES
	   ":%s:+MD5:" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}

#ifdef HAVE_LIBZ
test_code_t
test_zlib (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":+COMP-ZLIB:" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}
#endif

test_code_t
test_sha (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR "+AES-128-CBC:" ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES
	   ":%s:+SHA1:" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}

test_code_t
test_3des (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR "+3DES-CBC:" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}

test_code_t
test_arcfour (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR "+ARCFOUR-128:" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}

test_code_t
test_arcfour_40 (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR "+ARCFOUR-40:" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" "+RSA-EXPORT" ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  return ret;
}

test_code_t
test_tls1 (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES
	   ":+VERS-TLS1.0:" ALL_MACS ":" ALL_KX ":" REST);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_SUCCEED)
    tls1_ok = 1;

  return ret;

}

test_code_t
test_tls1_2 (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES
	   ":+VERS-TLS1.2:" ALL_MACS ":" ALL_KX ":" REST);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_SUCCEED)
    tls1_2_ok = 1;

  return ret;

}

test_code_t
test_tls1_1 (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES
	   ":+VERS-TLS1.1:" ALL_MACS ":" ALL_KX ":" REST);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_SUCCEED)
    tls1_1_ok = 1;

  return ret;

}

test_code_t
test_tls1_1_fallback (gnutls_session_t session)
{
  int ret;
  if (tls1_1_ok)
    return TEST_IGNORE;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES
	   ":+VERS-TLS1.1:+VERS-TLS1.0:+VERS-SSL3.0:" ALL_MACS ":" ALL_KX ":"
	   REST);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret != TEST_SUCCEED)
    return TEST_FAILED;

  if (gnutls_protocol_get_version (session) == GNUTLS_TLS1)
    return TEST_SUCCEED;
  else if (gnutls_protocol_get_version (session) == GNUTLS_SSL3)
    return TEST_UNSURE;

  return TEST_FAILED;

}

/* Advertize both TLS 1.0 and SSL 3.0. If the connection fails,
 * but the previous SSL 3.0 test succeeded then disable TLS 1.0.
 */
test_code_t
test_tls_disable (gnutls_session_t session)
{
  int ret;
  if (tls1_ok != 0)
    return TEST_IGNORE;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_FAILED)
    {
      /* disable TLS 1.0 */
      if (ssl3_ok != 0)
	{
	  strcpy (protocol_str, "+VERS-SSL3.0");
	}
    }
  return ret;

}

test_code_t
test_rsa_pms (gnutls_session_t session)
{
  int ret;

  /* here we enable both SSL 3.0 and TLS 1.0
   * and try to connect and use rsa authentication.
   * If the server is old, buggy and only supports
   * SSL 3.0 then the handshake will fail.
   */
  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":+RSA:" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_FAILED)
    return TEST_FAILED;

  if (gnutls_protocol_get_version (session) == GNUTLS_TLS1)
    return TEST_SUCCEED;
  return TEST_UNSURE;
}

test_code_t
test_max_record_size (gnutls_session_t session)
{
  int ret;
  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_record_set_max_size (session, 512);

  ret = do_handshake (session);
  if (ret == TEST_FAILED)
    return ret;

  ret = gnutls_record_get_max_size (session);
  if (ret == 512)
    return TEST_SUCCEED;

  return TEST_FAILED;
}

test_code_t
test_hello_extension (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_record_set_max_size (session, 512);

  ret = do_handshake (session);
  return ret;
}

void _gnutls_record_set_default_version (gnutls_session_t session,
					 unsigned char major,
					 unsigned char minor);

test_code_t
test_version_rollback (gnutls_session_t session)
{
  int ret;
  if (tls1_ok == 0)
    return TEST_IGNORE;

  /* here we enable both SSL 3.0 and TLS 1.0
   * and we connect using a 3.1 client hello version,
   * and a 3.0 record version. Some implementations
   * are buggy (and vulnerable to man in the middle
   * attacks which allow a version downgrade) and this 
   * connection will fail.
   */
  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  _gnutls_record_set_default_version (session, 3, 0);

  ret = do_handshake (session);
  if (ret != TEST_SUCCEED)
    return ret;

  if (tls1_ok != 0 && gnutls_protocol_get_version (session) == GNUTLS_SSL3)
    return TEST_FAILED;

  return TEST_SUCCEED;
}

/* See if the server tolerates out of bounds
 * record layer versions in the first client hello
 * message.
 */
test_code_t
test_version_oob (gnutls_session_t session)
{
  int ret;
  /* here we enable both SSL 3.0 and TLS 1.0
   * and we connect using a 5.5 record version.
   */
  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  _gnutls_record_set_default_version (session, 5, 5);

  ret = do_handshake (session);
  return ret;
}

void _gnutls_rsa_pms_set_version (gnutls_session_t session,
				  unsigned char major, unsigned char minor);

test_code_t
test_rsa_pms_version_check (gnutls_session_t session)
{
  int ret;
  /* here we use an arbitary version in the RSA PMS
   * to see whether to server will check this version.
   *
   * A normal server would abort this handshake.
   */
  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  _gnutls_rsa_pms_set_version (session, 5, 5);	/* use SSL 5.5 version */

  ret = do_handshake (session);
  return ret;

}

#ifdef ENABLE_ANON
test_code_t
test_anonymous (gnutls_session_t session)
{
  int ret;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":+ANON-DH:" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anon_cred);

  ret = do_handshake (session);

  if (ret == TEST_SUCCEED)
    gnutls_dh_get_pubkey (session, &pubkey);

  return ret;
}
#endif

test_code_t
test_session_resume2 (gnutls_session_t session)
{
  int ret;
  char tmp_session_id[32];
  size_t tmp_session_id_size;

  if (session == NULL)
    return TEST_IGNORE;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anon_cred);

  gnutls_session_set_data (session, session_data, session_data_size);

  memcpy (tmp_session_id, session_id, session_id_size);
  tmp_session_id_size = session_id_size;

  ret = do_handshake (session);
  if (ret == TEST_FAILED)
    return ret;

  /* check if we actually resumed the previous session */

  session_id_size = sizeof (session_id);
  gnutls_session_get_id (session, session_id, &session_id_size);

  if (session_id_size == 0)
    return TEST_FAILED;

  if (gnutls_session_is_resumed (session))
    return TEST_SUCCEED;

  if (tmp_session_id_size == session_id_size &&
      memcmp (tmp_session_id, session_id, tmp_session_id_size) == 0)
    return TEST_SUCCEED;
  else
    return TEST_FAILED;
}

extern char *hostname;

test_code_t
test_certificate (gnutls_session_t session)
{
  int ret;

  if (verbose == 0)
    return TEST_IGNORE;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  ret = do_handshake (session);
  if (ret == TEST_FAILED)
    return ret;

  printf ("\n");
  print_cert_info (session, hostname, 1);

  return TEST_SUCCEED;
}

/* A callback function to be used at the certificate selection time.
 */
static int
cert_callback (gnutls_session_t session,
	       const gnutls_datum_t * req_ca_rdn, int nreqs,
	       const gnutls_pk_algorithm_t * sign_algos,
	       int sign_algos_length, gnutls_retr_st * st)
{
  char issuer_dn[256];
  int i, ret;
  size_t len;

  if (verbose == 0)
    return -1;

  /* Print the server's trusted CAs
   */
  printf ("\n");
  if (nreqs > 0)
    printf ("- Server's trusted authorities:\n");
  else
    printf ("- Server did not send us any trusted authorities names.\n");

  /* print the names (if any) */
  for (i = 0; i < nreqs; i++)
    {
      len = sizeof (issuer_dn);
      ret = gnutls_x509_rdn_get (&req_ca_rdn[i], issuer_dn, &len);
      if (ret >= 0)
	{
	  printf ("   [%d]: ", i);
	  printf ("%s\n", issuer_dn);
	}
    }

  return -1;

}

/* Prints the trusted server's CAs. This is only
 * if the server sends a certificate request packet.
 */
test_code_t
test_server_cas (gnutls_session_t session)
{
  int ret;

  if (verbose == 0)
    return TEST_IGNORE;

  sprintf (prio_str,
	   INIT_STR ALL_CIPHERS ":" ALL_COMP ":" ALL_CERTTYPES ":%s:" ALL_MACS
	   ":" ALL_KX ":" REST, protocol_str);
  _gnutls_priority_set_direct (session, prio_str);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_certificate_client_set_retrieve_function (xcred, cert_callback);

  ret = do_handshake (session);
  gnutls_certificate_client_set_retrieve_function (xcred, NULL);

  if (ret == TEST_FAILED)
    return ret;
  return TEST_SUCCEED;
}
