/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2007, 2008, 2010
 * Free Software Foundation, Inc.
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

int _gnutls_parse_extensions (gnutls_session_t session,
			      gnutls_ext_parse_type_t parse_type,
			      const opaque * data, int data_size);
int _gnutls_gen_extensions (gnutls_session_t session, opaque * data,
			    size_t data_size, gnutls_ext_parse_type_t);
int _gnutls_ext_init (void);
void _gnutls_ext_deinit (void);

void _gnutls_extension_list_add (gnutls_session_t session, uint16_t type);
