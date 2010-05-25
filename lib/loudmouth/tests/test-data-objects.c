/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2008 Imendio AB
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <stdlib.h>
#include <glib.h>

#include "loudmouth/lm-data-objects.h"

static void
test_auth_parameters ()
{
    LmAuthParameters *params;
    
    params = lm_auth_parameters_new ("my_user", "my_pass", "my_resource");
    g_assert (g_strcmp0 ("my_user", lm_auth_parameters_get_username (params)) == 0);
    g_assert (g_strcmp0 ("my_pass", lm_auth_parameters_get_password (params)) == 0);
    g_assert (g_strcmp0 ("my_resource", lm_auth_parameters_get_resource (params)) == 0);
    
    lm_auth_parameters_unref (params);
}

static void
test_connect_parameters ()
{
    LmConnectParameters *params;
    
    params = lm_connect_parameters_new ("my_domain", "my_host", 5223);
    g_assert (g_strcmp0 ("my_domain", lm_connect_parameters_get_domain (params)) == 0);
    g_assert (g_strcmp0 ("my_host", lm_connect_parameters_get_host (params)) == 0);
    g_assert (5223 == lm_connect_parameters_get_port (params));
    
    lm_connect_parameters_unref (params);
}

int 
main (int argc, char **argv)
{
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/data_objects/auth_paramters", test_auth_parameters);
    g_test_add_func ("/data_objects/connect_parameters", test_connect_parameters);

    return g_test_run ();
}

