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

#include <config.h>

#include "lm-data-objects.h"

static void auth_parameters_free      (LmAuthParameters    *params);
static void connect_parameters_free   (LmConnectParameters *params);

struct LmAuthParameters {
    gchar *username;
    gchar *password;
    gchar *resource;
    
    guint  ref_count;
};

struct LmConnectParameters {
    gchar *domain;
    gchar *host;
    guint  port;
    
    guint  ref_count;
};

static void
auth_parameters_free (LmAuthParameters *params)
{
    g_free (params->username);
    g_free (params->password);
    g_free (params->resource);
    
    g_slice_free (LmAuthParameters, params);
}

static void
connect_parameters_free (LmConnectParameters *params)
{
    g_free (params->domain);
    g_free (params->host);
    
    g_slice_free (LmConnectParameters, params);
}

LmAuthParameters *
lm_auth_parameters_new (const gchar *username,
                        const gchar *password,
                        const gchar *resource)
{
    LmAuthParameters *params;
    
    params = g_slice_new0 (LmAuthParameters);
    params->username = g_strdup (username);
    params->password = g_strdup (password);
    
    if (resource) {
        params->resource = g_strdup (resource);
    }
    
    params->ref_count = 1;
    
    return params;
}

const gchar *
lm_auth_parameters_get_username (LmAuthParameters *params)
{
    g_return_val_if_fail (params != NULL, NULL);
    
    return params->username;
}

const gchar *
lm_auth_parameters_get_password (LmAuthParameters *params)
{
    g_return_val_if_fail (params != NULL, NULL);
    
    return params->password;
}

const gchar *
lm_auth_parameters_get_resource (LmAuthParameters *params)
{
    g_return_val_if_fail (params != NULL, NULL);
    
    return params->resource;
}

LmAuthParameters *
lm_auth_parameters_ref (LmAuthParameters *params)
{
    g_return_val_if_fail (params != NULL, NULL);
    
    params->ref_count++;
    
    return params;
}

void
lm_auth_parameters_unref (LmAuthParameters *params)
{
    g_return_if_fail (params != NULL);
    
    params->ref_count--;

    if (params->ref_count == 0) {
        auth_parameters_free (params);
    }
}

LmConnectParameters *
lm_connect_parameters_new (const gchar *domain,
                           const gchar *host,
                           guint        port)
{
    LmConnectParameters *params;
    
    params = g_slice_new0 (LmConnectParameters);
    
    params->domain = g_strdup (domain);
    params->host   = g_strdup (host);
    params->port   = port;
    
    params->ref_count = 1;
    
    return params;
}

const gchar *
lm_connect_parameters_get_domain (LmConnectParameters *params)
{
    g_return_val_if_fail (params != NULL, NULL);
    
    return params->domain;
}

const gchar *
lm_connect_parameters_get_host (LmConnectParameters *params)
{
    g_return_val_if_fail (params != NULL, NULL);
    
    return params->host;
}

guint
lm_connect_parameters_get_port (LmConnectParameters *params)
{
    g_return_val_if_fail (params != NULL, 0);
    
    return params->port;
}

LmConnectParameters *
lm_connect_parameters_ref (LmConnectParameters *params)
{
    g_return_val_if_fail (params != NULL, NULL);
    
    params->ref_count++;
    
    return params;
}

void
lm_connect_parameters_unref (LmConnectParameters *params)
{
    g_return_if_fail (params != NULL);
    
    params->ref_count--;
    
    if (params->ref_count == 0) {
        connect_parameters_free (params);
    }
}