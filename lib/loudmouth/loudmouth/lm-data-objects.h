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
#ifndef __LM_DATA_OBJECT_H__
#define __LM_DATA_OBJECT_H__

#include <glib.h>

typedef struct LmAuthParameters    LmAuthParameters;
typedef struct LmConnectParameters LmConnectParameters;

LmAuthParameters * lm_auth_parameters_new (const gchar *username,
                                           const gchar *password,
                                           const gchar *resource);

const gchar *      lm_auth_parameters_get_username (LmAuthParameters *params);
const gchar *      lm_auth_parameters_get_password (LmAuthParameters *params);
const gchar *      lm_auth_parameters_get_resource (LmAuthParameters *params);

LmAuthParameters * lm_auth_parameters_ref          (LmAuthParameters *params);
void               lm_auth_parameters_unref        (LmAuthParameters *params);

LmConnectParameters * lm_connect_parameters_new        (const gchar            *domain,
                                                        const gchar            *host,
                                                        guint                   port);

const gchar *         lm_connect_parameters_get_domain (LmConnectParameters *params);
const gchar *         lm_connect_parameters_get_host   (LmConnectParameters *params);
guint                 lm_connect_parameters_get_port   (LmConnectParameters *params);

LmConnectParameters * lm_connect_parameters_ref        (LmConnectParameters *params);
void                  lm_connect_parameters_unref      (LmConnectParameters *params);

#endif /* __LM_DATA_OBJECT_H__ */
