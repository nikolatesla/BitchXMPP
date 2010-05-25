/*
 * Copyright © 2009, 2010 Codethink Limited
 * Copyright © 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the licence, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Authors: Ryan Lortie <desrt@desrt.ca>
 *          Matthias Clasen <mclasen@redhat.com>
 */

#ifndef __G_SETTINGS_BACKEND_INTERNAL_H__
#define __G_SETTINGS_BACKEND_INTERNAL_H__

#include "gsettingsbackend.h"

typedef void          (*GSettingsBackendChangedFunc)                    (GSettingsBackend    *backend,
                                                                         GObject             *target,
                                                                         const gchar         *key,
                                                                         gpointer             origin_tag);
typedef void          (*GSettingsBackendPathChangedFunc)                (GSettingsBackend    *backend,
                                                                         GObject             *target,
                                                                         const gchar         *path,
                                                                         gpointer             origin_tag);
typedef void          (*GSettingsBackendKeysChangedFunc)                (GSettingsBackend    *backend,
                                                                         GObject             *target,
                                                                         const gchar         *prefix,
                                                                         const gchar * const *names,
                                                                         gpointer             origin_tag);
typedef void          (*GSettingsBackendWritableChangedFunc)            (GSettingsBackend    *backend,
                                                                         GObject             *target,
                                                                         const gchar         *key);
typedef void          (*GSettingsBackendPathWritableChangedFunc)        (GSettingsBackend    *backend,
                                                                         GObject             *target,
                                                                         const gchar         *path);

G_GNUC_INTERNAL
void                    g_settings_backend_watch                        (GSettingsBackend                        *backend,
                                                                         GObject                                 *target,
                                                                         GMainContext                            *context,
                                                                         GSettingsBackendChangedFunc              changed,
                                                                         GSettingsBackendPathChangedFunc          path_changed,
                                                                         GSettingsBackendKeysChangedFunc          keys_changed,
                                                                         GSettingsBackendWritableChangedFunc      writable_changed,
                                                                         GSettingsBackendPathWritableChangedFunc  path_writable_changed);
G_GNUC_INTERNAL
void                    g_settings_backend_unwatch                      (GSettingsBackend                     *backend,
                                                                         GObject                              *target);

G_GNUC_INTERNAL
gboolean                        g_settings_backend_supports_context     (const gchar                          *context);
G_GNUC_INTERNAL
GSettingsBackend *              g_settings_backend_get_with_context     (const gchar                          *context);
G_GNUC_INTERNAL
GTree *                         g_settings_backend_create_tree          (void);
G_GNUC_INTERNAL
GVariant *                      g_settings_backend_read                 (GSettingsBackend                     *backend,
                                                                         const gchar                          *key,
                                                                         const GVariantType                   *expected_type,
                                                                         gboolean                              default_value);
G_GNUC_INTERNAL
gboolean                        g_settings_backend_write                (GSettingsBackend                     *backend,
                                                                         const gchar                          *key,
                                                                         GVariant                             *value,
                                                                         gpointer                              origin_tag);
G_GNUC_INTERNAL
gboolean                        g_settings_backend_write_keys           (GSettingsBackend                     *backend,
                                                                         GTree                                *tree,
                                                                         gpointer                              origin_tag);
G_GNUC_INTERNAL
void                            g_settings_backend_reset                (GSettingsBackend                     *backend,
                                                                         const gchar                          *key,
                                                                         gpointer                              origin_tag);

G_GNUC_INTERNAL
void                            g_settings_backend_reset_path           (GSettingsBackend                     *backend,
                                                                         const gchar                          *path,
                                                                         gpointer                              origin_tag);

G_GNUC_INTERNAL
gboolean                        g_settings_backend_get_writable         (GSettingsBackend                     *backend,
                                                                         const char                           *key);
G_GNUC_INTERNAL
void                            g_settings_backend_unsubscribe          (GSettingsBackend                     *backend,
                                                                         const char                           *name);
G_GNUC_INTERNAL
void                            g_settings_backend_subscribe            (GSettingsBackend                     *backend,
                                                                         const char                           *name);
G_GNUC_INTERNAL
GMainContext *                  g_settings_backend_get_active_context   (void);

#endif  /* __G_SETTINGS_BACKEND_INTERNAL_H__ */
