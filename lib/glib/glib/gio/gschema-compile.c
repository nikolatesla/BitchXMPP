/*
 * Copyright © 2010 Codethink Limited
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
 * Author: Ryan Lortie <desrt@desrt.ca>
 */

#include "config.h"

#include <gstdio.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <gi18n.h>

#include "gvdb/gvdb-builder.h"

typedef struct
{
  gboolean byteswap;

  GVariantBuilder key_options;
  GHashTable *schemas;
  gchar *schemalist_domain;

  GHashTable *schema;
  GvdbItem *schema_root;
  gchar *schema_domain;

  GString *string;

  GvdbItem *key;
  GVariant *value;
  GVariant *min, *max;
  GString *choices;
  gchar l10n;
  gchar *context;
  GVariantType *type;
} ParseState;

static gboolean allow_any_name = FALSE;

static gboolean
is_valid_keyname (const gchar  *key,
                  GError      **error)
{
  gint i;

  if (key[0] == '\0')
    {
      g_set_error_literal (error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                           "empty names are not permitted");
      return FALSE;
    }

  if (allow_any_name)
    return TRUE;

  if (!g_ascii_islower (key[0]))
    {
      g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                   "invalid name '%s': names must begin "
                   "with a lowercase letter", key);
      return FALSE;
    }

  for (i = 1; key[i]; i++)
    {
      if (key[i] != '-' &&
          !g_ascii_islower (key[i]) &&
          !g_ascii_isdigit (key[i]))
        {
          g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                       "invalid name '%s': invalid character '%c'; "
                       "only lowercase letters, numbers and dash ('-') "
                       "are permitted.", key, key[i]);
          return FALSE;
        }

      if (key[i] == '-' && key[i + 1] == '-')
        {
          g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                       "invalid name '%s': two successive dashes ('--') are "
                       "not permitted.", key);
          return FALSE;
        }
    }

  if (key[i - 1] == '-')
    {
      g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                   "invalid name '%s': the last character may not be a "
                   "dash ('-').", key);
      return FALSE;
    }

  if (i > 32)
    {
      g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                   "invalid name '%s': maximum length is 32", key);
      return FALSE;
    }

  return TRUE;
}

static gboolean
type_allows_choices (const GVariantType *type)
{
  if (g_variant_type_is_array (type) ||
      g_variant_type_is_maybe (type))
    return type_allows_choices (g_variant_type_element (type));

  return g_variant_type_equal (type, G_VARIANT_TYPE_STRING);
}

static gboolean
type_allows_range (const GVariantType *type)
{
  static const char range_types[] = "ynqiuxtd";

  return strchr (range_types, *(const char*) type) != NULL;
}

static gboolean
is_valid_choices (GVariant    *variant,
                  const gchar *choices)
{
  switch (g_variant_classify (variant))
    {
      case G_VARIANT_CLASS_MAYBE:
      case G_VARIANT_CLASS_ARRAY:
        {
          gsize i, n;
          GVariant *child;
          gboolean is_valid;

          n = g_variant_n_children (variant);
          for (i = 0; i < n; ++i)
            {
              child = g_variant_get_child_value (variant, i);
              is_valid = is_valid_choices (child, choices);
              g_variant_unref (child);

              if (!is_valid)
                return FALSE;
            }

          return TRUE;
        }

      case G_VARIANT_CLASS_STRING:
        {
          const gchar *string;

          g_variant_get (variant, "&s", &string);

          while ((choices = strstr (choices, string)) && choices[-1] != 0xff);

          return choices != NULL;
        }

      default:
        g_assert_not_reached ();
    }
}

static void
start_element (GMarkupParseContext  *context,
               const gchar          *element_name,
               const gchar         **attribute_names,
               const gchar         **attribute_values,
               gpointer              user_data,
               GError              **error)
{
  ParseState *state = user_data;
  const GSList *element_stack;
  const gchar *container;

  element_stack = g_markup_parse_context_get_element_stack (context);
  container = element_stack->next ? element_stack->next->data : NULL;

#define COLLECT(first, ...) \
  g_markup_collect_attributes (element_name,                                 \
                               attribute_names, attribute_values, error,     \
                               first, __VA_ARGS__, G_MARKUP_COLLECT_INVALID)
#define OPTIONAL   G_MARKUP_COLLECT_OPTIONAL
#define STRDUP     G_MARKUP_COLLECT_STRDUP
#define STRING     G_MARKUP_COLLECT_STRING
#define NO_ATTRS()  COLLECT (G_MARKUP_COLLECT_INVALID, NULL)

  if (container == NULL)
    {
      if (strcmp (element_name, "schemalist") == 0)
        {
          COLLECT (OPTIONAL | STRDUP,
                   "gettext-domain",
                   &state->schemalist_domain);
          return;
        }
    }
  else if (strcmp (container, "schemalist") == 0)
    {
      if (strcmp (element_name, "schema") == 0)
        {
          const gchar *id, *path;

          if (COLLECT (STRING, "id", &id,
                       OPTIONAL | STRING, "path", &path,
                       OPTIONAL | STRDUP, "gettext-domain",
                                          &state->schema_domain))
            {
              if (!g_hash_table_lookup (state->schemas, id))
                {
                  state->schema = gvdb_hash_table_new (state->schemas, id);
                  state->schema_root = gvdb_hash_table_insert (state->schema, "");

                  if (path != NULL)
                    gvdb_hash_table_insert_string (state->schema,
                                                   ".path", path);
                }
              else
                g_set_error (error, G_MARKUP_ERROR,
                             G_MARKUP_ERROR_INVALID_CONTENT,
                             "<schema id='%s'> already specified", id);
            }
          return;
        }
    }
  else if (strcmp (container, "schema") == 0)
    {
      if (strcmp (element_name, "key") == 0)
        {
          const gchar *name, *type;

          if (COLLECT (STRING, "name", &name, STRING, "type", &type))
            {
              if (!is_valid_keyname (name, error))
                return;

              if (!g_hash_table_lookup (state->schema, name))
                {
                  state->key = gvdb_hash_table_insert (state->schema, name);
                  gvdb_item_set_parent (state->key, state->schema_root);
                }
              else
                {
                  g_set_error (error, G_MARKUP_ERROR,
                               G_MARKUP_ERROR_INVALID_CONTENT,
                               "<key name='%s'> already specified", name);
                  return;
                }

              if (g_variant_type_string_is_valid (type))
                state->type = g_variant_type_new (type);
              else
                {
                  g_set_error (error, G_MARKUP_ERROR,
                               G_MARKUP_ERROR_INVALID_CONTENT,
                               "invalid GVariant type string '%s'", type);
                  return;
                }

              g_variant_builder_init (&state->key_options,
                                      G_VARIANT_TYPE ("a{sv}"));
            }

          return;
        }
      else if (strcmp (element_name, "child") == 0)
        {
          const gchar *name, *schema;

          if (COLLECT (STRING, "name", &name, STRING, "schema", &schema))
            {
              gchar *childname;

              if (!is_valid_keyname (name, error))
                return;

              childname = g_strconcat (name, "/", NULL);

              if (!g_hash_table_lookup (state->schema, childname))
                gvdb_hash_table_insert_string (state->schema, childname, schema);
              else
                g_set_error (error, G_MARKUP_ERROR,
                             G_MARKUP_ERROR_INVALID_CONTENT,
                             "<child name='%s'> already specified", name);

              g_free (childname);
              return;
            }
        }
    }
  else if (strcmp (container, "key") == 0)
    {
      if (strcmp (element_name, "default") == 0)
        {
          const gchar *l10n;

          if (COLLECT (STRING | OPTIONAL, "l10n", &l10n,
                       STRDUP | OPTIONAL, "context", &state->context))
            {
              if (l10n != NULL)
                {
                  if (!g_hash_table_lookup (state->schema, ".gettext-domain"))
                    {
                      const gchar *domain = state->schema_domain ?
                                            state->schema_domain :
                                            state->schemalist_domain;

                      if (domain == NULL)
                        {
                          g_set_error_literal (error, G_MARKUP_ERROR,
                                               G_MARKUP_ERROR_INVALID_CONTENT,
                                               "l10n requested, but no "
                                               "gettext domain given");
                          return;
                        }

                      gvdb_hash_table_insert_string (state->schema,
                                                     ".gettext-domain",
                                                     domain);

                      if (strcmp (l10n, "messages") == 0)
                        state->l10n = 'm';
                      else if (strcmp (l10n, "time") == 0)
                        state->l10n = 't';
                      else
                        {
                          g_set_error (error, G_MARKUP_ERROR,
                                       G_MARKUP_ERROR_INVALID_CONTENT,
                                       "unsupported l10n category: %s", l10n);
                          return;
                        }
                    }
                }
              else
                {
                  state->l10n = '\0';

                  if (state->context != NULL)
                    {
                      g_set_error_literal (error, G_MARKUP_ERROR,
                                           G_MARKUP_ERROR_INVALID_CONTENT,
                                           "translation context given for "
                                           " value without l10n enabled");
                      return;
                    }
                }

              state->string = g_string_new (NULL);
            }

          return;
        }
      else if (strcmp (element_name, "summary") == 0 ||
               strcmp (element_name, "description") == 0)
        {
          state->string = g_string_new (NULL);
          NO_ATTRS ();
          return;
        }
      else if (strcmp (element_name, "range") == 0)
        {
          const gchar *min_str, *max_str;

          if (!type_allows_range (state->type))
            {
              gchar *type = g_variant_type_dup_string (state->type);
              g_set_error (error, G_MARKUP_ERROR,
                          G_MARKUP_ERROR_INVALID_CONTENT,
                          "Element <%s> not allowed for keys of type \"%s\"\n",
                          element_name, type);
              g_free (type);
              return;
            }

          if (!COLLECT (STRING, "min", &min_str,
                        STRING, "max", &max_str))
            return;

          state->min = g_variant_parse (state->type, min_str, NULL, NULL, error);
          if (state->min == NULL)
            return;

          state->max = g_variant_parse (state->type, max_str, NULL, NULL, error);
          if (state->max == NULL)
            return;

          if (g_variant_compare (state->min, state->max) > 0)
            {
              g_set_error (error, G_MARKUP_ERROR,
                           G_MARKUP_ERROR_INVALID_CONTENT,
                           "Element <%s> specified minimum is greater than maxmimum",
                           element_name);
              return;
            }

          g_variant_builder_add (&state->key_options, "{sv}", "range",
                                 g_variant_new ("(@?@?)", state->min, state->max));
          return;
        }
      else if (strcmp (element_name, "choices") == 0)
        {
          if (!type_allows_choices (state->type))
            {
              gchar *type = g_variant_type_dup_string (state->type);
              g_set_error (error, G_MARKUP_ERROR,
                           G_MARKUP_ERROR_INVALID_CONTENT,
                           "Element <%s> not allowed for keys of type \"%s\"\n",
                           element_name, type);
              g_free (type);
              return;
            }

          state->choices = g_string_new ("\xff");

          NO_ATTRS ();
          return;
        }
    }
  else if (strcmp (container, "choices") == 0)
    {
      if (strcmp (element_name, "choice") == 0)
        {
          const gchar *value;

          if (COLLECT (STRING, "value", &value))
            g_string_append_printf (state->choices, "%s\xff", value);

          return;
        }
    }

  if (container)
    g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                 "Element <%s> not allowed inside <%s>\n",
                 element_name, container);
  else
    g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                 "Element <%s> not allowed at toplevel\n", element_name);
}

static void
end_element (GMarkupParseContext  *context,
             const gchar          *element_name,
             gpointer              user_data,
             GError              **error)
{
  ParseState *state = user_data;

  if (strcmp (element_name, "default") == 0)
    {
      state->value = g_variant_parse (state->type, state->string->str,
                                      NULL, NULL, error);
      if (state->value == NULL)
        return;

      if (state->l10n)
        {
          if (state->context)
            {
              gint len;

              /* Contextified messages are supported by prepending the
               * context, followed by '\004' to the start of the message
               * string.  We do that here to save GSettings the work
               * later on.
               *
               * Note: we are about to g_free() the context anyway...
               */
              len = strlen (state->context);
              state->context[len] = '\004';
              g_string_prepend_len (state->string, state->context, len + 1);
            }

          g_variant_builder_add (&state->key_options, "{sv}", "l10n",
                                 g_variant_new ("(ys)",
                                                state->l10n,
                                                state->string->str));
        }

      g_string_free (state->string, TRUE);
      state->string = NULL;
      g_free (state->context);
      state->context = NULL;
    }

  else if (strcmp (element_name, "key") == 0)
    {
      if (state->value == NULL)
        {
          g_set_error_literal (error,
                               G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                               "element <default> is required in <key>\n");
          return;
        }

      if (state->min != NULL)
        {
          if (g_variant_compare (state->value, state->min) < 0 ||
              g_variant_compare (state->value, state->max) > 0)
            {
              g_set_error (error, G_MARKUP_ERROR,
                           G_MARKUP_ERROR_INVALID_CONTENT,
                           "<default> is not contained in the specified range");
              return;
            }

          state->min = state->max = NULL;
        }
      else if (state->choices != NULL)
        {
          if (!is_valid_choices (state->value, state->choices->str))
            {
              g_set_error_literal (error, G_MARKUP_ERROR,
                                   G_MARKUP_ERROR_INVALID_CONTENT,
                                   "<default> contains string not in <choices>");
              return;
            }

          state->choices = NULL;
        }

      gvdb_item_set_value (state->key, state->value);
      gvdb_item_set_options (state->key,
                             g_variant_builder_end (&state->key_options));

      state->value = NULL;
    }

  else if (strcmp (element_name, "summary") == 0 ||
           strcmp (element_name, "description") == 0)
    {
      g_string_free (state->string, TRUE);
      state->string = NULL;
    }

  else if (strcmp (element_name, "choices") == 0)
    {
      gchar *choices;

      choices = g_string_free (state->choices, FALSE);
      g_variant_builder_add (&state->key_options, "{sv}", "choices",
                             g_variant_new_byte_array (choices, -1));
      g_free (choices);
    }
}

static void
text (GMarkupParseContext  *context,
      const gchar          *text,
      gsize                 text_len,
      gpointer              user_data,
      GError              **error)
{
  ParseState *state = user_data;
  gsize i;

  for (i = 0; i < text_len; i++)
    if (!g_ascii_isspace (text[i]))
      {
        if (state->string)
          g_string_append_len (state->string, text, text_len);

        else
          g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                       "text may not appear inside <%s>\n",
                       g_markup_parse_context_get_element (context));

        break;
      }
}

static GHashTable *
parse_gschema_files (gchar    **files,
                     gboolean   byteswap,
                     GError   **error)
{
  GMarkupParser parser = { start_element, end_element, text };
  GMarkupParseContext *context;
  ParseState state = { byteswap, };
  const gchar *filename;

  context = g_markup_parse_context_new (&parser,
                                        G_MARKUP_PREFIX_ERROR_POSITION,
                                        &state, NULL);
  state.schemas = gvdb_hash_table_new (NULL, NULL);

  while ((filename = *files++) != NULL)
    {
      gchar *contents;
      gsize size;

      if (!g_file_get_contents (filename, &contents, &size, error))
        return FALSE;

      if (!g_markup_parse_context_parse (context, contents, size, error))
        {
          g_prefix_error (error, "%s: ", filename);
          return FALSE;
        }

      if (!g_markup_parse_context_end_parse (context, error))
        {
          g_prefix_error (error, "%s: ", filename);
          return FALSE;
        }
    }

  return state.schemas;
}

int
main (int argc, char **argv)
{
  gboolean byteswap = G_BYTE_ORDER != G_LITTLE_ENDIAN;
  GError *error;
  GHashTable *table;
  GDir *dir;
  const gchar *file;
  gchar *srcdir;
  gchar *targetdir = NULL;
  gchar *target;
  gboolean uninstall = FALSE;
  gboolean dry_run = FALSE;
  gchar **schema_files = NULL;
  GOptionContext *context;
  GOptionEntry entries[] = {
    { "targetdir", 0, 0, G_OPTION_ARG_FILENAME, &targetdir, N_("where to store the gschemas.compiled file"), N_("DIRECTORY") },
    { "dry-run", 0, 0, G_OPTION_ARG_NONE, &dry_run, N_("Do not write the gschema.compiled file"), NULL },
    { "uninstall", 0, 0, G_OPTION_ARG_NONE, &uninstall, N_("Do not give error for empty directory"), NULL },
    { "allow-any-name", 0, 0, G_OPTION_ARG_NONE, &allow_any_name, N_("Do not enforce key name restrictions") },

    /* These options are only for use in the gschema-compile tests */
    { "schema-file", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME_ARRAY, &schema_files, NULL, NULL },
    { NULL }
  };

  setlocale (LC_ALL, "");

  context = g_option_context_new (N_("DIRECTORY"));
  g_option_context_set_translation_domain (context, GETTEXT_PACKAGE);
  g_option_context_set_summary (context,
    N_("Compile all GSettings schema files into a schema cache.\n"
       "Schema files are required to have the extension .gschema.xml,\n"
       "and the cache file is called gschemas.compiled."));
  g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

  error = NULL;
  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      fprintf (stderr, "%s", error->message);
      return 1;
    }

  g_option_context_free (context);

  if (!schema_files && argc != 2)
    {
      fprintf (stderr, _("You should give exactly one directory name\n"));
      return 1;
    }

  srcdir = argv[1];

  if (targetdir == NULL)
    targetdir = srcdir;

  target = g_build_filename (targetdir, "gschemas.compiled", NULL);

  if (!schema_files)
    {
      GPtrArray *files;

      files = g_ptr_array_new ();

      dir = g_dir_open (srcdir, 0, &error);
      if (dir == NULL)
        {
          fprintf (stderr, "%s\n", error->message);
          return 1;
        }

      while ((file = g_dir_read_name (dir)) != NULL)
        {
          if (g_str_has_suffix (file, ".gschema.xml"))
            g_ptr_array_add (files, g_build_filename (srcdir, file, NULL));
        }

      if (files->len == 0)
        {
          if (uninstall)
            {
              g_unlink (target);
              return 0;
            }
          else
            {
              fprintf (stderr, _("No schema files found\n"));
              return 1;
            }
        }
      g_ptr_array_add (files, NULL);

      schema_files = (char **) g_ptr_array_free (files, FALSE);
    }


  if (!(table = parse_gschema_files (schema_files, byteswap, &error)) ||
      (!dry_run && !gvdb_table_write_contents (table, target, byteswap, &error)))
    {
      fprintf (stderr, "%s\n", error->message);
      return 1;
    }

  g_free (target);

  return 0;
}
