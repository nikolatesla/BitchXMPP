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

#ifndef __LM_FEATURE_PING_H__
#define __LM_FEATURE_PING_H__

#include <glib-object.h>

G_BEGIN_DECLS

#define LM_TYPE_FEATURE_PING            (lm_feature_ping_get_type ())
#define LM_FEATURE_PING(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), LM_TYPE_FEATURE_PING, LmFeaturePing))
#define LM_FEATURE_PING_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), LM_TYPE_FEATURE_PING, LmFeaturePingClass))
#define LM_IS_FEATURE_PING(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), LM_TYPE_FEATURE_PING))
#define LM_IS_FEATURE_PING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LM_TYPE_FEATURE_PING))
#define LM_FEATURE_PING_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), LM_TYPE_FEATURE_PING, LmFeaturePingClass))

typedef struct LmFeaturePing      LmFeaturePing;
typedef struct LmFeaturePingClass LmFeaturePingClass;

struct LmFeaturePing {
    GObject parent;
};

struct LmFeaturePingClass {
    GObjectClass parent_class;
};

GType   lm_feature_ping_get_type  (void);

void    lm_feature_ping_start     (LmFeaturePing *fp);
void    lm_feature_ping_stop      (LmFeaturePing *fp);

G_END_DECLS

#endif /* __LM_FEATURE_PING_H__ */

