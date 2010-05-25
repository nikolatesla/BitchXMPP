/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2003 Imendio AB
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

#ifndef __LM_MESSAGE_HANDLER_H__
#define __LM_MESSAGE_HANDLER_H__

#if !defined (LM_INSIDE_LOUDMOUTH_H) && !defined (LM_COMPILATION)
#error "Only <loudmouth/loudmouth.h> can be included directly, this file may disappear or change contents."
#endif

#include <loudmouth/lm-connection.h>

G_BEGIN_DECLS

/**
 * LmHandleMessageFunction:
 * @handler: an #LmMessageHandler
 * @connection: an #LmConnection
 * @message: an #LmMessage
 * @user_data: user data set when creating the handler
 * 
 * The actual callback function in an #LmMessageHandler. This function is called when an incoming message arrives that haven't been handled by an handler with higher priority.
 * 
 * Returns: #LM_HANDLER_RESULT_REMOVE_MESSAGE to indicate that message has been handled, otherwise #LM_HANDLER_RESULT_ALLOW_MORE_HANDLERS.
 */
typedef LmHandlerResult (* LmHandleMessageFunction) (LmMessageHandler *handler,
                                                     LmConnection     *connection,
                                                     LmMessage        *message,
                                                     gpointer          user_data);

LmMessageHandler *lm_message_handler_new   (LmHandleMessageFunction  function,
                                            gpointer                 user_data,
                                            GDestroyNotify           notify);
void              lm_message_handler_invalidate (LmMessageHandler   *handler);
gboolean          lm_message_handler_is_valid   (LmMessageHandler   *handler);
LmMessageHandler *lm_message_handler_ref   (LmMessageHandler        *handler);
void              lm_message_handler_unref (LmMessageHandler        *handler);

G_END_DECLS

#endif /* __LM_MESSAGE_HANDLER_H__ */

