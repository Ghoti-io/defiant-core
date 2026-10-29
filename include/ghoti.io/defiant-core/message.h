/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Defiant Core.
 *
 * Ghoti.io Defiant Core is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version
 * 3 as published by the Free Software Foundation.
 *
 * Ghoti.io Defiant Core is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file message.h
 * @brief Messages that survive a redirect: a signed, session-bound,
 * shown-once queue.
 * @stability free
 *
 * A save, an error or a refusal leaves a message for the next page the same
 * session is shown, and the message widget (the `messages` widget type of
 * layout.h) shows it once. The queue is **server-side, per session**: a
 * message is a record in the environment scope of the store, sealed
 * (AES-256-GCM under a key derived from the tenant keyring for the purpose
 * `message`) so that the store holds no clear text and a record that was
 * altered, or moved to a different session's queue, another tenant's, or another
 * place in the queue, fails to open and shows nothing. The record's key
 * names the session by a keyed digest, never by the session token, which is
 * a bearer credential and is not kept.
 *
 * - **Once.** A page claims the session's messages by deleting them in one
 *   write, and shows only the ones its write deleted. Writes of the
 *   environment scope are serialised, so two requests of one session cannot
 *   both show the same message. A message claimed by a render that then
 *   failed is put back (the messages widget does so).
 * - **Not a different session's.** The session is in the key of the record and in
 *   what the seal authenticates. A principal who is not signed in has no
 *   queue.
 * - **Lifetime.** A message not shown by its expiry (::GDEFCORE_MESSAGE_LIFE
 *   seconds after it was posted, and never past the session's own expiry) is
 *   dropped by the next post or take of that session, and shows nothing.
 * - **Text.** A message is text. The widget prints it through the render
 *   layer, which escapes it; nothing here produces HTML. It should carry
 *   nothing the actor does not already see, and none of it is logged.
 *
 * The queue is bound to a request by gdefcore_message_bind(), once the
 * session token has been shown to be live. It is kept out of snapshots,
 * restores, revisions and exports with the other environment-local records.
 */

#ifndef GHOTI_IO_GDEFCORE_MESSAGE_H
#define GHOTI_IO_GDEFCORE_MESSAGE_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A message that reports something done: "Saved." */
#define GDEFCORE_MESSAGE_STATUS 1
/** A message that reports something that went wrong. */
#define GDEFCORE_MESSAGE_ERROR 2
/** A message that says the actor may not do what they asked. */
#define GDEFCORE_MESSAGE_REFUSAL 3

/** Longest message text, in bytes. A longer one is ::GDEFCORE_ERR_LIMIT. */
#define GDEFCORE_MESSAGE_TEXT_MAX 1024
/** Seconds a message waits to be shown. */
#define GDEFCORE_MESSAGE_LIFE 600
/** Most messages one session holds; posting another drops the oldest. */
#define GDEFCORE_MESSAGE_QUEUE_MAX 16

/** The messages a take claimed. Opaque. */
typedef struct GDEFCORE_Messages GDEFCORE_Messages;

/**
 * @brief One claimed message. Begins with @ref size.
 *
 * The text is borrowed from the list and valid until it is freed.
 */
typedef struct GDEFCORE_Message {
  size_t size;       ///< `sizeof(GDEFCORE_Message)`.
  int kind;          ///< A `GDEFCORE_MESSAGE_` value.
  const char * text; ///< The text, NUL-terminated.
  size_t text_len;   ///< Length of @ref text.
} GDEFCORE_Message;

/**
 * @brief Bind the session's queue to the request.
 *
 * @p session is the session token as gdefcore_account_login() made it. It
 * must be live for this tenant (gdefcore_account_session_expiry()); a token
 * that is not, or is another tenant's, binds nothing and is an error, so
 * a made-up session has no queue. The keys the queue needs are derived here and
 * kept on the request (wiped when it is destroyed); the token and the root key
 * are not kept. Binding again replaces the earlier binding.
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID or the failure of the
 *   derivation.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_message_bind(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len);

/**
 * @brief Leave a message for the next page the bound session is shown.
 *
 * @p kind is a `GDEFCORE_MESSAGE_` value. A request with no binding is
 * ::GDEFCORE_ERR_INVALID: a visitor has no queue and the caller should show
 * its message another way. Text over ::GDEFCORE_MESSAGE_TEXT_MAX is
 * ::GDEFCORE_ERR_LIMIT and posts nothing. Expired messages of the session are
 * dropped first, and when ::GDEFCORE_MESSAGE_QUEUE_MAX remain the oldest is.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_message_post(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, int kind, const char * text, size_t text_len);

/**
 * @brief Claim the bound session's messages, oldest first.
 *
 * Every message returned is gone from the queue; none is returned twice, and
 * none to a different session. An expired, altered or misplaced record is deleted
 * and shows nothing. If the claim cannot be committed nothing is returned and
 * nothing is lost. A request with no binding is ::GDEFCORE_ERR_INVALID. An
 * empty queue is ::GDEFCORE_OK with a list of none. Free @p out with
 * gdefcore_messages_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_message_take(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Messages ** out);

/** @brief How many messages. A NULL list has none. */
GDEFCORE_API size_t gdefcore_messages_count(const GDEFCORE_Messages * messages);

/**
 * @brief Message @p index. @p out->size must be `sizeof(GDEFCORE_Message)`.
 * ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_messages_item(
    const GDEFCORE_Messages * messages, size_t index, GDEFCORE_Message * out);

/** @brief Free a list, wiping the texts. NULL is ignored. */
GDEFCORE_API void gdefcore_messages_free(GDEFCORE_Messages * messages);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_MESSAGE_H */
