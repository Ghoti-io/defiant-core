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
 * @file message_internal.h
 *
 * Private to src/message. Another subsystem includes message.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_MESSAGE_MESSAGE_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_MESSAGE_MESSAGE_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* What a request keeps once its session is bound: the sealing key, and the
 * keyed digest that names the session in the store (never the token). */
typedef struct Mailbox {
  uint8_t key[32];
  uint8_t digest[16];
  uint64_t session_expiry;
} Mailbox;

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SRC_MESSAGE_MESSAGE_INTERNAL_H */
