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
 * @file
 *
 * What a module's file and a site's file share: the spelling of a name and the
 * content hash. Not a public header.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_CORE_ASSET_UTIL_H
#define GHOTI_IO_GDEFCORE_SRC_CORE_ASSET_UTIL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/module.h>

#include <stddef.h>
#include <stdint.h>

/* Well-formed UTF-8 with no control character (newline and tab when
 * @p allow_ws is 1, carriage return as well when it is 2), no overlong form, no surrogate and nothing above U+10FFFF. */
int gdefcore_text_ok(const char * s, size_t n, int allow_ws);

/* Whether @p s is a file name: 1 to ::GDEFCORE_ASSET_NAME_MAX bytes of a-z, 0-9,
 * '.', '_' and '-', starting with a letter or a digit, with no "..". */
int gdefcore_asset_name_ok(const char * s, size_t n);

/* The content hash of @p bytes: the first 128 bits of its SHA-256, in lower-case
 * hex, NUL-terminated, in @p out (::GDEFCORE_ASSET_HASH_LEN + 1 bytes). */
GDEFCORE_Result gdefcore_asset_hash(const uint8_t * bytes, size_t n,
    char out[GDEFCORE_ASSET_HASH_LEN + 1]);

#endif
