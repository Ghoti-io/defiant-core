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
 * @file asset.h
 * @brief Files a tenant's pages may name: stylesheets, scripts, images, fonts.
 * @stability free
 *
 * An asset is public under `<owner>/<name>`. The owner is the module that
 * ships it (GDEFCORE_Module_Asset, module.h), and it exists for a tenant only
 * while that module is enabled. A template names an asset with
 * `asset("owner/name")`, which gives `/assets/<owner>/<name>?v=<hash>`: the
 * hash is of the bytes, so the address changes when the file does and an old
 * address is never served a new file from a cache. A name that is not an asset
 * of an enabled module renders as nothing.
 */

#ifndef GHOTI_IO_GDEFCORE_ASSET_H
#define GHOTI_IO_GDEFCORE_ASSET_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief An asset as a lookup reports it. Begins with @ref size.
 *
 * The strings and bytes are borrowed from the module that ships it, and are
 * valid until that module is uninstalled or its host closed; copy them to keep
 * them longer.
 */
typedef struct GDEFCORE_Asset {
  size_t size;                ///< `sizeof(GDEFCORE_Asset)`.
  const char * module;        ///< The owner.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< File name.
  size_t name_len;            ///< Length of @ref name.
  int kind;                   ///< ::GDEFCORE_ASSET_CSS, _JS, _IMAGE or _FONT.
  const char * media_type;    ///< The full `Content-Type` value.
  size_t media_type_len;      ///< Length of @ref media_type.
  const uint8_t * bytes;      ///< The file.
  size_t bytes_len;           ///< Length of @ref bytes.
  char hash[GDEFCORE_ASSET_HASH_LEN + 1]; ///< Content hash, hex, NUL-terminated.
} GDEFCORE_Asset;

/**
 * @brief Find the asset @p ref (`owner/name`) of the catalog's tenant.
 *
 * @param catalog The catalog.
 * @param projection A staged changeset whose module enables and disables are
 *   applied first, or NULL for what is in force.
 * @param ref The reference, `owner/name`: exactly one `/`, both sides
 *   non-empty.
 * @param ref_len Length of @p ref.
 * @param out Filled with `out->size` set to `sizeof(GDEFCORE_Asset)`; any other
 *   size is ::GDEFCORE_ERR_INVALID.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when there is no such asset
 *   for the tenant (including a reference that is not well formed).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_asset_find(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * ref, size_t ref_len,
    GDEFCORE_Asset * out);

/**
 * @brief The address a page uses for @p ref: `/assets/owner/name?v=hash`.
 *
 * Free @p out_url with gdefcore_text_free().
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID when there is no such asset, or
 *   ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_asset_url(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * ref, size_t ref_len,
    char ** out_url, size_t * out_len);

#ifdef __cplusplus
}
#endif

#endif
