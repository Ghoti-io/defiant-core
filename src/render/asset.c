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

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/asset.h>

#include <stdlib.h>
#include <string.h>

/* Split `owner/name` at its one slash. */
static int split_ref(const char * ref, size_t n, size_t * owner_len) {
  size_t i;
  size_t slash = n;
  if (ref == NULL) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (ref[i] == '/') {
      if (slash != n) {
        return 0;
      }
      slash = i;
    }
  }
  if (slash == n || slash == 0 || slash + 1 == n) {
    return 0;
  }
  *owner_len = slash;
  return 1;
}

GDEFCORE_Result gdefcore_asset_find(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * ref, size_t ref_len,
    GDEFCORE_Asset * out) {
  GDEFCORE_Host * host;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  size_t owner_len = 0;
  const GDEFCORE_Module_Declared_Asset ** items = NULL;
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || out == NULL || out->size != sizeof *out ||
      !split_ref(ref, ref_len, &owner_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  host = gdefcore_catalog_host(catalog);
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  if (host == NULL || tenant == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_module_assets(host, tenant, tenant_len, projection, &items, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = GDEFCORE_ERR_INVALID;
  for (i = 0; i < n; i++) {
    const GDEFCORE_Module_Declared_Asset * a = items[i];
    if (a->module_len == owner_len && memcmp(a->module, ref, owner_len) == 0 &&
        a->name_len == ref_len - owner_len - 1 &&
        memcmp(a->name, ref + owner_len + 1, a->name_len) == 0) {
      out->module = a->module;
      out->module_len = a->module_len;
      out->name = a->name;
      out->name_len = a->name_len;
      out->kind = a->kind;
      out->media_type = a->media_type;
      out->media_type_len = a->media_type_len;
      out->bytes = a->bytes;
      out->bytes_len = a->bytes_len;
      memcpy(out->hash, a->hash, sizeof out->hash);
      rc = GDEFCORE_OK;
      break;
    }
  }
  gdefcore_module_declared_free(host, items);
  return rc;
}

GDEFCORE_Result gdefcore_asset_url(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * ref, size_t ref_len,
    char ** out_url, size_t * out_len) {
  GDEFCORE_Asset a;
  static const char kPrefix[] = "/assets/";
  static const char kQuery[] = "?v=";
  char * buf;
  size_t at = 0;
  GDEFCORE_Result rc;
  if (out_url == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_url = NULL;
  *out_len = 0;
  memset(&a, 0, sizeof a);
  a.size = sizeof a;
  rc = gdefcore_asset_find(catalog, projection, ref, ref_len, &a);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  buf = (char *)malloc(sizeof kPrefix - 1 + ref_len + sizeof kQuery - 1 +
      GDEFCORE_ASSET_HASH_LEN + 1);
  if (buf == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(buf, kPrefix, sizeof kPrefix - 1);
  at = sizeof kPrefix - 1;
  memcpy(buf + at, ref, ref_len);
  at += ref_len;
  memcpy(buf + at, kQuery, sizeof kQuery - 1);
  at += sizeof kQuery - 1;
  memcpy(buf + at, a.hash, GDEFCORE_ASSET_HASH_LEN);
  at += GDEFCORE_ASSET_HASH_LEN;
  buf[at] = '\0';
  rc = gdefcore_text_dup(catalog, buf, at, out_url);
  free(buf);
  if (rc == GDEFCORE_OK) {
    *out_len = at;
  }
  return rc;
}
