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
 * libFuzzer harness for the changeset patch parser. Any byte string is
 * either a changeset or an error. It must not crash, and a rejected patch
 * must not be something the caller has to free.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Limits limits;
  GDEFCORE_Patch files[8];
  size_t count = 0;
  size_t at = 0;
  const char tenant[] = "fuzz";
  gdefcore_limits_default(&limits);
  if (size >= 4) {
    limits.max_patch_files = (size_t)(data[0] % 9u);
    limits.max_patch_path = (size_t)(data[1] % 64u);
    limits.max_patch_file = (size_t)(data[2] % 64u);
    limits.max_patch_total = (size_t)(data[3] % 128u);
    at = 4;
  }
  if (gdefsmemory_store_create(NULL, NULL, &store) != GDEFSMEMORY_OK) {
    return 0;
  }
  if (gdefcore_catalog_open(store, (const uint8_t *)tenant, 4, &limits, NULL,
          &catalog) != GDEFCORE_OK) {
    gdefstor_store_destroy(store);
    return 0;
  }
  memset(files, 0, sizeof files);
  while (at + 2 < size && count < 8) {
    size_t path_len = data[at];
    size_t nbytes;
    at += 1;
    if (at + path_len + 1 > size) {
      break;
    }
    nbytes = data[at + path_len];
    if (at + path_len + 1 + nbytes > size) {
      break;
    }
    files[count].size = sizeof files[count];
    files[count].path = (char *)(data + at);
    files[count].path_len = path_len;
    files[count].bytes = (uint8_t *)(data + at + path_len + 1);
    files[count].len = nbytes;
    count += 1;
    at += path_len + 1 + nbytes;
  }
  if (gdefcore_changeset_parse(catalog, files, count, &limits, &changeset) ==
      GDEFCORE_OK) {
    gdefcore_changeset_destroy(changeset);
  }
  gdefcore_catalog_destroy(catalog);
  gdefstor_store_destroy(store);
  return 0;
}
