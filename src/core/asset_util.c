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

#include "asset_util.h"

#include <ghoti.io/security/sha256.h>

/* Well-formed UTF-8 with no control character (newline and tab when @p allow_ws
 * is 1, and carriage return too when it is 2), no
 * overlong form, no surrogate and nothing above U+10FFFF. */
int gdefcore_text_ok(const char * s, size_t n, int allow_ws) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t more;
    uint32_t cp;
    uint32_t min;
    size_t k;
    if (c < 0x20 || c == 0x7f) {
      if ((allow_ws && (c == '\n' || c == '\t')) || (allow_ws > 1 && c == '\r')) {
        i += 1;
        continue;
      }
      return 0;
    }
    if (c < 0x80) {
      i += 1;
      continue;
    }
    if (c >= 0xc2 && c <= 0xdf) {
      more = 1;
      cp = c & 0x1f;
      min = 0x80;
    } else if ((c & 0xf0) == 0xe0) {
      more = 2;
      cp = c & 0x0f;
      min = 0x800;
    } else if (c >= 0xf0 && c <= 0xf4) {
      more = 3;
      cp = c & 0x07;
      min = 0x10000;
    } else {
      return 0;
    }
    if (i + more >= n) {
      return 0;
    }
    for (k = 1; k <= more; k++) {
      unsigned char e = (unsigned char)s[i + k];
      if ((e & 0xc0) != 0x80) {
        return 0;
      }
      cp = (cp << 6) | (e & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      return 0;
    }
    i += more + 1;
  }
  return 1;
}

int gdefcore_asset_name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > GDEFCORE_ASSET_NAME_MAX) {
    return 0;
  }
  if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9'))) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
            c == '_' || c == '-')) {
      return 0;
    }
    if (c == '.' && i + 1 < n && s[i + 1] == '.') {
      return 0;
    }
  }
  return 1;
}

GDEFCORE_Result gdefcore_asset_hash(const uint8_t * bytes, size_t n,
    char out[GDEFCORE_ASSET_HASH_LEN + 1]) {
  static const char kHex[] = "0123456789abcdef";
  GSEC_Sha256 ctx;
  unsigned char dig[GSEC_SHA256_DIGEST_LEN];
  size_t k;
  if (gsec_sha256_init(&ctx) != GSEC_OK ||
      (n > 0 && gsec_sha256_update(&ctx, bytes, n) != GSEC_OK) ||
      gsec_sha256_final(&ctx, dig) != GSEC_OK) {
    return GDEFCORE_ERR_INTERNAL;
  }
  for (k = 0; k < GDEFCORE_ASSET_HASH_LEN / 2; k++) {
    out[k * 2] = kHex[dig[k] >> 4];
    out[k * 2 + 1] = kHex[dig[k] & 0x0fu];
  }
  out[GDEFCORE_ASSET_HASH_LEN] = '\0';
  return GDEFCORE_OK;
}
