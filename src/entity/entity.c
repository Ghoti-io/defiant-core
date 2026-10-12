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
 * Entities, revisions and changesets. The row id is the port key. The
 * public id stays in the document. Apply is one write.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-storage/projection.h>
#include <ghoti.io/defiant-storage/revision.h>
#include <ghoti.io/regex/compile.h>
#include <ghoti.io/security/random.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entity_internal.h"

static const char kAlpha[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static void limits_fill(GDEFCORE_Limits * limits) {
  limits->max_patch_files = 128;
  limits->max_patch_path = 256;
  limits->max_patch_file = 65536;
  limits->max_patch_total = 1048576;
  limits->max_fields = 64;
  limits->max_values = 32;
  limits->max_value_bytes = 4096;
  limits->max_languages = 32;
}

void gdefcore_limits_default(GDEFCORE_Limits * limits) {
  if (limits == NULL) {
    return;
  }
  limits_fill(limits);
}

static const GDEFCORE_Allocator * use_alloc(const GDEFCORE_Allocator * alloc) {
  return alloc == NULL ? gdefcore_allocator_default() : alloc;
}

static void * mem(const GDEFCORE_Allocator * alloc, size_t n) {
  if (n == 0) {
    n = 1;
  }
  return gcu_allocator_malloc(alloc, n);
}

static void * mem0(const GDEFCORE_Allocator * alloc, size_t n) {
  void * p = mem(alloc, n);
  if (p != NULL) {
    memset(p, 0, n);
  }
  return p;
}

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static char * dup_span(const GDEFCORE_Allocator * alloc, const char * p,
    size_t n) {
  char * out = (char *)mem(alloc, n + 1);
  if (out == NULL) {
    return NULL;
  }
  if (n > 0 && p != NULL) {
    memcpy(out, p, n);
  }
  out[n] = '\0';
  return out;
}

static void text_clear(const GDEFCORE_Allocator * alloc, GDEFCORE_Text * t) {
  gcu_allocator_free(alloc, t->p);
  t->p = NULL;
  t->n = 0;
}

static GDEFCORE_Result text_set(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Text * t, const char * p, size_t n) {
  char * copy = dup_span(alloc, p, n);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  text_clear(alloc, t);
  t->p = copy;
  t->n = n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result map_stor(GDEFSTOR_Result rc) {
  switch (rc) {
  case GDEFSTOR_OK:
    return GDEFCORE_OK;
  case GDEFSTOR_ERR_LIMIT:
    return GDEFCORE_ERR_LIMIT;
  case GDEFSTOR_ERR_OOM:
    return GDEFCORE_ERR_OOM;
  case GDEFSTOR_ERR_CORRUPT:
    return GDEFCORE_ERR_CORRUPT;
  case GDEFSTOR_ERR_INVALID:
    return GDEFCORE_ERR_INVALID;
  default:
    return GDEFCORE_ERR_IO;
  }
}

static int u64_put(uint64_t v, char * buf, size_t cap, size_t * out_n) {
  int n = snprintf(buf, cap, "%llu", (unsigned long long)v);
  if (n <= 0 || (size_t)n >= cap) {
    return 0;
  }
  *out_n = (size_t)n;
  return 1;
}

static int u64_get(const char * s, size_t n, uint64_t * out) {
  uint64_t v = 0;
  size_t i;
  if (n == 0) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    unsigned digit;
    if (s[i] < '0' || s[i] > '9') {
      return 0;
    }
    digit = (unsigned)(s[i] - '0');
    if (v > (UINT64_MAX - digit) / 10u) {
      return 0;
    }
    v = v * 10u + digit;
  }
  *out = v;
  return 1;
}

static uint16_t crc10(const uint8_t * p, size_t n) {
  uint16_t crc = 0;
  size_t i;
  int b;
  for (i = 0; i < n; i++) {
    crc = (uint16_t)(crc ^ ((uint16_t)p[i] << 2));
    for (b = 0; b < 8; b++) {
      if ((crc & 0x200u) != 0) {
        crc = (uint16_t)((crc << 1) ^ 0x233u);
      } else {
        crc = (uint16_t)(crc << 1);
      }
      crc = (uint16_t)(crc & 0x3ffu);
    }
  }
  return crc;
}

static int alpha_index(char c) {
  const char * found = strchr(kAlpha, c);
  if (found == NULL) {
    return -1;
  }
  return (int)(found - kAlpha);
}

GDEFCORE_Result gdefcore_id_encode(const uint8_t raw[16],
    char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  unsigned acc = 0;
  int bits = 2;
  int k = 0;
  int i;
  uint16_t check;
  if (raw == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < 16; i++) {
    acc = (acc << 8) | raw[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out[k++] = kAlpha[(acc >> bits) & 31u];
    }
  }
  check = crc10(raw, 16);
  out[k++] = kAlpha[(check >> 5) & 31u];
  out[k++] = kAlpha[check & 31u];
  out[k] = '\0';
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_id_generate(char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  uint8_t raw[16];
  GSEC_Result rc;
  if (out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gsec_random_bytes(raw, sizeof raw, NULL);
  if (rc == GSEC_ERR_LIMIT) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (rc != GSEC_OK) {
    return GDEFCORE_ERR_IO;
  }
  return gdefcore_id_encode(raw, out);
}

static int decode_body(const char symbols[26], uint8_t raw[16]) {
  uint8_t bits[17];
  int pos = 0;
  int i;
  int b;
  memset(bits, 0, sizeof bits);
  for (i = 0; i < 26; i++) {
    int v = alpha_index(symbols[i]);
    if (v < 0) {
      return 0;
    }
    for (b = 4; b >= 0; b--) {
      if ((v & (1 << b)) != 0) {
        bits[pos / 8] = (uint8_t)(bits[pos / 8] | (uint8_t)(1u << (7 - (pos % 8))));
      }
      pos += 1;
    }
  }
  if ((bits[0] & 0xc0u) != 0) {
    return 0;
  }
  for (i = 0; i < 16; i++) {
    int src = 2 + i * 8;
    unsigned value = 0;
    for (b = 0; b < 8; b++) {
      int at = src + b;
      unsigned bit = (bits[at / 8] >> (7 - (at % 8))) & 1u;
      value = (value << 1) | bit;
    }
    raw[i] = (uint8_t)value;
  }
  return 1;
}

GDEFCORE_Result gdefcore_id_canonical(const char * text, size_t len,
    char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char folded[GDEFCORE_PUBLIC_ID_LEN];
  uint8_t raw[16];
  size_t n = 0;
  size_t i;
  uint16_t check;
  int hi;
  int lo;
  if (text == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)text[i];
    if (c == '-') {
      continue;
    }
    if (c >= 'a' && c <= 'z') {
      c = (unsigned char)(c - 'a' + 'A');
    }
    if (c == 'I' || c == 'L') {
      c = '1';
    } else if (c == 'O') {
      c = '0';
    }
    if (n >= GDEFCORE_PUBLIC_ID_LEN) {
      return GDEFCORE_ERR_INVALID;
    }
    folded[n++] = (char)c;
  }
  if (n != GDEFCORE_PUBLIC_ID_LEN) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!decode_body(folded, raw)) {
    return GDEFCORE_ERR_INVALID;
  }
  check = crc10(raw, 16);
  hi = alpha_index(folded[26]);
  lo = alpha_index(folded[27]);
  if (hi < 0 || lo < 0 || hi != ((check >> 5) & 31) || lo != (check & 31)) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_id_encode(raw, out);
}

static int utf8_ok(const uint8_t * s, size_t n) {
  size_t i = 0;
  while (i < n) {
    uint8_t c = s[i];
    size_t need;
    uint32_t cp;
    size_t j;
    uint32_t min;
    if (c <= 0x7fu) {
      i += 1;
      continue;
    }
    if ((c & 0xe0u) == 0xc0u) {
      need = 2;
      cp = c & 0x1fu;
      min = 0x80u;
    } else if ((c & 0xf0u) == 0xe0u) {
      need = 3;
      cp = c & 0x0fu;
      min = 0x800u;
    } else if ((c & 0xf8u) == 0xf0u) {
      need = 4;
      cp = c & 0x07u;
      min = 0x10000u;
    } else {
      return 0;
    }
    if (i + need > n) {
      return 0;
    }
    for (j = 1; j < need; j++) {
      if ((s[i + j] & 0xc0u) != 0x80u) {
        return 0;
      }
      cp = (cp << 6) | (s[i + j] & 0x3fu);
    }
    if (cp < min || cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) {
      return 0;
    }
    i += need;
  }
  return 1;
}

static int path_ok(const char * path, size_t n) {
  size_t i;
  size_t start = 0;
  if (path == NULL || n == 0 || path[0] == '/' || path[0] == '\\') {
    return 0;
  }
  for (i = 0; i <= n; i++) {
    if (i == n || path[i] == '/') {
      size_t len = i - start;
      if (len == 0) {
        return 0;
      }
      if (len == 1 && path[start] == '.') {
        return 0;
      }
      if (len == 2 && path[start] == '.' && path[start + 1] == '.') {
        return 0;
      }
      start = i + 1;
    } else if (path[i] == '\\' || path[i] == '\0') {
      return 0;
    }
  }
  return 1;
}

static int module_name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > 64) {
    return 0;
  }
  if (s[0] < 'a' || s[0] > 'z') {
    return 0;
  }
  for (i = 1; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
      return 0;
    }
  }
  return 1;
}

static int machine_ok(const char * s, size_t n) {
  size_t dot = n;
  size_t i;
  if (n < 3 || n > 128) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (c == '.') {
      if (dot != n) {
        return 0;
      }
      dot = i;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_')) {
      return 0;
    }
  }
  return dot > 0 && dot + 1 < n;
}

static int field_name_ok(const char * s, size_t n) {
  size_t i;
  if (n == 0 || n > 64) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_')) {
      return 0;
    }
  }
  return 1;
}

static int lang_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > 35) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-')) {
      return 0;
    }
  }
  return 1;
}

static int builtin_name(const char * s, size_t n) {
  return span_eq(s, n, "core.entity_type", 16) ||
         span_eq(s, n, "core.changeset", 14);
}

static void doc_free(const GDEFCORE_Allocator * alloc, GDEFCORE_Doc * doc) {
  size_t i;
  size_t j;
  size_t k;
  if (doc == NULL) {
    return;
  }
  for (i = 0; i < doc->nlangs; i++) {
    for (j = 0; j < doc->langs[i].nfields; j++) {
      for (k = 0; k < doc->langs[i].fields[j].nvals; k++) {
        text_clear(alloc, &doc->langs[i].fields[j].vals[k]);
      }
      gcu_allocator_free(alloc, doc->langs[i].fields[j].vals);
      text_clear(alloc, &doc->langs[i].fields[j].name);
    }
    gcu_allocator_free(alloc, doc->langs[i].fields);
    text_clear(alloc, &doc->langs[i].lang);
  }
  gcu_allocator_free(alloc, doc->langs);
  doc->langs = NULL;
  doc->nlangs = 0;
}

static void decls_free(const GDEFCORE_Allocator * alloc, GDEFCORE_Decl * decls,
    size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    text_clear(alloc, &decls[i].name);
    text_clear(alloc, &decls[i].pattern);
  }
  gcu_allocator_free(alloc, decls);
}

static void op_free(const GDEFCORE_Allocator * alloc, GDEFCORE_Op * op) {
  text_clear(alloc, &op->id);
  text_clear(alloc, &op->type_name);
  text_clear(alloc, &op->machine);
  doc_free(alloc, &op->staged);
  doc_free(alloc, &op->base);
  decls_free(alloc, op->decls, op->ndecls);
  op->decls = NULL;
  op->ndecls = 0;
}

static GDEFCORE_Result decls_copy(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Decl * in, size_t n, GDEFCORE_Decl ** out) {
  GDEFCORE_Decl * copy;
  size_t i;
  *out = NULL;
  if (n == 0) {
    return GDEFCORE_OK;
  }
  copy = (GDEFCORE_Decl *)mem0(alloc, n * sizeof *copy);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    if (text_set(alloc, &copy[i].name, in[i].name.p, in[i].name.n) !=
        GDEFCORE_OK) {
      decls_free(alloc, copy, i + 1);
      return GDEFCORE_ERR_OOM;
    }
    copy[i].required = in[i].required;
    copy[i].many = in[i].many;
    copy[i].personal = in[i].personal;
    copy[i].min_len = in[i].min_len;
    copy[i].max_len = in[i].max_len;
    copy[i].has_range = in[i].has_range;
    copy[i].range_min = in[i].range_min;
    copy[i].range_max = in[i].range_max;
    if (in[i].pattern.n > 0 &&
        text_set(alloc, &copy[i].pattern, in[i].pattern.p, in[i].pattern.n) !=
            GDEFCORE_OK) {
      decls_free(alloc, copy, i + 1);
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = copy;
  return GDEFCORE_OK;
}

static GDEFCORE_Result doc_clone(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Doc * in, GDEFCORE_Doc * out) {
  size_t i;
  size_t j;
  size_t k;
  memset(out, 0, sizeof *out);
  if (in->nlangs == 0) {
    return GDEFCORE_OK;
  }
  out->langs = (GDEFCORE_Lang *)mem0(alloc, in->nlangs * sizeof *out->langs);
  if (out->langs == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  out->nlangs = in->nlangs;
  for (i = 0; i < in->nlangs; i++) {
    GDEFCORE_Lang * dst = &out->langs[i];
    const GDEFCORE_Lang * src = &in->langs[i];
    if (text_set(alloc, &dst->lang, src->lang.p, src->lang.n) != GDEFCORE_OK) {
      doc_free(alloc, out);
      return GDEFCORE_ERR_OOM;
    }
    if (src->nfields == 0) {
      continue;
    }
    dst->fields =
        (GDEFCORE_Vals *)mem0(alloc, src->nfields * sizeof *dst->fields);
    if (dst->fields == NULL) {
      doc_free(alloc, out);
      return GDEFCORE_ERR_OOM;
    }
    dst->nfields = src->nfields;
    for (j = 0; j < src->nfields; j++) {
      if (text_set(alloc, &dst->fields[j].name, src->fields[j].name.p,
              src->fields[j].name.n) != GDEFCORE_OK) {
        doc_free(alloc, out);
        return GDEFCORE_ERR_OOM;
      }
      if (src->fields[j].nvals == 0) {
        continue;
      }
      dst->fields[j].vals = (GDEFCORE_Text *)mem0(
          alloc, src->fields[j].nvals * sizeof *dst->fields[j].vals);
      if (dst->fields[j].vals == NULL) {
        doc_free(alloc, out);
        return GDEFCORE_ERR_OOM;
      }
      dst->fields[j].nvals = src->fields[j].nvals;
      for (k = 0; k < src->fields[j].nvals; k++) {
        if (text_set(alloc, &dst->fields[j].vals[k], src->fields[j].vals[k].p,
                src->fields[j].vals[k].n) != GDEFCORE_OK) {
          doc_free(alloc, out);
          return GDEFCORE_ERR_OOM;
        }
      }
    }
  }
  return GDEFCORE_OK;
}

typedef struct Grow {
  const GDEFCORE_Allocator * alloc;
  char * p;
  size_t n;
  size_t cap;
  int oom;
} Grow;

static void grow_add(Grow * g, const char * s, size_t n) {
  size_t need;
  char * next;
  if (g->oom || n == 0) {
    return;
  }
  if (g->n > SIZE_MAX - n - 1) {
    g->oom = 1;
    return;
  }
  need = g->n + n + 1;
  if (need > g->cap) {
    size_t cap = g->cap == 0 ? 64 : g->cap;
    while (cap < need) {
      if (cap > SIZE_MAX / 2) {
        g->oom = 1;
        return;
      }
      cap *= 2;
    }
    next = (char *)gcu_allocator_realloc(g->alloc, g->p, cap);
    if (next == NULL) {
      g->oom = 1;
      return;
    }
    g->p = next;
    g->cap = cap;
  }
  memcpy(g->p + g->n, s, n);
  g->n += n;
  g->p[g->n] = '\0';
}

static void grow_json(Grow * g, const char * s, size_t n) {
  size_t i;
  grow_add(g, "\"", 1);
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    char esc[8];
    int en;
    if (c == '"' || c == '\\') {
      esc[0] = '\\';
      esc[1] = (char)c;
      grow_add(g, esc, 2);
    } else if (c < 0x20u) {
      en = snprintf(esc, sizeof esc, "\\u%04x", c);
      if (en > 0) {
        grow_add(g, esc, (size_t)en);
      }
    } else {
      esc[0] = (char)c;
      grow_add(g, esc, 1);
    }
  }
  grow_add(g, "\"", 1);
}

static GDEFCORE_Result doc_json(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Doc * doc, char ** out, size_t * out_len) {
  Grow g;
  size_t i;
  size_t j;
  size_t k;
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  grow_add(&g, "{", 1);
  for (i = 0; i < doc->nlangs; i++) {
    if (i > 0) {
      grow_add(&g, ",", 1);
    }
    grow_json(&g, doc->langs[i].lang.p, doc->langs[i].lang.n);
    grow_add(&g, ":{", 2);
    for (j = 0; j < doc->langs[i].nfields; j++) {
      if (j > 0) {
        grow_add(&g, ",", 1);
      }
      grow_json(&g, doc->langs[i].fields[j].name.p,
          doc->langs[i].fields[j].name.n);
      grow_add(&g, ":[", 2);
      for (k = 0; k < doc->langs[i].fields[j].nvals; k++) {
        if (k > 0) {
          grow_add(&g, ",", 1);
        }
        grow_json(&g, doc->langs[i].fields[j].vals[k].p,
            doc->langs[i].fields[j].vals[k].n);
      }
      grow_add(&g, "]", 1);
    }
    grow_add(&g, "}", 1);
  }
  grow_add(&g, "}", 1);
  if (g.oom) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  *out = g.p;
  *out_len = g.n;
  return GDEFCORE_OK;
}

typedef struct Scan {
  const char * s;
  size_t n;
  size_t i;
} Scan;

static void skip_ws(Scan * sc) {
  while (sc->i < sc->n) {
    char c = sc->s[sc->i];
    if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
      break;
    }
    sc->i += 1;
  }
}

static int scan_take(Scan * sc, char expect) {
  skip_ws(sc);
  if (sc->i >= sc->n || sc->s[sc->i] != expect) {
    return 0;
  }
  sc->i += 1;
  return 1;
}

static int scan_string(const GDEFCORE_Allocator * alloc, Scan * sc,
    GDEFCORE_Text * out) {
  Grow g;
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  memset(out, 0, sizeof *out);
  skip_ws(sc);
  if (sc->i >= sc->n || sc->s[sc->i] != '"') {
    return 0;
  }
  sc->i += 1;
  while (sc->i < sc->n) {
    unsigned char c = (unsigned char)sc->s[sc->i++];
    char one[4];
    if (c == '"') {
      if (g.oom) {
        gcu_allocator_free(alloc, g.p);
        return 0;
      }
      if (g.p == NULL) {
        g.p = dup_span(alloc, "", 0);
        if (g.p == NULL) {
          return 0;
        }
      }
      out->p = g.p;
      out->n = g.n;
      return 1;
    }
    if (c == '\\') {
      if (sc->i >= sc->n) {
        break;
      }
      c = (unsigned char)sc->s[sc->i++];
      if (c == 'u') {
        unsigned value = 0;
        int h;
        if (sc->i + 4 > sc->n) {
          break;
        }
        for (h = 0; h < 4; h++) {
          char d = sc->s[sc->i++];
          value <<= 4;
          if (d >= '0' && d <= '9') {
            value |= (unsigned)(d - '0');
          } else if (d >= 'a' && d <= 'f') {
            value |= (unsigned)(d - 'a' + 10);
          } else if (d >= 'A' && d <= 'F') {
            value |= (unsigned)(d - 'A' + 10);
          } else {
            gcu_allocator_free(alloc, g.p);
            return 0;
          }
        }
        if (value > 0x7fu) {
          gcu_allocator_free(alloc, g.p);
          return 0;
        }
        one[0] = (char)value;
        grow_add(&g, one, 1);
        continue;
      }
      if (c == '"' || c == '\\' || c == '/') {
        one[0] = (char)c;
      } else if (c == 'n') {
        one[0] = '\n';
      } else if (c == 't') {
        one[0] = '\t';
      } else {
        gcu_allocator_free(alloc, g.p);
        return 0;
      }
      grow_add(&g, one, 1);
      continue;
    }
    if (c < 0x20u) {
      break;
    }
    one[0] = (char)c;
    grow_add(&g, one, 1);
  }
  gcu_allocator_free(alloc, g.p);
  return 0;
}

static GDEFCORE_Result doc_parse(const GDEFCORE_Allocator * alloc,
    const char * json, size_t len, GDEFCORE_Doc * doc) {
  Scan sc;
  memset(doc, 0, sizeof *doc);
  sc.s = json;
  sc.n = len;
  sc.i = 0;
  if (!scan_take(&sc, '{')) {
    return GDEFCORE_ERR_CORRUPT;
  }
  skip_ws(&sc);
  if (sc.i < sc.n && sc.s[sc.i] == '}') {
    return GDEFCORE_OK;
  }
  for (;;) {
    GDEFCORE_Lang * langs;
    GDEFCORE_Lang * lang;
    if (doc->nlangs > 100000u) {
      doc_free(alloc, doc);
      return GDEFCORE_ERR_LIMIT;
    }
    langs = (GDEFCORE_Lang *)gcu_allocator_realloc(
        alloc, doc->langs, (doc->nlangs + 1) * sizeof *langs);
    if (langs == NULL) {
      doc_free(alloc, doc);
      return GDEFCORE_ERR_OOM;
    }
    doc->langs = langs;
    lang = &doc->langs[doc->nlangs];
    memset(lang, 0, sizeof *lang);
    doc->nlangs += 1;
    if (!scan_string(alloc, &sc, &lang->lang) || !scan_take(&sc, ':') ||
        !scan_take(&sc, '{')) {
      doc_free(alloc, doc);
      return GDEFCORE_ERR_CORRUPT;
    }
    skip_ws(&sc);
    if (!(sc.i < sc.n && sc.s[sc.i] == '}')) {
      for (;;) {
        GDEFCORE_Vals * fields;
        GDEFCORE_Vals * field;
        fields = (GDEFCORE_Vals *)gcu_allocator_realloc(
            alloc, lang->fields, (lang->nfields + 1) * sizeof *fields);
        if (fields == NULL) {
          doc_free(alloc, doc);
          return GDEFCORE_ERR_OOM;
        }
        lang->fields = fields;
        field = &lang->fields[lang->nfields];
        memset(field, 0, sizeof *field);
        lang->nfields += 1;
        if (!scan_string(alloc, &sc, &field->name) || !scan_take(&sc, ':') ||
            !scan_take(&sc, '[')) {
          doc_free(alloc, doc);
          return GDEFCORE_ERR_CORRUPT;
        }
        skip_ws(&sc);
        if (!(sc.i < sc.n && sc.s[sc.i] == ']')) {
          for (;;) {
            GDEFCORE_Text * vals;
            vals = (GDEFCORE_Text *)gcu_allocator_realloc(
                alloc, field->vals, (field->nvals + 1) * sizeof *vals);
            if (vals == NULL) {
              doc_free(alloc, doc);
              return GDEFCORE_ERR_OOM;
            }
            field->vals = vals;
            memset(&field->vals[field->nvals], 0, sizeof *field->vals);
            if (!scan_string(alloc, &sc, &field->vals[field->nvals])) {
              doc_free(alloc, doc);
              return GDEFCORE_ERR_CORRUPT;
            }
            field->nvals += 1;
            skip_ws(&sc);
            if (sc.i < sc.n && sc.s[sc.i] == ',') {
              sc.i += 1;
              continue;
            }
            break;
          }
        }
        if (!scan_take(&sc, ']')) {
          doc_free(alloc, doc);
          return GDEFCORE_ERR_CORRUPT;
        }
        skip_ws(&sc);
        if (sc.i < sc.n && sc.s[sc.i] == ',') {
          sc.i += 1;
          continue;
        }
        break;
      }
    }
    if (!scan_take(&sc, '}')) {
      doc_free(alloc, doc);
      return GDEFCORE_ERR_CORRUPT;
    }
    skip_ws(&sc);
    if (sc.i < sc.n && sc.s[sc.i] == ',') {
      sc.i += 1;
      continue;
    }
    break;
  }
  if (!scan_take(&sc, '}')) {
    doc_free(alloc, doc);
    return GDEFCORE_ERR_CORRUPT;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Vals * doc_field(GDEFCORE_Doc * doc, const char * lang,
    size_t lang_len, const char * field, size_t field_len) {
  size_t i;
  size_t j;
  for (i = 0; i < doc->nlangs; i++) {
    if (!span_eq(doc->langs[i].lang.p, doc->langs[i].lang.n, lang, lang_len)) {
      continue;
    }
    for (j = 0; j < doc->langs[i].nfields; j++) {
      if (span_eq(doc->langs[i].fields[j].name.p,
              doc->langs[i].fields[j].name.n, field, field_len)) {
        return &doc->langs[i].fields[j];
      }
    }
  }
  return NULL;
}

static GDEFCORE_Result doc_set_field(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Doc * doc, const GDEFCORE_Limits * limits, const char * lang,
    size_t lang_len, const char * field, size_t field_len,
    const char * const * texts, const size_t * lens, size_t count) {
  size_t i;
  GDEFCORE_Lang * bucket = NULL;
  GDEFCORE_Vals * slot = NULL;
  GDEFCORE_Text * vals;
  for (i = 0; i < doc->nlangs; i++) {
    if (span_eq(doc->langs[i].lang.p, doc->langs[i].lang.n, lang, lang_len)) {
      bucket = &doc->langs[i];
      break;
    }
  }
  if (bucket == NULL) {
    GDEFCORE_Lang * langs;
    if (doc->nlangs >= limits->max_languages) {
      return GDEFCORE_ERR_LIMIT;
    }
    langs = (GDEFCORE_Lang *)gcu_allocator_realloc(
        alloc, doc->langs, (doc->nlangs + 1) * sizeof *langs);
    if (langs == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    doc->langs = langs;
    bucket = &doc->langs[doc->nlangs];
    memset(bucket, 0, sizeof *bucket);
    if (text_set(alloc, &bucket->lang, lang, lang_len) != GDEFCORE_OK) {
      return GDEFCORE_ERR_OOM;
    }
    doc->nlangs += 1;
  }
  for (i = 0; i < bucket->nfields; i++) {
    if (span_eq(bucket->fields[i].name.p, bucket->fields[i].name.n, field,
            field_len)) {
      slot = &bucket->fields[i];
      break;
    }
  }
  if (slot == NULL) {
    GDEFCORE_Vals * fields;
    if (bucket->nfields >= limits->max_fields) {
      return GDEFCORE_ERR_LIMIT;
    }
    fields = (GDEFCORE_Vals *)gcu_allocator_realloc(
        alloc, bucket->fields, (bucket->nfields + 1) * sizeof *fields);
    if (fields == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    bucket->fields = fields;
    slot = &bucket->fields[bucket->nfields];
    memset(slot, 0, sizeof *slot);
    if (text_set(alloc, &slot->name, field, field_len) != GDEFCORE_OK) {
      return GDEFCORE_ERR_OOM;
    }
    bucket->nfields += 1;
  }
  vals = (GDEFCORE_Text *)mem0(alloc, (count == 0 ? 1 : count) * sizeof *vals);
  if (vals == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < count; i++) {
    if (text_set(alloc, &vals[i], texts[i], lens[i]) != GDEFCORE_OK) {
      size_t k;
      for (k = 0; k <= i; k++) {
        text_clear(alloc, &vals[k]);
      }
      gcu_allocator_free(alloc, vals);
      return GDEFCORE_ERR_OOM;
    }
  }
  for (i = 0; i < slot->nvals; i++) {
    text_clear(alloc, &slot->vals[i]);
  }
  gcu_allocator_free(alloc, slot->vals);
  slot->vals = vals;
  slot->nvals = count;
  return GDEFCORE_OK;
}

static int doc_has_required(const GDEFCORE_Doc * doc, const GDEFCORE_Decl * decls,
    size_t ndecls) {
  size_t i;
  size_t j;
  size_t d;
  if (doc->nlangs == 0) {
    for (d = 0; d < ndecls; d++) {
      if (decls[d].required) {
        return 0;
      }
    }
    return 1;
  }
  for (i = 0; i < doc->nlangs; i++) {
    for (d = 0; d < ndecls; d++) {
      int found = 0;
      if (!decls[d].required) {
        continue;
      }
      for (j = 0; j < doc->langs[i].nfields; j++) {
        if (span_eq(doc->langs[i].fields[j].name.p,
                doc->langs[i].fields[j].name.n, decls[d].name.p,
                decls[d].name.n) &&
            doc->langs[i].fields[j].nvals > 0) {
          found = 1;
          break;
        }
      }
      if (!found) {
        return 0;
      }
    }
  }
  return 1;
}

static GDEFCORE_Result join_vals(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Vals * field, char ** out, size_t * out_len) {
  Grow g;
  size_t i;
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  if (field == NULL) {
    *out = dup_span(alloc, "", 0);
    if (*out == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    *out_len = 0;
    return GDEFCORE_OK;
  }
  for (i = 0; i < field->nvals; i++) {
    if (i > 0) {
      grow_add(&g, ",", 1);
    }
    grow_add(&g, field->vals[i].p, field->vals[i].n);
  }
  if (g.oom) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  if (g.p == NULL) {
    g.p = dup_span(alloc, "", 0);
    if (g.p == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = g.p;
  *out_len = g.n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result proj_get(GDEFCORE_Catalog * cat, const char * type,
    size_t type_len, const char * entity, size_t entity_len,
    GDEFSTOR_Projection ** out) {
  return map_stor(gdefstor_projection_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, type, type_len, entity, entity_len, out));
}

static int col_find(GDEFSTOR_Projection * row, const char * name, size_t nlen,
    const uint8_t ** val, size_t * vlen) {
  size_t i;
  size_t count = gdefstor_projection_column_count(row);
  for (i = 0; i < count; i++) {
    GDEFSTOR_Column column;
    if (gdefstor_projection_column(row, i, &column) != GDEFSTOR_OK) {
      return 0;
    }
    if (span_eq(column.name, column.name_len, name, nlen)) {
      *val = column.value;
      *vlen = column.value_len;
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result read_high(GDEFCORE_Catalog * cat, uint64_t row,
    uint64_t * out) {
  char text[32];
  size_t n = 0;
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc;
  if (!u64_put(row, text, sizeof text, &n)) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = proj_get(cat, "w", 1, text, n, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    *out = 0;
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "seq", 3, &val, &vlen) ||
      !u64_get((const char *)val, vlen, out)) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_CORRUPT;
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

static GDEFCORE_Result read_epoch(GDEFCORE_Catalog * cat, uint64_t * out) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc = proj_get(cat, "e", 1, "epoch", 5, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    *out = 0;
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "n", 1, &val, &vlen) ||
      !u64_get((const char *)val, vlen, out)) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_CORRUPT;
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

static GDEFCORE_Result put_u64_col(GDEFSTOR_Write * write, const char * type,
    size_t type_len, const char * entity, size_t entity_len, const char * col,
    uint64_t value) {
  GDEFSTOR_Column column;
  char text[32];
  size_t n = 0;
  if (!u64_put(value, text, sizeof text, &n)) {
    return GDEFCORE_ERR_LIMIT;
  }
  memset(&column, 0, sizeof column);
  column.name = col;
  column.name_len = strlen(col);
  column.value = (const uint8_t *)text;
  column.value_len = n;
  return map_stor(gdefstor_projection_put(write, type, type_len, entity,
      entity_len, &column, 1));
}

typedef struct RowCursor {
  uint64_t next;
  int loaded;
  int taken;
} RowCursor;

static GDEFCORE_Result cursor_load(GDEFCORE_Catalog * cat, RowCursor * cur) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc;
  memset(cur, 0, sizeof *cur);
  rc = proj_get(cat, "c", 1, "next", 4, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    cur->next = 1;
    cur->loaded = 1;
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "n", 1, &val, &vlen) ||
      !u64_get((const char *)val, vlen, &cur->next) || cur->next == 0) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_CORRUPT;
  }
  gdefstor_projection_free(proj);
  cur->loaded = 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result cursor_take(RowCursor * cur, uint64_t * out) {
  if (!cur->loaded || cur->next == 0) {
    return GDEFCORE_ERR_INTERNAL;
  }
  if (cur->next == UINT64_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  *out = cur->next;
  cur->next += 1;
  cur->taken = 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result cursor_store(GDEFSTOR_Write * write, RowCursor * cur) {
  if (!cur->taken) {
    return GDEFCORE_OK;
  }
  return put_u64_col(write, "c", 1, "next", 4, "n", cur->next);
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

static char * hex_encode(const GDEFCORE_Allocator * alloc, const char * bytes,
    size_t n) {
  static const char kHex[] = "0123456789abcdef";
  char * out;
  size_t i;
  out = (char *)gcu_allocator_malloc(alloc, n * 2 + 1);
  if (out == NULL) {
    return NULL;
  }
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)bytes[i];
    out[i * 2] = kHex[c >> 4];
    out[i * 2 + 1] = kHex[c & 0x0f];
  }
  out[n * 2] = '\0';
  return out;
}

static int decl_constrained(const GDEFCORE_Decl * decl) {
  return decl->min_len != 0 || decl->max_len != 0 || decl->has_range ||
         decl->pattern.n > 0;
}

static GDEFCORE_Result constraint_suffix(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Decl * decl, char ** out, size_t * out_len) {
  char * hex;
  char * text;
  int kn;
  *out = NULL;
  *out_len = 0;
  if (!decl_constrained(decl)) {
    return GDEFCORE_OK;
  }
  hex = hex_encode(alloc, decl->pattern.p == NULL ? "" : decl->pattern.p,
      decl->pattern.n);
  if (hex == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  kn = snprintf(NULL, 0, "|%zu|%zu|%d|%lld|%lld|%s", decl->min_len,
      decl->max_len, decl->has_range ? 1 : 0, (long long)decl->range_min,
      (long long)decl->range_max, hex);
  if (kn < 0) {
    gcu_allocator_free(alloc, hex);
    return GDEFCORE_ERR_LIMIT;
  }
  text = (char *)gcu_allocator_malloc(alloc, (size_t)kn + 1);
  if (text == NULL) {
    gcu_allocator_free(alloc, hex);
    return GDEFCORE_ERR_OOM;
  }
  snprintf(text, (size_t)kn + 1, "|%zu|%zu|%d|%lld|%lld|%s", decl->min_len,
      decl->max_len, decl->has_range ? 1 : 0, (long long)decl->range_min,
      (long long)decl->range_max, hex);
  gcu_allocator_free(alloc, hex);
  *out = text;
  *out_len = (size_t)kn;
  return GDEFCORE_OK;
}

static int parse_u64_span(const char * text, size_t n, uint64_t * out) {
  char buf[32];
  char * end = NULL;
  unsigned long long v;
  if (n == 0 || n >= sizeof buf) {
    return 0;
  }
  memcpy(buf, text, n);
  buf[n] = '\0';
  errno = 0;
  v = strtoull(buf, &end, 10);
  if (end != buf + n || errno == ERANGE) {
    return 0;
  }
  *out = (uint64_t)v;
  return 1;
}

static int parse_i64_span(const char * text, size_t n, int64_t * out) {
  char buf[32];
  char * end = NULL;
  long long v;
  if (n == 0 || n >= sizeof buf) {
    return 0;
  }
  memcpy(buf, text, n);
  buf[n] = '\0';
  errno = 0;
  v = strtoll(buf, &end, 10);
  if (end != buf + n || errno == ERANGE) {
    return 0;
  }
  *out = (int64_t)v;
  return 1;
}

static int split_pipe(const char * text, size_t n, const char ** parts,
    size_t * lens, size_t expect) {
  size_t i;
  size_t start = 0;
  size_t found = 0;
  for (i = 0; i <= n; i++) {
    if (i == n || text[i] == '|') {
      if (found >= expect) {
        return 0;
      }
      parts[found] = text + start;
      lens[found] = i - start;
      found += 1;
      start = i + 1;
    }
  }
  return found == expect;
}

static GDEFCORE_Result fill_constraints(const GDEFCORE_Allocator * alloc,
    const char * text, size_t n, GDEFCORE_Decl * decl) {
  const char * parts[6];
  size_t lens[6];
  uint64_t min_len = 0;
  uint64_t max_len = 0;
  uint64_t has = 0;
  int64_t lo = 0;
  int64_t hi = 0;
  char * pattern = NULL;
  size_t i;
  if (!split_pipe(text, n, parts, lens, 6) ||
      !parse_u64_span(parts[0], lens[0], &min_len) ||
      !parse_u64_span(parts[1], lens[1], &max_len) ||
      !parse_u64_span(parts[2], lens[2], &has) || (has != 0 && has != 1) ||
      !parse_i64_span(parts[3], lens[3], &lo) ||
      !parse_i64_span(parts[4], lens[4], &hi)) {
    return GDEFCORE_ERR_CORRUPT;
  }
  if ((lens[5] % 2) != 0) {
    return GDEFCORE_ERR_CORRUPT;
  }
  if (lens[5] > 0) {
    pattern = (char *)gcu_allocator_malloc(alloc, lens[5] / 2);
    if (pattern == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    for (i = 0; i < lens[5]; i += 2) {
      int hi_n = hex_nibble(parts[5][i]);
      int lo_n = hex_nibble(parts[5][i + 1]);
      if (hi_n < 0 || lo_n < 0) {
        gcu_allocator_free(alloc, pattern);
        return GDEFCORE_ERR_CORRUPT;
      }
      pattern[i / 2] = (char)((hi_n << 4) | lo_n);
    }
    if (text_set(alloc, &decl->pattern, pattern, lens[5] / 2) != GDEFCORE_OK) {
      gcu_allocator_free(alloc, pattern);
      return GDEFCORE_ERR_OOM;
    }
    gcu_allocator_free(alloc, pattern);
  }
  decl->min_len = (size_t)min_len;
  decl->max_len = (size_t)max_len;
  decl->has_range = has ? 1 : 0;
  decl->range_min = lo;
  decl->range_max = hi;
  return GDEFCORE_OK;
}

static GDEFCORE_Result parse_decls(const GDEFCORE_Allocator * alloc,
    const char * text, size_t n, const GDEFCORE_Limits * limits,
    GDEFCORE_Decl ** out, size_t * out_n) {
  size_t i = 0;
  GDEFCORE_Decl * decls = NULL;
  size_t count = 0;
  *out = NULL;
  *out_n = 0;
  while (i < n) {
    size_t line = i;
    size_t name_len;
    size_t sp;
    GDEFCORE_Decl * next;
    int required;
    int many;
    int personal;
    while (i < n && text[i] != '\n') {
      i += 1;
    }
    if (i == line) {
      i += 1;
      continue;
    }
    personal = 0;
    name_len = 0;
    while (line + name_len < i && text[line + name_len] != ' ') {
      name_len += 1;
    }
    if (name_len == 0 || line + name_len >= i || text[line + name_len] != ' ') {
      decls_free(alloc, decls, count);
      return GDEFCORE_ERR_CORRUPT;
    }
    sp = line + name_len;
    {
      size_t flag_n = i - sp;
      size_t pi;
      const char * pipe = NULL;
      for (pi = 0; pi < flag_n; pi++) {
        if (text[sp + pi] == '|') {
          pipe = text + sp + pi;
          flag_n = pi;
          break;
        }
      }
      if ((flag_n == 4 || flag_n == 6) && text[sp] == ' ' &&
          text[sp + 2] == ' ' &&
          (text[sp + 1] == '0' || text[sp + 1] == '1') &&
          (text[sp + 3] == '0' || text[sp + 3] == '1') &&
          (flag_n == 4 ||
              (text[sp + 4] == ' ' &&
                  (text[sp + 5] == '0' || text[sp + 5] == '1')))) {
        required = text[sp + 1] == '1';
        many = text[sp + 3] == '1';
        personal = flag_n == 6 && text[sp + 5] == '1';
      } else {
        decls_free(alloc, decls, count);
        return GDEFCORE_ERR_CORRUPT;
      }
      if (pipe != NULL) {
        GDEFCORE_Decl extra;
        GDEFCORE_Result crc;
        memset(&extra, 0, sizeof extra);
        crc = fill_constraints(alloc, pipe + 1,
            (size_t)((text + i) - (pipe + 1)), &extra);
        if (crc != GDEFCORE_OK) {
          text_clear(alloc, &extra.pattern);
          decls_free(alloc, decls, count);
          return crc;
        }
        /* Stashed on the stack until the decl slot exists. */
        if (count >= limits->max_fields) {
          text_clear(alloc, &extra.pattern);
          decls_free(alloc, decls, count);
          return GDEFCORE_ERR_LIMIT;
        }
        next = (GDEFCORE_Decl *)gcu_allocator_realloc(
            alloc, decls, (count + 1) * sizeof *next);
        if (next == NULL) {
          text_clear(alloc, &extra.pattern);
          decls_free(alloc, decls, count);
          return GDEFCORE_ERR_OOM;
        }
        decls = next;
        memset(&decls[count], 0, sizeof decls[count]);
        if (text_set(alloc, &decls[count].name, text + line, name_len) !=
            GDEFCORE_OK) {
          text_clear(alloc, &extra.pattern);
          decls_free(alloc, decls, count + 1);
          return GDEFCORE_ERR_OOM;
        }
        decls[count].required = required;
        decls[count].many = many;
        decls[count].personal = personal;
        decls[count].min_len = extra.min_len;
        decls[count].max_len = extra.max_len;
        decls[count].has_range = extra.has_range;
        decls[count].range_min = extra.range_min;
        decls[count].range_max = extra.range_max;
        decls[count].pattern = extra.pattern;
        count += 1;
        if (i < n && text[i] == '\n') {
          i += 1;
        }
        continue;
      }
    }
    if (count >= limits->max_fields) {
      decls_free(alloc, decls, count);
      return GDEFCORE_ERR_LIMIT;
    }
    next = (GDEFCORE_Decl *)gcu_allocator_realloc(
        alloc, decls, (count + 1) * sizeof *next);
    if (next == NULL) {
      decls_free(alloc, decls, count);
      return GDEFCORE_ERR_OOM;
    }
    decls = next;
    memset(&decls[count], 0, sizeof decls[count]);
    if (text_set(alloc, &decls[count].name, text + line, name_len) !=
        GDEFCORE_OK) {
      decls_free(alloc, decls, count + 1);
      return GDEFCORE_ERR_OOM;
    }
    decls[count].required = required;
    decls[count].many = many;
    decls[count].personal = personal;
    count += 1;
    if (i < n && text[i] == '\n') {
      i += 1;
    }
  }
  *out = decls;
  *out_n = count;
  return GDEFCORE_OK;
}

static GDEFCORE_Result decls_text(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Decl * decls, size_t n, char ** out, size_t * out_len) {
  Grow g;
  size_t i;
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  for (i = 0; i < n; i++) {
    char flag[16];
    char * suffix = NULL;
    size_t suffix_len = 0;
    int kn = snprintf(flag, sizeof flag, " %d %d %d",
        decls[i].required ? 1 : 0, decls[i].many ? 1 : 0,
        decls[i].personal ? 1 : 0);
    if (constraint_suffix(alloc, &decls[i], &suffix, &suffix_len) !=
        GDEFCORE_OK) {
      gcu_allocator_free(alloc, g.p);
      return GDEFCORE_ERR_OOM;
    }
    grow_add(&g, decls[i].name.p, decls[i].name.n);
    if (kn > 0) {
      grow_add(&g, flag, (size_t)kn);
    }
    if (suffix_len > 0) {
      grow_add(&g, suffix, suffix_len);
    }
    grow_add(&g, "\n", 1);
    gcu_allocator_free(alloc, suffix);
  }
  if (g.oom) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  if (g.p == NULL) {
    g.p = dup_span(alloc, "", 0);
    if (g.p == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = g.p;
  *out_len = g.n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result load_type(GDEFCORE_Catalog * cat, const char * name,
    size_t name_len, int * out_kind, GDEFCORE_Decl ** out_decls,
    size_t * out_n, char ** out_id, size_t * out_id_len, uint64_t * out_row) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc;
  if (builtin_name(name, name_len)) {
    if (out_kind != NULL) {
      *out_kind = GDEFCORE_TYPE_CONFIG;
    }
    if (out_decls != NULL) {
      *out_decls = NULL;
      *out_n = 0;
    }
    if (out_row != NULL) {
      *out_row = 0;
    }
    return GDEFCORE_OK;
  }
  rc = proj_get(cat, "m", 1, name, name_len, &proj);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (out_kind != NULL) {
    if (!col_find(proj, "kind", 4, &val, &vlen)) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (span_eq((const char *)val, vlen, "content", 7)) {
      *out_kind = GDEFCORE_TYPE_CONTENT;
    } else if (span_eq((const char *)val, vlen, "config", 6)) {
      *out_kind = GDEFCORE_TYPE_CONFIG;
    } else {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_CORRUPT;
    }
  }
  if (out_decls != NULL) {
    val = NULL;
    if (!col_find(proj, "fields", 6, &val, &vlen)) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_CORRUPT;
    }
    rc = parse_decls(cat->alloc, (const char *)val, vlen, &cat->limits,
        out_decls, out_n);
    if (rc != GDEFCORE_OK) {
      gdefstor_projection_free(proj);
      return rc;
    }
  }
  if (out_id != NULL) {
    if (!col_find(proj, "id", 2, &val, &vlen)) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_CORRUPT;
    }
    *out_id = dup_span(cat->alloc, (const char *)val, vlen);
    if (*out_id == NULL) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_OOM;
    }
    *out_id_len = vlen;
  }
  if (out_row != NULL) {
    if (!col_find(proj, "row", 3, &val, &vlen) ||
        !u64_get((const char *)val, vlen, out_row)) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_CORRUPT;
    }
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

static int field_personal(const GDEFCORE_Field * field) {
  if (field->size < offsetof(GDEFCORE_Field, personal) + sizeof(int)) {
    return 0;
  }
  return field->personal ? 1 : 0;
}

static int field_covers(const GDEFCORE_Field * field, size_t end) {
  return field->size >= end;
}

static GDEFCORE_Result copy_constraints(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Field * field, GDEFCORE_Decl * decl) {
  size_t min_end = offsetof(GDEFCORE_Field, min_len) + sizeof(size_t);
  size_t max_end = offsetof(GDEFCORE_Field, max_len) + sizeof(size_t);
  size_t range_end = offsetof(GDEFCORE_Field, range_max) + sizeof(int64_t);
  size_t pat_end = offsetof(GDEFCORE_Field, pattern_len) + sizeof(size_t);
  decl->min_len = 0;
  decl->max_len = 0;
  decl->has_range = 0;
  decl->range_min = 0;
  decl->range_max = 0;
  decl->pattern.p = NULL;
  decl->pattern.n = 0;
  if (!field_covers(field, min_end)) {
    return GDEFCORE_OK;
  }
  decl->min_len = field->min_len;
  if (!field_covers(field, max_end)) {
    return GDEFCORE_OK;
  }
  decl->max_len = field->max_len;
  if (!field_covers(field, range_end)) {
    return GDEFCORE_OK;
  }
  decl->has_range = field->has_range ? 1 : 0;
  decl->range_min = field->range_min;
  decl->range_max = field->range_max;
  if (!field_covers(field, pat_end)) {
    return GDEFCORE_OK;
  }
  if (field->pattern_len == 0) {
    return GDEFCORE_OK;
  }
  if (field->pattern == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return text_set(alloc, &decl->pattern, field->pattern, field->pattern_len);
}

static GDEFCORE_Result pattern_compiles(const char * pattern, size_t len) {
  GRX_Regex * re = NULL;
  GRX_Result rr;
  if (len == 0) {
    return GDEFCORE_OK;
  }
  rr = grx_regex_compile_with_allocator(pattern, len, GRX_SYNTAX_ECMASCRIPT,
      GRX_OPT_NONE, NULL, NULL, NULL, &re);
  if (rr == GRX_OK) {
    grx_regex_free(re);
    return GDEFCORE_OK;
  }
  if (rr == GRX_ERR_OOM) {
    return GDEFCORE_ERR_OOM;
  }
  if (rr == GRX_ERR_LIMIT) {
    return GDEFCORE_ERR_LIMIT;
  }
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result check_fields(const GDEFCORE_Field * fields,
    size_t count, const GDEFCORE_Limits * limits) {
  size_t i;
  size_t j;
  if (count > limits->max_fields || (fields == NULL && count != 0)) {
    return count > limits->max_fields ? GDEFCORE_ERR_LIMIT
                                      : GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < count; i++) {
    if (fields[i].size < offsetof(GDEFCORE_Field, many) + sizeof(int) ||
        !field_name_ok(fields[i].name, fields[i].name_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    if (field_covers(&fields[i],
            offsetof(GDEFCORE_Field, pattern_len) + sizeof(size_t)) &&
        fields[i].pattern_len > 0) {
      GDEFCORE_Result pr;
      if (fields[i].pattern == NULL ||
          fields[i].pattern_len > limits->max_value_bytes) {
        return fields[i].pattern_len > limits->max_value_bytes
                   ? GDEFCORE_ERR_LIMIT
                   : GDEFCORE_ERR_INVALID;
      }
      pr = pattern_compiles(fields[i].pattern, fields[i].pattern_len);
      if (pr != GDEFCORE_OK) {
        return pr;
      }
    }
    for (j = 0; j < i; j++) {
      if (span_eq(fields[i].name, fields[i].name_len, fields[j].name,
              fields[j].name_len)) {
        return GDEFCORE_ERR_INVALID;
      }
    }
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result fields_to_decls(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Field * fields, size_t count, GDEFCORE_Decl ** out) {
  GDEFCORE_Decl * decls;
  size_t i;
  *out = NULL;
  if (count == 0) {
    return GDEFCORE_OK;
  }
  decls = (GDEFCORE_Decl *)mem0(alloc, count * sizeof *decls);
  if (decls == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < count; i++) {
    if (text_set(alloc, &decls[i].name, fields[i].name, fields[i].name_len) !=
        GDEFCORE_OK) {
      decls_free(alloc, decls, i + 1);
      return GDEFCORE_ERR_OOM;
    }
    decls[i].required = fields[i].required ? 1 : 0;
    decls[i].many = fields[i].many ? 1 : 0;
    decls[i].personal = field_personal(&fields[i]);
    {
      GDEFCORE_Result cr = copy_constraints(alloc, &fields[i], &decls[i]);
      if (cr != GDEFCORE_OK) {
        decls_free(alloc, decls, i + 1);
        return cr;
      }
    }
  }
  *out = decls;
  return GDEFCORE_OK;
}

static GDEFCORE_Result append_rev(GDEFSTOR_Write * write, uint64_t seq,
    uint64_t row, const char * id, size_t id_len, const char * type,
    size_t type_len, const char * lang, size_t lang_len) {
  Grow g;
  char seq_text[32];
  char row_text[32];
  size_t sn = 0;
  size_t rn = 0;
  const GDEFCORE_Allocator * alloc = gdefcore_allocator_default();
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  if (!u64_put(seq, seq_text, sizeof seq_text, &sn) ||
      !u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  grow_add(&g, "{\"format\":\"defiant-revision/1\",\"seq\":", 37);
  grow_add(&g, seq_text, sn);
  grow_add(&g, ",\"row\":", 7);
  grow_add(&g, row_text, rn);
  grow_add(&g, ",\"entity\":", 10);
  grow_json(&g, id, id_len);
  grow_add(&g, ",\"type\":", 8);
  grow_json(&g, type, type_len);
  grow_add(&g, ",\"lang\":", 8);
  grow_add(&g, lang, lang_len);
  grow_add(&g, ",\"body\":\"\"}", 11);
  if (g.oom) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  {
    GDEFCORE_Result rc = map_stor(gdefstor_revision_append(
        write, (const uint8_t *)g.p, g.n));
    gcu_allocator_free(alloc, g.p);
    return rc;
  }
}

static GDEFCORE_Result put_entity_proj(GDEFSTOR_Write * write,
    const char * prefix, const char * type, size_t type_len, uint64_t row,
    uint64_t seq, const char * id, size_t id_len, const char * lang,
    size_t lang_len, const char * actor, size_t actor_len) {
  char type_buf[160];
  char row_text[32];
  char seq_text[32];
  size_t rn = 0;
  size_t sn = 0;
  GDEFSTOR_Column columns[4];
  size_t n = 0;
  int kn;
  if (type_len + 2 >= sizeof type_buf) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (!u64_put(row, row_text, sizeof row_text, &rn) ||
      !u64_put(seq, seq_text, sizeof seq_text, &sn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  kn = snprintf(type_buf, sizeof type_buf, "%s%.*s", prefix, (int)type_len,
      type);
  if (kn <= 0 || (size_t)kn >= sizeof type_buf) {
    return GDEFCORE_ERR_LIMIT;
  }
  memset(columns, 0, sizeof columns);
  columns[n].name = "lang";
  columns[n].name_len = 4;
  columns[n].value = (const uint8_t *)lang;
  columns[n].value_len = lang_len;
  n += 1;
  columns[n].name = "seq";
  columns[n].name_len = 3;
  columns[n].value = (const uint8_t *)seq_text;
  columns[n].value_len = sn;
  n += 1;
  columns[n].name = "id";
  columns[n].name_len = 2;
  columns[n].value = (const uint8_t *)id;
  columns[n].value_len = id_len;
  n += 1;
  if (actor != NULL && actor_len > 0) {
    columns[n].name = "actor";
    columns[n].name_len = 5;
    columns[n].value = (const uint8_t *)actor;
    columns[n].value_len = actor_len;
    n += 1;
  }
  return map_stor(gdefstor_projection_put(
      write, type_buf, (size_t)kn, row_text, rn, columns, n));
}

static GDEFCORE_Result delete_entity_proj(GDEFSTOR_Write * write,
    const char * prefix, const char * type, size_t type_len, uint64_t row) {
  char type_buf[160];
  char row_text[32];
  size_t rn = 0;
  int kn;
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  kn = snprintf(type_buf, sizeof type_buf, "%s%.*s", prefix, (int)type_len,
      type);
  if (kn <= 0 || (size_t)kn >= sizeof type_buf) {
    return GDEFCORE_ERR_LIMIT;
  }
  return map_stor(gdefstor_projection_delete(
      write, type_buf, (size_t)kn, row_text, rn));
}

static GDEFCORE_Result put_index(GDEFSTOR_Write * write, const char * id,
    size_t id_len, uint64_t row, const char * type, size_t type_len,
    const char * machine, size_t machine_len) {
  char row_text[32];
  size_t rn = 0;
  GDEFSTOR_Column columns[3];
  size_t n = 0;
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  memset(columns, 0, sizeof columns);
  columns[n].name = "row";
  columns[n].name_len = 3;
  columns[n].value = (const uint8_t *)row_text;
  columns[n].value_len = rn;
  n += 1;
  columns[n].name = "type";
  columns[n].name_len = 4;
  columns[n].value = (const uint8_t *)type;
  columns[n].value_len = type_len;
  n += 1;
  if (machine != NULL && machine_len > 0) {
    columns[n].name = "machine";
    columns[n].name_len = 7;
    columns[n].value = (const uint8_t *)machine;
    columns[n].value_len = machine_len;
    n += 1;
  }
  return map_stor(
      gdefstor_projection_put(write, "i", 1, id, id_len, columns, n));
}

static GDEFCORE_Result put_meta(GDEFSTOR_Write * write, const char * name,
    size_t name_len, int kind, const char * fields, size_t fields_len,
    const char * id, size_t id_len, uint64_t row) {
  char row_text[32];
  size_t rn = 0;
  GDEFSTOR_Column columns[4];
  const char * kind_text = kind == GDEFCORE_TYPE_CONFIG ? "config" : "content";
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  memset(columns, 0, sizeof columns);
  columns[0].name = "kind";
  columns[0].name_len = 4;
  columns[0].value = (const uint8_t *)kind_text;
  columns[0].value_len = strlen(kind_text);
  columns[1].name = "fields";
  columns[1].name_len = 6;
  columns[1].value = (const uint8_t *)fields;
  columns[1].value_len = fields_len;
  columns[2].name = "id";
  columns[2].name_len = 2;
  columns[2].value = (const uint8_t *)id;
  columns[2].value_len = id_len;
  columns[3].name = "row";
  columns[3].name_len = 3;
  columns[3].value = (const uint8_t *)row_text;
  columns[3].value_len = rn;
  return map_stor(
      gdefstor_projection_put(write, "m", 1, name, name_len, columns, 4));
}

static GDEFCORE_Result lookup_id(GDEFCORE_Catalog * cat, const char * id,
    size_t id_len, uint64_t * out_row, char ** out_type, size_t * out_type_len,
    char ** out_machine, size_t * out_machine_len) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc = proj_get(cat, "i", 1, id, id_len, &proj);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "row", 3, &val, &vlen) ||
      !u64_get((const char *)val, vlen, out_row)) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_CORRUPT;
  }
  if (out_type != NULL) {
    if (!col_find(proj, "type", 4, &val, &vlen)) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_CORRUPT;
    }
    *out_type = dup_span(cat->alloc, (const char *)val, vlen);
    if (*out_type == NULL) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_OOM;
    }
    *out_type_len = vlen;
  }
  if (out_machine != NULL) {
    *out_machine = NULL;
    *out_machine_len = 0;
    if (col_find(proj, "machine", 7, &val, &vlen) && vlen > 0) {
      *out_machine = dup_span(cat->alloc, (const char *)val, vlen);
      if (*out_machine == NULL) {
        gdefstor_projection_free(proj);
        return GDEFCORE_ERR_OOM;
      }
      *out_machine_len = vlen;
    }
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

static GDEFCORE_Result read_proj_doc(GDEFCORE_Catalog * cat, const char * prefix,
    const char * type, size_t type_len, uint64_t row, GDEFCORE_Doc * doc,
    uint64_t * out_seq) {
  char type_buf[160];
  char row_text[32];
  size_t rn = 0;
  int kn;
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc;
  memset(doc, 0, sizeof *doc);
  if (out_seq != NULL) {
    *out_seq = 0;
  }
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  kn = snprintf(type_buf, sizeof type_buf, "%s%.*s", prefix, (int)type_len, type);
  if (kn <= 0 || (size_t)kn >= sizeof type_buf) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = proj_get(cat, type_buf, (size_t)kn, row_text, rn, &proj);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "lang", 4, &val, &vlen)) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_CORRUPT;
  }
  rc = doc_parse(cat->alloc, (const char *)val, vlen, doc);
  if (rc != GDEFCORE_OK) {
    gdefstor_projection_free(proj);
    return rc;
  }
  if (out_seq != NULL) {
    if (!col_find(proj, "seq", 3, &val, &vlen) ||
        !u64_get((const char *)val, vlen, out_seq)) {
      gdefstor_projection_free(proj);
      doc_free(cat->alloc, doc);
      return GDEFCORE_ERR_CORRUPT;
    }
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_catalog_open(GDEFSTOR_Store * store,
    const uint8_t * tenant, size_t tenant_len, const GDEFCORE_Limits * limits,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Catalog ** out_catalog) {
  GDEFCORE_Catalog * cat;
  if (store == NULL || tenant == NULL || tenant_len == 0 ||
      out_catalog == NULL || (tenant_len == 1 && tenant[0] == 0x01)) {
    return GDEFCORE_ERR_INVALID;
  }
  allocator = use_alloc(allocator);
  cat = (GDEFCORE_Catalog *)mem0(allocator, sizeof *cat);
  if (cat == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  cat->tenant = (uint8_t *)mem(allocator, tenant_len);
  if (cat->tenant == NULL) {
    gcu_allocator_free(allocator, cat);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(cat->tenant, tenant, tenant_len);
  cat->tenant_len = tenant_len;
  cat->store = store;
  cat->alloc = allocator;
  if (limits == NULL) {
    limits_fill(&cat->limits);
  } else {
    cat->limits = *limits;
  }
  *out_catalog = cat;
  return GDEFCORE_OK;
}

void gdefcore_catalog_destroy(GDEFCORE_Catalog * catalog) {
  if (catalog == NULL) {
    return;
  }
  gcu_allocator_free(catalog->alloc, catalog->tenant);
  gcu_allocator_free(catalog->alloc, catalog);
}

void gdefcore_text_free(GDEFCORE_Catalog * catalog, char * text) {
  if (catalog == NULL) {
    return;
  }
  gcu_allocator_free(catalog->alloc, text);
}

GDEFCORE_Result gdefcore_epoch(GDEFCORE_Catalog * catalog, uint64_t * out_epoch) {
  if (catalog == NULL || out_epoch == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return read_epoch(catalog, out_epoch);
}

static GDEFCORE_Result write_type_row(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, RowCursor * cursor, const char * name,
    size_t name_len, int kind, const GDEFCORE_Decl * decls, size_t ndecls,
    const char * existing_id, size_t existing_id_len, uint64_t existing_row,
    int is_new) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = existing_row;
  uint64_t seq;
  uint64_t high = 0;
  char * fields = NULL;
  size_t fields_len = 0;
  char * lang = NULL;
  size_t lang_len = 0;
  GDEFCORE_Result rc;
  const char * use_id;
  size_t use_id_len;
  rc = decls_text(cat->alloc, decls, ndecls, &fields, &fields_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (is_new) {
    rc = gdefcore_id_generate(id);
    if (rc != GDEFCORE_OK) {
      gcu_allocator_free(cat->alloc, fields);
      return rc;
    }
    rc = cursor_take(cursor, &row);
    if (rc != GDEFCORE_OK) {
      gcu_allocator_free(cat->alloc, fields);
      return rc;
    }
    seq = 1;
    use_id = id;
    use_id_len = GDEFCORE_PUBLIC_ID_LEN;
  } else {
    rc = read_high(cat, existing_row, &high);
    if (rc != GDEFCORE_OK) {
      gcu_allocator_free(cat->alloc, fields);
      return rc;
    }
    if (high == UINT64_MAX) {
      gcu_allocator_free(cat->alloc, fields);
      return GDEFCORE_ERR_LIMIT;
    }
    seq = high + 1;
    use_id = existing_id;
    use_id_len = existing_id_len;
    row = existing_row;
  }
  {
    const char * kind_json = kind == GDEFCORE_TYPE_CONFIG
                                 ? "{\"en\":{\"kind\":[\"config\"]}}"
                                 : "{\"en\":{\"kind\":[\"content\"]}}";
    lang = dup_span(cat->alloc, kind_json, strlen(kind_json));
    if (lang == NULL) {
      gcu_allocator_free(cat->alloc, fields);
      return GDEFCORE_ERR_OOM;
    }
    lang_len = strlen(kind_json);
  }
  rc = append_rev(write, seq, row, use_id, use_id_len, "core.entity_type", 16,
      lang, lang_len);
  if (rc == GDEFCORE_OK) {
    rc = put_entity_proj(write, "p:", "core.entity_type", 16, row, seq, use_id,
        use_id_len, lang, lang_len, NULL, 0);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_entity_proj(write, "d:", "core.entity_type", 16, row, seq, use_id,
        use_id_len, lang, lang_len, NULL, 0);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_meta(write, name, name_len, kind, fields, fields_len, use_id,
        use_id_len, row);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_index(write, use_id, use_id_len, row, "core.entity_type", 16, name,
        name_len);
  }
  if (rc == GDEFCORE_OK) {
    char row_text[32];
    size_t rn = 0;
    if (!u64_put(row, row_text, sizeof row_text, &rn)) {
      rc = GDEFCORE_ERR_LIMIT;
    } else {
      rc = put_u64_col(write, "w", 1, row_text, rn, "seq", seq);
    }
  }
  gcu_allocator_free(cat->alloc, fields);
  gcu_allocator_free(cat->alloc, lang);
  return rc;
}

GDEFCORE_Result gdefcore_type_define(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, int kind, const GDEFCORE_Field * fields,
    size_t field_count) {
  GDEFSTOR_Write * write = NULL;
  RowCursor cursor;
  GDEFCORE_Decl * decls = NULL;
  GDEFCORE_Result rc;
  int existing = 0;
  if (catalog == NULL || !machine_ok(name, name_len) ||
      (kind != GDEFCORE_TYPE_CONTENT && kind != GDEFCORE_TYPE_CONFIG) ||
      builtin_name(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = check_fields(fields, field_count, &catalog->limits);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_type(catalog, name, name_len, &existing, NULL, NULL, NULL, NULL,
      NULL);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  rc = fields_to_decls(catalog->alloc, fields, field_count, &decls);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = map_stor(gdefstor_write_begin(catalog->store, (const char *)catalog->tenant,
      catalog->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    decls_free(catalog->alloc, decls, field_count);
    return rc;
  }
  rc = cursor_load(catalog, &cursor);
  if (rc == GDEFCORE_OK) {
    rc = write_type_row(catalog, write, &cursor, name, name_len, kind, decls,
        field_count, NULL, 0, 0, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = cursor_store(write, &cursor);
  }
  decls_free(catalog->alloc, decls, field_count);
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return map_stor(gdefstor_write_commit(write));
}

GDEFCORE_Result gdefcore_type_kind(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, int * out_kind) {
  if (catalog == NULL || out_kind == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return load_type(catalog, name, name_len, out_kind, NULL, NULL, NULL, NULL,
      NULL);
}

GDEFCORE_Result gdefcore_type_field_count(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t * out_count) {
  GDEFCORE_Decl * decls = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, name, name_len, NULL, &decls, &n, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  decls_free(catalog->alloc, decls, n);
  *out_count = n;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_type_field(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, size_t index, char ** out_name, size_t * out_name_len,
    int * out_required, int * out_many) {
  GDEFCORE_Decl * decls = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_name == NULL || out_name_len == NULL ||
      out_required == NULL || out_many == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, name, name_len, NULL, &decls, &n, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (index >= n) {
    decls_free(catalog->alloc, decls, n);
    return GDEFCORE_ERR_INVALID;
  }
  *out_name = dup_span(catalog->alloc, decls[index].name.p, decls[index].name.n);
  if (*out_name == NULL) {
    decls_free(catalog->alloc, decls, n);
    return GDEFCORE_ERR_OOM;
  }
  *out_name_len = decls[index].name.n;
  *out_required = decls[index].required;
  *out_many = decls[index].many;
  decls_free(catalog->alloc, decls, n);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_type_field_personal(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, int * out_personal) {
  GDEFCORE_Decl * decls = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_personal == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, name, name_len, NULL, &decls, &n, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (index >= n) {
    decls_free(catalog->alloc, decls, n);
    return GDEFCORE_ERR_INVALID;
  }
  *out_personal = decls[index].personal ? 1 : 0;
  decls_free(catalog->alloc, decls, n);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_type_field_constraints(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, size_t * out_min_len,
    size_t * out_max_len, int * out_has_range, int64_t * out_range_min,
    int64_t * out_range_max, char ** out_pattern, size_t * out_pattern_len) {
  GDEFCORE_Decl * decls = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_min_len == NULL || out_max_len == NULL ||
      out_has_range == NULL || out_range_min == NULL || out_range_max == NULL ||
      out_pattern == NULL || out_pattern_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, name, name_len, NULL, &decls, &n, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (index >= n) {
    decls_free(catalog->alloc, decls, n);
    return GDEFCORE_ERR_INVALID;
  }
  {
    char * pattern = NULL;
    size_t pattern_len = 0;
    if (decls[index].pattern.n > 0) {
      pattern = dup_span(catalog->alloc, decls[index].pattern.p,
          decls[index].pattern.n);
      if (pattern == NULL) {
        decls_free(catalog->alloc, decls, n);
        return GDEFCORE_ERR_OOM;
      }
      pattern_len = decls[index].pattern.n;
    }
    *out_min_len = decls[index].min_len;
    *out_max_len = decls[index].max_len;
    *out_has_range = decls[index].has_range ? 1 : 0;
    *out_range_min = decls[index].range_min;
    *out_range_max = decls[index].range_max;
    *out_pattern = pattern;
    *out_pattern_len = pattern_len;
  }
  decls_free(catalog->alloc, decls, n);
  return GDEFCORE_OK;
}

static const char kIdsType[] = "core.ids";

static GDEFCORE_Result ids_add(GDEFCORE_Catalog * cat, GDEFSTOR_Write * write,
    const char * type, size_t type_len, const char * id) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  char * buf;
  size_t n = 0;
  GDEFSTOR_Column column;
  GDEFCORE_Result rc = proj_get(cat, kIdsType, sizeof kIdsType - 1, type,
      type_len, &proj);
  if (rc == GDEFCORE_OK) {
    if (!col_find(proj, "ids", 3, &val, &vlen)) {
      val = NULL;
      vlen = 0;
    }
  } else if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  buf = (char *)mem(cat->alloc, vlen + GDEFCORE_PUBLIC_ID_LEN + 2);
  if (buf == NULL) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_OOM;
  }
  if (val != NULL && vlen > 0) {
    memcpy(buf, val, vlen);
    n = vlen;
  }
  gdefstor_projection_free(proj);
  if (n > 0) {
    buf[n++] = '\n';
  }
  memcpy(buf + n, id, GDEFCORE_PUBLIC_ID_LEN);
  n += GDEFCORE_PUBLIC_ID_LEN;
  memset(&column, 0, sizeof column);
  column.name = "ids";
  column.name_len = 3;
  column.value = (const uint8_t *)buf;
  column.value_len = n;
  rc = map_stor(gdefstor_projection_put(write, kIdsType, sizeof kIdsType - 1,
      type, type_len, &column, 1));
  gcu_allocator_free(cat->alloc, buf);
  return rc;
}

GDEFCORE_Result gdefcore_entity_create(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1], uint64_t * out_row) {
  int kind = 0;
  GDEFSTOR_Write * write = NULL;
  RowCursor cursor;
  uint64_t row = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char row_text[32];
  size_t rn = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_id == NULL || builtin_name(type_name, type_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, type_name, type_len, &kind, NULL, NULL, NULL, NULL,
      NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_id_generate(id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = map_stor(gdefstor_write_begin(catalog->store,
      (const char *)catalog->tenant, catalog->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = cursor_load(catalog, &cursor);
  if (rc == GDEFCORE_OK) {
    rc = cursor_take(&cursor, &row);
  }
  if (rc == GDEFCORE_OK) {
    rc = cursor_store(write, &cursor);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_index(write, id, GDEFCORE_PUBLIC_ID_LEN, row, type_name, type_len,
        NULL, 0);
  }
  if (rc == GDEFCORE_OK) {
    rc = ids_add(catalog, write, type_name, type_len, id);
  }
  if (rc == GDEFCORE_OK) {
    if (!u64_put(row, row_text, sizeof row_text, &rn)) {
      rc = GDEFCORE_ERR_LIMIT;
    } else {
      rc = put_u64_col(write, "w", 1, row_text, rn, "seq", 0);
    }
  }
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  rc = map_stor(gdefstor_write_commit(write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memcpy(out_id, id, GDEFCORE_PUBLIC_ID_LEN + 1);
  if (out_row != NULL) {
    *out_row = row;
  }
  return GDEFCORE_OK;
}


static void changeset_free_ops(GDEFCORE_Changeset * cs) {
  size_t i;
  for (i = 0; i < cs->nops; i++) {
    op_free(cs->catalog->alloc, &cs->ops[i]);
  }
  gcu_allocator_free(cs->catalog->alloc, cs->ops);
  cs->ops = NULL;
  cs->nops = 0;
  for (i = 0; i < cs->nlines; i++) {
    text_clear(cs->catalog->alloc, &cs->lines[i]);
  }
  gcu_allocator_free(cs->catalog->alloc, cs->lines);
  cs->lines = NULL;
  cs->nlines = 0;
  text_clear(cs->catalog->alloc, &cs->conflict);
  text_clear(cs->catalog->alloc, &cs->actor);
}

void gdefcore_changeset_destroy(GDEFCORE_Changeset * changeset) {
  if (changeset == NULL) {
    return;
  }
  gdefcore_access_clear_staged(changeset);
  changeset_free_ops(changeset);
  gcu_allocator_free(changeset->catalog->alloc, changeset);
}

GDEFCORE_Result gdefcore_changeset_prepare(GDEFCORE_Catalog * catalog,
    const char * actor, size_t actor_len, GDEFCORE_Changeset ** out_changeset) {
  GDEFCORE_Changeset * cs;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t epoch = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (actor != NULL || actor_len != 0) {
    if (gdefcore_id_canonical(actor, actor_len, canon) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  rc = read_epoch(catalog, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  cs = (GDEFCORE_Changeset *)mem0(catalog->alloc, sizeof *cs);
  if (cs == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  cs->catalog = catalog;
  cs->epoch = epoch;
  if (actor != NULL && actor_len != 0) {
    if (text_set(catalog->alloc, &cs->actor, canon, GDEFCORE_PUBLIC_ID_LEN) !=
        GDEFCORE_OK) {
      gcu_allocator_free(catalog->alloc, cs);
      return GDEFCORE_ERR_OOM;
    }
  }
  *out_changeset = cs;
  return GDEFCORE_OK;
}

static GDEFCORE_Op * find_op_id(GDEFCORE_Changeset * cs, const char * id,
    size_t id_len) {
  size_t i;
  for (i = 0; i < cs->nops; i++) {
    if (cs->ops[i].id.p != NULL &&
        span_eq(cs->ops[i].id.p, cs->ops[i].id.n, id, id_len)) {
      return &cs->ops[i];
    }
  }
  return NULL;
}

static GDEFCORE_Op * find_op_machine(GDEFCORE_Changeset * cs, const char * name,
    size_t name_len) {
  size_t i;
  for (i = 0; i < cs->nops; i++) {
    if (cs->ops[i].kind == GDEFCORE_OP_DEFINE &&
        span_eq(cs->ops[i].machine.p, cs->ops[i].machine.n, name, name_len)) {
      return &cs->ops[i];
    }
  }
  return NULL;
}

static GDEFCORE_Result add_op(GDEFCORE_Changeset * cs, GDEFCORE_Op ** out) {
  GDEFCORE_Op * ops = (GDEFCORE_Op *)gcu_allocator_realloc(
      cs->catalog->alloc, cs->ops, (cs->nops + 1) * sizeof *ops);
  if (ops == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  cs->ops = ops;
  memset(&cs->ops[cs->nops], 0, sizeof cs->ops[cs->nops]);
  *out = &cs->ops[cs->nops];
  cs->nops += 1;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_changeset_define(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, int kind, const GDEFCORE_Field * fields,
    size_t field_count) {
  GDEFCORE_Op * op;
  GDEFCORE_Decl * decls = NULL;
  GDEFCORE_Result rc;
  char * existing_id = NULL;
  size_t existing_id_len = 0;
  uint64_t existing_row = 0;
  int have = 0;
  if (changeset == NULL || changeset->applied ||
      !machine_ok(name, name_len) || builtin_name(name, name_len) ||
      (kind != GDEFCORE_TYPE_CONTENT && kind != GDEFCORE_TYPE_CONFIG)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = check_fields(fields, field_count, &changeset->catalog->limits);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (find_op_machine(changeset, name, name_len) != NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(changeset->catalog, name, name_len, NULL, NULL, NULL,
      &existing_id, &existing_id_len, &existing_row);
  if (rc == GDEFCORE_OK) {
    have = 1;
  } else if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  rc = fields_to_decls(changeset->catalog->alloc, fields, field_count, &decls);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(changeset->catalog->alloc, existing_id);
    return rc;
  }
  rc = add_op(changeset, &op);
  if (rc != GDEFCORE_OK) {
    decls_free(changeset->catalog->alloc, decls, field_count);
    gcu_allocator_free(changeset->catalog->alloc, existing_id);
    return rc;
  }
  op->kind = GDEFCORE_OP_DEFINE;
  op->type_kind = kind;
  op->decls = decls;
  op->ndecls = field_count;
  if (text_set(changeset->catalog->alloc, &op->machine, name, name_len) !=
          GDEFCORE_OK ||
      text_set(changeset->catalog->alloc, &op->type_name, "core.entity_type",
          16) != GDEFCORE_OK) {
    op_free(changeset->catalog->alloc, op);
    changeset->nops -= 1;
    gcu_allocator_free(changeset->catalog->alloc, existing_id);
    return GDEFCORE_ERR_OOM;
  }
  if (have) {
    op->have_row = 1;
    op->row = existing_row;
    op->base_seq = 0;
    if (read_high(changeset->catalog, existing_row, &op->base_seq) !=
        GDEFCORE_OK) {
      op_free(changeset->catalog->alloc, op);
      changeset->nops -= 1;
      gcu_allocator_free(changeset->catalog->alloc, existing_id);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (text_set(changeset->catalog->alloc, &op->id, existing_id,
            existing_id_len) != GDEFCORE_OK) {
      op_free(changeset->catalog->alloc, op);
      changeset->nops -= 1;
      gcu_allocator_free(changeset->catalog->alloc, existing_id);
      return GDEFCORE_ERR_OOM;
    }
  }
  gcu_allocator_free(changeset->catalog->alloc, existing_id);
  return GDEFCORE_OK;
}

static const GDEFCORE_Decl * decl_named(const GDEFCORE_Decl * decls, size_t n,
    const char * name, size_t name_len) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (span_eq(decls[i].name.p, decls[i].name.n, name, name_len)) {
      return &decls[i];
    }
  }
  return NULL;
}

static GDEFCORE_Result stage_values(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count, int draft) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * cat;
  GDEFCORE_Op * op;
  GDEFCORE_Doc tentative;
  GDEFCORE_Decl * decls = NULL;
  size_t ndecls = 0;
  char * type_name = NULL;
  size_t type_len = 0;
  char * machine = NULL;
  size_t machine_len = 0;
  uint64_t row = 0;
  int kind = 0;
  uint64_t high = 0;
  GDEFCORE_Result rc;
  size_t i;
  int created = 0;
  if (changeset == NULL || changeset->applied || !lang_ok(lang, lang_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  cat = changeset->catalog;
  if (value_count > cat->limits.max_fields ||
      (values == NULL && value_count != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = lookup_id(cat, canon, GDEFCORE_PUBLIC_ID_LEN, &row, &type_name,
      &type_len, &machine, &machine_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_type(cat, type_name, type_len, &kind, &decls, &ndecls, NULL, NULL,
      NULL);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(cat->alloc, type_name);
    gcu_allocator_free(cat->alloc, machine);
    return rc;
  }
  for (i = 0; i < value_count; i++) {
    const GDEFCORE_Decl * decl;
    size_t v;
    if (values[i].size < offsetof(GDEFCORE_Value, count) + sizeof(size_t) ||
        values[i].count > cat->limits.max_values ||
        (values[i].texts == NULL && values[i].count != 0) ||
        (values[i].text_lens == NULL && values[i].count != 0)) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    decl = decl_named(decls, ndecls, values[i].field, values[i].field_len);
    if (decl == NULL) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    /* A many field with no values clears that field. A single field
     * still needs one value. A required field stays required. */
    if (!decl->many && values[i].count != 1) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    for (v = 0; v < values[i].count; v++) {
      if (values[i].texts[v] == NULL ||
          values[i].text_lens[v] > cat->limits.max_value_bytes) {
        rc = values[i].text_lens[v] > cat->limits.max_value_bytes
                 ? GDEFCORE_ERR_LIMIT
                 : GDEFCORE_ERR_INVALID;
        goto done;
      }
    }
  }
  op = find_op_id(changeset, canon, GDEFCORE_PUBLIC_ID_LEN);
  memset(&tentative, 0, sizeof tentative);
  if (op != NULL && op->kind != GDEFCORE_OP_CLEAR) {
    rc = doc_clone(cat->alloc, &op->staged, &tentative);
  } else if (op == NULL) {
    if (draft) {
      rc = read_proj_doc(cat, "d:", type_name, type_len, row, &tentative, NULL);
      if (rc == GDEFCORE_ERR_INVALID) {
        rc = read_proj_doc(cat, "p:", type_name, type_len, row, &tentative,
            NULL);
      }
    } else {
      rc = read_proj_doc(cat, "p:", type_name, type_len, row, &tentative, NULL);
    }
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
    }
  }
  if (rc != GDEFCORE_OK) {
    doc_free(cat->alloc, &tentative);
    goto done;
  }
  for (i = 0; i < value_count; i++) {
    rc = doc_set_field(cat->alloc, &tentative, &cat->limits, lang, lang_len,
        values[i].field, values[i].field_len, values[i].texts,
        values[i].text_lens, values[i].count);
    if (rc != GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      goto done;
    }
  }
  if (!doc_has_required(&tentative, decls, ndecls)) {
    doc_free(cat->alloc, &tentative);
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  if (op == NULL) {
    rc = add_op(changeset, &op);
    if (rc != GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      goto done;
    }
    created = 1;
    if (text_set(cat->alloc, &op->id, canon, GDEFCORE_PUBLIC_ID_LEN) !=
            GDEFCORE_OK ||
        text_set(cat->alloc, &op->type_name, type_name, type_len) !=
            GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      rc = GDEFCORE_ERR_OOM;
      goto done;
    }
    if (machine != NULL &&
        text_set(cat->alloc, &op->machine, machine, machine_len) !=
            GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      rc = GDEFCORE_ERR_OOM;
      goto done;
    }
    op->row = row;
    op->have_row = 1;
    op->type_kind = kind;
    rc = decls_copy(cat->alloc, decls, ndecls, &op->decls);
    if (rc != GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      goto done;
    }
    op->ndecls = ndecls;
    rc = read_high(cat, row, &high);
    if (rc != GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      goto done;
    }
    op->base_seq = high;
    rc = read_proj_doc(cat, "p:", type_name, type_len, row, &op->base, NULL);
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
    }
    if (rc != GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      goto done;
    }
  }
  doc_free(cat->alloc, &op->staged);
  op->staged = tentative;
  op->kind = draft ? GDEFCORE_OP_DRAFT : GDEFCORE_OP_SAVE;
  rc = GDEFCORE_OK;
done:
  if (rc != GDEFCORE_OK && created && op != NULL) {
    op_free(cat->alloc, op);
    changeset->nops -= 1;
  }
  decls_free(cat->alloc, decls, ndecls);
  gcu_allocator_free(cat->alloc, type_name);
  gcu_allocator_free(cat->alloc, machine);
  return rc;
}

GDEFCORE_Result gdefcore_entity_save(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count) {
  return stage_values(changeset, id, id_len, lang, lang_len, values,
      value_count, 0);
}

GDEFCORE_Result gdefcore_entity_save_draft(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count) {
  return stage_values(changeset, id, id_len, lang, lang_len, values,
      value_count, 1);
}

GDEFCORE_Result gdefcore_entity_publish(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * cat;
  GDEFCORE_Op * op;
  GDEFCORE_Doc staged;
  char * type_name = NULL;
  size_t type_len = 0;
  char * machine = NULL;
  size_t machine_len = 0;
  uint64_t row = 0;
  uint64_t seq = 0;
  uint64_t high = 0;
  int kind = 0;
  GDEFCORE_Result rc;
  if (changeset == NULL || changeset->applied) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (find_op_id(changeset, canon, GDEFCORE_PUBLIC_ID_LEN) != NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  cat = changeset->catalog;
  rc = lookup_id(cat, canon, GDEFCORE_PUBLIC_ID_LEN, &row, &type_name,
      &type_len, &machine, &machine_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_type(cat, type_name, type_len, &kind, NULL, NULL, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(cat->alloc, type_name);
    gcu_allocator_free(cat->alloc, machine);
    return rc;
  }
  memset(&staged, 0, sizeof staged);
  rc = read_proj_doc(cat, "d:", type_name, type_len, row, &staged, &seq);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(cat->alloc, type_name);
    gcu_allocator_free(cat->alloc, machine);
    return rc;
  }
  rc = read_high(cat, row, &high);
  if (rc != GDEFCORE_OK || high != seq) {
    doc_free(cat->alloc, &staged);
    gcu_allocator_free(cat->alloc, type_name);
    gcu_allocator_free(cat->alloc, machine);
    return rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_CORRUPT;
  }
  rc = add_op(changeset, &op);
  if (rc != GDEFCORE_OK) {
    doc_free(cat->alloc, &staged);
    gcu_allocator_free(cat->alloc, type_name);
    gcu_allocator_free(cat->alloc, machine);
    return rc;
  }
  op->kind = GDEFCORE_OP_PUBLISH;
  op->staged = staged;
  op->row = row;
  op->have_row = 1;
  op->base_seq = seq;
  op->type_kind = kind;
  if (text_set(cat->alloc, &op->id, canon, GDEFCORE_PUBLIC_ID_LEN) !=
          GDEFCORE_OK ||
      text_set(cat->alloc, &op->type_name, type_name, type_len) !=
          GDEFCORE_OK ||
      (machine != NULL &&
          text_set(cat->alloc, &op->machine, machine, machine_len) !=
              GDEFCORE_OK)) {
    op_free(cat->alloc, op);
    changeset->nops -= 1;
    gcu_allocator_free(cat->alloc, type_name);
    gcu_allocator_free(cat->alloc, machine);
    return GDEFCORE_ERR_OOM;
  }
  rc = read_proj_doc(cat, "p:", type_name, type_len, row, &op->base, NULL);
  gcu_allocator_free(cat->alloc, type_name);
  gcu_allocator_free(cat->alloc, machine);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    op_free(cat->alloc, op);
    changeset->nops -= 1;
  }
  return rc;
}

static GDEFCORE_Result revision_text(GDEFCORE_Catalog * catalog, const char * id,
    size_t id_len, char ** out, size_t * out_n) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char row_text[32];
  size_t rn = 0;
  uint64_t row = 0;
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc;
  *out = NULL;
  *out_n = 0;
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = lookup_id(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &row, NULL, NULL, NULL,
      NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = proj_get(catalog, "ra", 2, row_text, rn, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (col_find(proj, "v", 1, &val, &vlen) && vlen > 0) {
    *out = dup_span(catalog->alloc, (const char *)val, vlen);
    if (*out == NULL) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_OOM;
    }
    *out_n = vlen;
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

static size_t revision_lines(const char * text, size_t n) {
  size_t i;
  size_t count = 0;
  size_t start = 0;
  if (text == NULL || n == 0) {
    return 0;
  }
  for (i = 0; i <= n; i++) {
    if (i == n || text[i] == '\n') {
      if (i > start) {
        count += 1;
      }
      start = i + 1;
    }
  }
  return count;
}

static int revision_line(const char * text, size_t n, size_t index,
    uint64_t * out_seq, const char ** out_actor, size_t * out_actor_len) {
  size_t i;
  size_t start = 0;
  size_t seen = 0;
  for (i = 0; i <= n; i++) {
    if (i == n || text[i] == '\n') {
      if (i > start) {
        if (seen == index) {
          size_t at = start;
          uint64_t seq = 0;
          while (at < i && text[at] >= '0' && text[at] <= '9') {
            seq = seq * 10u + (uint64_t)(text[at] - '0');
            at += 1;
          }
          if (at == start) {
            return 0;
          }
          *out_seq = seq;
          *out_actor = NULL;
          *out_actor_len = 0;
          if (at < i && text[at] == ' ') {
            at += 1;
            if (at < i) {
              *out_actor = text + at;
              *out_actor_len = i - at;
            }
          }
          return 1;
        }
        seen += 1;
      }
      start = i + 1;
    }
  }
  return 0;
}

GDEFCORE_Result gdefcore_entity_revision_count(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, size_t * out_count) {
  char * text = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = revision_text(catalog, id, id_len, &text, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_count = revision_lines(text, n);
  gcu_allocator_free(catalog->alloc, text);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_revision_at(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, size_t index, uint64_t * out_seq,
    char ** out_actor, size_t * out_actor_len) {
  char * text = NULL;
  size_t n = 0;
  uint64_t seq = 0;
  const char * actor = NULL;
  size_t actor_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_seq == NULL || out_actor == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = revision_text(catalog, id, id_len, &text, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!revision_line(text, n, index, &seq, &actor, &actor_len)) {
    gcu_allocator_free(catalog->alloc, text);
    return GDEFCORE_ERR_INVALID;
  }
  if (actor != NULL && actor_len > 0) {
    char * copy = dup_span(catalog->alloc, actor, actor_len);
    if (copy == NULL) {
      gcu_allocator_free(catalog->alloc, text);
      return GDEFCORE_ERR_OOM;
    }
    *out_actor = copy;
    if (out_actor_len != NULL) {
      *out_actor_len = actor_len;
    }
  } else {
    *out_actor = NULL;
    if (out_actor_len != NULL) {
      *out_actor_len = 0;
    }
  }
  *out_seq = seq;
  gcu_allocator_free(catalog->alloc, text);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_revision(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, uint64_t * out_seq) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_seq == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = lookup_id(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &row, NULL, NULL, NULL,
      NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return read_high(catalog, row, out_seq);
}

static GDEFCORE_Result values_from(GDEFCORE_Catalog * cat, const GDEFCORE_Doc * doc,
    const char * lang, size_t lang_len, const char * field, size_t field_len,
    char *** out_texts, size_t ** out_lens, size_t * out_count) {
  GDEFCORE_Vals * slot;
  char ** texts;
  size_t * lens;
  size_t i;
  GDEFCORE_Doc * mutable_doc = (GDEFCORE_Doc *)doc;
  slot = doc_field(mutable_doc, lang, lang_len, field, field_len);
  if (slot == NULL || slot->nvals == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  texts = (char **)mem0(cat->alloc, slot->nvals * sizeof *texts);
  lens = (size_t *)mem0(cat->alloc, slot->nvals * sizeof *lens);
  if (texts == NULL || lens == NULL) {
    gcu_allocator_free(cat->alloc, texts);
    gcu_allocator_free(cat->alloc, lens);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < slot->nvals; i++) {
    texts[i] = dup_span(cat->alloc, slot->vals[i].p, slot->vals[i].n);
    if (texts[i] == NULL) {
      size_t k;
      for (k = 0; k < i; k++) {
        gcu_allocator_free(cat->alloc, texts[k]);
      }
      gcu_allocator_free(cat->alloc, texts);
      gcu_allocator_free(cat->alloc, lens);
      return GDEFCORE_ERR_OOM;
    }
    lens[i] = slot->vals[i].n;
  }
  *out_texts = texts;
  *out_lens = lens;
  *out_count = slot->nvals;
  return GDEFCORE_OK;
}

void gdefcore_values_free(GDEFCORE_Catalog * catalog, char ** texts,
    size_t * lens, size_t count) {
  size_t i;
  if (catalog == NULL) {
    return;
  }
  for (i = 0; i < count; i++) {
    gcu_allocator_free(catalog->alloc, texts == NULL ? NULL : texts[i]);
  }
  gcu_allocator_free(catalog->alloc, texts);
  gcu_allocator_free(catalog->alloc, lens);
}

GDEFCORE_Result gdefcore_entity_values(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * changeset, int view, const char * id,
    size_t id_len, const char * lang, size_t lang_len, const char * field,
    size_t field_len, char *** out_texts, size_t ** out_lens,
    size_t * out_count) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  const GDEFCORE_Op * op;
  uint64_t row = 0;
  char * type_name = NULL;
  size_t type_len = 0;
  GDEFCORE_Doc doc;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_texts == NULL || out_lens == NULL ||
      out_count == NULL ||
      (view != GDEFCORE_VIEW_PUBLISHED && view != GDEFCORE_VIEW_DRAFT)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (changeset != NULL) {
    size_t i;
    for (i = 0; i < changeset->nops; i++) {
      op = &changeset->ops[i];
      if (op->id.p != NULL &&
          span_eq(op->id.p, op->id.n, canon, GDEFCORE_PUBLIC_ID_LEN) &&
          op->kind != GDEFCORE_OP_DEFINE) {
        if (op->kind == GDEFCORE_OP_CLEAR) {
          return GDEFCORE_ERR_INVALID;
        }
        return values_from(catalog, &op->staged, lang, lang_len, field,
            field_len, out_texts, out_lens, out_count);
      }
    }
  }
  rc = lookup_id(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &row, &type_name,
      &type_len, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = read_proj_doc(catalog, view == GDEFCORE_VIEW_DRAFT ? "d:" : "p:",
      type_name, type_len, row, &doc, NULL);
  gcu_allocator_free(catalog->alloc, type_name);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = values_from(catalog, &doc, lang, lang_len, field, field_len, out_texts,
      out_lens, out_count);
  doc_free(catalog->alloc, &doc);
  return rc;
}

static int cmp_cstr(const void * a, const void * b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

static void free_cstrs(const GDEFCORE_Allocator * alloc, char ** items,
    size_t n) {
  size_t i;
  if (items == NULL) {
    return;
  }
  for (i = 0; i < n; i++) {
    gcu_allocator_free(alloc, items[i]);
  }
  gcu_allocator_free(alloc, items);
}

GDEFCORE_Result gdefcore_changeset_diff(const GDEFCORE_Changeset * changeset,
    char ** out_text, size_t * out_len) {
  const GDEFCORE_Allocator * alloc;
  char ** lines = NULL;
  size_t nlines = 0;
  size_t i;
  Grow g;
  if (changeset == NULL || out_text == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  alloc = changeset->catalog->alloc;
  for (i = 0; i < changeset->nops; i++) {
    const GDEFCORE_Op * op = &changeset->ops[i];
    size_t a;
    size_t b;
    if (op->kind == GDEFCORE_OP_DEFINE) {
      continue;
    }
    for (a = 0; a < op->base.nlangs; a++) {
      for (b = 0; b < op->base.langs[a].nfields; b++) {
        (void)b;
      }
    }
    {
      size_t pass;
      for (pass = 0; pass < 2; pass++) {
        const GDEFCORE_Doc * doc = pass == 0 ? &op->base : &op->staged;
        size_t li;
        size_t fi;
        for (li = 0; li < doc->nlangs; li++) {
          for (fi = 0; fi < doc->langs[li].nfields; fi++) {
            const GDEFCORE_Vals * other;
            const GDEFCORE_Doc * other_doc = pass == 0 ? &op->staged : &op->base;
            int seen = 0;
            size_t s;
            char * left = NULL;
            char * right = NULL;
            size_t ln = 0;
            size_t rn = 0;
            char * line;
            int kn;
            if (pass == 1) {
              other = NULL;
              for (s = 0; s < op->base.nlangs; s++) {
                if (span_eq(op->base.langs[s].lang.p, op->base.langs[s].lang.n,
                        doc->langs[li].lang.p, doc->langs[li].lang.n)) {
                  size_t f;
                  for (f = 0; f < op->base.langs[s].nfields; f++) {
                    if (span_eq(op->base.langs[s].fields[f].name.p,
                            op->base.langs[s].fields[f].name.n,
                            doc->langs[li].fields[fi].name.p,
                            doc->langs[li].fields[fi].name.n)) {
                      seen = 1;
                    }
                  }
                }
              }
              if (seen) {
                continue;
              }
            }
            other = NULL;
            (void)other;
            (void)other_doc;
            if (join_vals(alloc, pass == 0
                                     ? &op->base.langs[li].fields[fi]
                                     : doc_field((GDEFCORE_Doc *)&op->base,
                                           doc->langs[li].lang.p,
                                           doc->langs[li].lang.n,
                                           doc->langs[li].fields[fi].name.p,
                                           doc->langs[li].fields[fi].name.n),
                    &left, &ln) != GDEFCORE_OK) {
              free_cstrs(alloc, lines, nlines);
              return GDEFCORE_ERR_OOM;
            }
            if (join_vals(alloc, pass == 0
                                     ? doc_field((GDEFCORE_Doc *)&op->staged,
                                           op->base.langs[li].lang.p,
                                           op->base.langs[li].lang.n,
                                           op->base.langs[li].fields[fi].name.p,
                                           op->base.langs[li].fields[fi].name.n)
                                     : &doc->langs[li].fields[fi],
                    &right, &rn) != GDEFCORE_OK) {
              gcu_allocator_free(alloc, left);
              free_cstrs(alloc, lines, nlines);
              return GDEFCORE_ERR_OOM;
            }
            if (span_eq(left, ln, right, rn)) {
              gcu_allocator_free(alloc, left);
              gcu_allocator_free(alloc, right);
              continue;
            }
            line = (char *)mem(alloc, ln + rn +
                                         (pass == 0 ? op->base.langs[li].lang.n
                                                    : doc->langs[li].lang.n) +
                                         (pass == 0
                                                 ? op->base.langs[li]
                                                       .fields[fi]
                                                       .name.n
                                                 : doc->langs[li]
                                                       .fields[fi]
                                                       .name.n) +
                                         8);
            if (line == NULL) {
              gcu_allocator_free(alloc, left);
              gcu_allocator_free(alloc, right);
              free_cstrs(alloc, lines, nlines);
              return GDEFCORE_ERR_OOM;
            }
            if (pass == 0) {
              kn = snprintf(line, ln + rn + op->base.langs[li].lang.n +
                                       op->base.langs[li].fields[fi].name.n + 8,
                  "%.*s %.*s: %s -> %s", (int)op->base.langs[li].lang.n,
                  op->base.langs[li].lang.p,
                  (int)op->base.langs[li].fields[fi].name.n,
                  op->base.langs[li].fields[fi].name.p, left, right);
            } else {
              kn = snprintf(line, ln + rn + doc->langs[li].lang.n +
                                       doc->langs[li].fields[fi].name.n + 8,
                  "%.*s %.*s: %s -> %s", (int)doc->langs[li].lang.n,
                  doc->langs[li].lang.p,
                  (int)doc->langs[li].fields[fi].name.n,
                  doc->langs[li].fields[fi].name.p, left, right);
            }
            gcu_allocator_free(alloc, left);
            gcu_allocator_free(alloc, right);
            if (kn <= 0) {
              gcu_allocator_free(alloc, line);
              free_cstrs(alloc, lines, nlines);
              return GDEFCORE_ERR_LIMIT;
            }
            {
              char ** next = (char **)gcu_allocator_realloc(
                  alloc, lines, (nlines + 1) * sizeof *next);
              if (next == NULL) {
                gcu_allocator_free(alloc, line);
                free_cstrs(alloc, lines, nlines);
                return GDEFCORE_ERR_OOM;
              }
              lines = next;
              lines[nlines++] = line;
            }
          }
        }
      }
    }
  }
  if (nlines > 1) {
    qsort(lines, nlines, sizeof *lines, cmp_cstr);
  }
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  for (i = 0; i < nlines; i++) {
    if (i > 0) {
      grow_add(&g, "\n", 1);
    }
    grow_add(&g, lines[i], strlen(lines[i]));
    gcu_allocator_free(alloc, lines[i]);
  }
  gcu_allocator_free(alloc, lines);
  if (g.oom) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  if (g.p == NULL) {
    g.p = dup_span(alloc, "", 0);
    if (g.p == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  *out_text = g.p;
  *out_len = g.n;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_changeset_rate(const GDEFCORE_Changeset * changeset,
    int * out_risk) {
  size_t i;
  int high = 0;
  if (changeset == NULL || out_risk == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < changeset->nops; i++) {
    if (changeset->ops[i].kind == GDEFCORE_OP_DEFINE ||
        changeset->ops[i].kind == GDEFCORE_OP_ENABLE ||
        changeset->ops[i].kind == GDEFCORE_OP_DISABLE ||
        changeset->ops[i].type_kind == GDEFCORE_TYPE_CONFIG) {
      high = 1;
    }
  }
  *out_risk = high ? GDEFCORE_RISK_HIGH : GDEFCORE_RISK_LOW;
  return GDEFCORE_OK;
}

static GDEFCORE_Result append_confirm_lines(Grow * g,
    const GDEFCORE_Changeset * cs) {
  char ** lines;
  size_t i;
  size_t n = 0;
  char * prev = NULL;
  const GDEFCORE_Allocator * alloc = cs->catalog->alloc;
  if (cs->nlines == 0) {
    return GDEFCORE_OK;
  }
  lines = (char **)mem0(alloc, cs->nlines * sizeof *lines);
  if (lines == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < cs->nlines; i++) {
    lines[n] = dup_span(alloc, cs->lines[i].p, cs->lines[i].n);
    if (lines[n] == NULL) {
      free_cstrs(alloc, lines, n);
      return GDEFCORE_ERR_OOM;
    }
    n += 1;
  }
  if (n > 1) {
    qsort(lines, n, sizeof *lines, cmp_cstr);
  }
  for (i = 0; i < n; i++) {
    if (prev != NULL && strcmp(lines[i], prev) == 0) {
      gcu_allocator_free(alloc, lines[i]);
      continue;
    }
    if (g->n > 0) {
      grow_add(g, "\n", 1);
    }
    grow_add(g, lines[i], strlen(lines[i]));
    gcu_allocator_free(alloc, prev);
    prev = lines[i];
  }
  gcu_allocator_free(alloc, prev);
  gcu_allocator_free(alloc, lines);
  if (g->oom) {
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result confirm_text(const GDEFCORE_Changeset * cs, char ** out,
    size_t * out_len) {
  char ** names = NULL;
  size_t n = 0;
  size_t i;
  Grow g;
  const GDEFCORE_Allocator * alloc = cs->catalog->alloc;
  for (i = 0; i < cs->nops; i++) {
    const char * name = NULL;
    size_t name_len = 0;
    if (cs->ops[i].kind == GDEFCORE_OP_DEFINE ||
        cs->ops[i].kind == GDEFCORE_OP_ENABLE ||
        cs->ops[i].kind == GDEFCORE_OP_DISABLE) {
      name = cs->ops[i].machine.p;
      name_len = cs->ops[i].machine.n;
    } else if (cs->ops[i].type_kind == GDEFCORE_TYPE_CONFIG &&
               cs->ops[i].type_name.p != NULL) {
      name = cs->ops[i].type_name.p;
      name_len = cs->ops[i].type_name.n;
    }
    if (name != NULL) {
      char * copy = dup_span(alloc, name, name_len);
      char ** next;
      if (copy == NULL) {
        free_cstrs(alloc, names, n);
        return GDEFCORE_ERR_OOM;
      }
      next = (char **)gcu_allocator_realloc(alloc, names, (n + 1) * sizeof *next);
      if (next == NULL) {
        gcu_allocator_free(alloc, copy);
        free_cstrs(alloc, names, n);
        return GDEFCORE_ERR_OOM;
      }
      names = next;
      names[n++] = copy;
    }
  }
  if (n > 1) {
    qsort(names, n, sizeof *names, cmp_cstr);
  }
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  {
    char * kept = NULL;
    for (i = 0; i < n; i++) {
      if (kept != NULL && strcmp(names[i], kept) == 0) {
        gcu_allocator_free(alloc, names[i]);
        continue;
      }
      if (g.n > 0) {
        grow_add(&g, "\n", 1);
      }
      grow_add(&g, names[i], strlen(names[i]));
      gcu_allocator_free(alloc, kept);
      kept = names[i];
    }
    gcu_allocator_free(alloc, kept);
  }
  gcu_allocator_free(alloc, names);
  if (g.oom) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  if (append_confirm_lines(&g, cs) != GDEFCORE_OK) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  if (g.p == NULL) {
    g.p = dup_span(alloc, "", 0);
    if (g.p == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = g.p;
  *out_len = g.n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result name_list(GDEFCORE_Changeset * cs) {
  Grow g;
  char ** names = NULL;
  size_t n = 0;
  size_t i;
  const GDEFCORE_Allocator * alloc = cs->catalog->alloc;
  text_clear(alloc, &cs->conflict);
  for (i = 0; i < cs->nops; i++) {
    const char * name = cs->ops[i].id.p != NULL ? cs->ops[i].id.p
                                                : cs->ops[i].machine.p;
    size_t name_len =
        cs->ops[i].id.p != NULL ? cs->ops[i].id.n : cs->ops[i].machine.n;
    char * copy;
    char ** next;
    if (name == NULL) {
      continue;
    }
    copy = dup_span(alloc, name, name_len);
    if (copy == NULL) {
      free_cstrs(alloc, names, n);
      return GDEFCORE_ERR_OOM;
    }
    next = (char **)gcu_allocator_realloc(alloc, names, (n + 1) * sizeof *next);
    if (next == NULL) {
      gcu_allocator_free(alloc, copy);
      free_cstrs(alloc, names, n);
      return GDEFCORE_ERR_OOM;
    }
    names = next;
    names[n++] = copy;
  }
  if (n > 1) {
    qsort(names, n, sizeof *names, cmp_cstr);
  }
  memset(&g, 0, sizeof g);
  g.alloc = alloc;
  {
    char * kept = NULL;
    for (i = 0; i < n; i++) {
      if (kept != NULL && strcmp(names[i], kept) == 0) {
        gcu_allocator_free(alloc, names[i]);
        continue;
      }
      if (g.n > 0) {
        grow_add(&g, "\n", 1);
      }
      grow_add(&g, names[i], strlen(names[i]));
      gcu_allocator_free(alloc, kept);
      kept = names[i];
    }
    gcu_allocator_free(alloc, kept);
  }
  gcu_allocator_free(alloc, names);
  if (g.oom) {
    gcu_allocator_free(alloc, g.p);
    return GDEFCORE_ERR_OOM;
  }
  cs->conflict.p = g.p == NULL ? dup_span(alloc, "", 0) : g.p;
  cs->conflict.n = g.p == NULL ? 0 : g.n;
  if (cs->conflict.p == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result bump_epoch(GDEFSTOR_Write * write, uint64_t next) {
  return put_u64_col(write, "e", 1, "epoch", 5, "n", next);
}

/* One row's recorded revision actors, appended as this write applies. */
typedef struct ActorNote {
  uint64_t row;
  char * text;
  size_t n;
} ActorNote;

typedef struct ActorLog {
  const GDEFCORE_Allocator * alloc;
  ActorNote * notes;
  size_t n;
} ActorLog;

static void actor_log_free(ActorLog * log) {
  size_t i;
  if (log == NULL || log->alloc == NULL) {
    return;
  }
  for (i = 0; i < log->n; i++) {
    gcu_allocator_free(log->alloc, log->notes[i].text);
  }
  gcu_allocator_free(log->alloc, log->notes);
  log->notes = NULL;
  log->n = 0;
}

static GDEFCORE_Result actor_load(GDEFCORE_Catalog * cat, uint64_t row,
    char ** out, size_t * out_n) {
  char row_text[32];
  size_t rn = 0;
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc;
  *out = NULL;
  *out_n = 0;
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = proj_get(cat, "ra", 2, row_text, rn, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (col_find(proj, "v", 1, &val, &vlen) && vlen > 0) {
    *out = dup_span(cat->alloc, (const char *)val, vlen);
    if (*out == NULL) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_OOM;
    }
    *out_n = vlen;
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

static int actor_chars(const char * actor, size_t actor_len) {
  size_t i;
  if (actor == NULL || actor_len != GDEFCORE_PUBLIC_ID_LEN) {
    return 0;
  }
  for (i = 0; i < actor_len; i++) {
    if (actor[i] == ' ' || actor[i] == '\n' || actor[i] == '\r') {
      return 0;
    }
  }
  return 1;
}

static GDEFCORE_Result note_actor(GDEFCORE_Catalog * cat, GDEFSTOR_Write * write,
    ActorLog * log, uint64_t row, uint64_t seq, const char * actor,
    size_t actor_len) {
  char row_text[32];
  char line[80];
  size_t rn = 0;
  size_t line_n = 0;
  size_t i;
  ActorNote * note = NULL;
  char * next;
  GDEFSTOR_Column column;
  if (log == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!u64_put(row, row_text, sizeof row_text, &rn) ||
      !u64_put(seq, line, sizeof line, &line_n)) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (actor_chars(actor, actor_len)) {
    if (line_n + 1 + actor_len + 1 >= sizeof line) {
      return GDEFCORE_ERR_LIMIT;
    }
    line[line_n++] = ' ';
    memcpy(line + line_n, actor, actor_len);
    line_n += actor_len;
  }
  line[line_n++] = '\n';
  for (i = 0; i < log->n; i++) {
    if (log->notes[i].row == row) {
      note = &log->notes[i];
      break;
    }
  }
  if (note == NULL) {
    ActorNote * notes = (ActorNote *)gcu_allocator_realloc(log->alloc, log->notes,
        (log->n + 1) * sizeof *notes);
    GDEFCORE_Result rc;
    if (notes == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    log->notes = notes;
    note = &log->notes[log->n];
    memset(note, 0, sizeof *note);
    note->row = row;
    rc = actor_load(cat, row, &note->text, &note->n);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    log->n += 1;
  }
  next = (char *)gcu_allocator_realloc(log->alloc, note->text, note->n + line_n + 1);
  if (next == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(next + note->n, line, line_n);
  next[note->n + line_n] = '\0';
  note->text = next;
  note->n += line_n;
  memset(&column, 0, sizeof column);
  column.name = "v";
  column.name_len = 1;
  column.value = (const uint8_t *)note->text;
  column.value_len = note->n;
  return map_stor(gdefstor_projection_put(
      write, "ra", 2, row_text, rn, &column, 1));
}

static GDEFCORE_Result apply_op(GDEFCORE_Catalog * cat, GDEFSTOR_Write * write,
    RowCursor * cursor, GDEFCORE_Op * op, const char * actor, size_t actor_len,
    ActorLog * log) {
  char * lang = NULL;
  size_t lang_len = 0;
  uint64_t seq;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (op->kind == GDEFCORE_OP_DEFINE) {
    char * existing_id = NULL;
    size_t existing_id_len = 0;
    uint64_t existing_row = 0;
    int is_new = 1;
    rc = load_type(cat, op->machine.p, op->machine.n, NULL, NULL, NULL,
        &existing_id, &existing_id_len, &existing_row);
    if (rc == GDEFCORE_OK) {
      is_new = 0;
      if (op->have_row && (op->row != existing_row)) {
        gcu_allocator_free(cat->alloc, existing_id);
        return GDEFCORE_ERR_INVALID;
      }
    } else if (rc != GDEFCORE_ERR_INVALID) {
      return rc;
    } else {
      rc = GDEFCORE_OK;
    }
    rc = write_type_row(cat, write, cursor, op->machine.p, op->machine.n,
        op->type_kind, op->decls, op->ndecls, existing_id, existing_id_len,
        existing_row, is_new);
    gcu_allocator_free(cat->alloc, existing_id);
    return rc;
  }
  if (op->kind == GDEFCORE_OP_PUBLISH) {
    char * lang = NULL;
    size_t lang_len = 0;
    rc = doc_json(cat->alloc, &op->staged, &lang, &lang_len);
    if (rc == GDEFCORE_OK) {
      rc = put_entity_proj(write, "p:", op->type_name.p, op->type_name.n,
          op->row, op->base_seq, op->id.p, op->id.n, lang, lang_len, actor,
          actor_len);
    }
    gcu_allocator_free(cat->alloc, lang);
    return rc;
  }
  if (op->kind == GDEFCORE_OP_CLEAR) {
    rc = delete_entity_proj(write, "p:", op->type_name.p, op->type_name.n,
        op->row);
    if (rc == GDEFCORE_OK) {
      rc = delete_entity_proj(write, "d:", op->type_name.p, op->type_name.n,
          op->row);
    }
    return rc;
  }
  if (op->base_seq == UINT64_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  seq = op->base_seq + 1;
  rc = doc_json(cat->alloc, &op->staged, &lang, &lang_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = append_rev(write, seq, op->row, op->id.p, op->id.n, op->type_name.p,
      op->type_name.n, lang, lang_len);
  if (rc == GDEFCORE_OK) {
    rc = note_actor(cat, write, log, op->row, seq, actor, actor_len);
  }
  if (rc == GDEFCORE_OK && op->kind != GDEFCORE_OP_DRAFT) {
    rc = put_entity_proj(write, "p:", op->type_name.p, op->type_name.n, op->row,
        seq, op->id.p, op->id.n, lang, lang_len, actor, actor_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_entity_proj(write, "d:", op->type_name.p, op->type_name.n, op->row,
        seq, op->id.p, op->id.n, lang, lang_len, actor, actor_len);
  }
  if (rc == GDEFCORE_OK) {
    char row_text[32];
    size_t rn = 0;
    if (!u64_put(op->row, row_text, sizeof row_text, &rn)) {
      rc = GDEFCORE_ERR_LIMIT;
    } else {
      rc = put_u64_col(write, "w", 1, row_text, rn, "seq", seq);
    }
  }
  gcu_allocator_free(cat->alloc, lang);
  return rc;
}

const uint8_t * gdefcore_catalog_tenant(const GDEFCORE_Catalog * catalog,
    size_t * out_len) {
  if (catalog == NULL) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = catalog->tenant_len;
  }
  return catalog->tenant;
}

void gdefcore_catalog_bind_host(GDEFCORE_Catalog * catalog,
    GDEFCORE_Host * host) {
  if (catalog == NULL) {
    return;
  }
  catalog->host = host;
}

void gdefcore_changeset_set_request(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request) {
  if (changeset == NULL) {
    return;
  }
  changeset->request = request;
}

GDEFCORE_Result gdefcore_changeset_stage_module(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, int enable) {
  GDEFCORE_Op * op;
  GDEFCORE_Result rc;
  if (changeset == NULL || changeset->applied ||
      !module_name_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = add_op(changeset, &op);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  op->kind = enable ? GDEFCORE_OP_ENABLE : GDEFCORE_OP_DISABLE;
  op->type_kind = GDEFCORE_TYPE_CONFIG;
  op->have_row = 0;
  if (text_set(changeset->catalog->alloc, &op->machine, name, name_len) !=
      GDEFCORE_OK) {
    op_free(changeset->catalog->alloc, op);
    changeset->nops -= 1;
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_OK;
}

size_t gdefcore_changeset_module_count(const GDEFCORE_Changeset * changeset) {
  size_t i;
  size_t n = 0;
  if (changeset == NULL) {
    return 0;
  }
  for (i = 0; i < changeset->nops; i++) {
    if (changeset->ops[i].kind == GDEFCORE_OP_ENABLE ||
        changeset->ops[i].kind == GDEFCORE_OP_DISABLE) {
      n += 1;
    }
  }
  return n;
}

GDEFCORE_Result gdefcore_changeset_module_at(const GDEFCORE_Changeset * changeset,
    size_t index, const char ** out_name, size_t * out_len, int * out_enable) {
  size_t i;
  size_t seen = 0;
  if (changeset == NULL || out_name == NULL || out_len == NULL ||
      out_enable == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < changeset->nops; i++) {
    if (changeset->ops[i].kind != GDEFCORE_OP_ENABLE &&
        changeset->ops[i].kind != GDEFCORE_OP_DISABLE) {
      continue;
    }
    if (seen == index) {
      *out_name = changeset->ops[i].machine.p;
      *out_len = changeset->ops[i].machine.n;
      *out_enable = changeset->ops[i].kind == GDEFCORE_OP_ENABLE;
      return GDEFCORE_OK;
    }
    seen += 1;
  }
  return GDEFCORE_ERR_INVALID;
}

static int module_op_kind(int kind) {
  return kind == GDEFCORE_OP_ENABLE || kind == GDEFCORE_OP_DISABLE;
}

static GDEFCORE_Result fire_named(GDEFCORE_Changeset * changeset,
    const GDEFCORE_Op * op, const char * hook) {
  GDEFCORE_Write_Hook args;
  if (changeset->catalog->host == NULL) {
    return GDEFCORE_OK;
  }
  memset(&args, 0, sizeof args);
  args.size = sizeof args;
  args.entity_id = op->id.p;
  args.entity_id_len = op->id.n;
  args.type_name = op->type_name.p;
  args.type_name_len = op->type_name.n;
  args.base_seq = op->base_seq;
  return gdefcore_module_fire_write(changeset->catalog->host,
      changeset->request, changeset->catalog, hook, strlen(hook), &args);
}

GDEFCORE_Result gdefcore_changeset_apply(GDEFCORE_Changeset * changeset,
    const char * confirmation, size_t confirmation_len) {
  int risk = 0;
  uint64_t epoch = 0;
  GDEFSTOR_Write * write = NULL;
  RowCursor cursor;
  GDEFCORE_Result rc;
  size_t i;
  char * expect = NULL;
  size_t expect_len = 0;
  if (changeset == NULL || changeset->applied) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_changeset_rate(changeset, &risk);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (risk == GDEFCORE_RISK_HIGH) {
    rc = confirm_text(changeset, &expect, &expect_len);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (confirmation == NULL ||
        !span_eq(expect, expect_len, confirmation, confirmation_len)) {
      gcu_allocator_free(changeset->catalog->alloc, expect);
      return GDEFCORE_ERR_INVALID;
    }
    gcu_allocator_free(changeset->catalog->alloc, expect);
  }
  rc = read_epoch(changeset->catalog, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (epoch != changeset->epoch) {
    return name_list(changeset);
  }
  for (i = 0; i < changeset->nops; i++) {
    GDEFCORE_Op * op = &changeset->ops[i];
    if (!op->have_row) {
      continue;
    }
    {
      uint64_t high = 0;
      rc = read_high(changeset->catalog, op->row, &high);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
      if (high != op->base_seq) {
        return name_list(changeset);
      }
    }
  }
  if (gdefcore_changeset_module_count(changeset) > 0) {
    if (changeset->catalog->host == NULL) {
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_module_vet(changeset->catalog->host,
        changeset->catalog->tenant, changeset->catalog->tenant_len, changeset);
    if (rc != GDEFCORE_OK) {
      gdefcore_module_clear_pending(changeset->catalog->host);
      return rc;
    }
  }
  rc = map_stor(gdefstor_write_begin(changeset->catalog->store,
      (const char *)changeset->catalog->tenant,
      changeset->catalog->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    if (changeset->catalog->host != NULL) {
      gdefcore_module_clear_pending(changeset->catalog->host);
    }
    return rc;
  }
  rc = cursor_load(changeset->catalog, &cursor);
  {
    ActorLog noted;
    memset(&noted, 0, sizeof noted);
    noted.alloc = changeset->catalog->alloc;
    for (i = 0; rc == GDEFCORE_OK && i < changeset->nops; i++) {
    GDEFCORE_Op * op = &changeset->ops[i];
    if (module_op_kind(op->kind)) {
      continue;
    }
    if (op->kind == GDEFCORE_OP_SAVE || op->kind == GDEFCORE_OP_CLEAR ||
        op->kind == GDEFCORE_OP_DRAFT || op->kind == GDEFCORE_OP_PUBLISH) {
      rc = fire_named(changeset, op, GDEFCORE_HOOK_PRESAVE);
      if (rc == GDEFCORE_OK) {
        rc = fire_named(changeset, op, GDEFCORE_HOOK_VALIDATE);
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = apply_op(changeset->catalog, write, &cursor, op, changeset->actor.p,
          changeset->actor.n, &noted);
    }
    if (rc == GDEFCORE_OK &&
        (op->kind == GDEFCORE_OP_SAVE || op->kind == GDEFCORE_OP_DRAFT)) {
      rc = fire_named(changeset, op, GDEFCORE_HOOK_SAVE);
      if (rc == GDEFCORE_OK) {
        rc = fire_named(changeset, op, GDEFCORE_HOOK_REVISION);
      }
    }
    if (rc == GDEFCORE_OK && op->kind == GDEFCORE_OP_CLEAR) {
      rc = fire_named(changeset, op, GDEFCORE_HOOK_DELETE);
    }
  }
    actor_log_free(&noted);
  }
  if (rc == GDEFCORE_OK && gdefcore_changeset_module_count(changeset) > 0) {
    rc = gdefcore_module_write_enables(changeset->catalog->host,
        changeset->catalog->tenant, changeset->catalog->tenant_len, write,
        changeset);
  }
  if (rc == GDEFCORE_OK) {
    rc = cursor_store(write, &cursor);
  }
  if (rc == GDEFCORE_OK) {
    if (epoch == UINT64_MAX) {
      rc = GDEFCORE_ERR_LIMIT;
    } else {
      rc = bump_epoch(write, epoch + 1);
    }
  }
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    if (changeset->catalog->host != NULL) {
      gdefcore_module_clear_pending(changeset->catalog->host);
    }
    return rc;
  }
  rc = map_stor(gdefstor_write_commit(write));
  if (rc != GDEFCORE_OK) {
    if (changeset->catalog->host != NULL) {
      gdefcore_module_clear_pending(changeset->catalog->host);
    }
    return rc;
  }
  changeset->applied = 1;
  changeset->epoch = epoch + 1;
  {
    GDEFCORE_Result grant_rc = gdefcore_access_commit_staged(changeset);
    GDEFCORE_Result first = grant_rc;
    if (changeset->catalog->host != NULL) {
      GDEFCORE_Result hook_rc = GDEFCORE_OK;
      if (gdefcore_changeset_module_count(changeset) > 0) {
        hook_rc = gdefcore_module_after_apply(changeset->catalog->host,
            changeset->catalog->tenant, changeset->catalog->tenant_len,
            changeset);
        if (hook_rc != GDEFCORE_OK && first == GDEFCORE_OK) {
          first = hook_rc;
        }
      }
      for (i = 0; i < changeset->nops; i++) {
        GDEFCORE_Op * op = &changeset->ops[i];
        if (op->kind == GDEFCORE_OP_SAVE || op->kind == GDEFCORE_OP_CLEAR ||
            op->kind == GDEFCORE_OP_DRAFT || op->kind == GDEFCORE_OP_PUBLISH) {
          hook_rc = fire_named(changeset, op, GDEFCORE_HOOK_AFTER_COMMIT);
          if (hook_rc != GDEFCORE_OK && first == GDEFCORE_OK) {
            first = hook_rc;
          }
        }
      }
    }
    if (first != GDEFCORE_OK) {
      return first;
    }
  }
  return GDEFCORE_OK;
}

const char * gdefcore_changeset_conflict(const GDEFCORE_Changeset * changeset,
    size_t * out_len) {
  if (changeset == NULL || changeset->conflict.p == NULL) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = changeset->conflict.n;
  }
  return changeset->conflict.p;
}

GDEFCORE_Result gdefcore_changeset_rebase(GDEFCORE_Changeset * changeset) {
  uint64_t epoch = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (changeset == NULL || changeset->applied) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = read_epoch(changeset->catalog, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  changeset->epoch = epoch;
  for (i = 0; i < changeset->nops; i++) {
    if (!changeset->ops[i].have_row) {
      continue;
    }
    rc = read_high(changeset->catalog, changeset->ops[i].row,
        &changeset->ops[i].base_seq);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  text_clear(changeset->catalog->alloc, &changeset->conflict);
  return GDEFCORE_OK;
}

uint64_t gdefcore_changeset_epoch(const GDEFCORE_Changeset * changeset) {
  return changeset == NULL ? 0 : changeset->epoch;
}

GDEFCORE_Result gdefcore_changeset_base_seq(const GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, uint64_t * out_seq) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t i;
  if (changeset == NULL || out_seq == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < changeset->nops; i++) {
    if (changeset->ops[i].id.p != NULL &&
        span_eq(changeset->ops[i].id.p, changeset->ops[i].id.n, canon,
            GDEFCORE_PUBLIC_ID_LEN)) {
      *out_seq = changeset->ops[i].base_seq;
      return GDEFCORE_OK;
    }
  }
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result rev_doc(GDEFCORE_Catalog * cat, uint64_t row,
    uint64_t seq, GDEFCORE_Doc * doc) {
  char row_text[32];
  size_t rn = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFSTOR_Revision * rev = NULL;
  const char * lang;
  size_t lang_len = 0;
  GDEFCORE_Result rc;
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = map_stor(gdefstor_revision_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, row_text, rn, seq, &bytes, &len));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = map_stor(gdefstor_revision_parse(bytes, len, NULL, NULL, &rev));
  gdefstor_bytes_free(NULL, bytes);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  lang = gdefstor_revision_lang(rev, &lang_len);
  rc = doc_parse(cat->alloc, lang, lang_len, doc);
  gdefstor_revision_free(rev);
  return rc;
}

GDEFCORE_Result gdefcore_changeset_revert(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, const char * actor, size_t actor_len,
    GDEFCORE_Changeset ** out_changeset) {
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Op * op;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t seq = 0;
  uint64_t high = 0;
  char * type_name = NULL;
  size_t type_len = 0;
  char * machine = NULL;
  size_t machine_len = 0;
  int kind = 0;
  GDEFCORE_Decl * decls = NULL;
  size_t ndecls = 0;
  GDEFCORE_Result rc;
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_changeset_prepare(catalog, actor, actor_len, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = lookup_id(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &row, &type_name,
      &type_len, &machine, &machine_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(cs);
    return rc;
  }
  {
    GDEFCORE_Doc published;
    memset(&published, 0, sizeof published);
    rc = read_proj_doc(catalog, "p:", type_name, type_len, row, &published, &seq);
    if (rc != GDEFCORE_OK) {
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return rc;
    }
    rc = load_type(catalog, type_name, type_len, &kind, &decls, &ndecls, NULL,
        NULL, NULL);
    if (rc != GDEFCORE_OK) {
      doc_free(catalog->alloc, &published);
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return rc;
    }
    rc = read_high(catalog, row, &high);
    if (rc != GDEFCORE_OK) {
      doc_free(catalog->alloc, &published);
      decls_free(catalog->alloc, decls, ndecls);
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return rc;
    }
    rc = add_op(cs, &op);
    if (rc != GDEFCORE_OK) {
      doc_free(catalog->alloc, &published);
      decls_free(catalog->alloc, decls, ndecls);
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return rc;
    }
    op->have_row = 1;
    op->row = row;
    op->base_seq = high;
    op->type_kind = kind;
    op->decls = decls;
    op->ndecls = ndecls;
    op->base = published;
    if (text_set(catalog->alloc, &op->id, canon, GDEFCORE_PUBLIC_ID_LEN) !=
            GDEFCORE_OK ||
        text_set(catalog->alloc, &op->type_name, type_name, type_len) !=
            GDEFCORE_OK) {
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_OOM;
    }
    if (machine != NULL &&
        text_set(catalog->alloc, &op->machine, machine, machine_len) !=
            GDEFCORE_OK) {
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_OOM;
    }
    if (seq <= 1) {
      op->kind = GDEFCORE_OP_CLEAR;
    } else {
      op->kind = GDEFCORE_OP_SAVE;
      rc = rev_doc(catalog, row, seq - 1, &op->staged);
      if (rc != GDEFCORE_OK) {
        gcu_allocator_free(catalog->alloc, type_name);
        gcu_allocator_free(catalog->alloc, machine);
        gdefcore_changeset_destroy(cs);
        return rc;
      }
    }
    gcu_allocator_free(catalog->alloc, type_name);
    gcu_allocator_free(catalog->alloc, machine);
    *out_changeset = cs;
    return GDEFCORE_OK;
  }
}


static GDEFCORE_Result patch_add(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Patch ** files, size_t * count, const char * path,
    const char * bytes, size_t len) {
  GDEFCORE_Patch * next;
  GDEFCORE_Patch * slot;
  next = (GDEFCORE_Patch *)gcu_allocator_realloc(
      alloc, *files, (*count + 1) * sizeof *next);
  if (next == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  *files = next;
  slot = &(*files)[*count];
  memset(slot, 0, sizeof *slot);
  slot->size = sizeof *slot;
  slot->path = dup_span(alloc, path, strlen(path));
  slot->bytes = (uint8_t *)dup_span(alloc, bytes, len);
  if (slot->path == NULL || slot->bytes == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  slot->path_len = strlen(path);
  slot->len = len;
  *count += 1;
  return GDEFCORE_OK;
}

static int cmp_patch(const void * a, const void * b) {
  const GDEFCORE_Patch * pa = a;
  const GDEFCORE_Patch * pb = b;
  size_t n = pa->path_len < pb->path_len ? pa->path_len : pb->path_len;
  int cmp = memcmp(pa->path, pb->path, n);
  if (cmp != 0) {
    return cmp;
  }
  if (pa->path_len < pb->path_len) {
    return -1;
  }
  if (pa->path_len > pb->path_len) {
    return 1;
  }
  return 0;
}

void gdefcore_patch_free(GDEFCORE_Catalog * catalog, GDEFCORE_Patch * files,
    size_t count) {
  size_t i;
  if (catalog == NULL || files == NULL) {
    return;
  }
  for (i = 0; i < count; i++) {
    gcu_allocator_free(catalog->alloc, files[i].path);
    gcu_allocator_free(catalog->alloc, files[i].bytes);
  }
  gcu_allocator_free(catalog->alloc, files);
}

GDEFCORE_Result gdefcore_changeset_serialize(const GDEFCORE_Changeset * changeset,
    GDEFCORE_Patch ** out_files, size_t * out_count) {
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  char epoch[32];
  size_t en = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (changeset == NULL || out_files == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  alloc = changeset->catalog->alloc;
  if (!u64_put(changeset->epoch, epoch, sizeof epoch, &en)) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = patch_add(alloc, &files, &count, "format", "defiant-changeset/1", 19);
  if (rc == GDEFCORE_OK) {
    rc = patch_add(alloc, &files, &count, "epoch", epoch, en);
  }
  if (rc == GDEFCORE_OK && changeset->actor.p != NULL) {
    rc = patch_add(alloc, &files, &count, "actor", changeset->actor.p,
        changeset->actor.n);
  }
  for (i = 0; rc == GDEFCORE_OK && i < changeset->nops; i++) {
    const GDEFCORE_Op * op = &changeset->ops[i];
    char path[256];
    char base[32];
    size_t bn = 0;
    int kn;
    if (op->kind == GDEFCORE_OP_DEFINE) {
      const char * kind = op->type_kind == GDEFCORE_TYPE_CONFIG ? "config"
                                                                : "content";
      size_t f;
      kn = snprintf(path, sizeof path, "type/%.*s/kind", (int)op->machine.n,
          op->machine.p);
      if (kn <= 0 || (size_t)kn >= sizeof path) {
        rc = GDEFCORE_ERR_LIMIT;
        break;
      }
      rc = patch_add(alloc, &files, &count, path, kind, strlen(kind));
      for (f = 0; rc == GDEFCORE_OK && f < op->ndecls; f++) {
        const char * word = op->decls[f].required
                                ? (op->decls[f].many ? "required many"
                                                     : "required one")
                                : (op->decls[f].many ? "optional many"
                                                     : "optional one");
        char flag[32];
        char * suffix = NULL;
        size_t suffix_len = 0;
        int fn = snprintf(flag, sizeof flag, "%s%s", word,
            op->decls[f].personal ? " personal" : "");
        if (fn <= 0 || (size_t)fn >= sizeof flag) {
          rc = GDEFCORE_ERR_LIMIT;
          break;
        }
        rc = constraint_suffix(alloc, &op->decls[f], &suffix, &suffix_len);
        if (rc != GDEFCORE_OK) {
          break;
        }
        kn = snprintf(path, sizeof path, "type/%.*s/field/%.*s",
            (int)op->machine.n, op->machine.p, (int)op->decls[f].name.n,
            op->decls[f].name.p);
        if (kn <= 0 || (size_t)kn >= sizeof path) {
          gcu_allocator_free(alloc, suffix);
          rc = GDEFCORE_ERR_LIMIT;
          break;
        }
        if (suffix_len == 0) {
          rc = patch_add(alloc, &files, &count, path, flag, (size_t)fn);
        } else {
          char * both = (char *)gcu_allocator_malloc(
              alloc, (size_t)fn + suffix_len);
          if (both == NULL) {
            gcu_allocator_free(alloc, suffix);
            rc = GDEFCORE_ERR_OOM;
            break;
          }
          memcpy(both, flag, (size_t)fn);
          memcpy(both + fn, suffix, suffix_len);
          rc = patch_add(alloc, &files, &count, path, both,
              (size_t)fn + suffix_len);
          gcu_allocator_free(alloc, both);
        }
        gcu_allocator_free(alloc, suffix);
      }
      continue;
    }
    if (op->kind == GDEFCORE_OP_ENABLE || op->kind == GDEFCORE_OP_DISABLE) {
      const char * word =
          op->kind == GDEFCORE_OP_ENABLE ? "enable" : "disable";
      kn = snprintf(path, sizeof path, "module/%.*s/op", (int)op->machine.n,
          op->machine.p);
      if (kn <= 0 || (size_t)kn >= sizeof path) {
        rc = GDEFCORE_ERR_LIMIT;
        break;
      }
      rc = patch_add(alloc, &files, &count, path, word, strlen(word));
      continue;
    }
    kn = snprintf(path, sizeof path, "entity/%.*s/type", (int)op->id.n, op->id.p);
    if (kn <= 0 || (size_t)kn >= sizeof path) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    rc = patch_add(alloc, &files, &count, path, op->type_name.p, op->type_name.n);
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (!u64_put(op->base_seq, base, sizeof base, &bn)) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    kn = snprintf(path, sizeof path, "entity/%.*s/base", (int)op->id.n, op->id.p);
    if (kn <= 0 || (size_t)kn >= sizeof path) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    rc = patch_add(alloc, &files, &count, path, base, bn);
    if (rc != GDEFCORE_OK) {
      break;
    }
    kn = snprintf(path, sizeof path, "entity/%.*s/op", (int)op->id.n, op->id.p);
    if (kn <= 0 || (size_t)kn >= sizeof path) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    if (op->kind == GDEFCORE_OP_CLEAR) {
      rc = patch_add(alloc, &files, &count, path, "clear", 5);
    } else {
      const char * word = "save";
      size_t word_n = 4;
      size_t li;
      if (op->kind == GDEFCORE_OP_DRAFT) {
        word = "draft";
        word_n = 5;
      } else if (op->kind == GDEFCORE_OP_PUBLISH) {
        word = "publish";
        word_n = 7;
      }
      rc = patch_add(alloc, &files, &count, path, word, word_n);
      size_t fi;
      size_t vi;
      for (li = 0; rc == GDEFCORE_OK && li < op->staged.nlangs; li++) {
        for (fi = 0; rc == GDEFCORE_OK && fi < op->staged.langs[li].nfields;
             fi++) {
          for (vi = 0; rc == GDEFCORE_OK &&
                       vi < op->staged.langs[li].fields[fi].nvals;
               vi++) {
            char index[32];
            size_t in = 0;
            if (!u64_put(vi, index, sizeof index, &in)) {
              rc = GDEFCORE_ERR_LIMIT;
              break;
            }
            kn = snprintf(path, sizeof path, "entity/%.*s/lang/%.*s/%.*s/%s",
                (int)op->id.n, op->id.p,
                (int)op->staged.langs[li].lang.n, op->staged.langs[li].lang.p,
                (int)op->staged.langs[li].fields[fi].name.n,
                op->staged.langs[li].fields[fi].name.p, index);
            if (kn <= 0 || (size_t)kn >= sizeof path) {
              rc = GDEFCORE_ERR_LIMIT;
              break;
            }
            rc = patch_add(alloc, &files, &count, path,
                op->staged.langs[li].fields[fi].vals[vi].p,
                op->staged.langs[li].fields[fi].vals[vi].n);
          }
        }
      }
    }
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_patch_free(changeset->catalog, files, count);
    return rc;
  }
  if (count > 1) {
    qsort(files, count, sizeof *files, cmp_patch);
  }
  *out_files = files;
  *out_count = count;
  return GDEFCORE_OK;
}

static const GDEFCORE_Patch * find_file(const GDEFCORE_Patch * files, size_t count,
    const char * path) {
  size_t i;
  size_t n = strlen(path);
  for (i = 0; i < count; i++) {
    if (span_eq(files[i].path, files[i].path_len, path, n)) {
      return &files[i];
    }
  }
  return NULL;
}


static const char * span_chr(const char * s, size_t n, char c) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (s[i] == c) {
      return s + i;
    }
  }
  return NULL;
}

static const char * span_rchr(const char * s, size_t n, char c) {
  size_t i = n;
  while (i > 0) {
    i -= 1;
    if (s[i] == c) {
      return s + i;
    }
  }
  return NULL;
}

static int entity_canon(const char * path, size_t path_len, char * canon,
    const char ** tail, size_t * tail_len) {
  size_t slash = 0;
  size_t n;
  if (path == NULL || path_len < 8 || memcmp(path, "entity/", 7) != 0) {
    return 0;
  }
  n = path_len - 7;
  while (slash < n && path[7 + slash] != '/') {
    slash += 1;
  }
  if (slash == 0 || slash >= n) {
    return 0;
  }
  if (gdefcore_id_canonical(path + 7, slash, canon) != GDEFCORE_OK) {
    return 0;
  }
  *tail = path + 7 + slash;
  *tail_len = n - slash;
  return 1;
}

static const GDEFCORE_Patch * find_entity_tail(const GDEFCORE_Patch * files,
    size_t count, const char * canon, const char * tail, size_t tail_len) {
  size_t i;
  for (i = 0; i < count; i++) {
    char got[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * file_tail;
    size_t file_tail_len;
    if (!entity_canon(files[i].path, files[i].path_len, got, &file_tail,
            &file_tail_len)) {
      continue;
    }
    if (memcmp(got, canon, GDEFCORE_PUBLIC_ID_LEN) != 0) {
      continue;
    }
    if (file_tail_len == tail_len && memcmp(file_tail, tail, tail_len) == 0) {
      return &files[i];
    }
  }
  return NULL;
}

static int lang_tail(const char * tail, size_t tail_len, const char ** lang,
    size_t * lang_len, const char ** field, size_t * field_len,
    const char ** index, size_t * index_len) {
  const char * slash;
  const char * rest;
  const char * last;
  size_t rest_n;
  if (tail == NULL || tail_len < 7 || memcmp(tail, "/lang/", 6) != 0) {
    return 0;
  }
  slash = span_chr(tail + 6, tail_len - 6, '/');
  if (slash == NULL || slash == tail + 6) {
    return 0;
  }
  *lang = tail + 6;
  *lang_len = (size_t)(slash - (tail + 6));
  rest = slash + 1;
  rest_n = (size_t)((tail + tail_len) - rest);
  last = span_rchr(rest, rest_n, '/');
  if (last == NULL || last == rest) {
    return 0;
  }
  *field = rest;
  *field_len = (size_t)(last - rest);
  *index = last + 1;
  *index_len = (size_t)((rest + rest_n) - (last + 1));
  return *field_len > 0 && *index_len > 0 && *lang_len > 0;
}

static GDEFCORE_Result stage_parsed_saves(GDEFCORE_Changeset * cs,
    const GDEFCORE_Patch * files, size_t count, const char * canon,
    const GDEFCORE_Limits * cap) {
  struct {
    const char * name;
    size_t name_len;
    const char * texts[32];
    size_t lens[32];
    size_t nvals;
  } bunch[64];
  GDEFCORE_Value values[64];
  size_t f;
  for (f = 0; f < count; f++) {
    char got[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * tail;
    size_t tail_len;
    const char * lang;
    size_t lang_len;
    const char * field;
    size_t field_len;
    const char * index;
    size_t index_len;
    size_t g;
    size_t nb = 0;
    int seen = 0;
    if (!entity_canon(files[f].path, files[f].path_len, got, &tail, &tail_len) ||
        memcmp(got, canon, GDEFCORE_PUBLIC_ID_LEN) != 0) {
      continue;
    }
    if (tail_len < 6 || memcmp(tail, "/lang/", 6) != 0) {
      continue;
    }
    if (!lang_tail(tail, tail_len, &lang, &lang_len, &field, &field_len, &index,
            &index_len)) {
      return GDEFCORE_ERR_CORRUPT;
    }
    (void)field;
    (void)field_len;
    (void)index;
    (void)index_len;
    for (g = 0; g < f; g++) {
      char earlier_id[GDEFCORE_PUBLIC_ID_LEN + 1];
      const char * earlier_tail;
      size_t earlier_tail_len;
      const char * earlier_lang;
      size_t earlier_lang_len;
      const char * earlier_field;
      size_t earlier_field_len;
      const char * earlier_index;
      size_t earlier_index_len;
      if (!entity_canon(files[g].path, files[g].path_len, earlier_id,
              &earlier_tail, &earlier_tail_len) ||
          memcmp(earlier_id, canon, GDEFCORE_PUBLIC_ID_LEN) != 0 ||
          earlier_tail_len < 6 || memcmp(earlier_tail, "/lang/", 6) != 0) {
        continue;
      }
      if (!lang_tail(earlier_tail, earlier_tail_len, &earlier_lang,
              &earlier_lang_len, &earlier_field, &earlier_field_len,
              &earlier_index, &earlier_index_len)) {
        return GDEFCORE_ERR_CORRUPT;
      }
      (void)earlier_field;
      (void)earlier_field_len;
      (void)earlier_index;
      (void)earlier_index_len;
      if (earlier_lang_len == lang_len &&
          memcmp(earlier_lang, lang, lang_len) == 0) {
        seen = 1;
        break;
      }
    }
    if (seen) {
      continue;
    }
    memset(bunch, 0, sizeof bunch);
    for (g = f; g < count; g++) {
      char other_id[GDEFCORE_PUBLIC_ID_LEN + 1];
      const char * other_tail;
      size_t other_tail_len;
      const char * other_lang;
      size_t other_lang_len;
      const char * other_field;
      size_t other_field_len;
      const char * other_index;
      size_t other_index_len;
      uint64_t n = 0;
      size_t slot;
      size_t s;
      if (!entity_canon(files[g].path, files[g].path_len, other_id, &other_tail,
              &other_tail_len) ||
          memcmp(other_id, canon, GDEFCORE_PUBLIC_ID_LEN) != 0 ||
          other_tail_len < 6 || memcmp(other_tail, "/lang/", 6) != 0) {
        continue;
      }
      if (!lang_tail(other_tail, other_tail_len, &other_lang, &other_lang_len,
              &other_field, &other_field_len, &other_index, &other_index_len)) {
        return GDEFCORE_ERR_CORRUPT;
      }
      if (other_lang_len != lang_len ||
          memcmp(other_lang, lang, lang_len) != 0) {
        continue;
      }
      slot = nb;
      for (s = 0; s < nb; s++) {
        if (bunch[s].name_len == other_field_len &&
            memcmp(bunch[s].name, other_field, other_field_len) == 0) {
          slot = s;
          break;
        }
      }
      if (slot == nb) {
        if (nb >= 64 || nb >= cap->max_fields) {
          return GDEFCORE_ERR_LIMIT;
        }
        bunch[nb].name = other_field;
        bunch[nb].name_len = other_field_len;
        nb += 1;
      }
      if (!u64_get(other_index, other_index_len, &n) || n >= 32 ||
          n >= cap->max_values || bunch[slot].texts[n] != NULL) {
        return GDEFCORE_ERR_CORRUPT;
      }
      bunch[slot].texts[n] = (const char *)files[g].bytes;
      bunch[slot].lens[n] = files[g].len;
      if (n + 1 > bunch[slot].nvals) {
        bunch[slot].nvals = (size_t)n + 1;
      }
    }
    for (g = 0; g < nb; g++) {
      size_t v;
      for (v = 0; v < bunch[g].nvals; v++) {
        if (bunch[g].texts[v] == NULL) {
          return GDEFCORE_ERR_CORRUPT;
        }
      }
      memset(&values[g], 0, sizeof values[g]);
      values[g].size = sizeof values[g];
      values[g].field = bunch[g].name;
      values[g].field_len = bunch[g].name_len;
      values[g].texts = (const char * const *)bunch[g].texts;
      values[g].text_lens = bunch[g].lens;
      values[g].count = bunch[g].nvals;
    }
    {
      GDEFCORE_Result rc = gdefcore_entity_save(cs, canon, GDEFCORE_PUBLIC_ID_LEN,
          lang, lang_len, values, nb);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_changeset_parse(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Patch * files, size_t count, const GDEFCORE_Limits * limits,
    GDEFCORE_Changeset ** out_changeset) {
  GDEFCORE_Limits cap;
  GDEFCORE_Changeset * cs = NULL;
  const GDEFCORE_Patch * format;
  size_t total = 0;
  size_t i;
  GDEFCORE_Result rc;
  uint64_t epoch = 0;
  if (catalog == NULL || out_changeset == NULL || (files == NULL && count != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (limits == NULL) {
    limits_fill(&cap);
  } else {
    cap = *limits;
  }
  if (count > cap.max_patch_files) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < count; i++) {
    if (files[i].size < sizeof(GDEFCORE_Patch) || files[i].path == NULL ||
        (files[i].bytes == NULL && files[i].len != 0)) {
      return GDEFCORE_ERR_INVALID;
    }
    if (files[i].path_len > cap.max_patch_path ||
        files[i].len > cap.max_patch_file ||
        total > cap.max_patch_total ||
        files[i].len > cap.max_patch_total - total) {
      return GDEFCORE_ERR_LIMIT;
    }
    total += files[i].len;
    if (!path_ok(files[i].path, files[i].path_len) ||
        !utf8_ok((const uint8_t *)files[i].path, files[i].path_len) ||
        !utf8_ok(files[i].bytes, files[i].len)) {
      return GDEFCORE_ERR_CORRUPT;
    }
    if (files[i].path_len >= 7 && memcmp(files[i].path, "entity/", 7) == 0) {
      const char * rest = files[i].path + 7;
      size_t rest_len = files[i].path_len - 7;
      size_t slash = 0;
      char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
      while (slash < rest_len && rest[slash] != '/') {
        slash += 1;
      }
      if (gdefcore_id_canonical(rest, slash, canon) != GDEFCORE_OK) {
        return GDEFCORE_ERR_INVALID;
      }
      if (slash >= rest_len) {
        return GDEFCORE_ERR_CORRUPT;
      }
      {
        const char * suffix = rest + slash;
        size_t suffix_len = rest_len - slash;
        int known = span_eq(suffix, suffix_len, "/type", 5) ||
                    span_eq(suffix, suffix_len, "/base", 5) ||
                    span_eq(suffix, suffix_len, "/op", 3) ||
                    (suffix_len >= 6 && memcmp(suffix, "/lang/", 6) == 0);
        if (!known) {
          return GDEFCORE_ERR_CORRUPT;
        }
      }
    } else if (files[i].path_len >= 7 &&
               memcmp(files[i].path, "module/", 7) == 0) {
      const char * rest = files[i].path + 7;
      size_t rest_len = files[i].path_len - 7;
      size_t slash = 0;
      while (slash < rest_len && rest[slash] != '/') {
        slash += 1;
      }
      if (slash == 0 || slash >= rest_len || !module_name_ok(rest, slash) ||
          !span_eq(rest + slash, rest_len - slash, "/op", 3) ||
          (!span_eq((const char *)files[i].bytes, files[i].len, "enable", 6) &&
              !span_eq((const char *)files[i].bytes, files[i].len, "disable",
                  7))) {
        return GDEFCORE_ERR_CORRUPT;
      }
    } else if (!span_eq(files[i].path, files[i].path_len, "format", 6) &&
               !span_eq(files[i].path, files[i].path_len, "epoch", 5) &&
               !span_eq(files[i].path, files[i].path_len, "actor", 5) &&
               !(files[i].path_len >= 5 &&
                   memcmp(files[i].path, "type/", 5) == 0)) {
      return GDEFCORE_ERR_CORRUPT;
    }
  }
  format = find_file(files, count, "format");
  if (format == NULL ||
      !span_eq((const char *)format->bytes, format->len, "defiant-changeset/1",
          19)) {
    return GDEFCORE_ERR_FORMAT;
  }
  {
    const GDEFCORE_Patch * epoch_file = find_file(files, count, "epoch");
    if (epoch_file == NULL ||
        !u64_get((const char *)epoch_file->bytes, epoch_file->len, &epoch)) {
      return GDEFCORE_ERR_CORRUPT;
    }
  }
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  cs->epoch = epoch;
  {
    const GDEFCORE_Patch * actor = find_file(files, count, "actor");
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (actor != NULL) {
      if (gdefcore_id_canonical((const char *)actor->bytes, actor->len, canon) !=
          GDEFCORE_OK) {
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_INVALID;
      }
      if (text_set(catalog->alloc, &cs->actor, canon, GDEFCORE_PUBLIC_ID_LEN) !=
          GDEFCORE_OK) {
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_OOM;
      }
    }
  }
  for (i = 0; i < count; i++) {
    if (files[i].path_len >= 5 && memcmp(files[i].path, "type/", 5) == 0 &&
        files[i].path_len >= 10 &&
        memcmp(files[i].path + files[i].path_len - 5, "/kind", 5) == 0) {
      const char * name = files[i].path + 5;
      size_t name_len = files[i].path_len - 10;
      int kind;
      GDEFCORE_Field stack[64];
      size_t nfields = 0;
      size_t f;
      GDEFCORE_Op * op;
      if (!machine_ok(name, name_len)) {
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_CORRUPT;
      }
      if (span_eq((const char *)files[i].bytes, files[i].len, "content", 7)) {
        kind = GDEFCORE_TYPE_CONTENT;
      } else if (span_eq((const char *)files[i].bytes, files[i].len, "config",
                     6)) {
        kind = GDEFCORE_TYPE_CONFIG;
      } else {
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_CORRUPT;
      }
      for (f = 0; f < count; f++) {
        char prefix[160];
        int kn = snprintf(prefix, sizeof prefix, "type/%.*s/field/",
            (int)name_len, name);
        if (kn <= 0) {
          gdefcore_changeset_destroy(cs);
          return GDEFCORE_ERR_LIMIT;
        }
        if (files[f].path_len > (size_t)kn &&
            memcmp(files[f].path, prefix, (size_t)kn) == 0) {
          const char * fname = files[f].path + kn;
          size_t flen = files[f].path_len - (size_t)kn;
          int required = 0;
          int many = 0;
          int personal = 0;
          const uint8_t * body = files[f].bytes;
          size_t body_len = files[f].len;
          const uint8_t * pipe = NULL;
          size_t flag_len;
          GDEFCORE_Decl extra;
          if (!field_name_ok(fname, flen) || nfields >= cap.max_fields ||
              nfields >= 64) {
            gdefcore_changeset_destroy(cs);
            return GDEFCORE_ERR_CORRUPT;
          }
          memset(&extra, 0, sizeof extra);
          pipe = memchr(body, '|', body_len);
          flag_len = pipe == NULL ? body_len : (size_t)(pipe - body);
          if (pipe != NULL) {
            GDEFCORE_Result crc = fill_constraints(catalog->alloc,
                (const char *)pipe + 1, body_len - flag_len - 1, &extra);
            if (crc != GDEFCORE_OK) {
              text_clear(catalog->alloc, &extra.pattern);
              gdefcore_changeset_destroy(cs);
              return crc;
            }
          }
          body_len = flag_len;
          if (body_len >= 9 && memcmp(body + body_len - 9, " personal", 9) == 0) {
            personal = 1;
            body_len -= 9;
          }
          if (span_eq((const char *)body, body_len, "required one", 12)) {
            required = 1;
          } else if (span_eq((const char *)body, body_len, "required many",
                         13)) {
            required = 1;
            many = 1;
          } else if (span_eq((const char *)body, body_len, "optional one", 12)) {
          } else if (span_eq((const char *)body, body_len, "optional many",
                         13)) {
            many = 1;
          } else {
            size_t z;
            text_clear(catalog->alloc, &extra.pattern);
            for (z = 0; z < nfields; z++) {
              gcu_allocator_free(catalog->alloc, (void *)stack[z].pattern);
            }
            gdefcore_changeset_destroy(cs);
            return GDEFCORE_ERR_CORRUPT;
          }
          memset(&stack[nfields], 0, sizeof stack[nfields]);
          stack[nfields].size = sizeof stack[nfields];
          stack[nfields].name = fname;
          stack[nfields].name_len = flen;
          stack[nfields].required = required;
          stack[nfields].many = many;
          stack[nfields].personal = personal;
          stack[nfields].min_len = extra.min_len;
          stack[nfields].max_len = extra.max_len;
          stack[nfields].has_range = extra.has_range;
          stack[nfields].range_min = extra.range_min;
          stack[nfields].range_max = extra.range_max;
          stack[nfields].pattern = extra.pattern.p;
          stack[nfields].pattern_len = extra.pattern.n;
          nfields += 1;
        }
      }
      rc = gdefcore_changeset_define(cs, name, name_len, kind, stack, nfields);
      for (f = 0; f < nfields; f++) {
        gcu_allocator_free(catalog->alloc, (void *)stack[f].pattern);
        stack[f].pattern = NULL;
      }
      if (rc != GDEFCORE_OK) {
        gdefcore_changeset_destroy(cs);
        return rc;
      }
      op = find_op_machine(cs, name, name_len);
      (void)op;
    }
  }
  for (i = 0; i < count; i++) {
    const char * rest;
    size_t slash = 0;
    int enable;
    if (files[i].path_len < 11 || memcmp(files[i].path, "module/", 7) != 0) {
      continue;
    }
    rest = files[i].path + 7;
    while (slash < files[i].path_len - 7 && rest[slash] != '/') {
      slash += 1;
    }
    enable = span_eq((const char *)files[i].bytes, files[i].len, "enable", 6);
    rc = gdefcore_changeset_stage_module(cs, rest, slash, enable);
    if (rc != GDEFCORE_OK) {
      gdefcore_changeset_destroy(cs);
      return rc;
    }
  }
  for (i = 0; i < count; i++) {
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * id;
    size_t id_len;
    const GDEFCORE_Patch * type_file;
    char * type_name = NULL;
    size_t type_len = 0;
    char * machine = NULL;
    size_t machine_len = 0;
    uint64_t row = 0;
    const GDEFCORE_Patch * base_file;
    if (files[i].path_len < 12 || memcmp(files[i].path, "entity/", 7) != 0) {
      continue;
    }
    if (memcmp(files[i].path + files[i].path_len - 3, "/op", 3) != 0) {
      continue;
    }
    id = files[i].path + 7;
    id_len = files[i].path_len - 10;
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_INVALID;
    }
    type_file = find_entity_tail(files, count, canon, "/type", 5);
    if (type_file == NULL) {
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
    rc = lookup_id(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &row, &type_name,
        &type_len, &machine, &machine_len);
    if (rc != GDEFCORE_OK) {
      gdefcore_changeset_destroy(cs);
      return rc;
    }
    if (!span_eq((const char *)type_file->bytes, type_file->len, type_name,
            type_len)) {
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
    base_file = find_entity_tail(files, count, canon, "/base", 5);
    if (span_eq((const char *)files[i].bytes, files[i].len, "clear", 5)) {
      int kind = 0;
      GDEFCORE_Op * op;
      GDEFCORE_Doc published;
      uint64_t seq = 0;
      rc = load_type(catalog, type_name, type_len, &kind, NULL, NULL, NULL, NULL,
          NULL);
      if (rc != GDEFCORE_OK) {
        gcu_allocator_free(catalog->alloc, type_name);
        gcu_allocator_free(catalog->alloc, machine);
        gdefcore_changeset_destroy(cs);
        return rc;
      }
      memset(&published, 0, sizeof published);
      rc = read_proj_doc(catalog, "p:", type_name, type_len, row, &published,
          &seq);
      if (rc == GDEFCORE_ERR_INVALID) {
        rc = GDEFCORE_OK;
      }
      if (rc != GDEFCORE_OK) {
        gcu_allocator_free(catalog->alloc, type_name);
        gcu_allocator_free(catalog->alloc, machine);
        gdefcore_changeset_destroy(cs);
        return rc;
      }
      rc = add_op(cs, &op);
      if (rc != GDEFCORE_OK) {
        doc_free(catalog->alloc, &published);
        gcu_allocator_free(catalog->alloc, type_name);
        gcu_allocator_free(catalog->alloc, machine);
        gdefcore_changeset_destroy(cs);
        return rc;
      }
      op->kind = GDEFCORE_OP_CLEAR;
      op->have_row = 1;
      op->row = row;
      op->type_kind = kind;
      op->base = published;
      if (text_set(catalog->alloc, &op->id, canon, GDEFCORE_PUBLIC_ID_LEN) !=
              GDEFCORE_OK ||
          text_set(catalog->alloc, &op->type_name, type_name, type_len) !=
              GDEFCORE_OK ||
          (machine != NULL &&
              text_set(catalog->alloc, &op->machine, machine, machine_len) !=
                  GDEFCORE_OK)) {
        gcu_allocator_free(catalog->alloc, type_name);
        gcu_allocator_free(catalog->alloc, machine);
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_OOM;
      }
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      if (base_file == NULL ||
          !u64_get((const char *)base_file->bytes, base_file->len,
              &op->base_seq)) {
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_CORRUPT;
      }
    } else if (span_eq((const char *)files[i].bytes, files[i].len, "save", 4) ||
        span_eq((const char *)files[i].bytes, files[i].len, "draft", 5) ||
        span_eq((const char *)files[i].bytes, files[i].len, "publish", 7)) {
      GDEFCORE_Op * op;
      int drafted = span_eq((const char *)files[i].bytes, files[i].len, "draft",
          5);
      int publishing =
          span_eq((const char *)files[i].bytes, files[i].len, "publish", 7);
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      rc = stage_parsed_saves(cs, files, count, canon, &cap);
      if (rc != GDEFCORE_OK) {
        gdefcore_changeset_destroy(cs);
        return rc;
      }
      op = find_op_id(cs, canon, GDEFCORE_PUBLIC_ID_LEN);
      if (op == NULL || base_file == NULL ||
          !u64_get((const char *)base_file->bytes, base_file->len,
              &op->base_seq)) {
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_CORRUPT;
      }
      if (drafted) {
        op->kind = GDEFCORE_OP_DRAFT;
      } else if (publishing) {
        op->kind = GDEFCORE_OP_PUBLISH;
      }
    } else {
      gcu_allocator_free(catalog->alloc, type_name);
      gcu_allocator_free(catalog->alloc, machine);
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
  }
  *out_changeset = cs;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_ids(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_name_len, char *** out_ids,
    size_t * out_count) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  char * copy = NULL;
  char ** ids = NULL;
  size_t count = 0;
  size_t filled = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || type_name == NULL || type_name_len == 0 ||
      out_ids == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_ids = NULL;
  *out_count = 0;
  rc = proj_get(catalog, kIdsType, sizeof kIdsType - 1, type_name,
      type_name_len, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "ids", 3, &val, &vlen) || vlen == 0) {
    gdefstor_projection_free(proj);
    return GDEFCORE_OK;
  }
  copy = (char *)mem(catalog->alloc, vlen + 1);
  if (copy == NULL) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(copy, val, vlen);
  copy[vlen] = '\0';
  gdefstor_projection_free(proj);
  count = 1;
  for (i = 0; i < vlen; i++) {
    if (copy[i] == '\n') {
      count += 1;
    }
  }
  ids = (char **)mem0(catalog->alloc, count * sizeof *ids);
  if (ids == NULL) {
    gcu_allocator_free(catalog->alloc, copy);
    return GDEFCORE_ERR_OOM;
  }
  {
    size_t start = 0;
    for (i = 0; i <= vlen; i++) {
      if (i == vlen || copy[i] == '\n') {
        size_t n = i - start;
        if (n > 0) {
          ids[filled] = dup_span(catalog->alloc, copy + start, n);
          if (ids[filled] == NULL) {
            gdefcore_ids_free(catalog, ids, filled);
            gcu_allocator_free(catalog->alloc, copy);
            return GDEFCORE_ERR_OOM;
          }
          filled += 1;
        }
        start = i + 1;
      }
    }
  }
  gcu_allocator_free(catalog->alloc, copy);
  *out_ids = ids;
  *out_count = filled;
  return GDEFCORE_OK;
}

void gdefcore_ids_free(GDEFCORE_Catalog * catalog, char ** ids, size_t count) {
  size_t i;
  if (catalog == NULL || ids == NULL) {
    return;
  }
  for (i = 0; i < count; i++) {
    gcu_allocator_free(catalog->alloc, ids[i]);
  }
  gcu_allocator_free(catalog->alloc, ids);
}

GDEFCORE_Result gdefcore_entity_type(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_type, size_t * out_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  char * type_name = NULL;
  size_t type_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_type == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = lookup_id(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &row, &type_name,
      &type_len, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_type = type_name;
  if (out_len != NULL) {
    *out_len = type_len;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_actor(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_actor, size_t * out_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char type_buf[160];
  char row_text[32];
  size_t rn = 0;
  uint64_t row = 0;
  char * type_name = NULL;
  size_t type_len = 0;
  int kn;
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t vlen = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_actor == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_actor = NULL;
  if (out_len != NULL) {
    *out_len = 0;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = lookup_id(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &row, &type_name,
      &type_len, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!u64_put(row, row_text, sizeof row_text, &rn)) {
    gcu_allocator_free(catalog->alloc, type_name);
    return GDEFCORE_ERR_LIMIT;
  }
  kn = snprintf(type_buf, sizeof type_buf, "p:%.*s", (int)type_len, type_name);
  gcu_allocator_free(catalog->alloc, type_name);
  if (kn <= 0 || (size_t)kn >= sizeof type_buf) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = proj_get(catalog, type_buf, (size_t)kn, row_text, rn, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (col_find(proj, "actor", 5, &val, &vlen) && vlen > 0) {
    *out_actor = dup_span(catalog->alloc, (const char *)val, vlen);
    if (*out_actor == NULL) {
      gdefstor_projection_free(proj);
      return GDEFCORE_ERR_OOM;
    }
    if (out_len != NULL) {
      *out_len = vlen;
    }
  }
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_text_dup(GDEFCORE_Catalog * catalog, const char * text,
    size_t len, char ** out) {
  char * copy;
  if (catalog == NULL || out == NULL || (text == NULL && len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  copy = dup_span(catalog->alloc, text == NULL ? "" : text, len);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  *out = copy;
  return GDEFCORE_OK;
}

GDEFCORE_Catalog * gdefcore_changeset_catalog(
    const GDEFCORE_Changeset * changeset) {
  return changeset == NULL ? NULL : changeset->catalog;
}

GDEFCORE_Result gdefcore_changeset_add_confirm_line(
    GDEFCORE_Changeset * changeset, const char * line, size_t len) {
  GDEFCORE_Text * next;
  size_t i;
  if (changeset == NULL || changeset->applied || line == NULL || len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < len; i++) {
    if (line[i] == '\n' || line[i] == '\r') {
      return GDEFCORE_ERR_INVALID;
    }
  }
  next = (GDEFCORE_Text *)gcu_allocator_realloc(changeset->catalog->alloc,
      changeset->lines, (changeset->nlines + 1) * sizeof *next);
  if (next == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  changeset->lines = next;
  memset(&next[changeset->nlines], 0, sizeof next[changeset->nlines]);
  if (text_set(changeset->catalog->alloc, &next[changeset->nlines], line,
          len) != GDEFCORE_OK) {
    return GDEFCORE_ERR_OOM;
  }
  changeset->nlines += 1;
  return GDEFCORE_OK;
}
