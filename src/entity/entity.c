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
 * Entities, revisions and changesets. A changeset is staged in memory and
 * applied as one write of the storage port: every entity save, draft, state
 * change and revert it holds, the type declarations and module records it
 * changes, and the config epoch's next value commit together or not at all
 * (store.c says what each is on the port).
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>
#include <ghoti.io/defiant-core/subject.h>
#include <ghoti.io/defiant-core/template.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/query.h>
#include <ghoti.io/regex/compile.h>
#include <ghoti.io/security/random.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "entity_internal.h"

#define span_eq gdefcore_ent_span_eq
#define dup_span gdefcore_ent_dup
#define text_clear gdefcore_ent_text_clear
#define text_set gdefcore_ent_text_set
#define map_stor gdefcore_ent_map
#define doc_free gdefcore_ent_doc_free
#define doc_clone gdefcore_ent_doc_clone
#define decls_free gdefcore_ent_decls_free
#define decls_copy gdefcore_ent_decls_copy

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
    /* A hyphen is allowed in the local part, after the dot and not first or
     * last: `core.template-kind`. The module part keeps to letters, digits
     * and underscore. */
    if (c == '-' && dot != n && i > dot + 1 && i + 1 < n) {
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
  /* Values set by the flat API are matched by position (story S6d keeps
   * that for flat callers); only a tree names items by id. Whose a personal
   * value is, is its declaration's to say (story S7), not the read's. */
  gdefcore_ent_vals_clear(alloc, slot);
  slot->vals = vals;
  slot->nvals = count;
  return GDEFCORE_OK;
}

/* Whether @p path is a field directly inside the group at @p group ("" the
 * root group). */
static int directly_in(const GDEFCORE_Text * path, const char * group,
    size_t group_len, const char ** leaf, size_t * leaf_len) {
  const char * rest = path->p;
  size_t rn = path->n;
  if (group_len > 0) {
    if (rn <= group_len + 1 || memcmp(rest, group, group_len) != 0 ||
        rest[group_len] != '.') {
      return 0;
    }
    rest += group_len + 1;
    rn -= group_len + 1;
  }
  if (rn == 0 || memchr(rest, '.', rn) != NULL) {
    return 0;
  }
  *leaf = rest;
  *leaf_len = rn;
  return 1;
}

/* The required groups of the root, and the required fields and items of
 * every group item, are there (story S6d). */
static int groups_have_required(const GDEFCORE_Lang * l,
    const GDEFCORE_Decl * decls, size_t ndecls) {
  const GDEFCORE_Tree * g = l->groups;
  size_t n = gdefcore_tree_item_count(g);
  size_t d;
  size_t i;
  for (d = 0; d < ndecls; d++) {
    const char * leaf;
    size_t ln;
    if (decls[d].required && decls[d].type == GDEFSTOR_FIELD_GROUP &&
        directly_in(&decls[d].name, NULL, 0, &leaf, &ln) &&
        gdefcore_tree_child_count(g, 0, leaf, ln) == 0) {
      return 0;
    }
  }
  for (i = 1; i < n; i++) {
    GDEFCORE_TreeItem it;
    const GDEFCORE_Decl * under;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(g, i, &it) != GDEFCORE_OK) {
      return 0;
    }
    under = gdefcore_ent_decl_at(decls, ndecls, it.path, it.path_len);
    if (under == NULL || under->type != GDEFSTOR_FIELD_GROUP) {
      continue; /* an item of a multiple field: its value is required by the port */
    }
    for (d = 0; d < ndecls; d++) {
      const char * leaf;
      size_t ln;
      if (!decls[d].required ||
          !directly_in(&decls[d].name, it.path, it.path_len, &leaf, &ln)) {
        continue;
      }
      if (decls[d].type == GDEFSTOR_FIELD_GROUP || decls[d].many) {
        if (gdefcore_tree_child_count(g, i, leaf, ln) == 0) {
          return 0;
        }
      } else {
        const char * text = NULL;
        size_t len = 0;
        if (gdefcore_tree_get(g, i, leaf, ln, &text, &len) != GDEFCORE_OK ||
            text == NULL) {
          return 0;
        }
      }
    }
  }
  return 1;
}

static int doc_has_required(const GDEFCORE_Doc * doc, const GDEFCORE_Decl * decls,
    size_t ndecls) {
  size_t i;
  size_t j;
  size_t d;
  if (doc->nlangs == 0) {
    for (d = 0; d < ndecls; d++) {
      if (decls[d].required &&
          memchr(decls[d].name.p, '.', decls[d].name.n) == NULL) {
        return 0;
      }
    }
    return 1;
  }
  for (i = 0; i < doc->nlangs; i++) {
    for (d = 0; d < ndecls; d++) {
      int found = 0;
      if (!decls[d].required || !gdefcore_ent_decl_flat(&decls[d])) {
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
    if (!groups_have_required(&doc->langs[i], decls, ndecls)) {
      return 0;
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

/* A logical type's word in a patch's field line (text is the default and is
 * not written). */
static const char * const kTypeWords[] = {NULL, "text", "integer", "decimal",
    "float", "boolean", "date", "datetime", "reference"};

static const char * type_word(int type) {
  return type > GDEFSTOR_FIELD_TEXT && type <= GDEFSTOR_FIELD_REFERENCE
             ? kTypeWords[type]
             : NULL;
}

/* Strip a trailing ` <word>` from @p body: 1 when it was there. */
static int strip_word(const uint8_t * body, size_t * len, const char * word) {
  size_t n = strlen(word);
  if (*len > n && body[*len - n - 1] == ' ' &&
      memcmp(body + *len - n, word, n) == 0) {
    *len -= n + 1;
    return 1;
  }
  return 0;
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

/* A stored type: the kind, the fields, its public id and its version. A
 * built-in name has no record: it is configuration with no fields. */
static GDEFCORE_Result load_type(GDEFCORE_Catalog * cat, const char * name,
    size_t name_len, int * out_kind, GDEFCORE_Decl ** out_decls,
    size_t * out_n, char ** out_id, size_t * out_id_len,
    uint64_t * out_version) {
  GDEFCORE_EntType t;
  GDEFCORE_Result rc;
  if (out_decls != NULL) {
    *out_decls = NULL;
    *out_n = 0;
  }
  if (out_id != NULL) {
    *out_id = NULL;
    *out_id_len = 0;
  }
  if (out_version != NULL) {
    *out_version = 0;
  }
  if (builtin_name(name, name_len)) {
    if (out_kind != NULL) {
      *out_kind = GDEFCORE_TYPE_CONFIG;
    }
    return GDEFCORE_OK;
  }
  if (!machine_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_type_load(cat, name, name_len, &t);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (out_kind != NULL) {
    *out_kind = t.kind;
  }
  if (out_version != NULL) {
    *out_version = t.version;
  }
  if (out_id != NULL) {
    *out_id = dup_span(cat->alloc, t.id, GDEFCORE_PUBLIC_ID_LEN);
    if (*out_id == NULL) {
      gdefcore_ent_type_free(cat->alloc, &t);
      return GDEFCORE_ERR_OOM;
    }
    *out_id_len = GDEFCORE_PUBLIC_ID_LEN;
  }
  if (out_decls != NULL) {
    *out_decls = t.decls;
    *out_n = t.ndecls;
    t.decls = NULL;
    t.ndecls = 0;
  }
  gdefcore_ent_type_free(cat->alloc, &t);
  return GDEFCORE_OK;
}

/* Whether a stored type's entities are subjects (story S7). A built-in name
 * has no record and keeps none. */
static GDEFCORE_Result type_subjects_of(GDEFCORE_Catalog * cat,
    const char * name, size_t name_len, int * out) {
  GDEFCORE_EntType t;
  GDEFCORE_Result rc;
  *out = 0;
  if (builtin_name(name, name_len)) {
    return GDEFCORE_OK;
  }
  if (!machine_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_type_load(cat, name, name_len, &t);
  if (rc == GDEFCORE_OK) {
    *out = t.subjects;
    gdefcore_ent_type_free(cat->alloc, &t);
  }
  return rc;
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

static int field_type_of(const GDEFCORE_Field * field) {
  if (!field_covers(field, offsetof(GDEFCORE_Field, type) + sizeof(int)) ||
      field->type == 0) {
    return GDEFSTOR_FIELD_TEXT;
  }
  return field->type;
}

static int field_scale_of(const GDEFCORE_Field * field) {
  if (!field_covers(field, offsetof(GDEFCORE_Field, scale) + sizeof(int))) {
    return 0;
  }
  return field->scale;
}

static int field_indexed_of(const GDEFCORE_Field * field) {
  if (!field_covers(field, offsetof(GDEFCORE_Field, indexed) + sizeof(int))) {
    return 0;
  }
  return field->indexed ? 1 : 0;
}

static int field_has_tree(const GDEFCORE_Field * field) {
  return field_covers(field,
      offsetof(GDEFCORE_Field, subject_len) + sizeof(size_t));
}

static const GDEFCORE_Field * field_children(const GDEFCORE_Field * field,
    size_t * out_count) {
  if (!field_has_tree(field)) {
    *out_count = 0;
    return NULL;
  }
  *out_count = field->child_count;
  return field->children;
}

static size_t field_subject(const GDEFCORE_Field * field, const char ** out) {
  if (!field_has_tree(field) || field->subject_len == 0) {
    *out = NULL;
    return 0;
  }
  *out = field->subject;
  return field->subject_len;
}

/* One group's fields (the root group's at @p depth 0), and every group below
 * them (story S6d). @p total counts the fields at every depth. @p subjects:
 * the type's entities are subjects (::GDEFCORE_TYPE_SUBJECTS). */
static GDEFCORE_Result check_level(const GDEFCORE_Field * fields, size_t count,
    const GDEFCORE_Limits * limits, int depth, size_t * total, int subjects) {
  size_t i;
  size_t j;
  if (fields == NULL && count != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < count; i++) {
    int type;
    int scale;
    const GDEFCORE_Field * kids;
    size_t nkids = 0;
    const char * subject = NULL;
    size_t subject_len;
    if (fields[i].size < offsetof(GDEFCORE_Field, many) + sizeof(int) ||
        !field_name_ok(fields[i].name, fields[i].name_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    *total += 1;
    if (*total > limits->max_fields) {
      return GDEFCORE_ERR_LIMIT;
    }
    type = field_type_of(&fields[i]);
    scale = field_scale_of(&fields[i]);
    kids = field_children(&fields[i], &nkids);
    subject_len = field_subject(&fields[i], &subject);
    /* A logical type of the port's. A scale is a decimal's. A group holds
     * fields, and needs the members that say which. */
    if (type < GDEFSTOR_FIELD_TEXT || type > GDEFSTOR_FIELD_GROUP ||
        (type == GDEFSTOR_FIELD_GROUP && !field_has_tree(&fields[i])) ||
        (type == GDEFSTOR_FIELD_DECIMAL
                ? (scale < 0 || scale > GDEFSTOR_MODEL_MAX_SCALE)
                : scale != 0)) {
      return GDEFCORE_ERR_INVALID;
    }
    if (type == GDEFSTOR_FIELD_GROUP) {
      GDEFCORE_Result gr;
      /* A group has no value: nothing personal, indexed or constrained. */
      if (kids == NULL || nkids == 0 || field_personal(&fields[i]) ||
          field_indexed_of(&fields[i]) || subject_len != 0 ||
          (field_covers(&fields[i],
               offsetof(GDEFCORE_Field, pattern_len) + sizeof(size_t)) &&
              (fields[i].min_len != 0 || fields[i].max_len != 0 ||
                  fields[i].has_range || fields[i].pattern_len != 0))) {
        return GDEFCORE_ERR_INVALID;
      }
      if (depth + 1 > GDEFSTOR_MODEL_MAX_DEPTH) {
        return GDEFCORE_ERR_LIMIT;
      }
      gr = check_level(kids, nkids, limits, depth + 1, total, subjects);
      if (gr != GDEFCORE_OK) {
        return gr;
      }
    } else if (kids != NULL || nkids != 0) {
      return GDEFCORE_ERR_INVALID;
    }
    if (subject_len != 0) {
      /* The subject source: a single, non-personal reference among its
       * siblings (the port's rule too). */
      int found = 0;
      if (!field_personal(&fields[i]) || subject == NULL ||
          !field_name_ok(subject, subject_len)) {
        return GDEFCORE_ERR_INVALID;
      }
      for (j = 0; j < count; j++) {
        if (j != i && span_eq(fields[j].name, fields[j].name_len, subject,
                          subject_len)) {
          if (field_type_of(&fields[j]) != GDEFSTOR_FIELD_REFERENCE ||
              fields[j].many || field_personal(&fields[j])) {
            return GDEFCORE_ERR_INVALID;
          }
          found = 1;
        }
      }
      if (!found) {
        return GDEFCORE_ERR_INVALID;
      }
    } else if (depth > 0 && field_personal(&fields[i])) {
      /* A personal field inside a group names its subject source (story
       * S6d): a group's item is not the entity, and nothing else says whose
       * the value is. */
      return GDEFCORE_ERR_INVALID;
    } else if (field_personal(&fields[i]) && !subjects) {
      /* A personal field of the root that names no reference takes the
       * entity's own subject (AD-19, story S7), which only a type whose
       * entities are subjects has: with neither, whose the value is would
       * be nobody's to say. */
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

static GDEFCORE_Result check_fields(const GDEFCORE_Field * fields,
    size_t count, const GDEFCORE_Limits * limits, int subjects) {
  size_t total = 0;
  if (count > limits->max_fields || (fields == NULL && count != 0)) {
    return count > limits->max_fields ? GDEFCORE_ERR_LIMIT
                                      : GDEFCORE_ERR_INVALID;
  }
  return check_level(fields, count, limits, 0, &total, subjects);
}

/* The kind a definition names, without ::GDEFCORE_TYPE_SUBJECTS; 0 when it
 * names none of the kinds. */
static int kind_of(int kind) {
  int base = kind & ~GDEFCORE_TYPE_SUBJECTS;
  return base == GDEFCORE_TYPE_CONTENT || base == GDEFCORE_TYPE_CONFIG ? base
                                                                        : 0;
}

/* Fields at every depth: what fields_to_decls() makes. */
static size_t fields_total(const GDEFCORE_Field * fields, size_t count) {
  size_t n = 0;
  size_t i;
  for (i = 0; i < count; i++) {
    const GDEFCORE_Field * kids;
    size_t nkids = 0;
    n += 1;
    kids = field_children(&fields[i], &nkids);
    if (field_type_of(&fields[i]) == GDEFSTOR_FIELD_GROUP && kids != NULL) {
      n += fields_total(kids, nkids);
    }
  }
  return n;
}

static GDEFCORE_Result fill_decls(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Field * fields, size_t count, const char * prefix,
    size_t prefix_len, GDEFCORE_Decl * decls, size_t * at) {
  size_t i;
  for (i = 0; i < count; i++) {
    GDEFCORE_Decl * d = &decls[*at];
    const char * subject = NULL;
    size_t subject_len = field_subject(&fields[i], &subject);
    size_t n = prefix_len + (prefix_len > 0 ? 1 : 0) + fields[i].name_len;
    char * path = (char *)mem(alloc, n + 1);
    GDEFCORE_Result cr;
    if (path == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    if (prefix_len > 0) {
      memcpy(path, prefix, prefix_len);
      path[prefix_len] = '.';
    }
    memcpy(path + n - fields[i].name_len, fields[i].name, fields[i].name_len);
    path[n] = '\0';
    d->name.p = path;
    d->name.n = n;
    *at += 1;
    d->required = fields[i].required ? 1 : 0;
    d->many = fields[i].many ? 1 : 0;
    d->personal = field_personal(&fields[i]);
    d->type = field_type_of(&fields[i]);
    d->scale = field_scale_of(&fields[i]);
    d->indexed = field_indexed_of(&fields[i]);
    cr = copy_constraints(alloc, &fields[i], d);
    if (cr == GDEFCORE_OK && subject_len > 0) {
      cr = text_set(alloc, &d->subject, subject, subject_len);
    }
    if (cr != GDEFCORE_OK) {
      return cr;
    }
    if (d->type == GDEFSTOR_FIELD_GROUP) {
      size_t nkids = 0;
      const GDEFCORE_Field * kids = field_children(&fields[i], &nkids);
      cr = fill_decls(alloc, kids, nkids, path, n, decls, at);
      if (cr != GDEFCORE_OK) {
        return cr;
      }
    }
  }
  return GDEFCORE_OK;
}

/* A type's fields as decls: every field at every depth, in pre-order, each
 * named by its path (story S6d). */
static GDEFCORE_Result fields_to_decls(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Field * fields, size_t count, GDEFCORE_Decl ** out,
    size_t * out_n) {
  GDEFCORE_Decl * decls;
  size_t total = fields_total(fields, count);
  size_t at = 0;
  GDEFCORE_Result rc;
  *out = NULL;
  *out_n = 0;
  if (total == 0) {
    return GDEFCORE_OK;
  }
  decls = (GDEFCORE_Decl *)mem0(alloc, total * sizeof *decls);
  if (decls == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  rc = fill_decls(alloc, fields, count, NULL, 0, decls, &at);
  if (rc != GDEFCORE_OK || at != total) {
    decls_free(alloc, decls, total);
    return rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_INTERNAL;
  }
  *out = decls;
  *out_n = total;
  return GDEFCORE_OK;
}

int gdefcore_ent_decl_flat(const GDEFCORE_Decl * d) {
  return d->type != GDEFSTOR_FIELD_GROUP &&
         memchr(d->name.p, '.', d->name.n) == NULL;
}

const GDEFCORE_Decl * gdefcore_ent_decl_at(const GDEFCORE_Decl * decls,
    size_t n, const char * path, size_t path_len) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (span_eq(decls[i].name.p, decls[i].name.n, path, path_len)) {
      return &decls[i];
    }
  }
  return NULL;
}

/* The @p index th field the flat calls see: a field of the root group that
 * holds values (story S6d). NULL past the end. */
static const GDEFCORE_Decl * flat_decl(const GDEFCORE_Decl * decls, size_t n,
    size_t index) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (gdefcore_ent_decl_flat(&decls[i])) {
      if (index == 0) {
        return &decls[i];
      }
      index -= 1;
    }
  }
  return NULL;
}

static size_t flat_count(const GDEFCORE_Decl * decls, size_t n) {
  size_t i;
  size_t c = 0;
  for (i = 0; i < n; i++) {
    c += gdefcore_ent_decl_flat(&decls[i]) ? 1u : 0u;
  }
  return c;
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

static GDEFCORE_Result read_epoch(GDEFCORE_Catalog * cat, uint64_t * out) {
  return map_stor(gdefstor_counter_peek(cat->store, (const char *)cat->tenant,
      cat->tenant_len, GDEFCORE_ENT_EPOCH, sizeof GDEFCORE_ENT_EPOCH - 1, out));
}

GDEFCORE_Result gdefcore_epoch(GDEFCORE_Catalog * catalog, uint64_t * out_epoch) {
  if (catalog == NULL || out_epoch == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return read_epoch(catalog, out_epoch);
}

/* The port's clock for a write: the request's, else the wall's. */
static int64_t now_ms(const GDEFCORE_Changeset * cs) {
  if (cs != NULL && cs->job_key.p != NULL) {
    return cs->job_now; /* a scheduled publish runs at its runner's now */
  }
  if (cs != NULL && cs->request != NULL) {
    return gdefcore_request_time(cs->request) * 1000;
  }
  return (int64_t)time(NULL) * 1000;
}

/* A type written, new or again: its record and its port declaration. A new
 * type gets a public id; every definition moves its version. */
static GDEFCORE_Result write_type(GDEFCORE_Catalog * cat, GDEFSTOR_Write * write,
    const char * name, size_t name_len, int kind, int subjects,
    const GDEFCORE_Decl * decls, size_t ndecls, const char * existing_id,
    uint64_t existing_version) {
  GDEFCORE_EntType t;
  GDEFCORE_Result rc;
  memset(&t, 0, sizeof t);
  t.kind = kind;
  t.subjects = subjects ? 1 : 0;
  if (existing_id != NULL) {
    memcpy(t.id, existing_id, GDEFCORE_PUBLIC_ID_LEN);
    t.id[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  } else {
    rc = gdefcore_id_generate(t.id);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  if (existing_version == UINT64_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  t.version = existing_version + 1;
  t.decls = (GDEFCORE_Decl *)decls;
  t.ndecls = ndecls;
  return gdefcore_ent_type_write(cat, write, name, name_len, &t);
}

GDEFCORE_Result gdefcore_type_define(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, int kind, const GDEFCORE_Field * fields,
    size_t field_count) {
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Decl * decls = NULL;
  size_t ndecls = 0;
  GDEFCORE_Result rc;
  int existing = 0;
  if (catalog == NULL || !machine_ok(name, name_len) || kind_of(kind) == 0 ||
      builtin_name(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = check_fields(fields, field_count, &catalog->limits,
      (kind & GDEFCORE_TYPE_SUBJECTS) != 0);
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
  rc = fields_to_decls(catalog->alloc, fields, field_count, &decls, &ndecls);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = map_stor(gdefstor_write_begin(catalog->store, (const char *)catalog->tenant,
      catalog->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    decls_free(catalog->alloc, decls, ndecls);
    return rc;
  }
  rc = write_type(catalog, write, name, name_len, kind_of(kind),
      (kind & GDEFCORE_TYPE_SUBJECTS) != 0, decls, ndecls, NULL, 0);
  decls_free(catalog->alloc, decls, ndecls);
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return map_stor(gdefstor_write_commit(write));
}

GDEFCORE_Result gdefcore_type_field_type(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, int * out_type,
    int * out_scale) {
  GDEFCORE_Decl * decls = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_type == NULL || out_scale == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, name, name_len, NULL, &decls, &n, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  {
    const GDEFCORE_Decl * d = flat_decl(decls, n, index);
    if (d == NULL) {
      decls_free(catalog->alloc, decls, n);
      return GDEFCORE_ERR_INVALID;
    }
    *out_type = d->type;
    *out_scale = d->scale;
  }
  decls_free(catalog->alloc, decls, n);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_create(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1], uint64_t * out_row) {
  int kind = 0;
  int subjects = 0;
  GDEFSTOR_Write * write = NULL;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (catalog == NULL || out_id == NULL || builtin_name(type_name, type_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, type_name, type_len, &kind, NULL, NULL, NULL, NULL,
      NULL);
  if (rc == GDEFCORE_OK) {
    rc = type_subjects_of(catalog, type_name, type_len, &subjects);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (subjects && catalog->subjects == NULL) {
    /* The entity's own subject is made with it, and needs the keys. */
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_id_generate(id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (subjects) {
    /* Story S7: a type whose entities are subjects gets one per entity, its
     * key made in the key store now (a subject's creation is one of the
     * writes the key store takes, AD-19), kept with the entity below. */
    rc = gdefcore_subject_create(catalog->subjects, sid);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  rc = map_stor(gdefstor_write_begin(catalog->store,
      (const char *)catalog->tenant, catalog->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* The id is reserved by a draft with no content: the entity, with its
   * creator, is made at its first save (story S6b). */
  rc = map_stor(gdefstor_draft_put(write, type_name, type_len, id,
      GDEFCORE_PUBLIC_ID_LEN, 0, NULL, 0));
  if (rc == GDEFCORE_OK && subjects) {
    rc = map_stor(gdefstor_record_put(write, GDEFCORE_ENT_SUBJECT_NS,
        sizeof GDEFCORE_ENT_SUBJECT_NS - 1, id, GDEFCORE_PUBLIC_ID_LEN,
        (const uint8_t *)sid, GDEFCORE_PUBLIC_ID_LEN));
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
    *out_row = 0;
  }
  return GDEFCORE_OK;
}

void gdefcore_catalog_bind_subjects(GDEFCORE_Catalog * catalog,
    struct GDEFCORE_Subjects * subjects) {
  if (catalog != NULL) {
    catalog->subjects = subjects;
  }
}

struct GDEFCORE_Subjects * gdefcore_catalog_subjects(
    const GDEFCORE_Catalog * catalog) {
  return catalog == NULL ? NULL : catalog->subjects;
}

GDEFCORE_Result gdefcore_entity_subject(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len,
    char out_subject[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  int found = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_subject == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_ent_own_subject(catalog, canon, sid, &found);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!found) {
    return GDEFCORE_ERR_INVALID;
  }
  memcpy(out_subject, sid, GDEFCORE_PUBLIC_ID_LEN + 1);
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

GDEFCORE_Result gdefcore_type_kind(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, int * out_kind) {
  if (catalog == NULL || out_kind == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return load_type(catalog, name, name_len, out_kind, NULL, NULL, NULL, NULL,
      NULL);
}

GDEFCORE_Result gdefcore_type_subjects(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, int * out_subjects) {
  int subjects = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_subjects == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, name, name_len, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc == GDEFCORE_OK) {
    rc = type_subjects_of(catalog, name, name_len, &subjects);
  }
  if (rc == GDEFCORE_OK) {
    *out_subjects = subjects;
  }
  return rc;
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
  *out_count = flat_count(decls, n);
  decls_free(catalog->alloc, decls, n);
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
  {
    const GDEFCORE_Decl * d = flat_decl(decls, n, index);
    if (d == NULL) {
      decls_free(catalog->alloc, decls, n);
      return GDEFCORE_ERR_INVALID;
    }
    *out_name = dup_span(catalog->alloc, d->name.p, d->name.n);
    if (*out_name == NULL) {
      decls_free(catalog->alloc, decls, n);
      return GDEFCORE_ERR_OOM;
    }
    *out_name_len = d->name.n;
    *out_required = d->required;
    *out_many = d->many;
  }
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
  if (flat_decl(decls, n, index) == NULL) {
    decls_free(catalog->alloc, decls, n);
    return GDEFCORE_ERR_INVALID;
  }
  *out_personal = flat_decl(decls, n, index)->personal ? 1 : 0;
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
  if (flat_decl(decls, n, index) == NULL) {
    decls_free(catalog->alloc, decls, n);
    return GDEFCORE_ERR_INVALID;
  }
  {
    const GDEFCORE_Decl * d = flat_decl(decls, n, index);
    char * pattern = NULL;
    size_t pattern_len = 0;
    if (d->pattern.n > 0) {
      pattern = dup_span(catalog->alloc, d->pattern.p, d->pattern.n);
      if (pattern == NULL) {
        decls_free(catalog->alloc, decls, n);
        return GDEFCORE_ERR_OOM;
      }
      pattern_len = d->pattern.n;
    }
    *out_min_len = d->min_len;
    *out_max_len = d->max_len;
    *out_has_range = d->has_range ? 1 : 0;
    *out_range_min = d->range_min;
    *out_range_max = d->range_max;
    *out_pattern = pattern;
    *out_pattern_len = pattern_len;
  }
  decls_free(catalog->alloc, decls, n);
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
  text_clear(cs->catalog->alloc, &cs->refusal);
  text_clear(cs->catalog->alloc, &cs->actor);
  text_clear(cs->catalog->alloc, &cs->why);
}

static void notes_free(GDEFCORE_Changeset * cs) {
  size_t i;
  for (i = 0; i < cs->nnotes; i++) {
    text_clear(cs->catalog->alloc, &cs->notes[i].text);
  }
  gcu_allocator_free(cs->catalog->alloc, cs->notes);
  cs->notes = NULL;
  cs->nnotes = 0;
}

void gdefcore_changeset_destroy(GDEFCORE_Changeset * changeset) {
  if (changeset == NULL) {
    return;
  }
  gdefcore_access_clear_staged(changeset);
  changeset_free_ops(changeset);
  notes_free(changeset);
  text_clear(changeset->catalog->alloc, &changeset->job_key);
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
  size_t ndecls = 0;
  GDEFCORE_Result rc;
  char * existing_id = NULL;
  size_t existing_id_len = 0;
  uint64_t version = 0;
  int have = 0;
  if (changeset == NULL || changeset->applied ||
      !machine_ok(name, name_len) || builtin_name(name, name_len) ||
      kind_of(kind) == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = check_fields(fields, field_count, &changeset->catalog->limits,
      (kind & GDEFCORE_TYPE_SUBJECTS) != 0);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (find_op_machine(changeset, name, name_len) != NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(changeset->catalog, name, name_len, NULL, NULL, NULL,
      &existing_id, &existing_id_len, &version);
  if (rc == GDEFCORE_OK) {
    int stored = 0;
    have = 1;
    /* Whether its entities are subjects is part of what a type is: each
     * one's subject was made with it, or was not (story S7). */
    rc = type_subjects_of(changeset->catalog, name, name_len, &stored);
    if (rc == GDEFCORE_OK &&
        stored != ((kind & GDEFCORE_TYPE_SUBJECTS) != 0)) {
      rc = GDEFCORE_ERR_INVALID;
    }
    if (rc != GDEFCORE_OK) {
      gcu_allocator_free(changeset->catalog->alloc, existing_id);
      return rc;
    }
  } else if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  rc = fields_to_decls(changeset->catalog->alloc, fields, field_count, &decls,
      &ndecls);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(changeset->catalog->alloc, existing_id);
    return rc;
  }
  rc = add_op(changeset, &op);
  if (rc != GDEFCORE_OK) {
    decls_free(changeset->catalog->alloc, decls, ndecls);
    gcu_allocator_free(changeset->catalog->alloc, existing_id);
    return rc;
  }
  op->kind = GDEFCORE_OP_DEFINE;
  op->type_kind = kind_of(kind);
  op->type_subjects = (kind & GDEFCORE_TYPE_SUBJECTS) != 0;
  op->decls = decls;
  op->ndecls = ndecls;
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
    /* A definition of a stored type is a change of it: staged against its
     * version, so a definition applied in between is a conflict. */
    op->have_row = 1;
    op->base_seq = version;
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

/* A field the flat calls take a value for: one of the root group that holds
 * values. A group, and a field inside one, is not (story S6d). */
static const GDEFCORE_Decl * decl_named(const GDEFCORE_Decl * decls, size_t n,
    const char * name, size_t name_len) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (span_eq(decls[i].name.p, decls[i].name.n, name, name_len)) {
      return gdefcore_ent_decl_flat(&decls[i]) ? &decls[i] : NULL;
    }
  }
  return NULL;
}

/* What gdefcore_subject_save and the subject form route store for a personal
 * field: "s1:" and the hex of nonce (12), ciphertext and tag (16). The entity
 * layer holds no key, so this is the whole of what it can check: a plaintext
 * is refused, and so is anything not shaped like a sealed value. The shape is
 * the subject subsystem's (encrypt_value); keep the two in step. */
static int sealed_ok(const char * text, size_t n) {
  size_t i;
  if (text == NULL || n < 3 + 2 * (12 + 16) || memcmp(text, "s1:", 3) != 0 ||
      ((n - 3) % 2) != 0) {
    return 0;
  }
  for (i = 3; i < n; i++) {
    char c = text[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  return 1;
}

/* A personal field takes only a sealed value, and only from a changeset that
 * was told to accept sealed values (AD-19). A field that is cleared (no
 * value) carries nothing and is let through. */
static int personal_value_ok(const GDEFCORE_Changeset * changeset,
    const GDEFCORE_Decl * decl, const GDEFCORE_Value * value) {
  size_t v;
  if (!decl->personal || value->count == 0) {
    return 1;
  }
  if (!changeset->accept_sealed) {
    return 0;
  }
  for (v = 0; v < value->count; v++) {
    if (!sealed_ok(value->texts[v], value->text_lens[v])) {
      return 0;
    }
  }
  return 1;
}

/* Every personal value in a document restored from a stored revision or a
 * draft must already be sealed. Used where no value passes through
 * stage_values: a revert and a publish. */
static int groups_personal_sealed(const GDEFCORE_Tree * g,
    const GDEFCORE_Decl * decls, size_t ndecls) {
  size_t n = gdefcore_tree_item_count(g);
  size_t i;
  for (i = 1; i < n; i++) {
    GDEFCORE_TreeItem it;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(g, i, &it) != GDEFCORE_OK) {
      return 0;
    }
    for (k = 0; k < it.value_count; k++) {
      const char * f = NULL;
      size_t fn = 0;
      const char * text = NULL;
      size_t len = 0;
      GDEFCORE_Text path;
      const GDEFCORE_Decl * d;
      if (gdefcore_tree_value(g, i, k, &f, &fn, &text, &len) != GDEFCORE_OK ||
          gdefcore_ent_tree_value_path(g, i, f, fn, &path) != GDEFCORE_OK) {
        return 0;
      }
      d = gdefcore_ent_decl_at(decls, ndecls, path.p, path.n);
      gcu_allocator_free(g->alloc, path.p);
      if (d != NULL && d->personal && !sealed_ok(text, len)) {
        return 0;
      }
    }
  }
  return 1;
}

static int doc_personal_sealed(const GDEFCORE_Doc * doc,
    const GDEFCORE_Decl * decls, size_t ndecls) {
  size_t li;
  size_t fi;
  size_t vi;
  for (li = 0; li < doc->nlangs; li++) {
    if (!groups_personal_sealed(doc->langs[li].groups, decls, ndecls)) {
      return 0;
    }
    for (fi = 0; fi < doc->langs[li].nfields; fi++) {
      const GDEFCORE_Vals * f = &doc->langs[li].fields[fi];
      const GDEFCORE_Decl * decl = decl_named(decls, ndecls, f->name.p, f->name.n);
      if (decl == NULL || !decl->personal) {
        continue;
      }
      for (vi = 0; vi < f->nvals; vi++) {
        if (!sealed_ok(f->vals[vi].p, f->vals[vi].n)) {
          return 0;
        }
      }
    }
  }
  return 1;
}

/* What an op on an entity is staged against: the entity as the store has it
 * now, its type and its current values. */
typedef struct Staging {
  GDEFCORE_EntLook look;
  int kind;
  GDEFCORE_Decl * decls;
  size_t ndecls;
  uint64_t version;
} Staging;

static void staging_free(GDEFCORE_Catalog * cat, Staging * s) {
  decls_free(cat->alloc, s->decls, s->ndecls);
  s->decls = NULL;
  s->ndecls = 0;
}

static GDEFCORE_Result staging_load(GDEFCORE_Catalog * cat, const char * canon,
    Staging * out) {
  GDEFCORE_Result rc;
  memset(out, 0, sizeof *out);
  rc = gdefcore_ent_lookup(cat, canon, &out->look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_type(cat, out->look.type, out->look.type_len, &out->kind,
      &out->decls, &out->ndecls, NULL, NULL, NULL);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_ent_version(cat, canon, &out->version);
  }
  if (rc != GDEFCORE_OK) {
    staging_free(cat, out);
  }
  return rc;
}

/* The entity's current values, or none for one with no revision or cleared. */
static GDEFCORE_Result current_doc(GDEFCORE_Catalog * cat, const char * canon,
    const GDEFCORE_EntLook * look, GDEFCORE_Doc * out) {
  memset(out, 0, sizeof *out);
  if (!look->exists || look->revision == 0 || look->deleted) {
    return GDEFCORE_OK;
  }
  return gdefcore_ent_read_doc(cat, canon, 0, 0, out);
}

/* Fill a new op on an entity from what it was staged against. */
static GDEFCORE_Result op_from_staging(GDEFCORE_Catalog * cat, GDEFCORE_Op * op,
    const char * canon, Staging * st) {
  op->have_row = 1;
  op->reserved = st->look.reserved;
  op->type_kind = st->kind;
  op->base_seq = st->look.revision;
  op->base_ver = st->version;
  op->have_ver = 1;
  op->draft_base = st->look.has_draft ? st->look.draft_base : st->look.revision;
  op->decls = st->decls;
  op->ndecls = st->ndecls;
  st->decls = NULL;
  st->ndecls = 0;
  if (text_set(cat->alloc, &op->id, canon, GDEFCORE_PUBLIC_ID_LEN) !=
          GDEFCORE_OK ||
      text_set(cat->alloc, &op->type_name, st->look.type, st->look.type_len) !=
          GDEFCORE_OK) {
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_OK;
}

/* One staged value in its canonical text: a personal value as the sealed
 * text it is, any other as its type spells it. */
static GDEFCORE_Result canonical_values(GDEFCORE_Catalog * cat,
    const GDEFCORE_Decl * decl, const GDEFCORE_Value * value,
    GDEFCORE_Text ** out) {
  GDEFCORE_Text * texts;
  size_t v;
  *out = NULL;
  texts = (GDEFCORE_Text *)mem0(cat->alloc,
      (value->count == 0 ? 1 : value->count) * sizeof *texts);
  if (texts == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (v = 0; v < value->count; v++) {
    GDEFCORE_Result rc = gdefcore_ent_value_check(cat->alloc, decl,
        value->texts[v], value->text_lens[v], &texts[v]);
    if (rc != GDEFCORE_OK) {
      size_t k;
      for (k = 0; k < v; k++) {
        text_clear(cat->alloc, &texts[k]);
      }
      gcu_allocator_free(cat->alloc, texts);
      return rc;
    }
  }
  *out = texts;
  return GDEFCORE_OK;
}

/*
 * What a save or a draft of an entity builds on: the doc the changeset
 * already stages for it (@p out_op is that op), or, for the entity's first op
 * in the changeset, the draft or what it is now. A draft builds on the draft
 * the entity has, else on what it is now. A save builds on the draft too when
 * the draft was made from the newest revision (it saves the working copy, as
 * a publish of it would), else on what the entity is now; either way the save
 * consumes the draft.
 */
static GDEFCORE_Result staged_base(GDEFCORE_Changeset * changeset,
    const char * canon, const Staging * st, int draft, GDEFCORE_Op ** out_op,
    GDEFCORE_Doc * tentative) {
  GDEFCORE_Catalog * cat = changeset->catalog;
  GDEFCORE_Op * op = find_op_id(changeset, canon, GDEFCORE_PUBLIC_ID_LEN);
  GDEFCORE_Result rc = GDEFCORE_OK;
  memset(tentative, 0, sizeof *tentative);
  *out_op = op;
  if (op != NULL && op->kind != GDEFCORE_OP_CLEAR) {
    rc = doc_clone(cat->alloc, &op->staged, tentative);
  } else if (op == NULL) {
    if (st->look.has_draft &&
        (draft || st->look.draft_base == st->look.revision)) {
      rc = gdefcore_ent_read_doc(cat, canon, 0, 1, tentative);
    } else {
      rc = current_doc(cat, canon, &st->look, tentative);
    }
  }
  return rc;
}

/* Stage @p tentative (taken, whatever the result) as what the op on the
 * entity writes, making the op when the changeset has none for it. */
static GDEFCORE_Result stage_finish(GDEFCORE_Changeset * changeset,
    const char * canon, Staging * st, GDEFCORE_Op * op,
    GDEFCORE_Doc * tentative, int draft) {
  GDEFCORE_Catalog * cat = changeset->catalog;
  GDEFCORE_Result rc = GDEFCORE_OK;
  int created = 0;
  if (!doc_has_required(tentative, st->decls, st->ndecls)) {
    doc_free(cat->alloc, tentative);
    staging_free(cat, st);
    return GDEFCORE_ERR_INVALID;
  }
  if (op == NULL) {
    rc = add_op(changeset, &op);
    if (rc == GDEFCORE_OK) {
      created = 1;
      rc = op_from_staging(cat, op, canon, st);
    }
    if (rc == GDEFCORE_OK) {
      rc = current_doc(cat, canon, &st->look, &op->base);
    }
    if (rc != GDEFCORE_OK) {
      if (created) {
        op_free(cat->alloc, op);
        changeset->nops -= 1;
      }
      doc_free(cat->alloc, tentative);
      staging_free(cat, st);
      return rc;
    }
  }
  staging_free(cat, st);
  doc_free(cat->alloc, &op->staged);
  op->staged = *tentative;
  memset(tentative, 0, sizeof *tentative);
  op->kind = draft ? GDEFCORE_OP_DRAFT : GDEFCORE_OP_SAVE;
  return GDEFCORE_OK;
}

static GDEFCORE_Result stage_values(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count, int draft) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * cat;
  GDEFCORE_Op * op;
  GDEFCORE_Doc tentative;
  Staging st;
  GDEFCORE_Result rc;
  size_t i;
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
  rc = staging_load(cat, canon, &st);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < value_count; i++) {
    const GDEFCORE_Decl * decl;
    size_t v;
    if (values[i].size < offsetof(GDEFCORE_Value, count) + sizeof(size_t) ||
        values[i].count > cat->limits.max_values ||
        (values[i].texts == NULL && values[i].count != 0) ||
        (values[i].text_lens == NULL && values[i].count != 0)) {
      staging_free(cat, &st);
      return GDEFCORE_ERR_INVALID;
    }
    decl = decl_named(st.decls, st.ndecls, values[i].field, values[i].field_len);
    if (decl == NULL || !personal_value_ok(changeset, decl, &values[i])) {
      staging_free(cat, &st);
      return GDEFCORE_ERR_INVALID;
    }
    /* A many field with no values clears that field. A single field
     * still needs one value. A required field stays required. */
    if (!decl->many && values[i].count != 1) {
      staging_free(cat, &st);
      return GDEFCORE_ERR_INVALID;
    }
    for (v = 0; v < values[i].count; v++) {
      if (values[i].texts[v] == NULL ||
          values[i].text_lens[v] > cat->limits.max_value_bytes) {
        staging_free(cat, &st);
        return values[i].text_lens[v] > cat->limits.max_value_bytes
                   ? GDEFCORE_ERR_LIMIT
                   : GDEFCORE_ERR_INVALID;
      }
    }
  }
  rc = staged_base(changeset, canon, &st, draft, &op, &tentative);
  if (rc != GDEFCORE_OK) {
    doc_free(cat->alloc, &tentative);
    staging_free(cat, &st);
    return rc;
  }
  for (i = 0; i < value_count; i++) {
    const GDEFCORE_Decl * decl = decl_named(st.decls, st.ndecls,
        values[i].field, values[i].field_len);
    GDEFCORE_Text * canonical = NULL;
    const char ** texts = NULL;
    size_t * lens = NULL;
    size_t v;
    rc = canonical_values(cat, decl, &values[i], &canonical);
    if (rc == GDEFCORE_OK && values[i].count > 0) {
      texts = (const char **)mem0(cat->alloc, values[i].count * sizeof *texts);
      lens = (size_t *)mem0(cat->alloc, values[i].count * sizeof *lens);
      if (texts == NULL || lens == NULL) {
        rc = GDEFCORE_ERR_OOM;
      }
    }
    for (v = 0; rc == GDEFCORE_OK && v < values[i].count; v++) {
      texts[v] = canonical[v].p;
      lens[v] = canonical[v].n;
    }
    if (rc == GDEFCORE_OK) {
      rc = doc_set_field(cat->alloc, &tentative, &cat->limits, lang, lang_len,
          values[i].field, values[i].field_len, texts, lens, values[i].count);
    }
    for (v = 0; canonical != NULL && v < values[i].count; v++) {
      text_clear(cat->alloc, &canonical[v]);
    }
    gcu_allocator_free(cat->alloc, canonical);
    gcu_allocator_free(cat->alloc, (void *)texts);
    gcu_allocator_free(cat->alloc, lens);
    if (rc != GDEFCORE_OK) {
      doc_free(cat->alloc, &tentative);
      staging_free(cat, &st);
      return rc;
    }
  }
  return stage_finish(changeset, canon, &st, op, &tentative, draft);
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

/* The doc @p view reads of an entity: gdefcore_entity_values() and
 * gdefcore_entity_tree() (story S6d) read through this one rule. */
static GDEFCORE_Result view_doc(GDEFCORE_Catalog * catalog, const char * canon,
    int view, GDEFCORE_EntLook * out_look, GDEFCORE_Doc * doc) {
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  memset(doc, 0, sizeof *doc);
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (out_look != NULL) {
    *out_look = look;
  }
  if (view == GDEFCORE_VIEW_DRAFT && look.has_draft) {
    /* An editor's view: the draft, over what the entity is now. */
    rc = gdefcore_ent_read_doc(catalog, canon, 0, 1, doc);
  } else {
    /* A reader's view is the newest revision, and only while the flag is
     * set. The unpublished entity answers as one that is not there; so
     * does a cleared one, and one never saved. */
    if (!look.exists || look.revision == 0 || look.deleted ||
        (view == GDEFCORE_VIEW_PUBLISHED && !look.published)) {
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_ent_read_doc(catalog, canon, 0, 0, doc);
  }
  return rc;
}

/* ---- field trees (story S6d) --------------------------------------------- */

/* One value of a tree for field @p d in its canonical text: a personal value
 * as the sealed text it is (and only when the caller may hand one over), any
 * other as its type spells it. */
static GDEFCORE_Result canon_one(GDEFCORE_Catalog * cat, int accept_personal,
    const GDEFCORE_Decl * d, const char * text, size_t len,
    GDEFCORE_Text * out) {
  memset(out, 0, sizeof *out);
  if (text == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (len > cat->limits.max_value_bytes) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (d->personal) {
    if (!accept_personal || !sealed_ok(text, len)) {
      return GDEFCORE_ERR_INVALID;
    }
    return text_set(cat->alloc, out, text, len);
  }
  return gdefcore_ent_value_check(cat->alloc, d, text, len, out);
}

/* Items of a tree keyed by parent and field, to count siblings once. */
typedef struct Sib {
  size_t parent;
  const char * field;
  size_t field_len;
} Sib;

static int sib_cmp(const void * a, const void * b) {
  const Sib * x = (const Sib *)a;
  const Sib * y = (const Sib *)b;
  size_t n;
  int c;
  if (x->parent != y->parent) {
    return x->parent < y->parent ? -1 : 1;
  }
  n = x->field_len < y->field_len ? x->field_len : y->field_len;
  c = n == 0 ? 0 : memcmp(x->field, y->field, n);
  if (c != 0) {
    return c;
  }
  return x->field_len < y->field_len ? -1 : (x->field_len > y->field_len);
}

/* No field holds more items under one parent than it may: one for a field
 * that is not multiple, the catalog's max_values for one that is. */
static GDEFCORE_Result sibling_counts(GDEFCORE_Catalog * cat,
    const GDEFCORE_Decl * decls, size_t ndecls, const GDEFCORE_Tree * in) {
  size_t n = gdefcore_tree_item_count(in);
  Sib * sibs;
  size_t i;
  size_t run = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (n <= 1) {
    return GDEFCORE_OK;
  }
  sibs = (Sib *)mem0(cat->alloc, (n - 1) * sizeof *sibs);
  if (sibs == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 1; i < n; i++) {
    GDEFCORE_TreeItem it;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(in, i, &it) != GDEFCORE_OK) {
      gcu_allocator_free(cat->alloc, sibs);
      return GDEFCORE_ERR_INVALID;
    }
    sibs[i - 1].parent = it.parent;
    sibs[i - 1].field = it.path;
    sibs[i - 1].field_len = it.path_len;
  }
  qsort(sibs, n - 1, sizeof *sibs, sib_cmp);
  for (i = 0; rc == GDEFCORE_OK && i < n - 1; i++) {
    run = i > 0 && sib_cmp(&sibs[i], &sibs[i - 1]) == 0 ? run + 1 : 1;
    {
      const GDEFCORE_Decl * d = gdefcore_ent_decl_at(decls, ndecls,
          sibs[i].field, sibs[i].field_len);
      if (d == NULL) {
        rc = GDEFCORE_ERR_INVALID;
      } else if (!d->many && run > 1) {
        rc = GDEFCORE_ERR_INVALID;
      } else if (run > cat->limits.max_values) {
        rc = GDEFCORE_ERR_LIMIT;
      }
    }
  }
  gcu_allocator_free(cat->alloc, sibs);
  return rc;
}

/*
 * A tree checked against the type's decls, into language @p l: the root's
 * values (with @p with_root) and the items of its multiple fields as @p l's
 * fields, with their ids, and every group item, at any depth, into @p l's
 * groups, each value in its canonical text. Anything the type does not
 * declare where it sits is ::GDEFCORE_ERR_INVALID.
 */
static GDEFCORE_Result tree_to_lang(GDEFCORE_Catalog * cat, int accept_personal,
    const GDEFCORE_Decl * decls, size_t ndecls, const GDEFCORE_Tree * in,
    int with_root, GDEFCORE_Lang * l) {
  size_t n = gdefcore_tree_item_count(in);
  size_t * map = NULL;
  size_t i;
  GDEFCORE_Result rc;
  const size_t kScalarItem = SIZE_MAX - 1;
  if (in == NULL || n == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (n > GDEFSTOR_MODEL_MAX_ITEMS) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = sibling_counts(cat, decls, ndecls, in);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  map = (size_t *)mem0(cat->alloc, n * sizeof *map);
  if (map == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    GDEFCORE_TreeItem it;
    const GDEFCORE_Decl * under = NULL;
    size_t gi = 0;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(in, i, &it) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    if (i == 0) {
      if (!with_root && it.value_count > 0) {
        rc = GDEFCORE_ERR_INVALID;
        break;
      }
      for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
        const char * f = NULL;
        size_t fn = 0;
        const char * text = NULL;
        size_t len = 0;
        const GDEFCORE_Decl * d;
        GDEFCORE_Text canon;
        rc = gdefcore_tree_value(in, 0, k, &f, &fn, &text, &len);
        if (rc != GDEFCORE_OK) {
          break;
        }
        d = decl_named(decls, ndecls, f, fn);
        if (d == NULL || d->many) {
          rc = GDEFCORE_ERR_INVALID;
          break;
        }
        rc = canon_one(cat, accept_personal, d, text, len, &canon);
        if (rc == GDEFCORE_OK) {
          rc = gdefcore_ent_lang_add(cat->alloc, l, f, fn, &canon, 0, 0,
              NULL, 0);
          if (rc != GDEFCORE_OK) {
            text_clear(cat->alloc, &canon);
          }
        }
      }
      map[0] = 0;
      continue;
    }
    under = gdefcore_ent_decl_at(decls, ndecls, it.path, it.path_len);
    if (under == NULL || it.parent >= i ||
        (under->type != GDEFSTOR_FIELD_GROUP && !under->many) ||
        map[it.parent] == kScalarItem) {
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    if (under->type != GDEFSTOR_FIELD_GROUP) {
      /* An item of a multiple field: its one value, its own. */
      const char * f = NULL;
      size_t fn = 0;
      const char * text = NULL;
      size_t len = 0;
      GDEFCORE_Text canon;
      if (it.value_count != 1 ||
          gdefcore_tree_value(in, i, 0, &f, &fn, &text, &len) != GDEFCORE_OK ||
          fn != 0) {
        rc = GDEFCORE_ERR_INVALID;
        break;
      }
      rc = canon_one(cat, accept_personal, under, text, len, &canon);
      if (rc != GDEFCORE_OK) {
        break;
      }
      if (it.parent == 0) {
        if (!with_root) {
          text_clear(cat->alloc, &canon);
          rc = GDEFCORE_ERR_INVALID;
          break;
        }
        rc = gdefcore_ent_lang_add(cat->alloc, l, it.field, it.field_len,
            &canon, 1, it.id, NULL, 0);
        if (rc != GDEFCORE_OK) {
          text_clear(cat->alloc, &canon);
        }
        map[i] = kScalarItem;
        continue;
      }
      if (l->groups == NULL) {
        rc = gdefcore_ent_tree_new(cat->alloc, &l->groups);
      }
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_tree_add(l->groups, map[it.parent], it.field,
            it.field_len, it.id, &gi);
      }
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_ent_tree_put(l->groups, gi, NULL, 0, canon.p, canon.n,
            NULL, 0);
      }
      text_clear(cat->alloc, &canon);
      map[i] = kScalarItem;
      continue;
    }
    if (l->groups == NULL) {
      rc = gdefcore_ent_tree_new(cat->alloc, &l->groups);
      if (rc != GDEFCORE_OK) {
        break;
      }
    }
    rc = gdefcore_tree_add(l->groups, map[it.parent], it.field, it.field_len,
        it.id, &gi);
    if (rc != GDEFCORE_OK) {
      break;
    }
    map[i] = gi;
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * f = NULL;
      size_t fn = 0;
      const char * text = NULL;
      size_t len = 0;
      GDEFCORE_Text path;
      GDEFCORE_Text canon;
      const GDEFCORE_Decl * d;
      rc = gdefcore_tree_value(in, i, k, &f, &fn, &text, &len);
      if (rc != GDEFCORE_OK) {
        break;
      }
      if (fn == 0) {
        rc = GDEFCORE_ERR_INVALID; /* a group has no value of its own */
        break;
      }
      rc = gdefcore_ent_tree_value_path(in, i, f, fn, &path);
      if (rc != GDEFCORE_OK) {
        break;
      }
      d = gdefcore_ent_decl_at(decls, ndecls, path.p, path.n);
      text_clear(cat->alloc, &path);
      if (d == NULL || d->type == GDEFSTOR_FIELD_GROUP || d->many) {
        rc = GDEFCORE_ERR_INVALID;
        break;
      }
      rc = canon_one(cat, accept_personal, d, text, len, &canon);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_ent_tree_put(l->groups, gi, f, fn, canon.p, canon.n,
            NULL, 0);
        text_clear(cat->alloc, &canon);
      }
    }
  }
  gcu_allocator_free(cat->alloc, map);
  return rc;
}

/* Free what one language holds and empty it, leaving the struct itself. */
static void lang_clear(const GDEFCORE_Allocator * alloc, GDEFCORE_Lang * l) {
  size_t j;
  for (j = 0; j < l->nfields; j++) {
    gdefcore_ent_vals_clear(alloc, &l->fields[j]);
    text_clear(alloc, &l->fields[j].name);
  }
  gcu_allocator_free(alloc, l->fields);
  gdefcore_tree_free(l->groups);
  text_clear(alloc, &l->lang);
  memset(l, 0, sizeof *l);
}

/* The language @p lang of @p doc, emptied, or added empty. */
static GDEFCORE_Lang * doc_lang_reset(GDEFCORE_Catalog * cat,
    GDEFCORE_Doc * doc, const char * lang, size_t lang_len) {
  size_t i;
  GDEFCORE_Lang * l = NULL;
  for (i = 0; i < doc->nlangs; i++) {
    if (span_eq(doc->langs[i].lang.p, doc->langs[i].lang.n, lang, lang_len)) {
      l = &doc->langs[i];
      break;
    }
  }
  if (l == NULL) {
    GDEFCORE_Lang * langs;
    if (doc->nlangs >= cat->limits.max_languages) {
      return NULL;
    }
    langs = (GDEFCORE_Lang *)gcu_allocator_realloc(cat->alloc, doc->langs,
        (doc->nlangs + 1) * sizeof *langs);
    if (langs == NULL) {
      return NULL;
    }
    doc->langs = langs;
    l = &doc->langs[doc->nlangs];
    memset(l, 0, sizeof *l);
    if (text_set(cat->alloc, &l->lang, lang, lang_len) != GDEFCORE_OK) {
      return NULL;
    }
    doc->nlangs += 1;
    return l;
  }
  {
    /* Free what the language held, then keep the slot with its tag. */
    GDEFCORE_Text keep = l->lang;
    l->lang.p = NULL;
    l->lang.n = 0;
    lang_clear(cat->alloc, l);
    l->lang = keep;
  }
  return l;
}

static GDEFCORE_Result stage_tree(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Tree * tree, int draft) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * cat;
  GDEFCORE_Op * op = NULL;
  GDEFCORE_Doc tentative;
  GDEFCORE_Lang fresh;
  GDEFCORE_Lang * slot;
  Staging st;
  GDEFCORE_Result rc;
  if (changeset == NULL || changeset->applied || tree == NULL ||
      !lang_ok(lang, lang_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  cat = changeset->catalog;
  rc = staging_load(cat, canon, &st);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&fresh, 0, sizeof fresh);
  rc = tree_to_lang(cat, changeset->accept_sealed, st.decls, st.ndecls, tree,
      1, &fresh);
  if (rc == GDEFCORE_OK) {
    rc = staged_base(changeset, canon, &st, draft, &op, &tentative);
  } else {
    memset(&tentative, 0, sizeof tentative);
  }
  if (rc == GDEFCORE_OK) {
    slot = doc_lang_reset(cat, &tentative, lang, lang_len);
    if (slot == NULL) {
      rc = tentative.nlangs >= cat->limits.max_languages ? GDEFCORE_ERR_LIMIT
                                                         : GDEFCORE_ERR_OOM;
    } else {
      /* The tree is the language's whole content (AD-14). */
      slot->fields = fresh.fields;
      slot->nfields = fresh.nfields;
      slot->groups = fresh.groups;
      memset(&fresh, 0, sizeof fresh);
    }
  }
  if (rc != GDEFCORE_OK) {
    lang_clear(cat->alloc, &fresh);
    doc_free(cat->alloc, &tentative);
    staging_free(cat, &st);
    return rc;
  }
  return stage_finish(changeset, canon, &st, op, &tentative, draft);
}

GDEFCORE_Result gdefcore_tree_save(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Tree * tree) {
  return stage_tree(changeset, id, id_len, lang, lang_len, tree, 0);
}

GDEFCORE_Result gdefcore_tree_save_draft(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Tree * tree) {
  return stage_tree(changeset, id, id_len, lang, lang_len, tree, 1);
}

/* Language @p l as a public tree: the root's values on the root item, the
 * items of its multiple fields (with their ids) and its group items. */
static GDEFCORE_Result lang_to_tree(GDEFCORE_Catalog * cat,
    const GDEFCORE_Decl * decls, size_t ndecls, const GDEFCORE_Lang * l,
    GDEFCORE_Tree ** out) {
  GDEFCORE_Tree * t = NULL;
  size_t * map = NULL;
  size_t gn = gdefcore_tree_item_count(l->groups);
  size_t j;
  size_t k;
  GDEFCORE_Result rc = gdefcore_ent_tree_new(cat->alloc, &t);
  for (j = 0; rc == GDEFCORE_OK && j < l->nfields; j++) {
    const GDEFCORE_Vals * f = &l->fields[j];
    const GDEFCORE_Decl * d = decl_named(decls, ndecls, f->name.p, f->name.n);
    int items = f->ids != NULL || (d != NULL ? d->many : f->nvals != 1);
    for (k = 0; rc == GDEFCORE_OK && k < f->nvals; k++) {
      size_t item = 0;
      /* A personal value read from storage keeps the subject stored with
       * it (story S7), for the read path to open it with. */
      const char * sub = f->subjects != NULL ? f->subjects[k].p : NULL;
      size_t sub_len = f->subjects != NULL ? f->subjects[k].n : 0;
      if (items) {
        rc = gdefcore_tree_add(t, 0, f->name.p, f->name.n,
            f->ids != NULL ? f->ids[k] : 0, &item);
        if (rc == GDEFCORE_OK) {
          rc = gdefcore_ent_tree_put(t, item, NULL, 0, f->vals[k].p,
              f->vals[k].n, sub, sub_len);
        }
      } else {
        rc = gdefcore_ent_tree_put(t, 0, f->name.p, f->name.n, f->vals[k].p,
            f->vals[k].n, sub, sub_len);
      }
    }
  }
  if (rc == GDEFCORE_OK && gn > 1) {
    map = (size_t *)mem0(cat->alloc, gn * sizeof *map);
    if (map == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  for (j = 1; rc == GDEFCORE_OK && j < gn; j++) {
    GDEFCORE_TreeItem it;
    size_t item = 0;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    rc = gdefcore_tree_item(l->groups, j, &it);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_tree_add(t, it.parent == 0 ? 0 : map[it.parent], it.field,
          it.field_len, it.id, &item);
    }
    map[j] = item;
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * f = NULL;
      size_t fn = 0;
      const char * text = NULL;
      size_t len = 0;
      rc = gdefcore_tree_value(l->groups, j, k, &f, &fn, &text, &len);
      if (rc == GDEFCORE_OK) {
        size_t sub_len = 0;
        const char * sub = gdefcore_ent_tree_value_subject(l->groups, j, k,
            &sub_len);
        rc = gdefcore_ent_tree_put(t, item, f, fn, text, len, sub, sub_len);
      }
    }
  }
  gcu_allocator_free(cat->alloc, map);
  if (rc != GDEFCORE_OK) {
    gdefcore_tree_free(t);
    return rc;
  }
  *out = t;
  return GDEFCORE_OK;
}

static GDEFCORE_Result doc_tree(GDEFCORE_Catalog * cat, const char * type,
    size_t type_len, const GDEFCORE_Doc * doc, const char * lang,
    size_t lang_len, GDEFCORE_Tree ** out) {
  GDEFCORE_Decl * decls = NULL;
  size_t ndecls = 0;
  size_t i;
  GDEFCORE_Result rc;
  for (i = 0; i < doc->nlangs; i++) {
    if (span_eq(doc->langs[i].lang.p, doc->langs[i].lang.n, lang, lang_len)) {
      break;
    }
  }
  if (i == doc->nlangs) {
    return GDEFCORE_ERR_INVALID; /* no content in that language */
  }
  rc = load_type(cat, type, type_len, NULL, &decls, &ndecls, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = lang_to_tree(cat, decls, ndecls, &doc->langs[i], out);
  decls_free(cat->alloc, decls, ndecls);
  return rc;
}

GDEFCORE_Result gdefcore_entity_tree(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * changeset, int view, const char * id,
    size_t id_len, const char * lang, size_t lang_len,
    GDEFCORE_Tree ** out_tree) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Doc doc;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_tree == NULL || lang == NULL ||
      (view != GDEFCORE_VIEW_PUBLISHED && view != GDEFCORE_VIEW_DRAFT &&
          view != GDEFCORE_VIEW_CURRENT)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (changeset != NULL) {
    size_t i;
    for (i = 0; i < changeset->nops; i++) {
      const GDEFCORE_Op * op = &changeset->ops[i];
      if (op->id.p != NULL &&
          span_eq(op->id.p, op->id.n, canon, GDEFCORE_PUBLIC_ID_LEN) &&
          op->kind != GDEFCORE_OP_DEFINE) {
        if (op->kind == GDEFCORE_OP_CLEAR) {
          return GDEFCORE_ERR_INVALID;
        }
        return doc_tree(catalog, op->type_name.p, op->type_name.n, &op->staged,
            lang, lang_len, out_tree);
      }
    }
  }
  rc = view_doc(catalog, canon, view, &look, &doc);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = doc_tree(catalog, look.type, look.type_len, &doc, lang, lang_len,
      out_tree);
  doc_free(catalog->alloc, &doc);
  return rc;
}

GDEFCORE_Result gdefcore_entity_revision_tree(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, uint64_t seq, const char * lang,
    size_t lang_len, GDEFCORE_Tree ** out_tree) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Doc doc;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_tree == NULL || lang == NULL || seq == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!look.exists || seq > look.revision) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_read_doc(catalog, canon, seq, 0, &doc);
  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = doc_tree(catalog, look.type, look.type_len, &doc, lang, lang_len,
      out_tree);
  doc_free(catalog->alloc, &doc);
  return rc;
}

GDEFCORE_Result gdefcore_type_tree_field_count(GDEFCORE_Catalog * catalog,
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

GDEFCORE_Result gdefcore_type_tree_field(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, GDEFCORE_FieldInfo * out) {
  GDEFCORE_Decl * decls = NULL;
  size_t n = 0;
  size_t k;
  const GDEFCORE_Decl * d;
  GDEFCORE_FieldInfo info;
  GDEFCORE_Result rc;
  if (catalog == NULL || out == NULL || out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_type(catalog, name, name_len, NULL, &decls, &n, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (index >= n || decls[index].name.n > GDEFCORE_FIELD_PATH_MAX ||
      decls[index].subject.n >= sizeof info.subject) {
    decls_free(catalog->alloc, decls, n);
    return GDEFCORE_ERR_INVALID;
  }
  d = &decls[index];
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  memcpy(info.path, d->name.p, d->name.n);
  info.path_len = d->name.n;
  info.parent = GDEFCORE_TREE_ROOT;
  for (k = d->name.n; k > 0; k--) {
    if (d->name.p[k - 1] == '.') {
      size_t g;
      info.name_at = k;
      for (g = 0; g < index; g++) {
        if (span_eq(decls[g].name.p, decls[g].name.n, d->name.p, k - 1)) {
          info.parent = g;
        }
      }
      break;
    }
  }
  for (k = 0; k < d->name.n; k++) {
    info.depth += d->name.p[k] == '.' ? 1u : 0u;
  }
  info.type = d->type;
  info.scale = d->scale;
  info.many = d->many;
  info.required = d->required;
  info.personal = d->personal;
  info.indexed = d->indexed;
  if (d->subject.n > 0) {
    memcpy(info.subject, d->subject.p, d->subject.n);
    info.subject_len = d->subject.n;
  }
  decls_free(catalog->alloc, decls, n);
  *out = info;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_changeset_accept_sealed(
    GDEFCORE_Changeset * changeset) {
  if (changeset == NULL || changeset->applied) {
    return GDEFCORE_ERR_INVALID;
  }
  changeset->accept_sealed = 1;
  return GDEFCORE_OK;
}

/* Record whose sealed @p text is; @p subjects NULL leaves the changeset's
 * keys as they are (a parsed patch: the catalog's keys index it). */
static GDEFCORE_Result note_add(GDEFCORE_Changeset * changeset,
    struct GDEFCORE_Subjects * subjects, const char * text, size_t text_len,
    const char * subject, size_t subject_len,
    const uint8_t mac[GDEFSTOR_BLIND_MAC_BYTES]) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_SealNote * next;
  GDEFCORE_SealNote * n;
  if (changeset == NULL || changeset->applied || text == NULL ||
      text_len == 0 ||
      gdefcore_id_canonical(subject, subject_len, sid) != GDEFCORE_OK ||
      (subjects != NULL && changeset->subjects != NULL &&
          changeset->subjects != subjects)) {
    return GDEFCORE_ERR_INVALID;
  }
  next = (GDEFCORE_SealNote *)gcu_allocator_realloc(changeset->catalog->alloc,
      changeset->notes, (changeset->nnotes + 1) * sizeof *next);
  if (next == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  changeset->notes = next;
  n = &changeset->notes[changeset->nnotes];
  memset(n, 0, sizeof *n);
  if (text_set(changeset->catalog->alloc, &n->text, text, text_len) !=
      GDEFCORE_OK) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(n->subject, sid, sizeof sid);
  if (mac != NULL) {
    memcpy(n->mac, mac, sizeof n->mac);
    n->has_mac = 1;
  }
  changeset->nnotes += 1;
  if (subjects != NULL) {
    changeset->subjects = subjects;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_changeset_note_sealed(GDEFCORE_Changeset * changeset,
    struct GDEFCORE_Subjects * subjects, const char * text, size_t text_len,
    const char * subject, size_t subject_len,
    const uint8_t mac[GDEFSTOR_BLIND_MAC_BYTES]) {
  if (subjects == NULL || text == NULL || !sealed_ok(text, text_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  return note_add(changeset, subjects, text, text_len, subject, subject_len,
      mac);
}

/* The note a changeset holds for sealed @p text, or NULL. */
static const GDEFCORE_SealNote * note_of(const GDEFCORE_Changeset * cs,
    const char * text, size_t len) {
  size_t i;
  for (i = 0; i < cs->nnotes; i++) {
    if (span_eq(cs->notes[i].text.p, cs->notes[i].text.n, text, len)) {
      return &cs->notes[i];
    }
  }
  return NULL;
}

/*
 * Stage an operation on an entity that carries no field values of its own:
 * a publish (its draft applied, if it has one), an unpublish or a clear. The
 * op holds the current values as its base and, as what it stages, what the
 * entity's content becomes, so the diff, the template vet and the
 * personal-value check see the change as the changeset leaves it.
 */
static GDEFCORE_Result stage_record_op(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, int kind) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * cat;
  GDEFCORE_Op * op = NULL;
  GDEFCORE_Doc staged;
  GDEFCORE_Doc base;
  Staging st;
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
  memset(&staged, 0, sizeof staged);
  memset(&base, 0, sizeof base);
  rc = staging_load(cat, canon, &st);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = current_doc(cat, canon, &st.look, &base);
  if (rc == GDEFCORE_OK && kind == GDEFCORE_OP_PUBLISH) {
    if (st.look.has_draft) {
      rc = gdefcore_ent_read_doc(cat, canon, 0, 1, &staged);
      /* A reservation with nothing in it is not something to publish. */
      if (rc == GDEFCORE_OK && st.look.reserved && staged.nlangs == 0) {
        rc = GDEFCORE_ERR_INVALID;
      }
    } else if (!st.look.exists || st.look.revision == 0) {
      rc = GDEFCORE_ERR_INVALID;
    } else {
      rc = doc_clone(cat->alloc, &base, &staged);
    }
    /* What is published must hold personal values only sealed. */
    if (rc == GDEFCORE_OK && !doc_personal_sealed(&staged, st.decls, st.ndecls)) {
      rc = GDEFCORE_ERR_INVALID;
    }
  } else if (rc == GDEFCORE_OK && kind != GDEFCORE_OP_CLEAR) {
    rc = doc_clone(cat->alloc, &base, &staged);
  }
  if (rc == GDEFCORE_OK) {
    rc = add_op(changeset, &op);
  }
  if (rc == GDEFCORE_OK) {
    op->kind = kind;
    op->staged = staged;
    op->base = base;
    memset(&staged, 0, sizeof staged);
    memset(&base, 0, sizeof base);
    rc = op_from_staging(cat, op, canon, &st);
    if (rc != GDEFCORE_OK) {
      op_free(cat->alloc, op);
      changeset->nops -= 1;
    }
  }
  doc_free(cat->alloc, &staged);
  doc_free(cat->alloc, &base);
  staging_free(cat, &st);
  return rc;
}

GDEFCORE_Result gdefcore_entity_publish(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len) {
  return stage_record_op(changeset, id, id_len, GDEFCORE_OP_PUBLISH);
}

GDEFCORE_Result gdefcore_entity_unpublish(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len) {
  return stage_record_op(changeset, id, id_len, GDEFCORE_OP_UNPUBLISH);
}

GDEFCORE_Result gdefcore_entity_clear(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len) {
  return stage_record_op(changeset, id, id_len, GDEFCORE_OP_CLEAR);
}

/* ---- reading an entity ---------------------------------------------------- */

GDEFCORE_Result gdefcore_entity_revision_count(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, size_t * out_count) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_count == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!look.exists) {
    *out_count = 0;
    return GDEFCORE_OK;
  }
  return gdefcore_ent_history(catalog, canon, out_count, 0, NULL, NULL, NULL);
}

GDEFCORE_Result gdefcore_entity_revision_at(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, size_t index, uint64_t * out_seq,
    char ** out_actor, size_t * out_actor_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  uint64_t seq = 0;
  char * who = NULL;
  size_t who_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_seq == NULL || out_actor == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!look.exists) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_history(catalog, canon, NULL, index, &seq, &who, &who_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_seq = seq;
  *out_actor = who;
  if (out_actor_len != NULL) {
    *out_actor_len = who_len;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_revision(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, uint64_t * out_seq) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_seq == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_seq = look.revision;
  return GDEFCORE_OK;
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
  GDEFCORE_Doc doc;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_texts == NULL || out_lens == NULL ||
      out_count == NULL ||
      (view != GDEFCORE_VIEW_PUBLISHED && view != GDEFCORE_VIEW_DRAFT &&
          view != GDEFCORE_VIEW_CURRENT)) {
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
  rc = view_doc(catalog, canon, view, NULL, &doc);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = values_from(catalog, &doc, lang, lang_len, field, field_len, out_texts,
      out_lens, out_count);
  doc_free(catalog->alloc, &doc);
  return rc;
}

GDEFCORE_Result gdefcore_entity_revision_values(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, uint64_t seq, const char * lang,
    size_t lang_len, const char * field, size_t field_len, char *** out_texts,
    size_t ** out_lens, size_t * out_count) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Doc doc;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_texts == NULL || out_lens == NULL ||
      out_count == NULL || field == NULL || lang == NULL || seq == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!look.exists || seq > look.revision) {
    /* A sequence that was never recorded is no revision of this entity. */
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_read_doc(catalog, canon, seq, 0, &doc);
  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
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

static const GDEFCORE_Lang * lang_of(const GDEFCORE_Doc * doc,
    const GDEFCORE_Text * lang) {
  size_t i;
  for (i = 0; i < doc->nlangs; i++) {
    if (span_eq(doc->langs[i].lang.p, doc->langs[i].lang.n, lang->p, lang->n)) {
      return &doc->langs[i];
    }
  }
  return NULL;
}

/* One line per language and group field of the root whose items changed
 * (story S6d): `en lines: 2 items -> 3 items`. A group's items are compared
 * whole, ids, order and values; the line counts them. */
static GDEFCORE_Result group_lines(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Op * op, char *** lines, size_t * nlines) {
  size_t pass;
  for (pass = 0; pass < 2; pass++) {
    const GDEFCORE_Doc * doc = pass == 0 ? &op->base : &op->staged;
    const GDEFCORE_Doc * other = pass == 0 ? &op->staged : &op->base;
    size_t li;
    for (li = 0; li < doc->nlangs; li++) {
      const GDEFCORE_Lang * l = &doc->langs[li];
      const GDEFCORE_Lang * o = lang_of(other, &l->lang);
      size_t n = gdefcore_tree_item_count(l->groups);
      size_t i;
      for (i = 1; i < n; i++) {
        GDEFCORE_TreeItem it;
        const GDEFCORE_Tree * before;
        const GDEFCORE_Tree * after;
        size_t j;
        int seen = 0;
        char * line;
        int kn;
        memset(&it, 0, sizeof it);
        it.size = sizeof it;
        if (gdefcore_tree_item(l->groups, i, &it) != GDEFCORE_OK) {
          return GDEFCORE_ERR_INTERNAL;
        }
        if (it.parent != 0) {
          continue;
        }
        /* Each field once: its first item, and in the second pass only a
         * field the first did not see. */
        for (j = 1; j < i && !seen; j++) {
          GDEFCORE_TreeItem e;
          memset(&e, 0, sizeof e);
          e.size = sizeof e;
          seen = gdefcore_tree_item(l->groups, j, &e) == GDEFCORE_OK &&
                 e.parent == 0 &&
                 span_eq(e.field, e.field_len, it.field, it.field_len);
        }
        if (seen || (pass == 1 && o != NULL &&
                        gdefcore_tree_child_count(o->groups, 0, it.field,
                            it.field_len) > 0)) {
          continue;
        }
        before = pass == 0 ? l->groups : (o == NULL ? NULL : o->groups);
        after = pass == 0 ? (o == NULL ? NULL : o->groups) : l->groups;
        if (gdefcore_ent_tree_field_equal(before, after, it.field,
                it.field_len)) {
          continue;
        }
        line = (char *)mem(alloc, l->lang.n + it.field_len + 64);
        if (line == NULL) {
          return GDEFCORE_ERR_OOM;
        }
        kn = snprintf(line, l->lang.n + it.field_len + 64,
            "%.*s %.*s: %zu items -> %zu items", (int)l->lang.n, l->lang.p,
            (int)it.field_len, it.field,
            gdefcore_tree_child_count(before, 0, it.field, it.field_len),
            gdefcore_tree_child_count(after, 0, it.field, it.field_len));
        if (kn <= 0) {
          gcu_allocator_free(alloc, line);
          return GDEFCORE_ERR_LIMIT;
        }
        {
          char ** next = (char **)gcu_allocator_realloc(alloc, *lines,
              (*nlines + 1) * sizeof *next);
          if (next == NULL) {
            gcu_allocator_free(alloc, line);
            return GDEFCORE_ERR_OOM;
          }
          *lines = next;
          (*lines)[(*nlines)++] = line;
        }
      }
    }
  }
  return GDEFCORE_OK;
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
    {
      GDEFCORE_Result gr = group_lines(alloc, op, &lines, &nlines);
      if (gr != GDEFCORE_OK) {
        free_cstrs(alloc, lines, nlines);
        return gr;
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

/* An operation that appends a revision. */
static int revision_op(int kind) {
  return kind == GDEFCORE_OP_SAVE || kind == GDEFCORE_OP_DRAFT ||
         kind == GDEFCORE_OP_REVERT;
}

/* An operation the write-path hooks are told about. Unpublish writes no
 * revision and no values, and has no hook of its own. */
static int hooked_op(int kind) {
  return revision_op(kind) || kind == GDEFCORE_OP_CLEAR ||
         kind == GDEFCORE_OP_PUBLISH;
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

/* Who, when and why for the revisions a changeset writes. */
static GDEFSTOR_RevisionMeta revision_meta(const GDEFCORE_Changeset * cs,
    int64_t when) {
  GDEFSTOR_RevisionMeta m;
  memset(&m, 0, sizeof m);
  m.size = sizeof m;
  m.who = cs->actor.p == NULL ? "" : cs->actor.p;
  m.who_len = cs->actor.n;
  m.when_ms = when;
  m.why = cs->why.p == NULL ? "" : cs->why.p;
  m.why_len = cs->why.n;
  return m;
}

static GDEFCORE_Result set_state(GDEFSTOR_Write * write, const GDEFCORE_Op * op,
    const GDEFCORE_Changeset * cs, int published, int deleted, int64_t when,
    int * changed) {
  int appended = 0;
  GDEFCORE_Result rc = map_stor(gdefstor_entity_set_state(write, op->id.p,
      op->id.n, published, deleted, cs->actor.p == NULL ? "" : cs->actor.p,
      cs->actor.n, when, &appended));
  if (rc == GDEFCORE_OK && appended) {
    *changed = 1;
  }
  return rc;
}

/* The author of the entity's draft, as recorded when it was written: the
 * changeset's actor then, or the system (empty). @p out holds at most a
 * public id. */
static GDEFCORE_Result draft_author(GDEFCORE_Catalog * cat, const GDEFCORE_Op * op,
    char * out, size_t cap, size_t * out_len) {
  int found = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFCORE_Result rc = map_stor(gdefstor_record_get(cat->store,
      (const char *)cat->tenant, cat->tenant_len, GDEFCORE_ENT_DRAFT_NS,
      sizeof GDEFCORE_ENT_DRAFT_NS - 1, op->id.p, op->id.n, &found, &bytes,
      &len));
  *out_len = 0;
  if (rc == GDEFCORE_OK && found) {
    if (len >= cap) {
      rc = GDEFCORE_ERR_CORRUPT;
    } else {
      if (len > 0) {
        memcpy(out, bytes, len);
      }
      *out_len = len;
    }
  }
  gdefstor_bytes_free(NULL, bytes);
  return rc;
}

static GDEFCORE_Result put_draft_author(GDEFSTOR_Write * write,
    const GDEFCORE_Changeset * cs, const GDEFCORE_Op * op) {
  return map_stor(gdefstor_record_put(write, GDEFCORE_ENT_DRAFT_NS,
      sizeof GDEFCORE_ENT_DRAFT_NS - 1, op->id.p, op->id.n,
      (const uint8_t *)(cs->actor.p == NULL ? "" : cs->actor.p), cs->actor.n));
}

static GDEFCORE_Result drop_draft_author(GDEFSTOR_Write * write,
    const GDEFCORE_Op * op) {
  return map_stor(gdefstor_record_delete(write, GDEFCORE_ENT_DRAFT_NS,
      sizeof GDEFCORE_ENT_DRAFT_NS - 1, op->id.p, op->id.n, NULL));
}

/* Where the trees of an op find their subjects and MACs (GDEFCORE_Seals):
 * the notes, the keys, and the entity's own subject, kept with it (story
 * S7), for a personal field that names no subject reference. */
static GDEFCORE_Result seals_for(const GDEFCORE_Changeset * cs,
    const GDEFCORE_Op * op, int index, GDEFCORE_Seals * out) {
  int found = 0;
  GDEFCORE_Result rc;
  memset(out, 0, sizeof *out);
  out->notes = cs->notes;
  out->nnotes = cs->nnotes;
  out->subjects = cs->subjects != NULL ? cs->subjects : cs->catalog->subjects;
  out->index = index;
  rc = gdefcore_ent_own_subject(cs->catalog, op->id.p, out->own, &found);
  if (rc == GDEFCORE_OK && !found) {
    out->own[0] = '\0';
  }
  return rc;
}

/* Say in words why the trees were refused, when it was a personal value. */
static GDEFCORE_Result seals_refuse(GDEFCORE_Changeset * cs,
    const GDEFCORE_Seals * seals, GDEFCORE_Result rc) {
  static const char kErased[] =
      "a personal value names an erased subject: their key is gone, and no "
      "new value of theirs is written (the draft or the change is kept; "
      "replace or remove that value and apply again)";
  static const char kUnknown[] =
      "a personal value has no subject this changeset can name, or there are "
      "no subjects to index it with";
  if (rc != GDEFCORE_OK && seals->erased) {
    (void)gdefcore_changeset_set_refusal(cs, kErased, sizeof kErased - 1);
  } else if (rc != GDEFCORE_OK && seals->unknown) {
    (void)gdefcore_changeset_set_refusal(cs, kUnknown, sizeof kUnknown - 1);
  }
  return rc;
}

/* The values of field @p name in language @p lang of @p doc, or NULL. */
static const GDEFCORE_Vals * doc_vals(const GDEFCORE_Doc * doc,
    const GDEFCORE_Text * lang, const GDEFCORE_Text * name) {
  size_t i;
  size_t j;
  for (i = 0; i < doc->nlangs; i++) {
    if (!span_eq(doc->langs[i].lang.p, doc->langs[i].lang.n, lang->p, lang->n)) {
      continue;
    }
    for (j = 0; j < doc->langs[i].nfields; j++) {
      if (span_eq(doc->langs[i].fields[j].name.p, doc->langs[i].fields[j].name.n,
              name->p, name->n)) {
        return &doc->langs[i].fields[j];
      }
    }
  }
  return NULL;
}

static int vals_equal(const GDEFCORE_Vals * a, const GDEFCORE_Vals * b) {
  size_t k;
  size_t an = a == NULL ? 0 : a->nvals;
  size_t bn = b == NULL ? 0 : b->nvals;
  if (an != bn) {
    return 0;
  }
  for (k = 0; k < an; k++) {
    if (!span_eq(a->vals[k].p, a->vals[k].n, b->vals[k].p, b->vals[k].n)) {
      return 0;
    }
  }
  return 1;
}

/*
 * A draft is validated against its type as it is when it is applied (AD-14),
 * not as it was when the draft was written: every value it changes must be
 * of a field the type has now, of that field's type, and the fields the type
 * requires now must be there. A field the type no longer has may only hold
 * what the entity holds there now (the port keeps a retired field's data).
 */
static GDEFCORE_Result draft_fits(GDEFCORE_Changeset * cs, const GDEFCORE_Op * op) {
  static const char kFits[] =
      "the draft does not fit its type as the type is now";
  GDEFCORE_Catalog * cat = cs->catalog;
  GDEFCORE_Decl * decls = NULL;
  size_t ndecls = 0;
  size_t i;
  size_t j;
  size_t k;
  int ok = 1;
  GDEFCORE_Result rc;
  if (builtin_name(op->type_name.p, op->type_name.n)) {
    return GDEFCORE_OK;
  }
  rc = load_type(cat, op->type_name.p, op->type_name.n, NULL, &decls, &ndecls,
      NULL, NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; ok && i < op->staged.nlangs; i++) {
    const GDEFCORE_Lang * l = &op->staged.langs[i];
    for (j = 0; ok && j < l->nfields; j++) {
      const GDEFCORE_Vals * f = &l->fields[j];
      const GDEFCORE_Decl * decl = decl_named(decls, ndecls, f->name.p, f->name.n);
      if (decl == NULL) {
        ok = vals_equal(f, doc_vals(&op->base, &l->lang, &f->name));
        continue;
      }
      if (!decl->many && f->nvals > 1) {
        ok = 0;
      }
      for (k = 0; ok && k < f->nvals; k++) {
        GDEFCORE_Text canon;
        memset(&canon, 0, sizeof canon);
        if (decl->personal) {
          ok = sealed_ok(f->vals[k].p, f->vals[k].n);
          continue;
        }
        rc = gdefcore_ent_value_check(cat->alloc, decl, f->vals[k].p,
            f->vals[k].n, &canon);
        text_clear(cat->alloc, &canon);
        if (rc == GDEFCORE_ERR_OOM) {
          decls_free(cat->alloc, decls, ndecls);
          return rc;
        }
        ok = rc == GDEFCORE_OK;
      }
    }
  }
  for (i = 0; ok && i < op->staged.nlangs; i++) {
    /* The group items of a language, checked as a tree save checks them
     * (story S6d); a language whose groups are what the entity has now is
     * kept as it is, retired fields and all. */
    const GDEFCORE_Lang * l = &op->staged.langs[i];
    GDEFCORE_Lang tmp;
    GDEFCORE_Result gr;
    if (l->groups == NULL) {
      continue;
    }
    memset(&tmp, 0, sizeof tmp);
    gr = tree_to_lang(cat, 1, decls, ndecls, l->groups, 0, &tmp);
    lang_clear(cat->alloc, &tmp);
    if (gr == GDEFCORE_ERR_OOM) {
      decls_free(cat->alloc, decls, ndecls);
      return gr;
    }
    if (gr != GDEFCORE_OK) {
      size_t b;
      ok = 0;
      for (b = 0; b < op->base.nlangs; b++) {
        if (span_eq(op->base.langs[b].lang.p, op->base.langs[b].lang.n,
                l->lang.p, l->lang.n)) {
          ok = gdefcore_ent_tree_equal(l->groups, op->base.langs[b].groups);
        }
      }
    }
  }
  if (ok && !doc_has_required(&op->staged, decls, ndecls)) {
    ok = 0;
  }
  decls_free(cat->alloc, decls, ndecls);
  if (!ok) {
    (void)gdefcore_changeset_set_refusal(cs, kFits, sizeof kFits - 1);
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

/*
 * One op, in the changeset's write. The op was staged against the entity's
 * revision, version and (for a draft) the revision its draft was made from;
 * when any of them has moved, @p conflict is set and nothing is written.
 */
static GDEFCORE_Result apply_op(GDEFCORE_Changeset * cs, GDEFSTOR_Write * write,
    GDEFCORE_Op * op, int64_t when, int * conflict) {
  GDEFCORE_Catalog * cat = cs->catalog;
  GDEFCORE_EntLook look;
  GDEFSTOR_RevisionMeta meta = revision_meta(cs, when);
  uint64_t version = 0;
  uint64_t rev = 0;
  int changed = 0;
  int moved = 0;
  GDEFCORE_Result rc;
  *conflict = 0;
  op->written = 0;
  if (op->kind == GDEFCORE_OP_DEFINE) {
    char * existing_id = NULL;
    size_t existing_id_len = 0;
    uint64_t existing_version = 0;
    int is_new = 1;
    rc = load_type(cat, op->machine.p, op->machine.n, NULL, NULL, NULL,
        &existing_id, &existing_id_len, &existing_version);
    if (rc == GDEFCORE_OK) {
      int stored = 0;
      is_new = 0;
      if (op->have_row && existing_version != op->base_seq) {
        gcu_allocator_free(cat->alloc, existing_id);
        *conflict = 1;
        return GDEFCORE_OK;
      }
      rc = type_subjects_of(cat, op->machine.p, op->machine.n, &stored);
      if (rc == GDEFCORE_OK && stored != op->type_subjects) {
        rc = GDEFCORE_ERR_INVALID; /* a type defined since, the other way */
      }
      if (rc != GDEFCORE_OK) {
        gcu_allocator_free(cat->alloc, existing_id);
        return rc;
      }
    } else if (rc != GDEFCORE_ERR_INVALID) {
      return rc;
    } else if (op->have_row) {
      *conflict = 1;
      return GDEFCORE_OK;
    }
    rc = write_type(cat, write, op->machine.p, op->machine.n, op->type_kind,
        op->type_subjects, op->decls, op->ndecls, is_new ? NULL : existing_id,
        existing_version);
    gcu_allocator_free(cat->alloc, existing_id);
    return rc;
  }
  rc = gdefcore_ent_lookup(cat, op->id.p, &look);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_ent_version(cat, op->id.p, &version);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* Every write that touches the entity moves its version, including the
   * ones that move no revision (a draft, a publish, an unpublish, a clear). */
  if (look.revision != op->base_seq || (op->have_ver && version != op->base_ver) ||
      (op->reserved && look.exists)) {
    *conflict = 1;
    return GDEFCORE_OK;
  }
  switch (op->kind) {
  case GDEFCORE_OP_SAVE: {
    GDEFCORE_Seals seals;
    rc = seals_for(cs, op, 1, &seals);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (!look.exists) {
      /* The first save of an entity its draft reserves: the reservation
       * gives way to the entity, made with the actor as its creator, and
       * the values are its first revision, written as any save is, so that
       * their personal values get their blind rows (story S6c). */
      rc = map_stor(gdefstor_draft_delete(write, op->id.p, op->id.n));
      if (rc == GDEFCORE_OK) {
        rc = map_stor(gdefstor_entity_create(write, op->type_name.p,
            op->type_name.n, op->id.p, op->id.n, meta.who, meta.who_len, when,
            NULL));
      }
      if (rc == GDEFCORE_OK) {
        rc = seals_refuse(cs, &seals, gdefcore_ent_save_doc(cat, write,
            op->id.p, op->type_name.p, op->type_name.n, 0, &meta, &op->staged,
            &seals, &rev, &moved));
      }
      if (rc == GDEFCORE_OK && moved) {
        *conflict = 1;
        return GDEFCORE_OK;
      }
      if (rc == GDEFCORE_OK) {
        rc = drop_draft_author(write, op);
      }
      changed = 1;
    } else {
      rc = seals_refuse(cs, &seals, gdefcore_ent_save_doc(cat, write, op->id.p,
          op->type_name.p, op->type_name.n, op->base_seq, &meta, &op->staged,
          &seals, &rev, &moved));
      if (rc == GDEFCORE_OK && moved) {
        *conflict = 1;
        return GDEFCORE_OK;
      }
      if (rc == GDEFCORE_OK && look.has_draft) {
        /* The save consumed the draft (stage_values()). */
        rc = map_stor(gdefstor_draft_delete(write, op->id.p, op->id.n));
        if (rc == GDEFCORE_OK) {
          rc = drop_draft_author(write, op);
        }
        changed = 1;
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = set_state(write, op, cs, 1, 0, when, &changed);
    }
    break;
  }
  case GDEFCORE_OP_DRAFT: {
    GDEFCORE_Seals seals;
    rc = seals_for(cs, op, 0, &seals);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    /* A draft is not a revision (AD-14): the values go in the draft, which
     * records the revision it is made from, and nothing else is written. */
    if (look.has_draft && look.draft_base != op->draft_base) {
      *conflict = 1;
      return GDEFCORE_OK;
    }
    rc = GDEFCORE_OK;
    if (!look.exists) {
      /* The first draft of an id its empty draft reserves is when the
       * entity is made, with the actor as its creator and no revision yet
       * (access SPEC decision 13), so that what an `own` grant asks of a
       * draft has an answer. The reservation gives way to the entity. */
      if (look.has_draft) {
        rc = map_stor(gdefstor_draft_delete(write, op->id.p, op->id.n));
      }
      if (rc == GDEFCORE_OK) {
        rc = map_stor(gdefstor_entity_create(write, op->type_name.p,
            op->type_name.n, op->id.p, op->id.n,
            cs->actor.p == NULL ? "" : cs->actor.p, cs->actor.n, when, NULL));
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = seals_refuse(cs, &seals, gdefcore_ent_put_draft(cat, write, op->id.p,
          op->type_name.p, op->type_name.n, look.exists ? op->draft_base : 0,
          &op->staged, &seals));
    }
    if (rc == GDEFCORE_OK) {
      rc = put_draft_author(write, cs, op);
    }
    changed = 1;
    break;
  }
  case GDEFCORE_OP_PUBLISH:
    if (look.has_draft) {
      /* Applied only on the revision it was made from (CAP-S4). */
      if (look.exists && look.draft_base != look.revision) {
        *conflict = 1;
        return GDEFCORE_OK;
      }
      {
        /* The revision is the draft's author's, not the publisher's (defect
         * 1.5.3): publishing does not make the publisher the author. */
        char who[GDEFCORE_PUBLIC_ID_LEN + 2];
        size_t who_len = 0;
        GDEFSTOR_RevisionMeta authored = meta;
        GDEFCORE_Seals seals;
        memset(&seals, 0, sizeof seals);
        rc = draft_author(cat, op, who, sizeof who, &who_len);
        if (rc != GDEFCORE_OK) {
          return rc;
        }
        authored.who = who;
        authored.who_len = who_len;
        /* Validated against the type as it is now, and applied as a save
         * of the draft's values on the revision it was made from: core
         * gives each changed personal value its blind-index MAC (the port's
         * draft apply takes none, story S6c), and refuses one of an erased
         * subject. */
        rc = draft_fits(cs, op);
        if (rc == GDEFCORE_OK) {
          rc = seals_for(cs, op, 1, &seals);
        }
        if (rc == GDEFCORE_OK && !look.exists) {
          rc = map_stor(gdefstor_draft_delete(write, op->id.p, op->id.n));
          if (rc == GDEFCORE_OK) {
            rc = map_stor(gdefstor_entity_create(write, op->type_name.p,
                op->type_name.n, op->id.p, op->id.n, who, who_len, when,
                NULL));
          }
        }
        if (rc == GDEFCORE_OK) {
          rc = seals_refuse(cs, &seals, gdefcore_ent_save_doc(cat, write,
              op->id.p, op->type_name.p, op->type_name.n, look.revision,
              &authored, &op->staged, &seals, &rev, &moved));
        }
        if (rc == GDEFCORE_OK && moved) {
          *conflict = 1;
          return GDEFCORE_OK;
        }
        if (rc == GDEFCORE_OK && look.exists) {
          rc = map_stor(gdefstor_draft_delete(write, op->id.p, op->id.n));
        }
      }
      if (rc == GDEFCORE_OK) {
        rc = drop_draft_author(write, op);
      }
      changed = 1;
    } else if (!look.exists || look.revision == 0) {
      rc = GDEFCORE_ERR_INVALID;
    }
    if (rc == GDEFCORE_OK) {
      rc = set_state(write, op, cs, 1, 0, when, &changed);
    }
    break;
  case GDEFCORE_OP_UNPUBLISH:
    if (look.exists) {
      rc = set_state(write, op, cs, 0, look.deleted, when, &changed);
    }
    break;
  case GDEFCORE_OP_CLEAR:
    /* A cleared entity is not published at a later time either. */
    rc = gdefcore_ent_job_drop(cat, write, op->id.p);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (look.exists) {
      rc = set_state(write, op, cs, 0, 1, when, &changed);
      if (rc == GDEFCORE_OK && look.has_draft) {
        rc = map_stor(gdefstor_draft_delete(write, op->id.p, op->id.n));
        if (rc == GDEFCORE_OK) {
          rc = drop_draft_author(write, op);
        }
        changed = 1;
      }
    } else if (look.reserved) {
      /* Nothing was saved: the reservation keeps the id and holds nothing. */
      GDEFCORE_Doc none;
      memset(&none, 0, sizeof none);
      rc = gdefcore_ent_put_draft(cat, write, op->id.p, op->type_name.p,
          op->type_name.n, 0, &none, NULL);
      changed = 1;
    }
    break;
  case GDEFCORE_OP_REVERT: {
    /* The port's revert (AD-14): a new revision whose rows copy the old
     * values; no old row is touched. A cleared entity is no longer deleted. */
    GDEFSTOR_Result src;
    if (!look.exists) {
      return GDEFCORE_ERR_INVALID;
    }
    src = gdefstor_entity_revert(write, op->id.p, op->id.n, op->base_seq,
        op->target_seq, &meta, &rev);
    if (src == GDEFSTOR_ERR_CONFLICT) {
      *conflict = 1;
      return GDEFCORE_OK;
    }
    rc = map_stor(src);
    if (rc == GDEFCORE_OK && look.deleted) {
      rc = set_state(write, op, cs, look.published, 0, when, &changed);
    }
    break;
  }
  default:
    return GDEFCORE_ERR_INTERNAL;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (rev > 0) {
    changed = 1;
  }
  op->written = rev;
  if (changed) {
    rc = gdefcore_ent_bump(write, op->id.p, NULL);
  }
  return rc;
}

GDEFCORE_Result gdefcore_changeset_apply(GDEFCORE_Changeset * changeset,
    const char * confirmation, size_t confirmation_len) {
  int risk = 0;
  uint64_t epoch = 0;
  uint64_t next_epoch = 0;
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc;
  size_t i;
  char * expect = NULL;
  size_t expect_len = 0;
  int conflict = 0;
  int64_t when;
  if (changeset == NULL || changeset->applied) {
    return GDEFCORE_ERR_INVALID;
  }
  /*
   * Who may edit a template is decided first, before the confirmation, the
   * conflict check or the validation can say anything about it: a principal
   * who may not edit gets the same answer whatever the template holds. A
   * changeset with no request is the operator's, and is not asked.
   */
  if (changeset->request != NULL) {
    rc = gdefcore_template_authorize(changeset, changeset->request);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
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
  /*
   * Templates are checked against the contract in force once the changeset's
   * module operations have been applied (AD-16: a failing template refuses the
   * changeset). This is the second check; the first is the preview.
   */
  rc = gdefcore_template_vet(changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
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
  /* The tenant's writes queue behind this one now: what is committed cannot
   * move until it commits, so this is the epoch it applies on. */
  rc = read_epoch(changeset->catalog, &epoch);
  if (rc == GDEFCORE_OK && epoch != changeset->epoch) {
    conflict = 1;
  }
  if (rc == GDEFCORE_OK && !conflict && changeset->job_key.p != NULL) {
    /* A scheduled publish: its job row is read again inside the write, so
     * that it is applied once, and not before its time (story S6c). */
    int claimed = 0;
    rc = gdefcore_ent_job_claim(changeset, &claimed);
    if (rc == GDEFCORE_OK && !claimed) {
      gdefstor_write_abort(write);
      if (changeset->catalog->host != NULL) {
        gdefcore_module_clear_pending(changeset->catalog->host);
      }
      return GDEFCORE_OK;
    }
  }
  when = now_ms(changeset);
  for (i = 0; rc == GDEFCORE_OK && !conflict && i < changeset->nops; i++) {
    GDEFCORE_Op * op = &changeset->ops[i];
    if (module_op_kind(op->kind)) {
      continue;
    }
    if (hooked_op(op->kind)) {
      rc = fire_named(changeset, op, GDEFCORE_HOOK_PRESAVE);
      if (rc == GDEFCORE_OK) {
        rc = fire_named(changeset, op, GDEFCORE_HOOK_VALIDATE);
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = apply_op(changeset, write, op, when, &conflict);
    }
    if (rc == GDEFCORE_OK && !conflict && revision_op(op->kind)) {
      rc = fire_named(changeset, op, GDEFCORE_HOOK_SAVE);
      if (rc == GDEFCORE_OK) {
        rc = fire_named(changeset, op, GDEFCORE_HOOK_REVISION);
      }
    }
    if (rc == GDEFCORE_OK && !conflict && op->kind == GDEFCORE_OP_CLEAR) {
      rc = fire_named(changeset, op, GDEFCORE_HOOK_DELETE);
    }
  }
  if (rc == GDEFCORE_OK && !conflict &&
      gdefcore_changeset_module_count(changeset) > 0) {
    rc = gdefcore_module_write_enables(changeset->catalog->host,
        changeset->catalog->tenant, changeset->catalog->tenant_len, write,
        changeset);
  }
  if (rc == GDEFCORE_OK && !conflict && changeset->job_key.p != NULL) {
    rc = gdefcore_ent_job_done(changeset, write);
  }
  if (rc == GDEFCORE_OK && !conflict) {
    /* The config epoch moves in the write that applies the changeset
     * (AD-31). An aborted write may leave a gap; only committed values
     * are compared. */
    rc = map_stor(gdefstor_counter_next(write, GDEFCORE_ENT_EPOCH,
        sizeof GDEFCORE_ENT_EPOCH - 1, &next_epoch));
  }
  if (rc != GDEFCORE_OK || conflict) {
    gdefstor_write_abort(write);
    if (changeset->catalog->host != NULL) {
      gdefcore_module_clear_pending(changeset->catalog->host);
    }
    for (i = 0; i < changeset->nops; i++) {
      changeset->ops[i].written = 0;
    }
    return rc != GDEFCORE_OK ? rc : name_list(changeset);
  }
  rc = map_stor(gdefstor_write_commit(write));
  if (rc != GDEFCORE_OK) {
    if (changeset->catalog->host != NULL) {
      gdefcore_module_clear_pending(changeset->catalog->host);
    }
    for (i = 0; i < changeset->nops; i++) {
      changeset->ops[i].written = 0;
    }
    return rc;
  }
  changeset->applied = 1;
  changeset->epoch = next_epoch;
  {
    GDEFCORE_Result grant_rc = gdefcore_access_commit_staged(changeset);
    GDEFCORE_Result first = grant_rc;
    {
      /* A kind this changeset defined has its edit permission as it exists. */
      GDEFCORE_Result declared = gdefcore_template_declare_touched(changeset);
      if (declared != GDEFCORE_OK && first == GDEFCORE_OK) {
        first = declared;
      }
    }
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
        if (hooked_op(op->kind)) {
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

GDEFCORE_Host * gdefcore_catalog_host(const GDEFCORE_Catalog * catalog) {
  return catalog == NULL ? NULL : catalog->host;
}

static int touch_op(int kind) {
  return kind == GDEFCORE_OP_SAVE || kind == GDEFCORE_OP_DRAFT ||
         kind == GDEFCORE_OP_PUBLISH || kind == GDEFCORE_OP_CLEAR ||
         kind == GDEFCORE_OP_UNPUBLISH || kind == GDEFCORE_OP_REVERT;
}

size_t gdefcore_changeset_touched_count(const GDEFCORE_Changeset * changeset) {
  size_t i;
  size_t n = 0;
  if (changeset == NULL) {
    return 0;
  }
  for (i = 0; i < changeset->nops; i++) {
    if (touch_op(changeset->ops[i].kind)) {
      n += 1;
    }
  }
  return n;
}

GDEFCORE_Result gdefcore_changeset_touched_at(
    const GDEFCORE_Changeset * changeset, size_t index, const char ** out_id,
    size_t * out_id_len, const char ** out_type, size_t * out_type_len,
    int * out_op) {
  size_t i;
  size_t seen = 0;
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < changeset->nops; i++) {
    const GDEFCORE_Op * op = &changeset->ops[i];
    if (!touch_op(op->kind)) {
      continue;
    }
    if (seen == index) {
      if (out_id != NULL) {
        *out_id = op->id.p;
      }
      if (out_id_len != NULL) {
        *out_id_len = op->id.n;
      }
      if (out_type != NULL) {
        *out_type = op->type_name.p;
      }
      if (out_type_len != NULL) {
        *out_type_len = op->type_name.n;
      }
      if (out_op != NULL) {
        /* A revert is a save of an earlier revision's content: it reports as
         * one, so that what reads the touched list for content (the template
         * vet) keeps seeing it. */
        *out_op = op->kind == GDEFCORE_OP_SAVE    ? GDEFCORE_TOUCH_SAVE
                  : op->kind == GDEFCORE_OP_REVERT ? GDEFCORE_TOUCH_SAVE
                  : op->kind == GDEFCORE_OP_DRAFT ? GDEFCORE_TOUCH_DRAFT
                  : op->kind == GDEFCORE_OP_PUBLISH ? GDEFCORE_TOUCH_PUBLISH
                  : op->kind == GDEFCORE_OP_UNPUBLISH
                      ? GDEFCORE_TOUCH_UNPUBLISH
                      : GDEFCORE_TOUCH_CLEAR;
      }
      return GDEFCORE_OK;
    }
    seen += 1;
  }
  return GDEFCORE_ERR_INVALID;
}

const char * gdefcore_changeset_refusal(const GDEFCORE_Changeset * changeset,
    size_t * out_len) {
  if (changeset == NULL || changeset->refusal.p == NULL) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = changeset->refusal.n;
  }
  return changeset->refusal.p;
}

GDEFCORE_Result gdefcore_changeset_set_refusal(GDEFCORE_Changeset * changeset,
    const char * text, size_t len) {
  if (changeset == NULL || (text == NULL && len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  text_clear(changeset->catalog->alloc, &changeset->refusal);
  if (text == NULL) {
    return GDEFCORE_OK;
  }
  return text_set(changeset->catalog->alloc, &changeset->refusal, text, len) ==
                 GDEFCORE_OK
      ? GDEFCORE_OK
      : GDEFCORE_ERR_OOM;
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
    GDEFCORE_Op * op = &changeset->ops[i];
    if (!op->have_row) {
      continue;
    }
    if (op->kind == GDEFCORE_OP_DEFINE) {
      rc = load_type(changeset->catalog, op->machine.p, op->machine.n, NULL,
          NULL, NULL, NULL, NULL, &op->base_seq);
    } else {
      GDEFCORE_EntLook look;
      rc = gdefcore_ent_lookup(changeset->catalog, op->id.p, &look);
      if (rc == GDEFCORE_OK) {
        op->base_seq = look.revision;
        op->reserved = look.reserved;
        op->draft_base = look.has_draft ? look.draft_base : look.revision;
      }
      if (rc == GDEFCORE_OK && op->have_ver) {
        rc = gdefcore_ent_version(changeset->catalog, op->id.p, &op->base_ver);
      }
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  text_clear(changeset->catalog->alloc, &changeset->conflict);
  text_clear(changeset->catalog->alloc, &changeset->refusal);
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

/*
 * A changeset that writes a copy of an earlier revision as the newest,
 * leaving the flag alone: the port's revert. With no explicit target it
 * restores the revision before the newest, and clears when the newest is the
 * first.
 */
static GDEFCORE_Result revert_changeset(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, int explicit_target, uint64_t target,
    const char * actor, size_t actor_len, GDEFCORE_Changeset ** out_changeset) {
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Op * op;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  Staging st;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_changeset == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_changeset_prepare(catalog, actor, actor_len, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = staging_load(catalog, canon, &st);
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(cs);
    return rc;
  }
  /* The legacy form needs a current revision to step back from; naming the
   * target does not (it is how a cleared entity is restored). */
  if (!st.look.exists || st.look.revision == 0 ||
      (!explicit_target && st.look.deleted) ||
      (explicit_target && (target == 0 || target > st.look.revision))) {
    staging_free(catalog, &st);
    gdefcore_changeset_destroy(cs);
    return GDEFCORE_ERR_INVALID;
  }
  rc = add_op(cs, &op);
  if (rc == GDEFCORE_OK) {
    rc = current_doc(catalog, canon, &st.look, &op->base);
  }
  if (rc == GDEFCORE_OK) {
    if (!explicit_target && st.look.revision <= 1) {
      op->kind = GDEFCORE_OP_CLEAR;
    } else {
      op->kind = GDEFCORE_OP_REVERT;
      op->target_seq = explicit_target ? target : st.look.revision - 1;
      rc = gdefcore_ent_read_doc(catalog, canon, op->target_seq, 0, &op->staged);
      if (rc == GDEFCORE_OK &&
          !doc_personal_sealed(&op->staged, st.decls, st.ndecls)) {
        rc = GDEFCORE_ERR_INVALID;
      }
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = op_from_staging(catalog, op, canon, &st);
  }
  staging_free(catalog, &st);
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(cs);
    return rc;
  }
  *out_changeset = cs;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_changeset_revert(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, const char * actor, size_t actor_len,
    GDEFCORE_Changeset ** out_changeset) {
  return revert_changeset(catalog, id, id_len, 0, 0, actor, actor_len,
      out_changeset);
}

GDEFCORE_Result gdefcore_changeset_revert_to(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, uint64_t seq, const char * actor,
    size_t actor_len, GDEFCORE_Changeset ** out_changeset) {
  return revert_changeset(catalog, id, id_len, 1, seq, actor, actor_len,
      out_changeset);
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

/*
 * A personal value in a patch is its sealed text and, beside it at
 * `entity/<id>/subject/<lang>/<field>/<index>`, its subject's public id (story
 * S6c: on the port a personal value is both). The subject is the note's, else
 * the one the entity's current tree or draft records with the text; a value
 * neither names is written without one, and the patch's apply refuses it.
 */
static GDEFCORE_Result subject_file(const GDEFCORE_Changeset * cs,
    const GDEFCORE_Op * op, const GDEFCORE_Lang * l, const GDEFCORE_Vals * f,
    size_t vi, const char * index, GDEFCORE_Patch ** files, size_t * count) {
  const GDEFCORE_Decl * decl = decl_named(op->decls, op->ndecls, f->name.p,
      f->name.n);
  const GDEFCORE_SealNote * note;
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char path[512];
  int found = 0;
  int kn;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (decl == NULL || !decl->personal) {
    return GDEFCORE_OK;
  }
  note = note_of(cs, f->vals[vi].p, f->vals[vi].n);
  if (note != NULL) {
    memcpy(sid, note->subject, sizeof sid);
    found = 1;
  } else {
    rc = gdefcore_ent_value_subject(cs->catalog, op->id.p, l->lang.p, l->lang.n,
        f->name.p, f->name.n, f->vals[vi].p, f->vals[vi].n, sid, &found);
  }
  if (rc != GDEFCORE_OK || !found) {
    return rc;
  }
  kn = snprintf(path, sizeof path, "entity/%.*s/subject/%.*s/%.*s/%s",
      (int)op->id.n, op->id.p, (int)l->lang.n, l->lang.p, (int)f->name.n,
      f->name.p, index);
  if (kn <= 0 || (size_t)kn >= sizeof path) {
    return GDEFCORE_ERR_LIMIT;
  }
  return patch_add(cs->catalog->alloc, files, count, path, sid,
      GDEFCORE_PUBLIC_ID_LEN);
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
    {
      /* The patch form has no file for a group or its items yet (story S6d
       * leaves it to the site-admin stories, with forms for groups): such a
       * changeset is refused, never written without them. */
      size_t k;
      for (k = 0; k < op->ndecls && op->kind == GDEFCORE_OP_DEFINE; k++) {
        if (!gdefcore_ent_decl_flat(&op->decls[k])) {
          rc = GDEFCORE_ERR_UNSUPPORTED;
        }
      }
      for (k = 0; k < op->staged.nlangs; k++) {
        if (gdefcore_tree_item_count(op->staged.langs[k].groups) > 1) {
          rc = GDEFCORE_ERR_UNSUPPORTED;
        }
      }
      if (rc != GDEFCORE_OK) {
        break;
      }
    }
    if (op->kind == GDEFCORE_OP_DEFINE) {
      /* `content` or `config`, and ` subjects` for a type whose entities
       * are subjects (story S7). */
      const char * kind = op->type_kind == GDEFCORE_TYPE_CONFIG
                              ? (op->type_subjects ? "config subjects"
                                                   : "config")
                              : (op->type_subjects ? "content subjects"
                                                   : "content");
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
        char flag[160];
        char personal[80];
        char scale[8];
        char * suffix = NULL;
        size_t suffix_len = 0;
        const char * tw = type_word(op->decls[f].type);
        int fn;
        /* The logical type, its scale and the index hint follow the shape
         * (story S6b): `optional one decimal 2 indexed`. A personal field
         * that takes its subject from a reference names it (story S7):
         * `optional one personal:who`. */
        scale[0] = '\0';
        if (op->decls[f].type == GDEFSTOR_FIELD_DECIMAL) {
          snprintf(scale, sizeof scale, " %d", op->decls[f].scale);
        }
        personal[0] = '\0';
        if (op->decls[f].personal && op->decls[f].subject.n > 0) {
          snprintf(personal, sizeof personal, " personal:%.*s",
              (int)op->decls[f].subject.n, op->decls[f].subject.p);
        } else if (op->decls[f].personal) {
          snprintf(personal, sizeof personal, " personal");
        }
        fn = snprintf(flag, sizeof flag, "%s%s%s%s%s%s", word, personal,
            tw != NULL ? " " : "", tw != NULL ? tw : "", scale,
            op->decls[f].indexed ? " indexed" : "");
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
    if (op->have_ver) {
      /* The version the op was staged against: a patch made against a
       * version the entity has since left is a conflict, as a stale base
       * sequence is. */
      char ver[32];
      size_t vn = 0;
      if (!u64_put(op->base_ver, ver, sizeof ver, &vn)) {
        rc = GDEFCORE_ERR_LIMIT;
        break;
      }
      kn = snprintf(path, sizeof path, "entity/%.*s/ver", (int)op->id.n,
          op->id.p);
      if (kn <= 0 || (size_t)kn >= sizeof path) {
        rc = GDEFCORE_ERR_LIMIT;
        break;
      }
      rc = patch_add(alloc, &files, &count, path, ver, vn);
      if (rc != GDEFCORE_OK) {
        break;
      }
    }
    if (op->kind == GDEFCORE_OP_REVERT) {
      /* A revert names the revision it copies. */
      char target[32];
      size_t tn = 0;
      if (!u64_put(op->target_seq, target, sizeof target, &tn)) {
        rc = GDEFCORE_ERR_LIMIT;
        break;
      }
      kn = snprintf(path, sizeof path, "entity/%.*s/target", (int)op->id.n,
          op->id.p);
      if (kn <= 0 || (size_t)kn >= sizeof path) {
        rc = GDEFCORE_ERR_LIMIT;
        break;
      }
      rc = patch_add(alloc, &files, &count, path, target, tn);
      if (rc != GDEFCORE_OK) {
        break;
      }
    }
    kn = snprintf(path, sizeof path, "entity/%.*s/op", (int)op->id.n, op->id.p);
    if (kn <= 0 || (size_t)kn >= sizeof path) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    if (op->kind == GDEFCORE_OP_CLEAR) {
      rc = patch_add(alloc, &files, &count, path, "clear", 5);
    } else if (op->kind == GDEFCORE_OP_UNPUBLISH) {
      rc = patch_add(alloc, &files, &count, path, "unpublish", 9);
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
      } else if (op->kind == GDEFCORE_OP_REVERT) {
        word = "revert";
        word_n = 6;
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
            if (rc == GDEFCORE_OK) {
              rc = subject_file(changeset, op, &op->staged.langs[li],
                  &op->staged.langs[li].fields[fi], vi, index, &files, &count);
            }
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

static const char * span_find(const char * s, size_t n, const char * w,
    size_t wn) {
  size_t i;
  for (i = 0; wn > 0 && i + wn <= n; i++) {
    if (memcmp(s + i, w, wn) == 0) {
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
                    span_eq(suffix, suffix_len, "/ver", 4) ||
                    span_eq(suffix, suffix_len, "/target", 7) ||
                    (suffix_len >= 6 && memcmp(suffix, "/lang/", 6) == 0) ||
                    (suffix_len >= 9 && memcmp(suffix, "/subject/", 9) == 0);
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
    /*
     * `type/<name>/kind` says what a type is. `type/<name>/field/kind` is a
     * field that happens to be called kind: the name between the slashes has
     * no slash in it, which tells them apart.
     */
    if (files[i].path_len >= 5 && memcmp(files[i].path, "type/", 5) == 0 &&
        files[i].path_len >= 10 &&
        memcmp(files[i].path + files[i].path_len - 5, "/kind", 5) == 0 &&
        memchr(files[i].path + 5, '/', files[i].path_len - 10) == NULL) {
      const char * name = files[i].path + 5;
      size_t name_len = files[i].path_len - 10;
      int kind;
      GDEFCORE_Field stack[64];
      size_t nfields = 0;
      size_t nsubjects = 0;
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
      } else if (span_eq((const char *)files[i].bytes, files[i].len,
                     "content subjects", 16)) {
        kind = GDEFCORE_TYPE_CONTENT | GDEFCORE_TYPE_SUBJECTS;
      } else if (span_eq((const char *)files[i].bytes, files[i].len,
                     "config subjects", 15)) {
        kind = GDEFCORE_TYPE_CONFIG | GDEFCORE_TYPE_SUBJECTS;
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
          int indexed = 0;
          int ftype = 0;
          int fscale = 0;
          const char * subject_at = NULL;
          size_t subject_len = 0;
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
          {
            /* Read back in the reverse of the order they are written. */
            size_t t;
            int scale = 0;
            indexed = strip_word(body, &body_len, "indexed");
            if (body_len > 2) {
              size_t sp = body_len;
              while (sp > 0 && body[sp - 1] >= '0' && body[sp - 1] <= '9') {
                sp -= 1;
              }
              if (sp < body_len && sp > 0 && body[sp - 1] == ' ' &&
                  body_len - sp <= 2) {
                size_t z;
                for (z = sp; z < body_len; z++) {
                  scale = scale * 10 + (body[z] - '0');
                }
                body_len = sp - 1;
                if (!strip_word(body, &body_len, "decimal")) {
                  gdefcore_changeset_destroy(cs);
                  return GDEFCORE_ERR_CORRUPT;
                }
                ftype = GDEFSTOR_FIELD_DECIMAL;
                fscale = scale;
              }
            }
            for (t = GDEFSTOR_FIELD_INTEGER; ftype == 0 && t <= GDEFSTOR_FIELD_REFERENCE;
                 t++) {
              if (t != GDEFSTOR_FIELD_DECIMAL && strip_word(body, &body_len, kTypeWords[t])) {
                ftype = (int)t;
              }
            }
          }
          if (body_len >= 9 && memcmp(body + body_len - 9, " personal", 9) == 0) {
            personal = 1;
            body_len -= 9;
          } else {
            /* ` personal:<reference>` (story S7): the subject source. */
            size_t at = body_len;
            while (at > 0 && body[at - 1] != ' ') {
              at -= 1;
            }
            if (at > 0 && body_len - at > 9 &&
                memcmp(body + at, "personal:", 9) == 0) {
              if (!field_name_ok((const char *)body + at + 9,
                      body_len - at - 9) ||
                  nsubjects >= 64) {
                size_t z;
                text_clear(catalog->alloc, &extra.pattern);
                for (z = 0; z < nfields; z++) {
                  gcu_allocator_free(catalog->alloc, (void *)stack[z].pattern);
                }
                gdefcore_changeset_destroy(cs);
                return GDEFCORE_ERR_CORRUPT;
              }
              personal = 1;
              subject_at = (const char *)body + at + 9;
              subject_len = body_len - at - 9;
              body_len = at - 1;
            }
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
          stack[nfields].type = ftype;
          stack[nfields].scale = fscale;
          stack[nfields].indexed = indexed;
          if (subject_at != NULL) {
            /* Borrowed from the patch file, which outlives the define. */
            stack[nfields].subject = subject_at;
            stack[nfields].subject_len = subject_len;
            nsubjects += 1;
          }
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
    const GDEFCORE_Patch * base_file;
    const GDEFCORE_Patch * ver_file;
    GDEFCORE_EntLook look;
    GDEFCORE_Op * op = NULL;
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
    rc = gdefcore_ent_lookup(catalog, canon, &look);
    if (rc != GDEFCORE_OK) {
      gdefcore_changeset_destroy(cs);
      return rc;
    }
    if (!span_eq((const char *)type_file->bytes, type_file->len, look.type,
            look.type_len)) {
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
    base_file = find_entity_tail(files, count, canon, "/base", 5);
    if (base_file == NULL) {
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (span_eq((const char *)files[i].bytes, files[i].len, "clear", 5) ||
        span_eq((const char *)files[i].bytes, files[i].len, "unpublish", 9)) {
      /* No values: the op is staged by the public call, so it takes the same
       * checks, then the patch's own base and version are put back on it. */
      rc = span_eq((const char *)files[i].bytes, files[i].len, "clear", 5)
          ? gdefcore_entity_clear(cs, canon, GDEFCORE_PUBLIC_ID_LEN)
          : gdefcore_entity_unpublish(cs, canon, GDEFCORE_PUBLIC_ID_LEN);
      op = rc == GDEFCORE_OK ? find_op_id(cs, canon, GDEFCORE_PUBLIC_ID_LEN)
                             : NULL;
      if (op == NULL) {
        gdefcore_changeset_destroy(cs);
        return rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_CORRUPT;
      }
    } else if (span_eq((const char *)files[i].bytes, files[i].len, "save", 4) ||
        span_eq((const char *)files[i].bytes, files[i].len, "draft", 5) ||
        span_eq((const char *)files[i].bytes, files[i].len, "publish", 7) ||
        span_eq((const char *)files[i].bytes, files[i].len, "revert", 6)) {
      int drafted = span_eq((const char *)files[i].bytes, files[i].len, "draft",
          5);
      int publishing =
          span_eq((const char *)files[i].bytes, files[i].len, "publish", 7);
      int reverting =
          span_eq((const char *)files[i].bytes, files[i].len, "revert", 6);
      cs->accept_sealed = 1;
      rc = stage_parsed_saves(cs, files, count, canon, &cap);
      cs->accept_sealed = 0;
      if (rc != GDEFCORE_OK) {
        gdefcore_changeset_destroy(cs);
        return rc;
      }
      op = find_op_id(cs, canon, GDEFCORE_PUBLIC_ID_LEN);
      if (op == NULL) {
        gdefcore_changeset_destroy(cs);
        return GDEFCORE_ERR_CORRUPT;
      }
      if (drafted) {
        op->kind = GDEFCORE_OP_DRAFT;
      } else if (publishing) {
        op->kind = GDEFCORE_OP_PUBLISH;
      } else if (reverting) {
        /* A revert names the revision it copies. */
        const GDEFCORE_Patch * target_file =
            find_entity_tail(files, count, canon, "/target", 7);
        if (target_file == NULL ||
            !u64_get((const char *)target_file->bytes, target_file->len,
                &op->target_seq) ||
            op->target_seq == 0) {
          gdefcore_changeset_destroy(cs);
          return GDEFCORE_ERR_CORRUPT;
        }
        op->kind = GDEFCORE_OP_REVERT;
      }
    } else {
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (!u64_get((const char *)base_file->bytes, base_file->len,
            &op->base_seq)) {
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
    ver_file = find_entity_tail(files, count, canon, "/ver", 4);
    if (ver_file != NULL &&
        !u64_get((const char *)ver_file->bytes, ver_file->len, &op->base_ver)) {
      gdefcore_changeset_destroy(cs);
      return GDEFCORE_ERR_CORRUPT;
    }
  }
  /* Whose each personal value is: a subject file names the value file of
   * the same language, field and index. A save of the patch opens the value
   * with that subject's key to index it, so a subject that is not the
   * value's is refused then. */
  for (i = 0; i < count; i++) {
    const char * at;
    size_t pre;
    char value_path[600];
    const GDEFCORE_Patch * value_file;
    int kn;
    if (files[i].path_len < 7 || memcmp(files[i].path, "entity/", 7) != 0) {
      continue;
    }
    at = files[i].path_len > 7 + GDEFCORE_PUBLIC_ID_LEN
             ? span_find(files[i].path, files[i].path_len, "/subject/", 9)
             : NULL;
    if (at == NULL) {
      continue;
    }
    pre = (size_t)(at - files[i].path);
    kn = snprintf(value_path, sizeof value_path, "%.*s/lang/%.*s", (int)pre,
        files[i].path, (int)(files[i].path_len - pre - 9), at + 9);
    value_file = kn > 0 && (size_t)kn < sizeof value_path
                     ? find_file(files, count, value_path)
                     : NULL;
    rc = value_file == NULL
             ? GDEFCORE_ERR_CORRUPT
             : note_add(cs, NULL, (const char *)value_file->bytes,
                   value_file->len, (const char *)files[i].bytes, files[i].len,
                   NULL);
    if (rc != GDEFCORE_OK) {
      gdefcore_changeset_destroy(cs);
      return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_CORRUPT;
    }
  }
  *out_changeset = cs;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_ids(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_name_len, char *** out_ids,
    size_t * out_count) {
  if (catalog == NULL || type_name == NULL || type_name_len == 0 ||
      out_ids == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_ids = NULL;
  *out_count = 0;
  if (builtin_name(type_name, type_name_len) ||
      !machine_ok(type_name, type_name_len)) {
    return GDEFCORE_OK;
  }
  return gdefcore_ent_ids(catalog, type_name, type_name_len, out_ids, out_count);
}

void gdefcore_catalog_limits(const GDEFCORE_Catalog * catalog,
    GDEFCORE_Limits * out) {
  if (catalog == NULL || out == NULL) {
    return;
  }
  *out = catalog->limits;
}

GDEFCORE_Result gdefcore_entity_query_current(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_name_len, const GDEFSTOR_Query * query,
    char *** out_ids, size_t * out_count, uint64_t * out_total) {
  GDEFSTOR_Query q;
  GDEFSTOR_Value no;
  GDEFSTOR_Value one;
  GDEFSTOR_QueryNode live;
  GDEFSTOR_QueryNode saved;
  GDEFSTOR_QueryNode both;
  const GDEFSTOR_QueryNode * kids[3];
  size_t nkids = 0;
  GDEFSTOR_QueryResult * result = NULL;
  GDEFSTOR_Type * type = NULL;
  GDEFSTOR_Result src;
  char ** ids = NULL;
  size_t n;
  size_t i;
  if (catalog == NULL || type_name == NULL || type_name_len == 0 ||
      query == NULL || query->size != sizeof q ||
      out_ids == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_ids = NULL;
  *out_count = 0;
  if (out_total != NULL) {
    *out_total = 0;
  }
  /* An unknown type is an empty list, not a refused query. */
  if (builtin_name(type_name, type_name_len) ||
      !machine_ok(type_name, type_name_len)) {
    return GDEFCORE_OK;
  }
  src = gdefstor_type_get(catalog->store, (const char *)catalog->tenant,
      catalog->tenant_len, type_name, type_name_len, &type);
  if (src == GDEFSTOR_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (src != GDEFSTOR_OK) {
    return map_stor(src);
  }
  gdefstor_type_free(type);
  /* The entities that are something now: saved, and not cleared. */
  memset(&no, 0, sizeof no);
  no.type = GDEFSTOR_FIELD_BOOLEAN;
  memset(&one, 0, sizeof one);
  one.type = GDEFSTOR_FIELD_INTEGER;
  one.integer = 1;
  memset(&live, 0, sizeof live);
  live.op = GDEFSTOR_QUERY_EQ;
  live.left.kind = GDEFSTOR_QUERY_META;
  live.left.meta = GDEFSTOR_META_DELETED;
  live.right.kind = GDEFSTOR_QUERY_VALUES;
  live.right.values = &no;
  live.right.value_count = 1;
  memset(&saved, 0, sizeof saved);
  saved.op = GDEFSTOR_QUERY_GE;
  saved.left.kind = GDEFSTOR_QUERY_META;
  saved.left.meta = GDEFSTOR_META_REVISION;
  saved.right.kind = GDEFSTOR_QUERY_VALUES;
  saved.right.values = &one;
  saved.right.value_count = 1;
  kids[nkids++] = &live;
  kids[nkids++] = &saved;
  if (query->where != NULL) {
    kids[nkids++] = query->where;
  }
  memset(&both, 0, sizeof both);
  both.op = GDEFSTOR_QUERY_AND;
  both.children = kids;
  both.child_count = nkids;
  q = *query;
  q.where = &both;
  if (q.language == NULL) {
    q.language = "en";
    q.language_len = 2;
  }
  src = gdefstor_entity_query(catalog->store, (const char *)catalog->tenant,
      catalog->tenant_len, type_name, type_name_len, &q, &result);
  if (src != GDEFSTOR_OK) {
    return map_stor(src);
  }
  n = gdefstor_query_result_rows(result);
  ids = (char **)mem0(catalog->alloc, (n == 0 ? 1 : n) * sizeof *ids);
  if (ids == NULL) {
    gdefstor_query_result_free(result);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    const char * e = NULL;
    size_t en = 0;
    if (gdefstor_query_result_entity(result, i, &e, &en) != GDEFSTOR_OK ||
        en != GDEFCORE_PUBLIC_ID_LEN) {
      gdefcore_ids_free(catalog, ids, i);
      gdefstor_query_result_free(result);
      return GDEFCORE_ERR_CORRUPT;
    }
    ids[i] = dup_span(catalog->alloc, e, en);
    if (ids[i] == NULL) {
      gdefcore_ids_free(catalog, ids, i);
      gdefstor_query_result_free(result);
      return GDEFCORE_ERR_OOM;
    }
  }
  if (out_total != NULL) {
    *out_total = gdefstor_query_result_total(result);
  }
  gdefstor_query_result_free(result);
  *out_ids = ids;
  *out_count = n;
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

/* The record of an entity, for the accessors below. */
static GDEFCORE_Result entity_record(GDEFCORE_Catalog * catalog, const char * id,
    size_t id_len, char canon[GDEFCORE_PUBLIC_ID_LEN + 1],
    GDEFCORE_EntLook * out) {
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_ent_lookup(catalog, canon, out);
}

GDEFCORE_Result gdefcore_entity_type(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_type, size_t * out_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_type == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = entity_record(catalog, id, id_len, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_type = dup_span(catalog->alloc, look.type, look.type_len);
  if (*out_type == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (out_len != NULL) {
    *out_len = look.type_len;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_actor(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_actor, size_t * out_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  size_t count = 0;
  uint64_t seq = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_actor == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_actor = NULL;
  if (out_len != NULL) {
    *out_len = 0;
  }
  rc = entity_record(catalog, id, id_len, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!look.exists || look.revision == 0 || look.deleted) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_ent_history(catalog, canon, &count, 0, NULL, NULL, NULL);
  if (rc != GDEFCORE_OK || count == 0) {
    return rc;
  }
  return gdefcore_ent_history(catalog, canon, NULL, count - 1, &seq, out_actor,
      out_len);
}

GDEFCORE_Result gdefcore_entity_creator(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_creator, size_t * out_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_creator == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_creator = NULL;
  if (out_len != NULL) {
    *out_len = 0;
  }
  rc = entity_record(catalog, id, id_len, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (look.creator_len > 0) {
    *out_creator = dup_span(catalog->alloc, look.creator, look.creator_len);
    if (*out_creator == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    if (out_len != NULL) {
      *out_len = look.creator_len;
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_state(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, int * out_state) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_state == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = entity_record(catalog, id, id_len, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_state = look.published && !look.deleted ? GDEFCORE_STATE_PUBLISHED
                                               : GDEFCORE_STATE_DRAFT;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_entity_version(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, uint64_t * out_version) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_version == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = entity_record(catalog, id, id_len, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return gdefcore_ent_version(catalog, canon, out_version);
}

GDEFCORE_Result gdefcore_entity_current_revision(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, int * out_has, uint64_t * out_seq) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_EntLook look;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_has == NULL || out_seq == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = entity_record(catalog, id, id_len, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_has = look.exists && look.revision > 0 && !look.deleted;
  *out_seq = *out_has ? look.revision : 0;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_changeset_set_why(GDEFCORE_Changeset * changeset,
    const char * why, size_t why_len) {
  if (changeset == NULL || changeset->applied || (why == NULL && why_len != 0) ||
      why_len > GDEFSTOR_MODEL_MAX_WHY_BYTES ||
      (why != NULL && !utf8_ok((const uint8_t *)why, why_len))) {
    return GDEFCORE_ERR_INVALID;
  }
  if (why == NULL) {
    text_clear(changeset->catalog->alloc, &changeset->why);
    return GDEFCORE_OK;
  }
  return text_set(changeset->catalog->alloc, &changeset->why, why, why_len);
}

GDEFCORE_Result gdefcore_changeset_revision(const GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, uint64_t * out_revision) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t i;
  if (changeset == NULL || out_revision == NULL || !changeset->applied ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < changeset->nops; i++) {
    const GDEFCORE_Op * op = &changeset->ops[i];
    if (op->kind != GDEFCORE_OP_DEFINE && op->id.p != NULL &&
        span_eq(op->id.p, op->id.n, canon, GDEFCORE_PUBLIC_ID_LEN)) {
      *out_revision = op->written;
      return GDEFCORE_OK;
    }
  }
  return GDEFCORE_ERR_INVALID;
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
