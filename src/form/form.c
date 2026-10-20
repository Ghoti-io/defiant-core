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
 * Forms, signed under the tenant keyring purpose `form`. A draft save
 * leaves what readers see alone. A path alias stays hidden until
 * that draft is published. Routes are a segment trie.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>

#include "form_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/regex/compile.h>
#include <ghoti.io/regex/exec.h>
#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
  kVersion = 1,
  kVersionSubject = 2,
  kAlg = 1,
  kKeyId = 1,
  kKey = 32,
  kNonce = 12,
  kTag = 16,
  kSalt = 32,
  kMaxFields = 64,
  kMaxValues = 32,
  kMaxValue = 4096,
  kMaxAlias = 1024,
  kMaxFormId = 256,
  kMaxPlain = 1 << 20
};

static const char kPurpose[] = "form";
static const char kAliasType[] = "core.alias";
static const char kTitle[] = "title";
/* A token with no subject is version 1 and its layout has not changed, so a
 * reader of it (the admin reads the form id, target and base at fixed
 * offsets) is not affected. A token with a subject is version 2: the same
 * layout with the subject's public id after the base, and in the associated
 * data. The version byte is not authenticated by itself; the associated data
 * differs between the two, so a token cannot change from one to the other. */

typedef struct FormField {
  char * name;
  size_t name_len;
  int required;
  int many;
  int personal;
  size_t min_len;
  size_t max_len;
  int has_range;
  int64_t range_min;
  int64_t range_max;
  char * pattern;
  size_t pattern_len;
  char ** texts;
  size_t * lens;
  size_t count;
  int own_texts;
} FormField;

struct GDEFCORE_Form {
  GDEFCORE_Catalog * catalog;
  FormField * fields;
  size_t nfields;
};

typedef struct Opened {
  uint64_t expiry;
  uint64_t base;
  char * form_id;
  size_t form_id_len;
  char target[GDEFCORE_PUBLIC_ID_LEN + 1];
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  int has_subject;
  char * lang;
  size_t lang_len;
  char * alias;
  size_t alias_len;
  FormField * fields;
  size_t nfields;
} Opened;

typedef struct Seg {
  char * text; /* a literal, or the capture name when named */
  size_t len;
  int wild;  /* matches any one segment: `*` or a named segment */
  int named; /* `:name`: wild, and captures under text */
} Seg;

typedef struct Route {
  char * machine;
  size_t machine_len;
  char * path;
  size_t path_len;
  int weight;
  int after;
  int score;
  size_t index;
  GDEFCORE_Route_Fn fn;
  GDEFCORE_Route_Call_Fn cfn;
  void * data;
  Seg * segs;
  size_t nsegs;
  char * permission;
  size_t permission_len;
  char * entity_capture;
  size_t entity_capture_len;
  char * title;
  size_t title_len;
  int kind;
  char * parent;
  size_t parent_len;
  int is_default;
  /* A default tab also answers its parent's path, and only exactly. */
  Seg * alt;
  size_t nalt;
  int alt_score;
} Route;

struct GDEFCORE_Routes {
  const GDEFCORE_Allocator * alloc;
  Route * routes;
  size_t nroutes;
  size_t cap;
  GDEFCORE_Route_Check_Fn check;
  void * check_data;
};

static GDEFCORE_Result from_gsec(GSEC_Result rc) {
  if (rc == GSEC_OK) {
    return GDEFCORE_OK;
  }
  if (rc == GSEC_ERR_LIMIT) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (rc == GSEC_ERR_IO) {
    return GDEFCORE_ERR_IO;
  }
  if (rc == GSEC_ERR_OOM) {
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_ERR_INVALID;
}

static void wipe(void * p, size_t n) {
  if (p != NULL && n > 0) {
    (void)gsec_wipe(p, n);
  }
}

static int now_u64(uint64_t * out) {
  time_t now = time(NULL);
  if (now < 0) {
    return 0;
  }
  *out = (uint64_t)now;
  return 1;
}

static void put_u16(uint8_t * p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static void put_u32(uint8_t * p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void put_u64(uint8_t * p, uint64_t v) {
  int i;
  for (i = 7; i >= 0; i--) {
    p[i] = (uint8_t)(v & 0xffu);
    v >>= 8;
  }
}

static uint16_t get_u16(const uint8_t * p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t * p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get_u64(const uint8_t * p) {
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; i++) {
    v = (v << 8) | p[i];
  }
  return v;
}

static GDEFCORE_Result cat_dup(GDEFCORE_Catalog * catalog, const void * text,
    size_t len, char ** out) {
  if (text == NULL && len != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_text_dup(catalog, text == NULL ? "" : (const char *)text, len,
      out);
}

static void * cat_zalloc(GDEFCORE_Catalog * catalog, size_t n) {
  const GDEFCORE_Allocator * def = gdefcore_allocator_default();
  char * scratch;
  char * copy = NULL;
  if (n == 0) {
    n = 1;
  }
  scratch = (char *)gcu_allocator_calloc(def, 1, n);
  if (scratch == NULL) {
    return NULL;
  }
  if (gdefcore_text_dup(catalog, scratch, n, &copy) != GDEFCORE_OK) {
    gcu_allocator_free(def, scratch);
    return NULL;
  }
  gcu_allocator_free(def, scratch);
  return copy;
}

static void fields_free(GDEFCORE_Catalog * catalog, FormField * fields,
    size_t n) {
  size_t i;
  size_t v;
  if (fields == NULL) {
    return;
  }
  for (i = 0; i < n; i++) {
    gdefcore_text_free(catalog, fields[i].name);
    gdefcore_text_free(catalog, fields[i].pattern);
    if (fields[i].own_texts) {
      if (fields[i].texts != NULL) {
        for (v = 0; v < fields[i].count; v++) {
          gdefcore_text_free(catalog, fields[i].texts[v]);
        }
        gdefcore_text_free(catalog, (char *)fields[i].texts);
      }
      if (fields[i].lens != NULL) {
        gdefcore_text_free(catalog, (char *)fields[i].lens);
      }
    }
  }
  gdefcore_text_free(catalog, (char *)fields);
}

static void opened_free(GDEFCORE_Catalog * catalog, Opened * opened) {
  if (opened == NULL) {
    return;
  }
  gdefcore_text_free(catalog, opened->form_id);
  gdefcore_text_free(catalog, opened->lang);
  gdefcore_text_free(catalog, opened->alias);
  fields_free(catalog, opened->fields, opened->nfields);
  memset(opened, 0, sizeof *opened);
}

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  if (an != bn) {
    return 0;
  }
  if (an == 0) {
    return 1;
  }
  return memcmp(a, b, an) == 0;
}

static int whole_i64(const char * text, size_t len, int64_t * out) {
  size_t i = 0;
  int neg = 0;
  uint64_t acc = 0;
  if (text == NULL || len == 0) {
    return 0;
  }
  if (text[0] == '-') {
    neg = 1;
    i = 1;
    if (len == 1) {
      return 0;
    }
  }
  for (; i < len; i++) {
    unsigned digit;
    if (text[i] < '0' || text[i] > '9') {
      return 0;
    }
    digit = (unsigned)(text[i] - '0');
    if (acc > (uint64_t)INT64_MAX / 10) {
      return 0;
    }
    acc = acc * 10u + digit;
  }
  if (!neg) {
    if (acc > (uint64_t)INT64_MAX) {
      return 0;
    }
    *out = (int64_t)acc;
    return 1;
  }
  if (acc > (uint64_t)INT64_MAX + 1u) {
    return 0;
  }
  if (acc == (uint64_t)INT64_MAX + 1u) {
    *out = INT64_MIN;
  } else {
    *out = -(int64_t)acc;
  }
  return 1;
}

static GDEFCORE_Result regex_rc(GRX_Result rr) {
  if (rr == GRX_ERR_OOM) {
    return GDEFCORE_ERR_OOM;
  }
  if (rr == GRX_ERR_LIMIT) {
    return GDEFCORE_ERR_LIMIT;
  }
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result pattern_whole(const char * pattern, size_t pattern_len,
    const char * text, size_t text_len) {
  GRX_Regex * re = NULL;
  GRX_Match * match = NULL;
  GRX_Capture span;
  GRX_Result rr;
  int matched = 0;
  if (pattern_len == 0) {
    return GDEFCORE_OK;
  }
  rr = grx_regex_compile_with_allocator(pattern, pattern_len,
      GRX_SYNTAX_ECMASCRIPT, GRX_OPT_NONE, NULL, NULL, NULL, &re);
  if (rr != GRX_OK) {
    return regex_rc(rr);
  }
  rr = grx_match_create(re, NULL, &match);
  if (rr != GRX_OK) {
    grx_regex_free(re);
    return regex_rc(rr);
  }
  rr = grx_regex_match(re, text, text_len, 0, GRX_ENGINE_AUTO, NULL, match,
      &matched);
  if (rr != GRX_OK) {
    grx_match_destroy(match);
    grx_regex_free(re);
    return regex_rc(rr);
  }
  if (!matched || grx_match_span(match, &span) != GRX_OK || span.start != 0 ||
      span.end != text_len) {
    grx_match_destroy(match);
    grx_regex_free(re);
    return GDEFCORE_ERR_INVALID;
  }
  grx_match_destroy(match);
  grx_regex_free(re);
  return GDEFCORE_OK;
}

static GDEFCORE_Result value_ok(const FormField * field, const char * text,
    size_t len) {
  int64_t number = 0;
  if (text == NULL && len != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (len > kMaxValue) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (field->min_len != 0 && len < field->min_len) {
    return GDEFCORE_ERR_INVALID;
  }
  if (field->max_len != 0 && len > field->max_len) {
    return GDEFCORE_ERR_INVALID;
  }
  if (field->has_range) {
    if (!whole_i64(text, len, &number) || number < field->range_min ||
        number > field->range_max) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  return pattern_whole(field->pattern, field->pattern_len, text, len);
}

static GDEFCORE_Result bind_values(FormField * fields, size_t nfields,
    const GDEFCORE_Value * values, size_t value_count) {
  size_t i;
  uint8_t seen[kMaxFields];
  if (nfields > kMaxFields || value_count > kMaxFields) {
    return GDEFCORE_ERR_LIMIT;
  }
  memset(seen, 0, sizeof seen);
  for (i = 0; i < value_count; i++) {
    size_t f;
    int found = 0;
    if (values[i].size < sizeof(GDEFCORE_Value) ||
        values[i].count > kMaxValues ||
        (values[i].texts == NULL && values[i].count != 0) ||
        (values[i].text_lens == NULL && values[i].count != 0)) {
      return GDEFCORE_ERR_INVALID;
    }
    for (f = 0; f < nfields; f++) {
      size_t v;
      GDEFCORE_Result rc;
      if (!span_eq(values[i].field, values[i].field_len, fields[f].name,
              fields[f].name_len)) {
        continue;
      }
      if (seen[f]) {
        return GDEFCORE_ERR_INVALID;
      }
      seen[f] = 1;
      found = 1;
      if ((!fields[f].many && values[i].count != 1) ||
          (fields[f].many && values[i].count == 0)) {
        return GDEFCORE_ERR_INVALID;
      }
      for (v = 0; v < values[i].count; v++) {
        rc = value_ok(&fields[f], values[i].texts[v], values[i].text_lens[v]);
        if (rc != GDEFCORE_OK) {
          return rc;
        }
      }
      if (fields[f].own_texts) {
        return GDEFCORE_ERR_INVALID;
      }
      fields[f].texts = (char **)values[i].texts;
      fields[f].lens = (size_t *)values[i].text_lens;
      fields[f].count = values[i].count;
      break;
    }
    if (!found) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  for (i = 0; i < nfields; i++) {
    if (fields[i].required && fields[i].count == 0) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result load_type_fields(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_len, FormField ** out, size_t * out_n) {
  size_t count = 0;
  size_t i;
  FormField * fields = NULL;
  GDEFCORE_Result rc = gdefcore_type_field_count(catalog, type_name, type_len,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count > kMaxFields) {
    return GDEFCORE_ERR_LIMIT;
  }
  fields = cat_zalloc(catalog, count * sizeof *fields);
  if (fields == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < count; i++) {
    rc = gdefcore_type_field(catalog, type_name, type_len, i, &fields[i].name,
        &fields[i].name_len, &fields[i].required, &fields[i].many);
    if (rc != GDEFCORE_OK) {
      fields_free(catalog, fields, i + 1);
      return rc;
    }
    rc = gdefcore_type_field_personal(catalog, type_name, type_len, i,
        &fields[i].personal);
    if (rc != GDEFCORE_OK) {
      fields_free(catalog, fields, i + 1);
      return rc;
    }
    rc = gdefcore_type_field_constraints(catalog, type_name, type_len, i,
        &fields[i].min_len, &fields[i].max_len, &fields[i].has_range,
        &fields[i].range_min, &fields[i].range_max, &fields[i].pattern,
        &fields[i].pattern_len);
    if (rc != GDEFCORE_OK) {
      fields_free(catalog, fields, i + 1);
      return rc;
    }
  }
  *out = fields;
  *out_n = count;
  return GDEFCORE_OK;
}

static void slug_of(const char * in, size_t n, char * out, size_t cap,
    size_t * out_n) {
  size_t i;
  size_t w = 0;
  int prev = 0;
  for (i = 0; i < n && w + 1 < cap; i++) {
    unsigned char c = (unsigned char)in[i];
    char o;
    if (c >= 'A' && c <= 'Z') {
      o = (char)(c - 'A' + 'a');
    } else if (c == ' ' || c == '_') {
      o = '-';
    } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
      o = (char)c;
    } else {
      continue;
    }
    if (o == '-' && prev) {
      continue;
    }
    out[w++] = o;
    prev = o == '-';
  }
  *out_n = w;
}

static GDEFCORE_Result choose_alias(const FormField * fields, size_t nfields,
    const char * alias, size_t alias_len, char ** out, size_t * out_len,
    GDEFCORE_Catalog * catalog) {
  char buf[kMaxAlias];
  size_t n = 0;
  size_t i;
  if (alias_len > kMaxAlias) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (alias_len > 0) {
    if (alias == NULL) {
      return GDEFCORE_ERR_INVALID;
    }
    *out_len = alias_len;
    return cat_dup(catalog, alias, alias_len, out);
  }
  for (i = 0; i < nfields; i++) {
    if (span_eq(fields[i].name, fields[i].name_len, kTitle, strlen(kTitle)) &&
        fields[i].count > 0 && fields[i].texts != NULL &&
        fields[i].texts[0] != NULL) {
      slug_of(fields[i].texts[0], fields[i].lens[0], buf, sizeof buf, &n);
      break;
    }
  }
  *out_len = n;
  if (n == 0) {
    *out = NULL;
    return GDEFCORE_OK;
  }
  return cat_dup(catalog, buf, n, out);
}

static GDEFCORE_Result principal_of(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len,
    const char ** out_principal, size_t * out_len, uint64_t * out_expiry) {
  const char * principal;
  size_t plen = 0;
  GDEFCORE_Result rc;
  if (session == NULL || session_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_account_check(catalog, request, keyring, root, root_len, session,
      session_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  principal = gdefcore_request_principal(request, &plen);
  if (principal == NULL || plen == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_account_session_expiry(catalog, keyring, root, root_len, session,
      session_len, out_expiry);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_principal = principal;
  *out_len = plen;
  return GDEFCORE_OK;
}

static size_t plain_size(const Opened * opened) {
  size_t n = 2 + opened->lang_len + 2 + opened->alias_len + 2;
  size_t i;
  size_t v;
  for (i = 0; i < opened->nfields; i++) {
    const FormField * f = &opened->fields[i];
    n += 2 + f->name_len + 4 + 8 + 8 + 8 + 8 + 2 + f->pattern_len + 2;
    for (v = 0; v < f->count; v++) {
      n += 4 + f->lens[v];
    }
  }
  return n;
}

static int put_bytes(uint8_t * p, size_t cap, size_t * at, const void * src,
    size_t n) {
  if (*at > cap || n > cap - *at) {
    return 0;
  }
  if (n > 0) {
    memcpy(p + *at, src, n);
  }
  *at += n;
  return 1;
}

static int put_u16_at(uint8_t * p, size_t cap, size_t * at, uint16_t v) {
  uint8_t b[2];
  put_u16(b, v);
  return put_bytes(p, cap, at, b, 2);
}

static int put_u32_at(uint8_t * p, size_t cap, size_t * at, uint32_t v) {
  uint8_t b[4];
  put_u32(b, v);
  return put_bytes(p, cap, at, b, 4);
}

static int put_u64_at(uint8_t * p, size_t cap, size_t * at, uint64_t v) {
  uint8_t b[8];
  put_u64(b, v);
  return put_bytes(p, cap, at, b, 8);
}

static GDEFCORE_Result write_plain(const Opened * opened, uint8_t * p,
    size_t cap, size_t * out_n) {
  size_t at = 0;
  size_t i;
  size_t v;
  if (opened->lang_len > 65535 || opened->alias_len > 65535 ||
      opened->nfields > 65535) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (!put_u16_at(p, cap, &at, (uint16_t)opened->lang_len) ||
      !put_bytes(p, cap, &at, opened->lang, opened->lang_len) ||
      !put_u16_at(p, cap, &at, (uint16_t)opened->alias_len) ||
      !put_bytes(p, cap, &at, opened->alias, opened->alias_len) ||
      !put_u16_at(p, cap, &at, (uint16_t)opened->nfields)) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < opened->nfields; i++) {
    const FormField * f = &opened->fields[i];
    uint8_t flags[4];
    if (f->name_len > 65535 || f->pattern_len > 65535 || f->count > 65535) {
      return GDEFCORE_ERR_LIMIT;
    }
    flags[0] = (uint8_t)(f->required ? 1 : 0);
    flags[1] = (uint8_t)(f->many ? 1 : 0);
    flags[2] = (uint8_t)(f->personal ? 1 : 0);
    flags[3] = (uint8_t)(f->has_range ? 1 : 0);
    if (!put_u16_at(p, cap, &at, (uint16_t)f->name_len) ||
        !put_bytes(p, cap, &at, f->name, f->name_len) ||
        !put_bytes(p, cap, &at, flags, 4) ||
        !put_u64_at(p, cap, &at, (uint64_t)f->min_len) ||
        !put_u64_at(p, cap, &at, (uint64_t)f->max_len) ||
        !put_u64_at(p, cap, &at, (uint64_t)f->range_min) ||
        !put_u64_at(p, cap, &at, (uint64_t)f->range_max) ||
        !put_u16_at(p, cap, &at, (uint16_t)f->pattern_len) ||
        !put_bytes(p, cap, &at, f->pattern, f->pattern_len) ||
        !put_u16_at(p, cap, &at, (uint16_t)f->count)) {
      return GDEFCORE_ERR_LIMIT;
    }
    for (v = 0; v < f->count; v++) {
      if (f->lens[v] > UINT32_MAX) {
        return GDEFCORE_ERR_LIMIT;
      }
      if (!put_u32_at(p, cap, &at, (uint32_t)f->lens[v]) ||
          !put_bytes(p, cap, &at, f->texts[v], f->lens[v])) {
        return GDEFCORE_ERR_LIMIT;
      }
    }
  }
  *out_n = at;
  return GDEFCORE_OK;
}

typedef struct Rdr {
  const uint8_t * p;
  size_t n;
  size_t i;
} Rdr;

static int take(Rdr * r, size_t n, const uint8_t ** out) {
  if (n > r->n - r->i) {
    return 0;
  }
  *out = r->p + r->i;
  r->i += n;
  return 1;
}

static GDEFCORE_Result read_plain(GDEFCORE_Catalog * catalog, const uint8_t * p,
    size_t n, Opened * opened) {
  Rdr r;
  const uint8_t * b;
  uint16_t nfields;
  uint16_t i;
  r.p = p;
  r.n = n;
  r.i = 0;
  if (!take(&r, 2, &b)) {
    return GDEFCORE_ERR_INVALID;
  }
  opened->lang_len = get_u16(b);
  if (!take(&r, opened->lang_len, &b)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (cat_dup(catalog, b, opened->lang_len, &opened->lang) != GDEFCORE_OK) {
    return GDEFCORE_ERR_OOM;
  }
  if (!take(&r, 2, &b)) {
    return GDEFCORE_ERR_INVALID;
  }
  opened->alias_len = get_u16(b);
  if (!take(&r, opened->alias_len, &b)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (opened->alias_len == 0) {
    opened->alias = NULL;
  } else if (cat_dup(catalog, b, opened->alias_len, &opened->alias) !=
             GDEFCORE_OK) {
    return GDEFCORE_ERR_OOM;
  }
  if (!take(&r, 2, &b)) {
    return GDEFCORE_ERR_INVALID;
  }
  nfields = get_u16(b);
  if (nfields > kMaxFields) {
    return GDEFCORE_ERR_LIMIT;
  }
  opened->fields = cat_zalloc(catalog, (size_t)nfields * sizeof *opened->fields);
  if (opened->fields == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  opened->nfields = nfields;
  for (i = 0; i < nfields; i++) {
    FormField * f = &opened->fields[i];
    uint16_t nvals;
    uint16_t v;
    if (!take(&r, 2, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    f->name_len = get_u16(b);
    if (!take(&r, f->name_len, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    {
      GDEFCORE_Result copied = cat_dup(catalog, b, f->name_len, &f->name);
      if (copied != GDEFCORE_OK) {
        return copied;
      }
    }
    if (!take(&r, 4, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    f->required = b[0] ? 1 : 0;
    f->many = b[1] ? 1 : 0;
    f->personal = b[2] ? 1 : 0;
    f->has_range = b[3] ? 1 : 0;
    if (!take(&r, 8, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    f->min_len = (size_t)get_u64(b);
    if (!take(&r, 8, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    f->max_len = (size_t)get_u64(b);
    if (!take(&r, 8, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    f->range_min = (int64_t)get_u64(b);
    if (!take(&r, 8, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    f->range_max = (int64_t)get_u64(b);
    if (!take(&r, 2, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    f->pattern_len = get_u16(b);
    if (!take(&r, f->pattern_len, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    if (f->pattern_len == 0) {
      f->pattern = NULL;
    } else if (cat_dup(catalog, b, f->pattern_len, &f->pattern) != GDEFCORE_OK) {
      return GDEFCORE_ERR_OOM;
    }
    if (!take(&r, 2, &b)) {
      return GDEFCORE_ERR_INVALID;
    }
    nvals = get_u16(b);
    if (nvals > kMaxValues) {
      return GDEFCORE_ERR_LIMIT;
    }
    f->count = nvals;
    if (nvals == 0) {
      continue;
    }
    f->texts = cat_zalloc(catalog, (size_t)nvals * sizeof *f->texts);
    f->lens = cat_zalloc(catalog, (size_t)nvals * sizeof *f->lens);
    if (f->texts == NULL || f->lens == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    f->own_texts = 1;
    for (v = 0; v < nvals; v++) {
      uint32_t vl;
      if (!take(&r, 4, &b)) {
        return GDEFCORE_ERR_INVALID;
      }
      vl = get_u32(b);
      if (!take(&r, vl, &b)) {
        return GDEFCORE_ERR_INVALID;
      }
      f->lens[v] = vl;
      if (cat_dup(catalog, b, vl, &f->texts[v]) != GDEFCORE_OK) {
        return GDEFCORE_ERR_OOM;
      }
    }
  }
  if (r.i != r.n) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result build_aad(GDEFCORE_Catalog * catalog,
    const char * session, size_t session_len, const char * principal,
    size_t principal_len, const char * form_id, size_t form_id_len,
    const char * target, uint64_t expiry, uint64_t base, const char * subject,
    uint8_t ** out, size_t * out_len) {
  const uint8_t * tenant = NULL;
  size_t tenant_len = 0;
  size_t n;
  size_t at = 0;
  uint8_t * aad = NULL;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  if (tenant == NULL || tenant_len > UINT32_MAX || session_len > UINT32_MAX ||
      principal_len > 65535 || form_id_len > 65535) {
    return GDEFCORE_ERR_INVALID;
  }
  n = 4 + tenant_len + strlen(kPurpose) + 1 + 8 + 4 + session_len + 2 +
      principal_len + 2 + form_id_len + GDEFCORE_PUBLIC_ID_LEN + 8 +
      (subject == NULL ? 0 : GDEFCORE_PUBLIC_ID_LEN);
  aad = cat_zalloc(catalog, n);
  if (aad == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (!put_u32_at(aad, n, &at, (uint32_t)tenant_len) ||
      !put_bytes(aad, n, &at, tenant, tenant_len) ||
      !put_bytes(aad, n, &at, kPurpose, strlen(kPurpose))) {
    gdefcore_text_free(catalog, (char *)aad);
    return GDEFCORE_ERR_LIMIT;
  }
  aad[at++] = kKeyId;
  if (!put_u64_at(aad, n, &at, expiry) ||
      !put_u32_at(aad, n, &at, (uint32_t)session_len) ||
      !put_bytes(aad, n, &at, session, session_len) ||
      !put_u16_at(aad, n, &at, (uint16_t)principal_len) ||
      !put_bytes(aad, n, &at, principal, principal_len) ||
      !put_u16_at(aad, n, &at, (uint16_t)form_id_len) ||
      !put_bytes(aad, n, &at, form_id, form_id_len) ||
      !put_bytes(aad, n, &at, target, GDEFCORE_PUBLIC_ID_LEN) ||
      !put_u64_at(aad, n, &at, base) ||
      (subject != NULL &&
          !put_bytes(aad, n, &at, subject, GDEFCORE_PUBLIC_ID_LEN)) ||
      at != n) {
    gdefcore_text_free(catalog, (char *)aad);
    return GDEFCORE_ERR_LIMIT;
  }
  *out = aad;
  *out_len = n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result purpose_key(GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, uint8_t out[kKey]) {
  return gdefcore_keyring_derive(keyring, root, root_len, kPurpose,
      strlen(kPurpose), out, kKey);
}

static GDEFCORE_Result seal(GDEFCORE_Catalog * catalog, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * principal, size_t principal_len,
    const Opened * opened, char ** out_token, size_t * out_token_len) {
  uint8_t form_key[kKey];
  uint8_t token_key[kKey];
  uint8_t salt[kSalt];
  uint8_t nonce[kNonce];
  uint8_t tag[kTag];
  uint8_t * plain = NULL;
  uint8_t * ct = NULL;
  uint8_t * aad = NULL;
  uint8_t * raw = NULL;
  size_t plain_n = 0;
  size_t aad_n = 0;
  size_t raw_n;
  size_t at = 0;
  GDEFCORE_Result rc;
  plain_n = plain_size(opened);
  if (plain_n > kMaxPlain || opened->form_id_len > 65535) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = purpose_key(keyring, root, root_len, form_key);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_gsec(gsec_random_bytes(salt, sizeof salt, NULL));
  if (rc != GDEFCORE_OK) {
    wipe(form_key, sizeof form_key);
    return rc;
  }
  rc = from_gsec(gsec_random_bytes(nonce, sizeof nonce, NULL));
  if (rc != GDEFCORE_OK) {
    wipe(form_key, sizeof form_key);
    return rc;
  }
  rc = from_gsec(gsec_hkdf(GSEC_HKDF_SHA256, salt, sizeof salt, form_key, kKey,
      NULL, 0, token_key, kKey));
  wipe(form_key, sizeof form_key);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  plain = cat_zalloc(catalog, plain_n);
  ct = cat_zalloc(catalog, plain_n);
  if (plain == NULL || ct == NULL) {
    wipe(token_key, sizeof token_key);
    gdefcore_text_free(catalog, (char *)plain);
    gdefcore_text_free(catalog, (char *)ct);
    return GDEFCORE_ERR_OOM;
  }
  rc = write_plain(opened, plain, plain_n, &plain_n);
  if (rc != GDEFCORE_OK) {
    wipe(token_key, sizeof token_key);
    gdefcore_text_free(catalog, (char *)plain);
    gdefcore_text_free(catalog, (char *)ct);
    return rc;
  }
  rc = build_aad(catalog, session, session_len, principal, principal_len,
      opened->form_id, opened->form_id_len, opened->target, opened->expiry,
      opened->base, opened->has_subject ? opened->subject : NULL, &aad, &aad_n);
  if (rc != GDEFCORE_OK) {
    wipe(token_key, sizeof token_key);
    gdefcore_text_free(catalog, (char *)plain);
    gdefcore_text_free(catalog, (char *)ct);
    return rc;
  }
  rc = from_gsec(gsec_aes_gcm_encrypt(token_key, kKey, nonce, sizeof nonce, aad,
      aad_n, plain, plain_n, ct, tag, kTag));
  wipe(token_key, sizeof token_key);
  wipe(plain, plain_n);
  gdefcore_text_free(catalog, (char *)plain);
  gdefcore_text_free(catalog, (char *)aad);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, (char *)ct);
    return rc;
  }
  raw_n = 4 + strlen(kPurpose) + 8 + 2 + opened->form_id_len +
          GDEFCORE_PUBLIC_ID_LEN + 8 +
          (opened->has_subject ? GDEFCORE_PUBLIC_ID_LEN : 0) + kSalt + kNonce + 4 + plain_n + kTag;
  raw = cat_zalloc(catalog, raw_n);
  if (raw == NULL) {
    gdefcore_text_free(catalog, (char *)ct);
    return GDEFCORE_ERR_OOM;
  }
  raw[at++] = opened->has_subject ? kVersionSubject : kVersion;
  raw[at++] = kAlg;
  raw[at++] = kKeyId;
  raw[at++] = (uint8_t)strlen(kPurpose);
  memcpy(raw + at, kPurpose, strlen(kPurpose));
  at += strlen(kPurpose);
  put_u64(raw + at, opened->expiry);
  at += 8;
  put_u16(raw + at, (uint16_t)opened->form_id_len);
  at += 2;
  memcpy(raw + at, opened->form_id, opened->form_id_len);
  at += opened->form_id_len;
  memcpy(raw + at, opened->target, GDEFCORE_PUBLIC_ID_LEN);
  at += GDEFCORE_PUBLIC_ID_LEN;
  put_u64(raw + at, opened->base);
  at += 8;
  if (opened->has_subject) {
    memcpy(raw + at, opened->subject, GDEFCORE_PUBLIC_ID_LEN);
    at += GDEFCORE_PUBLIC_ID_LEN;
  }
  memcpy(raw + at, salt, sizeof salt);
  at += sizeof salt;
  memcpy(raw + at, nonce, sizeof nonce);
  at += sizeof nonce;
  put_u32(raw + at, (uint32_t)plain_n);
  at += 4;
  memcpy(raw + at, ct, plain_n);
  at += plain_n;
  memcpy(raw + at, tag, kTag);
  at += kTag;
  gdefcore_text_free(catalog, (char *)ct);
  wipe(salt, sizeof salt);
  wipe(tag, sizeof tag);
  if (at != raw_n) {
    gdefcore_text_free(catalog, (char *)raw);
    return GDEFCORE_ERR_LIMIT;
  }
  *out_token = (char *)raw;
  *out_token_len = raw_n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result parse_clear(const char * token, size_t token_len,
    const uint8_t ** form_id, size_t * form_id_len, const uint8_t ** target,
    const uint8_t ** subject, uint64_t * expiry, uint64_t * base, const uint8_t ** salt,
    const uint8_t ** nonce, const uint8_t ** ct, uint32_t * ct_len,
    const uint8_t ** tag) {
  const uint8_t * raw;
  size_t purpose_len;
  size_t fid_len;
  size_t at;
  int has_subject;
  if (token == NULL || token_len < 4) {
    return GDEFCORE_ERR_INVALID;
  }
  raw = (const uint8_t *)token;
  if ((raw[0] != kVersion && raw[0] != kVersionSubject) || raw[1] != kAlg ||
      raw[2] != kKeyId) {
    return GDEFCORE_ERR_INVALID;
  }
  has_subject = raw[0] == kVersionSubject;
  *subject = NULL;
  purpose_len = raw[3];
  at = 4;
  if (purpose_len != strlen(kPurpose) || token_len < at + purpose_len ||
      memcmp(raw + at, kPurpose, purpose_len) != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  at += purpose_len;
  if (token_len < at + 8 + 2) {
    return GDEFCORE_ERR_INVALID;
  }
  *expiry = get_u64(raw + at);
  at += 8;
  fid_len = get_u16(raw + at);
  at += 2;
  if (fid_len == 0 || fid_len > kMaxFormId ||
      token_len < at + fid_len + GDEFCORE_PUBLIC_ID_LEN + 8 +
                      (has_subject ? GDEFCORE_PUBLIC_ID_LEN : 0) + kSalt +
                      kNonce + 4 + kTag) {
    return GDEFCORE_ERR_INVALID;
  }
  *form_id = raw + at;
  *form_id_len = fid_len;
  at += fid_len;
  *target = raw + at;
  at += GDEFCORE_PUBLIC_ID_LEN;
  *base = get_u64(raw + at);
  at += 8;
  if (has_subject) {
    *subject = raw + at;
    at += GDEFCORE_PUBLIC_ID_LEN;
  }
  *salt = raw + at;
  at += kSalt;
  *nonce = raw + at;
  at += kNonce;
  *ct_len = get_u32(raw + at);
  at += 4;
  if (*ct_len > kMaxPlain || token_len != at + *ct_len + kTag) {
    return GDEFCORE_ERR_INVALID;
  }
  *ct = raw + at;
  *tag = raw + at + *ct_len;
  return GDEFCORE_OK;
}

static GDEFCORE_Result open_token(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * session, size_t session_len, const char * principal,
    size_t principal_len, uint64_t session_expiry, const char * token,
    size_t token_len, Opened * opened) {
  const uint8_t * form_id = NULL;
  const uint8_t * target = NULL;
  const uint8_t * subject = NULL;
  const uint8_t * salt = NULL;
  const uint8_t * nonce = NULL;
  const uint8_t * ct = NULL;
  const uint8_t * tag = NULL;
  size_t form_id_len = 0;
  uint32_t ct_len = 0;
  uint64_t now = 0;
  uint8_t form_key[kKey];
  uint8_t token_key[kKey];
  uint8_t * plain = NULL;
  uint8_t * aad = NULL;
  size_t aad_n = 0;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  memset(opened, 0, sizeof *opened);
  rc = parse_clear(token, token_len, &form_id, &form_id_len, &target, &subject,
      &opened->expiry, &opened->base, &salt, &nonce, &ct, &ct_len, &tag);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!now_u64(&now) ) {
    return GDEFCORE_ERR_IO;
  }
  if (opened->expiry <= now || opened->expiry > session_expiry) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical((const char *)target, GDEFCORE_PUBLIC_ID_LEN,
          canon) != GDEFCORE_OK ||
      memcmp(canon, target, GDEFCORE_PUBLIC_ID_LEN) != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  memcpy(opened->target, canon, GDEFCORE_PUBLIC_ID_LEN + 1);
  if (subject != NULL) {
    char scanon[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (gdefcore_id_canonical((const char *)subject, GDEFCORE_PUBLIC_ID_LEN,
            scanon) != GDEFCORE_OK ||
        memcmp(scanon, subject, GDEFCORE_PUBLIC_ID_LEN) != 0) {
      return GDEFCORE_ERR_INVALID;
    }
    memcpy(opened->subject, scanon, GDEFCORE_PUBLIC_ID_LEN + 1);
    opened->has_subject = 1;
  }
  rc = purpose_key(keyring, root, root_len, form_key);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_gsec(gsec_hkdf(GSEC_HKDF_SHA256, salt, kSalt, form_key, kKey, NULL,
      0, token_key, kKey));
  wipe(form_key, sizeof form_key);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = build_aad(catalog, session, session_len, principal, principal_len,
      (const char *)form_id, form_id_len, opened->target, opened->expiry,
      opened->base, (const char *)subject, &aad, &aad_n);
  if (rc != GDEFCORE_OK) {
    wipe(token_key, sizeof token_key);
    return rc;
  }
  plain = cat_zalloc(catalog, ct_len == 0 ? 1 : ct_len);
  if (plain == NULL) {
    wipe(token_key, sizeof token_key);
    gdefcore_text_free(catalog, (char *)aad);
    return GDEFCORE_ERR_OOM;
  }
  rc = from_gsec(gsec_aes_gcm_decrypt(token_key, kKey, nonce, kNonce, aad, aad_n,
      ct, ct_len, plain, tag, kTag));
  wipe(token_key, sizeof token_key);
  gdefcore_text_free(catalog, (char *)aad);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, (char *)plain);
    return GDEFCORE_ERR_INVALID;
  }
  rc = cat_dup(catalog, form_id, form_id_len, &opened->form_id);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, (char *)plain);
    return rc;
  }
  opened->form_id_len = form_id_len;
  rc = read_plain(catalog, plain, ct_len, opened);
  wipe(plain, ct_len);
  gdefcore_text_free(catalog, (char *)plain);
  if (rc != GDEFCORE_OK) {
    opened_free(catalog, opened);
  }
  return rc;
}

static GDEFCORE_Result copy_field_shells(GDEFCORE_Catalog * catalog,
    const FormField * src, size_t n, FormField ** out) {
  size_t i;
  FormField * dst = NULL;
  GDEFCORE_Result rc;
  dst = cat_zalloc(catalog, n * sizeof *dst);
  if (dst == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    dst[i].required = src[i].required;
    dst[i].many = src[i].many;
    dst[i].personal = src[i].personal;
    dst[i].min_len = src[i].min_len;
    dst[i].max_len = src[i].max_len;
    dst[i].has_range = src[i].has_range;
    dst[i].range_min = src[i].range_min;
    dst[i].range_max = src[i].range_max;
    dst[i].name_len = src[i].name_len;
    dst[i].pattern_len = src[i].pattern_len;
    rc = cat_dup(catalog, src[i].name, src[i].name_len, &dst[i].name);
    if (rc != GDEFCORE_OK) {
      fields_free(catalog, dst, i + 1);
      return rc;
    }
    if (src[i].pattern_len > 0) {
      rc = cat_dup(catalog, src[i].pattern, src[i].pattern_len, &dst[i].pattern);
      if (rc != GDEFCORE_OK) {
        fields_free(catalog, dst, i + 1);
        return rc;
      }
    }
  }
  *out = dst;
  return GDEFCORE_OK;
}

static GDEFCORE_Result cap_expiry(uint64_t session_expiry, uint64_t * out) {
  uint64_t now = 0;
  uint64_t cap;
  if (!now_u64(&now)) {
    return GDEFCORE_ERR_IO;
  }
  if (session_expiry <= now) {
    return GDEFCORE_ERR_INVALID;
  }
  cap = now + GDEFCORE_FORM_LIFETIME;
  if (cap < now || cap > session_expiry) {
    cap = session_expiry;
  }
  *out = cap;
  return GDEFCORE_OK;
}

static GDEFCORE_Result fields_still_ok(const FormField * fields, size_t n) {
  size_t i;
  size_t v;
  for (i = 0; i < n; i++) {
    if (fields[i].required && fields[i].count == 0) {
      return GDEFCORE_ERR_INVALID;
    }
    for (v = 0; v < fields[i].count; v++) {
      GDEFCORE_Result rc = value_ok(&fields[i], fields[i].texts[v],
          fields[i].lens[v]);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
  }
  return GDEFCORE_OK;
}

void gdefcore_form_destroy(GDEFCORE_Form * form) {
  if (form == NULL) {
    return;
  }
  fields_free(form->catalog, form->fields, form->nfields);
  gdefcore_text_free(form->catalog, (char *)form);
}

size_t gdefcore_form_field_count(const GDEFCORE_Form * form) {
  if (form == NULL) {
    return 0;
  }
  return form->nfields;
}

GDEFCORE_Result gdefcore_form_field(const GDEFCORE_Form * form, size_t index,
    const char ** out_name, size_t * out_name_len, int * out_required,
    int * out_many, int * out_personal, size_t * out_min_len,
    size_t * out_max_len, int * out_has_range, int64_t * out_range_min,
    int64_t * out_range_max, const char ** out_pattern, size_t * out_pattern_len,
    const char * const ** out_texts, const size_t ** out_lens,
    size_t * out_count) {
  const FormField * f;
  if (form == NULL || index >= form->nfields) {
    return GDEFCORE_ERR_INVALID;
  }
  f = &form->fields[index];
  if (out_name != NULL) {
    *out_name = f->name;
  }
  if (out_name_len != NULL) {
    *out_name_len = f->name_len;
  }
  if (out_required != NULL) {
    *out_required = f->required;
  }
  if (out_many != NULL) {
    *out_many = f->many;
  }
  if (out_personal != NULL) {
    *out_personal = f->personal;
  }
  if (out_min_len != NULL) {
    *out_min_len = f->min_len;
  }
  if (out_max_len != NULL) {
    *out_max_len = f->max_len;
  }
  if (out_has_range != NULL) {
    *out_has_range = f->has_range;
  }
  if (out_range_min != NULL) {
    *out_range_min = f->range_min;
  }
  if (out_range_max != NULL) {
    *out_range_max = f->range_max;
  }
  if (out_pattern != NULL) {
    *out_pattern = f->pattern;
  }
  if (out_pattern_len != NULL) {
    *out_pattern_len = f->pattern_len;
  }
  if (out_texts != NULL) {
    *out_texts = (const char * const *)f->texts;
  }
  if (out_lens != NULL) {
    *out_lens = f->lens;
  }
  if (out_count != NULL) {
    *out_count = f->count;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result fill_current(GDEFCORE_Catalog * catalog, FormField * field,
    const char * id, size_t id_len, const char * lang, size_t lang_len) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  /* The draft where there is one, else what the entity currently is,
   * published or not: a form is for the people who edit, not for readers.
   * (The draft view falls back to the newest revision itself since story
   * S6b; it used to stop at a cleared head and this read what was then the
   * active revision, a pointer since retired.) */
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_DRAFT,
      id, id_len, lang, lang_len, field->name, field->name_len, &texts, &lens,
      &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count == 0) {
    gdefcore_values_free(catalog, texts, lens, count);
    return GDEFCORE_OK;
  }
  field->texts = texts;
  field->lens = lens;
  field->count = count;
  field->own_texts = 1;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_form_tree(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_len, const char * id, size_t id_len,
    const char * lang, size_t lang_len, GDEFCORE_Form ** out) {
  GDEFCORE_Form * form = NULL;
  GDEFCORE_Result rc;
  size_t i;
  if (catalog == NULL || out == NULL || type_name == NULL || type_len == 0 ||
      lang == NULL || lang_len == 0 || (id == NULL && id_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  form = cat_zalloc(catalog, sizeof *form);
  if (form == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  form->catalog = catalog;
  rc = load_type_fields(catalog, type_name, type_len, &form->fields,
      &form->nfields);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, (char *)form);
    return rc;
  }
  if (id != NULL && id_len != 0) {
    for (i = 0; i < form->nfields; i++) {
      rc = fill_current(catalog, &form->fields[i], id, id_len, lang, lang_len);
      if (rc != GDEFCORE_OK) {
        gdefcore_form_destroy(form);
        return rc;
      }
    }
  }
  *out = form;
  return GDEFCORE_OK;
}

static int form_lang_ok(const char * s, size_t n) {
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

/* Whether any personal field holds a value. */
static int personal_valued(const FormField * fields, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (fields[i].personal && fields[i].count > 0) {
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result sign_opened(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len,
    const char * form_id, size_t form_id_len, const char * target,
    size_t target_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count, const char * alias,
    size_t alias_len, int reuse_constraints, const FormField * prior,
    size_t prior_n, uint64_t prior_base, const char * subject,
    size_t subject_len, char ** out_token, size_t * out_token_len) {
  const char * principal = NULL;
  size_t principal_len = 0;
  uint64_t session_expiry = 0;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type_name = NULL;
  size_t type_len = 0;
  Opened opened;
  GDEFCORE_Result rc;
  memset(&opened, 0, sizeof opened);
  if (catalog == NULL || request == NULL || keyring == NULL || out_token == NULL ||
      out_token_len == NULL || form_id == NULL || form_id_len == 0 ||
      form_id_len > kMaxFormId || !form_lang_ok(lang, lang_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = principal_of(catalog, request, keyring, root, root_len, session,
      session_len, &principal, &principal_len, &session_expiry);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (gdefcore_id_canonical(target, target_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  memcpy(opened.target, canon, GDEFCORE_PUBLIC_ID_LEN + 1);
  if (subject != NULL) {
    char scanon[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (gdefcore_id_canonical(subject, subject_len, scanon) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INVALID;
    }
    memcpy(opened.subject, scanon, GDEFCORE_PUBLIC_ID_LEN + 1);
    opened.has_subject = 1;
  }
  rc = cap_expiry(session_expiry, &opened.expiry);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = cat_dup(catalog, form_id, form_id_len, &opened.form_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  opened.form_id_len = form_id_len;
  rc = cat_dup(catalog, lang, lang_len, &opened.lang);
  if (rc != GDEFCORE_OK) {
    opened_free(catalog, &opened);
    return rc;
  }
  opened.lang_len = lang_len;
  if (reuse_constraints) {
    opened.base = prior_base;
    rc = copy_field_shells(catalog, prior, prior_n, &opened.fields);
    opened.nfields = prior_n;
  } else {
    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type_name,
        &type_len);
    if (rc != GDEFCORE_OK) {
      opened_free(catalog, &opened);
      return rc;
    }
    /* The entity's version, which every write that touches it moves, a draft
     * included: a draft is not a revision (story S6b), and a form signed
     * before another draft must not overwrite it. */
    rc = gdefcore_entity_version(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        &opened.base);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, type_name);
      opened_free(catalog, &opened);
      return rc;
    }
    rc = load_type_fields(catalog, type_name, type_len, &opened.fields,
        &opened.nfields);
    gdefcore_text_free(catalog, type_name);
  }
  if (rc != GDEFCORE_OK) {
    opened_free(catalog, &opened);
    return rc;
  }
  rc = bind_values(opened.fields, opened.nfields, values, value_count);
  if (rc == GDEFCORE_OK && !opened.has_subject &&
      personal_valued(opened.fields, opened.nfields)) {
    /* A personal value needs a subject to be sealed for (AD-19). */
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc != GDEFCORE_OK) {
    opened_free(catalog, &opened);
    return rc;
  }
  if (reuse_constraints) {
    opened.alias_len = alias_len;
    if (alias_len > 0) {
      rc = cat_dup(catalog, alias, alias_len, &opened.alias);
    }
  } else {
    rc = choose_alias(opened.fields, opened.nfields, alias, alias_len,
        &opened.alias, &opened.alias_len, catalog);
  }
  if (rc != GDEFCORE_OK) {
    opened_free(catalog, &opened);
    return rc;
  }
  rc = seal(catalog, keyring, root, root_len, session, session_len, principal,
      principal_len, &opened, out_token, out_token_len);
  opened_free(catalog, &opened);
  return rc;
}

GDEFCORE_Result gdefcore_form_sign(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len,
    const char * form_id, size_t form_id_len, const char * target,
    size_t target_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count, const char * alias,
    size_t alias_len, char ** out_token, size_t * out_token_len) {
  return sign_opened(catalog, request, keyring, root, root_len, session,
      session_len, form_id, form_id_len, target, target_len, lang, lang_len,
      values, value_count, alias, alias_len, 0, NULL, 0, 0, NULL, 0, out_token,
      out_token_len);
}

GDEFCORE_Result gdefcore_form_sign_subject(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len,
    const char * form_id, size_t form_id_len, const char * target,
    size_t target_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count, const char * alias,
    size_t alias_len, const char * subject, size_t subject_len,
    char ** out_token, size_t * out_token_len) {
  if (subject == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return sign_opened(catalog, request, keyring, root, root_len, session,
      session_len, form_id, form_id_len, target, target_len, lang, lang_len,
      values, value_count, alias, alias_len, 0, NULL, 0, 0, subject,
      subject_len, out_token, out_token_len);
}

GDEFCORE_Result gdefcore_form_check(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len, const char * token,
    size_t token_len, uint64_t * out_expiry) {
  const char * principal = NULL;
  size_t principal_len = 0;
  uint64_t session_expiry = 0;
  Opened opened;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || keyring == NULL || token == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = principal_of(catalog, request, keyring, root, root_len, session,
      session_len, &principal, &principal_len, &session_expiry);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = open_token(catalog, keyring, root, root_len, session, session_len,
      principal, principal_len, session_expiry, token, token_len, &opened);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (out_expiry != NULL) {
    *out_expiry = opened.expiry;
  }
  opened_free(catalog, &opened);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_form_resign(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len, const char * token,
    size_t token_len, const GDEFCORE_Value * values, size_t value_count,
    char ** out_token, size_t * out_token_len) {
  const char * principal = NULL;
  size_t principal_len = 0;
  uint64_t session_expiry = 0;
  Opened opened;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || keyring == NULL || token == NULL ||
      out_token == NULL || out_token_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = principal_of(catalog, request, keyring, root, root_len, session,
      session_len, &principal, &principal_len, &session_expiry);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = open_token(catalog, keyring, root, root_len, session, session_len,
      principal, principal_len, session_expiry, token, token_len, &opened);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = sign_opened(catalog, request, keyring, root, root_len, session,
      session_len, opened.form_id, opened.form_id_len, opened.target,
      GDEFCORE_PUBLIC_ID_LEN, opened.lang, opened.lang_len, values, value_count,
      opened.alias, opened.alias_len, 1, opened.fields, opened.nfields,
      opened.base, opened.has_subject ? opened.subject : NULL,
      GDEFCORE_PUBLIC_ID_LEN, out_token, out_token_len);
  opened_free(catalog, &opened);
  return rc;
}

static GDEFCORE_Result ensure_alias_type(GDEFCORE_Catalog * catalog) {
  int kind = 0;
  GDEFCORE_Field fields[3];
  GDEFCORE_Result rc = gdefcore_type_kind(catalog, kAliasType, strlen(kAliasType),
      &kind);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  memset(fields, 0, sizeof fields);
  fields[0].size = sizeof fields[0];
  fields[0].name = "path";
  fields[0].name_len = 4;
  fields[0].required = 1;
  fields[1].size = sizeof fields[1];
  fields[1].name = "target";
  fields[1].name_len = 6;
  fields[1].required = 1;
  fields[2].size = sizeof fields[2];
  fields[2].name = "lang";
  fields[2].name_len = 4;
  fields[2].required = 1;
  return gdefcore_type_define(catalog, kAliasType, strlen(kAliasType),
      GDEFCORE_TYPE_CONTENT, fields, 3);
}

static GDEFCORE_Result alias_text(GDEFCORE_Catalog * catalog, const char * id,
    int published_only, const char * field, size_t field_len, char ** out,
    size_t * out_len) {
  int views[2];
  int nviews = 0;
  int i;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  if (!published_only) {
    views[nviews++] = GDEFCORE_VIEW_DRAFT;
  }
  views[nviews++] = GDEFCORE_VIEW_PUBLISHED;
  for (i = 0; i < nviews; i++) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    rc = gdefcore_entity_values(catalog, NULL, views[i], id, strlen(id), "en", 2,
        field, field_len, &texts, &lens, &n);
    if (rc == GDEFCORE_ERR_INVALID) {
      continue;
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (n != 1 || texts == NULL || texts[0] == NULL) {
      gdefcore_values_free(catalog, texts, lens, n);
      return GDEFCORE_ERR_INVALID;
    }
    *out_len = lens[0];
    rc = cat_dup(catalog, texts[0], lens[0], out);
    gdefcore_values_free(catalog, texts, lens, n);
    return rc;
  }
  return rc;
}

static GDEFCORE_Result find_alias(GDEFCORE_Catalog * catalog, const char * target,
    size_t target_len, int want_target, const char * path, size_t path_len,
    char ** out_id, char ** out_path, size_t * out_path_len) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kAliasType, strlen(kAliasType),
      &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char * got = NULL;
    size_t got_len = 0;
    rc = alias_text(catalog, ids[i], 0, want_target ? "target" : "path",
        want_target ? 6 : 4, &got, &got_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      continue;
    }
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (!span_eq(got, got_len, want_target ? target : path,
            want_target ? target_len : path_len)) {
      gdefcore_text_free(catalog, got);
      continue;
    }
    gdefcore_text_free(catalog, got);
    if (out_id != NULL) {
      rc = cat_dup(catalog, ids[i], strlen(ids[i]), out_id);
      if (rc != GDEFCORE_OK) {
        gdefcore_ids_free(catalog, ids, count);
        return rc;
      }
    }
    if (out_path != NULL) {
      rc = alias_text(catalog, ids[i], 0, "path", 4, out_path, out_path_len);
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    gdefcore_ids_free(catalog, ids, count);
    return GDEFCORE_OK;
  }
  gdefcore_ids_free(catalog, ids, count);
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result save_alias(GDEFCORE_Changeset * changeset,
    GDEFCORE_Catalog * catalog, const char * target, const char * path,
    size_t path_len, const char * lang, size_t lang_len, char ** io_id) {
  GDEFCORE_Value values[3];
  const char * texts0[1];
  const char * texts1[1];
  const char * texts2[1];
  size_t lens0[1];
  size_t lens1[1];
  size_t lens2[1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (*io_id == NULL) {
    rc = gdefcore_entity_create(catalog, kAliasType, strlen(kAliasType), id,
        NULL);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = cat_dup(catalog, id, GDEFCORE_PUBLIC_ID_LEN, io_id);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  memset(values, 0, sizeof values);
  texts0[0] = path;
  lens0[0] = path_len;
  texts1[0] = target;
  lens1[0] = GDEFCORE_PUBLIC_ID_LEN;
  texts2[0] = lang;
  lens2[0] = lang_len;
  values[0].size = sizeof values[0];
  values[0].field = "path";
  values[0].field_len = 4;
  values[0].texts = texts0;
  values[0].text_lens = lens0;
  values[0].count = 1;
  values[1].size = sizeof values[1];
  values[1].field = "target";
  values[1].field_len = 6;
  values[1].texts = texts1;
  values[1].text_lens = lens1;
  values[1].count = 1;
  values[2].size = sizeof values[2];
  values[2].field = "lang";
  values[2].field_len = 4;
  values[2].texts = texts2;
  values[2].text_lens = lens2;
  values[2].count = 1;
  rc = gdefcore_entity_save_draft(changeset, *io_id, strlen(*io_id), lang,
      lang_len, values, 3);
  if (rc != GDEFCORE_OK || span_eq(lang, lang_len, "en", 2)) {
    return rc;
  }
  return gdefcore_entity_save_draft(changeset, *io_id, strlen(*io_id), "en", 2,
      values, 3);
}

static GDEFCORE_Result values_from_fields(const FormField * fields, size_t n,
    GDEFCORE_Value ** out, size_t * out_n) {
  size_t i;
  size_t used = 0;
  GDEFCORE_Value * values;
  const GDEFCORE_Allocator * def = gdefcore_allocator_default();
  for (i = 0; i < n; i++) {
    if (fields[i].count > 0) {
      used += 1;
    }
  }
  values = (GDEFCORE_Value *)gcu_allocator_calloc(def, used == 0 ? 1 : used,
      sizeof *values);
  if (values == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  used = 0;
  for (i = 0; i < n; i++) {
    if (fields[i].count == 0) {
      continue;
    }
    values[used].size = sizeof values[used];
    values[used].field = fields[i].name;
    values[used].field_len = fields[i].name_len;
    values[used].texts = (const char * const *)fields[i].texts;
    values[used].text_lens = fields[i].lens;
    values[used].count = fields[i].count;
    used += 1;
  }
  *out = values;
  *out_n = used;
  return GDEFCORE_OK;
}

/* The personal values of a form, sealed for its subject. One sealed text per
 * personal field that holds a value; field[] indexes opened.fields. */
typedef struct Sealed {
  size_t nsealed;
  size_t field[kMaxFields];
  char * text[kMaxFields];
  size_t len[kMaxFields];
  uint8_t mac[kMaxFields][GDEFCORE_SUBJECT_MAC_LEN];
} Sealed;

static void sealed_free(GDEFCORE_Subjects * subjects, Sealed * sealed) {
  size_t i;
  for (i = 0; i < sealed->nsealed; i++) {
    gdefcore_subject_free(subjects, sealed->text[i]);
    sealed->text[i] = NULL;
  }
  sealed->nsealed = 0;
}

/* Seal every personal value under the form's subject. Nothing is written to
 * a store: a subject that is erased or unknown fails here, ahead of every
 * write. A many field has no sealed form (gdefcore_subject_save stores one
 * value per field), so it is refused. */
static GDEFCORE_Result seal_personal(GDEFCORE_Subjects * subjects,
    const Opened * opened, Sealed * sealed) {
  size_t i;
  memset(sealed, 0, sizeof *sealed);
  for (i = 0; i < opened->nfields; i++) {
    const FormField * f = &opened->fields[i];
    GDEFCORE_Result rc;
    if (!f->personal || f->count == 0) {
      continue;
    }
    if (f->many || f->count != 1) {
      sealed_free(subjects, sealed);
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_subject_seal(subjects, opened->subject, GDEFCORE_PUBLIC_ID_LEN,
        f->name, f->name_len, f->texts[0], f->lens[0],
        &sealed->text[sealed->nsealed], &sealed->len[sealed->nsealed],
        sealed->mac[sealed->nsealed]);
    if (rc != GDEFCORE_OK) {
      sealed_free(subjects, sealed);
      return rc;
    }
    sealed->field[sealed->nsealed] = i;
    sealed->nsealed += 1;
  }
  return GDEFCORE_OK;
}

/*
 * What a signed-form path asks before it writes (SPEC decisions 7 and 8). The
 * entity the question is about is the token's target, which the AEAD bound at
 * sign time with the session, the principal and the base version: it is not
 * a value a body can steer. The id the request itself names (a route capture,
 * a hidden field) is only checked against it; if they differ, the request is
 * not about one entity and is refused. The question is asked of the entity as
 * it is stored, before anything is staged, so no value in the token can
 * enter the condition; the token's values and the principal's own id are not
 * read here at all, and the actor of the revision this writes is the
 * request's, set later by gdefcore_changeset_prepare().
 */
typedef struct Guard {
  const char * action;
  size_t action_len;
  const char * claimed;
  size_t claimed_len;
  int * out_allowed;
} Guard;

static GDEFCORE_Result guard_decide(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const Opened * opened, const Guard * guard,
    int * out_allowed) {
  char * type = NULL;
  size_t type_len = 0;
  char claimed[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  *out_allowed = 0;
  if (guard->claimed != NULL) {
    if (gdefcore_id_canonical(guard->claimed, guard->claimed_len, claimed) !=
            GDEFCORE_OK ||
        memcmp(claimed, opened->target, GDEFCORE_PUBLIC_ID_LEN) != 0) {
      return GDEFCORE_OK;
    }
  }
  rc = gdefcore_entity_type(catalog, opened->target, GDEFCORE_PUBLIC_ID_LEN,
      &type, &type_len);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_access_can(catalog, request, guard->action, guard->action_len,
      type, type_len, opened->target, out_allowed);
  gdefcore_text_free(catalog, type);
  return rc;
}

static GDEFCORE_Result submit_impl(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len, const char * token,
    size_t token_len, GDEFCORE_Subjects * subjects, const Guard * guard,
    int * out_conflict) {
  const char * principal = NULL;
  size_t principal_len = 0;
  uint64_t session_expiry = 0;
  uint64_t current = 0;
  Opened opened;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Value * values = NULL;
  size_t nvalues = 0;
  char * alias_id = NULL;
  Sealed sealed;
  const char * sealed_texts[kMaxFields];
  const GDEFCORE_Allocator * def = gdefcore_allocator_default();
  GDEFCORE_Result rc;
  if (out_conflict != NULL) {
    *out_conflict = 0;
  }
  if (catalog == NULL || request == NULL || keyring == NULL || token == NULL ||
      token_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = principal_of(catalog, request, keyring, root, root_len, session,
      session_len, &principal, &principal_len, &session_expiry);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&opened, 0, sizeof opened);
  rc = open_token(catalog, keyring, root, root_len, session, session_len,
      principal, principal_len, session_expiry, token, token_len, &opened);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = fields_still_ok(opened.fields, opened.nfields);
  if (rc == GDEFCORE_OK && personal_valued(opened.fields, opened.nfields) &&
      (subjects == NULL || !opened.has_subject)) {
    /* The plain route does not seal, and a personal value is never stored
     * as text (AD-19): refuse before anything is written. */
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc != GDEFCORE_OK) {
    opened_free(catalog, &opened);
    return rc;
  }
  if (guard != NULL) {
    int allowed = 0;
    rc = guard_decide(catalog, request, &opened, guard, &allowed);
    *guard->out_allowed = rc == GDEFCORE_OK && allowed;
    if (rc != GDEFCORE_OK || !allowed) {
      /* Nothing has been staged, let alone written. */
      opened_free(catalog, &opened);
      return rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_INVALID;
    }
  }
  memset(&sealed, 0, sizeof sealed);
  rc = gdefcore_entity_version(catalog, opened.target, GDEFCORE_PUBLIC_ID_LEN,
      &current);
  if (rc != GDEFCORE_OK) {
    opened_free(catalog, &opened);
    return rc;
  }
  if (current != opened.base) {
    if (out_conflict != NULL) {
      *out_conflict = 1;
    }
    opened_free(catalog, &opened);
    return GDEFCORE_ERR_INVALID;
  }
  if (subjects != NULL) {
    rc = seal_personal(subjects, &opened, &sealed);
    if (rc != GDEFCORE_OK) {
      opened_free(catalog, &opened);
      return rc;
    }
  }
  rc = values_from_fields(opened.fields, opened.nfields, &values, &nvalues);
  if (rc != GDEFCORE_OK) {
    sealed_free(subjects, &sealed);
    opened_free(catalog, &opened);
    return rc;
  }
  {
    size_t k;
    for (k = 0; k < sealed.nsealed; k++) {
      size_t j;
      const FormField * f = &opened.fields[sealed.field[k]];
      sealed_texts[k] = sealed.text[k];
      for (j = 0; j < nvalues; j++) {
        if (span_eq(values[j].field, values[j].field_len, f->name,
                f->name_len)) {
          values[j].texts = &sealed_texts[k];
          values[j].text_lens = &sealed.len[k];
        }
      }
    }
  }
  if (opened.alias_len > 0) {
    rc = ensure_alias_type(catalog);
    if (rc != GDEFCORE_OK) {
      gcu_allocator_free(def, values);
      sealed_free(subjects, &sealed);
      opened_free(catalog, &opened);
      return rc;
    }
    rc = find_alias(catalog, opened.target, GDEFCORE_PUBLIC_ID_LEN, 1, NULL, 0,
        &alias_id, NULL, NULL);
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
    }
    if (rc != GDEFCORE_OK) {
      gcu_allocator_free(def, values);
      sealed_free(subjects, &sealed);
      opened_free(catalog, &opened);
      return rc;
    }
  }
  rc = gdefcore_changeset_prepare(catalog, principal, principal_len, &changeset);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, alias_id);
    gcu_allocator_free(def, values);
    sealed_free(subjects, &sealed);
    opened_free(catalog, &opened);
    return rc;
  }
  if (sealed.nsealed > 0) {
    rc = gdefcore_changeset_accept_sealed(changeset);
  }
  {
    /* Whose each sealed value is: the draft records it beside the ciphertext
     * (AD-14). A draft holds no blind-index value; publishing it gives one
     * (story S6c). */
    size_t k;
    for (k = 0; rc == GDEFCORE_OK && k < sealed.nsealed; k++) {
      rc = gdefcore_changeset_note_sealed(changeset, subjects, sealed.text[k],
          sealed.len[k], opened.subject, GDEFCORE_PUBLIC_ID_LEN, NULL);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_save_draft(changeset, opened.target,
        GDEFCORE_PUBLIC_ID_LEN, opened.lang, opened.lang_len, values, nvalues);
  }
  if (rc == GDEFCORE_OK && opened.alias_len > 0) {
    rc = save_alias(changeset, catalog, opened.target, opened.alias,
        opened.alias_len, opened.lang, opened.lang_len, &alias_id);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, NULL, 0);
    if (rc != GDEFCORE_OK && out_conflict != NULL) {
      size_t names_len = 0;
      if (gdefcore_changeset_conflict(changeset, &names_len) != NULL) {
        *out_conflict = 1;
      }
    }
  }
  gdefcore_changeset_destroy(changeset);
  gdefcore_text_free(catalog, alias_id);
  gcu_allocator_free(def, values);
  sealed_free(subjects, &sealed);
  opened_free(catalog, &opened);
  return rc;
}

GDEFCORE_Result gdefcore_form_submit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len, const char * token,
    size_t token_len, int * out_conflict) {
  return submit_impl(catalog, request, keyring, root, root_len, session,
      session_len, token, token_len, NULL, NULL, out_conflict);
}

GDEFCORE_Result gdefcore_form_submit_authorized(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len, const char * token,
    size_t token_len, const char * claimed, size_t claimed_len, int * out_allowed,
    int * out_conflict) {
  Guard guard;
  int allowed = 0;
  if (out_allowed != NULL) {
    *out_allowed = 0;
  }
  if (out_allowed == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  guard.action = GDEFCORE_ACTION_UPDATE;
  guard.action_len = sizeof GDEFCORE_ACTION_UPDATE - 1;
  guard.claimed = claimed;
  guard.claimed_len = claimed_len;
  guard.out_allowed = &allowed;
  {
    GDEFCORE_Result rc = submit_impl(catalog, request, keyring, root, root_len,
        session, session_len, token, token_len, NULL, &guard, out_conflict);
    *out_allowed = allowed;
    return rc;
  }
}

GDEFCORE_Result gdefcore_form_authorize(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len, const char * token,
    size_t token_len, const char * claimed, size_t claimed_len,
    const char * action, size_t action_len, int * out_allowed) {
  const char * principal = NULL;
  size_t principal_len = 0;
  uint64_t session_expiry = 0;
  Opened opened;
  Guard guard;
  GDEFCORE_Result rc;
  if (out_allowed != NULL) {
    *out_allowed = 0;
  }
  if (catalog == NULL || request == NULL || keyring == NULL || token == NULL ||
      token_len == 0 || action == NULL || action_len == 0 || out_allowed == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = principal_of(catalog, request, keyring, root, root_len, session,
      session_len, &principal, &principal_len, &session_expiry);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&opened, 0, sizeof opened);
  rc = open_token(catalog, keyring, root, root_len, session, session_len,
      principal, principal_len, session_expiry, token, token_len, &opened);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  guard.action = action;
  guard.action_len = action_len;
  guard.claimed = claimed;
  guard.claimed_len = claimed_len;
  guard.out_allowed = out_allowed;
  rc = guard_decide(catalog, request, &opened, &guard, out_allowed);
  opened_free(catalog, &opened);
  if (rc != GDEFCORE_OK) {
    *out_allowed = 0;
  }
  return rc;
}

GDEFCORE_Result gdefcore_form_submit_subject(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len, const char * token,
    size_t token_len, GDEFCORE_Subjects * subjects, int * out_conflict) {
  if (subjects == NULL) {
    if (out_conflict != NULL) {
      *out_conflict = 0;
    }
    return GDEFCORE_ERR_INVALID;
  }
  return submit_impl(catalog, request, keyring, root, root_len, session,
      session_len, token, token_len, subjects, NULL, out_conflict);
}

static GDEFCORE_Result published_field(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    char ** out_field, size_t * out_field_len, int * out_yes) {
  char * type_name = NULL;
  size_t type_len = 0;
  size_t nfields = 0;
  size_t i;
  GDEFCORE_Result rc;
  *out_yes = 0;
  if (out_field != NULL) {
    *out_field = NULL;
  }
  rc = gdefcore_entity_type(catalog, id, id_len, &type_name, &type_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_type_field_count(catalog, type_name, type_len, &nfields);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    return rc;
  }
  for (i = 0; i < nfields; i++) {
    char * field = NULL;
    size_t field_len = 0;
    int required = 0;
    int many = 0;
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    rc = gdefcore_type_field(catalog, type_name, type_len, i, &field, &field_len,
        &required, &many);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, type_name);
      return rc;
    }
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
        id_len, lang, lang_len, field, field_len, &texts, &lens, &count);
    if (rc == GDEFCORE_OK && count > 0) {
      gdefcore_values_free(catalog, texts, lens, count);
      gdefcore_text_free(catalog, type_name);
      *out_yes = 1;
      if (out_field != NULL) {
        *out_field = field;
        *out_field_len = field_len;
      } else {
        gdefcore_text_free(catalog, field);
      }
      return GDEFCORE_OK;
    }
    gdefcore_text_free(catalog, field);
    gdefcore_values_free(catalog, texts, lens, count);
    if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_INVALID) {
      gdefcore_text_free(catalog, type_name);
      return rc;
    }
  }
  gdefcore_text_free(catalog, type_name);
  return GDEFCORE_OK;
}

static GDEFCORE_Result suffix_alias(GDEFCORE_Catalog * catalog, const char * id,
    const char * path, size_t path_len) {
  uint8_t rnd[2];
  char next[kMaxAlias];
  char hex[5];
  static const char kHex[] = "0123456789abcdef";
  GDEFCORE_Changeset * changeset = NULL;
  char * alias_id = NULL;
  char * lang = NULL;
  size_t lang_len = 0;
  GDEFCORE_Result rc = from_gsec(gsec_random_bytes(rnd, sizeof rnd, NULL));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  hex[0] = kHex[rnd[0] >> 4];
  hex[1] = kHex[rnd[0] & 0x0f];
  hex[2] = kHex[rnd[1] >> 4];
  hex[3] = kHex[rnd[1] & 0x0f];
  hex[4] = '\0';
  if (path_len + 5 >= sizeof next) {
    return GDEFCORE_ERR_LIMIT;
  }
  memcpy(next, path, path_len);
  next[path_len] = '-';
  memcpy(next + path_len + 1, hex, 4);
  rc = find_alias(catalog, id, GDEFCORE_PUBLIC_ID_LEN, 1, NULL, 0, &alias_id,
      NULL, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = alias_text(catalog, alias_id, 0, "lang", 4, &lang, &lang_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, alias_id);
    return rc;
  }
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, lang);
    gdefcore_text_free(catalog, alias_id);
    return rc;
  }
  rc = save_alias(changeset, catalog, id, next, path_len + 5, lang, lang_len,
      &alias_id);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, NULL, 0);
  }
  gdefcore_changeset_destroy(changeset);
  gdefcore_text_free(catalog, lang);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, alias_id);
    return rc;
  }
  changeset = NULL;
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, alias_id);
    return rc;
  }
  rc = gdefcore_entity_publish(changeset, alias_id, strlen(alias_id));
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, NULL, 0);
  }
  gdefcore_changeset_destroy(changeset);
  gdefcore_text_free(catalog, alias_id);
  return rc;
}

static GDEFCORE_Result path_taken(GDEFCORE_Catalog * catalog, const char * self,
    const char * path, size_t path_len, int * out_taken) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kAliasType, strlen(kAliasType),
      &ids, &count);
  *out_taken = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count && !*out_taken; i++) {
    char * got = NULL;
    size_t got_len = 0;
    char * target = NULL;
    size_t target_len = 0;
    char * lang = NULL;
    size_t lang_len = 0;
    int yes = 0;
    rc = alias_text(catalog, ids[i], 1, "path", 4, &got, &got_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      continue;
    }
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (!span_eq(got, got_len, path, path_len)) {
      gdefcore_text_free(catalog, got);
      continue;
    }
    gdefcore_text_free(catalog, got);
    rc = alias_text(catalog, ids[i], 1, "target", 6, &target, &target_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      continue;
    }
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (span_eq(target, target_len, self, GDEFCORE_PUBLIC_ID_LEN)) {
      gdefcore_text_free(catalog, target);
      continue;
    }
    rc = alias_text(catalog, ids[i], 1, "lang", 4, &lang, &lang_len);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, target);
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    rc = published_field(catalog, target, target_len, lang, lang_len, NULL, NULL,
        &yes);
    gdefcore_text_free(catalog, target);
    gdefcore_text_free(catalog, lang);
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (yes) {
      *out_taken = 1;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_form_publish(GDEFCORE_Catalog * catalog, const char * id,
    size_t id_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * changeset = NULL;
  char * path = NULL;
  size_t path_len = 0;
  char * alias_id = NULL;
  int tries;
  int taken = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_publish(changeset, canon, GDEFCORE_PUBLIC_ID_LEN);
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(changeset);
    return rc;
  }
  rc = find_alias(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, 1, NULL, 0, &alias_id,
      &path, &path_len);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = gdefcore_changeset_apply(changeset, NULL, 0);
    gdefcore_changeset_destroy(changeset);
    return rc;
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(changeset);
    return rc;
  }
  rc = gdefcore_entity_publish(changeset, alias_id, strlen(alias_id));
  gdefcore_text_free(catalog, alias_id);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, NULL, 0);
  }
  gdefcore_changeset_destroy(changeset);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, path);
    return rc;
  }
  for (tries = 0; tries < 8; tries++) {
    char * old;
    size_t old_len;
    rc = path_taken(catalog, canon, path, path_len, &taken);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, path);
      return rc;
    }
    if (!taken) {
      break;
    }
    old = path;
    old_len = path_len;
    path = NULL;
    rc = suffix_alias(catalog, canon, old, old_len);
    gdefcore_text_free(catalog, old);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = find_alias(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, 1, NULL, 0, NULL,
        &path, &path_len);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  rc = path_taken(catalog, canon, path, path_len, &taken);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, path);
    return rc;
  }
  if (taken) {
    gdefcore_text_free(catalog, path);
    return GDEFCORE_ERR_LIMIT;
  }
  gdefcore_text_free(catalog, path);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_form_alias(GDEFCORE_Catalog * catalog, const char * id,
    size_t id_len, char ** out_path, size_t * out_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  if (catalog == NULL || out_path == NULL || out_len == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return find_alias(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, 1, NULL, 0, NULL,
      out_path, out_len);
}

static const GDEFCORE_Allocator * use_alloc(const GDEFCORE_Allocator * alloc) {
  return alloc == NULL ? gdefcore_allocator_default() : alloc;
}

static void seg_free(const GDEFCORE_Allocator * alloc, Seg * segs, size_t n) {
  size_t i;
  if (segs == NULL) {
    return;
  }
  for (i = 0; i < n; i++) {
    gcu_allocator_free(alloc, segs[i].text);
  }
  gcu_allocator_free(alloc, segs);
}

/* A pattern segment `:name` (named mode only) matches one segment and
 * captures it. `why` receives a reason when the pattern is refused. */
static int name_char_ok(char c, int first) {
  if (c >= 'a' && c <= 'z') {
    return 1;
  }
  return !first && ((c >= '0' && c <= '9') || c == '_');
}

static GDEFCORE_Result split_path(const GDEFCORE_Allocator * alloc,
    const char * path, size_t path_len, int named, Seg ** out, size_t * out_n,
    int * score, const char ** why) {
  size_t i = 0;
  size_t n = 0;
  size_t cap = 0;
  size_t ncaps = 0;
  Seg * segs = NULL;
  int exact = 0;
  if (path == NULL || path_len == 0 || path[0] != '/') {
    if (why != NULL) {
      *why = "path must start with /";
    }
    return GDEFCORE_ERR_INVALID;
  }
  while (i < path_len) {
    size_t start;
    size_t len;
    size_t k;
    Seg * next;
    int is_named;
    const char * reason = NULL;
    if (path[i] == '/') {
      i += 1;
      continue;
    }
    start = i;
    while (i < path_len && path[i] != '/') {
      i += 1;
    }
    len = i - start;
    is_named = named && path[start] == ':';
    if (is_named) {
      if (len == 1) {
        reason = "empty capture name";
      } else if (len - 1 > GDEFCORE_ROUTE_NAME_MAX) {
        reason = "capture name too long";
      } else {
        for (k = 1; k < len && reason == NULL; k++) {
          if (!name_char_ok(path[start + k], k == 1)) {
            reason = "capture name must be [a-z][a-z0-9_]*";
          }
        }
      }
      for (k = 0; k < n && reason == NULL; k++) {
        if (segs[k].named && span_eq(segs[k].text, segs[k].len, path + start + 1,
                                 len - 1)) {
          reason = "repeated capture name";
        }
      }
      if (reason == NULL && ncaps == GDEFCORE_ROUTE_CAPTURE_MAX) {
        reason = "too many captures";
      }
      if (reason != NULL) {
        seg_free(alloc, segs, n);
        if (why != NULL) {
          *why = reason;
        }
        return GDEFCORE_ERR_INVALID;
      }
      ncaps += 1;
    }
    if (n == cap) {
      cap = cap == 0 ? 4 : cap * 2;
      next = (Seg *)gcu_allocator_realloc(alloc, segs, cap * sizeof *segs);
      if (next == NULL) {
        seg_free(alloc, segs, n);
        return GDEFCORE_ERR_OOM;
      }
      segs = next;
    }
    if (is_named) {
      start += 1;
      len -= 1;
    }
    segs[n].len = len;
    segs[n].named = is_named;
    segs[n].wild = is_named || (len == 1 && path[start] == '*');
    segs[n].text = (char *)gcu_allocator_malloc(alloc, len == 0 ? 1 : len);
    if (segs[n].text == NULL) {
      seg_free(alloc, segs, n);
      return GDEFCORE_ERR_OOM;
    }
    memcpy(segs[n].text, path + start, len);
    if (!segs[n].wild) {
      exact += 1000000 / (int)(n + 1);
    }
    n += 1;
  }
  *out = segs;
  *out_n = n;
  if (score != NULL) {
    *score = exact;
  }
  return GDEFCORE_OK;
}

static int segs_match(const Seg * pat, size_t npat, const Seg * req) {
  size_t i;
  for (i = 0; i < npat; i++) {
    if (pat[i].wild) {
      continue;
    }
    if (!span_eq(pat[i].text, pat[i].len, req[i].text, req[i].len)) {
      return 0;
    }
  }
  return 1;
}

static int route_matches(const Route * route, const Seg * req, size_t nreq) {
  if (route->nsegs > nreq) {
    return 0;
  }
  return segs_match(route->segs, route->nsegs, req);
}

static void route_clear(const GDEFCORE_Allocator * alloc, Route * route) {
  gcu_allocator_free(alloc, route->machine);
  gcu_allocator_free(alloc, route->path);
  gcu_allocator_free(alloc, route->permission);
  gcu_allocator_free(alloc, route->entity_capture);
  gcu_allocator_free(alloc, route->title);
  gcu_allocator_free(alloc, route->parent);
  seg_free(alloc, route->segs, route->nsegs);
  seg_free(alloc, route->alt, route->nalt);
  memset(route, 0, sizeof *route);
}

GDEFCORE_Result gdefcore_routes_create(const GDEFCORE_Allocator * allocator,
    GDEFCORE_Routes ** out) {
  const GDEFCORE_Allocator * alloc = use_alloc(allocator);
  GDEFCORE_Routes * routes;
  if (out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  routes = (GDEFCORE_Routes *)gcu_allocator_calloc(alloc, 1, sizeof *routes);
  if (routes == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  routes->alloc = alloc;
  *out = routes;
  return GDEFCORE_OK;
}

void gdefcore_routes_destroy(GDEFCORE_Routes * routes) {
  size_t i;
  const GDEFCORE_Allocator * alloc;
  if (routes == NULL) {
    return;
  }
  alloc = routes->alloc;
  for (i = 0; i < routes->nroutes; i++) {
    route_clear(alloc, &routes->routes[i]);
  }
  gcu_allocator_free(alloc, routes->routes);
  gcu_allocator_free(alloc, routes);
}

void gdefcore_routes_free(GDEFCORE_Routes * routes, void * bytes) {
  if (routes == NULL) {
    return;
  }
  gcu_allocator_free(routes->alloc, bytes);
}

/* An error text "<what>: <machine> <path>; <machine> <path>" naming both
 * routes. Failure to allocate it is not a reason to change the answer. */
static void route_error(const GDEFCORE_Allocator * alloc, char ** out_error,
    size_t * out_error_len, const char * what, const char * m1, size_t m1_len,
    const char * p1, size_t p1_len, const char * m2, size_t m2_len,
    const char * p2, size_t p2_len) {
  size_t what_len = strlen(what);
  size_t n = what_len + 2 + m1_len + 1 + p1_len;
  size_t at;
  char * text;
  if (out_error == NULL) {
    return;
  }
  if (m2 != NULL) {
    n += 2 + m2_len + 1 + p2_len;
  }
  text = (char *)gcu_allocator_malloc(alloc, n + 1);
  if (text == NULL) {
    return;
  }
  memcpy(text, what, what_len);
  memcpy(text + what_len, ": ", 2);
  at = what_len + 2;
  memcpy(text + at, m1, m1_len);
  at += m1_len;
  text[at++] = ' ';
  memcpy(text + at, p1, p1_len);
  at += p1_len;
  if (m2 != NULL) {
    memcpy(text + at, "; ", 2);
    at += 2;
    memcpy(text + at, m2, m2_len);
    at += m2_len;
    text[at++] = ' ';
    memcpy(text + at, p2, p2_len);
    at += p2_len;
  }
  text[at] = '\0';
  *out_error = text;
  if (out_error_len != NULL) {
    *out_error_len = at;
  }
}

static const Route * route_find(const GDEFCORE_Routes * routes,
    const char * machine, size_t machine_len) {
  size_t i;
  for (i = 0; i < routes->nroutes; i++) {
    if (span_eq(routes->routes[i].machine, routes->routes[i].machine_len, machine,
            machine_len)) {
      return &routes->routes[i];
    }
  }
  return NULL;
}

/* Well-formed UTF-8 with no control character, no overlong form, no
 * surrogate and nothing above U+10FFFF. */
static int text_ok(const char * s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t more;
    uint32_t cp;
    uint32_t min;
    size_t k;
    if (c < 0x20 || c == 0x7f) {
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
      unsigned char d = (unsigned char)s[i + k];
      if ((d & 0xc0) != 0x80) {
        return 0;
      }
      cp = (cp << 6) | (d & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      return 0;
    }
    i += more + 1;
  }
  return 1;
}

static char * dup_span(const GDEFCORE_Allocator * alloc, const char * s,
    size_t n) {
  char * out = (char *)gcu_allocator_malloc(alloc, n + 1);
  if (out == NULL) {
    return NULL;
  }
  if (n > 0) {
    memcpy(out, s, n);
  }
  out[n] = '\0';
  return out;
}

static GDEFCORE_Result seg_copy(const GDEFCORE_Allocator * alloc, const Seg * from,
    size_t n, Seg ** out) {
  Seg * segs;
  size_t i;
  *out = NULL;
  if (n == 0) {
    return GDEFCORE_OK;
  }
  segs = (Seg *)gcu_allocator_calloc(alloc, n, sizeof *segs);
  if (segs == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    segs[i] = from[i];
    segs[i].text = (char *)gcu_allocator_malloc(alloc, from[i].len == 0 ? 1 : from[i].len);
    if (segs[i].text == NULL) {
      seg_free(alloc, segs, i);
      return GDEFCORE_ERR_OOM;
    }
    memcpy(segs[i].text, from[i].text, from[i].len);
  }
  *out = segs;
  return GDEFCORE_OK;
}

/* Whether the pattern has a named segment @p name. */
static int capture_in(const Seg * segs, size_t nsegs, const char * name,
    size_t name_len) {
  size_t i;
  for (i = 0; i < nsegs; i++) {
    if (segs[i].named && span_eq(segs[i].text, segs[i].len, name, name_len)) {
      return 1;
    }
  }
  return 0;
}

/* The one place a route is validated and added. `named` is non-zero for
 * gdefcore_route_add_spec(), which reads `:name`; the older call keeps `:`
 * literal. Nothing is changed on any error. */
static GDEFCORE_Result route_insert(GDEFCORE_Routes * routes,
    const GDEFCORE_Route_Spec * spec, int named, char ** out_error,
    size_t * out_error_len) {
  const GDEFCORE_Allocator * alloc = routes->alloc;
  const Route * old;
  const Route * parent = NULL;
  Route * next;
  Seg * segs = NULL;
  Seg * alt = NULL;
  size_t nsegs = 0;
  size_t i;
  size_t j;
  int score = 0;
  const char * why = NULL;
  GDEFCORE_Result rc;
  old = route_find(routes, spec->machine, spec->machine_len);
  if (old != NULL) {
    if (out_error != NULL) {
      /* The first line names the new route and the old path, the second the
       * new route and the new path, as it always has. */
      size_t n = spec->machine_len + 1 + old->path_len + 1 + spec->machine_len +
                 1 + spec->path_len;
      char * text = (char *)gcu_allocator_malloc(alloc, n + 1);
      size_t at = 0;
      if (text == NULL) {
        return GDEFCORE_ERR_OOM;
      }
      memcpy(text, spec->machine, spec->machine_len);
      at = spec->machine_len;
      text[at++] = ' ';
      memcpy(text + at, old->path, old->path_len);
      at += old->path_len;
      text[at++] = '\n';
      memcpy(text + at, spec->machine, spec->machine_len);
      at += spec->machine_len;
      text[at++] = ' ';
      memcpy(text + at, spec->path, spec->path_len);
      text[n] = '\0';
      *out_error = text;
      if (out_error_len != NULL) {
        *out_error_len = n;
      }
    }
    return GDEFCORE_ERR_INVALID;
  }
  if (named && spec->path_len > GDEFCORE_ROUTE_PATH_MAX) {
    route_error(alloc, out_error, out_error_len, "path too long", spec->machine,
        spec->machine_len, "(path)", 6, NULL, 0, NULL, 0);
    return GDEFCORE_ERR_INVALID;
  }
  rc = split_path(alloc, spec->path, spec->path_len, named, &segs, &nsegs, &score,
      &why);
  if (rc != GDEFCORE_OK) {
    if (why != NULL) {
      route_error(alloc, out_error, out_error_len, why, spec->machine,
          spec->machine_len, spec->path, spec->path_len, NULL, 0, NULL, 0);
    }
    return rc;
  }
  why = NULL;
  if (spec->kind != GDEFCORE_ROUTE_PAGE && spec->kind != GDEFCORE_ROUTE_TAB &&
      spec->kind != GDEFCORE_ROUTE_ACTION) {
    why = "unknown route kind";
  } else if (spec->title_len > GDEFCORE_ROUTE_TITLE_MAX ||
             (spec->title_len > 0 &&
                 (spec->title == NULL || !text_ok(spec->title, spec->title_len)))) {
    why = "title is not UTF-8 text of at most 256 bytes";
  } else if (spec->permission_len > GDEFCORE_ROUTE_PERMISSION_MAX ||
             (spec->permission_len > 0 &&
                 (spec->permission == NULL ||
                     !text_ok(spec->permission, spec->permission_len)))) {
    why = "permission is not text of at most 256 bytes";
  } else if (spec->entity_capture_len > 0 &&
             (spec->entity_capture == NULL ||
                 !capture_in(segs, nsegs, spec->entity_capture,
                     spec->entity_capture_len))) {
    why = "entity capture names no capture of the pattern";
  } else if (spec->is_default && spec->kind != GDEFCORE_ROUTE_TAB) {
    why = "only a tab can be the default";
  } else if (spec->kind != GDEFCORE_ROUTE_TAB && spec->parent_len > 0) {
    why = "only a tab has a parent";
  } else if (spec->kind == GDEFCORE_ROUTE_TAB &&
             (spec->parent == NULL || spec->parent_len == 0)) {
    why = "a tab needs a parent";
  }
  if (why != NULL) {
    route_error(alloc, out_error, out_error_len, why, spec->machine,
        spec->machine_len, spec->path, spec->path_len, NULL, 0, NULL, 0);
    seg_free(alloc, segs, nsegs);
    return GDEFCORE_ERR_INVALID;
  }
  if (spec->kind == GDEFCORE_ROUTE_TAB) {
    parent = route_find(routes, spec->parent, spec->parent_len);
    if (parent == NULL) {
      route_error(alloc, out_error, out_error_len, "tab has no parent route",
          spec->machine, spec->machine_len, spec->path, spec->path_len,
          spec->parent, spec->parent_len, "(not registered)", 16);
      seg_free(alloc, segs, nsegs);
      return GDEFCORE_ERR_INVALID;
    }
    if (spec->is_default) {
      for (i = 0; i < routes->nroutes; i++) {
        const Route * r = &routes->routes[i];
        if (r->is_default && span_eq(r->parent, r->parent_len, spec->parent,
                                 spec->parent_len)) {
          route_error(alloc, out_error, out_error_len,
              "second default tab for one parent", spec->machine,
              spec->machine_len, spec->path, spec->path_len, r->machine,
              r->machine_len, r->path, r->path_len);
          seg_free(alloc, segs, nsegs);
          return GDEFCORE_ERR_INVALID;
        }
      }
      for (i = 0; i < nsegs; i++) {
        int found = 0;
        if (!segs[i].named) {
          continue;
        }
        for (j = 0; j < parent->nsegs; j++) {
          if (parent->segs[j].named &&
              span_eq(parent->segs[j].text, parent->segs[j].len, segs[i].text,
                  segs[i].len)) {
            found = 1;
          }
        }
        if (!found) {
          route_error(alloc, out_error, out_error_len,
              "default tab captures a name its parent does not", spec->machine,
              spec->machine_len, spec->path, spec->path_len, parent->machine,
              parent->machine_len, parent->path, parent->path_len);
          seg_free(alloc, segs, nsegs);
          return GDEFCORE_ERR_INVALID;
        }
      }
      rc = seg_copy(alloc, parent->segs, parent->nsegs, &alt);
      if (rc != GDEFCORE_OK) {
        seg_free(alloc, segs, nsegs);
        return rc;
      }
    }
  }
  if (routes->nroutes == routes->cap) {
    size_t cap = routes->cap == 0 ? 4 : routes->cap * 2;
    next = (Route *)gcu_allocator_realloc(alloc, routes->routes,
        cap * sizeof *next);
    if (next == NULL) {
      seg_free(alloc, segs, nsegs);
      seg_free(alloc, alt, parent != NULL ? parent->nsegs : 0);
      return GDEFCORE_ERR_OOM;
    }
    routes->routes = next;
    routes->cap = cap;
    if (parent != NULL) {
      /* The table moved. */
      parent = route_find(routes, spec->parent, spec->parent_len);
    }
  }
  next = &routes->routes[routes->nroutes];
  memset(next, 0, sizeof *next);
  next->machine = dup_span(alloc, spec->machine, spec->machine_len);
  next->path = dup_span(alloc, spec->path, spec->path_len);
  next->permission = dup_span(alloc, spec->permission, spec->permission_len);
  next->title = dup_span(alloc, spec->title, spec->title_len);
  next->parent = dup_span(alloc, spec->parent, spec->parent_len);
  next->entity_capture =
      dup_span(alloc, spec->entity_capture, spec->entity_capture_len);
  if (next->machine == NULL || next->path == NULL || next->permission == NULL ||
      next->title == NULL || next->parent == NULL ||
      next->entity_capture == NULL) {
    seg_free(alloc, segs, nsegs);
    seg_free(alloc, alt, parent != NULL ? parent->nsegs : 0);
    gcu_allocator_free(alloc, next->machine);
    gcu_allocator_free(alloc, next->path);
    gcu_allocator_free(alloc, next->permission);
    gcu_allocator_free(alloc, next->title);
    gcu_allocator_free(alloc, next->parent);
    gcu_allocator_free(alloc, next->entity_capture);
    memset(next, 0, sizeof *next);
    return GDEFCORE_ERR_OOM;
  }
  next->machine_len = spec->machine_len;
  next->path_len = spec->path_len;
  next->permission_len = spec->permission_len;
  next->title_len = spec->title_len;
  next->parent_len = spec->parent_len;
  next->entity_capture_len = spec->entity_capture_len;
  next->weight = spec->weight;
  next->after = spec->after ? 1 : 0;
  next->score = score;
  next->index = routes->nroutes;
  next->fn = spec->fn;
  next->cfn = spec->call_fn;
  next->data = spec->data;
  next->segs = segs;
  next->nsegs = nsegs;
  next->kind = spec->kind;
  next->is_default = spec->is_default ? 1 : 0;
  if (alt != NULL) {
    next->alt = alt;
    next->nalt = parent->nsegs;
    next->alt_score = parent->score + 1;
  }
  routes->nroutes += 1;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_route_add(GDEFCORE_Routes * routes, const char * machine,
    size_t machine_len, const char * path, size_t path_len, int weight, int after,
    GDEFCORE_Route_Fn fn, void * data, char ** out_error, size_t * out_error_len) {
  GDEFCORE_Route_Spec spec;
  if (out_error != NULL) {
    *out_error = NULL;
  }
  if (out_error_len != NULL) {
    *out_error_len = 0;
  }
  if (routes == NULL || fn == NULL || machine == NULL || machine_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&spec, 0, sizeof spec);
  spec.size = sizeof spec;
  spec.machine = machine;
  spec.machine_len = machine_len;
  spec.path = path;
  spec.path_len = path_len;
  spec.weight = weight;
  spec.after = after;
  spec.fn = fn;
  spec.data = data;
  return route_insert(routes, &spec, 0, out_error, out_error_len);
}

GDEFCORE_Result gdefcore_route_add_spec(GDEFCORE_Routes * routes,
    const GDEFCORE_Route_Spec * spec, char ** out_error, size_t * out_error_len) {
  GDEFCORE_Route_Spec local;
  if (out_error != NULL) {
    *out_error = NULL;
  }
  if (out_error_len != NULL) {
    *out_error_len = 0;
  }
  if (routes == NULL || spec == NULL ||
      (spec->size != sizeof *spec && spec->size != GDEFCORE_ROUTE_SPEC_SIZE_V1) ||
      spec->machine == NULL || spec->machine_len == 0 || spec->path == NULL ||
      ((spec->fn == NULL) == (spec->call_fn == NULL))) {
    return GDEFCORE_ERR_INVALID;
  }
  /* A spec from before the entity capture existed names none. */
  memset(&local, 0, sizeof local);
  memcpy(&local, spec, spec->size);
  local.size = sizeof local;
  return route_insert(routes, &local, 1, out_error, out_error_len);
}

GDEFCORE_Result gdefcore_routes_set_check(GDEFCORE_Routes * routes,
    GDEFCORE_Route_Check_Fn fn, void * data) {
  if (routes == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  routes->check = fn;
  routes->check_data = data;
  return GDEFCORE_OK;
}

/* What a call knows: the segments of the pattern that matched and the
 * request's own. Lives on dispatch's stack. */
typedef struct CallState {
  const Seg * pat;
  size_t npat;
  const Seg * req;
} CallState;

int gdefcore_route_call_capture(const GDEFCORE_Route_Call * call,
    const char * name, size_t name_len, const char ** out_value,
    size_t * out_len) {
  const CallState * st;
  size_t i;
  if (call == NULL || call->size != sizeof *call || call->internal == NULL ||
      name == NULL || out_value == NULL || out_len == NULL) {
    return 0;
  }
  st = (const CallState *)call->internal;
  for (i = 0; i < st->npat; i++) {
    if (st->pat[i].named &&
        span_eq(st->pat[i].text, st->pat[i].len, name, name_len)) {
      *out_value = st->req[i].text;
      *out_len = st->req[i].len;
      return 1;
    }
  }
  return 0;
}

static int tab_before(const Route * a, const Route * b) {
  size_t n;
  int c;
  if (a->weight != b->weight) {
    return a->weight < b->weight;
  }
  n = a->machine_len < b->machine_len ? a->machine_len : b->machine_len;
  c = memcmp(a->machine, b->machine, n);
  if (c != 0) {
    return c < 0;
  }
  return a->machine_len < b->machine_len;
}

GDEFCORE_Result gdefcore_routes_tabs(GDEFCORE_Routes * routes, const char * parent,
    size_t parent_len, GDEFCORE_Route_Info ** out, size_t * out_count) {
  size_t i;
  size_t n = 0;
  const Route ** pick;
  GDEFCORE_Route_Info * info;
  if (routes == NULL || parent == NULL || out == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out = NULL;
  *out_count = 0;
  pick = (const Route **)gcu_allocator_malloc(routes->alloc,
      (routes->nroutes == 0 ? 1 : routes->nroutes) * sizeof *pick);
  if (pick == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < routes->nroutes; i++) {
    const Route * r = &routes->routes[i];
    if (r->kind == GDEFCORE_ROUTE_TAB &&
        span_eq(r->parent, r->parent_len, parent, parent_len)) {
      size_t j = n++;
      while (j > 0 && tab_before(r, pick[j - 1])) {
        pick[j] = pick[j - 1];
        j -= 1;
      }
      pick[j] = r;
    }
  }
  if (n == 0) {
    gcu_allocator_free(routes->alloc, pick);
    return GDEFCORE_OK;
  }
  info = (GDEFCORE_Route_Info *)gcu_allocator_calloc(routes->alloc, n,
      sizeof *info);
  if (info == NULL) {
    gcu_allocator_free(routes->alloc, pick);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    info[i].size = sizeof info[i];
    info[i].machine = pick[i]->machine;
    info[i].machine_len = pick[i]->machine_len;
    info[i].path = pick[i]->path;
    info[i].path_len = pick[i]->path_len;
    info[i].title = pick[i]->title;
    info[i].title_len = pick[i]->title_len;
    info[i].permission = pick[i]->permission;
    info[i].permission_len = pick[i]->permission_len;
    info[i].entity_capture = pick[i]->entity_capture;
    info[i].entity_capture_len = pick[i]->entity_capture_len;
    info[i].kind = pick[i]->kind;
    info[i].is_default = pick[i]->is_default;
    info[i].weight = pick[i]->weight;
  }
  gcu_allocator_free(routes->alloc, pick);
  *out = info;
  *out_count = n;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_routes_tabs_visible(GDEFCORE_Routes * routes,
    const char * parent, size_t parent_len, const GDEFCORE_Route_Call * page,
    GDEFCORE_Route_Info ** out, size_t * out_count) {
  GDEFCORE_Route_Info * all = NULL;
  size_t n = 0;
  size_t kept = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (routes == NULL || parent == NULL || page == NULL ||
      page->size != sizeof *page || out == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out = NULL;
  *out_count = 0;
  rc = gdefcore_routes_tabs(routes, parent, parent_len, &all, &n);
  if (rc != GDEFCORE_OK || n == 0) {
    return rc;
  }
  for (i = 0; i < n; i++) {
    if (all[i].permission_len > 0) {
      /* What dispatch would ask for this tab, with the captures of the page
       * the tabs are drawn on in place of the tab's own request. */
      GDEFCORE_Route_Call call = *page;
      const Route * r = route_find(routes, all[i].machine, all[i].machine_len);
      int allowed = 0;
      call.machine = all[i].machine;
      call.machine_len = all[i].machine_len;
      call.data = r == NULL ? NULL : r->data;
      call.entity_capture = all[i].entity_capture;
      call.entity_capture_len = all[i].entity_capture_len;
      if (routes->check != NULL) {
        allowed = routes->check(&call, all[i].permission,
            all[i].permission_len, routes->check_data);
      }
      if (!allowed) {
        continue;
      }
    }
    all[kept++] = all[i];
  }
  if (kept == 0) {
    gcu_allocator_free(routes->alloc, all);
    return GDEFCORE_OK;
  }
  *out = all;
  *out_count = kept;
  return GDEFCORE_OK;
}

typedef struct Cand {
  size_t idx;
  int score;
  const Seg * pat;
  size_t npat;
} Cand;

static void dispatch(GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const Seg * req, size_t nreq) {
  Cand * order;
  size_t n = 0;
  size_t i;
  size_t j;
  int owned = 0;
  char * owned_res = NULL;
  size_t owned_len = 0;
  const GDEFCORE_Allocator * alloc = routes->alloc;
  order = (Cand *)gcu_allocator_malloc(alloc,
      (routes->nroutes == 0 ? 1 : routes->nroutes) * sizeof *order);
  if (order == NULL) {
    return;
  }
  for (i = 0; i < routes->nroutes; i++) {
    const Route * r = &routes->routes[i];
    Cand c;
    c.idx = i;
    if (route_matches(r, req, nreq)) {
      c.score = r->score;
      c.pat = r->segs;
      c.npat = r->nsegs;
    } else if (r->alt != NULL && r->nalt == nreq &&
               segs_match(r->alt, r->nalt, req)) {
      /* A default tab at its parent's path, ahead of the parent's handlers. */
      c.score = r->alt_score;
      c.pat = r->alt;
      c.npat = r->nalt;
    } else {
      continue;
    }
    if (r->permission_len > 0) {
      /* The path matched. Whether the principal may is decided with the
       * matched values in hand, and a refusal is a route that did not match:
       * nothing is recorded, so the answer is a missing route's. */
      GDEFCORE_Route_Call call;
      CallState st;
      int allowed = 0;
      if (routes->check != NULL) {
        st.pat = c.pat;
        st.npat = c.npat;
        st.req = req;
        memset(&call, 0, sizeof call);
        call.size = sizeof call;
        call.request = request;
        call.machine = r->machine;
        call.machine_len = r->machine_len;
        call.data = r->data;
        call.internal = &st;
        call.entity_capture = r->entity_capture;
        call.entity_capture_len = r->entity_capture_len;
        allowed = routes->check(&call, r->permission, r->permission_len,
            routes->check_data);
      }
      if (!allowed) {
        continue;
      }
    }
    order[n++] = c;
  }
  for (i = 1; i < n; i++) {
    Cand key = order[i];
    j = i;
    while (j > 0) {
      const Route * a = &routes->routes[order[j - 1].idx];
      const Route * b = &routes->routes[key.idx];
      int less = 0;
      if (a->weight > b->weight ||
          (a->weight == b->weight && order[j - 1].score < key.score) ||
          (a->weight == b->weight && order[j - 1].score == key.score &&
              a->index > b->index)) {
        less = 1;
      }
      if (!less) {
        break;
      }
      order[j] = order[j - 1];
      j -= 1;
    }
    order[j] = key;
  }
  for (i = 0; i < n; i++) {
    Route * route = &routes->routes[order[i].idx];
    const char * res;
    size_t res_len = 0;
    if (owned && !route->after) {
      continue;
    }
    if (route->cfn != NULL) {
      GDEFCORE_Route_Call call;
      CallState st;
      st.pat = order[i].pat;
      st.npat = order[i].npat;
      st.req = req;
      memset(&call, 0, sizeof call);
      call.size = sizeof call;
      call.request = request;
      call.machine = route->machine;
      call.machine_len = route->machine_len;
      call.data = route->data;
      call.internal = &st;
      route->cfn(&call);
    } else {
      route->fn(request, route->machine, route->machine_len, route->data);
    }
    res = gdefcore_request_resolution(request, &res_len);
    if (!owned && res != NULL && res_len > 0) {
      owned_res = (char *)gcu_allocator_malloc(alloc, res_len);
      if (owned_res != NULL) {
        memcpy(owned_res, res, res_len);
        owned_len = res_len;
        owned = 1;
      }
    } else if (owned) {
      (void)gdefcore_request_set_resolution(request, owned_res, owned_len);
    }
  }
  gcu_allocator_free(alloc, owned_res);
  gcu_allocator_free(alloc, order);
}

static GDEFCORE_Result resolve_alias(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * path, size_t path_len, char ** out,
    size_t * out_len) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kAliasType, strlen(kAliasType),
      &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char * got = NULL;
    size_t got_len = 0;
    char * target = NULL;
    size_t target_len = 0;
    char * lang = NULL;
    size_t lang_len = 0;
    char * field = NULL;
    size_t field_len = 0;
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    int yes = 0;
    rc = alias_text(catalog, ids[i], 1, "path", 4, &got, &got_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      continue;
    }
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (!span_eq(got, got_len, path, path_len)) {
      gdefcore_text_free(catalog, got);
      continue;
    }
    gdefcore_text_free(catalog, got);
    rc = alias_text(catalog, ids[i], 1, "target", 6, &target, &target_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      continue;
    }
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    rc = alias_text(catalog, ids[i], 1, "lang", 4, &lang, &lang_len);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, target);
      if (rc == GDEFCORE_ERR_INVALID) {
        continue;
      }
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    rc = published_field(catalog, target, target_len, lang, lang_len, &field,
        &field_len, &yes);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, target);
      gdefcore_text_free(catalog, lang);
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (!yes) {
      gdefcore_text_free(catalog, target);
      gdefcore_text_free(catalog, lang);
      gdefcore_text_free(catalog, field);
      continue;
    }
    rc = gdefcore_access_read(catalog, request, target, target_len, lang, lang_len,
        field, field_len, &texts, &lens, &n);
    gdefcore_text_free(catalog, field);
    gdefcore_values_free(catalog, texts, lens, n);
    gdefcore_text_free(catalog, lang);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, target);
      if (rc == GDEFCORE_ERR_INVALID) {
        continue;
      }
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    rc = cat_dup(catalog, target, target_len, out);
    if (rc == GDEFCORE_OK) {
      *out_len = target_len;
    }
    gdefcore_text_free(catalog, target);
    gdefcore_ids_free(catalog, ids, count);
    return rc;
  }
  gdefcore_ids_free(catalog, ids, count);
  return GDEFCORE_ERR_INVALID;
}

GDEFCORE_Result gdefcore_form_resolve(GDEFCORE_Routes * routes,
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request, const char * path,
    size_t path_len, char ** out, size_t * out_len) {
  Seg * segs = NULL;
  size_t nsegs = 0;
  const char * res;
  size_t res_len = 0;
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || out == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (routes != NULL && path != NULL && path_len > 0 && path[0] == '/') {
    alloc = routes->alloc;
    rc = split_path(alloc, path, path_len, 0, &segs, &nsegs, NULL, NULL);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    (void)gdefcore_request_set_resolution(request, NULL, 0);
    dispatch(routes, request, segs, nsegs);
    seg_free(alloc, segs, nsegs);
    res = gdefcore_request_resolution(request, &res_len);
    if (res != NULL && res_len > 0) {
      *out_len = res_len;
      return cat_dup(catalog, res, res_len, out);
    }
  }
  return resolve_alias(catalog, request, path, path_len, out, out_len);
}
