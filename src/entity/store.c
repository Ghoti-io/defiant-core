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
 * What core keeps on the storage port (model.h, AD-13, AD-14):
 *
 * - a type is a port declaration (each core field a field of the root group,
 *   in its logical type; a field that holds several values is MULTIPLE) and a
 *   record `core.type/<name>` with what the port does not hold: the kind,
 *   each field's constraints, the type's public id and a version that every
 *   definition bumps;
 * - an entity is a port entity: its creator, its revisions (who, when, why),
 *   its state (published, soft-deleted), one tree per language;
 * - a draft is the port's draft, which also reserves the public id of an
 *   entity never saved (its port entity is made when the draft is applied);
 * - an entity's version is the counter `core.v:<id>`, bumped by every write
 *   that touches the entity; the config epoch is the counter `core.epoch`.
 *
 * Values are texts at core's interface. Each is held in its field's logical
 * type, and read back in the one canonical text of that type, so a value
 * written as `07` to an integer field reads `7`.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/subject.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/query.h>

#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "entity_internal.h"

/* ---- small helpers -------------------------------------------------------- */

const GDEFCORE_Allocator * gdefcore_ent_alloc(const GDEFCORE_Allocator * a) {
  return a == NULL ? gdefcore_allocator_default() : a;
}

GDEFCORE_Result gdefcore_ent_map(GDEFSTOR_Result rc) {
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
  case GDEFSTOR_ERR_UNSUPPORTED:
    return GDEFCORE_ERR_INVALID;
  default:
    return GDEFCORE_ERR_IO;
  }
}

int gdefcore_ent_span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

char * gdefcore_ent_dup(const GDEFCORE_Allocator * alloc, const char * p,
    size_t n) {
  char * out = (char *)gcu_allocator_malloc(alloc, n + 1);
  if (out == NULL) {
    return NULL;
  }
  if (n > 0 && p != NULL) {
    memcpy(out, p, n);
  }
  out[n] = '\0';
  return out;
}

void gdefcore_ent_text_clear(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Text * t) {
  gcu_allocator_free(alloc, t->p);
  t->p = NULL;
  t->n = 0;
}

GDEFCORE_Result gdefcore_ent_text_set(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Text * t, const char * p, size_t n) {
  char * copy = gdefcore_ent_dup(alloc, p, n);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  gdefcore_ent_text_clear(alloc, t);
  t->p = copy;
  t->n = n;
  return GDEFCORE_OK;
}

#define span_eq gdefcore_ent_span_eq
#define dup_span gdefcore_ent_dup
#define text_clear gdefcore_ent_text_clear
#define text_set gdefcore_ent_text_set

typedef struct Buf {
  const GDEFCORE_Allocator * alloc;
  char * p;
  size_t n;
  size_t cap;
  int oom;
} Buf;

static void buf_add(Buf * b, const char * s, size_t n) {
  size_t need;
  if (b->oom || n == 0) {
    return;
  }
  if (b->n > SIZE_MAX - n - 1) {
    b->oom = 1;
    return;
  }
  need = b->n + n + 1;
  if (need > b->cap) {
    size_t cap = b->cap == 0 ? 128 : b->cap;
    char * next;
    while (cap < need) {
      cap *= 2;
    }
    next = (char *)gcu_allocator_realloc(b->alloc, b->p, cap);
    if (next == NULL) {
      b->oom = 1;
      return;
    }
    b->p = next;
    b->cap = cap;
  }
  memcpy(b->p + b->n, s, n);
  b->n += n;
  b->p[b->n] = '\0';
}

static void buf_str(Buf * b, const char * s) {
  buf_add(b, s, strlen(s));
}

static void buf_u64(Buf * b, uint64_t v) {
  char text[32];
  int n = snprintf(text, sizeof text, "%llu", (unsigned long long)v);
  if (n > 0) {
    buf_add(b, text, (size_t)n);
  }
}

static void buf_i64(Buf * b, int64_t v) {
  char text[32];
  int n = snprintf(text, sizeof text, "%lld", (long long)v);
  if (n > 0) {
    buf_add(b, text, (size_t)n);
  }
}

/* ---- docs and declarations ----------------------------------------------- */

void gdefcore_ent_doc_free(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Doc * doc) {
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
      gcu_allocator_free(alloc, doc->langs[i].fields[j].ids);
      text_clear(alloc, &doc->langs[i].fields[j].name);
    }
    gcu_allocator_free(alloc, doc->langs[i].fields);
    gdefcore_tree_free(doc->langs[i].groups);
    text_clear(alloc, &doc->langs[i].lang);
  }
  gcu_allocator_free(alloc, doc->langs);
  doc->langs = NULL;
  doc->nlangs = 0;
}

GDEFCORE_Result gdefcore_ent_doc_clone(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Doc * in, GDEFCORE_Doc * out) {
  size_t i;
  size_t j;
  size_t k;
  memset(out, 0, sizeof *out);
  if (in->nlangs == 0) {
    return GDEFCORE_OK;
  }
  out->langs = (GDEFCORE_Lang *)gcu_allocator_calloc(alloc, in->nlangs,
      sizeof *out->langs);
  if (out->langs == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  out->nlangs = in->nlangs;
  for (i = 0; i < in->nlangs; i++) {
    GDEFCORE_Lang * dst = &out->langs[i];
    const GDEFCORE_Lang * src = &in->langs[i];
    if (text_set(alloc, &dst->lang, src->lang.p, src->lang.n) != GDEFCORE_OK) {
      gdefcore_ent_doc_free(alloc, out);
      return GDEFCORE_ERR_OOM;
    }
    if (src->groups != NULL &&
        gdefcore_ent_tree_clone(src->groups, &dst->groups) != GDEFCORE_OK) {
      gdefcore_ent_doc_free(alloc, out);
      return GDEFCORE_ERR_OOM;
    }
    if (src->nfields == 0) {
      continue;
    }
    dst->fields = (GDEFCORE_Vals *)gcu_allocator_calloc(alloc, src->nfields,
        sizeof *dst->fields);
    if (dst->fields == NULL) {
      gdefcore_ent_doc_free(alloc, out);
      return GDEFCORE_ERR_OOM;
    }
    dst->nfields = src->nfields;
    for (j = 0; j < src->nfields; j++) {
      if (text_set(alloc, &dst->fields[j].name, src->fields[j].name.p,
              src->fields[j].name.n) != GDEFCORE_OK) {
        gdefcore_ent_doc_free(alloc, out);
        return GDEFCORE_ERR_OOM;
      }
      if (src->fields[j].nvals == 0) {
        continue;
      }
      dst->fields[j].vals = (GDEFCORE_Text *)gcu_allocator_calloc(alloc,
          src->fields[j].nvals, sizeof *dst->fields[j].vals);
      if (dst->fields[j].vals == NULL) {
        gdefcore_ent_doc_free(alloc, out);
        return GDEFCORE_ERR_OOM;
      }
      dst->fields[j].nvals = src->fields[j].nvals;
      if (src->fields[j].ids != NULL) {
        dst->fields[j].ids = (uint64_t *)gcu_allocator_malloc(alloc,
            src->fields[j].nvals * sizeof *dst->fields[j].ids);
        if (dst->fields[j].ids == NULL) {
          gdefcore_ent_doc_free(alloc, out);
          return GDEFCORE_ERR_OOM;
        }
        memcpy(dst->fields[j].ids, src->fields[j].ids,
            src->fields[j].nvals * sizeof *dst->fields[j].ids);
      }
      for (k = 0; k < src->fields[j].nvals; k++) {
        if (text_set(alloc, &dst->fields[j].vals[k], src->fields[j].vals[k].p,
                src->fields[j].vals[k].n) != GDEFCORE_OK) {
          gdefcore_ent_doc_free(alloc, out);
          return GDEFCORE_ERR_OOM;
        }
      }
    }
  }
  return GDEFCORE_OK;
}

void gdefcore_ent_decls_free(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Decl * decls, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    text_clear(alloc, &decls[i].name);
    text_clear(alloc, &decls[i].pattern);
    text_clear(alloc, &decls[i].subject);
  }
  gcu_allocator_free(alloc, decls);
}

GDEFCORE_Result gdefcore_ent_decls_copy(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Decl * in, size_t n, GDEFCORE_Decl ** out) {
  GDEFCORE_Decl * copy;
  size_t i;
  *out = NULL;
  if (n == 0) {
    return GDEFCORE_OK;
  }
  copy = (GDEFCORE_Decl *)gcu_allocator_calloc(alloc, n, sizeof *copy);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    copy[i] = in[i];
    copy[i].name.p = NULL;
    copy[i].name.n = 0;
    copy[i].pattern.p = NULL;
    copy[i].pattern.n = 0;
    copy[i].subject.p = NULL;
    copy[i].subject.n = 0;
    if (text_set(alloc, &copy[i].name, in[i].name.p, in[i].name.n) !=
            GDEFCORE_OK ||
        (in[i].pattern.n > 0 &&
            text_set(alloc, &copy[i].pattern, in[i].pattern.p,
                in[i].pattern.n) != GDEFCORE_OK) ||
        (in[i].subject.n > 0 &&
            text_set(alloc, &copy[i].subject, in[i].subject.p,
                in[i].subject.n) != GDEFCORE_OK)) {
      gdefcore_ent_decls_free(alloc, copy, i + 1);
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = copy;
  return GDEFCORE_OK;
}

void gdefcore_ent_type_free(const GDEFCORE_Allocator * alloc,
    GDEFCORE_EntType * t) {
  if (t == NULL) {
    return;
  }
  gdefcore_ent_decls_free(alloc, t->decls, t->ndecls);
  t->decls = NULL;
  t->ndecls = 0;
}

/* ---- the type record ------------------------------------------------------ */

/*
 * `core.type/<name>`, one line per fact, a field per `field` line:
 *
 *   defiant-core-type/1
 *   kind content
 *   id <public id>
 *   version <n>
 *   field <name> <required> <many> <personal> <type> <scale> <indexed>
 *         <min_len> <max_len> <has_range> <range_min> <range_max> <pattern hex or ->
 *         [<subject or ->]
 *
 * The port's declaration is the fields' shape; this is what only core reads.
 * A name is a field's path (story S6d: `lines.taxes.rate`), the fields in
 * pre-order, a group (type GROUP) before its fields. The last word, the
 * subject field of a personal field, is new with S6d; a line without it has
 * none.
 */

static const char kTypeFormat[] = "defiant-core-type/1";
static const char kHex[] = "0123456789abcdef";

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

static void type_text(Buf * b, const GDEFCORE_EntType * t) {
  size_t i;
  buf_str(b, kTypeFormat);
  buf_str(b, "\nkind ");
  buf_str(b, t->kind == GDEFCORE_TYPE_CONFIG ? "config" : "content");
  buf_str(b, "\nid ");
  buf_str(b, t->id);
  buf_str(b, "\nversion ");
  buf_u64(b, t->version);
  for (i = 0; i < t->ndecls; i++) {
    const GDEFCORE_Decl * d = &t->decls[i];
    size_t k;
    buf_str(b, "\nfield ");
    buf_add(b, d->name.p, d->name.n);
    buf_str(b, d->required ? " 1" : " 0");
    buf_str(b, d->many ? " 1" : " 0");
    buf_str(b, d->personal ? " 1 " : " 0 ");
    buf_i64(b, d->type);
    buf_str(b, " ");
    buf_i64(b, d->scale);
    buf_str(b, d->indexed ? " 1 " : " 0 ");
    buf_u64(b, (uint64_t)d->min_len);
    buf_str(b, " ");
    buf_u64(b, (uint64_t)d->max_len);
    buf_str(b, d->has_range ? " 1 " : " 0 ");
    buf_i64(b, d->range_min);
    buf_str(b, " ");
    buf_i64(b, d->range_max);
    buf_str(b, " ");
    if (d->pattern.n == 0) {
      buf_str(b, "-");
    }
    for (k = 0; k < d->pattern.n; k++) {
      unsigned char c = (unsigned char)d->pattern.p[k];
      char two[2];
      two[0] = kHex[c >> 4];
      two[1] = kHex[c & 15u];
      buf_add(b, two, 2);
    }
    if (d->subject.n > 0) {
      buf_str(b, " ");
      buf_add(b, d->subject.p, d->subject.n);
    }
  }
  buf_str(b, "\n");
}

/* The next space-separated word of a line. */
static int word(const char ** p, const char * end, const char ** w,
    size_t * wn) {
  const char * s = *p;
  while (s < end && *s == ' ') {
    s += 1;
  }
  *w = s;
  while (s < end && *s != ' ') {
    s += 1;
  }
  *wn = (size_t)(s - *w);
  *p = s;
  return *wn > 0;
}

static int word_u64(const char ** p, const char * end, uint64_t * out) {
  const char * w;
  size_t n;
  size_t i;
  uint64_t v = 0;
  if (!word(p, end, &w, &n)) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (w[i] < '0' || w[i] > '9' || v > (UINT64_MAX - 9) / 10) {
      return 0;
    }
    v = v * 10 + (uint64_t)(w[i] - '0');
  }
  *out = v;
  return 1;
}

static int word_i64(const char ** p, const char * end, int64_t * out) {
  const char * w;
  size_t n;
  size_t i = 0;
  int neg = 0;
  uint64_t v = 0;
  if (!word(p, end, &w, &n)) {
    return 0;
  }
  if (w[0] == '-') {
    neg = 1;
    i = 1;
  }
  if (i == n) {
    return 0;
  }
  for (; i < n; i++) {
    if (w[i] < '0' || w[i] > '9' || v > (UINT64_MAX - 9) / 10) {
      return 0;
    }
    v = v * 10 + (uint64_t)(w[i] - '0');
  }
  if ((!neg && v > (uint64_t)INT64_MAX) ||
      (neg && v > (uint64_t)INT64_MAX + 1u)) {
    return 0;
  }
  *out = neg ? (v == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)v)
             : (int64_t)v;
  return 1;
}

static int word_flag(const char ** p, const char * end, int * out) {
  uint64_t v = 0;
  if (!word_u64(p, end, &v) || v > 1) {
    return 0;
  }
  *out = (int)v;
  return 1;
}

static GDEFCORE_Result type_parse(const GDEFCORE_Allocator * alloc,
    const char * text, size_t n, GDEFCORE_EntType * out) {
  const char * p = text;
  const char * end = text + n;
  size_t line = 0;
  memset(out, 0, sizeof *out);
  while (p < end) {
    const char * eol = memchr(p, '\n', (size_t)(end - p));
    const char * q = p;
    const char * w;
    size_t wn;
    if (eol == NULL) {
      eol = end;
    }
    if (line == 0) {
      if (!span_eq(p, (size_t)(eol - p), kTypeFormat, sizeof kTypeFormat - 1)) {
        gdefcore_ent_type_free(alloc, out);
        return GDEFCORE_ERR_CORRUPT;
      }
    } else if (eol > p) {
      if (!word(&q, eol, &w, &wn)) {
        gdefcore_ent_type_free(alloc, out);
        return GDEFCORE_ERR_CORRUPT;
      }
      if (span_eq(w, wn, "kind", 4)) {
        if (!word(&q, eol, &w, &wn)) {
          gdefcore_ent_type_free(alloc, out);
          return GDEFCORE_ERR_CORRUPT;
        }
        if (span_eq(w, wn, "content", 7)) {
          out->kind = GDEFCORE_TYPE_CONTENT;
        } else if (span_eq(w, wn, "config", 6)) {
          out->kind = GDEFCORE_TYPE_CONFIG;
        } else {
          gdefcore_ent_type_free(alloc, out);
          return GDEFCORE_ERR_CORRUPT;
        }
      } else if (span_eq(w, wn, "id", 2)) {
        if (!word(&q, eol, &w, &wn) || wn != GDEFCORE_PUBLIC_ID_LEN) {
          gdefcore_ent_type_free(alloc, out);
          return GDEFCORE_ERR_CORRUPT;
        }
        memcpy(out->id, w, wn);
        out->id[wn] = '\0';
      } else if (span_eq(w, wn, "version", 7)) {
        if (!word_u64(&q, eol, &out->version)) {
          gdefcore_ent_type_free(alloc, out);
          return GDEFCORE_ERR_CORRUPT;
        }
      } else if (span_eq(w, wn, "field", 5)) {
        GDEFCORE_Decl d;
        GDEFCORE_Decl * next;
        uint64_t min_len = 0;
        uint64_t max_len = 0;
        int64_t type = 0;
        int64_t scale = 0;
        const char * pat;
        size_t pn;
        memset(&d, 0, sizeof d);
        if (!word(&q, eol, &w, &wn) ||
            text_set(alloc, &d.name, w, wn) != GDEFCORE_OK) {
          gdefcore_ent_type_free(alloc, out);
          return GDEFCORE_ERR_CORRUPT;
        }
        if (!word_flag(&q, eol, &d.required) || !word_flag(&q, eol, &d.many) ||
            !word_flag(&q, eol, &d.personal) || !word_i64(&q, eol, &type) ||
            !word_i64(&q, eol, &scale) || !word_flag(&q, eol, &d.indexed) ||
            !word_u64(&q, eol, &min_len) || !word_u64(&q, eol, &max_len) ||
            !word_flag(&q, eol, &d.has_range) ||
            !word_i64(&q, eol, &d.range_min) ||
            !word_i64(&q, eol, &d.range_max) || !word(&q, eol, &pat, &pn) ||
            type < GDEFSTOR_FIELD_TEXT || type > GDEFSTOR_FIELD_GROUP ||
            scale < 0 || scale > GDEFSTOR_MODEL_MAX_SCALE) {
          text_clear(alloc, &d.name);
          gdefcore_ent_type_free(alloc, out);
          return GDEFCORE_ERR_CORRUPT;
        }
        d.type = (int)type;
        d.scale = (int)scale;
        d.min_len = (size_t)min_len;
        d.max_len = (size_t)max_len;
        if (!(pn == 1 && pat[0] == '-')) {
          size_t k;
          char * raw;
          if (pn % 2 != 0) {
            text_clear(alloc, &d.name);
            gdefcore_ent_type_free(alloc, out);
            return GDEFCORE_ERR_CORRUPT;
          }
          raw = (char *)gcu_allocator_malloc(alloc, pn / 2 + 1);
          if (raw == NULL) {
            text_clear(alloc, &d.name);
            gdefcore_ent_type_free(alloc, out);
            return GDEFCORE_ERR_OOM;
          }
          for (k = 0; k < pn; k += 2) {
            int hi = hex_nibble(pat[k]);
            int lo = hex_nibble(pat[k + 1]);
            if (hi < 0 || lo < 0) {
              gcu_allocator_free(alloc, raw);
              text_clear(alloc, &d.name);
              gdefcore_ent_type_free(alloc, out);
              return GDEFCORE_ERR_CORRUPT;
            }
            raw[k / 2] = (char)((hi << 4) | lo);
          }
          d.pattern.p = raw;
          d.pattern.n = pn / 2;
          raw[pn / 2] = '\0';
        }
        {
          const char * sw;
          size_t sn;
          if (word(&q, eol, &sw, &sn) &&
              text_set(alloc, &d.subject, sw, sn) != GDEFCORE_OK) {
            text_clear(alloc, &d.name);
            text_clear(alloc, &d.pattern);
            gdefcore_ent_type_free(alloc, out);
            return GDEFCORE_ERR_OOM;
          }
        }
        next = (GDEFCORE_Decl *)gcu_allocator_realloc(alloc, out->decls,
            (out->ndecls + 1) * sizeof *next);
        if (next == NULL) {
          text_clear(alloc, &d.name);
          text_clear(alloc, &d.pattern);
          text_clear(alloc, &d.subject);
          gdefcore_ent_type_free(alloc, out);
          return GDEFCORE_ERR_OOM;
        }
        out->decls = next;
        out->decls[out->ndecls++] = d;
      } else {
        gdefcore_ent_type_free(alloc, out);
        return GDEFCORE_ERR_CORRUPT;
      }
    }
    line += 1;
    p = eol < end ? eol + 1 : end;
  }
  if (line == 0 || out->kind == 0 || out->id[0] == '\0') {
    gdefcore_ent_type_free(alloc, out);
    return GDEFCORE_ERR_CORRUPT;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_type_load(GDEFCORE_Catalog * cat,
    const char * name, size_t name_len, GDEFCORE_EntType * out) {
  int found = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFCORE_Result rc;
  memset(out, 0, sizeof *out);
  if (name == NULL || name_len == 0 || name_len > GDEFSTOR_RECORD_MAX_KEY_BYTES) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_map(gdefstor_record_get(cat->store,
      (const char *)cat->tenant, cat->tenant_len, GDEFCORE_ENT_TYPE_NS,
      sizeof GDEFCORE_ENT_TYPE_NS - 1, name, name_len, &found, &bytes, &len));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!found) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = type_parse(cat->alloc, (const char *)bytes, len, out);
  gdefstor_bytes_free(NULL, bytes);
  return rc;
}

/* The port specs of the fields directly inside group @p prefix (empty: the
 * root group), from a type's decls in pre-order. */
static void specs_free(const GDEFCORE_Allocator * alloc,
    GDEFSTOR_FieldSpec * specs, size_t n) {
  size_t i;
  for (i = 0; specs != NULL && i < n; i++) {
    specs_free(alloc, (GDEFSTOR_FieldSpec *)specs[i].children,
        specs[i].child_count);
  }
  gcu_allocator_free(alloc, specs);
}

/* The leaf name of @p name when it is a field directly inside @p prefix. */
static int child_of(const GDEFCORE_Text * name, const char * prefix, size_t pn,
    const char ** leaf, size_t * leaf_len) {
  const char * rest = name->p;
  size_t rn = name->n;
  if (pn > 0) {
    if (rn <= pn + 1 || memcmp(rest, prefix, pn) != 0 || rest[pn] != '.') {
      return 0;
    }
    rest += pn + 1;
    rn -= pn + 1;
  }
  if (rn == 0 || memchr(rest, '.', rn) != NULL) {
    return 0;
  }
  *leaf = rest;
  *leaf_len = rn;
  return 1;
}

static GDEFCORE_Result build_specs(GDEFCORE_Catalog * cat,
    const GDEFSTOR_Type * stored, const GDEFCORE_EntType * t,
    const char * prefix, size_t pn, int depth, GDEFSTOR_FieldSpec ** out,
    size_t * out_n) {
  GDEFSTOR_FieldSpec * specs;
  size_t n = 0;
  size_t at = 0;
  size_t i;
  *out = NULL;
  *out_n = 0;
  if (depth > GDEFSTOR_MODEL_MAX_DEPTH + 1) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < t->ndecls; i++) {
    const char * leaf;
    size_t ln;
    n += child_of(&t->decls[i].name, prefix, pn, &leaf, &ln) ? 1u : 0u;
  }
  if (n == 0) {
    return GDEFCORE_OK;
  }
  specs = (GDEFSTOR_FieldSpec *)gcu_allocator_calloc(cat->alloc, n,
      sizeof *specs);
  if (specs == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < t->ndecls && at < n; i++) {
    const GDEFCORE_Decl * d = &t->decls[i];
    const char * leaf = NULL;
    size_t ln = 0;
    int port_personal = d->personal;
    size_t fi = 0;
    GDEFSTOR_FieldSpec * sp;
    GDEFSTOR_FieldInfo info;
    if (!child_of(&d->name, prefix, pn, &leaf, &ln)) {
      continue;
    }
    sp = &specs[at++];
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (stored != NULL &&
        gdefstor_type_find(stored, d->name.p, d->name.n, &fi) == GDEFSTOR_OK &&
        gdefstor_type_field(stored, fi, &info) == GDEFSTOR_OK) {
      /* A port field keeps how it was first declared: making one personal
       * or not in place is a new field and a conversion (AD-15). A field
       * that became personal after it was declared stays a text column:
       * its values are sealed, with no subject column and no blind row,
       * until it is converted (story S7). One that was personal does not
       * stop being so. */
      int was = (info.flags & GDEFSTOR_FIELD_PERSONAL) != 0;
      if (was && !d->personal) {
        specs_free(cat->alloc, specs, n);
        return GDEFCORE_ERR_INVALID;
      }
      port_personal = was;
    }
    sp->size = sizeof *sp;
    sp->name = leaf;
    sp->name_len = ln;
    sp->type = d->type == GDEFSTOR_FIELD_GROUP
                   ? GDEFSTOR_FIELD_GROUP
                   : (d->personal ? GDEFSTOR_FIELD_TEXT : d->type);
    sp->scale =
        !d->personal && d->type == GDEFSTOR_FIELD_DECIMAL ? d->scale : 0;
    sp->flags = (d->many ? GDEFSTOR_FIELD_MULTIPLE : 0u) |
                (d->indexed && !d->personal ? GDEFSTOR_FIELD_INDEXED : 0u) |
                (port_personal ? GDEFSTOR_FIELD_PERSONAL : 0u);
    if (port_personal && d->subject.n > 0) {
      /* Story S6d: the sibling reference that names the value's subject. */
      sp->subject = d->subject.p;
      sp->subject_len = d->subject.n;
    }
    if (d->type == GDEFSTOR_FIELD_GROUP) {
      GDEFSTOR_FieldSpec * kids = NULL;
      size_t nk = 0;
      GDEFCORE_Result rc = build_specs(cat, stored, t, d->name.p, d->name.n,
          depth + 1, &kids, &nk);
      if (rc != GDEFCORE_OK) {
        specs_free(cat->alloc, specs, n);
        return rc;
      }
      sp->children = kids;
      sp->child_count = nk;
    }
  }
  *out = specs;
  *out_n = n;
  return GDEFCORE_OK;
}

/* The port's declaration of a type: each core field a field of its group in
 * its logical type, a group a GROUP with its fields (story S6d), a field that
 * holds several values or items MULTIPLE. A personal field is a PERSONAL text
 * field: each value is the sealed text with its subject's public id beside it
 * (AD-14, AD-19), named by core on every value, or by the subject field its
 * declaration names, and its blind-index rows go in the port's blind table
 * (story S6c). */
GDEFCORE_Result gdefcore_ent_type_write(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * name, size_t name_len,
    const GDEFCORE_EntType * t) {
  GDEFSTOR_FieldSpec * specs = NULL;
  size_t nspecs = 0;
  GDEFSTOR_TypeSpec spec;
  GDEFSTOR_Type * stored = NULL;
  Buf b;
  GDEFCORE_Result rc;
  GDEFSTOR_Result src = gdefstor_type_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, name, name_len, &stored);
  if (src != GDEFSTOR_OK && src != GDEFSTOR_ERR_INVALID) {
    return gdefcore_ent_map(src);
  }
  rc = build_specs(cat, stored, t, NULL, 0, 0, &specs, &nspecs);
  gdefstor_type_free(stored);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&spec, 0, sizeof spec);
  spec.size = sizeof spec;
  spec.name = name;
  spec.name_len = name_len;
  spec.fields = specs;
  spec.field_count = nspecs;
  rc = gdefcore_ent_map(gdefstor_type_declare(write, &spec));
  specs_free(cat->alloc, specs, nspecs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&b, 0, sizeof b);
  b.alloc = cat->alloc;
  type_text(&b, t);
  if (b.oom) {
    gcu_allocator_free(cat->alloc, b.p);
    return GDEFCORE_ERR_OOM;
  }
  rc = gdefcore_ent_map(gdefstor_record_put(write, GDEFCORE_ENT_TYPE_NS,
      sizeof GDEFCORE_ENT_TYPE_NS - 1, name, name_len, (const uint8_t *)b.p,
      b.n));
  gcu_allocator_free(cat->alloc, b.p);
  return rc;
}

/* ---- typed values -------------------------------------------------------- */

static int all_digits(const char * s, size_t n) {
  size_t i;
  if (n == 0) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') {
      return 0;
    }
  }
  return 1;
}

/* A magnitude of digits, leading zeros allowed, at most 10^18 - 1. */
static int magnitude(const char * s, size_t n, uint64_t * out) {
  uint64_t v = 0;
  size_t i;
  if (!all_digits(s, n)) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    v = v * 10 + (uint64_t)(s[i] - '0');
    if (v > (uint64_t)GDEFSTOR_MODEL_MAX_DECIMAL) {
      return 0;
    }
  }
  *out = v;
  return 1;
}

static int parse_integer(const char * s, size_t n, int64_t * out) {
  uint64_t v = 0;
  int neg = n > 0 && s[0] == '-';
  if (!magnitude(s + neg, n - (size_t)neg, &v)) {
    return 0;
  }
  *out = neg ? -(int64_t)v : (int64_t)v;
  return 1;
}

static int parse_decimal(const char * s, size_t n, int scale, int64_t * out) {
  int neg = n > 0 && s[0] == '-';
  const char * dot;
  size_t ip;
  size_t fp = 0;
  uint64_t v = 0;
  int k;
  s += neg;
  n -= (size_t)neg;
  dot = memchr(s, '.', n);
  ip = dot == NULL ? n : (size_t)(dot - s);
  if (dot != NULL) {
    fp = n - ip - 1;
    if (fp == 0 || fp > (size_t)scale || !all_digits(dot + 1, fp)) {
      return 0;
    }
  }
  if (!magnitude(s, ip, &v)) {
    return 0;
  }
  for (k = 0; k < scale; k++) {
    unsigned digit = 0;
    if ((size_t)k < fp) {
      digit = (unsigned)(dot[1 + k] - '0');
    }
    if (v > ((uint64_t)GDEFSTOR_MODEL_MAX_DECIMAL - digit) / 10u) {
      return 0;
    }
    v = v * 10u + digit;
  }
  *out = neg ? -(int64_t)v : (int64_t)v;
  return 1;
}

/* A double, by the C rules of strtod but without the locale: the text is
 * spelled `-?digits(.digits)?([eE][+-]?digits)?` and converted with the
 * locale's own decimal point put in its place. */
static int parse_float(const char * s, size_t n, double * out) {
  char buf[400];
  const char * point = localeconv()->decimal_point;
  size_t pl = point == NULL || point[0] == '\0' ? 1 : strlen(point);
  size_t i = 0;
  size_t o = 0;
  char * end = NULL;
  double v;
  if (n == 0 || n > 300) {
    return 0;
  }
  if (s[i] == '-') {
    buf[o++] = '-';
    i += 1;
  }
  if (i >= n || s[i] < '0' || s[i] > '9') {
    return 0;
  }
  while (i < n && s[i] >= '0' && s[i] <= '9') {
    buf[o++] = s[i++];
  }
  if (i < n && s[i] == '.') {
    i += 1;
    if (i >= n || s[i] < '0' || s[i] > '9') {
      return 0;
    }
    memcpy(buf + o, point == NULL || point[0] == '\0' ? "." : point, pl);
    o += pl;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
      buf[o++] = s[i++];
    }
  }
  if (i < n && (s[i] == 'e' || s[i] == 'E')) {
    buf[o++] = 'e';
    i += 1;
    if (i < n && (s[i] == '+' || s[i] == '-')) {
      buf[o++] = s[i++];
    }
    if (i >= n || s[i] < '0' || s[i] > '9') {
      return 0;
    }
    while (i < n && s[i] >= '0' && s[i] <= '9') {
      buf[o++] = s[i++];
    }
  }
  if (i != n) {
    return 0;
  }
  buf[o] = '\0';
  v = strtod(buf, &end);
  if (end == NULL || *end != '\0' || !isfinite(v)) {
    return 0;
  }
  *out = v == 0.0 ? 0.0 : v;
  return 1;
}

/* Days from 1970-01-01 to a civil date (proleptic Gregorian). */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
  int64_t era;
  unsigned yoe;
  unsigned doy;
  unsigned doe;
  y -= m <= 2;
  era = (y >= 0 ? y : y - 399) / 400;
  yoe = (unsigned)(y - era * 400);
  doy = (153u * (m + (m > 2 ? (unsigned)-3 : 9u)) + 2u) / 5u + d - 1u;
  doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int64_t * y, unsigned * m,
    unsigned * d) {
  int64_t era;
  unsigned doe;
  unsigned yoe;
  unsigned doy;
  unsigned mp;
  z += 719468;
  era = (z >= 0 ? z : z - 146096) / 146097;
  doe = (unsigned)(z - era * 146097);
  yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
  *y = (int64_t)yoe + era * 400;
  doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
  mp = (5u * doy + 2u) / 153u;
  *d = doy - (153u * mp + 2u) / 5u + 1u;
  *m = mp < 10 ? mp + 3 : mp - 9;
  *y += *m <= 2;
}

static int digits_at(const char * s, size_t n, size_t at, size_t k,
    unsigned * out) {
  unsigned v = 0;
  size_t i;
  if (at + k > n) {
    return 0;
  }
  for (i = 0; i < k; i++) {
    if (s[at + i] < '0' || s[at + i] > '9') {
      return 0;
    }
    v = v * 10u + (unsigned)(s[at + i] - '0');
  }
  *out = v;
  return 1;
}

static unsigned month_days(unsigned y, unsigned m) {
  static const unsigned k[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (m == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) {
    return 29;
  }
  return k[m - 1];
}

/* `YYYY-MM-DD`, years 1 to 9999. */
static int parse_date_at(const char * s, size_t n, int64_t * out) {
  unsigned y;
  unsigned m;
  unsigned d;
  if (n < 10 || !digits_at(s, n, 0, 4, &y) || s[4] != '-' ||
      !digits_at(s, n, 5, 2, &m) || s[7] != '-' || !digits_at(s, n, 8, 2, &d) ||
      y < 1 || m < 1 || m > 12 || d < 1 || d > month_days(y, m)) {
    return 0;
  }
  *out = days_from_civil((int64_t)y, m, d);
  return 1;
}

/* `YYYY-MM-DDTHH:MM:SS` with an optional `.f` of one to three digits, then
 * `Z`: milliseconds since 1970-01-01T00:00Z. */
static int parse_datetime(const char * s, size_t n, int64_t * out) {
  int64_t days;
  unsigned hh;
  unsigned mm;
  unsigned ss;
  unsigned ms = 0;
  size_t at = 19;
  if (n < 20 || !parse_date_at(s, n, &days) || s[10] != 'T' ||
      !digits_at(s, n, 11, 2, &hh) || s[13] != ':' ||
      !digits_at(s, n, 14, 2, &mm) || s[16] != ':' ||
      !digits_at(s, n, 17, 2, &ss) || hh > 23 || mm > 59 || ss > 59) {
    return 0;
  }
  if (s[at] == '.') {
    size_t k = 0;
    size_t pad;
    at += 1;
    while (at + k < n && s[at + k] >= '0' && s[at + k] <= '9') {
      k += 1;
    }
    if (k < 1 || k > 3 || !digits_at(s, n, at, k, &ms)) {
      return 0;
    }
    for (pad = k; pad < 3; pad++) {
      ms *= 10u;
    }
    at += k;
  }
  if (at + 1 != n || s[at] != 'Z') {
    return 0;
  }
  *out = ((days * 24 + (int64_t)hh) * 60 + (int64_t)mm) * 60000 +
         (int64_t)ss * 1000 + (int64_t)ms;
  return 1;
}

static int text_ok(const char * s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t need;
    uint32_t cp;
    uint32_t min;
    size_t j;
    if (c == 0) {
      return 0;
    }
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
      if (((unsigned char)s[i + j] & 0xc0u) != 0x80u) {
        return 0;
      }
      cp = (cp << 6) | ((unsigned char)s[i + j] & 0x3fu);
    }
    if (cp < min || cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) {
      return 0;
    }
    i += need;
  }
  return 1;
}

GDEFCORE_Result gdefcore_value_parse(int type, int scale, const char * text,
    size_t len, GDEFSTOR_Value * out) {
  if (out == NULL || (text == NULL && len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(out, 0, sizeof *out);
  if (text == NULL) {
    text = "";
  }
  if (type == 0) {
    type = GDEFSTOR_FIELD_TEXT;
  }
  out->type = type;
  switch (type) {
  case GDEFSTOR_FIELD_TEXT:
    if (len > GDEFSTOR_MODEL_MAX_VALUE_BYTES || !text_ok(text, len)) {
      return GDEFCORE_ERR_INVALID;
    }
    out->bytes = (const uint8_t *)text;
    out->len = len;
    return GDEFCORE_OK;
  case GDEFSTOR_FIELD_REFERENCE: {
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    /* Core's references are its own public ids, held canonical. */
    if (gdefcore_id_canonical(text, len, canon) != GDEFCORE_OK ||
        memcmp(canon, text, GDEFCORE_PUBLIC_ID_LEN) != 0 ||
        len != GDEFCORE_PUBLIC_ID_LEN) {
      return GDEFCORE_ERR_INVALID;
    }
    out->bytes = (const uint8_t *)text;
    out->len = len;
    return GDEFCORE_OK;
  }
  case GDEFSTOR_FIELD_INTEGER:
    return parse_integer(text, len, &out->integer) ? GDEFCORE_OK
                                                    : GDEFCORE_ERR_INVALID;
  case GDEFSTOR_FIELD_DECIMAL:
    if (scale < 0 || scale > GDEFSTOR_MODEL_MAX_SCALE) {
      return GDEFCORE_ERR_INVALID;
    }
    return parse_decimal(text, len, scale, &out->integer) ? GDEFCORE_OK
                                                           : GDEFCORE_ERR_INVALID;
  case GDEFSTOR_FIELD_FLOAT:
    return parse_float(text, len, &out->real) ? GDEFCORE_OK
                                               : GDEFCORE_ERR_INVALID;
  case GDEFSTOR_FIELD_BOOLEAN:
    if (span_eq(text, len, "true", 4)) {
      out->integer = 1;
      return GDEFCORE_OK;
    }
    if (span_eq(text, len, "false", 5)) {
      out->integer = 0;
      return GDEFCORE_OK;
    }
    return GDEFCORE_ERR_INVALID;
  case GDEFSTOR_FIELD_DATE:
    return len == 10 && parse_date_at(text, len, &out->integer)
               ? GDEFCORE_OK
               : GDEFCORE_ERR_INVALID;
  case GDEFSTOR_FIELD_DATETIME:
    return parse_datetime(text, len, &out->integer) ? GDEFCORE_OK
                                                     : GDEFCORE_ERR_INVALID;
  default:
    return GDEFCORE_ERR_INVALID;
  }
}

int gdefcore_value_compare(const GDEFSTOR_Value * a, const GDEFSTOR_Value * b) {
  if (a == NULL || b == NULL) {
    return 0;
  }
  if (a->type == 0 || b->type == 0) {
    return (a->type != 0) - (b->type != 0);
  }
  switch (a->type) {
  case GDEFSTOR_FIELD_TEXT:
  case GDEFSTOR_FIELD_REFERENCE: {
    size_t n = a->len < b->len ? a->len : b->len;
    int c = n == 0 ? 0 : memcmp(a->bytes, b->bytes, n);
    if (c != 0) {
      return c < 0 ? -1 : 1;
    }
    return a->len < b->len ? -1 : (a->len > b->len ? 1 : 0);
  }
  case GDEFSTOR_FIELD_FLOAT:
    return a->real < b->real ? -1 : (a->real > b->real ? 1 : 0);
  default:
    return a->integer < b->integer ? -1 : (a->integer > b->integer ? 1 : 0);
  }
}

/* The canonical text of a value of a field of @p scale. */
static GDEFCORE_Result render(const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Value * v, int scale, GDEFCORE_Text * out) {
  char buf[64];
  int n = 0;
  memset(out, 0, sizeof *out);
  switch (v->type) {
  case GDEFSTOR_FIELD_TEXT:
  case GDEFSTOR_FIELD_REFERENCE:
    return text_set(alloc, out, (const char *)v->bytes, v->len);
  case GDEFSTOR_FIELD_INTEGER:
    n = snprintf(buf, sizeof buf, "%lld", (long long)v->integer);
    break;
  case GDEFSTOR_FIELD_DECIMAL: {
    uint64_t mag = v->integer < 0 ? (uint64_t)(-(v->integer + 1)) + 1u
                                  : (uint64_t)v->integer;
    uint64_t p = 1;
    int k;
    for (k = 0; k < scale; k++) {
      p *= 10u;
    }
    if (scale == 0) {
      n = snprintf(buf, sizeof buf, "%s%llu", v->integer < 0 ? "-" : "",
          (unsigned long long)mag);
    } else {
      n = snprintf(buf, sizeof buf, "%s%llu.%0*llu", v->integer < 0 ? "-" : "",
          (unsigned long long)(mag / p), scale, (unsigned long long)(mag % p));
    }
    break;
  }
  case GDEFSTOR_FIELD_FLOAT: {
    /* The shortest digits that read back as the same double, with the
     * locale's decimal point put back to a `.`. */
    const char * point = localeconv()->decimal_point;
    int prec;
    char tmp[64];
    for (prec = 1; prec <= 17; prec++) {
      double back;
      n = snprintf(buf, sizeof buf, "%.*g", prec, v->real);
      if (n <= 0 || (size_t)n >= sizeof buf) {
        return GDEFCORE_ERR_INTERNAL;
      }
      back = strtod(buf, NULL);
      if (back == v->real) {
        break;
      }
    }
    if (point != NULL && point[0] != '\0' && strcmp(point, ".") != 0) {
      const char * at = strstr(buf, point);
      if (at != NULL) {
        size_t pre = (size_t)(at - buf);
        int m = snprintf(tmp, sizeof tmp, "%.*s.%s", (int)pre, buf,
            at + strlen(point));
        if (m <= 0 || (size_t)m >= sizeof tmp) {
          return GDEFCORE_ERR_INTERNAL;
        }
        memcpy(buf, tmp, (size_t)m + 1);
        n = m;
      }
    }
    break;
  }
  case GDEFSTOR_FIELD_BOOLEAN:
    n = snprintf(buf, sizeof buf, "%s", v->integer ? "true" : "false");
    break;
  case GDEFSTOR_FIELD_DATE: {
    int64_t y;
    unsigned m;
    unsigned d;
    civil_from_days(v->integer, &y, &m, &d);
    n = snprintf(buf, sizeof buf, "%04lld-%02u-%02u", (long long)y, m, d);
    break;
  }
  case GDEFSTOR_FIELD_DATETIME: {
    int64_t ms = v->integer;
    int64_t days = ms >= 0 ? ms / 86400000 : -((-ms + 86399999) / 86400000);
    int64_t rest = ms - days * 86400000;
    int64_t y;
    unsigned m;
    unsigned d;
    civil_from_days(days, &y, &m, &d);
    if (rest % 1000 == 0) {
      n = snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02u:%02u:%02uZ",
          (long long)y, m, d, (unsigned)(rest / 3600000),
          (unsigned)(rest / 60000 % 60), (unsigned)(rest / 1000 % 60));
    } else {
      n = snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02u:%02u:%02u.%03uZ",
          (long long)y, m, d, (unsigned)(rest / 3600000),
          (unsigned)(rest / 60000 % 60), (unsigned)(rest / 1000 % 60),
          (unsigned)(rest % 1000));
    }
    break;
  }
  default:
    return GDEFCORE_ERR_CORRUPT;
  }
  if (n <= 0 || (size_t)n >= sizeof buf) {
    return GDEFCORE_ERR_INTERNAL;
  }
  return text_set(alloc, out, buf, (size_t)n);
}

GDEFCORE_Result gdefcore_ent_value_check(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Decl * decl, const char * text, size_t len,
    GDEFCORE_Text * out_canonical) {
  GDEFSTOR_Value v;
  GDEFCORE_Result rc;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  int type = decl->personal ? GDEFSTOR_FIELD_TEXT : decl->type;
  if (type == GDEFSTOR_FIELD_REFERENCE &&
      gdefcore_id_canonical(text, len, canon) == GDEFCORE_OK) {
    /* A reference is written in any spelling of an id, kept canonical. */
    text = canon;
    len = GDEFCORE_PUBLIC_ID_LEN;
  }
  rc = gdefcore_value_parse(type, decl->scale, text, len, &v);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return render(alloc, &v, decl->scale, out_canonical);
}

/* ---- entities ------------------------------------------------------------- */

GDEFCORE_Result gdefcore_ent_lookup(GDEFCORE_Catalog * cat, const char * canon,
    GDEFCORE_EntLook * out) {
  GDEFSTOR_Entity * e = NULL;
  GDEFSTOR_Draft * d = NULL;
  GDEFSTOR_Result src;
  memset(out, 0, sizeof *out);
  src = gdefstor_entity_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, canon, GDEFCORE_PUBLIC_ID_LEN, &e);
  if (src == GDEFSTOR_OK) {
    GDEFSTOR_EntityInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefstor_entity_info(e, &info) != GDEFSTOR_OK ||
        info.type_len >= sizeof out->type ||
        info.creator_len >= sizeof out->creator) {
      gdefstor_entity_free(e);
      return GDEFCORE_ERR_CORRUPT;
    }
    out->exists = 1;
    memcpy(out->type, info.type, info.type_len);
    out->type_len = info.type_len;
    memcpy(out->creator, info.creator, info.creator_len);
    out->creator_len = info.creator_len;
    out->revision = info.revision;
    out->published = info.published != 0;
    out->deleted = info.deleted != 0;
    gdefstor_entity_free(e);
  } else if (src != GDEFSTOR_ERR_INVALID) {
    return gdefcore_ent_map(src);
  }
  src = gdefstor_draft_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, canon, GDEFCORE_PUBLIC_ID_LEN, &d);
  if (src == GDEFSTOR_OK) {
    GDEFSTOR_DraftInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefstor_draft_info(d, &info) != GDEFSTOR_OK) {
      gdefstor_draft_free(d);
      return GDEFCORE_ERR_CORRUPT;
    }
    out->has_draft = 1;
    out->draft_base = info.base_revision;
    if (!out->exists) {
      if (info.type_len >= sizeof out->type) {
        gdefstor_draft_free(d);
        return GDEFCORE_ERR_CORRUPT;
      }
      out->reserved = 1;
      memcpy(out->type, info.type, info.type_len);
      out->type_len = info.type_len;
    }
    gdefstor_draft_free(d);
  } else if (src != GDEFSTOR_ERR_INVALID) {
    return gdefcore_ent_map(src);
  }
  if (!out->exists && !out->reserved) {
    return GDEFCORE_ERR_INVALID;
  }
  out->type[out->type_len] = '\0';
  out->creator[out->creator_len] = '\0';
  return GDEFCORE_OK;
}

static GDEFCORE_Lang * doc_lang(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Doc * doc, const char * lang, size_t lang_len, int add) {
  size_t i;
  GDEFCORE_Lang * next;
  for (i = 0; i < doc->nlangs; i++) {
    if (span_eq(doc->langs[i].lang.p, doc->langs[i].lang.n, lang, lang_len)) {
      return &doc->langs[i];
    }
  }
  if (!add) {
    return NULL;
  }
  next = (GDEFCORE_Lang *)gcu_allocator_realloc(alloc, doc->langs,
      (doc->nlangs + 1) * sizeof *next);
  if (next == NULL) {
    return NULL;
  }
  doc->langs = next;
  memset(&doc->langs[doc->nlangs], 0, sizeof doc->langs[doc->nlangs]);
  if (text_set(alloc, &doc->langs[doc->nlangs].lang, lang, lang_len) !=
      GDEFCORE_OK) {
    return NULL;
  }
  doc->nlangs += 1;
  return &doc->langs[doc->nlangs - 1];
}

/* Append a value to field @p name of a language; @p has_id: it is an item
 * of a multiple field, with id @p id. */
GDEFCORE_Result gdefcore_ent_lang_add(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Lang * l, const char * name, size_t name_len,
    const GDEFCORE_Text * value, int has_id, uint64_t id) {
  GDEFCORE_Vals * slot = NULL;
  GDEFCORE_Text * vals;
  size_t i;
  for (i = 0; i < l->nfields; i++) {
    if (span_eq(l->fields[i].name.p, l->fields[i].name.n, name, name_len)) {
      slot = &l->fields[i];
      break;
    }
  }
  if (slot == NULL) {
    GDEFCORE_Vals * next = (GDEFCORE_Vals *)gcu_allocator_realloc(alloc,
        l->fields, (l->nfields + 1) * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    l->fields = next;
    slot = &l->fields[l->nfields];
    memset(slot, 0, sizeof *slot);
    if (text_set(alloc, &slot->name, name, name_len) != GDEFCORE_OK) {
      return GDEFCORE_ERR_OOM;
    }
    l->nfields += 1;
  }
  if (has_id && (slot->ids != NULL || slot->nvals == 0)) {
    uint64_t * ids = (uint64_t *)gcu_allocator_realloc(alloc, slot->ids,
        (slot->nvals + 1) * sizeof *ids);
    if (ids == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    slot->ids = ids;
    slot->ids[slot->nvals] = id;
  } else if (slot->ids != NULL) {
    return GDEFCORE_ERR_CORRUPT; /* a single value among items */
  }
  vals = (GDEFCORE_Text *)gcu_allocator_realloc(alloc, slot->vals,
      (slot->nvals + 1) * sizeof *vals);
  if (vals == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  slot->vals = vals;
  slot->vals[slot->nvals] = *value;
  slot->nvals += 1;
  return GDEFCORE_OK;
}

/* The port's description of the field at @p path, or CORRUPT. */
static GDEFCORE_Result field_at(const GDEFSTOR_Type * type, const char * path,
    size_t path_len, GDEFSTOR_FieldInfo * info) {
  size_t fi = 0;
  memset(info, 0, sizeof *info);
  info->size = sizeof *info;
  if (gdefstor_type_find(type, path, path_len, &fi) != GDEFSTOR_OK ||
      gdefstor_type_field(type, fi, info) != GDEFSTOR_OK) {
    return GDEFCORE_ERR_CORRUPT;
  }
  return GDEFCORE_OK;
}

/* The path of every item of a port tree: the path of the field it sits
 * under ("" for the root). A parent comes before its children. */
static GDEFCORE_Result port_paths(const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Tree * tree, GDEFCORE_Text ** out) {
  size_t n = gdefstor_tree_item_count(tree);
  GDEFCORE_Text * paths;
  size_t i;
  *out = NULL;
  paths = (GDEFCORE_Text *)gcu_allocator_calloc(alloc, n == 0 ? 1 : n,
      sizeof *paths);
  if (paths == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    GDEFSTOR_TreeItem it;
    const GDEFCORE_Text * up;
    size_t len;
    char * p;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefstor_tree_item(tree, i, &it) != GDEFSTOR_OK ||
        (i > 0 && it.parent >= i)) {
      size_t k;
      for (k = 0; k < i; k++) {
        text_clear(alloc, &paths[k]);
      }
      gcu_allocator_free(alloc, paths);
      return GDEFCORE_ERR_CORRUPT;
    }
    up = i == 0 ? NULL : &paths[it.parent];
    len = i == 0 ? 0
                 : up->n + (up->n > 0 ? 1 : 0) + it.field_len;
    p = (char *)gcu_allocator_malloc(alloc, len + 1);
    if (p == NULL) {
      size_t k;
      for (k = 0; k < i; k++) {
        text_clear(alloc, &paths[k]);
      }
      gcu_allocator_free(alloc, paths);
      return GDEFCORE_ERR_OOM;
    }
    if (up != NULL && up->n > 0) {
      memcpy(p, up->p, up->n);
      p[up->n] = '.';
    }
    if (i > 0) {
      memcpy(p + len - it.field_len, it.field, it.field_len);
    }
    p[len] = '\0';
    paths[i].p = p;
    paths[i].n = len;
  }
  *out = paths;
  return GDEFCORE_OK;
}

static void paths_free(const GDEFCORE_Allocator * alloc, GDEFCORE_Text * paths,
    size_t n) {
  size_t i;
  for (i = 0; paths != NULL && i < n; i++) {
    text_clear(alloc, &paths[i]);
  }
  gcu_allocator_free(alloc, paths);
}

/* The path of value @p field of an item at @p item_path. */
static GDEFCORE_Result join_path(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Text * item_path, const char * field, size_t field_len,
    GDEFCORE_Text * out) {
  size_t n = item_path->n + (item_path->n > 0 && field_len > 0 ? 1 : 0) +
             field_len;
  char * p = (char *)gcu_allocator_malloc(alloc, n + 1);
  memset(out, 0, sizeof *out);
  if (p == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (item_path->n > 0) {
    memcpy(p, item_path->p, item_path->n);
  }
  if (item_path->n > 0 && field_len > 0) {
    p[item_path->n] = '.';
  }
  if (field_len > 0) {
    memcpy(p + n - field_len, field, field_len);
  }
  p[n] = '\0';
  out->p = p;
  out->n = n;
  return GDEFCORE_OK;
}

/*
 * A tree's values into language @p l of a doc, each in its canonical text:
 * the root's values and the items of the root's multiple fields (with their
 * ids) as the language's fields, and every item of a group, at any depth,
 * into the language's group tree, under its id (story S6d).
 */
static GDEFCORE_Result tree_into(const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Type * type, const GDEFSTOR_Tree * tree, GDEFCORE_Lang * l) {
  size_t items = gdefstor_tree_item_count(tree);
  GDEFCORE_Text * paths = NULL;
  size_t * gmap = NULL;
  size_t i;
  GDEFCORE_Result rc = port_paths(alloc, tree, &paths);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  gmap = (size_t *)gcu_allocator_calloc(alloc, items == 0 ? 1 : items,
      sizeof *gmap);
  if (gmap == NULL) {
    paths_free(alloc, paths, items);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; rc == GDEFCORE_OK && i < items; i++) {
    GDEFSTOR_TreeItem it;
    GDEFSTOR_FieldInfo under;
    size_t k;
    size_t gi = SIZE_MAX;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    gmap[i] = SIZE_MAX;
    if (gdefstor_tree_item(tree, i, &it) != GDEFSTOR_OK) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    memset(&under, 0, sizeof under);
    if (i > 0) {
      rc = field_at(type, paths[i].p, paths[i].n, &under);
      if (rc != GDEFCORE_OK) {
        break;
      }
    }
    if (i > 0 && (it.parent != 0 || under.type == GDEFSTOR_FIELD_GROUP)) {
      /* An item of a group, or anything under one: the language's groups. */
      size_t parent = it.parent == 0 ? 0 : gmap[it.parent];
      if (parent == SIZE_MAX) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      if (l->groups == NULL) {
        rc = gdefcore_ent_tree_new(alloc, &l->groups);
        if (rc != GDEFCORE_OK) {
          break;
        }
      }
      rc = gdefcore_tree_add(l->groups, parent, it.field, it.field_len, it.id,
          &gi);
      if (rc != GDEFCORE_OK) {
        break;
      }
      gmap[i] = gi;
    }
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * field = NULL;
      size_t field_len = 0;
      GDEFSTOR_Value v;
      GDEFCORE_Text text;
      GDEFCORE_Text path;
      GDEFSTOR_FieldInfo info;
      memset(&v, 0, sizeof v);
      if (gdefstor_tree_value(tree, i, k, &field, &field_len, &v) !=
          GDEFSTOR_OK) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      if (v.type == 0) {
        continue;
      }
      rc = join_path(alloc, &paths[i], field, field_len, &path);
      if (rc != GDEFCORE_OK) {
        break;
      }
      rc = field_at(type, path.p, path.n, &info);
      text_clear(alloc, &path);
      if (rc != GDEFCORE_OK) {
        break;
      }
      rc = render(alloc, &v, info.scale, &text);
      if (rc != GDEFCORE_OK) {
        break;
      }
      if (gi != SIZE_MAX) {
        rc = gdefcore_ent_tree_put(l->groups, gi, field, field_len, text.p,
            text.n, (const char *)v.subject, v.subject_len);
        text_clear(alloc, &text);
      } else if (i > 0) {
        /* A multiple's item: its own value, under the field it sits in. */
        rc = gdefcore_ent_lang_add(alloc, l, it.field, it.field_len, &text, 1,
            it.id);
        if (rc != GDEFCORE_OK) {
          text_clear(alloc, &text);
        }
      } else {
        rc = gdefcore_ent_lang_add(alloc, l, field, field_len, &text, 0, 0);
        if (rc != GDEFCORE_OK) {
          text_clear(alloc, &text);
        }
      }
    }
  }
  gcu_allocator_free(alloc, gmap);
  paths_free(alloc, paths, items);
  return rc;
}

static GDEFCORE_Result load_port_type(GDEFCORE_Catalog * cat, const char * name,
    size_t name_len, GDEFSTOR_Type ** out) {
  return gdefcore_ent_map(gdefstor_type_get(cat->store,
      (const char *)cat->tenant, cat->tenant_len, name, name_len, out));
}

/* Replace (or add) language @p lang of @p doc with @p tree's values. */
static GDEFCORE_Result doc_put_tree(const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Type * type, GDEFCORE_Doc * doc, const char * lang,
    size_t lang_len, const GDEFSTOR_Tree * tree) {
  GDEFCORE_Lang * l = doc_lang(alloc, doc, lang, lang_len, 1);
  size_t j;
  size_t k;
  if (l == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (j = 0; j < l->nfields; j++) {
    for (k = 0; k < l->fields[j].nvals; k++) {
      text_clear(alloc, &l->fields[j].vals[k]);
    }
    gcu_allocator_free(alloc, l->fields[j].vals);
    gcu_allocator_free(alloc, l->fields[j].ids);
    text_clear(alloc, &l->fields[j].name);
  }
  gcu_allocator_free(alloc, l->fields);
  l->fields = NULL;
  l->nfields = 0;
  gdefcore_tree_free(l->groups);
  l->groups = NULL;
  return tree_into(alloc, type, tree, l);
}

GDEFCORE_Result gdefcore_ent_read_doc(GDEFCORE_Catalog * cat,
    const char * canon, uint64_t revision, int draft, GDEFCORE_Doc * out) {
  GDEFCORE_EntLook look;
  GDEFSTOR_Type * type = NULL;
  GDEFSTOR_Languages * langs = NULL;
  GDEFCORE_Result rc;
  size_t i;
  memset(out, 0, sizeof *out);
  rc = gdefcore_ent_lookup(cat, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_port_type(cat, look.type, look.type_len, &type);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* A cleared entity reads as one with no content now; its history stays. */
  if (look.exists && look.revision > 0 && revision <= look.revision &&
      !(revision == 0 && look.deleted)) {
    rc = gdefcore_ent_map(gdefstor_entity_languages(cat->store,
        (const char *)cat->tenant, cat->tenant_len, canon,
        GDEFCORE_PUBLIC_ID_LEN, revision, &langs));
    for (i = 0; rc == GDEFCORE_OK && i < gdefstor_languages_count(langs); i++) {
      const char * lang = NULL;
      size_t lang_len = 0;
      GDEFSTOR_Tree * tree = NULL;
      if (gdefstor_languages_get(langs, i, &lang, &lang_len) != GDEFSTOR_OK) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      rc = gdefcore_ent_map(gdefstor_entity_tree(cat->store,
          (const char *)cat->tenant, cat->tenant_len, canon,
          GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, revision, &tree));
      if (rc == GDEFCORE_OK) {
        rc = doc_put_tree(cat->alloc, type, out, lang, lang_len, tree);
      }
      gdefstor_tree_free(tree);
    }
    gdefstor_languages_free(langs);
  } else if (revision != 0 && (!look.exists || revision > look.revision)) {
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc == GDEFCORE_OK && draft && look.has_draft) {
    GDEFSTOR_Draft * d = NULL;
    GDEFSTOR_DraftInfo info;
    rc = gdefcore_ent_map(gdefstor_draft_get(cat->store,
        (const char *)cat->tenant, cat->tenant_len, canon,
        GDEFCORE_PUBLIC_ID_LEN, &d));
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (rc == GDEFCORE_OK && gdefstor_draft_info(d, &info) != GDEFSTOR_OK) {
      rc = GDEFCORE_ERR_CORRUPT;
    }
    for (i = 0; rc == GDEFCORE_OK && i < info.language_count; i++) {
      GDEFSTOR_DraftTree dt;
      GDEFSTOR_Tree * tree = NULL;
      memset(&dt, 0, sizeof dt);
      dt.size = sizeof dt;
      if (gdefstor_draft_tree(d, i, &dt) != GDEFSTOR_OK) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      rc = gdefcore_ent_map(gdefstor_tree_from_json(type, dt.json, dt.json_len,
          NULL, &tree));
      if (rc == GDEFCORE_OK) {
        rc = doc_put_tree(cat->alloc, type, out, dt.language, dt.language_len,
            tree);
      }
      gdefstor_tree_free(tree);
    }
    gdefstor_draft_free(d);
  }
  gdefstor_type_free(type);
  if (rc != GDEFCORE_OK) {
    gdefcore_ent_doc_free(cat->alloc, out);
  }
  return rc;
}

/* ---- personal values on the port (story S6c) ----------------------------- */

static const GDEFCORE_SealNote * find_note(const GDEFCORE_Seals * seals,
    const char * text, size_t len) {
  size_t i;
  for (i = 0; seals != NULL && i < seals->nnotes; i++) {
    if (span_eq(seals->notes[i].text.p, seals->notes[i].text.n, text, len)) {
      return &seals->notes[i];
    }
  }
  return NULL;
}

static int value_is(const GDEFSTOR_Value * v, const char * text, size_t len) {
  return v->type != 0 && v->subject_len == GDEFCORE_PUBLIC_ID_LEN &&
         span_eq((const char *)v->bytes, v->len, text, len);
}

/* Whether value @p field of an item at @p item_path is the field at @p path. */
static int path_is(const GDEFCORE_Text * item_path, const char * field,
    size_t field_len, const char * path, size_t path_len) {
  if (field_len == 0) {
    return span_eq(item_path->p, item_path->n, path, path_len);
  }
  if (item_path->n == 0) {
    return span_eq(field, field_len, path, path_len);
  }
  return path_len == item_path->n + 1 + field_len &&
         memcmp(path, item_path->p, item_path->n) == 0 &&
         path[item_path->n] == '.' &&
         memcmp(path + item_path->n + 1, field, field_len) == 0;
}

/* Calls @p fn with each value of @p tree of the field at @p path, at any
 * depth (story S6d: a field is its path, not its name), until it returns 1. */
typedef int (*ValueFn)(const GDEFSTOR_Value * v, void * user);

static int each_value_at(const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Tree * tree, const char * path, size_t path_len,
    ValueFn fn, void * user) {
  size_t n = tree == NULL ? 0 : gdefstor_tree_item_count(tree);
  GDEFCORE_Text * paths = NULL;
  size_t i;
  int hit = 0;
  if (n == 0 || port_paths(alloc, tree, &paths) != GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < n && !hit; i++) {
    GDEFSTOR_TreeItem it;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefstor_tree_item(tree, i, &it) != GDEFSTOR_OK) {
      break;
    }
    for (k = 0; k < it.value_count && !hit; k++) {
      const char * f = NULL;
      size_t fn_len = 0;
      GDEFSTOR_Value v;
      memset(&v, 0, sizeof v);
      if (gdefstor_tree_value(tree, i, k, &f, &fn_len, &v) != GDEFSTOR_OK) {
        continue;
      }
      if (path_is(&paths[i], f, fn_len, path, path_len)) {
        hit = fn(&v, user);
      }
    }
  }
  paths_free(alloc, paths, n);
  return hit;
}

typedef struct SubjectAsk {
  const char * text;
  size_t len;
  char * out;
} SubjectAsk;

static int subject_of(const GDEFSTOR_Value * v, void * user) {
  SubjectAsk * a = (SubjectAsk *)user;
  if (!value_is(v, a->text, a->len)) {
    return 0;
  }
  memcpy(a->out, v->subject, GDEFCORE_PUBLIC_ID_LEN);
  a->out[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  return 1;
}

/* The subject @p tree gives @p text as a value of the field at @p path, at
 * any depth, copied to @p out. 0 when it holds no such value. */
static int tree_subject(const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Tree * tree, const char * path, size_t path_len,
    const char * text, size_t len, char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  SubjectAsk a;
  a.text = text;
  a.len = len;
  a.out = out;
  return each_value_at(alloc, tree, path, path_len, subject_of, &a);
}

typedef struct ProbeAsk {
  GDEFCORE_Seals * seals;
  const char * path;
  size_t path_len;
  const char * text;
  size_t len;
  char * subject;
  uint8_t * mac;
} ProbeAsk;

static int probe_one(const GDEFSTOR_Value * v, void * user) {
  ProbeAsk * a = (ProbeAsk *)user;
  if (v->type == 0 || v->subject_len != GDEFCORE_PUBLIC_ID_LEN) {
    return 0;
  }
  if (gdefcore_subject_mac_sealed(a->seals->subjects, (const char *)v->subject,
          v->subject_len, a->path, a->path_len, a->text, a->len, a->mac) !=
      GDEFCORE_OK) {
    return 0;
  }
  memcpy(a->subject, v->subject, GDEFCORE_PUBLIC_ID_LEN);
  a->subject[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  return 1;
}

/*
 * A sealed text no tree and no note names: whose it is, proven by opening it.
 * The seal binds the subject and the field (encrypt_value()'s associated
 * data), so a text that opens under the key of a subject the field holds now,
 * or in the draft, is that subject's value (a patch carries sealed texts and
 * no subjects). Its MAC comes with the opening. 0 when none opens it. The
 * field is its path, which is what a seal binds (story S6d: a field inside a
 * group is sealed as `group.field`, and its values are found at every depth).
 */
static int probe_subject(GDEFCORE_Seals * seals, const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Tree * tree, const char * path, size_t path_len,
    const char * text, size_t len, char subject[GDEFCORE_PUBLIC_ID_LEN + 1],
    uint8_t mac[GDEFSTOR_BLIND_MAC_BYTES]) {
  ProbeAsk a;
  if (seals->subjects == NULL) {
    return 0;
  }
  a.seals = seals;
  a.path = path;
  a.path_len = path_len;
  a.text = text;
  a.len = len;
  a.subject = subject;
  a.mac = mac;
  return each_value_at(alloc, tree, path, path_len, probe_one, &a);
}

/*
 * The subject of personal value @p text of the field at @p path, and for a
 * save its MAC (GDEFCORE_Seals says where each comes from). @p same_place: the
 * current tree holds this text at this place, so the value is unchanged and
 * the port carries its blind row, if it gets a new version at all.
 * @p source: the value of the field's declared subject field in the same item
 * (story S6d), which is then the subject; NULL when the field names its
 * subjects value by value.
 */
static GDEFCORE_Result seal_value(GDEFCORE_Seals * seals,
    const GDEFCORE_Allocator * alloc, const GDEFSTOR_Tree * now,
    const GDEFSTOR_Tree * draft, const char * path, size_t path_len,
    const char * text, size_t len, int same_place, const GDEFCORE_Text * source,
    char subject[GDEFCORE_PUBLIC_ID_LEN + 1],
    uint8_t mac[GDEFSTOR_BLIND_MAC_BYTES], int * out_has_mac) {
  const GDEFCORE_SealNote * note = find_note(seals, text, len);
  int erased = 0;
  int opened = 0;
  GDEFCORE_Result rc;
  *out_has_mac = 0;
  if (source != NULL) {
    /* The declaration names the subject: the reference in the same item. */
    if (source->n != GDEFCORE_PUBLIC_ID_LEN) {
      seals->unknown = 1;
      return GDEFCORE_ERR_INVALID;
    }
    memcpy(subject, source->p, GDEFCORE_PUBLIC_ID_LEN);
    subject[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  } else if (tree_subject(alloc, now, path, path_len, text, len, subject)) {
    /* A value the entity holds: its subject is the one stored with it. */
  } else if (note != NULL) {
    memcpy(subject, note->subject, GDEFCORE_PUBLIC_ID_LEN + 1);
  } else if (tree_subject(alloc, draft, path, path_len, text, len, subject)) {
    /* A value the entity's draft holds, with the subject it recorded. */
  } else if (probe_subject(seals, alloc, now, path, path_len, text, len,
                 subject, mac) ||
             probe_subject(seals, alloc, draft, path, path_len, text, len,
                 subject, mac)) {
    opened = 1;
  } else {
    /* A sealed text from nowhere: nothing says whose it is (AD-19). */
    seals->unknown = 1;
    return GDEFCORE_ERR_INVALID;
  }
  if (!seals->index || same_place) {
    return GDEFCORE_OK;
  }
  /* A new version of the value, so a new blind row, and only while the
   * subject's key exists: asked here, inside the write, so that an erasure
   * whose blind deletion ran before this write began is seen. */
  if (seals->subjects == NULL) {
    seals->unknown = 1;
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_subject_erased(seals->subjects, subject, GDEFCORE_PUBLIC_ID_LEN,
      &erased);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (erased) {
    seals->erased = 1;
    return GDEFCORE_ERR_INVALID;
  }
  if (opened) {
    /* The MAC came with the opening. */
  } else if (note != NULL && note->has_mac &&
      span_eq(note->subject, GDEFCORE_PUBLIC_ID_LEN, subject,
          GDEFCORE_PUBLIC_ID_LEN)) {
    memcpy(mac, note->mac, GDEFSTOR_BLIND_MAC_BYTES);
  } else {
    rc = gdefcore_subject_mac_sealed(seals->subjects, subject,
        GDEFCORE_PUBLIC_ID_LEN, path, path_len, text, len, mac);
    if (rc != GDEFCORE_OK) {
      if (source != NULL && rc == GDEFCORE_ERR_INVALID) {
        /* Not sealed for the subject its item names, or for this field. */
        seals->unknown = 1;
      }
      return rc;
    }
  }
  *out_has_mac = 1;
  return GDEFCORE_OK;
}

/* Set @p value on item @p item, as field @p at (NULL: the item's own value),
 * the field at @p path: for a personal field, with its subject and, where
 * seal_value() gives one, its MAC. */
static GDEFCORE_Result set_value(GDEFSTOR_Tree * tree, size_t item,
    const GDEFSTOR_FieldInfo * info, const char * at, size_t at_len,
    const char * path, size_t path_len, GDEFSTOR_Value * v, const char * text,
    size_t len, GDEFCORE_Seals * seals, const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Tree * now, const GDEFSTOR_Tree * draft, int same_place,
    const GDEFCORE_Text * source) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t mac[GDEFSTOR_BLIND_MAC_BYTES];
  int has_mac = 0;
  GDEFCORE_Result rc;
  if ((info->flags & GDEFSTOR_FIELD_PERSONAL) == 0) {
    return gdefcore_ent_map(gdefstor_tree_set(tree, item, at, at_len, v));
  }
  if (seals == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = seal_value(seals, alloc, now, draft, path, path_len, text, len,
      same_place, source, subject, mac, &has_mac);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  v->subject = (const uint8_t *)subject;
  v->subject_len = GDEFCORE_PUBLIC_ID_LEN;
  rc = gdefcore_ent_map(gdefstor_tree_set(tree, item, at, at_len, v));
  if (rc == GDEFCORE_OK && has_mac) {
    GDEFSTOR_BlindMac m;
    memset(&m, 0, sizeof m);
    m.size = sizeof m;
    m.mac = mac;
    m.mac_len = sizeof mac;
    m.key_id = GDEFCORE_SUBJECT_MAC_KEY_ID;
    m.version = GDEFCORE_SUBJECT_MAC_VERSION;
    rc = gdefcore_ent_map(gdefstor_tree_set_blind(tree, item, at, at_len, &m));
  }
  return rc;
}

/* The ids of a current tree, sorted, each with its index. */
typedef struct IdAt {
  uint64_t id;
  size_t at;
} IdAt;

static int id_cmp(const void * a, const void * b) {
  uint64_t x = ((const IdAt *)a)->id;
  uint64_t y = ((const IdAt *)b)->id;
  return x < y ? -1 : (x > y ? 1 : 0);
}

static GDEFCORE_Result ids_of(const GDEFCORE_Allocator * alloc,
    const GDEFSTOR_Tree * now, IdAt ** out, size_t * out_n) {
  size_t n = now == NULL ? 0 : gdefstor_tree_item_count(now);
  IdAt * ids;
  size_t i;
  *out = NULL;
  *out_n = 0;
  if (n == 0) {
    return GDEFCORE_OK;
  }
  ids = (IdAt *)gcu_allocator_calloc(alloc, n, sizeof *ids);
  if (ids == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    GDEFSTOR_TreeItem it;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefstor_tree_item(now, i, &it) != GDEFSTOR_OK) {
      gcu_allocator_free(alloc, ids);
      return GDEFCORE_ERR_CORRUPT;
    }
    ids[i].id = it.id;
    ids[i].at = i;
  }
  qsort(ids, n, sizeof *ids, id_cmp);
  *out = ids;
  *out_n = n;
  return GDEFCORE_OK;
}

static size_t index_of(const IdAt * ids, size_t n, uint64_t id) {
  IdAt key;
  const IdAt * hit;
  if (id == 0 || n == 0) {
    return SIZE_MAX;
  }
  key.id = id;
  key.at = 0;
  hit = (const IdAt *)bsearch(&key, ids, n, sizeof *ids, id_cmp);
  return hit == NULL ? SIZE_MAX : hit->at;
}

/* Whether item @p at of @p now holds @p text as field @p f (NULL: its own). */
static int now_holds(const GDEFSTOR_Tree * now, size_t at, const char * f,
    size_t fn, const char * text, size_t len) {
  GDEFSTOR_Value was;
  memset(&was, 0, sizeof was);
  return at != SIZE_MAX &&
         gdefstor_tree_get(now, at, f, fn, &was) == GDEFSTOR_OK &&
         value_is(&was, text, len);
}

/* The text of the root's value of field @p name, or NULL. */
static const GDEFCORE_Text * root_value(const GDEFCORE_Lang * l,
    const char * name, size_t name_len) {
  size_t j;
  for (j = 0; j < l->nfields; j++) {
    if (span_eq(l->fields[j].name.p, l->fields[j].name.n, name, name_len) &&
        l->fields[j].nvals == 1) {
      return &l->fields[j].vals[0];
    }
  }
  return NULL;
}

/*
 * The items of a language's groups into port tree @p tree, under their ids
 * (story S6d): each item is added under the item its parent became, so an
 * item named by its id whose values and place are unchanged is unchanged,
 * and one that only moved gets a new order key and nothing else. A retired
 * field, and everything under a retired group, is left out, which keeps it.
 */
static GDEFCORE_Result build_groups(GDEFCORE_Catalog * cat,
    const GDEFSTOR_Type * type, const GDEFCORE_Lang * l, GDEFCORE_Seals * seals,
    const GDEFSTOR_Tree * now, const IdAt * ids, size_t nids,
    const GDEFSTOR_Tree * draft, GDEFSTOR_Tree * tree) {
  const GDEFCORE_Tree * g = l->groups;
  size_t n = gdefcore_tree_item_count(g);
  size_t * map;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (n <= 1) {
    return GDEFCORE_OK;
  }
  map = (size_t *)gcu_allocator_calloc(cat->alloc, n, sizeof *map);
  if (map == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  map[0] = 0;
  for (i = 1; rc == GDEFCORE_OK && i < n; i++) {
    GDEFCORE_TreeItem it;
    GDEFSTOR_FieldInfo under;
    size_t parent;
    size_t item = 0;
    size_t was;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    map[i] = SIZE_MAX;
    if (gdefcore_tree_item(g, i, &it) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_INTERNAL;
      break;
    }
    parent = map[it.parent];
    if (parent == SIZE_MAX) {
      continue; /* under a retired group */
    }
    if (field_at(type, it.path, it.path_len, &under) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    if (under.retired) {
      continue;
    }
    rc = gdefcore_ent_map(gdefstor_tree_add(tree, parent, it.field,
        it.field_len, it.id, &item));
    if (rc != GDEFCORE_OK) {
      break;
    }
    map[i] = item;
    was = index_of(ids, nids, it.id);
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * f = NULL;
      size_t fn = 0;
      const char * text = NULL;
      size_t len = 0;
      GDEFCORE_Text path;
      GDEFSTOR_FieldInfo info;
      GDEFSTOR_Value v;
      GDEFCORE_Text source;
      const GDEFCORE_Text * src = NULL;
      if (gdefcore_tree_value(g, i, k, &f, &fn, &text, &len) != GDEFCORE_OK) {
        rc = GDEFCORE_ERR_INTERNAL;
        break;
      }
      rc = gdefcore_ent_tree_value_path(g, i, f, fn, &path);
      if (rc != GDEFCORE_OK) {
        break;
      }
      if (field_at(type, path.p, path.n, &info) != GDEFCORE_OK) {
        text_clear(cat->alloc, &path);
        rc = GDEFCORE_ERR_INVALID;
        break;
      }
      if (info.retired) {
        text_clear(cat->alloc, &path);
        continue;
      }
      if ((info.flags & GDEFSTOR_FIELD_PERSONAL) != 0 && info.subject != NULL) {
        const char * st = NULL;
        size_t sn = 0;
        if (gdefcore_tree_get(g, fn == 0 ? it.parent : i, info.subject,
                info.subject_len, &st, &sn) == GDEFCORE_OK && st != NULL) {
          source.p = (char *)st;
          source.n = sn;
          src = &source;
        } else {
          source.p = NULL;
          source.n = 0;
          src = &source; /* named, and missing: refused */
        }
      }
      rc = gdefcore_value_parse(info.type, info.scale, text, len, &v);
      if (rc == GDEFCORE_OK) {
        rc = set_value(tree, item, &info, fn == 0 ? NULL : f, fn, path.p,
            path.n, &v, text, len, seals, cat->alloc, now, draft,
            now_holds(now, was, fn == 0 ? NULL : f, fn, text, len), src);
      }
      text_clear(cat->alloc, &path);
    }
  }
  gcu_allocator_free(cat->alloc, map);
  return rc;
}

/* The tree of one language of a doc for a save or a draft. A multiple of the
 * root keeps its items by id when the doc has them (a tree save, a read), else
 * by position: the k-th value goes in the item that holds the k-th value now,
 * so an unchanged list is unchanged. Group items keep their ids (story S6d).
 * Retired fields are left out, which keeps them. */
static GDEFCORE_Result build_tree(GDEFCORE_Catalog * cat,
    const GDEFSTOR_Type * type, const char * canon, int exists,
    const GDEFCORE_Lang * l, GDEFCORE_Seals * seals,
    const GDEFSTOR_Tree * draft, GDEFSTOR_Tree ** out) {
  GDEFSTOR_Tree * tree = NULL;
  GDEFSTOR_Tree * now = NULL;
  IdAt * byid = NULL;
  size_t nbyid = 0;
  GDEFCORE_Result rc;
  size_t j;
  *out = NULL;
  rc = gdefcore_ent_map(gdefstor_tree_create(NULL, &tree));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (exists) {
    GDEFSTOR_Result src = gdefstor_entity_tree(cat->store,
        (const char *)cat->tenant, cat->tenant_len, canon,
        GDEFCORE_PUBLIC_ID_LEN, l->lang.p, l->lang.n, 0, &now);
    if (src != GDEFSTOR_OK && src != GDEFSTOR_ERR_INVALID) {
      gdefstor_tree_free(tree);
      return gdefcore_ent_map(src);
    }
  }
  rc = ids_of(cat->alloc, now, &byid, &nbyid);
  for (j = 0; rc == GDEFCORE_OK && j < l->nfields; j++) {
    const GDEFCORE_Vals * f = &l->fields[j];
    GDEFSTOR_FieldInfo info;
    const GDEFCORE_Text * src = NULL;
    GDEFCORE_Text none;
    size_t k;
    if (field_at(type, f->name.p, f->name.n, &info) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    if (info.retired) {
      continue;
    }
    if ((info.flags & GDEFSTOR_FIELD_PERSONAL) != 0 && info.subject != NULL) {
      /* Story S6d: the subject is the root's value of its subject field. */
      src = root_value(l, info.subject, info.subject_len);
      if (src == NULL) {
        none.p = NULL;
        none.n = 0;
        src = &none;
      }
    }
    if ((info.flags & GDEFSTOR_FIELD_MULTIPLE) == 0) {
      GDEFSTOR_Value v;
      GDEFSTOR_Value was;
      int same = 0;
      if (f->nvals != 1) {
        rc = GDEFCORE_ERR_INVALID;
        break;
      }
      memset(&was, 0, sizeof was);
      if (now != NULL &&
          gdefstor_tree_get(now, 0, f->name.p, f->name.n, &was) == GDEFSTOR_OK) {
        same = value_is(&was, f->vals[0].p, f->vals[0].n);
      }
      rc = gdefcore_value_parse(info.type, info.scale, f->vals[0].p,
          f->vals[0].n, &v);
      if (rc == GDEFCORE_OK) {
        rc = set_value(tree, 0, &info, f->name.p, f->name.n, f->name.p,
            f->name.n, &v, f->vals[0].p, f->vals[0].n, seals, cat->alloc, now,
            draft, same, src);
      }
      continue;
    }
    {
      /* The ids of the items the field holds now, in order. */
      uint64_t ids[256];
      size_t at[256];
      size_t nids = 0;
      size_t count = now == NULL ? 0 : gdefstor_tree_item_count(now);
      size_t i;
      for (i = 1; f->ids == NULL && i < count &&
                  nids < sizeof ids / sizeof ids[0];
           i++) {
        GDEFSTOR_TreeItem it;
        memset(&it, 0, sizeof it);
        it.size = sizeof it;
        if (gdefstor_tree_item(now, i, &it) == GDEFSTOR_OK && it.parent == 0 &&
            span_eq(it.field, it.field_len, f->name.p, f->name.n)) {
          at[nids] = i;
          ids[nids++] = it.id;
        }
      }
      for (k = 0; rc == GDEFCORE_OK && k < f->nvals; k++) {
        GDEFSTOR_Value v;
        size_t item = 0;
        uint64_t id = 0;
        size_t place = SIZE_MAX;
        if (f->ids != NULL) {
          /* By id: a value that moved keeps its item (story S6d). */
          id = f->ids[k];
          place = index_of(byid, nbyid, id);
        } else if (k < nids) {
          id = ids[k];
          place = at[k];
        }
        rc = gdefcore_value_parse(info.type, info.scale, f->vals[k].p,
            f->vals[k].n, &v);
        if (rc == GDEFCORE_OK) {
          rc = gdefcore_ent_map(gdefstor_tree_add(tree, 0, f->name.p,
              f->name.n, id, &item));
        }
        if (rc == GDEFCORE_OK) {
          rc = set_value(tree, item, &info, NULL, 0, f->name.p, f->name.n, &v,
              f->vals[k].p, f->vals[k].n, seals, cat->alloc, now, draft,
              now_holds(now, place, NULL, 0, f->vals[k].p, f->vals[k].n),
              src);
        }
      }
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = build_groups(cat, type, l, seals, now, byid, nbyid, draft, tree);
  }
  gcu_allocator_free(cat->alloc, byid);
  gdefstor_tree_free(now);
  if (rc != GDEFCORE_OK) {
    gdefstor_tree_free(tree);
    return rc;
  }
  *out = tree;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_value_subject(GDEFCORE_Catalog * cat,
    const char * canon, const char * lang, size_t lang_len, const char * field,
    size_t field_len, const char * text, size_t len,
    char out[GDEFCORE_PUBLIC_ID_LEN + 1], int * out_found) {
  GDEFSTOR_Tree * tree = NULL;
  GDEFSTOR_Draft * d = NULL;
  GDEFSTOR_Result src;
  GDEFCORE_Result rc = GDEFCORE_OK;
  *out_found = 0;
  src = gdefstor_entity_tree(cat->store, (const char *)cat->tenant,
      cat->tenant_len, canon, GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, 0, &tree);
  if (src == GDEFSTOR_OK) {
    *out_found = tree_subject(cat->alloc, tree, field, field_len, text, len,
        out);
  } else if (src != GDEFSTOR_ERR_INVALID) {
    return gdefcore_ent_map(src);
  }
  gdefstor_tree_free(tree);
  tree = NULL;
  if (*out_found) {
    return GDEFCORE_OK;
  }
  src = gdefstor_draft_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, canon, GDEFCORE_PUBLIC_ID_LEN, &d);
  if (src == GDEFSTOR_OK) {
    GDEFSTOR_DraftInfo info;
    GDEFSTOR_Type * type = NULL;
    size_t i;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefstor_draft_info(d, &info) != GDEFSTOR_OK) {
      rc = GDEFCORE_ERR_CORRUPT;
    } else {
      rc = load_port_type(cat, info.type, info.type_len, &type);
    }
    for (i = 0; rc == GDEFCORE_OK && !*out_found && i < info.language_count;
         i++) {
      GDEFSTOR_DraftTree dt;
      memset(&dt, 0, sizeof dt);
      dt.size = sizeof dt;
      if (gdefstor_draft_tree(d, i, &dt) != GDEFSTOR_OK) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      if (!span_eq(dt.language, dt.language_len, lang, lang_len)) {
        continue;
      }
      rc = gdefcore_ent_map(gdefstor_tree_from_json(type, dt.json, dt.json_len,
          NULL, &tree));
      if (rc == GDEFCORE_OK) {
        *out_found = tree_subject(cat->alloc, tree, field, field_len, text,
            len, out);
      }
      gdefstor_tree_free(tree);
      tree = NULL;
    }
    gdefstor_type_free(type);
    gdefstor_draft_free(d);
  } else if (src != GDEFSTOR_ERR_INVALID) {
    rc = gdefcore_ent_map(src);
  }
  return rc;
}

/* Every language of a doc as a tree, borrowed by @p out for one call. */
typedef struct Trees {
  GDEFSTOR_Tree ** trees;
  GDEFSTOR_LanguageTree * langs;
  size_t n;
} Trees;

static void trees_free(const GDEFCORE_Allocator * alloc, Trees * t) {
  size_t i;
  for (i = 0; i < t->n; i++) {
    gdefstor_tree_free(t->trees[i]);
  }
  gcu_allocator_free(alloc, t->trees);
  gcu_allocator_free(alloc, t->langs);
  memset(t, 0, sizeof *t);
}

/* The entity's stored draft, one tree per language, for seal_value(): the
 * subjects a draft records for the values it holds. */
typedef struct DraftTrees {
  GDEFSTOR_Tree ** trees;
  char (*langs)[GDEFSTOR_MODEL_MAX_LANGUAGE_BYTES];
  size_t * lang_lens;
  size_t n;
} DraftTrees;

static void draft_trees_free(const GDEFCORE_Allocator * alloc, DraftTrees * d) {
  size_t i;
  for (i = 0; i < d->n; i++) {
    gdefstor_tree_free(d->trees[i]);
  }
  gcu_allocator_free(alloc, d->trees);
  gcu_allocator_free(alloc, d->langs);
  gcu_allocator_free(alloc, d->lang_lens);
  memset(d, 0, sizeof *d);
}

static GDEFCORE_Result draft_trees_load(GDEFCORE_Catalog * cat,
    const GDEFSTOR_Type * type, const char * canon, DraftTrees * out) {
  GDEFSTOR_Draft * d = NULL;
  GDEFSTOR_DraftInfo info;
  GDEFSTOR_Result src;
  GDEFCORE_Result rc = GDEFCORE_OK;
  size_t i;
  memset(out, 0, sizeof *out);
  src = gdefstor_draft_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, canon, GDEFCORE_PUBLIC_ID_LEN, &d);
  if (src == GDEFSTOR_ERR_INVALID) {
    return GDEFCORE_OK; /* no draft */
  }
  if (src != GDEFSTOR_OK) {
    return gdefcore_ent_map(src);
  }
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  if (gdefstor_draft_info(d, &info) != GDEFSTOR_OK) {
    gdefstor_draft_free(d);
    return GDEFCORE_ERR_CORRUPT;
  }
  if (info.language_count > 0) {
    out->trees = (GDEFSTOR_Tree **)gcu_allocator_calloc(cat->alloc,
        info.language_count, sizeof *out->trees);
    out->langs = (char (*)[GDEFSTOR_MODEL_MAX_LANGUAGE_BYTES])gcu_allocator_calloc(
        cat->alloc, info.language_count, sizeof *out->langs);
    out->lang_lens = (size_t *)gcu_allocator_calloc(cat->alloc,
        info.language_count, sizeof *out->lang_lens);
    if (out->trees == NULL || out->langs == NULL || out->lang_lens == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  for (i = 0; rc == GDEFCORE_OK && i < info.language_count; i++) {
    GDEFSTOR_DraftTree dt;
    memset(&dt, 0, sizeof dt);
    dt.size = sizeof dt;
    if (gdefstor_draft_tree(d, i, &dt) != GDEFSTOR_OK ||
        dt.language_len > GDEFSTOR_MODEL_MAX_LANGUAGE_BYTES) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    rc = gdefcore_ent_map(gdefstor_tree_from_json(type, dt.json, dt.json_len,
        NULL, &out->trees[i]));
    if (rc == GDEFCORE_OK) {
      memcpy(out->langs[i], dt.language, dt.language_len);
      out->lang_lens[i] = dt.language_len;
      out->n = i + 1;
    }
  }
  gdefstor_draft_free(d);
  if (rc != GDEFCORE_OK) {
    draft_trees_free(cat->alloc, out);
  }
  return rc;
}

static const GDEFSTOR_Tree * draft_tree_of(const DraftTrees * d,
    const GDEFCORE_Text * lang) {
  size_t i;
  for (i = 0; i < d->n; i++) {
    if (span_eq(d->langs[i], d->lang_lens[i], lang->p, lang->n)) {
      return d->trees[i];
    }
  }
  return NULL;
}

static GDEFCORE_Result doc_trees(GDEFCORE_Catalog * cat,
    const GDEFSTOR_Type * type, const char * canon, int exists,
    const GDEFCORE_Doc * doc, GDEFCORE_Seals * seals, Trees * out) {
  DraftTrees drafts;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  memset(out, 0, sizeof *out);
  memset(&drafts, 0, sizeof drafts);
  if (doc->nlangs == 0) {
    return GDEFCORE_OK;
  }
  if (seals != NULL && seals->with_draft) {
    rc = draft_trees_load(cat, type, canon, &drafts);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  out->trees = (GDEFSTOR_Tree **)gcu_allocator_calloc(cat->alloc, doc->nlangs,
      sizeof *out->trees);
  out->langs = (GDEFSTOR_LanguageTree *)gcu_allocator_calloc(cat->alloc,
      doc->nlangs, sizeof *out->langs);
  if (out->trees == NULL || out->langs == NULL) {
    trees_free(cat->alloc, out);
    draft_trees_free(cat->alloc, &drafts);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < doc->nlangs; i++) {
    rc = build_tree(cat, type, canon, exists, &doc->langs[i], seals,
        draft_tree_of(&drafts, &doc->langs[i].lang), &out->trees[i]);
    if (rc != GDEFCORE_OK) {
      trees_free(cat->alloc, out);
      draft_trees_free(cat->alloc, &drafts);
      return rc;
    }
    out->n = i + 1;
    out->langs[i].size = sizeof out->langs[i];
    out->langs[i].language = doc->langs[i].lang.p;
    out->langs[i].language_len = doc->langs[i].lang.n;
    out->langs[i].tree = out->trees[i];
  }
  draft_trees_free(cat->alloc, &drafts);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_save_doc(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * canon, const char * type_name,
    size_t type_len, uint64_t base, const GDEFSTOR_RevisionMeta * meta,
    const GDEFCORE_Doc * doc, GDEFCORE_Seals * seals, uint64_t * out_revision,
    int * out_conflict) {
  GDEFSTOR_Type * type = NULL;
  Trees t;
  GDEFSTOR_Result src;
  GDEFCORE_Result rc = load_port_type(cat, type_name, type_len, &type);
  *out_revision = 0;
  *out_conflict = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = doc_trees(cat, type, canon, 1, doc, seals, &t);
  gdefstor_type_free(type);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  src = gdefstor_entity_save_languages(write, canon, GDEFCORE_PUBLIC_ID_LEN,
      base, meta, t.langs, t.n, out_revision);
  trees_free(cat->alloc, &t);
  if (src == GDEFSTOR_ERR_CONFLICT) {
    /* The head moved since the op was staged: nothing was written. */
    *out_conflict = 1;
    return GDEFCORE_OK;
  }
  return gdefcore_ent_map(src);
}

GDEFCORE_Result gdefcore_ent_put_draft(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * canon, const char * type_name,
    size_t type_len, uint64_t base, const GDEFCORE_Doc * doc,
    GDEFCORE_Seals * seals) {
  GDEFSTOR_Type * type = NULL;
  GDEFSTOR_DraftTree * drafts = NULL;
  uint8_t ** jsons = NULL;
  Trees t;
  size_t i;
  GDEFCORE_Result rc = load_port_type(cat, type_name, type_len, &type);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = doc_trees(cat, type, canon, base > 0, doc, seals, &t);
  if (rc == GDEFCORE_OK && t.n > 0) {
    drafts = (GDEFSTOR_DraftTree *)gcu_allocator_calloc(cat->alloc, t.n,
        sizeof *drafts);
    jsons = (uint8_t **)gcu_allocator_calloc(cat->alloc, t.n, sizeof *jsons);
    if (drafts == NULL || jsons == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  for (i = 0; rc == GDEFCORE_OK && i < t.n; i++) {
    size_t len = 0;
    rc = gdefcore_ent_map(gdefstor_tree_to_json(type, t.trees[i], &jsons[i],
        &len));
    drafts[i].size = sizeof drafts[i];
    drafts[i].language = t.langs[i].language;
    drafts[i].language_len = t.langs[i].language_len;
    drafts[i].json = jsons[i];
    drafts[i].json_len = len;
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_ent_map(gdefstor_draft_put(write, type_name, type_len, canon,
        GDEFCORE_PUBLIC_ID_LEN, base, drafts, t.n));
  }
  for (i = 0; jsons != NULL && i < t.n; i++) {
    gdefstor_bytes_free(NULL, jsons[i]);
  }
  gcu_allocator_free(cat->alloc, jsons);
  gcu_allocator_free(cat->alloc, drafts);
  trees_free(cat->alloc, &t);
  gdefstor_type_free(type);
  return rc;
}

/* ---- revisions, versions, ids --------------------------------------------- */

GDEFCORE_Result gdefcore_ent_history(GDEFCORE_Catalog * cat,
    const char * canon, size_t * out_count, size_t index, uint64_t * out_seq,
    char ** out_who, size_t * out_who_len) {
  GDEFSTOR_History * h = NULL;
  GDEFSTOR_RevisionInfo r;
  GDEFCORE_Result rc = gdefcore_ent_map(gdefstor_entity_history(cat->store,
      (const char *)cat->tenant, cat->tenant_len, canon, GDEFCORE_PUBLIC_ID_LEN,
      NULL, 0, &h));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (out_count != NULL) {
    *out_count = gdefstor_history_revision_count(h);
  }
  if (out_seq != NULL) {
    memset(&r, 0, sizeof r);
    r.size = sizeof r;
    if (index >= gdefstor_history_revision_count(h) ||
        gdefstor_history_revision(h, index, &r) != GDEFSTOR_OK) {
      gdefstor_history_free(h);
      return GDEFCORE_ERR_INVALID;
    }
    *out_seq = r.revision;
    if (out_who != NULL) {
      *out_who = NULL;
      if (out_who_len != NULL) {
        *out_who_len = 0;
      }
      if (r.who_len > 0) {
        *out_who = dup_span(cat->alloc, r.who, r.who_len);
        if (*out_who == NULL) {
          gdefstor_history_free(h);
          return GDEFCORE_ERR_OOM;
        }
        if (out_who_len != NULL) {
          *out_who_len = r.who_len;
        }
      }
    }
  }
  gdefstor_history_free(h);
  return GDEFCORE_OK;
}

static int version_name(const char * canon, char out[40], size_t * out_len) {
  int n = snprintf(out, 40, "core.v:%.*s", GDEFCORE_PUBLIC_ID_LEN, canon);
  if (n <= 0 || n >= 40) {
    return 0;
  }
  *out_len = (size_t)n;
  return 1;
}

GDEFCORE_Result gdefcore_ent_version(GDEFCORE_Catalog * cat,
    const char * canon, uint64_t * out) {
  char name[40];
  size_t n = 0;
  if (!version_name(canon, name, &n)) {
    return GDEFCORE_ERR_INTERNAL;
  }
  return gdefcore_ent_map(gdefstor_counter_peek(cat->store,
      (const char *)cat->tenant, cat->tenant_len, name, n, out));
}

GDEFCORE_Result gdefcore_ent_bump(GDEFSTOR_Write * write, const char * canon,
    uint64_t * out) {
  char name[40];
  size_t n = 0;
  uint64_t v = 0;
  if (!version_name(canon, name, &n)) {
    return GDEFCORE_ERR_INTERNAL;
  }
  if (out == NULL) {
    out = &v;
  }
  return gdefcore_ent_map(gdefstor_counter_next(write, name, n, out));
}

GDEFCORE_Result gdefcore_ent_ids(GDEFCORE_Catalog * cat, const char * type,
    size_t type_len, char *** out_ids, size_t * out_count) {
  GDEFSTOR_Query q;
  GDEFSTOR_QueryResult * r = NULL;
  GDEFSTOR_Result src;
  char ** ids;
  size_t n;
  size_t i;
  *out_ids = NULL;
  *out_count = 0;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.language = "en"; /* nothing in this query reads a field */
  q.language_len = 2;
  src = gdefstor_entity_query(cat->store, (const char *)cat->tenant,
      cat->tenant_len, type, type_len, &q, &r);
  if (src == GDEFSTOR_ERR_INVALID) {
    /* A type that was never declared has no entity. */
    return GDEFCORE_OK;
  }
  if (src != GDEFSTOR_OK) {
    return gdefcore_ent_map(src);
  }
  n = gdefstor_query_result_rows(r);
  ids = (char **)gcu_allocator_calloc(cat->alloc, n > 0 ? n : 1, sizeof *ids);
  if (ids == NULL) {
    gdefstor_query_result_free(r);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    const char * e = NULL;
    size_t en = 0;
    if (gdefstor_query_result_entity(r, i, &e, &en) != GDEFSTOR_OK ||
        en != GDEFCORE_PUBLIC_ID_LEN) {
      gdefcore_ids_free(cat, ids, i);
      gdefstor_query_result_free(r);
      return GDEFCORE_ERR_CORRUPT;
    }
    ids[i] = dup_span(cat->alloc, e, en);
    if (ids[i] == NULL) {
      gdefcore_ids_free(cat, ids, i);
      gdefstor_query_result_free(r);
      return GDEFCORE_ERR_OOM;
    }
  }
  gdefstor_query_result_free(r);
  *out_ids = ids;
  *out_count = n;
  return GDEFCORE_OK;
}
