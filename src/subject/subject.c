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
 * Personal values are ciphertext in the tenant store. The subject key, the
 * tenant keyring wrap, the blind index and the erasure ledger stay in the
 * side store. Erasure destroys the key. A restored snapshot still reads as
 * erased because import replays the union of the ledgers first.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/subject.h>

#include "subject_internal.h"

#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/archive/zip.h>
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-storage/core.h>
#include <ghoti.io/defiant-storage/projection.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/text/json.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

enum {
  kVersion = 1,
  kAlg = 1,
  kKeyId = 1,
  kKey = 32,
  kNonce = 12,
  kTag = 16,
  kWrap = 63,
  kMac = 32
};

_Static_assert(kWrap == GDEFCORE_KEYRING_WRAP_LEN, "keyring wrap length");
_Static_assert(kKey == GDEFCORE_SUBJECT_KEY_LEN, "subject key length");
_Static_assert(sizeof GDEFCORE_SUBJECT_ERASED - 1 == GDEFCORE_SUBJECT_ERASED_LEN,
    "erased text");

static const char kWrapType[] = "core.keyring";
static const char kWrapId[] = "wrap";
static const char kSubjectType[] = "core.subject";
static const char kBlindType[] = "core.blind";
static const char kPurpose[] = "subject-wrap";
static const char kHex[] = "0123456789abcdef";

struct GDEFCORE_Subjects {
  const GDEFCORE_Allocator * alloc;
  GDEFSTOR_Store * side;
  uint8_t * tenant;
  size_t tenant_len;
  uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
  GDEFCORE_Keyring * keyring;
};

typedef struct Buf {
  const GDEFCORE_Allocator * alloc;
  char * p;
  size_t n;
  size_t cap;
  int oom;
} Buf;

typedef struct SubjectRow {
  uint8_t * key;
  size_t key_len;
  char * blinds;
  size_t blinds_len;
  char * locs;
  size_t locs_len;
  int present;
} SubjectRow;

static void wipe(void * p, size_t n) {
  if (p != NULL && n > 0) {
    gsec_wipe(p, n);
  }
}

static const GDEFCORE_Allocator * use_alloc(const GDEFCORE_Allocator * alloc) {
  return alloc == NULL ? gdefcore_allocator_default() : alloc;
}

static void * mem(const GDEFCORE_Allocator * alloc, size_t n) {
  return gcu_allocator_malloc(alloc, n == 0 ? 1 : n);
}

static char * dup_n(const GDEFCORE_Allocator * alloc, const void * s, size_t n) {
  char * p = (char *)mem(alloc, n + 1);
  if (p == NULL) {
    return NULL;
  }
  if (n > 0 && s != NULL) {
    memcpy(p, s, n);
  }
  p[n] = '\0';
  return p;
}

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

static GDEFCORE_Result from_stor(GDEFSTOR_Result rc) {
  if (rc == GDEFSTOR_OK) {
    return GDEFCORE_OK;
  }
  if (rc == GDEFSTOR_ERR_LIMIT) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (rc == GDEFSTOR_ERR_OOM) {
    return GDEFCORE_ERR_OOM;
  }
  if (rc == GDEFSTOR_ERR_CORRUPT) {
    return GDEFCORE_ERR_CORRUPT;
  }
  if (rc == GDEFSTOR_ERR_IO) {
    return GDEFCORE_ERR_IO;
  }
  return GDEFCORE_ERR_INVALID;
}

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  if (an != bn) {
    return 0;
  }
  if (an == 0) {
    return 1;
  }
  return a != NULL && b != NULL && memcmp(a, b, an) == 0;
}

static GDEFCORE_Result canon_id(const char * text, size_t len,
    char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  if (text == NULL || gdefcore_id_canonical(text, len, out) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

static void buf_add(Buf * b, const void * s, size_t n) {
  size_t cap;
  char * next;
  if (b->oom || n == 0) {
    return;
  }
  if (b->n > SIZE_MAX - n - 1) {
    b->oom = 1;
    return;
  }
  if (b->n + n + 1 > b->cap) {
    cap = b->cap == 0 ? 64 : b->cap;
    while (cap < b->n + n + 1) {
      if (cap > SIZE_MAX / 2) {
        b->oom = 1;
        return;
      }
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

static void buf_free(Buf * b) {
  gcu_allocator_free(b->alloc, b->p);
  b->p = NULL;
  b->n = 0;
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static GDEFCORE_Result hex_encode(const GDEFCORE_Allocator * alloc,
    const uint8_t * in, size_t n, char ** out, size_t * out_n) {
  char * p;
  size_t i;
  p = (char *)mem(alloc, n * 2 + 1);
  if (p == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    p[i * 2] = kHex[in[i] >> 4];
    p[i * 2 + 1] = kHex[in[i] & 0x0f];
  }
  p[n * 2] = '\0';
  *out = p;
  *out_n = n * 2;
  return GDEFCORE_OK;
}

static GDEFCORE_Result hex_decode(const char * text, size_t n, uint8_t * out,
    size_t out_n) {
  size_t i;
  if (n != out_n * 2) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < out_n; i++) {
    int hi = hex_val(text[i * 2]);
    int lo = hex_val(text[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return GDEFCORE_ERR_INVALID;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return GDEFCORE_OK;
}

static int column_find(const GDEFSTOR_Projection * row, const char * name,
    const uint8_t ** val, size_t * len) {
  size_t n = gdefstor_projection_column_count(row);
  size_t i;
  size_t name_len = strlen(name);
  for (i = 0; i < n; i++) {
    GDEFSTOR_Column col;
    if (gdefstor_projection_column(row, i, &col) != GDEFSTOR_OK) {
      return 0;
    }
    if (col.name_len == name_len && memcmp(col.name, name, name_len) == 0) {
      *val = col.value;
      *len = col.value_len;
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result side_get(GDEFSTOR_Store * side, const uint8_t * tenant,
    size_t tenant_len, const char * type, const char * entity, size_t entity_len,
    GDEFSTOR_Projection ** out) {
  return from_stor(gdefstor_projection_get(side, (const char *)tenant, tenant_len,
      type, strlen(type), entity, entity_len, out));
}

static GDEFCORE_Result side_put(GDEFSTOR_Store * side, const uint8_t * tenant,
    size_t tenant_len, const char * type, const char * entity, size_t entity_len,
    const GDEFSTOR_Column * columns, size_t column_count) {
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc = from_stor(gdefstor_write_begin(side, (const char *)tenant,
      tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_stor(gdefstor_projection_put(write, type, strlen(type), entity,
      entity_len, columns, column_count));
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return from_stor(gdefstor_write_commit(write));
}

static void row_clear(const GDEFCORE_Allocator * alloc, SubjectRow * row) {
  wipe(row->key, row->key_len);
  gcu_allocator_free(alloc, row->key);
  gcu_allocator_free(alloc, row->blinds);
  gcu_allocator_free(alloc, row->locs);
  memset(row, 0, sizeof *row);
}

static GDEFCORE_Result row_load(GDEFCORE_Subjects * subjects, const char * id,
    SubjectRow * row) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t len = 0;
  GDEFCORE_Result rc;
  memset(row, 0, sizeof *row);
  rc = side_get(subjects->side, subjects->tenant, subjects->tenant_len,
      kSubjectType, id, GDEFCORE_PUBLIC_ID_LEN, &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  row->present = 1;
  if (column_find(proj, "key", &val, &len) && len > 0) {
    row->key = (uint8_t *)mem(subjects->alloc, len);
    if (row->key == NULL) {
      gdefstor_projection_free(proj);
      row_clear(subjects->alloc, row);
      return GDEFCORE_ERR_OOM;
    }
    memcpy(row->key, val, len);
    row->key_len = len;
  }
  if (column_find(proj, "blinds", &val, &len)) {
    row->blinds = dup_n(subjects->alloc, val, len);
    row->blinds_len = len;
  } else {
    row->blinds = dup_n(subjects->alloc, "", 0);
    row->blinds_len = 0;
  }
  if (column_find(proj, "locs", &val, &len)) {
    row->locs = dup_n(subjects->alloc, val, len);
    row->locs_len = len;
  } else {
    row->locs = dup_n(subjects->alloc, "", 0);
    row->locs_len = 0;
  }
  gdefstor_projection_free(proj);
  if (row->blinds == NULL || row->locs == NULL) {
    row_clear(subjects->alloc, row);
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result row_store(GDEFCORE_Subjects * subjects, const char * id,
    const SubjectRow * row) {
  GDEFSTOR_Column columns[3];
  size_t n = 0;
  memset(columns, 0, sizeof columns);
  if (row->key != NULL && row->key_len > 0) {
    columns[n].name = "key";
    columns[n].name_len = 3;
    columns[n].value = row->key;
    columns[n].value_len = row->key_len;
    n += 1;
  }
  columns[n].name = "blinds";
  columns[n].name_len = 6;
  columns[n].value = (const uint8_t *)(row->blinds == NULL ? "" : row->blinds);
  columns[n].value_len = row->blinds_len;
  n += 1;
  columns[n].name = "locs";
  columns[n].name_len = 4;
  columns[n].value = (const uint8_t *)(row->locs == NULL ? "" : row->locs);
  columns[n].value_len = row->locs_len;
  n += 1;
  return side_put(subjects->side, subjects->tenant, subjects->tenant_len,
      kSubjectType, id, GDEFCORE_PUBLIC_ID_LEN, columns, n);
}

static GDEFCORE_Result wrap_load(GDEFSTOR_Store * side, const uint8_t * tenant,
    size_t tenant_len, uint8_t * out, int * found) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t len = 0;
  GDEFCORE_Result rc;
  *found = 0;
  rc = side_get(side, tenant, tenant_len, kWrapType, kWrapId, strlen(kWrapId),
      &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!column_find(proj, "bytes", &val, &len) || len != kWrap) {
    gdefstor_projection_free(proj);
    return GDEFCORE_ERR_CORRUPT;
  }
  memcpy(out, val, kWrap);
  *found = 1;
  gdefstor_projection_free(proj);
  return GDEFCORE_OK;
}

static GDEFCORE_Result wrap_store(GDEFSTOR_Store * side, const uint8_t * tenant,
    size_t tenant_len, const uint8_t * bytes) {
  GDEFSTOR_Column column;
  uint8_t existing[kWrap];
  int found = 0;
  GDEFCORE_Result rc = wrap_load(side, tenant, tenant_len, existing, &found);
  wipe(existing, sizeof existing);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (found) {
    return GDEFCORE_OK;
  }
  memset(&column, 0, sizeof column);
  column.name = "bytes";
  column.name_len = 5;
  column.value = bytes;
  column.value_len = kWrap;
  return side_put(side, tenant, tenant_len, kWrapType, kWrapId, strlen(kWrapId),
      &column, 1);
}

static GDEFCORE_Result adopt_wrap(const uint8_t * root, size_t root_len,
    const uint8_t * wrapped, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Keyring ** out) {
  return gdefcore_keyring_adopt(root, root_len, wrapped, kWrap, allocator, out);
}

GDEFCORE_Result gdefcore_subject_bind_keyring(GDEFSTOR_Store * side,
    const uint8_t * tenant, size_t tenant_len, const uint8_t * root,
    size_t root_len, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Keyring ** inout) {
  uint8_t wrapped[kWrap];
  int found = 0;
  GDEFCORE_Keyring * adopted = NULL;
  GDEFCORE_Result rc;
  if (side == NULL || inout == NULL || tenant == NULL || tenant_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = wrap_load(side, tenant, tenant_len, wrapped, &found);
  if (rc != GDEFCORE_OK) {
    wipe(wrapped, sizeof wrapped);
    return rc;
  }
  if (found) {
    rc = adopt_wrap(root, root_len, wrapped, allocator, &adopted);
    wipe(wrapped, sizeof wrapped);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    gdefcore_keyring_destroy(*inout);
    *inout = adopted;
    return GDEFCORE_OK;
  }
  wipe(wrapped, sizeof wrapped);
  if (*inout == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_keyring_export(*inout, wrapped, kWrap);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = wrap_store(side, tenant, tenant_len, wrapped);
  wipe(wrapped, sizeof wrapped);
  return rc;
}

GDEFCORE_Result gdefcore_subject_open(GDEFSTOR_Store * side,
    const uint8_t * tenant, size_t tenant_len, const uint8_t * root,
    size_t root_len, const GDEFCORE_Keyring * keyring,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Subjects ** out) {
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Subjects * subjects;
  uint8_t wrapped[kWrap];
  int found = 0;
  GDEFCORE_Result rc;
  if (side == NULL || out == NULL || tenant == NULL || tenant_len == 0 ||
      root == NULL || root_len != GDEFCORE_ACCOUNT_ROOT_LEN) {
    return GDEFCORE_ERR_INVALID;
  }
  alloc = use_alloc(allocator);
  subjects = (GDEFCORE_Subjects *)mem(alloc, sizeof *subjects);
  if (subjects == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(subjects, 0, sizeof *subjects);
  subjects->alloc = alloc;
  subjects->side = side;
  subjects->tenant = (uint8_t *)mem(alloc, tenant_len);
  if (subjects->tenant == NULL) {
    gcu_allocator_free(alloc, subjects);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(subjects->tenant, tenant, tenant_len);
  subjects->tenant_len = tenant_len;
  memcpy(subjects->root, root, root_len);
  rc = wrap_load(side, tenant, tenant_len, wrapped, &found);
  if (rc != GDEFCORE_OK) {
    wipe(wrapped, sizeof wrapped);
    gdefcore_subject_destroy(subjects);
    return rc;
  }
  if (!found) {
    if (keyring == NULL) {
      wipe(wrapped, sizeof wrapped);
      gdefcore_subject_destroy(subjects);
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_keyring_export(keyring, wrapped, kWrap);
    if (rc == GDEFCORE_OK) {
      rc = wrap_store(side, tenant, tenant_len, wrapped);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = adopt_wrap(root, root_len, wrapped, alloc, &subjects->keyring);
  }
  wipe(wrapped, sizeof wrapped);
  if (rc != GDEFCORE_OK) {
    gdefcore_subject_destroy(subjects);
    return rc;
  }
  *out = subjects;
  return GDEFCORE_OK;
}

void gdefcore_subject_destroy(GDEFCORE_Subjects * subjects) {
  if (subjects == NULL) {
    return;
  }
  gdefcore_keyring_destroy(subjects->keyring);
  wipe(subjects->root, sizeof subjects->root);
  gcu_allocator_free(subjects->alloc, subjects->tenant);
  gcu_allocator_free(subjects->alloc, subjects);
}

void gdefcore_subject_free(GDEFCORE_Subjects * subjects, void * bytes) {
  if (subjects == NULL) {
    return;
  }
  gcu_allocator_free(subjects->alloc, bytes);
}

static GDEFCORE_Result purpose(GDEFCORE_Subjects * subjects, const char * info,
    size_t info_len, uint8_t out[kKey]) {
  return gdefcore_keyring_derive(subjects->keyring, subjects->root,
      GDEFCORE_ACCOUNT_ROOT_LEN, info, info_len, out, kKey);
}

static GDEFCORE_Result seal_key(GDEFCORE_Subjects * subjects,
    const uint8_t raw[kKey], uint8_t wrapped[kWrap]) {
  uint8_t sw[kKey];
  uint8_t nonce[kNonce];
  uint8_t tag[kTag];
  uint8_t aad[13];
  GDEFCORE_Result rc = purpose(subjects, kPurpose, strlen(kPurpose), sw);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_gsec(gsec_random_bytes(nonce, sizeof nonce, NULL));
  if (rc != GDEFCORE_OK) {
    wipe(sw, sizeof sw);
    return rc;
  }
  memcpy(aad, kPurpose, 12);
  aad[12] = kKeyId;
  rc = from_gsec(gsec_aes_gcm_encrypt(sw, kKey, nonce, sizeof nonce, aad,
      sizeof aad, raw, kKey, wrapped + 15, tag, kTag));
  wipe(sw, sizeof sw);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  wrapped[0] = kVersion;
  wrapped[1] = kAlg;
  wrapped[2] = kKeyId;
  memcpy(wrapped + 3, nonce, sizeof nonce);
  memcpy(wrapped + 47, tag, kTag);
  return GDEFCORE_OK;
}

static GDEFCORE_Result open_key(GDEFCORE_Subjects * subjects,
    const uint8_t wrapped[kWrap], uint8_t raw[kKey]) {
  uint8_t sw[kKey];
  uint8_t aad[13];
  GDEFCORE_Result rc;
  if (wrapped[0] != kVersion || wrapped[1] != kAlg || wrapped[2] != kKeyId) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = purpose(subjects, kPurpose, strlen(kPurpose), sw);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memcpy(aad, kPurpose, 12);
  aad[12] = kKeyId;
  rc = from_gsec(gsec_aes_gcm_decrypt(sw, kKey, wrapped + 3, kNonce, aad,
      sizeof aad, wrapped + 15, kKey, raw, wrapped + 47, kTag));
  wipe(sw, sizeof sw);
  return rc;
}

static int now_u64(uint64_t * out) {
  time_t now = time(NULL);
  if (now < 0) {
    return 0;
  }
  *out = (uint64_t)now;
  return 1;
}

static GDEFCORE_Result ledger_load(GDEFCORE_Subjects * subjects, char ** out,
    size_t * out_len) {
  GDEFSTOR_Projection * proj = NULL;
  const uint8_t * val = NULL;
  size_t len = 0;
  GDEFCORE_Result rc = side_get(subjects->side, subjects->tenant,
      subjects->tenant_len, GDEFCORE_SUBJECT_LEDGER_TYPE,
      GDEFCORE_SUBJECT_LEDGER_ID, strlen(GDEFCORE_SUBJECT_LEDGER_ID), &proj);
  if (rc == GDEFCORE_ERR_INVALID) {
    *out = dup_n(subjects->alloc, "", 0);
    *out_len = 0;
    return *out == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!column_find(proj, "text", &val, &len)) {
    val = (const uint8_t *)"";
    len = 0;
  }
  *out = dup_n(subjects->alloc, val, len);
  *out_len = len;
  gdefstor_projection_free(proj);
  return *out == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
}

static int ledger_has(const char * text, size_t n, const char * id) {
  size_t i = 0;
  while (i < n) {
    size_t line = i;
    while (i < n && text[i] != '\n') {
      i += 1;
    }
    if (i - line >= GDEFCORE_PUBLIC_ID_LEN &&
        memcmp(text + line, id, GDEFCORE_PUBLIC_ID_LEN) == 0 &&
        (i - line == GDEFCORE_PUBLIC_ID_LEN ||
            text[line + GDEFCORE_PUBLIC_ID_LEN] == ' ')) {
      return 1;
    }
    if (i < n && text[i] == '\n') {
      i += 1;
    }
  }
  return 0;
}

static int line_span(const char * text, size_t n, size_t * at, size_t * line,
    size_t * len) {
  size_t i = *at;
  if (i >= n) {
    return 0;
  }
  *line = i;
  while (i < n && text[i] != '\n') {
    i += 1;
  }
  *len = i - *line;
  *at = i < n ? i + 1 : i;
  return *len > 0;
}

static int loc_match(const char * line, size_t len, const char * entity,
    const char * field, size_t field_len, const char * lang, size_t lang_len) {
  size_t field_at;
  size_t lang_at;
  if (len < GDEFCORE_PUBLIC_ID_LEN + 1 ||
      memcmp(line, entity, GDEFCORE_PUBLIC_ID_LEN) != 0 ||
      line[GDEFCORE_PUBLIC_ID_LEN] != ' ') {
    return 0;
  }
  field_at = GDEFCORE_PUBLIC_ID_LEN + 1;
  if (len < field_at + field_len + 1 + lang_len) {
    return 0;
  }
  if (memcmp(line + field_at, field, field_len) != 0 ||
      line[field_at + field_len] != ' ') {
    return 0;
  }
  lang_at = field_at + field_len + 1;
  return len - lang_at == lang_len && memcmp(line + lang_at, lang, lang_len) == 0;
}

static int loc_match_any(const char * text, size_t n, const char * entity,
    const char * field, size_t field_len, const char * lang, size_t lang_len);

static void blind_entity(char out[GDEFCORE_PUBLIC_ID_LEN + 64 + 1],
    const char * subject, const char * hex) {
  memcpy(out, subject, GDEFCORE_PUBLIC_ID_LEN);
  memcpy(out + GDEFCORE_PUBLIC_ID_LEN, hex, kMac * 2);
  out[GDEFCORE_PUBLIC_ID_LEN + kMac * 2] = '\0';
}

static GDEFCORE_Result drop_blind_line(const GDEFCORE_Allocator * alloc,
    char ** text, size_t * n, const char * entity, const char * field,
    size_t field_len, const char * lang, size_t lang_len, char * old_hex,
    size_t * old_hex_len) {
  Buf kept;
  size_t at = 0;
  memset(&kept, 0, sizeof kept);
  kept.alloc = alloc;
  *old_hex_len = 0;
  old_hex[0] = '\0';
  while (at < *n) {
    size_t line = 0;
    size_t len = 0;
    int match;
    if (!line_span(*text, *n, &at, &line, &len)) {
      continue;
    }
    match = 0;
    if (len > kMac * 2 + 1 && (*text)[line + kMac * 2] == ' ') {
      match = loc_match(*text + line + kMac * 2 + 1, len - (kMac * 2 + 1),
          entity, field, field_len, lang, lang_len);
    }
    if (match) {
      if (*old_hex_len == 0) {
        memcpy(old_hex, *text + line, kMac * 2);
        old_hex[kMac * 2] = '\0';
        *old_hex_len = kMac * 2;
      }
      continue;
    }
    buf_add(&kept, *text + line, len);
    buf_add(&kept, "\n", 1);
  }
  if (kept.oom) {
    buf_free(&kept);
    return GDEFCORE_ERR_OOM;
  }
  gcu_allocator_free(alloc, *text);
  if (kept.p == NULL) {
    kept.p = dup_n(alloc, "", 0);
    if (kept.p == NULL) {
      *text = NULL;
      *n = 0;
      return GDEFCORE_ERR_OOM;
    }
  }
  *text = kept.p;
  *n = kept.n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result count_lines(const char * text, size_t n, size_t * out) {
  size_t at = 0;
  size_t count = 0;
  while (at < n) {
    size_t line = 0;
    size_t len = 0;
    if (!line_span(text, n, &at, &line, &len)) {
      continue;
    }
    count += 1;
  }
  *out = count;
  return GDEFCORE_OK;
}

static GDEFCORE_Result field_personal(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, const char * field, size_t field_len,
    int * out) {
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_type_field_count(catalog, type, type_len, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < n; i++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int personal = 0;
    rc = gdefcore_type_field(catalog, type, type_len, i, &name, &name_len,
        &required, &many);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = gdefcore_type_field_personal(catalog, type, type_len, i, &personal);
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, name);
      return rc;
    }
    if (span_eq(name, name_len, field, field_len)) {
      gdefcore_text_free(catalog, name);
      *out = personal;
      return GDEFCORE_OK;
    }
    gdefcore_text_free(catalog, name);
  }
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result encrypt_value(GDEFCORE_Subjects * subjects,
    const char * subject, const char * field, size_t field_len,
    const void * plain, size_t plain_len, char ** out, size_t * out_len) {
  uint8_t raw[kKey];
  uint8_t nonce[kNonce];
  uint8_t tag[kTag];
  uint8_t * ct = NULL;
  uint8_t * packed = NULL;
  uint8_t * aad = NULL;
  size_t aad_len = GDEFCORE_PUBLIC_ID_LEN + 1 + field_len;
  SubjectRow row;
  char * hex = NULL;
  size_t hex_len = 0;
  char * text = NULL;
  GDEFCORE_Result rc;
  memset(&row, 0, sizeof row);
  rc = row_load(subjects, subject, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!row.present || row.key == NULL || row.key_len != kWrap) {
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_INVALID;
  }
  rc = open_key(subjects, row.key, raw);
  row_clear(subjects->alloc, &row);
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  aad = (uint8_t *)mem(subjects->alloc, aad_len);
  ct = (uint8_t *)mem(subjects->alloc, plain_len == 0 ? 1 : plain_len);
  packed = (uint8_t *)mem(subjects->alloc, kNonce + plain_len + kTag);
  if (aad == NULL || ct == NULL || packed == NULL) {
    gcu_allocator_free(subjects->alloc, aad);
    gcu_allocator_free(subjects->alloc, ct);
    gcu_allocator_free(subjects->alloc, packed);
    wipe(raw, sizeof raw);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(aad, subject, GDEFCORE_PUBLIC_ID_LEN);
  aad[GDEFCORE_PUBLIC_ID_LEN] = 0;
  if (field_len > 0) {
    memcpy(aad + GDEFCORE_PUBLIC_ID_LEN + 1, field, field_len);
  }
  rc = from_gsec(gsec_random_bytes(nonce, sizeof nonce, NULL));
  if (rc == GDEFCORE_OK) {
    rc = from_gsec(gsec_aes_gcm_encrypt(raw, kKey, nonce, sizeof nonce, aad,
        aad_len, plain, plain_len, ct, tag, kTag));
  }
  wipe(raw, sizeof raw);
  if (rc == GDEFCORE_OK) {
    memcpy(packed, nonce, kNonce);
    if (plain_len > 0) {
      memcpy(packed + kNonce, ct, plain_len);
    }
    memcpy(packed + kNonce + plain_len, tag, kTag);
    rc = hex_encode(subjects->alloc, packed, kNonce + plain_len + kTag, &hex,
        &hex_len);
  }
  wipe(ct, plain_len);
  wipe(packed, kNonce + plain_len + kTag);
  gcu_allocator_free(subjects->alloc, aad);
  gcu_allocator_free(subjects->alloc, ct);
  gcu_allocator_free(subjects->alloc, packed);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(subjects->alloc, hex);
    return rc;
  }
  text = (char *)mem(subjects->alloc, 3 + hex_len + 1);
  if (text == NULL) {
    gcu_allocator_free(subjects->alloc, hex);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(text, "s1:", 3);
  memcpy(text + 3, hex, hex_len);
  text[3 + hex_len] = '\0';
  gcu_allocator_free(subjects->alloc, hex);
  *out = text;
  *out_len = 3 + hex_len;
  return GDEFCORE_OK;
}

static GDEFCORE_Result decrypt_text(GDEFCORE_Subjects * subjects,
    const char * subject, const uint8_t raw[kKey], const char * field,
    size_t field_len, const char * text, size_t text_len, char ** out,
    size_t * out_len) {
  uint8_t * packed = NULL;
  uint8_t * plain = NULL;
  uint8_t * aad = NULL;
  size_t packed_len;
  size_t plain_len;
  size_t aad_len = GDEFCORE_PUBLIC_ID_LEN + 1 + field_len;
  GDEFCORE_Result rc;
  if (text_len < 3 || memcmp(text, "s1:", 3) != 0 || ((text_len - 3) % 2) != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  packed_len = (text_len - 3) / 2;
  if (packed_len < kNonce + kTag) {
    return GDEFCORE_ERR_INVALID;
  }
  plain_len = packed_len - kNonce - kTag;
  packed = (uint8_t *)mem(subjects->alloc, packed_len);
  plain = (uint8_t *)mem(subjects->alloc, plain_len == 0 ? 1 : plain_len);
  aad = (uint8_t *)mem(subjects->alloc, aad_len);
  if (packed == NULL || plain == NULL || aad == NULL) {
    gcu_allocator_free(subjects->alloc, packed);
    gcu_allocator_free(subjects->alloc, plain);
    gcu_allocator_free(subjects->alloc, aad);
    return GDEFCORE_ERR_OOM;
  }
  rc = hex_decode(text + 3, text_len - 3, packed, packed_len);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(subjects->alloc, packed);
    gcu_allocator_free(subjects->alloc, plain);
    gcu_allocator_free(subjects->alloc, aad);
    return rc;
  }
  memcpy(aad, subject, GDEFCORE_PUBLIC_ID_LEN);
  aad[GDEFCORE_PUBLIC_ID_LEN] = 0;
  if (field_len > 0) {
    memcpy(aad + GDEFCORE_PUBLIC_ID_LEN + 1, field, field_len);
  }
  rc = from_gsec(gsec_aes_gcm_decrypt(raw, kKey, packed, kNonce, aad, aad_len,
      packed + kNonce, plain_len, plain, packed + kNonce + plain_len, kTag));
  gcu_allocator_free(subjects->alloc, packed);
  gcu_allocator_free(subjects->alloc, aad);
  if (rc != GDEFCORE_OK) {
    wipe(plain, plain_len);
    gcu_allocator_free(subjects->alloc, plain);
    return rc;
  }
  if (plain_len > 0) {
    char * text_out = dup_n(subjects->alloc, plain, plain_len);
    wipe(plain, plain_len);
    gcu_allocator_free(subjects->alloc, plain);
    if (text_out == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    *out = text_out;
  } else {
    gcu_allocator_free(subjects->alloc, plain);
    *out = dup_n(subjects->alloc, "", 0);
    if (*out == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  *out_len = plain_len;
  return GDEFCORE_OK;
}

static GDEFCORE_Result erased_text(GDEFCORE_Subjects * subjects, char ** out,
    size_t * out_len) {
  char * p = dup_n(subjects->alloc, GDEFCORE_SUBJECT_ERASED,
      GDEFCORE_SUBJECT_ERASED_LEN);
  if (p == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  *out = p;
  *out_len = GDEFCORE_SUBJECT_ERASED_LEN;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_subject_create(GDEFCORE_Subjects * subjects,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  uint8_t raw[kKey];
  uint8_t wrapped[kWrap];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  SubjectRow row;
  GDEFCORE_Result rc;
  if (subjects == NULL || out_id == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_id_generate(id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_gsec(gsec_random_bytes(raw, sizeof raw, NULL));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = seal_key(subjects, raw, wrapped);
  wipe(raw, sizeof raw);
  if (rc != GDEFCORE_OK) {
    wipe(wrapped, sizeof wrapped);
    return rc;
  }
  memset(&row, 0, sizeof row);
  row.present = 1;
  row.key = wrapped;
  row.key_len = kWrap;
  row.blinds = (char *)"";
  row.locs = (char *)"";
  rc = row_store(subjects, id, &row);
  wipe(wrapped, sizeof wrapped);
  row.key = NULL;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memcpy(out_id, id, GDEFCORE_PUBLIC_ID_LEN + 1);
  return GDEFCORE_OK;
}

static GDEFCORE_Result index_value(GDEFCORE_Subjects * subjects,
    const char * field, size_t field_len, const void * plain, size_t plain_len,
    uint8_t mac[kMac]) {
  uint8_t ikm[kKey];
  char * info = NULL;
  size_t info_len = strlen("blind-index:") + field_len;
  GDEFCORE_Result rc;
  info = (char *)mem(subjects->alloc, info_len + 1);
  if (info == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(info, "blind-index:", strlen("blind-index:"));
  if (field_len > 0) {
    memcpy(info + strlen("blind-index:"), field, field_len);
  }
  info[info_len] = '\0';
  rc = purpose(subjects, info, info_len, ikm);
  gcu_allocator_free(subjects->alloc, info);
  if (rc != GDEFCORE_OK) {
    wipe(ikm, sizeof ikm);
    return rc;
  }
  rc = from_gsec(gsec_hmac(GSEC_HMAC_SHA256, ikm, kKey, plain, plain_len, mac));
  wipe(ikm, sizeof ikm);
  return rc;
}

static GDEFCORE_Result remember(GDEFCORE_Subjects * subjects, const char * subject,
    const char * entity, const char * field, size_t field_len, const char * lang,
    size_t lang_len, const uint8_t mac[kMac]) {
  SubjectRow row;
  char hex[kMac * 2 + 1];
  size_t hex_len = 0;
  char old_hex[kMac * 2 + 1];
  size_t old_len = 0;
  char * line = NULL;
  size_t line_len;
  GDEFSTOR_Write * write = NULL;
  GDEFSTOR_Column blind_cols[3];
  GDEFSTOR_Column subject_cols[3];
  size_t nsub = 0;
  GDEFCORE_Result rc = row_load(subjects, subject, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = hex_encode(subjects->alloc, mac, kMac, &line, &hex_len);
  if (rc != GDEFCORE_OK) {
    row_clear(subjects->alloc, &row);
    return rc;
  }
  if (hex_len != kMac * 2) {
    gcu_allocator_free(subjects->alloc, line);
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_INTERNAL;
  }
  memcpy(hex, line, hex_len);
  hex[hex_len] = '\0';
  gcu_allocator_free(subjects->alloc, line);
  line = NULL;
  rc = drop_blind_line(subjects->alloc, &row.blinds, &row.blinds_len, entity,
      field, field_len, lang, lang_len, old_hex, &old_len);
  if (rc != GDEFCORE_OK) {
    row_clear(subjects->alloc, &row);
    return rc;
  }
  line_len = hex_len + 1 + GDEFCORE_PUBLIC_ID_LEN + 1 + field_len + 1 + lang_len +
             1;
  line = (char *)mem(subjects->alloc, line_len + 1);
  if (line == NULL) {
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_OOM;
  }
  {
    int kn = snprintf(line, line_len + 1, "%s %s %.*s %.*s\n", hex, entity,
        (int)field_len, field, (int)lang_len, lang);
    if (kn <= 0 || (size_t)kn != line_len) {
      gcu_allocator_free(subjects->alloc, line);
      row_clear(subjects->alloc, &row);
      return GDEFCORE_ERR_LIMIT;
    }
  }
  {
    char * next = (char *)gcu_allocator_realloc(subjects->alloc, row.blinds,
        row.blinds_len + line_len + 1);
    if (next == NULL) {
      gcu_allocator_free(subjects->alloc, line);
      row_clear(subjects->alloc, &row);
      return GDEFCORE_ERR_OOM;
    }
    memcpy(next + row.blinds_len, line, line_len);
    next[row.blinds_len + line_len] = '\0';
    row.blinds = next;
    row.blinds_len += line_len;
  }
  if (!loc_match_any(row.locs, row.locs_len, entity, field, field_len, lang,
          lang_len)) {
    char loc[160];
    int kn;
    if (GDEFCORE_PUBLIC_ID_LEN + field_len + lang_len + 4 >= sizeof loc) {
      gcu_allocator_free(subjects->alloc, line);
      row_clear(subjects->alloc, &row);
      return GDEFCORE_ERR_LIMIT;
    }
    kn = snprintf(loc, sizeof loc, "%s %.*s %.*s\n", entity, (int)field_len,
        field, (int)lang_len, lang);
    if (kn <= 0) {
      gcu_allocator_free(subjects->alloc, line);
      row_clear(subjects->alloc, &row);
      return GDEFCORE_ERR_LIMIT;
    }
    {
      char * next = (char *)gcu_allocator_realloc(subjects->alloc, row.locs,
          row.locs_len + (size_t)kn + 1);
      if (next == NULL) {
        gcu_allocator_free(subjects->alloc, line);
        row_clear(subjects->alloc, &row);
        return GDEFCORE_ERR_OOM;
      }
      memcpy(next + row.locs_len, loc, (size_t)kn);
      next[row.locs_len + (size_t)kn] = '\0';
      row.locs = next;
      row.locs_len += (size_t)kn;
    }
  }
  rc = from_stor(gdefstor_write_begin(subjects->side,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(subjects->alloc, line);
    row_clear(subjects->alloc, &row);
    return rc;
  }
  if (old_len == kMac * 2) {
    char old_id[GDEFCORE_PUBLIC_ID_LEN + 64 + 1];
    blind_entity(old_id, subject, old_hex);
    rc = from_stor(gdefstor_projection_delete(write, kBlindType,
        strlen(kBlindType), old_id, GDEFCORE_PUBLIC_ID_LEN + old_len));
  }
  if (rc == GDEFCORE_OK) {
    char row_id[GDEFCORE_PUBLIC_ID_LEN + 64 + 1];
    blind_entity(row_id, subject, hex);
    memset(blind_cols, 0, sizeof blind_cols);
    blind_cols[0].name = "mac";
    blind_cols[0].name_len = 3;
    blind_cols[0].value = mac;
    blind_cols[0].value_len = kMac;
    blind_cols[1].name = "field";
    blind_cols[1].name_len = 5;
    blind_cols[1].value = (const uint8_t *)field;
    blind_cols[1].value_len = field_len;
    blind_cols[2].name = "subject";
    blind_cols[2].name_len = 7;
    blind_cols[2].value = (const uint8_t *)subject;
    blind_cols[2].value_len = GDEFCORE_PUBLIC_ID_LEN;
    rc = from_stor(gdefstor_projection_put(write, kBlindType, strlen(kBlindType),
        row_id, GDEFCORE_PUBLIC_ID_LEN + hex_len, blind_cols, 3));
  }
  if (rc == GDEFCORE_OK) {
    memset(subject_cols, 0, sizeof subject_cols);
    nsub = 0;
    if (row.key != NULL && row.key_len > 0) {
      subject_cols[nsub].name = "key";
      subject_cols[nsub].name_len = 3;
      subject_cols[nsub].value = row.key;
      subject_cols[nsub].value_len = row.key_len;
      nsub += 1;
    }
    subject_cols[nsub].name = "blinds";
    subject_cols[nsub].name_len = 6;
    subject_cols[nsub].value = (const uint8_t *)row.blinds;
    subject_cols[nsub].value_len = row.blinds_len;
    nsub += 1;
    subject_cols[nsub].name = "locs";
    subject_cols[nsub].name_len = 4;
    subject_cols[nsub].value = (const uint8_t *)row.locs;
    subject_cols[nsub].value_len = row.locs_len;
    nsub += 1;
    rc = from_stor(gdefstor_projection_put(write, kSubjectType,
        strlen(kSubjectType), subject, GDEFCORE_PUBLIC_ID_LEN, subject_cols,
        nsub));
  }
  if (rc == GDEFCORE_OK) {
    rc = from_stor(gdefstor_write_commit(write));
  } else {
    gdefstor_write_abort(write);
  }
  gcu_allocator_free(subjects->alloc, line);
  row_clear(subjects->alloc, &row);
  return rc;
}

static int loc_match_any(const char * text, size_t n, const char * entity,
    const char * field, size_t field_len, const char * lang, size_t lang_len) {
  size_t at = 0;
  while (at < n) {
    size_t line = 0;
    size_t len = 0;
    if (!line_span(text, n, &at, &line, &len)) {
      continue;
    }
    if (loc_match(text + line, len, entity, field, field_len, lang, lang_len)) {
      return 1;
    }
  }
  return 0;
}

/* Whether @p text is shaped like what encrypt_value returns: "s1:" and the
 * lower-case hex of a nonce, the ciphertext and a tag. Such a text is a value
 * that came out of storage, not a person's data; sealing it would store a
 * second ciphertext over the first (the entity layer's sealed_ok is the same
 * test). */
static int looks_sealed(const void * text, size_t n) {
  const char * p = (const char *)text;
  size_t i;
  if (p == NULL || n < 3 + 2 * (kNonce + kTag) || memcmp(p, "s1:", 3) != 0 ||
      ((n - 3) % 2) != 0) {
    return 0;
  }
  for (i = 3; i < n; i++) {
    if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) {
      return 0;
    }
  }
  return 1;
}

/* A subject the ledger names takes no new value, and no new index row. */
static GDEFCORE_Result not_erased(GDEFCORE_Subjects * subjects, const char * sid) {
  char * ledger = NULL;
  size_t ledger_len = 0;
  int erased;
  GDEFCORE_Result rc = ledger_load(subjects, &ledger, &ledger_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  erased = ledger_has(ledger, ledger_len, sid);
  gcu_allocator_free(subjects->alloc, ledger);
  return erased ? GDEFCORE_ERR_INVALID : GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_subject_save(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    const char * entity, size_t entity_len, const char * field, size_t field_len,
    const char * lang, size_t lang_len, const void * plain, size_t plain_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type = NULL;
  size_t type_len = 0;
  char * stored = NULL;
  size_t stored_len = 0;
  int personal = 0;
  int kind = 0;
  uint8_t mac[kMac];
  const char * texts[1];
  size_t lens[1];
  GDEFCORE_Value value;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc;
  if (subjects == NULL || catalog == NULL || field == NULL ||
      (plain == NULL && plain_len != 0) || lang == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = canon_id(entity, entity_len, eid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = not_erased(subjects, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_type(catalog, eid, GDEFCORE_PUBLIC_ID_LEN, &type,
      &type_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = field_personal(catalog, type, type_len, field, field_len, &personal);
  if (rc != GDEFCORE_OK || !personal) {
    gdefcore_text_free(catalog, type);
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : rc;
  }
  rc = gdefcore_type_kind(catalog, type, type_len, &kind);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type);
    return rc;
  }
  rc = gdefcore_subject_seal(subjects, sid, GDEFCORE_PUBLIC_ID_LEN, field,
      field_len, plain, plain_len, &stored, &stored_len, mac);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type);
    return rc;
  }
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc == GDEFCORE_OK) {
    /* The one caller that hands the entity layer sealed personal values. */
    rc = gdefcore_changeset_accept_sealed(changeset);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(changeset);
    gcu_allocator_free(subjects->alloc, stored);
    gdefcore_text_free(catalog, type);
    return rc;
  }
  texts[0] = stored;
  lens[0] = stored_len;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = field;
  value.field_len = field_len;
  value.texts = texts;
  value.text_lens = lens;
  value.count = 1;
  rc = gdefcore_entity_save(changeset, eid, GDEFCORE_PUBLIC_ID_LEN, lang,
      lang_len, &value, 1);
  if (rc == GDEFCORE_OK) {
    if (kind == GDEFCORE_TYPE_CONFIG) {
      rc = gdefcore_changeset_apply(changeset, type, type_len);
    } else {
      rc = gdefcore_changeset_apply(changeset, NULL, 0);
    }
  }
  gdefcore_changeset_destroy(changeset);
  gdefcore_text_free(catalog, type);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(subjects->alloc, stored);
    return rc;
  }
  gcu_allocator_free(subjects->alloc, stored);
  return remember(subjects, sid, eid, field, field_len, lang, lang_len, mac);
}

GDEFCORE_Result gdefcore_subject_seal(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * field,
    size_t field_len, const void * plain, size_t plain_len, char ** out_text,
    size_t * out_len, uint8_t out_mac[GDEFCORE_SUBJECT_MAC_LEN]) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * sealed = NULL;
  size_t sealed_len = 0;
  uint8_t mac[kMac];
  GDEFCORE_Result rc;
  if (subjects == NULL || field == NULL || field_len == 0 ||
      (plain == NULL && plain_len != 0) || out_text == NULL ||
      out_len == NULL || out_mac == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (looks_sealed(plain, plain_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = not_erased(subjects, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = encrypt_value(subjects, sid, field, field_len, plain, plain_len, &sealed,
      &sealed_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = index_value(subjects, field, field_len, plain, plain_len, mac);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(subjects->alloc, sealed);
    return rc;
  }
  memcpy(out_mac, mac, kMac);
  *out_text = sealed;
  *out_len = sealed_len;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_subject_index(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * entity,
    size_t entity_len, const char * field, size_t field_len, const char * lang,
    size_t lang_len, const uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN]) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eid[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (subjects == NULL || field == NULL || field_len == 0 || lang == NULL ||
      mac == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = canon_id(entity, entity_len, eid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = not_erased(subjects, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return remember(subjects, sid, eid, field, field_len, lang, lang_len, mac);
}

GDEFCORE_Result gdefcore_subject_read(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    const char * entity, size_t entity_len, const char * field, size_t field_len,
    const char * lang, size_t lang_len, char ** out_text, size_t * out_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * ledger = NULL;
  size_t ledger_len = 0;
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  SubjectRow row;
  uint8_t raw[kKey];
  GDEFCORE_Result rc;
  if (subjects == NULL || catalog == NULL || out_text == NULL ||
      out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = canon_id(entity, entity_len, eid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = ledger_load(subjects, &ledger, &ledger_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (ledger_has(ledger, ledger_len, sid)) {
    gcu_allocator_free(subjects->alloc, ledger);
    return erased_text(subjects, out_text, out_len);
  }
  gcu_allocator_free(subjects->alloc, ledger);
  rc = row_load(subjects, sid, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!row.present || row.key == NULL || row.key_len != kWrap) {
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_INVALID;
  }
  rc = open_key(subjects, row.key, raw);
  row_clear(subjects->alloc, &row);
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, eid,
      GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, field_len, &texts, &lens,
      &count);
  if (rc != GDEFCORE_OK || count != 1 || texts == NULL || texts[0] == NULL) {
    wipe(raw, sizeof raw);
    gdefcore_values_free(catalog, texts, lens, count);
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : rc;
  }
  rc = decrypt_text(subjects, sid, raw, field, field_len, texts[0], lens[0],
      out_text, out_len);
  wipe(raw, sizeof raw);
  gdefcore_values_free(catalog, texts, lens, count);
  return rc;
}

GDEFCORE_Result gdefcore_subject_revision_marker(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, int status, int * out_status,
    char ** out_text, size_t * out_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * ledger = NULL;
  size_t ledger_len = 0;
  int erased;
  GDEFCORE_Result rc;
  if (subjects == NULL || out_status == NULL || out_text == NULL ||
      out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_status = status;
  *out_text = NULL;
  *out_len = 0;
  if (status != GDEFCORE_REVISION_PERSONAL) {
    return GDEFCORE_OK;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = ledger_load(subjects, &ledger, &ledger_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  erased = ledger_has(ledger, ledger_len, sid);
  gcu_allocator_free(subjects->alloc, ledger);
  if (!erased) {
    return GDEFCORE_OK;
  }
  /* The key is gone: what the revision holds decrypts to nothing, and says
   * so in the one word every erased value is shown as. */
  rc = erased_text(subjects, out_text, out_len);
  if (rc == GDEFCORE_OK) {
    *out_status = GDEFCORE_REVISION_ERASED;
  }
  return rc;
}

static GDEFCORE_Result delete_blinds(GDEFSTOR_Write * write, const char * subject,
    const char * text, size_t n) {
  size_t at = 0;
  while (at < n) {
    size_t line = 0;
    size_t len = 0;
    char id[GDEFCORE_PUBLIC_ID_LEN + 64 + 1];
    GDEFCORE_Result rc;
    if (!line_span(text, n, &at, &line, &len)) {
      continue;
    }
    if (len < kMac * 2 + 1 || text[line + kMac * 2] != ' ') {
      return GDEFCORE_ERR_CORRUPT;
    }
    blind_entity(id, subject, text + line);
    rc = from_stor(gdefstor_projection_delete(write, kBlindType,
        strlen(kBlindType), id, GDEFCORE_PUBLIC_ID_LEN + kMac * 2));
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_subject_erase(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * confirmation,
    size_t confirmation_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * ledger = NULL;
  size_t ledger_len = 0;
  char line[64];
  uint64_t when = 0;
  int kn;
  SubjectRow row;
  GDEFSTOR_Write * write = NULL;
  GDEFSTOR_Column columns[3];
  GDEFSTOR_Column ledger_col;
  GDEFCORE_Result rc;
  if (subjects == NULL || confirmation == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (confirmation_len != GDEFCORE_PUBLIC_ID_LEN ||
      memcmp(confirmation, sid, GDEFCORE_PUBLIC_ID_LEN) != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = row_load(subjects, sid, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!row.present) {
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_INVALID;
  }
  rc = ledger_load(subjects, &ledger, &ledger_len);
  if (rc != GDEFCORE_OK) {
    row_clear(subjects->alloc, &row);
    return rc;
  }
  if (!now_u64(&when)) {
    gcu_allocator_free(subjects->alloc, ledger);
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_IO;
  }
  kn = snprintf(line, sizeof line, "%s %llu\n", sid, (unsigned long long)when);
  if (kn <= 0 || (size_t)kn >= sizeof line) {
    gcu_allocator_free(subjects->alloc, ledger);
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_LIMIT;
  }
  rc = from_stor(gdefstor_write_begin(subjects->side,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(subjects->alloc, ledger);
    row_clear(subjects->alloc, &row);
    return rc;
  }
  rc = delete_blinds(write, sid, row.blinds, row.blinds_len);
  if (rc == GDEFCORE_OK) {
    memset(columns, 0, sizeof columns);
    columns[0].name = "blinds";
    columns[0].name_len = 6;
    columns[0].value = (const uint8_t *)"";
    columns[0].value_len = 0;
    columns[1].name = "locs";
    columns[1].name_len = 4;
    columns[1].value = (const uint8_t *)(row.locs == NULL ? "" : row.locs);
    columns[1].value_len = row.locs_len;
    rc = from_stor(gdefstor_projection_put(write, kSubjectType,
        strlen(kSubjectType), sid, GDEFCORE_PUBLIC_ID_LEN, columns, 2));
  }
  if (rc == GDEFCORE_OK && !ledger_has(ledger, ledger_len, sid)) {
    char * next = (char *)gcu_allocator_realloc(subjects->alloc, ledger,
        ledger_len + (size_t)kn + 1);
    if (next == NULL) {
      rc = GDEFCORE_ERR_OOM;
    } else {
      memcpy(next + ledger_len, line, (size_t)kn);
      next[ledger_len + (size_t)kn] = '\0';
      ledger = next;
      ledger_len += (size_t)kn;
      memset(&ledger_col, 0, sizeof ledger_col);
      ledger_col.name = "text";
      ledger_col.name_len = 4;
      ledger_col.value = (const uint8_t *)ledger;
      ledger_col.value_len = ledger_len;
      rc = from_stor(gdefstor_projection_put(write, GDEFCORE_SUBJECT_LEDGER_TYPE,
          strlen(GDEFCORE_SUBJECT_LEDGER_TYPE), GDEFCORE_SUBJECT_LEDGER_ID,
          strlen(GDEFCORE_SUBJECT_LEDGER_ID), &ledger_col, 1));
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = from_stor(gdefstor_write_commit(write));
  } else {
    gdefstor_write_abort(write);
  }
  gcu_allocator_free(subjects->alloc, ledger);
  row_clear(subjects->alloc, &row);
  return rc;
}

static int utf8_ok(const uint8_t * s, size_t n) {
  size_t i = 0;
  while (i < n) {
    uint8_t c = s[i];
    size_t need = 0;
    size_t j;
    if (c < 0x80) {
      i += 1;
      continue;
    }
    if ((c & 0xe0) == 0xc0) {
      need = 2;
    } else if ((c & 0xf0) == 0xe0) {
      need = 3;
    } else if ((c & 0xf8) == 0xf0) {
      need = 4;
    } else {
      return 0;
    }
    if (i + need > n) {
      return 0;
    }
    for (j = 1; j < need; j++) {
      if ((s[i + j] & 0xc0) != 0x80) {
        return 0;
      }
    }
    i += need;
  }
  return 1;
}

static void json_escape(Buf * b, const char * s, size_t n) {
  size_t i;
  buf_add(b, "\"", 1);
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    char esc[8];
    int kn;
    if (c == '"' || c == '\\') {
      esc[0] = '\\';
      esc[1] = (char)c;
      buf_add(b, esc, 2);
    } else if (c == '\n') {
      buf_add(b, "\\n", 2);
    } else if (c == '\r') {
      buf_add(b, "\\r", 2);
    } else if (c == '\t') {
      buf_add(b, "\\t", 2);
    } else if (c < 0x20) {
      kn = snprintf(esc, sizeof esc, "\\u%04x", c);
      if (kn > 0) {
        buf_add(b, esc, (size_t)kn);
      }
    } else {
      buf_add(b, &s[i], 1);
    }
  }
  buf_add(b, "\"", 1);
}

GDEFCORE_Result gdefcore_subject_export(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    char ** out_json, size_t * out_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * ledger = NULL;
  size_t ledger_len = 0;
  SubjectRow row;
  Buf buf;
  size_t at = 0;
  int first = 1;
  GDEFCORE_Result rc;
  if (subjects == NULL || out_json == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = ledger_load(subjects, &ledger, &ledger_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (ledger_has(ledger, ledger_len, sid)) {
    gcu_allocator_free(subjects->alloc, ledger);
    *out_json = dup_n(subjects->alloc, "{\"erased\":\"[erased]\"}", 21);
    if (*out_json == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    *out_len = 21;
    return GDEFCORE_OK;
  }
  gcu_allocator_free(subjects->alloc, ledger);
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = row_load(subjects, sid, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&buf, 0, sizeof buf);
  buf.alloc = subjects->alloc;
  buf_add(&buf, "{\"values\":[", 11);
  while (at < row.locs_len) {
    size_t line = 0;
    size_t len = 0;
    char eid[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * field;
    size_t field_len;
    const char * lang;
    size_t lang_len;
    size_t sp;
    char * plain = NULL;
    size_t plain_len = 0;
    if (!line_span(row.locs, row.locs_len, &at, &line, &len)) {
      continue;
    }
    if (len < GDEFCORE_PUBLIC_ID_LEN + 3 ||
        row.locs[line + GDEFCORE_PUBLIC_ID_LEN] != ' ') {
      row_clear(subjects->alloc, &row);
      buf_free(&buf);
      return GDEFCORE_ERR_CORRUPT;
    }
    memcpy(eid, row.locs + line, GDEFCORE_PUBLIC_ID_LEN);
    eid[GDEFCORE_PUBLIC_ID_LEN] = '\0';
    field = row.locs + line + GDEFCORE_PUBLIC_ID_LEN + 1;
    sp = 0;
    while (sp < len - (GDEFCORE_PUBLIC_ID_LEN + 1) && field[sp] != ' ') {
      sp += 1;
    }
    if (sp == 0 || sp >= len - (GDEFCORE_PUBLIC_ID_LEN + 1)) {
      row_clear(subjects->alloc, &row);
      buf_free(&buf);
      return GDEFCORE_ERR_CORRUPT;
    }
    field_len = sp;
    lang = field + sp + 1;
    lang_len = len - (GDEFCORE_PUBLIC_ID_LEN + 1 + field_len + 1);
    rc = gdefcore_subject_read(subjects, catalog, sid, GDEFCORE_PUBLIC_ID_LEN,
        eid, GDEFCORE_PUBLIC_ID_LEN, field, field_len, lang, lang_len, &plain,
        &plain_len);
    if (rc != GDEFCORE_OK) {
      row_clear(subjects->alloc, &row);
      buf_free(&buf);
      return rc;
    }
    if (!utf8_ok((const uint8_t *)plain, plain_len)) {
      wipe(plain, plain_len);
      gdefcore_subject_free(subjects, plain);
      row_clear(subjects->alloc, &row);
      buf_free(&buf);
      return GDEFCORE_ERR_INVALID;
    }
    if (!first) {
      buf_add(&buf, ",", 1);
    }
    first = 0;
    buf_add(&buf, "{\"entity\":", 10);
    json_escape(&buf, eid, GDEFCORE_PUBLIC_ID_LEN);
    buf_add(&buf, ",\"field\":", 9);
    json_escape(&buf, field, field_len);
    buf_add(&buf, ",\"lang\":", 8);
    json_escape(&buf, lang, lang_len);
    buf_add(&buf, ",\"text\":", 8);
    json_escape(&buf, plain, plain_len);
    buf_add(&buf, "}", 1);
    wipe(plain, plain_len);
    gdefcore_subject_free(subjects, plain);
  }
  buf_add(&buf, "]}", 2);
  row_clear(subjects->alloc, &row);
  if (buf.oom || buf.p == NULL) {
    buf_free(&buf);
    return GDEFCORE_ERR_OOM;
  }
  *out_json = buf.p;
  *out_len = buf.n;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_subject_key(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len,
    uint8_t out[GDEFCORE_SUBJECT_KEY_LEN]) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  SubjectRow row;
  GDEFCORE_Result rc;
  if (subjects == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = row_load(subjects, sid, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!row.present || row.key == NULL || row.key_len != kWrap) {
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_INVALID;
  }
  rc = open_key(subjects, row.key, out);
  row_clear(subjects->alloc, &row);
  if (rc != GDEFCORE_OK) {
    wipe(out, GDEFCORE_SUBJECT_KEY_LEN);
  }
  return rc;
}

GDEFCORE_Result gdefcore_subject_blind_count(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, size_t * out_count) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  SubjectRow row;
  GDEFCORE_Result rc;
  if (subjects == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = row_load(subjects, sid, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!row.present) {
    row_clear(subjects->alloc, &row);
    return GDEFCORE_ERR_INVALID;
  }
  rc = count_lines(row.blinds, row.blinds_len, out_count);
  row_clear(subjects->alloc, &row);
  return rc;
}

GDEFCORE_Result gdefcore_subject_blind(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, size_t index, uint8_t out[32]) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  SubjectRow row;
  size_t at = 0;
  size_t seen = 0;
  GDEFCORE_Result rc;
  if (subjects == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = row_load(subjects, sid, &row);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  while (at < row.blinds_len) {
    size_t line = 0;
    size_t len = 0;
    if (!line_span(row.blinds, row.blinds_len, &at, &line, &len)) {
      continue;
    }
    if (seen == index) {
      if (len < kMac * 2) {
        row_clear(subjects->alloc, &row);
        return GDEFCORE_ERR_CORRUPT;
      }
      rc = hex_decode(row.blinds + line, kMac * 2, out, kMac);
      row_clear(subjects->alloc, &row);
      return rc;
    }
    seen += 1;
  }
  row_clear(subjects->alloc, &row);
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result replay_ids(GDEFCORE_Subjects * subjects, const char * text,
    size_t n) {
  size_t at = 0;
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc = from_stor(gdefstor_write_begin(subjects->side,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  while (at < n) {
    size_t line = 0;
    size_t len = 0;
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    SubjectRow row;
    GDEFSTOR_Column columns[2];
    if (!line_span(text, n, &at, &line, &len)) {
      continue;
    }
    if (len < GDEFCORE_PUBLIC_ID_LEN ||
        (len > GDEFCORE_PUBLIC_ID_LEN && text[line + GDEFCORE_PUBLIC_ID_LEN] != ' ')) {
      gdefstor_write_abort(write);
      return GDEFCORE_ERR_CORRUPT;
    }
    memcpy(id, text + line, GDEFCORE_PUBLIC_ID_LEN);
    id[GDEFCORE_PUBLIC_ID_LEN] = '\0';
    rc = row_load(subjects, id, &row);
    if (rc != GDEFCORE_OK) {
      gdefstor_write_abort(write);
      return rc;
    }
    if (row.present) {
      rc = delete_blinds(write, id, row.blinds, row.blinds_len);
      if (rc == GDEFCORE_OK) {
        memset(columns, 0, sizeof columns);
        columns[0].name = "blinds";
        columns[0].name_len = 6;
        columns[0].value = (const uint8_t *)"";
        columns[0].value_len = 0;
        columns[1].name = "locs";
        columns[1].name_len = 4;
        columns[1].value = (const uint8_t *)(row.locs == NULL ? "" : row.locs);
        columns[1].value_len = row.locs_len;
        rc = from_stor(gdefstor_projection_put(write, kSubjectType,
            strlen(kSubjectType), id, GDEFCORE_PUBLIC_ID_LEN, columns, 2));
      }
    }
    row_clear(subjects->alloc, &row);
    if (rc != GDEFCORE_OK) {
      gdefstor_write_abort(write);
      return rc;
    }
  }
  return from_stor(gdefstor_write_commit(write));
}

static GDEFCORE_Result ledger_union(const GDEFCORE_Allocator * alloc,
    const char * live, size_t live_len, const char * copy, size_t copy_len,
    char ** out, size_t * out_len) {
  Buf buf;
  size_t at = 0;
  memset(&buf, 0, sizeof buf);
  buf.alloc = alloc;
  buf_add(&buf, live, live_len);
  while (at < copy_len) {
    size_t line = 0;
    size_t len = 0;
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (!line_span(copy, copy_len, &at, &line, &len)) {
      continue;
    }
    if (len < GDEFCORE_PUBLIC_ID_LEN) {
      buf_free(&buf);
      return GDEFCORE_ERR_CORRUPT;
    }
    memcpy(id, copy + line, GDEFCORE_PUBLIC_ID_LEN);
    id[GDEFCORE_PUBLIC_ID_LEN] = '\0';
    if (ledger_has(live, live_len, id) ||
        (buf.p != NULL && ledger_has(buf.p, buf.n, id))) {
      continue;
    }
    buf_add(&buf, copy + line, len);
    buf_add(&buf, "\n", 1);
  }
  if (buf.oom) {
    buf_free(&buf);
    return GDEFCORE_ERR_OOM;
  }
  if (buf.p == NULL) {
    buf.p = dup_n(alloc, "", 0);
    if (buf.p == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = buf.p;
  *out_len = buf.n;
  return GDEFCORE_OK;
}

static GDEFCORE_Result ledger_store(GDEFCORE_Subjects * subjects,
    const char * text, size_t n) {
  GDEFSTOR_Column column;
  memset(&column, 0, sizeof column);
  column.name = "text";
  column.name_len = 4;
  column.value = (const uint8_t *)(text == NULL ? "" : text);
  column.value_len = n;
  return side_put(subjects->side, subjects->tenant, subjects->tenant_len,
      GDEFCORE_SUBJECT_LEDGER_TYPE, GDEFCORE_SUBJECT_LEDGER_ID,
      strlen(GDEFCORE_SUBJECT_LEDGER_ID), &column, 1);
}

GDEFCORE_Result gdefcore_subject_snapshot(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * tenant_store, uint8_t ** out_bytes, size_t * out_len) {
  char * ledger = NULL;
  size_t ledger_len = 0;
  GDEFCORE_Result rc;
  if (subjects == NULL || tenant_store == NULL || tenant_store == subjects->side ||
      out_bytes == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ledger_load(subjects, &ledger, &ledger_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_stor(gdefstor_snapshot_export_ledger(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL,
      (const uint8_t *)ledger, ledger_len, out_bytes, out_len));
  gcu_allocator_free(subjects->alloc, ledger);
  return rc;
}

static int name_bad(const char * name, size_t n) {
  size_t i;
  size_t start = 0;
  if (n == 0) {
    return 1;
  }
  for (i = 0; i <= n; i++) {
    if (i == n || name[i] == '/' || name[i] == '\\' || name[i] == '\0') {
      size_t seglen = i - start;
      if (i != n && (name[i] == '\\' || name[i] == '\0')) {
        return 1;
      }
      if (seglen == 0 || (seglen == 1 && name[start] == '.') ||
          (seglen == 2 && name[start] == '.' && name[start + 1] == '.')) {
        return 1;
      }
      start = i + 1;
    }
  }
  return 0;
}

static int ratio_over(uint64_t uncomp, uint64_t comp, uint32_t max_ratio) {
  if (uncomp == 0) {
    return 0;
  }
  if (comp == 0 || max_ratio == 0) {
    return 1;
  }
  if (comp > UINT64_MAX / (uint64_t)max_ratio) {
    return 0;
  }
  return uncomp > (uint64_t)max_ratio * comp;
}

static int digits_only(const char * text, size_t n) {
  size_t i;
  if (n == 0) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (text[i] < '0' || text[i] > '9') {
      return 0;
    }
  }
  return 1;
}

static int span_is(const char * text, size_t n, const char * want) {
  size_t want_len = strlen(want);
  return n == want_len && memcmp(text, want, n) == 0;
}

static int grant_confirm_ok(const char * role, size_t role_len,
    const char * confirm, size_t confirm_len) {
  if (span_is(role, role_len, "anonymous")) {
    return span_is(confirm, confirm_len, GDEFCORE_ACCESS_CONFIRM_ANONYMOUS);
  }
  if (span_is(role, role_len, "authenticated")) {
    return span_is(confirm, confirm_len,
        GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED);
  }
  return span_is(confirm, confirm_len, "core.role");
}

/* A stored role row has no top-level role and label. Those two keys are an
 * applied grant, which needs the same confirmation the grant call does. */
static GDEFCORE_Result judge_object(const GTEXT_JSON_Value * root) {
  const GTEXT_JSON_Value * format;
  const GTEXT_JSON_Value * entity;
  const GTEXT_JSON_Value * type;
  const GTEXT_JSON_Value * tenant;
  const GTEXT_JSON_Value * role;
  const GTEXT_JSON_Value * label;
  const GTEXT_JSON_Value * confirm;
  const char * format_text = NULL;
  size_t format_len = 0;
  const char * entity_text = NULL;
  size_t entity_len = 0;
  const char * type_text = NULL;
  size_t type_len = 0;
  const char * role_text = NULL;
  size_t role_len = 0;
  const char * label_text = NULL;
  size_t label_len = 0;
  const char * confirm_text = NULL;
  size_t confirm_len = 0;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  int revision = 0;
  if (gtext_json_typeof(root) != GTEXT_JSON_OBJECT) {
    return GDEFCORE_OK;
  }
  format = gtext_json_object_get(root, "format", 6);
  if (gtext_json_get_string(format, &format_text, &format_len) ==
      GTEXT_JSON_OK) {
    revision = format_len >= 17 &&
               memcmp(format_text, "defiant-revision/", 17) == 0;
  }
  tenant = gtext_json_object_get(root, "tenant", 6);
  if (tenant != NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (revision) {
    entity = gtext_json_object_get(root, "entity", 6);
    if (gtext_json_get_string(entity, &entity_text, &entity_len) !=
        GTEXT_JSON_OK) {
      return GDEFCORE_ERR_CORRUPT;
    }
    if (digits_only(entity_text, entity_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    if (gdefcore_id_canonical(entity_text, entity_len, canon) !=
        GDEFCORE_OK) {
      return GDEFCORE_ERR_INVALID;
    }
    type = gtext_json_object_get(root, "type", 4);
    if (gtext_json_get_string(type, &type_text, &type_len) == GTEXT_JSON_OK &&
        span_is(type_text, type_len, "core.tenant")) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  role = gtext_json_object_get(root, "role", 4);
  label = gtext_json_object_get(root, "label", 5);
  if (role == NULL && label == NULL) {
    return GDEFCORE_OK;
  }
  if (gtext_json_get_string(role, &role_text, &role_len) != GTEXT_JSON_OK ||
      gtext_json_get_string(label, &label_text, &label_len) != GTEXT_JSON_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  confirm = gtext_json_object_get(root, "confirmation", 12);
  if (gtext_json_get_string(confirm, &confirm_text, &confirm_len) !=
          GTEXT_JSON_OK ||
      !grant_confirm_ok(role_text, role_len, confirm_text, confirm_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result from_garc(GARC_Result gr) {
  if (gr == GARC_ERR_OOM) {
    return GDEFCORE_ERR_OOM;
  }
  if (garc_result_is_limit(gr)) {
    return GDEFCORE_ERR_LIMIT;
  }
  return GDEFCORE_ERR_CORRUPT;
}

static GDEFCORE_Result judge_member(const GDEFCORE_Allocator * alloc,
    const uint8_t * body, size_t n) {
  GTEXT_JSON_Parse_Options opt;
  GTEXT_JSON_Error err;
  GTEXT_JSON_Value * root;
  GDEFCORE_Result rc;
  size_t i;
  for (i = 0; i < n; i++) {
    if (body[i] != ' ' && body[i] != '\n' && body[i] != '\r' &&
        body[i] != '\t') {
      break;
    }
  }
  if (i >= n || body[i] != '{') {
    return GDEFCORE_OK;
  }
  memset(&err, 0, sizeof err);
  opt = gtext_json_parse_options_default();
  opt.allocator = (const GTEXT_Allocator *)alloc;
  root = gtext_json_parse((const char *)body, n, &opt, &err);
  gtext_json_error_free(&err);
  if (root == NULL) {
    return GDEFCORE_ERR_CORRUPT;
  }
  rc = judge_object(root);
  gtext_json_free(root);
  return rc;
}

/* Walk the zip before any tenant write. A bad name, a defeated ratio, a
 * named tenant, an internal id, an installation-scope type, a mistyped
 * public id, or a role grant without its confirmation refuses the import. */
static GDEFCORE_Result archive_refuse(const GDEFCORE_Allocator * alloc,
    const uint8_t * bytes, size_t len) {
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  GARC_Limits alimits;
  GDEFSTOR_Limits caps;
  GARC_Result gr;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (len == 0) {
    return GDEFCORE_ERR_CORRUPT;
  }
  gr = garc_stream_create_memory(bytes, len, &stream);
  if (gr != GARC_OK) {
    return GDEFCORE_ERR_CORRUPT;
  }
  gdefstor_limits_default(&caps);
  garc_limits_default(&alimits);
  alimits.max_members = caps.max_members;
  alimits.max_member_bytes = caps.max_member_bytes;
  alimits.max_total_bytes = caps.max_snapshot_bytes;
  gr = garc_open(stream, &alimits, &archive);
  if (gr != GARC_OK) {
    garc_stream_destroy(stream);
    return from_garc(gr);
  }
  for (;;) {
    const GARC_Member * member = NULL;
    uint8_t * body = NULL;
    size_t got_total = 0;
    gr = garc_next(archive, &member);
    if (gr == GARC_END) {
      break;
    }
    if (gr != GARC_OK) {
      rc = from_garc(gr);
      break;
    }
    if (member->type != GARC_MEMBER_FILE ||
        name_bad(member->name, member->name_length)) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    if (member->size > caps.max_member_bytes || member->size > SIZE_MAX) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    if (ratio_over(member->size, garc_zip_member_compressed_size(archive),
            caps.max_zip_ratio)) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    if (member->size == 0) {
      continue;
    }
    body = (uint8_t *)gcu_allocator_malloc(alloc, (size_t)member->size);
    if (body == NULL) {
      rc = GDEFCORE_ERR_OOM;
      break;
    }
    while (got_total < (size_t)member->size) {
      size_t got = 0;
      size_t chunk = (size_t)member->size - got_total;
      gr = garc_read_member(archive, body + got_total, chunk, &got);
      if (gr != GARC_OK || got == 0) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      got_total += got;
    }
    if (rc == GDEFCORE_OK &&
        !(member->name != NULL && member->name_length >= 2 &&
            member->name[0] == 'b' && member->name[1] == ':')) {
      rc = judge_member(alloc, body, (size_t)member->size);
    }
    gcu_allocator_free(alloc, body);
    if (rc != GDEFCORE_OK) {
      break;
    }
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return rc;
}

GDEFCORE_Result gdefcore_subject_import(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * tenant_store, const uint8_t * bytes, size_t len) {
  uint8_t * copy = NULL;
  size_t copy_len = 0;
  char * live = NULL;
  size_t live_len = 0;
  char * united = NULL;
  size_t united_len = 0;
  GDEFCORE_Result rc;
  if (subjects == NULL || tenant_store == NULL || tenant_store == subjects->side ||
      (bytes == NULL && len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = archive_refuse(subjects->alloc, bytes, len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_stor(gdefstor_snapshot_ledger(tenant_store, bytes, len, NULL, &copy,
      &copy_len));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_stor(gdefstor_snapshot_import(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, bytes, len, NULL));
  if (rc != GDEFCORE_OK) {
    gdefstor_bytes_free(NULL, copy);
    return rc;
  }
  rc = ledger_load(subjects, &live, &live_len);
  if (rc != GDEFCORE_OK) {
    gdefstor_bytes_free(NULL, copy);
    return rc;
  }
  rc = ledger_union(subjects->alloc, live, live_len, (const char *)copy, copy_len,
      &united, &united_len);
  gcu_allocator_free(subjects->alloc, live);
  gdefstor_bytes_free(NULL, copy);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = ledger_store(subjects, united, united_len);
  if (rc == GDEFCORE_OK) {
    rc = replay_ids(subjects, united, united_len);
  }
  gcu_allocator_free(subjects->alloc, united);
  return rc;
}
