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
 * Personal values are ciphertext on the tenant's entity port, each with its
 * subject's public id, and each version a save writes has its blind-index row
 * in the port's blind table, in the same write (the entity layer gives it,
 * from gdefcore_changeset_note_sealed() or gdefcore_subject_mac_sealed(); story
 * S6c). The subject keys (wrapped under the keyring's subject-wrap purpose),
 * the tenant keyring's wrap and the erasure ledger are in the key store
 * (defiant-storage's keystore.h), read and written only through its port.
 * Erasure destroys the key in the key store first, then deletes the blind
 * rows through the data store's port; every open and restore replays the
 * ledger, so a restored pair still reads as erased and an erasure cut short
 * after its first step is finished. A restore then rebuilds the blind index
 * from the values that can still be decrypted, since a data set carries none.
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
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/query.h>
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

static const char kPurpose[] = "subject-wrap";
static const char kHex[] = "0123456789abcdef";

struct GDEFCORE_Subjects {
  const GDEFCORE_Allocator * alloc;
  GDEFSTOR_KeyStore * keys; /* keys, the keyring's wrap, the ledger */
  GDEFSTOR_Store * data;    /* the tenant's data store: values, blind rows */
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

/* ---- the key store ----------------------------------------------------------
 *
 * Every byte that leaves the key store through these comes from its
 * allocator, which subject.h requires to be this subsystem's. */

static const char kKeyringSecret[] = GDEFCORE_SUBJECT_KEYRING_SECRET;

/* The tenant keyring's wrap, kept in the key store as a tenant secret. */
static GDEFCORE_Result wrap_load(GDEFSTOR_KeyStore * keys,
    const GDEFCORE_Allocator * alloc, const uint8_t * tenant,
    size_t tenant_len, uint8_t * out, int * found) {
  uint8_t * got = NULL;
  size_t len = 0;
  GDEFCORE_Result rc;
  *found = 0;
  rc = from_stor(gdefstor_keystore_secret_get(keys, (const char *)tenant,
      tenant_len, kKeyringSecret, strlen(kKeyringSecret), found, &got, &len));
  if (rc != GDEFCORE_OK || !*found) {
    *found = 0;
    return rc;
  }
  if (len != kWrap) {
    wipe(got, len);
    gcu_allocator_free(alloc, got);
    *found = 0;
    return GDEFCORE_ERR_CORRUPT;
  }
  memcpy(out, got, kWrap);
  wipe(got, len);
  gcu_allocator_free(alloc, got);
  return GDEFCORE_OK;
}

/* Written once: the same wrap again changes nothing, another is refused. */
static GDEFCORE_Result wrap_store(GDEFSTOR_KeyStore * keys,
    const uint8_t * tenant, size_t tenant_len, const uint8_t * bytes) {
  return from_stor(gdefstor_keystore_secret_put(keys, (const char *)tenant,
      tenant_len, kKeyringSecret, strlen(kKeyringSecret), bytes, kWrap));
}

/* The subject's wrapped key. *out_erased for an erased subject (nothing in
 * @p wrapped); ::GDEFCORE_ERR_INVALID for one the key store does not know. */
static GDEFCORE_Result key_load(GDEFCORE_Subjects * subjects, const char * sid,
    int * out_erased, uint8_t wrapped[kWrap]) {
  uint8_t * got = NULL;
  size_t len = 0;
  int erased = 0;
  GDEFCORE_Result rc = from_stor(gdefstor_keystore_subject_sealed(subjects->keys,
      (const char *)subjects->tenant, subjects->tenant_len, sid,
      GDEFCORE_PUBLIC_ID_LEN, &erased, &got, &len));
  *out_erased = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (erased) {
    *out_erased = 1;
    return GDEFCORE_OK;
  }
  if (len != kWrap) {
    wipe(got, len);
    gcu_allocator_free(subjects->alloc, got);
    return GDEFCORE_ERR_CORRUPT;
  }
  memcpy(wrapped, got, kWrap);
  wipe(got, len);
  gcu_allocator_free(subjects->alloc, got);
  return GDEFCORE_OK;
}

/* Whether the subject is erased, and whether the key store knows it at all
 * (it has its key, or erased it). */
static GDEFCORE_Result subject_state(GDEFCORE_Subjects * subjects,
    const char * sid, int * out_erased, int * out_known) {
  uint8_t wrapped[kWrap];
  GDEFCORE_Result rc = key_load(subjects, sid, out_erased, wrapped);
  wipe(wrapped, sizeof wrapped);
  *out_known = rc == GDEFCORE_OK;
  if (rc == GDEFCORE_ERR_INVALID) {
    *out_erased = 0;
    return GDEFCORE_OK;
  }
  return rc;
}

static int64_t now_ms(void) {
  struct timespec ts;
  if (timespec_get(&ts, TIME_UTC) != TIME_UTC || ts.tv_sec < 0) {
    return -1;
  }
  return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

static GDEFCORE_Result adopt_wrap(const uint8_t * root, size_t root_len,
    const uint8_t * wrapped, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Keyring ** out) {
  return gdefcore_keyring_adopt(root, root_len, wrapped, kWrap, allocator, out);
}

GDEFCORE_Result gdefcore_subject_bind_keyring(GDEFSTOR_KeyStore * keys,
    const uint8_t * tenant, size_t tenant_len, const uint8_t * root,
    size_t root_len, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Keyring ** inout) {
  uint8_t wrapped[kWrap];
  int found = 0;
  GDEFCORE_Keyring * adopted = NULL;
  GDEFCORE_Result rc;
  if (keys == NULL || inout == NULL || tenant == NULL || tenant_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = wrap_load(keys, use_alloc(allocator), tenant, tenant_len, wrapped,
      &found);
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
  rc = wrap_store(keys, tenant, tenant_len, wrapped);
  wipe(wrapped, sizeof wrapped);
  return rc;
}

static GDEFCORE_Result replay_ledger(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * store);

GDEFCORE_Result gdefcore_subject_open(GDEFSTOR_KeyStore * keys,
    GDEFSTOR_Store * data, const uint8_t * tenant, size_t tenant_len,
    const uint8_t * root, size_t root_len, const GDEFCORE_Keyring * keyring,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Subjects ** out) {
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Subjects * subjects;
  uint8_t wrapped[kWrap];
  int found = 0;
  GDEFCORE_Result rc;
  if (keys == NULL || data == NULL || out == NULL || tenant == NULL ||
      tenant_len == 0 || root == NULL ||
      root_len != GDEFCORE_ACCOUNT_ROOT_LEN) {
    return GDEFCORE_ERR_INVALID;
  }
  alloc = use_alloc(allocator);
  subjects = (GDEFCORE_Subjects *)mem(alloc, sizeof *subjects);
  if (subjects == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(subjects, 0, sizeof *subjects);
  subjects->alloc = alloc;
  subjects->keys = keys;
  subjects->data = data;
  subjects->tenant = (uint8_t *)mem(alloc, tenant_len);
  if (subjects->tenant == NULL) {
    gcu_allocator_free(alloc, subjects);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(subjects->tenant, tenant, tenant_len);
  subjects->tenant_len = tenant_len;
  memcpy(subjects->root, root, root_len);
  rc = wrap_load(keys, alloc, tenant, tenant_len, wrapped, &found);
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
      rc = wrap_store(keys, tenant, tenant_len, wrapped);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = adopt_wrap(root, root_len, wrapped, alloc, &subjects->keyring);
  }
  wipe(wrapped, sizeof wrapped);
  if (rc == GDEFCORE_OK) {
    /* An erasure cut short after its key-store step is finished here. */
    rc = replay_ledger(subjects, subjects->data);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_subject_destroy(subjects);
    return rc;
  }
  *out = subjects;
  return GDEFCORE_OK;
}

/* ---- the cipher a key store is given ------------------------------------- */

static GDEFSTOR_Result cipher_random(void * ctx, uint8_t * out, size_t n) {
  (void)ctx;
  return gsec_random_bytes(out, n, NULL) == GSEC_OK ? GDEFSTOR_OK
                                                    : GDEFSTOR_ERR_IO;
}

/* nonce (12) | ciphertext | tag (16), under a 32-byte key, no associated
 * data: the key store binds a sealed value to its subject by the key. */
static GDEFSTOR_Result cipher_seal(void * ctx, const GDEFSTOR_Allocator * alloc,
    const uint8_t * key, const uint8_t * in, size_t n, uint8_t ** out,
    size_t * out_len) {
  uint8_t * o;
  (void)ctx;
  if (n > SIZE_MAX - kNonce - kTag) {
    return GDEFSTOR_ERR_LIMIT;
  }
  o = (uint8_t *)gcu_allocator_malloc(alloc, kNonce + n + kTag);
  if (o == NULL) {
    return GDEFSTOR_ERR_OOM;
  }
  if (gsec_random_bytes(o, kNonce, NULL) != GSEC_OK ||
      gsec_aes_gcm_encrypt(key, kKey, o, kNonce, NULL, 0, in, n, o + kNonce,
          o + kNonce + n, kTag) != GSEC_OK) {
    wipe(o, kNonce + n + kTag);
    gcu_allocator_free(alloc, o);
    return GDEFSTOR_ERR_IO;
  }
  *out = o;
  *out_len = kNonce + n + kTag;
  return GDEFSTOR_OK;
}

static GDEFSTOR_Result cipher_open(void * ctx, const GDEFSTOR_Allocator * alloc,
    const uint8_t * key, const uint8_t * in, size_t n, uint8_t ** out,
    size_t * out_len) {
  uint8_t * o;
  size_t plain;
  (void)ctx;
  if (n < kNonce + kTag) {
    return GDEFSTOR_ERR_CORRUPT;
  }
  plain = n - kNonce - kTag;
  o = (uint8_t *)gcu_allocator_malloc(alloc, plain == 0 ? 1 : plain);
  if (o == NULL) {
    return GDEFSTOR_ERR_OOM;
  }
  if (gsec_aes_gcm_decrypt(key, kKey, in, kNonce, NULL, 0, in + kNonce, plain,
          o, in + kNonce + plain, kTag) != GSEC_OK) {
    wipe(o, plain);
    gcu_allocator_free(alloc, o);
    return GDEFSTOR_ERR_CORRUPT;
  }
  *out = o;
  *out_len = plain;
  return GDEFSTOR_OK;
}

void gdefcore_subject_cipher(GDEFSTOR_KeyCipher * out) {
  if (out == NULL) {
    return;
  }
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  out->ctx = NULL;
  out->key_bytes = kKey;
  out->random = cipher_random;
  out->seal = cipher_seal;
  out->open = cipher_open;
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
  uint8_t wrapped[kWrap];
  int erased = 0;
  char * hex = NULL;
  size_t hex_len = 0;
  char * text = NULL;
  GDEFCORE_Result rc;
  /* A read of the key store, never a write: the save path writes the tenant
   * store only. */
  rc = key_load(subjects, subject, &erased, wrapped);
  if (rc == GDEFCORE_OK && erased) {
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc == GDEFCORE_OK) {
    rc = open_key(subjects, wrapped, raw);
  }
  wipe(wrapped, sizeof wrapped);
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
  /* The one key-store write of a subject's life before its erasure. */
  rc = from_stor(gdefstor_keystore_subject_put(subjects->keys,
      (const char *)subjects->tenant, subjects->tenant_len, id,
      GDEFCORE_PUBLIC_ID_LEN, wrapped, kWrap));
  wipe(wrapped, sizeof wrapped);
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

/* An erased subject takes no new value, and no new index row. */
static GDEFCORE_Result not_erased(GDEFCORE_Subjects * subjects, const char * sid) {
  int erased = 0;
  int known = 0;
  GDEFCORE_Result rc = subject_state(subjects, sid, &erased, &known);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
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
  /* Whose value it is, and its blind-index value, which the save writes in
   * the port's blind table in the revision's own write (story S6c). */
  rc = gdefcore_changeset_note_sealed(changeset, subjects, stored, stored_len,
      sid, GDEFCORE_PUBLIC_ID_LEN, mac);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_save(changeset, eid, GDEFCORE_PUBLIC_ID_LEN, lang,
        lang_len, &value, 1);
  }
  if (rc == GDEFCORE_OK) {
    if (kind == GDEFCORE_TYPE_CONFIG) {
      rc = gdefcore_changeset_apply(changeset, type, type_len);
    } else {
      rc = gdefcore_changeset_apply(changeset, NULL, 0);
    }
  }
  gdefcore_changeset_destroy(changeset);
  gdefcore_text_free(catalog, type);
  gcu_allocator_free(subjects->alloc, stored);
  return rc;
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

GDEFCORE_Result gdefcore_subject_erased(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, int * out_erased) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  int known = 0;
  GDEFCORE_Result rc;
  if (subjects == NULL || out_erased == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return subject_state(subjects, sid, out_erased, &known);
}

GDEFCORE_Result gdefcore_subject_read(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    const char * entity, size_t entity_len, const char * field, size_t field_len,
    const char * lang, size_t lang_len, char ** out_text, size_t * out_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eid[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  uint8_t wrapped[kWrap];
  int erased = 0;
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
  /* The key, unwrapped through the key store's answer: an erased subject has
   * none, so it reads as erased from the moment the key store destroyed it. */
  rc = key_load(subjects, sid, &erased, wrapped);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (erased) {
    return erased_text(subjects, out_text, out_len);
  }
  rc = open_key(subjects, wrapped, raw);
  wipe(wrapped, sizeof wrapped);
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
  int erased = 0;
  int known = 0;
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
  rc = subject_state(subjects, sid, &erased, &known);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
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

/* Erasure's second step, and the ledger replay's: the subject's blind-index
 * rows go from the data store @p store, every type's, through the port
 * (gdefstor_blind_delete_subject()). Idempotent: a subject with none writes
 * nothing. The ciphertext and the subject column stay, as the revisions do. */
static GDEFCORE_Result forget_blinds(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * store, const char * sid) {
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc = from_stor(gdefstor_write_begin(store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_stor(gdefstor_blind_delete_subject(write, sid,
      GDEFCORE_PUBLIC_ID_LEN));
  if (rc == GDEFCORE_OK) {
    rc = from_stor(gdefstor_write_commit(write));
  } else {
    gdefstor_write_abort(write);
  }
  return rc;
}

GDEFCORE_Result gdefcore_subject_erase(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * confirmation,
    size_t confirmation_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  int64_t when;
  int erased = 0;
  int known = 0;
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
  rc = subject_state(subjects, sid, &erased, &known);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!known) {
    return GDEFCORE_ERR_INVALID;
  }
  when = now_ms();
  if (when < 0) {
    return GDEFCORE_ERR_IO;
  }
  /* 1. The key store destroys the key and appends the ledger row, in one
   *    step of its own: from here every value of the subject is unreadable.
   *    Nothing else runs unless it succeeded. An erased subject has done it. */
  if (!erased) {
    rc = from_stor(gdefstor_keystore_erase(subjects->keys,
        (const char *)subjects->tenant, subjects->tenant_len, sid,
        GDEFCORE_PUBLIC_ID_LEN, when));
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  /* 2. Then the blind-index rows, in the data store. */
  rc = forget_blinds(subjects, subjects->data, sid);
  /* 3. Then caches: core keeps no cache of a subject's values or key, so
   *    there is nothing to purge yet. A cache that holds one purges here. */
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

/* The values of field @p field of entity @p eid in @p lang, as the entity is
 * now, published or not, each opened with the subject's key @p raw and added
 * to @p buf. A value that does not open under it is another subject's (a
 * multiple can hold several people's) and is left out. */
/* Whether value @p f of an item whose field is at @p ip is the field @p path. */
static int value_at_path(const char * ip, size_t ipn, const char * f,
    size_t fn, const char * path, size_t path_len) {
  if (fn == 0) {
    return span_eq(ip, ipn, path, path_len);
  }
  if (ipn == 0) {
    return span_eq(f, fn, path, path_len);
  }
  return path_len == ipn + 1 + fn && memcmp(path, ip, ipn) == 0 &&
         path[ipn] == '.' && memcmp(path + ipn + 1, f, fn) == 0;
}

/* The current texts of a field inside a group (story S6d), at any depth: the
 * flat read gdefcore_entity_values() sees the root's fields only. The texts
 * are borrowed from @p *out_tree, which the caller frees. */
static GDEFCORE_Result nested_texts(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * eid, const char * field,
    size_t field_len, const char * lang, size_t lang_len,
    GDEFCORE_Tree ** out_tree, const char *** out_texts, size_t ** out_lens,
    size_t * out_count) {
  GDEFCORE_Tree * tree = NULL;
  size_t n;
  size_t i;
  size_t count = 0;
  const char ** texts = NULL;
  size_t * lens = NULL;
  GDEFCORE_Result rc = gdefcore_entity_tree(catalog, NULL,
      GDEFCORE_VIEW_CURRENT, eid, GDEFCORE_PUBLIC_ID_LEN, lang, lang_len,
      &tree);
  *out_tree = NULL;
  *out_texts = NULL;
  *out_lens = NULL;
  *out_count = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  n = gdefcore_tree_item_count(tree);
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    GDEFCORE_TreeItem it;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(tree, i, &it) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * f = NULL;
      size_t fn = 0;
      const char * t = NULL;
      size_t tn = 0;
      if (gdefcore_tree_value(tree, i, k, &f, &fn, &t, &tn) != GDEFCORE_OK) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      if (!value_at_path(it.path, it.path_len, f, fn, field, field_len)) {
        continue;
      }
      {
        const char ** nt = (const char **)gcu_allocator_realloc(subjects->alloc,
            (void *)texts, (count + 1) * sizeof *nt);
        size_t * nl;
        if (nt == NULL) {
          rc = GDEFCORE_ERR_OOM;
          break;
        }
        texts = nt;
        nl = (size_t *)gcu_allocator_realloc(subjects->alloc, lens,
            (count + 1) * sizeof *nl);
        if (nl == NULL) {
          rc = GDEFCORE_ERR_OOM;
          break;
        }
        lens = nl;
        texts[count] = t;
        lens[count] = tn;
        count += 1;
      }
    }
  }
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(subjects->alloc, (void *)texts);
    gcu_allocator_free(subjects->alloc, lens);
    gdefcore_tree_free(tree);
    return rc;
  }
  *out_tree = tree;
  *out_texts = texts;
  *out_lens = lens;
  *out_count = count;
  return GDEFCORE_OK;
}

static GDEFCORE_Result export_values(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * sid, const uint8_t raw[kKey],
    const char * eid, const char * field, size_t field_len, const char * lang,
    size_t lang_len, Buf * buf, int * first) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Tree * nested = NULL;
  GDEFCORE_Result rc;
  if (memchr(field, '.', field_len) != NULL) {
    /* A field inside a group (story S6d): its values in every item. */
    rc = nested_texts(subjects, catalog, eid, field, field_len, lang,
        lang_len, &nested, (const char ***)&texts, &lens, &count);
  } else {
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_CURRENT, eid,
        GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, field_len, &texts,
        &lens, &count);
  }
  if (rc == GDEFCORE_ERR_INVALID) {
    /* Nothing there now (a cleared entity reads as one with no content). */
    return GDEFCORE_OK;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    char * plain = NULL;
    size_t plain_len = 0;
    GDEFCORE_Result open_rc = decrypt_text(subjects, sid, raw, field, field_len,
        texts[i], lens[i], &plain, &plain_len);
    if (open_rc == GDEFCORE_ERR_OOM) {
      rc = open_rc;
      break;
    }
    if (open_rc != GDEFCORE_OK) {
      continue;
    }
    if (!utf8_ok((const uint8_t *)plain, plain_len)) {
      rc = GDEFCORE_ERR_INVALID;
    } else {
      if (!*first) {
        buf_add(buf, ",", 1);
      }
      *first = 0;
      buf_add(buf, "{\"entity\":", 10);
      json_escape(buf, eid, GDEFCORE_PUBLIC_ID_LEN);
      buf_add(buf, ",\"field\":", 9);
      json_escape(buf, field, field_len);
      buf_add(buf, ",\"lang\":", 8);
      json_escape(buf, lang, lang_len);
      buf_add(buf, ",\"text\":", 8);
      json_escape(buf, plain, plain_len);
      buf_add(buf, "}", 1);
    }
    wipe(plain, plain_len);
    gdefcore_subject_free(subjects, plain);
  }
  if (nested != NULL || memchr(field, '.', field_len) != NULL) {
    gcu_allocator_free(subjects->alloc, (void *)texts);
    gcu_allocator_free(subjects->alloc, lens);
    gdefcore_tree_free(nested);
  } else {
    gdefcore_values_free(catalog, texts, lens, count);
  }
  return rc;
}

GDEFCORE_Result gdefcore_subject_export(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    char ** out_json, size_t * out_len) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  int erased = 0;
  uint8_t wrapped[kWrap];
  uint8_t raw[kKey];
  GDEFSTOR_SubjectHits * hits = NULL;
  Buf buf;
  int first = 1;
  size_t i;
  GDEFCORE_Result rc;
  if (subjects == NULL || out_json == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = key_load(subjects, sid, &erased, wrapped);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (erased) {
    *out_json = dup_n(subjects->alloc, "{\"erased\":\"[erased]\"}", 21);
    if (*out_json == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    *out_len = 21;
    return GDEFCORE_OK;
  }
  if (catalog == NULL) {
    wipe(wrapped, sizeof wrapped);
    return GDEFCORE_ERR_INVALID;
  }
  rc = open_key(subjects, wrapped, raw);
  wipe(wrapped, sizeof wrapped);
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  /* "Everything about this person": every value naming them, by the subject
   * column beside each ciphertext (AD-19), of which the current ones are
   * read. */
  rc = from_stor(gdefstor_subject_lookup(subjects->data,
      (const char *)subjects->tenant, subjects->tenant_len, sid,
      GDEFCORE_PUBLIC_ID_LEN, &hits));
  memset(&buf, 0, sizeof buf);
  buf.alloc = subjects->alloc;
  buf_add(&buf, "{\"values\":[", 11);
  for (i = 0; rc == GDEFCORE_OK && i < gdefstor_subject_hits_count(hits); i++) {
    GDEFSTOR_SubjectHit h;
    size_t k;
    int seen = 0;
    memset(&h, 0, sizeof h);
    h.size = sizeof h;
    rc = from_stor(gdefstor_subject_hit(hits, i, &h));
    if (rc != GDEFCORE_OK || h.valid_to != 0 ||
        h.public_id_len != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    /* One entry per entity, field and language: the field's items are read
     * together. */
    for (k = 0; k < i && !seen; k++) {
      GDEFSTOR_SubjectHit e;
      memset(&e, 0, sizeof e);
      e.size = sizeof e;
      seen = gdefstor_subject_hit(hits, k, &e) == GDEFSTOR_OK &&
             e.valid_to == 0 &&
             span_eq(e.public_id, e.public_id_len, h.public_id,
                 h.public_id_len) &&
             span_eq(e.field, e.field_len, h.field, h.field_len) &&
             span_eq(e.language, e.language_len, h.language, h.language_len);
    }
    if (!seen) {
      char eid[GDEFCORE_PUBLIC_ID_LEN + 1];
      memcpy(eid, h.public_id, GDEFCORE_PUBLIC_ID_LEN);
      eid[GDEFCORE_PUBLIC_ID_LEN] = '\0';
      rc = export_values(subjects, catalog, sid, raw, eid, h.field, h.field_len,
          h.language, h.language_len, &buf, &first);
    }
  }
  wipe(raw, sizeof raw);
  gdefstor_subject_hits_free(hits);
  buf_add(&buf, "]}", 2);
  if (rc != GDEFCORE_OK) {
    buf_free(&buf);
    return rc;
  }
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
  uint8_t wrapped[kWrap];
  int erased = 0;
  GDEFCORE_Result rc;
  if (subjects == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = key_load(subjects, sid, &erased, wrapped);
  if (rc == GDEFCORE_OK && erased) {
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc == GDEFCORE_OK) {
    rc = open_key(subjects, wrapped, out);
    if (rc != GDEFCORE_OK) {
      wipe(out, GDEFCORE_SUBJECT_KEY_LEN);
    }
  }
  wipe(wrapped, sizeof wrapped);
  return rc;
}

GDEFCORE_Result gdefcore_subject_mac(GDEFCORE_Subjects * subjects,
    const char * field, size_t field_len, const void * plain, size_t plain_len,
    uint8_t out[GDEFCORE_SUBJECT_MAC_LEN]) {
  uint8_t mac[kMac];
  GDEFCORE_Result rc;
  if (subjects == NULL || field == NULL || field_len == 0 || out == NULL ||
      (plain == NULL && plain_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = index_value(subjects, field, field_len, plain, plain_len, mac);
  if (rc == GDEFCORE_OK) {
    memcpy(out, mac, kMac);
  }
  wipe(mac, sizeof mac);
  return rc;
}

/* The MAC of a sealed value, opened with the key @p raw of @p sid. */
static GDEFCORE_Result mac_of_sealed(GDEFCORE_Subjects * subjects,
    const char * sid, const uint8_t raw[kKey], const char * field,
    size_t field_len, const char * sealed, size_t sealed_len,
    uint8_t out[kMac]) {
  char * plain = NULL;
  size_t plain_len = 0;
  GDEFCORE_Result rc = decrypt_text(subjects, sid, raw, field, field_len,
      sealed, sealed_len, &plain, &plain_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = index_value(subjects, field, field_len, plain, plain_len, out);
  wipe(plain, plain_len);
  gdefcore_subject_free(subjects, plain);
  return rc;
}

/* The subject's raw key, or ::GDEFCORE_ERR_INVALID when it is erased. */
static GDEFCORE_Result raw_key(GDEFCORE_Subjects * subjects, const char * sid,
    uint8_t raw[kKey]) {
  uint8_t wrapped[kWrap];
  int erased = 0;
  GDEFCORE_Result rc = key_load(subjects, sid, &erased, wrapped);
  if (rc == GDEFCORE_OK && erased) {
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc == GDEFCORE_OK) {
    rc = open_key(subjects, wrapped, raw);
  }
  wipe(wrapped, sizeof wrapped);
  if (rc != GDEFCORE_OK) {
    wipe(raw, kKey);
  }
  return rc;
}

GDEFCORE_Result gdefcore_subject_mac_sealed(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * field,
    size_t field_len, const char * sealed, size_t sealed_len,
    uint8_t out[GDEFCORE_SUBJECT_MAC_LEN]) {
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t raw[kKey];
  uint8_t mac[kMac];
  GDEFCORE_Result rc;
  if (subjects == NULL || field == NULL || field_len == 0 || out == NULL ||
      sealed == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canon_id(subject, subject_len, sid);
  if (rc == GDEFCORE_OK) {
    rc = raw_key(subjects, sid, raw);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = mac_of_sealed(subjects, sid, raw, field, field_len, sealed, sealed_len,
      mac);
  wipe(raw, sizeof raw);
  if (rc == GDEFCORE_OK) {
    memcpy(out, mac, kMac);
  }
  wipe(mac, sizeof mac);
  return rc;
}

GDEFCORE_Result gdefcore_subject_find(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * type, size_t type_len,
    const char * field, size_t field_len, const char * lang, size_t lang_len,
    const void * plain, size_t plain_len, char *** out_ids, size_t * out_count) {
  uint8_t mac[kMac];
  GDEFSTOR_QueryText text;
  GDEFSTOR_QueryNode node;
  GDEFSTOR_Query q;
  GDEFCORE_Result rc;
  if (out_ids == NULL || out_count == NULL || catalog == NULL || lang == NULL ||
      lang_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_ids = NULL;
  *out_count = 0;
  rc = gdefcore_subject_mac(subjects, field, field_len, plain, plain_len, mac);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  text.bytes = mac;
  text.len = sizeof mac;
  memset(&node, 0, sizeof node);
  node.op = GDEFSTOR_QUERY_BLIND;
  node.left.kind = GDEFSTOR_QUERY_FIELD;
  node.left.field = field;
  node.left.field_len = field_len;
  node.right.kind = GDEFSTOR_QUERY_CONST;
  node.right.texts = &text;
  node.right.text_count = 1;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.where = &node;
  q.language = lang;
  q.language_len = lang_len;
  rc = gdefcore_entity_query_current(catalog, type, type_len, &q, out_ids,
      out_count, NULL);
  wipe(mac, sizeof mac);
  return rc;
}

/* One subject's rows put back: every version naming it, opened with its key,
 * gets the row its value's MAC makes. */
static GDEFCORE_Result reindex_subject(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * data, const char * sid, size_t * rows) {
  uint8_t raw[kKey];
  GDEFSTOR_SubjectHits * hits = NULL;
  GDEFSTOR_Write * write = NULL;
  size_t i;
  GDEFCORE_Result rc = raw_key(subjects, sid, raw);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK; /* erased: its key is gone, and so are its rows */
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_stor(gdefstor_subject_lookup(data, (const char *)subjects->tenant,
      subjects->tenant_len, sid, GDEFCORE_PUBLIC_ID_LEN, &hits));
  if (rc == GDEFCORE_OK && gdefstor_subject_hits_count(hits) > 0) {
    rc = from_stor(gdefstor_write_begin(data, (const char *)subjects->tenant,
        subjects->tenant_len, NULL, &write));
  }
  for (i = 0; rc == GDEFCORE_OK && write != NULL &&
              i < gdefstor_subject_hits_count(hits);
       i++) {
    GDEFSTOR_SubjectHit h;
    GDEFSTOR_Tree * tree = NULL;
    GDEFSTOR_Value v;
    size_t n;
    size_t k;
    int found = 0;
    const char * leaf;
    size_t leaf_len;
    memset(&h, 0, sizeof h);
    h.size = sizeof h;
    rc = from_stor(gdefstor_subject_hit(hits, i, &h));
    if (rc != GDEFCORE_OK) {
      break;
    }
    leaf = h.field;
    leaf_len = h.field_len;
    for (k = h.field_len; k > 0; k--) {
      if (h.field[k - 1] == '.') {
        leaf = h.field + k;
        leaf_len = h.field_len - k;
        break;
      }
    }
    /* The version as it was when it began: its item in that revision. */
    rc = from_stor(gdefstor_entity_tree(data, (const char *)subjects->tenant,
        subjects->tenant_len, h.public_id, h.public_id_len, h.language,
        h.language_len, h.valid_from, &tree));
    n = rc == GDEFCORE_OK ? gdefstor_tree_item_count(tree) : 0;
    memset(&v, 0, sizeof v);
    for (k = 0; rc == GDEFCORE_OK && k < n && !found; k++) {
      GDEFSTOR_TreeItem it;
      memset(&it, 0, sizeof it);
      it.size = sizeof it;
      if (gdefstor_tree_item(tree, k, &it) != GDEFSTOR_OK) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      if (it.id != h.item) {
        continue;
      }
      found = 1;
      if (span_eq(it.field, it.field_len, leaf, leaf_len)) {
        rc = from_stor(gdefstor_tree_get(tree, k, NULL, 0, &v));
      } else {
        rc = from_stor(gdefstor_tree_get(tree, k, leaf, leaf_len, &v));
      }
    }
    if (rc == GDEFCORE_OK && (!found || v.type == 0 || v.bytes == NULL)) {
      rc = GDEFCORE_ERR_CORRUPT; /* the lookup named a version that is not there */
    }
    if (rc == GDEFCORE_OK) {
      uint8_t mac[kMac];
      GDEFSTOR_BlindMac m;
      rc = mac_of_sealed(subjects, sid, raw, h.field, h.field_len,
          (const char *)v.bytes, v.len, mac);
      if (rc == GDEFCORE_OK) {
        memset(&m, 0, sizeof m);
        m.size = sizeof m;
        m.mac = mac;
        m.mac_len = sizeof mac;
        m.key_id = GDEFCORE_SUBJECT_MAC_KEY_ID;
        m.version = GDEFCORE_SUBJECT_MAC_VERSION;
        rc = from_stor(gdefstor_blind_put(write, h.type, h.type_len,
            h.public_id, h.public_id_len, h.field, h.field_len, h.item,
            h.valid_from, h.language, h.language_len, &m));
      }
      wipe(mac, sizeof mac);
      if (rc == GDEFCORE_OK && rows != NULL) {
        *rows += 1;
      }
    }
    gdefstor_tree_free(tree);
  }
  wipe(raw, sizeof raw);
  gdefstor_subject_hits_free(hits);
  if (write != NULL) {
    if (rc == GDEFCORE_OK) {
      rc = from_stor(gdefstor_write_commit(write));
    } else {
      gdefstor_write_abort(write);
    }
  }
  return rc;
}

GDEFCORE_Result gdefcore_subject_reindex(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * data, size_t * out_rows) {
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFSTOR_KeySet * set = NULL;
  size_t rows = 0;
  size_t i;
  int64_t taken;
  GDEFCORE_Result rc;
  if (subjects == NULL || data == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (out_rows != NULL) {
    *out_rows = 0;
  }
  taken = now_ms();
  if (taken < 0) {
    return GDEFCORE_ERR_IO;
  }
  /* The subjects the key store holds a key for: the only ones whose values
   * can be opened, so the only ones indexed (AD-19). */
  rc = from_stor(gdefstor_keystore_export(subjects->keys,
      (const char *)subjects->tenant, subjects->tenant_len, taken, &bytes,
      &len));
  if (rc == GDEFCORE_OK) {
    rc = from_stor(gdefstor_keyset_parse(subjects->alloc, bytes, len, &set));
  }
  for (i = 0; rc == GDEFCORE_OK && i < gdefstor_keyset_count(set); i++) {
    GDEFSTOR_KeyRow row;
    char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
    rc = from_stor(gdefstor_keyset_row(set, i, &row));
    if (rc == GDEFCORE_OK && row.kind == GDEFSTOR_KEYROW_SEALED &&
        canon_id(row.name, row.name_len, sid) == GDEFCORE_OK) {
      rc = reindex_subject(subjects, data, sid, &rows);
    }
  }
  gdefstor_keyset_free(set);
  if (bytes != NULL) {
    wipe(bytes, len);
  }
  gdefstor_bytes_free(NULL, bytes);
  if (rc == GDEFCORE_OK && out_rows != NULL) {
    *out_rows = rows;
  }
  return rc;
}

/* The ledger replay: erasure's second step again for every subject the key
 * store's ledger names. Each is a no-op once done, so this writes only what
 * an interrupted erasure left. */
static GDEFCORE_Result replay_ledger(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * store) {
  GDEFSTOR_Ledger * ledger = NULL;
  size_t i;
  GDEFCORE_Result rc = from_stor(gdefstor_keystore_ledger(subjects->keys,
      (const char *)subjects->tenant, subjects->tenant_len, &ledger));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; rc == GDEFCORE_OK && i < gdefstor_ledger_count(ledger); i++) {
    const char * id = NULL;
    size_t id_len = 0;
    int64_t when = 0;
    char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
    rc = from_stor(gdefstor_ledger_row(ledger, i, &id, &id_len, &when));
    if (rc == GDEFCORE_OK && canon_id(id, id_len, sid) == GDEFCORE_OK) {
      /* A row that is not a public id is not one of ours to replay. */
      rc = forget_blinds(subjects, store, sid);
    }
  }
  gdefstor_ledger_free(ledger);
  return rc;
}

GDEFCORE_Result gdefcore_subject_snapshot(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * tenant_store, uint8_t ** out_bytes, size_t * out_len) {
  int64_t taken;
  if (subjects == NULL || tenant_store == NULL || out_bytes == NULL ||
      out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  taken = now_ms();
  if (taken < 0) {
    return GDEFCORE_ERR_IO;
  }
  /* The data set: the tenant's rows and when they were taken. No key, no
   * keyring wrap and no ledger: those are the key set's. */
  return from_stor(gdefstor_snapshot_export_at(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, taken,
      out_bytes, out_len));
}

GDEFCORE_Result gdefcore_subject_keyset(GDEFCORE_Subjects * subjects,
    uint8_t ** out_bytes, size_t * out_len) {
  int64_t taken;
  if (subjects == NULL || out_bytes == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  taken = now_ms();
  if (taken < 0) {
    return GDEFCORE_ERR_IO;
  }
  return from_stor(gdefstor_keystore_export(subjects->keys,
      (const char *)subjects->tenant, subjects->tenant_len, taken, out_bytes,
      out_len));
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

/* One entity a snapshot names: its type and its public id, as the entity
 * part spells them (defiant-storage's formats.md). An internal (decimal) id,
 * an id that is not a canonical public id, and an installation-scope type are
 * refused (AD-34, AD-37). */
static GDEFCORE_Result judge_entity(const GTEXT_JSON_Value * type,
    const GTEXT_JSON_Value * entity) {
  const char * entity_text = NULL;
  size_t entity_len = 0;
  const char * type_text = NULL;
  size_t type_len = 0;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  if (gtext_json_get_string(entity, &entity_text, &entity_len) !=
      GTEXT_JSON_OK) {
    return GDEFCORE_ERR_CORRUPT;
  }
  if (digits_only(entity_text, entity_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(entity_text, entity_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gtext_json_get_string(type, &type_text, &type_len) == GTEXT_JSON_OK &&
      span_is(type_text, type_len, "core.tenant")) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

/* A member of the entity part that names a tenant, or names an entity it
 * must not: one entity's revisions (`"format":"defiant-revision/1"`, its
 * `type` and `id`) or a type's entities (`type` and `entities`, each with an
 * `id`). */
static GDEFCORE_Result judge_object(const GTEXT_JSON_Value * root) {
  const GTEXT_JSON_Value * format;
  const GTEXT_JSON_Value * type;
  const GTEXT_JSON_Value * entities;
  const char * format_text = NULL;
  size_t format_len = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (gtext_json_typeof(root) != GTEXT_JSON_OBJECT) {
    return GDEFCORE_OK;
  }
  if (gtext_json_object_get(root, "tenant", 6) != NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  type = gtext_json_object_get(root, "type", 4);
  format = gtext_json_object_get(root, "format", 6);
  if (gtext_json_get_string(format, &format_text, &format_len) ==
          GTEXT_JSON_OK &&
      format_len >= 17 && memcmp(format_text, "defiant-revision/", 17) == 0) {
    return judge_entity(type, gtext_json_object_get(root, "id", 2));
  }
  entities = gtext_json_object_get(root, "entities", 8);
  if (type != NULL && gtext_json_typeof(entities) == GTEXT_JSON_ARRAY) {
    size_t i;
    for (i = 0; rc == GDEFCORE_OK && i < gtext_json_array_size(entities); i++) {
      const GTEXT_JSON_Value * e = gtext_json_array_get(entities, i);
      if (gtext_json_typeof(e) != GTEXT_JSON_OBJECT) {
        return GDEFCORE_ERR_CORRUPT;
      }
      rc = judge_entity(type, gtext_json_object_get(e, "id", 2));
    }
  }
  return rc;
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
 * named tenant, an internal id, an installation-scope type or a mistyped
 * public id refuses the import. */
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
    if (rc == GDEFCORE_OK) {
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

/* When the key set was taken, and whether its keyring wrap, if it has one,
 * is this tenant's. */
static GDEFCORE_Result keyset_check(GDEFCORE_Subjects * subjects,
    const uint8_t * keys, size_t keys_len, int64_t * out_taken) {
  GDEFSTOR_KeySet * set = NULL;
  uint8_t wrap[kWrap];
  size_t i;
  GDEFCORE_Result rc = from_stor(gdefstor_keyset_parse(subjects->alloc, keys,
      keys_len, &set));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_taken = gdefstor_keyset_taken(set);
  rc = gdefcore_keyring_export(subjects->keyring, wrap, kWrap);
  for (i = 0; rc == GDEFCORE_OK && i < gdefstor_keyset_count(set); i++) {
    GDEFSTOR_KeyRow row;
    rc = from_stor(gdefstor_keyset_row(set, i, &row));
    if (rc == GDEFCORE_OK && row.kind == GDEFSTOR_KEYROW_SECRET &&
        span_eq(row.name, row.name_len, kKeyringSecret, strlen(kKeyringSecret)) &&
        (row.len != kWrap || memcmp(row.bytes, wrap, kWrap) != 0)) {
      rc = GDEFCORE_ERR_INVALID; /* another tenant's, or another keyring's */
    }
  }
  wipe(wrap, sizeof wrap);
  gdefstor_keyset_free(set);
  return rc;
}

GDEFCORE_Result gdefcore_subject_restore(GDEFCORE_Subjects * subjects,
    GDEFSTOR_Store * tenant_store, const uint8_t * data, size_t data_len,
    const uint8_t * keys, size_t keys_len) {
  int found = 0;
  int64_t data_taken = 0;
  int64_t keys_taken = 0;
  GDEFCORE_Result rc;
  if (subjects == NULL || tenant_store == NULL ||
      (data == NULL && data_len != 0) || (keys == NULL && keys_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = archive_refuse(subjects->alloc, data, data_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_stor(gdefstor_snapshot_taken(tenant_store, data, data_len, NULL,
      &found, &data_taken));
  if (rc == GDEFCORE_OK && !found) {
    rc = GDEFCORE_ERR_FORMAT; /* not a data set: it says when it was taken */
  }
  if (rc == GDEFCORE_OK) {
    rc = keyset_check(subjects, keys, keys_len, &keys_taken);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* A key set older than its data set may hold a key erased after it was
   * taken and before the data set was: refused, and nothing is written. */
  if (keys_taken < data_taken) {
    return GDEFCORE_ERR_STALE;
  }
  /* The keys first: a merge that brings no key back for a subject either
   * ledger names, and that a retry repeats as a no-op. */
  rc = from_stor(gdefstor_keystore_import(subjects->keys,
      (const char *)subjects->tenant, subjects->tenant_len, keys, keys_len));
  if (rc == GDEFCORE_OK) {
    rc = from_stor(gdefstor_snapshot_import(tenant_store,
        (const char *)subjects->tenant, subjects->tenant_len, data, data_len,
        NULL));
  }
  if (rc == GDEFCORE_OK) {
    /* Then the ledger, the live one and the set's together now, before
     * anything is served from the restored tenant: in it, and in this
     * subjects' own data store, whose blind rows an erasure the set's ledger
     * names would otherwise keep. */
    rc = replay_ledger(subjects, tenant_store);
    if (rc == GDEFCORE_OK && tenant_store != subjects->data) {
      rc = replay_ledger(subjects, subjects->data);
    }
  }
  if (rc == GDEFCORE_OK) {
    /* Last, the derived data a data set leaves out (AD-23): the blind index,
     * from the values that can still be decrypted. */
    rc = gdefcore_subject_reindex(subjects, tenant_store, NULL);
  }
  return rc;
}
