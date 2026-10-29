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
 * The session's message queue. A message is one record of the environment
 * scope (tenant byte 0x03, namespace core.message), under a key that holds the
 * tenant, a keyed digest of the session and a sequence number, and whose value
 * is sealed with AES-256-GCM. What the seal authenticates is the version, the
 * tenant, the session digest, the sequence number and the expiry, so a record
 * moved anywhere else, or altered, does not open.
 *
 * Every change to the queue is one write of the environment scope. Those writes
 * are serialised by the store, and the queue is read inside the write, so a
 * claim (read, delete, commit) is atomic: two requests of a session cannot both
 * claim one message.
 */

#include <ghoti.io/defiant-core/macros.h>

#include "message_internal.h"

#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/message.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>

#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/store.h>
#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  kVersion = 1,
  kKey = 32,
  kNonce = 12,
  kTag = 16,
  kDigest = 16,
  kIdLen = 16,
  kHead = 1 + 8 + kNonce, /* version, expiry, nonce */
  kPage = 64
};

static const char kEnvTenant[] = "\x03";
static const char kNs[] = "core.message";
static const char kPurpose[] = "message";
static const char kAttach[] = "core.message.box";
static const char kAadTag[] = "gdefcore-message";

static void wipe(void * p, size_t n) {
  if (p != NULL && n > 0) {
    (void)gsec_wipe(p, n);
  }
}

static GDEFCORE_Result from_gsec(GSEC_Result rc) {
  if (rc == GSEC_OK) {
    return GDEFCORE_OK;
  }
  if (rc == GSEC_ERR_LIMIT) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (rc == GSEC_ERR_OOM) {
    return GDEFCORE_ERR_OOM;
  }
  if (rc == GSEC_ERR_IO) {
    return GDEFCORE_ERR_IO;
  }
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result map_stor(GDEFSTOR_Result r) {
  switch (r) {
  case GDEFSTOR_OK:
    return GDEFCORE_OK;
  case GDEFSTOR_ERR_OOM:
    return GDEFCORE_ERR_OOM;
  case GDEFSTOR_ERR_LIMIT:
    return GDEFCORE_ERR_LIMIT;
  case GDEFSTOR_ERR_INVALID:
    return GDEFCORE_ERR_INVALID;
  default:
    return GDEFCORE_ERR_IO;
  }
}

static void put_u64(uint8_t * p, uint64_t v) {
  int i;
  for (i = 7; i >= 0; i--) {
    p[i] = (uint8_t)v;
    v >>= 8;
  }
}

static uint64_t get_u64(const uint8_t * p) {
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; i++) {
    v = (v << 8) | p[i];
  }
  return v;
}

static const char kHex[] = "0123456789abcdef";

static void to_hex(char * out, const uint8_t * in, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    out[2 * i] = kHex[in[i] >> 4];
    out[2 * i + 1] = kHex[in[i] & 15];
  }
}

/* The record key prefix of a session's queue: <tenant hex>:<digest hex>: */
static int queue_prefix(GDEFCORE_Catalog * catalog, const Mailbox * box,
    char * out, size_t cap, size_t * out_len) {
  size_t tn = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tn);
  size_t at = 0;
  if (tenant == NULL || tn == 0 || tn * 2 + 1 + kDigest * 2 + 1 + kIdLen + 1 > cap) {
    return 0;
  }
  to_hex(out, tenant, tn);
  at = tn * 2;
  out[at++] = ':';
  to_hex(out + at, box->digest, kDigest);
  at += kDigest * 2;
  out[at++] = ':';
  out[at] = '\0';
  *out_len = at;
  return 1;
}

static void put_id(char * out, uint64_t seq) {
  int i;
  for (i = kIdLen - 1; i >= 0; i--) {
    out[i] = kHex[seq & 15];
    seq >>= 4;
  }
}

static int get_id(const char * s, size_t n, uint64_t * seq) {
  uint64_t v = 0;
  size_t i;
  if (n != kIdLen) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    int d;
    if (c >= '0' && c <= '9') {
      d = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      d = c - 'a' + 10;
    } else {
      return 0;
    }
    v = (v << 4) | (uint64_t)d;
  }
  *seq = v;
  return 1;
}

/* What the seal authenticates, built in @p aad (cap 128 + tenant). */
static GDEFCORE_Result build_aad(GDEFCORE_Catalog * catalog, const Mailbox * box,
    const char * id, uint64_t expiry, uint8_t ** out, size_t * out_len) {
  size_t tn = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tn);
  size_t n;
  size_t at = 0;
  uint8_t * aad;
  if (tenant == NULL || tn == 0 || tn > 0xffff) {
    return GDEFCORE_ERR_INVALID;
  }
  n = sizeof kAadTag + 1 + 2 + tn + kDigest + kIdLen + 8;
  aad = (uint8_t *)malloc(n);
  if (aad == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(aad + at, kAadTag, sizeof kAadTag);
  at += sizeof kAadTag;
  aad[at++] = kVersion;
  aad[at++] = (uint8_t)(tn >> 8);
  aad[at++] = (uint8_t)tn;
  memcpy(aad + at, tenant, tn);
  at += tn;
  memcpy(aad + at, box->digest, kDigest);
  at += kDigest;
  memcpy(aad + at, id, kIdLen);
  at += kIdLen;
  put_u64(aad + at, expiry);
  at += 8;
  *out = aad;
  *out_len = at;
  return GDEFCORE_OK;
}

static GDEFCORE_Result seal(GDEFCORE_Catalog * catalog, const Mailbox * box,
    const char * id, uint64_t expiry, int kind, const char * text, size_t text_len,
    uint8_t ** out, size_t * out_len) {
  uint8_t * aad = NULL;
  size_t aad_n = 0;
  uint8_t * plain;
  uint8_t * rec;
  size_t plain_n = 1 + text_len;
  GDEFCORE_Result rc = build_aad(catalog, box, id, expiry, &aad, &aad_n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  plain = (uint8_t *)malloc(plain_n);
  rec = (uint8_t *)malloc(kHead + plain_n + kTag);
  if (plain == NULL || rec == NULL) {
    free(aad);
    free(plain);
    free(rec);
    return GDEFCORE_ERR_OOM;
  }
  plain[0] = (uint8_t)kind;
  if (text_len > 0) {
    memcpy(plain + 1, text, text_len);
  }
  rec[0] = kVersion;
  put_u64(rec + 1, expiry);
  rc = from_gsec(gsec_random_bytes(rec + 9, kNonce, NULL));
  if (rc == GDEFCORE_OK) {
    rc = from_gsec(gsec_aes_gcm_encrypt(box->key, kKey, rec + 9, kNonce, aad, aad_n,
        plain, plain_n, rec + kHead, rec + kHead + plain_n, kTag));
  }
  wipe(plain, plain_n);
  free(plain);
  free(aad);
  if (rc != GDEFCORE_OK) {
    free(rec);
    return rc;
  }
  *out = rec;
  *out_len = kHead + plain_n + kTag;
  return GDEFCORE_OK;
}

/* Open a record. 1 when it opens: *kind, *text (malloc'd, NUL-terminated) and
 * *expiry are set. 0 when it is altered, misplaced, from another version or
 * too short, which are all the same answer: it shows nothing. */
static int open_record(GDEFCORE_Catalog * catalog, const Mailbox * box,
    const char * id, const uint8_t * rec, size_t n, int * kind, char ** text,
    size_t * text_len, uint64_t * expiry) {
  uint8_t * aad = NULL;
  size_t aad_n = 0;
  uint8_t * plain;
  size_t plain_n;
  uint64_t exp;
  int ok;
  if (n < kHead + 1 + kTag || rec[0] != kVersion) {
    return 0;
  }
  plain_n = n - kHead - kTag;
  if (plain_n - 1 > GDEFCORE_MESSAGE_TEXT_MAX) {
    return 0;
  }
  exp = get_u64(rec + 1);
  if (build_aad(catalog, box, id, exp, &aad, &aad_n) != GDEFCORE_OK) {
    return 0;
  }
  plain = (uint8_t *)malloc(plain_n + 1);
  if (plain == NULL) {
    free(aad);
    return 0;
  }
  ok = from_gsec(gsec_aes_gcm_decrypt(box->key, kKey, rec + 9, kNonce, aad, aad_n,
           rec + kHead, plain_n, plain, rec + kHead + plain_n, kTag)) == GDEFCORE_OK;
  free(aad);
  if (!ok || plain[0] < GDEFCORE_MESSAGE_STATUS || plain[0] > GDEFCORE_MESSAGE_REFUSAL) {
    wipe(plain, plain_n);
    free(plain);
    return 0;
  }
  *kind = plain[0];
  memmove(plain, plain + 1, plain_n - 1);
  plain[plain_n - 1] = '\0';
  *text = (char *)plain;
  *text_len = plain_n - 1;
  *expiry = exp;
  return 1;
}

static void box_release(void * data) {
  if (data != NULL) {
    wipe(data, sizeof(Mailbox));
    free(data);
  }
}

GDEFCORE_Result gdefcore_message_bind(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring, const uint8_t * root,
    size_t root_len, const char * session, size_t session_len) {
  Mailbox * box;
  uint8_t index_key[kKey];
  uint8_t info[256];
  size_t tn = 0;
  const uint8_t * tenant;
  uint64_t expiry = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || keyring == NULL || root == NULL ||
      session == NULL || session_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tn);
  if (tenant == NULL || tn == 0 || tn > 200) {
    return GDEFCORE_ERR_INVALID;
  }
  /* A session that is not live for this tenant has no queue. */
  rc = gdefcore_account_session_expiry(catalog, keyring, root, root_len, session,
      session_len, &expiry);
  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  box = (Mailbox *)calloc(1, sizeof *box);
  if (box == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  rc = gdefcore_keyring_derive(keyring, root, root_len, kPurpose,
      sizeof kPurpose - 1, box->key, kKey);
  if (rc == GDEFCORE_OK) {
    static const char kIndex[] = "message-index";
    rc = gdefcore_keyring_derive(keyring, root, root_len, kIndex, sizeof kIndex - 1,
        index_key, kKey);
  }
  if (rc == GDEFCORE_OK) {
    /* The digest names the session in the store: a keyed function of the tenant
     * and the token, so the store never holds the token and a digest cannot be
     * made without the keyring. */
    memcpy(info, tenant, tn);
    rc = from_gsec(gsec_hkdf(GSEC_HKDF_SHA256, (const uint8_t *)session,
        session_len, index_key, kKey, info, tn, box->digest, kDigest));
  }
  wipe(index_key, sizeof index_key);
  if (rc != GDEFCORE_OK) {
    box_release(box);
    return rc;
  }
  box->session_expiry = expiry;
  rc = gdefcore_request_attach(request, kAttach, box, box_release);
  if (rc != GDEFCORE_OK) {
    box_release(box);
    return rc;
  }
  return GDEFCORE_OK;
}

/* One record of the queue, as listed. */
typedef struct Listed {
  char key[GDEFSTOR_RECORD_MAX_KEY_BYTES + 1];
  size_t key_len;
  uint8_t * rec;
  size_t rec_len;
  uint64_t seq;
} Listed;

static void listed_free(Listed * l, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    free(l[i].rec);
  }
  free(l);
}

/* The session's records inside the write @p w (so no other write of the
 * environment scope is between this read and its commit). */
static GDEFCORE_Result list_queue(GDEFCORE_Catalog * catalog, const char * prefix,
    size_t prefix_len, Listed ** out, size_t * n_out) {
  GDEFSTOR_RecordList * list = NULL;
  Listed * l;
  size_t n;
  size_t i;
  size_t kept = 0;
  GDEFCORE_Result rc;
  *out = NULL;
  *n_out = 0;
  rc = map_stor(gdefstor_record_list(gdefcore_catalog_store(catalog), kEnvTenant, 1,
      kNs, sizeof kNs - 1, prefix, prefix_len, 0, kPage, &list));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  n = gdefstor_record_list_count(list);
  l = (Listed *)calloc(n == 0 ? 1 : n, sizeof *l);
  if (l == NULL) {
    gdefstor_record_list_free(list);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    const char * key;
    size_t key_len;
    const uint8_t * bytes;
    size_t len;
    uint64_t seq = 0;
    if (gdefstor_record_list_item(list, i, &key, &key_len, &bytes, &len, NULL, NULL) !=
            GDEFSTOR_OK ||
        key_len >= sizeof l[0].key) {
      continue;
    }
    memcpy(l[kept].key, key, key_len);
    l[kept].key[key_len] = '\0';
    l[kept].key_len = key_len;
    /* A key that is not a sequence number is a record to drop. */
    l[kept].seq = get_id(key + prefix_len, key_len - prefix_len, &seq) ? seq : 0;
    l[kept].rec = (uint8_t *)malloc(len == 0 ? 1 : len);
    if (l[kept].rec == NULL) {
      gdefstor_record_list_free(list);
      listed_free(l, kept);
      return GDEFCORE_ERR_OOM;
    }
    if (len > 0) {
      memcpy(l[kept].rec, bytes, len);
    }
    l[kept].rec_len = len;
    kept += 1;
  }
  gdefstor_record_list_free(list);
  *out = l;
  *n_out = kept;
  return GDEFCORE_OK;
}

static Mailbox * box_of(GDEFCORE_Request * request) {
  return (Mailbox *)gdefcore_request_attached(request, kAttach);
}

GDEFCORE_Result gdefcore_message_post(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, int kind, const char * text, size_t text_len) {
  Mailbox * box;
  char prefix[GDEFSTOR_RECORD_MAX_KEY_BYTES + 1];
  size_t prefix_len = 0;
  GDEFSTOR_Write * write = NULL;
  Listed * l = NULL;
  size_t n = 0;
  size_t i;
  size_t live = 0;
  uint64_t top = 0;
  uint64_t expiry;
  int64_t now;
  char key[GDEFSTOR_RECORD_MAX_KEY_BYTES + 1];
  uint8_t * rec = NULL;
  size_t rec_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || (text == NULL && text_len != 0) ||
      kind < GDEFCORE_MESSAGE_STATUS || kind > GDEFCORE_MESSAGE_REFUSAL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (text_len > GDEFCORE_MESSAGE_TEXT_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  box = box_of(request);
  if (box == NULL || !queue_prefix(catalog, box, prefix, sizeof prefix, &prefix_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  now = gdefcore_request_time(request);
  if (now < 0) {
    return GDEFCORE_ERR_INVALID;
  }
  expiry = (uint64_t)now + GDEFCORE_MESSAGE_LIFE;
  if (box->session_expiry < expiry) {
    expiry = box->session_expiry;
  }
  if (expiry <= (uint64_t)now) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = map_stor(gdefstor_write_begin(gdefcore_catalog_store(catalog), kEnvTenant, 1,
      NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = list_queue(catalog, prefix, prefix_len, &l, &n);
  /* Expired and unreadable records go; then the oldest, to make room. */
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    int k;
    char * t = NULL;
    size_t tl = 0;
    uint64_t e = 0;
    int ok = l[i].seq != 0 &&
             open_record(catalog, box, l[i].key + prefix_len, l[i].rec, l[i].rec_len,
                 &k, &t, &tl, &e);
    if (ok) {
      wipe(t, tl);
      free(t);
    }
    if (l[i].seq > top) {
      top = l[i].seq;
    }
    if (!ok || e <= (uint64_t)now) {
      rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1, l[i].key,
          l[i].key_len, NULL));
      l[i].seq = 0;
    } else {
      live += 1;
    }
  }
  for (i = 0; rc == GDEFCORE_OK && i < n && live >= GDEFCORE_MESSAGE_QUEUE_MAX; i++) {
    if (l[i].seq != 0) {
      rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1, l[i].key,
          l[i].key_len, NULL));
      l[i].seq = 0;
      live -= 1;
    }
  }
  if (rc == GDEFCORE_OK) {
    memcpy(key, prefix, prefix_len);
    put_id(key + prefix_len, top + 1);
    key[prefix_len + kIdLen] = '\0';
    rc = seal(catalog, box, key + prefix_len, expiry, kind, text, text_len, &rec,
        &rec_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = map_stor(gdefstor_record_put(write, kNs, sizeof kNs - 1, key,
        prefix_len + kIdLen, GDEFCORE_SCHEMA_CORE_STAMP,
        sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, rec, rec_len));
  }
  free(rec);
  listed_free(l, n);
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return map_stor(gdefstor_write_commit(write));
}

struct GDEFCORE_Messages {
  int * kind;
  char ** text;
  size_t * len;
  size_t n;
};

void gdefcore_messages_free(GDEFCORE_Messages * m) {
  size_t i;
  if (m == NULL) {
    return;
  }
  for (i = 0; i < m->n; i++) {
    wipe(m->text[i], m->len[i]);
    free(m->text[i]);
  }
  free(m->kind);
  free(m->text);
  free(m->len);
  free(m);
}

size_t gdefcore_messages_count(const GDEFCORE_Messages * m) {
  return m == NULL ? 0 : m->n;
}

GDEFCORE_Result gdefcore_messages_item(const GDEFCORE_Messages * m, size_t index,
    GDEFCORE_Message * out) {
  if (m == NULL || out == NULL || out->size != sizeof *out || index >= m->n) {
    return GDEFCORE_ERR_INVALID;
  }
  out->kind = m->kind[index];
  out->text = m->text[index];
  out->text_len = m->len[index];
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_message_take(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Messages ** out) {
  Mailbox * box;
  char prefix[GDEFSTOR_RECORD_MAX_KEY_BYTES + 1];
  size_t prefix_len = 0;
  GDEFSTOR_Write * write = NULL;
  Listed * l = NULL;
  size_t n = 0;
  size_t i;
  GDEFCORE_Messages * m;
  int64_t now;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  box = box_of(request);
  if (box == NULL || !queue_prefix(catalog, box, prefix, sizeof prefix, &prefix_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  now = gdefcore_request_time(request);
  m = (GDEFCORE_Messages *)calloc(1, sizeof *m);
  if (m == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  rc = map_stor(gdefstor_write_begin(gdefcore_catalog_store(catalog), kEnvTenant, 1,
      NULL, &write));
  if (rc != GDEFCORE_OK) {
    free(m);
    return rc;
  }
  rc = list_queue(catalog, prefix, prefix_len, &l, &n);
  if (rc == GDEFCORE_OK && n > 0) {
    m->kind = (int *)calloc(n, sizeof(int));
    m->text = (char **)calloc(n, sizeof(char *));
    m->len = (size_t *)calloc(n, sizeof(size_t));
    if (m->kind == NULL || m->text == NULL || m->len == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  /* Every record is deleted in this write, the ones that show and the ones
   * that do not; what shows is what the same write deleted. */
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    int kind = 0;
    char * text = NULL;
    size_t text_len = 0;
    uint64_t exp = 0;
    int deleted = 0;
    int ok = l[i].seq != 0 &&
             open_record(catalog, box, l[i].key + prefix_len, l[i].rec, l[i].rec_len,
                 &kind, &text, &text_len, &exp);
    rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1, l[i].key,
        l[i].key_len, &deleted));
    if (rc != GDEFCORE_OK) {
      if (ok) {
        wipe(text, text_len);
        free(text);
      }
      break;
    }
    if (ok && deleted && now >= 0 && exp > (uint64_t)now) {
      m->kind[m->n] = kind;
      m->text[m->n] = text;
      m->len[m->n] = text_len;
      m->n += 1;
    } else if (ok) {
      wipe(text, text_len);
      free(text);
    }
  }
  listed_free(l, n);
  if (rc == GDEFCORE_OK) {
    rc = map_stor(gdefstor_write_commit(write));
  } else {
    gdefstor_write_abort(write);
  }
  if (rc != GDEFCORE_OK) {
    /* Nothing was committed, so nothing was claimed. */
    gdefcore_messages_free(m);
    return rc;
  }
  *out = m;
  return GDEFCORE_OK;
}
