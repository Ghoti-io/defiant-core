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
 * Accounts, one username each, and session tokens. The password is
 * Argon2id ciphertext under the tenant secret key. The epoch lives on
 * its own entity so reverting the account cannot lower it. The keyring
 * never enters the catalog.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>

#include "account_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/store.h>
#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/argon2.h>
#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>

#include <string.h>
#include <stdio.h>
#include <time.h>

enum {
  kAlg = 1,
  kKeyId = 1,
  kVersion = 1,
  kKey = 32,
  kNonce = 12,
  kTag = 16,
  kTokenSalt = 32,
  kArgonSalt = 16,
  kUserMax = 128,
  kPhcCap = 480,
  kBlobCap = 544,
  kHexCap = 1088,
  kTenantMax = 256,
  kSid = 16,
  kSidHex = 32,
  kPlain = 82,
  kRawCap = 192,
  kExpDigits = 20,
  kExpKey = kExpDigits + 1 + kSidHex,
  kPurgeBatch = 64,
  kWrapLen = 63
};

/* A revoked session stays on the list until its token has been expired for
 * this long, in seconds, so that nodes whose clocks differ by less than it
 * never see a revoked token live again. */
static const uint64_t kPurgeGrace = 300;

/* The record namespaces of revoked sessions (accounts.md): `revoked` is keyed
 * by the session id in hex and holds its expiry; `revoked.exp` is keyed
 * `<20-digit expiry>.<session id in hex>` with an empty value, so that the
 * oldest expiry is first and a purge reads one bounded page. */
static const char kRevokedNs[] = "core.session.revoked";
static const char kRevokedExpNs[] = "core.session.revoked.exp";

static const char kLang[] = "en";
static const char kAccountType[] = "core.account";
static const char kEpochType[] = "core.account_epoch";
static const char kPrincipalType[] = "core.principal";
static const char kAccountConfirm[] = "core.account";
static const char kEpochConfirm[] = "core.account_epoch";
static const char kBothConfirm[] = "core.account\ncore.account_epoch";
static const char kSession[] = "session";
static const char kSecret[] = "secret";

struct GDEFCORE_Keyring {
  const GDEFCORE_Allocator * alloc;
  uint8_t blob[kWrapLen];
};

static void wipe(void * p, size_t n) {
  if (p != NULL && n > 0) {
    gsec_wipe(p, n);
  }
}

static int same(const char * a, size_t an, const char * b, size_t bn) {
  if (an != bn) {
    return 0;
  }
  if (an == 0) {
    return 1;
  }
  if (a == NULL || b == NULL) {
    return 0;
  }
  return memcmp(a, b, an) == 0;
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
    p[i] = (uint8_t)v;
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

static int parse_u64(const char * s, size_t n, uint64_t * out) {
  uint64_t v = 0;
  size_t i;
  if (n == 0 || n > 20) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    unsigned d;
    if (s[i] < '0' || s[i] > '9') {
      return 0;
    }
    d = (unsigned)(s[i] - '0');
    if (v > UINT64_MAX / 10u) {
      return 0;
    }
    v *= 10u;
    if (v > UINT64_MAX - d) {
      return 0;
    }
    v += d;
  }
  *out = v;
  return 1;
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

static GDEFCORE_Result hex_encode(const uint8_t * in, size_t n, char * out,
    size_t cap, size_t * out_n) {
  static const char kDigits[] = "0123456789abcdef";
  size_t i;
  if (cap < 1 || n > (cap - 1) / 2) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < n; i++) {
    out[i * 2] = kDigits[in[i] >> 4];
    out[i * 2 + 1] = kDigits[in[i] & 0x0fu];
  }
  out[n * 2] = '\0';
  *out_n = n * 2;
  return GDEFCORE_OK;
}

static GDEFCORE_Result hex_decode(const char * in, size_t n, uint8_t * out,
    size_t cap, size_t * out_n) {
  size_t i;
  if ((n % 2u) != 0 || (n / 2u) > cap) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < n; i += 2) {
    int hi = hex_nibble(in[i]);
    int lo = hex_nibble(in[i + 1]);
    if (hi < 0 || lo < 0) {
      return GDEFCORE_ERR_INVALID;
    }
    out[i / 2] = (uint8_t)((hi << 4) | lo);
  }
  *out_n = n / 2u;
  return GDEFCORE_OK;
}

static int username_ok(const char * username, size_t n) {
  size_t i;
  if (username == NULL || n == 0 || n > kUserMax) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (username[i] == '\n' || username[i] == '\r') {
      return 0;
    }
  }
  return 1;
}

static int password_ok(const void * password, size_t n) {
  if (n == 0 || n > GDEFCORE_ACCOUNT_PASSWORD_MAX) {
    return 0;
  }
  return password != NULL;
}

static void field_set(GDEFCORE_Field * field, const char * name) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = 1;
}

static void value_set(GDEFCORE_Value * value, const char * field,
    const char * const * texts, const size_t * lens, size_t count) {
  memset(value, 0, sizeof *value);
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = texts;
  value->text_lens = lens;
  value->count = count;
}

static GDEFCORE_Result define_named(GDEFCORE_Catalog * catalog,
    const char * name, const GDEFCORE_Field * fields, size_t count) {
  int kind = 0;
  GDEFCORE_Result rc = gdefcore_type_kind(catalog, name, strlen(name), &kind);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  return gdefcore_type_define(catalog, name, strlen(name),
      GDEFCORE_TYPE_CONFIG, fields, count);
}

static GDEFCORE_Result ensure_types(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field account_fields[4];
  GDEFCORE_Field epoch_fields[1];
  GDEFCORE_Result rc;
  field_set(&account_fields[0], "principal");
  field_set(&account_fields[1], "username");
  field_set(&account_fields[2], "password");
  field_set(&account_fields[3], "epoch_id");
  field_set(&epoch_fields[0], "epoch");
  rc = define_named(catalog, kAccountType, account_fields, 4);
  if (rc == GDEFCORE_OK) {
    rc = define_named(catalog, kEpochType, epoch_fields, 1);
  }
  return rc;
}

static GDEFCORE_Result read_text(GDEFCORE_Catalog * catalog, const char * id,
    const char * field, char * buf, size_t cap, size_t * out_n) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc;
  *out_n = 0;
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, kLang, strlen(kLang), field, strlen(field),
      &texts, &lens, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count != 1 || texts == NULL || lens == NULL || texts[0] == NULL ||
      lens[0] >= cap) {
    int too_big = count == 1 && lens != NULL && lens[0] >= cap;
    gdefcore_values_free(catalog, texts, lens, count);
    return too_big ? GDEFCORE_ERR_LIMIT : GDEFCORE_ERR_INVALID;
  }
  memcpy(buf, texts[0], lens[0]);
  buf[lens[0]] = '\0';
  *out_n = lens[0];
  gdefcore_values_free(catalog, texts, lens, count);
  return GDEFCORE_OK;
}

static GDEFCORE_Result apply_high(GDEFCORE_Changeset * changeset,
    const char * confirm) {
  int risk = 0;
  GDEFCORE_Result rc = gdefcore_changeset_rate(changeset, &risk);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (risk != GDEFCORE_RISK_HIGH) {
    return GDEFCORE_ERR_INTERNAL;
  }
  return gdefcore_changeset_apply(changeset, confirm, strlen(confirm));
}

static GDEFCORE_Result save_fields(GDEFCORE_Catalog * catalog,
    const char * id, const GDEFCORE_Value * values, size_t count,
    const char * confirm) {
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog, NULL, 0,
      &changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      strlen(kLang), values, count);
  if (rc == GDEFCORE_OK) {
    rc = apply_high(changeset, confirm);
  }
  gdefcore_changeset_destroy(changeset);
  return rc;
}

static int root_ok(const uint8_t * root, size_t root_len) {
  return root != NULL && root_len == GDEFCORE_ACCOUNT_ROOT_LEN;
}

static GDEFCORE_Result unwrap(const GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, uint8_t out[kKey]) {
  uint8_t aad[8];
  GSEC_Result rc;
  if (keyring == NULL || !root_ok(root, root_len) ||
      keyring->blob[0] != kVersion || keyring->blob[1] != kAlg ||
      keyring->blob[2] != kKeyId) {
    return GDEFCORE_ERR_INVALID;
  }
  memcpy(aad, "keyring", 7);
  aad[7] = kKeyId;
  rc = gsec_aes_gcm_decrypt(root, kKey, keyring->blob + 3, kNonce, aad,
      sizeof aad, keyring->blob + 15, kKey, out, keyring->blob + 47, kTag);
  return from_gsec(rc);
}

static GDEFCORE_Result derive(const uint8_t raw[kKey], const void * info,
    size_t info_len, uint8_t out[kKey]) {
  return from_gsec(gsec_hkdf(GSEC_HKDF_SHA256, NULL, 0, raw, kKey, info,
      info_len, out, kKey));
}

static GDEFCORE_Result purpose_key(const GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * info,
    uint8_t out[kKey]) {
  uint8_t raw[kKey];
  GDEFCORE_Result rc = unwrap(keyring, root, root_len, raw);
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  rc = derive(raw, info, strlen(info), out);
  wipe(raw, sizeof raw);
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

static GDEFCORE_Result hash_password(const void * password, size_t password_len,
    char * phc, size_t cap, size_t * phc_len) {
  uint8_t salt[kArgonSalt];
  GDEFCORE_Result rc = from_gsec(gsec_random_bytes(salt, sizeof salt, NULL));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_gsec(gsec_argon2_phc(GSEC_ARGON2_VERSION_13, GSEC_ARGON2_ID,
      password, password_len, salt, sizeof salt, NULL, 0, NULL, 0,
      GDEFCORE_ACCOUNT_ARGON_MEMORY, GDEFCORE_ACCOUNT_ARGON_PASSES,
      GDEFCORE_ACCOUNT_ARGON_LANES, GDEFCORE_ACCOUNT_ARGON_TAG, phc, cap,
      phc_len));
  wipe(salt, sizeof salt);
  return rc;
}

static GDEFCORE_Result dummy_hash(const void * password, size_t password_len) {
  uint8_t salt[kArgonSalt];
  uint8_t tag[GDEFCORE_ACCOUNT_ARGON_TAG];
  GDEFCORE_Result rc = from_gsec(gsec_random_bytes(salt, sizeof salt, NULL));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_gsec(gsec_argon2(GSEC_ARGON2_ID, password, password_len, salt,
      sizeof salt, NULL, 0, NULL, 0, GDEFCORE_ACCOUNT_ARGON_MEMORY,
      GDEFCORE_ACCOUNT_ARGON_PASSES, GDEFCORE_ACCOUNT_ARGON_LANES, tag,
      sizeof tag));
  wipe(salt, sizeof salt);
  wipe(tag, sizeof tag);
  return rc;
}

static GDEFCORE_Result tenant_of(GDEFCORE_Catalog * catalog,
    const uint8_t ** out, size_t * out_len) {
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog, out_len);
  if (tenant == NULL || *out_len == 0 || *out_len > kTenantMax) {
    return *out_len > kTenantMax ? GDEFCORE_ERR_LIMIT : GDEFCORE_ERR_INVALID;
  }
  *out = tenant;
  return GDEFCORE_OK;
}

static GDEFCORE_Result seal_password(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const void * password, size_t password_len, char * hex, size_t * hex_len) {
  char phc[kPhcCap];
  uint8_t blob[kBlobCap];
  uint8_t secret[kKey];
  uint8_t nonce[kNonce];
  uint8_t tag[kTag];
  uint8_t aad[kTenantMax + 8];
  const uint8_t * tenant = NULL;
  size_t tenant_len = 0;
  size_t phc_len = 0;
  size_t blob_len = 0;
  GDEFCORE_Result   rc = hash_password(password, password_len, phc, sizeof phc,
      &phc_len);
  if (rc != GDEFCORE_OK) {
    wipe(phc, sizeof phc);
    return rc;
  }
  rc = purpose_key(keyring, root, root_len, kSecret, secret);
  if (rc != GDEFCORE_OK) {
    wipe(phc, sizeof phc);
    return rc;
  }
  rc = from_gsec(gsec_random_bytes(nonce, sizeof nonce, NULL));
  if (rc != GDEFCORE_OK) {
    wipe(phc, sizeof phc);
    wipe(secret, sizeof secret);
    return rc;
  }
  rc = tenant_of(catalog, &tenant, &tenant_len);
  if (rc != GDEFCORE_OK) {
    wipe(phc, sizeof phc);
    wipe(secret, sizeof secret);
    return rc;
  }
  memcpy(aad, tenant, tenant_len);
  memcpy(aad + tenant_len, kSecret, strlen(kSecret));
  aad[tenant_len + strlen(kSecret)] = kKeyId;
  if (phc_len + 33 > sizeof blob) {
    wipe(phc, sizeof phc);
    wipe(secret, sizeof secret);
    return GDEFCORE_ERR_LIMIT;
  }
  rc = from_gsec(gsec_aes_gcm_encrypt(secret, kKey, nonce, sizeof nonce, aad,
      tenant_len + strlen(kSecret) + 1, phc, phc_len, blob + 17, tag, kTag));
  wipe(secret, sizeof secret);
  wipe(phc, sizeof phc);
  if (rc != GDEFCORE_OK) {
    wipe(blob, sizeof blob);
    wipe(tag, sizeof tag);
    return rc;
  }
  blob[0] = kVersion;
  blob[1] = kAlg;
  blob[2] = kKeyId;
  memcpy(blob + 3, nonce, sizeof nonce);
  put_u16(blob + 15, (uint16_t)phc_len);
  memcpy(blob + 17 + phc_len, tag, kTag);
  blob_len = 17 + phc_len + kTag;
  rc = hex_encode(blob, blob_len, hex, kHexCap, hex_len);
  wipe(blob, sizeof blob);
  wipe(tag, sizeof tag);
  return rc;
}

static GDEFCORE_Result open_password(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * hex, size_t hex_len, char * phc, size_t cap, size_t * phc_len) {
  uint8_t blob[kBlobCap];
  uint8_t secret[kKey];
  uint8_t plain[kPhcCap];
  uint8_t aad[kTenantMax + 8];
  const uint8_t * tenant = NULL;
  size_t tenant_len = 0;
  size_t blob_len = 0;
  uint16_t ct_len = 0;
  GDEFCORE_Result rc = hex_decode(hex, hex_len, blob, sizeof blob, &blob_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (blob_len < 33 || blob[0] != kVersion || blob[1] != kAlg ||
      blob[2] != kKeyId) {
    wipe(blob, blob_len);
    return GDEFCORE_ERR_INVALID;
  }
  ct_len = get_u16(blob + 15);
  if ((size_t)ct_len + 33 != blob_len || ct_len >= cap || ct_len >= sizeof plain) {
    wipe(blob, blob_len);
    return GDEFCORE_ERR_INVALID;
  }
  rc = purpose_key(keyring, root, root_len, kSecret, secret);
  if (rc != GDEFCORE_OK) {
    wipe(blob, blob_len);
    return rc;
  }
  rc = tenant_of(catalog, &tenant, &tenant_len);
  if (rc != GDEFCORE_OK) {
    wipe(blob, blob_len);
    wipe(secret, sizeof secret);
    return rc;
  }
  memcpy(aad, tenant, tenant_len);
  memcpy(aad + tenant_len, kSecret, strlen(kSecret));
  aad[tenant_len + strlen(kSecret)] = kKeyId;
  rc = from_gsec(gsec_aes_gcm_decrypt(secret, kKey, blob + 3, kNonce, aad,
      tenant_len + strlen(kSecret) + 1, blob + 17, ct_len, plain,
      blob + 17 + ct_len, kTag));
  wipe(secret, sizeof secret);
  wipe(blob, blob_len);
  if (rc != GDEFCORE_OK) {
    wipe(plain, sizeof plain);
    return rc;
  }
  memcpy(phc, plain, ct_len);
  *phc_len = ct_len;
  wipe(plain, sizeof plain);
  return GDEFCORE_OK;
}

static GDEFCORE_Result canonical_copy(const char * id, size_t id_len,
    char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  return gdefcore_id_canonical(id, id_len, out);
}

static GDEFCORE_Result find_username(GDEFCORE_Catalog * catalog,
    const char * username, size_t username_len, int * found,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc;
  *found = 0;
  rc = gdefcore_entity_ids(catalog, kAccountType, strlen(kAccountType), &ids,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char user[kUserMax + 1];
    size_t n = 0;
    if (read_text(catalog, ids[i], "username", user, sizeof user, &n) !=
        GDEFCORE_OK) {
      continue;
    }
    if (same(user, n, username, username_len)) {
      memcpy(out_id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      *found = 1;
      break;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  return GDEFCORE_OK;
}

static GDEFCORE_Result principal_taken(GDEFCORE_Catalog * catalog,
    const char * principal, int * taken) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc;
  *taken = 0;
  rc = gdefcore_entity_ids(catalog, kAccountType, strlen(kAccountType), &ids,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char held[GDEFCORE_PUBLIC_ID_LEN + 1];
    size_t n = 0;
    if (read_text(catalog, ids[i], "principal", held, sizeof held, &n) !=
        GDEFCORE_OK) {
      continue;
    }
    if (same(held, n, principal, GDEFCORE_PUBLIC_ID_LEN)) {
      *taken = 1;
      break;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  return GDEFCORE_OK;
}

static GDEFCORE_Result principal_is(GDEFCORE_Catalog * catalog,
    const char * principal) {
  char * type = NULL;
  size_t n = 0;
  int ok = 0;
  GDEFCORE_Result rc = gdefcore_entity_type(catalog, principal,
      GDEFCORE_PUBLIC_ID_LEN, &type, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  ok = same(type, n, kPrincipalType, strlen(kPrincipalType));
  gdefcore_text_free(catalog, type);
  return ok ? GDEFCORE_OK : GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result store_new(GDEFCORE_Catalog * catalog,
    const char * principal, const char * username, size_t username_len,
    const char * hex, size_t hex_len, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char epoch_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char account_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const char * epoch_text = "1";
  size_t epoch_len = 1;
  const char * texts[4];
  size_t lens[4];
  GDEFCORE_Value values[4];
  GDEFCORE_Value epoch_value;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = gdefcore_entity_create(catalog, kEpochType,
      strlen(kEpochType), epoch_id, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_create(catalog, kAccountType, strlen(kAccountType),
      account_id, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  value_set(&epoch_value, "epoch", &epoch_text, &epoch_len, 1);
  texts[0] = principal;
  lens[0] = GDEFCORE_PUBLIC_ID_LEN;
  texts[1] = username;
  lens[1] = username_len;
  texts[2] = hex;
  lens[2] = hex_len;
  texts[3] = epoch_id;
  lens[3] = GDEFCORE_PUBLIC_ID_LEN;
  value_set(&values[0], "principal", &texts[0], &lens[0], 1);
  value_set(&values[1], "username", &texts[1], &lens[1], 1);
  value_set(&values[2], "password", &texts[2], &lens[2], 1);
  value_set(&values[3], "epoch_id", &texts[3], &lens[3], 1);
  rc = gdefcore_entity_save(changeset, epoch_id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      strlen(kLang), &epoch_value, 1);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_save(changeset, account_id, GDEFCORE_PUBLIC_ID_LEN,
        kLang, strlen(kLang), values, 4);
  }
  if (rc == GDEFCORE_OK) {
    rc = apply_high(changeset, kBothConfirm);
  }
  gdefcore_changeset_destroy(changeset);
  if (rc == GDEFCORE_OK) {
    memcpy(out_id, account_id, GDEFCORE_PUBLIC_ID_LEN + 1);
  }
  return rc;
}

static GDEFCORE_Result load_epoch(GDEFCORE_Catalog * catalog, const char * id,
    char epoch_id[GDEFCORE_PUBLIC_ID_LEN + 1], uint64_t * out_epoch) {
  char text[32];
  size_t id_len = 0;
  size_t n = 0;
  GDEFCORE_Result rc = read_text(catalog, id, "epoch_id", epoch_id,
      GDEFCORE_PUBLIC_ID_LEN + 1, &id_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (id_len != GDEFCORE_PUBLIC_ID_LEN) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = read_text(catalog, epoch_id, "epoch", text, sizeof text, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!parse_u64(text, n, out_epoch) || *out_epoch == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result write_epoch(GDEFCORE_Catalog * catalog,
    const char * epoch_id, uint64_t epoch) {
  char text[32];
  const char * held = text;
  size_t n = 0;
  GDEFCORE_Value value;
  int wrote = snprintf(text, sizeof text, "%llu", (unsigned long long)epoch);
  if (wrote <= 0 || (size_t)wrote >= sizeof text) {
    return GDEFCORE_ERR_LIMIT;
  }
  n = (size_t)wrote;
  value_set(&value, "epoch", &held, &n, 1);
  return save_fields(catalog, epoch_id, &value, 1, kEpochConfirm);
}

static GDEFCORE_Result bump_epoch(GDEFCORE_Catalog * catalog, const char * id,
    uint64_t * out_next) {
  char epoch_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t epoch = 0;
  GDEFCORE_Result rc = load_epoch(catalog, id, epoch_id, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (epoch == UINT64_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = write_epoch(catalog, epoch_id, epoch + 1u);
  if (rc == GDEFCORE_OK && out_next != NULL) {
    *out_next = epoch + 1u;
  }
  return rc;
}

static GDEFCORE_Result confirm_user(GDEFCORE_Catalog * catalog, const char * id,
    const char * confirmation, size_t confirmation_len) {
  char user[kUserMax + 1];
  size_t n = 0;
  GDEFCORE_Result rc;
  if (confirmation == NULL || confirmation_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = read_text(catalog, id, "username", user, sizeof user, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!same(user, n, confirmation, confirmation_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

static void clear_identity(GDEFCORE_Request * request) {
  gdefcore_request_set_principal(request, NULL, 0);
  gdefcore_request_set_acting_principal(request, NULL, 0);
}

static GDEFCORE_Result set_principal(GDEFCORE_Request * request,
    const char * principal) {
  GDEFCORE_Result rc = gdefcore_request_set_principal(request, principal,
      GDEFCORE_PUBLIC_ID_LEN);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return gdefcore_request_set_acting_principal(request, NULL, 0);
}

GDEFCORE_Result gdefcore_keyring_create(const uint8_t * root, size_t root_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Keyring ** out_keyring) {
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Keyring * keyring = NULL;
  uint8_t raw[kKey];
  uint8_t nonce[kNonce];
  uint8_t tag[kTag];
  uint8_t aad[8];
  GDEFCORE_Result rc;
  if (!root_ok(root, root_len) || out_keyring == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  alloc = allocator == NULL ? gdefcore_allocator_default() : allocator;
  keyring = (GDEFCORE_Keyring *)gcu_allocator_malloc(alloc, sizeof *keyring);
  if (keyring == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(keyring, 0, sizeof *keyring);
  keyring->alloc = alloc;
  memset(raw, 0, sizeof raw);
  memset(nonce, 0, sizeof nonce);
  rc = from_gsec(gsec_random_bytes(raw, sizeof raw, NULL));
  if (rc == GDEFCORE_OK) {
    rc = from_gsec(gsec_random_bytes(nonce, sizeof nonce, NULL));
  }
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    gcu_allocator_free(alloc, keyring);
    return rc;
  }
  memcpy(aad, "keyring", 7);
  aad[7] = kKeyId;
  rc = from_gsec(gsec_aes_gcm_encrypt(root, kKey, nonce, sizeof nonce, aad,
      sizeof aad, raw, sizeof raw, keyring->blob + 15, tag, kTag));
  wipe(raw, sizeof raw);
  if (rc != GDEFCORE_OK) {
    wipe(keyring, sizeof *keyring);
    gcu_allocator_free(alloc, keyring);
    return rc;
  }
  keyring->blob[0] = kVersion;
  keyring->blob[1] = kAlg;
  keyring->blob[2] = kKeyId;
  memcpy(keyring->blob + 3, nonce, sizeof nonce);
  memcpy(keyring->blob + 47, tag, kTag);
  keyring->alloc = alloc;
  *out_keyring = keyring;
  return GDEFCORE_OK;
}

void gdefcore_keyring_destroy(GDEFCORE_Keyring * keyring) {
  const GDEFCORE_Allocator * alloc;
  if (keyring == NULL) {
    return;
  }
  alloc = keyring->alloc;
  wipe(keyring, sizeof *keyring);
  gcu_allocator_free(alloc, keyring);
}

GDEFCORE_Result gdefcore_keyring_export(const GDEFCORE_Keyring * keyring,
    uint8_t * out, size_t out_len) {
  if (keyring == NULL || out == NULL || out_len != kWrapLen) {
    return GDEFCORE_ERR_INVALID;
  }
  memcpy(out, keyring->blob, kWrapLen);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_keyring_adopt(const uint8_t * root, size_t root_len,
    const uint8_t * wrapped, size_t wrapped_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Keyring ** out_keyring) {
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Keyring * keyring;
  uint8_t raw[kKey];
  GDEFCORE_Result rc;
  if (!root_ok(root, root_len) || wrapped == NULL || wrapped_len != kWrapLen ||
      out_keyring == NULL || wrapped[0] != kVersion || wrapped[1] != kAlg ||
      wrapped[2] != kKeyId) {
    return GDEFCORE_ERR_INVALID;
  }
  alloc = allocator == NULL ? gdefcore_allocator_default() : allocator;
  keyring = (GDEFCORE_Keyring *)gcu_allocator_malloc(alloc, sizeof *keyring);
  if (keyring == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(keyring, 0, sizeof *keyring);
  keyring->alloc = alloc;
  memcpy(keyring->blob, wrapped, kWrapLen);
  rc = unwrap(keyring, root, root_len, raw);
  wipe(raw, sizeof raw);
  if (rc != GDEFCORE_OK) {
    wipe(keyring, sizeof *keyring);
    gcu_allocator_free(alloc, keyring);
    return rc;
  }
  *out_keyring = keyring;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_keyring_derive(const GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const void * info, size_t info_len,
    uint8_t * out, size_t out_len) {
  uint8_t raw[kKey];
  GDEFCORE_Result rc;
  if (keyring == NULL || out == NULL || out_len != kKey ||
      (info == NULL && info_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = unwrap(keyring, root, root_len, raw);
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  rc = derive(raw, info, info_len, out);
  wipe(raw, sizeof raw);
  if (rc != GDEFCORE_OK) {
    wipe(out, out_len);
  }
  return rc;
}

GDEFCORE_Result gdefcore_account_bind(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * principal, size_t principal_len, const char * username,
    size_t username_len, const void * password, size_t password_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char hex[kHexCap];
  size_t hex_len = 0;
  int taken = 0;
  int found = 0;
  char existing[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (catalog == NULL || keyring == NULL || out_id == NULL ||
      !root_ok(root, root_len) || !username_ok(username, username_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (password_len > GDEFCORE_ACCOUNT_PASSWORD_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (!password_ok(password, password_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canonical_copy(principal, principal_len, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = ensure_types(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = principal_is(catalog, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = principal_taken(catalog, canon, &taken);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (taken) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_username(catalog, username, username_len, &found, existing);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (found) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = seal_password(catalog, keyring, root, root_len, password, password_len,
      hex, &hex_len);
  if (rc != GDEFCORE_OK) {
    wipe(hex, sizeof hex);
    return rc;
  }
  rc = store_new(catalog, canon, username, username_len, hex, hex_len, out_id);
  wipe(hex, sizeof hex);
  return rc;
}

GDEFCORE_Result gdefcore_account_create(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * username, size_t username_len, const void * password,
    size_t password_len, char out_principal[GDEFCORE_PUBLIC_ID_LEN + 1],
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char hex[kHexCap];
  size_t hex_len = 0;
  int found = 0;
  char existing[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (catalog == NULL || keyring == NULL || out_principal == NULL ||
      out_id == NULL || !root_ok(root, root_len) ||
      !username_ok(username, username_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (password_len > GDEFCORE_ACCOUNT_PASSWORD_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (!password_ok(password, password_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure_types(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_username(catalog, username, username_len, &found, existing);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (found) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = seal_password(catalog, keyring, root, root_len, password, password_len,
      hex, &hex_len);
  if (rc != GDEFCORE_OK) {
    wipe(hex, sizeof hex);
    return rc;
  }
  rc = gdefcore_access_principal_create(catalog, principal);
  if (rc != GDEFCORE_OK) {
    wipe(hex, sizeof hex);
    return rc;
  }
  rc = store_new(catalog, principal, username, username_len, hex, hex_len,
      out_id);
  wipe(hex, sizeof hex);
  if (rc == GDEFCORE_OK) {
    memcpy(out_principal, principal, GDEFCORE_PUBLIC_ID_LEN + 1);
  }
  return rc;
}

static GDEFCORE_Result mint_token(GDEFCORE_Catalog * catalog,
    const uint8_t session[kKey], const char * account,
    const char * principal, uint64_t epoch, uint64_t expiry, char ** out_token,
    size_t * out_token_len) {
  uint8_t salt[kTokenSalt];
  uint8_t nonce[kNonce];
  uint8_t token_key[kKey];
  uint8_t plain[kPlain];
  uint8_t ct[kPlain];
  uint8_t tag[kTag];
  uint8_t aad[kTenantMax + 32];
  uint8_t raw[kRawCap];
  const uint8_t * tenant = NULL;
  size_t tenant_len = 0;
  size_t aad_len = 0;
  size_t raw_len = 0;
  GDEFCORE_Result rc = from_gsec(gsec_random_bytes(salt, sizeof salt, NULL));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = from_gsec(gsec_random_bytes(nonce, sizeof nonce, NULL));
  if (rc != GDEFCORE_OK) {
    wipe(salt, sizeof salt);
    return rc;
  }
  /* The session id: 128 bits from the CSPRNG, sealed in the plaintext. */
  rc = from_gsec(gsec_random_bytes(plain + 66, kSid, NULL));
  if (rc != GDEFCORE_OK) {
    wipe(salt, sizeof salt);
    wipe(plain, sizeof plain);
    return rc;
  }
  rc = from_gsec(gsec_hkdf(GSEC_HKDF_SHA256, salt, sizeof salt, session, kKey,
      NULL, 0, token_key, kKey));
  if (rc != GDEFCORE_OK) {
    wipe(salt, sizeof salt);
    wipe(plain, sizeof plain);
    return rc;
  }
  rc = tenant_of(catalog, &tenant, &tenant_len);
  if (rc != GDEFCORE_OK) {
    wipe(salt, sizeof salt);
    wipe(plain, sizeof plain);
    wipe(token_key, sizeof token_key);
    return rc;
  }
  put_u32(aad, (uint32_t)tenant_len);
  memcpy(aad + 4, tenant, tenant_len);
  memcpy(aad + 4 + tenant_len, kSession, strlen(kSession));
  aad[4 + tenant_len + strlen(kSession)] = kKeyId;
  put_u64(aad + 5 + tenant_len + strlen(kSession), expiry);
  aad_len = 13 + tenant_len + strlen(kSession);
  put_u64(plain, epoch);
  plain[8] = GDEFCORE_PUBLIC_ID_LEN;
  memcpy(plain + 9, account, GDEFCORE_PUBLIC_ID_LEN);
  plain[37] = GDEFCORE_PUBLIC_ID_LEN;
  memcpy(plain + 38, principal, GDEFCORE_PUBLIC_ID_LEN);
  rc = from_gsec(gsec_aes_gcm_encrypt(token_key, kKey, nonce, sizeof nonce, aad,
      aad_len, plain, sizeof plain, ct, tag, kTag));
  wipe(token_key, sizeof token_key);
  wipe(plain, sizeof plain);
  if (rc != GDEFCORE_OK) {
    wipe(salt, sizeof salt);
    wipe(ct, sizeof ct);
    wipe(tag, sizeof tag);
    return rc;
  }
  raw[0] = kVersion;
  raw[1] = kAlg;
  raw[2] = kKeyId;
  raw[3] = (uint8_t)strlen(kSession);
  memcpy(raw + 4, kSession, strlen(kSession));
  put_u64(raw + 11, expiry);
  memcpy(raw + 19, salt, sizeof salt);
  memcpy(raw + 51, nonce, sizeof nonce);
  put_u32(raw + 63, (uint32_t)sizeof ct);
  memcpy(raw + 67, ct, sizeof ct);
  memcpy(raw + 67 + sizeof ct, tag, kTag);
  raw_len = 67 + sizeof ct + kTag;
  wipe(salt, sizeof salt);
  wipe(ct, sizeof ct);
  wipe(tag, sizeof tag);
  rc = gdefcore_text_dup(catalog, (const char *)raw, raw_len, out_token);
  wipe(raw, sizeof raw);
  if (rc == GDEFCORE_OK) {
    *out_token_len = raw_len;
  }
  return rc;
}

GDEFCORE_Result gdefcore_account_login(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * username, size_t username_len, const void * password,
    size_t password_len, uint64_t lifetime_sec, char ** out_token,
    size_t * out_token_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char hex[kHexCap];
  char phc[kPhcCap];
  uint8_t session[kKey];
  size_t hex_len = 0;
  size_t phc_len = 0;
  size_t principal_len = 0;
  uint64_t epoch = 0;
  uint64_t now = 0;
  char epoch_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int found = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || keyring == NULL || out_token == NULL ||
      out_token_len == NULL || username == NULL || !root_ok(root, root_len) ||
      (password == NULL && password_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (password_len > GDEFCORE_ACCOUNT_PASSWORD_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (lifetime_sec == 0 || lifetime_sec > GDEFCORE_ACCOUNT_SESSION_MAX) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure_types(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_username(catalog, username, username_len, &found, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!found) {
    rc = dummy_hash(password, password_len);
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : rc;
  }
  rc = read_text(catalog, id, "password", hex, sizeof hex, &hex_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = open_password(catalog, keyring, root, root_len, hex, hex_len, phc,
      sizeof phc, &phc_len);
  wipe(hex, sizeof hex);
  if (rc != GDEFCORE_OK) {
    GDEFCORE_Result hashed = dummy_hash(password, password_len);
    return hashed == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : hashed;
  }
  rc = from_gsec(gsec_argon2_phc_verify(phc, phc_len, password, password_len,
      NULL, 0, NULL, 0));
  wipe(phc, sizeof phc);
  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = read_text(catalog, id, "principal", principal, sizeof principal,
      &principal_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (principal_len != GDEFCORE_PUBLIC_ID_LEN) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_epoch(catalog, id, epoch_id, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!now_u64(&now) || now > UINT64_MAX - lifetime_sec) {
    return now > UINT64_MAX - lifetime_sec ? GDEFCORE_ERR_LIMIT
                                           : GDEFCORE_ERR_IO;
  }
  rc = purpose_key(keyring, root, root_len, kSession, session);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = mint_token(catalog, session, id, principal, epoch, now + lifetime_sec,
      out_token, out_token_len);
  wipe(session, sizeof session);
  return rc;
}

/* What a token that opens says, once its tag, tenant, purpose and expiry are
 * good. Nothing here says the session is still live. */
typedef struct Session {
  uint64_t expiry;
  uint64_t epoch;
  uint8_t sid[kSid];
  char account[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
} Session;

/* Parse and open @p token: the layout, the expiry window, the AEAD tag under
 * the tenant's session key and the tenant in the associated data. A token
 * that fails any of these is ::GDEFCORE_ERR_INVALID. */
static GDEFCORE_Result open_session(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * token, size_t token_len, Session * out) {
  const uint8_t * raw;
  const uint8_t * tenant = NULL;
  size_t tenant_len = 0;
  size_t purpose_len = 0;
  size_t aad_len = 0;
  uint32_t ct_len = 0;
  uint64_t expiry = 0;
  uint64_t now = 0;
  uint8_t session[kKey];
  uint8_t token_key[kKey];
  uint8_t plain[kPlain];
  uint8_t aad[kTenantMax + 32];
  size_t header = 0;
  GDEFCORE_Result rc;
  if (token == NULL || token_len < 83) {
    return GDEFCORE_ERR_INVALID;
  }
  raw = (const uint8_t *)token;
  if (raw[0] != kVersion || raw[1] != kAlg || raw[2] != kKeyId) {
    return GDEFCORE_ERR_INVALID;
  }
  purpose_len = raw[3];
  header = 4 + purpose_len + 8 + kTokenSalt + kNonce + 4;
  if (purpose_len != strlen(kSession) || token_len < header + kTag ||
      memcmp(raw + 4, kSession, purpose_len) != 0) {
    return GDEFCORE_ERR_INVALID;
  }
  expiry = get_u64(raw + 4 + purpose_len);
  ct_len = get_u32(raw + header - 4);
  if (ct_len != kPlain || token_len != header + ct_len + kTag) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!now_u64(&now)) {
    return GDEFCORE_ERR_IO;
  }
  if (expiry <= now || expiry > now + GDEFCORE_ACCOUNT_SESSION_MAX) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = purpose_key(keyring, root, root_len, kSession, session);
  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = from_gsec(gsec_hkdf(GSEC_HKDF_SHA256, raw + 4 + purpose_len + 8,
      kTokenSalt, session, kKey, NULL, 0, token_key, kKey));
  wipe(session, sizeof session);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = tenant_of(catalog, &tenant, &tenant_len);
  if (rc != GDEFCORE_OK) {
    wipe(token_key, sizeof token_key);
    return rc;
  }
  put_u32(aad, (uint32_t)tenant_len);
  memcpy(aad + 4, tenant, tenant_len);
  memcpy(aad + 4 + tenant_len, kSession, strlen(kSession));
  aad[4 + tenant_len + strlen(kSession)] = kKeyId;
  put_u64(aad + 5 + tenant_len + strlen(kSession), expiry);
  aad_len = 13 + tenant_len + strlen(kSession);
  rc = from_gsec(gsec_aes_gcm_decrypt(token_key, kKey,
      raw + 4 + purpose_len + 8 + kTokenSalt, kNonce, aad, aad_len,
      raw + header, ct_len, plain, raw + header + ct_len, kTag));
  wipe(token_key, sizeof token_key);
  if (rc != GDEFCORE_OK) {
    wipe(plain, sizeof plain);
    return GDEFCORE_ERR_INVALID;
  }
  if (plain[8] != GDEFCORE_PUBLIC_ID_LEN ||
      plain[37] != GDEFCORE_PUBLIC_ID_LEN) {
    wipe(plain, sizeof plain);
    return GDEFCORE_ERR_INVALID;
  }
  out->expiry = expiry;
  out->epoch = get_u64(plain);
  memcpy(out->account, plain + 9, GDEFCORE_PUBLIC_ID_LEN);
  out->account[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  memcpy(out->principal, plain + 38, GDEFCORE_PUBLIC_ID_LEN);
  out->principal[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  memcpy(out->sid, plain + 66, kSid);
  wipe(plain, sizeof plain);
  return GDEFCORE_OK;
}

static void session_wipe(Session * s) {
  wipe(s, sizeof *s);
}

static GDEFCORE_Result map_stor(GDEFSTOR_Result r) {
  switch (r) {
  case GDEFSTOR_OK:
    return GDEFCORE_OK;
  case GDEFSTOR_ERR_OOM:
    return GDEFCORE_ERR_OOM;
  case GDEFSTOR_ERR_LIMIT:
    return GDEFCORE_ERR_LIMIT;
  case GDEFSTOR_ERR_CORRUPT:
    return GDEFCORE_ERR_CORRUPT;
  case GDEFSTOR_ERR_INVALID:
  case GDEFSTOR_ERR_UNSUPPORTED:
    return GDEFCORE_ERR_INVALID;
  default:
    return GDEFCORE_ERR_IO;
  }
}

/* Whether the account still stands behind the token: its principal is the
 * account's, and its epoch is the account's current one. *out_live 0 with
 * ::GDEFCORE_OK is an older epoch (the session has ended); a newer epoch
 * than the account's, or a principal that is not the account's, is
 * ::GDEFCORE_ERR_INVALID. */
static GDEFCORE_Result session_standing(GDEFCORE_Catalog * catalog,
    const Session * s, int * out_live) {
  char stored_principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char epoch_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t stored_len = 0;
  uint64_t current = 0;
  GDEFCORE_Result rc = read_text(catalog, s->account, "principal",
      stored_principal, sizeof stored_principal, &stored_len);
  *out_live = 0;
  if (rc != GDEFCORE_OK || stored_len != GDEFCORE_PUBLIC_ID_LEN ||
      !same(stored_principal, stored_len, s->principal,
          GDEFCORE_PUBLIC_ID_LEN)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = load_epoch(catalog, s->account, epoch_id, &current);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (s->epoch != current) {
    return s->epoch < current ? GDEFCORE_OK : GDEFCORE_ERR_INVALID;
  }
  *out_live = 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result store_of(GDEFCORE_Catalog * catalog,
    GDEFSTOR_Store ** out_store, const char ** out_tenant,
    size_t * out_tenant_len) {
  size_t tenant_len = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  GDEFSTOR_Store * store = gdefcore_catalog_store(catalog);
  if (store == NULL || tenant == NULL || tenant_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_store = store;
  *out_tenant = (const char *)tenant;
  *out_tenant_len = tenant_len;
  return GDEFCORE_OK;
}

/* Whether the session is on the tenant's revocation list: one record read.
 * Any answer but a clean "not there" is an error, so the caller refuses. */
static GDEFCORE_Result is_revoked(GDEFCORE_Catalog * catalog,
    const uint8_t sid[kSid], int * out_revoked) {
  GDEFSTOR_Store * store = NULL;
  const char * tenant = NULL;
  size_t tenant_len = 0;
  char key[kSidHex + 1];
  size_t key_len = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  int found = 0;
  GDEFCORE_Result rc;
  *out_revoked = 1;
  rc = store_of(catalog, &store, &tenant, &tenant_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = hex_encode(sid, kSid, key, sizeof key, &key_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = map_stor(gdefstor_record_get(store, tenant, tenant_len, kRevokedNs,
      strlen(kRevokedNs), key, key_len, &found, &bytes, &len, NULL, NULL));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  gdefstor_bytes_free(NULL, bytes);
  *out_revoked = found != 0;
  return GDEFCORE_OK;
}

/* The expiry index key: the expiry as 20 digits, so keys sort by expiry, then
 * the session id in hex. */
static GDEFCORE_Result exp_key(uint64_t expiry, const char * sid_hex,
    char out[kExpKey + 1]) {
  int n = snprintf(out, kExpKey + 1, "%020llu.%.*s",
      (unsigned long long)expiry, kSidHex, sid_hex);
  return n == kExpKey ? GDEFCORE_OK : GDEFCORE_ERR_INTERNAL;
}

/* Read an index key back: 20 digits, a dot, 32 lowercase hex digits. */
static int exp_parse(const char * key, size_t len, uint64_t * out_expiry) {
  uint64_t v = 0;
  size_t i;
  if (len != kExpKey || key[kExpDigits] != '.') {
    return 0;
  }
  for (i = 0; i < kExpDigits; i++) {
    unsigned d;
    if (key[i] < '0' || key[i] > '9') {
      return 0;
    }
    d = (unsigned)(key[i] - '0');
    if (v > (UINT64_MAX - d) / 10u) {
      return 0;
    }
    v = v * 10u + d;
  }
  for (i = kExpDigits + 1; i < len; i++) {
    if (hex_nibble(key[i]) < 0) {
      return 0;
    }
  }
  *out_expiry = v;
  return 1;
}

/* In @p write, drop what has been dead long enough: the oldest page of the
 * expiry index, in order, stopping at the first entry still inside its
 * expiry plus the grace. A key that is not an index key cannot be one of
 * ours and goes too. At most ::kPurgeBatch entries are read, so the work of
 * one revocation is bounded; a revocation adds one entry and may remove a
 * page, so the list cannot fall behind. */
static GDEFCORE_Result purge_dead(GDEFSTOR_Store * store, const char * tenant,
    size_t tenant_len, GDEFSTOR_Write * write, uint64_t now) {
  GDEFSTOR_RecordList * list = NULL;
  size_t n;
  size_t i;
  GDEFCORE_Result rc = map_stor(gdefstor_record_list(store, tenant, tenant_len,
      kRevokedExpNs, strlen(kRevokedExpNs), "", 0, 0, kPurgeBatch, &list));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  n = gdefstor_record_list_count(list);
  for (i = 0; i < n && rc == GDEFCORE_OK; i++) {
    const char * key = NULL;
    size_t key_len = 0;
    uint64_t expiry = 0;
    const uint8_t * bytes = NULL;
    size_t len = 0;
    rc = map_stor(gdefstor_record_list_item(list, i, &key, &key_len, &bytes,
        &len, NULL, NULL));
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (exp_parse(key, key_len, &expiry)) {
      if (expiry > now || now - expiry < kPurgeGrace) {
        break; /* sorted by expiry: nothing later is dead either */
      }
      rc = map_stor(gdefstor_record_delete(write, kRevokedNs,
          strlen(kRevokedNs), key + kExpDigits + 1, kSidHex, NULL));
    }
    if (rc == GDEFCORE_OK) {
      rc = map_stor(gdefstor_record_delete(write, kRevokedExpNs,
          strlen(kRevokedExpNs), key, key_len, NULL));
    }
  }
  gdefstor_record_list_free(list);
  return rc;
}

/* Put the session on the revocation list, and purge, in one write. */
static GDEFCORE_Result record_revocation(GDEFCORE_Catalog * catalog,
    const Session * s) {
  GDEFSTOR_Store * store = NULL;
  GDEFSTOR_Write * write = NULL;
  const char * tenant = NULL;
  size_t tenant_len = 0;
  char sid_hex[kSidHex + 1];
  size_t sid_len = 0;
  char ekey[kExpKey + 1];
  char value[kExpDigits + 1];
  uint64_t now = 0;
  int n;
  GDEFCORE_Result rc = store_of(catalog, &store, &tenant, &tenant_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = hex_encode(s->sid, kSid, sid_hex, sizeof sid_hex, &sid_len);
  if (rc == GDEFCORE_OK) {
    rc = exp_key(s->expiry, sid_hex, ekey);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  n = snprintf(value, sizeof value, "%llu", (unsigned long long)s->expiry);
  if (n <= 0 || (size_t)n >= sizeof value || !now_u64(&now)) {
    return GDEFCORE_ERR_INTERNAL;
  }
  rc = map_stor(gdefstor_write_begin(store, tenant, tenant_len, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = map_stor(gdefstor_record_put(write, kRevokedNs, strlen(kRevokedNs),
      sid_hex, sid_len, GDEFCORE_SCHEMA_CORE_STAMP,
      sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, (const uint8_t *)value,
      (size_t)n));
  if (rc == GDEFCORE_OK) {
    rc = map_stor(gdefstor_record_put(write, kRevokedExpNs,
        strlen(kRevokedExpNs), ekey, kExpKey, GDEFCORE_SCHEMA_CORE_STAMP,
        sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, NULL, 0));
  }
  if (rc == GDEFCORE_OK) {
    rc = purge_dead(store, tenant, tenant_len, write, now);
  }
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return map_stor(gdefstor_write_commit(write));
}

GDEFCORE_Result gdefcore_account_check(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * token,
    size_t token_len) {
  Session s;
  int live = 0;
  int revoked = 1;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || keyring == NULL ||
      !root_ok(root, root_len) || token == NULL || token_len < 83) {
    if (request != NULL) {
      clear_identity(request);
    }
    return GDEFCORE_ERR_INVALID;
  }
  clear_identity(request);
  rc = open_session(catalog, keyring, root, root_len, token, token_len, &s);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = session_standing(catalog, &s, &live);
  if (rc != GDEFCORE_OK || !live) {
    session_wipe(&s);
    return rc;
  }
  /* The one lookup. A list that cannot be read is an error, never a pass. */
  rc = is_revoked(catalog, s.sid, &revoked);
  if (rc != GDEFCORE_OK || revoked) {
    session_wipe(&s);
    return rc;
  }
  rc = set_principal(request, s.principal);
  session_wipe(&s);
  return rc;
}

GDEFCORE_Result gdefcore_account_session_expiry(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * token, size_t token_len, uint64_t * out_expiry) {
  Session s;
  GDEFCORE_Result rc;
  if (catalog == NULL || keyring == NULL || out_expiry == NULL ||
      !root_ok(root, root_len) || token == NULL || token_len < 83) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = open_session(catalog, keyring, root, root_len, token, token_len, &s);
  if (rc == GDEFCORE_OK) {
    *out_expiry = s.expiry;
  }
  session_wipe(&s);
  return rc;
}

GDEFCORE_Result gdefcore_account_session_revoke(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * token,
    size_t token_len) {
  Session s;
  size_t request_tenant_len = 0;
  size_t tenant_len = 0;
  const uint8_t * request_tenant;
  const uint8_t * tenant;
  int live = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || keyring == NULL ||
      !root_ok(root, root_len) || token == NULL || token_len < 83) {
    return GDEFCORE_ERR_INVALID;
  }
  request_tenant = gdefcore_request_tenant(request, &request_tenant_len);
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  if (request_tenant == NULL || tenant == NULL ||
      !same((const char *)request_tenant, request_tenant_len,
          (const char *)tenant, tenant_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = open_session(catalog, keyring, root, root_len, token, token_len, &s);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = session_standing(catalog, &s, &live);
  if (rc == GDEFCORE_OK && live) {
    rc = record_revocation(catalog, &s);
  }
  /* A session an epoch already ended is gone; there is nothing to record. */
  session_wipe(&s);
  return rc;
}

GDEFCORE_Result gdefcore_account_password(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * id, size_t id_len, const void * password, size_t password_len,
    const char * confirmation, size_t confirmation_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char epoch_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char hex[kHexCap];
  char next_text[32];
  const char * held_hex;
  const char * held_epoch;
  size_t hex_len = 0;
  size_t next_len = 0;
  uint64_t epoch = 0;
  GDEFCORE_Value values[2];
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc;
  if (catalog == NULL || keyring == NULL || !root_ok(root, root_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (password_len > GDEFCORE_ACCOUNT_PASSWORD_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (!password_ok(password, password_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canonical_copy(id, id_len, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = confirm_user(catalog, canon, confirmation, confirmation_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_epoch(catalog, canon, epoch_id, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (epoch == UINT64_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = seal_password(catalog, keyring, root, root_len, password, password_len,
      hex, &hex_len);
  if (rc != GDEFCORE_OK) {
    wipe(hex, sizeof hex);
    return rc;
  }
  {
    int wrote = snprintf(next_text, sizeof next_text, "%llu",
        (unsigned long long)(epoch + 1u));
    if (wrote <= 0 || (size_t)wrote >= sizeof next_text) {
      wipe(hex, sizeof hex);
      return GDEFCORE_ERR_LIMIT;
    }
    next_len = (size_t)wrote;
  }
  held_hex = hex;
  held_epoch = next_text;
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    wipe(hex, sizeof hex);
    return rc;
  }
  value_set(&values[0], "password", &held_hex, &hex_len, 1);
  value_set(&values[1], "epoch", &held_epoch, &next_len, 1);
  rc = gdefcore_entity_save(changeset, canon, GDEFCORE_PUBLIC_ID_LEN, kLang,
      strlen(kLang), &values[0], 1);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_save(changeset, epoch_id, GDEFCORE_PUBLIC_ID_LEN,
        kLang, strlen(kLang), &values[1], 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = apply_high(changeset, kBothConfirm);
  }
  gdefcore_changeset_destroy(changeset);
  wipe(hex, sizeof hex);
  return rc;
}

GDEFCORE_Result gdefcore_account_logout_everywhere(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, const char * confirmation,
    size_t confirmation_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canonical_copy(id, id_len, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = confirm_user(catalog, canon, confirmation, confirmation_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return bump_epoch(catalog, canon, NULL);
}

GDEFCORE_Result gdefcore_account_remove_identifier(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, const char * username,
    size_t username_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char user[kUserMax + 1];
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || !username_ok(username, username_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canonical_copy(id, id_len, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = read_text(catalog, canon, "username", user, sizeof user, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!same(user, n, username, username_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  /* One login identifier, and the last one cannot be removed. */
  return GDEFCORE_ERR_INVALID;
}

GDEFCORE_Result gdefcore_account_remove_role(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, const char * role, size_t role_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || role == NULL || role_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canonical_copy(id, id_len, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = read_text(catalog, canon, "principal", principal, sizeof principal, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (n != GDEFCORE_PUBLIC_ID_LEN) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_access_principal_remove_role(catalog, principal, n, role,
      role_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return bump_epoch(catalog, canon, NULL);
}

GDEFCORE_Result gdefcore_account_revert(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canonical_copy(id, id_len, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_revert(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, NULL,
      0, &changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = apply_high(changeset, kAccountConfirm);
  gdefcore_changeset_destroy(changeset);
  return rc;
}

GDEFCORE_Result gdefcore_account_epoch(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, uint64_t * out_epoch) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char epoch_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (catalog == NULL || out_epoch == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = canonical_copy(id, id_len, canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return load_epoch(catalog, canon, epoch_id, out_epoch);
}
