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
 * The installation registry lives on the caller's registry store, as system
 * records (below, at write_record()). Site tenant catalogs live on the other
 * store, each under its own 16-byte
 * storage key. The keyring is wrapped by the root and is not a field.
 * When a key store is passed, that wrap is written there the first time, as
 * the tenant's secret, and adopted on a later open; no data store holds it.
 */

#define _POSIX_C_SOURCE 200809L

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/inst.h>
#include <ghoti.io/defiant-core/subject.h>

#include "inst_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/text/toml/toml_dom.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  kRoles = 0,
  kStore,
  kListen,
  kProxies,
  kSecret,
  kSecretFile,
  kSettingCount,
  kSrcDefault = 0,
  kSrcEnv = 1,
  kSrcFile = 2,
  kKeyBytes = 16,
  kHexKey = 32,
  kKeyMax = 256,
  kPlaceMax = 4096,
  kValueMax = 4096,
  kTomlMax = 65536
};

static const uint8_t kRegistryTenant[] = {0x02};
static const char kRegistryNs[] = "core.tenant";
static const char kActive[] = "active";
static const char * kEnvNames[kSettingCount] = {
    "DEFIANT_ROLES", "DEFIANT_STORE", "DEFIANT_LISTEN",
    "DEFIANT_TRUSTED_PROXIES", "DEFIANT_SECRET", "DEFIANT_SECRET_FILE"};
static const char * kTomlNames[kSettingCount] = {
    "ROLES", "STORE", "LISTEN", "TRUSTED_PROXIES", "SECRET", "SECRET_FILE"};
static const char * kSrcNames[] = {"default", "env", "file"};

struct LimitField {
  const char * name;
  size_t offset;
  int u32;
};

static const struct LimitField kLimits[] = {
    {"max_document_bytes", offsetof(GDEFSTOR_Limits, max_document_bytes), 0},
    {"max_blob_bytes", offsetof(GDEFSTOR_Limits, max_blob_bytes), 0},
    {"max_member_bytes", offsetof(GDEFSTOR_Limits, max_member_bytes), 0},
    {"max_members", offsetof(GDEFSTOR_Limits, max_members), 0},
    {"max_snapshot_bytes", offsetof(GDEFSTOR_Limits, max_snapshot_bytes), 0},
    {"max_zip_ratio", offsetof(GDEFSTOR_Limits, max_zip_ratio), 1},
    {"max_public_id_bytes", offsetof(GDEFSTOR_Limits, max_public_id_bytes), 0},
    {"max_tenant_bytes", offsetof(GDEFSTOR_Limits, max_tenant_bytes), 0},
    {"max_type_bytes", offsetof(GDEFSTOR_Limits, max_type_bytes), 0},
    {"max_body_bytes", offsetof(GDEFSTOR_Limits, max_body_bytes), 0},
    {"max_hash_bytes", offsetof(GDEFSTOR_Limits, max_hash_bytes), 0},
    {"max_json_depth", offsetof(GDEFSTOR_Limits, max_json_depth), 0},
    {"max_columns", offsetof(GDEFSTOR_Limits, max_columns), 0},
    {"max_column_name_bytes", offsetof(GDEFSTOR_Limits, max_column_name_bytes),
        0},
    {"max_column_value_bytes",
        offsetof(GDEFSTOR_Limits, max_column_value_bytes), 0},
    {"max_outbox_payload_bytes",
        offsetof(GDEFSTOR_Limits, max_outbox_payload_bytes), 0},
    {"max_stream_bytes", offsetof(GDEFSTOR_Limits, max_stream_bytes), 0},
    {"max_revisions", offsetof(GDEFSTOR_Limits, max_revisions), 0},
    {"max_blobs", offsetof(GDEFSTOR_Limits, max_blobs), 0},
    {"max_projections", offsetof(GDEFSTOR_Limits, max_projections), 0},
    {"max_outbox_rows", offsetof(GDEFSTOR_Limits, max_outbox_rows), 0},
};

struct TenantSlot {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t storage[kKeyBytes];
  char * placement;
  size_t placement_len;
  char * edition;
  size_t edition_len;
  char * status;
  size_t status_len;
  char * resolution;
  size_t resolution_len;
  int is_default;
  char * limits;
  size_t limits_len;
  GDEFCORE_Keyring * keyring;
};

struct GDEFCORE_Inst_Config {
  const GDEFCORE_Allocator * alloc;
  char * values[kSettingCount];
  size_t lens[kSettingCount];
  int sources[kSettingCount];
  uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
  int has_root;
};

struct GDEFCORE_Inst {
  const GDEFCORE_Allocator * alloc;
  GDEFSTOR_Store * registry;
  GDEFSTOR_Store * site;
  GDEFSTOR_KeyStore * keys;
  GDEFCORE_Keyring * keyring;
  uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
  struct TenantSlot * slots;
  size_t nslots;
  size_t ncap;
};

static void wipe(void * p, size_t n) {
  if (p != NULL && n > 0) {
    gsec_wipe(p, n);
  }
}

static const GDEFCORE_Allocator * use_alloc(const GDEFCORE_Allocator * alloc) {
  return alloc == NULL ? gdefcore_allocator_default() : alloc;
}

static void * mem(const GDEFCORE_Allocator * alloc, size_t n) {
  return gcu_allocator_malloc(alloc, n);
}

static char * dup_n(const GDEFCORE_Allocator * alloc, const char * s, size_t n) {
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

static int has_break(const char * s, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (s[i] == '\n' || s[i] == '\r') {
      return 1;
    }
  }
  return 0;
}

static int hex_nibble(char c) {
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

static GDEFCORE_Result hex_decode(const char * in, size_t n, uint8_t * out,
    size_t out_n) {
  size_t i;
  if (in == NULL || out == NULL || n != out_n * 2) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < out_n; i++) {
    int hi = hex_nibble(in[i * 2]);
    int lo = hex_nibble(in[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return GDEFCORE_ERR_INVALID;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result hex_encode(const uint8_t * in, size_t n, char * out,
    size_t cap) {
  static const char kHex[] = "0123456789abcdef";
  size_t i;
  if (cap < n * 2 + 1) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < n; i++) {
    out[i * 2] = kHex[in[i] >> 4];
    out[i * 2 + 1] = kHex[in[i] & 0x0f];
  }
  out[n * 2] = '\0';
  return GDEFCORE_OK;
}

static int key_well_formed(const char * key, size_t n) {
  size_t i;
  if (key == NULL || n == 0 || n > kKeyMax) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)key[i];
    if (c < 0x20u || c == 0x7fu) {
      return 0;
    }
  }
  return 1;
}

static const struct LimitField * limit_field(const char * name, size_t n) {
  size_t i;
  for (i = 0; i < sizeof kLimits / sizeof kLimits[0]; i++) {
    if (same(kLimits[i].name, strlen(kLimits[i].name), name, n)) {
      return &kLimits[i];
    }
  }
  return NULL;
}

static GDEFCORE_Result apply_limits(const char * text, size_t n,
    GDEFSTOR_Limits * out) {
  size_t i = 0;
  memset(out, 0, sizeof *out);
  gdefstor_limits_default(out);
  if (text == NULL || n == 0) {
    return GDEFCORE_OK;
  }
  while (i < n) {
    size_t line = i;
    size_t eq = 0;
    size_t end;
    int saw = 0;
    const struct LimitField * field;
    uint64_t value = 0;
    size_t d;
    while (i < n && text[i] != '\n') {
      i += 1;
    }
    end = i;
    if (i < n && text[i] == '\n') {
      i += 1;
    }
    if (end == line) {
      continue;
    }
    for (eq = line; eq < end; eq++) {
      if (text[eq] == '=') {
        saw = 1;
        break;
      }
    }
    if (!saw || eq == line || eq + 1 >= end) {
      return GDEFCORE_ERR_CORRUPT;
    }
    field = limit_field(text + line, eq - line);
    if (field == NULL) {
      return GDEFCORE_ERR_CORRUPT;
    }
    for (d = eq + 1; d < end; d++) {
      unsigned char c = (unsigned char)text[d];
      if (c < '0' || c > '9') {
        return GDEFCORE_ERR_CORRUPT;
      }
      if (value > (UINT64_MAX - (uint64_t)(c - '0')) / 10u) {
        return GDEFCORE_ERR_LIMIT;
      }
      value = value * 10u + (uint64_t)(c - '0');
    }
    if (field->u32) {
      uint32_t stored32;
      if (value > UINT32_MAX) {
        return GDEFCORE_ERR_LIMIT;
      }
      stored32 = (uint32_t)value;
      memcpy((char *)out + field->offset, &stored32, sizeof stored32);
    } else {
      size_t stored = (size_t)value;
      if ((uint64_t)stored != value) {
        return GDEFCORE_ERR_LIMIT;
      }
      memcpy((char *)out + field->offset, &stored, sizeof stored);
    }
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result read_exact(const char * path, uint8_t * out, size_t n) {
  FILE * fp;
  long got;
  if (path == NULL || path[0] == '\0') {
    return GDEFCORE_ERR_INVALID;
  }
  fp = fopen(path, "rb");
  if (fp == NULL) {
    return GDEFCORE_ERR_IO;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return GDEFCORE_ERR_IO;
  }
  got = ftell(fp);
  if (got < 0) {
    fclose(fp);
    return GDEFCORE_ERR_IO;
  }
  if ((size_t)got != n) {
    fclose(fp);
    return GDEFCORE_ERR_INVALID;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return GDEFCORE_ERR_IO;
  }
  if (fread(out, 1, n, fp) != n) {
    fclose(fp);
    wipe(out, n);
    return GDEFCORE_ERR_IO;
  }
  fclose(fp);
  return GDEFCORE_OK;
}

static int toml_index(const char * key, size_t n) {
  int i;
  for (i = 0; i < kSettingCount; i++) {
    if (same(kTomlNames[i], strlen(kTomlNames[i]), key, n)) {
      return i;
    }
  }
  return -1;
}

static GDEFCORE_Result take_value(GDEFCORE_Inst_Config * config, int index,
    const char * text, size_t n, int source) {
  char * copy;
  if (n > kValueMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (has_break(text, n)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (index == kSecret) {
    uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
    GDEFCORE_Result rc = hex_decode(text, n, root, sizeof root);
    if (rc != GDEFCORE_OK) {
      wipe(root, sizeof root);
      return rc;
    }
    memcpy(config->root, root, sizeof root);
    wipe(root, sizeof root);
    config->has_root = 1;
    config->sources[index] = source;
    return GDEFCORE_OK;
  }
  copy = dup_n(config->alloc, text, n);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  gcu_allocator_free(config->alloc, config->values[index]);
  config->values[index] = copy;
  config->lens[index] = n;
  config->sources[index] = source;
  return GDEFCORE_OK;
}

static GDEFCORE_Result toml_status(GTEXT_TOML_Status code) {
  if (code == GTEXT_TOML_E_LIMIT || code == GTEXT_TOML_E_DEPTH) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (code == GTEXT_TOML_E_OOM) {
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_ERR_FORMAT;
}

static GDEFCORE_Result load_toml(GDEFCORE_Inst_Config * config,
    const char * path) {
  GTEXT_TOML_Parse_Options opts = gtext_toml_parse_options_default();
  GTEXT_TOML_Error err;
  GTEXT_TOML_Value * root;
  size_t n;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  opts.max_total_bytes = kTomlMax;
  memset(&err, 0, sizeof err);
  root = gtext_toml_parse_file(path, &opts, &err);
  if (root == NULL) {
    rc = toml_status(err.code);
    gtext_toml_error_free(&err);
    return rc;
  }
  if (gtext_toml_value_type(root) != GTEXT_TOML_TABLE) {
    gtext_toml_free(root);
    return GDEFCORE_ERR_FORMAT;
  }
  n = gtext_toml_table_size(root);
  for (i = 0; i < n; i++) {
    size_t key_len = 0;
    size_t val_len = 0;
    const char * key = gtext_toml_table_key_at(root, i, &key_len);
    const GTEXT_TOML_Value * val = gtext_toml_table_value_at(root, i);
    const char * text;
    int index = toml_index(key, key_len);
    if (index < 0 || val == NULL) {
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    if (config->sources[index] == kSrcEnv ||
        (index == kSecret && config->sources[kSecretFile] == kSrcEnv)) {
      continue;
    }
    if (gtext_toml_value_type(val) != GTEXT_TOML_STRING) {
      rc = GDEFCORE_ERR_FORMAT;
      break;
    }
    text = gtext_toml_value_string(val, &val_len);
    if (text == NULL) {
      rc = GDEFCORE_ERR_FORMAT;
      break;
    }
    rc = take_value(config, index, text, val_len, kSrcFile);
    if (rc != GDEFCORE_OK) {
      break;
    }
  }
  gtext_toml_free(root);
  return rc;
}

static void blank_values(GDEFCORE_Inst_Config * config) {
  int i;
  for (i = 0; i < kSettingCount; i++) {
    config->values[i] = dup_n(config->alloc, "", 0);
    config->lens[i] = 0;
    config->sources[i] = kSrcDefault;
  }
}

GDEFCORE_Result gdefcore_inst_config_load(const GDEFCORE_Allocator * allocator,
    GDEFCORE_Inst_Config ** out_config) {
  GDEFCORE_Inst_Config * config;
  const char * config_path;
  char * secret_env = NULL;
  size_t secret_len = 0;
  int i;
  int values_ok;
  GDEFCORE_Result rc;
  if (out_config == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  allocator = use_alloc(allocator);
  config = (GDEFCORE_Inst_Config *)mem(allocator, sizeof *config);
  if (config == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(config, 0, sizeof *config);
  config->alloc = allocator;
  blank_values(config);
  values_ok = 1;
  for (i = 0; i < kSettingCount; i++) {
    if (config->values[i] == NULL) {
      values_ok = 0;
    }
  }
  if (!values_ok) {
    gdefcore_inst_config_destroy(config);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < kSettingCount; i++) {
    char * env = getenv(kEnvNames[i]);
    size_t n;
    if (env == NULL) {
      continue;
    }
    n = strlen(env);
    if (i == kSecret) {
      uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
      rc = hex_decode(env, n, root, sizeof root);
      if (rc != GDEFCORE_OK) {
        wipe(root, sizeof root);
        gdefcore_inst_config_destroy(config);
        return rc;
      }
      memcpy(config->root, root, sizeof root);
      wipe(root, sizeof root);
      config->has_root = 1;
      config->sources[i] = kSrcEnv;
      secret_env = env;
      secret_len = n;
      continue;
    }
    rc = take_value(config, i, env, n, kSrcEnv);
    if (rc != GDEFCORE_OK) {
      gdefcore_inst_config_destroy(config);
      return rc;
    }
  }
  config_path = getenv("DEFIANT_CONFIG");
  if (config_path != NULL && config_path[0] != '\0') {
    rc = load_toml(config, config_path);
    if (rc != GDEFCORE_OK) {
      gdefcore_inst_config_destroy(config);
      return rc;
    }
  }
  if (!config->has_root && config->sources[kSecretFile] != kSrcDefault) {
    rc = read_exact(config->values[kSecretFile], config->root, sizeof config->root);
    if (rc != GDEFCORE_OK) {
      gdefcore_inst_config_destroy(config);
      return rc;
    }
    config->has_root = 1;
    config->sources[kSecret] = kSrcFile;
  }
  if (secret_env != NULL) {
    wipe(secret_env, secret_len);
#ifdef _WIN32
    {
      /* The C runtime has no unsetenv; NAME= removes the variable. */
      char blank[64];
      snprintf(blank, sizeof blank, "%s=", kEnvNames[kSecret]);
      _putenv(blank);
    }
#else
    unsetenv(kEnvNames[kSecret]);
#endif
  }
  *out_config = config;
  return GDEFCORE_OK;
}

void gdefcore_inst_config_destroy(GDEFCORE_Inst_Config * config) {
  int i;
  if (config == NULL) {
    return;
  }
  for (i = 0; i < kSettingCount; i++) {
    gcu_allocator_free(config->alloc, config->values[i]);
  }
  wipe(config->root, sizeof config->root);
  gcu_allocator_free(config->alloc, config);
}

GDEFCORE_Result gdefcore_inst_config_format(const GDEFCORE_Inst_Config * config,
    char ** out_text, size_t * out_len) {
  size_t total = 1;
  char * text;
  size_t at = 0;
  int i;
  if (config == NULL || out_text == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < kSettingCount; i++) {
    size_t value_len = i == kSecret ? 0 : config->lens[i];
    total += strlen(kEnvNames[i]) + 1 + value_len + strlen(" source=") +
             strlen(kSrcNames[config->sources[i]]) + 1;
  }
  text = (char *)mem(config->alloc, total);
  if (text == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < kSettingCount; i++) {
    int wrote;
    const char * value = i == kSecret ? "" : config->values[i];
    size_t value_len = i == kSecret ? 0 : config->lens[i];
    wrote = snprintf(text + at, total - at, "%s=%.*s source=%s\n",
        kEnvNames[i], (int)value_len, value == NULL ? "" : value,
        kSrcNames[config->sources[i]]);
    if (wrote < 0 || (size_t)wrote >= total - at) {
      gcu_allocator_free(config->alloc, text);
      return GDEFCORE_ERR_LIMIT;
    }
    at += (size_t)wrote;
  }
  *out_text = text;
  *out_len = at;
  return GDEFCORE_OK;
}

void gdefcore_inst_config_free(const GDEFCORE_Inst_Config * config, char * text) {
  if (config == NULL) {
    return;
  }
  gcu_allocator_free(config->alloc, text);
}

GDEFCORE_Result gdefcore_inst_config_root(const GDEFCORE_Inst_Config * config,
    uint8_t out[GDEFCORE_ACCOUNT_ROOT_LEN]) {
  if (config == NULL || out == NULL || !config->has_root) {
    return GDEFCORE_ERR_INVALID;
  }
  memcpy(out, config->root, sizeof config->root);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_inst_config_setting(const GDEFCORE_Inst_Config * config,
    const char * name, size_t name_len, const char ** out_value,
    size_t * out_value_len, const char ** out_source) {
  int i;
  if (config == NULL || name == NULL || out_value == NULL ||
      out_value_len == NULL || out_source == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < kSettingCount; i++) {
    if (!same(kEnvNames[i], strlen(kEnvNames[i]), name, name_len)) {
      continue;
    }
    if (i == kSecret) {
      *out_value = config->values[i];
      *out_value_len = 0;
    } else {
      *out_value = config->values[i];
      *out_value_len = config->lens[i];
    }
    *out_source = kSrcNames[config->sources[i]];
    return GDEFCORE_OK;
  }
  return GDEFCORE_ERR_INVALID;
}

/*
 * The registry: one record per tenant in namespace `core.tenant` of the
 * registry tenant, keyed by the tenant's public id. Its value is one line per
 * field, `name hex\n`, the hex of the field's bytes: storage (the hex of the
 * storage key, so the value holds the key twice over), placement, edition,
 * status, resolution, is_default (`1` or `0`) and, when set, limits. It is a
 * system record: it has no history, so a change is one put in one write.
 */

typedef struct Rec {
  char * p;
  size_t n;
  size_t cap;
  int oom;
} Rec;

static void rec_put(const GDEFCORE_Allocator * alloc, Rec * b,
    const char * name, const char * value, size_t len) {
  static const char hex[] = "0123456789abcdef";
  size_t nl = strlen(name);
  size_t need = nl + 2 + 2 * len;
  size_t i;
  if (b->oom) {
    return;
  }
  if (b->n + need > b->cap) {
    size_t cap = (b->n + need) * 2;
    char * next = (char *)gcu_allocator_realloc(alloc, b->p, cap);
    if (next == NULL) {
      b->oom = 1;
      return;
    }
    b->p = next;
    b->cap = cap;
  }
  memcpy(b->p + b->n, name, nl);
  b->n += nl;
  b->p[b->n++] = ' ';
  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)value[i];
    b->p[b->n++] = hex[c >> 4];
    b->p[b->n++] = hex[c & 15u];
  }
  b->p[b->n++] = '\n';
}

/* Field @p name of a record value, allocated. ::GDEFCORE_ERR_CORRUPT when the
 * value is not of the form, or a required field is missing (an optional one
 * is NULL). */
static GDEFCORE_Result rec_field(const GDEFCORE_Allocator * alloc,
    const uint8_t * bytes, size_t len, const char * name, int required,
    char ** out, size_t * out_n) {
  const char * p = (const char *)bytes;
  const char * end = p + len;
  size_t name_len = strlen(name);
  *out = NULL;
  *out_n = 0;
  while (p < end) {
    const char * eol = memchr(p, '\n', (size_t)(end - p));
    const char * sp;
    if (eol == NULL) {
      return GDEFCORE_ERR_CORRUPT;
    }
    sp = memchr(p, ' ', (size_t)(eol - p));
    if (sp == NULL) {
      return GDEFCORE_ERR_CORRUPT;
    }
    if ((size_t)(sp - p) == name_len && memcmp(p, name, name_len) == 0) {
      size_t hn = (size_t)(eol - sp - 1);
      uint8_t * raw;
      if (hn % 2 != 0) {
        return GDEFCORE_ERR_CORRUPT;
      }
      raw = (uint8_t *)mem(alloc, hn / 2 + 1);
      if (raw == NULL) {
        return GDEFCORE_ERR_OOM;
      }
      if (hn > 0 && hex_decode(sp + 1, hn, raw, hn / 2) != GDEFCORE_OK) {
        gcu_allocator_free(alloc, raw);
        return GDEFCORE_ERR_CORRUPT;
      }
      raw[hn / 2] = '\0';
      *out = (char *)raw;
      *out_n = hn / 2;
      return GDEFCORE_OK;
    }
    p = eol + 1;
  }
  return required ? GDEFCORE_ERR_CORRUPT : GDEFCORE_OK;
}

static GDEFCORE_Result map_stor(GDEFSTOR_Result rc) {
  switch (rc) {
    case GDEFSTOR_OK:
      return GDEFCORE_OK;
    case GDEFSTOR_ERR_INVALID:
      return GDEFCORE_ERR_INVALID;
    case GDEFSTOR_ERR_OOM:
      return GDEFCORE_ERR_OOM;
    case GDEFSTOR_ERR_LIMIT:
      return GDEFCORE_ERR_LIMIT;
    case GDEFSTOR_ERR_CORRUPT:
      return GDEFCORE_ERR_CORRUPT;
    default:
      return GDEFCORE_ERR_IO;
  }
}

/* Write a tenant's record, whole, in one write of its own. */
static GDEFCORE_Result write_record(GDEFCORE_Inst * inst, const char * id,
    const uint8_t storage[kKeyBytes], const char * placement,
    size_t placement_len, const char * edition, size_t edition_len,
    const char * status, size_t status_len, const char * resolution,
    size_t resolution_len, int is_default, const char * limits,
    size_t limits_len) {
  char hex[kHexKey + 1];
  Rec b;
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc = hex_encode(storage, kKeyBytes, hex, sizeof hex);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&b, 0, sizeof b);
  rec_put(inst->alloc, &b, "storage", hex, kHexKey);
  rec_put(inst->alloc, &b, "placement", placement, placement_len);
  rec_put(inst->alloc, &b, "edition", edition, edition_len);
  rec_put(inst->alloc, &b, "status", status, status_len);
  rec_put(inst->alloc, &b, "resolution", resolution == NULL ? "" : resolution,
      resolution_len);
  rec_put(inst->alloc, &b, "is_default", is_default ? "1" : "0", 1);
  if (limits != NULL && limits_len > 0) {
    rec_put(inst->alloc, &b, "limits", limits, limits_len);
  }
  wipe(hex, sizeof hex);
  if (b.oom) {
    gcu_allocator_free(inst->alloc, b.p);
    return GDEFCORE_ERR_OOM;
  }
  rc = map_stor(gdefstor_write_begin(inst->registry,
      (const char *)kRegistryTenant, sizeof kRegistryTenant, NULL, &write));
  if (rc == GDEFCORE_OK) {
    rc = map_stor(gdefstor_record_put(write, kRegistryNs, strlen(kRegistryNs),
        id, GDEFCORE_PUBLIC_ID_LEN, (const uint8_t *)b.p, b.n));
    if (rc == GDEFCORE_OK) {
      rc = map_stor(gdefstor_write_commit(write));
    } else {
      gdefstor_write_abort(write);
    }
  }
  wipe(b.p, b.n);
  gcu_allocator_free(inst->alloc, b.p);
  return rc;
}

static void slot_clear(const GDEFCORE_Allocator * alloc, struct TenantSlot * slot) {
  gcu_allocator_free(alloc, slot->placement);
  gcu_allocator_free(alloc, slot->edition);
  gcu_allocator_free(alloc, slot->status);
  gcu_allocator_free(alloc, slot->resolution);
  gcu_allocator_free(alloc, slot->limits);
  gdefcore_keyring_destroy(slot->keyring);
  wipe(slot->storage, sizeof slot->storage);
  memset(slot, 0, sizeof *slot);
}

static struct TenantSlot * find_id(const GDEFCORE_Inst * inst, const char * id,
    size_t id_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t i;
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return NULL;
  }
  for (i = 0; i < inst->nslots; i++) {
    if (same(inst->slots[i].id, GDEFCORE_PUBLIC_ID_LEN, canon,
            GDEFCORE_PUBLIC_ID_LEN)) {
      return &inst->slots[i];
    }
  }
  return NULL;
}

static int resolution_taken(const GDEFCORE_Inst * inst, const char * key,
    size_t key_len) {
  size_t i;
  for (i = 0; i < inst->nslots; i++) {
    if (same(inst->slots[i].resolution, inst->slots[i].resolution_len, key,
            key_len)) {
      return 1;
    }
  }
  return 0;
}

static int storage_taken(const GDEFCORE_Inst * inst, const uint8_t raw[kKeyBytes]) {
  size_t i;
  for (i = 0; i < inst->nslots; i++) {
    if (memcmp(inst->slots[i].storage, raw, kKeyBytes) == 0) {
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result grow_slot(GDEFCORE_Inst * inst, struct TenantSlot ** out) {
  if (inst->nslots == inst->ncap) {
    size_t cap = inst->ncap == 0 ? 4 : inst->ncap * 2;
    struct TenantSlot * next = (struct TenantSlot *)gcu_allocator_realloc(
        inst->alloc, inst->slots, cap * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    memset(next + inst->nslots, 0, (cap - inst->nslots) * sizeof *next);
    inst->slots = next;
    inst->ncap = cap;
  }
  *out = &inst->slots[inst->nslots];
  memset(*out, 0, sizeof **out);
  return GDEFCORE_OK;
}

static GDEFCORE_Result adopt(GDEFCORE_Inst * inst,
    const uint8_t storage[kKeyBytes], const char * id, const char * placement,
    size_t placement_len, const char * edition, size_t edition_len,
    const char * status, size_t status_len, const char * resolution,
    size_t resolution_len, int is_default, char * limits, size_t limits_len,
    const uint8_t * root) {
  struct TenantSlot * slot = NULL;
  GDEFCORE_Result rc = grow_slot(inst, &slot);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memcpy(slot->id, id, GDEFCORE_PUBLIC_ID_LEN + 1);
  memcpy(slot->storage, storage, kKeyBytes);
  slot->placement = dup_n(inst->alloc, placement, placement_len);
  slot->edition = dup_n(inst->alloc, edition, edition_len);
  slot->status = dup_n(inst->alloc, status, status_len);
  slot->resolution = dup_n(inst->alloc, resolution == NULL ? "" : resolution,
      resolution_len);
  slot->placement_len = placement_len;
  slot->edition_len = edition_len;
  slot->status_len = status_len;
  slot->resolution_len = resolution_len;
  slot->is_default = is_default;
  slot->limits = NULL;
  slot->limits_len = 0;
  if (limits != NULL && limits_len > 0) {
    slot->limits = dup_n(inst->alloc, limits, limits_len);
    slot->limits_len = limits_len;
  }
  if (slot->placement == NULL || slot->edition == NULL || slot->status == NULL ||
      slot->resolution == NULL || (limits != NULL && limits_len > 0 &&
                                      slot->limits == NULL)) {
    slot_clear(inst->alloc, slot);
    return GDEFCORE_ERR_OOM;
  }
  slot->keyring = NULL;
  if (inst->keys != NULL) {
    rc = gdefcore_subject_bind_keyring(inst->keys, slot->storage, kKeyBytes, root,
        GDEFCORE_ACCOUNT_ROOT_LEN, inst->alloc, &slot->keyring);
    if (rc == GDEFCORE_ERR_INVALID && slot->keyring == NULL) {
      rc = gdefcore_keyring_create(root, GDEFCORE_ACCOUNT_ROOT_LEN, inst->alloc,
          &slot->keyring);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_subject_bind_keyring(inst->keys, slot->storage, kKeyBytes,
            root, GDEFCORE_ACCOUNT_ROOT_LEN, inst->alloc, &slot->keyring);
      }
    }
  } else {
    rc = gdefcore_keyring_create(root, GDEFCORE_ACCOUNT_ROOT_LEN, inst->alloc,
        &slot->keyring);
  }
  if (rc != GDEFCORE_OK) {
    slot_clear(inst->alloc, slot);
    return rc;
  }
  inst->nslots += 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result add_tenant(GDEFCORE_Inst * inst, const char * key,
    size_t key_len, const char * placement, size_t placement_len, int is_default,
    const uint8_t * root, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  uint8_t raw[kKeyBytes];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int tries;
  GDEFCORE_Result rc;
  if (placement == NULL) {
    if (placement_len != 0) {
      return GDEFCORE_ERR_INVALID;
    }
    placement = "";
  }
  if (placement_len > kPlaceMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (is_default) {
    key = "";
    key_len = 0;
  } else if (!key_well_formed(key, key_len) || resolution_taken(inst, key, key_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = GDEFCORE_ERR_INTERNAL;
  for (tries = 0; tries < 4; tries++) {
    rc = GDEFCORE_OK;
    if (gsec_random_bytes(raw, sizeof raw, NULL) != GSEC_OK) {
      wipe(raw, sizeof raw);
      return GDEFCORE_ERR_IO;
    }
    if (!storage_taken(inst, raw)) {
      break;
    }
    rc = GDEFCORE_ERR_INTERNAL;
  }
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  rc = gdefcore_id_encode(raw, id);
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  rc = write_record(inst, id, raw, placement, placement_len, "", 0, kActive,
      strlen(kActive), key, key_len, is_default, NULL, 0);
  if (rc != GDEFCORE_OK) {
    wipe(raw, sizeof raw);
    return rc;
  }
  rc = adopt(inst, raw, id, placement, placement_len, "", 0, kActive,
      strlen(kActive), key, key_len, is_default, NULL, 0, root);
  wipe(raw, sizeof raw);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (out_id != NULL) {
    memcpy(out_id, id, GDEFCORE_PUBLIC_ID_LEN + 1);
  }
  return GDEFCORE_OK;
}

/* One tenant's record into a slot. */
static GDEFCORE_Result load_one(GDEFCORE_Inst * inst, const char * key,
    size_t key_len, const uint8_t * bytes, size_t len, const uint8_t * root,
    int * out_default) {
  char * f[7] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
  size_t n[7] = {0, 0, 0, 0, 0, 0, 0};
  static const char * const names[7] = {"storage", "placement", "edition",
      "status", "resolution", "is_default", "limits"};
  uint8_t raw[kKeyBytes];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_OK;
  size_t i;
  memset(raw, 0, sizeof raw);
  for (i = 0; i < 7 && rc == GDEFCORE_OK; i++) {
    rc = rec_field(inst->alloc, bytes, len, names[i], i < 6, &f[i], &n[i]);
  }
  if (rc == GDEFCORE_OK) {
    rc = hex_decode(f[0], n[0], raw, sizeof raw);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_id_encode(raw, id);
  }
  /* The key is the id the storage key encodes: a record under another key
   * is not one this registry wrote. */
  if (rc == GDEFCORE_OK &&
      (!same(key, key_len, id, GDEFCORE_PUBLIC_ID_LEN) ||
          (!same(f[5], n[5], "1", 1) && !same(f[5], n[5], "0", 1)))) {
    rc = GDEFCORE_ERR_CORRUPT;
  }
  if (rc == GDEFCORE_OK) {
    *out_default = same(f[5], n[5], "1", 1);
    rc = adopt(inst, raw, id, f[1], n[1], f[2], n[2], f[3], n[3], f[4], n[4],
        *out_default, f[6], n[6], root);
  }
  wipe(raw, sizeof raw);
  if (f[0] != NULL) {
    wipe(f[0], n[0]);
  }
  for (i = 0; i < 7; i++) {
    gcu_allocator_free(inst->alloc, f[i]);
  }
  return rc == GDEFCORE_ERR_INVALID ? GDEFCORE_ERR_CORRUPT : rc;
}

static GDEFCORE_Result load_slots(GDEFCORE_Inst * inst, const uint8_t * root) {
  uint64_t offset = 0;
  int defaults = 0;
  size_t total = 0;
  for (;;) {
    GDEFSTOR_RecordList * list = NULL;
    size_t count;
    size_t i;
    GDEFCORE_Result rc = map_stor(gdefstor_record_list(inst->registry,
        (const char *)kRegistryTenant, sizeof kRegistryTenant, kRegistryNs,
        strlen(kRegistryNs), "", 0, offset, GDEFSTOR_RECORD_MAX_PAGE, &list));
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    count = gdefstor_record_list_count(list);
    for (i = 0; i < count; i++) {
      const char * key = NULL;
      size_t key_len = 0;
      const uint8_t * bytes = NULL;
      size_t blen = 0;
      int is_default = 0;
      if (gdefstor_record_list_item(list, i, &key, &key_len, &bytes, &blen) !=
          GDEFSTOR_OK) {
        gdefstor_record_list_free(list);
        return GDEFCORE_ERR_CORRUPT;
      }
      rc = load_one(inst, key, key_len, bytes, blen, root, &is_default);
      if (rc != GDEFCORE_OK) {
        gdefstor_record_list_free(list);
        return rc;
      }
      defaults += is_default;
    }
    gdefstor_record_list_free(list);
    total += count;
    if (count < GDEFSTOR_RECORD_MAX_PAGE) {
      break;
    }
    offset += count;
  }
  if (total == 0) {
    return GDEFCORE_OK;
  }
  if (defaults != 1) {
    return GDEFCORE_ERR_CORRUPT;
  }
  return GDEFCORE_OK;
}

static char * dup_out(const GDEFCORE_Allocator * alloc, const char * s, size_t n) {
  return dup_n(alloc, s == NULL ? "" : s, n);
}

static GDEFCORE_Result open_inst(GDEFSTOR_Store * registry,
    GDEFSTOR_Store * site, GDEFSTOR_KeyStore * keys, const uint8_t * root,
    size_t root_len, const char * placement, size_t placement_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Inst ** out_inst) {
  GDEFCORE_Inst * inst;
  GDEFCORE_Result rc;
  if (registry == NULL || site == NULL || root == NULL ||
      root_len != GDEFCORE_ACCOUNT_ROOT_LEN || out_inst == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (placement == NULL) {
    if (placement_len != 0) {
      return GDEFCORE_ERR_INVALID;
    }
    placement = "";
  }
  if (placement_len > kPlaceMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  allocator = use_alloc(allocator);
  inst = (GDEFCORE_Inst *)mem(allocator, sizeof *inst);
  if (inst == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(inst, 0, sizeof *inst);
  inst->alloc = allocator;
  inst->registry = registry;
  inst->site = site;
  inst->keys = keys;
  memcpy(inst->root, root, sizeof inst->root);
  rc = gdefcore_keyring_create(root, root_len, allocator, &inst->keyring);
  if (rc != GDEFCORE_OK) {
    gdefcore_inst_destroy(inst);
    return rc;
  }
  rc = load_slots(inst, root);
  if (rc != GDEFCORE_OK) {
    gdefcore_inst_destroy(inst);
    return rc;
  }
  if (inst->nslots == 0) {
    rc = add_tenant(inst, "", 0, placement, placement_len, 1, root, NULL);
    if (rc != GDEFCORE_OK) {
      gdefcore_inst_destroy(inst);
      return rc;
    }
  }
  *out_inst = inst;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_inst_open(GDEFSTOR_Store * registry,
    GDEFSTOR_Store * site, const uint8_t * root, size_t root_len,
    const char * placement, size_t placement_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Inst ** out_inst) {
  return open_inst(registry, site, NULL, root, root_len, placement,
      placement_len, allocator, out_inst);
}

GDEFCORE_Result gdefcore_inst_open_keys(GDEFSTOR_Store * registry,
    GDEFSTOR_Store * site, GDEFSTOR_KeyStore * keys, const uint8_t * root,
    size_t root_len, const char * placement, size_t placement_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Inst ** out_inst) {
  if (keys == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return open_inst(registry, site, keys, root, root_len, placement,
      placement_len, allocator, out_inst);
}

void gdefcore_inst_destroy(GDEFCORE_Inst * inst) {
  size_t i;
  if (inst == NULL) {
    return;
  }
  for (i = 0; i < inst->nslots; i++) {
    slot_clear(inst->alloc, &inst->slots[i]);
  }
  gcu_allocator_free(inst->alloc, inst->slots);
  gdefcore_keyring_destroy(inst->keyring);
  wipe(inst->root, sizeof inst->root);
  gcu_allocator_free(inst->alloc, inst);
}

GDEFCORE_Result gdefcore_inst_default(const GDEFCORE_Inst * inst,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  size_t i;
  if (inst == NULL || out_id == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < inst->nslots; i++) {
    if (inst->slots[i].is_default) {
      memcpy(out_id, inst->slots[i].id, GDEFCORE_PUBLIC_ID_LEN + 1);
      return GDEFCORE_OK;
    }
  }
  return GDEFCORE_ERR_CORRUPT;
}

GDEFCORE_Result gdefcore_inst_tenant_create(GDEFCORE_Inst * inst, const char * key,
    size_t key_len, const char * placement, size_t placement_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  if (inst == NULL || out_id == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return add_tenant(inst, key, key_len, placement, placement_len, 0, inst->root,
      out_id);
}

GDEFCORE_Result gdefcore_inst_resolve(const GDEFCORE_Inst * inst, const char * key,
    size_t key_len, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1], char ** out_placement,
    size_t * out_placement_len, char ** out_edition, size_t * out_edition_len,
    char ** out_status, size_t * out_status_len, GDEFSTOR_Limits * out_limits) {
  size_t i;
  struct TenantSlot * slot = NULL;
  char * placement = NULL;
  char * edition = NULL;
  char * status = NULL;
  GDEFSTOR_Limits limits;
  GDEFCORE_Result rc;
  if (inst == NULL || out_id == NULL || out_placement == NULL ||
      out_placement_len == NULL || out_edition == NULL ||
      out_edition_len == NULL || out_status == NULL || out_status_len == NULL ||
      out_limits == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!key_well_formed(key, key_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < inst->nslots; i++) {
    if (same(inst->slots[i].resolution, inst->slots[i].resolution_len, key,
            key_len)) {
      slot = &inst->slots[i];
      break;
    }
  }
  if (slot == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  placement = dup_out(inst->alloc, slot->placement, slot->placement_len);
  edition = dup_out(inst->alloc, slot->edition, slot->edition_len);
  status = dup_out(inst->alloc, slot->status, slot->status_len);
  if (placement == NULL || edition == NULL || status == NULL) {
    gcu_allocator_free(inst->alloc, placement);
    gcu_allocator_free(inst->alloc, edition);
    gcu_allocator_free(inst->alloc, status);
    return GDEFCORE_ERR_OOM;
  }
  rc = apply_limits(slot->limits, slot->limits_len, &limits);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(inst->alloc, placement);
    gcu_allocator_free(inst->alloc, edition);
    gcu_allocator_free(inst->alloc, status);
    return rc;
  }
  memcpy(out_id, slot->id, GDEFCORE_PUBLIC_ID_LEN + 1);
  *out_placement = placement;
  *out_placement_len = slot->placement_len;
  *out_edition = edition;
  *out_edition_len = slot->edition_len;
  *out_status = status;
  *out_status_len = slot->status_len;
  *out_limits = limits;
  return GDEFCORE_OK;
}

void gdefcore_inst_text_free(const GDEFCORE_Inst * inst, char * text) {
  if (inst == NULL) {
    return;
  }
  gcu_allocator_free(inst->alloc, text);
}

GDEFCORE_Result gdefcore_inst_catalog_open(GDEFCORE_Inst * inst, const char * id,
    size_t id_len, GDEFCORE_Catalog ** out_catalog) {
  struct TenantSlot * slot;
  if (inst == NULL || out_catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  slot = find_id(inst, id, id_len);
  if (slot == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_catalog_open(inst->site, slot->storage, kKeyBytes, NULL,
      inst->alloc, out_catalog);
}

GDEFCORE_Result gdefcore_inst_storage_key(const GDEFCORE_Inst * inst,
    const char * id, size_t id_len, uint8_t out[16]) {
  struct TenantSlot * slot;
  if (inst == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  slot = find_id(inst, id, id_len);
  if (slot == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  memcpy(out, slot->storage, kKeyBytes);
  return GDEFCORE_OK;
}

GDEFCORE_Keyring * gdefcore_inst_keyring(GDEFCORE_Inst * inst) {
  if (inst == NULL) {
    return NULL;
  }
  return inst->keyring;
}

GDEFCORE_Keyring * gdefcore_inst_tenant_keyring(GDEFCORE_Inst * inst,
    const char * id, size_t id_len) {
  struct TenantSlot * slot;
  if (inst == NULL) {
    return NULL;
  }
  slot = find_id(inst, id, id_len);
  if (slot == NULL) {
    return NULL;
  }
  return slot->keyring;
}

static GDEFCORE_Result rewrite_limits(GDEFCORE_Inst * inst, struct TenantSlot * slot,
    const char * text, size_t n) {
  return write_record(inst, slot->id, slot->storage, slot->placement,
      slot->placement_len, slot->edition, slot->edition_len, slot->status,
      slot->status_len, slot->resolution, slot->resolution_len,
      slot->is_default, text, n);
}

GDEFCORE_Result gdefcore_inst_limit_set(GDEFCORE_Inst * inst, const char * id,
    size_t id_len, const char * field, size_t field_len, uint64_t value) {
  struct TenantSlot * slot;
  const struct LimitField * known;
  GDEFSTOR_Limits limits;
  char * built = NULL;
  size_t built_n = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (inst == NULL || field == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  slot = find_id(inst, id, id_len);
  if (slot == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  known = limit_field(field, field_len);
  if (known == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (known->u32 && value > UINT32_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  if ((uint64_t)(size_t)value != value && !known->u32) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = apply_limits(slot->limits, slot->limits_len, &limits);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (known->u32) {
    uint32_t stored = (uint32_t)value;
    memcpy((char *)&limits + known->offset, &stored, sizeof stored);
  } else {
    size_t stored = (size_t)value;
    memcpy((char *)&limits + known->offset, &stored, sizeof stored);
  }
  for (i = 0; i < sizeof kLimits / sizeof kLimits[0]; i++) {
    uint64_t have = 0;
    GDEFSTOR_Limits defaults;
    uint64_t base = 0;
    char piece[96];
    char * next;
    int n;
    memset(&defaults, 0, sizeof defaults);
    gdefstor_limits_default(&defaults);
    if (kLimits[i].u32) {
      uint32_t cur = 0;
      uint32_t def = 0;
      memcpy(&cur, (char *)&limits + kLimits[i].offset, sizeof cur);
      memcpy(&def, (char *)&defaults + kLimits[i].offset, sizeof def);
      have = cur;
      base = def;
    } else {
      size_t cur = 0;
      size_t def = 0;
      memcpy(&cur, (char *)&limits + kLimits[i].offset, sizeof cur);
      memcpy(&def, (char *)&defaults + kLimits[i].offset, sizeof def);
      have = cur;
      base = def;
    }
    if (have == base) {
      continue;
    }
    n = snprintf(piece, sizeof piece, "%s=%llu\n", kLimits[i].name,
        (unsigned long long)have);
    if (n < 0 || (size_t)n >= sizeof piece) {
      gcu_allocator_free(inst->alloc, built);
      return GDEFCORE_ERR_LIMIT;
    }
    next = (char *)gcu_allocator_realloc(inst->alloc, built, built_n + (size_t)n + 1);
    if (next == NULL) {
      gcu_allocator_free(inst->alloc, built);
      return GDEFCORE_ERR_OOM;
    }
    built = next;
    memcpy(built + built_n, piece, (size_t)n);
    built_n += (size_t)n;
    built[built_n] = '\0';
  }
  if (built == NULL) {
    built = dup_n(inst->alloc, "", 0);
    built_n = 0;
    if (built == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  rc = rewrite_limits(inst, slot, built, built_n);
  if (rc != GDEFCORE_OK) {
    gcu_allocator_free(inst->alloc, built);
    return rc;
  }
  gcu_allocator_free(inst->alloc, slot->limits);
  slot->limits = built;
  slot->limits_len = built_n;
  return GDEFCORE_OK;
}
