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
 * Hook bus and module host. Order is a sorted list rebuilt when the config
 * epoch changes. The entered record is a stored flag: a native call sets it
 * before the call and clears it after, so a crash leaves it set.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/condition.h>

#include "module_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/library.h>
#include <ghoti.io/defiant-storage/model.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_STR2(x) #x
#define TOKEN_STR(x) TOKEN_STR2(x)

enum {
  kNameMax = 64,
  kTokenMax = 128,
  kPathMax = 1024,
  kModMax = 64,
  kRelMax = 8,
  kSubMax = 16,
  kSvcMax = 16,
  kPermMax = 8,
  kStepMax = 64,
  kChainMax = 32,
  kNodeMax = 64,
  kNoticeMax = 1024,
  kErrorMax = 512,
  kSkipMax = 1024,
  kTenantMax = 256,
  kAlterMax = 4096,
  kContribMax = 64,
  kContribText = 256
};

static const char kCoreToken[] = TOKEN_STR(GHOTIIO_DEFCORE_NAME);
static const char kEntrySymbol[] = "gdefcore_module_manifest";
static const char kInstallTenant[] = "\x01";
static const char kInstallType[] = "core.module.install";
static const char kEnabledType[] = GDEFCORE_MODULE_ENABLED_TYPE;
static const char kSchemaType[] = GDEFCORE_SCHEMA_TYPE;
static const char kCoreStamp[] = GDEFCORE_SCHEMA_CORE_STAMP;

typedef struct Name {
  char text[kNameMax + 1];
  size_t len;
} Name;

typedef struct Rel {
  int kind;
  char name[kNameMax + 1];
  size_t name_len;
} Rel;

typedef struct Sub {
  char hook[kNameMax + 1];
  size_t hook_len;
  int kind;
  int weight;
  int access;
  char before[kNameMax + 1];
  size_t before_len;
  char after[kNameMax + 1];
  size_t after_len;
  GDEFCORE_Hook_Fn fn;
  void * user;
} Sub;

typedef struct Svc {
  char name[kNameMax + 1];
  size_t name_len;
  uint32_t version;
  const void * table;
} Svc;

typedef struct Perm {
  char label[kNameMax + 1];
  size_t label_len;
  char action[kNameMax + 1];
  size_t action_len;
  int condition;
  char type_name[kNameMax + 1];
  size_t type_len;
  char field[kNameMax + 1];
  size_t field_len;
} Perm;

/* A forward step or a read-time upcaster, by the version it starts from. */
typedef struct Step {
  uint32_t from;
  GDEFCORE_Step_Fn step;
  GDEFCORE_Upcast_Fn up;
  void * user;
} Step;

typedef struct Mod {
  int used;
  char name[kNameMax + 1];
  size_t name_len;
  char label[kNameMax + 1];
  size_t label_len;
  char path[kPathMax];
  size_t path_len;
  char token[kTokenMax + 1];
  size_t token_len;
  int native;
  int quarantined;
  int loaded;
  GCU_Library library;
  int have_library;
  int enter_depth;
  GDEFCORE_Module_Entry entry;
  Rel rels[kRelMax];
  size_t nrels;
  Sub subs[kSubMax];
  size_t nsubs;
  Svc services[kSvcMax];
  size_t nservices;
  Perm perms[kPermMax];
  size_t nperms;
  Decl * decl;
  uint32_t schema; /* stored-data schema version (AD-15), 1 or more */
  Step steps[kStepMax];
  size_t nsteps;
  Step ups[kStepMax];
  size_t nups;
} Mod;

typedef struct ChainNode {
  char name[kNameMax + 1];
  size_t name_len;
  GDEFCORE_Hook_Fn fn;
  void * user;
  int access;
  int native;
  int mod_index;
} ChainNode;

/*
 * One registered contribution to a template kind's contract. The public
 * record points into the buffers beside it, so a pointer to it is stable for
 * the life of the host: contributions are only ever added.
 */
typedef struct Contrib {
  GDEFCORE_Module_Contributed pub;
  char module[kNameMax + 1];
  char kind[kNameMax + 1];
  char name[kNameMax + 1];
  char type[16];
  char description[kContribText + 1];
  char before[kNameMax + 1];
  size_t before_len;
  char after[kNameMax + 1];
  size_t after_len;
  int weight;
} Contrib;

typedef struct Chain {
  int used;
  uint8_t tenant[kTenantMax];
  size_t tenant_len;
  uint64_t epoch;
  char hook[kNameMax + 1];
  size_t hook_len;
  int kind;
  ChainNode nodes[kNodeMax];
  size_t n;
} Chain;

struct GDEFCORE_Host {
  GDEFSTOR_Store * store;
  const GDEFCORE_Allocator * alloc;
  Mod mods[kModMax];
  size_t nmods;
  Chain chains[kChainMax];
  size_t nchains;
  char notice[kNoticeMax];
  size_t notice_n;
  char pending[kNoticeMax];
  size_t pending_n;
  int pending_valid;
  char error[kErrorMax];
  size_t error_n;
  char skipped[kSkipMax];
  size_t skipped_n;
  size_t skipped_count;
  int firing;
  Contrib contribs[kContribMax];
  size_t ncontribs;
  Decl * retired;
};

struct GDEFCORE_Alter {
  const GDEFCORE_Allocator * alloc;
  char * text;
  size_t len;
};

static const GDEFCORE_Allocator * use_alloc(const GDEFCORE_Allocator * alloc) {
  return alloc == NULL ? gdefcore_allocator_default() : alloc;
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

static void set_error(GDEFCORE_Host * host, const char * text) {
  size_t n = 0;
  if (host == NULL) {
    return;
  }
  if (text != NULL) {
    n = strlen(text);
  }
  if (n >= sizeof host->error) {
    n = sizeof host->error - 1;
  }
  if (n > 0) {
    memcpy(host->error, text, n);
  }
  host->error[n] = '\0';
  host->error_n = n;
}

/*
 * A Decl a reload replaces may still be pointed at by an enumeration someone
 * holds, so it is kept on the host's list and freed with the host.
 */
static void retire_decl(GDEFCORE_Host * host, Decl * decl) {
  if (decl == NULL) {
    return;
  }
  decl->next = host->retired;
  host->retired = decl;
}

static GDEFCORE_Result projected_names(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection, Name * names, size_t * n);
static GDEFCORE_Result validate_declared(GDEFCORE_Host * host,
    const Name * names, size_t nnames, int local);

static int name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > kNameMax) {
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

static int ident_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > kNameMax) {
    return 0;
  }
  if (s[0] < 'a' || s[0] > 'z') {
    return 0;
  }
  for (i = 1; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '.' || c == '_')) {
      return 0;
    }
  }
  return 1;
}

static int copy_span(char * dst, size_t cap, size_t * out_n, const char * s,
    size_t n) {
  if (s == NULL || n >= cap) {
    return 0;
  }
  if (n > 0) {
    memcpy(dst, s, n);
  }
  dst[n] = '\0';
  *out_n = n;
  return 1;
}

static int cmp_name(const void * a, const void * b) {
  const Name * na = (const Name *)a;
  const Name * nb = (const Name *)b;
  size_t n = na->len < nb->len ? na->len : nb->len;
  int cmp = memcmp(na->text, nb->text, n);
  if (cmp != 0) {
    return cmp;
  }
  if (na->len < nb->len) {
    return -1;
  }
  if (na->len > nb->len) {
    return 1;
  }
  return 0;
}

static void take_prefix(void * dst, size_t dst_n, const void * src) {
  const size_t * sizep;
  size_t n;
  memset(dst, 0, dst_n);
  if (src == NULL) {
    return;
  }
  sizep = (const size_t *)src;
  n = *sizep;
  if (n > dst_n) {
    n = dst_n;
  }
  if (n > 0) {
    memcpy(dst, src, n);
  }
}

static Mod * find_mod(GDEFCORE_Host * host, const char * name, size_t len) {
  size_t i;
  for (i = 0; i < host->nmods; i++) {
    if (host->mods[i].used && host->mods[i].name_len == len &&
        memcmp(host->mods[i].name, name, len) == 0) {
      return &host->mods[i];
    }
  }
  return NULL;
}

static int name_has(const Name * names, size_t n, const char * text,
    size_t len) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (names[i].len == len && memcmp(names[i].text, text, len) == 0) {
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result name_add(Name * names, size_t * n, size_t cap,
    const char * text, size_t len) {
  if (name_has(names, *n, text, len)) {
    return GDEFCORE_OK;
  }
  if (*n >= cap || !name_ok(text, len)) {
    return *n >= cap ? GDEFCORE_ERR_LIMIT : GDEFCORE_ERR_INVALID;
  }
  if (!copy_span(names[*n].text, sizeof names[*n].text, &names[*n].len, text,
          len)) {
    return GDEFCORE_ERR_LIMIT;
  }
  *n += 1;
  return GDEFCORE_OK;
}

static void name_remove(Name * names, size_t * n, const char * text,
    size_t len) {
  size_t i;
  for (i = 0; i < *n; i++) {
    if (names[i].len == len && memcmp(names[i].text, text, len) == 0) {
      names[i] = names[*n - 1];
      *n -= 1;
      return;
    }
  }
}

/*
 * A module record (story S6b: installed and enabled modules are records of
 * the storage port, AD-31): one `name hex` line per column, the value in
 * lowercase hex so that no byte of it can end a line.
 */
typedef struct RecBuf {
  char text[4 * (kPathMax + 64)];
  size_t n;
  int full;
} RecBuf;

static void rec_put(RecBuf * b, const char * name, const char * value,
    size_t len) {
  static const char hex[] = "0123456789abcdef";
  size_t nl = strlen(name);
  size_t i;
  if (b->full || b->n + nl + 2 + 2 * len >= sizeof b->text) {
    b->full = 1;
    return;
  }
  memcpy(b->text + b->n, name, nl);
  b->n += nl;
  b->text[b->n++] = ' ';
  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)value[i];
    b->text[b->n++] = hex[c >> 4];
    b->text[b->n++] = hex[c & 15u];
  }
  b->text[b->n++] = '\n';
}

static int rec_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

static GDEFCORE_Result rec_copy(const uint8_t * bytes, size_t len,
    const char * name, size_t name_len, char * dst, size_t cap, size_t * out_n,
    int required) {
  const char * p = (const char *)bytes;
  const char * end = p + len;
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
      size_t i;
      if (hn % 2 != 0) {
        return GDEFCORE_ERR_CORRUPT;
      }
      if (hn / 2 >= cap) {
        return GDEFCORE_ERR_LIMIT;
      }
      for (i = 0; i < hn; i += 2) {
        int hi = rec_nibble(sp[1 + i]);
        int lo = rec_nibble(sp[2 + i]);
        if (hi < 0 || lo < 0) {
          return GDEFCORE_ERR_CORRUPT;
        }
        dst[i / 2] = (char)((hi << 4) | lo);
      }
      dst[hn / 2] = '\0';
      *out_n = hn / 2;
      return GDEFCORE_OK;
    }
    p = eol + 1;
  }
  if (required) {
    return GDEFCORE_ERR_CORRUPT;
  }
  dst[0] = '\0';
  *out_n = 0;
  return GDEFCORE_OK;
}

/* The names of a namespace's records, in key order. */
static GDEFCORE_Result load_names(GDEFCORE_Host * host, const char * tenant,
    size_t tenant_len, const char * ns, Name * names, size_t cap,
    size_t * out_n) {
  uint64_t offset = 0;
  *out_n = 0;
  for (;;) {
    GDEFSTOR_RecordList * list = NULL;
    size_t i;
    size_t count;
    GDEFSTOR_Result src = gdefstor_record_list(host->store, tenant, tenant_len,
        ns, strlen(ns), "", 0, offset, GDEFSTOR_RECORD_MAX_PAGE, &list);
    if (src != GDEFSTOR_OK) {
      return map_stor(src);
    }
    count = gdefstor_record_list_count(list);
    for (i = 0; i < count; i++) {
      const char * key = NULL;
      size_t key_len = 0;
      const uint8_t * bytes = NULL;
      size_t blen = 0;
      if (gdefstor_record_list_item(list, i, &key, &key_len, &bytes, &blen,
              NULL, NULL) != GDEFSTOR_OK) {
        gdefstor_record_list_free(list);
        return GDEFCORE_ERR_CORRUPT;
      }
      if (*out_n >= cap) {
        gdefstor_record_list_free(list);
        return GDEFCORE_ERR_LIMIT;
      }
      if (!name_ok(key, key_len) ||
          !copy_span(names[*out_n].text, sizeof names[*out_n].text,
              &names[*out_n].len, key, key_len)) {
        gdefstor_record_list_free(list);
        return GDEFCORE_ERR_CORRUPT;
      }
      *out_n += 1;
    }
    gdefstor_record_list_free(list);
    if (count < GDEFSTOR_RECORD_MAX_PAGE) {
      return GDEFCORE_OK;
    }
    offset += count;
  }
}

static void close_mod(Mod * mod) {
  if (mod->have_library) {
    gcu_library_close(&mod->library);
    mod->have_library = 0;
  }
  mod->library = NULL;
  mod->entry = NULL;
}

static GDEFCORE_Result put_install_row(GDEFSTOR_Write * write, const Mod * mod,
    int entered) {
  RecBuf b;
  const char * kind = mod->native ? "native" : "guest";
  memset(&b, 0, sizeof b);
  rec_put(&b, "kind", kind, strlen(kind));
  rec_put(&b, "token", mod->token, mod->token_len);
  rec_put(&b, "entered", entered ? "1" : "0", 1);
  if (mod->native) {
    rec_put(&b, "path", mod->path, mod->path_len);
  }
  {
    char schema[16];
    int n = snprintf(schema, sizeof schema, "%lu",
        (unsigned long)mod->schema);
    if (mod->schema == 0 || n <= 0 || (size_t)n >= sizeof schema) {
      return GDEFCORE_ERR_INTERNAL;
    }
    rec_put(&b, "schema", schema, (size_t)n);
  }
  if (b.full) {
    return GDEFCORE_ERR_LIMIT;
  }
  return map_stor(gdefstor_record_put(write, kInstallType, strlen(kInstallType),
      mod->name, mod->name_len, kCoreStamp, strlen(kCoreStamp),
      (const uint8_t *)b.text, b.n));
}

/* The installation's record of a module, in a write of its own on the
 * installation tenant. */
static GDEFCORE_Result store_install(GDEFCORE_Host * host, const Mod * mod) {
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc = map_stor(gdefstor_write_begin(host->store,
      kInstallTenant, 1, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = put_install_row(write, mod, 0);
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return map_stor(gdefstor_write_commit(write));
}

static GDEFCORE_Result persist_entered(GDEFCORE_Host * host, Mod * mod,
    int entered) {
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc;
  if (!mod->native) {
    return GDEFCORE_OK;
  }
  rc = map_stor(gdefstor_write_begin(host->store, kInstallTenant, 1, NULL,
      &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = put_install_row(write, mod, entered);
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return map_stor(gdefstor_write_commit(write));
}

/* The stored flag stays set until the outermost native call returns. */
static GDEFCORE_Result touch_entered(GDEFCORE_Host * host, Mod * mod,
    int enter) {
  if (!mod->native) {
    return GDEFCORE_OK;
  }
  if (enter) {
    if (mod->enter_depth == 0) {
      GDEFCORE_Result rc = persist_entered(host, mod, 1);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
    mod->enter_depth += 1;
    return GDEFCORE_OK;
  }
  if (mod->enter_depth == 0) {
    return persist_entered(host, mod, 0);
  }
  mod->enter_depth -= 1;
  if (mod->enter_depth > 0) {
    return GDEFCORE_OK;
  }
  return persist_entered(host, mod, 0);
}

static GDEFCORE_Result copy_manifest(GDEFCORE_Host * host, Mod * mod,
    const GDEFCORE_Module_Manifest * src) {
  GDEFCORE_Module_Manifest man;
  size_t i;
  if (src == NULL || src->size < sizeof(size_t)) {
    set_error(host, "Module manifest is missing.");
    return GDEFCORE_ERR_INVALID;
  }
  take_prefix(&man, sizeof man, src);
  if (!name_ok(man.name, man.name_len)) {
    set_error(host, "Module name is not lowercase.");
    return GDEFCORE_ERR_INVALID;
  }
  if (mod->name_len != 0 &&
      (mod->name_len != man.name_len ||
          memcmp(mod->name, man.name, man.name_len) != 0)) {
    set_error(host, "Module entry changed its name.");
    return GDEFCORE_ERR_INVALID;
  }
  if (!copy_span(mod->name, sizeof mod->name, &mod->name_len, man.name,
          man.name_len)) {
    return GDEFCORE_ERR_LIMIT;
  }
  mod->label_len = 0;
  mod->label[0] = '\0';
  if (man.label != NULL && man.label_len > 0) {
    if (!copy_span(mod->label, sizeof mod->label, &mod->label_len, man.label,
            man.label_len)) {
      return GDEFCORE_ERR_LIMIT;
    }
  }
  if (man.core_token == NULL || man.core_token_len > kTokenMax ||
      !copy_span(mod->token, sizeof mod->token, &mod->token_len, man.core_token,
          man.core_token_len)) {
    set_error(host, "Module core token is missing.");
    return GDEFCORE_ERR_INVALID;
  }
  /* The module's stored-data schema version is required (AD-15): a manifest
   * that leaves it 0, or is too short to hold it, says nothing about what its
   * data is written in, and is refused. */
  if (man.schema_version == 0) {
    set_error(host, "Module manifest declares no stored-data schema version; "
                    "its schema_version must be 1 or more.");
    return GDEFCORE_ERR_INVALID;
  }
  mod->schema = man.schema_version;
  if (man.nsteps > kStepMax || man.nupcasters > kStepMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  if ((man.nsteps > 0 && man.steps == NULL) ||
      (man.nupcasters > 0 && man.upcasters == NULL)) {
    return GDEFCORE_ERR_INVALID;
  }
  mod->nsteps = 0;
  for (i = 0; i < man.nsteps; i++) {
    GDEFCORE_Module_Step st;
    size_t k;
    take_prefix(&st, sizeof st, &man.steps[i]);
    if (st.fn == NULL || st.from == 0 || st.from >= mod->schema) {
      set_error(host, "A module's forward step starts from a version that is "
                      "not below its schema version, or has no function.");
      return GDEFCORE_ERR_INVALID;
    }
    for (k = 0; k < mod->nsteps; k++) {
      if (mod->steps[k].from == st.from) {
        set_error(host, "A module declares two forward steps from one "
                        "version.");
        return GDEFCORE_ERR_INVALID;
      }
    }
    mod->steps[mod->nsteps].from = st.from;
    mod->steps[mod->nsteps].step = st.fn;
    mod->steps[mod->nsteps].up = NULL;
    mod->steps[mod->nsteps].user = st.user;
    mod->nsteps += 1;
  }
  mod->nups = 0;
  for (i = 0; i < man.nupcasters; i++) {
    GDEFCORE_Module_Upcaster up;
    size_t k;
    take_prefix(&up, sizeof up, &man.upcasters[i]);
    if (up.fn == NULL || up.from == 0 || up.from >= mod->schema) {
      set_error(host, "A module's upcaster reads a version that is not below "
                      "its schema version, or has no function.");
      return GDEFCORE_ERR_INVALID;
    }
    for (k = 0; k < mod->nups; k++) {
      if (mod->ups[k].from == up.from) {
        set_error(host, "A module declares two upcasters for one version.");
        return GDEFCORE_ERR_INVALID;
      }
    }
    mod->ups[mod->nups].from = up.from;
    mod->ups[mod->nups].step = NULL;
    mod->ups[mod->nups].up = up.fn;
    mod->ups[mod->nups].user = up.user;
    mod->nups += 1;
  }
  if (man.nrels > kRelMax || man.nsubs > kSubMax || man.nservices > kSvcMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  if ((man.nrels > 0 && man.rels == NULL) ||
      (man.nsubs > 0 && man.subs == NULL) ||
      (man.nservices > 0 && man.services == NULL)) {
    return GDEFCORE_ERR_INVALID;
  }
  mod->nrels = 0;
  for (i = 0; i < man.nrels; i++) {
    GDEFCORE_Module_Rel rel;
    take_prefix(&rel, sizeof rel, &man.rels[i]);
    if (rel.kind != GDEFCORE_REL_REQUIRES && rel.kind != GDEFCORE_REL_ENHANCES) {
      return GDEFCORE_ERR_INVALID;
    }
    if (!name_ok(rel.name, rel.name_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    mod->rels[mod->nrels].kind = rel.kind;
    if (!copy_span(mod->rels[mod->nrels].name, sizeof mod->rels[mod->nrels].name,
            &mod->rels[mod->nrels].name_len, rel.name, rel.name_len)) {
      return GDEFCORE_ERR_LIMIT;
    }
    mod->nrels += 1;
  }
  mod->nsubs = 0;
  for (i = 0; i < man.nsubs; i++) {
    GDEFCORE_Module_Sub sub;
    size_t j;
    take_prefix(&sub, sizeof sub, &man.subs[i]);
    if (sub.fn == NULL ||
        (sub.kind != GDEFCORE_HOOK_EVENT && sub.kind != GDEFCORE_HOOK_ALTER &&
            sub.kind != GDEFCORE_HOOK_DECISION) ||
        !ident_ok(sub.hook, sub.hook_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    for (j = 0; j < mod->nsubs; j++) {
      if (mod->subs[j].hook_len == sub.hook_len &&
          memcmp(mod->subs[j].hook, sub.hook, sub.hook_len) == 0) {
        set_error(host, "A module subscribed twice to one hook.");
        return GDEFCORE_ERR_INVALID;
      }
    }
    if (sub.before != NULL && sub.before_len > 0 &&
        !name_ok(sub.before, sub.before_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    if (sub.after != NULL && sub.after_len > 0 &&
        !name_ok(sub.after, sub.after_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    memset(&mod->subs[mod->nsubs], 0, sizeof mod->subs[mod->nsubs]);
    if (!copy_span(mod->subs[mod->nsubs].hook, sizeof mod->subs[mod->nsubs].hook,
            &mod->subs[mod->nsubs].hook_len, sub.hook, sub.hook_len)) {
      return GDEFCORE_ERR_LIMIT;
    }
    mod->subs[mod->nsubs].kind = sub.kind;
    mod->subs[mod->nsubs].weight = sub.weight;
    mod->subs[mod->nsubs].access = sub.access_relevant ? 1 : 0;
    mod->subs[mod->nsubs].fn = sub.fn;
    mod->subs[mod->nsubs].user = sub.user;
    if (sub.before != NULL && sub.before_len > 0) {
      if (!copy_span(mod->subs[mod->nsubs].before,
              sizeof mod->subs[mod->nsubs].before,
              &mod->subs[mod->nsubs].before_len, sub.before, sub.before_len)) {
        return GDEFCORE_ERR_LIMIT;
      }
    }
    if (sub.after != NULL && sub.after_len > 0) {
      if (!copy_span(mod->subs[mod->nsubs].after,
              sizeof mod->subs[mod->nsubs].after,
              &mod->subs[mod->nsubs].after_len, sub.after, sub.after_len)) {
        return GDEFCORE_ERR_LIMIT;
      }
    }
    mod->nsubs += 1;
  }
  mod->nservices = 0;
  for (i = 0; i < man.nservices; i++) {
    GDEFCORE_Module_Service svc;
    take_prefix(&svc, sizeof svc, &man.services[i]);
    if (!ident_ok(svc.name, svc.name_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    if (!copy_span(mod->services[mod->nservices].name,
            sizeof mod->services[mod->nservices].name,
            &mod->services[mod->nservices].name_len, svc.name, svc.name_len)) {
      return GDEFCORE_ERR_LIMIT;
    }
    mod->services[mod->nservices].version = svc.version;
    mod->services[mod->nservices].table = svc.table;
    mod->nservices += 1;
  }
  mod->nperms = 0;
  if (man.nperms > kPermMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (man.nperms > 0 && man.perms == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < man.nperms; i++) {
    GDEFCORE_Module_Perm perm;
    take_prefix(&perm, sizeof perm, &man.perms[i]);
    if (perm.label == NULL || perm.label_len == 0 || perm.action == NULL ||
        perm.action_len == 0 || perm.type_name == NULL ||
        perm.type_name_len == 0 ||
        (perm.condition != GDEFCORE_ACCESS_ANY &&
            perm.condition != GDEFCORE_ACCESS_OWN)) {
      return GDEFCORE_ERR_INVALID;
    }
    memset(&mod->perms[mod->nperms], 0, sizeof mod->perms[mod->nperms]);
    if (!copy_span(mod->perms[mod->nperms].label,
            sizeof mod->perms[mod->nperms].label,
            &mod->perms[mod->nperms].label_len, perm.label, perm.label_len) ||
        !copy_span(mod->perms[mod->nperms].action,
            sizeof mod->perms[mod->nperms].action,
            &mod->perms[mod->nperms].action_len, perm.action,
            perm.action_len) ||
        !copy_span(mod->perms[mod->nperms].type_name,
            sizeof mod->perms[mod->nperms].type_name,
            &mod->perms[mod->nperms].type_len, perm.type_name,
            perm.type_name_len)) {
      return GDEFCORE_ERR_LIMIT;
    }
    if (perm.field != NULL && perm.field_len > 0) {
      if (!copy_span(mod->perms[mod->nperms].field,
              sizeof mod->perms[mod->nperms].field,
              &mod->perms[mod->nperms].field_len, perm.field,
              perm.field_len)) {
        return GDEFCORE_ERR_LIMIT;
      }
    }
    mod->perms[mod->nperms].condition = perm.condition;
    mod->nperms += 1;
  }
  {
    DeclSvc svcs[kSvcMax];
    Decl * decl = NULL;
    char text[kErrorMax];
    GDEFCORE_Result rc;
    for (i = 0; i < mod->nservices; i++) {
      svcs[i].name = mod->services[i].name;
      svcs[i].name_len = mod->services[i].name_len;
      svcs[i].version = mod->services[i].version;
      svcs[i].table = mod->services[i].table;
    }
    text[0] = '\0';
    rc = gdefcore_decl_build(host->alloc, mod->name, mod->name_len, &man, svcs,
        mod->nservices, &decl, text, sizeof text);
    if (rc != GDEFCORE_OK) {
      set_error(host, text);
      return rc;
    }
    retire_decl(host, mod->decl);
    mod->decl = decl;
  }
  mod->loaded = 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result tokens_differ(GDEFCORE_Host * host, const Mod * mod) {
  if (mod->token_len == strlen(kCoreToken) &&
      memcmp(mod->token, kCoreToken, mod->token_len) == 0) {
    return GDEFCORE_OK;
  }
  snprintf(host->error, sizeof host->error,
      "Module core token is %s; running core token is %s.",
      mod->token_len == 0 ? "(empty)" : mod->token, kCoreToken);
  host->error_n = strlen(host->error);
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result call_entry(GDEFCORE_Host * host, Mod * mod) {
  const GDEFCORE_Module_Manifest * manifest;
  GDEFCORE_Result rc;
  GDEFCORE_Result clear_rc;
  if (mod->entry == NULL) {
    set_error(host, "Module entry is missing.");
    return GDEFCORE_ERR_INVALID;
  }
  /* The name is known after install. The first read of a new library has no
   * row yet, so the entered flag starts with the next call. */
  if (mod->native && mod->name_len > 0) {
    rc = touch_entered(host, mod, 1);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  manifest = mod->entry();
  clear_rc = GDEFCORE_OK;
  if (mod->native && mod->name_len > 0) {
    clear_rc = touch_entered(host, mod, 0);
  }
  if (manifest == NULL) {
    set_error(host, "Module entry returned nothing.");
    return GDEFCORE_ERR_INVALID;
  }
  rc = copy_manifest(host, mod, manifest);
  if (rc != GDEFCORE_OK) {
    mod->nperms = 0;
    return rc;
  }
  rc = tokens_differ(host, mod);
  if (rc != GDEFCORE_OK) {
    mod->loaded = 0;
    mod->nsubs = 0;
    mod->nrels = 0;
    mod->nservices = 0;
    mod->nperms = 0;
    gdefcore_decl_free(mod->decl);
    mod->decl = NULL;
    return rc;
  }
  if (clear_rc != GDEFCORE_OK) {
    return clear_rc;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result open_native(GDEFCORE_Host * host, Mod * mod) {
  GCU_Library_Function symbol;
  char buf[256];
  if (mod->have_library) {
    return GDEFCORE_OK;
  }
  if (gcu_library_open(&mod->library, mod->path) != 0) {
    buf[0] = '\0';
    gcu_library_error(buf, sizeof buf);
    snprintf(host->error, sizeof host->error, "Native module did not open: %s",
        buf);
    host->error_n = strlen(host->error);
    return GDEFCORE_ERR_IO;
  }
  mod->have_library = 1;
  symbol = gcu_library_symbol(mod->library, kEntrySymbol);
  if (symbol == NULL) {
    close_mod(mod);
    snprintf(host->error, sizeof host->error,
        "Module entry %s is missing.", kEntrySymbol);
    host->error_n = strlen(host->error);
    return GDEFCORE_ERR_INVALID;
  }
  mod->entry = (GDEFCORE_Module_Entry)symbol;
  return GDEFCORE_OK;
}

static void clear_mod(Mod * mod) {
  close_mod(mod);
  gdefcore_decl_free(mod->decl);
  memset(mod, 0, sizeof *mod);
}


static GDEFCORE_Result adopt(GDEFCORE_Host * host, Mod * filled) {
  if (find_mod(host, filled->name, filled->name_len) != NULL) {
    set_error(host, "Module is already installed.");
    clear_mod(filled);
    return GDEFCORE_ERR_INVALID;
  }
  if (host->nmods >= kModMax) {
    clear_mod(filled);
    return GDEFCORE_ERR_LIMIT;
  }
  host->mods[host->nmods] = *filled;
  host->mods[host->nmods].used = 1;
  host->nmods += 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result reload_one(GDEFCORE_Host * host, const Name * name) {
  Mod mod;
  char kind[16];
  char entered[8];
  size_t kind_len = 0;
  size_t entered_len = 0;
  int found = 0;
  uint8_t * bytes = NULL;
  size_t blen = 0;
  GDEFSTOR_Result src;
  GDEFCORE_Result rc;
  memset(&mod, 0, sizeof mod);
  if (!copy_span(mod.name, sizeof mod.name, &mod.name_len, name->text,
          name->len)) {
    return GDEFCORE_ERR_LIMIT;
  }
  src = gdefstor_record_get(host->store, kInstallTenant, 1, kInstallType,
      strlen(kInstallType), name->text, name->len, &found, &bytes, &blen,
      NULL, NULL);
  if (src != GDEFSTOR_OK) {
    return map_stor(src);
  }
  if (!found) {
    return GDEFCORE_ERR_CORRUPT;
  }
  rc = rec_copy(bytes, blen, "kind", 4, kind, sizeof kind, &kind_len, 1);
  if (rc == GDEFCORE_OK) {
    rc = rec_copy(bytes, blen, "token", 5, mod.token, sizeof mod.token,
        &mod.token_len, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = rec_copy(bytes, blen, "entered", 7, entered, sizeof entered,
        &entered_len, 0);
  }
  if (rc == GDEFCORE_OK && kind_len == 6 && memcmp(kind, "native", 6) == 0) {
    mod.native = 1;
    rc = rec_copy(bytes, blen, "path", 4, mod.path, sizeof mod.path,
        &mod.path_len, 1);
  }
  if (rc == GDEFCORE_OK) {
    /* What the install recorded, for a module that is not called again
     * (quarantined). Every install records it. */
    char schema[16];
    size_t schema_len = 0;
    rc = rec_copy(bytes, blen, "schema", 6, schema, sizeof schema, &schema_len,
        1);
    mod.schema = 0;
    if (rc == GDEFCORE_OK && schema_len == 0) {
      rc = GDEFCORE_ERR_CORRUPT;
    }
    if (rc == GDEFCORE_OK) {
      uint64_t v = 0;
      size_t i;
      for (i = 0; i < schema_len; i++) {
        if (schema[i] < '0' || schema[i] > '9' || v > UINT32_MAX / 10u) {
          rc = GDEFCORE_ERR_CORRUPT;
          break;
        }
        v = v * 10u + (uint64_t)(schema[i] - '0');
      }
      if (rc == GDEFCORE_OK && (v == 0 || v > UINT32_MAX)) {
        rc = GDEFCORE_ERR_CORRUPT;
      }
      if (rc == GDEFCORE_OK) {
        mod.schema = (uint32_t)v;
      }
    }
  }
  gdefstor_bytes_free(NULL, bytes);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (mod.native && entered_len == 1 && entered[0] == '1') {
    mod.quarantined = 1;
    mod.loaded = 0;
    return adopt(host, &mod);
  }
  if (mod.native) {
    rc = open_native(host, &mod);
    if (rc != GDEFCORE_OK) {
      mod.quarantined = 1;
      mod.loaded = 0;
      mod.entry = NULL;
      mod.have_library = 0;
      return adopt(host, &mod);
    }
    rc = call_entry(host, &mod);
    if (rc != GDEFCORE_OK) {
      clear_mod(&mod);
      return rc;
    }
  }
  return adopt(host, &mod);
}

GDEFCORE_Result gdefcore_host_open(GDEFSTOR_Store * store,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Host ** out_host) {
  GDEFCORE_Host * host;
  Name names[kModMax];
  size_t nnames = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (store == NULL || out_host == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  allocator = use_alloc(allocator);
  host = (GDEFCORE_Host *)gcu_allocator_malloc(allocator, sizeof *host);
  if (host == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(host, 0, sizeof *host);
  host->store = store;
  host->alloc = allocator;
  rc = load_names(host, kInstallTenant, 1, kInstallType, names, kModMax,
      &nnames);
  for (i = 0; rc == GDEFCORE_OK && i < nnames; i++) {
    rc = reload_one(host, &names[i]);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_host_destroy(host);
    return rc;
  }
  *out_host = host;
  return GDEFCORE_OK;
}

void gdefcore_host_destroy(GDEFCORE_Host * host) {
  size_t i;
  if (host == NULL) {
    return;
  }
  for (i = 0; i < host->nmods; i++) {
    close_mod(&host->mods[i]);
    gdefcore_decl_free(host->mods[i].decl);
  }
  while (host->retired != NULL) {
    Decl * next = host->retired->next;
    gdefcore_decl_free(host->retired);
    host->retired = next;
  }
  gcu_allocator_free(host->alloc, host);
}

GDEFCORE_Result gdefcore_module_install_native(GDEFCORE_Host * host,
    const char * path, int full_trust) {
  Mod mod;
  size_t path_len;
  GDEFCORE_Result rc;
  if (host == NULL || path == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  set_error(host, NULL);
  if (full_trust != GDEFCORE_MODULE_TRUST_FULL) {
    set_error(host, "Native install requires full trust.");
    return GDEFCORE_ERR_INVALID;
  }
  path_len = strlen(path);
  if (path_len == 0 || path_len >= kPathMax) {
    return path_len == 0 ? GDEFCORE_ERR_INVALID : GDEFCORE_ERR_LIMIT;
  }
  memset(&mod, 0, sizeof mod);
  memcpy(mod.path, path, path_len);
  mod.path[path_len] = '\0';
  mod.path_len = path_len;
  mod.native = 1;
  rc = open_native(host, &mod);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = call_entry(host, &mod);
  if (rc != GDEFCORE_OK) {
    clear_mod(&mod);
    return rc;
  }
  if (find_mod(host, mod.name, mod.name_len) != NULL) {
    clear_mod(&mod);
    set_error(host, "Module is already installed.");
    return GDEFCORE_ERR_INVALID;
  }
  rc = store_install(host, &mod);
  if (rc != GDEFCORE_OK) {
    clear_mod(&mod);
    return rc;
  }
  rc = adopt(host, &mod);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  set_error(host, NULL);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_install_guest(GDEFCORE_Host * host,
    GDEFCORE_Module_Entry entry) {
  Mod mod;
  GDEFCORE_Result rc;
  if (host == NULL || entry == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  set_error(host, NULL);
  memset(&mod, 0, sizeof mod);
  mod.entry = entry;
  mod.native = 0;
  rc = call_entry(host, &mod);
  if (rc != GDEFCORE_OK) {
    clear_mod(&mod);
    return rc;
  }
  {
    Mod * existing = find_mod(host, mod.name, mod.name_len);
    if (existing != NULL) {
      if (!existing->native && existing->entry == NULL) {
        retire_decl(host, existing->decl);
        *existing = mod;
        existing->used = 1;
        set_error(host, NULL);
        return GDEFCORE_OK;
      }
      clear_mod(&mod);
      set_error(host, "Module is already installed.");
      return GDEFCORE_ERR_INVALID;
    }
  }
  rc = store_install(host, &mod);
  if (rc != GDEFCORE_OK) {
    clear_mod(&mod);
    return rc;
  }
  rc = adopt(host, &mod);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  set_error(host, NULL);
  return GDEFCORE_OK;
}

static GDEFCORE_Result stage_named(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len,
    int enable) {
  if (host == NULL || changeset == NULL || !name_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (find_mod(host, name, name_len) == NULL) {
    set_error(host, "Module is not installed.");
    return GDEFCORE_ERR_INVALID;
  }
  if (enable) {
    /* The module's own declarations, by themselves: a name outside its prefix,
     * a table that is malformed, a handler that is not its own. What they
     * refer to in other modules is judged when the changeset is applied,
     * against the site the whole changeset leaves, because the changeset may
     * enable the other module too, in whatever order. A refusal stages
     * nothing. */
    Name only[1];
    GDEFCORE_Result rc;
    memcpy(only[0].text, name, name_len);
    only[0].text[name_len] = '\0';
    only[0].len = name_len;
    rc = validate_declared(host, only, 1, 1);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  return gdefcore_changeset_stage_module(changeset, name, name_len, enable);
}

/*
 * What a permission label names, for a module that wants to grant it: the
 * module's own declaration, or the catalog's. @p owner is who declared it.
 * 1 when found, 0 when nothing declares it.
 */
typedef struct GrantTarget {
  char owner[161];
  char action[161];
  char type_name[161];
  size_t type_len;
  char field[161];
  size_t field_len;
} GrantTarget;

static int label_target(GDEFCORE_Host * host, GDEFCORE_Catalog * catalog,
    const Mod * mod, const char * permission, size_t permission_len,
    GrantTarget * t) {
  size_t i;
  GDEFCORE_Access_Permission info;
  size_t j;
  memset(t, 0, sizeof *t);
  for (i = 0; i < mod->nperms; i++) {
    if (mod->perms[i].label_len == permission_len &&
        memcmp(mod->perms[i].label, permission, permission_len) == 0) {
      memcpy(t->owner, mod->name, mod->name_len);
      memcpy(t->action, mod->perms[i].action, mod->perms[i].action_len);
      memcpy(t->type_name, mod->perms[i].type_name, mod->perms[i].type_len);
      t->type_len = mod->perms[i].type_len;
      memcpy(t->field, mod->perms[i].field, mod->perms[i].field_len);
      t->field_len = mod->perms[i].field_len;
      return 1;
    }
  }
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  if (gdefcore_access_permission_info(catalog, permission, permission_len,
          &info) == GDEFCORE_OK) {
    snprintf(t->owner, sizeof t->owner, "%s", info.module);
    snprintf(t->action, sizeof t->action, "%s", info.action);
    snprintf(t->type_name, sizeof t->type_name, "%s", info.type_name);
    t->type_len = strlen(t->type_name);
    snprintf(t->field, sizeof t->field, "%s", info.field);
    t->field_len = strlen(t->field);
    return 1;
  }
  /* Another installed module declares it, and has not been enabled yet. */
  for (i = 0; i < host->nmods; i++) {
    const Mod * other = &host->mods[i];
    if (!other->used || other == mod) {
      continue;
    }
    for (j = 0; j < other->nperms; j++) {
      if (other->perms[j].label_len == permission_len &&
          memcmp(other->perms[j].label, permission, permission_len) == 0) {
        memcpy(t->owner, other->name, other->name_len);
        memcpy(t->action, other->perms[j].action, other->perms[j].action_len);
        memcpy(t->type_name, other->perms[j].type_name,
            other->perms[j].type_len);
        t->type_len = other->perms[j].type_len;
        memcpy(t->field, other->perms[j].field, other->perms[j].field_len);
        t->field_len = other->perms[j].field_len;
        return 1;
      }
    }
  }
  return 0;
}

static int grant_target(GDEFCORE_Host * host, GDEFCORE_Catalog * catalog,
    const Mod * mod, const GDEFCORE_Module_Declared_Grant * g, GrantTarget * t) {
  return label_target(host, catalog, mod, g->permission, g->permission_len, t);
}

/*
 * The access callbacks a module registers, judged at enable as its grants
 * are: each names a permission the module may grant, on that permission's
 * type and field. A field callback's permission names the field; an
 * operation callback's names none and is not a row action, which is row
 * scope by another name. A refusal names the module and the callback, and
 * nothing has been staged.
 */
static GDEFCORE_Result check_callbacks(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const Mod * mod) {
  const Decl * d = mod->decl;
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(changeset);
  size_t i;
  if (d == NULL || d->ncallbacks == 0) {
    return GDEFCORE_OK;
  }
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < d->ncallbacks; i++) {
    const GDEFCORE_Module_Declared_Callback * c = &d->callbacks[i].pub;
    GrantTarget t;
    char text[kErrorMax];
    const char * why = NULL;
    if (!label_target(host, catalog, mod, c->permission, c->permission_len,
            &t)) {
      why = "which no module or the kernel declares";
    } else if (strcmp(t.owner, mod->name) != 0 &&
               strcmp(t.owner, "core") != 0) {
      why = "which another module declares";
    } else if (t.type_len != c->type_name_len ||
               memcmp(t.type_name, c->type_name, c->type_name_len) != 0 ||
               t.field_len != c->field_len ||
               memcmp(t.field, c->field, c->field_len) != 0) {
      why = "on a type or field other than the one the permission declares";
    } else if (c->scope == GDEFCORE_CALLBACK_OPERATION &&
               gdefcore_access_row_action(t.action, strlen(t.action))) {
      why = "whose action decides whether an entity is seen, listed or "
            "counted: that is row scope, decided by conditions only";
    }
    if (why != NULL) {
      snprintf(text, sizeof text,
          "Module %s access callback %.*s grants permission %.*s, %s.",
          mod->name, (int)c->name_len, c->name, (int)c->permission_len,
          c->permission, why);
      set_error(host, text);
      return GDEFCORE_ERR_INVALID;
    }
  }
  return GDEFCORE_OK;
}

/*
 * The grants a module declares, judged against the site as it is now: each
 * names a permission the module may grant (its own, or the kernel's, never
 * another module's: AD-35), on that permission's type and field, under a
 * condition that is valid for the type. A grant that fails refuses the
 * enable; the host's error names the module and the grant, and nothing has
 * been staged.
 */
static GDEFCORE_Result check_grants(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const Mod * mod, int * out_has) {
  const Decl * d = mod->decl;
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(changeset);
  size_t i;
  *out_has = d != NULL && d->ngrants > 0;
  if (!*out_has) {
    return GDEFCORE_OK;
  }
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < d->ngrants; i++) {
    const GDEFCORE_Module_Declared_Grant * g = &d->grants[i].pub;
    GrantTarget t;
    GDEFCORE_Condition * cond = NULL;
    GDEFCORE_Condition_Error err;
    GDEFCORE_Result rc;
    char text[kErrorMax];
    if (!grant_target(host, catalog, mod, g, &t)) {
      snprintf(text, sizeof text,
          "Module %s grants permission %.*s, which no module or the kernel "
          "declares.",
          mod->name, (int)g->permission_len, g->permission);
      set_error(host, text);
      return GDEFCORE_ERR_INVALID;
    }
    if (strcmp(t.owner, mod->name) != 0 && strcmp(t.owner, "core") != 0) {
      snprintf(text, sizeof text,
          "Module %s grants permission %.*s, which module %s declares.",
          mod->name, (int)g->permission_len, g->permission, t.owner);
      set_error(host, text);
      return GDEFCORE_ERR_INVALID;
    }
    if (t.type_len != g->type_name_len ||
        memcmp(t.type_name, g->type_name, g->type_name_len) != 0 ||
        t.field_len != g->field_len ||
        memcmp(t.field, g->field, g->field_len) != 0) {
      snprintf(text, sizeof text,
          "Module %s grants permission %.*s on a type or field other than the "
          "one the permission declares.",
          mod->name, (int)g->permission_len, g->permission);
      set_error(host, text);
      return GDEFCORE_ERR_INVALID;
    }
    memset(&err, 0, sizeof err);
    err.size = sizeof err;
    rc = gdefcore_condition_parse(g->condition, g->condition_len, &cond, &err);
    if (rc == GDEFCORE_OK) {
      /* The condition may test this module's own relations, which are not
       * enabled yet: judge it against the site as this changeset would leave
       * it, the module included. The real changeset has not been touched. */
      GDEFCORE_Changeset * projected = NULL;
      size_t k;
      rc = gdefcore_changeset_prepare(catalog, NULL, 0, &projected);
      for (k = 0; rc == GDEFCORE_OK && k < gdefcore_changeset_module_count(changeset);
           k++) {
        const char * other = NULL;
        size_t other_len = 0;
        int enable = 0;
        if (gdefcore_changeset_module_at(changeset, k, &other, &other_len,
                &enable) == GDEFCORE_OK) {
          rc = gdefcore_changeset_stage_module(projected, other, other_len, enable);
        }
      }
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_changeset_stage_module(projected, mod->name, mod->name_len, 1);
      }
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_condition_validate_in(catalog, cond, g->type_name,
            g->type_name_len, projected, &err);
      }
      gdefcore_changeset_destroy(projected);
    }
    gdefcore_condition_free(cond);
    if (rc != GDEFCORE_OK) {
      if (rc == GDEFCORE_ERR_INVALID) {
        snprintf(text, sizeof text,
            "Module %s grants permission %.*s under a condition that is not "
            "valid: %s (byte %zu).",
            mod->name, (int)g->permission_len, g->permission,
            err.message == NULL ? "refused" : err.message, err.offset);
        set_error(host, text);
      }
      return rc;
    }
  }
  return GDEFCORE_OK;
}

/*
 * The relations a module declares, judged against the site as it is now: an
 * entity column that names a type names one that is defined, or one in the
 * module's own namespace (which the module defines when it runs). Nothing is
 * staged when one fails.
 */
static GDEFCORE_Result check_relations(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const Mod * mod) {
  const Decl * d = mod->decl;
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(changeset);
  size_t i;
  size_t c;
  if (d == NULL || d->nrelations == 0) {
    return GDEFCORE_OK;
  }
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < d->nrelations; i++) {
    const GDEFCORE_Module_Declared_Relation * r = &d->relations[i].pub;
    for (c = 0; c < r->ncolumns; c++) {
      const GDEFCORE_Module_Relation_Column * col = &r->columns[c];
      int kind = 0;
      int own = col->type_name_len > mod->name_len &&
                memcmp(col->type_name, mod->name, mod->name_len) == 0 &&
                col->type_name[mod->name_len] == '.';
      char text[kErrorMax];
      if (col->type_name_len == 0 || own ||
          gdefcore_type_kind(catalog, col->type_name, col->type_name_len,
              &kind) == GDEFCORE_OK) {
        continue;
      }
      snprintf(text, sizeof text,
          "Module %s relation %.*s column %.*s refers to type %.*s, which is "
          "not defined and not in the module's own namespace.",
          mod->name, (int)r->name_len, r->name, (int)col->name_len, col->name,
          (int)col->type_name_len, col->type_name);
      set_error(host, text);
      return GDEFCORE_ERR_INVALID;
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_enable(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len) {
  Mod * mod;
  size_t i;
  int has_grants = 0;
  GDEFCORE_Result rc;
  mod = (host == NULL || name == NULL) ? NULL : find_mod(host, name, name_len);
  if (mod != NULL && changeset != NULL) {
    rc = check_relations(host, changeset, mod);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = check_grants(host, changeset, mod, &has_grants);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = check_callbacks(host, changeset, mod);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  rc = stage_named(host, changeset, name, name_len, 1);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  mod = find_mod(host, name, name_len);
  if (mod == NULL) {
    return GDEFCORE_OK;
  }
  for (i = 0; has_grants && i < mod->decl->ngrants; i++) {
    const GDEFCORE_Module_Declared_Grant * g = &mod->decl->grants[i].pub;
    GrantTarget t;
    if (!grant_target(host, gdefcore_changeset_catalog(changeset), mod, g, &t)) {
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_access_stage_module_grant(changeset, name, name_len,
        g->permission, g->permission_len, t.action, strlen(t.action),
        g->type_name, g->type_name_len, g->field, g->field_len, g->condition,
        g->condition_len);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  for (i = 0; mod->decl != NULL && i < mod->decl->ncallbacks; i++) {
    const GDEFCORE_Module_Declared_Callback * c = &mod->decl->callbacks[i].pub;
    GrantTarget t;
    if (!label_target(host, gdefcore_changeset_catalog(changeset), mod,
            c->permission, c->permission_len, &t)) {
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_access_stage_module_callback(changeset, name, name_len,
        c->name, c->name_len, c->scope, c->permission, c->permission_len,
        t.action, strlen(t.action), c->type_name, c->type_name_len, c->field,
        c->field_len);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  for (i = 0; i < mod->nperms; i++) {
    rc = gdefcore_access_stage_module_permission(changeset, name, name_len,
        mod->perms[i].label, mod->perms[i].label_len, mod->perms[i].action,
        mod->perms[i].action_len, mod->perms[i].condition,
        mod->perms[i].type_name, mod->perms[i].type_len,
        mod->perms[i].field_len == 0 ? NULL : mod->perms[i].field,
        mod->perms[i].field_len);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_disable(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len) {
  return stage_named(host, changeset, name, name_len, 0);
}

static GDEFCORE_Result enabled_names(GDEFCORE_Host * host, const uint8_t * tenant,
    size_t tenant_len, Name * names, size_t * out_n) {
  if (tenant == NULL || tenant_len == 0 || tenant_len > kTenantMax) {
    return GDEFCORE_ERR_INVALID;
  }
  return load_names(host, (const char *)tenant, tenant_len, kEnabledType, names,
      kModMax, out_n);
}

static const Mod * find_const(const GDEFCORE_Host * host, const char * name,
    size_t name_len) {
  size_t i;
  for (i = 0; host != NULL && i < host->nmods; i++) {
    const Mod * mod = &host->mods[i];
    if (mod->used && mod->name_len == name_len &&
        memcmp(mod->name, name, name_len) == 0) {
      return mod;
    }
  }
  return NULL;
}

static int is_core(const char * name, size_t name_len) {
  return name_len == strlen(GDEFCORE_SCHEMA_CORE) &&
         memcmp(name, GDEFCORE_SCHEMA_CORE, name_len) == 0;
}

GDEFCORE_Result gdefcore_module_schema(const GDEFCORE_Host * host,
    const char * name, size_t name_len, uint32_t * out_version) {
  const Mod * mod;
  if (out_version == NULL || name == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (is_core(name, name_len)) {
    *out_version = GDEFCORE_SCHEMA_VERSION;
    return GDEFCORE_OK;
  }
  mod = find_const(host, name, name_len);
  if (mod == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_version = mod->schema;
  return GDEFCORE_OK;
}

/* A step (@p ups 0) or an upcaster of component @p name from @p from. Core
 * declares neither at its version 1. */
static GDEFCORE_Result find_step(const GDEFCORE_Host * host, const char * name,
    size_t name_len, uint32_t from, int ups, const Step ** out) {
  const Mod * mod;
  const Step * v;
  size_t n;
  size_t i;
  *out = NULL;
  if (name == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (is_core(name, name_len)) {
    return GDEFCORE_OK;
  }
  mod = find_const(host, name, name_len);
  if (mod == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (mod->quarantined) {
    return GDEFCORE_OK;
  }
  v = ups ? mod->ups : mod->steps;
  n = ups ? mod->nups : mod->nsteps;
  for (i = 0; i < n; i++) {
    if (v[i].from == from) {
      *out = &v[i];
      break;
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_step(const GDEFCORE_Host * host,
    const char * name, size_t name_len, uint32_t from,
    GDEFCORE_Step_Fn * out_fn, void ** out_user) {
  const Step * st = NULL;
  GDEFCORE_Result rc;
  if (out_fn == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_step(host, name, name_len, from, 0, &st);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_fn = st == NULL ? NULL : st->step;
  if (out_user != NULL) {
    *out_user = st == NULL ? NULL : st->user;
  }
  return GDEFCORE_OK;
}

size_t gdefcore_module_upcaster_count(const GDEFCORE_Host * host,
    const char * name, size_t name_len) {
  const Mod * mod;
  if (name == NULL || is_core(name, name_len)) {
    return 0;
  }
  mod = find_const(host, name, name_len);
  return mod == NULL || mod->quarantined ? 0 : mod->nups;
}

GDEFCORE_Result gdefcore_module_upcaster(const GDEFCORE_Host * host,
    const char * name, size_t name_len, uint32_t from,
    GDEFCORE_Upcast_Fn * out_fn, void ** out_user) {
  const Step * st = NULL;
  GDEFCORE_Result rc;
  if (out_fn == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_step(host, name, name_len, from, 1, &st);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_fn = st == NULL ? NULL : st->up;
  if (out_user != NULL) {
    *out_user = st == NULL ? NULL : st->user;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_enabled(GDEFCORE_Host * host,
    GDEFCORE_Request * request, const char * name, size_t name_len,
    int * out_enabled) {
  const uint8_t * tenant;
  size_t tenant_len = 0;
  Name names[kModMax];
  size_t nnames = 0;
  Mod * mod;
  GDEFCORE_Result rc;
  if (host == NULL || request == NULL || out_enabled == NULL ||
      !name_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  tenant = gdefcore_request_tenant(request, &tenant_len);
  rc = enabled_names(host, tenant, tenant_len, names, &nnames);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  mod = find_mod(host, name, name_len);
  *out_enabled = name_has(names, nnames, name, name_len) && mod != NULL &&
                 !mod->quarantined && (mod->native || mod->entry != NULL);
  return GDEFCORE_OK;
}

/* A dotted Tang identifier path: `m.count`, `m.a.b`. */
static int path_ok(const char * s, size_t n) {
  size_t i;
  int start = 1;
  if (s == NULL || n == 0 || n > kNameMax) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (c == '.') {
      if (start || i + 1 == n) {
        return 0;
      }
      start = 1;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
            (!start && c >= '0' && c <= '9'))) {
      return 0;
    }
    start = 0;
  }
  return 1;
}

/* Whether `name` is `<module>.<something>`, a hyphen of the module spelled _. */
static int under_module(const char * name, size_t n, const char * module,
    size_t mlen) {
  size_t i;
  if (n <= mlen + 1 || name[mlen] != '.') {
    return 0;
  }
  for (i = 0; i < mlen; i++) {
    char want = module[i] == '-' ? '_' : module[i];
    if (name[i] != want) {
      return 0;
    }
  }
  return 1;
}

static void set_error2(GDEFCORE_Host * host, const char * a, const char * b,
    const char * c, const char * d, const char * e) {
  char text[kErrorMax];
  int n = snprintf(text, sizeof text, "%s%s%s%s%s", a, b, c, d, e);
  if (n < 0) {
    text[0] = '\0';
  }
  set_error(host, text);
}

GDEFCORE_Result gdefcore_module_contribute(GDEFCORE_Host * host,
    const char * module, size_t module_len,
    const GDEFCORE_Module_Contribution * c) {
  Contrib * slot;
  Mod * mod;
  size_t i;
  if (host == NULL || c == NULL || c->size < sizeof *c || c->kind == NULL ||
      c->name == NULL || c->type == NULL || c->provider == NULL ||
      !name_ok(module, module_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  mod = find_mod(host, module, module_len);
  if (mod == NULL) {
    set_error(host, "Module is not installed.");
    return GDEFCORE_ERR_INVALID;
  }
  if (!path_ok(c->kind, c->kind_len) || !path_ok(c->name, c->name_len) ||
      !under_module(c->name, c->name_len, module, module_len) ||
      memchr(c->name + module_len + 1, '.', c->name_len - module_len - 1) !=
          NULL) {
    set_error2(host, "A contribution of ", mod->name, " must be named ",
        mod->name, ".<name>, letters, digits and underscore.");
    return GDEFCORE_ERR_INVALID;
  }
  if (!((c->type_len == 4 && memcmp(c->type, "text", 4) == 0) ||
          (c->type_len == 6 && memcmp(c->type, "markup", 6) == 0) ||
          (c->type_len == 6 && memcmp(c->type, "number", 6) == 0))) {
    set_error2(host, "A contributed variable is text, markup or number: ",
        mod->name, "", "", "");
    return GDEFCORE_ERR_INVALID;
  }
  if (c->description_len > kContribText ||
      (c->description == NULL && c->description_len != 0) ||
      (c->before_len > 0 && !name_ok(c->before, c->before_len)) ||
      (c->after_len > 0 && !name_ok(c->after, c->after_len))) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < host->ncontribs; i++) {
    const Contrib * old = &host->contribs[i];
    if (strlen(old->module) == module_len &&
        memcmp(old->module, module, module_len) == 0 &&
        strlen(old->kind) == c->kind_len &&
        memcmp(old->kind, c->kind, c->kind_len) == 0 &&
        strlen(old->name) == c->name_len &&
        memcmp(old->name, c->name, c->name_len) == 0) {
      set_error2(host, "Module ", old->module, " contributes ", old->name,
          " to the same kind twice.");
      return GDEFCORE_ERR_INVALID;
    }
  }
  if (host->ncontribs >= kContribMax) {
    set_error(host, "Too many contributions.");
    return GDEFCORE_ERR_LIMIT;
  }
  slot = &host->contribs[host->ncontribs];
  memset(slot, 0, sizeof *slot);
  memcpy(slot->module, module, module_len);
  memcpy(slot->kind, c->kind, c->kind_len);
  memcpy(slot->name, c->name, c->name_len);
  memcpy(slot->type, c->type, c->type_len);
  if (c->description_len > 0) {
    memcpy(slot->description, c->description, c->description_len);
  }
  if (c->before_len > 0) {
    memcpy(slot->before, c->before, c->before_len);
    slot->before_len = c->before_len;
  }
  if (c->after_len > 0) {
    memcpy(slot->after, c->after, c->after_len);
    slot->after_len = c->after_len;
  }
  slot->weight = c->weight;
  slot->pub.size = sizeof slot->pub;
  slot->pub.module = slot->module;
  slot->pub.module_len = module_len;
  slot->pub.kind = slot->kind;
  slot->pub.kind_len = c->kind_len;
  slot->pub.name = slot->name;
  slot->pub.name_len = c->name_len;
  slot->pub.type = slot->type;
  slot->pub.type_len = c->type_len;
  slot->pub.description = slot->description;
  slot->pub.description_len = c->description_len;
  slot->pub.provider = c->provider;
  slot->pub.user = c->user;
  slot->pub.principal_free = c->principal_free != 0;
  host->ncontribs += 1;
  set_error(host, NULL);
  return GDEFCORE_OK;
}

/* The enabled set the tenant has, then the projection's operations. */
static GDEFCORE_Result projected_names(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection, Name * names, size_t * n) {
  size_t i;
  size_t ops;
  GDEFCORE_Result rc = enabled_names(host, tenant, tenant_len, names, n);
  if (rc != GDEFCORE_OK || projection == NULL) {
    return rc;
  }
  ops = gdefcore_changeset_module_count(projection);
  for (i = 0; i < ops; i++) {
    const char * name = NULL;
    size_t len = 0;
    int enable = 0;
    if (gdefcore_changeset_module_at(projection, i, &name, &len, &enable) !=
        GDEFCORE_OK) {
      return GDEFCORE_ERR_INTERNAL;
    }
    if (enable) {
      rc = name_add(names, n, kModMax, name, len);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    } else {
      name_remove(names, n, name, len);
    }
  }
  return GDEFCORE_OK;
}

static int module_live(GDEFCORE_Host * host, const Name * names, size_t n,
    const char * module) {
  size_t len = strlen(module);
  Mod * mod = find_mod(host, module, len);
  return mod != NULL && name_has(names, n, module, len) && !mod->quarantined &&
         (mod->native || mod->entry != NULL);
}

static int span_is(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

/* Raw bytes, shorter first when one is a prefix of the other. */
static int span_cmp(const char * a, size_t an, const char * b, size_t bn) {
  size_t n = an < bn ? an : bn;
  int c = n == 0 ? 0 : memcmp(a, b, n);
  if (c != 0) {
    return c;
  }
  return an < bn ? -1 : (an > bn ? 1 : 0);
}

/*
 * The modules in force for @p names, in AD-10 order: a subscription that says
 * `before` or `after` against another module in force puts the two in that
 * order, and among modules nothing constrains the module name decides, as raw
 * bytes. Registration order never does. Hook orders are decided one hook at a
 * time, so two hooks can ask for opposite orders; the declarations take one
 * order for all of them, and where the relationships loop the lowest name
 * among the modules left goes first, which is a rule that does not depend on
 * how the host was built up.
 */
static int mod_name_less(const Mod * a, const Mod * b) {
  return span_cmp(a->name, a->name_len, b->name, b->name_len) < 0;
}

static size_t order_live(GDEFCORE_Host * host, const Name * names,
    size_t nnames, Mod ** out) {
  Mod * live[kModMax];
  unsigned char before[kModMax][kModMax];
  unsigned char done[kModMax];
  size_t n = 0;
  size_t i;
  size_t j;
  size_t k;
  size_t step;
  memset(before, 0, sizeof before);
  memset(done, 0, sizeof done);
  for (i = 0; i < host->nmods; i++) {
    Mod * mod = &host->mods[i];
    if (!mod->used || mod->quarantined || !(mod->native || mod->entry != NULL) ||
        !name_has(names, nnames, mod->name, mod->name_len)) {
      continue;
    }
    live[n++] = mod;
  }
  for (i = 0; i < n; i++) {
    for (k = 0; k < live[i]->nsubs; k++) {
      const Sub * sub = &live[i]->subs[k];
      for (j = 0; j < n; j++) {
        if (j == i) {
          continue;
        }
        if (sub->before_len > 0 &&
            span_is(sub->before, sub->before_len, live[j]->name,
                live[j]->name_len)) {
          before[i][j] = 1;
        }
        if (sub->after_len > 0 &&
            span_is(sub->after, sub->after_len, live[j]->name,
                live[j]->name_len)) {
          before[j][i] = 1;
        }
      }
    }
  }
  for (step = 0; step < n; step++) {
    int pick = -1;
    int lowest = -1;
    for (i = 0; i < n; i++) {
      int ready = 1;
      if (done[i]) {
        continue;
      }
      for (j = 0; j < n; j++) {
        if (!done[j] && j != i && before[j][i]) {
          ready = 0;
        }
      }
      if (ready && (pick < 0 || mod_name_less(live[i], live[pick]))) {
        pick = (int)i;
      }
      if (lowest < 0 || mod_name_less(live[i], live[lowest])) {
        lowest = (int)i;
      }
    }
    if (pick < 0) {
      pick = lowest;
    }
    done[pick] = 1;
    out[step] = live[pick];
  }
  return n;
}

/* The declarations of the modules in force, in module order. Free the array
 * with the host allocator. */
static GDEFCORE_Result decl_refs(GDEFCORE_Host * host, const Name * names,
    size_t nnames, DeclRef ** out, size_t * out_n) {
  Mod * ordered[kModMax];
  size_t n = order_live(host, names, nnames, ordered);
  size_t i;
  size_t at = 0;
  DeclRef * refs =
      (DeclRef *)gcu_allocator_calloc(host->alloc, n + 1, sizeof *refs);
  if (refs == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    if (ordered[i]->decl != NULL) {
      refs[at++].decl = ordered[i]->decl;
    }
  }
  *out = refs;
  *out_n = at;
  return GDEFCORE_OK;
}

static GDEFCORE_Result enumerate_refs(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection, DeclRef ** refs, size_t * n) {
  Name names[kModMax];
  size_t nnames = 0;
  GDEFCORE_Result rc;
  *refs = NULL;
  *n = 0;
  if (host == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = projected_names(host, tenant, tenant_len, projection, names, &nnames);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return decl_refs(host, names, nnames, refs, n);
}

GDEFCORE_Result gdefcore_module_routes(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Route *** out_items, size_t * out_count) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_routes(host->alloc, refs, n, out_items, out_count);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

GDEFCORE_Result gdefcore_module_links(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Link *** out_items, size_t * out_count) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_links(host->alloc, refs, n, out_items, out_count);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

GDEFCORE_Result gdefcore_module_settings(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Setting *** out_items, size_t * out_count) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_settings(host->alloc, refs, n, out_items, out_count);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

GDEFCORE_Result gdefcore_module_variables(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Contributed *** out_items, size_t * out_count) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_variables(host->alloc, refs, n, out_items, out_count);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

GDEFCORE_Result gdefcore_module_grants(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Grant *** out_items, size_t * out_count) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_grants(host->alloc, refs, n, out_items, out_count);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

GDEFCORE_Result gdefcore_module_relations(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Relation *** out_items, size_t * out_count) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_relations(host->alloc, refs, n, out_items, out_count);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

GDEFCORE_Result gdefcore_module_callbacks(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Callback *** out_items, size_t * out_count) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  if (host == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  {
    /* Access asks this on every decision: when nothing installed registers
     * a callback, the answer needs no read of the store. */
    size_t k;
    int any = 0;
    for (k = 0; k < host->nmods && !any; k++) {
      any = host->mods[k].used && host->mods[k].decl != NULL &&
            host->mods[k].decl->ncallbacks > 0;
    }
    if (!any) {
      return GDEFCORE_OK;
    }
  }
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_callbacks(host->alloc, refs, n, out_items, out_count);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

/* Whether @p d registers a field callback on (type, field); its locked flag
 * in @p locked. */
static int decl_governs(const Decl * d, const char * type, size_t type_len,
    const char * field, size_t field_len, int * locked) {
  size_t i;
  int found = 0;
  for (i = 0; d != NULL && i < d->ncallbacks; i++) {
    const GDEFCORE_Module_Declared_Callback * c = &d->callbacks[i].pub;
    if (c->scope == GDEFCORE_CALLBACK_FIELD && c->type_name_len == type_len &&
        memcmp(c->type_name, type, type_len) == 0 &&
        c->field_len == field_len &&
        memcmp(c->field, field, field_len) == 0) {
      found = 1;
      if ((c->flags & GDEFCORE_CALLBACK_LOCKED) != 0) {
        *locked = 1;
      }
    }
  }
  return found;
}

int gdefcore_module_field_governed(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, const char * type_name,
    size_t type_name_len, const char * field, size_t field_len,
    int * out_locked) {
  DeclRef * refs = NULL;
  size_t n = 0;
  size_t i;
  int any = 0;
  int ignored = 0;
  int governed = 0;
  int locked = 0;
  if (out_locked != NULL) {
    *out_locked = 0;
  }
  if (host == NULL || type_name == NULL || field == NULL || field_len == 0) {
    return 0;
  }
  /* Nothing installed registers one: no read of the store. */
  for (i = 0; i < host->nmods && !any; i++) {
    any = host->mods[i].used &&
          decl_governs(host->mods[i].decl, type_name, type_name_len, field,
              field_len, &ignored);
  }
  if (!any) {
    return 0;
  }
  if (enumerate_refs(host, tenant, tenant_len, NULL, &refs, &n) !=
      GDEFCORE_OK) {
    /* Unknown is governed: refused, never probed. */
    return 1;
  }
  for (i = 0; i < n; i++) {
    governed |= decl_governs(refs[i].decl, type_name, type_name_len, field,
        field_len, &locked);
  }
  gcu_allocator_free(host->alloc, refs);
  if (out_locked != NULL) {
    *out_locked = governed && locked;
  }
  return governed;
}

void gdefcore_module_declared_free(GDEFCORE_Host * host, const void * items) {
  if (host != NULL && items != NULL) {
    gcu_allocator_free(host->alloc, (void *)items);
  }
}

GDEFCORE_Result gdefcore_module_add_routes(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection, GDEFCORE_Routes * routes,
    char ** out_error, size_t * out_error_len) {
  DeclRef * refs;
  size_t n;
  GDEFCORE_Result rc;
  if (out_error != NULL) {
    *out_error = NULL;
  }
  if (out_error_len != NULL) {
    *out_error_len = 0;
  }
  if (routes == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_add_routes(host->alloc, refs, n, routes, out_error,
      out_error_len, NULL, 0);
  gcu_allocator_free(host->alloc, refs);
  return rc;
}

/*
 * Whether the modules in @p names, taken together, declare a site that holds
 * together. The host's error names the entry and its module.
 */
static GDEFCORE_Result validate_declared(GDEFCORE_Host * host,
    const Name * names, size_t nnames, int local) {
  DeclRef * refs = NULL;
  size_t n = 0;
  size_t r;
  size_t v;
  size_t c;
  char text[kErrorMax];
  GDEFCORE_Result rc = decl_refs(host, names, nnames, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  text[0] = '\0';
  if (n > 0 && gdefcore_decl_validate(refs, n, local, text, sizeof text)) {
    set_error(host, text);
    gcu_allocator_free(host->alloc, refs);
    return GDEFCORE_ERR_INVALID;
  }
  /* A variable declared in a manifest and contributed in code is two
   * registrations of one name. */
  for (r = 0; r < n; r++) {
    const Decl * d = refs[r].decl;
    for (v = 0; v < d->nvars; v++) {
      const GDEFCORE_Module_Contributed * var = &d->vars[v].pub;
      for (c = 0; c < host->ncontribs; c++) {
        const Contrib * old = &host->contribs[c];
        if (span_is(old->module, strlen(old->module), var->module,
                var->module_len) &&
            span_is(old->kind, strlen(old->kind), var->kind, var->kind_len) &&
            span_is(old->name, strlen(old->name), var->name, var->name_len)) {
          set_error2(host, "Module ", d->module, ": template variable ",
              old->name, " is declared in the manifest and also contributed in "
                         "code.");
          gcu_allocator_free(host->alloc, refs);
          return GDEFCORE_ERR_INVALID;
        }
      }
    }
  }
  gcu_allocator_free(host->alloc, refs);
  return GDEFCORE_OK;
}

/* A candidate of one kind: a contribution registered in code or declared in a
 * manifest, as the ordering sees it. */
typedef struct CNode {
  const GDEFCORE_Module_Contributed * pub;
  int weight;
  const char * before;
  size_t before_len;
  const char * after;
  size_t after_len;
  int indeg;
  int emitted;
} CNode;

GDEFCORE_Result gdefcore_module_contributions(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection, const char * kind, size_t kind_len,
    const GDEFCORE_Module_Contributed *** out_items, size_t * out_count) {
  Name names[kModMax];
  size_t nnames = 0;
  CNode * nodes;
  unsigned char * adj;
  const GDEFCORE_Module_Contributed ** out;
  size_t bound;
  size_t n = 0;
  size_t emitted = 0;
  size_t i;
  size_t j;
  GDEFCORE_Result rc;
  if (host == NULL || kind == NULL || out_items == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_items = NULL;
  *out_count = 0;
  rc = projected_names(host, tenant, tenant_len, projection, names, &nnames);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  bound = host->ncontribs;
  for (i = 0; i < host->nmods; i++) {
    if (host->mods[i].used && host->mods[i].decl != NULL) {
      bound += host->mods[i].decl->nvars;
    }
  }
  nodes = (CNode *)gcu_allocator_calloc(host->alloc, bound + 1, sizeof *nodes);
  out = (const GDEFCORE_Module_Contributed **)gcu_allocator_calloc(host->alloc,
      bound + 1, sizeof *out);
  if (nodes == NULL || out == NULL) {
    gcu_allocator_free(host->alloc, nodes);
    gcu_allocator_free(host->alloc, out);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < host->ncontribs; i++) {
    const Contrib * c = &host->contribs[i];
    if (!span_is(c->kind, strlen(c->kind), kind, kind_len) ||
        !module_live(host, names, nnames, c->module)) {
      continue;
    }
    nodes[n].pub = &c->pub;
    nodes[n].weight = c->weight;
    nodes[n].before = c->before;
    nodes[n].before_len = c->before_len;
    nodes[n].after = c->after;
    nodes[n].after_len = c->after_len;
    n += 1;
  }
  /* What manifests declare: no weight and no relationships, so they order by
   * module name and, within a module, by kind and name. */
  for (i = 0; i < host->nmods; i++) {
    const Decl * d = host->mods[i].decl;
    if (!host->mods[i].used || d == NULL ||
        !module_live(host, names, nnames, host->mods[i].name)) {
      continue;
    }
    for (j = 0; j < d->nvars; j++) {
      const GDEFCORE_Module_Contributed * v = &d->vars[j].pub;
      if (!span_is(v->kind, v->kind_len, kind, kind_len)) {
        continue;
      }
      nodes[n].pub = v;
      nodes[n].before = "";
      nodes[n].after = "";
      n += 1;
    }
  }
  adj = (unsigned char *)gcu_allocator_calloc(host->alloc, n * n + 1, 1);
  if (adj == NULL) {
    gcu_allocator_free(host->alloc, nodes);
    gcu_allocator_free(host->alloc, out);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    for (j = 0; j < n; j++) {
      const CNode * a = &nodes[i];
      const CNode * b = &nodes[j];
      if (i == j || span_is(a->pub->module, a->pub->module_len, b->pub->module,
                        b->pub->module_len)) {
        continue;
      }
      /* a runs first when it says before b, or b says after a. */
      if (span_is(a->before, a->before_len, b->pub->module,
              b->pub->module_len) ||
          span_is(b->after, b->after_len, a->pub->module, a->pub->module_len)) {
        if (!adj[i * n + j]) {
          adj[i * n + j] = 1;
          nodes[j].indeg += 1;
        }
      }
    }
  }
  while (emitted < n) {
    int pick = -1;
    size_t s;
    for (i = 0; i < n; i++) {
      if (nodes[i].emitted || nodes[i].indeg != 0) {
        continue;
      }
      if (pick < 0) {
        pick = (int)i;
        continue;
      }
      if (nodes[i].weight < nodes[pick].weight) {
        pick = (int)i;
      } else if (nodes[i].weight == nodes[pick].weight) {
        int cmp = span_cmp(nodes[i].pub->module, nodes[i].pub->module_len,
            nodes[pick].pub->module, nodes[pick].pub->module_len);
        if (cmp < 0) {
          pick = (int)i;
        }
      }
    }
    if (pick < 0) {
      const GDEFCORE_Module_Contributed * first = NULL;
      const GDEFCORE_Module_Contributed * second = NULL;
      for (i = 0; i < n; i++) {
        if (nodes[i].emitted) {
          continue;
        }
        if (first == NULL) {
          first = nodes[i].pub;
        } else if (second == NULL &&
                   !span_is(first->module, first->module_len,
                       nodes[i].pub->module, nodes[i].pub->module_len)) {
          second = nodes[i].pub;
        }
      }
      set_error2(host, "Contribution order cycled between ",
          first == NULL ? "" : first->module, " and ",
          second == NULL ? "" : second->module, ".");
      gcu_allocator_free(host->alloc, adj);
      gcu_allocator_free(host->alloc, nodes);
      gcu_allocator_free(host->alloc, out);
      return GDEFCORE_ERR_INVALID;
    }
    nodes[pick].emitted = 1;
    out[emitted++] = nodes[pick].pub;
    for (s = 0; s < n; s++) {
      if (adj[(size_t)pick * n + s] && nodes[s].indeg > 0) {
        nodes[s].indeg -= 1;
      }
    }
  }
  gcu_allocator_free(host->alloc, adj);
  gcu_allocator_free(host->alloc, nodes);
  if (n == 0) {
    gcu_allocator_free(host->alloc, out);
    out = NULL;
  }
  *out_items = out;
  *out_count = n;
  return GDEFCORE_OK;
}

void gdefcore_module_contributions_free(GDEFCORE_Host * host,
    const GDEFCORE_Module_Contributed ** items) {
  if (host != NULL && items != NULL) {
    gcu_allocator_free(host->alloc, (void *)items);
  }
}

const char * gdefcore_module_notice(const GDEFCORE_Host * host,
    size_t * out_len) {
  if (host == NULL || host->notice_n == 0) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = host->notice_n;
  }
  return host->notice;
}

const char * gdefcore_module_error(const GDEFCORE_Host * host,
    size_t * out_len) {
  if (host == NULL || host->error_n == 0) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = host->error_n;
  }
  return host->error;
}

GDEFCORE_Result gdefcore_module_mark_entered(GDEFCORE_Host * host,
    const char * name, size_t name_len) {
  Mod * mod;
  GDEFCORE_Result rc;
  if (host == NULL || !name_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  mod = find_mod(host, name, name_len);
  if (mod == NULL || !mod->native) {
    set_error(host, "Entered record is for an installed native module.");
    return GDEFCORE_ERR_INVALID;
  }
  rc = persist_entered(host, mod, 1);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  mod->quarantined = 1;
  return GDEFCORE_OK;
}

const void * gdefcore_module_service(GDEFCORE_Host * host,
    GDEFCORE_Request * request, const char * name, size_t name_len,
    uint32_t version) {
  const uint8_t * tenant;
  size_t tenant_len = 0;
  Name enabled[kModMax];
  size_t nenabled = 0;
  size_t i;
  size_t s;
  if (host == NULL || request == NULL || !ident_ok(name, name_len)) {
    return NULL;
  }
  tenant = gdefcore_request_tenant(request, &tenant_len);
  if (enabled_names(host, tenant, tenant_len, enabled, &nenabled) !=
      GDEFCORE_OK) {
    return NULL;
  }
  for (i = 0; i < host->nmods; i++) {
    Mod * mod = &host->mods[i];
    if (!mod->used || mod->quarantined || !mod->loaded) {
      continue;
    }
    if (!name_has(enabled, nenabled, mod->name, mod->name_len)) {
      continue;
    }
    for (s = 0; s < mod->nservices; s++) {
      if (mod->services[s].name_len == name_len &&
          memcmp(mod->services[s].name, name, name_len) == 0 &&
          mod->services[s].version == version) {
        return mod->services[s].table;
      }
    }
  }
  return NULL;
}

void gdefcore_module_text_free(GDEFCORE_Host * host, char * text) {
  if (host == NULL) {
    return;
  }
  gcu_allocator_free(host->alloc, text);
}

static GDEFCORE_Result append_notice(GDEFCORE_Host * host, const char * name,
    const char * target) {
  char sentence[256];
  int wrote;
  size_t n;
  wrote = snprintf(sentence, sizeof sentence,
      "Module %s enhances %s, which is not installed.", name, target);
  if (wrote <= 0 || (size_t)wrote >= sizeof sentence) {
    return GDEFCORE_ERR_LIMIT;
  }
  n = (size_t)wrote;
  if (host->pending_n > 0) {
    if (host->pending_n + 1 + n >= sizeof host->pending) {
      return GDEFCORE_ERR_LIMIT;
    }
    host->pending[host->pending_n++] = '\n';
  } else if (n >= sizeof host->pending) {
    return GDEFCORE_ERR_LIMIT;
  }
  memcpy(host->pending + host->pending_n, sentence, n);
  host->pending_n += n;
  host->pending[host->pending_n] = '\0';
  return GDEFCORE_OK;
}

static GDEFCORE_Result resulting_set(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, GDEFCORE_Changeset * changeset,
    Name * names, size_t * out_n) {
  size_t count;
  size_t i;
  GDEFCORE_Result rc = enabled_names(host, tenant, tenant_len, names, out_n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  count = gdefcore_changeset_module_count(changeset);
  for (i = 0; i < count; i++) {
    const char * name = NULL;
    size_t name_len = 0;
    int enable = 0;
    rc = gdefcore_changeset_module_at(changeset, i, &name, &name_len, &enable);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (find_mod(host, name, name_len) == NULL) {
      set_error(host, "Module is not installed.");
      return GDEFCORE_ERR_INVALID;
    }
    if (enable) {
      rc = name_add(names, out_n, kModMax, name, name_len);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    } else {
      name_remove(names, out_n, name, name_len);
    }
  }
  return GDEFCORE_OK;
}

static int hook_kind(const Mod * mod, const char * hook, size_t hook_len,
    const Sub ** out) {
  size_t i;
  for (i = 0; i < mod->nsubs; i++) {
    if (mod->subs[i].hook_len == hook_len &&
        memcmp(mod->subs[i].hook, hook, hook_len) == 0) {
      *out = &mod->subs[i];
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result order_hook(GDEFCORE_Host * host, const Name * enabled,
    size_t nenabled, const char * hook, size_t hook_len) {
  typedef struct Node {
    const Mod * mod;
    const Sub * sub;
    int indeg;
    int nsucc;
    int succ[kNodeMax];
    int emitted;
  } Node;
  Node nodes[kNodeMax];
  size_t n = 0;
  size_t i;
  size_t emitted = 0;
  int kind = 0;
  memset(nodes, 0, sizeof nodes);
  for (i = 0; i < host->nmods; i++) {
    const Sub * sub = NULL;
    Mod * mod = &host->mods[i];
    if (!mod->used || !mod->loaded) {
      continue;
    }
    if (!name_has(enabled, nenabled, mod->name, mod->name_len)) {
      continue;
    }
    if (!hook_kind(mod, hook, hook_len, &sub)) {
      continue;
    }
    if (n == 0) {
      kind = sub->kind;
    } else if (sub->kind != kind) {
      set_error(host, "Subscribers disagree on the hook kind.");
      return GDEFCORE_ERR_INVALID;
    }
    if (n >= kNodeMax) {
      return GDEFCORE_ERR_LIMIT;
    }
    nodes[n].mod = mod;
    nodes[n].sub = sub;
    n += 1;
  }
  for (i = 0; i < n; i++) {
    size_t j;
    if (nodes[i].sub->after_len > 0) {
      for (j = 0; j < n; j++) {
        if (nodes[j].mod->name_len == nodes[i].sub->after_len &&
            memcmp(nodes[j].mod->name, nodes[i].sub->after, nodes[i].sub->after_len) ==
                0) {
          if (nodes[j].nsucc >= kNodeMax) {
            return GDEFCORE_ERR_LIMIT;
          }
          nodes[j].succ[nodes[j].nsucc++] = (int)i;
          nodes[i].indeg += 1;
        }
      }
    }
    if (nodes[i].sub->before_len > 0) {
      for (j = 0; j < n; j++) {
        if (nodes[j].mod->name_len == nodes[i].sub->before_len &&
            memcmp(nodes[j].mod->name, nodes[i].sub->before,
                nodes[i].sub->before_len) == 0) {
          if (nodes[i].nsucc >= kNodeMax) {
            return GDEFCORE_ERR_LIMIT;
          }
          nodes[i].succ[nodes[i].nsucc++] = (int)j;
          nodes[j].indeg += 1;
        }
      }
    }
  }
  while (emitted < n) {
    int pick = -1;
    size_t s;
    for (i = 0; i < n; i++) {
      if (nodes[i].emitted || nodes[i].indeg != 0) {
        continue;
      }
      if (pick < 0) {
        pick = (int)i;
        continue;
      }
      if (nodes[i].sub->weight < nodes[pick].sub->weight) {
        pick = (int)i;
        continue;
      }
      if (nodes[i].sub->weight == nodes[pick].sub->weight) {
        size_t na = nodes[i].mod->name_len;
        size_t nb = nodes[pick].mod->name_len;
        size_t m = na < nb ? na : nb;
        int cmp = memcmp(nodes[i].mod->name, nodes[pick].mod->name, m);
        if (cmp < 0 || (cmp == 0 && na < nb)) {
          pick = (int)i;
        }
      }
    }
    if (pick < 0) {
      Name left[kNodeMax];
      size_t nleft = 0;
      char message[kErrorMax];
      size_t at = 0;
      int wrote;
      for (i = 0; i < n; i++) {
        if (!nodes[i].emitted) {
          memset(&left[nleft], 0, sizeof left[nleft]);
          left[nleft].len = nodes[i].mod->name_len;
          memcpy(left[nleft].text, nodes[i].mod->name, left[nleft].len);
          left[nleft].text[left[nleft].len] = '\0';
          nleft += 1;
        }
      }
      if (nleft > 1) {
        qsort(left, nleft, sizeof left[0], cmp_name);
      }
      wrote = snprintf(message, sizeof message, "Hook cycle between");
      if (wrote < 0) {
        return GDEFCORE_ERR_LIMIT;
      }
      at = (size_t)wrote;
      for (i = 0; i < nleft && at + 1 < sizeof message; i++) {
        wrote = snprintf(message + at, sizeof message - at, "%s %s",
            i == 0 ? "" : " and", left[i].text);
        if (wrote < 0 || (size_t)wrote >= sizeof message - at) {
          return GDEFCORE_ERR_LIMIT;
        }
        at += (size_t)wrote;
      }
      if (at + 1 < sizeof message) {
        message[at++] = '.';
        message[at] = '\0';
      }
      set_error(host, message);
      return GDEFCORE_ERR_INVALID;
    }
    nodes[pick].emitted = 1;
    emitted += 1;
    for (s = 0; s < (size_t)nodes[pick].nsucc; s++) {
      int to = nodes[pick].succ[s];
      if (nodes[to].indeg > 0) {
        nodes[to].indeg -= 1;
      }
    }
  }
  (void)kind;
  return GDEFCORE_OK;
}

/* A quarantined install still has edges. Read them before the cycle check. */
static GDEFCORE_Result load_edges(GDEFCORE_Host * host, Mod * mod) {
  int was_quarantined;
  GDEFCORE_Result rc;
  if (mod->loaded) {
    return GDEFCORE_OK;
  }
  was_quarantined = mod->quarantined;
  if (mod->native && !mod->have_library) {
    if (mod->path_len == 0) {
      return GDEFCORE_OK;
    }
    rc = open_native(host, mod);
    if (rc != GDEFCORE_OK) {
      mod->quarantined = 1;
      mod->loaded = 0;
      mod->entry = NULL;
      mod->have_library = 0;
      return GDEFCORE_OK;
    }
  }
  if (mod->entry == NULL) {
    return GDEFCORE_OK;
  }
  rc = call_entry(host, mod);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (was_quarantined) {
    mod->quarantined = 1;
    return persist_entered(host, mod, 1);
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_vet(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, GDEFCORE_Changeset * changeset) {
  Name names[kModMax];
  size_t nnames = 0;
  size_t i;
  size_t h;
  char hooks[kNodeMax][kNameMax + 1];
  size_t hook_lens[kNodeMax];
  size_t nhooks = 0;
  GDEFCORE_Result rc;
  if (host == NULL || changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  set_error(host, NULL);
  host->pending_n = 0;
  host->pending[0] = '\0';
  host->pending_valid = 0;
  rc = resulting_set(host, tenant, tenant_len, changeset, names, &nnames);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < nnames; i++) {
    Mod * mod = find_mod(host, names[i].text, names[i].len);
    size_t r;
    if (mod == NULL) {
      set_error(host, "Module is not installed.");
      return GDEFCORE_ERR_INVALID;
    }
    if (!mod->loaded) {
      rc = load_edges(host, mod);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
    for (r = 0; r < mod->nrels; r++) {
      Mod * target = find_mod(host, mod->rels[r].name, mod->rels[r].name_len);
      int present = target != NULL && !target->quarantined &&
                     name_has(names, nnames, mod->rels[r].name,
                         mod->rels[r].name_len);
      if (mod->rels[r].kind == GDEFCORE_REL_REQUIRES) {
        if (!present) {
          snprintf(host->error, sizeof host->error,
              "Module %s requires %s, which is absent.", mod->name,
              mod->rels[r].name);
          host->error_n = strlen(host->error);
          return GDEFCORE_ERR_INVALID;
        }
      } else if (target == NULL) {
        rc = append_notice(host, mod->name, mod->rels[r].name);
        if (rc != GDEFCORE_OK) {
          return rc;
        }
      }
    }
    for (h = 0; h < mod->nsubs; h++) {
      size_t k;
      int seen = 0;
      for (k = 0; k < nhooks; k++) {
        if (hook_lens[k] == mod->subs[h].hook_len &&
            memcmp(hooks[k], mod->subs[h].hook, hook_lens[k]) == 0) {
          seen = 1;
        }
      }
      if (!seen) {
        if (nhooks >= kNodeMax) {
          return GDEFCORE_ERR_LIMIT;
        }
        memcpy(hooks[nhooks], mod->subs[h].hook, mod->subs[h].hook_len);
        hooks[nhooks][mod->subs[h].hook_len] = '\0';
        hook_lens[nhooks] = mod->subs[h].hook_len;
        nhooks += 1;
      }
    }
  }
  for (h = 0; h < nhooks; h++) {
    rc = order_hook(host, names, nnames, hooks[h], hook_lens[h]);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  rc = validate_declared(host, names, nnames, 0);
  if (rc != GDEFCORE_OK) {
    size_t text_len = 0;
    const char * text = gdefcore_module_error(host, &text_len);
    if (text != NULL) {
      (void)gdefcore_changeset_set_refusal(changeset, text, text_len);
    }
    return rc;
  }
  host->pending_valid = 1;
  return GDEFCORE_OK;
}

void gdefcore_module_clear_pending(GDEFCORE_Host * host) {
  if (host == NULL) {
    return;
  }
  host->pending_n = 0;
  host->pending[0] = '\0';
  host->pending_valid = 0;
}

GDEFCORE_Result gdefcore_module_write_enables(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, GDEFSTOR_Write * write,
    GDEFCORE_Changeset * changeset) {
  Name names[kModMax];
  size_t nnames = 0;
  size_t count;
  size_t i;
  GDEFCORE_Result rc;
  if (host == NULL || write == NULL || changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = resulting_set(host, tenant, tenant_len, changeset, names, &nnames);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* In the changeset's write, as records of the tenant: a module disabled
   * loses its record, and every module the set holds has one. */
  count = gdefcore_changeset_module_count(changeset);
  for (i = 0; i < count; i++) {
    const char * name = NULL;
    size_t name_len = 0;
    int enable = 0;
    rc = gdefcore_changeset_module_at(changeset, i, &name, &name_len, &enable);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (!enable) {
      rc = map_stor(gdefstor_record_delete(write, kEnabledType,
          strlen(kEnabledType), name, name_len, NULL));
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
  }
  /* Every module the set holds has its enabled record, and a record of where
   * its data stands (AD-15): one the tenant has already is where its data
   * is, and stays (a module enabled again, or one waiting for its migration);
   * a module whose data the tenant has never held is at the installed
   * version, which its writes will be in. */
  for (i = 0; i < nnames; i++) {
    const Mod * mod = find_mod(host, names[i].text, names[i].len);
    int found = 0;
    uint8_t * bytes = NULL;
    size_t blen = 0;
    rc = map_stor(gdefstor_record_put(write, kEnabledType, strlen(kEnabledType),
        names[i].text, names[i].len, kCoreStamp, strlen(kCoreStamp), NULL, 0));
    if (rc == GDEFCORE_OK) {
      rc = map_stor(gdefstor_record_get(host->store, (const char *)tenant,
          tenant_len, kSchemaType, strlen(kSchemaType), names[i].text,
          names[i].len, &found, &bytes, &blen, NULL, NULL));
      gdefstor_bytes_free(NULL, bytes);
    }
    if (rc == GDEFCORE_OK && !found) {
      char schema[16];
      int n = snprintf(schema, sizeof schema, "%lu",
          (unsigned long)(mod == NULL ? 0u : mod->schema));
      if (mod == NULL || n <= 0 || (size_t)n >= sizeof schema) {
        return GDEFCORE_ERR_INTERNAL;
      }
      rc = map_stor(gdefstor_record_put(write, kSchemaType,
          strlen(kSchemaType), names[i].text, names[i].len, kCoreStamp,
          strlen(kCoreStamp), (const uint8_t *)schema, (size_t)n));
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result activate(GDEFCORE_Host * host, Mod * mod) {
  GDEFCORE_Result rc;
  if (mod->native && !mod->have_library) {
    rc = open_native(host, mod);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  if (!mod->loaded) {
    rc = call_entry(host, mod);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  mod->enter_depth = 0;
  rc = persist_entered(host, mod, 0);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  mod->quarantined = 0;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_after_apply(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, GDEFCORE_Changeset * changeset) {
  size_t count;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  (void)tenant;
  (void)tenant_len;
  if (host == NULL || changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (host->pending_valid) {
    memcpy(host->notice, host->pending, host->pending_n);
    host->notice[host->pending_n] = '\0';
    host->notice_n = host->pending_n;
    host->pending_valid = 0;
    host->pending_n = 0;
  }
  count = gdefcore_changeset_module_count(changeset);
  for (i = 0; i < count; i++) {
    const char * name = NULL;
    size_t name_len = 0;
    int enable = 0;
    Mod * mod;
    rc = gdefcore_changeset_module_at(changeset, i, &name, &name_len, &enable);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    mod = find_mod(host, name, name_len);
    if (mod == NULL) {
      continue;
    }
    if (enable && mod->quarantined) {
      rc = activate(host, mod);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
  }
  host->nchains = 0;
  memset(host->chains, 0, sizeof host->chains);
  return GDEFCORE_OK;
}

static void drop_chains(GDEFCORE_Host * host) {
  host->nchains = 0;
  memset(host->chains, 0, sizeof host->chains);
}

static GDEFCORE_Result build_chain(GDEFCORE_Host * host, const uint8_t * tenant,
    size_t tenant_len, uint64_t epoch, const char * hook, size_t hook_len,
    Chain ** out) {
  Name enabled[kModMax];
  size_t nenabled = 0;
  typedef struct Node {
    Mod * mod;
    const Sub * sub;
    int indeg;
    int nsucc;
    int succ[kNodeMax];
    int emitted;
  } Node;
  Node nodes[kNodeMax];
  Chain * chain;
  size_t n = 0;
  size_t i;
  size_t emitted = 0;
  int kind = 0;
  GDEFCORE_Result rc;
  *out = NULL;
  if (hook_len == 0 || hook_len > kNameMax || tenant_len > kTenantMax) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = enabled_names(host, tenant, tenant_len, enabled, &nenabled);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(nodes, 0, sizeof nodes);
  for (i = 0; i < host->nmods; i++) {
    const Sub * sub = NULL;
    if (!host->mods[i].used || !host->mods[i].loaded ||
        host->mods[i].quarantined) {
      continue;
    }
    if (!name_has(enabled, nenabled, host->mods[i].name,
            host->mods[i].name_len)) {
      continue;
    }
    if (!hook_kind(&host->mods[i], hook, hook_len, &sub)) {
      continue;
    }
    if (n == 0) {
      kind = sub->kind;
    } else if (sub->kind != kind) {
      set_error(host, "Subscribers disagree on the hook kind.");
      return GDEFCORE_ERR_INVALID;
    }
    nodes[n].mod = &host->mods[i];
    nodes[n].sub = sub;
    n += 1;
  }
  for (i = 0; i < n; i++) {
    size_t j;
    if (nodes[i].sub->after_len > 0) {
      for (j = 0; j < n; j++) {
        if (nodes[j].mod->name_len == nodes[i].sub->after_len &&
            memcmp(nodes[j].mod->name, nodes[i].sub->after,
                nodes[i].sub->after_len) == 0) {
          nodes[j].succ[nodes[j].nsucc++] = (int)i;
          nodes[i].indeg += 1;
        }
      }
    }
    if (nodes[i].sub->before_len > 0) {
      for (j = 0; j < n; j++) {
        if (nodes[j].mod->name_len == nodes[i].sub->before_len &&
            memcmp(nodes[j].mod->name, nodes[i].sub->before,
                nodes[i].sub->before_len) == 0) {
          nodes[i].succ[nodes[i].nsucc++] = (int)j;
          nodes[j].indeg += 1;
        }
      }
    }
  }
  if (host->nchains >= kChainMax) {
    drop_chains(host);
  }
  chain = &host->chains[host->nchains];
  memset(chain, 0, sizeof *chain);
  chain->used = 1;
  memcpy(chain->tenant, tenant, tenant_len);
  chain->tenant_len = tenant_len;
  chain->epoch = epoch;
  memcpy(chain->hook, hook, hook_len);
  chain->hook[hook_len] = '\0';
  chain->hook_len = hook_len;
  chain->kind = kind;
  while (emitted < n) {
    int pick = -1;
    size_t s;
    for (i = 0; i < n; i++) {
      int better = 0;
      size_t m;
      int cmp;
      if (nodes[i].emitted || nodes[i].indeg != 0) {
        continue;
      }
      if (pick < 0) {
        pick = (int)i;
        continue;
      }
      if (nodes[i].sub->weight < nodes[pick].sub->weight) {
        better = 1;
      } else if (nodes[i].sub->weight == nodes[pick].sub->weight) {
        m = nodes[i].mod->name_len < nodes[pick].mod->name_len
                ? nodes[i].mod->name_len
                : nodes[pick].mod->name_len;
        cmp = memcmp(nodes[i].mod->name, nodes[pick].mod->name, m);
        if (cmp < 0 || (cmp == 0 &&
                           nodes[i].mod->name_len < nodes[pick].mod->name_len)) {
          better = 1;
        }
      }
      if (better) {
        pick = (int)i;
      }
    }
    if (pick < 0) {
      set_error(host, "Hook order cycled after enable.");
      return GDEFCORE_ERR_INVALID;
    }
    nodes[pick].emitted = 1;
    emitted += 1;
    chain->nodes[chain->n].name_len = nodes[pick].mod->name_len;
    memcpy(chain->nodes[chain->n].name, nodes[pick].mod->name,
        nodes[pick].mod->name_len);
    chain->nodes[chain->n].name[nodes[pick].mod->name_len] = '\0';
    chain->nodes[chain->n].fn = nodes[pick].sub->fn;
    chain->nodes[chain->n].user = nodes[pick].sub->user;
    chain->nodes[chain->n].access = nodes[pick].sub->access;
    chain->nodes[chain->n].native = nodes[pick].mod->native;
    chain->nodes[chain->n].mod_index = (int)(nodes[pick].mod - host->mods);
    chain->n += 1;
    for (s = 0; s < (size_t)nodes[pick].nsucc; s++) {
      int to = nodes[pick].succ[s];
      if (nodes[to].indeg > 0) {
        nodes[to].indeg -= 1;
      }
    }
  }
  host->nchains += 1;
  *out = chain;
  return GDEFCORE_OK;
}

static Chain * find_chain(GDEFCORE_Host * host, const uint8_t * tenant,
    size_t tenant_len, uint64_t epoch, const char * hook, size_t hook_len) {
  size_t i;
  for (i = 0; i < host->nchains; i++) {
    Chain * chain = &host->chains[i];
    if (!chain->used || chain->epoch != epoch || chain->tenant_len != tenant_len ||
        chain->hook_len != hook_len) {
      continue;
    }
    if (memcmp(chain->tenant, tenant, tenant_len) == 0 &&
        memcmp(chain->hook, hook, hook_len) == 0) {
      return chain;
    }
  }
  return NULL;
}

static int field_covers(size_t size, size_t end) {
  return size >= end;
}

static GDEFCORE_Result note_skip(GDEFCORE_Host * host, const char * name,
    size_t name_len) {
  if (host->skipped_n > 0) {
    if (host->skipped_n + 1 >= sizeof host->skipped) {
      return GDEFCORE_ERR_LIMIT;
    }
    host->skipped[host->skipped_n++] = '\n';
  }
  if (host->skipped_n + name_len >= sizeof host->skipped) {
    return GDEFCORE_ERR_LIMIT;
  }
  memcpy(host->skipped + host->skipped_n, name, name_len);
  host->skipped_n += name_len;
  host->skipped[host->skipped_n] = '\0';
  host->skipped_count += 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result call_subscriber(GDEFCORE_Host * host, ChainNode * node,
    GDEFCORE_Request * request, const void * args, GDEFCORE_Alter * alter,
    int * decision, int skip_soft) {
  GDEFCORE_Hook_Out out;
  GDEFCORE_Result rc;
  Mod * mod = NULL;
  int reported = GDEFCORE_DECISION_NONE;
  int access = 0;
  if (node->mod_index >= 0 && (size_t)node->mod_index < host->nmods) {
    mod = &host->mods[node->mod_index];
    if (mod->quarantined) {
      return GDEFCORE_OK;
    }
  }
  memset(&out, 0, sizeof out);
  out.size = sizeof out;
  {
    char * saved = NULL;
    size_t saved_len = 0;
    if (alter != NULL) {
      saved_len = alter->len;
      saved = gcu_allocator_malloc(host->alloc, saved_len + 1);
      if (saved == NULL) {
        return GDEFCORE_ERR_OOM;
      }
      if (saved_len > 0 && alter->text != NULL) {
        memcpy(saved, alter->text, saved_len);
      }
      saved[saved_len] = '\0';
    }
    if (mod != NULL && mod->native && mod->have_library) {
      rc = touch_entered(host, mod, 1);
      if (rc != GDEFCORE_OK) {
        gcu_allocator_free(host->alloc, saved);
        return rc;
      }
    }
    rc = node->fn(request, args, alter, &out, node->user);
    if (mod != NULL && mod->native && mod->have_library) {
      GDEFCORE_Result clear_rc = touch_entered(host, mod, 0);
      if (rc == GDEFCORE_OK) {
        rc = clear_rc;
      }
    }
    if (rc != GDEFCORE_OK && alter != NULL) {
      GDEFCORE_Result restore = gdefcore_alter_set(alter, saved, saved_len);
      gcu_allocator_free(host->alloc, saved);
      if (restore != GDEFCORE_OK) {
        return restore;
      }
    } else {
      gcu_allocator_free(host->alloc, saved);
    }
  }
  if (field_covers(out.size,
          offsetof(GDEFCORE_Hook_Out, decision) + sizeof(int))) {
    reported = out.decision;
  }
  if (field_covers(out.size, offsetof(GDEFCORE_Hook_Out, access) + sizeof(int))) {
    access = out.access;
  }
  if (access && !node->access) {
    set_error(host, "Access contribution was not declared.");
    return GDEFCORE_ERR_INVALID;
  }
  if (rc != GDEFCORE_OK) {
    if (!skip_soft || node->access) {
      return rc;
    }
    return note_skip(host, node->name, node->name_len);
  }
  if (reported == GDEFCORE_DECISION_ALLOW ||
      reported == GDEFCORE_DECISION_DENY) {
    *decision = reported;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result fire_at(GDEFCORE_Host * host, GDEFCORE_Request * request,
    GDEFCORE_Catalog * catalog, const char * hook, size_t hook_len, int kind,
    const void * args, GDEFCORE_Alter * alter, int * out_decision,
    int skip_soft, int * out_deny_vote) {
  const uint8_t * tenant;
  size_t tenant_len = 0;
  uint64_t epoch = 0;
  Chain * chain;
  size_t i;
  int any_deny = 0;
  int any_allow = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (out_deny_vote != NULL) {
    *out_deny_vote = 0;
  }
  if (host == NULL || request == NULL || catalog == NULL || hook == NULL ||
      hook_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (kind == GDEFCORE_HOOK_DECISION && out_decision == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (host->firing) {
    return GDEFCORE_ERR_INVALID;
  }
  host->firing = 1;
  host->skipped_n = 0;
  host->skipped[0] = '\0';
  host->skipped_count = 0;
  if (kind == GDEFCORE_HOOK_ALTER && alter == NULL) {
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  tenant = gdefcore_request_tenant(request, &tenant_len);
  {
    size_t cat_len = 0;
    const uint8_t * cat_tenant = gdefcore_catalog_tenant(catalog, &cat_len);
    if (tenant == NULL || cat_tenant == NULL || tenant_len != cat_len ||
        memcmp(tenant, cat_tenant, tenant_len) != 0) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
  }
  rc = gdefcore_epoch(catalog, &epoch);
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  chain = find_chain(host, tenant, tenant_len, epoch, hook, hook_len);
  if (chain == NULL) {
    rc = build_chain(host, tenant, tenant_len, epoch, hook, hook_len, &chain);
    if (rc != GDEFCORE_OK) {
      goto done;
    }
  }
  if (chain->n == 0) {
    if (kind == GDEFCORE_HOOK_DECISION) {
      *out_decision = GDEFCORE_DECISION_DENY;
    }
    rc = GDEFCORE_OK;
    goto done;
  }
  if (chain->kind != kind) {
    set_error(host, "Hook kind does not match its subscribers.");
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  for (i = 0; i < chain->n; i++) {
    int vote = GDEFCORE_DECISION_NONE;
    rc = call_subscriber(host, &chain->nodes[i], request, args, alter, &vote,
        kind == GDEFCORE_HOOK_DECISION ? 0 : skip_soft);
    if (rc != GDEFCORE_OK) {
      goto done;
    }
    if (vote == GDEFCORE_DECISION_DENY) {
      any_deny = 1;
    } else if (vote == GDEFCORE_DECISION_ALLOW) {
      any_allow = 1;
    }
  }
  if (out_deny_vote != NULL) {
    *out_deny_vote = any_deny;
  }
  if (kind == GDEFCORE_HOOK_DECISION) {
    if (any_deny) {
      *out_decision = GDEFCORE_DECISION_DENY;
    } else if (any_allow) {
      *out_decision = GDEFCORE_DECISION_ALLOW;
    } else {
      *out_decision = GDEFCORE_DECISION_DENY;
    }
  }
  rc = GDEFCORE_OK;
done:
  host->firing = 0;
  return rc;
}

GDEFCORE_Result gdefcore_hook_fire(GDEFCORE_Host * host,
    GDEFCORE_Request * request, GDEFCORE_Catalog * catalog, const char * hook,
    size_t hook_len, int kind, const void * args, GDEFCORE_Alter * alter,
    int * out_decision) {
  if (kind != GDEFCORE_HOOK_EVENT && kind != GDEFCORE_HOOK_ALTER &&
      kind != GDEFCORE_HOOK_DECISION) {
    return GDEFCORE_ERR_INVALID;
  }
  return fire_at(host, request, catalog, hook, hook_len, kind, args, alter,
      out_decision, 1, NULL);
}

size_t gdefcore_hook_skipped(const GDEFCORE_Host * host) {
  return host == NULL ? 0 : host->skipped_count;
}

const char * gdefcore_hook_skipped_names(const GDEFCORE_Host * host,
    size_t * out_len) {
  if (host == NULL || host->skipped_n == 0) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = host->skipped_n;
  }
  return host->skipped;
}

GDEFCORE_Result gdefcore_alter_create(GDEFCORE_Host * host, const char * text,
    size_t len, GDEFCORE_Alter ** out_alter) {
  GDEFCORE_Alter * alter;
  if (host == NULL || out_alter == NULL || (text == NULL && len != 0) ||
      len > kAlterMax) {
    return len > kAlterMax ? GDEFCORE_ERR_LIMIT : GDEFCORE_ERR_INVALID;
  }
  alter = (GDEFCORE_Alter *)gcu_allocator_malloc(host->alloc, sizeof *alter);
  if (alter == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  alter->alloc = host->alloc;
  alter->text = (char *)gcu_allocator_malloc(host->alloc, len + 1);
  if (alter->text == NULL) {
    gcu_allocator_free(host->alloc, alter);
    return GDEFCORE_ERR_OOM;
  }
  if (len > 0) {
    memcpy(alter->text, text, len);
  }
  alter->text[len] = '\0';
  alter->len = len;
  *out_alter = alter;
  return GDEFCORE_OK;
}

void gdefcore_alter_destroy(GDEFCORE_Host * host, GDEFCORE_Alter * alter) {
  if (alter == NULL) {
    return;
  }
  gcu_allocator_free(alter->alloc, alter->text);
  if (host != NULL) {
    gcu_allocator_free(host->alloc, alter);
  } else {
    gcu_allocator_free(alter->alloc, alter);
  }
}

GDEFCORE_Result gdefcore_alter_text(const GDEFCORE_Alter * alter,
    const char ** out_text, size_t * out_len) {
  if (alter == NULL || out_text == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_text = alter->text;
  *out_len = alter->len;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_alter_set(GDEFCORE_Alter * alter, const char * text,
    size_t len) {
  char * next;
  if (alter == NULL || (text == NULL && len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (len > kAlterMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  next = (char *)gcu_allocator_realloc(alter->alloc, alter->text, len + 1);
  if (next == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (len > 0) {
    memcpy(next, text, len);
  }
  next[len] = '\0';
  alter->text = next;
  alter->len = len;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_fire_write(GDEFCORE_Host * host,
    GDEFCORE_Request * request, GDEFCORE_Catalog * catalog, const char * hook,
    size_t hook_len, const GDEFCORE_Write_Hook * args) {
  const uint8_t * tenant;
  size_t tenant_len = 0;
  uint64_t epoch = 0;
  Chain * chain = NULL;
  int decision = GDEFCORE_DECISION_NONE;
  GDEFCORE_Result rc;
  if (host == NULL || catalog == NULL || hook == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (request == NULL) {
    tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  } else {
    size_t cat_len = 0;
    const uint8_t * cat_tenant = gdefcore_catalog_tenant(catalog, &cat_len);
    tenant = gdefcore_request_tenant(request, &tenant_len);
    if (tenant == NULL || cat_tenant == NULL || tenant_len != cat_len ||
        memcmp(tenant, cat_tenant, tenant_len) != 0) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  rc = gdefcore_epoch(catalog, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  chain = find_chain(host, tenant, tenant_len, epoch, hook, hook_len);
  if (chain == NULL) {
    rc = build_chain(host, tenant, tenant_len, epoch, hook, hook_len, &chain);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  if (chain->n == 0) {
    return GDEFCORE_OK;
  }
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = fire_at(host, request, catalog, hook, hook_len, chain->kind, args, NULL,
      &decision, 0, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (chain->kind == GDEFCORE_HOOK_DECISION &&
      decision == GDEFCORE_DECISION_DENY) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_module_fire_veto(GDEFCORE_Host * host,
    GDEFCORE_Request * request, GDEFCORE_Catalog * catalog, const char * hook,
    size_t hook_len, const void * args, int * out_vetoed) {
  int decision = GDEFCORE_DECISION_NONE;
  int denied = 0;
  GDEFCORE_Result rc;
  if (out_vetoed == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_vetoed = 0;
  rc = fire_at(host, request, catalog, hook, hook_len, GDEFCORE_HOOK_DECISION,
      args, NULL, &decision, 0, &denied);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_vetoed = denied;
  return GDEFCORE_OK;
}
