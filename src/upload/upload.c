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

/* Staged files (upload.h): the metadata entity, the derived reference count,
 * the sweep and the read. */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <ghoti.io/defiant-core/upload.h>
#include <ghoti.io/defiant-storage/value.h>
#include <ghoti.io/security/sha256.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kLang[] = "en";
static const char kType[] = GDEFCORE_UPLOAD_TYPE;
#define TYPE_LEN (sizeof kType - 1)
#define ONE_DAY_MS (24ull * 60ull * 60ull * 1000ull)

struct GDEFCORE_Upload_File {
  char * name;
  char * media;
  uint8_t * bytes;
  size_t size;
};

/* ---- the type ------------------------------------------------------------ */

static const char * const kFields[] = {"name", "media", "size", "digest", "state",
    "expires", "uploader"};

GDEFCORE_Result gdefcore_upload_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field fields[7];
  GDEFCORE_Permission perm;
  int kind = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_type_kind(catalog, kType, TYPE_LEN, &kind) != GDEFCORE_OK) {
    memset(fields, 0, sizeof fields);
    for (i = 0; i < 7; i++) {
      fields[i].size = sizeof fields[i];
      fields[i].name = kFields[i];
      fields[i].name_len = strlen(kFields[i]);
      fields[i].required = i != 6;
    }
    fields[2].type = GDEFSTOR_FIELD_INTEGER;
    fields[5].type = GDEFSTOR_FIELD_INTEGER;
    rc = gdefcore_type_define(catalog, kType, TYPE_LEN, GDEFCORE_TYPE_CONTENT, fields, 7);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  memset(&perm, 0, sizeof perm);
  perm.size = sizeof perm;
  perm.label = "Upload files";
  perm.label_len = strlen(perm.label);
  perm.module_name = "core";
  perm.module_name_len = 4;
  perm.action = "create";
  perm.action_len = 6;
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = kType;
  perm.type_name_len = TYPE_LEN;
  rc = gdefcore_access_declare(catalog, &perm);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  perm.label = "See the files you uploaded";
  perm.label_len = strlen(perm.label);
  perm.action = "read";
  perm.action_len = 4;
  perm.condition = GDEFCORE_ACCESS_OWN;
  return gdefcore_access_declare(catalog, &perm);
}

/* ---- the rules ------------------------------------------------------------- */

int gdefcore_upload_name_ok(const char * name, size_t len) {
  size_t i;
  if (name == NULL || len == 0 || len > GDEFCORE_UPLOAD_NAME_MAX) {
    return 0;
  }
  if ((len == 1 && name[0] == '.') || (len == 2 && name[0] == '.' && name[1] == '.')) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)name[i];
    if (c < 0x20 || c == 0x7f || c == '/' || c == '\\') {
      return 0;
    }
    if (c >= 0x80) {
      /* UTF-8: a lead byte and its continuation bytes, nothing short. */
      size_t extra;
      size_t k;
      if (c >= 0xf0 && c <= 0xf4) {
        extra = 3;
      } else if (c >= 0xe0 && c < 0xf0) {
        extra = 2;
      } else if (c >= 0xc2 && c < 0xe0) {
        extra = 1;
      } else {
        return 0;
      }
      if (i + extra >= len) {
        return 0;
      }
      for (k = 1; k <= extra; k++) {
        if (((unsigned char)name[i + k] & 0xc0) != 0x80) {
          return 0;
        }
      }
      i += extra;
    }
  }
  return 1;
}

int gdefcore_upload_media_ok(const GDEFCORE_Upload_Policy * policy, const char * media,
    size_t len) {
  size_t i;
  if (policy == NULL || policy->size != sizeof *policy || media == NULL || len == 0 ||
      len > 127 || policy->media == NULL) {
    return 0;
  }
  for (i = 0; i < policy->media_count; i++) {
    const char * m = policy->media[i];
    if (m != NULL && strlen(m) == len && memcmp(m, media, len) == 0) {
      return 1;
    }
  }
  return 0;
}

static uint64_t policy_max(const GDEFCORE_Upload_Policy * p) {
  return p->max_bytes == 0 || p->max_bytes > GDEFCORE_UPLOAD_HARD_MAX
             ? GDEFCORE_UPLOAD_HARD_MAX
             : p->max_bytes;
}

static uint64_t policy_ttl(const GDEFCORE_Upload_Policy * p) {
  return p->ttl_ms == 0 ? ONE_DAY_MS : p->ttl_ms;
}

static int blobs_ok(const GDEFCORE_Blob_Store * b) {
  return b != NULL && b->size == sizeof *b && b->put != NULL && b->get != NULL &&
         b->remove != NULL;
}

/* ---- small helpers ---------------------------------------------------------- */

static void hex_of(const unsigned char * d, char out[GDEFCORE_UPLOAD_DIGEST_LEN + 1]) {
  static const char h[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < 32; i++) {
    out[2 * i] = h[d[i] >> 4];
    out[2 * i + 1] = h[d[i] & 15];
  }
  out[GDEFCORE_UPLOAD_DIGEST_LEN] = '\0';
}

static void value_set(GDEFCORE_Value * value, const char * field, const char ** slot,
    size_t * len_slot, const char * text, size_t len) {
  memset(value, 0, sizeof *value);
  *slot = text;
  *len_slot = len;
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = slot;
  value->text_lens = len_slot;
  value->count = 1;
}

/* The first value of a field of an entity, copied; NULL when there is none. */
static char * read_one(GDEFCORE_Catalog * catalog, const char * id, const char * field) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  char * out = NULL;
  if (gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
          GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, field, strlen(field), &texts,
          &lens, &count) != GDEFCORE_OK) {
    return NULL;
  }
  if (count > 0 && texts != NULL && texts[0] != NULL) {
    out = (char *)malloc(lens[0] + 1);
    if (out != NULL) {
      memcpy(out, texts[0], lens[0]);
      out[lens[0]] = '\0';
    }
  }
  gdefcore_values_free(catalog, texts, lens, count);
  return out;
}

/* The request's principal as a NUL-terminated public id; 0 when anonymous. */
static int principal_of(GDEFCORE_Request * request, char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  size_t n = 0;
  const char * p = gdefcore_request_principal(request, &n);
  if (p == NULL || n != GDEFCORE_PUBLIC_ID_LEN) {
    return 0;
  }
  memcpy(out, p, n);
  out[n] = '\0';
  return 1;
}

/* ---- staging ------------------------------------------------------------------ */

GDEFCORE_Result gdefcore_upload_stage(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Blob_Store * blobs,
    const GDEFCORE_Upload_Policy * policy, const char * name, size_t name_len,
    const char * media, size_t media_len, const uint8_t * bytes, size_t len,
    uint64_t now_ms, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  unsigned char digest[32];
  char hex[GDEFCORE_UPLOAD_DIGEST_LEN + 1];
  char size_text[24];
  char expires_text[24];
  char actor[GDEFCORE_PUBLIC_ID_LEN + 1];
  const uint8_t * tenant;
  size_t tenant_len = 0;
  int allowed = 0;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value values[7];
  const char * slots[7];
  size_t lens[7];
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || !blobs_ok(blobs) || policy == NULL ||
      policy->size != sizeof *policy || out_id == NULL || bytes == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_upload_declare(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* Everything is refused before a byte is given to the store. */
  if (gdefcore_access_can_create(catalog, request, NULL, 0, kType, TYPE_LEN, NULL, NULL, 0,
          &allowed) != GDEFCORE_OK ||
      !allowed) {
    return GDEFCORE_ERR_INVALID;
  }
  if (len == 0 || (uint64_t)len > policy_max(policy) ||
      !gdefcore_upload_name_ok(name, name_len) ||
      !gdefcore_upload_media_ok(policy, media, media_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!principal_of(request, actor)) {
    return GDEFCORE_ERR_INVALID;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  if (tenant == NULL || gsec_sha256(bytes, len, digest) != GSEC_OK) {
    return GDEFCORE_ERR_INTERNAL;
  }
  hex_of(digest, hex);
  if (blobs->put(blobs->ctx, tenant, tenant_len, hex, bytes, len) != 0) {
    return GDEFCORE_ERR_IO;
  }
  snprintf(size_text, sizeof size_text, "%zu", len);
  snprintf(expires_text, sizeof expires_text, "%" PRIu64, now_ms + policy_ttl(policy));
  rc = gdefcore_entity_create(catalog, kType, TYPE_LEN, out_id, NULL);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_prepare(catalog, actor, GDEFCORE_PUBLIC_ID_LEN, &cs);
  }
  if (rc == GDEFCORE_OK) {
    value_set(&values[0], "name", &slots[0], &lens[0], name, name_len);
    value_set(&values[1], "media", &slots[1], &lens[1], media, media_len);
    value_set(&values[2], "size", &slots[2], &lens[2], size_text, strlen(size_text));
    value_set(&values[3], "digest", &slots[3], &lens[3], hex, GDEFCORE_UPLOAD_DIGEST_LEN);
    value_set(&values[4], "state", &slots[4], &lens[4], GDEFCORE_UPLOAD_STATE_STAGED,
        strlen(GDEFCORE_UPLOAD_STATE_STAGED));
    value_set(&values[5], "expires", &slots[5], &lens[5], expires_text,
        strlen(expires_text));
    value_set(&values[6], "uploader", &slots[6], &lens[6], actor, GDEFCORE_PUBLIC_ID_LEN);
    rc = gdefcore_entity_save(cs, out_id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1,
        values, 7);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(cs, NULL, 0);
  }
  gdefcore_changeset_destroy(cs);
  if (rc != GDEFCORE_OK) {
    /* The metadata was not written: the blob is only removed when no other
     * file of this tenant holds it, which the sweep decides; leave it. */
    return rc;
  }
  return GDEFCORE_OK;
}

/* ---- the derived reference count --------------------------------------------- */

struct Ref {
  char file[GDEFCORE_PUBLIC_ID_LEN + 1];
  char referrer[GDEFCORE_PUBLIC_ID_LEN + 1];
};

struct Refs {
  struct Ref * v;
  size_t n;
  size_t cap;
};

static int refs_add(struct Refs * r, const char * file, const char * referrer) {
  if (r->n == r->cap) {
    size_t cap = r->cap == 0 ? 16 : r->cap * 2;
    struct Ref * p = (struct Ref *)realloc(r->v, cap * sizeof *p);
    if (p == NULL) {
      return -1;
    }
    r->v = p;
    r->cap = cap;
  }
  memcpy(r->v[r->n].file, file, GDEFCORE_PUBLIC_ID_LEN + 1);
  memcpy(r->v[r->n].referrer, referrer, GDEFCORE_PUBLIC_ID_LEN + 1);
  r->n++;
  return 0;
}

#define PATHS_MAX 64

struct Paths {
  size_t n;
  char p[PATHS_MAX][GDEFCORE_FIELD_PATH_MAX + 1];
  size_t len[PATHS_MAX];
};

static int path_wanted(const struct Paths * ps, const char * path, size_t len) {
  size_t i;
  for (i = 0; i < ps->n; i++) {
    if (ps->len[i] == len && memcmp(ps->p[i], path, len) == 0) {
      return 1;
    }
  }
  return 0;
}

/* The reference fields, at any depth, of a type that a file could be named in:
 * every reference that is not personal. */
static GDEFCORE_Result paths_of(GDEFCORE_Catalog * catalog, const char * type, size_t type_len,
    struct Paths * ps) {
  size_t count = 0;
  size_t i;
  ps->n = 0;
  if (gdefcore_type_tree_field_count(catalog, type, type_len, &count) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < count && ps->n < PATHS_MAX; i++) {
    GDEFCORE_FieldInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefcore_type_tree_field(catalog, type, type_len, i, &info) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INTERNAL;
    }
    if (info.type == GDEFSTOR_FIELD_REFERENCE && !info.personal) {
      memcpy(ps->p[ps->n], info.path, info.path_len + 1);
      ps->len[ps->n] = info.path_len;
      ps->n++;
    }
  }
  return GDEFCORE_OK;
}

/* Every file reference of the entities of every content and configuration
 * type: the pair (file, referrer). With a @p request, an entity is read through
 * the access filter and one the principal cannot see, or a field they cannot
 * read, is not there; without one, as the system. */
static GDEFCORE_Result scan(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    struct Refs * out) {
  int kinds[2] = {GDEFCORE_TYPE_CONTENT, GDEFCORE_TYPE_CONFIG};
  size_t k;
  for (k = 0; k < 2; k++) {
    char ** names = NULL;
    size_t * nlens = NULL;
    size_t ntypes = 0;
    size_t t;
    if (gdefcore_type_names(catalog, kinds[k], &names, &nlens, &ntypes) != GDEFCORE_OK) {
      continue;
    }
    for (t = 0; t < ntypes; t++) {
      struct Paths * ps;
      char ** ids = NULL;
      size_t nids = 0;
      size_t e;
      if (nlens[t] == TYPE_LEN && memcmp(names[t], kType, TYPE_LEN) == 0) {
        continue;
      }
      ps = (struct Paths *)malloc(sizeof *ps);
      if (ps == NULL) {
        gdefcore_values_free(catalog, names, nlens, ntypes);
        return GDEFCORE_ERR_OOM;
      }
      if (paths_of(catalog, names[t], nlens[t], ps) != GDEFCORE_OK || ps->n == 0 ||
          gdefcore_entity_ids(catalog, names[t], nlens[t], &ids, &nids) != GDEFCORE_OK) {
        free(ps);
        continue;
      }
      for (e = 0; e < nids; e++) {
        GDEFCORE_Tree * tree = NULL;
        size_t items;
        size_t it;
        GDEFCORE_Result rr;
        if (strlen(ids[e]) != GDEFCORE_PUBLIC_ID_LEN) {
          continue;
        }
        rr = request != NULL
                 ? gdefcore_access_tree(catalog, request, ids[e], GDEFCORE_PUBLIC_ID_LEN,
                       kLang, sizeof kLang - 1, &tree)
                 : gdefcore_entity_tree(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[e],
                       GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, &tree);
        if (rr != GDEFCORE_OK || tree == NULL) {
          continue;
        }
        items = gdefcore_tree_item_count(tree);
        for (it = 0; it < items; it++) {
          GDEFCORE_TreeItem item;
          size_t v;
          memset(&item, 0, sizeof item);
          item.size = sizeof item;
          if (gdefcore_tree_item(tree, it, &item) != GDEFCORE_OK) {
            continue;
          }
          for (v = 0; v < item.value_count; v++) {
            const char * field = NULL;
            size_t field_len = 0;
            const char * text = NULL;
            size_t text_len = 0;
            char path[GDEFCORE_FIELD_PATH_MAX + 2];
            size_t plen;
            if (gdefcore_tree_value(tree, it, v, &field, &field_len, &text, &text_len) !=
                GDEFCORE_OK || text_len != GDEFCORE_PUBLIC_ID_LEN) {
              continue;
            }
            if (item.path_len + field_len + 1 > GDEFCORE_FIELD_PATH_MAX) {
              continue;
            }
            plen = 0;
            if (item.path_len > 0) {
              memcpy(path, item.path, item.path_len);
              plen = item.path_len;
            }
            if (field_len > 0) {
              if (plen > 0) {
                path[plen++] = '.';
              }
              memcpy(path + plen, field, field_len);
              plen += field_len;
            }
            if (!path_wanted(ps, path, plen)) {
              continue;
            }
            {
              char file[GDEFCORE_PUBLIC_ID_LEN + 1];
              if (gdefcore_id_canonical(text, text_len, file) != GDEFCORE_OK) {
                continue;
              }
              if (refs_add(out, file, ids[e]) != 0) {
                gdefcore_tree_free(tree);
                gdefcore_ids_free(catalog, ids, nids);
                free(ps);
                gdefcore_values_free(catalog, names, nlens, ntypes);
                return GDEFCORE_ERR_OOM;
              }
            }
          }
        }
        gdefcore_tree_free(tree);
      }
      gdefcore_ids_free(catalog, ids, nids);
      free(ps);
    }
    gdefcore_values_free(catalog, names, nlens, ntypes);
  }
  return GDEFCORE_OK;
}

static size_t count_of(const struct Refs * r, const char * file) {
  size_t i;
  size_t n = 0;
  for (i = 0; i < r->n; i++) {
    if (memcmp(r->v[i].file, file, GDEFCORE_PUBLIC_ID_LEN) == 0) {
      n++;
    }
  }
  return n;
}

GDEFCORE_Result gdefcore_upload_references(GDEFCORE_Catalog * catalog, const char * id,
    size_t id_len, size_t * out_count) {
  struct Refs refs;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  memset(&refs, 0, sizeof refs);
  if (catalog == NULL || id == NULL || out_count == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = scan(catalog, NULL, &refs);
  if (rc == GDEFCORE_OK) {
    *out_count = count_of(&refs, canon);
  }
  free(refs.v);
  return rc;
}

GDEFCORE_Result gdefcore_upload_field_ok(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * field, size_t field_len, int * out_ok) {
  size_t count = 0;
  size_t i;
  if (catalog == NULL || type == NULL || field == NULL || out_ok == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_ok = 0;
  if (gdefcore_type_tree_field_count(catalog, type, type_len, &count) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < count; i++) {
    GDEFCORE_FieldInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefcore_type_tree_field(catalog, type, type_len, i, &info) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INTERNAL;
    }
    if (info.path_len == field_len && memcmp(info.path, field, field_len) == 0) {
      *out_ok = info.type == GDEFSTOR_FIELD_REFERENCE && !info.personal;
      return GDEFCORE_OK;
    }
  }
  return GDEFCORE_OK;
}

/* ---- the sweep ------------------------------------------------------------------ */

static GDEFCORE_Result set_state(GDEFCORE_Catalog * catalog, const char * id,
    const char * state, uint64_t expires) {
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value values[2];
  const char * slots[2];
  size_t lens[2];
  char text[24];
  GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  snprintf(text, sizeof text, "%" PRIu64, expires);
  value_set(&values[0], "state", &slots[0], &lens[0], state, strlen(state));
  value_set(&values[1], "expires", &slots[1], &lens[1], text, strlen(text));
  rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, values, 2);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(cs, NULL, 0);
  }
  gdefcore_changeset_destroy(cs);
  return rc;
}

static GDEFCORE_Result remove_entity(GDEFCORE_Catalog * catalog, const char * id) {
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_clear(cs, id, GDEFCORE_PUBLIC_ID_LEN);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(cs, NULL, 0);
  }
  gdefcore_changeset_destroy(cs);
  return rc;
}

/* Whether any file entity other than @p except holds @p digest. */
static int digest_held(GDEFCORE_Catalog * catalog, const char * digest, const char * except) {
  char ** ids = NULL;
  size_t n = 0;
  size_t i;
  int held = 0;
  if (gdefcore_entity_ids(catalog, kType, TYPE_LEN, &ids, &n) != GDEFCORE_OK) {
    return 1;  /* unknown: keep the blob */
  }
  for (i = 0; i < n && !held; i++) {
    char * d;
    if (strcmp(ids[i], except) == 0) {
      continue;
    }
    d = read_one(catalog, ids[i], "digest");
    held = d != NULL && strcmp(d, digest) == 0;
    free(d);
  }
  gdefcore_ids_free(catalog, ids, n);
  return held;
}

GDEFCORE_Result gdefcore_upload_sweep(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Blob_Store * blobs, const GDEFCORE_Upload_Policy * policy,
    uint64_t now_ms, size_t * out_promoted, size_t * out_demoted, size_t * out_removed) {
  struct Refs refs;
  char ** ids = NULL;
  size_t n = 0;
  size_t i;
  size_t promoted = 0;
  size_t demoted = 0;
  size_t removed = 0;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  GDEFCORE_Result rc;
  memset(&refs, 0, sizeof refs);
  if (catalog == NULL || !blobs_ok(blobs) || policy == NULL || policy->size != sizeof *policy) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_upload_declare(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  rc = scan(catalog, NULL, &refs);
  if (rc != GDEFCORE_OK) {
    free(refs.v);
    return rc;
  }
  rc = gdefcore_entity_ids(catalog, kType, TYPE_LEN, &ids, &n);
  if (rc != GDEFCORE_OK) {
    free(refs.v);
    return rc;
  }
  for (i = 0; i < n && rc == GDEFCORE_OK; i++) {
    char * state = NULL;
    char * expires = NULL;
    char * digest = NULL;
    uint64_t exp = 0;
    size_t used;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    state = read_one(catalog, ids[i], "state");
    expires = read_one(catalog, ids[i], "expires");
    if (state == NULL || expires == NULL) {
      free(state);
      free(expires);
      continue;
    }
    exp = (uint64_t)strtoull(expires, NULL, 10);
    used = count_of(&refs, ids[i]);
    if (used > 0 && strcmp(state, GDEFCORE_UPLOAD_STATE_KEPT) != 0) {
      rc = set_state(catalog, ids[i], GDEFCORE_UPLOAD_STATE_KEPT, 0);
      promoted += rc == GDEFCORE_OK;
    } else if (used == 0 && strcmp(state, GDEFCORE_UPLOAD_STATE_KEPT) == 0) {
      rc = set_state(catalog, ids[i], GDEFCORE_UPLOAD_STATE_STAGED, now_ms + policy_ttl(policy));
      demoted += rc == GDEFCORE_OK;
    } else if (used == 0 && exp <= now_ms) {
      digest = read_one(catalog, ids[i], "digest");
      rc = remove_entity(catalog, ids[i]);
      if (rc == GDEFCORE_OK) {
        removed++;
        if (digest != NULL && strlen(digest) == GDEFCORE_UPLOAD_DIGEST_LEN &&
            !digest_held(catalog, digest, ids[i]) && tenant != NULL) {
          (void)blobs->remove(blobs->ctx, tenant, tenant_len, digest);
        }
      }
    }
    free(state);
    free(expires);
    free(digest);
  }
  gdefcore_ids_free(catalog, ids, n);
  free(refs.v);
  if (out_promoted != NULL) {
    *out_promoted = promoted;
  }
  if (out_demoted != NULL) {
    *out_demoted = demoted;
  }
  if (out_removed != NULL) {
    *out_removed = removed;
  }
  return rc;
}

/* ---- reading ---------------------------------------------------------------------- */

void gdefcore_upload_file_free(GDEFCORE_Upload_File * file) {
  if (file != NULL) {
    free(file->name);
    free(file->media);
    free(file->bytes);
    free(file);
  }
}

const char * gdefcore_upload_file_name(const GDEFCORE_Upload_File * file) {
  return file == NULL ? NULL : file->name;
}

const char * gdefcore_upload_file_media(const GDEFCORE_Upload_File * file) {
  return file == NULL ? NULL : file->media;
}

const uint8_t * gdefcore_upload_file_bytes(const GDEFCORE_Upload_File * file) {
  return file == NULL ? NULL : file->bytes;
}

size_t gdefcore_upload_file_size(const GDEFCORE_Upload_File * file) {
  return file == NULL ? 0 : file->size;
}

/* Whether the principal may have the file: the uploader of a staged one, and
 * for a kept one anyone who sees the reference to it in an entity they may read. */
static int may_have(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request, const char * id,
    const char * state, const char * uploader) {
  char who[GDEFCORE_PUBLIC_ID_LEN + 1];
  struct Refs refs;
  int ok = 0;
  if (principal_of(request, who) && uploader != NULL && strcmp(who, uploader) == 0) {
    return 1;
  }
  if (strcmp(state, GDEFCORE_UPLOAD_STATE_KEPT) != 0) {
    return 0;
  }
  memset(&refs, 0, sizeof refs);
  if (scan(catalog, request, &refs) == GDEFCORE_OK) {
    ok = count_of(&refs, id) > 0;
  }
  free(refs.v);
  return ok;
}

GDEFCORE_Result gdefcore_upload_read(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const GDEFCORE_Blob_Store * blobs, const char * id, size_t id_len,
    GDEFCORE_Upload_File ** out_file) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * name = NULL;
  char * media = NULL;
  char * size = NULL;
  char * digest = NULL;
  char * state = NULL;
  char * uploader = NULL;
  GDEFCORE_Upload_File * f = NULL;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  size_t want;
  size_t got = 0;
  unsigned char sum[32];
  char hex[GDEFCORE_UPLOAD_DIGEST_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  if (catalog == NULL || request == NULL || !blobs_ok(blobs) || id == NULL ||
      out_file == NULL || gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_file = NULL;
  name = read_one(catalog, canon, "name");
  media = read_one(catalog, canon, "media");
  size = read_one(catalog, canon, "size");
  digest = read_one(catalog, canon, "digest");
  state = read_one(catalog, canon, "state");
  uploader = read_one(catalog, canon, "uploader");
  if (name == NULL || media == NULL || size == NULL || digest == NULL || state == NULL ||
      strlen(digest) != GDEFCORE_UPLOAD_DIGEST_LEN ||
      !may_have(catalog, request, canon, state, uploader)) {
    goto done;
  }
  want = (size_t)strtoull(size, NULL, 10);
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  f = (GDEFCORE_Upload_File *)calloc(1, sizeof *f);
  if (f == NULL || tenant == NULL || want == 0 || want > GDEFCORE_UPLOAD_HARD_MAX) {
    rc = f == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_ERR_CORRUPT;
    goto done;
  }
  f->bytes = (uint8_t *)malloc(want);
  if (f->bytes == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  /* A blob that is gone, or is not the bytes of its digest, is corrupt and is
   * never served. */
  if (blobs->get(blobs->ctx, tenant, tenant_len, digest, f->bytes, want, &got) != 0 ||
      got != want || gsec_sha256(f->bytes, got, sum) != GSEC_OK) {
    rc = GDEFCORE_ERR_CORRUPT;
    goto done;
  }
  hex_of(sum, hex);
  if (strcmp(hex, digest) != 0) {
    rc = GDEFCORE_ERR_CORRUPT;
    goto done;
  }
  f->size = got;
  f->name = name;
  f->media = media;
  name = NULL;
  media = NULL;
  *out_file = f;
  f = NULL;
  rc = GDEFCORE_OK;
done:
  gdefcore_upload_file_free(f);
  free(name);
  free(media);
  free(size);
  free(digest);
  free(state);
  free(uploader);
  return rc;
}
