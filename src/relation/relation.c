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
 * The rows of the relations modules declare: the writes, and the version
 * counter. A row is an entity of `core.relation_row`; a relation that has had a
 * row has an entity of `core.relation`, whose version counter every change to
 * the relation's rows bumps in the same changeset. Nothing here reads a row
 * for a caller; the evaluator and the list compiler read them (condition.h).
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/relation.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/condition.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/sha256.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { kRemoveBatch = 500, kTextMax = 256 };

static const char kRowType[] = GDEFCORE_RELATION_ROW_TYPE;
static const char kStateType[] = GDEFCORE_RELATION_STATE_TYPE;
static const char kNameField[] = GDEFCORE_RELATION_FIELD_NAME;
static const char kLang[] = GDEFCORE_RELATION_LANG;
static const char * const kColumnField[GDEFCORE_RELATION_COLUMNS_MAX] = {
    "c0", "c1", "c2", "c3"};

const char * gdefcore_relation_column_field(size_t index) {
  return index < GDEFCORE_RELATION_COLUMNS_MAX ? kColumnField[index] : NULL;
}

static GDEFCORE_Field make_field(const char * name, int required) {
  GDEFCORE_Field f;
  memset(&f, 0, sizeof f);
  f.size = sizeof f;
  f.name = name;
  f.name_len = strlen(name);
  f.required = required;
  return f;
}

/* The two kernel types, defined the first time a relation is written. */
static GDEFCORE_Result ensure_types(GDEFCORE_Catalog * catalog) {
  int kind = 0;
  GDEFCORE_Result rc;
  if (gdefcore_type_kind(catalog, kRowType, strlen(kRowType), &kind) !=
      GDEFCORE_OK) {
    GDEFCORE_Field f[1 + GDEFCORE_RELATION_COLUMNS_MAX];
    size_t i;
    f[0] = make_field(kNameField, 1);
    for (i = 0; i < GDEFCORE_RELATION_COLUMNS_MAX; i++) {
      f[1 + i] = make_field(kColumnField[i], 0);
    }
    rc = gdefcore_type_define(catalog, kRowType, strlen(kRowType),
        GDEFCORE_TYPE_CONTENT, f, 1 + GDEFCORE_RELATION_COLUMNS_MAX);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  if (gdefcore_type_kind(catalog, kStateType, strlen(kStateType), &kind) !=
      GDEFCORE_OK) {
    GDEFCORE_Field f[1];
    f[0] = make_field("name", 1);
    rc = gdefcore_type_define(catalog, kStateType, strlen(kStateType),
        GDEFCORE_TYPE_CONTENT, f, 1);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  return GDEFCORE_OK;
}

/* What the declaration says about the relation, if the named module declares
 * it and is enabled. */
typedef struct Declared {
  size_t ncolumns;
  int kinds[GDEFCORE_RELATION_COLUMNS_MAX];
} Declared;

static GDEFCORE_Result declared(GDEFCORE_Catalog * catalog, const char * module,
    size_t module_len, const char * relation, size_t relation_len,
    Declared * out) {
  GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
  const GDEFCORE_Module_Declared_Relation ** items = NULL;
  size_t n = 0;
  size_t i;
  size_t c;
  size_t tenant_len = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  GDEFCORE_Result rc;
  GDEFCORE_Result out_rc = GDEFCORE_ERR_INVALID;
  if (host == NULL || module == NULL || module_len == 0 || relation == NULL ||
      relation_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_module_relations(host, tenant, tenant_len, NULL, &items, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < n; i++) {
    const GDEFCORE_Module_Declared_Relation * r = items[i];
    if (r->name_len != relation_len || memcmp(r->name, relation, relation_len) != 0) {
      continue;
    }
    /* The relation is the named module's, or nobody's to this caller. */
    if (r->module_len == module_len && memcmp(r->module, module, module_len) == 0) {
      memset(out, 0, sizeof *out);
      out->ncolumns = r->ncolumns;
      for (c = 0; c < r->ncolumns && c < GDEFCORE_RELATION_COLUMNS_MAX; c++) {
        out->kinds[c] = r->columns[c].kind;
      }
      out_rc = GDEFCORE_OK;
    }
    break;
  }
  gdefcore_module_declared_free(host, items);
  return out_rc;
}

/* A value in the form it is stored in, or 0 when it does not suit the column. */
typedef struct Stored {
  char text[kTextMax + 1];
  size_t len;
} Stored;

static int store_value(int kind, const char * v, size_t n, Stored * out) {
  if (v == NULL && n != 0) {
    return 0;
  }
  if (kind == GDEFCORE_RELATION_ENTITY) {
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (gdefcore_id_canonical(v, n, canon) != GDEFCORE_OK) {
      return 0;
    }
    memcpy(out->text, canon, GDEFCORE_PUBLIC_ID_LEN);
    out->len = GDEFCORE_PUBLIC_ID_LEN;
    return 1;
  }
  if (kind == GDEFCORE_RELATION_INTEGER) {
    size_t i = 0;
    int neg = 0;
    long long x = 0;
    int wn;
    if (n > 0 && v[0] == '-') {
      neg = 1;
      i = 1;
    }
    if (n - i < 1 || n - i > 18) {
      return 0;
    }
    for (; i < n; i++) {
      if (v[i] < '0' || v[i] > '9') {
        return 0;
      }
      x = x * 10 + (v[i] - '0');
    }
    wn = snprintf(out->text, sizeof out->text, "%lld", neg ? -x : x);
    if (wn <= 0 || (size_t)wn > kTextMax) {
      return 0;
    }
    out->len = (size_t)wn;
    return 1;
  }
  if (n > kTextMax) {
    return 0;
  }
  if (n > 0) {
    memcpy(out->text, v, n);
  }
  out->len = n;
  return 1;
}

/* ---- finding rows -------------------------------------------------------- */

typedef struct Keep {
  GDEFSTOR_QueryText texts[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  GDEFSTOR_QueryNode leaves[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  const GDEFSTOR_QueryNode * kids[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  GDEFSTOR_QueryNode root;
} Keep;

static void row_field(GDEFSTOR_QueryOperand * o, const char * field) {
  memset(o, 0, sizeof *o);
  o->kind = GDEFSTOR_QUERY_COLUMN;
  o->column = GDEFCORE_QUERY_COL_DOC;
  o->column_len = strlen(GDEFCORE_QUERY_COL_DOC);
  o->path_depth = 2;
  o->path1 = kLang;
  o->path1_len = strlen(kLang);
  o->path2 = field;
  o->path2_len = strlen(field);
}

/* name = relation, and each column given equal to its value. */
static void build_where(Keep * k, const char * relation, size_t relation_len,
    const Stored * stored, const int * given, size_t ncolumns) {
  size_t n = 0;
  size_t i;
  memset(k, 0, sizeof *k);
  k->texts[0].bytes = (const uint8_t *)relation;
  k->texts[0].len = relation_len;
  k->leaves[0].op = GDEFSTOR_QUERY_EQ;
  row_field(&k->leaves[0].left, kNameField);
  k->leaves[0].right.kind = GDEFSTOR_QUERY_CONST;
  k->leaves[0].right.texts = &k->texts[0];
  k->leaves[0].right.text_count = 1;
  k->kids[n++] = &k->leaves[0];
  for (i = 0; i < ncolumns; i++) {
    if (!given[i]) {
      continue;
    }
    k->texts[1 + i].bytes = (const uint8_t *)stored[i].text;
    k->texts[1 + i].len = stored[i].len;
    k->leaves[1 + i].op = GDEFSTOR_QUERY_EQ;
    row_field(&k->leaves[1 + i].left, kColumnField[i]);
    k->leaves[1 + i].right.kind = GDEFSTOR_QUERY_CONST;
    k->leaves[1 + i].right.texts = &k->texts[1 + i];
    k->leaves[1 + i].right.text_count = 1;
    k->kids[n++] = &k->leaves[1 + i];
  }
  k->root.op = GDEFSTOR_QUERY_AND;
  k->root.children = k->kids;
  k->root.child_count = n;
}

static GDEFCORE_Result find_rows(GDEFCORE_Catalog * catalog,
    const char * relation, size_t relation_len, const Stored * stored,
    const int * given, size_t ncolumns, uint64_t limit, char *** ids,
    size_t * n) {
  Keep keep;
  GDEFSTOR_Query q;
  build_where(&keep, relation, relation_len, stored, given, ncolumns);
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.where = &keep.root;
  q.entity_numeric = 1;
  q.limit = limit;
  return gdefcore_entity_query_active(catalog, kRowType, strlen(kRowType), &q,
      ids, n, NULL);
}

/* The entity that counts a relation's changes, if it has had a row. */
static GDEFCORE_Result find_state(GDEFCORE_Catalog * catalog,
    const char * relation, size_t relation_len, char out[GDEFCORE_PUBLIC_ID_LEN + 1],
    int * out_found) {
  GDEFSTOR_QueryText text;
  GDEFSTOR_QueryNode leaf;
  GDEFSTOR_Query q;
  char ** ids = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  *out_found = 0;
  memset(&leaf, 0, sizeof leaf);
  text.bytes = (const uint8_t *)relation;
  text.len = relation_len;
  leaf.op = GDEFSTOR_QUERY_EQ;
  memset(&leaf.left, 0, sizeof leaf.left);
  leaf.left.kind = GDEFSTOR_QUERY_COLUMN;
  leaf.left.column = GDEFCORE_QUERY_COL_DOC;
  leaf.left.column_len = strlen(GDEFCORE_QUERY_COL_DOC);
  leaf.left.path_depth = 2;
  leaf.left.path1 = kLang;
  leaf.left.path1_len = strlen(kLang);
  leaf.left.path2 = "name";
  leaf.left.path2_len = 4;
  leaf.right.kind = GDEFSTOR_QUERY_CONST;
  leaf.right.texts = &text;
  leaf.right.text_count = 1;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.where = &leaf;
  q.limit = 1;
  rc = gdefcore_entity_query_active(catalog, kStateType, strlen(kStateType), &q,
      &ids, &n, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (n > 0) {
    memcpy(out, ids[0], GDEFCORE_PUBLIC_ID_LEN + 1);
    *out_found = 1;
  }
  gdefcore_ids_free(catalog, ids, n);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_relation_version(GDEFCORE_Catalog * catalog,
    const char * relation, size_t relation_len, uint64_t * out_version) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int found = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || relation == NULL || relation_len == 0 ||
      out_version == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_version = 0;
  rc = find_state(catalog, relation, relation_len, id, &found);
  if (rc != GDEFCORE_OK || !found) {
    return rc;
  }
  return gdefcore_entity_version(catalog, id, GDEFCORE_PUBLIC_ID_LEN,
      out_version);
}

GDEFCORE_Result gdefcore_relation_note_dependency(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * relation, size_t relation_len) {
  GSEC_Sha256 ctx;
  uint8_t dig[GSEC_SHA256_DIGEST_LEN];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t version = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || relation == NULL ||
      relation_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_relation_version(catalog, relation, relation_len, &version);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* The relation has no id of its own until it has had a row, so the read is
   * recorded under one the name makes: the same on every node and every run. */
  if (gsec_sha256_init(&ctx) != GSEC_OK ||
      gsec_sha256_update(&ctx, "defiant.relation:", 17) != GSEC_OK ||
      gsec_sha256_update(&ctx, relation, relation_len) != GSEC_OK ||
      gsec_sha256_final(&ctx, dig) != GSEC_OK) {
    return GDEFCORE_ERR_INTERNAL;
  }
  rc = gdefcore_id_encode(dig, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return gdefcore_request_record_dependency(request, id, GDEFCORE_PUBLIC_ID_LEN,
      version);
}

/* ---- writes -------------------------------------------------------------- */

static GDEFCORE_Result one_value(GDEFCORE_Value * v, const char * field,
    const char * text, size_t len, const char ** slot, size_t * len_slot) {
  memset(v, 0, sizeof *v);
  *slot = text;
  *len_slot = len;
  v->size = sizeof *v;
  v->field = field;
  v->field_len = strlen(field);
  v->texts = slot;
  v->text_lens = len_slot;
  v->count = 1;
  return GDEFCORE_OK;
}

/* Check the call and put the values in their stored form. */
static GDEFCORE_Result prepare(GDEFCORE_Catalog * catalog, const char * module,
    size_t module_len, const char * relation, size_t relation_len,
    const char * const * values, const size_t * value_lens, size_t count,
    int allow_free, Stored * stored, int * given, Declared * decl) {
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || (count > 0 && (values == NULL || value_lens == NULL))) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = declared(catalog, module, module_len, relation, relation_len, decl);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count != decl->ncolumns) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < count; i++) {
    if (values[i] == NULL) {
      if (!allow_free) {
        return GDEFCORE_ERR_INVALID;
      }
      given[i] = 0;
      continue;
    }
    given[i] = 1;
    if (!store_value(decl->kinds[i], values[i], value_lens[i], &stored[i])) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  return GDEFCORE_OK;
}

/* The state entity of the relation, made if it is not there. */
static GDEFCORE_Result state_entity(GDEFCORE_Catalog * catalog,
    const char * relation, size_t relation_len,
    char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  int found = 0;
  GDEFCORE_Result rc = find_state(catalog, relation, relation_len, out, &found);
  if (rc != GDEFCORE_OK || found) {
    return rc;
  }
  return gdefcore_entity_create(catalog, kStateType, strlen(kStateType), out,
      NULL);
}

GDEFCORE_Result gdefcore_relation_add(GDEFCORE_Catalog * catalog,
    const char * module, size_t module_len, const char * relation,
    size_t relation_len, const char * const * values, const size_t * value_lens,
    size_t count, const char * actor, size_t actor_len, int * out_added) {
  Stored stored[GDEFCORE_RELATION_COLUMNS_MAX];
  int given[GDEFCORE_RELATION_COLUMNS_MAX];
  Declared decl;
  char row_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char state_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** ids = NULL;
  size_t n = 0;
  size_t i;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value vals[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  const char * slot[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  size_t slot_len[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  GDEFCORE_Value state_value;
  const char * state_slot;
  size_t state_slot_len;
  GDEFCORE_Result rc;
  if (out_added != NULL) {
    *out_added = 0;
  }
  memset(stored, 0, sizeof stored);
  memset(given, 0, sizeof given);
  rc = prepare(catalog, module, module_len, relation, relation_len, values,
      value_lens, count, 0, stored, given, &decl);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = ensure_types(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_rows(catalog, relation, relation_len, stored, given, count, 1, &ids,
      &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  gdefcore_ids_free(catalog, ids, n);
  if (n > 0) {
    return GDEFCORE_OK; /* already there */
  }
  rc = state_entity(catalog, relation, relation_len, state_id);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_create(catalog, kRowType, strlen(kRowType), row_id,
        NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_prepare(catalog, actor, actor_len, &cs);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  one_value(&vals[0], kNameField, relation, relation_len, &slot[0], &slot_len[0]);
  for (i = 0; i < count; i++) {
    one_value(&vals[1 + i], kColumnField[i], stored[i].text, stored[i].len,
        &slot[1 + i], &slot_len[1 + i]);
  }
  rc = gdefcore_entity_save(cs, row_id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      strlen(kLang), vals, 1 + count);
  if (rc == GDEFCORE_OK) {
    /* The same changeset touches the relation, so its version moves with the
     * row or not at all. */
    one_value(&state_value, "name", relation, relation_len, &state_slot,
        &state_slot_len);
    rc = gdefcore_entity_save(cs, state_id, GDEFCORE_PUBLIC_ID_LEN, kLang,
        strlen(kLang), &state_value, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(cs, NULL, 0);
  }
  gdefcore_changeset_destroy(cs);
  if (rc == GDEFCORE_OK && out_added != NULL) {
    *out_added = 1;
  }
  return rc;
}

GDEFCORE_Result gdefcore_relation_remove(GDEFCORE_Catalog * catalog,
    const char * module, size_t module_len, const char * relation,
    size_t relation_len, const char * const * values, const size_t * value_lens,
    size_t count, const char * actor, size_t actor_len, size_t * out_removed) {
  Stored stored[GDEFCORE_RELATION_COLUMNS_MAX];
  int given[GDEFCORE_RELATION_COLUMNS_MAX];
  Declared decl;
  size_t removed = 0;
  int pass;
  GDEFCORE_Result rc;
  if (out_removed != NULL) {
    *out_removed = 0;
  }
  memset(stored, 0, sizeof stored);
  memset(given, 0, sizeof given);
  rc = prepare(catalog, module, module_len, relation, relation_len, values,
      value_lens, count, 1, stored, given, &decl);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = ensure_types(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* In batches, each one changeset with the bump of the version. */
  for (pass = 0; pass < 1000; pass++) {
    char ** ids = NULL;
    size_t n = 0;
    size_t i;
    GDEFCORE_Changeset * cs = NULL;
    char state_id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Value state_value;
    const char * state_slot;
    size_t state_slot_len;
    rc = find_rows(catalog, relation, relation_len, stored, given, count,
        kRemoveBatch, &ids, &n);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (n == 0) {
      gdefcore_ids_free(catalog, ids, n);
      break;
    }
    rc = state_entity(catalog, relation, relation_len, state_id);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_prepare(catalog, actor, actor_len, &cs);
    }
    for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
      rc = gdefcore_entity_clear(cs, ids[i], GDEFCORE_PUBLIC_ID_LEN);
    }
    if (rc == GDEFCORE_OK) {
      one_value(&state_value, "name", relation, relation_len, &state_slot,
          &state_slot_len);
      rc = gdefcore_entity_save(cs, state_id, GDEFCORE_PUBLIC_ID_LEN, kLang,
          strlen(kLang), &state_value, 1);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    gdefcore_ids_free(catalog, ids, n);
    if (rc != GDEFCORE_OK) {
      break;
    }
    removed += n;
    if (n < kRemoveBatch) {
      break;
    }
  }
  if (out_removed != NULL) {
    *out_removed = removed;
  }
  return rc;
}
