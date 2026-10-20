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
 * The field tree in texts (story S6d): GDEFCORE_Tree. It is a port tree
 * (model.h) whose values are all text values holding canonical texts, and a
 * path per item, the path of the field the item sits under. A language's
 * group items are held as one of these in its GDEFCORE_Lang, and the public
 * tree calls hand one out. Staging and reading a tree against a type is
 * entity.c's; the mapping to the port's typed tree is store.c's.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-storage/model.h>

#include <stdlib.h>
#include <string.h>

#include "entity_internal.h"

static int name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > 64) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_')) {
      return 0;
    }
  }
  return 1;
}

static GDEFCORE_Result path_push(GDEFCORE_Tree * t, const char * a,
    size_t an, const char * b, size_t bn) {
  GDEFCORE_Text * p;
  size_t n = an + (an > 0 && bn > 0 ? 1 : 0) + bn;
  char * text;
  if (n > GDEFCORE_FIELD_PATH_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (t->npaths == t->cap) {
    size_t grown = t->cap == 0 ? 8 : t->cap * 2;
    GDEFCORE_Text * next = (GDEFCORE_Text *)gcu_allocator_realloc(t->alloc,
        t->paths, grown * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    t->paths = next;
    t->cap = grown;
  }
  text = (char *)gcu_allocator_malloc(t->alloc, n + 1);
  if (text == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (an > 0) {
    memcpy(text, a, an);
  }
  if (an > 0 && bn > 0) {
    text[an] = '.';
  }
  if (bn > 0) {
    memcpy(text + n - bn, b, bn);
  }
  text[n] = '\0';
  p = &t->paths[t->npaths++];
  p->p = text;
  p->n = n;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_tree_new(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Tree ** out) {
  GDEFCORE_Tree * t;
  GDEFCORE_Result rc;
  *out = NULL;
  alloc = gdefcore_ent_alloc(alloc);
  t = (GDEFCORE_Tree *)gcu_allocator_calloc(alloc, 1, sizeof *t);
  if (t == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  t->alloc = alloc;
  rc = gdefcore_ent_map(gdefstor_tree_create(alloc, &t->t));
  if (rc == GDEFCORE_OK) {
    rc = path_push(t, NULL, 0, NULL, 0);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_tree_free(t);
    return rc;
  }
  *out = t;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_tree_create(GDEFCORE_Catalog * catalog,
    GDEFCORE_Tree ** out_tree) {
  if (catalog == NULL || out_tree == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_ent_tree_new(catalog->alloc, out_tree);
}

void gdefcore_tree_free(GDEFCORE_Tree * tree) {
  size_t i;
  if (tree == NULL) {
    return;
  }
  for (i = 0; i < tree->npaths; i++) {
    gcu_allocator_free(tree->alloc, tree->paths[i].p);
  }
  gcu_allocator_free(tree->alloc, tree->paths);
  gdefstor_tree_free(tree->t);
  gcu_allocator_free(tree->alloc, tree);
}

GDEFCORE_Result gdefcore_tree_add(GDEFCORE_Tree * tree, size_t parent,
    const char * field, size_t field_len, uint64_t id, size_t * out_item) {
  size_t item = 0;
  GDEFCORE_Result rc;
  if (tree == NULL || parent >= tree->npaths || !name_ok(field, field_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  /* The path first, so that a refused one leaves the tree as it was. */
  rc = path_push(tree, tree->paths[parent].p, tree->paths[parent].n, field,
      field_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_ent_map(gdefstor_tree_add(tree->t, parent, field, field_len,
      id, &item));
  if (rc != GDEFCORE_OK) {
    tree->npaths -= 1;
    gcu_allocator_free(tree->alloc, tree->paths[tree->npaths].p);
    return rc;
  }
  if (out_item != NULL) {
    *out_item = item;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_tree_put(GDEFCORE_Tree * t, size_t item,
    const char * field, size_t field_len, const char * text, size_t len,
    const char * subject, size_t subject_len) {
  GDEFSTOR_Value v;
  if (t == NULL || item >= t->npaths || (field == NULL && field_len != 0) ||
      (field_len != 0 && !name_ok(field, field_len)) ||
      (text == NULL && len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&v, 0, sizeof v);
  if (text != NULL) {
    v.type = GDEFSTOR_FIELD_TEXT;
    v.bytes = (const uint8_t *)text;
    v.len = len;
    if (subject != NULL && subject_len > 0) {
      v.subject = (const uint8_t *)subject;
      v.subject_len = subject_len;
    }
  }
  return gdefcore_ent_map(gdefstor_tree_set(t->t, item, field, field_len, &v));
}

GDEFCORE_Result gdefcore_tree_set(GDEFCORE_Tree * tree, size_t item,
    const char * field, size_t field_len, const char * text, size_t len) {
  return gdefcore_ent_tree_put(tree, item, field, field_len, text, len, NULL,
      0);
}

size_t gdefcore_tree_item_count(const GDEFCORE_Tree * tree) {
  return tree == NULL ? 0 : tree->npaths;
}

GDEFCORE_Result gdefcore_tree_item(const GDEFCORE_Tree * tree, size_t index,
    GDEFCORE_TreeItem * out) {
  GDEFSTOR_TreeItem it;
  if (tree == NULL || out == NULL || out->size != sizeof *out ||
      index >= tree->npaths) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&it, 0, sizeof it);
  it.size = sizeof it;
  if (gdefstor_tree_item(tree->t, index, &it) != GDEFSTOR_OK) {
    return GDEFCORE_ERR_INTERNAL;
  }
  out->id = it.id;
  out->parent = index == 0 ? GDEFCORE_TREE_ROOT : it.parent;
  out->field = it.field;
  out->field_len = it.field_len;
  out->path = tree->paths[index].p;
  out->path_len = tree->paths[index].n;
  out->value_count = it.value_count;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_tree_value(const GDEFCORE_Tree * tree, size_t item,
    size_t k, const char ** out_field, size_t * out_field_len,
    const char ** out_text, size_t * out_len) {
  GDEFSTOR_Value v;
  const char * f = NULL;
  size_t fn = 0;
  if (tree == NULL || out_field == NULL || out_field_len == NULL ||
      out_text == NULL || out_len == NULL || item >= tree->npaths) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&v, 0, sizeof v);
  if (gdefstor_tree_value(tree->t, item, k, &f, &fn, &v) != GDEFSTOR_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_field = f == NULL ? "" : f;
  *out_field_len = fn;
  *out_text = v.bytes == NULL ? "" : (const char *)v.bytes;
  *out_len = v.len;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_tree_get(const GDEFCORE_Tree * tree, size_t item,
    const char * field, size_t field_len, const char ** out_text,
    size_t * out_len) {
  GDEFSTOR_Value v;
  if (tree == NULL || out_text == NULL || out_len == NULL ||
      item >= tree->npaths || (field == NULL && field_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&v, 0, sizeof v);
  if (gdefstor_tree_get(tree->t, item, field, field_len, &v) != GDEFSTOR_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (v.type == 0) {
    *out_text = NULL;
    *out_len = 0;
  } else {
    *out_text = v.bytes == NULL ? "" : (const char *)v.bytes;
    *out_len = v.len;
  }
  return GDEFCORE_OK;
}

/* Item @p i sits directly under @p field of @p item. */
static int under(const GDEFCORE_Tree * t, size_t i, size_t item,
    const char * field, size_t field_len) {
  GDEFSTOR_TreeItem it;
  memset(&it, 0, sizeof it);
  it.size = sizeof it;
  return i > 0 && gdefstor_tree_item(t->t, i, &it) == GDEFSTOR_OK &&
         it.parent == item &&
         gdefcore_ent_span_eq(it.field, it.field_len, field, field_len);
}

size_t gdefcore_tree_child_count(const GDEFCORE_Tree * tree, size_t item,
    const char * field, size_t field_len) {
  size_t n = 0;
  size_t i;
  if (tree == NULL || item >= tree->npaths) {
    return 0;
  }
  for (i = item + 1; i < tree->npaths; i++) {
    n += under(tree, i, item, field, field_len) ? 1u : 0u;
  }
  return n;
}

size_t gdefcore_ent_tree_count_under(const GDEFCORE_Tree * t, size_t item,
    const char * field, size_t field_len) {
  return gdefcore_tree_child_count(t, item, field, field_len);
}

GDEFCORE_Result gdefcore_tree_child(const GDEFCORE_Tree * tree, size_t item,
    const char * field, size_t field_len, size_t k, size_t * out_item) {
  size_t i;
  if (tree == NULL || out_item == NULL || item >= tree->npaths) {
    return GDEFCORE_ERR_INVALID;
  }
  /* A child is added after its parent, and siblings in their order. */
  for (i = item + 1; i < tree->npaths; i++) {
    if (under(tree, i, item, field, field_len)) {
      if (k == 0) {
        *out_item = i;
        return GDEFCORE_OK;
      }
      k -= 1;
    }
  }
  return GDEFCORE_ERR_INVALID;
}

GDEFCORE_Result gdefcore_ent_tree_value_path(const GDEFCORE_Tree * t,
    size_t item, const char * field, size_t field_len, GDEFCORE_Text * out) {
  const GDEFCORE_Text * p;
  size_t n;
  char * text;
  memset(out, 0, sizeof *out);
  if (t == NULL || item >= t->npaths) {
    return GDEFCORE_ERR_INVALID;
  }
  p = &t->paths[item];
  n = p->n + (p->n > 0 && field_len > 0 ? 1 : 0) + field_len;
  text = (char *)gcu_allocator_malloc(t->alloc, n + 1);
  if (text == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (p->n > 0) {
    memcpy(text, p->p, p->n);
  }
  if (p->n > 0 && field_len > 0) {
    text[p->n] = '.';
  }
  if (field_len > 0) {
    memcpy(text + n - field_len, field, field_len);
  }
  text[n] = '\0';
  out->p = text;
  out->n = n;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_tree_clone(const GDEFCORE_Tree * in,
    GDEFCORE_Tree ** out) {
  GDEFCORE_Tree * t = NULL;
  size_t i;
  GDEFCORE_Result rc;
  *out = NULL;
  if (in == NULL) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_ent_tree_new(in->alloc, &t);
  /* Items are added in index order, so a parent's new index is its old one. */
  for (i = 0; rc == GDEFCORE_OK && i < in->npaths; i++) {
    GDEFSTOR_TreeItem it;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefstor_tree_item(in->t, i, &it) != GDEFSTOR_OK) {
      rc = GDEFCORE_ERR_INTERNAL;
      break;
    }
    if (i > 0) {
      size_t got = 0;
      rc = gdefcore_tree_add(t, it.parent, it.field, it.field_len, it.id, &got);
      if (rc == GDEFCORE_OK && got != i) {
        rc = GDEFCORE_ERR_INTERNAL;
      }
    }
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * f = NULL;
      size_t fn = 0;
      GDEFSTOR_Value v;
      memset(&v, 0, sizeof v);
      if (gdefstor_tree_value(in->t, i, k, &f, &fn, &v) != GDEFSTOR_OK) {
        rc = GDEFCORE_ERR_INTERNAL;
        break;
      }
      rc = gdefcore_ent_map(gdefstor_tree_set(t->t, i, f, fn, &v));
    }
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_tree_free(t);
    return rc;
  }
  *out = t;
  return GDEFCORE_OK;
}

/* ---- comparison ---------------------------------------------------------- */

/* A canonical text of an item and what is under it: its id, its values in the
 * order of their fields, then each field's items in their order. Two trees
 * built in another order (a read lists a level at a time, a built tree as it
 * was added) give the same text for the same content. */
typedef struct Ser {
  const GDEFCORE_Allocator * alloc;
  char * p;
  size_t n;
  size_t cap;
  int oom;
} Ser;

static void ser_add(Ser * s, const void * b, size_t n) {
  if (s->oom || n == 0) {
    return;
  }
  if (s->n + n + 1 > s->cap) {
    size_t cap = s->cap == 0 ? 256 : s->cap;
    char * next;
    while (cap < s->n + n + 1) {
      cap *= 2;
    }
    next = (char *)gcu_allocator_realloc(s->alloc, s->p, cap);
    if (next == NULL) {
      s->oom = 1;
      return;
    }
    s->p = next;
    s->cap = cap;
  }
  memcpy(s->p + s->n, b, n);
  s->n += n;
  s->p[s->n] = '\0';
}

static void ser_u64(Ser * s, uint64_t v) {
  char buf[24];
  size_t k = sizeof buf;
  do {
    buf[--k] = (char)('0' + v % 10);
    v /= 10;
  } while (v > 0 && k > 0);
  ser_add(s, buf + k, sizeof buf - k);
}

/* A length-prefixed span, so no byte of a value can fake a delimiter. */
static void ser_span(Ser * s, const void * b, size_t n) {
  ser_u64(s, (uint64_t)n);
  ser_add(s, ":", 1);
  ser_add(s, b, n);
}

typedef struct Kid {
  size_t item;
  const char * field;
  size_t field_len;
  size_t seq; /* position among all the item's children, for a stable sort */
} Kid;

static int kid_cmp(const void * a, const void * b) {
  const Kid * x = (const Kid *)a;
  const Kid * y = (const Kid *)b;
  size_t n = x->field_len < y->field_len ? x->field_len : y->field_len;
  int c = n == 0 ? 0 : memcmp(x->field, y->field, n);
  if (c != 0) {
    return c;
  }
  if (x->field_len != y->field_len) {
    return x->field_len < y->field_len ? -1 : 1;
  }
  return x->seq < y->seq ? -1 : (x->seq > y->seq ? 1 : 0);
}

typedef struct Val {
  const char * field;
  size_t field_len;
  GDEFSTOR_Value v;
} Val;

static int val_cmp(const void * a, const void * b) {
  const Val * x = (const Val *)a;
  const Val * y = (const Val *)b;
  size_t n = x->field_len < y->field_len ? x->field_len : y->field_len;
  int c = n == 0 ? 0 : memcmp(x->field, y->field, n);
  if (c != 0) {
    return c;
  }
  return x->field_len < y->field_len ? -1 : (x->field_len > y->field_len);
}

static void ser_item(Ser * s, const GDEFCORE_Tree * t, size_t item,
    int with_values, int depth) {
  GDEFSTOR_TreeItem it;
  Kid * kids = NULL;
  Val * vals = NULL;
  size_t nk = 0;
  size_t k;
  size_t i;
  if (s->oom || depth > GDEFSTOR_MODEL_MAX_DEPTH * 2 + 4) {
    s->oom = 1;
    return;
  }
  memset(&it, 0, sizeof it);
  it.size = sizeof it;
  if (gdefstor_tree_item(t->t, item, &it) != GDEFSTOR_OK) {
    s->oom = 1;
    return;
  }
  ser_add(s, "(", 1);
  ser_u64(s, it.id);
  if (with_values && it.value_count > 0) {
    vals = (Val *)gcu_allocator_calloc(s->alloc, it.value_count, sizeof *vals);
    if (vals == NULL) {
      s->oom = 1;
      return;
    }
    for (k = 0; k < it.value_count; k++) {
      if (gdefstor_tree_value(t->t, item, k, &vals[k].field,
              &vals[k].field_len, &vals[k].v) != GDEFSTOR_OK) {
        s->oom = 1;
      }
    }
    qsort(vals, it.value_count, sizeof *vals, val_cmp);
    for (k = 0; k < it.value_count; k++) {
      ser_add(s, " v", 2);
      ser_span(s, vals[k].field, vals[k].field_len);
      ser_span(s, vals[k].v.bytes, vals[k].v.len);
      ser_span(s, vals[k].v.subject, vals[k].v.subject_len);
    }
    gcu_allocator_free(s->alloc, vals);
  }
  for (i = item + 1; i < t->npaths; i++) {
    GDEFSTOR_TreeItem c;
    memset(&c, 0, sizeof c);
    c.size = sizeof c;
    if (gdefstor_tree_item(t->t, i, &c) == GDEFSTOR_OK && c.parent == item) {
      nk += 1;
    }
  }
  if (nk > 0) {
    size_t at = 0;
    kids = (Kid *)gcu_allocator_calloc(s->alloc, nk, sizeof *kids);
    if (kids == NULL) {
      s->oom = 1;
      return;
    }
    for (i = item + 1; i < t->npaths && at < nk; i++) {
      GDEFSTOR_TreeItem c;
      memset(&c, 0, sizeof c);
      c.size = sizeof c;
      if (gdefstor_tree_item(t->t, i, &c) == GDEFSTOR_OK && c.parent == item) {
        kids[at].item = i;
        kids[at].field = c.field;
        kids[at].field_len = c.field_len;
        kids[at].seq = at;
        at += 1;
      }
    }
    qsort(kids, nk, sizeof *kids, kid_cmp);
    for (k = 0; k < nk; k++) {
      ser_add(s, " k", 2);
      ser_span(s, kids[k].field, kids[k].field_len);
      ser_item(s, t, kids[k].item, 1, depth + 1);
    }
    gcu_allocator_free(s->alloc, kids);
  }
  ser_add(s, ")", 1);
}

/* The text of the root's items under @p field, or (NULL) of the whole tree
 * but the root's own values. No tree reads as an empty one. */
static int ser_tree(const GDEFCORE_Tree * t, const char * field,
    size_t field_len, Ser * s) {
  size_t i;
  memset(s, 0, sizeof *s);
  s->alloc = t == NULL ? gdefcore_ent_alloc(NULL) : t->alloc;
  ser_add(s, "=", 1);
  if (t == NULL) {
    return !s->oom;
  }
  if (field == NULL) {
    /* The root without its values: a core tree's root has id 0. */
    ser_item(s, t, 0, 0, 0);
    return !s->oom;
  }
  for (i = 1; i < t->npaths; i++) {
    if (under(t, i, 0, field, field_len)) {
      ser_add(s, " k", 2);
      ser_item(s, t, i, 1, 1);
    }
  }
  return !s->oom;
}

static int texts_equal(const GDEFCORE_Tree * a, const GDEFCORE_Tree * b,
    const char * field, size_t field_len) {
  Ser x;
  Ser y;
  int same = 0;
  int ok_x = ser_tree(a, field, field_len, &x);
  int ok_y = ser_tree(b, field, field_len, &y);
  if (ok_x && ok_y) {
    same = x.n == y.n && memcmp(x.p, y.p, x.n) == 0;
  }
  gcu_allocator_free(x.alloc, x.p);
  gcu_allocator_free(y.alloc, y.p);
  return same;
}

int gdefcore_ent_tree_equal(const GDEFCORE_Tree * a, const GDEFCORE_Tree * b) {
  return texts_equal(a, b, NULL, 0);
}

int gdefcore_ent_tree_field_equal(const GDEFCORE_Tree * a,
    const GDEFCORE_Tree * b, const char * field, size_t field_len) {
  return texts_equal(a, b, field, field_len);
}
