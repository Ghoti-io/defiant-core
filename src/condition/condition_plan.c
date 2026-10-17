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
 * A condition compiled into the storage port's query form (plan.h). The
 * evaluator in condition_eval.c is the reference: the compiled predicate must
 * select the entities it holds on.
 *
 * The evaluator is lazy and fails closed. `and` stops at the first operand that
 * is false, `or` at the first that is true, and an operand that cannot be read
 * (a personal field, a field the type lacks) makes the whole condition not hold
 * once evaluation reaches it, `not` included. A compiled operand is therefore a
 * pair: V, the value it would have if nothing failed, and X, the predicate "the
 * evaluation reaches a failure". The condition holds when V holds and X does
 * not. For `and` of c1..ck:
 *
 *   V = V1 and ... and Vk
 *   X = or over i of ( (V1 and not X1) and ... and (V(i-1) and not X(i-1)) and Xi )
 *
 * and for `or`, with "not Vj" in place of Vj in the prefix. `not` keeps X. A
 * leaf that cannot fail has X absent, so a condition with no such leaf pays
 * nothing for any of this.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/plan.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/relation.h>

#include "condition_internal.h"

#include <ghoti.io/cutil/allocator.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Chunk {
  struct Chunk * next;
  size_t used;
  size_t cap;
  union {
    max_align_t align;
    unsigned char data[1];
  } u;
} Chunk;

struct GDEFCORE_Plan {
  GDEFCORE_Catalog * catalog;
  const GDEFCORE_Allocator * alloc;
  char type[160];
  size_t type_len;
  char lang[80];
  size_t lang_len;
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t principal_len;
  int has_principal;
  int64_t now;
  size_t max_values;
  Chunk * chunks;
  size_t nodes;
  int unsupported;
  int oom;
  int failed;
  const GDEFSTOR_QueryNode * yes;
  const GDEFSTOR_QueryNode * no;
  const GDEFSTOR_QueryNode * pub1;
  const GDEFSTOR_QueryNode * pub0;
  const GDEFSTOR_QueryNode * outer_pub1;
  const GDEFSTOR_QueryNode * outer_pub0;
  char * rels[GDEFCORE_CONDITION_MAX_RELATIONS * 8];
  size_t rel_lens[GDEFCORE_CONDITION_MAX_RELATIONS * 8];
  size_t nrels;
};

static void * plan_mem(GDEFCORE_Plan * p, size_t n) {
  Chunk * c = p->chunks;
  size_t at;
  void * out;
  n = (n + 15u) & ~(size_t)15u;
  if (c == NULL || c->cap - c->used < n) {
    size_t cap = n > 32768u ? n : 32768u;
    Chunk * fresh = (Chunk *)gcu_allocator_calloc(p->alloc, 1,
        offsetof(Chunk, u) + cap);
    if (fresh == NULL) {
      p->oom = 1;
      return NULL;
    }
    fresh->cap = cap;
    fresh->next = p->chunks;
    p->chunks = fresh;
    c = fresh;
  }
  at = c->used;
  c->used += n;
  out = c->u.data + at;
  return out;
}

static char * plan_str(GDEFCORE_Plan * p, const char * s, size_t n) {
  char * out = (char *)plan_mem(p, n + 1);
  if (out == NULL) {
    return NULL;
  }
  if (n > 0) {
    memcpy(out, s, n);
  }
  out[n] = '\0';
  return out;
}

GDEFCORE_Result gdefcore_plan_create(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_name_len, const char * lang,
    size_t lang_len, const char * principal, size_t principal_len, int64_t now,
    GDEFCORE_Plan ** out_plan) {
  GDEFCORE_Plan * p;
  GDEFCORE_Limits limits;
  const GDEFCORE_Allocator * alloc = gdefcore_allocator_default();
  if (catalog == NULL || type_name == NULL || type_name_len == 0 ||
      type_name_len >= sizeof p->type || lang == NULL || lang_len == 0 ||
      lang_len >= sizeof p->lang || out_plan == NULL ||
      principal_len > GDEFCORE_PUBLIC_ID_LEN ||
      (principal == NULL && principal_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  p = (GDEFCORE_Plan *)gcu_allocator_calloc(alloc, 1, sizeof *p);
  if (p == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  p->catalog = catalog;
  p->alloc = alloc;
  memcpy(p->type, type_name, type_name_len);
  p->type_len = type_name_len;
  memcpy(p->lang, lang, lang_len);
  p->lang_len = lang_len;
  if (principal != NULL && principal_len > 0) {
    memcpy(p->principal, principal, principal_len);
    p->principal_len = principal_len;
    p->has_principal = 1;
  }
  p->now = now;
  gdefcore_catalog_limits(catalog, &limits);
  p->max_values = limits.max_values;
  *out_plan = p;
  return GDEFCORE_OK;
}

void gdefcore_plan_free(GDEFCORE_Plan * plan) {
  Chunk * c;
  if (plan == NULL) {
    return;
  }
  c = plan->chunks;
  while (c != NULL) {
    Chunk * next = c->next;
    gcu_allocator_free(plan->alloc, c);
    c = next;
  }
  gcu_allocator_free(plan->alloc, plan);
}

int gdefcore_plan_unsupported(const GDEFCORE_Plan * plan) {
  return plan != NULL && plan->unsupported;
}

int gdefcore_plan_oom(const GDEFCORE_Plan * plan) {
  return plan != NULL && plan->oom;
}

int gdefcore_plan_failed(const GDEFCORE_Plan * plan) {
  return plan != NULL && plan->failed;
}

/* ---- building nodes ------------------------------------------------------ */

static GDEFSTOR_QueryNode * new_node(GDEFCORE_Plan * p, int op) {
  GDEFSTOR_QueryNode * n;
  if (p->nodes >= GDEFCORE_PLAN_MAX_NODES) {
    p->unsupported = 1;
    return NULL;
  }
  n = (GDEFSTOR_QueryNode *)plan_mem(p, sizeof *n);
  if (n == NULL) {
    return NULL;
  }
  p->nodes += 1;
  n->op = op;
  return n;
}

const GDEFSTOR_QueryNode * gdefcore_plan_constant(GDEFCORE_Plan * plan,
    int value) {
  const GDEFSTOR_QueryNode ** slot;
  if (plan == NULL) {
    return NULL;
  }
  slot = value ? &plan->yes : &plan->no;
  if (*slot == NULL) {
    *slot = new_node(plan, value ? GDEFSTOR_QUERY_TRUE : GDEFSTOR_QUERY_FALSE);
  }
  return *slot;
}

static const GDEFSTOR_QueryNode * list_node(GDEFCORE_Plan * p, int op,
    const GDEFSTOR_QueryNode * const * kids, size_t count) {
  GDEFSTOR_QueryNode * n;
  const GDEFSTOR_QueryNode ** copy = NULL;
  size_t i;
  if (count > 0) {
    copy = (const GDEFSTOR_QueryNode **)plan_mem(p, count * sizeof *copy);
    if (copy == NULL) {
      return NULL;
    }
    for (i = 0; i < count; i++) {
      copy[i] = kids[i];
    }
  }
  n = new_node(p, op);
  if (n == NULL) {
    return NULL;
  }
  n->children = copy;
  n->child_count = count;
  return n;
}

/* An and or or, with the constants folded away: a true child of an and, a
 * false child of an or, and a one-child list, are not nodes. */
static const GDEFSTOR_QueryNode * fold_list(GDEFCORE_Plan * p, int op,
    const GDEFSTOR_QueryNode * const * kids, size_t count) {
  const GDEFSTOR_QueryNode * const * use = kids;
  const GDEFSTOR_QueryNode ** kept = NULL;
  size_t n = 0;
  size_t i;
  const GDEFSTOR_QueryNode * neutral;
  const GDEFSTOR_QueryNode * absorbing;
  int is_and = op == GDEFSTOR_QUERY_AND;
  neutral = gdefcore_plan_constant(p, is_and);
  absorbing = gdefcore_plan_constant(p, !is_and);
  if (neutral == NULL || absorbing == NULL) {
    return NULL;
  }
  if (count > 0) {
    kept = (const GDEFSTOR_QueryNode **)plan_mem(p, count * sizeof *kept);
    if (kept == NULL) {
      return NULL;
    }
  }
  for (i = 0; i < count; i++) {
    if (use[i] == NULL) {
      p->unsupported = 1;
      return NULL;
    }
    if (use[i] == absorbing) {
      return absorbing;
    }
    if (use[i] != neutral) {
      kept[n++] = use[i];
    }
  }
  if (n == 0) {
    return neutral;
  }
  if (n == 1) {
    return kept[0];
  }
  return list_node(p, op, kept, n);
}

const GDEFSTOR_QueryNode * gdefcore_plan_and(GDEFCORE_Plan * plan,
    const GDEFSTOR_QueryNode * const * children, size_t count) {
  if (plan == NULL || (children == NULL && count != 0)) {
    return NULL;
  }
  return fold_list(plan, GDEFSTOR_QUERY_AND, children, count);
}

const GDEFSTOR_QueryNode * gdefcore_plan_or(GDEFCORE_Plan * plan,
    const GDEFSTOR_QueryNode * const * children, size_t count) {
  if (plan == NULL || (children == NULL && count != 0)) {
    return NULL;
  }
  return fold_list(plan, GDEFSTOR_QUERY_OR, children, count);
}

static const GDEFSTOR_QueryNode * mk_not(GDEFCORE_Plan * p,
    const GDEFSTOR_QueryNode * kid) {
  const GDEFSTOR_QueryNode * kids[1];
  const GDEFSTOR_QueryNode * yes = gdefcore_plan_constant(p, 1);
  const GDEFSTOR_QueryNode * no = gdefcore_plan_constant(p, 0);
  if (kid == NULL || yes == NULL || no == NULL) {
    return NULL;
  }
  if (kid == yes) {
    return no;
  }
  if (kid == no) {
    return yes;
  }
  kids[0] = kid;
  return list_node(p, GDEFSTOR_QUERY_NOT, kids, 1);
}

static const GDEFSTOR_QueryNode * mk_and2(GDEFCORE_Plan * p,
    const GDEFSTOR_QueryNode * a, const GDEFSTOR_QueryNode * b) {
  const GDEFSTOR_QueryNode * kids[2];
  kids[0] = a;
  kids[1] = b;
  return fold_list(p, GDEFSTOR_QUERY_AND, kids, 2);
}

static const GDEFSTOR_QueryNode * mk_or2(GDEFCORE_Plan * p,
    const GDEFSTOR_QueryNode * a, const GDEFSTOR_QueryNode * b) {
  const GDEFSTOR_QueryNode * kids[2];
  kids[0] = a;
  kids[1] = b;
  return fold_list(p, GDEFSTOR_QUERY_OR, kids, 2);
}

/* ---- operands ------------------------------------------------------------ */

static GDEFSTOR_QueryOperand const_operand(GDEFCORE_Plan * p,
    const char * const * texts, const size_t * lens, size_t count) {
  GDEFSTOR_QueryOperand o;
  GDEFSTOR_QueryText * t = NULL;
  size_t i;
  memset(&o, 0, sizeof o);
  o.kind = GDEFSTOR_QUERY_CONST;
  if (count > 0) {
    t = (GDEFSTOR_QueryText *)plan_mem(p, count * sizeof *t);
    if (t == NULL) {
      return o;
    }
    for (i = 0; i < count; i++) {
      t[i].bytes = (const uint8_t *)texts[i];
      t[i].len = lens[i];
    }
  }
  o.texts = t;
  o.text_count = count;
  return o;
}

static GDEFSTOR_QueryOperand one_text(GDEFCORE_Plan * p, const char * text,
    size_t len) {
  return const_operand(p, &text, &len, 1);
}

static GDEFSTOR_QueryOperand column_operand(const char * column,
    int in_record, int empty_if_none) {
  GDEFSTOR_QueryOperand o;
  memset(&o, 0, sizeof o);
  o.kind = GDEFSTOR_QUERY_COLUMN;
  o.column = column;
  o.column_len = strlen(column);
  if (in_record) {
    o.join_type = GDEFCORE_QUERY_RECORD_TYPE;
    o.join_type_len = sizeof GDEFCORE_QUERY_RECORD_TYPE - 1;
  }
  o.flags = empty_if_none ? GDEFSTOR_QUERY_EMPTY_IF_NONE : 0;
  return o;
}

static const GDEFSTOR_QueryNode * mk_cmp(GDEFCORE_Plan * p, int op,
    const GDEFSTOR_QueryOperand * l, const GDEFSTOR_QueryOperand * r) {
  GDEFSTOR_QueryNode * n = new_node(p, op);
  if (n == NULL || p->oom) {
    return NULL;
  }
  n->left = *l;
  n->right = *r;
  return n;
}

static const GDEFSTOR_QueryNode * pub_is(GDEFCORE_Plan * p, int value) {
  const GDEFSTOR_QueryNode ** slot = value ? &p->pub1 : &p->pub0;
  if (*slot == NULL) {
    GDEFSTOR_QueryOperand l = column_operand(GDEFCORE_QUERY_COL_PUBLISHED, 1, 0);
    GDEFSTOR_QueryOperand r = one_text(p, value ? "1" : "0", 1);
    *slot = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
  }
  return *slot;
}

const GDEFSTOR_QueryNode * gdefcore_plan_published(GDEFCORE_Plan * plan) {
  return plan == NULL ? NULL : pub_is(plan, 1);
}

const GDEFSTOR_QueryNode * gdefcore_plan_creator_is_principal(
    GDEFCORE_Plan * plan) {
  GDEFSTOR_QueryOperand l;
  GDEFSTOR_QueryOperand r;
  if (plan == NULL) {
    return NULL;
  }
  /* An anonymous request is nobody's: it matches no creator. */
  if (!plan->has_principal) {
    return gdefcore_plan_constant(plan, 0);
  }
  l = column_operand(GDEFCORE_QUERY_COL_CREATOR, 1, 0);
  r = one_text(plan, plan->principal, plan->principal_len);
  return mk_cmp(plan, GDEFSTOR_QUERY_EQ, &l, &r);
}

/* The field of the type: whether it exists, is personal, holds many. */
typedef struct FieldInfo {
  int found;
  int personal;
  int many;
} FieldInfo;

static int field_info(GDEFCORE_Plan * p, const char * name, size_t name_len,
    FieldInfo * out) {
  size_t count = 0;
  size_t i;
  memset(out, 0, sizeof *out);
  if (gdefcore_type_field_count(p->catalog, p->type, p->type_len, &count) !=
      GDEFCORE_OK) {
    return 1; /* cannot read the type: treated as no such field */
  }
  for (i = 0; i < count; i++) {
    char * got = NULL;
    size_t got_len = 0;
    int required = 0;
    int many = 0;
    int match;
    if (gdefcore_type_field(p->catalog, p->type, p->type_len, i, &got,
            &got_len, &required, &many) != GDEFCORE_OK) {
      return 1;
    }
    match = got_len == name_len && memcmp(got, name, name_len) == 0;
    gdefcore_text_free(p->catalog, got);
    if (match) {
      int personal = 0;
      out->found = 1;
      out->many = many;
      if (gdefcore_type_field_personal(p->catalog, p->type, p->type_len, i,
              &personal) != GDEFCORE_OK) {
        return 1;
      }
      out->personal = personal;
      return 0;
    }
  }
  return 0;
}

/* A field read as the evaluator reads it. Returns 0, or 1 when the field is one
 * the evaluator fails on (a personal field, or one the type lacks): the leaf
 * is then a failure. A field the plan cannot promise to read the same way is
 * marked unsupported. */
static int field_operand(GDEFCORE_Plan * p, const char * name, size_t name_len,
    int empty_if_none, GDEFSTOR_QueryOperand * out) {
  FieldInfo info;
  char * key1;
  char * key2;
  memset(out, 0, sizeof *out);
  if (field_info(p, name, name_len, &info) != 0 || !info.found ||
      info.personal) {
    return 1;
  }
  if (info.many && p->max_values > kMaxFieldValues) {
    /* The evaluator fails on a field with more than 64 values; the stored
     * document says nothing of how many a save was allowed. */
    p->unsupported = 1;
    return 1;
  }
  key1 = plan_str(p, p->lang, p->lang_len);
  key2 = plan_str(p, name, name_len);
  if (key1 == NULL || key2 == NULL) {
    return 1;
  }
  *out = column_operand(GDEFCORE_QUERY_COL_DOC, 0, empty_if_none);
  out->path_depth = 2;
  out->path1 = key1;
  out->path1_len = p->lang_len;
  out->path2 = key2;
  out->path2_len = name_len;
  return 0;
}

const GDEFSTOR_QueryNode * gdefcore_plan_field_is(GDEFCORE_Plan * plan,
    const char * field, size_t field_len, const char * text, size_t text_len) {
  GDEFSTOR_QueryOperand l;
  GDEFSTOR_QueryOperand r;
  if (plan == NULL || field == NULL || field_len == 0 ||
      (text == NULL && text_len != 0)) {
    return NULL;
  }
  if (field_operand(plan, field, field_len, 0, &l) != 0) {
    plan->unsupported = 1;
    return NULL;
  }
  /* "-" is the mark of an empty slot in a stored list, never a match. */
  if (text_len == 1 && text[0] == '-') {
    return gdefcore_plan_constant(plan, 0);
  }
  r = one_text(plan, text == NULL ? "" : text, text_len);
  return mk_cmp(plan, GDEFSTOR_QUERY_EQ, &l, &r);
}

const GDEFSTOR_QuerySort * gdefcore_plan_sort_field(GDEFCORE_Plan * plan,
    const char * field, size_t field_len, int descending) {
  GDEFSTOR_QuerySort * s;
  if (plan == NULL || field == NULL || field_len == 0) {
    return NULL;
  }
  s = (GDEFSTOR_QuerySort *)plan_mem(plan, sizeof *s);
  if (s == NULL) {
    return NULL;
  }
  if (field_operand(plan, field, field_len, 1, &s->key) != 0) {
    plan->unsupported = 1;
    return NULL;
  }
  s->descending = descending ? 1 : 0;
  return s;
}

/* ---- a condition --------------------------------------------------------- */

typedef struct Op {
  GDEFSTOR_QueryOperand op;
  int is_state;
  int fail;
} Op;

typedef struct VX {
  const GDEFSTOR_QueryNode * v;
  const GDEFSTOR_QueryNode * x; /* NULL: evaluation cannot fail here */
} VX;

static void make_operand(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * node, Op * out, int outer) {
  const char * text;
  memset(out, 0, sizeof *out);
  switch (node->kind) {
    case kText:
    case kInt:
      text = c->pool + node->str;
      out->op = const_operand(p, &text, &(size_t){node->str_len}, 1);
      return;
    case kType: {
      const char * t = p->type;
      size_t n = p->type_len;
      out->op = const_operand(p, &t, &n, 1);
      return;
    }
    case kNow: {
      char buf[32];
      int wn = snprintf(buf, sizeof buf, "%lld", (long long)p->now);
      char * keep;
      size_t n;
      if (wn <= 0 || (size_t)wn >= sizeof buf) {
        out->fail = 1;
        return;
      }
      keep = plan_str(p, buf, (size_t)wn);
      n = (size_t)wn;
      out->op = const_operand(p, (const char * const *)&keep, &n, 1);
      return;
    }
    case kPrincipal:
      if (p->has_principal) {
        const char * t = p->principal;
        size_t n = p->principal_len;
        out->op = const_operand(p, &t, &n, 1);
      } else {
        out->op = const_operand(p, NULL, NULL, 0);
      }
      return;
    case kCreator:
      out->op = column_operand(GDEFCORE_QUERY_COL_CREATOR, 1, 0);
      out->op.flags |= outer ? GDEFSTOR_QUERY_OUTER : 0;
      return;
    case kRevCreator:
      out->op = column_operand(GDEFCORE_QUERY_COL_REVISION_CREATOR, 0, 0);
      out->op.flags |= outer ? GDEFSTOR_QUERY_OUTER : 0;
      return;
    case kState:
      out->is_state = 1;
      return;
    case kField:
      out->fail = field_operand(p, c->pool + node->str, node->str_len, 1,
          &out->op);
      out->op.flags |= outer ? GDEFSTOR_QUERY_OUTER : 0;
      return;
    default:
      out->fail = 1;
      return;
  }
}

static VX failure(GDEFCORE_Plan * p) {
  VX r;
  p->failed = 1;
  r.v = gdefcore_plan_constant(p, 0);
  r.x = gdefcore_plan_constant(p, 1);
  return r;
}

static VX plain(const GDEFSTOR_QueryNode * v) {
  VX r;
  r.v = v;
  r.x = NULL;
  return r;
}

/* state compared with another operand: some text of the other side is the
 * entity's state ("published" when the flag is set, else "draft"). */
static const GDEFSTOR_QueryNode * state_equals(GDEFCORE_Plan * p,
    const GDEFSTOR_QueryOperand * other) {
  GDEFSTOR_QueryOperand published = one_text(p, "published", 9);
  GDEFSTOR_QueryOperand draft = one_text(p, "draft", 5);
  const GDEFSTOR_QueryNode * a = mk_cmp(p, GDEFSTOR_QUERY_EQ, other, &published);
  const GDEFSTOR_QueryNode * b = mk_cmp(p, GDEFSTOR_QUERY_EQ, other, &draft);
  return mk_or2(p, mk_and2(p, pub_is(p, 1), a), mk_and2(p, pub_is(p, 0), b));
}

static int cmp_op(int evaluator_op) {
  switch (evaluator_op) {
    case kEq:
      return GDEFSTOR_QUERY_EQ;
    case kNe:
      return GDEFSTOR_QUERY_NE;
    case kLt:
      return GDEFSTOR_QUERY_LT;
    case kLe:
      return GDEFSTOR_QUERY_LE;
    case kGt:
      return GDEFSTOR_QUERY_GT;
    default:
      return GDEFSTOR_QUERY_GE;
  }
}

/* ---- a relation ---------------------------------------------------------- */

/* The row's field as an operand of the relation rows: language and field. */
static GDEFSTOR_QueryOperand row_operand(const char * field) {
  GDEFSTOR_QueryOperand o = column_operand(GDEFCORE_QUERY_COL_DOC, 0, 0);
  o.path_depth = 2;
  o.path1 = GDEFCORE_RELATION_LANG;
  o.path1_len = strlen(GDEFCORE_RELATION_LANG);
  o.path2 = field;
  o.path2_len = strlen(field);
  return o;
}

/* The outer entity's published flag, from inside the semi-join. */
static const GDEFSTOR_QueryNode * outer_pub_is(GDEFCORE_Plan * p, int value) {
  const GDEFSTOR_QueryNode ** slot = value ? &p->outer_pub1 : &p->outer_pub0;
  if (*slot == NULL) {
    GDEFSTOR_QueryOperand l = column_operand(GDEFCORE_QUERY_COL_PUBLISHED, 1, 0);
    GDEFSTOR_QueryOperand r = one_text(p, value ? "1" : "0", 1);
    l.flags |= GDEFSTOR_QUERY_OUTER;
    *slot = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
  }
  return *slot;
}

/* Whether an enabled module declares the relation with this many columns. */
static int relation_declared(GDEFCORE_Plan * p, const char * name,
    size_t name_len, size_t arity) {
  GDEFCORE_Host * host = gdefcore_catalog_host(p->catalog);
  const GDEFCORE_Module_Declared_Relation ** items = NULL;
  size_t n = 0;
  size_t i;
  size_t tenant_len = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(p->catalog, &tenant_len);
  int ok = 0;
  if (host == NULL ||
      gdefcore_module_relations(host, tenant, tenant_len, NULL, &items, &n) !=
          GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (items[i]->name_len == name_len && memcmp(items[i]->name, name, name_len) == 0) {
      ok = items[i]->ncolumns == arity;
      break;
    }
  }
  gdefcore_module_declared_free(host, items);
  return ok;
}

static void note_relation(GDEFCORE_Plan * p, const char * name, size_t name_len) {
  size_t i;
  char * keep;
  for (i = 0; i < p->nrels; i++) {
    if (p->rel_lens[i] == name_len && memcmp(p->rels[i], name, name_len) == 0) {
      return;
    }
  }
  if (p->nrels >= sizeof p->rels / sizeof p->rels[0]) {
    p->unsupported = 1;
    return;
  }
  keep = plan_str(p, name, name_len);
  if (keep == NULL) {
    return;
  }
  p->rels[p->nrels] = keep;
  p->rel_lens[p->nrels] = name_len;
  p->nrels += 1;
}

size_t gdefcore_plan_relation_count(const GDEFCORE_Plan * plan) {
  return plan == NULL ? 0 : plan->nrels;
}

int gdefcore_plan_relation_at(const GDEFCORE_Plan * plan, size_t index,
    const char ** out_name, size_t * out_len) {
  if (plan == NULL || index >= plan->nrels || out_name == NULL || out_len == NULL) {
    return 0;
  }
  *out_name = plan->rels[index];
  *out_len = plan->rel_lens[index];
  return 1;
}

/*
 * (related "name" (operand ...)): there is a row of the relation whose columns
 * are among the operand's texts, as a semi-join over the active copies of the
 * relation's rows, with the entity being decided as the outer row. A relation
 * that no enabled module declares with this many columns, or an operand that
 * cannot be read, is a failure, as it is for the evaluator.
 */
static VX compile_related(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * n) {
  const CNode * name = &c->nodes[c->kids[n->first]];
  size_t arity = (size_t)n->count - 1;
  const GDEFSTOR_QueryNode * parts[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  size_t nparts = 0;
  size_t i;
  GDEFSTOR_QueryOperand l;
  GDEFSTOR_QueryOperand r;
  GDEFSTOR_QueryNode * exists;
  const GDEFSTOR_QueryNode * kids[1];
  const GDEFSTOR_QueryNode * inner;
  char * type;
  size_t type_len;
  if (arity == 0 || arity > GDEFCORE_RELATION_COLUMNS_MAX ||
      !relation_declared(p, c->pool + name->str, name->str_len, arity)) {
    return failure(p);
  }
  l = row_operand(GDEFCORE_RELATION_FIELD_NAME);
  r = one_text(p, c->pool + name->str, name->str_len);
  parts[nparts++] = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
  for (i = 0; i < arity; i++) {
    const CNode * operand = &c->nodes[c->kids[n->first + 1 + i]];
    Op o;
    if (operand->kind == kAny) {
      continue;
    }
    make_operand(p, c, operand, &o, 1);
    if (o.fail) {
      return failure(p);
    }
    l = row_operand(gdefcore_relation_column_field(i));
    if (o.is_state) {
      /* The column holds the state of the outer entity, as text. */
      GDEFSTOR_QueryOperand published = one_text(p, "published", 9);
      GDEFSTOR_QueryOperand draft = one_text(p, "draft", 5);
      const GDEFSTOR_QueryNode * a = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &published);
      const GDEFSTOR_QueryNode * b = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &draft);
      parts[nparts++] = mk_or2(p, mk_and2(p, outer_pub_is(p, 1), a),
          mk_and2(p, outer_pub_is(p, 0), b));
    } else {
      parts[nparts++] = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &o.op);
    }
  }
  for (i = 0; i < nparts; i++) {
    if (parts[i] == NULL) {
      return plain(NULL);
    }
  }
  inner = fold_list(p, GDEFSTOR_QUERY_AND, parts, nparts);
  if (inner == NULL) {
    return plain(NULL);
  }
  type_len = strlen(GDEFCORE_QUERY_ACTIVE_PREFIX) + strlen(GDEFCORE_RELATION_ROW_TYPE);
  type = (char *)plan_mem(p, type_len + 1);
  if (type == NULL) {
    return plain(NULL);
  }
  snprintf(type, type_len + 1, "%s%s", GDEFCORE_QUERY_ACTIVE_PREFIX,
      GDEFCORE_RELATION_ROW_TYPE);
  kids[0] = inner;
  exists = (GDEFSTOR_QueryNode *)list_node(p, GDEFSTOR_QUERY_EXISTS, kids, 1);
  if (exists == NULL) {
    return plain(NULL);
  }
  exists->exists_type = type;
  exists->exists_type_len = type_len;
  note_relation(p, c->pool + name->str, name->str_len);
  return plain(exists);
}

static VX compile_cmp(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * n) {
  Op a;
  Op b;
  make_operand(p, c, &c->nodes[c->kids[n->first]], &a, 0);
  make_operand(p, c, &c->nodes[c->kids[n->first + 1]], &b, 0);
  if (a.fail || b.fail) {
    return failure(p);
  }
  if (a.is_state || b.is_state) {
    const GDEFSTOR_QueryNode * eq;
    if (n->op != kEq && n->op != kNe) {
      /* A state is never an integer, so an ordered comparison is false. */
      return plain(gdefcore_plan_constant(p, 0));
    }
    if (a.is_state && b.is_state) {
      eq = gdefcore_plan_constant(p, 1);
    } else {
      eq = state_equals(p, a.is_state ? &b.op : &a.op);
    }
    return plain(n->op == kEq ? eq : mk_not(p, eq));
  }
  return plain(mk_cmp(p, cmp_op(n->op), &a.op, &b.op));
}

static VX compile_in(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * n) {
  Op a;
  const char ** texts;
  size_t * lens;
  size_t k;
  size_t members = n->count - 1;
  GDEFSTOR_QueryOperand list;
  make_operand(p, c, &c->nodes[c->kids[n->first]], &a, 0);
  if (a.fail) {
    return failure(p);
  }
  texts = (const char **)plan_mem(p, (members == 0 ? 1 : members) * sizeof *texts);
  lens = (size_t *)plan_mem(p, (members == 0 ? 1 : members) * sizeof *lens);
  if (texts == NULL || lens == NULL) {
    return plain(NULL);
  }
  for (k = 0; k < members; k++) {
    const CNode * m = &c->nodes[c->kids[n->first + 1 + k]];
    texts[k] = c->pool + m->str;
    lens[k] = m->str_len;
  }
  if (a.is_state) {
    int has_published = 0;
    int has_draft = 0;
    for (k = 0; k < members; k++) {
      has_published |= lens[k] == 9 && memcmp(texts[k], "published", 9) == 0;
      has_draft |= lens[k] == 5 && memcmp(texts[k], "draft", 5) == 0;
    }
    return plain(mk_or2(p,
        has_published ? pub_is(p, 1) : gdefcore_plan_constant(p, 0),
        has_draft ? pub_is(p, 0) : gdefcore_plan_constant(p, 0)));
  }
  list = const_operand(p, texts, lens, members);
  return plain(mk_cmp(p, GDEFSTOR_QUERY_IN, &a.op, &list));
}

/* The prefix of an and (or or): every earlier operand reached, undecided and
 * not failed. */
static const GDEFSTOR_QueryNode * reached(GDEFCORE_Plan * p, int is_and,
    const VX * kids, size_t upto) {
  const GDEFSTOR_QueryNode * acc = gdefcore_plan_constant(p, 1);
  size_t j;
  for (j = 0; j < upto && acc != NULL; j++) {
    const GDEFSTOR_QueryNode * step = is_and ? kids[j].v : mk_not(p, kids[j].v);
    acc = mk_and2(p, acc, step);
    if (kids[j].x != NULL && acc != NULL) {
      acc = mk_and2(p, acc, mk_not(p, kids[j].x));
    }
  }
  return acc;
}

static VX compile_node(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    int idx);

static VX compile_list(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * n, int is_and) {
  VX * kids;
  const GDEFSTOR_QueryNode ** vs;
  size_t k;
  VX out;
  const GDEFSTOR_QueryNode ** xs;
  size_t nx = 0;
  kids = (VX *)plan_mem(p, (n->count == 0 ? 1 : n->count) * sizeof *kids);
  vs = (const GDEFSTOR_QueryNode **)plan_mem(p,
      (n->count == 0 ? 1 : n->count) * sizeof *vs);
  xs = (const GDEFSTOR_QueryNode **)plan_mem(p,
      (n->count == 0 ? 1 : n->count) * sizeof *xs);
  if (kids == NULL || vs == NULL || xs == NULL) {
    return plain(NULL);
  }
  for (k = 0; k < n->count; k++) {
    kids[k] = compile_node(p, c, c->kids[n->first + k]);
    if (kids[k].v == NULL) {
      return plain(NULL);
    }
    vs[k] = kids[k].v;
  }
  for (k = 0; k < n->count; k++) {
    if (kids[k].x != NULL) {
      const GDEFSTOR_QueryNode * pre = reached(p, is_and, kids, k);
      const GDEFSTOR_QueryNode * term = mk_and2(p, pre, kids[k].x);
      if (term == NULL) {
        return plain(NULL);
      }
      xs[nx++] = term;
    }
  }
  out.v = fold_list(p, is_and ? GDEFSTOR_QUERY_AND : GDEFSTOR_QUERY_OR, vs,
      n->count);
  out.x = nx == 0 ? NULL : fold_list(p, GDEFSTOR_QUERY_OR, xs, nx);
  if (nx > 0 && out.x == NULL) {
    out.v = NULL;
  }
  return out;
}

static VX compile_node(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    int idx) {
  const CNode * n = &c->nodes[idx];
  VX r;
  if (p->unsupported || p->oom) {
    return plain(NULL);
  }
  switch (n->kind) {
    case kTrue:
      return plain(gdefcore_plan_constant(p, 1));
    case kFalse:
      return plain(gdefcore_plan_constant(p, 0));
    case kNot:
      r = compile_node(p, c, c->kids[n->first]);
      if (r.v != NULL) {
        r.v = mk_not(p, r.v);
      }
      return r;
    case kAnd:
      return compile_list(p, c, n, 1);
    case kOr:
      return compile_list(p, c, n, 0);
    case kCmp:
      return compile_cmp(p, c, n);
    case kIn:
      return compile_in(p, c, n);
    case kRelated:
      return compile_related(p, c, n);
    default:
      p->unsupported = 1;
      return plain(NULL);
  }
}

const GDEFSTOR_QueryNode * gdefcore_plan_condition(GDEFCORE_Plan * plan,
    const GDEFCORE_Condition * condition) {
  VX r;
  if (plan == NULL || condition == NULL) {
    return NULL;
  }
  r = compile_node(plan, condition, condition->root);
  if (plan->oom || plan->unsupported) {
    return NULL;
  }
  if (r.v == NULL) {
    if (!plan->oom) {
      plan->unsupported = 1;
    }
    return NULL;
  }
  if (r.x == NULL) {
    return r.v;
  }
  return mk_and2(plan, r.v, mk_not(plan, r.x));
}
