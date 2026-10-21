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
 * A condition compiled into the storage port's query form over entities
 * (plan.h, defiant-storage query.h). The evaluator in
 * condition_eval.c is the reference: the compiled predicate must select the
 * entities it holds on. Field operands are typed: condition_internal.h says
 * how both read a comparison, and the port's flags (EMPTY_IF_NONE, AS_TEXT)
 * are how a typed operand is read as the evaluator's texts.
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

/* Typed constants, copied into the plan. A text points at plan memory. */
static GDEFSTOR_QueryOperand values_operand(GDEFCORE_Plan * p,
    const GDEFSTOR_Value * values, size_t count) {
  GDEFSTOR_QueryOperand o;
  GDEFSTOR_Value * v = NULL;
  size_t i;
  memset(&o, 0, sizeof o);
  o.kind = GDEFSTOR_QUERY_VALUES;
  if (count > 0) {
    v = (GDEFSTOR_Value *)plan_mem(p, count * sizeof *v);
    if (v == NULL) {
      return o;
    }
    for (i = 0; i < count; i++) {
      v[i] = values[i];
      if (values[i].len > 0) {
        char * keep = plan_str(p, (const char *)values[i].bytes, values[i].len);
        if (keep == NULL) {
          return o;
        }
        v[i].bytes = (const uint8_t *)keep;
      }
    }
  }
  o.values = v;
  o.value_count = count;
  return o;
}

static GDEFSTOR_QueryOperand text_operand(GDEFCORE_Plan * p, const char * text,
    size_t len) {
  GDEFSTOR_Value v;
  memset(&v, 0, sizeof v);
  v.type = GDEFSTOR_FIELD_TEXT;
  v.bytes = (const uint8_t *)text;
  v.len = len;
  return values_operand(p, &v, 1);
}

static GDEFSTOR_QueryOperand meta_operand(int meta, int flags) {
  GDEFSTOR_QueryOperand o;
  memset(&o, 0, sizeof o);
  o.kind = GDEFSTOR_QUERY_META;
  o.meta = meta;
  o.flags = flags;
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

/* The published fact of the entity (@p outer: of the outer entity, from
 * inside an EXISTS) is @p value. */
static const GDEFSTOR_QueryNode * pub_node(GDEFCORE_Plan * p, int value,
    int outer) {
  const GDEFSTOR_QueryNode ** slot =
      outer ? (value ? &p->outer_pub1 : &p->outer_pub0)
            : (value ? &p->pub1 : &p->pub0);
  if (*slot == NULL) {
    GDEFSTOR_QueryOperand l = meta_operand(GDEFSTOR_META_PUBLISHED,
        outer ? GDEFSTOR_QUERY_OUTER : 0);
    GDEFSTOR_Value v;
    GDEFSTOR_QueryOperand r;
    memset(&v, 0, sizeof v);
    v.type = GDEFSTOR_FIELD_BOOLEAN;
    v.integer = value ? 1 : 0;
    r = values_operand(p, &v, 1);
    *slot = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
  }
  return *slot;
}

static const GDEFSTOR_QueryNode * pub_is(GDEFCORE_Plan * p, int value) {
  return pub_node(p, value, 0);
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
  l = meta_operand(GDEFSTOR_META_CREATOR, GDEFSTOR_QUERY_AS_TEXT);
  r = text_operand(plan, plan->principal, plan->principal_len);
  return mk_cmp(plan, GDEFSTOR_QUERY_EQ, &l, &r);
}

/* A field read as the evaluator reads it. Returns 0, or 1 when the field is one
 * the evaluator fails on (a personal field, or one the type lacks): the leaf
 * is then a failure. A field the plan cannot promise to read the same way is
 * marked unsupported. A field an access callback governs is one the
 * evaluator fails on (story A6). @p info receives what the field is. */
static int field_operand(GDEFCORE_Plan * p, const char * name, size_t name_len,
    CondField * info, GDEFSTOR_QueryOperand * out) {
  char * key;
  memset(out, 0, sizeof *out);
  if (cond_field_info(p->catalog, p->type, p->type_len, name, name_len, info) !=
          0 ||
      !info->found || info->personal || info->governed) {
    return 1;
  }
  if (info->many && p->max_values > kMaxFieldValues) {
    /* The evaluator fails on a field with more than 64 values; the stored
     * tree says nothing of how many a save was allowed. */
    p->unsupported = 1;
    return 1;
  }
  key = plan_str(p, name, name_len);
  if (key == NULL) {
    return 1;
  }
  out->kind = GDEFSTOR_QUERY_FIELD;
  out->field = key;
  out->field_len = name_len;
  return 0;
}

/* A field with no value: it does not equal itself. */
static const GDEFSTOR_QueryNode * field_none(GDEFCORE_Plan * p,
    const GDEFSTOR_QueryOperand * f) {
  return mk_not(p, mk_cmp(p, GDEFSTOR_QUERY_EQ, f, f));
}

const GDEFSTOR_QueryNode * gdefcore_plan_field_is(GDEFCORE_Plan * plan,
    const char * field, size_t field_len, const char * text, size_t text_len) {
  GDEFSTOR_QueryOperand l;
  GDEFSTOR_QueryOperand r;
  CondField info;
  GDEFSTOR_Value v;
  if (plan == NULL || field == NULL || field_len == 0 ||
      (text == NULL && text_len != 0)) {
    return NULL;
  }
  if (field_operand(plan, field, field_len, &info, &l) != 0) {
    plan->unsupported = 1;
    return NULL;
  }
  /* "-" is the mark of an empty slot in a stored list, never a match. */
  if (text_len == 1 && text[0] == '-') {
    return gdefcore_plan_constant(plan, 0);
  }
  if (cond_texty_type(info.type)) {
    if (info.type == GDEFSTOR_FIELD_REFERENCE) {
      l.flags |= GDEFSTOR_QUERY_AS_TEXT;
    }
    r = text_operand(plan, text == NULL ? "" : text, text_len);
    return mk_cmp(plan, GDEFSTOR_QUERY_EQ, &l, &r);
  }
  /* A text that is no value of the field's type is equal to none of its. */
  if (text_len == 0 ||
      gdefcore_value_parse(info.type, info.scale, text, text_len, &v) !=
          GDEFCORE_OK) {
    return gdefcore_plan_constant(plan, 0);
  }
  r = values_operand(plan, &v, 1);
  return mk_cmp(plan, GDEFSTOR_QUERY_EQ, &l, &r);
}

const GDEFSTOR_QuerySort * gdefcore_plan_sort_field(GDEFCORE_Plan * plan,
    const char * field, size_t field_len, int descending) {
  GDEFSTOR_QuerySort * s;
  CondField info;
  if (plan == NULL || field == NULL || field_len == 0) {
    return NULL;
  }
  s = (GDEFSTOR_QuerySort *)plan_mem(plan, sizeof *s);
  if (s == NULL) {
    return NULL;
  }
  if (field_operand(plan, field, field_len, &info, &s->key) != 0) {
    plan->unsupported = 1;
    return NULL;
  }
  if (cond_texty_type(info.type)) {
    s->key.flags |= GDEFSTOR_QUERY_EMPTY_IF_NONE;
  }
  if (info.many) {
    s->key.flags |= GDEFSTOR_QUERY_FIRST;
  }
  s->descending = descending ? 1 : 0;
  return s;
}

/* ---- a condition --------------------------------------------------------- */

/*
 * An operand: a constant the plan knows (a text, an integer, `type`, `now`,
 * `principal`), `state`, or something of the entity the port reads (a field,
 * `creator`, `revision.creator`).
 */
typedef struct Op {
  int kind;            /* the node's kind */
  int fail;
  int known;           /* a constant: text/len, or none when !has_text */
  int has_text;
  const char * text;
  size_t len;
  int64_t now;         /* kNow */
  CondField f;         /* kField */
  GDEFSTOR_QueryOperand op; /* a field or a META fact */
} Op;

typedef struct VX {
  const GDEFSTOR_QueryNode * v;
  const GDEFSTOR_QueryNode * x; /* NULL: evaluation cannot fail here */
} VX;

static void make_operand(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * node, Op * out, int outer) {
  int flag = outer ? GDEFSTOR_QUERY_OUTER : 0;
  memset(out, 0, sizeof *out);
  out->kind = node->kind;
  switch (node->kind) {
    case kText:
    case kInt:
      out->known = 1;
      out->has_text = 1;
      out->text = c->pool + node->str;
      out->len = node->str_len;
      return;
    case kType:
      out->known = 1;
      out->has_text = 1;
      out->text = p->type;
      out->len = p->type_len;
      return;
    case kNow: {
      char buf[32];
      int wn = snprintf(buf, sizeof buf, "%lld", (long long)p->now);
      if (wn <= 0 || (size_t)wn >= sizeof buf) {
        out->fail = 1;
        return;
      }
      out->known = 1;
      out->has_text = 1;
      out->text = plan_str(p, buf, (size_t)wn);
      out->len = (size_t)wn;
      out->now = p->now;
      if (out->text == NULL) {
        out->fail = 1;
      }
      return;
    }
    case kPrincipal:
      out->known = 1;
      out->has_text = p->has_principal;
      out->text = p->principal;
      out->len = p->principal_len;
      return;
    case kCreator:
      out->op = meta_operand(GDEFSTOR_META_CREATOR, flag);
      return;
    case kRevCreator:
      out->op = meta_operand(GDEFSTOR_META_REVISION_WHO, flag);
      return;
    case kState:
      return;
    case kField:
      out->fail = field_operand(p, c->pool + node->str, node->str_len, &out->f,
          &out->op);
      out->op.flags |= flag;
      return;
    default:
      out->fail = 1;
      return;
  }
}

/* A non-texty field: compared in its type. */
static int op_typed(const Op * o) {
  return o->kind == kField && !cond_texty_type(o->f.type);
}

static int op_ident(const Op * o) {
  return o->kind == kPrincipal || o->kind == kCreator || o->kind == kRevCreator;
}

/* The operand as a text-typed port operand, the evaluator's bytes. */
static GDEFSTOR_QueryOperand as_text(GDEFCORE_Plan * p, const Op * o) {
  GDEFSTOR_QueryOperand r;
  if (o->known) {
    if (!o->has_text) {
      memset(&r, 0, sizeof r);
      r.kind = GDEFSTOR_QUERY_VALUES; /* none: equal to nothing */
      return r;
    }
    return text_operand(p, o->text, o->len);
  }
  r = o->op;
  if (o->kind == kField) {
    r.flags |= GDEFSTOR_QUERY_EMPTY_IF_NONE;
    if (o->f.type == GDEFSTOR_FIELD_REFERENCE) {
      r.flags |= GDEFSTOR_QUERY_AS_TEXT;
    }
  } else {
    r.flags |= GDEFSTOR_QUERY_AS_TEXT;
  }
  return r;
}

/* A known operand as a value of @p f's type, as the evaluator's as_type(). */
static int known_as(const Op * o, const CondField * f, GDEFSTOR_Value * out) {
  if (op_ident(o) || !o->known || !o->has_text) {
    return 0;
  }
  if (o->kind == kNow) {
    return cond_now_as(f->type, f->scale, o->now, out);
  }
  if (o->len == 0) {
    return 2;
  }
  return gdefcore_value_parse(f->type, f->scale, o->text, o->len, out) ==
         GDEFCORE_OK;
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

static int span_same(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

/* Two known operands, decided here as the evaluator decides them. */
static int known_holds(int op, const Op * a, const Op * b) {
  int64_t x;
  int64_t y;
  if (!a->has_text || !b->has_text) {
    return 0;
  }
  if (op == kEq) {
    return span_same(a->text, a->len, b->text, b->len);
  }
  if (!cond_parse_int(a->text, a->len, &x) ||
      !cond_parse_int(b->text, b->len, &y)) {
    return 0;
  }
  switch (op) {
    case kLt:
      return x < y;
    case kLe:
      return x <= y;
    case kGt:
      return x > y;
    default:
      return x >= y;
  }
}

/* `state` equal to some text of the other side ("published" when the
 * published fact is set, else "draft"); @p outer reads the outer entity's. */
static const GDEFSTOR_QueryNode * state_equals(GDEFCORE_Plan * p,
    const GDEFSTOR_QueryOperand * other, int outer) {
  GDEFSTOR_QueryOperand published = text_operand(p, "published", 9);
  GDEFSTOR_QueryOperand draft = text_operand(p, "draft", 5);
  const GDEFSTOR_QueryNode * a = mk_cmp(p, GDEFSTOR_QUERY_EQ, other, &published);
  const GDEFSTOR_QueryNode * b = mk_cmp(p, GDEFSTOR_QUERY_EQ, other, &draft);
  return mk_or2(p, mk_and2(p, pub_node(p, 1, outer), a),
      mk_and2(p, pub_node(p, 0, outer), b));
}

/* `state` equal to a known text. */
static const GDEFSTOR_QueryNode * state_is_known(GDEFCORE_Plan * p,
    const Op * o) {
  if (!o->has_text) {
    return gdefcore_plan_constant(p, 0);
  }
  if (span_same(o->text, o->len, "published", 9)) {
    return pub_is(p, 1);
  }
  if (span_same(o->text, o->len, "draft", 5)) {
    return pub_is(p, 0);
  }
  return gdefcore_plan_constant(p, 0);
}

/* kEq or an ordering, read in a typed field's type (any_typed()). */
static const GDEFSTOR_QueryNode * typed_cmp(GDEFCORE_Plan * p, int op,
    const Op * a, const Op * b) {
  const Op * field = op_typed(a) ? a : b;
  const Op * other = field == a ? b : a;
  GDEFSTOR_Value v;
  GDEFSTOR_QueryOperand k;
  int r;
  if (a->kind == kField && b->kind == kField) {
    const GDEFSTOR_QueryNode * n = mk_cmp(p, cmp_op(op), &a->op, &b->op);
    if (op != kEq) {
      return n;
    }
    /* Two fields with no value are each the empty text, and equal. */
    return mk_or2(p, n,
        mk_and2(p, field_none(p, &a->op), field_none(p, &b->op)));
  }
  r = known_as(other, &field->f, &v);
  if (r == 0) {
    return gdefcore_plan_constant(p, 0);
  }
  if (r == 2) {
    return op == kEq ? field_none(p, &field->op)
                     : gdefcore_plan_constant(p, 0);
  }
  k = values_operand(p, &v, 1);
  return field == a ? mk_cmp(p, cmp_op(op), &field->op, &k)
                    : mk_cmp(p, cmp_op(op), &k, &field->op);
}

static VX compile_cmp(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * n) {
  Op a;
  Op b;
  int ordered = n->op != kEq && n->op != kNe;
  int op = n->op == kNe ? kEq : n->op;
  const GDEFSTOR_QueryNode * r;
  make_operand(p, c, &c->nodes[c->kids[n->first]], &a, 0);
  make_operand(p, c, &c->nodes[c->kids[n->first + 1]], &b, 0);
  if (a.fail || b.fail) {
    return failure(p);
  }
  if ((a.kind == kField && b.kind == kField &&
          !cond_types_meet(a.f.type, a.f.scale, b.f.type, b.f.scale)) ||
      (ordered && ((a.kind == kField && !cond_numeric_type(a.f.type)) ||
                      (b.kind == kField && !cond_numeric_type(b.f.type))))) {
    return failure(p);
  }
  if (a.kind == kState || b.kind == kState) {
    const Op * other = a.kind == kState ? &b : &a;
    if (ordered) {
      /* A state is no integer and no value of any typed field. */
      return plain(gdefcore_plan_constant(p, 0));
    }
    if (a.kind == kState && b.kind == kState) {
      r = gdefcore_plan_constant(p, 1);
    } else if (op_typed(other)) {
      r = gdefcore_plan_constant(p, 0);
    } else if (other->known) {
      r = state_is_known(p, other);
    } else {
      GDEFSTOR_QueryOperand t = as_text(p, other);
      r = state_equals(p, &t, 0);
    }
  } else if (op_typed(&a) || op_typed(&b)) {
    r = typed_cmp(p, op, &a, &b);
  } else if (a.known && b.known) {
    r = gdefcore_plan_constant(p, known_holds(op, &a, &b));
  } else if (ordered) {
    /* Bytes read as integers: an identifier is never one. Only creator and
     * revision.creator reach here (a text field fails above). */
    r = gdefcore_plan_constant(p, 0);
  } else {
    GDEFSTOR_QueryOperand l = as_text(p, &a);
    GDEFSTOR_QueryOperand rt = as_text(p, &b);
    r = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &rt);
  }
  return plain(n->op == kNe ? mk_not(p, r) : r);
}

static VX compile_in(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * n) {
  Op a;
  size_t k;
  size_t members = n->count - 1;
  GDEFSTOR_Value * vals;
  size_t nvals = 0;
  int has_empty = 0;
  make_operand(p, c, &c->nodes[c->kids[n->first]], &a, 0);
  if (a.fail) {
    return failure(p);
  }
  vals = (GDEFSTOR_Value *)plan_mem(p,
      (members == 0 ? 1 : members) * sizeof *vals);
  if (vals == NULL) {
    return plain(NULL);
  }
  if (a.kind == kState) {
    int has_published = 0;
    int has_draft = 0;
    for (k = 0; k < members; k++) {
      const CNode * m = &c->nodes[c->kids[n->first + 1 + k]];
      has_published |= span_same(c->pool + m->str, m->str_len, "published", 9);
      has_draft |= span_same(c->pool + m->str, m->str_len, "draft", 5);
    }
    return plain(mk_or2(p,
        has_published ? pub_is(p, 1) : gdefcore_plan_constant(p, 0),
        has_draft ? pub_is(p, 0) : gdefcore_plan_constant(p, 0)));
  }
  if (a.known) {
    int hit = 0;
    for (k = 0; k < members && a.has_text; k++) {
      const CNode * m = &c->nodes[c->kids[n->first + 1 + k]];
      hit |= span_same(a.text, a.len, c->pool + m->str, m->str_len);
    }
    return plain(gdefcore_plan_constant(p, hit));
  }
  for (k = 0; k < members; k++) {
    const CNode * m = &c->nodes[c->kids[n->first + 1 + k]];
    GDEFSTOR_Value * v = &vals[nvals];
    memset(v, 0, sizeof *v);
    if (!op_typed(&a)) {
      v->type = GDEFSTOR_FIELD_TEXT;
      v->bytes = (const uint8_t *)(c->pool + m->str);
      v->len = m->str_len;
      nvals += 1;
    } else if (m->str_len == 0) {
      has_empty = 1;
    } else if (gdefcore_value_parse(a.f.type, a.f.scale, c->pool + m->str,
                   m->str_len, v) == GDEFCORE_OK) {
      nvals += 1;
    }
  }
  {
    GDEFSTOR_QueryOperand l = op_typed(&a) ? a.op : as_text(p, &a);
    GDEFSTOR_QueryOperand list = values_operand(p, vals, nvals);
    const GDEFSTOR_QueryNode * some = nvals == 0
                                          ? gdefcore_plan_constant(p, 0)
                                          : mk_cmp(p, GDEFSTOR_QUERY_IN, &l, &list);
    if (has_empty) {
      some = mk_or2(p, some, field_none(p, &a.op));
    }
    return plain(some);
  }
}

/* ---- a relation ---------------------------------------------------------- */

/* Whether an enabled module declares the relation with this many columns, and
 * the kinds of its columns. */
static int relation_declared(GDEFCORE_Plan * p, const char * name,
    size_t name_len, size_t arity, int * kinds) {
  GDEFCORE_Host * host = gdefcore_catalog_host(p->catalog);
  const GDEFCORE_Module_Declared_Relation ** items = NULL;
  size_t n = 0;
  size_t i;
  size_t k;
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
      for (k = 0; ok && k < arity; k++) {
        kinds[k] = items[i]->columns[k].kind;
      }
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

static GDEFSTOR_QueryOperand row_field(const char * name, int flags) {
  GDEFSTOR_QueryOperand o;
  memset(&o, 0, sizeof o);
  o.kind = GDEFSTOR_QUERY_FIELD;
  o.field = name;
  o.field_len = strlen(name);
  o.flags = flags;
  return o;
}

/* Column @p i of a row equal to some text of operand @p o of the outer
 * entity, as the evaluator's port query asks it. */
static const GDEFSTOR_QueryNode * column_is(GDEFCORE_Plan * p, size_t i,
    int kind, const Op * o) {
  GDEFSTOR_QueryOperand l;
  GDEFSTOR_QueryOperand r;
  GDEFSTOR_Value v;
  if (kind == GDEFCORE_RELATION_INTEGER) {
    l = row_field(gdefcore_relation_number_field(i), 0);
    if (o->kind == kField) {
      if (o->f.type != GDEFSTOR_FIELD_INTEGER) {
        /* Refused at validation: the evaluator reads its texts as integers,
         * which no port comparison says. */
        p->unsupported = 1;
        return NULL;
      }
      return mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &o->op);
    }
    memset(&v, 0, sizeof v);
    v.type = GDEFSTOR_FIELD_INTEGER;
    if (!o->known || !o->has_text ||
        !cond_parse_int(o->text, o->len, &v.integer)) {
      /* creator, revision.creator, state: never an integer. */
      return gdefcore_plan_constant(p, 0);
    }
    r = values_operand(p, &v, 1);
    return mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
  }
  l = row_field(gdefcore_relation_column_field(i), GDEFSTOR_QUERY_EMPTY_IF_NONE);
  if (o->kind == kState) {
    return state_equals(p, &l, 1);
  }
  if (op_typed(o)) {
    p->unsupported = 1; /* refused at validation */
    return NULL;
  }
  r = as_text(p, o);
  return mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
}

/*
 * (related "name" (operand ...)): there is a row of the relation whose columns
 * are among the operand's texts, as an EXISTS over the relation's rows (read
 * in their own language), with the entity being decided as the outer row. A
 * relation that no enabled module declares with this many columns, or an
 * operand that cannot be read, is a failure, as it is for the evaluator.
 */
static VX compile_related(GDEFCORE_Plan * p, const GDEFCORE_Condition * c,
    const CNode * n) {
  const CNode * name = &c->nodes[c->kids[n->first]];
  size_t arity = (size_t)n->count - 1;
  const GDEFSTOR_QueryNode * parts[3 + GDEFCORE_RELATION_COLUMNS_MAX];
  int kinds[GDEFCORE_RELATION_COLUMNS_MAX];
  GDEFSTOR_Value live[2];
  size_t nparts = 0;
  size_t i;
  int row_kind = 0;
  GDEFSTOR_QueryOperand l;
  GDEFSTOR_QueryOperand r;
  GDEFSTOR_QueryNode * exists;
  const GDEFSTOR_QueryNode * kids[1];
  const GDEFSTOR_QueryNode * inner;
  if (arity == 0 || arity > GDEFCORE_RELATION_COLUMNS_MAX ||
      !relation_declared(p, c->pool + name->str, name->str_len, arity, kinds)) {
    return failure(p);
  }
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
    parts[1 + nparts++] = column_is(p, i, kinds[i], &o);
    if (parts[nparts] == NULL) {
      return plain(NULL);
    }
  }
  note_relation(p, c->pool + name->str, name->str_len);
  if (gdefcore_type_kind(p->catalog, GDEFCORE_RELATION_ROW_TYPE,
          strlen(GDEFCORE_RELATION_ROW_TYPE), &row_kind) != GDEFCORE_OK) {
    /* No relation has ever had a row: there is none to find. */
    return plain(gdefcore_plan_constant(p, 0));
  }
  l = row_field(GDEFCORE_RELATION_FIELD_NAME, 0);
  r = text_operand(p, c->pool + name->str, name->str_len);
  parts[0] = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
  if (parts[0] == NULL) {
    return plain(NULL);
  }
  /* A row that is there now: saved and not removed, as
   * gdefcore_entity_query_current() reads them for the evaluator. */
  memset(live, 0, sizeof live);
  live[0].type = GDEFSTOR_FIELD_BOOLEAN;
  live[1].type = GDEFSTOR_FIELD_INTEGER;
  live[1].integer = 1;
  l = meta_operand(GDEFSTOR_META_DELETED, 0);
  r = values_operand(p, &live[0], 1);
  parts[1 + nparts] = mk_cmp(p, GDEFSTOR_QUERY_EQ, &l, &r);
  l = meta_operand(GDEFSTOR_META_REVISION, 0);
  r = values_operand(p, &live[1], 1);
  parts[2 + nparts] = mk_cmp(p, GDEFSTOR_QUERY_GE, &l, &r);
  if (parts[1 + nparts] == NULL || parts[2 + nparts] == NULL) {
    return plain(NULL);
  }
  inner = fold_list(p, GDEFSTOR_QUERY_AND, parts, 3 + nparts);
  if (inner == NULL) {
    return plain(NULL);
  }
  if (inner == gdefcore_plan_constant(p, 0)) {
    return plain(inner);
  }
  kids[0] = inner;
  exists = (GDEFSTOR_QueryNode *)list_node(p, GDEFSTOR_QUERY_EXISTS, kids, 1);
  if (exists == NULL) {
    return plain(NULL);
  }
  exists->exists_type = GDEFCORE_RELATION_ROW_TYPE;
  exists->exists_type_len = strlen(GDEFCORE_RELATION_ROW_TYPE);
  exists->exists_language = GDEFCORE_RELATION_LANG;
  exists->exists_language_len = strlen(GDEFCORE_RELATION_LANG);
  return plain(exists);
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
