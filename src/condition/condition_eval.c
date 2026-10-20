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
 * The condition evaluator. It evaluates on one entity, read as the system, and
 * it fails closed: anything it cannot interpret is "does not hold", and a
 * failure is also reported through a flag, never as a grant.
 *
 * An operand is a set of texts. `type`, `state`, `now` and constants are one
 * text. `creator`, `revision.creator` and `principal` are one text, or none
 * when there is no creator or no principal, so that an absent creator and an
 * anonymous request are never equal. A field is its values in the call's
 * language, each the canonical text of the field's logical type, or the
 * single empty text when it has none. A comparison holds when some text on
 * the left stands in the stated relation to some text on the right, read as
 * condition_internal.h says: by bytes when no side is a field of a type other
 * than text and reference, in that type when one is.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/relation.h>

#include "condition_internal.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct Span {
  const char * p;
  size_t n;
} Span;

typedef struct Vals {
  Span v[kMaxFieldValues];
  size_t n;
  int kind;        /* the operand node's kind */
  CondField f;     /* kField: what the field is */
  int64_t now;     /* kNow: the request time */
  char ** texts;
  size_t * lens;
  size_t ntexts;
  char num[24];
} Vals;

typedef struct Ctx {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Request * request;
  const GDEFCORE_Condition * c;
  const char * lang;
  size_t lang_len;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int real;               /* an entity, as opposed to a hypothetical one */
  const char * type;      /* the type name (owned when type_owned) */
  size_t type_len;
  char * type_owned;
  int actor_loaded;       /* revision.creator */
  char * actor;
  size_t actor_len;
  int creator_loaded;     /* creator */
  char * creator;
  size_t creator_len;
  int state_loaded;
  int state;
  int failed;
} Ctx;

static const char kEmpty[] = "";

static int ctx_fail(Ctx * ctx) {
  ctx->failed = 1;
  return 0;
}

static void vals_free(Ctx * ctx, Vals * vals) {
  if (vals->texts != NULL) {
    gdefcore_values_free(ctx->catalog, vals->texts, vals->lens, vals->ntexts);
  }
  vals->texts = NULL;
  vals->lens = NULL;
  vals->ntexts = 0;
  vals->n = 0;
}

static void vals_one(Vals * vals, const char * p, size_t n) {
  vals->v[0].p = p;
  vals->v[0].n = n;
  vals->n = 1;
}

/* The field's values, or the single empty text when it has none. */
static int read_field(Ctx * ctx, const CNode * node, Vals * vals) {
  const char * name = ctx->c->pool + node->str;
  size_t name_len = node->str_len;
  size_t i;
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (cond_field_info(ctx->catalog, ctx->type, ctx->type_len, name, name_len,
          &vals->f) != 0 ||
      !vals->f.found || vals->f.personal) {
    /* A personal value is ciphertext: never compare it. */
    return ctx_fail(ctx);
  }
  if (!ctx->real) {
    vals_one(vals, kEmpty, 0);
    return 1;
  }
  /* The active revision, whether or not the entity is published: a condition
   * is about what the entity is, and whether readers may see it is a separate
   * question the reader-facing actions ask for themselves. The NULL is the
   * changeset: staged data can never enter. */
  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_ACTIVE,
      ctx->id, GDEFCORE_PUBLIC_ID_LEN, ctx->lang, ctx->lang_len, name,
      name_len, &texts, &lens, &n);
  if (rc == GDEFCORE_ERR_INVALID) {
    vals_one(vals, kEmpty, 0);
    return 1;
  }
  if (rc != GDEFCORE_OK) {
    return ctx_fail(ctx);
  }
  if (n == 0) {
    gdefcore_values_free(ctx->catalog, texts, lens, n);
    vals_one(vals, kEmpty, 0);
    return 1;
  }
  if (n > kMaxFieldValues) {
    gdefcore_values_free(ctx->catalog, texts, lens, n);
    return ctx_fail(ctx);
  }
  vals->texts = texts;
  vals->lens = lens;
  vals->ntexts = n;
  for (i = 0; i < n; i++) {
    vals->v[i].p = texts[i];
    vals->v[i].n = lens[i];
  }
  vals->n = n;
  return 1;
}

/* Fill @p vals for an operand node. 0 on failure (ctx->failed is set). */
static int operand(Ctx * ctx, int idx, Vals * vals) {
  const CNode * node = &ctx->c->nodes[idx];
  const char * p;
  size_t n = 0;
  memset(vals, 0, offsetof(Vals, num));
  vals->kind = node->kind;
  switch (node->kind) {
    case kText:
    case kInt:
      vals_one(vals, ctx->c->pool + node->str, node->str_len);
      return 1;
    case kType:
      vals_one(vals, ctx->type, ctx->type_len);
      return 1;
    case kNow: {
      int wn;
      vals->now = gdefcore_request_time(ctx->request);
      wn = snprintf(vals->num, sizeof vals->num, "%lld", (long long)vals->now);
      if (wn <= 0 || (size_t)wn >= sizeof vals->num) {
        return ctx_fail(ctx);
      }
      vals_one(vals, vals->num, (size_t)wn);
      return 1;
    }
    case kPrincipal:
      p = gdefcore_request_principal(ctx->request, &n);
      if (p != NULL && n > 0) {
        vals_one(vals, p, n);
      }
      return 1;
    case kCreator:
      if (!ctx->creator_loaded) {
        if (ctx->real &&
            gdefcore_entity_creator(ctx->catalog, ctx->id,
                GDEFCORE_PUBLIC_ID_LEN, &ctx->creator, &ctx->creator_len) !=
                GDEFCORE_OK) {
          return ctx_fail(ctx);
        }
        ctx->creator_loaded = 1;
      }
      if (ctx->creator != NULL && ctx->creator_len > 0) {
        vals_one(vals, ctx->creator, ctx->creator_len);
      }
      return 1;
    case kRevCreator:
      if (!ctx->actor_loaded) {
        if (ctx->real &&
            gdefcore_entity_actor(ctx->catalog, ctx->id,
                GDEFCORE_PUBLIC_ID_LEN, &ctx->actor, &ctx->actor_len) !=
                GDEFCORE_OK) {
          return ctx_fail(ctx);
        }
        ctx->actor_loaded = 1;
      }
      if (ctx->actor != NULL && ctx->actor_len > 0) {
        vals_one(vals, ctx->actor, ctx->actor_len);
      }
      return 1;
    case kState:
      if (!ctx->state_loaded) {
        ctx->state = 0;
        if (ctx->real &&
            gdefcore_entity_state(ctx->catalog, ctx->id,
                GDEFCORE_PUBLIC_ID_LEN, &ctx->state) != GDEFCORE_OK) {
          return ctx_fail(ctx);
        }
        ctx->state_loaded = 1;
      }
      if (ctx->state == GDEFCORE_STATE_PUBLISHED) {
        vals_one(vals, "published", 9);
      } else if (ctx->state == GDEFCORE_STATE_DRAFT) {
        vals_one(vals, "draft", 5);
      }
      return 1;
    case kField:
      return read_field(ctx, node, vals);
    default:
      return ctx_fail(ctx);
  }
}

static int same_text(Span a, Span b) {
  return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0);
}

static int any_equal(const Vals * a, const Vals * b) {
  size_t i;
  size_t j;
  for (i = 0; i < a->n; i++) {
    for (j = 0; j < b->n; j++) {
      if (same_text(a->v[i], b->v[j])) {
        return 1;
      }
    }
  }
  return 0;
}

static int op_holds(int op, int64_t x, int64_t y) {
  switch (op) {
    case kLt:
      return x < y;
    case kLe:
      return x <= y;
    case kGt:
      return x > y;
    case kGe:
      return x >= y;
    default:
      return 0;
  }
}

/* Some pair of integers on the two sides stands in the relation. A side that
 * is not an integer makes that pair false, never an error. */
static int any_ordered(int op, const Vals * a, const Vals * b) {
  size_t i;
  size_t j;
  for (i = 0; i < a->n; i++) {
    int64_t x;
    if (!cond_parse_int(a->v[i].p, a->v[i].n, &x)) {
      continue;
    }
    for (j = 0; j < b->n; j++) {
      int64_t y;
      if (cond_parse_int(b->v[j].p, b->v[j].n, &y) && op_holds(op, x, y)) {
        return 1;
      }
    }
  }
  return 0;
}

/* The type a side is read in: a field's of a type other than text and
 * reference, or 0 for bytes. */
static int typed(const Vals * s) {
  return s->kind == kField && !cond_texty_type(s->f.type) ? s->f.type : 0;
}

/* Text @p k of a side as a value of @p f's type. 1 with *out set, 2 for the
 * empty text (a field with no value, or the constant ""), 0 when the text is
 * no value of the type: an identifier never is, `now` is its number. */
static int as_type(const Vals * s, size_t k, const CondField * f,
    GDEFSTOR_Value * out) {
  if (s->kind == kPrincipal || s->kind == kCreator || s->kind == kRevCreator) {
    return 0;
  }
  if (s->kind == kNow) {
    return cond_now_as(f->type, f->scale, s->now, out);
  }
  if (s->v[k].n == 0) {
    return 2;
  }
  return gdefcore_value_parse(f->type, f->scale, s->v[k].p, s->v[k].n, out) ==
         GDEFCORE_OK;
}

static int cmp_holds(int op, int c) {
  switch (op) {
    case kEq:
      return c == 0;
    case kLt:
      return c < 0;
    case kLe:
      return c <= 0;
    case kGt:
      return c > 0;
    case kGe:
      return c >= 0;
    default:
      return 0;
  }
}

/* Some pair stands in @p op (kEq or an ordering), read in @p f's type. The
 * empty text equals only the empty text and is never ordered. */
static int any_typed(int op, const Vals * a, const Vals * b,
    const CondField * f) {
  size_t i;
  size_t j;
  for (i = 0; i < a->n; i++) {
    GDEFSTOR_Value x;
    int ra = as_type(a, i, f, &x);
    if (ra == 0) {
      continue;
    }
    for (j = 0; j < b->n; j++) {
      GDEFSTOR_Value y;
      int rb = as_type(b, j, f, &y);
      if (rb == 0) {
        continue;
      }
      if (ra == 2 || rb == 2) {
        if (op == kEq && ra == 2 && rb == 2) {
          return 1;
        }
        continue;
      }
      if (cmp_holds(op, gdefcore_value_compare(&x, &y))) {
        return 1;
      }
    }
  }
  return 0;
}

static int eval_node(Ctx * ctx, int idx);

static int eval_cmp(Ctx * ctx, const CNode * node) {
  Vals a;
  Vals b;
  int r = 0;
  int ordered = node->op != kEq && node->op != kNe;
  if (!operand(ctx, ctx->c->kids[node->first], &a)) {
    return 0;
  }
  if (!operand(ctx, ctx->c->kids[node->first + 1], &b)) {
    vals_free(ctx, &a);
    return 0;
  }
  if ((a.kind == kField && b.kind == kField &&
          !cond_types_meet(a.f.type, a.f.scale, b.f.type, b.f.scale)) ||
      (ordered && ((a.kind == kField && !cond_numeric_type(a.f.type)) ||
                      (b.kind == kField && !cond_numeric_type(b.f.type))))) {
    /* Refused at validation; a stored condition that predates a type change
     * fails rather than answering (decision 12). */
    vals_free(ctx, &a);
    vals_free(ctx, &b);
    return ctx_fail(ctx);
  }
  if (typed(&a) != 0 || typed(&b) != 0) {
    const CondField * f = typed(&a) != 0 ? &a.f : &b.f;
    if (node->op == kNe) {
      r = !any_typed(kEq, &a, &b, f);
    } else {
      r = any_typed(node->op, &a, &b, f);
    }
  } else if (node->op == kEq) {
    r = any_equal(&a, &b);
  } else if (node->op == kNe) {
    r = !any_equal(&a, &b);
  } else {
    r = any_ordered(node->op, &a, &b);
  }
  vals_free(ctx, &a);
  vals_free(ctx, &b);
  return r;
}

static int eval_in(Ctx * ctx, const CNode * node) {
  Vals a;
  size_t k;
  int r = 0;
  if (!operand(ctx, ctx->c->kids[node->first], &a)) {
    return 0;
  }
  for (k = 1; k < node->count && !r; k++) {
    const CNode * member = &ctx->c->nodes[ctx->c->kids[node->first + k]];
    Vals m;
    memset(&m, 0, offsetof(Vals, num));
    m.kind = kText;
    vals_one(&m, ctx->c->pool + member->str, member->str_len);
    if (typed(&a) != 0) {
      r = any_typed(kEq, &a, &m, &a.f);
    } else {
      r = any_equal(&a, &m);
    }
  }
  vals_free(ctx, &a);
  return r;
}

/*
 * (related "name" (operand ...)): some row of the relation has, in each column
 * given, one of the texts of the operand for it (an integer column: one of
 * them read as an integer). The relation is read as the system, through the
 * same port query every host read uses, and only if an enabled module
 * declares it with this many columns: a relation that is gone (its module
 * disabled) or changed shape is a failure, not a no, so that `not` of it never
 * becomes a grant. The read is noted on the request at the relation's version,
 * so a render key that depends on it moves with the rows.
 */
static int eval_related(Ctx * ctx, const CNode * node) {
  const CNode * name = &ctx->c->nodes[ctx->c->kids[node->first]];
  const char * rel = ctx->c->pool + name->str;
  size_t rel_len = name->str_len;
  size_t arity = (size_t)node->count - 1;
  GDEFCORE_Host * host = gdefcore_catalog_host(ctx->catalog);
  const GDEFCORE_Module_Declared_Relation ** items = NULL;
  size_t nitems = 0;
  size_t tenant_len = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(ctx->catalog, &tenant_len);
  size_t i;
  int declared = 0;
  int kinds[GDEFCORE_RELATION_COLUMNS_MAX];
  Vals vals[GDEFCORE_RELATION_COLUMNS_MAX];
  int any[GDEFCORE_RELATION_COLUMNS_MAX];
  size_t got = 0;
  GDEFSTOR_Value values[1 + GDEFCORE_RELATION_COLUMNS_MAX * kMaxFieldValues];
  size_t nvalues = 0;
  GDEFSTOR_QueryNode leaves[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  const GDEFSTOR_QueryNode * kids[1 + GDEFCORE_RELATION_COLUMNS_MAX];
  size_t nleaves = 0;
  GDEFSTOR_QueryNode root;
  GDEFSTOR_Query q;
  char ** ids = NULL;
  size_t nids = 0;
  int result = 0;
  int bad = 0;
  int empty = 0;
  GDEFCORE_Result rc;
  if (host == NULL || arity == 0 || arity > GDEFCORE_RELATION_COLUMNS_MAX) {
    return ctx_fail(ctx);
  }
  rc = gdefcore_module_relations(host, tenant, tenant_len, NULL, &items, &nitems);
  if (rc != GDEFCORE_OK) {
    return ctx_fail(ctx);
  }
  for (i = 0; i < nitems; i++) {
    if (items[i]->name_len == rel_len && memcmp(items[i]->name, rel, rel_len) == 0) {
      size_t k;
      declared = items[i]->ncolumns == arity;
      for (k = 0; declared && k < arity; k++) {
        kinds[k] = items[i]->columns[k].kind;
      }
      break;
    }
  }
  gdefcore_module_declared_free(host, items);
  if (!declared) {
    return ctx_fail(ctx);
  }
  memset(vals, 0, sizeof vals);
  memset(any, 0, sizeof any);
  for (i = 0; i < arity; i++) {
    int kid = ctx->c->kids[node->first + 1 + i];
    if (ctx->c->nodes[kid].kind == kAny) {
      any[i] = 1;
      continue;
    }
    if (!operand(ctx, kid, &vals[i])) {
      bad = 1;
      got = i;
      break;
    }
    got = i + 1;
  }
  if (!bad && gdefcore_relation_note_dependency(ctx->catalog, ctx->request, rel,
                  rel_len) != GDEFCORE_OK) {
    bad = 1;
  }
  if (!bad) {
    GDEFSTOR_QueryOperand * left;
    /* relation = the name */
    memset(&values[nvalues], 0, sizeof values[nvalues]);
    values[nvalues].type = GDEFSTOR_FIELD_TEXT;
    values[nvalues].bytes = (const uint8_t *)rel;
    values[nvalues].len = rel_len;
    memset(&leaves[nleaves], 0, sizeof leaves[nleaves]);
    leaves[nleaves].op = GDEFSTOR_QUERY_EQ;
    left = &leaves[nleaves].left;
    left->kind = GDEFSTOR_QUERY_FIELD;
    left->field = GDEFCORE_RELATION_FIELD_NAME;
    left->field_len = strlen(GDEFCORE_RELATION_FIELD_NAME);
    leaves[nleaves].right.kind = GDEFSTOR_QUERY_VALUES;
    leaves[nleaves].right.values = &values[nvalues];
    leaves[nleaves].right.value_count = 1;
    kids[nleaves] = &leaves[nleaves];
    nvalues += 1;
    nleaves += 1;
    for (i = 0; i < arity && !empty; i++) {
      size_t k;
      size_t first = nvalues;
      int integer = kinds[i] == GDEFCORE_RELATION_INTEGER;
      if (any[i]) {
        continue;
      }
      for (k = 0; k < vals[i].n; k++) {
        GDEFSTOR_Value * v = &values[nvalues];
        memset(v, 0, sizeof *v);
        if (integer) {
          /* A text that is no integer is equal to no row's. */
          if (!cond_parse_int(vals[i].v[k].p, vals[i].v[k].n, &v->integer)) {
            continue;
          }
          v->type = GDEFSTOR_FIELD_INTEGER;
        } else {
          v->type = GDEFSTOR_FIELD_TEXT;
          v->bytes = (const uint8_t *)vals[i].v[k].p;
          v->len = vals[i].v[k].n;
        }
        nvalues += 1;
      }
      if (nvalues == first) {
        empty = 1; /* a none: equal to nothing */
        break;
      }
      memset(&leaves[nleaves], 0, sizeof leaves[nleaves]);
      leaves[nleaves].op = GDEFSTOR_QUERY_IN;
      left = &leaves[nleaves].left;
      left->kind = GDEFSTOR_QUERY_FIELD;
      left->field = integer ? gdefcore_relation_number_field(i)
                            : gdefcore_relation_column_field(i);
      left->field_len = strlen(left->field);
      if (!integer) {
        /* A row's text column holds "" for an empty text: the operand's
         * empty text is one. */
        left->flags = GDEFSTOR_QUERY_EMPTY_IF_NONE;
      }
      leaves[nleaves].right.kind = GDEFSTOR_QUERY_VALUES;
      leaves[nleaves].right.values = &values[first];
      leaves[nleaves].right.value_count = nvalues - first;
      kids[nleaves] = &leaves[nleaves];
      nleaves += 1;
    }
    if (!empty) {
      memset(&root, 0, sizeof root);
      root.op = GDEFSTOR_QUERY_AND;
      root.children = kids;
      root.child_count = nleaves;
      memset(&q, 0, sizeof q);
      q.size = sizeof q;
      q.where = &root;
      q.limit = 1;
      q.language = GDEFCORE_RELATION_LANG;
      q.language_len = strlen(GDEFCORE_RELATION_LANG);
      rc = gdefcore_entity_query_active(ctx->catalog, GDEFCORE_RELATION_ROW_TYPE,
          strlen(GDEFCORE_RELATION_ROW_TYPE), &q, &ids, &nids, NULL);
      if (rc != GDEFCORE_OK) {
        bad = 1;
      } else {
        result = nids > 0;
        gdefcore_ids_free(ctx->catalog, ids, nids);
      }
    }
  }
  for (i = 0; i < got; i++) {
    vals_free(ctx, &vals[i]);
  }
  if (bad) {
    return ctx_fail(ctx);
  }
  return result;
}

static int eval_node(Ctx * ctx, int idx) {
  const CNode * node = &ctx->c->nodes[idx];
  size_t k;
  if (ctx->failed) {
    return 0;
  }
  switch (node->kind) {
    case kRelated:
      return eval_related(ctx, node);
    case kTrue:
      return 1;
    case kFalse:
      return 0;
    case kNot: {
      int r = eval_node(ctx, ctx->c->kids[node->first]);
      return ctx->failed ? 0 : !r;
    }
    case kAnd:
      for (k = 0; k < node->count; k++) {
        if (!eval_node(ctx, ctx->c->kids[node->first + k])) {
          return 0;
        }
      }
      return 1;
    case kOr:
      for (k = 0; k < node->count; k++) {
        if (eval_node(ctx, ctx->c->kids[node->first + k])) {
          return 1;
        }
        if (ctx->failed) {
          return 0;
        }
      }
      return 0;
    case kCmp:
      return eval_cmp(ctx, node);
    case kIn:
      return eval_in(ctx, node);
    default:
      return ctx_fail(ctx);
  }
}

int gdefcore_condition_eval(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Condition * condition,
    const GDEFCORE_Condition_Subject * subject, int * out_failed) {
  GDEFCORE_Condition_Subject local;
  Ctx ctx;
  int r;
  size_t ncopy;
  GDEFCORE_Result rc;
  if (out_failed != NULL) {
    *out_failed = 0;
  }
  if (catalog == NULL || request == NULL || condition == NULL ||
      subject == NULL || subject->size < sizeof(size_t)) {
    return 0;
  }
  memset(&local, 0, sizeof local);
  ncopy = subject->size < sizeof local ? subject->size : sizeof local;
  memcpy(&local, subject, ncopy);
  memset(&ctx, 0, sizeof ctx);
  ctx.catalog = catalog;
  ctx.request = request;
  ctx.c = condition;
  ctx.lang = local.lang == NULL || local.lang_len == 0 ? "en" : local.lang;
  ctx.lang_len = local.lang == NULL || local.lang_len == 0 ? 2 : local.lang_len;
  if (local.entity != NULL) {
    if (gdefcore_id_canonical(local.entity, local.entity_len, ctx.id) !=
        GDEFCORE_OK) {
      return 0;
    }
    rc = gdefcore_entity_type(catalog, ctx.id, GDEFCORE_PUBLIC_ID_LEN,
        &ctx.type_owned, &ctx.type_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return 0;
    }
    if (rc != GDEFCORE_OK) {
      if (out_failed != NULL) {
        *out_failed = 1;
      }
      return 0;
    }
    ctx.real = 1;
    ctx.type = ctx.type_owned;
  } else if (local.type_name != NULL && local.type_name_len > 0) {
    ctx.type = local.type_name;
    ctx.type_len = local.type_name_len;
  } else {
    return 0;
  }
  r = eval_node(&ctx, condition->root);
  if (ctx.failed) {
    r = 0;
    if (out_failed != NULL) {
      *out_failed = 1;
    }
  }
  gdefcore_text_free(catalog, ctx.type_owned);
  gdefcore_text_free(catalog, ctx.actor);
  gdefcore_text_free(catalog, ctx.creator);
  return r != 0;
}
