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
 * text. `actor` and `principal` are one text, or none when there is no actor
 * or no principal, so that an absent actor and an anonymous request are never
 * equal. A field is its values in the call's language, or the single empty
 * text when it has none. A comparison holds when some text on the left stands
 * in the stated relation to some text on the right.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/condition.h>

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
  int actor_loaded;
  char * actor;
  size_t actor_len;
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
  size_t count = 0;
  size_t i;
  int found = 0;
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (gdefcore_type_field_count(ctx->catalog, ctx->type, ctx->type_len,
          &count) != GDEFCORE_OK) {
    return ctx_fail(ctx);
  }
  for (i = 0; i < count && !found; i++) {
    char * got = NULL;
    size_t got_len = 0;
    int required = 0;
    int many = 0;
    int match;
    if (gdefcore_type_field(ctx->catalog, ctx->type, ctx->type_len, i, &got,
            &got_len, &required, &many) != GDEFCORE_OK) {
      return ctx_fail(ctx);
    }
    match = got_len == name_len && memcmp(got, name, name_len) == 0;
    gdefcore_text_free(ctx->catalog, got);
    if (match) {
      int personal = 0;
      found = 1;
      if (gdefcore_type_field_personal(ctx->catalog, ctx->type, ctx->type_len,
              i, &personal) != GDEFCORE_OK || personal != 0) {
        /* A personal value is ciphertext: never compare it. */
        return ctx_fail(ctx);
      }
    }
  }
  if (!found) {
    return ctx_fail(ctx);
  }
  if (!ctx->real) {
    vals_one(vals, kEmpty, 0);
    return 1;
  }
  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_PUBLISHED,
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
  switch (node->kind) {
    case kText:
    case kInt:
      vals_one(vals, ctx->c->pool + node->str, node->str_len);
      return 1;
    case kType:
      vals_one(vals, ctx->type, ctx->type_len);
      return 1;
    case kNow: {
      int wn = snprintf(vals->num, sizeof vals->num, "%lld",
          (long long)gdefcore_request_time(ctx->request));
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
    case kActor:
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

static int eval_node(Ctx * ctx, int idx);

static int eval_cmp(Ctx * ctx, const CNode * node) {
  Vals a;
  Vals b;
  int r = 0;
  if (!operand(ctx, ctx->c->kids[node->first], &a)) {
    return 0;
  }
  if (!operand(ctx, ctx->c->kids[node->first + 1], &b)) {
    vals_free(ctx, &a);
    return 0;
  }
  if (node->op == kEq) {
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
    Span s;
    size_t i;
    s.p = ctx->c->pool + member->str;
    s.n = member->str_len;
    for (i = 0; i < a.n; i++) {
      if (same_text(a.v[i], s)) {
        r = 1;
        break;
      }
    }
  }
  vals_free(ctx, &a);
  return r;
}

static int eval_node(Ctx * ctx, int idx) {
  const CNode * node = &ctx->c->nodes[idx];
  size_t k;
  if (ctx->failed) {
    return 0;
  }
  switch (node->kind) {
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
  return r != 0;
}
