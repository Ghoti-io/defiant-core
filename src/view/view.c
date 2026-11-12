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
 * Views as data (view.h): saving, reading, validating and running a stored
 * list of entities. A view is read through the access filter and draws
 * nothing: its cells are text.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <ghoti.io/defiant-core/view.h>
#include <ghoti.io/defiant-storage/value.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kLang[] = "en";

/* ---- the tables ----------------------------------------------------------- */

static const char * const kOpsText[] = {"=", "!=", "in", NULL};
static const char * const kOpsBool[] = {"=", "!=", "in", NULL};
static const char * const kOpsOrdered[] = {"=", "!=", "<", "<=", ">", ">=", "in",
    NULL};
static const char * const kOpsNone[] = {NULL};

static const char * const kFmtText[] = {"raw", "upper", "lower", "truncate-N", NULL};
static const char * const kFmtBool[] = {"raw", "yesno", NULL};
static const char * const kFmtDate[] = {"raw", "date", NULL};
static const char * const kFmtRaw[] = {"raw", NULL};
static const char * const kFmtMany[] = {"join", "count", NULL};
static const char * const kFmtCount[] = {"count", NULL};
static const char * const kFmtNone[] = {NULL};

static size_t table_count(const char * const * t) {
  size_t n = 0;
  while (t[n] != NULL) {
    n += 1;
  }
  return n;
}

const char * const * gdefcore_view_operators(int field_type, size_t * out_count) {
  const char * const * t = kOpsNone;
  switch (field_type) {
  case GDEFSTOR_FIELD_TEXT:
  case GDEFSTOR_FIELD_REFERENCE:
    t = kOpsText;
    break;
  case GDEFSTOR_FIELD_BOOLEAN:
    t = kOpsBool;
    break;
  case GDEFSTOR_FIELD_INTEGER:
  case GDEFSTOR_FIELD_DECIMAL:
  case GDEFSTOR_FIELD_FLOAT:
  case GDEFSTOR_FIELD_DATE:
  case GDEFSTOR_FIELD_DATETIME:
    t = kOpsOrdered;
    break;
  default:
    break;
  }
  if (out_count != NULL) {
    *out_count = table_count(t);
  }
  return t;
}

const char * const * gdefcore_view_formatters(int field_type, int many,
    size_t * out_count) {
  const char * const * t = kFmtNone;
  if (field_type == GDEFSTOR_FIELD_GROUP) {
    t = kFmtCount;
  } else if (many) {
    t = kFmtMany;
  } else {
    switch (field_type) {
    case GDEFSTOR_FIELD_TEXT:
      t = kFmtText;
      break;
    case GDEFSTOR_FIELD_BOOLEAN:
      t = kFmtBool;
      break;
    case GDEFSTOR_FIELD_DATE:
    case GDEFSTOR_FIELD_DATETIME:
      t = kFmtDate;
      break;
    case GDEFSTOR_FIELD_INTEGER:
    case GDEFSTOR_FIELD_DECIMAL:
    case GDEFSTOR_FIELD_FLOAT:
    case GDEFSTOR_FIELD_REFERENCE:
      t = kFmtRaw;
      break;
    default:
      break;
    }
  }
  if (out_count != NULL) {
    *out_count = table_count(t);
  }
  return t;
}

/* A formatter's name, with `truncate-N` reading as `truncate-N` and its
 * count in @p n: 1 when it is allowed for a field of @p type, else 0. */
static int formatter_ok(int type, int many, const char * f, size_t len,
    size_t * truncate) {
  size_t count = 0;
  const char * const * t = gdefcore_view_formatters(type, many, &count);
  size_t i;
  *truncate = 0;
  if (f == NULL || len == 0) {
    f = "raw";
    len = 3;
  }
  for (i = 0; i < count; i++) {
    if (strcmp(t[i], "truncate-N") == 0) {
      if (len > 9 && memcmp(f, "truncate-", 9) == 0) {
        size_t n = 0;
        size_t k;
        int good = len - 9 <= 4;
        for (k = 9; good && k < len; k++) {
          good = f[k] >= '0' && f[k] <= '9';
          n = n * 10 + (size_t)(f[k] - '0');
        }
        if (good && n >= 1 && n <= 1000) {
          *truncate = n;
          return 1;
        }
      }
    } else if (strlen(t[i]) == len && memcmp(t[i], f, len) == 0) {
      return 1;
    }
  }
  return 0;
}

/* ---- names, text -------------------------------------------------------- */

static int name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > 64) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_')) {
      return 0;
    }
  }
  return 1;
}

static int field_name_ok(const char * s, size_t n) {
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

static void reason(char * why, size_t cap, const char * fmt, const char * a,
    size_t alen) {
  if (why != NULL && cap > 0) {
    (void)snprintf(why, cap, fmt, (int)alen, a == NULL ? "" : a);
  }
}

/* The root field @p name of @p type: its storage type and shape. 1 when it
 * is a field that holds values, 0 when there is none (or it is a group). */
typedef struct FieldShape {
  int type;
  int many;
  int personal;
} FieldShape;

static int root_field(GDEFCORE_Catalog * catalog, const char * type, size_t type_len,
    const char * name, size_t name_len, FieldShape * out) {
  size_t count = 0;
  size_t i;
  if (gdefcore_type_tree_field_count(catalog, type, type_len, &count) !=
      GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < count; i++) {
    GDEFCORE_FieldInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefcore_type_tree_field(catalog, type, type_len, i, &info) != GDEFCORE_OK) {
      return 0;
    }
    if (info.depth == 0 && info.path_len == name_len &&
        memcmp(info.path, name, name_len) == 0) {
      if (info.type == GDEFSTOR_FIELD_GROUP) {
        return 0;
      }
      out->type = info.type;
      out->many = info.many;
      out->personal = info.personal;
      return 1;
    }
  }
  return 0;
}

/* A column's field: a root field, a group (its items are counted), or a field
 * inside a group (the values it holds in every item of that group, in order).
 * A field in a group is read as one that holds many values, because a group
 * may hold many items. @p item_path is the path of the items the values sit
 * on ("" for the root item) and @p leaf the field's own name there. */
typedef struct ColShape {
  FieldShape f;
  int group;
  char item_path[GDEFCORE_FIELD_PATH_MAX + 1];
  size_t item_path_len;
  char leaf[GDEFCORE_FIELD_PATH_MAX + 1];
  size_t leaf_len;
} ColShape;

static int path_ok(const char * s, size_t n) {
  size_t i;
  size_t seg = 0;
  if (s == NULL || n == 0 || n > GDEFCORE_FIELD_PATH_MAX) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (c == '.') {
      if (seg == 0 || seg > 64) {
        return 0;
      }
      seg = 0;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_')) {
      return 0;
    }
    seg += 1;
  }
  return seg > 0 && seg <= 64;
}

static int column_field(GDEFCORE_Catalog * catalog, const char * type, size_t type_len,
    const char * name, size_t name_len, ColShape * out) {
  size_t count = 0;
  size_t i;
  if (!path_ok(name, name_len) ||
      gdefcore_type_tree_field_count(catalog, type, type_len, &count) != GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < count; i++) {
    GDEFCORE_FieldInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefcore_type_tree_field(catalog, type, type_len, i, &info) != GDEFCORE_OK) {
      return 0;
    }
    if (info.path_len != name_len || memcmp(info.path, name, name_len) != 0) {
      continue;
    }
    memset(out, 0, sizeof *out);
    out->f.type = info.type;
    out->f.personal = info.personal;
    if (info.type == GDEFSTOR_FIELD_GROUP) {
      out->group = 1;
      out->f.many = 1;
      memcpy(out->item_path, info.path, info.path_len);
      out->item_path_len = info.path_len;
    } else if (info.many) {
      /* A field of many values keeps each in an item of its own under the
       * field, holding the value as its own (an empty field name). */
      out->f.many = 1;
      memcpy(out->item_path, info.path, info.path_len);
      out->item_path_len = info.path_len;
    } else if (info.depth == 0) {
      out->f.many = 0;
      memcpy(out->leaf, info.path, info.path_len);
      out->leaf_len = info.path_len;
    } else {
      out->f.many = 1;
      if (info.name_at == 0 || info.name_at > info.path_len) {
        return 0;
      }
      memcpy(out->item_path, info.path, info.name_at - 1);
      out->item_path_len = info.name_at - 1;
      memcpy(out->leaf, info.path + info.name_at, info.path_len - info.name_at);
      out->leaf_len = info.path_len - info.name_at;
    }
    return 1;
  }
  return 0;
}

/* The values of a column in one row's tree, borrowed from it: for a group the
 * number of items and no values. Free the arrays, not what they point to. */
static GDEFCORE_Result column_values(const GDEFCORE_Tree * tree, const ColShape * cs,
    const char *** out_texts, size_t ** out_lens, size_t * out_count) {
  size_t items = gdefcore_tree_item_count(tree);
  size_t i;
  size_t k;
  size_t n = 0;
  size_t cap = 0;
  const char ** texts = NULL;
  size_t * lens = NULL;
  *out_texts = NULL;
  *out_lens = NULL;
  *out_count = 0;
  for (i = 0; i < items; i++) {
    GDEFCORE_TreeItem it;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(tree, i, &it) != GDEFCORE_OK) {
      return GDEFCORE_ERR_CORRUPT;
    }
    if (it.path_len != cs->item_path_len ||
        (it.path_len > 0 && memcmp(it.path, cs->item_path, it.path_len) != 0)) {
      continue;
    }
    if (cs->group) {
      n += 1;
      continue;
    }
    cap += it.value_count;
  }
  if (cs->group) {
    *out_count = n;
    return GDEFCORE_OK;
  }
  if (cap == 0) {
    return GDEFCORE_OK;
  }
  texts = (const char **)calloc(cap, sizeof *texts);
  lens = (size_t *)calloc(cap, sizeof *lens);
  if (texts == NULL || lens == NULL) {
    free(texts);
    free(lens);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < items; i++) {
    GDEFCORE_TreeItem it;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(tree, i, &it) != GDEFCORE_OK) {
      free(texts);
      free(lens);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (it.path_len != cs->item_path_len ||
        (it.path_len > 0 && memcmp(it.path, cs->item_path, it.path_len) != 0)) {
      continue;
    }
    for (k = 0; k < it.value_count && n < cap; k++) {
      const char * field = NULL;
      size_t field_len = 0;
      const char * text = NULL;
      size_t len = 0;
      if (gdefcore_tree_value(tree, i, k, &field, &field_len, &text, &len) !=
          GDEFCORE_OK) {
        free(texts);
        free(lens);
        return GDEFCORE_ERR_CORRUPT;
      }
      if (field_len == cs->leaf_len && memcmp(field, cs->leaf, field_len) == 0) {
        texts[n] = text;
        lens[n] = len;
        n += 1;
      }
    }
  }
  *out_texts = texts;
  *out_lens = lens;
  *out_count = n;
  return GDEFCORE_OK;
}

/* ---- arguments in a condition ------------------------------------------ */

/* Walk @p cond for the arguments it names, calling @p emit for each piece:
 * literal text outside an argument, and each argument's name. A `$` inside a
 * quoted constant is that constant's own. Returns 0, or -1 for a `$` that
 * names nothing, and the callback's own refusal. */
typedef int (*Piece)(void * ctx, const char * text, size_t len, int is_arg);

static int walk_condition(const char * cond, size_t n, Piece emit, void * ctx) {
  size_t i = 0;
  size_t from = 0;
  int in_string = 0;
  while (i < n) {
    char c = cond[i];
    if (in_string) {
      if (c == '\\' && i + 1 < n) {
        i += 2;
        continue;
      }
      if (c == '"') {
        in_string = 0;
      }
      i += 1;
      continue;
    }
    if (c == '"') {
      in_string = 1;
      i += 1;
      continue;
    }
    if (c == '$') {
      size_t s = i + 1;
      size_t e = s;
      while (e < n && ((cond[e] >= 'a' && cond[e] <= 'z') ||
                          (cond[e] >= '0' && cond[e] <= '9') || cond[e] == '-' ||
                          cond[e] == '_')) {
        e += 1;
      }
      if (e == s) {
        return -1;
      }
      if (i > from && emit(ctx, cond + from, i - from, 0) != 0) {
        return -1;
      }
      if (emit(ctx, cond + s, e - s, 1) != 0) {
        return -1;
      }
      i = e;
      from = e;
      continue;
    }
    i += 1;
  }
  if (n > from && emit(ctx, cond + from, n - from, 0) != 0) {
    return -1;
  }
  return 0;
}

typedef struct Buf {
  char * p;
  size_t n;
  size_t cap;
  int bad;
} Buf;

static int buf_add(Buf * b, const char * s, size_t n) {
  if (b->bad) {
    return -1;
  }
  if (b->n + n + 1 > b->cap) {
    size_t cap = b->cap == 0 ? 256 : b->cap;
    char * q;
    while (cap < b->n + n + 1) {
      cap *= 2;
    }
    q = (char *)realloc(b->p, cap);
    if (q == NULL) {
      b->bad = 1;
      return -1;
    }
    b->p = q;
    b->cap = cap;
  }
  if (n > 0) {
    memcpy(b->p + b->n, s, n);
  }
  b->n += n;
  b->p[b->n] = '\0';
  return 0;
}

static int buf_str(Buf * b, const char * s) {
  return buf_add(b, s, strlen(s));
}

/* ---- validation ---------------------------------------------------------- */

typedef struct UseCtx {
  const GDEFCORE_View_Def * def;
  Buf out;
  unsigned seen;    /* bit per declared argument that is named */
  int unknown;
  char missing[65];
} UseCtx;

static int arg_index(const GDEFCORE_View_Def * def, const char * name, size_t n) {
  size_t i;
  for (i = 0; i < def->arg_count; i++) {
    if (def->args[i].name_len == n && memcmp(def->args[i].name, name, n) == 0) {
      return (int)i;
    }
  }
  return -1;
}

static int use_piece(void * vctx, const char * text, size_t len, int is_arg) {
  UseCtx * c = (UseCtx *)vctx;
  if (!is_arg) {
    return buf_add(&c->out, text, len);
  }
  {
    int k = arg_index(c->def, text, len);
    if (k < 0) {
      size_t m = len < 64 ? len : 64;
      memcpy(c->missing, text, m);
      c->missing[m] = '\0';
      c->unknown = 1;
      return -1;
    }
    c->seen |= 1u << k;
  }
  return buf_str(&c->out, "\"x\"");
}

GDEFCORE_Result gdefcore_view_validate(GDEFCORE_Catalog * catalog,
    const GDEFCORE_View_Def * def, char * why, size_t why_cap) {
  FieldShape shape;
  ColShape col;
  int kind = 0;
  size_t i;
  size_t j;
  if (why != NULL && why_cap > 0) {
    why[0] = '\0';
  }
  if (catalog == NULL || def == NULL || def->size != sizeof *def) {
    return GDEFCORE_ERR_INVALID;
  }
#define REFUSE(fmt, a, alen)                      \
  do {                                            \
    reason(why, why_cap, fmt, a, alen);           \
    return GDEFCORE_ERR_INVALID;                  \
  } while (0)
  if (!name_ok(def->name, def->name_len)) {
    REFUSE("the view's name %.*s is not lower-case letters, digits, - and _ (at most 64)",
        def->name, def->name_len);
  }
  if (def->type == NULL || def->type_len == 0 ||
      gdefcore_type_kind(catalog, def->type, def->type_len, &kind) != GDEFCORE_OK) {
    REFUSE("there is no type %.*s", def->type, def->type_len);
  }
  if (def->format < GDEFCORE_VIEW_FORMAT_TABLE ||
      def->format > GDEFCORE_VIEW_FORMAT_JSON) {
    REFUSE("%.*s is not a set format", "the format", (size_t)10);
  }
  if (def->limit < 1 || def->limit > GDEFCORE_VIEW_MAX_ROWS) {
    REFUSE("the page size %.*s is not from 1 to 200", "given", (size_t)5);
  }
  for (i = 0; i < 2; i++) {
    const char * s = i == 0 ? def->sort : def->sort2;
    size_t n = i == 0 ? def->sort_len : def->sort2_len;
    if (s == NULL || n == 0) {
      if (i == 0 && def->sort2 != NULL && def->sort2_len > 0) {
        REFUSE("a second sort key needs a first%.*s", "", (size_t)0);
      }
      continue;
    }
    if (!root_field(catalog, def->type, def->type_len, s, n, &shape)) {
      REFUSE("%.*s is not a field the type holds a value in, so it cannot be sorted by", s, n);
    }
    if (shape.personal) {
      REFUSE("%.*s is a personal field, which cannot be sorted by", s, n);
    }
    if (shape.many) {
      REFUSE("%.*s holds many values, which cannot be sorted by", s, n);
    }
  }
  if (def->columns == NULL || def->column_count == 0 ||
      def->column_count > GDEFCORE_VIEW_MAX_COLUMNS) {
    REFUSE("a view needs from 1 to 16 columns%.*s", "", (size_t)0);
  }
  for (i = 0; i < def->column_count; i++) {
    const GDEFCORE_View_Column * c = &def->columns[i];
    size_t trunc = 0;
    if (c->size != sizeof *c) {
      return GDEFCORE_ERR_INVALID;
    }
    if (!column_field(catalog, def->type, def->type_len, c->field, c->field_len,
            &col)) {
      REFUSE("%.*s is not a field or group the type has", c->field, c->field_len);
    }
    shape = col.f;
    if (shape.personal) {
      REFUSE("%.*s is a personal field, which a view does not show", c->field,
          c->field_len);
    }
    if (!formatter_ok(shape.type, shape.many, c->formatter, c->formatter_len, &trunc)) {
      REFUSE("the formatter %.*s does not suit that field", c->formatter == NULL ? "raw" : c->formatter,
          c->formatter == NULL ? (size_t)3 : c->formatter_len);
    }
    if (c->label_len > 120 || (c->label_len > 0 && memchr(c->label, '\0', c->label_len) != NULL)) {
      REFUSE("a heading is at most 120 bytes%.*s", "", (size_t)0);
    }
    if ((c->formatter != NULL && memchr(c->formatter, '|', c->formatter_len) != NULL) ||
        (c->label != NULL && memchr(c->label, '\n', c->label_len) != NULL)) {
      REFUSE("a formatter or heading holds a character that is not allowed%.*s", "", (size_t)0);
    }
    for (j = 0; j < i; j++) {
      const GDEFCORE_View_Column * d = &def->columns[j];
      const char * la = d->label_len > 0 ? d->label : d->field;
      size_t ln = d->label_len > 0 ? d->label_len : d->field_len;
      const char * lb = c->label_len > 0 ? c->label : c->field;
      size_t lm = c->label_len > 0 ? c->label_len : c->field_len;
      if (ln == lm && memcmp(la, lb, ln) == 0) {
        REFUSE("two columns are headed %.*s; each needs a heading of its own", lb, lm);
      }
    }
  }
  if (def->arg_count > GDEFCORE_VIEW_MAX_ARGS || (def->arg_count > 0 && def->args == NULL)) {
    REFUSE("a view declares at most 8 arguments%.*s", "", (size_t)0);
  }
  for (i = 0; i < def->arg_count; i++) {
    const GDEFCORE_View_Arg * a = &def->args[i];
    if (a->size != sizeof *a) {
      return GDEFCORE_ERR_INVALID;
    }
    if (!name_ok(a->name, a->name_len)) {
      REFUSE("the argument name %.*s is not lower-case letters, digits, - and _", a->name, a->name_len);
    }
    if (a->source < GDEFCORE_VIEW_SOURCE_URL || a->source > GDEFCORE_VIEW_SOURCE_FIXED) {
      REFUSE("the argument %.*s has no source", a->name, a->name_len);
    }
    if (a->source == GDEFCORE_VIEW_SOURCE_FIXED && a->fixed_len == 0) {
      REFUSE("the fixed argument %.*s has no value", a->name, a->name_len);
    }
    if (a->fixed_len > 256 || (a->fixed_len > 0 && memchr(a->fixed, '\n', a->fixed_len) != NULL)) {
      REFUSE("the value of the argument %.*s is too long or holds a line break", a->name, a->name_len);
    }
    for (j = 0; j < i; j++) {
      if (def->args[j].name_len == a->name_len &&
          memcmp(def->args[j].name, a->name, a->name_len) == 0) {
        REFUSE("the argument %.*s is declared twice", a->name, a->name_len);
      }
    }
  }
  {
    UseCtx ctx;
    GDEFCORE_Condition * cond = NULL;
    GDEFCORE_Condition_Error err;
    GDEFCORE_Result rc;
    memset(&ctx, 0, sizeof ctx);
    ctx.def = def;
    if (def->condition != NULL && def->condition_len > 0) {
      int w = walk_condition(def->condition, def->condition_len, use_piece, &ctx);
      if (ctx.out.bad) {
        free(ctx.out.p);
        return GDEFCORE_ERR_OOM;
      }
      if (w != 0) {
        free(ctx.out.p);
        if (ctx.unknown) {
          REFUSE("the condition names an argument, %.*s, that is not declared", ctx.missing,
              strlen(ctx.missing));
        }
        REFUSE("a $ in the condition names no argument%.*s", "", (size_t)0);
      }
      memset(&err, 0, sizeof err);
      rc = gdefcore_condition_parse(ctx.out.p, ctx.out.n, &cond, &err);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_condition_validate(catalog, cond, def->type, def->type_len, &err);
      }
      gdefcore_condition_free(cond);
      free(ctx.out.p);
      if (rc == GDEFCORE_ERR_OOM) {
        return rc;
      }
      if (rc != GDEFCORE_OK) {
        if (why != NULL && why_cap > 0) {
          (void)snprintf(why, why_cap, "the condition: %s", err.message == NULL ? "refused" : err.message);
        }
        return GDEFCORE_ERR_INVALID;
      }
    }
    for (i = 0; i < def->arg_count; i++) {
      if ((ctx.seen & (1u << i)) == 0) {
        REFUSE("the argument %.*s is declared and the condition never uses it",
            def->args[i].name, def->args[i].name_len);
      }
    }
  }
#undef REFUSE
  return GDEFCORE_OK;
}

/* ---- storing ----------------------------------------------------------------- */

static const char kSourceWord[][10] = {"", "url", "exposed", "principal", "fixed"};
static const char kFormatWord[][6] = {"", "table", "list", "csv", "json"};

GDEFCORE_Result gdefcore_view_declare(GDEFCORE_Catalog * catalog) {
  static const char * const names[] = {"name", "type", "condition", "sort", "sort2",
      "columns", "arguments", "format", "limit"};
  GDEFCORE_Field fields[9];
  int kind = 0;
  size_t i;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_type_kind(catalog, GDEFCORE_VIEW_TYPE, sizeof GDEFCORE_VIEW_TYPE - 1,
          &kind) == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  memset(fields, 0, sizeof fields);
  for (i = 0; i < 9; i++) {
    fields[i].size = sizeof fields[i];
    fields[i].name = names[i];
    fields[i].name_len = strlen(names[i]);
    fields[i].required = i == 0 || i == 1 || i == 5 || i == 7 || i == 8;
    fields[i].many = i == 5 || i == 6;
  }
  return gdefcore_type_define(catalog, GDEFCORE_VIEW_TYPE,
      sizeof GDEFCORE_VIEW_TYPE - 1, GDEFCORE_TYPE_CONFIG, fields, 9);
}

GDEFCORE_Result gdefcore_view_declare_edit(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Permission perm;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  {
    memset(&perm, 0, sizeof perm);
    perm.size = sizeof perm;
    perm.label = GDEFCORE_VIEW_EDIT_LABEL;
    perm.label_len = sizeof GDEFCORE_VIEW_EDIT_LABEL - 1;
    perm.module_name = "core";
    perm.module_name_len = 4;
    perm.action = GDEFCORE_VIEW_EDIT;
    perm.action_len = sizeof GDEFCORE_VIEW_EDIT - 1;
    perm.condition = GDEFCORE_ACCESS_ANY;
    perm.type_name = GDEFCORE_VIEW_TYPE;
    perm.type_name_len = sizeof GDEFCORE_VIEW_TYPE - 1;
    return gdefcore_access_declare(catalog, &perm);
  }
}

int gdefcore_view_may_edit(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request) {
  if (catalog == NULL || request == NULL) {
    return 0;
  }
  return gdefcore_access_permits(catalog, request, GDEFCORE_VIEW_EDIT,
      sizeof GDEFCORE_VIEW_EDIT - 1) != 0;
}

GDEFCORE_Result gdefcore_view_authorize(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request) {
  static const char kNotAllowed[] = "That edit is not allowed.";
  size_t touched;
  size_t i;
  if (changeset == NULL || request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  touched = gdefcore_changeset_touched_count(changeset);
  for (i = 0; i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type, &type_len,
            &op) != GDEFCORE_OK ||
        type_len != sizeof GDEFCORE_VIEW_TYPE - 1 ||
        memcmp(type, GDEFCORE_VIEW_TYPE, type_len) != 0) {
      continue;
    }
    if (!gdefcore_view_may_edit(gdefcore_changeset_catalog(changeset), request)) {
      (void)gdefcore_changeset_set_refusal(changeset, kNotAllowed,
          sizeof kNotAllowed - 1);
      return GDEFCORE_ERR_INVALID;
    }
    return GDEFCORE_OK;
  }
  return GDEFCORE_OK;
}

/* The text of field @p field of entity @p id, first value; *out is NULL when
 * there is none. Free with free(). */
static GDEFCORE_Result read_one(GDEFCORE_Catalog * catalog, const char * id,
    const char * field, char ** out, size_t * out_len) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED,
      id, strlen(id), kLang, 2, field, strlen(field), &texts, &lens, &count);
  *out = NULL;
  *out_len = 0;
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count > 0) {
    *out = (char *)malloc(lens[0] + 1);
    if (*out == NULL) {
      gdefcore_values_free(catalog, texts, lens, count);
      return GDEFCORE_ERR_OOM;
    }
    memcpy(*out, texts[0], lens[0]);
    (*out)[lens[0]] = '\0';
    *out_len = lens[0];
  }
  gdefcore_values_free(catalog, texts, lens, count);
  return GDEFCORE_OK;
}

/* The id of the view called @p name (GDEFCORE_ERR_INVALID when there is none). */
static GDEFCORE_Result find_view(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, GDEFCORE_VIEW_TYPE,
      sizeof GDEFCORE_VIEW_TYPE - 1, &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = GDEFCORE_ERR_INVALID;
  for (i = 0; i < count && rc == GDEFCORE_ERR_INVALID; i++) {
    char * got = NULL;
    size_t got_len = 0;
    GDEFCORE_Result r;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    r = read_one(catalog, ids[i], "name", &got, &got_len);
    if (r == GDEFCORE_ERR_OOM) {
      rc = r;
    } else if (r == GDEFCORE_OK && got != NULL && got_len == name_len &&
               memcmp(got, name, name_len) == 0) {
      memcpy(id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      rc = GDEFCORE_OK;
    }
    free(got);
  }
  gdefcore_ids_free(catalog, ids, count);
  return rc;
}

typedef struct Lines {
  char ** p;
  size_t * n;
  size_t count;
} Lines;

static void lines_free(Lines * l) {
  size_t i;
  for (i = 0; i < l->count; i++) {
    free(l->p[i]);
  }
  free(l->p);
  free(l->n);
  memset(l, 0, sizeof *l);
}

static int lines_add(Lines * l, const char * a, size_t an, const char * b, size_t bn,
    const char * c, size_t cn, int with_pipes) {
  size_t total = an + bn + cn + (with_pipes ? 2 : 0);
  char * s;
  char ** np = (char **)realloc(l->p, (l->count + 1) * sizeof *np);
  size_t * nn;
  if (np == NULL) {
    return -1;
  }
  l->p = np;
  nn = (size_t *)realloc(l->n, (l->count + 1) * sizeof *nn);
  if (nn == NULL) {
    return -1;
  }
  l->n = nn;
  s = (char *)malloc(total + 1);
  if (s == NULL) {
    return -1;
  }
  memcpy(s, a, an);
  if (with_pipes) {
    s[an] = '|';
    memcpy(s + an + 1, b, bn);
    s[an + 1 + bn] = '|';
    memcpy(s + an + bn + 2, c, cn);
  } else {
    memcpy(s + an, b, bn);
    memcpy(s + an + bn, c, cn);
  }
  s[total] = '\0';
  l->p[l->count] = s;
  l->n[l->count] = total;
  l->count += 1;
  return 0;
}

GDEFCORE_Result gdefcore_view_stage(GDEFCORE_Changeset * changeset,
    const GDEFCORE_View_Def * def) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(changeset);
  char why[256];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  Lines columns;
  Lines args;
  Lines sorts;
  char limit[24];
  GDEFCORE_Value values[9];
  const char * ctext[GDEFCORE_VIEW_MAX_COLUMNS];
  size_t clen[GDEFCORE_VIEW_MAX_COLUMNS];
  const char * atext[GDEFCORE_VIEW_MAX_ARGS];
  size_t alen[GDEFCORE_VIEW_MAX_ARGS];
  const char * one[7];
  size_t one_len[7];
  size_t nv = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || def == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_view_validate(catalog, def, why, sizeof why);
  if (rc != GDEFCORE_OK) {
    if (rc == GDEFCORE_ERR_INVALID && why[0] != '\0') {
      (void)gdefcore_changeset_set_refusal(changeset, why, strlen(why));
    }
    return rc;
  }
  rc = gdefcore_view_declare(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&columns, 0, sizeof columns);
  memset(&args, 0, sizeof args);
  memset(&sorts, 0, sizeof sorts);
  for (i = 0; i < def->column_count; i++) {
    const GDEFCORE_View_Column * c = &def->columns[i];
    if (lines_add(&columns, c->field, c->field_len,
            c->formatter_len == 0 ? "raw" : c->formatter,
            c->formatter_len == 0 ? 3 : c->formatter_len, c->label == NULL ? "" : c->label,
            c->label_len, 1) != 0) {
      lines_free(&columns);
      return GDEFCORE_ERR_OOM;
    }
  }
  for (i = 0; i < def->arg_count; i++) {
    const GDEFCORE_View_Arg * a = &def->args[i];
    const char * w = kSourceWord[a->source];
    if (lines_add(&args, a->name, a->name_len, w, strlen(w),
            a->fixed == NULL ? "" : a->fixed, a->fixed_len, 1) != 0) {
      lines_free(&columns);
      lines_free(&args);
      return GDEFCORE_ERR_OOM;
    }
  }
  /* sorts: [0] the first key with its sign, [1] the second. */
  for (i = 0; i < 2; i++) {
    const char * s = i == 0 ? def->sort : def->sort2;
    size_t n = i == 0 ? def->sort_len : def->sort2_len;
    int desc = i == 0 ? def->sort_descending : def->sort2_descending;
    if (s == NULL || n == 0) {
      continue;
    }
    if (lines_add(&sorts, desc ? "-" : "", desc ? 1 : 0, s, n, "", 0, 0) != 0) {
      lines_free(&columns);
      lines_free(&args);
      lines_free(&sorts);
      return GDEFCORE_ERR_OOM;
    }
  }
  (void)snprintf(limit, sizeof limit, "%llu", (unsigned long long)def->limit);
  memset(values, 0, sizeof values);
  one[0] = def->name;
  one_len[0] = def->name_len;
  values[nv].size = sizeof values[nv];
  values[nv].field = "name";
  values[nv].field_len = 4;
  values[nv].texts = &one[0];
  values[nv].text_lens = &one_len[0];
  values[nv].count = 1;
  nv += 1;
  one[1] = def->type;
  one_len[1] = def->type_len;
  values[nv].size = sizeof values[nv];
  values[nv].field = "type";
  values[nv].field_len = 4;
  values[nv].texts = &one[1];
  values[nv].text_lens = &one_len[1];
  values[nv].count = 1;
  nv += 1;
  one[2] = kFormatWord[def->format];
  one_len[2] = strlen(one[2]);
  values[nv].size = sizeof values[nv];
  values[nv].field = "format";
  values[nv].field_len = 6;
  values[nv].texts = &one[2];
  values[nv].text_lens = &one_len[2];
  values[nv].count = 1;
  nv += 1;
  one[3] = limit;
  one_len[3] = strlen(limit);
  values[nv].size = sizeof values[nv];
  values[nv].field = "limit";
  values[nv].field_len = 5;
  values[nv].texts = &one[3];
  values[nv].text_lens = &one_len[3];
  values[nv].count = 1;
  nv += 1;
  if (def->condition != NULL && def->condition_len > 0) {
    one[4] = def->condition;
    one_len[4] = def->condition_len;
    values[nv].size = sizeof values[nv];
    values[nv].field = "condition";
    values[nv].field_len = 9;
    values[nv].texts = &one[4];
    values[nv].text_lens = &one_len[4];
    values[nv].count = 1;
    nv += 1;
  }
  if (sorts.count > 0) {
    one[5] = sorts.p[0];
    one_len[5] = sorts.n[0];
    values[nv].size = sizeof values[nv];
    values[nv].field = "sort";
    values[nv].field_len = 4;
    values[nv].texts = &one[5];
    values[nv].text_lens = &one_len[5];
    values[nv].count = 1;
    nv += 1;
  }
  if (sorts.count > 1) {
    one[6] = sorts.p[1];
    one_len[6] = sorts.n[1];
    values[nv].size = sizeof values[nv];
    values[nv].field = "sort2";
    values[nv].field_len = 5;
    values[nv].texts = &one[6];
    values[nv].text_lens = &one_len[6];
    values[nv].count = 1;
    nv += 1;
  }
  for (i = 0; i < columns.count; i++) {
    ctext[i] = columns.p[i];
    clen[i] = columns.n[i];
  }
  values[nv].size = sizeof values[nv];
  values[nv].field = "columns";
  values[nv].field_len = 7;
  values[nv].texts = ctext;
  values[nv].text_lens = clen;
  values[nv].count = columns.count;
  nv += 1;
  if (args.count > 0) {
    for (i = 0; i < args.count; i++) {
      atext[i] = args.p[i];
      alen[i] = args.n[i];
    }
    values[nv].size = sizeof values[nv];
    values[nv].field = "arguments";
    values[nv].field_len = 9;
    values[nv].texts = atext;
    values[nv].text_lens = alen;
    values[nv].count = args.count;
    nv += 1;
  }
  rc = find_view(catalog, def->name, def->name_len, id);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = gdefcore_entity_create(catalog, GDEFCORE_VIEW_TYPE,
        sizeof GDEFCORE_VIEW_TYPE - 1, id, NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang, 2, values, nv);
  }
  lines_free(&columns);
  lines_free(&args);
  lines_free(&sorts);
  return rc;
}

/* ---- reading a stored view back -------------------------------------------- */

typedef struct Owner {
  char * strings[10];
  GDEFCORE_View_Column * columns;
  GDEFCORE_View_Arg * args;
  Lines column_lines;
  Lines arg_lines;
} Owner;

static void owner_free(Owner * o) {
  size_t i;
  if (o == NULL) {
    return;
  }
  for (i = 0; i < 10; i++) {
    free(o->strings[i]);
  }
  free(o->columns);
  free(o->args);
  lines_free(&o->column_lines);
  lines_free(&o->arg_lines);
  free(o);
}

void gdefcore_view_def_free(GDEFCORE_Catalog * catalog, void * owner) {
  (void)catalog;
  owner_free((Owner *)owner);
}

static GDEFCORE_Result read_many(GDEFCORE_Catalog * catalog, const char * id,
    const char * field, Lines * out) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED,
      id, strlen(id), kLang, 2, field, strlen(field), &texts, &lens, &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    if (lines_add(out, texts[i], lens[i], "", 0, "", 0, 0) != 0) {
      rc = GDEFCORE_ERR_OOM;
      break;
    }
  }
  gdefcore_values_free(catalog, texts, lens, count);
  return rc;
}

/* Split @p s at its first two pipes into three spans. */
static int split3(char * s, size_t n, char ** a, size_t * an, char ** b, size_t * bn,
    char ** c, size_t * cn) {
  char * p1 = (char *)memchr(s, '|', n);
  char * p2;
  if (p1 == NULL) {
    return -1;
  }
  p2 = (char *)memchr(p1 + 1, '|', n - (size_t)(p1 + 1 - s));
  if (p2 == NULL) {
    return -1;
  }
  *a = s;
  *an = (size_t)(p1 - s);
  *b = p1 + 1;
  *bn = (size_t)(p2 - p1 - 1);
  *c = p2 + 1;
  *cn = (size_t)(s + n - p2 - 1);
  return 0;
}

GDEFCORE_Result gdefcore_view_get(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, GDEFCORE_View_Def * out, void ** out_owner) {
  static const char * const kOne[] = {"name", "type", "condition", "sort", "sort2",
      "format", "limit"};
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  Owner * o;
  size_t lens[7];
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || name == NULL || out == NULL || out_owner == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_owner = NULL;
  rc = find_view(catalog, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  o = (Owner *)calloc(1, sizeof *o);
  if (o == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; rc == GDEFCORE_OK && i < 7; i++) {
    rc = read_one(catalog, id, kOne[i], &o->strings[i], &lens[i]);
  }
  if (rc == GDEFCORE_OK) {
    rc = read_many(catalog, id, "columns", &o->column_lines);
  }
  if (rc == GDEFCORE_OK) {
    rc = read_many(catalog, id, "arguments", &o->arg_lines);
  }
  if (rc == GDEFCORE_OK &&
      (o->strings[0] == NULL || o->strings[1] == NULL || o->strings[5] == NULL ||
          o->strings[6] == NULL || o->column_lines.count == 0 ||
          o->column_lines.count > GDEFCORE_VIEW_MAX_COLUMNS ||
          o->arg_lines.count > GDEFCORE_VIEW_MAX_ARGS)) {
    rc = GDEFCORE_ERR_CORRUPT;
  }
  if (rc == GDEFCORE_OK) {
    o->columns = (GDEFCORE_View_Column *)calloc(o->column_lines.count, sizeof *o->columns);
    o->args = (GDEFCORE_View_Arg *)calloc(o->arg_lines.count + 1, sizeof *o->args);
    if (o->columns == NULL || o->args == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  for (i = 0; rc == GDEFCORE_OK && i < o->column_lines.count; i++) {
    char * a;
    char * b;
    char * c;
    size_t an;
    size_t bn;
    size_t cn;
    if (split3(o->column_lines.p[i], o->column_lines.n[i], &a, &an, &b, &bn, &c, &cn) != 0) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    o->columns[i].size = sizeof o->columns[i];
    o->columns[i].field = a;
    o->columns[i].field_len = an;
    o->columns[i].formatter = b;
    o->columns[i].formatter_len = bn;
    o->columns[i].label = c;
    o->columns[i].label_len = cn;
  }
  for (i = 0; rc == GDEFCORE_OK && i < o->arg_lines.count; i++) {
    char * a;
    char * b;
    char * c;
    size_t an;
    size_t bn;
    size_t cn;
    int s;
    if (split3(o->arg_lines.p[i], o->arg_lines.n[i], &a, &an, &b, &bn, &c, &cn) != 0) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    for (s = GDEFCORE_VIEW_SOURCE_URL; s <= GDEFCORE_VIEW_SOURCE_FIXED; s++) {
      if (strlen(kSourceWord[s]) == bn && memcmp(kSourceWord[s], b, bn) == 0) {
        break;
      }
    }
    if (s > GDEFCORE_VIEW_SOURCE_FIXED) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    o->args[i].size = sizeof o->args[i];
    o->args[i].name = a;
    o->args[i].name_len = an;
    o->args[i].source = s;
    o->args[i].fixed = c;
    o->args[i].fixed_len = cn;
  }
  if (rc == GDEFCORE_OK) {
    int f;
    uint64_t lim = 0;
    memset(out, 0, sizeof *out);
    out->size = sizeof *out;
    out->name = o->strings[0];
    out->name_len = lens[0];
    out->type = o->strings[1];
    out->type_len = lens[1];
    out->condition = o->strings[2];
    out->condition_len = lens[2];
    for (i = 0; i < 2; i++) {
      char * s = o->strings[3 + i];
      size_t n = lens[3 + i];
      int desc = s != NULL && n > 0 && s[0] == '-';
      if (desc) {
        s += 1;
        n -= 1;
      }
      if (i == 0) {
        out->sort = s;
        out->sort_len = n;
        out->sort_descending = desc;
      } else {
        out->sort2 = s;
        out->sort2_len = n;
        out->sort2_descending = desc;
      }
    }
    for (f = GDEFCORE_VIEW_FORMAT_TABLE; f <= GDEFCORE_VIEW_FORMAT_JSON; f++) {
      if (strlen(kFormatWord[f]) == lens[5] && memcmp(kFormatWord[f], o->strings[5], lens[5]) == 0) {
        break;
      }
    }
    for (i = 0; i < lens[6]; i++) {
      if (o->strings[6][i] < '0' || o->strings[6][i] > '9' || i > 5) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      lim = lim * 10 + (uint64_t)(o->strings[6][i] - '0');
    }
    if (f > GDEFCORE_VIEW_FORMAT_JSON) {
      rc = GDEFCORE_ERR_CORRUPT;
    }
    out->format = f;
    out->limit = lim;
    out->columns = o->columns;
    out->column_count = o->column_lines.count;
    out->args = o->args;
    out->arg_count = o->arg_lines.count;
  }
  if (rc != GDEFCORE_OK) {
    owner_free(o);
    return rc;
  }
  *out_owner = o;
  return GDEFCORE_OK;
}

static int cmp_names(const void * a, const void * b) {
  return strcmp(*(char * const *)a, *(char * const *)b);
}

GDEFCORE_Result gdefcore_view_names(GDEFCORE_Catalog * catalog, char *** out_names,
    size_t * out_count) {
  char ** ids = NULL;
  size_t count = 0;
  char ** names;
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_names == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_names = NULL;
  *out_count = 0;
  rc = gdefcore_entity_ids(catalog, GDEFCORE_VIEW_TYPE, sizeof GDEFCORE_VIEW_TYPE - 1,
      &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  names = (char **)calloc(count + 1, sizeof *names);
  if (names == NULL) {
    gdefcore_ids_free(catalog, ids, count);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    char * got = NULL;
    size_t got_len = 0;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    rc = read_one(catalog, ids[i], "name", &got, &got_len);
    if (rc == GDEFCORE_OK && got != NULL) {
      names[n++] = got;
    } else {
      free(got);
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  if (rc != GDEFCORE_OK) {
    for (i = 0; i < n; i++) {
      free(names[i]);
    }
    free(names);
    return rc;
  }
  qsort(names, n, sizeof *names, cmp_names);
  *out_names = names;
  *out_count = n;
  return GDEFCORE_OK;
}

void gdefcore_view_names_free(GDEFCORE_Catalog * catalog, char ** names, size_t count) {
  size_t i;
  (void)catalog;
  for (i = 0; names != NULL && i < count; i++) {
    free(names[i]);
  }
  free(names);
}

/* ---- running ------------------------------------------------------------------- */

struct GDEFCORE_View_Result {
  int format;
  uint64_t total;
  size_t rows;
  size_t cols;
  char (*ids)[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** cells;
  size_t * cell_len;
  char ** labels;
  size_t * label_len;
};

void gdefcore_view_result_free(GDEFCORE_View_Result * r) {
  size_t i;
  if (r == NULL) {
    return;
  }
  for (i = 0; r->cells != NULL && i < r->rows * r->cols; i++) {
    free(r->cells[i]);
  }
  for (i = 0; r->labels != NULL && i < r->cols; i++) {
    free(r->labels[i]);
  }
  free(r->cells);
  free(r->cell_len);
  free(r->labels);
  free(r->label_len);
  free(r->ids);
  free(r);
}

int gdefcore_view_result_format(const GDEFCORE_View_Result * r) {
  return r == NULL ? 0 : r->format;
}

size_t gdefcore_view_result_rows(const GDEFCORE_View_Result * r) {
  return r == NULL ? 0 : r->rows;
}

uint64_t gdefcore_view_result_total(const GDEFCORE_View_Result * r) {
  return r == NULL ? 0 : r->total;
}

size_t gdefcore_view_result_columns(const GDEFCORE_View_Result * r) {
  return r == NULL ? 0 : r->cols;
}

const char * gdefcore_view_result_label(const GDEFCORE_View_Result * r, size_t column,
    size_t * out_len) {
  if (r == NULL || column >= r->cols) {
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = r->label_len[column];
  }
  return r->labels[column];
}

const char * gdefcore_view_result_id(const GDEFCORE_View_Result * r, size_t row) {
  return r == NULL || row >= r->rows ? NULL : r->ids[row];
}

const char * gdefcore_view_result_cell(const GDEFCORE_View_Result * r, size_t row,
    size_t column, size_t * out_len) {
  if (r == NULL || row >= r->rows || column >= r->cols) {
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = r->cell_len[row * r->cols + column];
  }
  return r->cells[row * r->cols + column];
}

/* One value as a column shows it. */
static GDEFCORE_Result format_cell(const char * formatter, size_t flen,
    const FieldShape * shape, const char * const * texts, const size_t * lens, size_t count, char ** out,
    size_t * out_len) {
  size_t trunc = 0;
  Buf b;
  size_t i;
  memset(&b, 0, sizeof b);
  (void)formatter_ok(shape->type, shape->many, formatter, flen, &trunc);
  if (flen == 0) {
    formatter = "raw";
    flen = 3;
  }
  if (shape->many) {
    if (flen == 5 && memcmp(formatter, "count", 5) == 0) {
      char num[24];
      (void)snprintf(num, sizeof num, "%zu", count);
      (void)buf_str(&b, num);
    } else {
      for (i = 0; i < count; i++) {
        if (i > 0) {
          (void)buf_str(&b, ", ");
        }
        (void)buf_add(&b, texts[i], lens[i]);
      }
    }
  } else if (count > 0) {
    const char * t = texts[0];
    size_t n = lens[0];
    if (flen == 5 && memcmp(formatter, "upper", 5) == 0) {
      for (i = 0; i < n; i++) {
        char c = t[i];
        char u = c >= 'a' && c <= 'z' ? (char)(c - 32) : c;
        (void)buf_add(&b, &u, 1);
      }
    } else if (flen == 5 && memcmp(formatter, "lower", 5) == 0) {
      for (i = 0; i < n; i++) {
        char c = t[i];
        char u = c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
        (void)buf_add(&b, &u, 1);
      }
    } else if (trunc > 0) {
      size_t keep = n;
      if (n > trunc) {
        keep = trunc;
        /* not in the middle of a UTF-8 sequence */
        while (keep > 0 && ((unsigned char)t[keep] & 0xC0u) == 0x80u) {
          keep -= 1;
        }
      }
      (void)buf_add(&b, t, keep);
      if (keep < n) {
        (void)buf_str(&b, "...");
      }
    } else if (flen == 5 && memcmp(formatter, "yesno", 5) == 0) {
      (void)buf_str(&b, n == 4 && memcmp(t, "true", 4) == 0 ? "yes" : "no");
    } else if (flen == 4 && memcmp(formatter, "date", 4) == 0) {
      (void)buf_add(&b, t, n < 10 ? n : 10);
    } else {
      (void)buf_add(&b, t, n);
    }
  }
  if (b.bad) {
    free(b.p);
    return GDEFCORE_ERR_OOM;
  }
  if (b.p == NULL) {
    b.p = (char *)calloc(1, 1);
    if (b.p == NULL) {
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = b.p;
  *out_len = b.n;
  return GDEFCORE_OK;
}

typedef struct RunCtx {
  const GDEFCORE_View_Def * def;
  GDEFCORE_Request * request;
  const GDEFCORE_View_Param * params;
  size_t nparams;
  Buf out;
  int missing; /* an argument has no value: no rows */
  int refused; /* a value the condition cannot hold */
} RunCtx;

static int run_piece(void * vctx, const char * text, size_t len, int is_arg) {
  RunCtx * c = (RunCtx *)vctx;
  const GDEFCORE_View_Arg * a;
  const char * v = NULL;
  size_t vn = 0;
  size_t i;
  int k;
  if (!is_arg) {
    return buf_add(&c->out, text, len);
  }
  k = arg_index(c->def, text, len);
  if (k < 0) {
    c->refused = 1;
    return -1;
  }
  a = &c->def->args[k];
  if (a->source == GDEFCORE_VIEW_SOURCE_PRINCIPAL) {
    v = gdefcore_request_principal(c->request, &vn);
    if (v == NULL) {
      c->missing = 1;
      return buf_str(&c->out, "\"\"");
    }
  } else if (a->source == GDEFCORE_VIEW_SOURCE_FIXED) {
    v = a->fixed;
    vn = a->fixed_len;
  } else {
    int found = 0;
    for (i = 0; i < c->nparams; i++) {
      if (c->params[i].size == sizeof c->params[i] && c->params[i].name_len == a->name_len &&
          memcmp(c->params[i].name, a->name, a->name_len) == 0) {
        v = c->params[i].value;
        vn = c->params[i].value_len;
        found = 1;
        break;
      }
    }
    if (!found) {
      if (a->fixed_len == 0) {
        c->missing = 1;
        return buf_str(&c->out, "\"\"");
      }
      v = a->fixed;
      vn = a->fixed_len;
    }
  }
  if (vn > 256 || (vn > 0 && v == NULL)) {
    c->refused = 1;
    return -1;
  }
  if (buf_str(&c->out, "\"") != 0) {
    return -1;
  }
  for (i = 0; i < vn; i++) {
    unsigned char ch = (unsigned char)v[i];
    if (ch < 0x20 || ch == 0x7f) {
      c->refused = 1;
      return -1;
    }
    if (ch == '"' || ch == '\\') {
      if (buf_str(&c->out, "\\") != 0) {
        return -1;
      }
    }
    if (buf_add(&c->out, v + i, 1) != 0) {
      return -1;
    }
  }
  return buf_str(&c->out, "\"");
}

GDEFCORE_Result gdefcore_view_run(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const char * name, size_t name_len, const GDEFCORE_View_Param * params,
    size_t param_count, uint64_t offset, GDEFCORE_View_Result ** out_result) {
  GDEFCORE_View_Def def;
  void * owner = NULL;
  GDEFCORE_View_Result * r = NULL;
  RunCtx ctx;
  GDEFCORE_Access_List q;
  char ** ids = NULL;
  ColShape * shapes = NULL;
  size_t count = 0;
  uint64_t total = 0;
  size_t row;
  size_t col;
  size_t kept = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || out_result == NULL ||
      (param_count > 0 && params == NULL)) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_result = NULL;
  for (row = 0; row < param_count; row++) {
    if (params[row].size != sizeof params[row]) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  rc = gdefcore_view_get(catalog, name, name_len, &def, &owner);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_CORRUPT ? GDEFCORE_ERR_INVALID : rc;
  }
  /* A stored view that no longer fits its type is never run loosely. */
  rc = gdefcore_view_validate(catalog, &def, NULL, 0);
  if (rc != GDEFCORE_OK) {
    gdefcore_view_def_free(catalog, owner);
    return rc;
  }
  memset(&ctx, 0, sizeof ctx);
  ctx.def = &def;
  ctx.request = request;
  ctx.params = params;
  ctx.nparams = param_count;
  if (def.condition != NULL && def.condition_len > 0 &&
      walk_condition(def.condition, def.condition_len, run_piece, &ctx) != 0) {
    rc = ctx.out.bad ? GDEFCORE_ERR_OOM : GDEFCORE_ERR_INVALID;
    free(ctx.out.p);
    gdefcore_view_def_free(catalog, owner);
    return rc;
  }
  r = (GDEFCORE_View_Result *)calloc(1, sizeof *r);
  if (r == NULL) {
    free(ctx.out.p);
    gdefcore_view_def_free(catalog, owner);
    return GDEFCORE_ERR_OOM;
  }
  r->format = def.format;
  r->cols = def.column_count;
  r->labels = (char **)calloc(r->cols, sizeof *r->labels);
  r->label_len = (size_t *)calloc(r->cols, sizeof *r->label_len);
  if (r->labels == NULL || r->label_len == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  for (col = 0; rc == GDEFCORE_OK && col < r->cols; col++) {
    const GDEFCORE_View_Column * c = &def.columns[col];
    const char * l = c->label_len > 0 ? c->label : c->field;
    size_t ln = c->label_len > 0 ? c->label_len : c->field_len;
    r->labels[col] = (char *)malloc(ln + 1);
    if (r->labels[col] == NULL) {
      rc = GDEFCORE_ERR_OOM;
      break;
    }
    memcpy(r->labels[col], l, ln);
    r->labels[col][ln] = '\0';
    r->label_len[col] = ln;
  }
  if (rc == GDEFCORE_OK && !ctx.missing) {
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = def.type;
    q.type_name_len = def.type_len;
    q.lang = kLang;
    q.lang_len = 2;
    q.sort_field = def.sort_len > 0 ? def.sort : NULL;
    q.sort_field_len = def.sort_len;
    q.sort_descending = def.sort_descending;
    q.sort2_field = def.sort2_len > 0 ? def.sort2 : NULL;
    q.sort2_field_len = def.sort2_len;
    q.sort2_descending = def.sort2_descending;
    q.offset = offset;
    q.limit = def.limit;
    q.condition = ctx.out.p;
    q.condition_len = ctx.out.n;
    rc = gdefcore_access_list_page(catalog, request, &q, &ids, &count, &total);
  }
  if (rc == GDEFCORE_OK && count > 0) {
    r->ids = (char (*)[GDEFCORE_PUBLIC_ID_LEN + 1])calloc(count, sizeof *r->ids);
    r->cells = (char **)calloc(count * r->cols, sizeof *r->cells);
    r->cell_len = (size_t *)calloc(count * r->cols, sizeof *r->cell_len);
    if (r->ids == NULL || r->cells == NULL || r->cell_len == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  /* Each column's field is resolved once, and each row is read once: a row
   * costs one read of the entity however many columns, values or group items
   * it shows. */
  if (rc == GDEFCORE_OK && count > 0) {
    shapes = (ColShape *)calloc(r->cols, sizeof *shapes);
    if (shapes == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
    for (col = 0; rc == GDEFCORE_OK && col < r->cols; col++) {
      const GDEFCORE_View_Column * c = &def.columns[col];
      if (!column_field(catalog, def.type, def.type_len, c->field, c->field_len,
              &shapes[col])) {
        rc = GDEFCORE_ERR_INVALID;
      }
    }
  }
  for (row = 0; rc == GDEFCORE_OK && row < count; row++) {
    int visible = 1;
    size_t base = kept * r->cols;
    GDEFCORE_Tree * tree = NULL;
    GDEFCORE_Result rr = gdefcore_access_tree(catalog, request, ids[row], strlen(ids[row]),
        kLang, 2, &tree);
    if (rr == GDEFCORE_ERR_INVALID) {
      /* An entity with no content to show answers as one with no values:
       * empty cells. The rows themselves came from the filtered list, so a
       * row the principal may not see is never here. */
      tree = NULL;
      rr = GDEFCORE_OK;
    }
    if (rr != GDEFCORE_OK) {
      rc = rr;
      break;
    }
    for (col = 0; rc == GDEFCORE_OK && visible && col < r->cols; col++) {
      const GDEFCORE_View_Column * c = &def.columns[col];
      const char ** texts = NULL;
      size_t * lens = NULL;
      size_t n = 0;
      if (tree != NULL) {
        rc = column_values(tree, &shapes[col], &texts, &lens, &n);
      }
      if (rc != GDEFCORE_OK) {
        break;
      }
      rc = format_cell(c->formatter, c->formatter_len, &shapes[col].f, texts, lens, n,
          &r->cells[base + col], &r->cell_len[base + col]);
      free((void *)texts);
      free(lens);
    }
    gdefcore_tree_free(tree);
    if (rc == GDEFCORE_OK && visible) {
      memcpy(r->ids[kept], ids[row], GDEFCORE_PUBLIC_ID_LEN + 1);
      kept += 1;
    } else if (!visible) {
      for (col = 0; col < r->cols; col++) {
        free(r->cells[base + col]);
        r->cells[base + col] = NULL;
        r->cell_len[base + col] = 0;
      }
    }
  }
  r->rows = kept;
  r->total = total;
  free(shapes);
  gdefcore_ids_free(catalog, ids, count);
  free(ctx.out.p);
  gdefcore_view_def_free(catalog, owner);
  if (rc != GDEFCORE_OK) {
    gdefcore_view_result_free(r);
    return rc;
  }
  *out_result = r;
  return GDEFCORE_OK;
}

/* ---- csv and json ----------------------------------------------------------------- */

static int csv_cell(Buf * b, const char * s, size_t n) {
  size_t i;
  int quote = 0;
  int formula = n > 0 && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' ||
                             s[0] == '\t' || s[0] == '\r');
  for (i = 0; i < n; i++) {
    if (s[i] == ',' || s[i] == '"' || s[i] == '\r' || s[i] == '\n') {
      quote = 1;
    }
  }
  if (formula) {
    quote = 1;
  }
  if (quote && buf_str(b, "\"") != 0) {
    return -1;
  }
  if (formula && buf_str(b, "'") != 0) {
    return -1;
  }
  for (i = 0; i < n; i++) {
    if (s[i] == '"' && buf_str(b, "\"") != 0) {
      return -1;
    }
    if (buf_add(b, s + i, 1) != 0) {
      return -1;
    }
  }
  return quote ? buf_str(b, "\"") : 0;
}

static int json_string(Buf * b, const char * s, size_t n) {
  size_t i;
  if (buf_str(b, "\"") != 0) {
    return -1;
  }
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"' || c == '\\') {
      char two[2] = {'\\', (char)c};
      if (buf_add(b, two, 2) != 0) {
        return -1;
      }
    } else if (c < 0x20 || c == '<' || c == '>' || c == '&') {
      char u[8];
      (void)snprintf(u, sizeof u, "\\u%04x", c);
      if (buf_str(b, u) != 0) {
        return -1;
      }
    } else if (buf_add(b, s + i, 1) != 0) {
      return -1;
    }
  }
  return buf_str(b, "\"");
}

GDEFCORE_Result gdefcore_view_result_text(GDEFCORE_Catalog * catalog,
    const GDEFCORE_View_Result * r, char ** out_text, size_t * out_len) {
  Buf b;
  size_t row;
  size_t col;
  GDEFCORE_Result rc;
  if (catalog == NULL || r == NULL || out_text == NULL || out_len == NULL ||
      (r->format != GDEFCORE_VIEW_FORMAT_CSV && r->format != GDEFCORE_VIEW_FORMAT_JSON)) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&b, 0, sizeof b);
  if (r->format == GDEFCORE_VIEW_FORMAT_CSV) {
    for (col = 0; col < r->cols; col++) {
      if ((col > 0 && buf_str(&b, ",") != 0) ||
          csv_cell(&b, r->labels[col], r->label_len[col]) != 0) {
        break;
      }
    }
    (void)buf_str(&b, "\r\n");
    for (row = 0; row < r->rows; row++) {
      for (col = 0; col < r->cols; col++) {
        if ((col > 0 && buf_str(&b, ",") != 0) ||
            csv_cell(&b, r->cells[row * r->cols + col], r->cell_len[row * r->cols + col]) != 0) {
          break;
        }
      }
      (void)buf_str(&b, "\r\n");
    }
  } else {
    (void)buf_str(&b, "[");
    for (row = 0; row < r->rows; row++) {
      (void)buf_str(&b, row > 0 ? ",{" : "{");
      for (col = 0; col < r->cols; col++) {
        if (col > 0) {
          (void)buf_str(&b, ",");
        }
        (void)json_string(&b, r->labels[col], r->label_len[col]);
        (void)buf_str(&b, ":");
        (void)json_string(&b, r->cells[row * r->cols + col], r->cell_len[row * r->cols + col]);
      }
      (void)buf_str(&b, "}");
    }
    (void)buf_str(&b, "]");
  }
  if (b.bad) {
    free(b.p);
    return GDEFCORE_ERR_OOM;
  }
  rc = gdefcore_text_dup(catalog, b.p == NULL ? "" : b.p, b.n, out_text);
  free(b.p);
  if (rc == GDEFCORE_OK) {
    *out_len = b.n;
  }
  return rc;
}
