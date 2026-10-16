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
 * Template kinds, their layered contracts, and the validator.
 *
 * The validator reads the syntax tree through lang-tang's installed `ast/`
 * headers: it recurses over the public node structs itself, because the
 * library's own walk gives a callback no scope, no parent and no way to skip a
 * function body, and does not descend into a map literal's pairs. A node whose
 * class it does not know is refused, never skipped, so a construct the
 * validator cannot see through cannot pass.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/template.h>
#include <ghoti.io/defiant-core/access.h>

#include "template_internal.h"

#include <ghoti.io/cutil/fiber.h>
#include <ghoti.io/lang-tang/parse.h>
#include <ghoti.io/lang-tang/ast/astNodeAll.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEMPLATE_SIDE_STACK ((size_t)4194304)
#define TEMPLATE_MAX_ISSUES 64u
#define TEMPLATE_MAX_ID 256u

/* The word the plain-text lint also looks for (defiant-test lint.c). */
static const char kMarker[] = GDEFCORE_TEMPLATE_MARKER;
/* The name the render plumbing keeps for itself. */
static const char kReserved[] = "pane";

/*
 * Small helpers
 */

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static char * dup_span(const char * s, size_t n) {
  char * p = (char *)malloc(n + 1);
  if (p == NULL) {
    return NULL;
  }
  if (n > 0) {
    memcpy(p, s, n);
  }
  p[n] = '\0';
  return p;
}

static int has_word(const char * s, size_t n, const char * w) {
  size_t m = strlen(w);
  size_t i;
  if (m == 0 || m > n) {
    return 0;
  }
  for (i = 0; i + m <= n; i++) {
    if (memcmp(s + i, w, m) == 0) {
      return 1;
    }
  }
  return 0;
}

static int type_code(const char * s, size_t n) {
  static const struct {
    const char * name;
    int code;
  } kTypes[] = {{"text", GDEFCORE_TEMPLATE_TEXT},
      {"markup", GDEFCORE_TEMPLATE_MARKUP}, {"number", GDEFCORE_TEMPLATE_NUMBER},
      {"list", GDEFCORE_TEMPLATE_LIST}, {"entity", GDEFCORE_TEMPLATE_ENTITY},
      {"structure", GDEFCORE_TEMPLATE_STRUCTURE}};
  size_t i;
  for (i = 0; i < sizeof kTypes / sizeof kTypes[0]; i++) {
    if (span_eq(s, n, kTypes[i].name, strlen(kTypes[i].name))) {
      return kTypes[i].code;
    }
  }
  return 0;
}

/*
 * Reading entities
 */

static GDEFCORE_Result read_texts(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, const char * field,
    char *** texts, size_t ** lens, size_t * n) {
  return gdefcore_entity_values(catalog, cs, view, id, strlen(id), "en", 2,
      field, strlen(field), texts, lens, n);
}

/* The first value of a field as a malloc'd copy. ERR_INVALID when absent. */
static GDEFCORE_Result read_one(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, const char * field,
    char ** out, size_t * out_len) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  GDEFCORE_Result rc = read_texts(catalog, cs, view, id, field, &texts, &lens, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (n == 0) {
    gdefcore_values_free(catalog, texts, lens, n);
    return GDEFCORE_ERR_INVALID;
  }
  *out = dup_span(texts[0], lens[0]);
  *out_len = lens[0];
  gdefcore_values_free(catalog, texts, lens, n);
  return *out == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
}

/* The id of the entity of @p type whose name field is @p name. */
static GDEFCORE_Result find_named(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, const char * type, const char * name,
    size_t name_len, char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  int found = 0;
  GDEFCORE_Result rc =
      gdefcore_entity_ids(catalog, type, strlen(type), &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count && !found; i++) {
    char * got = NULL;
    size_t got_len = 0;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    rc = read_one(catalog, cs, GDEFCORE_VIEW_PUBLISHED, ids[i], "name", &got,
        &got_len);
    if (rc == GDEFCORE_OK) {
      if (span_eq(got, got_len, name, name_len)) {
        memcpy(id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
        found = 1;
      }
      free(got);
    } else if (rc == GDEFCORE_ERR_OOM) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  return found ? GDEFCORE_OK : GDEFCORE_ERR_INVALID;
}

/*
 * Contracts
 */

void gdefcore_template_contract_close(GDEFCORE_Contract * c) {
  size_t i;
  if (c == NULL) {
    return;
  }
  for (i = 0; i < c->nvars; i++) {
    free(c->vars[i].name);
    free(c->vars[i].description);
  }
  for (i = 0; i < c->nfns; i++) {
    free(c->fns[i].name);
  }
  free(c->vars);
  free(c->fns);
  free(c->kind);
  free(c);
}

static const GDEFCORE_CVar * cvar_find(const GDEFCORE_Contract * c,
    const char * name, size_t n) {
  size_t i;
  for (i = 0; i < c->nvars; i++) {
    if (span_eq(c->vars[i].name, c->vars[i].name_len, name, n)) {
      return &c->vars[i];
    }
  }
  return NULL;
}

static const GDEFCORE_CFn * cfn_find(const GDEFCORE_Contract * c,
    const char * name, size_t n) {
  size_t i;
  for (i = 0; i < c->nfns; i++) {
    if (span_eq(c->fns[i].name, c->fns[i].name_len, name, n)) {
      return &c->fns[i];
    }
  }
  return NULL;
}

static GDEFCORE_Result cvar_add(GDEFCORE_Contract * c, const char * name,
    size_t name_len, int type, const char * desc, size_t desc_len,
    const GDEFCORE_Module_Contributed * contributed) {
  GDEFCORE_CVar * v;
  if (c->nvars == c->cap_vars) {
    size_t cap = c->cap_vars == 0 ? 8 : c->cap_vars * 2;
    GDEFCORE_CVar * next = (GDEFCORE_CVar *)realloc(c->vars, cap * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    c->vars = next;
    c->cap_vars = cap;
  }
  v = &c->vars[c->nvars];
  v->name = dup_span(name, name_len);
  v->name_len = name_len;
  v->type = type;
  v->description = dup_span(desc, desc_len);
  v->description_len = desc_len;
  v->contributed = contributed;
  if (v->name == NULL || v->description == NULL) {
    free(v->name);
    free(v->description);
    return GDEFCORE_ERR_OOM;
  }
  c->nvars += 1;
  return GDEFCORE_OK;
}

static GDEFCORE_Result cfn_add(GDEFCORE_Contract * c, const char * name,
    size_t name_len, int arity) {
  GDEFCORE_CFn * f;
  if (c->nfns == c->cap_fns) {
    size_t cap = c->cap_fns == 0 ? 8 : c->cap_fns * 2;
    GDEFCORE_CFn * next = (GDEFCORE_CFn *)realloc(c->fns, cap * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    c->fns = next;
    c->cap_fns = cap;
  }
  f = &c->fns[c->nfns];
  f->name = dup_span(name, name_len);
  f->name_len = name_len;
  f->arity = arity;
  if (f->name == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  c->nfns += 1;
  return GDEFCORE_OK;
}

/*
 * A Tang identifier: letters, digits and underscore, not starting with a
 * digit. @p dotted allows `a.b`, which is how a module's variables are named
 * and how a kind a module owns can name its own.
 */
static int name_shape(const char * s, size_t n, int dotted) {
  size_t i;
  int start = 1;
  if (n == 0 || n > 64) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char ch = s[i];
    if (ch == '.' && dotted && !start && i + 1 < n) {
      start = 1;
      continue;
    }
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' ||
            (!start && ch >= '0' && ch <= '9'))) {
      return 0;
    }
    start = 0;
  }
  return 1;
}

static int ident_ok(const char * s, size_t n) {
  return name_shape(s, n, 0);
}

static int path_ok(const char * s, size_t n) {
  return name_shape(s, n, 1);
}

static void say(char ** out_message, const char * fmt, ...) {
  char buf[512];
  va_list ap;
  if (out_message == NULL) {
    return;
  }
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  *out_message = dup_span(buf, strlen(buf));
}

/* Split off the next space-separated word of line; the rest follows it. */
static int next_word(const char ** p, const char * end, const char ** w,
    size_t * n) {
  while (*p < end && **p == ' ') {
    *p += 1;
  }
  if (*p >= end) {
    return 0;
  }
  *w = *p;
  while (*p < end && **p != ' ') {
    *p += 1;
  }
  *n = (size_t)(*p - *w);
  return 1;
}

/* Parse the base variables and functions of the stored kind. */
static GDEFCORE_Result load_base(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, const char * id, GDEFCORE_Contract * c,
    char ** out_message) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc;
  rc = read_texts(catalog, cs, GDEFCORE_VIEW_PUBLISHED, id, "variables", &texts,
      &lens, &n);
  if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    const char * p = texts[i];
    const char * end = texts[i] + lens[i];
    const char * name;
    const char * type;
    size_t name_n = 0;
    size_t type_n = 0;
    int code;
    if (!next_word(&p, end, &name, &name_n) ||
        !next_word(&p, end, &type, &type_n) || !path_ok(name, name_n) ||
        (code = type_code(type, type_n)) == 0 ||
        span_eq(name, name_n, kReserved, sizeof kReserved - 1)) {
      say(out_message,
          "Template kind %s: variable %zu is malformed (name, type, description).",
          c->kind, i + 1);
      gdefcore_values_free(catalog, texts, lens, n);
      return GDEFCORE_ERR_FORMAT;
    }
    while (p < end && *p == ' ') {
      p++;
    }
    if (cvar_find(c, name, name_n) != NULL) {
      say(out_message, "Template kind %s declares the variable %.*s twice.",
          c->kind, (int)name_n, name);
      gdefcore_values_free(catalog, texts, lens, n);
      return GDEFCORE_ERR_FORMAT;
    }
    rc = cvar_add(c, name, name_n, code, p, (size_t)(end - p), NULL);
  }
  gdefcore_values_free(catalog, texts, lens, n);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  texts = NULL;
  lens = NULL;
  n = 0;
  rc = read_texts(catalog, cs, GDEFCORE_VIEW_PUBLISHED, id, "functions", &texts,
      &lens, &n);
  if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    const char * p = texts[i];
    const char * end = texts[i] + lens[i];
    const char * name;
    const char * arity;
    size_t name_n = 0;
    size_t arity_n = 0;
    int value = 0;
    size_t k;
    int ok = next_word(&p, end, &name, &name_n) &&
             next_word(&p, end, &arity, &arity_n) && ident_ok(name, name_n) &&
             !span_eq(name, name_n, kReserved, sizeof kReserved - 1) &&
             arity_n > 0 && arity_n <= 4;
    if (ok && span_eq(arity, arity_n, "any", 3)) {
      value = GDEFCORE_TEMPLATE_ARITY_ANY;
    } else if (ok) {
      for (k = 0; k < arity_n; k++) {
        if (arity[k] < '0' || arity[k] > '9') {
          ok = 0;
          break;
        }
        value = value * 10 + (arity[k] - '0');
      }
    }
    if (!ok || cvar_find(c, name, name_n) != NULL ||
        cfn_find(c, name, name_n) != NULL) {
      say(out_message,
          "Template kind %s: function %zu is malformed or repeated (name, arity).",
          c->kind, i + 1);
      gdefcore_values_free(catalog, texts, lens, n);
      return GDEFCORE_ERR_FORMAT;
    }
    rc = cfn_add(c, name, name_n, value);
  }
  gdefcore_values_free(catalog, texts, lens, n);
  return rc == GDEFCORE_ERR_INVALID ? GDEFCORE_OK : rc;
}

GDEFCORE_Result gdefcore_template_contract_open(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * kind, size_t kind_len,
    GDEFCORE_Contract ** out_contract, char ** out_message) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Contract * c;
  GDEFCORE_Host * host;
  const GDEFCORE_Module_Contributed ** items = NULL;
  size_t nitems = 0;
  size_t i;
  char * version = NULL;
  size_t version_len = 0;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  GDEFCORE_Result rc;
  if (out_message != NULL) {
    *out_message = NULL;
  }
  if (catalog == NULL || kind == NULL || kind_len == 0 || out_contract == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_contract = NULL;
  rc = find_named(catalog, projection, GDEFCORE_TEMPLATE_KIND_TYPE, kind,
      kind_len, id);
  if (rc != GDEFCORE_OK) {
    if (rc == GDEFCORE_ERR_INVALID) {
      say(out_message, "There is no template kind %.*s.", (int)kind_len, kind);
    }
    return rc;
  }
  c = (GDEFCORE_Contract *)calloc(1, sizeof *c);
  if (c == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  c->kind = dup_span(kind, kind_len);
  c->kind_len = kind_len;
  if (c->kind == NULL) {
    free(c);
    return GDEFCORE_ERR_OOM;
  }
  rc = read_one(catalog, projection, GDEFCORE_VIEW_PUBLISHED, id, "version",
      &version, &version_len);
  if (rc == GDEFCORE_OK) {
    size_t k;
    for (k = 0; k < version_len && k < 9; k++) {
      if (version[k] >= '0' && version[k] <= '9') {
        c->version = c->version * 10 + (version[k] - '0');
      }
    }
    free(version);
  } else if (rc != GDEFCORE_ERR_INVALID) {
    gdefcore_template_contract_close(c);
    return rc;
  }
  rc = load_base(catalog, projection, id, c, out_message);
  if (rc != GDEFCORE_OK) {
    gdefcore_template_contract_close(c);
    return rc;
  }
  host = gdefcore_catalog_host(catalog);
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  if (host != NULL) {
    rc = gdefcore_module_contributions(host, tenant, tenant_len, projection,
        kind, kind_len, &items, &nitems);
    if (rc != GDEFCORE_OK) {
      size_t mlen = 0;
      const char * m = gdefcore_module_error(host, &mlen);
      say(out_message, "Template kind %s: %.*s", c->kind, (int)mlen,
          m == NULL ? "its contributions cannot be ordered." : m);
      gdefcore_template_contract_close(c);
      return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
    }
  }
  for (i = 0; i < nitems; i++) {
    const GDEFCORE_Module_Contributed * item = items[i];
    const GDEFCORE_CVar * clash = cvar_find(c, item->name, item->name_len);
    int is_fn = cfn_find(c, item->name, item->name_len) != NULL;
    if (clash != NULL || is_fn) {
      if (clash != NULL && clash->contributed != NULL) {
        say(out_message,
            "Template kind %s: module %.*s cannot contribute %.*s: module "
            "%.*s already contributed it.",
            c->kind, (int)item->module_len, item->module, (int)item->name_len,
            item->name, (int)clash->contributed->module_len,
            clash->contributed->module);
      } else {
        say(out_message,
            "Template kind %s: module %.*s cannot contribute %.*s: the base of "
            "%s already declares it.",
            c->kind, (int)item->module_len, item->module, (int)item->name_len,
            item->name, c->kind);
      }
      gdefcore_module_contributions_free(host, items);
      gdefcore_template_contract_close(c);
      return GDEFCORE_ERR_INVALID;
    }
    rc = cvar_add(c, item->name, item->name_len,
        type_code(item->type, item->type_len), item->description,
        item->description_len, item);
    if (rc != GDEFCORE_OK) {
      gdefcore_module_contributions_free(host, items);
      gdefcore_template_contract_close(c);
      return rc;
    }
  }
  gdefcore_module_contributions_free(host, items);
  *out_contract = c;
  return GDEFCORE_OK;
}

int gdefcore_template_contract_version(const GDEFCORE_Contract * c) {
  return c == NULL ? 0 : c->version;
}

size_t gdefcore_template_contract_var_count(const GDEFCORE_Contract * c) {
  return c == NULL ? 0 : c->nvars;
}

static void fill_var(const GDEFCORE_CVar * v, GDEFCORE_Contract_Var * out) {
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  out->name = v->name;
  out->name_len = v->name_len;
  out->type = v->type;
  out->description = v->description;
  out->description_len = v->description_len;
  out->contributed = v->contributed;
}

GDEFCORE_Result gdefcore_template_contract_var_at(const GDEFCORE_Contract * c,
    size_t index, GDEFCORE_Contract_Var * out) {
  if (c == NULL || out == NULL || index >= c->nvars) {
    return GDEFCORE_ERR_INVALID;
  }
  fill_var(&c->vars[index], out);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_template_contract_var(const GDEFCORE_Contract * c,
    const char * name, size_t name_len, GDEFCORE_Contract_Var * out) {
  const GDEFCORE_CVar * v;
  if (c == NULL || name == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  v = cvar_find(c, name, name_len);
  if (v == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  fill_var(v, out);
  return GDEFCORE_OK;
}

size_t gdefcore_template_contract_fn_count(const GDEFCORE_Contract * c) {
  return c == NULL ? 0 : c->nfns;
}

GDEFCORE_Result gdefcore_template_contract_fn_at(const GDEFCORE_Contract * c,
    size_t index, GDEFCORE_Contract_Fn * out) {
  if (c == NULL || out == NULL || index >= c->nfns) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  out->name = c->fns[index].name;
  out->name_len = c->fns[index].name_len;
  out->arity = c->fns[index].arity;
  return GDEFCORE_OK;
}

/*
 * Reports
 */

static GDEFCORE_Template_Report * report_new(void) {
  return (GDEFCORE_Template_Report *)calloc(1, sizeof(GDEFCORE_Template_Report));
}

void gdefcore_template_report_free(GDEFCORE_Template_Report * r) {
  size_t i;
  if (r == NULL) {
    return;
  }
  for (i = 0; i < r->n; i++) {
    free(r->issues[i].template_name);
    free(r->issues[i].name);
    free(r->issues[i].message);
  }
  free(r->issues);
  free(r->text);
  free(r);
}

size_t gdefcore_template_report_count(const GDEFCORE_Template_Report * r) {
  return r == NULL ? 0 : r->n;
}

GDEFCORE_Result gdefcore_template_report_at(const GDEFCORE_Template_Report * r,
    size_t index, GDEFCORE_Template_Issue * out) {
  const GDEFCORE_CIssue * s;
  if (r == NULL || out == NULL || index >= r->n) {
    return GDEFCORE_ERR_INVALID;
  }
  s = &r->issues[index];
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  out->reason = s->reason;
  out->template_name = s->template_name;
  out->template_name_len = s->template_name_len;
  out->line = s->line;
  out->column = s->column;
  out->name = s->name;
  out->name_len = s->name_len;
  out->message = s->message;
  out->message_len = s->message_len;
  return GDEFCORE_OK;
}

/* Add a finding; the same finding twice is added once. */
static GDEFCORE_Result report_add(GDEFCORE_Template_Report * r, int reason,
    const char * tname, size_t tname_len, int line, int column,
    const char * name, size_t name_len, const char * fmt, ...) {
  char buf[640];
  va_list ap;
  GDEFCORE_CIssue * s;
  size_t i;
  size_t mlen;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  mlen = strlen(buf);
  for (i = 0; i < r->n; i++) {
    const GDEFCORE_CIssue * o = &r->issues[i];
    if (o->reason == reason && o->line == line && o->column == column &&
        span_eq(o->template_name, o->template_name_len, tname, tname_len) &&
        span_eq(o->message, o->message_len, buf, mlen)) {
      return GDEFCORE_OK;
    }
  }
  if (r->n >= TEMPLATE_MAX_ISSUES) {
    r->truncated = 1;
    return GDEFCORE_OK;
  }
  if (r->n == r->cap) {
    size_t cap = r->cap == 0 ? 8 : r->cap * 2;
    GDEFCORE_CIssue * next =
        (GDEFCORE_CIssue *)realloc(r->issues, cap * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    r->issues = next;
    r->cap = cap;
  }
  s = &r->issues[r->n];
  s->reason = reason;
  s->line = line;
  s->column = column;
  s->template_name = dup_span(tname == NULL ? "" : tname, tname_len);
  s->template_name_len = tname_len;
  s->name = dup_span(name == NULL ? "" : name, name_len);
  s->name_len = name_len;
  s->message = dup_span(buf, mlen);
  s->message_len = mlen;
  if (s->template_name == NULL || s->name == NULL || s->message == NULL) {
    free(s->template_name);
    free(s->name);
    free(s->message);
    return GDEFCORE_ERR_OOM;
  }
  r->n += 1;
  return GDEFCORE_OK;
}

/* Order by line (stable), then build the text. */
static GDEFCORE_Result report_finish(GDEFCORE_Template_Report * r) {
  size_t i;
  size_t total = 1;
  size_t at = 0;
  for (i = 1; i < r->n; i++) {
    GDEFCORE_CIssue key = r->issues[i];
    size_t j = i;
    while (j > 0 && r->issues[j - 1].line > key.line &&
           span_eq(r->issues[j - 1].template_name,
               r->issues[j - 1].template_name_len, key.template_name,
               key.template_name_len)) {
      r->issues[j] = r->issues[j - 1];
      j--;
    }
    r->issues[j] = key;
  }
  for (i = 0; i < r->n; i++) {
    total += r->issues[i].template_name_len + r->issues[i].message_len + 48;
  }
  total += 64;
  free(r->text);
  r->text = (char *)malloc(total);
  if (r->text == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  r->text[0] = '\0';
  for (i = 0; i < r->n; i++) {
    const GDEFCORE_CIssue * s = &r->issues[i];
    int w;
    if (s->template_name_len > 0 && s->line > 0) {
      w = snprintf(r->text + at, total - at, "template '%.*s', line %d: %.*s\n",
          (int)s->template_name_len, s->template_name, s->line,
          (int)s->message_len, s->message);
    } else if (s->template_name_len > 0) {
      w = snprintf(r->text + at, total - at, "template '%.*s': %.*s\n",
          (int)s->template_name_len, s->template_name, (int)s->message_len,
          s->message);
    } else if (s->line > 0) {
      w = snprintf(r->text + at, total - at, "line %d: %.*s\n", s->line,
          (int)s->message_len, s->message);
    } else {
      w = snprintf(r->text + at, total - at, "%.*s\n", (int)s->message_len,
          s->message);
    }
    if (w < 0 || (size_t)w >= total - at) {
      break;
    }
    at += (size_t)w;
  }
  if (r->truncated && at + 40 < total) {
    at += (size_t)snprintf(r->text + at, total - at,
        "more findings were left out.\n");
  }
  r->text_len = at;
  return GDEFCORE_OK;
}

const char * gdefcore_template_report_text(const GDEFCORE_Template_Report * r,
    size_t * out_len) {
  if (out_len != NULL) {
    *out_len = r == NULL ? 0 : r->text_len;
  }
  return r == NULL || r->text == NULL ? "" : r->text;
}

/*
 * The walk
 */

/*
 * Every node class begins with the base node, so a pointer to the base,
 * suitably converted, is a pointer to the node (C17 6.7.2.1p15), and this
 * section reads the tree through that downcast, as lang-tang's own AST code
 * does. Level 1 of -Wstrict-aliasing reports every such cast, so it is off
 * for this section only; lang-tang builds its AST with level 3 for the same
 * reason (its Makefile says so).
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"

typedef struct Decl {
  char * name;
  size_t name_len;
  char * path;       /* a `use`: the contract path it binds */
  size_t path_len;
  int is_fn;         /* a function the template declares */
  size_t arity;      /* of that function */
} Decl;

typedef struct Scope {
  Decl * v;
  size_t n;
  size_t cap;
} Scope;

typedef struct Ctx {
  const GDEFCORE_Contract * contract;
  const char * src;
  size_t src_len;
  GDEFCORE_Template_Report * rep;
  const char * tname;
  size_t tname_len;
  Scope * top;
  GDEFCORE_Result rc;
} Ctx;

static void scope_free(Scope * s) {
  size_t i;
  for (i = 0; i < s->n; i++) {
    free(s->v[i].name);
    free(s->v[i].path);
  }
  free(s->v);
  s->v = NULL;
  s->n = s->cap = 0;
}

static const Decl * scope_find(const Scope * s, const char * name, size_t n) {
  size_t i;
  for (i = s->n; i > 0; i--) {
    if (span_eq(s->v[i - 1].name, s->v[i - 1].name_len, name, n)) {
      return &s->v[i - 1];
    }
  }
  return NULL;
}

static void scope_add(Ctx * ctx, Scope * s, const char * name, size_t n,
    const char * path, size_t path_n, int is_fn, size_t arity) {
  Decl * d;
  if (ctx->rc != GDEFCORE_OK) {
    return;
  }
  if (path == NULL && !is_fn && scope_find(s, name, n) != NULL) {
    return;
  }
  if (s->n == s->cap) {
    size_t cap = s->cap == 0 ? 16 : s->cap * 2;
    Decl * next = (Decl *)realloc(s->v, cap * sizeof *next);
    if (next == NULL) {
      ctx->rc = GDEFCORE_ERR_OOM;
      return;
    }
    s->v = next;
    s->cap = cap;
  }
  d = &s->v[s->n];
  d->name = dup_span(name, n);
  d->name_len = n;
  d->path = path == NULL ? NULL : dup_span(path, path_n);
  d->path_len = path_n;
  d->is_fn = is_fn;
  d->arity = arity;
  if (d->name == NULL || (path != NULL && d->path == NULL)) {
    free(d->name);
    free(d->path);
    ctx->rc = GDEFCORE_ERR_OOM;
    return;
  }
  s->n += 1;
}

#define IS(n, T) GLTANG_AST_IS_##T(n)
/* The base is a node's first member; assign the cast to a local, never dereference it. */
#define AS(T, n) ((T *)(n))

/* Field readers. Each assigns the downcast to a local, as lang-tang does. */
#define ACCESS(NAME, T, RET, FIELD)                                            \
  static RET NAME(GLTANG_Ast_Node * n) {                                       \
    T * node = AS(T, n);                                                       \
    return node->FIELD;                                                        \
  }
ACCESS(ident_of, GLTANG_Ast_Node_Identifier, const char *, identifier)
ACCESS(library_of, GLTANG_Ast_Node_Library, const char *, identifier)
ACCESS(period_rhs, GLTANG_Ast_Node_Period, const char *, rhs)
ACCESS(period_lhs, GLTANG_Ast_Node_Period, GLTANG_Ast_Node *, lhs)
ACCESS(assign_lhs, GLTANG_Ast_Node_Assign, GLTANG_Ast_Node *, lhs)
ACCESS(assign_rhs, GLTANG_Ast_Node_Assign, GLTANG_Ast_Node *, rhs)
ACCESS(call_lhs, GLTANG_Ast_Node_Function_Call, GLTANG_Ast_Node *, lhs)
ACCESS(call_args, GLTANG_Ast_Node_Function_Call, GLTANG_VectorX *, arguments)
ACCESS(global_assignment, GLTANG_Ast_Node_Global, GLTANG_Ast_Node *, assignment)

static void note(Ctx * ctx, int reason, const GLTANG_Ast_Node * node,
    const char * name, size_t name_len, const char * fmt, ...) {
  char buf[600];
  va_list ap;
  int line = node == NULL ? 0 : node->location.first_line + 1;
  int col = node == NULL ? 0 : node->location.first_column + 1;
  if (ctx->rc != GDEFCORE_OK) {
    return;
  }
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  ctx->rc = report_add(ctx->rep, reason, ctx->tname, ctx->tname_len, line, col,
      name, name_len, "%s", buf);
}

/* Whether source line @p line (1-based) holds the marker word. */
static int line_marked(const Ctx * ctx, int line) {
  const char * s = ctx->src;
  size_t i = 0;
  int at = 1;
  size_t start;
  size_t end;
  if (line < 1) {
    return 0;
  }
  while (at < line && i < ctx->src_len) {
    if (s[i] == '\n') {
      at++;
    }
    i++;
  }
  if (at != line) {
    return 0;
  }
  start = i;
  end = i;
  while (end < ctx->src_len && s[end] != '\n') {
    end++;
  }
  return has_word(s + start, end - start, kMarker);
}

typedef void (*Visit)(Ctx *, Scope *, GLTANG_Ast_Node *);

static void each_vec(Ctx * ctx, Scope * sc, GLTANG_VectorX * vec, Visit fn) {
  size_t i;
  if (vec == NULL) {
    return;
  }
  for (i = 0; i < GLTANG_VECTORX_COUNT(vec); i++) {
    fn(ctx, sc, (GLTANG_Ast_Node *)GLTANG_TYPEX_P(vec->data[i]));
  }
}

/*
 * Every child of @p n, in source order. A node class this does not know is
 * reported once and not entered, so the validator never passes what it cannot
 * see.
 */
static void each_child(Ctx * ctx, Scope * sc, GLTANG_Ast_Node * n, Visit fn) {
  if (n == NULL) {
    return;
  }
  if (IS(n, ARRAY)) {
    GLTANG_Ast_Node_Array * node = AS(GLTANG_Ast_Node_Array, n);
    each_vec(ctx, sc, node->elements, fn);
  } else if (IS(n, ASSIGN)) {
    GLTANG_Ast_Node_Assign * node = AS(GLTANG_Ast_Node_Assign, n);
    fn(ctx, sc, node->lhs);
    fn(ctx, sc, node->rhs);
  } else if (IS(n, BINARY)) {
    GLTANG_Ast_Node_Binary * node = AS(GLTANG_Ast_Node_Binary, n);
    fn(ctx, sc, node->lhs);
    fn(ctx, sc, node->rhs);
  } else if (IS(n, BLOCK)) {
    GLTANG_Ast_Node_Block * node = AS(GLTANG_Ast_Node_Block, n);
    each_vec(ctx, sc, node->statements, fn);
  } else if (IS(n, CAST)) {
    GLTANG_Ast_Node_Cast * node = AS(GLTANG_Ast_Node_Cast, n);
    fn(ctx, sc, node->expression);
  } else if (IS(n, DO_WHILE)) {
    GLTANG_Ast_Node_Do_While * node = AS(GLTANG_Ast_Node_Do_While, n);
    fn(ctx, sc, node->block);
    fn(ctx, sc, node->condition);
  } else if (IS(n, FOR)) {
    GLTANG_Ast_Node_For * node = AS(GLTANG_Ast_Node_For, n);
    fn(ctx, sc, node->init);
    fn(ctx, sc, node->condition);
    fn(ctx, sc, node->update);
    fn(ctx, sc, node->block);
  } else if (IS(n, FUNCTION_CALL)) {
    GLTANG_Ast_Node_Function_Call * node = AS(GLTANG_Ast_Node_Function_Call, n);
    fn(ctx, sc, node->lhs);
    each_vec(ctx, sc, node->arguments, fn);
  } else if (IS(n, IF_ELSE)) {
    GLTANG_Ast_Node_If_Else * node = AS(GLTANG_Ast_Node_If_Else, n);
    fn(ctx, sc, node->condition);
    fn(ctx, sc, node->ifBlock);
    fn(ctx, sc, node->elseBlock);
  } else if (IS(n, INDEX)) {
    GLTANG_Ast_Node_Index * node = AS(GLTANG_Ast_Node_Index, n);
    fn(ctx, sc, node->lhs);
    fn(ctx, sc, node->rhs);
  } else if (IS(n, MAP)) {
    GLTANG_Ast_Node_Map * node = AS(GLTANG_Ast_Node_Map, n);
    GLTANG_VectorX * pairs = node->pairs;
    size_t i;
    for (i = 0; pairs != NULL && i < GLTANG_VECTORX_COUNT(pairs); i++) {
      GLTANG_Ast_Node_Map_Pair * pair =
          (GLTANG_Ast_Node_Map_Pair *)GLTANG_TYPEX_P(pairs->data[i]);
      fn(ctx, sc, pair->key);
      fn(ctx, sc, pair->value);
    }
  } else if (IS(n, PERIOD)) {
    GLTANG_Ast_Node_Period * node = AS(GLTANG_Ast_Node_Period, n);
    fn(ctx, sc, node->lhs);
  } else if (IS(n, PRINT)) {
    GLTANG_Ast_Node_Print * node = AS(GLTANG_Ast_Node_Print, n);
    fn(ctx, sc, node->expression);
  } else if (IS(n, RETURN)) {
    GLTANG_Ast_Node_Return * node = AS(GLTANG_Ast_Node_Return, n);
    fn(ctx, sc, node->expression);
  } else if (IS(n, SLICE)) {
    GLTANG_Ast_Node_Slice * node = AS(GLTANG_Ast_Node_Slice, n);
    fn(ctx, sc, node->lhs);
    fn(ctx, sc, node->start);
    fn(ctx, sc, node->end);
    fn(ctx, sc, node->skip);
  } else if (IS(n, TERNARY)) {
    GLTANG_Ast_Node_Ternary * node = AS(GLTANG_Ast_Node_Ternary, n);
    fn(ctx, sc, node->condition);
    fn(ctx, sc, node->ifTrue);
    fn(ctx, sc, node->ifFalse);
  } else if (IS(n, UNARY)) {
    GLTANG_Ast_Node_Unary * node = AS(GLTANG_Ast_Node_Unary, n);
    fn(ctx, sc, node->expression);
  } else if (IS(n, WHILE)) {
    GLTANG_Ast_Node_While * node = AS(GLTANG_Ast_Node_While, n);
    fn(ctx, sc, node->condition);
    fn(ctx, sc, node->block);
  } else if (IS(n, BOOLEAN) || IS(n, BREAK) || IS(n, CONTINUE) ||
             IS(n, FLOAT) || IS(n, IDENTIFIER) || IS(n, INTEGER) ||
             IS(n, LIBRARY) || IS(n, STRING) ||
             n->vtable == &gltang_ast_node_null_vtable) {
    /* a leaf */
  } else {
    note(ctx, GDEFCORE_ISSUE_SYNTAX, n, "", 0,
        "This construct (%s) cannot be checked, so it is not allowed.",
        n->vtable != NULL && n->vtable->name != NULL ? n->vtable->name : "?");
  }
}

/* The dotted path a `use` names: Library, or Periods over a Library. */
static int use_path(GLTANG_Ast_Node * e, char * out, size_t cap, size_t * n) {
  if (e == NULL) {
    return 0;
  }
  if (IS(e, LIBRARY)) {
    const char * id = library_of(e);
    size_t len = id == NULL ? 0 : strlen(id);
    if (len == 0 || len >= cap) {
      return 0;
    }
    memcpy(out, id, len);
    out[len] = '\0';
    *n = len;
    return 1;
  }
  if (IS(e, PERIOD)) {
    const char * rhs = period_rhs(e);
    size_t rlen = rhs == NULL ? 0 : strlen(rhs);
    if (!use_path(period_lhs(e), out, cap, n) || rlen == 0 ||
        *n + 1 + rlen >= cap) {
      return 0;
    }
    out[(*n)++] = '.';
    memcpy(out + *n, rhs, rlen);
    *n += rlen;
    out[*n] = '\0';
    return 1;
  }
  return 0;
}

static size_t param_count(const GLTANG_Ast_Node_Function * f) {
  return f->parameters == NULL ? 0 : GLTANG_VECTORX_COUNT(f->parameters);
}

/* Pass one: what the scope declares. A function body is another scope. */
static void collect(Ctx * ctx, Scope * sc, GLTANG_Ast_Node * n) {
  if (n == NULL || ctx->rc != GDEFCORE_OK) {
    return;
  }
  if (IS(n, ASSIGN)) {
    GLTANG_Ast_Node * lhs = assign_lhs(n);
    if (lhs != NULL && IS(lhs, IDENTIFIER)) {
      const char * id = ident_of(lhs);
      scope_add(ctx, sc, id, strlen(id), NULL, 0, 0, 0);
    } else {
      collect(ctx, sc, lhs);
    }
    collect(ctx, sc, assign_rhs(n));
  } else if (IS(n, USE)) {
    GLTANG_Ast_Node_Use * use = AS(GLTANG_Ast_Node_Use, n);
    char path[TEMPLATE_MAX_ID];
    size_t plen = 0;
    if (use->identifier != NULL && use_path(use->expression, path, sizeof path, &plen)) {
      scope_add(ctx, sc, use->identifier, strlen(use->identifier), path, plen, 0, 0);
    } else if (use->identifier != NULL) {
      scope_add(ctx, sc, use->identifier, strlen(use->identifier), "", 0, 0, 0);
    }
  } else if (IS(n, RANGED_FOR)) {
    GLTANG_Ast_Node_Ranged_For * rf = AS(GLTANG_Ast_Node_Ranged_For, n);
    if (rf->identifier != NULL && IS(rf->identifier, IDENTIFIER)) {
      const char * id = ident_of(rf->identifier);
      scope_add(ctx, sc, id, strlen(id), NULL, 0, 0, 0);
    }
    collect(ctx, sc, rf->expression);
    collect(ctx, sc, rf->block);
  } else if (IS(n, GLOBAL)) {
    GLTANG_Ast_Node_Global * g = AS(GLTANG_Ast_Node_Global, n);
    if (g->identifier != NULL && IS(g->identifier, IDENTIFIER)) {
      const char * id = ident_of(g->identifier);
      scope_add(ctx, sc, id, strlen(id), NULL, 0, 0, 0);
    }
    collect(ctx, sc, g->assignment);
  } else if (IS(n, FUNCTION)) {
    GLTANG_Ast_Node_Function * f = AS(GLTANG_Ast_Node_Function, n);
    if (f->identifier != NULL) {
      scope_add(ctx, sc, f->identifier, strlen(f->identifier), NULL, 0, 1,
          param_count(f));
    }
  } else {
    each_child(ctx, sc, n, collect);
  }
}

static const GDEFCORE_CFn * contract_fn(const Ctx * ctx, const char * p, size_t n) {
  return cfn_find(ctx->contract, p, n);
}

static const GDEFCORE_CVar * contract_var(const Ctx * ctx, const char * p, size_t n) {
  return cvar_find(ctx->contract, p, n);
}

static void check(Ctx * ctx, Scope * sc, GLTANG_Ast_Node * n);

static void check_function(Ctx * ctx, GLTANG_Ast_Node_Function * f) {
  Scope fs;
  size_t i;
  memset(&fs, 0, sizeof fs);
  /* The program's own functions are visible by name in a function. */
  for (i = 0; ctx->top != NULL && i < ctx->top->n; i++) {
    if (ctx->top->v[i].is_fn) {
      scope_add(ctx, &fs, ctx->top->v[i].name, ctx->top->v[i].name_len, NULL, 0,
          1, ctx->top->v[i].arity);
    }
  }
  for (i = 0; f->parameters != NULL && i < GLTANG_VECTORX_COUNT(f->parameters);
       i++) {
    GLTANG_Ast_Node * p = (GLTANG_Ast_Node *)GLTANG_TYPEX_P(f->parameters->data[i]);
    if (p != NULL && IS(p, IDENTIFIER)) {
      const char * id = ident_of(p);
      scope_add(ctx, &fs, id, strlen(id), NULL, 0, 0, 0);
    }
  }
  collect(ctx, &fs, f->block);
  check(ctx, &fs, f->block);
  scope_free(&fs);
}

static void check_use(Ctx * ctx, GLTANG_Ast_Node * n) {
  GLTANG_Ast_Node_Use * use = AS(GLTANG_Ast_Node_Use, n);
  char path[TEMPLATE_MAX_ID];
  size_t plen = 0;
  if (!use_path(use->expression, path, sizeof path, &plen)) {
    note(ctx, GDEFCORE_ISSUE_SYNTAX, n, "", 0,
        "This `use` cannot be checked, so it is not allowed.");
    return;
  }
  if (contract_var(ctx, path, plen) == NULL && contract_fn(ctx, path, plen) == NULL) {
    note(ctx, GDEFCORE_ISSUE_USE, n, path, plen,
        "`use %s` names something that is not in the contract of %s.", path,
        ctx->contract->kind);
  }
}

static void check_call(Ctx * ctx, Scope * sc, GLTANG_Ast_Node * n) {
  GLTANG_Ast_Node_Function_Call * call = AS(GLTANG_Ast_Node_Function_Call, n);
  GLTANG_Ast_Node * lhs = call->lhs;
  size_t nargs = call->arguments == NULL ? 0 : GLTANG_VECTORX_COUNT(call->arguments);
  if (lhs != NULL && IS(lhs, IDENTIFIER)) {
    const char * id = ident_of(lhs);
    size_t idn = strlen(id);
    const Decl * d = scope_find(sc, id, idn);
    if (d == NULL) {
      if (contract_fn(ctx, id, idn) != NULL) {
        note(ctx, GDEFCORE_ISSUE_CALL, n, id, idn,
            "`%s()` is called but never declared; add `use %s;`.", id, id);
      } else {
        note(ctx, GDEFCORE_ISSUE_CALL, n, id, idn,
            "`%s()` is not a function of %s.", id, ctx->contract->kind);
      }
    } else if (d->path != NULL && d->path_len > 0) {
      const GDEFCORE_CFn * f = contract_fn(ctx, d->path, d->path_len);
      if (f == NULL) {
        if (contract_var(ctx, d->path, d->path_len) != NULL) {
          note(ctx, GDEFCORE_ISSUE_CALL, n, id, idn,
              "`%s` is a variable of %s, not a function.", id,
              ctx->contract->kind);
        }
        /* otherwise the `use` itself was already reported */
      } else if (f->arity != GDEFCORE_TEMPLATE_ARITY_ANY && (size_t)f->arity != nargs) {
        note(ctx, GDEFCORE_ISSUE_CALL, n, id, idn,
            "`%s()` takes %d argument%s and is called with %zu.", id, f->arity,
            f->arity == 1 ? "" : "s", nargs);
      }
    }
  } else {
    note(ctx, GDEFCORE_ISSUE_CALL, n, "", 0,
        "A call must name its function; calling the result of an expression is "
        "not allowed.");
  }
}

static void check_period(Ctx * ctx, GLTANG_Ast_Node * n) {
  GLTANG_Ast_Node_Period * p = AS(GLTANG_Ast_Node_Period, n);
  if (p->rhs != NULL && strcmp(p->rhs, "raw") == 0) {
    int first = n->location.first_line + 1;
    int last = n->location.last_line + 1;
    int line;
    int marked = 0;
    for (line = first; line <= last && line < first + 8; line++) {
      if (line_marked(ctx, line)) {
        marked = 1;
      }
    }
    if (!marked) {
      note(ctx, GDEFCORE_ISSUE_UNSAFE, n, "raw", 3,
          "`.raw` turns escaping off and needs the word `%s` on its line (for "
          "example `// %s: why`).",
          kMarker, kMarker);
    }
  }
}

/* Pass two: every read, call and `use` against the contract. */
static void check(Ctx * ctx, Scope * sc, GLTANG_Ast_Node * n) {
  if (n == NULL || ctx->rc != GDEFCORE_OK) {
    return;
  }
  if (IS(n, IDENTIFIER)) {
    const char * id = ident_of(n);
    size_t idn = strlen(id);
    if (scope_find(sc, id, idn) == NULL) {
      if (contract_var(ctx, id, idn) != NULL || contract_fn(ctx, id, idn) != NULL) {
        note(ctx, GDEFCORE_ISSUE_NAME, n, id, idn,
            "`%s` is in the contract but the template never says `use %s;`.", id,
            id);
      } else {
        note(ctx, GDEFCORE_ISSUE_NAME, n, id, idn,
            "`%s` is read but never declared.", id);
      }
    }
  } else if (IS(n, ASSIGN)) {
    GLTANG_Ast_Node * lhs = assign_lhs(n);
    if (lhs == NULL || !IS(lhs, IDENTIFIER)) {
      check(ctx, sc, lhs);
    }
    check(ctx, sc, assign_rhs(n));
  } else if (IS(n, USE)) {
    check_use(ctx, n);
  } else if (IS(n, FUNCTION_CALL)) {
    check_call(ctx, sc, n);
    /* A bare callee was judged as a callee; anything else is read. */
    if (call_lhs(n) != NULL && !IS(call_lhs(n), IDENTIFIER)) {
      check(ctx, sc, call_lhs(n));
    }
    each_vec(ctx, sc, call_args(n), check);
  } else if (IS(n, PERIOD)) {
    check_period(ctx, n);
    check(ctx, sc, period_lhs(n));
  } else if (IS(n, FUNCTION)) {
    check_function(ctx, AS(GLTANG_Ast_Node_Function, n));
  } else if (IS(n, RANGED_FOR)) {
    GLTANG_Ast_Node_Ranged_For * rf = AS(GLTANG_Ast_Node_Ranged_For, n);
    check(ctx, sc, rf->expression);
    check(ctx, sc, rf->block);
  } else if (IS(n, GLOBAL)) {
    check(ctx, sc, global_assignment(n));
  } else {
    each_child(ctx, sc, n, check);
  }
}

#pragma GCC diagnostic pop

typedef struct Job {
  const GDEFCORE_Contract * contract;
  const char * body;
  size_t body_len;
  const char * tname;
  size_t tname_len;
  GDEFCORE_Template_Report * rep;
  GDEFCORE_Result rc;
} Job;

static void validate_run(Job * job) {
  GLTANG_Tree * tree = NULL;
  GLTANG_ParseError error;
  GLTANG_Result step;
  char * z = dup_span(job->body, job->body_len);
  Ctx ctx;
  Scope top;
  if (z == NULL) {
    job->rc = GDEFCORE_ERR_OOM;
    return;
  }
  memset(&error, 0, sizeof error);
  step = gltang_parse(z, GLTANG_PARSE_TEMPLATE, &error, &tree);
  if (step == GLTANG_ERR_FORMAT) {
    job->rc = report_add(job->rep, GDEFCORE_ISSUE_PARSE, job->tname,
        job->tname_len, error.line, error.column, "", 0, "%s", error.message);
  } else if (step == GLTANG_ERR_LIMIT) {
    job->rc = report_add(job->rep, GDEFCORE_ISSUE_PARSE, job->tname,
        job->tname_len, 0, 0, "", 0, "The template is nested too deeply.");
  } else if (step != GLTANG_OK) {
    job->rc = step == GLTANG_ERR_OOM ? GDEFCORE_ERR_OOM : GDEFCORE_ERR_INTERNAL;
  } else {
    memset(&ctx, 0, sizeof ctx);
    memset(&top, 0, sizeof top);
    ctx.contract = job->contract;
    ctx.src = z;
    ctx.src_len = job->body_len;
    ctx.rep = job->rep;
    ctx.tname = job->tname;
    ctx.tname_len = job->tname_len;
    ctx.top = &top;
    ctx.rc = GDEFCORE_OK;
    collect(&ctx, &top, gltang_tree_root(tree));
    check(&ctx, &top, gltang_tree_root(tree));
    scope_free(&top);
    job->rc = ctx.rc;
  }
  gltang_tree_destroy(tree);
  free(z);
}

static void validate_entry(void * arg) {
  validate_run((Job *)arg);
}

/* Parse and walk on a stack of our own: lang-tang recurses once per level. */
static GDEFCORE_Result validate_on_side_stack(Job * job) {
#if GCU_FIBER_SUPPORTED
  GCU_Fiber * fiber = NULL;
  GCU_Fiber_Result made =
      gcu_fiber_create(&fiber, validate_entry, job, TEMPLATE_SIDE_STACK, NULL);
  if (made != GCU_FIBER_OK) {
    return made == GCU_FIBER_ERR_OOM ? GDEFCORE_ERR_OOM : GDEFCORE_ERR_UNSUPPORTED;
  }
  job->rc = GDEFCORE_ERR_INTERNAL;
  if (gcu_fiber_switch_to(fiber) != GCU_FIBER_OK) {
    job->rc = GDEFCORE_ERR_INTERNAL;
  }
  gcu_fiber_destroy(fiber);
  return job->rc;
#else
  validate_run(job);
  return job->rc;
#endif
}

/* Validate one source into @p rep. The contract failing is a finding. */
static GDEFCORE_Result validate_into(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * kind, size_t kind_len,
    const char * body, size_t body_len, const char * tname, size_t tname_len,
    GDEFCORE_Template_Report * rep) {
  GDEFCORE_Contract * contract = NULL;
  char * message = NULL;
  GDEFCORE_Result rc;
  Job job;
  rc = gdefcore_template_contract_open(catalog, projection, kind, kind_len,
      &contract, &message);
  if (rc == GDEFCORE_ERR_INVALID || rc == GDEFCORE_ERR_FORMAT) {
    int reason = message != NULL && strstr(message, "no template kind") != NULL
        ? GDEFCORE_ISSUE_KIND
        : GDEFCORE_ISSUE_CONTRACT;
    rc = report_add(rep, reason, tname, tname_len, 0, 0, kind, kind_len, "%s",
        message == NULL ? "The kind's contract cannot be built." : message);
    free(message);
    return rc;
  }
  free(message);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&job, 0, sizeof job);
  job.contract = contract;
  job.body = body;
  job.body_len = body_len;
  job.tname = tname;
  job.tname_len = tname_len;
  job.rep = rep;
  rc = validate_on_side_stack(&job);
  gdefcore_template_contract_close(contract);
  return rc;
}

GDEFCORE_Result gdefcore_template_validate(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * kind, size_t kind_len,
    const char * body, size_t body_len, GDEFCORE_Template_Report ** out_report) {
  GDEFCORE_Template_Report * rep;
  GDEFCORE_Result rc;
  if (catalog == NULL || kind == NULL || kind_len == 0 || out_report == NULL ||
      (body == NULL && body_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_report = NULL;
  rep = report_new();
  if (rep == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  rc = validate_into(catalog, projection, kind, kind_len,
      body == NULL ? "" : body, body_len, "", 0, rep);
  if (rc == GDEFCORE_OK) {
    rc = report_finish(rep);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_template_report_free(rep);
    return rc;
  }
  *out_report = rep;
  return GDEFCORE_OK;
}

/*
 * Changesets
 */

typedef struct Stored {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * name;
  size_t name_len;
  char * kind;
  size_t kind_len;
  char * body;
  size_t body_len;
} Stored;

static void stored_free(Stored * s) {
  free(s->name);
  free(s->kind);
  free(s->body);
  memset(s, 0, sizeof *s);
}

/* Read a template through @p cs (staged values win) in @p view. */
static GDEFCORE_Result stored_read(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, Stored * s) {
  GDEFCORE_Result rc;
  memset(s, 0, sizeof *s);
  memcpy(s->id, id, GDEFCORE_PUBLIC_ID_LEN);
  rc = read_one(catalog, cs, view, id, "name", &s->name, &s->name_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = read_one(catalog, cs, view, id, "body", &s->body, &s->body_len);
  if (rc == GDEFCORE_ERR_INVALID) {
    s->body = dup_span("", 0);
    s->body_len = 0;
    rc = s->body == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    stored_free(s);
    return rc;
  }
  rc = read_one(catalog, cs, view, id, "kind", &s->kind, &s->kind_len);
  if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_INVALID) {
    stored_free(s);
    return rc;
  }
  return GDEFCORE_OK;
}

/* One stored template into @p rep; returns whether it validated clean. */
static GDEFCORE_Result stored_check(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const Stored * s,
    GDEFCORE_Template_Report * rep, size_t * out_issues) {
  size_t before = rep->n;
  GDEFCORE_Result rc;
  if (s->kind == NULL || s->kind_len == 0) {
    rc = report_add(rep, GDEFCORE_ISSUE_KIND, s->name, s->name_len, 0, 0, "", 0,
        "The template has no kind.");
  } else {
    rc = validate_into(catalog, projection, s->kind, s->kind_len, s->body,
        s->body_len, s->name, s->name_len, rep);
  }
  *out_issues = rep->n - before;
  return rc;
}

/* Whether the stored `core.template` type carries a field called kind. */
static int template_type_has_kind(GDEFCORE_Catalog * catalog) {
  size_t count = 0;
  size_t i;
  int found = 0;
  if (gdefcore_type_field_count(catalog, GDEFCORE_TEMPLATE_TYPE,
          sizeof GDEFCORE_TEMPLATE_TYPE - 1, &count) != GDEFCORE_OK) {
    return 1;
  }
  for (i = 0; i < count && !found; i++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    if (gdefcore_type_field(catalog, GDEFCORE_TEMPLATE_TYPE,
            sizeof GDEFCORE_TEMPLATE_TYPE - 1, i, &name, &name_len, &required,
            &many) == GDEFCORE_OK) {
      found = span_eq(name, name_len, "kind", 4);
      gdefcore_text_free(catalog, name);
    }
  }
  return found;
}

static int touches_type(const GDEFCORE_Changeset * cs, const char * type,
    int ops_mask) {
  size_t i;
  size_t n = gdefcore_changeset_touched_count(cs);
  for (i = 0; i < n; i++) {
    const char * t = NULL;
    size_t tn = 0;
    int op = 0;
    if (gdefcore_changeset_touched_at(cs, i, NULL, NULL, &t, &tn, &op) ==
            GDEFCORE_OK &&
        t != NULL && span_eq(t, tn, type, strlen(type)) && (op & ops_mask) != 0) {
      return 1;
    }
  }
  return 0;
}

static int has_disable(const GDEFCORE_Changeset * cs) {
  size_t i;
  size_t n = gdefcore_changeset_module_count(cs);
  for (i = 0; i < n; i++) {
    const char * name = NULL;
    size_t len = 0;
    int enable = 1;
    if (gdefcore_changeset_module_at(cs, i, &name, &len, &enable) == GDEFCORE_OK &&
        !enable) {
      return 1;
    }
  }
  return 0;
}

GDEFCORE_Result gdefcore_template_preview(GDEFCORE_Changeset * changeset,
    GDEFCORE_Template_Report ** out_report, int * out_risk) {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Template_Report * rep;
  size_t touched;
  size_t i;
  int rate = GDEFCORE_RISK_LOW;
  int breaks = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (changeset == NULL || out_report == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_report = NULL;
  catalog = gdefcore_changeset_catalog(changeset);
  rep = report_new();
  if (rep == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  touched = gdefcore_changeset_touched_count(changeset);
  /* 1. Every template the changeset writes, as it would be left. */
  for (i = 0; rc == GDEFCORE_OK && i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    Stored s;
    size_t issues = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL ||
        !span_eq(type, type_len, GDEFCORE_TEMPLATE_TYPE,
            sizeof GDEFCORE_TEMPLATE_TYPE - 1) ||
        op == GDEFCORE_TOUCH_CLEAR ||
        gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      continue;
    }
    if (op == GDEFCORE_TOUCH_PUBLISH) {
      rc = stored_read(catalog, NULL, GDEFCORE_VIEW_DRAFT, canon, &s);
    } else {
      rc = stored_read(catalog, changeset, GDEFCORE_VIEW_PUBLISHED, canon, &s);
    }
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
      continue;
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (s.kind == NULL && !template_type_has_kind(catalog)) {
      /* A type from before kinds existed cannot carry one: the template is
       * refused at render, which is where it matters, not here. */
      stored_free(&s);
      continue;
    }
    rc = stored_check(catalog, changeset, &s, rep, &issues);
    stored_free(&s);
  }
  /* 1b. Every kind the changeset writes must still build a contract. */
  for (i = 0; rc == GDEFCORE_OK && i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * kname = NULL;
    size_t kname_len = 0;
    GDEFCORE_Contract * contract = NULL;
    char * message = NULL;
    GDEFCORE_Result opened;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL ||
        !span_eq(type, type_len, GDEFCORE_TEMPLATE_KIND_TYPE,
            sizeof GDEFCORE_TEMPLATE_KIND_TYPE - 1) ||
        op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_DRAFT ||
        gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      continue;
    }
    rc = read_one(catalog, op == GDEFCORE_TOUCH_PUBLISH ? NULL : changeset,
        op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                     : GDEFCORE_VIEW_PUBLISHED,
        canon, "name", &kname, &kname_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
      continue;
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
    opened = gdefcore_template_contract_open(catalog, changeset, kname, kname_len,
        &contract, &message);
    if (opened == GDEFCORE_OK) {
      gdefcore_template_contract_close(contract);
    } else if (opened == GDEFCORE_ERR_INVALID || opened == GDEFCORE_ERR_FORMAT) {
      rc = report_add(rep, GDEFCORE_ISSUE_CONTRACT, "", 0, 0, 0, kname,
          kname_len, "%s",
          message == NULL ? "The kind's contract cannot be built." : message);
    } else {
      rc = opened;
    }
    free(message);
    free(kname);
  }
  /* 2. A module operation or a kind edit: what else would stop validating. */
  if (rc == GDEFCORE_OK &&
      (gdefcore_changeset_module_count(changeset) > 0 ||
          touches_type(changeset, GDEFCORE_TEMPLATE_KIND_TYPE,
              GDEFCORE_TOUCH_SAVE | GDEFCORE_TOUCH_PUBLISH |
                  GDEFCORE_TOUCH_ACTIVATE))) {
    char ** ids = NULL;
    size_t count = 0;
    rc = gdefcore_entity_ids(catalog, GDEFCORE_TEMPLATE_TYPE,
        sizeof GDEFCORE_TEMPLATE_TYPE - 1, &ids, &count);
    for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
      Stored s;
      GDEFCORE_Template_Report * now = NULL;
      GDEFCORE_Template_Report * then = NULL;
      size_t a = 0;
      size_t b = 0;
      size_t k;
      int staged = 0;
      size_t touched_n = gdefcore_changeset_touched_count(changeset);
      if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
        continue;
      }
      for (k = 0; k < touched_n; k++) {
        const char * tid = NULL;
        size_t tlen = 0;
        if (gdefcore_changeset_touched_at(changeset, k, &tid, &tlen, NULL, NULL,
                NULL) == GDEFCORE_OK &&
            span_eq(tid, tlen, ids[i], GDEFCORE_PUBLIC_ID_LEN)) {
          staged = 1;
        }
      }
      if (staged) {
        continue; /* already judged as the changeset leaves it */
      }
      rc = stored_read(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], &s);
      if (rc == GDEFCORE_ERR_INVALID) {
        rc = GDEFCORE_OK;
        continue;
      }
      if (rc != GDEFCORE_OK) {
        break;
      }
      now = report_new();
      then = report_new();
      if (now == NULL || then == NULL) {
        rc = GDEFCORE_ERR_OOM;
      } else {
        rc = stored_check(catalog, NULL, &s, then, &b);
      }
      if (rc == GDEFCORE_OK) {
        rc = stored_check(catalog, changeset, &s, now, &a);
      }
      if (rc == GDEFCORE_OK && b == 0 && a > 0) {
        rc = report_add(rep, GDEFCORE_ISSUE_BREAKS, s.name, s.name_len,
            now->issues[0].line, now->issues[0].column, now->issues[0].name,
            now->issues[0].name_len,
            "This template would stop validating: %.*s",
            (int)now->issues[0].message_len, now->issues[0].message);
        breaks = 1;
      }
      gdefcore_template_report_free(now);
      gdefcore_template_report_free(then);
      stored_free(&s);
    }
    gdefcore_ids_free(catalog, ids, count);
  }
  /* 3. A module operation can make a kind's contract unbuildable: a name a
   * newly enabled module contributes that the kind already has. Only a
   * contract that builds now and would not is a finding. */
  if (rc == GDEFCORE_OK && gdefcore_changeset_module_count(changeset) > 0) {
    char ** ids = NULL;
    size_t count = 0;
    rc = gdefcore_entity_ids(catalog, GDEFCORE_TEMPLATE_KIND_TYPE,
        sizeof GDEFCORE_TEMPLATE_KIND_TYPE - 1, &ids, &count);
    for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
      char * kname = NULL;
      size_t kname_len = 0;
      GDEFCORE_Contract * now = NULL;
      GDEFCORE_Contract * then = NULL;
      char * message = NULL;
      GDEFCORE_Result before;
      GDEFCORE_Result after;
      if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
        continue;
      }
      rc = read_one(catalog, changeset, GDEFCORE_VIEW_PUBLISHED, ids[i], "name",
          &kname, &kname_len);
      if (rc == GDEFCORE_ERR_INVALID) {
        rc = GDEFCORE_OK;
        continue;
      }
      if (rc != GDEFCORE_OK) {
        break;
      }
      before = gdefcore_template_contract_open(catalog, NULL, kname, kname_len,
          &now, NULL);
      after = gdefcore_template_contract_open(catalog, changeset, kname,
          kname_len, &then, &message);
      if (before == GDEFCORE_OK &&
          (after == GDEFCORE_ERR_INVALID || after == GDEFCORE_ERR_FORMAT)) {
        rc = report_add(rep, GDEFCORE_ISSUE_CONTRACT, "", 0, 0, 0, kname,
            kname_len, "%s",
            message == NULL ? "The kind's contract cannot be built." : message);
      } else if (after == GDEFCORE_ERR_OOM) {
        rc = after;
      }
      gdefcore_template_contract_close(now);
      gdefcore_template_contract_close(then);
      free(message);
      free(kname);
    }
    gdefcore_ids_free(catalog, ids, count);
  }
  /* 4. A variable a module declares in its manifest, for a kind that does
   * not exist. Only for a module this changeset enables: one already enabled
   * was judged when it was. */
  if (rc == GDEFCORE_OK && gdefcore_changeset_module_count(changeset) > 0 &&
      gdefcore_catalog_host(catalog) != NULL) {
    const GDEFCORE_Module_Contributed ** items = NULL;
    size_t nitems = 0;
    size_t tenant_len = 0;
    const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
    GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
    rc = gdefcore_module_variables(host, tenant, tenant_len, changeset, &items,
        &nitems);
    for (i = 0; rc == GDEFCORE_OK && i < nitems; i++) {
      const GDEFCORE_Module_Contributed * v = items[i];
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      size_t k;
      size_t ops = gdefcore_changeset_module_count(changeset);
      int enabling = 0;
      for (k = 0; k < ops; k++) {
        const char * mname = NULL;
        size_t mlen = 0;
        int enable = 0;
        if (gdefcore_changeset_module_at(changeset, k, &mname, &mlen, &enable) ==
                GDEFCORE_OK &&
            enable && span_eq(mname, mlen, v->module, v->module_len)) {
          enabling = 1;
        }
      }
      if (!enabling) {
        continue;
      }
      rc = find_named(catalog, changeset, GDEFCORE_TEMPLATE_KIND_TYPE, v->kind,
          v->kind_len, id);
      if (rc == GDEFCORE_ERR_INVALID) {
        rc = report_add(rep, GDEFCORE_ISSUE_KIND, "", 0, 0, 0, v->kind,
            v->kind_len,
            "Module %.*s declares template variable %.*s for kind %.*s, which "
            "does not exist.",
            (int)v->module_len, v->module, (int)v->name_len, v->name,
            (int)v->kind_len, v->kind);
      }
    }
    gdefcore_module_declared_free(host, items);
  }
  if (rc == GDEFCORE_OK) {
    rc = report_finish(rep);
  }
  if (rc == GDEFCORE_OK && out_risk != NULL) {
    rc = gdefcore_changeset_rate(changeset, &rate);
    *out_risk = (rate == GDEFCORE_RISK_HIGH || breaks || has_disable(changeset))
        ? GDEFCORE_RISK_HIGH
        : GDEFCORE_RISK_LOW;
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_template_report_free(rep);
    return rc;
  }
  *out_report = rep;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_template_vet(GDEFCORE_Changeset * changeset) {
  GDEFCORE_Template_Report * rep = NULL;
  size_t i;
  int refuse = 0;
  GDEFCORE_Result rc;
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  /* Most changesets write no template and change no module: nothing to read. */
  if (!touches_type(changeset, GDEFCORE_TEMPLATE_TYPE,
          GDEFCORE_TOUCH_SAVE | GDEFCORE_TOUCH_DRAFT | GDEFCORE_TOUCH_PUBLISH |
              GDEFCORE_TOUCH_ACTIVATE) &&
      !touches_type(changeset, GDEFCORE_TEMPLATE_KIND_TYPE,
          GDEFCORE_TOUCH_SAVE | GDEFCORE_TOUCH_PUBLISH |
              GDEFCORE_TOUCH_ACTIVATE) &&
      gdefcore_changeset_module_count(changeset) == 0) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_template_preview(changeset, &rep, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < gdefcore_template_report_count(rep); i++) {
    GDEFCORE_Template_Issue issue;
    if (gdefcore_template_report_at(rep, i, &issue) == GDEFCORE_OK &&
        issue.reason != GDEFCORE_ISSUE_BREAKS) {
      refuse = 1;
    }
  }
  if (refuse) {
    size_t n = 0;
    const char * text = gdefcore_template_report_text(rep, &n);
    rc = gdefcore_changeset_set_refusal(changeset, text, n);
    gdefcore_template_report_free(rep);
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_FORMAT : rc;
  }
  gdefcore_template_report_free(rep);
  return GDEFCORE_OK;
}

/*
 * Who may edit a template (site-admin story 3)
 */

static const char kEditLabelPrefix[] = "Edit templates of kind ";
static const char kNotAllowed[] = "That edit is not allowed.";

size_t gdefcore_template_edit_name(const char * kind, size_t kind_len, char * out,
    size_t cap) {
  size_t pre = sizeof GDEFCORE_TEMPLATE_EDIT_PREFIX - 1;
  if (kind == NULL || out == NULL || kind_len == 0 || kind_len > 255 ||
      pre + kind_len + 1 > cap) {
    return 0;
  }
  memcpy(out, GDEFCORE_TEMPLATE_EDIT_PREFIX, pre);
  memcpy(out + pre, kind, kind_len);
  out[pre + kind_len] = '\0';
  return pre + kind_len;
}

GDEFCORE_Result gdefcore_template_edit_label(GDEFCORE_Catalog * catalog,
    const char * kind, size_t kind_len, char ** out_label, size_t * out_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * label = NULL;
  size_t label_len = 0;
  char * text;
  size_t pre = sizeof kEditLabelPrefix - 1;
  GDEFCORE_Result rc;
  if (catalog == NULL || kind == NULL || kind_len == 0 || out_label == NULL ||
      out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_named(catalog, NULL, GDEFCORE_TEMPLATE_KIND_TYPE, kind, kind_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = read_one(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "label", &label,
      &label_len);
  if (rc == GDEFCORE_ERR_INVALID || (rc == GDEFCORE_OK && label_len == 0)) {
    /* A kind with no label is called by its machine name. */
    free(label);
    label = dup_span(kind, kind_len);
    label_len = kind_len;
    rc = label == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  text = (char *)malloc(pre + label_len + 1);
  if (text == NULL) {
    free(label);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(text, kEditLabelPrefix, pre);
  memcpy(text + pre, label, label_len);
  text[pre + label_len] = '\0';
  free(label);
  rc = gdefcore_text_dup(catalog, text, pre + label_len, out_label);
  free(text);
  if (rc == GDEFCORE_OK) {
    *out_len = pre + label_len;
  }
  return rc;
}

GDEFCORE_Result gdefcore_template_kind_declare(GDEFCORE_Catalog * catalog,
    const char * kind, size_t kind_len) {
  GDEFCORE_Permission perm;
  char name[300];
  size_t name_len;
  char * label = NULL;
  size_t label_len = 0;
  const char * dot;
  GDEFCORE_Result rc;
  if (catalog == NULL || kind == NULL || kind_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  name_len = gdefcore_template_edit_name(kind, kind_len, name, sizeof name);
  if (name_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_template_edit_label(catalog, kind, kind_len, &label, &label_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&perm, 0, sizeof perm);
  perm.size = sizeof perm;
  perm.label = label;
  perm.label_len = label_len;
  /* The module that owns the kind: the part of its machine name before the
   * first dot (AD-35). */
  dot = (const char *)memchr(kind, '.', kind_len);
  perm.module_name = kind;
  perm.module_name_len = dot == NULL ? kind_len : (size_t)(dot - kind);
  perm.action = name;
  perm.action_len = name_len;
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = GDEFCORE_TEMPLATE_TYPE;
  perm.type_name_len = sizeof GDEFCORE_TEMPLATE_TYPE - 1;
  rc = gdefcore_access_declare(catalog, &perm);
  gdefcore_text_free(catalog, label);
  return rc;
}

GDEFCORE_Result gdefcore_template_declare_touched(
    GDEFCORE_Changeset * changeset) {
  GDEFCORE_Catalog * catalog;
  size_t i;
  size_t n;
  GDEFCORE_Result first = GDEFCORE_OK;
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  n = gdefcore_changeset_touched_count(changeset);
  for (i = 0; i < n; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * kname = NULL;
    size_t kname_len = 0;
    GDEFCORE_Result rc;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL ||
        !span_eq(type, type_len, GDEFCORE_TEMPLATE_KIND_TYPE,
            sizeof GDEFCORE_TEMPLATE_KIND_TYPE - 1) ||
        (op != GDEFCORE_TOUCH_SAVE && op != GDEFCORE_TOUCH_PUBLISH &&
            op != GDEFCORE_TOUCH_ACTIVATE) ||
        gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      continue;
    }
    /* The changeset has been applied: read the kind as it now is. */
    rc = read_one(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon, "name", &kname,
        &kname_len);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_template_kind_declare(catalog, kname, kname_len);
      free(kname);
    } else if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
    }
    if (rc != GDEFCORE_OK && first == GDEFCORE_OK) {
      first = rc;
    }
  }
  return first;
}

int gdefcore_template_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * kind, size_t kind_len) {
  char name[300];
  size_t name_len;
  if (catalog == NULL || request == NULL || kind == NULL || kind_len == 0) {
    return 0;
  }
  name_len = gdefcore_template_edit_name(kind, kind_len, name, sizeof name);
  if (name_len == 0) {
    return 0;
  }
  return gdefcore_access_permits(catalog, request, name, name_len);
}

/* One value of a template field as the write leaves it; absent is empty. */
static GDEFCORE_Result read_or_empty(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, const char * field,
    char ** out, size_t * out_len) {
  GDEFCORE_Result rc = read_one(catalog, cs, view, id, field, out, out_len);
  if (rc == GDEFCORE_ERR_INVALID) {
    *out = dup_span("", 0);
    *out_len = 0;
    return *out == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
  }
  return rc;
}

static GDEFCORE_Result refuse_edit(GDEFCORE_Changeset * changeset,
    GDEFCORE_Result rc) {
  (void)gdefcore_changeset_set_refusal(changeset, kNotAllowed,
      sizeof kNotAllowed - 1);
  return rc;
}

/* May the request edit this template as a template of @p kind? Asked of
 * gdefcore_access_can(), about this template entity, so the editor's answer is
 * the route's and the tab's. A failure is a no. */
static int template_can(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const char * kind, size_t kind_len, const char * template_id) {
  char name[300];
  size_t name_len = gdefcore_template_edit_name(kind, kind_len, name, sizeof name);
  int allowed = 0;
  if (name_len == 0) {
    return 0;
  }
  if (gdefcore_access_can(catalog, request, name, name_len, GDEFCORE_TEMPLATE_TYPE,
          sizeof GDEFCORE_TEMPLATE_TYPE - 1, template_id, &allowed) !=
      GDEFCORE_OK) {
    return 0;
  }
  return allowed;
}

GDEFCORE_Result gdefcore_template_authorize(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request) {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Host * host;
  size_t touched;
  size_t i;
  if (changeset == NULL || request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  host = gdefcore_catalog_host(catalog);
  touched = gdefcore_changeset_touched_count(changeset);
  for (i = 0; i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * name = NULL;
    char * kind = NULL;
    char * old_kind = NULL;
    char * attached = NULL;
    char * classification = NULL;
    char * attached_type = NULL;
    size_t name_len = 0;
    size_t kind_len = 0;
    size_t old_len = 0;
    size_t attached_len = 0;
    size_t class_len = 0;
    size_t atype_len = 0;
    GDEFCORE_Result rc = GDEFCORE_OK;
    int allowed = 1;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL ||
        !span_eq(type, type_len, GDEFCORE_TEMPLATE_TYPE,
            sizeof GDEFCORE_TEMPLATE_TYPE - 1)) {
      continue;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      return refuse_edit(changeset, GDEFCORE_ERR_INVALID);
    }
    /* Before the write: what is stored. */
    rc = read_or_empty(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon, "kind",
        &old_kind, &old_len);
    /* After it: the staged values win; a clear leaves the template's kind. */
    if (rc == GDEFCORE_OK) {
      const GDEFCORE_Changeset * through = op == GDEFCORE_TOUCH_CLEAR ? NULL
                                                                       : changeset;
      int view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                               : GDEFCORE_VIEW_PUBLISHED;
      if (op == GDEFCORE_TOUCH_PUBLISH) {
        through = NULL;
      }
      rc = read_or_empty(catalog, through, view, canon, "kind", &kind, &kind_len);
      if (rc == GDEFCORE_OK) {
        rc = read_or_empty(catalog, through, view, canon, "name", &name,
            &name_len);
      }
      if (rc == GDEFCORE_OK) {
        rc = read_or_empty(catalog, through, view, canon, "attached", &attached,
            &attached_len);
      }
      if (rc == GDEFCORE_OK) {
        rc = read_or_empty(catalog, through, view, canon, "classification",
            &classification, &class_len);
      }
    }
    if (rc != GDEFCORE_OK) {
      free(name);
      free(kind);
      free(old_kind);
      free(attached);
      free(classification);
      return refuse_edit(changeset, rc);
    }
    if (kind_len == 0 && old_len > 0) {
      /* A clear, or a write that leaves the kind alone, keeps the stored one. */
      free(kind);
      kind = dup_span(old_kind, old_len);
      kind_len = old_len;
      if (kind == NULL) {
        free(name);
        free(old_kind);
        free(attached);
        free(classification);
        return refuse_edit(changeset, GDEFCORE_ERR_OOM);
      }
    }
    /* Permission first: the kind it is, and the kind it was. The one
     * decision every caller asks, about this template. */
    allowed = kind_len > 0 && template_can(catalog, request, kind, kind_len, canon);
    if (allowed && old_len > 0 && !span_eq(kind, kind_len, old_kind, old_len)) {
      allowed = template_can(catalog, request, old_kind, old_len, canon);
    }
    if (allowed && host != NULL) {
      GDEFCORE_Template_Write_Hook args;
      int vetoed = 0;
      if (attached_len > 0) {
        char * t = NULL;
        size_t tn = 0;
        if (gdefcore_entity_type(catalog, attached, attached_len, &t, &tn) ==
            GDEFCORE_OK) {
          attached_type = dup_span(t, tn);
          atype_len = tn;
          gdefcore_text_free(catalog, t);
        }
      }
      memset(&args, 0, sizeof args);
      args.size = sizeof args;
      args.template_id = canon;
      args.template_id_len = GDEFCORE_PUBLIC_ID_LEN;
      args.name = name;
      args.name_len = name_len;
      args.kind = kind;
      args.kind_len = kind_len;
      args.old_kind = old_kind;
      args.old_kind_len = old_len;
      args.attached = attached;
      args.attached_len = attached_len;
      args.attached_type = attached_type == NULL ? "" : attached_type;
      args.attached_type_len = atype_len;
      args.classification = classification;
      args.classification_len = class_len;
      rc = gdefcore_module_fire_veto(host, request, catalog,
          GDEFCORE_HOOK_TEMPLATE_WRITE, sizeof GDEFCORE_HOOK_TEMPLATE_WRITE - 1,
          &args, &vetoed);
      if (rc == GDEFCORE_OK && vetoed) {
        allowed = 0;
      }
    }
    free(name);
    free(kind);
    free(old_kind);
    free(attached);
    free(classification);
    free(attached_type);
    if (rc != GDEFCORE_OK) {
      /* A subscriber that fails fails the request (AD-10). */
      return refuse_edit(changeset, rc);
    }
    if (!allowed) {
      return refuse_edit(changeset, GDEFCORE_ERR_INVALID);
    }
  }
  return GDEFCORE_OK;
}
