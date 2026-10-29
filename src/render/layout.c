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
 * The widget catalog, layouts and the rules that choose one for a page. A
 * layout is the `core.display` entity; a rule is a `core.layout-rule`. The
 * choice is made by the route trie (form.c: gdefcore_routes_offers()), which
 * keeps the offers in one total order; this file only offers the site's rules
 * to it, takes the first layout that can be applied, and fires the alter hook.
 */

#include <ghoti.io/defiant-core/macros.h>

#include "render_internal.h"

#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/form.h>
#include <ghoti.io/defiant-core/layout.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/render.h>
#include <ghoti.io/defiant-core/request.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kLang[] = "en";
static const char kDisplayType[] = GDEFCORE_LAYOUT_TYPE;
static const char kRuleType[] = GDEFCORE_LAYOUT_RULE_TYPE;
static const char kNotAllowed[] = "That edit is not allowed.";

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

/* ---- the catalog of widget types ---------------------------------------- */

typedef struct Builtin {
  const char * name;
  const char * kind;
  const char * tmpl;
} Builtin;

/* The built-in types, in the order the catalog lists them. The index plus one
 * is GDEFCORE_Layout_Widget::builtin. */
static const Builtin kBuiltin[GDEFCORE_LAYOUT_BUILTIN_WIDGETS] = {
    {GDEFCORE_WIDGET_SITENAME, "core.sitename", "sitename"},
    {GDEFCORE_WIDGET_TITLE, "core.title", "title"},
    {GDEFCORE_WIDGET_CONTENT, "core.pane", "entity"},
    {GDEFCORE_WIDGET_MENU, "core.menu", "menu"},
    {GDEFCORE_WIDGET_TABS, "core.tabs", "tabs"},
    {GDEFCORE_WIDGET_BREADCRUMBS, "core.breadcrumbs", "breadcrumbs"},
    {GDEFCORE_WIDGET_MESSAGES, "core.messages", "messages"},
    {GDEFCORE_WIDGET_RECENT, "core.pane", "recent"},
};

static void builtin_fill(size_t i, GDEFCORE_Layout_Widget * out) {
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  out->name = kBuiltin[i].name;
  out->name_len = strlen(kBuiltin[i].name);
  out->kind = kBuiltin[i].kind;
  out->kind_len = strlen(kBuiltin[i].kind);
  out->template_name = kBuiltin[i].tmpl;
  out->template_len = strlen(kBuiltin[i].tmpl);
  out->permission = "";
  out->module = "";
  out->builtin = (int)i + 1;
}

static void module_fill(const GDEFCORE_Module_Declared_Widget * w,
    GDEFCORE_Layout_Widget * out) {
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  out->name = w->name;
  out->name_len = w->name_len;
  out->kind = w->kind;
  out->kind_len = w->kind_len;
  out->template_name = w->template_name;
  out->template_len = w->template_len;
  out->permission = w->permission;
  out->permission_len = w->permission_len;
  out->module = w->module;
  out->module_len = w->module_len;
  out->fn = w->fn;
  out->user = w->user;
}

/* The enabled modules' widget types, as the changeset @p projection would leave
 * them (NULL: as they are). Free with gdefcore_module_declared_free(). */
static GDEFCORE_Result module_widgets(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Widget *** items, size_t * n) {
  GDEFCORE_Host * host = catalog == NULL ? NULL : gdefcore_catalog_host(catalog);
  size_t tenant_len = 0;
  const uint8_t * tenant;
  *items = NULL;
  *n = 0;
  if (host == NULL) {
    return GDEFCORE_OK;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  if (tenant == NULL) {
    return GDEFCORE_OK;
  }
  return gdefcore_module_widgets(host, tenant, tenant_len, projection, items, n);
}

static void module_widgets_free(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Module_Declared_Widget ** items) {
  GDEFCORE_Host * host = catalog == NULL ? NULL : gdefcore_catalog_host(catalog);
  if (host != NULL) {
    gdefcore_module_declared_free(host, items);
  }
}

size_t gdefcore_layout_widget_count(GDEFCORE_Catalog * catalog) {
  const GDEFCORE_Module_Declared_Widget ** items = NULL;
  size_t n = 0;
  if (catalog == NULL) {
    return 0;
  }
  if (module_widgets(catalog, NULL, &items, &n) != GDEFCORE_OK) {
    n = 0;
  }
  module_widgets_free(catalog, items);
  return GDEFCORE_LAYOUT_BUILTIN_WIDGETS + n;
}

GDEFCORE_Result gdefcore_layout_widget_at(GDEFCORE_Catalog * catalog,
    size_t index, GDEFCORE_Layout_Widget * out) {
  const GDEFCORE_Module_Declared_Widget ** items = NULL;
  size_t n = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (catalog == NULL || out == NULL || out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  if (index < GDEFCORE_LAYOUT_BUILTIN_WIDGETS) {
    builtin_fill(index, out);
    return GDEFCORE_OK;
  }
  rc = module_widgets(catalog, NULL, &items, &n);
  if (rc == GDEFCORE_OK) {
    if (index - GDEFCORE_LAYOUT_BUILTIN_WIDGETS < n) {
      module_fill(items[index - GDEFCORE_LAYOUT_BUILTIN_WIDGETS], out);
    } else {
      rc = GDEFCORE_ERR_INVALID;
    }
  }
  module_widgets_free(catalog, items);
  return rc;
}

static GDEFCORE_Result widget_find_in(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * name, size_t name_len,
    GDEFCORE_Layout_Widget * out) {
  const GDEFCORE_Module_Declared_Widget ** items = NULL;
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc;
  for (i = 0; i < GDEFCORE_LAYOUT_BUILTIN_WIDGETS; i++) {
    if (span_eq(kBuiltin[i].name, strlen(kBuiltin[i].name), name, name_len)) {
      builtin_fill(i, out);
      return GDEFCORE_OK;
    }
  }
  rc = module_widgets(catalog, projection, &items, &n);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }
  rc = GDEFCORE_ERR_INVALID;
  for (i = 0; i < n; i++) {
    if (span_eq(items[i]->name, items[i]->name_len, name, name_len)) {
      module_fill(items[i], out);
      rc = GDEFCORE_OK;
      break;
    }
  }
  module_widgets_free(catalog, items);
  return rc;
}

GDEFCORE_Result gdefcore_layout_widget_find(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, GDEFCORE_Layout_Widget * out) {
  if (catalog == NULL || name == NULL || out == NULL ||
      out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  return widget_find_in(catalog, NULL, name, name_len, out);
}

/* ---- placements ------------------------------------------------------------ */

int gdefcore_render_split_pane(const char * s, size_t n, const char ** region,
    size_t * region_len, const char ** widget, size_t * widget_len,
    const char ** target, size_t * target_len) {
  size_t i = 0;
  size_t b;
  size_t k;
  while (i < n && s[i] != ' ') {
    i += 1;
  }
  if (i == 0 || i >= n) {
    return 0;
  }
  *region = s;
  *region_len = i;
  i += 1;
  b = i;
  while (i < n && s[i] != ' ') {
    i += 1;
  }
  if (i == b) {
    return 0;
  }
  *widget = s + b;
  *widget_len = i - b;
  if (i == n) {
    *target = s + n;
    *target_len = 0;
  } else {
    for (k = i + 1; k < n; k++) {
      if (s[k] == ' ') {
        return 0;
      }
    }
    if (i + 1 == n) {
      return 0;
    }
    *target = s + i + 1;
    *target_len = n - (i + 1);
  }
  return *region_len < 64 && *widget_len <= GDEFCORE_LAYOUT_NAME_MAX;
}

/* ---- reading ---------------------------------------------------------------- */

/* One single-valued field as the write would leave it; absent is "". */
static GDEFCORE_Result text_field(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, const char * field,
    char ** out, size_t * out_len) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, cs, view, id,
      GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, field, strlen(field),
      &texts, &lens, &n);
  *out = NULL;
  *out_len = 0;
  if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  if (rc == GDEFCORE_OK && n > 0) {
    *out = (char *)malloc(lens[0] + 1);
    if (*out != NULL) {
      memcpy(*out, texts[0], lens[0]);
      (*out)[lens[0]] = '\0';
      *out_len = lens[0];
    }
  } else {
    *out = (char *)calloc(1, 1);
  }
  if (rc == GDEFCORE_OK) {
    gdefcore_values_free(catalog, texts, lens, n);
  }
  return *out == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
}

/* The id of the published entity of @p type whose name is @p name. */
static GDEFCORE_Result find_published(GDEFCORE_Catalog * catalog,
    const char * type, const char * name, size_t name_len,
    char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  return gdefcore_render_find_named(catalog, type, strlen(type), name, name_len,
      id);
}

/* ---- checking a layout ------------------------------------------------------- */

static void say(char * why, size_t cap, const char * a, const char * b,
    size_t blen, const char * c) {
  if (why != NULL && cap > 0) {
    snprintf(why, cap, "%s%.*s%s", a, (int)(blen > 64 ? 64 : blen),
        b == NULL ? "" : b, c);
  }
}

static int printable_name(const char * s, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e) {
      return 0;
    }
  }
  return 1;
}

/*
 * Whether placements @p panes fit the page template whose source is @p body:
 * each is `region widget [target]`, names a region the template declares and a
 * widget type the tenant has (as @p projection would leave them). ::GDEFCORE_OK
 * or ::GDEFCORE_ERR_INVALID with @p why saying which.
 */
static GDEFCORE_Result check_panes(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * body, size_t body_len,
    char ** panes, const size_t * lens, size_t count, char * why, size_t cap) {
  char ** regions = NULL;
  size_t nregions = 0;
  size_t i;
  size_t k;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (count > GDEFCORE_LAYOUT_PANES_MAX) {
    say(why, cap, "A layout holds at most 32 placements.", NULL, 0, "");
    return GDEFCORE_ERR_INVALID;
  }
  gdefcore_render_scan_regions(body, body_len, &regions, &nregions, catalog, &rc);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count && rc == GDEFCORE_OK; i++) {
    const char * region;
    const char * widget;
    const char * target;
    size_t region_len = 0;
    size_t widget_len = 0;
    size_t target_len = 0;
    int found = 0;
    GDEFCORE_Layout_Widget w;
    w.size = sizeof w;
    if (!gdefcore_render_split_pane(panes[i], lens[i], &region, &region_len,
            &widget, &widget_len, &target, &target_len)) {
      say(why, cap, "A placement is not `region widget [target]`: ", panes[i],
          lens[i], ".");
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    for (k = 0; k < nregions; k++) {
      if (span_eq(regions[k], strlen(regions[k]), region, region_len)) {
        found = 1;
      }
    }
    if (!found) {
      say(why, cap, "The page template does not declare the region ", region,
          region_len, ".");
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    if (widget_find_in(catalog, projection, widget, widget_len, &w) !=
        GDEFCORE_OK) {
      say(why, cap, "No enabled module or built-in type offers the widget ",
          widget, widget_len, ".");
      rc = GDEFCORE_ERR_INVALID;
    }
  }
  gdefcore_render_names_free(catalog, regions, nregions);
  return rc;
}

/* What the changeset @p cs does to entity @p id, or 0 if it does not touch it. */
static int touched_op(const GDEFCORE_Changeset * cs, const char * id) {
  size_t i;
  size_t n = cs == NULL ? 0 : gdefcore_changeset_touched_count(cs);
  for (i = 0; i < n; i++) {
    const char * tid = NULL;
    size_t tid_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (gdefcore_changeset_touched_at(cs, i, &tid, &tid_len, NULL, NULL, &op) ==
            GDEFCORE_OK &&
        gdefcore_id_canonical(tid, tid_len, canon) == GDEFCORE_OK &&
        memcmp(canon, id, GDEFCORE_PUBLIC_ID_LEN) == 0) {
      return op;
    }
  }
  return 0;
}

/*
 * The body of the page template @p name, as the write @p cs would leave it. A
 * template the write clears, or renames, is not there under @p name.
 */
static GDEFCORE_Result template_source(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, const char * name, size_t name_len,
    char ** body, size_t * body_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = find_published(catalog, "core.template", name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (cs != NULL) {
    char * now = NULL;
    size_t now_len = 0;
    int same;
    if (touched_op(cs, id) == GDEFCORE_TOUCH_CLEAR) {
      return GDEFCORE_ERR_INVALID;
    }
    rc = text_field(catalog, cs, GDEFCORE_VIEW_CURRENT, id, "name", &now, &now_len);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    same = span_eq(now, now_len, name, name_len);
    free(now);
    if (!same) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  return text_field(catalog, cs, GDEFCORE_VIEW_CURRENT, id, "body", body,
      body_len);
}

GDEFCORE_Result gdefcore_layout_check(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * tmpl = NULL;
  size_t tmpl_len = 0;
  char * body = NULL;
  size_t body_len = 0;
  char ** panes = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || name == NULL || name_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_published(catalog, kDisplayType, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }
  rc = text_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "layout", &tmpl,
      &tmpl_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (tmpl_len == 0) {
    free(tmpl);
    return GDEFCORE_ERR_INVALID;
  }
  rc = template_source(catalog, NULL, tmpl, tmpl_len, &body, &body_len);
  free(tmpl);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "panes", 5, &panes, &lens,
      &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    panes = NULL;
    lens = NULL;
    count = 0;
    rc = GDEFCORE_OK;
  }
  if (rc == GDEFCORE_OK) {
    rc = check_panes(catalog, NULL, body, body_len, panes, lens, count, NULL, 0);
    gdefcore_values_free(catalog, panes, lens, count);
  }
  gdefcore_text_free(catalog, body);
  return rc;
}

/* ---- the types and the permission --------------------------------------------- */

/* An optional field is declared many: that is how the port lets a save take a
 * value away. At most one value is ever written to it. */
static void field_set(GDEFCORE_Field * field, const char * name, int required) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = required;
  field->many = !required;
}

static GDEFCORE_Result declare_edit(GDEFCORE_Catalog * catalog,
    const char * label, const char * type) {
  GDEFCORE_Permission perm;
  memset(&perm, 0, sizeof perm);
  perm.size = sizeof perm;
  perm.label = label;
  perm.label_len = strlen(label);
  perm.module_name = "core";
  perm.module_name_len = 4;
  perm.action = GDEFCORE_LAYOUT_EDIT;
  perm.action_len = sizeof GDEFCORE_LAYOUT_EDIT - 1;
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = type;
  perm.type_name_len = strlen(type);
  return gdefcore_access_declare(catalog, &perm);
}

GDEFCORE_Result gdefcore_layout_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field rule[6];
  int kind = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  field_set(&rule[0], "name", 1);
  field_set(&rule[1], "path", 1);
  field_set(&rule[2], "layout", 1);
  field_set(&rule[3], "type", 0);
  field_set(&rule[4], "exact", 0);
  field_set(&rule[5], "weight", 0);
  rc = GDEFCORE_OK;
  if (gdefcore_type_kind(catalog, kRuleType, strlen(kRuleType), &kind) !=
      GDEFCORE_OK) {
    rc = gdefcore_type_define(catalog, kRuleType, strlen(kRuleType),
        GDEFCORE_TYPE_CONFIG, rule, 6);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_edit(catalog, GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL, kDisplayType);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_edit(catalog, GDEFCORE_LAYOUT_EDIT_RULE_LABEL, kRuleType);
  }
  return rc;
}

int gdefcore_layout_may_edit(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request) {
  if (catalog == NULL || request == NULL) {
    return 0;
  }
  return gdefcore_access_permits(catalog, request, GDEFCORE_LAYOUT_EDIT,
             sizeof GDEFCORE_LAYOUT_EDIT - 1) != 0;
}

/* ---- staging a rule ----------------------------------------------------------- */

static int machine_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
         c == '_' || c == '-';
}

static int ident_ok(const char * s, size_t n, size_t max) {
  size_t i;
  if (s == NULL || n == 0 || n > max || s[0] < 'a' || s[0] > 'z') {
    return 0;
  }
  for (i = 1; i < n; i++) {
    if (!machine_char(s[i])) {
      return 0;
    }
  }
  return 1;
}

static int site_name_ok(const char * s, size_t n) {
  size_t pl = sizeof GDEFCORE_LAYOUT_SITE_PREFIX - 1;
  return n > pl && memcmp(s, GDEFCORE_LAYOUT_SITE_PREFIX, pl) == 0 &&
         ident_ok(s, n, GDEFCORE_LAYOUT_NAME_MAX);
}

/* A type name as the port spells one: `module.name`. */
static int type_name_ok(const char * s, size_t n) {
  size_t i;
  size_t dot = n;
  if (s == NULL || n < 3 || n > GDEFCORE_LAYOUT_NAME_MAX) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (c == '.') {
      if (dot != n || i == 0 || i + 1 == n) {
        return 0;
      }
      dot = i;
    } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_' ||
                   (c == '-' && dot != n))) {
      return 0;
    }
  }
  return dot != n;
}

static int weight_ok(const char * s, size_t n) {
  size_t i = 0;
  size_t digits = 0;
  if (n == 0 || n > 11) {
    return 0;
  }
  if (s[0] == '-') {
    i = 1;
  }
  for (; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') {
      return 0;
    }
    digits += 1;
  }
  return digits > 0 && digits <= 9;
}

static void value_set(GDEFCORE_Value * value, const char * field,
    const char ** slot, size_t * len_slot, const char * text, size_t len,
    int set) {
  memset(value, 0, sizeof *value);
  *slot = text;
  *len_slot = len;
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = slot;
  value->text_lens = len_slot;
  value->count = set ? 1 : 0;
}

GDEFCORE_Result gdefcore_layout_stage_rule(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const GDEFCORE_Layout_Rule * rule) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Value values[6];
  const char * slots[6];
  size_t lens[6];
  char number[16];
  GDEFCORE_Result rc;
  if (changeset == NULL || rule == NULL || rule->size != sizeof *rule ||
      !site_name_ok(name, name_len) || rule->path == NULL ||
      !gdefcore_route_pattern_ok(rule->path, rule->path_len, NULL) ||
      !ident_ok(rule->layout, rule->layout_len, GDEFCORE_LAYOUT_NAME_MAX) ||
      (rule->type != NULL && !type_name_ok(rule->type, rule->type_len)) ||
      (rule->type == NULL && rule->type_len != 0) || rule->weight > 999999999 ||
      rule->weight < -999999999) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  rc = find_published(catalog, kRuleType, name, name_len, id);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = gdefcore_entity_create(catalog, kRuleType, strlen(kRuleType), id, NULL);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  snprintf(number, sizeof number, "%d", rule->weight);
  value_set(&values[0], "name", &slots[0], &lens[0], name, name_len, 1);
  value_set(&values[1], "path", &slots[1], &lens[1], rule->path, rule->path_len,
      1);
  value_set(&values[2], "layout", &slots[2], &lens[2], rule->layout,
      rule->layout_len, 1);
  value_set(&values[3], "type", &slots[3], &lens[3], rule->type, rule->type_len,
      rule->type != NULL);
  value_set(&values[4], "exact", &slots[4], &lens[4], "true", 4, rule->exact != 0);
  value_set(&values[5], "weight", &slots[5], &lens[5], number, strlen(number),
      rule->weight != 0);
  return gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      sizeof kLang - 1, values, 6);
}

GDEFCORE_Result gdefcore_layout_stage_forget(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  if (changeset == NULL || !site_name_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_published(gdefcore_changeset_catalog(changeset), kRuleType, name,
      name_len, id);
  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_entity_clear(changeset, id, GDEFCORE_PUBLIC_ID_LEN);
}

/* ---- vetting a changeset ------------------------------------------------------ */

static GDEFCORE_Result refuse(GDEFCORE_Changeset * changeset, const char * what,
    const char * name, size_t name_len, const char * why) {
  char text[384];
  snprintf(text, sizeof text, "%s '%.*s' is refused: %s", what,
      (int)(name_len > 64 ? 64 : name_len),
      name == NULL || !printable_name(name, name_len > 64 ? 64 : name_len)
          ? "?"
          : name,
      why);
  (void)gdefcore_changeset_set_refusal(changeset, text, strlen(text));
  return GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result vet_display(GDEFCORE_Changeset * changeset,
    GDEFCORE_Catalog * catalog, const char * id, int op) {
  const GDEFCORE_Changeset * through = op == GDEFCORE_TOUCH_PUBLISH ? NULL : changeset;
  int view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                           : GDEFCORE_VIEW_CURRENT;
  char * name = NULL;
  char * tmpl = NULL;
  char * body = NULL;
  size_t name_len = 0;
  size_t tmpl_len = 0;
  size_t body_len = 0;
  char ** panes = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  char why[256];
  GDEFCORE_Result rc;
  GDEFCORE_Result out = GDEFCORE_OK;
  rc = text_field(catalog, through, view, id, "name", &name, &name_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = text_field(catalog, through, view, id, "layout", &tmpl, &tmpl_len);
  if (rc != GDEFCORE_OK) {
    free(name);
    return rc;
  }
  why[0] = '\0';
  if (tmpl_len == 0) {
    out = refuse(changeset, "Layout", name, name_len,
        "it names no page template.");
    goto done;
  }
  rc = template_source(catalog, changeset, tmpl, tmpl_len, &body, &body_len);
  if (rc == GDEFCORE_ERR_INVALID) {
    out = refuse(changeset, "Layout", name, name_len,
        "its page template does not exist.");
    goto done;
  }
  if (rc != GDEFCORE_OK) {
    out = rc;
    goto done;
  }
  rc = gdefcore_entity_values(catalog, through, view, id, GDEFCORE_PUBLIC_ID_LEN,
      kLang, sizeof kLang - 1, "panes", 5, &panes, &lens, &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    panes = NULL;
    lens = NULL;
    count = 0;
  } else if (rc != GDEFCORE_OK) {
    out = rc;
    goto done;
  }
  rc = check_panes(catalog, changeset, body, body_len, panes, lens, count, why,
      sizeof why);
  gdefcore_values_free(catalog, panes, lens, count);
  if (rc == GDEFCORE_ERR_INVALID) {
    out = refuse(changeset, "Layout", name, name_len,
        why[0] != '\0' ? why : "it does not fit its page template.");
  } else {
    out = rc;
  }
done:
  gdefcore_text_free(catalog, body);
  free(name);
  free(tmpl);
  return out;
}

static GDEFCORE_Result vet_rule(GDEFCORE_Changeset * changeset,
    GDEFCORE_Catalog * catalog, const char * id, int op) {
  const GDEFCORE_Changeset * through = op == GDEFCORE_TOUCH_PUBLISH ? NULL : changeset;
  int view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                           : GDEFCORE_VIEW_CURRENT;
  char * f[6];
  size_t n[6];
  static const char * const kName[6] = {"name", "path", "layout", "type",
      "exact", "weight"};
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  GDEFCORE_Result out = GDEFCORE_OK;
  memset(f, 0, sizeof f);
  for (i = 0; i < 6 && rc == GDEFCORE_OK; i++) {
    rc = text_field(catalog, through, view, id, kName[i], &f[i], &n[i]);
  }
  if (rc != GDEFCORE_OK) {
    for (i = 0; i < 6; i++) {
      free(f[i]);
    }
    return rc;
  }
  if (!site_name_ok(f[0], n[0])) {
    out = refuse(changeset, "Layout rule", f[0], n[0],
        "its name is not site.<name> of a-z, 0-9, '.', '_' and '-'.");
  } else if (!gdefcore_route_pattern_ok(f[1], n[1], NULL)) {
    out = refuse(changeset, "Layout rule", f[0], n[0],
        "its path is not a route pattern.");
  } else if (!ident_ok(f[2], n[2], GDEFCORE_LAYOUT_NAME_MAX)) {
    out = refuse(changeset, "Layout rule", f[0], n[0],
        "its layout is not a name of a-z, 0-9, '.', '_' and '-'.");
  } else if (n[3] > 0 && !type_name_ok(f[3], n[3])) {
    out = refuse(changeset, "Layout rule", f[0], n[0],
        "its type is not an entity type name.");
  } else if (n[4] > 0 && !span_eq(f[4], n[4], "true", 4)) {
    out = refuse(changeset, "Layout rule", f[0], n[0],
        "its exact flag is neither absent nor true.");
  } else if (n[5] > 0 && !weight_ok(f[5], n[5])) {
    out = refuse(changeset, "Layout rule", f[0], n[0],
        "its weight is not an integer.");
  }
  for (i = 0; i < 6; i++) {
    free(f[i]);
  }
  return out;
}

/* Whether the changeset touches the entity of the page template called @p name. */
static int template_touched(GDEFCORE_Changeset * changeset, GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len) {
  size_t touched = gdefcore_changeset_touched_count(changeset);
  size_t i;
  for (i = 0; i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * stored = NULL;
    char * left = NULL;
    size_t stored_len = 0;
    size_t left_len = 0;
    int hit = 0;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL || !span_eq(type, type_len, "core.template", 13) ||
        gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      continue;
    }
    if (text_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon, "name", &stored,
            &stored_len) == GDEFCORE_OK) {
      hit = span_eq(stored, stored_len, name, name_len);
      free(stored);
    }
    if (!hit && text_field(catalog, changeset, GDEFCORE_VIEW_CURRENT, canon,
                    "name", &left, &left_len) == GDEFCORE_OK) {
      hit = span_eq(left, left_len, name, name_len);
      free(left);
    }
    if (hit) {
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result vet_template_users(GDEFCORE_Changeset * changeset,
    GDEFCORE_Catalog * catalog) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  size_t touched = gdefcore_changeset_touched_count(changeset);
  int any = 0;
  for (i = 0; i < touched && !any; i++) {
    const char * type = NULL;
    size_t type_len = 0;
    any = gdefcore_changeset_touched_at(changeset, i, NULL, NULL, &type,
              &type_len, NULL) == GDEFCORE_OK &&
          type != NULL && span_eq(type, type_len, "core.template", 13);
  }
  /* So does a module the write enables or disables: it takes its widget types
   * with it. */
  any = any || gdefcore_changeset_module_count(changeset) > 0;
  if (!any) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_entity_ids(catalog, kDisplayType, strlen(kDisplayType), &ids,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count && rc == GDEFCORE_OK; i++) {
    char * tmpl = NULL;
    size_t tmpl_len = 0;
    int uses;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN ||
        touched_op(changeset, ids[i]) != 0) {
      continue;   /* a layout the write touches was vetted as it is left */
    }
    if (text_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], "layout",
            &tmpl, &tmpl_len) != GDEFCORE_OK) {
      continue;
    }
    uses = tmpl_len > 0 &&
           (gdefcore_changeset_module_count(changeset) > 0 ||
               template_touched(changeset, catalog, tmpl, tmpl_len));
    free(tmpl);
    if (uses) {
      rc = vet_display(changeset, catalog, ids[i], GDEFCORE_TOUCH_SAVE);
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  return rc;
}

GDEFCORE_Result gdefcore_layout_vet(GDEFCORE_Changeset * changeset) {
  GDEFCORE_Catalog * catalog;
  size_t touched;
  size_t i;
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  touched = gdefcore_changeset_touched_count(changeset);
  for (i = 0; i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    int display;
    GDEFCORE_Result rc;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL) {
      continue;
    }
    display = span_eq(type, type_len, kDisplayType, sizeof kDisplayType - 1);
    if (!display && !span_eq(type, type_len, kRuleType, sizeof kRuleType - 1)) {
      continue;
    }
    if (op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_UNPUBLISH) {
      continue;   /* nothing is written that a page could be built from */
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INVALID;
    }
    rc = display ? vet_display(changeset, catalog, canon, op)
                 : vet_rule(changeset, catalog, canon, op);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  /* A page template the write changes, renames or removes leaves every layout
   * that uses it as the write leaves the template. */
  return vet_template_users(changeset, catalog);
}

/* ---- who may edit --------------------------------------------------------------- */

enum { kShapeFields = 2 };
static const char * const kShapeName[kShapeFields] = {"name", "layout"};

static GDEFCORE_Result decide_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * type, const char * id,
    const GDEFCORE_Changeset * through, int view, int * allowed) {
  GDEFCORE_Condition_Value values[kShapeFields];
  char * text[kShapeFields];
  size_t len[kShapeFields];
  size_t revisions = 0;
  size_t i;
  int ok = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  *allowed = 0;
  memset(text, 0, sizeof text);
  for (i = 0; i < kShapeFields && rc == GDEFCORE_OK; i++) {
    rc = text_field(catalog, through, view, id, kShapeName[i], &text[i], &len[i]);
  }
  if (rc == GDEFCORE_OK && len[0] > 0) {
    for (i = 0; i < kShapeFields; i++) {
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = kShapeName[i];
      values[i].field_len = strlen(kShapeName[i]);
      values[i].text = text[i];
      values[i].text_len = len[i];
    }
    rc = gdefcore_access_can_with(catalog, request, GDEFCORE_LAYOUT_EDIT,
        sizeof GDEFCORE_LAYOUT_EDIT - 1, type, strlen(type), id, values,
        kShapeFields, &ok);
    if (rc == GDEFCORE_OK && ok) {
      rc = gdefcore_entity_revision_count(catalog, id, GDEFCORE_PUBLIC_ID_LEN,
          &revisions);
      if (rc == GDEFCORE_OK && revisions > 0) {
        rc = gdefcore_access_can(catalog, request, GDEFCORE_LAYOUT_EDIT,
            sizeof GDEFCORE_LAYOUT_EDIT - 1, type, strlen(type), id, &ok);
      }
    }
  }
  for (i = 0; i < kShapeFields; i++) {
    free(text[i]);
  }
  if (rc == GDEFCORE_ERR_OOM) {
    return rc;
  }
  *allowed = rc == GDEFCORE_OK && ok;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_layout_authorize(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request) {
  GDEFCORE_Catalog * catalog;
  size_t touched;
  size_t i;
  if (changeset == NULL || request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  touched = gdefcore_changeset_touched_count(changeset);
  for (i = 0; i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * kind;
    const GDEFCORE_Changeset * through;
    int view;
    int allowed = 0;
    GDEFCORE_Result rc;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL) {
      continue;
    }
    if (span_eq(type, type_len, kDisplayType, sizeof kDisplayType - 1)) {
      kind = kDisplayType;
    } else if (span_eq(type, type_len, kRuleType, sizeof kRuleType - 1)) {
      kind = kRuleType;
    } else {
      continue;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      (void)gdefcore_changeset_set_refusal(changeset, kNotAllowed,
          sizeof kNotAllowed - 1);
      return GDEFCORE_ERR_INVALID;
    }
    through = op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_PUBLISH
                  ? NULL
                  : changeset;
    view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                         : GDEFCORE_VIEW_CURRENT;
    rc = decide_edit(catalog, request, kind, canon, through, view, &allowed);
    if (rc != GDEFCORE_OK || !allowed) {
      (void)gdefcore_changeset_set_refusal(changeset, kNotAllowed,
          sizeof kNotAllowed - 1);
      return rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_INVALID;
    }
  }
  return GDEFCORE_OK;
}

/* ---- the site's rules, offered to the trie ------------------------------------ */

/* The type of the entity the request resolved to, or "" for a page with none. */
static char * page_type(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    size_t * out_len) {
  size_t res_len = 0;
  const char * res = gdefcore_request_resolution(request, &res_len);
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type = NULL;
  size_t type_len = 0;
  *out_len = 0;
  if (res == NULL || res_len == 0 ||
      gdefcore_id_canonical(res, res_len, canon) != GDEFCORE_OK ||
      gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type,
          &type_len) != GDEFCORE_OK) {
    return NULL;
  }
  *out_len = type_len;
  return type;
}

void gdefcore_layout_site_contributor(const GDEFCORE_Contributor_Call * call) {
  GDEFCORE_Catalog * catalog;
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  char * ptype = NULL;
  size_t ptype_len = 0;
  if (call == NULL || call->catalog == NULL || call->request == NULL) {
    return;
  }
  catalog = call->catalog;
  if (gdefcore_entity_ids(catalog, kRuleType, strlen(kRuleType), &ids, &count) !=
      GDEFCORE_OK) {
    return;
  }
  ptype = page_type(catalog, call->request, &ptype_len);
  for (i = 0; i < count; i++) {
    char * f[6];
    size_t n[6];
    static const char * const kName[6] = {"name", "path", "layout", "type",
        "exact", "weight"};
    size_t k;
    GDEFCORE_Result rc = GDEFCORE_OK;
    GDEFCORE_Offer offer;
    int weight = 0;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    memset(f, 0, sizeof f);
    for (k = 0; k < 6 && rc == GDEFCORE_OK; k++) {
      /* An unpublished rule is not a rule yet: the published view has no
       * values for it, which reads as every field being empty. */
      rc = text_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], kName[k],
          &f[k], &n[k]);
    }
    if (rc == GDEFCORE_OK && n[0] > 0 && n[1] > 0 && n[2] > 0 &&
        (n[3] == 0 || span_eq(f[3], n[3], ptype == NULL ? "" : ptype, ptype_len)) &&
        (n[4] == 0 || span_eq(f[4], n[4], "true", 4)) &&
        (n[5] == 0 || weight_ok(f[5], n[5]))) {
      if (n[5] > 0) {
        weight = (int)strtol(f[5], NULL, 10);
      }
      memset(&offer, 0, sizeof offer);
      offer.size = sizeof offer;
      offer.value = f[2];
      offer.value_len = n[2];
      offer.source = f[0];
      offer.source_len = n[0];
      offer.pattern = f[1];
      offer.pattern_len = n[1];
      offer.exact = n[4] > 0;
      offer.weight = weight;
      offer.refined = n[3] > 0;
      offer.site = 1;
      (void)gdefcore_contributor_offer(call, &offer);
    }
    for (k = 0; k < 6; k++) {
      free(f[k]);
    }
  }
  gdefcore_text_free(catalog, ptype);
  gdefcore_ids_free(catalog, ids, count);
}

/* ---- choosing a layout ---------------------------------------------------------- */

GDEFCORE_Result gdefcore_layout_select(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request, const char * path,
    size_t path_len, char ** out_name, size_t * out_len) {
  GDEFCORE_Routes * own = NULL;
  GDEFCORE_Offers * offers = NULL;
  char * slashed = NULL;
  char * chosen = NULL;
  size_t chosen_len = 0;
  size_t i;
  size_t n;
  GDEFCORE_Host * host;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || path == NULL || path_len == 0 ||
      out_name == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_name = NULL;
  *out_len = 0;
  /* An alias is spelled without its slash (`hello`), and the page is at
   * `/hello`: the trie's patterns are matched against the latter. */
  if (path[0] != '/') {
    slashed = (char *)malloc(path_len + 2);
    if (slashed == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    slashed[0] = '/';
    memcpy(slashed + 1, path, path_len);
    slashed[path_len + 1] = '\0';
    path = slashed;
    path_len += 1;
  }
  if (routes == NULL) {
    rc = gdefcore_routes_create(NULL, &own);
    if (rc != GDEFCORE_OK) {
      free(slashed);
      return rc;
    }
    routes = own;
  }
  rc = gdefcore_routes_offers(routes, catalog, request,
      GDEFCORE_CONTRIBUTOR_LAYOUT, sizeof GDEFCORE_CONTRIBUTOR_LAYOUT - 1, path,
      path_len, &offers);
  if (rc != GDEFCORE_OK) {
    gdefcore_routes_destroy(own);
    free(slashed);
    return rc;
  }
  n = gdefcore_offers_count(offers);
  for (i = 0; i < n && chosen == NULL; i++) {
    const char * value = NULL;
    size_t value_len = 0;
    if (gdefcore_offers_at(offers, i, &value, &value_len, NULL, NULL) !=
            GDEFCORE_OK ||
        gdefcore_layout_check(catalog, value, value_len) != GDEFCORE_OK) {
      continue;
    }
    rc = gdefcore_text_dup(catalog, value, value_len, &chosen);
    if (rc != GDEFCORE_OK) {
      break;
    }
    chosen_len = value_len;
  }
  gdefcore_offers_free(offers);
  gdefcore_routes_destroy(own);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, chosen);
    free(slashed);
    return rc;
  }
  if (chosen == NULL) {
    free(slashed);
    return GDEFCORE_ERR_INVALID;
  }
  /* The alter hook refines the choice. It can name another layout and nothing
   * else: a failure is skipped by the host, the decision a subscriber reports
   * is not read, and a name that cannot be applied is ignored. */
  host = gdefcore_catalog_host(catalog);
  if (host != NULL) {
    GDEFCORE_Alter * alter = NULL;
    GDEFCORE_Layout_Hook args;
    char * ptype;
    size_t ptype_len = 0;
    ptype = page_type(catalog, request, &ptype_len);
    memset(&args, 0, sizeof args);
    args.size = sizeof args;
    args.path = path;
    args.path_len = path_len;
    args.entity_type = ptype == NULL ? "" : ptype;
    args.entity_type_len = ptype_len;
    if (gdefcore_alter_create(host, chosen, chosen_len, &alter) == GDEFCORE_OK) {
      if (gdefcore_hook_fire(host, request, catalog, GDEFCORE_HOOK_LAYOUT,
              sizeof GDEFCORE_HOOK_LAYOUT - 1, GDEFCORE_HOOK_ALTER, &args, alter,
              NULL) == GDEFCORE_OK) {
        const char * text = NULL;
        size_t text_len = 0;
        if (gdefcore_alter_text(alter, &text, &text_len) == GDEFCORE_OK &&
            text_len > 0 && !span_eq(text, text_len, chosen, chosen_len) &&
            gdefcore_layout_check(catalog, text, text_len) == GDEFCORE_OK) {
          char * refined = NULL;
          if (gdefcore_text_dup(catalog, text, text_len, &refined) ==
              GDEFCORE_OK) {
            gdefcore_text_free(catalog, chosen);
            chosen = refined;
            chosen_len = text_len;
          }
        }
      }
      gdefcore_alter_destroy(host, alter);
    }
    gdefcore_text_free(catalog, ptype);
  }
  free(slashed);
  *out_name = chosen;
  *out_len = chosen_len;
  return GDEFCORE_OK;
}
