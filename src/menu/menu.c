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
 * Menus, tabs and breadcrumbs, computed on every read from what is declared
 * (kernel links, module links, tab routes) and what the site stored (its own
 * entries and the overrides of generated ones). Nothing generated is stored.
 * Whether an entry is shown is the target route's own permission check, asked
 * through gdefcore_routes_permits(); there is no other predicate here.
 */

#include <ghoti.io/defiant-core/macros.h>

#include "menu_internal.h"

#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/form.h>
#include <ghoti.io/defiant-core/menu.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NONE ((size_t)-1)

static const char kLang[] = "en";
static const char kEntryType[] = GDEFCORE_MENU_ENTRY_TYPE;
static const char kOverrideType[] = GDEFCORE_MENU_OVERRIDE_TYPE;
static const char kChangeType[] = GDEFCORE_MENU_CHANGE_TYPE;
static const char kNotAllowed[] = "That edit is not allowed.";

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static int str_eq(const Str * a, const Str * b) {
  return span_eq(a->p, a->n, b->p, b->n);
}

/* ---- an arena: strings that live as long as one computation ----------- */

typedef struct Chunk {
  struct Chunk * next;
  size_t used;
  size_t cap;
  char data[1];
} Chunk;

typedef struct Arena {
  Chunk * head;
} Arena;

static void arena_free(Arena * a) {
  Chunk * c = a->head;
  while (c != NULL) {
    Chunk * next = c->next;
    free(c);
    c = next;
  }
  a->head = NULL;
}

/* A NUL-terminated copy of @p s. NULL on allocation failure. */
static char * arena_dup(Arena * a, const char * s, size_t n) {
  Chunk * c = a->head;
  char * out;
  if (c == NULL || c->cap - c->used < n + 1) {
    size_t cap = n + 1 > 8192 ? n + 1 : 8192;
    c = (Chunk *)malloc(sizeof *c + cap);
    if (c == NULL) {
      return NULL;
    }
    c->next = a->head;
    c->used = 0;
    c->cap = cap;
    a->head = c;
  }
  out = c->data + c->used;
  if (n > 0) {
    memcpy(out, s, n);
  }
  out[n] = '\0';
  c->used += n + 1;
  return out;
}

static int str_set(Arena * a, Str * to, const char * s, size_t n) {
  char * p = arena_dup(a, s == NULL ? "" : s, s == NULL ? 0 : n);
  if (p == NULL) {
    return 0;
  }
  to->p = p;
  to->n = s == NULL ? 0 : n;
  return 1;
}

/* ---- text rules -------------------------------------------------------- */

static int machine_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
         c == '_' || c == '-';
}

/* A machine name: a-z, 0-9, '.', '_' and '-', starting with a letter. */
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
  size_t pl = sizeof GDEFCORE_MENU_SITE_PREFIX - 1;
  return n > pl && memcmp(s, GDEFCORE_MENU_SITE_PREFIX, pl) == 0 &&
         ident_ok(s, n, GDEFCORE_MENU_ENTRY_NAME_MAX);
}

/* The name of anything a module or the kernel generates: `<owner>.<name>`. */
static int generated_name_ok(const char * s, size_t n) {
  return ident_ok(s, n, GDEFCORE_MENU_ENTRY_NAME_MAX) &&
         memchr(s, '.', n) != NULL && !site_name_ok(s, n);
}

/* Well-formed UTF-8 with no control character, no overlong form, no
 * surrogate and nothing above U+10FFFF. */
static int text_ok(const char * s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t more;
    uint32_t cp;
    uint32_t min;
    size_t k;
    if (c < 0x20 || c == 0x7f) {
      return 0;
    }
    if (c < 0x80) {
      i += 1;
      continue;
    }
    if (c >= 0xc2 && c <= 0xdf) {
      more = 1;
      cp = c & 0x1f;
      min = 0x80;
    } else if ((c & 0xf0) == 0xe0) {
      more = 2;
      cp = c & 0x0f;
      min = 0x800;
    } else if (c >= 0xf0 && c <= 0xf4) {
      more = 3;
      cp = c & 0x07;
      min = 0x10000;
    } else {
      return 0;
    }
    if (i + more >= n) {
      return 0;
    }
    for (k = 1; k <= more; k++) {
      unsigned char d = (unsigned char)s[i + k];
      if ((d & 0xc0) != 0x80) {
        return 0;
      }
      cp = (cp << 6) | (d & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      return 0;
    }
    i += more + 1;
  }
  return 1;
}

/* An integer as the port holds it: `-?[0-9]{1,9}`, no leading zero. */
static int int_parse(const char * s, size_t n, int * out) {
  size_t i = 0;
  long v = 0;
  int neg = 0;
  if (n > 0 && s[0] == '-') {
    neg = 1;
    i = 1;
  }
  if (i >= n || n - i > 9 || (s[i] == '0' && n - i > 1)) {
    return 0;
  }
  for (; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') {
      return 0;
    }
    v = v * 10 + (s[i] - '0');
  }
  *out = (int)(neg ? -v : v);
  return 1;
}

/* ---- what a computation holds ------------------------------------------ */

typedef struct Node {
  Str name;
  Str label;
  Str route;    /* "" for an entry that only groups others */
  Str parent;   /* an entry's name; for a tab, a route's (or a link's) */
  Str menu;     /* "" for a tab */
  Str href;
  int weight;
  int kind;
  int source;
  int hidden;
  int overridden;
  int is_default;
  size_t up;    /* index of the parent entry, or NONE */
  int ok;       /* -1 not asked yet; else whether the viewer may follow it */
} Node;

typedef struct Ov {
  Str name;
  Str label;
  Str parent;
  Str menu;
  int has_label;
  int has_weight;
  int weight;
  int hidden;   /* -1 unset */
  int has_parent;
  int has_menu;
} Ov;

typedef struct Ctx {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Routes * routes;
  GDEFCORE_Request * request;
  const GDEFCORE_Route_Match * match;
  Arena arena;
  Node * nodes;
  size_t n;
  size_t cap;
  Ov * ovs;
  size_t nov;
  size_t ovcap;
} Ctx;

static void ctx_free(Ctx * c) {
  free(c->nodes);
  free(c->ovs);
  arena_free(&c->arena);
}

static GDEFCORE_Result node_push(Ctx * c, const Node * node) {
  size_t i;
  for (i = 0; i < c->n; i++) {
    if (str_eq(&c->nodes[i].name, &node->name)) {
      return GDEFCORE_OK;   /* one name, one entry: the first stays */
    }
  }
  if (c->n >= GDEFCORE_MENU_ENTRIES_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (c->n == c->cap) {
    size_t cap = c->cap == 0 ? 32 : c->cap * 2;
    Node * grown = (Node *)realloc(c->nodes, cap * sizeof *grown);
    if (grown == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    c->nodes = grown;
    c->cap = cap;
  }
  c->nodes[c->n] = *node;
  c->nodes[c->n].up = NONE;
  c->nodes[c->n].ok = -1;
  c->n += 1;
  return GDEFCORE_OK;
}

/* One field of an entity, as published. @p present is 0 for none. */
static GDEFCORE_Result field_get(Ctx * c, const char * id, const char * field,
    Str * out, int * present) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc;
  out->p = "";
  out->n = 0;
  *present = 0;
  rc = gdefcore_entity_values(c->catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      strlen(id), kLang, sizeof kLang - 1, field, strlen(field), &texts, &lens,
      &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count > 0) {
    *present = str_set(&c->arena, out, texts[0], lens[0]);
    if (!*present) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  gdefcore_values_free(c->catalog, texts, lens, count);
  return rc;
}

/* The overrides the site stored. A bad value is no override of that field. */
static GDEFCORE_Result load_overrides(Ctx * c) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(c->catalog, kOverrideType,
      sizeof kOverrideType - 1, &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    Ov ov;
    Str v;
    int present = 0;
    size_t k;
    int dup = 0;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    memset(&ov, 0, sizeof ov);
    ov.hidden = -1;
    rc = field_get(c, ids[i], "name", &ov.name, &present);
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (!present || !ident_ok(ov.name.p, ov.name.n,
                          GDEFCORE_MENU_ENTRY_NAME_MAX)) {
      continue;
    }
    for (k = 0; k < c->nov; k++) {
      dup = dup || str_eq(&c->ovs[k].name, &ov.name);
    }
    if (dup) {
      continue;   /* one override per name: the first stays */
    }
    rc = field_get(c, ids[i], "label", &ov.label, &present);
    if (rc == GDEFCORE_OK && present && ov.label.n <= GDEFCORE_MENU_LABEL_MAX &&
        ov.label.n > 0 && text_ok(ov.label.p, ov.label.n)) {
      ov.has_label = 1;
    }
    if (rc == GDEFCORE_OK) {
      rc = field_get(c, ids[i], "weight", &v, &present);
      if (rc == GDEFCORE_OK && present && int_parse(v.p, v.n, &ov.weight)) {
        ov.has_weight = 1;
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = field_get(c, ids[i], "hidden", &v, &present);
      if (rc == GDEFCORE_OK && present && v.n == 1 && (v.p[0] == '0' || v.p[0] == '1')) {
        ov.hidden = v.p[0] - '0';
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = field_get(c, ids[i], "parent", &ov.parent, &present);
      if (rc == GDEFCORE_OK && present &&
          (span_eq(ov.parent.p, ov.parent.n, GDEFCORE_MENU_TOP,
               sizeof GDEFCORE_MENU_TOP - 1) ||
              ident_ok(ov.parent.p, ov.parent.n, GDEFCORE_MENU_ENTRY_NAME_MAX))) {
        ov.has_parent = 1;
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = field_get(c, ids[i], "menu", &ov.menu, &present);
      if (rc == GDEFCORE_OK && present &&
          ident_ok(ov.menu.p, ov.menu.n, GDEFCORE_MENU_NAME_MAX)) {
        ov.has_menu = 1;
      }
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (c->nov == c->ovcap) {
      size_t cap = c->ovcap == 0 ? 8 : c->ovcap * 2;
      Ov * grown = (Ov *)realloc(c->ovs, cap * sizeof *grown);
      if (grown == NULL) {
        rc = GDEFCORE_ERR_OOM;
        break;
      }
      c->ovs = grown;
      c->ovcap = cap;
    }
    c->ovs[c->nov++] = ov;
  }
  gdefcore_ids_free(c->catalog, ids, count);
  return rc;
}

/* The entries the site made. */
static GDEFCORE_Result load_site(Ctx * c) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(c->catalog, kEntryType,
      sizeof kEntryType - 1, &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    Node node;
    Str weight;
    Str hidden;
    int present = 0;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    memset(&node, 0, sizeof node);
    node.source = GDEFCORE_MENU_SOURCE_SITE;
    node.kind = GDEFCORE_ROUTE_PAGE;
    rc = field_get(c, ids[i], "name", &node.name, &present);
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (!present || !site_name_ok(node.name.p, node.name.n)) {
      continue;
    }
    rc = field_get(c, ids[i], "menu", &node.menu, &present);
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (!present || !ident_ok(node.menu.p, node.menu.n, GDEFCORE_MENU_NAME_MAX)) {
      continue;
    }
    rc = field_get(c, ids[i], "label", &node.label, &present);
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (!present || node.label.n > GDEFCORE_MENU_LABEL_MAX ||
        !text_ok(node.label.p, node.label.n)) {
      continue;
    }
    rc = field_get(c, ids[i], "route", &node.route, &present);
    if (rc == GDEFCORE_OK) {
      rc = field_get(c, ids[i], "parent", &node.parent, &present);
    }
    if (rc == GDEFCORE_OK) {
      rc = field_get(c, ids[i], "weight", &weight, &present);
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (present && !int_parse(weight.p, weight.n, &node.weight)) {
      node.weight = 0;
    }
    rc = field_get(c, ids[i], "hidden", &hidden, &present);
    if (rc != GDEFCORE_OK) {
      break;
    }
    node.hidden = present && hidden.n == 1 && hidden.p[0] == '1';
    rc = node_push(c, &node);
  }
  gdefcore_ids_free(c->catalog, ids, count);
  return rc;
}

/* The entries the kernel, the enabled modules and the tab routes declare. */
static GDEFCORE_Result load_generated(Ctx * c) {
  GDEFCORE_Host * host = gdefcore_catalog_host(c->catalog);
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  for (i = 0; rc == GDEFCORE_OK && i < gdefcore_routes_link_count(c->routes);
       i++) {
    GDEFCORE_Route_Link link;
    Node node;
    memset(&link, 0, sizeof link);
    link.size = sizeof link;
    if (gdefcore_routes_link_at(c->routes, i, &link) != GDEFCORE_OK) {
      continue;
    }
    memset(&node, 0, sizeof node);
    node.source = GDEFCORE_MENU_SOURCE_KERNEL;
    node.kind = link.kind;
    node.weight = link.weight;
    if (!str_set(&c->arena, &node.name, link.name, link.name_len) ||
        !str_set(&c->arena, &node.label, link.label, link.label_len) ||
        !str_set(&c->arena, &node.route, link.route, link.route_len) ||
        !str_set(&c->arena, &node.parent, link.parent, link.parent_len) ||
        !str_set(&c->arena, &node.menu, link.menu, link.menu_len)) {
      return GDEFCORE_ERR_OOM;
    }
    rc = node_push(c, &node);
  }
  if (rc == GDEFCORE_OK && host != NULL) {
    const GDEFCORE_Module_Declared_Link ** links = NULL;
    size_t nlinks = 0;
    size_t tenant_len = 0;
    const uint8_t * tenant = gdefcore_catalog_tenant(c->catalog, &tenant_len);
    rc = gdefcore_module_links(host, tenant, tenant_len, NULL, &links, &nlinks);
    for (i = 0; rc == GDEFCORE_OK && i < nlinks; i++) {
      const GDEFCORE_Module_Declared_Link * link = links[i];
      Node node;
      memset(&node, 0, sizeof node);
      node.source = GDEFCORE_MENU_SOURCE_MODULE;
      node.kind = link->kind;
      node.weight = link->weight;
      if (!str_set(&c->arena, &node.name, link->name, link->name_len) ||
          !str_set(&c->arena, &node.label, link->label, link->label_len) ||
          !str_set(&c->arena, &node.route, link->route, link->route_len) ||
          !str_set(&c->arena, &node.parent, link->parent, link->parent_len) ||
          !str_set(&c->arena, &node.menu, link->menu, link->menu_len)) {
        rc = GDEFCORE_ERR_OOM;
        break;
      }
      rc = node_push(c, &node);
    }
    gdefcore_module_declared_free(host, links);
  }
  if (rc == GDEFCORE_OK) {
    GDEFCORE_Route_Info * routes = NULL;
    size_t nroutes = 0;
    rc = gdefcore_routes_list(c->routes, &routes, &nroutes);
    for (i = 0; rc == GDEFCORE_OK && i < nroutes; i++) {
      Node node;
      if (routes[i].kind != GDEFCORE_ROUTE_TAB) {
        continue;
      }
      memset(&node, 0, sizeof node);
      node.source = GDEFCORE_MENU_SOURCE_TAB;
      node.kind = GDEFCORE_ROUTE_TAB;
      node.weight = routes[i].weight;
      node.is_default = routes[i].is_default;
      if (!str_set(&c->arena, &node.name, routes[i].machine,
              routes[i].machine_len) ||
          !str_set(&c->arena, &node.label,
              routes[i].title_len > 0 ? routes[i].title : routes[i].machine,
              routes[i].title_len > 0 ? routes[i].title_len
                                      : routes[i].machine_len) ||
          !str_set(&c->arena, &node.route, routes[i].machine,
              routes[i].machine_len) ||
          !str_set(&c->arena, &node.parent, routes[i].parent,
              routes[i].parent_len) ||
          !str_set(&c->arena, &node.menu, "", 0)) {
        rc = GDEFCORE_ERR_OOM;
        break;
      }
      rc = node_push(c, &node);
    }
    gdefcore_routes_free(c->routes, routes);
  }
  return rc;
}

/* An override applies to a generated entry of its name, and to none else. */
static GDEFCORE_Result apply_overrides(Ctx * c) {
  size_t k;
  size_t i;
  for (k = 0; k < c->nov; k++) {
    const Ov * ov = &c->ovs[k];
    for (i = 0; i < c->n; i++) {
      Node * node = &c->nodes[i];
      if (node->source == GDEFCORE_MENU_SOURCE_SITE ||
          !str_eq(&node->name, &ov->name)) {
        continue;
      }
      if (ov->has_label) {
        node->label = ov->label;
        node->overridden = 1;
      }
      if (ov->has_weight) {
        node->weight = ov->weight;
        node->overridden = 1;
      }
      if (ov->hidden >= 0) {
        node->hidden = ov->hidden;
        node->overridden = 1;
      }
      if (ov->has_parent) {
        if (span_eq(ov->parent.p, ov->parent.n, GDEFCORE_MENU_TOP,
                sizeof GDEFCORE_MENU_TOP - 1)) {
          node->parent.p = "";
          node->parent.n = 0;
        } else {
          node->parent = ov->parent;
        }
        node->overridden = 1;
      }
      if (ov->has_menu && node->source != GDEFCORE_MENU_SOURCE_TAB) {
        node->menu = ov->menu;
        node->overridden = 1;
      }
    }
  }
  return GDEFCORE_OK;
}

/* Where each entry sits: the entry its parent names, in its own menu. A
 * missing parent, a parent in another menu and a loop all leave an entry at the
 * top of its menu. */
static void resolve_up(Ctx * c) {
  size_t i;
  size_t j;
  for (i = 0; i < c->n; i++) {
    Node * node = &c->nodes[i];
    node->up = NONE;
    if (node->source == GDEFCORE_MENU_SOURCE_TAB || node->parent.n == 0) {
      continue;
    }
    for (j = 0; j < c->n; j++) {
      const Node * p = &c->nodes[j];
      if (j != i && p->source != GDEFCORE_MENU_SOURCE_TAB &&
          str_eq(&p->name, &node->parent) && str_eq(&p->menu, &node->menu)) {
        node->up = j;
        break;
      }
    }
  }
  for (i = 0; i < c->n; i++) {
    size_t hops = 0;
    size_t at = c->nodes[i].up;
    while (at != NONE && hops <= c->n) {
      at = c->nodes[at].up;
      hops += 1;
    }
    if (at != NONE) {
      c->nodes[i].up = NONE;
    }
  }
}

static GDEFCORE_Result ctx_build(Ctx * c) {
  GDEFCORE_Result rc = load_overrides(c);
  if (rc == GDEFCORE_OK) {
    rc = load_generated(c);
  }
  if (rc == GDEFCORE_OK) {
    rc = load_site(c);
  }
  if (rc == GDEFCORE_OK) {
    rc = apply_overrides(c);
  }
  if (rc == GDEFCORE_OK) {
    resolve_up(c);
  }
  return rc;
}

/* ---- the one question: may this viewer follow the entry's route? ------- */

/* The path of an entry with its route's pattern filled from the page, or none
 * when it has no route or the page lacks a value the pattern names. */
static int node_href(Ctx * c, size_t i) {
  Node * node = &c->nodes[i];
  char * href = NULL;
  size_t href_len = 0;
  if (node->href.n > 0) {
    return 1;
  }
  if (node->route.n == 0 ||
      gdefcore_routes_href(c->routes, node->route.p, node->route.n, c->match,
          &href, &href_len) != GDEFCORE_OK) {
    return 0;
  }
  if (!str_set(&c->arena, &node->href, href, href_len)) {
    node->href.n = 0;
  }
  gdefcore_routes_free(c->routes, href);
  return node->href.n > 0;
}

/*
 * An entry the viewer may follow: not hidden, and (for one with a route) its
 * route's own check passes for the values of the page, and the route has a
 * path with those values put in. The check is the route table's:
 * gdefcore_routes_permits() asks what dispatch would ask. An entry that only
 * groups others has no route and is decided by what is under it.
 */
static int node_ok(Ctx * c, size_t i) {
  Node * node = &c->nodes[i];
  int allowed = 0;
  if (node->ok >= 0) {
    return node->ok;
  }
  node->ok = 0;
  if (node->hidden) {
    return 0;
  }
  if (node->route.n == 0) {
    node->ok = 1;
    return 1;
  }
  if (gdefcore_routes_permits(c->routes, c->request, node->route.p,
          node->route.n, c->match, &allowed) != GDEFCORE_OK ||
      !allowed) {
    return 0;
  }
  node->ok = node_href(c, i);
  return node->ok;
}

static int in_match(const Ctx * c, const Str * route) {
  size_t i;
  if (route->n == 0) {
    return 0;
  }
  for (i = 0; i < gdefcore_route_match_route_count(c->match); i++) {
    const char * m = NULL;
    size_t n = 0;
    if (gdefcore_route_match_route(c->match, i, &m, &n) == GDEFCORE_OK &&
        span_eq(m, n, route->p, route->n)) {
      return 1;
    }
  }
  return 0;
}

/* ---- the result --------------------------------------------------------- */

struct GDEFCORE_Menu {
  Arena arena;
  GDEFCORE_Menu_Item * items;
  size_t n;
  size_t cap;
};

void gdefcore_menu_free(GDEFCORE_Menu * menu) {
  if (menu == NULL) {
    return;
  }
  free(menu->items);
  arena_free(&menu->arena);
  free(menu);
}

size_t gdefcore_menu_count(const GDEFCORE_Menu * menu) {
  return menu == NULL ? 0 : menu->n;
}

GDEFCORE_Result gdefcore_menu_item(const GDEFCORE_Menu * menu, size_t index,
    GDEFCORE_Menu_Item * out) {
  if (menu == NULL || out == NULL || out->size != sizeof *out ||
      index >= menu->n) {
    return GDEFCORE_ERR_INVALID;
  }
  *out = menu->items[index];
  return GDEFCORE_OK;
}

static GDEFCORE_Menu * menu_new(void) {
  return (GDEFCORE_Menu *)calloc(1, sizeof(GDEFCORE_Menu));
}

static const char * menu_str(GDEFCORE_Menu * m, const Str * s, size_t * len) {
  char * p = arena_dup(&m->arena, s->p, s->n);
  *len = s->n;
  return p;
}

/* Append @p node to @p m. */
static GDEFCORE_Result menu_push(GDEFCORE_Menu * m, const Node * node, int depth,
    size_t up, int current, int visible) {
  GDEFCORE_Menu_Item * it;
  if (m->n == m->cap) {
    size_t cap = m->cap == 0 ? 16 : m->cap * 2;
    GDEFCORE_Menu_Item * grown =
        (GDEFCORE_Menu_Item *)realloc(m->items, cap * sizeof *grown);
    if (grown == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    m->items = grown;
    m->cap = cap;
  }
  it = &m->items[m->n];
  memset(it, 0, sizeof *it);
  it->size = sizeof *it;
  it->name = menu_str(m, &node->name, &it->name_len);
  it->label = menu_str(m, &node->label, &it->label_len);
  it->route = menu_str(m, &node->route, &it->route_len);
  it->href = menu_str(m, &node->href, &it->href_len);
  it->menu = menu_str(m, &node->menu, &it->menu_len);
  it->parent = menu_str(m, &node->parent, &it->parent_len);
  if (it->name == NULL || it->label == NULL || it->route == NULL ||
      it->href == NULL || it->menu == NULL || it->parent == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  it->weight = node->weight;
  it->kind = node->kind;
  it->source = node->source;
  it->depth = depth;
  it->up = up;
  it->current = current;
  it->hidden = node->hidden;
  it->overridden = node->overridden;
  it->visible = visible;
  m->n += 1;
  return GDEFCORE_OK;
}

/* Mark the ancestors of every current item. */
static void mark_trail(GDEFCORE_Menu * m) {
  size_t i;
  for (i = 0; i < m->n; i++) {
    if (m->items[i].current) {
      size_t at = m->items[i].up;
      size_t hops = 0;
      while (at != NONE && hops <= m->n) {
        m->items[at].trail = 1;
        at = m->items[at].up;
        hops += 1;
      }
    }
  }
}

/* ---- ordering ------------------------------------------------------------ */

static int node_before(const Ctx * c, size_t a, size_t b) {
  const Node * x = &c->nodes[a];
  const Node * y = &c->nodes[b];
  size_t n;
  int d;
  if (x->weight != y->weight) {
    return x->weight < y->weight;
  }
  n = x->name.n < y->name.n ? x->name.n : y->name.n;
  d = n == 0 ? 0 : memcmp(x->name.p, y->name.p, n);
  if (d != 0) {
    return d < 0;
  }
  return x->name.n < y->name.n;
}

/* The nodes in order (weight, then machine name). */
static size_t * order_all(const Ctx * c) {
  size_t * ord = (size_t *)malloc((c->n == 0 ? 1 : c->n) * sizeof *ord);
  size_t i;
  if (ord == NULL) {
    return NULL;
  }
  for (i = 0; i < c->n; i++) {
    size_t j = i;
    while (j > 0 && node_before(c, i, ord[j - 1])) {
      ord[j] = ord[j - 1];
      j -= 1;
    }
    ord[j] = i;
  }
  return ord;
}

/* For each node the first of its children in order, and the next sibling. */
static GDEFCORE_Result child_lists(const Ctx * c, const size_t * ord,
    size_t ** head, size_t ** next) {
  size_t k;
  *head = (size_t *)malloc((c->n == 0 ? 1 : c->n) * sizeof **head);
  *next = (size_t *)malloc((c->n == 0 ? 1 : c->n) * sizeof **next);
  if (*head == NULL || *next == NULL) {
    free(*head);
    free(*next);
    return GDEFCORE_ERR_OOM;
  }
  for (k = 0; k < c->n; k++) {
    (*head)[k] = NONE;
    (*next)[k] = NONE;
  }
  for (k = c->n; k-- > 0;) {
    size_t i = ord[k];
    size_t up = c->nodes[i].up;
    if (up != NONE) {
      (*next)[i] = (*head)[up];
      (*head)[up] = i;
    }
  }
  return GDEFCORE_OK;
}

/* ---- a tree -------------------------------------------------------------- */

typedef struct Walk {
  Ctx * c;
  GDEFCORE_Menu * out;
  const size_t * head;
  const size_t * next;
  int all;   /* the editor's list: every entry, with whether it is shown */
} Walk;

/*
 * Emit entry @p i under an ancestor chain that is @p parent_ok, and what is
 * below it. Returns whether the entry (or, for one that groups, something
 * under it) is shown. In the viewer's tree what is not shown is not emitted
 * at all, and so is not told of; in the editor's list it is, with
 * visible = 0.
 */
static GDEFCORE_Result walk(Walk * w, size_t i, int depth, size_t up,
    int parent_ok, int * shown) {
  Ctx * c = w->c;
  Node * node = &c->nodes[i];
  int group = node->route.n == 0;
  int own = !node->hidden && (group || node_ok(c, i));
  int chain = parent_ok && own;
  size_t at = w->out->n;
  size_t k;
  int any = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  *shown = 0;
  if (depth >= GDEFCORE_MENU_DEPTH_MAX || (!w->all && !chain)) {
    return GDEFCORE_OK;
  }
  if (w->all) {
    (void)node_href(c, i);   /* the editor is told where an entry goes */
  }
  rc = menu_push(w->out, node, depth, up, in_match(c, &node->route), 0);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (k = w->head[i]; rc == GDEFCORE_OK && k != NONE; k = w->next[k]) {
    int child = 0;
    rc = walk(w, k, depth + 1, at, chain, &child);
    any = any || child;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *shown = group ? (chain && any) : chain;
  if (!w->all && !*shown) {
    w->out->n = at;   /* a group with nothing under it is not there */
    return GDEFCORE_OK;
  }
  w->out->items[at].visible = *shown;
  return GDEFCORE_OK;
}

static GDEFCORE_Result tree_of(Ctx * c, const char * menu, size_t menu_len,
    int all, GDEFCORE_Menu * out) {
  size_t * ord = order_all(c);
  size_t * head = NULL;
  size_t * next = NULL;
  size_t k;
  Walk w;
  GDEFCORE_Result rc;
  if (ord == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  rc = child_lists(c, ord, &head, &next);
  if (rc != GDEFCORE_OK) {
    free(ord);
    return rc;
  }
  w.c = c;
  w.out = out;
  w.head = head;
  w.next = next;
  w.all = all;
  for (k = 0; rc == GDEFCORE_OK && k < c->n; k++) {
    size_t i = ord[k];
    int shown = 0;
    if (c->nodes[i].source == GDEFCORE_MENU_SOURCE_TAB || c->nodes[i].up != NONE ||
        !span_eq(c->nodes[i].menu.p, c->nodes[i].menu.n, menu, menu_len)) {
      continue;
    }
    rc = walk(&w, i, 0, NONE, 1, &shown);
  }
  free(head);
  free(next);
  free(ord);
  return rc;
}

/* ---- the entry points ----------------------------------------------------- */

static GDEFCORE_Result ctx_open(Ctx * c, GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match) {
  memset(c, 0, sizeof *c);
  c->catalog = catalog;
  c->routes = routes;
  c->request = request;
  c->match = match;
  return ctx_build(c);
}

GDEFCORE_Result gdefcore_menu_tree(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, const char * menu, size_t menu_len,
    GDEFCORE_Menu ** out) {
  Ctx c;
  GDEFCORE_Menu * made;
  GDEFCORE_Result rc;
  if (out != NULL) {
    *out = NULL;
  }
  if (catalog == NULL || routes == NULL || request == NULL || menu == NULL ||
      menu_len == 0 || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ctx_open(&c, catalog, routes, request, match);
  made = rc == GDEFCORE_OK ? menu_new() : NULL;
  if (rc == GDEFCORE_OK && made == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  if (rc == GDEFCORE_OK) {
    rc = tree_of(&c, menu, menu_len, 0, made);
  }
  if (rc == GDEFCORE_OK) {
    mark_trail(made);
    *out = made;
  } else {
    gdefcore_menu_free(made);
  }
  ctx_free(&c);
  return rc;
}

/* The route a tab shows on: the route its parent names, or the route of the
 * entry it names. A tab moved to a place that is neither is shown nowhere. */
static int tab_page(Ctx * c, const Node * tab, Str * page) {
  GDEFCORE_Route_Info info;
  size_t i;
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  if (tab->parent.n == 0) {
    return 0;
  }
  if (gdefcore_routes_info(c->routes, tab->parent.p, tab->parent.n, &info) ==
      GDEFCORE_OK) {
    *page = tab->parent;
    return 1;
  }
  for (i = 0; i < c->n; i++) {
    const Node * p = &c->nodes[i];
    if (p->source != GDEFCORE_MENU_SOURCE_TAB && p->route.n > 0 &&
        str_eq(&p->name, &tab->parent)) {
      *page = p->route;
      return 1;
    }
  }
  return 0;
}

/* The page a route belongs to: itself, or for a tab the page it is a tab of. */
static Str page_of(Ctx * c, const char * machine, size_t machine_len) {
  Str page;
  size_t hops = 0;
  page.p = machine;
  page.n = machine_len;
  while (hops < GDEFCORE_MENU_DEPTH_MAX) {
    GDEFCORE_Route_Info info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefcore_routes_info(c->routes, page.p, page.n, &info) != GDEFCORE_OK ||
        info.kind != GDEFCORE_ROUTE_TAB || info.parent_len == 0) {
      break;
    }
    page.p = info.parent;
    page.n = info.parent_len;
    hops += 1;
  }
  return page;
}

static GDEFCORE_Result tabs_of(Ctx * c, int all, GDEFCORE_Menu * out) {
  Str roots[GDEFCORE_MENU_DEPTH_MAX];
  size_t nroots = 0;
  size_t * ord;
  size_t k;
  size_t m;
  GDEFCORE_Result rc = GDEFCORE_OK;
  for (m = 0; m < gdefcore_route_match_route_count(c->match); m++) {
    const char * name = NULL;
    size_t name_len = 0;
    Str page;
    size_t r;
    int seen = 0;
    if (gdefcore_route_match_route(c->match, m, &name, &name_len) !=
        GDEFCORE_OK) {
      continue;
    }
    page = page_of(c, name, name_len);
    for (r = 0; r < nroots; r++) {
      seen = seen || str_eq(&roots[r], &page);
    }
    if (!seen && nroots < GDEFCORE_MENU_DEPTH_MAX) {
      roots[nroots++] = page;
    }
  }
  ord = order_all(c);
  if (ord == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (k = 0; rc == GDEFCORE_OK && k < c->n; k++) {
    size_t i = ord[k];
    Node * node = &c->nodes[i];
    Str page;
    size_t r;
    int on_page = 0;
    int shown;
    if (node->source != GDEFCORE_MENU_SOURCE_TAB || !tab_page(c, node, &page)) {
      continue;
    }
    for (r = 0; r < nroots; r++) {
      on_page = on_page || str_eq(&roots[r], &page);
    }
    if (!on_page && !all) {
      continue;
    }
    shown = on_page && node_ok(c, i);
    if (!shown && !all) {
      continue;
    }
    if (all) {
      (void)node_href(c, i);
    }
    rc = menu_push(out, node, 0, NONE, in_match(c, &node->route), shown);
  }
  free(ord);
  return rc;
}

GDEFCORE_Result gdefcore_menu_tabs(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, GDEFCORE_Menu ** out) {
  Ctx c;
  GDEFCORE_Menu * made;
  GDEFCORE_Result rc;
  if (out != NULL) {
    *out = NULL;
  }
  if (catalog == NULL || routes == NULL || request == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ctx_open(&c, catalog, routes, request, match);
  made = rc == GDEFCORE_OK ? menu_new() : NULL;
  if (rc == GDEFCORE_OK && made == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  if (rc == GDEFCORE_OK) {
    rc = tabs_of(&c, 0, made);
  }
  if (rc == GDEFCORE_OK) {
    *out = made;
  } else {
    gdefcore_menu_free(made);
  }
  ctx_free(&c);
  return rc;
}

/* The entry for route @p route among the links, the first by menu name, then
 * weight, then machine name; @p menu narrows it when it is not empty. */
static size_t entry_for_route(Ctx * c, const Str * route, const Str * menu) {
  size_t best = NONE;
  size_t i;
  for (i = 0; i < c->n; i++) {
    const Node * x = &c->nodes[i];
    if (x->source == GDEFCORE_MENU_SOURCE_TAB || x->route.n == 0 ||
        !str_eq(&x->route, route) ||
        (menu->n > 0 && !str_eq(&x->menu, menu))) {
      continue;
    }
    if (best == NONE) {
      best = i;
    } else {
      const Node * y = &c->nodes[best];
      size_t n = x->menu.n < y->menu.n ? x->menu.n : y->menu.n;
      int d = n == 0 ? 0 : memcmp(x->menu.p, y->menu.p, n);
      if (d < 0 || (d == 0 && x->menu.n < y->menu.n) ||
          (d == 0 && x->menu.n == y->menu.n && node_before(c, i, best))) {
        best = i;
      }
    }
  }
  return best;
}

/* A node for a route that has a title and no entry: a crumb of its own. */
static size_t route_crumb(Ctx * c, const char * machine, size_t machine_len) {
  GDEFCORE_Route_Info info;
  Node node;
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  if (gdefcore_routes_info(c->routes, machine, machine_len, &info) !=
          GDEFCORE_OK ||
      info.title_len == 0 || c->n >= GDEFCORE_MENU_ENTRIES_MAX) {
    return NONE;
  }
  if (c->n == c->cap) {
    size_t cap = c->cap == 0 ? 32 : c->cap * 2;
    Node * grown = (Node *)realloc(c->nodes, cap * sizeof *grown);
    if (grown == NULL) {
      return NONE;
    }
    c->nodes = grown;
    c->cap = cap;
  }
  memset(&node, 0, sizeof node);
  node.source = GDEFCORE_MENU_SOURCE_ROUTE;
  node.kind = info.kind;
  node.weight = info.weight;
  node.up = NONE;
  node.ok = -1;
  if (!str_set(&c->arena, &node.name, machine, machine_len) ||
      !str_set(&c->arena, &node.label, info.title, info.title_len) ||
      !str_set(&c->arena, &node.route, machine, machine_len) ||
      !str_set(&c->arena, &node.parent, "", 0) ||
      !str_set(&c->arena, &node.menu, "", 0)) {
    return NONE;
  }
  c->nodes[c->n] = node;
  return c->n++;
}

GDEFCORE_Result gdefcore_menu_breadcrumbs(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, const char * menu, size_t menu_len,
    GDEFCORE_Menu ** out) {
  Ctx c;
  GDEFCORE_Menu * made = NULL;
  size_t chain[GDEFCORE_MENU_DEPTH_MAX * 2];
  size_t nchain = 0;
  size_t anchor = NONE;
  Str filter;
  size_t m;
  size_t i;
  GDEFCORE_Result rc;
  if (out != NULL) {
    *out = NULL;
  }
  if (catalog == NULL || routes == NULL || request == NULL || out == NULL ||
      (menu == NULL && menu_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  filter.p = menu == NULL ? "" : menu;
  filter.n = menu == NULL ? 0 : menu_len;
  rc = ctx_open(&c, catalog, routes, request, match);
  if (rc != GDEFCORE_OK) {
    ctx_free(&c);
    return rc;
  }
  /* The page's entry: that of the first route the match holds that has one,
   * else the first that has a title. */
  for (m = 0; anchor == NONE && m < gdefcore_route_match_route_count(match);
       m++) {
    const char * name = NULL;
    size_t name_len = 0;
    Str route;
    if (gdefcore_route_match_route(match, m, &name, &name_len) != GDEFCORE_OK) {
      continue;
    }
    route.p = name;
    route.n = name_len;
    anchor = entry_for_route(&c, &route, &filter);
    if (anchor == NONE) {
      for (i = 0; i < c.n; i++) {
        if (c.nodes[i].source == GDEFCORE_MENU_SOURCE_TAB &&
            str_eq(&c.nodes[i].route, &route)) {
          anchor = i;
          break;
        }
      }
    }
  }
  for (m = 0; anchor == NONE && m < gdefcore_route_match_route_count(match);
       m++) {
    const char * name = NULL;
    size_t name_len = 0;
    if (gdefcore_route_match_route(match, m, &name, &name_len) == GDEFCORE_OK) {
      anchor = route_crumb(&c, name, name_len);
    }
  }
  /* Up the tree. A tab goes up to the page it shows on, and a page to the
   * entry above its entry. */
  {
    size_t at = anchor;
    while (at != NONE && nchain < sizeof chain / sizeof chain[0]) {
      const Node * node = &c.nodes[at];
      size_t up = NONE;
      chain[nchain++] = at;
      if (node->source == GDEFCORE_MENU_SOURCE_TAB ||
          node->source == GDEFCORE_MENU_SOURCE_ROUTE) {
        Str page;
        int has = 0;
        if (node->source == GDEFCORE_MENU_SOURCE_TAB) {
          has = tab_page(&c, node, &page);
        } else {
          GDEFCORE_Route_Info info;
          memset(&info, 0, sizeof info);
          info.size = sizeof info;
          if (gdefcore_routes_info(c.routes, node->route.p, node->route.n,
                  &info) == GDEFCORE_OK &&
              info.kind == GDEFCORE_ROUTE_TAB && info.parent_len > 0) {
            page.p = info.parent;
            page.n = info.parent_len;
            has = 1;
          }
        }
        if (has) {
          up = entry_for_route(&c, &page, &filter);
          if (up == NONE) {
            up = route_crumb(&c, page.p, page.n);
          }
        }
      } else {
        up = node->up;
      }
      at = up;
    }
  }
  made = menu_new();
  if (made == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  /* From the top down, leaving out what is hidden, groups, and what the
   * viewer may not follow. The page itself is the last, if it is there. */
  for (i = nchain; rc == GDEFCORE_OK && i-- > 0;) {
    const Node * node = &c.nodes[chain[i]];
    if (node->route.n == 0 || !node_ok(&c, chain[i])) {
      continue;
    }
    rc = menu_push(made, node, 0, NONE, i == 0, 1);
  }
  if (rc == GDEFCORE_OK) {
    *out = made;
  } else {
    gdefcore_menu_free(made);
  }
  ctx_free(&c);
  return rc;
}

int gdefcore_menu_may_edit(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request) {
  if (catalog == NULL || request == NULL) {
    return 0;
  }
  return gdefcore_access_permits(catalog, request, GDEFCORE_MENU_EDIT,
      sizeof GDEFCORE_MENU_EDIT - 1) != 0;
}

/* Whether menu name @p a sorts before @p b. */
static int name_before(const Str * a, const Str * b) {
  size_t n = a->n < b->n ? a->n : b->n;
  int d = n == 0 ? 0 : memcmp(a->p, b->p, n);
  return d != 0 ? d < 0 : a->n < b->n;
}

/* Every menu as a tree and then the tabs, hidden or not, from an opened
 * computation. */
static GDEFCORE_Result entries_of(Ctx * c, GDEFCORE_Menu ** out) {
  GDEFCORE_Menu * made;
  Str * names = NULL;
  size_t nnames = 0;
  size_t i;
  size_t j;
  GDEFCORE_Result rc = GDEFCORE_OK;
  *out = NULL;
  made = menu_new();
  names = (Str *)malloc((c->n == 0 ? 1 : c->n) * sizeof *names);
  if (made == NULL || names == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  /* The menus in the order of their names, each as a tree, then the tabs. */
  for (i = 0; rc == GDEFCORE_OK && i < c->n; i++) {
    const Str * menu = &c->nodes[i].menu;
    int seen = 0;
    if (c->nodes[i].source == GDEFCORE_MENU_SOURCE_TAB || menu->n == 0) {
      continue;
    }
    for (j = 0; j < nnames; j++) {
      seen = seen || str_eq(&names[j], menu);
    }
    if (!seen) {
      j = nnames++;
      while (j > 0 && name_before(menu, &names[j - 1])) {
        names[j] = names[j - 1];
        j -= 1;
      }
      names[j] = *menu;
    }
  }
  for (i = 0; rc == GDEFCORE_OK && i < nnames; i++) {
    rc = tree_of(c, names[i].p, names[i].n, 1, made);
  }
  if (rc == GDEFCORE_OK) {
    rc = tabs_of(c, 1, made);
  }
  free(names);
  if (rc == GDEFCORE_OK) {
    mark_trail(made);
    *out = made;
  } else {
    gdefcore_menu_free(made);
  }
  return rc;
}

GDEFCORE_Result gdefcore_menu_entries(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, GDEFCORE_Menu ** out) {
  Ctx c;
  GDEFCORE_Result rc;
  if (out != NULL) {
    *out = NULL;
  }
  if (catalog == NULL || routes == NULL || request == NULL || out == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!gdefcore_menu_may_edit(catalog, request)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ctx_open(&c, catalog, routes, request, match);
  if (rc == GDEFCORE_OK) {
    rc = entries_of(&c, out);
  }
  ctx_free(&c);
  return rc;
}

/* ---- the types and the permission ------------------------------------------ */

/* An optional field is declared many, because that is how the port lets a
 * save take a value away: a many field with no values is cleared, and a single
 * field still needs one. At most one value is ever written to it. */
static void field_set(GDEFCORE_Field * field, const char * name, int required) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = required;
  field->many = !required;
}

static GDEFCORE_Result define_type(GDEFCORE_Catalog * catalog, const char * name,
    const GDEFCORE_Field * fields, size_t count) {
  int kind = 0;
  if (gdefcore_type_kind(catalog, name, strlen(name), &kind) == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  return gdefcore_type_define(catalog, name, strlen(name), GDEFCORE_TYPE_CONFIG,
      fields, count);
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
  perm.action = GDEFCORE_MENU_EDIT;
  perm.action_len = sizeof GDEFCORE_MENU_EDIT - 1;
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = type;
  perm.type_name_len = strlen(type);
  return gdefcore_access_declare(catalog, &perm);
}

GDEFCORE_Result gdefcore_menu_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field entry[7];
  GDEFCORE_Field over[6];
  GDEFCORE_Field change[2];
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  field_set(&entry[0], "name", 1);
  field_set(&entry[1], "menu", 1);
  field_set(&entry[2], "label", 1);
  field_set(&entry[3], "route", 0);
  field_set(&entry[4], "parent", 0);
  field_set(&entry[5], "weight", 0);
  field_set(&entry[6], "hidden", 0);
  field_set(&change[0], "name", 1);
  field_set(&change[1], "entities", 0);
  field_set(&over[0], "name", 1);
  field_set(&over[1], "label", 0);
  field_set(&over[2], "weight", 0);
  field_set(&over[3], "hidden", 0);
  field_set(&over[4], "parent", 0);
  field_set(&over[5], "menu", 0);
  rc = define_type(catalog, kEntryType, entry, 7);
  if (rc == GDEFCORE_OK) {
    rc = define_type(catalog, kOverrideType, over, 6);
  }
  if (rc == GDEFCORE_OK) {
    rc = define_type(catalog, kChangeType, change, 2);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_edit(catalog, GDEFCORE_MENU_EDIT_ENTRY_LABEL, kEntryType);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_edit(catalog, GDEFCORE_MENU_EDIT_OVERRIDE_LABEL, kOverrideType);
  }
  return rc;
}

/* ---- staging ----------------------------------------------------------------- */

/* The id of the entity of @p type whose name is @p name: ::GDEFCORE_OK, or
 * ::GDEFCORE_ERR_INVALID for none. */
static GDEFCORE_Result find_named(GDEFCORE_Catalog * catalog, const char * type,
    const char * name, size_t name_len, char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  int found = 0;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, type, strlen(type), &ids,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count && !found; i++) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
        GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "name", 4, &texts,
        &lens, &n);
    if (rc == GDEFCORE_OK) {
      if (n > 0 && span_eq(texts[0], lens[0], name, name_len)) {
        memcpy(id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
        found = 1;
      }
      gdefcore_values_free(catalog, texts, lens, n);
    } else if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return found ? GDEFCORE_OK : GDEFCORE_ERR_INVALID;
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

/* The entity of @p type called @p name, made if there is none. */
static GDEFCORE_Result entity_for(GDEFCORE_Changeset * changeset,
    const char * type, const char * name, size_t name_len,
    char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(changeset);
  int kind = 0;
  GDEFCORE_Result rc;
  if (gdefcore_type_kind(catalog, type, strlen(type), &kind) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;   /* gdefcore_menu_declare() has not run */
  }
  rc = find_named(catalog, type, name, name_len, id);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = gdefcore_entity_create(catalog, type, strlen(type), id, NULL);
  }
  return rc;
}

/* A site entry's stored hidden flag, or 0 when it has none or is not stored. */
static int stored_hidden(GDEFCORE_Catalog * catalog, const char * id) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  int hidden = 0;
  if (gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_CURRENT, id,
          GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "hidden", 6, &texts,
          &lens, &n) == GDEFCORE_OK) {
    hidden = n > 0 && lens[0] == 1 && texts[0][0] == '1';
    gdefcore_values_free(catalog, texts, lens, n);
  }
  return hidden;
}

/* Stage a site entry with every field, the hidden flag included (-1: as it is
 * stored). */
static GDEFCORE_Result stage_entry_full(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const char * menu, size_t menu_len,
    const char * label, size_t label_len, const char * route, size_t route_len,
    const char * parent, size_t parent_len, int weight, int hide) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[7];
  const char * slots[7];
  size_t lens[7];
  char number[16];
  GDEFCORE_Result rc;
  if (changeset == NULL || !site_name_ok(name, name_len) ||
      !ident_ok(menu, menu_len, GDEFCORE_MENU_NAME_MAX) || label == NULL ||
      label_len == 0 || label_len > GDEFCORE_MENU_LABEL_MAX ||
      !text_ok(label, label_len) || (route_len > 0 && route == NULL) ||
      route_len > GDEFCORE_MENU_ENTRY_NAME_MAX ||
      (parent_len > 0 && !ident_ok(parent, parent_len,
                             GDEFCORE_MENU_ENTRY_NAME_MAX)) ||
      weight > 999999999 || weight < -999999999) {
    return GDEFCORE_ERR_INVALID;
  }
  if (route_len > 0 && !ident_ok(route, route_len, GDEFCORE_MENU_ENTRY_NAME_MAX)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = entity_for(changeset, kEntryType, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  snprintf(number, sizeof number, "%d", weight);
  value_set(&values[0], "name", &slots[0], &lens[0], name, name_len, 1);
  value_set(&values[1], "menu", &slots[1], &lens[1], menu, menu_len, 1);
  value_set(&values[2], "label", &slots[2], &lens[2], label, label_len, 1);
  value_set(&values[3], "route", &slots[3], &lens[3], route, route_len,
      route_len > 0);
  value_set(&values[4], "parent", &slots[4], &lens[4], parent, parent_len,
      parent_len > 0);
  value_set(&values[5], "weight", &slots[5], &lens[5], number, strlen(number), 1);
  if (hide < 0) {
    hide = stored_hidden(gdefcore_changeset_catalog(changeset), id);
  }
  value_set(&values[6], "hidden", &slots[6], &lens[6], "1", 1, hide > 0);
  return gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      sizeof kLang - 1, values, 7);
}

GDEFCORE_Result gdefcore_menu_stage_entry(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const char * menu, size_t menu_len,
    const char * label, size_t label_len, const char * route, size_t route_len,
    const char * parent, size_t parent_len, int weight) {
  return stage_entry_full(changeset, name, name_len, menu, menu_len, label,
      label_len, route, route_len, parent, parent_len, weight, -1);
}

GDEFCORE_Result gdefcore_menu_stage_override(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const GDEFCORE_Menu_Override * override) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[6];
  const char * slots[6];
  size_t lens[6];
  char number[16];
  const char * hidden = "";
  GDEFCORE_Result rc;
  if (changeset == NULL || override == NULL || override->size != sizeof *override ||
      !generated_name_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if ((override->label != NULL &&
          (override->label_len == 0 ||
              override->label_len > GDEFCORE_MENU_LABEL_MAX ||
              !text_ok(override->label, override->label_len))) ||
      (override->label == NULL && override->label_len != 0) ||
      (override->has_weight &&
          (override->weight > 999999999 || override->weight < -999999999)) ||
      override->hidden < -1 || override->hidden > 1 ||
      (override->parent != NULL &&
          !span_eq(override->parent, override->parent_len, GDEFCORE_MENU_TOP,
              sizeof GDEFCORE_MENU_TOP - 1) &&
          !ident_ok(override->parent, override->parent_len,
              GDEFCORE_MENU_ENTRY_NAME_MAX)) ||
      (override->parent == NULL && override->parent_len != 0) ||
      (override->menu != NULL &&
          !ident_ok(override->menu, override->menu_len,
              GDEFCORE_MENU_NAME_MAX)) ||
      (override->menu == NULL && override->menu_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = entity_for(changeset, kOverrideType, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  number[0] = '\0';
  if (override->has_weight) {
    snprintf(number, sizeof number, "%d", override->weight);
  }
  hidden = override->hidden == 1 ? "1" : "0";
  value_set(&values[0], "name", &slots[0], &lens[0], name, name_len, 1);
  value_set(&values[1], "label", &slots[1], &lens[1], override->label,
      override->label_len, override->label != NULL);
  value_set(&values[2], "weight", &slots[2], &lens[2], number, strlen(number),
      override->has_weight);
  value_set(&values[3], "hidden", &slots[3], &lens[3], hidden, 1,
      override->hidden >= 0);
  value_set(&values[4], "parent", &slots[4], &lens[4], override->parent,
      override->parent_len, override->parent != NULL);
  value_set(&values[5], "menu", &slots[5], &lens[5], override->menu,
      override->menu_len, override->menu != NULL);
  return gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      sizeof kLang - 1, values, 6);
}

GDEFCORE_Result gdefcore_menu_stage_forget(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * catalog;
  const char * type;
  GDEFCORE_Result rc;
  if (changeset == NULL || name == NULL || name_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  type = site_name_ok(name, name_len) ? kEntryType : kOverrideType;
  rc = find_named(catalog, type, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_entity_clear(changeset, id, GDEFCORE_PUBLIC_ID_LEN);
}

/* ---- who may edit -------------------------------------------------------------- */

/* The fields a grant's condition can be about when it is asked about a write:
 * the entry's menu, name, route and parent. An override has no route. */
enum { kShapeFields = 4 };
static const char * const kShapeName[kShapeFields] = {"menu", "name", "route",
    "parent"};

typedef struct Shape {
  char * text[kShapeFields];
  size_t len[kShapeFields];
} Shape;

static void shape_free(Shape * shape) {
  size_t i;
  for (i = 0; i < kShapeFields; i++) {
    free(shape->text[i]);
    shape->text[i] = NULL;
    shape->len[i] = 0;
  }
}

/* One field as the write leaves it; absent is the empty text. */
static GDEFCORE_Result shape_field(GDEFCORE_Catalog * catalog,
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

static GDEFCORE_Result shape_load(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, Shape * shape) {
  size_t i;
  memset(shape, 0, sizeof *shape);
  for (i = 0; i < kShapeFields; i++) {
    GDEFCORE_Result rc = shape_field(catalog, cs, view, id, kShapeName[i],
        &shape->text[i], &shape->len[i]);
    if (rc != GDEFCORE_OK) {
      shape_free(shape);
      return rc;
    }
  }
  return GDEFCORE_OK;
}

/*
 * The decision about the entity @p id of @p type left as @p shape: allowed when
 * a grant holds on it as the write leaves it and, if it has been stored, on it
 * as it is stored too. Both, so that a value in @p shape can only narrow what
 * is stored. A failure is a no; only an allocation failure is returned. The
 * stored question is gdefcore_access_can(); the other, about an entity that
 * may not be stored yet, gdefcore_access_can_with().
 */
static GDEFCORE_Result decide_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * type, const char * id,
    const Shape * shape, int * allowed) {
  GDEFCORE_Condition_Value values[kShapeFields];
  size_t revisions = 0;
  int ok = 0;
  size_t i;
  GDEFCORE_Result rc;
  *allowed = 0;
  if (shape->len[1] == 0) {
    return GDEFCORE_OK;   /* no name: nothing to be an entry of */
  }
  for (i = 0; i < kShapeFields; i++) {
    memset(&values[i], 0, sizeof values[i]);
    values[i].size = sizeof values[i];
    values[i].field = kShapeName[i];
    values[i].field_len = strlen(kShapeName[i]);
    values[i].text = shape->text[i];
    values[i].text_len = shape->len[i];
  }
  rc = gdefcore_access_can_with(catalog, request, GDEFCORE_MENU_EDIT,
      sizeof GDEFCORE_MENU_EDIT - 1, type, strlen(type), id, values,
      kShapeFields, &ok);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_OK;
  }
  if (!ok) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_entity_revision_count(catalog, id, GDEFCORE_PUBLIC_ID_LEN,
      &revisions);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_OK;
  }
  if (revisions > 0) {
    rc = gdefcore_access_can(catalog, request, GDEFCORE_MENU_EDIT,
        sizeof GDEFCORE_MENU_EDIT - 1, type, strlen(type), id, &ok);
    if (rc != GDEFCORE_OK) {
      return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_OK;
    }
  }
  *allowed = ok;
  return GDEFCORE_OK;
}

static GDEFCORE_Result refuse_edit(GDEFCORE_Changeset * changeset,
    GDEFCORE_Result rc) {
  (void)gdefcore_changeset_set_refusal(changeset, kNotAllowed,
      sizeof kNotAllowed - 1);
  return rc;
}

GDEFCORE_Result gdefcore_menu_authorize(GDEFCORE_Changeset * changeset,
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
    Shape shape;
    const GDEFCORE_Changeset * through;
    const char * kind;
    int view;
    int allowed = 0;
    GDEFCORE_Result rc;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL) {
      continue;
    }
    if (span_eq(type, type_len, kEntryType, sizeof kEntryType - 1)) {
      kind = kEntryType;
    } else if (span_eq(type, type_len, kOverrideType, sizeof kOverrideType - 1)) {
      kind = kOverrideType;
    } else {
      continue;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      return refuse_edit(changeset, GDEFCORE_ERR_INVALID);
    }
    /* The entity as the write leaves it: what the write stages, else what is
     * stored. A clear leaves the stored one, and a publish makes the draft
     * the entity. */
    through = op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_PUBLISH
                  ? NULL
                  : changeset;
    view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                         : GDEFCORE_VIEW_CURRENT;
    rc = shape_load(catalog, through, view, canon, &shape);
    if (rc != GDEFCORE_OK) {
      return refuse_edit(changeset, rc);
    }
    if (kind == kEntryType && shape.len[0] == 0) {
      shape_free(&shape);   /* an entry in no menu is in none to be granted */
      return refuse_edit(changeset, GDEFCORE_ERR_INVALID);
    }
    rc = decide_edit(catalog, request, kind, canon, &shape, &allowed);
    shape_free(&shape);
    if (rc != GDEFCORE_OK) {
      return refuse_edit(changeset, rc);
    }
    if (!allowed) {
      return refuse_edit(changeset, GDEFCORE_ERR_INVALID);
    }
  }
  return GDEFCORE_OK;
}

/* ---- editing: one action, one changeset ---------------------------------- */

static GDEFCORE_Result refuse(GDEFCORE_Changeset * changeset, const char * text) {
  (void)gdefcore_changeset_set_refusal(changeset, text, strlen(text));
  return GDEFCORE_ERR_INVALID;
}

static uint64_t fnv_bytes(uint64_t h, const void * p, size_t n) {
  const unsigned char * b = (const unsigned char *)p;
  size_t i;
  for (i = 0; i < n; i++) {
    h ^= b[i];
    h *= 1099511628211ULL;
  }
  return h;
}

/* A field with its length in front, so that two fields cannot run together
 * into the same bytes as two others. */
static uint64_t fnv_field(uint64_t h, const char * p, size_t n) {
  unsigned char len[8];
  size_t k;
  for (k = 0; k < 8; k++) {
    len[k] = (unsigned char)(((uint64_t)n >> (8 * k)) & 0xffu);
  }
  h = fnv_bytes(h, len, sizeof len);
  return fnv_bytes(h, p, n);
}

static uint64_t fnv_int(uint64_t h, long v) {
  char text[32];
  int n = snprintf(text, sizeof text, "%ld", v);
  return fnv_field(h, text, n > 0 ? (size_t)n : 0);
}

GDEFCORE_Result gdefcore_menu_version(const GDEFCORE_Menu * menu, char * out,
    size_t cap) {
  uint64_t h = 14695981039346656037ULL;
  size_t i;
  if (menu == NULL || out == NULL || cap < GDEFCORE_MENU_VERSION_LEN + 1) {
    return GDEFCORE_ERR_INVALID;
  }
  h = fnv_int(h, (long)menu->n);
  for (i = 0; i < menu->n; i++) {
    const GDEFCORE_Menu_Item * it = &menu->items[i];
    h = fnv_field(h, it->name, it->name_len);
    h = fnv_field(h, it->label, it->label_len);
    h = fnv_field(h, it->route, it->route_len);
    h = fnv_field(h, it->menu, it->menu_len);
    h = fnv_field(h, it->parent, it->parent_len);
    h = fnv_int(h, it->weight);
    h = fnv_int(h, it->hidden);
    h = fnv_int(h, it->source);
    h = fnv_int(h, it->kind);
    h = fnv_int(h, it->depth);
  }
  /* Letters, so that a version is never a run of digits, which a page's
   * scanner for internal ids would take for one. */
  for (i = 0; i < GDEFCORE_MENU_VERSION_LEN; i++) {
    out[i] = (char)('a' + (int)((h >> (60 - 4 * i)) & 0xfu));
  }
  out[GDEFCORE_MENU_VERSION_LEN] = '\0';
  return GDEFCORE_OK;
}

static size_t node_find(const Ctx * c, const char * name, size_t n) {
  size_t i;
  for (i = 0; i < c->n; i++) {
    if (span_eq(c->nodes[i].name.p, c->nodes[i].name.n, name, n)) {
      return i;
    }
  }
  return NONE;
}

static const Ov * ov_find(const Ctx * c, const Str * name) {
  size_t k;
  for (k = 0; k < c->nov; k++) {
    if (str_eq(&c->ovs[k].name, name)) {
      return &c->ovs[k];
    }
  }
  return NULL;
}

/* What an edit changes about one entry. */
typedef struct Change {
  int label_set;
  Str label;
  int weight_set;
  int weight;
  int parent_set;
  Str parent;     /* "" for the top level */
  int hidden_set;
  int hidden;     /* 1 to hide, 0 to show */
} Change;

/*
 * Write entry @p i with @p ch. A site entry is edited as it is. A generated
 * entry gets an override that holds what the override held and what @p ch
 * changes, and nothing of the entry; an override left holding nothing is
 * forgotten.
 */
static GDEFCORE_Result node_write(const Ctx * c, GDEFCORE_Changeset * cs,
    size_t i, const Change * ch) {
  const Node * nd = &c->nodes[i];
  const Ov * ov;
  GDEFCORE_Menu_Override o;
  if (nd->source == GDEFCORE_MENU_SOURCE_SITE) {
    const Str * label = ch->label_set ? &ch->label : &nd->label;
    const Str * parent = ch->parent_set ? &ch->parent : &nd->parent;
    return stage_entry_full(cs, nd->name.p, nd->name.n, nd->menu.p, nd->menu.n,
        label->p, label->n, nd->route.p, nd->route.n, parent->p, parent->n,
        ch->weight_set ? ch->weight : nd->weight,
        ch->hidden_set ? ch->hidden : nd->hidden);
  }
  ov = ov_find(c, &nd->name);
  memset(&o, 0, sizeof o);
  o.size = sizeof o;
  o.hidden = -1;
  if (ov != NULL) {
    if (ov->has_label) {
      o.label = ov->label.p;
      o.label_len = ov->label.n;
    }
    if (ov->has_weight) {
      o.has_weight = 1;
      o.weight = ov->weight;
    }
    o.hidden = ov->hidden;
    if (ov->has_parent) {
      o.parent = ov->parent.p;
      o.parent_len = ov->parent.n;
    }
    if (ov->has_menu) {
      o.menu = ov->menu.p;
      o.menu_len = ov->menu.n;
    }
  }
  if (ch->label_set) {
    o.label = ch->label.p;
    o.label_len = ch->label.n;
  }
  if (ch->weight_set) {
    o.has_weight = 1;
    o.weight = ch->weight;
  }
  if (ch->parent_set) {
    if (ch->parent.n == 0) {
      o.parent = GDEFCORE_MENU_TOP;
      o.parent_len = sizeof GDEFCORE_MENU_TOP - 1;
    } else {
      o.parent = ch->parent.p;
      o.parent_len = ch->parent.n;
    }
  }
  if (ch->hidden_set) {
    o.hidden = ch->hidden ? 1 : -1;
  }
  if (o.label == NULL && !o.has_weight && o.hidden < 0 && o.parent == NULL &&
      o.menu == NULL) {
    return ov != NULL ? gdefcore_menu_stage_forget(cs, nd->name.p, nd->name.n)
                      : GDEFCORE_OK;
  }
  return gdefcore_menu_stage_override(cs, nd->name.p, nd->name.n, &o);
}

/* The entries directly under @p parent (NONE: the top level) in the order they
 * are shown, leaving out @p skip. Returns how many. */
static size_t siblings_of(const Ctx * c, const size_t * ord, size_t parent,
    const Str * menu, size_t skip, size_t * out) {
  size_t k;
  size_t n = 0;
  for (k = 0; k < c->n; k++) {
    size_t j = ord[k];
    const Node * nd = &c->nodes[j];
    if (j == skip || nd->source == GDEFCORE_MENU_SOURCE_TAB || nd->up != parent ||
        !str_eq(&nd->menu, menu)) {
      continue;
    }
    out[n++] = j;
  }
  return n;
}

static int node_depth(const Ctx * c, size_t i) {
  int d = 0;
  while (c->nodes[i].up != NONE && d < 64) {
    i = c->nodes[i].up;
    d += 1;
  }
  return d;
}

/* How many levels the entry and what is under it take. */
static int subtree_height(const Ctx * c, size_t i, int budget) {
  int best = 0;
  size_t j;
  if (budget <= 0) {
    return 1;
  }
  for (j = 0; j < c->n; j++) {
    if (c->nodes[j].up == i && c->nodes[j].source != GDEFCORE_MENU_SOURCE_TAB) {
      int h = subtree_height(c, j, budget - 1);
      best = h > best ? h : best;
    }
  }
  return 1 + best;
}

/* One entry a move writes, with the weight it ends up with. */
typedef struct Plan {
  size_t node;
  int weight;
  int weight_set;
  int parent_set;
} Plan;

/*
 * Put entry @p m under @p np (NONE: the top level of its menu) so that it is
 * the @p pos th of its new siblings. The weights it gives are the ones that
 * need no other entry changed, when the room between its neighbours allows,
 * and otherwise every sibling is numbered again; only an entry whose weight or
 * parent differs from what it has is written. All of it is staged here, in
 * the one changeset, after every refusal has been decided.
 */
static GDEFCORE_Result do_move(const Ctx * c, GDEFCORE_Changeset * cs, size_t m,
    size_t np, size_t pos) {
  size_t * ord = order_all(c);
  size_t * sib = (size_t *)malloc((c->n + 1) * sizeof *sib);
  size_t * old = (size_t *)malloc((c->n + 1) * sizeof *old);
  Plan * plan = (Plan *)malloc((c->n + 1) * sizeof *plan);
  const Node * mn = &c->nodes[m];
  size_t nsib;
  size_t nold;
  size_t oldpos = 0;
  size_t nplan = 0;
  size_t k;
  Str parent_name;
  int parent_changed;
  int renumber = 0;
  long wm = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (ord == NULL || sib == NULL || old == NULL || plan == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  if (np == NONE) {
    parent_name.p = "";
    parent_name.n = 0;
  } else {
    parent_name = c->nodes[np].name;
  }
  parent_changed = !str_eq(&mn->parent, &parent_name);
  nold = siblings_of(c, ord, mn->up, &mn->menu, NONE, old);
  for (k = 0; k < nold; k++) {
    if (old[k] == m) {
      oldpos = k;
    }
  }
  nsib = siblings_of(c, ord, np, &mn->menu, m, sib);
  if (pos > nsib) {
    rc = refuse(cs, GDEFCORE_MENU_REFUSED_PLACE);
    goto done;
  }
  if (np == mn->up && !parent_changed && pos == oldpos) {
    goto done;   /* it is already there */
  }
  {
    long cur = mn->weight;
    long a = 0;
    long b = 0;
    int have_a = pos > 0;
    int have_b = pos < nsib;
    if (have_a) {
      a = c->nodes[sib[pos - 1]].weight;
    }
    if (have_b) {
      b = c->nodes[sib[pos]].weight;
    }
    if (have_a && have_b) {
      if (cur > a && cur < b) {
        wm = cur;
      } else if (b - a >= 2) {
        wm = a + (b - a) / 2;
      } else {
        renumber = 1;
        wm = cur;
      }
    } else if (have_a) {
      wm = cur > a ? cur : a + 10;
      renumber = wm > 999999999;
    } else if (have_b) {
      wm = cur < b ? cur : b - 10;
      renumber = wm < -999999999;
    } else {
      wm = cur;
    }
  }
  if (!renumber) {
    if (parent_changed || wm != mn->weight) {
      plan[nplan].node = m;
      plan[nplan].weight = (int)wm;
      plan[nplan].weight_set = wm != mn->weight;
      plan[nplan].parent_set = parent_changed;
      nplan += 1;
    }
  } else {
    for (k = 0; k <= nsib; k++) {
      size_t node = k == pos ? m : sib[k < pos ? k : k - 1];
      int w = (int)(10 * (k + 1));
      if (node == m) {
        if (parent_changed || w != mn->weight) {
          plan[nplan].node = m;
          plan[nplan].weight = w;
          plan[nplan].weight_set = w != mn->weight;
          plan[nplan].parent_set = parent_changed;
          nplan += 1;
        }
      } else if (w != c->nodes[node].weight) {
        plan[nplan].node = node;
        plan[nplan].weight = w;
        plan[nplan].weight_set = 1;
        plan[nplan].parent_set = 0;
        nplan += 1;
      }
    }
  }
  if (nplan > GDEFCORE_MENU_EDIT_MAX) {
    rc = refuse(cs, GDEFCORE_MENU_REFUSED_MANY);
    goto done;
  }
  for (k = 0; rc == GDEFCORE_OK && k < nplan; k++) {
    Change ch;
    memset(&ch, 0, sizeof ch);
    ch.weight_set = plan[k].weight_set;
    ch.weight = plan[k].weight;
    ch.parent_set = plan[k].parent_set;
    ch.parent = parent_name;
    rc = node_write(c, cs, plan[k].node, &ch);
  }
done:
  free(ord);
  free(sib);
  free(old);
  free(plan);
  return rc;
}

/* Where an entry stands among its siblings: the index, and how many there are.
 * NONE on an allocation failure. */
static size_t sibling_index(const Ctx * c, const size_t * ord, size_t m,
    size_t * count) {
  size_t * list = (size_t *)malloc((c->n + 1) * sizeof *list);
  size_t n;
  size_t k;
  size_t at = 0;
  if (list == NULL) {
    *count = 0;
    return NONE;
  }
  n = siblings_of(c, ord, c->nodes[m].up, &c->nodes[m].menu, NONE, list);
  for (k = 0; k < n; k++) {
    if (list[k] == m) {
      at = k;
    }
  }
  free(list);
  *count = n;
  return at;
}

/* Decide the move of @p m under @p np: not into itself or what is under it,
 * and not so deep that the menu stops showing it. */
static GDEFCORE_Result move_checked(const Ctx * c, GDEFCORE_Changeset * cs,
    size_t m, size_t np, size_t pos) {
  size_t a;
  int depth;
  for (a = np; a != NONE; a = c->nodes[a].up) {
    if (a == m) {
      return refuse(cs, GDEFCORE_MENU_REFUSED_CYCLE);
    }
  }
  depth = (np == NONE ? 0 : node_depth(c, np) + 1) + subtree_height(c, m, 64);
  if (depth > GDEFCORE_MENU_DEPTH_MAX) {
    return refuse(cs, GDEFCORE_MENU_REFUSED_PLACE);
  }
  return do_move(c, cs, m, np, pos);
}

/* The record of what an edit wrote: one line for each entry or override, with
 * the revision it had when the changeset was prepared and whether the edit
 * clears it. Staged last, so that it names every write. */
static GDEFCORE_Result journal_save(GDEFCORE_Changeset * cs,
    const char * const * lines, const size_t * lens, size_t n) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[2];
  const char * slot;
  size_t len;
  GDEFCORE_Result rc = entity_for(cs, kChangeType, "last", 4, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  value_set(&values[0], "name", &slot, &len, "last", 4, 1);
  memset(&values[1], 0, sizeof values[1]);
  values[1].size = sizeof values[1];
  values[1].field = "entities";
  values[1].field_len = 8;
  values[1].texts = lines;
  values[1].text_lens = lens;
  values[1].count = n;
  return gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      sizeof kLang - 1, values, 2);
}

enum { kLineMax = 64 };

static GDEFCORE_Result record_writes(GDEFCORE_Changeset * cs) {
  size_t touched = gdefcore_changeset_touched_count(cs);
  size_t room = touched == 0 ? 1 : touched;
  char (*text)[kLineMax] = (char (*)[kLineMax])malloc(room * sizeof *text);
  const char ** lines = (const char **)malloc(room * sizeof *lines);
  size_t * lens = (size_t *)malloc(room * sizeof *lens);
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (text == NULL || lines == NULL || lens == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  for (i = 0; i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    uint64_t seq = 0;
    int w;
    if (gdefcore_changeset_touched_at(cs, i, &id, &id_len, &type, &type_len,
            &op) != GDEFCORE_OK ||
        type == NULL ||
        !(span_eq(type, type_len, kEntryType, sizeof kEntryType - 1) ||
            span_eq(type, type_len, kOverrideType, sizeof kOverrideType - 1))) {
      continue;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK ||
        gdefcore_changeset_base_seq(cs, canon, GDEFCORE_PUBLIC_ID_LEN, &seq) !=
            GDEFCORE_OK) {
      rc = GDEFCORE_ERR_INTERNAL;
      goto done;
    }
    w = snprintf(text[n], kLineMax, "%s %llu %c", canon, (unsigned long long)seq,
        op == GDEFCORE_TOUCH_CLEAR ? 'C' : 'S');
    if (w <= 0 || w >= kLineMax) {
      rc = GDEFCORE_ERR_INTERNAL;
      goto done;
    }
    lines[n] = text[n];
    lens[n] = (size_t)w;
    n += 1;
  }
  if (n > GDEFCORE_MENU_EDIT_MAX) {
    rc = refuse(cs, GDEFCORE_MENU_REFUSED_MANY);
  } else if (n > 0) {
    rc = journal_save(cs, lines, lens, n);
  }
done:
  free(text);
  free(lines);
  free(lens);
  return rc;
}

GDEFCORE_Result gdefcore_menu_stage_record(GDEFCORE_Changeset * changeset) {
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return record_writes(changeset);
}

GDEFCORE_Result gdefcore_menu_stage_edit(GDEFCORE_Changeset * changeset,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, const GDEFCORE_Menu_Edit * edit) {
  Ctx c;
  GDEFCORE_Menu * entries = NULL;
  GDEFCORE_Catalog * catalog;
  char version[GDEFCORE_MENU_VERSION_LEN + 1];
  size_t * ord = NULL;
  size_t m = NONE;
  Str parent_name;
  GDEFCORE_Result rc;
  if (changeset == NULL || routes == NULL || request == NULL || edit == NULL ||
      edit->size != sizeof *edit || edit->name == NULL || edit->name_len == 0 ||
      edit->version == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  /* Staging tells a caller about the menus (a stale version, a missing entry),
   * so it is for who may edit them; apply decides each write again. */
  if (!gdefcore_menu_may_edit(catalog, request)) {
    return refuse(changeset, kNotAllowed);
  }
  rc = ctx_open(&c, catalog, routes, request, match);
  if (rc == GDEFCORE_OK) {
    rc = entries_of(&c, &entries);
  }
  if (rc != GDEFCORE_OK) {
    ctx_free(&c);
    return rc;
  }
  rc = gdefcore_menu_version(entries, version, sizeof version);
  gdefcore_menu_free(entries);
  if (rc == GDEFCORE_OK &&
      !span_eq(version, strlen(version), edit->version, edit->version_len)) {
    rc = refuse(changeset, GDEFCORE_MENU_REFUSED_STALE);
  }
  if (rc == GDEFCORE_OK) {
    ord = order_all(&c);
    rc = ord == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
  }
  if (rc == GDEFCORE_OK && edit->action != GDEFCORE_MENU_ACT_ADD) {
    m = node_find(&c, edit->name, edit->name_len);
    if (m == NONE) {
      rc = refuse(changeset, GDEFCORE_MENU_REFUSED_ENTRY);
    }
  }
  if (rc == GDEFCORE_OK) {
    parent_name.p = edit->parent == NULL ? "" : edit->parent;
    parent_name.n = edit->parent == NULL ? 0 : edit->parent_len;
    switch (edit->action) {
    case GDEFCORE_MENU_ACT_ADD: {
      size_t np = NONE;
      size_t * list = (size_t *)malloc((c.n + 1) * sizeof *list);
      size_t n = 0;
      Str menu;
      int weight = 0;
      menu.p = edit->menu == NULL ? "" : edit->menu;
      menu.n = edit->menu == NULL ? 0 : edit->menu_len;
      if (list == NULL) {
        rc = GDEFCORE_ERR_OOM;
      } else if (node_find(&c, edit->name, edit->name_len) != NONE) {
        rc = refuse(changeset, GDEFCORE_MENU_REFUSED_ENTRY);
      } else if (parent_name.n > 0) {
        np = node_find(&c, parent_name.p, parent_name.n);
        if (np == NONE || c.nodes[np].source == GDEFCORE_MENU_SOURCE_TAB ||
            !str_eq(&c.nodes[np].menu, &menu)) {
          rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PARENT);
        }
      }
      if (rc == GDEFCORE_OK) {
        n = siblings_of(&c, ord, np, &menu, NONE, list);
        if (n > 0) {
          long last = c.nodes[list[n - 1]].weight;
          if (last + 10 > 999999999) {
            rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PLACE);
          } else {
            weight = (int)(last + 10);
          }
        }
      }
      if (rc == GDEFCORE_OK &&
          (np == NONE ? 0 : node_depth(&c, np) + 1) >= GDEFCORE_MENU_DEPTH_MAX) {
        rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PLACE);
      }
      if (rc == GDEFCORE_OK) {
        rc = stage_entry_full(changeset, edit->name, edit->name_len, menu.p,
            menu.n, edit->label, edit->label_len,
            edit->route == NULL ? "" : edit->route,
            edit->route == NULL ? 0 : edit->route_len, parent_name.p,
            parent_name.n, weight, 0);
      }
      free(list);
      break;
    }
    case GDEFCORE_MENU_ACT_RENAME: {
      Change ch;
      memset(&ch, 0, sizeof ch);
      ch.label_set = 1;
      ch.label.p = edit->label == NULL ? "" : edit->label;
      ch.label.n = edit->label == NULL ? 0 : edit->label_len;
      if (!str_eq(&ch.label, &c.nodes[m].label)) {
        rc = node_write(&c, changeset, m, &ch);
      }
      break;
    }
    case GDEFCORE_MENU_ACT_HIDE:
    case GDEFCORE_MENU_ACT_SHOW: {
      Change ch;
      int hide = edit->action == GDEFCORE_MENU_ACT_HIDE;
      memset(&ch, 0, sizeof ch);
      ch.hidden_set = 1;
      ch.hidden = hide;
      if ((c.nodes[m].hidden != 0) != hide) {
        rc = node_write(&c, changeset, m, &ch);
      }
      break;
    }
    case GDEFCORE_MENU_ACT_REMOVE:
      if (c.nodes[m].source != GDEFCORE_MENU_SOURCE_SITE) {
        rc = refuse(changeset, GDEFCORE_MENU_REFUSED_REMOVE);
      } else {
        rc = gdefcore_menu_stage_forget(changeset, edit->name, edit->name_len);
      }
      break;
    case GDEFCORE_MENU_ACT_MOVE:
    case GDEFCORE_MENU_ACT_UP:
    case GDEFCORE_MENU_ACT_DOWN:
    case GDEFCORE_MENU_ACT_INDENT:
    case GDEFCORE_MENU_ACT_OUTDENT: {
      size_t np = c.nodes[m].up;
      size_t pos = 0;
      size_t count = 0;
      size_t at;
      if (c.nodes[m].source == GDEFCORE_MENU_SOURCE_TAB) {
        rc = refuse(changeset, GDEFCORE_MENU_REFUSED_ENTRY);
        break;
      }
      at = sibling_index(&c, ord, m, &count);
      if (at == NONE) {
        rc = GDEFCORE_ERR_OOM;
        break;
      }
      if (edit->action == GDEFCORE_MENU_ACT_MOVE) {
        np = NONE;
        if (parent_name.n > 0) {
          np = node_find(&c, parent_name.p, parent_name.n);
          if (np == NONE || c.nodes[np].source == GDEFCORE_MENU_SOURCE_TAB ||
              !str_eq(&c.nodes[np].menu, &c.nodes[m].menu)) {
            rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PARENT);
            break;
          }
        }
        pos = edit->position;
      } else if (edit->action == GDEFCORE_MENU_ACT_UP) {
        if (at == 0) {
          rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PLACE);
          break;
        }
        pos = at - 1;
      } else if (edit->action == GDEFCORE_MENU_ACT_DOWN) {
        if (at + 1 >= count) {
          rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PLACE);
          break;
        }
        pos = at + 1;
      } else if (edit->action == GDEFCORE_MENU_ACT_INDENT) {
        size_t * list = (size_t *)malloc((c.n + 1) * sizeof *list);
        if (list == NULL) {
          rc = GDEFCORE_ERR_OOM;
          break;
        }
        (void)siblings_of(&c, ord, c.nodes[m].up, &c.nodes[m].menu, NONE, list);
        if (at == 0) {
          rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PLACE);
        } else {
          np = list[at - 1];
          pos = siblings_of(&c, ord, np, &c.nodes[m].menu, m, list);
        }
        free(list);
        if (rc != GDEFCORE_OK) {
          break;
        }
      } else {
        size_t * list;
        size_t gp;
        size_t n;
        size_t k;
        if (np == NONE) {
          rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PLACE);
          break;
        }
        gp = c.nodes[np].up;
        list = (size_t *)malloc((c.n + 1) * sizeof *list);
        if (list == NULL) {
          rc = GDEFCORE_ERR_OOM;
          break;
        }
        n = siblings_of(&c, ord, gp, &c.nodes[m].menu, m, list);
        for (k = 0; k < n; k++) {
          if (list[k] == np) {
            pos = k + 1;
          }
        }
        free(list);
        np = gp;
      }
      rc = move_checked(&c, changeset, m, np, pos);
      break;
    }
    default:
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
  }
  if (rc == GDEFCORE_OK && gdefcore_changeset_touched_count(changeset) > 0) {
    rc = record_writes(changeset);
  }
  free(ord);
  ctx_free(&c);
  return rc;
}

/* ---- undo ------------------------------------------------------------------- */

/* The fields of an entry and of an override, as stored. */
static const char * const kEntryFields[] = {"name", "menu", "label", "route",
    "parent", "weight", "hidden"};
static const char * const kOverrideFields[] = {"name", "label", "weight",
    "hidden", "parent", "menu"};

/* Write the values entity @p id had at revision @p seq as its newest. */
static GDEFCORE_Result restore_revision(GDEFCORE_Changeset * cs, const char * id,
    int is_entry, uint64_t seq) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(cs);
  const char * const * fields = is_entry ? kEntryFields : kOverrideFields;
  size_t nfields = is_entry ? sizeof kEntryFields / sizeof kEntryFields[0]
                            : sizeof kOverrideFields / sizeof kOverrideFields[0];
  GDEFCORE_Value values[7];
  char ** texts[7];
  size_t * lens[7];
  size_t counts[7];
  const char * slots[7];
  size_t slot_lens[7];
  size_t k;
  GDEFCORE_Result rc = GDEFCORE_OK;
  memset(texts, 0, sizeof texts);
  memset(lens, 0, sizeof lens);
  memset(counts, 0, sizeof counts);
  for (k = 0; rc == GDEFCORE_OK && k < nfields; k++) {
    GDEFCORE_Result got = gdefcore_entity_revision_values(catalog, id,
        GDEFCORE_PUBLIC_ID_LEN, seq, kLang, sizeof kLang - 1, fields[k],
        strlen(fields[k]), &texts[k], &lens[k], &counts[k]);
    if (got == GDEFCORE_ERR_INVALID) {
      counts[k] = 0;   /* a field that revision did not have */
    } else if (got != GDEFCORE_OK) {
      rc = got;
    }
    if (rc == GDEFCORE_OK) {
      value_set(&values[k], fields[k], &slots[k], &slot_lens[k],
          counts[k] > 0 ? texts[k][0] : NULL, counts[k] > 0 ? lens[k][0] : 0,
          counts[k] > 0);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
        sizeof kLang - 1, values, nfields);
  }
  for (k = 0; k < nfields; k++) {
    if (counts[k] > 0) {
      gdefcore_values_free(catalog, texts[k], lens[k], counts[k]);
    }
  }
  return rc;
}

/* One line of the record: the entity, the revision it had before the edit and
 * whether the edit cleared it. */
static int journal_line(const char * s, size_t n,
    char id[GDEFCORE_PUBLIC_ID_LEN + 1], uint64_t * seq, int * cleared) {
  size_t i = GDEFCORE_PUBLIC_ID_LEN + 1;
  uint64_t v = 0;
  size_t digits = 0;
  if (n < GDEFCORE_PUBLIC_ID_LEN + 4 || s[GDEFCORE_PUBLIC_ID_LEN] != ' ') {
    return 0;
  }
  memcpy(id, s, GDEFCORE_PUBLIC_ID_LEN);
  id[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  for (; i < n && s[i] >= '0' && s[i] <= '9' && digits < 19; i++) {
    v = v * 10 + (uint64_t)(s[i] - '0');
    digits += 1;
  }
  if (digits == 0 || i + 2 != n || s[i] != ' ' ||
      (s[i + 1] != 'S' && s[i + 1] != 'C')) {
    return 0;
  }
  *seq = v;
  *cleared = s[i + 1] == 'C';
  return 1;
}

typedef enum { kUndoSkip, kUndoClear, kUndoRestore } UndoAct;

GDEFCORE_Result gdefcore_menu_stage_undo(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request) {
  GDEFCORE_Catalog * catalog;
  char journal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  UndoAct * act = NULL;
  uint64_t * base = NULL;
  int * is_entry = NULL;
  size_t k;
  GDEFCORE_Result rc;
  if (changeset == NULL || request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  /* Whether there is an edit to undo, and whether it can be, are the menus'
   * editors' to be told. */
  if (!gdefcore_menu_may_edit(catalog, request)) {
    return refuse(changeset, kNotAllowed);
  }
  rc = find_named(catalog, kChangeType, "last", 4, journal);
  if (rc == GDEFCORE_ERR_INVALID) {
    return refuse(changeset, GDEFCORE_MENU_REFUSED_NOTHING);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_CURRENT, journal,
      GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "entities", 8, &texts,
      &lens, &n);
  if (rc == GDEFCORE_ERR_INVALID) {
    return refuse(changeset, GDEFCORE_MENU_REFUSED_NOTHING);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (n == 0) {
    gdefcore_values_free(catalog, texts, lens, n);
    return refuse(changeset, GDEFCORE_MENU_REFUSED_NOTHING);
  }
  act = (UndoAct *)calloc(n, sizeof *act);
  base = (uint64_t *)calloc(n, sizeof *base);
  is_entry = (int *)calloc(n, sizeof *is_entry);
  if (act == NULL || base == NULL || is_entry == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  /* Everything is decided before anything is staged: an entry written since
   * the edit refuses the whole undo. */
  for (k = 0; rc == GDEFCORE_OK && k < n; k++) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    int cleared = 0;
    char * type = NULL;
    size_t type_n = 0;
    int has = 0;
    uint64_t seq = 0;
    uint64_t latest = 0;
    if (!journal_line(texts[k], lens[k], id, &base[k], &cleared)) {
      rc = refuse(changeset, GDEFCORE_MENU_REFUSED_UNDO);
      break;
    }
    if (gdefcore_entity_type(catalog, id, GDEFCORE_PUBLIC_ID_LEN, &type,
            &type_n) != GDEFCORE_OK ||
        type == NULL) {
      rc = refuse(changeset, GDEFCORE_MENU_REFUSED_UNDO);
      break;
    }
    is_entry[k] = span_eq(type, type_n, kEntryType, sizeof kEntryType - 1);
    if (!is_entry[k] &&
        !span_eq(type, type_n, kOverrideType, sizeof kOverrideType - 1)) {
      gdefcore_text_free(catalog, type);
      rc = refuse(changeset, GDEFCORE_MENU_REFUSED_UNDO);
      break;
    }
    gdefcore_text_free(catalog, type);
    if (gdefcore_entity_current_revision(catalog, id, GDEFCORE_PUBLIC_ID_LEN,
            &has, &seq) != GDEFCORE_OK ||
        gdefcore_entity_revision(catalog, id, GDEFCORE_PUBLIC_ID_LEN, &latest) !=
            GDEFCORE_OK) {
      rc = refuse(changeset, GDEFCORE_MENU_REFUSED_UNDO);
      break;
    }
    if (cleared) {
      if (!has && latest == base[k] && base[k] > 0) {
        act[k] = kUndoRestore;
      } else {
        rc = refuse(changeset, GDEFCORE_MENU_REFUSED_UNDO);
      }
    } else if (has && seq == base[k] + 1) {
      act[k] = base[k] == 0 ? kUndoClear : kUndoRestore;
    } else if (has && seq == base[k] && base[k] > 0) {
      act[k] = kUndoSkip;   /* the edit saved what the entry already held */
    } else {
      rc = refuse(changeset, GDEFCORE_MENU_REFUSED_UNDO);
    }
  }
  for (k = 0; rc == GDEFCORE_OK && k < n; k++) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    int cleared = 0;
    uint64_t seq = 0;
    if (act[k] == kUndoSkip) {
      continue;
    }
    if (!journal_line(texts[k], lens[k], id, &seq, &cleared)) {
      rc = GDEFCORE_ERR_INTERNAL;
    } else if (act[k] == kUndoClear) {
      rc = gdefcore_entity_clear(changeset, id, GDEFCORE_PUBLIC_ID_LEN);
    } else {
      rc = restore_revision(changeset, id, is_entry[k], base[k]);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = journal_save(changeset, NULL, NULL, 0);
  }
  gdefcore_values_free(catalog, texts, lens, n);
  free(act);
  free(base);
  free(is_entry);
  return rc;
}
