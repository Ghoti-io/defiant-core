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
 * What a manifest declares besides hooks: routes, menu links, settings and
 * template variables. A manifest is copied once, at install, into a Decl whose
 * tables are sorted by machine name. Whether a set of Decls is acceptable is
 * decided here, in one function, for the enable that stages a module and for
 * the apply that commits it. The order of modules is not decided here: the
 * caller hands the Decls over in AD-10 order.
 */

#include <ghoti.io/defiant-core/macros.h>

#include "module_internal.h"

#include <ghoti.io/cutil/allocator.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  kCopyMax = 65536,
  kMenuMax = 64,
  kKindMax = 64,
  kVarDescMax = 256,
  kShow = 48
};

static const char kEmpty[] = "";

static int span_is(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static int span_cmp(const char * a, size_t an, const char * b, size_t bn) {
  size_t n = an < bn ? an : bn;
  int c = n == 0 ? 0 : memcmp(a, b, n);
  if (c != 0) {
    return c;
  }
  return an < bn ? -1 : (an > bn ? 1 : 0);
}

static void take_prefix(void * dst, size_t dst_n, const void * src) {
  const size_t * sizep = (const size_t *)src;
  size_t n = *sizep;
  memset(dst, 0, dst_n);
  if (n > dst_n) {
    n = dst_n;
  }
  if (n > 0) {
    memcpy(dst, src, n);
  }
}

/* -------------------------------------------------------------- build */

typedef struct Build {
  Decl * d;
  char * err;
  size_t cap;
  GDEFCORE_Result rc;
} Build;

static void build_fail(Build * b, GDEFCORE_Result rc, const char * what,
    size_t index) {
  if (b->rc != GDEFCORE_OK) {
    return;
  }
  b->rc = rc;
  if (b->err != NULL && b->cap > 0) {
    if (rc == GDEFCORE_ERR_LIMIT) {
      snprintf(b->err, b->cap, "Module %s: %s %zu is past a limit.",
          b->d->module, what, index + 1);
    } else if (rc == GDEFCORE_ERR_OOM) {
      snprintf(b->err, b->cap, "Module %s: out of memory.", b->d->module);
    } else {
      snprintf(b->err, b->cap, "Module %s: %s %zu is malformed.", b->d->module,
          what, index + 1);
    }
  }
}

/* Copy a string into the Decl. A NULL pointer is fine for length 0 only. */
static const char * dup_str(Build * b, const char * p, size_t n,
    const char * what, size_t index) {
  char * copy;
  if (b->rc != GDEFCORE_OK) {
    return kEmpty;
  }
  if (n == 0) {
    return kEmpty;
  }
  if (p == NULL) {
    build_fail(b, GDEFCORE_ERR_INVALID, what, index);
    return kEmpty;
  }
  if (n > kCopyMax) {
    build_fail(b, GDEFCORE_ERR_LIMIT, what, index);
    return kEmpty;
  }
  if (b->d->nblocks == b->d->cap_blocks) {
    size_t cap = b->d->cap_blocks == 0 ? 32 : b->d->cap_blocks * 2;
    void ** next = (void **)gcu_allocator_realloc(b->d->alloc, b->d->blocks,
        cap * sizeof *next);
    if (next == NULL) {
      build_fail(b, GDEFCORE_ERR_OOM, what, index);
      return kEmpty;
    }
    b->d->blocks = next;
    b->d->cap_blocks = cap;
  }
  copy = (char *)gcu_allocator_malloc(b->d->alloc, n + 1);
  if (copy == NULL) {
    build_fail(b, GDEFCORE_ERR_OOM, what, index);
    return kEmpty;
  }
  memcpy(copy, p, n);
  copy[n] = '\0';
  b->d->blocks[b->d->nblocks++] = copy;
  return copy;
}

/*
 * Resolve @p name among the module's own services. The same data
 * gdefcore_module_service() reads, limited to the declaring module: a handler
 * or a provider is the module's, not whichever module answers to the name.
 */
static int resolve(const DeclSvc * svcs, size_t nsvcs, const char * name,
    size_t name_len, uint32_t version, size_t need, const void ** table) {
  size_t i;
  *table = NULL;
  if (name_len == 0) {
    return kDeclNoName;
  }
  for (i = 0; i < nsvcs; i++) {
    if (span_is(svcs[i].name, svcs[i].name_len, name, name_len)) {
      const size_t * sizep;
      if (svcs[i].version != version) {
        return kDeclBadVersion;
      }
      if (svcs[i].table == NULL) {
        return kDeclBadTable;
      }
      sizep = (const size_t *)svcs[i].table;
      if (*sizep < need) {
        return kDeclBadTable;
      }
      *table = svcs[i].table;
      return kDeclResolved;
    }
  }
  return kDeclNoService;
}

static int cmp_route(const void * a, const void * b) {
  const DeclRoute * x = (const DeclRoute *)a;
  const DeclRoute * y = (const DeclRoute *)b;
  int c = span_cmp(x->pub.spec.machine, x->pub.spec.machine_len,
      y->pub.spec.machine, y->pub.spec.machine_len);
  return c != 0 ? c : (x->index < y->index ? -1 : (x->index > y->index));
}

static int cmp_link(const void * a, const void * b) {
  const DeclLink * x = (const DeclLink *)a;
  const DeclLink * y = (const DeclLink *)b;
  int c = span_cmp(x->pub.name, x->pub.name_len, y->pub.name, y->pub.name_len);
  return c != 0 ? c : (x->index < y->index ? -1 : (x->index > y->index));
}

static int cmp_setting(const void * a, const void * b) {
  const DeclSetting * x = (const DeclSetting *)a;
  const DeclSetting * y = (const DeclSetting *)b;
  int c = span_cmp(x->pub.name, x->pub.name_len, y->pub.name, y->pub.name_len);
  return c != 0 ? c : (x->index < y->index ? -1 : (x->index > y->index));
}

static int cmp_var(const void * a, const void * b) {
  const DeclVar * x = (const DeclVar *)a;
  const DeclVar * y = (const DeclVar *)b;
  int c = span_cmp(x->pub.kind, x->pub.kind_len, y->pub.kind, y->pub.kind_len);
  if (c == 0) {
    c = span_cmp(x->pub.name, x->pub.name_len, y->pub.name, y->pub.name_len);
  }
  return c != 0 ? c : (x->index < y->index ? -1 : (x->index > y->index));
}

void gdefcore_decl_free(Decl * d) {
  size_t i;
  if (d == NULL) {
    return;
  }
  for (i = 0; i < d->nblocks; i++) {
    gcu_allocator_free(d->alloc, d->blocks[i]);
  }
  gcu_allocator_free(d->alloc, d->blocks);
  gcu_allocator_free(d->alloc, d->routes);
  gcu_allocator_free(d->alloc, d->links);
  gcu_allocator_free(d->alloc, d->settings);
  gcu_allocator_free(d->alloc, d->vars);
  gcu_allocator_free(d->alloc, d);
}

static void build_routes(Build * b, const GDEFCORE_Module_Manifest * m,
    const DeclSvc * svcs, size_t nsvcs) {
  Decl * d = b->d;
  size_t i;
  d->routes = (DeclRoute *)gcu_allocator_calloc(d->alloc, m->nroutes,
      sizeof *d->routes);
  if (d->routes == NULL) {
    build_fail(b, GDEFCORE_ERR_OOM, "route", 0);
    return;
  }
  for (i = 0; i < m->nroutes && b->rc == GDEFCORE_OK; i++) {
    GDEFCORE_Module_Route r;
    DeclRoute * dr = &d->routes[i];
    GDEFCORE_Route_Spec * spec = &dr->pub.spec;
    const void * table = NULL;
    take_prefix(&r, sizeof r, &m->routes[i]);
    dr->index = i;
    dr->pub.size = sizeof dr->pub;
    dr->pub.module = d->module;
    dr->pub.module_len = d->module_len;
    dr->pub.admin = r.admin != 0;
    spec->size = sizeof *spec;
    spec->machine = dup_str(b, r.name, r.name_len, "route", i);
    spec->machine_len = r.name_len;
    spec->path = dup_str(b, r.path, r.path_len, "route", i);
    spec->path_len = r.path_len;
    spec->weight = r.weight;
    spec->after = r.after != 0;
    spec->permission = r.permission_len == 0
        ? NULL : dup_str(b, r.permission, r.permission_len, "route", i);
    spec->permission_len = r.permission_len;
    spec->title = r.title_len == 0
        ? NULL : dup_str(b, r.title, r.title_len, "route", i);
    spec->title_len = r.title_len;
    spec->kind = r.kind;
    spec->parent = r.parent_len == 0
        ? NULL : dup_str(b, r.parent, r.parent_len, "route", i);
    spec->parent_len = r.parent_len;
    spec->is_default = r.is_default != 0;
    dr->handler = dup_str(b, r.handler, r.handler_len, "route", i);
    dr->handler_len = r.handler_len;
    if (b->rc != GDEFCORE_OK) {
      break; /* a string did not copy: the lengths no longer match them */
    }
    dr->resolved = resolve(svcs, nsvcs, dr->handler, dr->handler_len,
        GDEFCORE_MODULE_ROUTE_HANDLER_VERSION,
        offsetof(GDEFCORE_Module_Route_Handler, data), &table);
    if (dr->resolved == kDeclResolved) {
      GDEFCORE_Module_Route_Handler h;
      take_prefix(&h, sizeof h, table);
      if (h.call_fn == NULL) {
        dr->resolved = kDeclBadTable;
      } else {
        spec->call_fn = h.call_fn;
        spec->data = h.data;
      }
    }
    d->nroutes = i + 1;
  }
  if (b->rc == GDEFCORE_OK && d->nroutes > 1) {
    qsort(d->routes, d->nroutes, sizeof *d->routes, cmp_route);
  }
}

static void build_links(Build * b, const GDEFCORE_Module_Manifest * m) {
  Decl * d = b->d;
  size_t i;
  d->links = (DeclLink *)gcu_allocator_calloc(d->alloc, m->nlinks,
      sizeof *d->links);
  if (d->links == NULL) {
    build_fail(b, GDEFCORE_ERR_OOM, "link", 0);
    return;
  }
  for (i = 0; i < m->nlinks && b->rc == GDEFCORE_OK; i++) {
    GDEFCORE_Module_Link l;
    DeclLink * dl = &d->links[i];
    take_prefix(&l, sizeof l, &m->links[i]);
    dl->index = i;
    dl->pub.size = sizeof dl->pub;
    dl->pub.module = d->module;
    dl->pub.module_len = d->module_len;
    dl->pub.name = dup_str(b, l.name, l.name_len, "link", i);
    dl->pub.name_len = l.name_len;
    dl->pub.menu = dup_str(b, l.menu, l.menu_len, "link", i);
    dl->pub.menu_len = l.menu_len;
    dl->pub.label = dup_str(b, l.label, l.label_len, "link", i);
    dl->pub.label_len = l.label_len;
    dl->pub.route = dup_str(b, l.route, l.route_len, "link", i);
    dl->pub.route_len = l.route_len;
    dl->pub.weight = l.weight;
    dl->pub.parent = dup_str(b, l.parent, l.parent_len, "link", i);
    dl->pub.parent_len = l.parent_len;
    dl->pub.kind = l.kind;
    d->nlinks = i + 1;
  }
  if (b->rc == GDEFCORE_OK && d->nlinks > 1) {
    qsort(d->links, d->nlinks, sizeof *d->links, cmp_link);
  }
}

static void build_settings(Build * b, const GDEFCORE_Module_Manifest * m) {
  Decl * d = b->d;
  size_t i;
  d->settings = (DeclSetting *)gcu_allocator_calloc(d->alloc, m->nsettings,
      sizeof *d->settings);
  if (d->settings == NULL) {
    build_fail(b, GDEFCORE_ERR_OOM, "setting", 0);
    return;
  }
  for (i = 0; i < m->nsettings && b->rc == GDEFCORE_OK; i++) {
    GDEFCORE_Module_Setting s;
    DeclSetting * ds = &d->settings[i];
    take_prefix(&s, sizeof s, &m->settings[i]);
    ds->index = i;
    ds->pub.size = sizeof ds->pub;
    ds->pub.module = d->module;
    ds->pub.module_len = d->module_len;
    ds->pub.name = dup_str(b, s.name, s.name_len, "setting", i);
    ds->pub.name_len = s.name_len;
    ds->pub.type = dup_str(b, s.type, s.type_len, "setting", i);
    ds->pub.type_len = s.type_len;
    ds->pub.default_value = dup_str(b, s.default_value, s.default_len,
        "setting", i);
    ds->pub.default_len = s.default_len;
    ds->pub.label = dup_str(b, s.label, s.label_len, "setting", i);
    ds->pub.label_len = s.label_len;
    ds->pub.description = dup_str(b, s.description, s.description_len,
        "setting", i);
    ds->pub.description_len = s.description_len;
    ds->pub.environment_local = s.environment_local != 0;
    ds->pub.group = dup_str(b, s.group, s.group_len, "setting", i);
    ds->pub.group_len = s.group_len;
    d->nsettings = i + 1;
  }
  if (b->rc == GDEFCORE_OK && d->nsettings > 1) {
    qsort(d->settings, d->nsettings, sizeof *d->settings, cmp_setting);
  }
}

static void build_vars(Build * b, const GDEFCORE_Module_Manifest * m,
    const DeclSvc * svcs, size_t nsvcs) {
  Decl * d = b->d;
  size_t i;
  d->vars = (DeclVar *)gcu_allocator_calloc(d->alloc, m->nvariables,
      sizeof *d->vars);
  if (d->vars == NULL) {
    build_fail(b, GDEFCORE_ERR_OOM, "variable", 0);
    return;
  }
  for (i = 0; i < m->nvariables && b->rc == GDEFCORE_OK; i++) {
    GDEFCORE_Module_Variable v;
    DeclVar * dv = &d->vars[i];
    const void * table = NULL;
    take_prefix(&v, sizeof v, &m->variables[i]);
    dv->index = i;
    dv->pub.size = sizeof dv->pub;
    dv->pub.module = d->module;
    dv->pub.module_len = d->module_len;
    dv->pub.kind = dup_str(b, v.kind, v.kind_len, "variable", i);
    dv->pub.kind_len = v.kind_len;
    dv->pub.name = dup_str(b, v.name, v.name_len, "variable", i);
    dv->pub.name_len = v.name_len;
    dv->pub.type = dup_str(b, v.type, v.type_len, "variable", i);
    dv->pub.type_len = v.type_len;
    dv->pub.description = dup_str(b, v.description, v.description_len,
        "variable", i);
    dv->pub.description_len = v.description_len;
    dv->pub.principal_free = v.principal_free != 0;
    dv->provider = dup_str(b, v.provider, v.provider_len, "variable", i);
    dv->provider_len = v.provider_len;
    if (b->rc != GDEFCORE_OK) {
      break;
    }
    dv->resolved = resolve(svcs, nsvcs, dv->provider, dv->provider_len,
        GDEFCORE_MODULE_VARIABLE_PROVIDER_VERSION,
        offsetof(GDEFCORE_Module_Variable_Provider, provider) +
            sizeof(GDEFCORE_Contribution_Fn),
        &table);
    if (dv->resolved == kDeclResolved) {
      GDEFCORE_Module_Variable_Provider p;
      take_prefix(&p, sizeof p, table);
      if (p.provider == NULL) {
        dv->resolved = kDeclBadTable;
      } else {
        dv->pub.provider = p.provider;
        dv->pub.user = p.user;
      }
    }
    d->nvars = i + 1;
  }
  if (b->rc == GDEFCORE_OK && d->nvars > 1) {
    qsort(d->vars, d->nvars, sizeof *d->vars, cmp_var);
  }
}

GDEFCORE_Result gdefcore_decl_build(const GDEFCORE_Allocator * alloc,
    const char * module, size_t module_len,
    const GDEFCORE_Module_Manifest * man, const DeclSvc * svcs, size_t nsvcs,
    Decl ** out, char * err, size_t cap) {
  Build b;
  Decl * d;
  *out = NULL;
  if (man->nroutes == 0 && man->nlinks == 0 && man->nsettings == 0 &&
      man->nvariables == 0) {
    return GDEFCORE_OK;
  }
  if (module_len > 64) {
    return GDEFCORE_ERR_INVALID;
  }
  d = (Decl *)gcu_allocator_calloc(alloc, 1, sizeof *d);
  if (d == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  d->alloc = alloc;
  memcpy(d->module, module, module_len);
  d->module[module_len] = '\0';
  d->module_len = module_len;
  b.d = d;
  b.err = err;
  b.cap = cap;
  b.rc = GDEFCORE_OK;
  if (man->nroutes > GDEFCORE_MODULE_ROUTES_MAX ||
      man->nlinks > GDEFCORE_MODULE_LINKS_MAX ||
      man->nsettings > GDEFCORE_MODULE_SETTINGS_MAX ||
      man->nvariables > GDEFCORE_MODULE_VARIABLES_MAX) {
    b.rc = GDEFCORE_ERR_LIMIT;
    if (err != NULL && cap > 0) {
      snprintf(err, cap,
          "Module %s declares more than %d routes, %d links, %d settings or "
          "%d variables.",
          d->module, GDEFCORE_MODULE_ROUTES_MAX, GDEFCORE_MODULE_LINKS_MAX,
          GDEFCORE_MODULE_SETTINGS_MAX, GDEFCORE_MODULE_VARIABLES_MAX);
    }
  } else if ((man->nroutes > 0 && man->routes == NULL) ||
             (man->nlinks > 0 && man->links == NULL) ||
             (man->nsettings > 0 && man->settings == NULL) ||
             (man->nvariables > 0 && man->variables == NULL)) {
    b.rc = GDEFCORE_ERR_INVALID;
    if (err != NULL && cap > 0) {
      snprintf(err, cap, "Module %s: a declared table has a count and no data.",
          d->module);
    }
  }
  if (b.rc == GDEFCORE_OK && man->nroutes > 0) {
    build_routes(&b, man, svcs, nsvcs);
  }
  if (b.rc == GDEFCORE_OK && man->nlinks > 0) {
    build_links(&b, man);
  }
  if (b.rc == GDEFCORE_OK && man->nsettings > 0) {
    build_settings(&b, man);
  }
  if (b.rc == GDEFCORE_OK && man->nvariables > 0) {
    build_vars(&b, man, svcs, nsvcs);
  }
  if (b.rc != GDEFCORE_OK) {
    gdefcore_decl_free(d);
    return b.rc;
  }
  *out = d;
  return GDEFCORE_OK;
}

/* ----------------------------------------------------------- validation */

/* Well-formed UTF-8 with no control character (newline and tab when asked), no
 * overlong form, no surrogate and nothing above U+10FFFF. */
static int text_ok(const char * s, size_t n, int allow_ws) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t more;
    uint32_t cp;
    uint32_t min;
    size_t k;
    if (c < 0x20 || c == 0x7f) {
      if (allow_ws && (c == '\n' || c == '\t')) {
        i += 1;
        continue;
      }
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
      unsigned char e = (unsigned char)s[i + k];
      if ((e & 0xc0) != 0x80) {
        return 0;
      }
      cp = (cp << 6) | (e & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      return 0;
    }
    i += more + 1;
  }
  return 1;
}

/* A short, printable rendering of a name for a message. Hostile bytes and
 * long names never reach the message whole. */
static const char * show(char * buf, const char * s, size_t n) {
  size_t i;
  size_t take = n < kShow ? n : kShow;
  for (i = 0; i < take; i++) {
    unsigned char c = (unsigned char)s[i];
    buf[i] = (c >= 0x20 && c < 0x7f && c != '\'') ? (char)c : '?';
  }
  if (n > take) {
    buf[take++] = '.';
    buf[take++] = '.';
    buf[take++] = '.';
  }
  buf[take] = '\0';
  return buf;
}

static int machine_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
         c == '_' || c == '-';
}

/* 0 fine, 1 not under the module, 2 bad length or characters. */
static int machine_check(const char * name, size_t n, const char * module,
    size_t mlen) {
  size_t i;
  if (n <= mlen + 1 || memcmp(name, module, mlen) != 0 || name[mlen] != '.') {
    return 1;
  }
  if (n > GDEFCORE_MODULE_DECL_NAME_MAX) {
    return 2;
  }
  for (i = 0; i < n; i++) {
    if (!machine_char(name[i])) {
      return 2;
    }
  }
  return 0;
}

/* `menu` and `group`: lowercase letters, digits, '.', '_' and '-'. */
static int ident_ok(const char * s, size_t n, size_t max) {
  size_t i;
  if (n == 0 || n > max || s[0] < 'a' || s[0] > 'z') {
    return 0;
  }
  for (i = 1; i < n; i++) {
    if (!machine_char(s[i])) {
      return 0;
    }
  }
  return 1;
}

/* A dotted Tang identifier path: `core.page`. */
static int path_ok(const char * s, size_t n) {
  size_t i;
  int start = 1;
  if (n == 0 || n > kKindMax) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (c == '.') {
      if (start || i + 1 == n) {
        return 0;
      }
      start = 1;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
            (!start && c >= '0' && c <= '9'))) {
      return 0;
    }
    start = 0;
  }
  return 1;
}

/* `m.count`, a hyphen of the module spelled '_', and no further dot. */
static int variable_name_ok(const char * name, size_t n, const char * module,
    size_t mlen) {
  size_t i;
  if (n <= mlen + 1 || name[mlen] != '.' || !path_ok(name, n)) {
    return 0;
  }
  for (i = 0; i < mlen; i++) {
    char want = module[i] == '-' ? '_' : module[i];
    if (name[i] != want) {
      return 0;
    }
  }
  return memchr(name + mlen + 1, '.', n - mlen - 1) == NULL;
}

static int number_ok(const char * s, size_t n) {
  size_t i = 0;
  size_t digits = 0;
  if (n == 0 || n > 40) {
    return 0;
  }
  if (s[i] == '-') {
    i += 1;
  }
  while (i < n && s[i] >= '0' && s[i] <= '9') {
    i += 1;
    digits += 1;
  }
  if (digits == 0) {
    return 0;
  }
  if (i < n && s[i] == '.') {
    size_t frac = 0;
    i += 1;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
      i += 1;
      frac += 1;
    }
    if (frac == 0) {
      return 0;
    }
  }
  return i == n;
}

typedef struct Entry {
  const char * p;
  size_t n;
  const char * kind;
  size_t kind_n;
  size_t mod;
  size_t idx;
} Entry;

static int cmp_entry(const void * a, const void * b) {
  const Entry * x = (const Entry *)a;
  const Entry * y = (const Entry *)b;
  int c = span_cmp(x->kind, x->kind_n, y->kind, y->kind_n);
  if (c == 0) {
    c = span_cmp(x->p, x->n, y->p, y->n);
  }
  if (c != 0) {
    return c;
  }
  if (x->mod != y->mod) {
    return x->mod < y->mod ? -1 : 1;
  }
  return x->idx < y->idx ? -1 : (x->idx > y->idx);
}

static const Entry * find_entry(const Entry * sorted, size_t n, const char * p,
    size_t len) {
  size_t lo = 0;
  size_t hi = n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = span_cmp(sorted[mid].p, sorted[mid].n, p, len);
    if (c == 0) {
      return &sorted[mid];
    }
    if (c < 0) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return NULL;
}

typedef struct Say {
  char * err;
  size_t cap;
} Say;

#define SAY(say, ...)                                                          \
  do {                                                                         \
    if ((say)->err != NULL && (say)->cap > 0) {                                \
      snprintf((say)->err, (say)->cap, __VA_ARGS__);                           \
    }                                                                          \
  } while (0)

/* Names may repeat within a table, in one module or across two. */
static int duplicates(const Entry * sorted, size_t n, const DeclRef * refs,
    const char * what, Say * say) {
  size_t i;
  for (i = 1; i < n; i++) {
    char a[kShow + 8];
    if (span_is(sorted[i].kind, sorted[i].kind_n, sorted[i - 1].kind,
            sorted[i - 1].kind_n) &&
        span_is(sorted[i].p, sorted[i].n, sorted[i - 1].p, sorted[i - 1].n)) {
      const Decl * x = refs[sorted[i - 1].mod].decl;
      const Decl * y = refs[sorted[i].mod].decl;
      if (sorted[i].mod == sorted[i - 1].mod) {
        SAY(say, "Module %s: %s '%s' is declared twice.", x->module, what,
            show(a, sorted[i].p, sorted[i].n));
      } else {
        SAY(say, "Module %s and module %s both declare %s '%s'.", x->module,
            y->module, what, show(a, sorted[i].p, sorted[i].n));
      }
      return 1;
    }
  }
  return 0;
}

static const char * why_service(int status) {
  switch (status) {
  case kDeclNoName:
    return "names no service";
  case kDeclNoService:
    return "names a service the module does not declare";
  case kDeclBadVersion:
    return "names a service declared at another version";
  default:
    return "names a service whose table does not carry the function";
  }
}

static int check_routes(const DeclRef * refs, size_t n, const Entry * routes,
    size_t nroutes, int local, Say * say) {
  size_t m;
  size_t i;
  for (m = 0; m < n; m++) {
    const Decl * d = refs[m].decl;
    for (i = 0; i < d->nroutes; i++) {
      const DeclRoute * r = &d->routes[i];
      const GDEFCORE_Route_Spec * s = &r->pub.spec;
      char a[kShow + 8];
      int mc;
      if (s->machine_len == 0) {
        SAY(say, "Module %s: a route has an empty name.", d->module);
        return 1;
      }
      mc = machine_check(s->machine, s->machine_len, d->module, d->module_len);
      if (mc == 1) {
        SAY(say, "Module %s: route '%s' is not named %s.<name>.", d->module,
            show(a, s->machine, s->machine_len), d->module);
        return 1;
      }
      if (mc == 2) {
        SAY(say,
            "Module %s: route '%s' has a name over %d bytes or with a "
            "character outside a-z, 0-9, '.', '_' and '-'.",
            d->module, show(a, s->machine, s->machine_len),
            GDEFCORE_MODULE_DECL_NAME_MAX);
        return 1;
      }
      if (r->resolved != kDeclResolved) {
        char b[kShow + 8];
        SAY(say, "Module %s: route '%s' handler %s ('%s').", d->module,
            show(a, s->machine, s->machine_len), why_service(r->resolved),
            show(b, r->handler, r->handler_len));
        return 1;
      }
      if (s->kind != GDEFCORE_ROUTE_PAGE && s->kind != GDEFCORE_ROUTE_TAB &&
          s->kind != GDEFCORE_ROUTE_ACTION) {
        SAY(say, "Module %s: route '%s' has an unknown kind %d.", d->module,
            show(a, s->machine, s->machine_len), s->kind);
        return 1;
      }
      if (!local && s->kind == GDEFCORE_ROUTE_TAB && s->parent_len > 0 &&
          find_entry(routes, nroutes, s->parent, s->parent_len) == NULL) {
        char b[kShow + 8];
        SAY(say, "Module %s: route '%s' is a tab of '%s', which no enabled "
                 "module declares as a route.",
            d->module, show(a, s->machine, s->machine_len),
            show(b, s->parent, s->parent_len));
        return 1;
      }
    }
  }
  return 0;
}

static int check_links(const DeclRef * refs, size_t n, const Entry * routes,
    size_t nroutes, const Entry * links, size_t nlinks, int local, Say * say) {
  size_t m;
  size_t i;
  for (m = 0; m < n; m++) {
    const Decl * d = refs[m].decl;
    for (i = 0; i < d->nlinks; i++) {
      const GDEFCORE_Module_Declared_Link * l = &d->links[i].pub;
      char a[kShow + 8];
      char b[kShow + 8];
      int mc;
      if (l->name_len == 0) {
        SAY(say, "Module %s: a menu link has an empty name.", d->module);
        return 1;
      }
      mc = machine_check(l->name, l->name_len, d->module, d->module_len);
      if (mc == 1) {
        SAY(say, "Module %s: menu link '%s' is not named %s.<name>.", d->module,
            show(a, l->name, l->name_len), d->module);
        return 1;
      }
      if (mc == 2) {
        SAY(say,
            "Module %s: menu link '%s' has a name over %d bytes or with a "
            "character outside a-z, 0-9, '.', '_' and '-'.",
            d->module, show(a, l->name, l->name_len),
            GDEFCORE_MODULE_DECL_NAME_MAX);
        return 1;
      }
      if (!ident_ok(l->menu, l->menu_len, kMenuMax)) {
        SAY(say, "Module %s: menu link '%s' names a menu that is not 1 to %d "
                 "bytes of a-z, 0-9, '.', '_' and '-' starting with a letter.",
            d->module, show(a, l->name, l->name_len), kMenuMax);
        return 1;
      }
      if (l->label_len == 0 || l->label_len > GDEFCORE_MODULE_DECL_LABEL_MAX ||
          !text_ok(l->label, l->label_len, 0)) {
        SAY(say, "Module %s: menu link '%s' has no label, or one that is over "
                 "%d bytes or not UTF-8 text.",
            d->module, show(a, l->name, l->name_len),
            GDEFCORE_MODULE_DECL_LABEL_MAX);
        return 1;
      }
      if (l->kind != GDEFCORE_ROUTE_PAGE && l->kind != GDEFCORE_ROUTE_TAB &&
          l->kind != GDEFCORE_ROUTE_ACTION) {
        SAY(say, "Module %s: menu link '%s' has an unknown kind %d.", d->module,
            show(a, l->name, l->name_len), l->kind);
        return 1;
      }
      if (local) {
        continue;
      }
      if (find_entry(routes, nroutes, l->route, l->route_len) == NULL) {
        SAY(say, "Module %s: menu link '%s' targets route '%s', which no "
                 "enabled module declares.",
            d->module, show(a, l->name, l->name_len),
            show(b, l->route, l->route_len));
        return 1;
      }
      if (l->parent_len > 0) {
        const Entry * up = find_entry(links, nlinks, l->parent, l->parent_len);
        size_t hops = 0;
        if (up == NULL) {
          SAY(say, "Module %s: menu link '%s' has parent link '%s', which no "
                   "enabled module declares.",
              d->module, show(a, l->name, l->name_len),
              show(b, l->parent, l->parent_len));
          return 1;
        }
        /* Same menu, and no loop on the way up. */
        while (up != NULL) {
          const GDEFCORE_Module_Declared_Link * u =
              &refs[up->mod].decl->links[up->idx].pub;
          if (!span_is(u->menu, u->menu_len, l->menu, l->menu_len)) {
            SAY(say, "Module %s: menu link '%s' has a parent in another menu.",
                d->module, show(a, l->name, l->name_len));
            return 1;
          }
          if (u->parent_len == 0) {
            break;
          }
          hops += 1;
          if (hops > nlinks) {
            SAY(say, "Module %s: menu link '%s' is its own ancestor.",
                d->module, show(a, l->name, l->name_len));
            return 1;
          }
          up = find_entry(links, nlinks, u->parent, u->parent_len);
        }
      }
    }
  }
  return 0;
}

static int check_settings(const DeclRef * refs, size_t n, Say * say) {
  size_t m;
  size_t i;
  for (m = 0; m < n; m++) {
    const Decl * d = refs[m].decl;
    for (i = 0; i < d->nsettings; i++) {
      const GDEFCORE_Module_Declared_Setting * s = &d->settings[i].pub;
      char a[kShow + 8];
      int mc;
      int is_text;
      int is_number;
      int is_bool;
      if (s->name_len == 0) {
        SAY(say, "Module %s: a setting has an empty name.", d->module);
        return 1;
      }
      mc = machine_check(s->name, s->name_len, d->module, d->module_len);
      if (mc == 1) {
        SAY(say, "Module %s: setting '%s' is not named %s.<name>.", d->module,
            show(a, s->name, s->name_len), d->module);
        return 1;
      }
      if (mc == 2) {
        SAY(say,
            "Module %s: setting '%s' has a name over %d bytes or with a "
            "character outside a-z, 0-9, '.', '_' and '-'.",
            d->module, show(a, s->name, s->name_len),
            GDEFCORE_MODULE_DECL_NAME_MAX);
        return 1;
      }
      is_text = span_is(s->type, s->type_len, "text", 4);
      is_number = span_is(s->type, s->type_len, "number", 6);
      is_bool = span_is(s->type, s->type_len, "boolean", 7);
      if (!is_text && !is_number && !is_bool) {
        SAY(say, "Module %s: setting '%s' has a type that is not text, number "
                 "or boolean.",
            d->module, show(a, s->name, s->name_len));
        return 1;
      }
      if (s->default_len > GDEFCORE_MODULE_DECL_TEXT_MAX ||
          !text_ok(s->default_value, s->default_len, 1) ||
          (is_number && !number_ok(s->default_value, s->default_len)) ||
          (is_bool && !span_is(s->default_value, s->default_len, "true", 4) &&
              !span_is(s->default_value, s->default_len, "false", 5))) {
        SAY(say, "Module %s: setting '%s' has a default that is not a valid %s.",
            d->module, show(a, s->name, s->name_len),
            is_text ? "text" : (is_number ? "number" : "boolean"));
        return 1;
      }
      if (s->label_len == 0 || s->label_len > GDEFCORE_MODULE_DECL_LABEL_MAX ||
          !text_ok(s->label, s->label_len, 0)) {
        SAY(say, "Module %s: setting '%s' has no label, or one that is over "
                 "%d bytes or not UTF-8 text.",
            d->module, show(a, s->name, s->name_len),
            GDEFCORE_MODULE_DECL_LABEL_MAX);
        return 1;
      }
      if (s->description_len > GDEFCORE_MODULE_DECL_TEXT_MAX ||
          !text_ok(s->description, s->description_len, 1)) {
        SAY(say, "Module %s: setting '%s' has a description that is over %d "
                 "bytes or not UTF-8 text.",
            d->module, show(a, s->name, s->name_len),
            GDEFCORE_MODULE_DECL_TEXT_MAX);
        return 1;
      }
      if (s->group_len > 0 && !ident_ok(s->group, s->group_len, kMenuMax)) {
        SAY(say, "Module %s: setting '%s' has a group that is not 1 to %d "
                 "bytes of a-z, 0-9, '.', '_' and '-' starting with a letter.",
            d->module, show(a, s->name, s->name_len), kMenuMax);
        return 1;
      }
    }
  }
  return 0;
}

static int check_vars(const DeclRef * refs, size_t n, Say * say) {
  size_t m;
  size_t i;
  for (m = 0; m < n; m++) {
    const Decl * d = refs[m].decl;
    for (i = 0; i < d->nvars; i++) {
      const DeclVar * v = &d->vars[i];
      const GDEFCORE_Module_Contributed * p = &v->pub;
      char a[kShow + 8];
      char b[kShow + 8];
      if (p->name_len == 0) {
        SAY(say, "Module %s: a template variable has an empty name.", d->module);
        return 1;
      }
      if (!variable_name_ok(p->name, p->name_len, d->module, d->module_len)) {
        SAY(say, "Module %s: template variable '%s' is not named %s.<name>, "
                 "letters, digits and underscore.",
            d->module, show(a, p->name, p->name_len), d->module);
        return 1;
      }
      if (!path_ok(p->kind, p->kind_len)) {
        SAY(say, "Module %s: template variable '%s' names a kind that is not a "
                 "dotted identifier.",
            d->module, show(a, p->name, p->name_len));
        return 1;
      }
      if (!span_is(p->type, p->type_len, "text", 4) &&
          !span_is(p->type, p->type_len, "markup", 6) &&
          !span_is(p->type, p->type_len, "number", 6)) {
        SAY(say, "Module %s: template variable '%s' is not text, markup or "
                 "number.",
            d->module, show(a, p->name, p->name_len));
        return 1;
      }
      if (p->description_len > kVarDescMax ||
          !text_ok(p->description, p->description_len, 1)) {
        SAY(say, "Module %s: template variable '%s' has a description over %d "
                 "bytes or not UTF-8 text.",
            d->module, show(a, p->name, p->name_len), kVarDescMax);
        return 1;
      }
      if (v->resolved != kDeclResolved) {
        SAY(say, "Module %s: template variable '%s' provider %s ('%s').",
            d->module, show(a, p->name, p->name_len), why_service(v->resolved),
            show(b, v->provider, v->provider_len));
        return 1;
      }
    }
  }
  return 0;
}

/* Fill an Entry table; the caller sorts it. */
static Entry * collect(const GDEFCORE_Allocator * alloc, const DeclRef * refs,
    size_t n, int table, size_t * out_n) {
  size_t m;
  size_t i;
  size_t total = 0;
  size_t at = 0;
  Entry * e;
  for (m = 0; m < n; m++) {
    const Decl * d = refs[m].decl;
    total += table == 0 ? d->nroutes
                        : (table == 1 ? d->nlinks
                                      : (table == 2 ? d->nsettings : d->nvars));
  }
  e = (Entry *)gcu_allocator_calloc(alloc, total == 0 ? 1 : total, sizeof *e);
  if (e == NULL) {
    return NULL;
  }
  for (m = 0; m < n; m++) {
    const Decl * d = refs[m].decl;
    size_t count = table == 0 ? d->nroutes
                              : (table == 1 ? d->nlinks
                                            : (table == 2 ? d->nsettings
                                                          : d->nvars));
    for (i = 0; i < count; i++) {
      e[at].mod = m;
      e[at].idx = i;
      e[at].kind = kEmpty;
      if (table == 0) {
        e[at].p = d->routes[i].pub.spec.machine;
        e[at].n = d->routes[i].pub.spec.machine_len;
      } else if (table == 1) {
        e[at].p = d->links[i].pub.name;
        e[at].n = d->links[i].pub.name_len;
      } else if (table == 2) {
        e[at].p = d->settings[i].pub.name;
        e[at].n = d->settings[i].pub.name_len;
      } else {
        e[at].p = d->vars[i].pub.name;
        e[at].n = d->vars[i].pub.name_len;
        e[at].kind = d->vars[i].pub.kind;
        e[at].kind_n = d->vars[i].pub.kind_len;
      }
      at += 1;
    }
  }
  if (at > 1) {
    qsort(e, at, sizeof *e, cmp_entry);
  }
  *out_n = at;
  return e;
}

int gdefcore_decl_validate(const DeclRef * refs, size_t n, int local,
    char * err, size_t cap) {
  const GDEFCORE_Allocator * alloc;
  Entry * routes = NULL;
  Entry * links = NULL;
  Entry * settings = NULL;
  Entry * vars = NULL;
  size_t nroutes = 0;
  size_t nlinks = 0;
  size_t nsettings = 0;
  size_t nvars = 0;
  Say say;
  GDEFCORE_Routes * scratch = NULL;
  int bad = 0;
  say.err = err;
  say.cap = cap;
  if (n == 0) {
    return 0;
  }
  alloc = refs[0].decl->alloc;
  routes = collect(alloc, refs, n, 0, &nroutes);
  links = collect(alloc, refs, n, 1, &nlinks);
  settings = collect(alloc, refs, n, 2, &nsettings);
  vars = collect(alloc, refs, n, 3, &nvars);
  if (routes == NULL || links == NULL || settings == NULL || vars == NULL) {
    SAY(&say, "Out of memory while checking the declarations.");
    bad = 1;
    goto done;
  }
  /* Field checks first, so a malformed entry is named for what it is and a
   * duplicate is only reported among entries that are otherwise sound. */
  bad = check_routes(refs, n, routes, nroutes, local, &say) ||
        check_links(refs, n, routes, nroutes, links, nlinks, local, &say) ||
        check_settings(refs, n, &say) || check_vars(refs, n, &say) ||
        duplicates(routes, nroutes, refs, "route", &say) ||
        duplicates(links, nlinks, refs, "menu link", &say) ||
        duplicates(settings, nsettings, refs, "setting", &say) ||
        duplicates(vars, nvars, refs, "template variable", &say);
  if (bad) {
    goto done;
  }
  /* The routes as a route table would take them: patterns, titles, a second
   * default tab, a default tab that captures what its parent does not. The
   * table decides, so this cannot drift from what dispatch accepts. */
  if (nroutes > 0) {
    char * text = NULL;
    size_t text_n = 0;
    const GDEFCORE_Module_Declared_Route * failed = NULL;
    GDEFCORE_Result rc = gdefcore_routes_create(alloc, &scratch);
    if (rc != GDEFCORE_OK) {
      SAY(&say, "Out of memory while checking the routes.");
      bad = 1;
      goto done;
    }
    rc = gdefcore_decl_add_routes(alloc, refs, n, scratch, &text, &text_n,
        &failed, local);
    if (rc != GDEFCORE_OK) {
      char a[kShow + 8];
      char why[160];
      size_t k = 0;
      /* The table's first line, without the route's own path. */
      while (text != NULL && k < text_n && text[k] != '\n' && k < sizeof why - 1) {
        why[k] = (text[k] >= 0x20 && text[k] < 0x7f) ? text[k] : '?';
        k += 1;
      }
      why[k] = '\0';
      if (failed != NULL) {
        SAY(&say, "Module %s: route '%s' is refused as a route: %s.",
            failed->module,
            show(a, failed->spec.machine, failed->spec.machine_len),
            k > 0 ? why : "the route table refused it");
      } else {
        SAY(&say, "The routes are refused as a route table: %s.",
            k > 0 ? why : "out of memory");
      }
      gdefcore_routes_free(scratch, text);
      bad = 1;
      goto done;
    }
    gdefcore_routes_free(scratch, text);
  }
done:
  gdefcore_routes_destroy(scratch);
  gcu_allocator_free(alloc, routes);
  gcu_allocator_free(alloc, links);
  gcu_allocator_free(alloc, settings);
  gcu_allocator_free(alloc, vars);
  return bad;
}

/* ---------------------------------------------------------- enumeration */

GDEFCORE_Result gdefcore_decl_routes(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Route *** out, size_t * count) {
  size_t m;
  size_t i;
  size_t total = 0;
  size_t at = 0;
  const GDEFCORE_Module_Declared_Route ** items;
  *out = NULL;
  *count = 0;
  for (m = 0; m < n; m++) {
    total += refs[m].decl->nroutes;
  }
  if (total == 0) {
    return GDEFCORE_OK;
  }
  items = (const GDEFCORE_Module_Declared_Route **)gcu_allocator_calloc(alloc,
      total, sizeof *items);
  if (items == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (m = 0; m < n; m++) {
    for (i = 0; i < refs[m].decl->nroutes; i++) {
      items[at++] = &refs[m].decl->routes[i].pub;
    }
  }
  *out = items;
  *count = total;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_decl_links(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Link *** out, size_t * count) {
  size_t m;
  size_t i;
  size_t total = 0;
  size_t at = 0;
  const GDEFCORE_Module_Declared_Link ** items;
  *out = NULL;
  *count = 0;
  for (m = 0; m < n; m++) {
    total += refs[m].decl->nlinks;
  }
  if (total == 0) {
    return GDEFCORE_OK;
  }
  items = (const GDEFCORE_Module_Declared_Link **)gcu_allocator_calloc(alloc,
      total, sizeof *items);
  if (items == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (m = 0; m < n; m++) {
    for (i = 0; i < refs[m].decl->nlinks; i++) {
      items[at++] = &refs[m].decl->links[i].pub;
    }
  }
  *out = items;
  *count = total;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_decl_settings(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Setting *** out, size_t * count) {
  size_t m;
  size_t i;
  size_t total = 0;
  size_t at = 0;
  const GDEFCORE_Module_Declared_Setting ** items;
  *out = NULL;
  *count = 0;
  for (m = 0; m < n; m++) {
    total += refs[m].decl->nsettings;
  }
  if (total == 0) {
    return GDEFCORE_OK;
  }
  items = (const GDEFCORE_Module_Declared_Setting **)gcu_allocator_calloc(alloc,
      total, sizeof *items);
  if (items == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (m = 0; m < n; m++) {
    for (i = 0; i < refs[m].decl->nsettings; i++) {
      items[at++] = &refs[m].decl->settings[i].pub;
    }
  }
  *out = items;
  *count = total;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_decl_variables(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n, const GDEFCORE_Module_Contributed *** out,
    size_t * count) {
  size_t m;
  size_t i;
  size_t total = 0;
  size_t at = 0;
  const GDEFCORE_Module_Contributed ** items;
  *out = NULL;
  *count = 0;
  for (m = 0; m < n; m++) {
    total += refs[m].decl->nvars;
  }
  if (total == 0) {
    return GDEFCORE_OK;
  }
  items = (const GDEFCORE_Module_Contributed **)gcu_allocator_calloc(alloc,
      total, sizeof *items);
  if (items == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (m = 0; m < n; m++) {
    for (i = 0; i < refs[m].decl->nvars; i++) {
      items[at++] = &refs[m].decl->vars[i].pub;
    }
  }
  *out = items;
  *count = total;
  return GDEFCORE_OK;
}

/* ------------------------------------------------------------ add routes */

GDEFCORE_Result gdefcore_decl_add_routes(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n, GDEFCORE_Routes * routes, char ** out_error,
    size_t * out_error_len,
    const GDEFCORE_Module_Declared_Route ** failed, int local) {
  const GDEFCORE_Module_Declared_Route ** items = NULL;
  unsigned char * done;
  size_t count = 0;
  size_t left;
  size_t i;
  size_t j;
  GDEFCORE_Result rc;
  if (out_error != NULL) {
    *out_error = NULL;
  }
  if (out_error_len != NULL) {
    *out_error_len = 0;
  }
  if (failed != NULL) {
    *failed = NULL;
  }
  rc = gdefcore_decl_routes(alloc, refs, n, &items, &count);
  if (rc != GDEFCORE_OK || count == 0) {
    return rc;
  }
  done = (unsigned char *)gcu_allocator_calloc(alloc, count, 1);
  if (done == NULL) {
    gcu_allocator_free(alloc, (void *)items);
    return GDEFCORE_ERR_OOM;
  }
  left = count;
  if (local) {
    /* A tab whose parent is not here is another module's to answer for, and so
     * is a tab of that tab: count them as done until nothing more changes. */
    int changed = 1;
    while (changed) {
      changed = 0;
      for (i = 0; i < count; i++) {
        const GDEFCORE_Route_Spec * s = &items[i]->spec;
        int found = 0;
        if (done[i] || s->kind != GDEFCORE_ROUTE_TAB || s->parent_len == 0) {
          continue;
        }
        for (j = 0; j < count; j++) {
          if (done[j] == 0 && j != i &&
              span_is(items[j]->spec.machine, items[j]->spec.machine_len,
                  s->parent, s->parent_len)) {
            found = 1;
            break;
          }
        }
        if (!found) {
          done[i] = 2;
          left -= 1;
          changed = 1;
        }
      }
    }
  }
  while (left > 0) {
    size_t added = 0;
    for (i = 0; i < count; i++) {
      const GDEFCORE_Route_Spec * s;
      int wait = 0;
      if (done[i]) {
        continue;
      }
      s = &items[i]->spec;
      /* A tab waits for its parent when the parent is in this set. */
      if (s->kind == GDEFCORE_ROUTE_TAB) {
        for (j = 0; j < count; j++) {
          if (!done[j] && j != i &&
              span_is(items[j]->spec.machine, items[j]->spec.machine_len,
                  s->parent, s->parent_len)) {
            wait = 1;
            break;
          }
        }
      }
      if (wait) {
        continue;
      }
      rc = gdefcore_route_add_spec(routes, s, out_error, out_error_len);
      if (rc != GDEFCORE_OK) {
        if (failed != NULL) {
          *failed = items[i];
        }
        gcu_allocator_free(alloc, done);
        gcu_allocator_free(alloc, (void *)items);
        return rc;
      }
      done[i] = 1;
      left -= 1;
      added += 1;
    }
    if (added == 0) {
      /* Tabs that wait on each other: let the table say what is missing. */
      for (i = 0; i < count; i++) {
        if (!done[i]) {
          rc = gdefcore_route_add_spec(routes, &items[i]->spec, out_error,
              out_error_len);
          if (rc == GDEFCORE_OK) {
            rc = GDEFCORE_ERR_INVALID;
          }
          if (failed != NULL) {
            *failed = items[i];
          }
          gcu_allocator_free(alloc, done);
          gcu_allocator_free(alloc, (void *)items);
          return rc;
        }
      }
    }
  }
  gcu_allocator_free(alloc, done);
  gcu_allocator_free(alloc, (void *)items);
  return GDEFCORE_OK;
}
