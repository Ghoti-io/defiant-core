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
 * Settings: the kernel's and the modules' declarations, the changed values on
 * the entity port, the environment-local values beside the tenant, the generated
 * form, and the configuration export and import. See settings.h.
 */

#include <ghoti.io/defiant-core/macros.h>

#include "settings_internal.h"

#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>
#include <ghoti.io/defiant-core/settings.h>

#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/store.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kLang[] = "en";
static const char kType[] = GDEFCORE_SETTING_TYPE;
static const char kNotAllowed[] = "That edit is not allowed.";
/* The environment scope: the tenant byte beside the module host's `0x01` and
 * the installation's `0x02`, and the namespace of the local values in it. */
static const char kEnvTenant[] = "\x03";
static const char kLocalNs[] = "core.setting-local";

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

/* ---- the declarations -------------------------------------------------------- */

static const struct {
  const char * name;
  const char * type;
  const char * default_value;
  const char * label;
  const char * description;
  size_t max_length;
} kBuiltin[GDEFCORE_SETTINGS_BUILTIN] = {
    {GDEFCORE_SETTING_SITE_TITLE, "text", "My site", "Site title",
        "The name of the site, drawn by the site name widget on every page.",
        120},
    {GDEFCORE_SETTING_TAGLINE, "text", "", "Tagline",
        "A short line under the name of the site. Empty shows none.", 200},
};

/* ---- the value rules ---------------------------------------------------------- */

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

typedef struct Dec {
  int neg;
  const char * ip;
  size_t in;
  const char * fp;
  size_t fn;
} Dec;

static int dec_parse(const char * s, size_t n, Dec * d) {
  size_t i = 0;
  size_t start;
  if (!number_ok(s, n)) {
    return 0;
  }
  memset(d, 0, sizeof *d);
  if (s[0] == '-') {
    d->neg = 1;
    i = 1;
  }
  start = i;
  while (i < n && s[i] != '.') {
    i += 1;
  }
  d->ip = s + start;
  d->in = i - start;
  while (d->in > 1 && d->ip[0] == '0') {
    d->ip += 1;
    d->in -= 1;
  }
  if (i < n) {
    d->fp = s + i + 1;
    d->fn = n - i - 1;
    while (d->fn > 0 && d->fp[d->fn - 1] == '0') {
      d->fn -= 1;
    }
  }
  if (d->in == 1 && d->ip[0] == '0' && d->fn == 0) {
    d->neg = 0;
  }
  return 1;
}

static int mag_cmp(const Dec * a, const Dec * b) {
  size_t i;
  size_t m;
  int c;
  if (a->in != b->in) {
    return a->in < b->in ? -1 : 1;
  }
  c = memcmp(a->ip, b->ip, a->in);
  if (c != 0) {
    return c < 0 ? -1 : 1;
  }
  m = a->fn > b->fn ? a->fn : b->fn;
  for (i = 0; i < m; i++) {
    char ca = i < a->fn ? a->fp[i] : '0';
    char cb = i < b->fn ? b->fp[i] : '0';
    if (ca != cb) {
      return ca < cb ? -1 : 1;
    }
  }
  return 0;
}

int gdefcore_settings_decimal_cmp(const char * a, size_t a_len, const char * b,
    size_t b_len) {
  Dec x;
  Dec y;
  int m;
  if (a == NULL || b == NULL || !dec_parse(a, a_len, &x) ||
      !dec_parse(b, b_len, &y)) {
    return 2;
  }
  if (x.neg != y.neg) {
    return x.neg ? -1 : 1;
  }
  m = mag_cmp(&x, &y);
  return x.neg ? -m : m;
}

static int text_ok(const char * s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t extra;
    if (c < 0x20) {
      if (c != '\n' && c != '\t' && c != '\r') {
        return 0;
      }
      i += 1;
      continue;
    }
    if (c == 0x7f) {
      return 0;
    }
    if (c < 0x80) {
      i += 1;
      continue;
    }
    if (c >= 0xc2 && c <= 0xdf) {
      extra = 1;
    } else if (c >= 0xe0 && c <= 0xef) {
      extra = 2;
    } else if (c >= 0xf0 && c <= 0xf4) {
      extra = 3;
    } else {
      return 0;
    }
    if (i + extra >= n) {
      return 0;
    }
    {
      size_t k;
      for (k = 1; k <= extra; k++) {
        if (((unsigned char)s[i + k] & 0xc0) != 0x80) {
          return 0;
        }
      }
      if (c == 0xe0 && (unsigned char)s[i + 1] < 0xa0) {
        return 0;
      }
      if (c == 0xed && (unsigned char)s[i + 1] > 0x9f) {
        return 0;
      }
      if (c == 0xf0 && (unsigned char)s[i + 1] < 0x90) {
        return 0;
      }
      if (c == 0xf4 && (unsigned char)s[i + 1] > 0x8f) {
        return 0;
      }
    }
    i += extra + 1;
  }
  return 1;
}

int gdefcore_settings_check(const char * type, size_t type_len,
    const char * minimum, size_t minimum_len, const char * maximum,
    size_t maximum_len, size_t max_length, const char * value, size_t value_len,
    const char ** why) {
  const char * w = "";
  int ok = 0;
  if (value == NULL && value_len != 0) {
    w = "is not valid text";
  } else if (span_eq(type, type_len, "text", 4)) {
    size_t cap = max_length > 0 ? max_length : GDEFCORE_SETTING_TEXT_MAX;
    if (value_len > cap) {
      w = "is longer than allowed";
    } else if (!text_ok(value == NULL ? "" : value, value_len)) {
      w = "is not valid text";
    } else {
      ok = 1;
    }
  } else if (span_eq(type, type_len, "number", 6)) {
    if (!number_ok(value == NULL ? "" : value, value_len)) {
      w = "must be a number";
    } else if (minimum_len > 0 &&
               gdefcore_settings_decimal_cmp(value, value_len, minimum,
                   minimum_len) < 0) {
      w = "is below the lowest value allowed";
    } else if (maximum_len > 0 &&
               gdefcore_settings_decimal_cmp(value, value_len, maximum,
                   maximum_len) == 1) {
      w = "is above the highest value allowed";
    } else {
      ok = 1;
    }
  } else if (span_eq(type, type_len, "boolean", 7)) {
    if (span_eq(value, value_len, "true", 4) ||
        span_eq(value, value_len, "false", 5)) {
      ok = 1;
    } else {
      w = "must be true or false";
    }
  } else {
    w = "has a type nobody knows";
  }
  if (why != NULL) {
    *why = w;
  }
  return ok;
}

/* Two values of a setting are the same value: numbers by what they say. */
static int value_same(const GDEFCORE_Setting * s, const char * a, size_t an,
    const char * b, size_t bn) {
  if (span_eq(s->type, s->type_len, "number", 6)) {
    return gdefcore_settings_decimal_cmp(a, an, b, bn) == 0;
  }
  return span_eq(a, an, b, bn);
}

static int value_ok(const GDEFCORE_Setting * s, const char * v, size_t n,
    const char ** why) {
  return gdefcore_settings_check(s->type, s->type_len, s->minimum,
      s->minimum_len, s->maximum, s->maximum_len, s->max_length, v, n, why);
}

/* ---- the catalog of settings ---------------------------------------------------- */

static void set_group(GDEFCORE_Setting * s, const char * module, size_t mn,
    const char * group, size_t gn) {
  int n;
  if (gn == 0) {
    group = "general";
    gn = 7;
  }
  n = snprintf(s->group, sizeof s->group, "%.*s.%.*s", (int)mn, module, (int)gn,
      group);
  s->group_len = n > 0 && (size_t)n < sizeof s->group ? (size_t)n : 0;
}

static void defs_free(GDEFCORE_Catalog * catalog, Defs * d) {
  (void)catalog;
  if (d->host != NULL && d->items != NULL) {
    gdefcore_module_declared_free(d->host, d->items);
  }
  free(d->v);
  memset(d, 0, sizeof *d);
}

static GDEFCORE_Result defs_load(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, Defs * d) {
  size_t nmod = 0;
  size_t i;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  memset(d, 0, sizeof *d);
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  d->host = gdefcore_catalog_host(catalog);
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  if (d->host != NULL && tenant != NULL) {
    GDEFCORE_Result rc = gdefcore_module_settings(d->host, tenant, tenant_len,
        projection, &d->items, &nmod);
    if (rc != GDEFCORE_OK) {
      d->items = NULL;
      return rc;
    }
  }
  d->v = (GDEFCORE_Setting *)calloc(GDEFCORE_SETTINGS_BUILTIN + nmod + 1,
      sizeof *d->v);
  if (d->v == NULL) {
    defs_free(catalog, d);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < GDEFCORE_SETTINGS_BUILTIN; i++) {
    GDEFCORE_Setting * s = &d->v[d->n++];
    s->size = sizeof *s;
    s->name = kBuiltin[i].name;
    s->name_len = strlen(kBuiltin[i].name);
    s->module = "core";
    s->module_len = 4;
    s->type = kBuiltin[i].type;
    s->type_len = strlen(kBuiltin[i].type);
    s->default_value = kBuiltin[i].default_value;
    s->default_len = strlen(kBuiltin[i].default_value);
    s->label = kBuiltin[i].label;
    s->label_len = strlen(kBuiltin[i].label);
    s->description = kBuiltin[i].description;
    s->description_len = strlen(kBuiltin[i].description);
    s->minimum = "";
    s->maximum = "";
    s->max_length = kBuiltin[i].max_length;
    s->builtin = 1;
    set_group(s, "core", 4, "site", 4);
  }
  for (i = 0; i < nmod; i++) {
    const GDEFCORE_Module_Declared_Setting * m = d->items[i];
    GDEFCORE_Setting * s = &d->v[d->n++];
    s->size = sizeof *s;
    s->name = m->name;
    s->name_len = m->name_len;
    s->module = m->module;
    s->module_len = m->module_len;
    s->type = m->type;
    s->type_len = m->type_len;
    s->default_value = m->default_value;
    s->default_len = m->default_len;
    s->label = m->label;
    s->label_len = m->label_len;
    s->description = m->description;
    s->description_len = m->description_len;
    s->minimum = m->minimum;
    s->minimum_len = m->minimum_len;
    s->maximum = m->maximum;
    s->maximum_len = m->maximum_len;
    s->max_length = m->max_length;
    s->local = m->environment_local != 0;
    s->secret = m->secret != 0;
    set_group(s, m->module, m->module_len, m->group, m->group_len);
  }
  return GDEFCORE_OK;
}

static const GDEFCORE_Setting * defs_find(const Defs * d, const char * name,
    size_t name_len) {
  size_t i;
  for (i = 0; i < d->n; i++) {
    if (span_eq(d->v[i].name, d->v[i].name_len, name, name_len)) {
      return &d->v[i];
    }
  }
  return NULL;
}

size_t gdefcore_settings_count(GDEFCORE_Catalog * catalog) {
  Defs d;
  size_t n;
  if (defs_load(catalog, NULL, &d) != GDEFCORE_OK) {
    return 0;
  }
  n = d.n;
  defs_free(catalog, &d);
  return n;
}

GDEFCORE_Result gdefcore_settings_at(GDEFCORE_Catalog * catalog, size_t index,
    GDEFCORE_Setting * out) {
  Defs d;
  GDEFCORE_Result rc;
  if (out == NULL || out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (index >= d.n) {
    rc = GDEFCORE_ERR_INVALID;
  } else {
    *out = d.v[index];
  }
  defs_free(catalog, &d);
  return rc;
}

GDEFCORE_Result gdefcore_settings_find(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, GDEFCORE_Setting * out) {
  Defs d;
  const GDEFCORE_Setting * s;
  GDEFCORE_Result rc;
  if (out == NULL || out->size != sizeof *out || name == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  s = defs_find(&d, name, name_len);
  if (s == NULL) {
    rc = GDEFCORE_ERR_INVALID;
  } else {
    *out = *s;
  }
  defs_free(catalog, &d);
  return rc;
}

static int group_has(const GDEFCORE_Settings_Group * g, size_t n, const char * key,
    size_t key_len) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (span_eq(g[i].key, g[i].key_len, key, key_len)) {
      return 1;
    }
  }
  return 0;
}

/* The groups in a total order: the kernel's, then by key. */
static int group_before(const GDEFCORE_Settings_Group * a,
    const GDEFCORE_Settings_Group * b) {
  int ac = strcmp(a->module, "core") == 0;
  int bc = strcmp(b->module, "core") == 0;
  if (ac != bc) {
    return ac;
  }
  return strcmp(a->key, b->key) < 0;
}

static GDEFCORE_Result groups_load(GDEFCORE_Catalog * catalog,
    GDEFCORE_Settings_Group ** out, size_t * n) {
  Defs d;
  GDEFCORE_Settings_Group * g;
  size_t i;
  size_t j;
  GDEFCORE_Result rc = defs_load(catalog, NULL, &d);
  *out = NULL;
  *n = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  g = (GDEFCORE_Settings_Group *)calloc(d.n + 1, sizeof *g);
  if (g == NULL) {
    defs_free(catalog, &d);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < d.n; i++) {
    const GDEFCORE_Setting * s = &d.v[i];
    if (s->group_len == 0) {
      continue;
    }
    if (!group_has(g, *n, s->group, s->group_len)) {
      GDEFCORE_Settings_Group * e = &g[*n];
      const char * dot = strchr(s->group, '.');
      size_t mn = dot == NULL ? 0 : (size_t)(dot - s->group);
      e->size = sizeof *e;
      memcpy(e->key, s->group, s->group_len);
      e->key_len = s->group_len;
      if (mn > 0 && mn <= GDEFCORE_MODULE_DECL_NAME_MAX &&
          s->group_len - mn - 1 <= GDEFCORE_MODULE_DECL_NAME_MAX) {
        memcpy(e->module, s->group, mn);
        memcpy(e->name, dot + 1, s->group_len - mn - 1);
      }
      *n += 1;
    }
    for (j = 0; j < *n; j++) {
      if (span_eq(g[j].key, g[j].key_len, s->group, s->group_len)) {
        g[j].count += 1;
      }
    }
  }
  for (i = 1; i < *n; i++) {
    GDEFCORE_Settings_Group t = g[i];
    j = i;
    while (j > 0 && group_before(&t, &g[j - 1])) {
      g[j] = g[j - 1];
      j -= 1;
    }
    g[j] = t;
  }
  defs_free(catalog, &d);
  *out = g;
  return GDEFCORE_OK;
}

size_t gdefcore_settings_group_count(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Settings_Group * g;
  size_t n;
  if (groups_load(catalog, &g, &n) != GDEFCORE_OK) {
    return 0;
  }
  free(g);
  return n;
}

GDEFCORE_Result gdefcore_settings_group_at(GDEFCORE_Catalog * catalog,
    size_t index, GDEFCORE_Settings_Group * out) {
  GDEFCORE_Settings_Group * g;
  size_t n;
  GDEFCORE_Result rc;
  if (out == NULL || out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = groups_load(catalog, &g, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (index >= n) {
    rc = GDEFCORE_ERR_INVALID;
  } else {
    *out = g[index];
  }
  free(g);
  return rc;
}

/* ---- the stored values ---------------------------------------------------------- */

static GDEFCORE_Result map_stor(GDEFSTOR_Result r) {
  switch (r) {
  case GDEFSTOR_OK:
    return GDEFCORE_OK;
  case GDEFSTOR_ERR_OOM:
    return GDEFCORE_ERR_OOM;
  case GDEFSTOR_ERR_LIMIT:
    return GDEFCORE_ERR_LIMIT;
  case GDEFSTOR_ERR_INVALID:
    return GDEFCORE_ERR_INVALID;
  default:
    return GDEFCORE_ERR_IO;
  }
}

/* One field's first value of an entity, as published. *present 0 when it has
 * none (or the entity is gone). */
static GDEFCORE_Result read_field(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, const char * field,
    char ** out, size_t * out_len, int * present) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, cs, view, id,
      GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, field, strlen(field),
      &texts, &lens, &n);
  *out = NULL;
  *out_len = 0;
  *present = 0;
  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (n > 0) {
    rc = gdefcore_text_dup(catalog, texts[0], lens[0], out);
    if (rc == GDEFCORE_OK) {
      *out_len = lens[0];
      *present = 1;
    }
  }
  gdefcore_values_free(catalog, texts, lens, n);
  return rc;
}

typedef struct Stored {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * name;
  size_t name_len;
} Stored;

static void stored_free(GDEFCORE_Catalog * catalog, Stored * s, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    gdefcore_text_free(catalog, s[i].name);
  }
  free(s);
}

/* Every changed setting, by the name it carries. */
static GDEFCORE_Result stored_all(GDEFCORE_Catalog * catalog, Stored ** out,
    size_t * n_out) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  Stored * s;
  size_t n = 0;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kType, sizeof kType - 1, &ids,
      &count);
  *out = NULL;
  *n_out = 0;
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_INVALID ? GDEFCORE_OK : rc;
  }
  s = (Stored *)calloc(count + 1, sizeof *s);
  if (s == NULL) {
    gdefcore_ids_free(catalog, ids, count);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    int present = 0;
    if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    rc = read_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], "name",
        &s[n].name, &s[n].name_len, &present);
    if (rc == GDEFCORE_OK && present) {
      memcpy(s[n].id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      n += 1;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  if (rc != GDEFCORE_OK) {
    stored_free(catalog, s, n);
    return rc;
  }
  *out = s;
  *n_out = n;
  return GDEFCORE_OK;
}

static const Stored * stored_find(const Stored * s, size_t n, const char * name,
    size_t name_len) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (span_eq(s[i].name, s[i].name_len, name, name_len)) {
      return &s[i];
    }
  }
  return NULL;
}

/* The id of the entity that carries @p name, if any. */
static GDEFCORE_Result stored_id(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, char id[GDEFCORE_PUBLIC_ID_LEN + 1], int * found) {
  Stored * s;
  size_t n;
  const Stored * hit;
  GDEFCORE_Result rc = stored_all(catalog, &s, &n);
  *found = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  hit = stored_find(s, n, name, name_len);
  if (hit != NULL) {
    memcpy(id, hit->id, GDEFCORE_PUBLIC_ID_LEN + 1);
    *found = 1;
  }
  stored_free(catalog, s, n);
  return GDEFCORE_OK;
}

/* ---- the environment-local values ------------------------------------------------- */

static int local_key(GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    char * key, size_t cap) {
  static const char hex[] = "0123456789abcdef";
  size_t tn = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tn);
  size_t i;
  size_t at = 0;
  if (tenant == NULL || tn * 2 + 1 + name_len + 1 > cap) {
    return 0;
  }
  for (i = 0; i < tn; i++) {
    key[at++] = hex[tenant[i] >> 4];
    key[at++] = hex[tenant[i] & 15];
  }
  key[at++] = ':';
  memcpy(key + at, name, name_len);
  at += name_len;
  key[at] = '\0';
  return 1;
}

/* *found 0 when the environment has no value for the setting. */
static GDEFCORE_Result local_get(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, char ** out, size_t * out_len, int * found) {
  char key[GDEFSTOR_RECORD_MAX_KEY_BYTES + 1];
  uint8_t * bytes = NULL;
  size_t len = 0;
  int got = 0;
  GDEFCORE_Result rc;
  *out = NULL;
  *out_len = 0;
  *found = 0;
  if (!local_key(catalog, name, name_len, key, sizeof key)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = map_stor(gdefstor_record_get(gdefcore_catalog_store(catalog), kEnvTenant, 1,
      kLocalNs, sizeof kLocalNs - 1, key, strlen(key), &got, &bytes, &len, NULL,
      NULL));
  if (rc == GDEFCORE_OK && got) {
    rc = gdefcore_text_dup(catalog, (const char *)bytes, len, out);
    if (rc == GDEFCORE_OK) {
      *out_len = len;
      *found = 1;
    }
  }
  gdefstor_bytes_free(NULL, bytes);
  return rc;
}

/* Put (value non-NULL) or delete (NULL) the environment's value. */
static GDEFCORE_Result local_put(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, const char * value, size_t value_len) {
  char key[GDEFSTOR_RECORD_MAX_KEY_BYTES + 1];
  GDEFSTOR_Write * write = NULL;
  GDEFCORE_Result rc;
  if (!local_key(catalog, name, name_len, key, sizeof key)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = map_stor(gdefstor_write_begin(gdefcore_catalog_store(catalog), kEnvTenant,
      1, NULL, &write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (value != NULL) {
    rc = map_stor(gdefstor_record_put(write, kLocalNs, sizeof kLocalNs - 1, key,
        strlen(key), GDEFCORE_SCHEMA_CORE_STAMP,
        sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, (const uint8_t *)value,
        value_len));
  } else {
    rc = map_stor(gdefstor_record_delete(write, kLocalNs, sizeof kLocalNs - 1, key,
        strlen(key), NULL));
  }
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(write);
    return rc;
  }
  return map_stor(gdefstor_write_commit(write));
}

/* ---- reading a value ------------------------------------------------------------ */

static GDEFCORE_Result value_of(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Setting * s, char ** out, size_t * out_len, int * source) {
  GDEFCORE_Result rc;
  int found = 0;
  *out = NULL;
  *out_len = 0;
  if (s->local) {
    rc = local_get(catalog, s->name, s->name_len, out, out_len, &found);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (found) {
      *source = GDEFCORE_SETTING_FROM_LOCAL;
      return GDEFCORE_OK;
    }
  } else {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    int present = 0;
    rc = stored_id(catalog, s->name, s->name_len, id, &found);
    if (rc == GDEFCORE_OK && found) {
      rc = read_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "value", out,
          out_len, &present);
      if (rc == GDEFCORE_OK && present) {
        *source = GDEFCORE_SETTING_FROM_SITE;
        return GDEFCORE_OK;
      }
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  *source = GDEFCORE_SETTING_FROM_DEFAULT;
  rc = gdefcore_text_dup(catalog, s->default_value, s->default_len, out);
  if (rc == GDEFCORE_OK) {
    *out_len = s->default_len;
  }
  return rc;
}

GDEFCORE_Result gdefcore_settings_get(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, char ** out, size_t * out_len, int * out_source) {
  Defs d;
  const GDEFCORE_Setting * s;
  int source = 0;
  GDEFCORE_Result rc;
  if (out == NULL || out_len == NULL || name == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out = NULL;
  *out_len = 0;
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  s = defs_find(&d, name, name_len);
  if (s == NULL) {
    rc = GDEFCORE_ERR_INVALID;
  } else {
    rc = value_of(catalog, s, out, out_len, &source);
    if (rc == GDEFCORE_OK && out_source != NULL) {
      *out_source = source;
    }
  }
  defs_free(catalog, &d);
  return rc;
}

int gdefcore_settings_is_set(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len) {
  char * v = NULL;
  size_t n = 0;
  int source = 0;
  if (gdefcore_settings_get(catalog, name, name_len, &v, &n, &source) !=
      GDEFCORE_OK) {
    return 0;
  }
  gdefcore_text_free(catalog, v);
  return source != GDEFCORE_SETTING_FROM_DEFAULT;
}

/* ---- the type and the permission ---------------------------------------------------- */

static void field_set(GDEFCORE_Field * field, const char * name, int required) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = required;
  field->many = !required;
}

GDEFCORE_Result gdefcore_settings_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field f[4];
  GDEFCORE_Permission perm;
  int kind = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  field_set(&f[0], "name", 1);
  field_set(&f[1], "group", 1);
  field_set(&f[2], "value", 0);
  field_set(&f[3], "serial", 0);
  if (gdefcore_type_kind(catalog, kType, sizeof kType - 1, &kind) !=
      GDEFCORE_OK) {
    rc = gdefcore_type_define(catalog, kType, sizeof kType - 1,
        GDEFCORE_TYPE_CONFIG, f, 4);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&perm, 0, sizeof perm);
  perm.size = sizeof perm;
  perm.label = GDEFCORE_SETTINGS_EDIT_LABEL;
  perm.label_len = sizeof GDEFCORE_SETTINGS_EDIT_LABEL - 1;
  perm.module_name = "core";
  perm.module_name_len = 4;
  perm.action = GDEFCORE_SETTINGS_EDIT;
  perm.action_len = sizeof GDEFCORE_SETTINGS_EDIT - 1;
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = kType;
  perm.type_name_len = sizeof kType - 1;
  return gdefcore_access_declare(catalog, &perm);
}

int gdefcore_settings_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request) {
  if (catalog == NULL || request == NULL) {
    return 0;
  }
  return gdefcore_access_permits(catalog, request, GDEFCORE_SETTINGS_EDIT,
      sizeof GDEFCORE_SETTINGS_EDIT - 1) != 0;
}

/* ---- staging --------------------------------------------------------------------------- */

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

/* Save a setting's entity: a value for a changed one, a serial for the marker
 * of a local one. */
static GDEFCORE_Result save_entity(GDEFCORE_Changeset * cs, const char * id,
    const GDEFCORE_Setting * s, const char * value, size_t value_len,
    const char * serial, size_t serial_len) {
  GDEFCORE_Value v[4];
  const char * slot[4];
  size_t len[4];
  value_set(&v[0], "name", &slot[0], &len[0], s->name, s->name_len, 1);
  value_set(&v[1], "group", &slot[1], &len[1], s->group, s->group_len, 1);
  value_set(&v[2], "value", &slot[2], &len[2], value, value_len, value != NULL);
  value_set(&v[3], "serial", &slot[3], &len[3], serial, serial_len,
      serial != NULL);
  return gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      sizeof kLang - 1, v, 4);
}

static GDEFCORE_Result id_for(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, char id[GDEFCORE_PUBLIC_ID_LEN + 1], int * existed) {
  GDEFCORE_Result rc = stored_id(catalog, name, name_len, id, existed);
  if (rc == GDEFCORE_OK && !*existed) {
    rc = gdefcore_entity_create(catalog, kType, sizeof kType - 1, id, NULL);
  }
  return rc;
}

static GDEFCORE_Result stage_def(GDEFCORE_Changeset * cs, const GDEFCORE_Setting * s,
    const char * value, size_t value_len, int * out_changed) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(cs);
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int existed = 0;
  int changed = 0;
  GDEFCORE_Result rc;
  if (out_changed != NULL) {
    *out_changed = 0;
  }
  if (value_same(s, value, value_len, s->default_value, s->default_len)) {
    /* The default is stored as nothing. */
    rc = stored_id(catalog, s->name, s->name_len, id, &existed);
    if (rc == GDEFCORE_OK && existed) {
      rc = gdefcore_entity_clear(cs, id, GDEFCORE_PUBLIC_ID_LEN);
      changed = rc == GDEFCORE_OK;
    }
  } else {
    char * cur = NULL;
    size_t cur_len = 0;
    int present = 0;
    rc = stored_id(catalog, s->name, s->name_len, id, &existed);
    if (rc == GDEFCORE_OK && existed) {
      rc = read_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "value", &cur,
          &cur_len, &present);
    }
    if (rc == GDEFCORE_OK && existed && present &&
        value_same(s, cur, cur_len, value, value_len)) {
      /* As stored: nothing to write. */
    } else if (rc == GDEFCORE_OK) {
      if (!existed) {
        rc = gdefcore_entity_create(catalog, kType, sizeof kType - 1, id, NULL);
      }
      if (rc == GDEFCORE_OK) {
        rc = save_entity(cs, id, s, value, value_len, NULL, 0);
        changed = rc == GDEFCORE_OK;
      }
    }
    gdefcore_text_free(catalog, cur);
  }
  if (rc == GDEFCORE_OK && out_changed != NULL) {
    *out_changed = changed;
  }
  return rc;
}

GDEFCORE_Result gdefcore_settings_stage(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const char * value, size_t value_len,
    int * out_changed) {
  GDEFCORE_Catalog * catalog;
  Defs d;
  const GDEFCORE_Setting * s;
  GDEFCORE_Result rc;
  if (changeset == NULL || name == NULL || (value == NULL && value_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  s = defs_find(&d, name, name_len);
  if (s == NULL || s->local || !value_ok(s, value == NULL ? "" : value, value_len,
                                    NULL)) {
    rc = GDEFCORE_ERR_INVALID;
  } else {
    rc = stage_def(changeset, s, value == NULL ? "" : value, value_len,
        out_changed);
  }
  defs_free(catalog, &d);
  return rc;
}

/* ---- the group's version ---------------------------------------------------------------- */

GDEFCORE_Result gdefcore_settings_group_version(GDEFCORE_Catalog * catalog,
    const char * group, size_t group_len, char out[17]) {
  Defs d;
  Stored * st = NULL;
  size_t nst = 0;
  size_t i;
  uint64_t h = 1469598103934665603ull;
  GDEFCORE_Result rc;
  if (out == NULL || group == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = stored_all(catalog, &st, &nst);
  for (i = 0; rc == GDEFCORE_OK && i < d.n; i++) {
    const GDEFCORE_Setting * s = &d.v[i];
    const Stored * hit;
    uint64_t ver = 0;
    size_t k;
    int env = 0;
    if (!span_eq(s->group, s->group_len, group, group_len)) {
      continue;
    }
    hit = stored_find(st, nst, s->name, s->name_len);
    if (hit != NULL) {
      rc = gdefcore_entity_version(catalog, hit->id, GDEFCORE_PUBLIC_ID_LEN, &ver);
    }
    if (rc == GDEFCORE_OK && s->local) {
      char * v = NULL;
      size_t vn = 0;
      int found = 0;
      rc = local_get(catalog, s->name, s->name_len, &v, &vn, &found);
      gdefcore_text_free(catalog, v);
      env = found;
    }
    for (k = 0; k < s->name_len; k++) {
      h = (h ^ (unsigned char)s->name[k]) * 1099511628211ull;
    }
    for (k = 0; k < 8; k++) {
      h = (h ^ (unsigned char)(ver >> (8 * k))) * 1099511628211ull;
    }
    h = (h ^ (unsigned)env) * 1099511628211ull;
  }
  stored_free(catalog, st, nst);
  defs_free(catalog, &d);
  if (rc == GDEFCORE_OK) {
    /* Letters only, so that a page carrying it holds no run of digits that a
     * scanner for leaked row numbers would take for one. */
    for (i = 0; i < 16; i++) {
      out[i] = (char)('a' + (int)((h >> (4 * i)) & 15u));
    }
    out[16] = '\0';
  }
  return rc;
}

/* ---- saving a form ------------------------------------------------------------------------- */

typedef struct Pending {
  size_t def;          /* index into the defs */
  char * value;        /* the new value, or NULL to delete */
  size_t value_len;
  char * old;          /* what the environment held */
  size_t old_len;
  int had_old;
  int done;
} Pending;

static GDEFCORE_Result say(GDEFCORE_Catalog * catalog, char ** out, size_t * out_len,
    const char * a, const char * b, size_t bn, const char * c) {
  char buf[600];
  int n;
  if (out == NULL) {
    return GDEFCORE_OK;
  }
  n = snprintf(buf, sizeof buf, "%s%.*s%s", a, (int)(bn > 200 ? 200 : bn), b, c);
  if (n <= 0 || (size_t)n >= sizeof buf) {
    n = (int)(sizeof buf - 1);
  }
  if (gdefcore_text_dup(catalog, buf, (size_t)n, out) != GDEFCORE_OK) {
    *out = NULL;
    return GDEFCORE_ERR_OOM;
  }
  if (out_len != NULL) {
    *out_len = (size_t)n;
  }
  return GDEFCORE_OK;
}

static void pending_free(GDEFCORE_Catalog * catalog, Pending * p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    free(p[i].value);
    gdefcore_text_free(catalog, p[i].old);
  }
  free(p);
}

/* A local setting's change: the marker (a serial that moves, so the change is
 * revisioned, authorized and moves the epoch) and the value to put or take. */
static GDEFCORE_Result stage_local(GDEFCORE_Changeset * cs,
    const GDEFCORE_Setting * s, size_t def, const char * value, size_t value_len,
    Pending * pending, size_t * npending, int * out_changed) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(cs);
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * cur = NULL;
  size_t cur_len = 0;
  int have = 0;
  int existed = 0;
  int to_default = value_same(s, value, value_len, s->default_value,
      s->default_len);
  GDEFCORE_Result rc = local_get(catalog, s->name, s->name_len, &cur, &cur_len,
      &have);
  *out_changed = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!to_default && have && span_eq(cur, cur_len, value, value_len)) {
    gdefcore_text_free(catalog, cur);
    return GDEFCORE_OK;
  }
  rc = stored_id(catalog, s->name, s->name_len, id, &existed);
  if (rc == GDEFCORE_OK && to_default) {
    if (!have && !existed) {
      gdefcore_text_free(catalog, cur);
      return GDEFCORE_OK;
    }
    if (existed) {
      rc = gdefcore_entity_clear(cs, id, GDEFCORE_PUBLIC_ID_LEN);
    }
  } else if (rc == GDEFCORE_OK) {
    char serial[24];
    char * old_serial = NULL;
    size_t old_serial_len = 0;
    int present = 0;
    unsigned long long next = 1;
    if (existed) {
      rc = read_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "serial",
          &old_serial, &old_serial_len, &present);
      if (rc == GDEFCORE_OK && present && old_serial_len > 0 &&
          old_serial_len < 19) {
        next = strtoull(old_serial, NULL, 10) + 1;
      }
      gdefcore_text_free(catalog, old_serial);
    } else {
      rc = gdefcore_entity_create(catalog, kType, sizeof kType - 1, id, NULL);
    }
    if (rc == GDEFCORE_OK) {
      snprintf(serial, sizeof serial, "%llu", next);
      rc = save_entity(cs, id, s, NULL, 0, serial, strlen(serial));
    }
  }
  if (rc == GDEFCORE_OK) {
    Pending * p = &pending[*npending];
    memset(p, 0, sizeof *p);
    p->def = def;
    if (!to_default) {
      p->value = (char *)malloc(value_len + 1);
      if (p->value == NULL) {
        rc = GDEFCORE_ERR_OOM;
      } else {
        memcpy(p->value, value, value_len);
        p->value[value_len] = '\0';
        p->value_len = value_len;
      }
    }
    if (rc == GDEFCORE_OK) {
      p->old = cur;
      p->old_len = cur_len;
      p->had_old = have;
      cur = NULL;
      *npending += 1;
      *out_changed = 1;
    }
  }
  gdefcore_text_free(catalog, cur);
  return rc;
}

GDEFCORE_Result gdefcore_settings_save(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * group, size_t group_len,
    const char * expected_version, const GDEFCORE_Setting_Change * changes,
    size_t count, size_t * out_written, char ** out_message,
    size_t * out_message_len) {
  Defs d;
  const GDEFCORE_Setting * defs[GDEFCORE_SETTINGS_SAVE_MAX];
  size_t def_at[GDEFCORE_SETTINGS_SAVE_MAX];
  Pending * pending = NULL;
  size_t npending = 0;
  GDEFCORE_Changeset * cs = NULL;
  size_t written = 0;
  size_t i;
  size_t who_n = 0;
  const char * who;
  GDEFCORE_Result rc;
  if (out_written != NULL) {
    *out_written = 0;
  }
  if (out_message != NULL) {
    *out_message = NULL;
  }
  if (out_message_len != NULL) {
    *out_message_len = 0;
  }
  if (catalog == NULL || request == NULL || (changes == NULL && count != 0) ||
      count > GDEFCORE_SETTINGS_SAVE_MAX) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* Everything is checked before anything is written. */
  for (i = 0; i < count; i++) {
    const GDEFCORE_Setting * s;
    const char * why = "";
    size_t k;
    if (changes[i].size != sizeof changes[i] || changes[i].name == NULL ||
        (changes[i].value == NULL && changes[i].value_len != 0)) {
      defs_free(catalog, &d);
      return GDEFCORE_ERR_INVALID;
    }
    s = defs_find(&d, changes[i].name, changes[i].name_len);
    if (s == NULL || (group != NULL && !span_eq(s->group, s->group_len, group,
                                           group_len))) {
      (void)say(catalog, out_message, out_message_len,
          "This form has no setting called ", changes[i].name,
          changes[i].name_len, ".");
      defs_free(catalog, &d);
      return GDEFCORE_ERR_INVALID;
    }
    for (k = 0; k < i; k++) {
      if (defs[k] == s) {
        (void)say(catalog, out_message, out_message_len,
            "The same setting is changed twice: ", s->name, s->name_len, ".");
        defs_free(catalog, &d);
        return GDEFCORE_ERR_INVALID;
      }
    }
    if (!value_ok(s, changes[i].value == NULL ? "" : changes[i].value,
            changes[i].value_len, &why)) {
      char tail[160];
      snprintf(tail, sizeof tail, " %s. Nothing was saved.", why);
      (void)say(catalog, out_message, out_message_len, "", s->label, s->label_len,
          tail);
      defs_free(catalog, &d);
      return GDEFCORE_ERR_INVALID;
    }
    defs[i] = s;
    def_at[i] = (size_t)(s - d.v);
  }
  if (expected_version != NULL && group != NULL) {
    char now[17];
    rc = gdefcore_settings_group_version(catalog, group, group_len, now);
    if (rc != GDEFCORE_OK) {
      defs_free(catalog, &d);
      return rc;
    }
    if (strcmp(now, expected_version) != 0) {
      (void)say(catalog, out_message, out_message_len,
          "These settings changed since the form was drawn. Nothing was saved. "
          "Reload the page and make the change again.",
          "", 0, "");
      defs_free(catalog, &d);
      return GDEFCORE_ERR_STALE;
    }
  }
  who = gdefcore_request_principal(request, &who_n);
  rc = gdefcore_changeset_prepare(catalog, who, who_n, &cs);
  if (rc != GDEFCORE_OK) {
    defs_free(catalog, &d);
    return rc;
  }
  pending = (Pending *)calloc(count + 1, sizeof *pending);
  if (pending == NULL) {
    gdefcore_changeset_destroy(cs);
    defs_free(catalog, &d);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    int changed = 0;
    const char * v = changes[i].value == NULL ? "" : changes[i].value;
    if (defs[i]->local) {
      rc = stage_local(cs, defs[i], def_at[i], v, changes[i].value_len, pending,
          &npending, &changed);
    } else {
      rc = stage_def(cs, defs[i], v, changes[i].value_len, &changed);
    }
    written += changed ? 1 : 0;
  }
  if (rc == GDEFCORE_OK && written == 0) {
    /* As it was: no changeset, so the epoch stays where it is. */
    goto done;
  }
  if (rc == GDEFCORE_OK) {
    gdefcore_changeset_set_request(cs, request);
    /* Who may make every one of these is asked before a local value is
     * written, so that a refusal leaves the environment as it was. Apply asks
     * again for the entities. */
    rc = gdefcore_settings_authorize(cs, request);
  }
  for (i = 0; rc == GDEFCORE_OK && i < npending; i++) {
    const GDEFCORE_Setting * s = &d.v[pending[i].def];
    rc = local_put(catalog, s->name, s->name_len, pending[i].value,
        pending[i].value_len);
    pending[i].done = rc == GDEFCORE_OK;
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(cs, kType, sizeof kType - 1);
  }
  if (rc != GDEFCORE_OK) {
    size_t k;
    for (k = 0; k < npending; k++) {
      if (pending[k].done) {
        const GDEFCORE_Setting * s = &d.v[pending[k].def];
        (void)local_put(catalog, s->name, s->name_len,
            pending[k].had_old ? pending[k].old : NULL, pending[k].old_len);
      }
    }
    if (out_message != NULL && *out_message == NULL) {
      size_t rn = 0;
      const char * why = gdefcore_changeset_refusal(cs, &rn);
      if (why != NULL && rn > 0) {
        (void)say(catalog, out_message, out_message_len, "", why, rn, "");
      } else {
        (void)say(catalog, out_message, out_message_len, kNotAllowed, "", 0, "");
      }
    }
    if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_OOM && rc != GDEFCORE_ERR_STALE) {
      rc = GDEFCORE_ERR_INVALID;
    }
  }
done:
  pending_free(catalog, pending, count + 1 > 0 ? count + 1 : 0);
  gdefcore_changeset_destroy(cs);
  defs_free(catalog, &d);
  if (rc == GDEFCORE_OK && out_written != NULL) {
    *out_written = written;
  }
  return rc;
}

/* ---- who may edit ------------------------------------------------------------------------------ */

enum { kShapeFields = 2 };
static const char * const kShapeName[kShapeFields] = {"name", "group"};

typedef struct Shape {
  char * text[kShapeFields];
  size_t len[kShapeFields];
} Shape;

static void shape_free(GDEFCORE_Catalog * catalog, Shape * shape) {
  size_t i;
  for (i = 0; i < kShapeFields; i++) {
    gdefcore_text_free(catalog, shape->text[i]);
    shape->text[i] = NULL;
    shape->len[i] = 0;
  }
}

static GDEFCORE_Result shape_load(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, Shape * shape) {
  size_t i;
  memset(shape, 0, sizeof *shape);
  for (i = 0; i < kShapeFields; i++) {
    int present = 0;
    GDEFCORE_Result rc = read_field(catalog, cs, view, id, kShapeName[i],
        &shape->text[i], &shape->len[i], &present);
    if (rc != GDEFCORE_OK) {
      shape_free(catalog, shape);
      return rc;
    }
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result decide_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, const Shape * shape,
    int * allowed) {
  GDEFCORE_Condition_Value values[kShapeFields];
  size_t revisions = 0;
  int ok = 0;
  size_t i;
  GDEFCORE_Result rc;
  *allowed = 0;
  if (shape->len[0] == 0) {
    return GDEFCORE_OK;
  }
  for (i = 0; i < kShapeFields; i++) {
    memset(&values[i], 0, sizeof values[i]);
    values[i].size = sizeof values[i];
    values[i].field = kShapeName[i];
    values[i].field_len = strlen(kShapeName[i]);
    values[i].text = shape->text[i] == NULL ? "" : shape->text[i];
    values[i].text_len = shape->len[i];
  }
  rc = gdefcore_access_can_with(catalog, request, GDEFCORE_SETTINGS_EDIT,
      sizeof GDEFCORE_SETTINGS_EDIT - 1, kType, sizeof kType - 1, id, values,
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
    rc = gdefcore_access_can(catalog, request, GDEFCORE_SETTINGS_EDIT,
        sizeof GDEFCORE_SETTINGS_EDIT - 1, kType, sizeof kType - 1, id, &ok);
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

GDEFCORE_Result gdefcore_settings_authorize(GDEFCORE_Changeset * changeset,
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
    int view;
    int allowed = 0;
    GDEFCORE_Result rc;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL || !span_eq(type, type_len, kType, sizeof kType - 1)) {
      continue;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      return refuse_edit(changeset, GDEFCORE_ERR_INVALID);
    }
    through = op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_PUBLISH
                  ? NULL
                  : changeset;
    view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                         : GDEFCORE_VIEW_CURRENT;
    rc = shape_load(catalog, through, view, canon, &shape);
    if (rc != GDEFCORE_OK) {
      return refuse_edit(changeset, rc);
    }
    rc = decide_edit(catalog, request, canon, &shape, &allowed);
    shape_free(catalog, &shape);
    if (rc != GDEFCORE_OK) {
      return refuse_edit(changeset, rc);
    }
    if (!allowed) {
      return refuse_edit(changeset, GDEFCORE_ERR_INVALID);
    }
  }
  return GDEFCORE_OK;
}

/* ---- vetting what is written ----------------------------------------------------------------------- */

static GDEFCORE_Result refuse(GDEFCORE_Changeset * cs, const char * a,
    const char * b, size_t bn, const char * c) {
  char buf[400];
  int n = snprintf(buf, sizeof buf, "%s%.*s%s", a, (int)(bn > 120 ? 120 : bn), b,
      c);
  if (n > 0 && (size_t)n < sizeof buf) {
    (void)gdefcore_changeset_set_refusal(cs, buf, (size_t)n);
  }
  return GDEFCORE_ERR_INVALID;
}

GDEFCORE_Result gdefcore_settings_vet(GDEFCORE_Changeset * changeset) {
  GDEFCORE_Catalog * catalog;
  size_t touched;
  size_t i;
  Defs d;
  int loaded = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  touched = gdefcore_changeset_touched_count(changeset);
  memset(&d, 0, sizeof d);
  for (i = 0; rc == GDEFCORE_OK && i < touched; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * name = NULL;
    char * group = NULL;
    char * value = NULL;
    char * serial = NULL;
    size_t nn = 0;
    size_t gn = 0;
    size_t vn = 0;
    size_t sn = 0;
    int pn = 0;
    int pg = 0;
    int pv = 0;
    int ps = 0;
    const GDEFCORE_Setting * s;
    const char * why = "";
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        type == NULL || !span_eq(type, type_len, kType, sizeof kType - 1) ||
        op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_UNPUBLISH) {
      continue;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      return refuse(changeset, "A setting is written under an id that is not one.",
          "", 0, "");
    }
    if (!loaded) {
      rc = defs_load(catalog, changeset, &d);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
      loaded = 1;
    }
    {
      int view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                               : GDEFCORE_VIEW_CURRENT;
      const GDEFCORE_Changeset * through =
          op == GDEFCORE_TOUCH_PUBLISH ? NULL : changeset;
      rc = read_field(catalog, through, view, canon, "name", &name, &nn, &pn);
      if (rc == GDEFCORE_OK) {
        rc = read_field(catalog, through, view, canon, "group", &group, &gn, &pg);
      }
      if (rc == GDEFCORE_OK) {
        rc = read_field(catalog, through, view, canon, "value", &value, &vn, &pv);
      }
      if (rc == GDEFCORE_OK) {
        rc = read_field(catalog, through, view, canon, "serial", &serial, &sn, &ps);
      }
    }
    if (rc == GDEFCORE_OK) {
      s = pn ? defs_find(&d, name, nn) : NULL;
      if (s == NULL) {
        rc = refuse(changeset, "No module declares the setting ", pn ? name : "",
            nn, ".");
      } else if (!pg || !span_eq(group, gn, s->group, s->group_len)) {
        rc = refuse(changeset, "The setting ", name, nn,
            " is written in a group that is not its own.");
      } else if (s->local && pv) {
        rc = refuse(changeset, "The setting ", name, nn,
            " is environment-local; its value is never written to the site.");
      } else if (!s->local && ps) {
        rc = refuse(changeset, "The setting ", name, nn,
            " is not environment-local and has no serial.");
      } else if (!s->local && !pv) {
        rc = refuse(changeset, "The setting ", name, nn, " has no value.");
      } else if (!s->local && !value_ok(s, value, vn, &why)) {
        char tail[160];
        snprintf(tail, sizeof tail, " %s.", why);
        rc = refuse(changeset, "", s->label, s->label_len, tail);
      }
    }
    gdefcore_text_free(catalog, name);
    gdefcore_text_free(catalog, group);
    gdefcore_text_free(catalog, value);
    gdefcore_text_free(catalog, serial);
  }
  if (loaded) {
    defs_free(catalog, &d);
  }
  return rc;
}

/* ---- the generated form --------------------------------------------------------------------------------- */

typedef struct Buf {
  char * p;
  size_t n;
  size_t cap;
  int bad;
} Buf;

static void buf_add(Buf * b, const char * s, size_t n) {
  if (b->bad) {
    return;
  }
  if (b->n + n + 1 > b->cap) {
    size_t cap = b->cap == 0 ? 1024 : b->cap;
    char * p;
    while (cap < b->n + n + 1) {
      cap *= 2;
    }
    p = (char *)realloc(b->p, cap);
    if (p == NULL) {
      b->bad = 1;
      return;
    }
    b->p = p;
    b->cap = cap;
  }
  memcpy(b->p + b->n, s, n);
  b->n += n;
  b->p[b->n] = '\0';
}

static void buf_str(Buf * b, const char * s) {
  buf_add(b, s, strlen(s));
}

static void buf_esc_with(Buf * b, const char * s, size_t n, int digits) {
  size_t i;
  for (i = 0; i < n; i++) {
    switch (s[i]) {
    case '&':
      buf_str(b, "&amp;");
      break;
    case '<':
      buf_str(b, "&lt;");
      break;
    case '>':
      buf_str(b, "&gt;");
      break;
    case '"':
      buf_str(b, "&quot;");
      break;
    case '\'':
      buf_str(b, "&#39;");
      break;
    default:
      if (digits && s[i] >= '0' && s[i] <= '9') {
        /* A digit is written as the character reference of itself: it shows
         * and posts the same, and a page scanner for leaked row numbers does
         * not read a number in text as one. */
        char ref[8];
        snprintf(ref, sizeof ref, "&#%d;", 48 + (s[i] - '0'));
        buf_str(b, ref);
      } else {
        buf_add(b, s + i, 1);
      }
    }
  }
}

/* Escaped, digits as character references (see above). */
static void buf_esc(Buf * b, const char * s, size_t n) {
  buf_esc_with(b, s, n, 1);
}

/* Escaped, digits as they are: a token and an address. */
static void buf_esc_plain(Buf * b, const char * s, size_t n) {
  buf_esc_with(b, s, n, 0);
}

static void field_html(Buf * b, GDEFCORE_Catalog * catalog,
    const GDEFCORE_Setting * s, size_t index, int editable) {
  char * v = NULL;
  size_t vn = 0;
  int source = 0;
  char idbuf[40];
  const char * dis = editable ? "" : " disabled";
  int is_text = span_eq(s->type, s->type_len, "text", 4);
  int is_bool = span_eq(s->type, s->type_len, "boolean", 7);
  idbuf[0] = '\0';
  snprintf(idbuf, sizeof idbuf, "setting-%c%c", (char)('a' + (int)(index / 26 % 26)),
      (char)('a' + (int)(index % 26)));
  if (value_of(catalog, s, &v, &vn, &source) != GDEFCORE_OK) {
    b->bad = 1;
    return;
  }
  buf_str(b, "<div class=\"setting\"><label for=\"");
  buf_str(b, idbuf);
  buf_str(b, "\">");
  buf_esc(b, s->label, s->label_len);
  buf_str(b, "</label> ");
  if (is_bool) {
    int on = span_eq(v, vn, "true", 4);
    buf_str(b, "<select id=\"");
    buf_str(b, idbuf);
    buf_str(b, "\" name=\"s.");
    buf_esc(b, s->name, s->name_len);
    buf_str(b, "\"");
    buf_str(b, dis);
    buf_str(b, "><option value=\"true\"");
    buf_str(b, on ? " selected" : "");
    buf_str(b, ">Yes</option><option value=\"false\"");
    buf_str(b, on ? "" : " selected");
    buf_str(b, ">No</option></select>");
  } else if (s->secret) {
    buf_str(b, "<input type=\"password\" autocomplete=\"new-password\" id=\"");
    buf_str(b, idbuf);
    buf_str(b, "\" name=\"s.");
    buf_esc(b, s->name, s->name_len);
    buf_str(b, "\" value=\"\"");
    buf_str(b, dis);
    buf_str(b, "> <span class=\"state\">");
    buf_str(b, source == GDEFCORE_SETTING_FROM_DEFAULT ? "Not set" : "Set");
    buf_str(b, "</span> <label><input type=\"checkbox\" name=\"c.");
    buf_esc(b, s->name, s->name_len);
    buf_str(b, "\" value=\"clear\"");
    buf_str(b, dis);
    buf_str(b, "> Clear</label>");
  } else if (is_text && (s->max_length == 0 || s->max_length > 200)) {
    buf_str(b, "<textarea id=\"");
    buf_str(b, idbuf);
    buf_str(b, "\" name=\"s.");
    buf_esc(b, s->name, s->name_len);
    buf_str(b, "\"");
    buf_str(b, dis);
    buf_str(b, ">");
    buf_esc(b, v, vn);
    buf_str(b, "</textarea>");
  } else {
    buf_str(b, "<input type=\"text\"");
    if (!is_text) {
      buf_str(b, " inputmode=\"decimal\"");
    }
    buf_str(b, " id=\"");
    buf_str(b, idbuf);
    buf_str(b, "\" name=\"s.");
    buf_esc(b, s->name, s->name_len);
    buf_str(b, "\" value=\"");
    buf_esc(b, v, vn);
    buf_str(b, "\"");
    buf_str(b, dis);
    buf_str(b, ">");
  }
  if (s->description_len > 0) {
    buf_str(b, " <span class=\"hint\">");
    buf_esc(b, s->description, s->description_len);
    buf_str(b, "</span>");
  }
  if (!is_text && !is_bool && (s->minimum_len > 0 || s->maximum_len > 0)) {
    buf_str(b, " <span class=\"bounds\">");
    if (s->minimum_len > 0) {
      buf_str(b, "From ");
      buf_esc(b, s->minimum, s->minimum_len);
      buf_str(b, ". ");
    }
    if (s->maximum_len > 0) {
      buf_str(b, "Up to ");
      buf_esc(b, s->maximum, s->maximum_len);
      buf_str(b, ".");
    }
    buf_str(b, "</span>");
  }
  if (s->local) {
    buf_str(b, " <span class=\"local\">This site only: it is never exported or "
               "imported.</span>");
  }
  buf_str(b, "</div>");
  gdefcore_text_free(catalog, v);
}

GDEFCORE_Result gdefcore_settings_form_html(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * group, size_t group_len,
    const char * action, const char * token, char ** out, size_t * out_len) {
  Defs d;
  Buf b;
  char version[17];
  size_t i;
  size_t shown = 0;
  int editable;
  GDEFCORE_Result rc;
  if (out == NULL || out_len == NULL || group == NULL || action == NULL ||
      token == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out = NULL;
  *out_len = 0;
  if (!gdefcore_settings_may_edit(catalog, request)) {
    return GDEFCORE_ERR_INVALID;
  }
  editable = 1;
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_settings_group_version(catalog, group, group_len, version);
  memset(&b, 0, sizeof b);
  if (rc == GDEFCORE_OK) {
    buf_str(&b, "<form method=\"post\" class=\"settings-form\" action=\"");
    buf_esc_plain(&b, action, strlen(action));
    buf_str(&b, "\"><input type=\"hidden\" name=\"token\" value=\"");
    buf_esc_plain(&b, token, strlen(token));
    buf_str(&b, "\"><input type=\"hidden\" name=\"version\" value=\"");
    buf_str(&b, version);
    buf_str(&b, "\">");
    for (i = 0; i < d.n; i++) {
      if (span_eq(d.v[i].group, d.v[i].group_len, group, group_len)) {
        field_html(&b, catalog, &d.v[i], i, editable);
        shown += 1;
      }
    }
    buf_str(&b, "<button type=\"submit\">Save</button></form>");
  }
  defs_free(catalog, &d);
  if (rc != GDEFCORE_OK || b.bad || shown == 0) {
    free(b.p);
    return rc != GDEFCORE_OK ? rc
                             : (b.bad ? GDEFCORE_ERR_OOM : GDEFCORE_ERR_INVALID);
  }
  rc = gdefcore_text_dup(catalog, b.p, b.n, out);
  if (rc == GDEFCORE_OK) {
    *out_len = b.n;
  }
  free(b.p);
  return rc;
}

/* ---- the configuration export and import ---------------------------------------------------------------------- */

GDEFCORE_Result gdefcore_settings_export(GDEFCORE_Catalog * catalog,
    GDEFCORE_Patch ** out_files, size_t * out_count) {
  Defs d;
  Stored * st = NULL;
  size_t nst = 0;
  GDEFCORE_Changeset * cs = NULL;
  size_t i;
  GDEFCORE_Result rc;
  if (out_files == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_files = NULL;
  *out_count = 0;
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = stored_all(catalog, &st, &nst);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  }
  for (i = 0; rc == GDEFCORE_OK && i < nst; i++) {
    const GDEFCORE_Setting * s = defs_find(&d, st[i].name, st[i].name_len);
    char * value = NULL;
    size_t vn = 0;
    int present = 0;
    /* A local setting is not in the export, nor is a name nobody declares. */
    if (s == NULL || s->local) {
      continue;
    }
    rc = read_field(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, st[i].id, "value",
        &value, &vn, &present);
    if (rc == GDEFCORE_OK && present) {
      rc = save_entity(cs, st[i].id, s, value, vn, NULL, 0);
    }
    gdefcore_text_free(catalog, value);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_serialize(cs, out_files, out_count);
  }
  gdefcore_changeset_destroy(cs);
  stored_free(catalog, st, nst);
  defs_free(catalog, &d);
  return rc;
}

typedef struct Ent {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char target[GDEFCORE_PUBLIC_ID_LEN + 1];
  int keep;
  int decided;
} Ent;

/* The id in an `entity/<id>/...` path, or 0. */
static int path_entity(const GDEFCORE_Patch * f, char id[GDEFCORE_PUBLIC_ID_LEN + 1],
    const char ** tail, size_t * tail_len) {
  if (f->path_len < 7 + GDEFCORE_PUBLIC_ID_LEN + 1 ||
      memcmp(f->path, "entity/", 7) != 0 ||
      f->path[7 + GDEFCORE_PUBLIC_ID_LEN] != '/') {
    return 0;
  }
  if (gdefcore_id_canonical(f->path + 7, GDEFCORE_PUBLIC_ID_LEN, id) !=
      GDEFCORE_OK) {
    return 0;
  }
  *tail = f->path + 7 + GDEFCORE_PUBLIC_ID_LEN;
  *tail_len = f->path_len - 7 - GDEFCORE_PUBLIC_ID_LEN;
  return 1;
}

GDEFCORE_Result gdefcore_settings_import(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Patch * files, size_t count, GDEFCORE_Changeset ** out_changeset,
    size_t * out_skipped_local, size_t * out_skipped_unknown) {
  Defs d;
  Ent * ents = NULL;
  size_t nents = 0;
  GDEFCORE_Patch * keep = NULL;
  char ** owned = NULL;
  size_t nkeep = 0;
  size_t nowned = 0;
  size_t i;
  size_t j;
  size_t skipped_local = 0;
  size_t skipped_unknown = 0;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (out_changeset != NULL) {
    *out_changeset = NULL;
  }
  if (out_skipped_local != NULL) {
    *out_skipped_local = 0;
  }
  if (out_skipped_unknown != NULL) {
    *out_skipped_unknown = 0;
  }
  if (catalog == NULL || out_changeset == NULL || (files == NULL && count != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = defs_load(catalog, NULL, &d);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  ents = (Ent *)calloc(count + 1, sizeof *ents);
  keep = (GDEFCORE_Patch *)calloc(count + 1, sizeof *keep);
  owned = (char **)calloc(count + 1, sizeof *owned);
  if (ents == NULL || keep == NULL || owned == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  /* What is in the files: the header, and entities of one type. */
  for (i = 0; i < count; i++) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * tail = NULL;
    size_t tail_len = 0;
    int seen = 0;
    if (span_eq(files[i].path, files[i].path_len, "format", 6) ||
        span_eq(files[i].path, files[i].path_len, "epoch", 5) ||
        span_eq(files[i].path, files[i].path_len, "actor", 5)) {
      continue;
    }
    if (!path_entity(&files[i], id, &tail, &tail_len)) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    for (j = 0; j < nents; j++) {
      if (memcmp(ents[j].id, id, GDEFCORE_PUBLIC_ID_LEN) == 0) {
        seen = 1;
      }
    }
    if (!seen) {
      memcpy(ents[nents].id, id, GDEFCORE_PUBLIC_ID_LEN + 1);
      nents += 1;
    }
  }
  /* Each entity is a setting this tenant declares, or it is left out. */
  for (j = 0; j < nents; j++) {
    const GDEFCORE_Patch * type_file = NULL;
    const GDEFCORE_Patch * name_file = NULL;
    for (i = 0; i < count; i++) {
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      const char * tail = NULL;
      size_t tail_len = 0;
      if (!path_entity(&files[i], id, &tail, &tail_len) ||
          memcmp(id, ents[j].id, GDEFCORE_PUBLIC_ID_LEN) != 0) {
        continue;
      }
      if (span_eq(tail, tail_len, "/type", 5)) {
        type_file = &files[i];
      } else if (span_eq(tail, tail_len, "/lang/en/name/0", 15)) {
        name_file = &files[i];
      }
    }
    if (type_file == NULL || name_file == NULL ||
        !span_eq((const char *)type_file->bytes, type_file->len, kType,
            sizeof kType - 1)) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    {
      const GDEFCORE_Setting * s =
          defs_find(&d, (const char *)name_file->bytes, name_file->len);
      if (s == NULL) {
        skipped_unknown += 1;
      } else if (s->local) {
        /* The target keeps its own value, or none. */
        skipped_local += 1;
      } else {
        int existed = 0;
        rc = id_for(catalog, s->name, s->name_len, ents[j].target, &existed);
        if (rc != GDEFCORE_OK) {
          goto done;
        }
        ents[j].keep = 1;
      }
    }
  }
  /* The files that stay, under this site's own ids. */
  for (i = 0; i < count; i++) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * tail = NULL;
    size_t tail_len = 0;
    if (!path_entity(&files[i], id, &tail, &tail_len)) {
      keep[nkeep++] = files[i];
      continue;
    }
    for (j = 0; j < nents; j++) {
      if (memcmp(ents[j].id, id, GDEFCORE_PUBLIC_ID_LEN) == 0) {
        break;
      }
    }
    if (j == nents || !ents[j].keep || span_eq(tail, tail_len, "/ver", 4)) {
      continue;
    }
    {
      char * path = (char *)malloc(files[i].path_len + 1);
      GDEFCORE_Patch f = files[i];
      if (path == NULL) {
        rc = GDEFCORE_ERR_OOM;
        goto done;
      }
      owned[nowned++] = path;
      memcpy(path, files[i].path, files[i].path_len);
      memcpy(path + 7, ents[j].target, GDEFCORE_PUBLIC_ID_LEN);
      f.path = path;
      if (span_eq(tail, tail_len, "/base", 5)) {
        /* Built on what this site has of the entity. */
        char seq[24];
        uint64_t head = 0;
        char * bytes;
        (void)gdefcore_entity_revision(catalog, ents[j].target,
            GDEFCORE_PUBLIC_ID_LEN, &head);
        snprintf(seq, sizeof seq, "%llu", (unsigned long long)head);
        bytes = (char *)malloc(strlen(seq) + 1);
        if (bytes == NULL) {
          rc = GDEFCORE_ERR_OOM;
          goto done;
        }
        owned[nowned++] = bytes;
        memcpy(bytes, seq, strlen(seq) + 1);
        f.bytes = (uint8_t *)bytes;
        f.len = strlen(seq);
      }
      keep[nkeep++] = f;
    }
  }
  rc = gdefcore_changeset_parse(catalog, keep, nkeep, NULL, &cs);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_rebase(cs);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(cs);
    cs = NULL;
  } else {
    *out_changeset = cs;
    if (out_skipped_local != NULL) {
      *out_skipped_local = skipped_local;
    }
    if (out_skipped_unknown != NULL) {
      *out_skipped_unknown = skipped_unknown;
    }
  }
done:
  for (i = 0; i < nowned; i++) {
    free(owned[i]);
  }
  free(owned);
  free(keep);
  free(ents);
  defs_free(catalog, &d);
  return rc;
}
