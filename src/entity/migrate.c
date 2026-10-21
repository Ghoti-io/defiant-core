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
 * The forward migration of a tenant's stored data (AD-15, module.h): the one
 * path a live upgrade and a restore both take. Every component whose data
 * the tenant holds is read from ::GDEFCORE_SCHEMA_TYPE, checked against what
 * is installed, and brought forward step by step.
 *
 * Each step runs in a write of its own, with the migration table's row of
 * the step and the component's version it reaches: the port reads only the
 * last commit, so a step must see what the one before it wrote, and the
 * version recorded is always where the committed data stands.
 */

#include <ghoti.io/defiant-core/macros.h>
#include "entity_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-core/module.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char kSchemaNs[] = GDEFCORE_SCHEMA_TYPE;
static const char kMigrationNs[] = GDEFCORE_MIGRATION_TYPE;
static const char kCore[] = GDEFCORE_SCHEMA_CORE;

enum { kComponentsMax = 64 };

struct GDEFCORE_Migration {
  GDEFCORE_Host * host;
  GDEFCORE_Catalog * catalog;
  GDEFSTOR_Write * write;
  char comp[GDEFSTOR_SCHEMA_COMPONENT_MAX + 1];
  size_t comp_len;
  uint32_t from;
  uint32_t to;
  int64_t now;
};

/* One component whose data the tenant holds. */
typedef struct Comp {
  char name[GDEFSTOR_SCHEMA_COMPONENT_MAX + 1];
  size_t len;
  char label[GDEFSTOR_SCHEMA_COMPONENT_MAX + 8]; /* "core", "module <name>" */
  uint32_t recorded;
  uint32_t installed;
} Comp;

static void say(char ** out, size_t * out_len, const char * fmt, ...) {
  char text[768];
  va_list ap;
  int n;
  if (out == NULL) {
    return;
  }
  va_start(ap, fmt);
  n = vsnprintf(text, sizeof text, fmt, ap);
  va_end(ap);
  if (n <= 0) {
    return;
  }
  if ((size_t)n >= sizeof text) {
    n = (int)sizeof text - 1;
  }
  *out = gdefcore_ent_dup(gdefcore_ent_alloc(NULL), text, (size_t)n);
  if (out_len != NULL) {
    *out_len = *out == NULL ? 0 : (size_t)n;
  }
}

void gdefcore_schema_text_free(char * text) {
  gcu_allocator_free(gdefcore_ent_alloc(NULL), text);
}

/* Every component the tenant's ::GDEFCORE_SCHEMA_TYPE records name, core
 * first and then by name, with where its data stands and what is installed
 * (0: not installed). */
static GDEFCORE_Result components(GDEFCORE_Host * host, GDEFSTOR_Store * store,
    const uint8_t * tenant, size_t tenant_len, Comp * out, size_t * out_n) {
  uint64_t offset = 0;
  size_t n = 0;
  size_t i;
  for (;;) {
    GDEFSTOR_RecordList * list = NULL;
    size_t count;
    GDEFCORE_Result rc = gdefcore_ent_map(gdefstor_record_list(store,
        (const char *)tenant, tenant_len, kSchemaNs, sizeof kSchemaNs - 1, "",
        0, offset, GDEFSTOR_RECORD_MAX_PAGE, &list));
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    count = gdefstor_record_list_count(list);
    for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
      const char * key = NULL;
      size_t key_len = 0;
      const uint8_t * bytes = NULL;
      size_t blen = 0;
      rc = gdefcore_ent_map(gdefstor_record_list_item(list, i, &key, &key_len,
          &bytes, &blen, NULL, NULL));
      if (rc == GDEFCORE_OK && n >= kComponentsMax) {
        rc = GDEFCORE_ERR_LIMIT;
      }
      if (rc == GDEFCORE_OK &&
          (key_len == 0 || key_len > GDEFSTOR_SCHEMA_COMPONENT_MAX ||
              !gdefcore_ent_schema_text((const char *)bytes, blen,
                  &out[n].recorded))) {
        rc = GDEFCORE_ERR_CORRUPT;
      }
      if (rc == GDEFCORE_OK) {
        memcpy(out[n].name, key, key_len);
        out[n].name[key_len] = '\0';
        out[n].len = key_len;
        if (gdefcore_ent_span_eq(key, key_len, kCore, sizeof kCore - 1)) {
          memcpy(out[n].label, kCore, sizeof kCore);
        } else {
          memcpy(out[n].label, "module ", 7);
          memcpy(out[n].label + 7, key, key_len);
          out[n].label[7 + key_len] = '\0';
        }
        if (gdefcore_module_schema(host, key, key_len, &out[n].installed) !=
            GDEFCORE_OK) {
          out[n].installed = 0;
        }
        n += 1;
      }
    }
    gdefstor_record_list_free(list);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (count < GDEFSTOR_RECORD_MAX_PAGE) {
      break;
    }
    offset += count;
  }
  /* Core is brought forward first: a module's step writes on core's data as
   * core installed here writes it. */
  for (i = 0; i < n; i++) {
    if (gdefcore_ent_span_eq(out[i].name, out[i].len, kCore,
            sizeof kCore - 1) &&
        i > 0) {
      Comp c = out[i];
      memmove(&out[1], &out[0], i * sizeof *out);
      out[0] = c;
      break;
    }
  }
  *out_n = n;
  return GDEFCORE_OK;
}

/* Whether @p c can be brought where it is installed, in words when not:
 * installed, not newer, and a step from every version on the way. */
static GDEFCORE_Result judge(GDEFCORE_Host * host, const Comp * c,
    char ** out_reason, size_t * out_reason_len) {
  uint32_t v;
  if (c->installed == 0) {
    say(out_reason, out_reason_len,
        "The tenant holds data of module %s at stored-data schema version "
        "%lu, and module %s is not installed here, so its data cannot be "
        "brought forward. Install it first.",
        c->name, (unsigned long)c->recorded, c->name);
    return GDEFCORE_ERR_UNSUPPORTED;
  }
  if (c->recorded > c->installed) {
    say(out_reason, out_reason_len,
        "The tenant holds %s's data at stored-data schema version %lu, newer "
        "than version %lu of %s installed here. Install %s at version %lu or "
        "later.",
        c->label, (unsigned long)c->recorded, (unsigned long)c->installed,
        c->label, c->label, (unsigned long)c->recorded);
    return GDEFCORE_ERR_UNSUPPORTED;
  }
  for (v = c->recorded; v < c->installed; v++) {
    GDEFCORE_Step_Fn fn = NULL;
    GDEFCORE_Result rc = gdefcore_module_step(host, c->name, c->len, v, &fn,
        NULL);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (fn == NULL) {
      say(out_reason, out_reason_len,
          "The tenant holds %s's data at stored-data schema version %lu and "
          "version %lu is installed, and %s declares no step from version "
          "%lu to %lu, so its data cannot be brought forward and nothing was "
          "written.",
          c->label, (unsigned long)c->recorded, (unsigned long)c->installed,
          c->label, (unsigned long)v, (unsigned long)(v + 1));
      return GDEFCORE_ERR_UNSUPPORTED;
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_schema_status(GDEFCORE_Host * host,
    GDEFSTOR_Store * store, const uint8_t * tenant, size_t tenant_len,
    char ** out_reason, size_t * out_reason_len) {
  Comp comps[kComponentsMax];
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (out_reason != NULL) {
    *out_reason = NULL;
  }
  if (out_reason_len != NULL) {
    *out_reason_len = 0;
  }
  if (store == NULL || tenant == NULL || tenant_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = components(host, store, tenant, tenant_len, comps, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < n; i++) {
    const Comp * c = &comps[i];
    if (c->installed == 0 || c->recorded > c->installed) {
      return judge(host, c, out_reason, out_reason_len);
    }
    if (c->recorded < c->installed) {
      say(out_reason, out_reason_len,
          "The tenant holds %s's data at stored-data schema version %lu and "
          "version %lu is installed: it is under maintenance until its data "
          "is brought forward.",
          c->label, (unsigned long)c->recorded, (unsigned long)c->installed);
      return GDEFCORE_ERR_MAINTENANCE;
    }
  }
  return GDEFCORE_OK;
}

/* One step of @p c from @p from, with its migration-table row and the
 * version it reaches, in a write of its own. */
static GDEFCORE_Result run_step(GDEFCORE_Host * host, GDEFSTOR_Store * store,
    GDEFCORE_Catalog * cat, const Comp * c, uint32_t from, int64_t now,
    char ** out_reason, size_t * out_reason_len) {
  GDEFCORE_Migration m;
  GDEFCORE_Step_Fn fn = NULL;
  void * user = NULL;
  char key[GDEFSTOR_SCHEMA_COMPONENT_MAX + 16];
  char row[32];
  char ver[16];
  int kn;
  int rn;
  int vn;
  GDEFCORE_Result rc = gdefcore_module_step(host, c->name, c->len, from, &fn,
      &user);
  if (rc == GDEFCORE_OK && fn == NULL) {
    rc = GDEFCORE_ERR_INTERNAL; /* judged present before anything ran */
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  kn = snprintf(key, sizeof key, "%s:%010lu", c->name, (unsigned long)from);
  rn = snprintf(row, sizeof row, "%lu %lu", (unsigned long)from,
      (unsigned long)(from + 1));
  vn = snprintf(ver, sizeof ver, "%lu", (unsigned long)(from + 1));
  if (kn <= 0 || (size_t)kn >= sizeof key || rn <= 0 ||
      (size_t)rn >= sizeof row || vn <= 0 || (size_t)vn >= sizeof ver) {
    return GDEFCORE_ERR_INTERNAL;
  }
  memset(&m, 0, sizeof m);
  m.host = host;
  m.catalog = cat;
  memcpy(m.comp, c->name, c->len + 1);
  m.comp_len = c->len;
  m.from = from;
  m.to = from + 1;
  m.now = now;
  rc = gdefcore_ent_map(gdefstor_write_begin(store, (const char *)cat->tenant,
      cat->tenant_len, NULL, &m.write));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* The catalog writes as this step until it returns: its component's data
   * at the step's target version (schema.c). */
  cat->mig_write = m.write;
  memcpy(cat->mig_comp, c->name, c->len + 1);
  cat->mig_comp_len = c->len;
  cat->mig_to = m.to;
  cat->mig_now = now;
  rc = fn(&m, user);
  cat->mig_write = NULL;
  cat->mig_comp_len = 0;
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(m.write);
    say(out_reason, out_reason_len,
        "%s's step from stored-data schema version %lu to %lu failed (%s); "
        "nothing of it was written, and the tenant's data of it stays at "
        "version %lu.",
        c->label, (unsigned long)from, (unsigned long)(from + 1),
        gdefcore_result_string(rc), (unsigned long)from);
    return rc;
  }
  rc = gdefcore_ent_map(gdefstor_record_put(m.write, kMigrationNs,
      sizeof kMigrationNs - 1, key, (size_t)kn, GDEFCORE_SCHEMA_CORE_STAMP,
      sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, (const uint8_t *)row,
      (size_t)rn));
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_ent_map(gdefstor_record_put(m.write, kSchemaNs,
        sizeof kSchemaNs - 1, c->name, c->len, GDEFCORE_SCHEMA_CORE_STAMP,
        sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, (const uint8_t *)ver,
        (size_t)vn));
  }
  if (rc != GDEFCORE_OK) {
    gdefstor_write_abort(m.write);
    return rc;
  }
  return gdefcore_ent_map(gdefstor_write_commit(m.write));
}

GDEFCORE_Result gdefcore_schema_migrate(GDEFCORE_Host * host,
    GDEFSTOR_Store * store, const uint8_t * tenant, size_t tenant_len,
    int64_t now_ms, size_t * out_migrated, char ** out_reason,
    size_t * out_reason_len) {
  Comp comps[kComponentsMax];
  GDEFCORE_Catalog * cat = NULL;
  size_t n = 0;
  size_t moved = 0;
  size_t i;
  int due = 0;
  GDEFCORE_Result rc;
  if (out_reason != NULL) {
    *out_reason = NULL;
  }
  if (out_reason_len != NULL) {
    *out_reason_len = 0;
  }
  if (out_migrated != NULL) {
    *out_migrated = 0;
  }
  if (store == NULL || tenant == NULL || tenant_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = components(host, store, tenant, tenant_len, comps, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* Every component judged before any step runs: a gap, newer data or a
   * module not here refuses the whole, and nothing is written. */
  for (i = 0; i < n; i++) {
    rc = judge(host, &comps[i], out_reason, out_reason_len);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    due |= comps[i].recorded < comps[i].installed;
  }
  if (!due) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_catalog_open(store, tenant, tenant_len, NULL, NULL, &cat);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  gdefcore_catalog_bind_host(cat, host);
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    uint32_t v;
    for (v = comps[i].recorded; rc == GDEFCORE_OK && v < comps[i].installed;
         v++) {
      rc = run_step(host, store, cat, &comps[i], v, now_ms, out_reason,
          out_reason_len);
      if (rc == GDEFCORE_OK) {
        moved += 1;
      }
    }
  }
  gdefcore_catalog_destroy(cat);
  if (out_migrated != NULL) {
    *out_migrated = moved;
  }
  return rc;
}

GDEFCORE_Catalog * gdefcore_migration_catalog(GDEFCORE_Migration * migration) {
  return migration == NULL ? NULL : migration->catalog;
}

void gdefcore_migration_step_of(const GDEFCORE_Migration * migration,
    const char ** out_component, size_t * out_component_len,
    uint32_t * out_from, uint32_t * out_to) {
  if (migration == NULL) {
    return;
  }
  if (out_component != NULL) {
    *out_component = migration->comp;
  }
  if (out_component_len != NULL) {
    *out_component_len = migration->comp_len;
  }
  if (out_from != NULL) {
    *out_from = migration->from;
  }
  if (out_to != NULL) {
    *out_to = migration->to;
  }
}

int64_t gdefcore_migration_time(const GDEFCORE_Migration * migration) {
  return migration == NULL ? 0 : migration->now;
}

GDEFCORE_Result gdefcore_migration_apply(GDEFCORE_Migration * migration,
    GDEFCORE_Changeset * changeset) {
  if (migration == NULL || changeset == NULL ||
      changeset->catalog != migration->catalog || migration->write == NULL ||
      migration->catalog->mig_write != migration->write) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_ent_apply_in(changeset, migration->write, migration->now);
}
