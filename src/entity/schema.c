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
 * Stored-data schema versions on the write and the read path (AD-15,
 * module.h): which component's data an entity is, the stamp each write of it
 * takes, the check that the tenant's data stands where the component writes
 * it, and the read-time upcasters that bring what was written at an older
 * version into the installed shape.
 */

#include <ghoti.io/defiant-core/macros.h>
#include "entity_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-core/module.h>
#include <stdio.h>
#include <string.h>

static const char kSchemaNs[] = GDEFCORE_SCHEMA_TYPE;
static const char kCore[] = GDEFCORE_SCHEMA_CORE;

int gdefcore_ent_schema_text(const char * p, size_t n, uint32_t * out) {
  uint64_t v = 0;
  size_t i;
  if (p == NULL || n == 0 || n > 10 || p[0] == '0') {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (p[i] < '0' || p[i] > '9') {
      return 0;
    }
    v = v * 10u + (uint64_t)(p[i] - '0');
  }
  if (v > UINT32_MAX) {
    return 0;
  }
  *out = (uint32_t)v;
  return 1;
}

static int is_core(const char * p, size_t n) {
  return gdefcore_ent_span_eq(p, n, kCore, sizeof kCore - 1);
}

GDEFCORE_Result gdefcore_ent_recorded(GDEFCORE_Catalog * cat,
    const char * comp, size_t comp_len, int * out_found,
    uint32_t * out_version) {
  int found = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFCORE_Result rc = gdefcore_ent_map(gdefstor_record_get(cat->store,
      (const char *)cat->tenant, cat->tenant_len, kSchemaNs,
      sizeof kSchemaNs - 1, comp, comp_len, &found, &bytes, &len, NULL,
      NULL));
  *out_found = 0;
  *out_version = 0;
  if (rc == GDEFCORE_OK && found) {
    if (!gdefcore_ent_schema_text((const char *)bytes, len, out_version)) {
      rc = GDEFCORE_ERR_CORRUPT;
    } else {
      *out_found = 1;
    }
  }
  gdefstor_bytes_free(NULL, bytes);
  return rc;
}

GDEFCORE_Result gdefcore_ent_owner(GDEFCORE_Catalog * cat, const char * type,
    size_t type_len, char out[GDEFSTOR_SCHEMA_COMPONENT_MAX + 1],
    size_t * out_len) {
  size_t dot = 0;
  uint32_t v = 0;
  int found = 0;
  GDEFCORE_Result rc;
  while (dot < type_len && type[dot] != '.') {
    dot += 1;
  }
  /* `core.*` and `site.*` are core's; so is a namespace that is no module
   * here and no component whose data the tenant holds. */
  if (dot == type_len || dot > GDEFSTOR_SCHEMA_COMPONENT_MAX ||
      is_core(type, dot) || gdefcore_ent_span_eq(type, dot, "site", 4)) {
    memcpy(out, kCore, sizeof kCore);
    *out_len = sizeof kCore - 1;
    return GDEFCORE_OK;
  }
  if (gdefcore_module_schema(cat->host, type, dot, &v) == GDEFCORE_OK) {
    found = 1;
  } else {
    rc = gdefcore_ent_recorded(cat, type, dot, &found, &v);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  if (!found) {
    memcpy(out, kCore, sizeof kCore);
    *out_len = sizeof kCore - 1;
    return GDEFCORE_OK;
  }
  memcpy(out, type, dot);
  out[dot] = '\0';
  *out_len = dot;
  return GDEFCORE_OK;
}

void gdefcore_ent_schema_reset(GDEFCORE_Catalog * cat) {
  cat->checked_write = NULL;
  cat->nchecked = 0;
}

/* Spell `<comp>/<version>`. */
static GDEFCORE_Result spell(const char * comp, size_t comp_len,
    uint32_t version, char out[GDEFSTOR_SCHEMA_MAX_BYTES + 1],
    size_t * out_len) {
  int n;
  if (comp_len == 0 || comp_len > GDEFSTOR_SCHEMA_COMPONENT_MAX ||
      version == 0) {
    return GDEFCORE_ERR_INTERNAL;
  }
  n = snprintf(out, GDEFSTOR_SCHEMA_MAX_BYTES + 1, "%.*s/%lu", (int)comp_len,
      comp, (unsigned long)version);
  if (n <= 0 || n > GDEFSTOR_SCHEMA_MAX_BYTES) {
    return GDEFCORE_ERR_INTERNAL;
  }
  *out_len = (size_t)n;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_stamp(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * comp, size_t comp_len,
    char out[GDEFSTOR_SCHEMA_MAX_BYTES + 1], size_t * out_len) {
  uint32_t installed = 0;
  uint32_t recorded = 0;
  int known;
  int found = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (cat->mig_write != NULL && cat->mig_write == write) {
    /* A step's own data takes the step's target version; core's data in a
     * step is core's as installed (core is brought forward first). A step
     * that writes another module's data has no version to give it. */
    if (gdefcore_ent_span_eq(comp, comp_len, cat->mig_comp,
            cat->mig_comp_len)) {
      return spell(comp, comp_len, cat->mig_to, out, out_len);
    }
    if (is_core(comp, comp_len)) {
      return spell(comp, comp_len, GDEFCORE_SCHEMA_VERSION, out, out_len);
    }
    return GDEFCORE_ERR_INVALID;
  }
  if (cat->checked_write != write) {
    cat->checked_write = write;
    cat->nchecked = 0;
  }
  for (i = 0; i < cat->nchecked; i++) {
    if (gdefcore_ent_span_eq(cat->checked[i].name, cat->checked[i].len, comp,
            comp_len)) {
      return spell(comp, comp_len, cat->checked[i].version, out, out_len);
    }
  }
  known = gdefcore_module_schema(cat->host, comp, comp_len, &installed) ==
          GDEFCORE_OK;
  rc = gdefcore_ent_recorded(cat, comp, comp_len, &found, &recorded);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!found) {
    /* The component's first data here: it is at the version it is written
     * in, recorded in the same write (AD-15). */
    char text[16];
    int n;
    if (!known) {
      return GDEFCORE_ERR_INTERNAL; /* the owner rule names no such one */
    }
    n = snprintf(text, sizeof text, "%lu", (unsigned long)installed);
    if (n <= 0 || (size_t)n >= sizeof text) {
      return GDEFCORE_ERR_INTERNAL;
    }
    rc = gdefcore_ent_map(gdefstor_record_put(write, kSchemaNs,
        sizeof kSchemaNs - 1, comp, comp_len, GDEFCORE_SCHEMA_CORE_STAMP,
        sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, (const uint8_t *)text,
        (size_t)n));
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    recorded = installed;
  } else if (known && recorded < installed) {
    /* The tenant waits for its forward migration: nothing it holds of the
     * component is in the installed shape yet. */
    return GDEFCORE_ERR_MAINTENANCE;
  } else if (known && recorded > installed) {
    return GDEFCORE_ERR_UNSUPPORTED;
  }
  if (cat->nchecked < sizeof cat->checked / sizeof cat->checked[0]) {
    memcpy(cat->checked[cat->nchecked].name, comp, comp_len);
    cat->checked[cat->nchecked].len = comp_len;
    cat->checked[cat->nchecked].version = recorded;
    cat->nchecked += 1;
  }
  return spell(comp, comp_len, recorded, out, out_len);
}

GDEFCORE_Result gdefcore_ent_type_stamp(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * type, size_t type_len,
    char out[GDEFSTOR_SCHEMA_MAX_BYTES + 1], size_t * out_len) {
  char comp[GDEFSTOR_SCHEMA_COMPONENT_MAX + 1];
  size_t comp_len = 0;
  GDEFCORE_Result rc = gdefcore_ent_owner(cat, type, type_len, comp,
      &comp_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return gdefcore_ent_stamp(cat, write, comp, comp_len, out, out_len);
}

GDEFCORE_Result gdefcore_ent_core_check(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write) {
  char stamp[GDEFSTOR_SCHEMA_MAX_BYTES + 1];
  size_t len = 0;
  return gdefcore_ent_stamp(cat, write, kCore, sizeof kCore - 1, stamp, &len);
}

int gdefcore_ent_upcasts(GDEFCORE_Catalog * cat, const char * type,
    size_t type_len) {
  size_t dot = 0;
  uint32_t v = 0;
  while (dot < type_len && type[dot] != '.') {
    dot += 1;
  }
  if (cat->host == NULL || dot == type_len ||
      gdefcore_module_schema(cat->host, type, dot, &v) != GDEFCORE_OK) {
    return 0; /* core declares no upcaster */
  }
  return gdefcore_module_upcaster_count(cat->host, type, dot) > 0;
}

GDEFCORE_Result gdefcore_ent_upcast(GDEFCORE_Catalog * cat, const char * type,
    size_t type_len, const GDEFSTOR_Type * decl, const char * stamp,
    size_t stamp_len, GDEFSTOR_Tree * tree) {
  const char * comp = NULL;
  size_t comp_len = 0;
  uint32_t written = 0;
  uint32_t installed = 0;
  uint32_t v;
  if (gdefstor_schema_parse(stamp, stamp_len, &comp, &comp_len, &written) !=
      GDEFSTOR_OK) {
    /* Without its stamp a revision's shape is not known, and it is not
     * read as some shape it may not be in. */
    return GDEFCORE_ERR_CORRUPT;
  }
  if (gdefcore_module_schema(cat->host, comp, comp_len, &installed) !=
      GDEFCORE_OK) {
    return GDEFCORE_OK; /* a component not here has no upcaster here */
  }
  {
    /* Up to where the tenant's current data of the component stands: the
     * installed version once it is migrated, and before that the shape its
     * current data is in (a step reads its component's data in the shape it
     * starts from, and brings it the rest of the way). */
    int found = 0;
    uint32_t recorded = 0;
    GDEFCORE_Result rc = gdefcore_ent_recorded(cat, comp, comp_len, &found,
        &recorded);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (found && recorded < installed) {
      installed = recorded;
    }
  }
  if (written > installed) {
    return GDEFCORE_ERR_UNSUPPORTED;
  }
  for (v = written; v < installed; v++) {
    GDEFCORE_Upcast_Fn fn = NULL;
    void * user = NULL;
    GDEFCORE_Result rc = gdefcore_module_upcaster(cat->host, comp, comp_len, v,
        &fn, &user);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (fn != NULL) {
      rc = fn(type, type_len, decl, tree, user);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_lang_stamp(const GDEFSTOR_History * h,
    const char * lang, size_t lang_len, uint64_t revision,
    char out[GDEFSTOR_SCHEMA_MAX_BYTES + 1], size_t * out_len) {
  size_t n = gdefstor_history_revision_count(h);
  size_t i;
  *out_len = 0;
  out[0] = '\0';
  /* The newest revision up to @p revision that changed the language's tree:
   * its writer wrote the whole tree (a save names each language's whole
   * tree), so the tree as of @p revision is in that writer's shape. */
  for (i = n; i > 0; i--) {
    GDEFSTOR_RevisionInfo r;
    size_t at = 0;
    memset(&r, 0, sizeof r);
    r.size = sizeof r;
    if (gdefstor_history_revision(h, i - 1, &r) != GDEFSTOR_OK) {
      return GDEFCORE_ERR_CORRUPT;
    }
    if (revision != 0 && r.revision > revision) {
      continue;
    }
    while (at <= r.languages_len) {
      size_t end = at;
      while (end < r.languages_len && r.languages[end] != ',') {
        end += 1;
      }
      if (gdefcore_ent_span_eq(r.languages + at, end - at, lang, lang_len)) {
        if (r.schema_len > GDEFSTOR_SCHEMA_MAX_BYTES) {
          return GDEFCORE_ERR_CORRUPT;
        }
        memcpy(out, r.schema, r.schema_len);
        out[r.schema_len] = '\0';
        *out_len = r.schema_len;
        return GDEFCORE_OK;
      }
      at = end + 1;
    }
  }
  return GDEFCORE_ERR_CORRUPT; /* a tree no revision wrote */
}
