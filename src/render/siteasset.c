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

/*
 * The site's own stylesheets and scripts (siteasset.h): two configuration
 * types of a name and a text, staged, vetted and authorized as a changeset
 * writes them, and looked up under the owner `site` by the same call that
 * finds a module's file (asset.c).
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/asset.h>
#include <ghoti.io/defiant-core/siteasset.h>

#include "../core/asset_util.h"
#include "render_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kCssType[] = GDEFCORE_ASSET_CSS_TYPE;
static const char kJsType[] = GDEFCORE_ASSET_JS_TYPE;
static const char kLang[] = "en";
static const char kNotAllowed[] = "That edit is not allowed.";
static const char kCssMedia[] = "text/css; charset=utf-8";
static const char kJsMedia[] = "text/javascript; charset=utf-8";

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static const char * type_of(int kind) {
  return kind == GDEFCORE_ASSET_CSS ? kCssType
                                    : kind == GDEFCORE_ASSET_JS ? kJsType : NULL;
}

/* The kind of the type called @p type, or 0 when it is neither. */
static int kind_of(const char * type, size_t n) {
  if (type == NULL) {
    return 0;
  }
  if (span_eq(type, n, kCssType, sizeof kCssType - 1)) {
    return GDEFCORE_ASSET_CSS;
  }
  if (span_eq(type, n, kJsType, sizeof kJsType - 1)) {
    return GDEFCORE_ASSET_JS;
  }
  return 0;
}

/* One value of @p field as a NUL-terminated copy, empty when there is none. */
GDEFCORE_Result gdefcore_render_field_text(GDEFCORE_Catalog * catalog,
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

/* Where an entity's fields are read from: what is published, or, with a
 * changeset, as that write would leave it. */
static void read_where(const GDEFCORE_Changeset * projection,
    const GDEFCORE_Changeset ** through, int * view) {
  *through = projection;
  *view = projection == NULL ? GDEFCORE_VIEW_PUBLISHED : GDEFCORE_VIEW_CURRENT;
}

/*
 * The site file called @p name, as @p projection would leave the site (what is
 * published when NULL): its id and its kind. @p skip, when not NULL, is an id
 * that does not count, so that a file is not a duplicate of itself.
 * ::GDEFCORE_ERR_INVALID when there is none.
 */
static GDEFCORE_Result locate(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * name, size_t name_len,
    const char * skip, char id[GDEFCORE_PUBLIC_ID_LEN + 1], int * kind) {
  const GDEFCORE_Changeset * through;
  int view;
  size_t t;
  size_t i;
  size_t touched = projection == NULL ? 0 : gdefcore_changeset_touched_count(projection);
  read_where(projection, &through, &view);
  for (t = 0; t < 2; t++) {
    int k = t == 0 ? GDEFCORE_ASSET_CSS : GDEFCORE_ASSET_JS;
    const char * type = type_of(k);
    char ** ids = NULL;
    size_t count = 0;
    GDEFCORE_Result rc = gdefcore_entity_ids(catalog, type, strlen(type), &ids,
        &count);
    if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_INVALID) {
      return rc;
    }
    for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
      char * stored = NULL;
      size_t stored_len = 0;
      int op;
      if (strlen(ids[i]) != GDEFCORE_PUBLIC_ID_LEN ||
          (skip != NULL && memcmp(ids[i], skip, GDEFCORE_PUBLIC_ID_LEN) == 0)) {
        continue;
      }
      op = touched_op(projection, ids[i]);
      if (op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_UNPUBLISH) {
        continue;
      }
      if (gdefcore_render_field_text(catalog, through, view, ids[i], "name", &stored,
              &stored_len) != GDEFCORE_OK) {
        gdefcore_ids_free(catalog, ids, count);
        return GDEFCORE_ERR_OOM;
      }
      if (stored_len > 0 && span_eq(stored, stored_len, name, name_len)) {
        memcpy(id, ids[i], GDEFCORE_PUBLIC_ID_LEN);
        id[GDEFCORE_PUBLIC_ID_LEN] = '\0';
        *kind = k;
        free(stored);
        gdefcore_ids_free(catalog, ids, count);
        return GDEFCORE_OK;
      }
      free(stored);
    }
    if (rc == GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
    }
  }
  /* A file the write creates is not in the store yet. */
  for (i = 0; i < touched; i++) {
    const char * tid = NULL;
    size_t tid_len = 0;
    const char * type = NULL;
    size_t type_len = 0;
    int op = 0;
    int k;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * stored = NULL;
    size_t stored_len = 0;
    int hit;
    if (gdefcore_changeset_touched_at(projection, i, &tid, &tid_len, &type,
            &type_len, &op) != GDEFCORE_OK ||
        (k = kind_of(type, type_len)) == 0 ||
        op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_UNPUBLISH ||
        gdefcore_id_canonical(tid, tid_len, canon) != GDEFCORE_OK ||
        (skip != NULL && memcmp(canon, skip, GDEFCORE_PUBLIC_ID_LEN) == 0)) {
      continue;
    }
    if (gdefcore_render_field_text(catalog, through, view, canon, "name", &stored, &stored_len) !=
        GDEFCORE_OK) {
      return GDEFCORE_ERR_OOM;
    }
    hit = stored_len > 0 && span_eq(stored, stored_len, name, name_len);
    free(stored);
    if (hit) {
      memcpy(id, canon, GDEFCORE_PUBLIC_ID_LEN);
      id[GDEFCORE_PUBLIC_ID_LEN] = '\0';
      *kind = k;
      return GDEFCORE_OK;
    }
  }
  return GDEFCORE_ERR_INVALID;
}

GDEFCORE_Result gdefcore_siteasset_lookup(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * name, size_t name_len,
    GDEFCORE_Asset * out) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const GDEFCORE_Changeset * through;
  int view;
  int kind = 0;
  char * text = NULL;
  size_t text_len = 0;
  uint8_t * block;
  GDEFCORE_Result rc = locate(catalog, projection, name, name_len, NULL, id, &kind);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  read_where(projection, &through, &view);
  rc = gdefcore_render_field_text(catalog, through, view, id, "text", &text, &text_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* One block: the text, a NUL, then the name, a NUL. */
  block = (uint8_t *)malloc(text_len + 1 + name_len + 1);
  if (block == NULL) {
    free(text);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(block, text, text_len);
  block[text_len] = 0;
  memcpy(block + text_len + 1, name, name_len);
  block[text_len + 1 + name_len] = 0;
  free(text);
  rc = gdefcore_asset_hash(block, text_len, out->hash);
  if (rc != GDEFCORE_OK) {
    free(block);
    return rc;
  }
  out->module = GDEFCORE_SITE_ASSET_OWNER;
  out->module_len = sizeof GDEFCORE_SITE_ASSET_OWNER - 1;
  out->name = (const char *)block + text_len + 1;
  out->name_len = name_len;
  out->kind = kind;
  out->media_type = kind == GDEFCORE_ASSET_CSS ? kCssMedia : kJsMedia;
  out->media_type_len = strlen(out->media_type);
  out->bytes = block;
  out->bytes_len = text_len;
  out->owned = block;
  return GDEFCORE_OK;
}

/* ---- the types and the permissions ------------------------------------------------ */

static void field_set(GDEFCORE_Field * field, const char * name) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = 1;
}

static GDEFCORE_Result declare_edit(GDEFCORE_Catalog * catalog,
    const char * label, const char * action, const char * type) {
  GDEFCORE_Permission perm;
  memset(&perm, 0, sizeof perm);
  perm.size = sizeof perm;
  perm.label = label;
  perm.label_len = strlen(label);
  perm.module_name = "core";
  perm.module_name_len = 4;
  perm.action = action;
  perm.action_len = strlen(action);
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = type;
  perm.type_name_len = strlen(type);
  return gdefcore_access_declare(catalog, &perm);
}

int gdefcore_siteasset_name_ok(const char * name, size_t name_len) {
  return gdefcore_asset_name_ok(name, name_len);
}

GDEFCORE_Result gdefcore_siteasset_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field fields[2];
  size_t t;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  field_set(&fields[0], "name");
  field_set(&fields[1], "text");
  for (t = 0; t < 2 && rc == GDEFCORE_OK; t++) {
    const char * type = t == 0 ? kCssType : kJsType;
    int kind = 0;
    if (gdefcore_type_kind(catalog, type, strlen(type), &kind) != GDEFCORE_OK) {
      rc = gdefcore_type_define(catalog, type, strlen(type), GDEFCORE_TYPE_CONFIG,
          fields, 2);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_edit(catalog, GDEFCORE_ASSET_CSS_EDIT_LABEL,
        GDEFCORE_ASSET_CSS_EDIT, kCssType);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_edit(catalog, GDEFCORE_ASSET_JS_EDIT_LABEL,
        GDEFCORE_ASSET_JS_EDIT, kJsType);
  }
  return rc;
}

int gdefcore_siteasset_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, int kind) {
  const char * action = kind == GDEFCORE_ASSET_CSS ? GDEFCORE_ASSET_CSS_EDIT
                        : kind == GDEFCORE_ASSET_JS ? GDEFCORE_ASSET_JS_EDIT
                                                    : NULL;
  if (catalog == NULL || request == NULL || action == NULL) {
    return 0;
  }
  return gdefcore_access_permits(catalog, request, action, strlen(action)) != 0;
}

/* ---- staging ---------------------------------------------------------------------- */

static void value_set(GDEFCORE_Value * value, const char * field,
    const char ** slot, size_t * len_slot, const char * text, size_t len) {
  memset(value, 0, sizeof *value);
  *slot = text;
  *len_slot = len;
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = slot;
  value->text_lens = len_slot;
  value->count = 1;
}

/* A file's text: UTF-8 with no control character but a tab, a newline and a
 * carriage return (a form posts its line ends as CRLF). It is the rule a
 * module's stylesheet or script has too. */
static int file_text_ok(const char * s, size_t n) {
  if (s == NULL || n == 0 || n > GDEFCORE_ASSET_BYTES_MAX) {
    return 0;
  }
  return gdefcore_text_ok(s, n, 2);
}

GDEFCORE_Result gdefcore_siteasset_stage(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, int kind, const char * text,
    size_t text_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Value values[2];
  const char * slots[2];
  size_t lens[2];
  const char * type = type_of(kind);
  int have_kind = 0;
  GDEFCORE_Result rc;
  if (changeset == NULL || type == NULL || !gdefcore_asset_name_ok(name, name_len) ||
      !file_text_ok(text, text_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  rc = locate(catalog, changeset, name, name_len, NULL, id, &have_kind);
  if (rc == GDEFCORE_OK && have_kind != kind) {
    return GDEFCORE_ERR_INVALID;   /* the name is the other kind's already */
  }
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = gdefcore_entity_create(catalog, type, strlen(type), id, NULL);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  value_set(&values[0], "name", &slots[0], &lens[0], name, name_len);
  value_set(&values[1], "text", &slots[1], &lens[1], text, text_len);
  return gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      sizeof kLang - 1, values, 2);
}

GDEFCORE_Result gdefcore_siteasset_stage_forget(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int kind = 0;
  if (changeset == NULL || !gdefcore_asset_name_ok(name, name_len) ||
      locate(gdefcore_changeset_catalog(changeset), changeset, name, name_len,
          NULL, id, &kind) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_entity_clear(changeset, id, GDEFCORE_PUBLIC_ID_LEN);
}

/* ---- vetting ---------------------------------------------------------------------- */

static GDEFCORE_Result refuse(GDEFCORE_Changeset * changeset, const char * name,
    size_t name_len, const char * why) {
  char text[384];
  size_t shown = name_len > 64 ? 64 : name_len;
  size_t i;
  int plain = 1;
  for (i = 0; i < shown; i++) {
    if ((unsigned char)name[i] < 0x20 || (unsigned char)name[i] > 0x7e) {
      plain = 0;
    }
  }
  snprintf(text, sizeof text, "Site file '%.*s' is refused: %s",
      (int)(plain ? shown : 1), plain ? name : "?", why);
  (void)gdefcore_changeset_set_refusal(changeset, text, strlen(text));
  return GDEFCORE_ERR_INVALID;
}

GDEFCORE_Result gdefcore_siteasset_vet(GDEFCORE_Changeset * changeset) {
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
    int kind;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char other[GDEFCORE_PUBLIC_ID_LEN + 1];
    int other_kind = 0;
    char * name = NULL;
    char * text = NULL;
    size_t name_len = 0;
    size_t text_len = 0;
    GDEFCORE_Result rc;
    GDEFCORE_Result out = GDEFCORE_OK;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type, &type_len,
            &op) != GDEFCORE_OK ||
        (kind = kind_of(type, type_len)) == 0) {
      continue;
    }
    if (op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_UNPUBLISH) {
      continue;   /* nothing is written that a page could name */
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INVALID;
    }
    {
      const GDEFCORE_Changeset * through =
          op == GDEFCORE_TOUCH_PUBLISH ? NULL : changeset;
      int view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT
                                               : GDEFCORE_VIEW_CURRENT;
      rc = gdefcore_render_field_text(catalog, through, view, canon, "name", &name, &name_len);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_render_field_text(catalog, through, view, canon, "text", &text, &text_len);
      }
    }
    if (rc != GDEFCORE_OK) {
      free(name);
      free(text);
      return rc;
    }
    if (!gdefcore_asset_name_ok(name, name_len)) {
      out = refuse(changeset, name, name_len,
          "its name is not 1 to 128 bytes of a-z, 0-9, '.', '_' and '-', "
          "starting with a letter or digit, with no '..'.");
    } else if (!file_text_ok(text, text_len)) {
      out = refuse(changeset, name, name_len,
          "its text is empty, over 4 MiB, or not UTF-8 text.");
    } else {
      rc = locate(catalog, changeset, name, name_len, canon, other, &other_kind);
      if (rc == GDEFCORE_OK) {
        out = refuse(changeset, name, name_len,
            "the site already has a file of that name.");
      } else if (rc != GDEFCORE_ERR_INVALID) {
        out = rc;
      }
    }
    free(name);
    free(text);
    if (out != GDEFCORE_OK) {
      return out;
    }
  }
  return GDEFCORE_OK;
}

/* ---- who may write -------------------------------------------------------------- */

static GDEFCORE_Result decide_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, int kind, const char * id,
    const GDEFCORE_Changeset * through, int view, int * allowed) {
  const char * action = kind == GDEFCORE_ASSET_CSS ? GDEFCORE_ASSET_CSS_EDIT
                                                   : GDEFCORE_ASSET_JS_EDIT;
  const char * type = type_of(kind);
  GDEFCORE_Condition_Value value;
  char * name = NULL;
  size_t name_len = 0;
  size_t revisions = 0;
  int ok = 0;
  GDEFCORE_Result rc;
  *allowed = 0;
  rc = gdefcore_render_field_text(catalog, through, view, id, "name", &name, &name_len);
  if (rc == GDEFCORE_OK && name_len > 0) {
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "name";
    value.field_len = 4;
    value.text = name;
    value.text_len = name_len;
    rc = gdefcore_access_can_with(catalog, request, action, strlen(action), type,
        strlen(type), id, &value, 1, &ok);
    if (rc == GDEFCORE_OK && ok) {
      rc = gdefcore_entity_revision_count(catalog, id, GDEFCORE_PUBLIC_ID_LEN,
          &revisions);
      if (rc == GDEFCORE_OK && revisions > 0) {
        rc = gdefcore_access_can(catalog, request, action, strlen(action), type,
            strlen(type), id, &ok);
      }
    }
  }
  free(name);
  if (rc == GDEFCORE_ERR_OOM) {
    return rc;
  }
  *allowed = rc == GDEFCORE_OK && ok;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_siteasset_authorize(GDEFCORE_Changeset * changeset,
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
    int kind;
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    const GDEFCORE_Changeset * through;
    int view;
    int allowed = 0;
    GDEFCORE_Result rc;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type, &type_len,
            &op) != GDEFCORE_OK ||
        (kind = kind_of(type, type_len)) == 0) {
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
