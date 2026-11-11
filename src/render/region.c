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
 * Region descriptors (region.h): a label and a help text for a region name, from
 * the template's own list, from the shared catalog, or from the name.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/region.h>

#include "../core/asset_util.h"
#include "render_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REGIONS_MAX 32   /* what the port holds of one many-valued field */

static const char kType[] = GDEFCORE_REGION_DESCRIPTOR_TYPE;
static const char kLang[] = "en";
static const char kNotAllowed[] = "That edit is not allowed.";

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

int gdefcore_region_name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > GDEFCORE_REGION_NAME_MAX || s[0] < 'a' ||
      s[0] > 'z') {
    return 0;
  }
  for (i = 1; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' ||
            c == '-')) {
      return 0;
    }
  }
  return 1;
}

static int label_ok(const char * s, size_t n) {
  return n >= 1 && n <= GDEFCORE_REGION_LABEL_MAX && gdefcore_text_ok(s, n, 0);
}

static int description_ok(const char * s, size_t n) {
  return n <= GDEFCORE_REGION_DESCRIPTION_MAX && (n == 0 || gdefcore_text_ok(s, n, 0));
}

/* ---- a template's own lines ------------------------------------------------------- */

/*
 * One line, `name ~label=<text> ~description=<text>`, the values percent-encoded.
 * 1 when well formed; @p name and the decoded texts are copied out.
 */
static int parse_line(const char * s, size_t n, char name[GDEFCORE_REGION_NAME_MAX + 1],
    char label[GDEFCORE_REGION_LABEL_MAX + 1],
    char description[GDEFCORE_REGION_DESCRIPTION_MAX + 1]) {
  size_t i = 0;
  size_t have_label = 0;
  size_t have_description = 0;
  while (i < n && s[i] != ' ') {
    i += 1;
  }
  if (!gdefcore_region_name_ok(s, i)) {
    return 0;
  }
  memcpy(name, s, i);
  name[i] = '\0';
  label[0] = '\0';
  description[0] = '\0';
  while (i < n) {
    size_t b;
    size_t e;
    char decoded[GDEFCORE_REGION_DESCRIPTION_MAX * 3 + 1];
    long dn;
    i += 1;   /* the space */
    b = i;
    while (i < n && s[i] != ' ') {
      i += 1;
    }
    e = i;
    if (e - b > 7 && memcmp(s + b, "~label=", 7) == 0 && !have_label) {
      dn = gdefcore_render_unescape(s + b + 7, e - b - 7, decoded, sizeof decoded);
      if (dn < 0 || !label_ok(decoded, (size_t)dn)) {
        return 0;
      }
      memcpy(label, decoded, (size_t)dn + 1);
      have_label = 1;
    } else if (e - b >= 14 && memcmp(s + b, "~description=", 13) == 0 &&
               !have_description) {
      dn = gdefcore_render_unescape(s + b + 13, e - b - 13, decoded, sizeof decoded);
      if (dn < 0 || !description_ok(decoded, (size_t)dn)) {
        return 0;
      }
      memcpy(description, decoded, (size_t)dn + 1);
      have_description = 1;
    } else {
      return 0;
    }
  }
  return have_label;
}

/* Percent-encode a text so that it holds no space and no `%`. */
static size_t escape(const char * s, size_t n, char * out) {
  static const char kHex[] = "0123456789ABCDEF";
  size_t i;
  size_t o = 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == '%' || c == '~' || c >= 0x7f) {
      out[o++] = '%';
      out[o++] = kHex[c >> 4];
      out[o++] = kHex[c & 0x0f];
    } else {
      out[o++] = (char)c;
    }
  }
  out[o] = '\0';
  return o;
}

/* ---- describing ------------------------------------------------------------------- */

static GDEFCORE_Result copy_text(const char * s, size_t n, char ** out, size_t * out_len) {
  *out = (char *)malloc(n + 1);
  if (*out == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (n > 0) {
    memcpy(*out, s, n);
  }
  (*out)[n] = '\0';
  *out_len = n;
  return GDEFCORE_OK;
}

/* The template's own line for @p region, 1 when there is one. */
static int from_template(GDEFCORE_Catalog * catalog, const char * template_name,
    size_t template_len, const char * region, size_t region_len,
    GDEFCORE_Region_Info * info, GDEFCORE_Result * rc) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** lines = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t i;
  int found = 0;
  if (template_name == NULL || template_len == 0) {
    return 0;
  }
  if (gdefcore_render_find_named(catalog, "core.template", 13, template_name,
          template_len, id) != GDEFCORE_OK ||
      gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
          GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "regions", 7, &lines,
          &lens, &count) != GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < count && !found; i++) {
    char name[GDEFCORE_REGION_NAME_MAX + 1];
    char label[GDEFCORE_REGION_LABEL_MAX + 1];
    char description[GDEFCORE_REGION_DESCRIPTION_MAX + 1];
    if (parse_line(lines[i], lens[i], name, label, description) &&
        span_eq(name, strlen(name), region, region_len)) {
      *rc = copy_text(label, strlen(label), &info->label, &info->label_len);
      if (*rc == GDEFCORE_OK) {
        *rc = copy_text(description, strlen(description), &info->description,
            &info->description_len);
      }
      info->source = GDEFCORE_REGION_SOURCE_TEMPLATE;
      found = 1;
    }
  }
  gdefcore_values_free(catalog, lines, lens, count);
  return found;
}

static int from_shared(GDEFCORE_Catalog * catalog, const char * region,
    size_t region_len, GDEFCORE_Region_Info * info, GDEFCORE_Result * rc) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * label = NULL;
  char * description = NULL;
  size_t label_len = 0;
  size_t description_len = 0;
  if (gdefcore_render_find_named(catalog, kType, sizeof kType - 1, region,
          region_len, id) != GDEFCORE_OK) {
    return 0;
  }
  *rc = gdefcore_render_field_text(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      "label", &label, &label_len);
  if (*rc == GDEFCORE_OK) {
    *rc = gdefcore_render_field_text(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
        "description", &description, &description_len);
  }
  if (*rc == GDEFCORE_OK && label_len > 0) {
    info->label = label;
    info->label_len = label_len;
    info->description = description;
    info->description_len = description_len;
    info->source = GDEFCORE_REGION_SOURCE_SHARED;
    return 1;
  }
  free(label);
  free(description);
  return 0;
}

GDEFCORE_Result gdefcore_region_describe(GDEFCORE_Catalog * catalog,
    const char * template_name, size_t template_len, const char * region,
    size_t region_len, GDEFCORE_Region_Info * info) {
  GDEFCORE_Result rc = GDEFCORE_OK;
  size_t i;
  if (catalog == NULL || info == NULL || info->size != sizeof *info ||
      !gdefcore_region_name_ok(region, region_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  info->label = NULL;
  info->description = NULL;
  info->label_len = 0;
  info->description_len = 0;
  info->source = 0;
  if (from_template(catalog, template_name, template_len, region, region_len, info,
          &rc) ||
      rc != GDEFCORE_OK) {
    if (rc != GDEFCORE_OK) {
      gdefcore_region_info_free(catalog, info);
    }
    return rc;
  }
  if (from_shared(catalog, region, region_len, info, &rc) || rc != GDEFCORE_OK) {
    if (rc != GDEFCORE_OK) {
      gdefcore_region_info_free(catalog, info);
    }
    return rc;
  }
  /* The name, made readable: separators are spaces and the first letter is a capital. */
  rc = copy_text(region, region_len, &info->label, &info->label_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < info->label_len; i++) {
    if (info->label[i] == '_' || info->label[i] == '-') {
      info->label[i] = ' ';
    }
  }
  if (info->label[0] >= 'a' && info->label[0] <= 'z') {
    info->label[0] = (char)(info->label[0] - 'a' + 'A');
  }
  rc = copy_text("", 0, &info->description, &info->description_len);
  info->source = GDEFCORE_REGION_SOURCE_NAME;
  if (rc != GDEFCORE_OK) {
    gdefcore_region_info_free(catalog, info);
  }
  return rc;
}

void gdefcore_region_info_free(GDEFCORE_Catalog * catalog, GDEFCORE_Region_Info * info) {
  (void)catalog;
  if (info != NULL) {
    free(info->label);
    free(info->description);
    info->label = NULL;
    info->description = NULL;
    info->label_len = 0;
    info->description_len = 0;
  }
}

/* ---- the type and the permission -------------------------------------------------- */

static void field_set(GDEFCORE_Field * field, const char * name, int required) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = required;
  field->many = !required;
}

GDEFCORE_Result gdefcore_region_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field fields[3];
  GDEFCORE_Permission perm;
  int kind = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  field_set(&fields[0], "name", 1);
  field_set(&fields[1], "label", 1);
  field_set(&fields[2], "description", 0);
  if (gdefcore_type_kind(catalog, kType, sizeof kType - 1, &kind) != GDEFCORE_OK) {
    rc = gdefcore_type_define(catalog, kType, sizeof kType - 1, GDEFCORE_TYPE_CONFIG,
        fields, 3);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&perm, 0, sizeof perm);
  perm.size = sizeof perm;
  perm.label = GDEFCORE_REGION_EDIT_LABEL;
  perm.label_len = sizeof GDEFCORE_REGION_EDIT_LABEL - 1;
  perm.module_name = "core";
  perm.module_name_len = 4;
  perm.action = GDEFCORE_REGION_EDIT;
  perm.action_len = sizeof GDEFCORE_REGION_EDIT - 1;
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = kType;
  perm.type_name_len = sizeof kType - 1;
  return gdefcore_access_declare(catalog, &perm);
}

int gdefcore_region_may_edit(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request) {
  if (catalog == NULL || request == NULL) {
    return 0;
  }
  return gdefcore_access_permits(catalog, request, GDEFCORE_REGION_EDIT,
             sizeof GDEFCORE_REGION_EDIT - 1) != 0;
}

/* ---- staging ---------------------------------------------------------------------- */

static void value_set(GDEFCORE_Value * value, const char * field, const char ** slot,
    size_t * len_slot, const char * text, size_t len, int set) {
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

GDEFCORE_Result gdefcore_region_stage_shared(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const char * label, size_t label_len,
    const char * description, size_t description_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Value values[3];
  const char * slots[3];
  size_t lens[3];
  GDEFCORE_Result rc;
  if (description == NULL) {
    description_len = 0;
  }
  if (changeset == NULL || !gdefcore_region_name_ok(name, name_len) ||
      !label_ok(label, label_len) || !description_ok(description, description_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  rc = gdefcore_render_find_named(catalog, kType, sizeof kType - 1, name, name_len, id);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = gdefcore_entity_create(catalog, kType, sizeof kType - 1, id, NULL);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  value_set(&values[0], "name", &slots[0], &lens[0], name, name_len, 1);
  value_set(&values[1], "label", &slots[1], &lens[1], label, label_len, 1);
  value_set(&values[2], "description", &slots[2], &lens[2], description,
      description_len, description_len > 0);
  return gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      sizeof kLang - 1, values, 3);
}

GDEFCORE_Result gdefcore_region_stage_shared_forget(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  if (changeset == NULL || !gdefcore_region_name_ok(name, name_len) ||
      gdefcore_render_find_named(gdefcore_changeset_catalog(changeset), kType,
          sizeof kType - 1, name, name_len, id) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_entity_clear(changeset, id, GDEFCORE_PUBLIC_ID_LEN);
}

GDEFCORE_Result gdefcore_region_stage_template(GDEFCORE_Changeset * changeset,
    const char * template_name, size_t template_len, const char * region,
    size_t region_len, const char * label, size_t label_len,
    const char * description, size_t description_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Catalog * catalog;
  char ** old = NULL;
  size_t * old_lens = NULL;
  size_t nold = 0;
  char * lines[REGIONS_MAX + 1];
  size_t line_lens[REGIONS_MAX + 1];
  const char * slots[REGIONS_MAX + 1];
  size_t nlines = 0;
  size_t i;
  GDEFCORE_Value value;
  GDEFCORE_Result rc;
  int removing;
  if (label == NULL) {
    label_len = 0;
  }
  if (description == NULL) {
    description_len = 0;
  }
  removing = label_len == 0;
  if (changeset == NULL || template_name == NULL || template_len == 0 ||
      !gdefcore_region_name_ok(region, region_len) ||
      (!removing && (!label_ok(label, label_len) ||
                        !description_ok(description, description_len)))) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  if (gdefcore_render_find_named(catalog, "core.template", 13, template_name,
          template_len, id) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_entity_values(catalog, changeset, GDEFCORE_VIEW_CURRENT, id,
      GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "regions", 7, &old,
      &old_lens, &nold);
  if (rc == GDEFCORE_ERR_INVALID) {
    old = NULL;
    old_lens = NULL;
    nold = 0;
    rc = GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < nold && rc == GDEFCORE_OK; i++) {
    char name[GDEFCORE_REGION_NAME_MAX + 1];
    char l[GDEFCORE_REGION_LABEL_MAX + 1];
    char d[GDEFCORE_REGION_DESCRIPTION_MAX + 1];
    if (parse_line(old[i], old_lens[i], name, l, d) &&
        span_eq(name, strlen(name), region, region_len)) {
      continue;   /* replaced, or taken away */
    }
    if (nlines >= REGIONS_MAX) {
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    lines[nlines] = (char *)malloc(old_lens[i] + 1);
    if (lines[nlines] == NULL) {
      rc = GDEFCORE_ERR_OOM;
      break;
    }
    memcpy(lines[nlines], old[i], old_lens[i]);
    lines[nlines][old_lens[i]] = '\0';
    line_lens[nlines] = old_lens[i];
    nlines += 1;
  }
  gdefcore_values_free(catalog, old, old_lens, nold);
  if (rc == GDEFCORE_OK && !removing) {
    size_t cap = region_len + 1 + 8 + label_len * 3 + 1 + 13 + description_len * 3 + 1;
    char * line = (char *)malloc(cap);
    if (nlines >= REGIONS_MAX || line == NULL) {
      free(line);
      rc = line == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_ERR_INVALID;
    } else {
      size_t at = 0;
      memcpy(line, region, region_len);
      at = region_len;
      memcpy(line + at, " ~label=", 8);
      at += 8;
      at += escape(label, label_len, line + at);
      if (description_len > 0) {
        memcpy(line + at, " ~description=", 14);
        at += 14;
        at += escape(description, description_len, line + at);
      }
      lines[nlines] = line;
      line_lens[nlines] = at;
      nlines += 1;
    }
  }
  if (rc == GDEFCORE_OK) {
    for (i = 0; i < nlines; i++) {
      slots[i] = lines[i];
    }
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "regions";
    value.field_len = 7;
    value.texts = slots;
    value.text_lens = line_lens;
    value.count = nlines;
    rc = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
        sizeof kLang - 1, &value, 1);
  }
  for (i = 0; i < nlines; i++) {
    free(lines[i]);
  }
  return rc;
}

/* ---- vetting ---------------------------------------------------------------------- */

static GDEFCORE_Result refuse(GDEFCORE_Changeset * changeset, const char * what,
    const char * why) {
  char text[320];
  snprintf(text, sizeof text, "%s is refused: %s", what, why);
  (void)gdefcore_changeset_set_refusal(changeset, text, strlen(text));
  return GDEFCORE_ERR_INVALID;
}

GDEFCORE_Result gdefcore_region_vet(GDEFCORE_Changeset * changeset) {
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
    GDEFCORE_Result rc = GDEFCORE_OK;
    const GDEFCORE_Changeset * through;
    int view;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type, &type_len,
            &op) != GDEFCORE_OK ||
        type == NULL || op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_UNPUBLISH ||
        gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      continue;
    }
    through = op == GDEFCORE_TOUCH_PUBLISH ? NULL : changeset;
    view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT : GDEFCORE_VIEW_CURRENT;
    if (span_eq(type, type_len, kType, sizeof kType - 1)) {
      char * name = NULL;
      char * label = NULL;
      char * description = NULL;
      size_t nl = 0;
      size_t ll = 0;
      size_t dl = 0;
      rc = gdefcore_render_field_text(catalog, through, view, canon, "name", &name, &nl);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_render_field_text(catalog, through, view, canon, "label", &label,
            &ll);
      }
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_render_field_text(catalog, through, view, canon, "description",
            &description, &dl);
      }
      if (rc == GDEFCORE_OK) {
        if (!gdefcore_region_name_ok(name, nl)) {
          rc = refuse(changeset, "A region descriptor",
              "its name is a-z first, then a-z, 0-9, '_' and '-', at most 63 bytes.");
        } else if (!label_ok(label, ll)) {
          rc = refuse(changeset, "A region descriptor",
              "its label is 1 to 64 bytes of text.");
        } else if (!description_ok(description, dl)) {
          rc = refuse(changeset, "A region descriptor",
              "its description is at most 256 bytes of text.");
        }
      }
      free(name);
      free(label);
      free(description);
    } else if (span_eq(type, type_len, "core.template", 13)) {
      char ** lines = NULL;
      size_t * lens = NULL;
      size_t n = 0;
      size_t k;
      size_t j;
      rc = gdefcore_entity_values(catalog, through, view, canon,
          GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "regions", 7, &lines, &lens,
          &n);
      if (rc == GDEFCORE_ERR_INVALID) {
        rc = GDEFCORE_OK;
        continue;
      }
      if (rc != GDEFCORE_OK) {
        return rc;
      }
      if (n > REGIONS_MAX) {
        rc = refuse(changeset, "A page template", "it holds at most 32 region descriptors.");
      }
      for (k = 0; k < n && rc == GDEFCORE_OK; k++) {
        char name[GDEFCORE_REGION_NAME_MAX + 1];
        char label[GDEFCORE_REGION_LABEL_MAX + 1];
        char description[GDEFCORE_REGION_DESCRIPTION_MAX + 1];
        char other[GDEFCORE_REGION_NAME_MAX + 1];
        if (!parse_line(lines[k], lens[k], name, label, description)) {
          rc = refuse(changeset, "A page template",
              "a region descriptor is not 'name ~label=text [~description=text]'.");
          break;
        }
        for (j = 0; j < k; j++) {
          char l2[GDEFCORE_REGION_LABEL_MAX + 1];
          char d2[GDEFCORE_REGION_DESCRIPTION_MAX + 1];
          if (parse_line(lines[j], lens[j], other, l2, d2) && strcmp(other, name) == 0) {
            rc = refuse(changeset, "A page template",
                "it describes a region twice.");
            break;
          }
        }
      }
      gdefcore_values_free(catalog, lines, lens, n);
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  return GDEFCORE_OK;
}

/* ---- who may write ---------------------------------------------------------------- */

GDEFCORE_Result gdefcore_region_authorize(GDEFCORE_Changeset * changeset,
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
    int ok = 0;
    GDEFCORE_Result rc;
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type, &type_len,
            &op) != GDEFCORE_OK ||
        type == NULL || !span_eq(type, type_len, kType, sizeof kType - 1)) {
      continue;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      (void)gdefcore_changeset_set_refusal(changeset, kNotAllowed, sizeof kNotAllowed - 1);
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_access_can(catalog, request, GDEFCORE_REGION_EDIT,
        sizeof GDEFCORE_REGION_EDIT - 1, kType, sizeof kType - 1, canon, &ok);
    if (rc == GDEFCORE_ERR_OOM) {
      return rc;
    }
    if (rc != GDEFCORE_OK || !ok) {
      (void)gdefcore_changeset_set_refusal(changeset, kNotAllowed, sizeof kNotAllowed - 1);
      return GDEFCORE_ERR_INVALID;
    }
  }
  return GDEFCORE_OK;
}

/* ---- the defaults a site starts with ---------------------------------------------- */

GDEFCORE_Result gdefcore_render_region_seed(GDEFCORE_Catalog * catalog) {
  static const struct {
    const char * name;
    const char * label;
    const char * description;
  } kDefaults[] = {
      {"main", "Main content area", "Where the page's own content goes."},
      {"side", "Side area", "Shown beside the main content."},
      {"header", "Header", "The top of the page."},
      {"navigation", "Navigation", "Menus and ways around the site."},
      {"footer", "Footer", "The bottom of the page."},
  };
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  size_t i;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < sizeof kDefaults / sizeof kDefaults[0] && rc == GDEFCORE_OK; i++) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    /* A site's own descriptor for a default name is left as it is. */
    if (gdefcore_render_find_named(catalog, kType, sizeof kType - 1, kDefaults[i].name,
            strlen(kDefaults[i].name), id) == GDEFCORE_OK) {
      continue;
    }
    rc = gdefcore_region_stage_shared(cs, kDefaults[i].name, strlen(kDefaults[i].name),
        kDefaults[i].label, strlen(kDefaults[i].label), kDefaults[i].description,
        strlen(kDefaults[i].description));
  }
  if (rc == GDEFCORE_OK && gdefcore_changeset_touched_count(cs) > 0) {
    rc = gdefcore_changeset_apply(cs, kType, sizeof kType - 1);
  }
  gdefcore_changeset_destroy(cs);
  return rc;
}
