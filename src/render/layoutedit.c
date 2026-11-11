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
 * Changing a layout one placement at a time (layoutedit.h).
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/layout.h>
#include <ghoti.io/defiant-core/layoutedit.h>
#include <ghoti.io/defiant-core/render.h>

#include "../core/asset_util.h"
#include "render_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kLang[] = "en";
static const char kDisplay[] = "core.display";

/* ---- a placement as a struct ------------------------------------------------------ */

int gdefcore_placement_parse(const char * line, size_t n, int has_region,
    GDEFCORE_Placement * out) {
  char * with = NULL;
  const char * s = line;
  size_t sn = n;
  const char * region;
  const char * widget;
  const char * target;
  size_t region_len = 0;
  size_t widget_len = 0;
  size_t target_len = 0;
  GdefPane extras;
  size_t i;
  int ok = 0;
  if (out == NULL || line == NULL) {
    return 0;
  }
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  if (!has_region) {
    with = (char *)malloc(n + 3);
    if (with == NULL) {
      return 0;
    }
    memcpy(with, "x ", 2);
    memcpy(with + 2, line, n);
    s = with;
    sn = n + 2;
  }
  if (gdefcore_render_split_pane(s, sn, &region, &region_len, &widget, &widget_len,
          &target, &target_len) &&
      gdefcore_render_pane_extras(s, sn, &extras, NULL, 0) &&
      region_len <= GDEFCORE_REGION_NAME_MAX && widget_len <= GDEFCORE_LAYOUT_NAME_MAX &&
      target_len <= GDEFCORE_PLACEMENT_TARGET_MAX) {
    if (has_region) {
      memcpy(out->region, region, region_len);
      out->region[region_len] = '\0';
    }
    memcpy(out->widget, widget, widget_len);
    out->widget[widget_len] = '\0';
    memcpy(out->target, target, target_len);
    out->target[target_len] = '\0';
    memcpy(out->title, extras.title, extras.title_len + 1);
    memcpy(out->path, extras.path, extras.path_len + 1);
    memcpy(out->type, extras.type, extras.type_len + 1);
    out->nroles = extras.nroles;
    for (i = 0; i < extras.nroles; i++) {
      memcpy(out->roles[i], extras.roles[i], strlen(extras.roles[i]) + 1);
    }
    ok = 1;
  }
  free(with);
  return ok;
}

size_t gdefcore_placement_format(const GDEFCORE_Placement * p, int with_region, char * out,
    size_t cap) {
  size_t at = 0;
  size_t i;
  /* Room for the longest: every byte escaped, and the keys. */
  size_t need;
  char * buf;
  if (p == NULL || p->size != sizeof *p || out == NULL || p->widget[0] == '\0' ||
      (with_region && p->region[0] == '\0')) {
    return 0;
  }
  need = 4 + strlen(p->region) + strlen(p->widget) + strlen(p->target) + 3 * (strlen(p->title) +
      strlen(p->path) + strlen(p->type)) + p->nroles * (3 * GDEFCORE_PLACEMENT_ROLE_MAX + 8) + 64;
  buf = (char *)malloc(need);
  if (buf == NULL) {
    return 0;
  }
  if (with_region) {
    at += (size_t)sprintf(buf + at, "%s ", p->region);
  }
  at += (size_t)sprintf(buf + at, "%s", p->widget);
  if (p->target[0] != '\0') {
    at += (size_t)sprintf(buf + at, " %s", p->target);
  }
  if (p->title[0] != '\0') {
    at += (size_t)sprintf(buf + at, " ~title=");
    at += gdefcore_render_escape(p->title, strlen(p->title), buf + at);
  }
  if (p->path[0] != '\0') {
    at += (size_t)sprintf(buf + at, " ~path=");
    at += gdefcore_render_escape(p->path, strlen(p->path), buf + at);
  }
  if (p->type[0] != '\0') {
    at += (size_t)sprintf(buf + at, " ~type=");
    at += gdefcore_render_escape(p->type, strlen(p->type), buf + at);
  }
  for (i = 0; i < p->nroles && i < GDEFCORE_PLACEMENT_ROLES_MAX; i++) {
    at += (size_t)sprintf(buf + at, " ~role=");
    at += gdefcore_render_escape(p->roles[i], strlen(p->roles[i]), buf + at);
  }
  if (at + 1 > cap) {
    free(buf);
    return 0;
  }
  memcpy(out, buf, at + 1);
  free(buf);
  return at;
}

/* ---- reading a layout ------------------------------------------------------------- */

static void version_of(char ** panes, const size_t * lens, size_t n, char ** unplaced,
    const size_t * ulens, size_t un, char out[GDEFCORE_LAYOUT_VERSION_LEN + 1]) {
  size_t total = 24;
  size_t i;
  char * buf;
  size_t at = 0;
  for (i = 0; i < n; i++) {
    total += lens[i] + 1;
  }
  for (i = 0; i < un; i++) {
    total += ulens[i] + 1;
  }
  buf = (char *)malloc(total);
  if (buf == NULL) {
    memset(out, '0', GDEFCORE_LAYOUT_VERSION_LEN);
    out[GDEFCORE_LAYOUT_VERSION_LEN] = '\0';
    return;
  }
  memcpy(buf, "panes\n", 6);
  at = 6;
  for (i = 0; i < n; i++) {
    memcpy(buf + at, panes[i], lens[i]);
    at += lens[i];
    buf[at++] = '\n';
  }
  memcpy(buf + at, "unplaced\n", 9);
  at += 9;
  for (i = 0; i < un; i++) {
    memcpy(buf + at, unplaced[i], ulens[i]);
    at += ulens[i];
    buf[at++] = '\n';
  }
  if (gdefcore_asset_hash((const uint8_t *)buf, at, out) != GDEFCORE_OK) {
    memset(out, '0', GDEFCORE_LAYOUT_VERSION_LEN);
    out[GDEFCORE_LAYOUT_VERSION_LEN] = '\0';
  }
  free(buf);
}

void gdefcore_layout_view_free(GDEFCORE_Layout_View * view) {
  size_t i;
  if (view == NULL) {
    return;
  }
  free(view->template_name);
  for (i = 0; i < view->nregions; i++) {
    free(view->regions[i]);
  }
  free(view->regions);
  free(view->placed);
  free(view->unplaced);
  view->template_name = NULL;
  view->regions = NULL;
  view->placed = NULL;
  view->unplaced = NULL;
  view->nregions = 0;
  view->nplaced = 0;
  view->nunplaced = 0;
}

static GDEFCORE_Result load_lines(GDEFCORE_Catalog * catalog, const char * id,
    const char * field, char *** lines, size_t ** lens, size_t * count) {
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, field, strlen(field), lines, lens,
      count);
  if (rc == GDEFCORE_ERR_INVALID) {
    *lines = NULL;
    *lens = NULL;
    *count = 0;
    rc = GDEFCORE_OK;
  }
  return rc;
}

GDEFCORE_Result gdefcore_layout_view(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, GDEFCORE_Layout_View * out) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** panes = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  char ** unplaced = NULL;
  size_t * ulens = NULL;
  size_t un = 0;
  char ** names = NULL;
  size_t nnames = 0;
  size_t tlen = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || name == NULL || out == NULL || out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  memset((char *)out + sizeof out->size, 0, sizeof *out - sizeof out->size);
  rc = gdefcore_render_find_named(catalog, kDisplay, sizeof kDisplay - 1, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_render_field_text(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "layout",
      &out->template_name, &tlen);
  if (rc == GDEFCORE_OK) {
    rc = load_lines(catalog, id, "panes", &panes, &lens, &n);
  }
  if (rc == GDEFCORE_OK) {
    rc = load_lines(catalog, id, "unplaced", &unplaced, &ulens, &un);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_render_regions(catalog, out->template_name, tlen, &names, &nnames);
    if (rc == GDEFCORE_ERR_INVALID) {
      names = NULL;
      nnames = 0;
      rc = GDEFCORE_OK;   /* a layout whose template is gone has no regions to show */
    }
  }
  if (rc == GDEFCORE_OK) {
    out->regions = (char **)calloc(nnames == 0 ? 1 : nnames, sizeof *out->regions);
    out->placed = (GDEFCORE_Placement *)calloc(n == 0 ? 1 : n, sizeof *out->placed);
    out->unplaced = (GDEFCORE_Placement *)calloc(un == 0 ? 1 : un, sizeof *out->unplaced);
    if (out->regions == NULL || out->placed == NULL || out->unplaced == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  for (i = 0; rc == GDEFCORE_OK && i < nnames; i++) {
    out->regions[i] = (char *)malloc(strlen(names[i]) + 1);
    if (out->regions[i] == NULL) {
      rc = GDEFCORE_ERR_OOM;
      break;
    }
    memcpy(out->regions[i], names[i], strlen(names[i]) + 1);
    out->nregions = i + 1;
  }
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    if (!gdefcore_placement_parse(panes[i], lens[i], 1, &out->placed[i])) {
      rc = GDEFCORE_ERR_INVALID;
    }
    out->nplaced = i + 1;
  }
  for (i = 0; rc == GDEFCORE_OK && i < un; i++) {
    if (!gdefcore_placement_parse(unplaced[i], ulens[i], 0, &out->unplaced[i])) {
      rc = GDEFCORE_ERR_INVALID;
    }
    out->nunplaced = i + 1;
  }
  if (rc == GDEFCORE_OK) {
    version_of(panes, lens, n, unplaced, ulens, un, out->version);
  }
  gdefcore_values_free(catalog, panes, lens, n);
  gdefcore_values_free(catalog, unplaced, ulens, un);
  gdefcore_render_names_free(catalog, names, nnames);
  if (rc != GDEFCORE_OK) {
    gdefcore_layout_view_free(out);
  }
  return rc;
}

/* ---- editing ---------------------------------------------------------------------- */

static GDEFCORE_Result refuse(GDEFCORE_Changeset * changeset, const char * sentence) {
  (void)gdefcore_changeset_set_refusal(changeset, sentence, strlen(sentence));
  return GDEFCORE_ERR_INVALID;
}

static int has_region(const GDEFCORE_Layout_View * v, const char * region, size_t len) {
  size_t i;
  for (i = 0; i < v->nregions; i++) {
    if (strlen(v->regions[i]) == len && memcmp(v->regions[i], region, len) == 0) {
      return 1;
    }
  }
  return 0;
}

/* Put @p p in the placed list so that it is the @p position-th of its region. */
static void insert_at(GDEFCORE_Placement * list, size_t * n, const GDEFCORE_Placement * p,
    size_t position) {
  size_t seen = 0;
  size_t at = *n;
  size_t i;
  for (i = 0; i < *n; i++) {
    if (strcmp(list[i].region, p->region) == 0) {
      if (seen == position) {
        at = i;
        break;
      }
      seen += 1;
      at = i + 1;
    }
  }
  memmove(list + at + 1, list + at, (*n - at) * sizeof *list);
  list[at] = *p;
  *n += 1;
}

static void delete_at(GDEFCORE_Placement * list, size_t * n, size_t at) {
  memmove(list + at, list + at + 1, (*n - at - 1) * sizeof *list);
  *n -= 1;
}

static void copy_settings(GDEFCORE_Placement * to, const GDEFCORE_Placement * from) {
  size_t i;
  memcpy(to->target, from->target, sizeof to->target);
  memcpy(to->title, from->title, sizeof to->title);
  memcpy(to->path, from->path, sizeof to->path);
  memcpy(to->type, from->type, sizeof to->type);
  to->nroles = from->nroles;
  for (i = 0; i < GDEFCORE_PLACEMENT_ROLES_MAX; i++) {
    memcpy(to->roles[i], from->roles[i], sizeof to->roles[i]);
  }
}

/* A placement that would be read back as itself. */
static int placement_ok(const GDEFCORE_Placement * p, int with_region) {
  char line[4096];
  GDEFCORE_Placement back;
  size_t n = gdefcore_placement_format(p, with_region, line, sizeof line);
  return n > 0 && gdefcore_placement_parse(line, n, with_region, &back) &&
         strcmp(back.widget, p->widget) == 0 && strcmp(back.target, p->target) == 0 &&
         strcmp(back.title, p->title) == 0 && strcmp(back.path, p->path) == 0 &&
         strcmp(back.type, p->type) == 0 && back.nroles == p->nroles;
}

static int widget_exists(GDEFCORE_Catalog * catalog, const char * widget) {
  GDEFCORE_Layout_Widget w;
  memset(&w, 0, sizeof w);
  w.size = sizeof w;
  return gdefcore_layout_widget_find(catalog, widget, strlen(widget), &w) == GDEFCORE_OK;
}

static int lines_of(const GDEFCORE_Placement * list, size_t n, int with_region, char *** out,
    size_t ** lens) {
  size_t i;
  *out = (char **)calloc(n == 0 ? 1 : n, sizeof **out);
  *lens = (size_t *)calloc(n == 0 ? 1 : n, sizeof **lens);
  if (*out == NULL || *lens == NULL) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char line[4096];
    size_t len = gdefcore_placement_format(&list[i], with_region, line, sizeof line);
    if (len == 0) {
      return 0;
    }
    (*out)[i] = (char *)malloc(len + 1);
    if ((*out)[i] == NULL) {
      return 0;
    }
    memcpy((*out)[i], line, len + 1);
    (*lens)[i] = len;
  }
  return 1;
}

static void free_lines(char ** lines, size_t * lens, size_t n) {
  size_t i;
  if (lines != NULL) {
    for (i = 0; i < n; i++) {
      free(lines[i]);
    }
  }
  free(lines);
  free(lens);
}

GDEFCORE_Result gdefcore_layout_stage_edit(GDEFCORE_Changeset * changeset,
    const GDEFCORE_Layout_Edit * edit) {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Layout_View view;
  GDEFCORE_Placement * placed = NULL;
  GDEFCORE_Placement * unplaced = NULL;
  size_t n;
  size_t un;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** lines = NULL;
  size_t * lens = NULL;
  char ** ulines = NULL;
  size_t * ulens = NULL;
  char ** old_lines = NULL;
  size_t * old_lens = NULL;
  size_t old_n = 0;
  char ** old_u = NULL;
  size_t * old_ulens = NULL;
  size_t old_un = 0;
  GDEFCORE_Value values[2];
  const char ** slots1 = NULL;
  const char ** slots2 = NULL;
  size_t i;
  GDEFCORE_Result rc;
  GDEFCORE_Result out = GDEFCORE_OK;
  GDEFCORE_Placement moved;
  int same;
  if (changeset == NULL || edit == NULL || edit->size != sizeof *edit || edit->layout == NULL ||
      edit->version == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  memset(&view, 0, sizeof view);
  view.size = sizeof view;
  rc = gdefcore_layout_view(catalog, edit->layout, edit->layout_len, &view);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (edit->version_len != GDEFCORE_LAYOUT_VERSION_LEN ||
      memcmp(edit->version, view.version, GDEFCORE_LAYOUT_VERSION_LEN) != 0) {
    gdefcore_layout_view_free(&view);
    return refuse(changeset, GDEFCORE_LAYOUT_REFUSED_STALE);
  }
  placed = (GDEFCORE_Placement *)calloc(GDEFCORE_LAYOUT_PANES_MAX + 2, sizeof *placed);
  unplaced = (GDEFCORE_Placement *)calloc(GDEFCORE_LAYOUT_PANES_MAX + 2, sizeof *unplaced);
  if (placed == NULL || unplaced == NULL) {
    free(placed);
    free(unplaced);
    gdefcore_layout_view_free(&view);
    return GDEFCORE_ERR_OOM;
  }
  n = view.nplaced;
  un = view.nunplaced;
  if (n > GDEFCORE_LAYOUT_PANES_MAX || un > GDEFCORE_LAYOUT_PANES_MAX) {
    out = GDEFCORE_ERR_INVALID;
    goto done;
  }
  memcpy(placed, view.placed, n * sizeof *placed);
  memcpy(unplaced, view.unplaced, un * sizeof *unplaced);
  memset(&moved, 0, sizeof moved);
  switch (edit->action) {
  case GDEFCORE_LAYOUT_ACT_PLACE:
    moved = edit->placement;
    if (moved.size != sizeof moved) {
      out = GDEFCORE_ERR_INVALID;
      goto done;
    }
    memcpy(moved.region, edit->region, edit->region_len < sizeof moved.region ? edit->region_len : 0);
    moved.region[edit->region_len < sizeof moved.region ? edit->region_len : 0] = '\0';
    if (!has_region(&view, moved.region, strlen(moved.region))) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_REGION);
    } else if (!widget_exists(catalog, moved.widget)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_WIDGET);
    } else if (n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else if (!placement_ok(&moved, 1)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_PART);
    } else {
      insert_at(placed, &n, &moved, edit->position);
    }
    break;
  case GDEFCORE_LAYOUT_ACT_PLACE_UNPLACED:
    if (edit->index >= un) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_THERE);
      break;
    }
    moved = unplaced[edit->index];
    memcpy(moved.region, edit->region, edit->region_len < sizeof moved.region ? edit->region_len : 0);
    moved.region[edit->region_len < sizeof moved.region ? edit->region_len : 0] = '\0';
    if (!has_region(&view, moved.region, strlen(moved.region))) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_REGION);
    } else if (!widget_exists(catalog, moved.widget)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_WIDGET);
    } else if (n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else {
      delete_at(unplaced, &un, edit->index);
      insert_at(placed, &n, &moved, edit->position);
    }
    break;
  case GDEFCORE_LAYOUT_ACT_MOVE:
    if (edit->index >= n) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_THERE);
      break;
    }
    moved = placed[edit->index];
    memcpy(moved.region, edit->region, edit->region_len < sizeof moved.region ? edit->region_len : 0);
    moved.region[edit->region_len < sizeof moved.region ? edit->region_len : 0] = '\0';
    if (!has_region(&view, moved.region, strlen(moved.region))) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_REGION);
    } else {
      delete_at(placed, &n, edit->index);
      insert_at(placed, &n, &moved, edit->position);
    }
    break;
  case GDEFCORE_LAYOUT_ACT_CONFIGURE: {
    GDEFCORE_Placement * target = edit->from_unplaced ? unplaced : placed;
    size_t count = edit->from_unplaced ? un : n;
    if (edit->index >= count) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_THERE);
      break;
    }
    moved = target[edit->index];
    copy_settings(&moved, &edit->placement);
    if (!placement_ok(&moved, !edit->from_unplaced)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_PART);
    } else {
      target[edit->index] = moved;
    }
    break;
  }
  case GDEFCORE_LAYOUT_ACT_REMOVE:
    if (edit->from_unplaced) {
      if (edit->index >= un) {
        out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_THERE);
      } else {
        delete_at(unplaced, &un, edit->index);
      }
    } else if (edit->index >= n) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_THERE);
    } else {
      delete_at(placed, &n, edit->index);
    }
    break;
  case GDEFCORE_LAYOUT_ACT_UNPLACE:
    if (edit->index >= n) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_THERE);
    } else if (un >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else {
      moved = placed[edit->index];
      moved.region[0] = '\0';
      delete_at(placed, &n, edit->index);
      unplaced[un++] = moved;
    }
    break;
  default:
    out = GDEFCORE_ERR_INVALID;
    break;
  }
  if (out != GDEFCORE_OK) {
    goto done;
  }
  if (!lines_of(placed, n, 1, &lines, &lens) || !lines_of(unplaced, un, 0, &ulines, &ulens)) {
    out = GDEFCORE_ERR_OOM;
    goto done;
  }
  /* What changed nothing stages nothing. */
  rc = gdefcore_render_find_named(catalog, kDisplay, sizeof kDisplay - 1, edit->layout,
      edit->layout_len, id);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
        GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "panes", 5, &old_lines, &old_lens,
        &old_n);
    if (rc == GDEFCORE_ERR_INVALID) {
      old_lines = NULL;
      old_lens = NULL;
      old_n = 0;
      rc = GDEFCORE_OK;
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
        GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, "unplaced", 8, &old_u, &old_ulens,
        &old_un);
    if (rc == GDEFCORE_ERR_INVALID) {
      old_u = NULL;
      old_ulens = NULL;
      old_un = 0;
      rc = GDEFCORE_OK;
    }
  }
  if (rc != GDEFCORE_OK) {
    out = rc;
    goto done;
  }
  same = old_n == n && old_un == un;
  for (i = 0; same && i < n; i++) {
    same = old_lens[i] == lens[i] && memcmp(old_lines[i], lines[i], lens[i]) == 0;
  }
  for (i = 0; same && i < un; i++) {
    same = old_ulens[i] == ulens[i] && memcmp(old_u[i], ulines[i], ulens[i]) == 0;
  }
  if (same) {
    goto done;
  }
  slots1 = (const char **)calloc(n == 0 ? 1 : n, sizeof *slots1);
  slots2 = (const char **)calloc(un == 0 ? 1 : un, sizeof *slots2);
  if (slots1 == NULL || slots2 == NULL) {
    out = GDEFCORE_ERR_OOM;
    goto done;
  }
  for (i = 0; i < n; i++) {
    slots1[i] = lines[i];
  }
  for (i = 0; i < un; i++) {
    slots2[i] = ulines[i];
  }
  memset(values, 0, sizeof values);
  values[0].size = sizeof values[0];
  values[0].field = "panes";
  values[0].field_len = 5;
  values[0].texts = slots1;
  values[0].text_lens = lens;
  values[0].count = n;
  values[1].size = sizeof values[1];
  values[1].field = "unplaced";
  values[1].field_len = 8;
  values[1].texts = slots2;
  values[1].text_lens = ulens;
  values[1].count = un;
  out = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1,
      values, 2);
done:
  free(slots1);
  free(slots2);
  free_lines(lines, lens, n);
  free_lines(ulines, ulens, un);
  gdefcore_values_free(catalog, old_lines, old_lens, old_n);
  gdefcore_values_free(catalog, old_u, old_ulens, old_un);
  free(placed);
  free(unplaced);
  gdefcore_layout_view_free(&view);
  return out;
}

/* ---- carrying placements when a template's regions change ---------------------------- */

static int in_list(const char * const * list, size_t n, const char * name) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (strcmp(list[i], name) == 0) {
      return 1;
    }
  }
  return 0;
}

GDEFCORE_Result gdefcore_layout_stage_carry(GDEFCORE_Changeset * changeset, const char * layout,
    size_t layout_len, const char * const * regions, size_t nregions,
    const char * const * rename_from, const char * const * rename_to, size_t nrenames,
    char ** report, size_t * report_len) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(changeset);
  GDEFCORE_Layout_View view;
  GDEFCORE_Placement * placed;
  GDEFCORE_Placement * unplaced;
  size_t n;
  size_t un;
  size_t i;
  size_t k;
  size_t out_n = 0;
  int changed = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** lines = NULL;
  size_t * lens = NULL;
  char ** ulines = NULL;
  size_t * ulens = NULL;
  const char ** slots1 = NULL;
  const char ** slots2 = NULL;
  GDEFCORE_Value values[2];
  GDEFCORE_Result rc;
  GDEFCORE_Result out = GDEFCORE_OK;
  memset(&view, 0, sizeof view);
  view.size = sizeof view;
  rc = gdefcore_layout_view(catalog, layout, layout_len, &view);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  placed = (GDEFCORE_Placement *)calloc(GDEFCORE_LAYOUT_PANES_MAX + 2, sizeof *placed);
  unplaced = (GDEFCORE_Placement *)calloc(GDEFCORE_LAYOUT_PANES_MAX + 2, sizeof *unplaced);
  if (placed == NULL || unplaced == NULL) {
    free(placed);
    free(unplaced);
    gdefcore_layout_view_free(&view);
    return GDEFCORE_ERR_OOM;
  }
  n = view.nplaced;
  un = view.nunplaced;
  memcpy(placed, view.placed, n * sizeof *placed);
  memcpy(unplaced, view.unplaced, un * sizeof *unplaced);
  k = 0;
  for (i = 0; i < n; i++) {
    GDEFCORE_Placement p = placed[i];
    size_t r;
    if (in_list(regions, nregions, p.region)) {
      placed[k++] = p;
      continue;
    }
    changed = 1;
    for (r = 0; r < nrenames; r++) {
      if (strcmp(rename_from[r], p.region) == 0 && in_list(regions, nregions, rename_to[r])) {
        snprintf(p.region, sizeof p.region, "%s", rename_to[r]);
        break;
      }
    }
    if (r < nrenames) {
      placed[k++] = p;
      continue;
    }
    if (un >= GDEFCORE_LAYOUT_PANES_MAX) {
      (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_LAYOUT_REFUSED_FULL,
          sizeof GDEFCORE_LAYOUT_REFUSED_FULL - 1);
      out = GDEFCORE_ERR_INVALID;
      goto done;
    }
    if (report != NULL) {
      char piece[512];
      int pn = snprintf(piece, sizeof piece, "%.*s %s %s\n", (int)layout_len, layout, p.widget,
          p.region);
      char * grown = (char *)realloc(*report, out_n + (size_t)pn + 1);
      if (grown == NULL) {
        out = GDEFCORE_ERR_OOM;
        goto done;
      }
      memcpy(grown + out_n, piece, (size_t)pn + 1);
      *report = grown;
      out_n += (size_t)pn;
      *report_len = out_n;
    }
    p.region[0] = '\0';
    unplaced[un++] = p;
  }
  n = k;
  if (!changed) {
    goto done;
  }
  rc = gdefcore_render_find_named(catalog, kDisplay, sizeof kDisplay - 1, layout, layout_len, id);
  if (rc != GDEFCORE_OK || !lines_of(placed, n, 1, &lines, &lens) ||
      !lines_of(unplaced, un, 0, &ulines, &ulens)) {
    out = rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_OOM;
    goto done;
  }
  slots1 = (const char **)calloc(n == 0 ? 1 : n, sizeof *slots1);
  slots2 = (const char **)calloc(un == 0 ? 1 : un, sizeof *slots2);
  if (slots1 == NULL || slots2 == NULL) {
    out = GDEFCORE_ERR_OOM;
    goto done;
  }
  for (i = 0; i < n; i++) {
    slots1[i] = lines[i];
  }
  for (i = 0; i < un; i++) {
    slots2[i] = ulines[i];
  }
  memset(values, 0, sizeof values);
  values[0].size = sizeof values[0];
  values[0].field = "panes";
  values[0].field_len = 5;
  values[0].texts = slots1;
  values[0].text_lens = lens;
  values[0].count = n;
  values[1].size = sizeof values[1];
  values[1].field = "unplaced";
  values[1].field_len = 8;
  values[1].texts = slots2;
  values[1].text_lens = ulens;
  values[1].count = un;
  out = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1,
      values, 2);
done:
  free(slots1);
  free(slots2);
  free_lines(lines, lens, n);
  free_lines(ulines, ulens, un);
  free(placed);
  free(unplaced);
  gdefcore_layout_view_free(&view);
  return out;
}

GDEFCORE_Result gdefcore_layout_stage_carry_all(GDEFCORE_Changeset * changeset,
    const char * template_name, size_t template_len, const char * const * regions,
    size_t nregions, const char * const * rename_from, const char * const * rename_to,
    size_t nrenames, char ** report, size_t * report_len) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(changeset);
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kDisplay, sizeof kDisplay - 1, &ids, &count);
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    char * layout = NULL;
    size_t layout_len = 0;
    char * uses = NULL;
    size_t uses_len = 0;
    rc = gdefcore_render_field_text(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], "layout",
        &uses, &uses_len);
    if (rc == GDEFCORE_OK && uses_len == template_len &&
        (template_len == 0 || memcmp(uses, template_name, template_len) == 0)) {
      rc = gdefcore_render_field_text(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], "name",
          &layout, &layout_len);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_layout_stage_carry(changeset, layout, layout_len, regions, nregions,
            rename_from, rename_to, nrenames, report, report_len);
      }
    }
    free(layout);
    free(uses);
  }
  gdefcore_ids_free(catalog, ids, count);
  return rc;
}
