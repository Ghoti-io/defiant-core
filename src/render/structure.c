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
 * A page template's structure (structure.h): the document, its checking, and the
 * source and stylesheet it makes.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/asset.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/layout.h>
#include <ghoti.io/defiant-core/region.h>
#include <ghoti.io/defiant-core/template.h>
#include <ghoti.io/defiant-core/structure.h>

#include "render_internal.h"
#include "../core/asset_util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { kStack = 1, kWrap = 2, kFixed = 3 };
enum { kNarrow = 1, kMedium = 2, kWide = 3 };

typedef struct Cell {
  char region[GDEFCORE_REGION_NAME_MAX + 1];
  int width;
  int stacked;
} Cell;

typedef struct Row {
  int behavior;
  int breakpoint;
  int ncells;
  Cell cells[GDEFCORE_STRUCTURE_ROW_CELLS_MAX];
} Row;

typedef struct Doc {
  int nrows;
  Row rows[GDEFCORE_STRUCTURE_ROWS_MAX];
} Doc;

static const char kLang[] = "en";
static const char kTemplate[] = "core.template";
static const int kBreakpointPx[] = {0, 480, 720, 960};
static const char * const kBreakpointName[] = {"", "narrow", "medium", "wide"};
static const char * const kBehaviorName[] = {"", "stack", "wrap", "fixed"};

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static void say(char * why, size_t cap, const char * text, int line) {
  if (why != NULL && cap > 0) {
    if (line > 0) {
      snprintf(why, cap, "Line %d: %s", line, text);
    } else {
      snprintf(why, cap, "%s", text);
    }
  }
}

int gdefcore_structure_name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > 100 || s[0] < 'a' || s[0] > 'z') {
    return 0;
  }
  for (i = 1; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
      return 0;
    }
  }
  return 1;
}

/* ---- the document ----------------------------------------------------------------- */

/* A whole number of 1 or 2 digits, 1 to 12; -1 otherwise. */
static int small(const char * s, size_t n) {
  int v = 0;
  size_t i;
  if (n == 0 || n > 2 || s[0] == '0') {
    return -1;
  }
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') {
      return -1;
    }
    v = v * 10 + (s[i] - '0');
  }
  return v <= 12 ? v : -1;
}

/* Split one line into at most @p max words. The count, or -1 for an empty
 * word (a leading, trailing or double space). */
static int words(const char * s, size_t n, const char ** w, size_t * wl, int max) {
  int count = 0;
  size_t i = 0;
  while (i <= n) {
    size_t b = i;
    while (i < n && s[i] != ' ') {
      i += 1;
    }
    if (i == b) {
      return -1;
    }
    if (count >= max) {
      return -1;
    }
    w[count] = s + b;
    wl[count] = i - b;
    count += 1;
    i += 1;
  }
  return count;
}

/* 1 when @p text is a document; it is read into @p doc. */
static int parse(const char * text, size_t n, Doc * doc, char * why, size_t cap) {
  size_t at = 0;
  int line = 0;
  int total = 0;
  memset(doc, 0, sizeof *doc);
  if (text == NULL || n == 0 || n > GDEFCORE_STRUCTURE_BYTES_MAX) {
    say(why, cap, "A structure is 1 to 4096 bytes.", 0);
    return 0;
  }
  while (at < n) {
    size_t e = at;
    const char * w[5];
    size_t wl[5];
    int nw;
    line += 1;
    while (e < n && text[e] != '\n') {
      e += 1;
    }
    nw = words(text + at, e - at, w, wl, 5);
    at = e + 1;
    if (nw < 0 || nw == 0) {
      say(why, cap, "A line is words with one space between them, and is not empty.", line);
      return 0;
    }
    if (span_eq(w[0], wl[0], "row", 3)) {
      Row * row;
      if (doc->nrows >= GDEFCORE_STRUCTURE_ROWS_MAX) {
        say(why, cap, "A structure has at most 32 rows.", line);
        return 0;
      }
      row = &doc->rows[doc->nrows];
      if (nw >= 2 && span_eq(w[1], wl[1], "stack", 5)) {
        row->behavior = kStack;
        if (nw != 3) {
          say(why, cap, "A stack row is 'row stack narrow', 'row stack medium' or 'row stack wide'.", line);
          return 0;
        }
        if (span_eq(w[2], wl[2], "narrow", 6)) {
          row->breakpoint = kNarrow;
        } else if (span_eq(w[2], wl[2], "medium", 6)) {
          row->breakpoint = kMedium;
        } else if (span_eq(w[2], wl[2], "wide", 4)) {
          row->breakpoint = kWide;
        } else {
          say(why, cap, "A stack row folds at narrow, medium or wide.", line);
          return 0;
        }
      } else if (nw == 2 && span_eq(w[1], wl[1], "wrap", 4)) {
        row->behavior = kWrap;
      } else if (nw == 2 && span_eq(w[1], wl[1], "fixed", 5)) {
        row->behavior = kFixed;
      } else {
        say(why, cap, "A row is 'row stack <width>', 'row wrap' or 'row fixed'.", line);
        return 0;
      }
      doc->nrows += 1;
    } else if (span_eq(w[0], wl[0], "cell", 4)) {
      Row * row;
      Cell * cell;
      int width = 12;
      int stacked = 0;
      int k;
      int r;
      if (doc->nrows == 0) {
        say(why, cap, "A cell belongs to a row, so a row comes first.", line);
        return 0;
      }
      row = &doc->rows[doc->nrows - 1];
      if (row->ncells >= GDEFCORE_STRUCTURE_ROW_CELLS_MAX || total >= GDEFCORE_STRUCTURE_CELLS_MAX) {
        say(why, cap, "A row has at most 12 cells and a structure 64.", line);
        return 0;
      }
      if (nw < 2 || !gdefcore_region_name_ok(w[1], wl[1])) {
        say(why, cap, "A cell names a region: a-z first, then a-z, 0-9, '_' and '-'.", line);
        return 0;
      }
      if (row->behavior == kWrap) {
        if (nw != 2) {
          say(why, cap, "A cell of a wrap row is 'cell <region>' and has no width.", line);
          return 0;
        }
      } else {
        if (nw < 3 || (width = small(w[2], wl[2])) < 1) {
          say(why, cap, "A cell has a width of 1 to 12 columns.", line);
          return 0;
        }
        if (nw == 4) {
          if (row->behavior == kFixed) {
            say(why, cap, "A cell of a fixed row never stacks, so it has no stacked position.", line);
            return 0;
          }
          stacked = small(w[3], wl[3]);
          if (stacked < 1) {
            say(why, cap, "A stacked position is a whole number of 1 to 12.", line);
            return 0;
          }
        } else if (nw != 3) {
          say(why, cap, "A cell is 'cell <region> <width> [<stacked>]'.", line);
          return 0;
        }
      }
      for (r = 0; r < doc->nrows; r++) {
        for (k = 0; k < doc->rows[r].ncells; k++) {
          if (span_eq(doc->rows[r].cells[k].region, strlen(doc->rows[r].cells[k].region),
                  w[1], wl[1])) {
            say(why, cap, "A region is used once in a structure.", line);
            return 0;
          }
        }
      }
      cell = &row->cells[row->ncells];
      memcpy(cell->region, w[1], wl[1]);
      cell->region[wl[1]] = '\0';
      cell->width = row->behavior == kWrap ? 0 : width;
      cell->stacked = stacked;
      row->ncells += 1;
      total += 1;
    } else {
      say(why, cap, "A line is a 'row' or a 'cell'.", line);
      return 0;
    }
  }
  if (doc->nrows == 0) {
    say(why, cap, "A structure has a row.", 0);
    return 0;
  }
  {
    int r;
    for (r = 0; r < doc->nrows; r++) {
      Row * row = &doc->rows[r];
      int sum = 0;
      int k;
      int j;
      if (row->ncells == 0) {
        say(why, cap, "A row has a cell.", 0);
        return 0;
      }
      for (k = 0; k < row->ncells; k++) {
        sum += row->cells[k].width;
      }
      if (sum > 12) {
        say(why, cap, "The widths of a row come to more than 12 columns.", 0);
        return 0;
      }
      if (row->behavior == kStack) {
        /* A stacked position that was not given is the cell's place in the row. */
        for (k = 0; k < row->ncells; k++) {
          if (row->cells[k].stacked == 0) {
            row->cells[k].stacked = k + 1;
          }
          if (row->cells[k].stacked > row->ncells) {
            say(why, cap, "A stacked position is at most the number of cells in its row.", 0);
            return 0;
          }
        }
        for (k = 0; k < row->ncells; k++) {
          for (j = k + 1; j < row->ncells; j++) {
            if (row->cells[k].stacked == row->cells[j].stacked) {
              say(why, cap, "Two cells of a row stack in the same position.", 0);
              return 0;
            }
          }
        }
      }
    }
  }
  return 1;
}

/* The canonical text of @p doc, malloc'd. */
static char * canonical(const Doc * doc, size_t * out_len) {
  size_t cap = 256 + (size_t)doc->nrows * 64 + (size_t)GDEFCORE_STRUCTURE_CELLS_MAX * 96;
  char * buf = (char *)malloc(cap);
  size_t at = 0;
  int r;
  int k;
  if (buf == NULL) {
    return NULL;
  }
  for (r = 0; r < doc->nrows; r++) {
    const Row * row = &doc->rows[r];
    at += (size_t)snprintf(buf + at, cap - at, "row %s%s%s\n", kBehaviorName[row->behavior],
        row->behavior == kStack ? " " : "", row->behavior == kStack ? kBreakpointName[row->breakpoint] : "");
    for (k = 0; k < row->ncells; k++) {
      const Cell * cell = &row->cells[k];
      if (row->behavior == kWrap) {
        at += (size_t)snprintf(buf + at, cap - at, "cell %s\n", cell->region);
      } else if (row->behavior == kFixed) {
        at += (size_t)snprintf(buf + at, cap - at, "cell %s %d\n", cell->region, cell->width);
      } else {
        at += (size_t)snprintf(buf + at, cap - at, "cell %s %d %d\n", cell->region,
            cell->width, cell->stacked);
      }
    }
  }
  *out_len = at;
  return buf;
}

GDEFCORE_Result gdefcore_structure_check(const char * text, size_t text_len,
    char ** out_canonical, size_t * out_len, char * why, size_t why_cap) {
  Doc * doc;
  GDEFCORE_Result rc = GDEFCORE_OK;
  size_t n = 0;
  char * canon;
  if (out_canonical != NULL) {
    *out_canonical = NULL;
  }
  doc = (Doc *)malloc(sizeof *doc);
  if (doc == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (!parse(text, text_len, doc, why, why_cap)) {
    free(doc);
    return GDEFCORE_ERR_INVALID;
  }
  canon = canonical(doc, &n);
  if (canon == NULL) {
    rc = GDEFCORE_ERR_OOM;
  } else if (out_canonical != NULL) {
    *out_canonical = canon;
    if (out_len != NULL) {
      *out_len = n;
    }
  } else {
    free(canon);
  }
  free(doc);
  return rc;
}

/* ---- what it makes ---------------------------------------------------------------- */

typedef struct Out {
  char * p;
  size_t n;
  size_t cap;
  int bad;
} Out;

static void put(Out * o, const char * fmt, ...) __attribute__((format(printf, 2, 3)));

static void put(Out * o, const char * fmt, ...) {
  va_list ap;
  int need;
  if (o->bad) {
    return;
  }
  va_start(ap, fmt);
  need = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (need < 0) {
    o->bad = 1;
    return;
  }
  if (o->n + (size_t)need + 1 > o->cap) {
    size_t cap = o->cap == 0 ? 1024 : o->cap;
    char * next;
    while (cap < o->n + (size_t)need + 1) {
      cap *= 2;
    }
    next = (char *)realloc(o->p, cap);
    if (next == NULL) {
      o->bad = 1;
      return;
    }
    o->p = next;
    o->cap = cap;
  }
  va_start(ap, fmt);
  (void)vsnprintf(o->p + o->n, o->cap - o->n, fmt, ap);
  va_end(ap);
  o->n += (size_t)need;
}

static int generate_doc(const char * name, const Doc * doc, Out * src, Out * css) {
  int r;
  int k;
  int w;
  int bp;
  int used_width[13];
  int used_bp[4];
  memset(used_width, 0, sizeof used_width);
  memset(used_bp, 0, sizeof used_bp);
  put(src, "<%% use region; %%><div class=\"pg pg-%s\">\n", name);
  for (r = 0; r < doc->nrows; r++) {
    const Row * row = &doc->rows[r];
    put(src, "<div class=\"row-box\"><div class=\"row row-%s", kBehaviorName[row->behavior]);
    if (row->behavior == kStack) {
      put(src, " bp-%s", kBreakpointName[row->breakpoint]);
      used_bp[row->breakpoint] = 1;
    }
    put(src, " r%d\">\n", r + 1);
    for (k = 0; k < row->ncells; k++) {
      const Cell * cell = &row->cells[k];
      put(src, "<div class=\"cell cell-%s", cell->region);
      if (row->behavior != kWrap) {
        put(src, " w%d", cell->width);
        used_width[cell->width] = 1;
      }
      put(src, "\"><%%= region(\"%s\") %%></div>\n", cell->region);
    }
    put(src, "</div></div>\n");
  }
  put(src, "</div>\n");
  put(css, "/* Generated from the structure of the page template %s. Do not edit it: change the structure. */\n", name);
  put(css, ".pg-%s .row-box { container-type: inline-size; }\n", name);
  put(css, ".pg-%s .row { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 1rem; }\n", name);
  put(css, ".pg-%s .cell { min-width: 0; }\n", name);
  put(css, ".pg-%s .row-wrap { grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }\n", name);
  put(css, ".pg-%s .row-wrap > .cell { grid-column: auto; }\n", name);
  for (w = 1; w <= 12; w++) {
    if (used_width[w]) {
      put(css, ".pg-%s .w%d { grid-column: span %d; }\n", name, w, w);
    }
  }
  for (bp = kNarrow; bp <= kWide; bp++) {
    if (!used_bp[bp]) {
      continue;
    }
    put(css, "@container (max-width: %dpx) {\n", kBreakpointPx[bp]);
    put(css, "  .pg-%s .row-stack.bp-%s { grid-template-columns: minmax(0, 1fr); }\n", name, kBreakpointName[bp]);
    put(css, "  .pg-%s .row-stack.bp-%s > .cell { grid-column: auto; }\n", name, kBreakpointName[bp]);
    for (r = 0; r < doc->nrows; r++) {
      const Row * row = &doc->rows[r];
      if (row->behavior != kStack || row->breakpoint != bp) {
        continue;
      }
      for (k = 0; k < row->ncells; k++) {
        put(css, "  .pg-%s .r%d > .cell-%s { order: %d; }\n", name, r + 1,
            row->cells[k].region, row->cells[k].stacked);
      }
    }
    put(css, "}\n");
  }
  return src->bad || css->bad ? -1 : 0;
}

GDEFCORE_Result gdefcore_structure_generate(const char * template_name,
    size_t template_len, const char * text, size_t text_len, char ** out_source,
    size_t * out_source_len, char ** out_css, size_t * out_css_len) {
  Doc * doc;
  Out src;
  Out css;
  char name[101];
  if (out_source == NULL || out_css == NULL || out_source_len == NULL ||
      out_css_len == NULL || !gdefcore_structure_name_ok(template_name, template_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_source = NULL;
  *out_css = NULL;
  memcpy(name, template_name, template_len);
  name[template_len] = '\0';
  doc = (Doc *)malloc(sizeof *doc);
  if (doc == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (!parse(text, text_len, doc, NULL, 0)) {
    free(doc);
    return GDEFCORE_ERR_INVALID;
  }
  memset(&src, 0, sizeof src);
  memset(&css, 0, sizeof css);
  if (generate_doc(name, doc, &src, &css) != 0) {
    free(src.p);
    free(css.p);
    free(doc);
    return GDEFCORE_ERR_OOM;
  }
  free(doc);
  *out_source = src.p;
  *out_source_len = src.n;
  *out_css = css.p;
  *out_css_len = css.n;
  return GDEFCORE_OK;
}

/* ---- reading and staging ---------------------------------------------------------- */

static GDEFCORE_Result template_id(GDEFCORE_Catalog * catalog, const char * name, size_t n,
    char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  return gdefcore_render_find_named(catalog, kTemplate, sizeof kTemplate - 1, name, n, id);
}

GDEFCORE_Result gdefcore_structure_read(GDEFCORE_Catalog * catalog,
    const char * template_name, size_t template_len, char ** out, size_t * out_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * text = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out = NULL;
  rc = template_id(catalog, template_name, template_len, id);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_render_field_text(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "structure",
      &text, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_text_dup(catalog, text, n, out);
  free(text);
  if (rc == GDEFCORE_OK) {
    *out_len = n;
  }
  return rc;
}

static void value_set(GDEFCORE_Value * value, const char * field, const char ** slot,
    size_t * len_slot, const char * text, size_t len) {
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

static void css_name(const char * name, size_t n, char out[128]) {
  snprintf(out, 128, "layout-%.*s.css", (int)n, name);
}

GDEFCORE_Result gdefcore_structure_stage(GDEFCORE_Changeset * changeset,
    const char * template_name, size_t template_len, const char * text,
    size_t text_len, int replace_custom) {
  GDEFCORE_Catalog * catalog;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * canon = NULL;
  size_t canon_len = 0;
  char * source = NULL;
  char * css = NULL;
  size_t source_len = 0;
  size_t css_len = 0;
  char asset[128];
  GDEFCORE_Value values[4];
  const char * slots[4];
  size_t lens[4];
  size_t nvalues;
  int exists;
  GDEFCORE_Result rc;
  if (changeset == NULL || !gdefcore_structure_name_ok(template_name, template_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_structure_check(text, text_len, &canon, &canon_len, NULL, 0);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_structure_generate(template_name, template_len, canon, canon_len, &source,
      &source_len, &css, &css_len);
  if (rc != GDEFCORE_OK) {
    free(canon);
    return rc;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  rc = template_id(catalog, template_name, template_len, id);
  exists = rc == GDEFCORE_OK;
  if (rc == GDEFCORE_OK) {
    char * kind = NULL;
    char * had = NULL;
    size_t kind_len = 0;
    size_t had_len = 0;
    rc = gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, id, "kind",
        &kind, &kind_len);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, id,
          "structure", &had, &had_len);
    }
    if (rc == GDEFCORE_OK &&
        (!span_eq(kind, kind_len, "core.page", 9) ||
            (span_eq(had, had_len, GDEFCORE_STRUCTURE_CUSTOM, sizeof GDEFCORE_STRUCTURE_CUSTOM - 1) &&
                !replace_custom))) {
      rc = GDEFCORE_ERR_INVALID;   /* not a page template, or written by hand */
    }
    free(kind);
    free(had);
  } else if (rc == GDEFCORE_ERR_INVALID) {
    rc = gdefcore_entity_create(catalog, kTemplate, sizeof kTemplate - 1, id, NULL);
  }
  if (rc != GDEFCORE_OK) {
    free(canon);
    free(source);
    free(css);
    return rc;
  }
  value_set(&values[0], "name", &slots[0], &lens[0], template_name, template_len);
  value_set(&values[1], "body", &slots[1], &lens[1], source, source_len);
  value_set(&values[2], "structure", &slots[2], &lens[2], canon, canon_len);
  nvalues = 3;
  if (!exists) {
    value_set(&values[3], "kind", &slots[3], &lens[3], "core.page", 9);
    nvalues = 4;
  }
  rc = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1,
      values, nvalues);
  if (rc == GDEFCORE_OK) {
    css_name(template_name, template_len, asset);
    rc = gdefcore_siteasset_stage_generated(changeset, asset, strlen(asset), css, css_len,
        template_name, template_len, replace_custom);
  }
  free(canon);
  free(source);
  free(css);
  return rc;
}

GDEFCORE_Result gdefcore_structure_stage_custom(GDEFCORE_Changeset * changeset,
    const char * template_name, size_t template_len) {
  GDEFCORE_Catalog * catalog;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * had = NULL;
  size_t had_len = 0;
  GDEFCORE_Value value;
  const char * slot;
  size_t len;
  char asset[128];
  GDEFCORE_Result rc;
  if (changeset == NULL || !gdefcore_structure_name_ok(template_name, template_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  if (template_id(catalog, template_name, template_len, id) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, id, "structure",
      &had, &had_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (had_len == 0) {
    free(had);
    return GDEFCORE_ERR_INVALID;   /* nothing to take over */
  }
  free(had);
  value_set(&value, "structure", &slot, &len, GDEFCORE_STRUCTURE_CUSTOM,
      sizeof GDEFCORE_STRUCTURE_CUSTOM - 1);
  rc = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1,
      &value, 1);
  if (rc == GDEFCORE_OK) {
    char tag[128 + 1];
    css_name(template_name, template_len, asset);
    /* The stylesheet stays and becomes a file the site may change. */
    if (gdefcore_siteasset_generated_by(catalog, changeset, asset, strlen(asset), tag) &&
        tag[0] != '\0') {
      rc = gdefcore_siteasset_stage_generated(changeset, asset, strlen(asset), NULL, 0,
          NULL, 0, 0);
    }
  }
  return rc;
}

/* ---- vetting ---------------------------------------------------------------------- */

static GDEFCORE_Result refuse(GDEFCORE_Changeset * changeset, const char * name,
    size_t name_len, const char * why) {
  char text[400];
  snprintf(text, sizeof text, "Page template '%.*s' is refused: %s",
      (int)(name_len > 64 ? 64 : name_len), name, why);
  (void)gdefcore_changeset_set_refusal(changeset, text, strlen(text));
  return GDEFCORE_ERR_INVALID;
}

/* The generated pair for @p name as @p doc says, or a refusal. */
static GDEFCORE_Result check_template(GDEFCORE_Changeset * changeset,
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len, const char * structure,
    size_t structure_len, const char * body, size_t body_len) {
  char * source = NULL;
  char * css = NULL;
  size_t source_len = 0;
  size_t css_len = 0;
  char asset[128];
  char tag[128 + 1];
  GDEFCORE_Asset found;
  GDEFCORE_Result rc;
  char why[200];
  if (!gdefcore_structure_name_ok(name, name_len)) {
    return refuse(changeset, name, name_len,
        "a structured template's name is a-z first, then a-z, 0-9 and '-'.");
  }
  if (gdefcore_structure_check(structure, structure_len, NULL, NULL, why, sizeof why) !=
      GDEFCORE_OK) {
    return refuse(changeset, name, name_len, why);
  }
  rc = gdefcore_structure_generate(name, name_len, structure, structure_len, &source,
      &source_len, &css, &css_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!span_eq(body, body_len, source, source_len)) {
    free(source);
    free(css);
    return refuse(changeset, name, name_len,
        "its source is not what its structure makes. Mark it custom to write it by hand.");
  }
  css_name(name, name_len, asset);
  memset(&found, 0, sizeof found);
  found.size = sizeof found;
  {
    char ref[160];
    snprintf(ref, sizeof ref, "site/%s", asset);
    rc = gdefcore_asset_find(catalog, changeset, ref, strlen(ref), &found);
  }
  if (rc != GDEFCORE_OK || !span_eq((const char *)found.bytes, found.bytes_len, css, css_len) ||
      !gdefcore_siteasset_generated_by(catalog, changeset, asset, strlen(asset), tag) ||
      !span_eq(tag, strlen(tag), name, name_len)) {
    if (rc == GDEFCORE_OK) {
      gdefcore_asset_release(&found);
    }
    free(source);
    free(css);
    return refuse(changeset, name, name_len,
        "its generated stylesheet is missing or is not what its structure makes.");
  }
  gdefcore_asset_release(&found);
  free(source);
  free(css);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_structure_vet(GDEFCORE_Changeset * changeset) {
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
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type, &type_len, &op) !=
            GDEFCORE_OK ||
        type == NULL || op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_UNPUBLISH ||
        gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
      continue;
    }
    if (span_eq(type, type_len, kTemplate, sizeof kTemplate - 1)) {
      char * name = NULL;
      char * structure = NULL;
      char * body = NULL;
      size_t nl = 0;
      size_t sl = 0;
      size_t bl = 0;
      const GDEFCORE_Changeset * through = op == GDEFCORE_TOUCH_PUBLISH ? NULL : changeset;
      int view = op == GDEFCORE_TOUCH_PUBLISH ? GDEFCORE_VIEW_DRAFT : GDEFCORE_VIEW_CURRENT;
      rc = gdefcore_render_field_text(catalog, through, view, canon, "name", &name, &nl);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_render_field_text(catalog, through, view, canon, "structure",
            &structure, &sl);
      }
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_render_field_text(catalog, through, view, canon, "body", &body, &bl);
      }
      if (rc == GDEFCORE_OK && sl > 0 &&
          !span_eq(structure, sl, GDEFCORE_STRUCTURE_CUSTOM, sizeof GDEFCORE_STRUCTURE_CUSTOM - 1)) {
        rc = check_template(changeset, catalog, name, nl, structure, sl, body, bl);
      }
      free(name);
      free(structure);
      free(body);
    } else if (span_eq(type, type_len, "core.css-asset", 14)) {
      char * name = NULL;
      size_t nl = 0;
      char tag[128 + 1];
      rc = gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, canon, "name",
          &name, &nl);
      if (rc == GDEFCORE_OK && nl > 0 &&
          gdefcore_siteasset_generated_by(catalog, changeset, name, nl, tag) && tag[0] != '\0') {
        /* A generated file belongs to the template it names, and to its structure. */
        char asset[128];
        css_name(tag, strlen(tag), asset);
        if (!span_eq(asset, strlen(asset), name, nl)) {
          rc = refuse(changeset, name, nl, "a generated stylesheet is named for its template.");
        } else {
          char * structure = NULL;
          char * body = NULL;
          char * tname = NULL;
          size_t sl = 0;
          size_t bl = 0;
          size_t tl = 0;
          char tid[GDEFCORE_PUBLIC_ID_LEN + 1];
          int found_template = 0;
          size_t t;
          size_t tc = gdefcore_changeset_touched_count(changeset);
          /* The template, as the changeset leaves it: a touched one first, else the published. */
          for (t = 0; t < tc && !found_template; t++) {
            const char * tid_in = NULL;
            size_t tid_len = 0;
            const char * ttype = NULL;
            size_t ttype_len = 0;
            char tcanon[GDEFCORE_PUBLIC_ID_LEN + 1];
            char * got = NULL;
            size_t got_len = 0;
            if (gdefcore_changeset_touched_at(changeset, t, &tid_in, &tid_len, &ttype,
                    &ttype_len, NULL) == GDEFCORE_OK &&
                ttype != NULL && span_eq(ttype, ttype_len, kTemplate, sizeof kTemplate - 1) &&
                gdefcore_id_canonical(tid_in, tid_len, tcanon) == GDEFCORE_OK &&
                gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, tcanon,
                    "name", &got, &got_len) == GDEFCORE_OK) {
              if (span_eq(got, got_len, tag, strlen(tag))) {
                memcpy(tid, tcanon, sizeof tid);
                found_template = 1;
              }
              free(got);
            }
          }
          if (!found_template && template_id(catalog, tag, strlen(tag), tid) == GDEFCORE_OK) {
            found_template = 1;
          }
          if (found_template) {
            rc = gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, tid,
                "structure", &structure, &sl);
            if (rc == GDEFCORE_OK) {
              rc = gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, tid,
                  "body", &body, &bl);
            }
            if (rc == GDEFCORE_OK) {
              rc = gdefcore_render_field_text(catalog, changeset, GDEFCORE_VIEW_CURRENT, tid,
                  "name", &tname, &tl);
            }
          }
          if (rc == GDEFCORE_OK) {
            if (!found_template || sl == 0 ||
                span_eq(structure, sl, GDEFCORE_STRUCTURE_CUSTOM, sizeof GDEFCORE_STRUCTURE_CUSTOM - 1)) {
              rc = refuse(changeset, name, nl,
                  "a generated stylesheet belongs to a template that has a structure.");
            } else {
              rc = check_template(changeset, catalog, tname, tl, structure, sl, body, bl);
            }
          }
          free(structure);
          free(body);
          free(tname);
        }
      }
      free(name);
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  return GDEFCORE_OK;
}

/* ---- editing ---------------------------------------------------------------------- */

static const struct {
  const char * name;
  const char * label;
  const char * document;
} kStarts[] = {
    {"one-column", "One column",
        "row stack medium\ncell main 12 1\n"},
    {"two-columns-right", "Two columns, sidebar on the right",
        "row stack medium\ncell main 8 1\ncell side 4 2\n"},
    {"two-columns-left", "Two columns, sidebar on the left",
        "row stack medium\ncell side 4 2\ncell main 8 1\n"},
    {"three-columns", "Three columns",
        "row stack medium\ncell navigation 3 2\ncell main 6 1\ncell side 3 3\n"},
    {"header-two-columns-footer", "Header, two columns, footer",
        "row fixed\ncell header 12\nrow stack medium\ncell main 8 1\ncell side 4 2\n"
        "row fixed\ncell footer 12\n"},
    {"holy-grail", "Header, left rail, main, right rail, footer",
        "row fixed\ncell header 12\nrow stack wide\ncell navigation 2 2\ncell main 8 1\n"
        "cell side 2 3\nrow fixed\ncell footer 12\n"},
    {"landing-page", "Landing page: header, feature row, main, footer",
        "row fixed\ncell header 12\nrow wrap\ncell feature-one\ncell feature-two\n"
        "cell feature-three\nrow fixed\ncell main 12\nrow fixed\ncell footer 12\n"},
};

int gdefcore_structure_starting_point(size_t index, const char ** name, const char ** label,
    const char ** document) {
  if (index >= sizeof kStarts / sizeof kStarts[0]) {
    return 0;
  }
  if (name != NULL) {
    *name = kStarts[index].name;
  }
  if (label != NULL) {
    *label = kStarts[index].label;
  }
  if (document != NULL) {
    *document = kStarts[index].document;
  }
  return 1;
}

static void version_text(const char * text, size_t n, char out[GDEFCORE_STRUCTURE_VERSION_LEN + 1]) {
  if (gdefcore_asset_hash((const uint8_t *)text, n, out) != GDEFCORE_OK) {
    out[0] = '\0';
  }
}

/* The stored structure of @p name: 1 with the text malloc'd (empty when it has
 * none), 0 when there is no such template. */
static GDEFCORE_Result stored_text(GDEFCORE_Catalog * catalog, const char * name, size_t n,
    int * exists, char ** text, size_t * text_len) {
  char * got = NULL;
  size_t got_len = 0;
  GDEFCORE_Result rc = gdefcore_structure_read(catalog, name, n, &got, &got_len);
  *exists = 1;
  *text = NULL;
  *text_len = 0;
  if (rc == GDEFCORE_ERR_INVALID) {
    *exists = 0;
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *text = (char *)malloc(got_len + 1);
  if (*text == NULL) {
    gdefcore_text_free(catalog, got);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(*text, got, got_len);
  (*text)[got_len] = '\0';
  *text_len = got_len;
  gdefcore_text_free(catalog, got);
  return GDEFCORE_OK;
}

void gdefcore_structure_view_free(GDEFCORE_Structure_View * view) {
  if (view == NULL) {
    return;
  }
  free(view->rows);
  free(view->document);
  view->rows = NULL;
  view->document = NULL;
  view->nrows = 0;
  view->document_len = 0;
}

GDEFCORE_Result gdefcore_structure_view(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, GDEFCORE_Structure_View * out) {
  char * text = NULL;
  size_t n = 0;
  int exists = 0;
  Doc * doc = NULL;
  GDEFCORE_Result rc;
  int r;
  int k;
  if (catalog == NULL || name == NULL || out == NULL || out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  memset((char *)out + sizeof out->size, 0, sizeof *out - sizeof out->size);
  rc = stored_text(catalog, name, name_len, &exists, &text, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!exists) {
    return GDEFCORE_ERR_INVALID;
  }
  out->document = text;
  out->document_len = n;
  version_text(text, n, out->version);
  if (n == 0) {
    out->kind = GDEFCORE_STRUCTURE_KIND_NONE;
    return GDEFCORE_OK;
  }
  if (span_eq(text, n, GDEFCORE_STRUCTURE_CUSTOM, sizeof GDEFCORE_STRUCTURE_CUSTOM - 1)) {
    out->kind = GDEFCORE_STRUCTURE_KIND_CUSTOM;
    return GDEFCORE_OK;
  }
  doc = (Doc *)malloc(sizeof *doc);
  if (doc == NULL) {
    gdefcore_structure_view_free(out);
    return GDEFCORE_ERR_OOM;
  }
  if (!parse(text, n, doc, NULL, 0)) {
    free(doc);
    gdefcore_structure_view_free(out);
    return GDEFCORE_ERR_INVALID;
  }
  out->rows = (GDEFCORE_Structure_Row *)calloc(doc->nrows == 0 ? 1 : (size_t)doc->nrows,
      sizeof *out->rows);
  if (out->rows == NULL) {
    free(doc);
    gdefcore_structure_view_free(out);
    return GDEFCORE_ERR_OOM;
  }
  out->kind = GDEFCORE_STRUCTURE_KIND_DOCUMENT;
  out->nrows = (size_t)doc->nrows;
  for (r = 0; r < doc->nrows; r++) {
    out->rows[r].behavior = doc->rows[r].behavior;
    out->rows[r].breakpoint = doc->rows[r].breakpoint;
    out->rows[r].ncells = (size_t)doc->rows[r].ncells;
    for (k = 0; k < doc->rows[r].ncells; k++) {
      memcpy(out->rows[r].cells[k].region, doc->rows[r].cells[k].region,
          sizeof out->rows[r].cells[k].region);
      out->rows[r].cells[k].width = doc->rows[r].cells[k].width;
      out->rows[r].cells[k].stacked = doc->rows[r].cells[k].stacked;
    }
  }
  free(doc);
  return GDEFCORE_OK;
}

/* A stacked position 1..n for each cell of @p row, closing any gap and keeping the order. */
static void restack(Row * row) {
  int k;
  int j;
  int rank;
  int used[GDEFCORE_STRUCTURE_ROW_CELLS_MAX];
  for (k = 0; k < row->ncells; k++) {
    rank = 1;
    for (j = 0; j < row->ncells; j++) {
      if (row->cells[j].stacked < row->cells[k].stacked ||
          (row->cells[j].stacked == row->cells[k].stacked && j < k)) {
        rank++;
      }
    }
    used[k] = rank;
  }
  for (k = 0; k < row->ncells; k++) {
    row->cells[k].stacked = used[k];
  }
}

/* Give a row's cells widths that fit when it becomes a stack or fixed row. */
static int widths_for(Row * row) {
  int k;
  int each;
  if (row->ncells == 0) {
    return 1;
  }
  each = 12 / row->ncells;
  if (each < 1) {
    return 0;
  }
  for (k = 0; k < row->ncells; k++) {
    row->cells[k].width = each;
  }
  return 1;
}

static void remove_cell_at(Row * row, int k) {
  int j;
  int gone = row->cells[k].stacked;
  for (j = k; j + 1 < row->ncells; j++) {
    row->cells[j] = row->cells[j + 1];
  }
  row->ncells--;
  for (j = 0; j < row->ncells; j++) {
    if (row->cells[j].stacked > gone) {
      row->cells[j].stacked--;
    }
  }
}

static void insert_cell_at(Row * row, int at, const Cell * cell) {
  int j;
  for (j = row->ncells; j > at; j--) {
    row->cells[j] = row->cells[j - 1];
  }
  row->cells[at] = *cell;
  row->ncells++;
}

static void drop_row(Doc * doc, int r) {
  int j;
  for (j = r; j + 1 < doc->nrows; j++) {
    doc->rows[j] = doc->rows[j + 1];
  }
  doc->nrows--;
}

/* Apply @p edit to @p doc. 0 with a sentence in @p why when it cannot be. */
static int apply_edit(Doc * doc, const GDEFCORE_Structure_Edit * e, const char ** why,
    char renamed_from[GDEFCORE_REGION_NAME_MAX + 1], int * renamed) {
  static const char kThere[] = GDEFCORE_STRUCTURE_REFUSED_THERE;
  int r = (int)e->row;
  int k = (int)e->cell;
  Cell cell;
  *renamed = 0;
  if (e->row > 4096 || e->cell > 4096 || e->to_row > 4096 || e->to_cell > 4096) {
    *why = kThere;   /* past anything a structure holds; keeps the casts below safe */
    return 0;
  }
  switch (e->act) {
    case GDEFCORE_STRUCTURE_ACT_ADD_ROW: {
      Row row;
      int at = r > doc->nrows ? doc->nrows : r;
      int j;
      if (doc->nrows >= GDEFCORE_STRUCTURE_ROWS_MAX) {
        *why = "A structure has at most 32 rows.";
        return 0;
      }
      if (e->behavior < kStack || e->behavior > kFixed) {
        *why = "A row is stack, wrap or fixed.";
        return 0;
      }
      if (e->region == NULL || !gdefcore_region_name_ok(e->region, e->region_len)) {
        *why = "A cell names a region: a-z first, then a-z, 0-9, '_' and '-'.";
        return 0;
      }
      memset(&row, 0, sizeof row);
      row.behavior = e->behavior;
      row.ncells = 1;
      memcpy(row.cells[0].region, e->region, e->region_len);
      if (e->behavior != kWrap) {
        row.cells[0].width = e->width > 0 ? e->width : 12;
        row.cells[0].stacked = 1;
      }
      row.breakpoint = e->behavior == kStack ? (e->breakpoint == 0 ? kMedium : e->breakpoint) : 0;
      if (row.breakpoint < 0 || row.breakpoint > kWide) {
        *why = "A stack row folds at narrow, medium or wide.";
        return 0;
      }
      for (j = doc->nrows; j > at; j--) {
        doc->rows[j] = doc->rows[j - 1];
      }
      doc->rows[at] = row;
      doc->nrows++;
      return 1;
    }
    case GDEFCORE_STRUCTURE_ACT_REMOVE_ROW: {
      int j;
      if (r >= doc->nrows) {
        *why = kThere;
        return 0;
      }
      for (j = r; j + 1 < doc->nrows; j++) {
        doc->rows[j] = doc->rows[j + 1];
      }
      doc->nrows--;
      return 1;
    }
    case GDEFCORE_STRUCTURE_ACT_MOVE_ROW: {
      Row row;
      int to = (int)e->to_row;
      int j;
      if (r >= doc->nrows) {
        *why = kThere;
        return 0;
      }
      if (to >= doc->nrows) {
        to = doc->nrows - 1;
      }
      row = doc->rows[r];
      for (j = r; j + 1 < doc->nrows; j++) {
        doc->rows[j] = doc->rows[j + 1];
      }
      for (j = doc->nrows - 1; j > to; j--) {
        doc->rows[j] = doc->rows[j - 1];
      }
      doc->rows[to] = row;
      return 1;
    }
    case GDEFCORE_STRUCTURE_ACT_SET_ROW: {
      Row * row;
      if (r >= doc->nrows) {
        *why = kThere;
        return 0;
      }
      row = &doc->rows[r];
      if (e->behavior < kStack || e->behavior > kFixed) {
        *why = "A row is stack, wrap or fixed.";
        return 0;
      }
      if (e->breakpoint < 0 || e->breakpoint > kWide) {
        *why = "A stack row folds at narrow, medium or wide.";
        return 0;
      }
      if (row->behavior == kWrap && e->behavior != kWrap && !widths_for(row)) {
        *why = "A row has at most 12 cells.";
        return 0;
      }
      if (e->behavior == kWrap) {
        int j;
        for (j = 0; j < row->ncells; j++) {
          row->cells[j].width = 0;
          row->cells[j].stacked = 0;
        }
      } else if (row->behavior == kWrap) {
        int j;
        for (j = 0; j < row->ncells; j++) {
          row->cells[j].stacked = j + 1;
        }
      }
      row->behavior = e->behavior;
      row->breakpoint = e->behavior == kStack ? (e->breakpoint == 0 ? kMedium : e->breakpoint) : 0;
      return 1;
    }
    case GDEFCORE_STRUCTURE_ACT_ADD_CELL: {
      Row * row;
      int at;
      if (r >= doc->nrows) {
        *why = kThere;
        return 0;
      }
      row = &doc->rows[r];
      if (row->ncells >= GDEFCORE_STRUCTURE_ROW_CELLS_MAX) {
        *why = "A row has at most 12 cells.";
        return 0;
      }
      if (e->region == NULL || !gdefcore_region_name_ok(e->region, e->region_len)) {
        *why = "A cell names a region: a-z first, then a-z, 0-9, '_' and '-'.";
        return 0;
      }
      memset(&cell, 0, sizeof cell);
      memcpy(cell.region, e->region, e->region_len);
      if (row->behavior != kWrap) {
        cell.width = e->width;
        cell.stacked = e->stacked > 0 && e->stacked <= row->ncells + 1 ? e->stacked : row->ncells + 1;
        for (at = 0; at < row->ncells; at++) {
          if (row->cells[at].stacked >= cell.stacked) {
            row->cells[at].stacked++;
          }
        }
      }
      insert_cell_at(row, row->ncells, &cell);
      return 1;
    }
    case GDEFCORE_STRUCTURE_ACT_REMOVE_CELL:
      if (r >= doc->nrows || k >= doc->rows[r].ncells) {
        *why = kThere;
        return 0;
      }
      remove_cell_at(&doc->rows[r], k);
      if (doc->rows[r].behavior != kWrap) {
        restack(&doc->rows[r]);
      }
      if (doc->rows[r].ncells == 0) {
        drop_row(doc, r);   /* a row with no cell is no row */
      }
      return 1;
    case GDEFCORE_STRUCTURE_ACT_MOVE_CELL: {
      int tr = (int)e->to_row;
      int tk;
      if (r >= doc->nrows || k >= doc->rows[r].ncells || tr >= doc->nrows) {
        *why = kThere;
        return 0;
      }
      cell = doc->rows[r].cells[k];
      if (tr == r) {
        Row * row = &doc->rows[r];
        tk = (int)e->to_cell;
        if (tk >= row->ncells) {
          tk = row->ncells - 1;
        }
        {
          int j;
          for (j = k; j + 1 < row->ncells; j++) {
            row->cells[j] = row->cells[j + 1];
          }
          row->ncells--;
          insert_cell_at(row, tk, &cell);
        }
        return 1;
      }
      if (doc->rows[tr].ncells >= GDEFCORE_STRUCTURE_ROW_CELLS_MAX) {
        *why = "A row has at most 12 cells.";
        return 0;
      }
      remove_cell_at(&doc->rows[r], k);
      if (doc->rows[r].behavior != kWrap) {
        restack(&doc->rows[r]);
      }
      tk = (int)e->to_cell;
      if (tk > doc->rows[tr].ncells) {
        tk = doc->rows[tr].ncells;
      }
      if (doc->rows[tr].behavior == kWrap) {
        cell.width = 0;
        cell.stacked = 0;
      } else {
        int used = 0;
        int j;
        for (j = 0; j < doc->rows[tr].ncells; j++) {
          used += doc->rows[tr].cells[j].width;
        }
        cell.stacked = doc->rows[tr].ncells + 1;
        /* It takes what room the row has left, at least one column. */
        if (cell.width < 1 || cell.width > 12 - used) {
          cell.width = 12 - used < 1 ? 1 : (cell.width < 1 ? 1 : 12 - used);
        }
      }
      insert_cell_at(&doc->rows[tr], tk, &cell);
      if (doc->rows[r].ncells == 0) {
        drop_row(doc, r);
      }
      return 1;
    }
    case GDEFCORE_STRUCTURE_ACT_SET_WIDTH:
      if (r >= doc->nrows || k >= doc->rows[r].ncells) {
        *why = kThere;
        return 0;
      }
      if (doc->rows[r].behavior == kWrap) {
        *why = "A cell of a wrap row has no width.";
        return 0;
      }
      doc->rows[r].cells[k].width = e->width;
      return 1;
    case GDEFCORE_STRUCTURE_ACT_SET_STACKED: {
      Row * row;
      int j;
      if (r >= doc->nrows || k >= doc->rows[r].ncells) {
        *why = kThere;
        return 0;
      }
      row = &doc->rows[r];
      if (row->behavior == kWrap) {
        *why = "A cell of a wrap row has no stacked position.";
        return 0;
      }
      if (e->stacked < 1 || e->stacked > row->ncells) {
        *why = "A stacked position is 1 up to the cells in the row.";
        return 0;
      }
      for (j = 0; j < row->ncells; j++) {
        if (j != k && row->cells[j].stacked == e->stacked) {
          row->cells[j].stacked = row->cells[k].stacked;
        }
      }
      row->cells[k].stacked = e->stacked;
      return 1;
    }
    case GDEFCORE_STRUCTURE_ACT_RENAME_CELL:
      if (r >= doc->nrows || k >= doc->rows[r].ncells) {
        *why = kThere;
        return 0;
      }
      if (e->region == NULL || !gdefcore_region_name_ok(e->region, e->region_len)) {
        *why = "A cell names a region: a-z first, then a-z, 0-9, '_' and '-'.";
        return 0;
      }
      memcpy(renamed_from, doc->rows[r].cells[k].region, sizeof doc->rows[r].cells[k].region);
      memset(doc->rows[r].cells[k].region, 0, sizeof doc->rows[r].cells[k].region);
      memcpy(doc->rows[r].cells[k].region, e->region, e->region_len);
      *renamed = 1;
      return 1;
    default:
      *why = kThere;
      return 0;
  }
}

GDEFCORE_Result gdefcore_structure_stage_edit(GDEFCORE_Changeset * changeset, const char * name,
    size_t name_len, const GDEFCORE_Structure_Edit * edit, char ** moved, size_t * moved_len) {
  GDEFCORE_Catalog * catalog;
  char * text = NULL;
  size_t n = 0;
  int exists = 0;
  Doc * doc = NULL;
  char version[GDEFCORE_STRUCTURE_VERSION_LEN + 1];
  char renamed_from[GDEFCORE_REGION_NAME_MAX + 1];
  int renamed = 0;
  const char * why = NULL;
  char say_why[200];
  char * canon = NULL;
  const char * document = NULL;
  const char * start_doc = NULL;
  int replace = 0;
  int is_custom = 0;
  GDEFCORE_Result rc;
  if (moved != NULL) {
    *moved = NULL;
  }
  if (moved_len != NULL) {
    *moved_len = 0;
  }
  if (changeset == NULL || name == NULL || edit == NULL || edit->size != sizeof *edit ||
      !gdefcore_structure_name_ok(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  rc = stored_text(catalog, name, name_len, &exists, &text, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  version_text(text == NULL ? "" : text, n, version);
  /* A template that is not there has no structure to have changed since it was drawn. */
  if (exists && (edit->version == NULL ||
                    !span_eq(edit->version, edit->version_len, version, strlen(version)))) {
    (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_STRUCTURE_REFUSED_STALE,
        sizeof GDEFCORE_STRUCTURE_REFUSED_STALE - 1);
    free(text);
    return GDEFCORE_ERR_INVALID;
  }
  is_custom = span_eq(text, n, GDEFCORE_STRUCTURE_CUSTOM, sizeof GDEFCORE_STRUCTURE_CUSTOM - 1);
  if (edit->act == GDEFCORE_STRUCTURE_ACT_CUSTOM) {
    free(text);
    if (!exists) {
      (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_STRUCTURE_REFUSED_THERE,
          sizeof GDEFCORE_STRUCTURE_REFUSED_THERE - 1);
      return GDEFCORE_ERR_INVALID;
    }
    rc = gdefcore_structure_stage_custom(changeset, name, name_len);
    return rc == GDEFCORE_OK ? gdefcore_structure_stage_record(changeset) : rc;
  }
  if (is_custom && edit->act != GDEFCORE_STRUCTURE_ACT_START &&
      edit->act != GDEFCORE_STRUCTURE_ACT_START_NEW) {
    (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_STRUCTURE_REFUSED_CUSTOM,
        sizeof GDEFCORE_STRUCTURE_REFUSED_CUSTOM - 1);
    free(text);
    return GDEFCORE_ERR_INVALID;
  }
  if (!exists && edit->act != GDEFCORE_STRUCTURE_ACT_START &&
      edit->act != GDEFCORE_STRUCTURE_ACT_START_NEW) {
    (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_STRUCTURE_REFUSED_THERE,
        sizeof GDEFCORE_STRUCTURE_REFUSED_THERE - 1);
    free(text);
    return GDEFCORE_ERR_INVALID;
  }
  doc = (Doc *)calloc(1, sizeof *doc);
  if (doc == NULL) {
    free(text);
    return GDEFCORE_ERR_OOM;
  }
  if (edit->act == GDEFCORE_STRUCTURE_ACT_START) {
    size_t i;
    const char * sname;
    for (i = 0; gdefcore_structure_starting_point(i, &sname, NULL, &start_doc); i++) {
      if (span_eq(sname, strlen(sname), edit->region, edit->region_len)) {
        break;
      }
      start_doc = NULL;
    }
    if (start_doc == NULL) {
      (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_STRUCTURE_REFUSED_START,
          sizeof GDEFCORE_STRUCTURE_REFUSED_START - 1);
      free(doc);
      free(text);
      return GDEFCORE_ERR_INVALID;
    }
    document = start_doc;
    replace = 1;
  } else if (edit->act == GDEFCORE_STRUCTURE_ACT_START_NEW) {
    char one[160];
    int len;
    if (edit->region == NULL || !gdefcore_region_name_ok(edit->region, edit->region_len)) {
      (void)gdefcore_changeset_set_refusal(changeset,
          "A cell names a region: a-z first, then a-z, 0-9, '_' and '-'.", 62);
      free(doc);
      free(text);
      return GDEFCORE_ERR_INVALID;
    }
    len = snprintf(one, sizeof one, "row stack medium\ncell %.*s 12 1\n", (int)edit->region_len,
        edit->region);
    canon = (char *)malloc((size_t)len + 1);
    if (canon == NULL) {
      free(doc);
      free(text);
      return GDEFCORE_ERR_OOM;
    }
    memcpy(canon, one, (size_t)len + 1);
    document = canon;
    replace = 1;
  } else {
    if (n > 0 && !parse(text, n, doc, say_why, sizeof say_why)) {
      (void)gdefcore_changeset_set_refusal(changeset, say_why, strlen(say_why));
      free(doc);
      free(text);
      return GDEFCORE_ERR_INVALID;
    }
    if (!apply_edit(doc, edit, &why, renamed_from, &renamed)) {
      (void)gdefcore_changeset_set_refusal(changeset, why, strlen(why));
      free(doc);
      free(text);
      return GDEFCORE_ERR_INVALID;
    }
    {
      size_t len = 0;
      char * made = canonical(doc, &len);
      if (made == NULL) {
        free(doc);
        free(text);
        return GDEFCORE_ERR_OOM;
      }
      canon = (char *)realloc(made, len + 1);
      if (canon == NULL) {
        free(made);
        free(doc);
        free(text);
        return GDEFCORE_ERR_OOM;
      }
      canon[len] = '\0';
      document = canon;
    }
  }
  {
    char * again = NULL;
    size_t again_len = 0;
    rc = gdefcore_structure_check(document, strlen(document), &again, &again_len, say_why,
        sizeof say_why);
    if (rc == GDEFCORE_ERR_INVALID) {
      (void)gdefcore_changeset_set_refusal(changeset, say_why, strlen(say_why));
    }
    if (rc == GDEFCORE_OK) {
      Doc * fresh = (Doc *)malloc(sizeof *fresh);
      if (fresh == NULL) {
        rc = GDEFCORE_ERR_OOM;
      } else {
        const char ** names;
        size_t total = 0;
        int i;
        int j;
        size_t at = 0;
        (void)parse(again, again_len, fresh, NULL, 0);
        for (i = 0; i < fresh->nrows; i++) {
          total += (size_t)fresh->rows[i].ncells;
        }
        names = (const char **)calloc(total == 0 ? 1 : total, sizeof *names);
        if (names == NULL) {
          rc = GDEFCORE_ERR_OOM;
        } else {
          for (i = 0; i < fresh->nrows; i++) {
            for (j = 0; j < fresh->rows[i].ncells; j++) {
              names[at++] = fresh->rows[i].cells[j].region;
            }
          }
          rc = gdefcore_structure_stage(changeset, name, name_len, again, again_len, replace);
          if (rc == GDEFCORE_OK) {
            const char * rf[1];
            const char * rt[1];
            rf[0] = renamed_from;
            rt[0] = renamed ? edit->region : NULL;
            rc = gdefcore_layout_stage_carry_all(changeset, name, name_len, names, total,
                rf, rt, renamed ? 1 : 0, moved, moved_len);
          }
          if (rc == GDEFCORE_OK) {
            rc = gdefcore_structure_stage_record(changeset);
          }
          free(names);
        }
        free(fresh);
      }
    }
    gdefcore_text_free(catalog, again);
  }
  free(canon);
  free(doc);
  free(text);
  return rc;
}

/* ---- undoing a structure edit or a template save that carried layouts ------------ */

static const char kChangeType[] = GDEFCORE_STRUCTURE_CHANGE_TYPE;
static const char kChangeTemplate[] = "core.template";
static const char kChangeDisplay[] = "core.display";
static const char kChangeAsset[] = "core.css-asset";
static const char kChangeNotAllowed[] = "That edit is not allowed.";

GDEFCORE_Result gdefcore_structure_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field fields[2];
  int kind = 0;
  size_t i;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_type_kind(catalog, kChangeType, strlen(kChangeType), &kind) == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  memset(fields, 0, sizeof fields);
  for (i = 0; i < 2; i++) {
    fields[i].size = sizeof fields[i];
    fields[i].name = i == 0 ? "name" : "entities";
    fields[i].name_len = strlen(fields[i].name);
    fields[i].required = i == 0;
    fields[i].many = i != 0;
  }
  return gdefcore_type_define(catalog, kChangeType, strlen(kChangeType), GDEFCORE_TYPE_CONFIG,
      fields, 2);
}

/* The id of the record, or ::GDEFCORE_ERR_INVALID when there is none. */
static GDEFCORE_Result change_find(GDEFCORE_Catalog * catalog, int made,
    char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kChangeType, strlen(kChangeType), &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = GDEFCORE_ERR_INVALID;
  for (i = 0; i < count && rc == GDEFCORE_ERR_INVALID; i++) {
    if (strlen(ids[i]) == GDEFCORE_PUBLIC_ID_LEN) {
      memcpy(id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      rc = GDEFCORE_OK;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  if (rc == GDEFCORE_ERR_INVALID && made) {
    rc = gdefcore_entity_create(catalog, kChangeType, strlen(kChangeType), id, NULL);
  }
  return rc;
}

static GDEFCORE_Result change_save(GDEFCORE_Changeset * cs, const char * const * lines,
    const size_t * lens, size_t n) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[2];
  const char * slot;
  size_t len;
  GDEFCORE_Result rc = change_find(gdefcore_changeset_catalog(cs), 1, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  value_set(&values[0], "name", &slot, &len, "last", 4);
  memset(&values[1], 0, sizeof values[1]);
  values[1].size = sizeof values[1];
  values[1].field = "entities";
  values[1].field_len = 8;
  values[1].texts = lines;
  values[1].text_lens = lens;
  values[1].count = n;
  return gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, values, 2);
}

static int change_type_is(const char * type, size_t n) {
  return span_eq(type, n, kChangeTemplate, sizeof kChangeTemplate - 1) ||
         span_eq(type, n, kChangeDisplay, sizeof kChangeDisplay - 1) ||
         span_eq(type, n, kChangeAsset, sizeof kChangeAsset - 1);
}

GDEFCORE_Result gdefcore_structure_stage_record(GDEFCORE_Changeset * changeset) {
  enum { kLineMax = 64 };
  size_t touched;
  size_t i;
  size_t n = 0;
  size_t nonroot = 0;
  char (*text)[kLineMax];
  const char ** lines;
  size_t * lens;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  touched = gdefcore_changeset_touched_count(changeset);
  text = (char (*)[kLineMax])malloc((touched == 0 ? 1 : touched) * sizeof *text);
  lines = (const char **)malloc((touched == 0 ? 1 : touched) * sizeof *lines);
  lens = (size_t *)malloc((touched == 0 ? 1 : touched) * sizeof *lens);
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
    if (gdefcore_changeset_touched_at(changeset, i, &id, &id_len, &type, &type_len, &op) !=
            GDEFCORE_OK ||
        type == NULL || !change_type_is(type, type_len)) {
      continue;
    }
    /* A template alone is an ordinary revision: only a change that wrote a layout
     * or a stylesheet with it is one this record takes back whole. */
    if (!span_eq(type, type_len, kChangeTemplate, sizeof kChangeTemplate - 1)) {
      nonroot += 1;
    }
    if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK ||
        gdefcore_changeset_base_seq(changeset, canon, GDEFCORE_PUBLIC_ID_LEN, &seq) !=
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
  if (nonroot == 0) {
    goto done;
  }
  rc = change_save(changeset, lines, lens, n > GDEFCORE_STRUCTURE_UNDO_MAX ? 0 : n);
done:
  free(text);
  free(lines);
  free(lens);
  return rc;
}

/* One line of the record: the entity, the revision it had before the change and
 * whether the change cleared it. */
static int change_line(const char * s, size_t n, char id[GDEFCORE_PUBLIC_ID_LEN + 1], uint64_t * seq,
    int * cleared) {
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
  if (digits == 0 || i + 2 != n || s[i] != ' ' || (s[i + 1] != 'S' && s[i + 1] != 'C')) {
    return 0;
  }
  *seq = v;
  *cleared = s[i + 1] == 'C';
  return 1;
}

int gdefcore_structure_can_undo(GDEFCORE_Catalog * catalog) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  if (catalog == NULL || change_find(catalog, 0, id) != GDEFCORE_OK ||
      gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_CURRENT, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
          sizeof kLang - 1, "entities", 8, &texts, &lens, &n) != GDEFCORE_OK) {
    return 0;
  }
  gdefcore_values_free(catalog, texts, lens, n);
  return n > 0;
}

/* Write the values entity @p id had at revision @p seq as its newest: every field
 * of its type that had a value then, with each value it had, and a field that has
 * one now and had none then, cleared. */
static GDEFCORE_Result change_restore(GDEFCORE_Changeset * cs, const char * id, uint64_t seq) {
  GDEFCORE_Catalog * catalog = gdefcore_changeset_catalog(cs);
  char * type = NULL;
  size_t type_n = 0;
  size_t nfields = 0;
  size_t nv = 0;
  GDEFCORE_Value * values = NULL;
  char *** texts = NULL;
  size_t ** lens = NULL;
  size_t * counts = NULL;
  char ** names = NULL;
  size_t k;
  GDEFCORE_Result rc;
  rc = gdefcore_entity_type(catalog, id, GDEFCORE_PUBLIC_ID_LEN, &type, &type_n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_type_field_count(catalog, type, type_n, &nfields);
  if (rc != GDEFCORE_OK || nfields == 0) {
    gdefcore_text_free(catalog, type);
    return rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_INTERNAL;
  }
  values = (GDEFCORE_Value *)calloc(nfields, sizeof *values);
  texts = (char ***)calloc(nfields, sizeof *texts);
  lens = (size_t **)calloc(nfields, sizeof *lens);
  counts = (size_t *)calloc(nfields, sizeof *counts);
  names = (char **)calloc(nfields, sizeof *names);
  if (values == NULL || texts == NULL || lens == NULL || counts == NULL || names == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  for (k = 0; rc == GDEFCORE_OK && k < nfields; k++) {
    char * name = NULL;
    size_t name_n = 0;
    int req = 0;
    int many = 0;
    int keep = 1;
    GDEFCORE_Result got = gdefcore_type_field(catalog, type, type_n, k, &name, &name_n, &req, &many);
    if (got != GDEFCORE_OK) {
      rc = got;
      break;
    }
    got = gdefcore_entity_revision_values(catalog, id, GDEFCORE_PUBLIC_ID_LEN, seq, kLang,
        sizeof kLang - 1, name, name_n, &texts[nv], &lens[nv], &counts[nv]);
    if (got == GDEFCORE_ERR_INVALID) {
      counts[nv] = 0;   /* a field that revision did not have */
    } else if (got != GDEFCORE_OK) {
      rc = got;
    }
    if (rc == GDEFCORE_OK && counts[nv] == 0) {
      /* Nothing then: it is cleared only if something is there now. */
      char ** now = NULL;
      size_t * now_lens = NULL;
      size_t now_n = 0;
      if (gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_CURRENT, id, GDEFCORE_PUBLIC_ID_LEN,
              kLang, sizeof kLang - 1, name, name_n, &now, &now_lens, &now_n) == GDEFCORE_OK) {
        gdefcore_values_free(catalog, now, now_lens, now_n);
      }
      keep = now_n > 0;
    }
    if (rc == GDEFCORE_OK && keep) {
      names[nv] = (char *)malloc(name_n + 1);
      if (names[nv] == NULL) {
        rc = GDEFCORE_ERR_OOM;
      } else {
        memcpy(names[nv], name, name_n);
        names[nv][name_n] = '\0';
        values[nv].size = sizeof values[nv];
        values[nv].field = names[nv];
        values[nv].field_len = name_n;
        values[nv].texts = (const char * const *)texts[nv];
        values[nv].text_lens = lens[nv];
        values[nv].count = counts[nv];
        nv += 1;
      }
    }
    gdefcore_text_free(catalog, name);
  }
  if (rc == GDEFCORE_OK && nv > 0) {
    rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, kLang, sizeof kLang - 1, values, nv);
  }
  for (k = 0; k < nv; k++) {
    free(names[k]);
    if (counts[k] > 0) {
      gdefcore_values_free(catalog, texts[k], lens[k], counts[k]);
    }
  }
  free(names);
  free(values);
  free(texts);
  free(lens);
  free(counts);
  gdefcore_text_free(catalog, type);
  return rc;
}

typedef enum { kUndoSkip, kUndoClear, kUndoRestore } UndoAct;

GDEFCORE_Result gdefcore_structure_stage_undo(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request) {
  GDEFCORE_Catalog * catalog;
  char journal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  UndoAct * act = NULL;
  uint64_t * base = NULL;
  size_t k;
  GDEFCORE_Result rc;
  if (changeset == NULL || request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  if (!gdefcore_layout_may_edit(catalog, request) &&
      !gdefcore_template_may_edit(catalog, request, "core.page", 9)) {
    (void)gdefcore_changeset_set_refusal(changeset, kChangeNotAllowed, sizeof kChangeNotAllowed - 1);
    return GDEFCORE_ERR_INVALID;
  }
  rc = change_find(catalog, 0, journal);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_CURRENT, journal, GDEFCORE_PUBLIC_ID_LEN,
        kLang, sizeof kLang - 1, "entities", 8, &texts, &lens, &n);
  }
  if (rc == GDEFCORE_ERR_INVALID || (rc == GDEFCORE_OK && n == 0)) {
    if (rc == GDEFCORE_OK) {
      gdefcore_values_free(catalog, texts, lens, n);
    }
    (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_STRUCTURE_REFUSED_NOTHING,
        sizeof GDEFCORE_STRUCTURE_REFUSED_NOTHING - 1);
    return GDEFCORE_ERR_INVALID;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  act = (UndoAct *)calloc(n, sizeof *act);
  base = (uint64_t *)calloc(n, sizeof *base);
  if (act == NULL || base == NULL) {
    rc = GDEFCORE_ERR_OOM;
  }
  /* Everything is decided before anything is staged: an entity written since the
   * change refuses the whole undo. */
  for (k = 0; rc == GDEFCORE_OK && k < n; k++) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    int cleared = 0;
    int has = 0;
    uint64_t seq = 0;
    uint64_t latest = 0;
    if (!change_line(texts[k], lens[k], id, &base[k], &cleared) ||
        gdefcore_entity_current_revision(catalog, id, GDEFCORE_PUBLIC_ID_LEN, &has, &seq) !=
            GDEFCORE_OK ||
        gdefcore_entity_revision(catalog, id, GDEFCORE_PUBLIC_ID_LEN, &latest) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_INVALID;
      break;
    }
    if (cleared) {
      if (!has && latest == base[k] && base[k] > 0) {
        act[k] = kUndoRestore;
      } else {
        rc = GDEFCORE_ERR_INVALID;
      }
    } else if (has && seq == base[k] + 1) {
      act[k] = base[k] == 0 ? kUndoClear : kUndoRestore;
    } else if (has && seq == base[k] && base[k] > 0) {
      act[k] = kUndoSkip;   /* the change saved what the entity already held */
    } else {
      rc = GDEFCORE_ERR_INVALID;
    }
  }
  if (rc == GDEFCORE_ERR_INVALID) {
    (void)gdefcore_changeset_set_refusal(changeset, GDEFCORE_STRUCTURE_REFUSED_UNDO,
        sizeof GDEFCORE_STRUCTURE_REFUSED_UNDO - 1);
  }
  for (k = 0; rc == GDEFCORE_OK && k < n; k++) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    int cleared = 0;
    uint64_t seq = 0;
    if (act[k] == kUndoSkip) {
      continue;
    }
    if (!change_line(texts[k], lens[k], id, &seq, &cleared)) {
      rc = GDEFCORE_ERR_INTERNAL;
    } else if (act[k] == kUndoClear) {
      rc = gdefcore_entity_clear(changeset, id, GDEFCORE_PUBLIC_ID_LEN);
    } else {
      rc = change_restore(changeset, id, base[k]);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = change_save(changeset, NULL, NULL, 0);
  }
  gdefcore_values_free(catalog, texts, lens, n);
  free(act);
  free(base);
  return rc;
}
