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
 * One page selects one display. Tang runs the layout and the panes and
 * returns the bytes already written when a template's scope runs out.
 * The kernel does not name regions: a layout template declares its own.
 * Render reads the tenant store. It does not read the kit archive.
 */

#include <ghoti.io/defiant-core/macros.h>

#include "render_internal.h"

#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/sink.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/archive/writer.h>
#include <ghoti.io/lang-tang/compile.h>
#include <ghoti.io/lang-tang/execution.h>
#include <ghoti.io/lang-tang/parse.h>
#include <ghoti.io/lang-tang/value.h>
#include <ghoti.io/runtime-core/runtime-core.h>
#include <ghoti.io/runtime-heap/runtime-heap.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RENDER_MAGIC 0x524B4954u
#define RENDER_SUMMARY_CHARS 600u
#define RENDER_MAX_PANES 32u
#define RENDER_MAX_REGIONS 16u
#define RENDER_MAX_VIEW 64u
#define RENDER_MEMBER_CAP (2u * 1024u * 1024u)

static const char kBreak[] = "<!--break-->";
static const char kWrap[] = "use pane;\nprint(pane());\n";
static const char kConfirm[] =
    "core.display\ncore.template\ncore.theme\ncore.view\nsite.post";

static const char kLayoutBody[] =
    "<% use region; %>"
    "<div class=\"main\"><%= region(\"main\") %></div>"
    "<div class=\"side\"><%= region(\"side\") %></div>";
static const char kEntityBody[] =
    "<% use title; use body; %>"
    "<article class=\"post\"><h1><%= title.html %></h1>"
    "<div class=\"body\"><%= body.html %></div></article>";
static const char kRecentBody[] =
    "<% use title; use summary; %>"
    "<article class=\"recent\"><h2><%= title.html %></h2>"
    "<p><%= summary.html %></p></article>";
static const char kFieldBody[] = "<% use value; %><%= value.html %>";

typedef struct TangBind {
  const char * name;
  const char * text;
  size_t len;
} TangBind;

typedef struct RegionSlot {
  char name[64];
  size_t name_len;
  char * html;
  size_t html_len;
  size_t cap;
} RegionSlot;

typedef struct RegionSet {
  RegionSlot slots[RENDER_MAX_REGIONS];
  size_t n;
} RegionSet;

static int span_eq(const char * a, size_t an, const char * b, size_t bn) {
  if (an != bn) {
    return 0;
  }
  return an == 0 || memcmp(a, b, an) == 0;
}

static const char * find_bytes(const char * s, size_t n, const char * needle,
    size_t m) {
  size_t i;
  if (m == 0 || m > n) {
    return NULL;
  }
  for (i = 0; i + m <= n; i++) {
    if (memcmp(s + i, needle, m) == 0) {
      return s + i;
    }
  }
  return NULL;
}

static int is_ws(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* One code point, or one byte when the sequence is not UTF-8. */
static size_t utf8_next(const char * s, size_t n, size_t i) {
  unsigned char c;
  size_t need;
  size_t k;
  if (i >= n) {
    return n;
  }
  c = (unsigned char)s[i];
  if (c < 0x80u) {
    return i + 1;
  }
  if ((c & 0xE0u) == 0xC0u) {
    need = 2;
  } else if ((c & 0xF0u) == 0xE0u) {
    need = 3;
  } else if ((c & 0xF8u) == 0xF0u) {
    need = 4;
  } else {
    return i + 1;
  }
  if (i + need > n) {
    return i + 1;
  }
  for (k = 1; k < need; k++) {
    if (((unsigned char)s[i + k] & 0xC0u) != 0x80u) {
      return i + 1;
    }
  }
  return i + need;
}

static void trim_summary(const char * body, size_t n, const char ** out,
    size_t * out_n) {
  size_t i = 0;
  size_t chars = 0;
  size_t boundary = n;
  size_t ws = 0;
  int saw = 0;
  int over = 0;
  while (i < n) {
    size_t next;
    if (chars == RENDER_SUMMARY_CHARS) {
      over = 1;
      boundary = i;
      break;
    }
    next = utf8_next(body, n, i);
    if (next == i) {
      break;
    }
    if (next == i + 1 && is_ws((unsigned char)body[i]) && i > 0) {
      ws = i;
      saw = 1;
    }
    i = next;
    chars += 1;
  }
  if (!over) {
    *out = body;
    *out_n = n;
    return;
  }
  *out = body;
  *out_n = saw ? ws : boundary;
}

static void summary_of(const char * summary, size_t slen, const char * body,
    size_t blen, const char ** out, size_t * out_n) {
  const char * hit;
  if (slen > 0) {
    *out = summary;
    *out_n = slen;
    return;
  }
  hit = find_bytes(body, blen, kBreak, sizeof kBreak - 1);
  if (hit != NULL) {
    *out = body;
    *out_n = (size_t)(hit - body);
    return;
  }
  trim_summary(body, blen, out, out_n);
}

static GDEFCORE_Result strip_marker(GDEFCORE_Catalog * catalog,
    const char * body, size_t blen, char ** out, size_t * out_len) {
  size_t m = sizeof kBreak - 1;
  size_t i = 0;
  size_t n = 0;
  char * buf;
  while (i < blen) {
    if (i + m <= blen && memcmp(body + i, kBreak, m) == 0) {
      i += m;
      continue;
    }
    n += 1;
    i += 1;
  }
  buf = NULL;
  if (gdefcore_text_dup(catalog, "", 0, &buf) != GDEFCORE_OK) {
    return GDEFCORE_ERR_OOM;
  }
  gdefcore_text_free(catalog, buf);
  buf = NULL;
  if (gdefcore_text_dup(catalog, body, n == blen ? blen : n, &buf) !=
      GDEFCORE_OK) {
    return GDEFCORE_ERR_OOM;
  }
  if (n != blen) {
    size_t w = 0;
    i = 0;
    while (i < blen) {
      if (i + m <= blen && memcmp(body + i, kBreak, m) == 0) {
        i += m;
        continue;
      }
      buf[w++] = body[i++];
    }
    buf[w] = '\0';
  }
  *out = buf;
  *out_len = n;
  return GDEFCORE_OK;
}

static void put_be32(uint8_t * p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t * p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
      ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void set_field(GDEFCORE_Field * field, const char * name, int required,
    int many) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = required;
  field->many = many;
}

static void set_value(GDEFCORE_Value * value, const char * field,
    const char * const * texts, const size_t * lens, size_t count) {
  memset(value, 0, sizeof *value);
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = texts;
  value->text_lens = lens;
  value->count = count;
}

static GDEFCORE_Result save_entity(GDEFCORE_Catalog * catalog,
    const char * type, const GDEFCORE_Value * values, size_t count, int high) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Result rc;
  rc = gdefcore_entity_create(catalog, type, strlen(type), id, NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values,
      count);
  if (rc != GDEFCORE_OK) {
    gdefcore_changeset_destroy(cs);
    return rc;
  }
  rc = gdefcore_changeset_apply(cs, high ? type : NULL, high ? strlen(type) : 0);
  gdefcore_changeset_destroy(cs);
  return rc;
}

static GDEFCORE_Result find_named(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  int found = 0;
  GDEFCORE_Result rc;
  rc = gdefcore_entity_ids(catalog, type, type_len, &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    size_t idn = strlen(ids[i]);
    if (idn != GDEFCORE_PUBLIC_ID_LEN) {
      continue;
    }
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
        idn, "en", 2, "name", 4, &texts, &lens, &n);
    if (rc == GDEFCORE_OK && n > 0 && span_eq(texts[0], lens[0], name, name_len)) {
      memcpy(out_id, ids[i], idn + 1);
      found = 1;
    }
    if (rc == GDEFCORE_OK) {
      gdefcore_values_free(catalog, texts, lens, n);
    }
    if (found) {
      break;
    }
    if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_INVALID) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  return found ? GDEFCORE_OK : GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result config_text(GDEFCORE_Catalog * catalog, const char * id,
    const char * field, int required, char ** out, size_t * out_len) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc;
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      strlen(id), "en", 2, field, strlen(field), &texts, &lens, &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    if (!required) {
      *out = NULL;
      *out_len = 0;
      return GDEFCORE_OK;
    }
    return rc;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count == 0) {
    gdefcore_values_free(catalog, texts, lens, count);
    if (!required) {
      *out = NULL;
      *out_len = 0;
      return GDEFCORE_OK;
    }
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_text_dup(catalog, texts[0], lens[0], out);
  if (rc == GDEFCORE_OK) {
    *out_len = lens[0];
  }
  gdefcore_values_free(catalog, texts, lens, count);
  return rc;
}

static GDEFCORE_Result template_body(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, char ** body, size_t * body_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  rc = find_named(catalog, "core.template", 13, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return config_text(catalog, id, "body", 1, body, body_len);
}

/*
 * unsafe: the pane template already escaped field values. The layout
 * pastes those bytes as trusted so the tags survive.
 */
static bool native_region(GLTANG_NativeCall * call, void * user) {
  RegionSet * set = (RegionSet *)user;
  size_t n = 0;
  const char * name;
  size_t i;
  name = gltang_call_text(call, 0, &n);
  if (name == NULL) {
    gltang_call_return_string(call, "", 0, GLTANG_UNICODE_STRING_TYPE_TRUSTED);
    return true;
  }
  for (i = 0; i < set->n; i++) {
    if (set->slots[i].name_len == n &&
        memcmp(set->slots[i].name, name, n) == 0) {
      const char * html = set->slots[i].html == NULL ? "" : set->slots[i].html;
      gltang_call_return_string(call, html, set->slots[i].html_len,
          GLTANG_UNICODE_STRING_TYPE_TRUSTED);
      return true;
    }
  }
  gltang_call_return_string(call, "", 0, GLTANG_UNICODE_STRING_TYPE_TRUSTED);
  return true;
}

static GDEFCORE_Result region_add(RegionSet * set, const char * name,
    size_t nlen, const char * html, size_t hlen) {
  size_t i;
  RegionSlot * slot = NULL;
  if (nlen == 0 || nlen >= sizeof set->slots[0].name) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < set->n; i++) {
    if (set->slots[i].name_len == nlen &&
        memcmp(set->slots[i].name, name, nlen) == 0) {
      slot = &set->slots[i];
      break;
    }
  }
  if (slot == NULL) {
    if (set->n >= RENDER_MAX_REGIONS) {
      return GDEFCORE_ERR_LIMIT;
    }
    slot = &set->slots[set->n];
    memcpy(slot->name, name, nlen);
    slot->name[nlen] = '\0';
    slot->name_len = nlen;
    slot->html = NULL;
    slot->html_len = 0;
    slot->cap = 0;
    set->n += 1;
  }
  if (hlen == 0) {
    return GDEFCORE_OK;
  }
  if (slot->html_len > SIZE_MAX - hlen) {
    return GDEFCORE_ERR_LIMIT;
  }
  if (slot->html_len + hlen > slot->cap) {
    size_t cap = slot->cap == 0 ? 64 : slot->cap;
    char * next;
    while (cap < slot->html_len + hlen) {
      if (cap > SIZE_MAX / 2) {
        return GDEFCORE_ERR_LIMIT;
      }
      cap *= 2;
    }
    next = (char *)realloc(slot->html, cap);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    slot->html = next;
    slot->cap = cap;
  }
  memcpy(slot->html + slot->html_len, html, hlen);
  slot->html_len += hlen;
  return GDEFCORE_OK;
}

static void region_clear(RegionSet * set) {
  size_t i;
  for (i = 0; i < set->n; i++) {
    free(set->slots[i].html);
    set->slots[i].html = NULL;
  }
  set->n = 0;
}

static GDEFCORE_Result tang_run(GDEFCORE_Catalog * catalog, const char * source,
    size_t source_len, uint64_t scope_fuel, const TangBind * binds, size_t nbinds,
    GLTANG_NativeFn native, void * native_user, const char * native_name,
    char ** out, size_t * out_len) {
  char * source_z = NULL;
  GLTANG_Tree * body_tree = NULL;
  GLTANG_Tree * wrap_tree = NULL;
  GLTANG_Program * body = NULL;
  GLTANG_Program * wrap = NULL;
  GLTANG_Library * lib = NULL;
  GRCORE_Group * group = NULL;
  GRCORE_Options * options = NULL;
  GRHEAP_Options * heap_options = NULL;
  GRCORE_Context * context = NULL;
  GRHEAP_Heap * heap = NULL;
  GLTANG_Execution * execution = NULL;
  char * rendered = NULL;
  size_t rendered_len = 0;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  GLTANG_ParseError error;
  GRCORE_Outcome outcome = GRCORE_OUTCOME_FINISHED;
  uint64_t ceiling;
  size_t i;
  if (catalog == NULL || source == NULL || out == NULL || out_len == NULL ||
      scope_fuel == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  source_z = (char *)malloc(source_len + 1);
  if (source_z == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (source_len > 0) {
    memcpy(source_z, source, source_len);
  }
  source_z[source_len] = '\0';
  if (gltang_parse(source_z, GLTANG_PARSE_TEMPLATE, &error, &body_tree) !=
          GLTANG_OK ||
      gltang_compile(body_tree, "pane.tang", &error, &body) != GLTANG_OK ||
      gltang_parse(kWrap, GLTANG_PARSE_SCRIPT, &error, &wrap_tree) != GLTANG_OK ||
      gltang_compile(wrap_tree, "wrap.tang", &error, &wrap) != GLTANG_OK) {
    rc = GDEFCORE_ERR_FORMAT;
    goto done;
  }
  if (gltang_library_create(NULL, &lib) != GLTANG_OK) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  for (i = 0; i < nbinds; i++) {
    const char * text = binds[i].text == NULL ? "" : binds[i].text;
    if (gltang_library_add_string(lib, binds[i].name, text, binds[i].len,
            GLTANG_UNICODE_STRING_TYPE_TRUSTED) != GLTANG_OK) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
  }
  if (native != NULL &&
      gltang_library_add_native(lib, native_name, native, native_user) !=
          GLTANG_OK) {
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  if (gltang_library_add_template(lib, "pane", body, scope_fuel,
          GLTANG_SCOPE_SEGMENTS) != GLTANG_OK) {
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  ceiling = scope_fuel;
  if (ceiling <= UINT64_MAX - 1000000ull) {
    ceiling += 1000000ull;
  }
  if (grcore_group_create(NULL, NULL, &group) != GRCORE_OK ||
      grcore_options_create(NULL, &options) != GRCORE_OK ||
      grheap_options_create(NULL, &heap_options) != GRHEAP_OK) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  grcore_options_set_fuel(options, ceiling);
  if (gltang_heap_options_configure(heap_options) != GLTANG_OK ||
      grcore_context_create(group, options, &context) != GRCORE_OK ||
      grheap_heap_create(context, heap_options, &heap) != GRHEAP_OK ||
      gltang_execution_create(context, wrap, &execution) != GLTANG_OK ||
      gltang_execution_set_libraries(execution, lib) != GLTANG_OK) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  if (grcore_run(context, gltang_execution_entry, execution, &outcome) !=
          GRCORE_OK ||
      outcome != GRCORE_OUTCOME_FINISHED) {
    rc = GDEFCORE_ERR_LIMIT;
    goto done;
  }
  if (gltang_execution_output_render(execution, &rendered, &rendered_len) !=
      GLTANG_OK) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  rc = gdefcore_text_dup(catalog, rendered, rendered_len, out);
  if (rc == GDEFCORE_OK) {
    *out_len = rendered_len;
  }
done:
  (void)heap;
  gltang_buffer_free(rendered);
  if (context != NULL) {
    grcore_context_destroy(context);
  }
  if (heap_options != NULL) {
    grheap_options_destroy(heap_options);
  }
  if (options != NULL) {
    grcore_options_destroy(options);
  }
  if (group != NULL) {
    grcore_group_destroy(group);
  }
  gltang_library_release(lib);
  gltang_program_release(wrap);
  gltang_program_release(body);
  gltang_tree_destroy(wrap_tree);
  gltang_tree_destroy(body_tree);
  free(source_z);
  return rc;
}

static GDEFCORE_Result access_copy(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len, const char * field,
    char ** out, size_t * out_len, int * missing) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc;
  *missing = 0;
  *out = NULL;
  *out_len = 0;
  rc = gdefcore_access_read(catalog, request, id, id_len, "en", 2, field,
      strlen(field), &texts, &lens, &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    *missing = 1;
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (count == 0) {
    gdefcore_values_free(catalog, texts, lens, count);
    return GDEFCORE_OK;
  }
  rc = gdefcore_text_dup(catalog, texts[0], lens[0], out);
  if (rc == GDEFCORE_OK) {
    *out_len = lens[0];
  }
  gdefcore_values_free(catalog, texts, lens, count);
  return rc;
}

static GDEFCORE_Result render_one(GDEFCORE_Catalog * catalog,
    const char * tmpl, size_t tmpl_len, uint64_t fuel, const TangBind * binds,
    size_t nbinds, char ** html, size_t * html_len) {
  char * body = NULL;
  size_t body_len = 0;
  GDEFCORE_Result rc;
  rc = template_body(catalog, tmpl, tmpl_len, &body, &body_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = tang_run(catalog, body, body_len, fuel, binds, nbinds, NULL, NULL, NULL,
      html, html_len);
  gdefcore_text_free(catalog, body);
  return rc;
}

static GDEFCORE_Result render_entity_pane(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * tmpl, size_t tmpl_len,
    uint64_t fuel, char ** html, size_t * html_len) {
  const char * id;
  size_t id_len = 0;
  char * title = NULL;
  char * body = NULL;
  char * shown = NULL;
  size_t title_len = 0;
  size_t body_len = 0;
  size_t shown_len = 0;
  int missing = 0;
  TangBind binds[2];
  GDEFCORE_Result rc;
  id = gdefcore_request_resolution(request, &id_len);
  if (id == NULL || id_len == 0) {
    *html = NULL;
    *html_len = 0;
    return gdefcore_text_dup(catalog, "", 0, html);
  }
  rc = access_copy(catalog, request, id, id_len, "title", &title, &title_len,
      &missing);
  if (rc != GDEFCORE_OK || missing) {
    gdefcore_text_free(catalog, title);
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : rc;
  }
  rc = access_copy(catalog, request, id, id_len, "body", &body, &body_len,
      &missing);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, title);
    return rc;
  }
  rc = strip_marker(catalog, body == NULL ? "" : body, body_len, &shown,
      &shown_len);
  gdefcore_text_free(catalog, body);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, title);
    return rc;
  }
  binds[0].name = "title";
  binds[0].text = title;
  binds[0].len = title_len;
  binds[1].name = "body";
  binds[1].text = shown;
  binds[1].len = shown_len;
  rc = render_one(catalog, tmpl, tmpl_len, fuel, binds, 2, html, html_len);
  gdefcore_text_free(catalog, title);
  gdefcore_text_free(catalog, shown);
  return rc;
}

static GDEFCORE_Result render_field_pane(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * field, size_t field_len,
    uint64_t fuel, char ** html, size_t * html_len) {
  const char * id;
  size_t id_len = 0;
  char * value = NULL;
  size_t value_len = 0;
  int missing = 0;
  char name[65];
  TangBind bind;
  GDEFCORE_Result rc;
  id = gdefcore_request_resolution(request, &id_len);
  if (id == NULL || field_len == 0 || field_len >= sizeof name) {
    return gdefcore_text_dup(catalog, "", 0, html) == GDEFCORE_OK
        ? (*html_len = 0, GDEFCORE_OK)
        : GDEFCORE_ERR_OOM;
  }
  memcpy(name, field, field_len);
  name[field_len] = '\0';
  rc = access_copy(catalog, request, id, id_len, name, &value, &value_len,
      &missing);
  if (rc != GDEFCORE_OK || missing) {
    gdefcore_text_free(catalog, value);
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : rc;
  }
  bind.name = "value";
  bind.text = value == NULL ? "" : value;
  bind.len = value_len;
  rc = render_one(catalog, "field", 5, fuel, &bind, 1, html, html_len);
  gdefcore_text_free(catalog, value);
  return rc;
}

static GDEFCORE_Result render_view_pane(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * view, size_t view_len,
    uint64_t fuel, char ** html, size_t * html_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type = NULL;
  char * limit_text = NULL;
  char * tmpl = NULL;
  char * sort = NULL;
  size_t type_len = 0;
  size_t limit_len = 0;
  size_t tmpl_len = 0;
  size_t sort_len = 0;
  uint64_t limit = 0;
  char ** ids = NULL;
  size_t count = 0;
  size_t taken = 0;
  size_t i;
  char kept[RENDER_MAX_VIEW][GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Access_List query;
  GDEFCORE_Result rc;
  *html = NULL;
  *html_len = 0;
  rc = find_named(catalog, "core.view", 9, view, view_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = config_text(catalog, id, "type", 1, &type, &type_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = config_text(catalog, id, "limit", 1, &limit_text, &limit_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type);
    return rc;
  }
  rc = config_text(catalog, id, "template", 1, &tmpl, &tmpl_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type);
    gdefcore_text_free(catalog, limit_text);
    return rc;
  }
  rc = config_text(catalog, id, "sort", 0, &sort, &sort_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type);
    gdefcore_text_free(catalog, limit_text);
    gdefcore_text_free(catalog, tmpl);
    return rc;
  }
  for (i = 0; i < limit_len; i++) {
    if (limit_text[i] < '0' || limit_text[i] > '9') {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    limit = limit * 10u + (uint64_t)(limit_text[i] - '0');
  }
  if (limit == 0 || limit > RENDER_MAX_VIEW) {
    rc = GDEFCORE_ERR_LIMIT;
    goto done;
  }
  memset(&query, 0, sizeof query);
  query.size = sizeof query;
  query.type_name = type;
  query.type_name_len = type_len;
  query.lang = "en";
  query.lang_len = 2;
  if (sort != NULL && sort_len > 0) {
    query.sort_field = sort;
    query.sort_field_len = sort_len;
  }
  rc = gdefcore_access_list(catalog, request, &query, &ids, &count);
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  if (sort != NULL && sort_len > 0) {
    for (i = 0; i < count && taken < limit; i++) {
      char * title = NULL;
      size_t title_len = 0;
      int missing = 0;
      rc = access_copy(catalog, request, ids[i], GDEFCORE_PUBLIC_ID_LEN, "title",
          &title, &title_len, &missing);
      gdefcore_text_free(catalog, title);
      if (rc != GDEFCORE_OK) {
        goto done;
      }
      if (missing) {
        continue;
      }
      memcpy(kept[taken], ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      taken += 1;
    }
  } else {
    i = count;
    while (i > 0 && taken < limit) {
      char * title = NULL;
      size_t title_len = 0;
      int missing = 0;
      i -= 1;
      rc = access_copy(catalog, request, ids[i], GDEFCORE_PUBLIC_ID_LEN, "title",
          &title, &title_len, &missing);
      gdefcore_text_free(catalog, title);
      if (rc != GDEFCORE_OK) {
        goto done;
      }
      if (missing) {
        continue;
      }
      memcpy(kept[taken], ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      taken += 1;
    }
  }
  rc = gdefcore_text_dup(catalog, "", 0, html);
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  *html_len = 0;
  for (i = 0; i < taken; i++) {
    char * title = NULL;
    char * body = NULL;
    char * summary = NULL;
    char * piece = NULL;
    size_t title_len = 0;
    size_t body_len = 0;
    size_t summary_len = 0;
    size_t piece_len = 0;
    int missing = 0;
    const char * sum;
    size_t sum_len = 0;
    char * joined = NULL;
    TangBind binds[2];
    rc = access_copy(catalog, request, kept[i], GDEFCORE_PUBLIC_ID_LEN, "title",
        &title, &title_len, &missing);
    if (rc != GDEFCORE_OK) {
      goto piece_done;
    }
    rc = access_copy(catalog, request, kept[i], GDEFCORE_PUBLIC_ID_LEN, "body",
        &body, &body_len, &missing);
    if (rc != GDEFCORE_OK) {
      goto piece_done;
    }
    rc = access_copy(catalog, request, kept[i], GDEFCORE_PUBLIC_ID_LEN,
        "summary", &summary, &summary_len, &missing);
    if (rc != GDEFCORE_OK) {
      goto piece_done;
    }
    if (missing) {
      summary_len = 0;
    }
    summary_of(summary, summary_len, body == NULL ? "" : body, body_len, &sum,
        &sum_len);
    binds[0].name = "title";
    binds[0].text = title == NULL ? "" : title;
    binds[0].len = title_len;
    binds[1].name = "summary";
    binds[1].text = sum;
    binds[1].len = sum_len;
    rc = render_one(catalog, tmpl, tmpl_len, fuel, binds, 2, &piece, &piece_len);
    if (rc != GDEFCORE_OK) {
      goto piece_done;
    }
    joined = NULL;
    if (gdefcore_text_dup(catalog, "", 0, &joined) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_OOM;
      goto piece_done;
    }
    gdefcore_text_free(catalog, joined);
    joined = (char *)malloc(*html_len + piece_len + 1);
    if (joined == NULL) {
      rc = GDEFCORE_ERR_OOM;
      goto piece_done;
    }
    if (*html_len > 0) {
      memcpy(joined, *html, *html_len);
    }
    if (piece_len > 0) {
      memcpy(joined + *html_len, piece, piece_len);
    }
    joined[*html_len + piece_len] = '\0';
    gdefcore_text_free(catalog, *html);
    *html = NULL;
    rc = gdefcore_text_dup(catalog, joined, *html_len + piece_len, html);
    free(joined);
    if (rc == GDEFCORE_OK) {
      *html_len += piece_len;
    }
  piece_done:
    gdefcore_text_free(catalog, title);
    gdefcore_text_free(catalog, body);
    gdefcore_text_free(catalog, summary);
    gdefcore_text_free(catalog, piece);
    if (rc != GDEFCORE_OK) {
      goto done;
    }
  }
  rc = GDEFCORE_OK;
done:
  gdefcore_access_free(catalog, ids, count);
  gdefcore_text_free(catalog, type);
  gdefcore_text_free(catalog, limit_text);
  gdefcore_text_free(catalog, tmpl);
  gdefcore_text_free(catalog, sort);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, *html);
    *html = NULL;
    *html_len = 0;
  }
  return rc;
}

static int split3(const char * s, size_t n, const char ** a, size_t * an,
    const char ** b, size_t * bn, const char ** c, size_t * cn) {
  size_t i = 0;
  size_t a0;
  size_t b0;
  size_t k;
  while (i < n && s[i] != ' ') {
    i += 1;
  }
  if (i == 0 || i >= n) {
    return 0;
  }
  a0 = i;
  i += 1;
  b0 = i;
  while (i < n && s[i] != ' ') {
    i += 1;
  }
  if (i == b0 || i + 1 >= n) {
    return 0;
  }
  for (k = i + 1; k < n; k++) {
    if (s[k] == ' ') {
      return 0;
    }
  }
  *a = s;
  *an = a0;
  *b = s + b0;
  *bn = i - b0;
  *c = s + i + 1;
  *cn = n - (i + 1);
  return *cn > 0;
}

static GDEFCORE_Result render_display(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * name, size_t name_len,
    uint64_t fuel, char ** out, size_t * out_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * layout = NULL;
  size_t layout_len = 0;
  char ** panes = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t i;
  RegionSet regions;
  char * layout_body = NULL;
  size_t layout_body_len = 0;
  GDEFCORE_Result rc;
  memset(&regions, 0, sizeof regions);
  rc = find_named(catalog, "core.display", 12, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = config_text(catalog, id, "layout", 1, &layout, &layout_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, "en", 2, "panes", 5, &panes, &lens, &count);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, layout);
    return rc;
  }
  if (count > RENDER_MAX_PANES) {
    rc = GDEFCORE_ERR_LIMIT;
    goto done;
  }
  for (i = 0; i < count; i++) {
    const char * region;
    const char * kind;
    const char * target;
    size_t region_len = 0;
    size_t kind_len = 0;
    size_t target_len = 0;
    char * html = NULL;
    size_t html_len = 0;
    if (!split3(panes[i], lens[i], &region, &region_len, &kind, &kind_len,
            &target, &target_len)) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    if (span_eq(kind, kind_len, "view", 4)) {
      rc = render_view_pane(catalog, request, target, target_len, fuel, &html,
          &html_len);
    } else if (span_eq(kind, kind_len, "entity", 6)) {
      rc = render_entity_pane(catalog, request, target, target_len, fuel, &html,
          &html_len);
    } else if (span_eq(kind, kind_len, "field", 5)) {
      rc = render_field_pane(catalog, request, target, target_len, fuel, &html,
          &html_len);
    } else {
      rc = GDEFCORE_ERR_INVALID;
    }
    if (rc != GDEFCORE_OK) {
      gdefcore_text_free(catalog, html);
      goto done;
    }
    rc = region_add(&regions, region, region_len, html == NULL ? "" : html,
        html_len);
    gdefcore_text_free(catalog, html);
    if (rc != GDEFCORE_OK) {
      goto done;
    }
  }
  rc = template_body(catalog, layout, layout_len, &layout_body, &layout_body_len);
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  rc = tang_run(catalog, layout_body, layout_body_len, fuel, NULL, 0,
      native_region, &regions, "region", out, out_len);
done:
  gdefcore_text_free(catalog, layout_body);
  gdefcore_values_free(catalog, panes, lens, count);
  gdefcore_text_free(catalog, layout);
  region_clear(&regions);
  return rc;
}

GDEFCORE_Result gdefcore_render_scope(GDEFCORE_Catalog * catalog,
    const char * source, size_t source_len, uint64_t scope_fuel, char ** out_bytes,
    size_t * out_len) {
  if (out_bytes == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return tang_run(catalog, source, source_len, scope_fuel, NULL, 0, NULL, NULL,
      NULL, out_bytes, out_len);
}

GDEFCORE_Result gdefcore_render_page(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request, const char * path,
    size_t path_len, uint64_t scope_fuel, char ** out_bytes, size_t * out_len) {
  char * resolved = NULL;
  size_t resolved_len = 0;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type = NULL;
  size_t type_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || path == NULL || out_bytes == NULL ||
      out_len == NULL || scope_fuel == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (path_len == 1 && path[0] == '/') {
    rc = gdefcore_request_set_resolution(request, NULL, 0);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    return render_display(catalog, request, "front", 5, scope_fuel, out_bytes,
        out_len);
  }
  rc = gdefcore_form_resolve(routes, catalog, request, path, path_len, &resolved,
      &resolved_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (gdefcore_id_canonical(resolved, resolved_len, canon) != GDEFCORE_OK) {
    gdefcore_text_free(catalog, resolved);
    return GDEFCORE_ERR_INVALID;
  }
  gdefcore_text_free(catalog, resolved);
  rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type,
      &type_len);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_INVALID ? rc : rc;
  }
  if (!span_eq(type, type_len, "site.post", 9)) {
    gdefcore_text_free(catalog, type);
    return GDEFCORE_ERR_INVALID;
  }
  gdefcore_text_free(catalog, type);
  rc = gdefcore_request_set_resolution(request, canon, GDEFCORE_PUBLIC_ID_LEN);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return render_display(catalog, request, "post", 4, scope_fuel, out_bytes,
      out_len);
}

static int axis_personal(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * field, size_t field_len) {
  size_t count = 0;
  size_t i;
  int found = 0;
  int personal = 0;
  if (field == NULL || field_len == 0) {
    return 0;
  }
  if (gdefcore_type_field_count(catalog, type, type_len, &count) != GDEFCORE_OK) {
    return 1;
  }
  for (i = 0; i < count; i++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int flag = 0;
    if (gdefcore_type_field(catalog, type, type_len, i, &name, &name_len,
            &required, &many) != GDEFCORE_OK) {
      return 1;
    }
    if (span_eq(name, name_len, field, field_len)) {
      found = 1;
      if (gdefcore_type_field_personal(catalog, type, type_len, i, &flag) ==
          GDEFCORE_OK) {
        personal = flag;
      } else {
        personal = 1;
      }
    }
    gdefcore_text_free(catalog, name);
    if (found) {
      break;
    }
  }
  return !found || personal;
}

GDEFCORE_Result gdefcore_render_view_define(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, const char * type_name, size_t type_len,
    uint64_t limit, const char * template_name, size_t template_len,
    const char * sort, size_t sort_len, const char * range, size_t range_len) {
  GDEFCORE_Value values[6];
  const char * texts[6];
  size_t lens[6];
  char limit_text[32];
  int n;
  size_t nvalues = 0;
  if (catalog == NULL || name == NULL || name_len == 0 || type_name == NULL ||
      type_len == 0 || template_name == NULL || template_len == 0 ||
      limit == 0 || limit > RENDER_MAX_VIEW) {
    return GDEFCORE_ERR_INVALID;
  }
  if (axis_personal(catalog, type_name, type_len, sort, sort_len) ||
      axis_personal(catalog, type_name, type_len, range, range_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  n = snprintf(limit_text, sizeof limit_text, "%llu", (unsigned long long)limit);
  if (n <= 0 || (size_t)n >= sizeof limit_text) {
    return GDEFCORE_ERR_LIMIT;
  }
  texts[0] = name;
  lens[0] = name_len;
  set_value(&values[nvalues++], "name", &texts[0], &lens[0], 1);
  texts[1] = type_name;
  lens[1] = type_len;
  set_value(&values[nvalues++], "type", &texts[1], &lens[1], 1);
  texts[2] = limit_text;
  lens[2] = (size_t)n;
  set_value(&values[nvalues++], "limit", &texts[2], &lens[2], 1);
  texts[3] = template_name;
  lens[3] = template_len;
  set_value(&values[nvalues++], "template", &texts[3], &lens[3], 1);
  if (sort != NULL && sort_len > 0) {
    texts[4] = sort;
    lens[4] = sort_len;
    set_value(&values[nvalues++], "sort", &texts[4], &lens[4], 1);
  }
  if (range != NULL && range_len > 0) {
    texts[5] = range;
    lens[5] = range_len;
    set_value(&values[nvalues++], "range", &texts[5], &lens[5], 1);
  }
  return save_entity(catalog, "core.view", values, nvalues, 1);
}

static void scan_regions(const char * body, size_t n, char *** out_names,
    size_t * out_count, GDEFCORE_Catalog * catalog, GDEFCORE_Result * rc) {
  static const char kCall[] = "region(\"";
  size_t i = 0;
  char ** names = NULL;
  size_t count = 0;
  *out_names = NULL;
  *out_count = 0;
  *rc = GDEFCORE_OK;
  while (i + sizeof kCall - 1 < n) {
    size_t start;
    size_t end;
    size_t k;
    int dup = 0;
    if (memcmp(body + i, kCall, sizeof kCall - 1) != 0) {
      i += 1;
      continue;
    }
    start = i + sizeof kCall - 1;
    end = start;
    while (end < n && body[end] != '"') {
      end += 1;
    }
    if (end >= n || end == start || end - start >= 64) {
      i = end >= n ? n : end + 1;
      continue;
    }
    for (k = 0; k < count; k++) {
      if (strlen(names[k]) == end - start &&
          memcmp(names[k], body + start, end - start) == 0) {
        dup = 1;
      }
    }
    if (!dup) {
      char ** next = (char **)gcu_allocator_realloc(gdefcore_allocator_default(),
          names, (count + 1) * sizeof *names);
      char * copy = NULL;
      if (next == NULL) {
        *rc = GDEFCORE_ERR_OOM;
        break;
      }
      names = next;
      if (gdefcore_text_dup(catalog, body + start, end - start, &copy) !=
          GDEFCORE_OK) {
        *rc = GDEFCORE_ERR_OOM;
        break;
      }
      names[count++] = copy;
    }
    i = end + 1;
  }
  if (*rc != GDEFCORE_OK) {
    gdefcore_render_names_free(catalog, names, count);
    return;
  }
  *out_names = names;
  *out_count = count;
}

GDEFCORE_Result gdefcore_render_regions(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, char *** out_names, size_t * out_count) {
  char * body = NULL;
  size_t body_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || name == NULL || out_names == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_names = NULL;
  *out_count = 0;
  rc = template_body(catalog, name, name_len, &body, &body_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  scan_regions(body, body_len, out_names, out_count, catalog, &rc);
  gdefcore_text_free(catalog, body);
  return rc;
}

void gdefcore_render_names_free(GDEFCORE_Catalog * catalog, char ** names,
    size_t count) {
  size_t i;
  if (names == NULL) {
    return;
  }
  for (i = 0; i < count; i++) {
    gdefcore_text_free(catalog, names[i]);
  }
  gcu_allocator_free(gdefcore_allocator_default(), names);
}

GDEFCORE_Result gdefcore_render_pane_at(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, char ** out_region,
    size_t * out_region_len, char ** out_kind, size_t * out_kind_len,
    char ** out_target, size_t * out_target_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** panes = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  const char * region;
  const char * kind;
  const char * target;
  size_t region_len = 0;
  size_t kind_len = 0;
  size_t target_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || name == NULL || out_region == NULL || out_kind == NULL ||
      out_target == NULL || out_region_len == NULL || out_kind_len == NULL ||
      out_target_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_region = NULL;
  *out_kind = NULL;
  *out_target = NULL;
  rc = find_named(catalog, "core.display", 12, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, "en", 2, "panes", 5, &panes, &lens, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (index >= count ||
      !split3(panes[index], lens[index], &region, &region_len, &kind, &kind_len,
          &target, &target_len)) {
    gdefcore_values_free(catalog, panes, lens, count);
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_text_dup(catalog, region, region_len, out_region);
  if (rc == GDEFCORE_OK) {
    *out_region_len = region_len;
    rc = gdefcore_text_dup(catalog, kind, kind_len, out_kind);
  }
  if (rc == GDEFCORE_OK) {
    *out_kind_len = kind_len;
    rc = gdefcore_text_dup(catalog, target, target_len, out_target);
  }
  if (rc == GDEFCORE_OK) {
    *out_target_len = target_len;
  } else {
    gdefcore_text_free(catalog, *out_region);
    gdefcore_text_free(catalog, *out_kind);
    gdefcore_text_free(catalog, *out_target);
    *out_region = NULL;
    *out_kind = NULL;
    *out_target = NULL;
  }
  gdefcore_values_free(catalog, panes, lens, count);
  return rc;
}

static GDEFCORE_Result pack_patches(const GDEFCORE_Patch * files, size_t count,
    uint8_t ** out, size_t * out_len) {
  size_t bytes = 8;
  size_t i;
  size_t at = 0;
  uint8_t * buf;
  for (i = 0; i < count; i++) {
    if (files[i].path_len > UINT32_MAX || files[i].len > UINT32_MAX) {
      return GDEFCORE_ERR_LIMIT;
    }
    if (bytes > SIZE_MAX - 8 - files[i].path_len - files[i].len) {
      return GDEFCORE_ERR_LIMIT;
    }
    bytes += 8 + files[i].path_len + files[i].len;
  }
  buf = (uint8_t *)malloc(bytes);
  if (buf == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  put_be32(buf, RENDER_MAGIC);
  put_be32(buf + 4, (uint32_t)count);
  at = 8;
  for (i = 0; i < count; i++) {
    put_be32(buf + at, (uint32_t)files[i].path_len);
    at += 4;
    if (files[i].path_len > 0) {
      memcpy(buf + at, files[i].path, files[i].path_len);
      at += files[i].path_len;
    }
    put_be32(buf + at, (uint32_t)files[i].len);
    at += 4;
    if (files[i].len > 0) {
      memcpy(buf + at, files[i].bytes, files[i].len);
      at += files[i].len;
    }
  }
  *out = buf;
  *out_len = at;
  return GDEFCORE_OK;
}

static void free_patches(GDEFCORE_Catalog * catalog, GDEFCORE_Patch * files,
    size_t count) {
  size_t i;
  if (files == NULL) {
    return;
  }
  for (i = 0; i < count; i++) {
    gdefcore_text_free(catalog, files[i].path);
    gdefcore_text_free(catalog, (char *)files[i].bytes);
  }
  free(files);
}

static GDEFCORE_Result unpack_patches(GDEFCORE_Catalog * catalog,
    const uint8_t * blob, size_t n, GDEFCORE_Patch ** out, size_t * out_count) {
  uint32_t count;
  size_t at = 8;
  size_t i;
  GDEFCORE_Patch * files;
  if (n < 8 || get_be32(blob) != RENDER_MAGIC) {
    return GDEFCORE_ERR_FORMAT;
  }
  count = get_be32(blob + 4);
  if (count > 128) {
    return GDEFCORE_ERR_LIMIT;
  }
  files = (GDEFCORE_Patch *)calloc(count == 0 ? 1 : count, sizeof *files);
  if (files == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < count; i++) {
    uint32_t path_len;
    uint32_t data_len;
    char * path = NULL;
    char * data = NULL;
    if (at + 4 > n) {
      free_patches(catalog, files, i);
      return GDEFCORE_ERR_CORRUPT;
    }
    path_len = get_be32(blob + at);
    at += 4;
    if (at + path_len + 4 > n) {
      free_patches(catalog, files, i);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (gdefcore_text_dup(catalog, (const char *)blob + at, path_len, &path) !=
        GDEFCORE_OK) {
      free_patches(catalog, files, i);
      return GDEFCORE_ERR_OOM;
    }
    at += path_len;
    data_len = get_be32(blob + at);
    at += 4;
    if (at + data_len > n) {
      gdefcore_text_free(catalog, path);
      free_patches(catalog, files, i);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (gdefcore_text_dup(catalog, (const char *)blob + at, data_len, &data) !=
        GDEFCORE_OK) {
      gdefcore_text_free(catalog, path);
      free_patches(catalog, files, i);
      return GDEFCORE_ERR_OOM;
    }
    at += data_len;
    files[i].size = sizeof files[i];
    files[i].path = path;
    files[i].path_len = path_len;
    files[i].bytes = (uint8_t *)data;
    files[i].len = data_len;
  }
  if (at != n) {
    free_patches(catalog, files, count);
    return GDEFCORE_ERR_CORRUPT;
  }
  *out = files;
  *out_count = count;
  return GDEFCORE_OK;
}

static GDEFCORE_Result tar_member(const uint8_t * blob, size_t n, uint8_t ** out,
    size_t * out_len) {
  GARC_Sink * sink = NULL;
  GARC_Writer * writer = NULL;
  GARC_Member member;
  const void * data = NULL;
  size_t size = 0;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return GDEFCORE_ERR_OOM;
  }
  if (garc_writer_create(sink, GARC_FORMAT_TAR, NULL, &writer) != GARC_OK) {
    garc_sink_destroy(sink);
    return GDEFCORE_ERR_INVALID;
  }
  memset(&member, 0, sizeof member);
  member.name = "changeset";
  member.name_length = 9;
  member.type = GARC_MEMBER_FILE;
  member.size = n;
  member.mode = 0644;
  member.mode_valid = 1;
  if (garc_writer_add(writer, &member) != GARC_OK ||
      garc_writer_write(writer, blob, n) != GARC_OK ||
      garc_writer_finish(writer) != GARC_OK ||
      garc_sink_finish(sink) != GARC_OK ||
      garc_sink_data(sink, &data, &size) != GARC_OK) {
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  rc = GDEFCORE_OK;
  *out = (uint8_t *)malloc(size == 0 ? 1 : size);
  if (*out == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  if (size > 0) {
    memcpy(*out, data, size);
  }
  *out_len = size;
done:
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return rc;
}

static GDEFCORE_Result read_changeset(const uint8_t * archive, size_t n,
    uint8_t ** blob, size_t * blob_len) {
  GARC_Stream * stream = NULL;
  GARC_Archive * arc = NULL;
  const GARC_Member * member = NULL;
  uint8_t * buf = NULL;
  size_t filled = 0;
  GARC_Result result;
  if (garc_stream_create_memory(archive, n, &stream) != GARC_OK) {
    return GDEFCORE_ERR_OOM;
  }
  if (garc_open(stream, NULL, &arc) != GARC_OK) {
    garc_stream_destroy(stream);
    return GDEFCORE_ERR_FORMAT;
  }
  result = garc_next(arc, &member);
  if (result != GARC_OK || member->name_length != 9 ||
      memcmp(member->name, "changeset", 9) != 0 ||
      member->size > RENDER_MEMBER_CAP || member->size > SIZE_MAX) {
    garc_close(arc);
    garc_stream_destroy(stream);
    return GDEFCORE_ERR_FORMAT;
  }
  buf = (uint8_t *)malloc((size_t)member->size == 0 ? 1 : (size_t)member->size);
  if (buf == NULL) {
    garc_close(arc);
    garc_stream_destroy(stream);
    return GDEFCORE_ERR_OOM;
  }
  while (filled < (size_t)member->size) {
    size_t got = 0;
    if (garc_read_member(arc, buf + filled, (size_t)member->size - filled, &got) !=
            GARC_OK ||
        got == 0) {
      free(buf);
      garc_close(arc);
      garc_stream_destroy(stream);
      return GDEFCORE_ERR_CORRUPT;
    }
    filled += got;
  }
  if (garc_next(arc, &member) != GARC_END) {
    free(buf);
    garc_close(arc);
    garc_stream_destroy(stream);
    return GDEFCORE_ERR_FORMAT;
  }
  garc_close(arc);
  garc_stream_destroy(stream);
  *blob = buf;
  *blob_len = filled;
  return GDEFCORE_OK;
}

static GDEFCORE_Result put_named(GDEFCORE_Catalog * catalog, const char * type,
    const char * name, const char * extra_field, const char * extra) {
  GDEFCORE_Value values[2];
  const char * texts[2];
  size_t lens[2];
  size_t nvalues = 1;
  texts[0] = name;
  lens[0] = strlen(name);
  set_value(&values[0], "name", &texts[0], &lens[0], 1);
  if (extra_field != NULL) {
    texts[1] = extra;
    lens[1] = strlen(extra);
    set_value(&values[1], extra_field, &texts[1], &lens[1], 1);
    nvalues = 2;
  }
  return save_entity(catalog, type, values, nvalues, 1);
}

static GDEFCORE_Result put_display(GDEFCORE_Catalog * catalog, const char * name,
    const char * pane) {
  GDEFCORE_Value values[3];
  const char * texts[3];
  size_t lens[3];
  texts[0] = name;
  lens[0] = strlen(name);
  texts[1] = "layout";
  lens[1] = 6;
  texts[2] = pane;
  lens[2] = strlen(pane);
  set_value(&values[0], "name", &texts[0], &lens[0], 1);
  set_value(&values[1], "layout", &texts[1], &lens[1], 1);
  set_value(&values[2], "panes", &texts[2], &lens[2], 1);
  return save_entity(catalog, "core.display", values, 3, 1);
}

static GDEFCORE_Result grant_posts(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Permission permission;
  const char * confirm = GDEFCORE_ACCESS_CONFIRM_ANONYMOUS;
  memset(&permission, 0, sizeof permission);
  permission.size = sizeof permission;
  permission.label = "Read posts";
  permission.label_len = 10;
  permission.module_name = "site";
  permission.module_name_len = 4;
  permission.action = "read";
  permission.action_len = 4;
  permission.condition = GDEFCORE_ACCESS_ANY;
  permission.type_name = "site.post";
  permission.type_name_len = 9;
  if (gdefcore_access_declare(catalog, &permission) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return gdefcore_access_grant(catalog, "anonymous", 9, "Read posts", 10, confirm,
      strlen(confirm));
}

GDEFCORE_Result gdefcore_render_kit(GDEFCORE_Catalog * catalog, uint8_t ** out_bytes,
    size_t * out_len) {
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Field post[3];
  GDEFCORE_Field tmpl[2];
  GDEFCORE_Field theme[1];
  GDEFCORE_Field view[5];
  GDEFCORE_Field display[3];
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  uint8_t * blob = NULL;
  size_t blob_len = 0;
  uint8_t * archive = NULL;
  size_t archive_len = 0;
  char * copy = NULL;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_bytes == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  set_field(&post[0], "title", 1, 0);
  set_field(&post[1], "body", 1, 0);
  set_field(&post[2], "summary", 0, 0);
  set_field(&tmpl[0], "name", 1, 0);
  set_field(&tmpl[1], "body", 1, 0);
  set_field(&theme[0], "name", 1, 0);
  set_field(&view[0], "name", 1, 0);
  set_field(&view[1], "type", 1, 0);
  set_field(&view[2], "limit", 1, 0);
  set_field(&view[3], "template", 1, 0);
  set_field(&view[4], "sort", 0, 0);
  view[4].name = "sort";
  set_field(&display[0], "name", 1, 0);
  set_field(&display[1], "layout", 1, 0);
  set_field(&display[2], "panes", 1, 1);
  /* range is optional and declared with sort's slot reused below. */
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_define(cs, "site.post", 9, GDEFCORE_TYPE_CONTENT, post,
      3);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_define(cs, "core.template", 13, GDEFCORE_TYPE_CONFIG,
        tmpl, 2);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_define(cs, "core.theme", 10, GDEFCORE_TYPE_CONFIG,
        theme, 1);
  }
  if (rc == GDEFCORE_OK) {
    GDEFCORE_Field view_fields[6];
    view_fields[0] = view[0];
    view_fields[1] = view[1];
    view_fields[2] = view[2];
    view_fields[3] = view[3];
    set_field(&view_fields[4], "sort", 0, 0);
    set_field(&view_fields[5], "range", 0, 0);
    rc = gdefcore_changeset_define(cs, "core.view", 9, GDEFCORE_TYPE_CONFIG,
        view_fields, 6);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_define(cs, "core.display", 12, GDEFCORE_TYPE_CONFIG,
        display, 3);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_serialize(cs, &files, &count);
  }
  gdefcore_changeset_destroy(cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = pack_patches(files, count, &blob, &blob_len);
  gdefcore_patch_free(catalog, files, count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = tar_member(blob, blob_len, &archive, &archive_len);
  free(blob);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_text_dup(catalog, (const char *)archive, archive_len, &copy);
  free(archive);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_bytes = (uint8_t *)copy;
  *out_len = archive_len;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_render_install(GDEFCORE_Catalog * catalog,
    const uint8_t * archive, size_t archive_len) {
  int kind = 0;
  uint8_t * blob = NULL;
  size_t blob_len = 0;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_type_kind(catalog, "site.post", 9, &kind);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  if (archive == NULL || archive_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = read_changeset(archive, archive_len, &blob, &blob_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = unpack_patches(catalog, blob, blob_len, &files, &count);
  free(blob);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_parse(catalog, files, count, NULL, &cs);
  free_patches(catalog, files, count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_apply(cs, kConfirm, sizeof kConfirm - 1);
  gdefcore_changeset_destroy(cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = put_named(catalog, "core.template", "layout", "body", kLayoutBody);
  if (rc == GDEFCORE_OK) {
    rc = put_named(catalog, "core.template", "entity", "body", kEntityBody);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_named(catalog, "core.template", "recent", "body", kRecentBody);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_named(catalog, "core.template", "field", "body", kFieldBody);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_named(catalog, "core.theme", "base", NULL, NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_render_view_define(catalog, "recent", 6, "site.post", 9, 5,
        "recent", 6, NULL, 0, NULL, 0);
  }
  if (rc == GDEFCORE_OK) {
    rc = put_display(catalog, "front", "side view recent");
  }
  if (rc == GDEFCORE_OK) {
    rc = put_display(catalog, "post", "main entity entity");
  }
  if (rc == GDEFCORE_OK) {
    rc = grant_posts(catalog);
  }
  return rc;
}
