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
#include <ghoti.io/defiant-core/layout.h>
#include <ghoti.io/defiant-core/menu.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>
#include <ghoti.io/defiant-core/template.h>
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/fiber.h>
#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/sink.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/archive/writer.h>
#include <ghoti.io/lang-tang/compile.h>
#include <ghoti.io/lang-tang/description.h>
#include <ghoti.io/lang-tang/execution.h>
#include <ghoti.io/lang-tang/parse.h>
#include <ghoti.io/lang-tang/value.h>
#include <ghoti.io/runtime-core/runtime-core.h>
#include <ghoti.io/runtime-heap/runtime-heap.h>

#include <stdatomic.h>
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
    "core.display\ncore.template\ncore.template-kind\ncore.theme\ncore.view\n"
    "site.post";

static const char kLayoutBody[] =
    "<% use region; %>"
    "<div class=\"main\"><%= region(\"main\") %></div>"
    "<div class=\"side\"><%= region(\"side\") %></div>";
static const char kEntityBody[] =
    "<% use title; use body; %>"
    "<article class=\"post\"><h1><%= title %></h1>"
    "<div class=\"body\"><%= body %></div></article>";
static const char kRecentBody[] =
    "<% use title; use summary; %>"
    "<article class=\"recent\"><h2><%= title %></h2>"
    "<p><%= summary %></p></article>";

/*
 * The navigation widgets' templates. `items` is the computed list (menu.h): a
 * map each, with name, label, route, href, menu, weight, depth, current and
 * trail. Every text in it is escaped by the engine, and url() makes an href
 * safe in the one place it is used. The depth is part of a class name
 * (`depth1`) and never a bare number, which a page scanner for internal ids
 * would take for one.
 */
static const char kMenuBody[] =
    "<% use items; use url; %><ul class=\"menu\">"
    "<% for (item : items) { %><li class=\"depth<%= item.depth %>"
    "<% if (item.current) { %> current<% } %>"
    "<% if (item.trail) { %> trail<% } %>\">"
    "<a href=\"<%= url(item.href) %>\"><%= item.label %></a></li><% } %></ul>";
static const char kTabsBody[] =
    "<% use items; use url; %><ul class=\"tabs\">"
    "<% for (item : items) { %><li<% if (item.current) { %> class=\"current\""
    "<% } %>><a href=\"<%= url(item.href) %>\"><%= item.label %></a></li>"
    "<% } %></ul>";
static const char kCrumbsBody[] =
    "<% use items; use url; %><ol class=\"breadcrumbs\">"
    "<% for (item : items) { %><li<% if (item.current) { %> class=\"current\""
    "<% } %>><a href=\"<%= url(item.href) %>\"><%= item.label %></a></li>"
    "<% } %></ol>";

/* The site name, the page title and the messages. The messages template
 * prints nothing while the list is empty, so a page without a queue shows no
 * trace of the widget. */
static const char kSiteNameBody[] =
    "<% use name; %><span class=\"site-name\"><%= name %></span>";
static const char kTitleBody[] = "<% use title; %><h1><%= title %></h1>";
static const char kMessagesBody[] =
    "<% use items; %><% for (item : items) { %><div class=\"message\">"
    "<%= item.text %></div><% } %>";

/*
 * The built-in kinds and the contract each template really uses. A page
 * layout calls region() and may call url(); a pane reads title, body or
 * summary, and may call url(). A pane is one kind for two widgets (page content
 * and recent posts), so its contract is the union: each binds the subset its
 * renderer has.
 */
static const char * const kPageVars[] = {NULL};
static const char * const kPageFns[] = {"region 1", "url 1"};
static const char * const kPaneVars[] = {
    "title text The title of the post being shown.",
    "body text The body of the post being shown. It is text: printing it "
    "escapes it.",
    "summary text The summary of a post in a list: its summary field, else the "
    "text before the break marker, else its first 600 characters. The "
    "recent-posts view binds it."};
static const char * const kPaneFns[] = {"url 1"};

/* A widget's kind reads the list of what it shows, and url(). */
static const char * const kMenuVars[] = {
    "menu text The name of the menu being drawn.",
    "items list The entries the viewer may follow, in order. Each is a map "
    "with name, label, route, href, menu, weight, depth, current and trail."};
static const char * const kTabsVars[] = {
    "items list The tabs of the page the viewer may follow, in order. Each is "
    "a map with name, label, route, href, weight, current and trail."};
static const char * const kCrumbsVars[] = {
    "items list The trail to the page, from the top. Each is a map with name, "
    "label, route, href and current (the page itself)."};
static const char * const kNavFns[] = {"url 1"};

static const char * const kSiteNameVars[] = {
    "name text The name of the site, which is the site_name of the base theme "
    "until settings supply it."};
static const char * const kPageTitleVars[] = {
    "title text The title of the page being shown, as the viewer may read it."};
static const char * const kMessagesVars[] = {
    "items list The messages for this viewer, each a map with text. It is "
    "empty until a message queue supplies it."};

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
 * The fragments this process has offered to a shared cache. A host that keeps
 * a shared fragment cache stores exactly the fragments counted here; a
 * fragment rendered under any overlay but `live` (a preview) is never one.
 */
static atomic_uint_fast64_t g_shareable;

static int fragment_offer(const char * overlay, size_t overlay_len) {
  if (!gdefcore_access_shared_cache(overlay, overlay_len)) {
    return 0;
  }
  atomic_fetch_add_explicit(&g_shareable, 1, memory_order_relaxed);
  return 1;
}

uint64_t gdefcore_render_shareable_count(void) {
  return (uint64_t)atomic_load_explicit(&g_shareable, memory_order_relaxed);
}

/*
 * unsafe: the pane template already escaped field values. The layout
 * pastes those bytes as trusted so the tags survive. This is the one
 * trusted insertion in the render layer: every other value a template
 * can print is bound HTML_ATTRIBUTE-tagged (see tang_job_run) and every
 * byte pasted here came out of a template whose own values were.
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

/* ASCII whitespace and controls: skipped before the scheme is read. */
static int url_skippable(unsigned char c) {
  return c <= 0x20 || c == 0x7f;
}

/* The bytes a URL parser drops wherever they occur. */
static int url_dropped(unsigned char c) {
  return c == '\t' || c == '\n' || c == '\r';
}

static int url_lower(unsigned char c) {
  return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

/*
 * Whether `s` may be an href. The scheme is http, https or mailto, or the
 * reference is relative. A network-path reference (`//host`, and the
 * `/\host` forms a browser reads the same way) is not relative here.
 */
static int url_allowed(const char * s, size_t n) {
  static const char * const ok[] = {"http", "https", "mailto"};
  char head[8];
  size_t i = 0;
  size_t k = 0;
  int long_head = 0;
  while (i < n && url_skippable((unsigned char)s[i])) {
    i += 1;
  }
  for (; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (url_dropped(c)) {
      continue;
    }
    if (c == ':') {
      size_t j;
      for (j = 0; !long_head && j < sizeof ok / sizeof ok[0]; j++) {
        if (k == strlen(ok[j]) && memcmp(head, ok[j], k) == 0) {
          return 1;
        }
      }
      return 0;
    }
    if (c == '/' || c == '?' || c == '#' || c == '\\') {
      break;
    }
    if (k < sizeof head) {
      head[k++] = (char)url_lower(c);
    } else {
      long_head = 1;
    }
  }
  /* Relative. A reference that opens with two slashes is a network path. */
  if (k == 0 && i < n && (s[i] == '/' || s[i] == '\\')) {
    for (i += 1; i < n; i++) {
      if (!url_dropped((unsigned char)s[i])) {
        return !(s[i] == '/' || s[i] == '\\');
      }
    }
  }
  return 1;
}

/*
 * url(x): x when it is safe in an href, else "#". The answer carries the
 * HTML_ATTRIBUTE tag, so it is escaped in an attribute whatever it holds.
 */
static bool native_url(GLTANG_NativeCall * call, void * user) {
  size_t n = 0;
  const char * text;
  (void)user;
  text = gltang_call_count(call) == 1 &&
          gltang_call_kind(call, 0) == GLTANG_KIND_STRING
      ? gltang_call_text(call, 0, &n)
      : NULL;
  if (text == NULL || !url_allowed(text, n)) {
    gltang_call_return_string(call, "#", 1,
        GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE);
    return true;
  }
  gltang_call_return_string(call, text, n,
      GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE);
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

typedef struct {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Request * request;
  const GDEFCORE_Contract * contract;
  const char * source;
  size_t source_len;
  uint64_t scope_fuel;
  const TangBind * binds;
  size_t nbinds;
  /* A described value bound to one name (story S6d: an entity, its groups
   * and multiples as lists), or NULL. */
  const char * value_name;
  GLTANG_ValueDescription * value;
  GLTANG_NativeFn native;
  void * native_user;
  const char * native_name;
  char ** out;
  size_t * out_len;
  GDEFCORE_Result rc;
} TangJob;

/* A parse or compile refused for depth is a limit, not a format error. */
static GDEFCORE_Result tang_refusal(GLTANG_Result result) {
  return result == GLTANG_ERR_LIMIT ? GDEFCORE_ERR_LIMIT : GDEFCORE_ERR_FORMAT;
}

/* A contributed variable, called lazily by the engine. */
typedef struct Adapter {
  GDEFCORE_Request * request;
  const GDEFCORE_Module_Contributed * item;
} Adapter;

/*
 * Called when a `use` reaches a contributed variable, and never otherwise.
 * Whether a page depends on its principal is observed here, while it renders
 * (AD-30): a variable that is not principal_free marks the request, so the
 * render key carries the principal.
 */
static bool contrib_factory(void * user, GLTANG_HostValue * out) {
  Adapter * a = (Adapter *)user;
  GDEFCORE_Contribution_Value v;
  int markup = a->item->type_len == 6 && memcmp(a->item->type, "markup", 6) == 0;
  int number = a->item->type_len == 6 && memcmp(a->item->type, "number", 6) == 0;
  if (!a->item->principal_free) {
    gdefcore_request_mark_principal_dependent(a->request);
  }
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  if (a->item->provider(a->request, a->item->user, &v) != GDEFCORE_OK ||
      v.size != sizeof v) {
    return false;
  }
  memset(out, 0, sizeof *out);
  if (!number && v.kind == GDEFCORE_CONTRIBUTION_TEXT && v.text != NULL) {
    out->kind = GLTANG_HOST_STRING;
    out->text = v.text;
    out->length = v.text_len;
    /* markup is the one trusted type; text is as inert as a field. */
    out->encoding = markup ? GLTANG_UNICODE_STRING_TYPE_TRUSTED
                           : GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE;
    return true;
  }
  if (number && v.kind == GDEFCORE_CONTRIBUTION_INTEGER) {
    out->kind = GLTANG_HOST_INTEGER;
    out->integer = v.integer;
    return true;
  }
  if (number && v.kind == GDEFCORE_CONTRIBUTION_FLOAT) {
    out->kind = GLTANG_HOST_FLOAT;
    out->number = v.real;
    return true;
  }
  return false;
}

typedef struct Group {
  char name[65];
  GLTANG_Library * lib;
} Group;

static void groups_release(Group * groups, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    gltang_library_release(groups[i].lib);
  }
}

/*
 * The library handed to a template holds the contract's names and nothing
 * else: the values the host bound that the contract declares, the functions
 * it declares, the lazy contributed variables, and null for the engine's own
 * `math` and `random`, which a library shadows.
 */
static GDEFCORE_Result build_library(TangJob * job, GLTANG_Library ** out_lib,
    Adapter ** out_adapters) {
  const GDEFCORE_Contract * c = job->contract;
  GLTANG_Library * lib = NULL;
  Adapter * adapters = NULL;
  Group * groups = NULL;
  size_t ngroups = 0;
  size_t nvars;
  size_t nfns;
  size_t used = 0;
  size_t i;
  int has_math = 0;
  int has_random = 0;
  GDEFCORE_Contract_Var probe;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  *out_lib = NULL;
  *out_adapters = NULL;
  if (gltang_library_create(NULL, &lib) != GLTANG_OK) {
    return GDEFCORE_ERR_OOM;
  }
  if (c == NULL) {
    /* A bare scope has no kind: it may build an href, and read nothing. */
    if (gltang_library_add_native(lib, "url", native_url, NULL) != GLTANG_OK ||
        gltang_library_add_null(lib, "math") != GLTANG_OK ||
        gltang_library_add_null(lib, "random") != GLTANG_OK) {
      goto fail;
    }
    *out_lib = lib;
    return GDEFCORE_OK;
  }
  nvars = gdefcore_template_contract_var_count(c);
  nfns = gdefcore_template_contract_fn_count(c);
  for (i = 0; i < job->nbinds; i++) {
    GDEFCORE_Contract_Var v;
    const char * text = job->binds[i].text == NULL ? "" : job->binds[i].text;
    if (gdefcore_template_contract_var(c, job->binds[i].name,
            strlen(job->binds[i].name), &v) != GDEFCORE_OK ||
        v.contributed != NULL) {
      continue;
    }
    /*
     * A bound value came from a user, a field or a request: tag it for the
     * strictest encoding, so a template that prints it bare is safe in
     * element text and in either quote style of an attribute.
     */
    if (gltang_library_add_string(lib, job->binds[i].name, text,
            job->binds[i].len, GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE) !=
        GLTANG_OK) {
      goto fail;
    }
  }
  if (job->value != NULL && job->value_name != NULL) {
    GDEFCORE_Contract_Var v;
    /* Bound only where the contract declares it, as a text bind is. */
    if (gdefcore_template_contract_var(c, job->value_name,
            strlen(job->value_name), &v) == GDEFCORE_OK &&
        v.contributed == NULL &&
        gltang_library_add_value(lib, job->value_name, job->value) !=
            GLTANG_OK) {
      goto fail;
    }
  }
  for (i = 0; i < nfns; i++) {
    GDEFCORE_Contract_Fn f;
    if (gdefcore_template_contract_fn_at(c, i, &f) != GDEFCORE_OK) {
      goto fail;
    }
    if (f.name_len == 3 && memcmp(f.name, "url", 3) == 0) {
      if (gltang_library_add_native(lib, "url", native_url, NULL) != GLTANG_OK) {
        goto fail;
      }
    } else if (job->native != NULL && job->native_name != NULL &&
               f.name_len == strlen(job->native_name) &&
               memcmp(f.name, job->native_name, f.name_len) == 0) {
      if (gltang_library_add_native(lib, job->native_name, job->native,
              job->native_user) != GLTANG_OK) {
        goto fail;
      }
    }
  }
  adapters = (Adapter *)calloc(nvars == 0 ? 1 : nvars, sizeof *adapters);
  groups = (Group *)calloc(nvars == 0 ? 1 : nvars, sizeof *groups);
  if (adapters == NULL || groups == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto fail;
  }
  for (i = 0; i < nvars; i++) {
    GDEFCORE_Contract_Var v;
    const char * dot;
    size_t head;
    size_t g;
    if (gdefcore_template_contract_var_at(c, i, &v) != GDEFCORE_OK) {
      goto fail;
    }
    if (v.contributed == NULL) {
      continue;
    }
    /* `m.count` is the library `m` holding the factory `count`. */
    dot = (const char *)memchr(v.name, '.', v.name_len);
    if (dot == NULL || (size_t)(dot - v.name) >= sizeof groups[0].name) {
      goto fail;
    }
    head = (size_t)(dot - v.name);
    for (g = 0; g < ngroups; g++) {
      if (strlen(groups[g].name) == head && memcmp(groups[g].name, v.name, head) == 0) {
        break;
      }
    }
    if (g == ngroups) {
      memcpy(groups[g].name, v.name, head);
      groups[g].name[head] = '\0';
      if (gltang_library_create(groups[g].name, &groups[g].lib) != GLTANG_OK) {
        goto fail;
      }
      ngroups += 1;
    }
    adapters[used].request = job->request;
    adapters[used].item = v.contributed;
    {
      char local[65];
      size_t local_len = v.name_len - head - 1;
      if (local_len >= sizeof local) {
        goto fail;
      }
      memcpy(local, dot + 1, local_len);
      local[local_len] = '\0';
      if (gltang_library_add_factory(groups[g].lib, local, contrib_factory,
              &adapters[used]) != GLTANG_OK) {
        goto fail;
      }
    }
    used += 1;
  }
  for (i = 0; i < ngroups; i++) {
    if (gltang_library_add_library(lib, groups[i].lib) != GLTANG_OK) {
      goto fail;
    }
    has_math = has_math || strcmp(groups[i].name, "math") == 0;
    has_random = has_random || strcmp(groups[i].name, "random") == 0;
  }
  groups_release(groups, ngroups);
  free(groups);
  groups = NULL;
  has_math = has_math ||
             gdefcore_template_contract_var(c, "math", 4, &probe) == GDEFCORE_OK;
  has_random = has_random ||
               gdefcore_template_contract_var(c, "random", 6, &probe) ==
                   GDEFCORE_OK;
  if ((!has_math && gltang_library_add_null(lib, "math") != GLTANG_OK) ||
      (!has_random && gltang_library_add_null(lib, "random") != GLTANG_OK)) {
    goto fail;
  }
  *out_lib = lib;
  *out_adapters = adapters;
  return GDEFCORE_OK;
fail:
  if (groups != NULL) {
    groups_release(groups, ngroups);
    free(groups);
  }
  free(adapters);
  gltang_library_release(lib);
  return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result tang_job_run(TangJob * job) {
  GDEFCORE_Catalog * catalog = job->catalog;
  char * source_z = NULL;
  GLTANG_Tree * body_tree = NULL;
  GLTANG_Tree * wrap_tree = NULL;
  GLTANG_Program * body = NULL;
  GLTANG_Program * wrap = NULL;
  GLTANG_Library * lib = NULL;
  GLTANG_Library * plumbing = NULL;
  Adapter * adapters = NULL;
  GDEFCORE_RenderCtx * ctx = NULL;
  char * rendered = NULL;
  size_t rendered_len = 0;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  GLTANG_Result step;
  GLTANG_ParseError error;
  uint64_t ceiling;
  source_z = (char *)malloc(job->source_len + 1);
  if (source_z == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (job->source_len > 0) {
    memcpy(source_z, job->source, job->source_len);
  }
  source_z[job->source_len] = '\0';
  step = gltang_parse(source_z, GLTANG_PARSE_TEMPLATE, &error, &body_tree);
  if (step == GLTANG_OK) {
    step = gltang_compile(body_tree, "pane.tang", &error, &body);
  }
  if (step == GLTANG_OK) {
    step = gltang_parse(kWrap, GLTANG_PARSE_SCRIPT, &error, &wrap_tree);
  }
  if (step == GLTANG_OK) {
    step = gltang_compile(wrap_tree, "wrap.tang", &error, &wrap);
  }
  if (step != GLTANG_OK) {
    rc = tang_refusal(step);
    goto done;
  }
  rc = build_library(job, &lib, &adapters);
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  /*
   * The template that runs the body is plumbing, not part of the contract: it
   * lives in a layer of the wrapper program, which the body cannot reach.
   */
  if (gltang_library_create(NULL, &plumbing) != GLTANG_OK) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  if (gltang_library_add_template(plumbing, "pane", body, job->scope_fuel,
          GLTANG_SCOPE_SEGMENTS) != GLTANG_OK ||
      gltang_program_set_libraries(wrap, plumbing) != GLTANG_OK) {
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  ceiling = job->scope_fuel;
  if (ceiling <= UINT64_MAX - 1000000ull) {
    ceiling += 1000000ull;
  }
  rc = gdefcore_render_ctx_open(ceiling, &ctx);
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  rc = gdefcore_render_ctx_run(ctx, wrap, lib, &rendered, &rendered_len);
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  rc = gdefcore_text_dup(catalog, rendered, rendered_len, job->out);
  if (rc == GDEFCORE_OK) {
    *job->out_len = rendered_len;
  }
done:
  gltang_buffer_free(rendered);
  gdefcore_render_ctx_close(ctx);
  gltang_library_release(lib);
  gltang_library_release(plumbing);
  free(adapters);
  gltang_program_release(wrap);
  gltang_program_release(body);
  gltang_tree_destroy(wrap_tree);
  gltang_tree_destroy(body_tree);
  free(source_z);
  return rc;
}

static void tang_job_entry(void * arg) {
  TangJob * job = (TangJob *)arg;
  job->rc = tang_job_run(job);
}

/*
 * Parse, compile and run on a stack of our own (AD-32). The caller's fiber
 * may have 16 KiB, and lang-tang recurses once per level of a tree.
 */
static GDEFCORE_Result side_stack_run(TangJob * job) {
#if GCU_FIBER_SUPPORTED
  GCU_Fiber * fiber = NULL;
  GCU_Fiber_Result made = gcu_fiber_create(
      &fiber, tang_job_entry, job, GDEFCORE_RENDER_SIDE_STACK, NULL);
  if (made != GCU_FIBER_OK) {
    return made == GCU_FIBER_ERR_OOM ? GDEFCORE_ERR_OOM
                                     : GDEFCORE_ERR_UNSUPPORTED;
  }
  job->rc = GDEFCORE_ERR_INTERNAL;
  if (gcu_fiber_switch_to(fiber) != GCU_FIBER_OK) {
    job->rc = GDEFCORE_ERR_INTERNAL;
  }
  gcu_fiber_destroy(fiber);
  return job->rc;
#else
  return tang_job_run(job);
#endif
}

static GDEFCORE_Result tang_run_value(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Contract * contract,
    const char * source, size_t source_len, uint64_t scope_fuel,
    const TangBind * binds, size_t nbinds, const char * value_name,
    GLTANG_ValueDescription * value, GLTANG_NativeFn native,
    void * native_user, const char * native_name, char ** out,
    size_t * out_len) {
  TangJob job;
  if (catalog == NULL || source == NULL || out == NULL || out_len == NULL ||
      scope_fuel == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  job.value_name = value_name;
  job.value = value;
  job.catalog = catalog;
  job.request = request;
  job.contract = contract;
  job.source = source;
  job.source_len = source_len;
  job.scope_fuel = scope_fuel;
  job.binds = binds;
  job.nbinds = nbinds;
  job.native = native;
  job.native_user = native_user;
  job.native_name = native_name;
  job.out = out;
  job.out_len = out_len;
  job.rc = GDEFCORE_ERR_INVALID;
  return side_stack_run(&job);
}

static GDEFCORE_Result tang_run(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Contract * contract,
    const char * source, size_t source_len, uint64_t scope_fuel,
    const TangBind * binds, size_t nbinds, GLTANG_NativeFn native,
    void * native_user, const char * native_name, char ** out,
    size_t * out_len) {
  return tang_run_value(catalog, request, contract, source, source_len,
      scope_fuel, binds, nbinds, NULL, NULL, native, native_user, native_name,
      out, out_len);
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
      strlen(field), &texts, &lens, &count, NULL);
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

/*
 * A template's body and its kind. A template with no kind is refused the way
 * a template that is not there is: the same error.
 */
static GDEFCORE_Result template_load(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, char ** body, size_t * body_len, char ** kind,
    size_t * kind_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  *body = NULL;
  *kind = NULL;
  rc = find_named(catalog, "core.template", 13, name, name_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = config_text(catalog, id, "body", 1, body, body_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = config_text(catalog, id, "kind", 1, kind, kind_len);
  if (rc != GDEFCORE_OK || *kind_len == 0) {
    gdefcore_text_free(catalog, *body);
    gdefcore_text_free(catalog, *kind);
    *body = NULL;
    *kind = NULL;
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : rc;
  }
  return GDEFCORE_OK;
}

/* Run the stored template @p tmpl under the contract of its kind. */
static GDEFCORE_Result render_template(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * tmpl, size_t tmpl_len,
    uint64_t fuel, const TangBind * binds, size_t nbinds, GLTANG_NativeFn native,
    void * native_user, const char * native_name, char ** html,
    size_t * html_len) {
  char * body = NULL;
  char * kind = NULL;
  size_t body_len = 0;
  size_t kind_len = 0;
  GDEFCORE_Contract * contract = NULL;
  GDEFCORE_Result rc;
  rc = template_load(catalog, tmpl, tmpl_len, &body, &body_len, &kind, &kind_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_template_contract_open(catalog, NULL, kind, kind_len, &contract,
      NULL);
  if (rc == GDEFCORE_OK) {
    rc = tang_run(catalog, request, contract, body, body_len, fuel, binds, nbinds,
        native, native_user, native_name, html, html_len);
    if (rc == GDEFCORE_OK) {
      (void)fragment_offer("live", 4);
    }
  } else if (rc != GDEFCORE_ERR_OOM) {
    rc = GDEFCORE_ERR_INVALID;
  }
  gdefcore_template_contract_close(contract);
  gdefcore_text_free(catalog, body);
  gdefcore_text_free(catalog, kind);
  return rc;
}

static GDEFCORE_Result render_one(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * tmpl, size_t tmpl_len, uint64_t fuel,
    const TangBind * binds, size_t nbinds, char ** html, size_t * html_len) {
  return render_template(catalog, request, tmpl, tmpl_len, fuel, binds, nbinds,
      NULL, NULL, NULL, html, html_len);
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
  rc = render_one(catalog, request, tmpl, tmpl_len, fuel, binds, 2, html,
      html_len);
  gdefcore_text_free(catalog, title);
  gdefcore_text_free(catalog, shown);
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
    rc = render_one(catalog, request, tmpl, tmpl_len, fuel, binds, 2, &piece,
        &piece_len);
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

/* ---- navigation widgets (site admin story 6) ----------------------------- */

/* What a pane or a widget call draws against: the page, and a cache. */
typedef struct NavCtx {
  GDEFCORE_Routes * routes;       /* may be NULL */
  const char * path;
  size_t path_len;
  GDEFCORE_FragmentCache * cache; /* may be NULL */
} NavCtx;

static int nav_kind(const char * kind, size_t kind_len) {
  if (span_eq(kind, kind_len, GDEFCORE_WIDGET_MENU,
          sizeof GDEFCORE_WIDGET_MENU - 1)) {
    return 1;
  }
  if (span_eq(kind, kind_len, GDEFCORE_WIDGET_TABS,
          sizeof GDEFCORE_WIDGET_TABS - 1)) {
    return 2;
  }
  if (span_eq(kind, kind_len, GDEFCORE_WIDGET_BREADCRUMBS,
          sizeof GDEFCORE_WIDGET_BREADCRUMBS - 1)) {
    return 3;
  }
  return 0;
}

/* A growing buffer for the key. */
typedef struct KeyBuf {
  char * p;
  size_t n;
  size_t cap;
  int oom;
} KeyBuf;

static void keybuf_add(KeyBuf * k, const char * s, size_t n) {
  if (k->oom) {
    return;
  }
  if (k->n + n + 1 > k->cap) {
    size_t cap = k->cap == 0 ? 256 : k->cap * 2;
    char * next;
    while (cap < k->n + n + 1) {
      cap *= 2;
    }
    next = (char *)realloc(k->p, cap);
    if (next == NULL) {
      k->oom = 1;
      return;
    }
    k->p = next;
    k->cap = cap;
  }
  if (n > 0) {
    memcpy(k->p + k->n, s, n);
  }
  k->n += n;
  k->p[k->n] = '\0';
}

/*
 * The key a widget's fragment is kept under (AD-30): the render key of the
 * request, which carries the tenant, the config epoch, the permission set
 * and, when the render read it, the principal, and which the entries just
 * computed have already added to (the entities and revisions their visibility
 * read); and the widget, its template, its menu, and every value the page
 * matched. A viewer with another permission set, or the same viewer on the
 * page of another `:id`, is another key.
 */
static GDEFCORE_Result widget_key(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, int which, const char * tmpl, size_t tmpl_len,
    const char * menu, size_t menu_len, const GDEFCORE_Route_Match * match,
    char ** out_key, size_t * out_len) {
  KeyBuf k;
  char * base = NULL;
  size_t base_len = 0;
  size_t i;
  GDEFCORE_Result rc;
  memset(&k, 0, sizeof k);
  rc = gdefcore_access_render_key(catalog, request, NULL, 0, NULL, 0, &base,
      &base_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  keybuf_add(&k, base, base_len);
  gdefcore_text_free(catalog, base);
  keybuf_add(&k, "widget:", 7);
  keybuf_add(&k, which == 1 ? "menu" : (which == 2 ? "tabs" : "breadcrumbs"),
      which == 1 ? 4 : (which == 2 ? 4 : 11));
  keybuf_add(&k, "\ntemplate:", 10);
  keybuf_add(&k, tmpl, tmpl_len);
  keybuf_add(&k, "\nmenu:", 6);
  keybuf_add(&k, menu, menu_len);
  keybuf_add(&k, "\nvalues:", 8);
  for (i = 0; i < gdefcore_route_match_capture_count(match); i++) {
    const char * name = NULL;
    const char * value = NULL;
    size_t name_len = 0;
    size_t value_len = 0;
    char lens[48];
    int ln;
    if (gdefcore_route_match_capture(match, i, &name, &name_len, &value,
            &value_len) != GDEFCORE_OK) {
      continue;
    }
    /* Lengths first, so no value can read as the next name. */
    ln = snprintf(lens, sizeof lens, "\n%llu:%llu:", (unsigned long long)name_len,
        (unsigned long long)value_len);
    keybuf_add(&k, lens, ln > 0 ? (size_t)ln : 0);
    keybuf_add(&k, name, name_len);
    keybuf_add(&k, value, value_len);
  }
  keybuf_add(&k, "\n", 1);
  if (k.oom) {
    free(k.p);
    return GDEFCORE_ERR_OOM;
  }
  *out_key = k.p;
  *out_len = k.n;
  return GDEFCORE_OK;
}

/* A text into a map, for the strictest encoding. A text the engine will not
 * take (it is not UTF-8: a raw path segment can be anything) is the empty one. */
static GLTANG_Result nav_text(GLTANG_ValueDescription * d, GLTANG_ValueRef map,
    const char * key, const char * text, size_t len) {
  GLTANG_ValueRef v;
  GLTANG_Result rc = gltang_value_string(d, text, len,
      GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, &v);
  if (rc == GLTANG_ERR_INVALID) {
    rc = gltang_value_string(d, "", 0, GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE,
        &v);
  }
  if (rc == GLTANG_OK) {
    rc = gltang_value_map_set(d, map, key, strlen(key),
        GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, v);
  }
  return rc;
}

static GLTANG_Result nav_int(GLTANG_ValueDescription * d, GLTANG_ValueRef map,
    const char * key, int64_t n) {
  GLTANG_ValueRef v;
  GLTANG_Result rc = gltang_value_integer(d, n, &v);
  if (rc == GLTANG_OK) {
    rc = gltang_value_map_set(d, map, key, strlen(key),
        GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, v);
  }
  return rc;
}

static GLTANG_Result nav_bool(GLTANG_ValueDescription * d, GLTANG_ValueRef map,
    const char * key, int yes) {
  GLTANG_ValueRef v;
  GLTANG_Result rc = gltang_value_bool(d, yes != 0, &v);
  if (rc == GLTANG_OK) {
    rc = gltang_value_map_set(d, map, key, strlen(key),
        GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, v);
  }
  return rc;
}

/* The items of a computed menu as a value: a list of maps. */
static GDEFCORE_Result describe_menu(const GDEFCORE_Menu * menu,
    GLTANG_ValueDescription ** out) {
  GLTANG_ValueDescription * d = NULL;
  GLTANG_ValueRef list;
  GLTANG_Result lr;
  size_t i;
  *out = NULL;
  if (gltang_value_description_create(NULL, &d) != GLTANG_OK) {
    return GDEFCORE_ERR_OOM;
  }
  lr = gltang_value_array(d, &list);
  for (i = 0; lr == GLTANG_OK && i < gdefcore_menu_count(menu); i++) {
    GDEFCORE_Menu_Item it;
    GLTANG_ValueRef map;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_menu_item(menu, i, &it) != GDEFCORE_OK) {
      lr = GLTANG_ERR_INVALID;
      break;
    }
    lr = gltang_value_map(d, &map);
    if (lr == GLTANG_OK) {
      lr = nav_text(d, map, "name", it.name, it.name_len);
    }
    if (lr == GLTANG_OK) {
      lr = nav_text(d, map, "label", it.label, it.label_len);
    }
    if (lr == GLTANG_OK) {
      lr = nav_text(d, map, "route", it.route, it.route_len);
    }
    if (lr == GLTANG_OK) {
      lr = nav_text(d, map, "href", it.href, it.href_len);
    }
    if (lr == GLTANG_OK) {
      lr = nav_text(d, map, "menu", it.menu, it.menu_len);
    }
    if (lr == GLTANG_OK) {
      lr = nav_int(d, map, "weight", it.weight);
    }
    if (lr == GLTANG_OK) {
      lr = nav_int(d, map, "depth", it.depth);
    }
    if (lr == GLTANG_OK) {
      lr = nav_bool(d, map, "current", it.current);
    }
    if (lr == GLTANG_OK) {
      lr = nav_bool(d, map, "trail", it.trail);
    }
    if (lr == GLTANG_OK) {
      lr = gltang_value_array_push(d, list, map);
    }
  }
  if (lr == GLTANG_OK) {
    lr = gltang_value_set_root(d, list);
  }
  if (lr != GLTANG_OK) {
    gltang_value_description_release(d);
    return lr == GLTANG_ERR_LIMIT ? GDEFCORE_ERR_LIMIT : GDEFCORE_ERR_OOM;
  }
  *out = d;
  return GDEFCORE_OK;
}

/*
 * Compute the widget's entries for the page, draw them with the template, and
 * keep the fragment when there is a cache. The entries come first: what their
 * visibility read is part of the key the cache looks under.
 */
static GDEFCORE_Result render_nav(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const NavCtx * nav, const char * kind,
    size_t kind_len, const char * target, size_t target_len, uint64_t fuel,
    char ** html, size_t * html_len) {
  static const char * const kDefault[] = {"", "menu", "tabs", "breadcrumbs"};
  static const char * const kTemplateKind[] = {"", "core.menu", "core.tabs",
      "core.breadcrumbs"};
  int which = nav_kind(kind, kind_len);
  const char * menu = "";
  size_t menu_len = 0;
  const char * tmpl = kDefault[which];
  size_t tmpl_len = strlen(kDefault[which]);
  GDEFCORE_Routes * own_routes = NULL;
  GDEFCORE_Routes * routes;
  GDEFCORE_Route_Match * match = NULL;
  GDEFCORE_Menu * items = NULL;
  GLTANG_ValueDescription * value = NULL;
  GDEFCORE_Contract * contract = NULL;
  char * body = NULL;
  char * tkind = NULL;
  size_t body_len = 0;
  size_t tkind_len = 0;
  char * key = NULL;
  size_t key_len = 0;
  char * bytes = NULL;
  size_t n = 0;
  TangBind bind;
  GDEFCORE_Result rc;
  *html = NULL;
  *html_len = 0;
  if (which == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (which == 1) {
    /* `<menu>` or `<menu>/<template>`. */
    const char * slash = target == NULL ? NULL
                                        : (const char *)memchr(target, '/', target_len);
    menu = target;
    menu_len = slash == NULL ? target_len : (size_t)(slash - target);
    if (menu == NULL || menu_len == 0) {
      return GDEFCORE_ERR_INVALID;
    }
    if (slash != NULL) {
      tmpl = slash + 1;
      tmpl_len = target_len - menu_len - 1;
    }
  } else if (target != NULL && target_len > 0) {
    tmpl = target;
    tmpl_len = target_len;
  }
  if (tmpl_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  routes = nav->routes;
  if (routes == NULL) {
    /* A host with no routes has no page and no tab: only what is declared
     * with no route to follow, which is nothing. */
    rc = gdefcore_routes_create(NULL, &own_routes);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    routes = own_routes;
  }
  if (nav->path != NULL && nav->path_len > 0 && nav->path[0] == '/') {
    rc = gdefcore_routes_match(routes, request, nav->path, nav->path_len, &match);
    if (rc != GDEFCORE_OK) {
      goto done;
    }
  }
  if (which == 1) {
    rc = gdefcore_menu_tree(catalog, routes, request, match, menu, menu_len,
        &items);
  } else if (which == 2) {
    rc = gdefcore_menu_tabs(catalog, routes, request, match, &items);
  } else {
    rc = gdefcore_menu_breadcrumbs(catalog, routes, request, match, NULL, 0,
        &items);
  }
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  rc = template_load(catalog, tmpl, tmpl_len, &body, &body_len, &tkind,
      &tkind_len);
  if (rc == GDEFCORE_OK &&
      !span_eq(tkind, tkind_len, kTemplateKind[which], strlen(kTemplateKind[which]))) {
    rc = GDEFCORE_ERR_INVALID;   /* a template of another kind is not this widget's */
  }
  if (rc != GDEFCORE_OK) {
    goto done;
  }
  if (nav->cache != NULL) {
    char * hit = NULL;
    size_t hit_len = 0;
    int found = 0;
    rc = widget_key(catalog, request, which, tmpl, tmpl_len, menu, menu_len, match,
        &key, &key_len);
    if (rc != GDEFCORE_OK) {
      goto done;
    }
    rc = gdefcore_fragment_get(nav->cache, key, key_len, &hit, &hit_len, &found);
    if (rc != GDEFCORE_OK) {
      goto done;
    }
    if (found) {
      rc = gdefcore_text_dup(catalog, hit, hit_len, html);
      if (rc == GDEFCORE_OK) {
        *html_len = hit_len;
      }
      gdefcore_fragment_free(nav->cache, hit);
      goto done;
    }
  }
  rc = describe_menu(items, &value);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_template_contract_open(catalog, NULL, tkind, tkind_len,
        &contract, NULL);
    if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_OOM) {
      rc = GDEFCORE_ERR_INVALID;
    }
  }
  if (rc == GDEFCORE_OK) {
    bind.name = "menu";
    bind.text = menu;
    bind.len = menu_len;
    rc = tang_run_value(catalog, request, contract, body, body_len, fuel, &bind,
        which == 1 ? 1 : 0, "items", value, NULL, NULL, NULL, &bytes, &n);
  }
  if (rc == GDEFCORE_OK) {
    if (nav->cache != NULL) {
      /* Offered to a cache only when there is one: a pane in a page, or a
       * widget on an admin screen, is kept nowhere. */
      (void)fragment_offer("live", 4);
      (void)gdefcore_fragment_put(nav->cache, request, key, key_len, bytes, n);
    }
    *html = bytes;
    *html_len = n;
  }
done:
  gdefcore_template_contract_close(contract);
  gltang_value_description_release(value);
  gdefcore_menu_free(items);
  gdefcore_route_match_free(match);
  gdefcore_routes_destroy(own_routes);
  gdefcore_text_free(catalog, body);
  gdefcore_text_free(catalog, tkind);
  free(key);
  return rc;
}

GDEFCORE_Result gdefcore_render_widget(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    GDEFCORE_FragmentCache * cache, const char * kind, size_t kind_len,
    const char * target, size_t target_len, const char * path, size_t path_len,
    uint64_t scope_fuel, char ** out_bytes, size_t * out_len) {
  NavCtx nav;
  char * html = NULL;
  size_t html_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || kind == NULL || out_bytes == NULL ||
      out_len == NULL || scope_fuel == 0 || (target == NULL && target_len != 0) ||
      (path == NULL && path_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  nav.routes = routes;
  nav.path = path;
  nav.path_len = path_len;
  nav.cache = cache;
  rc = render_nav(catalog, request, &nav, kind, kind_len, target, target_len,
      scope_fuel, &html, &html_len);
  if (rc == GDEFCORE_OK) {
    *out_bytes = html;
    *out_len = html_len;
  }
  return rc;
}

/* ---- the widget catalog's sources (site admin story 7) --------------------- */

static GDEFCORE_Result empty_html(GDEFCORE_Catalog * catalog, char ** html,
    size_t * html_len) {
  *html = NULL;
  *html_len = 0;
  return gdefcore_text_dup(catalog, "", 0, html);
}

/*
 * Draw the stored template @p tmpl, which must be of the kind @p want, with
 * the text variables @p binds and the list @p value (either may be absent).
 */
static GDEFCORE_Result render_kind(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * tmpl, size_t tmpl_len,
    const char * want, size_t want_len, uint64_t fuel, const TangBind * binds,
    size_t nbinds, const char * value_name, GLTANG_ValueDescription * value,
    char ** html, size_t * html_len) {
  char * body = NULL;
  char * kind = NULL;
  size_t body_len = 0;
  size_t kind_len = 0;
  GDEFCORE_Contract * contract = NULL;
  GDEFCORE_Result rc;
  *html = NULL;
  *html_len = 0;
  rc = template_load(catalog, tmpl, tmpl_len, &body, &body_len, &kind, &kind_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!span_eq(kind, kind_len, want, want_len)) {
    rc = GDEFCORE_ERR_INVALID;   /* a template of another kind is not this widget's */
  } else {
    rc = gdefcore_template_contract_open(catalog, NULL, kind, kind_len, &contract,
        NULL);
    if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_OOM) {
      rc = GDEFCORE_ERR_INVALID;
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = tang_run_value(catalog, request, contract, body, body_len, fuel, binds,
        nbinds, value_name, value, NULL, NULL, NULL, html, html_len);
    if (rc == GDEFCORE_OK) {
      (void)fragment_offer("live", 4);
    }
  }
  gdefcore_template_contract_close(contract);
  gdefcore_text_free(catalog, body);
  gdefcore_text_free(catalog, kind);
  return rc;
}

/* The site name widget. Its source is the base theme's site_name, which
 * settings will replace; a theme without one draws an empty name. */
static GDEFCORE_Result render_sitename(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * tmpl, size_t tmpl_len, uint64_t fuel,
    char ** html, size_t * html_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * name = NULL;
  size_t name_len = 0;
  TangBind bind;
  GDEFCORE_Result rc = find_named(catalog, "core.theme", 10, "base", 4, id);
  if (rc == GDEFCORE_OK) {
    rc = config_text(catalog, id, "site_name", 0, &name, &name_len);
  } else if (rc == GDEFCORE_ERR_INVALID) {
    rc = GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  bind.name = "name";
  bind.text = name == NULL ? "" : name;
  bind.len = name_len;
  rc = render_kind(catalog, request, tmpl, tmpl_len, "core.sitename", 13, fuel,
      &bind, 1, NULL, NULL, html, html_len);
  gdefcore_text_free(catalog, name);
  return rc;
}

/* The page title widget: the title of the entity the page shows, as the
 * request's principal may read it. An entity the viewer may not read makes the
 * page what an unknown path is. */
static GDEFCORE_Result render_title(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * tmpl, size_t tmpl_len, uint64_t fuel,
    char ** html, size_t * html_len) {
  const char * id;
  size_t id_len = 0;
  char * title = NULL;
  size_t title_len = 0;
  int missing = 0;
  TangBind bind;
  GDEFCORE_Result rc;
  id = gdefcore_request_resolution(request, &id_len);
  if (id == NULL || id_len == 0) {
    return empty_html(catalog, html, html_len);
  }
  rc = access_copy(catalog, request, id, id_len, "title", &title, &title_len,
      &missing);
  if (rc != GDEFCORE_OK || missing) {
    gdefcore_text_free(catalog, title);
    return rc == GDEFCORE_OK ? GDEFCORE_ERR_INVALID : rc;
  }
  bind.name = "title";
  bind.text = title == NULL ? "" : title;
  bind.len = title_len;
  rc = render_kind(catalog, request, tmpl, tmpl_len, "core.title", 10, fuel,
      &bind, 1, NULL, NULL, html, html_len);
  gdefcore_text_free(catalog, title);
  return rc;
}

/* The messages widget: declared, with a source that is always empty until the
 * message queue exists. */
static GDEFCORE_Result render_messages(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * tmpl, size_t tmpl_len, uint64_t fuel,
    char ** html, size_t * html_len) {
  GLTANG_ValueDescription * none = NULL;
  GDEFCORE_Result rc = describe_menu(NULL, &none);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = render_kind(catalog, request, tmpl, tmpl_len, "core.messages", 13, fuel,
      NULL, 0, "items", none, html, html_len);
  gltang_value_description_release(none);
  return rc;
}

/* The variables a module's widget provider binds. */
struct GDEFCORE_Widget_Sink {
  char name[GDEFCORE_WIDGET_BINDS_MAX][65];
  char * text[GDEFCORE_WIDGET_BINDS_MAX];
  size_t len[GDEFCORE_WIDGET_BINDS_MAX];
  size_t n;
};

static int bind_name_ok(const char * s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > 64) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
            (i > 0 && c >= '0' && c <= '9'))) {
      return 0;
    }
  }
  return 1;
}

GDEFCORE_Result gdefcore_widget_bind_text(GDEFCORE_Widget_Sink * sink,
    const char * name, size_t name_len, const char * text, size_t text_len) {
  size_t i;
  char * copy;
  if (sink == NULL || !bind_name_ok(name, name_len) ||
      (text == NULL && text_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (text_len > GDEFCORE_WIDGET_VALUE_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < sink->n; i++) {
    if (strlen(sink->name[i]) == name_len &&
        memcmp(sink->name[i], name, name_len) == 0) {
      break;
    }
  }
  if (i == sink->n && sink->n == GDEFCORE_WIDGET_BINDS_MAX) {
    return GDEFCORE_ERR_LIMIT;
  }
  copy = (char *)malloc(text_len + 1);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  if (text_len > 0) {
    memcpy(copy, text, text_len);
  }
  copy[text_len] = '\0';
  if (i == sink->n) {
    memcpy(sink->name[i], name, name_len);
    sink->name[i][name_len] = '\0';
    sink->text[i] = NULL;
    sink->n += 1;
  }
  free(sink->text[i]);
  sink->text[i] = copy;
  sink->len[i] = text_len;
  return GDEFCORE_OK;
}

/*
 * A widget type an enabled module declared. It is drawn only if the viewer
 * holds the permission its source needs, and the provider is not even called
 * otherwise. A provider that fails, a kind or template that does not exist, or
 * a template of another kind draws nothing: a module's widget never takes the
 * page down with it.
 */
static GDEFCORE_Result render_module_widget(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Layout_Widget * w,
    const char * target, size_t target_len, uint64_t fuel, char ** html,
    size_t * html_len) {
  GDEFCORE_Widget_Sink sink;
  TangBind binds[GDEFCORE_WIDGET_BINDS_MAX];
  size_t i;
  GDEFCORE_Result rc;
  if (w->fn == NULL ||
      (w->permission_len > 0 &&
          !gdefcore_access_permits(catalog, request, w->permission,
              w->permission_len))) {
    return empty_html(catalog, html, html_len);
  }
  memset(&sink, 0, sizeof sink);
  rc = w->fn(request, target == NULL ? "" : target, target_len, &sink, w->user);
  if (rc == GDEFCORE_OK) {
    for (i = 0; i < sink.n; i++) {
      binds[i].name = sink.name[i];
      binds[i].text = sink.text[i];
      binds[i].len = sink.len[i];
    }
    rc = render_kind(catalog, request, w->template_name, w->template_len, w->kind,
        w->kind_len, fuel, binds, sink.n, NULL, NULL, html, html_len);
  }
  for (i = 0; i < sink.n; i++) {
    free(sink.text[i]);
  }
  if (rc == GDEFCORE_ERR_OOM || rc == GDEFCORE_OK) {
    return rc;
  }
  gdefcore_text_free(catalog, *html);
  return empty_html(catalog, html, html_len);
}

/* Draw one placement: the widget type by name, with what its source gives. */
static GDEFCORE_Result render_widget_at(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const NavCtx * nav, const char * widget,
    size_t widget_len, const char * target, size_t target_len, uint64_t fuel,
    char ** html, size_t * html_len) {
  GDEFCORE_Layout_Widget w;
  const char * tmpl;
  size_t tmpl_len;
  GDEFCORE_Result rc;
  memset(&w, 0, sizeof w);
  w.size = sizeof w;
  rc = gdefcore_layout_widget_find(catalog, widget, widget_len, &w);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (w.builtin == 0) {
    return render_module_widget(catalog, request, &w, target, target_len, fuel,
        html, html_len);
  }
  tmpl = target_len > 0 ? target : w.template_name;
  tmpl_len = target_len > 0 ? target_len : w.template_len;
  switch (w.builtin) {
  case 1:
    return render_sitename(catalog, request, tmpl, tmpl_len, fuel, html, html_len);
  case 2:
    return render_title(catalog, request, tmpl, tmpl_len, fuel, html, html_len);
  case 3:
    return render_entity_pane(catalog, request, tmpl, tmpl_len, fuel, html,
        html_len);
  case 4:
  case 5:
  case 6:
    return render_nav(catalog, request, nav, widget, widget_len, target,
        target_len, fuel, html, html_len);
  case 7:
    return render_messages(catalog, request, tmpl, tmpl_len, fuel, html, html_len);
  default:
    /* Recent posts: the target names the view, `recent` unless said. */
    return render_view_pane(catalog, request, target_len > 0 ? target : "recent",
        target_len > 0 ? target_len : 6, fuel, html, html_len);
  }
}

static GDEFCORE_Result render_display(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const NavCtx * nav, const char * name,
    size_t name_len, uint64_t fuel, char ** out, size_t * out_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * layout = NULL;
  size_t layout_len = 0;
  char ** panes = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t i;
  RegionSet regions;
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
  if (rc == GDEFCORE_ERR_INVALID) {
    panes = NULL;
    lens = NULL;
    count = 0;
    rc = GDEFCORE_OK;
  } else if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, layout);
    return rc;
  }
  if (count > RENDER_MAX_PANES) {
    rc = GDEFCORE_ERR_LIMIT;
    goto done;
  }
  for (i = 0; i < count; i++) {
    const char * region;
    const char * widget;
    const char * target;
    size_t region_len = 0;
    size_t widget_len = 0;
    size_t target_len = 0;
    char * html = NULL;
    size_t html_len = 0;
    if (!gdefcore_render_split_pane(panes[i], lens[i], &region, &region_len,
            &widget, &widget_len, &target, &target_len)) {
      rc = GDEFCORE_ERR_INVALID;
      goto done;
    }
    rc = render_widget_at(catalog, request, nav, widget, widget_len, target,
        target_len, fuel, &html, &html_len);
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
  rc = render_template(catalog, request, layout, layout_len, fuel, NULL, 0,
      native_region, &regions, "region", out, out_len);
done:
  gdefcore_values_free(catalog, panes, lens, count);
  gdefcore_text_free(catalog, layout);
  region_clear(&regions);
  return rc;
}

/* region("main") in a preview: a marked stand-in, since there is no page. */
static bool native_region_sample(GLTANG_NativeCall * call, void * user) {
  char out[160];
  size_t n = 0;
  size_t o = 0;
  size_t i;
  const char * name = gltang_call_text(call, 0, &n);
  static const char head[] = "<div class=\"sample\">Sample region ";
  (void)user;
  memcpy(out, head, sizeof head - 1);
  o = sizeof head - 1;
  for (i = 0; name != NULL && i < n && o + 8 < sizeof out - 8; i++) {
    unsigned char c = (unsigned char)name[i];
    if (c == '<' || c == '>' || c == '&' || c == '"' || c == '\'' || c < 0x20) {
      out[o++] = '?';
    } else {
      out[o++] = (char)c;
    }
  }
  memcpy(out + o, "</div>", 6);
  o += 6;
  gltang_call_return_string(call, out, o, GLTANG_UNICODE_STRING_TYPE_TRUSTED);
  return true;
}

GDEFCORE_Result gdefcore_render_sample(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * kind, size_t kind_len,
    const char * body, size_t body_len, const char * overlay,
    size_t overlay_len, uint64_t scope_fuel, char ** out_bytes, size_t * out_len,
    int * out_shareable) {
  GDEFCORE_Contract * contract = NULL;
  TangBind * binds = NULL;
  char ** texts = NULL;
  size_t nbinds = 0;
  size_t nvars;
  size_t i;
  int has_region = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || kind == NULL || kind_len == 0 ||
      (body == NULL && body_len != 0) || out_bytes == NULL || out_len == NULL ||
      scope_fuel == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (out_shareable != NULL) {
    *out_shareable = 0;
  }
  /* A principal who may not edit this kind gets what a missing kind gets. */
  if (!gdefcore_template_may_edit(catalog, request, kind, kind_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_template_contract_open(catalog, NULL, kind, kind_len, &contract,
      NULL);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }
  nvars = gdefcore_template_contract_var_count(contract);
  binds = (TangBind *)calloc(nvars == 0 ? 1 : nvars, sizeof *binds);
  texts = (char **)calloc(nvars == 0 ? 1 : nvars, sizeof *texts);
  if (binds == NULL || texts == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  for (i = 0; i < nvars; i++) {
    GDEFCORE_Contract_Var v;
    size_t text_len;
    if (gdefcore_template_contract_var_at(contract, i, &v) != GDEFCORE_OK) {
      rc = GDEFCORE_ERR_INTERNAL;
      goto done;
    }
    if (v.contributed != NULL) {
      continue;
    }
    text_len = 7 + v.name_len;
    texts[nbinds] = (char *)malloc(text_len + 1);
    if (texts[nbinds] == NULL) {
      rc = GDEFCORE_ERR_OOM;
      goto done;
    }
    memcpy(texts[nbinds], "Sample ", 7);
    memcpy(texts[nbinds] + 7, v.name, v.name_len);
    texts[nbinds][text_len] = '\0';
    binds[nbinds].name = v.name;
    binds[nbinds].text = texts[nbinds];
    binds[nbinds].len = text_len;
    nbinds += 1;
  }
  for (i = 0; i < gdefcore_template_contract_fn_count(contract); i++) {
    GDEFCORE_Contract_Fn f;
    if (gdefcore_template_contract_fn_at(contract, i, &f) == GDEFCORE_OK &&
        f.name_len == 6 && memcmp(f.name, "region", 6) == 0) {
      has_region = 1;
    }
  }
  rc = tang_run(catalog, request, contract, body == NULL ? "" : body, body_len,
      scope_fuel, binds, nbinds, has_region ? native_region_sample : NULL, NULL,
      has_region ? "region" : NULL, out_bytes, out_len);
  if (rc == GDEFCORE_OK) {
    int shared = fragment_offer(overlay, overlay_len);
    if (out_shareable != NULL) {
      *out_shareable = shared;
    }
  }
done:
  if (texts != NULL) {
    for (i = 0; i < nvars; i++) {
      free(texts[i]);
    }
  }
  free(texts);
  free(binds);
  gdefcore_template_contract_close(contract);
  return rc;
}

/* ---- an entity in the render context (story S6d) ------------------------ */

typedef struct Kids {
  size_t * head;
  size_t * next;
} Kids;

/* The item @p item of @p tree as a map: each single field a string, each
 * group and multiple field a list in item order, a group's items maps and a
 * multiple field's its values. The tree is gdefcore_access_tree()'s, so a
 * personal value in it is already the plaintext the reader may see, or the
 * erased marker (story S7), and never a ciphertext. */
static GLTANG_Result describe_item(GLTANG_ValueDescription * d,
    const GDEFCORE_Tree * tree, const Kids * kids, size_t item,
    GLTANG_ValueRef * out) {
  GDEFCORE_TreeItem it;
  GLTANG_ValueRef map;
  GLTANG_Result rc;
  size_t k;
  size_t c;
  memset(&it, 0, sizeof it);
  it.size = sizeof it;
  if (gdefcore_tree_item(tree, item, &it) != GDEFCORE_OK) {
    return GLTANG_ERR_INVALID;
  }
  rc = gltang_value_map(d, &map);
  for (k = 0; rc == GLTANG_OK && k < it.value_count; k++) {
    const char * field = NULL;
    size_t field_len = 0;
    const char * text = NULL;
    size_t len = 0;
    GLTANG_ValueRef v;
    if (gdefcore_tree_value(tree, item, k, &field, &field_len, &text, &len) !=
            GDEFCORE_OK ||
        field_len == 0) {
      continue;
    }
    rc = gltang_value_string(d, text, len,
        GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, &v);
    if (rc == GLTANG_OK) {
      rc = gltang_value_map_set(d, map, field, field_len,
          GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, v);
    }
  }
  /* Each field's items as one list, in their order. */
  for (c = kids->head[item]; rc == GLTANG_OK && c != SIZE_MAX;
       c = kids->next[c]) {
    GDEFCORE_TreeItem ci;
    GLTANG_ValueRef list;
    size_t e;
    size_t prior;
    int seen = 0;
    memset(&ci, 0, sizeof ci);
    ci.size = sizeof ci;
    if (gdefcore_tree_item(tree, c, &ci) != GDEFCORE_OK) {
      return GLTANG_ERR_INVALID;
    }
    for (prior = kids->head[item]; prior != c && !seen;
         prior = kids->next[prior]) {
      GDEFCORE_TreeItem pi;
      memset(&pi, 0, sizeof pi);
      pi.size = sizeof pi;
      seen = gdefcore_tree_item(tree, prior, &pi) == GDEFCORE_OK &&
             pi.field_len == ci.field_len &&
             memcmp(pi.field, ci.field, ci.field_len) == 0;
    }
    if (seen) {
      continue;
    }
    rc = gltang_value_array(d, &list);
    if (rc == GLTANG_OK) {
      rc = gltang_value_map_set(d, map, ci.field, ci.field_len,
          GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, list);
    }
    for (e = c; rc == GLTANG_OK && e != SIZE_MAX; e = kids->next[e]) {
      GDEFCORE_TreeItem ei;
      GLTANG_ValueRef el;
      const char * own = NULL;
      size_t own_len = 0;
      memset(&ei, 0, sizeof ei);
      ei.size = sizeof ei;
      if (gdefcore_tree_item(tree, e, &ei) != GDEFCORE_OK) {
        return GLTANG_ERR_INVALID;
      }
      if (ei.field_len != ci.field_len ||
          memcmp(ei.field, ci.field, ci.field_len) != 0) {
        continue;
      }
      if (gdefcore_tree_get(tree, e, NULL, 0, &own, &own_len) ==
              GDEFCORE_OK &&
          own != NULL) {
        rc = gltang_value_string(d, own, own_len,
            GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, &el);
      } else {
        rc = describe_item(d, tree, kids, e, &el);
      }
      if (rc == GLTANG_OK) {
        rc = gltang_value_array_push(d, list, el);
      }
    }
  }
  if (rc == GLTANG_OK) {
    *out = map;
  }
  return rc;
}

static GDEFCORE_Result describe_entity(const GDEFCORE_Tree * tree,
    GLTANG_ValueDescription ** out) {
  GLTANG_ValueDescription * d = NULL;
  Kids kids;
  size_t * tail = NULL;
  size_t n = gdefcore_tree_item_count(tree);
  size_t i;
  GLTANG_ValueRef root;
  GLTANG_Result lr;
  GDEFCORE_Result rc = GDEFCORE_OK;
  *out = NULL;
  kids.head = (size_t *)malloc((n == 0 ? 1 : n) * sizeof *kids.head);
  kids.next = (size_t *)malloc((n == 0 ? 1 : n) * sizeof *kids.next);
  tail = (size_t *)malloc((n == 0 ? 1 : n) * sizeof *tail);
  if (kids.head == NULL || kids.next == NULL || tail == NULL) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  for (i = 0; i < n; i++) {
    kids.head[i] = SIZE_MAX;
    kids.next[i] = SIZE_MAX;
    tail[i] = SIZE_MAX;
  }
  /* A child comes after its parent, and siblings in their order. */
  for (i = 1; i < n; i++) {
    GDEFCORE_TreeItem it;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    if (gdefcore_tree_item(tree, i, &it) != GDEFCORE_OK || it.parent >= i) {
      rc = GDEFCORE_ERR_CORRUPT;
      goto done;
    }
    if (tail[it.parent] == SIZE_MAX) {
      kids.head[it.parent] = i;
    } else {
      kids.next[tail[it.parent]] = i;
    }
    tail[it.parent] = i;
  }
  if (gltang_value_description_create(NULL, &d) != GLTANG_OK) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  lr = describe_item(d, tree, &kids, 0, &root);
  if (lr == GLTANG_OK) {
    lr = gltang_value_set_root(d, root);
  }
  if (lr != GLTANG_OK) {
    gltang_value_description_release(d);
    d = NULL;
    rc = lr == GLTANG_ERR_LIMIT ? GDEFCORE_ERR_LIMIT : GDEFCORE_ERR_OOM;
    goto done;
  }
  *out = d;
done:
  free(kids.head);
  free(kids.next);
  free(tail);
  return rc;
}

GDEFCORE_Result gdefcore_render_entity(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * template_name,
    size_t template_len, const char * id, size_t id_len, const char * lang,
    size_t lang_len, uint64_t scope_fuel, char ** out_bytes,
    size_t * out_len) {
  GDEFCORE_Tree * tree = NULL;
  GLTANG_ValueDescription * value = NULL;
  GDEFCORE_Contract * contract = NULL;
  char * body = NULL;
  char * kind = NULL;
  size_t body_len = 0;
  size_t kind_len = 0;
  char * bytes = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || template_name == NULL ||
      template_len == 0 || id == NULL || lang == NULL || out_bytes == NULL ||
      out_len == NULL || scope_fuel == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  /* The entity as the principal may read it, field by field in every item:
   * one the principal may not see answers as one that is not there. */
  rc = gdefcore_access_tree(catalog, request, id, id_len, lang, lang_len,
      &tree);
  if (rc == GDEFCORE_OK) {
    rc = describe_entity(tree, &value);
  }
  if (rc == GDEFCORE_OK) {
    rc = template_load(catalog, template_name, template_len, &body, &body_len,
        &kind, &kind_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_template_contract_open(catalog, NULL, kind, kind_len,
        &contract, NULL);
    if (rc != GDEFCORE_OK && rc != GDEFCORE_ERR_OOM) {
      rc = GDEFCORE_ERR_INVALID;
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = tang_run_value(catalog, request, contract, body, body_len, scope_fuel,
        NULL, 0, "entity", value, NULL, NULL, NULL, &bytes, &n);
  }
  if (rc == GDEFCORE_OK) {
    (void)fragment_offer("live", 4);
    *out_bytes = bytes;
    *out_len = n;
  }
  gdefcore_template_contract_close(contract);
  gdefcore_text_free(catalog, body);
  gdefcore_text_free(catalog, kind);
  gltang_value_description_release(value);
  gdefcore_tree_free(tree);
  return rc;
}

GDEFCORE_Result gdefcore_render_scope(GDEFCORE_Catalog * catalog,
    const char * source, size_t source_len, uint64_t scope_fuel, char ** out_bytes,
    size_t * out_len) {
  if (out_bytes == NULL || out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return tang_run(catalog, NULL, NULL, source, source_len, scope_fuel, NULL, 0,
      NULL, NULL, NULL, out_bytes, out_len);
}

GDEFCORE_Result gdefcore_render_page(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request, const char * path,
    size_t path_len, uint64_t scope_fuel, char ** out_bytes, size_t * out_len) {
  char * resolved = NULL;
  size_t resolved_len = 0;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type = NULL;
  size_t type_len = 0;
  char * layout = NULL;
  size_t layout_len = 0;
  NavCtx nav;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || path == NULL || out_bytes == NULL ||
      out_len == NULL || scope_fuel == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  nav.routes = routes;
  nav.path = path;
  nav.path_len = path_len;
  nav.cache = NULL;
  if (path_len == 1 && path[0] == '/') {
    rc = gdefcore_request_set_resolution(request, NULL, 0);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  } else {
    rc = gdefcore_form_resolve(routes, catalog, request, path, path_len,
        &resolved, &resolved_len);
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
      return rc;
    }
    gdefcore_text_free(catalog, type);
    rc = gdefcore_request_set_resolution(request, canon, GDEFCORE_PUBLIC_ID_LEN);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  /* Which layout draws the page is the route trie's answer (layout.h): the
   * site's rules and the modules' selectors, most specific first, and the
   * alter hook. A page no layout applies to is what an unknown path is. */
  rc = gdefcore_layout_select(catalog, routes, request, path, path_len, &layout,
      &layout_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = render_display(catalog, request, &nav, layout, layout_len, scope_fuel,
      out_bytes, out_len);
  gdefcore_text_free(catalog, layout);
  return rc;
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

/* Shared with the layouts (layout.c), which are part of the render subsystem. */
GDEFCORE_Result gdefcore_render_find_named(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  return find_named(catalog, type, type_len, name, name_len, out_id);
}

void gdefcore_render_scan_regions(const char * body, size_t n, char *** out_names,
    size_t * out_count, GDEFCORE_Catalog * catalog, GDEFCORE_Result * rc) {
  scan_regions(body, n, out_names, out_count, catalog, rc);
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
      !gdefcore_render_split_pane(panes[index], lens[index], &region,
          &region_len, &kind, &kind_len, &target, &target_len)) {
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

static GDEFCORE_Result ensure_named(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * name, size_t name_len, const char * extra_field,
    const char * extra) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = find_named(catalog, type, type_len, name, name_len, id);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  return put_named(catalog, type, name, extra_field, extra);
}

static GDEFCORE_Result ensure_display(GDEFCORE_Catalog * catalog,
    const char * name, const char * pane) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = find_named(catalog, "core.display", 12, name, strlen(name),
      id);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  return put_display(catalog, name, pane);
}

static GDEFCORE_Result grant_posts(GDEFCORE_Catalog * catalog);

/* A kind and its base contract, unless a kind of that name is stored. */
static GDEFCORE_Result ensure_kind(GDEFCORE_Catalog * catalog, const char * name,
    const char * label, const char * const * vars, size_t nvars,
    const char * const * fns, size_t nfns) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[5];
  const char * texts[3];
  size_t lens[3];
  size_t vlens[8];
  size_t flens[8];
  size_t nvalues = 3;
  size_t i;
  GDEFCORE_Result rc = find_named(catalog, GDEFCORE_TEMPLATE_KIND_TYPE,
      sizeof GDEFCORE_TEMPLATE_KIND_TYPE - 1, name, strlen(name), id);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID || nvars > 8 || nfns > 8) {
    return rc == GDEFCORE_ERR_INVALID ? GDEFCORE_ERR_LIMIT : rc;
  }
  texts[0] = name;
  lens[0] = strlen(name);
  texts[1] = label;
  lens[1] = strlen(label);
  texts[2] = "1";
  lens[2] = 1;
  set_value(&values[0], "name", &texts[0], &lens[0], 1);
  set_value(&values[1], "label", &texts[1], &lens[1], 1);
  set_value(&values[2], "version", &texts[2], &lens[2], 1);
  for (i = 0; i < nvars; i++) {
    vlens[i] = strlen(vars[i]);
  }
  for (i = 0; i < nfns; i++) {
    flens[i] = strlen(fns[i]);
  }
  if (nvars > 0) {
    set_value(&values[nvalues++], "variables", vars, vlens, nvars);
  }
  if (nfns > 0) {
    set_value(&values[nvalues++], "functions", fns, flens, nfns);
  }
  return save_entity(catalog, GDEFCORE_TEMPLATE_KIND_TYPE,
      values, nvalues, 1);
}

/* A template of a kind, unless a template of that name is stored. */
static GDEFCORE_Result ensure_template(GDEFCORE_Catalog * catalog,
    const char * name, const char * body, const char * kind) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[3];
  const char * texts[3];
  size_t lens[3];
  GDEFCORE_Result rc =
      find_named(catalog, "core.template", 13, name, strlen(name), id);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  texts[0] = name;
  lens[0] = strlen(name);
  texts[1] = body;
  lens[1] = strlen(body);
  texts[2] = kind;
  lens[2] = strlen(kind);
  set_value(&values[0], "name", &texts[0], &lens[0], 1);
  set_value(&values[1], "body", &texts[1], &lens[1], 1);
  set_value(&values[2], "kind", &texts[2], &lens[2], 1);
  return save_entity(catalog, "core.template", values, 3, 1);
}

/* A selector rule of the site, unless one of that name is stored. */
static GDEFCORE_Result ensure_rule(GDEFCORE_Catalog * catalog, const char * name,
    const char * path, int exact, const char * layout, const char * type) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Layout_Rule rule;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Result rc = find_named(catalog, GDEFCORE_LAYOUT_RULE_TYPE,
      sizeof GDEFCORE_LAYOUT_RULE_TYPE - 1, name, strlen(name), id);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  memset(&rule, 0, sizeof rule);
  rule.size = sizeof rule;
  rule.path = path;
  rule.path_len = strlen(path);
  rule.layout = layout;
  rule.layout_len = strlen(layout);
  rule.type = type;
  rule.type_len = type == NULL ? 0 : strlen(type);
  rule.exact = exact;
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_layout_stage_rule(cs, name, strlen(name), &rule);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(cs, GDEFCORE_LAYOUT_RULE_TYPE,
        sizeof GDEFCORE_LAYOUT_RULE_TYPE - 1);
  }
  gdefcore_changeset_destroy(cs);
  return rc;
}

static GDEFCORE_Result write_kit(GDEFCORE_Catalog * catalog) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc;
  /* The kinds first: a template is validated against its kind as it is saved. */
  rc = ensure_kind(catalog, "core.page", "Page layout", kPageVars, 0, kPageFns, 2);
  if (rc == GDEFCORE_OK) {
    rc = ensure_kind(catalog, "core.pane", "Pane", kPaneVars, 3, kPaneFns, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "layout", kLayoutBody, "core.page");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "entity", kEntityBody, "core.pane");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "recent", kRecentBody, "core.pane");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_kind(catalog, "core.menu", "Menu", kMenuVars, 2, kNavFns, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_kind(catalog, "core.tabs", "Tabs", kTabsVars, 1, kNavFns, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_kind(catalog, "core.breadcrumbs", "Breadcrumbs", kCrumbsVars, 1,
        kNavFns, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "menu", kMenuBody, "core.menu");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "tabs", kTabsBody, "core.tabs");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "breadcrumbs", kCrumbsBody, "core.breadcrumbs");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_kind(catalog, "core.sitename", "Site name", kSiteNameVars, 1,
        NULL, 0);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_kind(catalog, "core.title", "Page title", kPageTitleVars, 1,
        NULL, 0);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_kind(catalog, "core.messages", "Messages", kMessagesVars, 1,
        NULL, 0);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "sitename", kSiteNameBody, "core.sitename");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "title", kTitleBody, "core.title");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_template(catalog, "messages", kMessagesBody, "core.messages");
  }
  if (rc == GDEFCORE_OK) {
    /* The types of the site's own entries and overrides, and the permission to
     * edit them, granted to nobody. */
    rc = gdefcore_menu_declare(catalog);
  }
  if (rc == GDEFCORE_OK) {
    /* The same for layouts and the rules that choose one. */
    rc = gdefcore_layout_declare(catalog);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_named(catalog, "core.theme", 10, "base", 4, NULL, NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = find_named(catalog, "core.view", 9, "recent", 6, id);
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = gdefcore_render_view_define(catalog, "recent", 6, "site.post", 9, 5,
          "recent", 6, NULL, 0, NULL, 0);
    }
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_display(catalog, "front", "side recent");
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_display(catalog, "post", "main content");
  }
  if (rc == GDEFCORE_OK) {
    /* Which layout draws which page is data too: the front page is exactly
     * `/`, and a page whose entity is a post is any other path. */
    rc = ensure_rule(catalog, "site.front", "/", 1, "front", NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = ensure_rule(catalog, "site.post", "/", 0, "post", "site.post");
  }
  if (rc == GDEFCORE_OK) {
    /* The one permission to edit a template, granted to nobody. */
    rc = gdefcore_template_edit_declare(catalog);
  }
  if (rc == GDEFCORE_OK) {
    rc = grant_posts(catalog);
  }
  return rc;
}

static GDEFCORE_Result displays_ready(GDEFCORE_Catalog * catalog, int * ready) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result front;
  GDEFCORE_Result post;
  *ready = 0;
  front = find_named(catalog, "core.display", 12, "front", 5, id);
  if (front != GDEFCORE_OK && front != GDEFCORE_ERR_INVALID) {
    return front;
  }
  post = find_named(catalog, "core.display", 12, "post", 4, id);
  if (post != GDEFCORE_OK && post != GDEFCORE_ERR_INVALID) {
    return post;
  }
  *ready = front == GDEFCORE_OK && post == GDEFCORE_OK;
  if (*ready) {
    /* The rules that choose them: a tenant with the displays and no rules has
     * a front page nobody can reach. */
    GDEFCORE_Result rf = find_named(catalog, GDEFCORE_LAYOUT_RULE_TYPE,
        sizeof GDEFCORE_LAYOUT_RULE_TYPE - 1, "site.front", 10, id);
    GDEFCORE_Result rp = find_named(catalog, GDEFCORE_LAYOUT_RULE_TYPE,
        sizeof GDEFCORE_LAYOUT_RULE_TYPE - 1, "site.post", 9, id);
    if (rf != GDEFCORE_OK && rf != GDEFCORE_ERR_INVALID) {
      return rf;
    }
    if (rp != GDEFCORE_OK && rp != GDEFCORE_ERR_INVALID) {
      return rp;
    }
    *ready = rf == GDEFCORE_OK && rp == GDEFCORE_OK;
  }
  return GDEFCORE_OK;
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
  GDEFCORE_Field tmpl[5];
  GDEFCORE_Field kinds[5];
  GDEFCORE_Field theme[2];
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
  set_field(&tmpl[2], "kind", 1, 0);
  set_field(&tmpl[3], "attached", 0, 0);
  set_field(&tmpl[4], "classification", 0, 0);
  set_field(&kinds[0], "name", 1, 0);
  set_field(&kinds[1], "label", 1, 0);
  set_field(&kinds[2], "version", 1, 0);
  set_field(&kinds[3], "variables", 0, 1);
  set_field(&kinds[4], "functions", 0, 1);
  set_field(&theme[0], "name", 1, 0);
  set_field(&theme[1], "site_name", 0, 1);
  set_field(&view[0], "name", 1, 0);
  set_field(&view[1], "type", 1, 0);
  set_field(&view[2], "limit", 1, 0);
  set_field(&view[3], "template", 1, 0);
  set_field(&view[4], "sort", 0, 0);
  view[4].name = "sort";
  set_field(&display[0], "name", 1, 0);
  set_field(&display[1], "layout", 1, 0);
  set_field(&display[2], "panes", 0, 1);
  /* range is optional and declared with sort's slot reused below. */
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_define(cs, "site.post", 9, GDEFCORE_TYPE_CONTENT, post,
      3);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_define(cs, "core.template", 13, GDEFCORE_TYPE_CONFIG,
        tmpl, 5);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_define(cs, GDEFCORE_TEMPLATE_KIND_TYPE,
        sizeof GDEFCORE_TEMPLATE_KIND_TYPE - 1, GDEFCORE_TYPE_CONFIG, kinds, 5);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_define(cs, "core.theme", 10, GDEFCORE_TYPE_CONFIG,
        theme, 2);
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
  int ready = 0;
  uint8_t * blob = NULL;
  size_t blob_len = 0;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = displays_ready(catalog, &ready);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (ready) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_type_kind(catalog, "site.post", 9, &kind);
  if (rc == GDEFCORE_ERR_INVALID) {
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
  } else if (rc != GDEFCORE_OK) {
    return rc;
  }
  return write_kit(catalog);
}
