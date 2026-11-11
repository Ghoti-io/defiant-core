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
 * What a placement says beyond `region widget [target]`: a title, and when it
 * shows. They follow the target as `~key=value` tokens, the value
 * percent-encoded so that it has no space:
 *
 *   side menu ~title=Site%20menu ~role=editor ~path=/admin/ followed by two stars
 *
 * `title` is drawn above the widget, escaped. The rest are visibility, and a
 * placement shows only when every one given holds: `path` is the page's path
 * (a segment of `:name` or `*` takes any one segment, and a last segment `**`
 * takes the rest), `role` is one of the roles the principal holds (the
 * built-in anonymous and authenticated count, and the key may be given up to 8
 * times, any of them), `type` is the type of the entity the page resolved to.
 * It is data, never code, and it only narrows: a placement a viewer may not
 * see renders nothing, is never asked to draw, and leaves nothing of itself
 * behind. A condition says who sees a placement; it grants nothing, and the
 * widget's own checks still decide what it shows.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>

#include "../core/asset_util.h"
#include "render_internal.h"

#include <stdio.h>
#include <string.h>

static int hex_val(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/* Decode @p n bytes of a value into @p out (@p cap bytes with the NUL). Returns
 * the length, or -1 for a bad escape or a value that does not fit. */
long gdefcore_render_unescape(const char * s, size_t n, char * out, size_t cap) {
  size_t i;
  size_t o = 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '%') {
      int hi;
      int lo;
      if (i + 2 >= n) {
        return -1;
      }
      hi = hex_val(s[i + 1]);
      lo = hex_val(s[i + 2]);
      if (hi < 0 || lo < 0) {
        return -1;
      }
      c = (unsigned char)(hi * 16 + lo);
      i += 2;
    }
    if (o + 1 >= cap) {
      return -1;
    }
    out[o++] = (char)c;
  }
  out[o] = '\0';
  return (long)o;
}

static int role_ok(const char * s, size_t n) {
  size_t i;
  if (n == 0 || n > GDEFCORE_PANE_ROLE_MAX ||
      !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9'))) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
            c == '_' || c == '-')) {
      return 0;
    }
  }
  return 1;
}

/* `module.name`: letters, digits, '_' and '-', one dot between two non-empty parts. */
static int type_ok(const char * s, size_t n) {
  size_t i;
  size_t dots = 0;
  if (n < 3 || n > GDEFCORE_PANE_TYPE_MAX || s[0] == '.' || s[n - 1] == '.') {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (c == '.') {
      dots += 1;
    } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_' || c == '-')) {
      return 0;
    }
  }
  return dots == 1;
}

/* A path pattern: a leading slash, segments of letters, digits and `._~-`, or
 * `:name`, or `*`, and, last, `**`. */
static int path_ok(const char * s, size_t n) {
  size_t i = 1;
  if (n == 0 || n > GDEFCORE_PANE_PATH_MAX || s[0] != '/') {
    return 0;
  }
  while (i <= n) {
    size_t b = i;
    size_t j;
    int last;
    while (i < n && s[i] != '/') {
      i += 1;
    }
    last = i >= n;
    if (i == b) {
      /* An empty segment is only the end of "/" or of a trailing slash. */
      if (n == 1) {
        return 1;
      }
      return 0;
    }
    if (i - b == 2 && s[b] == '*' && s[b + 1] == '*') {
      if (!last) {
        return 0;
      }
    } else if (i - b == 1 && s[b] == '*') {
      /* any one segment */
    } else if (s[b] == ':') {
      if (i - b < 2) {
        return 0;
      }
      for (j = b + 1; j < i; j++) {
        char c = s[j];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
          return 0;
        }
      }
    } else {
      for (j = b; j < i; j++) {
        char c = s[j];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '~' ||
                c == '-')) {
          return 0;
        }
      }
    }
    if (last) {
      return 1;
    }
    i += 1;
  }
  return 1;
}

static void say(char * why, size_t cap, const char * text) {
  if (why != NULL && cap > 0) {
    snprintf(why, cap, "%s", text);
  }
}

int gdefcore_render_pane_extras(const char * s, size_t n, GdefPane * out, char * why,
    size_t cap) {
  size_t i = 0;
  size_t token = 0;
  memset(out, 0, sizeof *out);
  while (i <= n) {
    size_t b = i;
    size_t e;
    while (i < n && s[i] != ' ') {
      i += 1;
    }
    e = i;
    i += 1;
    if (e == b) {
      say(why, cap, "A placement has an empty part.");
      return 0;
    }
    token += 1;
    if (token <= 2 || s[b] != '~') {
      if (token > 2 && token != 3) {
        say(why, cap, "A placement's parts after its target start with '~'.");
        return 0;
      }
      continue;
    }
    {
      const char * key = s + b + 1;
      size_t key_len = 0;
      const char * value;
      size_t value_len;
      char decoded[GDEFCORE_PANE_TITLE_MAX * 3 + 1];
      long dn;
      while (b + 1 + key_len < e && key[key_len] != '=') {
        key_len += 1;
      }
      if (b + 1 + key_len >= e) {
        say(why, cap, "A placement part is ~key=value.");
        return 0;
      }
      value = key + key_len + 1;
      value_len = e - (b + 1 + key_len + 1);
      dn = gdefcore_render_unescape(value, value_len, decoded, sizeof decoded);
      if (dn < 0 || memchr(decoded, '\0', (size_t)dn) != NULL) {
        say(why, cap, "A placement part has a value that is not escaped properly.");
        return 0;
      }
      if (key_len == 5 && memcmp(key, "title", 5) == 0) {
        if (out->title_len > 0 || dn == 0 || dn > GDEFCORE_PANE_TITLE_MAX ||
            !gdefcore_text_ok(decoded, (size_t)dn, 0)) {
          say(why, cap, "A placement's title is 1 to 128 bytes of text, given once.");
          return 0;
        }
        memcpy(out->title, decoded, (size_t)dn);
        out->title_len = (size_t)dn;
      } else if (key_len == 4 && memcmp(key, "path", 4) == 0) {
        if (out->path_len > 0 || !path_ok(decoded, (size_t)dn)) {
          say(why, cap, "A placement's path is not a path pattern, or is given twice.");
          return 0;
        }
        memcpy(out->path, decoded, (size_t)dn);
        out->path_len = (size_t)dn;
      } else if (key_len == 4 && memcmp(key, "type", 4) == 0) {
        if (out->type_len > 0 || !type_ok(decoded, (size_t)dn)) {
          say(why, cap, "A placement's type is not an entity type name, or is given twice.");
          return 0;
        }
        memcpy(out->type, decoded, (size_t)dn);
        out->type_len = (size_t)dn;
      } else if (key_len == 4 && memcmp(key, "role", 4) == 0) {
        size_t k;
        if (out->nroles >= GDEFCORE_PANE_ROLES_MAX || !role_ok(decoded, (size_t)dn)) {
          say(why, cap, "A placement's role is not a role name, or there are more than 8.");
          return 0;
        }
        for (k = 0; k < out->nroles; k++) {
          if (strlen(out->roles[k]) == (size_t)dn &&
              memcmp(out->roles[k], decoded, (size_t)dn) == 0) {
            say(why, cap, "A placement names a role twice.");
            return 0;
          }
        }
        memcpy(out->roles[out->nroles], decoded, (size_t)dn);
        out->roles[out->nroles][dn] = '\0';
        out->nroles += 1;
      } else {
        say(why, cap, "A placement part is ~title, ~path, ~type or ~role.");
        return 0;
      }
    }
  }
  return 1;
}

/* Whether the page's path matches the pattern: segment for segment, `:name` and
 * `*` taking any one, and a last `**` the rest, none included. */
int gdefcore_render_path_matches(const char * pat, size_t pn, const char * path, size_t n);
#define path_matches gdefcore_render_path_matches
int gdefcore_render_path_matches(const char * pat, size_t pn, const char * path, size_t n) {
  size_t pi = 0;
  size_t qi = 0;
  if (pn == 1 && pat[0] == '/') {
    return n == 1 && path[0] == '/';
  }
  while (pi < pn) {
    size_t pb;
    size_t pe;
    size_t qb;
    size_t qe;
    pi += 1;   /* the slash */
    pb = pi;
    while (pi < pn && pat[pi] != '/') {
      pi += 1;
    }
    pe = pi;
    if (pe - pb == 2 && pat[pb] == '*' && pat[pb + 1] == '*') {
      return 1;
    }
    if (qi >= n || path[qi] != '/') {
      return 0;
    }
    qi += 1;
    qb = qi;
    while (qi < n && path[qi] != '/') {
      qi += 1;
    }
    qe = qi;
    if (qe == qb) {
      return 0;
    }
    if (!((pe - pb == 1 && pat[pb] == '*') || pat[pb] == ':' ||
            (pe - pb == qe - qb && memcmp(pat + pb, path + qb, pe - pb) == 0))) {
      return 0;
    }
  }
  return qi >= n || (qi + 1 == n && path[qi] == '/');
}

/* The roles the principal holds, with the two built-ins. */
static int holds_role(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const GdefPane * p) {
  size_t plen = 0;
  const char * principal = gdefcore_request_principal(request, &plen);
  char ** roles = NULL;
  size_t nroles = 0;
  size_t i;
  size_t k;
  int hit = 0;
  /* What this page shows now depends on who asks, so a host that keeps a page
   * keeps one for each principal (the render key then names the principal). */
  gdefcore_request_mark_principal_dependent(request);
  for (k = 0; k < p->nroles && !hit; k++) {
    const char * want = p->roles[k];
    if (principal == NULL || plen == 0) {
      hit = strcmp(want, "anonymous") == 0;
    } else if (strcmp(want, "authenticated") == 0) {
      hit = 1;
    }
  }
  if (hit || principal == NULL || plen == 0) {
    return hit;
  }
  if (gdefcore_access_principal_roles(catalog, principal, plen, &roles, &nroles) !=
      GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < nroles && !hit; i++) {
    for (k = 0; k < p->nroles; k++) {
      if (strcmp(roles[i], p->roles[k]) == 0) {
        hit = 1;
      }
    }
  }
  gdefcore_access_free(catalog, roles, nroles);
  return hit;
}

int gdefcore_render_pane_visible(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * path, size_t path_len,
    const GdefPane * p) {
  if (p->path_len > 0 &&
      (path == NULL || !path_matches(p->path, p->path_len, path, path_len))) {
    return 0;
  }
  if (p->type_len > 0) {
    size_t res_len = 0;
    const char * res = gdefcore_request_resolution(request, &res_len);
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * type = NULL;
    size_t type_len = 0;
    int same;
    if (res == NULL || res_len == 0 ||
        gdefcore_id_canonical(res, res_len, canon) != GDEFCORE_OK ||
        gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type,
            &type_len) != GDEFCORE_OK) {
      return 0;
    }
    same = type_len == p->type_len && memcmp(type, p->type, type_len) == 0;
    gdefcore_text_free(catalog, type);
    if (!same) {
      return 0;
    }
  }
  if (p->nroles > 0 && !holds_role(catalog, request, p)) {
    return 0;
  }
  return 1;
}
