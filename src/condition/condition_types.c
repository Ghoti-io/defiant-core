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
 * What a condition knows of a field's logical type, shared by the evaluator
 * (condition_eval.c), the list compiler (condition_plan.c) and the validator
 * (condition.c), so that the three read a comparison alike
 * (condition_internal.h says how).
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/entity.h>

#include "condition_internal.h"

#include <string.h>

int cond_field_info(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * name, size_t name_len, CondField * out) {
  size_t count = 0;
  size_t i;
  memset(out, 0, sizeof *out);
  if (gdefcore_type_field_count(catalog, type, type_len, &count) !=
      GDEFCORE_OK) {
    return 1;
  }
  for (i = 0; i < count; i++) {
    char * got = NULL;
    size_t got_len = 0;
    int required = 0;
    int many = 0;
    int match;
    if (gdefcore_type_field(catalog, type, type_len, i, &got, &got_len,
            &required, &many) != GDEFCORE_OK) {
      return 1;
    }
    match = got_len == name_len && memcmp(got, name, name_len) == 0;
    gdefcore_text_free(catalog, got);
    if (match) {
      int personal = 0;
      out->found = 1;
      out->many = many;
      if (gdefcore_type_field_personal(catalog, type, type_len, i, &personal) !=
              GDEFCORE_OK ||
          gdefcore_type_field_type(catalog, type, type_len, i, &out->type,
              &out->scale) != GDEFCORE_OK) {
        return 1;
      }
      out->personal = personal;
      /* A field an access callback decides is unusable in any condition, so
       * that no list can probe it (story A6). */
      out->governed = gdefcore_access_field_governed(catalog, type, type_len,
          name, name_len);
      return 0;
    }
  }
  return 0;
}

int cond_numeric_type(int type) {
  return type == GDEFSTOR_FIELD_INTEGER || type == GDEFSTOR_FIELD_DECIMAL ||
         type == GDEFSTOR_FIELD_FLOAT || type == GDEFSTOR_FIELD_DATE ||
         type == GDEFSTOR_FIELD_DATETIME;
}

int cond_texty_type(int type) {
  return type == GDEFSTOR_FIELD_TEXT || type == GDEFSTOR_FIELD_REFERENCE;
}

int cond_types_meet(int ta, int sa, int tb, int sb) {
  if (cond_texty_type(ta) && cond_texty_type(tb)) {
    return 1;
  }
  return ta == tb && (ta != GDEFSTOR_FIELD_DECIMAL || sa == sb);
}

int cond_now_as(int type, int scale, int64_t now, GDEFSTOR_Value * out) {
  int k;
  memset(out, 0, sizeof *out);
  out->type = type;
  switch (type) {
  case GDEFSTOR_FIELD_INTEGER:
    out->integer = now;
    return 1;
  case GDEFSTOR_FIELD_DECIMAL:
    out->integer = now;
    for (k = 0; k < scale; k++) {
      if (out->integer > INT64_MAX / 10 || out->integer < INT64_MIN / 10) {
        return 0;
      }
      out->integer *= 10;
    }
    return 1;
  case GDEFSTOR_FIELD_FLOAT:
    out->real = (double)now;
    return 1;
  case GDEFSTOR_FIELD_DATE:
    out->integer = now >= 0 ? now / 86400 : -((-now + 86399) / 86400);
    return 1;
  case GDEFSTOR_FIELD_DATETIME:
    if (now > INT64_MAX / 1000 || now < INT64_MIN / 1000) {
      return 0;
    }
    out->integer = now * 1000;
    return 1;
  default:
    return 0;
  }
}
