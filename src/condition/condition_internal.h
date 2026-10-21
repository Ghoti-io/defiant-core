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
 * @file condition_internal.h
 *
 * Private to src/condition. Another subsystem includes condition.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_CONDITION_CONDITION_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_CONDITION_CONDITION_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/entity.h>

#include <stddef.h>
#include <stdint.h>

/* A node's kind. Boolean kinds come first. */
enum {
  kTrue = 1,
  kFalse,
  kAnd,
  kOr,
  kNot,
  kCmp,
  kIn,
  kType,
  kState,
  kRevCreator,  /* revision.creator: who wrote the current revision */
  kCreator,     /* creator: who created the entity */
  kPrincipal,
  kNow,
  kField,
  kText,
  kInt,
  kRelated,     /* (related "name" (operand ...)): kids[0] is the name, a kText */
  kAny          /* `_` in a related: this column is free */
};

/* A comparison operator, in the node's op member. */
enum { kEq = 1, kNe, kLt, kLe, kGt, kGe };

enum {
  kMaxNodes = GDEFCORE_CONDITION_MAX_NODES,
  kMaxPool = GDEFCORE_CONDITION_MAX_BYTES + 16,
  kMaxFieldName = 64,
  kMaxFieldValues = 64
};

typedef struct CNode {
  uint8_t kind;
  uint8_t op;
  uint16_t first;   /* index into kids */
  uint16_t count;   /* children, starting at kids[first] */
  uint32_t pos;     /* byte offset in the parsed text */
  uint32_t str;     /* offset in pool: text, integer text or field name */
  uint32_t str_len;
  int64_t ival;
} CNode;

/* Everything a parsed condition owns lives in this one block. */
struct GDEFCORE_Condition {
  uint16_t nnodes;
  uint16_t nkids;
  uint16_t root;
  uint32_t pool_len;
  unsigned uses;
  CNode nodes[kMaxNodes];
  uint16_t kids[kMaxNodes];
  char pool[kMaxPool];
};

/* True when text is an integer: -?[0-9]{1,18}. */
int cond_parse_int(const char * p, size_t n, int64_t * out);

/*
 * Fields have logical types (entity.h). The evaluator and the list compiler
 * read a comparison the same way (condition_types.c):
 *
 * - A field's values are typed; one with no value reads as the single empty
 *   text, as it always has. Constants, `type`, `state` and `now` are texts;
 *   `principal`, `creator` and `revision.creator` are identifiers.
 * - `=`, `!=` and `in`: a text or reference field compares by bytes with
 *   texts and identifiers; any other field reads a text in its own type (a
 *   text that is not one of its type equals no value of it) and never equals
 *   an identifier; `now` is that number in the field's type. Two fields
 *   compare when both are text or reference, or both of one type.
 * - `<`, `<=`, `>`, `>=` need a numeric or temporal field on a field side
 *   (access SPEC decision 12); two fields need one type. A text that is not
 *   a value of the type makes its pair false. Without a field both sides are
 *   read as integers, as before.
 * - A comparison these rules do not allow (an ordering of a text field, two
 *   fields of different types) fails: it holds for nothing, `not` included,
 *   and gdefcore_condition_validate() refuses it.
 */
typedef struct CondField {
  int found;
  int personal;
  /* An access callback governs it (story A6): never read by a condition. */
  int governed;
  int many;
  int type;
  int scale;
} CondField;

/* What a field of the type is. 0, or 1 when the type cannot be read. */
int cond_field_info(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * name, size_t name_len, CondField * out);
/* An integer, decimal, float, date or date-time. */
int cond_numeric_type(int type);
/* A text or a reference: compared by bytes. */
int cond_texty_type(int type);
/* Two fields' types can be compared with `=` (and, numeric, ordered). */
int cond_types_meet(int ta, int sa, int tb, int sb);
/* `now` (seconds) as a value of a field of @p type: 0 when it is none. */
int cond_now_as(int type, int scale, int64_t now, GDEFSTOR_Value * out);

#endif /* GHOTI_IO_GDEFCORE_SRC_CONDITION_CONDITION_INTERNAL_H */
