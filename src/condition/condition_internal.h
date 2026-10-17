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
  kRevCreator,  /* revision.creator: who wrote the active revision */
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

#endif /* GHOTI_IO_GDEFCORE_SRC_CONDITION_CONDITION_INTERNAL_H */
