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
 * @file entity_internal.h
 *
 * Private to src/entity. Another subsystem includes entity.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_ENTITY_ENTITY_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_ENTITY_ENTITY_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>

enum {
  GDEFCORE_OP_SAVE = 1,
  GDEFCORE_OP_CLEAR = 2,
  GDEFCORE_OP_DEFINE = 3,
  GDEFCORE_OP_ENABLE = 4,
  GDEFCORE_OP_DISABLE = 5,
  GDEFCORE_OP_DRAFT = 6,
  GDEFCORE_OP_PUBLISH = 7,
  GDEFCORE_OP_UNPUBLISH = 8,
  GDEFCORE_OP_ACTIVATE = 9,
  GDEFCORE_OP_REVERT = 10
};

typedef struct GDEFCORE_Text {
  char * p;
  size_t n;
} GDEFCORE_Text;

typedef struct GDEFCORE_Vals {
  GDEFCORE_Text name;
  GDEFCORE_Text * vals;
  size_t nvals;
} GDEFCORE_Vals;

typedef struct GDEFCORE_Lang {
  GDEFCORE_Text lang;
  GDEFCORE_Vals * fields;
  size_t nfields;
} GDEFCORE_Lang;

typedef struct GDEFCORE_Doc {
  GDEFCORE_Lang * langs;
  size_t nlangs;
} GDEFCORE_Doc;

typedef struct GDEFCORE_Decl {
  GDEFCORE_Text name;
  int required;
  int many;
  int personal;
  size_t min_len;
  size_t max_len;
  int has_range;
  int64_t range_min;
  int64_t range_max;
  GDEFCORE_Text pattern;
} GDEFCORE_Decl;

typedef struct GDEFCORE_Op {
  int kind;
  GDEFCORE_Text id;
  uint64_t row;
  int have_row;
  GDEFCORE_Text type_name;
  int type_kind;
  GDEFCORE_Text machine;
  GDEFCORE_Doc staged;
  GDEFCORE_Doc base;
  uint64_t base_seq;
  uint64_t base_ver;   /* the entity's version when the op was staged */
  int have_ver;
  uint64_t target_seq; /* the revision an activate makes active */
  GDEFCORE_Decl * decls;
  size_t ndecls;
} GDEFCORE_Op;

struct GDEFCORE_Catalog {
  GDEFSTOR_Store * store;
  uint8_t * tenant;
  size_t tenant_len;
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Limits limits;
  GDEFCORE_Host * host;
};

struct GDEFCORE_Changeset {
  GDEFCORE_Catalog * catalog;
  uint64_t epoch;
  GDEFCORE_Text actor;
  GDEFCORE_Op * ops;
  size_t nops;
  GDEFCORE_Text conflict;
  GDEFCORE_Text refusal;
  GDEFCORE_Text * lines;
  size_t nlines;
  int applied;
  GDEFCORE_Request * request;
  int accept_sealed;
};

#endif /* GHOTI_IO_GDEFCORE_SRC_ENTITY_ENTITY_INTERNAL_H */
