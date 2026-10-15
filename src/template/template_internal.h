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
 * @file template_internal.h
 *
 * Private to src/template. Another subsystem includes template.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_TEMPLATE_TEMPLATE_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_TEMPLATE_TEMPLATE_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/template.h>

#include <stddef.h>

/** A contract variable as held. */
typedef struct GDEFCORE_CVar {
  char * name;
  size_t name_len;
  int type;
  char * description;
  size_t description_len;
  const GDEFCORE_Module_Contributed * contributed;
} GDEFCORE_CVar;

/** A contract function as held. */
typedef struct GDEFCORE_CFn {
  char * name;
  size_t name_len;
  int arity;
} GDEFCORE_CFn;

struct GDEFCORE_Contract {
  char * kind;
  size_t kind_len;
  int version;
  GDEFCORE_CVar * vars;
  size_t nvars;
  size_t cap_vars;
  GDEFCORE_CFn * fns;
  size_t nfns;
  size_t cap_fns;
};

/** One finding as held. */
typedef struct GDEFCORE_CIssue {
  int reason;
  char * template_name;
  size_t template_name_len;
  int line;
  int column;
  char * name;
  size_t name_len;
  char * message;
  size_t message_len;
} GDEFCORE_CIssue;

struct GDEFCORE_Template_Report {
  GDEFCORE_CIssue * issues;
  size_t n;
  size_t cap;
  char * text;
  size_t text_len;
  int truncated;
};

#endif /* GHOTI_IO_GDEFCORE_SRC_TEMPLATE_TEMPLATE_INTERNAL_H */
