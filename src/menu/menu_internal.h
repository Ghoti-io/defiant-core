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
 * @file menu_internal.h
 *
 * Private to src/menu. Another subsystem includes menu.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_MENU_MENU_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_MENU_MENU_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A borrowed text and its length. Owned by the computation's arena. */
typedef struct Str {
  const char * p;
  size_t n;
} Str;

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SRC_MENU_MENU_INTERNAL_H */
