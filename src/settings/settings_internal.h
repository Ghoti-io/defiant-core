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
 * @file settings_internal.h
 *
 * Private to src/settings. Another subsystem includes settings.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_SETTINGS_SETTINGS_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_SETTINGS_SETTINGS_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/settings.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The settings the tenant has, loaded for one operation. */
typedef struct Defs {
  GDEFCORE_Setting * v;
  size_t n;
  GDEFCORE_Host * host;
  const GDEFCORE_Module_Declared_Setting ** items;
} Defs;

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SRC_SETTINGS_SETTINGS_INTERNAL_H */
