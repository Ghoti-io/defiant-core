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
 * @file allocator.h
 * @brief Allocator abstraction. This is cutil's under a local name.
 * @stability free
 */

#ifndef GHOTI_IO_GDEFCORE_ALLOCATOR_H
#define GHOTI_IO_GDEFCORE_ALLOCATOR_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/cutil/allocator.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocator interface used by the library.
 *
 * A NULL allocator argument means gdefcore_allocator_default().
 */
typedef GCU_Allocator GDEFCORE_Allocator;

/**
 * @brief The process-wide default allocator.
 *
 * @return A pointer the caller does not free.
 */
GDEFCORE_API const GDEFCORE_Allocator * gdefcore_allocator_default(void);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_ALLOCATOR_H */
