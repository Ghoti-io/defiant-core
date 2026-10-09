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
 * @file request_internal.h
 *
 * Private to src/request. Another subsystem includes request.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_REQUEST_REQUEST_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_REQUEST_REQUEST_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/request.h>

struct GDEFCORE_Request {
  uint8_t * tenant;
  size_t tenant_len;
  uint64_t deadline_ms;
  uint64_t yield_bound_ms;
  uint64_t id;
  GDEFCORE_Result status;
  GCU_Fiber * fiber;
  GDEFSTOR_Write * write;
  const GDEFCORE_Allocator * allocator;
};

#endif /* GHOTI_IO_GDEFCORE_SRC_REQUEST_REQUEST_INTERNAL_H */
