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
 * @file namespace.h
 * @brief Maps every public name into this build's version namespace.
 * @stability free
 *
 * `make check-symbols` fails if an exported symbol is missing from this list.
 */

#ifndef GHOTI_IO_GDEFCORE_NAMESPACE_H
#define GHOTI_IO_GDEFCORE_NAMESPACE_H

#include <ghoti.io/defiant-core/libver.h>

/// @cond HIDDEN_SYMBOLS

#define GDEFCORE_Allocator GHOTIIO_DEFCORE(GDEFCORE_Allocator)
#define GDEFCORE_Offload_Fn GHOTIIO_DEFCORE(GDEFCORE_Offload_Fn)
#define GDEFCORE_Request GHOTIIO_DEFCORE(GDEFCORE_Request)
#define GDEFCORE_Request_Fn GHOTIIO_DEFCORE(GDEFCORE_Request_Fn)
#define GDEFCORE_Result GHOTIIO_DEFCORE(GDEFCORE_Result)
#define GDEFCORE_Sched GHOTIIO_DEFCORE(GDEFCORE_Sched)
#define GDEFCORE_Turn GHOTIIO_DEFCORE(GDEFCORE_Turn)

#define gdefcore_allocator_default GHOTIIO_DEFCORE(gdefcore_allocator_default)
#define gdefcore_request_attach_fiber                                          \
  GHOTIIO_DEFCORE(gdefcore_request_attach_fiber)
#define gdefcore_request_create GHOTIIO_DEFCORE(gdefcore_request_create)
#define gdefcore_request_deadline_ms                                            \
  GHOTIIO_DEFCORE(gdefcore_request_deadline_ms)
#define gdefcore_request_destroy GHOTIIO_DEFCORE(gdefcore_request_destroy)
#define gdefcore_request_fiber GHOTIIO_DEFCORE(gdefcore_request_fiber)
#define gdefcore_request_id GHOTIIO_DEFCORE(gdefcore_request_id)
#define gdefcore_request_set_status GHOTIIO_DEFCORE(gdefcore_request_set_status)
#define gdefcore_request_set_write GHOTIIO_DEFCORE(gdefcore_request_set_write)
#define gdefcore_request_status GHOTIIO_DEFCORE(gdefcore_request_status)
#define gdefcore_request_tenant GHOTIIO_DEFCORE(gdefcore_request_tenant)
#define gdefcore_request_write GHOTIIO_DEFCORE(gdefcore_request_write)
#define gdefcore_request_yield_bound_ms                                         \
  GHOTIIO_DEFCORE(gdefcore_request_yield_bound_ms)
#define gdefcore_result_string GHOTIIO_DEFCORE(gdefcore_result_string)
#define gdefcore_sched_create GHOTIIO_DEFCORE(gdefcore_sched_create)
#define gdefcore_sched_destroy GHOTIIO_DEFCORE(gdefcore_sched_destroy)
#define gdefcore_sched_offload GHOTIIO_DEFCORE(gdefcore_sched_offload)
#define gdefcore_sched_run GHOTIIO_DEFCORE(gdefcore_sched_run)
#define gdefcore_sched_spawn GHOTIIO_DEFCORE(gdefcore_sched_spawn)
#define gdefcore_sched_watchdog_count                                           \
  GHOTIIO_DEFCORE(gdefcore_sched_watchdog_count)
#define gdefcore_sched_watchdog_id_at                                           \
  GHOTIIO_DEFCORE(gdefcore_sched_watchdog_id_at)
#define gdefcore_sched_yield GHOTIIO_DEFCORE(gdefcore_sched_yield)

/// @endcond

#endif /* GHOTI_IO_GDEFCORE_NAMESPACE_H */
