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
#define GDEFCORE_Catalog GHOTIIO_DEFCORE(GDEFCORE_Catalog)
#define GDEFCORE_Changeset GHOTIIO_DEFCORE(GDEFCORE_Changeset)
#define GDEFCORE_Field GHOTIIO_DEFCORE(GDEFCORE_Field)
#define GDEFCORE_Limits GHOTIIO_DEFCORE(GDEFCORE_Limits)
#define GDEFCORE_Offload_Fn GHOTIIO_DEFCORE(GDEFCORE_Offload_Fn)
#define GDEFCORE_Patch GHOTIIO_DEFCORE(GDEFCORE_Patch)
#define GDEFCORE_Request GHOTIIO_DEFCORE(GDEFCORE_Request)
#define GDEFCORE_Request_Fn GHOTIIO_DEFCORE(GDEFCORE_Request_Fn)
#define GDEFCORE_Result GHOTIIO_DEFCORE(GDEFCORE_Result)
#define GDEFCORE_Sched GHOTIIO_DEFCORE(GDEFCORE_Sched)
#define GDEFCORE_Turn GHOTIIO_DEFCORE(GDEFCORE_Turn)
#define GDEFCORE_Value GHOTIIO_DEFCORE(GDEFCORE_Value)

#define gdefcore_allocator_default GHOTIIO_DEFCORE(gdefcore_allocator_default)
#define gdefcore_catalog_destroy GHOTIIO_DEFCORE(gdefcore_catalog_destroy)
#define gdefcore_catalog_open GHOTIIO_DEFCORE(gdefcore_catalog_open)
#define gdefcore_changeset_apply GHOTIIO_DEFCORE(gdefcore_changeset_apply)
#define gdefcore_changeset_base_seq GHOTIIO_DEFCORE(gdefcore_changeset_base_seq)
#define gdefcore_changeset_conflict GHOTIIO_DEFCORE(gdefcore_changeset_conflict)
#define gdefcore_changeset_define GHOTIIO_DEFCORE(gdefcore_changeset_define)
#define gdefcore_changeset_destroy GHOTIIO_DEFCORE(gdefcore_changeset_destroy)
#define gdefcore_changeset_diff GHOTIIO_DEFCORE(gdefcore_changeset_diff)
#define gdefcore_changeset_epoch GHOTIIO_DEFCORE(gdefcore_changeset_epoch)
#define gdefcore_changeset_parse GHOTIIO_DEFCORE(gdefcore_changeset_parse)
#define gdefcore_changeset_prepare GHOTIIO_DEFCORE(gdefcore_changeset_prepare)
#define gdefcore_changeset_rate GHOTIIO_DEFCORE(gdefcore_changeset_rate)
#define gdefcore_changeset_rebase GHOTIIO_DEFCORE(gdefcore_changeset_rebase)
#define gdefcore_changeset_revert GHOTIIO_DEFCORE(gdefcore_changeset_revert)
#define gdefcore_changeset_serialize                                           \
  GHOTIIO_DEFCORE(gdefcore_changeset_serialize)
#define gdefcore_entity_create GHOTIIO_DEFCORE(gdefcore_entity_create)
#define gdefcore_entity_save GHOTIIO_DEFCORE(gdefcore_entity_save)
#define gdefcore_entity_values GHOTIIO_DEFCORE(gdefcore_entity_values)
#define gdefcore_epoch GHOTIIO_DEFCORE(gdefcore_epoch)
#define gdefcore_id_canonical GHOTIIO_DEFCORE(gdefcore_id_canonical)
#define gdefcore_id_encode GHOTIIO_DEFCORE(gdefcore_id_encode)
#define gdefcore_id_generate GHOTIIO_DEFCORE(gdefcore_id_generate)
#define gdefcore_limits_default GHOTIIO_DEFCORE(gdefcore_limits_default)
#define gdefcore_patch_free GHOTIIO_DEFCORE(gdefcore_patch_free)
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
#define gdefcore_text_free GHOTIIO_DEFCORE(gdefcore_text_free)
#define gdefcore_type_define GHOTIIO_DEFCORE(gdefcore_type_define)
#define gdefcore_type_field GHOTIIO_DEFCORE(gdefcore_type_field)
#define gdefcore_type_field_count GHOTIIO_DEFCORE(gdefcore_type_field_count)
#define gdefcore_type_kind GHOTIIO_DEFCORE(gdefcore_type_kind)
#define gdefcore_values_free GHOTIIO_DEFCORE(gdefcore_values_free)

/// @endcond

#endif /* GHOTI_IO_GDEFCORE_NAMESPACE_H */
