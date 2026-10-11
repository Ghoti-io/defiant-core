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

#define GDEFCORE_Access_List GHOTIIO_DEFCORE(GDEFCORE_Access_List)
#define GDEFCORE_Allocator GHOTIIO_DEFCORE(GDEFCORE_Allocator)
#define GDEFCORE_Alter GHOTIIO_DEFCORE(GDEFCORE_Alter)
#define GDEFCORE_Catalog GHOTIIO_DEFCORE(GDEFCORE_Catalog)
#define GDEFCORE_Changeset GHOTIIO_DEFCORE(GDEFCORE_Changeset)
#define GDEFCORE_Field GHOTIIO_DEFCORE(GDEFCORE_Field)
#define GDEFCORE_Hook_Fn GHOTIIO_DEFCORE(GDEFCORE_Hook_Fn)
#define GDEFCORE_Hook_Out GHOTIIO_DEFCORE(GDEFCORE_Hook_Out)
#define GDEFCORE_Host GHOTIIO_DEFCORE(GDEFCORE_Host)
#define GDEFCORE_Limits GHOTIIO_DEFCORE(GDEFCORE_Limits)
#define GDEFCORE_Module_Entry GHOTIIO_DEFCORE(GDEFCORE_Module_Entry)
#define GDEFCORE_Module_Manifest GHOTIIO_DEFCORE(GDEFCORE_Module_Manifest)
#define GDEFCORE_Module_Perm GHOTIIO_DEFCORE(GDEFCORE_Module_Perm)
#define GDEFCORE_Module_Rel GHOTIIO_DEFCORE(GDEFCORE_Module_Rel)
#define GDEFCORE_Module_Service GHOTIIO_DEFCORE(GDEFCORE_Module_Service)
#define GDEFCORE_Module_Sub GHOTIIO_DEFCORE(GDEFCORE_Module_Sub)
#define GDEFCORE_Offload_Fn GHOTIIO_DEFCORE(GDEFCORE_Offload_Fn)
#define GDEFCORE_Patch GHOTIIO_DEFCORE(GDEFCORE_Patch)
#define GDEFCORE_Permission GHOTIIO_DEFCORE(GDEFCORE_Permission)
#define GDEFCORE_Request GHOTIIO_DEFCORE(GDEFCORE_Request)
#define GDEFCORE_Request_Fn GHOTIIO_DEFCORE(GDEFCORE_Request_Fn)
#define GDEFCORE_Result GHOTIIO_DEFCORE(GDEFCORE_Result)
#define GDEFCORE_Sched GHOTIIO_DEFCORE(GDEFCORE_Sched)
#define GDEFCORE_Turn GHOTIIO_DEFCORE(GDEFCORE_Turn)
#define GDEFCORE_Value GHOTIIO_DEFCORE(GDEFCORE_Value)
#define GDEFCORE_Write_Hook GHOTIIO_DEFCORE(GDEFCORE_Write_Hook)

#define gdefcore_access_admin_principal                                        \
  GHOTIIO_DEFCORE(gdefcore_access_admin_principal)
#define gdefcore_access_clear_staged                                           \
  GHOTIIO_DEFCORE(gdefcore_access_clear_staged)
#define gdefcore_access_commit_staged                                          \
  GHOTIIO_DEFCORE(gdefcore_access_commit_staged)
#define gdefcore_access_copy_template                                          \
  GHOTIIO_DEFCORE(gdefcore_access_copy_template)
#define gdefcore_access_declare GHOTIIO_DEFCORE(gdefcore_access_declare)
#define gdefcore_access_delete_role GHOTIIO_DEFCORE(gdefcore_access_delete_role)
#define gdefcore_access_free GHOTIIO_DEFCORE(gdefcore_access_free)
#define gdefcore_access_grant GHOTIIO_DEFCORE(gdefcore_access_grant)
#define gdefcore_access_list GHOTIIO_DEFCORE(gdefcore_access_list)
#define gdefcore_access_principal_add_role                                     \
  GHOTIIO_DEFCORE(gdefcore_access_principal_add_role)
#define gdefcore_access_principal_create                                       \
  GHOTIIO_DEFCORE(gdefcore_access_principal_create)
#define gdefcore_access_principal_remove                                       \
  GHOTIIO_DEFCORE(gdefcore_access_principal_remove)
#define gdefcore_access_principal_remove_role                                  \
  GHOTIIO_DEFCORE(gdefcore_access_principal_remove_role)
#define gdefcore_access_principal_roles                                        \
  GHOTIIO_DEFCORE(gdefcore_access_principal_roles)
#define gdefcore_access_read GHOTIIO_DEFCORE(gdefcore_access_read)
#define gdefcore_access_render_key GHOTIIO_DEFCORE(gdefcore_access_render_key)
#define gdefcore_access_role_create GHOTIIO_DEFCORE(gdefcore_access_role_create)
#define gdefcore_access_role_grants GHOTIIO_DEFCORE(gdefcore_access_role_grants)
#define gdefcore_access_role_id GHOTIIO_DEFCORE(gdefcore_access_role_id)
#define gdefcore_access_roles GHOTIIO_DEFCORE(gdefcore_access_roles)
#define gdefcore_access_shared_cache                                           \
  GHOTIIO_DEFCORE(gdefcore_access_shared_cache)
#define gdefcore_access_stage_module_permission                                \
  GHOTIIO_DEFCORE(gdefcore_access_stage_module_permission)
#define gdefcore_allocator_default GHOTIIO_DEFCORE(gdefcore_allocator_default)
#define gdefcore_alter_create GHOTIIO_DEFCORE(gdefcore_alter_create)
#define gdefcore_alter_destroy GHOTIIO_DEFCORE(gdefcore_alter_destroy)
#define gdefcore_alter_set GHOTIIO_DEFCORE(gdefcore_alter_set)
#define gdefcore_alter_text GHOTIIO_DEFCORE(gdefcore_alter_text)
#define gdefcore_catalog_bind_host GHOTIIO_DEFCORE(gdefcore_catalog_bind_host)
#define gdefcore_catalog_destroy GHOTIIO_DEFCORE(gdefcore_catalog_destroy)
#define gdefcore_catalog_open GHOTIIO_DEFCORE(gdefcore_catalog_open)
#define gdefcore_catalog_tenant GHOTIIO_DEFCORE(gdefcore_catalog_tenant)
#define gdefcore_changeset_add_confirm_line                                    \
  GHOTIIO_DEFCORE(gdefcore_changeset_add_confirm_line)
#define gdefcore_changeset_apply GHOTIIO_DEFCORE(gdefcore_changeset_apply)
#define gdefcore_changeset_base_seq GHOTIIO_DEFCORE(gdefcore_changeset_base_seq)
#define gdefcore_changeset_catalog GHOTIIO_DEFCORE(gdefcore_changeset_catalog)
#define gdefcore_changeset_conflict GHOTIIO_DEFCORE(gdefcore_changeset_conflict)
#define gdefcore_changeset_define GHOTIIO_DEFCORE(gdefcore_changeset_define)
#define gdefcore_changeset_destroy GHOTIIO_DEFCORE(gdefcore_changeset_destroy)
#define gdefcore_changeset_module_at                                           \
  GHOTIIO_DEFCORE(gdefcore_changeset_module_at)
#define gdefcore_changeset_module_count                                        \
  GHOTIIO_DEFCORE(gdefcore_changeset_module_count)
#define gdefcore_changeset_diff GHOTIIO_DEFCORE(gdefcore_changeset_diff)
#define gdefcore_changeset_epoch GHOTIIO_DEFCORE(gdefcore_changeset_epoch)
#define gdefcore_changeset_parse GHOTIIO_DEFCORE(gdefcore_changeset_parse)
#define gdefcore_changeset_prepare GHOTIIO_DEFCORE(gdefcore_changeset_prepare)
#define gdefcore_changeset_rate GHOTIIO_DEFCORE(gdefcore_changeset_rate)
#define gdefcore_changeset_rebase GHOTIIO_DEFCORE(gdefcore_changeset_rebase)
#define gdefcore_changeset_revert GHOTIIO_DEFCORE(gdefcore_changeset_revert)
#define gdefcore_changeset_serialize                                           \
  GHOTIIO_DEFCORE(gdefcore_changeset_serialize)
#define gdefcore_changeset_set_request                                         \
  GHOTIIO_DEFCORE(gdefcore_changeset_set_request)
#define gdefcore_changeset_stage_module                                        \
  GHOTIIO_DEFCORE(gdefcore_changeset_stage_module)
#define gdefcore_entity_actor GHOTIIO_DEFCORE(gdefcore_entity_actor)
#define gdefcore_entity_create GHOTIIO_DEFCORE(gdefcore_entity_create)
#define gdefcore_entity_ids GHOTIIO_DEFCORE(gdefcore_entity_ids)
#define gdefcore_entity_save GHOTIIO_DEFCORE(gdefcore_entity_save)
#define gdefcore_entity_type GHOTIIO_DEFCORE(gdefcore_entity_type)
#define gdefcore_entity_values GHOTIIO_DEFCORE(gdefcore_entity_values)
#define gdefcore_epoch GHOTIIO_DEFCORE(gdefcore_epoch)
#define gdefcore_hook_fire GHOTIIO_DEFCORE(gdefcore_hook_fire)
#define gdefcore_hook_skipped GHOTIIO_DEFCORE(gdefcore_hook_skipped)
#define gdefcore_hook_skipped_names GHOTIIO_DEFCORE(gdefcore_hook_skipped_names)
#define gdefcore_host_destroy GHOTIIO_DEFCORE(gdefcore_host_destroy)
#define gdefcore_host_open GHOTIIO_DEFCORE(gdefcore_host_open)
#define gdefcore_id_canonical GHOTIIO_DEFCORE(gdefcore_id_canonical)
#define gdefcore_id_encode GHOTIIO_DEFCORE(gdefcore_id_encode)
#define gdefcore_id_generate GHOTIIO_DEFCORE(gdefcore_id_generate)
#define gdefcore_ids_free GHOTIIO_DEFCORE(gdefcore_ids_free)
#define gdefcore_limits_default GHOTIIO_DEFCORE(gdefcore_limits_default)
#define gdefcore_module_after_apply GHOTIIO_DEFCORE(gdefcore_module_after_apply)
#define gdefcore_module_clear_pending                                          \
  GHOTIIO_DEFCORE(gdefcore_module_clear_pending)
#define gdefcore_module_disable GHOTIIO_DEFCORE(gdefcore_module_disable)
#define gdefcore_module_enable GHOTIIO_DEFCORE(gdefcore_module_enable)
#define gdefcore_module_enabled GHOTIIO_DEFCORE(gdefcore_module_enabled)
#define gdefcore_module_error GHOTIIO_DEFCORE(gdefcore_module_error)
#define gdefcore_module_fire_write GHOTIIO_DEFCORE(gdefcore_module_fire_write)
#define gdefcore_module_install_guest                                          \
  GHOTIIO_DEFCORE(gdefcore_module_install_guest)
#define gdefcore_module_install_native                                         \
  GHOTIIO_DEFCORE(gdefcore_module_install_native)
#define gdefcore_module_mark_entered                                           \
  GHOTIIO_DEFCORE(gdefcore_module_mark_entered)
#define gdefcore_module_notice GHOTIIO_DEFCORE(gdefcore_module_notice)
#define gdefcore_module_service GHOTIIO_DEFCORE(gdefcore_module_service)
#define gdefcore_module_text_free GHOTIIO_DEFCORE(gdefcore_module_text_free)
#define gdefcore_module_vet GHOTIIO_DEFCORE(gdefcore_module_vet)
#define gdefcore_module_write_enables                                          \
  GHOTIIO_DEFCORE(gdefcore_module_write_enables)
#define gdefcore_patch_free GHOTIIO_DEFCORE(gdefcore_patch_free)
#define gdefcore_request_acting_principal                                      \
  GHOTIIO_DEFCORE(gdefcore_request_acting_principal)
#define gdefcore_request_attach_fiber                                          \
  GHOTIIO_DEFCORE(gdefcore_request_attach_fiber)
#define gdefcore_request_create GHOTIIO_DEFCORE(gdefcore_request_create)
#define gdefcore_request_deadline_ms                                            \
  GHOTIIO_DEFCORE(gdefcore_request_deadline_ms)
#define gdefcore_request_destroy GHOTIIO_DEFCORE(gdefcore_request_destroy)
#define gdefcore_request_fiber GHOTIIO_DEFCORE(gdefcore_request_fiber)
#define gdefcore_request_id GHOTIIO_DEFCORE(gdefcore_request_id)
#define gdefcore_request_principal GHOTIIO_DEFCORE(gdefcore_request_principal)
#define gdefcore_request_set_acting_principal                                  \
  GHOTIIO_DEFCORE(gdefcore_request_set_acting_principal)
#define gdefcore_request_set_principal                                         \
  GHOTIIO_DEFCORE(gdefcore_request_set_principal)
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
#define gdefcore_text_dup GHOTIIO_DEFCORE(gdefcore_text_dup)
#define gdefcore_text_free GHOTIIO_DEFCORE(gdefcore_text_free)
#define gdefcore_type_define GHOTIIO_DEFCORE(gdefcore_type_define)
#define gdefcore_type_field GHOTIIO_DEFCORE(gdefcore_type_field)
#define gdefcore_type_field_count GHOTIIO_DEFCORE(gdefcore_type_field_count)
#define gdefcore_type_kind GHOTIIO_DEFCORE(gdefcore_type_kind)
#define gdefcore_values_free GHOTIIO_DEFCORE(gdefcore_values_free)

/// @endcond

#endif /* GHOTI_IO_GDEFCORE_NAMESPACE_H */
