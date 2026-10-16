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
#define GDEFCORE_Condition GHOTIIO_DEFCORE(GDEFCORE_Condition)
#define GDEFCORE_Condition_Error GHOTIIO_DEFCORE(GDEFCORE_Condition_Error)
#define GDEFCORE_Condition_Subject GHOTIIO_DEFCORE(GDEFCORE_Condition_Subject)
#define GDEFCORE_Field GHOTIIO_DEFCORE(GDEFCORE_Field)
#define GDEFCORE_Form GHOTIIO_DEFCORE(GDEFCORE_Form)
#define GDEFCORE_Hook_Fn GHOTIIO_DEFCORE(GDEFCORE_Hook_Fn)
#define GDEFCORE_Hook_Out GHOTIIO_DEFCORE(GDEFCORE_Hook_Out)
#define GDEFCORE_Host GHOTIIO_DEFCORE(GDEFCORE_Host)
#define GDEFCORE_Inst GHOTIIO_DEFCORE(GDEFCORE_Inst)
#define GDEFCORE_Inst_Config GHOTIIO_DEFCORE(GDEFCORE_Inst_Config)
#define GDEFCORE_Keyring GHOTIIO_DEFCORE(GDEFCORE_Keyring)
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
#define GDEFCORE_Route_Call GHOTIIO_DEFCORE(GDEFCORE_Route_Call)
#define GDEFCORE_Route_Call_Fn GHOTIIO_DEFCORE(GDEFCORE_Route_Call_Fn)
#define GDEFCORE_Route_Check_Fn GHOTIIO_DEFCORE(GDEFCORE_Route_Check_Fn)
#define GDEFCORE_Route_Fn GHOTIIO_DEFCORE(GDEFCORE_Route_Fn)
#define GDEFCORE_Route_Info GHOTIIO_DEFCORE(GDEFCORE_Route_Info)
#define GDEFCORE_Route_Spec GHOTIIO_DEFCORE(GDEFCORE_Route_Spec)
#define GDEFCORE_Routes GHOTIIO_DEFCORE(GDEFCORE_Routes)
#define GDEFCORE_Sched GHOTIIO_DEFCORE(GDEFCORE_Sched)
#define GDEFCORE_Subjects GHOTIIO_DEFCORE(GDEFCORE_Subjects)
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
#define gdefcore_access_permits GHOTIIO_DEFCORE(gdefcore_access_permits)
#define gdefcore_access_shared_cache                                           \
  GHOTIIO_DEFCORE(gdefcore_access_shared_cache)
#define gdefcore_access_grant_when GHOTIIO_DEFCORE(gdefcore_access_grant_when)
#define gdefcore_access_permission_info \
  GHOTIIO_DEFCORE(gdefcore_access_permission_info)
#define gdefcore_access_grant_risk GHOTIIO_DEFCORE(gdefcore_access_grant_risk)
#define gdefcore_access_risk_name GHOTIIO_DEFCORE(gdefcore_access_risk_name)
#define gdefcore_access_matrix GHOTIIO_DEFCORE(gdefcore_access_matrix)
#define gdefcore_access_matrix_free GHOTIIO_DEFCORE(gdefcore_access_matrix_free)
#define gdefcore_access_stage_module_grant \
  GHOTIIO_DEFCORE(gdefcore_access_stage_module_grant)
#define gdefcore_access_can GHOTIIO_DEFCORE(gdefcore_access_can)
#define gdefcore_access_route_check \
  GHOTIIO_DEFCORE(gdefcore_access_route_check)
#define gdefcore_access_stage_module_permission                                \
  GHOTIIO_DEFCORE(gdefcore_access_stage_module_permission)
#define gdefcore_condition_parse \
  GHOTIIO_DEFCORE(gdefcore_condition_parse)
#define gdefcore_condition_free \
  GHOTIIO_DEFCORE(gdefcore_condition_free)
#define gdefcore_condition_validate \
  GHOTIIO_DEFCORE(gdefcore_condition_validate)
#define gdefcore_condition_canonical \
  GHOTIIO_DEFCORE(gdefcore_condition_canonical)
#define gdefcore_condition_text_free \
  GHOTIIO_DEFCORE(gdefcore_condition_text_free)
#define gdefcore_condition_hash \
  GHOTIIO_DEFCORE(gdefcore_condition_hash)
#define gdefcore_condition_builtin \
  GHOTIIO_DEFCORE(gdefcore_condition_builtin)
#define gdefcore_condition_uses \
  GHOTIIO_DEFCORE(gdefcore_condition_uses)
#define gdefcore_condition_constrains_type                                     \
  GHOTIIO_DEFCORE(gdefcore_condition_constrains_type)
#define gdefcore_condition_explain \
  GHOTIIO_DEFCORE(gdefcore_condition_explain)
#define gdefcore_condition_eval \
  GHOTIIO_DEFCORE(gdefcore_condition_eval)
#define gdefcore_account_bind GHOTIIO_DEFCORE(gdefcore_account_bind)
#define gdefcore_account_check GHOTIIO_DEFCORE(gdefcore_account_check)
#define gdefcore_account_create GHOTIIO_DEFCORE(gdefcore_account_create)
#define gdefcore_account_epoch GHOTIIO_DEFCORE(gdefcore_account_epoch)
#define gdefcore_account_login GHOTIIO_DEFCORE(gdefcore_account_login)
#define gdefcore_account_logout_everywhere                                     \
  GHOTIIO_DEFCORE(gdefcore_account_logout_everywhere)
#define gdefcore_account_password GHOTIIO_DEFCORE(gdefcore_account_password)
#define gdefcore_account_remove_identifier                                     \
  GHOTIIO_DEFCORE(gdefcore_account_remove_identifier)
#define gdefcore_account_remove_role                                           \
  GHOTIIO_DEFCORE(gdefcore_account_remove_role)
#define gdefcore_account_revert GHOTIIO_DEFCORE(gdefcore_account_revert)
#define gdefcore_account_session_expiry                                        \
  GHOTIIO_DEFCORE(gdefcore_account_session_expiry)
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
#define gdefcore_changeset_accept_sealed                                       \
  GHOTIIO_DEFCORE(gdefcore_changeset_accept_sealed)
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
#define gdefcore_changeset_enforce_access \
  GHOTIIO_DEFCORE(gdefcore_changeset_enforce_access)
#define gdefcore_changeset_set_request                                         \
  GHOTIIO_DEFCORE(gdefcore_changeset_set_request)
#define gdefcore_changeset_stage_module                                        \
  GHOTIIO_DEFCORE(gdefcore_changeset_stage_module)
#define gdefcore_entity_actor GHOTIIO_DEFCORE(gdefcore_entity_actor)
#define gdefcore_entity_state GHOTIIO_DEFCORE(gdefcore_entity_state)
#define gdefcore_entity_create GHOTIIO_DEFCORE(gdefcore_entity_create)
#define gdefcore_entity_ids GHOTIIO_DEFCORE(gdefcore_entity_ids)
#define gdefcore_entity_publish GHOTIIO_DEFCORE(gdefcore_entity_publish)
#define gdefcore_entity_revision GHOTIIO_DEFCORE(gdefcore_entity_revision)
#define gdefcore_entity_revision_at                                            \
  GHOTIIO_DEFCORE(gdefcore_entity_revision_at)
#define gdefcore_entity_revision_count                                         \
  GHOTIIO_DEFCORE(gdefcore_entity_revision_count)
#define gdefcore_entity_save GHOTIIO_DEFCORE(gdefcore_entity_save)
#define gdefcore_entity_save_draft GHOTIIO_DEFCORE(gdefcore_entity_save_draft)
#define gdefcore_entity_type GHOTIIO_DEFCORE(gdefcore_entity_type)
#define gdefcore_entity_values GHOTIIO_DEFCORE(gdefcore_entity_values)
#define gdefcore_epoch GHOTIIO_DEFCORE(gdefcore_epoch)
#define gdefcore_form_alias GHOTIIO_DEFCORE(gdefcore_form_alias)
#define gdefcore_form_check GHOTIIO_DEFCORE(gdefcore_form_check)
#define gdefcore_form_destroy GHOTIIO_DEFCORE(gdefcore_form_destroy)
#define gdefcore_form_field GHOTIIO_DEFCORE(gdefcore_form_field)
#define gdefcore_form_field_count GHOTIIO_DEFCORE(gdefcore_form_field_count)
#define gdefcore_form_publish GHOTIIO_DEFCORE(gdefcore_form_publish)
#define gdefcore_form_resign GHOTIIO_DEFCORE(gdefcore_form_resign)
#define gdefcore_form_resolve GHOTIIO_DEFCORE(gdefcore_form_resolve)
#define gdefcore_form_sign GHOTIIO_DEFCORE(gdefcore_form_sign)
#define gdefcore_form_sign_subject GHOTIIO_DEFCORE(gdefcore_form_sign_subject)
#define gdefcore_form_submit GHOTIIO_DEFCORE(gdefcore_form_submit)
#define gdefcore_form_submit_subject                                           \
  GHOTIIO_DEFCORE(gdefcore_form_submit_subject)
#define gdefcore_form_tree GHOTIIO_DEFCORE(gdefcore_form_tree)
#define gdefcore_hook_fire GHOTIIO_DEFCORE(gdefcore_hook_fire)
#define gdefcore_hook_skipped GHOTIIO_DEFCORE(gdefcore_hook_skipped)
#define gdefcore_hook_skipped_names GHOTIIO_DEFCORE(gdefcore_hook_skipped_names)
#define gdefcore_host_destroy GHOTIIO_DEFCORE(gdefcore_host_destroy)
#define gdefcore_host_open GHOTIIO_DEFCORE(gdefcore_host_open)
#define gdefcore_id_canonical GHOTIIO_DEFCORE(gdefcore_id_canonical)
#define gdefcore_id_encode GHOTIIO_DEFCORE(gdefcore_id_encode)
#define gdefcore_id_generate GHOTIIO_DEFCORE(gdefcore_id_generate)
#define gdefcore_ids_free GHOTIIO_DEFCORE(gdefcore_ids_free)
#define gdefcore_inst_catalog_open GHOTIIO_DEFCORE(gdefcore_inst_catalog_open)
#define gdefcore_inst_config_destroy GHOTIIO_DEFCORE(gdefcore_inst_config_destroy)
#define gdefcore_inst_config_format GHOTIIO_DEFCORE(gdefcore_inst_config_format)
#define gdefcore_inst_config_free GHOTIIO_DEFCORE(gdefcore_inst_config_free)
#define gdefcore_inst_config_load GHOTIIO_DEFCORE(gdefcore_inst_config_load)
#define gdefcore_inst_config_root GHOTIIO_DEFCORE(gdefcore_inst_config_root)
#define gdefcore_inst_config_setting GHOTIIO_DEFCORE(gdefcore_inst_config_setting)
#define gdefcore_inst_default GHOTIIO_DEFCORE(gdefcore_inst_default)
#define gdefcore_inst_destroy GHOTIIO_DEFCORE(gdefcore_inst_destroy)
#define gdefcore_inst_keyring GHOTIIO_DEFCORE(gdefcore_inst_keyring)
#define gdefcore_inst_limit_set GHOTIIO_DEFCORE(gdefcore_inst_limit_set)
#define gdefcore_inst_open GHOTIIO_DEFCORE(gdefcore_inst_open)
#define gdefcore_inst_open_side GHOTIIO_DEFCORE(gdefcore_inst_open_side)
#define gdefcore_inst_resolve GHOTIIO_DEFCORE(gdefcore_inst_resolve)
#define gdefcore_inst_storage_key GHOTIIO_DEFCORE(gdefcore_inst_storage_key)
#define gdefcore_inst_tenant_create GHOTIIO_DEFCORE(gdefcore_inst_tenant_create)
#define gdefcore_inst_tenant_keyring GHOTIIO_DEFCORE(gdefcore_inst_tenant_keyring)
#define gdefcore_inst_text_free GHOTIIO_DEFCORE(gdefcore_inst_text_free)
#define gdefcore_keyring_adopt GHOTIIO_DEFCORE(gdefcore_keyring_adopt)
#define gdefcore_keyring_create GHOTIIO_DEFCORE(gdefcore_keyring_create)
#define gdefcore_keyring_derive GHOTIIO_DEFCORE(gdefcore_keyring_derive)
#define gdefcore_keyring_destroy GHOTIIO_DEFCORE(gdefcore_keyring_destroy)
#define gdefcore_keyring_export GHOTIIO_DEFCORE(gdefcore_keyring_export)
#define gdefcore_limits_default GHOTIIO_DEFCORE(gdefcore_limits_default)
#define gdefcore_module_after_apply GHOTIIO_DEFCORE(gdefcore_module_after_apply)
#define gdefcore_module_clear_pending                                          \
  GHOTIIO_DEFCORE(gdefcore_module_clear_pending)
#define gdefcore_module_disable GHOTIIO_DEFCORE(gdefcore_module_disable)
#define gdefcore_module_enable GHOTIIO_DEFCORE(gdefcore_module_enable)
#define gdefcore_module_enabled GHOTIIO_DEFCORE(gdefcore_module_enabled)
#define gdefcore_module_error GHOTIIO_DEFCORE(gdefcore_module_error)
#define gdefcore_module_fire_veto GHOTIIO_DEFCORE(gdefcore_module_fire_veto)
#define gdefcore_module_fire_write GHOTIIO_DEFCORE(gdefcore_module_fire_write)
#define gdefcore_module_install_guest                                          \
  GHOTIIO_DEFCORE(gdefcore_module_install_guest)
#define gdefcore_module_install_native                                         \
  GHOTIIO_DEFCORE(gdefcore_module_install_native)
#define gdefcore_module_mark_entered                                           \
  GHOTIIO_DEFCORE(gdefcore_module_mark_entered)
#define gdefcore_module_notice GHOTIIO_DEFCORE(gdefcore_module_notice)
#define gdefcore_module_add_routes GHOTIIO_DEFCORE(gdefcore_module_add_routes)
#define gdefcore_module_declared_free \
  GHOTIIO_DEFCORE(gdefcore_module_declared_free)
#define gdefcore_module_links GHOTIIO_DEFCORE(gdefcore_module_links)
#define gdefcore_module_routes GHOTIIO_DEFCORE(gdefcore_module_routes)
#define gdefcore_module_settings GHOTIIO_DEFCORE(gdefcore_module_settings)
#define gdefcore_module_grants GHOTIIO_DEFCORE(gdefcore_module_grants)
#define gdefcore_module_variables GHOTIIO_DEFCORE(gdefcore_module_variables)
#define gdefcore_module_service GHOTIIO_DEFCORE(gdefcore_module_service)
#define gdefcore_module_text_free GHOTIIO_DEFCORE(gdefcore_module_text_free)
#define gdefcore_module_vet GHOTIIO_DEFCORE(gdefcore_module_vet)
#define gdefcore_module_write_enables                                          \
  GHOTIIO_DEFCORE(gdefcore_module_write_enables)
#define gdefcore_patch_free GHOTIIO_DEFCORE(gdefcore_patch_free)
#define gdefcore_render_install GHOTIIO_DEFCORE(gdefcore_render_install)
#define gdefcore_render_kit GHOTIIO_DEFCORE(gdefcore_render_kit)
#define gdefcore_render_names_free GHOTIIO_DEFCORE(gdefcore_render_names_free)
#define gdefcore_render_page GHOTIIO_DEFCORE(gdefcore_render_page)
#define gdefcore_render_pane_at GHOTIIO_DEFCORE(gdefcore_render_pane_at)
#define gdefcore_render_regions GHOTIIO_DEFCORE(gdefcore_render_regions)
#define gdefcore_render_sample GHOTIIO_DEFCORE(gdefcore_render_sample)
#define gdefcore_render_shareable_count \
  GHOTIIO_DEFCORE(gdefcore_render_shareable_count)
#define gdefcore_render_scope GHOTIIO_DEFCORE(gdefcore_render_scope)
#define gdefcore_render_view_define GHOTIIO_DEFCORE(gdefcore_render_view_define)
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
#define gdefcore_request_note GHOTIIO_DEFCORE(gdefcore_request_note)
#define gdefcore_request_principal GHOTIIO_DEFCORE(gdefcore_request_principal)
#define gdefcore_request_memo_get GHOTIIO_DEFCORE(gdefcore_request_memo_get)
#define gdefcore_request_memo_put GHOTIIO_DEFCORE(gdefcore_request_memo_put)
#define gdefcore_request_memo_stats GHOTIIO_DEFCORE(gdefcore_request_memo_stats)
#define gdefcore_request_record_dependency \
  GHOTIIO_DEFCORE(gdefcore_request_record_dependency)
#define gdefcore_request_dependency_count \
  GHOTIIO_DEFCORE(gdefcore_request_dependency_count)
#define gdefcore_request_dependency_at \
  GHOTIIO_DEFCORE(gdefcore_request_dependency_at)
#define gdefcore_request_dependencies_overflowed \
  GHOTIIO_DEFCORE(gdefcore_request_dependencies_overflowed)
#define gdefcore_request_set_fuel GHOTIIO_DEFCORE(gdefcore_request_set_fuel)
#define gdefcore_request_spend_fuel GHOTIIO_DEFCORE(gdefcore_request_spend_fuel)
#define gdefcore_request_fuel_left GHOTIIO_DEFCORE(gdefcore_request_fuel_left)
#define gdefcore_request_set_time GHOTIIO_DEFCORE(gdefcore_request_set_time)
#define gdefcore_request_time GHOTIIO_DEFCORE(gdefcore_request_time)
#define gdefcore_request_mark_principal_dependent                              \
  GHOTIIO_DEFCORE(gdefcore_request_mark_principal_dependent)
#define gdefcore_request_principal_dependent                                   \
  GHOTIIO_DEFCORE(gdefcore_request_principal_dependent)
#define gdefcore_request_resolution GHOTIIO_DEFCORE(gdefcore_request_resolution)
#define gdefcore_request_set_acting_principal                                  \
  GHOTIIO_DEFCORE(gdefcore_request_set_acting_principal)
#define gdefcore_request_set_note GHOTIIO_DEFCORE(gdefcore_request_set_note)
#define gdefcore_request_set_principal                                         \
  GHOTIIO_DEFCORE(gdefcore_request_set_principal)
#define gdefcore_request_set_resolution                                        \
  GHOTIIO_DEFCORE(gdefcore_request_set_resolution)
#define gdefcore_request_set_status GHOTIIO_DEFCORE(gdefcore_request_set_status)
#define gdefcore_request_set_write GHOTIIO_DEFCORE(gdefcore_request_set_write)
#define gdefcore_request_status GHOTIIO_DEFCORE(gdefcore_request_status)
#define gdefcore_request_tenant GHOTIIO_DEFCORE(gdefcore_request_tenant)
#define gdefcore_request_write GHOTIIO_DEFCORE(gdefcore_request_write)
#define gdefcore_request_yield_bound_ms                                         \
  GHOTIIO_DEFCORE(gdefcore_request_yield_bound_ms)
#define gdefcore_result_string GHOTIIO_DEFCORE(gdefcore_result_string)
#define gdefcore_route_add GHOTIIO_DEFCORE(gdefcore_route_add)
#define gdefcore_route_add_spec GHOTIIO_DEFCORE(gdefcore_route_add_spec)
#define gdefcore_route_call_capture GHOTIIO_DEFCORE(gdefcore_route_call_capture)
#define gdefcore_routes_create GHOTIIO_DEFCORE(gdefcore_routes_create)
#define gdefcore_routes_destroy GHOTIIO_DEFCORE(gdefcore_routes_destroy)
#define gdefcore_routes_free GHOTIIO_DEFCORE(gdefcore_routes_free)
#define gdefcore_routes_set_check GHOTIIO_DEFCORE(gdefcore_routes_set_check)
#define gdefcore_routes_tabs_visible \
  GHOTIIO_DEFCORE(gdefcore_routes_tabs_visible)
#define gdefcore_routes_tabs GHOTIIO_DEFCORE(gdefcore_routes_tabs)
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
#define gdefcore_subject_bind_keyring                                          \
  GHOTIIO_DEFCORE(gdefcore_subject_bind_keyring)
#define gdefcore_subject_blind GHOTIIO_DEFCORE(gdefcore_subject_blind)
#define gdefcore_subject_blind_count GHOTIIO_DEFCORE(gdefcore_subject_blind_count)
#define gdefcore_subject_create GHOTIIO_DEFCORE(gdefcore_subject_create)
#define gdefcore_subject_destroy GHOTIIO_DEFCORE(gdefcore_subject_destroy)
#define gdefcore_subject_erase GHOTIIO_DEFCORE(gdefcore_subject_erase)
#define gdefcore_subject_export GHOTIIO_DEFCORE(gdefcore_subject_export)
#define gdefcore_subject_free GHOTIIO_DEFCORE(gdefcore_subject_free)
#define gdefcore_subject_import GHOTIIO_DEFCORE(gdefcore_subject_import)
#define gdefcore_subject_index GHOTIIO_DEFCORE(gdefcore_subject_index)
#define gdefcore_subject_key GHOTIIO_DEFCORE(gdefcore_subject_key)
#define gdefcore_subject_open GHOTIIO_DEFCORE(gdefcore_subject_open)
#define gdefcore_subject_read GHOTIIO_DEFCORE(gdefcore_subject_read)
#define gdefcore_subject_save GHOTIIO_DEFCORE(gdefcore_subject_save)
#define gdefcore_subject_seal GHOTIIO_DEFCORE(gdefcore_subject_seal)
#define gdefcore_subject_snapshot GHOTIIO_DEFCORE(gdefcore_subject_snapshot)
#define gdefcore_text_dup GHOTIIO_DEFCORE(gdefcore_text_dup)
#define gdefcore_text_free GHOTIIO_DEFCORE(gdefcore_text_free)
#define gdefcore_type_define GHOTIIO_DEFCORE(gdefcore_type_define)
#define gdefcore_type_field GHOTIIO_DEFCORE(gdefcore_type_field)
#define gdefcore_type_field_constraints                                        \
  GHOTIIO_DEFCORE(gdefcore_type_field_constraints)
#define gdefcore_type_field_count GHOTIIO_DEFCORE(gdefcore_type_field_count)
#define gdefcore_type_field_personal                                           \
  GHOTIIO_DEFCORE(gdefcore_type_field_personal)
#define gdefcore_type_kind GHOTIIO_DEFCORE(gdefcore_type_kind)
#define gdefcore_values_free GHOTIIO_DEFCORE(gdefcore_values_free)

#define gdefcore_catalog_host GHOTIIO_DEFCORE(gdefcore_catalog_host)
#define gdefcore_changeset_touched_count \
  GHOTIIO_DEFCORE(gdefcore_changeset_touched_count)
#define gdefcore_changeset_touched_at \
  GHOTIIO_DEFCORE(gdefcore_changeset_touched_at)
#define gdefcore_changeset_refusal GHOTIIO_DEFCORE(gdefcore_changeset_refusal)
#define gdefcore_changeset_set_refusal \
  GHOTIIO_DEFCORE(gdefcore_changeset_set_refusal)

#define gdefcore_module_contribute GHOTIIO_DEFCORE(gdefcore_module_contribute)
#define gdefcore_module_contributions \
  GHOTIIO_DEFCORE(gdefcore_module_contributions)
#define gdefcore_module_contributions_free \
  GHOTIIO_DEFCORE(gdefcore_module_contributions_free)

#define gdefcore_template_contract_open \
  GHOTIIO_DEFCORE(gdefcore_template_contract_open)
#define gdefcore_template_contract_close \
  GHOTIIO_DEFCORE(gdefcore_template_contract_close)
#define gdefcore_template_contract_version \
  GHOTIIO_DEFCORE(gdefcore_template_contract_version)
#define gdefcore_template_contract_var_count \
  GHOTIIO_DEFCORE(gdefcore_template_contract_var_count)
#define gdefcore_template_contract_var_at \
  GHOTIIO_DEFCORE(gdefcore_template_contract_var_at)
#define gdefcore_template_contract_var \
  GHOTIIO_DEFCORE(gdefcore_template_contract_var)
#define gdefcore_template_contract_fn_count \
  GHOTIIO_DEFCORE(gdefcore_template_contract_fn_count)
#define gdefcore_template_contract_fn_at \
  GHOTIIO_DEFCORE(gdefcore_template_contract_fn_at)
#define gdefcore_template_validate GHOTIIO_DEFCORE(gdefcore_template_validate)
#define gdefcore_template_preview GHOTIIO_DEFCORE(gdefcore_template_preview)
#define gdefcore_template_vet GHOTIIO_DEFCORE(gdefcore_template_vet)
#define gdefcore_template_authorize GHOTIIO_DEFCORE(gdefcore_template_authorize)
#define gdefcore_template_declare_touched \
  GHOTIIO_DEFCORE(gdefcore_template_declare_touched)
#define gdefcore_template_edit_label GHOTIIO_DEFCORE(gdefcore_template_edit_label)
#define gdefcore_template_edit_name GHOTIIO_DEFCORE(gdefcore_template_edit_name)
#define gdefcore_template_kind_declare \
  GHOTIIO_DEFCORE(gdefcore_template_kind_declare)
#define gdefcore_template_may_edit GHOTIIO_DEFCORE(gdefcore_template_may_edit)
#define gdefcore_template_report_count \
  GHOTIIO_DEFCORE(gdefcore_template_report_count)
#define gdefcore_template_report_at GHOTIIO_DEFCORE(gdefcore_template_report_at)
#define gdefcore_template_report_text \
  GHOTIIO_DEFCORE(gdefcore_template_report_text)
#define gdefcore_template_report_free \
  GHOTIIO_DEFCORE(gdefcore_template_report_free)

/// @endcond

#endif /* GHOTI_IO_GDEFCORE_NAMESPACE_H */
