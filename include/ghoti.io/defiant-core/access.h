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
 * @file access.h
 * @brief Roles, permissions, the access filter and the render key.
 * @stability free
 *
 * One subsystem. A tenant is seeded with the roles admin, authenticated
 * and anonymous, and with one admin principal. Anonymous and authenticated
 * are states. A filtered read is what a principal uses. gdefcore_entity_values()
 * stays the unfiltered preview.
 */

#ifndef GHOTI_IO_GDEFCORE_ACCESS_H
#define GHOTI_IO_GDEFCORE_ACCESS_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The condition matches every entity of the type. */
#define GDEFCORE_ACCESS_ANY 1
/** The condition matches when the entity actor is the request principal. */
#define GDEFCORE_ACCESS_OWN 2

/**
 * Typed confirmation that grants a permission to the authenticated state.
 * Any other text writes nothing.
 */
#define GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED \
  "authenticated means everyone with an account"

/**
 * Typed confirmation that grants a permission to the anonymous state.
 * Any other text writes nothing.
 */
#define GDEFCORE_ACCESS_CONFIRM_ANONYMOUS \
  "anonymous means everyone without an account"

/**
 * @brief A permission declaration. Begins with @ref size.
 *
 * @ref field empty means the permission covers the entity. A field name
 * covers that field only. New permissions are granted to nobody.
 */
typedef struct GDEFCORE_Permission {
  size_t size;                 ///< Must be `sizeof(GDEFCORE_Permission)`.
  const char * label;          ///< Plain-language label. Required.
  size_t label_len;            ///< Length of @ref label.
  const char * module_name;    ///< Module that declared it. Required.
  size_t module_name_len;      ///< Length of @ref module_name.
  const char * action;         ///< Action name. Required.
  size_t action_len;           ///< Length of @ref action.
  int condition;               ///< ::GDEFCORE_ACCESS_ANY or ::GDEFCORE_ACCESS_OWN.
  const char * type_name;      ///< Entity type the condition names. Required.
  size_t type_name_len;        ///< Length of @ref type_name.
  const char * field;          ///< Field, or NULL when the permission is entity-wide.
  size_t field_len;            ///< Length of @ref field.
} GDEFCORE_Permission;

/**
 * @brief A filtered list. Begins with @ref size.
 *
 * A filter or a sort that names a field the principal may not read, or a
 * field the type does not have, is refused and returns no rows.
 */
typedef struct GDEFCORE_Access_List {
  size_t size;                  ///< Must be `sizeof(GDEFCORE_Access_List)`.
  const char * type_name;       ///< Entity type. Required.
  size_t type_name_len;         ///< Length of @ref type_name.
  const char * lang;            ///< Language of field values. Required.
  size_t lang_len;              ///< Length of @ref lang.
  const char * filter_field;    ///< Field to match, or NULL.
  size_t filter_field_len;      ///< Length of @ref filter_field.
  const char * filter_text;     ///< Value to match, or NULL.
  size_t filter_text_len;       ///< Length of @ref filter_text.
  const char * sort_field;      ///< Field to sort by, or NULL.
  size_t sort_field_len;        ///< Length of @ref sort_field.
} GDEFCORE_Access_List;

/** @brief Free a list of texts from this header. NULL is ignored. */
GDEFCORE_API void gdefcore_access_free(GDEFCORE_Catalog * catalog,
    char ** items, size_t count);

/**
 * @brief Role names on the tenant, including the three seeded roles.
 *
 * Free @p out_names with gdefcore_access_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_roles(GDEFCORE_Catalog * catalog,
    char *** out_names, size_t * out_count);

/**
 * @brief The seeded admin principal. Not an account.
 *
 * @param out_id Receives the canonical public id and a NUL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_admin_principal(
    GDEFCORE_Catalog * catalog, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief The public id of a role with @p name.
 *
 * @param out_id Receives the canonical id and a NUL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_role_id(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Labels granted to @p name.
 *
 * Free @p out_labels with gdefcore_access_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_role_grants(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    char *** out_labels, size_t * out_count);

/**
 * @brief Create a tenant role with no permissions.
 *
 * `anonymous` and `authenticated` are refused. @p out_id may be NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_role_create(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Copy the Editor template into a new tenant role.
 *
 * `Moderator` and `Usher` are refused. A second copy is a different role.
 * @p out_id may be NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_copy_template(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Delete a role. The seeded states are refused and nothing is written.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_delete_role(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len);

/**
 * @brief Declare a permission. It is granted to nobody, admin included.
 *
 * A second declare of the same label leaves the first in place.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_declare(
    GDEFCORE_Catalog * catalog, const GDEFCORE_Permission * permission);

/**
 * @brief Grant a declared permission to a role. High risk.
 *
 * Granting to `authenticated` requires
 * ::GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED. Granting to `anonymous` requires
 * ::GDEFCORE_ACCESS_CONFIRM_ANONYMOUS. Any other confirmation writes nothing.
 * A grant to any other role confirms with `core.role`.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_grant(GDEFCORE_Catalog * catalog,
    const char * role, size_t role_len, const char * label, size_t label_len,
    const char * confirmation, size_t confirmation_len);

/**
 * @brief Create a principal with no roles. @p out_id receives the public id.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_principal_create(
    GDEFCORE_Catalog * catalog, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Give @p principal the role @p role.
 *
 * The states `anonymous` and `authenticated` cannot be assigned.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_principal_add_role(
    GDEFCORE_Catalog * catalog, const char * principal, size_t principal_len,
    const char * role, size_t role_len);

/**
 * @brief Take @p role away from @p principal.
 *
 * The last principal who holds `admin` keeps it. Nothing is written.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_principal_remove_role(
    GDEFCORE_Catalog * catalog, const char * principal, size_t principal_len,
    const char * role, size_t role_len);

/**
 * @brief Remove a principal.
 *
 * The last principal who holds `admin` is kept. Nothing is written.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_principal_remove(
    GDEFCORE_Catalog * catalog, const char * principal, size_t principal_len);

/**
 * @brief Role names held by @p principal.
 *
 * Free @p out_roles with gdefcore_access_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_principal_roles(
    GDEFCORE_Catalog * catalog, const char * principal, size_t principal_len,
    char *** out_roles, size_t * out_count);

/**
 * @brief Read one field through the access filter.
 *
 * An id the principal may not see is ::GDEFCORE_ERR_INVALID, the same as an
 * id that was never created, and no field value is written. A field the
 * principal may not read is absent: success with a count of 0, not an empty
 * string. Free texts with gdefcore_values_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_read(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len,
    const char * lang, size_t lang_len, const char * field, size_t field_len,
    char *** out_texts, size_t ** out_lens, size_t * out_count);

/**
 * @brief List public ids the principal may see.
 *
 * @p out_count is the number of ids. Free @p out_ids with
 * gdefcore_access_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_list(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    char *** out_ids, size_t * out_count);

/**
 * @brief The render key for this request.
 *
 * The edition is empty. @p overlay NULL or `live` is the live overlay. A
 * module's compiled filter is keyed by the hash of @p module_bytes, not by
 * a name. Free @p out_key with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_render_key(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const char * overlay, size_t overlay_len, const uint8_t * module_bytes,
    size_t module_len, char ** out_key, size_t * out_len);

/**
 * @brief Whether a fragment for @p overlay may enter a shared cache.
 *
 * @return 1 for NULL, empty, or `live`. 0 for any other overlay.
 */
GDEFCORE_API int gdefcore_access_shared_cache(const char * overlay,
    size_t overlay_len);

/**
 * @brief Remember a module permission for the enable confirmation.
 *
 * Does not grant it. Apply grants it to admin when the confirmation matches.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_stage_module_permission(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len, const char * label, size_t label_len,
    const char * action, size_t action_len, int condition,
    const char * type_name, size_t type_name_len, const char * field,
    size_t field_len);

/** @brief Grant staged module permissions to admin. A changeset with none is success. */
GDEFCORE_API GDEFCORE_Result gdefcore_access_commit_staged(
    GDEFCORE_Changeset * changeset);

/** @brief Drop staged module permissions. NULL is ignored. */
GDEFCORE_API void gdefcore_access_clear_staged(GDEFCORE_Changeset * changeset);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_ACCESS_H */
