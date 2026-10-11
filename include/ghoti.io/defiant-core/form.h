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
 * @file form.h
 * @brief Abstract forms, signed tokens, drafts and path routes.
 * @stability free
 *
 * One subsystem. A form is a tree of field names, flags, constraints and
 * values. It is not HTML. The token is AES-256-GCM under the tenant
 * keyring's `form` purpose. A draft save leaves the published projection
 * alone. An alias stays hidden until publish.
 */

#ifndef GHOTI_IO_GDEFCORE_FORM_H
#define GHOTI_IO_GDEFCORE_FORM_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A form expires after this many seconds, and not later than its session. */
#define GDEFCORE_FORM_LIFETIME ((uint64_t)24 * 60 * 60)

/** An abstract form tree. Opaque. Not HTML. */
typedef struct GDEFCORE_Form GDEFCORE_Form;

/** A segment trie of path handlers. Opaque. */
typedef struct GDEFCORE_Routes GDEFCORE_Routes;

/**
 * @brief A path handler.
 *
 * It may set notes on @p request and fall through, or set the resolution
 * and own the request. @p machine is the name it was registered under.
 */
typedef void (*GDEFCORE_Route_Fn)(GDEFCORE_Request * request,
    const char * machine, size_t machine_len, void * data);

/** @brief Free a form tree. NULL is ignored. */
GDEFCORE_API void gdefcore_form_destroy(GDEFCORE_Form * form);

/** @brief How many fields the tree lists. */
GDEFCORE_API size_t gdefcore_form_field_count(const GDEFCORE_Form * form);

/**
 * @brief One field. Pointers are borrowed from @p form until it is destroyed.
 *
 * @p out_required is non-zero when the field is required. @p out_texts may
 * be NULL when the field has no current value; the count is then 0.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_field(const GDEFCORE_Form * form,
    size_t index, const char ** out_name, size_t * out_name_len,
    int * out_required, int * out_many, int * out_personal,
    size_t * out_min_len, size_t * out_max_len, int * out_has_range,
    int64_t * out_range_min, int64_t * out_range_max, const char ** out_pattern,
    size_t * out_pattern_len, const char * const ** out_texts,
    const size_t ** out_lens, size_t * out_count);

/**
 * @brief Build the tree for @p type_name.
 *
 * Current values come from the draft projection when it exists, otherwise
 * the published one. @p id NULL builds a tree with no values. @p out is not
 * written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_tree(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_len, const char * id, size_t id_len,
    const char * lang, size_t lang_len, GDEFCORE_Form ** out);

/**
 * @brief Sign @p values. Nothing is written to the catalog.
 *
 * @p alias NULL or zero length slugs the `title` value. No title value
 * means no alias. The caller-supplied alias is stored unchanged when the
 * token is later submitted. Free @p out_token with gdefcore_text_free().
 * A value that fails a constraint is an error and @p out_token is not written.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_sign(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * form_id, size_t form_id_len,
    const char * target, size_t target_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count, const char * alias,
    size_t alias_len, char ** out_token, size_t * out_token_len);

/**
 * @brief Verify @p token. Nothing is written.
 *
 * @p out_expiry receives the token expiry when it is not NULL. A bad tag,
 * another session, another tenant, or an expired token is an error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_check(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * token, size_t token_len,
    uint64_t * out_expiry);

/**
 * @brief Check @p token and @p values and return a new token.
 *
 * The entity is not written. A value that fails a constraint is an error
 * and @p out_token is not written. Free @p out_token with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_resign(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * token, size_t token_len,
    const GDEFCORE_Value * values, size_t value_count, char ** out_token,
    size_t * out_token_len);

/**
 * @brief Submit @p token. A draft is appended. The published row is not.
 *
 * A missing token, a bad tag, another session or another tenant writes
 * nothing. A second submit whose base revision is no longer current writes
 * nothing and sets @p out_conflict to 1 when it is not NULL. Other errors
 * set it to 0.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_submit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * token, size_t token_len,
    int * out_conflict);

/**
 * @brief Copy the draft onto the published projection and reveal the alias.
 *
 * A published path that is already taken gains a short random suffix.
 * An entity with no draft writes nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_publish(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len);

/**
 * @brief The alias stored for @p id, including one that is not yet public.
 *
 * Free @p out_path with gdefcore_text_free(). No alias is
 * ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_alias(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_path, size_t * out_len);

/**
 * @brief Resolve @p path to a public id or a handler's machine name.
 *
 * An alias does not resolve until its entity is published, and it does not
 * resolve for a request that may not read that entity. Both failures are
 * ::GDEFCORE_ERR_INVALID, the same as an unknown path. Free @p out with
 * gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_resolve(GDEFCORE_Routes * routes,
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request, const char * path,
    size_t path_len, char ** out, size_t * out_len);

/** @brief An empty route table. */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_create(
    const GDEFCORE_Allocator * allocator, GDEFCORE_Routes ** out);

/** @brief Free a route table. NULL is ignored. */
GDEFCORE_API void gdefcore_routes_destroy(GDEFCORE_Routes * routes);

/**
 * @brief Register a handler.
 *
 * Two handlers may share @p path. The same @p machine twice is an error,
 * nothing is added, and @p out_error names both. Free @p out_error with
 * gdefcore_routes_free(). @p after is non-zero when the handler runs after
 * another handler has taken ownership.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_route_add(GDEFCORE_Routes * routes,
    const char * machine, size_t machine_len, const char * path,
    size_t path_len, int weight, int after, GDEFCORE_Route_Fn fn, void * data,
    char ** out_error, size_t * out_error_len);

/** @brief Free bytes from gdefcore_route_add(). NULL is ignored. */
GDEFCORE_API void gdefcore_routes_free(GDEFCORE_Routes * routes, void * bytes);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_FORM_H */
