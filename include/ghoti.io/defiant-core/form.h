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
 * keyring's `form` purpose. A submit writes a draft and leaves what readers
 * see alone. An alias stays hidden until publish.
 *
 * A personal field (AD-19) is never stored as the caller's text. The plain
 * route, gdefcore_form_sign() and gdefcore_form_submit(), refuses a value for
 * one. The subject route, gdefcore_form_sign_subject() and
 * gdefcore_form_submit_subject(), binds the form to one subject and seals the
 * personal values under that subject's key as gdefcore_subject_save() does.
 * Every value in a form's tree is plaintext as the caller supplies it, so
 * an edit form for a personal field is filled from gdefcore_form_tree_for(),
 * which decrypts a personal value the principal may read (story S7), not
 * from gdefcore_form_tree(), which returns what is stored: ciphertext.
 * The token carries the values, sealed by the `form` key, and is returned to
 * the caller; the library keeps no copy.
 */

#ifndef GHOTI_IO_GDEFCORE_FORM_H
#define GHOTI_IO_GDEFCORE_FORM_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <ghoti.io/defiant-core/subject.h>
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
 * Current values come from the entity's draft when it has one, otherwise
 * from its newest revision, published or not. @p id NULL builds a tree with no values. @p out is not
 * written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_tree(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_len, const char * id, size_t id_len,
    const char * lang, size_t lang_len, GDEFCORE_Form ** out);

/**
 * @brief The tree of entity @p id as the request's principal may edit it
 * (story S7): gdefcore_form_tree()'s fields of its type, with the values of
 * the draft over the newest revision, filtered.
 *
 * An entity the principal may not update (gdefcore_access_can(),
 * ::GDEFCORE_ACTION_UPDATE) answers as one that is not there,
 * ::GDEFCORE_ERR_INVALID, and @p out is not written. A field the principal
 * may not read (its field-read grants, gdefcore_access_can_field()) is in the
 * tree with no value. A personal value of a field the principal may read is
 * decrypted after that check, with the catalog's subjects
 * (gdefcore_catalog_bind_subjects()): its plaintext, or
 * ::GDEFCORE_SUBJECT_ERASED, never its ciphertext; a catalog with no subjects
 * gives it no value. Each subject decrypted is recorded on @p request
 * (gdefcore_request_record_subject()). The values feed
 * gdefcore_form_sign_subject() as they are. Free @p out with
 * gdefcore_form_destroy(), which wipes them.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_tree_for(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len,
    const char * lang, size_t lang_len, GDEFCORE_Form ** out);

/**
 * @brief Sign @p values. Nothing is written to the catalog.
 *
 * @p alias NULL or zero length slugs the `title` value. No title value
 * means no alias. The caller-supplied alias is stored unchanged when the
 * token is later submitted. Free @p out_token with gdefcore_text_free().
 * A value that fails a constraint is an error and @p out_token is not written.
 * A value for a personal field is ::GDEFCORE_ERR_INVALID, because this token
 * has no subject to seal it for; see gdefcore_form_sign_subject().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_sign(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * form_id, size_t form_id_len,
    const char * target, size_t target_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count, const char * alias,
    size_t alias_len, char ** out_token, size_t * out_token_len);

/**
 * @brief Sign @p values for one @p subject.
 *
 * As gdefcore_form_sign(), and the token also carries @p subject, the public
 * id of the person the personal values belong to. The id is in what the AEAD
 * authenticates, as the session and the tenant are, so a token cannot be
 * moved to another subject. @p values for personal fields are plaintext.
 * Submit with gdefcore_form_submit_subject(). The subject is not looked up
 * here; submit refuses an unknown or erased one.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_sign_subject(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * session, size_t session_len, const char * form_id,
    size_t form_id_len, const char * target, size_t target_len,
    const char * lang, size_t lang_len, const GDEFCORE_Value * values,
    size_t value_count, const char * alias, size_t alias_len,
    const char * subject, size_t subject_len, char ** out_token,
    size_t * out_token_len);

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
 * The new token keeps the subject of @p token, if it has one. A value for a
 * personal field on a token with no subject is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_resign(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * token, size_t token_len,
    const GDEFCORE_Value * values, size_t value_count, char ** out_token,
    size_t * out_token_len);

/**
 * @brief Submit @p token. The values become the entity's draft (a draft is
 * never a revision, and readers do not see it); what is published is not
 * touched.
 *
 * A missing token, a bad tag, another session or another tenant writes
 * nothing. The token's base is the entity's version when it was signed
 * (gdefcore_entity_version(), which every write moves, a draft included): a
 * submit once the entity has moved, a second submit of one token among them,
 * writes nothing and sets @p out_conflict to 1 when it is not NULL. Other
 * errors set it to 0.
 *
 * A token that holds a value for a personal field is
 * ::GDEFCORE_ERR_INVALID and writes nothing, whether or not the token has a
 * subject: this route does not seal. Fields without a value, and every
 * non-personal field, are written as always.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_submit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * session,
    size_t session_len, const char * token, size_t token_len,
    int * out_conflict);

/**
 * @brief May the request do @p action to the entity this token is for?
 *
 * The question a signed-form path asks before it hands control to code (a
 * route, a button, a preview), answered by gdefcore_access_can() for **the
 * token's target**, which the token binds with the session, the principal
 * and the base version, so a body cannot steer it. @p claimed is the entity
 * id the request itself names (a route capture, a hidden field), or NULL; if
 * it is not the token's target the answer is no, because such a request is
 * not about one entity. The condition is evaluated on the entity as it is
 * stored (SPEC decision 8): no value in the token, and nothing the principal
 * typed, is read.
 *
 * A token that does not verify is the error gdefcore_form_check() gives. A
 * refusal, a target that does not exist and a target of another type all are
 * @p out_allowed 0 and ::GDEFCORE_OK. Nothing is written.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_authorize(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * session, size_t session_len, const char * token,
    size_t token_len, const char * claimed, size_t claimed_len,
    const char * action, size_t action_len, int * out_allowed);

/**
 * @brief The signed-form path for an update: gdefcore_form_authorize() for
 * the permission `update`, then gdefcore_form_submit().
 *
 * gdefcore_form_submit() itself asks nothing, as no library function does
 * (SPEC decision 7); this is the entry point a route's handler calls. The
 * question is asked first, of the entity as it is stored, before anything is
 * staged. A refusal is ::GDEFCORE_ERR_INVALID with @p out_allowed 0 and
 * nothing written; the refusal is the same whichever way the request was
 * wrong. @p claimed is as for gdefcore_form_authorize().
 *
 * @param out_allowed Required. 1 when the question was a yes.
 * @param out_conflict As for gdefcore_form_submit().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_submit_authorized(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * session, size_t session_len, const char * token,
    size_t token_len, const char * claimed, size_t claimed_len, int * out_allowed,
    int * out_conflict);

/**
 * @brief Submit @p token and seal its personal values for its subject.
 *
 * As gdefcore_form_submit(), for a token from gdefcore_form_sign_subject()
 * (or gdefcore_form_resign() of one). Each personal field's value is
 * encrypted with the subject's key exactly as gdefcore_subject_save() does,
 * the draft stores the ciphertext, and the blind-index row is recorded after
 * the draft is applied. Non-personal fields behave as in the plain route.
 * A personal field must be single-valued; a many field is refused.
 *
 * The token's subject must be the one each personal field's declaration names
 * (story S7): the entity's own subject, or the value its reference holds in
 * the draft (the form may set it); a value sealed for another is refused when
 * the draft is applied. A subject that is unknown or erased, a token with no
 * subject that holds a personal value, or any failure before the draft is
 * applied writes nothing and never falls back to plaintext. The draft and the blind-index row are
 * two commits in two stores, as in gdefcore_subject_save(): a failure of the
 * second leaves the sealed draft without its row, the error is returned, and
 * erasure still makes the draft unreadable. The row reflects the draft, so
 * until gdefcore_form_publish() the published text and the row can differ.
 * @p subjects must be the store of the same tenant as @p catalog.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_form_submit_subject(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * session, size_t session_len, const char * token,
    size_t token_len, GDEFCORE_Subjects * subjects, int * out_conflict);

/**
 * @brief Apply the entity's draft as its next revision, set the published
 * flag, and reveal the alias.
 *
 * A published path that is already taken gains a short random suffix. The
 * revision's author is whoever submitted the draft, and the entity's creator
 * stays whoever made it. A draft made from a revision that
 * is no longer the newest is a conflict and writes nothing. An entity that
 * was never saved and has no draft is ::GDEFCORE_ERR_INVALID.
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

/** A route is a page. Nothing is implied for a menu. */
#define GDEFCORE_ROUTE_PAGE 0
/** A route is a tab of its parent route (Drupal's "local task"). */
#define GDEFCORE_ROUTE_TAB 1
/** A route is an action link, such as "add". */
#define GDEFCORE_ROUTE_ACTION 2

/** Longest capture name in a pattern, in bytes. */
#define GDEFCORE_ROUTE_NAME_MAX 64
/** Most `:name` segments in one pattern. */
#define GDEFCORE_ROUTE_CAPTURE_MAX 16
/** Longest path pattern gdefcore_route_add_spec() takes, in bytes. */
#define GDEFCORE_ROUTE_PATH_MAX 2048
/** Longest title, in bytes. */
#define GDEFCORE_ROUTE_TITLE_MAX 256
/** Longest permission name, in bytes. */
#define GDEFCORE_ROUTE_PERMISSION_MAX 256

/**
 * @brief What a handler is called with.
 *
 * Begins with @ref size. Valid for the duration of the call only; a handler
 * that keeps a capture copies it. The matched values are reached through
 * gdefcore_route_call_capture(), never through ambient state.
 */
typedef struct GDEFCORE_Route_Call {
  size_t size;               ///< `sizeof(GDEFCORE_Route_Call)`.
  GDEFCORE_Request * request; ///< The request being dispatched.
  const char * machine;      ///< The machine name the route was registered under.
  size_t machine_len;        ///< Length of @ref machine.
  void * data;               ///< The route's data pointer.
  const void * internal;     ///< Private. Use the accessors.
  const char * entity_capture; ///< The route's @ref GDEFCORE_Route_Spec::entity_capture, or "".
  size_t entity_capture_len; ///< Length of @ref entity_capture.
} GDEFCORE_Route_Call;

/** @brief A handler that reads captures through its call. */
typedef void (*GDEFCORE_Route_Call_Fn)(const GDEFCORE_Route_Call * call);

/**
 * @brief The route permission check.
 *
 * Called by dispatch, for a route whose path has matched and that names a
 * permission, with the matched values available from @p call. Return non-zero
 * to allow. Zero makes the route not match: the request is answered exactly
 * as if the route did not exist (AD-11). The principal is the request's
 * (gdefcore_request_principal() on @p call->request). It runs before the
 * handler and must not set notes, a resolution or a status.
 */
typedef int (*GDEFCORE_Route_Check_Fn)(const GDEFCORE_Route_Call * call,
    const char * permission, size_t permission_len, void * data);

/**
 * @brief A route with a permission, a title, a kind and a parent.
 *
 * Begins with @ref size. Set exactly one of @ref fn and @ref call_fn.
 *
 * @ref permission names a permission by its action. When @ref entity_capture
 * names one of the pattern's `:name` captures, the permission is about the
 * entity whose public id that segment holds: the check
 * (gdefcore_access_route_check()) asks whether the principal holds it for
 * that entity, not for some entity of the type. With no entity capture the
 * question is the type-level one.
 */
typedef struct GDEFCORE_Route_Spec {
  size_t size;                ///< Must be `sizeof(GDEFCORE_Route_Spec)`.
  const char * machine;       ///< Unique machine name. Required.
  size_t machine_len;         ///< Length of @ref machine.
  const char * path;          ///< Pattern, `/a/:name/*/b`. Required.
  size_t path_len;            ///< Length of @ref path.
  int weight;                 ///< Lowest runs first.
  int after;                  ///< Non-zero: runs after another handler owns.
  GDEFCORE_Route_Fn fn;       ///< Handler without captures, or NULL.
  GDEFCORE_Route_Call_Fn call_fn; ///< Handler with captures, or NULL.
  void * data;                ///< Passed back to the handler.
  const char * permission;    ///< Permission name, or NULL for none.
  size_t permission_len;      ///< Length of @ref permission.
  const char * title;         ///< UTF-8 title for menus, or NULL.
  size_t title_len;           ///< Length of @ref title.
  int kind;                   ///< ::GDEFCORE_ROUTE_PAGE, _TAB or _ACTION.
  const char * parent;        ///< Parent machine name. Required for a tab.
  size_t parent_len;          ///< Length of @ref parent.
  int is_default;             ///< Non-zero: the default tab of @ref parent.
  const char * entity_capture; ///< Capture that holds an entity id, or NULL.
  size_t entity_capture_len;  ///< Length of @ref entity_capture.
} GDEFCORE_Route_Spec;

/**
 * @brief One route as the enumeration reports it.
 *
 * The text pointers are borrowed from the route table and stay valid until
 * the table is destroyed. Routes are never removed.
 */
typedef struct GDEFCORE_Route_Info {
  size_t size;                ///< `sizeof(GDEFCORE_Route_Info)`.
  const char * machine;       ///< Machine name.
  size_t machine_len;         ///< Length of @ref machine.
  const char * path;          ///< Path pattern as registered.
  size_t path_len;            ///< Length of @ref path.
  const char * title;         ///< Title, or "" when none.
  size_t title_len;           ///< Length of @ref title.
  const char * permission;    ///< Permission name, or "" when none.
  size_t permission_len;      ///< Length of @ref permission.
  int kind;                   ///< ::GDEFCORE_ROUTE_PAGE, _TAB or _ACTION.
  int is_default;             ///< Non-zero for the default tab.
  int weight;                 ///< The route's weight.
  const char * entity_capture; ///< Its entity capture, or "" when none.
  size_t entity_capture_len;  ///< Length of @ref entity_capture.
  const char * parent;        ///< The parent route of a tab, or "" for none.
  size_t parent_len;          ///< Length of @ref parent.
} GDEFCORE_Route_Info;

/**
 * @brief Register a route with named segments, a permission, a title, a kind
 * and a parent.
 *
 * A pattern segment `:name` matches exactly one segment and captures it under
 * `name`, which is `[a-z][a-z0-9_]*`, at most ::GDEFCORE_ROUTE_NAME_MAX bytes,
 * and unique in the pattern, with at most ::GDEFCORE_ROUTE_CAPTURE_MAX per
 * pattern. `*` still matches one segment and captures nothing. A named
 * segment scores as `*` does, so an explicit segment beats it.
 * (gdefcore_route_add() does not read `:`: its segment stays literal.)
 *
 * A tab names a parent that is already registered; a second default tab for
 * one parent, a tab without a parent, a parent on a non-tab, and a default
 * tab that captures a name its parent's pattern does not are errors. A
 * default tab also answers its parent's path, exactly (not as an ancestor),
 * and outranks the parent's own handlers there at equal weight.
 *
 * Every error leaves the table unchanged, is ::GDEFCORE_ERR_INVALID, and
 * when @p out_error is not NULL, names both routes involved. Free
 * @p out_error with gdefcore_routes_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_route_add_spec(GDEFCORE_Routes * routes,
    const GDEFCORE_Route_Spec * spec, char ** out_error,
    size_t * out_error_len);

/**
 * @brief Set the permission check. NULL removes it.
 *
 * A route that names a permission while no check is set never matches.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_set_check(GDEFCORE_Routes * routes,
    GDEFCORE_Route_Check_Fn fn, void * data);

/**
 * @brief The value @p name captured for this call.
 *
 * Returns 1 and sets @p out_value (borrowed, not NUL-terminated, valid for
 * the call) and @p out_len when the route's pattern has a segment `:name`.
 * Returns 0 otherwise, including for `*`. The value is the request segment
 * as received: percent-encoding is not decoded.
 */
GDEFCORE_API int gdefcore_route_call_capture(const GDEFCORE_Route_Call * call,
    const char * name, size_t name_len, const char ** out_value,
    size_t * out_len);

/**
 * @brief The tabs of @p parent that the request may use, for the page whose
 * call is @p page.
 *
 * As gdefcore_routes_tabs(), without the tabs the permission check refuses.
 * The check is the route table's own (gdefcore_routes_set_check()) and is
 * asked what dispatch would ask for that tab: its permission, and the entity
 * its @ref GDEFCORE_Route_Spec::entity_capture names, taken from the captures
 * of @p page (the call of the page the tabs are drawn on, whose pattern
 * should capture the same names). So a menu cannot show a tab that dispatch
 * would answer as not found, and cannot hide one it would serve. A tab that
 * names a permission while no check is set is not shown, as it never matches.
 * Free @p out with gdefcore_routes_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_tabs_visible(
    GDEFCORE_Routes * routes, const char * parent, size_t parent_len,
    const GDEFCORE_Route_Call * page, GDEFCORE_Route_Info ** out,
    size_t * out_count);

/**
 * @brief The tabs of the route @p parent, in weight order then machine name.
 *
 * @p out receives an array of @p out_count entries, to be freed with
 * gdefcore_routes_free(). An unknown parent, or one with no tabs, is success
 * with a count of 0 and @p out NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_tabs(GDEFCORE_Routes * routes,
    const char * parent, size_t parent_len, GDEFCORE_Route_Info ** out,
    size_t * out_count);


/**
 * @brief A request path matched against the route table. Opaque.
 *
 * It holds which routes the path reached, in the order dispatch would run
 * them, and the values their named segments took. It holds no request, so
 * the question "may this viewer follow that route?" is asked with a request
 * (gdefcore_routes_permits()) and one match serves any number of viewers.
 */
typedef struct GDEFCORE_Route_Match GDEFCORE_Route_Match;

/**
 * @brief A link the kernel itself places in a menu. Begins with @ref size.
 *
 * The fields are those of a module's link (GDEFCORE_Module_Link): the host
 * that owns a route table is the kernel's side of a deployment, and the pages
 * it serves are menu entries the way a module's are. @ref name is
 * `core.<name>` (AD-35).
 */
typedef struct GDEFCORE_Route_Link {
  size_t size;                ///< `sizeof(GDEFCORE_Route_Link)`.
  const char * name;          ///< Machine name `core.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * menu;          ///< Menu name, such as `admin`.
  size_t menu_len;            ///< Length of @ref menu.
  const char * label;         ///< UTF-8 label. Required.
  size_t label_len;           ///< Length of @ref label.
  const char * route;         ///< Target route machine name. Required.
  size_t route_len;           ///< Length of @ref route.
  int weight;                 ///< Lowest first.
  const char * parent;        ///< Parent link machine name, or NULL.
  size_t parent_len;          ///< Length of @ref parent.
  int kind;                   ///< ::GDEFCORE_ROUTE_PAGE, _TAB or _ACTION.
} GDEFCORE_Route_Link;

/**
 * @brief Match @p path against the table.
 *
 * The routes a path reaches are those dispatch would run for it
 * (gdefcore_form_resolve()), the permission check included: a route the
 * request may not follow is not in the match, exactly as it is not run. Of
 * those, the match keeps the ones whose pattern is the **longest** (a route
 * `/node/:id/edit` and not the `/node` it also passes through), in dispatch
 * order, and the values of every named segment those patterns capture. A
 * default tab answers its parent's path, so it is in the match at that path.
 * Nothing is run, written or recorded on @p request but what the permission
 * check itself records.
 *
 * @p out is a match with no routes when nothing matched, and is never NULL
 * on success. Free it with gdefcore_route_match_free().
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID (bad arguments, a path that
 *   does not start with `/`) or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_match(GDEFCORE_Routes * routes,
    GDEFCORE_Request * request, const char * path, size_t path_len,
    GDEFCORE_Route_Match ** out);

/** @brief Free a match. NULL is ignored. */
GDEFCORE_API void gdefcore_route_match_free(GDEFCORE_Route_Match * match);

/** @brief How many routes the match holds. A NULL match holds none. */
GDEFCORE_API size_t gdefcore_route_match_route_count(
    const GDEFCORE_Route_Match * match);

/**
 * @brief The machine name of route @p index of the match, in dispatch order.
 * The text is borrowed from the match. ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_route_match_route(
    const GDEFCORE_Route_Match * match, size_t index, const char ** out_machine,
    size_t * out_machine_len);

/** @brief How many distinct names the match captured. A NULL match, none. */
GDEFCORE_API size_t gdefcore_route_match_capture_count(
    const GDEFCORE_Route_Match * match);

/**
 * @brief Capture @p index of the match, in the order first seen. The texts are
 * borrowed from the match. The value is the segment as received. A name two
 * matched routes capture from different segments keeps the first route's.
 * ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_route_match_capture(
    const GDEFCORE_Route_Match * match, size_t index, const char ** out_name,
    size_t * out_name_len, const char ** out_value, size_t * out_value_len);

/**
 * @brief The route @p machine as the enumeration reports it.
 *
 * @p out->size must be `sizeof(GDEFCORE_Route_Info)`. The text pointers are
 * borrowed from the table. An unknown route is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_info(GDEFCORE_Routes * routes,
    const char * machine, size_t machine_len, GDEFCORE_Route_Info * out);

/**
 * @brief Every route, in the order they were registered.
 *
 * As gdefcore_routes_tabs(): free @p out with gdefcore_routes_free(). An empty
 * table is success with a count of 0 and @p out NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_list(GDEFCORE_Routes * routes,
    GDEFCORE_Route_Info ** out, size_t * out_count);

/**
 * @brief May the request follow route @p machine, for the values of @p match?
 *
 * It is the question dispatch asks of a route whose path matched, and it is
 * asked of the **route's own check** (gdefcore_routes_set_check()), with the
 * route's own permission and entity capture, and the value of each named
 * segment of the route's pattern taken from @p match. A menu, a tab or a
 * breadcrumb asks this and nothing else, so what a page shows cannot drift
 * from what dispatch serves.
 *
 * @p out_allowed is 1 for a route with no permission, and for one with a
 * permission whose check passes. It is 0 for a route whose pattern names a
 * segment @p match did not capture (there is no entity to ask about), for a
 * route that names a permission while no check is set (it never matches),
 * and for a check that says no. An unknown route is ::GDEFCORE_ERR_INVALID.
 * @p match may be NULL: it captures nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_permits(GDEFCORE_Routes * routes,
    GDEFCORE_Request * request, const char * machine, size_t machine_len,
    const GDEFCORE_Route_Match * match, int * out_allowed);

/**
 * @brief The path of route @p machine with the values of @p match put in.
 *
 * Each `:name` segment is replaced by the value @p match captured under that
 * name, as received. A default tab's path is its parent's, as that is where
 * it answers. A route whose pattern has a `*` segment (it captures nothing, so
 * there is nothing to put there) and a route with a name @p match did not
 * capture have no path: ::GDEFCORE_ERR_INVALID, and @p out is not written.
 * Free @p out with gdefcore_routes_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_href(GDEFCORE_Routes * routes,
    const char * machine, size_t machine_len, const GDEFCORE_Route_Match * match,
    char ** out, size_t * out_len);

/**
 * @brief Add a link the kernel places in a menu.
 *
 * The link is checked as a module's is: a name `core.<name>` of at most 128
 * bytes of a-z, 0-9, '.', '_' and '-'; a menu of 1 to 64 bytes of the same
 * set starting with a letter; a label of 1 to 256 bytes of UTF-8 text; a kind;
 * a target route this table has; and, when it names a parent, a parent link
 * already added to the same menu. A name twice is an error, as is a name that
 * a route of the table has (an entry's name is one name). Every error leaves
 * the table unchanged and is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_add_link(GDEFCORE_Routes * routes,
    const GDEFCORE_Route_Link * link);

/** @brief How many kernel links the table holds. */
GDEFCORE_API size_t gdefcore_routes_link_count(const GDEFCORE_Routes * routes);

/**
 * @brief Kernel link @p index, in the order added. The texts are borrowed from
 * the table and @p out->size must be `sizeof(GDEFCORE_Route_Link)`.
 * ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_routes_link_at(
    const GDEFCORE_Routes * routes, size_t index, GDEFCORE_Route_Link * out);

/** @brief Free bytes from the route functions that return them. NULL is ignored. */
GDEFCORE_API void gdefcore_routes_free(GDEFCORE_Routes * routes, void * bytes);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_FORM_H */
