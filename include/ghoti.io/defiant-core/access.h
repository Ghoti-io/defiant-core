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
#include <ghoti.io/defiant-core/form.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The action vocabulary. A permission names any action a module likes; these
 * are the ones the kernel and its entity paths ask about, spelled once. The
 * decision gdefcore_access_can() is asked with them, and the risk rating
 * knows their classes (read, edit, strong).
 *
 * - `create`: add an entity. Checked against the **container the path names**
 *   (a permission on the container's type, asked of the container), or at type
 *   level; a permission with a field limits what may be supplied, field by
 *   field (gdefcore_access_can_field()). Never a condition on the values
 *   being written.
 * - `read`: see an entity's newest revision while it is published. Needs the published flag.
 * - `update`: save a draft. Decided on the entity as stored, before the change.
 * - `publish`: apply the entity's draft, if it has one, and set the published
 *   flag; and take it away again (`unpublish` is the same permission).
 * - `delete`: clear the entity (it is unpublished and deleted; its revisions
 *   stay).
 * - `revisions.read`: view history and the draft, field by field.
 * - `revisions.revert`: write a new revision that copies an earlier one.
 *
 * There is no action that makes an older revision current without writing
 * one: the current revision is always the newest (access SPEC decision 13).
 */
/** Add an entity. */
#define GDEFCORE_ACTION_CREATE "create"
/** See an entity as readers see it. */
#define GDEFCORE_ACTION_READ "read"
/** Change an entity's content (saves a draft). */
#define GDEFCORE_ACTION_UPDATE "update"
/** Publish, and unpublish. */
#define GDEFCORE_ACTION_PUBLISH "publish"
/** Clear an entity. */
#define GDEFCORE_ACTION_DELETE "delete"
/** View the revisions of an entity, filtered field by field. */
#define GDEFCORE_ACTION_REVISIONS_READ "revisions.read"
/** Revert an entity to an earlier revision (appends a copy). */
#define GDEFCORE_ACTION_REVISIONS_REVERT "revisions.revert"

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
 *
 * The condition is either @ref condition (::GDEFCORE_ACCESS_ANY or
 * ::GDEFCORE_ACCESS_OWN) or, newer, @ref condition_text: an expression in the
 * language of condition.h, validated against @ref type_name when the
 * permission is declared and stored in its canonical form. Setting both is
 * ::GDEFCORE_ERR_INVALID, and so is setting neither. @ref size must be
 * `sizeof(GDEFCORE_Permission)`; any other size is ::GDEFCORE_ERR_INVALID.
 * @ref condition_text is NULL when the condition is @ref condition.
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
  const char * condition_text; ///< A condition expression (condition.h), or NULL.
  size_t condition_text_len;   ///< Length of @ref condition_text.
} GDEFCORE_Permission;

/** A grant whose breadth is narrow: the matrix rates it low. */
#define GDEFCORE_ACCESS_RISK_LOW 1
/** A grant that is broad on one thing, or reaches a single field. */
#define GDEFCORE_ACCESS_RISK_MEDIUM 2
/** A grant whose breadth is unbounded or cannot be judged. */
#define GDEFCORE_ACCESS_RISK_HIGH 3

/**
 * @brief A declared permission, as gdefcore_access_permission_info() reports
 * it. Begins with @ref size. The texts are NUL-terminated.
 */
typedef struct GDEFCORE_Access_Permission {
  size_t size;              ///< Must be `sizeof(GDEFCORE_Access_Permission)`.
  char module[161];         ///< The module that declared it (`core` for the kernel).
  char action[65];          ///< Its action.
  char type_name[161];      ///< Its entity type.
  char field[65];           ///< Its field; empty when it covers the entity.
} GDEFCORE_Access_Permission;

/**
 * @brief One row of the access matrix. Begins with @ref size.
 *
 * Every text is plain, not escaped for any output, and may hold what a module
 * author wrote: a page must escape it. @ref source reads `role <name>` or
 * `module <name>`. A role grant made with a condition of its own shows the
 * permission's label, not the stored name of the derived permission. A
 * module's access callback is a row of its module, marked @ref callback.
 */
typedef struct GDEFCORE_Access_Matrix_Row {
  size_t size;                ///< `sizeof(GDEFCORE_Access_Matrix_Row)`.
  const char * source;        ///< `role <name>` or `module <name>`.
  size_t source_len;          ///< Length of @ref source.
  int from_module;            ///< Non-zero: a module's grant, held by no role.
  const char * permission;    ///< The permission's label.
  size_t permission_len;      ///< Length of @ref permission.
  const char * action;        ///< Its action; empty when the permission is not declared.
  size_t action_len;          ///< Length of @ref action.
  const char * type_name;     ///< Entity type.
  size_t type_name_len;       ///< Length of @ref type_name.
  const char * field;         ///< Field, or "".
  size_t field_len;           ///< Length of @ref field.
  const char * condition;     ///< The condition, in its canonical text.
  size_t condition_len;       ///< Length of @ref condition.
  const char * explain;       ///< The condition in plain English.
  size_t explain_len;         ///< Length of @ref explain.
  int risk;                   ///< ::GDEFCORE_ACCESS_RISK_LOW, _MEDIUM or _HIGH.
  /** Non-zero: the grant is a module's access callback (module.h), decided
   * per entity by the module's code. @ref condition reads `callback
   * <module>.<name>`, @ref explain says so in words, and @ref risk is
   * ::GDEFCORE_ACCESS_RISK_HIGH: its breadth cannot be judged. */
  int callback;
} GDEFCORE_Access_Matrix_Row;

/** A revision's field: the values were returned. */
#define GDEFCORE_REVISION_SHOWN 1
/** A revision's field the principal may not read, or that has no value in that
 * revision: nothing is returned, and the two cannot be told apart. */
#define GDEFCORE_REVISION_ABSENT 2
/** A revision's personal field. The stored ciphertext is never returned. */
#define GDEFCORE_REVISION_PERSONAL 3
/** A revision's personal field of a subject whose key was destroyed: the
 * value is gone, and the marker ::GDEFCORE_SUBJECT_ERASED is returned. */
#define GDEFCORE_REVISION_ERASED 4

/** The most rows one page of a list returns. A larger limit is this. */
#define GDEFCORE_ACCESS_LIST_MAX_LIMIT 200

/** List flag: decide entity by entity, in memory, and not as a storage query.
 * The answer is the same by contract; this is the reference the compiled list
 * is held to, and what a principal can ask for to see the two agree. */
#define GDEFCORE_ACCESS_LIST_EVALUATE 1

/**
 * @brief A filtered list. Begins with @ref size.
 *
 * A filter or a sort that names a field the principal may not read, or a
 * field the type does not have, is refused and returns no rows. So is one
 * that names a field an access callback governs, by anyone, whoever may read
 * it (gdefcore_access_field_governed()), and a condition that names one.
 *
 * A list asks no access callback anything: what is listed and counted is
 * decided by conditions alone. The page it returns is kept on the request as
 * the next batch (gdefcore_request_set_batch()), so that reading those
 * entities asks a callback about all of them in one call.
 *
 * What is listed is the published entities of the type for which some read
 * grant of the principal holds (AD-11), narrowed by the filter and by
 * @ref condition. @ref size must be `sizeof(GDEFCORE_Access_List)`; any other
 * size is ::GDEFCORE_ERR_INVALID. A member a list does not use is zero or
 * NULL (no offset, no limit, no second sort).
 *
 * Order is the sort keys, each the first value of its field in @ref lang
 * (none before any value), compared as bytes, ascending unless asked for the
 * reverse, and then creation order. So a page is always a slice of one order.
 * Paging is @ref offset and @ref limit over that order; a @ref limit above
 * ::GDEFCORE_ACCESS_LIST_MAX_LIMIT is clamped to it and 0 is every row.
 *
 * Counted and paged by the store when the list can be compiled into a storage
 * query (plan.h), and entity by entity otherwise: when a field it names has a
 * field-level read grant, when a filter or sort names a personal field, when
 * the compiled form is over a cap of the query form, or when asked for with
 * ::GDEFCORE_ACCESS_LIST_EVALUATE. The two give the same rows in the same
 * order and the same total.
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
  uint64_t offset;              ///< Matches skipped before the first returned.
  uint64_t limit;               ///< Rows returned; 0 is every row.
  const char * sort2_field;     ///< A second sort key, or NULL.
  size_t sort2_field_len;       ///< Length of @ref sort2_field.
  int sort_descending;          ///< Non-zero reverses the first key.
  int sort2_descending;         ///< Non-zero reverses the second key.
  const char * condition;       ///< A condition (condition.h) ANDed with the
                                ///< access filter, or NULL.
  size_t condition_len;         ///< Length of @ref condition.
  int flags;                    ///< ::GDEFCORE_ACCESS_LIST_EVALUATE or 0.
} GDEFCORE_Access_List;

/**
 * @brief One field of one recorded revision, as a principal may see it.
 *
 * The read behind a revision view (history, the draft, an earlier
 * revision). Two checks, in this order, both on the entity **as it is stored**
 * (its newest revision and its creator), never on the revision being viewed
 * and never on anything supplied by the caller:
 *
 * 1. `revisions.read` (::GDEFCORE_ACTION_REVISIONS_READ) by gdefcore_access_can().
 *    It does not need the published flag, because a revision view shows drafts
 *    that readers do not see; it is rated at least an edit (see
 *    gdefcore_access_grant_risk()).
 * 2. The field-read grants of the field, as a live read applies them.
 *
 * No permission, an unknown entity, an unknown field, a sequence that is not a
 * revision of the entity and an id that is not an id are one answer,
 * ::GDEFCORE_ERR_INVALID. A field the principal may not read, and a field with
 * no value in that revision, are @p out_status ::GDEFCORE_REVISION_ABSENT with
 * no texts; they cannot be told apart. A personal field's stored ciphertext is
 * never shown (story S7): once the field filter allowed it, its value of that
 * revision is decrypted with the catalog's subjects
 * (gdefcore_catalog_bind_subjects()), ::GDEFCORE_REVISION_SHOWN and the
 * plaintext, or ::GDEFCORE_REVISION_ERASED and ::GDEFCORE_SUBJECT_ERASED for
 * an erased subject, and the subject is recorded on @p request
 * (gdefcore_request_record_subject()); with no subjects bound it is
 * ::GDEFCORE_REVISION_PERSONAL with no texts
 * (gdefcore_subject_revision_marker() recovers an erased subject's marker).
 * Otherwise ::GDEFCORE_REVISION_SHOWN and the texts, to be freed with
 * gdefcore_values_free().
 *
 * @param seq A recorded revision sequence of the entity.
 * @param lang The language, e.g. `en`. Required.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_revision_values(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request, const char * id,
    size_t id_len, uint64_t seq, const char * lang, size_t lang_len,
    const char * field, size_t field_len, int * out_status, char *** out_texts,
    size_t ** out_lens, size_t * out_count);

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
 * @brief Take a grant away from a role.
 *
 * @p label is the grant as the role holds it (gdefcore_access_role_grants()):
 * the permission's label, or, for a grant made with a condition of its own
 * (gdefcore_access_grant_when()), the stored name that grant carries. The role
 * keeps its history, as for every change of a role: a new revision holds the
 * grants that are left. No confirmation is asked, because nothing is widened.
 * A grant the role does not hold writes nothing and is ::GDEFCORE_OK. The
 * `admin` role is refused (::GDEFCORE_ERR_INVALID): it holds every permission
 * by construction. An unknown role is ::GDEFCORE_ERR_INVALID.
 *
 * What a person could do only through the grant is gone from the next
 * decision, and from the next render key (the config epoch moves), so nothing
 * cached for them outlives it (story A7).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_revoke(GDEFCORE_Catalog * catalog,
    const char * role, size_t role_len, const char * label, size_t label_len);

/**
 * @brief Grant a declared permission to a role, under a condition of its own.
 *
 * As gdefcore_access_grant(), and the same confirmations. The role holds the
 * permission only where @p condition_text holds as well as the condition the
 * permission was declared with (`any` and `own` are conditions): a grant can
 * narrow a permission and never widen it. The text is validated against the
 * permission's type (condition.h) and refused, with nothing written, if it is
 * not valid. The grant is kept as a permission of its own (the label with a
 * suffix naming the condition), so the same condition granted twice is one
 * grant and a different condition is another; gdefcore_access_role_grants()
 * names it as stored, and the matrix shows the label as declared.
 *
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID (a bad confirmation, a
 *   condition that is not valid, an unknown role or permission), or
 *   ::GDEFCORE_ERR_LIMIT (the combined condition is past a limit of
 *   condition.h).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_grant_when(
    GDEFCORE_Catalog * catalog, const char * role, size_t role_len,
    const char * label, size_t label_len, const char * condition_text,
    size_t condition_len, const char * confirmation, size_t confirmation_len);

/**
 * @brief The declaration behind a permission label.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when nothing declared it.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_permission_info(
    GDEFCORE_Catalog * catalog, const char * label, size_t label_len,
    GDEFCORE_Access_Permission * out);

/**
 * @brief How broad a grant is: a pure function of the grant.
 *
 * The action decides its class: `read`, `view`, `list`, `search`, `count`,
 * `export` are reads; `update`, `edit`, `create`, `save`, `draft`, `write`
 * are edits; `delete`, `remove`, `erase`, `publish`, `unpublish`, `admin`,
 * `grant`, `revert`, `restore`, `activate`, `install`, `enable`, `disable` are
 * strong. The words are taken from the action's dot-separated parts; an action
 * that has a strong word is strong, then one with an edit word is an edit, then
 * a read; an action with none of them is strong. A `revisions` part makes the
 * action at least an edit, whatever its other words say: `revisions.read`
 * shows drafts nobody published, so it is not rated as a read of what readers
 * see. The condition decides the rest.
 *
 * - **High**: the condition bounds nothing (it neither names a type, see
 *   gdefcore_condition_constrains_type(), nor reads the entity: `true`, or a
 *   condition about the time or the principal alone, matches every entity); or
 *   the grant reaches the anonymous state and is not a read; or the class is
 *   strong and the condition reads neither the entity nor the principal; or
 *   the condition cannot be parsed.
 * - **Low**: the condition reads both the entity and the principal (`own`);
 *   or the grant is a read and the condition reads the entity or the
 *   principal.
 * - **Medium**: everything else: any grant of a single field, an edit that no
 *   condition narrows, a read that none narrows.
 *
 * @param has_field Non-zero when the permission covers one field.
 * @param reaches_anonymous Non-zero for a grant that the anonymous state
 *   holds: a grant of the role `anonymous`, or a module grant whose condition
 *   does not read the principal.
 * @return ::GDEFCORE_ACCESS_RISK_LOW, _MEDIUM or _HIGH.
 */
GDEFCORE_API int gdefcore_access_grant_risk(const char * action,
    size_t action_len, int has_field, const char * condition_text,
    size_t condition_len, int reaches_anonymous);

/**
 * @brief gdefcore_access_grant_risk() that also knows the field the grant
 * covers, so it can tell a grant that lets its holder change the very field
 * its condition tests.
 *
 * A holder of `(= field.group "a")` for `update` can set `group` and so move
 * a post into the group that lets them edit it: the grant can widen itself.
 * The action must be one that changes content (`update`, `edit`, `save`,
 * `draft`, `write`, `revert`, `restore`, `activate`, including as the last part
 * of `revisions.revert`; not `create`, whose
 * condition is on the container the path names), and the condition must test
 * the grant's @p field, or, for an entity-wide grant (@p field_len 0), any
 * field. Such a grant is rated **one step higher** than gdefcore_access_grant_risk()
 * rates it (low to medium, medium to high, high stays), and the matrix says
 * so in the row's explanation.
 */
GDEFCORE_API int gdefcore_access_grant_risk_on(const char * action,
    size_t action_len, const char * field, size_t field_len,
    const char * condition_text, size_t condition_len, int reaches_anonymous);

/**
 * @brief Whether a grant of @p action covering @p field (empty for the whole
 * entity) lets its holder change a field its condition tests. The test
 * gdefcore_access_grant_risk_on() applies, on its own.
 */
GDEFCORE_API int gdefcore_access_grant_changes_own_field(const char * action,
    size_t action_len, const char * field, size_t field_len,
    const char * condition_text, size_t condition_len);

/** @brief `low`, `medium` or `high` for a rating; `unknown` otherwise. */
GDEFCORE_API const char * gdefcore_access_risk_name(int risk);

/**
 * @brief One grant gdefcore_access_hold_for_confirmation() took back, as the role
 * held it. Begins with @ref size. The texts are borrowed for the call.
 */
typedef struct GDEFCORE_Access_Held {
  size_t size;                  ///< `sizeof(GDEFCORE_Access_Held)`.
  const char * role;            ///< `anonymous` or `authenticated`.
  size_t role_len;              ///< Length of @ref role.
  const char * permission;      ///< The permission as the role held it: what
                                ///< gdefcore_access_grant() grants again.
  size_t permission_len;        ///< Length of @ref permission.
  const char * label;           ///< Its label as declared, as the matrix shows it.
  size_t label_len;             ///< Length of @ref label.
  const char * action;          ///< Its action.
  size_t action_len;            ///< Length of @ref action.
  const char * type_name;       ///< Its entity type.
  size_t type_name_len;         ///< Length of @ref type_name.
  const char * field;           ///< Its field, or "".
  size_t field_len;             ///< Length of @ref field.
  const char * condition;       ///< Its condition, canonical (condition.h).
  size_t condition_len;         ///< Length of @ref condition.
  int risk;                     ///< As the matrix rates it: ::GDEFCORE_ACCESS_RISK_LOW, _MEDIUM or _HIGH.
  const char * confirmation;    ///< The typed confirmation granting it asks
                                ///< for (::GDEFCORE_ACCESS_CONFIRM_ANONYMOUS or
                                ///< ::GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED).
  size_t confirmation_len;      ///< Length of @ref confirmation.
} GDEFCORE_Access_Held;

/** Told of each grant gdefcore_access_hold_for_confirmation() took back. A
 * failure stops the call and is returned. */
typedef GDEFCORE_Result (*GDEFCORE_Access_Held_Fn)(void * ctx,
    const GDEFCORE_Access_Held * held);

/**
 * @brief Take back, as the system, every grant that a role which is a state
 * (`anonymous`, `authenticated`) holds, telling @p fn what each was (AD-11,
 * AD-37; story S8).
 *
 * For data that came in without the admin edit (a restored snapshot,
 * gdefcore_subject_restore()): a grant to a state is what that edit asks a
 * typed confirmation for (gdefcore_access_grant()), so imported data never
 * applies one unconfirmed. Each is rated as the matrix rates it
 * (gdefcore_access_grant_risk_on()) and given to @p fn with the confirmation
 * that applies it again, through gdefcore_access_grant() with
 * GDEFCORE_Access_Held::permission. Every role entity named for a state is
 * visited, not only the first. A role with grants gets one new revision that
 * holds none, written before @p fn hears of them; its history keeps them.
 * Grants to any other role are left as they are.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_hold_for_confirmation(
    GDEFCORE_Catalog * catalog, GDEFCORE_Access_Held_Fn fn, void * ctx);

/**
 * @brief Every effective grant: role grants and the grants of enabled modules.
 *
 * Rows are sorted by source, permission, type, field and condition, bytewise,
 * so the order does not depend on the order roles were granted or modules
 * enabled in. Only an administrator may read it: the request's principal
 * (and its acting principal, if it names another) must hold `admin`.
 * Anyone else gets ::GDEFCORE_ERR_INVALID, the answer a page that does not
 * exist gets, and no row. A matrix that cannot be read whole is an error,
 * never a short one. Free @p out_rows with gdefcore_access_matrix_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_matrix(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Access_Matrix_Row ** out_rows,
    size_t * out_count);

/** @brief Free rows from gdefcore_access_matrix(). NULL is ignored. */
GDEFCORE_API void gdefcore_access_matrix_free(GDEFCORE_Catalog * catalog,
    GDEFCORE_Access_Matrix_Row * rows, size_t count);

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
 * string. The one exception is a field an access callback governs and opts in
 * to the locked indicator (module.h, ::GDEFCORE_CALLBACK_LOCKED; access SPEC
 * decision 4): when it is refused to the principal and has a value,
 * @p out_locked is 1, still with a count of 0 and no value. Otherwise
 * @p out_locked (which may be NULL) is 0, for a field shown, a field with no
 * value and a field hidden alike. A personal field the principal may read is decrypted then, and only
 * then (AD-19, story S7): each value's plaintext, or ::GDEFCORE_SUBJECT_ERASED
 * for an erased subject, opened with the catalog's subjects
 * (gdefcore_catalog_bind_subjects()) and its subject recorded on @p request
 * (gdefcore_request_record_subject()); never the ciphertext, and with no
 * subjects bound no value (a count of 0). Free texts with
 * gdefcore_values_free(), and wipe a personal one first.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_read(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len,
    const char * lang, size_t lang_len, const char * field, size_t field_len,
    char *** out_texts, size_t ** out_lens, size_t * out_count,
    int * out_locked);

/**
 * @brief Read one language of an entity as a tree through the access filter
 * (story S6d).
 *
 * The entity as gdefcore_access_read() sees it (published, a read grant
 * holds; else ::GDEFCORE_ERR_INVALID, the same as an id never created, and
 * nothing is written), as gdefcore_entity_tree() gives it, with the field
 * filter applied per field in every item: a field the principal may not read
 * is absent from the root and from every group item, and a group field the
 * principal may not read is absent with all its items. A field-read
 * permission names a field inside a group by its path (`lines.price`). A
 * personal value of a field the principal may read, at any depth, is
 * decrypted after that check, as by gdefcore_access_read(): its plaintext, or
 * ::GDEFCORE_SUBJECT_ERASED, never the stored text (story S7). A field that
 * gdefcore_access_read() would report locked is absent from its item with
 * its value, and marked there (gdefcore_tree_locked()). An entity with
 * no content in @p lang is
 * ::GDEFCORE_ERR_INVALID. Free @p out_tree with gdefcore_tree_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_tree(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len,
    const char * lang, size_t lang_len, GDEFCORE_Tree ** out_tree);

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
 * @brief gdefcore_access_list() and the number of entities the principal may
 * see that match, before the offset and the limit.
 *
 * The total counts only what is visible: a principal who may see 3 of 10
 * entities has a total of 3, whatever page it asks for. It is the number the
 * store counts for a compiled list and the number of rows the evaluation
 * kept for one that was not. Free @p out_ids with gdefcore_access_free().
 *
 * @param out_total Receives the total. Required.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_list_page(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const GDEFCORE_Access_List * query, char *** out_ids, size_t * out_count,
    uint64_t * out_total);

/**
 * @brief How many entities the principal may see that match @p query, whatever
 * its offset and limit. The count of gdefcore_access_list_page().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_count(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    uint64_t * out_total);

/**
 * @brief Whether the request's principal holds the permission called
 * @p permission.
 *
 * A permission is named by its action, for example
 * `core.template.edit.core.pane`. It is held when a role the principal has
 * (or the `authenticated` or `anonymous` state) was granted a declared
 * permission with that action. A name nobody declared is not held, and a
 * permission nobody was granted is not held by admin either. A failure to
 * read the grants is "not held".
 *
 * @return 1 when held, else 0.
 */
GDEFCORE_API int gdefcore_access_permits(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * permission, size_t permission_len);

/**
 * @brief Whether @p action decides row visibility (access SPEC "Three
 * scopes"): `read`, or an action with a dot-separated part `list`, `search`,
 * `count` or `export`. Such an action is decided by conditions alone; an
 * access callback may not grant it (module.h).
 */
GDEFCORE_API int gdefcore_access_row_action(const char * action, size_t len);

/**
 * @brief Whether an access callback of an enabled module governs @p field of
 * @p type (module.h): the field is then unusable in a filter, a sort or a
 * condition, by anyone, so that it cannot be probed through a list. 1 also
 * when it cannot be told. A catalog with no module host governs nothing.
 */
GDEFCORE_API int gdefcore_access_field_governed(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, const char * field, size_t field_len);

/** Fuel a gdefcore_access_can() that is answered from the request's memo costs. */
#define GDEFCORE_ACCESS_CAN_FUEL_HIT 1
/** Fuel a gdefcore_access_can() that has to be decided costs, memo hits included in the price. */
#define GDEFCORE_ACCESS_CAN_FUEL_MISS 4

/**
 * @brief May the request's principal do @p permission to this entity? The one
 * decision.
 *
 * Roles, then the grants of enabled modules, with conditions evaluated by the
 * one evaluator that read, list and permits use, and bounded by the
 * acting principal's ceiling (AD-12). The write path, the route check, the
 * tab list and the template editor all ask this, so a button, the page it
 * leads to and the write behind it cannot disagree.
 *
 * @p permission is named by its action, as for gdefcore_access_permits() (the
 * story that defined this calls it the permission label). @p type is the
 * entity type the permission is about. @p entity_id is the entity's public id
 * (NUL-terminated), or NULL.
 *
 * - **With an entity**: allowed when a grant for the permission, on that type
 *   and not on a field, holds on that entity. An entity that does not exist, a
 *   permission nobody declared, an entity of another type than @p type, and an
 *   entity on which no grant holds all answer the same way: @p out_allowed 0
 *   and ::GDEFCORE_OK. This does not require the entity to be readable by the
 *   principal as well; a site that does not want the existence of an entity
 *   told to someone who may change it but not read it grants the read too.
 *   The one exception is the permission `read` itself, which needs the
 *   published flag: an entity without it (a draft never published) is not
 *   readable, as for gdefcore_access_read().
 * - **With no entity** (type level): whether the principal could hold the
 *   permission for some entity of the type, as gdefcore_access_permits() asks.
 *   That is **not** safe for deciding an operation on a specific entity, and a
 *   page, tab or button must pass the entity.
 *
 * The answer is memoized on the request, keyed by principal, acting
 * principal, permission, type, entity and the entity's revision (the config
 * epoch at type level), so a write within the request makes the next question
 * a new one. The memo holds ::GDEFCORE_REQUEST_MEMO_MAX answers and then
 * starts over. A call marks the request principal-dependent
 * (gdefcore_request_mark_principal_dependent()) and records the entity and
 * revision it read (gdefcore_request_record_dependency()), which the render
 * key carries. A call costs ::GDEFCORE_ACCESS_CAN_FUEL_HIT of the request's
 * fuel, and ::GDEFCORE_ACCESS_CAN_FUEL_MISS in all when it is decided rather
 * than remembered; with too little fuel the answer is refused.
 *
 * A failure (a store read, an allocation, a condition that could not be
 * decided, no fuel) is @p out_allowed 0 and a result other than
 * ::GDEFCORE_OK, which the caller may log. It never grants, and is not
 * remembered. Bad arguments are ::GDEFCORE_ERR_INVALID.
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_LIMIT (no
 *   fuel), or the failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_can(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * permission, size_t permission_len,
    const char * type, size_t type_len, const char * entity_id,
    int * out_allowed);

/**
 * @brief Whether a permission that limits one field lets the principal act on
 * it.
 *
 * Some permissions are declared for one field of a type (the `field` of
 * ::GDEFCORE_Permission). A field that no declared permission of @p action
 * limits is not limited by this question, and the answer is 1: the entity or
 * the container decides. A field that one does limit needs a grant of that
 * permission that holds, and this is 0 without one.
 *
 * With @p entity_id the grant's condition is evaluated on that entity as it
 * is stored. With NULL (a create: there is no stored entity) a grant holds
 * when its permission is not about one entity, or when its condition could
 * apply to something; no value that is being written is ever consulted
 * (SPEC decision 8). An entity that does not exist, or is of another type, is
 * 0. Bad arguments are ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_can_field(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request, const char * action,
    size_t action_len, const char * type, size_t type_len, const char * entity_id,
    const char * field, size_t field_len, int * out_allowed);

/**
 * @brief May the principal create an entity of @p type, supplying these fields?
 *
 * Create has no stored entity, so no condition is evaluated on what is about
 * to be written. It is checked against **the container the path names**: a
 * route such as `/group/:id/new` captures the container's id, and the handler
 * passes that capture (never a value from the form) as @p container. Then the
 * question is ::GDEFCORE_ACTION_CREATE of the container's type, on the container
 * as stored, as gdefcore_access_can() answers it. With @p container NULL it is
 * a type-level grant of `create` on @p type itself. In either case each name in
 * @p fields is then asked of gdefcore_access_can_field(): a field that a
 * `create` permission limits needs its own grant, and the rest are free.
 *
 * A refusal is @p out_allowed 0 and ::GDEFCORE_OK, as for gdefcore_access_can();
 * a container that does not exist is the same refusal.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_can_create(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const char * container, size_t container_len, const char * type,
    size_t type_len, const char * const * fields, const size_t * field_lens,
    size_t nfields, int * out_allowed);

/**
 * @brief The ready-made route check, for gdefcore_routes_set_check().
 *
 * Pass the catalog as the check's data. A route with no
 * @ref GDEFCORE_Route_Spec::entity_capture asks the type-level question
 * (gdefcore_access_permits()). One with a capture asks gdefcore_access_can()
 * for the entity the captured segment names, on that entity's own type; a
 * segment that is not an id, or names no entity, is a no. A no makes the route
 * not match, which dispatch answers as a route that does not exist.
 *
 * @return Non-zero to allow.
 */
GDEFCORE_API int gdefcore_access_route_check(const GDEFCORE_Route_Call * call,
    const char * permission, size_t permission_len, void * data);

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

/**
 * @brief Remember a module's grant for the enable confirmation.
 *
 * Adds one line to the changeset's confirmation that says, in words, what the
 * grant does and how broad it is, so that applying the enable means having
 * been shown it. The condition is parsed again here and must be valid for
 * @p type_name. This writes nothing: the grant takes effect through the
 * module being enabled, and ends when it is disabled.
 * @param action The permission's action (for the rating).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_stage_module_grant(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len, const char * label, size_t label_len,
    const char * action, size_t action_len, const char * type_name,
    size_t type_name_len, const char * field, size_t field_len,
    const char * condition_text, size_t condition_len);

/**
 * @brief Remember a module's access callback for the enable confirmation.
 *
 * Adds the line `Module <m> decides <permission> per entity with its
 * callback <name> (<scope> scope, high risk): its breadth cannot be judged.`,
 * so that applying the enable means having been shown it. Writes nothing.
 * @param scope ::GDEFCORE_CALLBACK_FIELD or ::GDEFCORE_CALLBACK_OPERATION.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_access_stage_module_callback(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len, const char * name, size_t name_len, int scope,
    const char * label, size_t label_len, const char * action,
    size_t action_len, const char * type_name, size_t type_name_len,
    const char * field, size_t field_len);

/** @brief Grant staged module permissions to admin. A changeset with none is success. */
GDEFCORE_API GDEFCORE_Result gdefcore_access_commit_staged(
    GDEFCORE_Changeset * changeset);

/** @brief Drop staged module permissions. NULL is ignored. */
GDEFCORE_API void gdefcore_access_clear_staged(GDEFCORE_Changeset * changeset);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_ACCESS_H */
