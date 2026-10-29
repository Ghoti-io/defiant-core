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
 * @file module.h
 * @brief Hook bus and module host. Native libraries and guest tables.
 * @stability free
 *
 * One subsystem. A manifest names the module, the modules it requires or
 * enhances, and the hooks it subscribes to. The host looks up one symbol,
 * `gdefcore_module_manifest`. Module code does not search the process for
 * symbols. A guest is the same entry, handed over as a function pointer.
 * `lang-wasm` later fills that table. This header does not parse bytecode.
 */

#ifndef GHOTI_IO_GDEFCORE_MODULE_H
#define GHOTI_IO_GDEFCORE_MODULE_H

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

/** Event: every subscriber is told. The fire has no result value. */
#define GDEFCORE_HOOK_EVENT 1
/** Alter: subscribers share one value, in sorted order. */
#define GDEFCORE_HOOK_ALTER 2
/** Decision: allow, deny, or no opinion. Any deny wins. */
#define GDEFCORE_HOOK_DECISION 3

/** The subscriber has no opinion. */
#define GDEFCORE_DECISION_NONE 0
/** The subscriber allows the operation. */
#define GDEFCORE_DECISION_ALLOW 1
/** The subscriber denies the operation. */
#define GDEFCORE_DECISION_DENY 2

/** Refuse to enable when the named module is absent. */
#define GDEFCORE_REL_REQUIRES 1
/** Enable anyway when the named module is not installed. */
#define GDEFCORE_REL_ENHANCES 2

/**
 * The only value of the native-install flag that opens a library.
 * Any other value leaves the library unopened.
 */
#define GDEFCORE_MODULE_TRUST_FULL 1

/** Write-path hook names. Apply fires the ones that match the operation. */
#define GDEFCORE_HOOK_PRESAVE "presave"
#define GDEFCORE_HOOK_VALIDATE "validate"
#define GDEFCORE_HOOK_SAVE "save"
#define GDEFCORE_HOOK_DELETE "delete"
#define GDEFCORE_HOOK_REVISION "revision"
#define GDEFCORE_HOOK_AFTER_COMMIT "after-commit"

/** The module host. Opaque. */
typedef struct GDEFCORE_Host GDEFCORE_Host;

/** The shared value of an alter hook. Opaque. */
typedef struct GDEFCORE_Alter GDEFCORE_Alter;

/**
 * @brief What a subscriber may report. Begins with @ref size.
 *
 * The host sets @ref size to `sizeof(GDEFCORE_Hook_Out)` and zeroes the rest
 * before the call. A subscriber leaves @ref size as it is: a call that returns
 * with any other size is ::GDEFCORE_ERR_INVALID, and the error names both
 * sizes. @ref access set by a subscriber that did not declare itself
 * access-relevant is refused.
 */
typedef struct GDEFCORE_Hook_Out {
  size_t size;   ///< Set by the host to `sizeof(GDEFCORE_Hook_Out)`; leave it.
  int decision;  ///< ::GDEFCORE_DECISION_ALLOW, DENY, or NONE.
  int access;    ///< Non-zero when this call contributes an access result.
} GDEFCORE_Hook_Out;

/**
 * @brief Argument block for a write-path hook. Begins with @ref size.
 *
 * The request is a separate argument of the subscriber. @ref size is
 * `sizeof(GDEFCORE_Write_Hook)`; gdefcore_module_fire_write() refuses any other
 * with ::GDEFCORE_ERR_INVALID, and the error names both sizes.
 */
typedef struct GDEFCORE_Write_Hook {
  size_t size;                 ///< Must be `sizeof(GDEFCORE_Write_Hook)`.
  const char * entity_id;      ///< Public id, or NULL.
  size_t entity_id_len;        ///< Length of @ref entity_id.
  const char * type_name;      ///< Entity type, or NULL.
  size_t type_name_len;        ///< Length of @ref type_name.
  uint64_t base_seq;           ///< Sequence the save was based on.
} GDEFCORE_Write_Hook;

/**
 * @brief One subscriber.
 *
 * @p args begins with `size_t size` when it is not NULL. @p alter is NULL
 * unless the hook is an alter. @p out is never NULL; its @c size is set by
 * the host.
 */
typedef GDEFCORE_Result (*GDEFCORE_Hook_Fn)(GDEFCORE_Request * request,
    const void * args, GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out,
    void * user);

/**
 * @brief One relationship. Begins with @ref size.
 *
 * @ref size must be `sizeof(GDEFCORE_Module_Rel)`; the install of a manifest
 * with any other is ::GDEFCORE_ERR_INVALID, and the error names both sizes.
 */
typedef struct GDEFCORE_Module_Rel {
  size_t size;         ///< `sizeof(GDEFCORE_Module_Rel)` for this build.
  int kind;            ///< ::GDEFCORE_REL_REQUIRES or ::GDEFCORE_REL_ENHANCES.
  const char * name;   ///< The other module. Lowercase, borrowed.
  size_t name_len;     ///< Length of @ref name.
} GDEFCORE_Module_Rel;

/**
 * @brief One subscription. Begins with @ref size.
 *
 * @ref before and @ref after name modules. A larger @ref weight runs later.
 * Equal weights run in ascending module-name order, compared as raw bytes.
 * Registration order does not decide.
 */
typedef struct GDEFCORE_Module_Sub {
  size_t size;            ///< `sizeof(GDEFCORE_Module_Sub)` for this build.
  const char * hook;      ///< Hook name. Borrowed.
  size_t hook_len;        ///< Length of @ref hook.
  int kind;               ///< Event, alter, or decision.
  int weight;             ///< Tie break. Larger runs later.
  int access_relevant;    ///< Non-zero: a failure fails the call.
  const char * before;    ///< Run before this module. NULL if none.
  size_t before_len;      ///< Length of @ref before.
  const char * after;     ///< Run after this module. NULL if none.
  size_t after_len;       ///< Length of @ref after.
  GDEFCORE_Hook_Fn fn;    ///< The subscriber. Required.
  void * user;            ///< Passed back to @ref fn. May be NULL.
} GDEFCORE_Module_Sub;

/**
 * @brief A named versioned function table. Begins with @ref size.
 *
 * Lookup returns @ref table or NULL. The host does not call `dlsym` for this.
 */
typedef struct GDEFCORE_Module_Service {
  size_t size;           ///< `sizeof(GDEFCORE_Module_Service)` for this build.
  const char * name;     ///< Service name. Borrowed.
  size_t name_len;       ///< Length of @ref name.
  uint32_t version;      ///< Exact version. A different version is NULL.
  const void * table;    ///< The table. NULL is an empty service.
} GDEFCORE_Module_Service;

/**
 * @brief A permission the module declares. Begins with @ref size.
 *
 * Enabling the module does not grant it. The condition is 1 for any entity
 * of @ref type_name, or 2 for the principal's own. @ref field NULL covers
 * the entity.
 */
typedef struct GDEFCORE_Module_Perm {
  size_t size;              ///< `sizeof(GDEFCORE_Module_Perm)` for this build.
  const char * label;       ///< Plain-language label. Borrowed.
  size_t label_len;         ///< Length of @ref label.
  const char * action;      ///< Action name. Borrowed.
  size_t action_len;        ///< Length of @ref action.
  int condition;            ///< 1 any, or 2 own.
  const char * type_name;   ///< Entity type. Borrowed.
  size_t type_name_len;     ///< Length of @ref type_name.
  const char * field;       ///< Field, or NULL.
  size_t field_len;         ///< Length of @ref field.
} GDEFCORE_Module_Perm;

/**
 * @brief A grant the module declares. Begins with @ref size.
 *
 * While the module is enabled, every principal whose request meets
 * @ref condition holds the permission called @ref permission, whether or not
 * any role grants it. Nothing denies: a grant only adds (AD-10, AD-11).
 *
 * @ref permission is the label of a permission the module declares in
 * @ref GDEFCORE_Module_Manifest::perms, or of a core permission (declared by
 * the module `core`). Granting another module's permission is refused when
 * the module is enabled, and the refusal names both modules. @ref type_name
 * must be the permission's type, and @ref field its field (empty for none).
 * @ref condition is a condition expression (condition.h) validated against
 * @ref type_name when the module is enabled; an unparseable or invalid one
 * refuses the enable and stages nothing. The condition stands on its own: it
 * is not narrowed by the integer condition the permission was declared with.
 * Because the grant is not held by a role, a condition that does not read the
 * principal also reaches the anonymous state; the matrix rates it so.
 */
typedef struct GDEFCORE_Module_Grant {
  size_t size;              ///< `sizeof(GDEFCORE_Module_Grant)` for this build.
  const char * permission;  ///< Label of the permission granted. Borrowed.
  size_t permission_len;    ///< Length of @ref permission.
  const char * type_name;   ///< The permission's entity type. Borrowed.
  size_t type_name_len;     ///< Length of @ref type_name.
  const char * field;       ///< The permission's field, or NULL.
  size_t field_len;         ///< Length of @ref field.
  const char * condition;   ///< Condition text. Borrowed.
  size_t condition_len;     ///< Length of @ref condition.
} GDEFCORE_Module_Grant;

/**
 * @brief One column of a relation. Begins with @ref size.
 *
 * @ref kind is ::GDEFCORE_RELATION_ENTITY, ::GDEFCORE_RELATION_TEXT or
 * ::GDEFCORE_RELATION_INTEGER. For an entity column, @ref type_name names the
 * type it refers to (a type that is defined when the module is enabled, or
 * one in the module's own namespace), or is empty for any type.
 */
typedef struct GDEFCORE_Module_Relation_Column {
  size_t size;              ///< `sizeof(GDEFCORE_Module_Relation_Column)`.
  const char * name;        ///< Column name: `[a-z][a-z0-9_]*`. Borrowed.
  size_t name_len;          ///< Length of @ref name.
  int kind;                 ///< One of the `GDEFCORE_RELATION_` kinds.
  const char * type_name;   ///< For an entity column, its type, or NULL.
  size_t type_name_len;     ///< Length of @ref type_name.
} GDEFCORE_Module_Relation_Column;

/**
 * @brief A relation the module declares. Begins with @ref size.
 *
 * A relation is a typed link between entities, in the module's own namespace
 * (`module.name`, AD-35), with one to ::GDEFCORE_RELATION_COLUMNS_MAX columns.
 * Its rows are stored as entities of a kernel type and written by the owning
 * module through gdefcore_relation_add(); a condition tests membership with
 * `(related "module.name" (operand ...))` (condition.h). The host reads a
 * relation as the system, only while the module is enabled, and only the
 * declared columns. Disabling the module takes the relation out of every
 * decision at once; its rows stay and come back with the module.
 */
typedef struct GDEFCORE_Module_Relation {
  size_t size;              ///< `sizeof(GDEFCORE_Module_Relation)`.
  const char * name;        ///< `module.name`. Borrowed.
  size_t name_len;          ///< Length of @ref name.
  const GDEFCORE_Module_Relation_Column * columns; ///< The columns, in order.
  size_t ncolumns;          ///< How many, 1 to 4.
} GDEFCORE_Module_Relation;

/**
 * @name Access callbacks (access SPEC CAP-A5)
 *
 * Some access answers cannot be data: "has this reader paid for this
 * article". A module registers a **callback** that grants a permission it may
 * grant (its own, or the kernel's; never another module's) for one of two
 * scopes:
 *
 * - ::GDEFCORE_CALLBACK_FIELD: may this principal read (or write) this field
 *   of this entity, on a row the principal can already see. The permission
 *   names the field.
 * - ::GDEFCORE_CALLBACK_OPERATION: may this principal perform this operation
 *   on this one entity (edit, delete, publish, show a tab). The permission is
 *   entity-wide, and is not a row action: `read`, or an action with a part
 *   `list`, `search`, `count` or `export`.
 *
 * ::GDEFCORE_CALLBACK_ROW (whether an entity is in a list, or counted) is
 * refused at install, and so is an operation callback on a row action at
 * enable: lists compile their filter into the storage query, and a per-row
 * callback would break paging and counts and open an oracle.
 *
 * A callback grants or has no opinion, never denies (AD-10): it is one more
 * grant, consulted only when no other grant of the permission holds. The host
 * asks it in process (deferred D1: never a remote call), and:
 *
 * - **batched**: one call answers a page of entities (up to
 *   ::GDEFCORE_CALLBACK_BATCH_MAX): the entities of the request's last list
 *   page (gdefcore_request_set_batch()) are asked about together;
 * - **memoized per request**: per (callback, principal, acting principal,
 *   entity, entity version), so a second read in the request asks nothing;
 * - **bounded**: each call has @ref GDEFCORE_Module_Callback::fuel units
 *   (gdefcore_callback_spend()) and @ref GDEFCORE_Module_Callback::timeout_ms
 *   (never past the request's deadline), and costs the request
 *   ::GDEFCORE_CALLBACK_REQUEST_FUEL;
 * - **fail closed**: an error returned (a trap), a malformed answer, a call
 *   that spent past its fuel, one that returned after its timeout, a request
 *   with no fuel left, and a callback asked from inside a callback each grant
 *   nothing, for every entity of the call, for the rest of the request; the
 *   failure is reported on the request (note `defiant.callback.failed`,
 *   `<module>.<name> <reason>`) and makes it uncacheable. It is not an error
 *   of the read or decision that asked;
 * - **cacheable as declared**: ::GDEFCORE_CALLBACK_CACHE_TOKEN (each answer
 *   gives a validity token, which enters the render key), _TTL (the key
 *   changes every @ref GDEFCORE_Module_Callback::ttl_seconds of request time),
 *   or _NONE (a request that consulted it is uncacheable,
 *   gdefcore_request_cacheable()).
 *
 * A field a field callback governs is unusable in a filter, a sort or a
 * condition (a list's or a grant's) by anyone: a list naming it is refused,
 * and a condition naming it is refused at validation and does not hold when
 * evaluated, so the field cannot be probed through a list
 * (gdefcore_access_field_governed()). With ::GDEFCORE_CALLBACK_LOCKED, a
 * principal the field is refused to is told that a value is there and not
 * what it is (gdefcore_access_read(), gdefcore_tree_locked()).
 *
 * Callbacks are shown in the access matrix as granted by the module and
 * evaluated per entity, and an enable that brings one is rated high.
 * @{
 */

/** Row scope: whether an entity is in a list. Refused. */
#define GDEFCORE_CALLBACK_ROW 1
/** Field scope: may the principal read or write this field of this entity. */
#define GDEFCORE_CALLBACK_FIELD 2
/** Operation scope: may the principal do this to this one entity. */
#define GDEFCORE_CALLBACK_OPERATION 3

/** A request that consulted the callback is not cached. */
#define GDEFCORE_CALLBACK_CACHE_NONE 0
/** Each answer carries a validity token, which the render key carries. */
#define GDEFCORE_CALLBACK_CACHE_TOKEN 1
/** An answer holds for a time: the render key changes every TTL. */
#define GDEFCORE_CALLBACK_CACHE_TTL 2

/** Flag: the governed field tells a refused principal it is LOCKED. */
#define GDEFCORE_CALLBACK_LOCKED 1

/** Most entities one call is asked about. */
#define GDEFCORE_CALLBACK_BATCH_MAX 200
/** Most fuel one call may be given. */
#define GDEFCORE_CALLBACK_FUEL_MAX ((uint64_t)1000000)
/** Longest timeout one call may be given, in milliseconds. */
#define GDEFCORE_CALLBACK_TIMEOUT_MAX_MS 1000
/** Longest time to live, in seconds. */
#define GDEFCORE_CALLBACK_TTL_MAX 86400
/** Longest validity token, in bytes (printable ASCII, no space). */
#define GDEFCORE_CALLBACK_TOKEN_MAX 64
/** Fuel of the request one call of a callback costs. */
#define GDEFCORE_CALLBACK_REQUEST_FUEL 8
/** The version of an access callback service table. */
#define GDEFCORE_MODULE_ACCESS_CALLBACK_VERSION 1

/** One call of a callback: its fuel and its clock. Opaque. */
typedef struct GDEFCORE_Callback_Call GDEFCORE_Callback_Call;

/**
 * @brief What a callback is asked. Begins with @ref size. Borrowed for the
 * call.
 */
typedef struct GDEFCORE_Callback_Question {
  size_t size;                ///< `sizeof(GDEFCORE_Callback_Question)`.
  const char * module;        ///< The registering module.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< The callback's name.
  size_t name_len;            ///< Length of @ref name.
  int scope;                  ///< ::GDEFCORE_CALLBACK_FIELD or _OPERATION.
  const char * permission;    ///< The permission's label.
  size_t permission_len;      ///< Length of @ref permission.
  const char * action;        ///< Its action.
  size_t action_len;          ///< Length of @ref action.
  const char * type_name;     ///< The entities' type.
  size_t type_name_len;       ///< Length of @ref type_name.
  const char * field;         ///< The field; "" for an operation.
  size_t field_len;           ///< Length of @ref field.
  const char * principal;     ///< The principal; NULL for the anonymous state.
  size_t principal_len;       ///< Length of @ref principal.
  const char * acting;        ///< An acting principal, or NULL.
  size_t acting_len;          ///< Length of @ref acting.
  const char * const * entities; ///< Canonical public ids, NUL-terminated.
  size_t count;               ///< How many, 1 to ::GDEFCORE_CALLBACK_BATCH_MAX.
} GDEFCORE_Callback_Question;

/**
 * @brief What a callback answers. Begins with @ref size. The host zeroes it.
 *
 * @ref granted has one slot per entity of the question, in order: 1 grants,
 * 0 has no opinion; anything else is a malformed answer. A callback declared
 * ::GDEFCORE_CALLBACK_CACHE_TOKEN sets @ref token (1 to
 * ::GDEFCORE_CALLBACK_TOKEN_MAX printable ASCII bytes, no space); one with no
 * token is malformed.
 */
typedef struct GDEFCORE_Callback_Answer {
  size_t size;                ///< `sizeof(GDEFCORE_Callback_Answer)`.
  int * granted;              ///< One slot per entity, zeroed.
  size_t count;               ///< Slots in @ref granted.
  char token[GDEFCORE_CALLBACK_TOKEN_MAX + 1]; ///< The validity token.
  size_t token_len;           ///< Its length.
} GDEFCORE_Callback_Answer;

/**
 * @brief A callback. Return ::GDEFCORE_OK with @p answer filled; any other
 * result is a trap and grants nothing. @p request is the request that asked:
 * a callback reads through the access filter as its principal, and a callback
 * asked again from inside one grants nothing.
 */
typedef GDEFCORE_Result (*GDEFCORE_Callback_Fn)(GDEFCORE_Callback_Call * call,
    GDEFCORE_Request * request, const GDEFCORE_Callback_Question * question,
    GDEFCORE_Callback_Answer * answer, void * user);

/**
 * @brief The table an access callback's service carries (version
 * ::GDEFCORE_MODULE_ACCESS_CALLBACK_VERSION). Begins with @ref size.
 */
typedef struct GDEFCORE_Module_Access_Callback {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Access_Callback)`.
  GDEFCORE_Callback_Fn fn;    ///< The callback. Required.
  void * user;                ///< Passed back to @ref fn.
} GDEFCORE_Module_Access_Callback;

/**
 * @brief A callback a module registers. Begins with @ref size.
 *
 * @ref name is `[a-z][a-z0-9_]*`, unique in the module, at most 64 bytes.
 * @ref permission, @ref type_name and @ref field name the permission it
 * grants, as for ::GDEFCORE_Module_Grant: a field callback's permission names
 * @ref field, an operation callback's names none. @ref service is a service
 * the module declares, at ::GDEFCORE_MODULE_ACCESS_CALLBACK_VERSION.
 * @ref fuel is 1 to ::GDEFCORE_CALLBACK_FUEL_MAX, @ref timeout_ms 1 to
 * ::GDEFCORE_CALLBACK_TIMEOUT_MAX_MS, @ref cache one of the
 * `GDEFCORE_CALLBACK_CACHE_` kinds, @ref ttl_seconds 1 to
 * ::GDEFCORE_CALLBACK_TTL_MAX for _TTL and 0 otherwise, and @ref flags 0 or,
 * for a field callback, ::GDEFCORE_CALLBACK_LOCKED. Anything else is refused
 * at install, with words.
 */
typedef struct GDEFCORE_Module_Callback {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Callback)`.
  const char * name;          ///< Its name in the module. Borrowed.
  size_t name_len;            ///< Length of @ref name.
  int scope;                  ///< ::GDEFCORE_CALLBACK_FIELD or _OPERATION.
  const char * permission;    ///< Label of the permission granted. Borrowed.
  size_t permission_len;      ///< Length of @ref permission.
  const char * type_name;     ///< The permission's type. Borrowed.
  size_t type_name_len;       ///< Length of @ref type_name.
  const char * field;         ///< The permission's field, or NULL.
  size_t field_len;           ///< Length of @ref field.
  const char * service;       ///< Name of the module's callback service.
  size_t service_len;         ///< Length of @ref service.
  uint64_t fuel;              ///< Fuel of one call.
  uint32_t timeout_ms;        ///< Timeout of one call.
  int cache;                  ///< A `GDEFCORE_CALLBACK_CACHE_` kind.
  uint32_t ttl_seconds;       ///< For ::GDEFCORE_CALLBACK_CACHE_TTL.
  int flags;                  ///< 0 or ::GDEFCORE_CALLBACK_LOCKED.
} GDEFCORE_Module_Callback;

/**
 * @brief Spend @p units of the call's fuel. ::GDEFCORE_ERR_LIMIT when there
 * is less left: the call is then over budget, and grants nothing whatever it
 * answers.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_callback_spend(
    GDEFCORE_Callback_Call * call, uint64_t units);

/**
 * @brief Whether the call has passed its timeout: what it answers now grants
 * nothing. A callback that loops checks this.
 */
GDEFCORE_API int gdefcore_callback_expired(const GDEFCORE_Callback_Call * call);

/** @} */

/** A contribution provider answers with text (also for `markup`). */
#define GDEFCORE_CONTRIBUTION_TEXT 1
/** A contribution provider answers with an integer. */
#define GDEFCORE_CONTRIBUTION_INTEGER 2
/** A contribution provider answers with a float. */
#define GDEFCORE_CONTRIBUTION_FLOAT 3

/**
 * @brief What a contribution provider answers. Begins with @ref size.
 *
 * The provider sets @ref kind and the member that kind names. The bytes of
 * @ref text are copied before the provider's caller returns, so a provider
 * may point at its own stack.
 */
typedef struct GDEFCORE_Contribution_Value {
  size_t size;        ///< Set by the caller of the provider.
  int kind;           ///< ::GDEFCORE_CONTRIBUTION_TEXT, INTEGER or FLOAT.
  const char * text;  ///< For TEXT. Valid UTF-8.
  size_t text_len;    ///< Length of @ref text.
  int64_t integer;    ///< For INTEGER.
  double real;        ///< For FLOAT.
} GDEFCORE_Contribution_Value;

/**
 * @brief A lazy provider of one contributed template variable.
 *
 * Called only when a template reaches the variable, with the request being
 * rendered, so it is principal-aware and reads through the access filter. A
 * result other than ::GDEFCORE_OK means "not available": the template sees
 * null. @p request may be NULL when the render has none; a provider that
 * needs a principal then answers not available.
 */
typedef GDEFCORE_Result (*GDEFCORE_Contribution_Fn)(GDEFCORE_Request * request,
    void * user, GDEFCORE_Contribution_Value * out);

/**
 * @name Declared tables
 *
 * A manifest can declare tables: routes, menu links, settings, template
 * variables, grants, relations and callbacks. A table a module does not use is
 * NULL with a count of 0, and every entry's @c size is `sizeof` of its struct
 * (any other size refuses the install, naming the entry and both sizes). The
 * host copies them when the module is installed, validates them when the module is enabled (the enable
 * changeset is refused, naming the entry and the module), and enumerates what
 * the enabled modules declared, in one total order: the modules in AD-10 order
 * (before and after relationships of their subscriptions, then module name),
 * then each table by machine name.
 * @{
 */

/** Longest machine name of a declared route, link or setting, in bytes. */
#define GDEFCORE_MODULE_DECL_NAME_MAX 128
/** Longest label of a link or a setting, in bytes. */
#define GDEFCORE_MODULE_DECL_LABEL_MAX 256
/** Longest description or default value, in bytes. */
#define GDEFCORE_MODULE_DECL_TEXT_MAX 1024
/** Most routes one manifest declares. */
#define GDEFCORE_MODULE_ROUTES_MAX 64
/** Most menu links one manifest declares. */
#define GDEFCORE_MODULE_LINKS_MAX 64
/** Most settings one manifest declares. */
#define GDEFCORE_MODULE_SETTINGS_MAX 64
/** Most template variables one manifest declares. */
#define GDEFCORE_MODULE_VARIABLES_MAX 32
/** Most grants one manifest declares. */
#define GDEFCORE_MODULE_GRANTS_MAX 16
/** Most relations one manifest declares. */
#define GDEFCORE_MODULE_RELATIONS_MAX 16
/** Most access callbacks one manifest registers. */
#define GDEFCORE_MODULE_CALLBACKS_MAX 16
/** Most contributors one manifest declares. */
#define GDEFCORE_MODULE_CONTRIBUTORS_MAX 32
/** Most widget types one manifest declares. */
#define GDEFCORE_MODULE_WIDGETS_MAX 32
/** Most columns one relation has. */
#define GDEFCORE_RELATION_COLUMNS_MAX 4
/** Longest name of a relation column, in bytes. */
#define GDEFCORE_RELATION_COLUMN_NAME_MAX 32

/** A relation column that holds an entity, by its public id. */
#define GDEFCORE_RELATION_ENTITY 1
/** A relation column that holds a text, compared byte for byte. */
#define GDEFCORE_RELATION_TEXT 2
/** A relation column that holds an integer (`-?[0-9]{1,18}`, no leading zero). */
#define GDEFCORE_RELATION_INTEGER 3

/** The version of a route handler service table. */
#define GDEFCORE_MODULE_ROUTE_HANDLER_VERSION 1
/** The version of a template variable provider service table. */
#define GDEFCORE_MODULE_VARIABLE_PROVIDER_VERSION 1
/** The version of a contributor service table. */
#define GDEFCORE_MODULE_CONTRIBUTOR_HANDLER_VERSION 1
/** The version of a widget provider service table. */
#define GDEFCORE_MODULE_WIDGET_PROVIDER_VERSION 1
/** Most variables one widget draw binds. */
#define GDEFCORE_WIDGET_BINDS_MAX 16
/** Longest value one widget variable carries, in bytes. */
#define GDEFCORE_WIDGET_VALUE_MAX 65536

/**
 * @brief The table a route's handler service carries. Begins with @ref size.
 *
 * A route names its handler by a service name its module also declares
 * (GDEFCORE_Module_Service, version ::GDEFCORE_MODULE_ROUTE_HANDLER_VERSION),
 * and that service's @c table points at one of these. A native module and a
 * guest declare it the same way. Dispatch calls @ref call_fn with the call
 * and, in the call, @ref data as the call's data pointer.
 */
typedef struct GDEFCORE_Module_Route_Handler {
  size_t size;                    ///< `sizeof(GDEFCORE_Module_Route_Handler)`.
  GDEFCORE_Route_Call_Fn call_fn; ///< The handler. Required.
  void * data;                    ///< The route's data pointer.
} GDEFCORE_Module_Route_Handler;

/**
 * @brief The table a template variable's provider service carries. Begins
 * with @ref size.
 *
 * The variable names its provider by a service name its module also declares
 * (version ::GDEFCORE_MODULE_VARIABLE_PROVIDER_VERSION). The provider is lazy
 * and is called as a contribution's is (GDEFCORE_Contribution_Fn).
 */
typedef struct GDEFCORE_Module_Variable_Provider {
  size_t size;                     ///< `sizeof(GDEFCORE_Module_Variable_Provider)`.
  GDEFCORE_Contribution_Fn provider; ///< The provider. Required.
  void * user;                     ///< Passed back to @ref provider.
} GDEFCORE_Module_Variable_Provider;

/**
 * @brief The table a contributor's service carries. Begins with @ref size.
 *
 * A contributor (GDEFCORE_Module_Contributor) names its function by a service
 * name its module also declares (version
 * ::GDEFCORE_MODULE_CONTRIBUTOR_HANDLER_VERSION).
 */
typedef struct GDEFCORE_Module_Contributor_Handler {
  size_t size;                    ///< `sizeof(GDEFCORE_Module_Contributor_Handler)`.
  GDEFCORE_Contributor_Fn fn;     ///< The contributor. Required.
  void * data;                    ///< Passed back in the call.
} GDEFCORE_Module_Contributor_Handler;

/**
 * @brief Where a widget provider binds the variables its template reads.
 * Opaque; valid for the provider's call.
 */
typedef struct GDEFCORE_Widget_Sink GDEFCORE_Widget_Sink;

/**
 * @brief The function that draws a module's widget.
 *
 * Called when a layout places the widget on a page, after the widget's
 * permission has been asked of the viewer (a widget whose permission the
 * viewer does not hold is not drawn and the provider is not called). It binds
 * the variables the widget's template kind declares, as text, with
 * gdefcore_widget_bind_text(); it reads through @p request, so it is
 * principal-aware and reads through the access filter. A result other than
 * ::GDEFCORE_OK draws nothing. @p target is whatever the placement carried
 * after the widget's name, or empty.
 */
typedef GDEFCORE_Result (*GDEFCORE_Widget_Fn)(GDEFCORE_Request * request,
    const char * target, size_t target_len, GDEFCORE_Widget_Sink * sink,
    void * user);

/**
 * @brief The table a widget's provider service carries. Begins with @ref size.
 */
typedef struct GDEFCORE_Module_Widget_Provider {
  size_t size;                    ///< `sizeof(GDEFCORE_Module_Widget_Provider)`.
  GDEFCORE_Widget_Fn fn;          ///< The provider. Required.
  void * user;                    ///< Passed back to @ref fn.
} GDEFCORE_Module_Widget_Provider;

/**
 * @brief Bind a text variable for the widget's template. The bytes are copied.
 *
 * ::GDEFCORE_ERR_LIMIT past ::GDEFCORE_WIDGET_BINDS_MAX variables or
 * ::GDEFCORE_WIDGET_VALUE_MAX bytes; ::GDEFCORE_ERR_INVALID for a NULL sink or
 * an empty name. A name the template kind does not declare is not seen by the
 * template (the contract is the kind's, not the provider's). Binding a name
 * again replaces it.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_widget_bind_text(GDEFCORE_Widget_Sink * sink,
    const char * name, size_t name_len, const char * text, size_t text_len);

/**
 * @brief A contributor a module declares. Begins with @ref size.
 *
 * A contributor is a handler in the route trie that offers and does not own
 * the request (GDEFCORE_Contributor_Spec). @ref name is `<module>.<name>`
 * (AD-35); @ref kind is what it contributes, such as
 * ::GDEFCORE_CONTRIBUTOR_LAYOUT, so a module's layout selector is one of
 * these. The handler is a service name the module also declares.
 */
typedef struct GDEFCORE_Module_Contributor {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Contributor)`.
  const char * name;          ///< Machine name `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * kind;          ///< What it contributes.
  size_t kind_len;            ///< Length of @ref kind.
  const char * path;          ///< Pattern, `/a/:name/*`.
  size_t path_len;            ///< Length of @ref path.
  int exact;                  ///< Non-zero: only a path that is the pattern.
  int weight;                 ///< Breaks a tie of specificity: lowest first.
  const char * handler;       ///< Name of the module's contributor service.
  size_t handler_len;         ///< Length of @ref handler.
} GDEFCORE_Module_Contributor;

/**
 * @brief A widget type a module declares. Begins with @ref size.
 *
 * A widget type is a template kind and the source of its variables. @ref name
 * is `<module>.<name>` (AD-35), so it never takes a built-in type's name. The
 * @ref kind names the template kind the widget is drawn with (a kind the site
 * or the module's starter data defines; the widget draws nothing while no
 * such kind exists). @ref template_name is the template drawn when a
 * placement names none; empty means the widget's own name. @ref permission,
 * when not empty, is a permission name (as a route's is): a viewer who does
 * not hold it is shown nothing and the provider is not called, so a widget
 * never shows what its source would not.
 */
typedef struct GDEFCORE_Module_Widget {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Widget)`.
  const char * name;          ///< Machine name `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * kind;          ///< The template kind it is drawn with.
  size_t kind_len;            ///< Length of @ref kind.
  const char * template_name; ///< The default template, or NULL.
  size_t template_len;        ///< Length of @ref template_name.
  const char * permission;    ///< The permission its source needs, or NULL.
  size_t permission_len;      ///< Length of @ref permission.
  const char * description;   ///< Plain words for the editor. May be NULL.
  size_t description_len;     ///< Length of @ref description.
  const char * provider;      ///< Name of the module's widget provider service.
  size_t provider_len;        ///< Length of @ref provider.
} GDEFCORE_Module_Widget;

/**
 * @brief A route a module declares. Begins with @ref size.
 *
 * The fields are those of GDEFCORE_Route_Spec, except that the handler is a
 * service name. @ref name is `<module>.<name>` (AD-35). A tab names its
 * @ref parent, which an enabled module declares, and a default tab is the
 * default of that parent. @ref admin marks a route the admin directory lists.
 */
typedef struct GDEFCORE_Module_Route {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Route)`.
  const char * name;          ///< Machine name `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * path;          ///< Pattern, `/a/:name/*/b`.
  size_t path_len;            ///< Length of @ref path.
  int weight;                 ///< Lowest runs first.
  int after;                  ///< Non-zero: runs after another handler owns.
  const char * permission;    ///< Permission name, or NULL for none.
  size_t permission_len;      ///< Length of @ref permission.
  const char * title;         ///< UTF-8 title for menus, or NULL.
  size_t title_len;           ///< Length of @ref title.
  int kind;                   ///< ::GDEFCORE_ROUTE_PAGE, _TAB or _ACTION.
  const char * parent;        ///< Parent route machine name, for a tab.
  size_t parent_len;          ///< Length of @ref parent.
  int is_default;             ///< Non-zero: the default tab of @ref parent.
  int admin;                  ///< Non-zero: an admin route.
  const char * handler;       ///< Name of the module's handler service.
  size_t handler_len;         ///< Length of @ref handler.
  const char * entity_capture; ///< Capture that holds an entity id, or NULL.
  size_t entity_capture_len;  ///< Length of @ref entity_capture.
} GDEFCORE_Module_Route;

/**
 * @brief A menu link a module declares. Begins with @ref size.
 *
 * The menu entity is not part of this: a link only says which menu it wants
 * to be in, what it is called and where it goes.
 */
typedef struct GDEFCORE_Module_Link {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Link)`.
  const char * name;          ///< Machine name `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * menu;          ///< Menu name, such as `main` or `admin`.
  size_t menu_len;            ///< Length of @ref menu.
  const char * label;         ///< UTF-8 label. Required.
  size_t label_len;           ///< Length of @ref label.
  const char * route;         ///< Target route machine name. Required.
  size_t route_len;           ///< Length of @ref route.
  int weight;                 ///< Lowest first.
  const char * parent;        ///< Parent link machine name, or NULL.
  size_t parent_len;          ///< Length of @ref parent.
  int kind;                   ///< ::GDEFCORE_ROUTE_PAGE, _TAB or _ACTION.
} GDEFCORE_Module_Link;

/**
 * @brief A setting a module declares. Begins with @ref size.
 *
 * Declaration only: values and the settings page are not part of this.
 * @ref type is `text`, `number` or `boolean`; @ref default_value is that
 * type's text (a decimal number, or `true` or `false`).
 */
typedef struct GDEFCORE_Module_Setting {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Setting)`.
  const char * name;          ///< Machine name `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * type;          ///< `text`, `number` or `boolean`.
  size_t type_len;            ///< Length of @ref type.
  const char * default_value; ///< Default, as text. May be empty.
  size_t default_len;         ///< Length of @ref default_value.
  const char * label;         ///< UTF-8 label. Required.
  size_t label_len;           ///< Length of @ref label.
  const char * description;   ///< Plain words. May be NULL.
  size_t description_len;     ///< Length of @ref description.
  int environment_local;      ///< Non-zero: never imported, never exported.
  const char * group;         ///< Group name for the settings page, or NULL.
  size_t group_len;           ///< Length of @ref group.
} GDEFCORE_Module_Setting;

/**
 * @brief A template variable a module declares. Begins with @ref size.
 *
 * What gdefcore_module_contribute() takes as code is declared here as data:
 * @ref name is `<module>.<name>` (a hyphen of the module spelled `_`),
 * @ref type is `text`, `markup` or `number`, and the provider is a service
 * (see GDEFCORE_Module_Variable_Provider). The enumeration reports it as a
 * GDEFCORE_Module_Contributed, and gdefcore_module_contributions() includes
 * it while the module is enabled.
 */
typedef struct GDEFCORE_Module_Variable {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Variable)`.
  const char * kind;          ///< Template kind it contributes to.
  size_t kind_len;            ///< Length of @ref kind.
  const char * name;          ///< `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * type;          ///< `text`, `markup` or `number`.
  size_t type_len;            ///< Length of @ref type.
  const char * description;   ///< Plain words for the editor. May be NULL.
  size_t description_len;     ///< Length of @ref description.
  const char * provider;      ///< Name of the module's provider service.
  size_t provider_len;        ///< Length of @ref provider.
  int principal_free;         ///< Non-zero: the answer ignores the principal.
} GDEFCORE_Module_Variable;

/** @} */

/**
 * @name Stored-data schema versions (AD-15)
 *
 * Every component that stores data, core itself and each module, has a
 * stored-data schema version: an integer, 1 for its first shape and one more
 * for each later one, never a semver (a module's release version, if it has
 * one, is another thing). Every revision, draft and record a component writes
 * carries the component's version at the time, in its schema stamp
 * (`<component>/<version>`, defiant-storage model.h), and history keeps it:
 * a revision written at 1 says so for ever.
 *
 * A component brings its *current* data forward by numbered steps, each from
 * one version to the next (::GDEFCORE_Module_Step); there are none back. A
 * step adds what the new shape needs, through changesets applied in the
 * migration's write (gdefcore_migration_apply()): new revisions in the new
 * shape, declarations, records. It never rewrites what was written, and
 * nothing it writes is stamped older than the step's target. What was written
 * at an older version is read through the component's read-time upcasters
 * (::GDEFCORE_Module_Upcaster), one per version whose shape changed, run from
 * the version a revision or draft was written at up to where the tenant's
 * current data stands (the installed version, once migrated; inside a step,
 * the version the step starts from).
 *
 * Per tenant, the record ::GDEFCORE_SCHEMA_TYPE of each component says where
 * its current data stands, and ::GDEFCORE_MIGRATION_TYPE records each step
 * applied. A live upgrade (a module installed at a version above the
 * tenant's) and a restore of older data (gdefcore_subject_restore()) run the
 * same steps through the same code, gdefcore_schema_migrate(). Until it has
 * run, the tenant is under maintenance: its writes and gdefcore_schema_status()
 * answer ::GDEFCORE_ERR_MAINTENANCE.
 * @{
 */

/** Core's own stored-data schema version: the shape of the records and
 * declarations core keeps for itself. */
#define GDEFCORE_SCHEMA_VERSION 1
/** The component name core stamps its own data with. */
#define GDEFCORE_SCHEMA_CORE "core"
/** Core's schema stamp, `core/<GDEFCORE_SCHEMA_VERSION>`. */
#define GDEFCORE_SCHEMA_CORE_STAMP "core/1"

/**
 * The record namespace of where a tenant's data stands: one record per
 * component whose data the tenant holds (`core`, and each module), keyed by
 * its name, whose text is the version its current data is at, in decimal.
 * Written with a component's first data, by an enable, and by a migration;
 * never deleted.
 */
#define GDEFCORE_SCHEMA_TYPE "core.schema"

/**
 * The record namespace of the tenant's migration table: one record per step
 * applied, keyed `<component>:<from>` (from in ten digits, so the keys sort
 * by it), whose text is `<from> <to>`. Written in the write that applies the
 * step; never rewritten.
 */
#define GDEFCORE_MIGRATION_TYPE "core.migration"

/** A migration in progress, handed to a step. Opaque. */
typedef struct GDEFCORE_Migration GDEFCORE_Migration;

/**
 * @brief One forward step: it brings the component's current data at
 * version @p from to @p from + 1, in the migration's write.
 */
typedef GDEFCORE_Result (*GDEFCORE_Step_Fn)(GDEFCORE_Migration * migration,
    void * user);

/** One forward step a module declares. Begins with @ref size. */
typedef struct GDEFCORE_Module_Step {
  size_t size;            ///< `sizeof(GDEFCORE_Module_Step)`.
  uint32_t from;          ///< The version it starts from, 1 or more.
  GDEFCORE_Step_Fn fn;    ///< The step. Required.
  void * user;            ///< Passed back to @ref fn. May be NULL.
} GDEFCORE_Module_Step;

/**
 * @brief A read-time upcaster: it turns one language's tree of entity type
 * @p type, written in the shape of version @p from, into the shape of
 * @p from + 1, in place. @p decl is the type's declaration as it is now: the
 * tree may be given values of any field it declares. Nothing is written.
 */
typedef GDEFCORE_Result (*GDEFCORE_Upcast_Fn)(const char * type,
    size_t type_len, const GDEFSTOR_Type * decl, GDEFSTOR_Tree * tree,
    void * user);

/** One upcaster a module declares. Begins with @ref size. */
typedef struct GDEFCORE_Module_Upcaster {
  size_t size;            ///< `sizeof(GDEFCORE_Module_Upcaster)`.
  uint32_t from;          ///< The version whose shape it reads, 1 or more.
  GDEFCORE_Upcast_Fn fn;  ///< The upcaster. Required.
  void * user;            ///< Passed back to @ref fn. May be NULL.
} GDEFCORE_Module_Upcaster;

/** @} */

/**
 * @brief What `gdefcore_module_manifest` returns. Begins with @ref size.
 *
 * @ref core_token is the namespace token the module was built against. The
 * host refuses a token that is not the running core's, and the error names
 * both.
 *
 * @ref schema_version is the version of the module's stored-data schema
 * (AD-15): what its data is written in now. It is required: 0 is refused at
 * install, in words. @ref steps and
 * @ref upcasters are its forward steps and its read-time upcasters (above),
 * each at most once per version, from 1 to @ref schema_version - 1; a version
 * may have neither (no data of its shape to bring forward, or none to read
 * differently).
 */
typedef struct GDEFCORE_Module_Manifest {
  size_t size;                              ///< `sizeof(GDEFCORE_Module_Manifest)`.
  const char * core_token;                  ///< Running token, borrowed.
  size_t core_token_len;                    ///< Length of @ref core_token.
  const char * name;                        ///< Machine name. Borrowed.
  size_t name_len;                          ///< Length of @ref name.
  const char * label;                       ///< Human label. May be NULL.
  size_t label_len;                         ///< Length of @ref label.
  const GDEFCORE_Module_Rel * rels;         ///< Relationships. May be NULL.
  size_t nrels;                             ///< How many relationships.
  const GDEFCORE_Module_Sub * subs;         ///< Subscriptions. May be NULL.
  size_t nsubs;                             ///< How many subscriptions.
  const GDEFCORE_Module_Service * services; ///< Optional tables. May be NULL.
  size_t nservices;                         ///< How many services.
  const GDEFCORE_Module_Perm * perms;       ///< Declared permissions. May be NULL.
  size_t nperms;                            ///< How many permissions.
  const GDEFCORE_Module_Route * routes;     ///< Declared routes. May be NULL.
  size_t nroutes;                           ///< How many routes.
  const GDEFCORE_Module_Link * links;       ///< Declared menu links. May be NULL.
  size_t nlinks;                            ///< How many links.
  const GDEFCORE_Module_Setting * settings; ///< Declared settings. May be NULL.
  size_t nsettings;                         ///< How many settings.
  const GDEFCORE_Module_Variable * variables; ///< Declared template variables.
  size_t nvariables;                        ///< How many variables.
  const GDEFCORE_Module_Grant * grants;     ///< Declared grants. May be NULL.
  size_t ngrants;                           ///< How many grants.
  const GDEFCORE_Module_Relation * relations; ///< Declared relations. May be NULL.
  size_t nrelations;                        ///< How many relations.
  uint32_t schema_version;                  ///< Stored-data schema version, 1 or more.
  const GDEFCORE_Module_Step * steps;       ///< Forward steps. May be NULL.
  size_t nsteps;                            ///< How many steps.
  const GDEFCORE_Module_Upcaster * upcasters; ///< Read-time upcasters. May be NULL.
  size_t nupcasters;                        ///< How many upcasters.
  const GDEFCORE_Module_Callback * callbacks; ///< Access callbacks. May be NULL.
  size_t ncallbacks;                        ///< How many callbacks.
  const GDEFCORE_Module_Contributor * contributors; ///< Contributors. May be NULL.
  size_t ncontributors;                     ///< How many contributors.
  const GDEFCORE_Module_Widget * widgets;   ///< Widget types. May be NULL.
  size_t nwidgets;                          ///< How many widget types.
} GDEFCORE_Module_Manifest;

/**
 * The record namespace of a tenant's enabled modules (story S6b): one empty
 * record per module, keyed by its name. Where each one's data stands is
 * ::GDEFCORE_SCHEMA_TYPE's, which a disable leaves. A snapshot carries both
 * with the rest of the tenant's records (AD-23).
 */
#define GDEFCORE_MODULE_ENABLED_TYPE "core.module.enabled"

/** The entry a native module exports and a guest hands to the host. */
typedef const GDEFCORE_Module_Manifest * (*GDEFCORE_Module_Entry)(void);

/**
 * @brief Open a host on @p store. The store is borrowed.
 *
 * Installed native modules are read back. A module whose entered record is
 * still set is quarantined: it is not called.
 *
 * @param store The port. Required.
 * @param allocator NULL uses the default.
 * @param out_host Receives the host on success.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_host_open(GDEFSTOR_Store * store,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Host ** out_host);

/** @brief Close libraries and free the host. NULL is ignored. */
GDEFCORE_API void gdefcore_host_destroy(GDEFCORE_Host * host);

/**
 * @brief Install a native library.
 *
 * @p full_trust must be ::GDEFCORE_MODULE_TRUST_FULL. Any other value
 * returns ::GDEFCORE_ERR_INVALID and does not open @p path. The host
 * resolves `gdefcore_module_manifest` and nothing else.
 *
 * @param host The host.
 * @param path Filesystem path of the library. Required.
 * @param full_trust ::GDEFCORE_MODULE_TRUST_FULL, or the library stays shut.
 * @return ::GDEFCORE_OK or an error. Nothing is kept on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_install_native(
    GDEFCORE_Host * host, const char * path, int full_trust);

/**
 * @brief Install a guest by its entry. No full-trust flag.
 *
 * @p entry is the same function a native module exports. The host does not
 * open a library.
 *
 * @param host The host.
 * @param entry Required.
 * @return ::GDEFCORE_OK or an error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_install_guest(
    GDEFCORE_Host * host, GDEFCORE_Module_Entry entry);

/**
 * @brief Stage an enable. Apply is what commits it.
 *
 * Enabling is high risk. The module must already be installed. A native
 * module is installed by the operator; this call does not install one.
 *
 * The changeset's typed confirmation names what the module brings: a line for
 * each permission, each grant (rated), each access callback (rated high), and,
 * for a module whose field callbacks decide a field that a stored grant's
 * condition names, a line for each grant that would hold nothing from then on
 * (gdefcore_access_stage_module_suspensions()). An enable confirmed without
 * those lines enables nothing.
 *
 * @param host The host.
 * @param changeset The changeset. Required.
 * @param name Module name.
 * @param name_len Its length.
 * @return ::GDEFCORE_OK or an error. A refusal stages nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_enable(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len);

/**
 * @brief Stage a disable. Apply is what commits it. High risk.
 *
 * @param host The host.
 * @param changeset The changeset.
 * @param name Module name.
 * @param name_len Its length.
 * @return ::GDEFCORE_OK or an error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_disable(GDEFCORE_Host * host,
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len);

/**
 * @brief The stored-data schema version of installed component @p name: a
 * module's manifest ::GDEFCORE_Module_Manifest::schema_version, or for
 * `core`, ::GDEFCORE_SCHEMA_VERSION.
 *
 * A quarantined native module answers the version its install recorded.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when no module of that
 *   name is installed (a NULL @p host has none, and still has core).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_schema(const GDEFCORE_Host * host,
    const char * name, size_t name_len, uint32_t * out_version);

/**
 * @brief The forward step component @p name declares from version @p from,
 * if any. Core has none at ::GDEFCORE_SCHEMA_VERSION 1.
 *
 * @param out_fn Receives the step, or NULL when there is none (a gap).
 * @param out_user Receives its user pointer. May be NULL.
 * @return ::GDEFCORE_OK (with or without a step), or ::GDEFCORE_ERR_INVALID
 *   for a component that is not installed. A quarantined native module is
 *   never called: it has no step here.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_step(const GDEFCORE_Host * host,
    const char * name, size_t name_len, uint32_t from,
    GDEFCORE_Step_Fn * out_fn, void ** out_user);

/**
 * @brief The read-time upcaster component @p name declares for the shape of
 * version @p from, if any, as gdefcore_module_step(). Core has none.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_upcaster(
    const GDEFCORE_Host * host, const char * name, size_t name_len,
    uint32_t from, GDEFCORE_Upcast_Fn * out_fn, void ** out_user);

/** @return How many read-time upcasters installed module @p name declares
 * (0 for core, and for a module not installed). */
GDEFCORE_API size_t gdefcore_module_upcaster_count(const GDEFCORE_Host * host,
    const char * name, size_t name_len);

/**
 * @brief Whether a tenant's stored data stands where the components
 * installed here write it (AD-15): ::GDEFCORE_OK when it does, or when it
 * holds none of a component; ::GDEFCORE_ERR_MAINTENANCE when a component's
 * data is at an older version and waits for gdefcore_schema_migrate() (a
 * request for the tenant gets a maintenance response); ::GDEFCORE_ERR_UNSUPPORTED
 * when a component's data is newer than the one installed, or its module is
 * not installed; ::GDEFCORE_ERR_CORRUPT for a ::GDEFCORE_SCHEMA_TYPE record
 * that is not a version. Reads the last commit; writes nothing.
 *
 * @param host The installed modules. NULL: core only.
 * @param out_reason NULL, or receives the answer in plain words, naming the
 *   component and both versions (NULL on ::GDEFCORE_OK). Free it with
 *   gdefcore_schema_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_schema_status(GDEFCORE_Host * host,
    GDEFSTOR_Store * store, const uint8_t * tenant, size_t tenant_len,
    char ** out_reason, size_t * out_reason_len);

/**
 * @brief Bring a tenant's stored data forward to the versions installed
 * here: the one migration path, for a live upgrade and for a restore alike.
 *
 * For core and then each module whose data the tenant holds (by name), from
 * the version its ::GDEFCORE_SCHEMA_TYPE record says to the installed one,
 * every step in turn, each called with a migration whose catalog is the
 * tenant's: a step stages a changeset on it and applies it with
 * gdefcore_migration_apply(), into the step's write. That write also records
 * the step in ::GDEFCORE_MIGRATION_TYPE and the version it reaches in
 * ::GDEFCORE_SCHEMA_TYPE, and commits only when the step succeeded: a step
 * and the version it brings the data to commit together or not at all. Each
 * step has a write of its own because the next one reads what it wrote (the
 * port reads the last commit), so a step that fails leaves the tenant at the
 * last version reached, recorded, and still under maintenance. A revision a
 * step writes is stamped with the step's target version and dated
 * @p now_ms.
 *
 * Everything is checked before anything is written. Refused, in words naming
 * the component and both versions, with nothing written: data at a version
 * for which a step is missing (::GDEFCORE_ERR_UNSUPPORTED), data newer than
 * the installed component (::GDEFCORE_ERR_UNSUPPORTED), data of a module
 * not installed (::GDEFCORE_ERR_UNSUPPORTED). A step that fails aborts the
 * write (its result). A tenant already current writes nothing.
 *
 * @param out_migrated Receives how many steps were applied. May be NULL.
 * @param out_reason As gdefcore_schema_status(); on success, NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_schema_migrate(GDEFCORE_Host * host,
    GDEFSTOR_Store * store, const uint8_t * tenant, size_t tenant_len,
    int64_t now_ms, size_t * out_migrated, char ** out_reason,
    size_t * out_reason_len);

/** @brief Free a reason gdefcore_schema_status() or gdefcore_schema_migrate()
 * gave. NULL is ignored. */
GDEFCORE_API void gdefcore_schema_text_free(char * text);

/** @brief The tenant's catalog a step stages its changesets on. */
GDEFCORE_API GDEFCORE_Catalog * gdefcore_migration_catalog(
    GDEFCORE_Migration * migration);

/** @brief The step's component, its starting version and its target. */
GDEFCORE_API void gdefcore_migration_step_of(
    const GDEFCORE_Migration * migration, const char ** out_component,
    size_t * out_component_len, uint32_t * out_from, uint32_t * out_to);

/** @brief When the migration is dated: what each revision it writes says. */
GDEFCORE_API int64_t gdefcore_migration_time(
    const GDEFCORE_Migration * migration);

/**
 * @brief Apply @p changeset, staged on gdefcore_migration_catalog(), in the
 * migration's write: its declarations, saves, drafts and reverts, stamped
 * with the step's target version, with no confirmation (the operator who runs
 * the migration is its authority) and no hook (a step is the component's own
 * code, and nothing has committed). It reads the last commit, as every
 * staging does: a step applies one changeset, or several that do not build
 * on each other. A changeset that touches a module's enablement is refused.
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID (a changeset of another
 *   catalog, or one applied already), or the apply's error, which fails the
 *   step and so the migration.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_migration_apply(
    GDEFCORE_Migration * migration, GDEFCORE_Changeset * changeset);

/**
 * @brief Whether @p name is enabled for the request's tenant.
 *
 * A quarantined module is off. @p out_enabled receives 0 or 1.
 *
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_enabled(GDEFCORE_Host * host,
    GDEFCORE_Request * request, const char * name, size_t name_len,
    int * out_enabled);

/**
 * @brief The enhances sentence, or NULL when there is none.
 *
 * The text is `Module {name} enhances {target}, which is not installed.`
 * Valid until the next successful enable or until the host is destroyed.
 *
 * @param out_len Receives the length. May be NULL.
 */
GDEFCORE_API const char * gdefcore_module_notice(const GDEFCORE_Host * host,
    size_t * out_len);

/**
 * @brief The last host error, or NULL. Not a result string.
 *
 * A namespace mismatch names both tokens. A cycle names both modules.
 * Valid until the next host call that sets an error.
 *
 * @param out_len Receives the length. May be NULL.
 */
GDEFCORE_API const char * gdefcore_module_error(const GDEFCORE_Host * host,
    size_t * out_len);

/**
 * @brief Set the entered record and leave it set.
 *
 * The next host open quarantines the module. The host sets this around a
 * native call and clears it when the call returns; a crash leaves it set
 * because the clear never ran. This call is how a test sets the flag
 * without killing the process.
 *
 * @param host The host.
 * @param name An installed native module.
 * @param name_len Its length.
 * @return ::GDEFCORE_OK or an error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_mark_entered(GDEFCORE_Host * host,
    const char * name, size_t name_len);

/**
 * @brief A named versioned table, or NULL.
 *
 * NULL means the module is not enabled, the name is unknown, or @p version
 * does not match. The caller does not free the pointer.
 *
 * @param host The host.
 * @param request The request. Its tenant selects the enabled set.
 * @param name Service name.
 * @param name_len Its length.
 * @param version Exact version.
 * @return The table, or NULL.
 */
GDEFCORE_API const void * gdefcore_module_service(GDEFCORE_Host * host,
    GDEFCORE_Request * request, const char * name, size_t name_len,
    uint32_t version);

/** @brief Free text returned by a hook fire. NULL is ignored. */
GDEFCORE_API void gdefcore_module_text_free(GDEFCORE_Host * host, char * text);

/**
 * @brief Fire a hook on the read path.
 *
 * No subscribers on an event or an alter do nothing. No subscribers on a
 * decision deny. A failing event or alter is skipped, counted, and named. A
 * failing decision fails the call. An access-relevant subscriber that fails
 * fails the call. An access contribution from a subscriber that did not
 * declare it is refused.
 *
 * @param host The host.
 * @param request Required. Passed to every subscriber.
 * @param catalog Epoch and tenant. Required.
 * @param hook Hook name.
 * @param hook_len Its length.
 * @param kind ::GDEFCORE_HOOK_EVENT, ALTER, or DECISION.
 * @param args Begins with `size_t size`, or NULL.
 * @param alter Required for an alter. NULL otherwise.
 * @param out_decision Receives allow, deny, or none. NULL for an event.
 * @return ::GDEFCORE_OK, or the failure the rules above keep.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_hook_fire(GDEFCORE_Host * host,
    GDEFCORE_Request * request, GDEFCORE_Catalog * catalog, const char * hook,
    size_t hook_len, int kind, const void * args, GDEFCORE_Alter * alter,
    int * out_decision);

/** @brief How many subscribers the last fire skipped. */
GDEFCORE_API size_t gdefcore_hook_skipped(const GDEFCORE_Host * host);

/**
 * @brief Names skipped by the last fire, one per line, or NULL.
 *
 * @param out_len Receives the length. May be NULL.
 */
GDEFCORE_API const char * gdefcore_hook_skipped_names(
    const GDEFCORE_Host * host, size_t * out_len);

/**
 * @brief An alter value holding @p text. The bytes are copied.
 *
 * @param host The host. Its allocator owns the value.
 * @param text Initial text. NULL only when @p len is 0.
 * @param len Length of @p text.
 * @param out_alter Receives the value.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_alter_create(GDEFCORE_Host * host,
    const char * text, size_t len, GDEFCORE_Alter ** out_alter);

/** @brief Free an alter value. NULL is ignored. */
GDEFCORE_API void gdefcore_alter_destroy(GDEFCORE_Host * host,
    GDEFCORE_Alter * alter);

/**
 * @brief Borrow the current text. Valid until the next set or destroy.
 *
 * @param alter The value.
 * @param out_text Receives a pointer. Not NULL on success; may be empty.
 * @param out_len Receives the length.
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_alter_text(const GDEFCORE_Alter * alter,
    const char ** out_text, size_t * out_len);

/**
 * @brief Replace the shared text. The bytes are copied.
 *
 * @param alter The value.
 * @param text The new text. NULL only when @p len is 0.
 * @param len Length of @p text.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_LIMIT, or
 *   ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_alter_set(GDEFCORE_Alter * alter,
    const char * text, size_t len);

/**
 * @brief Check module ops before the write. A cycle or a missing requirement
 * refuses the changeset. Other tenants are not touched.
 *
 * On success, an enhances notice is held until apply commits.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_vet(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, GDEFCORE_Changeset * changeset);

/** @brief Drop a notice held by a vet whose apply did not commit. */
GDEFCORE_API void gdefcore_module_clear_pending(GDEFCORE_Host * host);

/**
 * @brief Write enable and disable rows into the open port write.
 *
 * The caller has already vetted the changeset.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_write_enables(
    GDEFCORE_Host * host, const uint8_t * tenant, size_t tenant_len,
    GDEFSTOR_Write * write, GDEFCORE_Changeset * changeset);

/**
 * @brief Publish the enhances notice and load a module that was quarantined
 * and has just been enabled again.
 *
 * Called after the port write commits. A failure here does not roll the
 * write back.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_after_apply(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, GDEFCORE_Changeset * changeset);

/**
 * @brief Fire one write-path hook. Any failure, including a deny, is
 * returned. Nothing is skipped.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_fire_write(GDEFCORE_Host * host,
    GDEFCORE_Request * request, GDEFCORE_Catalog * catalog, const char * hook,
    size_t hook_len, const GDEFCORE_Write_Hook * args);

/**
 * @brief One variable a module adds to a template kind's contract.
 *
 * Begins with @ref size. @ref name is exactly `<module>.<name>` (AD-35; a
 * hyphen in the module's name is an underscore here, because Tang cannot
 * spell it) and is used in a template as `use m.count as count;`. @ref type is `text`,
 * `markup` or `number`. `markup` is already-safe markup and is the one type
 * a template prints unescaped: the module vouches for it. @ref principal_free
 * says the answer does not depend on who is asking; when it is not set, a page
 * that reads the variable is recorded as principal-dependent in the render key
 * (AD-30). @ref weight, @ref before and @ref after order this module's
 * contributions against other modules' as AD-10 orders hooks.
 */
typedef struct GDEFCORE_Module_Contribution {
  size_t size;                  ///< `sizeof(GDEFCORE_Module_Contribution)`.
  const char * kind;            ///< Template kind it contributes to.
  size_t kind_len;              ///< Length of @ref kind.
  const char * name;            ///< `<module>.<name>`.
  size_t name_len;              ///< Length of @ref name.
  const char * type;            ///< `text`, `markup` or `number`.
  size_t type_len;              ///< Length of @ref type.
  const char * description;     ///< Plain words for the editor. May be NULL.
  size_t description_len;       ///< Length of @ref description.
  GDEFCORE_Contribution_Fn provider; ///< Required.
  void * user;                  ///< Passed back to @ref provider.
  int principal_free;           ///< Non-zero: the answer ignores the principal.
  int weight;                   ///< Tie break. Larger runs later.
  const char * before;          ///< Run before this module. NULL if none.
  size_t before_len;            ///< Length of @ref before.
  const char * after;           ///< Run after this module. NULL if none.
  size_t after_len;             ///< Length of @ref after.
} GDEFCORE_Module_Contribution;

/**
 * @brief A contribution as the host holds it. Borrowed from the host, valid
 * until it is destroyed.
 */
typedef struct GDEFCORE_Module_Contributed {
  size_t size;                  ///< `sizeof(GDEFCORE_Module_Contributed)`.
  const char * module;          ///< The contributing module.
  size_t module_len;            ///< Length of @ref module.
  const char * kind;            ///< Template kind.
  size_t kind_len;              ///< Length of @ref kind.
  const char * name;            ///< `<module>.<name>`.
  size_t name_len;              ///< Length of @ref name.
  const char * type;            ///< `text`, `markup` or `number`.
  size_t type_len;              ///< Length of @ref type.
  const char * description;     ///< Never NULL; may be empty.
  size_t description_len;       ///< Length of @ref description.
  GDEFCORE_Contribution_Fn provider; ///< The lazy provider.
  void * user;                  ///< Its state.
  int principal_free;           ///< As contributed.
} GDEFCORE_Module_Contributed;

/**
 * @brief Register a contribution of the installed module @p module.
 *
 * The registration is code, not data: it lives with the host and says what
 * the module can add. Whether it is in force for a tenant is decided when the
 * contract is built, by whether the module is enabled. Contributing is
 * additive: nothing here removes a contribution, so a module's disable is
 * what ends it. Register while the host is being set up, with the modules
 * installed and before requests are served: the registry is not locked.
 *
 * Refused with ::GDEFCORE_ERR_INVALID, and the error text from
 * gdefcore_module_error(): the module is not installed, a field is malformed,
 * @ref GDEFCORE_Module_Contribution::name is not under the module's name, or
 * the same module already contributed that name to that kind (the message
 * names both).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_contribute(GDEFCORE_Host * host,
    const char * module, size_t module_len,
    const GDEFCORE_Module_Contribution * contribution);

/**
 * @brief The contributions to template kind @p kind of the modules enabled for
 * @p tenant, in AD-10 order.
 *
 * Ordered by before and after relationships between the modules, then weight,
 * then module name, then registration order. When @p projection is not NULL, its staged module enables and
 * disables are applied first, so a preview sees the set the changeset would
 * leave. A cycle is ::GDEFCORE_ERR_INVALID and the error text names both
 * modules. Free @p out_items with gdefcore_module_contributions_free().
 *
 * @param out_items Receives an array of pointers; NULL when @p out_count is 0.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_contributions(
    GDEFCORE_Host * host, const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection, const char * kind, size_t kind_len,
    const GDEFCORE_Module_Contributed *** out_items, size_t * out_count);

/** @brief Free the array from gdefcore_module_contributions(). NULL is ignored. */
GDEFCORE_API void gdefcore_module_contributions_free(GDEFCORE_Host * host,
    const GDEFCORE_Module_Contributed ** items);

/**
 * @brief A route as the enumeration reports it. Begins with @ref size.
 *
 * @ref spec is ready for gdefcore_route_add_spec(): the handler is resolved
 * through the module's service and the text is borrowed from the host. It is
 * valid until the matching gdefcore_module_declared_free() call, and the text
 * pointers until the host is destroyed.
 */
typedef struct GDEFCORE_Module_Declared_Route {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Route)`.
  const char * module;        ///< The declaring module.
  size_t module_len;          ///< Length of @ref module.
  int admin;                  ///< Non-zero: an admin route.
  GDEFCORE_Route_Spec spec;   ///< The route, ready to add.
} GDEFCORE_Module_Declared_Route;

/** @brief A menu link as the enumeration reports it. Borrowed from the host. */
typedef struct GDEFCORE_Module_Declared_Link {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Link)`.
  const char * module;        ///< The declaring module.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< Machine name.
  size_t name_len;            ///< Length of @ref name.
  const char * menu;          ///< Menu name.
  size_t menu_len;            ///< Length of @ref menu.
  const char * label;         ///< Label.
  size_t label_len;           ///< Length of @ref label.
  const char * route;         ///< Target route machine name.
  size_t route_len;           ///< Length of @ref route.
  int weight;                 ///< Lowest first.
  const char * parent;        ///< Parent link, or "".
  size_t parent_len;          ///< Length of @ref parent.
  int kind;                   ///< ::GDEFCORE_ROUTE_PAGE, _TAB or _ACTION.
} GDEFCORE_Module_Declared_Link;

/** @brief A setting as the enumeration reports it. Borrowed from the host. */
typedef struct GDEFCORE_Module_Declared_Setting {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Setting)`.
  const char * module;        ///< The declaring module.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< Machine name.
  size_t name_len;            ///< Length of @ref name.
  const char * type;          ///< `text`, `number` or `boolean`.
  size_t type_len;            ///< Length of @ref type.
  const char * default_value; ///< The default, as text. Never NULL.
  size_t default_len;         ///< Length of @ref default_value.
  const char * label;         ///< Label.
  size_t label_len;           ///< Length of @ref label.
  const char * description;   ///< Never NULL; may be empty.
  size_t description_len;     ///< Length of @ref description.
  int environment_local;      ///< Non-zero: never imported or exported.
  const char * group;         ///< Never NULL; may be empty.
  size_t group_len;           ///< Length of @ref group.
} GDEFCORE_Module_Declared_Setting;

/** @brief A grant as the enumeration reports it. Borrowed from the host. */
typedef struct GDEFCORE_Module_Declared_Grant {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Grant)`.
  const char * module;        ///< The declaring module.
  size_t module_len;          ///< Length of @ref module.
  const char * permission;    ///< Label of the permission granted.
  size_t permission_len;      ///< Length of @ref permission.
  const char * type_name;     ///< The permission's type.
  size_t type_name_len;       ///< Length of @ref type_name.
  const char * field;         ///< The permission's field; "" for none.
  size_t field_len;           ///< Length of @ref field.
  const char * condition;     ///< The condition text as the module wrote it.
  size_t condition_len;       ///< Length of @ref condition.
} GDEFCORE_Module_Declared_Grant;

/** @brief An access callback as the enumeration reports it. Borrowed from
 * the host; the service is resolved. */
typedef struct GDEFCORE_Module_Declared_Callback {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Callback)`.
  const char * module;        ///< The registering module.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< Its name in the module.
  size_t name_len;            ///< Length of @ref name.
  int scope;                  ///< ::GDEFCORE_CALLBACK_FIELD or _OPERATION.
  const char * permission;    ///< Label of the permission granted.
  size_t permission_len;      ///< Length of @ref permission.
  const char * type_name;     ///< The permission's type.
  size_t type_name_len;       ///< Length of @ref type_name.
  const char * field;         ///< The permission's field; "" for none.
  size_t field_len;           ///< Length of @ref field.
  GDEFCORE_Callback_Fn fn;    ///< The callback.
  void * user;                ///< Its user pointer.
  uint64_t fuel;              ///< Fuel of one call.
  uint32_t timeout_ms;        ///< Timeout of one call.
  int cache;                  ///< A `GDEFCORE_CALLBACK_CACHE_` kind.
  uint32_t ttl_seconds;       ///< For ::GDEFCORE_CALLBACK_CACHE_TTL.
  int flags;                  ///< 0 or ::GDEFCORE_CALLBACK_LOCKED.
} GDEFCORE_Module_Declared_Callback;

/** @brief A relation as the enumeration reports it. Borrowed from the host. */
typedef struct GDEFCORE_Module_Declared_Relation {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Relation)`.
  const char * module;        ///< The declaring module.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< The relation's name, `module.name`.
  size_t name_len;            ///< Length of @ref name.
  const GDEFCORE_Module_Relation_Column * columns; ///< Its columns, copied.
  size_t ncolumns;            ///< How many.
} GDEFCORE_Module_Declared_Relation;

/** @brief A contributor as the enumeration reports it. Borrowed from the
 * host; the service is resolved. */
typedef struct GDEFCORE_Module_Declared_Contributor {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Contributor)`.
  const char * module;        ///< The declaring module.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< Machine name.
  size_t name_len;            ///< Length of @ref name.
  const char * kind;          ///< What it contributes.
  size_t kind_len;            ///< Length of @ref kind.
  const char * path;          ///< Pattern.
  size_t path_len;            ///< Length of @ref path.
  int exact;                  ///< Non-zero: only a path that is the pattern.
  int weight;                 ///< Breaks a tie of specificity.
  GDEFCORE_Contributor_Fn fn; ///< The contributor.
  void * data;                ///< Its data pointer.
} GDEFCORE_Module_Declared_Contributor;

/** @brief A widget type as the enumeration reports it. Borrowed from the
 * host; the provider is resolved. */
typedef struct GDEFCORE_Module_Declared_Widget {
  size_t size;                ///< `sizeof(GDEFCORE_Module_Declared_Widget)`.
  const char * module;        ///< The declaring module.
  size_t module_len;          ///< Length of @ref module.
  const char * name;          ///< Machine name.
  size_t name_len;            ///< Length of @ref name.
  const char * kind;          ///< The template kind it is drawn with.
  size_t kind_len;            ///< Length of @ref kind.
  const char * template_name; ///< The default template; never NULL, and the
                              ///< widget's own name when the module named none.
  size_t template_len;        ///< Length of @ref template_name.
  const char * permission;    ///< The permission its source needs; never NULL.
  size_t permission_len;      ///< Length of @ref permission.
  const char * description;   ///< Never NULL; may be empty.
  size_t description_len;     ///< Length of @ref description.
  GDEFCORE_Widget_Fn fn;      ///< The provider.
  void * user;                ///< Its user pointer.
} GDEFCORE_Module_Declared_Widget;

/**
 * @brief The routes the modules enabled for @p tenant declare.
 *
 * In one total order: modules in AD-10 order, then machine name. When
 * @p projection is not NULL, its staged module enables and disables are
 * applied first, so a preview sees the set the changeset would leave. The
 * enumeration does not depend on the order modules were installed or enabled,
 * on enabling twice, or on enabling again after a disable. A quarantined
 * module declares nothing. Free @p out_items with
 * gdefcore_module_declared_free().
 *
 * @param out_items Receives an array of pointers; NULL when @p out_count is 0.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_routes(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Route *** out_items, size_t * out_count);

/** @brief The menu links of the enabled modules. As gdefcore_module_routes(). */
GDEFCORE_API GDEFCORE_Result gdefcore_module_links(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Link *** out_items, size_t * out_count);

/** @brief The settings of the enabled modules. As gdefcore_module_routes(). */
GDEFCORE_API GDEFCORE_Result gdefcore_module_settings(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Setting *** out_items, size_t * out_count);

/**
 * @brief The template variables the enabled modules declare in their
 * manifests, of every kind, ordered by module, then kind, then name.
 *
 * These are the records gdefcore_module_contributions() returns for a kind, so
 * a template's contract includes them while the module is enabled. Variables
 * registered in code with gdefcore_module_contribute() are not listed here.
 * As gdefcore_module_routes() otherwise.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_variables(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Contributed *** out_items, size_t * out_count);

/**
 * @brief The grants of the enabled modules.
 *
 * As gdefcore_module_routes(), in module order and, within a module, sorted by
 * permission, type, field and condition, so the answer does not depend on the
 * order the modules were enabled in. This is what access decides with: a
 * module that is disabled, or quarantined, is not here, and so grants nothing.
 * With @p projection, the set the changeset would leave. Free @p out_items
 * with gdefcore_module_declared_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_grants(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Grant *** out_items, size_t * out_count);

/**
 * @brief The relations of the enabled modules.
 *
 * As gdefcore_module_routes(), in module order and, within a module, by name.
 * This is what a condition's `related` is judged against: a relation of a
 * module that is disabled, or quarantined, is not here, and with
 * @p projection a relation of a module the changeset enables is. Free
 * @p out_items with gdefcore_module_declared_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_relations(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Relation *** out_items, size_t * out_count);

/**
 * @brief The access callbacks of the enabled modules.
 *
 * As gdefcore_module_grants(): in module order and, within a module, by
 * name; a disabled or quarantined module's are not here, so they grant
 * nothing and govern no field. Free @p out_items with
 * gdefcore_module_declared_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_callbacks(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Callback *** out_items, size_t * out_count);

/**
 * @brief Whether a field callback of a module enabled for @p tenant governs
 * field @p field of @p type_name (gdefcore_access_field_governed()), and
 * whether one of them opts the field in to the locked indicator
 * (@p out_locked, may be NULL). A module that registers none costs no read
 * of the store. When the enabled set cannot be read and an installed module
 * registers one for the field, the field is governed: unknown is refused.
 * @return 1 when governed, else 0.
 */
GDEFCORE_API int gdefcore_module_field_governed(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len, const char * type_name,
    size_t type_name_len, const char * field, size_t field_len,
    int * out_locked);

/**
 * @brief The contributors of the enabled modules. As
 * gdefcore_module_routes(): module order, then name.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_contributors(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Contributor *** out_items, size_t * out_count);

/**
 * @brief The widget types of the enabled modules. As
 * gdefcore_module_routes(): module order, then name. A layout may place a
 * widget type only while its module is enabled.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_widgets(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection,
    const GDEFCORE_Module_Declared_Widget *** out_items, size_t * out_count);

/**
 * @brief Free an array from gdefcore_module_routes(), _links(), _settings(),
 * _variables(), _grants(), _relations(), _callbacks(), _contributors() or
 * _widgets(). NULL is ignored.
 */
GDEFCORE_API void gdefcore_module_declared_free(GDEFCORE_Host * host,
    const void * items);

/**
 * @brief Add every enabled module's routes, and then its contributors, to
 * @p routes, in enumeration order.
 *
 * A contributor is registered with its service resolved
 * (gdefcore_routes_add_contributor()); one that clashes with another in
 * @p routes is an error that names both.
 *
 * A tab is added after its parent; otherwise the order is that of
 * gdefcore_module_routes(). Each route is added with its handler resolved
 * through the declaring module's service, so dispatch calls the module's
 * function with the route's capture accessors and permission check. A route
 * that clashes with one already in @p routes is an error that names both
 * (as gdefcore_route_add_spec() does) and, because a route table never loses
 * a route, the routes added before it stay. Free @p out_error with
 * gdefcore_routes_free().
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_add_routes(GDEFCORE_Host * host,
    const uint8_t * tenant, size_t tenant_len,
    const GDEFCORE_Changeset * projection, GDEFCORE_Routes * routes,
    char ** out_error, size_t * out_error_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_MODULE_H */
