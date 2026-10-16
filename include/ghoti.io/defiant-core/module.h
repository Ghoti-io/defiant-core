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
 * A receiver reads @ref decision and @ref access only when @ref size covers
 * them. @ref access set by a subscriber that did not declare itself
 * access-relevant is refused.
 */
typedef struct GDEFCORE_Hook_Out {
  size_t size;   ///< Must be the prefix the subscriber understands.
  int decision;  ///< ::GDEFCORE_DECISION_ALLOW, DENY, or NONE.
  int access;    ///< Non-zero when this call contributes an access result.
} GDEFCORE_Hook_Out;

/**
 * @brief Argument block for a write-path hook. Begins with @ref size.
 *
 * The request is a separate argument of the subscriber. A receiver reads a
 * field only when @ref size covers it.
 */
typedef struct GDEFCORE_Write_Hook {
  size_t size;                 ///< `sizeof` as known to the caller.
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
 * The host reads @ref kind and @ref name only when @ref size covers them.
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
 * A manifest can declare four tables: routes, menu links, settings and
 * template variables. They are appended to the manifest (AD-4): a module that
 * fills a shorter prefix declares none. The host copies them when the module
 * is installed, validates them when the module is enabled (the enable
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

/** The version of a route handler service table. */
#define GDEFCORE_MODULE_ROUTE_HANDLER_VERSION 1
/** The version of a template variable provider service table. */
#define GDEFCORE_MODULE_VARIABLE_PROVIDER_VERSION 1

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
  size_t size;                     ///< `sizeof(...)` for this build.
  GDEFCORE_Contribution_Fn provider; ///< The provider. Required.
  void * user;                     ///< Passed back to @ref provider.
} GDEFCORE_Module_Variable_Provider;

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
 * @brief What `gdefcore_module_manifest` returns. Begins with @ref size.
 *
 * @ref core_token is the namespace token the module was built against. The
 * host refuses a token that is not the running core's, and the error names
 * both.
 */
typedef struct GDEFCORE_Module_Manifest {
  size_t size;                              ///< Prefix the module filled.
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
} GDEFCORE_Module_Manifest;

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
 * @brief Fire a decision hook as a veto.
 *
 * For an operation that something else has already allowed (a permission the
 * principal holds): every subscriber answers allow, deny or no opinion, and
 * @p out_vetoed is 1 when at least one answered deny (any deny wins, AD-10)
 * and 0 otherwise. No subscribers, or subscribers with no opinion, leave the
 * operation standing; AD-10's "otherwise deny" is what the permission being
 * absent already does. A subscriber that fails fails the call and nothing is
 * allowed. A subscriber that traps is a failure, never a skip.
 *
 * @param args Begins with `size_t size`, or NULL.
 * @param out_vetoed Receives 0 or 1. Required.
 * @return ::GDEFCORE_OK, or the failure of a subscriber, or
 *   ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_module_fire_veto(GDEFCORE_Host * host,
    GDEFCORE_Request * request, GDEFCORE_Catalog * catalog, const char * hook,
    size_t hook_len, const void * args, int * out_vetoed);

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
 * @brief Free an array from gdefcore_module_routes(), _links(), _settings(),
 * _variables() or _grants(). NULL is ignored.
 */
GDEFCORE_API void gdefcore_module_declared_free(GDEFCORE_Host * host,
    const void * items);

/**
 * @brief Add every enabled module's routes to @p routes, in enumeration order.
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
