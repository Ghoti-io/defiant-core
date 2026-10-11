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

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_MODULE_H */
