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
 * @file inst.h
 * @brief The installation scope: tenants, bootstrap and the root key.
 * @stability free
 *
 * One subsystem. An installation has its own store and its own keyring.
 * It is not a site tenant. The first open of an empty installation creates
 * one default tenant. A second tenant gets its own storage key, keyring
 * and catalog. The directory answers one resolution key. It has no list.
 */

#ifndef GHOTI_IO_GDEFCORE_INST_H
#define GHOTI_IO_GDEFCORE_INST_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-storage/core.h>
#include <ghoti.io/defiant-storage/keystore.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bootstrap settings read from the environment or an optional TOML file. */
typedef struct GDEFCORE_Inst_Config GDEFCORE_Inst_Config;

/**
 * @brief An installation. Opaque.
 *
 * The registry store and the site store are borrowed. They must outlive
 * the installation. There is no current installation on the thread.
 */
typedef struct GDEFCORE_Inst GDEFCORE_Inst;

/**
 * @brief Read bootstrap settings. Nothing else is read outside the database.
 *
 * The names are `DEFIANT_ROLES`, `DEFIANT_STORE`, `DEFIANT_LISTEN`,
 * `DEFIANT_TRUSTED_PROXIES`, `DEFIANT_SECRET` and `DEFIANT_SECRET_FILE`.
 * `DEFIANT_CONFIG` is an optional TOML file whose keys are those names
 * without the `DEFIANT_` prefix. The environment wins. A missing setting
 * is the default.
 *
 * `DEFIANT_SECRET` is 64 hex characters. `DEFIANT_SECRET_FILE` is a file of
 * exactly ::GDEFCORE_ACCOUNT_ROOT_LEN bytes. When both are set, the
 * environment is the root and the file is not opened. After a successful
 * read of the environment value, those bytes are overwritten in place and
 * the variable is unset.
 *
 * @param allocator NULL uses the default.
 * @param out_config Receives the configuration. Not written on failure.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_FORMAT,
 *   ::GDEFCORE_ERR_IO, ::GDEFCORE_ERR_LIMIT, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_config_load(
    const GDEFCORE_Allocator * allocator, GDEFCORE_Inst_Config ** out_config);

/** @brief Free a configuration. NULL is ignored. The root bytes are wiped. */
GDEFCORE_API void gdefcore_inst_config_destroy(GDEFCORE_Inst_Config * config);

/**
 * @brief One line per setting: `name=value source=env|file|default`.
 *
 * The secret line names its source and does not contain the key bytes.
 * Free @p out_text with gdefcore_inst_config_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_config_format(
    const GDEFCORE_Inst_Config * config, char ** out_text, size_t * out_len);

/** @brief Free text from gdefcore_inst_config_format(). NULL is ignored. */
GDEFCORE_API void gdefcore_inst_config_free(const GDEFCORE_Inst_Config * config,
    char * text);

/**
 * @brief The root key, when a secret or a secret file supplied one.
 *
 * @param out Exactly ::GDEFCORE_ACCOUNT_ROOT_LEN bytes.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when no root was read.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_config_root(
    const GDEFCORE_Inst_Config * config,
    uint8_t out[GDEFCORE_ACCOUNT_ROOT_LEN]);

/**
 * @brief One setting. @p out_value is borrowed. The secret value is empty.
 *
 * @p out_source is `env`, `file`, or `default`. It is not freed.
 * @p name is the environment name, including the `DEFIANT_` prefix.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_config_setting(
    const GDEFCORE_Inst_Config * config, const char * name, size_t name_len,
    const char ** out_value, size_t * out_value_len, const char ** out_source);

/**
 * @brief Open an installation on @p registry. Tenant catalogs use @p site.
 *
 * The first open of an empty installation creates the default tenant and
 * records @p placement as its directory. The directory is not created.
 * A later open returns that same tenant and does not create another.
 * @p root wraps the installation keyring and each tenant keyring. It is
 * not stored.
 *
 * @param placement NULL only when @p placement_len is 0.
 * @param out_inst Receives the installation. Not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_open(GDEFSTOR_Store * registry,
    GDEFSTOR_Store * site, const uint8_t * root, size_t root_len,
    const char * placement, size_t placement_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Inst ** out_inst);

/**
 * @brief Open an installation that keeps tenant keyrings in @p keys.
 *
 * The first open writes each tenant keyring's wrap into the key store, as
 * the tenant secret ::GDEFCORE_SUBJECT_KEYRING_SECRET under the tenant's
 * storage key (gdefcore_subject_bind_keyring()). A later open adopts that
 * wrap instead of drawing a new key. @p keys is borrowed. It is a key store
 * (AD-19), never a data store: no keyring wrap is written to @p registry or
 * @p site. The raw key is not written anywhere.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_open_keys(GDEFSTOR_Store * registry,
    GDEFSTOR_Store * site, GDEFSTOR_KeyStore * keys, const uint8_t * root,
    size_t root_len, const char * placement, size_t placement_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Inst ** out_inst);

/** @brief Close an installation. NULL is ignored. The stores stay open. */
GDEFCORE_API void gdefcore_inst_destroy(GDEFCORE_Inst * inst);

/**
 * @brief The default tenant's public id.
 *
 * The id is the tenant's storage key encoded with gdefcore_id_encode().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_default(const GDEFCORE_Inst * inst,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Create a tenant. The default tenant's key, keyring and entities stay.
 *
 * @p key is the resolution key. A malformed key and a key already in use
 * are ::GDEFCORE_ERR_INVALID and write nothing. Edition starts empty.
 * Status starts as `active`. @p placement is recorded and no file is created.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_tenant_create(GDEFCORE_Inst * inst,
    const char * key, size_t key_len, const char * placement,
    size_t placement_len, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Map one resolution key to one tenant.
 *
 * An unknown key and a malformed key are the same error. Neither writes
 * @p out_id, the strings, or @p out_limits, and neither names another tenant.
 * With no limit override, @p out_limits is gdefstor_limits_default().
 * The store the caller opened is not changed.
 *
 * Free the strings with gdefcore_inst_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_resolve(const GDEFCORE_Inst * inst,
    const char * key, size_t key_len, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1],
    char ** out_placement, size_t * out_placement_len, char ** out_edition,
    size_t * out_edition_len, char ** out_status, size_t * out_status_len,
    GDEFSTOR_Limits * out_limits);

/** @brief Free one string from gdefcore_inst_resolve(). NULL is ignored. */
GDEFCORE_API void gdefcore_inst_text_free(const GDEFCORE_Inst * inst,
    char * text);

/**
 * @brief Open the tenant's catalog on the site store, using its storage key.
 *
 * The caller destroys the catalog. The site store stays borrowed.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_catalog_open(GDEFCORE_Inst * inst,
    const char * id, size_t id_len, GDEFCORE_Catalog ** out_catalog);

/**
 * @brief Copy the tenant's 16-byte storage key.
 *
 * Two tenants do not share one. @p out is not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_storage_key(
    const GDEFCORE_Inst * inst, const char * id, size_t id_len,
    uint8_t out[16]);

/** @brief The installation keyring. Borrowed. NULL if @p inst is NULL. */
GDEFCORE_API GDEFCORE_Keyring * gdefcore_inst_keyring(GDEFCORE_Inst * inst);

/**
 * @brief The tenant keyring wrapped by the root passed to gdefcore_inst_open().
 *
 * Borrowed. NULL when @p id is not a tenant of @p inst.
 */
GDEFCORE_API GDEFCORE_Keyring * gdefcore_inst_tenant_keyring(
    GDEFCORE_Inst * inst, const char * id, size_t id_len);

/**
 * @brief Record one ::GDEFSTOR_Limits field on the tenant.
 *
 * @p field is the member name, such as `max_revisions`. The directory
 * returns it from gdefcore_inst_resolve(). The site store is not changed.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_inst_limit_set(GDEFCORE_Inst * inst,
    const char * id, size_t id_len, const char * field, size_t field_len,
    uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_INST_H */
