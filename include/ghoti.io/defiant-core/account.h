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
 * @file account.h
 * @brief Accounts, login identifiers, the wrapped keyring and session tokens.
 * @stability free
 *
 * One subsystem. An account owns one username and a password. The keyring
 * is wrapped for the caller and is not stored. A session token is bound to
 * the tenant and to the account's security epoch, and names its session by a
 * random id sealed inside it. The epoch ends every session of an account; a
 * revocation list ends one.
 */

#ifndef GHOTI_IO_GDEFCORE_ACCOUNT_H
#define GHOTI_IO_GDEFCORE_ACCOUNT_H

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

/** Root key length. AES-256 wraps the keyring with these bytes. */
#define GDEFCORE_ACCOUNT_ROOT_LEN 32

/** Wrapped tenant keyring length. The layout is not changed. */
#define GDEFCORE_KEYRING_WRAP_LEN 63

/** A purpose key derived from the tenant keyring. */
#define GDEFCORE_KEYRING_KEY_LEN 32

/** Longest password this story accepts, in bytes. Empty is refused. */
#define GDEFCORE_ACCOUNT_PASSWORD_MAX 1024u

/** Argon2id memory cost, in KiB. */
#define GDEFCORE_ACCOUNT_ARGON_MEMORY 19456u

/** Argon2id passes. */
#define GDEFCORE_ACCOUNT_ARGON_PASSES 2u

/** Argon2id lanes. */
#define GDEFCORE_ACCOUNT_ARGON_LANES 1u

/** Argon2id tag length, in bytes. */
#define GDEFCORE_ACCOUNT_ARGON_TAG 32u

/** Longest absolute session lifetime, in seconds. Thirty days. */
#define GDEFCORE_ACCOUNT_SESSION_MAX ((uint64_t)30 * 24u * 60u * 60u)

/** A tenant keyring wrapped for one root key. Opaque. Not an entity. */
typedef struct GDEFCORE_Keyring GDEFCORE_Keyring;

/**
 * @brief Draw a tenant keyring and wrap it with @p root.
 *
 * The wrapped bytes stay in the object. Nothing is written to a catalog.
 * A key wrapped for one root does not unwrap under another.
 *
 * @param root Exactly ::GDEFCORE_ACCOUNT_ROOT_LEN bytes. Not stored.
 * @param allocator NULL uses the default.
 * @param out_keyring Receives the keyring on success. Not written on failure.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_IO,
 *   ::GDEFCORE_ERR_LIMIT, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_keyring_create(const uint8_t * root,
    size_t root_len, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Keyring ** out_keyring);

/** @brief Free a keyring. NULL is ignored. The catalog is not touched. */
GDEFCORE_API void gdefcore_keyring_destroy(GDEFCORE_Keyring * keyring);

/**
 * @brief Copy the wrapped keyring bytes.
 *
 * @p out receives ::GDEFCORE_KEYRING_WRAP_LEN bytes. The raw key is not
 * copied. @p out is not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_keyring_export(
    const GDEFCORE_Keyring * keyring, uint8_t * out, size_t out_len);

/**
 * @brief Build a keyring from wrapped bytes.
 *
 * The bytes must be the layout gdefcore_keyring_create() writes, and they
 * must unwrap under @p root. A different root is an error and @p out_keyring
 * is not written. The wrap layout is not changed.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_keyring_adopt(const uint8_t * root,
    size_t root_len, const uint8_t * wrapped, size_t wrapped_len,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Keyring ** out_keyring);

/**
 * @brief Derive one purpose key.
 *
 * HKDF-SHA-256, with @p info as the info string. `subject-wrap` and
 * `blind-index:<field>` are info strings. @p out is
 * ::GDEFCORE_KEYRING_KEY_LEN bytes and is not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_keyring_derive(
    const GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const void * info, size_t info_len, uint8_t * out, size_t out_len);

/**
 * @brief Attach a username and a password to an existing principal.
 *
 * This is how the seeded admin becomes an account. The security epoch
 * starts at 1. An empty password writes nothing. The stored secret is
 * ciphertext, not the PHC string.
 *
 * @param out_id Receives the account's public id and a NUL.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_LIMIT,
 *   ::GDEFCORE_ERR_IO, or ::GDEFCORE_ERR_OOM. Nothing is stored on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_bind(GDEFCORE_Catalog * catalog,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * principal, size_t principal_len, const char * username,
    size_t username_len, const void * password, size_t password_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Create a new principal and an account that owns it.
 *
 * @p out_principal receives the new principal. @p out_id receives the
 * account. Neither is written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_create(
    GDEFCORE_Catalog * catalog, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * username,
    size_t username_len, const void * password, size_t password_len,
    char out_principal[GDEFCORE_PUBLIC_ID_LEN + 1],
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Log in. Unknown usernames and wrong passwords are the same error.
 *
 * A missing account still runs the password hash before that error.
 * @p lifetime_sec is the absolute lifetime and must be from 1 through
 * ::GDEFCORE_ACCOUNT_SESSION_MAX. @p out_token_len is the length of
 * @p out_token. The bytes are not text. Free @p out_token with
 * gdefcore_text_free(). It is not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_login(
    GDEFCORE_Catalog * catalog, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * username,
    size_t username_len, const void * password, size_t password_len,
    uint64_t lifetime_sec, char ** out_token, size_t * out_token_len);

/**
 * @brief Check a session token and set the request principal.
 *
 * A good tag, the account's current epoch and a session that is not revoked
 * set the principal and leave the acting principal unset. A bad tag, a wrong
 * tenant, a wrong purpose, a wrong root key, or an expired token sets no
 * principal and is an error. A good tag with an older epoch sets no
 * principal and returns ::GDEFCORE_OK: the request stays anonymous. So does
 * a good tag whose session was revoked by gdefcore_account_session_revoke():
 * the two are not told apart.
 *
 * The revocation test is one record read in the tenant's storage. It fails
 * closed: if the list cannot be read (storage unavailable, out of memory,
 * corrupt) no principal is set and the storage error is returned, never
 * ::GDEFCORE_OK.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_check(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * token, size_t token_len);

/**
 * @brief The absolute expiry of a session token, in seconds since the epoch.
 *
 * The token bytes are not changed. A bad tag, a wrong tenant, or an expired
 * token is an error and @p out_expiry is not written. This does not set a
 * principal, and it does not consult the epoch or the revocation list: it
 * says what the token claims, not whether the session is live.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_session_expiry(
    GDEFCORE_Catalog * catalog, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * token,
    size_t token_len, uint64_t * out_expiry);

/**
 * @brief End the one session a token names, and no other.
 *
 * The token is opened first, exactly as gdefcore_account_check() opens it. A
 * bad tag, a wrong tenant, a wrong purpose, a wrong root key or an expired
 * token is ::GDEFCORE_ERR_INVALID and nothing is written. @p request must be
 * a request for the catalog's tenant (otherwise ::GDEFCORE_ERR_INVALID); its
 * principal is not read and not changed, so a request already signed in by
 * this token stays so until it ends.
 *
 * The session id is then added to the tenant's revocation list in the
 * tenant's storage, with the token's absolute expiry, in one write that also
 * purges a bounded page of records whose tokens expired (see
 * documentation/accounts.md). The list is part of the tenant's data: it
 * survives a restart and goes into a snapshot. The security epoch is not
 * touched, and neither is any other sign-in of the account, so this is not
 * a substitute for gdefcore_account_logout_everywhere().
 *
 * Revoking a session that is already revoked succeeds and changes nothing.
 * Revoking a session that an epoch has already ended (an older epoch)
 * succeeds and writes nothing: it is as ended as a revocation would make it.
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, or a storage error
 *   (::GDEFCORE_ERR_IO, ::GDEFCORE_ERR_OOM, ::GDEFCORE_ERR_LIMIT,
 *   ::GDEFCORE_ERR_CORRUPT); on any error the session is not known to be
 *   revoked, and the caller must not treat it as signed out.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_session_revoke(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    GDEFCORE_Keyring * keyring, const uint8_t * root, size_t root_len,
    const char * token, size_t token_len);

/**
 * @brief Replace the password. High risk. The confirmation is the username.
 *
 * A wrong confirmation writes nothing. The security epoch increases. An
 * empty password is refused.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_password(
    GDEFCORE_Catalog * catalog, GDEFCORE_Keyring * keyring,
    const uint8_t * root, size_t root_len, const char * id, size_t id_len,
    const void * password, size_t password_len, const char * confirmation,
    size_t confirmation_len);

/**
 * @brief End every live session. High risk. The confirmation is the username.
 *
 * A wrong confirmation writes nothing. The security epoch increases, which
 * ends every session of the account, whether or not it was revoked. The
 * password is left as it was.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_logout_everywhere(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    const char * confirmation, size_t confirmation_len);

/**
 * @brief Remove a login identifier.
 *
 * The last one cannot be removed. This story has only one, so removal is
 * refused and the epoch stays.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_remove_identifier(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    const char * username, size_t username_len);

/**
 * @brief Take a role off the account's principal and increase the epoch.
 *
 * A removal the access layer refuses writes nothing, and the epoch stays.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_remove_role(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    const char * role, size_t role_len);

/**
 * @brief Revert the account's previous save.
 *
 * The previous password ciphertext comes back. The security epoch does not
 * decrease, so a token from before the change stays anonymous.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_revert(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len);

/**
 * @brief The account's security epoch. It starts at 1 and only increases.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_account_epoch(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    uint64_t * out_epoch);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_ACCOUNT_H */
