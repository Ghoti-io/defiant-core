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
 * @file subject.h
 * @brief Subjects, personal values, erasure and export.
 * @stability free
 *
 * One subsystem. A subject is not an account. A personal field is
 * encrypted with that subject's key. The keyring wrap, the subject keys,
 * the blind index and the erasure ledger live in the side store the caller
 * passes. They are not written into the tenant store. Erasure has no undo.
 */

#ifndef GHOTI_IO_GDEFCORE_SUBJECT_H
#define GHOTI_IO_GDEFCORE_SUBJECT_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-storage/store.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bytes a subject read returns after erasure. Not a NUL-terminated claim. */
#define GDEFCORE_SUBJECT_ERASED "[erased]"

/** Length of ::GDEFCORE_SUBJECT_ERASED, not counting a trailing NUL. */
#define GDEFCORE_SUBJECT_ERASED_LEN 8

/** Raw subject key length. */
#define GDEFCORE_SUBJECT_KEY_LEN 32

/**
 * Side-store projection that holds the append-only ledger. A row is the
 * subject public id and the time. The plant in the restore gate names
 * these; the library does not read an environment variable.
 */
#define GDEFCORE_SUBJECT_LEDGER_TYPE "core.ledger"
#define GDEFCORE_SUBJECT_LEDGER_ID "log"

/** The side store for one tenant. Opaque. */
typedef struct GDEFCORE_Subjects GDEFCORE_Subjects;

/**
 * @brief Open the side store for @p tenant.
 *
 * The first open copies @p keyring's wrapped bytes into @p side. A later
 * open adopts those bytes and ignores @p keyring. A wrap that does not
 * unwrap under @p root is an error and @p out is not written. @p side is
 * borrowed.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_open(GDEFSTOR_Store * side,
    const uint8_t * tenant, size_t tenant_len, const uint8_t * root,
    size_t root_len, const GDEFCORE_Keyring * keyring,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Subjects ** out);

/** @brief Close a subject store. NULL is ignored. @p side stays open. */
GDEFCORE_API void gdefcore_subject_destroy(GDEFCORE_Subjects * subjects);

/**
 * @brief Adopt the tenant keyring stored in @p side, or copy @p inout into it.
 *
 * When @p side already holds wrapped bytes, those bytes replace @p inout
 * and the previous object is destroyed. When it does not, @p inout is
 * required and its wrapped bytes are copied in. A wrap that does not
 * unwrap is ::GDEFCORE_ERR_CORRUPT and @p inout is left as it was.
 * ::GDEFCORE_ERR_INVALID with @p inout still NULL means the side store has
 * no wrap yet.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_bind_keyring(
    GDEFSTOR_Store * side, const uint8_t * tenant, size_t tenant_len,
    const uint8_t * root, size_t root_len, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Keyring ** inout);

/**
 * @brief Mint a public id and a subject key.
 *
 * The key is 32 random bytes, wrapped with AES-256-GCM under the tenant
 * keyring's `subject-wrap` purpose. @p out_id receives the canonical id
 * and a NUL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_create(
    GDEFCORE_Subjects * subjects, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Encrypt @p plain for @p subject and store it as the field text.
 *
 * The field must be personal. The stored revision text is ciphertext.
 * A blind-index row is HMAC-SHA-256 under `blind-index:<field>`. A failure
 * writes nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_save(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    const char * entity, size_t entity_len, const char * field,
    size_t field_len, const char * lang, size_t lang_len, const void * plain,
    size_t plain_len);

/**
 * @brief The plaintext, or ::GDEFCORE_SUBJECT_ERASED when the ledger says so.
 *
 * A missing key that the ledger does not name is an error. Free
 * @p out_text with gdefcore_subject_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_read(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    const char * entity, size_t entity_len, const char * field,
    size_t field_len, const char * lang, size_t lang_len, char ** out_text,
    size_t * out_len);

/** @brief Free bytes from this subsystem. NULL is ignored. */
GDEFCORE_API void gdefcore_subject_free(GDEFCORE_Subjects * subjects,
    void * bytes);

/**
 * @brief Destroy the subject key.
 *
 * @p confirmation is the subject's public id, one line. A wrong id writes
 * nothing. The ledger gains one row, the blind-index rows are deleted, and
 * the revisions stay.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_erase(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * confirmation,
    size_t confirmation_len);

/**
 * @brief One JSON document of the plaintext values.
 *
 * The bytes are returned to the caller. Nothing is written into
 * @p catalog. After erasure the document says erased and does not contain
 * the plaintext. Free @p out_json with gdefcore_subject_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_export(
    GDEFCORE_Subjects * subjects, GDEFCORE_Catalog * catalog,
    const char * subject, size_t subject_len, char ** out_json,
    size_t * out_len);

/**
 * @brief Snapshot @p tenant_store and carry a copy of the ledger.
 *
 * The copy is the zip member `ledger`. It is not a storage key. The zip
 * does not carry a key. @p tenant_store must not be the side store.
 * Free @p out_bytes with gdefstor_bytes_free() and the store allocator.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_snapshot(
    GDEFCORE_Subjects * subjects, GDEFSTOR_Store * tenant_store,
    uint8_t ** out_bytes, size_t * out_len);

/**
 * @brief Import into an empty tenant, then replay the ledger union.
 *
 * The union is the live ledger and the snapshot's copy. Replay runs before
 * this function returns, so a later read of an erased subject is
 * ::GDEFCORE_SUBJECT_ERASED even when the erasure is newer than the snapshot.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_import(
    GDEFCORE_Subjects * subjects, GDEFSTOR_Store * tenant_store,
    const uint8_t * bytes, size_t len);

/**
 * @brief Copy the raw subject key.
 *
 * ::GDEFCORE_ERR_INVALID when the key is gone. @p out is not written then.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_key(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len,
    uint8_t out[GDEFCORE_SUBJECT_KEY_LEN]);

/** @brief How many blind-index rows this subject has. */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_blind_count(
    GDEFCORE_Subjects * subjects, const char * subject, size_t subject_len,
    size_t * out_count);

/**
 * @brief One blind-index row. The bytes are not the plaintext.
 *
 * @p out is 32 bytes.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_blind(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, size_t index, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SUBJECT_H */
