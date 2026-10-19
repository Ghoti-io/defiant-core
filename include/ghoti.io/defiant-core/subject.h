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
 * encrypted with that subject's key. The tenant keyring's wrap, the subject
 * keys (wrapped under the keyring's `subject-wrap` purpose) and the erasure
 * ledger live in the key store the caller passes (defiant-storage's
 * keystore.h, AD-19), one per tenant and apart from every data store. The
 * blind-index keys are derived from the keyring, so the key store holds their
 * derivation input and nothing per field. Core's blind-index rows, and where
 * each subject's values are, live in a data store of their own (`blind`),
 * never the tenant store, until they move onto the entity port. Erasure has
 * no undo.
 *
 * Writes to the key store: creating a subject (its wrapped key), the first
 * open of a tenant (the keyring's wrap), erasure (the key destroyed and the
 * ledger row, in one key-store step) and a restore (the key set merged). A
 * save, a read and an export only read it.
 *
 * Erasure runs in this order: (1) the key store destroys the key and appends
 * the ledger row, in one step, after which every value of the subject reads
 * ::GDEFCORE_SUBJECT_ERASED; (2) the subject's blind-index rows are deleted in
 * the blind store; (3) caches are purged (core holds no cache of a subject's
 * values or key, so there is nothing yet). Steps 2 and 3 are idempotent, and
 * every gdefcore_subject_open() and gdefcore_subject_restore() replays the
 * ledger through them before returning, so an erasure interrupted after step
 * 1 is completed then.
 *
 * Backups are two sets (AD-19, AD-23): the data set, gdefcore_subject_snapshot()
 * (the tenant store's logical export, no key and no ledger), and the key set,
 * gdefcore_subject_keyset() (the key store's export: wrapped keys, the
 * keyring's wrap and the ledger). Each records when it was taken.
 * gdefcore_subject_restore() refuses a key set older than its data set and
 * replays the ledger before it returns.
 */

#ifndef GHOTI_IO_GDEFCORE_SUBJECT_H
#define GHOTI_IO_GDEFCORE_SUBJECT_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/account.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-storage/keystore.h>
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

/** Length of a blind-index value, as gdefcore_subject_seal() returns it. */
#define GDEFCORE_SUBJECT_MAC_LEN 32

/**
 * The tenant secret, in the key store, that holds the tenant keyring's wrap
 * (gdefstor_keystore_secret_put()).
 */
#define GDEFCORE_SUBJECT_KEYRING_SECRET "core-keyring"

/** One tenant's subjects: its key store and its blind store. Opaque. */
typedef struct GDEFCORE_Subjects GDEFCORE_Subjects;

/**
 * @brief The cipher a key store that seals in process is given
 * (GDEFSTOR_KeyCipher): AES-256-GCM with a fresh 12-byte nonce from the
 * security library's randomness, 32-byte keys.
 *
 * Core keeps its own keys in a key store as sealed material and never asks
 * one to seal with a key it made; a key store needs a cipher all the same,
 * and this is the one to give it. @p out is written whole; its `ctx` is NULL.
 */
GDEFCORE_API void gdefcore_subject_cipher(GDEFSTOR_KeyCipher * out);

/**
 * @brief Open @p tenant's subjects over its key store and its blind store.
 *
 * The first open writes @p keyring's wrap into @p keys as the tenant secret
 * ::GDEFCORE_SUBJECT_KEYRING_SECRET. A later open adopts that wrap and
 * ignores @p keyring. A wrap that does not unwrap under @p root is an error
 * and @p out is not written. The open then replays the key store's ledger:
 * the blind-index rows of every subject it names are deleted from @p blind
 * (erasure's step 2, done again for one interrupted after step 1).
 *
 * @param keys The tenant's key store (borrowed). Never a data store.
 * @param blind The data store that holds core's blind-index rows and the
 *   places each subject's values are (borrowed). It holds no key, wrap or
 *   ledger row, and it is not the tenant store: a snapshot of the tenant
 *   store carries no blind index (AD-23).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_open(GDEFSTOR_KeyStore * keys,
    GDEFSTOR_Store * blind, const uint8_t * tenant, size_t tenant_len,
    const uint8_t * root, size_t root_len, const GDEFCORE_Keyring * keyring,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Subjects ** out);

/** @brief Close a subject store. NULL is ignored. Both stores stay open. */
GDEFCORE_API void gdefcore_subject_destroy(GDEFCORE_Subjects * subjects);

/**
 * @brief Adopt the tenant keyring kept in @p keys, or write @p inout's wrap
 * there.
 *
 * When the key store already holds the wrap, it replaces @p inout and the
 * previous object is destroyed. When it does not, @p inout is required and
 * its wrap is written. A failed adopt is returned as that result and
 * @p inout is left as it was. ::GDEFCORE_ERR_INVALID with @p inout still NULL
 * means the key store has no wrap yet.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_bind_keyring(
    GDEFSTOR_KeyStore * keys, const uint8_t * tenant, size_t tenant_len,
    const uint8_t * root, size_t root_len, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Keyring ** inout);

/**
 * @brief Mint a public id and a subject key.
 *
 * The key is 32 random bytes, wrapped with AES-256-GCM under the tenant
 * keyring's `subject-wrap` purpose and kept in the key store as the
 * subject's sealed material (gdefstor_keystore_subject_put()): the one write
 * to the key store a subject's life makes before its erasure. @p out_id
 * receives the canonical id and a NUL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_create(
    GDEFCORE_Subjects * subjects, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Encrypt @p plain for @p subject and store it as the field text.
 *
 * The field must be personal. The stored revision text is ciphertext.
 * A blind-index row is HMAC-SHA-256 under `blind-index:<field>`, written to
 * the blind store. A failure of the revision writes nothing. The key store
 * is only read: a save never writes it. This and the form route
 * (gdefcore_form_submit_subject()) are the only ways to store a value in a
 * personal field: gdefcore_entity_save() and the plain form route refuse it.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_save(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * subject, size_t subject_len,
    const char * entity, size_t entity_len, const char * field,
    size_t field_len, const char * lang, size_t lang_len, const void * plain,
    size_t plain_len);

/**
 * @brief Seal @p plain for @p subject without writing anything.
 *
 * The first half of gdefcore_subject_save() for a caller that has to stage
 * the revision itself, as the subject route of a form does
 * (gdefcore_form_submit_subject()). @p out_text receives the same ciphertext
 * gdefcore_subject_save() would store, in the same format and under the same
 * key, and @p out_mac the blind-index value for gdefcore_subject_index().
 * A @p plain that is itself a sealed text (it came out of storage, from
 * gdefcore_form_tree() or gdefcore_entity_values(), not from a person) is
 * ::GDEFCORE_ERR_INVALID: it would be sealed a second time. The same is
 * true of gdefcore_subject_save(). An unknown subject, and an erased one,
 * are ::GDEFCORE_ERR_INVALID and
 * nothing is written to @p out_text or @p out_mac. Neither store is written
 * either way. Free @p out_text with gdefcore_subject_free().
 *
 * Sealing is not a write of the field: a sealed text is accepted for a
 * personal field only by a changeset that gdefcore_changeset_accept_sealed()
 * was called on. Most callers want gdefcore_subject_save().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_seal(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * field,
    size_t field_len, const void * plain, size_t plain_len, char ** out_text,
    size_t * out_len, uint8_t out_mac[GDEFCORE_SUBJECT_MAC_LEN]);

/**
 * @brief Record the blind-index row for a value already stored.
 *
 * The second half of gdefcore_subject_save(). Call it after the revision
 * holding the text from gdefcore_subject_seal() has been applied. It
 * replaces the row the same @p entity, @p field and @p lang had before, in
 * the blind store. The two halves are separate commits, in two stores, so a
 * failure between them
 * leaves a sealed revision with no index row; erasure does not need the row
 * to make the revision unreadable. An erased subject is
 * ::GDEFCORE_ERR_INVALID and writes nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_index(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * entity,
    size_t entity_len, const char * field, size_t field_len, const char * lang,
    size_t lang_len, const uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN]);

/**
 * @brief The plaintext, or ::GDEFCORE_SUBJECT_ERASED when the subject is
 * erased.
 *
 * The subject's wrapped key is read from the key store and unwrapped under
 * the keyring; an erased subject has none, and reads as erased at once. A
 * subject the key store does not know is an error. Free @p out_text with
 * gdefcore_subject_free().
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
 * @brief Say what a revision view shows for an erased person.
 *
 * gdefcore_access_revision_values() never returns the stored ciphertext of a
 * personal field: it answers ::GDEFCORE_REVISION_PERSONAL and no text. Give
 * that answer and @p subject (the person the value belongs to; the caller
 * names them, as for gdefcore_subject_read()) to this function, and when the
 * ledger names the person it makes the answer ::GDEFCORE_REVISION_ERASED with
 * @p out_text the marker ::GDEFCORE_SUBJECT_ERASED, which is what the history
 * of an erased person says in place of what they wrote. A person not erased
 * stays ::GDEFCORE_REVISION_PERSONAL with no text: a revision view never
 * decrypts. Any other @p status is returned as it is. No principal is asked
 * here and nothing is read of the entity; the permission and the field filter
 * were the access layer's. Free @p out_text with gdefcore_subject_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_revision_marker(
    GDEFCORE_Subjects * subjects, const char * subject, size_t subject_len,
    int status, int * out_status, char ** out_text, size_t * out_len);

/**
 * @brief Erase a subject: destroy its key.
 *
 * @p confirmation is the subject's public id, one line. A wrong id writes
 * nothing. Then, in this order: the key store destroys the key and appends
 * the ledger row (subject id and time, nothing personal) in one step; the
 * subject's blind-index rows are deleted from the blind store; caches are
 * purged (none are kept yet). The revisions stay, as ciphertext. A failure
 * of the first step is returned and nothing else runs. A failure after it
 * is returned too, and the subject already reads as erased; erasing it again,
 * or the next gdefcore_subject_open(), finishes the rest. Erasing an erased
 * subject runs the last two steps again and writes no second ledger row.
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
 * @brief The data set of a backup pair: a snapshot of @p tenant_store that
 * records when it was taken (gdefstor_snapshot_export_at()).
 *
 * It holds the tenant's rows, personal values as ciphertext, and nothing of
 * the key store: no key, no keyring wrap, no ledger. @p tenant_store must
 * not be the blind store. Free @p out_bytes with gdefstor_bytes_free() and
 * the store allocator.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_snapshot(
    GDEFCORE_Subjects * subjects, GDEFSTOR_Store * tenant_store,
    uint8_t ** out_bytes, size_t * out_len);

/**
 * @brief The key set of a backup pair: the key store's export for the
 * tenant (gdefstor_keystore_export(), `defiant-keyset/1`), recording when it
 * was taken.
 *
 * It holds the subject keys, each wrapped under the keyring, the keyring's
 * wrap (under the installation root) and the ledger: it is a key backup,
 * kept apart from the data set and never inside it. Take it after the data
 * set it pairs with. Free @p out_bytes with gdefstor_bytes_free() and the key
 * store's allocator.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_keyset(
    GDEFCORE_Subjects * subjects, uint8_t ** out_bytes, size_t * out_len);

/**
 * @brief Restore a backup pair into an empty tenant, replaying the ledger
 * before it returns.
 *
 * A key set older than the data set is ::GDEFCORE_ERR_STALE, and nothing is
 * written: it could bring back a key erased after it was taken. A data set
 * that records no time (a plain storage snapshot) is ::GDEFCORE_ERR_FORMAT.
 * Otherwise the key set is merged into the key store (its ledger rows replayed
 * as erasures, and no key brought back for a subject the live ledger or the
 * set's names), the data set is imported into @p tenant_store, and the
 * ledger, now the union of the live one and the set's, is replayed: the
 * blind-index rows of every subject it names are deleted. So an erasure newer
 * than either set still reads ::GDEFCORE_SUBJECT_ERASED afterwards. A key set
 * whose keyring wrap is not this tenant's is ::GDEFCORE_ERR_INVALID before
 * anything is imported.
 *
 * To restore into an empty key store, import the key set into it first
 * (gdefstor_keystore_import()), then open the subjects on it, which adopts the
 * keyring from it, and then call this.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_restore(
    GDEFCORE_Subjects * subjects, GDEFSTOR_Store * tenant_store,
    const uint8_t * data, size_t data_len, const uint8_t * keys,
    size_t keys_len);

/**
 * @brief Copy the raw subject key.
 *
 * ::GDEFCORE_ERR_INVALID when the key is gone. @p out is not written then.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_key(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len,
    uint8_t out[GDEFCORE_SUBJECT_KEY_LEN]);

/** @brief How many blind-index rows this subject has. A subject the key
 * store does not know is ::GDEFCORE_ERR_INVALID. */
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
