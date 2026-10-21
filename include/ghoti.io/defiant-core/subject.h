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
 * derivation input and nothing per field. A personal value is stored on the
 * tenant's entity port as its sealed text and its subject's public id
 * (AD-14), and each version of it that a save writes has a blind-index row
 * in the port's blind table, in the same write (story S6c); "everything
 * about this person" is the port's subject lookup (gdefcore_subject_export()).
 * Erasure has no undo.
 *
 * Whose a value is, is its field's declaration's to say (AD-19, story S7):
 * the field's subject reference, else the entity's own subject
 * (::GDEFCORE_TYPE_SUBJECTS, gdefcore_entity_subject()). A value is decrypted
 * only in the application's read path, after the access filter has allowed
 * its field (gdefcore_access_read(), gdefcore_access_tree(),
 * gdefcore_access_revision_values(), gdefcore_form_tree_for(), and the
 * renders that read through them), with gdefcore_subject_open_value(); an
 * erased subject's value reads ::GDEFCORE_SUBJECT_ERASED. Each subject a read
 * decrypted is recorded on its request (gdefcore_request_record_subject()),
 * and a fragment cached from that request depends on it
 * (gdefcore_fragment_put()): erasing the subject purges it.
 *
 * Writes to the key store: creating a subject (its wrapped key), the first
 * open of a tenant (the keyring's wrap), erasure (the key destroyed and the
 * ledger row, in one key-store step) and a restore (the key set merged). A
 * save, a read and an export only read it.
 *
 * Erasure runs in this order: (1) the key store destroys the key and appends
 * the ledger row, in one step, after which every value of the subject reads
 * ::GDEFCORE_SUBJECT_ERASED; (2) the subject's blind-index rows are deleted
 * from the tenant's data store (gdefstor_blind_delete_subject()); (3) caches
 * are purged: every fragment of the bound fragment cache that decrypted the
 * subject (gdefcore_subject_bind_cache()). Steps 2 and 3 are idempotent, and
 * every gdefcore_subject_open() and gdefcore_subject_restore() replays the
 * ledger through them before returning, as binding a cache does through
 * step 3, so an erasure interrupted after step 1 is completed then. No
 * blind row is written for an erased subject: a save of a new value of one is
 * refused inside its write (gdefcore_changeset_note_sealed()), and a rebuild
 * (gdefcore_subject_reindex()) skips one, its key being gone.
 *
 * Backups are two sets (AD-19, AD-23): the data set, gdefcore_subject_snapshot()
 * (the tenant store's logical export, no key and no ledger, with the tenant's
 * edition and its enabled modules at their stored-data schema versions), and
 * the key set, gdefcore_subject_keyset() (the key store's export: wrapped
 * keys, the keyring's wrap and the ledger). Each records when it was taken.
 * gdefcore_subject_restore() refuses a key set older than its data set and a
 * module's data newer than the module installed, and then, in AD-23's order,
 * merges the key set, imports the data set (holding back each grant to a
 * state for its confirmation), runs the forward migrations, replays the
 * merged ledger and rebuilds the blind index, all before it returns.
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

/** The key id recorded with every blind-index row core writes (AD-14): the
 * tenant keyring's per-field `blind-index:<field>` key. */
#define GDEFCORE_SUBJECT_MAC_KEY_ID 1

/** The normalization version recorded with every blind-index row core
 * writes (AD-14): 1 is the plaintext's bytes as given, not normalized. */
#define GDEFCORE_SUBJECT_MAC_VERSION 1

/**
 * The tenant secret, in the key store, that holds the tenant keyring's wrap
 * (gdefstor_keystore_secret_put()).
 */
#define GDEFCORE_SUBJECT_KEYRING_SECRET "core-keyring"

/** One tenant's subjects: its key store and its data store. Opaque. */
typedef struct GDEFCORE_Subjects GDEFCORE_Subjects;

/* Defined in render.h. */
struct GDEFCORE_FragmentCache;

/* Defined in module.h. */
struct GDEFCORE_Host;

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
 * @brief Open @p tenant's subjects over its key store and its data store.
 *
 * The first open writes @p keyring's wrap into @p keys as the tenant secret
 * ::GDEFCORE_SUBJECT_KEYRING_SECRET. A later open adopts that wrap and
 * ignores @p keyring. A wrap that does not unwrap under @p root is an error
 * and @p out is not written. The open then replays the key store's ledger:
 * the blind-index rows of every subject it names are deleted from @p data
 * (erasure's step 2, done again for one interrupted after step 1).
 *
 * @param keys The tenant's key store (borrowed). Never a data store.
 * @param data The tenant's data store (borrowed): the store with the entity
 *   port that the tenant's catalog is opened over, which holds the personal
 *   values and their blind-index rows (story S6c; before it, a separate
 *   "blind store"). It holds no key, wrap or ledger row. A catalog whose
 *   changesets index personal values is bound to these subjects
 *   (gdefcore_catalog_bind_subjects()).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_open(GDEFSTOR_KeyStore * keys,
    GDEFSTOR_Store * data, const uint8_t * tenant, size_t tenant_len,
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
 * The field must be a personal field of the entity's root group. The stored
 * revision text is ciphertext, with the subject's public id beside it. Its
 * blind-index row, HMAC-SHA-256 of the plaintext under `blind-index:<field>`,
 * goes in the port's blind table in the same write as the revision (story
 * S6c), so a failure writes neither. The key store is only read: a save
 * never writes it. This and the form route (gdefcore_form_submit_subject())
 * are the only ways to store a value in a personal field:
 * gdefcore_entity_save() and the plain form route refuse it. @p catalog must
 * be opened over this subjects' data store.
 *
 * The subject is the one the field's declaration names (story S7). A field
 * that takes the entity's own subject stores under it, and @p subject, when
 * given, must be it. A field that names a subject reference stores under that
 * reference's value in @p lang, and @p subject, when given, must be it; when
 * the reference holds no value yet, @p subject is required and the same save
 * sets the reference to it. @p subject NULL (or @p subject_len 0) is "the
 * subject the declaration names". A subject the declaration does not name is
 * ::GDEFCORE_ERR_INVALID and nothing is written.
 *
 * A value equal in plaintext to the one stored writes nothing: no item
 * version, no revision and no blind row (AD-19), although its ciphertext
 * would differ.
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
 * key, and @p out_mac its blind-index value, for
 * gdefcore_changeset_note_sealed().
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
 * @brief Whether @p subject is erased: the key store destroyed its key.
 *
 * A subject the key store does not know is not erased (@p out_erased 0).
 * Only reads the key store.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_erased(
    GDEFCORE_Subjects * subjects, const char * subject, size_t subject_len,
    int * out_erased);

/**
 * @brief The blind-index value of @p plain for personal field @p field:
 * HMAC-SHA-256 under the tenant's `blind-index:<field>` key, as every blind
 * row of that field holds it (key ::GDEFCORE_SUBJECT_MAC_KEY_ID, version
 * ::GDEFCORE_SUBJECT_MAC_VERSION).
 *
 * The key is the tenant's, not a subject's, so this works whoever the value
 * belongs to, erased or not: it is what a blind lookup asks with. @p out is
 * written only on success.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_mac(GDEFCORE_Subjects * subjects,
    const char * field, size_t field_len, const void * plain, size_t plain_len,
    uint8_t out[GDEFCORE_SUBJECT_MAC_LEN]);

/**
 * @brief The blind-index value of a stored sealed value: @p sealed is opened
 * with @p subject's key and its plaintext given to gdefcore_subject_mac().
 *
 * What a save computes for a personal value it did not seal itself (one a
 * draft holds, or one a rebuild indexes). The plaintext is wiped before
 * this returns and is never handed out. An erased subject (its key is gone)
 * and an unknown one are ::GDEFCORE_ERR_INVALID; a text that does not open
 * under the subject's key for @p field is ::GDEFCORE_ERR_INVALID too.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_mac_sealed(
    GDEFCORE_Subjects * subjects, const char * subject, size_t subject_len,
    const char * field, size_t field_len, const char * sealed,
    size_t sealed_len, uint8_t out[GDEFCORE_SUBJECT_MAC_LEN]);

/**
 * @brief Blind-index equality: the public ids of the entities of @p type
 * whose current value of personal field @p field, in @p lang, is @p plain.
 *
 * The MAC of @p plain (gdefcore_subject_mac()) is matched against the port's
 * blind rows of each entity's current value version (GDEFSTOR_QUERY_BLIND):
 * an older value does not match, and neither does any value of an erased
 * subject, whose rows are gone. Read as the system: no principal's filter
 * is applied (gdefcore_entity_query_current()). Free @p out_ids with
 * gdefcore_ids_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_find(GDEFCORE_Subjects * subjects,
    GDEFCORE_Catalog * catalog, const char * type, size_t type_len,
    const char * field, size_t field_len, const char * lang, size_t lang_len,
    const void * plain, size_t plain_len, char *** out_ids, size_t * out_count);

/**
 * @brief Rebuild the blind index of the tenant in @p data from the values
 * that can still be decrypted (AD-14, CAP-S1).
 *
 * Every subject the key store holds a key for is visited; for each personal
 * value version the port's subject lookup names for it, across history, the
 * value is opened with its key and its row put back in the blind table
 * (gdefstor_blind_put()), replacing the row the version had. An erased
 * subject has no key and gets no row. Blind rows are not in a snapshot
 * (AD-23), so gdefcore_subject_restore() runs this after its ledger replay;
 * run on a live tenant it changes nothing. @p out_rows (may be NULL)
 * receives how many rows were put.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_reindex(
    GDEFCORE_Subjects * subjects, GDEFSTOR_Store * data, size_t * out_rows);

/**
 * @brief The plaintext, or ::GDEFCORE_SUBJECT_ERASED when the subject is
 * erased.
 *
 * The subject's wrapped key is read from the key store and unwrapped under
 * the keyring; an erased subject has none, and reads as erased at once. A
 * subject the key store does not know is an error. @p field is the field's
 * path at any depth (story S7: `contacts.note` inside a group): the value
 * read is the first, in the published tree's order, of that field that is
 * stored for @p subject; an entity that is not published, or holds no such
 * value, is ::GDEFCORE_ERR_INVALID. This is a system read and asks no
 * principal: a reader's view is gdefcore_access_read() and its siblings.
 * Free @p out_text with gdefcore_subject_free().
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
 * @brief Open one stored personal value (story S7): the read path's one
 * decryption.
 *
 * @p sealed is a value of personal field @p field (its path) as stored, and
 * @p subject the subject stored beside it (gdefcore_tree_value_subject()).
 * The access layer calls this only after the access filter has allowed the
 * field to the reader (AD-19); it asks no principal itself. @p out_text
 * receives the plaintext and @p out_erased 0, or, for a subject whose key the
 * key store destroyed, ::GDEFCORE_SUBJECT_ERASED and @p out_erased 1. A
 * subject the key store does not know, and a value that does not open under
 * its key for @p field, are ::GDEFCORE_ERR_INVALID. Free @p out_text with
 * gdefcore_subject_free(); it is plaintext, so wipe it first.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_open_value(
    GDEFCORE_Subjects * subjects, const char * subject, size_t subject_len,
    const char * field, size_t field_len, const char * sealed,
    size_t sealed_len, char ** out_text, size_t * out_len, int * out_erased);

/**
 * @brief How many times these subjects have decrypted a value, by any call
 * (a read, a seal check at write, an export, a rebuild), since they were
 * opened. For checks: a read that must not decrypt leaves it as it was.
 */
GDEFCORE_API uint64_t gdefcore_subject_open_count(
    const GDEFCORE_Subjects * subjects);

/**
 * @brief The fragment cache erasure purges (erasure's step 3, story S7).
 * Borrowed; NULL unbinds.
 *
 * Binding replays the ledger into @p cache: every fragment that depends on a
 * subject the ledger names is purged, so a cache filled before an erasure
 * that was cut short is purged too. Afterwards gdefcore_subject_erase()
 * purges every fragment that depends on the subject it erases.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_bind_cache(
    GDEFCORE_Subjects * subjects, struct GDEFCORE_FragmentCache * cache);

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
 * subject's blind-index rows are deleted from the data store; every fragment
 * of the bound cache that decrypted the subject is purged
 * (gdefcore_subject_bind_cache()). The revisions stay, as ciphertext. A failure
 * of the first step is returned and nothing else runs. A failure after it
 * is returned too, and the subject already reads as erased; erasing it again,
 * or the next gdefcore_subject_open(), finishes the rest. Erasing an erased
 * subject runs the last two steps again and writes no second ledger row.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_erase(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len, const char * confirmation,
    size_t confirmation_len);

/**
 * @brief "Everything about this person" (AD-19): one JSON document of the
 * plaintext of every value stored for the subject.
 *
 * The values are every personal value version the port's subject lookup
 * finds for the subject (the subject columns, story S6c), across types,
 * groups and history (story S7), published or not, each opened with the
 * subject's key: `{"values":[{"entity":…,"type":…,"field":…,"lang":…,
 * "item":…,"from":…,"to":…,"text":…},…],"drafts":[…]}`, where `field` is the
 * field's path, `from` the revision the version was written in and `to` the
 * one that replaced it, or null for a current value. A draft holds no version,
 * so a draft's values are listed apart (story S8): every value naming the
 * subject in every draft of the tenant (gdefstor_draft_list()), a draft that
 * reserves an id included, in each language the draft holds,
 * `{"entity":…,"type":…,"field":…,"lang":…,"item":…,"base":…,"text":…}`,
 * by entity, language and the draft tree's order, `item` being the draft
 * tree's item id (0 for an item it adds) and `base` the revision the draft was
 * made from (0 for an entity not made yet). The bytes are returned to the
 * caller. Nothing is written into @p catalog. After erasure the document says
 * erased and does not contain the plaintext. Free @p out_json with
 * gdefcore_subject_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_export(
    GDEFCORE_Subjects * subjects, GDEFCORE_Catalog * catalog,
    const char * subject, size_t subject_len, char ** out_json,
    size_t * out_len);

/**
 * @brief The data set of a backup pair: a snapshot of @p tenant_store that
 * records when it was taken and what the tenant needs to come back up
 * (gdefstor_snapshot_export_tenant(), AD-23).
 *
 * It holds the tenant's rows, personal values as ciphertext, and nothing of
 * the key store: no key, no keyring wrap, no ledger. It holds no blind-index
 * row either (AD-23): gdefcore_subject_restore() rebuilds them. Its manifest
 * names @p edition and every component whose data the tenant holds (`core`
 * and its modules) with the stored-data schema version its current data is
 * at, read from the tenant's records (::GDEFCORE_SCHEMA_TYPE), which travel
 * in the same snapshot; every revision, draft and record in it carries the
 * stamp it was written with. Free @p out_bytes with gdefstor_bytes_free()
 * and the store allocator.
 *
 * @param edition The tenant's edition as its installation pins it
 *   (gdefcore_inst_resolve()), `defiant-edition/<n>`; NULL with
 *   @p edition_len 0 for a tenant that pins none.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID (an edition that is not
 *   `defiant-edition/<n>`), ::GDEFCORE_ERR_CORRUPT (a ::GDEFCORE_SCHEMA_TYPE
 *   record that does not hold a schema version), or the store's error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_snapshot(
    GDEFCORE_Subjects * subjects, GDEFSTOR_Store * tenant_store,
    const char * edition, size_t edition_len, uint8_t ** out_bytes,
    size_t * out_len);

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

/** What a restore did, and why it refused when it did. Opaque. */
typedef struct GDEFCORE_Restore GDEFCORE_Restore;

/** One grant a restore held back for its confirmation. Begins with
 * @ref size. Texts are borrowed until the report is freed. */
typedef struct GDEFCORE_Restore_Held {
  size_t size;                ///< `sizeof(GDEFCORE_Restore_Held)`.
  const char * role;          ///< `anonymous` or `authenticated`.
  size_t role_len;            ///< Length of @ref role.
  const char * permission;    ///< As the snapshot granted it: the label
                              ///< gdefcore_access_grant() takes.
  size_t permission_len;      ///< Length of @ref permission.
  int risk;                   ///< As the matrix rates it (access.h).
  const char * confirmation;  ///< The typed confirmation granting it asks for.
  size_t confirmation_len;    ///< Length of @ref confirmation.
  const char * sentence;      ///< In plain words: what was held and how to apply it.
  size_t sentence_len;        ///< Length of @ref sentence.
} GDEFCORE_Restore_Held;

/**
 * @brief Restore a backup pair into an empty tenant, in AD-23's order, all
 * before it returns (story S8).
 *
 * Everything below is checked before anything is written. The data set is
 * walked as untrusted input (AD-37): a bad member name, a defeated limit, a
 * named tenant, an internal or mistyped id, or an installation-scope type
 * refuses it. A data set that records no time, or not what the tenant needs
 * (a plain storage snapshot), is ::GDEFCORE_ERR_FORMAT. A key set older than
 * the data set is ::GDEFCORE_ERR_STALE: it could bring back a key erased after
 * it was taken. A key set whose keyring wrap is not this tenant's is
 * ::GDEFCORE_ERR_INVALID. A component the data set's manifest names that its
 * records (::GDEFCORE_SCHEMA_TYPE) do not hold at that version, or the other
 * way about, is ::GDEFCORE_ERR_CORRUPT. A module the data set needs that
 * @p host does not have installed, a component whose stored data is at a
 * schema version newer than the installed one (gdefcore_module_schema()),
 * and one whose data is at a version from which no forward step leads to the
 * installed one (a gap, gdefcore_module_step()) are each
 * ::GDEFCORE_ERR_UNSUPPORTED, and the report says, naming the component and
 * both versions.
 *
 * Then, in this order: (1) the key set is merged into the key store (its
 * ledger rows replayed as erasures, and no key brought back for a subject the
 * live ledger or the set's names); (2) the data set is imported into
 * @p tenant_store (gdefstor_snapshot_import(); its refusal is the report's
 * reason), and every grant it gives a state (anonymous, authenticated) is
 * held back (gdefcore_access_hold_for_confirmation()): rated, reported in words,
 * and not applied, because granting it is what the admin edit asks a typed
 * confirmation for; the caller applies one with that confirmation through
 * gdefcore_access_grant(); (3) the forward migrations: every component whose
 * data is at an older schema version than the installed one is brought
 * forward by gdefcore_schema_migrate(), the path a live upgrade takes, its
 * steps dated @p when_ms (what was written keeps its shape and its stamp and
 * is read through the upcasters; no row is rewritten; a step that fails
 * stops the restore with the tenant under maintenance); (4) the ledger, now
 * the union of the
 * live one and the set's, is replayed: the blind-index rows of every subject
 * it names are deleted, in @p tenant_store and in this subjects' own data
 * store, and the bound fragment cache purged of them; (5) the derived data a
 * data set does not carry is rebuilt from the values that can be decrypted
 * (the blind index, gdefcore_subject_reindex(); the import rebuilt the
 * current tables). Only then does it return, and the tenant may be served. An
 * erasure newer than either set still reads ::GDEFCORE_SUBJECT_ERASED
 * afterwards.
 *
 * To restore into an empty key store, import the key set into it first
 * (gdefstor_keystore_import()), then open the subjects on it, which adopts the
 * keyring from it, and then call this.
 *
 * @param host The destination's modules (borrowed): the installed versions a
 *   data set's components are checked against and brought to. NULL is an
 *   installation with no module installed.
 * @param when_ms What the forward migrations' writes are dated (the
 *   caller's clock, AD-8): a live upgrade run at the same time writes the
 *   same rows.
 * @param out_report May be NULL. Receives the report, on success and on a
 *   refusal alike (a refusal's reason is gdefcore_restore_reason()), unless
 *   memory ran out for it. Free it with gdefcore_restore_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_restore(
    GDEFCORE_Subjects * subjects, struct GDEFCORE_Host * host,
    GDEFSTOR_Store * tenant_store, const uint8_t * data, size_t data_len,
    const uint8_t * keys, size_t keys_len, int64_t when_ms,
    GDEFCORE_Restore ** out_report);

/**
 * @brief Why the restore refused, in plain words, NUL-terminated; NULL when
 * it did not (or when no sentence could be made).
 */
GDEFCORE_API const char * gdefcore_restore_reason(
    const GDEFCORE_Restore * report, size_t * out_len);

/**
 * @brief The edition the data set says the tenant pins, `defiant-edition/<n>`,
 * or "" for none: for the operator to pin at the destination (a restore never
 * touches the installation scope, AD-23).
 */
GDEFCORE_API const char * gdefcore_restore_edition(
    const GDEFCORE_Restore * report, size_t * out_len);

/** @return How many grants the restore held back for confirmation. */
GDEFCORE_API size_t gdefcore_restore_held_count(
    const GDEFCORE_Restore * report);

/**
 * @brief Held grant @p index, in the order the restore found them.
 * @param out Its @ref GDEFCORE_Restore_Held::size is set by the caller.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_restore_held(
    const GDEFCORE_Restore * report, size_t index, GDEFCORE_Restore_Held * out);

/** @return How many forward steps the restore's migrations applied. */
GDEFCORE_API size_t gdefcore_restore_migrated_count(
    const GDEFCORE_Restore * report);

/** @brief Release a report. NULL is ignored. */
GDEFCORE_API void gdefcore_restore_free(GDEFCORE_Restore * report);

/**
 * @brief Copy the raw subject key.
 *
 * ::GDEFCORE_ERR_INVALID when the key is gone. @p out is not written then.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_subject_key(GDEFCORE_Subjects * subjects,
    const char * subject, size_t subject_len,
    uint8_t out[GDEFCORE_SUBJECT_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SUBJECT_H */
