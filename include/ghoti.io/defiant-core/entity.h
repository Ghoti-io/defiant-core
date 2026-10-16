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
 * @file entity.h
 * @brief Types, public ids, revisions and changesets.
 * @stability free
 *
 * One subsystem. A type is content or configuration. A field is text, one
 * value or many, under a caller-supplied language. The integer row id is the
 * storage key and is not an argument a later call accepts. The document's
 * `entity` string is the public id. Saves stage a changeset. Apply is one
 * port write.
 */

#ifndef GHOTI_IO_GDEFCORE_ENTITY_H
#define GHOTI_IO_GDEFCORE_ENTITY_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-storage/store.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Canonical public id length, not counting a trailing NUL. */
#define GDEFCORE_PUBLIC_ID_LEN 28

/** The type holds content. */
#define GDEFCORE_TYPE_CONTENT 1
/** The type holds configuration. */
#define GDEFCORE_TYPE_CONFIG 2

/* The touch codes are bit flags, so a caller can test a set of them. */
/** A touched entity was saved to the published projection. */
#define GDEFCORE_TOUCH_SAVE 1
/** A touched entity was saved to the draft projection only. */
#define GDEFCORE_TOUCH_DRAFT 2
/** A touched entity's draft is published by the changeset. */
#define GDEFCORE_TOUCH_PUBLISH 4
/** A touched entity is cleared by the changeset. */
#define GDEFCORE_TOUCH_CLEAR 8

/** A changeset that only changes content field values. */
#define GDEFCORE_RISK_LOW 1
/** A changeset that defines a type or touches configuration. */
#define GDEFCORE_RISK_HIGH 2

/** Read the published projection. */
#define GDEFCORE_VIEW_PUBLISHED 1
/** Read the draft projection. */
#define GDEFCORE_VIEW_DRAFT 2

/** Caps for the changeset parser and for field values. */
typedef struct GDEFCORE_Limits {
  size_t max_patch_files;   ///< How many patch files one parse accepts.
  size_t max_patch_path;    ///< Bytes in one relative path.
  size_t max_patch_file;    ///< Bytes in one file.
  size_t max_patch_total;   ///< Bytes across every file.
  size_t max_fields;        ///< Fields on one type.
  size_t max_values;        ///< Values of one field in one save.
  size_t max_value_bytes;   ///< Bytes in one field value.
  size_t max_languages;     ///< Languages in one staged document.
} GDEFCORE_Limits;

/**
 * @brief Fill @p limits with the defaults. NULL is ignored.
 *
 * @param limits The struct to fill.
 */
GDEFCORE_API void gdefcore_limits_default(GDEFCORE_Limits * limits);

/** A catalog bound to one store and one tenant. Opaque. */
typedef struct GDEFCORE_Catalog GDEFCORE_Catalog;

/** A prepared changeset. Opaque. */
typedef struct GDEFCORE_Changeset GDEFCORE_Changeset;

/**
 * @brief A field declaration. The caller owns the name for the call.
 *
 * @ref size is `sizeof(GDEFCORE_Field)`. A value that stops before
 * @ref many is ::GDEFCORE_ERR_INVALID. @ref personal is 0 when @ref size
 * stops before it. Members after @ref personal are absent when @ref size
 * stops before them: no minimum, no maximum, no range and no pattern.
 */
typedef struct GDEFCORE_Field {
  size_t size;              ///< Must be `sizeof(GDEFCORE_Field)`.
  const char * name;        ///< Required. ASCII letters, digits, underscore.
  size_t name_len;          ///< Length of @ref name.
  int required;             ///< Non-zero when a save must supply the field.
  int many;                 ///< Non-zero when the field holds more than one value.
  int personal;             ///< Non-zero when the value is encrypted for a subject.
  size_t min_len;           ///< Minimum byte length. 0 means no minimum.
  size_t max_len;           ///< Maximum byte length. 0 means no maximum.
  int has_range;            ///< Non-zero when @ref range_min and @ref range_max apply.
  int64_t range_min;        ///< Inclusive lower bound of a base-10 integer.
  int64_t range_max;        ///< Inclusive upper bound of a base-10 integer.
  const char * pattern;     ///< ECMAScript regex, or NULL. Must match the whole value.
  size_t pattern_len;       ///< Length of @ref pattern. 0 means no pattern.
} GDEFCORE_Field;

/**
 * @brief Field values for one save. The caller owns the bytes for the call.
 *
 * @ref size is `sizeof(GDEFCORE_Value)`.
 */
typedef struct GDEFCORE_Value {
  size_t size;                 ///< Must be `sizeof(GDEFCORE_Value)`.
  const char * field;          ///< Field machine name.
  size_t field_len;            ///< Length of @ref field.
  const char * const * texts;  ///< The values. NULL only when @ref count is 0.
  const size_t * text_lens;    ///< One length per value.
  size_t count;                ///< How many values.
} GDEFCORE_Value;

/**
 * @brief One file of a `defiant-changeset/1` tree.
 *
 * @ref size is `sizeof(GDEFCORE_Patch)`. Paths are relative. Bytes are UTF-8.
 */
typedef struct GDEFCORE_Patch {
  size_t size;     ///< Must be `sizeof(GDEFCORE_Patch)`.
  char * path;     ///< Relative path. No leading slash.
  size_t path_len; ///< Length of @ref path.
  uint8_t * bytes; ///< File bytes.
  size_t len;      ///< Length of @ref bytes.
} GDEFCORE_Patch;

/**
 * @brief Open a catalog. The store is borrowed.
 *
 * @param store The port. Required.
 * @param tenant Tenant bytes. Required, non-empty.
 * @param tenant_len Length of @p tenant.
 * @param limits NULL uses gdefcore_limits_default().
 * @param allocator NULL uses the default.
 * @param out_catalog Receives the catalog on success.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_catalog_open(GDEFSTOR_Store * store,
    const uint8_t * tenant, size_t tenant_len, const GDEFCORE_Limits * limits,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Catalog ** out_catalog);

/** @brief Close a catalog. NULL is ignored. The store stays open. */
GDEFCORE_API void gdefcore_catalog_destroy(GDEFCORE_Catalog * catalog);

/**
 * @brief Encode 16 bytes as a canonical public id.
 *
 * @param raw Exactly 16 bytes, most significant first.
 * @param out Receives 28 symbols and a NUL.
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_id_encode(const uint8_t raw[16],
    char out[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Draw 16 bytes from `gsec_random_bytes` and encode them.
 *
 * @param out Receives 28 symbols and a NUL.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_IO, or
 *   ::GDEFCORE_ERR_LIMIT.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_id_generate(
    char out[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Canonicalise a public id. A failed check is malformed.
 *
 * Case is folded, hyphens are removed, `I` and `L` become `1`, and `O`
 * becomes `0`. This function does not look anything up.
 *
 * @param text The caller's bytes.
 * @param len Their length.
 * @param out Receives the canonical id and a NUL.
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_id_canonical(const char * text,
    size_t len, char out[GDEFCORE_PUBLIC_ID_LEN + 1]);

/**
 * @brief Define a type now. A second define of the same name is refused.
 *
 * The write does not change the config epoch. A changeset that defines a
 * type is gdefcore_changeset_define() and is high risk.
 *
 * @param catalog The catalog.
 * @param name Machine name: `core.<name>`, `site.<name>`, or `<module>.<name>`.
 * @param name_len Its length.
 * @param kind ::GDEFCORE_TYPE_CONTENT or ::GDEFCORE_TYPE_CONFIG.
 * @param fields Field declarations. NULL only when @p field_count is 0.
 * @param field_count How many.
 * @return ::GDEFCORE_OK or an error. Nothing is written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_type_define(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, int kind, const GDEFCORE_Field * fields,
    size_t field_count);

/**
 * @brief The stored kind of a type.
 *
 * @param catalog The catalog.
 * @param name Machine name.
 * @param name_len Its length.
 * @param out_kind Receives the kind.
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID when the type is absent.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_type_kind(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, int * out_kind);

/** @brief How many fields the type declares. */
GDEFCORE_API GDEFCORE_Result gdefcore_type_field_count(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    size_t * out_count);

/**
 * @brief Copy one field declaration. @p out_name is allocated.
 *
 * Free @p out_name with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_type_field(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, char ** out_name,
    size_t * out_name_len, int * out_required, int * out_many);

/**
 * @brief Whether the field at @p index is personal.
 *
 * A field declared before @ref GDEFCORE_Field::personal existed is not
 * personal. @p out_personal is not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_type_field_personal(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    size_t index, int * out_personal);

/**
 * @brief Constraints stored on the field at @p index.
 *
 * A field stored before these members existed reports no minimum, no
 * maximum, no range and a NULL pattern. Free @p out_pattern with
 * gdefcore_text_free() when it is not NULL. Nothing is written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_type_field_constraints(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    size_t index, size_t * out_min_len, size_t * out_max_len,
    int * out_has_range, int64_t * out_range_min, int64_t * out_range_max,
    char ** out_pattern, size_t * out_pattern_len);

/**
 * @brief Mint a public id and a row id for an entity of @p type_name.
 *
 * The row id is returned for inspection. Later calls take the public id.
 * A never-published entity has no published row.
 *
 * @param catalog The catalog.
 * @param type_name A type that is already readable.
 * @param type_len Its length.
 * @param out_id Receives the canonical id and a NUL.
 * @param out_row Receives the row id. May be NULL.
 * @return ::GDEFCORE_OK or an error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_create(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1], uint64_t * out_row);

/** @brief The tenant config epoch. An unseen epoch is 0. */
GDEFCORE_API GDEFCORE_Result gdefcore_epoch(GDEFCORE_Catalog * catalog,
    uint64_t * out_epoch);

/**
 * @brief Start a changeset at the current epoch.
 *
 * @param actor Optional public id. Not checked against an account. NULL
 *   means none.
 * @param actor_len Length of @p actor.
 * @param out_changeset Receives the changeset.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_prepare(
    GDEFCORE_Catalog * catalog, const char * actor, size_t actor_len,
    GDEFCORE_Changeset ** out_changeset);

/** @brief Free a changeset. NULL is ignored. */
GDEFCORE_API void gdefcore_changeset_destroy(GDEFCORE_Changeset * changeset);

/**
 * @brief Stage a type definition. Apply is what publishes it.
 *
 * Defining or changing a type makes the changeset high risk.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_define(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len,
    int kind, const GDEFCORE_Field * fields, size_t field_count);

/**
 * @brief Stage field values. A rejected save leaves the changeset unchanged.
 *
 * @p lang is required: non-empty, at most 35 bytes, ASCII letters, digits
 * and hyphens. An undeclared field or a missing required field stages
 * nothing. A value for a personal field is ::GDEFCORE_ERR_INVALID and stages
 * nothing: a personal value is stored only sealed for its subject (see
 * gdefcore_subject_save() and gdefcore_changeset_accept_sealed()).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_save(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Value * values, size_t value_count);

/**
 * @brief Let @p changeset stage sealed values for personal fields.
 *
 * By default gdefcore_entity_save() and gdefcore_entity_save_draft() refuse
 * a value for a personal field. After this call they take one for a
 * personal field if, and only if, it is a sealed text from
 * gdefcore_subject_seal(). The entity layer holds no key, so it checks the
 * shape (`s1:` and an even run of lower-case hex of at least a nonce and a
 * tag), not the seal: plaintext is refused and a forged shape is not. This
 * exists for the subject routes and is not a way to store personal data.
 * ::GDEFCORE_ERR_INVALID for a NULL or an applied changeset.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_accept_sealed(
    GDEFCORE_Changeset * changeset);

/**
 * @brief Stage field values onto the draft projection only.
 *
 * Apply appends a revision and updates the draft. The published projection
 * is left as it was. The arguments are the same as gdefcore_entity_save().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_save_draft(
    GDEFCORE_Changeset * changeset, const char * id, size_t id_len,
    const char * lang, size_t lang_len, const GDEFCORE_Value * values,
    size_t value_count);

/**
 * @brief Stage a copy of the draft projection onto the published one.
 *
 * Apply does not append a revision. An entity with no draft writes nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_publish(
    GDEFCORE_Changeset * changeset, const char * id, size_t id_len);

/**
 * @brief The latest revision sequence, or 0 when the entity has none.
 *
 * A missing id is ::GDEFCORE_ERR_INVALID. @p out_seq is not written then.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_revision(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    uint64_t * out_seq);

/**
 * @brief How many revisions were recorded for the entity.
 *
 * A revision is recorded when a changeset that appends one is applied.
 * A missing id is ::GDEFCORE_ERR_INVALID. An entity with none reports 0.
 * @p out_count is not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_revision_count(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    size_t * out_count);

/**
 * @brief One recorded revision, oldest first.
 *
 * @p out_seq receives the sequence. @p out_actor receives the actor public
 * id, or NULL when that revision recorded none. Free @p out_actor with
 * gdefcore_text_free(). An index past the end is ::GDEFCORE_ERR_INVALID
 * and nothing is written.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_revision_at(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len, size_t index,
    uint64_t * out_seq, char ** out_actor, size_t * out_actor_len);

/**
 * @brief Read field values.
 *
 * When @p changeset touches the entity, the staged fields are returned and
 * @p view is ignored. Otherwise @p view selects the published or draft
 * projection. A miss is ::GDEFCORE_ERR_INVALID.
 *
 * Free the texts with gdefcore_values_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_values(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * changeset, int view, const char * id,
    size_t id_len, const char * lang, size_t lang_len, const char * field,
    size_t field_len, char *** out_texts, size_t ** out_lens,
    size_t * out_count);

/** @brief Free texts from gdefcore_entity_values(). */
GDEFCORE_API void gdefcore_values_free(GDEFCORE_Catalog * catalog,
    char ** texts, size_t * lens, size_t count);

/** @brief Free one text allocated by the catalog. NULL is ignored. */
GDEFCORE_API void gdefcore_text_free(GDEFCORE_Catalog * catalog, char * text);

/**
 * @brief One line per changed language and field: `en title: Hello -> Bonjour`.
 *
 * Free @p out_text with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_diff(
    const GDEFCORE_Changeset * changeset, char ** out_text, size_t * out_len);

/**
 * @brief Rate the changeset. The caller cannot supply the rating.
 *
 * @param out_risk Receives ::GDEFCORE_RISK_LOW or ::GDEFCORE_RISK_HIGH.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_rate(
    const GDEFCORE_Changeset * changeset, int * out_risk);

/**
 * @brief Commit the changeset in one port write.
 *
 * High risk requires @p confirmation equal to the touched machine names,
 * sorted, one per line, with no extra newline. Low risk ignores
 * @p confirmation. A stale epoch or sequence writes nothing; the touched
 * names are then available from gdefcore_changeset_conflict().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_apply(
    GDEFCORE_Changeset * changeset, const char * confirmation,
    size_t confirmation_len);

/**
 * @brief Names from the last conflicting apply, or NULL.
 *
 * One name per line. Valid until the next apply, rebase, or destroy.
 */
GDEFCORE_API const char * gdefcore_changeset_conflict(
    const GDEFCORE_Changeset * changeset, size_t * out_len);

/**
 * @brief Retarget the changeset at the current epoch and sequences.
 *
 * Does not apply it.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_rebase(
    GDEFCORE_Changeset * changeset);

/** @brief The epoch the changeset was prepared against. */
GDEFCORE_API uint64_t gdefcore_changeset_epoch(
    const GDEFCORE_Changeset * changeset);

/**
 * @brief The sequence the changeset holds for @p id.
 *
 * @return ::GDEFCORE_ERR_INVALID when @p id is not in the changeset.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_base_seq(
    const GDEFCORE_Changeset * changeset, const char * id, size_t id_len,
    uint64_t * out_seq);

/**
 * @brief A new changeset that restores the previous revision.
 *
 * Sequence 1 clears the published row and the current draft fields. The
 * document stays readable. The caller applies the result.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_revert(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    const char * actor, size_t actor_len, GDEFCORE_Changeset ** out_changeset);

/**
 * @brief Ordered relative paths and UTF-8 bytes, `defiant-changeset/1`.
 *
 * Free the list with gdefcore_patch_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_serialize(
    const GDEFCORE_Changeset * changeset, GDEFCORE_Patch ** out_files,
    size_t * out_count);

/** @brief Free a patch list. NULL is ignored. */
GDEFCORE_API void gdefcore_patch_free(GDEFCORE_Catalog * catalog,
    GDEFCORE_Patch * files, size_t count);

/**
 * @brief Parse a patch. Untrusted.
 *
 * `..`, an absolute path, a byte that is not UTF-8, and a public id that
 * fails its check are refused. A failing check is not looked up. Nothing
 * is written to the store.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_parse(
    GDEFCORE_Catalog * catalog, const GDEFCORE_Patch * files, size_t count,
    const GDEFCORE_Limits * limits, GDEFCORE_Changeset ** out_changeset);

/** The module host bound to a catalog. Opaque to this header. */
typedef struct GDEFCORE_Host GDEFCORE_Host;

/** The request a write-path hook receives. */
typedef struct GDEFCORE_Request GDEFCORE_Request;

/**
 * @brief Borrow the catalog's tenant bytes.
 *
 * @param catalog The catalog. NULL returns NULL.
 * @param out_len Receives the length. May be NULL.
 * @return The bytes, or NULL.
 */
GDEFCORE_API const uint8_t * gdefcore_catalog_tenant(
    const GDEFCORE_Catalog * catalog, size_t * out_len);

/**
 * @brief Remember the module host apply should fire. NULL clears it.
 *
 * The host is borrowed. It must outlive the catalog, or be cleared first.
 *
 * @param catalog The catalog. NULL is ignored.
 * @param host The host, or NULL.
 */
GDEFCORE_API void gdefcore_catalog_bind_host(GDEFCORE_Catalog * catalog,
    GDEFCORE_Host * host);

/**
 * @brief The request write-path hooks receive. NULL clears it.
 *
 * @param changeset The changeset. NULL is ignored.
 * @param request Borrowed. Not a thread-local.
 */
GDEFCORE_API void gdefcore_changeset_set_request(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request);

/**
 * @brief Make apply ask whether the changeset's request may do what it writes.
 *
 * Off by default, and then a changeset writes whatever it stages, as it
 * always has. On, apply asks gdefcore_access_can() for each entity the
 * changeset touches, with the request set by gdefcore_changeset_set_request():
 * a save or a draft is the permission `update`, a publish is `publish`, and a
 * clear (a revert to nothing) is `delete`, each on the entity's type. One
 * that is not allowed refuses the whole changeset, writes nothing, and sets
 * the refusal; so does asking for this with no request. A new entity has no
 * actor yet, so an `own` grant does not allow its first save. Templates are
 * left to their own permission (gdefcore_template_authorize()).
 *
 * @param changeset The changeset. NULL is ignored.
 * @param enforce Non-zero to turn it on, zero to turn it off.
 */
GDEFCORE_API void gdefcore_changeset_enforce_access(
    GDEFCORE_Changeset * changeset, int enforce);

/**
 * @brief Stage enabling or disabling a module. Apply commits it.
 *
 * The operation is high risk. @p name is lowercase letters, digits and
 * hyphens. Confirmation is that name.
 *
 * @param changeset The changeset.
 * @param name Module name.
 * @param name_len Its length.
 * @param enable Non-zero to enable, zero to disable.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_stage_module(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len,
    int enable);

/** @brief How many module enable or disable ops are staged. */
GDEFCORE_API size_t gdefcore_changeset_module_count(
    const GDEFCORE_Changeset * changeset);

/**
 * @brief One staged module op.
 *
 * @p out_name is borrowed from the changeset.
 *
 * @param changeset The changeset.
 * @param index Zero-based among module ops.
 * @param out_name Receives the name.
 * @param out_len Receives its length.
 * @param out_enable Receives non-zero when the op enables.
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_module_at(
    const GDEFCORE_Changeset * changeset, size_t index, const char ** out_name,
    size_t * out_len, int * out_enable);

/**
 * @brief Public ids of entities of @p type_name, in creation order.
 *
 * This is the unfiltered index. A principal's list is
 * gdefcore_access_list(). An unknown type is an empty list.
 * Free @p out_ids with gdefcore_ids_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_ids(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_name_len, char *** out_ids,
    size_t * out_count);

/** @brief Free ids from gdefcore_entity_ids(). NULL is ignored. */
GDEFCORE_API void gdefcore_ids_free(GDEFCORE_Catalog * catalog, char ** ids,
    size_t count);

/**
 * @brief The entity's type name. Free @p out_type with gdefcore_text_free().
 *
 * A missing id is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_type(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_type, size_t * out_len);

/**
 * @brief The actor stored on the published revision, or NULL when there is none.
 *
 * An entity with no actor is not anyone's own. A missing id is
 * ::GDEFCORE_ERR_INVALID. Free @p out_actor with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_actor(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_actor, size_t * out_len);

/** The entity has no published projection (a draft, or nothing saved yet). */
#define GDEFCORE_STATE_DRAFT 1
/** The entity has a published projection. */
#define GDEFCORE_STATE_PUBLISHED 2

/**
 * @brief The projection state of an entity.
 *
 * ::GDEFCORE_STATE_PUBLISHED when the entity has a published projection,
 * whether or not a newer draft sits beside it; otherwise
 * ::GDEFCORE_STATE_DRAFT. A missing id is ::GDEFCORE_ERR_INVALID and
 * @p out_state is not written. Unfiltered, like gdefcore_entity_values().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_state(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, int * out_state);

/**
 * @brief Copy bytes with the catalog allocator.
 *
 * Free @p out with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_text_dup(GDEFCORE_Catalog * catalog,
    const char * text, size_t len, char ** out);

/** @brief The catalog a changeset was prepared on, or NULL. */
GDEFCORE_API GDEFCORE_Catalog * gdefcore_changeset_catalog(
    const GDEFCORE_Changeset * changeset);

/**
 * @brief Add a confirmation line. Apply sorts these after the machine names.
 *
 * A line break is refused. Enabling a module uses this for permission labels.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_add_confirm_line(
    GDEFCORE_Changeset * changeset, const char * line, size_t len);

/**
 * @brief The module host bound with gdefcore_catalog_bind_host(), or NULL.
 *
 * @param catalog The catalog. NULL returns NULL.
 */
GDEFCORE_API GDEFCORE_Host * gdefcore_catalog_host(
    const GDEFCORE_Catalog * catalog);

/**
 * @brief How many entities the changeset writes: saves, drafts, publishes
 * and clears. Type definitions and module operations are not counted.
 */
GDEFCORE_API size_t gdefcore_changeset_touched_count(
    const GDEFCORE_Changeset * changeset);

/**
 * @brief One entity the changeset writes.
 *
 * @p out_id and @p out_type are borrowed from the changeset and are not
 * NUL-terminated. @p out_op receives ::GDEFCORE_TOUCH_SAVE,
 * ::GDEFCORE_TOUCH_DRAFT, ::GDEFCORE_TOUCH_PUBLISH or
 * ::GDEFCORE_TOUCH_CLEAR. Any out pointer may be NULL.
 *
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID for an index past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_touched_at(
    const GDEFCORE_Changeset * changeset, size_t index, const char ** out_id,
    size_t * out_id_len, const char ** out_type, size_t * out_type_len,
    int * out_op);

/**
 * @brief Why the last apply or preview refused, in words, or NULL.
 *
 * A template that fails validation is named here with its line and the
 * offending name, one issue per line. Valid until the next apply, rebase, or
 * destroy.
 *
 * @param out_len Receives the length. May be NULL.
 */
GDEFCORE_API const char * gdefcore_changeset_refusal(
    const GDEFCORE_Changeset * changeset, size_t * out_len);

/**
 * @brief Record the refusal text. The bytes are copied; NULL clears it.
 *
 * For the subsystems that vet a changeset (templates). Not a way to refuse
 * an apply: the caller returns its own result.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_set_refusal(
    GDEFCORE_Changeset * changeset, const char * text, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_ENTITY_H */
