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
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/query.h>
#include <ghoti.io/defiant-storage/value.h>
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
/** A touched entity gets a new revision, its newest, and is published. A
 * revert reports this too: it is a save of an earlier revision's content. */
#define GDEFCORE_TOUCH_SAVE 1
/** A touched entity's draft is written: no revision, nothing a reader sees. */
#define GDEFCORE_TOUCH_DRAFT 2
/** A touched entity's draft, if it has one, is applied as its newest
 * revision, and the entity is published. */
#define GDEFCORE_TOUCH_PUBLISH 4
/** A touched entity is cleared by the changeset. */
#define GDEFCORE_TOUCH_CLEAR 8
/** A touched entity is unpublished. Its revisions do not change. */
#define GDEFCORE_TOUCH_UNPUBLISH 16

/** A changeset that only changes content field values. */
#define GDEFCORE_RISK_LOW 1
/** A changeset that defines a type or touches configuration. */
#define GDEFCORE_RISK_HIGH 2

/** Read the newest revision, but only while the entity is published. This is
 * what a reader sees; an unpublished entity has no such view. */
#define GDEFCORE_VIEW_PUBLISHED 1
/** Read the entity's draft, where it has one, over its newest revision: what
 * an editor opens. A draft is never a revision and never in a list. */
#define GDEFCORE_VIEW_DRAFT 2
/** Read the newest revision whether or not the entity is published. This is
 * the revision the entity currently is, and what a condition reads. (The
 * newest revision is always the current one: there is no older revision an
 * entity can be made to be, story S6b.) */
#define GDEFCORE_VIEW_CURRENT 3

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
 * stops before them: no minimum, no maximum, no range and no pattern, a text
 * field, not indexed.
 *
 * Every field has a logical type (AD-13), which is what the storage port
 * keeps and compares: ::GDEFSTOR_FIELD_TEXT (also @ref type 0), INTEGER,
 * DECIMAL (with @ref scale), FLOAT, BOOLEAN, DATE, DATETIME or REFERENCE.
 * Values are still texts at this interface, written and read in each type's
 * canonical text (gdefcore_value_parse()): an integer reads `7` however it
 * was written, a decimal of scale 2 `1.50`, a boolean `true` or `false`, a
 * date `2026-10-19`, a date-time `2026-10-19T08:30:00Z` (with `.mmm` when it
 * has milliseconds), a reference a canonical public id. A value that is not
 * one of its type is ::GDEFCORE_ERR_INVALID at staging. A personal field holds
 * the sealed text of its value whatever its type, until subjects reach the
 * port (story S7). `<`, `<=`, `>` and `>=` in a condition need a numeric or
 * temporal field (access SPEC decision 12).
 *
 * Nested groups (story S6d): a field of @ref type ::GDEFSTOR_FIELD_GROUP holds
 * items, each with the fields in @ref children, recursively, at most
 * ::GDEFSTOR_MODEL_MAX_DEPTH groups deep. @ref many may be set on any field,
 * a group included: a group that is not @ref many holds at most one item. A
 * group is a field of the entity, never an entity of its own (AD-14). A
 * group has no value, so it is never @ref personal or @ref indexed and has no
 * constraint and no scale; @ref required on a group means at least one item.
 * Field names are unique among siblings; a field is named by its path, the
 * names from the root group joined by `.` (`lines.taxes.rate`).
 *
 * The flat calls of this header (gdefcore_entity_save(), the field
 * enumeration gdefcore_type_field_count() and its siblings, conditions, forms
 * and lists) see the fields of the root group that hold values, and nothing
 * else: a group field and the fields inside it are reached through the tree
 * calls (gdefcore_tree_save(), gdefcore_entity_tree(),
 * gdefcore_type_tree_field()). A flat save of a type with groups keeps its
 * group items as they are. Conditions on nested fields are not built (SPEC
 * "Deferred"): a condition naming one is refused as one naming a field the
 * type does not have.
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
  int type;                 ///< A ::GDEFSTOR_FieldType other than GROUP; 0 is text.
  int scale;                ///< DECIMAL: digits after the point, 0 to 18.
  int indexed;              ///< Non-zero asks the store to index it (a hint).
  /** GROUP (@ref type ::GDEFSTOR_FIELD_GROUP): its fields, at least one, each
   * one a GDEFCORE_Field of its own, recursively (story S6d). NULL for any
   * other field. */
  const struct GDEFCORE_Field * children;
  size_t child_count;       ///< How many in @ref children.
  /** PERSONAL: where each value's subject comes from. The name of a sibling
   * field (in the same group) that is a single, non-personal REFERENCE: the
   * subject is that field's value in the same item. NULL: each value names
   * its subject as it is sealed (gdefcore_changeset_note_sealed()), which
   * only a field of the root group may do. A personal field inside a group
   * must name its subject source. */
  const char * subject;
  size_t subject_len;       ///< Length of @ref subject.
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

/**
 * @brief How many fields of the root group that hold values the type
 * declares: the fields the flat calls see. A group, and the fields inside one,
 * are counted by gdefcore_type_tree_field_count() (story S6d); for a type with
 * no group the two are the same. The index of gdefcore_type_field() and its
 * siblings is among these.
 */
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
 * @brief Mint a public id for an entity of @p type_name and reserve it.
 *
 * The id is reserved by the entity's draft, which holds no content yet (a
 * draft of a never-saved entity has no entity row, AD-14): the entity itself,
 * with its creator, is made when its first draft or its first save is
 * applied, with that changeset's actor as its creator. Until then it has no
 * creator and its type is its draft's. Until its first revision it is in no
 * list. @p out_row receives 0: an entity has no internal row before
 * it exists, and the row is the port's afterwards.
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

/** @brief The tenant config epoch (the store's counter `core.epoch`, AD-31).
 * An unseen epoch is 0. */
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
 * Apply writes the entity's next revision from the values it has now and
 * these, in every language they touch, and sets the published flag: the
 * system's "save and publish", used for configuration and by every caller
 * that has no draft step. Only what changed is written; values equal to the
 * current ones write no revision, which gdefcore_changeset_revision() says.
 * A path that separates the acts uses gdefcore_entity_save_draft() and
 * gdefcore_entity_publish(). An entity whose id its draft reserves is made
 * here, with the changeset's actor as its creator. A draft the entity has is
 * consumed: when it was made from the newest revision the save builds on it
 * (it saves the working copy), otherwise on the newest revision, and after
 * the apply the entity has no draft.
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

/* Defined in subject.h, which includes this header. */
struct GDEFCORE_Subjects;

/**
 * @brief Tell @p changeset whose sealed value @p text is (story S6c).
 *
 * On the storage port a personal value is its sealed text and its subject's
 * public id, and every new version of it gets a blind-index row (AD-14,
 * AD-19). A text the entity already holds names its own subject, and one a
 * draft holds names the subject the draft recorded; a text sealed for this
 * changeset names none, and is told here: @p subject, and @p mac, the
 * blind-index value gdefcore_subject_seal() returned with it (NULL for a
 * draft, which carries no MAC; a save then computes it). @p subjects are the
 * keys that made it: apply asks them, inside its write, whether the subject
 * is erased, and refuses the value of one that is. gdefcore_subject_save()
 * and the subject form route call this; it does not make the changeset
 * accept sealed values (gdefcore_changeset_accept_sealed()). A text that is
 * not shaped as a sealed one, a subject that is not a public id, another
 * @p subjects than an earlier note's, or an applied changeset is
 * ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_note_sealed(
    GDEFCORE_Changeset * changeset, struct GDEFCORE_Subjects * subjects,
    const char * text, size_t text_len, const char * subject,
    size_t subject_len, const uint8_t mac[GDEFSTOR_BLIND_MAC_BYTES]);

/**
 * @brief The subjects whose keys index the personal values @p catalog's
 * changesets write (story S6c). Borrowed; NULL unbinds.
 *
 * A save or a publish that writes a new version of a personal value gives
 * it a blind-index MAC, computed under the tenant's blind-index key from the
 * value it opens with its subject's key, and refuses a value whose subject
 * is erased. A changeset given a note (gdefcore_changeset_note_sealed())
 * uses that note's subjects; any other needs the catalog's, and without them
 * such a write is ::GDEFCORE_ERR_INVALID. The subjects must be the tenant's,
 * opened over the catalog's store.
 */
GDEFCORE_API void gdefcore_catalog_bind_subjects(GDEFCORE_Catalog * catalog,
    struct GDEFCORE_Subjects * subjects);

/**
 * @brief Stage field values as the entity's draft (access SPEC decision 13).
 *
 * Apply writes the draft: the entity's values as they would be, kept apart
 * from its revisions, recording the revision it was made from. It writes no
 * revision, moves no published flag, and nothing it holds is in a list, a
 * query or a reader's view; gdefcore_entity_publish() applies it. Staged on
 * an entity that has a draft, it builds on the draft. The first draft of an
 * entity whose id its draft reserves makes the entity, with the changeset's
 * actor as its creator and no revision. The arguments are the same as
 * gdefcore_entity_save(). A personal value is held in the draft as its
 * sealed text and its subject, and no blind-index value (AD-14).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_save_draft(
    GDEFCORE_Changeset * changeset, const char * id, size_t id_len,
    const char * lang, size_t lang_len, const GDEFCORE_Value * values,
    size_t value_count);

/**
 * @brief Stage publishing: apply the entity's draft, if it has one, as its
 * next revision, and set the published flag.
 *
 * The draft is applied only on the revision it was made from: when the
 * entity has a newer one, apply is a conflict and writes nothing. A draft
 * equal to the current values writes no revision. Without a draft only the
 * flag is set. An entity with no revision and no draft is
 * ::GDEFCORE_ERR_INVALID. The revision's author is whoever wrote the draft
 * last (recorded with it), not the publisher (defect 1.5.3); the entity's
 * creator is whoever made it.
 *
 * At apply the draft is validated against its type as the type is then
 * (AD-14): a value of a field the type no longer has (other than what the
 * entity holds there now), a value not of its field's type, or a required
 * field missing is ::GDEFCORE_ERR_INVALID with a refusal
 * (gdefcore_changeset_refusal()). Each personal value the draft changes gets
 * its blind-index MAC (gdefcore_catalog_bind_subjects()); one that names an
 * erased subject refuses the apply, which writes nothing and keeps the draft
 * (story S6c: an erased subject's key is gone, so no new value of theirs is
 * written).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_publish(
    GDEFCORE_Changeset * changeset, const char * id, size_t id_len);

/* ---- scheduled publish (story S6c) --------------------------------------- */

/** gdefcore_entity_schedule_state(): the entity has no schedule. */
#define GDEFCORE_SCHEDULE_NONE 0
/** It is waiting for its time. */
#define GDEFCORE_SCHEDULE_PENDING 1
/** It was applied: the entity was published, its draft applied if it had one. */
#define GDEFCORE_SCHEDULE_DONE 2
/** It was refused as a conflict: the draft was made from a revision that was
 * no longer the newest when its time came (CAP-S4). The draft is kept. */
#define GDEFCORE_SCHEDULE_CONFLICT 3
/** It was refused: there was nothing to publish, the draft did not fit its
 * type as the type was then, or it held a new value of an erased subject.
 * The draft is kept. */
#define GDEFCORE_SCHEDULE_REFUSED 4
/** gdefcore_schedule_apply(): the job was not there (applied already,
 * cancelled, or moved to another time), and nothing was written. */
#define GDEFCORE_SCHEDULE_GONE 5
/** gdefcore_schedule_apply(): the job's time has not come, and nothing was
 * written. */
#define GDEFCORE_SCHEDULE_EARLY 6

/** A due job (gdefcore_schedule_due()). */
typedef struct GDEFCORE_ScheduleJob {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1]; ///< The entity, canonical, NUL-terminated.
  int64_t at_ms;                       ///< Its time, in milliseconds since 1970 UTC.
} GDEFCORE_ScheduleJob;

/**
 * @brief Publish entity @p id at time @p at_ms (AD-14: "scheduled publish
 * applies a draft at a time"), as @p actor.
 *
 * A job row in the tenant's store (AD-33), written in a port write of its
 * own; an entity has one schedule, which this replaces. When the job is
 * applied (gdefcore_schedule_apply(), gdefcore_schedule_run()), at or after
 * its time and once, the entity is published as by gdefcore_entity_publish()
 * staged by @p actor (empty or NULL: the system): the draft it has then, if
 * any, is validated against its type and applied on the revision it was made
 * from, a moved head is a conflict, and the published flag is set. Clearing
 * the entity cancels its schedule. The time is the caller's: a civil time and
 * zone (AD-33) are converted before this.
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID (an id that is not a known
 *   entity or reservation, an actor that is not a public id, a negative time),
 *   or the store's error.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_schedule_publish(
    GDEFCORE_Catalog * catalog, const char * actor, size_t actor_len,
    const char * id, size_t id_len, int64_t at_ms);

/** @brief Cancel the entity's schedule, and forget what became of an ended
 * one. An entity with none is ::GDEFCORE_OK. */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_unschedule(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len);

/**
 * @brief The entity's schedule: ::GDEFCORE_SCHEDULE_NONE, or
 * ::GDEFCORE_SCHEDULE_PENDING, _DONE, _CONFLICT or _REFUSED, and its time.
 * @p out_at_ms may be NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_schedule_state(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len, int * out_state,
    int64_t * out_at_ms);

/**
 * @brief The jobs due at @p now_ms, earliest first: at most @p cap of them.
 *
 * A read. What it lists may be applied by another runner before this one
 * reaches it; gdefcore_schedule_apply() says so.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_schedule_due(GDEFCORE_Catalog * catalog,
    int64_t now_ms, GDEFCORE_ScheduleJob * out_jobs, size_t cap,
    size_t * out_count);

/**
 * @brief Apply the job of entity @p id at @p at_ms, if it is still there and
 * due at @p now_ms.
 *
 * The publish is one changeset, applied in one port write that reads the job
 * row again and deletes it: a job is applied once, whichever runner gets to
 * it first, and never before its time. @p now_ms is also the time the
 * revision and the state change record. @p out_outcome receives
 * ::GDEFCORE_SCHEDULE_DONE, _CONFLICT or _REFUSED (the job ended; the entity's
 * schedule says the same), _GONE or _EARLY (nothing was written), or _PENDING
 * when the write kept losing to other writers (::GDEFCORE_ERR_BUSY is returned
 * and the job stays).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_schedule_apply(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len, int64_t at_ms,
    int64_t now_ms, int * out_outcome);

/**
 * @brief The runner: apply every job due at @p now_ms, at most @p max.
 *
 * @p out_applied and @p out_ended (either may be NULL) receive how many were
 * applied and how many ended refused or in conflict.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_schedule_run(GDEFCORE_Catalog * catalog,
    int64_t now_ms, size_t max, size_t * out_applied, size_t * out_ended);

/**
 * @brief Stage clearing the published flag.
 *
 * Apply writes no revision, so the entity keeps its content and its creator
 * and readers stop seeing it. Unpublishing an entity that is not published
 * is allowed and writes nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_unpublish(
    GDEFCORE_Changeset * changeset, const char * id, size_t id_len);

/**
 * @brief Stage clearing an entity: a soft delete. It is unpublished, marked
 * deleted, and reads as if it had no content; its draft is dropped.
 *
 * Every recorded revision stays, and the entity is restored by a revert to
 * one of them (gdefcore_changeset_revert_to()) or by a save. This is the
 * delete that a revert of a first revision makes (gdefcore_changeset_revert()),
 * staged in a changeset of its own choosing so that it can be applied with
 * other changes atomically. It checks no permission (SPEC decision 7).
 *
 * @return ::GDEFCORE_ERR_INVALID for an unknown id, an id already in the
 *   changeset, or an applied changeset.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_clear(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len);

/**
 * @brief The entity's version: a counter that every write touching the
 * entity bumps, including a publish, an unpublish, a draft and a clear, none
 * of which need move the latest revision sequence.
 *
 * Starts at 0 at gdefcore_entity_create(). A caller that remembers a fact
 * about an entity keys it on this, not on gdefcore_entity_revision(). An op
 * that writes nothing (a save of the values the entity has, an unpublish of
 * an unpublished entity) does not move it. It only increases, though not
 * always by one (a write that aborted can leave a gap).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_version(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    uint64_t * out_version);

/**
 * @brief The revision the entity currently is: its newest.
 *
 * @p out_has is 0 and @p out_seq is 0 when the entity has none (nothing saved
 * yet, or cleared). A missing id is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_current_revision(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len, int * out_has,
    uint64_t * out_seq);

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
 * @p view is ignored. Otherwise @p view selects what is read: the newest
 * revision while published, the newest revision, or the draft over it. Values
 * are in their field type's canonical text. A miss is ::GDEFCORE_ERR_INVALID.
 *
 * Free the texts with gdefcore_values_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_values(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * changeset, int view, const char * id,
    size_t id_len, const char * lang, size_t lang_len, const char * field,
    size_t field_len, char *** out_texts, size_t ** out_lens,
    size_t * out_count);

/**
 * @brief Read field values of one recorded revision, unfiltered.
 *
 * Like gdefcore_entity_values(), a preview for the host and for
 * gdefcore_access_revision_values(), which is the read a principal uses. A
 * personal field comes out as the sealed text it was stored as. @p seq is a
 * revision sequence of the entity; one never recorded, a missing id and a field
 * with no value in that revision are ::GDEFCORE_ERR_INVALID. Free the texts
 * with gdefcore_values_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_revision_values(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len, uint64_t seq,
    const char * lang, size_t lang_len, const char * field, size_t field_len,
    char *** out_texts, size_t ** out_lens, size_t * out_count);

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
 * @brief A new changeset that restores the revision before the newest.
 *
 * That is a new revision (the port's revert, AD-14: old rows are never
 * touched), a copy of the revision numbered one less than the newest; the
 * published flag is unchanged. When the newest revision is the first, the
 * changeset clears the entity instead (gdefcore_entity_clear(); every
 * recorded revision stays). An entity with no revision is
 * ::GDEFCORE_ERR_INVALID. The caller applies the result.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_revert(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len,
    const char * actor, size_t actor_len, GDEFCORE_Changeset ** out_changeset);

/**
 * @brief A new changeset that writes a copy of revision @p seq as the newest,
 * leaving the published flag as it is.
 *
 * Unlike gdefcore_changeset_revert() this names its target and never clears;
 * a cleared entity reverted to a revision is no longer deleted. This is what
 * "make an older revision the content" is now (access SPEC decision 13: there
 * is no active-revision pointer). The new revision's creator is @p actor. Any
 * personal value in revision @p seq must be sealed. ::GDEFCORE_ERR_INVALID
 * for a sequence that is not a recorded revision. Reverting to the values the
 * entity has writes no revision. The caller applies the result.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_revert_to(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len, uint64_t seq,
    const char * actor, size_t actor_len, GDEFCORE_Changeset ** out_changeset);

/**
 * @brief Ordered relative paths and UTF-8 bytes, `defiant-changeset/1`.
 *
 * The format has no file for a group field or a group item (story S6d): a
 * changeset that defines a type with a group, or stages an entity that has
 * group items in any language, is ::GDEFCORE_ERR_UNSUPPORTED and nothing is
 * returned. Free the list with gdefcore_patch_free().
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

/**
 * @brief The caps this catalog was opened with.
 *
 * @param out Receives a copy. Required.
 */
GDEFCORE_API void gdefcore_catalog_limits(const GDEFCORE_Catalog * catalog,
    GDEFCORE_Limits * out);

/**
 * @brief Public ids of the entities of a type that have a revision and are not
 * cleared, matching a storage query, in the query's order, with the total.
 *
 * This is the unfiltered index with a predicate: the port's entity query
 * (query.h) over the type's current tables, read as the
 * system, knowing nothing of a principal. A caller that serves a principal
 * puts that principal's access filter into the query's tree
 * (gdefcore_access_list() does, through plan.h). Rows are the entities whose
 * newest revision exists and that are not deleted, whether or not they are
 * published; a tree that reads META PUBLISHED decides that. The query binds
 * one language (GDEFSTOR_Query::language; NULL reads `en`). The order ends
 * in creation order, which is the order of gdefcore_entity_ids(). Free
 * @p out_ids with gdefcore_ids_free().
 *
 * @param query A query over the type's fields and facts.
 * @param out_total Receives the matches before the offset and the limit. May
 *   be NULL.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_LIMIT (the
 *   query is over a cap of the query form), ::GDEFCORE_ERR_CORRUPT, or the
 *   store's error. An unknown type is an empty list.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_query_current(
    GDEFCORE_Catalog * catalog, const char * type_name, size_t type_name_len,
    const GDEFSTOR_Query * query, char *** out_ids, size_t * out_count,
    uint64_t * out_total);

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
 * @brief The creator of the newest revision (the revision's own creator), or
 * NULL when there is none.
 *
 * This is the principal that wrote the revision the entity currently is, set
 * when the revision was written and never taken from the publisher. It is not
 * the entity's creator (see gdefcore_entity_creator()): an editor who saves
 * someone's post is the creator of the revision they wrote, and of nothing
 * else. It is read whether or not the entity is published. A missing id is
 * ::GDEFCORE_ERR_INVALID. A row with no entity record is
 * ::GDEFCORE_ERR_CORRUPT. Free @p out_actor with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_actor(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_actor, size_t * out_len);

/**
 * @brief The entity's creator, or NULL when there is none.
 *
 * The principal of the entity's first revision, recorded on the entity
 * record at that revision and never changed: not by a later revision, a
 * revert, a publish or a clear. An entity whose first revision
 * had no actor has no creator, ever. `own` means this. A missing id is
 * ::GDEFCORE_ERR_INVALID. A row with no entity record is
 * ::GDEFCORE_ERR_CORRUPT. Free @p out_creator with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_creator(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, char ** out_creator, size_t * out_len);

/** The entity is not published: readers do not see it. */
#define GDEFCORE_STATE_DRAFT 1
/** The entity is published: readers see its newest revision. */
#define GDEFCORE_STATE_PUBLISHED 2

/**
 * @brief Whether the entity is published.
 *
 * ::GDEFCORE_STATE_PUBLISHED when the entity's published flag is set, whether
 * or not a draft sits beside its newest revision; otherwise
 * ::GDEFCORE_STATE_DRAFT, which includes an entity that was unpublished or
 * cleared. A missing id is ::GDEFCORE_ERR_INVALID and @p out_state is not
 * written. A row with no entity record is ::GDEFCORE_ERR_CORRUPT. Unfiltered,
 * like gdefcore_entity_values().
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
 * @brief How many entities the changeset writes: saves, drafts, publishes,
 * unpublishes, reverts and clears. Type definitions and module operations are not counted.
 */
GDEFCORE_API size_t gdefcore_changeset_touched_count(
    const GDEFCORE_Changeset * changeset);

/**
 * @brief One entity the changeset writes.
 *
 * @p out_id and @p out_type are borrowed from the changeset and are not
 * NUL-terminated. @p out_op receives ::GDEFCORE_TOUCH_SAVE,
 * ::GDEFCORE_TOUCH_DRAFT, ::GDEFCORE_TOUCH_PUBLISH,
 * ::GDEFCORE_TOUCH_CLEAR or ::GDEFCORE_TOUCH_UNPUBLISH. Any out pointer may be
 * NULL.
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

/**
 * @brief The logical type of the field at @p index, and its scale.
 *
 * A field declared before @ref GDEFCORE_Field::type existed is text.
 * Nothing is written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_type_field_type(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    size_t index, int * out_type, int * out_scale);

/**
 * @brief Read @p text as a value of logical @p type (and @p scale).
 *
 * The canonical texts gdefcore_entity_values() gives are read, and so are the
 * other spellings a save takes: leading zeros and a missing fraction of a
 * number, fewer milliseconds than three. A text or reference value points
 * into @p text. Type 0 is text. ::GDEFCORE_ERR_INVALID when it is not one.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_value_parse(int type, int scale,
    const char * text, size_t len, GDEFSTOR_Value * out);

/**
 * @brief Order two values of one type: negative, 0 or positive. Text and
 * references by bytes, numbers and dates by value.
 */
GDEFCORE_API int gdefcore_value_compare(const GDEFSTOR_Value * a,
    const GDEFSTOR_Value * b);

/**
 * @brief Say why: the reason every revision the changeset writes records
 * (AD-14: who, when and why). UTF-8, at most 4096 bytes; copied. NULL clears.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_set_why(
    GDEFCORE_Changeset * changeset, const char * why, size_t why_len);

/**
 * @brief After apply: the revision the changeset wrote for @p id, or 0 when
 * it wrote none (a save of values the entity already had, a publish with no
 * draft, a state change). ::GDEFCORE_ERR_INVALID when the changeset does not
 * touch @p id or was not applied.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_changeset_revision(
    const GDEFCORE_Changeset * changeset, const char * id, size_t id_len,
    uint64_t * out_revision);

/* ---- nested groups, multiples and order (story S6d) ---------------------- */

/** The parent of the root item of a GDEFCORE_Tree, and of a field of the root
 * group in a GDEFCORE_FieldInfo. */
#define GDEFCORE_TREE_ROOT SIZE_MAX

/** Bytes of a field path: names of at most ::GDEFSTOR_MODEL_MAX_DEPTH groups
 * and a field, each at most 64 bytes, joined by `.`. */
#define GDEFCORE_FIELD_PATH_MAX 600

/**
 * @brief One field of a type, at any depth, as gdefcore_type_tree_field()
 * describes it. @ref size is set by the caller.
 */
typedef struct GDEFCORE_FieldInfo {
  size_t size;                         ///< `sizeof(GDEFCORE_FieldInfo)`.
  char path[GDEFCORE_FIELD_PATH_MAX + 1]; ///< Its path, NUL-terminated.
  size_t path_len;                     ///< Length of @ref path.
  size_t name_at;                      ///< Where its own name starts in @ref path.
  size_t parent;                       ///< Index of its group, or ::GDEFCORE_TREE_ROOT.
  size_t depth;                        ///< 0 for a field of the root group.
  int type;                            ///< A ::GDEFSTOR_FieldType (GROUP for a group).
  int scale;                           ///< DECIMAL: digits after the point.
  int many;                            ///< Non-zero: it holds any number of items.
  int required;                        ///< Non-zero: a value (a group: an item) is required.
  int personal;                        ///< Non-zero: personal (AD-19).
  int indexed;                         ///< Non-zero: asked to be indexed.
  char subject[65];                    ///< PERSONAL: its subject field, or empty.
  size_t subject_len;                  ///< Length of @ref subject.
} GDEFCORE_FieldInfo;

/** @brief How many fields the type declares at every depth, groups included. */
GDEFCORE_API GDEFCORE_Result gdefcore_type_tree_field_count(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    size_t * out_count);

/**
 * @brief Describe field @p index of the type, in pre-order (each group before
 * its fields). @p out is written only on success.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_type_tree_field(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, GDEFCORE_FieldInfo * out);

/**
 * @brief One language's field tree of an entity, in texts (story S6d). Opaque.
 *
 * Item 0 is the root item: it holds the values of the root group's single
 * fields. Every other item sits under one field of its parent: a GROUP field
 * (the item holds that group's single fields, and items of its own) or a
 * MULTIPLE single field (the item holds one value, its own, set with an empty
 * field name). Values are texts, in their field type's canonical text as
 * gdefcore_entity_values() gives them. Items carry an id that is the port's
 * and is stable for the life of the item (AD-14): a tree for a save names an
 * item the entity has by its id and a new one by 0, and states order by the
 * order items are added. So a save that changes one item writes one item
 * version, and moving an item (adding the same items, with their ids, in
 * another order) changes only order keys.
 */
typedef struct GDEFCORE_Tree GDEFCORE_Tree;

/** @brief An empty tree: the root item, with no value. */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_create(GDEFCORE_Catalog * catalog,
    GDEFCORE_Tree ** out_tree);

/** @brief Release a tree. NULL is ignored. */
GDEFCORE_API void gdefcore_tree_free(GDEFCORE_Tree * tree);

/**
 * @brief Add an item under @p field of item @p parent, after its siblings.
 *
 * @param id 0 for a new item, or the id of an item the entity has now under
 *   the same field, in the same language (gdefcore_tree_item()).
 * @param out_item Receives the new item's index. May be NULL.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_LIMIT or
 *   ::GDEFCORE_ERR_OOM. Whether @p field is a group or a multiple field is
 *   checked when the tree is staged.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_add(GDEFCORE_Tree * tree,
    size_t parent, const char * field, size_t field_len, uint64_t id,
    size_t * out_item);

/**
 * @brief Set single field @p field of item @p item to @p text, replacing what
 * was set; for an item of a multiple field, @p field_len is 0 (its own
 * value). A NULL @p text unsets. The bytes are copied.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_set(GDEFCORE_Tree * tree,
    size_t item, const char * field, size_t field_len, const char * text,
    size_t len);

/** @return Items, the root included. */
GDEFCORE_API size_t gdefcore_tree_item_count(const GDEFCORE_Tree * tree);

/** One item. Pointers are valid until the tree is freed or changed. */
typedef struct GDEFCORE_TreeItem {
  size_t size;           ///< Set by the caller: `sizeof(GDEFCORE_TreeItem)`.
  uint64_t id;           ///< Its id; 0 for a new item.
  size_t parent;         ///< Its parent's index; ::GDEFCORE_TREE_ROOT for the root.
  const char * field;    ///< The field of the parent it sits under ("" for the root).
  size_t field_len;      ///< Its length.
  const char * path;     ///< That field's path from the root ("" for the root).
  size_t path_len;       ///< Its length.
  size_t value_count;    ///< Values set on it.
} GDEFCORE_TreeItem;

/**
 * @brief Describe item @p index. A parent comes before its children, and
 * siblings in their order.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_item(const GDEFCORE_Tree * tree,
    size_t index, GDEFCORE_TreeItem * out);

/**
 * @brief The @p k th value set on item @p item, and its field ("" for an
 * item's own value). Borrowed until the tree is freed or changed.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_value(const GDEFCORE_Tree * tree,
    size_t item, size_t k, const char ** out_field, size_t * out_field_len,
    const char ** out_text, size_t * out_len);

/**
 * @brief The value of @p field on item @p item, borrowed: @p out_text NULL
 * when there is none.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_get(const GDEFCORE_Tree * tree,
    size_t item, const char * field, size_t field_len, const char ** out_text,
    size_t * out_len);

/** @return The items directly under @p field of item @p item. */
GDEFCORE_API size_t gdefcore_tree_child_count(const GDEFCORE_Tree * tree,
    size_t item, const char * field, size_t field_len);

/**
 * @brief The index of the @p k th item directly under @p field of item
 * @p item, in order. ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_child(const GDEFCORE_Tree * tree,
    size_t item, const char * field, size_t field_len, size_t k,
    size_t * out_item);

/**
 * @brief Stage @p tree as language @p lang's whole new content of entity
 * @p id: the save of gdefcore_entity_save() (the next revision, published,
 * the draft consumed), with the tree in place of the language's values.
 *
 * Every field of the type may be in it, at every depth: the root's single
 * fields as values of the root item, multiple fields and groups as items.
 * What the tree leaves out is removed from the language, as the port's save
 * of a whole tree does (AD-14). Only what changed is written: an item named
 * by its id whose values and place are unchanged writes nothing, a reorder
 * writes order keys and nothing else, and a tree equal to the current one
 * writes no revision. Each value is checked against its field as
 * gdefcore_entity_save() checks one, at any depth; a field the type does not
 * have, a value set on a group, an item under a single field, a second item
 * of a field that is not multiple, a missing required field or item, or a
 * personal value that is not a sealed text the changeset accepts
 * (gdefcore_changeset_accept_sealed()) stages nothing and is
 * ::GDEFCORE_ERR_INVALID. A personal field inside a group takes its subject
 * from its subject field (GDEFCORE_Field::subject) in the same item.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_save(GDEFCORE_Changeset * changeset,
    const char * id, size_t id_len, const char * lang, size_t lang_len,
    const GDEFCORE_Tree * tree);

/** @brief gdefcore_tree_save() as the entity's draft, as
 * gdefcore_entity_save_draft() is to gdefcore_entity_save(). */
GDEFCORE_API GDEFCORE_Result gdefcore_tree_save_draft(
    GDEFCORE_Changeset * changeset, const char * id, size_t id_len,
    const char * lang, size_t lang_len, const GDEFCORE_Tree * tree);

/**
 * @brief Read language @p lang of an entity as a tree: what @p changeset
 * stages when it touches the entity, else the @p view of
 * gdefcore_entity_values(). Unfiltered, like gdefcore_entity_values();
 * gdefcore_access_tree() is a principal's read. An entity with no content in
 * that view or language is ::GDEFCORE_ERR_INVALID. Free @p out_tree with
 * gdefcore_tree_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_tree(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * changeset, int view, const char * id,
    size_t id_len, const char * lang, size_t lang_len, GDEFCORE_Tree ** out_tree);

/**
 * @brief Read language @p lang of recorded revision @p seq as a tree,
 * unfiltered, as gdefcore_entity_revision_values() reads one field.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_entity_revision_tree(
    GDEFCORE_Catalog * catalog, const char * id, size_t id_len, uint64_t seq,
    const char * lang, size_t lang_len, GDEFCORE_Tree ** out_tree);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_ENTITY_H */
