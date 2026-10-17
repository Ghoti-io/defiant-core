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
 * @file condition.h
 * @brief Conditions as data: parse, validate, canonical text, explain, eval.
 * @stability free
 *
 * A condition is a small boolean expression stored as text
 * (`defiant-condition/3`, AD-34). A grant carries one. The text is an
 * s-expression; documentation/conditions.md gives the grammar. In short:
 *
 *     (and (= type "site.blog") (in field.group ("a" "b")))
 *
 * Operands: `type`, `state`, `creator`, `revision.creator`, `principal`,
 * `now`, `field.<name>`, text constants and integer constants. `creator` is
 * who created the entity (immutable, and what `own` means);
 * `revision.creator` is who wrote the revision that is now active. Edition 1
 * called the second `actor`; see gdefcore_condition_upcast(). Operators: `=`, `!=`, `<`, `<=`,
 * `>`, `>=`, `in`, `and`, `or`, `not`, and the words `true` and `false`.
 * `(related "<relation>" (<operand> ...))` holds when a module's relation
 * (module.h) has a row whose columns equal the listed operands, in order; an
 * operand `_` leaves its column free. At most four relations in one condition.
 *
 * Hard limits, enforced at parse: depth 16, 256 nodes, 4096 bytes of text,
 * a constant of at most 256 bytes. The input is UTF-8 with no NUL.
 *
 * Nothing here denies. A condition only narrows what a grant covers, and any
 * failure to evaluate one is "does not hold" (AD-10, AD-11).
 */

#ifndef GHOTI_IO_GDEFCORE_CONDITION_H
#define GHOTI_IO_GDEFCORE_CONDITION_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The registered format name and version (AD-34). */
#define GDEFCORE_CONDITION_FORMAT "defiant-condition/3"
/** The editions before it, whose stored text gdefcore_condition_upcast() reads. */
#define GDEFCORE_CONDITION_FORMAT_PREVIOUS "defiant-condition/2"
/** The edition before that one. */
#define GDEFCORE_CONDITION_FORMAT_FIRST "defiant-condition/1"
/** Most relations one condition may name. */
#define GDEFCORE_CONDITION_MAX_RELATIONS 4
/** Most operands one `related` takes (a relation's columns). */
#define GDEFCORE_CONDITION_MAX_RELATED_OPERANDS 4
/** Deepest nesting of parentheses. */
#define GDEFCORE_CONDITION_MAX_DEPTH 16
/** Most nodes (operators, operands, constants, list members) in one condition. */
#define GDEFCORE_CONDITION_MAX_NODES 256
/** Most bytes of condition text. */
#define GDEFCORE_CONDITION_MAX_BYTES 4096
/** Most bytes in one text constant, after escapes are decoded. */
#define GDEFCORE_CONDITION_MAX_CONSTANT 256
/** Length of a hash in hex, not counting the NUL. */
#define GDEFCORE_CONDITION_HASH_LEN 64

/** The condition reads the request principal (`principal`, `creator` or
 * `revision.creator`). */
#define GDEFCORE_CONDITION_USES_PRINCIPAL 1
/** The condition reads the entity (`state`, `creator`, `revision.creator` or
 * a field). */
#define GDEFCORE_CONDITION_USES_ENTITY 2
/** The condition reads the request time (`now`). */
#define GDEFCORE_CONDITION_USES_TIME 4
/** The condition reads a relation (`related`). */
#define GDEFCORE_CONDITION_USES_RELATION 8

/** The grant covers every entity of the type: `(= type "<T>")`. */
#define GDEFCORE_CONDITION_BUILTIN_ANY 1
/** The grant covers the entity's creator:
 * `(and (= type "<T>") (= creator principal))`. */
#define GDEFCORE_CONDITION_BUILTIN_OWN 2

/** A parsed condition. Opaque. Free with gdefcore_condition_free(). */
typedef struct GDEFCORE_Condition GDEFCORE_Condition;

/**
 * @brief Where and why a condition was refused. Begins with @ref size.
 *
 * @ref message is one of a fixed set of static strings. It never points into
 * the input and never contains input bytes.
 */
typedef struct GDEFCORE_Condition_Error {
  size_t size;            ///< Must be `sizeof(GDEFCORE_Condition_Error)`.
  size_t offset;          ///< Byte offset in the text given to parse.
  const char * message;   ///< Static, NUL-terminated.
} GDEFCORE_Condition_Error;

/**
 * @brief What gdefcore_condition_eval() evaluates on. Begins with @ref size.
 *
 * With @ref entity set, the entity is read as the system. With it NULL and
 * @ref type_name set, the condition is evaluated on a hypothetical entity of
 * that type that has no state, no actor and no values (the question "could
 * this grant apply to anything?", used where no entity exists yet). With
 * neither, nothing holds.
 */
typedef struct GDEFCORE_Condition_Subject {
  size_t size;               ///< Must be `sizeof(GDEFCORE_Condition_Subject)`.
  const char * entity;       ///< Public id, or NULL.
  size_t entity_len;         ///< Length of @ref entity.
  const char * type_name;    ///< Type of the hypothetical entity, or NULL.
  size_t type_name_len;      ///< Length of @ref type_name.
  const char * lang;         ///< Language of field values. NULL means `en`.
  size_t lang_len;           ///< Length of @ref lang.
} GDEFCORE_Condition_Subject;

/**
 * @brief Parse condition text. Pure: no catalog, no request.
 *
 * @param text Condition text. Need not be NUL-terminated.
 * @param len Length of @p text.
 * @param out_condition Receives the parsed condition on success. NULL when
 *        only the check is wanted.
 * @param out_error Receives the offset and message when refused. May be NULL.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID (the text is refused; nothing
 *         is allocated) or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_parse(const char * text,
    size_t len, GDEFCORE_Condition ** out_condition,
    GDEFCORE_Condition_Error * out_error);

/** @brief Free a parsed condition. NULL is ignored. */
GDEFCORE_API void gdefcore_condition_free(GDEFCORE_Condition * condition);

/**
 * @brief Check a parsed condition against the catalog for @p type_name.
 *
 * Every `field.<name>` must name a field the type has, and that field must
 * not be personal (AD-19: a personal field is refused with the same message
 * as a field the type does not have). A type constant compared with `type`
 * must name a defined type. A state constant compared with `state` must be
 * `published` or `draft`.
 *
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID with @p out_error set.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_validate(
    GDEFCORE_Catalog * catalog, const GDEFCORE_Condition * condition,
    const char * type_name, size_t type_name_len,
    GDEFCORE_Condition_Error * out_error);

/**
 * @brief gdefcore_condition_validate() for a condition that will hold when
 * @p projection is applied.
 *
 * A `related` is checked against the relations of the modules enabled and,
 * when @p projection is not NULL, of the modules that changeset enables or
 * disables: the relation must be declared, the operands must be as many as its
 * columns, and each operand's kind must suit its column (an entity column takes
 * `principal`, `creator`, `revision.creator`, a field or a public id; an integer
 * column an integer, `now` or a field; a text column anything). The error says
 * which, at the byte offset of the clause or the operand.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_validate_in(
    GDEFCORE_Catalog * catalog, const GDEFCORE_Condition * condition,
    const char * type_name, size_t type_name_len,
    const GDEFCORE_Changeset * projection, GDEFCORE_Condition_Error * out_error);

/**
 * @brief The canonical text of @p condition.
 *
 * Whitespace is single spaces. The operands of `and` and `or` are flattened
 * (a nested `and` inside an `and` is merged), sorted bytewise by their own
 * canonical text and de-duplicated; an `and` or `or` left with one operand is
 * that operand. The constants of `in` are sorted and de-duplicated. Integers
 * lose leading zeros. Parsing the canonical text and serializing again gives
 * the same bytes. These bytes are what is stored and hashed.
 *
 * Free @p out_text with gdefcore_condition_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_canonical(
    const GDEFCORE_Condition * condition, char ** out_text, size_t * out_len);

/** @brief Free text from this header. NULL is ignored. */
GDEFCORE_API void gdefcore_condition_text_free(char * text);

/**
 * @brief Read condition text written in an earlier edition as the current one.
 *
 * Edition 1 named the operand for who wrote the entity's content `actor`.
 * Edition 2 splits it: `creator` (the entity's, immutable) and
 * `revision.creator` (the active revision's). A stored `actor` meant the
 * second, so from edition 1 this renames that one operand to
 * `revision.creator`, leaving text constants alone. From edition 2 it copies.
 * Text already in edition 2 has no bare `actor`, so upcasting it is the
 * identity and a stored condition need not say which edition it is in.
 * Free @p out_text with gdefcore_condition_text_free().
 *
 * Edition 3 added `related` and changed nothing else, so from edition 2 or 3
 * the text is copied, `related` clauses and all.
 *
 * @param from_edition 1, 2 or 3; anything else is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_upcast(const char * text,
    size_t len, int from_edition, char ** out_text, size_t * out_len);

/**
 * @brief gdefcore_condition_parse() for text read from storage: upcast from
 * edition 1 first.
 *
 * Text a person writes now goes to gdefcore_condition_parse(), which refuses
 * `actor`; text read back from a stored grant or a module's manifest goes
 * here.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_parse_stored(const char * text,
    size_t len, GDEFCORE_Condition ** out_condition,
    GDEFCORE_Condition_Error * out_error);

/**
 * @brief SHA-256 of the canonical text of @p text, in lowercase hex.
 *
 * Two spellings of one condition have one hash. @p out_hash receives
 * ::GDEFCORE_CONDITION_HASH_LEN characters and a NUL.
 *
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID with @p out_error set.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_hash(const char * text,
    size_t len, char out_hash[GDEFCORE_CONDITION_HASH_LEN + 1],
    GDEFCORE_Condition_Error * out_error);

/**
 * @brief The canonical text of a built-in: any or own, for @p type_name.
 *
 * @p builtin is ::GDEFCORE_CONDITION_BUILTIN_ANY or
 * ::GDEFCORE_CONDITION_BUILTIN_OWN. Free @p out_text with
 * gdefcore_condition_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_builtin(int builtin,
    const char * type_name, size_t type_name_len, char ** out_text,
    size_t * out_len);

/**
 * @brief Which parts of the world the condition reads.
 *
 * A bit set of the `GDEFCORE_CONDITION_USES_` values. 0 for NULL.
 */
GDEFCORE_API unsigned gdefcore_condition_uses(
    const GDEFCORE_Condition * condition);

/**
 * @brief Whether @p condition can hold only for entities of some stated type.
 * True when `type` is an operand of an equality or an `in` that every way of
 * satisfying the condition must pass (an operand of an `and`, or of every
 * operand of an `or`). `not` never counts. The access matrix uses this to
 * tell a grant that is bounded by a type from one that is not. 0 for NULL.
 */
GDEFCORE_API int gdefcore_condition_constrains_type(
    const GDEFCORE_Condition * condition);

/**
 * @brief The names of the relations @p condition tests, in order of first use.
 *
 * @param index Zero-based, below ::GDEFCORE_CONDITION_MAX_RELATIONS.
 * @param out_name Receives a pointer into the condition (valid until it is
 *   freed) and @p out_len its length.
 * @return 1 when there is such a relation, else 0.
 */
GDEFCORE_API int gdefcore_condition_relation_at(
    const GDEFCORE_Condition * condition, size_t index, const char ** out_name,
    size_t * out_len);

/**
 * @brief Whether @p condition reads the entity field @p field anywhere, even
 * under `not`. A NULL @p field asks whether it reads any field at all. The
 * access matrix uses this to find a grant whose holder could change what its
 * own condition tests. 0 for a NULL condition.
 */
GDEFCORE_API int gdefcore_condition_tests_field(
    const GDEFCORE_Condition * condition, const char * field, size_t field_len);

/**
 * @brief Plain English for @p condition. English only; deterministic.
 *
 * Built from the canonical form, so two spellings of one condition read
 * alike. It is text, escaped nowhere: callers escape for their output. It
 * names fields and constants the author wrote, never an entity's values.
 * Free @p out_text with gdefcore_condition_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_condition_explain(
    const GDEFCORE_Condition * condition, char ** out_text, size_t * out_len);

/**
 * @brief Whether @p condition holds on one entity.
 *
 * The entity is read as the system, unfiltered: this is not the access
 * decision, it is one input to it, and a true answer tells its caller that
 * the entity exists and what it holds. Only the host may call it, with a
 * condition an administrator or a module wrote and an id the host chose;
 * never a condition or an id a principal supplied.
 *
 * The principal and the time come from @p request. An entity that does not
 * exist, an id that is not an id, or a NULL argument is "does not hold" and
 * sets nothing (a hidden entity and a missing one answer alike). Anything
 * else that goes wrong (an allocation, a storage error, a field that is
 * personal or gone from the type, a field with more than 64 values) is
 * "does not hold" too, even under `not`, and sets @p out_failed to 1.
 * @p out_failed is set to 0 first and may be NULL.
 *
 * @return 1 when the condition holds, else 0. Never an error.
 */
GDEFCORE_API int gdefcore_condition_eval(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Condition * condition,
    const GDEFCORE_Condition_Subject * subject, int * out_failed);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_CONDITION_H */
