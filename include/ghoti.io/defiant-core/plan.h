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
 * @file plan.h
 * @brief A condition compiled into the storage port's query form.
 * @stability free
 *
 * A list is the entities a principal may see, counted and paged. The access
 * layer builds that as a storage query (defiant-storage query.h) so that the
 * store, not this library, finds the rows, and the count and the pages are of
 * what the principal may see. This is the part that turns the language of
 * condition.h into that query's predicate tree.
 *
 * A plan is an arena for one list: the entity type, the language the fields
 * are read in, and the principal and clock a condition's operands take. It
 * builds nodes and owns them until gdefcore_plan_free(). Nothing here reads
 * the store: it compiles. The evaluator (gdefcore_condition_eval()) is the
 * reference; the compiled predicate selects exactly the entities it holds
 * on, in the same cases, including the ones where it cannot decide:
 *
 * - `and` and `or` stop at the first operand that decides them, and a
 *   condition that cannot be decided (a personal field, which is ciphertext,
 *   or a field the type no longer has) fails only when evaluation reaches it,
 *   and then the whole condition does not hold, `not` included. The compiled
 *   form carries the "reached" condition as a second predicate.
 * - `state` is the published fact of the entity: "published" when it is
 *   set, else "draft".
 * - `creator` is the entity's creator and `revision.creator` the author of
 *   its newest revision, each none (not the empty text) when absent; a field
 *   with no value in the plan's language is the single empty text.
 * - Fields are typed, and compared as condition.h says.
 * - `now` and `principal` are the plan's, as constants.
 *
 * The predicate is of the port's form over entities: it reads the current
 * trees of the plan's language, and a relation as an EXISTS over its rows,
 * which are kept in their own language (relation.h).
 *
 * Every builder returns NULL when it could not build (out of memory, or a
 * plan grown past ::GDEFCORE_PLAN_MAX_NODES, or something the query form
 * cannot say). gdefcore_plan_unsupported() then says so and the caller does
 * what it does without a plan; the answer must be the same.
 */

#ifndef GHOTI_IO_GDEFCORE_PLAN_H
#define GHOTI_IO_GDEFCORE_PLAN_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-storage/query.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Nodes one plan builds before it stops. Under the storage form's own cap. */
#define GDEFCORE_PLAN_MAX_NODES 6000

/** A plan. Opaque. Free with gdefcore_plan_free(). */
typedef struct GDEFCORE_Plan GDEFCORE_Plan;

/**
 * @brief Begin a plan for lists of one type.
 *
 * @param catalog The catalog whose type declarations say which fields exist,
 *   which are personal and which hold several values. Borrowed until the plan
 *   is freed.
 * @param type_name The entity type. Copied.
 * @param lang The language fields are read in. Copied. The port's query
 *   binds one language (GDEFSTOR_Query::language) and the plan's nodes carry
 *   none, so a query built from them must bind this one; a relation's EXISTS
 *   names its rows' own.
 * @param principal The request's principal, or NULL for none. Copied.
 * @param now The request clock, in seconds.
 * @param out_plan Receives the plan.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_plan_create(GDEFCORE_Catalog * catalog,
    const char * type_name, size_t type_name_len, const char * lang,
    size_t lang_len, const char * principal, size_t principal_len, int64_t now,
    GDEFCORE_Plan ** out_plan);

/** @brief Free a plan and every node it built. NULL is ignored. */
GDEFCORE_API void gdefcore_plan_free(GDEFCORE_Plan * plan);

/** @return 1 when a builder returned NULL for a reason other than memory. */
GDEFCORE_API int gdefcore_plan_unsupported(const GDEFCORE_Plan * plan);

/** @return 1 when a builder returned NULL because memory ran out. */
GDEFCORE_API int gdefcore_plan_oom(const GDEFCORE_Plan * plan);

/**
 * @return 1 when a condition compiled into the plan can fail to decide: it
 * names a personal field or a field the type does not have. The evaluator marks
 * a request when it reaches one; the plan cannot say whether any entity does.
 */
GDEFCORE_API int gdefcore_plan_failed(const GDEFCORE_Plan * plan);

/** @brief A predicate that holds on every row (@p value non-zero) or none. */
GDEFCORE_API const GDEFSTOR_QueryNode * gdefcore_plan_constant(
    GDEFCORE_Plan * plan, int value);

/** @brief The entity is published: its record's flag is set. */
GDEFCORE_API const GDEFSTOR_QueryNode * gdefcore_plan_published(
    GDEFCORE_Plan * plan);

/** @brief The entity's creator is the plan's principal (never, with none). */
GDEFCORE_API const GDEFSTOR_QueryNode * gdefcore_plan_creator_is_principal(
    GDEFCORE_Plan * plan);

/**
 * @brief The predicate that @p condition holds on the entity.
 *
 * Equal, entity for entity, to gdefcore_condition_eval() answering 1 with
 * its failure flag clear or set (a failure is a no).
 */
GDEFCORE_API const GDEFSTOR_QueryNode * gdefcore_plan_condition(
    GDEFCORE_Plan * plan, const GDEFCORE_Condition * condition);

/** @brief Every child holds. No children is true. */
GDEFCORE_API const GDEFSTOR_QueryNode * gdefcore_plan_and(GDEFCORE_Plan * plan,
    const GDEFSTOR_QueryNode * const * children, size_t count);

/** @brief Some child holds. No children is false. */
GDEFCORE_API const GDEFSTOR_QueryNode * gdefcore_plan_or(GDEFCORE_Plan * plan,
    const GDEFSTOR_QueryNode * const * children, size_t count);

/**
 * @brief A field of the entity has the value @p text, other than "-" (the
 * mark the access list's filter has always ignored), read in the field's
 * type: a text that is no value of it matches nothing. A field with no value
 * has none, and so matches nothing. NULL for a personal field or one the
 * type lacks, with the plan marked unsupported: those are read as stored.
 */
GDEFCORE_API const GDEFSTOR_QueryNode * gdefcore_plan_field_is(
    GDEFCORE_Plan * plan, const char * field, size_t field_len,
    const char * text, size_t text_len);

/**
 * @brief How many relations the compiled conditions test, and their names.
 *
 * A list that used a relation reads its version (relation.h) into the
 * request's read set, so that the render key's `reads:` digest moves with the
 * rows. @p index is zero-based; the name is valid until the plan is freed.
 */
GDEFCORE_API size_t gdefcore_plan_relation_count(const GDEFCORE_Plan * plan);

/** @brief The @p index-th relation named. 1 when there is one, else 0. */
GDEFCORE_API int gdefcore_plan_relation_at(const GDEFCORE_Plan * plan,
    size_t index, const char ** out_name, size_t * out_len);

/**
 * @brief A sort key: the first value of a field (by its order in the
 * entity), in the field's type; a text or reference with none sorts as the
 * empty text, any other field with none first. NULL under the same rules as
 * gdefcore_plan_field_is().
 */
GDEFCORE_API const GDEFSTOR_QuerySort * gdefcore_plan_sort_field(
    GDEFCORE_Plan * plan, const char * field, size_t field_len,
    int descending);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_PLAN_H */
