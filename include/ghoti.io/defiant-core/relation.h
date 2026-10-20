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
 * @file relation.h
 * @brief The rows of the relations that modules declare: writing them.
 * @stability free
 *
 * A module declares a relation in its manifest (module.h): a name in its own
 * namespace and one to four typed columns. The rows are entities of a kernel
 * type, `core.relation_row`, one per row: a `relation` field with the
 * relation's name and, per column, a text field `c0` to `c3` (an entity or a
 * text column) or an integer field `n0` to `n3` (an integer column), so that a
 * column is compared in its own type. They are business data
 * (SPEC decision 6): an entity column holds the public id of what it refers
 * to, and keeps holding it when the person it names is erased; no personal
 * value is ever stored in one.
 *
 * **There is no call here that reads rows.** A relation is read as the system,
 * only to decide a condition (`related` in condition.h) and only by the
 * evaluator and the list compiler, which read only a relation that an enabled
 * module declares and only its declared columns. What rows a handler of the
 * owning module may see of its own relation is the module's to expose, through
 * the access filter like any other entity: the type has no permission, so a
 * principal reads and lists none of them.
 *
 * **Who may write.** Protection is on the path, not the function (SPEC
 * decision 7), so these calls check no principal. They check what the
 * declaration says: the relation must be one the named module declares, and
 * the module must be enabled for the tenant. The module's name is the one
 * thing a caller states, and a module's code states its own; a call that names
 * another module's relation is refused. (There is no ambient "current module"
 * in a C call to check it against, so a module that lies about its name is
 * stopped only by the path that reaches its code.) The row's creator is the
 * @p actor.
 */

#ifndef GHOTI_IO_GDEFCORE_RELATION_H
#define GHOTI_IO_GDEFCORE_RELATION_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The kernel type of a relation row. */
#define GDEFCORE_RELATION_ROW_TYPE "core.relation_row"
/** The kernel type of a relation's state: one entity per relation that has had
 * a row, whose version counter is the relation's version (its `changes`
 * field counts the changes, so each one writes a revision). */
#define GDEFCORE_RELATION_STATE_TYPE "core.relation"
/** The field of a row that holds the relation's name. */
#define GDEFCORE_RELATION_FIELD_NAME "relation"
/** The language a row's fields are stored in. */
#define GDEFCORE_RELATION_LANG "en"

/**
 * @brief The text field that holds entity or text column @p index of a row:
 * "c0" to "c3".
 *
 * @return A static string, or NULL for an index of 4 or more.
 */
GDEFCORE_API const char * gdefcore_relation_column_field(size_t index);

/**
 * @brief The field that holds integer column @p index of a row: "n0" to "n3".
 *
 * @return A static string, or NULL for an index of 4 or more.
 */
GDEFCORE_API const char * gdefcore_relation_number_field(size_t index);

/**
 * @brief Add a row to a relation.
 *
 * Adding a row that is already there changes nothing, not even the version.
 * Each value is checked against its column: an entity column takes a public
 * id (stored in its canonical form; whether the entity exists is not asked),
 * an integer column `-?[0-9]{1,18}` (stored without leading zeros), a text
 * column UTF-8 of at most 256 bytes. The row, and the bump of the relation's
 * version, are one changeset.
 *
 * @param catalog A catalog with a host bound (gdefcore_catalog_bind_host()).
 * @param module The module that declares the relation.
 * @param relation The relation's name.
 * @param values One text per column, in order.
 * @param value_lens Their lengths.
 * @param count How many; the relation's number of columns.
 * @param actor The row's creator (a public id), or NULL.
 * @param out_added Receives 1 when a row was added, 0 when it was there. May
 *   be NULL.
 * @return ::GDEFCORE_OK; ::GDEFCORE_ERR_INVALID for a relation the module does
 *   not declare or has not enabled, a count that is not the columns, or a value
 *   that does not suit its column; or the changeset's error (a stale epoch
 *   writes nothing, and the call may be repeated).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_relation_add(GDEFCORE_Catalog * catalog,
    const char * module, size_t module_len, const char * relation,
    size_t relation_len, const char * const * values, const size_t * value_lens,
    size_t count, const char * actor, size_t actor_len, int * out_added);

/**
 * @brief Remove the rows of a relation that match.
 *
 * A NULL entry in @p values is a column left free. With every column free,
 * every row of the relation goes. Nothing matching is success with nothing
 * removed and the version unchanged. Otherwise the rows are cleared and the
 * version is bumped in one changeset. The same checks as
 * gdefcore_relation_add().
 *
 * @param out_removed Receives how many rows were removed. May be NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_relation_remove(
    GDEFCORE_Catalog * catalog, const char * module, size_t module_len,
    const char * relation, size_t relation_len, const char * const * values,
    const size_t * value_lens, size_t count, const char * actor,
    size_t actor_len, size_t * out_removed);

/**
 * @brief The version of a relation: a counter that every change to its rows
 * bumps, 0 for a relation that has never had a row. It is not the rows.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_relation_version(
    GDEFCORE_Catalog * catalog, const char * relation, size_t relation_len,
    uint64_t * out_version);

/**
 * @brief Note on @p request that a decision read the relation, at its version.
 *
 * The relation is recorded as a dependency (gdefcore_request_record_dependency())
 * under a stable id derived from its name, with its version as the revision, so
 * the render key's `reads:` digest changes when the relation's rows do and a
 * fragment that used it is invalid (AD-26). The evaluator and the list
 * compiler call this; it reads the counter and nothing else.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_relation_note_dependency(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const char * relation, size_t relation_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_RELATION_H */
