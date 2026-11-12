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
 * @file view.h
 * @brief Views as data: a stored list of entities with a condition tree,
 * arguments, columns, formatters and a set format.
 * @stability free
 *
 * A view is a configuration entity of the type ::GDEFCORE_VIEW_TYPE. It names
 * an entity type, an optional condition (`defiant-condition/1`, so the
 * and/or/not tree is the condition's own), up to two sort keys, the columns
 * to show with a formatter each, the arguments the condition may name, a set
 * format and a page size. Saving one validates all of it (gdefcore_view_stage())
 * and a stored one that no longer validates because its type changed is
 * refused when run, never run loosely.
 *
 * **Arguments.** The condition names an argument as a bare `$name` where a
 * constant may stand. Each argument has a source: `url` (a token the caller
 * read from the path), `exposed` (a value the visitor chose), `principal` (the
 * request's own principal, which is what "my own" means, AD-11) or `fixed` (a
 * constant stored with the view). The value is put into the condition as a
 * quoted constant with `"` and `\` escaped and nothing else: it can never
 * become an operator, a field or another clause, whatever it holds. A value
 * the condition language cannot hold (a control character, over 256 bytes) is
 * refused with ::GDEFCORE_ERR_INVALID, and an argument with no value makes the
 * view return no rows, never every row.
 *
 * **Access.** A view reads through the access filter (gdefcore_access_list_page()
 * and gdefcore_access_read()): a row the principal may not see is not in the
 * result and not in the total, and a field the principal may not read is an
 * empty cell, the same as one with no value. The condition narrows, as a
 * grant's does, and never widens. No HTML is made here: a cell is text, which
 * the caller draws escaped.
 *
 * **Columns** are fields of the type's root that hold values (a group is not a
 * column). A many-valued field is shown with the `join`
 * or `count` formatter.
 *
 * The tables the editor offers and the save checks are one: gdefcore_view_operators()
 * and gdefcore_view_formatters() give the operators and formatters a field of
 * each kind may use.
 */

#ifndef GHOTI_IO_GDEFCORE_VIEW_H
#define GHOTI_IO_GDEFCORE_VIEW_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The configuration type a view is stored as. */
#define GDEFCORE_VIEW_TYPE "core.query"
/** The most columns a view may have. */
#define GDEFCORE_VIEW_MAX_COLUMNS 16
/** The most arguments a view may declare. */
#define GDEFCORE_VIEW_MAX_ARGS 8
/** The most rows one run returns, whatever the page size asks. */
#define GDEFCORE_VIEW_MAX_ROWS 200

/** An argument's source: what supplies its value. */
typedef enum GDEFCORE_View_Source {
  GDEFCORE_VIEW_SOURCE_URL = 1,       ///< A token the caller read from the path.
  GDEFCORE_VIEW_SOURCE_EXPOSED = 2,   ///< A value the visitor chose.
  GDEFCORE_VIEW_SOURCE_PRINCIPAL = 3, ///< The request's principal.
  GDEFCORE_VIEW_SOURCE_FIXED = 4      ///< A constant stored with the view.
} GDEFCORE_View_Source;

/** How a set of rows is written out. */
typedef enum GDEFCORE_View_Format {
  GDEFCORE_VIEW_FORMAT_TABLE = 1, ///< Rows of cells, drawn by the caller.
  GDEFCORE_VIEW_FORMAT_LIST = 2,  ///< A list of rows, drawn by the caller.
  GDEFCORE_VIEW_FORMAT_CSV = 3,   ///< RFC 4180 text, see gdefcore_view_result_text().
  GDEFCORE_VIEW_FORMAT_JSON = 4   ///< A JSON array of objects, as text.
} GDEFCORE_View_Format;

/** One column of a view. */
typedef struct GDEFCORE_View_Column {
  size_t size;               ///< Must be `sizeof(GDEFCORE_View_Column)`.
  const char * field;        ///< A root field of the type that holds values.
  size_t field_len;          ///< Length of @ref field.
  const char * formatter;    ///< A formatter of gdefcore_view_formatters(), or NULL for `raw`.
  size_t formatter_len;      ///< Length of @ref formatter.
  const char * label;        ///< The heading; NULL or empty is the field's name.
  size_t label_len;          ///< Length of @ref label.
} GDEFCORE_View_Column;

/** One argument a view's condition may name. */
typedef struct GDEFCORE_View_Arg {
  size_t size;               ///< Must be `sizeof(GDEFCORE_View_Arg)`.
  const char * name;         ///< Lowercase letters, digits, `-` and `_`.
  size_t name_len;           ///< Length of @ref name.
  int source;                ///< A ::GDEFCORE_View_Source.
  const char * fixed;        ///< The value of a `fixed` argument, or the default of a url or exposed one.
  size_t fixed_len;          ///< Length of @ref fixed.
} GDEFCORE_View_Arg;

/** A view as it is stored. Strings are not copied by a save. */
typedef struct GDEFCORE_View_Def {
  size_t size;               ///< Must be `sizeof(GDEFCORE_View_Def)`.
  const char * name;         ///< Machine name; unique among views.
  size_t name_len;           ///< Length of @ref name.
  const char * type;         ///< The entity type listed.
  size_t type_len;           ///< Length of @ref type.
  const char * condition;    ///< `defiant-condition/1` with `$name` arguments, or NULL.
  size_t condition_len;      ///< Length of @ref condition.
  const char * sort;         ///< First sort key, a root field, or NULL.
  size_t sort_len;           ///< Length of @ref sort.
  int sort_descending;       ///< Non-zero reverses the first key.
  const char * sort2;        ///< Second sort key, or NULL.
  size_t sort2_len;          ///< Length of @ref sort2.
  int sort2_descending;      ///< Non-zero reverses the second key.
  const GDEFCORE_View_Column * columns; ///< At least one.
  size_t column_count;       ///< How many in @ref columns.
  const GDEFCORE_View_Arg * args; ///< May be NULL.
  size_t arg_count;          ///< How many in @ref args.
  int format;                ///< A ::GDEFCORE_View_Format.
  uint64_t limit;            ///< Rows in a page, 1 to ::GDEFCORE_VIEW_MAX_ROWS.
} GDEFCORE_View_Def;

/** A value a caller supplies for an argument of the view it runs. */
typedef struct GDEFCORE_View_Param {
  size_t size;               ///< Must be `sizeof(GDEFCORE_View_Param)`.
  const char * name;         ///< The argument's name.
  size_t name_len;           ///< Length of @ref name.
  const char * value;        ///< Its value.
  size_t value_len;          ///< Length of @ref value.
} GDEFCORE_View_Param;

/** The rows of one run. Opaque; free with gdefcore_view_result_free(). */
typedef struct GDEFCORE_View_Result GDEFCORE_View_Result;

/**
 * @brief Declare the view type, once; it is already declared when it is.
 *
 * Called with the rest of the render layer's types and by the admin area.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_view_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief Check @p def against the catalog and say why it is refused.
 *
 * The type exists and has no personal field named; every sort key and column
 * is a root field that holds values and is not personal; each formatter suits
 * its field's kind (gdefcore_view_formatters()); the condition parses,
 * validates against the type with each `$name` standing as a constant, and
 * names only declared arguments, each declared one at least once; names are
 * well formed and unique; the format and the limit are in range. @p why, when
 * not NULL, receives a short reason of at most @p why_cap bytes (NUL
 * included) on a refusal. ::GDEFCORE_ERR_INVALID is a refusal.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_view_validate(GDEFCORE_Catalog * catalog,
    const GDEFCORE_View_Def * def, char * why, size_t why_cap);

/**
 * @brief Stage @p def as the view of its name: a new entity, or the saved
 * view's next revision, in @p changeset.
 *
 * Validated first (gdefcore_view_validate()); a refusal stages nothing and
 * its reason is gdefcore_changeset_refusal(). The change is a configuration
 * change, so applying it needs the type's name typed as the confirmation.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_view_stage(GDEFCORE_Changeset * changeset,
    const GDEFCORE_View_Def * def);

/**
 * @brief The names of the stored views, sorted. Free with
 * gdefcore_view_names_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_view_names(GDEFCORE_Catalog * catalog,
    char *** out_names, size_t * out_count);

/** @brief Free the names of gdefcore_view_names(). NULL is ignored. */
GDEFCORE_API void gdefcore_view_names_free(GDEFCORE_Catalog * catalog,
    char ** names, size_t count);

/**
 * @brief Read the view called @p name into @p out.
 *
 * The strings of @p out live until gdefcore_view_def_free() is called with
 * @p out_owner. ::GDEFCORE_ERR_INVALID when there is no such view.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_view_get(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, GDEFCORE_View_Def * out, void ** out_owner);

/** @brief Release what gdefcore_view_get() allocated. NULL is ignored. */
GDEFCORE_API void gdefcore_view_def_free(GDEFCORE_Catalog * catalog, void * owner);

/**
 * @brief Run the view called @p name for @p request's principal.
 *
 * @p params are the values for its `url` and `exposed` arguments. @p offset
 * rows are skipped. The rows are those the principal may see, in the view's
 * order, a page of the view's limit; the total is the number the principal may
 * see that match. A stored view that no longer validates, an argument value
 * the condition cannot hold, or an unknown name is ::GDEFCORE_ERR_INVALID with
 * nothing returned. Free @p out_result with gdefcore_view_result_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_view_run(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * name, size_t name_len,
    const GDEFCORE_View_Param * params, size_t param_count, uint64_t offset,
    GDEFCORE_View_Result ** out_result);

/** @brief The set format the view asks for (::GDEFCORE_View_Format). */
GDEFCORE_API int gdefcore_view_result_format(const GDEFCORE_View_Result * result);
/** @brief Rows in the page. */
GDEFCORE_API size_t gdefcore_view_result_rows(const GDEFCORE_View_Result * result);
/** @brief Rows the principal may see that match, before the page. */
GDEFCORE_API uint64_t gdefcore_view_result_total(const GDEFCORE_View_Result * result);
/** @brief Columns of every row. */
GDEFCORE_API size_t gdefcore_view_result_columns(const GDEFCORE_View_Result * result);
/** @brief The heading of column @p column. Valid until the result is freed. */
GDEFCORE_API const char * gdefcore_view_result_label(
    const GDEFCORE_View_Result * result, size_t column, size_t * out_len);
/** @brief The public id of row @p row. Valid until the result is freed. */
GDEFCORE_API const char * gdefcore_view_result_id(
    const GDEFCORE_View_Result * result, size_t row);
/**
 * @brief The cell at @p row and @p column, formatted, as text to be escaped
 * by whoever draws it. An empty cell is empty, not NULL.
 */
GDEFCORE_API const char * gdefcore_view_result_cell(
    const GDEFCORE_View_Result * result, size_t row, size_t column,
    size_t * out_len);

/**
 * @brief The whole page written as the view's format: CSV or JSON text. A
 * table or list format is ::GDEFCORE_ERR_INVALID (the caller draws those).
 *
 * CSV quotes a cell holding a comma, a quote, a CR or LF, doubles its quotes,
 * ends rows with CRLF, and prefixes a cell that starts with `=`, `+`, `-`, `@`,
 * TAB or CR with `'` so a spreadsheet does not run it. JSON is an array of
 * objects keyed by the columns' headings, every string escaped. Free with
 * gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_view_result_text(
    GDEFCORE_Catalog * catalog, const GDEFCORE_View_Result * result,
    char ** out_text, size_t * out_len);

/** @brief Free a result. NULL is ignored. */
GDEFCORE_API void gdefcore_view_result_free(GDEFCORE_View_Result * result);

/**
 * @brief The operators a condition may use on a field of storage type
 * @p field_type (a ::GDEFSTOR_FieldType), one name each, NUL-terminated, in a
 * static array. The same rule the condition validator applies.
 */
GDEFCORE_API const char * const * gdefcore_view_operators(int field_type,
    size_t * out_count);

/**
 * @brief The formatters a column of storage type @p field_type may use, static.
 * @p many is non-zero for a many-valued field.
 */
GDEFCORE_API const char * const * gdefcore_view_formatters(int field_type,
    int many, size_t * out_count);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_VIEW_H */
