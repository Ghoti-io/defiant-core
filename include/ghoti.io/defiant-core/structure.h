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
 * @file structure.h
 * @brief A page template's structure: rows of cells, and what is made from it.
 * @stability free
 *
 * A page template can be **structured**: it keeps a *structure document*, an
 * ordered list of rows, each with up to 12 columns shared among its cells, each
 * cell one region (a name, a width and a stacked position). The template's source
 * and a stylesheet are *generated* from it, the same bytes every time, in one
 * changeset: the source holds a `region("name")` call in each cell, and the
 * stylesheet, the site file `site/layout-<template>.css`, is plain CSS Grid with
 * the responsive choices named below. The generated source and stylesheet are
 * read only beside the document: the apply refuses a template whose body is not
 * what its structure makes, and a stylesheet that is not either.
 *
 * A template whose source an editor wrote by hand is **custom** (its structure is
 * the word `custom`): it works, and its regions are found by reading it, but it is
 * not changed by a structure unless the caller says to replace it.
 *
 * The document is text, one line each:
 *
 *     row stack medium
 *     cell main 8 1
 *     cell side 4 2
 *     row wrap
 *     cell card
 *     cell card2
 *     row fixed
 *     cell footer 12
 *
 * `row stack <narrow|medium|wide>` folds to one column below that width, the
 * cells in their stacked order; `row wrap` flows its cells into as many columns as
 * fit, none narrower than a minimum width, with no breakpoint and no widths;
 * `row fixed` never folds. A cell of a stack or fixed row is `cell <region> <width>
 * [<stacked>]`, the width 1 to 12 and the widths of a row at most 12 in all; a
 * stacked position (1 to the cells in the row, none twice) defaults to the cell's
 * place in the row. A region name is that of region.h and is used once in the
 * whole document. There are at most 32 rows, 12 cells in a row and 64 cells in
 * all. A row folds on the width of its own container, by a container query, so
 * the same structure behaves when it sits in a narrow region; the three named
 * widths are 480, 720 and 960 CSS pixels. Browsers that predate container queries
 * (before 2023) show the rows at full width and unfolded. A structured template's
 * name is a-z first, then a-z, 0-9 and '-'.
 */

#ifndef GHOTI_IO_GDEFCORE_STRUCTURE_H
#define GHOTI_IO_GDEFCORE_STRUCTURE_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Most rows in a structure. */
#define GDEFCORE_STRUCTURE_ROWS_MAX 32
/** @brief Most cells in one row. */
#define GDEFCORE_STRUCTURE_ROW_CELLS_MAX 12
/** @brief Most cells in a structure. */
#define GDEFCORE_STRUCTURE_CELLS_MAX 64
/** @brief Most bytes of a document. */
#define GDEFCORE_STRUCTURE_BYTES_MAX 4096
/** @brief The structure of a template whose source an editor wrote. */
#define GDEFCORE_STRUCTURE_CUSTOM "custom"

/**
 * @brief Whether @p name may be a structured template's name.
 */
GDEFCORE_API int gdefcore_structure_name_ok(const char * name, size_t name_len);

/**
 * @brief Check a structure document and write its canonical form.
 *
 * The canonical form has every stacked position written, one `\n` after each
 * line, and nothing else.
 *
 * @param text The document.
 * @param text_len Its length.
 * @param out_canonical The canonical document, to free with gdefcore_text_free()
 *   (any catalog), or NULL.
 * @param out_len Its length, or NULL.
 * @param why Where to write a sentence naming the first fault, or NULL.
 * @param why_cap Its size.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID for a document that breaks a
 *   rule, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_check(const char * text,
    size_t text_len, char ** out_canonical, size_t * out_len, char * why,
    size_t why_cap);

/**
 * @brief The template source and the stylesheet a structure makes for page
 * template @p template_name. The same structure and name give the same bytes.
 *
 * Free each with free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_generate(const char * template_name,
    size_t template_len, const char * text, size_t text_len, char ** out_source,
    size_t * out_source_len, char ** out_css, size_t * out_css_len);

/**
 * @brief The structure of page template @p template_name: its canonical
 * document, ::GDEFCORE_STRUCTURE_CUSTOM, or empty for a template that has none.
 *
 * Free @p out with gdefcore_text_free(). A template that does not exist is
 * ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_read(GDEFCORE_Catalog * catalog,
    const char * template_name, size_t template_len, char ** out, size_t * out_len);

/**
 * @brief Stage a structure for page template @p template_name: the document,
 * the source and the stylesheet it makes, in @p changeset.
 *
 * The template is made when there is none. A template that is custom is left as
 * it is, with ::GDEFCORE_ERR_INVALID, unless @p replace_custom is non-zero.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_stage(GDEFCORE_Changeset * changeset,
    const char * template_name, size_t template_len, const char * text,
    size_t text_len, int replace_custom);

/**
 * @brief Stage that page template @p template_name is now written by hand:
 * its structure becomes ::GDEFCORE_STRUCTURE_CUSTOM and its source is kept.
 * The generated stylesheet stays, as a file the site may then change.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_stage_custom(
    GDEFCORE_Changeset * changeset, const char * template_name, size_t template_len);

/**
 * @brief Refuse a changeset that leaves a structured template whose source is
 * not what its structure makes, or a generated stylesheet that is not. Called by
 * the apply; the changeset's refusal says which.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_vet(GDEFCORE_Changeset * changeset);


/* ---- editing a structure ---------------------------------------------------------- */

/** @name What a refused structure edit says (gdefcore_changeset_refusal()). @{ */
#define GDEFCORE_STRUCTURE_REFUSED_STALE "This structure changed. Showing the current structure."
#define GDEFCORE_STRUCTURE_REFUSED_CUSTOM \
  "This template is written by hand. Start a new structure to replace it."
#define GDEFCORE_STRUCTURE_REFUSED_THERE "That row or cell is not there."
#define GDEFCORE_STRUCTURE_REFUSED_START "That starting point is not there."
#define GDEFCORE_STRUCTURE_REFUSED_NOT_PAGE "That template is not a page template."
/** @} */

/** @brief Length of a structure's version, without the NUL. */
#define GDEFCORE_STRUCTURE_VERSION_LEN 32

/** @brief A row's behavior (::GDEFCORE_Structure_Row::behavior). */
enum {
  GDEFCORE_STRUCTURE_STACK = 1,   ///< Folds to one column below its breakpoint.
  GDEFCORE_STRUCTURE_WRAP = 2,    ///< Flows into as many columns as fit.
  GDEFCORE_STRUCTURE_FIXED = 3    ///< Never folds.
};

/** @brief A stack row's breakpoint (::GDEFCORE_Structure_Row::breakpoint). */
enum {
  GDEFCORE_STRUCTURE_NARROW = 1,  ///< 480 CSS pixels.
  GDEFCORE_STRUCTURE_MEDIUM = 2,  ///< 720 CSS pixels.
  GDEFCORE_STRUCTURE_WIDE = 3     ///< 960 CSS pixels.
};

/** @brief What a template's structure is (::GDEFCORE_Structure_View::kind). */
enum {
  GDEFCORE_STRUCTURE_KIND_NONE = 0,      ///< The template has none.
  GDEFCORE_STRUCTURE_KIND_DOCUMENT = 1,  ///< A document its source is made from.
  GDEFCORE_STRUCTURE_KIND_CUSTOM = 2     ///< Written by hand.
};

/** @brief One cell of a row. A width of 0 is a wrap row's cell. */
typedef struct GDEFCORE_Structure_Cell {
  char region[64];            ///< The region it holds.
  int width;                  ///< 1 to 12, or 0 in a wrap row.
  int stacked;                ///< Its place when the row is folded, 1 up; 0 in a wrap row.
} GDEFCORE_Structure_Cell;

/** @brief One row. */
typedef struct GDEFCORE_Structure_Row {
  int behavior;               ///< A GDEFCORE_STRUCTURE_STACK, _WRAP or _FIXED.
  int breakpoint;             ///< A GDEFCORE_STRUCTURE_NARROW.. value for a stack row, else 0.
  size_t ncells;              ///< How many cells.
  GDEFCORE_Structure_Cell cells[GDEFCORE_STRUCTURE_ROW_CELLS_MAX]; ///< In order.
} GDEFCORE_Structure_Row;

/** @brief A template's structure as an editor draws it. Free with gdefcore_structure_view_free(). */
typedef struct GDEFCORE_Structure_View {
  size_t size;                ///< `sizeof(GDEFCORE_Structure_View)`.
  int kind;                   ///< A GDEFCORE_STRUCTURE_KIND_* value.
  GDEFCORE_Structure_Row * rows;  ///< The rows of a document.
  size_t nrows;               ///< How many.
  char * document;            ///< The canonical document, or "" (custom is the word custom).
  size_t document_len;        ///< Its length.
  char version[GDEFCORE_STRUCTURE_VERSION_LEN + 1]; ///< What an edit names.
} GDEFCORE_Structure_View;

/**
 * @brief Read the structure of page template @p name as it is published.
 *
 * A template that does not exist is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_view(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, GDEFCORE_Structure_View * out);

/** @brief Free what gdefcore_structure_view() allocated. NULL is ignored. */
GDEFCORE_API void gdefcore_structure_view_free(GDEFCORE_Structure_View * view);

/** @brief The actions of ::GDEFCORE_Structure_Edit. */
enum {
  GDEFCORE_STRUCTURE_ACT_ADD_ROW = 1,    ///< Insert a row at `row` (or at the end) of `behavior`, `breakpoint`, holding one cell of `region` and `width` (12 when 0).
  GDEFCORE_STRUCTURE_ACT_REMOVE_ROW,     ///< Remove row `row`; its regions' placements are set aside.
  GDEFCORE_STRUCTURE_ACT_MOVE_ROW,       ///< Move row `row` to place `to_row`.
  GDEFCORE_STRUCTURE_ACT_SET_ROW,        ///< Give row `row` a `behavior` and `breakpoint`.
  GDEFCORE_STRUCTURE_ACT_ADD_CELL,       ///< Add a cell of region `region`, `width` and `stacked`, to row `row`.
  GDEFCORE_STRUCTURE_ACT_REMOVE_CELL,    ///< Remove cell `cell` of row `row`; a row left with no cell goes too.
  GDEFCORE_STRUCTURE_ACT_MOVE_CELL,      ///< Move cell `cell` of row `row` to place `to_cell` of row `to_row`.
  GDEFCORE_STRUCTURE_ACT_SET_WIDTH,      ///< Give that cell `width`.
  GDEFCORE_STRUCTURE_ACT_SET_STACKED,    ///< Give that cell the folded place `stacked`.
  GDEFCORE_STRUCTURE_ACT_RENAME_CELL,    ///< Name that cell's region `region`; every layout's placements follow.
  GDEFCORE_STRUCTURE_ACT_START,          ///< Replace the structure by starting point `region` (a name).
  GDEFCORE_STRUCTURE_ACT_START_NEW,      ///< Replace it by one row holding `region`.
  GDEFCORE_STRUCTURE_ACT_CUSTOM          ///< Write the template by hand from now on.
};

/** @brief One edit of a structure. Begins with @ref size. */
typedef struct GDEFCORE_Structure_Edit {
  size_t size;                ///< `sizeof(GDEFCORE_Structure_Edit)`.
  int act;                    ///< A GDEFCORE_STRUCTURE_ACT_* value.
  const char * version;       ///< The version the editor was shown.
  size_t version_len;         ///< Its length.
  size_t row;                 ///< A row, 0 up. For an add, the place to insert (past the end adds).
  size_t cell;                ///< A cell, 0 up.
  size_t to_row;              ///< Where a move goes.
  size_t to_cell;             ///< Where a cell move goes (past the end appends).
  const char * region;        ///< A region name, or a starting point's name.
  size_t region_len;          ///< Its length.
  int width;                  ///< A cell's width.
  int stacked;                ///< A cell's folded place; 0 for the end.
  int behavior;               ///< A row's behavior.
  int breakpoint;             ///< A stack row's breakpoint; 0 for medium.
} GDEFCORE_Structure_Edit;

/**
 * @brief Stage one edit of page template @p name's structure in @p changeset.
 *
 * The template's source and stylesheet are made again from the result, and every
 * layout that draws with the template is carried along in the same changeset: a
 * placement in a region the structure no longer has goes to the layout's Not
 * placed list, and a renamed region's placements follow it. A start on a template
 * that is custom replaces it; any other edit of one is refused. A stale or
 * impossible edit is ::GDEFCORE_ERR_INVALID with the refusal naming why.
 *
 * @param moved Where to put a text of one line, `layout widget region`, for each
 *   placement set aside (free with free()), or NULL.
 * @param moved_len Its length.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_stage_edit(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const GDEFCORE_Structure_Edit * edit, char ** moved,
    size_t * moved_len);

/**
 * @brief Starting point @p index: its name, its label and its document. The
 * table is the same every time; 0 past the last.
 */
GDEFCORE_API int gdefcore_structure_starting_point(size_t index, const char ** name,
    const char ** label, const char ** document);

/* ---- undoing a structure edit or a template save that carried layouts ------------ */

/** The entity type of the record of the last such change, which undo reads. Its
 * fields: `name` (always `last`) and `entities`, one `<id> <seq> <S|C>` line for
 * each template, layout or generated stylesheet the change wrote. It holds ids
 * and revision numbers and no one's text, so it needs no grant of its own. It is a
 * config type like the others, so a change that writes it names it among the
 * machine names its typed confirmation lists. */
#define GDEFCORE_STRUCTURE_CHANGE_TYPE "core.structure-change"
/** Most entities one undoable change writes. A change that writes more is made,
 * and cannot be undone as a whole: the record is emptied. */
#define GDEFCORE_STRUCTURE_UNDO_MAX 32
/** The refusal of an undo when there is no change to undo. */
#define GDEFCORE_STRUCTURE_REFUSED_NOTHING "There is no page structure change to undo."
/** The refusal of an undo of a change whose writes have been written over since. */
#define GDEFCORE_STRUCTURE_REFUSED_UNDO \
  "That page was changed after that edit, so the edit cannot be undone."

/**
 * @brief Stage the record of what @p changeset writes of templates, layouts and
 * generated stylesheets, so that gdefcore_structure_stage_undo() can undo it.
 *
 * gdefcore_structure_stage_edit() does this itself. A caller that stages a
 * template with its carried layouts by hand (gdefcore_layout_stage_template_carry())
 * calls it last, once the changeset names everything it writes. It replaces the
 * record of the earlier change, and stages nothing when the changeset writes no
 * layout or stylesheet (a plain template save is undone as any revision is). A
 * change of more than ::GDEFCORE_STRUCTURE_UNDO_MAX entities empties the record
 * instead, so that a later undo cannot take back an older change by mistake.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_stage_record(GDEFCORE_Changeset * changeset);

/**
 * @brief Stage the undo of the last recorded change in @p changeset.
 *
 * Every entity it wrote is put back as it was before, in this one changeset: one
 * the change made is cleared, one it cleared is restored, one it changed gets its
 * earlier values again, a new revision as every revert is. The record is then
 * emptied, so a change is undone once.
 *
 * Refused with ::GDEFCORE_ERR_INVALID and the fixed sentence "That edit is not
 * allowed." (nothing read) when @p request may edit neither layouts nor page
 * templates, with ::GDEFCORE_STRUCTURE_REFUSED_NOTHING when there is no change
 * to undo, and with ::GDEFCORE_STRUCTURE_REFUSED_UNDO when anything the change
 * wrote has been written since, so that an undo never overwrites a later edit.
 * Apply decides every write again as it decides any other.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_stage_undo(GDEFCORE_Changeset * changeset,
    GDEFCORE_Request * request);

/**
 * @brief Whether there is a change for gdefcore_structure_stage_undo() to take back.
 * Asks nothing about who may.
 */
GDEFCORE_API int gdefcore_structure_can_undo(GDEFCORE_Catalog * catalog);

/** @brief Define ::GDEFCORE_STRUCTURE_CHANGE_TYPE. Repeating it changes nothing. */
GDEFCORE_API GDEFCORE_Result gdefcore_structure_declare(GDEFCORE_Catalog * catalog);


#ifdef __cplusplus
}
#endif

#endif
