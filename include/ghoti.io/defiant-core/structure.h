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

#ifdef __cplusplus
}
#endif

#endif
