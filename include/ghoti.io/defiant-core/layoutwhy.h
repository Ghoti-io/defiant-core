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
 * @file layoutwhy.h
 * @brief Which layout a path gets, and why.
 * @stability free
 *
 * gdefcore_layout_why() answers the question an editor asks of the selector
 * rules, "which layout does this page get?", with the answer the renderer would
 * give: it runs the very decision gdefcore_layout_select() runs (the offers of
 * the route trie in their one order, the first whose layout can be applied, then
 * the alter hook), and keeps what it saw. Each offer is listed in that order
 * with whether it could be applied and, for one that lost, why: a lower rank (a
 * less specific pattern), a higher weight at the same rank, or later in the
 * total order at the same rank and weight (the engine breaks that tie by the
 * site's own first, then source, then value). It says whether the alter hook of
 * a module changed the choice; which module did is not recorded by the host.
 */

#ifndef GHOTI_IO_GDEFCORE_LAYOUTWHY_H
#define GHOTI_IO_GDEFCORE_LAYOUTWHY_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/form.h>
#include <ghoti.io/defiant-core/layout.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Why an offer is where it is. */
enum {
  GDEFCORE_WHY_CHOSEN = 1,        ///< The first that can be applied.
  GDEFCORE_WHY_LESS_SPECIFIC,     ///< A lower rank than the one chosen.
  GDEFCORE_WHY_HEAVIER,           ///< The same rank, a higher weight.
  GDEFCORE_WHY_LATER,             ///< The same rank and weight, later in the order.
  GDEFCORE_WHY_UNUSABLE           ///< Its layout cannot be applied (it is missing or invalid).
};

/** @brief One offer of the selection. An element of GDEFCORE_Layout_Why::offers:
 *  the engine fills it and the caller only reads it, so the size that guards the
 *  array is the one in GDEFCORE_Layout_Why. */
typedef struct GDEFCORE_Layout_Why_Offer {
  char layout[GDEFCORE_LAYOUT_NAME_MAX + 1];    ///< The layout offered.
  char source[GDEFCORE_LAYOUT_NAME_MAX + 1];    ///< Who offered it: a rule of the site, or a module's contributor.
  int64_t rank;                                 ///< The engine's rank: larger is more specific.
  int weight;                                   ///< Lowest first among equal ranks.
  int site;                                     ///< Non-zero for the site's own rule.
  int usable;                                   ///< Whether its layout can be applied.
  int why;                                      ///< A GDEFCORE_WHY_ value.
} GDEFCORE_Layout_Why_Offer;

/** @brief The selection for one path. Begins with @ref size. */
typedef struct GDEFCORE_Layout_Why {
  size_t size;                                  ///< \`sizeof\`.
  GDEFCORE_Layout_Why_Offer * offers;           ///< In the engine's order.
  size_t noffers;                               ///< How many.
  char ordered[GDEFCORE_LAYOUT_NAME_MAX + 1];   ///< The layout the offers chose, or "".
  char final[GDEFCORE_LAYOUT_NAME_MAX + 1];     ///< The layout after the alter hook, or "".
  int refined;                                  ///< Non-zero when the hook changed it.
} GDEFCORE_Layout_Why;

/**
 * @brief Which layout @p path gets for @p request, and why.
 *
 * Arguments as gdefcore_layout_select(). The answer's @ref
 * GDEFCORE_Layout_Why::final is exactly what that call returns for the same
 * arguments. A path no offer can serve has an empty final and is
 * ::GDEFCORE_OK; free with gdefcore_layout_why_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_why(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request, const char * path,
    size_t path_len, GDEFCORE_Layout_Why * out);

/** @brief Free what gdefcore_layout_why() allocated. NULL is ignored. */
GDEFCORE_API void gdefcore_layout_why_free(GDEFCORE_Layout_Why * why);

#ifdef __cplusplus
}
#endif

#endif
