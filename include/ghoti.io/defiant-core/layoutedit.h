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
 * @file layoutedit.h
 * @brief Changing a layout one placement at a time: read it, edit it, refuse a
 * stale edit.
 * @stability free
 *
 * An editor shows a layout as its regions (the ones its page template names, in
 * the template's order), the placements in each, and a Not placed list, and
 * changes it by one of a few actions: place a widget, place one from the Not
 * placed list, move a placement to a region and a position, configure its title
 * and when it shows, take it out (it is deleted), or set it aside (it goes to
 * the Not placed list). Each is one changeset on the one layout, so it is one
 * revision, undone whole by reverting it, and refused when the layout is no
 * longer the one the editor drew: every edit carries the version the editor was
 * shown (gdefcore_layout_view()).
 *
 * A placement is `region widget [target] [~key=value ...]` (layout.h), here as a
 * struct. The calls only stage; the apply asks the layout permission, checks the
 * layout as it is left (gdefcore_layout_vet()) and writes it.
 */

#ifndef GHOTI_IO_GDEFCORE_LAYOUTEDIT_H
#define GHOTI_IO_GDEFCORE_LAYOUTEDIT_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/layout.h>
#include <ghoti.io/defiant-core/region.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Length of a layout's version, without the NUL. */
#define GDEFCORE_LAYOUT_VERSION_LEN 32
/** @brief Most bytes of a placement's target. */
#define GDEFCORE_PLACEMENT_TARGET_MAX 128
/** @brief Most bytes of a placement's title. */
#define GDEFCORE_PLACEMENT_TITLE_MAX 128
/** @brief Most bytes of a placement's path pattern. */
#define GDEFCORE_PLACEMENT_PATH_MAX 128
/** @brief Most bytes of a placement's type. */
#define GDEFCORE_PLACEMENT_TYPE_MAX 96
/** @brief Most roles a placement names. */
#define GDEFCORE_PLACEMENT_ROLES_MAX 8
/** @brief Most bytes of a role. */
#define GDEFCORE_PLACEMENT_ROLE_MAX 64

/** @name What a refused edit says (gdefcore_changeset_refusal()). @{ */
#define GDEFCORE_LAYOUT_REFUSED_STALE "This layout changed. Showing the current layout."
#define GDEFCORE_LAYOUT_REFUSED_REGION "That region is not in this template."
#define GDEFCORE_LAYOUT_REFUSED_WIDGET "That widget is not available."
#define GDEFCORE_LAYOUT_REFUSED_THERE "That placement is not there."
#define GDEFCORE_LAYOUT_REFUSED_FULL "A layout holds at most 32 placements."
#define GDEFCORE_LAYOUT_REFUSED_PART "That setting is not one a placement can hold."
/** @} */

/**
 * @brief One placement. Begins with @ref size.
 *
 * Every text is NUL-terminated; an empty one is not set. A placement in the Not
 * placed list has no region.
 */
typedef struct GDEFCORE_Placement {
  size_t size;                                          ///< `sizeof(GDEFCORE_Placement)`.
  char region[GDEFCORE_REGION_NAME_MAX + 1];            ///< The region, or "".
  char widget[GDEFCORE_LAYOUT_NAME_MAX + 1];            ///< The widget type.
  char target[GDEFCORE_PLACEMENT_TARGET_MAX + 1];       ///< The widget's target.
  char title[GDEFCORE_PLACEMENT_TITLE_MAX + 1];         ///< A title drawn above it.
  char path[GDEFCORE_PLACEMENT_PATH_MAX + 1];           ///< Shown only on this path.
  char type[GDEFCORE_PLACEMENT_TYPE_MAX + 1];           ///< Shown only for this type.
  size_t nroles;                                        ///< How many roles.
  char roles[GDEFCORE_PLACEMENT_ROLES_MAX][GDEFCORE_PLACEMENT_ROLE_MAX + 1]; ///< Any of these.
} GDEFCORE_Placement;

/**
 * @brief Read one stored line into @p out.
 *
 * @param has_region Non-zero for a line of the placed list (`region widget ...`),
 *   zero for one of the Not placed list (`widget ...`).
 * @return 1, or 0 for a line that is not one.
 */
GDEFCORE_API int gdefcore_placement_parse(const char * line, size_t line_len,
    int has_region, GDEFCORE_Placement * out);

/**
 * @brief The stored line of @p placement, into @p out (@p cap bytes with the NUL).
 *
 * @return Its length, or 0 when it does not fit or is not a placement.
 */
GDEFCORE_API size_t gdefcore_placement_format(const GDEFCORE_Placement * placement,
    int with_region, char * out, size_t cap);

/**
 * @brief A layout as an editor draws it. Free with gdefcore_layout_view_free().
 */
typedef struct GDEFCORE_Layout_View {
  size_t size;                ///< `sizeof(GDEFCORE_Layout_View)`.
  char * template_name;       ///< The page template the layout draws with.
  char ** regions;            ///< The template's regions, in its order.
  size_t nregions;            ///< How many.
  GDEFCORE_Placement * placed;    ///< The placements, in stored order.
  size_t nplaced;             ///< How many.
  GDEFCORE_Placement * unplaced;  ///< The Not placed list.
  size_t nunplaced;           ///< How many.
  char version[GDEFCORE_LAYOUT_VERSION_LEN + 1]; ///< What an edit names.
} GDEFCORE_Layout_View;

/**
 * @brief Read layout @p name as it is published.
 *
 * A stored line that is not a placement is ::GDEFCORE_ERR_INVALID. A layout that
 * does not exist is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_view(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, GDEFCORE_Layout_View * out);

/** @brief Free what gdefcore_layout_view() allocated. NULL is ignored. */
GDEFCORE_API void gdefcore_layout_view_free(GDEFCORE_Layout_View * view);

/** @brief What an edit does. */
enum {
  GDEFCORE_LAYOUT_ACT_PLACE = 1,        ///< Place a widget: @ref GDEFCORE_Layout_Edit::placement
  GDEFCORE_LAYOUT_ACT_PLACE_UNPLACED,   ///< Place the Not placed entry @ref GDEFCORE_Layout_Edit::index.
  GDEFCORE_LAYOUT_ACT_MOVE,             ///< Move placement @ref GDEFCORE_Layout_Edit::index to a region and position.
  GDEFCORE_LAYOUT_ACT_CONFIGURE,        ///< Replace the target, title and conditions of a placement.
  GDEFCORE_LAYOUT_ACT_REMOVE,           ///< Delete a placement.
  GDEFCORE_LAYOUT_ACT_UNPLACE           ///< Set a placement aside in the Not placed list.
};

/**
 * @brief An edit. Begins with @ref size; the action says which members are read.
 */
typedef struct GDEFCORE_Layout_Edit {
  size_t size;                ///< `sizeof(GDEFCORE_Layout_Edit)`.
  int action;                 ///< A GDEFCORE_LAYOUT_ACT_ value.
  const char * layout;        ///< The layout's name.
  size_t layout_len;          ///< Its length.
  const char * version;       ///< The version the editor drew.
  size_t version_len;         ///< Its length.
  size_t index;               ///< Which placement (move, configure, remove,
                              ///< unplace, place-unplaced).
  int from_unplaced;          ///< Configure, remove: @ref index is in the Not placed list.
  const char * region;        ///< Place, place-unplaced, move: the region.
  size_t region_len;          ///< Its length.
  size_t position;            ///< Place, place-unplaced, move: where among the
                              ///< region's placements (0 first; more than there are is last).
  GDEFCORE_Placement placement;   ///< Place: the widget and its settings.
                                  ///< Configure: the new settings; region and widget are kept.
} GDEFCORE_Layout_Edit;

/**
 * @brief Stage one edit of a layout in @p changeset.
 *
 * Refused with ::GDEFCORE_ERR_INVALID and one of the GDEFCORE_LAYOUT_REFUSED_
 * sentences as the refusal when the version is not the layout's now, the region
 * is not one the layout's template names, the widget is not one the tenant has,
 * the placement is not there, the layout would hold more than 32, or a setting is
 * not one. An edit that changes nothing is success and stages nothing (check
 * gdefcore_changeset_touched_count()).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_stage_edit(
    GDEFCORE_Changeset * changeset, const GDEFCORE_Layout_Edit * edit);

/**
 * @brief Stage, beside an edit of page template @p template_name's body to
 * @p body, what every layout that draws with it becomes.
 *
 * A placement in a region the new body does not call is set aside in its layout's
 * Not placed list, so a template edit never leaves a layout naming a region the
 * template does not have and never loses a placement. The caller stages the
 * template's own change in the same @p changeset. Nothing is staged for a layout
 * whose regions all remain.
 *
 * @param moved Where to put one line, `layout widget region`, for each placement
 *   set aside (free with free()), or NULL.
 * @param moved_len Its length.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_stage_template_carry(
    GDEFCORE_Changeset * changeset, const char * template_name, size_t template_len,
    const char * body, size_t body_len, char ** moved, size_t * moved_len);

/* ---- previewing a layout ---------------------------------------------------------- */

/**
 * @brief Who a preview shows the layout to. Begins with @ref size.
 *
 * A preview is the layout as one kind of visitor would see it, without a
 * request: an empty @ref role is a visitor who is not signed in, `authenticated`
 * is anyone signed in who holds no role the placements name, and any other name is
 * a signed-in person who holds that role (and so also matches a placement for
 * `authenticated`). @ref path and @ref type say which page it is: a placement
 * that names a path or an entity type shows only when they match.
 */
typedef struct GDEFCORE_Preview_Viewer {
  size_t size;                ///< `sizeof(GDEFCORE_Preview_Viewer)`.
  const char * role;          ///< "" (not signed in), "authenticated" or a role's name.
  size_t role_len;            ///< Its length.
  const char * path;          ///< The page's path, e.g. "/blog/hello"; "" for none.
  size_t path_len;            ///< Its length.
  const char * type;          ///< The entity type the page shows, or "".
  size_t type_len;            ///< Its length.
} GDEFCORE_Preview_Viewer;

/**
 * @brief A layout as one visitor would see it. Free with gdefcore_layout_preview_free().
 */
typedef struct GDEFCORE_Layout_Preview {
  size_t size;                ///< `sizeof(GDEFCORE_Layout_Preview)`.
  GDEFCORE_Layout_View view;  ///< The layout as an editor draws it.
  unsigned char * shown;      ///< For each of `view.placed`, 1 when the visitor sees it.
  size_t nshown;              ///< How many of them.
  size_t nhidden;             ///< How many the visitor does not see.
} GDEFCORE_Layout_Preview;

/**
 * @brief Read layout @p name and decide, for @p viewer, which of its placements show.
 *
 * It reads the published layout and nothing else: nothing is written, cached
 * or kept, and a placement the visitor does not see is counted and never named
 * (read `shown`, not `view.placed`, to draw). The decision is the one the
 * renderer makes for a placement's path, type and roles. A layout that does not
 * exist is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_preview(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, const GDEFCORE_Preview_Viewer * viewer,
    GDEFCORE_Layout_Preview * out);

/** @brief Free what gdefcore_layout_preview() allocated. NULL is ignored. */
GDEFCORE_API void gdefcore_layout_preview_free(GDEFCORE_Layout_Preview * preview);

#ifdef __cplusplus
}
#endif

#endif
