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
 * @file render.h
 * @brief One page, one display, the Post starter kit, and a Tang scope.
 * @stability free
 *
 * A page selects one display. A display is a layout of regions and an
 * ordered list of panes in those regions. Region names belong to the
 * layout template. Tang runs the templates and the rendered bytes are
 * what the template call had already written when its scope ran out.
 * That partial page is success. There is no socket.
 */

#ifndef GHOTI_IO_GDEFCORE_RENDER_H
#define GHOTI_IO_GDEFCORE_RENDER_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/form.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fuel for a page's template scope. A gate passes a smaller number.
 * The scope policy is segments: the bytes already written are the result.
 */
#define GDEFCORE_RENDER_PAGE_FUEL ((uint64_t)1000000)

/**
 * @brief Render @p path.
 *
 * `/` selects the front-page display. A resolved public id of type
 * `site.post` selects the post display. Any other resolution, including
 * a path that resolves to nothing, writes no bytes and returns the same
 * error as an unknown path. @p scope_fuel is the budget of each template
 * the page registers. Zero is ::GDEFCORE_ERR_INVALID.
 *
 * Free @p out_bytes with gdefcore_text_free(). Not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_page(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request, const char * path,
    size_t path_len, uint64_t scope_fuel, char ** out_bytes, size_t * out_len);

/**
 * @brief Run @p source as a template under @p scope_fuel.
 *
 * The host registers it with a segment scope. When the scope runs out,
 * @p out_bytes is the prefix already written and the result is success.
 * @p source is a template, not a file. Free @p out_bytes with
 * gdefcore_text_free(). Not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_scope(GDEFCORE_Catalog * catalog,
    const char * source, size_t source_len, uint64_t scope_fuel,
    char ** out_bytes, size_t * out_len);

/**
 * @brief The Post starter kit as a tar archive.
 *
 * One member, named `changeset`. The catalog is not modified. Free
 * @p out_bytes with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_kit(GDEFCORE_Catalog * catalog,
    uint8_t ** out_bytes, size_t * out_len);

/**
 * @brief Read @p archive and install the kit.
 *
 * Applies the changeset, then stores the base theme, the recent-posts
 * view, and the two displays, and grants anonymous read of `site.post`.
 * A second install writes nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_install(GDEFCORE_Catalog * catalog,
    const uint8_t * archive, size_t archive_len);

/**
 * @brief Define a view. A personal sort or range writes nothing.
 *
 * @p sort or @p range NULL or zero length means that axis is absent.
 * Recent posts leave both absent and list in creation order.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_view_define(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    const char * type_name, size_t type_len, uint64_t limit,
    const char * template_name, size_t template_len, const char * sort,
    size_t sort_len, const char * range, size_t range_len);

/**
 * @brief Region names declared by the layout template @p name.
 *
 * Read from that template's source. Free @p out_names with
 * gdefcore_render_names_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_regions(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, char *** out_names, size_t * out_count);

/** @brief Free names from gdefcore_render_regions(). NULL is ignored. */
GDEFCORE_API void gdefcore_render_names_free(GDEFCORE_Catalog * catalog,
    char ** names, size_t count);

/**
 * @brief One pane of the display named @p name, in stored order.
 *
 * @p out_region, @p out_kind and @p out_target are freed with
 * gdefcore_text_free(). A kind is `view`, `entity` or `field`.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_pane_at(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, char ** out_region,
    size_t * out_region_len, char ** out_kind, size_t * out_kind_len,
    char ** out_target, size_t * out_target_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_RENDER_H */
