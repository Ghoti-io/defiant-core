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
 * @file region.h
 * @brief What an editor calls a region: its label and its help text.
 * @stability free
 *
 * A page template names its regions with `region("side")`, and that is all it
 * says. What an editor is shown for one comes from a **descriptor**, a label and
 * an optional description such as "Side area", "Shown beside the main content".
 * A descriptor is found in this order and the first match wins:
 *
 *  1. the template's own, kept with that page template (its `regions` field,
 *     one `name ~label=<text> ~description=<text>` line each, the values
 *     percent-encoded as a placement's are);
 *  2. a shared one with that region name, a `core.region-descriptor` entity,
 *     seeded with main, side, header, navigation and footer and extended by the
 *     site;
 *  3. an enabled module's (its manifest's `regions`, GDEFCORE_Module_Region), the
 *     first in module order that names the region: a module that ships page
 *     templates or widgets for regions it names ships their labels with them, and
 *     they are there while it is enabled and gone when it is not;
 *  4. the name itself in readable form, `footer_links` as "Footer links".
 *
 * A descriptor changes what the editor and the preview show and nothing else: it
 * never changes how a page renders, and removing a shared one touches labels
 * only, never a placement. The texts are the site's, so a caller escapes them.
 *
 * The shared catalog is configuration written by changeset (revisions, undo, a
 * stale save refused) under the permission ::GDEFCORE_REGION_EDIT, labelled
 * "Edit region descriptors", which ::GDEFCORE_LAYOUT_EDIT does not imply. A template's own descriptors are written with the
 * template, so they ask the template permission.
 */

#ifndef GHOTI_IO_GDEFCORE_REGION_H
#define GHOTI_IO_GDEFCORE_REGION_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The entity type of a shared descriptor. */
#define GDEFCORE_REGION_DESCRIPTOR_TYPE "core.region-descriptor"
/** @brief The permission to write shared descriptors. */
#define GDEFCORE_REGION_EDIT "core.region.edit"
/** @brief The label the permission to write shared descriptors is granted under. */
#define GDEFCORE_REGION_EDIT_LABEL "Edit region descriptors"
/** @brief The most bytes of a label. */
#define GDEFCORE_REGION_LABEL_MAX 64
/** @brief The most bytes of a description. */
#define GDEFCORE_REGION_DESCRIPTION_MAX 256
/** @brief The most bytes of a region name. */
#define GDEFCORE_REGION_NAME_MAX 63

/** @brief Where a descriptor came from (::GDEFCORE_Region_Info::source). */
enum {
  GDEFCORE_REGION_SOURCE_TEMPLATE = 1,  ///< The page template's own.
  GDEFCORE_REGION_SOURCE_SHARED = 2,    ///< The shared catalog.
  GDEFCORE_REGION_SOURCE_NAME = 3,      ///< The name, made readable.
  GDEFCORE_REGION_SOURCE_MODULE = 4     ///< An enabled module's (GDEFCORE_Module_Region).
};

/**
 * @brief A region's label and description. Begins with @ref size.
 *
 * Free with gdefcore_region_info_free().
 */
typedef struct GDEFCORE_Region_Info {
  size_t size;                ///< `sizeof(GDEFCORE_Region_Info)`.
  char * label;               ///< The label, never empty.
  size_t label_len;           ///< Length of @ref label.
  char * description;         ///< The description, empty when there is none.
  size_t description_len;     ///< Length of @ref description.
  int source;                 ///< A GDEFCORE_REGION_SOURCE_* value.
} GDEFCORE_Region_Info;

/**
 * @brief Whether @p name is a region name: a-z first, then a-z, 0-9, '_' and '-',
 * at most ::GDEFCORE_REGION_NAME_MAX bytes.
 */
GDEFCORE_API int gdefcore_region_name_ok(const char * name, size_t name_len);

/** @brief Define the shared type and declare its permission. Idempotent. */
GDEFCORE_API GDEFCORE_Result gdefcore_region_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief What an editor shows for region @p region of page template @p template_name.
 *
 * @param template_name The page template, or NULL to skip its own descriptors.
 * @param info Filled in; its `size` must be `sizeof`. A region name that is not
 *   one is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_region_describe(GDEFCORE_Catalog * catalog,
    const char * template_name, size_t template_len, const char * region,
    size_t region_len, GDEFCORE_Region_Info * info);

/** @brief Free what gdefcore_region_describe() allocated. NULL is ignored. */
GDEFCORE_API void gdefcore_region_info_free(GDEFCORE_Catalog * catalog,
    GDEFCORE_Region_Info * info);

/**
 * @brief Stage a shared descriptor: create it, or replace its label and
 * description. A NULL or empty @p description has none.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_region_stage_shared(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len,
    const char * label, size_t label_len, const char * description,
    size_t description_len);

/** @brief Stage the removal of a shared descriptor. */
GDEFCORE_API GDEFCORE_Result gdefcore_region_stage_shared_forget(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len);

/**
 * @brief Stage a descriptor of page template @p template_name for @p region,
 * kept with that template. A NULL or empty @p label takes the template's
 * descriptor for the region away.
 *
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when there is no such
 *   template or a text is not one.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_region_stage_template(
    GDEFCORE_Changeset * changeset, const char * template_name, size_t template_len,
    const char * region, size_t region_len, const char * label, size_t label_len,
    const char * description, size_t description_len);

/**
 * @brief Refuse a changeset that leaves a descriptor that is not one. Called by
 * the apply; the changeset's refusal says which and why.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_region_vet(GDEFCORE_Changeset * changeset);

/**
 * @brief Refuse a changeset that writes a shared descriptor its request may
 * not. The refusal is the one fixed sentence. Called by the apply.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_region_authorize(
    GDEFCORE_Changeset * changeset, GDEFCORE_Request * request);

/** @brief Whether the principal may write shared descriptors. */
GDEFCORE_API int gdefcore_region_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request);

#ifdef __cplusplus
}
#endif

#endif
