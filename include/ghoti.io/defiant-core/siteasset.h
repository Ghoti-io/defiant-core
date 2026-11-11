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
 * @file siteasset.h
 * @brief The site's own stylesheets and scripts, written by changeset.
 * @stability free
 *
 * The site's own stylesheets and scripts.
 *
 * A module ships its files in its manifest (asset.h). A site adds its own on
 * top: a stylesheet is a `core.css-asset` and a script a `core.js-asset`, two
 * configuration entities of a name and a text, changed only by changeset
 * (revisions, undo, a stale save refused) and read from the catalog's own
 * tenant. They are served and named like a module's, under the owner `site`:
 * `asset("site/site.css")` gives `/assets/site/site.css?v=<hash>`. The hash is
 * made from the stored text when it is read, so it cannot disagree with what is
 * served and an edit changes the address of the next page with no restart.
 *
 * The two kinds are two types so that the permission to change them is two
 * permissions: ::GDEFCORE_ASSET_CSS_EDIT and ::GDEFCORE_ASSET_JS_EDIT are
 * separate, and neither is implied by ::GDEFCORE_LAYOUT_EDIT or the other. A
 * script runs with the authority of whoever is signed in when it loads, so the
 * permission to write one is the higher. The port holds UTF-8 text only, so a
 * site cannot upload an image or a font; a module ships those.
 *
 * A name is unique across both kinds, as a file name is unique under an owner.
 * Both types are configuration, so a changeset that writes one is high risk and
 * is applied only with the typed confirmation of the names it touches.
 */

#ifndef GHOTI_IO_GDEFCORE_SITEASSET_H
#define GHOTI_IO_GDEFCORE_SITEASSET_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The owner of the site's own files in an address and a reference. */
#define GDEFCORE_SITE_ASSET_OWNER "site"

/** @brief The entity type of a site stylesheet. */
#define GDEFCORE_ASSET_CSS_TYPE "core.css-asset"
/** @brief The entity type of a site script. */
#define GDEFCORE_ASSET_JS_TYPE "core.js-asset"

/** @brief The permission to write a site stylesheet. */
#define GDEFCORE_ASSET_CSS_EDIT "core.asset.css.edit"
/** @brief The permission to write a site script. */
#define GDEFCORE_ASSET_JS_EDIT "core.asset.js.edit"
/** @brief The label the stylesheet permission is granted under. */
#define GDEFCORE_ASSET_CSS_EDIT_LABEL "Edit site stylesheets"
/** @brief The label the script permission is granted under. */
#define GDEFCORE_ASSET_JS_EDIT_LABEL "Edit site scripts"

/**
 * @brief Whether @p name is a file name: 1 to ::GDEFCORE_ASSET_NAME_MAX bytes of
 * a-z, 0-9, '.', '_' and '-', starting with a letter or digit, with no "..".
 * It is the rule of a module's file name too.
 */
GDEFCORE_API int gdefcore_siteasset_name_ok(const char * name, size_t name_len);

/**
 * @brief The page template whose structure generated the site file @p name
 * (structure.h), written to @p template_name (::GDEFCORE_ASSET_NAME_MAX + 1
 * bytes). A generated file is read only.
 *
 * @return 1 when the file is generated, 0 when it is the site's own or there is
 *   none.
 */
GDEFCORE_API int gdefcore_siteasset_generator(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, char template_name[GDEFCORE_ASSET_NAME_MAX + 1]);

/**
 * @brief Define the two types and declare the two permissions, granted to
 * nobody. Idempotent.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_siteasset_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief Stage a site file in @p changeset: create it, or replace its text.
 *
 * @param changeset The changeset.
 * @param name The file name: 1 to ::GDEFCORE_ASSET_NAME_MAX bytes of a-z, 0-9,
 *   '.', '_' and '-', starting with a letter or digit, with no "..".
 * @param name_len Length of @p name.
 * @param kind ::GDEFCORE_ASSET_CSS or ::GDEFCORE_ASSET_JS.
 * @param text The file: UTF-8 with no NUL, 1 to ::GDEFCORE_ASSET_BYTES_MAX bytes.
 * @param text_len Length of @p text.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID for a name, kind or text that
 *   is not one, or a name the site already has as the other kind, or
 *   ::GDEFCORE_ERR_OOM. Nothing is written until the changeset is applied.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_siteasset_stage(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, int kind, const char * text,
    size_t text_len);

/**
 * @brief Stage the removal of the site file called @p name.
 *
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when the site has no such file.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_siteasset_stage_forget(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len);

/**
 * @brief Refuse a changeset that leaves a site file that is not one: a bad
 * name or text, or a name used twice. Called by the apply; the changeset's
 * refusal says which and why.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_siteasset_vet(GDEFCORE_Changeset * changeset);

/**
 * @brief Refuse a changeset that writes a site file its request may not.
 *
 * The permission is ::GDEFCORE_ASSET_CSS_EDIT for a stylesheet and
 * ::GDEFCORE_ASSET_JS_EDIT for a script, asked of each file it writes. The
 * refusal is the one fixed sentence, whatever the file holds. Called by the
 * apply.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_siteasset_authorize(
    GDEFCORE_Changeset * changeset, GDEFCORE_Request * request);

/**
 * @brief Whether the request's principal holds the permission to write a file
 * of @p kind (::GDEFCORE_ASSET_CSS or ::GDEFCORE_ASSET_JS). A kind that is
 * neither is 0.
 */
GDEFCORE_API int gdefcore_siteasset_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, int kind);

#ifdef __cplusplus
}
#endif

#endif
