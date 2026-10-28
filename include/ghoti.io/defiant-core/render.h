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
 * @brief Render @p body as a template of @p kind against sample data.
 *
 * For an editor's preview. Every variable the kind's base declares is bound
 * to the text `Sample <name>`, `region(x)` gives a marked stand-in, and a
 * module's contributed variable is its real lazy provider, called with
 * @p request. The body is not stored and nothing is written. It is rendered
 * under the contract of @p kind exactly as a stored template is.
 *
 * @p overlay names the render. A fragment rendered under any overlay but
 * `live` (NULL and empty are `live`) must not enter a shared cache
 * (gdefcore_access_shared_cache()); @p out_shareable receives whether this
 * one may, and gdefcore_render_shareable_count() counts the ones that may. An
 * editor passes an overlay of its own, `preview`.
 *
 * A principal who may edit no template of @p kind
 * (gdefcore_template_may_edit()) gets ::GDEFCORE_ERR_INVALID, the same as a
 * kind that does not exist. A body that does not parse, or that fails at run
 * time, returns the error and writes no bytes.
 *
 * Free @p out_bytes with gdefcore_text_free(). Not written on failure.
 *
 * @param scope_fuel The budget of the template. Zero is
 *   ::GDEFCORE_ERR_INVALID.
 * @param out_shareable May be NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_sample(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * kind, size_t kind_len,
    const char * body, size_t body_len, const char * overlay,
    size_t overlay_len, uint64_t scope_fuel, char ** out_bytes, size_t * out_len,
    int * out_shareable);

/**
 * @brief Render the stored template @p template_name with entity @p id in its
 * context, in language @p lang, as the request's principal may read it
 * (story S6d).
 *
 * The template's kind declares a variable `entity` (of type `entity`), which
 * is bound to a map: each single field of the root a string, each group and
 * each multiple field a list in item order, a group's items maps of the same
 * shape at every depth, a multiple field's items its values. It is
 * gdefcore_access_tree() made into a value: the access filter is applied per
 * field in every item, so a field the principal may not read is absent from
 * every item that has it, and so is a field with no value or a group with no
 * items (absent, not hidden: a template cannot tell them apart). Values are
 * texts bound for the strictest encoding, as every bound field is (render.md).
 * A personal value of a field the principal may read is its plaintext,
 * decrypted by gdefcore_access_tree() after the filter allowed the field, or
 * ::GDEFCORE_SUBJECT_ERASED for an erased subject; its sealed text is never
 * rendered, and a catalog with no subjects bound renders none (story S7).
 * Each subject decrypted is recorded on @p request
 * (gdefcore_request_record_subject()), so a fragment cached from it is
 * purged when that subject is erased (gdefcore_fragment_put()). A kind that
 * does not declare `entity` binds nothing.
 *
 * An entity the principal may not see, an unknown template, one with no kind
 * and a kind that does not exist are one answer, ::GDEFCORE_ERR_INVALID, and
 * @p out_bytes is not written. Free @p out_bytes with gdefcore_text_free().
 *
 * @param scope_fuel The budget of the template. Zero is ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_entity(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * template_name,
    size_t template_len, const char * id, size_t id_len, const char * lang,
    size_t lang_len, uint64_t scope_fuel, char ** out_bytes, size_t * out_len);

/**
 * @brief How many fragments this process has offered to a shared cache.
 *
 * A render of a stored template is offered under the `live` overlay. A
 * gdefcore_render_sample() under any other overlay is not offered, and a
 * counter that moves across one is a fragment that would be cached for
 * everyone. Only a difference between two reads means anything.
 */
GDEFCORE_API uint64_t gdefcore_render_shareable_count(void);

/* ---- the fragment cache (story S7) -------------------------------------- */

/**
 * @brief Rendered fragments, keyed by the render key, each with the subjects
 * whose personal values it decrypted (AD-19, AD-26). Opaque.
 *
 * A fragment that decrypted a subject is purged when that subject is erased:
 * bind the cache to the tenant's subjects (gdefcore_subject_bind_cache()) and
 * erasure's third step purges it, as does every ledger replay. A fragment that
 * decrypted nothing is kept. The cache is in this process only, and safe to
 * use from several threads; it holds plaintext of personal values, so it is
 * never written anywhere, and a key holds none (it is a render key,
 * gdefcore_access_render_key()). Eviction is first in, first out once it holds
 * its capacity.
 */
typedef struct GDEFCORE_FragmentCache GDEFCORE_FragmentCache;

/** @brief A cache of at most @p capacity fragments (0: 1024). */
GDEFCORE_API GDEFCORE_Result gdefcore_fragment_cache_create(
    const GDEFCORE_Allocator * allocator, size_t capacity,
    GDEFCORE_FragmentCache ** out_cache);

/** @brief Release a cache and every fragment in it. NULL is ignored. Unbind
 * it from its subjects first (gdefcore_subject_bind_cache(), NULL). */
GDEFCORE_API void gdefcore_fragment_cache_destroy(GDEFCORE_FragmentCache * cache);

/**
 * @brief Keep @p bytes under @p key, with the subjects @p request recorded as
 * decrypted while it rendered them (gdefcore_request_subject_count()).
 *
 * A fragment already under @p key is replaced. A request whose subject set
 * overflowed (gdefcore_request_subjects_overflowed()) is ::GDEFCORE_ERR_LIMIT
 * and nothing is kept: a fragment whose dependencies are not all known could
 * outlive an erasure. So is a request that is not cacheable
 * (gdefcore_request_cacheable(): it consulted an access callback that
 * declares no cacheability, or one that failed). The bytes and the key are
 * copied.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_fragment_put(
    GDEFCORE_FragmentCache * cache, const GDEFCORE_Request * request,
    const char * key, size_t key_len, const char * bytes, size_t len);

/**
 * @brief The fragment under @p key: a copy in @p out_bytes and @p out_found 1,
 * or @p out_found 0 and nothing written. Free @p out_bytes with
 * gdefcore_fragment_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_fragment_get(
    GDEFCORE_FragmentCache * cache, const char * key, size_t key_len,
    char ** out_bytes, size_t * out_len, int * out_found);

/** @brief Free bytes from gdefcore_fragment_get(). NULL is ignored. */
GDEFCORE_API void gdefcore_fragment_free(GDEFCORE_FragmentCache * cache,
    char * bytes);

/**
 * @brief Purge every fragment that decrypted a value of @p subject. Erasure
 * calls this (gdefcore_subject_bind_cache()). @p out_purged (may be NULL)
 * receives how many went. A subject that is no public id is
 * ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_fragment_purge_subject(
    GDEFCORE_FragmentCache * cache, const char * subject, size_t subject_len,
    size_t * out_purged);

/** @brief How many fragments the cache holds. */
GDEFCORE_API size_t gdefcore_fragment_count(GDEFCORE_FragmentCache * cache);

/* ---- navigation widgets (site admin story 6) ---------------------------- */

/** The widget (and pane) kind that draws a menu. Its template kind is
 * `core.menu`. */
#define GDEFCORE_WIDGET_MENU "menu"
/** The widget kind that draws the tabs of the page. Template kind `core.tabs`. */
#define GDEFCORE_WIDGET_TABS "tabs"
/** The widget kind that draws the breadcrumbs. Template kind `core.breadcrumbs`. */
#define GDEFCORE_WIDGET_BREADCRUMBS "breadcrumbs"

/**
 * @brief Draw a menu, the tabs of a page, or its breadcrumbs, with a stored
 * template.
 *
 * The widget is computed for the page @p path (gdefcore_routes_match()) and
 * for the request's principal (menu.h), then drawn by a template of the kind
 * `core.menu`, `core.tabs` or `core.breadcrumbs`, which a site can restyle
 * like any other (templates.md). The template reads one variable, `items`: a
 * list of maps, in order, each with `name`, `label`, `route`, `href`, `menu`,
 * `weight`, `depth`, `current` and `trail`; `core.menu` also reads `menu`, the
 * name of the menu. Every text in it is bound for the strictest encoding, and
 * `url()` makes an `href` safe.
 *
 * @p kind is ::GDEFCORE_WIDGET_MENU, ::GDEFCORE_WIDGET_TABS or
 * ::GDEFCORE_WIDGET_BREADCRUMBS. @p target is `<menu>` or `<menu>/<template>`
 * for a menu (the template is `menu` unless named), and the template's name,
 * or empty for the template of that kind's own name, for the other two. This is
 * also what a display's pane of that kind names as its target. @p path is the
 * page, as the request named it; a path no route reaches draws the widget for
 * a page that matched nothing. @p routes may be NULL, for a host with none.
 *
 * @p cache, when not NULL, keeps the fragment under a key made of the render
 * key (gdefcore_access_render_key(): the tenant, the config epoch, the
 * **permission set** of the principal, the principal when the render read it,
 * and the entities and revisions the visibility read) and of the widget, its
 * template, and **every value the page matched**: a viewer with another
 * permission set, or the same viewer on the page of another `:id`, is another
 * fragment. The entries are worked out first, because what they read is part of
 * the key; the cache saves drawing them. A fragment the cache refuses (the
 * request is not cacheable) is returned all the same.
 *
 * An unknown kind, a template that does not exist or is not of the kind's
 * template kind, and a zero @p scope_fuel are ::GDEFCORE_ERR_INVALID. Free
 * @p out_bytes with gdefcore_text_free(). Not written on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_widget(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    GDEFCORE_FragmentCache * cache, const char * kind, size_t kind_len,
    const char * target, size_t target_len, const char * path, size_t path_len,
    uint64_t scope_fuel, char ** out_bytes, size_t * out_len);

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
 * gdefcore_text_free(). A kind is `view`, `entity`, `field`, `menu`, `tabs`
 * or `breadcrumbs`; the last three are drawn by gdefcore_render_widget() for
 * the page being rendered.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_render_pane_at(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, size_t index, char ** out_region,
    size_t * out_region_len, char ** out_kind, size_t * out_kind_len,
    char ** out_target, size_t * out_target_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_RENDER_H */
