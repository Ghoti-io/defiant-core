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
 * @file layout.h
 * @brief Widget types, layouts, and layout selection through the route trie.
 * @stability free
 *
 * A **widget type** is a template kind and the source of the variables its
 * template reads. The catalog has eight built in (site name, page title, page
 * content, menu, tabs, breadcrumbs, messages, recent posts) and an enabled
 * module adds more through its manifest (GDEFCORE_Module_Widget), with no
 * change to the kernel.
 *
 * A **layout** is a `core.display`: the page template it uses (which declares
 * its regions) and an ordered list of placements, `region widget [target]`. A
 * layout that names a region its page template does not declare, or a widget
 * type nobody offers, is refused when it is saved (gdefcore_layout_vet(), at
 * apply) and is never applied to a page (gdefcore_layout_check()).
 *
 * A **selector rule** is a `core.layout-rule`: a path pattern, the layout it
 * chooses, and optionally the type of the entity the page must be and whether
 * the pattern is the whole path. Rules and layouts are configuration on the
 * entity port, changed only by changeset (revisions, undo), and read from the
 * catalog's own tenant.
 *
 * **Selection** is a contributor kind of the route trie
 * (::GDEFCORE_CONTRIBUTOR_LAYOUT). The trie keeps one contributor of its own,
 * ::GDEFCORE_LAYOUT_RULES_CONTRIBUTOR, which offers the site's rules; a module
 * adds contributors through its manifest. The offers are ordered by the trie
 * (gdefcore_routes_offers()), most specific first, in one order that does not
 * depend on the order modules were enabled or contributors registered, and the
 * first layout that can be applied wins. A contributor offers a layout name
 * and nothing else: it is given no way to set the request's resolution or to
 * write the page, so it cannot change the main content.
 *
 * The **alter hook** ::GDEFCORE_HOOK_LAYOUT is then fired as an alter, with the
 * chosen layout as the shared value: a module subscribed to it may name
 * another layout (by role, by classification), and the subscribers compose in
 * the host's one order (AD-10). It changes the layout and nothing else: the
 * decision a subscriber reports is not read, a subscriber that fails is
 * skipped, and a name that is not a layout that can be applied is ignored, so
 * no refinement can deny a page.
 *
 * Whether a widget shows is decided by its source: the access filter for what
 * it reads of an entity, the target route's own check for a menu entry, the
 * widget's permission for a module's. A widget the viewer may not read draws
 * nothing and says nothing about why.
 */

#ifndef GHOTI_IO_GDEFCORE_LAYOUT_H
#define GHOTI_IO_GDEFCORE_LAYOUT_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/form.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The entity type of a layout. Its fields: `name`, `layout` (the page
 * template), `panes` (the placements, many). */
#define GDEFCORE_LAYOUT_TYPE "core.display"
/** The entity type of a selector rule. Its fields: `name`, `path`, `layout`;
 * and optional `type`, `exact`, `weight`. */
#define GDEFCORE_LAYOUT_RULE_TYPE "core.layout-rule"
/** The action of the permission to edit layouts and their rules. */
#define GDEFCORE_LAYOUT_EDIT "core.layout.edit"
/** The label of that permission on layouts. */
#define GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL "Edit layouts"
/** The label of that permission on selector rules. */
#define GDEFCORE_LAYOUT_EDIT_RULE_LABEL "Edit layout rules"
/** What a site rule's name starts with (AD-35). */
#define GDEFCORE_LAYOUT_SITE_PREFIX "site."
/** The trie's own contributor, which offers the site's rules. */
#define GDEFCORE_LAYOUT_RULES_CONTRIBUTOR "core.layout-rules"
/** The alter hook fired once a layout has been chosen. */
#define GDEFCORE_HOOK_LAYOUT "layout"

/** The built-in widget types. */
#define GDEFCORE_WIDGET_SITENAME "sitename"
#define GDEFCORE_WIDGET_TITLE "title"
#define GDEFCORE_WIDGET_CONTENT "content"
#define GDEFCORE_WIDGET_MESSAGES "messages"
#define GDEFCORE_WIDGET_RECENT "recent"

/** How many widget types are built in (the menu, tabs and breadcrumbs of
 * render.h among them). */
#define GDEFCORE_LAYOUT_BUILTIN_WIDGETS 8
/** Most placements one layout holds. */
#define GDEFCORE_LAYOUT_PANES_MAX 32
/** Longest layout, rule or widget name, in bytes. */
#define GDEFCORE_LAYOUT_NAME_MAX 128

/**
 * @brief A widget type as the catalog reports it. Begins with @ref size.
 *
 * The texts are borrowed: those of a built-in type are static, a module's are
 * the host's and valid until it is destroyed.
 */
typedef struct GDEFCORE_Layout_Widget {
  size_t size;                ///< `sizeof(GDEFCORE_Layout_Widget)`.
  const char * name;          ///< `sitename`, ... or `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * kind;          ///< The template kind it is drawn with.
  size_t kind_len;            ///< Length of @ref kind.
  const char * template_name; ///< The template drawn when a placement names none.
  size_t template_len;        ///< Length of @ref template_name.
  const char * permission;    ///< What its source needs of the viewer, or "".
  size_t permission_len;      ///< Length of @ref permission.
  const char * module;        ///< The declaring module, or "" for a built-in.
  size_t module_len;          ///< Length of @ref module.
  int builtin;                ///< 1 to 8 for a built-in type, else 0.
  GDEFCORE_Widget_Fn fn;      ///< A module's provider, else NULL.
  void * user;                ///< Its user pointer.
} GDEFCORE_Layout_Widget;

/**
 * @brief How many widget types the catalog's tenant may place: the built-in
 * ones and those of the modules enabled for it.
 */
GDEFCORE_API size_t gdefcore_layout_widget_count(GDEFCORE_Catalog * catalog);

/**
 * @brief Widget type @p index: the built-in ones first, in a fixed order, then
 * the enabled modules' in module order and then by name. @p out->size must be
 * `sizeof(GDEFCORE_Layout_Widget)`. ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_widget_at(GDEFCORE_Catalog * catalog,
    size_t index, GDEFCORE_Layout_Widget * out);

/** @brief The widget type @p name, or ::GDEFCORE_ERR_INVALID if the tenant has
 * none (a module's type of a module that is disabled is none). */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_widget_find(
    GDEFCORE_Catalog * catalog, const char * name, size_t name_len,
    GDEFCORE_Layout_Widget * out);

/**
 * @brief Define the types of layouts' selector rules and the permission to edit
 * layouts and rules, which is granted to nobody. Repeating it changes nothing.
 * The render kit does it (gdefcore_render_install()).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief Whether the layout @p name can be applied to a page: it exists and is
 * published, its page template exists, and every placement is well formed,
 * names a region that template declares and a widget type the tenant has.
 * ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_check(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len);

/** @brief A selector rule to stage. Begins with @ref size. */
typedef struct GDEFCORE_Layout_Rule {
  size_t size;                ///< `sizeof(GDEFCORE_Layout_Rule)`.
  const char * path;          ///< Pattern, `/a/:name/*`. Required.
  size_t path_len;            ///< Length of @ref path.
  const char * layout;        ///< The layout it chooses. Required.
  size_t layout_len;          ///< Length of @ref layout.
  const char * type;          ///< The entity type the page must be, or NULL.
  size_t type_len;            ///< Length of @ref type.
  int exact;                  ///< Non-zero: only a path that is the pattern.
  int weight;                 ///< Breaks a tie of specificity: lowest first.
} GDEFCORE_Layout_Rule;

/**
 * @brief Stage the site's rule @p name (`site.<name>`), made if there is none.
 *
 * The pattern is checked as the route table checks one. The layout need not
 * exist yet (a rule may be staged ahead of its layout); a rule whose layout
 * cannot be applied is passed over when the page is chosen.
 * ::GDEFCORE_ERR_INVALID for anything malformed.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_stage_rule(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len,
    const GDEFCORE_Layout_Rule * rule);

/** @brief Stage the removal of the site's rule @p name. */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_stage_forget(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len);

/**
 * @brief Refuse a changeset that writes a layout or a rule that is not valid.
 *
 * Called by apply, with or without a request. Every layout the changeset
 * writes is checked as gdefcore_layout_check() does, as the write leaves it:
 * its page template is read through the changeset, a placement that names an
 * undeclared region or a widget nobody offers refuses the whole changeset and
 * nothing is written. A rule's pattern, layout name, type, flag and weight are
 * checked the same way. The refusal says which layout or rule and what.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_vet(GDEFCORE_Changeset * changeset);

/**
 * @brief Refuse a changeset a principal may not make: one action,
 * ::GDEFCORE_LAYOUT_EDIT, asked of each layout and rule it writes, as it is
 * stored and as the write leaves it. Called by apply for a changeset that
 * carries a request.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_authorize(
    GDEFCORE_Changeset * changeset, GDEFCORE_Request * request);

/**
 * @brief The trie's own layout contributor
 * (::GDEFCORE_LAYOUT_RULES_CONTRIBUTOR): offers every site rule, each ranked
 * by its own pattern, for the trie to keep the ones that reach the path. A
 * rule that names a type is offered only for a page whose entity is of that
 * type, and ranks above the same pattern without one. Registered in every
 * route table; not called directly.
 */
GDEFCORE_API void gdefcore_layout_site_contributor(
    const GDEFCORE_Contributor_Call * call);

/**
 * @brief What the alter hook ::GDEFCORE_HOOK_LAYOUT is given. Begins with
 * @ref size.
 */
typedef struct GDEFCORE_Layout_Hook {
  size_t size;                ///< `sizeof(GDEFCORE_Layout_Hook)`.
  const char * path;          ///< The page's path.
  size_t path_len;            ///< Length of @ref path.
  const char * entity_type;   ///< The type of the page's entity, or "".
  size_t entity_type_len;     ///< Length of @ref entity_type.
} GDEFCORE_Layout_Hook;

/**
 * @brief Choose the layout of the page @p path for @p request.
 *
 * Gathers the layout offers of the trie @p routes (NULL: a table of the
 * kernel's own contributor only), takes the first that
 * gdefcore_layout_check() accepts, fires ::GDEFCORE_HOOK_LAYOUT on the
 * tenant's host (if the catalog has one), and keeps the refined name only if
 * it is a layout that can be applied. The request's resolution is the page's
 * entity, as gdefcore_form_resolve() left it. ::GDEFCORE_ERR_INVALID when no
 * layout applies. Free @p out_name with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_layout_select(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request, const char * path,
    size_t path_len, char ** out_name, size_t * out_len);

/** @brief Whether the request's principal may edit layouts at all (decision:
 * yes or no; the type-level question, as gdefcore_access_permits() asks). */
GDEFCORE_API int gdefcore_layout_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_LAYOUT_H */
