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
 * @file menu.h
 * @brief Hierarchical menus, tabs generated per page, and breadcrumbs.
 * @stability free
 *
 * A menu is a tree of entries, and it is computed on every read. An entry is
 * one of
 *
 *  - a **kernel link** (gdefcore_routes_add_link()), a **module link** (a
 *    link in an enabled module's manifest), or a **tab** (a route of kind
 *    ::GDEFCORE_ROUTE_TAB): *generated* from what is declared now, never
 *    stored, so a module that is disabled takes its entries with it and a
 *    module upgrade that changes a label or a route changes the entry;
 *  - a **site entry**: a `core.menu-entry` the site made, named `site.<name>`,
 *    stored on the entity port like any other configuration.
 *
 * The site changes a generated entry with an **override**, a
 * `core.menu-override` keyed by the entry's machine name that stores only the
 * fields the site changed: its label, its weight, whether it is hidden, its
 * parent and its menu. An override is never a copy of the entry. It is kept
 * when the module is disabled and applies again when the module is enabled,
 * and it follows the entry through an upgrade, because it holds nothing the
 * entry says.
 *
 * Whether a viewer sees an entry is decided by the **target route's own
 * permission check** (gdefcore_routes_permits()), for the values the page
 * matched, and by nothing else: an entry has no permission of its own that
 * could drift from its route's. An entry whose route needs a value the page
 * did not capture is not shown, as it has no address. A hidden entry is shown
 * to nobody in any output, and its route is still served: hiding a link is not
 * denying a page. An entry whose ancestor is not shown is not shown.
 *
 * Tabs are generated per matched path. With `/node/:id` a route and
 * `/node/:id/view` and `/node/:id/edit` its tabs, the tabs of the page
 * `/node/42` are the two routes with `42` put in, and each is shown only if
 * the route behind it passes its own check for that `42`.
 *
 * Every write goes through a changeset (revisions, undo, the typed
 * confirmation of any configuration write), and apply asks
 * gdefcore_menu_authorize() when the changeset carries a request. Whoever may
 * edit menus (::GDEFCORE_MENU_EDIT) may also list every entry, hidden or not
 * (gdefcore_menu_entries()); everyone else sees what the outputs show.
 *
 * Tenants are separate: a catalog reads its own tenant's entries and
 * overrides, and the enabled modules of its own tenant.
 */

#ifndef GHOTI_IO_GDEFCORE_MENU_H
#define GHOTI_IO_GDEFCORE_MENU_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/form.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The entity type of a site-made entry. Its fields: `name`, `menu`, `label`,
 * `route`, `parent`, `weight`, and `hidden` (optional: 1 when the site hid it). */
#define GDEFCORE_MENU_ENTRY_TYPE "core.menu-entry"
/** The entity type of an override. Its fields: `name`, `label`, `weight`,
 * `hidden`, `parent`, `menu`; every one but `name` is optional. */
#define GDEFCORE_MENU_OVERRIDE_TYPE "core.menu-override"
/** The action of the permission to edit menus. */
#define GDEFCORE_MENU_EDIT "core.menu.edit"
/** The label of that permission on site entries. */
#define GDEFCORE_MENU_EDIT_ENTRY_LABEL "Edit menu entries"
/** The label of that permission on overrides. */
#define GDEFCORE_MENU_EDIT_OVERRIDE_LABEL "Edit menu overrides"
/** What a site entry's name starts with (AD-35). */
#define GDEFCORE_MENU_SITE_PREFIX "site."
/** An override's `parent` that moves an entry to the top level of its menu. */
#define GDEFCORE_MENU_TOP "-"
/** The entity type of the record of the last menu edit, which undo reads. Its
 * fields: `name` (always `last`) and `entities`, one `<id> <seq> <S|C>` line
 * for each entry or override the edit wrote. */
#define GDEFCORE_MENU_CHANGE_TYPE "core.menu-change"
/** Length of a menu version (gdefcore_menu_version()), without the NUL. */
#define GDEFCORE_MENU_VERSION_LEN 16
/** Most entries or overrides one edit writes. A move that would write more is
 * refused. */
#define GDEFCORE_MENU_EDIT_MAX 256

/** An edit: add a site entry under a parent, at the end of its siblings. */
#define GDEFCORE_MENU_ACT_ADD 1
/** An edit: give an entry another label. */
#define GDEFCORE_MENU_ACT_RENAME 2
/** An edit: hide an entry from every output. */
#define GDEFCORE_MENU_ACT_HIDE 3
/** An edit: show a hidden entry again. */
#define GDEFCORE_MENU_ACT_SHOW 4
/** An edit: remove a site entry. A generated entry is hidden, not removed. */
#define GDEFCORE_MENU_ACT_REMOVE 5
/** An edit: put an entry under a parent at a position. */
#define GDEFCORE_MENU_ACT_MOVE 6
/** An edit: swap an entry with the sibling before it. */
#define GDEFCORE_MENU_ACT_UP 7
/** An edit: swap an entry with the sibling after it. */
#define GDEFCORE_MENU_ACT_DOWN 8
/** An edit: put an entry last under the sibling before it. */
#define GDEFCORE_MENU_ACT_INDENT 9
/** An edit: put an entry after its parent, under its grandparent. */
#define GDEFCORE_MENU_ACT_OUTDENT 10

/** The refusal (gdefcore_changeset_refusal()) of an edit based on a menu that
 * has since changed. Nothing is staged. */
#define GDEFCORE_MENU_REFUSED_STALE \
  "The menu changed since this page was shown. Nothing was changed."
/** The refusal of a move under the entry itself or one of its own entries. */
#define GDEFCORE_MENU_REFUSED_CYCLE \
  "An entry cannot be moved under itself or under one of its own entries."
/** The refusal of a move under an entry that is not in the menu. */
#define GDEFCORE_MENU_REFUSED_PARENT "That parent is not in this menu."
/** The refusal of an edit that names an entry that is not there, or one that
 * cannot take the edit (a tab cannot move). */
#define GDEFCORE_MENU_REFUSED_ENTRY "That entry cannot take that edit."
/** The refusal of a move that cannot be made: the entry is already first,
 * last, top level or has no sibling before it, or it would sit too deep. */
#define GDEFCORE_MENU_REFUSED_PLACE "That entry cannot move that way."
/** The refusal of removing a generated entry. */
#define GDEFCORE_MENU_REFUSED_REMOVE \
  "A generated entry is hidden, not removed."
/** The refusal of an edit that would write more than ::GDEFCORE_MENU_EDIT_MAX
 * entries. */
#define GDEFCORE_MENU_REFUSED_MANY "That edit would change too many entries."
/** The refusal of an undo when there is no edit to undo. */
#define GDEFCORE_MENU_REFUSED_NOTHING "There is no menu edit to undo."
/** The refusal of an undo of an edit whose entries were written since. */
#define GDEFCORE_MENU_REFUSED_UNDO \
  "The menu changed after that edit, so it cannot be undone."

/** Longest menu name, in bytes. */
#define GDEFCORE_MENU_NAME_MAX 64
/** Longest entry name, in bytes. */
#define GDEFCORE_MENU_ENTRY_NAME_MAX 128
/** Longest label, in bytes. */
#define GDEFCORE_MENU_LABEL_MAX 256
/** Most entries one menu computation holds; more is ::GDEFCORE_ERR_LIMIT. */
#define GDEFCORE_MENU_ENTRIES_MAX 2048
/** Deepest nesting a menu shows. Entries below it are not shown. */
#define GDEFCORE_MENU_DEPTH_MAX 16

/** An entry from a kernel link (gdefcore_routes_add_link()). */
#define GDEFCORE_MENU_SOURCE_KERNEL 1
/** An entry from a link an enabled module declares. */
#define GDEFCORE_MENU_SOURCE_MODULE 2
/** An entry from a tab route. */
#define GDEFCORE_MENU_SOURCE_TAB 3
/** An entry the site made. */
#define GDEFCORE_MENU_SOURCE_SITE 4
/** A breadcrumb that is a route with a title and no entry. */
#define GDEFCORE_MENU_SOURCE_ROUTE 5

/** The parent of an item with none. */
#define GDEFCORE_MENU_NO_PARENT ((size_t)-1)

/** A computed menu, tab strip or breadcrumb trail. Opaque. */
typedef struct GDEFCORE_Menu GDEFCORE_Menu;

/**
 * @brief One item of a computed menu. Begins with @ref size.
 *
 * The texts are borrowed from the menu and valid until it is freed. A text
 * with nothing in it is "" and never NULL.
 */
typedef struct GDEFCORE_Menu_Item {
  size_t size;                ///< `sizeof(GDEFCORE_Menu_Item)`.
  const char * name;          ///< The entry's machine name; for a route
                              ///< breadcrumb, the route's.
  size_t name_len;            ///< Length of @ref name.
  const char * label;         ///< The label, after any override.
  size_t label_len;           ///< Length of @ref label.
  const char * route;         ///< The target route's machine name, or "" for an
                              ///< entry that only groups others.
  size_t route_len;           ///< Length of @ref route.
  const char * href;          ///< The path, with the page's values put in, or
                              ///< "" for an entry that only groups others.
  size_t href_len;            ///< Length of @ref href.
  const char * menu;          ///< The menu it is in, or "" for a tab.
  size_t menu_len;            ///< Length of @ref menu.
  const char * parent;        ///< The machine name of its parent as the entry
                              ///< says, or "" for the top level.
  size_t parent_len;          ///< Length of @ref parent.
  int weight;                 ///< The weight, after any override.
  int kind;                   ///< ::GDEFCORE_ROUTE_PAGE, _TAB or _ACTION.
  int source;                 ///< A `GDEFCORE_MENU_SOURCE_` value.
  int depth;                  ///< 0 at the top of a tree; 0 for a tab or crumb.
  size_t up;                  ///< Index of the parent item in this menu, or
                              ///< ::GDEFCORE_MENU_NO_PARENT.
  int current;                ///< The page being shown is this entry's route.
  int trail;                  ///< Some item below this one is current.
  int hidden;                 ///< The site hid it. Only gdefcore_menu_entries()
                              ///< lists a hidden item.
  int overridden;             ///< An override applies to it.
  int visible;                ///< The viewer would see it. Always 1 but in
                              ///< gdefcore_menu_entries().
} GDEFCORE_Menu_Item;

/**
 * @brief What the site changed about a generated entry. Begins with @ref size.
 *
 * Only what is set is stored. A NULL text, a clear @ref has_weight and a
 * @ref hidden of -1 leave the entry as its module made it.
 */
typedef struct GDEFCORE_Menu_Override {
  size_t size;                ///< `sizeof(GDEFCORE_Menu_Override)`.
  const char * label;         ///< A new label, or NULL.
  size_t label_len;           ///< Length of @ref label.
  int has_weight;             ///< Non-zero when @ref weight is set.
  int weight;                 ///< A new weight.
  int hidden;                 ///< 1 to hide, 0 to show though a module hid it
                              ///< (stored), -1 for no change.
  const char * parent;        ///< A new parent: an entry's machine name,
                              ///< ::GDEFCORE_MENU_TOP, or NULL. For a tab, the
                              ///< machine name of the route it shows on.
  size_t parent_len;          ///< Length of @ref parent.
  const char * menu;          ///< A new menu, or NULL. A tab has no menu.
  size_t menu_len;            ///< Length of @ref menu.
} GDEFCORE_Menu_Override;

/**
 * @brief One edit of the menus, as the editor makes it. Begins with
 * @ref size.
 *
 * Which fields an edit reads is named by @ref action; the others are ignored.
 */
typedef struct GDEFCORE_Menu_Edit {
  size_t size;                ///< `sizeof(GDEFCORE_Menu_Edit)`.
  int action;                 ///< A `GDEFCORE_MENU_ACT_` value.
  const char * name;          ///< The entry's machine name; for an add, the new
                              ///< `site.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * label;         ///< Rename and add: the label.
  size_t label_len;           ///< Length of @ref label.
  const char * menu;          ///< Add: the menu the entry is in.
  size_t menu_len;            ///< Length of @ref menu.
  const char * route;         ///< Add: the route it goes to, or "".
  size_t route_len;           ///< Length of @ref route.
  const char * parent;        ///< Move and add: the entry it goes under, or ""
                              ///< for the top level of its menu.
  size_t parent_len;          ///< Length of @ref parent.
  size_t position;            ///< Move: the index it has among its new
                              ///< siblings once it is there (0 is first).
  const char * version;       ///< The version of the menu the editor showed
                              ///< (gdefcore_menu_version()).
  size_t version_len;         ///< Length of @ref version.
} GDEFCORE_Menu_Edit;

/**
 * @brief Define the entity types of menus and declare the permission to edit
 * them.
 *
 * Three types of configuration, ::GDEFCORE_MENU_ENTRY_TYPE,
 * ::GDEFCORE_MENU_OVERRIDE_TYPE and the record of the last edit
 * (::GDEFCORE_MENU_CHANGE_TYPE, which needs no grant), and one action,
 * ::GDEFCORE_MENU_EDIT,
 * declared on each under the labels ::GDEFCORE_MENU_EDIT_ENTRY_LABEL and
 * ::GDEFCORE_MENU_EDIT_OVERRIDE_LABEL, module `core`, granted to nobody,
 * admin included. A role is granted the two to edit menus; a condition on a
 * grant to a site entry may name its `menu`, `name`, `route` and `parent`. A
 * second call changes nothing. Installing the render kit calls this.
 *
 * Reading needs none of it: a catalog that never called this has no entries
 * of its own and the generated ones.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief The entries of menu @p menu that @p request sees, as a tree in
 * depth-first order (siblings by weight, then machine name).
 *
 * @p match is the page being shown (gdefcore_routes_match()): the values its
 * routes captured are put into the entries' paths and given to their routes'
 * checks, and the entries whose route it holds are current. It may be NULL,
 * for a page that matched nothing. An entry that groups others and has none
 * to show is not shown. An unknown menu is an empty menu.
 *
 * Free @p out with gdefcore_menu_free(). It is not written on failure.
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_LIMIT (more
 *   than ::GDEFCORE_MENU_ENTRIES_MAX entries) or the failure of a read.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_tree(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, const char * menu, size_t menu_len,
    GDEFCORE_Menu ** out);

/**
 * @brief The tabs of the page @p match names that @p request may follow.
 *
 * A tab is shown when the route behind it passes its own check for the values
 * of @p match: the edit tab of `/node/42` only to someone who may edit node 42.
 * The tabs are those of every route the match holds, climbing from a tab to
 * its page, so the strip is the same on each tab of a page; the default tab
 * answers the page's own path. Items are in weight order, then machine name,
 * and the one whose route the match holds is current.
 *
 * Free @p out with gdefcore_menu_free(). A page with no tabs is an empty menu.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_tabs(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, GDEFCORE_Menu ** out);

/**
 * @brief The trail from the top of the tree to the page @p match names, from
 * the same entries as gdefcore_menu_tree().
 *
 * The page's entry is found among the entries of @p menu (NULL: any menu, the
 * first by name) and its ancestors are walked up, a tab's through the page it
 * shows on. An ancestor that is hidden, that groups others, or that the
 * request may not follow is **left out without a trace**: the trail has the
 * rest. The last item is the page, ::GDEFCORE_MENU_SOURCE_ROUTE when it has no
 * entry but a title. A page with nothing to show is an empty trail.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_breadcrumbs(
    GDEFCORE_Catalog * catalog, GDEFCORE_Routes * routes,
    GDEFCORE_Request * request, const GDEFCORE_Route_Match * match,
    const char * menu, size_t menu_len, GDEFCORE_Menu ** out);

/**
 * @brief Every entry of every menu and every tab, hidden or not, for the
 * editor of menus.
 *
 * Whole trees in depth-first order by menu name, then the tabs by the page
 * they show on. Each item says whether it is hidden, overridden, and whether
 * @p request would see it (@ref GDEFCORE_Menu_Item::visible) on the page
 * @p match names. Only a principal who may edit menus asks this
 * (gdefcore_menu_may_edit()); anyone else is ::GDEFCORE_ERR_INVALID, the same
 * as for a page that is not there.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_entries(GDEFCORE_Catalog * catalog,
    GDEFCORE_Routes * routes, GDEFCORE_Request * request,
    const GDEFCORE_Route_Match * match, GDEFCORE_Menu ** out);

/** @brief How many items. A NULL menu has none. */
GDEFCORE_API size_t gdefcore_menu_count(const GDEFCORE_Menu * menu);

/**
 * @brief Item @p index. @p out->size must be `sizeof(GDEFCORE_Menu_Item)`.
 * ::GDEFCORE_ERR_INVALID past the end.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_item(const GDEFCORE_Menu * menu,
    size_t index, GDEFCORE_Menu_Item * out);

/** @brief Free a computed menu. NULL is ignored. */
GDEFCORE_API void gdefcore_menu_free(GDEFCORE_Menu * menu);

/**
 * @brief Could the request's principal edit menus at all?
 *
 * True when gdefcore_access_permits() holds ::GDEFCORE_MENU_EDIT for some site
 * entry. It is the question a list of entries asks, where no one entry is in
 * hand; a write is decided per entry by gdefcore_menu_authorize().
 *
 * @return 1 when it may, else 0.
 */
GDEFCORE_API int gdefcore_menu_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request);

/**
 * @brief Stage a site entry: make it, or change the one called @p name.
 *
 * The entry is exactly these fields. @p name is `site.<name>` of at most
 * ::GDEFCORE_MENU_ENTRY_NAME_MAX bytes of a-z, 0-9, '.', '_' and '-'. @p menu
 * is a menu name; @p label is UTF-8 text of 1 to ::GDEFCORE_MENU_LABEL_MAX
 * bytes without control characters. @p route names the route the entry goes
 * to, or is empty for an entry that only groups others. @p parent is the
 * machine name of the entry it sits under, or empty for the top level; an
 * entry whose parent is gone is shown at the top level.
 *
 * Nothing is written until the changeset is applied, and a write of any
 * configuration is high risk: the typed confirmation is the names of the
 * configuration types the changeset writes. The types must have been declared
 * (gdefcore_menu_declare()).
 *
 * @return ::GDEFCORE_OK or ::GDEFCORE_ERR_INVALID (a bad argument, types not
 *   declared); the changeset is unchanged on failure.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_stage_entry(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len,
    const char * menu, size_t menu_len, const char * label, size_t label_len,
    const char * route, size_t route_len, const char * parent, size_t parent_len,
    int weight);

/**
 * @brief Stage an override of the generated entry @p name.
 *
 * The override is exactly the fields @p override sets: what was stored before
 * and is not set again is dropped. @p name must not be a site entry's (change
 * that entry itself) and may be the name of an entry no enabled module
 * generates now: the override waits for it. @p override with nothing set
 * stores an override that changes nothing.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_stage_override(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len,
    const GDEFCORE_Menu_Override * override);

/**
 * @brief Stage removing the site entry or the override called @p name.
 *
 * It is a clear, so history keeps it and undo restores it. An unknown name is
 * ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_stage_forget(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len);

/**
 * @brief Check that @p request may make every menu write in @p changeset.
 *
 * For each site entry and override the changeset saves, drafts, publishes or
 * clears, the decision of gdefcore_access_can() about the entity as it is
 * stored (when it has been stored) **and** of gdefcore_access_can_with() about
 * the entity as the write leaves it, so a value that moves an entry cannot
 * widen the answer of what is stored: a move to another menu needs the grant
 * for the menu it was in and for the one it becomes. A new entry has nothing
 * stored, and the second question is all there is to ask of it. A changeset
 * that writes neither type is success.
 *
 * A refusal returns ::GDEFCORE_ERR_INVALID, sets the changeset's refusal to
 * the fixed sentence "That edit is not allowed." and writes nothing. Apply
 * calls this when the changeset has a request.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_authorize(
    GDEFCORE_Changeset * changeset, GDEFCORE_Request * request);

/**
 * @brief The version of the menus gdefcore_menu_entries() listed: 16
 * lowercase letters (`a` to `p`, four bits each, so that it is never a number)
 * and a NUL, written to @p out.
 *
 * A hash of everything an edit depends on: each entry's name, label, route,
 * menu, parent, weight, hidden state, source and kind, in the order listed. It
 * is not about who asks (what a viewer would see is not in it), and it is not a
 * secret: it says whether the menus an editor was shown are the menus now.
 *
 * @p cap must be at least ::GDEFCORE_MENU_VERSION_LEN + 1.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_version(const GDEFCORE_Menu * menu,
    char * out, size_t cap);

/**
 * @brief Stage one edit of the menus in @p changeset.
 *
 * The editor's actions, each one changeset: add, rename, hide, show, remove,
 * move, and the moves the keyboard makes (up, down, indent, outdent). For a
 * generated entry, rename, hide, show and the moves write an **override** that
 * holds only what the edit changes besides what the override already held, and
 * never a copy of the entry; for a site entry they edit the entry. The siblings
 * a move has to renumber are written in the same changeset, so a move is one
 * revision or none.
 *
 * Refused with ::GDEFCORE_ERR_INVALID (a changeset that was refused is
 * discarded, not applied), with the
 * refusal (gdefcore_changeset_refusal()) one of the `GDEFCORE_MENU_REFUSED_`
 * sentences: an edit whose @ref GDEFCORE_Menu_Edit::version is not the version
 * of the menus now (stale), a move under the entry itself or one of its own
 * entries (cycle) or under an entry that is not in the menu, a tab that moves,
 * a generated entry that is removed, and a position that does not exist.
 *
 * An edit that changes nothing (an entry moved to the place it has) is success
 * and stages nothing: check gdefcore_changeset_touched_count().
 *
 * When the edit writes anything it also stages the record of it
 * (::GDEFCORE_MENU_CHANGE_TYPE) that gdefcore_menu_stage_undo() reads. The
 * record is bookkeeping: it names entries and revisions and no one's text, and
 * the writes undo makes are authorized as any menu write (apply asks
 * gdefcore_menu_authorize()), so the record itself needs no grant.
 *
 * Nothing is written until the changeset is applied. @p routes, @p request and
 * @p match are as for gdefcore_menu_entries().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_stage_edit(
    GDEFCORE_Changeset * changeset, GDEFCORE_Routes * routes,
    GDEFCORE_Request * request, const GDEFCORE_Route_Match * match,
    const GDEFCORE_Menu_Edit * edit);

/**
 * @brief Stage the record of what @p changeset writes of entries and
 * overrides, so that gdefcore_menu_stage_undo() can undo it.
 *
 * gdefcore_menu_stage_edit() does this itself. A caller that stages entries and
 * overrides by hand (gdefcore_menu_stage_entry() and the like) and wants the
 * write undone calls it last, once the changeset names everything it writes.
 * It replaces the record of the earlier edit, and stages nothing when the
 * changeset writes no entry or override. At most ::GDEFCORE_MENU_EDIT_MAX
 * entries are recorded; more is ::GDEFCORE_ERR_INVALID with
 * ::GDEFCORE_MENU_REFUSED_MANY.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_stage_record(
    GDEFCORE_Changeset * changeset);

/**
 * @brief Stage the undo of the last menu edit in @p changeset.
 *
 * Every entry and override the last edit wrote is put back as it was before,
 * in this one changeset: an entry the edit made is cleared, one it cleared is
 * restored, one it changed gets its earlier values again. It is a new
 * revision, as every revert is; old rows are never touched. The record is then
 * emptied, so an edit is undone once.
 *
 * Refused with ::GDEFCORE_ERR_INVALID, and the fixed sentence "That edit is not
 * allowed." and nothing read, when @p request may not edit menus
 * (gdefcore_menu_may_edit()), so that it learns nothing of the last edit;
 * with ::GDEFCORE_MENU_REFUSED_NOTHING when
 * there is no edit to undo, and with ::GDEFCORE_MENU_REFUSED_UNDO when any
 * entry the edit wrote has been written since, so that an undo never
 * overwrites a later edit.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_menu_stage_undo(
    GDEFCORE_Changeset * changeset, GDEFCORE_Request * request);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_MENU_H */
