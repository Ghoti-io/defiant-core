# Menus, tabs and breadcrumbs

A menu is a tree of entries, and it is computed on every read. Nothing about a
page's navigation is stored but what the site itself changed.

## Where an entry comes from

- A **kernel link** (`gdefcore_routes_add_link()`, named `core.<name>`): the
  pages the host serves, which the host registers in its route table.
- A **module link**: a link in an enabled module's manifest. A module that is
  disabled takes its links with it, and a module upgrade that changes a label
  or a route changes the entry.
- A **tab**: a route of kind `GDEFCORE_ROUTE_TAB`. It is an entry named by its
  route, shown on the page of its parent route.
- A **site entry**: a `core.menu-entry` the site made, named `site.<name>`
  (AD-35), with a menu, a label, optionally a route and a parent entry, and a
  weight. An entry with no route only groups the entries under it, and is
  shown only when one of them is.

Generated entries are never stored, so enabling modules in any order, twice,
or off and on again gives the same menu. One name is one entry: where two
sources produce the same name, the first of kernel, module, tab and site stays.
A module's link may not take a route's name; the enable is refused.

## Overrides

The site changes a generated entry with an override: a `core.menu-override`
keyed by the entry's machine name that stores **only the fields the site
changed**: `label`, `weight`, `hidden`, `parent` (an entry's name, or `-` for
the top level) and `menu`. It is never a copy of the entry:

- a module upgrade that changes the entry's label or route shows through,
  because the override holds neither;
- the override is kept when the module is disabled and applies again when it
  is enabled, because nothing in it depends on the module being there;
- one more field set is one more field stored, and an override is exactly the
  fields `gdefcore_menu_stage_override()` is given.

A tab can be renamed, reweighted, hidden and moved to another page like any
entry (its `parent` is then the machine name of a route, or of an entry, whose
page it shows on); it has no menu. An entry whose parent is missing, in another
menu or part of a loop is at the top of its menu. A value an override or entry
holds that staging would have refused (a label over 256 bytes, a name that is
not a name) is ignored.

## What is shown

An entry is shown to a viewer when it is not hidden **and the target route's
own permission check passes** for the values of the page being shown
(`gdefcore_routes_permits()`, which asks the route table's check with the
route's own permission and entity capture): there is no permission on an entry
that could drift from its route's. An entry whose route needs a value the page
did not capture has no path, and is not shown. An entry under one that is not
shown is not shown, and a group with nothing under it is not.

*Hidden* removes an entry from every output for everyone, and not the route:
hiding a link is not denying the page. Hiding is the site's, a refusal is the
route's, and neither tells the other's story.

Tabs are generated per matched path. With `/node/:id` a route and
`/node/:id/view` and `/node/:id/edit` its tabs, the tabs of `/node/42` are the
two routes with `42` put in, and each is shown only if its route passes its own
check for that `42`: the edit tab only to someone who may edit node 42. The
tabs of every route the match holds are shown, climbing from a tab to its page,
so the strip is the same on each tab.

Breadcrumbs come from the same entries: the page's entry, and its ancestors up
the tree (a tab's through the page it shows on). An ancestor that is hidden, a
group, or one the viewer may not follow is left out without a trace.

`gdefcore_routes_match()` names the page (the longest pattern the path
reaches, in dispatch order) and the values its segments took; one match serves
every viewer. `gdefcore_menu_tree()`, `gdefcore_menu_tabs()` and
`gdefcore_menu_breadcrumbs()` return flat lists with a depth and the index of
each item's parent; `current` marks the entry whose route the page holds and
`trail` the entries above it.

## Editing

`gdefcore_menu_declare()` defines the types and declares the permission to
edit. A site entry has an optional `hidden` flag, as an override has. There is
one action, `core.menu.edit`, declared on each type under the
labels `Edit menu entries` and `Edit menu overrides`; roles are granted both to
edit menus, nobody is granted either by default, and a condition on a grant may
name a site entry's `menu`, `name`, `route` and `parent`.

Every write is a changeset (`gdefcore_menu_stage_entry()`,
`gdefcore_menu_stage_override()`, `gdefcore_menu_stage_forget()`), so it has a
revision, can be undone, and needs the typed confirmation any configuration
write needs: the names of the types it writes. Apply asks
`gdefcore_menu_authorize()` when the changeset carries a request: the decision
of `gdefcore_access_can()` about the entry as it is stored and of
`gdefcore_access_can_with()` about the entry as the write leaves it (a new
entry, or one moved to another menu, is not yet what is stored). A refusal
writes nothing and says "That edit is not allowed."

`gdefcore_menu_entries()` is the editor's list: every entry of every menu and
every tab, with whether the site hid it, whether an override applies, and
whether the viewer would see it. Only a principal who may edit menus asks it.

## Editing as an editor does

An editor changes a menu one action at a time, and each action is one
changeset: `gdefcore_menu_stage_edit()` takes a `GDEFCORE_Menu_Edit` and stages
add, rename, hide, show, remove, move and the four moves a keyboard makes (up,
down, indent: put it last under the sibling before it, outdent: put it after its
parent). The same call serves a drag, which names a parent and a position, and a
key, which names only the move.

- **A generated entry is never copied.** Rename, hide, show, and moving write an
  override keyed by the entry's machine name that holds what the override held
  and what the edit changes, and nothing of the entry. A site entry is edited as
  it is, and a remove applies to site entries only (a generated entry is hidden).
- **A move is one changeset or none.** Room is made between the new neighbours
  with their weights where there is any; where the neighbours leave none (every
  entry has weight 0, or two weights are next to each other) every sibling is
  numbered again in the same changeset, and only an entry whose weight or parent
  differs from what it has is written.
- **A stale edit is refused.** The edit names the version of the menus the editor
  showed (`gdefcore_menu_version()` of the list `gdefcore_menu_entries()`
  returned); if the menus are not that now, nothing is staged and the refusal is
  `GDEFCORE_MENU_REFUSED_STALE`. Apply is also refused if anything the edit
  writes has been written since the changeset was prepared, as for any changeset.
- **A cycle is refused.** An entry cannot go under itself or under one of its own
  entries, nor under an entry that is not in its menu, nor so deep that the menu
  stops showing it.
- **Hidden is hidden.** A hidden entry is in no output, and the route behind it is
  still served.

Staging asks who may edit menus (`gdefcore_menu_may_edit()`), so that a refusal
tells a visitor nothing about the menus, and apply asks about every entry written
(`gdefcore_menu_authorize()`).

### Undo

An edit that writes anything also writes a record, the single `core.menu-change`
entity named `last`, one line for each entry or override it wrote: the entity,
the revision it had when the changeset was prepared, and whether the edit cleared
it. `gdefcore_menu_stage_undo()` reads the record and stages, in one changeset,
the values each entity had before: an entry the edit made is cleared, one it
cleared is restored, one it changed gets its earlier values. It is a new
revision, never an edit of the past. It is refused when any entity the edit wrote
has been written since, so an undo never overwrites a later edit, and it empties
the record, so an edit is undone once. The record names entities and revisions
and nobody's text, and it is bookkeeping: every write undo makes is authorized as
a menu write.

## Tenants

A catalog reads its own tenant's entries and overrides and the modules enabled
for its own tenant. Two tenants' menus, entries and overrides never mix.

## Widgets

The menu, the tabs and the breadcrumbs are template kinds (`core.menu`,
`core.tabs`, `core.breadcrumbs`), seeded with a template each by the render
kit. `gdefcore_render_widget()` computes the entries for the page and the
viewer, and draws them with a stored template; a display's pane of the kind
`menu`, `tabs` or `breadcrumbs` does the same for the page being rendered. A
pane's target is `<menu>` or `<menu>/<template>` for a menu and the template's
name for the others, and its text is the engine's, escaped; only `href`, run
through `url()`, can make a link. A site restyles a widget by editing its
template, like any other (templates.md).

A widget is given an optional fragment cache, and keeps the fragment under a
key made of the render key (the tenant, the config epoch, the viewer's
permission set, the viewer when the render read them, and the entities and
revisions the visibility read), the widget and its template and menu, and
**every value the page matched**. A viewer with another permission set, or the
same viewer on the page of another `:id`, is another fragment, and so is
another tenant's. The entries are computed before the cache is asked, because
what their visibility read is part of the key; the cache saves drawing them.
