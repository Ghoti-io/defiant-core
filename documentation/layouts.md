# Widget types, layouts and their selection

A page is drawn by a **layout**: a page template, which declares its regions,
and placements of **widget types** into those regions. Which layout draws a
page is decided by the route trie.

## Widget types

A widget type is a template kind and the source of the variables its template
reads. Eight are built in:

| Type | Template kind | Source |
| --- | --- | --- |
| `sitename` | `core.sitename` | the settings `core.site_title` and `core.tagline` (settings.md) |
| `title` | `core.title` | the page's entity `title`, as the viewer may read it |
| `content` | `core.pane` | the page's entity title and body, through the access filter |
| `menu` | `core.menu` | the menu named by the target (menus.md) |
| `tabs` | `core.tabs` | the tabs of the page (menus.md) |
| `breadcrumbs` | `core.breadcrumbs` | the trail to the page (menus.md) |
| `messages` | `core.messages` | the signed-in session's message queue (messages.md); a visitor has none, and the widget draws nothing |
| `recent` | `core.pane` | the view named by the target, `recent` unless said |

An enabled module adds a type through its manifest (`GDEFCORE_Module_Widget`,
modules.md): `<module>.<name>`, the template kind it is drawn with, a default
template (its own name unless the module names one), the permission its source
needs, and a provider. The provider binds the text variables the kind declares
(`gdefcore_widget_bind_text()`) and is called only for a viewer who holds the
permission. Nothing in the kernel changes. A type is the module's while the
module is enabled; a layout cannot place it before, and disabling the module is
refused while a layout places it (the refusal names the layout).

`gdefcore_layout_widget_count()`, `_at()` and `_find()` list what the tenant has.

## Layouts

A layout is a `core.display`: `name`, `layout` (the page template) and `panes`,
one placement per line, `region widget [target]`, single spaces. What the target
means is the widget's: a template to draw with for a built-in type (a menu's is
`<menu>[/<template>]`), the view for `recent`, and whatever the provider reads
for a module's.

A layout is checked when it is saved, as the write leaves it
(`gdefcore_layout_vet()`, run by apply with or without a request), and the
whole changeset is refused with nothing written when

- its page template does not exist;
- a placement names a region the page template does not declare;
- a placement names a widget type the tenant does not have, as the changeset
  would leave the enabled modules;
- a placement is not `region widget [target]`, or there are more than 32.

The same check runs the other way: a changeset that changes, renames or clears a
page template, or enables or disables a module, is refused if it would leave a
layout that uses it unable to be applied. A layout that cannot be applied is
never applied to a page (`gdefcore_layout_check()`).

## Selector rules

A rule is a `core.layout-rule` named `site.<name>`: `path` (a route pattern),
`layout`, and optionally `type` (the entity type the page must have), `exact`
(the pattern is the whole path) and `weight`. They are configuration on the
entity port, changed by changeset like a template (revisions, undo), per tenant.
The kit has `site.front` (`/`, exact) and `site.post` (`/`, for a `site.post`).

## Selection

The layout is chosen **through the route trie**. A selector is a contributor of
kind `layout` (forms.md, "Contributors"): the trie keeps the kernel's own,
`core.layout-rules`, which offers the site's rules, and an enabled module's
(`GDEFCORE_Module_Contributor`). `gdefcore_routes_offers()` returns what they
offered most specific first, in one order that does not depend on the order
modules were enabled or contributors registered; the site's rule beats a
module's of the same rank. `gdefcore_layout_select()` takes the first layout
that can be applied.

A contributor offers a layout name and nothing else. It cannot set the
request's resolution (it is put back), so the main content is the same bytes
with and without any contributor.

Then the alter hook `layout` (`GDEFCORE_HOOK_LAYOUT`) is fired with the chosen
name as the shared value and a `GDEFCORE_Layout_Hook` (the path and the entity's
type) as the argument. A module may name another layout, by role or by
classification: subscribers compose in the host's one order, each seeing what
the one before named. It changes the layout and nothing else. The decision a
subscriber reports is not read, a subscriber that fails is skipped by the host,
and if the final name cannot be applied, the choice made before the hook
stands. No refinement can deny a page.

## Who sees what

A widget shows what its source would: the access filter for what it reads of an
entity, the target route's own check for a menu entry, the widget's permission
for a module's. A viewer who may not read a widget's source gets nothing of it,
and not a wrapper. A module widget that fails, or whose template is missing or of
another kind, draws nothing and does not take the page down.

A layout and a rule belong to one tenant: the trie's contributor reads the
catalog of the request it is asked about, so one route table serves any number
of tenants without mixing them.

## Editing

One permission, `core.layout.edit`, labelled "Edit layouts" on `core.display` and
"Edit layout rules" on `core.layout-rule`, granted to nobody until a changeset
grants it. Apply asks it for each layout and rule a changeset with a request
writes, about the entity as stored and as the write leaves it
(`gdefcore_layout_authorize()`); a grant can be conditioned on the `name` or the
`layout` (conditions.md). A layout change is a changeset and moves the config
epoch, so every key that holds the epoch (the render key, a widget's fragment)
moves with it.
