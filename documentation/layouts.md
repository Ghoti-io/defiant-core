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
module is enabled; a layout cannot place it before. Disabling the module is
never refused because a layout places its widget: a disable can be a security
decision, and it must not wait on anyone editing layouts. The placement stays
stored and draws nothing (see below).

`gdefcore_layout_widget_count()`, `_at()` and `_find()` list what the tenant has.

## Layouts

A layout is a `core.display`: `name`, `layout` (the page template) and `panes`,
one placement per line, `region widget [target]`, single spaces. What the target
means is the widget's: a template to draw with for a built-in type (a menu's is
`<menu>[/<template>]`), the view for `recent`, and whatever the provider reads
for a module's.

A placement may carry parts after its target, each `~key=value` with the value
percent-encoded so that it holds no space:

```
side menu primary ~title=Site%20menu ~role=editor ~path=/admin/ **
```

(the path is written with no space before the two stars). `title` is drawn above
the widget, escaped, in `<section class="pane"><h2 class="pane-title">`; a
placement with no title is bare, as it always was. The others say when the
placement shows, and it shows only when every one given holds:

- `path` is the page's path. A segment of `:name` or `*` takes any one segment,
  and a last segment of `**` takes the rest (none included), so `/` is the front
  page alone and `/news/**` is everything under it. A path is not a prefix.
- `role` is a role the principal holds. It may be given up to eight times and
  any one will do. The built-in `anonymous` (nobody signed in) and
  `authenticated` (anyone signed in) count.
- `type` is the type of the entity the page resolved to; a page that resolved to
  none has no type to match.

A part is data in a fixed shape, never code. A placement that is not for the
viewer is not asked to draw: its widget is not called and nothing of it is read
or left behind. A part only narrows. A role condition grants nothing, and the
widget's own permission still decides what it shows. A render that reads a role
marks its request as depending on the principal, so a host that keeps a page
(the render key, access.md) keeps one for each principal, and a path or a type,
which a host keys by the page already, does not. A layout is refused when it is
saved if a part is not one of the four, is given twice (a role excepted), has a
value that is not escaped properly or is out of range: a title is 1 to 128
bytes of text, a path is a pattern as above of at most 128 bytes, a type is
`module.name`, a role is a name of a-z, 0-9, `.`, `_` and `-`.

A layout also keeps a **Not placed** list, `unplaced`, one entry per line in the
form of a placement without its region: `widget [target] [~key=value ...]`. It is
only data. A widget there draws nothing, and its type need not exist, so a
module that is disabled keeps its placements and they come back when it is
enabled. A layout is refused when an entry is not that shape or when it holds
more than 32 (the most values the port keeps of one field).

A layout is checked when it is saved, as the write leaves it
(`gdefcore_layout_vet()`, run by apply with or without a request), and the
whole changeset is refused with nothing written when

- its page template does not exist;
- a placement names a region the page template does not declare;
- a placement names a widget type the tenant does not have, as the changeset
  would leave the enabled modules;
- a placement is not `region widget [target] [~key=value ...]`, or there are
  more than 32.

The same check runs the other way: a changeset that changes, renames or clears a
page template is refused if it would leave a layout that uses it unable to be
applied. Enabling or disabling a module is not checked this way (see below). A layout that cannot be applied is
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
stands. No refinement can deny a page. The module whose subscriber last changed
the name (`gdefcore_alter_changed_by()`) is what `gdefcore_layout_why()` reports as
`refined_by` when the refinement is the one that applied, so an editor asking why
a page got a layout is told which module sent it there; a subscriber whose change
was rolled back because it failed is not named.

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

## Region descriptors

A template names a region with `region("side")` and says no more. What an editor
is shown for one (region.h) is a **descriptor**, a label and an optional
description, found in this order, the first match winning:

1. the template's own, kept in its `regions` field, one
   `name ~label=<text> ~description=<text>` line each (the values
   percent-encoded as a placement's are), at most 32;
2. a shared one, a `core.region-descriptor` entity of a name, a label and a
   description. A new site starts with `main`, `side`, `header`, `navigation` and
   `footer`, and the site adds its own; the seed leaves one the site changed;
3. one a module ships (`GDEFCORE_Module_Region`, the manifest's `regions`, at most 32
   a module): the first enabled module in module order that names the region. A
   module that ships widgets or page templates for regions it names ships their
   labels with them; they are there while it is enabled and gone when it is not,
   and the site's own shared descriptor of that name wins over them (so a module
   cannot take over `side`, and the site can always rename what a module calls a
   region). A module whose region has a name that is not a region name, a label
   that is empty, over 64 bytes or not UTF-8 text with no control character, a
   description over 256 bytes or not such text, or two entries for one name is
   refused when it is enabled, with the entry named;
4. the name in readable form: `footer_links` is "Footer links".

A descriptor changes what an editor and a preview show and nothing else: how a
page renders does not depend on one, and removing a shared one touches labels
only, never a placement. A name is a-z first, then a-z, 0-9, `_` and `-`, at most
63 bytes; a label is 1 to 64 bytes of text and a description at most 256.

A shared descriptor is configuration written by changeset under
`core.region.edit` ("Edit region descriptors"), which the layout permission does
not imply and the administrator role is granted at seed. A template's own are
written with the template (`gdefcore_region_stage_template()`), so they ask the
template permission. Each is checked when it is saved (`gdefcore_region_vet()`).

## Page structure

A page template can be **structured** (structure.h): it keeps a document of rows
and cells, and its source and a stylesheet are generated from it. A cell is one
region; a row has up to 12 columns shared among its cells. The document is text:

```
row stack medium
cell main 8 1
cell side 4 2
row wrap
cell card
cell card2
row fixed
cell footer 12
```

`row stack <narrow|medium|wide>` folds to one column below that width, the cells
in their stacked order (so a side area can come after the main content on a
phone); `row wrap` flows its cells into as many columns as fit, none narrower
than a minimum width, with no widths and no breakpoint; `row fixed` never folds.
A cell is `cell <region> <width> [<stacked>]` (a wrap row's is just `cell
<region>`); the width is 1 to 12 and a row's come to at most 12; a stacked
position is 1 to the cells in the row, none twice, and is the cell's place in the
row when left out. A region name is used once in the whole document. There are at
most 32 rows, 12 cells in a row and 64 cells in all, in at most 4096 bytes.

`gdefcore_structure_stage()` writes the template (made when there is none, as a
`core.page`), its `structure` and the stylesheet `site/layout-<template>.css`
(a `core.css-asset` that says which template generated it) in one changeset. The
same structure and name give the same bytes every time, so the same address. The
regions a layout finds by reading the generated source are exactly the cells.

The generated pair is read only. The apply refuses a structured template whose
source is not what its structure makes, a generated stylesheet that is not
either, and any attempt to change or remove the stylesheet as a site file
(`gdefcore_structure_vet()`). A person who wants to write the source by hand marks
the template **custom** (`gdefcore_structure_stage_custom()`, its structure is
the word `custom`): its source is theirs, its stylesheet becomes a file the site
may change, and the template is found by reading it like any other. A custom
template is replaced only by a structure staged with the caller saying so. A
structured template's name is a-z first, then a-z, 0-9 and `-`, so it can name a
class.

The stylesheet is plain CSS Grid. A row folds by a **container query** on the
width of its own container (the row's box), so the same structure behaves when it
sits in a narrow region; the named widths are 480, 720 and 960 CSS pixels.
Container queries have shipped in the current evergreen browsers since 2023; a
browser without them shows every row at full width and unfolded, which is a
usable page. The page's policy allows the site's own stylesheet (the web layer's
documentation), and the template names no inline style.

## Editing a layout one placement at a time

An editor reads a layout with `gdefcore_layout_view()`: the page template it
draws with, that template's regions in its order, the placements (each a
`GDEFCORE_Placement`: region, widget, target, title, path, type, roles), the Not
placed list, and a **version**. It changes the layout with
`gdefcore_layout_stage_edit()`, one action at a time:

- *place* a widget in a region at a position, with its settings;
- *place* an entry of the Not placed list in a region at a position;
- *move* a placement to a region and a position;
- *configure* a placement: its target, title and conditions are replaced whole
  (what is not given is taken away), its region and widget kept;
- *remove* a placement, from either list, which deletes it;
- *unplace* a placement, which sets it aside in the Not placed list with its
  settings.

A position counts among the placements of that region, 0 first, and a position
past the last is the last. Each edit is one changeset on the one layout, so it is
one revision, and reverting the layout undoes it whole (reverting again is the
redo). Every edit carries the version the editor drew, and an edit of a layout
that has changed since is refused with "This layout changed. Showing the current
layout." and writes nothing. The other refusals each have a sentence and write
nothing: a region the template does not name ("That region is not in this
template."), a widget the tenant does not have ("That widget is not available.",
which is also why a Not placed entry whose module is disabled cannot be placed
until it is enabled, though it can be configured and removed), a setting that is
not one, a layout that would hold more than 32 placements, and a placement that is
not there. An edit that changes nothing is success and stages nothing. The apply
still asks the layout permission for the layout and checks the layout as it is
left.

## Editing a page structure

An editor reads a page template's structure with `gdefcore_structure_view()`: its
kind (none, a document, or custom), the rows with their behavior, breakpoint and
cells (region, width, stacked position), and a version, the hash of the stored
text. It changes it with `gdefcore_structure_stage_edit()`, one action at a time:
add a row (it holds one cell, so a row is never empty), remove or move a row, give
a row another behavior or breakpoint, add, remove, move, widen, stack or rename a
cell, start from one of the built-in starting points
(`gdefcore_structure_starting_point()`: one column, two columns with the sidebar
on either side, three columns, header with two columns and footer, the holy grail,
and a landing page), start a new structure from a single region, or make the
template custom.

Each edit is one changeset: the structure, the template's source and the
stylesheet made from the result, and **every layout that draws with the template**,
so a layout is never left naming a region the template no longer has. A placement
of a region that is renamed follows it. A placement of a region that is gone (a
cell removed, a row removed, a new start) is set aside in that layout's Not placed
list, and the call returns one line `layout widget region` for each, which an
editor shows; nothing is lost, and placing it again puts it where it is wanted.
Removing a template's last cell of a row removes the row; a cell moved to another
row takes the width the row has left (at least one column); a stacked position set
on one cell swaps with the cell that held it.

An edit carries the version it was drawn from, and a stale one is refused with
"This structure changed. Showing the current structure." and writes nothing. A
custom template is refused every edit but a new start ("This template is written
by hand. Start a new structure to replace it."), so a hand-written template is
never overwritten by accident. The apply asks the template and stylesheet
permissions and, for each layout carried, the layout permission.

The starting points are a fixed table of structure documents in the library, not
stored data: a site's own named structures are a later addition that needs a
stored type and a permission of its own.

## Previewing a layout

`gdefcore_layout_preview()` answers what a visitor would see of a layout without a
request: it reads the published layout and decides, for a viewer given as data (a
role, a page's path and an entity type), which placements show. An empty role is a
visitor who is not signed in, `authenticated` is anyone signed in, and any other
name is a signed-in person holding that role (who therefore also matches a
placement for `authenticated`). A placement that names a path or a type shows only
on a matching page. The result flags each placement shown or not and counts both;
**a placement that is not shown is counted and never named**, so previewing as
another role cannot find out what that role is not given. Nothing is written,
cached or kept. It does not run widgets: a preview is the layout's structure with
its widgets' names, because running a widget as another role is the leak a preview
must not be. Measured on a layout of 31 placements, a preview takes about 440
microseconds on the development host (the read of the one layout).

## A page template's body and the layouts that draw with it

A page template's body calls the regions a layout may place widgets in. When the
body is edited, `gdefcore_layout_stage_template_carry()` stages, beside the
template's own change and in the same changeset, what each layout that draws with
the template becomes: a placement in a region the new body no longer calls is set
aside in the layout's Not placed list, and one line `layout widget region` per
placement is returned for the editor to say so. No placement is lost, and none is
left naming a region the template lacks. An edit of a structure does the same and
also carries a rename (see *Editing a page structure*). Either is undone whole
(see *Undoing a structure edit*).

Disabling a module is never refused because of a layout. A placement of its
widget stays stored, in its region, and is **unavailable**: the page is built
without it (no widget code runs, and no title is drawn), the rest of the layout
is unaffected, and the placement can still be moved, configured, set aside or
removed; the layout can be saved with it in place. A *new* placement of that
widget is refused ("That widget is not available.") until the module is
enabled, and when it is, the placement draws again as it was. A Not placed
entry of the widget is kept the same way.

## Undoing a structure edit

A structure edit, and a template save that carried layouts, write several entities
at once: the template, the stylesheet it generates and every layout it moved. They
are not one entity's revision, so reverting an entity cannot take them back whole.
`gdefcore_structure_stage_edit()` and `gdefcore_layout_stage_template_carry()`
therefore stage a record of the change (`core.structure-change`: one line
`<id> <revision> <S|C>` for each entity, the revision it had before and whether the
change cleared it), and `gdefcore_structure_stage_undo()` puts each entity back as it
was in one changeset: an entity the change made is cleared, one it cleared is
restored, one it changed gets the values of its earlier revision, a new revision as
every revert is. The record is then emptied, so a change is undone once.

Everything is decided before anything is staged. If any entity the change wrote has
been written since, the whole undo is refused ("That page was changed after that
edit, so the edit cannot be undone.") and nothing is written, so an undo never
overwrites a later edit. A request that may edit neither layouts nor page templates
is told "That edit is not allowed." whether or not there is a change to undo, and
nothing is read. The apply then decides each write as it decides any other (the
template and stylesheet grants, the layout grant). A change that writes more than 32
entities is made normally but cannot be undone as a whole, and it empties the record
so that an older change is not taken back in its place; a template save that moves no
layout is not recorded (it is undone as a template is). The record is a config type,
so a change that writes it names `core.structure-change` among the types its
confirmation lists.
