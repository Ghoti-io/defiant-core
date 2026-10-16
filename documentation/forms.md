# Forms

A form is a tree of field names, flags, constraints and current values.
It is not a page. Nothing here emits HTML, reads a cookie, or opens a
socket.

## Constraints

A field may declare a minimum length, a maximum length, an integer
range, and a pattern. Lengths are byte lengths. Zero means that
constraint is absent. A range requires the whole value to be a base-10
integer inside the bounds, and a pattern is an ECMAScript regex that
must match the whole value. A pattern that does not compile is refused
when the type is defined.

Callers whose `GDEFCORE_Field.size` stops before these members impose
no extra constraint. A field stored before the members existed is read
the same way.

## The token

`gdefcore_form_sign` seals the constraints and the values with
AES-256-GCM under the tenant keyring's `form` purpose. The associated
data binds the tenant, that purpose, the key id, the expiry, the
session, the principal, the form id, the target public id, the subject
(see below), and the base revision. The token is returned to the caller.
It is not written into the tenant store.

The token expires after 24 hours and not later than the session. A
token from another session, another tenant, or with a bad tag is
refused. A missing token is refused. None of those write.

Signing does not write the entity. Re-signing checks the token and the
constraints and returns a new token. It does not write either.

## Personal fields

A personal value is never stored as the caller's text. The plain route,
`gdefcore_form_sign` and `gdefcore_form_submit`, refuses a value for a
personal field with `GDEFCORE_ERR_INVALID` and writes nothing. A field
left empty, and every field that is not personal, go through as before.
`gdefcore_entity_save` and `gdefcore_entity_save_draft` refuse a personal
value in the same way, and so does a parsed patch, unless the value is
already sealed. A revert or a publish that would put a personal value that
is not sealed into a new revision (it was stored before the field became
personal) is refused too.

The subject route is the way to write one through a form.
`gdefcore_form_sign_subject` takes the subject's public id and carries it
in the token, inside the associated data like the session, so a token
cannot be moved to another subject. `gdefcore_form_submit_subject` takes
the subject store. It seals each personal value exactly as
`gdefcore_subject_save` does (same key, same ciphertext, same blind-index
row), stores the ciphertext in the draft, and records the blind-index row
after the draft is applied. An unknown or erased subject, a many field,
or any failure before the draft is applied writes nothing, and nothing
falls back to plaintext. The draft and the index row are two commits in
two stores, as in `gdefcore_subject_save`; a failure of the second leaves
a sealed draft with no row, which erasure still makes unreadable. The row
tracks the draft, so until publish the published text and the row can
differ.

To edit, open the form with the value `gdefcore_subject_read` returns for
the subject, not with `gdefcore_form_tree`, which shows what is stored:
ciphertext. Reading shows the published value; a draft that is not yet
published is not shown. An unchanged value is sealed again under a fresh
nonce. A value that is itself a sealed text, as the tree returns it, is
refused at submit rather than sealed a second time.

## Draft and publish

`gdefcore_form_submit` appends a revision and updates the draft
projection only. The published projection is left as it was. A second
submit whose base revision is no longer current is a conflict and
writes nothing.

`gdefcore_form_publish` copies that draft onto the published
projection. `gdefcore_entity_save` still writes both projections.

## Aliases

A caller may supply a path. Core stores that path and does not rewrite
it. When the caller supplies none, the `title` value is slugged:
lowercase, spaces and underscores become hyphens, characters outside
`a-z`, digits and hyphen drop, and repeated hyphens collapse. No title
means no alias.

An alias names one entity. It does not resolve until that entity is
published, and it does not resolve for a request that may not read the
entity. Both failures are the same error as an unknown path. A
published path that is already taken gains a short random suffix.

## Routes

Paths are a segment trie. `*` is one segment. A request matches that
segment, a `*` in its place, and every ancestor, so a handler on `/`
also sees `/foo`. Handlers run lowest weight first. At the same weight
the more exact path runs first: an explicit segment scores
`1/(index+1)` and a `*` scores 0.

A handler may add named notes and fall through, or set the resolution
and own the request. Later handlers run only when they are marked to
run after ownership. The resolution is the entity's public id, or the
handler's machine name when it is not serving an entity. Two handlers
with the same machine name are an error naming both. Two handlers may
share a path.

### Named segments, permission, title, kind and tabs

`gdefcore_route_add()` is unchanged, and a `:` in its path is literal text.
`gdefcore_route_add_spec()` takes a size-prefixed `GDEFCORE_Route_Spec` with
the same fields and these:

- **Named segments.** A pattern segment `:name` matches exactly one request
  segment and captures it under `name`; `*` still matches one segment and
  captures nothing. A name is `[a-z][a-z0-9_]*`, at most 64 bytes, unique in
  the pattern, and a pattern has at most 16. `:Id`, `:`, `:x%41`, a non-ASCII
  name and a repeated name are refused at registration, with the route in the
  error text. A named segment scores as `*` does (0), so `/node/42/edit` beats
  `/node/:id/edit` at equal weight; ties fall to registration order as before.
- **Reading a capture.** The handler is a `GDEFCORE_Route_Call_Fn`, called
  with a `GDEFCORE_Route_Call` (the request, the machine name, the data). It
  reads a capture with `gdefcore_route_call_capture(call, name, len, &value,
  &value_len)`, which returns 1 when the pattern has that name and 0 otherwise.
  The value is the request segment as received: percent-encoding is not
  decoded, and `//` still collapses. Nothing is read from ambient state.
  A handler of the old type can be given to the new call as `fn`.
- **Permission.** A route may name a permission. The caller installs one check
  with `gdefcore_routes_set_check()`; dispatch calls it for a route whose path
  matched, with the call (so the captures) and the permission name, and the
  principal is the request's. A zero answer makes the route not match: it is
  left out before ordering, nothing is recorded, and the request is answered
  as if the route did not exist (AD-11). A route that names a permission when
  no check is installed never matches. A route with no permission never asks.
- **Title and kind.** A title is UTF-8 text of at most 256 bytes with no
  control characters. A kind is `GDEFCORE_ROUTE_PAGE` (the default),
  `GDEFCORE_ROUTE_TAB` or `GDEFCORE_ROUTE_ACTION`. Neither changes dispatch;
  both are data for the menu system and are returned by the enumeration.
- **Tabs, after Drupal's local tasks.** A tab names a parent route by machine
  name, and the parent must already be registered. At most one tab of a parent
  is the default. A default tab links to its parent's path, and the parent's
  path is served by that tab: `node/:id` parent, `node/:id/view` default,
  `node/:id/edit` tab means `/node/42` and `/node/42/view` run the view
  handler and `/node/42/edit` runs the edit handler. The parent's path is
  answered exactly, not as an ancestor, so a longer path does not reach the
  default tab by that road, and at equal weight the default tab runs before
  the parent's own handlers. A tab whose parent is missing, a second default
  for one parent, a parent on a non-tab, and a default tab that captures a
  name its parent's pattern lacks are errors that name both routes and leave
  the table unchanged.
- **Weight** orders dispatch, as it always did, and also the tabs in the
  enumeration. A parent whose handler owns the request must have a higher
  weight than its tabs, or it answers its tabs' paths first as an ancestor.
- **Enumeration.** `gdefcore_routes_tabs()` returns the tabs of a parent in
  weight order, then machine name, each with title, kind, default flag, path
  pattern, permission and weight. Free the array with `gdefcore_routes_free()`.

**Asking the access layer.** `gdefcore_access_can()` (access.md) is the one
decision, and the route table uses it through a ready-made check:

- `gdefcore_routes_set_check(routes, gdefcore_access_route_check, catalog)`
  installs it. A route whose permission has no `entity_capture` asks the type
  level question (`gdefcore_access_permits()`), as a check always could.
- A route spec may name an `entity_capture`, one of the `:name` captures of
  its pattern (an unknown name is refused when the route is added). The check
  then reads that capture, takes it as an entity id, finds the entity's type
  and asks `gdefcore_access_can()` whether the principal holds the permission
  for that entity. A segment that is not an id, an entity that is not there,
  one on which no grant holds, and a permission nobody declared are all one
  answer: no, and so the route does not match and the request is answered as
  for a path with no such route. A spec built before the field existed (its
  size is `GDEFCORE_ROUTE_SPEC_SIZE_V1`) is accepted and names none. A module
  manifest's route has the field too.
- `gdefcore_routes_tabs_visible(routes, parent, len, page, &tabs, &n)` is
  `gdefcore_routes_tabs()` without the tabs the check refuses. `page` is the
  call of the page the tabs are drawn on (the handler's own call, which has
  the captures), and each tab is asked exactly what dispatch would ask for it,
  its permission and its entity capture, with the page's captures: so a menu
  cannot show a tab dispatch would answer as not found, nor hide one it would
  serve. Pass the same capture names in the page's pattern and the tabs'.

