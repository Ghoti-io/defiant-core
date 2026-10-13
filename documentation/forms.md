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
