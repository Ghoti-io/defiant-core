# Entities

**Status:** describes what shipped in milestone 1, story 7.

A type is `core.<name>`, `site.<name>`, or `<module>.<name>`. The name part
may hold letters, digits and underscore, and a hyphen that is neither first
nor last (`core.template-kind`); the part before the dot has no hyphen. It is
content or configuration, and its fields are text, one value or many. Values sit
under a language in the revision's `lang` object. The built-in types are
`core.entity_type` and `core.changeset`.

The integer row id is the storage key. The head and active revisions are
copied into projections whose type is `d:` or `a:` plus the machine name, and
the entity argument is the decimal row id. `d:site.note` cannot collide with a
machine name, because a machine name has no colon. The public-id index is a
projection whose type is `i` and whose entity argument is the public id.
Reading by the public id uses that index. The document's `entity` field is the
public id, not the key.

## The entity record

An entity is a small record plus append-only revisions (SPEC decisions 9-11).
The record is a core-owned projection of type `s`, keyed by the decimal row id:

| Column | Meaning |
| --- | --- |
| `pub` | `1` when the entity is published, else `0`. Whether the public may see it. |
| `act` | the sequence of the active revision, absent when there is none. The content the entity currently is, which exists even while it is unpublished. |
| `ver` | a counter that every write touching the entity bumps, including a publish, an unpublish, an activate and a clear, none of which moves the latest revision sequence. `can()`'s memo and the render read set are keyed on it. |
| `creator` | the principal of the entity's first revision, recorded at that revision and never again. Absent when the first revision had no actor. |

Three things are separate. The **published flag** says whether readers may see
the entity. The **active revision** is the content it currently is; readers,
conditions and `own` see it, and so does the author of an unpublished entity.
The **other revisions** are history, and a newer draft not yet made active.
`gdefcore_entity_values` takes the view: `GDEFCORE_VIEW_PUBLISHED` is the
active revision while the flag is set (a miss otherwise), `GDEFCORE_VIEW_ACTIVE`
is the active revision whether or not it is, and `GDEFCORE_VIEW_DRAFT` is the
head, the latest revision.

| Projection | Holds |
| --- | --- |
| `a:<type>` | the active revision's content, with its `seq`, its `id` and the `actor` it was written with. |
| `d:<type>` | the head revision's content, the latest. |
| `ra` | one line `<seq> <actor>` per revision: every revision's own creator. |

An entity's creator and a revision's creator are different things. A revision's
creator is whoever wrote that revision, so an editor who saves someone else's
post is the creator of their revision and of nothing else. The entity's creator
is the first revision's, and `own` means it. `gdefcore_entity_actor` returns the
active revision's creator and `gdefcore_entity_creator` the entity's. A publish
does not write a revision, so the publisher is recorded nowhere and the revision
keeps its own creator.

| Operation | New revision | Head | Active revision | `pub` | `ver` |
| --- | --- | --- | --- | --- | --- |
| `gdefcore_entity_create` | none | none | none | 0 | 0 |
| `gdefcore_entity_save` ("save and publish") | yes | moves | the new one | 1 | +1 |
| `gdefcore_entity_save_draft` | yes | moves | unchanged; the entity's first revision becomes active | unchanged | +1 |
| `gdefcore_entity_publish` | none | unchanged | the head | 1 | +1 |
| `gdefcore_entity_unpublish` | none | unchanged | unchanged | 0 | +1 |
| `gdefcore_entity_activate(seq)` | none | unchanged (the head is restored if a clear removed it and `seq` is the head) | `seq` | unchanged | +1 |
| `gdefcore_changeset_revert_to(seq)` | yes, a copy of `seq` | moves | the copy | unchanged | +1 |
| `gdefcore_changeset_revert` (legacy) | as `revert_to(active - 1)`; a clear when the active revision is the first | | | | |
| clear (a revert of the first revision) | none | `d:` removed | none, `a:` removed | 0 | +1 |
| type definition | yes | moves | the new one | 1 | +1 |

A draft never moves the active revision; only a save, a publish, an activate
and a revert do. Publishing and activating are different acts: a publish makes
the head active *and* sets the flag; an activate moves the pointer to any
recorded revision and leaves the flag alone, and an unpublish clears the flag
and leaves the pointer. A revert is a save of an earlier revision's content
that leaves the flag alone, so reverting an unpublished entity does not
publish it. An activate, like a revert, refuses a revision that holds a
personal value that is not sealed (a revision written before the field was
personal): it would put plaintext in front of readers without a new revision. The one exception is an entity's first
revision, which becomes active while staying unpublished, so that the entity
has content and a creator for a condition to read. A clear keeps every revision,
the `ra` lines, the public id and the creator; it empties the projections and
clears the flag. There is no hard delete: erasure is by key (AD-19), not by
deleting records. A cleared entity has no active revision, so a field-conditioned
`update` grant cannot hold on it, and only an unconditioned permission to
activate can bring it back (an activate of the head also restores the head
projection, so it can be published; an activate of an older revision does not,
and a revert to it, which writes a revision, does).

A row in the index with no `s` row is a store written before the record
existed. Nothing is released and nothing migrates it: every call that needs the
record answers `GDEFCORE_ERR_CORRUPT` rather than reading the entity as
unpublished, which would hide it without a word.

A core-owned projection of type `w`, keyed by the decimal row id, holds the
high-water sequence. Clearing does not remove it, so the next save after
reverting sequence 1 is sequence 2.

`gdefcore_type_define` writes a type without moving the config epoch, so a
content save can still be the epoch's first step. A changeset that defines
or changes a type is high risk. Apply of a high-risk changeset requires the
touched machine names, sorted, one per line. Apply commits the revisions and
both projections in one port write and increments the epoch in that write.
A port error aborts the write.

Serializing a changeset yields `defiant-changeset/1`: an ordered list of
relative paths and UTF-8 bytes. The `revert`, `unpublish` and `activate` words
and the `ver` and `target` files are additions to `/1`: a reader from before them
refuses the unknown word or file as corrupt. An `unpublish` and an `activate`
carry no values; `publish` carries them for the diff but apply publishes the head
as the store has it, not what the patch says it is. A patch made against a
version the entity has since left is a conflict, whatever the epoch says.

| Path | Bytes |
| --- | --- |
| `format` | `defiant-changeset/1` |
| `epoch` | the decimal epoch the changeset was prepared against |
| `actor` | optional canonical public id |
| `entity/<id>/type` | the entity's machine name |
| `entity/<id>/base` | the decimal sequence the save was prepared against |
| `entity/<id>/ver` | the decimal version of the entity the change was staged against (optional; absent means the version at parse time) |
| `entity/<id>/op` | `save`, `draft`, `publish`, `revert`, `unpublish`, `activate` or `clear` |
| `entity/<id>/target` | the decimal sequence an `activate` makes active |
| `entity/<id>/lang/<lang>/<field>/<index>` | one field value |
| `type/<machine>/kind` | `content` or `config` |
| `type/<machine>/field/<name>` | `required one`, `required many`, `optional one`, or `optional many` |

A field may be called `kind`: `type/core.template/field/kind` is that field,
and not the kind of a type called `core.template/field`. The parser takes
`type/<machine>/kind` as a type's kind only when the machine name has no slash.

Parsing that list is untrusted. `..`, an absolute path, a byte that is not
UTF-8, and a public id that fails its check are refused. A failing check is
not looked up, and nothing is written.
