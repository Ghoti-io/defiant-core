# Entities

**Status:** describes what shipped in milestone 1, story 7.

A type is `core.<name>`, `site.<name>`, or `<module>.<name>`. The name part
may hold letters, digits and underscore, and a hyphen that is neither first
nor last (`core.template-kind`); the part before the dot has no hyphen. It is
content or configuration, and its fields hold one value or many, each of a
logical type (`GDEFCORE_Field::type`): text (the default), integer, decimal
(with a scale), float, boolean, date, date-time or reference. A field may ask
the store to index it (`GDEFCORE_Field::indexed`, a hint that changes no
answer). Values are kept per language. The built-in types are
`core.entity_type` and `core.changeset`.

Since story S6b an entity is the storage port's (defiant-storage `model.h`):
the port keeps the entity record, the append-only revisions, the trees of
each language, the current tables a query reads and the draft. Core keeps
beside it, as system records (non-revisioned, written in the changeset's own
port write): each type's declaration (namespace `core.type`, format
`defiant-core-type/1`: the kind, the type's public id and version, and each
field's shape, type, scale, index hint and constraints), and as counters the
config epoch (`core.epoch`) and each entity's version (`core.v:<public id>`).
The port's own declaration of the type is the fields' shape; a personal
field is a `PERSONAL` text field: its value is the sealed text with its
subject's public id beside it, and each version of it has a blind-index row
(story S6c, subjects.md). A field made personal after it was declared keeps
its text column (a conversion is AD-15's), and a personal field cannot stop
being personal in place. A value is stored as its type's
value and read back as its canonical text: an integer `7` however it was
written, a decimal of scale 2 `1.50`, a boolean `true` or `false`, a date
`2026-10-19`, a date-time `2026-10-19T08:30:00Z` (`.mmm` with milliseconds),
a reference a canonical public id. A value that is not one of its type, and a
text holding a NUL byte, are refused at staging.

No function in this document checks a permission (SPEC decision 7): each runs
at the trust of its caller, and the path in front of it asks `gdefcore_access_can()`
(access.md). The one exception is the template check that apply still makes for a
changeset that has a request, which story A8 retires. `gdefcore_entity_values()`
and `gdefcore_entity_revision_values()` are the unfiltered previews; a principal
reads through `gdefcore_access_read()` and `gdefcore_access_revision_values()`.

## The entity record

An entity is a record plus append-only revisions (SPEC decisions 9-11, as
access SPEC decision 13 leaves them):

| Fact | Where | Meaning |
| --- | --- | --- |
| published | the port's state | whether the public may see the entity |
| deleted | the port's state | a soft delete: a cleared entity reads as one with no content |
| revision | the port's record | the newest revision, which is always the content: there is no active-revision pointer, so no older revision is the content without a new revision that copies it |
| creator | the port's record | whoever made the entity, set once and never again; none for the system |
| version | core's counter `core.v:<id>` | moved by every write that touches the entity, a draft, a publish, an unpublish and a clear included, none of which need move the revision. `can()`'s memo, the render read set and a form's base are keyed on it. |
| draft | the port's draft | at most one working copy, never a revision, recording the revision it was made from |

`gdefcore_entity_values` takes the view: `GDEFCORE_VIEW_PUBLISHED` is the
newest revision while the entity is published (a miss otherwise),
`GDEFCORE_VIEW_CURRENT` is the newest revision whether or not it is, and
`GDEFCORE_VIEW_DRAFT` is the draft over it, where there is one. A draft is in
no list, no query and no reader's view, and no condition reads it.

An entity's creator and a revision's author are different things. A revision's
author is whoever wrote that revision, so an editor who saves someone else's
post is the author of their revision and of nothing else. The entity's
creator is who made it, and `own` means it. `gdefcore_entity_actor` returns
the newest revision's author and `gdefcore_entity_creator` the entity's
creator. A draft records who wrote it last (the record `core.draft`, keyed by
public id), and a publish applies it as that author's revision, so publishing
does not make the publisher the author (defect 1.5.3).

| Operation | Revision | Draft | Published | Version |
| --- | --- | --- | --- | --- |
| `gdefcore_entity_create` | none: the id is reserved by an empty draft, and there is no port entity | the reservation | no | 0 |
| `gdefcore_entity_save_draft` | none | written; it builds on the draft there is, made from the newest revision. The first draft of a reserved id makes the port entity, with the actor as its creator | unchanged | +1 |
| `gdefcore_entity_save` ("save and publish") | the next, from the draft when it was made from the newest revision, else from the newest; nothing when the values are those the entity has, which `gdefcore_changeset_revision` says | consumed | yes | +1 when anything was written |
| `gdefcore_entity_publish` | the draft applied as the next, only on the revision it was made from (a moved head is a conflict and writes nothing), with the draft's author as its author, validated against the type as it is now and refused for a new value of an erased subject (subjects.md); with no draft, none | applied | yes | +1 when anything was written |
| `gdefcore_entity_unpublish` | none | unchanged | no | +1 when it was published |
| `gdefcore_changeset_revert_to(seq)` | a copy of `seq` as the next (none when the content is already that); a cleared entity is no longer deleted | unchanged | unchanged | +1 |
| `gdefcore_changeset_revert` (legacy) | as `revert_to(newest - 1)`; a clear when the newest is the first | | | |
| `gdefcore_entity_clear` (a revert of the first revision) | none: every revision stays | dropped | no, and deleted | +1 |

A draft is applied only on the revision it was made from (CAP-S4): a publish
of a draft whose entity has a newer revision (a revert, or another writer
between the draft and its publish) is a conflict and writes nothing. A draft
is validated against its type as the type is when it is applied (AD-14): a
value of a field the type no longer has (unless it is what the entity holds
there now), a value not of its field's type, or a required field missing
refuses the publish in words (`gdefcore_changeset_refusal`), and the draft
stays. A save
consumes the draft: it saves the working copy when the draft was made from
the newest revision, and otherwise saves on the newest revision and drops
the stale draft. A revert, like a save, refuses a revision that holds a
personal value that is not sealed (a revision written before the field was
personal). There is no hard delete: erasure is by key (AD-19), not by
deleting records, and a cleared entity is brought back by a revert to one of
its revisions or by a save.

### Scheduled publish

`gdefcore_entity_schedule_publish(catalog, actor, id, T)` publishes an
entity at time `T` (AD-14: "scheduled publish applies a draft at a time";
story S6c). It is a job row in the tenant's store (AD-33), a port record
`core.sched/<20-digit T>.<public id>` holding who scheduled it, beside the
entity's one schedule, `core.sched.id/<public id>` (`pending`, `done`,
`conflict` or `refused`, and `T`), which a new schedule replaces and
`gdefcore_entity_unschedule` cancels. A runner calls `gdefcore_schedule_run`
(or `gdefcore_schedule_due` and `gdefcore_schedule_apply` one job at a time)
with the time it is: each due job is a changeset that publishes the entity as
its scheduler, and that changeset's write reads the job row again and deletes
it, so a job is applied once, whichever runner reaches it first, and never
before `T`. The publish is an ordinary one: the draft the entity has then is
validated against its type as it is then and applied on the revision it was
made from, as its author's revision; a moved head ends the job as a conflict
and a refused draft ends it as refused, each keeping the draft and leaving no
revision. With no draft the job only sets the published flag. Clearing the
entity cancels its schedule, so a cleared entity is not brought back. The
time is milliseconds since 1970 UTC; a civil time and zone are the caller's
to convert. A job does not yet check its scheduler's permission again when it
runs (AD-33 asks it of jobs, which are out of milestone 1): the path that
schedules asks it.

`gdefcore_type_define` writes a type without moving the config epoch, so a
content save can still be the epoch's first step. A changeset that defines
or changes a type is high risk. Apply of a high-risk changeset requires the
touched machine names, sorted, one per line. Apply is one port write: the
revisions, the drafts, the states, the type records, the version counters and
the epoch, which moves in that write. A port error aborts the write, and
nothing of the changeset is kept.

Serializing a changeset yields `defiant-changeset/1`: an ordered list of
relative paths and UTF-8 bytes. The `revert` and `unpublish` words, the `ver`
and `target` files and a field's type words are additions to `/1`: a reader
from before them refuses the unknown word or file as corrupt. (The `activate`
word went with `activate`, story S6b.) An `unpublish` carries no values;
`publish` carries them for the diff but apply publishes the draft as the store
has it, not what the patch says it is. A patch made against a
version the entity has since left is a conflict, whatever the epoch says.

| Path | Bytes |
| --- | --- |
| `format` | `defiant-changeset/1` |
| `epoch` | the decimal epoch the changeset was prepared against |
| `actor` | optional canonical public id |
| `entity/<id>/type` | the entity's machine name |
| `entity/<id>/base` | the decimal sequence the save was prepared against |
| `entity/<id>/ver` | the decimal version of the entity the change was staged against (optional; absent means the version at parse time) |
| `entity/<id>/op` | `save`, `draft`, `publish`, `revert`, `unpublish` or `clear` |
| `entity/<id>/target` | the decimal sequence a `revert` copies |
| `entity/<id>/lang/<lang>/<field>/<index>` | one field value |
| `entity/<id>/subject/<lang>/<field>/<index>` | the canonical public id of the subject of that value, for a personal field (story S6c; an addition to `/1`) |
| `type/<machine>/kind` | `content` or `config` |
| `type/<machine>/field/<name>` | `required one`, `required many`, `optional one`, or `optional many`, then ` personal` for a personal field, then the type word when it is not text (`integer`, `decimal <scale>`, `float`, `boolean`, `date`, `datetime`, `reference`), then ` indexed` for the index hint, then the constraints after a `|` |

A field may be called `kind`: `type/core.template/field/kind` is that field,
and not the kind of a type called `core.template/field`. The parser takes
`type/<machine>/kind` as a type's kind only when the machine name has no slash.

Parsing that list is untrusted. `..`, an absolute path, a byte that is not
UTF-8, and a public id that fails its check are refused. A failing check is
not looked up, and nothing is written.

## Querying a type's entities

`gdefcore_entity_query_current()` is the unfiltered list with a predicate: it
runs the port's query over entities (defiant-storage `query.h`, "Over
entities") on the type's current tables, with the entities that are something
now (saved, and not cleared) and the predicate the caller hands it, and
returns the public ids in the query's order, with the total. The predicate is
of the port's form: typed field operands, the entity's facts (published,
deleted, creator, the newest revision and its author) and EXISTS over
another type. The query binds one language (the caller's, `en` by default).
The fields a declaration indexes are indexed by the store, so an equality, an
`in`, a range or a sort on one reads its answer and not the table.

This function filters nothing for a principal; it is not a way to read for
one. `gdefcore_access_list()` builds a principal's access filter into the
predicate it hands it (access.md, "Lists").

## Groups, multiples and order

Since story S6d a field may be a **group** (`GDEFCORE_Field::type` is
`GDEFSTOR_FIELD_GROUP`): it holds items, each with the fields in
`GDEFCORE_Field::children`, recursively, at most `GDEFSTOR_MODEL_MAX_DEPTH`
groups deep. Any field may be **multiple** (`GDEFCORE_Field::many`), a group
included; a group that is not multiple holds at most one item. A group is a
field of the entity, never an entity of its own (AD-14): a change anywhere in
it is a change to the entity, one revision of its one history. A group holds
no value, so it is never personal or indexed, has no constraint and no scale,
and `required` on it means at least one item. A field is named by its path,
the names from the root group joined by `.`: `lines.taxes.rate`. Core's
declaration maps to the port's field tree one to one; the type record lists
every field by its path, in pre-order.

The purchase order is the design's own example and core's fixture
(`tests/test_groups.cpp`): lines with taxes and with discounts that have
breakdowns, and shipments with packages with tracking events.

**The flat calls see the root.** `gdefcore_entity_save()`, the field
enumeration (`gdefcore_type_field_count()` and its siblings), conditions,
forms and lists see the root group's fields that hold values, and nothing
else; for a type with no group that is every field, and nothing about such a
type has changed. A flat save of a type with groups keeps the group items as
they are. `gdefcore_type_tree_field_count()` and `gdefcore_type_tree_field()`
describe every field at every depth. A condition naming a group or a field
inside one is refused as one naming a field the type lacks: conditions on
nested fields are deferred (storage SPEC, "Deferred").

**Trees.** `GDEFCORE_Tree` is one language's content in texts: item 0 is the
root and holds the root's single fields; every other item sits under a group
field (and holds that group's single fields and items of its own) or under a
multiple single field (and holds one value, its own). Values are canonical
texts, as `gdefcore_entity_values()` gives them. `gdefcore_tree_save()` and
`gdefcore_tree_save_draft()` stage a tree as the language's whole content;
`gdefcore_entity_tree()` and `gdefcore_entity_revision_tree()` read one
unfiltered, and `gdefcore_access_tree()` reads one as a principal may.

**Item ids are the port's and stable.** A tree read from storage carries each
item's id; a tree staged for a save names an item the entity has by its id and
a new one by 0, and states order by the order it adds items. So:

- only what changed is written: a tracking event appended three groups deep
  is one item version and one revision, and an item named by its id whose
  values and place are the same writes nothing;
- a reorder (the same items, by their ids, in another order) changes order
  keys and nothing else;
- a tree equal to the current one writes no revision.

The flat API keeps matching a multiple field's values by position (the k-th
value in the item that holds the k-th value now), as it always has; a tree
names them by id.

**Personal fields inside groups name their subject source**
(`GDEFCORE_Field::subject`): a sibling field that is a single, non-personal
reference, whose value in the same item is the subject of the value
(AD-19). A field of the root may name one too, or leave it NULL and name each
value's subject as it is sealed (story S6c). A value is sealed for its
field's path (`gdefcore_subject_seal(..., "contacts.note", ...)`), and every
place that opens one, the save's MAC, the probe that finds a subject by
opening the text, the export and the re-index, opens it under that path.

**Not yet:** the patch form (`defiant-changeset/1`) has no file for a group or
its items, so `gdefcore_changeset_serialize()` refuses a changeset that
defines a type with groups or stages group items (`GDEFCORE_ERR_UNSUPPORTED`),
and forms for groups are the site-admin stories'. `gdefcore_subject_read()`
reads a field of the root.
