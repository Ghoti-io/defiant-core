# Access

A tenant starts with three roles and one admin principal. The roles are
`admin`, `authenticated`, and `anonymous`. The principal holds `admin`.
It is not an account. `admin` starts with no permissions.

`authenticated` and `anonymous` are states. A request with no principal is
anonymous. A request with a principal is authenticated. Those two roles
cannot be assigned and cannot be deleted.

Admin is every permission granted to the `admin` role. The filter still
applies. There is no skip. The last principal who holds `admin` cannot
lose it and cannot be removed.

## Permissions

A permission has a plain-language label, the module that declared it, an
action, and a condition. The condition is `any` entity of a type, or
`own`. `own` is true when the entity's **creator** is the request principal:
the principal of its first revision, recorded on the entity record then and
never changed. An editor who saves someone's post becomes the creator of their
revision and not of the post, so the author keeps `own` and the editor does not
gain it. An entity with no creator is not anyone's own. There is no separate
permission named "own".

A condition can also be an expression (conditions.md), declared with
`condition_text` instead of the integer. `any` and `own` are the expressions
`(= type "T")` and `(and (= type "T") (= creator principal))`, and a grant that
uses the integers keeps its exact meaning. Access is default deny and purely
additive: a condition only says which entities a grant covers, and a
condition that cannot be decided covers none.

A new permission is granted to nobody, `admin` included, until a
changeset grants it. Granting to `authenticated` or `anonymous` is high
risk. The confirmation for authenticated is the line

```
authenticated means everyone with an account
```

The confirmation for anonymous is the line

```
anonymous means everyone without an account
```

A wrong confirmation writes nothing. Any other grant confirms with
`core.role`. A permission change is a high-risk changeset and can be
reverted.

Milestone 1 ships one role template, `Editor`. Copying it creates a
tenant role with permission to update its own `core.node` entities. The
copy is not the template. `Moderator` and `Usher` are not templates. A
second copy is a different role.

## The filter

The filter is a table of grants, rebuilt from storage at the current
config epoch. `gdefcore_entity_values` stays the unfiltered preview.
`gdefcore_access_read` is the read a principal uses.

A public id the principal may not see is the same error as an id that
does not exist, and no field value is returned. A field the principal
may not read is absent, not an empty string. A list returns only the
visible public ids, and its count is that number. A filter or a sort
that names a field the principal may not read, or a field that does not
exist, is the same error, and no row is returned.

A grant whose condition is an expression is evaluated for each candidate
entity, as the system, by `gdefcore_condition_eval()` (a read, a permits
question, and the reference for a list). A list is compiled instead: see
"Lists" below. An entity whose only grant has a false condition answers the
principal exactly as an id that was never created does. If a condition cannot
be decided (an allocation fails, a store read fails, the stored text no longer
parses, a field is gone from the type or is personal) the grant does not hold,
the read answers as for a hidden entity, and the request carries the note
`defiant.condition.failed` with the value `1`.

A field inside a group (story S6d) is named by its path in a field-read
permission (`lines.price`). `gdefcore_access_tree()` reads an entity's tree
through the filter: the entity as `gdefcore_access_read()` sees it, with each
field's read grants applied in every item that has the field, so a field the
principal may not read is absent from the root and from every group item, and
a group the principal may not read is absent with all its items. A condition
still reads only the root's fields (nested conditions are deferred), so the
answer for a field is the same in every item of one entity.

## Lists

`gdefcore_access_list()` returns the public ids of the published entities of a
type for which some read grant of the principal holds (an acting principal's
ceiling too, AD-12), narrowed by the list's own filter, sorts and condition.
`gdefcore_access_list_page()` also returns the total, and
`gdefcore_access_count()` only the total: **the number of entities the
principal may see that match, whatever the page**. A principal who may see 3 of
10 has a total of 3. `GDEFCORE_Access_List` is size-prefixed and grew by
appending: `offset`, `limit`, a second sort key, a descending flag for each
key, `condition` (a condition of condition.h, validated against the type, ANDed
with the access filter: it narrows and never widens) and `flags`. A caller
built against the shorter struct sets `size` to its size and gets the old list
exactly: the single equality filter, the single ascending sort, every row.

Order is the sort keys (the first value of the field in the call's language,
none before any value, compared as bytes), and last the order the entities
were created in; so a page is always a slice of one total order. The old list
sorted with `qsort`, whose order for equal keys was not defined; it is now
stable. A key containing a NUL byte used to be compared up to the NUL; it is
now compared in full. `limit` 0 is every row; a larger `limit` than
`GDEFCORE_ACCESS_LIST_MAX_LIMIT` (200) is clamped to it.

### Compiled, and the fallback

A list is compiled into a storage query (`gdefstor` query form, see
defiant-storage's `documentation/query.md`) and the store finds, orders, counts
and pages the rows. The predicate is: the entity record's published flag is
set, **and** one of the read grants of the type holds, **and** the filter and
the condition hold. Each grant is its base (`any` is true, `own` is "the
record's creator is the principal", an expression is `plan.h` compiling it)
and, for an agent, one of the acting principal's grants for the same permission
with its base. Since story S6b this is the port's query over the type's
current tables (defiant-storage `query.h`, "Over entities"), in the list's
language: a field is a typed operand of the entity's newest revision;
`creator`, the published fact and `revision.creator` (the newest revision's
author) are the entity record's; a relation is an EXISTS over its rows; `now`
and `principal` are constants of the request. A draft, and an older revision,
are never read: the current tables hold neither. `gdefcore_condition_eval()` remains the reference:
the compiled predicate selects the entities it holds on, including where it
cannot decide (an operand that fails ends the evaluation and the condition does
not hold, `not` included; `plan.h` carries that as a second predicate, "the
evaluation reaches a failure").

The list is decided entity by entity instead, with the same rows in the same
order and the same total, when:

- a filter, a sort or the condition names a field that has a field-level
  read grant declared on it (whether the principal may name it is decided per
  entity, and a refusal refuses the whole list);
- a filter or a sort names a personal field (its stored value is ciphertext,
  which the query form never reads: a *condition* naming one is refused);
- the catalog lets a field hold more than 64 values (the evaluator fails past
  64 and a stored document does not say how many a save was allowed);
- the compiled predicate is over a cap of the query form (8192 nodes, 64
  deep), or a plan builds more than 6000 nodes; or
- `GDEFCORE_ACCESS_LIST_EVALUATE` is set, which is how a test or a person
  can ask for the reference.

A condition that tests a relation (`related`, conditions.md) is compiled as a
semi-join over the relation's rows, with the entity as the outer row, in both
backends; the list notes each relation it used on the request at the relation's
version, so the render key's `reads:` digest moves with its rows. A relation
that is no longer declared is a failure, and the grant is out of the list.

After a successful list the request carries the note `defiant.access.list`,
`planned` or `evaluated`. A grant whose condition cannot be read (the stored
text no longer parses) does not hold, and the request carries
`defiant.condition.failed`; a compiled list sets that note when a condition
*could* fail to decide (it names a personal field or one the type lacks), where
the evaluated list sets it when an entity reaches the failure.

A module may declare permissions. Enabling it does not grant them. The
confirmation is the module name, then those permission labels, sorted,
one per line. Apply with that text enables the module and grants those
permissions to `admin`. Any other confirmation is refused. A module that also
declares grants adds one line for each, in words, between those lines in sort
order: `Module <name> grants <label> (<risk> risk): <the condition in English>`.
A confirmation without that line is refused, so nothing is granted that was not
shown.

## A grant under a condition

`gdefcore_access_grant_when()` grants a declared permission to a role under a
condition of the grant's own. The role holds the permission where the new
condition holds as well as the one the permission was declared with, so a grant
can narrow a permission and never widen it: a permission declared `own` and
granted `(= field.group "a")` is held for the person's own posts of group a,
not for all their own and not for all of group a. The text is validated against
the permission's type, and refused with nothing written if it is not valid, if
the confirmation is wrong, or if the role or the permission is unknown. The
confirmations are those of `gdefcore_access_grant()`.

The grant is stored as a permission of its own, declared by the same module
with the same action, type and field, whose label is the label and a suffix
that names the combined condition (`#when:` and sixteen hex digits of its
hash). The same condition granted twice is one grant; a different condition is
another. `gdefcore_access_role_grants()` names it as stored; the matrix shows
the label as declared. If the combined condition is past a limit of
conditions.md (4096 bytes, 256 nodes, depth 16) the grant is refused with
`GDEFCORE_ERR_LIMIT`.

## Grants of modules

A module can declare grants in its manifest (modules.md): a permission it
declared itself, or one the kernel declared, a condition, and nothing else.
While the module is enabled, a principal holds the permission for every entity
the condition holds on, whether or not any role grants it, and the anonymous
state does too unless the condition reads the principal. Roles and modules add:
any grant that holds allows, and the order they are met in never matters.
Disabling the module removes its grants from every decision with the same
changeset, because they are read from the module host's enabled set and are
never copied into a role.

A module grant stands on its own condition. It is not narrowed by the integer
condition (`any` or `own`) its permission was declared with, because the module
declared both and the matrix shows what the grant does. A grant is inert, not
widened, when its permission is not declared (yet), is declared by a module
other than the grant's own or the kernel, or differs from the grant in type or
field. Role grants and module grants share one limit of 64 grants per decision.

## Acting for a person

A request can name an acting principal (an agent or a delegate) besides its
principal. The decision is the intersection of the two sets (AD-12): a grant of
the principal's allows only where one of the acting principal's **role** grants
for the same permission (action, type and field) also holds on the same entity,
with the person as the principal. Module grants are not part of the acting
principal's set: they are held by everyone who meets a condition, so counting
them for the agent would let a module grant lift an agent past what its own
roles allow. A module grant is therefore within the ceiling only where the
agent's roles also hold the permission. An acting principal that is the
principal changes nothing. If the acting principal's grants cannot be read,
nothing is allowed, and the request carries `defiant.condition.failed`. Read,
list, permits and the render key follow this; the render key names the acting
principal when it is not the principal.

## The actions

A permission names any action a module likes. These are the ones the kernel and
its entity paths ask about, with a constant each (`access.h`) so a path and the
grant it needs are spelled once:

| Constant | Action | What it lets a path do |
| --- | --- | --- |
| `GDEFCORE_ACTION_CREATE` | `create` | Add an entity. Asked of **the container the path names**, or at type level; see below. |
| `GDEFCORE_ACTION_READ` | `read` | See an entity as readers do. Needs the published flag. |
| `GDEFCORE_ACTION_UPDATE` | `update` | Save a draft. Decided on the entity as stored, before the change. |
| `GDEFCORE_ACTION_PUBLISH` | `publish` | Apply the entity's draft, if it has one, and set the published flag; and `unpublish`, which is the same permission. |
| `GDEFCORE_ACTION_DELETE` | `delete` | Clear the entity: unpublished and deleted, every revision kept. |
| `GDEFCORE_ACTION_REVISIONS_READ` | `revisions.read` | View history, field by field. |
| `GDEFCORE_ACTION_REVISIONS_REVERT` | `revisions.revert` | Write a new revision that copies an earlier one. |

There is no `revisions.activate`: access SPEC decision 13 retired the
active-revision pointer, so the newest revision is always the content and an
older one becomes it again only by a revert (story S6b).

The revision actions are asked of the entity's **current state**: the permission
`revisions.read` is decided on the entity as stored (its newest revision and its
creator), not on the revision being looked at, and it does not need the
published flag, because a revision view shows drafts that readers do not see.
A grant of any of them is rated at least an edit.

## The matrix

`gdefcore_access_matrix()` lists every effective grant: each role's grants
(including `authenticated` and `anonymous`) and the grants of the enabled
modules. A row has its source (`role <name>` or `module <name>`), the
permission's label, action, type and field, the condition in canonical form,
the condition in plain English, and a risk. Rows are sorted bytewise by source,
label, type, field and condition, so the order depends on nothing but the
grants. Only an administrator may read it (the principal, and an acting
principal if there is one, must hold the role `admin`); anyone else gets
`GDEFCORE_ERR_INVALID`, as for a page that is not there, and no row. A matrix
that cannot be read whole (a stored condition that no longer parses) is an
error, not a short matrix. The texts are plain: a page escapes them.

Disabling a module leaves, as it always did, the grant of its declared
permissions to `admin` that enabling made. That is a role grant, so the matrix
keeps showing it.

### The risk of a grant

`gdefcore_access_grant_risk_on()` is a pure function of the action, the field
the permission covers (if any), the condition, and whether the grant reaches the
anonymous state (the role `anonymous`, or a module grant whose condition does
not read the principal). The action is read in its dot-separated parts: an
action with a strong word (`delete`, `remove`, `erase`, `publish`, `unpublish`,
`admin`, `grant`, `revert`, `restore`, `activate`, `install`, `enable`,
`disable`) is strong; else one with an edit word (`update`, `edit`, `create`,
`save`, `draft`, `write`) is an edit; else one with a read word (`read`,
`view`, `list`, `search`, `count`, `export`) is a read; an action with none of
them is strong, so a name nobody recognises never lowers a rating. A part
`revisions` makes the action **at least an edit**, whatever its verb says:
`revisions.read` has the word `read`, but it shows revisions that nobody has
published, so it is not rated as the read it looks like. `revisions.revert` is
strong already. (`activate` stays a strong word for a module's own actions.)

- **High** when the condition bounds nothing (it names no type and reads
  nothing of the entity: `true`, a condition about the time or the principal
  alone, or `not` of a type); or the grant reaches the anonymous state and is
  not a read; or the action is strong and the condition reads neither the
  entity nor the principal; or the condition cannot be read.
- **Low** when the condition reads both the entity and the principal (`own`),
  or the grant is a read and the condition reads the entity or the principal.
- **Medium** otherwise: a grant of one field, an edit that nothing narrows, a
  read that nothing narrows.

Then one more rule, which looks at what the holder could do with the grant
(D15): a grant whose condition **tests a field that the same grant lets the
holder change** is rated one step higher (low to medium, medium to high). Take
`update` where `(= field.group "a")`: its holder can set `group` on a post they
may edit, and move it into the group that lets them edit it, or move one of
theirs out of reach of anyone else's grant; the grant can widen itself. The
actions that can change what a condition reads are `update`, `edit`, `save`,
`draft`, `write`, `revert`, `restore` and `activate` (so also
`revisions.revert`). A grant of a single field is
asked about that field only; an entity-wide grant is asked about every field
its condition names. A `create` is not one of them: its condition is evaluated
on the container the path names, and the holder does not change that. `own`
tests the creator, which no one can change, so it is never raised.
`gdefcore_access_grant_risk()` is the same function without the field and so
without this rule; the matrix and the enable confirmation use the `_on` form,
and the matrix says it in words after the condition: "the holder can change
the field that decides who may edit, so this is rated one step higher".

The story that defined this said "no type constraint" for the first high case.
A grant is always for one type, and a condition that reads the entity's data
bounds it, so a condition that names no type but reads a field is not high on
that ground.

## One can()

`gdefcore_access_can(catalog, request, permission, type, entity_id, &allowed)`
is the single answer to "may this principal do this to that". The route check
(`gdefcore_access_route_check()`), the tab list (`gdefcore_routes_tabs_visible()`),
the signed-form path (`gdefcore_form_authorize()`) and the template editor
(`gdefcore_template_authorize()`) all ask it, so a button, the page behind it
and the write it guards cannot disagree. It is the
one evaluator: roles, then the grants of enabled modules, with conditions
decided as for read, list and permits, and bounded by an acting principal's
ceiling.

- **With an entity**: allowed when a grant for the permission, on that type and
  not on a field, holds on that entity. A permission nobody declared, an entity
  that does not exist (or whose id is not one), an entity of another type, and
  an entity on which no grant holds are one answer: not allowed, with
  `GDEFCORE_OK`. It does not also require the principal to be able to *read*
  the entity: a site that lets someone edit what they may not read has told
  them, by the edit, that it is there; grant the read as well to avoid that. (It
  was chosen over requiring the read because the template editor has always
  worked on a grant to edit alone.) The permission `read` is the exception that
  follows from what a read is: it is of what readers see, so an entity that is
  not published (never published, unpublished, or cleared) is not readable and
  answers as one that is not there, as `gdefcore_access_read()` and
  `gdefcore_access_list()` do. All three ask the one helper, `reader_sees`, so
  they cannot disagree about it; the oracle sweep found the first version
  telling an anonymous visitor that a draft existed, and the list went on
  listing such entities until it asked too. A condition reads the entity's
  **newest revision** and its creator whether or not it is published (see
  conditions.md), so a grant on `update` over group a holds for an unpublished
  group a entity, and `own` matches its creator: its author can edit it while
  readers cannot see it.
- **With no entity** (type level): whether the principal could hold it for some
  entity of the type, the question `gdefcore_access_permits()` asks. It is not
  safe for deciding an operation on a specific entity and says nothing about
  one; a page, a tab or a button passes the entity.
- **Memo.** The answer is remembered on the request, keyed by principal, acting
  principal, permission, type, entity and the entity's version (the config
  epoch at type level). The version is `gdefcore_entity_version()`, which every
  write that touches the entity bumps, a draft, a publish, an unpublish and a
  clear included; the latest revision number moves for none of those, and a
  memo keyed on it answered a question about an entity that had become another
  one, so a question asked twice is answered once, an entity
  written within the request is a new question, and no principal's answer is
  served to another. The memo holds `GDEFCORE_REQUEST_MEMO_MAX` (256) answers
  and then starts over. Failures are not remembered.
- **Render key.** A call marks the request principal-dependent and records
  the (entity, version) it read in the request's read set
  (`gdefcore_request_record_dependency()`). `gdefcore_access_render_key()` adds a
  `reads:` line, a digest of the set, when there is one, so a fragment that
  depended on an entity is a different fragment once the entity changes; a set
  of more than 256 says `+overflow`. Because the key then carries the
  principal, no two principals share a fragment that asked. (There was no read
  set before: the key carried only the config epoch, which every applied
  changeset moves; this is the precise form of it.)
- **Fuel.** A request may be given a budget (`gdefcore_request_set_fuel()`; none
  means unlimited). A call costs `GDEFCORE_ACCESS_CAN_FUEL_HIT` (1) when the memo
  answers it and `GDEFCORE_ACCESS_CAN_FUEL_MISS` (4) when it is decided. Without
  enough, it is refused with `GDEFCORE_ERR_LIMIT` and `allowed` 0, and the
  budget is left empty.
- **Failure.** A store read, an allocation, a condition that could not be decided
  (any grant, even one that would not have been the one to allow) and a lack of
  fuel give `allowed` 0 and a result other than `GDEFCORE_OK`, which is the
  caller's to log. They never allow and are not remembered. Bad arguments are
  `GDEFCORE_ERR_INVALID`.

## Protection is on the path

SPEC decision 7: **a library function runs at the trust of its caller.**
`gdefcore_entity_save()`, `_save_draft()`, `_publish()`, `_unpublish()`,
`_clear()`, `gdefcore_changeset_revert()`, `_revert_to()`, `gdefcore_form_submit()` and
`gdefcore_form_publish()` check no permission, there is no second, guarded copy
of any of them, and `gdefcore_changeset_enforce_access()` and the flag behind it
are gone. A system job, an importer and a handler call them with the authority
they have. What stands in front of them is the **path**: a route that names the
permission it needs and the capture of the entity it is about, dispatched
through `gdefcore_access_route_check()`; the menu drawn by
`gdefcore_routes_tabs_visible()`; a button. The handler behind the route calls
the entity operation, and is reached only when the decision was a yes. The
equivalence gate (`Can.TheDecisionIsTheOperation`) compares `can()` with whether
the *path* is served and the entity changes, for every action in the vocabulary,
over twenty kinds of principal (an agent's ceiling and a module's grant among
them), with both outcomes counted.

One exception remains, and is not this rule's to fix: `gdefcore_changeset_apply()`
still calls `gdefcore_template_authorize()` for a changeset that has a request
(templates.md). It is a permission check inside a library function that story A8
retires with the template veto.

**A condition is evaluated only on the stored entity the path names, never on
submitted data (SPEC decision 8).** The evaluator has no parameter for values and
reads the newest revision with no changeset (`gdefcore_entity_values()` with a
NULL changeset), so a body cannot enter it; what the paths must get right is
*which* entity is asked about and *when*:

- **The target comes from the token.** A signed form binds its target and its
  base version with the session and the principal. `gdefcore_form_authorize()`
  asks `can()` about the token's target; the id the request itself names (a route
  capture, a hidden field) is only checked against it, and a request whose id is
  not the token's target is refused, not decided on either one.
  `gdefcore_form_submit_authorized()` is the path for an update: that question,
  then `gdefcore_form_submit()`.
- **Before the change, on what is stored.** The question is asked first, before
  anything is staged, of the entity's newest revision: `update` over
  `(= field.group "a")` holds for a post that is in group a now, whatever the
  body says the group will be; a post can be moved out of the group by someone who
  may edit it, and cannot be moved in by someone who may not.
- **Never the draft.** A draft beside the newest revision is not what is
  asked about (a post that is group a as published and group b as drafted is still
  group a).
- **The actor is the system's.** The creator of a revision is the principal of the
  request that wrote it, set by `gdefcore_changeset_prepare()`; `own` is the
  entity's creator, recorded at its first revision. No field of a form can name
  either, and a field called `author` is only a field.

**Create has no stored entity,** so no condition is evaluated on what is about to
be written. `gdefcore_access_can_create(catalog, request, container, ..., type,
fields...)` is checked against **the container the path names**: a route such as
`/group/:id/new` captures the container's id and its handler passes that capture
(never a value from the form), and the question is `create` of the container's
type, on the container as stored. With no container it is a type-level grant of
`create` on the type. Then, field by field, `gdefcore_access_can_field()`: a
field that no `create` permission limits is free, and one that a permission
declared for that field limits needs a grant that holds, with no stored entity to
look at. (Group is only an example; the kernel has no group type and no group
permission. The tests use a container type of their own.) An `update` permission
declared for one field is not enforced field by field by the signed-form path;
`gdefcore_access_can_field()` answers the question for a path that wants it.

## Revision views

`gdefcore_access_revision_values()` is the read behind a revision view. It asks
`revisions.read` of the entity as stored, then the field-read grants of the field,
as a live read applies them, and returns one field of one recorded revision. It
does not need the published flag. Not permitted, an entity that is not there, a
field the type lacks and a sequence that is no revision of the entity are one
answer (`GDEFCORE_ERR_INVALID`). A field the principal may not read, and a field
with no value in that revision, are `GDEFCORE_REVISION_ABSENT` with no text, and
cannot be told apart. A **personal** field is never shown as the ciphertext it is
stored as: the answer is `GDEFCORE_REVISION_PERSONAL` and no text.
`gdefcore_subject_revision_marker()` turns that into `GDEFCORE_REVISION_ERASED`
and the text `[erased]` when the subject ledger names the person the value belongs
to (the caller names them, as for `gdefcore_subject_read()`); a revision view
never decrypts. `gdefcore_entity_revision_values()` is the unfiltered preview
that it is built on.

## The render key

Derived artifacts are keyed by the render key: tenant, config epoch,
edition, the hash of the granted permissions, overlay or `live`, and the
principal's public id when a compiled condition read the principal, or
`gdefcore_access_can()` was asked, and a digest of the entities and revisions
it read. The
hash covers labels, conditions (an expression by the hash of its canonical
text), types, fields and actions. A condition that reads the principal
(`principal`, `creator`, `revision.creator`) makes the key depend on who asks. It does not
cover role names. This edition is empty. The live overlay is `live`.

A fragment for any other overlay is not stored in a shared cache. A
module's compiled filter is also keyed by the hash of that module's
bytes, not its name. Two principals with the same grants and an `own`
condition get different keys. Two with the same grants and only `any`
conditions get the same key.

## Holding a permission

`gdefcore_access_permits()` answers whether the request's principal holds a
permission, named by its action. Granting does not change: the declared
permission is granted to a role by its label, and a principal holds what the
roles it has, `authenticated` and `anonymous` hold. A name nobody declared and
a permission nobody was granted are both "not held", admin included. The
permission to edit templates of a kind, `core.template.edit.<kind>`, is
declared this way (templates.md).

For a grant whose condition is an integer, held means a role was granted a
permission with that action, as it always did: the permission is not about one
entity. For an expression it means the condition could apply to something:
it holds for a hypothetical entity of the grant's type (which has no state,
no creator and no values) or for some entity of that type that exists. So an
`any` expression is held on a type with no entities yet, and an own
expression is held when the principal has authored one.
