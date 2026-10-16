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
`own`. `own` is true when the entity's actor is the request principal.
An entity with no actor is not anyone's own. There is no separate
permission named "own".

A condition can also be an expression (conditions.md), declared with
`condition_text` instead of the integer. `any` and `own` are the expressions
`(= type "T")` and `(and (= type "T") (= actor principal))`, and a grant that
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
entity, as the system, in memory. That is correct and not fast; compiling it
into the list query is a later story. A list's count is the number of
entities for which some grant holds. An entity whose only grant has a false
condition answers the principal exactly as an id that was never created does.
If a condition cannot be decided (an allocation fails, a store read fails, the
stored text no longer parses, a field is gone from the type or is personal) the
grant does not hold, the read answers as for a hidden entity, and the request
carries the note `defiant.condition.failed` with the value `1`.

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

`gdefcore_access_grant_risk()` is a pure function of the action, whether the
permission covers one field, the condition, and whether the grant reaches the
anonymous state (the role `anonymous`, or a module grant whose condition does
not read the principal). The action is read in its dot-separated parts: an
action with a strong word (`delete`, `remove`, `erase`, `publish`, `unpublish`,
`admin`, `grant`, `revert`, `restore`, `install`, `enable`, `disable`) is
strong; else one with an edit word (`update`, `edit`, `create`, `save`,
`draft`, `write`) is an edit; else one with a read word (`read`, `view`,
`list`, `search`, `count`, `export`) is a read; an action with none of them is
strong, so a name nobody recognises never lowers a rating.

- **High** when the condition bounds nothing (it names no type and reads
  nothing of the entity: `true`, a condition about the time or the principal
  alone, or `not` of a type); or the grant reaches the anonymous state and is
  not a read; or the action is strong and the condition reads neither the
  entity nor the principal; or the condition cannot be read.
- **Low** when the condition reads both the entity and the principal (`own`),
  or the grant is a read and the condition reads the entity or the principal.
- **Medium** otherwise: a grant of one field, an edit that nothing narrows, a
  read that nothing narrows.

The story that defined this said "no type constraint" for the first high case.
A grant is always for one type, and a condition that reads the entity's data
bounds it, so a condition that names no type but reads a field is not high on
that ground.

## The render key

Derived artifacts are keyed by the render key: tenant, config epoch,
edition, the hash of the granted permissions, overlay or `live`, and the
principal's public id when a compiled condition read the principal. The
hash covers labels, conditions (an expression by the hash of its canonical
text), types, fields and actions. A condition that reads the principal
(`principal`, `actor`) makes the key depend on who asks. It does not
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
no actor and no values) or for some entity of that type that exists. So an
`any` expression is held on a type with no entities yet, and an own
expression is held when the principal has authored one.
