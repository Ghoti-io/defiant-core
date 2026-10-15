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

A module may declare permissions. Enabling it does not grant them. The
confirmation is the module name, then those permission labels, sorted,
one per line. Apply with that text enables the module and grants those
permissions to `admin`. Any other confirmation is refused.

## The render key

Derived artifacts are keyed by the render key: tenant, config epoch,
edition, the hash of the granted permissions, overlay or `live`, and the
principal's public id when a compiled condition read the principal. The
hash covers labels, conditions, types, fields and actions. It does not
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
