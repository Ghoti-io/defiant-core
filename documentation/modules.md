# Modules

A module is installed once for the whole installation and enabled per
tenant. The installation record belongs to the kernel. A tenant's enabled
set is a changeset, and enabling or disabling is high risk. The
confirmation is the module name. Two names are sorted and joined with a
newline.

## Relationships

`requires` refuses the enable when the named module is not installed, or
not in the tenant's enabled set after this changeset. `enhances` enables
anyway. When the enhanced module is not installed the host reports exactly:

```
Module example enhances missing, which is not installed.
```

The name and the target are the ones in the manifest.

## Template contributions

A module can add variables to a template kind's contract with
`gdefcore_module_contribute()`: a name `<module>.<name>`, a type (`text`,
`markup` or `number`), a lazy provider and a `principal_free` flag. The
registration is code held by the host. A contribution is in force for a tenant
while the module is enabled, and is ordered against other modules' as hooks
are (before and after, then weight, then module name). Disabling the module
ends it. templates.md has the rest.

## Declared tables

A manifest can declare four tables (and grants, below) besides its hooks, services and permissions:
**routes**, **menu links**, **settings** and **template variables**. They are
members of `GDEFCORE_Module_Manifest`; a table a module does not use is NULL
with a count of 0. The manifest and every entry have a `size` member that must
be `sizeof` of its struct: any other size refuses the install, and the error
names the struct and both sizes.

| Table | Entry | What it says |
| --- | --- | --- |
| routes | `GDEFCORE_Module_Route` | machine name, path pattern with named segments, weight, after, permission, title, kind (page, tab or action), parent, default flag, admin flag, handler |
| menu links | `GDEFCORE_Module_Link` | machine name, menu name, label, target route, weight, parent link, link kind |
| settings | `GDEFCORE_Module_Setting` | machine name, type (`text`, `number`, `boolean`), default (as text), label, description, environment-local flag, group |
| template variables | `GDEFCORE_Module_Variable` | template kind, name, type (`text`, `markup`, `number`), description, provider, principal-free flag |

This is declaration only. There is no menu entity here, no stored setting value
and no menu rendering.

**Names.** Every machine name is `<module>.<name>` (AD-35), lowercase letters,
digits, `.`, `_` and `-`, at most 128 bytes. A template variable is
`<module>.<name>` as for `gdefcore_module_contribute()` (a hyphen of the module
is spelled `_`, and there is no further dot). A name outside the module's prefix
is an error that names the module and the entry. A name declared twice is an
error too. Because every name is under its module's prefix, two modules cannot
declare one name; the clash that can happen across modules is a second default
tab for one parent, and a route already in the table that receives them.

**Handlers and providers are services.** A route names its handler, and a
variable its provider, by the name of a service the same module declares in its
`services`. The service's table is a `GDEFCORE_Module_Route_Handler`
(version `GDEFCORE_MODULE_ROUTE_HANDLER_VERSION`) holding a
`GDEFCORE_Route_Call_Fn` and the route's data pointer, or a
`GDEFCORE_Module_Variable_Provider` (version
`GDEFCORE_MODULE_VARIABLE_PROVIDER_VERSION`) holding a
`GDEFCORE_Contribution_Fn` and its state. A native library and a guest declare
them the same way, and the host reads them from the same copy of the manifest
`gdefcore_module_service()` reads. The service has to be the declaring
module's own: a service of another module under the name is not it. A missing
service, another version, or a table without the function is an error naming
the route or the variable.

**Validation.** `gdefcore_module_enable()` checks the module's own tables by
themselves, and stages nothing when they are wrong (a name outside the prefix,
a malformed field, a handler that is not the module's own, a title that is not
UTF-8, a pattern the route table would refuse, a second default tab among its
own routes). The references that leave the module (a tab's parent route, a menu
link's route and parent link, a default tab against another module's) are
judged at apply, against the site the whole changeset leaves, because the
changeset may enable the other module too, in any order, and may disable one
that the first still needs. `gdefcore_changeset_apply()` refuses the changeset
with the module, the entry and the reason in `gdefcore_changeset_refusal()`.
The checks are: an orphan tab; two default tabs for one parent; a menu link
whose route, parent link or menu does not match, or that is its own ancestor; a
setting whose default is not a valid value of its type; a template variable for
a kind that does not exist (the kind is read from the store); and a name a
kind's base already has. The route rules are the route table's own: the
declared routes are added to a scratch table for the check.

**Order.** The enumerations list the enabled modules in AD-10 order: a
subscription's `before` and `after` against another enabled module put the two
in that order; the module name, as raw bytes, decides among the rest.
Registration order never does, and neither does the order modules were
installed or enabled in. Hook orders are decided one hook at a time, so two
hooks may ask for opposite orders; the declarations take one order for all of
them, and where the relationships loop the lowest name among the modules left
goes first. Within a module each table is in machine-name order (template
variables by kind, then name). Enabling a module twice, or disabling and
enabling it, leaves the same enumerations.

**Enumeration.** `gdefcore_module_routes()`, `_links()`, `_settings()` and
`_variables()` return what the modules enabled for a tenant declared, in that
order. A changeset passed as the projection shows the site it would leave. The
routes come as `GDEFCORE_Route_Spec`s with the handler resolved, ready for
`gdefcore_route_add_spec()`; `gdefcore_module_add_routes()` adds them all to a
`GDEFCORE_Routes`, a tab after its parent. The variables are the records
`gdefcore_module_contributions()` returns for their kind, so a template's
contract includes them while the module is enabled. A module that is
quarantined declares nothing.

**Limits.** At most 64 routes, 64 links, 64 settings and 32 variables per
manifest, and 16 services (it was 4: a module with a handler, a provider and a
service of its own needs more). A string past 64 KiB, or a table with a count
and no data, is refused when the module is installed. The other limits are
checked when the module is enabled: 128 bytes for a machine name, 256 for a
label or title or permission, 2048 for a path, 1024 for a description or a
default value.

## Grants

A manifest can declare **grants** (`GDEFCORE_Module_Grant`, appended after the
template variables): the label of a permission, its type, its field (or none),
and a condition (conditions.md). While the module is enabled, every principal
whose request meets the condition holds the permission, with or without a role.
Nothing denies: a grant only adds. access.md has how that is decided, shown and
rated.

- **Which permission.** The module's own (a label in its `perms`) or one the
  kernel declared (module `core`). A label another module declares is refused
  when the module is enabled, and the host's error names both modules and the
  label, whether the other module is enabled or only installed. A label nobody
  declares is refused too. The type must be the permission's type and the field
  its field, or the grant is refused.
- **The condition** is parsed and checked against the type when the module is
  enabled (an unknown field, a personal field, a `related` of a relation that is
  not declared, a type that is
  not defined, text that is not a condition, are all refused), and the enable
  stages nothing. It is not narrowed by the integer condition the permission
  was declared with.
- **Confirmation.** Enabling adds one line per grant to the confirmation: what
  it grants, how broad it is (low, medium or high risk) and the condition in
  English. Enabling is already high risk; the lines are what makes the grants
  seen. A wrong confirmation writes nothing.
- **Enumeration.** `gdefcore_module_grants()` returns the grants of the enabled
  modules, as the other enumerations do (AD-10 order, a projection shows the
  site a changeset would leave). Access reads this, so a disabled module
  grants nothing at once.
- **Limits.** At most 16 grants per manifest (`GDEFCORE_MODULE_GRANTS_MAX`).
  An empty permission, type or condition is refused when the module is
  installed. A manifest built before grants existed declares none.

## Access callbacks

A manifest can register **access callbacks** (`GDEFCORE_Module_Callback`,
appended after the upcasters): a name, a scope (`GDEFCORE_CALLBACK_FIELD` or
`_OPERATION`), the permission it grants with its type and field, the service
that carries the function (`GDEFCORE_Module_Access_Callback`, at
`GDEFCORE_MODULE_ACCESS_CALLBACK_VERSION`), the fuel and timeout of a call,
its cacheability (`GDEFCORE_CALLBACK_CACHE_TOKEN`, `_TTL` with
`ttl_seconds`, or `_NONE`) and, for a field, `GDEFCORE_CALLBACK_LOCKED`.
access.md has how a callback is asked, bounded and shown.

- **At install** the shape is checked, in words: row scope
  (`GDEFCORE_CALLBACK_ROW`) is refused, a field scope names a field and an
  operation none, the fuel, timeout and time to live are within their limits,
  the flag is locked or none, the name is `[a-z][a-z0-9_]*` and unique in the
  module, and the service resolves to a function.
- **At enable** the permission is judged as a grant's is (the module's own or
  the kernel's, on its type and field), a field callback's permission names
  the field, and an operation callback's action is not a row action. A
  refusal names the module, the callback and why, and stages nothing.
- **Confirmation.** Enabling adds one line per callback: `Module <m> decides
  <permission> per entity with its callback <name> (<scope> scope, high
  risk): its breadth cannot be judged.`
- **Enumeration.** `gdefcore_module_callbacks()` returns the callbacks of the
  enabled modules; `gdefcore_module_field_governed()` says whether one governs
  a field. A disabled module's callbacks grant nothing and govern nothing.
- **Limits.** At most 16 callbacks per manifest
  (`GDEFCORE_MODULE_CALLBACKS_MAX`).

## Relations

A manifest can declare **relations** (`GDEFCORE_Module_Relation`, appended after
the grants): a typed link between entities, in the module's own namespace
(`blog.group-editor`), with one to four columns. Each column is an entity (a
public id, optionally of a stated type), a text, or an integer
(`GDEFCORE_RELATION_ENTITY`, `_TEXT`, `_INTEGER`). A condition tests membership
with `(related "blog.group-editor" (principal field.group))` (conditions.md).

- **Names.** `<module>.<name>` as for any declared name; a column is
  `[a-z][a-z0-9_]*` and at most 32 bytes; two columns of one relation do not
  share a name; a type is named only by an entity column. A relation with no
  column, more than four, or a column of an unknown kind is refused when the
  module is installed or enabled.
- **Types.** An entity column's type must be defined when the module is
  enabled, or be in the module's own namespace (which the module defines when
  it runs). The enable stages nothing when it is not.
- **Enumeration.** `gdefcore_module_relations()` returns the relations of the
  enabled modules (AD-10 order, then name; a projection shows the site a
  changeset would leave). Conditions are judged against this, so a disabled
  module's relation takes every decision that rested on it out at once, in the
  same changeset. The rows stay and come back with the module.
- **Rows** are entities of the kernel type `core.relation_row`, one per row,
  written by the owning module through `gdefcore_relation_add()` and
  `gdefcore_relation_remove()` (relation.h). They are business data (SPEC
  decision 6): an entity column holds a public id and keeps holding it when
  the person it names is erased. **The owning-module rule:** the call names the
  module; the relation must be one that module declares and has enabled. A
  module that names another module is refused. There is no ambient "current
  module" in a C call, so the name is a claim the call checks against the
  declaration, and the path that reaches the module's code is what keeps a
  module from using another's name (SPEC decision 7). A relation's rows are not
  read by any call; the evaluator and the list compiler read them as the
  system, only the declared columns of a declared, enabled relation.
- **Version.** Each relation has a counter that every change to its rows bumps,
  in the changeset that changes them, so a render key's `reads:` digest moves
  with them.
- **Limits.** At most 16 relations per manifest
  (`GDEFCORE_MODULE_RELATIONS_MAX`), four columns each. A manifest built before
  relations existed declares none.

## Stored-data schema versions

Every component that stores data, core and each module, has a stored-data
schema version (AD-15): an integer, 1 for its first shape and one more for
each later one, never a semver. A manifest must say its module's
(`schema_version`): 0, and a manifest too short to hold the member, are
refused at install, in words. Core's is `GDEFCORE_SCHEMA_VERSION`, 1.
`gdefcore_module_schema` answers either; the install record keeps a module's,
so a quarantined module, which is not called, still answers it.

**Stamps.** Every revision, draft and record a component writes carries its
schema stamp, `<component>/<version>` (defiant-storage model.h): records are
core's (`core/1`); an entity is the data of the module its type's namespace
names when that module is installed or the tenant holds its data, and core's
otherwise (`core.*`, `site.*`, and any other namespace). History keeps every
stamp, through export, import and migration. A revert copies a past
revision's trees, so it is stamped as they were written.

**Where the data stands.** Per tenant, the record `core.schema` of each
component (`GDEFCORE_SCHEMA_TYPE`, keyed by its name, text the version)
says the version its current data is at. A component's first write records
the installed version; an enable records it when the tenant has none; a
disable leaves it. `core.module.enabled` is an empty record per enabled
module. A write of a component whose data is at an older version than the
one installed is refused with `GDEFCORE_ERR_MAINTENANCE` and writes nothing;
at a newer one, `GDEFCORE_ERR_UNSUPPORTED`. `gdefcore_schema_status` says the
same for a tenant, in words, for a maintenance response (AD-15).

**Steps and upcasters.** A manifest declares forward steps
(`GDEFCORE_Module_Step`, from N to N + 1) and read-time upcasters
(`GDEFCORE_Module_Upcaster`, the shape of N into that of N + 1), each at most
once per version below its own; there are no steps back. A step stages a
changeset on the migration's catalog and applies it with
`gdefcore_migration_apply`, in the step's write: what it writes is stamped
with the step's target. It reads its component's data in the shape it
starts from. A read of an entity whose module declares upcasters runs them
on each tree, from the version of the revision that wrote it (the newest
revision up to the one read that changed that language) or of the draft, up
to where the tenant's current data stands.

**One migration path.** `gdefcore_schema_migrate` brings a tenant forward:
core first, then each module by name, every step in turn. It checks
everything first and writes nothing on a refusal, naming the component and
both versions: data at a version with no step from it (a gap), data newer
than the installed component, data of a module not installed. Each step
commits in a write of its own with its row in the migration table
(`core.migration`, keyed `<component>:<from>` in ten digits, text
`<from> <to>`) and the version it reaches, because the next step reads what
it wrote; a failed step leaves the tenant at the last version reached, under
maintenance. A live upgrade (a host with a module installed above the
tenant's version) and a restore of older data (subjects.md, "Backups") both
call it, so the same tenant brought forward either way is written alike.
`tools/check-migration.sh` plants a migration skipped at import, a revision
upcast as the wrong version, a step that rewrites the migration table's
history, a restore that dates its steps by its own clock, and a write that
records the installed version over data that is behind, each red by name.

## Hooks

A hook is an event, an alter, or a decision.

An event tells every subscriber and has no result. An alter hands every
subscriber one shared value, in order. A decision is allow, deny, or no
opinion: any deny wins, otherwise any allow wins, otherwise the fire is
deny. No subscribers on an event or an alter do nothing. No subscribers
on a decision deny.

Subscribers name `before` and `after` against module names. The host
sorts each hook for each tenant. A cycle names both modules and refuses
the changeset; other tenants stay ready. A larger weight runs later.
Equal weights run in ascending module-name order, compared as raw bytes.
Registration order does not decide. The chain is data, rebuilt when the
config epoch changes.

Apply fires `presave`, `validate`, then `save` or `delete`, then
`revision` for a save, inside the one port write. Any failure aborts that
write. `after-commit` runs only after the write has committed, and its
failure does not roll the write back.

No hook decides who may edit a template, and no decision hook can refuse what
a grant allows: a module that wants to widen who edits supplies a grant, and
one that wants to narrow it grants less (templates.md, "Who may edit a
template").

On a read, a failing event or alter is skipped, counted, and named. A
failing decision fails the call. An access-relevant subscriber fails the
call when it fails. An access contribution from a subscriber that did not
declare it is refused.

## Loaders

The host looks up one symbol, `gdefcore_module_manifest`. Module code
does not search the process for symbols. A native library is opened only
when the caller passes the full-trust flag. A module built against
another core namespace token is refused, and the error names both tokens.

Before a native call the host records that the call has entered, and
clears the record when the call returns. At the next open, a record that
is still set means the module is quarantined: it is not called, and it
stays off until a human enables it again. The record is a stored flag.

A guest is the same entry, handed over as a function table, without the
full-trust flag. `lang-wasm` will fill that table later. This library
does not parse Wasm bytecode and does not depend on `lang-wasm`.

An optional capability is a named, versioned function table. Lookup
returns the table, or NULL when the module is not enabled or the version
does not match. The host does not search for the functions. A route
handler and a template variable's provider are such tables (see Declared
tables).
