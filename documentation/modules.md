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

`template-write` is a decision hook fired by apply before the write, for each
`core.template` a request's changeset writes (templates.md). It is fired as a
veto, `gdefcore_module_fire_veto()`: an operation something else has already
allowed, here the permission to edit a kind of template, is refused when any
subscriber denies and stands when none does. A subscriber with no opinion is
not a deny there. The subscriber is handed a `GDEFCORE_Template_Write_Hook`.

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
does not match. The host does not search for the functions.
