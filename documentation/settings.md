# Settings

A **setting** is a named value a site can change without a deploy: declared by
the kernel or by an enabled module, stored only when changed, edited through a
generated form. The header is `settings.h`.

## Declared

The kernel declares `core.site_title` (default `My site`) and `core.tagline`
(default empty), both in the group `core.site`. A module declares its own in its
manifest (modules.md): name `<module>.<name>`, type `text`, `number` or
`boolean`, default, label, description, group, and optionally

- a number's `minimum` and `maximum` (decimals, compared as numbers and never by
  locale),
- a text's `max_length` (at most 65536 bytes; 4096 when it names none),
- `environment_local`, and `secret` (a text only).

A module's declaration is checked when it is enabled: a default outside its own
bounds, a bound on something that is not a number, a minimum above a maximum,
and a secret that is not text each refuse the module. A group is
`<module>.<group>` (`<module>.general` for a setting with none) and is one tab
of a settings page.

## Stored only when changed

A setting that equals its default stores nothing. A value changed to the
default takes the stored row away (a clear, so history keeps it and undo
restores it). So a module upgrade that moves a default reaches every site that
never changed the setting and no site that did.

A changed value is a `core.setting` entity on the entity port (fields `name`,
`group`, `value`), written by changeset, read from the catalog's own tenant, and
revisioned. `gdefcore_settings_get()` answers the stored value, else the
default. Saving applies a changeset, which moves the config epoch, so the next
request is drawn with the new value and every fragment that carried the old one
is keyed out (AD-30). A save that changes nothing applies nothing and leaves the
epoch where it is.

The site name widget reads `core.site_title`, and draws `core.tagline` when it
is not empty. The base theme of the first kit, whose `site_name` it used to read,
is gone.

## Environment-local

An environment-local setting (an API key, a banner) is not part of the site's
truth, and the entity port does not hold its value. The value is a record in the
environment scope of the catalog's store (tenant byte `0x03`, the key made of the
tenant and the setting's name), beside the module host's installation record.
The entity port holds a marker for it: the same `core.setting` type with the
name, the group and a serial that moves on every change, and no value. The
marker is what makes a change to a local value a revision, a permission
question, and a move of the epoch like any other. Because the value is never in
the tenant's rows:

- a snapshot of the tenant does not carry it, and a restore does not write it;
  the destination keeps its own value, or none;
- a revision never keeps an old one, so undo cannot bring back a retired key;
- the configuration export leaves local settings out, and the import drops any it
  is handed (and any setting this tenant does not declare), so the target keeps
  its own;
- apply refuses a changeset that writes a value to a local setting
  (`gdefcore_settings_vet()`).

A secret setting is never echoed back: the form says Set or Not set, an empty
field leaves it alone, and a Clear box sends it back to its default.

## Who may

One permission, `core.settings.edit` on `core.setting`, granted to nobody. A grant
may carry a condition naming the setting's `name` and `group`
(`(= field.group "shop.limits")`), so a role edits one group and not another.
It is decided by the one `gdefcore_access_can_with()` for each setting a save
changes, as it is stored and as the write leaves it, by apply
(`gdefcore_settings_authorize()`), and a form that mixes a group the principal
may edit with one it may not changes nothing.

One permission with a condition on the group rather than a permission for each
group: a group is declared by a module at any time, and a permission for it would
have to be declared and granted by someone first, while a condition on the
existing permission is the mechanism the access model already has for exactly
this. The route that places a settings page asks the permission at type level
(the page is there for anyone who may edit some setting); the write is decided
for the setting.

## The form

`gdefcore_settings_form_html()` returns the form of a group: a field for each
setting, named `s.<name>`, with its description and bounds; a secret's
`c.<name>` Clear box; a hidden `token` the caller signs; and a hidden `version`.
Every text is escaped, and every digit is written as a character reference, so a
number in a value or a label is not a bare integer on a page a scanner for leaked
row numbers reads. How a settings page is laid out (one page, tabs, side tabs) is
the host's: the form is the part the core generates.

`gdefcore_settings_save()` takes what the form posted, all or nothing: every
value is checked first, a bad one refuses the form with a sentence that names
the setting, and nothing is written. `version` is the group's
(`gdefcore_settings_group_version()`, letters only and nothing of a value): a
save made against a version that has moved is refused as stale.

## Export and import

`gdefcore_settings_export()` is the `defiant-changeset/1` tree of the changed,
non-local settings. `gdefcore_settings_import()` parses a tree into a changeset
for this catalog, matching settings by name (the entity this site already has for
it, else a new one), accepting nothing but `core.setting` entities, dropping
local and undeclared settings (and counting them), and retargeting at the current
epoch. The caller applies it.
