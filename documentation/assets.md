# Assets: files a module ships

A module ships the stylesheets, scripts, images and fonts its pages need by
declaring them in its manifest (`GDEFCORE_Module_Asset`, modules.md). The bytes
are compiled into the module's library, so there is nothing to unpack and no
file on disk that can go missing or fall out of step with the code that names
it. A site's own files are a separate thing, stored as data and edited in the
admin.

## What a module declares

| Member | Meaning |
| --- | --- |
| `name` | A file name: 1 to 128 bytes of `a-z`, `0-9`, `.`, `_` and `-`, starting with a letter or digit, with no `..`. |
| `kind` | `GDEFCORE_ASSET_CSS`, `_JS`, `_IMAGE` or `_FONT`. |
| `media_type` | Empty for a stylesheet or script, whose type is fixed by its kind. An image names one of `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/avif` or `image/svg+xml`; a font one of `font/woff2` or `font/woff`. |
| `bytes` | The file. Never empty and at most 4 MiB. A stylesheet or script must be UTF-8 text. |

A manifest declares at most 64 assets. A module that breaks a rule is refused at
install, and the error names the module and the file.

## Public names and the tenant

An asset is public as `<owner>/<name>`, where the owner is the module's name, so
two modules can both ship `logo.svg` and neither is the other. It exists for a
tenant only while the module is enabled: `gdefcore_module_assets()` lists the
files of the modules enabled for a tenant, in module order and then by name, and
a module that is disabled ships nothing and ships it again, unchanged, when it
is enabled.

Each asset has a content hash: the first 128 bits of the SHA-256 of its bytes,
in lowercase hexadecimal. Equal bytes give an equal hash, in any module.

## Finding one and naming it

`gdefcore_asset_find()` takes `owner/name` (exactly one slash, both sides
non-empty) and gives the asset or `GDEFCORE_ERR_INVALID`; `gdefcore_asset_url()`
gives `/assets/<owner>/<name>?v=<hash>`. The hash is in the address so a changed
file has a new address and a cache never holds the old one under it. A template
uses `asset("owner/name")` (templates.md), which renders as an empty address for
a file the tenant does not have.

The bytes an asset reports are borrowed from the module and valid until it is
uninstalled; copy them to keep them longer.

## What is not here

Serving the files over HTTP, the policy a page is served under, and the files a
site authors itself are not in this library yet (a request path
is never joined to a filesystem path: a name is matched against the declared
names). Binary files a site uploads need a storage of their own, because a
changeset file is UTF-8 text.
