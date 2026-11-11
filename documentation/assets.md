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

The bytes of a module's file are borrowed from the module; the site's own file
(below) is a copy the lookup made. Either way they are valid until
`gdefcore_asset_release()` is called on the result, which a caller of the lookup
always does, and a caller copies anything it keeps.

## The site's own files

A site adds its own stylesheets and scripts on top of a module's, under the
owner `site`: `asset("site/site.css")` gives `/assets/site/site.css?v=<hash>`. A
stylesheet is a `core.css-asset` and a script a `core.js-asset`, two
configuration entities of a name and a text, written only by changeset
(`gdefcore_siteasset_stage()` and `_stage_forget()`), so they have revisions,
undo and a stale save refused. The hash is made from the stored text when it is
read, so it cannot disagree with what is served: an edit changes the address of
the next page with no restart and no cache to invalidate. A file a changeset has
staged is found through that changeset, so a template saved with it in the same
changeset can name it.

The two kinds are two types so that two permissions are two permissions:
`core.asset.css.edit` ("Edit site stylesheets") and `core.asset.js.edit` ("Edit
site scripts"). Neither is implied by the other or by `core.layout.edit`. A script
runs with the authority of whoever is signed in when it loads, so the permission
to write one is the higher, and the administrator role is granted both at seed
like the other editing permissions. A refusal is the one fixed sentence, "That
edit is not allowed.", whatever the file holds. Both types are configuration, so a
changeset that writes one is high risk and is applied only with the typed
confirmation of the type names it touches.

A name has the same shape as a module's file name, and it is used once across the
two kinds, as a file name is under an owner. A text is UTF-8 with no control
character except a tab, a newline and a carriage return (a form posts its line
ends as CRLF), from 1 byte to 4 MiB. The staging call refuses a name or a text
that is not one, and the apply refuses an entity the port was given by another
road, with a sentence that names the file. A module cannot be called `site` and
ship files, so the owner is never ambiguous. The port holds UTF-8 text only, so a
site cannot upload an image or a font; a module ships those.

## What is not here

Serving the files over HTTP and the policy a page is served under are the web
layer's (defiant-web). Binary files a site uploads need a storage of their own,
because a changeset file is UTF-8 text.
