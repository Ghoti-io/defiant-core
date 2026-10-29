# Templates: kinds, contracts and validation

A template is a `core.template` entity: a `name`, a `body` and a `kind`, and
optionally an `attached` entity (a public id) and a `classification` (text a
module may refine edits by). The
kind says what the template may use. A template that names anything outside
its kind's contract does not validate, and a template that does not validate
is not stored.

## Kinds

A kind is a `core.template-kind` entity. It is configuration, so it changes
only by changeset.

| Field | Meaning |
|---|---|
| `name` | The machine name: `core.page`, `core.pane`, or `<module>.<name>`. |
| `label` | Words for the admin. |
| `version` | The contract version, an integer. |
| `variables` | Many. Each value is `name type description`; the description is the rest of the line. |
| `functions` | Many. Each value is `name arity`; arity is an integer or `any`. |

A type is `text`, `markup`, `number`, `list`, `entity` or `structure`.
`markup` is already-safe markup and is the one trusted type: a template
prints it unescaped. Everything else the host binds is `text`, bound with the
`HTML_ATTRIBUTE` tag, which is inert in element text and in either quote
style of an attribute (see render.md). A variable name is an identifier; a
module's variables are `module.name`. The name `pane` is the render's own and
a kind cannot declare it. A kind that declares `math` or `random` lets a
template use the engine's library of that name; every other kind has them
shadowed with null.

The starter kit stores these kinds and sets each built-in template's kind:

| Kind | Variables | Functions | Templates |
|---|---|---|---|
| `core.page` | none | `region/1`, `url/1` | `layout` |
| `core.pane` | `title`, `body`, `summary` (all `text`) | `url/1` | `entity`, `recent` |
| `core.menu` | `menu` (`text`), `items` (`list`) | `url/1` | `menu` |
| `core.tabs` | `items` (`list`) | `url/1` | `tabs` |
| `core.breadcrumbs` | `items` (`list`) | `url/1` | `breadcrumbs` |
| `core.sitename` | `name` (`text`) | none | `sitename` |
| `core.title` | `title` (`text`) | none | `title` |
| `core.messages` | `items` (`list`) | none | `messages` |

Each widget type has a template kind (layouts.md): page content and recent
posts draw with `core.pane`, the others with a kind of their own, and a module's
widget type names one.

The last three draw navigation (menus.md, "Widgets"). `items` is a list of
maps, one per entry in order, with `name`, `label`, `route`, `href`, `menu`,
`weight` and `depth` (an integer) and `current` and `trail` (booleans). A site
restyles a widget by editing its template, and may store more templates of a
kind and name one from a pane.

These are what the C templates the kit started from actually used. A pane is
one kind, so its contract is the union of what its two templates read: the
page content widget binds `title` and `body`, the recent-posts widget `title`
and `summary`. A name the widget's renderer does not bind
reads as null. `url` is in both contracts because story 1 registered it for
every template.

## The effective contract

The effective contract of a kind is its base, then the contributions of every
enabled module, in the order AD-10 gives a hook chain: before and after
relationships between modules first, then weight (larger runs later), then
module name, then registration order. Registration order alone never decides.
A cycle is an error naming both modules.

A module contributes a variable with `gdefcore_module_contribute()`:

```c
GDEFCORE_Module_Contribution c = {sizeof c};
c.kind = "core.pane";      c.kind_len = 9;
c.name = "m.count";        c.name_len = 7;       /* exactly <module>.<name> */
c.type = "number";         c.type_len = 6;       /* text, markup or number */
c.description = "...";     c.description_len = 3;
c.provider = my_provider;  c.user = my_state;
c.principal_free = 1;      /* the answer ignores who is asking */
gdefcore_module_contribute(host, "m", 1, &c);
```

The registration is code: it lives with the host, says what the module can
add, and is in force for a tenant only while the module is enabled. A
tenant that disables the module loses the variable, with nothing to remove.
Story 5's manifest table will call this for each row. The contributions a
catalog sees are those of the host bound to it with
`gdefcore_catalog_bind_host()`; a catalog with no host has none.

A module cannot redefine a name. The same module contributing a name twice
is refused when it contributes. A contribution that would land on a name the
kind's base already declares is an error that names both, the module and the
kind: `Template kind t.clash: module m cannot contribute m.count: the base of
t.clash already declares it.` It is found when the contract is built, so a
changeset that would enable such a module is refused at apply, and the
refusal says it. A contribution is a `text`, `markup` or `number` because a
Tang factory answers one scalar; a list, entity or structure cannot be
contributed lazily.

`gdefcore_template_contract_open()` builds the effective contract. With a
changeset as its second argument it builds the contract that changeset would
leave, which is what the preview uses.

## What a template is handed

The Tang library a template runs against holds the contract's names and
nothing else:

- the values the host bound that the contract declares as base variables
  (a bound name the contract does not declare is not in the library);
- the functions it declares (`url`, `region`);
- the contributed variables, each registered as a lazy Tang factory;
- null for `math` and `random`, the engine's own libraries, which a library
  shadows;
- nothing for the template that runs the body. That one is plumbing and sits
  in a layer of the wrapper program the body cannot reach.

A contributed variable is a library named for its module holding a factory,
so `m.count` is read as `use m.count as count;`. The factory is called when a
`use` reaches it, and never otherwise. It is given the request being
rendered, so it is principal-aware and reads through the access filter.
When it runs and the contribution is not `principal_free`, the request is
marked principal-dependent (`gdefcore_request_mark_principal_dependent()`),
and `gdefcore_access_render_key()` then puts the principal in the key. A
`principal_free` contribution leaves the key alone. This is observed while
rendering and never declared (AD-30). Because the render key is computed
after the page, a caller that wants it must compute it from the same request.

## Validation

`gdefcore_template_validate()` parses the source with `gltang_parse()` and
walks the tree through lang-tang's `ast/` headers. It finds:

- every `use` path, which must be a variable or function in the contract
  (`use m.count as c;`; a bare `use m;` is not a name);
- every identifier that is read and that the template never declares, which
  is a typo or a name used without `use` (the message says which);
- every call, which must name a function declared by `use` that is in the
  contract, with the contract's argument count. A call through an expression
  (`title.upper()`) is refused;
- every `.raw` and the marker it needs.

A name the template assigns, loops over, declares as a function, takes as a
parameter or marks `global` is free. A function body is its own scope: it
sees its parameters, its own locals and `use`s, its `global`s and the
template's functions, and not the template's variables. A parse error is a
finding with the parser's line and column. Syntax the walk does not know is a
finding too (`GDEFCORE_ISSUE_SYNTAX`): the validator refuses what it cannot
see.

Each finding carries a reason code, the 1-based line and column, the name and
a sentence.

The parse and the walk run on a side stack of 4 MiB, because lang-tang
recurses once per level of the tree and a tree may be 10000 levels deep.

### The unsafe marker

AD-18 allows an unsafe construct only beside a greppable `unsafe` marker. The
marker is the one `defiant-test`'s lint already uses: **the word `unsafe`
anywhere on the same line**. In a template that is a comment:

```
<% /* unsafe: this is the sanitised summary from the import */ %><%= summary.raw %>
```

or `<%= summary.raw // unsafe: why` on a line of its own. The marker belongs to
a line, not to the template. A template that uses `.raw` on a line without it
does not validate. `.html`, `.html_attribute`, `.percent` and `.javascript`
are not on the list; `.raw` is, because it turns escaping off. The word in
the template's plain text counts as well, since the rule is the lint's rule.

Editing a template, a kind or a module's enabled state is not itself an item
on AD-18's unsafe list (item 6 is Tang executing text it received as data
at run time); see the note in the spine patch.

## When it runs

- **Preview.** `gdefcore_template_preview()` validates every template the
  changeset saves, against the contract that holds once the changeset's
  module operations and kind edits are applied. It also checks that each kind
  the changeset saves still builds a contract, and, when the changeset
  enables a module, that no kind's contract would newly clash. If the
  changeset enables or disables a module, or saves a kind, it lists every
  stored template that would stop validating (`GDEFCORE_ISSUE_BREAKS`, with
  the name and line that no longer resolve). The risk it returns is high for
  a module operation, a kind edit, or any break.
- **Apply.** `gdefcore_changeset_apply()` calls the same check before it
  writes anything. A finding other than `BREAKS` refuses the changeset with
  `GDEFCORE_ERR_FORMAT`, and `gdefcore_changeset_refusal()` returns the text:
  `template 'recent', line 3: `summry` is read but never declared.` Nothing
  is written. A disable that breaks stored templates is allowed: it is
  already a high-risk change confirmed by name, and the preview is what
  tells the admin. The broken template then renders with the missing name as
  null.
- **Render.** A template with no kind, or whose kind is not stored, is
  refused at render with the same error as a template that is not stored. No
  site predates kinds, so there is no migration.

A change to a template takes effect on the next request. The render reads the
store every time; there is no compiled-template cache in this story. One
added later is keyed by the render key and by the template's revision.

## Who may edit a template

There is one permission, `core.template.edit`, labelled "Edit templates", on
the type `core.template` and declared by the kit (`gdefcore_template_edit_declare()`).
It is granted to nobody, admin included, until a changeset grants it. What it
covers is the grant's **condition**, written about the template (conditions.md):

```
(= field.kind "core.pane")                        panes, and not pages
(and (= field.kind "core.page")
     (= field.classification "internal"))         the pages classified internal
```

A role is granted it for a kind with `gdefcore_access_grant_when()` and the
first condition. A module supplies the second as a grant in its manifest, which
the matrix shows as "also granted by module X when ..." and the enable
confirms, and which goes when the module is disabled. The fields a condition
on a template can be about are `kind`, `name`, `attached` and `classification`
of the template, and any other it has, as stored.

**Nothing denies.** There is no hook a module can subscribe to in order to
refuse a template write. A principal edits a template when one grant holds on
it, whether it comes from a role, from a module, or from an access callback
(access.md); a source that grants nothing, or fails, takes nothing from
another. A restriction is written by not granting.

```c
/* The pages classified internal, for the people the desk module lists. */
static const GDEFCORE_Module_Grant kDeskGrant = {
    sizeof(GDEFCORE_Module_Grant), "Edit templates", 14, "core.template", 13,
    NULL, 0,
    "(and (= field.kind \"core.page\") (= field.classification \"internal\")"
    " (related \"desk.reviewer\" (principal)))", 106};
```

**One decision.** `gdefcore_template_can_edit()` is the question: may this
principal edit this template, leaving it of this kind? It asks
`gdefcore_access_can()` about the template as it is stored (when it has been
stored) and `gdefcore_access_can_with()` about the template as the edit leaves
it: the kind it becomes (or the stored one), and the name, attached entity and
classification a write stages or, if it stages none, as stored. Both must say
yes, which is what makes a move between kinds need the grant for the kind the
template is and for the kind it becomes, and what makes a new template, which has no
stored kind, need the grant for the kind it is to be. Because the stored
question is asked too, a value in the write can only narrow what is stored.
The editor's tab, its button and the write ask this one function.

**Where it is checked.** `gdefcore_changeset_apply()` calls
`gdefcore_template_authorize()` before it does anything else, for a changeset
that has a request (`gdefcore_changeset_set_request()`): the principal is the
request's. It asks `gdefcore_template_can_edit()` for each template the
changeset writes, so roles, the grants of enabled modules, conditions, and an
acting principal's ceiling all count. (This is the one permission check left
inside a library function; access.md says why.) A changeset with no request is
the operator's, such as the kit install or a tool run with the changeset API,
and is not asked. A refusal is `GDEFCORE_ERR_INVALID`, the code a principal
gets for an id it may not see, with the fixed sentence `That edit is not
allowed.`, never a module's reason, and writes nothing. It is checked before the
confirmation, the conflict check and validation, so what a principal may not
edit says the same thing whatever it holds. A revert
(`gdefcore_changeset_revert()`) is a changeset and is checked the same way.

**Which kinds a principal may see.** `gdefcore_template_may_edit()` answers
whether the principal may edit some stored template of a kind; a kind that
does not exist, one with no template, and one nobody granted give the same
answer. An editor lists only kinds for which it is true, and answers for any
template it may not edit as it answers for a missing one (AD-11).

## Previewing an edited body

`gdefcore_render_sample()` renders a body as a template of a kind, against
sample data, without storing it. Each base variable is bound to `Sample
<name>`, `region(x)` gives a marked stand-in, and a module's contributed
variable runs its real provider with the request. The kind's contract is the
library, as for a stored template. It is for a principal who may edit the kind
and gives `GDEFCORE_ERR_INVALID` to any other.

It takes an overlay. A fragment under any overlay but `live` must not enter a
shared cache (`gdefcore_access_shared_cache()`), and an editor passes
`preview`. `gdefcore_render_shareable_count()` counts the fragments the
process has offered to a shared cache: a render of a stored template offers
one, a preview offers none. Only a difference between two reads means
anything. This core has no fragment cache of its own; the count is the
instrument that shows a host's cache what it may keep.

## Public functions

| Function | Purpose |
|---|---|
| `gdefcore_template_contract_open/close`, `_version`, `_var_count/_var_at/_var`, `_fn_count/_fn_at` | The effective contract of a kind. |
| `gdefcore_template_validate` | For the editor: source and kind in, findings out. |
| `gdefcore_template_preview` | The changeset's findings and risk. |
| `gdefcore_template_vet` | What apply runs. |
| `gdefcore_template_report_count/_at/_text/_free` | Reading and freeing findings. |
| `gdefcore_module_contribute`, `gdefcore_module_contributions(_free)` | A module's contributions. |
| `gdefcore_request_mark_principal_dependent`, `gdefcore_request_principal_dependent` | The observed dependence the render key reads. |
| `gdefcore_changeset_touched_count/_at`, `gdefcore_changeset_refusal`, `gdefcore_changeset_set_refusal`, `gdefcore_catalog_host` | Reading a changeset and its refusal. |
| `gdefcore_template_edit_declare` | The one permission to edit a template. |
| `gdefcore_template_can_edit`, `gdefcore_template_may_edit`, `gdefcore_template_authorize` | Who may edit this template; some template of this kind; what apply asks. |
| `gdefcore_access_can_with` | `can()` about an entity as a write would leave it. |
| `gdefcore_access_permits` | Whether a request's principal holds a permission by its action. |
| `gdefcore_access_can` | The one decision: may the principal do this to this entity. What authorize asks. |
| `gdefcore_render_sample`, `gdefcore_render_shareable_count` | The editor's preview, and the shared-cache count. |
