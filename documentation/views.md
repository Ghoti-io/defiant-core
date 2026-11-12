# Views

A **view** is a stored list of entities: which type, which rows, in what order,
which columns and how each is written. It is configuration data, saved and
changed as a changeset like a menu or a template, so a change takes effect on
a running site with no deploy (`view.h`).

## What a view holds

| Part | What it is |
| --- | --- |
| `name` | lower-case letters, digits, `-` and `_`, at most 64; unique among views |
| `type` | the entity type listed |
| `condition` | optional, `defiant-condition/1` (conditions.md): the and/or/not tree, comparisons of `field.<name>` with constants, `in`, `principal`, `creator`, `now` |
| `sort`, `sort2` | up to two root fields, each ascending or descending |
| `columns` | one to sixteen: a field, a group or a field inside a group (`lines.price`), a formatter and a heading |
| `args` | up to eight named arguments the condition may use, each with a source |
| `format` | `table`, `list`, `csv` or `json` |
| `limit` | rows in a page, 1 to 200 |

A column names a field by its path. A root field shows its value; a
many-valued field is shown with `join` or `count`. A **group** (`lines`) is
shown with `count`, the number of its items. A field inside a group
(`lines.price`, `lines.taxes.rate`) shows the values it holds in every item of
that group, in order, so it is read as many-valued: `join` or `count`. A group's
fields are not sort keys or condition operands (the condition language sees the
root only), and a personal field inside a group is refused as a root one is.

## Arguments

The condition names an argument as a bare `$name` where a constant may stand:

    (and (= field.kind $kind) (or (>= field.qty $min) (= creator $me)))

| Source | Value |
| --- | --- |
| `url` | a token the caller read from the path |
| `exposed` | a value the visitor chose |
| `principal` | the request's own principal: this is what "my own" means (AD-11); a caller cannot name it |
| `fixed` | a constant stored with the view |

A `url` or `exposed` argument may carry a default, used when the caller gives
none. An argument with no value and no default makes the view return **no
rows**, never every row; an anonymous request with a `principal` argument is
the same. The value is put into the condition as a quoted constant, with `"`
and `\` escaped: it cannot become an operator, a field or another clause. A
value the condition language cannot hold (a control character, over 256 bytes)
is refused. A `$` inside a quoted constant of the stored condition is that
constant's own.

## Saving

`gdefcore_view_stage()` validates first and stages nothing on a refusal;
`gdefcore_changeset_refusal()` then says why. The checks: the type exists; each
sort key and column is a root field that holds values and is not personal, and
is not many-valued where a sort needs one value; each formatter suits the
field's kind; the condition parses and validates against the type with each
argument standing as a constant, names only declared arguments and uses every
declared one; names are well formed and unique; two columns do not share a
heading; the format and the limit are in range. A save is a configuration
change, so applying it takes the type's name typed as the confirmation.

`gdefcore_view_operators()` and `gdefcore_view_formatters()` give the operators
and formatters a field of each kind may use. They are the tables the editor
offers, and a test checks them against what the save accepts.

| Kind | Operators | Formatters |
| --- | --- | --- |
| text | `=` `!=` `in` | `raw` `upper` `lower` `truncate-N` |
| reference | `=` `!=` `in` | `raw` |
| boolean | `=` `!=` `in` | `raw` `yesno` |
| integer, decimal, float | `=` `!=` `<` `<=` `>` `>=` `in` | `raw` |
| date, date and time | the same | `raw` `date` |
| many-valued, or inside a group | | `join` `count` |
| group | | `count` |

## Running

`gdefcore_view_run()` returns the page for the request's principal. Rows come
from the access filter (`gdefcore_access_list_page()`), so a row the principal
may not see is neither in the page nor in the total, and the condition only
narrows, as a grant's does. Each row is read **once**, with `gdefcore_access_tree()`, and every column
takes its values from that tree: a row costs one read of the entity however many
columns, values or group items it shows (`gdefcore_catalog_doc_reads()` counts
the reads, and a test holds the number to one per row). A field the principal
may not read, or one inside a group they may not read, is an empty cell, the
same as a field with no value. What a page of N rows still costs is N reads:
the store port has no read of many entities at once, so the reads are not
constant in the rows. A batched read of a page would be one more call of the
port (a list of public ids in, the trees out) in each backend and its
conformance suite. A stored view that no longer fits its type (a field was removed) is
refused with `GDEFCORE_ERR_INVALID`, never run loosely. A caller draws a table
or a list from the cells, escaped; a view makes no HTML.

`csv` and `json` are written by `gdefcore_view_result_text()`. CSV follows
RFC 4180 (quoting, doubled quotes, CRLF) and prefixes a cell that starts with
`=`, `+`, `-`, `@`, TAB or CR with `'` so a spreadsheet does not run it. JSON is
an array of objects keyed by the headings, with `<`, `>`, `&` and control
characters written as `\u` escapes.

## The older flat view

`core.view` (the `recent` pane of the starter kit: a type, a limit, a template
and one sort) is unchanged; it is what the render layer draws as a widget. A
stored view of this document is a different type, `core.query`, and a widget
that places one is the web layer's story.
