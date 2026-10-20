# Conditions

A condition is a small boolean expression, stored as text, that says which
entities a grant covers. Its format is `defiant-condition/3` (AD-34; see "Editions" below for what changed from `/1` and `/2`). The same
text is parsed, checked against the catalog, written in one canonical form,
explained in English, and evaluated on one entity. Everything is in
`condition.h`.

A condition only narrows a grant. Access is default deny and purely additive
(AD-10, AD-11): a condition never denies, and one that cannot be decided
covers nothing.

## Syntax

An s-expression. UTF-8, no NUL. White space is space, tab, CR and LF.

```
(and (= type "site.blog") (in field.group ("a" "b")))
(and (= type "site.blog") (= creator principal))
(and (= state "published") (< now field.embargo))
```

```
condition := "true" | "false"
           | "(" "and" condition+ ")"  | "(" "or" condition+ ")"
           | "(" "not" condition ")"
           | "(" cmp operand operand ")"
 | "(" "in" operand "(" constant+ ")" ")"
           | "(" "related" text "(" column+ ")" ")"
column    := operand | "_"
cmp       := "=" | "!=" | "<" | "<=" | ">" | ">="
operand   := "type" | "state" | "creator" | "revision.creator" | "principal"
           | "now"
           | "field." name | constant
constant  := "text" | integer
name      := [A-Za-z0-9_]+                  (at most 64 bytes)
integer   := "-"? [0-9]+                    (at most 18 digits)
```

`(related "blog.group-editor" (principal field.group))` holds when the relation
has a row whose first column is the principal and whose second is the entity's
`group` (see "Relations" below). Text constants are double-quoted. The escapes are `\"`, `\\`, `\n` and `\t`;
any other control character, and any other escape, is refused. `related` is a
clause and is refused anywhere else, with the message "related is written
(related "relation" (operand ...))". There are no variables and no function
calls; only the words above mean anything.

### Limits

Enforced at parse, with the byte offset of the first violation:

| Limit | Value |
|---|---|
| nesting of parentheses | 16 (an `in` list is one level) |
| nodes (operators, operands, constants, list members) | 256 |
| relations named in one condition | 4 |
| operands of one `related` | 4 |
| bytes of text | 4096 |
| bytes in one text constant, after escapes | 256 |

The canonical form puts one space between tokens an author may have run
together, so it can be longer than the text given. It must also fit in 4096
bytes, and a condition whose readable form is longer is refused ("once written
out"). That keeps every canonical text parseable and storable.

The parser is a hand-written recursive descent. It recurses once per level of
parentheses, so the depth limit bounds its stack, and its work is linear in the
input. A parsed condition is one fixed block.

## Operands

Every operand is a set of texts.

| Operand | The texts |
|---|---|
| `type` | the entity's type name |
| `state` | `published` when the entity's published flag is set (a draft beside its newest revision does not change that), else `draft`. An entity that was never published, was unpublished or was cleared is `draft`. There is no third state. |
| `creator` | the entity's creator: whoever made it (its first draft or its first save), recorded then and never changed, or none |
| `revision.creator` | the author of the newest revision (whoever wrote that revision), or none |
| `principal` | the request principal's public id, or none (an anonymous request) |
| `now` | the request clock in seconds since the epoch, as decimal text |
| `field.f` | the field's values in the language of the call, each the canonical text of the field's logical type (entities.md), or the single empty text when the field has none |
| a constant | itself |

`creator`, `revision.creator` and `principal` are *none*, not the empty text,
when absent, so an entity with no creator is nobody's own and an anonymous
request is nobody: two absences never equal each other. An absent field is the empty text (the spec's
rule), so `(= field.group "x")` is false on it and `(= field.group "")` is true.

Field values, `creator`, `revision.creator` and `state` are read from the
entity as it is stored: the **newest revision**, whether or not the entity is
published, which is always its content (access SPEC decision 13), never from
its draft and never from data being written (the evaluator has no parameter for values, so a submitted value cannot
steer a check). A condition says what the entity is; whether readers may see it
at all is a separate question that `read`, `list` and the route check ask for
themselves (`reader_sees` in access.c), so a stored `(= state "published")` is
not implied by `read` and not needed in it. A grant on `update` over group a
therefore holds for an unpublished group a entity, and its author can edit it
before anyone can see it. An entity with no revision (nothing saved but a
draft) or a cleared one has no fields: a field condition cannot hold on it. Values are read
in the language of the call, with no fallback to another language, as the
filter reads them. A many-valued field is all its values (at most 64).

The request clock is `gdefcore_request_set_time()`. A request that never set
it reads the wall clock once, at the first use, and keeps that value, so it is
fixed for the life of the request. Tests set it.

## Relations

A module declares a relation in its manifest (modules.md): a name in its own
namespace and one to four typed columns, each an entity (a public id), a text
or an integer. `(related "r" (a b ...))` holds when the relation has a row
whose columns are, in order, among the texts of the operands: `=` for each
column, the way `in` is `=` against a list, so a many-valued field matches
when any of its values is the column's. A `_` leaves a column free. A column
that is an operand with no text at all (`creator` of an entity with no creator,
`principal` of an anonymous request) matches nothing, as `=` does.

- **Validation** (`gdefcore_condition_validate_in()`): the relation must be
  declared by an enabled module, or by the module the same changeset enables;
  the operands must be as many as the columns; and each must suit its column.
  An entity column takes `principal`, `creator`, `revision.creator`, a text or
  reference field, or a text that is a canonical public id; an integer column
  an integer, `now` or an integer field; a text column anything but a field of
  another type than text and reference. Errors are at the byte offset of the clause
  (no such relation, wrong number) or of the operand.
- **Reading** is as the system. The evaluator and the list compiler read
  `core.relation_row` through the port's query of its current rows (its rows
  are kept in their own language, `en`, whatever the list's is), only for a relation an
  enabled module declares with this many columns and only its declared columns;
  there is no call that returns rows (relation.h). A relation that is not
  declared now (its module is disabled), or declared with another number of
  columns, is a failure: the condition does not hold, `not` included, so that
  disabling a module can never widen anything. A read that fails fails the
  same way.
- **Versions.** Every change to a relation's rows bumps a counter on the
  relation, in the changeset that changes them. A decision that read a relation
  notes it on the request at that version (`gdefcore_relation_note_dependency()`), so
  the render key's `reads:` digest moves with the rows and a fragment that used
  the relation is invalid after a change.
- **Compiled.** In a list, `related` is an EXISTS over
  `core.relation_row`'s current rows, read in the rows' language, with the
  entity being decided as the outer row. The compiled list equals the evaluated one (access.md).
- **Explain and rating.** "there is a row of blog.group-editor listing the
  person and the group field". The matrix and the module's confirmation add
  that the grant's breadth depends on who may add rows to the relation, and a
  grant that rests on a relation is never rated low.

## Operators

Fields are typed (entities.md), and a comparison reads them in their type
(access SPEC decision 12):

- Where no side is a field of a type other than text and reference, `=` holds
  when some text on the left equals some text on the right, byte for byte (so
  `"7"` and `"07"` differ, and so do `"x"` and `"X"`), as every operand did
  before fields had types.
- Where one side is a field of another type (an integer, a decimal, a float,
  a boolean, a date, a date-time), the other side is read in that type: a
  constant as a value of it (`"07"` equals an integer field holding 7; a text
  that is no value of the type equals none of its values), `now` as that
  instant in the type, and `principal`, `creator` and `revision.creator` never
  equal it. The empty text (a field with no value, or the constant `""`)
  equals only the empty text. Two fields compare when both are text or
  reference, or both of one type.
- `!=` is exactly `(not (= ...))`. `in` holds when some text of the operand
  is one of the constants, read the same way.
- `<`, `<=`, `>`, `>=` need a number, a date or a date-time field wherever a
  field is compared, and two fields of one type; they compare values, so they
  hold when some pair stands in the relation. A constant that is no value of
  the field's type makes its pair false, never an error. Without a field,
  both sides are read as integers (`-?[0-9]{1,18}`, `"07"` is 7) and a side
  that is not one makes its pair false. `not` of that false is true, as for
  any false.
- An ordering of a text, reference or boolean field, and a comparison of two
  fields of different types, are refused by validation (below). Met where
  nothing validated it (a condition parsed and evaluated directly), such a
  comparison fails: the condition does not hold, `not` included.

`and`, `or` and `not` are the usual truth tables. `not` is an operator inside
an expression; it is not a negative grant.

## Canonical form

`gdefcore_condition_canonical()` writes the form that is stored and hashed:
single spaces; a nested `and` inside an `and` (or `or` inside `or`) merged;
the operands of `and` and `or` sorted bytewise by their own canonical text and
de-duplicated; an `and` or `or` left with one operand is that operand; the
constants of `in` sorted and de-duplicated; integers without leading zeros
(`-0` is `0`). It repeats until the text stops changing, so
`serialize(parse(x)) == serialize(parse(serialize(parse(x))))`.

`gdefcore_condition_hash()` is the SHA-256, in hex, of the canonical text of
its input, so two spellings of one condition have one hash.

## Validation

`gdefcore_condition_validate(catalog, condition, type)` checks, with a byte
offset and one of these fixed messages:

- `no such field`: a `field.f` the type does not have, **or one that is
  personal** (AD-19: its stored value is ciphertext). The two are
  indistinguishable on purpose.
- `no such type`: a text constant compared with `type` that names no defined
  type.
- `no such state`: a text constant compared with `state` that is neither
  `published` nor `draft`.
- `only a number, a date or a date-time field can be compared by order`: a
  `<`, `<=`, `>` or `>=` with a text, reference or boolean field on a side, at
  the offset of the field (access SPEC decision 12). The message is one of the
  fixed set, so the offset is what names the field.
- `these two fields have different types and cannot be compared`: two fields
  of different types, at the offset of the second.

Fields are checked against the permission's own type.

## Explain

`gdefcore_condition_explain()` is English, built from the canonical form, so it
is deterministic and two spellings read alike. It names operands and constants
the author wrote; it can never print an entity's value.

```
(and (= type "site.blog") (in field.group ("a" "b")))
  the type is site.blog and the group field is one of: a, b
(and (= type "site.blog") (= creator principal))
  the creator is the person and the type is site.blog
(= revision.creator principal)
  the author of the revision is the person
```

## Evaluation

`gdefcore_condition_eval(catalog, request, condition, subject, &failed)` returns
1 or 0 and never an error. It reads the entity **as the system**, unfiltered.
It is not the access decision; it is an input to it. A true answer says the
entity exists and what it holds, so only the host calls it, with a condition an
administrator or a module wrote, never one a principal supplied.

- An entity that does not exist, a malformed id, or a NULL argument: 0, and
  `failed` stays 0. A hidden entity whose condition is false and an id that was
  never created answer the same.
- Anything else that goes wrong (an allocation, a store error, a field the
  type no longer has, a personal field, more than 64 values in a field): 0, and
  `failed` is set to 1. This holds under `not` too: a failure never becomes a
  grant.
- With no entity and a type, the subject is a hypothetical entity of that type
  (no state, no creator, no values).

Evaluation is bounded: the node limit bounds the work, and a field read per
operand evaluation is the only I/O. `and` and `or` stop at the first operand
that decides them.

## In a grant

`GDEFCORE_Permission.condition_text` declares an expression instead of
`condition`. Setting both is an error, and so is setting neither. It is parsed,
validated against the permission's type and stored in canonical form on the
`core.permission` entity. Roles keep granting by label. `any` and `own` stay
integers: they are stored as before, evaluated by the existing fast path, and
a test proves them identical to `(= type "T")` and
`(and (= type "T") (= creator principal))` through read, list and permits.
`own` is the entity's creator: an editor who saves someone's post does not
become its owner.

`gdefcore_access_read` and `_permits` evaluate an expression on the entity
asked about. `gdefcore_access_list` compiles it into a storage query (plan.h),
and decides entity by entity, with this evaluator, only when it cannot (see
"Lists" in access.md). The evaluator is the reference: the two give the same
entities for every condition, in the same order, with the same total, which a
generated sweep over both storage backends holds them to.

`gdefcore_access_grant_when()` grants under a condition of the grant's own, a
module's manifest can declare grants, and `gdefcore_access_matrix()` lists them
all with a risk. `gdefcore_condition_constrains_type()` says whether a
condition holds only for entities of some stated type; the risk rating uses it.
access.md and modules.md have the rest.

Not here yet: callbacks.

## Editions

`defiant-condition/3` adds `related` and changes nothing else, so a condition
stored at `/1` or `/2` means what it meant and `gdefcore_condition_upcast()`
copies it whole from edition 2 or 3 (a `related` clause included). A condition
written at `/3` is refused by nothing earlier than `/3`'s own parser, which is
the only parser: the editions share one, and the stored text does not say which
it is.

`defiant-condition/2` is the first edition that is not `/1`. Nothing is
released, but the stored form is versioned data (AD-15, AD-34), so the one
change is made the way a later one would be:

- Edition 1 had the operand `actor`: "who wrote the entity's published
  revision". It could not tell the entity's author from the last editor, so
  `own` followed whoever saved last.
- Edition 2 splits it. `creator` is the entity's, set at its first revision
  and never changed, and is what `own` means. `revision.creator` is the old
  `actor`: the creator of the revision that is now active.
- A person writing `actor` now is refused, with a message that names the new
  spellings. Silently reading it as one of the two would pick a meaning for
  them.

`gdefcore_condition_upcast(text, len, 1, ...)` is the upcaster: it renames the
operand `actor` to `revision.creator` (what `actor` read) outside text constants,
and nothing else. From edition 2 it copies. Text that is already in edition 2
has no bare `actor`, so upcasting it changes nothing and a stored condition need
not say which edition it is in. `gdefcore_condition_parse_stored()` is the
upcast followed by the parse; it is what reads a stored grant, a module's
declared grant and a stored text being rated or explained. `gdefcore_condition_parse()`
is for text being written. The upcaster is a rename and is as trivial as it
looks; `Cond.EditionOneActorIsUpcastAndNotWrittenAnyMore` and
`CondAccess.AStoredEditionOneGrantStillMeansWhatItMeant` pin it, and
tools/check-conditions.sh plants the three ways it can go wrong.

## Compiled into a list (plan.h)

`gdefcore_plan_condition()` turns a parsed condition into the predicate tree of
the storage query form. It is part of the public surface so that a list
(`gdefcore_access_list()`), a count and a later search all build their filter
the same way. Everything the evaluator decides, it decides:

- Constants, `type`, `now` and `principal` are constants of the plan. `now` is
  the request clock at the time the plan is built; the render key still does
  not capture it (A6).
- `creator` is the entity record's creator, `revision.creator` the newest
  revision's author; each is *none*, not the empty text, when absent. A field
  is read from the entity's current tables in the call's language, as a typed
  operand; a text or reference field with no value is the single empty text
  (the port's EMPTY_IF_NONE), and a reference is compared as text with texts
  and identifiers (AS_TEXT).
- `state` is compared through the record's published flag: "published" when
  set, "draft" otherwise. `state` against an operand that is not a constant is
  compiled too (some text of the operand is the state); an ordered comparison
  with `state` is false, as a state is never an integer.
- A comparison is compiled as the evaluator reads it (Operators, above): a
  constant compared with a field of another type than text is parsed into
  that type when the plan is built, and one that is no value of it is false;
  a comparison the types refuse is a failure.
- A condition that names a personal field or a field the type lacks fails when
  evaluation reaches it, and then does not hold at all, `not` included. `and`
  and `or` stop at the first operand that decides them, so a failure after that
  point is never reached. The plan builds, for each operand, the predicate for
  its value and the predicate for "evaluation reaches a failure", and the
  condition holds where the first holds and the second does not.
