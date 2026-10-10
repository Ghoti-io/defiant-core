# Entities

**Status:** describes what shipped in milestone 1, story 7.

A type is `core.<name>`, `site.<name>`, or `<module>.<name>`. It is content
or configuration, and its fields are text, one value or many. Values sit
under a language in the revision's `lang` object. The built-in types are
`core.entity_type` and `core.changeset`.

The integer row id is the storage key. Draft and published projections use
the type `d:` or `p:` plus the machine name, and the entity argument is the
decimal row id. `d:site.note` cannot collide with a machine name, because a
machine name has no colon. The public-id index is a projection whose type
is `i` and whose entity argument is the public id. Reading by the public id
uses that index. The document's `entity` field is the public id, not the key.

A core-owned projection of type `w`, keyed by the decimal row id, holds the
high-water sequence. Clearing draft fields does not remove it, so the next
save after reverting sequence 1 is sequence 2.

`gdefcore_type_define` writes a type without moving the config epoch, so a
content save can still be the epoch's first step. A changeset that defines
or changes a type is high risk. Apply of a high-risk changeset requires the
touched machine names, sorted, one per line. Apply commits the revisions and
both projections in one port write and increments the epoch in that write.
A port error aborts the write.

Serializing a changeset yields `defiant-changeset/1`: an ordered list of
relative paths and UTF-8 bytes.

| Path | Bytes |
| --- | --- |
| `format` | `defiant-changeset/1` |
| `epoch` | the decimal epoch the changeset was prepared against |
| `actor` | optional canonical public id |
| `entity/<id>/type` | the entity's machine name |
| `entity/<id>/base` | the decimal sequence the save was prepared against |
| `entity/<id>/op` | `save` or `clear` |
| `entity/<id>/lang/<lang>/<field>/<index>` | one field value |
| `type/<machine>/kind` | `content` or `config` |
| `type/<machine>/field/<name>` | `required one`, `required many`, `optional one`, or `optional many` |

Parsing that list is untrusted. `..`, an absolute path, a byte that is not
UTF-8, and a public id that fails its check are refused. A failing check is
not looked up, and nothing is written.
