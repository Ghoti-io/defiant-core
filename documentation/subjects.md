# Subjects

A subject is not an account. An account is a login. A subject is the
person a personal value is about. Nothing here links one to the other.
Erasure of a subject does not change an account's security epoch, and it
does not touch the password ciphertext.

## Personal and secret

`personal` is a property of the field definition. A personal value is
encrypted with its subject's key. The text stored on the entity is
ciphertext. `gdefcore_entity_values`, `gdefcore_entity_tree` and the other
unfiltered reads return that stored text: they do not decrypt (story S7).

## Whose a value is (story S7)

Every personal field names where its values' subject comes from (AD-19), on
its definition (`GDEFCORE_Field::subject`):

- a sibling reference: a single, non-personal `REFERENCE` field in the same
  group, whose value in the same item is the subject (a group's personal
  field must name one, story S6d); or
- nothing, which means the entity's own subject. Only a type declared with
  `GDEFCORE_TYPE_SUBJECTS` ORed into its kind has one: its entities are
  subjects. Core makes each entity's subject when its id is made
  (`gdefcore_entity_create`, which then needs the subjects bound with
  `gdefcore_catalog_bind_subjects`: making a subject is a key-store write) and
  keeps it with the entity, as the record `core.subject/<public id>`, in the
  reservation's own write. `gdefcore_entity_subject` reads it.

A personal field with neither is refused when it is declared. Whether a
type's entities are subjects cannot change once the type is stored, and a
field cannot become personal, or stop being, in place (a new field and a
conversion, AD-15). The patch form carries both (`content subjects` in a
type's `kind` file, `personal:<reference>` in a field's).

A save names every personal value's subject from the declaration, never from
the caller: a value sealed for anyone else (a note,
`gdefcore_changeset_note_sealed`, that names another, or a text that does not
open under the named subject's key for its field) is refused. When a
reference moves to another person, the value beside it must be sealed for
them again.

Two routes store one: `gdefcore_subject_save`, and a form signed and
submitted with `gdefcore_form_sign_subject` and
`gdefcore_form_submit_subject`. Every other writer refuses a personal
value (`gdefcore_entity_save`, the plain form route, a parsed patch),
and a revert or publish refuses a personal value that is not sealed. The
entity layer holds no key, so it checks that a value is shaped like a
sealed one (`s1:` and hex), not that it is one. A caller that has to stage
the revision itself, as the form route does, seals with
`gdefcore_subject_seal` and tells the changeset whose the sealed text is with
`gdefcore_changeset_note_sealed` (the subject, and the blind-index value the
seal returned).

## On the entity port (story S6c)

A personal field is a `PERSONAL` field of the port's declaration (AD-14): each
value is stored as its sealed text with its subject's public id in the column
beside it, and "everything about this person" is the port's subject lookup
(`gdefstor_subject_lookup`), which `gdefcore_subject_export` reads. A value
whose subject the declaration cannot name is refused, with a refusal
(`gdefcore_changeset_refusal`). A patch carries the subject of each personal
value beside it (`entity/<id>/subject/<lang>/<field>/<index>`).

`gdefcore_subject_save` names the subject itself: a field that takes the
entity's own subject stores under it; a field that names a reference stores
under that reference's value, and a first save, with the reference unset,
sets it to the subject the caller gives. A subject given that is not the one
the declaration names is refused.

**Unchanged is decided on the plaintext** (AD-19). Encryption is randomized,
so the same value sealed again is another ciphertext. A save that finds, at a
value's place, a stored value of the same subject compares the two by their
blind-index MACs under the tenant's key (a function of the plaintext): equal,
the stored ciphertext is kept, and the port sees no change, so the value
writes no item version, no revision and no blind row. Only a save does this:
a draft keeps the ciphertext it was given, and its publish is a save.

Every new version of a personal value that a save writes, a draft's publish
included, gets its blind-index row in the port's blind table, in the same
write: the MAC is the note's, or core opens the value with its subject's key
(`gdefcore_subject_mac_sealed`, which needs the catalog bound to the subjects
with `gdefcore_catalog_bind_subjects`). A draft holds the sealed text and the
subject and no MAC. Inside the write core asks the key store whether the
subject is erased: a new value of an erased subject is refused, the write is
aborted and the changeset or the draft is kept, so no blind row is ever
written for an erased subject. A value the entity already holds (another
field changed) is not a new value, and the port carries its row. Blind
equality is `gdefcore_subject_find`; `gdefcore_subject_mac` is the value a
lookup asks with.

A field cannot become personal after it was declared, nor stop being: the
redefinition is refused (AD-15), since a plain column has no subject beside
its values. A store written by something other than core can still hold a
plaintext in a personal field's history; a revert or a publish that would
carry it into a new revision refuses it.

A `secret` field is different. The password hash stays a secret under
the tenant `secret` key. Subject erasure does not unwrap it, replace it,
or bump the epoch that retires session tokens.

A field declared before `personal` existed is not personal. Callers that
set `size` and stop before that member keep compiling, and the missing
member is read as not personal.

## Where the key lives

Keys live in a **key store** (defiant-storage's `keystore.h`, AD-19): one per
tenant, apart from every data store, on the memory, SQLite or Postgres
backend. Core reaches it only through the port, and holds there:

- the tenant keyring's wrap (under the installation root), as the tenant
  secret `core-keyring`. The first open (`gdefcore_subject_open`, or
  `gdefcore_inst_open_keys` for every tenant of an installation) writes it; a
  later open adopts it. The raw keyring key is written nowhere.
- each subject key: 32 random bytes from `gdefcore_subject_create`, wrapped
  with AES-256-GCM under the keyring's `subject-wrap` purpose, kept as the
  subject's sealed material (`gdefstor_keystore_subject_put`). The key store
  never opens it; a read takes it back through the port and unwraps it here.
- the blind-index keys' derivation input: the keyring. Each field's key is
  HKDF under `blind-index:<field>`, so nothing is written per field.
- the erasure ledger.

The key store is written when a subject is created, when a tenant's keyring
wrap is first filed, when a subject is erased, and when a backup pair is
restored. A save, a seal, a publish, a read, an export, a rebuild and a
revision view only read it; the subject tests count the calls at the port.

The blind index is HMAC-SHA-256 of the value under that key (key id
`GDEFCORE_SUBJECT_MAC_KEY_ID`, normalization version
`GDEFCORE_SUBJECT_MAC_VERSION`: the bytes as given). Its rows live in the
tenant's data store, in the port's blind table, one per value version, never
in a revision row and never in a snapshot (story S6c; before it, a separate
"blind store" the caller passed to `gdefcore_subject_open`, which now takes
the tenant's data store). A snapshot or export of the tenant store holds
ciphertext, never a key and never a blind row.

`gdefcore_subject_cipher` is the cipher to give a key store that seals in
process (AES-256-GCM, a fresh nonce): core keeps its keys as sealed material,
but a key store needs one all the same.

## Erasure

Erasure has no undo. The confirmation is the subject's public id, one
line. A wrong id writes nothing.

A matching id runs three steps, in this order:

1. The key store destroys the subject key and appends the ledger row, in
   one step of its own. The ledger row is the public id and the time, and
   nothing else. From here every value of the subject reads `[erased]`.
2. The subject's blind-index rows are deleted from the tenant's data store,
   every type's, through the port (`gdefstor_blind_delete_subject`).
3. Caches are purged: every fragment of the bound fragment cache
   (`gdefcore_subject_bind_cache`, render.md) that decrypted a value of the
   subject. A render records each subject it decrypted on its request
   (`gdefcore_request_record_subject`), and the cache keeps that with the
   fragment; a fragment that decrypted nothing of theirs is kept.

A failure of step 1 is returned and nothing else runs. Steps 2 and 3 are
idempotent, and every `gdefcore_subject_open` and every restore replays the
ledger through them, as binding a cache does through step 3, so an erasure
cut short after step 1 (a crash, a failed data store) is finished then. Erasing an erased subject runs them again and
writes no second ledger row. Revisions stay, so the stored ciphertext stays.

What an engine keeps of a destroyed key is its own: SQLite's key store clears
it with `secure_delete` and a truncated log; Postgres's vacuums the key
tables after the erasure (`VACUUM (FULL)`). Neither reaches a write-ahead log
already archived: **expiring WAL archives is the operator's**, on the key
store's own retention.

## Backups

A backup is a pair (AD-19, AD-23):

- the **data set**, `gdefcore_subject_snapshot`: the tenant store's logical
  export, personal values as ciphertext, with the time it was taken in its
  manifest and what the tenant needs to come back up (AD-23, story S8): its
  edition, as the caller passes it from the installation's directory, and
  every component whose data the tenant holds (`core` and each module) with
  the stored-data schema version its current data is at, read from the
  tenant's own records (`core.schema`, one per component, whose text is that
  version; modules.md, "Stored-data schema versions"). Every revision, draft
  and record in it carries the schema stamp it was written with. It holds no
  key, no keyring wrap and no ledger.
- the **key set**, `gdefcore_subject_keyset`: the key store's export
  (`defiant-keyset/1`): the wrapped subject keys, the keyring's wrap and the
  ledger, with the time it was taken. It is a key backup, kept and retained
  apart from the data set.

Take the key set after the data set it pairs with. `gdefcore_subject_restore`
checks everything before it writes: the archive as untrusted input (AD-37),
that it is a data set, that the key set is this tenant's and not older than
the data set (`GDEFCORE_ERR_STALE` otherwise, since such a key set may hold a
key erased between the two), and that every component the data set needs is
installed here (the host it is given) at a stored-data schema version no older
than the data's, with a forward step from every version between
(`GDEFCORE_ERR_UNSUPPORTED` otherwise, the report naming the component and
both versions), with the manifest and the records it carries agreeing
(`GDEFCORE_ERR_CORRUPT` otherwise). Then, in AD-23's order:

1. it merges the key set into the key store (its ledger replayed as erasures;
   no key comes back for a subject the live ledger or the set's names);
2. it imports the data set into an empty tenant (the storage import's refusal,
   in words, is the report's reason) and holds back every grant the data gives
   the anonymous or authenticated state (`gdefcore_access_hold_for_confirmation`):
   granting one is what the admin edit asks a typed confirmation for, so a
   restore nobody watches never applies one. Each is rated as the matrix rates
   it and reported in words (`gdefcore_restore_held`); the role gets one new
   revision that holds none. The caller applies one with
   `gdefcore_access_grant` and the same typed confirmation. Grants to other
   roles are restored as they were, except one whose condition names a field
   an enabled module decides per entity (access.md, "A grant that names a
   governed field is suspended"): it would hold nothing and nobody confirmed
   that, so it is taken out of its role and reported in words too, and
   applied only when it is granted again;
3. it runs the forward migrations, `gdefcore_schema_migrate`, the one path a
   live upgrade takes too: every component whose data is at an older version
   than the installed one is brought forward by its steps, dated by the time
   the caller passes. What was written keeps its shape and its stamp and is
   read through the component's upcasters (AD-15); no row is rewritten. A
   step that fails stops the restore, with the tenant at the last version
   reached and under maintenance;
4. it replays the ledger, now the union of the two, over the restored tenant
   and over the subjects' own data store, and purges the bound fragment cache
   of every subject it names;
5. it rebuilds the restored tenant's blind index, which a data set does not
   carry, from the values that can still be decrypted
   (`gdefcore_subject_reindex`: every version the subject lookup names for a
   subject with a key, its row put back with `gdefstor_blind_put`; an erased
   subject has no key and gets no row). The import rebuilt the current tables.

Only then does it return, and the tenant may be served. An erasure newer than
the data set still reads `[erased]`. The report (`GDEFCORE_Restore`) also
gives the edition the data set names, for the operator to pin at the
destination: a restore never touches the installation scope.

A data set records nothing of the ledger; the ledger copy a backup carries is
the key set's. A restore into an empty key store imports the key set into it
first (`gdefstor_keystore_import`), opens the subjects on it (which adopts the
keyring from it), and then restores.

Export, "everything about this person", is one JSON document of the
plaintext values, returned to the caller: every value version the subject
lookup finds for the subject, across types, groups and history (story S7),
published or not, each with its entity, type, field path, language, item, and
the revisions it was written in (`from`) and replaced in (`to`, null for a
current value). A draft holds no version, so its values are listed apart,
under `drafts` (story S8): every value naming the subject in every draft of
the tenant (`gdefstor_draft_list`), a draft that reserves an id included, in
each language it holds, with its entity, type, field path, language, the
draft tree's item id and the revision the draft was made from (`base`). It is
not written into the tenant store. After erasure the document says erased and does not
contain the plaintext.

## The read path (story S7)

A personal value is decrypted only in the application's read path, after the
access filter has allowed its field to the reader (AD-19): a read
(`gdefcore_access_read`), a tree (`gdefcore_access_tree`) and every render
made from one, a revision view (`gdefcore_access_revision_values`) and the
editor's form (`gdefcore_form_tree_for`). Each opens the value with the
subject stored beside it, through `gdefcore_subject_open_value`, and records
the subject on the request. A field the reader may not read is absent and is
never decrypted (`gdefcore_subject_open_count` is the instrument the gate
reads). An erased subject's value reads `[erased]` (a revision view says
`GDEFCORE_REVISION_ERASED`). A catalog with no subjects bound shows no
personal value at all, never its ciphertext. The opening is eager: a tree
read opens every personal value the reader may see, whether or not a
template then prints it, so a render of an entity depends on the subjects of
all of them.

`gdefcore_subject_read` is the system's read, no principal asked, of a field
at any depth (`contacts.note`): the first value of that path in the
published tree that is stored for the subject.

## Revision views

A revision view (`gdefcore_access_revision_values()`, access.md) is an output
too. It never shows the stored ciphertext of a personal field: for a reader
the filter allows it opens the value of that revision (above). With no
subjects bound it answers `GDEFCORE_REVISION_PERSONAL` and no text, and
`gdefcore_subject_revision_marker()` turns that answer into
`GDEFCORE_REVISION_ERASED` and the eight bytes `[erased]` when the ledger
names the person the caller says the value belongs to, so the history of an
erased person says so in the same word a read does. The marker does not
decrypt, and it asks no principal; the permission and the field filter were
the access layer's.

Reverting to an old revision of an erased person
(`gdefcore_changeset_revert_to()`, a new revision that copies it; there is no
activate since access SPEC decision 13) puts its ciphertext in front of readers
and nothing else: the key is gone, so it decrypts to nothing, and a revision
that holds a personal value that is not sealed is refused (entities.md).
`Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject` sweeps every
output for the value, its hashes and the key after both.
