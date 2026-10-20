# Subjects

A subject is not an account. An account is a login. A subject is the
person a personal value is about. Nothing here links one to the other.
Erasure of a subject does not change an account's security epoch, and it
does not touch the password ciphertext.

## Personal and secret

`personal` is a property of the field definition. A personal value is
encrypted with that subject's key. The text stored on the entity is
ciphertext. `gdefcore_entity_values` returns that stored text. It does
not decrypt.

Two routes store one: `gdefcore_subject_save`, and a form signed and
submitted with `gdefcore_form_sign_subject` and
`gdefcore_form_submit_subject`. Every other writer refuses a personal
value (`gdefcore_entity_save`, the plain form route, a parsed patch),
and a revert or publish refuses a personal value that is not sealed. The
entity layer holds no key, so it checks that a value is shaped like a
sealed one (`s1:` and hex), not that it is one. `gdefcore_subject_seal`
and `gdefcore_subject_index` are the two halves of a save for a caller
that has to stage the revision itself, as the form route does.

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
restored. A save, a seal, an index row, a read, an export and a revision view
only read it; the subject tests count the calls at the port.

The blind index is HMAC-SHA-256 of the value under that key. Its rows, and
the places each subject's values are, live in the **blind store**, a data
store the caller passes that is not the tenant store and holds no key, wrap
or ledger row. They move onto the entity port, beside the values, in a later
story. A snapshot or export of the tenant store holds ciphertext, never a key.

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
2. The subject's blind-index rows are deleted from the blind store.
3. Caches are purged. Core keeps no cache of a subject's values or key yet,
   so there is nothing to purge; a cache that holds one purges here.

A failure of step 1 is returned and nothing else runs. Steps 2 and 3 are
idempotent, and every `gdefcore_subject_open` and every restore replays the
ledger through them, so an erasure cut short after step 1 (a crash, a failed
blind store) is finished then. Erasing an erased subject runs them again and
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
  manifest. It holds no key, no keyring wrap and no ledger.
- the **key set**, `gdefcore_subject_keyset`: the key store's export
  (`defiant-keyset/1`): the wrapped subject keys, the keyring's wrap and the
  ledger, with the time it was taken. It is a key backup, kept and retained
  apart from the data set.

Take the key set after the data set it pairs with. `gdefcore_subject_restore`
refuses a pair whose key set is older than its data set with
`GDEFCORE_ERR_STALE` and writes nothing, since such a key set may hold a key
erased between the two. Otherwise it merges the key set into the key store
(its ledger replayed as erasures; no key comes back for a subject the live
ledger or the set's names), imports the data set into an empty tenant, and
replays the ledger, now the union of the two, over the blind store before it
returns. An erasure newer than the data set still reads `[erased]`.

A data set records nothing of the ledger; the ledger copy a backup carries is
the key set's. A restore into an empty key store imports the key set into it
first (`gdefstor_keystore_import`), opens the subjects on it (which adopts the
keyring from it), and then restores.

Export is one JSON document of the plaintext values, returned to the
caller. It is not written into the tenant store. After erasure the
document says erased and does not contain the plaintext.

## Revision views

A revision view (`gdefcore_access_revision_values()`, access.md) is an output
too. It never shows a personal value, whether or not the person is erased: the
answer for a personal field is `GDEFCORE_REVISION_PERSONAL` and no text, and the
stored ciphertext is never returned. `gdefcore_subject_revision_marker()` turns
that answer into `GDEFCORE_REVISION_ERASED` and the eight bytes `[erased]` when
the ledger names the person the caller says the value belongs to, so the history
of an erased person says so in the same word a read does. It does not decrypt, and
it asks no principal; the permission and the field filter were the access
layer's.

Reverting to an old revision of an erased person
(`gdefcore_changeset_revert_to()`, a new revision that copies it; there is no
activate since access SPEC decision 13) puts its ciphertext in front of readers
and nothing else: the key is gone, so it decrypts to nothing, and a revision
that holds a personal value that is not sealed is refused (entities.md).
`Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject` sweeps every
output for the value, its hashes and the key after both.
