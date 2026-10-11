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

A `secret` field is different. The password hash stays a secret under
the tenant `secret` key. Subject erasure does not unwrap it, replace it,
or bump the epoch that retires session tokens.

A field declared before `personal` existed is not personal. Callers that
set `size` and stop before that member keep compiling, and the missing
member is read as not personal.

## Where the key lives

The caller passes a side store, the same shape as the installation
registry, and it is not the tenant store. The first open copies the
tenant keyring's wrapped bytes into that side store. A later open adopts
those bytes instead of drawing a new key. The raw keyring key is not
written there.

Creating a subject returns a public id and draws 32 random bytes. Those
bytes are wrapped with AES-256-GCM under the tenant keyring's
`subject-wrap` purpose. The wrap and the blind index live in the side
store. A snapshot or export of the tenant store holds ciphertext, never
a key.

The blind index is HMAC-SHA-256 of the value under the HKDF info
`blind-index:<field>`. The row is the mac. It is not the plaintext.

## Erasure

Erasure has no undo. The confirmation is the subject's public id, one
line. A wrong id writes nothing.

A matching id destroys the subject key, appends one ledger row, and
deletes that subject's blind-index rows. The ledger row is the public id
and the time, and nothing else. Revisions stay, so the stored ciphertext
stays. A later read returns the eight bytes `[erased]`.

The ledger is append-only in the side store. A snapshot of the tenant
carries a copy of it and does not carry a key. The copy rides in the zip
as the member `ledger`. It is not one of the storage prefixes. Import
into an empty tenant replays the union of the live ledger and that copy
before any read, so an erasure newer than the snapshot still reads as
erased.

Export is one JSON document of the plaintext values, returned to the
caller. It is not written into the tenant store. After erasure the
document says erased and does not contain the plaintext.
