# Accounts

An account owns one login identifier, a username, and a password. The
seeded admin principal is not an account until a username and a password
are set on it. A later account creates a new principal.
`gdefcore_access_admin_principal` still returns the seeded id.

Email, phone, SSO and passkey are not identifiers here. The username is
unique for login. The last one cannot be removed, so removing it is
refused and the security epoch stays where it is.

## Password

A new password is Argon2id, version 0x13, at 19456 KiB, 2 passes and 1
lane. The salt is random and at least 8 bytes. The tag is 32 bytes. The
PHC string records those costs. It is stored as ciphertext under the
tenant `secret` key, never as the PHC string itself. There is no pepper
and no second hash. An old PHC string still verifies, so a later pepper
can be added without refusing what is already stored.

Empty is refused and nothing is stored. Any other password up to 1024
bytes is accepted. Unknown usernames and wrong passwords are the same
error. A missing account still runs the password hash before that error.

## Keyring

The caller passes the root key bytes. This library does not read
`DEFIANT_*` or a key file. A random tenant keyring is wrapped with that
root key and returned to the caller. It is not an entity and not a
field.

HKDF-SHA-256 derives `session` and `secret` from the keyring key. The
purpose label is the info. A key of one root key does not verify
another root key's token.

## Sessions

A session token is AES-256-GCM. The token records that algorithm id.
Associated data binds the tenant, the purpose `session`, the key id and
the expiry. The ciphertext carries the security epoch, the account, the
principal and the session id: 128 random bits from the CSPRNG, drawn at
login, one per token. Each token carries a fresh 256-bit salt and a
12-byte nonce. Its per-token key is HKDF from the session key with that
salt. The session id is inside the encryption, so it cannot be read or
changed without the key, and two logins of one account have two
different ids.

The absolute expiry is at most 30 days. Checking a token with a good
tag, the current epoch and a session that is not revoked sets the
request principal to the account's principal and leaves the acting
principal unset. A bad tag, a wrong tenant, a wrong purpose, or an
expired token sets no principal and is an error. A good tag with an
older epoch, or with a revoked session, sets no principal and is not
that error. The request stays anonymous, and the two cases are not told
apart.

The token layout is not a persisted format: the server never stores a
token, and the library and its callers are rebuilt together, so the
layout changed in place when the session id was added.

## Ending one session

The epoch ends every session of an account. To end one,
`gdefcore_account_session_revoke` puts that session's id on the tenant's
revocation list.

- **What it does.** The token is opened first, as `gdefcore_account_check`
  opens it. A bad tag, a wrong tenant, a wrong purpose, a wrong root key
  or an expired token is an error and nothing is written. So is a request
  for a different tenant than the catalog's. Then the id is recorded with
  the token's absolute expiry. The epoch and every other sign-in are not
  touched. Revoking a session that is already revoked succeeds and
  changes nothing. Revoking a session an older epoch has already ended
  succeeds and writes nothing. The request's own principal is neither
  read nor changed: a request already signed in by this token stays
  signed in until it ends, and the next request with the token is
  anonymous.
- **Where it lives.** The list is two kinds of record in the tenant's own
  storage (not the environment scope), each written with core's schema
  stamp. `core.session.revoked` is keyed by the session id in 32 hex
  digits and holds the expiry as decimal text. `core.session.revoked.exp`
  is keyed by the expiry as 20 zero-padded digits, a dot, and the same
  32 digits, with an empty value: it sorts by expiry, so the oldest is
  first. Both are put in one write, so a crash leaves both or neither.
  Neither names a person, an account or a principal, and the id on its
  own opens nothing: the token's key is not derivable from it.
- **What check costs.** One read of one record by key, after the account
  and the epoch have been read as before. A token with an older epoch
  never reaches it.
- **Fail closed.** If that read fails for any reason (the store is
  unavailable, out of memory, the record is corrupt, the backend does not
  keep records), `gdefcore_account_check` sets no principal and returns
  the storage error. It never returns `GDEFCORE_OK` with a principal on a
  list it could not read. A revoke whose write fails returns the error
  and leaves the session live, so a caller must not tell the person they
  are signed out unless the call returned `GDEFCORE_OK`.
- **Bounded.** A record is useful only until its token expires, because
  check refuses an expired token before it reads the list. Each revoke
  also reads the oldest page of the expiry index (64 entries) and drops,
  in the same write, those whose token expired at least 300 seconds
  ago, with their id records. The 300 seconds cover nodes whose clocks
  differ by less than that, so a purge on a fast clock never lets a
  revoked token live on a slow one. The page is read in order of expiry
  and the read stops at the first entry still inside its expiry plus the
  grace, so the work of one revoke is bounded and each revoke adds one
  entry and can remove up to 64: the list cannot fall behind. A key in
  the index that is not an index key is dropped when it is read. The
  list therefore holds at most the sessions revoked within the last 30
  days (the longest a token lives) plus the grace. It grows with the
  number of sign-outs of that period, each of which costs a login, which
  costs an Argon2 hash; there is no separate cap, because a cap that
  refused a revocation would leave a person unable to sign out.
- **Clocks and maintenance.** Nodes of one tenant must keep their clocks
  within 300 seconds of each other; the grace is a constant and not an
  option, because a value smaller than the real skew would let a revoked
  token live on a slow node. A tenant waiting for a core migration can
  still sign out: the list is written without the entity layer's schema
  check, because a sign-out refused in maintenance would leave a person
  signed in just when the site is least able to say so. A migration that
  changes the shape of these records must carry the existing ones over.
- **Restore.** The list is part of the tenant's data. A snapshot exports
  the tenant's records, and a restore imports them, so a session
  revoked before the backup point is still revoked after a restore, on
  every backend. The converse is the restore contract for a revocation
  made after the backup point: the restore brings the tenant back as it
  was at that point, the revocation is not in it, and the session is live
  again at the destination for the rest of its original expiry, as is a
  session ended by a later epoch change (the epoch goes back too). The
  restore does not know of it. After a restore from an older point, the
  operator ends sessions that should not return with
  `gdefcore_account_logout_everywhere` for the accounts affected, or
  revokes the tokens again. Nothing at the source changes.
  A restore goes into a tenant that holds no data at all: the import
  refuses any tenant with a row of any kind, so one that has already been
  seeded (`gdefcore_admin_seed`) or has run is refused, in words, and
  nothing is written. Restore before the program's first start.
- **Cross node.** The list is in the storage every node reads, so a
  revocation on one node is seen by the next check on any other, as soon
  as the write commits.
- **Log-out-everywhere** is unchanged. It raises the epoch, which ends
  every session of the account, revoked or not.

## Epoch

The epoch starts at 1 and only increases. Password change,
log-out-everywhere, removing a login identifier and removing a role
each increase it. Reverting the account restores the previous password
ciphertext and does not lower the epoch, so the old token stays
anonymous.

A revoked session does not raise the epoch: the epoch is the account's, and
a revocation is one session's.

Password change and log-out-everywhere are high risk. The confirmation
is the username, one line. A wrong confirmation writes nothing.
