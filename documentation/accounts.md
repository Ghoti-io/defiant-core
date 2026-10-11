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
the expiry. The ciphertext carries the account, the principal and the
security epoch. Each token carries a fresh 256-bit salt and a 12-byte
nonce. Its per-token key is HKDF from the session key with that salt.

The absolute expiry is at most 30 days. Checking a token with a good
tag and the current epoch sets the request principal to the account's
principal and leaves the acting principal unset. A bad tag, a wrong
tenant, a wrong purpose, or an expired token sets no principal and is
an error. A good tag with an older epoch sets no principal and is not
that error. The request stays anonymous.

## Epoch

The epoch starts at 1 and only increases. Password change,
log-out-everywhere, removing a login identifier and removing a role
each increase it. Reverting the account restores the previous password
ciphertext and does not lower the epoch, so the old token stays
anonymous.

Password change and log-out-everywhere are high risk. The confirmation
is the username, one line. A wrong confirmation writes nothing.
