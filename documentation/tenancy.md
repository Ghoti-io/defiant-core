# Tenancy

An installation is not a site tenant, and it is not the module host's
private tenant `0x01`. It is a catalog on the registry store the caller
passes. That catalog's tenant is the single byte `0x02`. Site data stays
on the other store, the one the caller opened for tenants.

The first open of an empty installation creates one default tenant. The
next open returns that same tenant and does not create another. A second
tenant gets its own storage key, its own keyring and its own catalog.
Creating it leaves the first tenant's storage key, keyring and saved
entities as they were.

## Storage key

A tenant's storage key is 16 random bytes. Its public id is those bytes
encoded with `gdefcore_id_encode`. Two tenants do not share a storage
key. Opening the tenant's catalog is `gdefcore_catalog_open` on the site
store with that key.

Placement is a directory string recorded on the tenant. This does not
create a SQLite file. The SQLite backend already turns a tenant into
`<directory>/<hex>.db`.

A tenant with no limit override reports the storage defaults. An override
is one `GDEFSTOR_Limits` field the directory returns. The store the caller
opened stays the enforcer.

## Directory

One resolution key answers with one tenant's public id, placement,
edition and status. There is no list. An unknown key and a malformed key
are the same error, and neither answer names another tenant. Edition and
status are stored strings. The default status is `active`. The default
edition is empty.

## Root key

The root is 32 bytes, the length `gdefcore_keyring_create` already takes.
Each tenant keyring, and the installation's own keyring, is wrapped with
that root. A keyring wrapped for one root does not open under another.
The wrap stays in the account subsystem. The keyring is not stored.

`DEFIANT_SECRET` is 64 hex characters. `DEFIANT_SECRET_FILE` is a file of
exactly those 32 bytes. When both are set, the environment wins and the
file is not read. After a successful read, the environment value is
overwritten in place and unset.

## Bootstrap

The only settings read outside the database are `DEFIANT_ROLES`,
`DEFIANT_STORE`, `DEFIANT_LISTEN`, `DEFIANT_TRUSTED_PROXIES`,
`DEFIANT_SECRET` and `DEFIANT_SECRET_FILE`. `DEFIANT_CONFIG` is an
optional TOML file. Its keys are the same names without the `DEFIANT_`
prefix. The environment wins over the file. A missing setting is the
default.

`DEFIANT_LISTEN` is recorded and reported. Nothing here binds a socket.

The effective configuration is one line per setting,
`name=value source=env|file|default`. The secret line names its source
and does not contain the key bytes. `examples/effective-config` prints
those lines, and `make install` copies it into the prefix.
