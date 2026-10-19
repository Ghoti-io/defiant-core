#!/bin/sh
#
# The key store gate (storage story S5b): subject keys, the keyring's wrap and
# the erasure ledger live in the key store, never a data store; a save never
# writes the key store; erasure destroys the key before it deletes the blind
# rows; a restore refuses a key set older than its data set and replays the
# ledger before it returns. Runs the named tests on the real tree, then plants
# each defect in a COPY of the source by an exact text edit and requires the
# named test to fail (tools/plant-lib.sh):
#
#   key-in-a-data-store         Subject.KeysNeverReachADataStore
#   blind-rows-before-the-key   Subject.ErasureDestroysTheKeyBeforeTheBlindRows
#   save-writes-the-key-store   Subject.ASaveWritesNothingToTheKeyStore
#   restore-takes-older-keys    Subject.ARestoreRefusesAnOlderKeySet
#   restore-serves-before-replay Subject.ARestoreReplaysTheLedgerBeforeItReturns
#
# The plants run against the default key store (memory); `make check-keystores`
# runs the same tests, unplanted, on SQLite, and `make test-keystore-postgres`
# on Postgres.
#
# Usage: check-keystore.sh <make> <build-dir> [make args]

set -u

MAKE="${1:?usage: check-keystore.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-keystore.sh <make> <build-dir> [make args]}"
shift 2

. tools/plant-lib.sh
plant_setup "$MAKE" "$BUILD_DIR" "$@"

plant_control testSubject 'Subject.KeysNeverReachADataStore:Subject.ErasureDestroysTheKeyBeforeTheBlindRows:Subject.ASaveWritesNothingToTheKeyStore:Subject.ARestoreRefusesAnOlderKeySet:Subject.ARestoreReplaysTheLedgerBeforeItReturns:Subject.AnErasureCutShortAfterTheKeyIsFinishedOnTheNextOpen'

# 1. A subject's wrapped key written to a data store: creating a subject also
#    files it in the blind store, as the side store used to hold it.
plant key-in-a-data-store src/subject/subject.c testSubject \
  'Subject.KeysNeverReachADataStore' \
  '  wipe(wrapped, sizeof wrapped);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memcpy(out_id, id, GDEFCORE_PUBLIC_ID_LEN + 1);' \
  '  if (rc == GDEFCORE_OK) {
    GDEFSTOR_Write * kw = NULL;
    GDEFSTOR_Column kc;
    memset(&kc, 0, sizeof kc);
    kc.name = "key";
    kc.name_len = 3;
    kc.value = wrapped;
    kc.value_len = kWrap;
    if (gdefstor_write_begin(subjects->side, (const char *)subjects->tenant,
            subjects->tenant_len, NULL, &kw) == GDEFSTOR_OK) {
      if (gdefstor_projection_put(kw, "core.key", 8, id,
              GDEFCORE_PUBLIC_ID_LEN, &kc, 1) == GDEFSTOR_OK) {
        (void)gdefstor_write_commit(kw);
      } else {
        gdefstor_write_abort(kw);
      }
    }
  }
  wipe(wrapped, sizeof wrapped);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memcpy(out_id, id, GDEFCORE_PUBLIC_ID_LEN + 1);'

# 2. Erasure deleting the blind rows before the key store destroys the key.
plant blind-rows-before-the-key src/subject/subject.c testSubject \
  'Subject.ErasureDestroysTheKeyBeforeTheBlindRows' \
  '  if (!erased) {
    rc = from_stor(gdefstor_keystore_erase(subjects->keys,' \
  '  rc = forget_blinds(subjects, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!erased) {
    rc = from_stor(gdefstor_keystore_erase(subjects->keys,' \
  '  /* 2. Then the blind-index rows, in the blind store. */
  rc = forget_blinds(subjects, sid);' \
  '  /* 2. (moved ahead of the key) */'

# 3. A save that writes the key store: sealing a value files the keyring's
#    wrap again (the same bytes, so nothing reads differently).
plant save-writes-the-key-store src/subject/subject.c testSubject \
  'Subject.ASaveWritesNothingToTheKeyStore' \
  '  rc = encrypt_value(subjects, sid, field, field_len, plain, plain_len, &sealed,
      &sealed_len);' \
  '  {
    uint8_t again[kWrap];
    if (gdefcore_keyring_export(subjects->keyring, again, kWrap) ==
        GDEFCORE_OK) {
      (void)wrap_store(subjects->keys, subjects->tenant, subjects->tenant_len,
          again);
    }
    wipe(again, sizeof again);
  }
  rc = encrypt_value(subjects, sid, field, field_len, plain, plain_len, &sealed,
      &sealed_len);'

# 4. A restore that takes a key set older than its data set.
plant restore-takes-older-keys src/subject/subject.c testSubject \
  'Subject.ARestoreRefusesAnOlderKeySet' \
  '  if (keys_taken < data_taken) {
    return GDEFCORE_ERR_STALE;
  }' \
  '  if (0 && keys_taken < data_taken) {
    return GDEFCORE_ERR_STALE;
  }'

# 5. A restore that returns, and so serves, before the ledger is replayed.
plant restore-serves-before-replay src/subject/subject.c testSubject \
  'Subject.ARestoreReplaysTheLedgerBeforeItReturns' \
  '  if (rc == GDEFCORE_OK) {
    /* Then the ledger, the live one and the set'"'"'s together now, before
     * anything is served from the restored tenant. */
    rc = replay_ledger(subjects);
  }' \
  '  /* the ledger is replayed later */'

plant_finish
