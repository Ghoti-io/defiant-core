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
# and story S6c's, the blind index on the tenant's entity port (its blind
# table; the S5b "blind store" is gone):
#
#   blind-row-for-an-erased-subject Subject.ABlindRowIsNeverWrittenForAnErasedSubject
#   erased-draft-applied        Subject.ADraftNamingAnErasedSubjectIsRefusedAndKept
#   publish-gives-no-mac        Subject.BlindEqualityFindsOnlyTheNewValueAfterASaveAndADraftApply
#   reindex-skips-history       Subject.AReindexPutsBackEveryRowThatCanBeDecrypted
#   restore-skips-reindex       Subject.ARestoreRebuildsTheBlindIndexOfWhatCanBeDecrypted
#
# (blind-rows-before-the-key above is the story's "blind deletion before the
# key step", now on the port.)
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

plant_control testSubject 'Subject.KeysNeverReachADataStore:Subject.ErasureDestroysTheKeyBeforeTheBlindRows:Subject.ASaveWritesNothingToTheKeyStore:Subject.ARestoreRefusesAnOlderKeySet:Subject.ARestoreReplaysTheLedgerBeforeItReturns:Subject.AnErasureCutShortAfterTheKeyIsFinishedOnTheNextOpen:Subject.ABlindRowIsNeverWrittenForAnErasedSubject:Subject.ADraftNamingAnErasedSubjectIsRefusedAndKept:Subject.BlindEqualityFindsOnlyTheNewValueAfterASaveAndADraftApply:Subject.AReindexPutsBackEveryRowThatCanBeDecrypted:Subject.ARestoreRebuildsTheBlindIndexOfWhatCanBeDecrypted'

# 1. A subject's wrapped key written to a data store: creating a subject also
#    files it in the tenant's data store, as the side store used to hold it.
plant key-in-a-data-store src/subject/subject.c testSubject \
  'Subject.KeysNeverReachADataStore' \
  '  wipe(wrapped, sizeof wrapped);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memcpy(out_id, id, GDEFCORE_PUBLIC_ID_LEN + 1);' \
  '  if (rc == GDEFCORE_OK) {
    GDEFSTOR_Write * kw = NULL;
    if (gdefstor_write_begin(subjects->data, (const char *)subjects->tenant,
            subjects->tenant_len, NULL, &kw) == GDEFSTOR_OK) {
      if (gdefstor_record_put(kw, "core.key", 8, id, GDEFCORE_PUBLIC_ID_LEN,
              GDEFCORE_SCHEMA_CORE_STAMP,
              sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, wrapped, kWrap) ==
          GDEFSTOR_OK) {
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
  '  rc = forget_blinds(subjects, subjects->data, sid);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!erased) {
    rc = from_stor(gdefstor_keystore_erase(subjects->keys,' \
  '  /* 2. Then the blind-index rows, in the data store. */
  rc = forget_blinds(subjects, subjects->data, sid);' \
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
     * anything is served from the restored tenant: in it, and in this
     * subjects'"'"' own data store, whose blind rows an erasure the set'"'"'s ledger
     * names would otherwise keep. */
    rc = replay_ledger(subjects, tenant_store);
    if (rc == GDEFCORE_OK && tenant_store != subjects->data) {
      rc = replay_ledger(subjects, subjects->data);
    }
  }' \
  '  /* the ledger is replayed later */'

# Story S6c ------------------------------------------------------------------

# 6. A blind row written for an erased subject: the apply takes the MAC a note
#    carries from the seal without asking, inside its write, whether the
#    subject was erased since.
plant blind-row-for-an-erased-subject src/entity/store.c testSubject \
  'Subject.ABlindRowIsNeverWrittenForAnErasedSubject' \
  '  if (erased) {
    seals->erased = 1;
    return GDEFCORE_ERR_INVALID;
  }' \
  '  if (0 && erased) {
    seals->erased = 1;
    return GDEFCORE_ERR_INVALID;
  }'

# 7. A draft naming an erased subject applied anyway, its value written with
#    no blind row (the "[erased]" choice the story rejects).
plant erased-draft-applied src/entity/store.c testSubject \
  'Subject.ADraftNamingAnErasedSubjectIsRefusedAndKept' \
  '  if (erased) {
    seals->erased = 1;
    return GDEFCORE_ERR_INVALID;
  }' \
  '  if (erased) {
    return GDEFCORE_OK;
  }'

# 8. A draft applied with no MAC for the values it changes, as the port's
#    draft apply would: a publish leaves blind equality on the old value.
plant publish-gives-no-mac src/entity/store.c testSubject \
  'Subject.BlindEqualityFindsOnlyTheNewValueAfterASaveAndADraftApply' \
  '  rc = gdefcore_ent_map(gdefstor_tree_set(tree, item, at, at_len, v));
  if (rc == GDEFCORE_OK && has_mac) {' \
  '  rc = gdefcore_ent_map(gdefstor_tree_set(tree, item, at, at_len, v));
  if (rc == GDEFCORE_OK && has_mac && seals->notes != NULL) {'

# 9. A rebuild of the current values only: every version but the newest of
#    each value loses its row for good.
plant reindex-skips-history src/subject/subject.c testSubject \
  'Subject.AReindexPutsBackEveryRowThatCanBeDecrypted' \
  '    rc = from_stor(gdefstor_subject_hit(hits, i, &h));
    if (rc != GDEFCORE_OK) {
      break;
    }
    leaf = h.field;' \
  '    rc = from_stor(gdefstor_subject_hit(hits, i, &h));
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (h.valid_to != 0) {
      continue;
    }
    leaf = h.field;'

# 10. A restore that leaves the blind index a data set does not carry unbuilt.
plant restore-skips-reindex src/subject/subject.c testSubject \
  'Subject.ARestoreRebuildsTheBlindIndexOfWhatCanBeDecrypted' \
  '    rc = gdefcore_subject_reindex(subjects, tenant_store, NULL);' \
  '    rc = GDEFCORE_OK;'

plant_finish
