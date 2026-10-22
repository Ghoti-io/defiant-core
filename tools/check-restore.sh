#!/bin/sh
#
# The restore gate (storage story S8): a backup pair restored through core,
# end to end, as AD-23 and AD-37 say. Runs the named tests on the real tree,
# then plants each defect the story names in a COPY of the source by an exact
# text edit and requires the named test to fail (defiant-storage's plant-lib.sh):
#
#   import-without-rebuild         Restore.ATenantTakenOnMemoryComesBackThroughCoreOnEveryBackend
#   restore-returns-before-replay  Restore.EveryStepRunsInOrderBeforeTheRestoreReturns
#   restored-grant-applied-unrated Restore.ARestoredGrantToAStateIsHeldForItsTypedConfirmation
#   newer-module-schema-imported   Restore.ADataSetNewerThanAModuleHereIsRefusedNamingItsVersions
#   draft-missing-from-the-export  Personal.EverythingAboutThisPersonListsEveryDraftsValues
#
# The restore tests go into memory and SQLite here; `make
# test-restore-postgres` runs them, unplanted, into Postgres. S5b's
# restore-serves-before-replay and S6c's restore-skips-reindex
# (check-keystore.sh) stay where they are: they take the replay and the
# rebuild out, and these take the restore's return, and the rebuild's store,
# somewhere else.
#
# Usage: check-restore.sh <make> <build-dir> [make args]

set -u

MAKE="${1:?usage: check-restore.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-restore.sh <make> <build-dir> [make args]}"
shift 2

. tools/plant-load.sh
plant_setup "$MAKE" "$BUILD_DIR" "$@"

plant_control testRestore 'Restore.*'
plant_control testPersonal 'Personal.EverythingAboutThisPersonListsEveryDraftsValues'

SUB=src/subject/subject.c

# 1. An import without its rebuild: the derived data is rebuilt, but in the
#    live data store and not in the tenant the data set went into, which so
#    serves with no blind index.
plant import-without-rebuild "$SUB" testRestore \
  'Restore.ATenantTakenOnMemoryComesBackThroughCoreOnEveryBackend' \
  '    rc = gdefcore_subject_reindex(subjects, tenant_store, NULL);' \
  '    rc = gdefcore_subject_reindex(subjects, subjects->data, NULL);'

# 2. A restore that serves before the replay: it returns once the data set is
#    in and the modules are migrated, before the merged ledger is replayed
#    and the derived data rebuilt.
plant restore-returns-before-replay "$SUB" testRestore \
  'Restore.EveryStepRunsInOrderBeforeTheRestoreReturns' \
  '    rc = forward_migrations(subjects, host, tenant_store, when_ms, report);
  }' \
  '    rc = forward_migrations(subjects, host, tenant_store, when_ms, report);
  }
  if (rc == GDEFCORE_OK) {
    goto done; /* served from here */
  }'

# 3. An imported grant applied without its rating: the import takes the
#    snapshot's role entities as they are, a grant to anonymous included.
plant restored-grant-applied-unrated "$SUB" testRestore \
  'Restore.ARestoredGrantToAStateIsHeldForItsTypedConfirmation' \
  '    rc = gdefcore_access_hold_for_confirmation(catalog, on_held, report);' \
  '    rc = GDEFCORE_OK;'

# 4. A module schema newer than the destination's imported: the version is
#    no longer compared, only whether the module is installed.
plant newer-module-schema-imported "$SUB" testRestore \
  'Restore.ADataSetNewerThanAModuleHereIsRefusedNamingItsVersions' \
  '    if (m.schema > here) {' \
  '    if (0 && m.schema > here) {'

# 5. A draft missing from "everything about this person": the export lists
#    the revision tables' values and an empty list of drafts.
plant draft-missing-from-the-export "$SUB" testPersonal \
  'Personal.EverythingAboutThisPersonListsEveryDraftsValues' \
  '    rc = export_drafts(subjects, catalog, sid, raw, &buf);' \
  '    buf_add(&buf, ",\"drafts\":[]", 12);'

plant_finish
