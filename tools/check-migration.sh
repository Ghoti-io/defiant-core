#!/bin/sh
#
# The forward-migration gate (storage story S11, AD-15): every write carries
# its component's stored-data schema version, and a restore of older data and
# a live upgrade bring it forward by the same steps. Runs the named tests on
# the real tree, then plants each defect the story names in a COPY of the
# source by an exact text edit and requires the named test to fail
# (defiant-storage's plant-lib.sh):
#
#   migration-skipped-at-import          Migration.ARestoreOfOlderDataRunsEveryStepAndReadsHistoryThroughTheUpcasters
#   revision-upcast-as-the-wrong-version Migration.EveryRevisionKeepsTheVersionItWasWrittenAt
#   step-rewrites-history                Migration.EveryRevisionKeepsTheVersionItWasWrittenAt
#   upgrade-and-restore-diverge          Migration.ALiveUpgradeAndARestoreEndByteIdentical
#   recorded-version-ahead-of-the-data   Migration.ATenantBehindItsModulesAnswersMaintenanceAndRecordsNothing
#
# The tests go into memory and SQLite here; `make test-restore-postgres` runs
# them, unplanted, into Postgres.
#
# Usage: check-migration.sh <make> <build-dir> [make args]

set -u

MAKE="${1:?usage: check-migration.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-migration.sh <make> <build-dir> [make args]}"
shift 2

. tools/plant-load.sh
plant_setup "$MAKE" "$BUILD_DIR" "$@"

plant_control testRestore 'Migration.*'

SUB=src/subject/subject.c
SCH=src/entity/schema.c
MIG=src/entity/migrate.c

# 1. A migration skipped at import: the restore imports the data set and
#    goes on to the ledger with its data where the snapshot left it.
plant migration-skipped-at-import "$SUB" testRestore \
  'Migration.ARestoreOfOlderDataRunsEveryStepAndReadsHistoryThroughTheUpcasters' \
  '  GDEFCORE_Result rc = gdefcore_schema_migrate(host, tenant_store,
      subjects->tenant, subjects->tenant_len, now, &moved, &why, &why_len);' \
  '  GDEFCORE_Result rc = GDEFCORE_OK;
  (void)subjects;
  (void)tenant_store;
  (void)host;
  (void)now;'

# 2. A revision upcast as the wrong version: a tree is read in the shape of
#    the entity's newest revision, not of the revision that wrote it.
plant revision-upcast-as-the-wrong-version "$SCH" testRestore \
  'Migration.EveryRevisionKeepsTheVersionItWasWrittenAt' \
  '    if (revision != 0 && r.revision > revision) {' \
  '    if (0 && revision != 0 && r.revision > revision) {'

# 3. A step that rewrites history: the migration table keeps one row per
#    component, so each later step writes over the record of the one before.
plant step-rewrites-history "$MIG" testRestore \
  'Migration.EveryRevisionKeepsTheVersionItWasWrittenAt' \
  '  kn = snprintf(key, sizeof key, "%s:%010lu", c->name, (unsigned long)from);' \
  '  kn = snprintf(key, sizeof key, "%s", c->name);'

# 4. A live upgrade and a restore that diverge: the restore dates its
#    migration by its own clock, not the one it was handed.
plant upgrade-and-restore-diverge "$SUB" testRestore \
  'Migration.ALiveUpgradeAndARestoreEndByteIdentical' \
  '    rc = forward_migrations(subjects, host, tenant_store, when_ms, report);' \
  '    (void)when_ms;
    rc = forward_migrations(subjects, host, tenant_store, now_ms(), report);'

# 5. A recorded version ahead of the data: a write of a module whose data is
#    behind records the installed version, as a first write does, instead of
#    answering maintenance.
plant recorded-version-ahead-of-the-data "$SCH" testRestore \
  'Migration.ATenantBehindItsModulesAnswersMaintenanceAndRecordsNothing' \
  '  if (!found) {
    /* The component'"'"'s first data here: it is at the version it is written
     * in, recorded in the same write (AD-15). */' \
  '  if (!found || (known && recorded < installed)) {
    /* The component'"'"'s first data here: it is at the version it is written
     * in, recorded in the same write (AD-15). */'

plant_finish
