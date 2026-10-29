#!/bin/sh
#
# The settings gate (site admin story 8): a setting that equals its default
# stores nothing; a form is saved all or nothing, against the version it was
# drawn at, by whoever holds the one permission for the group; an
# environment-local value is never in the tenant's rows, is not in the
# configuration export, and is not written by an import; a secret is never
# echoed back; and one tenant's settings never reach another's.
#
# Runs the Settings and Moves tests on the real tree, then plants each defect in
# a COPY of the source by an exact text edit and requires the named test to
# fail:
#
#   stale-object                          the first plant, rebuilt: shows a plant is built
#   unchanged-stored                      Settings.SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs
#   stored-value-rewritten                Settings.SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs
#   empty-save-applies                    Settings.SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs
#   bounds-unchecked                      Settings.ANumberOutsideItsBoundsOrOfTheWrongTypeIsRefusedAndNothingIsWritten
#   stale-form-saved                      Settings.AFormThatWasDrawnBeforeAnotherSaveIsStaleAndWritesNothing
#   vet-not-called                        Settings.ApplyRefusesASettingNobodyDeclaresALocalValueAsAnEntityAndABadValue
#   authorize-not-called                  Settings.ApplyAsksThePermissionOfAChangesetThatCarriesARequestAndNotOfTheOperators
#   group-not-in-the-decision             Settings.OnePermissionWithAConditionOnTheGroupEditsThatGroupAndNotAnother
#   local-written-before-authorization    Settings.ARefusedSaveLeavesTheLocalValueAsItWas
#   local-value-stored-as-entity          Settings.ALocalValueIsNeverInTheTenantsTruthAndItsMarkerHoldsNoValue
#   secret-echoed-in-the-form             Settings.TheFormShowsASecretAsSetOrNotSetAndNeverItsValue
#   local-key-ignores-the-tenant          Settings.TwoTenantsSettingsNeverMix
#   export-carries-local                  Moves.TheExportCarriesTheChangedSettingsAndNoLocalOne
#   import-overwrites-local                Moves.ImportAppliesTheChangedSettingsAndBKeepsItsOwnLocalValue, Moves.AnImportThatCarriesALocalValueDropsItAndLeavesBsAbsentOneAbsent
#   title-not-fresh                       Settings.AChangedTitleShowsOnTheNextRequestAndMovesTheRenderKey
#
# Every test has a control (the role that holds the permission DOES save, the
# value at the bound IS accepted, the other tenant DOES keep its own), so a
# plant turning one red is a test seeing the defect, not a build failure.
#
# Usage: check-settings.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testSettings 'Settings.*:Moves.*'

SET=src/settings/settings.c

UNCHANGED_OLD='  if (value_same(s, value, value_len, s->default_value, s->default_len)) {
    /* The default is stored as nothing. */'
UNCHANGED_NEW='  if (0) {
    /* The default is stored as nothing. */'

plant_stale stale-object $SET testSettings \
  'Settings.SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs' \
  "$UNCHANGED_OLD" "$UNCHANGED_NEW"

# Plant 1: a value equal to the default is stored all the same.
plant unchanged-stored $SET testSettings \
  'Settings.SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs' \
  "$UNCHANGED_OLD" "$UNCHANGED_NEW"

# Plant 2: the value that is stored is written again.
plant stored-value-rewritten $SET testSettings \
  'Settings.SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs' \
  '    if (rc == GDEFCORE_OK && existed && present &&
        value_same(s, cur, cur_len, value, value_len)) {' \
  '    if (rc == GDEFCORE_OK && existed && present && 0 &&
        value_same(s, cur, cur_len, value, value_len)) {'

# Plant 3: a save that changes nothing still applies a changeset.
plant empty-save-applies $SET testSettings \
  'Settings.SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs' \
  '  if (rc == GDEFCORE_OK && written == 0) {' \
  '  if (rc == GDEFCORE_OK && written == 0 && 0) {'

# Plant 4: a number is not held to its declared bounds.
plant bounds-unchecked $SET testSettings \
  'Settings.ANumberOutsideItsBoundsOrOfTheWrongTypeIsRefusedAndNothingIsWritten' \
  '    } else if (minimum_len > 0 &&' \
  '    } else if (0 && minimum_len > 0 &&' \
  '    } else if (maximum_len > 0 &&' \
  '    } else if (0 && maximum_len > 0 &&'

# Plant 5: a form drawn before another save is saved all the same.
plant stale-form-saved $SET testSettings \
  'Settings.AFormThatWasDrawnBeforeAnotherSaveIsStaleAndWritesNothing' \
  '    if (strcmp(now, expected_version) != 0) {' \
  '    if (0) {'

# Plant 6: apply does not vet what a changeset writes to a setting.
plant vet-not-called src/entity/entity.c testSettings \
  'Settings.ApplyRefusesASettingNobodyDeclaresALocalValueAsAnEntityAndABadValue' \
  '  rc = gdefcore_settings_vet(changeset);' \
  '  rc = GDEFCORE_OK;'

# Plant 7: apply does not ask who may change a setting.
plant authorize-not-called src/entity/entity.c testSettings \
  'Settings.ApplyAsksThePermissionOfAChangesetThatCarriesARequestAndNotOfTheOperators' \
  '    rc = gdefcore_settings_authorize(changeset, changeset->request);' \
  '    rc = GDEFCORE_OK;'

# Plant 8: the group of a setting is not part of the question, so a grant that
# names a group never holds.
plant group-not-in-the-decision $SET testSettings \
  'Settings.OnePermissionWithAConditionOnTheGroupEditsThatGroupAndNotAnother' \
  '      kShapeFields, &ok);' \
  '      1, &ok);'

# Plant 9: a local value is written before anyone has asked whether it may be,
# and is not put back when apply refuses.
plant local-written-before-authorization $SET testSettings \
  'Settings.ARefusedSaveLeavesTheLocalValueAsItWas' \
  '    rc = gdefcore_settings_authorize(cs, request);
  }' \
  '    rc = GDEFCORE_OK;
  }' \
  '      if (pending[k].done) {' \
  '      if (0) {'

# Plant 10: a local value is written into the entity port, with the marker.
plant local-value-stored-as-entity $SET testSettings \
  'Settings.ALocalValueIsNeverInTheTenantsTruthAndItsMarkerHoldsNoValue' \
  '      rc = save_entity(cs, id, s, NULL, 0, serial, strlen(serial));' \
  '      rc = save_entity(cs, id, s, value, value_len, serial, strlen(serial));'

# Plant 11: a secret's value is put back in the field it came from.
plant secret-echoed-in-the-form $SET testSettings \
  'Settings.TheFormShowsASecretAsSetOrNotSetAndNeverItsValue' \
  '    buf_str(b, "\" value=\"\"");
    buf_str(b, dis);
    buf_str(b, "> <span class=\"state\">");' \
  '    buf_str(b, "\" value=\"");
    buf_esc(b, v, vn);
    buf_str(b, "\"");
    buf_str(b, dis);
    buf_str(b, "> <span class=\"state\">");'

# Plant 12: the environment key is made of the setting's name alone.
plant local-key-ignores-the-tenant $SET testSettings \
  'Settings.TwoTenantsSettingsNeverMix' \
  '  for (i = 0; i < tn; i++) {
    key[at++] = hex[tenant[i] >> 4];' \
  '  for (i = 0; i < tn && tn == 0; i++) {
    key[at++] = hex[tenant[i] >> 4];'

# Plant 13: the export carries a local setting.
plant export-carries-local $SET testSettings \
  'Moves.TheExportCarriesTheChangedSettingsAndNoLocalOne' \
  '    if (s == NULL || s->local) {
      continue;
    }' \
  '    if (s == NULL) {
      continue;
    }' \
  '    if (rc == GDEFCORE_OK && present) {
      rc = save_entity(cs, st[i].id, s, value, vn, NULL, 0);' \
  '    if (rc == GDEFCORE_OK && (present || s->local)) {
      rc = save_entity(cs, st[i].id, s, value, vn, NULL, 0);'

# Plant 14: the import takes a local setting as it takes any other.
plant import-overwrites-local $SET testSettings \
  'Moves.AnImportThatCarriesALocalValueDropsItAndLeavesBsAbsentOneAbsent' \
  '      } else if (s->local) {' \
  '      } else if (0) {'

# Plant 15: the site name is kept from the first time it was drawn.
plant title-not-fresh src/render/render.c testSettings \
  'Settings.AChangedTitleShowsOnTheNextRequestAndMovesTheRenderKey' \
  '  bind[0].text = name == NULL ? "" : name;
  bind[0].len = name_len;' \
  '  static char memo[256];
  static size_t memo_len;
  if (memo_len == 0 && name_len > 0 && name_len < sizeof memo) {
    memcpy(memo, name, name_len);
    memo_len = name_len;
  }
  bind[0].text = memo_len > 0 ? memo : (name == NULL ? "" : name);
  bind[0].len = memo_len > 0 ? memo_len : name_len;'

plant_finish
