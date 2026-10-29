#!/bin/sh
#
# The menu editing gate (site admin story 10): an edit of the menus is one
# changeset; a generated entry changes by an override keyed by its machine name
# and never by a copy; a stale edit, a move into the entry's own subtree and a
# move under an entry that is not there are refused with nothing written; a
# hidden entry stays hidden through an edit of it; and the last edit is undone in
# one changeset, never over a later write.
#
# Runs the MenuEdit tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   stale-object                       MenuEdit.AFormBasedOnAnOlderVersionOfTheMenuIsRefusedAndNothingIsWritten
#   stale-form-accepted                MenuEdit.AFormBasedOnAnOlderVersionOfTheMenuIsRefusedAndNothingIsWritten
#   version-ignores-labels             MenuEdit.TheVersionIsSixteenLettersAndMovesWithWhatAnEditDependsOn
#   cycle-accepted                     MenuEdit.AMoveUnderItsOwnSubtreeOrUnderNothingIsRefusedAndNothingIsWritten
#   missing-parent-accepted            MenuEdit.AMoveUnderItsOwnSubtreeOrUnderNothingIsRefusedAndNothingIsWritten
#   tab-moves                          MenuEdit.AMoveUnderItsOwnSubtreeOrUnderNothingIsRefusedAndNothingIsWritten
#   too-deep-accepted                  MenuEdit.AnEntryTooDeepToBeShownIsRefused
#   override-stored-as-a-copy          MenuEdit.RenamingAGeneratedEntryWritesOneOverrideByMachineNameAndNeverACopy
#   half-applied-move                  MenuEdit.MovingBetweenTiedEntriesNumbersEverySiblingInOneChangesetOrNone
#   move-renumbers-nothing             MenuEdit.MovingBetweenTiedEntriesNumbersEverySiblingInOneChangesetOrNone
#   keys-move-differently-from-a-drag  MenuEdit.TheKeysMakeTheSameMovesADragMakes
#   generated-entry-removed            MenuEdit.OnlyASiteEntryIsRemovedAndAGeneratedOneIsHiddenInstead
#   hide-forgets-on-an-entry-save      MenuEdit.HidingHidesFromEveryOutputAndShowingBringsItBack
#   edit-staged-without-permission     MenuEdit.WhoMayNotEditMenusIsRefusedBeforeAnythingIsStagedAndAfterwardsNothingIsWritten
#   apply-does-not-ask-who-may         MenuEdit.MovingBetweenTiedEntriesNumbersEverySiblingInOneChangesetOrNone
#   undo-does-not-restore              MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset
#   undo-overwrites-a-later-edit       MenuEdit.UndoIsRefusedWhenAnythingTheEditWroteHasBeenWrittenSince
#   undo-clears-nothing-it-made        MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset
#   edit-not-recorded                  MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset
#   record-not-staged                  MenuEdit.AWriteStagedByHandIsUndoneWhenItsChangesetIsRecorded
#   undo-staged-without-permission     MenuEdit.UndoIsDecidedAgainAtApplyForWhoAsksIt
#   undo-twice                         MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset
#
# Every test has a control (the current version IS accepted, the move that is no
# cycle IS made, the role that holds the grant DOES write), so a plant turning
# one red is a test seeing the defect, not a build failure.
#
# Usage: check-menuedit.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testMenuedit 'MenuEdit.*'

plant_stale stale-object src/menu/menu.c testMenuedit \
  'MenuEdit.AFormBasedOnAnOlderVersionOfTheMenuIsRefusedAndNothingIsWritten' \
  '  if (rc == GDEFCORE_OK &&
      !span_eq(version, strlen(version), edit->version, edit->version_len)) {
    rc = refuse(changeset, GDEFCORE_MENU_REFUSED_STALE);
  }' \
  '  if (rc == GDEFCORE_OK &&
      !span_eq(version, strlen(version), edit->version, edit->version_len) &&
      0) {
    rc = refuse(changeset, GDEFCORE_MENU_REFUSED_STALE);
  }'

plant stale-form-accepted src/menu/menu.c testMenuedit \
  'MenuEdit.AFormBasedOnAnOlderVersionOfTheMenuIsRefusedAndNothingIsWritten' \
  '  if (rc == GDEFCORE_OK &&
      !span_eq(version, strlen(version), edit->version, edit->version_len)) {
    rc = refuse(changeset, GDEFCORE_MENU_REFUSED_STALE);
  }' \
  '  if (rc == GDEFCORE_OK &&
      !span_eq(version, strlen(version), edit->version, edit->version_len) &&
      0) {
    rc = refuse(changeset, GDEFCORE_MENU_REFUSED_STALE);
  }'

plant version-ignores-labels src/menu/menu.c testMenuedit \
  'MenuEdit.TheVersionIsSixteenLettersAndMovesWithWhatAnEditDependsOn' \
  '    h = fnv_field(h, it->label, it->label_len);
' \
  '    (void)it->label_len;
'

plant cycle-accepted src/menu/menu.c testMenuedit \
  'MenuEdit.AMoveUnderItsOwnSubtreeOrUnderNothingIsRefusedAndNothingIsWritten' \
  '    if (a == m) {
      return refuse(cs, GDEFCORE_MENU_REFUSED_CYCLE);' \
  '    if (a == m && 0) {
      return refuse(cs, GDEFCORE_MENU_REFUSED_CYCLE);'

plant missing-parent-accepted src/menu/menu.c testMenuedit \
  'MenuEdit.AMoveUnderItsOwnSubtreeOrUnderNothingIsRefusedAndNothingIsWritten' \
  '            rc = refuse(changeset, GDEFCORE_MENU_REFUSED_PARENT);
            break;' \
  '            (void)0;'

plant tab-moves src/menu/menu.c testMenuedit \
  'MenuEdit.AMoveUnderItsOwnSubtreeOrUnderNothingIsRefusedAndNothingIsWritten' \
  '      if (c.nodes[m].source == GDEFCORE_MENU_SOURCE_TAB) {' \
  '      if (c.nodes[m].source == GDEFCORE_MENU_SOURCE_TAB && 0) {'

plant too-deep-accepted src/menu/menu.c testMenuedit \
  'MenuEdit.AnEntryTooDeepToBeShownIsRefused' \
  '  if (depth > GDEFCORE_MENU_DEPTH_MAX) {
    return refuse(cs, GDEFCORE_MENU_REFUSED_PLACE);' \
  '  if (depth > GDEFCORE_MENU_DEPTH_MAX && 0) {
    return refuse(cs, GDEFCORE_MENU_REFUSED_PLACE);'

plant override-stored-as-a-copy src/menu/menu.c testMenuedit \
  'MenuEdit.RenamingAGeneratedEntryWritesOneOverrideByMachineNameAndNeverACopy' \
  '  o.hidden = -1;
  if (ov != NULL) {
    if (ov->has_label) {' \
  '  o.hidden = -1;
  o.label = nd->label.p;
  o.label_len = nd->label.n;
  o.has_weight = 1;
  o.weight = nd->weight;
  if (ov != NULL) {
    if (ov->has_label) {'

plant half-applied-move src/menu/menu.c testMenuedit \
  'MenuEdit.MovingBetweenTiedEntriesNumbersEverySiblingInOneChangesetOrNone' \
  '  for (k = 0; rc == GDEFCORE_OK && k < nplan; k++) {
    Change ch;' \
  '  for (k = 0; rc == GDEFCORE_OK && k + 1 < nplan; k++) {
    Change ch;'

plant move-renumbers-nothing src/menu/menu.c testMenuedit \
  'MenuEdit.MovingBetweenTiedEntriesNumbersEverySiblingInOneChangesetOrNone' \
  '      } else if (w != c->nodes[node].weight) {' \
  '      } else if (w != c->nodes[node].weight && 0) {'

plant keys-move-differently-from-a-drag src/menu/menu.c testMenuedit \
  'MenuEdit.TheKeysMakeTheSameMovesADragMakes' \
  '        pos = at - 1;
      } else if (edit->action == GDEFCORE_MENU_ACT_DOWN) {' \
  '        pos = at;
      } else if (edit->action == GDEFCORE_MENU_ACT_DOWN) {'

plant generated-entry-removed src/menu/menu.c testMenuedit \
  'MenuEdit.OnlyASiteEntryIsRemovedAndAGeneratedOneIsHiddenInstead' \
  '      if (c.nodes[m].source != GDEFCORE_MENU_SOURCE_SITE) {
        rc = refuse(changeset, GDEFCORE_MENU_REFUSED_REMOVE);' \
  '      if (c.nodes[m].source != GDEFCORE_MENU_SOURCE_SITE && 0) {
        rc = refuse(changeset, GDEFCORE_MENU_REFUSED_REMOVE);'

plant hide-forgets-on-an-entry-save src/menu/menu.c testMenuedit \
  'MenuEdit.HidingHidesFromEveryOutputAndShowingBringsItBack' \
  '    hidden = n > 0 && lens[0] == 1 && texts[0][0] == '"'"'1'"'"';' \
  '    hidden = n > 0 && lens[0] == 1 && texts[0][0] == '"'"'1'"'"' && 0;'

plant edit-staged-without-permission src/menu/menu.c testMenuedit \
  'MenuEdit.WhoMayNotEditMenusIsRefusedBeforeAnythingIsStagedAndAfterwardsNothingIsWritten' \
  '  if (!gdefcore_menu_may_edit(catalog, request)) {
    return refuse(changeset, kNotAllowed);
  }
  rc = ctx_open(&c, catalog, routes, request, match);' \
  '  if (!gdefcore_menu_may_edit(catalog, request) && 0) {
    return refuse(changeset, kNotAllowed);
  }
  rc = ctx_open(&c, catalog, routes, request, match);'

plant apply-does-not-ask-who-may src/entity/entity.c testMenuedit \
  'MenuEdit.MovingBetweenTiedEntriesNumbersEverySiblingInOneChangesetOrNone MenuEdit.UndoIsDecidedAgainAtApplyForWhoAsksIt' \
  '    rc = gdefcore_menu_authorize(changeset, changeset->request);' \
  '    rc = GDEFCORE_OK;'

plant undo-does-not-restore src/menu/menu.c testMenuedit \
  'MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset' \
  '      rc = restore_revision(changeset, id, is_entry[k], base[k]);' \
  '      rc = GDEFCORE_OK;'

plant undo-overwrites-a-later-edit src/menu/menu.c testMenuedit \
  'MenuEdit.UndoIsRefusedWhenAnythingTheEditWroteHasBeenWrittenSince' \
  '    } else if (has && seq == base[k] + 1) {' \
  '    } else if (has) {'

plant undo-clears-nothing-it-made src/menu/menu.c testMenuedit \
  'MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset' \
  '      act[k] = base[k] == 0 ? kUndoClear : kUndoRestore;' \
  '      act[k] = base[k] == 0 ? kUndoSkip : kUndoRestore;'

plant edit-not-recorded src/menu/menu.c testMenuedit \
  'MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset' \
  '    rc = record_writes(changeset);
  }
  free(ord);' \
  '    rc = GDEFCORE_OK;
  }
  free(ord);'

plant record-not-staged src/menu/menu.c testMenuedit \
  'MenuEdit.AWriteStagedByHandIsUndoneWhenItsChangesetIsRecorded' \
  '  return record_writes(changeset);
}' \
  '  return GDEFCORE_OK;
}'

plant undo-staged-without-permission src/menu/menu.c testMenuedit \
  'MenuEdit.UndoIsDecidedAgainAtApplyForWhoAsksIt' \
  '  if (!gdefcore_menu_may_edit(catalog, request)) {
    return refuse(changeset, kNotAllowed);
  }
  rc = find_named(catalog, kChangeType, "last", 4, journal);' \
  '  if (!gdefcore_menu_may_edit(catalog, request) && 0) {
    return refuse(changeset, kNotAllowed);
  }
  rc = find_named(catalog, kChangeType, "last", 4, journal);'

plant undo-twice src/menu/menu.c testMenuedit \
  'MenuEdit.UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset' \
  '  if (rc == GDEFCORE_OK) {
    rc = journal_save(changeset, NULL, NULL, 0);
  }' \
  '  (void)journal_save;'

plant_finish
