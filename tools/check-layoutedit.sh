#!/bin/sh
#
# The layout-edit gate (site admin story 24, core half): a layout is read as its
# regions, placements and Not placed list; each action is one changeset that
# changes one thing; a stale edit, a region the template does not name, a widget
# nobody offers, a setting that is not one, a full layout and a placement that is
# not there are refused with their own sentence and write nothing; an edit that
# changes nothing stages nothing.
#
# Runs the LayoutEdit tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   stale-edit-accepted               LayoutEdit.AnEditOfALayoutThatChangedSinceItWasDrawnIsRefusedAndWritesNothing
#   place-settings-unchecked          LayoutEdit.APlacementThatBreaksARuleIsRefusedWithItsSentenceAndNothingIsWritten
#   place-widget-unchecked            LayoutEdit.APlacementThatBreaksARuleIsRefusedWithItsSentenceAndNothingIsWritten
#   place-fullness-unchecked          LayoutEdit.APlacementThatBreaksARuleIsRefusedWithItsSentenceAndNothingIsWritten
#   position-ignored                  LayoutEdit.PlacingAWidgetIsOneChangesetAtThePositionAsked
#   no-op-edit-staged                 LayoutEdit.AMoveGoesToARegionAndAPositionAndAMoveToWhereItIsStagesNothing
#   configure-changes-the-widget      LayoutEdit.ConfiguringReplacesTheSettingsAndKeepsTheRegionAndTheWidget
#   remove-ignores-the-list           LayoutEdit.APlacementIsRemovedOrSetAsideAndAPlacedEntryComesBack
#   unavailable-widget-placed         LayoutEdit.ANotPlacedEntryWhoseWidgetIsGoneIsKeptAndCannotBePlaced
#
# Every test has a control (the same edit with the version of now, the longest
# layout, the widget that is there), so a plant turning one red is a test seeing
# the defect, not a build failure.
#
# Usage: check-layoutedit.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testLayoutedit 'LayoutEdit.*'

EDIT=src/render/layoutedit.c
T_STALE='LayoutEdit.AnEditOfALayoutThatChangedSinceItWasDrawnIsRefusedAndWritesNothing'
T_REFUSED='LayoutEdit.APlacementThatBreaksARuleIsRefusedWithItsSentenceAndNothingIsWritten'
T_PLACE='LayoutEdit.PlacingAWidgetIsOneChangesetAtThePositionAsked'
T_MOVE='LayoutEdit.AMoveGoesToARegionAndAPositionAndAMoveToWhereItIsStagesNothing'
T_CONFIG='LayoutEdit.ConfiguringReplacesTheSettingsAndKeepsTheRegionAndTheWidget'
T_AWAY='LayoutEdit.APlacementIsRemovedOrSetAsideAndAPlacedEntryComesBack'
T_GHOST='LayoutEdit.ANotPlacedEntryWhoseWidgetIsGoneIsKeptAndCannotBePlaced'

plant_stale stale-object $EDIT testLayoutedit "$T_STALE" \
  '  if (edit->version_len != GDEFCORE_LAYOUT_VERSION_LEN ||
      memcmp(edit->version, view.version, GDEFCORE_LAYOUT_VERSION_LEN) != 0) {' \
  '  if (0 && (edit->version_len != GDEFCORE_LAYOUT_VERSION_LEN ||
      memcmp(edit->version, view.version, GDEFCORE_LAYOUT_VERSION_LEN) != 0)) {'

plant stale-edit-accepted $EDIT testLayoutedit "$T_STALE" \
  '  if (edit->version_len != GDEFCORE_LAYOUT_VERSION_LEN ||
      memcmp(edit->version, view.version, GDEFCORE_LAYOUT_VERSION_LEN) != 0) {' \
  '  if (0 && (edit->version_len != GDEFCORE_LAYOUT_VERSION_LEN ||
      memcmp(edit->version, view.version, GDEFCORE_LAYOUT_VERSION_LEN) != 0)) {'

plant place-settings-unchecked $EDIT testLayoutedit "$T_REFUSED" \
  '    } else if (!placement_ok(&moved, 1)) {' \
  '    } else if (0 && !placement_ok(&moved, 1)) {'

plant place-widget-unchecked $EDIT testLayoutedit "$T_REFUSED" \
  '    } else if (!widget_exists(catalog, moved.widget)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_WIDGET);
    } else if (n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else if (!placement_ok(&moved, 1)) {' \
  '    } else if (0 && !widget_exists(catalog, moved.widget)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_WIDGET);
    } else if (n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else if (!placement_ok(&moved, 1)) {'

plant place-fullness-unchecked $EDIT testLayoutedit "$T_REFUSED" \
  '    } else if (n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else if (!placement_ok(&moved, 1)) {' \
  '    } else if (0 && n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else if (!placement_ok(&moved, 1)) {'

plant position-ignored $EDIT testLayoutedit "$T_PLACE" \
  '      if (seen == position) {' \
  '      if (0 && seen == position) {'

plant no-op-edit-staged $EDIT testLayoutedit "$T_MOVE" \
  '  if (same) {
    goto done;
  }' \
  '  if (0 && same) {
    goto done;
  }'

plant configure-changes-the-widget $EDIT testLayoutedit "$T_CONFIG" \
  '    copy_settings(&moved, &edit->placement);' \
  '    copy_settings(&moved, &edit->placement);
    memcpy(moved.widget, edit->placement.widget, sizeof moved.widget);'

plant remove-ignores-the-list $EDIT testLayoutedit "$T_AWAY" \
  '  case GDEFCORE_LAYOUT_ACT_REMOVE:
    if (edit->from_unplaced) {' \
  '  case GDEFCORE_LAYOUT_ACT_REMOVE:
    if (0 && edit->from_unplaced) {'

plant unavailable-widget-placed $EDIT testLayoutedit "$T_GHOST" \
  '    } else if (!widget_exists(catalog, moved.widget)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_WIDGET);
    } else if (n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else {
      delete_at(unplaced, &un, edit->index);' \
  '    } else if (0 && !widget_exists(catalog, moved.widget)) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_WIDGET);
    } else if (n >= GDEFCORE_LAYOUT_PANES_MAX) {
      out = refuse(changeset, GDEFCORE_LAYOUT_REFUSED_FULL);
    } else {
      delete_at(unplaced, &un, edit->index);'

# ---- structure edits (site admin story 27) -------------------------------------------

SEDIT=src/render/structure.c
CARRY=src/render/layoutedit.c
T_CELLS='LayoutEdit.TheCellsOfARowAreWidenedMovedAndStackedAndARowNeverPassesTwelve'
T_CARRY='LayoutEdit.RenamingACellCarriesEveryLayoutsPlacementsAndRemovingOneSetsThemAside'
T_SSTALE='LayoutEdit.AStaleStructureFormAHandWrittenTemplateAndAMissingPermissionWriteNothing'

# A rename names no pair, so the placements of the old name are set aside.
plant rename-loses-placements $SEDIT testLayoutedit "$T_CARRY" \
  '                rf, rt, renamed ? 1 : 0, moved, moved_len);' \
  '                rf, rt, 0 && renamed, moved, moved_len);'

# A placement in a region that is gone is dropped, not set aside.
plant orphan-dropped $CARRY testLayoutedit "$T_CARRY" \
  "    p.region[0] = '\\0';
    unplaced[un++] = p;" \
  "    p.region[0] = '\\0';
    (void)p;"

# What was set aside is not reported.
plant orphans-not-reported $SEDIT testLayoutedit "$T_CARRY" \
  '                rf, rt, renamed ? 1 : 0, moved, moved_len);' \
  '                rf, rt, renamed ? 1 : 0, NULL, NULL);'

# A form drawn before another change is applied over it.
plant stale-structure-accepted $SEDIT testLayoutedit "$T_SSTALE" \
  '  if (exists && (edit->version == NULL ||
                    !span_eq(edit->version, edit->version_len, version, strlen(version)))) {' \
  '  if (exists && (edit->version == NULL ||
                    (0 && !span_eq(edit->version, edit->version_len, version, strlen(version))))) {'

# A template written by hand is changed by an edit of rows and cells.
plant custom-edited-without-a-new-start $SEDIT testLayoutedit "$T_SSTALE" \
  '  if (is_custom && edit->act != GDEFCORE_STRUCTURE_ACT_START &&' \
  '  if (0 && is_custom && edit->act != GDEFCORE_STRUCTURE_ACT_START &&'

# A row left with no cell stays, so the structure is refused.
plant emptied-row-kept $SEDIT testLayoutedit "$T_CELLS" \
  '        drop_row(doc, r);   /* a row with no cell is no row */' \
  '        if (0) { drop_row(doc, r); }'

plant emptied-row-kept-by-a-move $SEDIT testLayoutedit "$T_CELLS" \
  '      insert_cell_at(&doc->rows[tr], tk, &cell);
      if (doc->rows[r].ncells == 0) {
        drop_row(doc, r);
      }' \
  '      insert_cell_at(&doc->rows[tr], tk, &cell);
      if (0 && doc->rows[r].ncells == 0) {
        drop_row(doc, r);
      }'

# A cell moved to another row keeps the width it had, past what the row has left.
plant moved-cell-overflows-its-new-row $SEDIT testLayoutedit "$T_CELLS" \
  '        if (cell.width < 1 || cell.width > 12 - used) {' \
  '        if (cell.width < 1 || (0 && cell.width > 12 - used)) {'

# A stacked position set on one cell leaves two cells with the same place.
plant stacked-set-without-the-swap $SEDIT testLayoutedit "$T_CELLS" \
  '        if (j != k && row->cells[j].stacked == e->stacked) {' \
  '        if (0 && j != k && row->cells[j].stacked == e->stacked) {'

plant_finish
