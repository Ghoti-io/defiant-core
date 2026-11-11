#!/bin/sh
#
# The page-structure gate (site admin story 23): a template's structure is a
# document of rows and cells; its source and stylesheet are generated from it, the
# same bytes every time, in one changeset; the regions of the source are exactly
# the cells; a row over 12 columns or a repeated region is refused; and a template
# a person wrote by hand is custom and is never overwritten except by an explicit
# new structure.
#
# Runs the Structures tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   accept-13-columns                     Structures.ADocumentThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   repeated-region-allowed               Structures.ADocumentThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   template-name-unchecked               Structures.ADocumentThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   nondeterministic-output               Structures.TheSameStructureMakesTheSameBytesAndTheCellsAreTheRegions
#   stacked-position-ignored              Structures.TheStackedPositionIsWhereACellGoesWhenTheRowFolds
#   custom-overwritten                    Structures.ACustomTemplateIsNeverOverwrittenExceptByAnExplicitNewStructure
#   source-not-checked-against-structure  Structures.ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom
#   stylesheet-not-checked                Structures.ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom
#   structure-vet-not-called              Structures.ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom
#   generated-file-editable               Structures.ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom
#   generated-file-removable              Structures.ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom
#   custom-keeps-the-stylesheet-locked    Structures.ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom
#   non-page-template-structured          Structures.OnlyAPageTemplateTakesAStructure
#
# Every test has a control (exactly 12 columns, 12 cells, 32 rows, the same
# document made again, a stylesheet that is changed once the template is custom),
# so a plant turning one red is a test seeing the defect, not a build failure.
#
# Usage: check-structure.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testStructure 'Structures.*'

STRUCT=src/render/structure.c
T_DET='Structures.TheSameStructureMakesTheSameBytesAndTheCellsAreTheRegions'
T_RULES='Structures.ADocumentThatBreaksARuleIsRefusedAndTheErrorNamesIt'
T_STACK='Structures.TheStackedPositionIsWhereACellGoesWhenTheRowFolds'
T_HAND='Structures.ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom'
T_CUSTOM='Structures.ACustomTemplateIsNeverOverwrittenExceptByAnExplicitNewStructure'
T_PAGE='Structures.OnlyAPageTemplateTakesAStructure'

plant_stale stale-object $STRUCT testStructure "$T_RULES" \
  '      if (sum > 12) {' \
  '      if (sum > 13) {'

plant accept-13-columns $STRUCT testStructure "$T_RULES" \
  '      if (sum > 12) {' \
  '      if (sum > 13) {'

plant repeated-region-allowed $STRUCT testStructure "$T_RULES" \
  '          if (span_eq(doc->rows[r].cells[k].region, strlen(doc->rows[r].cells[k].region),' \
  '          if (0 && span_eq(doc->rows[r].cells[k].region, strlen(doc->rows[r].cells[k].region),'

plant template-name-unchecked $STRUCT testStructure "$T_RULES" \
  "  if (s == NULL || n == 0 || n > 100 || s[0] < 'a' || s[0] > 'z') {" \
  '  if (s == NULL || n == 0 || n > 100) {'

plant nondeterministic-output $STRUCT testStructure "$T_DET" \
  '  put(src, "</div>\n");' \
  '  { static unsigned n; put(src, "</div><!-- %u -->\n", n++); }'

plant stacked-position-ignored $STRUCT testStructure "$T_STACK" \
  '            row->cells[k].region, row->cells[k].stacked);' \
  '            row->cells[k].region, k + 1);'

plant custom-overwritten $STRUCT testStructure "$T_CUSTOM" \
  '                !replace_custom))) {' \
  '                0))) {'

plant source-not-checked-against-structure $STRUCT testStructure "$T_HAND" \
  '  if (!span_eq(body, body_len, source, source_len)) {' \
  '  if (0 && !span_eq(body, body_len, source, source_len)) {'

plant stylesheet-not-checked $STRUCT testStructure "$T_HAND" \
  '  if (rc != GDEFCORE_OK || !span_eq((const char *)found.bytes, found.bytes_len, css, css_len) ||' \
  '  if (rc != GDEFCORE_OK || 0 ||'

plant structure-vet-not-called src/entity/entity.c testStructure "$T_HAND" \
  '  rc = gdefcore_structure_vet(changeset);' \
  '  rc = GDEFCORE_OK;'

plant generated-file-editable src/render/siteasset.c testStructure "$T_HAND" \
  '  if (rc == GDEFCORE_OK && is_generated(catalog, changeset, id)) {' \
  '  if (0) {'

plant generated-file-removable src/render/siteasset.c testStructure "$T_HAND" \
  '      is_generated(gdefcore_changeset_catalog(changeset), changeset, id)) {' \
  '      0) {'

plant custom-keeps-the-stylesheet-locked $STRUCT testStructure "$T_HAND" \
  "    if (gdefcore_siteasset_generated_by(catalog, changeset, asset, strlen(asset), tag) &&
        tag[0] != '\\0') {" \
  "    if (0 && gdefcore_siteasset_generated_by(catalog, changeset, asset, strlen(asset), tag) &&
        tag[0] != '\\0') {"

plant non-page-template-structured $STRUCT testStructure "$T_PAGE" \
  '        (!span_eq(kind, kind_len, "core.page", 9) ||' \
  '        (0 ||'

plant_finish
