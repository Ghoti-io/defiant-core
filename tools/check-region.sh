#!/bin/sh
#
# The region-descriptor gate (site admin story 22): what an editor calls a region
# comes from the template's own list, then the shared catalog, then the name made
# readable; a site starts with five shared descriptors and keeps its own; a
# descriptor that is not one is refused; shared descriptors are written on their
# own permission; and a layout's Not placed list is only data, checked for its
# shape.
#
# Runs the Regions tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   template-descriptor-ignored         Regions.ATemplatesOwnDescriptorBeatsASharedOneWhichBeatsTheName
#   shared-descriptor-ignored           Regions.ANewSiteStartsWithTheFiveSharedDescriptors
#   name-not-capitalised                Regions.ANewSiteStartsWithTheFiveSharedDescriptors
#   separators-kept-in-the-name         Regions.ANewSiteStartsWithTheFiveSharedDescriptors
#   region-name-first-letter-unchecked  Regions.ANewSiteStartsWithTheFiveSharedDescriptors
#   seed-overwrites-a-sites-own         Regions.ASharedDescriptorIsMadeChangedAndRemovedByChangeset
#   text-not-escaped-in-a-line          Regions.ATemplatesOwnDescriptorBeatsASharedOneWhichBeatsTheName
#   old-line-kept-on-replace            Regions.ATemplatesOwnDescriptorBeatsASharedOneWhichBeatsTheName
#   authorize-not-asked                 Regions.SharedDescriptorsAreWrittenOnTheirOwnPermissionAndTemplatesOnTheTemplates
#   authorize-asks-the-layout-permission Regions.SharedDescriptorsAreWrittenOnTheirOwnPermissionAndTemplatesOnTheTemplates
#   vet-not-asked                       Regions.ADescriptorThatIsNotOneIsRefusedAtStageAndAtApply
#   unplaced-unchecked                  Regions.ALayoutsNotPlacedListIsOnlyDataAndIsCheckedForItsShape
#
# Every test has a control (the right descriptor, the editor who holds the
# permission, the longest label, 32 entries), so a plant turning one red is a
# test seeing the defect, not a build failure.
#
# Usage: check-region.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testRegion 'Regions.*'

REGION=src/render/region.c
T_SEED='Regions.ANewSiteStartsWithTheFiveSharedDescriptors'
T_ORDER='Regions.ATemplatesOwnDescriptorBeatsASharedOneWhichBeatsTheName'
T_SHARED='Regions.ASharedDescriptorIsMadeChangedAndRemovedByChangeset'
T_BAD='Regions.ADescriptorThatIsNotOneIsRefusedAtStageAndAtApply'
T_PERM='Regions.SharedDescriptorsAreWrittenOnTheirOwnPermissionAndTemplatesOnTheTemplates'
T_UNPLACED='Regions.ALayoutsNotPlacedListIsOnlyDataAndIsCheckedForItsShape'

plant_stale stale-object $REGION testRegion "$T_ORDER" \
  '  if (from_template(catalog, template_name, template_len, region, region_len, info,
          &rc) ||
      rc != GDEFCORE_OK) {' \
  '  if (0) {'

plant template-descriptor-ignored $REGION testRegion "$T_ORDER" \
  '  if (from_template(catalog, template_name, template_len, region, region_len, info,
          &rc) ||
      rc != GDEFCORE_OK) {' \
  '  if (0) {'

plant shared-descriptor-ignored $REGION testRegion "$T_SEED" \
  '  if (from_shared(catalog, region, region_len, info, &rc) || rc != GDEFCORE_OK) {' \
  '  if (0) {'

plant name-not-capitalised $REGION testRegion "$T_SEED" \
  "  if (info->label[0] >= 'a' && info->label[0] <= 'z') {" \
  '  if (0) {'

plant separators-kept-in-the-name $REGION testRegion "$T_SEED" \
  "    if (info->label[i] == '_' || info->label[i] == '-') {" \
  '    if (0) {'

plant region-name-first-letter-unchecked $REGION testRegion "$T_SEED" \
  "  if (s == NULL || n == 0 || n > GDEFCORE_REGION_NAME_MAX || s[0] < 'a' ||
      s[0] > 'z') {" \
  '  if (s == NULL || n == 0 || n > GDEFCORE_REGION_NAME_MAX) {'

plant seed-overwrites-a-sites-own $REGION testRegion "$T_SHARED" \
  '            strlen(kDefaults[i].name), id) == GDEFCORE_OK) {
      continue;' \
  '            strlen(kDefaults[i].name), id) == GDEFCORE_OK && 0) {
      continue;'

plant text-not-escaped-in-a-line $REGION testRegion "$T_ORDER" \
  "    if (c <= 0x20 || c == '%' || c == '~' || c >= 0x7f) {" \
  '    if (c <= 0x20) {'

plant old-line-kept-on-replace $REGION testRegion "$T_ORDER" \
  '      continue;   /* replaced, or taken away */' \
  '      /* kept */'

plant authorize-not-asked src/entity/entity.c testRegion "$T_PERM" \
  '    rc = gdefcore_region_authorize(changeset, changeset->request);' \
  '    rc = GDEFCORE_OK;'

plant authorize-asks-the-layout-permission $REGION testRegion "$T_PERM" \
  '    rc = gdefcore_access_can(catalog, request, GDEFCORE_REGION_EDIT,
        sizeof GDEFCORE_REGION_EDIT - 1, kType, sizeof kType - 1, canon, &ok);' \
  '    rc = gdefcore_access_can(catalog, request, "core.layout.edit",
        16, kType, sizeof kType - 1, canon, &ok);'

plant vet-not-asked src/entity/entity.c testRegion "$T_BAD" \
  '  rc = gdefcore_region_vet(changeset);' \
  '  rc = GDEFCORE_OK;'

plant unplaced-unchecked src/render/layout.c testRegion "$T_UNPLACED" \
  '      rc = check_unplaced(unplaced, unplaced_lens, unplaced_count, why, sizeof why);' \
  '      rc = GDEFCORE_OK;'

plant_finish
