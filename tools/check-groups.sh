#!/bin/sh
#
# The nested-groups gate (story S6d, CAP-S3): core's field model and values
# API carry groups, multiples and order to the storage port, an item is
# written only when it changed, a reorder moves order keys and nothing else,
# and the access filter is applied in every item of a group. Runs the Groups
# tests on the real tree, then plants each defect in a COPY of the source by
# an exact text edit and requires the named test to fail:
#
#   item-rewritten-through-core
#       GroupsPo.ATrackingEventThreeGroupsDeepWritesOneItemVersionAndOneRevision
#   reorder-rewrites-values     GroupsPo.AReorderChangesOrderKeysOnly
#   hidden-field-in-group-item  GroupsRender.AFieldTheReaderMayNotSeeIsAbsentInEveryItem
#   nested-personal-by-name     GroupsPersonal.AValueInsideAGroupNamesTheSubjectItsItemNames
#   flat-save-drops-groups      GroupsPo.AFlatSaveOfANestedTypeKeepsItsGroupItems
#   group-required-unchecked    GroupsPo.ATreeIsCheckedAgainstTheTypeAndAMisfitStagesNothing
#   tree-skips-filter           GroupsRender.AnOrderTheReaderMayNotSeeIsNotThere
#
# On Postgres (make test-groups-postgres) the same plants are read in
# GroupsPoPostgres and GroupsRenderPostgres; nested-personal-by-name stays on
# memory, where GroupsPersonal runs.
#
# Each test counts what the port stored (gdefstor_model_dump()) or what a
# principal was given, and has a control (the same call on the other side of
# the rule answers differently), so a plant turning one red is a test seeing
# the defect, not a build failure.
#
# Usage: check-groups.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

# The suites the plants are read in: the purchase order and the render on
# memory in `make test`, or on Postgres in `make test-groups-postgres`
# (GDEFCORE_TEST_GROUPS=postgres and a server, through
# defiant-storage-postgres's tools/pg-test.sh; story S10). GroupsPersonal
# runs on memory only, so its plant is planted there only.
PO=GroupsPo
RENDER=GroupsRender
PG=
if [ "${GDEFCORE_TEST_GROUPS:-}" = postgres ]; then
  PO=GroupsPoPostgres
  RENDER=GroupsRenderPostgres
  PG=1
  plant_control testGroups "$PO.*:$RENDER.*"
else
  plant_control testGroups 'Groups*'
fi

ENT=src/entity/entity.c
STO=src/entity/store.c
ACC=src/access/access.c

# Every group item is written as a new item at every save: its id is not
# handed to the port, so an unchanged item gets a new version (and a new id).
plant item-rewritten-through-core $STO testGroups \
  "$PO.ATrackingEventThreeGroupsDeepWritesOneItemVersionAndOneRevision" \
  '    rc = gdefcore_ent_map(gdefstor_tree_add(tree, parent, it.field,
        it.field_len, it.id, &item));' \
  '    rc = gdefcore_ent_map(gdefstor_tree_add(tree, parent, it.field,
        it.field_len, 0, &item));'

# The items of a multiple field are matched by position, not by the ids the
# tree names: moving one rewrites the values of every item it passes.
plant reorder-rewrites-values $STO testGroups \
  "$PO.AReorderChangesOrderKeysOnly" \
  '      for (i = 1; f->ids == NULL && i < count &&' \
  '      for (i = 1; i < count &&' \
  '        if (f->ids != NULL) {
          /* By id: a value that moved keeps its item (story S6d). */' \
  '        if (0) {
          /* By id: a value that moved keeps its item (story S6d). */'

# The field filter is applied to the root's values and not inside a group's
# items, so a field the reader may not read is shown in every line.
plant hidden-field-in-group-item $ACC testGroups \
  "$RENDER.AFieldTheReaderMayNotSeeIsAbsentInEveryItem" \
  '      if (field_len > 0 && !path_shown(f, path, pn)) {' \
  '      if (field_len > 0 && i == 0 && !path_shown(f, path, pn)) {'

# A value inside a group is opened under its field's name, not its path: the
# path-equals-name assumption story S6c left for S6d.
[ -n "$PG" ] || plant nested-personal-by-name $STO testGroups \
  'GroupsPersonal.AValueInsideAGroupNamesTheSubjectItsItemNames' \
  '        rc = set_value(tree, item, &info, fn == 0 ? NULL : f, fn, path.p,
            path.n, &v,' \
  '        rc = set_value(tree, item, &info, fn == 0 ? NULL : f, fn, f,
            fn, &v,'

# A flat save of a type with groups writes the root and drops the group items
# (the port closes what the tree leaves out).
plant flat-save-drops-groups $STO testGroups \
  "$PO.AFlatSaveOfANestedTypeKeepsItsGroupItems" \
  '    rc = build_groups(cat, type, l, seals, now, byid, nbyid, tree);' \
  '    rc = GDEFCORE_OK;'

# A required field inside a group item, or a required group, is not checked.
plant group-required-unchecked $ENT testGroups \
  "$PO.ATreeIsCheckedAgainstTheTypeAndAMisfitStagesNothing" \
  '    if (!groups_have_required(&doc->langs[i], decls, ndecls)) {' \
  '    if (0) {'

# A constraint a field declares (length, range, pattern) is not enforced on a
# value inside a group: only the root's were, by the form layer, so a hostile
# or malformed item is stored. Each rule, and where the refusal names the field.
GC='GroupsConstraints.ALengthRangeOrPatternBrokenOneGroupDeepIsRefusedByPath'
GC2='GroupsConstraints.ALengthRangeOrPatternBrokenTwoGroupsDeepIsRefusedByPath'
[ -n "$PG" ] || plant group-value-constraints-skipped $ENT testGroups "$GC2" \
  '      rc = canon_checked(cat, accept_personal, d, path.p, path.n, text, len,
          &canon, why);' \
  '      rc = canon_one(cat, accept_personal, d, text, len, &canon);'
[ -n "$PG" ] || plant constraint-max-length-ignored $ENT testGroups "$GC" \
  '  if (d->max_len != 0 && len > d->max_len) {' \
  '  if (0) {'
[ -n "$PG" ] || plant constraint-min-length-ignored $ENT testGroups "$GC" \
  '  if (d->min_len != 0 && len < d->min_len) {' \
  '  if (0) {'
[ -n "$PG" ] || plant constraint-range-ignored $ENT testGroups "$GC" \
  '  if (d->has_range) {
    int64_t number = 0;' \
  '  if (0) {
    int64_t number = 0;'
[ -n "$PG" ] || plant constraint-pattern-ignored $ENT testGroups "$GC" \
  '  if (d->pattern.n > 0) {
    GRX_Regex * re = NULL;' \
  '  if (0) {
    GRX_Regex * re = NULL;'
[ -n "$PG" ] || plant constraint-refusal-names-no-path $ENT testGroups "$GC2" \
  '    refuse_set(why, path, path_len, what);' \
  '    refuse_set(why, path + path_len, 0, what);'
# A pattern need only match somewhere in the value, not all of it.
[ -n "$PG" ] || plant constraint-pattern-matches-a-part $ENT testGroups "$GC" \
  '        (grx_match_span(match, &span) != GRX_OK || span.start != 0 ||
            span.end != len)) {' \
  '        (grx_match_span(match, &span) != GRX_OK)) {'

# The tree read asks for the published flag and not for a read grant, so an
# order shows to anyone once it is published.
plant tree-skips-filter $ACC testGroups \
  "$RENDER.AnOrderTheReaderMayNotSeeIsNotThere" \
  '  visible = reader_sees(catalog, canon, &ev);
  if (visible) {
    visible = entity_visible(' \
  '  visible = reader_sees(catalog, canon, &ev);
  if (0) {
    visible = entity_visible('

plant_finish
