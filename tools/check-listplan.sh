#!/bin/sh
#
# The compiled list (story A2): defects planted in the source, each required to
# turn a named test red. The compiled list and the evaluated list are two code
# paths for one answer, so each check that answer rests on is planted in the
# path that makes it: the count, the page, the cap, the published flag, the
# ceiling of an agent, the personal field, the way a failure is carried.
# (The query form's own checks, the clause of an and, the integer rule, the
# bind, are planted in defiant-storage and defiant-storage-sqlite.)
#
# Usage: check-listplan.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testListplan 'ListPlan.*'

# The total counted before the filter: every entity of the type.
plant count-before-filter-compiled src/access/access.c testListplan \
  'ListPlan.CountCountsOnlyWhatIsVisible' \
  '  *out_total = total;
  *out_count = 0;
  *out_ids = NULL;' \
  '  {
    char ** every = NULL;
    size_t nevery = 0;
    (void)gdefcore_entity_ids(catalog, q->type_name, q->type_name_len, &every,
        &nevery);
    gdefcore_ids_free(catalog, every, nevery);
    total = nevery;
  }
  *out_total = total;
  *out_count = 0;
  *out_ids = NULL;'

plant count-before-filter-evaluated src/access/access.c testListplan \
  'ListPlan.CountCountsOnlyWhatIsVisible' \
  '  *out_total = nrows;' \
  '  *out_total = count;'

# The offset applied before the sort: the first rows in creation order are
# dropped and the rest sorted.
plant offset-before-sort src/access/access.c testListplan \
  'ListPlan.PagesAreSlicesOfTheEvaluatedList' \
  '    rc = listed_sort(rows, nrows, local->sort_descending,
        local->sort2_descending);' \
  '    rc = listed_sort(rows + (local->offset < nrows ? (size_t)local->offset : nrows),
        nrows - (local->offset < nrows ? (size_t)local->offset : nrows),
        local->sort_descending, local->sort2_descending);'

# The published flag left out of the compiled filter.
plant unpublished-listed-compiled src/access/access.c testListplan \
  'ListPlan.AnUnpublishedEntityIsNeverListed' \
  '  parts[nparts++] = gdefcore_plan_published(plan);' \
  '  parts[nparts++] = gdefcore_plan_constant(plan, 1);'

# And from the entity-by-entity list.
plant unpublished-listed-evaluated src/access/access.c testListplan \
  'ListPlan.AnUnpublishedEntityIsNeverListed' \
  '    if (!reader_sees(catalog, ids[i], ev) ||
        !entity_visible(ev, grants, ngrants, local->type_name,' \
  '    if ((0 && !reader_sees(catalog, ids[i], ev)) ||
        !entity_visible(ev, grants, ngrants, local->type_name,'

# The cap on a page removed.
plant limit-cap-removed src/access/access.c testListplan \
  'ListPlan.TheLimitIsClamped' \
  '  spec.limit = local.limit == 0 ? 0
               : (local.limit > GDEFCORE_ACCESS_LIST_MAX_LIMIT
                         ? GDEFCORE_ACCESS_LIST_MAX_LIMIT
                         : local.limit);' \
  '  spec.limit = local.limit;'

# Creation order as the last tiebreak lost: the store orders the row numbers
# by their digits.
plant tiebreak-as-text src/access/access.c testListplan \
  'ListPlan.TheLastTiebreakIsCreationOrder' \
  '  sq.entity_numeric = 1; /* ends in creation order, as the index lists */' \
  '  sq.entity_numeric = 0;'

# A grant of one field taken for a grant of the entity.
plant field-grant-widens src/access/access.c testListplan \
  'ListPlan.AFieldWithAFieldGrantIsDecidedEntityByEntity' \
  '    if (!same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        grants[i].field_len != 0 ||
        !same(grants[i].action, grants[i].action_len, "read", 4)) {' \
  '    if (!same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        !same(grants[i].action, grants[i].action_len, "read", 4)) {'

# The ceiling of an acting principal left out of the compiled list.
plant ceiling-ignored src/access/access.c testListplan \
  'ListPlan.AnAgentIsHeldToTheCeilingInTheCompiledList' \
  '    if (ev->has_ceiling) {
      /* A grant of the acting principal'"'"'s' \
  '    if (0 && ev->has_ceiling) {
      /* A grant of the acting principal'"'"'s'

# A personal field read like any other: its ciphertext is compared.
plant personal-field-accepted src/condition/condition_plan.c testListplan \
  'ListPlan.APersonalFieldIsNeverComparedAndNeverGrants' \
  '  if (field_info(p, name, name_len, &info) != 0 || !info.found ||
      info.personal) {' \
  '  if (field_info(p, name, name_len, &info) != 0 || !info.found) {'

# A failure that cannot be decided carried into no predicate: the evaluator
# says no, the list says yes.
plant failure-not-carried src/condition/condition_plan.c testListplan \
  'ListPlan.FailureNeverGrantsWhenCompiled ListPlan.ConditionsAgreeWithTheEvaluator' \
  '  out.x = nx == 0 ? NULL : fold_list(p, GDEFSTOR_QUERY_OR, xs, nx);' \
  '  out.x = NULL;'

# `in` off by one: the last member of the list is not in it.
plant in-off-by-one src/condition/condition_plan.c testListplan \
  'ListPlan.ConditionsAgreeWithTheEvaluator' \
  '  size_t members = n->count - 1;' \
  '  size_t members = n->count - 2;'

# `<=` compiled as `<`.
plant le-as-lt src/condition/condition_plan.c testListplan \
  'ListPlan.ConditionsAgreeWithTheEvaluator' \
  '    case kLe:
      return GDEFSTOR_QUERY_LE;' \
  '    case kLe:
      return GDEFSTOR_QUERY_LT;'

# state compared with the wrong value of the flag.
plant state-flag-swapped src/condition/condition_plan.c testListplan \
  'ListPlan.ConditionsAgreeWithTheEvaluator' \
  '  return mk_or2(p, mk_and2(p, pub_is(p, 1), a), mk_and2(p, pub_is(p, 0), b));' \
  '  return mk_or2(p, mk_and2(p, pub_is(p, 0), a), mk_and2(p, pub_is(p, 1), b));'

plant_finish
