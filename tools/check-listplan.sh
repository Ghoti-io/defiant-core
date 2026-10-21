#!/bin/sh
#
# The compiled list (story A2): defects planted in the source, each required to
# turn a named test red. The compiled list and the evaluated list are two code
# paths for one answer, so each check that answer rests on is planted in the
# path that makes it: the count, the page, the cap, the published flag, the
# ceiling of an agent, the personal field, the way a failure is carried.
# (The query form's own checks, the clause of an and, the integer rule, the
# bind, are planted in defiant-storage and defiant-storage-sqlite.) Since
# story S6b the compiled list is a query of the port's current tables, which
# hold no draft and no older revision; the entity-by-entity list reads them
# through core, so that is where a list can read either, and is planted.
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
  '    rc = listed_sort(rows, nrows, &order);' \
  '    rc = listed_sort(rows + (local->offset < nrows ? (size_t)local->offset : nrows),
        nrows - (local->offset < nrows ? (size_t)local->offset : nrows), &order);'

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

# Creation order as the last tiebreak lost: the compiled list ends in the
# order of the public ids.
plant tiebreak-by-id src/access/access.c testListplan \
  'ListPlan.TheLastTiebreakIsCreationOrder' \
  '  sq.sort_count = nsorts;' \
  '  if (nsorts < 2) {
    memset(&sort_copy[nsorts], 0, sizeof sort_copy[nsorts]);
    sort_copy[nsorts].key.kind = GDEFSTOR_QUERY_ENTITY;
    nsorts += 1;
    sq.sorts = sort_copy;
  }
  sq.sort_count = nsorts;'

# A grant of one field taken for a grant of the entity.
plant field-grant-widens src/access/access.c testListplan \
  'ListPlan.AFieldWithAFieldGrantIsDecidedEntityByEntity' \
  '    if (!same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        grants[i].field_len != 0 || grants[i].source == kSrcCallback ||
        !same(grants[i].action, grants[i].action_len, "read", 4)) {' \
  '    if (!same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        grants[i].source == kSrcCallback ||
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
  '  if (cond_field_info(p->catalog, p->type, p->type_len, name, name_len, info) !=
          0 ||
      !info->found || info->personal || info->governed) {' \
  '  if (cond_field_info(p->catalog, p->type, p->type_len, name, name_len, info) !=
          0 ||
      !info->found || info->governed) {'

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
  '  return mk_or2(p, mk_and2(p, pub_node(p, 1, outer), a),
      mk_and2(p, pub_node(p, 0, outer), b));' \
  '  return mk_or2(p, mk_and2(p, pub_node(p, 0, outer), a),
      mk_and2(p, pub_node(p, 1, outer), b));'

# A list that reads an older revision: the entity-by-entity list reads each
# entity's first revision for its filter and its sort (story S6b).
plant list-reads-old-revision src/access/access.c testListplan \
  'ListPlan.AListReadsOnlyTheCurrentRevision' \
  '  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, strlen(field), out_texts,
      out_lens, out_count);' \
  '  rc = gdefcore_entity_revision_values(catalog, id, GDEFCORE_PUBLIC_ID_LEN, 1,
      lang, lang_len, field, strlen(field), out_texts, out_lens, out_count);'

# Draft content in a list: the entity-by-entity list reads the draft over an
# entity for its filter and its sort (story S6b).
plant draft-content-listed src/access/access.c testListplan \
  'ListPlan.ADraftIsNeverInAList' \
  '  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, strlen(field), out_texts,
      out_lens, out_count);' \
  '  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_DRAFT, id,
      GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, strlen(field), out_texts,
      out_lens, out_count);'

plant_finish
