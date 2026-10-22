#!/bin/sh
#
# Relations (story A3): defects planted in the source, each required to turn a
# named test red. A relation is read in two places that must agree, the
# evaluator (condition_eval.c) and the list compiler (condition_plan.c), and
# written in one (relation.c); each check that keeps a relation from deciding
# what it should not is planted where it is made.
#
# Usage: check-relations.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

EVAL=src/condition/condition_eval.c
PLAN=src/condition/condition_plan.c
ACCESS=src/access/access.c

plant_control testRelations 'Relations.*:RelationsSurface.*'

# 1. A relation no enabled module declares is read: the name is not looked up.
plant undeclared-relation-readable $EVAL testRelations \
  'Relations.AnUndeclaredRelationIsNeverRead' \
  '    if (items[i]->name_len == rel_len && memcmp(items[i]->name, rel, rel_len) == 0) {
      size_t k;
      declared = items[i]->ncolumns == arity;
      for (k = 0; declared && k < arity; k++) {
        kinds[k] = items[i]->columns[k].kind;
      }
      break;
    }' \
  '    {
      size_t k;
      declared = 1;
      for (k = 0; k < arity; k++) {
        kinds[k] = GDEFCORE_RELATION_TEXT;
      }
      break;
    }'

# 2. A column the declaration does not have: the number of operands is not
# held to the number of columns.
plant undeclared-column-readable $EVAL testRelations \
  'Relations.AnUndeclaredRelationIsNeverRead' \
  '      declared = items[i]->ncolumns == arity;
      for (k = 0; declared && k < arity; k++) {
        kinds[k] = items[i]->columns[k].kind;
      }' \
  '      declared = 1;
      for (k = 0; declared && k < arity; k++) {
        kinds[k] = k < items[i]->ncolumns ? items[i]->columns[k].kind
                                          : GDEFCORE_RELATION_TEXT;
      }'

# 3. A disabled module'"'"'s relation still decides: the declaration is not asked.
plant disabled-relation-decides $EVAL testRelations \
  'Relations.ADisabledModulesRelationDecidesNothing Relations.AnUndeclaredRelationIsNeverRead' \
  '  if (!declared) {' \
  '  if (!declared && 0) {'

# 3b. The same in the list compiler.
plant disabled-relation-decides-compiled $PLAN testRelations \
  'Relations.TheCompiledListReadsAnUndeclaredRelationAsAFailure Relations.ADisabledModulesRelationDecidesNothing' \
  '  gdefcore_module_declared_free(host, items);
  return ok;' \
  '  gdefcore_module_declared_free(host, items);
  return ok || 1;'

# 4. Membership compared on the wrong column.
plant wrong-column $EVAL testRelations \
  'Relations.MembershipGrantsAndOnlyForTheRowsOwner' \
  '                            : gdefcore_relation_column_field(i);' \
  '                            : gdefcore_relation_column_field(arity - 1 - i);'

# 5. The relation read as the principal: a principal who may not read the rows
# is hidden from the decision.
plantm relation-read-as-principal testRelations \
  'Relations.MembershipGrantsAndOnlyForTheRowsOwner' \
  $EVAL '#include <ghoti.io/defiant-core/relation.h>
' '#include <ghoti.io/defiant-core/relation.h>
#include <ghoti.io/defiant-core/access.h>
' \
  $EVAL '        result = nids > 0;' \
  '        result = nids > 0 && gdefcore_access_permits(ctx->catalog, ctx->request, "relation.rows", 13);'

# 6. The relation'"'"'s version left out of the read set, in a decision...
plant version-left-out-evaluator $EVAL testRelations \
  'Relations.ARowChangesTheKeysReadsDigestAndOnlyForTheRelationRead' \
  '  if (!bad && gdefcore_relation_note_dependency(ctx->catalog, ctx->request, rel,
                  rel_len) != GDEFCORE_OK) {
    bad = 1;
  }' \
  '  if (0) {
    bad = 1;
  }'

# 6b. ...and in a list.
plant version-left-out-list $ACCESS testRelations \
  'Relations.AListThatRestsOnARelationReadsItsVersionToo' \
  '      rc = gdefcore_relation_note_dependency(catalog, request, rname, rlen);' \
  '      rc = GDEFCORE_OK;
      (void)rname;
      (void)rlen;'

# 7. A read that fails is a grant.
plant failing-read-grants $EVAL testRelations \
  'Relations.AFailureWhileReadingGrantsNothing' \
  '      if (rc != GDEFCORE_OK) {
        bad = 1;
      } else {
        result = nids > 0;' \
  '      if (rc != GDEFCORE_OK) {
        result = 1;
      } else {
        result = nids > 0;'

# 8. A column left out of the compiled semi-join.
plant compiled-ignores-a-column $PLAN testRelations \
  'Relations.ListsThatRestOnARelationAgreeWithTheEvaluatedList' \
  '  for (i = 0; i < arity; i++) {
    const CNode * operand = &c->nodes[c->kids[n->first + 1 + i]];' \
  '  for (i = 0; i + 1 < arity; i++) {
    const CNode * operand = &c->nodes[c->kids[n->first + 1 + i]];'

# 9. The owning-module rule skipped: any enabled module'"'"'s relation is writable.
plant owning-module-rule-skipped src/relation/relation.c testRelations \
  'Relations.OnlyTheOwningModuleWritesItsRelation' \
  '    if (r->module_len == module_len && memcmp(r->module, module, module_len) == 0) {' \
  '    if (1) {'

# 10. A handler-facing call that reads rows past the filter.
plant rows-readable-by-a-call include/ghoti.io/defiant-core/relation.h testRelations \
  'RelationsSurface.NoCallReadsRowsPastTheFilter' \
  '/**
 * @brief The version of a relation:' \
  'GDEFCORE_API GDEFCORE_Result gdefcore_relation_rows(GDEFCORE_Catalog * catalog,
    const char * relation, size_t relation_len, char *** out_ids,
    size_t * out_count);

/**
 * @brief The version of a relation:'

# 12. The note about who may add rows left off a relation grant: the rating
# stays low where it should not.
plant relation-grant-rated-low $ACCESS testRelations \
  'Relations.TheMatrixSaysInWordsWhatRestsOnARelationAndRatesItAtLeastMedium' \
  '    return related ? GDEFCORE_ACCESS_RISK_MEDIUM : GDEFCORE_ACCESS_RISK_LOW;
  }
  if (has_field) {' \
  '    return GDEFCORE_ACCESS_RISK_LOW;
  }
  if (has_field) {'

plant_finish
