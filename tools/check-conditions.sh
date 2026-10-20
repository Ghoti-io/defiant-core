#!/bin/sh
#
# The conditions gate (access-conditions story A1): the language that says
# which entities a grant covers. Runs the Cond, CondAccess and CondSweep tests
# on the real tree, then plants each defect in a COPY of the source by an exact
# text edit and requires the named test to fail:
#
#   not-equal-as-equal         Cond.NotEqual
#   in-off-by-one              Cond.InList
#   and-as-or                  Cond.BooleanTruthTables
#   not-dropped                Cond.BooleanTruthTables
#   own-matches-no-actor       Cond.OwnNeedsAnActor, CondAccess.OwnExpressionNeedsAnActor
#   revision-creator-matches-none Cond.CreatorIsTheEntitysAndRevisionCreatorIsTheRevisions
#   absent-field-wildcard      Cond.AbsentFieldIsNotAWildcard
#   depth-limit-moved          Cond.LimitDepth
#   node-limit-moved           Cond.LimitNodes
#   byte-limit-removed         Cond.LimitBytes
#   trailing-garbage-accepted  Cond.RefusesBadSyntax
#   personal-field-allowed     Cond.PersonalFieldRefused, CondAccess.DeclareRefusals
#   failure-grants (eval)      Cond.FailureNeverGrants
#   failure-grants (filter)    CondAccess.FailureNeverGrants
#   unreadable-text-grants     CondAccess.FailureNeverGrants
#   hash-before-canonical      Cond.CanonicalAndHash
#   list-counts-before-filter  CondAccess.ListCountsWhatIsGranted
#   lookup-failure-reseeds     CondAccess.FailureNeverGrants (two plants)
#   list-skips-the-flag        CondAccess.ReadAndListHonorTheExpression
#   condition-reads-head       Cond.TheNewestRevisionIsWhatIsRead
#   condition-reads-published  Cond.TheNewestRevisionIsWhatIsRead
#   actor-still-written        Cond.EditionOneActorIsUpcastAndNotWrittenAnyMore
#   upcast-does-nothing        Cond.EditionOneActorIsUpcastAndNotWrittenAnyMore, CondAccess.AStoredEditionOneGrantStillMeansWhatItMeant
#   upcast-rewrites-constants  Cond.EditionOneActorIsUpcastAndNotWrittenAnyMore
#
# Every test has a control (the condition that matches DOES grant, the same
# input with no failure DOES hold, a valid sibling of every refused text is
# accepted, the allocation one past the last is the one that does not fail), so
# a plant turning one red is a test seeing the defect, not a build failure.
# The CondSweep tests (a seeded random-tree sweep against an independent
# evaluator, and hostile bytes) run in the control too: they are not planted
# against, they are the net under the named tests.
#
# Usage: check-conditions.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testCondition 'Cond.*:CondAccess.*:CondSweep.*'

EVAL=src/condition/condition_eval.c
PARSE=src/condition/condition.c
ACCESS=src/access/access.c

# Plant 1: != answers as =.
plant not-equal-as-equal $EVAL testCondition 'Cond.NotEqual' \
  '    r = !any_equal(&a, &b);' \
  '    r = any_equal(&a, &b);'

# Plant 2: the last member of an in list is never looked at.
plant in-off-by-one $EVAL testCondition 'Cond.InList' \
  '  for (k = 1; k < node->count && !r; k++) {' \
  '  for (k = 1; k + 1 < node->count && !r; k++) {'

# Plant 3: and holds when any operand does.
plant and-as-or $EVAL testCondition 'Cond.BooleanTruthTables' \
  '    case kAnd:
      for (k = 0; k < node->count; k++) {
        if (!eval_node(ctx, ctx->c->kids[node->first + k])) {
          return 0;
        }
      }
      return 1;' \
  '    case kAnd:
      for (k = 0; k < node->count; k++) {
        if (eval_node(ctx, ctx->c->kids[node->first + k])) {
          return 1;
        }
      }
      return 0;'

# Plant 4: not does not negate.
plant not-dropped $EVAL testCondition 'Cond.BooleanTruthTables' \
  '      return ctx->failed ? 0 : !r;' \
  '      return ctx->failed ? 0 : r;'

# Plant 5: an absent creator and an absent principal read as the empty text,
# so an entity with no creator is an anonymous request's own. (The operand was
# `actor` until edition 2; `own` is the creator, so this is the block `own`
# goes through.)
plant own-matches-no-actor $EVAL testCondition \
  'Cond.OwnNeedsAnActor CondAccess.OwnExpressionNeedsAnActor' \
  '      if (ctx->creator != NULL && ctx->creator_len > 0) {
        vals_one(vals, ctx->creator, ctx->creator_len);
      }
      return 1;' \
  '      vals_one(vals, ctx->creator != NULL ? ctx->creator : kEmpty, ctx->creator_len);
      return 1;' \
  '      if (p != NULL && n > 0) {
        vals_one(vals, p, n);
      }
      return 1;' \
  '      vals_one(vals, p != NULL ? p : kEmpty, p != NULL ? n : 0);
      return 1;'

# Plant 5b: the same for the revision's creator.
plant revision-creator-matches-none $EVAL testCondition \
  'Cond.CreatorIsTheEntitysAndRevisionCreatorIsTheRevisions' \
  '      if (ctx->actor != NULL && ctx->actor_len > 0) {
        vals_one(vals, ctx->actor, ctx->actor_len);
      }
      return 1;' \
  '      vals_one(vals, ctx->actor != NULL ? ctx->actor : kEmpty, ctx->actor_len);
      return 1;' \
  '      if (p != NULL && n > 0) {
        vals_one(vals, p, n);
      }
      return 1;' \
  '      vals_one(vals, p != NULL ? p : kEmpty, p != NULL ? n : 0);
      return 1;'

# Plant 6: an absent field (the empty text) equals anything.
plant absent-field-wildcard $EVAL testCondition 'Cond.AbsentFieldIsNotAWildcard' \
  'static int any_equal(const Vals * a, const Vals * b) {
  size_t i;
  size_t j;
' \
  'static int any_equal(const Vals * a, const Vals * b) {
  size_t i;
  size_t j;
  if (a->n == 1 && a->v[0].n == 0) {
    return 1;
  }
'

# Plant 7a: one more level of parentheses is allowed.
plant depth-limit-moved $PARSE testCondition 'Cond.LimitDepth' \
  '    if (depth + 1 > GDEFCORE_CONDITION_MAX_DEPTH) {' \
  '    if (depth + 1 > GDEFCORE_CONDITION_MAX_DEPTH + 1) {'

# Plant 7b: one node fewer is allowed.
plant node-limit-moved $PARSE testCondition 'Cond.LimitNodes' \
  '  if (c->nnodes >= kMaxNodes) {' \
  '  if (c->nnodes >= kMaxNodes - 1) {'

# Plant 7c: the byte limit is not what it says.
plant byte-limit-removed $PARSE testCondition 'Cond.LimitBytes' \
  '  if (len > GDEFCORE_CONDITION_MAX_BYTES) {' \
  '  if (len > GDEFCORE_CONDITION_MAX_BYTES + 1000) {'

# Plant 8: text after the condition is ignored.
plant trailing-garbage-accepted $PARSE testCondition 'Cond.RefusesBadSyntax' \
  '    if (p.pos < p.len) {
      root = fail(&p, p.pos, kMsgTrail);' \
  '    if (0 && p.pos < p.len) {
      root = fail(&p, p.pos, kMsgTrail);'

# Plant 9: a personal field may be named in a condition.
plant personal-field-allowed $PARSE testCondition \
  'Cond.PersonalFieldRefused CondAccess.DeclareRefusals' \
  '  return out->found && !out->personal;' \
  '  return out->found;'

# Plant 10a: an evaluation that failed holds.
plant failure-grants-in-eval $EVAL testCondition 'Cond.FailureNeverGrants' \
  '  if (ctx.failed) {
    r = 0;' \
  '  if (ctx.failed) {
    r = 1;'

# Plant 10b: the filter takes a failed evaluation as a grant.
plant failure-grants-in-filter $ACCESS testCondition 'CondAccess.FailureNeverGrants' \
  '  if (failed) {
    ev->failed = 1;
    return 0;
  }
  return r;' \
  '  if (failed) {
    ev->failed = 1;
    return 1;
  }
  return r;'

# Plant 10c: stored text that cannot be read holds.
plant unreadable-text-grants $ACCESS testCondition 'CondAccess.FailureNeverGrants' \
  '  if (slot == NULL || slot->bad || slot->cond == NULL) {
    ev->failed = 1;
    return 0;
  }' \
  '  if (slot == NULL || slot->bad || slot->cond == NULL) {
    ev->failed = 1;
    return 1;
  }'

# Plant 11: the hash is of the text as written, not of the canonical form.
plant hash-before-canonical $PARSE testCondition 'Cond.CanonicalAndHash' \
  '      gsec_sha256_update(&ctx, canon, canon_len) != GSEC_OK ||' \
  '      gsec_sha256_update(&ctx, text, len) != GSEC_OK ||'

# Plant 12: the interim list takes every candidate, so its count is the
# candidates and not the entities a grant holds for.
plant list-counts-before-filter $ACCESS testCondition \
  'CondAccess.ListCountsWhatIsGranted CondAccess.ReadAndListHonorTheExpression' \
  '    if (!reader_sees(catalog, ids[i], ev) ||
        !entity_visible(ev, grants, ngrants, local->type_name,
            local->type_name_len, actor, actor_len, principal, principal_len)) {' \
  '    if (0 && (!reader_sees(catalog, ids[i], ev) ||
        !entity_visible(ev, grants, ngrants, local->type_name,
            local->type_name_len, actor, actor_len, principal, principal_len))) {' \
  '  parts[nparts++] = access_node(ev, plan, grants, ngrants, q->type_name,
      q->type_name_len);' \
  '  parts[nparts++] = gdefcore_plan_constant(plan, 1);
  (void)grants;
  (void)ngrants;' \
  '  parts[nparts++] = gdefcore_plan_published(plan);' \
  '  parts[nparts++] = gdefcore_plan_constant(plan, 1);'

# Plant 13 (a defect found on the way): a lookup that failed reads as "no such
# entity", and the next call seeds the roles again.
plant lookup-failure-reseeds $ACCESS testCondition 'CondAccess.FailureNeverGrants' \
  '  if (rc != GDEFCORE_OK && failure != GDEFCORE_OK) {
    return failure;
  }
  return rc;' \
  '  return rc;' \
  '  if (rc != GDEFCORE_ERR_INVALID) {
    /* Not "no admin role yet"' \
  '  if (0) {
    /* Not "no admin role yet"'

# Plant 14 (access-conditions A5b): a list does not ask whether an entity is
# published, so an `any` reader is told the id of one a direct read refuses.
plant list-skips-the-flag $ACCESS testCondition 'CondAccess.ReadAndListHonorTheExpression' \
  '    if (!reader_sees(catalog, ids[i], ev) ||
        !entity_visible(ev, grants, ngrants, local->type_name,' \
  '    if (!entity_visible(ev, grants, ngrants, local->type_name,' \
  '  parts[nparts++] = gdefcore_plan_published(plan);' \
  '  parts[nparts++] = gdefcore_plan_constant(plan, 1);'

# Plant 15: a condition reads the head revision, so a draft beside the active
# revision decides who may do what.
plant condition-reads-head $EVAL testCondition 'Cond.TheNewestRevisionIsWhatIsRead' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_ACTIVE,' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_DRAFT,'

# Plant 16: a condition reads what readers see, so an entity that is not
# published has no fields for a grant to hold on and its author cannot edit it.
plant condition-reads-published $EVAL testCondition 'Cond.TheNewestRevisionIsWhatIsRead' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_ACTIVE,' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_PUBLISHED,'

# Plant 17: the parser still takes the edition 1 `actor`, as the new operand,
# from a person writing a condition.
plant actor-still-written $PARSE testCondition 'Cond.EditionOneActorIsUpcastAndNotWrittenAnyMore' \
  '    return fail(p, start, kMsgRenamed);' \
  '    (void)kMsgRenamed;
    return new_node(p, kRevCreator, start);'

# Plant 18: the upcaster leaves an edition 1 `actor` as it found it, so a
# stored grant stops meaning what it meant.
plant upcast-does-nothing $PARSE testCondition 'Cond.EditionOneActorIsUpcastAndNotWrittenAnyMore CondAccess.AStoredEditionOneGrantStillMeansWhatItMeant' \
  '      if (from_edition == 1 && j - i == sizeof kOld - 1 &&' \
  '      if (0 && from_edition == 1 && j - i == sizeof kOld - 1 &&'

# Plant 19: the upcaster rewrites inside a text constant too.
plant upcast-rewrites-constants $PARSE testCondition 'Cond.EditionOneActorIsUpcastAndNotWrittenAnyMore' \
  '      buf_add(&b, text + i, j - i);
      i = j;
    } else if (is_delim(ch)) {' \
  '      if (j - i == 7 && memcmp(text + i, "\"actor\"", 7) == 0) {
        buf_add(&b, "\"revision.creator\"", 18);
      } else {
        buf_add(&b, text + i, j - i);
      }
      i = j;
    } else if (is_delim(ch)) {'

plant_finish
