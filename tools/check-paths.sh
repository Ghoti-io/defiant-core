#!/bin/sh
#
# The entry-path gate (access-conditions story A5b, SPEC decisions 7 and 8).
# Protection is on the path: a route that names a permission and the capture
# of its entity, and a handler that calls library code, which asks nothing. A
# condition is evaluated only on the stored entity the path names, never on
# what was submitted. Runs the EntryPath tests on the real tree, then plants
# each defect in a COPY of the source by an exact text edit and requires the
# named test to fail:
#
#   create-fields-unchecked        EntryPath.ACreateCanBeLimitedFieldByField
#   create-container-ignored       EntryPath.CreateIsCheckedAgainstTheContainerThePathNames
#   field-limit-ignored            EntryPath.ACreateCanBeLimitedFieldByField
#   field-grant-ignores-entity     EntryPath.AFieldGrantOnAnEntityIsDecidedOnTheStoredEntity
#   authorize-skips-can            EntryPath.AGroupBPostResubmittedAsGroupAIsRefused,
#                                  EntryPath.AuthorizeAsksTheTokensTarget
#   path-decides-on-the-requests-id
#                                  EntryPath.AGroupBPostResubmittedAsGroupAIsRefused,
#                                  EntryPath.AuthorizeAsksTheTokensTarget
#   evaluator-reads-open-changeset EntryPath.AnOpenChangesetDoesNotSteerTheCheck
#   path-checks-after-staging      EntryPath.AGroupBPostResubmittedAsGroupAIsRefused
#   path-checks-post-change-value  EntryPath.AGroupBPostResubmittedAsGroupAIsRefused
#   path-checks-head-not-active    EntryPath.TheCheckIsOnTheActiveRevisionNotTheNewestDraft
#   own-follows-the-author-field   EntryPath.TheStoredAuthorFieldDoesNotMakeAnOwner
#
# Every test has a control (the same path, the same principal, one thing
# different, and the answer differs), so a plant turning one red is a test
# seeing the defect, not a build failure. The sweep over every operation and
# every person is Can.TheDecisionIsTheOperation in check-can.sh.
#
# Usage: check-paths.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testEntrypaths 'EntryPath.*'

ACCESS=src/access/access.c
FORM=src/form/form.c
ENT=src/entity/entity.c

# Plant 1: a create is not asked about the fields it supplies.
plant create-fields-unchecked $ACCESS testEntrypaths \
  'EntryPath.ACreateCanBeLimitedFieldByField' \
  '  for (i = 0; i < nfields; i++) {
    int field_ok = 0;' \
  '  for (i = 0; i < 0 * nfields; i++) {
    int field_ok = 0;'

# Plant 2: the container the path names is ignored; only the type is asked.
plant create-container-ignored $ACCESS testEntrypaths \
  'EntryPath.CreateIsCheckedAgainstTheContainerThePathNames' \
  '  if (container != NULL) {
    /* The container is the one the path names' \
  '  if (0 && container != NULL) {
    /* The container is the one the path names'

# Plant 3: a field that a permission limits is free.
plant field-limit-ignored $ACCESS testEntrypaths \
  'EntryPath.ACreateCanBeLimitedFieldByField' \
  '  if (!restricted) {
    /* No permission limits this field' \
  '  if (1 || !restricted) {
    /* No permission limits this field'

# Plant 4: a field grant asked of a stored entity is decided as if there were
# none, which lets any grant whose condition could apply to something hold.
plant field-grant-ignores-entity $ACCESS testEntrypaths \
  'EntryPath.AFieldGrantOnAnEntityIsDecidedOnTheStoredEntity' \
  '      entity_id == NULL);
  if (allowed && entity_id == NULL && ev.has_ceiling) {' \
  '      1);
  if (allowed && entity_id == NULL && ev.has_ceiling) {'

# Plant 5: the signed-form path does not ask the decision.
plant authorize-skips-can $FORM testEntrypaths \
  'EntryPath.AGroupBPostResubmittedAsGroupAIsRefused EntryPath.AuthorizeAsksTheTokensTarget' \
  '  rc = gdefcore_access_can(catalog, request, guard->action, guard->action_len,
      type, type_len, opened->target, out_allowed);' \
  '  *out_allowed = 1;
  rc = GDEFCORE_OK;
  (void)request;'

# Plant 6: the path takes the entity it asks about from the request (a route
# capture, a field of the form) instead of from the token's target.
plant path-decides-on-the-requests-id $FORM testEntrypaths \
  'EntryPath.AGroupBPostResubmittedAsGroupAIsRefused EntryPath.AuthorizeAsksTheTokensTarget' \
  '  if (guard->claimed != NULL) {
    if (gdefcore_id_canonical(guard->claimed, guard->claimed_len, claimed) !=
            GDEFCORE_OK ||
        memcmp(claimed, opened->target, GDEFCORE_PUBLIC_ID_LEN) != 0) {
      return GDEFCORE_OK;
    }
  }
  rc = gdefcore_entity_type(catalog, opened->target, GDEFCORE_PUBLIC_ID_LEN,
      &type, &type_len);' \
  '  const char * subject = opened->target;
  if (guard->claimed != NULL) {
    if (gdefcore_id_canonical(guard->claimed, guard->claimed_len, claimed) !=
        GDEFCORE_OK) {
      return GDEFCORE_OK;
    }
    subject = claimed;
  }
  rc = gdefcore_entity_type(catalog, subject, GDEFCORE_PUBLIC_ID_LEN,
      &type, &type_len);' \
  '      type, type_len, opened->target, out_allowed);
  gdefcore_text_free(catalog, type);' \
  '      type, type_len, subject, out_allowed);
  gdefcore_text_free(catalog, type);'

# ---- the attacks (SPEC decision 8): a body cannot steer the check ------------

# The ambient changeset: the three edits that give the entity layer a notion
# of "the changeset being built", which a reader that was handed none then
# falls back on. The evaluator passes NULL for the changeset on purpose
# (condition_eval.c); with this, NULL no longer means "the stored entity".
AMBIENT_DECL='void gdefcore_changeset_destroy(GDEFCORE_Changeset * changeset) {
  if (changeset == NULL) {
    return;
  }'
AMBIENT_DECL_NEW='static const GDEFCORE_Changeset * g_ambient = NULL;
void gdefcore_changeset_destroy(GDEFCORE_Changeset * changeset) {
  if (changeset == NULL) {
    return;
  }
  if (g_ambient == changeset) {
    g_ambient = NULL;
  }'
AMBIENT_SET='  *out_changeset = cs;
  return GDEFCORE_OK;
}

static GDEFCORE_Op * find_op_id('
AMBIENT_SET_NEW='  *out_changeset = cs;
  g_ambient = cs;
  return GDEFCORE_OK;
}

static GDEFCORE_Op * find_op_id('
AMBIENT_USE='  if (changeset != NULL) {
    size_t i;
    for (i = 0; i < changeset->nops; i++) {
      op = &changeset->ops[i];'
AMBIENT_USE_NEW='  if (changeset == NULL) {
    changeset = g_ambient;
  }
  if (changeset != NULL) {
    size_t i;
    for (i = 0; i < changeset->nops; i++) {
      op = &changeset->ops[i];'

# The guard block, as it stands before anything is staged.
GUARD_BLOCK='  if (guard != NULL) {
    int allowed = 0;
    rc = guard_decide(catalog, request, &opened, guard, &allowed);
    *guard->out_allowed = rc == GDEFCORE_OK && allowed;
    if (rc != GDEFCORE_OK || !allowed) {
      /* Nothing has been staged, let alone written. */
      opened_free(catalog, &opened);
      return rc != GDEFCORE_OK ? rc : GDEFCORE_ERR_INVALID;
    }
  }
'
# The same question asked late: the result is carried in rc, and the write
# (or the staging) has already happened by then.
LATE_CHECK='  if (rc == GDEFCORE_OK && guard != NULL) {
    int late = 0;
    rc = guard_decide(catalog, request, &opened, guard, &late);
    *guard->out_allowed = rc == GDEFCORE_OK && late;
    if (rc == GDEFCORE_OK && !late) {
      rc = GDEFCORE_ERR_INVALID;
    }
  }
'

# Plant 7: a reader handed no changeset reads the one being built, so the
# evaluator sees what a form is about to write.
plant evaluator-reads-open-changeset $ENT testEntrypaths \
  'EntryPath.AnOpenChangesetDoesNotSteerTheCheck' \
  "$AMBIENT_DECL" "$AMBIENT_DECL_NEW" \
  "$AMBIENT_SET" "$AMBIENT_SET_NEW" \
  "$AMBIENT_USE" "$AMBIENT_USE_NEW"

# Plant 8: the path asks after it has staged the body (and, with the
# evaluator reading the changeset being built, asks about the post-change
# value). Each half alone is harmless; together they let the body in.
plantm path-checks-after-staging testEntrypaths \
  'EntryPath.AGroupBPostResubmittedAsGroupAIsRefused' \
  $ENT "$AMBIENT_DECL" "$AMBIENT_DECL_NEW" \
  $ENT "$AMBIENT_SET" "$AMBIENT_SET_NEW" \
  $ENT "$AMBIENT_USE" "$AMBIENT_USE_NEW" \
  $FORM "$GUARD_BLOCK" '' \
  $FORM '  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, NULL, 0);
    if (rc != GDEFCORE_OK && out_conflict != NULL) {' \
  "$LATE_CHECK"'  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, NULL, 0);
    if (rc != GDEFCORE_OK && out_conflict != NULL) {'

# Plant 9: the path asks after it has written, about the post-change value.
plant path-checks-post-change-value $FORM testEntrypaths \
  'EntryPath.AGroupBPostResubmittedAsGroupAIsRefused' \
  "$GUARD_BLOCK" '' \
  '  gdefcore_changeset_destroy(changeset);
  gdefcore_text_free(catalog, alias_id);
  gcu_allocator_free(def, values);' \
  '  gdefcore_changeset_destroy(changeset);
  gdefcore_text_free(catalog, alias_id);
  gcu_allocator_free(def, values);
'"$LATE_CHECK"

# Plant 10: the check reads the head revision, the newest draft, where it
# should read the one in force.
plant path-checks-head-not-active src/condition/condition_eval.c testEntrypaths \
  'EntryPath.TheCheckIsOnTheActiveRevisionNotTheNewestDraft' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_ACTIVE,' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_DRAFT,'

# Plant 11: `own` is whoever the stored author field names, which a body can
# set, and not the entity's creator.
plant own-follows-the-author-field $ENT testEntrypaths \
  'EntryPath.TheStoredAuthorFieldDoesNotMakeAnOwner' \
  '  if (look.creator_len > 0) {
    *out_creator = dup_span(catalog->alloc, look.creator, look.creator_len);' \
  '  {
    char ** at = NULL;
    size_t * al = NULL;
    size_t an = 0;
    if (gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_ACTIVE, id, id_len,
            "en", 2, "author", 6, &at, &al, &an) == GDEFCORE_OK && an > 0) {
      *out_creator = dup_span(catalog->alloc, at[0], al[0]);
      if (out_len != NULL) {
        *out_len = al[0];
      }
      gdefcore_values_free(catalog, at, al, an);
      return *out_creator == NULL ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
    }
  }
  if (look.creator_len > 0) {
    *out_creator = dup_span(catalog->alloc, look.creator, look.creator_len);'

plant_finish
