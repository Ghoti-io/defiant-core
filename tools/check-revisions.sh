#!/bin/sh
#
# The entity record gate (access-conditions story A5b): the published flag, the
# active revision, the version and the creator, beside the append-only
# revisions (SPEC decisions 9-11). Runs the Revisions tests on the real tree,
# then plants each defect in a COPY of the source by an exact text edit and
# requires the named test to fail:
#
#   publish-forgets-flag        Revisions.PublishSetsTheFlagAndMakesTheHeadActive
#   publish-stores-publisher    Revisions.PublishKeepsTheRevisionsOwnCreator
#   draft-moves-pointer         Revisions.ALaterDraftDoesNotMoveThePointer
#   first-draft-not-active      Revisions.FirstDraftIsActiveButNotPublished
#   clear-leaves-flag           Revisions.ClearUnpublishesAndEmptiesTheActiveRevision
#   published-view-ignores-flag Revisions.FirstDraftIsActiveButNotPublished
#   active-view-reads-head      Revisions.ALaterDraftDoesNotMoveThePointer
#   save-omits-state            Revisions.StoredShape
#   row-without-state           Revisions.CreateWritesTheRecord
#   publish-skips-version       Revisions.TheVersionMovesWhereTheRevisionDoesNot
#   creator-mutable             Revisions.TheCreatorIsSetOnceAtTheFirstRevision
#   old-shape-read-unpublished  Revisions.AnOldShapedStoreIsCorruptNotUnpublished
#
#   unpublish-clears-pointer     Revisions.UnpublishClearsTheFlagAndNothingElse
#   activate-moves-flag          Revisions.ActivateMovesThePointerAndNothingElse
#   activate-publisher-creator   Revisions.ActivateMovesThePointerAndNothingElse
#   activate-unrecorded          Revisions.ActivateNeedsARecordedRevision
#   activate-cleared-no-head     Revisions.ActivateBringsBackAClearedEntity
#   revert-publishes             Revisions.RevertToCopiesATargetAndKeepsTheFlag
#   revert-writes-no-revision    Revisions.RevertToCopiesATargetAndKeepsTheFlag
#   legacy-revert-from-head      Revisions.TheLegacyRevertStepsBackFromTheActiveRevision
#   stale-version-accepted       Revisions.AStalePatchOfTheNewOperationsIsAConflict
#   patch-drops-version          Revisions.TheNewOperationsRoundTripThroughAPatch
#   form-tree-skips-active       Form.TreeFallsBackToTheActiveRevision
#   revisions-not-edit-class    ActionRating.RevisionsActionsAreAtLeastAnEdit
#   activate-not-strong         ActionRating.RevisionsActionsAreAtLeastAnEdit
#   self-reference-not-raised   ActionRating.AGrantThatCanChangeItsOwnFieldIsRatedOneStepHigher,
#                               Actions.TheMatrixSaysItInWords
#   self-reference-blind-to-whole-entity-grants
#                               ActionRating.AGrantThatCanChangeItsOwnFieldIsRatedOneStepHigher
#   self-reference-ignores-the-grants-field
#                               ActionRating.AGrantThatCanChangeItsOwnFieldIsRatedOneStepHigher
#   matrix-silent-on-self-reference
#                               Actions.TheMatrixSaysItInWords
#   revision-view-skips-permission
#                               Actions.RevisionViewNeedsThePermissionAndNotTheFlag
#   revision-view-skips-sequence-check
#                               Actions.RevisionViewRefusalsAreOneAnswer
#   revision-view-skips-field-filter
#                               Actions.RevisionViewIsFilteredFieldByField
#   revision-view-shows-personal
#                               Actions.RevisionViewNeverShowsAPersonalFieldAsStored
#   condition-reads-head        Actions.RevisionViewAsksTheActiveStateNotTheViewedRevision
#   (activate-skips-sealed-check is in check-erasure.sh, which owns the
#    personal-value fixtures: Erasure.PlaintextRevisionIsNotActivated)
#
# Every test has a control (the same call on the other side of the rule
# answers differently), so a plant turning one red is a test seeing the
# defect, not a build failure. Later tasks of the story add their plants here.
#
# Usage: check-revisions.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testRevisions 'Revisions.*'
plant_control testForm 'Form.TreeFallsBackToTheActiveRevision'
plant_control testActions 'ActionVocabulary.*:ActionRating.*:Actions.*'

ENT=src/entity/entity.c

# Plant 1: a publish does not set the flag.
plant publish-forgets-flag $ENT testRevisions \
  'Revisions.PublishSetsTheFlagAndMakesTheHeadActive' \
  '    case GDEFCORE_OP_PUBLISH:
      st->pub = 1;' \
  '    case GDEFCORE_OP_PUBLISH:
      st->pub = st->pub;'

# Plant 2: a publish writes the publisher as the revision's creator (defect
# 1.5.3: the author was lost, and `own` stopped matching).
plant publish-stores-publisher $ENT testRevisions \
  'Revisions.PublishKeepsTheRevisionsOwnCreator' \
  '            head_actor, head_actor_len);' \
  '            actor, actor_len);'

# Plant 3: a later draft moves the active pointer.
plant draft-moves-pointer $ENT testRevisions \
  'Revisions.ALaterDraftDoesNotMoveThePointer' \
  '      moves = step->first;' \
  '      moves = 1;'

# Plant 4: the first draft of an entity is not made active.
plant first-draft-not-active $ENT testRevisions \
  'Revisions.FirstDraftIsActiveButNotPublished' \
  '      moves = step->first;' \
  '      moves = 0;'

# Plant 5: a clear leaves the published flag set.
plant clear-leaves-flag $ENT testRevisions \
  'Revisions.ClearUnpublishesAndEmptiesTheActiveRevision' \
  '      st->pub = 0;
      st->has_act = 0;' \
  '      st->has_act = 0;'

# Plant 6: the reader's view ignores the flag.
plant published-view-ignores-flag $ENT testRevisions \
  'Revisions.FirstDraftIsActiveButNotPublished' \
  '    if (view == GDEFCORE_VIEW_PUBLISHED && !st.pub) {' \
  '    if (0 && view == GDEFCORE_VIEW_PUBLISHED && !st.pub) {'

# Plant 7: the active view reads the head.
plant active-view-reads-head $ENT testRevisions \
  'Revisions.ALaterDraftDoesNotMoveThePointer' \
  '  rc = read_proj_doc(catalog, view == GDEFCORE_VIEW_DRAFT ? "d:" : "a:",' \
  '  rc = read_proj_doc(catalog, "d:",'

# Plant 8: a save does not write the entity record.
plant save-omits-state $ENT testRevisions \
  'Revisions.StoredShape' \
  '    if (rc == GDEFCORE_OK) {
      rc = put_state(write, op->row, &st);
    }
    gcu_allocator_free(cat->alloc, lang);' \
  '    gcu_allocator_free(cat->alloc, lang);'

# Plant 9: create does not write the entity record (a row with no record).
plant row-without-state $ENT testRevisions \
  'Revisions.CreateWritesTheRecord' \
  '    EntState st;
    memset(&st, 0, sizeof st);
    rc = put_state(write, row, &st);' \
  '    EntState st;
    memset(&st, 0, sizeof st);
    (void)st;'

# Plant 10: a publish or a clear does not move the version (defect 1.5.2: the
# memo and the read set were keyed on a number that did not move).
plant publish-skips-version $ENT testRevisions \
  'Revisions.TheVersionMovesWhereTheRevisionDoesNot' \
  '  st->ver += 1;
  if (step->first' \
  '  if (step->kind != GDEFCORE_OP_PUBLISH && step->kind != GDEFCORE_OP_CLEAR) {
    st->ver += 1;
  }
  if (step->first'

# Plant 11: the creator follows the latest actor, not the first.
plant creator-mutable $ENT testRevisions \
  'Revisions.TheCreatorIsSetOnceAtTheFirstRevision' \
  '  if (step->first && st->creator_len == 0 && step->actor != NULL &&' \
  '  if (step->kind == GDEFCORE_OP_SAVE && step->actor != NULL &&'

# Plant 12: a row with no entity record reads as an unpublished entity.
plant old-shape-read-unpublished $ENT testRevisions \
  'Revisions.AnOldShapedStoreIsCorruptNotUnpublished' \
  '  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_ERR_CORRUPT;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "pub", 3, &val, &vlen) || vlen != 1 ||' \
  '  if (rc == GDEFCORE_ERR_INVALID) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!col_find(proj, "pub", 3, &val, &vlen) || vlen != 1 ||'

# Plant 13: an unpublish also forgets which revision the entity is.
plant unpublish-clears-pointer $ENT testRevisions \
  'Revisions.UnpublishClearsTheFlagAndNothingElse' \
  '      /* The active revision stays where it is. */
      st->pub = 0;
      return 0;' \
  '      /* The active revision stays where it is. */
      st->pub = 0;
      st->has_act = 0;
      return 0;'

# Plant 14: an activate also publishes.
plant activate-moves-flag $ENT testRevisions \
  'Revisions.ActivateMovesThePointerAndNothingElse' \
  '    case GDEFCORE_OP_ACTIVATE:
      moves = 1;' \
  '    case GDEFCORE_OP_ACTIVATE:
      st->pub = 1;
      moves = 1;'

# Plant 15: an activated revision is credited to whoever activated it.
plant activate-publisher-creator $ENT testRevisions \
  'Revisions.ActivateMovesThePointerAndNothingElse' \
  '            op->row, op->target_seq, op->id.p, op->id.n, doc_text,
            doc_text_len, who, who_len);
      }
      if (rc == GDEFCORE_OK && op->target_seq == high) {' \
  '            op->row, op->target_seq, op->id.p, op->id.n, doc_text,
            doc_text_len, actor, actor_len);
      }
      if (rc == GDEFCORE_OK && op->target_seq == high) {'

# Plant 16: a sequence that was never recorded is accepted (the call does not
# look the revision up, and apply reads whatever is not there as empty).
plant activate-unrecorded $ENT testRevisions \
  'Revisions.ActivateNeedsARecordedRevision' \
  '    if (target == 0 || target > high) {
      rc = GDEFCORE_ERR_INVALID;
    } else {
      rc = rev_doc(cat, row, target, &staged);' \
  '    if (0) {
      rc = GDEFCORE_ERR_INVALID;
    } else {
      rc = GDEFCORE_OK;
      (void)rev_doc(cat, row, target, &staged);' \
  '      if (rc == GDEFCORE_OK && (op->target_seq == 0 || op->target_seq > high)) {
        rc = GDEFCORE_ERR_INVALID;
      }
      if (rc == GDEFCORE_OK) {
        rc = rev_doc(cat, op->row, op->target_seq, &doc);
      }' \
  '      if (rc == GDEFCORE_OK) {
        (void)rev_doc(cat, op->row, op->target_seq, &doc);
      }'

# Plant 17: making the head active again does not put its projection back.
plant activate-cleared-no-head $ENT testRevisions \
  'Revisions.ActivateBringsBackAClearedEntity' \
  '      if (rc == GDEFCORE_OK && op->target_seq == high) {' \
  '      if (0 && rc == GDEFCORE_OK && op->target_seq == high) {'

# Plant 18: a revert sets the published flag (not the revert is to set).
plant revert-publishes $ENT testRevisions \
  'Revisions.RevertToCopiesATargetAndKeepsTheFlag' \
  '    case GDEFCORE_OP_REVERT:' \
  '    case GDEFCORE_OP_REVERT:
      st->pub = 1;'

# Plant 19: a revert with a target moves the pointer and writes no revision.
plant revert-writes-no-revision $ENT testRevisions \
  'Revisions.RevertToCopiesATargetAndKeepsTheFlag' \
  '    op->kind = GDEFCORE_OP_REVERT;
    op->target_seq = explicit_target ? target : seq - 1;' \
  '    op->kind = explicit_target ? GDEFCORE_OP_ACTIVATE : GDEFCORE_OP_REVERT;
    op->target_seq = explicit_target ? target : seq - 1;'

# Plant 20: the legacy revert steps back from the head, not from the active
# revision.
plant legacy-revert-from-head $ENT testRevisions \
  'Revisions.TheLegacyRevertStepsBackFromTheActiveRevision' \
  '    op->target_seq = explicit_target ? target : seq - 1;' \
  '    op->target_seq = explicit_target ? target : high - 1;'

# Plant 21: a changeset staged against a version the entity has left applies.
plant stale-version-accepted $ENT testRevisions \
  'Revisions.AStalePatchOfTheNewOperationsIsAConflict' \
  '      if (st.ver != op->base_ver) {' \
  '      if (0) {'

# Plant 22: a serialized changeset does not carry the version it was staged at.
plant patch-drops-version $ENT testRevisions \
  'Revisions.TheNewOperationsRoundTripThroughAPatch' \
  '    if (op->have_ver) {
      /* The version the op was staged against: a patch made against a' \
  '    if (0 && op->have_ver) {
      /* The version the op was staged against: a patch made against a'

# Plant 23: the form tree falls back to the published revision, so an entity
# restored but not published opens as an empty form.
plant form-tree-skips-active src/form/form.c testForm \
  'Form.TreeFallsBackToTheActiveRevision' \
  '    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_ACTIVE, id,' \
  '    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,'

# ---- the action vocabulary, the rating and the revision views (task 4) ----

ACC=src/access/access.c

# Plant 24: a `revisions` action is rated by its verb, so `revisions.read` is
# the read it looks like.
plant revisions-not-edit-class $ACC testActions \
  'ActionRating.RevisionsActionsAreAtLeastAnEdit' \
  '  if (edit || revisions) {' \
  '  if (edit || (0 && revisions)) {'

# Plant 25: `activate` is not a strong word, so `revisions.activate` is only
# an edit.
plant activate-not-strong $ACC testActions \
  'ActionRating.RevisionsActionsAreAtLeastAnEdit' \
  '"restore", "activate", "install",' \
  '"restore", "install",'

# Plant 26: a grant that can change the field its own condition tests is
# rated as its breadth says.
plant self-reference-not-raised $ACC testActions \
  'ActionRating.AGrantThatCanChangeItsOwnFieldIsRatedOneStepHigher Actions.TheMatrixSaysItInWords' \
  '  if (self && risk < GDEFCORE_ACCESS_RISK_HIGH) {' \
  '  if (0 && self && risk < GDEFCORE_ACCESS_RISK_HIGH) {'

# Plant 27: an entity-wide grant is not asked about every field.
plant self-reference-blind-to-whole-entity-grants $ACC testActions \
  'ActionRating.AGrantThatCanChangeItsOwnFieldIsRatedOneStepHigher' \
  '  return gdefcore_condition_tests_field(cond, field_len > 0 ? field : NULL,
      field_len);' \
  '  return gdefcore_condition_tests_field(cond, field_len > 0 ? field : "",
      field_len);'

# Plant 28: a grant of one field is asked about every field.
plant self-reference-ignores-the-grants-field $ACC testActions \
  'ActionRating.AGrantThatCanChangeItsOwnFieldIsRatedOneStepHigher' \
  '  return gdefcore_condition_tests_field(cond, field_len > 0 ? field : NULL,
      field_len);' \
  '  return gdefcore_condition_tests_field(cond, field != NULL ? NULL : NULL,
      field_len);'

# Plant 29: the matrix rates the grant higher and does not say why.
plant matrix-silent-on-self-reference $ACC testActions \
  'Actions.TheMatrixSaysItInWords' \
  '  if (rc == GDEFCORE_OK &&
      gdefcore_access_grant_changes_own_field(action, action_len, field,' \
  '  if (0 && rc == GDEFCORE_OK &&
      gdefcore_access_grant_changes_own_field(action, action_len, field,'

# Plant 30: the revision view does not ask `revisions.read`.
plant revision-view-skips-permission $ACC testActions \
  'Actions.RevisionViewNeedsThePermissionAndNotTheFlag' \
  '  if (rc != GDEFCORE_OK || !may_view ||' \
  '  if (rc != GDEFCORE_OK ||'

# Plant 31: the revision view takes any sequence for a revision.
plant revision-view-skips-sequence-check $ACC testActions \
  'Actions.RevisionViewRefusalsAreOneAnswer' \
  '    if (rc != GDEFCORE_OK || seq == 0 || seq > head) {' \
  '    if (rc != GDEFCORE_OK) {'

# Plant 32: the revision view does not apply the field-read grants.
plant revision-view-skips-field-filter $ACC testActions \
  'Actions.RevisionViewIsFilteredFieldByField' \
  '  if (field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {
    granted = field_granted(' \
  '  if (0 && field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {
    granted = field_granted('

# Plant 33: a personal field is shown as it is stored.
plant revision-view-shows-personal $ACC testActions \
  'Actions.RevisionViewNeverShowsAPersonalFieldAsStored' \
  '  if (field_is_personal(catalog, type_name, type_len, field, field_len)) {' \
  '  if (0 && field_is_personal(catalog, type_name, type_len, field, field_len)) {'

# Plant 34: a condition reads the head revision, the newest draft, where the
# permission to view history is asked of the entity as it is stored.
plant condition-reads-head src/condition/condition_eval.c testActions \
  'Actions.RevisionViewAsksTheActiveStateNotTheViewedRevision' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_ACTIVE,' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_DRAFT,'

plant_finish
