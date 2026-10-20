#!/bin/sh
#
# The entity record gate (access-conditions story A5b, as decision 13 and
# story S6b leave it): the published flag, the version and the creator,
# beside the append-only revisions, and the draft, which is never a revision
# and which a publish applies only on the revision it was made from. The
# newest revision is always the content: there is no active-revision pointer.
# Runs the Revisions tests on the real tree, then plants each defect in a COPY
# of the source by an exact text edit and requires the named test to fail:
#
#   publish-forgets-flag        Revisions.PublishAppliesTheDraftAsOneRevision
#   publish-stores-publisher    Revisions.TheFirstDraftMakesTheEntityWithNoRevision
#   draft-creator-dropped       Revisions.TheFirstDraftMakesTheEntityWithNoRevision
#   draft-writes-revision       Revisions.ADraftIsNeverARevision
#   first-draft-makes-no-entity Revisions.TheFirstDraftMakesTheEntityWithNoRevision
#   clear-leaves-flag           Revisions.ClearUnpublishesDeletesAndDropsTheDraft
#   clear-keeps-draft           Revisions.ClearUnpublishesDeletesAndDropsTheDraft
#   published-view-ignores-flag Revisions.UnpublishClearsTheFlagAndNothingElse
#   current-view-reads-draft    Revisions.ADraftIsNeverARevision
#   save-leaves-unpublished     Revisions.SaveIsSaveAndPublish
#   save-keeps-draft            Revisions.SaveIsSaveAndPublish
#   create-reserves-nothing     Revisions.CreateReservesTheIdWithADraft
#   publish-skips-version       Revisions.TheVersionMovesWhereTheRevisionDoesNot
#   creator-follows-the-author  Revisions.TheCreatorIsSetOnce
#   draft-on-moved-head         Revisions.ADraftOnAMovedHeadIsRefused
#   noop-save-writes-revision   Revisions.ANoOpSaveWritesNoRevisionAndSaysSo
#   record-outside-its-write    EntityRollback.ATypeRecordIsWrittenInItsChangesetsWrite
#
# and story S6c's scheduled publish (a draft applied at a time T, once):
#
#   schedule-applies-early      Schedule.ADraftScheduledForTIsAppliedAtOrAfterTOnce
#   schedule-applies-twice      Schedule.ADraftScheduledForTIsAppliedAtOrAfterTOnce
#   schedule-job-not-reread     Schedule.AJobGoneSinceItWasListedIsNotApplied
#   schedule-conflict-retried   Schedule.AScheduledPublishOnAMovedHeadIsAConflict
#   draft-fits-skipped          Schedule.AScheduledDraftIsValidatedWhenItIsApplied
#   schedule-survives-clear     Schedule.ClearingAnEntityCancelsItsSchedule
#
#   unpublish-deletes           Revisions.UnpublishClearsTheFlagAndNothingElse
#   revert-leaves-deleted       Revisions.ClearUnpublishesDeletesAndDropsTheDraft
#   revert-publishes            Revisions.RevertToCopiesATargetAndKeepsTheFlag
#   revert-writes-no-revision   Revisions.RevertToCopiesATargetAndKeepsTheFlag
#   legacy-revert-wrong-step    Revisions.TheLegacyRevertStepsBackFromTheNewest
#   stale-version-accepted      Revisions.AStalePatchOfTheNewOperationsIsAConflict
#   patch-drops-version         Revisions.TheNewOperationsRoundTripThroughAPatch
#   form-tree-reads-published   Form.TreeFallsBackToTheCurrentRevision
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
#   condition-reads-draft       Actions.RevisionViewAsksTheCurrentStateNotTheViewedRevision
#   (the gate that a plaintext revision cannot become the content again is in
#    check-erasure.sh, which owns the personal-value fixtures:
#    Erasure.PlaintextRevisionCannotBecomeTheContentAgain)
#
# The activate plants (activate-moves-flag, activate-publisher-creator,
# activate-unrecorded, activate-cleared-no-head) went with activate, which
# access SPEC decision 13 retired; old-shape-read-unpublished went with core's
# own index, there being no row without a record when the port's entity
# record is the only one.
#
# Every test has a control (the same call on the other side of the rule
# answers differently), so a plant turning one red is a test seeing the
# defect, not a build failure.
#
# Usage: check-revisions.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testRevisions 'Revisions.*:Schedule.*'
plant_control testForm 'Form.TreeFallsBackToTheCurrentRevision'
plant_control testActions 'ActionVocabulary.*:ActionRating.*:Actions.*'
plant_control testEntity 'EntityRollback.*'

ENT=src/entity/entity.c
STO=src/entity/store.c

# A publish writes the publisher as the revision's author (defect 1.5.3: the
# author was lost, and a form publish, which has no actor, dropped it).
plant publish-stores-publisher $ENT testRevisions \
  'Revisions.TheFirstDraftMakesTheEntityWithNoRevision' \
  '        authored.who = who;
        authored.who_len = who_len;' \
  '        (void)who;
        (void)who_len;'

# A publish applies the draft and does not set the flag.
plant publish-forgets-flag $ENT testRevisions \
  'Revisions.PublishAppliesTheDraftAsOneRevision' \
  '    if (rc == GDEFCORE_OK) {
      rc = set_state(write, op, cs, 1, 0, when, &changed);
    }
    break;
  case GDEFCORE_OP_UNPUBLISH:' \
  '    if (rc == GDEFCORE_OK) {
      rc = set_state(write, op, cs, look.published, 0, when, &changed);
    }
    break;
  case GDEFCORE_OP_UNPUBLISH:'

# The first draft makes the entity with no creator, so `own` has no answer
# for a draft (and the publisher would not become it either).
plant draft-creator-dropped $ENT testRevisions \
  'Revisions.TheFirstDraftMakesTheEntityWithNoRevision' \
  '            op->type_name.n, op->id.p, op->id.n,
            cs->actor.p == NULL ? "" : cs->actor.p, cs->actor.n, when, NULL));' \
  '            op->type_name.n, op->id.p, op->id.n,
            "", 0, when, NULL));'

# A draft is written as a revision.
plant draft-writes-revision $ENT testRevisions \
  'Revisions.ADraftIsNeverARevision' \
  '      rc = seals_refuse(cs, &seals, gdefcore_ent_put_draft(cat, write, op->id.p,
          op->type_name.p, op->type_name.n, look.exists ? op->draft_base : 0,
          &op->staged, &seals));
    }' \
  '      int moved_ = 0;
      rc = look.exists
               ? gdefcore_ent_save_doc(cat, write, op->id.p, op->type_name.p,
                     op->type_name.n, op->draft_base, &meta, &op->staged,
                     &seals, &rev, &moved_)
               : gdefcore_ent_put_draft(cat, write, op->id.p, op->type_name.p,
                     op->type_name.n, 0, &op->staged, &seals);
    }'

# The first draft leaves the id reserved and makes no entity.
plant first-draft-makes-no-entity $ENT testRevisions \
  'Revisions.TheFirstDraftMakesTheEntityWithNoRevision' \
  '    if (!look.exists) {
      /* The first draft of an id its empty draft reserves is when the' \
  '    if (0 && !look.exists) {
      /* The first draft of an id its empty draft reserves is when the'

# A clear leaves the published flag set.
plant clear-leaves-flag $ENT testRevisions \
  'Revisions.ClearUnpublishesDeletesAndDropsTheDraft' \
  '      rc = set_state(write, op, cs, 0, 1, when, &changed);' \
  '      rc = set_state(write, op, cs, look.published, 1, when, &changed);'

# A clear leaves the draft, which a publish would then bring back.
plant clear-keeps-draft $ENT testRevisions \
  'Revisions.ClearUnpublishesDeletesAndDropsTheDraft' \
  '      if (rc == GDEFCORE_OK && look.has_draft) {
        rc = map_stor(gdefstor_draft_delete(write, op->id.p, op->id.n));
        if (rc == GDEFCORE_OK) {
          rc = drop_draft_author(write, op);
        }
        changed = 1;
      }
    } else if (look.reserved) {' \
  '    } else if (look.reserved) {'

# The reader's view ignores the flag.
plant published-view-ignores-flag $ENT testRevisions \
  'Revisions.UnpublishClearsTheFlagAndNothingElse' \
  '        (view == GDEFCORE_VIEW_PUBLISHED && !look.published)) {' \
  '        (0 && view == GDEFCORE_VIEW_PUBLISHED && !look.published)) {'

# Every view reads the draft, so what the entity is includes its draft.
plant current-view-reads-draft $ENT testRevisions \
  'Revisions.ADraftIsNeverARevision' \
  '  if (view == GDEFCORE_VIEW_DRAFT && look.has_draft) {' \
  '  if (look.has_draft) {'

# A save does not set the flag.
plant save-leaves-unpublished $ENT testRevisions \
  'Revisions.SaveIsSaveAndPublish' \
  '    if (rc == GDEFCORE_OK) {
      rc = set_state(write, op, cs, 1, 0, when, &changed);
    }
    break;
  }
  case GDEFCORE_OP_DRAFT: {' \
  '    if (rc == GDEFCORE_OK) {
      rc = set_state(write, op, cs, look.published, 0, when, &changed);
    }
    break;
  }
  case GDEFCORE_OP_DRAFT: {'

# A save leaves the draft it consumed.
plant save-keeps-draft $ENT testRevisions \
  'Revisions.SaveIsSaveAndPublish' \
  '      if (rc == GDEFCORE_OK && look.has_draft) {
        /* The save consumed the draft (stage_values()). */' \
  '      if (0 && rc == GDEFCORE_OK && look.has_draft) {
        /* The save consumed the draft (stage_values()). */'

# A create reserves nothing: the id has no draft, so nothing holds it.
plant create-reserves-nothing $ENT testRevisions \
  'Revisions.CreateReservesTheIdWithADraft' \
  '  rc = map_stor(gdefstor_draft_put(write, type_name, type_len, id,
      GDEFCORE_PUBLIC_ID_LEN, 0, NULL, 0));' \
  '  rc = GDEFCORE_OK;'

# A publish or a draft does not move the version (defect 1.5.2: the memo and
# the read set were keyed on a number that did not move).
plant publish-skips-version $ENT testRevisions \
  'Revisions.TheVersionMovesWhereTheRevisionDoesNot' \
  '  if (changed) {
    rc = gdefcore_ent_bump(write, op->id.p, NULL);
  }' \
  '  if (changed && op->kind != GDEFCORE_OP_PUBLISH &&
      op->kind != GDEFCORE_OP_DRAFT) {
    rc = gdefcore_ent_bump(write, op->id.p, NULL);
  }'

# The creator follows the newest revision's author.
plant creator-follows-the-author $ENT testRevisions \
  'Revisions.TheCreatorIsSetOnce' \
  '  if (look.creator_len > 0) {
    *out_creator = dup_span(catalog->alloc, look.creator, look.creator_len);' \
  '  if (look.revision > 0) {
    return gdefcore_entity_actor(catalog, id, id_len, out_creator, out_len);
  }
  if (look.creator_len > 0) {
    *out_creator = dup_span(catalog->alloc, look.creator, look.creator_len);'

# A draft made from an older revision is rebased onto the head and applied,
# overwriting what the head holds (CAP-S4: it is refused).
plant draft-on-moved-head $ENT testRevisions \
  'Revisions.ADraftOnAMovedHeadIsRefused' \
  '      if (look.exists && look.draft_base != look.revision) {
        *conflict = 1;
        return GDEFCORE_OK;
      }' \
  '      if (look.exists && look.draft_base != look.revision) {
        GDEFCORE_Doc moved_;
        memset(&moved_, 0, sizeof moved_);
        rc = gdefcore_ent_read_doc(cat, op->id.p, 0, 1, &moved_);
        if (rc == GDEFCORE_OK) {
          rc = gdefcore_ent_put_draft(cat, write, op->id.p, op->type_name.p,
              op->type_name.n, look.revision, &moved_, NULL);
        }
        gdefcore_ent_doc_free(cat->alloc, &moved_);
        if (rc != GDEFCORE_OK) {
          return rc;
        }
      }'

# A save of the values the entity has writes a revision: the items of a
# multiple field get new ids every save, so the port sees them all change.
# (Story S6d: the id is the item's own, from the doc, or by position.)
plant noop-save-writes-revision $STO testRevisions \
  'Revisions.ANoOpSaveWritesNoRevisionAndSaysSo' \
  '              f->name.n, id, &item));' \
  '              f->name.n, 0, &item));'

# A system record written outside its changeset's write: each type a changeset
# defines is written, and committed, in a write of its own ahead of the
# changeset's, so a changeset the port refuses still leaves the type.
plant record-outside-its-write $ENT testEntity \
  'EntityRollback.ATypeRecordIsWrittenInItsChangesetsWrite' \
  '  rc = map_stor(gdefstor_write_begin(changeset->catalog->store,
      (const char *)changeset->catalog->tenant,
      changeset->catalog->tenant_len, NULL, &write));' \
  '  for (i = 0; i < changeset->nops; i++) {
    GDEFCORE_Op * dop = &changeset->ops[i];
    GDEFSTOR_Write * own = NULL;
    if (dop->kind == GDEFCORE_OP_DEFINE && !dop->have_row &&
        gdefstor_write_begin(changeset->catalog->store,
            (const char *)changeset->catalog->tenant,
            changeset->catalog->tenant_len, NULL, &own) == GDEFSTOR_OK) {
      if (write_type(changeset->catalog, own, dop->machine.p, dop->machine.n,
              dop->type_kind, dop->decls, dop->ndecls, NULL, 0) == GDEFCORE_OK) {
        (void)gdefstor_write_commit(own);
      } else {
        gdefstor_write_abort(own);
      }
    }
  }
  rc = map_stor(gdefstor_write_begin(changeset->catalog->store,
      (const char *)changeset->catalog->tenant,
      changeset->catalog->tenant_len, NULL, &write));'

# An unpublish also deletes the entity.
plant unpublish-deletes $ENT testRevisions \
  'Revisions.UnpublishClearsTheFlagAndNothingElse' \
  '      rc = set_state(write, op, cs, 0, look.deleted, when, &changed);' \
  '      rc = set_state(write, op, cs, 0, 1, when, &changed);'

# A revert of a cleared entity leaves it deleted.
plant revert-leaves-deleted $ENT testRevisions \
  'Revisions.ClearUnpublishesDeletesAndDropsTheDraft' \
  '    if (rc == GDEFCORE_OK && look.deleted) {
      rc = set_state(write, op, cs, look.published, 0, when, &changed);
    }' \
  '    if (0 && rc == GDEFCORE_OK && look.deleted) {
      rc = set_state(write, op, cs, look.published, 0, when, &changed);
    }'

# A revert sets the published flag (the flag is not the revert's to set).
plant revert-publishes $ENT testRevisions \
  'Revisions.RevertToCopiesATargetAndKeepsTheFlag' \
  '    if (rc == GDEFCORE_OK && look.deleted) {
      rc = set_state(write, op, cs, look.published, 0, when, &changed);
    }' \
  '    if (rc == GDEFCORE_OK) {
      rc = set_state(write, op, cs, 1, 0, when, &changed);
    }'

# A revert writes no revision.
plant revert-writes-no-revision $ENT testRevisions \
  'Revisions.RevertToCopiesATargetAndKeepsTheFlag' \
  '    src = gdefstor_entity_revert(write, op->id.p, op->id.n, op->base_seq,
        op->target_seq, &meta, &rev);' \
  '    src = GDEFSTOR_OK;'

# The legacy revert copies the first revision, not the one before the newest.
plant legacy-revert-wrong-step $ENT testRevisions \
  'Revisions.TheLegacyRevertStepsBackFromTheNewest' \
  '      op->target_seq = explicit_target ? target : st.look.revision - 1;' \
  '      op->target_seq = explicit_target ? target : 1;'

# A changeset staged against a version the entity has left applies.
plant stale-version-accepted $ENT testRevisions \
  'Revisions.AStalePatchOfTheNewOperationsIsAConflict' \
  '  if (look.revision != op->base_seq || (op->have_ver && version != op->base_ver) ||' \
  '  if (look.revision != op->base_seq ||'

# A serialized changeset does not carry the version it was staged at.
plant patch-drops-version $ENT testRevisions \
  'Revisions.TheNewOperationsRoundTripThroughAPatch' \
  '    if (op->have_ver) {
      /* The version the op was staged against: a patch made against a' \
  '    if (0 && op->have_ver) {
      /* The version the op was staged against: a patch made against a'

# The form tree reads the published view, so an entity restored but not
# published opens as an empty form (it was form-tree-skips-current, on the
# fallback to the active revision that the draft view makes needless now).
plant form-tree-reads-published src/form/form.c testForm \
  'Form.TreeFallsBackToTheCurrentRevision' \
  '  GDEFCORE_Result rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_DRAFT,
      id, id_len, lang, lang_len, field->name, field->name_len, &texts, &lens,
      &count);' \
  '  GDEFCORE_Result rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED,
      id, id_len, lang, lang_len, field->name, field->name_len, &texts, &lens,
      &count);'

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

# Plant 34: a condition reads the draft, where the permission to view history
# is asked of the entity as it is stored: its newest revision.
plant condition-reads-draft src/condition/condition_eval.c testActions \
  'Actions.RevisionViewAsksTheCurrentStateNotTheViewedRevision' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_CURRENT,' \
  '  rc = gdefcore_entity_values(ctx->catalog, NULL, GDEFCORE_VIEW_DRAFT,'

# Scheduled publish (story S6c) ------------------------------------------------

SCH=src/entity/schedule.c

# A job applied before its time: the apply does not ask whether it is due.
plant schedule-applies-early $SCH testRevisions \
  'Schedule.ADraftScheduledForTIsAppliedAtOrAfterTOnce' \
  '  if (at > cs->job_now) {
    cs->job_outcome = GDEFCORE_SCHEDULE_EARLY;' \
  '  if (0 && at > cs->job_now) {
    cs->job_outcome = GDEFCORE_SCHEDULE_EARLY;'

# A job applied twice: the publish leaves its job row, so the next run
# publishes whatever draft the entity has by then.
plant schedule-applies-twice $SCH testRevisions \
  'Schedule.ADraftScheduledForTIsAppliedAtOrAfterTOnce' \
  '  rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1,
      cs->job_key.p, cs->job_key.n, NULL));
  if (rc == GDEFCORE_OK) {
    rc = id_put(write, canon, GDEFCORE_SCHEDULE_DONE, at);' \
  '  rc = GDEFCORE_OK;
  if (rc == GDEFCORE_OK) {
    rc = id_put(write, canon, GDEFCORE_SCHEDULE_DONE, at);'

# A job applied from what a runner listed, without reading the row again in
# the publish'"'"'s write: one cancelled, moved or applied since is applied.
plant schedule-job-not-reread $SCH testRevisions \
  'Schedule.AJobGoneSinceItWasListedIsNotApplied' \
  '  if (!found) {
    cs->job_outcome = GDEFCORE_SCHEDULE_GONE;' \
  '  if (0 && !found) {
    cs->job_outcome = GDEFCORE_SCHEDULE_GONE;'

# A moved head taken for a race with another writer: the job is tried again
# and stays pending instead of ending as the conflict it is.
plant schedule-conflict-retried $SCH testRevisions \
  'Schedule.AScheduledPublishOnAMovedHeadIsAConflict' \
  '    if (look.has_draft && look.exists && look.draft_base != look.revision) {' \
  '    if (0) {'

# A draft applied as it was written, not validated against its type as the
# type is when it is applied.
plant draft-fits-skipped $ENT testRevisions \
  'Schedule.AScheduledDraftIsValidatedWhenItIsApplied' \
  '        rc = draft_fits(cs, op);' \
  '        rc = GDEFCORE_OK;'

# A clear that leaves the entity's schedule: the publish at T brings the
# cleared entity back.
plant schedule-survives-clear $ENT testRevisions \
  'Schedule.ClearingAnEntityCancelsItsSchedule' \
  '    rc = gdefcore_ent_job_drop(cat, write, op->id.p);' \
  '    rc = GDEFCORE_OK;'

plant_finish
