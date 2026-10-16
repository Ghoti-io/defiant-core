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
# Every test has a control (the same call on the other side of the rule
# answers differently), so a plant turning one red is a test seeing the
# defect, not a build failure. Later tasks of the story add their plants here.
#
# Usage: check-revisions.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testRevisions 'Revisions.*'

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

plant_finish
