#!/bin/sh
#
# The access model's gate: the roles, permissions and principals a decision
# rests on are read from the store once for a configuration epoch and used by
# every decision made at that epoch (src/access/access.c, "the access model").
# Keeping them is right only if a copy is dropped when the store moves on and
# is never used for another catalog or another principal. Runs the Model tests
# on the real tree, then plants each defect in a COPY of the source by an exact
# text edit and requires the named tests to fail:
#
#   model-reused-across-epochs   a request keeps its copy after the epoch moved
#                                (a revoke, a grant or a role change inside the
#                                request, or another catalog's write, goes
#                                unseen)
#   catalog-model-of-another-epoch  the catalog hands a request the model it
#                                kept at an epoch the store has moved on from
#   model-not-of-its-catalog     a copy made for one catalog is used for
#                                another that is at the same epoch
#   failed-model-kept            a model some of whose reads failed is kept, and
#                                the next decision of the catalog is made on it
#   principal-not-keyed          the roles kept for one principal are given to
#                                the next one that asks, in one request (an
#                                acting principal) or between requests
#
# And one rule that no test can see happen: the epoch is read BEFORE the model
# is, never after (a write that lands in between then leaves the copy newer
# than the epoch it is filed under, which the next decision sees; read after,
# the copy would be older and filed as current). That is checked in the text of
# model_acquire() and shown to be seen by a copy with the order swapped.
#
# Usage: check-model.sh <make> <build-dir> [make args]

set -u

MAKE="${1:?usage: check-model.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-model.sh <make> <build-dir> [make args]}"
shift 2

. tools/plant-load.sh
plant_setup "$MAKE" "$BUILD_DIR" "$@"

plant_control testModel 'Model.*'

# A copy kept after the epoch moved: the request's memo is used on the owner
# alone.
plant model-reused-across-epochs src/access/access.c testModel \
  'Model.ARevokeInTheMiddleOfARequestIsSeenByTheNextDecision Model.AGrantInTheMiddleOfARequestIsSeenByTheNextDecision Model.AnotherCatalogsWriteIsSeenByTheNextDecision' \
  '    if (m != NULL && m->owner == cache->nonce && m->epoch == epoch &&
        epoch != 0) {' \
  '    if (m != NULL && m->owner == cache->nonce && epoch != 0) {'

# What the catalog kept, at an epoch the store has moved on from, handed to a
# request that has no copy of its own to drop.
plant catalog-model-of-another-epoch src/access/access.c testModel \
  'Model.ARevokeIsSeenByARequestThatHasNotDecidedYet' \
  '    if (cache->current != NULL && cache->current->epoch == epoch) {' \
  '    if (cache->current != NULL) {'

# A role whose read failed is left out of the model and the model is kept, so
# the catalog decides on a model that has lost a role until the epoch moves.
plant failed-model-kept src/access/access.c testModel \
  'Model.AModelThatFailedToReadIsNotKeptAndTheNextDecisionReadsItAgain' \
  '    many_free(catalog, f, 3);
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    m->nroles += 1;' \
  '    many_free(catalog, f, 3);
    if (rc != GDEFCORE_OK) {
      continue;
    }
    m->nroles += 1;'

# A copy made for another catalog, used for this one.
plant model-not-of-its-catalog src/access/access.c testModel \
  'Model.ARequestUsedWithTwoCatalogsIsDecidedByEachOnItsOwnStore' \
  '    if (m != NULL && m->owner == cache->nonce && m->epoch == epoch &&
        epoch != 0) {' \
  '    if (m != NULL && m->epoch == epoch && epoch != 0) {'

# The roles kept for one principal, given to whoever asks next.
plant principal-not-keyed src/access/access.c testModel \
  'Model.AnActingPrincipalIsNotGivenThePrincipalsGrants Model.OnePrincipalIsNeverGivenAnothersGrants' \
  '    if (kept->used && memcmp(kept->id, id, GDEFCORE_PUBLIC_ID_LEN) == 0) {' \
  '    if (kept->used) {'

# The epoch is read first. The check is on the line numbers, in
# model_acquire(), of the epoch read and of the build of the model.
epoch_first() {
  awk '
    /^static GDEFCORE_Result model_acquire\(/ { inside = 1 }
    inside && /gdefcore_epoch\(catalog, &epoch\)/ && !e { e = NR }
    inside && /model_build\(catalog, epoch/ && !b { b = NR }
    inside && /^}/ { inside = 0 }
    END { exit !(e && b && e < b) }
  ' "$1"
}

if epoch_first src/access/access.c; then
  plant_say "$PLANT_TAG: epoch-first: the epoch is read before the model is"
else
  plant_say "$PLANT_TAG: epoch-first: FAILED: model_acquire() does not read the epoch before it builds the model"
  PLANT_FAIL=1
fi
swapped=$(mktemp "${TMPDIR:-/tmp}/check-model.XXXXXX") || exit 1
sed -e 's/GDEFCORE_Result rc = gdefcore_epoch(catalog, &epoch);/GDEFCORE_Result rc = GDEFCORE_OK;/' \
    -e 's/^ *rc = model_build(catalog, epoch, cache->nonce, &m);/&\n  if (rc == GDEFCORE_OK) { rc = gdefcore_epoch(catalog, \&epoch); }/' \
    src/access/access.c > "$swapped"
if cmp -s "$swapped" src/access/access.c; then
  plant_say "$PLANT_TAG: epoch-read-after-model: FAILED: the plant did not change the source, so it shows nothing"
  PLANT_FAIL=1
elif epoch_first "$swapped"; then
  plant_say "$PLANT_TAG: epoch-read-after-model: FAILED: a copy that reads the epoch after the model was not refused"
  PLANT_FAIL=1
else
  plant_say "$PLANT_TAG: epoch-read-after-model: caught by the check of the order in model_acquire()"
fi
rm -f "$swapped"

plant_finish
