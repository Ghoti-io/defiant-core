#!/bin/sh
#
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (C) 2026 Corey Pennycuff
# This file is part of Ghoti.io Defiant Core.
#
# The transaction-wait gate (AD-25, AD-32).
#
# A fiber that awaits a non-database operation while it holds a write
# transaction must have that write rolled back. Three routes out of a held
# write exist in the scheduler: an offload, a yield, and a turn that ends
# while the write is still held. Each has a test in tests/test_matrix.cpp.
# This runs them on the real tree, then plants the defect named in the row -
# the wait that does not roll the write back - by an exact edit of a scratch
# copy of src/sched/sched.c, once for the shared rollback and once per route,
# and requires the named test to fail.
#
# Usage: check-wait.sh <make> <build-dir> [make args]
#   e.g. check-wait.sh make build/linux/release PREFIX=/path

set -u
. "$(dirname "$0")/plant-fibers.sh"
pl_init "$@"
L=check-wait
EXE=testMatrix
GATE='Write.OtherWaitAbortsThePortWrite:Write.YieldWhileHoldingAbortsThePortWrite:Write.TurnAgainWhileHoldingAbortsThePortWrite'

pl_control "$EXE" "$GATE" "$L"

# Every route calls abort_write; making it keep the write is the defect in
# the row ("is not rolled back") with no route left out.
pl_plant "$L" no-rollback src/sched/sched.c "$EXE" "$GATE" \
  'Write.OtherWaitAbortsThePortWrite Write.YieldWhileHoldingAbortsThePortWrite Write.TurnAgainWhileHoldingAbortsThePortWrite' \
  '  gdefcore_request_set_write(request, NULL);
  gdefcore_request_set_status(request, GDEFCORE_ERR_INVALID);
}' \
  '  (void)0;
}'

# One route at a time: the rollback is absent on that route only. The turn
# route ends the fiber with the write held rather than looping, so the test
# fails by its own assertion and not by hanging.
pl_plant "$L" offload-holds-write src/sched/sched.c "$EXE" "$GATE" \
  'Write.OtherWaitAbortsThePortWrite' \
  '  if (gdefcore_request_write(slot->request) != NULL) {
    abort_write(slot->request);
    return GDEFCORE_ERR_INVALID;
  }
  if (deadline_passed(slot->request)) {' \
  '  if (deadline_passed(slot->request)) {'

pl_plant "$L" yield-holds-write src/sched/sched.c "$EXE" "$GATE" \
  'Write.YieldWhileHoldingAbortsThePortWrite' \
  '  if (gdefcore_request_write(slot->request) != NULL) {
    abort_write(slot->request);
    return GDEFCORE_ERR_INVALID;
  }
  slot->phase = GDEFCORE_SCHED_PHASE_TURN;
  gcu_fiber_yield();
  return GDEFCORE_OK;' \
  '  slot->phase = GDEFCORE_SCHED_PHASE_TURN;
  gcu_fiber_yield();
  return GDEFCORE_OK;'

pl_plant "$L" turn-holds-write src/sched/sched.c "$EXE" "$GATE" \
  'Write.TurnAgainWhileHoldingAbortsThePortWrite' \
  '    if (gdefcore_request_write(slot->request) != NULL) {
      abort_write(slot->request);
      return;
    }
    slot->phase = GDEFCORE_SCHED_PHASE_TURN;' \
  '    if (gdefcore_request_write(slot->request) != NULL) {
      return;
    }
    slot->phase = GDEFCORE_SCHED_PHASE_TURN;'

pl_finish "$L"
