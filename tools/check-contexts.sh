#!/bin/sh
#
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (C) 2026 Corey Pennycuff
# This file is part of Ghoti.io Defiant Core.
#
# The contexts-under-fibers gate (AD-25, AD-32).
#
# tests/test_contexts.cpp holds a context to one fiber at a time and renders a
# deep template on the smallest fiber cutil will make. This runs those tests
# on the real tree, then plants each defect named in the row by an exact edit
# of a scratch copy and requires the test named for it to fail:
#
#   two-fibers-in-one-context  the shadow owner stops telling fibers apart
#   reentry                    a held context may be run again
#   native-depth-unset         the runtime's depth budgets are never set
#   no-side-stack              the template is parsed and run on the caller's
#                              own (here 16 KiB) fiber stack
#
# The control is in the tests: the holder is never refused, a recursion
# inside the budget still renders, and a child that overflows its stack is
# reported as killed (Contexts.HarnessSeesACrash), so a fault in the planted
# copy cannot read as a pass.
#
# Usage: check-contexts.sh <make> <build-dir> [make args]

set -u
. "$(dirname "$0")/plant-fibers.sh"
EXE=testContexts
GATE='Contexts.*'
fibers_gate check-contexts "$GATE" "$@"

plant_control "$EXE" "$GATE"

plant two-fibers-in-one-context src/render/render_ctx.c "$EXE" \
  'Contexts.OneFiberAtATime' \
  '  return ctx->holder == gcu_fiber_current() &&
      pthread_equal(ctx->holder_thread, pthread_self());' \
  '  (void)ctx;
  return 1;'

plant reentry src/render/render_ctx.c "$EXE" \
  'Contexts.HeldContextIsNotReentered' \
  '  if (ctx->running) {' \
  '  if (0) {'

plant native-depth-unset src/render/render_ctx.c "$EXE" \
  'Contexts.DeepRecursionOnMinimumFiber' \
  '  grcore_options_set_native_stack_bytes(options, GDEFCORE_RENDER_NATIVE_STACK);
  grcore_options_set_guest_depth(options, GDEFCORE_RENDER_GUEST_DEPTH);
  grcore_options_set_native_depth(options, GDEFCORE_RENDER_NATIVE_DEPTH);' \
  '  (void)options;'

plant no-side-stack src/render/render.c "$EXE" \
  'Contexts.DeepNestOnMinimumFiber' \
  '  job.rc = GDEFCORE_ERR_INVALID;
  return side_stack_run(&job);' \
  '  job.rc = GDEFCORE_ERR_INVALID;
  return tang_job_run(&job);'

plant_finish
