#!/bin/sh
#
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (C) 2026 Corey Pennycuff
# This file is part of Ghoti.io Defiant Core.
#
# Shared by check-wait.sh, check-contexts.sh and check-bus.sh. Sourced, not run.
#
# The three gates plant a defect into a scratch copy of the library by an exact
# text edit, rebuild the test, and require that the named test failed, with
# the helpers all the plant gates share (defiant-storage's plant-lib.sh, loaded
# by plant-load.sh). What is particular to these three is set here:
#
#   - each prints its own label in front of every line;
#   - a plant runs the whole gate filter (not only the tests it names), with
#     the test program built first and then run on its own under a time limit
#     (GHOTI_CHECK_TIMEOUT, 120 seconds), so a defect that makes a fiber wait
#     for ever is a failed plant and not a gate that never ends.
#
# Usage, after sourcing this file:
#
#   fibers_gate <label> <gate filter> "$@"      # "$@": <make> <build-dir> [make args]
#   plant_control <exe> <gate filter>
#   plant <name> <file> <exe> '<tests that must fail>' <old> <new>
#   plant_finish

. "$(dirname "$0")/plant-load.sh"

fibers_gate() {
  PLANT_TAG=$1
  PLANT_RUN_FILTER=$2
  shift 2
  PLANT_TIMEOUT="${GHOTI_CHECK_TIMEOUT:-120}"
  plant_setup "$@"
}

plant_hook_control() { # exe filter
  plant_say "$PLANT_TAG: control passes ($2)"
}

plant_hook_caught() { # name expect log
  for t in $2; do
    printf '%s: %s: caught by %s\n' "$PLANT_TAG" "$1" "$t"
  done
}

plant_hook_done() {
  printf '%s: every planted defect turned its gate red\n' "$PLANT_TAG"
}
