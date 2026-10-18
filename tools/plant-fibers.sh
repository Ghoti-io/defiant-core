#!/bin/sh
#
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (C) 2026 Corey Pennycuff
# This file is part of Ghoti.io Defiant Core.
#
# Shared by check-wait.sh, check-contexts.sh and check-bus.sh. Sourced, not run.
#
# A gate is shown to work by planting the defect it names into a scratch copy
# of the library by an exact text edit, rebuilding the test, and requiring
# that the named test failed. Three ways such a plant passes for the wrong
# reason, and what this does about each:
#
#   - the edit did not apply (the anchor drifted): the anchor must match
#     exactly once and the edited file must differ from the original, or the
#     script stops;
#   - the binary was not rebuilt: the edited file is touched and the test
#     executable removed before the build;
#   - something else failed: the run counts only if gtest printed
#     "[  FAILED  ] <the named test>" and then finished its summary, so a
#     crash of the whole binary, or a different test failing, does not count.
#
# The caller sets nothing; it calls pl_init, then pl_control and pl_plant.
# Nothing here writes outside $ROOT/build/plants-fibers-<pid>, which is removed
# on exit; the pid keeps gates that share this file apart when make runs them
# in parallel.

pl_init() {
  MAKE_CMD="${1:?usage: <make> <build-dir> [make args]}"
  BUILD_DIR="${2:?usage: <make> <build-dir> [make args]}"
  shift 2
  PL_MARGS="-j${GHOTI_CHECK_JOBS:-$(n=$(nproc 2>/dev/null || echo 4); [ "$n" -gt 4 ] && n=4; echo "$n")} $*"
  unset MAKEFLAGS MFLAGS
  PL_ROOT=$(pwd)
  PL_SCRATCH="$PL_ROOT/build/plants-fibers-$$"
  PL_FAIL=0
  rm -rf "$PL_SCRATCH"
  mkdir -p "$PL_SCRATCH"
  # GHOTI_CHECK_KEEP=1 leaves the copies and their logs for reading.
  if [ -z "${GHOTI_CHECK_KEEP:-}" ]; then
    trap 'rm -rf "$PL_SCRATCH"' EXIT
  fi
}

pl_copy_tree() {
  dest=$1
  mkdir -p "$dest"
  for d in src include tests tools pkgconfig documentation examples; do
    [ -e "$PL_ROOT/$d" ] && cp -a "$PL_ROOT/$d" "$dest/"
  done
  cp -a "$PL_ROOT/Makefile" "$PL_ROOT/Doxyfile" "$dest/"
  pl_warm "$PL_ROOT" "$dest" "$BUILD_DIR"
}

# The copy also takes the main tree's build output for this build directory,
# with its timestamps, so make recompiles only what the plant edited (and,
# through the .d files, whatever includes an edited header) and relinks.
# Without it every plant was a cold rebuild of the whole library.
# GHOTI_CHECK_COLD=1 copies no build output, for comparing the two.
pl_warm() {
  [ -n "${GHOTI_CHECK_COLD:-}" ] && return 0
  case "$3" in /*|*..*|'') return 0 ;; esac
  [ -d "$1/$3" ] || return 0
  mkdir -p "$2/$(dirname "$3")"
  cp -a "$1/$3" "$2/$3"
}

# pl_build <dir> <exe>: build one test executable in <dir>.
pl_build() {
  ( cd "$1" && "$MAKE_CMD" --no-print-directory "$BUILD_DIR/apps/$2" $PL_MARGS ) \
    > "$1.build.log" 2>&1
}

# pl_run <dir> <exe> <filter> <log>: run the named tests; the exit status is
# the test binary's.
pl_run() {
  ( cd "$1" && LD_LIBRARY_PATH="$1/$BUILD_DIR/apps" \
    timeout "${GHOTI_CHECK_TIMEOUT:-120}" "$BUILD_DIR/apps/$2" --gtest_filter="$3" --gtest_brief=1 ) > "$4" 2>&1
}

# pl_control <exe> <filter> <label>: the unpatched copy builds and passes.
pl_control() {
  exe=$1 filter=$2 label=$3
  PL_CONTROL="$PL_SCRATCH/control"
  [ -d "$PL_CONTROL" ] || pl_copy_tree "$PL_CONTROL"
  if ! pl_build "$PL_CONTROL" "$exe"; then
    printf '%s: the CONTROL (unpatched) copy does not build; log:\n' "$label" >&2
    grep -E 'error|Error' "$PL_CONTROL.build.log" | cut -c1-300 | tail -10 >&2
    exit 1
  fi
  if ! pl_run "$PL_CONTROL" "$exe" "$filter" "$PL_SCRATCH/control.$exe.log"; then
    printf '%s: the CONTROL (unpatched) copy fails %s; log:\n' "$label" "$filter" >&2
    tail -30 "$PL_SCRATCH/control.$exe.log" >&2
    exit 1
  fi
  printf '%s: control passes (%s)\n' "$label" "$filter"
}

# pl_plant <label> <name> <file> <exe> <filter> <expect> <old> <new>
# <expect> is a space-separated list of gtest names that must each fail.
pl_plant() {
  label=$1 name=$2 file=$3 exe=$4 filter=$5 expect=$6 old=$7 new=$8
  dir="$PL_SCRATCH/$name"
  cp -a "$PL_CONTROL" "$dir"
  python3 - "$dir/$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if text.count(old) != 1:
    sys.stderr.write("anchor matched %d times in %s\n" % (text.count(old), path))
    sys.exit(3)
if old == new:
    sys.stderr.write("the edit is a no-op\n")
    sys.exit(4)
open(path, "w").write(text.replace(old, new, 1))
PY
  rc=$?
  if [ $rc -ne 0 ]; then
    printf '%s: %s: THE EDIT DID NOT APPLY, nothing was tested\n' "$label" "$name" >&2
    PL_FAIL=1
    return
  fi
  if cmp -s "$PL_ROOT/$file" "$dir/$file"; then
    printf '%s: %s: the edited file equals the original\n' "$label" "$name" >&2
    PL_FAIL=1
    return
  fi
  touch "$dir/$file"
  rm -f "$dir/$BUILD_DIR/apps/$exe" "$dir/$BUILD_DIR"/apps/*.a "$dir/$BUILD_DIR"/apps/*.so*
  if ! pl_build "$dir" "$exe"; then
    printf '%s: %s: the planted copy does not build; log:\n' "$label" "$name" >&2
    grep -E 'error|Error' "$dir.build.log" | cut -c1-300 | tail -10 >&2
    PL_FAIL=1
    return
  fi
  log="$dir.run.log"
  if pl_run "$dir" "$exe" "$filter" "$log"; then
    printf '%s: %s: the tests PASSED with the defect planted\n' "$label" "$name" >&2
    PL_FAIL=1
    return
  fi
  if ! grep -q 'tests\? from .* ran\.' "$log"; then
    printf '%s: %s: the binary died before its summary; that is not a catch. Log:\n' "$label" "$name" >&2
    tail -20 "$log" >&2
    PL_FAIL=1
    return
  fi
  missing=
  for t in $expect; do
    grep -q "^\[  FAILED  \] $t\b" "$log" || missing="$missing $t"
  done
  if [ -n "$missing" ]; then
    printf '%s: %s: the run failed, but not in:%s. Log:\n' "$label" "$name" "$missing" >&2
    tail -20 "$log" >&2
    PL_FAIL=1
    return
  fi
  for t in $expect; do
    printf '%s: %s: caught by %s\n' "$label" "$name" "$t"
  done
}

pl_finish() {
  if [ "$PL_FAIL" -ne 0 ]; then
    printf '%s: a plant was not caught\n' "$1" >&2
    exit 1
  fi
  printf '%s: every planted defect turned its gate red\n' "$1"
}
