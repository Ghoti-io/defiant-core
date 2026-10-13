#!/bin/sh
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io Defiant Core. See COPYING.LESSER.
#
# The session-revocation gate and the CSRF-and-replay gate, each shown to
# catch a defect planted in the real source.
#
# Copies the tree, proves the unpatched copy passes (the control), then for
# each plant applies one exact textual edit to the copy's source, rebuilds,
# and requires that the NAMED test failed. A crash of the whole binary does
# not count, and neither does a different test failing. An edit that does not
# match exactly once is an error: a stale anchor would leave an unpatched
# copy that passes, and the plant would read as caught for the wrong reason.
#
# Nothing here lives in src/: the library carries no plant switch.
#
# Usage: check-defects.sh <make> <build-dir> [make args]
#   e.g. tools/check-defects.sh make build/linux/release PREFIX=/p

set -u

MAKE_CMD="${1:?usage: check-defects.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-defects.sh <make> <build-dir> [make args]}"
shift 2
MARGS="-j${GHOTI_CHECK_JOBS:-$(n=$(nproc 2>/dev/null || echo 4); [ "$n" -gt 4 ] && n=4; echo "$n")} $*"

unset MAKEFLAGS MFLAGS

ROOT=$(pwd)
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXE_EXT=.exe ;; *) EXE_EXT= ;; esac
SCRATCH="$ROOT/build/defects"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

copy_tree() {
  dest=$1
  mkdir -p "$dest"
  for d in src include tests tools pkgconfig documentation examples; do
    [ -e "$ROOT/$d" ] && cp -a "$ROOT/$d" "$dest/"
  done
  cp -a "$ROOT/Makefile" "$ROOT/Doxyfile" "$dest/"
  rm -rf "$dest/tests/fuzz/corpus"
}

fail=0

copy_tree "$SCRATCH/control"
if ! ( cd "$SCRATCH/control" && "$MAKE_CMD" --no-print-directory test TEST_GATES= \
    TEST_EXECUTABLES="$BUILD_DIR/apps/testAccount$EXE_EXT $BUILD_DIR/apps/testForm$EXE_EXT" \
    $MARGS ) > "$SCRATCH/control.log" 2>&1; then
  printf 'check-defects: the CONTROL (unpatched) copy fails its own tests, so no\n' >&2
  printf 'result below would mean anything. Its log:\n' >&2
  tail -40 "$SCRATCH/control.log" >&2
  exit 1
fi
printf 'check-defects: control passes (testAccount, testForm)\n'

# A plant is one or more exact edits to a copy of the control, then a run.
#   begin <name>
#   edit <file> <old> <new>          (once per edit; exactly one match each)
#   run <exe> "<Suite.Test> ..."     (every named test must have failed)
dir=
name=
armed=0

begin() {
  name=$1
  dir="$SCRATCH/$name"
  armed=1
  cp -a "$SCRATCH/control" "$dir"
}

edit() {
  file=$1 old=$2 new=$3
  [ "$armed" -eq 1 ] || return
  python3 - "$dir/$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if text.count(old) != 1:
    sys.stderr.write("anchor matched %d times in %s\n" % (text.count(old), path))
    sys.exit(3)
open(path, "w").write(text.replace(old, new, 1))
PY
  rc=$?
  if [ $rc -ne 0 ]; then
    printf 'check-defects: %s: THE PATCH DID NOT APPLY (stale anchor), nothing was tested\n' "$name" >&2
    fail=1
    armed=0
    return
  fi
  if cmp -s "$ROOT/$file" "$dir/$file"; then
    printf 'check-defects: %s: the patched file equals the original\n' "$name" >&2
    fail=1
    armed=0
    return
  fi
  touch "$dir/$file"
}

run() {
  exe=$1 expect=$2
  [ "$armed" -eq 1 ] || return
  armed=0
  rm -f "$dir/$BUILD_DIR"/apps/test* "$dir/$BUILD_DIR"/apps/*.a \
    "$dir/$BUILD_DIR"/apps/*.so*
  ( cd "$dir" && "$MAKE_CMD" --no-print-directory test TEST_GATES= \
      TEST_EXECUTABLES="$BUILD_DIR/apps/$exe$EXE_EXT" $MARGS ) > "$dir.log" 2>&1
  status=$?
  if [ $status -eq 0 ]; then
    printf 'check-defects: %s: the tests PASSED with the defect planted\n' "$name" >&2
    fail=1
    return
  fi
  if ! grep -q '^\[==========\] .* ran\.' "$dir.log"; then
    printf 'check-defects: %s: the binary did not finish a run (build error or crash), which proves nothing - read %s\n' \
      "$name" "$dir.log" >&2
    tail -30 "$dir.log" >&2
    fail=1
    return
  fi
  missed=
  for t in $expect; do
    if ! grep -q "^\[  FAILED  \] $t " "$dir.log"; then
      missed="$missed $t"
    fi
  done
  if [ -n "$missed" ]; then
    printf 'check-defects: %s: the run failed, but not in:%s - read %s\n' \
      "$name" "$missed" "$dir.log" >&2
    grep '^\[  FAILED  \] ' "$dir.log" | sort -u >&2
    fail=1
    return
  fi
  printf 'check-defects: %s: caught by' "$name"
  for t in $expect; do printf ' %s' "$t"; done
  printf '\n'
  extra=$(grep '^\[  FAILED  \] [A-Za-z]*\.[A-Za-z]* ' "$dir.log" | sed 's/^\[  FAILED  \] \([^ ]*\) .*/\1/' | sort -u)
  for t in $expect; do extra=$(printf '%s\n' "$extra" | grep -v -x "$t"); done
  if [ -n "$extra" ]; then
    printf 'check-defects: %s: also red (collateral, not counted): %s\n' \
      "$name" "$(printf '%s' "$extra" | tr '\n' ' ')"
  fi
}

# ---- Session revocation: a session checked by signature only ----------------
# Every trigger test goes red when the epoch compare is skipped.
begin epoch-ignored
edit src/account/account.c \
  '  if (token_epoch != current) {' \
  '  if (0 && token_epoch != current) {'
run testAccount \
  'Account.Revocation Account.Epoch Account.LogOut Account.Demotion Account.Revert'

# Each trigger, taken alone: the trigger that stops moving the epoch.
begin password-keeps-epoch
edit src/account/account.c \
  '        (unsigned long long)(epoch + 1u));
    if (wrote <= 0 || (size_t)wrote >= sizeof next_text) {' \
  '        (unsigned long long)(epoch));
    if (wrote <= 0 || (size_t)wrote >= sizeof next_text) {'
run testAccount 'Account.Revocation Account.Epoch'

begin logout-keeps-epoch
edit src/account/account.c \
  '  rc = confirm_user(catalog, canon, confirmation, confirmation_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return bump_epoch(catalog, canon, NULL);' \
  '  rc = confirm_user(catalog, canon, confirmation, confirmation_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return GDEFCORE_OK;'
run testAccount 'Account.Revocation Account.LogOut'

begin demotion-keeps-epoch
edit src/account/account.c \
  '      role_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return bump_epoch(catalog, canon, NULL);' \
  '      role_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return GDEFCORE_OK;'
run testAccount 'Account.Revocation Account.Demotion'

# ---- CSRF and replay: associated data that does not bind the form ---------
begin form-session-unbound
edit src/form/form.c \
  '  uint8_t * aad = NULL;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);' \
  '  uint8_t * aad = NULL;
  session_len = 0;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);'
run testForm 'Form.OtherSession'

begin form-base-unchecked
edit src/form/form.c \
  '  if (current != opened.base) {' \
  '  if (0 && current != opened.base) {'
run testForm 'Form.StaleBase Form.Replay'

# The tenant is bound twice: in the session token's associated data and in the
# form token's. A copy of the tenant under other tenant bytes (the same
# account, session and form) is refused by whichever layer is intact, so
# dropping the tenant from ONE layer is invisible to every public call and
# cannot be a plant. Dropping it from the session layer is seen by
# Account.OtherTenant; dropping it from both is seen by Form.OtherTenant.
begin session-tenant-unbound
edit src/account/account.c \
  '  *out = tenant;
  return GDEFCORE_OK;' \
  '  *out = (const uint8_t *)"x";
  *out_len = 1;
  (void)tenant;
  return GDEFCORE_OK;'
run testAccount 'Account.OtherTenant'

begin tenant-unbound-everywhere
edit src/account/account.c \
  '  *out = tenant;
  return GDEFCORE_OK;' \
  '  *out = (const uint8_t *)"x";
  *out_len = 1;
  (void)tenant;
  return GDEFCORE_OK;'
edit src/form/form.c \
  '  uint8_t * aad = NULL;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);' \
  '  uint8_t * aad = NULL;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  tenant_len = 0;'
run testForm 'Form.OtherTenant'

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf 'check-defects: every planted defect turned its named test red\n'
