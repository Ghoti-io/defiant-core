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

. "$(dirname "$0")/plant-load.sh"
PLANT_TAG=check-defects
# A plant runs both test programs whole, as the control does: the named tests
# have to be among the failures, and any others are reported beside them.
PLANT_RUN_FILTER='*'

plant_hook_control() { # exe filter
  plant_say "check-defects: control passes (testAccount, testForm)"
}

plant_hook_caught() { # name expect log
  printf 'check-defects: %s: caught by' "$1"
  for t in $2; do printf ' %s' "$t"; done
  printf '\n'
  extra=$(grep '^\[  FAILED  \] [A-Za-z]*\.[A-Za-z]* ' "$3" | sed 's/^\[  FAILED  \] \([^ ]*\) .*/\1/' | sort -u)
  for t in $2; do extra=$(printf '%s\n' "$extra" | grep -v -x "$t"); done
  if [ -n "$extra" ]; then
    printf 'check-defects: %s: also red (collateral, not counted): %s\n' \
      "$1" "$(printf '%s' "$extra" | tr '\n' ' ')"
  fi
}

plant_hook_done() {
  printf 'check-defects: every planted defect turned its named test red\n'
}

plant_setup "$@"
plant_control 'testAccount testForm' '*'

# ---- Session revocation: a session checked by signature only ----------------
# Every trigger test goes red when the epoch compare is skipped.
plant epoch-ignored src/account/account.c testAccount \
  'Account.Revocation Account.Epoch Account.LogOut Account.Demotion Account.Revert' \
  '  if (token_epoch != current) {' \
  '  if (0 && token_epoch != current) {'

# Each trigger, taken alone: the trigger that stops moving the epoch.
plant password-keeps-epoch src/account/account.c testAccount \
  'Account.Revocation Account.Epoch' \
  '        (unsigned long long)(epoch + 1u));
    if (wrote <= 0 || (size_t)wrote >= sizeof next_text) {' \
  '        (unsigned long long)(epoch));
    if (wrote <= 0 || (size_t)wrote >= sizeof next_text) {'

plant logout-keeps-epoch src/account/account.c testAccount \
  'Account.Revocation Account.LogOut' \
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

plant demotion-keeps-epoch src/account/account.c testAccount \
  'Account.Revocation Account.Demotion' \
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

# ---- CSRF and replay: associated data that does not bind the form ---------
plant form-session-unbound src/form/form.c testForm \
  'Form.OtherSession' \
  '  uint8_t * aad = NULL;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);' \
  '  uint8_t * aad = NULL;
  session_len = 0;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);'

plant form-base-unchecked src/form/form.c testForm \
  'Form.StaleBase Form.Replay' \
  '  if (current != opened.base) {' \
  '  if (0 && current != opened.base) {'

# The tenant is bound twice: in the session token's associated data and in the
# form token's. A copy of the tenant under other tenant bytes (the same
# account, session and form) is refused by whichever layer is intact, so
# dropping the tenant from ONE layer is invisible to every public call and
# cannot be a plant. Dropping it from the session layer is seen by
# Account.OtherTenant; dropping it from both is seen by Form.OtherTenant.
plant session-tenant-unbound src/account/account.c testAccount \
  'Account.OtherTenant' \
  '  *out = tenant;
  return GDEFCORE_OK;' \
  '  *out = (const uint8_t *)"x";
  *out_len = 1;
  (void)tenant;
  return GDEFCORE_OK;'

plantm tenant-unbound-everywhere testForm \
  'Form.OtherTenant' \
  src/account/account.c \
  '  *out = tenant;
  return GDEFCORE_OK;' \
  '  *out = (const uint8_t *)"x";
  *out_len = 1;
  (void)tenant;
  return GDEFCORE_OK;' \
  src/form/form.c \
  '  uint8_t * aad = NULL;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);' \
  '  uint8_t * aad = NULL;
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  tenant_len = 0;'

plant_finish
