#!/bin/sh
#
# The session-revocation gate: the real-tree half.
#
# After the security epoch moves (password change, log out everywhere,
# demotion), a good token leaves the request anonymous; a refused identifier
# removal ends nothing; a copy of the tenant under other bytes refuses the
# token. The planted half, which edits a copy of the source so the session is
# checked by signature only and requires these same tests to go red, is
# tools/check-defects.sh.
#
# Usage: check-account.sh <test_account-binary>

set -eu

BIN="${1:?usage: check-account.sh <test_account>}"
FILTER='Account.Revocation:Account.Epoch:Account.LogOut:Account.Demotion:Account.LastIdentifier:Account.Revert:Account.OtherTenant:Account.Expired:Account.Purpose'

if ! "$BIN" --gtest_filter="$FILTER" --gtest_brief=1
then
  printf 'check-account: the revocation tests failed on the real tree\n' >&2
  exit 1
fi
printf 'check-account: an old epoch leaves the request anonymous\n'
