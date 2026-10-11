#!/bin/sh
#
# The session-revocation gate.
#
# After the epoch moves, a good token leaves the request anonymous. The
# same check with the epoch compare skipped must turn the gate red.
#
# Usage: check-account.sh <test_account-binary>

set -eu

BIN="${1:?usage: check-account.sh <test_account>}"

pass() {
  filter=$1
  if ! env -u GHOTI_ACCOUNT_PLANT "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-account: %s failed on the real tree\n' "$filter" >&2
    return 1
  fi
  return 0
}

red() {
  filter=$1
  plant=$2
  if GHOTI_ACCOUNT_PLANT="$plant" "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-account: planted %s passed\n' "$plant" >&2
    return 1
  fi
  printf 'check-account: planted %s turned the gate red\n' "$plant"
  return 0
}

pass 'Account.Revocation'
printf 'check-account: an old epoch leaves the request anonymous\n'
red 'Account.Revocation' skip-epoch
