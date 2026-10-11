#!/bin/sh
#
# The cross-tenant gate.
#
# An entity that exists only on tenant A is absent from tenant B. The same
# check, reading with A's storage key while claiming to be B, must turn
# the gate red.
#
# Usage: check-inst.sh <test_inst-binary>

set -eu

BIN="${1:?usage: check-inst.sh <test_inst>}"

pass() {
  filter=$1
  if ! env -u GHOTI_INST_PLANT "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-inst: %s failed on the real tree\n' "$filter" >&2
    return 1
  fi
  return 0
}

red() {
  filter=$1
  plant=$2
  if GHOTI_INST_PLANT="$plant" "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-inst: planted %s passed\n' "$plant" >&2
    return 1
  fi
  printf 'check-inst: planted %s turned the gate red\n' "$plant"
  return 0
}

pass 'Inst.Gate'
printf 'check-inst: tenant B does not show tenant A\n'
red 'Inst.Gate' other-key
