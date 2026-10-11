#!/bin/sh
#
# The access-filter bypass gate and the same-grants gate.
#
# Each one runs on the real tree, then again with a plant that must turn
# it red. A plant that still passes means the gate cannot fail.
#
# Usage: check-access.sh <test_access-binary>

set -eu

BIN="${1:?usage: check-access.sh <test_access>}"

pass() {
  filter=$1
  if ! env -u GHOTI_ACCESS_PLANT "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-access: %s failed on the real tree\n' "$filter" >&2
    return 1
  fi
  return 0
}

red() {
  filter=$1
  plant=$2
  if GHOTI_ACCESS_PLANT="$plant" "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-access: planted %s passed\n' "$plant" >&2
    return 1
  fi
  printf 'check-access: planted %s turned the gate red\n' "$plant"
  return 0
}

pass 'Access.Bypass'
printf 'check-access: a principal who may see nothing matches a missing id\n'
pass 'Access.RenderKey'
printf 'check-access: two principals with an own condition have different keys\n'
red 'Access.Bypass' skip
red 'Access.RenderKey' omit
