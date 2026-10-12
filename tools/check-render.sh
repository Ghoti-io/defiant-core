#!/bin/sh
#
# The render scope gate.
#
# A template that exceeds a tiny scope returns the prefix it had already
# written, and not the rest. A planted render that skips the scope must
# turn the gate red. The plant lives in the test, not in the library.
#
# Usage: check-render.sh <test_render-binary>

set -eu

BIN="${1:?usage: check-render.sh <test_render>}"

pass() {
  filter=$1
  if ! env -u GHOTI_RENDER_PLANT "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-render: %s failed on the real tree\n' "$filter" >&2
    return 1
  fi
  return 0
}

red() {
  filter=$1
  plant=$2
  if GHOTI_RENDER_PLANT="$plant" "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-render: planted %s passed\n' "$plant" >&2
    return 1
  fi
  printf 'check-render: planted %s turned the gate red\n' "$plant"
  return 0
}

pass 'Render.Gate'
printf 'check-render: a tiny scope returns the prefix and not the rest\n'
red 'Render.Gate' skip-scope
