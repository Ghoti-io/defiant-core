#!/bin/sh
#
# The form submit gate.
#
# A valid token stores a draft and leaves the published projection absent.
# A planted submit that skips the tag check must turn the gate red.
#
# Usage: check-form.sh <test_form-binary>

set -eu

BIN="${1:?usage: check-form.sh <test_form>}"

pass() {
  filter=$1
  if ! env -u GHOTI_FORM_PLANT "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-form: %s failed on the real tree\n' "$filter" >&2
    return 1
  fi
  return 0
}

red() {
  filter=$1
  plant=$2
  if GHOTI_FORM_PLANT="$plant" "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-form: planted %s passed\n' "$plant" >&2
    return 1
  fi
  printf 'check-form: planted %s turned the gate red\n' "$plant"
  return 0
}

pass 'Form.Gate'
printf 'check-form: a valid token stores a draft and leaves the published projection absent\n'
red 'Form.Gate' skip-tag
