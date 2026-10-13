#!/bin/sh
#
# The form submit gate: the real-tree half.
#
# A valid token stores a draft and leaves the published projection absent. A
# form under another session or tenant, a replayed form, a form on a stale
# base revision, a tampered form and an expired one are refused. The planted
# half, which edits a copy of the source so the session, the tenant or the
# base revision no longer binds the form and requires the matching test to go
# red, is tools/check-defects.sh.
#
# Usage: check-form.sh <test_form-binary>

set -eu

BIN="${1:?usage: check-form.sh <test_form>}"
FILTER='Form.Gate:Form.OtherSession:Form.OtherTenant:Form.Replay:Form.StaleBase:Form.Tamper:Form.Expired:Form.Unsigned'

if ! "$BIN" --gtest_filter="$FILTER" --gtest_brief=1
then
  printf 'check-form: the form tests failed on the real tree\n' >&2
  exit 1
fi
printf 'check-form: a valid token stores a draft and leaves the published projection absent\n'
