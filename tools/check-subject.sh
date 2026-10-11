#!/bin/sh
#
# The erasure restore gate.
#
# A snapshot, then an erasure, then an import into an empty tenant still
# reads as [erased]. A planted restore that keeps the snapshot's ledger and
# drops a newer live row must turn the gate red.
#
# Usage: check-subject.sh <test_subject-binary>

set -eu

BIN="${1:?usage: check-subject.sh <test_subject>}"

pass() {
  filter=$1
  if ! env -u GHOTI_SUBJECT_PLANT "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-subject: %s failed on the real tree\n' "$filter" >&2
    return 1
  fi
  return 0
}

red() {
  filter=$1
  plant=$2
  if GHOTI_SUBJECT_PLANT="$plant" "$BIN" --gtest_filter="$filter" --gtest_brief=1
  then
    printf 'check-subject: planted %s passed\n' "$plant" >&2
    return 1
  fi
  printf 'check-subject: planted %s turned the gate red\n' "$plant"
  return 0
}

pass 'Subject.Gate'
printf 'check-subject: an erasure newer than the snapshot still reads as erased\n'
red 'Subject.Gate' snapshot-ledger
