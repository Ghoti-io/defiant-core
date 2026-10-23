#!/bin/sh
#
# Fail if the veto on template writes, or the per-kind edit permission that went
# with it, is named anywhere in this tree. Nothing denies (access SPEC decision
# 1): the hook, its argument struct and the function that fired it as a veto
# are gone, and a name left in a header, a document or a test is a way back.
#
# Usage: check-noveto.sh <root>
#   <root> is the library's root. The script then plants a header that names
#   the hook and requires that copy to fail.
#
# The names are written in halves so that this file does not match itself.

set -eu

ROOT="${1:?usage: check-noveto.sh <root>}"
NAMES='TEMPLATE_''WRITE|template-''write|fire_''veto|Template_''Write_''Hook|TEMPLATE_EDIT_''PREFIX|template_edit_''name|template_edit_''label|template_kind_''declare|template_declare_''touched'

# The files that could name them, one per line. Nothing found means the
# gate is looking at nothing.
files_of() {
  tree=$1
  for d in src include tests tools documentation examples; do
    [ -d "$tree/$d" ] && find "$tree/$d" -type f
  done
  for f in Makefile README.md; do
    [ -f "$tree/$f" ] && printf '%s\n' "$tree/$f"
  done
  return 0
}

scan_tree() {
  tree=$1
  list=$(files_of "$tree")
  if [ -z "$list" ]; then
    printf 'check-noveto: nothing to scan under %s; this gate is measuring nothing\n' \
      "$tree" >&2
    return 2
  fi
  # shellcheck disable=SC2086
  hits=$(printf '%s\n' "$list" | xargs grep -nE "$NAMES" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    printf 'check-noveto: the retired veto on template writes is named:\n%s\n' "$hits" >&2
    return 1
  fi
  printf 'check-noveto: %d files, none names the retired veto\n' \
    "$(printf '%s\n' "$list" | wc -l)"
  return 0
}

rc=0
scan_tree "$ROOT" || rc=$?
if [ "$rc" -ne 0 ]; then
  exit 1
fi

plant=$(mktemp -d)
trap 'rm -rf "$plant"' EXIT
cp -a "$ROOT/include" "$plant/include"
target=$(find "$plant/include" -name 'template.h' | head -1)
if [ -z "$target" ]; then
  printf 'check-noveto: plant could not find template.h\n' >&2
  exit 1
fi
printf '#define GDEFCORE_HOOK_TEMPLATE_%s "template-%s"\n' WRITE write >> "$target"
if scan_tree "$plant" > /dev/null 2>&1; then
  printf 'check-noveto: a header that names the hook was NOT found; the gate cannot see\n' >&2
  exit 1
fi
printf 'check-noveto: a header that names the hook was seen to fail\n'
