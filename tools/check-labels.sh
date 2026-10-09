#!/bin/sh
#
# Fail if a public header has no @stability label, or any label other than
# free. Every public header of this library is free.
#
# Usage: check-labels.sh <root>
#   <root> holds include/ghoti.io/defiant-core/. The script then plants a
#   header with the label removed and requires that copy to fail.

set -eu

ROOT="${1:?usage: check-labels.sh <root>}"
BASE="$ROOT/include/ghoti.io/defiant-core"

check_tree() {
  tree=$1
  base="$tree/include/ghoti.io/defiant-core"
  if [ ! -d "$base" ]; then
    printf 'check-labels: %s does not exist; this gate is measuring nothing\n' \
      "$base" >&2
    return 1
  fi
  headers=$(find "$base" -type f -name '*.h' | sort)
  if [ -z "$headers" ]; then
    printf 'check-labels: no headers under %s; this gate is measuring nothing\n' \
      "$base" >&2
    return 1
  fi
  status=0
  count=0
  for h in $headers; do
    count=$((count + 1))
    labels=$(grep -E '^[[:space:]]*(\*|//)[[:space:]]*@stability[[:space:]]' "$h" \
      | sed 's/.*@stability[[:space:]]*//; s/[[:space:]]*$//' || true)
    if [ -z "$labels" ]; then
      printf 'check-labels: %s has no @stability label (want free)\n' "$h" >&2
      status=1
      continue
    fi
    if [ "$(printf '%s\n' "$labels" | wc -l)" -ne 1 ]; then
      printf 'check-labels: %s has more than one @stability label\n' "$h" >&2
      status=1
      continue
    fi
    if [ "$labels" != "free" ]; then
      printf 'check-labels: %s is labelled %s but this library requires free\n' \
        "$h" "$labels" >&2
      status=1
    fi
  done
  if [ "$status" -ne 0 ]; then
    return 1
  fi
  printf 'check-labels: %d public headers, each labelled free\n' "$count"
  return 0
}

if ! check_tree "$ROOT"; then
  exit 1
fi

plant=$(mktemp -d)
trap 'rm -rf "$plant"' EXIT
mkdir -p "$plant/include/ghoti.io"
cp -a "$BASE" "$plant/include/ghoti.io/"
target=$(find "$plant/include/ghoti.io/defiant-core" -name 'request.h' | head -1)
if [ -z "$target" ]; then
  printf 'check-labels: plant could not find request.h\n' >&2
  exit 1
fi
python3 - "$target" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
old = " * @stability free\n"
if text.count(old) != 1:
    sys.stderr.write("anchor matched %d times\n" % text.count(old))
    sys.exit(3)
open(path, "w").write(text.replace(old, "", 1))
PY
if check_tree "$plant"; then
  printf 'check-labels: the planted header with no @stability passed\n' >&2
  exit 1
fi
printf 'check-labels: planted missing @stability was refused\n'
