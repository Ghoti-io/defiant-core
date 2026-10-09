#!/bin/sh
#
# Fail if one subsystem includes another's private header.
#
# request and sched are the two subsystems. Each may include the other's
# public header. src/request including sched_internal.h, or src/sched
# including request_internal.h, is the seam the gate exists to catch.
#
# The real tree must pass. A planted copy of request that includes
# sched_internal.h must fail. The script also refuses gcu_tls: a current
# request is not stored on the thread.
#
# Usage: check-seams.sh <root>

set -eu

ROOT="${1:?usage: check-seams.sh <root>}"

scan() {
  tree=$1
  status=0
  if [ -d "$tree/src/request" ]; then
    if grep -R -n -E 'sched_internal\.h' "$tree/src/request" >/dev/null 2>&1; then
      printf 'check-seams: request includes sched'\''s private header\n' >&2
      grep -R -n -E 'sched_internal\.h' "$tree/src/request" >&2 || true
      status=1
    fi
  fi
  if [ -d "$tree/src/sched" ]; then
    if grep -R -n -E 'request_internal\.h' "$tree/src/sched" >/dev/null 2>&1; then
      printf 'check-seams: sched includes request'\''s private header\n' >&2
      grep -R -n -E 'request_internal\.h' "$tree/src/sched" >&2 || true
      status=1
    fi
  fi
  if [ -d "$tree/include" ] || [ -d "$tree/src" ]; then
    if grep -R -n -E 'gcu_tls' "$tree/include" "$tree/src" >/dev/null 2>&1; then
      printf 'check-seams: gcu_tls is not a current request\n' >&2
      grep -R -n -E 'gcu_tls' "$tree/include" "$tree/src" >&2 || true
      status=1
    fi
  fi
  return "$status"
}

if [ ! -f "$ROOT/src/request/request_internal.h" ] ||
   [ ! -f "$ROOT/src/sched/sched_internal.h" ]; then
  printf 'check-seams: private headers are missing; this gate is measuring nothing\n' >&2
  exit 1
fi

if ! scan "$ROOT"; then
  exit 1
fi
printf 'check-seams: request and sched include only public headers of each other\n'

plant=$(mktemp -d)
trap 'rm -rf "$plant"' EXIT
mkdir -p "$plant/src/request" "$plant/src/sched" "$plant/include"
printf '%s\n' '#include "../sched/sched_internal.h"' > "$plant/src/request/plant.c"
printf '%s\n' '/* private */' > "$plant/src/sched/sched_internal.h"
printf '%s\n' '/* private */' > "$plant/src/request/request_internal.h"
if scan "$plant"; then
  printf 'check-seams: the planted private include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of sched_internal.h was refused\n'
