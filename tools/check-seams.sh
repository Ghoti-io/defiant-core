#!/bin/sh
#
# Fail if one subsystem includes another's private header.
#
# request, sched and entity are the subsystems. Each may include the
# other's public header. A private header included from another subsystem
# is the seam the gate exists to catch.
#
# The real tree must pass. A planted copy of request that includes
# sched_internal.h must fail. The script also refuses gcu_tls: a current
# request is not stored on the thread.
#
# Usage: check-seams.sh <root>

set -eu

ROOT="${1:?usage: check-seams.sh <root>}"

refuse() {
  tree=$1
  dir=$2
  header=$3
  if [ -d "$tree/src/$dir" ] &&
     grep -R -n -E "$header" "$tree/src/$dir" >/dev/null 2>&1; then
    printf 'check-seams: %s includes %s\n' "$dir" "$header" >&2
    grep -R -n -E "$header" "$tree/src/$dir" >&2 || true
    return 1
  fi
  return 0
}

scan() {
  tree=$1
  status=0
  refuse "$tree" request 'sched_internal\.h' || status=1
  refuse "$tree" request 'entity_internal\.h' || status=1
  refuse "$tree" sched 'request_internal\.h' || status=1
  refuse "$tree" sched 'entity_internal\.h' || status=1
  refuse "$tree" entity 'request_internal\.h' || status=1
  refuse "$tree" entity 'sched_internal\.h' || status=1
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
   [ ! -f "$ROOT/src/sched/sched_internal.h" ] ||
   [ ! -f "$ROOT/src/entity/entity_internal.h" ]; then
  printf 'check-seams: private headers are missing; this gate is measuring nothing\n' >&2
  exit 1
fi

if ! scan "$ROOT"; then
  exit 1
fi
printf 'check-seams: request, sched and entity include only public headers of each other\n'

plant=$(mktemp -d)
trap 'rm -rf "$plant"' EXIT
mkdir -p "$plant/src/request" "$plant/src/sched" "$plant/src/entity" "$plant/include"
printf '%s\n' '#include "../sched/sched_internal.h"' > "$plant/src/request/plant.c"
printf '%s\n' '/* private */' > "$plant/src/sched/sched_internal.h"
printf '%s\n' '/* private */' > "$plant/src/request/request_internal.h"
printf '%s\n' '/* private */' > "$plant/src/entity/entity_internal.h"
if scan "$plant"; then
  printf 'check-seams: the planted private include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of sched_internal.h was refused\n'

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../entity/entity_internal.h"' > "$plant/src/request/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted entity include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of entity_internal.h was refused\n'
