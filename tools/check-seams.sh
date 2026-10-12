#!/bin/sh
#
# Fail if one subsystem includes another's private header.
#
# request, sched, entity, module, access, account, inst, subject, form and render are the subsystems.
# Each may include another's public header. A private header included
# from another subsystem is the seam the gate exists to catch.
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
  dirs='request sched entity module access account inst subject form render'
  headers='request_internal\.h sched_internal\.h entity_internal\.h module_internal\.h access_internal\.h account_internal\.h inst_internal\.h subject_internal\.h form_internal\.h render_internal\.h'
  for dir in $dirs; do
    for header in $headers; do
      case "$header" in
        "$dir"_internal.h|"${dir}_internal\.h") continue ;;
      esac
      # The escaped form is what refuse greps. Skip a directory's own header.
      own=$(printf '%s' "$header" | sed 's/\\\././')
      case "$own" in
        "${dir}_internal.h") continue ;;
      esac
      refuse "$tree" "$dir" "$header" || status=1
    done
  done
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
   [ ! -f "$ROOT/src/entity/entity_internal.h" ] ||
   [ ! -f "$ROOT/src/module/module_internal.h" ] ||
   [ ! -f "$ROOT/src/access/access_internal.h" ] ||
   [ ! -f "$ROOT/src/account/account_internal.h" ] ||
   [ ! -f "$ROOT/src/inst/inst_internal.h" ] ||
   [ ! -f "$ROOT/src/subject/subject_internal.h" ] ||
   [ ! -f "$ROOT/src/form/form_internal.h" ] ||
   [ ! -f "$ROOT/src/render/render_internal.h" ]; then
  printf 'check-seams: private headers are missing; this gate is measuring nothing\n' >&2
  exit 1
fi

if ! scan "$ROOT"; then
  exit 1
fi
printf 'check-seams: request, sched, entity, module, access, account, inst, subject, form and render include only public headers of each other\n'

plant=$(mktemp -d)
trap 'rm -rf "$plant"' EXIT
mkdir -p "$plant/src/request" "$plant/src/sched" "$plant/src/entity" \
  "$plant/src/module" "$plant/src/access" "$plant/src/account" \
  "$plant/src/inst" "$plant/src/subject" "$plant/src/form" \
  "$plant/src/render" "$plant/include"
printf '%s\n' '#include "../sched/sched_internal.h"' > "$plant/src/request/plant.c"
printf '%s\n' '/* private */' > "$plant/src/sched/sched_internal.h"
printf '%s\n' '/* private */' > "$plant/src/request/request_internal.h"
printf '%s\n' '/* private */' > "$plant/src/entity/entity_internal.h"
printf '%s\n' '/* private */' > "$plant/src/module/module_internal.h"
printf '%s\n' '/* private */' > "$plant/src/access/access_internal.h"
printf '%s\n' '/* private */' > "$plant/src/account/account_internal.h"
printf '%s\n' '/* private */' > "$plant/src/inst/inst_internal.h"
printf '%s\n' '/* private */' > "$plant/src/subject/subject_internal.h"
printf '%s\n' '/* private */' > "$plant/src/form/form_internal.h"
printf '%s\n' '/* private */' > "$plant/src/render/render_internal.h"
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

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../module/module_internal.h"' > "$plant/src/request/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted module include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of module_internal.h was refused\n'

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../access/access_internal.h"' > "$plant/src/request/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted access include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of access_internal.h was refused\n'

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../account/account_internal.h"' > "$plant/src/request/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted account include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of account_internal.h was refused\n'

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../inst/inst_internal.h"' > "$plant/src/request/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted inst include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of inst_internal.h was refused\n'

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../subject/subject_internal.h"' > "$plant/src/request/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted subject include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of subject_internal.h was refused\n'

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../form/form_internal.h"' > "$plant/src/request/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted form include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of form_internal.h was refused\n'

rm -f "$plant/src/request/plant.c"
printf '%s\n' '#include "../render/render_internal.h"' > "$plant/src/form/plant.c"
if scan "$plant"; then
  printf 'check-seams: the planted render include passed\n' >&2
  exit 1
fi
printf 'check-seams: planted include of render_internal.h was refused\n'
