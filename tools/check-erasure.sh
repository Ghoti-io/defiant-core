#!/bin/sh
#
# The erasure sweep gates, each with the defect they exist to catch.
#
# Erasure.Sweep puts a canary personal value through the library, erases
# its subject, and searches every byte the library can hand back for the
# canary, its hashes and HMACs, and the subject's key. Erasure.SnapshotCarriesNoKey
# does the same for a snapshot and a restore. A gate that has never failed
# is not shown to work (AD-25), so this script:
#
#   1. runs both tests on the real tree and requires them to pass;
#   2. copies the library source to a scratch tree, reintroduces one defect
#      at a time by an exact textual edit, rebuilds, and requires THAT test,
#      named, to fail. A plant that does not match exactly once, or that
#      leaves the file unchanged, is an error: a stale anchor would leave a
#      pristine copy that passes for the wrong reason. A crash, a build
#      failure or a different failing test does not count.
#
# Plants live only in the scratch copy. Nothing in src/ knows about them.
#
# It also runs the one known-open defect (a personal field written through a
# form is stored as plaintext) and reports whether it still fails.
#
# Usage: check-erasure.sh <make> <app-dir> [make args]

set -u

MAKE_CMD="${1:?usage: check-erasure.sh <make> <app-dir> [make args]}"
APP_DIR="${2:?usage: check-erasure.sh <make> <app-dir> [make args]}"
shift 2
MARGS="-j${GHOTI_CHECK_JOBS:-$(n=$(nproc 2>/dev/null || echo 4); [ "$n" -gt 4 ] && n=4; echo "$n")} $*"

unset MAKEFLAGS MFLAGS

ROOT=$(pwd)
SCRATCH="$ROOT/build/erasure-plants"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

copy_tree() {
  dest=$1
  mkdir -p "$dest"
  for d in src include tests tools pkgconfig documentation examples; do
    [ -e "$ROOT/$d" ] && cp -a "$ROOT/$d" "$dest/"
  done
  cp -a "$ROOT/Makefile" "$ROOT/Doxyfile" "$dest/"
  rm -rf "$dest/tests/fuzz/corpus"
}

fail=0

build() {
  ( cd "$1" && "$MAKE_CMD" --no-print-directory "$APP_DIR/testErasure" $MARGS ) \
    > "$1.log" 2>&1
}

# Run one named test in tree $1. Output goes to $1.run. Returns the status.
run_test() {
  dir=$1
  name=$2
  shift 2
  ( cd "$dir" && "$APP_DIR/testErasure" --gtest_filter="$name" "$@" ) > "$dir.run" 2>&1
}

copy_tree "$SCRATCH/control"
if ! build "$SCRATCH/control"; then
  printf 'check-erasure: the CONTROL (unpatched) copy does not build. Its log:\n' >&2
  tail -30 "$SCRATCH/control.log" >&2
  exit 1
fi

for t in Erasure.Scanner Erasure.Channels Erasure.Sweep Erasure.SnapshotCarriesNoKey; do
  if ! run_test "$SCRATCH/control" "$t"; then
    printf 'check-erasure: %s failed on the real tree\n' "$t" >&2
    tail -30 "$SCRATCH/control.run" >&2
    exit 1
  fi
  printf 'check-erasure: %s passes on the real tree\n' "$t"
done

# plant <name> <file> <test that must fail> <old> <new> [<old> <new> ...]
plant() {
  name=$1
  file=$2
  expect=$3
  shift 3
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  python3 - "$dir/$file" "$@" <<'PY'
import sys
path = sys.argv[1]
pairs = sys.argv[2:]
text = open(path).read()
for i in range(0, len(pairs), 2):
    old, new = pairs[i], pairs[i + 1]
    if text.count(old) != 1:
        sys.stderr.write("anchor matched %d times in %s:\n%s\n"
                         % (text.count(old), path, old))
        sys.exit(3)
    text = text.replace(old, new, 1)
open(path, "w").write(text)
PY
  rc=$?
  if [ $rc -ne 0 ]; then
    printf 'check-erasure: %s: THE PATCH DID NOT APPLY (stale anchor), nothing was tested\n' "$name" >&2
    fail=1
    return
  fi
  if cmp -s "$ROOT/$file" "$dir/$file"; then
    printf 'check-erasure: %s: the patched file equals the original\n' "$name" >&2
    fail=1
    return
  fi
  touch "$dir/$file"
  rm -f "$dir/$APP_DIR/testErasure"
  if ! build "$dir"; then
    printf 'check-erasure: %s: the planted tree does not build, read %s.log\n' "$name" "$dir" >&2
    tail -20 "$dir.log" >&2
    fail=1
    return
  fi
  run_test "$dir" "$expect"
  rc=$?
  if [ $rc -eq 0 ]; then
    printf 'check-erasure: %s: %s PASSED with the defect planted\n' "$name" "$expect" >&2
    fail=1
  elif [ $rc -ge 128 ]; then
    printf 'check-erasure: %s: the run crashed (status %d), which is not a catch\n' "$name" "$rc" >&2
    tail -15 "$dir.run" >&2
    fail=1
  elif grep -q "^\[  FAILED  \] $expect\$" "$dir.run"; then
    printf 'check-erasure: %s: caught by %s\n' "$name" "$expect"
    grep -m3 'leak:' "$dir.run" | sed 's/^ */check-erasure:   /'
  else
    printf 'check-erasure: %s: the run failed, but %s is not among the failures\n' "$name" "$expect" >&2
    tail -15 "$dir.run" >&2
    fail=1
  fi
}

# 1. A blind index written into a revision document (AD-19: blind-index rows
#    live only in projections and side tables, never in documents). The save
#    appends the index to the stored value, and the read path ignores it.
plant revision-blind src/subject/subject.c Erasure.Sweep \
  '  texts[0] = stored;
  lens[0] = stored_len;
  memset(&value, 0, sizeof value);' \
  '  {
    char * ixhex = NULL;
    size_t ixn = 0;
    if (hex_encode(subjects->alloc, mac, kMac, &ixhex, &ixn) == GDEFCORE_OK) {
      char * grown = (char *)gcu_allocator_realloc(subjects->alloc, stored,
          stored_len + 4 + ixn + 1);
      if (grown != NULL) {
        stored = grown;
        memcpy(stored + stored_len, ".ix:", 4);
        memcpy(stored + stored_len + 4, ixhex, ixn);
        stored_len += 4 + ixn;
        stored[stored_len] = 0;
      }
      gcu_allocator_free(subjects->alloc, ixhex);
    }
  }
  texts[0] = stored;
  lens[0] = stored_len;
  memset(&value, 0, sizeof value);' \
  '  GDEFCORE_Result rc;
  if (text_len < 3 || memcmp(text, "s1:", 3) != 0 ||' \
  '  GDEFCORE_Result rc;
  {
    const char * dot = (const char *)memchr(text, 0x2e, text_len);
    if (dot != NULL) {
      text_len = (size_t)(dot - text);
    }
  }
  if (text_len < 3 || memcmp(text, "s1:", 3) != 0 ||'

# 2. Erasure that leaves the blind-index rows behind.
plant keeps-blind-rows src/subject/subject.c Erasure.Sweep \
  '  rc = delete_blinds(write, sid, row.blinds, row.blinds_len);' \
  '  rc = GDEFCORE_OK;'

# 3. Erasure that leaves the wrapped subject key in its row.
plant keeps-key src/subject/subject.c Erasure.Sweep \
  '    rc = from_stor(gdefstor_projection_put(write, kSubjectType,
        strlen(kSubjectType), sid, GDEFCORE_PUBLIC_ID_LEN, columns, 2));' \
  '    columns[2].name = "key";
    columns[2].name_len = 3;
    columns[2].value = row.key;
    columns[2].value_len = row.key_len;
    rc = from_stor(gdefstor_projection_put(write, kSubjectType,
        strlen(kSubjectType), sid, GDEFCORE_PUBLIC_ID_LEN, columns, 3));'

# 4. Erasure survives restore: a snapshot that carries a key. The ledger copy
#    in the snapshot gains a line whose second column is the tenant keyring
#    wrap, in hex. The line is well formed, so import still works and only
#    the key travels.
plant snapshot-key src/subject/subject.c Erasure.SnapshotCarriesNoKey \
  '  rc = from_stor(gdefstor_snapshot_export_ledger(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL,
      (const uint8_t *)ledger, ledger_len, out_bytes, out_len));
  gcu_allocator_free(subjects->alloc, ledger);
  return rc;' \
  '  {
    uint8_t wrap[kWrap];
    int found = 0;
    char * hex = NULL;
    size_t hex_len = 0;
    Buf kept;
    memset(&kept, 0, sizeof kept);
    kept.alloc = subjects->alloc;
    buf_add(&kept, ledger, ledger_len);
    if (wrap_load(subjects->side, subjects->tenant, subjects->tenant_len, wrap,
            &found) == GDEFCORE_OK && found &&
        hex_encode(subjects->alloc, wrap, kWrap, &hex, &hex_len) ==
            GDEFCORE_OK) {
      buf_add(&kept, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA ", GDEFCORE_PUBLIC_ID_LEN + 1);
      buf_add(&kept, hex, hex_len);
      buf_add(&kept, "\n", 1);
      gcu_allocator_free(subjects->alloc, hex);
    }
    rc = from_stor(gdefstor_snapshot_export_ledger(tenant_store,
        (const char *)subjects->tenant, subjects->tenant_len, NULL,
        (const uint8_t *)(kept.p == NULL ? "" : kept.p), kept.n, out_bytes,
        out_len));
    buf_free(&kept);
  }
  gcu_allocator_free(subjects->alloc, ledger);
  return rc;'

# The known-open defect: it is expected to fail until the form path refuses or
# encrypts a personal value. When it starts to pass, enable the test.
if run_test "$SCRATCH/control" 'Erasure.DISABLED_FormPersonalField' \
    --gtest_also_run_disabled_tests; then
  printf 'check-erasure: Erasure.DISABLED_FormPersonalField now PASSES: remove its DISABLED_ prefix\n' >&2
  fail=1
else
  printf 'check-erasure: KNOWN OPEN: a personal field written through a form is stored as plaintext (Erasure.DISABLED_FormPersonalField still fails)\n'
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf 'check-erasure: every planted defect turned its gate red\n'
