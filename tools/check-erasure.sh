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
# The form route is gated the same way (AD-19): the plain form sign and
# submit and gdefcore_entity_save refuse a personal value, and the subject
# route (gdefcore_form_sign_subject / gdefcore_form_submit_subject) seals it.
# Erasure.FormPersonalField, FormSubjectRoute, FormSubjectBinding,
# EntitySavePersonal and PlaintextHistoryIsNotRestored are those gates. The
# entity layer and the form layer each refuse a plaintext on their own, so a
# plant that must show the form layer's refusal also lifts the entity layer's
# (a plant may edit several files: a "--file <path>" pair switches the file
# the following old/new pairs apply to).
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

for t in Erasure.Scanner Erasure.Channels Erasure.Sweep Erasure.SnapshotCarriesNoKey \
    Erasure.FormPersonalField Erasure.FormPlainRouteOtherFields \
    Erasure.EntitySavePersonal Erasure.RevertKeepsCiphertext \
    Erasure.ParsePersonalPatch Erasure.PlaintextHistoryIsNotRestored \
    Erasure.FormSubjectRoute Erasure.FormUnknownSubject \
    Erasure.FormSubjectBinding; do
  if ! run_test "$SCRATCH/control" "$t"; then
    printf 'check-erasure: %s failed on the real tree\n' "$t" >&2
    tail -30 "$SCRATCH/control.run" >&2
    exit 1
  fi
  printf 'check-erasure: %s passes on the real tree\n' "$t"
done

# plant <name> <file> <test that must fail> <old> <new> [<old> <new> ...]
#       [--file <file2> <old> <new> ...]
plant() {
  name=$1
  file=$2
  expect=$3
  shift 3
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  python3 - "$dir" "$file" "$@" <<'PY'
import sys
root = sys.argv[1]
path = root + "/" + sys.argv[2]
args = sys.argv[3:]
edits = {}
names = []
i = 0
while i < len(args):
    if args[i] == "--file":
        path = root + "/" + args[i + 1]
        i += 2
        continue
    edits.setdefault(path, []).append((args[i], args[i + 1]))
    i += 2
for path, pairs in edits.items():
    text = open(path).read()
    for old, new in pairs:
        if text.count(old) != 1:
            sys.stderr.write("anchor matched %d times in %s:\n%s\n"
                             % (text.count(old), path, old))
            sys.exit(3)
        text = text.replace(old, new, 1)
    open(path, "w").write(text)
    names.append(path[len(root) + 1:])
open(root + ".files", "w").write("\n".join(names) + "\n")
PY
  rc=$?
  if [ $rc -ne 0 ]; then
    printf 'check-erasure: %s: THE PATCH DID NOT APPLY (stale anchor), nothing was tested\n' "$name" >&2
    fail=1
    return
  fi
  for f in $(cat "$dir.files"); do
    if cmp -s "$ROOT/$f" "$dir/$f"; then
      printf 'check-erasure: %s: the patched file %s equals the original\n' "$name" "$f" >&2
      fail=1
      return
    fi
    touch "$dir/$f"
  done
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

# AD-19 on the form route. Every plant below edits the real source of the
# library, and the named test must go red BY NAME.
#
# The entity layer refuses a plaintext for a personal field on its own, and so
# does the form layer; the plants that lift one layer lift both, or the other
# refuses and the plant would show nothing. ENTITY_GATE is the entity layer's
# refusal, the first test in personal_value_ok().
ENTITY_GATE_OLD='  if (!decl->personal || value->count == 0) {
    return 1;
  }'
ENTITY_GATE_NEW='  if (1 || !decl->personal || value->count == 0) {
    return 1;
  }'

# 5. The subject route of a form stores the caller's plaintext (the sealed text
#    is built and then not used). The entity layer's refusal is lifted too, so
#    the plaintext is really stored.
plant form-submit-stores-plaintext src/form/form.c Erasure.FormSubjectRoute \
  '          values[j].texts = &sealed_texts[k];
          values[j].text_lens = &sealed.len[k];' \
  '          (void)sealed_texts;' \
  --file src/entity/entity.c "$ENTITY_GATE_OLD" "$ENTITY_GATE_NEW"

# 6. The plain submit stops refusing a personal value. (The plain sign still
#    refuses, so the token comes from the subject route.)
plant plain-submit-takes-personal src/form/form.c Erasure.FormPersonalField \
  '  if (rc == GDEFCORE_OK && personal_valued(opened.fields, opened.nfields) &&
      (subjects == NULL || !opened.has_subject)) {' \
  '  if (rc == GDEFCORE_OK && 0 &&
      (subjects == NULL || !opened.has_subject)) {' \
  --file src/entity/entity.c "$ENTITY_GATE_OLD" "$ENTITY_GATE_NEW"

# 6b. The plain sign stops refusing a personal value (the token then holds
#     plaintext for a subject-less submit to find).
plant plain-sign-takes-personal src/form/form.c Erasure.FormPersonalField \
  '  if (rc == GDEFCORE_OK && !opened.has_subject &&
      personal_valued(opened.fields, opened.nfields)) {' \
  '  if (rc == GDEFCORE_OK && 0) {'

# 7. The token no longer authenticates its subject: the AEAD's associated data
#    carries the "no subject" bytes whatever the header says.
plant token-drops-subject src/form/form.c Erasure.FormSubjectBinding \
  '      !put_bytes(aad, n, &at, subject, GDEFCORE_PUBLIC_ID_LEN) ||' \
  '      !put_bytes(aad, n, &at, subject == NULL ? kNoSubject : kNoSubject,
          GDEFCORE_PUBLIC_ID_LEN) ||'

# 8. gdefcore_entity_save takes a personal value as it always did.
plant entity-save-takes-personal src/entity/entity.c Erasure.EntitySavePersonal \
  "$ENTITY_GATE_OLD" "$ENTITY_GATE_NEW"

# 9. A changeset that accepts sealed values accepts plaintext too.
plant sealed-accepts-plaintext src/entity/entity.c Erasure.EntitySavePersonal \
  '    if (!sealed_ok(value->texts[v], value->text_lens[v])) {
      return 0;
    }' \
  '    if (!sealed_ok(value->texts[v], value->text_lens[v]) && 0) {
      return 0;
    }'

# 10. A revert and a publish restore a personal value without asking whether
#     it is sealed.
plant restore-skips-sealed-check src/entity/entity.c Erasure.PlaintextHistoryIsNotRestored \
  '      if (decl == NULL || !decl->personal) {
        continue;
      }' \
  '      if (decl == NULL || 1) {
        continue;
      }'

# 10b. The seal takes a text that is already sealed (what the form tree shows
#      for a personal field) and seals it a second time.
plant seal-takes-sealed src/subject/subject.c Erasure.FormSubjectRoute \
  '  if (looks_sealed(plain, plain_len)) {
    return GDEFCORE_ERR_INVALID;
  }' \
  '  if (0 && looks_sealed(plain, plain_len)) {
    return GDEFCORE_ERR_INVALID;
  }'

# 11. A patch is parsed without the sealed-value rule: the parser accepts
#     plaintext for a personal field.
plant parse-takes-personal src/entity/entity.c Erasure.ParsePersonalPatch \
  "$ENTITY_GATE_OLD" "$ENTITY_GATE_NEW"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf 'check-erasure: every planted defect turned its gate red\n'
