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
  warm_build "$dest" "$(dirname "$APP_DIR")"
}

# The copy also takes the main tree's build output for this build directory,
# with its timestamps, so make recompiles only what the plant edited (and,
# through the .d files, whatever includes an edited header) and relinks.
# Without it every plant was a cold rebuild of the whole library.
# GHOTI_CHECK_COLD=1 copies no build output, for comparing the two.
warm_build() {
  [ -n "${GHOTI_CHECK_COLD:-}" ] && return 0
  case "$2" in /*|*..*|'') return 0 ;; esac
  [ -d "$ROOT/$2" ] || return 0
  mkdir -p "$1/$(dirname "$2")"
  cp -a "$ROOT/$2" "$1/$2"
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
    Erasure.FormSubjectBinding Erasure.PlaintextRevisionCannotBecomeTheContentAgain \
    Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject; do
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

# 2. Erasure that leaves the blind-index rows behind (in the port's blind
#    table since story S6c; the sweep reads them in the tenant store's rows).
plant keeps-blind-rows src/subject/subject.c Erasure.Sweep \
  '  rc = from_stor(gdefstor_blind_delete_subject(write, sid,
      GDEFCORE_PUBLIC_ID_LEN));' \
  '  rc = GDEFCORE_OK;
  (void)sid;'

# 3. Erasure that leaves the wrapped subject key where it is kept: the key
#    store is never asked to destroy it (story S5b moved it there from the
#    side store's row).
plant keeps-key src/subject/subject.c Erasure.Sweep \
  '    rc = from_stor(gdefstor_keystore_erase(subjects->keys,
        (const char *)subjects->tenant, subjects->tenant_len, sid,
        GDEFCORE_PUBLIC_ID_LEN, when));' \
  '    rc = GDEFCORE_OK;
    (void)when;'

# 4. Erasure survives restore: a snapshot that carries a key. The data set is
#    taken with the tenant keyring's wrap filed in the tenant store first, as
#    a record of its own, so import still works and only the key travels.
plant snapshot-key src/subject/subject.c Erasure.SnapshotCarriesNoKey \
  '  return from_stor(gdefstor_snapshot_export_at(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, taken,
      out_bytes, out_len));' \
  '  {
    uint8_t wrap[kWrap];
    int found = 0;
    GDEFSTOR_Write * kw = NULL;
    if (wrap_load(subjects->keys, subjects->alloc, subjects->tenant,
            subjects->tenant_len, wrap, &found) == GDEFCORE_OK && found &&
        gdefstor_write_begin(tenant_store, (const char *)subjects->tenant,
            subjects->tenant_len, NULL, &kw) == GDEFSTOR_OK) {
      if (gdefstor_record_put(kw, "core.keyring", 12, "wrap", 4, wrap,
              kWrap) == GDEFSTOR_OK) {
        (void)gdefstor_write_commit(kw);
      } else {
        gdefstor_write_abort(kw);
      }
    }
  }
  return from_stor(gdefstor_snapshot_export_at(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, taken,
      out_bytes, out_len));'

# AD-19 on the form route. Every plant below edits the real source of the
# library, and the named test must go red BY NAME.
#
# The entity layer refuses a plaintext for a personal field on its own, and so
# does the form layer; the plants that lift one layer lift both, or the other
# refuses and the plant would show nothing. ENTITY_GATE is the entity layer's
# refusal, the first test in personal_value_ok(). Since story S6c a personal
# value on the port also needs its subject, which a plaintext no note names
# does not have; SUBJECT_GATE lifts that refusal (seal_value()) by naming a
# made-up subject, so that a form plant can still store the plaintext.
ENTITY_GATE_OLD='  if (!decl->personal || value->count == 0) {
    return 1;
  }'
ENTITY_GATE_NEW='  if (1 || !decl->personal || value->count == 0) {
    return 1;
  }'
SUBJECT_GATE_OLD='    /* A sealed text from nowhere: nothing says whose it is (AD-19). */
    seals->unknown = 1;
    return GDEFCORE_ERR_INVALID;'
SUBJECT_GATE_NEW='    memcpy(subject, "0000000000000000000000000000",
        GDEFCORE_PUBLIC_ID_LEN + 1);'

# 5. The subject route of a form stores the caller's plaintext (the sealed text
#    is built and then not used). The entity layer's refusal is lifted too, so
#    the plaintext is really stored.
plant form-submit-stores-plaintext src/form/form.c Erasure.FormSubjectRoute \
  '          values[j].texts = &sealed_texts[k];
          values[j].text_lens = &sealed.len[k];' \
  '          (void)sealed_texts;' \
  --file src/entity/entity.c "$ENTITY_GATE_OLD" "$ENTITY_GATE_NEW" \
  --file src/entity/store.c "$SUBJECT_GATE_OLD" "$SUBJECT_GATE_NEW"

# 6. The plain submit stops refusing a personal value. (The plain sign still
#    refuses, so the token comes from the subject route.)
plant plain-submit-takes-personal src/form/form.c Erasure.FormPersonalField \
  '  if (rc == GDEFCORE_OK && personal_valued(opened.fields, opened.nfields) &&
      (subjects == NULL || !opened.has_subject)) {' \
  '  if (rc == GDEFCORE_OK && 0 &&
      (subjects == NULL || !opened.has_subject)) {' \
  --file src/entity/entity.c "$ENTITY_GATE_OLD" "$ENTITY_GATE_NEW" \
  --file src/entity/store.c "$SUBJECT_GATE_OLD" "$SUBJECT_GATE_NEW"

# 6b. The plain sign stops refusing a personal value (the token then holds
#     plaintext for a subject-less submit to find).
plant plain-sign-takes-personal src/form/form.c Erasure.FormPersonalField \
  '  if (rc == GDEFCORE_OK && !opened.has_subject &&
      personal_valued(opened.fields, opened.nfields)) {' \
  '  if (rc == GDEFCORE_OK && 0) {'

# 7. The token no longer authenticates its subject: the AEAD's associated data
#    carries a fixed id whatever the header says.
plant token-drops-subject src/form/form.c Erasure.FormSubjectBinding \
  '          !put_bytes(aad, n, &at, subject, GDEFCORE_PUBLIC_ID_LEN)) ||' \
  '          !put_bytes(aad, n, &at, "0000000000000000000000000000",
              GDEFCORE_PUBLIC_ID_LEN)) ||'

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

# 10a. The same check, seen from the other gate: a revert to a revision from
#      before the field was personal (the only way an old revision becomes
#      the content again since access SPEC decision 13 retired `activate`,
#      whose own plant, activate-skips-sealed-check, went with it).
plant restore-skips-sealed-check-again src/entity/entity.c \
  Erasure.PlaintextRevisionCannotBecomeTheContentAgain \
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

# 12. A revision view shows a personal field as it is stored, the ciphertext.
plant revision-view-shows-ciphertext src/access/access.c \
  Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject \
  '  if (field_is_personal(catalog, type_name, type_len, field, field_len)) {' \
  '  if (0 && field_is_personal(catalog, type_name, type_len, field, field_len)) {'

# 13. The erased marker is never shown: a view of an erased person's history
#     says "a personal value is here" as it does for everyone.
plant erased-marker-never-shown src/subject/subject.c \
  Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject \
  '  if (!erased) {
    return GDEFCORE_OK;
  }
  /* The key is gone: what the revision holds decrypts to nothing, and says' \
  '  if (1 || !erased) {
    return GDEFCORE_OK;
  }
  /* The key is gone: what the revision holds decrypts to nothing, and says'

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf 'check-erasure: every planted defect turned its gate red\n'
