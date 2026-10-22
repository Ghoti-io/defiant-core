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
# Usage: check-erasure.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
PLANT_TAG=check-erasure

plant_hook_control() { # exe filter
  plant_say "check-erasure: $2 passes on the real tree"
}

plant_hook_caught() { # name expect log
  printf 'check-erasure: %s: caught by %s\n' "$1" "$2"
  grep -m3 'leak:' "$3" | sed 's/^ */check-erasure:   /'
}

plant_hook_done() {
  printf 'check-erasure: every planted defect turned its gate red\n'
}

plant_setup "$@"

for t in Erasure.Scanner Erasure.Channels Erasure.Sweep \
    Erasure.SnapshotCarriesNoKey Erasure.FormPersonalField \
    Erasure.FormPlainRouteOtherFields Erasure.EntitySavePersonal \
    Erasure.RevertKeepsCiphertext Erasure.ParsePersonalPatch \
    Erasure.PlaintextHistoryIsNotRestored \
    Erasure.FormSubjectRoute Erasure.FormUnknownSubject \
    Erasure.FormSubjectBinding \
    Erasure.PlaintextRevisionCannotBecomeTheContentAgain \
    Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject; do
  plant_control testErasure "$t"
done

# A plant that edits more than one file is a plantm (the helpers): its edits
# come as file/old/new triples, where this gate used to write a "--file <path>"
# before the pairs that apply to that file.

# 1. A blind index written into a revision document (AD-19: blind-index rows
#    live only in projections and side tables, never in documents). The save
#    appends the index to the stored value, and the read path ignores it.
plant revision-blind src/subject/subject.c testErasure Erasure.Sweep \
  '  texts[0] = stored;
  lens[0] = stored_len;
  memset(values, 0, sizeof values);' \
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
  memset(values, 0, sizeof values);' \
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
plant keeps-blind-rows src/subject/subject.c testErasure Erasure.Sweep \
  '  rc = from_stor(gdefstor_blind_delete_subject(write, sid,
      GDEFCORE_PUBLIC_ID_LEN));' \
  '  rc = GDEFCORE_OK;
  (void)sid;'

# 3. Erasure that leaves the wrapped subject key where it is kept: the key
#    store is never asked to destroy it (story S5b moved it there from the
#    side store's row).
plant keeps-key src/subject/subject.c testErasure Erasure.Sweep \
  '    rc = from_stor(gdefstor_keystore_erase(subjects->keys,
        (const char *)subjects->tenant, subjects->tenant_len, sid,
        GDEFCORE_PUBLIC_ID_LEN, when));' \
  '    rc = GDEFCORE_OK;
    (void)when;'

# 4. Erasure survives restore: a snapshot that carries a key. The data set is
#    taken with the tenant keyring's wrap filed in the tenant store first, as
#    a record of its own, so import still works and only the key travels.
plant snapshot-key src/subject/subject.c testErasure Erasure.SnapshotCarriesNoKey \
  '  return from_stor(gdefstor_snapshot_export_tenant(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, taken,
      edition, edition_len, list, n, out_bytes, out_len));' \
  '  {
    uint8_t wrap[kWrap];
    int found = 0;
    GDEFSTOR_Write * kw = NULL;
    if (wrap_load(subjects->keys, subjects->alloc, subjects->tenant,
            subjects->tenant_len, wrap, &found) == GDEFCORE_OK && found &&
        gdefstor_write_begin(tenant_store, (const char *)subjects->tenant,
            subjects->tenant_len, NULL, &kw) == GDEFSTOR_OK) {
      if (gdefstor_record_put(kw, "core.keyring", 12, "wrap", 4,
              GDEFCORE_SCHEMA_CORE_STAMP,
              sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, wrap, kWrap) ==
          GDEFSTOR_OK) {
        (void)gdefstor_write_commit(kw);
      } else {
        gdefstor_write_abort(kw);
      }
    }
  }
  return from_stor(gdefstor_snapshot_export_tenant(tenant_store,
      (const char *)subjects->tenant, subjects->tenant_len, NULL, taken,
      edition, edition_len, list, n, out_bytes, out_len));'

# AD-19 on the form route. Every plant below edits the real source of the
# library, and the named test must go red BY NAME.
#
# The entity layer refuses a plaintext for a personal field on its own, and so
# does the form layer; the plants that lift one layer lift both, or the other
# refuses and the plant would show nothing. ENTITY_GATE is the entity layer's
# refusal, the first test in personal_value_ok(). Since story S7 a save opens
# every new personal value under the key of the subject its declaration names
# (for its MAC, and to decide on the plaintext whether it changed), which a
# plaintext does not survive; SUBJECT_GATE lifts that refusal (seal_value())
# by taking the value without a MAC, so that a form plant can still store the
# plaintext.
ENTITY_GATE_OLD='  if (!decl->personal || value->count == 0) {
    return 1;
  }'
ENTITY_GATE_NEW='  if (1 || !decl->personal || value->count == 0) {
    return 1;
  }'
SUBJECT_GATE_OLD='    if (rc == GDEFCORE_ERR_INVALID) {
      /* It does not open under the key of the subject the declaration
       * names, for this field: not that person'"'"'s value (AD-19). */
      seals->unknown = 1;
      return GDEFCORE_ERR_INVALID;
    }'
SUBJECT_GATE_NEW='    if (rc == GDEFCORE_ERR_INVALID) {
      *out_has_mac = 0;
      return GDEFCORE_OK;
    }'

# 5. The subject route of a form stores the caller's plaintext (the sealed text
#    is built and then not used). The entity layer's refusal is lifted too, so
#    the plaintext is really stored.
plantm form-submit-stores-plaintext testErasure Erasure.FormSubjectRoute \
  src/form/form.c \
  '          values[j].texts = &sealed_texts[k];
          values[j].text_lens = &sealed.len[k];' \
  '          (void)sealed_texts;' \
  src/entity/entity.c \
  "$ENTITY_GATE_OLD" \
  "$ENTITY_GATE_NEW" \
  src/entity/store.c \
  "$SUBJECT_GATE_OLD" \
  "$SUBJECT_GATE_NEW"

# 6. The plain submit stops refusing a personal value. (The plain sign still
#    refuses, so the token comes from the subject route.)
plantm plain-submit-takes-personal testErasure Erasure.FormPersonalField \
  src/form/form.c \
  '  if (rc == GDEFCORE_OK && personal_valued(opened.fields, opened.nfields) &&
      (subjects == NULL || !opened.has_subject)) {' \
  '  if (rc == GDEFCORE_OK && 0 &&
      (subjects == NULL || !opened.has_subject)) {' \
  src/entity/entity.c \
  "$ENTITY_GATE_OLD" \
  "$ENTITY_GATE_NEW" \
  src/entity/store.c \
  "$SUBJECT_GATE_OLD" \
  "$SUBJECT_GATE_NEW"

# 6b. The plain sign stops refusing a personal value (the token then holds
#     plaintext for a subject-less submit to find).
plant plain-sign-takes-personal src/form/form.c testErasure Erasure.FormPersonalField \
  '  if (rc == GDEFCORE_OK && !opened.has_subject &&
      personal_valued(opened.fields, opened.nfields)) {' \
  '  if (rc == GDEFCORE_OK && 0) {'

# 7. The token no longer authenticates its subject: the AEAD's associated data
#    carries a fixed id whatever the header says.
plant token-drops-subject src/form/form.c testErasure Erasure.FormSubjectBinding \
  '          !put_bytes(aad, n, &at, subject, GDEFCORE_PUBLIC_ID_LEN)) ||' \
  '          !put_bytes(aad, n, &at, "0000000000000000000000000000",
              GDEFCORE_PUBLIC_ID_LEN)) ||'

# 8. gdefcore_entity_save takes a personal value as it always did.
plant entity-save-takes-personal src/entity/entity.c testErasure Erasure.EntitySavePersonal \
  "$ENTITY_GATE_OLD" \
  "$ENTITY_GATE_NEW"

# 9. A changeset that accepts sealed values accepts plaintext too.
plant sealed-accepts-plaintext src/entity/entity.c testErasure Erasure.EntitySavePersonal \
  '    if (!sealed_ok(value->texts[v], value->text_lens[v])) {
      return 0;
    }' \
  '    if (!sealed_ok(value->texts[v], value->text_lens[v]) && 0) {
      return 0;
    }'

# 10. A revert and a publish restore a personal value without asking whether
#     it is sealed.
plant restore-skips-sealed-check src/entity/entity.c testErasure Erasure.PlaintextHistoryIsNotRestored \
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
plant restore-skips-sealed-check-again src/entity/entity.c testErasure Erasure.PlaintextRevisionCannotBecomeTheContentAgain \
  '      if (decl == NULL || !decl->personal) {
        continue;
      }' \
  '      if (decl == NULL || 1) {
        continue;
      }'

# 10b. The seal takes a text that is already sealed (what the form tree shows
#      for a personal field) and seals it a second time.
plant seal-takes-sealed src/subject/subject.c testErasure Erasure.FormSubjectRoute \
  '  if (looks_sealed(plain, plain_len)) {
    return GDEFCORE_ERR_INVALID;
  }' \
  '  if (0 && looks_sealed(plain, plain_len)) {
    return GDEFCORE_ERR_INVALID;
  }'

# 11. A patch is parsed without the sealed-value rule: the parser accepts
#     plaintext for a personal field.
plant parse-takes-personal src/entity/entity.c testErasure Erasure.ParsePersonalPatch \
  "$ENTITY_GATE_OLD" \
  "$ENTITY_GATE_NEW"

# 12. A revision view shows a personal field as it is stored, the ciphertext.
plant revision-view-shows-ciphertext src/access/access.c testErasure Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject \
  '  if (field_is_personal(catalog, type_name, type_len, field, field_len)) {' \
  '  if (0 && field_is_personal(catalog, type_name, type_len, field, field_len)) {'

# 13. The erased marker is never shown: a view of an erased person's history
#     says "a personal value is here" as it does for everyone.
plant erased-marker-never-shown src/subject/subject.c testErasure Erasure.RevisionViewsAndARestoredOldRevisionOfAnErasedSubject \
  '  if (!erased) {
    return GDEFCORE_OK;
  }
  /* The key is gone: what the revision holds decrypts to nothing, and says' \
  '  if (1 || !erased) {
    return GDEFCORE_OK;
  }
  /* The key is gone: what the revision holds decrypts to nothing, and says'

plant_finish
