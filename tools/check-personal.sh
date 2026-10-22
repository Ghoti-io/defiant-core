#!/bin/sh
#
# The personal-data gate (story S7, AD-19, CAP-S5): every personal field
# names its subject, a value is decrypted only in the read path after the
# access filter has allowed its field, "unchanged" is decided on the
# plaintext, a render records each subject it decrypted and erasure purges
# the fragments that depend on it, and "everything about this person" lists
# every value. Runs the Personal tests on the real tree, then plants each
# defect in a COPY of the source by an exact text edit and requires the named
# test to fail (defiant-storage's plant-lib.sh):
#
# The story's five:
#
#   plaintext-in-a-stored-row      Personal.NoStoredRowHoldsAPlaintext
#   value-without-its-subject      Personal.EveryValueIsStoredUnderTheSubjectItsDeclarationNames
#   erasure-keeps-fragments        Personal.ACachedRenderThatDecryptedASubjectIsPurgedWhenItIsErased
#   unchanged-writes-a-revision    Personal.AnUnchangedPersonalValueWritesNothing
#   decryption-before-the-filter   Personal.AReaderWhoMayNotSeeTheFieldCausesNoDecryption
#
# and the rest of the story's rules:
#
#   render-records-no-subject      Personal.ACachedRenderThatDecryptedASubjectIsPurgedWhenItIsErased
#   own-subject-not-kept           Personal.AnEntityOfASubjectTypeIsItsOwnSubject
#   read-shows-the-stored-text     Personal.AnAllowedReaderSeesThePlaintextAndAnErasedSubjectReadsErased
#   revision-view-erased-as-shown  Personal.ARevisionViewOfAnErasedSubjectSaysErased
#   export-skips-history           Personal.EverythingAboutThisPersonListsEveryValueAcrossTypesGroupsAndHistory
#   personal-without-a-source      Personal.APersonalFieldWithNoSubjectSourceIsRefusedAtDeclaration
#
# Each test counts what the port stored (gdefstor_model_dump(), the subject
# lookup), what the key store did, or what a principal was given, with a
# control on the other side of the rule, so a plant turning one red is a test
# seeing the defect, not a build failure.
#
# Usage: check-personal.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testPersonal 'Personal.*'

ENT=src/entity/entity.c
STO=src/entity/store.c
ACC=src/access/access.c
SUB=src/subject/subject.c

# 1. A plaintext in a stored row: the blind-index value computed as the
#    plaintext itself, padded, so the blind row holds the value (equality on
#    it still finds what it should, so only a search of the rows sees it).
plant plaintext-in-a-stored-row $SUB testPersonal \
  'Personal.NoStoredRowHoldsAPlaintext' \
  '  rc = from_gsec(gsec_hmac(GSEC_HMAC_SHA256, ikm, kKey, plain, plain_len, mac));
  wipe(ikm, sizeof ikm);
  return rc;' \
  '  rc = from_gsec(gsec_hmac(GSEC_HMAC_SHA256, ikm, kKey, plain, plain_len, mac));
  memset(mac, 0, kMac);
  memcpy(mac, plain, plain_len < kMac ? plain_len : kMac);
  wipe(ikm, sizeof ikm);
  return rc;'

# 2. A value stored without its subject: the entity'"'"'s own subject taken from
#    whoever the caller said it sealed the value for, so the value is filed
#    under someone else and its own subject'"'"'s lookup and erasure miss it.
plant value-without-its-subject $STO testPersonal \
  'Personal.EveryValueIsStoredUnderTheSubjectItsDeclarationNames' \
  '    memcpy(subject, seals->own, GDEFCORE_PUBLIC_ID_LEN + 1);' \
  '    memcpy(subject, note != NULL ? note->subject : seals->own,
        GDEFCORE_PUBLIC_ID_LEN + 1);'

# 3. A cached fragment surviving its subject'"'"'s erasure: erasure'"'"'s third step
#    is skipped.
plant erasure-keeps-fragments $SUB testPersonal \
  'Personal.ACachedRenderThatDecryptedASubjectIsPurgedWhenItIsErased' \
  '  if (rc == GDEFCORE_OK) {
    rc = purge_fragments(subjects, sid);
  }
  return rc;' \
  '  return rc;'

# 4. An unchanged personal value writing a revision: "unchanged" decided on
#    the ciphertext, which encryption makes new every time.
plant unchanged-writes-a-revision $STO testPersonal \
  'Personal.AnUnchangedPersonalValueWritesNothing' \
  '  if (was != NULL && was->type != 0 && was->bytes != NULL &&' \
  '  if (0 && was != NULL && was->type != 0 && was->bytes != NULL &&'

# 5. A decryption before the access filter: a tree read opens every personal
#    value, then drops the ones the reader may not see.
plant decryption-before-the-filter $ACC testPersonal \
  'Personal.AReaderWhoMayNotSeeTheFieldCausesNoDecryption' \
  '      /* An item'"'"'s own value is its field'"'"'s, and was decided with the item. */
      if (field_len > 0 && !path_shown(f, path, pn)) {' \
  '      if (personal_path(f, path, pn)) {
        const char * ps = NULL;
        size_t psn = 0;
        char * pt = NULL;
        size_t ptn = 0;
        int pshown = 0;
        int pgone = 0;
        if (gdefcore_tree_value_subject(in, i, k, &ps, &psn) == GDEFCORE_OK &&
            open_for_reader(catalog, f->request, ps, psn, path, pn, text, len,
                &pt, &ptn, &pshown, &pgone) == GDEFCORE_OK) {
          gdefcore_text_free(catalog, pt);
        }
      }
      /* An item'"'"'s own value is its field'"'"'s, and was decided with the item. */
      if (field_len > 0 && !path_shown(f, path, pn)) {'

# 6. A render that does not record the subjects it decrypted: its cached
#    fragment depends on nobody, and outlives the erasure.
plant render-records-no-subject $ACC testPersonal \
  'Personal.ACachedRenderThatDecryptedASubjectIsPurgedWhenItIsErased' \
  '    rc = gdefcore_request_record_subject(request, subject, subject_len);' \
  '    (void)request;
    rc = GDEFCORE_OK;'

# 7. The entity'"'"'s own subject made and not kept with it.
plant own-subject-not-kept $ENT testPersonal \
  'Personal.AnEntityOfASubjectTypeIsItsOwnSubject' \
  '  if (rc == GDEFCORE_OK && subjects) {
    rc = map_stor(gdefstor_record_put(write, GDEFCORE_ENT_SUBJECT_NS,' \
  '  if (0 && subjects) {
    rc = map_stor(gdefstor_record_put(write, GDEFCORE_ENT_SUBJECT_NS,'

# 8. A read that shows a personal value as it is stored, the ciphertext.
plant read-shows-the-stored-text $ACC testPersonal \
  'Personal.AnAllowedReaderSeesThePlaintextAndAnErasedSubjectReadsErased' \
  '  if (personal) {
    /* Only now, the field allowed, is a personal value decrypted (AD-19,' \
  '  if (0 && personal) {
    /* Only now, the field allowed, is a personal value decrypted (AD-19,'

# 9. A revision view of an erased subject'"'"'s value that says it is shown.
plant revision-view-erased-as-shown $ACC testPersonal \
  'Personal.ARevisionViewOfAnErasedSubjectSaysErased' \
  '      *out_status = all_erased ? GDEFCORE_REVISION_ERASED
                               : GDEFCORE_REVISION_SHOWN;' \
  '      *out_status = GDEFCORE_REVISION_SHOWN;
      (void)all_erased;'

# 10. "Everything about this person" of the current values only.
plant export-skips-history $SUB testPersonal \
  'Personal.EverythingAboutThisPersonListsEveryValueAcrossTypesGroupsAndHistory' \
  '    rc = from_stor(gdefstor_subject_hit(hits, i, &hit));
    if (rc == GDEFCORE_OK) {
      rc = hit_value(subjects, &hit, &tree, &v);
    }' \
  '    rc = from_stor(gdefstor_subject_hit(hits, i, &hit));
    if (rc == GDEFCORE_OK && hit.valid_to != 0) {
      continue;
    }
    if (rc == GDEFCORE_OK) {
      rc = hit_value(subjects, &hit, &tree, &v);
    }'

# 11. A personal field with no subject source taken at declaration.
plant personal-without-a-source $ENT testPersonal \
  'Personal.APersonalFieldWithNoSubjectSourceIsRefusedAtDeclaration' \
  '    } else if (field_personal(&fields[i]) && !subjects) {' \
  '    } else if (0 && field_personal(&fields[i]) && !subjects) {'

plant_finish
