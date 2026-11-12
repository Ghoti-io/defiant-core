#!/bin/sh
#
# The upload gate: a file is checked against the policy before a byte reaches
# the blob store, staged with an expiry, promoted by a reference that is counted
# from the stored entities (never from a counter), demoted and swept when
# nothing references it, shares a blob only while a file needs it, and is read
# only by its uploader (staged) or by whoever may see an entity that names it
# (kept), and only when the blob is the bytes of its digest.
#
# Runs the Uploads tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   size-unchecked              Uploads.NoPolicyLetsAFileBeBiggerThanTheHardMaximum
#   hard-maximum-dropped        Uploads.NoPolicyLetsAFileBeBiggerThanTheHardMaximum
#   policy-size-unchecked       Uploads.AFileThePolicyRefusesIsRefusedBeforeAByteIsStored
#   media-unchecked             Uploads.AFileThePolicyRefusesIsRefusedBeforeAByteIsStored
#   name-unchecked              Uploads.AFileThePolicyRefusesIsRefusedBeforeAByteIsStored
#   slash-allowed-in-a-name     Uploads.AFileThePolicyRefusesIsRefusedBeforeAByteIsStored
#   create-permission-skipped   Uploads.OnlyAPrincipalWhoMayCreateFilesStagesOne
#   tenant-dropped              Uploads.TheBlobStoreIsGivenTheTenantAndTheDigest
#   expiry-ignored              Uploads.AStagedFileLivesUntilItsExpiryAndNoLonger
#   blob-left-behind            Uploads.AStagedFileLivesUntilItsExpiryAndNoLonger
#   expired-reference-lost      Uploads.AReferencedFileIsPromotedAndSurvivesItsExpiry
#   group-reference-not-seen    Uploads.TheCountIsDerivedFromTheCurrentRevisionsOfTheEntitiesThatNameTheFile
#   unreferenced-not-demoted    Uploads.AKeptFileNothingReferencesAnyMoreIsStagedAgainWithAFreshExpiry
#   demoted-without-new-expiry  Uploads.AKeptFileNothingReferencesAnyMoreIsStagedAgainWithAFreshExpiry
#   shared-blob-removed         Uploads.FilesOfTheSameBytesShareABlobUntilTheLastOfThemGoes
#   read-skips-access           Uploads.TheBytesGoToTheUploaderOfAStagedFileAndToNoOneElse
#   reference-read-as-system    Uploads.AKeptFileIsReadByWhoeverMaySeeTheEntityThatNamesIt
#   digest-not-verified         Uploads.ABlobThatIsMissingOrIsNotTheDigestIsNeverServed
#   personal-field-allowed      Uploads.AFileIsNeverAttachedThroughAPersonalFieldOrAFieldThatIsNotAReference
#   only-the-first-language-read Uploads.AReferenceInAnyLanguageOfAnEntityHoldsTheFile
#   drafts-not-counted          Uploads.ADraftThatNamesAFileHoldsItAsAPublishedRevisionDoes
#   policy-struct-size-unchecked Uploads.TheStructsOfAnUploadAreAcceptedAtOnlyTheirOwnSize
#   blob-store-size-unchecked   Uploads.TheStructsOfAnUploadAreAcceptedAtOnlyTheirOwnSize
#
# Every test has a control (a good file stages, reads, promotes and sweeps), so a
# plant turning one red is a test seeing the defect, not a build failure.
#
# Usage: check-upload.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testUpload 'Uploads.*'

U=src/upload/upload.c
T_POL='Uploads.AFileThePolicyRefusesIsRefusedBeforeAByteIsStored'
T_MAX='Uploads.NoPolicyLetsAFileBeBiggerThanTheHardMaximum'
T_PERM='Uploads.OnlyAPrincipalWhoMayCreateFilesStagesOne'
T_TEN='Uploads.TheBlobStoreIsGivenTheTenantAndTheDigest'
T_LIFE='Uploads.AStagedFileLivesUntilItsExpiryAndNoLonger'
T_PROMO='Uploads.AReferencedFileIsPromotedAndSurvivesItsExpiry'
T_COUNT='Uploads.TheCountIsDerivedFromTheCurrentRevisionsOfTheEntitiesThatNameTheFile'
T_DEMO='Uploads.AKeptFileNothingReferencesAnyMoreIsStagedAgainWithAFreshExpiry'
T_SHARE='Uploads.FilesOfTheSameBytesShareABlobUntilTheLastOfThemGoes'
T_READ='Uploads.TheBytesGoToTheUploaderOfAStagedFileAndToNoOneElse'
T_KEPT='Uploads.AKeptFileIsReadByWhoeverMaySeeTheEntityThatNamesIt'
T_BLOB='Uploads.ABlobThatIsMissingOrIsNotTheDigestIsNeverServed'
T_PERS='Uploads.AFileIsNeverAttachedThroughAPersonalFieldOrAFieldThatIsNotAReference'
T_SIZE='Uploads.TheStructsOfAnUploadAreAcceptedAtOnlyTheirOwnSize'

# A file bigger than the largest the policy allows is stored.
plant size-unchecked $U testUpload "$T_MAX" \
  '  if (len == 0 || (uint64_t)len > policy_max(policy) ||' \
  '  if (len == 0 ||'

# A policy that asks for more than the hard maximum is believed.
plant hard-maximum-dropped $U testUpload "$T_MAX" \
  '  return p->max_bytes == 0 || p->max_bytes > GDEFCORE_UPLOAD_HARD_MAX' \
  '  return p->max_bytes == 0'

plant policy-size-unchecked $U testUpload "$T_POL" \
  '  if (len == 0 || (uint64_t)len > policy_max(policy) ||' \
  '  if (len == 0 || (uint64_t)len > (uint64_t)-1 ||'

plant media-unchecked $U testUpload "$T_POL" \
  '      !gdefcore_upload_media_ok(policy, media, media_len)) {' \
  '      0) {'

plant name-unchecked $U testUpload "$T_POL" \
  '      !gdefcore_upload_name_ok(name, name_len) ||' \
  '      0 ||'

SLASH_OLD="c == 0x7f || c == '/' ||"
SLASH_NEW="c == 0x7f ||"
plant slash-allowed-in-a-name $U testUpload "$T_POL" "$SLASH_OLD" "$SLASH_NEW"

plant create-permission-skipped $U testUpload "$T_PERM" \
  '          &allowed) != GDEFCORE_OK ||
      !allowed) {' \
  '          &allowed) != GDEFCORE_OK ||
      0) {'

# The tenant is not given to the blob store, so two tenants' bytes meet.
plant tenant-dropped $U testUpload "$T_TEN" \
  '  if (blobs->put(blobs->ctx, tenant, tenant_len, hex, bytes, len) != 0) {' \
  '  if (blobs->put(blobs->ctx, tenant, 0, hex, bytes, len) != 0) {'

# A staged file is swept before its expiry.
plant expiry-ignored $U testUpload "$T_LIFE" \
  '    } else if (used == 0 && exp <= now_ms) {' \
  '    } else if (used == 0 && (exp <= now_ms || exp > 0)) {'

# The blob of a deleted file stays in the store.
plant blob-left-behind $U testUpload "$T_LIFE" \
  '          (void)blobs->remove(blobs->ctx, tenant, tenant_len, digest);' \
  '          (void)digest;'

# A reference saved just before the sweep is lost to an expiry that has passed.
plant expired-reference-lost $U testUpload "$T_PROMO" \
  '    if (used > 0 && strcmp(state, GDEFCORE_UPLOAD_STATE_KEPT) != 0) {' \
  '    if (used > 0 && exp > now_ms && strcmp(state, GDEFCORE_UPLOAD_STATE_KEPT) != 0) {'

# A reference inside a group item, or in a many-valued field, is not counted.
plant group-reference-not-seen $U testUpload "$T_COUNT" \
  '            if (!path_wanted(ps, path, plen)) {' \
  '            if (!path_wanted(ps, path, plen) || item.path_len > 0) {'

plant unreferenced-not-demoted $U testUpload "$T_DEMO" \
  '    } else if (used == 0 && strcmp(state, GDEFCORE_UPLOAD_STATE_KEPT) == 0) {' \
  '    } else if (0) {'

# A file nothing references any more gets no time: it is the old expiry's.
plant demoted-without-new-expiry $U testUpload "$T_DEMO" \
  '      rc = set_state(catalog, ids[i], GDEFCORE_UPLOAD_STATE_STAGED, now_ms + policy_ttl(policy));' \
  '      rc = set_state(catalog, ids[i], GDEFCORE_UPLOAD_STATE_STAGED, now_ms);'

# Another file's blob is removed with this one's.
plant shared-blob-removed $U testUpload "$T_SHARE" \
  '            !digest_held(catalog, digest, ids[i]) && tenant != NULL) {' \
  '            tenant != NULL) {'

# Anyone reads a staged file.
plant read-skips-access $U testUpload "$T_READ" \
  '      !may_have(catalog, request, canon, state, uploader)) {' \
  '      0) {'

# The references are looked for as the system, so a reader the access filter
# hides the entity from still gets the file.
plant reference-read-as-system $U testUpload "$T_KEPT" \
  '  if (scan(catalog, request, &refs) == GDEFCORE_OK) {' \
  '  if (scan(catalog, NULL, &refs) == GDEFCORE_OK) {'

plant digest-not-verified $U testUpload "$T_BLOB" \
  '  if (strcmp(hex, digest) != 0) {' \
  '  if (0) {'

plant personal-field-allowed $U testUpload "$T_PERS" \
  '      *out_ok = info.type == GDEFSTOR_FIELD_REFERENCE && !info.personal;' \
  '      *out_ok = info.type == GDEFSTOR_FIELD_REFERENCE;'

# The policy's size is read twice (the stage and the type check it calls): both
# are removed, so that the size is the whole of the defect.
plant policy-struct-size-unchecked $U testUpload "$T_SIZE" \
  '      policy->size != sizeof *policy || out_id == NULL || bytes == NULL) {' \
  '      out_id == NULL || bytes == NULL) {' \
  '  if (policy == NULL || policy->size != sizeof *policy || media == NULL || len == 0 ||' \
  '  if (policy == NULL || media == NULL || len == 0 ||'

plant blob-store-size-unchecked $U testUpload "$T_SIZE" \
  '  return b != NULL && b->size == sizeof *b && b->put != NULL && b->get != NULL &&' \
  '  return b != NULL && b->put != NULL && b->get != NULL &&'

# A reference in a language after the first (by bytes) is not seen, so a file named
# only there is swept.
plant only-the-first-language-read $U testUpload \
  'Uploads.AReferenceInAnyLanguageOfAnEntityHoldsTheFile' \
  '        for (l = 0; l < nlangs && rr == GDEFCORE_OK; l++) {' \
  '        for (l = 0; l < (nlangs > 1 ? 1 : nlangs) && rr == GDEFCORE_OK; l++) {'

# A draft that names a file does not hold it, so the editor's unpublished work is swept.
plant drafts-not-counted $U testUpload \
  'Uploads.ADraftThatNamesAFileHoldsItAsAPublishedRevisionDoes' \
  '          for (pass = 0; pass < (drafts && request == NULL ? 2 : 1) && rr == GDEFCORE_OK;' \
  '          for (pass = 0; pass < (0 && drafts && request == NULL ? 2 : 1) && rr == GDEFCORE_OK;'

plant_finish
