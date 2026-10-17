#!/bin/sh
#
# The entry-path gate (access-conditions story A5b, SPEC decisions 7 and 8).
# Protection is on the path: a route that names a permission and the capture
# of its entity, and a handler that calls library code, which asks nothing. A
# condition is evaluated only on the stored entity the path names, never on
# what was submitted. Runs the EntryPath tests on the real tree, then plants
# each defect in a COPY of the source by an exact text edit and requires the
# named test to fail:
#
#   create-fields-unchecked        EntryPath.ACreateCanBeLimitedFieldByField
#   create-container-ignored       EntryPath.CreateIsCheckedAgainstTheContainerThePathNames
#   field-limit-ignored            EntryPath.ACreateCanBeLimitedFieldByField
#   field-grant-ignores-entity     EntryPath.AFieldGrantOnAnEntityIsDecidedOnTheStoredEntity
#   authorize-skips-can            EntryPath.AuthorizeAsksTheTokensTarget
#   path-decides-on-the-requests-id
#                                  EntryPath.AuthorizeAsksTheTokensTarget
#
# Every test has a control (the same path, the same principal, one thing
# different, and the answer differs), so a plant turning one red is a test
# seeing the defect, not a build failure. The sweep over every operation and
# every person is Can.TheDecisionIsTheOperation in check-can.sh.
#
# Usage: check-paths.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testEntrypaths 'EntryPath.*'

ACCESS=src/access/access.c
FORM=src/form/form.c
ENT=src/entity/entity.c

# Plant 1: a create is not asked about the fields it supplies.
plant create-fields-unchecked $ACCESS testEntrypaths \
  'EntryPath.ACreateCanBeLimitedFieldByField' \
  '  for (i = 0; i < nfields; i++) {
    int field_ok = 0;' \
  '  for (i = 0; i < 0 * nfields; i++) {
    int field_ok = 0;'

# Plant 2: the container the path names is ignored; only the type is asked.
plant create-container-ignored $ACCESS testEntrypaths \
  'EntryPath.CreateIsCheckedAgainstTheContainerThePathNames' \
  '  if (container != NULL) {
    /* The container is the one the path names' \
  '  if (0 && container != NULL) {
    /* The container is the one the path names'

# Plant 3: a field that a permission limits is free.
plant field-limit-ignored $ACCESS testEntrypaths \
  'EntryPath.ACreateCanBeLimitedFieldByField' \
  '  if (!restricted) {
    /* No permission limits this field' \
  '  if (1 || !restricted) {
    /* No permission limits this field'

# Plant 4: a field grant asked of a stored entity is decided as if there were
# none, which lets any grant whose condition could apply to something hold.
plant field-grant-ignores-entity $ACCESS testEntrypaths \
  'EntryPath.AFieldGrantOnAnEntityIsDecidedOnTheStoredEntity' \
  '      entity_id == NULL);
  if (allowed && entity_id == NULL && ev.has_ceiling) {' \
  '      1);
  if (allowed && entity_id == NULL && ev.has_ceiling) {'

# Plant 5: the signed-form path does not ask the decision.
plant authorize-skips-can $FORM testEntrypaths \
  'EntryPath.AuthorizeAsksTheTokensTarget' \
  '  rc = gdefcore_access_can(catalog, request, guard->action, guard->action_len,
      type, type_len, opened->target, out_allowed);' \
  '  *out_allowed = 1;
  rc = GDEFCORE_OK;
  (void)request;'

# Plant 6: the path takes the entity it asks about from the request (a route
# capture, a field of the form) instead of from the token's target.
plant path-decides-on-the-requests-id $FORM testEntrypaths \
  'EntryPath.AuthorizeAsksTheTokensTarget' \
  '  if (guard->claimed != NULL) {
    if (gdefcore_id_canonical(guard->claimed, guard->claimed_len, claimed) !=
            GDEFCORE_OK ||
        memcmp(claimed, opened->target, GDEFCORE_PUBLIC_ID_LEN) != 0) {
      return GDEFCORE_OK;
    }
  }
  rc = gdefcore_entity_type(catalog, opened->target, GDEFCORE_PUBLIC_ID_LEN,
      &type, &type_len);' \
  '  const char * subject = opened->target;
  if (guard->claimed != NULL) {
    if (gdefcore_id_canonical(guard->claimed, guard->claimed_len, claimed) !=
        GDEFCORE_OK) {
      return GDEFCORE_OK;
    }
    subject = claimed;
  }
  rc = gdefcore_entity_type(catalog, subject, GDEFCORE_PUBLIC_ID_LEN,
      &type, &type_len);' \
  '      type, type_len, opened->target, out_allowed);
  gdefcore_text_free(catalog, type);' \
  '      type, type_len, subject, out_allowed);
  gdefcore_text_free(catalog, type);'

plant_finish
