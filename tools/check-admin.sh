#!/bin/sh
#
# The admin-area gate (site admin story 13): the permissions of the admin pages,
# the first administrator's grants, and the matrix that asks a grant and not a
# role's name. Runs the AdminArea tests on the real tree, then plants each
# defect in a COPY of the source by an exact text edit and requires the named
# test to fail:
#
#   matrix-asks-the-role-name        AdminArea.ARoleNamedAdminWithNoGrantsReachesNothing
#   seed-grants-only-the-area        AdminArea.TheFirstAdministratorHoldsEveryPermissionAPageAsks
#   seed-runs-every-time             AdminArea.SeedingAgainDoesNotGiveBackWhatWasRevoked
#   admin-role-cannot-be-revoked     AdminArea.ARevokedGrantOfTheAdminRoleTakesEffect
#   undo-shares-the-areas-action     AdminArea.AGrantOpensTheOnePageItGovernsAndNoOther
#   declare-grants-the-admin-role    AdminArea.DeclaringGrantsNobodyAndNullIsRefused
#
# Every test has a control (the call that must be allowed is made beside the one
# that must be refused), so a plant turning one red is a test seeing the defect,
# not a build failure.
#
# Usage: check-admin.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testAdmin 'AdminArea.*'

ACCESS=src/access/access.c
ADMIN=src/access/adminarea.c

# The matrix asks whether the person holds the role named admin, as it did.
plant matrix-asks-the-role-name $ACCESS testAdmin 'AdminArea.ARoleNamedAdminWithNoGrantsReachesNothing' \
  '  if (!gdefcore_access_permits(catalog, request, GDEFCORE_ACCESS_READ,
          sizeof GDEFCORE_ACCESS_READ - 1)) {
    return GDEFCORE_ERR_INVALID;
  }' \
  '  char plant_who[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t plant_n = 0;
  const char * plant_id = gdefcore_request_principal(request, &plant_n);
  int plant_admin = 0;
  if (plant_id != NULL && plant_n == GDEFCORE_PUBLIC_ID_LEN) {
    memcpy(plant_who, plant_id, plant_n);
    plant_who[plant_n] = '"'"'\0'"'"';
    (void)holds_admin(catalog, plant_who, &plant_admin);
  }
  if (!plant_admin) {
    return GDEFCORE_ERR_INVALID;
  }'

# The seed grants the area and leaves the pages' permissions out: the first
# administrator is locked out of every page but the home.
plant seed-grants-only-the-area $ADMIN testAdmin 'AdminArea.TheFirstAdministratorHoldsEveryPermissionAPageAsks' \
  '  for (i = 0; rc == GDEFCORE_OK && i < sizeof kLabels / sizeof kLabels[0]; i++) {' \
  '  for (i = 0; rc == GDEFCORE_OK && kLabels[0] == NULL && i < sizeof kLabels / sizeof kLabels[0]; i++) {'

# The seed does not remember that it was done: every start gives back what was
# revoked.
plant seed-runs-every-time $ADMIN testAdmin 'AdminArea.SeedingAgainDoesNotGiveBackWhatWasRevoked' \
  '          sizeof GDEFCORE_ADMIN_USE_LABEL - 1, &info) == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }' \
  '          sizeof GDEFCORE_ADMIN_USE_LABEL - 1, &info) == GDEFCORE_OK && info.size == 0) {
    return GDEFCORE_OK;
  }'

# The admin role cannot be revoked from, as it could not before: the "revoked"
# row of the matrix cannot happen.
plant admin-role-cannot-be-revoked $ACCESS testAdmin 'AdminArea.ARevokedGrantOfTheAdminRoleTakesEffect' \
  '  rc = find_role(catalog, role, role_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_role_grants(catalog, role_id, existing, kGrantMax, &nexisting);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < nexisting; i++) {
    if (!same(existing[i].label' \
  '  if (same(role, role_len, kAdmin, strlen(kAdmin))) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_role(catalog, role, role_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_role_grants(catalog, role_id, existing, kGrantMax, &nexisting);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < nexisting; i++) {
    if (!same(existing[i].label'

# The undo page asks the action of the area: whoever may use the area may undo.
plant undo-shares-the-areas-action $ADMIN testAdmin 'AdminArea.AGrantOpensTheOnePageItGovernsAndNoOther' \
  '      declare_one(catalog, GDEFCORE_ADMIN_UNDO_LABEL, GDEFCORE_ADMIN_UNDO, kRoleType);' \
  '      declare_one(catalog, GDEFCORE_ADMIN_UNDO_LABEL, GDEFCORE_ADMIN_USE, kRoleType);'

# Declaring grants the administrator too: the "granted to nobody" of the
# permission is false.
plant declare-grants-the-admin-role $ADMIN testAdmin 'AdminArea.DeclaringGrantsNobodyAndNullIsRefused' \
  '  rc = declare_pages(catalog);
  if (rc == GDEFCORE_OK) {
    rc = declare_area(catalog);
  }
  return rc;
}' \
  '  rc = declare_pages(catalog);
  if (rc == GDEFCORE_OK) {
    rc = declare_area(catalog);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_access_grant(catalog, "admin", 5, GDEFCORE_ACCESS_READ_LABEL,
        sizeof GDEFCORE_ACCESS_READ_LABEL - 1, "core.role", 9);
  }
  return rc;
}'

plant_finish
