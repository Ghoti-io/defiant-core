#!/bin/sh
#
# The can() gate (access-conditions story A5): one decision, memoized, shared by
# the write path, the route check, the tab list and the template editor. Runs
# the Can tests on the real tree, then plants each defect in a COPY of the
# source by an exact text edit and requires the named test to fail:
#
#   route-check-reads-another-predicate  Can.RouteAndTabsFollowTheDecision
#   memo-ignores-revision                Can.AWriteInTheRequestIsANewQuestion
#   memo-ignores-principal               Can.MemoIsPerPrincipal
#   failure-reads-as-a-clean-no          Can.ACorruptConditionIsAFailureNotAYes
#   decision-failure-grants              CanFailures.AnAllocationThatFailsNeverGrants
#   missing-answers-unlike-unreadable    Can.UnknownMissingAndUnreadableAnswerAlike
#   tabs-skip-the-filter                 Can.RouteAndTabsFollowTheDecision
#   principal-dependent-mark-left-off    Can.MarksTheRequestAndRecordsWhatItRead
#   fuel-exhaustion-grants               Can.NoFuelIsNotAYes
#   memo-unbounded                       Can.MemoIsBounded
#   type-level-used-for-an-entity        Can.TypeLevelIsNotTheEntityQuestion
#   template-authorize-skips-modules     Can.TemplateSaveIsTheDecision
#   write-path-not-asked                 Can.TheDecisionIsTheOperation
#   ceiling-not-set-up                   Can.AnAgentIsBoundByItsCeiling
#   draft-readable                       Can.TheDecisionIsTheOperation, Oracle.Entities
#   missing-answers-unlike-hidden        Oracle.Entities
#
# Every test has a control (the same call that must be a yes is made beside
# the one that must be a no, and the sweep counts both outcomes of every
# operation), so a plant turning one red is a test seeing the defect, not a
# build failure. The sweep also holds the decision to a model of the fixture
# written apart from the library, because the operations it guards ask the
# decision themselves.
#
# Usage: check-can.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testCan 'Can.*:CanFailures.*'
plant_control testOracle 'Oracle.*'

ACCESS=src/access/access.c

# Plant 1: the route check asks the type-level question where the write asks
# about the entity.
plant route-check-reads-another-predicate $ACCESS testCan 'Can.RouteAndTabsFollowTheDecision' \
  '  rc = gdefcore_access_can(catalog, call->request, permission, permission_len,
      type, type_len, canon, &allowed);
  gdefcore_text_free(catalog, type);
  return rc == GDEFCORE_OK && allowed;' \
  '  allowed = gdefcore_access_permits(catalog, call->request, permission,
      permission_len);
  rc = GDEFCORE_OK;
  gdefcore_text_free(catalog, type);
  return rc == GDEFCORE_OK && allowed;'

# Plant 2: the memo is not keyed on the entity's revision.
plant memo-ignores-revision $ACCESS testCan 'Can.AWriteInTheRequestIsANewQuestion' \
  '      entity == NULL ? "*" : entity, (unsigned long long)version);' \
  '      entity == NULL ? "*" : entity, (unsigned long long)(version * 0));'

# Plant 3: the memo is not keyed on the principal.
plant memo-ignores-principal $ACCESS testCan 'Can.MemoIsPerPrincipal' \
  '      (int)(principal == NULL ? 1 : principal_len),
      principal == NULL ? "-" : principal,' \
  '      (int)(1 + 0 * principal_len), principal == NULL ? "-" : "-",'

# Plant 4a: a condition that could not be decided is reported as a plain no, as
# if nothing had gone wrong.
plant failure-reads-as-a-clean-no $ACCESS testCan 'Can.ACorruptConditionIsAFailureNotAYes' \
  '  if (failed) {
    /* A condition that could not be decided is not a no that can be
     * remembered, and not a yes. */
    return GDEFCORE_ERR_INTERNAL;
  }' \
  '  if (0 && failed) {
    /* A condition that could not be decided is not a no that can be
     * remembered, and not a yes. */
    return GDEFCORE_ERR_INTERNAL;
  }'

# Plant 4b: any failure of the decision is a yes.
plant decision-failure-grants $ACCESS testCan 'CanFailures.AnAllocationThatFailsNeverGrants' \
  '  rc = can_decide(catalog, request, permission, permission_len, type, type_len,
      entity_id == NULL ? NULL : canon, &allowed);
  if (rc != GDEFCORE_OK) {
    return rc;
  }' \
  '  rc = can_decide(catalog, request, permission, permission_len, type, type_len,
      entity_id == NULL ? NULL : canon, &allowed);
  if (rc != GDEFCORE_OK) {
    *out_allowed = 1;
    return rc;
  }'

# Plant 5: an entity that is not there answers with a result code, unlike one
# that is there and may not be touched.
plant missing-answers-unlike-unreadable $ACCESS testCan 'Can.UnknownMissingAndUnreadableAnswerAlike' \
  '    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        &actual_type, &actual_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_OK;
    }' \
  '    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        &actual_type, &actual_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_ERR_INVALID;
    }'

# Plant 5b: the same, seen by the oracle sweep.
plant missing-answers-unlike-hidden $ACCESS testOracle 'Oracle.Entities' \
  '    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        &actual_type, &actual_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_OK;
    }' \
  '    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        &actual_type, &actual_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_ERR_INVALID;
    }'

# Plant 6: the tab list does not ask the check.
plant tabs-skip-the-filter src/form/form.c testCan 'Can.RouteAndTabsFollowTheDecision' \
  '      if (!allowed) {
        continue;
      }
    }
    all[kept++] = all[i];' \
  '      (void)allowed;
    }
    all[kept++] = all[i];'

# Plant 7: a decision does not mark the request as depending on its principal.
plant principal-dependent-mark-left-off $ACCESS testCan 'Can.MarksTheRequestAndRecordsWhatItRead' \
  '  gdefcore_request_mark_principal_dependent(request);
  rc = gdefcore_request_spend_fuel(request, GDEFCORE_ACCESS_CAN_FUEL_HIT);' \
  '  rc = gdefcore_request_spend_fuel(request, GDEFCORE_ACCESS_CAN_FUEL_HIT);'

# Plant 8: no fuel is a yes.
plant fuel-exhaustion-grants $ACCESS testCan 'Can.NoFuelIsNotAYes' \
  '  rc = gdefcore_request_spend_fuel(request, GDEFCORE_ACCESS_CAN_FUEL_HIT);
  if (rc != GDEFCORE_OK) {
    return rc;
  }' \
  '  rc = gdefcore_request_spend_fuel(request, GDEFCORE_ACCESS_CAN_FUEL_HIT);
  if (rc != GDEFCORE_OK) {
    *out_allowed = 1;
    return rc;
  }'

# Plant 9: the memo never starts over.
plant memo-unbounded src/request/request.c testCan 'Can.MemoIsBounded' \
  '  if (request->nmemo >= GDEFCORE_REQUEST_MEMO_MAX) {' \
  '  if (0 && request->nmemo >= GDEFCORE_REQUEST_MEMO_MAX) {'

# Plant 10: the type-level question is asked where an entity was given.
plant type-level-used-for-an-entity $ACCESS testCan 'Can.TypeLevelIsNotTheEntityQuestion' \
  '  rc = can_decide(catalog, request, permission, permission_len, type, type_len,
      entity_id == NULL ? NULL : canon, &allowed);' \
  '  rc = can_decide(catalog, request, permission, permission_len, type, type_len,
      NULL, &allowed);'

# Plant 11: the template editor reads the roles' grants and not the modules'.
plant template-authorize-skips-modules src/template/template.c testCan 'Can.TemplateSaveIsTheDecision' \
  '    allowed = kind_len > 0 && template_can(catalog, request, kind, kind_len, canon);' \
  '    allowed = 0;
    if (kind_len > 0) {
      char * lab = NULL;
      size_t lab_len = 0;
      size_t who_len = 0;
      const char * who = gdefcore_request_principal(request, &who_len);
      char ** roles = NULL;
      size_t nroles = 0;
      size_t r;
      if (gdefcore_template_edit_label(catalog, kind, kind_len, &lab, &lab_len) ==
              GDEFCORE_OK) {
        if (who != NULL &&
            gdefcore_access_principal_roles(catalog, who, who_len, &roles,
                &nroles) == GDEFCORE_OK) {
          for (r = 0; r < nroles && !allowed; r++) {
            char ** labels = NULL;
            size_t nl = 0;
            size_t g;
            if (gdefcore_access_role_grants(catalog, roles[r], strlen(roles[r]),
                    &labels, &nl) == GDEFCORE_OK) {
              for (g = 0; g < nl; g++) {
                if (strlen(labels[g]) == lab_len &&
                    memcmp(labels[g], lab, lab_len) == 0) {
                  allowed = 1;
                }
              }
              gdefcore_access_free(catalog, labels, nl);
            }
          }
          gdefcore_access_free(catalog, roles, nroles);
        }
        gdefcore_text_free(catalog, lab);
      }
    }'

# Plant 12: apply does not ask the decision for what it writes.
plant write-path-not-asked src/entity/entity.c testCan 'Can.TheDecisionIsTheOperation' \
  '  if (changeset->enforce_access) {
    rc = authorize_writes(changeset);' \
  '  if (0 && changeset->enforce_access) {
    rc = authorize_writes(changeset);'

# Plant 13: the decision never sets up the acting principal's ceiling.
plant ceiling-not-set-up $ACCESS testCan 'Can.AnAgentIsBoundByItsCeiling' \
  '  (void)setup_ceiling(&ev);
  if (canon == NULL) {' \
  '  if (canon == NULL) {'

# Plant 14: a draft is readable to the decision, though not to a read.
plant draft-readable $ACCESS testCan 'Can.TheDecisionIsTheOperation' \
  '    if (allowed && same(permission, permission_len, "read", 4)) {' \
  '    if (0 && allowed && same(permission, permission_len, "read", 4)) {'

plant draft-readable-oracle $ACCESS testOracle 'Oracle.Entities' \
  '    if (allowed && same(permission, permission_len, "read", 4)) {' \
  '    if (0 && allowed && same(permission, permission_len, "read", 4)) {'

plant_finish
