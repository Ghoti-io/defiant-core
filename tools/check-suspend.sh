#!/bin/sh
#
# The suspended-grants gate (access-conditions story A7, part 1): a stored
# grant whose condition names a field an enabled module decides by callback is
# listed at the enable and needs the typed confirmation, shows in the matrix as
# suspended by every module that decides the field, holds nothing, and resumes
# when none does; a restored one is held and reported; a role's grants, a
# module's grants and the callbacks of several modules combine by union, and
# the decision names the source that allowed it. Runs the Suspend and Combine
# tests on the real tree, then plants each defect in a COPY of the source by an
# exact text edit and requires the named test to fail (defiant-storage's
# plant-lib.sh):
#
#   suspended-grant-still-grants     Suspend.TheMatrixShowsASuspendedGrantAndItHoldsNothing
#   suspension-reported-as-failure   Suspend.TheMatrixShowsASuspendedGrantAndItHoldsNothing
#   matrix-hides-suspension          Suspend.TheMatrixShowsASuspendedGrantAndItHoldsNothing
#   enable-does-not-list-the-grants  Suspend.EnablingListsTheGrantsItWouldSuspendAndNeedsTheTypedConfirmation
#   suspended-by-names-one-module    Suspend.TwoModulesGovernOneFieldAndTheGrantResumesWhenNoneDoes
#   restore-applies-governed-grant   Suspend.ARestoredGrantNamingAGovernedFieldIsHeldAndReported
#   failing-source-cancels-an-allow  Combine.AFailingConditionBesideAnAllowingCallbackIsNotAnError
#   failing-source-cancels-field-allow
#                                    Combine.AFailingConditionBesideAnAllowingCallbackIsNotAnError
#   callbacks-share-one-memo-entry   Combine.TwoCallbacksOnOneFieldKeepTheirAnswersApart
#   decision-names-no-source         Combine.TheDecisionNamesTheSourceThatAllowedIt
#   callback-asked-beside-a-grant    Combine.ACallbackBesideARoleGrantIsAskedOnlyWhereTheRoleDoesNotAllow
#   (and the stale-object plant: a plant whose rebuild is made not to happen is
#   refused as a STALE OBJECT)
#
# Every test has a control (the same call before the module, the grant that is
# not suspended beside the one that is, the source that answers beside the one
# that fails), so a plant turning one red is a test seeing the defect, not a
# build failure.
#
# Usage: check-suspend.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testSuspend '*'

ACCESS=src/access/access.c
MODULE=src/module/module.c
EVAL=src/condition/condition_eval.c
PLAN=src/condition/condition_plan.c

SUSPEND_OLD='  slot->suspended =
      gov_modules(&ev->gov, slot->cond, grant->type_name, grant->type_len,
          mods) > 0;'
SUSPEND_NEW='  (void)mods;
  (void)grant;
  slot->suspended = 0;'

# Plant 1: a suspended grant still grants. The suspension is turned off, and so
# is the evaluator's refusal of a governed field behind it (the backstop), so
# that the grant is evaluated on the very value only the callback may read.
plantm suspended-grant-still-grants testSuspend \
  'Suspend.TheMatrixShowsASuspendedGrantAndItHoldsNothing' \
  $ACCESS "$SUSPEND_OLD" "$SUSPEND_NEW" \
  $EVAL '      !vals->f.found || vals->f.personal || vals->f.governed) {' \
        '      !vals->f.found || vals->f.personal) {' \
  $PLAN '      !info->found || info->personal || info->governed) {' \
        '      !info->found || info->personal) {'

# Plant 2: the suspension is turned off, so the backstop fails the condition
# closed: it still holds nothing, but as a failure the request reports, which a
# state the matrix shows and the enable confirmed must not be.
plant suspension-reported-as-failure $ACCESS testSuspend \
  'Suspend.TheMatrixShowsASuspendedGrantAndItHoldsNothing' \
  "$SUSPEND_OLD" "$SUSPEND_NEW"

# Plant 3: the matrix shows the grant as an active one.
plant matrix-hides-suspension $ACCESS testSuspend \
  'Suspend.TheMatrixShowsASuspendedGrantAndItHoldsNothing' \
  '      if (slot->suspended) {
        susp_len = suspended_by_of(ev, slot->cond, grants[i].type_name,' \
  '      if (0 && slot->suspended) {
        susp_len = suspended_by_of(ev, slot->cond, grants[i].type_name,'

# Plant 4: the enable does not list the grants it would suspend.
plant_stale stale-object $MODULE testSuspend \
  'Suspend.EnablingListsTheGrantsItWouldSuspendAndNeedsTheTypedConfirmation' \
  '  rc = gdefcore_access_stage_module_suspensions(changeset, name, name_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }' \
  ''
plant enable-does-not-list-the-grants $MODULE testSuspend \
  'Suspend.EnablingListsTheGrantsItWouldSuspendAndNeedsTheTypedConfirmation' \
  '  rc = gdefcore_access_stage_module_suspensions(changeset, name, name_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }' \
  ''

# Plant 5: the matrix names one of the modules that decide the field.
plant suspended-by-names-one-module $ACCESS testSuspend \
  'Suspend.TwoModulesGovernOneFieldAndTheGrantResumesWhenNoneDoes' \
  '  size_t at = 0;
  size_t i;
  for (i = 0; i < n; i++) {
    size_t need = mods[i]->module_len + (i > 0 ? 2 : 0);' \
  '  size_t at = 0;
  size_t i;
  for (i = 0; i < n && i < 1; i++) {
    size_t need = mods[i]->module_len + (i > 0 ? 2 : 0);'

# Plant 6: a restore applies a grant that names a governed field, unreported.
plant restore-applies-governed-grant $ACCESS testSuspend \
  'Suspend.ARestoredGrantNamingAGovernedFieldIsHeldAndReported' \
  '    held[i].keep = suspended_only && held[i].by == NULL;' \
  '    held[i].keep = suspended_only;'

# Plant 7: a source that cannot be decided cancels another source's allow.
plant failing-source-cancels-an-allow $ACCESS testSuspend \
  'Combine.AFailingConditionBesideAnAllowingCallbackIsNotAnError' \
  '  if (failed && !allowed) {' \
  '  if (failed) {'

# Plant 8: the same in the field-level decision.
plant failing-source-cancels-field-allow $ACCESS testSuspend \
  'Combine.AFailingConditionBesideAnAllowingCallbackIsNotAnError' \
  '  rc = ev.failed && !allowed ? GDEFCORE_ERR_INTERNAL : GDEFCORE_OK;' \
  '  rc = ev.failed ? GDEFCORE_ERR_INTERNAL : GDEFCORE_OK;'

# Plant 9: two callbacks of two modules share one memo entry: the key names
# neither the module nor the callback.
plant callbacks-share-one-memo-entry $ACCESS testSuspend \
  'Combine.TwoCallbacksOnOneFieldKeepTheirAnswersApart' \
  '      (int)cb->module_len, cb->module, (int)cb->name_len, cb->name,
      (int)who_len, who, (int)agent_len, agent, entity,' \
  '      (int)(0 * cb->module_len), "", 0, "",
      (int)who_len, who, (int)agent_len, agent, entity,'

# Plant 10: a decision does not record which source allowed it.
plant decision-names-no-source $ACCESS testSuspend \
  'Combine.TheDecisionNamesTheSourceThatAllowedIt' \
  '  if (allowed && dec != NULL && win >= 0) {
    source_fill(catalog, &grants[win], dec);
  }' \
  '  if (0 && allowed && dec != NULL && win >= 0) {
    source_fill(catalog, &grants[win], dec);
  }'

# Plant 11: a callback is asked beside a grant that already holds (the grants
# are no longer tried in order, each only if none before it allowed).
plant callback-asked-beside-a-grant $ACCESS testSuspend \
  'Combine.ACallbackBesideARoleGrantIsAskedOnlyWhereTheRoleDoesNotAllow' \
  '    for (i = 0; i < ngrants && !allowed; i++) {
      if (grants[i].field_len != 0 ||' \
  '    for (i = 0; i < ngrants; i++) {
      if (grants[i].field_len != 0 ||'

plant_finish
