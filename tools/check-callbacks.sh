#!/bin/sh
#
# The access-callback gate (access-conditions story A6, CAP-A5): a module
# registers a callback that grants a field or an operation, per entity, for
# what data cannot say. Runs the Callbacks tests on the real tree, then plants
# each defect in a COPY of the source by an exact text edit and requires the
# named test to fail (tools/plant-lib.sh):
#
# The story's five:
#
#   callback-counted-in-a-list         Callbacks.AListCountsAndPagesWithoutCallingTheCallback
#   validity-token-left-out-of-the-key Callbacks.ARenderThatConsultedACallbackCarriesItsValidityToken
#   locked-returns-the-value           Callbacks.APrincipalWhoHasNotPaidSeesTheTitleAndLockedNeverTheBody
#   trapping-callback-grants           Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing
#   governed-field-in-a-filter         Callbacks.AGovernedFieldIsRefusedInAFilterSortOrCondition
#
# and the rest of the story's rules:
#
#   row-scope-registered               Callbacks.RowScopeIsRefusedAtRegistration
#   row-action-by-callback             Callbacks.RowScopeIsRefusedAtRegistration
#   callback-not-batched               Callbacks.APageOfTwentyIsOneCallAndASecondReadIsMemoized
#   callback-not-memoized              Callbacks.APageOfTwentyIsOneCallAndASecondReadIsMemoized
#   timeout-ignored                    Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing
#   fuel-ignored                       Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing
#   callback-reentered-grants          Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing
#   uncacheable-cached                 Callbacks.ATimeToLiveMovesTheKeyAndNoCacheabilityIsUncacheable
#   ttl-window-ignored                 Callbacks.ATimeToLiveMovesTheKeyAndNoCacheabilityIsUncacheable
#   matrix-omits-callbacks             Callbacks.TheMatrixShowsTheCallbackAndTheEnableRatesItHigh
#   callback-enable-not-shown          Callbacks.TheMatrixShowsTheCallbackAndTheEnableRatesItHigh
#   callback-at-type-level             Callbacks.AnOperationCallbackDecidesCanOnOneEntity
#   locked-without-opt-in              Callbacks.AFieldThatDoesNotOptInReadsAbsentNotLocked
#
# Every test has a control (the principal who paid beside the one who did
# not, the field that is not governed beside the one that is, the callback
# that answers beside the one that fails), so a plant turning one red is a
# test seeing the defect, not a build failure.
#
# Usage: check-callbacks.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testCallbacks 'Callbacks.*'

ACCESS=src/access/access.c
DECL=src/module/decl.c
MODULE=src/module/module.c
FRAGMENT=src/render/fragment.c

# Plant 1: the list asks the callback about the page it returns ("to batch
# it"): a callback consulted by a list.
plant callback-counted-in-a-list $ACCESS testCallbacks \
  'Callbacks.AListCountsAndPagesWithoutCallingTheCallback' \
  '    (void)gdefcore_request_set_batch(request, local.type_name,
        local.type_name_len, (const char * const *)*out_ids, *out_count);' \
  '    (void)gdefcore_request_set_batch(request, local.type_name,
        local.type_name_len, (const char * const *)*out_ids, *out_count);
    for (i = 0; i < *out_count; i++) {
      size_t g;
      ev->id = (*out_ids)[i];
      for (g = 0; g < ngrants; g++) {
        if (grants[g].source == kSrcCallback) {
          (void)callback_holds(ev, &grants[g]);
        }
      }
    }'

# Plant 2: the render key leaves out what the callbacks answered.
plant validity-token-left-out-of-the-key $ACCESS testCallbacks \
  'Callbacks.ARenderThatConsultedACallbackCarriesItsValidityToken' \
  '      ADD_KEY("\ncallbacks:", 11);
      ADD_KEY(validity_hex, strlen(validity_hex));' \
  '      (void)validity_hex;'

# Plant 3: the locked path hands over the values it only had to count.
plant locked-returns-the-value $ACCESS testCallbacks \
  'Callbacks.APrincipalWhoHasNotPaidSeesTheTitleAndLockedNeverTheBody' \
  '        *out_locked = nheld > 0;
        for (k = 0; k < nheld; k++) {
          if (held[k] != NULL && held_lens[k] > 0) {
            gsec_wipe(held[k], held_lens[k]);
          }
        }
        gdefcore_values_free(catalog, held, held_lens, nheld);' \
  '        *out_locked = nheld > 0;
        (void)k;
        *out_texts = held;
        *out_lens = held_lens;
        *out_count = nheld;'

# Plant 4: a callback that returned an error keeps what it wrote.
plant trapping-callback-grants $ACCESS testCallbacks \
  'Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing' \
  '    if (rc != GDEFCORE_OK) {
      reason = "trapped";' \
  '    if (rc != GDEFCORE_OK && 0) {
      reason = "trapped";'

# Plant 5: the list takes a filter on the governed field from a principal who
# may read it.
plant governed-field-in-a-filter $ACCESS testCallbacks \
  'Callbacks.AGovernedFieldIsRefusedInAFilterSortOrCondition' \
  '            local.filter_field, local.filter_field_len) ||
        gdefcore_access_field_governed(catalog, local.type_name,
            local.type_name_len, local.filter_field, local.filter_field_len) ||' \
  '            local.filter_field, local.filter_field_len) ||'

# Plant 6: registration takes a row-scope callback.
plant row-scope-registered $DECL testCallbacks \
  'Callbacks.RowScopeIsRefusedAtRegistration' \
  '    if (c.scope == GDEFCORE_CALLBACK_ROW) {' \
  '    if (0 && c.scope == GDEFCORE_CALLBACK_ROW) {' \
  '    if (c.scope != GDEFCORE_CALLBACK_FIELD &&
        c.scope != GDEFCORE_CALLBACK_OPERATION) {' \
  '    if (c.scope != GDEFCORE_CALLBACK_FIELD &&
        c.scope != GDEFCORE_CALLBACK_OPERATION &&
        c.scope != GDEFCORE_CALLBACK_ROW) {'

# Plant 7: the enable takes an operation callback on a row action.
plant row-action-by-callback $MODULE testCallbacks \
  'Callbacks.RowScopeIsRefusedAtRegistration' \
  '    } else if (c->scope == GDEFCORE_CALLBACK_OPERATION &&
               gdefcore_access_row_action(t.action, strlen(t.action))) {' \
  '    } else if (0) {'

# Plant 8: every entity is a call of its own.
plant callback-not-batched $ACCESS testCallbacks \
  'Callbacks.APageOfTwentyIsOneCallAndASecondReadIsMemoized' \
  '    if (nb > 0 && same(btype, btype_len, grant->type_name, grant->type_len)) {' \
  '    if (0 && nb > 0 &&
        same(btype, btype_len, grant->type_name, grant->type_len)) {'

# Plant 9: an answer is not remembered.
plant callback-not-memoized $ACCESS testCallbacks \
  'Callbacks.APageOfTwentyIsOneCallAndASecondReadIsMemoized' \
  '  if (key_len > 0 &&
      gdefcore_request_memo_get(request, key, (size_t)key_len, &value)) {' \
  '  if (0 && key_len > 0 &&
      gdefcore_request_memo_get(request, key, (size_t)key_len, &value)) {'

# Plant 10: a call past its timeout counts.
plant timeout-ignored $ACCESS testCallbacks \
  'Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing' \
  '    } else if (mono_ms() > deadline) {
      reason = "timed-out";' \
  '    } else if (0 && mono_ms() > deadline) {
      reason = "timed-out";'

# Plant 11: a call past its fuel counts.
plant fuel-ignored $ACCESS testCallbacks \
  'Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing' \
  '    } else if (call.over) {
      reason = "out-of-fuel";' \
  '    } else if (0 && call.over) {
      reason = "out-of-fuel";'

# Plant 12: a callback asked from inside a callback grants. (Asking it again
# instead recurses without end, which is a crash, not a test seeing it.)
plant callback-reentered-grants $ACCESS testCallbacks \
  'Callbacks.ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing' \
  '    callback_failed(request, cb, "reentered");
    return 0;' \
  '    callback_failed(request, cb, "reentered");
    return 1;'

# Plant 13: the cache keeps a fragment of an uncacheable request.
plant uncacheable-cached $FRAGMENT testCallbacks \
  'Callbacks.ATimeToLiveMovesTheKeyAndNoCacheabilityIsUncacheable' \
  '  if (!gdefcore_request_cacheable(request)) {' \
  '  if (0 && !gdefcore_request_cacheable(request)) {'

# Plant 14: a time to live is keyed without its window.
plant ttl-window-ignored $ACCESS testCallbacks \
  'Callbacks.ATimeToLiveMovesTheKeyAndNoCacheabilityIsUncacheable' \
  '        (unsigned long)cb->ttl_seconds, (long long)window);' \
  '        (unsigned long)cb->ttl_seconds, (long long)0 * window);'

# Plant 15: the matrix leaves the callbacks out.
plant matrix-omits-callbacks $ACCESS testCallbacks \
  'Callbacks.TheMatrixShowsTheCallbackAndTheEnableRatesItHigh' \
  '    rc = mx_callbacks(&b, host);' \
  '    (void)mx_callbacks;'

# Plant 16: the enable does not show the callback.
plant callback-enable-not-shown $MODULE testCallbacks \
  'Callbacks.TheMatrixShowsTheCallbackAndTheEnableRatesItHigh' \
  '    rc = gdefcore_access_stage_module_callback(changeset, name, name_len,' \
  '    rc = GDEFCORE_OK;
    (void)gdefcore_access_stage_module_callback;
    if (0) gdefcore_access_stage_module_callback(changeset, name, name_len,'

# Plant 17: at type level a callback grant is taken as held.
plant callback-at-type-level $ACCESS testCallbacks \
  'Callbacks.AnOperationCallbackDecidesCanOnOneEntity' \
  '    if (grants[i].condition == kCondCallback) {
      /* Decided per entity, and there is none to ask about (story A6). */
      continue;
    }' \
  '    if (0) {
      continue;
    }'

# Plant 18: a governed field reads locked whether or not it opted in.
plant locked-without-opt-in $ACCESS testCallbacks \
  'Callbacks.AFieldThatDoesNotOptInReadsAbsentNotLocked' \
  '  return gdefcore_module_field_governed(host, tenant, tenant_len, type,
             type_len, field, field_len, &locked) &&
         locked;' \
  '  return gdefcore_module_field_governed(host, tenant, tenant_len, type,
             type_len, field, field_len, &locked);'

plant_finish
