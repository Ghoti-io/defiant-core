#!/bin/sh
#
# The conditional access sweep gate (AD-25, access-conditions story A7, CAP-A6):
# every value derived from a gated one is gated the same way. A canary (a
# value only an authorized reader may see) and a principal who does not meet
# its condition are swept across every output the library derives from it,
# each with a control principal who must see the canary, before and after the
# condition changes (a grant revoked, a published flag cleared, a callback's
# answer changed, a module disabled, time passing). Runs the Sweep tests on
# the real tree, then plants, in a COPY of the source and by an exact text
# edit, a defect that makes each output carry the canary, and requires the
# named test to fail (defiant-storage's plant-lib.sh):
#
#   read-field-filter-skipped           Sweep.ReadCarriesNoCanary
#   read-entity-filter-skipped          Sweep.ReadCarriesNoCanary
#   tree-field-filter-skipped           Sweep.TreeCarriesNoCanary
#   revision-field-filter-skipped       Sweep.RevisionCarriesNoCanary
#   list-skips-visibility               Sweep.ListCarriesNoCanary
#   list-filters-a-field-it-may-not-name  Sweep.ListCarriesNoCanary
#   count-skips-visibility              Sweep.CountCarriesNoCanary
#   form-field-filter-skipped           Sweep.FormCarriesNoCanary
#   summary-built-from-an-unfiltered-body
#                                       Sweep.RecentPostsSummaryCarriesNoCanary
#   render-reads-an-unfiltered-entity   Sweep.RenderCarriesNoCanary
#   fragment-key-ignores-the-principal  Sweep.FragmentCacheCarriesNoCanary
#   cached-derivation-outlives-a-revoked-grant
#                                       Sweep.FragmentCacheCarriesNoCanary
#   render-key-ignores-the-time         Sweep.FragmentCacheCarriesNoCanary
#   export-route-ignores-the-condition  SweepOps.SubjectExportCarriesNoCanaryToTheUnauthorized
#   snapshot-route-ignores-the-permission
#                                       SweepOps.SnapshotCarriesNoCanaryToTheUnauthorized
#   personal-value-stored-as-plaintext  SweepOps.StoredProjectionHoldsNoPersonalPlaintext,
#                                       SweepOps.SnapshotCarriesNoCanaryToTheUnauthorized
#   search-added-and-not-listed         SweepList.EveryDerivedOutputIsListed
#   (and the stale-object plant)
#
# Every test has controls (the principal who meets the condition beside the one
# who does not, the second authorized principal who keeps the canary after the
# change), so a plant turning one red is a test seeing the defect, not a build
# failure.
#
# Usage: check-sweep.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testSweep '*'

ACCESS=src/access/access.c
FORM=src/form/form.c
RENDER=src/render/render.c
SUBJECT=src/subject/subject.c
HEADER=include/ghoti.io/defiant-core/access.h

READ_OLD='  if (visible && type_has_field(catalog, type_name, type_len, field,
                     field_len) &&
      field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {
    granted = field_granted('
READ_NEW='  if (0 && visible && type_has_field(catalog, type_name, type_len, field,
                     field_len) &&
      field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {
    granted = field_granted('

# The stale-object plant: a plant whose rebuild is made not to happen is
# refused as a STALE OBJECT, so a warm copy cannot pass with the defect never
# built in.
plant_stale stale-object $ACCESS testSweep 'Sweep.ReadCarriesNoCanary' \
  "$READ_OLD" "$READ_NEW"

# Read: a field the principal may not read is returned.
plant read-field-filter-skipped $ACCESS testSweep 'Sweep.ReadCarriesNoCanary' \
  "$READ_OLD" "$READ_NEW"

# Read: an entity the principal may not see is returned.
plant read-entity-filter-skipped $ACCESS testSweep 'Sweep.ReadCarriesNoCanary' \
  '  visible = reader_sees(catalog, canon, &ev) &&
            entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
                actor_len, principal, principal_len);' \
  '  visible = reader_sees(catalog, canon, &ev);'

# Tree: a field the principal may not read stays in the tree.
plant tree-field-filter-skipped $ACCESS testSweep 'Sweep.TreeCarriesNoCanary' \
  '      if (field_len > 0 && !path_shown(f, path, pn)) {
        if (path_locked(f, path, pn)) {
          /* Refused and locked (story A6): marked, never set. */' \
  '      if (0 && field_len > 0 && !path_shown(f, path, pn)) {
        if (path_locked(f, path, pn)) {
          /* Refused and locked (story A6): marked, never set. */'

# Revision view: the field filter of a live read is not applied.
plant revision-field-filter-skipped $ACCESS testSweep \
  'Sweep.RevisionCarriesNoCanary' \
  '  /* The same field-by-field filter as a live read. */
  if (field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {' \
  '  /* The same field-by-field filter as a live read. */
  if (0 && field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {'

# List: the rows the principal may not see are listed (the compiled filter and
# the entity-by-entity one both).
plant list-skips-visibility $ACCESS testSweep 'Sweep.ListCarriesNoCanary' \
  '    if (!reader_sees(catalog, ids[i], ev) ||
        !entity_visible(ev, grants, ngrants, local->type_name,
            local->type_name_len, actor, actor_len, principal, principal_len)) {' \
  '    if (!reader_sees(catalog, ids[i], ev) ||
        (0 && !entity_visible(ev, grants, ngrants, local->type_name,
            local->type_name_len, actor, actor_len, principal, principal_len))) {' \
  '  parts[nparts++] = access_node(ev, plan, grants, ngrants, q->type_name,
      q->type_name_len);' \
  '  parts[nparts++] = gdefcore_plan_constant(plan, 1);
  (void)grants;
  (void)ngrants;'

# List: a filter on a field the principal may not name is taken.
plant list-filters-a-field-it-may-not-name $ACCESS testSweep \
  'Sweep.ListCarriesNoCanary' \
  '  if (local.filter_field != NULL && local.filter_field_len > 0) {
    if (!type_has_field(' \
  '  if (0 && local.filter_field != NULL && local.filter_field_len > 0) {
    if (!type_has_field(' \
  '    if ((local->filter_field != NULL && local->filter_field_len > 0 &&' \
  '    if ((0 && local->filter_field != NULL && local->filter_field_len > 0 &&'

# Count: counts what is there, not what the principal may see.
plant count-skips-visibility $ACCESS testSweep 'Sweep.CountCarriesNoCanary' \
  '  parts[nparts++] = access_node(ev, plan, grants, ngrants, q->type_name,
      q->type_name_len);' \
  '  parts[nparts++] = spec->count_only
                        ? gdefcore_plan_constant(plan, 1)
                        : access_node(ev, plan, grants, ngrants, q->type_name,
                              q->type_name_len);'

# The editor's form: a field the principal may not read is filled in.
plant form-field-filter-skipped $FORM testSweep 'Sweep.FormCarriesNoCanary' \
  '    if (rc != GDEFCORE_OK || !readable) {
      continue;
    }
    if (field->personal) {' \
  '    if (rc != GDEFCORE_OK) {
      continue;
    }
    if (field->personal) {'

# The recent-posts summary is built from a body read without the access filter.
plant summary-built-from-an-unfiltered-body $RENDER testSweep \
  'Sweep.RecentPostsSummaryCarriesNoCanary' \
  '  rc = gdefcore_access_read(catalog, request, id, id_len, "en", 2, field,
      strlen(field), &texts, &lens, &count, NULL);
  if (rc == GDEFCORE_ERR_INVALID) {
    *missing = 1;' \
  '  (void)request;
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      id_len, "en", 2, field, strlen(field), &texts, &lens, &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    *missing = 1;'

# An entity rendered through a template is read without the access filter.
plant render-reads-an-unfiltered-entity $RENDER testSweep \
  'Sweep.RenderCarriesNoCanary' \
  '  rc = gdefcore_access_tree(catalog, request, id, id_len, lang, lang_len,
      &tree);
  if (rc == GDEFCORE_OK) {
    rc = describe_entity(tree, &value);' \
  '  (void)request;
  rc = gdefcore_entity_tree(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, id_len,
      lang, lang_len, &tree);
  if (rc == GDEFCORE_OK) {
    rc = describe_entity(tree, &value);'

# The render key does not tell two principals of one permission set apart when
# a callback decides: a fragment kept for the one who paid is served to the
# one who did not.
plant fragment-key-ignores-the-principal $ACCESS testSweep \
  'Sweep.FragmentCacheCarriesNoCanary' \
  '  if ((read_principal || gdefcore_request_principal_dependent(request)) &&
      principal != NULL && principal_len > 0) {' \
  '  if (0 && (read_principal || gdefcore_request_principal_dependent(request)) &&
      principal != NULL && principal_len > 0) {'

# The render key leaves out the permissions and the config epoch: a fragment
# kept while a grant held is served after the grant is revoked.
plant cached-derivation-outlives-a-revoked-grant $ACCESS testSweep \
  'Sweep.FragmentCacheCarriesNoCanary' \
  '    ADD_KEY("\nepoch:", 7);
    ADD_KEY(epoch_text, (size_t)en);' \
  '    (void)epoch_text;
    (void)en;' \
  '    ADD_KEY(perm_hex, 64);' \
  '    ADD_KEY("-", 1);'

# The render key leaves out the time: a grant that expires (a condition on
# `now`) is served from a fragment kept before it did.
plant render-key-ignores-the-time $ACCESS testSweep \
  'Sweep.FragmentCacheCarriesNoCanary' \
  '    if (time_dependent) {
      /* The answer changes with the clock, not with anything written. */' \
  '    if (0 && time_dependent) {
      /* The answer changes with the clock, not with anything written. */'

# A person's export is handed over to whoever the route lets in, whatever the
# route's condition says.
plant export-route-ignores-the-condition $ACCESS testSweep \
  'SweepOps.SubjectExportCarriesNoCanaryToTheUnauthorized' \
  '  gdefcore_text_free(catalog, type);
  return rc == GDEFCORE_OK && allowed;' \
  '  gdefcore_text_free(catalog, type);
  return rc == GDEFCORE_OK;'

# A route that names a permission and no entity lets in whoever asks.
plant snapshot-route-ignores-the-permission $ACCESS testSweep \
  'SweepOps.SnapshotCarriesNoCanaryToTheUnauthorized' \
  '  held = permits_in(&ev, grants, ngrants, permission, permission_len, NULL, 0);' \
  '  held = 1 || permits_in(&ev, grants, ngrants, permission, permission_len, NULL, 0);'

# A personal value is stored as it was written: the current tables, the
# blind index's neighbours and every snapshot of them hold the plaintext.
plant personal-value-stored-as-plaintext $SUBJECT testSweep \
  'SweepOps.StoredProjectionHoldsNoPersonalPlaintext SweepOps.SnapshotCarriesNoCanaryToTheUnauthorized' \
  '    if (plain_len > 0) {
      memcpy(packed + kNonce, ct, plain_len);
    }' \
  '    if (plain_len > 0) {
      memcpy(packed + kNonce, plain, plain_len);
    }'

# A search is added to a public header and the sweep does not list it.
plant search-added-and-not-listed $HEADER testSweep \
  'SweepList.EveryDerivedOutputIsListed' \
  'GDEFCORE_API GDEFCORE_Result gdefcore_access_decide(GDEFCORE_Catalog * catalog,' \
  'GDEFCORE_API GDEFCORE_Result gdefcore_access_search(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * text, size_t text_len);

GDEFCORE_API GDEFCORE_Result gdefcore_access_decide(GDEFCORE_Catalog * catalog,'

plant_finish
