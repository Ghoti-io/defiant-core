#!/bin/sh
#
# The template-editing gate (access-conditions story A8, which moved the
# site-admin story 3 gate to the additive model): who may edit a template is
# one permission, `core.template.edit`, granted with a condition on the
# template's kind by roles and on its classification by modules, and decided
# by the one can(). Nothing denies. The render of an edited body is never
# offered to a shared cache.
#
# Runs the TPerm tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   permission-not-checked        TPerm.WriteNeedsThePermission, TPerm.NewTemplateNeedsThePermissionOfItsKind
#   new-kind-not-checked          TPerm.MovingNeedsBothKinds, TPerm.NewTemplateNeedsThePermissionOfItsKind
#   old-kind-not-checked          TPerm.MovingNeedsBothKinds
#   kind-grant-lets-other-kinds-through  TPerm.KindGrantEditsOnlyThatKind
#   classification-grant-outlives-its-module  TPerm.AGrantWithNoRelationGoesWithItsModuleToo
#   module-hook-denies-again      TPerm.NoModuleHookCanRefuseAWrite
#   write-reads-another-template-than-the-editor  TPerm.TheEditorsAnswersAreTheWritesForEveryPrincipal
#   failing-source-fails-the-write  TPerm.AFailingConditionGrantsNothingAndTakesNothingAway
#   authorize-not-called          TPerm.WriteNeedsThePermission, TPerm.RevertIsChecked
#   permission-not-declared       TPerm.EditPermissionIsDeclaredOnce
#   permits-ignores-the-name      TPerm.KindGrantEditsOnlyThatKind
#   sample-render-unchecked       TPerm.SampleRenderIsGatedAndNeverShared
#   preview-offered-to-cache      TPerm.SampleRenderIsGatedAndNeverShared
#
# What the retired plants of story 3 are replaced by is in the commit that
# retired them: hook-skipped, deny-ignored, deny-lost-at-the-bus and
# failing-subscriber-allowed went with the veto (module-hook-denies-again and
# TPerm.AFailingCallbackGrantsNothingAndTakesNothingAway stand where they did).
#
# Every test has a control (the principal who holds the permission DOES write,
# the module that grants DOES grant, the live overlay DOES move the counter),
# so a plant turning one red is a test seeing the defect, not a build failure.
#
# Usage: check-tpermission.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testTpermission 'TPerm.*'


SRC=src/template/template.c

# Plant 1: a template write no longer asks whether the principal may edit it.
plant permission-not-checked $SRC testTpermission \
  'TPerm.WriteNeedsThePermission TPerm.NewTemplateNeedsThePermissionOfItsKind' \
  '    rc = decide_edit(catalog, request, canon, &shape, &allowed);
    shape_free(&shape);' \
  '    allowed = shape.len[0] > 0;
    rc = GDEFCORE_OK;
    shape_free(&shape);'

# Plant 2: the kind a template becomes is not asked about: only the kind it
# was, which a new template does not have.
plant new-kind-not-checked $SRC testTpermission \
  'TPerm.MovingNeedsBothKinds TPerm.NewTemplateNeedsThePermissionOfItsKind' \
  '  rc = gdefcore_access_can_with(catalog, request, GDEFCORE_TEMPLATE_EDIT,
      sizeof GDEFCORE_TEMPLATE_EDIT - 1, GDEFCORE_TEMPLATE_TYPE,
      sizeof GDEFCORE_TEMPLATE_TYPE - 1, canon, values, kShapeFields, &ok);' \
  '  ok = 1;
  rc = GDEFCORE_OK;
  (void)values;'

# Plant 3: the kind a template was is not asked about: only the kind it
# becomes.
plant old-kind-not-checked $SRC testTpermission \
  'TPerm.MovingNeedsBothKinds' \
  '  if (revisions > 0) {
    rc = can_as_stored(catalog, request, canon, &ok);' \
  '  if (0 && revisions > 0) {
    rc = can_as_stored(catalog, request, canon, &ok);'

# Plant 4: a grant for one kind lets the list of kinds name another.
plant kind-grant-lets-other-kinds-through $SRC testTpermission \
  'TPerm.KindGrantEditsOnlyThatKind' \
  '    if (span_eq(stored, stored_len, kind, kind_len) &&
        can_as_stored(catalog, request, ids[i], &ok) == GDEFCORE_OK) {' \
  '    if (can_as_stored(catalog, request, ids[i], &ok) == GDEFCORE_OK) {'

# Plant 5: the grants of a module are read from every module that is
# installed, so a classification grant outlives the module that supplied it.
plant classification-grant-outlives-its-module src/module/module.c testTpermission \
  'TPerm.AGrantWithNoRelationGoesWithItsModuleToo' \
  '  rc = gdefcore_decl_grants(host->alloc, refs, n, out_items, out_count);' \
  '  {
    Name all[kModMax];
    size_t k;
    size_t na = 0;
    for (k = 0; k < host->nmods && na < kModMax; k++) {
      if (host->mods[k].used) {
        (void)name_add(all, &na, kModMax, host->mods[k].name,
            host->mods[k].name_len);
      }
    }
    gcu_allocator_free(host->alloc, refs);
    refs = NULL;
    n = 0;
    rc = decl_refs(host, all, na, &refs, &n);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
  }
  rc = gdefcore_decl_grants(host->alloc, refs, n, out_items, out_count);'

# Plant 6: the write asks a decision hook again, and a deny refuses it (the
# veto). The hook is named by two literals so that this text, like the tree,
# does not spell the old name out.
plant module-hook-denies-again $SRC testTpermission \
  'TPerm.NoModuleHookCanRefuseAWrite' \
  '    rc = decide_edit(catalog, request, canon, &shape, &allowed);
    shape_free(&shape);' \
  '    rc = decide_edit(catalog, request, canon, &shape, &allowed);
    if (rc == GDEFCORE_OK && allowed) {
      int vote = GDEFCORE_DECISION_NONE;
      GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
      if (host != NULL &&
          gdefcore_hook_fire(host, request, catalog, "template" "-write", 14,
              GDEFCORE_HOOK_DECISION, NULL, NULL, &vote) == GDEFCORE_OK &&
          vote == GDEFCORE_DECISION_DENY) {
        allowed = 0;
      }
    }
    shape_free(&shape);'

# Plant 7: the write reads the template as it is stored, where the editor
# asks about the template as the write would leave it.
plant write-reads-another-template-than-the-editor $SRC testTpermission \
  'TPerm.TheEditorsAnswersAreTheWritesForEveryPrincipal' \
  '    through = op == GDEFCORE_TOUCH_CLEAR || op == GDEFCORE_TOUCH_PUBLISH
                  ? NULL
                  : changeset;' \
  '    through = NULL;
    (void)op;'

# Plant 8: a grant whose condition cannot be decided fails the write, where a
# source that fails grants nothing and the write is refused like any other.
plant failing-source-fails-the-write $SRC testTpermission \
  'TPerm.AFailingConditionGrantsNothingAndTakesNothingAway' \
  '  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_OK;
  }
  if (!ok) {
    return GDEFCORE_OK;
  }' \
  '  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!ok) {
    return GDEFCORE_OK;
  }'

# Plant 9: apply does not call the check.
plant authorize-not-called src/entity/entity.c testTpermission \
  'TPerm.WriteNeedsThePermission TPerm.RevertIsChecked' \
  '  if (changeset->request != NULL) {
    rc = gdefcore_template_authorize(changeset, changeset->request);' \
  '  if (0 && changeset->request != NULL) {
    rc = gdefcore_template_authorize(changeset, changeset->request);'

# Plant 10: the kit does not declare the permission.
plant permission-not-declared src/render/render.c testTpermission \
  'TPerm.EditPermissionIsDeclaredOnce' \
  '    rc = gdefcore_template_edit_declare(catalog);' \
  '    rc = GDEFCORE_OK;'

# Plant 11: any grant at all counts as holding the permission asked about.
plant permits-ignores-the-name src/access/access.c testTpermission \
  'TPerm.KindGrantEditsOnlyThatKind' \
  '    if (!same(grants[i].action, grants[i].action_len, permission,
            permission_len)) {
      continue;
    }' \
  '    if (0 && !same(grants[i].action, grants[i].action_len, permission,
            permission_len)) {
      continue;
    }'

# Plant 12: the sample render does not ask whether the principal may edit.
plant sample-render-unchecked src/render/render.c testTpermission \
  'TPerm.SampleRenderIsGatedAndNeverShared' \
  '  if (!gdefcore_template_may_edit(catalog, request, kind, kind_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_template_contract_open(catalog, NULL, kind, kind_len, &contract,
      NULL);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }' \
  '  rc = gdefcore_template_contract_open(catalog, NULL, kind, kind_len, &contract,
      NULL);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }'

# Plant 13: a preview is offered to the shared cache like a live render.
plant preview-offered-to-cache src/render/render.c testTpermission \
  'TPerm.SampleRenderIsGatedAndNeverShared' \
  '  if (!gdefcore_access_shared_cache(overlay, overlay_len)) {
    return 0;
  }
  atomic_fetch_add_explicit' \
  '  if (!gdefcore_access_shared_cache(overlay, overlay_len) && 0) {
    return 0;
  }
  atomic_fetch_add_explicit'

plant_finish
