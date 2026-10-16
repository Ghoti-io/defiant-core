#!/bin/sh
#
# The template-editing gate (site-admin story 3): the permission each kind
# declares is checked when a template is written, the decision hook can deny
# the write, a deny wins, and the render of an edited body is never offered to
# a shared cache.
#
# Runs the TPerm tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   permission-not-checked        TPerm.WriteNeedsThePermission, TPerm.NewTemplateNeedsThePermissionOfItsKind
#   old-kind-not-checked          TPerm.MovingNeedsBothKinds
#   authorize-not-called          TPerm.WriteNeedsThePermission, TPerm.RevertIsChecked
#   hook-skipped                  TPerm.ModuleDeniesPageTemplatesUnlessClassificationMatches
#   deny-ignored                  TPerm.ModuleDeniesPageTemplatesUnlessClassificationMatches, TPerm.AnyDenyWins...
#   deny-lost-at-the-bus          TPerm.ModuleDeniesPageTemplatesUnlessClassificationMatches
#   failing-subscriber-allowed    TPerm.FailingSubscriberFailsTheRequest
#   permission-not-declared       TPerm.KindDeclaresItsPermission
#   permits-ignores-the-name      TPerm.GrantFlow
#   sample-render-unchecked       TPerm.SampleRenderIsGatedAndNeverShared
#   preview-offered-to-cache      TPerm.SampleRenderIsGatedAndNeverShared
#
# Every test has a control (the principal who holds the permission DOES write,
# the module that allows DOES allow, the live overlay DOES move the counter),
# so a plant turning one red is a test seeing the defect, not a build failure.
#
# Usage: check-tpermission.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testTpermission 'TPerm.*'

# Plant 1: a template write no longer asks whether the principal holds the
# permission of the template's kind.
plant permission-not-checked src/template/template.c testTpermission \
  'TPerm.WriteNeedsThePermission TPerm.NewTemplateNeedsThePermissionOfItsKind' \
  '    allowed = kind_len > 0 &&
              gdefcore_template_may_edit(catalog, request, kind, kind_len);' \
  '    allowed = kind_len > 0;'

# Plant 2: moving a template needs the new kind's permission and not the old.
plant old-kind-not-checked src/template/template.c testTpermission \
  'TPerm.MovingNeedsBothKinds' \
  '      allowed = gdefcore_template_may_edit(catalog, request, old_kind, old_len);' \
  '      allowed = 1;'

# Plant 3: apply does not call the check.
plant authorize-not-called src/entity/entity.c testTpermission \
  'TPerm.WriteNeedsThePermission TPerm.RevertIsChecked' \
  '  if (changeset->request != NULL) {
    rc = gdefcore_template_authorize(changeset, changeset->request);' \
  '  if (0 && changeset->request != NULL) {
    rc = gdefcore_template_authorize(changeset, changeset->request);'

# Plant 4: the decision hook is never fired.
plant hook-skipped src/template/template.c testTpermission \
  'TPerm.ModuleDeniesPageTemplatesUnlessClassificationMatches TPerm.AnyDenyWinsAndNoOpinionStands' \
  '    if (allowed && host != NULL) {' \
  '    if (allowed && host != NULL && 0) {'

# Plant 5: it is fired and a deny is read and ignored.
plant deny-ignored src/template/template.c testTpermission \
  'TPerm.ModuleDeniesPageTemplatesUnlessClassificationMatches TPerm.AnyDenyWinsAndNoOpinionStands' \
  '      if (rc == GDEFCORE_OK && vetoed) {
        allowed = 0;
      }' \
  '      (void)vetoed;'

# Plant 6: the bus loses the deny on its way back.
plant deny-lost-at-the-bus src/module/module.c testTpermission \
  'TPerm.ModuleDeniesPageTemplatesUnlessClassificationMatches' \
  '    *out_deny_vote = any_deny;' \
  '    *out_deny_vote = 0;'

# Plant 7: a subscriber that fails counts as having no objection.
plant failing-subscriber-allowed src/template/template.c testTpermission \
  'TPerm.FailingSubscriberFailsTheRequest' \
  '      /* A subscriber that fails fails the request (AD-10). */
      return refuse_edit(changeset, rc);' \
  '      /* A subscriber that fails fails the request (AD-10). */
      rc = GDEFCORE_OK;'

# Plant 8: a kind defined by changeset gets no permission.
plant permission-not-declared src/entity/entity.c testTpermission \
  'TPerm.KindDeclaresItsPermission' \
  '      GDEFCORE_Result declared = gdefcore_template_declare_touched(changeset);' \
  '      GDEFCORE_Result declared = GDEFCORE_OK;'

# Plant 9: any grant at all counts as holding the permission asked about.
plant permits-ignores-the-name src/access/access.c testTpermission \
  'TPerm.GrantFlow' \
  '    if (!same(grants[i].action, grants[i].action_len, permission,
            permission_len)) {
      continue;
    }' \
  '    if (0 && !same(grants[i].action, grants[i].action_len, permission,
            permission_len)) {
      continue;
    }'

# Plant 10: the sample render does not ask whether the principal may edit.
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

# Plant 11: a preview is offered to the shared cache like a live render.
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
