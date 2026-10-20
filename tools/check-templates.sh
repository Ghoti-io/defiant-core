#!/bin/sh
#
# The template-contract gate (site-admin story 2): a template may use exactly
# what its kind's effective contract names, a contribution is lazy, scoped to
# an enabled module, and recorded in the render key, and a template that
# does not validate never gets stored.
#
# Runs the Templates tests on the real tree, then plants each defect in a COPY
# of the source by an exact text edit and requires the named test to fail:
#
#   validation-skipped-at-apply   Templates.ApplyRefusesAndNames, Templates.ModuleVariable
#   library-hands-outside-names   Templates.NarrowContractIsTheLibrary
#   contribution-evaluated-eagerly Templates.LazyProvider
#   contribution-outlives-disable Templates.ModuleVariable
#   principal-not-recorded        Templates.PrincipalKey
#   key-ignores-observed-principal Templates.PrincipalKey
#   unsafe-marker-check-removed   Templates.Unsafe
#   revert-not-vetted             Templates.RevertIsVetted (it was
#                                 activate-not-vetted, on the retired
#                                 activate: access SPEC decision 13)
#
# and six more that stand behind a matrix row each: the engine's own math is
# no longer shadowed, the plumbing template is reachable from a template, the
# error line is off by one, a map literal's values are not walked, the
# changeset parser reads a field called kind as a type's kind, and a type name
# may not hold a hyphen.
#
# Every test has a control (the accepted shape of the same input, or the same
# page with the value present), so a plant turning one red is a test seeing
# the defect, not a build failure.
#
# Usage: check-templates.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testTemplates 'Templates.*'
plant_control testEntity 'Entity.FieldNamedKind:Entity.HyphenInTypeName'

# Plant 1: apply no longer validates the templates a changeset writes.
plant validation-skipped-at-apply src/entity/entity.c testTemplates \
  'Templates.ApplyRefusesAndNames Templates.ModuleVariable' \
  '  rc = gdefcore_template_vet(changeset);' \
  '  rc = GDEFCORE_OK;'

# Plant 2: the library is handed every value the host bound, contract or not.
plant library-hands-outside-names src/render/render.c testTemplates \
  'Templates.NarrowContractIsTheLibrary' \
  '    if (gdefcore_template_contract_var(c, job->binds[i].name,
            strlen(job->binds[i].name), &v) != GDEFCORE_OK ||
        v.contributed != NULL) {
      continue;
    }' \
  '    (void)v;'

# Plant 3: a contributed variable is computed when the library is built.
plant contribution-evaluated-eagerly src/render/render.c testTemplates \
  'Templates.LazyProvider' \
  '      if (gltang_library_add_factory(groups[g].lib, local, contrib_factory,
              &adapters[used]) != GLTANG_OK) {' \
  '      GLTANG_HostValue eager;
      (void)contrib_factory(&adapters[used], &eager);
      if (gltang_library_add_factory(groups[g].lib, local, contrib_factory,
              &adapters[used]) != GLTANG_OK) {'

# Plant 4: a module's contributions stay in force after the module is disabled.
plant contribution-outlives-disable src/module/module.c testTemplates \
  'Templates.ModuleVariable' \
  '  return mod != NULL && name_has(names, n, module, len) && !mod->quarantined &&' \
  '  return mod != NULL && (name_has(names, n, module, len) || 1) && !mod->quarantined &&'

# Plant 5: reading a variable that is not principal_free marks nothing.
plant principal-not-recorded src/render/render.c testTemplates \
  'Templates.PrincipalKey' \
  '    gdefcore_request_mark_principal_dependent(a->request);' \
  '    (void)a;'

# Plant 5b: the mark is made, and the key derivation does not read it.
plant key-ignores-observed-principal src/access/access.c testTemplates \
  'Templates.PrincipalKey' \
  '  if ((read_principal || gdefcore_request_principal_dependent(request)) &&' \
  '  if ((read_principal) &&'

# Plant 6: `.raw` needs no marker.
plant unsafe-marker-check-removed src/template/template.c testTemplates \
  'Templates.Unsafe' \
  '  if (p->rhs != NULL && strcmp(p->rhs, "raw") == 0) {' \
  '  if (p->rhs != NULL && strcmp(p->rhs, "raw") == 0 && 0) {'

# Plant 7: the engine's own math and random are reachable from a template.
plant builtins-not-shadowed src/render/render.c testTemplates \
  'Templates.PlumbingAndBuiltinsAreNotReachable' \
  '    if (gltang_library_add_native(lib, "url", native_url, NULL) != GLTANG_OK ||
        gltang_library_add_null(lib, "math") != GLTANG_OK ||
        gltang_library_add_null(lib, "random") != GLTANG_OK) {' \
  '    if (gltang_library_add_native(lib, "url", native_url, NULL) != GLTANG_OK) {'

# Plant 8: the template that runs the body is in the library the body reads.
plant plumbing-in-the-library src/render/render.c testTemplates \
  'Templates.PlumbingAndBuiltinsAreNotReachable' \
  '  if (gltang_library_add_template(plumbing, "pane", body, job->scope_fuel,
          GLTANG_SCOPE_SEGMENTS) != GLTANG_OK ||
      gltang_program_set_libraries(wrap, plumbing) != GLTANG_OK) {' \
  '  if (gltang_library_add_template(lib, "pane", body, job->scope_fuel,
          GLTANG_SCOPE_SEGMENTS) != GLTANG_OK) {'

# Plant 9: an error is reported on the line before the one that holds it.
plant line-off-by-one src/template/template.c testTemplates \
  'Templates.Typo' \
  '  int line = node == NULL ? 0 : node->location.first_line + 1;' \
  '  int line = node == NULL ? 0 : node->location.first_line;'

# Plant 10: a map literal's values are not read.
plant map-values-unread src/template/template.c testTemplates \
  'Templates.AstWalkSeesInsideLiterals' \
  '      fn(ctx, sc, pair->value);' \
  '      (void)pair;'

# Plant 11: a field called kind is read as the type's own kind file again.
plant field-named-kind-misread src/entity/entity.c testEntity \
  'Entity.FieldNamedKind' \
  '        memcmp(files[i].path + files[i].path_len - 5, "/kind", 5) == 0 &&
        memchr(files[i].path + 5, '"'"'/'"'"', files[i].path_len - 10) == NULL) {' \
  '        memcmp(files[i].path + files[i].path_len - 5, "/kind", 5) == 0) {'

# Plant 12: a type name may not hold a hyphen, so core.template-kind cannot be
# defined.
plant hyphen-refused-in-type-name src/entity/entity.c testEntity \
  'Entity.HyphenInTypeName' \
  "    if (c == '-' && dot != n && i > dot + 1 && i + 1 < n) {
      continue;
    }" \
  '    (void)dot;'

# Plant 13: a changeset that writes a template revision (a revert is one) is
# not vetted, so a revision that no longer builds becomes the template.
plant revert-not-vetted src/template/template.c testTemplates \
  'Templates.RevertIsVetted' \
  '  if (!touches_type(changeset, GDEFCORE_TEMPLATE_TYPE,
          GDEFCORE_TOUCH_SAVE | GDEFCORE_TOUCH_DRAFT | GDEFCORE_TOUCH_PUBLISH) &&' \
  '  if (!touches_type(changeset, GDEFCORE_TEMPLATE_TYPE,
          GDEFCORE_TOUCH_DRAFT | GDEFCORE_TOUCH_PUBLISH) &&'

plant_finish
