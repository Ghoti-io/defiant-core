#!/bin/sh
#
# The manifest-table gate (site admin epic, story 5): a module declares routes,
# menu links, settings and template variables; enabling registers them, the
# host enumerates them in one order, and the result does not depend on how the
# site was built up.
#
# Runs the Manifest tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   Manifest.ModuleOrder, Manifest.OrderIndependence
#                                   modules are in AD-10 order, not installed order
#   Manifest.ModuleOrderFollowsRelationships
#                                   a subscription's before and after count
#   Manifest.Clash                  a name declared twice is refused
#   Manifest.OffAndOn, Manifest.Declare
#                                   a disable removes what the enable made, and a
#                                   module that is not enabled declares nothing
#   Manifest.Prefix                 a name outside the module's prefix is refused
#                                   (route, link, setting, variable)
#   Manifest.BothLoaders            the guest loader and the native one give the
#                                   same tables
#   Manifest.VetIsTheAuthority      apply checks the whole site, not only enable
#   Manifest.OrphanTab, Manifest.BadLink
#                                   a tab needs its parent, a link its route
#   Manifest.AddRoutesPutsTabsAfterTheirParents
#   Manifest.ServiceResolution      a handler or provider is the module's own
#                                   service, at the version the table has
#   Manifest.APrefixWithoutItsSchemaVersionIsRefused  a manifest is read only as far as it says
#   Manifest.TemplateVariable       a declared variable is in story 2's contract
#   Manifest.TemplateVariableKinds  a variable for no kind is refused
#   Manifest.Hostile, Manifest.Limits
#                                   a hostile field is refused, a limit holds
#
# Every test has a control (the accepted shape of the same input, or the same
# site with the module removed), so a plant turning one red is a test seeing the
# defect, not a build failure.
#
# Usage: check-manifest.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testModule 'Manifest.*'

# (1) Enumeration ordered by registration order: among the modules nothing
# constrains, the first installed goes first, not the lowest name.
plant order-by-install src/module/module.c testModule \
  'Manifest.ModuleOrder Manifest.OrderIndependence' \
  '      if (ready && (pick < 0 || mod_name_less(live[i], live[pick]))) {' \
  '      if (ready && (pick < 0 || 0)) {'

# (1b) A subscription's before, or its after, no longer orders the modules.
plant order-ignores-before src/module/module.c testModule \
  'Manifest.ModuleOrderBefore' \
  '          before[i][j] = 1;' \
  '          (void)0;'

plant order-ignores-after src/module/module.c testModule \
  'Manifest.ModuleOrderFollowsRelationships' \
  '          before[j][i] = 1;' \
  '          (void)0;'

# (2) A duplicate registration is accepted.
plant duplicate-accepted src/module/decl.c testModule 'Manifest.Clash' \
  '    if (span_is(sorted[i].kind, sorted[i].kind_n, sorted[i - 1].kind,' \
  '    if (0 && span_is(sorted[i].kind, sorted[i].kind_n, sorted[i - 1].kind,'

# (3) Disable leaves the declarations: a disable no longer takes the module
# out of the set the site is left with.
plant disable-leaves-module src/module/module.c testModule 'Manifest.OffAndOn' \
  '      name_remove(names, out_n, name, name_len);' \
  '      (void)0;'

# (3b) ... or the enumeration lists every installed module, enabled or not.
plant enumerates-installed src/module/module.c testModule \
  'Manifest.Declare Manifest.OffAndOn' \
  '        !name_has(names, nnames, mod->name, mod->name_len)) {
      continue;
    }
    live[n++] = mod;' \
  '        (!name_has(names, nnames, mod->name, mod->name_len) && 0)) {
      continue;
    }
    live[n++] = mod;'

# (4) An unprefixed name is accepted: once for routes, links and settings,
# once for variables, which have a rule of their own.
plant unprefixed-accepted src/module/decl.c testModule 'Manifest.Prefix' \
  "  if (n <= mlen + 1 || memcmp(name, module, mlen) != 0 || name[mlen] != '.') {
    return 1;
  }" \
  "  if (0 && (n <= mlen + 1 || memcmp(name, module, mlen) != 0 ||
            name[mlen] != '.')) {
    return 1;
  }"

plant unprefixed-variable-accepted src/module/decl.c testModule 'Manifest.Prefix' \
  "  if (n <= mlen + 1 || name[mlen] != '.' || !path_ok(name, n)) {
    return 0;
  }" \
  '  if (n <= mlen + 1 || !path_ok(name, n)) {
    return 0;
  }' \
  "    if (name[i] != want) {
      return 0;
    }" \
  '    if (0 && name[i] != want) {
      return 0;
    }' \
  '  return memchr(name + mlen + 1, '"'"'.'"'"', n - mlen - 1) == NULL;' \
  '  return 1;'

# (5) The guest loader drops a table.
plant guest-drops-links src/module/module.c testModule 'Manifest.BothLoaders' \
  '  {
    Mod * existing = find_mod(host, mod.name, mod.name_len);' \
  '  if (mod.decl != NULL) {
    mod.decl->nlinks = 0;
  }
  {
    Mod * existing = find_mod(host, mod.name, mod.name_len);'

plant guest-drops-variables src/module/module.c testModule 'Manifest.BothLoaders' \
  '  {
    Mod * existing = find_mod(host, mod.name, mod.name_len);' \
  '  if (mod.decl != NULL) {
    mod.decl->nvars = 0;
  }
  {
    Mod * existing = find_mod(host, mod.name, mod.name_len);'

# Apply no longer checks the site; only enable does.
plant vet-skips-declarations src/module/module.c testModule \
  'Manifest.VetIsTheAuthority Manifest.OrphanTab Manifest.BadLink' \
  '  rc = validate_declared(host, names, nnames, 0);
  if (rc != GDEFCORE_OK) {
    size_t text_len = 0;' \
  '  rc = GDEFCORE_OK;
  if (rc != GDEFCORE_OK) {
    size_t text_len = 0;'

# A tab with no parent route is accepted by the reference check (the route
# table's own refusal then says something else).
plant orphan-tab-accepted src/module/decl.c testModule 'Manifest.OrphanTab' \
  '      if (!local && s->kind == GDEFCORE_ROUTE_TAB && s->parent_len > 0 &&' \
  '      if (!local && 0 && s->kind == GDEFCORE_ROUTE_TAB && s->parent_len > 0 &&'

# A link to a route nobody declares is accepted.
plant bad-link-accepted src/module/decl.c testModule 'Manifest.BadLink' \
  '      if (find_entry(routes, nroutes, l->route, l->route_len) == NULL) {' \
  '      if (0 && find_entry(routes, nroutes, l->route, l->route_len) == NULL) {'

# A tab is added in name order, before its parent.
plant tabs-before-parents src/module/decl.c testModule \
  'Manifest.AddRoutesPutsTabsAfterTheirParents' \
  '      if (wait) {
        continue;
      }' \
  '      if (0 && wait) {
        continue;
      }'

# A handler service at another version is taken for the handler.
plant service-version-ignored src/module/decl.c testModule \
  'Manifest.ServiceResolution' \
  '      if (svcs[i].version != version) {' \
  '      if (0 && svcs[i].version != version) {'

# The manifest is read whatever size the module says it is.
plant manifest-read-at-any-size src/module/module.c testModule \
  'Manifest.AManifestOfAnotherSizeIsRefused' \
  '  if (!TAKE_EXACT(host, GDEFCORE_Module_Manifest, man, src)) {
    return GDEFCORE_ERR_INVALID;
  }' \
  '  memcpy(&man, src, sizeof man);'

# A declared variable is not in the contract's contributions.
plant variables-not-contributed src/module/module.c testModule \
  'Manifest.TemplateVariable' \
  '    for (j = 0; j < d->nvars; j++) {
      const GDEFCORE_Module_Contributed * v = &d->vars[j].pub;' \
  '    for (j = 0; j < d->nvars && 0; j++) {
      const GDEFCORE_Module_Contributed * v = &d->vars[j].pub;'

# A variable for a kind that does not exist is accepted.
plant unknown-kind-accepted src/template/template.c testModule \
  'Manifest.TemplateVariableKinds Manifest.Hostile' \
  '      rc = find_named(catalog, changeset, GDEFCORE_TEMPLATE_KIND_TYPE, v->kind,
          v->kind_len, id);' \
  '      rc = GDEFCORE_OK;
      (void)id;'

# A name past the length limit is accepted.
plant huge-name-accepted src/module/decl.c testModule \
  'Manifest.Hostile Manifest.Limits' \
  '  if (n > GDEFCORE_MODULE_DECL_NAME_MAX) {
    return 2;
  }' \
  '  if (0) {
    return 2;
  }'

# A table is not sorted by machine name.
plant tables-unsorted src/module/decl.c testModule 'Manifest.Declare' \
  '  if (b->rc == GDEFCORE_OK && d->nroutes > 1) {' \
  '  if (0 && b->rc == GDEFCORE_OK && d->nroutes > 1) {'

plant_finish
