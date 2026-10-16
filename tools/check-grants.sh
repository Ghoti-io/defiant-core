#!/bin/sh
#
# The grants gate (access-conditions story A4): grants that carry conditions,
# the grants a module declares, the matrix that lists them and the rating of
# how broad each is. Runs the Grants tests on the real tree, then plants each
# defect in a COPY of the source by an exact text edit and requires the named
# test to fail:
#
#   module-grant-survives-disable   Grants.ModuleGrantDisappears
#   grant-ignores-condition         Grants.ModuleGrantWorks
#   module-grant-ignores-ceiling    Grants.ModuleGrantCeiling
#   ceiling-ignored                 Grants.ModuleGrantCeiling
#   grant-without-confirmation      Grants.ModuleGrantNotSilent
#   foreign-permission-accepted     Grants.ModuleGrantForeignPermission
#   invalid-condition-accepted      Grants.ModuleGrantBadCondition
#   matrix-omits-module-grants      Grants.MatrixRolesAndModules
#   matrix-for-everyone             Grants.MatrixOnlyForAdmin
#   matrix-unsorted                 Grants.MatrixRolesAndModules
#   risk-strong-unconstrained-low   Grants.RiskRatings
#   risk-edit-unconstrained-low     Grants.RiskRatings
#   first-grant-wins                Grants.GrantsAreAUnion
#   foreign-owner-evaluated         Grants.ModuleGrantFailsClosed
#   role-grant-drops-condition      Grants.RoleGrantWithCondition
#   role-grant-widens               Grants.RoleGrantOnlyNarrows
#   role-grant-skips-confirmation   Grants.RoleGrantRefusals
#   matrix-visible-to-everyone      Oracle.MatrixIsForAdministrators (testOracle)
#   module-grant-seen-hidden        Oracle.ModuleGrant (testOracle)
#
# Every test has a control (the same call that must be allowed, enabled or
# read is made beside the one that must be refused), so a plant turning one
# red is a test seeing the defect, not a build failure.
#
# Usage: check-grants.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testGrants 'Grants.*'
plant_control testOracle 'Oracle.*'

ACCESS=src/access/access.c
MODULE=src/module/module.c

# Plant 1: the host reports the grants of every installed module, enabled or
# not, so a disabled module still grants.
plant module-grant-survives-disable $MODULE testGrants 'Grants.ModuleGrantDisappears' \
  '  rc = enumerate_refs(host, tenant, tenant_len, projection, &refs, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_decl_grants(host->alloc, refs, n, out_items, out_count);' \
  '  {
    size_t k;
    refs = (DeclRef *)gcu_allocator_calloc(host->alloc, host->nmods + 1,
        sizeof *refs);
    n = 0;
    for (k = 0; refs != NULL && k < host->nmods; k++) {
      if (host->mods[k].used && host->mods[k].decl != NULL) {
        refs[n++].decl = host->mods[k].decl;
      }
    }
    (void)projection;
    (void)tenant;
    (void)tenant_len;
  }
  rc = gdefcore_decl_grants(host->alloc, refs, n, out_items, out_count);'

# Plant 2: a module grant holds whatever its condition says.
plant grant-ignores-condition $ACCESS testGrants 'Grants.ModuleGrantWorks' \
  '  int failed = 0;
  int r;
  if (slot == NULL || slot->bad || slot->cond == NULL) {' \
  '  int failed = 0;
  int r;
  if (grant->source == kSrcModule) {
    return 1;
  }
  if (slot == NULL || slot->bad || slot->cond == NULL) {'

# Plant 3a: a module grant is not asked of the acting principal's ceiling.
plant module-grant-ignores-ceiling $ACCESS testGrants 'Grants.ModuleGrantCeiling' \
  '  if (ev == NULL || !ev->has_ceiling) {
    return 1;
  }' \
  '  if (ev == NULL || !ev->has_ceiling || grant->source == kSrcModule) {
    return 1;
  }'

# Plant 3b: no grant is.
plant ceiling-ignored $ACCESS testGrants 'Grants.ModuleGrantCeiling' \
  '  if (ev == NULL || !ev->has_ceiling) {
    return 1;
  }' \
  '  if (ev == NULL || !ev->has_ceiling || grant != NULL) {
    return 1;
  }'

# Plant 4: the grant is not in the words the enable is confirmed with.
plant grant-without-confirmation $ACCESS testGrants 'Grants.ModuleGrantNotSilent' \
  '  rc = gdefcore_changeset_add_confirm_line(changeset, line, (size_t)n);
  gcu_allocator_free(alloc_default(), line);
  return rc;' \
  '  rc = GDEFCORE_OK;
  gcu_allocator_free(alloc_default(), line);
  return rc;'

# Plant 5: a module may grant the permission another module declared.
plant foreign-permission-accepted $MODULE testGrants 'Grants.ModuleGrantForeignPermission' \
  '    if (strcmp(t.owner, mod->name) != 0 && strcmp(t.owner, "core") != 0) {' \
  '    if (0 && strcmp(t.owner, mod->name) != 0 && strcmp(t.owner, "core") != 0) {'

# Plant 6: the condition is neither parsed nor checked against the type when
# the module is enabled.
plant invalid-condition-accepted $MODULE testGrants 'Grants.ModuleGrantBadCondition' \
  '    rc = gdefcore_condition_parse(g->condition, g->condition_len, &cond, &err);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_condition_validate(catalog, cond, g->type_name,
          g->type_name_len, &err);
    }' \
  '    rc = GDEFCORE_OK;'

# Plant 7: the matrix lists role grants and leaves out the modules'.
plant matrix-omits-module-grants $ACCESS testGrants 'Grants.MatrixRolesAndModules' \
  '  for (i = 0; rc == GDEFCORE_OK && i < nitems; i++) {' \
  '  for (i = 0; rc == GDEFCORE_OK && nitems > 1000000 && i < nitems; i++) {'

# Plant 8a: a strong action that nothing narrows is rated low.
plant risk-strong-unconstrained-low $ACCESS testGrants 'Grants.RiskRatings' \
  '  if (cls == kClassStrong && !narrowing) {
    return GDEFCORE_ACCESS_RISK_HIGH;
  }' \
  '  if (cls == kClassStrong && !narrowing) {
    return GDEFCORE_ACCESS_RISK_LOW;
  }'

# Plant 8b: an edit that nothing narrows is rated low.
plant risk-edit-unconstrained-low $ACCESS testGrants 'Grants.RiskRatings' \
  '  return GDEFCORE_ACCESS_RISK_MEDIUM;
}

const char * gdefcore_access_risk_name' \
  '  return GDEFCORE_ACCESS_RISK_LOW;
}

const char * gdefcore_access_risk_name'

# Plant 9: anyone may read the matrix.
plant matrix-visible-to-everyone $ACCESS testGrants 'Grants.MatrixOnlyForAdmin' \
  '  if (!principal_is_admin(catalog, who, who_len) ||
      (acting != NULL && !same(acting, acting_len, who, who_len) &&
          !principal_is_admin(catalog, acting, acting_len))) {
    return GDEFCORE_ERR_INVALID;
  }' \
  '  (void)who;
  (void)who_len;
  (void)acting;
  (void)acting_len;
  if (0) {
    return GDEFCORE_ERR_INVALID;
  }'

# Plant 9b: the same, seen by the oracle sweep.
plant matrix-visible-to-everyone-oracle $ACCESS testOracle 'Oracle.MatrixIsForAdministrators' \
  '  if (!principal_is_admin(catalog, who, who_len) ||
      (acting != NULL && !same(acting, acting_len, who, who_len) &&
          !principal_is_admin(catalog, acting, acting_len))) {
    return GDEFCORE_ERR_INVALID;
  }' \
  '  (void)who;
  (void)who_len;
  (void)acting;
  (void)acting_len;
  if (0) {
    return GDEFCORE_ERR_INVALID;
  }'

# Plant 10: the matrix is in the order things were found.
plant matrix-unsorted $ACCESS testGrants 'Grants.MatrixRolesAndModules' \
  '  if (b.n > 1) {
    qsort(b.rows, b.n, sizeof *b.rows, mx_cmp);
  }' \
  '  if (0 && b.n > 1) {
    qsort(b.rows, b.n, sizeof *b.rows, mx_cmp);
  }'

# Plant 11: the first grant of a type and action decides, so what is granted
# depends on the order grants are met in.
plant first-grant-wins $ACCESS testGrants 'Grants.GrantsAreAUnion Grants.ModuleGrantOrderAndSweep' \
  '    if (same(grants[i].action, grants[i].action_len, "read", 4) &&
        condition_ok(ev, &grants[i], actor, actor_len, principal,
            principal_len)) {
      return 1;
    }
  }
  return 0;
}

static int field_restricted' \
  '    if (same(grants[i].action, grants[i].action_len, "read", 4)) {
      return condition_ok(ev, &grants[i], actor, actor_len, principal,
          principal_len);
    }
  }
  return 0;
}

static int field_restricted'

# Plant 12: a grant is evaluated even when the permission it names belongs to
# another module than the grant's own.
plant foreign-owner-evaluated $ACCESS testGrants 'Grants.ModuleGrantFailsClosed' \
  '    if (!(same(owner, owner_len, item->module, item->module_len) ||
            same(owner, owner_len, "core", 4)) ||' \
  '    if (0 ||'

# Plant 13: a role grant under a condition forgets the condition.
plant role-grant-drops-condition $ACCESS testGrants 'Grants.RoleGrantWithCondition' \
  '  n = snprintf(composite, sizeof composite, "(and %s %.*s)", base_text,
      (int)condition_len, condition_text);' \
  '  n = snprintf(composite, sizeof composite, "%s", base_text);'

# Plant 14: a role grant under a condition replaces the permission'"'"'s own
# instead of joining it.
plant role-grant-widens $ACCESS testGrants 'Grants.RoleGrantOnlyNarrows' \
  '  n = snprintf(composite, sizeof composite, "(and %s %.*s)", base_text,
      (int)condition_len, condition_text);' \
  '  n = snprintf(composite, sizeof composite, "%.*s", (int)condition_len,
      condition_text);'

# Plant 15: a role grant under a condition does not need the confirmation.
plant role-grant-skips-confirmation $ACCESS testGrants 'Grants.RoleGrantRefusals' \
  '  if (!confirm_ok(role, role_len, confirmation, confirmation_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);' \
  '  if (0 && !confirm_ok(role, role_len, confirmation, confirmation_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);'

# Plant 16: a module grant that does not hold is let through to the hidden
# entity: it holds for everything (seen by the oracle sweep).
plant module-grant-seen-hidden $ACCESS testOracle 'Oracle.ModuleGrant' \
  '  int failed = 0;
  int r;
  if (slot == NULL || slot->bad || slot->cond == NULL) {' \
  '  int failed = 0;
  int r;
  if (grant->source == kSrcModule) {
    return 1;
  }
  if (slot == NULL || slot->bad || slot->cond == NULL) {'

plant_finish
