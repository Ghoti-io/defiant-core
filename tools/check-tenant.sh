#!/bin/sh
#
# The cross-tenant gate (AD-25), defiant-core's part: two tenants interleaved
# through every route and View the library resolves, and the compiled
# artifacts it keeps (the render key, the host's hook chains).
#
# Runs on the real tree, then plants each defect in a COPY of the source by an
# exact text edit and requires the named test to fail:
#
#   Tenant.RenderKeyCarriesTenant      a render key built without the tenant
#   Tenant.HookChainsAreKeptPerTenant  a hook chain found without the tenant
#   Tenant.Interleaved                 a stored projection read without the tenant
#
# Usage: check-tenant.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testTenant 'Tenant.*'

# "A compiled artifact keyed without the tenant", twice over.
plant render-key-without-tenant src/access/access.c testTenant \
  'Tenant.RenderKeyCarriesTenant' \
  '    ADD_KEY(tenant_hex, hex_n);' \
  '    ADD_KEY("", 0);'

plant hook-chain-without-tenant src/module/module.c testTenant \
  'Tenant.HookChainsAreKeptPerTenant' \
  '    if (memcmp(chain->tenant, tenant, tenant_len) == 0 &&' \
  '    if (((void)tenant, 1) &&'

# "A tenant missing from a query": every entity record read goes to tenant
# "A" (the port's read, since story S6b).
plant entity-read-without-tenant src/entity/store.c testTenant \
  'Tenant.Interleaved' \
  '  src = gdefstor_entity_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, canon, GDEFCORE_PUBLIC_ID_LEN, &e);' \
  '  src = gdefstor_entity_get(cat->store, "A", 1, canon,
      GDEFCORE_PUBLIC_ID_LEN, &e);'

plant_finish
