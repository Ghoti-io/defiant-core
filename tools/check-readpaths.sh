#!/bin/sh
#
# The access-filter bypass gate (AD-25): every read path, as a principal who
# may see nothing, and an access-relevant alter that traps.
#
# Runs on the real tree, then plants each defect in a COPY of the source by an
# exact text edit and requires the named test to fail. The tests:
#
#   Paths.EveryPublicFunctionIsFiled  the denominator over the public headers
#   Paths.NoPermission                every filtered read, as a principal with no grants
#   Paths.AlterThatTraps              an access-relevant alter that traps fails the call
#   Paths.DecisionThatTraps           a decision that traps fails the call
#   Paths.UndeclaredAccess            an undeclared access contribution is refused
#
# Usage: check-readpaths.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testReadpaths 'Paths.*:Principals.*'

# A read that skips the filter, in each of the places that makes one.
plant read-skips-filter src/access/access.c testReadpaths 'Paths.NoPermission' \
  '  visible = reader_sees(catalog, canon, &ev) &&
            entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
                actor_len, principal, principal_len);' \
  '  visible = 1 || (reader_sees(catalog, canon, &ev) &&
            entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
                actor_len, principal, principal_len));'

plant list-skips-visibility src/access/access.c testReadpaths 'Paths.NoPermission' \
  '    if (!reader_sees(catalog, ids[i], ev) ||
        !entity_visible(ev, grants, ngrants, local.type_name,
            local.type_name_len, actor, actor_len, principal, principal_len)) {' \
  '    if (!reader_sees(catalog, ids[i], ev) ||
        (0 && !entity_visible(ev, grants, ngrants, local.type_name,
            local.type_name_len, actor, actor_len, principal, principal_len))) {'

# The render path reads fields through the filter; this one reads them raw.
plant render-reads-unfiltered src/render/render.c testReadpaths 'Paths.NoPermission' \
  '  rc = gdefcore_access_read(catalog, request, id, id_len, "en", 2, field,' \
  '  (void)request;
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, id_len, "en", 2, field,'

# An alias resolves to an entity the request may not read.
plant alias-resolves-unfiltered src/form/form.c testReadpaths 'Paths.NoPermission' \
  '    rc = gdefcore_access_read(catalog, request, target, target_len, lang, lang_len,' \
  '    (void)request;
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, target, target_len, lang, lang_len,'

# "An access-relevant alter that traps": the subscriber is skipped and the
# call goes on, so a failed access check reads as no check.
plant access-alter-traps-open src/module/module.c testReadpaths 'Paths.AlterThatTraps' \
  '    if (!skip_soft || node->access) {' \
  '    if (!skip_soft) {'

# A decision that traps is skipped like an event.
plant decision-traps-open src/module/module.c testReadpaths 'Paths.DecisionThatTraps' \
  '        kind == GDEFCORE_HOOK_DECISION ? 0 : skip_soft);' \
  '        skip_soft);'

# An access contribution nobody declared is believed.
plant undeclared-access-believed src/module/module.c testReadpaths 'Paths.UndeclaredAccess' \
  '  if (access && !node->access) {' \
  '  if (0 && access && !node->access) {'

# The denominator: a new public read nobody filed. Only a declaration is
# needed; the test reads the headers.
plant unfiled-public-read include/ghoti.io/defiant-core/entity.h testReadpaths \
  'Paths.EveryPublicFunctionIsFiled' \
  '/** @brief Free ids from gdefcore_entity_ids(). NULL is ignored. */' \
  'GDEFCORE_API GDEFCORE_Result gdefcore_entity_peek(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len, char ** out);

/** @brief Free ids from gdefcore_entity_ids(). NULL is ignored. */'

plant_finish
