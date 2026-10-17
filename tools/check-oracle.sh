#!/bin/sh
#
# The oracle sweep gate (AD-25): filter, sort, alias collision and diagnostics
# behave alike for hidden and missing entities.
#
# Runs the sweep on the real tree, then plants "a filter on an unreadable
# field accepted" in a copy of the source and requires Oracle.Fields to fail
# by name. Oracle.Control is run too: it proves the sweep can tell a visible
# entity from an absent one.
#
# Usage: check-oracle.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testOracle 'Oracle.*'

# access_list refuses a filter on a field the principal may not read twice:
# once before it looks at any row, and once per visible row. The planted
# defect turns both off, so the filter is accepted and evaluated against the
# unreadable field's values.
plant filter-unreadable-field src/access/access.c testOracle 'Oracle.Fields' \
  '  if (local.filter_field != NULL && local.filter_field_len > 0) {
    if (!type_has_field(' \
  '  if (0 && local.filter_field != NULL && local.filter_field_len > 0) {
    if (!type_has_field(' \
  '    if ((local->filter_field != NULL && local->filter_field_len > 0 &&' \
  '    if ((0 && local->filter_field != NULL && local->filter_field_len > 0 &&'

# The same defect for sort: a sort on an unreadable field orders by it.
plant sort-unreadable-field src/access/access.c testOracle 'Oracle.Fields' \
  '  if (local.sort_field != NULL && local.sort_field_len > 0) {
    if (!type_has_field(' \
  '  if (0 && local.sort_field != NULL && local.sort_field_len > 0) {
    if (!type_has_field(' \
  '        (local->sort_field != NULL && local->sort_field_len > 0 &&' \
  '        (0 && local->sort_field != NULL && local->sort_field_len > 0 &&'

# Alias resolution: a hidden entity's alias resolves, so the path answers
# differently from a path nobody owns.
plant alias-resolves-unfiltered src/form/form.c testOracle 'Oracle.Entities' \
  '    rc = gdefcore_access_read(catalog, request, target, target_len, lang, lang_len,' \
  '    (void)request;
    rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, target, target_len, lang, lang_len,'

# A list that shows rows the principal may not read: count and order differ.
# (The list asks two things of a row, whether it is published and whether a
# grant covers it; this turns off the second. The first is planted by
# list-lists-unpublished-oracle in check-can.sh.)
plant list-skips-visibility src/access/access.c testOracle 'Oracle.Entities' \
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

# A read that answers for a hidden id as if the principal could see it.
plant read-skips-filter src/access/access.c testOracle 'Oracle.Entities' \
  '  visible = reader_sees(catalog, canon, &ev) &&
            entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
                actor_len, principal, principal_len);' \
  '  visible = 1 || (reader_sees(catalog, canon, &ev) &&
            entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
                actor_len, principal, principal_len));'

# A revision view that tells an entity the principal may not look at (one that
# exists) from one that does not exist.
plant revision-view-tells-hidden-from-missing src/access/access.c testOracle 'Oracle.Entities' \
  '    /* No permission, no such entity and no such field answer alike. */
    gdefcore_text_free(catalog, type_name);
    return GDEFCORE_ERR_INVALID;' \
  '    /* No permission, no such entity and no such field answer alike. */
    gdefcore_text_free(catalog, type_name);
    return may_view ? GDEFCORE_ERR_INVALID : GDEFCORE_ERR_LIMIT;'

plant_finish
