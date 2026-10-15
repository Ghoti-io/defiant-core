#!/bin/sh
#
# The route-pattern gate (site admin epic, story 4): named segments, route
# permission with the matched values, default tabs, and the rule that a
# refused route answers as a missing route does.
#
# Runs the Routes tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   Routes.Capture                  a capture is the segment its name says
#   Routes.PermissionWithValue      the check is given the matched values
#   Routes.RefusalIsAMissingRoute   a refusal is not distinguishable from a
#                                   missing route (return code, resolution,
#                                   status, notes, handlers that ran)
#   Routes.DefaultTab               a default tab answers its parent's path
#   Routes.DefaultTabIsExactAndFallThroughIsHonest
#                                   ... and only exactly that path
#   Routes.OrphanTab                a tab needs a registered parent
#   Routes.TabErrors                a second default tab is refused
#   Routes.BadNamesAreRefused       a repeated capture name is refused
#   Routes.PatternLimits            a capture name has a length limit
#   Routes.Exactness                an explicit segment beats a named one
#
# Usage: check-routes.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testRoutes 'Routes.*'

# (1) The permission is checked without the matched values: the call the
# check receives names no segment of the pattern, so no capture can be read.
plant check-without-values src/form/form.c testRoutes 'Routes.PermissionWithValue' \
  '        st.npat = c.npat;' \
  '        st.npat = 0;'

# (2) A capture returns the wrong segment (the first, not the one it names).
plant capture-wrong-segment src/form/form.c testRoutes 'Routes.Capture' \
  '      *out_value = st->req[i].text;
      *out_len = st->req[i].len;' \
  '      *out_value = st->req[0].text;
      *out_len = st->req[0].len;'

# (3) A default tab is not served at its parent's path.
plant default-tab-not-at-parent src/form/form.c testRoutes 'Routes.DefaultTab' \
  '    } else if (r->alt != NULL && r->nalt == nreq &&' \
  '    } else if (0 && r->alt != NULL && r->nalt == nreq &&'

# (3b) ... or is served there as an ancestor, so a longer path reaches it.
plant default-tab-as-ancestor src/form/form.c testRoutes \
  'Routes.DefaultTabIsExactAndFallThroughIsHonest' \
  'r->nalt == nreq' 'r->nalt <= nreq'

# (4) A refusal that answers differently from a missing route: once in the
# resolution, once in the request status, and once not at all (the check's
# answer is ignored, so the refused route runs).
plant refusal-sets-resolution src/form/form.c testRoutes 'Routes.RefusalIsAMissingRoute' \
  '      if (!allowed) {
        continue;
      }' \
  '      if (!allowed) {
        (void)gdefcore_request_set_resolution(request, "route.denied", 12);
        continue;
      }'

plant refusal-sets-status src/form/form.c testRoutes 'Routes.RefusalIsAMissingRoute' \
  '      if (!allowed) {
        continue;
      }' \
  '      if (!allowed) {
        gdefcore_request_set_status(request, GDEFCORE_ERR_INVALID);
        continue;
      }'

plant refusal-ignored src/form/form.c testRoutes 'Routes.RefusalIsAMissingRoute' \
  '      if (!allowed) {
        continue;
      }' \
  '      if (0 && !allowed) {
        continue;
      }'

# (5) An orphan tab is accepted.
plant orphan-tab-accepted src/form/form.c testRoutes 'Routes.OrphanTab' \
  '    if (parent == NULL) {
      route_error(alloc, out_error, out_error_len, "tab has no parent route",' \
  '    if (0 && parent == NULL) {
      route_error(alloc, out_error, out_error_len, "tab has no parent route",' \
  '    if (spec->is_default) {
      for (i = 0; i < routes->nroutes; i++) {' \
  '    if (spec->is_default && parent != NULL) {
      for (i = 0; i < routes->nroutes; i++) {'

# A second default tab for one parent is accepted.
plant second-default-accepted src/form/form.c testRoutes 'Routes.TabErrors' \
  '        if (r->is_default && span_eq(r->parent, r->parent_len, spec->parent,' \
  '        if (0 && r->is_default && span_eq(r->parent, r->parent_len, spec->parent,'

# A repeated capture name is accepted.
plant repeated-name-accepted src/form/form.c testRoutes 'Routes.BadNamesAreRefused' \
  '        if (segs[k].named && span_eq(segs[k].text, segs[k].len, path + start + 1,' \
  '        if (0 && segs[k].named && span_eq(segs[k].text, segs[k].len, path + start + 1,'

# A capture name has no length limit.
plant name-length-unbounded src/form/form.c testRoutes 'Routes.PatternLimits' \
  '      } else if (len - 1 > GDEFCORE_ROUTE_NAME_MAX) {' \
  '      } else if (0 && len - 1 > GDEFCORE_ROUTE_NAME_MAX) {'

# A named segment is scored as an explicit one, so it no longer loses to it.
plant named-scores-as-explicit src/form/form.c testRoutes 'Routes.Exactness' \
  '    if (!segs[n].wild) {
      exact += 1000000 / (int)(n + 1);' \
  '    if (1) {
      exact += 1000000 / (int)(n + 1);'

plant_finish
