#!/bin/sh
#
# The menu gate (site admin story 6): a menu is a tree computed from what is
# declared and what the site stored, and an entry is shown when its target
# route's own permission check passes for the page's values. The site changes
# a generated entry with an override that stores only what it changed, and an
# override survives its module being disabled and enabled.
#
# Runs the Menus tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   stale-object                          the first plant, rebuilt: shows a plant is built
#   visibility-by-parallel-predicate      Menus.ATabIsShownOnlyForAnXTheRouteAllows, Menus.VisibilityIsWhatTheRouteTableSaysAboutThatRoute
#   override-stored-as-a-copy             Menus.AnOverrideStoresOnlyWhatTheSiteChangedAndFollowsTheEntryThroughAnUpgrade
#   anonymous-shown-an-admin-entry        Menus.AnAnonymousVisitorSeesNoAdminEntryAnywhere
#   tab-shown-for-an-x-the-route-denies   Menus.ATabIsShownOnlyForAnXTheRouteAllows
#   override-lost-on-disable-and-enable   Menus.AnOverrideSurvivesDisablingAndEnablingTheModule
#   authorize-not-called                  Menus.EditingMenusIsOnePermissionCheckedAtApplyForAChangesetWithARequest
#   stored-question-not-asked             Menus.AGrantNarrowedToOneMenuEditsThatMenuAndCannotMoveAnEntryOutOfIt
#   written-shape-not-asked               Menus.AGrantNarrowedToOneMenuEditsThatMenuAndCannotMoveAnEntryOutOfIt
#   hidden-crumb-kept                     Menus.ACrumbAboveThePageThatIsHiddenOrUnreachableIsLeftOutWithoutATrace
#   empty-group-shown                     Menus.AnEntryThatOnlyGroupsOthersIsShownOnlyWithSomethingUnderIt
#   hidden-parent-still-shown             Menus.HidingAnEntryRemovesItFromEveryOutputButNotTheRoute
#
# Every test has a control (the viewer who may follow the route DOES see the
# entry, the module that is enabled again DOES apply the override, the role
# that holds the grant DOES write), so a plant turning one red is a test seeing
# the defect, not a build failure.
#
# Usage: check-menu.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testMenu 'Menus.*'

SRC=src/menu/menu.c

# The check that decides an entry, and a rebuild that must be shown to happen.
PERMITS_OLD='  if (gdefcore_routes_permits(c->routes, c->request, node->route.p,
          node->route.n, c->match, &allowed) != GDEFCORE_OK ||
      !allowed) {
    return 0;
  }
  node->ok = node_href(c, i);'

# Plant 1: the entry is decided by a predicate of its own, the type-level
# question of the route'"'"'s permission, where the route'"'"'s own check asks about
# the entity its path names.
PERMITS_NEW='  {
    GDEFCORE_Route_Info info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    allowed = gdefcore_routes_info(c->routes, node->route.p, node->route.n,
                  &info) == GDEFCORE_OK &&
              (info.permission_len == 0 ||
                  gdefcore_access_permits(c->catalog, c->request, info.permission,
                      info.permission_len));
    if (!allowed) {
      return 0;
    }
  }
  node->ok = node_href(c, i);'

plant_stale stale-object $SRC testMenu \
  'Menus.ATabIsShownOnlyForAnXTheRouteAllows' \
  "$PERMITS_OLD" "$PERMITS_NEW"

plant visibility-by-parallel-predicate $SRC testMenu \
  'Menus.ATabIsShownOnlyForAnXTheRouteAllows Menus.VisibilityIsWhatTheRouteTableSaysAboutThatRoute' \
  "$PERMITS_OLD" "$PERMITS_NEW"

# Plant 2: an override carries a label the site never set, as a copy of the
# entry would: the stand-in is the name, as the caller'"'"'s snapshot of the entry
# stands for the label it had.
plant override-stored-as-a-copy $SRC testMenu \
  'Menus.AnOverrideStoresOnlyWhatTheSiteChangedAndFollowsTheEntryThroughAnUpgrade' \
  '  value_set(&values[1], "label", &slots[1], &lens[1], override->label,
      override->label_len, override->label != NULL);' \
  '  value_set(&values[1], "label", &slots[1], &lens[1],
      override->label != NULL ? override->label : name,
      override->label != NULL ? override->label_len : name_len, 1);'

# Plant 3: a request with no principal is let through where the route'"'"'s check
# said no.
plant anonymous-shown-an-admin-entry $SRC testMenu \
  'Menus.AnAnonymousVisitorSeesNoAdminEntryAnywhere' \
  '  int allowed = 0;
  if (node->ok >= 0) {' \
  '  int allowed = 0;
  size_t pl = 0;
  if (node->ok >= 0) {' \
  '      !allowed) {
    return 0;
  }
  node->ok = node_href(c, i);' \
  '      (!allowed && gdefcore_request_principal(c->request, &pl) != NULL)) {
    return 0;
  }
  node->ok = node_href(c, i);'

# Plant 4: a tab is shown for the page it is on whatever its route says of the
# value of that page.
plant tab-shown-for-an-x-the-route-denies $SRC testMenu \
  'Menus.ATabIsShownOnlyForAnXTheRouteAllows' \
  '    shown = on_page && node_ok(c, i);' \
  '    shown = on_page;'

# Plant 5: apply cleans up the overrides that no enabled module has an entry
# for, which is what turning a module off looks like to an override.
plant override-lost-on-disable-and-enable $SRC testMenu \
  'Menus.AnOverrideSurvivesDisablingAndEnablingTheModule' \
  'static GDEFCORE_Result ctx_build(Ctx * c) {' \
  'static GDEFCORE_Result find_named(GDEFCORE_Catalog * catalog, const char * type,
    const char * name, size_t name_len, char id[GDEFCORE_PUBLIC_ID_LEN + 1]);

static GDEFCORE_Result forget_orphans(Ctx * c) {
  size_t k;
  size_t i;
  for (k = 0; k < c->nov; k++) {
    int found = 0;
    for (i = 0; i < c->n; i++) {
      found = found || (c->nodes[i].source != GDEFCORE_MENU_SOURCE_SITE &&
                           str_eq(&c->nodes[i].name, &c->ovs[k].name));
    }
    if (!found) {
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      GDEFCORE_Changeset * cs = NULL;
      if (find_named(c->catalog, kOverrideType, c->ovs[k].name.p,
              c->ovs[k].name.n, id) == GDEFCORE_OK &&
          gdefcore_changeset_prepare(c->catalog, NULL, 0, &cs) == GDEFCORE_OK) {
        if (gdefcore_entity_clear(cs, id, GDEFCORE_PUBLIC_ID_LEN) ==
            GDEFCORE_OK) {
          (void)gdefcore_changeset_apply(cs, kOverrideType,
              sizeof kOverrideType - 1);
        }
        gdefcore_changeset_destroy(cs);
      }
    }
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result ctx_build(Ctx * c) {' \
  '  if (rc == GDEFCORE_OK) {
    rc = apply_overrides(c);
  }' \
  '  if (rc == GDEFCORE_OK) {
    rc = apply_overrides(c);
  }
  if (rc == GDEFCORE_OK) {
    rc = forget_orphans(c);
  }'

# Plant 6: apply does not ask whether the principal may edit a menu.
plant authorize-not-called src/entity/entity.c testMenu \
  'Menus.EditingMenusIsOnePermissionCheckedAtApplyForAChangesetWithARequest' \
  '    rc = gdefcore_menu_authorize(changeset, changeset->request);' \
  '    rc = GDEFCORE_OK;'

# Plant 7: a write that changes a stored entry is judged by the entry it
# becomes only, so a grant for the menu it moves to is enough to take it.
plant stored-question-not-asked $SRC testMenu \
  'Menus.AGrantNarrowedToOneMenuEditsThatMenuAndCannotMoveAnEntryOutOfIt' \
  '  if (revisions > 0) {' \
  '  if (revisions > 0 && 0) {'

# Plant 8: a write is judged by the entry as stored only, so a new entry, which
# has nothing stored, needs no grant for the menu it is put in.
plant written-shape-not-asked $SRC testMenu \
  'Menus.AGrantNarrowedToOneMenuEditsThatMenuAndCannotMoveAnEntryOutOfIt' \
  '  rc = gdefcore_access_can_with(catalog, request, GDEFCORE_MENU_EDIT,
      sizeof GDEFCORE_MENU_EDIT - 1, type, strlen(type), id, values,
      kShapeFields, &ok);' \
  '  ok = 1;
  rc = GDEFCORE_OK;
  (void)values;'

# Plant 9: the trail keeps a crumb the viewer may not follow, or the site hid.
plant hidden-crumb-kept $SRC testMenu \
  'Menus.ACrumbAboveThePageThatIsHiddenOrUnreachableIsLeftOutWithoutATrace' \
  '    if (node->route.n == 0 || !node_ok(&c, chain[i])) {' \
  '    if (node->route.n == 0) {'

# Plant 10: an entry that only groups others is shown with nothing under it.
plant empty-group-shown $SRC testMenu \
  'Menus.AnEntryThatOnlyGroupsOthersIsShownOnlyWithSomethingUnderIt' \
  '  *shown = group ? (chain && any) : chain;' \
  '  *shown = chain;'

# Plant 11: an entry is shown whatever its own check says, and what is under
# it with it.
plant hidden-parent-still-shown $SRC testMenu \
  'Menus.HidingAnEntryRemovesItFromEveryOutputButNotTheRoute' \
  '  int chain = parent_ok && own;' \
  '  int chain = parent_ok;
  (void)own;'

plant_finish
