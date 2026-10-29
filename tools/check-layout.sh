#!/bin/sh
#
# The layout gate (site admin story 7): widget types are a catalog a module
# adds to with no change to the kernel; a layout places widgets only into the
# regions its page template declares, and is refused when it is saved if it does
# not; the layout of a page is chosen through the route trie, most specific
# first, in one order that does not depend on registration; an alter hook may
# refine the choice and can deny nothing; a contributor cannot change the main
# content; a widget never shows what its source would not; and one tenant's
# layouts never reach another.
#
# Runs the Layouts tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   stale-object                             the first plant, rebuilt: shows a plant is built
#   unknown-region-accepted                  Layouts.AnUnknownRegionIsRefusedAndNothingIsWritten
#   vet-not-called                           Layouts.AnUnknownRegionIsRefusedAndNothingIsWritten
#   template-change-breaks-layout            Layouts.ChangingAPageTemplateCannotLeaveALayoutBroken
#   module-disable-leaves-layout-broken      Layouts.AModuleWidgetAndSelectorChangeAPageWithNoKernelChange
#   module-widget-needs-a-kernel-change      Layouts.TheCatalogHasEightTypesAndAModuleAddsMore, Layouts.AModuleWidgetAndSelectorChangeAPageWithNoKernelChange
#   overlap-resolved-by-registration-order   Layouts.OverlappingContributorsResolveTheSameWayWhateverTheRegistrationOrder
#   site-rule-not-before-a-module            Layouts.ModulesEnabledInAnyOrderGiveTheSameOffersAndTheSiteBeatsAModule
#   type-of-a-rule-ignored                   Layouts.TheMoreSpecificRuleWinsAndTheOffersAreInOneOrder
#   rule-pattern-unchecked                   Layouts.ARuleIsCheckedWhenItIsSavedAndPassedOverWhenItsLayoutIsGone
#   contributor-alters-main-content          Layouts.TheMainContentIsTheSameWithAndWithoutAContributor
#   alter-hook-able-to-deny                  Layouts.AnAlterHookRefinesTheLayoutForARoleAndCannotDenyAPage
#   alter-name-not-checked                   Layouts.AnAlterHookRefinesTheLayoutForARoleAndCannotDenyAPage
#   hidden-widget-reveals-content            Layouts.AHiddenWidgetRendersNothingAndRevealsNothing
#   tenant-layout-leak                       Layouts.TwoTenantsLayoutsNeverMix
#   authorize-not-called                     Layouts.EditingLayoutsIsOnePermissionCheckedAtApplyForAChangesetWithARequest
#
# Every test has a control (the viewer who holds the permission DOES see the
# widget, the module enabled in the other order DOES give the same offers, the
# role that holds the grant DOES write), so a plant turning one red is a test
# seeing the defect, not a build failure.
#
# Usage: check-layout.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testLayout 'Layouts.*'

LAYOUT=src/render/layout.c
FORM=src/form/form.c

# The check of a placement's region, and a rebuild that must be shown to
# happen.
REGION_OLD='    if (!found) {
      say(why, cap, "The page template does not declare the region ", region,'
REGION_NEW='    if (!found && 0) {
      say(why, cap, "The page template does not declare the region ", region,'

plant_stale stale-object $LAYOUT testLayout \
  'Layouts.AnUnknownRegionIsRefusedAndNothingIsWritten' \
  "$REGION_OLD" "$REGION_NEW"

# Plant 1: a layout may place into a region its page template does not declare.
plant unknown-region-accepted $LAYOUT testLayout \
  'Layouts.AnUnknownRegionIsRefusedAndNothingIsWritten' \
  "$REGION_OLD" "$REGION_NEW"

# Plant 2: apply does not vet layouts and rules at all.
plant vet-not-called src/entity/entity.c testLayout \
  'Layouts.AnUnknownRegionIsRefusedAndNothingIsWritten' \
  '  rc = gdefcore_layout_vet(changeset);' \
  '  rc = GDEFCORE_OK;'

# Plant 3: a page template can be changed under the layouts that use it.
plant template-change-breaks-layout $LAYOUT testLayout \
  'Layouts.ChangingAPageTemplateCannotLeaveALayoutBroken' \
  '  return vet_template_users(changeset, catalog);' \
  '  return GDEFCORE_OK;'

# Plant 4: disabling a module leaves a layout that places its widget.
plant module-disable-leaves-layout-broken $LAYOUT testLayout \
  'Layouts.AModuleWidgetAndSelectorChangeAPageWithNoKernelChange' \
  '  any = any || gdefcore_changeset_module_count(changeset) > 0;' \
  '  any = any || 0;' \
  '           (gdefcore_changeset_module_count(changeset) > 0 ||
               template_touched(changeset, catalog, tmpl, tmpl_len));' \
  '           (0 || template_touched(changeset, catalog, tmpl, tmpl_len));'

# Plant 5: the catalog is the built-in list: a module's type is not in it.
plant module-widget-needs-a-kernel-change $LAYOUT testLayout \
  'Layouts.TheCatalogHasEightTypesAndAModuleAddsMore Layouts.AModuleWidgetAndSelectorChangeAPageWithNoKernelChange' \
  '  rc = module_widgets(catalog, projection, &items, &n);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INVALID;
  }
  rc = GDEFCORE_ERR_INVALID;' \
  '  (void)projection;
  rc = GDEFCORE_ERR_INVALID;'

# Plant 6: offers with the same rank are left in the order they were made, so
# the order depends on the order contributors were registered.
plant overlap-resolved-by-registration-order $FORM testLayout \
  'Layouts.OverlappingContributorsResolveTheSameWayWhateverTheRegistrationOrder' \
  '  int weight;
  int site;
} OfferRec;' \
  '  int weight;
  int site;
  size_t seq;
} OfferRec;' \
  '  rec->site = offer->site != 0;
  set->n += 1;' \
  '  rec->site = offer->site != 0;
  rec->seq = set->n;
  set->n += 1;' \
  '  if (a->weight != b->weight) {
    return a->weight < b->weight ? -1 : 1;
  }
  if (a->site != b->site) {
    return a->site ? -1 : 1;
  }
  c = bytes_cmp(a->source, a->source_len, b->source, b->source_len);
  if (c != 0) {
    return c;
  }
  return bytes_cmp(a->value, a->value_len, b->value, b->value_len);' \
  '  c = 0;
  (void)c;
  return a->seq < b->seq ? -1 : (a->seq > b->seq);'

# Plant 7: the site's rule is no better than a module'"'"'s of the same rank.
plant site-rule-not-before-a-module $FORM testLayout \
  'Layouts.ModulesEnabledInAnyOrderGiveTheSameOffersAndTheSiteBeatsAModule' \
  '  if (a->site != b->site) {
    return a->site ? -1 : 1;
  }
  c = bytes_cmp' \
  '  c = bytes_cmp'

# Plant 8: a rule that names a type is offered for a page of any type.
plant type-of-a-rule-ignored $LAYOUT testLayout \
  'Layouts.TheMoreSpecificRuleWinsAndTheOffersAreInOneOrder' \
  '        (n[3] == 0 || span_eq(f[3], n[3], ptype == NULL ? "" : ptype, ptype_len)) &&' \
  '        1 &&'

# Plant 9: a rule is saved with a path that is no pattern.
plant rule-pattern-unchecked $LAYOUT testLayout \
  'Layouts.ARuleIsCheckedWhenItIsSavedAndPassedOverWhenItsLayoutIsGone' \
  '  } else if (!gdefcore_route_pattern_ok(f[1], n[1], NULL)) {' \
  '  } else if (0) {'

# Plant 10: a contributor'"'"'s change to the request'"'"'s resolution stands, so it
# can change which entity the page shows.
plant contributor-alters-main-content $FORM testLayout \
  'Layouts.TheMainContentIsTheSameWithAndWithoutAContributor' \
  '    (void)gdefcore_request_set_resolution(request, kept_res, kept_len);
' \
  '    (void)kept_len;
'

# Plant 11: a refinement that names nothing denies the page.
plant alter-hook-able-to-deny $LAYOUT testLayout \
  'Layouts.AnAlterHookRefinesTheLayoutForARoleAndCannotDenyAPage' \
  '        size_t text_len = 0;
        if (gdefcore_alter_text(alter, &text, &text_len) == GDEFCORE_OK &&
            text_len > 0 &&' \
  '        size_t text_len = 0;
        if (gdefcore_alter_text(alter, &text, &text_len) == GDEFCORE_OK &&
            text_len == 0) {
          return GDEFCORE_ERR_INVALID;
        }
        if (gdefcore_alter_text(alter, &text, &text_len) == GDEFCORE_OK &&
            text_len > 0 &&'

# Plant 12: a refinement is taken whether or not it names a layout that can be
# applied.
plant alter-name-not-checked $LAYOUT testLayout \
  'Layouts.AnAlterHookRefinesTheLayoutForARoleAndCannotDenyAPage' \
  '!span_eq(text, text_len, chosen, chosen_len) &&
            gdefcore_layout_check(catalog, text, text_len) == GDEFCORE_OK) {' \
  '!span_eq(text, text_len, chosen, chosen_len)) {'

# Plant 13: a module'"'"'s widget is drawn for a viewer who lacks the permission
# its source needs.
plant hidden-widget-reveals-content src/render/render.c testLayout \
  'Layouts.AHiddenWidgetRendersNothingAndRevealsNothing' \
  '  if (w->fn == NULL ||
      (w->permission_len > 0 &&
          !gdefcore_access_permits(catalog, request, w->permission,
              w->permission_len))) {' \
  '  if (w->fn == NULL) {'

# Plant 14: the choice for a path is kept by the path alone, as a cache of one
# route table'"'"'s answers shared by every tenant would keep it.
plant tenant-layout-leak $LAYOUT testLayout \
  'Layouts.TwoTenantsLayoutsNeverMix' \
  '  *out_name = NULL;
  *out_len = 0;
  /* An alias is spelled without its slash' \
  '  static char memo_path[512];
  static char memo_name[256];
  *out_name = NULL;
  *out_len = 0;
  if (path_len < sizeof memo_path && memo_name[0] != 0 &&
      strlen(memo_path) == path_len && memcmp(memo_path, path, path_len) == 0) {
    if (gdefcore_text_dup(catalog, memo_name, strlen(memo_name), out_name) !=
        GDEFCORE_OK) {
      return GDEFCORE_ERR_OOM;
    }
    *out_len = strlen(memo_name);
    return GDEFCORE_OK;
  }
  /* An alias is spelled without its slash' \
  '  free(slashed);
  *out_name = chosen;
  *out_len = chosen_len;' \
  '  if (path_len < sizeof memo_path && chosen_len < sizeof memo_name) {
    memcpy(memo_path, path, path_len);
    memo_path[path_len] = 0;
    memcpy(memo_name, chosen, chosen_len);
    memo_name[chosen_len] = 0;
  }
  free(slashed);
  *out_name = chosen;
  *out_len = chosen_len;'

# Plant 15: apply does not ask whether the principal may edit a layout.
plant authorize-not-called src/entity/entity.c testLayout \
  'Layouts.EditingLayoutsIsOnePermissionCheckedAtApplyForAChangesetWithARequest' \
  '    rc = gdefcore_layout_authorize(changeset, changeset->request);' \
  '    rc = GDEFCORE_OK;'

plant_finish
