#!/bin/sh
#
# The shipped-assets gate (site admin story 18): a module ships stylesheets,
# scripts, images and fonts in its manifest; they exist for a tenant only while
# the module is enabled, are named by their owner, carry a content hash, take
# their type from their kind, and are refused at install when a rule is broken.
#
# Runs the Assets tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   stale-object                   the first plant, rebuilt: shows a plant is built
#   hash-of-the-name               Assets.AShippedFileIsListedWithItsTypeAndAContentHashWhileItsModuleIsEnabled, Assets.TheSameBytesGiveTheSameHashInAnyModule
#   script-typed-as-css            Assets.AShippedFileIsListedWithItsTypeAndAContentHashWhileItsModuleIsEnabled
#   dotdot-in-a-name               Assets.AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   any-character-in-a-name        Assets.AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   media-type-on-a-stylesheet     Assets.AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   image-type-unchecked           Assets.AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   font-type-unchecked            Assets.AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   text-asset-not-checked         Assets.AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt
#   size-unbounded                 Assets.EmptyOversizeAndRepeatedAssetsAreRefused
#   duplicate-name-allowed         Assets.EmptyOversizeAndRepeatedAssetsAreRefused
#   count-unbounded                Assets.EmptyOversizeAndRepeatedAssetsAreRefused
#   asset-owner-ignored            Layouts.AnAssetNameIsCheckedWhenATemplateIsSavedAndMustBeWrittenOut
#   asset-address-without-hash     Layouts.AFileAModuleShipsHasAnAddressWithItsHashAndAPageUsesIt
#   asset-not-checked-at-save      Layouts.AnAssetNameIsCheckedWhenATemplateIsSavedAndMustBeWrittenOut, Layouts.AFileAModuleShipsHasAnAddressWithItsHashAndAPageUsesIt
#   computed-asset-name-allowed    Layouts.AnAssetNameIsCheckedWhenATemplateIsSavedAndMustBeWrittenOut
#
# Every refusal test has its control in the tests beside it (a manifest that
# differs in the one thing and is accepted), so a plant turning one red is a
# test seeing the defect, not a build failure.
#
# Usage: check-assets.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testAssets 'Assets.*'
plant_control testLayout 'Layouts.*Asset*:Layouts.AFile*'

DECL=src/module/decl.c
TEMPLATE=src/template/template.c
T_LIST='Assets.AShippedFileIsListedWithItsTypeAndAContentHashWhileItsModuleIsEnabled'
T_REFUSE='Assets.AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt'
T_LIMITS='Assets.EmptyOversizeAndRepeatedAssetsAreRefused'

DOTDOT_OLD="    if (s[i] == '.' && i + 1 < n && s[i + 1] == '.') {"
DOTDOT_NEW="    if (0) {"

plant_stale stale-object $DECL testAssets "$T_LIST" \
  "$DOTDOT_OLD" "$DOTDOT_NEW" 

# Plant 1: the hash is of the file's name, so two files that differ have one
# hash when they share a name and the same bytes differ.
plant hash-of-the-name $DECL testAssets \
  "$T_LIST Assets.TheSameBytesGiveTheSameHashInAnyModule" \
  '        gsec_sha256_update(&ctx, da->pub.bytes, da->pub.bytes_len) != GSEC_OK ||' \
  '        gsec_sha256_update(&ctx, da->pub.name, da->pub.name_len) != GSEC_OK ||'

# Plant 2: a script is served as a stylesheet.
plant script-typed-as-css $DECL testAssets "$T_LIST" \
  '                               : "text/javascript; charset=utf-8";' \
  '                               : "text/css; charset=utf-8";'

# Plant 3: a name may hold `..`.
plant dotdot-in-a-name $DECL testAssets "$T_REFUSE" \
  "$DOTDOT_OLD" "$DOTDOT_NEW"

# Plant 4: a name may hold any character.
plant any-character-in-a-name $DECL testAssets "$T_REFUSE" \
  "    if (!machine_char(s[i])) {
      return 0;
    }
    if (s[i] == '.' && i + 1 < n" \
  "    if (0) {
      return 0;
    }
    if (s[i] == '.' && i + 1 < n"

# Plant 5: a stylesheet may name a media type of its own.
plant media-type-on-a-stylesheet $DECL testAssets "$T_REFUSE" \
  '        if (d->assets[i].given_media_len != 0) {' \
  '        if (0) {'

# Plant 6 and 7: an image or a font may be of any type.
plant image-type-unchecked $DECL testAssets "$T_REFUSE" \
  '        if (!type_listed(kImageTypes, p->media_type, p->media_type_len)) {' \
  '        if (!type_listed(kImageTypes, p->media_type, p->media_type_len) && 0) {'
plant font-type-unchecked $DECL testAssets "$T_REFUSE" \
  '        if (!type_listed(kFontTypes, p->media_type, p->media_type_len)) {' \
  '        if (!type_listed(kFontTypes, p->media_type, p->media_type_len) && 0) {'

# Plant 8: a stylesheet or script may be any bytes.
plant text-asset-not-checked $DECL testAssets "$T_REFUSE" \
  '        if (!text_ok((const char *)p->bytes, p->bytes_len, 1)) {' \
  '        if (0) {'

# Plant 9: one asset may be any size.
plant size-unbounded $DECL testAssets "$T_LIMITS" \
  '  if (n > GDEFCORE_ASSET_BYTES_MAX) {' \
  '  if (n > 0xFFFFFFFFu) {'

# Plant 10: a module may declare one name twice.
plant duplicate-name-allowed $DECL testAssets "$T_LIMITS" \
  '      for (j = i + 1; j < d->nassets; j++) {' \
  '      for (j = i + 1; j < i + 1; j++) {'

# Plant 11: a manifest may declare any number of assets.
plant count-unbounded $DECL testAssets "$T_LIMITS" \
  '      man->nassets > GDEFCORE_MODULE_ASSETS_MAX) {' \
  '      man->nassets > 0xFFFFFu) {'

# The asset() function and the check made when a template is saved are tested
# in the layout suite, where a page is rendered.
T_NAME='Layouts.AnAssetNameIsCheckedWhenATemplateIsSavedAndMustBeWrittenOut'
T_PAGE='Layouts.AFileAModuleShipsHasAnAddressWithItsHashAndAPageUsesIt'

# Plant 12: a reference resolves whatever its owner, so `other/site.css` finds
# `skin/site.css`.
plant asset-owner-ignored src/render/asset.c testLayout "$T_NAME" \
  '    if (a->module_len == owner_len && memcmp(a->module, ref, owner_len) == 0 &&' \
  '    if (1 &&'

# Plant 13: the address carries no hash, so a changed file keeps its address.
plant asset-address-without-hash src/render/asset.c testLayout "$T_PAGE" \
  '  memcpy(buf + at, a.hash, GDEFCORE_ASSET_HASH_LEN);
  at += GDEFCORE_ASSET_HASH_LEN;' \
  '  at += 0;'

# Plant 14: a template that names a missing file is saved.
plant asset-not-checked-at-save $TEMPLATE testLayout "$T_NAME $T_PAGE" \
  '  if (ctx->catalog == NULL) {
    return;
  }
  if (arg == NULL' \
  '  if (1) {
    return;
  }
  if (arg == NULL'

# Plant 15: a name that is computed is let through unchecked.
plant computed-asset-name-allowed $TEMPLATE testLayout "$T_NAME" \
  '  if (arg == NULL || !IS(arg, STRING)) {
    note(' \
  '  if (arg == NULL || !IS(arg, STRING)) {
    return;
    note('

plant_finish
