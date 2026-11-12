#!/bin/sh
#
# The views gate: a view is stored as data
# (a condition tree, arguments, columns, formatters, a set format), refused at
# save with the reason when anything in it is wrong, and run through the access
# filter, so that a row or a field the principal may not see is not in the
# result, an argument value is only ever a constant, and a stored view that no
# longer fits its type is never run loosely.
#
# Runs the Views tests on the real tree, then plants each defect in a COPY of the
# source by an exact text edit and requires the named test to fail:
#
#   list-unfiltered                   Views.ARowThePrincipalMayNotSeeIsNotInTheRowsOrTheTotal
#   cells-read-unfiltered             Views.AFieldThePrincipalMayNotReadIsAnEmptyCellAndAFieldTheyMayIsShown
#   argument-not-escaped              Views.AnArgumentValueIsAConstantAndNeverPartOfTheCondition
#   dollar-in-a-constant-is-an-argument  Views.AnArgumentValueIsAConstantAndNeverPartOfTheCondition
#   condition-not-validated           Views.ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong
#   formatter-not-checked             Views.ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong
#   personal-column-allowed           Views.ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong
#   unused-argument-allowed           Views.ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong
#   save-skips-validation             Views.ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong
#   refusal-reason-dropped            Views.ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong
#   run-skips-validation              Views.AStoredViewThatNoLongerFitsItsTypeIsNeverRunLoosely
#   limit-ignored                     Views.ARunGivesTheRowsInOrderWithEachColumnFormatted
#   offset-ignored                    Views.ARunGivesTheRowsInOrderWithEachColumnFormatted
#   total-not-from-the-list           Views.ARunGivesTheRowsInOrderWithEachColumnFormatted
#   csv-formula-not-neutralised       Views.CsvAndJsonAreQuotedEscapedAndSafeToOpenInASpreadsheet
#   csv-quote-not-doubled             Views.CsvAndJsonAreQuotedEscapedAndSafeToOpenInASpreadsheet
#   json-not-escaped                  Views.CsvAndJsonAreQuotedEscapedAndSafeToOpenInASpreadsheet
#   principal-argument-from-caller    Views.TheCurrentPrincipalIsAnArgumentAndAnonymousIsNoRows
#   operator-table-wrong              Views.TheOperatorAndFormatterTablesAreWhatTheSaveAccepts
#   param-size-unchecked              Views.TheStructsOfAViewAreAcceptedAtOnlyTheirOwnSize
#   view-authorize-skipped            Views.AViewIsWrittenOnlyByARequestThatMayEditViews
#   row-read-per-column               ViewGroups.ARowCostsOneReadOfTheEntityHoweverManyColumnsItShows
#   group-items-of-any-path-counted   ViewGroups.AGroupAndAFieldInsideOneAreColumnsReadAcrossEveryItem
#   nested-leaf-not-matched           ViewGroups.AGroupAndAFieldInsideOneAreColumnsReadAcrossEveryItem
#   group-formatter-allows-join       ViewGroups.AColumnNamesOnlyWhatTheTypeHasAndOnlyAFormatterThatSuitsIt
#   nested-personal-field-shown       ViewGroups.AColumnNamesOnlyWhatTheTypeHasAndOnlyAFormatterThatSuitsIt
#   sort-by-nested-field-allowed      ViewGroups.AColumnNamesOnlyWhatTheTypeHasAndOnlyAFormatterThatSuitsIt
#   nested-cells-read-unfiltered      ViewGroups.TheFieldsAReaderMayNotSeeAreEmptyInEveryItem
#
# Every test has a control (a good view saves, a condition of every operator the
# table lists, the administrator-like reader who sees all four rows, the default
# of an argument, a title that holds quotes), so a plant turning one red is a test
# seeing the defect, not a build failure.
#
# Usage: check-view.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testView 'Views.*'
plant_control testView 'ViewGroups.*'

V=src/view/view.c
T_HID='Views.ARowThePrincipalMayNotSeeIsNotInTheRowsOrTheTotal'
T_FIELD='Views.AFieldThePrincipalMayNotReadIsAnEmptyCellAndAFieldTheyMayIsShown'
T_ARG='Views.AnArgumentValueIsAConstantAndNeverPartOfTheCondition'
T_REF='Views.ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong'
T_LOOSE='Views.AStoredViewThatNoLongerFitsItsTypeIsNeverRunLoosely'
T_RUN='Views.ARunGivesTheRowsInOrderWithEachColumnFormatted'
T_OUT='Views.CsvAndJsonAreQuotedEscapedAndSafeToOpenInASpreadsheet'
T_PRIN='Views.TheCurrentPrincipalIsAnArgumentAndAnonymousIsNoRows'
T_TAB='Views.TheOperatorAndFormatterTablesAreWhatTheSaveAccepts'
T_SIZE='Views.TheStructsOfAViewAreAcceptedAtOnlyTheirOwnSize'
T_GCOLS='ViewGroups.AGroupAndAFieldInsideOneAreColumnsReadAcrossEveryItem'
T_GBAD='ViewGroups.AColumnNamesOnlyWhatTheTypeHasAndOnlyAFormatterThatSuitsIt'
T_GREADS='ViewGroups.ARowCostsOneReadOfTheEntityHoweverManyColumnsItShows'
T_GHID='ViewGroups.TheFieldsAReaderMayNotSeeAreEmptyInEveryItem'

# The list is the unfiltered index of the type, not the principal's page: a row
# the principal may not see is in the rows and in the total.
plant list-unfiltered $V testView "$T_HID" \
  '    rc = gdefcore_access_list_page(catalog, request, &q, &ids, &count, &total);' \
  '    rc = gdefcore_entity_ids(catalog, def.type, def.type_len, &ids, &count);
    total = count;'

# A row is read as the system, not through the field filter.
plant cells-read-unfiltered $V testView "$T_FIELD" \
  '    GDEFCORE_Result rr = gdefcore_access_tree(catalog, request, ids[row], strlen(ids[row]),
        kLang, 2, &tree);' \
  '    GDEFCORE_Result rr = gdefcore_entity_tree(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[row],
        strlen(ids[row]), kLang, 2, &tree);'

# The same, seen in the fields of the items of a group.
plant nested-cells-read-unfiltered $V testView "$T_GHID" \
  '    GDEFCORE_Result rr = gdefcore_access_tree(catalog, request, ids[row], strlen(ids[row]),
        kLang, 2, &tree);' \
  '    GDEFCORE_Result rr = gdefcore_entity_tree(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[row],
        strlen(ids[row]), kLang, 2, &tree);'

# An argument value is put in as it came: a quote or backslash in it ends the
# constant.
plant argument-not-escaped $V testView "$T_ARG" \
  "    if (ch == '\"' || ch == '\\\\') {" \
  '    if (0) {'

# A $ inside a quoted constant of the stored condition is read as an argument.
plant dollar-in-a-constant-is-an-argument $V testView "$T_ARG" \
  '    if (c == '"'"'"'"'"') {
      in_string = 1;' \
  '    if (c == '"'"'"'"'"') {
      in_string = 0;'

# The condition is parsed and not checked against the type, so a field the type
# lacks, a personal one and an ordering of text are saved.
plant condition-not-validated $V testView "$T_REF" \
  '        rc = gdefcore_condition_validate(catalog, cond, def->type, def->type_len, &err);' \
  '        rc = GDEFCORE_OK;'

plant formatter-not-checked $V testView "$T_REF" \
  '    if (!formatter_ok(shape.type, shape.many, c->formatter, c->formatter_len, &trunc)) {' \
  '    if (formatter_ok(shape.type, shape.many, c->formatter, c->formatter_len, &trunc) < 0) {'

plant personal-column-allowed $V testView "$T_REF" \
  '    if (shape.personal) {
      REFUSE("%.*s is a personal field, which a view does not show", c->field,' \
  '    if (shape.personal < 0) {
      REFUSE("%.*s is a personal field, which a view does not show", c->field,'

plant unused-argument-allowed $V testView "$T_REF" \
  '      if ((ctx.seen & (1u << i)) == 0) {' \
  '      if ((ctx.seen & (1u << i)) == 2) {'

# A save stages without validating; and a refusal's reason is not kept.
plant save-skips-validation $V testView "$T_REF" \
  '  rc = gdefcore_view_validate(catalog, def, why, sizeof why);
  if (rc != GDEFCORE_OK) {' \
  '  rc = GDEFCORE_OK;
  why[0] = 0;
  if (rc != GDEFCORE_OK) {'

plant refusal-reason-dropped $V testView "$T_REF" \
  '      (void)gdefcore_changeset_set_refusal(changeset, why, strlen(why));' \
  '      (void)why;'

# A stored view is run without being checked against its type again.
plant run-skips-validation $V testView "$T_LOOSE" \
  '  rc = gdefcore_view_validate(catalog, &def, NULL, 0);
  if (rc != GDEFCORE_OK) {
    gdefcore_view_def_free(catalog, owner);
    return rc;
  }' \
  '  rc = GDEFCORE_OK;'

plant limit-ignored $V testView "$T_RUN" \
  '    q.limit = def.limit;' \
  '    q.limit = 0;'

plant offset-ignored $V testView "$T_RUN" \
  '    q.offset = offset;' \
  '    q.offset = offset * 0;'

# The total is the number of rows kept on the page.
plant total-not-from-the-list $V testView "$T_RUN" \
  '  r->total = total;' \
  '  r->total = count;'

plant csv-formula-not-neutralised $V testView "$T_OUT" \
  '  int formula = n > 0 && (s[0] == '"'"'='"'"' ||' \
  '  int formula = 0 && (s[0] == '"'"'='"'"' ||'

plant csv-quote-not-doubled $V testView "$T_OUT" \
  '    if (s[i] == '"'"'"'"'"' && buf_str(b, "\"") != 0) {' \
  '    if (0) {'

plant json-not-escaped $V testView "$T_OUT" \
  '    if (c == '"'"'"'"'"' || c == '"'"'\\'"'"') {
      char two[2]' \
  '    if (0) {
      char two[2]'

# The principal argument takes the value a caller names, not the request's own.
plant principal-argument-from-caller $V testView "$T_PRIN" \
  '  if (a->source == GDEFCORE_VIEW_SOURCE_PRINCIPAL) {' \
  '  if (a->source == GDEFCORE_VIEW_SOURCE_PRINCIPAL && c->nparams == 0) {'

# The table that tells an editor what a boolean may be compared with is not what
# the save accepts.
plant operator-table-wrong $V testView "$T_TAB" \
  'static const char * const kOpsBool[] = {"=", "!=", "in", NULL};' \
  'static const char * const kOpsBool[] = {"=", "!=", NULL};'

# A parameter of another size is read as it is.
plant param-size-unchecked $V testView "$T_SIZE" \
  '    if (params[row].size != sizeof params[row]) {' \
  '    if (params[row].size == 0) {'

# A column reads the entity again for itself, so a page costs rows times columns.
plant row-read-per-column $V testView "$T_GREADS" \
  '      if (tree != NULL) {
        rc = column_values(tree, &shapes[col], &texts, &lens, &n);
      }' \
  '      if (tree != NULL) {
        char ** again = NULL;
        size_t * again_lens = NULL;
        size_t again_n = 0;
        (void)gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[row],
            strlen(ids[row]), kLang, 2, c->field, c->field_len, &again, &again_lens, &again_n);
        gdefcore_values_free(catalog, again, again_lens, again_n);
        rc = column_values(tree, &shapes[col], &texts, &lens, &n);
      }'

# Items of every group are counted for a group, not the items of that group.
plant group-items-of-any-path-counted $V testView "$T_GCOLS" \
  '    if (it.path_len != cs->item_path_len ||
        (it.path_len > 0 && memcmp(it.path, cs->item_path, it.path_len) != 0)) {
      continue;
    }
    if (cs->group) {' \
  '    if (it.path_len == 0) {
      continue;
    }
    if (cs->group) {'

# Every value of the item is taken, not the values of the field asked for.
plant nested-leaf-not-matched $V testView "$T_GCOLS" \
  '      if (field_len == cs->leaf_len && memcmp(field, cs->leaf, field_len) == 0) {' \
  '      if (memcmp(field, cs->leaf, 0) == 0) {'

plant group-formatter-allows-join $V testView "$T_GBAD" \
  'static const char * const kFmtCount[] = {"count", NULL};' \
  'static const char * const kFmtCount[] = {"count", "join", NULL};'

# A personal field inside a group is shown as any other.
plant nested-personal-field-shown $V testView "$T_GBAD" \
  '    out->f.type = info.type;
    out->f.personal = info.personal;' \
  '    out->f.type = info.type;
    out->f.personal = 0;'

# A field inside a group can be a sort key.
plant sort-by-nested-field-allowed $V testView "$T_GBAD" \
  '    if (info.depth == 0 && info.path_len == name_len &&' \
  '    if (info.depth < 99 && info.path_len == name_len &&'

# A request that may not edit views writes one.
plant view-authorize-skipped $V testView 'Views.AViewIsWrittenOnlyByARequestThatMayEditViews' \
  '    if (!gdefcore_view_may_edit(gdefcore_changeset_catalog(changeset), request)) {' \
  '    if (0) {'

plant_finish
