#!/bin/sh
#
# The render-safe-output gate (site-admin story 1): a value bound into a
# template is inert without the template calling anything, url() refuses
# script schemes, and the one trusted insertion (a pane's rendered HTML
# pasted by the layout) is neither escaped twice nor opened up.
#
# Runs the SafeOut tests on the real tree, then plants each defect in a COPY
# of the source by an exact text edit and requires the named tests to fail:
#
#   SafeOut.ForgottenCall        a template that calls no tag method
#   SafeOut.AttributeDoubleQuoted / AttributeSingleQuoted
#   SafeOut.HostileEverywhere    the hostile table, in text and both quote styles
#   SafeOut.BuiltinPost / BuiltinRecent / BuiltinField   the built-in templates
#   SafeOut.UrlRows              each url() row of the matrix
#   SafeOut.RegionNotDoubleEscaped  a pane's markup arrives once-escaped
#
# Every test has a control (the same template with .raw, which does leak), so
# a plant turning one red is a test seeing the defect, not a build failure.
#
# Usage: check-safeout.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testSafeout 'SafeOut.*'

# Plant 1: user values bound as TRUSTED again, the way they were.
plant bind-trusted src/render/render.c testSafeout \
  'SafeOut.ForgottenCall SafeOut.AttributeDoubleQuoted SafeOut.AttributeSingleQuoted SafeOut.HostileEverywhere SafeOut.BuiltinPost SafeOut.BuiltinRecent SafeOut.BuiltinField' \
  '            job->binds[i].len, GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE) !=' \
  '            job->binds[i].len, GLTANG_UNICODE_STRING_TYPE_TRUSTED) !='

# Plant 1b: the plain HTML tag, which does not escape a quote in an attribute.
plant bind-plain-html src/render/render.c testSafeout \
  'SafeOut.AttributeDoubleQuoted SafeOut.AttributeSingleQuoted SafeOut.HostileEverywhere' \
  '            job->binds[i].len, GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE) !=' \
  '            job->binds[i].len, GLTANG_UNICODE_STRING_TYPE_HTML) !='

# Plant 2: url() returns its argument unchanged.
plant url-passes-through src/render/render.c testSafeout \
  'SafeOut.UrlRows' \
  '  if (text == NULL || !url_allowed(text, n)) {' \
  '  if (text == NULL) {'

# Plant 3: the region paste is returned tagged, so it is escaped a second time.
plant region-escaped-twice src/render/render.c testSafeout \
  'SafeOut.RegionNotDoubleEscaped' \
  '      gltang_call_return_string(call, html, set->slots[i].html_len,
          GLTANG_UNICODE_STRING_TYPE_TRUSTED);' \
  '      gltang_call_return_string(call, html, set->slots[i].html_len,
          GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE);'

plant_finish
