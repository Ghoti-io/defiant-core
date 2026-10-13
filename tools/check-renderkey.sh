#!/bin/sh
#
# The same-grants-two-principals gate (AD-25): where "own" makes two
# principals' output differ, their render keys differ.
#
# Plants "render key without the principal" in the library source (a COPY of
# it, by an exact text edit) and requires both the long-standing
# Access.RenderKey and the output-level Principals.OwnOutputDiffers to fail by
# name. The older plant in check-access.sh strips the principal in a test
# helper and leaves the library alone; this one changes the key derivation.
#
# Usage: check-renderkey.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-lib.sh"
plant_setup "$@"

plant_control testAccess 'Access.RenderKey'
plant_control testReadpaths 'Principals.OwnOutputDiffers'

plant render-key-without-principal-access src/access/access.c testAccess \
  'Access.RenderKey' \
  '    ADD_KEY(principal_text, principal_text_len);' \
  '    ADD_KEY("-", 1); (void)principal_text; (void)principal_text_len;'

plant render-key-without-principal-output src/access/access.c testReadpaths \
  'Principals.OwnOutputDiffers' \
  '    ADD_KEY(principal_text, principal_text_len);' \
  '    ADD_KEY("-", 1); (void)principal_text; (void)principal_text_len;'

plant_finish
