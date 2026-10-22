#!/bin/sh
#
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (C) 2026 Corey Pennycuff
# This file is part of Ghoti.io Defiant Core.
#
# Sourced by the check-*.sh gates that plant a defect in the source. It loads
# the helpers they share with the other Defiant libraries: defiant-storage
# installs plant-lib.sh with its conformance suites, and the Makefile names the
# file in GHOTI_PLANT_LIB. There is no copy here to keep in step.

PLANT_LIB="${GHOTI_PLANT_LIB:-}"
if [ ! -r "$PLANT_LIB" ]; then
  printf '%s: defiant-storage installs the plant helpers (plant-lib.sh) with its conformance suites and none was found at "%s": install defiant-storage first, then run this through make (GHOTI_PLANT_LIB names the file)\n' \
    "$(basename "$0")" "$PLANT_LIB" >&2
  exit 1
fi
. "$PLANT_LIB"
if ! command -v plant_spawn > /dev/null 2>&1; then
  printf '%s: the plant helpers at "%s" are older than this gate needs (no plant_spawn): install defiant-storage again from this checkout\n' \
    "$(basename "$0")" "$PLANT_LIB" >&2
  exit 1
fi
