#!/bin/sh
#
# The scale gate (storage stories S6b and S10, CAP-S7): core's list, count and
# create at 10,000 entities of one type cost what they cost at 1,000, counted
# in rows and steps, never in time (tests/test_scale.cpp). Runs the Scale
# tests on the real tree, then plants the defect in a COPY of the source by an
# exact text edit and requires the named tests to fail (tools/plant-lib.sh):
#
#   field-index-dropped   the list and count tests of the backend's suite
#
# The backend is the one the tests are given: SQLite in `make test`
# (suite Scale), Postgres in `make test-scale-postgres` with
# GDEFCORE_TEST_SCALE=postgres and a server (suite ScalePostgres, through
# defiant-storage-postgres's tools/pg-test.sh). The control inside both suites,
# a filter on a field nothing indexes, shows the instrument can see a scan;
# the plant shows a declaration that loses its index is seen as one.
#
# Usage: check-scale.sh <make> <build-dir> [make args]

set -u

MAKE="${1:?usage: check-scale.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-scale.sh <make> <build-dir> [make args]}"
shift 2

. tools/plant-lib.sh
plant_setup "$MAKE" "$BUILD_DIR" "$@"

SUITE=Scale
[ "${GDEFCORE_TEST_SCALE:-}" = postgres ] && SUITE=ScalePostgres

plant_control testScale "$SUITE.*"

# The index dropped: core declares every field without the port's indexed
# flag, so no field index is built and a filter on "group" reads the type.
plant field-index-dropped src/entity/store.c testScale \
  "$SUITE.AFilteredListPageReadsItsAnswerNotTheTable $SUITE.ACountReadsItsAnswerNotTheTable" \
  '                (d->indexed && !d->personal ? GDEFSTOR_FIELD_INDEXED : 0u) |' \
  '                0u |'

plant_finish
