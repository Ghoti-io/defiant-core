#!/bin/sh
#
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (C) 2026 Corey Pennycuff
# This file is part of Ghoti.io Defiant Core.
#
# The bus-as-accelerator gate (AD-25, AD-31).
#
# tests/test_bus.cpp runs several nodes over one store with a bus that drops,
# duplicates and reorders, and requires each node to serve the committed epoch:
# the configuration it runs, the key its fragments are cached under, and the
# sessions it admits. defiant-core has no bus, so this plants the defect the
# row names, "a node that trusts the bus for its epoch", the way it would
# appear in this code: a node that remembers the epoch it read and goes on
# believing it until told otherwise, and the bus is where it would be told.
# Each plant is an exact edit of a scratch copy at the real read site, and the
# test named for it must fail.
#
#   epoch-remembered      gdefcore_epoch returns the first epoch a catalog saw
#   chain-served-stale    a compiled hook chain is found without its epoch
#   session-epoch-trusted a session check reads the account epoch once per
#                         catalog and believes it afterwards
#
# Usage: check-bus.sh <make> <build-dir> [make args]

set -u
. "$(dirname "$0")/plant-fibers.sh"
pl_init "$@"
L=check-bus
EXE=testBus
GATE='Bus.*'

pl_control "$EXE" "$GATE" "$L"

pl_plant "$L" epoch-remembered src/entity/entity.c "$EXE" "$GATE" \
  'Bus.ConfigEpoch Bus.FragmentKey' \
  '  if (catalog == NULL || out_epoch == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return read_epoch(catalog, out_epoch);' \
  '  static GDEFCORE_Catalog * seen_catalog[16];
  static uint64_t seen_epoch[16];
  GDEFCORE_Result read;
  size_t slot = 0;
  if (catalog == NULL || out_epoch == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  while (slot < 16 && seen_catalog[slot] != NULL && seen_catalog[slot] != catalog) {
    slot += 1;
  }
  if (slot < 16 && seen_catalog[slot] == catalog) {
    *out_epoch = seen_epoch[slot];
    return GDEFCORE_OK;
  }
  read = read_epoch(catalog, out_epoch);
  if (read == GDEFCORE_OK && slot < 16) {
    seen_catalog[slot] = catalog;
    seen_epoch[slot] = *out_epoch;
  }
  return read;'

pl_plant "$L" chain-served-stale src/module/module.c "$EXE" "$GATE" \
  'Bus.ConfigEpoch' \
  '    if (!chain->used || chain->epoch != epoch || chain->tenant_len != tenant_len ||' \
  '    if (!chain->used || ((void)epoch, 0) || chain->tenant_len != tenant_len ||'

pl_plant "$L" session-epoch-trusted src/account/account.c "$EXE" "$GATE" \
  'Bus.SessionEpoch' \
  '  rc = load_epoch(catalog, account, epoch_id, &current);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (token_epoch != current) {' \
  '  {
    static GDEFCORE_Catalog * seen_catalog[16];
    static uint64_t seen_epoch[16];
    size_t slot = 0;
    while (slot < 16 && seen_catalog[slot] != NULL && seen_catalog[slot] != catalog) {
      slot += 1;
    }
    if (slot < 16 && seen_catalog[slot] == catalog) {
      current = seen_epoch[slot];
      rc = GDEFCORE_OK;
    } else {
      rc = load_epoch(catalog, account, epoch_id, &current);
      if (rc == GDEFCORE_OK && slot < 16) {
        seen_catalog[slot] = catalog;
        seen_epoch[slot] = current;
      }
    }
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (token_epoch != current) {'

pl_finish "$L"
