/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Defiant Core.
 *
 * Ghoti.io Defiant Core is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version
 * 3 as published by the Free Software Foundation.
 *
 * Ghoti.io Defiant Core is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * One request, one turn, on the calling thread.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <stdio.h>

static GDEFCORE_Turn body(GDEFCORE_Request * request, void * user) {
  size_t len = 0;
  const uint8_t * tenant = gdefcore_request_tenant(request, &len);
  (void)user;
  printf("tenant bytes: %zu, id: %llu\n", len,
      (unsigned long long)gdefcore_request_id(request));
  (void)tenant;
  return GDEFCORE_TURN_DONE;
}

int main(void) {
  const uint8_t tenant[] = {'a'};
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  if (gdefcore_sched_create(NULL, 1, 0, &sched) != GDEFCORE_OK) {
    return 1;
  }
  if (gdefcore_request_create(tenant, 1, 0, 0, NULL, &request) !=
      GDEFCORE_OK) {
    gdefcore_sched_destroy(sched);
    return 1;
  }
  if (gdefcore_sched_spawn(sched, request, body, NULL) != GDEFCORE_OK) {
    gdefcore_request_destroy(request);
    gdefcore_sched_destroy(sched);
    return 1;
  }
  if (gdefcore_sched_run(sched) != GDEFCORE_OK) {
    gdefcore_sched_destroy(sched);
    gdefcore_request_destroy(request);
    return 1;
  }
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
  return 0;
}
