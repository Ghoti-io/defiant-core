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
 * One module, built two ways: this file is the native shared library, and
 * the test process calls the same entry as a guest. Both append ":touched".
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/module.h>

#include "module_example.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EXAMPLE_STR2(x) #x
#define EXAMPLE_STR(x) EXAMPLE_STR2(x)

#if defined(_WIN32) || defined(__CYGWIN__)
#define EXAMPLE_EXPORT __declspec(dllexport)
#else
#define EXAMPLE_EXPORT __attribute__((visibility("default")))
#endif

typedef void (*ExampleDuring)(void);

static ExampleDuring g_during;

EXAMPLE_EXPORT void gdefcore_module_example_set_during(ExampleDuring during) {
  g_during = during;
}

static GDEFCORE_Result example_alter(GDEFCORE_Request * request,
    const void * args, GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out,
    void * user) {
  const char * text = NULL;
  size_t len = 0;
  char buf[4096];
  (void)request;
  (void)args;
  (void)out;
  (void)user;
  if (g_during != NULL) {
    g_during();
  }
  if (gdefcore_alter_text(alter, &text, &len) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (len + 8 >= sizeof buf) {
    return GDEFCORE_ERR_LIMIT;
  }
  memcpy(buf, text, len);
  memcpy(buf + len, ":touched", 8);
  return gdefcore_alter_set(alter, buf, len + 8);
}

static int example_append(char * dst, size_t cap, const char * text, size_t len,
    size_t * out_len) {
  if (dst == NULL || out_len == NULL || (text == NULL && len != 0) ||
      len + 8 >= cap) {
    return -1;
  }
  if (len > 0) {
    memcpy(dst, text, len);
  }
  memcpy(dst + len, ":touched", 8);
  dst[len + 8] = '\0';
  *out_len = len + 8;
  return 0;
}

static const ExampleApi kApi = {example_append};

static const GDEFCORE_Module_Rel kRel = {sizeof(GDEFCORE_Module_Rel),
    GDEFCORE_REL_ENHANCES, "missing", 7};

static const GDEFCORE_Module_Sub kSub = {sizeof(GDEFCORE_Module_Sub),
    "example.alter", 13, GDEFCORE_HOOK_ALTER, 0, 0, NULL, 0, NULL, 0,
    example_alter, NULL};

static const GDEFCORE_Module_Service kSvc = {sizeof(GDEFCORE_Module_Service),
    "example.api", 11, 1, &kApi};

static const char kToken[] = EXAMPLE_STR(GHOTIIO_DEFCORE_NAME);

static const GDEFCORE_Module_Manifest kManifest = {sizeof(GDEFCORE_Module_Manifest),
    kToken, sizeof kToken - 1, "example", 7, "Example", 7, &kRel, 1, &kSub, 1,
    &kSvc, 1};

EXAMPLE_EXPORT const GDEFCORE_Module_Manifest * gdefcore_module_manifest(void) {
  return &kManifest;
}

#ifdef __cplusplus
}
#endif
