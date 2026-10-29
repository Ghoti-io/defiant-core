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

/*
 * The declared tables (story 5 of the site-admin epic). The handler runs for
 * the routes below; it owns the request, and records the capture `id` and its
 * own data pointer, so a test can see that the call reached this function
 * with both whether the module was loaded natively or handed over as a guest.
 */
static const char kHandlerData[] = "example-handler-data";

static void example_route(const GDEFCORE_Route_Call * call) {
  const char * id = NULL;
  size_t id_len = 0;
  gdefcore_request_set_resolution(call->request, call->machine,
      call->machine_len);
  if (gdefcore_route_call_capture(call, "id", 2, &id, &id_len)) {
    gdefcore_request_set_note(call->request, "example.id", 10, id, id_len);
  }
  gdefcore_request_set_note(call->request, "example.data", 12,
      (const char *)call->data, strlen((const char *)call->data));
}

static GDEFCORE_Result example_count(GDEFCORE_Request * request, void * user,
    GDEFCORE_Contribution_Value * out) {
  (void)request;
  (void)user;
  out->kind = GDEFCORE_CONTRIBUTION_INTEGER;
  out->integer = 42;
  return GDEFCORE_OK;
}

static const GDEFCORE_Module_Route_Handler kHandler = {
    sizeof(GDEFCORE_Module_Route_Handler), example_route,
    (void *)kHandlerData};

static const GDEFCORE_Module_Variable_Provider kProvider = {
    sizeof(GDEFCORE_Module_Variable_Provider), example_count, NULL};

#define XS(text) text, sizeof(text) - 1

static const GDEFCORE_Module_Service kSvcs[] = {
    {sizeof(GDEFCORE_Module_Service), XS("example.api"), 1, &kApi},
    {sizeof(GDEFCORE_Module_Service), XS("example.handler"),
        GDEFCORE_MODULE_ROUTE_HANDLER_VERSION, &kHandler},
    {sizeof(GDEFCORE_Module_Service), XS("example.provider"),
        GDEFCORE_MODULE_VARIABLE_PROVIDER_VERSION, &kProvider}};

static const GDEFCORE_Module_Route kRoutes[] = {
    {sizeof(GDEFCORE_Module_Route), XS("example.settings"), XS("/admin/example"),
        0, 0, XS("administer example"), XS("Example settings"),
        GDEFCORE_ROUTE_PAGE, NULL, 0, 0, 1, XS("example.handler"), NULL, 0},
    {sizeof(GDEFCORE_Module_Route), XS("example.node.view"),
        XS("/example/:id/view"), 0, 0, XS("view example"), XS("View"),
        GDEFCORE_ROUTE_TAB,
        XS("example.node"), 1, 0, XS("example.handler"), NULL, 0},
    {sizeof(GDEFCORE_Module_Route), XS("example.node.edit"),
        XS("/example/:id/edit"), 0, 0, XS("edit example"), XS("Edit"),
        GDEFCORE_ROUTE_TAB, XS("example.node"), 0, 0, XS("example.handler"), NULL, 0},
    {sizeof(GDEFCORE_Module_Route), XS("example.node"), XS("/example/:id"), 0,
        0, XS("view example"), XS("Example"), GDEFCORE_ROUTE_PAGE, NULL, 0, 0,
        0, XS("example.handler"), NULL, 0},
    {sizeof(GDEFCORE_Module_Route), XS("example.add"), XS("/example/add"), 0, 0,
        XS("add example"), XS("Add example"), GDEFCORE_ROUTE_ACTION, NULL, 0, 0,
        0, XS("example.handler"), NULL, 0}};

static const GDEFCORE_Module_Link kLinks[] = {
    {sizeof(GDEFCORE_Module_Link), XS("example.link.home"), XS("main"),
        XS("Example"), XS("example.node"), 0, NULL, 0, GDEFCORE_ROUTE_PAGE},
    {sizeof(GDEFCORE_Module_Link), XS("example.link.edit"), XS("main"),
        XS("Edit example"), XS("example.node.edit"), 1, XS("example.link.home"),
        GDEFCORE_ROUTE_TAB},
    {sizeof(GDEFCORE_Module_Link), XS("example.link.admin"), XS("admin"),
        XS("Example"), XS("example.settings"), 5, NULL, 0,
        GDEFCORE_ROUTE_PAGE}};

static const GDEFCORE_Module_Setting kSettings[] = {
    {sizeof(GDEFCORE_Module_Setting), XS("example.limit"), XS("number"),
        XS("10"), XS("Limit"), XS("How many to show."), 0, XS("general"), NULL, 0, NULL, 0, 0, 0},
    {sizeof(GDEFCORE_Module_Setting), XS("example.key"), XS("text"), NULL, 0,
        XS("Key"), XS("An API key, local to this site."), 1, XS("keys"), NULL, 0, NULL, 0, 0, 0},
    {sizeof(GDEFCORE_Module_Setting), XS("example.greeting"), XS("text"),
        XS("hello"), XS("Greeting"), NULL, 0, 0, NULL, 0, NULL, 0, NULL, 0, 0, 0}};

static const GDEFCORE_Module_Variable kVariables[] = {
    {sizeof(GDEFCORE_Module_Variable), XS("core.page"), XS("example.count"),
        XS("number"), XS("How many examples."), XS("example.provider"), 1}};

static const char kToken[] = EXAMPLE_STR(GHOTIIO_DEFCORE_NAME);

static const GDEFCORE_Module_Manifest kManifest = {sizeof(GDEFCORE_Module_Manifest),
    kToken, sizeof kToken - 1, "example", 7, "Example", 7, &kRel, 1, &kSub, 1,
    kSvcs, 3, NULL, 0, kRoutes, 5, kLinks, 3, kSettings, 3, kVariables, 1, NULL, 0, NULL, 0, 1, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0};

EXAMPLE_EXPORT const GDEFCORE_Module_Manifest * gdefcore_module_manifest(void) {
  return &kManifest;
}

#ifdef __cplusplus
}
#endif
