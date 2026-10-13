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
 * The cross-tenant gate (AD-25), defiant-core's part: two tenants on one store,
 * one module host and one route table, interleaved call by call. Every route
 * the library resolves (a handler, an alias, the front page, a post page, the
 * recent-posts View, a list) is asked as tenant A and as tenant B in turn, and
 * each answer must carry its own tenant's content and none of the other's.
 *
 * Tenant.RenderKeyCarriesTenant and Tenant.HookChainsAreKeptPerTenant are the
 * compiled artifacts: the render key a cache is keyed by, and the hook chain
 * the host builds and keeps. Each is checked at an epoch the two tenants
 * share, because a key that includes the epoch hides a missing tenant until
 * the epochs happen to agree.
 *
 * Out of scope here, and owned by the web layer: a connection pool, a token at
 * a transport, MCP tools. Not covered anywhere in defiant-core: a request
 * created for one tenant and handed the other tenant's catalog (the library
 * does not compare them outside hook_fire; callers choose the catalog from
 * the request).
 */

#include "gate_fixture.h"

#define MODULE_STR2(x) #x
#define MODULE_STR(x) MODULE_STR2(x)

namespace {

using namespace gate;

const char kCoreToken[] = MODULE_STR(GHOTIIO_DEFCORE_NAME);

GDEFCORE_Module_Manifest g_man;
GDEFCORE_Module_Sub g_sub;
const GDEFCORE_Module_Manifest * g_current;

extern "C" const GDEFCORE_Module_Manifest * TestGuest(void) {
  return g_current;
}

extern "C" GDEFCORE_Result Count(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  (void)request;
  (void)args;
  (void)alter;
  (void)out;
  *(int *)user += 1;
  return GDEFCORE_OK;
}

void InstallCounter(GDEFCORE_Host * host, const char * name, const char * hook,
    int * counter) {
  memset(&g_man, 0, sizeof g_man);
  memset(&g_sub, 0, sizeof g_sub);
  g_sub.size = sizeof g_sub;
  g_sub.hook = hook;
  g_sub.hook_len = strlen(hook);
  g_sub.kind = GDEFCORE_HOOK_EVENT;
  g_sub.fn = Count;
  g_sub.user = counter;
  g_man.size = sizeof g_man;
  g_man.core_token = kCoreToken;
  g_man.core_token_len = strlen(kCoreToken);
  g_man.name = name;
  g_man.name_len = strlen(name);
  g_man.label = name;
  g_man.label_len = strlen(name);
  g_man.subs = &g_sub;
  g_man.nsubs = 1;
  g_current = &g_man;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host, TestGuest));
}

void EnableModule(GDEFCORE_Host * host, Site * site, const char * name) {
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Request * request = site->NewRequest();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(site->catalog, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_enable(host, changeset, name, strlen(name)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_apply(changeset, name, strlen(name)));
  gdefcore_changeset_destroy(changeset);
  gdefcore_request_destroy(request);
}

/* Two tenants, built by one recipe so their epochs agree. */
struct Two {
  GDEFSTOR_Store * store = NULL;
  Site s[2];
  GDEFCORE_Host * host = NULL;
  GDEFCORE_Routes * routes = NULL;
  std::string tag[2] = {"ALPHA", "BRAVO"};
  std::string shared[2];   ///< the post at "/shared", per tenant
  std::string only[2];     ///< the post at "/only-x", per tenant
  int alpha_calls = 0;
  int other_calls = 0;

  static void GoShared(GDEFCORE_Request * request, const char * machine,
      size_t machine_len, void * data) {
    Two * two = (Two *)data;
    size_t n = 0;
    const uint8_t * tenant = gdefcore_request_tenant(request, &n);
    int which = (n == 1 && tenant[0] == 'B') ? 1 : 0;
    (void)machine;
    (void)machine_len;
    gdefcore_request_set_resolution(request, two->shared[which].data(),
        two->shared[which].size());
  }

  /* The other tenant's id: a handler that is handed an id from elsewhere. */
  static void GoOther(GDEFCORE_Request * request, const char * machine,
      size_t machine_len, void * data) {
    Two * two = (Two *)data;
    size_t n = 0;
    const uint8_t * tenant = gdefcore_request_tenant(request, &n);
    int which = (n == 1 && tenant[0] == 'B') ? 1 : 0;
    (void)machine;
    (void)machine_len;
    gdefcore_request_set_resolution(request, two->shared[1 - which].data(),
        two->shared[1 - which].size());
  }

  void Open() {
    char * err = NULL;
    size_t err_len = 0;
    int i;
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store, NULL, &host));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_route_add(routes, "go-shared", 9, "/go/shared", 10, 0, 0,
            GoShared, this, &err, &err_len));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_route_add(routes, "go-other", 8, "/go/other", 9, 0, 0, GoOther,
            this, &err, &err_len));
    for (i = 0; i < 2; i++) {
      Site & site = s[i];
      std::string only_alias = i == 0 ? "/only-a" : "/only-b";
      site.Open(store, i == 0 ? "A" : "B", (uint8_t)(0x41 + i));
      gdefcore_catalog_bind_host(site.catalog, host);
      site.InstallKit();
      site.Login();
      shared[i] = site.Post("/shared", (tag[i] + "-shared").c_str(),
          (tag[i] + "-shared-body").c_str(), true);
      only[i] = site.Post(only_alias.c_str(), (tag[i] + "-only").c_str(),
          (tag[i] + "-only-body").c_str(), true);
    }
    InstallCounter(host, "alpha", "demo.x", &alpha_calls);
    EnableModule(host, &s[0], "alpha");
    InstallCounter(host, "other", "demo.y", &other_calls);
    EnableModule(host, &s[1], "other");
  }

  void Close() {
    int i;
    gdefcore_routes_destroy(routes);
    for (i = 0; i < 2; i++) {
      gdefcore_catalog_bind_host(s[i].catalog, NULL);
    }
    gdefcore_host_destroy(host);
    for (i = 0; i < 2; i++) {
      s[i].Close();
    }
    gdefstor_store_destroy(store);
  }
};

std::string Page(Site & site, GDEFCORE_Routes * routes,
    GDEFCORE_Request * request, const std::string & path, GDEFCORE_Result * rc) {
  char * bytes = NULL;
  size_t n = 0;
  std::string out;
  *rc = gdefcore_render_page(site.catalog, routes, request, path.data(),
      path.size(), GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
  if (*rc == GDEFCORE_OK && bytes != NULL) {
    out.assign(bytes, n);
  }
  gdefcore_text_free(site.catalog, bytes);
  return out;
}

std::string Resolve(Site & site, GDEFCORE_Routes * routes,
    GDEFCORE_Request * request, const std::string & path, GDEFCORE_Result * rc) {
  char * text = NULL;
  size_t n = 0;
  std::string out;
  *rc = gdefcore_form_resolve(routes, site.catalog, request, path.data(),
      path.size(), &text, &n);
  if (*rc == GDEFCORE_OK && text != NULL) {
    out.assign(text, n);
  }
  gdefcore_text_free(site.catalog, text);
  return out;
}

std::string Key(Site & site, GDEFCORE_Request * request) {
  char * key = NULL;
  size_t n = 0;
  std::string out;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_access_render_key(site.catalog, request, NULL, 0, NULL, 0, &key,
          &n));
  if (key != NULL) {
    out.assign(key, n);
  }
  gdefcore_text_free(site.catalog, key);
  return out;
}

std::vector<std::string> Listed(Site & site, GDEFCORE_Request * request) {
  GDEFCORE_Access_List q;
  char ** ids = NULL;
  size_t count = 0;
  std::vector<std::string> out;
  size_t i;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.type_name = "site.post";
  q.type_name_len = 9;
  q.lang = "en";
  q.lang_len = 2;
  q.sort_field = "title";
  q.sort_field_len = 5;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_access_list(site.catalog, request, &q, &ids, &count));
  for (i = 0; i < count; i++) {
    out.push_back(ids[i]);
  }
  gdefcore_access_free(site.catalog, ids, count);
  return out;
}

bool Has(const std::string & text, const std::string & what) {
  return text.find(what) != std::string::npos;
}

}  // namespace

TEST(Tenant, Interleaved) {
  Two two;
  int round;
  int i;
  two.Open();
  /* Each tenant is asked on its own request, anonymous (the kit grants
   * anonymous read of posts), and again as a principal with no grants. */
  for (round = 0; round < 3; round++) {
    for (i = 0; i < 2; i++) {
      Site & site = two.s[i];
      int j = 1 - i;
      const std::string & mine = two.tag[i];
      const std::string & theirs = two.tag[j];
      std::string who = site.Principal();
      GDEFCORE_Request * anon = site.NewRequest();
      GDEFCORE_Request * none = site.NewRequest(who);
      GDEFCORE_Result rc;
      std::string page;
      std::string id;
      std::vector<std::string> ids;
      /* The front page and its recent-posts View. */
      page = Page(site, two.routes, anon, "/", &rc);
      EXPECT_EQ(GDEFCORE_OK, rc) << "round " << round << " tenant " << i;
      EXPECT_TRUE(Has(page, mine + "-shared")) << page;
      EXPECT_TRUE(Has(page, mine + "-only")) << page;
      EXPECT_FALSE(Has(page, theirs)) << "tenant " << i << " page shows " << theirs;
      /* The same path, in both tenants, with different content. */
      page = Page(site, two.routes, anon, "/shared", &rc);
      EXPECT_EQ(GDEFCORE_OK, rc);
      EXPECT_TRUE(Has(page, mine + "-shared-body")) << page;
      EXPECT_FALSE(Has(page, theirs)) << page;
      id = Resolve(site, two.routes, anon, "/shared", &rc);
      EXPECT_EQ(GDEFCORE_OK, rc);
      EXPECT_EQ(two.shared[i], id);
      EXPECT_NE(two.shared[j], id);
      /* A path only the other tenant has. */
      Page(site, two.routes, anon, i == 0 ? "/only-b" : "/only-a", &rc);
      EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
      Resolve(site, two.routes, anon, i == 0 ? "/only-b" : "/only-a", &rc);
      EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
      Page(site, two.routes, anon, i == 0 ? "/only-a" : "/only-b", &rc);
      EXPECT_EQ(GDEFCORE_OK, rc);
      /* A route handler, asked as this tenant. */
      id = Resolve(site, two.routes, anon, "/go/shared", &rc);
      EXPECT_EQ(GDEFCORE_OK, rc);
      EXPECT_EQ(two.shared[i], id);
      page = Page(site, two.routes, anon, "/go/shared", &rc);
      EXPECT_EQ(GDEFCORE_OK, rc);
      EXPECT_FALSE(Has(page, theirs)) << page;
      /* A route handler that hands over the other tenant's id: the id is
       * not an entity here. */
      Page(site, two.routes, anon, "/go/other", &rc);
      EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
      Page(site, two.routes, none, "/go/other", &rc);
      EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
      /* The other tenant's ids, by read, list and unfiltered index. */
      {
        char ** texts = NULL;
        size_t * lens = NULL;
        size_t n = 0;
        char ** all = NULL;
        size_t count = 0;
        size_t k;
        EXPECT_EQ(GDEFCORE_ERR_INVALID,
            gdefcore_access_read(site.catalog, anon, two.shared[j].data(),
                two.shared[j].size(), "en", 2, "title", 5, &texts, &lens, &n));
        EXPECT_EQ(GDEFCORE_ERR_INVALID,
            gdefcore_entity_values(site.catalog, NULL, GDEFCORE_VIEW_PUBLISHED,
                two.shared[j].data(), two.shared[j].size(), "en", 2, "title", 5,
                &texts, &lens, &n));
        ids = Listed(site, anon);
        ASSERT_EQ(2u, ids.size());
        EXPECT_TRUE((ids[0] == two.shared[i] && ids[1] == two.only[i]) ||
                    (ids[1] == two.shared[i] && ids[0] == two.only[i]));
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_entity_ids(site.catalog, "site.post", 9, &all, &count));
        EXPECT_EQ(2u, count);
        for (k = 0; k < count; k++) {
          EXPECT_NE(two.shared[j], all[k]);
          EXPECT_NE(two.only[j], all[k]);
        }
        gdefcore_ids_free(site.catalog, all, count);
        /* A principal with nothing: nothing in either tenant. */
        EXPECT_TRUE(Listed(site, none).empty());
      }
      /* A session minted for the other tenant is refused here. */
      {
        GDEFCORE_Request * probe = site.NewRequest();
        EXPECT_NE(GDEFCORE_OK,
            gdefcore_account_check(site.catalog, probe, site.keyring, site.root,
                sizeof site.root, two.s[j].session.data(),
                two.s[j].session.size()));
        gdefcore_request_destroy(probe);
      }
      gdefcore_request_destroy(anon);
      gdefcore_request_destroy(none);
    }
  }
  two.Close();
}

TEST(Tenant, RenderKeyCarriesTenant) {
  /* The same principal state (anonymous), the same grants, the same epoch:
   * the only thing left to tell the two keys apart is the tenant. */
  Two two;
  uint64_t ea = 0;
  uint64_t eb = 0;
  GDEFCORE_Request * a;
  GDEFCORE_Request * b;
  std::string ka;
  std::string kb;
  two.Open();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(two.s[0].catalog, &ea));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(two.s[1].catalog, &eb));
  ASSERT_EQ(ea, eb) << "the precondition of this test: both tenants at one epoch";
  a = two.s[0].NewRequest();
  b = two.s[1].NewRequest();
  ka = Key(two.s[0], a);
  kb = Key(two.s[1], b);
  EXPECT_NE(ka, kb) << "two tenants at one epoch share a render key:\n" << ka;
  EXPECT_TRUE(Has(ka, "tenant:41\n")) << ka;
  EXPECT_TRUE(Has(kb, "tenant:42\n")) << kb;
  gdefcore_request_destroy(a);
  gdefcore_request_destroy(b);
  two.Close();
}

TEST(Tenant, HookChainsAreKeptPerTenant) {
  /* Module "alpha" subscribes to demo.x and is enabled for tenant A only.
   * The host builds a chain per tenant and keeps it; interleaved fires must
   * call alpha for A and never for B, at an epoch both tenants share. */
  Two two;
  uint64_t ea = 0;
  uint64_t eb = 0;
  int round;
  GDEFCORE_Request * a;
  GDEFCORE_Request * b;
  int on = 99;
  two.Open();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(two.s[0].catalog, &ea));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(two.s[1].catalog, &eb));
  ASSERT_EQ(ea, eb) << "the precondition of this test: both tenants at one epoch";
  a = two.s[0].NewRequest();
  b = two.s[1].NewRequest();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_enabled(two.host, a, "alpha", 5, &on));
  EXPECT_EQ(1, on);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_enabled(two.host, b, "alpha", 5, &on));
  EXPECT_EQ(0, on);
  for (round = 1; round <= 3; round++) {
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_hook_fire(two.host, a, two.s[0].catalog, "demo.x", 6,
            GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
    EXPECT_EQ(round, two.alpha_calls);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_hook_fire(two.host, b, two.s[1].catalog, "demo.x", 6,
            GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
    EXPECT_EQ(round, two.alpha_calls)
        << "tenant B ran a subscriber that is enabled for tenant A only";
  }
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(two.host, b, two.s[1].catalog, "demo.y", 6,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
  EXPECT_EQ(1, two.other_calls);
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(two.host, a, two.s[0].catalog, "demo.y", 6,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
  EXPECT_EQ(1, two.other_calls)
      << "tenant A ran a subscriber that is enabled for tenant B only";
  /* A request for one tenant on the other's catalog is refused outright. */
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_hook_fire(two.host, a, two.s[1].catalog, "demo.x", 6,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
  gdefcore_request_destroy(a);
  gdefcore_request_destroy(b);
  two.Close();
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
