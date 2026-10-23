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
 * Template kinds, layered contracts and validation (site-admin story 2).
 *
 * Every assertion that something is refused or absent has a control: the same
 * input in the shape that is accepted, or present, so a test that cannot see
 * the thing it looks for is not passing by accident.
 */

#include <ghoti.io/cutil/fiber.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include "size_structs.h"

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <functional>
#include <string>
#include <vector>

#define TPL_STR2(x) #x
#define TPL_STR(x) TPL_STR2(x)

namespace {

const char kCoreToken[] = TPL_STR(GHOTIIO_DEFCORE_NAME);

/* Test modules: each needs an entry of its own. */
GDEFCORE_Module_Manifest g_man[4];
const char * g_names[4] = {"m", "n", "a", "b"};

template <int I>
const GDEFCORE_Module_Manifest * Entry() {
  return &g_man[I];
}
extern "C" const GDEFCORE_Module_Manifest * Entry0(void) { return Entry<0>(); }
extern "C" const GDEFCORE_Module_Manifest * Entry1(void) { return Entry<1>(); }
extern "C" const GDEFCORE_Module_Manifest * Entry2(void) { return Entry<2>(); }
extern "C" const GDEFCORE_Module_Manifest * Entry3(void) { return Entry<3>(); }
GDEFCORE_Module_Entry g_entries[4] = {Entry0, Entry1, Entry2, Entry3};

/* A contribution's provider and what it saw. */
struct Probe {
  int calls = 0;
  int kind = GDEFCORE_CONTRIBUTION_INTEGER;
  std::string text = "seven";
  int64_t integer = 7;
  GDEFCORE_Request * last = NULL;
  bool set_size = false; /* answer in a block of this size instead */
  size_t size_value = 0;
};

extern "C" GDEFCORE_Result Provide(GDEFCORE_Request * request, void * user,
    GDEFCORE_Contribution_Value * out) {
  Probe * p = (Probe *)user;
  p->calls += 1;
  p->last = request;
  if (p->set_size) {
    out->size = p->size_value;
  }
  out->kind = p->kind;
  out->text = p->text.c_str();
  out->text_len = p->text.size();
  out->integer = p->integer;
  return GDEFCORE_OK;
}

struct Issue {
  int reason;
  int line;
  std::string name;
  std::string message;
};

void OneValue(GDEFCORE_Value * value, const char * field, const char ** slot,
    size_t * len_slot, size_t count = 1) {
  memset(value, 0, sizeof *value);
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = slot;
  value->text_lens = len_slot;
  value->count = count;
}

class Templates : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  GDEFCORE_Host * host_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  GDEFCORE_Request * anon_ = NULL;
  Probe probe_;
  std::string refusal_;

  void SetUp() override {
    const uint8_t tenant[] = {'t'};
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, tenant, 1, NULL, NULL, &catalog_));
    gdefcore_catalog_bind_host(catalog_, host_);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant, 1, 0, 0, NULL, &anon_));
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
  }

  void TearDown() override {
    gdefcore_request_destroy(anon_);
    gdefcore_catalog_bind_host(catalog_, NULL);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_host_destroy(host_);
    gdefstor_store_destroy(store_);
  }

  /* Modules ------------------------------------------------------------ */

  void Install(int slot) {
    memset(&g_man[slot], 0, sizeof g_man[slot]);
    g_man[slot].size = sizeof g_man[slot];
    g_man[slot].core_token = kCoreToken;
    g_man[slot].core_token_len = strlen(kCoreToken);
    g_man[slot].schema_version = 1;
    g_man[slot].name = g_names[slot];
    g_man[slot].name_len = strlen(g_names[slot]);
    g_man[slot].label = g_names[slot];
    g_man[slot].label_len = strlen(g_names[slot]);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_module_install_guest(host_, g_entries[slot]));
  }

  GDEFCORE_Result Contribute(const char * module, const char * kind,
      const char * name, const char * type, Probe * probe, int principal_free,
      int weight = 0, const char * before = NULL, const char * after = NULL) {
    GDEFCORE_Module_Contribution c;
    memset(&c, 0, sizeof c);
    c.size = sizeof c;
    c.kind = kind;
    c.kind_len = strlen(kind);
    c.name = name;
    c.name_len = strlen(name);
    c.type = type;
    c.type_len = strlen(type);
    c.description = "a count";
    c.description_len = 7;
    c.provider = Provide;
    c.user = probe;
    c.principal_free = principal_free;
    c.weight = weight;
    c.before = before;
    c.before_len = before == NULL ? 0 : strlen(before);
    c.after = after;
    c.after_len = after == NULL ? 0 : strlen(after);
    return gdefcore_module_contribute(host_, module, strlen(module), &c);
  }

  GDEFCORE_Result ModuleOp(const char * name, bool enable) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc =
        gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = enable ? gdefcore_module_enable(host_, cs, name, strlen(name))
                : gdefcore_module_disable(host_, cs, name, strlen(name));
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, name, strlen(name));
    }
    SaveRefusal(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  void SaveRefusal(GDEFCORE_Changeset * cs) {
    size_t n = 0;
    const char * r = gdefcore_changeset_refusal(cs, &n);
    refusal_.assign(r == NULL ? "" : r, n);
  }

  /* Entities ------------------------------------------------------------ */

  bool Find(const char * type, const char * name,
      char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
    char ** ids = NULL;
    size_t n = 0;
    bool have = false;
    if (gdefcore_entity_ids(catalog_, type, strlen(type), &ids, &n) !=
        GDEFCORE_OK) {
      return false;
    }
    for (size_t i = 0; i < n && !have; i++) {
      char ** vals = NULL;
      size_t * lens = NULL;
      size_t c = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              strlen(ids[i]), "en", 2, "name", 4, &vals, &lens, &c) ==
          GDEFCORE_OK) {
        if (c > 0 && lens[0] == strlen(name) &&
            memcmp(vals[0], name, lens[0]) == 0) {
          memcpy(id, ids[i], strlen(ids[i]) + 1);
          have = true;
        }
        gdefcore_values_free(catalog_, vals, lens, c);
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    return have;
  }

  std::string Field(const char * type, const char * name, const char * field) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    std::string out = "!";
    if (!Find(type, name, id)) {
      return out;
    }
    char ** vals = NULL;
    size_t * lens = NULL;
    size_t c = 0;
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id,
            GDEFCORE_PUBLIC_ID_LEN, "en", 2, field, strlen(field), &vals, &lens,
            &c) == GDEFCORE_OK) {
      out = c > 0 ? std::string(vals[0], lens[0]) : "";
      gdefcore_values_free(catalog_, vals, lens, c);
    }
    return out;
  }

  /* Save a template (new or existing) by changeset and apply it. */
  GDEFCORE_Result SaveTemplate(const char * name, const std::string & body,
      const char * kind, GDEFCORE_Changeset ** keep = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * slots[3] = {name, body.c_str(), kind};
    size_t lens[3] = {strlen(name), body.size(), strlen(kind)};
    GDEFCORE_Result rc;
    if (!Find("core.template", name, id)) {
      rc = gdefcore_entity_create(catalog_, "core.template", 13, id, NULL);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
    OneValue(&values[0], "name", &slots[0], &lens[0]);
    OneValue(&values[1], "body", &slots[1], &lens[1]);
    OneValue(&values[2], "kind", &slots[2], &lens[2]);
    rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 3);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, "core.template", 13);
    }
    SaveRefusal(cs);
    if (keep != NULL) {
      *keep = cs;
    } else {
      gdefcore_changeset_destroy(cs);
    }
    return rc;
  }

  /* A changeset that saves a template and is not applied. */
  GDEFCORE_Changeset * StageTemplate(const char * name, const std::string & body,
      const char * kind) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * slots[3] = {name, body.c_str(), kind};
    size_t lens[3] = {strlen(name), body.size(), strlen(kind)};
    if (!Find("core.template", name, id) &&
        gdefcore_entity_create(catalog_, "core.template", 13, id, NULL) !=
            GDEFCORE_OK) {
      return NULL;
    }
    OneValue(&values[0], "name", &slots[0], &lens[0]);
    OneValue(&values[1], "body", &slots[1], &lens[1]);
    OneValue(&values[2], "kind", &slots[2], &lens[2]);
    if (gdefcore_changeset_prepare(catalog_, NULL, 0, &cs) != GDEFCORE_OK) {
      return NULL;
    }
    if (gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 3) !=
        GDEFCORE_OK) {
      gdefcore_changeset_destroy(cs);
      return NULL;
    }
    return cs;
  }

  /* Save a kind (new or existing) by changeset and apply it. */
  GDEFCORE_Result PutKind(const char * name, std::vector<std::string> vars,
      std::vector<std::string> fns, GDEFCORE_Changeset ** keep = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[5];
    const char * label = name;
    const char * version = "1";
    const char * nslot = name;
    size_t nlen = strlen(name);
    size_t llen = strlen(label);
    size_t vlen = 1;
    std::vector<const char *> vtexts;
    std::vector<size_t> vlens;
    std::vector<const char *> ftexts;
    std::vector<size_t> flens;
    size_t nvalues = 3;
    GDEFCORE_Result rc;
    for (const std::string & v : vars) {
      vtexts.push_back(v.c_str());
      vlens.push_back(v.size());
    }
    for (const std::string & f : fns) {
      ftexts.push_back(f.c_str());
      flens.push_back(f.size());
    }
    if (!Find(GDEFCORE_TEMPLATE_KIND_TYPE, name, id)) {
      rc = gdefcore_entity_create(catalog_, GDEFCORE_TEMPLATE_KIND_TYPE, 18, id,
          NULL);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
    }
    OneValue(&values[0], "name", &nslot, &nlen);
    OneValue(&values[1], "label", &label, &llen);
    OneValue(&values[2], "version", &version, &vlen);
    if (!vtexts.empty()) {
      OneValue(&values[nvalues++], "variables", vtexts.data(), vlens.data(),
          vtexts.size());
    }
    if (!ftexts.empty()) {
      OneValue(&values[nvalues++], "functions", ftexts.data(), flens.data(),
          ftexts.size());
    }
    rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values,
        nvalues);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, GDEFCORE_TEMPLATE_KIND_TYPE, 18);
    }
    SaveRefusal(cs);
    if (keep != NULL) {
      *keep = cs;
    } else {
      gdefcore_changeset_destroy(cs);
    }
    return rc;
  }

  void AddPost(const char * title, const char * body) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[2];
    const char * slots[2] = {title, body};
    size_t lens[2] = {strlen(title), strlen(body)};
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.post", 9, id, NULL));
    OneValue(&values[0], "title", &slots[0], &lens[0]);
    OneValue(&values[1], "body", &slots[1], &lens[1]);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 2));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    posts_.push_back(id);
  }

  void SetLayout(const char * layout) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_TRUE(Find("core.display", "front", id));
    const char * name = "front";
    size_t name_len = 5;
    size_t layout_len = strlen(layout);
    const char * pane = "side view recent";
    size_t pane_len = strlen(pane);
    GDEFCORE_Value values[3];
    OneValue(&values[0], "name", &name, &name_len);
    OneValue(&values[1], "layout", &layout, &layout_len);
    OneValue(&values[2], "panes", &pane, &pane_len);
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 3));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.display", 12));
    gdefcore_changeset_destroy(cs);
  }

  std::vector<std::string> posts_;

  /* Validation ----------------------------------------------------------- */

  std::vector<Issue> Check(const char * kind, const std::string & body,
      const GDEFCORE_Changeset * projection = NULL, bool * ran = NULL) {
    std::vector<Issue> out;
    GDEFCORE_Template_Report * rep = NULL;
    GDEFCORE_Result rc = gdefcore_template_validate(catalog_, projection, kind,
        strlen(kind), body.data(), body.size(), &rep);
    if (ran != NULL) {
      *ran = rc == GDEFCORE_OK;
    }
    EXPECT_EQ(GDEFCORE_OK, rc);
    for (size_t i = 0; i < gdefcore_template_report_count(rep); i++) {
      GDEFCORE_Template_Issue issue;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_template_report_at(rep, i, &issue));
      out.push_back({issue.reason, issue.line,
          std::string(issue.name, issue.name_len),
          std::string(issue.message, issue.message_len)});
    }
    gdefcore_template_report_free(rep);
    return out;
  }

  /* Rendering ------------------------------------------------------------ */

  std::string Page(GDEFCORE_Request * request, GDEFCORE_Result * rc = NULL,
      const char * path = "/") {
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Result result = gdefcore_render_page(catalog_, NULL, request, path,
        strlen(path), GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
    std::string page;
    if (rc != NULL) {
      *rc = result;
    }
    if (result == GDEFCORE_OK && bytes != NULL) {
      page.assign(bytes, n);
    }
    gdefcore_text_free(catalog_, bytes);
    return page;
  }

  std::string Key(GDEFCORE_Request * request) {
    char * key = NULL;
    size_t n = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(catalog_, request, NULL, 0, NULL, 0, &key, &n));
    if (key != NULL) {
      out.assign(key, n);
      gdefcore_text_free(catalog_, key);
    }
    return out;
  }

  /* A request for a fresh principal. */
  GDEFCORE_Request * AsPrincipal(std::string * id_out) {
    const uint8_t tenant[] = {'t'};
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Request * request = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, id));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant, 1, 0, 0, NULL, &request));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request, id, strlen(id)));
    *id_out = id;
    return request;
  }
};

bool Has(const std::vector<Issue> & v, int reason, const std::string & name,
    int line = -1) {
  for (const Issue & i : v) {
    if (i.reason == reason && i.name == name && (line < 0 || i.line == line)) {
      return true;
    }
  }
  return false;
}

std::string Dump(const std::vector<Issue> & v) {
  std::string out;
  for (const Issue & i : v) {
    out += "[" + std::to_string(i.reason) + " line " + std::to_string(i.line) +
           " '" + i.name + "': " + i.message + "] ";
  }
  return out.empty() ? "(none)" : out;
}

/* ---------------------------------------------------------------------- */
/* The matrix                                                              */
/* ---------------------------------------------------------------------- */

TEST_F(Templates, KnownVariable) {
  auto ok = Check("core.pane", "<% use title; %><%= title %>");
  EXPECT_TRUE(ok.empty()) << Dump(ok);
  /* Control: the checker does report, so an empty answer means something. */
  auto bad = Check("core.pane", "<% use title; %><%= titl %>");
  EXPECT_FALSE(bad.empty());
}

TEST_F(Templates, Typo) {
  auto v = Check("core.pane", "<% use title; %>\n<p>\n<%= titl %>\n");
  ASSERT_EQ(1u, v.size()) << Dump(v);
  EXPECT_EQ(GDEFCORE_ISSUE_NAME, v[0].reason);
  EXPECT_EQ("titl", v[0].name);
  EXPECT_EQ(3, v[0].line);
  /* Control: the hint differs for a name the contract does have. */
  v = Check("core.pane", "<%= title %>");
  ASSERT_EQ(1u, v.size());
  EXPECT_NE(std::string::npos, v[0].message.find("use title"));
}

TEST_F(Templates, UndeclaredUse) {
  auto v = Check("core.pane", "\n<% use nope; %>");
  ASSERT_EQ(1u, v.size()) << Dump(v);
  EXPECT_EQ(GDEFCORE_ISSUE_USE, v[0].reason);
  EXPECT_EQ("nope", v[0].name);
  EXPECT_EQ(2, v[0].line);
  /* The engine's own libraries are not in any contract. */
  EXPECT_TRUE(Has(Check("core.pane", "<% use math; %>"), GDEFCORE_ISSUE_USE, "math"));
  EXPECT_TRUE(Has(Check("core.pane", "<% use random; %>"), GDEFCORE_ISSUE_USE, "random"));
  /* A bare prefix of a dotted name is not a name. */
  Install(0);
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.pane", "m.count", "number", &probe_, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  EXPECT_TRUE(Has(Check("core.pane", "<% use m as q; %>"), GDEFCORE_ISSUE_USE, "m"));
  /* Control: the full path is. */
  EXPECT_TRUE(Check("core.pane", "<% use m.count as q; %><%= q %>").empty());
}

TEST_F(Templates, UndeclaredFunction) {
  auto v = Check("core.pane", "x\n<%= secret() %>");
  ASSERT_EQ(1u, v.size()) << Dump(v);
  EXPECT_EQ(GDEFCORE_ISSUE_CALL, v[0].reason);
  EXPECT_EQ("secret", v[0].name);
  EXPECT_EQ(2, v[0].line);
  /* Declared by use and still not in the contract: refused at the use. */
  v = Check("core.pane", "<% use secret; %><%= secret() %>");
  EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_USE, "secret")) << Dump(v);
  /* A function in the contract, used and called, is fine; called without a
   * use it is not. */
  EXPECT_TRUE(Check("core.pane", "<% use url; %><%= url(\"/x\") %>").empty());
  v = Check("core.pane", "<%= url(\"/x\") %>");
  EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_CALL, "url")) << Dump(v);
  /* region belongs to the page, not to a pane. */
  EXPECT_TRUE(Check("core.page", "<% use region; %><%= region(\"main\") %>").empty());
  EXPECT_TRUE(Has(Check("core.pane", "<% use region; %>"), GDEFCORE_ISSUE_USE, "region"));
  /* A variable is not a function, and the argument count is part of the
   * contract. */
  v = Check("core.pane", "<% use title; %><%= title() %>");
  EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_CALL, "title")) << Dump(v);
  v = Check("core.pane", "<% use url; %><%= url() %>");
  EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_CALL, "url")) << Dump(v);
  v = Check("core.pane", "<% use url; %><%= url(\"a\", \"b\") %>");
  EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_CALL, "url")) << Dump(v);
  /* A call must name its function. */
  v = Check("core.pane", "<% use title; %><%= title.upper() %>");
  EXPECT_EQ(1u, v.size()) << Dump(v);
  EXPECT_EQ(GDEFCORE_ISSUE_CALL, v[0].reason);
}

TEST_F(Templates, LocalVariable) {
  EXPECT_TRUE(Check("core.pane", "<% n = 1; %><%= n %>").empty());
  /* Loops, ranged loops and the template's own functions are free. */
  auto ok = Check("core.pane",
      "<% a = [1, 2]; total = 0;\n"
      "for (x : a) { total = total + x; }\n"
      "for (i = 0; i < 2; i += 1) { total = total + i; }\n"
      "function twice(q) { r = q * 2; return r; }\n"
      "w = {k: total}; %><%= twice(total) %><%= w.k %>");
  EXPECT_TRUE(ok.empty()) << Dump(ok);
  /* Control: a name that is never assigned is not free. */
  auto bad = Check("core.pane", "<% n = 1; %><%= m %>");
  EXPECT_TRUE(Has(bad, GDEFCORE_ISSUE_NAME, "m")) << Dump(bad);
  /* A function does not see the template's variables without `global`. */
  bad = Check("core.pane", "<% n = 1; function f() { return n; } %><%= f() %>");
  EXPECT_TRUE(Has(bad, GDEFCORE_ISSUE_NAME, "n")) << Dump(bad);
  EXPECT_TRUE(Check("core.pane",
      "<% n = 1; function f() { global n; return n; } %><%= f() %>").empty());
  /* A function may call another of the template's functions. */
  EXPECT_TRUE(Check("core.pane",
      "<% function g() { return 1; } function f() { return g(); } %><%= f() %>")
          .empty());
  /* The contract's names reach a function only through its own use. */
  bad = Check("core.pane",
      "<% use title; function f() { return title; } %><%= f() %>");
  EXPECT_TRUE(Has(bad, GDEFCORE_ISSUE_NAME, "title")) << Dump(bad);
  EXPECT_TRUE(Check("core.pane",
      "<% function f() { use title; return title; } %><%= f() %>").empty());
}

TEST_F(Templates, ParseError) {
  auto v = Check("core.pane", "line one\nline two\n<% use title; x = ; %>\n");
  ASSERT_EQ(1u, v.size()) << Dump(v);
  EXPECT_EQ(GDEFCORE_ISSUE_PARSE, v[0].reason);
  EXPECT_EQ(3, v[0].line);
  v = Check("core.pane", "a\nb\n<%= title");
  ASSERT_EQ(1u, v.size()) << Dump(v);
  EXPECT_EQ(GDEFCORE_ISSUE_PARSE, v[0].reason);
  EXPECT_GE(v[0].line, 3);
  /* Control: the same text, closed, parses. */
  EXPECT_FALSE(Has(Check("core.pane", "a\nb\n<%= title %>"), GDEFCORE_ISSUE_PARSE, ""));
}

TEST_F(Templates, ModuleVariable) {
  Install(0);
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.pane", "m.count", "number", &probe_, 1));
  const char * body = "<% use m.count as count; %><%= count %>";
  /* Registered and not enabled: the contract does not have it. */
  auto off = Check("core.pane", body);
  EXPECT_TRUE(Has(off, GDEFCORE_ISSUE_USE, "m.count")) << Dump(off);
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  auto on = Check("core.pane", body);
  EXPECT_TRUE(on.empty()) << Dump(on);
  /* It is a contribution to core.pane only. */
  EXPECT_TRUE(Has(Check("core.page", body), GDEFCORE_ISSUE_USE, "m.count"));
  /* Disabled again: gone. */
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", false));
  EXPECT_TRUE(Has(Check("core.pane", body), GDEFCORE_ISSUE_USE, "m.count"));
  /* Saving a template that uses it follows the same rule at apply. */
  EXPECT_EQ(GDEFCORE_ERR_FORMAT, SaveTemplate("uses-m", body, "core.pane"));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  EXPECT_EQ(GDEFCORE_OK, SaveTemplate("uses-m", body, "core.pane")) << refusal_;
}

TEST_F(Templates, ContractLayers) {
  Install(0);
  Install(1);
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.pane", "m.count", "number", &probe_, 1));
  ASSERT_EQ(GDEFCORE_OK, Contribute("n", "core.pane", "n.size", "text", &probe_, 1));
  GDEFCORE_Contract * c = NULL;
  char * message = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, NULL, "core.pane", 9, &c, &message));
  /* Base first, then contributions of enabled modules (none yet). */
  EXPECT_EQ(4u, gdefcore_template_contract_var_count(c));
  EXPECT_EQ(1, gdefcore_template_contract_version(c));
  gdefcore_template_contract_close(c);
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("n", true));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, NULL, "core.pane", 9, &c, &message));
  EXPECT_EQ(5u, gdefcore_template_contract_var_count(c));
  GDEFCORE_Contract_Var v;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_var(c, "n.size", 6, &v));
  EXPECT_NE(nullptr, v.contributed);
  EXPECT_EQ(GDEFCORE_TEMPLATE_TEXT, v.type);
  EXPECT_EQ("a count", std::string(v.description, v.description_len));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_var(c, "title", 5, &v));
  EXPECT_EQ(nullptr, v.contributed);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_template_contract_var(c, "m.count", 7, &v));
  gdefcore_template_contract_close(c);
  /* A projection shows the contract a changeset would leave. */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, cs, "m", 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, cs, "core.pane", 9, &c, &message));
  EXPECT_EQ(6u, gdefcore_template_contract_var_count(c));
  gdefcore_template_contract_close(c);
  EXPECT_TRUE(Check("core.pane", "<% use m.count as q; %>", cs).empty());
  EXPECT_FALSE(Check("core.pane", "<% use m.count as q; %>").empty());
  gdefcore_changeset_destroy(cs);
  /* Unknown kind. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_template_contract_open(catalog_, NULL, "core.nothing", 12, &c, &message));
  EXPECT_NE(nullptr, message);
  gdefcore_text_free(catalog_, message);
  auto none = Check("core.nothing", "x");
  ASSERT_EQ(1u, none.size());
  EXPECT_EQ(GDEFCORE_ISSUE_KIND, none[0].reason);
}

TEST_F(Templates, Order) {
  Install(2);
  Install(3);
  Probe pa, pb;
  /* Equal weights: module name. */
  ASSERT_EQ(GDEFCORE_OK, Contribute("b", "core.pane", "b.v", "text", &pb, 1));
  ASSERT_EQ(GDEFCORE_OK, Contribute("a", "core.pane", "a.v", "text", &pa, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("a", true));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("b", true));
  auto order = [&]() {
    std::string out;
    GDEFCORE_Contract * c = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, NULL, "core.pane", 9, &c, NULL));
    for (size_t i = 4; i < gdefcore_template_contract_var_count(c); i++) {
      GDEFCORE_Contract_Var v;
      gdefcore_template_contract_var_at(c, i, &v);
      out += std::string(v.name, v.name_len) + " ";
    }
    gdefcore_template_contract_close(c);
    return out;
  };
  EXPECT_EQ("a.v b.v ", order());
  /* Registration order did not decide: a register-later module with a weight
   * lower than the other's runs first. */
  ASSERT_EQ(GDEFCORE_OK, Contribute("a", "core.pane", "a.w", "text", &pa, 1, 5));
  ASSERT_EQ(GDEFCORE_OK, Contribute("b", "core.pane", "b.w", "text", &pb, 1, -5));
  std::string got = order();
  EXPECT_LT(got.find("b.w"), got.find("a.v")) << got;
  EXPECT_LT(got.find("a.v"), got.find("a.w")) << got;
}

TEST_F(Templates, Relationships) {
  Install(2);
  Install(3);
  Probe pa, pb;
  /* a would sort first by name; `after` puts it behind b. */
  ASSERT_EQ(GDEFCORE_OK, Contribute("a", "core.pane", "a.v", "text", &pa, 1, 0, NULL, "b"));
  ASSERT_EQ(GDEFCORE_OK, Contribute("b", "core.pane", "b.v", "text", &pb, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("a", true));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("b", true));
  GDEFCORE_Contract * c = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, NULL, "core.pane", 9, &c, NULL));
  GDEFCORE_Contract_Var v;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_var_at(c, 4, &v));
  EXPECT_EQ("b.v", std::string(v.name, v.name_len));
  gdefcore_template_contract_close(c);
  /* A cycle is an error naming both modules. */
  Probe pc;
  ASSERT_EQ(GDEFCORE_OK, Contribute("b", "core.pane", "b.x", "text", &pc, 1, 0, NULL, "a"));
  char * message = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_template_contract_open(catalog_, NULL, "core.pane", 9, &c, &message));
  ASSERT_NE(nullptr, message);
  std::string text = message;
  gdefcore_text_free(catalog_, message);
  EXPECT_NE(std::string::npos, text.find("a")) << text;
  EXPECT_NE(std::string::npos, text.find("b")) << text;
  EXPECT_NE(std::string::npos, text.find("cycled")) << text;
}

TEST_F(Templates, DisablePreview) {
  Install(0);
  Install(1);
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.pane", "m.count", "number", &probe_, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("n", true));
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("counted", "<% use m.count as c; %><%= c %>", "core.pane"));
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_disable(host_, cs, "m", 1));
  GDEFCORE_Template_Report * rep = NULL;
  int risk = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_preview(cs, &rep, &risk));
  EXPECT_EQ(GDEFCORE_RISK_HIGH, risk);
  ASSERT_EQ(1u, gdefcore_template_report_count(rep));
  GDEFCORE_Template_Issue issue;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_report_at(rep, 0, &issue));
  EXPECT_EQ(GDEFCORE_ISSUE_BREAKS, issue.reason);
  EXPECT_EQ("counted", std::string(issue.template_name, issue.template_name_len));
  EXPECT_EQ("m.count", std::string(issue.name, issue.name_len));
  EXPECT_EQ(1, issue.line);
  gdefcore_template_report_free(rep);
  /* The built-in templates do not break, and are not listed. */
  /* A disable that breaks nothing lists nothing (control). */
  gdefcore_changeset_destroy(cs);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_disable(host_, cs, "n", 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_preview(cs, &rep, &risk));
  EXPECT_EQ(0u, gdefcore_template_report_count(rep));
  EXPECT_EQ(GDEFCORE_RISK_HIGH, risk);
  gdefcore_template_report_free(rep);
  gdefcore_changeset_destroy(cs);
  /* The disable itself is allowed: the preview informs, apply does not refuse
   * (the admin confirms the high-risk change by name). */
  EXPECT_EQ(GDEFCORE_OK, ModuleOp("m", false));
  EXPECT_TRUE(Has(Check("core.pane", "<% use m.count as c; %>"), GDEFCORE_ISSUE_USE, "m.count"));
}

TEST_F(Templates, NameClash) {
  Install(0);
  /* The base of a custom kind already has m.count. */
  ASSERT_EQ(GDEFCORE_OK, PutKind("t.clash", {"m.count number The base has it."}, {"url 1"}));
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "t.clash", "m.count", "number", &probe_, 1));
  /* Registered, not enabled: no clash yet. */
  GDEFCORE_Contract * c = NULL;
  char * message = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, NULL, "t.clash", 7, &c, &message));
  gdefcore_template_contract_close(c);
  /* Enabling it would clash, so apply refuses, and the refusal names both. */
  EXPECT_EQ(GDEFCORE_ERR_FORMAT, ModuleOp("m", true));
  EXPECT_NE(std::string::npos, refusal_.find("module m")) << refusal_;
  EXPECT_NE(std::string::npos, refusal_.find("m.count")) << refusal_;
  EXPECT_NE(std::string::npos, refusal_.find("t.clash")) << refusal_;
  int on = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enabled(host_, anon_, "m", 1, &on));
  EXPECT_EQ(0, on);
  /* The same module twice is an error at contribute, naming it. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Contribute("m", "t.clash", "m.count", "number", &probe_, 1));
  size_t n = 0;
  const char * e = gdefcore_module_error(host_, &n);
  ASSERT_NE(nullptr, e);
  EXPECT_NE(std::string::npos, std::string(e, n).find("m.count"));
  /* Control: a name that does not clash enables. */
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.pane", "m.other", "text", &probe_, 1));
  EXPECT_EQ(GDEFCORE_ERR_FORMAT, ModuleOp("m", true));  /* t.clash is still there */
  ASSERT_EQ(GDEFCORE_OK, PutKind("t.clash", {"x number The base has x."}, {"url 1"}));
  EXPECT_EQ(GDEFCORE_OK, ModuleOp("m", true)) << refusal_;
}

TEST_F(Templates, ContributeErrors) {
  Install(0);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Contribute("zz", "core.pane", "zz.v", "text", &probe_, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Contribute("m", "core.pane", "other.v", "text", &probe_, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Contribute("m", "core.pane", "m.a.b", "text", &probe_, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Contribute("m", "core.pane", "m.v", "list", &probe_, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Contribute("m", "core.pane", "m.", "text", &probe_, 1));
  /* Control. */
  EXPECT_EQ(GDEFCORE_OK, Contribute("m", "core.pane", "m.v", "text", &probe_, 1));
}

TEST_F(Templates, LazyProvider) {
  Install(0);
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.page", "m.count", "number", &probe_, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  /* A layout that never reads it. */
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout", "<% use region; %><i>plain</i>", "core.page"));
  GDEFCORE_Result rc;
  std::string page = Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("<i>plain</i>"));
  EXPECT_EQ(0, probe_.calls);
  /* Control: the same page with a template that reads it calls the provider. */
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout", "<% use m.count as c; %><i><%= c %></i>", "core.page"));
  page = Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("<i>7</i>")) << page;
  EXPECT_EQ(1, probe_.calls);
  EXPECT_EQ(anon_, probe_.last);  /* the provider got the request being rendered */
}

TEST_F(Templates, ProviderTypes) {
  Install(0);
  Probe markup;
  markup.text = "<b>bold</b> & more";
  markup.kind = GDEFCORE_CONTRIBUTION_TEXT;
  Probe text;
  text.kind = GDEFCORE_CONTRIBUTION_TEXT;
  text.text = "<b>bold</b> & more";
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.page", "m.html", "markup", &markup, 1));
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.page", "m.plain", "text", &text, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout",
          "<% use m.html as h; use m.plain as p; %>[<%= h %>][<%= p %>]", "core.page"));
  GDEFCORE_Result rc;
  std::string page = Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  /* markup is the one trusted type; text is as inert as a field. */
  EXPECT_NE(std::string::npos, page.find("[<b>bold</b> & more]")) << page;
  EXPECT_NE(std::string::npos, page.find("[&lt;b&gt;bold&lt;/b&gt; &amp; more]")) << page;
  /* A provider that answers the wrong kind of value is "not available". */
  text.kind = GDEFCORE_CONTRIBUTION_INTEGER;
  page = Page(anon_, &rc);
  EXPECT_NE(std::string::npos, page.find("[<b>bold</b> & more][]")) << page;
}

TEST_F(Templates, PrincipalKey) {
  Install(0);
  Probe personal;
  Probe shared;
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.page", "m.me", "text", &personal, 0));
  ASSERT_EQ(GDEFCORE_OK, Contribute("m", "core.page", "m.all", "text", &shared, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  std::string who;
  GDEFCORE_Request * p1 = AsPrincipal(&who);
  GDEFCORE_Result rc;
  /* A page that reads a variable that is not principal_free: the key carries
   * the principal. */
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout", "<% use m.me as q; %><%= q %>", "core.page"));
  Page(p1, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_EQ(1, personal.calls);
  EXPECT_NE(std::string::npos, Key(p1).find("\nprincipal:" + who + "\n")) << Key(p1);
  /* Control: the same principal, a page that reads only a principal_free
   * variable, leaves the key without it. */
  GDEFCORE_Request * p2 = AsPrincipal(&who);
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout", "<% use m.all as q; %><%= q %>", "core.page"));
  Page(p2, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_EQ(1, shared.calls);
  EXPECT_EQ(std::string::npos, Key(p2).find(who)) << Key(p2);
  EXPECT_NE(std::string::npos, Key(p2).find("\nprincipal:-\n"));
  /* Control: a page that reads neither is not marked either, even though a
   * provider is registered and enabled (observed, never declared). */
  GDEFCORE_Request * p3 = AsPrincipal(&who);
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout", "<% use region; %>none", "core.page"));
  Page(p3, &rc);
  EXPECT_EQ(std::string::npos, Key(p3).find(who));
  EXPECT_EQ(0, gdefcore_request_principal_dependent(p3));
  EXPECT_EQ(1, gdefcore_request_principal_dependent(p1));
  gdefcore_request_destroy(p1);
  gdefcore_request_destroy(p2);
  gdefcore_request_destroy(p3);
}

TEST_F(Templates, EditWhileServing) {
  AddPost("First post", "The body of the first post.");
  GDEFCORE_Result rc;
  std::string page = Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("<article class=\"recent\"><h2>First post</h2>")) << page;
  EXPECT_EQ(std::string::npos, page.find("EDITED"));
  /* Edit core.pane's `recent` by changeset; no restart. */
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("recent",
          "<% use title; %><section class=\"edited\">EDITED <%= title %></section>",
          "core.pane")) << refusal_;
  page = Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("<section class=\"edited\">EDITED First post</section>")) << page;
  EXPECT_EQ(std::string::npos, page.find("class=\"recent\""));
  /* And the layout, a page kind. */
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout",
          "<% use region; %><main><%= region(\"side\") %></main>", "core.page"));
  page = Page(anon_, &rc);
  EXPECT_NE(std::string::npos, page.find("<main><section")) << page;
  /* Control: a refused edit leaves what is served as it was. */
  EXPECT_EQ(GDEFCORE_ERR_FORMAT,
      SaveTemplate("layout", "<% use region; %><b><%= regoin(\"side\") %></b>", "core.page"));
  Page(anon_, &rc);
  page = Page(anon_, &rc);
  EXPECT_NE(std::string::npos, page.find("<main><section")) << page;
}

TEST_F(Templates, UnknownKindNoRender) {
  AddPost("First post", "Body.");
  GDEFCORE_Result rc;
  std::string page = Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);  /* control: with its kind the page renders */
  EXPECT_NE(std::string::npos, page.find("First post"));
  /* Rename the kind away: every template that names it has no kind to read.
   * A kind edit lists what breaks and does not refuse. */
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_TRUE(Find(GDEFCORE_TEMPLATE_KIND_TYPE, "core.pane", id));
  const char * renamed = "core.pane-gone";
  size_t renamed_len = strlen(renamed);
  const char * label = "x";
  size_t label_len = 1;
  const char * version = "1";
  size_t version_len = 1;
  GDEFCORE_Value values[3];
  OneValue(&values[0], "name", &renamed, &renamed_len);
  OneValue(&values[1], "label", &label, &label_len);
  OneValue(&values[2], "version", &version, &version_len);
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 3));
  GDEFCORE_Template_Report * rep = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_preview(cs, &rep, NULL));
  /* entity, recent and field name core.pane, which would no longer exist. */
  size_t breaks = 0;
  for (size_t i = 0; i < gdefcore_template_report_count(rep); i++) {
    GDEFCORE_Template_Issue issue;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_template_report_at(rep, i, &issue));
    breaks += issue.reason == GDEFCORE_ISSUE_BREAKS ? 1 : 0;
  }
  EXPECT_EQ(3u, breaks);
  gdefcore_template_report_free(rep);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, GDEFCORE_TEMPLATE_KIND_TYPE, 18));
  gdefcore_changeset_destroy(cs);
  page = Page(anon_, &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  EXPECT_TRUE(page.empty());
}

TEST_F(Templates, Unsafe) {
  const char * lead = "<% use title; %>";
  auto bad = Check("core.pane", std::string(lead) + "<%= title.raw %>");
  EXPECT_TRUE(Has(bad, GDEFCORE_ISSUE_UNSAFE, "raw", 1)) << Dump(bad);
  /* With the marker on its line, valid. */
  auto ok = Check("core.pane",
      std::string(lead) + "<% /* unsafe: reviewed */ %><%= title.raw %>");
  EXPECT_TRUE(ok.empty()) << Dump(ok);
  /* The marker is a line's, not the template's. */
  bad = Check("core.pane",
      std::string(lead) + "<% /* unsafe: reviewed */ %>\n<%= title.raw %>");
  EXPECT_TRUE(Has(bad, GDEFCORE_ISSUE_UNSAFE, "raw", 2)) << Dump(bad);
  /* A line comment works too. */
  ok = Check("core.pane", std::string(lead) + "<%= title.raw // unsafe: why\n %>");
  EXPECT_TRUE(ok.empty()) << Dump(ok);
  /* The other tag methods are not on the list. */
  ok = Check("core.pane", std::string(lead) + "<%= title.html %><%= title.percent %>");
  EXPECT_TRUE(ok.empty()) << Dump(ok);
  /* It is a refusal at apply, with the line. */
  EXPECT_EQ(GDEFCORE_ERR_FORMAT,
      SaveTemplate("rawcheck", std::string(lead) + "\n<%= title.raw %>", "core.pane"));
  EXPECT_NE(std::string::npos, refusal_.find("template 'rawcheck', line 2:")) << refusal_;
  EXPECT_EQ(GDEFCORE_OK,
      SaveTemplate("rawcheck", std::string(lead) + "\n<%= title.raw %><% /* unsafe */ %>", "core.pane"));
}

/* ---------------------------------------------------------------------- */
/* Apply and preview                                                       */
/* ---------------------------------------------------------------------- */

TEST_F(Templates, ApplyRefusesAndNames) {
  std::string before = Field("core.template", "recent", "body");
  ASSERT_NE("!", before);
  GDEFCORE_Changeset * cs = NULL;
  EXPECT_EQ(GDEFCORE_ERR_FORMAT,
      SaveTemplate("recent",
          "<% use title; %>\n<p><%= title %></p>\n<%= summry %>\n", "core.pane", &cs));
  EXPECT_NE(std::string::npos, refusal_.find("template 'recent', line 3:")) << refusal_;
  EXPECT_NE(std::string::npos, refusal_.find("summry")) << refusal_;
  /* Nothing was written. */
  EXPECT_EQ(before, Field("core.template", "recent", "body"));
  /* The preview says the same thing without applying. */
  GDEFCORE_Template_Report * rep = NULL;
  int risk = 0;
  gdefcore_changeset_destroy(cs);
  cs = StageTemplate("recent", "<% use title; %>\n\n<%= nope %>", "core.pane");
  ASSERT_NE(nullptr, cs);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_preview(cs, &rep, &risk));
  ASSERT_EQ(1u, gdefcore_template_report_count(rep));
  GDEFCORE_Template_Issue issue;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_report_at(rep, 0, &issue));
  EXPECT_EQ(3, issue.line);
  EXPECT_EQ("nope", std::string(issue.name, issue.name_len));
  EXPECT_EQ("recent", std::string(issue.template_name, issue.template_name_len));
  size_t n = 0;
  const char * text = gdefcore_template_report_text(rep, &n);
  EXPECT_NE(std::string::npos, std::string(text, n).find("template 'recent', line 3:"));
  gdefcore_template_report_free(rep);
  EXPECT_EQ(GDEFCORE_RISK_HIGH, risk);
  EXPECT_EQ(GDEFCORE_ERR_FORMAT, gdefcore_changeset_apply(cs, "core.template", 13));
  gdefcore_changeset_destroy(cs);
  /* Control: a valid edit applies. */
  EXPECT_EQ(GDEFCORE_OK,
      SaveTemplate("recent", "<% use title; %><p><%= title %></p>", "core.pane"));
  EXPECT_EQ("<% use title; %><p><%= title %></p>", Field("core.template", "recent", "body"));
  /* An unknown kind, and no kind, are refused. */
  EXPECT_EQ(GDEFCORE_ERR_FORMAT, SaveTemplate("recent", "x", "core.nothing"));
  EXPECT_NE(std::string::npos, refusal_.find("core.nothing")) << refusal_;
}

TEST_F(Templates, BuiltInsAndContracts) {
  /* The kit's own templates validate against the contracts the kit sets. */
  const char * names[] = {"layout", "entity", "recent", "field"};
  const char * kinds[] = {"core.page", "core.pane", "core.pane", "core.pane"};
  for (int i = 0; i < 4; i++) {
    SCOPED_TRACE(names[i]);
    EXPECT_EQ(kinds[i], Field("core.template", names[i], "kind"));
    auto v = Check(kinds[i], Field("core.template", names[i], "body"));
    EXPECT_TRUE(v.empty()) << Dump(v);
  }
  /* The contracts are what the C templates used: each name is used by one. */
  GDEFCORE_Contract * c = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, NULL, "core.pane", 9, &c, NULL));
  std::string vars;
  for (size_t i = 0; i < gdefcore_template_contract_var_count(c); i++) {
    GDEFCORE_Contract_Var v;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_var_at(c, i, &v));
    vars += std::string(v.name, v.name_len) + ":" + std::to_string(v.type) + " ";
    EXPECT_GT(v.description_len, 0u);
  }
  EXPECT_EQ("title:1 body:1 summary:1 value:1 ", vars);
  EXPECT_EQ(1u, gdefcore_template_contract_fn_count(c));
  GDEFCORE_Contract_Fn f;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_fn_at(c, 0, &f));
  EXPECT_EQ("url", std::string(f.name, f.name_len));
  EXPECT_EQ(1, f.arity);
  gdefcore_template_contract_close(c);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_template_contract_open(catalog_, NULL, "core.page", 9, &c, NULL));
  EXPECT_EQ(0u, gdefcore_template_contract_var_count(c));
  EXPECT_EQ(2u, gdefcore_template_contract_fn_count(c));
  gdefcore_template_contract_close(c);
}

TEST_F(Templates, NoKindNoRender) {
  GDEFCORE_Result rc;
  /* Control: the page renders through its layout. */
  Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  /* What a display whose layout is not stored gets. */
  SetLayout("no-such-template");
  std::string page = Page(anon_, &rc);
  GDEFCORE_Result missing = rc;
  ASSERT_NE(GDEFCORE_OK, missing);
  EXPECT_TRUE(page.empty());
  /* A template row that predates kinds: its type has no kind field, so the
   * row has none. Apply does not judge it (it cannot carry a kind); render
   * refuses it with the very same error as a template that is not there. */
  GDEFCORE_Field fields[2];
  memset(fields, 0, sizeof fields);
  fields[0].size = sizeof fields[0];
  fields[0].name = "name";
  fields[0].name_len = 4;
  fields[0].required = 1;
  fields[1].size = sizeof fields[1];
  fields[1].name = "body";
  fields[1].name_len = 4;
  fields[1].required = 1;
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(cs, "core.template", 13, GDEFCORE_TYPE_CONFIG, fields, 2));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.template", 13));
  gdefcore_changeset_destroy(cs);
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, "core.template", 13, id, NULL));
  const char * slots[2] = {"legacy", "<% use region; %>old"};
  size_t lens[2] = {6, strlen(slots[1])};
  GDEFCORE_Value values[2];
  OneValue(&values[0], "name", &slots[0], &lens[0]);
  OneValue(&values[1], "body", &slots[1], &lens[1]);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 2));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.template", 13)) << refusal_;
  gdefcore_changeset_destroy(cs);
  SetLayout("legacy");
  page = Page(anon_, &rc);
  EXPECT_EQ(missing, rc);
  EXPECT_TRUE(page.empty());
  /* Control: the same display, pointed back at a template with a kind. */
  SetLayout("layout");
  Page(anon_, &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
}

TEST_F(Templates, NarrowContractIsTheLibrary) {
  AddPost("A title", "A body");
  GDEFCORE_Result rc;
  /* A pane that reads body: the contract has it. */
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("recent", "<% use title; use body; %>[<%= title %>|<%= body %>]", "core.pane"));
  EXPECT_NE(std::string::npos, Page(anon_, &rc).find("[A title|"));
  /* The recent pane does not bind body at all; use the library the layout is
   * given: a layout is bound nothing, so even `title` is outside its contract. */
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("recent", "<% use title; %>[<%= title %>]", "core.pane"));
  EXPECT_NE(std::string::npos, Page(anon_, &rc).find("[A title]"));
  /* Narrow core.pane to drop `title`: the host still binds it, the library
   * does not hand it over. The template, stored before, is not re-validated
   * (a kind edit lists what breaks; it does not refuse). */
  ASSERT_EQ(GDEFCORE_OK, PutKind("core.pane", {"body text The body."}, {"url 1"}));
  std::string page = Page(anon_, &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("[]")) << page;
  EXPECT_EQ(std::string::npos, page.find("A title")) << page;
}

TEST_F(Templates, PlumbingAndBuiltinsAreNotReachable) {
  /* The library is the contract's names: not the template that runs the body,
   * not the engine's math or random. A bare scope is not validated, so it
   * asks the engine directly what a `use` finds. */
  char * bytes = NULL;
  size_t n = 0;
  const char * src =
      "<% use url; use pane; use math; use random; use nope; %>"
      "[<%= url == null %>][<%= pane == null %>][<%= math == null %>]"
      "[<%= random == null %>][<%= nope == null %>]";
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_scope(catalog_, src, strlen(src), GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n));
  std::string page(bytes, n);
  gdefcore_text_free(catalog_, bytes);
  /* url is there (the control: this reads what is bound), the rest are null. */
  EXPECT_EQ("[false][true][true][true][true]", page);
  /* A kind cannot hand the template the plumbing's name either. */
  EXPECT_EQ(GDEFCORE_ERR_FORMAT, PutKind("t.reserved", {"pane text no"}, {}));
  /* Control: another name is a name. */
  EXPECT_EQ(GDEFCORE_OK, PutKind("t.reserved", {"panes text no"}, {}));
}

TEST_F(Templates, AstWalkSeesInsideLiterals) {
  /* The library's own walk does not enter a map literal's pairs; this does. */
  auto v = Check("core.pane", "<% m = {k: nope, j: [also]}; %><%= m.k %>");
  EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_NAME, "nope")) << Dump(v);
  EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_NAME, "also")) << Dump(v);
  /* Control: the same literal over declared names. */
  EXPECT_TRUE(Check("core.pane", "<% a = 1; b = 2; m = {k: a, j: [b]}; %><%= m.k %>").empty());
  /* Slices, ternaries, unary, casts, index, do-while: reads in all of them. */
  v = Check("core.pane",
      "<% s = \"abc\"; r = s[p:q]; t = zz ? 1 : 2; u = -yy; c = xx as int; i = s[ww];\n"
      "do { vv = 1; } while (uu); %>");
  for (const char * name : {"p", "q", "zz", "yy", "xx", "ww", "uu"}) {
    EXPECT_TRUE(Has(v, GDEFCORE_ISSUE_NAME, name)) << name << " " << Dump(v);
  }
}

/* `<% x = 1+1+...+1<tail> %>`, @p levels deep on its left. */
std::string DeepSum(int levels, const char * tail) {
  std::string deep = "<% x = 1";
  for (int i = 0; i < levels; i++) {
    deep += "+1";
  }
  return deep + tail;
}

/* The validator's walk keeps its own stack: a tree as deep as the parser
 * accepts is walked under AddressSanitizer, whose frames are about three times
 * larger, on the 4 MiB side stack (a recursive walk overflowed it). */
TEST_F(Templates, DeepTreeDoesNotOverflowTheStack) {
  EXPECT_TRUE(Check("core.pane", DeepSum(9000, "; %><%= x %>")).empty());
  /* Control: a read buried that deep is found. */
  EXPECT_TRUE(Has(Check("core.pane", DeepSum(9000, "+nope; %>")), GDEFCORE_ISSUE_NAME,
      "nope"));
  /* Past the parser's limit the template is refused, not crashed on. */
  auto v = Check("core.pane", DeepSum(10100, "; %>"));
  ASSERT_EQ(1u, v.size());
  EXPECT_EQ(GDEFCORE_ISSUE_PARSE, v[0].reason);
}

/* A request's fiber can be as small as cutil allows. Validation moves to a
 * stack of its own before it parses, so the same deep cases pass when they are
 * validated from such a fiber. It runs in a child, so that a fault on the
 * small stack is this test failing rather than the suite ending. */
TEST_F(Templates, DeepTreeOnTheSmallestFiber) {
#if defined(_WIN32) || !GCU_FIBER_SUPPORTED
  GTEST_SKIP() << "needs fork() and fibers";
#else
  std::function<bool()> body = [&]() {
    bool ran = false;
    bool ok = Check("core.pane", DeepSum(9000, "; %><%= x %>"), NULL, &ran).empty() &&
        ran;
    ok = ok && Has(Check("core.pane", DeepSum(9000, "+nope; %>")),
        GDEFCORE_ISSUE_NAME, "nope");
    auto v = Check("core.pane", DeepSum(10100, "; %>"));
    return ok && v.size() == 1 && v[0].reason == GDEFCORE_ISSUE_PARSE;
  };
  struct Job {
    std::function<bool()> * body;
    bool ok;
  } job = {&body, false};
  int status = 0;
  pid_t pid;
  fflush(NULL);
  pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    GCU_Fiber * fiber = NULL;
    if (gcu_fiber_create(&fiber,
            [](void * a) {
              Job * j = (Job *)a;
              j->ok = (*j->body)();
            },
            &job, GCU_FIBER_MIN_STACK_SIZE, NULL) != GCU_FIBER_OK) {
      _exit(2);
    }
    gcu_fiber_switch_to(fiber);
    gcu_fiber_destroy(fiber);
    _exit(job.ok ? 0 : 1);
  }
  ASSERT_EQ(pid, waitpid(pid, &status, 0));
  ASSERT_TRUE(WIFEXITED(status)) << "killed by signal " << WTERMSIG(status);
  EXPECT_EQ(0, WEXITSTATUS(status));
#endif
}

/* Reverting a template to an old revision puts that revision's text in front
 * of the renderer again, so the changeset that does it is vetted as a save
 * is: a revision that no longer builds against the contracts in force cannot
 * become the template. (Such a revision is reached here by writing it behind
 * the library's back, as a contract that has since narrowed would leave one.)
 * It replaces the gate on `activate`, which access SPEC decision 13 retired. */
TEST_F(Templates, RevertIsVetted) {
  const char tenant[] = {'t'};
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const std::string good = "<% use title; %><p><%= title %></p>";
  ASSERT_EQ(GDEFCORE_OK, SaveTemplate("recent", good, "core.pane"));
  ASSERT_TRUE(Find("core.template", "recent", id));
  uint64_t head = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision(catalog_, id, GDEFCORE_PUBLIC_ID_LEN, &head));
  ASSERT_GE(head, 1u);
  /* The bad revision, then the good text again, written raw on the port. */
  auto Raw = [&](const std::string & body, uint64_t base) {
    GDEFSTOR_Tree * tree = NULL;
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_entity_tree(store_, tenant, 1, id, GDEFCORE_PUBLIC_ID_LEN, "en",
            2, 0, &tree));
    GDEFSTOR_Value v;
    memset(&v, 0, sizeof v);
    v.type = GDEFSTOR_FIELD_TEXT;
    v.bytes = (const uint8_t *)body.data();
    v.len = body.size();
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_tree_set(tree, 0, "body", 4, &v));
    GDEFSTOR_RevisionMeta meta;
    memset(&meta, 0, sizeof meta);
    meta.size = sizeof meta;
    meta.who = "";
    meta.why = "";
    meta.schema = "core/1";
    meta.schema_len = 6;
    GDEFSTOR_Write * write = NULL;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_begin(store_, tenant, 1, NULL, &write));
    uint64_t rev = 0;
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_entity_save(write, id, GDEFCORE_PUBLIC_ID_LEN, base, &meta, "en",
            2, tree, &rev));
    ASSERT_EQ(base + 1, rev);
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(write));
    gdefstor_tree_free(tree);
  };
  Raw("<% use title; %><%= nope %>", head);
  Raw(good, head + 1);
  uint64_t bad = head + 1;

  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert_to(catalog_, id, GDEFCORE_PUBLIC_ID_LEN, bad,
          NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_FORMAT, gdefcore_changeset_apply(cs, "core.template", 13));
  SaveRefusal(cs);
  EXPECT_NE(std::string::npos, refusal_.find("nope")) << refusal_;
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(good, Field("core.template", "recent", "body"));
  /* Control: the revision before it, which builds, can be reverted to. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert_to(catalog_, id, GDEFCORE_PUBLIC_ID_LEN, head,
          NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.template", 13));
  gdefcore_changeset_destroy(cs);
}

}  // namespace

/* AD-34: a struct with a size member is accepted at exactly its own size. The
 * four here are the templates': what a contract and a report list (the core
 * fills them), and what a contribution's provider answers in (a block of
 * another size gives nothing: the variable reads as not available). See
 * size_structs.h, which lists every struct. */
TEST_F(Templates, TheStructsHereAreAcceptedAtOnlyTheirOwnSize) {
  Install(0);
  ASSERT_EQ(GDEFCORE_OK,
      Contribute("m", "core.page", "m.count", "number", &probe_, 1));
  ASSERT_EQ(GDEFCORE_OK, ModuleOp("m", true));
  ASSERT_EQ(GDEFCORE_OK,
      SaveTemplate("layout", "<% use m.count as c; %><i><%= c %></i>",
          "core.page"));
  GDEFCORE_Contract * contract = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_contract_open(catalog_, NULL, "core.pane", 9, &contract,
          NULL));
  GDEFCORE_Template_Report * report = NULL;
  const std::string bad = "<% use title; %><%= titl %>";
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_validate(catalog_, NULL, "core.pane", 9, bad.data(),
          bad.size(), &report));
  ASSERT_GT(gdefcore_template_report_count(report), 0u);
  const std::map<std::string, size_structs::Probe> probes = {
      /* The core fills the first three: whether it filled the size asked. */
      GDEFCORE_SIZE_PROBE(GDEFCORE_Contract_Var, {
        GDEFCORE_Contract_Var v;
        memset(&v, 0, sizeof v);
        EXPECT_EQ(GDEFCORE_OK, gdefcore_template_contract_var_at(contract, 0, &v));
        return v.size == size;
      }),
      GDEFCORE_SIZE_PROBE(GDEFCORE_Contract_Fn, {
        GDEFCORE_Contract_Fn f;
        memset(&f, 0, sizeof f);
        EXPECT_EQ(GDEFCORE_OK, gdefcore_template_contract_fn_at(contract, 0, &f));
        return f.size == size;
      }),
      GDEFCORE_SIZE_PROBE(GDEFCORE_Template_Issue, {
        GDEFCORE_Template_Issue issue;
        memset(&issue, 0, sizeof issue);
        EXPECT_EQ(GDEFCORE_OK, gdefcore_template_report_at(report, 0, &issue));
        return issue.size == size;
      }),
      GDEFCORE_SIZE_PROBE(GDEFCORE_Contribution_Value, {
        probe_.set_size = true;
        probe_.size_value = size;
        GDEFCORE_Result rc = GDEFCORE_OK;
        std::string page = Page(anon_, &rc);
        probe_.set_size = false;
        EXPECT_EQ(GDEFCORE_OK, rc);
        return page.find("<i>7</i>") != std::string::npos;
      }),
  };
  size_structs::Run("tests/test_templates.cpp", probes);
  gdefcore_template_report_free(report);
  gdefcore_template_contract_close(contract);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
