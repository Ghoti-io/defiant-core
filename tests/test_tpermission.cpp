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
 * Who may edit a template (site-admin story 3): the permission each kind
 * declares, the decision hook a module refines it through, and the render of
 * an edited body that no shared cache may keep.
 *
 * Every refusal has a control that makes the same write succeed, so a test
 * that cannot see the thing it looks for is not passing by accident.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#define TP_STR2(x) #x
#define TP_STR(x) TP_STR2(x)

namespace {

const char kCoreToken[] = TP_STR(GHOTIIO_DEFCORE_NAME);
const char kNotAllowed[] = "That edit is not allowed.";

/* The test modules: each needs an entry of its own. */
GDEFCORE_Module_Manifest g_man[3];
GDEFCORE_Module_Sub g_sub[3];
const char * g_names[3] = {"judge", "mute", "broken"};

template <int I>
const GDEFCORE_Module_Manifest * Entry() {
  return &g_man[I];
}
extern "C" const GDEFCORE_Module_Manifest * Entry0(void) { return Entry<0>(); }
extern "C" const GDEFCORE_Module_Manifest * Entry1(void) { return Entry<1>(); }
extern "C" const GDEFCORE_Module_Manifest * Entry2(void) { return Entry<2>(); }
GDEFCORE_Module_Entry g_entries[3] = {Entry0, Entry1, Entry2};

/* What the judge saw, and the classification it lets a principal edit. */
struct Judge {
  int calls = 0;
  std::string allowed;       /* the classification this principal may edit */
  std::string name;
  std::string kind;
  std::string old_kind;
  std::string attached;
  std::string attached_type;
  std::string classification;
  size_t size = 0;
};

std::string Span(const char * p, size_t n) { return std::string(p, n); }

/*
 * The refining module of the story: it denies edits of core.page templates
 * unless the template's classification matches the principal's grant, and has
 * no opinion about any other kind.
 */
extern "C" GDEFCORE_Result JudgeFn(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  Judge * j = (Judge *)user;
  const GDEFCORE_Template_Write_Hook * a =
      (const GDEFCORE_Template_Write_Hook *)args;
  (void)request;
  (void)alter;
  j->calls += 1;
  j->size = a->size;
  j->name = Span(a->name, a->name_len);
  j->kind = Span(a->kind, a->kind_len);
  j->old_kind = Span(a->old_kind, a->old_kind_len);
  j->attached = Span(a->attached, a->attached_len);
  j->attached_type = Span(a->attached_type, a->attached_type_len);
  j->classification = Span(a->classification, a->classification_len);
  out->decision = GDEFCORE_DECISION_NONE;
  if (j->kind == "core.page") {
    out->decision = j->classification == j->allowed ? GDEFCORE_DECISION_ALLOW
                                                    : GDEFCORE_DECISION_DENY;
  }
  return GDEFCORE_OK;
}

/* A subscriber with no opinion at all. */
extern "C" GDEFCORE_Result MuteFn(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  (void)request;
  (void)args;
  (void)alter;
  (void)out;
  *(int *)user += 1;
  return GDEFCORE_OK;
}

/* A subscriber that fails. */
extern "C" GDEFCORE_Result BrokenFn(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  (void)request;
  (void)args;
  (void)alter;
  (void)out;
  *(int *)user += 1;
  return GDEFCORE_ERR_INTERNAL;
}

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

class TPerm : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  GDEFCORE_Host * host_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  std::vector<GDEFCORE_Request *> requests_;
  Judge judge_;
  int mute_calls_ = 0;
  int broken_calls_ = 0;
  std::string refusal_;
  uint8_t tenant_[1] = {'t'};

  void SetUp() override {
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, tenant_, 1, NULL, NULL, &catalog_));
    gdefcore_catalog_bind_host(catalog_, host_);
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
  }

  void TearDown() override {
    for (GDEFCORE_Request * r : requests_) {
      gdefcore_request_destroy(r);
    }
    gdefcore_catalog_bind_host(catalog_, NULL);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_host_destroy(host_);
    gdefstor_store_destroy(store_);
  }

  /* People ------------------------------------------------------------- */

  /* A request for a new principal who holds one role with these labels. */
  GDEFCORE_Request * Who(const char * role, std::vector<std::string> kinds) {
    char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Request * request = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, role, strlen(role), NULL));
    for (const std::string & kind : kinds) {
      char * label = NULL;
      size_t label_len = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_template_edit_label(catalog_, kind.c_str(), kind.size(), &label,
              &label_len));
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_access_grant(catalog_, role, strlen(role), label, label_len,
              "core.role", 9));
      gdefcore_text_free(catalog_, label);
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, principal));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_principal_add_role(catalog_, principal,
            GDEFCORE_PUBLIC_ID_LEN, role, strlen(role)));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant_, 1, 0, 0, NULL, &request));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request, principal,
            GDEFCORE_PUBLIC_ID_LEN));
    requests_.push_back(request);
    return request;
  }

  GDEFCORE_Request * Anonymous() {
    GDEFCORE_Request * request = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant_, 1, 0, 0, NULL, &request));
    requests_.push_back(request);
    return request;
  }

  GDEFCORE_Request * Admin() {
    char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Request * request = Anonymous();
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request, admin, GDEFCORE_PUBLIC_ID_LEN));
    return request;
  }

  /* Modules ------------------------------------------------------------ */

  void Install(int slot, GDEFCORE_Hook_Fn fn, void * user) {
    memset(&g_man[slot], 0, sizeof g_man[slot]);
    memset(&g_sub[slot], 0, sizeof g_sub[slot]);
    g_sub[slot].size = sizeof g_sub[slot];
    g_sub[slot].hook = GDEFCORE_HOOK_TEMPLATE_WRITE;
    g_sub[slot].hook_len = strlen(GDEFCORE_HOOK_TEMPLATE_WRITE);
    g_sub[slot].kind = GDEFCORE_HOOK_DECISION;
    g_sub[slot].fn = fn;
    g_sub[slot].user = user;
    g_man[slot].size = sizeof g_man[slot];
    g_man[slot].core_token = kCoreToken;
    g_man[slot].core_token_len = strlen(kCoreToken);
    g_man[slot].name = g_names[slot];
    g_man[slot].name_len = strlen(g_names[slot]);
    g_man[slot].label = g_names[slot];
    g_man[slot].label_len = strlen(g_names[slot]);
    g_man[slot].subs = &g_sub[slot];
    g_man[slot].nsubs = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, g_entries[slot]));
  }

  void ModuleOn(const char * name, bool enable = true) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        enable ? gdefcore_module_enable(host_, cs, name, strlen(name))
               : gdefcore_module_disable(host_, cs, name, strlen(name)));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, name, strlen(name)));
    gdefcore_changeset_destroy(cs);
  }

  /* Entities ----------------------------------------------------------- */

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

  std::string FieldOf(const char * id, const char * field) {
    char ** vals = NULL;
    size_t * lens = NULL;
    size_t c = 0;
    std::string out = "!";
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id,
            GDEFCORE_PUBLIC_ID_LEN, "en", 2, field, strlen(field), &vals, &lens,
            &c) == GDEFCORE_OK) {
      out = c > 0 ? std::string(vals[0], lens[0]) : "";
      gdefcore_values_free(catalog_, vals, lens, c);
    }
    return out;
  }

  std::string Field(const char * type, const char * name, const char * field) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (!Find(type, name, id)) {
      return "!";
    }
    return FieldOf(id, field);
  }

  size_t Revisions(const char * name) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    size_t count = 0;
    if (!Find("core.template", name, id) ||
        gdefcore_entity_revision_count(catalog_, id, GDEFCORE_PUBLIC_ID_LEN,
            &count) != GDEFCORE_OK) {
      return 0;
    }
    return count;
  }

  /*
   * Save a template (new or existing) by changeset. With a request it is the
   * principal's write; with NULL it is the operator's.
   */
  GDEFCORE_Result Edit(const char * name, const std::string & body,
      const char * kind, GDEFCORE_Request * request,
      const char * classification = NULL, const char * attached = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[5];
    const char * slots[5] = {name, body.c_str(), kind, classification, attached};
    size_t lens[5] = {strlen(name), body.size(), strlen(kind),
        classification == NULL ? 0 : strlen(classification),
        attached == NULL ? 0 : strlen(attached)};
    size_t n = 3;
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
    if (classification != NULL) {
      OneValue(&values[n++], "classification", &slots[3], &lens[3]);
    }
    if (attached != NULL) {
      OneValue(&values[n++], "attached", &slots[4], &lens[4]);
    }
    rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    gdefcore_changeset_set_request(cs, request);
    rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, n);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, "core.template", 13);
    }
    size_t rn = 0;
    const char * r = gdefcore_changeset_refusal(cs, &rn);
    refusal_.assign(r == NULL ? "" : r, rn);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* Define a kind by changeset. */
  GDEFCORE_Result PutKind(const char * name, const char * label) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * slots[3] = {name, label, "1"};
    size_t lens[3] = {strlen(name), strlen(label), 1};
    GDEFCORE_Result rc =
        gdefcore_entity_create(catalog_, GDEFCORE_TEMPLATE_KIND_TYPE,
            sizeof GDEFCORE_TEMPLATE_KIND_TYPE - 1, id, NULL);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    OneValue(&values[0], "name", &slots[0], &lens[0]);
    OneValue(&values[1], "label", &slots[1], &lens[1]);
    OneValue(&values[2], "version", &slots[2], &lens[2]);
    rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 3);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, GDEFCORE_TEMPLATE_KIND_TYPE,
          sizeof GDEFCORE_TEMPLATE_KIND_TYPE - 1);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* The module a declared permission is grouped under, or "!". */
  std::string PermissionModule(const std::string & label) {
    char ** ids = NULL;
    size_t n = 0;
    std::string out = "!";
    if (gdefcore_entity_ids(catalog_, "core.permission", 15, &ids, &n) !=
        GDEFCORE_OK) {
      return out;
    }
    for (size_t i = 0; i < n; i++) {
      if (FieldOf(ids[i], "label") == label) {
        out = FieldOf(ids[i], "module");
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    return out;
  }
};

const std::string kPaneBody = "<% use title; %><h2><%= title %></h2>";

}  // namespace

/* -------------------------------------------------------------------- */
/* The permission a kind declares                                        */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, KindDeclaresItsPermission) {
  char * label = NULL;
  size_t label_len = 0;
  char name[300];
  GDEFCORE_Request * admin = Admin();
  /* The built-in kinds have theirs, with a plain-language label. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_edit_label(catalog_, "core.pane", 9, &label, &label_len));
  EXPECT_EQ("Edit templates of kind Pane", Span(label, label_len));
  EXPECT_EQ(std::string("core"), PermissionModule("Edit templates of kind Pane"));
  gdefcore_text_free(catalog_, label);
  EXPECT_EQ(std::string("core"),
      PermissionModule("Edit templates of kind Page layout"));
  ASSERT_GT(gdefcore_template_edit_name("core.pane", 9, name, sizeof name), 0u);
  EXPECT_STREQ("core.template.edit.core.pane", name);
  /* Granted to nobody, admin included. */
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, admin, "core.pane", 9));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, admin, "core.page", 9));
  EXPECT_EQ(0, gdefcore_access_permits(catalog_, admin, name, strlen(name)));
  /* A kind defined later by changeset declares its own, under its module. */
  ASSERT_EQ(GDEFCORE_OK, PutKind("blog.card", "Blog card"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_edit_label(catalog_, "blog.card", 9, &label, &label_len));
  EXPECT_EQ("Edit templates of kind Blog card", Span(label, label_len));
  EXPECT_EQ(std::string("blog"), PermissionModule(Span(label, label_len)));
  gdefcore_text_free(catalog_, label);
  /* A kind that does not exist has no permission to hold. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_template_edit_label(catalog_, "no.such", 7, &label, &label_len));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_template_kind_declare(catalog_, "no.such", 7));
  /* Declaring again changes nothing. */
  EXPECT_EQ(GDEFCORE_OK, gdefcore_template_kind_declare(catalog_, "core.pane", 9));
}

TEST_F(TPerm, GrantFlow) {
  /* The control for every "not allowed" below: a grant is what changes it. */
  GDEFCORE_Request * pane = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * nobody = Who("nobody", {});
  GDEFCORE_Request * admin = Admin();
  char name[300];
  EXPECT_EQ(1, gdefcore_template_may_edit(catalog_, pane, "core.pane", 9));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, pane, "core.page", 9));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, pane, "no.such", 7));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, nobody, "core.pane", 9));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, Anonymous(), "core.pane", 9));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, NULL, "core.pane", 9));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, admin, "core.pane", 9));
  /* The admin role is granted it by a changeset like anyone's, and then holds
   * it. */
  {
    char * label = NULL;
    size_t label_len = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_template_edit_label(catalog_, "core.pane", 9, &label,
            &label_len));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "admin", 5, label, label_len, "core.role",
            9));
    gdefcore_text_free(catalog_, label);
  }
  EXPECT_EQ(1, gdefcore_template_may_edit(catalog_, admin, "core.pane", 9));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, admin, "core.page", 9));
  ASSERT_GT(gdefcore_template_edit_name("core.pane", 9, name, sizeof name), 0u);
  EXPECT_EQ(1, gdefcore_access_permits(catalog_, admin, name, strlen(name)));
  EXPECT_EQ(0, gdefcore_access_permits(catalog_, admin, "core.template.edit.", 19));
  EXPECT_EQ(0, gdefcore_access_permits(catalog_, admin, "read", 4));
}

/* -------------------------------------------------------------------- */
/* The permission is checked on a template write                         */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, WriteNeedsThePermission) {
  GDEFCORE_Request * allowed = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * denied = Who("page-editors", {"core.page"});
  GDEFCORE_Request * nobody = Who("nobody", {});
  const std::string before = Field("core.template", "recent", "body");
  size_t revs = Revisions("recent");
  ASSERT_NE("!", before);
  /* No permission for the kind: refused, with the one fixed sentence, and
   * nothing is stored. A principal with another kind's permission is the same
   * as one with none. */
  for (GDEFCORE_Request * r : {denied, nobody}) {
    EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("recent", kPaneBody, "core.pane", r));
    EXPECT_EQ(kNotAllowed, refusal_);
    EXPECT_EQ(before, Field("core.template", "recent", "body"));
    EXPECT_EQ(revs, Revisions("recent"));
  }
  /* Control: the principal who holds it writes, and the body changed. */
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", allowed));
  EXPECT_EQ(kPaneBody, Field("core.template", "recent", "body"));
  EXPECT_EQ(revs + 1, Revisions("recent"));
  /* Control: the operator's changeset, with no request, is not asked. */
  ASSERT_EQ(GDEFCORE_OK,
      Edit("recent", kPaneBody + "<!-- op -->", "core.pane", NULL));
  EXPECT_EQ(kPaneBody + "<!-- op -->", Field("core.template", "recent", "body"));
}

TEST_F(TPerm, NewTemplateNeedsThePermissionOfItsKind) {
  GDEFCORE_Request * allowed = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * denied = Who("page-editors", {"core.page"});
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("card", kPaneBody, "core.pane", denied));
  EXPECT_FALSE(Find("core.template", "card", id) &&
               Field("core.template", "card", "body") != "");
  ASSERT_EQ(GDEFCORE_OK, Edit("card", kPaneBody, "core.pane", allowed));
  EXPECT_EQ(kPaneBody, Field("core.template", "card", "body"));
  /* A kind that does not exist is not a kind anyone may write to. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("odd", kPaneBody, "no.such", allowed));
}

TEST_F(TPerm, MovingNeedsBothKinds) {
  GDEFCORE_Request * only_new = Who("page-editors", {"core.page"});
  GDEFCORE_Request * only_old = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * both = Who("both", {"core.pane", "core.page"});
  const std::string plain = "<p>fixed</p>";
  /* A body both contracts accept, so that only the permission can refuse. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("recent", plain, "core.page", only_new));
  EXPECT_EQ("core.pane", Field("core.template", "recent", "kind"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("recent", plain, "core.page", only_old));
  EXPECT_EQ("core.pane", Field("core.template", "recent", "kind"));
  /* Control: with both, the move happens... */
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", plain, "core.page", both));
  EXPECT_EQ("core.page", Field("core.template", "recent", "kind"));
  EXPECT_EQ(plain, Field("core.template", "recent", "body"));
  /* ...and is checked against the new contract: `title` is not on a page's. */
  EXPECT_NE(GDEFCORE_OK, Edit("recent", kPaneBody, "core.page", both));
  EXPECT_EQ(plain, Field("core.template", "recent", "body"));
  EXPECT_NE(kNotAllowed, refusal_) << "a validation error, not a refusal";
}

TEST_F(TPerm, RevertIsChecked) {
  GDEFCORE_Request * allowed = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * denied = Who("nobody", {});
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const std::string original = Field("core.template", "recent", "body");
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", allowed));
  ASSERT_TRUE(Find("core.template", "recent", id));
  for (int pass = 0; pass < 2; pass++) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Request * r = pass == 0 ? denied : allowed;
    GDEFCORE_Result rc;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revert(catalog_, id, GDEFCORE_PUBLIC_ID_LEN, NULL, 0,
            &cs));
    gdefcore_changeset_set_request(cs, r);
    rc = gdefcore_changeset_apply(cs, "core.template", 13);
    gdefcore_changeset_destroy(cs);
    if (pass == 0) {
      EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
      EXPECT_EQ(kPaneBody, Field("core.template", "recent", "body"));
    } else {
      /* The control: the same revert, by a principal who may, is applied. */
      EXPECT_EQ(GDEFCORE_OK, rc);
      EXPECT_EQ(original, Field("core.template", "recent", "body"));
    }
  }
}

/* -------------------------------------------------------------------- */
/* The decision hook                                                     */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, ModuleDeniesPageTemplatesUnlessClassificationMatches) {
  GDEFCORE_Request * pages = Who("page-editors", {"core.page", "core.pane"});
  const std::string layout = Field("core.template", "layout", "body");
  const std::string edited = layout + "<!-- edit -->";
  char post[GDEFCORE_PUBLIC_ID_LEN + 1];
  /* Before the module is on, the permission alone decides (the control). */
  judge_.allowed = "public";
  Install(0, JudgeFn, &judge_);
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", edited, "core.page", pages, "internal"));
  EXPECT_EQ(0, judge_.calls) << "an installed but disabled module is not asked";
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", pages, "internal"));
  ModuleOn("judge");
  /* The classification does not match the principal's grant: refused. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", edited, "core.page", pages, "internal"));
  EXPECT_EQ(1, judge_.calls);
  EXPECT_EQ(kNotAllowed, refusal_);
  EXPECT_EQ(std::string::npos, refusal_.find("judge"))
      << "the module's name is not part of what the editor is told";
  EXPECT_EQ(layout, Field("core.template", "layout", "body"));
  /* What the hook is told. */
  EXPECT_GE(judge_.size, sizeof(GDEFCORE_Template_Write_Hook));
  EXPECT_EQ("layout", judge_.name);
  EXPECT_EQ("core.page", judge_.kind);
  EXPECT_EQ("core.page", judge_.old_kind);
  EXPECT_EQ("internal", judge_.classification);
  EXPECT_EQ("", judge_.attached);
  /* Control: when it matches, the same edit is allowed. */
  judge_.allowed = "internal";
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", edited, "core.page", pages, "internal"));
  EXPECT_EQ(edited, Field("core.template", "layout", "body"));
  EXPECT_EQ(2, judge_.calls);
  /* Control: a kind the module has no opinion about is not touched by it. */
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", pages));
  EXPECT_EQ("core.pane", judge_.kind);
  EXPECT_EQ(3, judge_.calls) << "the hook is asked about every template write";
  /* The entity a template is attached to is in the arguments. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.post", 9, post, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      Edit("recent", kPaneBody + " ", "core.pane", pages, "", post));
  EXPECT_EQ(post, judge_.attached);
  EXPECT_EQ("site.post", judge_.attached_type);
}

TEST_F(TPerm, AnyDenyWinsAndNoOpinionStands) {
  GDEFCORE_Request * pages = Who("page-editors", {"core.page", "core.pane"});
  const std::string layout = Field("core.template", "layout", "body");
  judge_.allowed = "public";
  Install(0, JudgeFn, &judge_);
  Install(1, MuteFn, &mute_calls_);
  ModuleOn("mute");
  /* Control: a subscriber with no opinion leaves the write standing. */
  ASSERT_EQ(GDEFCORE_OK,
      Edit("layout", layout + "<!-- 1 -->", "core.page", pages, "public"));
  EXPECT_EQ(1, mute_calls_);
  /* A second subscriber that denies wins over the one with no opinion, and
   * over an allow. */
  ModuleOn("judge");
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", layout + "<!-- 2 -->", "core.page", pages, "internal"));
  EXPECT_EQ(layout + "<!-- 1 -->", Field("core.template", "layout", "body"));
  /* Control: the judge allowing is not a deny. */
  ASSERT_EQ(GDEFCORE_OK,
      Edit("layout", layout + "<!-- 3 -->", "core.page", pages, "public"));
}

TEST_F(TPerm, FailingSubscriberFailsTheRequest) {
  GDEFCORE_Request * pane = Who("pane-editors", {"core.pane"});
  Install(2, BrokenFn, &broken_calls_);
  /* The control: the module is installed and not enabled, so it is not asked. */
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", pane));
  EXPECT_EQ(0, broken_calls_);
  ModuleOn("broken");
  GDEFCORE_Result rc = Edit("recent", kPaneBody + " ", "core.pane", pane);
  EXPECT_NE(GDEFCORE_OK, rc);
  EXPECT_EQ(1, broken_calls_);
  EXPECT_EQ(kPaneBody, Field("core.template", "recent", "body"));
  /* The operator's changeset has no request and no principal to ask about. */
  EXPECT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody + " ", "core.pane", NULL));
  EXPECT_EQ(1, broken_calls_);
}

TEST_F(TPerm, ASaveThatOmitsAFieldKeepsIt) {
  /* What an editor relies on: it saves name, body and kind, and the template's
   * classification, which it does not show, is still there afterwards. */
  GDEFCORE_Request * pane = Who("pane-editors", {"core.pane"});
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", NULL, "secret"));
  EXPECT_EQ("secret", Field("core.template", "recent", "classification"));
  ASSERT_EQ(GDEFCORE_OK,
      Edit("recent", kPaneBody + " ", "core.pane", pane));
  EXPECT_EQ("secret", Field("core.template", "recent", "classification"));
}

TEST_F(TPerm, AuthorizeCanBeAskedFirst) {
  GDEFCORE_Request * allowed = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * denied = Who("nobody", {});
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value values[3];
  const char * body = "<p>x</p>";
  const char * kind = "core.pane";
  const char * name = "recent";
  const char * slots[3] = {name, body, kind};
  size_t lens[3] = {strlen(name), strlen(body), strlen(kind)};
  ASSERT_TRUE(Find("core.template", "recent", id));
  OneValue(&values[0], "name", &slots[0], &lens[0]);
  OneValue(&values[1], "body", &slots[1], &lens[1]);
  OneValue(&values[2], "kind", &slots[2], &lens[2]);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 3));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_template_authorize(cs, allowed));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_template_authorize(cs, denied));
  size_t n = 0;
  const char * r = gdefcore_changeset_refusal(cs, &n);
  ASSERT_NE(nullptr, r);
  EXPECT_EQ(kNotAllowed, Span(r, n));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_template_authorize(cs, NULL));
  gdefcore_changeset_destroy(cs);
  /* A changeset that writes no template is nobody's business. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_template_authorize(cs, denied));
  gdefcore_changeset_destroy(cs);
}

/* -------------------------------------------------------------------- */
/* The render of an edited body                                          */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, SampleRenderIsGatedAndNeverShared) {
  GDEFCORE_Request * allowed = Who("pane-editors", {"core.pane", "core.page"});
  GDEFCORE_Request * denied = Who("nobody", {});
  char * out = NULL;
  size_t out_len = 0;
  int shareable = -1;
  uint64_t before;
  /* The body is rendered against sample data under the kind's contract. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_sample(catalog_, allowed, "core.pane", 9, kPaneBody.c_str(),
          kPaneBody.size(), "preview", 7, GDEFCORE_RENDER_PAGE_FUEL, &out,
          &out_len, &shareable));
  EXPECT_EQ("<h2>Sample title</h2>", Span(out, out_len));
  EXPECT_EQ(0, shareable);
  gdefcore_text_free(catalog_, out);
  /* A page layout gets a stand-in for each region. */
  {
    const std::string page = "<% use region; %><main><%= region(\"main\") %></main>";
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_render_sample(catalog_, allowed, "core.page", 9, page.c_str(),
            page.size(), "preview", 7, GDEFCORE_RENDER_PAGE_FUEL, &out, &out_len,
            NULL));
    EXPECT_NE(std::string::npos, Span(out, out_len).find("Sample region main"));
    gdefcore_text_free(catalog_, out);
  }
  /* The value is bound escaped: sample text is inert like any bound value. */
  /* The principal who may not edit the kind gets what a missing kind gets. */
  out = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_render_sample(catalog_, denied, "core.pane", 9, kPaneBody.c_str(),
          kPaneBody.size(), "preview", 7, GDEFCORE_RENDER_PAGE_FUEL, &out,
          &out_len, &shareable));
  EXPECT_EQ(nullptr, out);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_render_sample(catalog_, allowed, "no.such", 7, "x", 1, "preview", 7,
          GDEFCORE_RENDER_PAGE_FUEL, &out, &out_len, NULL));
  /* A body that does not parse writes no bytes. */
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_render_sample(catalog_, allowed, "core.pane", 9, "<% if %>", 8,
          "preview", 7, GDEFCORE_RENDER_PAGE_FUEL, &out, &out_len, NULL));
  EXPECT_EQ(nullptr, out);
  /* Nothing was written: the stored templates are as the kit left them. */
  EXPECT_NE(kPaneBody, Field("core.template", "recent", "body"));
  /* The shared-cache count does not move for a preview... */
  before = gdefcore_render_shareable_count();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_sample(catalog_, allowed, "core.pane", 9, kPaneBody.c_str(),
          kPaneBody.size(), "preview", 7, GDEFCORE_RENDER_PAGE_FUEL, &out,
          &out_len, &shareable));
  gdefcore_text_free(catalog_, out);
  EXPECT_EQ(before, gdefcore_render_shareable_count());
  EXPECT_EQ(0, shareable);
  /* ...and it is the counter's own instrument that is moving when the same
   * render is offered under the live overlay (the control), or an empty one. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_sample(catalog_, allowed, "core.pane", 9, kPaneBody.c_str(),
          kPaneBody.size(), "live", 4, GDEFCORE_RENDER_PAGE_FUEL, &out, &out_len,
          &shareable));
  gdefcore_text_free(catalog_, out);
  EXPECT_EQ(before + 1, gdefcore_render_shareable_count());
  EXPECT_EQ(1, shareable);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_sample(catalog_, allowed, "core.pane", 9, kPaneBody.c_str(),
          kPaneBody.size(), NULL, 0, GDEFCORE_RENDER_PAGE_FUEL, &out, &out_len,
          &shareable));
  gdefcore_text_free(catalog_, out);
  EXPECT_EQ(before + 2, gdefcore_render_shareable_count());
  /* A real page render of a stored template moves it too. */
  {
    GDEFCORE_Routes * routes = NULL;
    uint64_t at = gdefcore_render_shareable_count();
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_render_page(catalog_, routes, Anonymous(), "/", 1,
            GDEFCORE_RENDER_PAGE_FUEL, &out, &out_len));
    gdefcore_text_free(catalog_, out);
    gdefcore_routes_destroy(routes);
    EXPECT_GT(gdefcore_render_shareable_count(), at);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
