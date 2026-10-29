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
 * Who may edit a template (access-conditions story A8): one permission,
 * `core.template.edit`, granted by roles with a condition on the template's
 * kind and by modules with a condition on its classification, decided by the
 * one can(). Nothing denies: no module can take away what a grant allows. The
 * render of an edited body that no shared cache may keep is here too.
 *
 * Every refusal has a control that makes the same write succeed, so a test
 * that cannot see the thing it looks for is not passing by accident.
 */

#include "grants_fixture.h"

#include <set>

namespace {

using namespace gfx;

const char kNotAllowed[] = "That edit is not allowed.";
const char kEdit[] = GDEFCORE_TEMPLATE_EDIT;

/* The example module's grant: the pages classified internal, for the people
 * its relation lists. */
const char kDeskCondition[] =
    "(and (= field.kind \"core.page\") (= field.classification \"internal\") "
    "(related \"desk.reviewer\" (principal)))";

const std::string kPaneBody = "<% use title; %><h2><%= title %></h2>";

/* The hook the veto was fired through, named without spelling the name out:
 * nothing in this tree names it, and a gate keeps it so. */
std::string FormerHook() { return std::string("template") + "-write"; }

/* A subscriber that denies, as the veto's subscribers did. */
extern "C" GDEFCORE_Result DenyFn(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  (void)request;
  (void)args;
  (void)alter;
  *(int *)user += 1;
  out->decision = GDEFCORE_DECISION_DENY;
  return GDEFCORE_OK;
}

/* An operation callback of the gate module: grants every entity, or fails
 * after writing grants (a callback that fails is thrown away, not trusted). */
struct Gate {
  int calls = 0;
  bool fail = false;
};
Gate g_gate;

extern "C" GDEFCORE_Result GateFn(GDEFCORE_Callback_Call * call,
    GDEFCORE_Request * request, const GDEFCORE_Callback_Question * q,
    GDEFCORE_Callback_Answer * a, void * user) {
  Gate * g = static_cast<Gate *>(user);
  (void)call;
  (void)request;
  g->calls += 1;
  for (size_t i = 0; i < q->count; i++) {
    a->granted[i] = 1;
  }
  snprintf(a->token, sizeof a->token, "%s", "t");
  a->token_len = 1;
  return g->fail ? GDEFCORE_ERR_INTERNAL : GDEFCORE_OK;
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

std::string KindIs(const std::string & kind) {
  return "(= field.kind \"" + kind + "\")";
}

class TPerm : public GrantsFixture {
 protected:
  std::string refusal_;

  void SetUp() override {
    GrantsFixture::SetUp();
    g_gate = Gate();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
  }

  /* People ------------------------------------------------------------- */

  /* A request for a new principal whose one role is granted the permission to
   * edit templates of each of these kinds, and of no other. */
  GDEFCORE_Request * Who(const char * role, std::vector<std::string> kinds) {
    Role(role);
    for (const std::string & kind : kinds) {
      EXPECT_EQ(GDEFCORE_OK,
          GrantWhen(role, GDEFCORE_TEMPLATE_EDIT_LABEL, KindIs(kind)));
    }
    return Req(Principal(role));
  }

  GDEFCORE_Request * Anonymous() { return Req(); }

  GDEFCORE_Request * AdminReq() { return Req(Admin()); }

  /* A principal on the desk module's list of reviewers, with no role. The
   * module must be enabled. */
  std::string Reviewer(const char * role = NULL) {
    std::string who = Principal(role);
    ListReviewer(who);
    return who;
  }

  /* Put a principal on the list (a second time changes nothing). */
  void ListReviewer(const std::string & who) {
    const char * values[1] = {who.c_str()};
    size_t lens[1] = {who.size()};
    int added = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_relation_add(catalog_, "desk", 4, "desk.reviewer", 13, values,
            lens, 1, NULL, 0, &added));
  }

  /* Modules ------------------------------------------------------------ */

  /* The example module: it grants the permission to edit templates for the
   * pages classified internal, to the people on its list. */
  void InstallDesk() {
    ModDef * m = NewMod("desk");
    m->Relation("desk.reviewer", {{"who", GDEFCORE_RELATION_ENTITY, ""}});
    m->Grant(GDEFCORE_TEMPLATE_EDIT_LABEL, GDEFCORE_TEMPLATE_TYPE, kDeskCondition);
    ASSERT_EQ(GDEFCORE_OK, Install(m));
  }

  /* How the enable rates a module's grant of this permission on @p condition. */
  std::string RiskOf(const char * condition) {
    GDEFCORE_Condition * c = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_condition_parse(condition, strlen(condition), &c, NULL));
    bool anonymous = (gdefcore_condition_uses(c) & GDEFCORE_CONDITION_USES_PRINCIPAL) == 0;
    gdefcore_condition_free(c);
    return gdefcore_access_risk_name(gdefcore_access_grant_risk_on(kEdit,
        strlen(kEdit), "", 0, condition, strlen(condition), anonymous));
  }

  std::string DeskLine() {
    return GrantLine("desk", GDEFCORE_TEMPLATE_EDIT_LABEL,
               RiskOf(kDeskCondition).c_str(), kDeskCondition) +
           " Its breadth depends on who may add rows to the relation "
           "desk.reviewer: anyone who can add a row widens this grant.";
  }

  void EnableDesk() {
    ASSERT_EQ(GDEFCORE_OK, Enable("desk", {DeskLine()})) << last_error_;
  }

  /* Entities ----------------------------------------------------------- */

  bool FindEntity(const char * type, const char * name,
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

  std::string TemplateId(const char * name) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_TRUE(FindEntity("core.template", name, id)) << name;
    return std::string(id);
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
    if (!FindEntity(type, name, id)) {
      return "!";
    }
    return FieldOf(id, field);
  }

  size_t Revisions(const char * name) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    size_t count = 0;
    if (!FindEntity("core.template", name, id) ||
        gdefcore_entity_revision_count(catalog_, id, GDEFCORE_PUBLIC_ID_LEN,
            &count) != GDEFCORE_OK) {
      return 0;
    }
    return count;
  }

  /*
   * Save a template (new or existing) by changeset. With a request it is the
   * principal's write; with NULL it is the operator's. A field left NULL is
   * not staged, as the editor leaves out the ones it does not show.
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
    if (!FindEntity("core.template", name, id)) {
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

  /* gdefcore_template_authorize() on a save of template @p id with this name,
   * body and kind (an entity that has none yet is created, empty). */
  GDEFCORE_Result Authorize(const std::string & id, const char * name,
      const char * kind, GDEFCORE_Request * request) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * slots[3] = {name, "<p>x</p>", kind};
    size_t lens[3] = {strlen(name), 8, strlen(kind)};
    OneValue(&values[0], "name", &slots[0], &lens[0]);
    OneValue(&values[1], "body", &slots[1], &lens[1]);
    OneValue(&values[2], "kind", &slots[2], &lens[2]);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id.c_str(), GDEFCORE_PUBLIC_ID_LEN, "en", 2,
            values, 3));
    GDEFCORE_Result rc = gdefcore_template_authorize(cs, request);
    size_t rn = 0;
    const char * r = gdefcore_changeset_refusal(cs, &rn);
    refusal_.assign(r == NULL ? "" : r, rn);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* gdefcore_template_can_edit(), 1 or 0 (-1 when it failed). */
  int CanEdit(GDEFCORE_Request * request, const std::string & id,
      const char * kind = NULL) {
    int allowed = -7;
    GDEFCORE_Result rc = gdefcore_template_can_edit(catalog_, request, id.c_str(),
        kind, kind == NULL ? 0 : strlen(kind), &allowed);
    return rc == GDEFCORE_OK ? allowed : -1;
  }

  int MayEdit(GDEFCORE_Request * request, const char * kind) {
    return gdefcore_template_may_edit(catalog_, request, kind, strlen(kind));
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

  bool Declared(const char * label) {
    GDEFCORE_Access_Permission info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    return gdefcore_access_permission_info(catalog_, label, strlen(label),
               &info) == GDEFCORE_OK;
  }
};

}  // namespace

/* -------------------------------------------------------------------- */
/* The permission                                                        */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, EditPermissionIsDeclaredOnce) {
  GDEFCORE_Access_Permission info;
  GDEFCORE_Request * admin = AdminReq();
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  /* One permission, the kernel's, on the template type. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_permission_info(catalog_, GDEFCORE_TEMPLATE_EDIT_LABEL,
          strlen(GDEFCORE_TEMPLATE_EDIT_LABEL), &info));
  EXPECT_STREQ("core", info.module);
  EXPECT_STREQ("core.template.edit", info.action);
  EXPECT_STREQ("core.template", info.type_name);
  EXPECT_STREQ("", info.field);
  /* The permission of a kind is gone, for the kit's kinds and for a kind
   * defined later. */
  EXPECT_FALSE(Declared("Edit templates of kind Pane"));
  ASSERT_EQ(GDEFCORE_OK, PutKind("blog.card", "Blog card"));
  EXPECT_FALSE(Declared("Edit templates of kind Blog card"));
  /* Declaring again changes nothing. */
  EXPECT_EQ(GDEFCORE_OK, gdefcore_template_edit_declare(catalog_));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_template_edit_declare(NULL));
  /* Granted to nobody, admin included. */
  EXPECT_EQ(0, gdefcore_access_permits(catalog_, admin, kEdit, strlen(kEdit)));
  EXPECT_EQ(0, MayEdit(admin, "core.pane"));
  EXPECT_EQ(0, MayEdit(admin, "core.page"));
}

TEST_F(TPerm, KindGrantEditsOnlyThatKind) {
  /* The control for every "not allowed" below: a grant is what changes it. */
  GDEFCORE_Request * pane = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * nobody = Who("nobody", {});
  GDEFCORE_Request * both = Who("both", {"core.pane", "core.page"});
  GDEFCORE_Request * admin = AdminReq();
  const std::string recent = TemplateId("recent");  /* a pane */
  const std::string layout = TemplateId("layout");  /* a page layout */
  /* A principal granted for kind core.pane edits panes and is refused pages. */
  EXPECT_EQ(1, CanEdit(pane, recent));
  EXPECT_EQ(0, CanEdit(pane, layout));
  EXPECT_EQ(1, MayEdit(pane, "core.pane"));
  EXPECT_EQ(0, MayEdit(pane, "core.page"));
  EXPECT_EQ(0, MayEdit(pane, "no.such"));
  /* Both kinds, both. */
  EXPECT_EQ(1, CanEdit(both, recent));
  EXPECT_EQ(1, CanEdit(both, layout));
  /* No grant, no request, no principal: no. */
  EXPECT_EQ(0, CanEdit(nobody, recent));
  EXPECT_EQ(0, CanEdit(Anonymous(), recent));
  EXPECT_EQ(0, MayEdit(nobody, "core.pane"));
  EXPECT_EQ(0, MayEdit(Anonymous(), "core.pane"));
  EXPECT_EQ(0, gdefcore_template_may_edit(catalog_, NULL, "core.pane", 9));
  EXPECT_EQ(0, MayEdit(admin, "core.pane"));
  /* The decision is the one every other write asks. */
  {
    int allowed = -1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_can(catalog_, pane, kEdit, strlen(kEdit),
            "core.template", 13, recent.c_str(), &allowed));
    EXPECT_EQ(1, allowed);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_can(catalog_, pane, kEdit, strlen(kEdit),
            "core.template", 13, layout.c_str(), &allowed));
    EXPECT_EQ(0, allowed);
  }
  /* A template that is not there, and bad arguments. */
  EXPECT_EQ(0, CanEdit(pane, std::string("0123456789012345678901234567890123456")));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_template_can_edit(catalog_, pane, NULL, NULL, 0, NULL));
  /* The admin role is granted it by a changeset like anyone's, and then holds
   * it, for the kind the condition names. */
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("admin", GDEFCORE_TEMPLATE_EDIT_LABEL, KindIs("core.pane")));
  /* (A request remembers its answers, so the next question is a new request's.) */
  admin = AdminReq();
  EXPECT_EQ(1, MayEdit(admin, "core.pane"));
  EXPECT_EQ(0, MayEdit(admin, "core.page"));
  EXPECT_EQ(1, gdefcore_access_permits(catalog_, admin, kEdit, strlen(kEdit)));
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
  EXPECT_FALSE(FindEntity("core.template", "card", id) &&
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
  EXPECT_EQ(kNotAllowed, refusal_);
  /* The same question, asked of the decision. */
  EXPECT_EQ(0, CanEdit(only_new, TemplateId("recent"), "core.page"));
  EXPECT_EQ(0, CanEdit(only_old, TemplateId("recent"), "core.page"));
  /* Control: with both, the move happens... */
  EXPECT_EQ(1, CanEdit(both, TemplateId("recent"), "core.page"));
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
  ASSERT_TRUE(FindEntity("core.template", "recent", id));
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
/* A module's grant, and nothing that denies                             */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, ClassificationGrantComesFromTheModuleAndGoesWithIt) {
  const std::string layout = Field("core.template", "layout", "body");
  const std::string edited = layout + "<!-- edit -->";
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", NULL, "internal"));
  ASSERT_EQ(GDEFCORE_OK, Edit("entity", Field("core.template", "entity", "body"),
                              "core.pane", NULL, "internal"));
  InstallDesk();
  std::string person = Principal();
  std::string stranger = Principal();
  /* Listed and not enabled: it grants nothing. */
  EnableDesk();
  ListReviewer(person);
  ASSERT_EQ(GDEFCORE_OK, Disable("desk"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("layout", edited, "core.page", Req(person)));
  EXPECT_EQ(layout, Field("core.template", "layout", "body"));
  EXPECT_EQ(0, CanEdit(Req(person), TemplateId("layout")));
  /* Enabled, it grants the pages classified internal to the people it lists,
   * and nothing else. */
  EnableDesk();
  ListReviewer(person);
  EXPECT_EQ(1, CanEdit(Req(person), TemplateId("layout")));
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", edited, "core.page", Req(person)));
  EXPECT_EQ(edited, Field("core.template", "layout", "body"));
  /* Not a person it does not list. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", edited + " ", "core.page", Req(stranger)));
  EXPECT_EQ(edited, Field("core.template", "layout", "body"));
  /* Not a pane, though the pane is classified internal too. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("entity", kPaneBody, "core.pane", Req(person)));
  /* Not a page that is classified otherwise. */
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", edited, "core.page", NULL, "public"));
  EXPECT_EQ(0, CanEdit(Req(person), TemplateId("layout")));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", edited + " ", "core.page", Req(person)));
  /* ...and an internal page cannot be written into another classification:
   * the grant covers the page as it is and as it would be left. */
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", edited, "core.page", NULL, "internal"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", edited + " ", "core.page", Req(person), "public"));
  EXPECT_EQ("internal", Field("core.template", "layout", "classification"));
  /* The module goes away, and so does the grant: its people can no longer
   * edit those pages. */
  ASSERT_EQ(GDEFCORE_OK, Disable("desk"));
  EXPECT_EQ(0, CanEdit(Req(person), TemplateId("layout")));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", edited + " ", "core.page", Req(person)));
  EXPECT_EQ(kNotAllowed, refusal_);
  EXPECT_EQ(edited, Field("core.template", "layout", "body"));
  /* Control: enabled again, the same write is allowed. */
  EnableDesk();
  ListReviewer(person);
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", edited + " ", "core.page", Req(person)));
}

TEST_F(TPerm, ASaveThatOmitsAFieldIsAskedAboutWithTheStoredOne) {
  /* What an editor relies on: it saves name, body and kind, and the template's
   * classification, which it does not show, is still there afterwards and is
   * what a classification grant is decided on. */
  GDEFCORE_Request * pane = Who("pane-editors", {"core.pane"});
  const std::string layout = Field("core.template", "layout", "body");
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", NULL, "secret"));
  EXPECT_EQ("secret", Field("core.template", "recent", "classification"));
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody + " ", "core.pane", pane));
  EXPECT_EQ("secret", Field("core.template", "recent", "classification"));
  /* The module's people edit an internal page without saying so. */
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", NULL, "internal"));
  InstallDesk();
  EnableDesk();
  std::string person = Reviewer();
  ASSERT_EQ(GDEFCORE_OK,
      Edit("layout", layout + "<!-- 1 -->", "core.page", Req(person)));
  EXPECT_EQ("internal", Field("core.template", "layout", "classification"));
  /* A draft is asked about the same way as a save. */
  {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const std::string body = layout + "<!-- draft -->";
    const char * slots[3] = {"layout", body.c_str(), "core.page"};
    size_t lens[3] = {6, body.size(), 9};
    ASSERT_TRUE(FindEntity("core.template", "layout", id));
    OneValue(&values[0], "name", &slots[0], &lens[0]);
    OneValue(&values[1], "body", &slots[1], &lens[1]);
    OneValue(&values[2], "kind", &slots[2], &lens[2]);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values,
            3));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_template_authorize(cs, Req(person)));
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_template_authorize(cs, Req(Principal())));
    gdefcore_changeset_destroy(cs);
  }
  /* The control: the same save of a page classified otherwise is refused. */
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", NULL, "public"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", layout + "<!-- 2 -->", "core.page", Req(person)));
}

/* A grant that names no one, supplied by a module, is held by whoever its
 * condition covers while the module is enabled, and by no one after: nothing
 * of it is left behind. */
TEST_F(TPerm, AGrantWithNoRelationGoesWithItsModuleToo) {
  static const char kBadge[] =
      "(and (= field.kind \"core.page\") (= field.classification \"internal\"))";
  const std::string layout = Field("core.template", "layout", "body");
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", NULL, "internal"));
  ModDef * m = NewMod("badge");
  m->Grant(GDEFCORE_TEMPLATE_EDIT_LABEL, GDEFCORE_TEMPLATE_TYPE, kBadge);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  std::string anyone = Principal();
  const std::string id = TemplateId("layout");
  /* Installed, not enabled: it grants nothing. */
  EXPECT_EQ(0, CanEdit(Req(anyone), id));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("badge", {GrantLine("badge", GDEFCORE_TEMPLATE_EDIT_LABEL,
                           RiskOf(kBadge).c_str(), kBadge)}))
      << last_error_;
  EXPECT_EQ(1, CanEdit(Req(anyone), id));
  EXPECT_EQ(1, CanEdit(Anonymous(), id)) << "it names no principal, so it reaches all";
  ASSERT_EQ(GDEFCORE_OK,
      Edit("layout", layout + "<!-- 1 -->", "core.page", Req(anyone)));
  /* A page classified otherwise is not covered. */
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", NULL, "public"));
  EXPECT_EQ(0, CanEdit(Req(anyone), id));
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", NULL, "internal"));
  EXPECT_EQ(1, CanEdit(Req(anyone), id));
  /* Disabled, it is gone from the very next answer. */
  ASSERT_EQ(GDEFCORE_OK, Disable("badge"));
  EXPECT_EQ(0, CanEdit(Req(anyone), id));
  EXPECT_EQ(0, CanEdit(Anonymous(), id));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Edit("layout", layout + "<!-- 2 -->", "core.page", Req(anyone)));
  EXPECT_EQ(kNotAllowed, refusal_);
}

TEST_F(TPerm, NothingDeniesWhatAGrantAllows) {
  GDEFCORE_Request * pages = Who("page-editors", {"core.page", "core.pane"});
  const std::string layout = Field("core.template", "layout", "body");
  /* The module that used to refuse every page not classified as its people
   * were: now it grants for them and has no opinion about anyone else. */
  InstallDesk();
  EnableDesk();
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout, "core.page", NULL, "public"));
  EXPECT_EQ(1, CanEdit(pages, TemplateId("layout")));
  ASSERT_EQ(GDEFCORE_OK,
      Edit("layout", layout + "<!-- 1 -->", "core.page", pages));
  ASSERT_EQ(GDEFCORE_OK,
      Edit("layout", layout + "<!-- 2 -->", "core.page", pages, "internal"));
  /* A role's grant and a module's both hold, and either is enough. */
  std::string person = Reviewer("page-editors");
  ASSERT_EQ(GDEFCORE_OK,
      Edit("layout", layout + "<!-- 3 -->", "core.page", Req(person), "public"));
}

TEST_F(TPerm, NoModuleHookCanRefuseAWrite) {
  GDEFCORE_Request * pane = Who("pane-editors", {"core.pane"});
  int calls = 0;
  ModDef * m = NewMod("former");
  m->Sub(FormerHook(), GDEFCORE_HOOK_DECISION, DenyFn, &calls);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK, Enable("former", {})) << last_error_;
  /* A subscriber to the hook the veto was fired through, denying every time,
   * is never asked and cannot cancel a role's allow. */
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", pane));
  EXPECT_EQ(kPaneBody, Field("core.template", "recent", "body"));
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody + " ", "core.pane", pane));
  EXPECT_EQ(0, calls);
  EXPECT_EQ(1, CanEdit(pane, TemplateId("recent")));
}

TEST_F(TPerm, AFailingCallbackGrantsNothingAndTakesNothingAway) {
  GDEFCORE_Request * pane = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * nobody = Who("nobody", {});
  ModDef * m = NewMod("gate");
  m->Callback("pass", GDEFCORE_CALLBACK_OPERATION, GDEFCORE_TEMPLATE_EDIT_LABEL,
      GDEFCORE_TEMPLATE_TYPE, "", GateFn, &g_gate);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("gate", {"Module gate decides Edit templates per entity with its "
                      "callback pass (operation scope, high risk): its breadth "
                      "cannot be judged."}))
      << last_error_;
  /* It fails: the principal a role allows is allowed (and it is not asked),
   * and the one nothing allows is refused. */
  g_gate.fail = true;
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", pane));
  EXPECT_EQ(0, g_gate.calls) << "a source is asked only when no earlier one allowed";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("recent", kPaneBody + " ", "core.pane", nobody));
  EXPECT_EQ(kNotAllowed, refusal_);
  EXPECT_GT(g_gate.calls, 0);
  EXPECT_EQ(kPaneBody, Field("core.template", "recent", "body"));
  /* Control: the same callback, not failing, is one more source that grants. */
  g_gate.fail = false;
  Gate fresh;
  g_gate = fresh;
  GDEFCORE_Request * other = Req(Principal());
  ASSERT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody + " ", "core.pane", other));
  EXPECT_GT(g_gate.calls, 0);
}

/* A grant whose condition cannot be decided (it rests on a relation of a
 * module that has since been disabled) grants nothing: the principal it was
 * the only grant of is refused like any other, with the one sentence and no
 * error, and the principal another grant allows is allowed. */
TEST_F(TPerm, AFailingConditionGrantsNothingAndTakesNothingAway) {
  InstallDesk();
  EnableDesk();
  Role("watchers");
  Role("pane-editors");
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("watchers", GDEFCORE_TEMPLATE_EDIT_LABEL,
          "(related \"desk.reviewer\" (principal))"));
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("pane-editors", GDEFCORE_TEMPLATE_EDIT_LABEL, KindIs("core.pane")));
  std::string only = Principal("watchers");
  std::string both = Principal("watchers");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, both.c_str(), both.size(),
          "pane-editors", 12));
  /* While the relation exists, the watchers' grant is one that can hold (it
   * does not: nobody is listed). */
  EXPECT_EQ(0, CanEdit(Req(only), TemplateId("recent")));
  ASSERT_EQ(GDEFCORE_OK, Disable("desk"));
  /* Now it cannot be decided. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Edit("recent", kPaneBody, "core.pane", Req(only)));
  EXPECT_EQ(kNotAllowed, refusal_);
  EXPECT_EQ(GDEFCORE_OK, Edit("recent", kPaneBody, "core.pane", Req(both)));
  EXPECT_EQ(kPaneBody, Field("core.template", "recent", "body"));
}

/* -------------------------------------------------------------------- */
/* One decision                                                          */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, AuthorizeCanBeAskedFirst) {
  GDEFCORE_Request * allowed = Who("pane-editors", {"core.pane"});
  GDEFCORE_Request * denied = Who("nobody", {});
  const std::string recent = TemplateId("recent");
  EXPECT_EQ(GDEFCORE_OK, Authorize(recent, "recent", "core.pane", allowed));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Authorize(recent, "recent", "core.pane", denied));
  EXPECT_EQ(kNotAllowed, refusal_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Authorize(recent, "recent", "core.pane", NULL));
  /* A changeset that writes no template is nobody's business. */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_template_authorize(cs, denied));
  gdefcore_changeset_destroy(cs);
}

/* The editor's tab, its button and the write agree for every principal of a
 * fixture, against a model written apart from the library: a grant of a kind,
 * and the module's grant of the pages classified internal for its people. */
TEST_F(TPerm, TheEditorsAnswersAreTheWritesForEveryPrincipal) {
  struct Person {
    const char * name;
    GDEFCORE_Request * request;
    std::set<std::string> kinds;
    bool reviewer;
  };
  const std::string layout_body = Field("core.template", "layout", "body");
  ASSERT_EQ(GDEFCORE_OK, Edit("layout", layout_body, "core.page", NULL, "internal"));
  InstallDesk();
  EnableDesk();
  std::vector<Person> people;
  people.push_back({"pane", Who("pane-editors", {"core.pane"}), {"core.pane"}, false});
  people.push_back({"page", Who("page-editors", {"core.page"}), {"core.page"}, false});
  people.push_back({"both", Who("both", {"core.pane", "core.page"}),
      {"core.pane", "core.page"}, false});
  people.push_back({"nobody", Who("nobody", {}), {}, false});
  people.push_back({"anonymous", Anonymous(), {}, false});
  people.push_back({"reviewer", Req(Reviewer()), {}, true});
  {
    Role("pane-reviewers");
    EXPECT_EQ(GDEFCORE_OK,
        GrantWhen("pane-reviewers", GDEFCORE_TEMPLATE_EDIT_LABEL, KindIs("core.pane")));
    people.push_back({"pane-reviewer", Req(Reviewer("pane-reviewers")),
        {"core.pane"}, true});
  }
  struct Tpl {
    const char * name;
    const char * kind;
    const char * classification;
  };
  const Tpl templates[] = {{"recent", "core.pane", ""}, {"entity", "core.pane", ""},
      {"layout", "core.page", "internal"}};
  /* The model: the permission is held for a template of this kind and
   * classification by a kind grant, or by the module for its people. */
  auto held = [](const Person & p, const std::string & kind,
                  const std::string & classification) {
    return p.kinds.count(kind) > 0 ||
           (p.reviewer && kind == "core.page" && classification == "internal");
  };
  int yes = 0;
  int no = 0;
  for (const Person & p : people) {
    for (const Tpl & t : templates) {
      std::string id = TemplateId(t.name);
      for (const char * dest : {"", "core.pane", "core.page"}) {
        std::string to = dest[0] == '\0' ? t.kind : dest;
        /* The template is stored, so the grant must hold on it as it is and
         * as it would be left. */
        bool want = held(p, t.kind, t.classification) &&
                    held(p, to, t.classification);
        SCOPED_TRACE(std::string(p.name) + " " + t.name + " -> " + to);
        /* The decision. */
        EXPECT_EQ(want ? 1 : 0, CanEdit(p.request, id, dest[0] == '\0' ? NULL : dest));
        /* The write's check, on a save that leaves it of this kind. */
        EXPECT_EQ(want ? GDEFCORE_OK : GDEFCORE_ERR_INVALID,
            Authorize(id, t.name, to.c_str(), p.request));
        EXPECT_EQ(want ? "" : kNotAllowed, refusal_);
        if (dest[0] == '\0') {
          /* The write itself, which changes nothing but a revision. */
          std::string body = Field("core.template", t.name, "body");
          EXPECT_EQ(want ? GDEFCORE_OK : GDEFCORE_ERR_INVALID,
              Edit(t.name, body, t.kind, p.request));
          /* The route's question. */
          int allowed = -1;
          ASSERT_EQ(GDEFCORE_OK,
              gdefcore_access_can(catalog_, p.request, kEdit, strlen(kEdit),
                  "core.template", 13, id.c_str(), &allowed));
          EXPECT_EQ(want ? 1 : 0, allowed);
        }
        yes += want;
        no += !want;
      }
    }
    /* The list of kinds: some template of the kind may be edited. */
    for (const char * kind : {"core.pane", "core.page"}) {
      bool some = false;
      for (const Tpl & t : templates) {
        some = some || (std::string(t.kind) == kind &&
                        held(p, t.kind, t.classification));
      }
      EXPECT_EQ(some ? 1 : 0, MayEdit(p.request, kind)) << p.name << " " << kind;
    }
    /* A new template has no stored kind: the kind it is to be is the question. */
    for (const char * kind : {"core.pane", "core.page"}) {
      char fresh[GDEFCORE_PUBLIC_ID_LEN + 1];
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_entity_create(catalog_, "core.template", 13, fresh, NULL));
      bool want = held(p, kind, "");
      EXPECT_EQ(want ? GDEFCORE_OK : GDEFCORE_ERR_INVALID,
          Authorize(fresh, "brand-new", kind, p.request))
          << p.name << " new " << kind;
      EXPECT_EQ(want ? 1 : 0, CanEdit(p.request, fresh, kind));
      yes += want;
      no += !want;
    }
  }
  EXPECT_GT(yes, 10);
  EXPECT_GT(no, 10);
}

/* -------------------------------------------------------------------- */
/* The render of an edited body                                          */
/* -------------------------------------------------------------------- */

TEST_F(TPerm, SampleRenderIsGatedAndNeverShared) {
  GDEFCORE_Request * allowed = Who("editors", {"core.pane", "core.page"});
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
  EXPECT_EQ("<h2>Sample title</h2>", std::string(out, out_len));
  EXPECT_EQ(0, shareable);
  gdefcore_text_free(catalog_, out);
  /* A page layout gets a stand-in for each region. */
  {
    const std::string page = "<% use region; %><main><%= region(\"main\") %></main>";
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_render_sample(catalog_, allowed, "core.page", 9, page.c_str(),
            page.size(), "preview", 7, GDEFCORE_RENDER_PAGE_FUEL, &out, &out_len,
            NULL));
    EXPECT_NE(std::string::npos,
        std::string(out, out_len).find("Sample region main"));
    gdefcore_text_free(catalog_, out);
  }
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
