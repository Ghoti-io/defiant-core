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
 * Callbacks and grants (access-conditions story A7, part 1): what happens to
 * a stored grant whose condition names a field a module later decides by
 * callback, how a role's grants, a module's grants and the callbacks of
 * several modules combine, and which of them allowed a decision.
 *
 * The suspended grants: enabling such a module lists the grants it would
 * suspend and needs a typed confirmation that names them; afterwards the
 * matrix shows them as suspended by every module that decides the field, and
 * they hold nothing; a grant resumes when no enabled module decides the field
 * any more, with nothing stored to undo; a restore holds one in words.
 *
 * The sources combine by union. A role's grant, a module's grant and two
 * modules' callbacks are tried in every combination of allowing, having no
 * opinion and failing, for a field read and for an operation reached by a
 * route, and the decision names the first that allows.
 *
 * Every test has a control (the same call before the module, the grant that
 * is not suspended beside the one that is, the source that answers beside the
 * one that fails). tools/check-suspend.sh plants a defect in the source for
 * each rule and requires the named test here to fail.
 */

#include "grants_fixture.h"
#include "size_structs.h"

using namespace gfx;

namespace {

const char kArticle[] = "news.article";
const char kView[] = "View articles";
const char kBody[] = "Read article body";
const char kBodyLedger[] = "Read article body (ledger)";
const char kPromoBody[] = "Promo read body";
const char kPromoRead[] = "Promo read";
const char kPublish[] = "Publish article";
const char kPublishLedger[] = "Publish article (ledger)";
const char kPromoPublish[] = "Promo publish";

/* What one callback knows and how it behaves. */
struct Cb {
  std::set<std::pair<std::string, std::string> > allow; /* (principal, id) */
  int mode = 0;
  int calls = 0;
};

enum { kAnswer = 0, kTrap = 1, kMalformed = 2 };

extern "C" GDEFCORE_Result Answer(GDEFCORE_Callback_Call * call,
    GDEFCORE_Request * request, const GDEFCORE_Callback_Question * q,
    GDEFCORE_Callback_Answer * a, void * user) {
  Cb * cb = static_cast<Cb *>(user);
  std::string who = q->principal == NULL
                        ? std::string()
                        : std::string(q->principal, q->principal_len);
  (void)call;
  (void)request;
  cb->calls += 1;
  for (size_t i = 0; i < q->count; i++) {
    /* A failing callback has written a grant first: failing closed means the
     * host throws the answer away. */
    a->granted[i] = cb->allow.count(std::make_pair(who, std::string(q->entities[i])))
                        ? 1
                        : 0;
    if (cb->mode != kAnswer) {
      a->granted[i] = 1;
    }
  }
  snprintf(a->token, sizeof a->token, "v1");
  a->token_len = 2;
  if (cb->mode == kTrap) {
    return GDEFCORE_ERR_INTERNAL;
  }
  if (cb->mode == kMalformed) {
    a->granted[0] = 7;
  }
  return GDEFCORE_OK;
}

void GuardRoute(const GDEFCORE_Route_Call * call) {
  const char * value = NULL;
  size_t n = 0;
  if (gdefcore_route_call_capture(call, "id", 2, &value, &n)) {
    gdefcore_request_set_resolution(call->request, value, n);
  }
}

class Suspend : public GrantsFixture {
 protected:
  Cb bill_;        /* billing.paid: the body */
  Cb bill_pub_;    /* billing.pub: publish */
  Cb ledg_;        /* ledger.owed: the body */
  Cb ledg_pub_;    /* ledger.pub: publish */
  GDEFCORE_Routes * routes_ = NULL;

  void SetUp() override {
    GrantsFixture::SetUp();
    GDEFCORE_Field f[3] = {Field("title"), Field("body"), Field("tier")};
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, kArticle, strlen(kArticle),
            GDEFCORE_TYPE_CONTENT, f, 3));
    Declare(Perm(kView, "read", GDEFCORE_ACCESS_ANY, kArticle));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes_));
    Route("/publish/:id", "publish");
  }

  void TearDown() override {
    gdefcore_routes_destroy(routes_);
    routes_ = NULL;
    GrantsFixture::TearDown();
  }

  void Route(const char * path, const char * permission) {
    GDEFCORE_Route_Spec spec;
    char * err = NULL;
    size_t err_len = 0;
    memset(&spec, 0, sizeof spec);
    spec.size = sizeof spec;
    spec.machine = "publish";
    spec.machine_len = 7;
    spec.path = path;
    spec.path_len = strlen(path);
    spec.call_fn = GuardRoute;
    spec.permission = permission;
    spec.permission_len = strlen(permission);
    spec.entity_capture = "id";
    spec.entity_capture_len = 2;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes_, &spec, &err, &err_len))
        << (err == NULL ? "" : err);
    gdefcore_routes_free(routes_, err);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_routes_set_check(routes_, gdefcore_access_route_check,
            catalog_));
  }

  /* ---- the modules ---------------------------------------------------- */

  /** billing: the body permission with callback `paid`, the publish permission
   * with callback `pub`. */
  ModDef * Billing() {
    ModDef * m = NewMod("billing");
    m->Perm(kBody, "read", GDEFCORE_ACCESS_ANY, kArticle, "body");
    m->Perm(kPublish, "publish", GDEFCORE_ACCESS_ANY, kArticle);
    m->Callback("paid", GDEFCORE_CALLBACK_FIELD, kBody, kArticle, "body",
        Answer, &bill_);
    m->Callback("pub", GDEFCORE_CALLBACK_OPERATION, kPublish, kArticle, "",
        Answer, &bill_pub_);
    return m;
  }

  /** ledger: the same, under its own permissions. */
  ModDef * Ledger() {
    ModDef * m = NewMod("ledger");
    m->Perm(kBodyLedger, "read", GDEFCORE_ACCESS_ANY, kArticle, "body");
    m->Perm(kPublishLedger, "publish", GDEFCORE_ACCESS_ANY, kArticle);
    m->Callback("owed", GDEFCORE_CALLBACK_FIELD, kBodyLedger, kArticle, "body",
        Answer, &ledg_);
    m->Callback("pub", GDEFCORE_CALLBACK_OPERATION, kPublishLedger, kArticle,
        "", Answer, &ledg_pub_);
    return m;
  }

  /** promo: grants, to everyone, reading the body and publishing a gold
   * article. A module grant, not a callback. */
  ModDef * Promo() {
    ModDef * m = NewMod("promo");
    m->Perm(kPromoBody, "read", GDEFCORE_ACCESS_ANY, kArticle, "body");
    m->Perm(kPromoPublish, "publish", GDEFCORE_ACCESS_ANY, kArticle);
    m->Grant(kPromoBody, kArticle, "(= field.tier \"gold\")", "body");
    m->Grant(kPromoPublish, kArticle, "(= field.tier \"gold\")");
    return m;
  }

  /** promo2: a grant of reading open articles, naming the body in its
   * condition. */
  ModDef * Open() {
    ModDef * m = NewMod("opened");
    m->Perm(kPromoRead, "read", GDEFCORE_ACCESS_ANY, kArticle);
    m->Grant(kPromoRead, kArticle, "(= field.body \"open\")");
    return m;
  }

  /* ---- the words the enable shows ---------------------------------------- */

  static std::string Words(const std::string & condition) {
    GDEFCORE_Condition * c = NULL;
    char * words = NULL;
    size_t n = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_condition_parse(condition.data(), condition.size(), &c, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_condition_explain(c, &words, &n));
    out.assign(words, n);
    gdefcore_condition_text_free(words);
    gdefcore_condition_free(c);
    return out;
  }

  /** The rating the enable gives a module's grant that the anonymous state
   * would hold (its condition reads no principal). */
  static const char * Risk(const char * action, const char * field,
      const std::string & condition) {
    return gdefcore_access_risk_name(gdefcore_access_grant_risk_on(action,
        strlen(action), field, strlen(field), condition.data(), condition.size(),
        1));
  }

  /** The line the enable shows for a grant a module would suspend. */
  static std::string Susp(const std::string & module, const std::string & holder,
      const std::string & label, const std::string & words,
      const std::string & field, const std::string & callback) {
    return "Module " + module + " suspends " + holder + " grant " + label +
           " (" + words + "): its condition names field " + field + " of " +
           kArticle + ", which that module decides per entity with its "
           "callback " + callback + ", so the grant holds nothing until no "
           "enabled module decides that field.";
  }

  static std::string CallbackLine(const std::string & module,
      const std::string & label, const std::string & callback,
      const char * scope) {
    return "Module " + module + " decides " + label + " per entity with its "
           "callback " + callback + " (" + scope + " scope, high risk): its "
           "breadth cannot be judged.";
  }

  /** The matrix rows with the A7 fields. */
  struct MRow {
    std::string source, permission, field, condition, explain, by;
    int suspended;
    int callback;
  };

  std::vector<MRow> Rows() {
    GDEFCORE_Access_Matrix_Row * rows = NULL;
    size_t n = 0;
    std::vector<MRow> out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_matrix(catalog_, Req(Admin()), &rows, &n));
    for (size_t i = 0; i < n; i++) {
      MRow r;
      r.source.assign(rows[i].source, rows[i].source_len);
      r.permission.assign(rows[i].permission, rows[i].permission_len);
      r.field.assign(rows[i].field, rows[i].field_len);
      r.condition.assign(rows[i].condition, rows[i].condition_len);
      r.explain.assign(rows[i].explain, rows[i].explain_len);
      r.by.assign(rows[i].suspended_by, rows[i].suspended_by_len);
      r.suspended = rows[i].suspended;
      r.callback = rows[i].callback;
      out.push_back(r);
    }
    gdefcore_access_matrix_free(catalog_, rows, n);
    return out;
  }

  static const MRow * RowOf(const std::vector<MRow> & rows,
      const std::string & source, const std::string & permission) {
    for (const MRow & r : rows) {
      if (r.source == source && r.permission == permission) {
        return &r;
      }
    }
    return NULL;
  }

  /* ---- the articles and what a principal sees of them ---------------------- */

  std::string Article(const std::string & title, const std::string & body,
      const std::string & tier = std::string("basic")) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * texts[3] = {title.c_str(), body.c_str(), tier.c_str()};
    size_t lens[3] = {title.size(), body.size(), tier.size()};
    const char * names[3] = {"title", "body", "tier"};
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kArticle, strlen(kArticle), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    memset(values, 0, sizeof values);
    for (int i = 0; i < 3; i++) {
      values[i].size = sizeof values[i];
      values[i].field = names[i];
      values[i].field_len = strlen(names[i]);
      values[i].texts = &texts[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, strlen(id), "en", 2, values, 3));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  /** The field as @p req reads it: "<denied>" when the read is refused,
   * "<absent>" when nothing is returned, else the first value. */
  std::string FieldOf(GDEFCORE_Request * req, const std::string & id,
      const char * field = "body") {
    return Read(req, id, field);
  }

  /** The ids @p req lists, as titles. */
  std::vector<std::string> Titles(GDEFCORE_Request * req, uint64_t * total = NULL) {
    GDEFCORE_Access_List q;
    char ** ids = NULL;
    size_t count = 0;
    uint64_t t = 0;
    std::vector<std::string> out;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = kArticle;
    q.type_name_len = strlen(kArticle);
    q.lang = "en";
    q.lang_len = 2;
    q.sort_field = "title";
    q.sort_field_len = 5;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_list_page(catalog_, req, &q, &ids,
                               &count, &t));
    for (size_t i = 0; i < count; i++) {
      out.push_back(Read(req, ids[i], "title"));
    }
    gdefcore_access_free(catalog_, ids, count);
    if (total != NULL) {
      *total = t;
    }
    return out;
  }

  std::string Note(GDEFCORE_Request * req, const char * key) {
    size_t n = 0;
    const char * v = gdefcore_request_note(req, key, strlen(key), &n);
    return v == NULL ? std::string() : std::string(v, n);
  }

  /** The id the publish route answered with for @p req, or "" when it did not
   * answer: the route is there only where the check says yes. */
  std::string Publish(GDEFCORE_Request * req, const std::string & id) {
    char * out = NULL;
    size_t n = 0;
    std::string path = "/publish/" + id;
    GDEFCORE_Result rc = gdefcore_form_resolve(routes_, catalog_, req,
        path.data(), path.size(), &out, &n);
    std::string text;
    if (rc == GDEFCORE_OK && out != NULL) {
      text.assign(out, n);
      gdefcore_text_free(catalog_, out);
    }
    return text;
  }

  GDEFCORE_Access_Decision Decide(GDEFCORE_Request * req, const char * action,
      const std::string & id, const char * field = NULL,
      GDEFCORE_Result * rc_out = NULL) {
    GDEFCORE_Access_Decision d;
    GDEFCORE_Result rc;
    memset(&d, 0, sizeof d);
    d.size = sizeof d;
    rc = gdefcore_access_decide(catalog_, req, action, strlen(action), kArticle,
        strlen(kArticle), id.empty() ? NULL : id.c_str(), field,
        field == NULL ? 0 : strlen(field), &d);
    if (rc_out != NULL) {
      *rc_out = rc;
    }
    return d;
  }

  std::string RoleGrantsOf(const char * role) {
    char ** items = NULL;
    size_t n = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_role_grants(catalog_, role, strlen(role), &items, &n));
    for (size_t i = 0; i < n; i++) {
      out += std::string(i > 0 ? "|" : "") + items[i];
    }
    gdefcore_access_free(catalog_, items, n);
    return out;
  }
};

/* ---- suspended grants ------------------------------------------------------ */

/* The grants an enable would suspend are listed in its preview, and applying
 * it needs a typed confirmation that names them: one that leaves them out
 * enables nothing. */
TEST_F(Suspend, EnablingListsTheGrantsItWouldSuspendAndNeedsTheTypedConfirmation) {
  std::string a1 = Article("Tides", "open");
  std::string a2 = Article("Waves", "closed");
  Role("clerk");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("clerk", kView, "(= field.body \"open\")"));
  std::string clerk = Principal("clerk");
  Role("plain");
  Grant("plain", kView);
  std::string plain = Principal("plain");
  Install(Open());
  ASSERT_EQ(GDEFCORE_OK,
      Enable("opened", {GrantLine("opened", kPromoRead, "low",
                           "(= field.body \"open\")")}))
      << last_error_;
  Install(Billing());
  /* Control: before the module, both grants hold. The clerk lists the open
   * article, and so does anyone, by the module's grant. */
  EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(clerk)));
  EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(Principal())));
  EXPECT_EQ((std::vector<std::string>{"Tides", "Waves"}), Titles(Req(plain)));
  std::vector<MRow> before = Rows();
  const MRow * role_row = RowOf(before, "role clerk", kView);
  ASSERT_NE((const MRow *)NULL, role_row);
  EXPECT_EQ(0, role_row->suspended);
  EXPECT_EQ("", role_row->by);
  std::string role_words = role_row->explain;
  std::string module_words = Words("(= field.body \"open\")");
  std::vector<std::string> lines = {
      CallbackLine("billing", kBody, "paid", "field"),
      CallbackLine("billing", kPublish, "pub", "operation"),
      Susp("billing", "role clerk's", kView, role_words, "body", "paid"),
      Susp("billing", "module opened's", kPromoRead, module_words, "body",
          "paid")};
  /* The confirmation that leaves the suspended grants out is refused, and
   * nothing is enabled. */
  {
    std::vector<std::string> short_lines = {lines[0], lines[1]};
    for (size_t i = 0; i < Defs().size(); i++) {
      if (Defs()[i]->name == "billing") {
        for (const std::string & l : Defs()[i]->lines) {
          short_lines.push_back(l);
        }
      }
    }
    EXPECT_NE(GDEFCORE_OK, EnableWith("billing", Confirmation("billing", short_lines)));
    EXPECT_EQ(0, gdefcore_access_field_governed(catalog_, kArticle,
                     strlen(kArticle), "body", 4));
    EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(clerk)));
    EXPECT_EQ(0, RowOf(Rows(), "role clerk", kView)->suspended);
  }
  /* The preview itself carries the lines. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, Stage("billing", &cs));
    std::string wanted;
    {
      std::vector<std::string> all = lines;
      for (size_t i = 0; i < Defs().size(); i++) {
        if (Defs()[i]->name == "billing") {
          for (const std::string & l : Defs()[i]->lines) {
            all.push_back(l);
          }
        }
      }
      wanted = Confirmation("billing", all);
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_apply(cs, wanted.data(), wanted.size()))
        << wanted;
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ(1, gdefcore_access_field_governed(catalog_, kArticle,
                   strlen(kArticle), "body", 4));
}

/* After the enable the matrix shows the grants as suspended by the module,
 * and the holder gains nothing from them. A grant of the same role that names
 * no governed field is not suspended. */
TEST_F(Suspend, TheMatrixShowsASuspendedGrantAndItHoldsNothing) {
  std::string a1 = Article("Tides", "open");
  Article("Waves", "closed");
  Role("clerk");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("clerk", kView, "(= field.body \"open\")"));
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("clerk", kView, "(= field.title \"Waves\")"));
  std::string clerk = Principal("clerk");
  Install(Open());
  ASSERT_EQ(GDEFCORE_OK,
      Enable("opened", {GrantLine("opened", kPromoRead, "low",
                           "(= field.body \"open\")")}));
  Install(Billing());
  /* Control: before, both of the clerk's grants hold. */
  EXPECT_EQ((std::vector<std::string>{"Tides", "Waves"}), Titles(Req(clerk)));
  std::vector<MRow> rows0 = Rows();
  std::vector<std::string> lines = {CallbackLine("billing", kBody, "paid", "field"),
      CallbackLine("billing", kPublish, "pub", "operation")};
  for (const MRow & r : rows0) {
    if (r.source == "role clerk" && r.condition.find("body") != std::string::npos) {
      lines.push_back(Susp("billing", "role clerk's", kView, r.explain, "body", "paid"));
    }
  }
  lines.push_back(Susp("billing", "module opened's", kPromoRead,
      Words("(= field.body \"open\")"), "body", "paid"));
  ASSERT_EQ(GDEFCORE_OK, Enable("billing", lines)) << last_error_;
  std::vector<MRow> rows = Rows();
  int suspended_clerk = 0;
  int plain_clerk = 0;
  for (const MRow & r : rows) {
    if (r.source == "role clerk" && r.permission == kView) {
      if (r.condition.find("field.body") != std::string::npos) {
        suspended_clerk += 1;
        EXPECT_EQ(1, r.suspended);
        EXPECT_EQ("billing", r.by);
        EXPECT_NE(std::string::npos, r.explain.find("suspended by billing"))
            << r.explain;
      } else {
        plain_clerk += 1;
        EXPECT_EQ(0, r.suspended) << r.condition;
        EXPECT_EQ("", r.by);
        EXPECT_EQ(std::string::npos, r.explain.find("suspended"));
      }
    }
  }
  EXPECT_EQ(1, suspended_clerk);
  EXPECT_EQ(1, plain_clerk);
  const MRow * module_row = RowOf(rows, "module opened", kPromoRead);
  ASSERT_NE((const MRow *)NULL, module_row);
  EXPECT_EQ(1, module_row->suspended);
  EXPECT_EQ("billing", module_row->by);
  /* The callback's own row is not a suspended grant. */
  const MRow * cb_row = RowOf(rows, "module billing", kBody);
  ASSERT_NE((const MRow *)NULL, cb_row);
  EXPECT_EQ(1, cb_row->callback);
  EXPECT_EQ(0, cb_row->suspended);
  /* The holder gains nothing from the suspended grant: only the second grant
   * of the clerk holds, in a read, a list, a count and a decision. */
  {
    GDEFCORE_Request * req = Req(clerk);
    EXPECT_EQ((std::vector<std::string>{"Waves"}), Titles(req));
    EXPECT_EQ("<denied>", FieldOf(req, a1, "title"));
    GDEFCORE_Access_Decision d = Decide(req, "read", a1);
    EXPECT_EQ(0, d.allowed);
    EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_NONE, d.source);
    /* A suspension is a state, not a failure: nothing is reported. */
    EXPECT_EQ("", Note(req, "defiant.condition.failed"));
  }
  /* And a stranger gains nothing from the module's grant either. */
  {
    GDEFCORE_Request * req = Req(Principal());
    EXPECT_EQ((std::vector<std::string>{}), Titles(req));
    EXPECT_EQ("", Note(req, "defiant.condition.failed"));
  }
  /* The decision of a grant that is not suspended still names its role. */
  {
    GDEFCORE_Request * req = Req(clerk);
    GDEFCORE_Access_List q;
    char ** ids = NULL;
    size_t n = 0;
    uint64_t t = 0;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = kArticle;
    q.type_name_len = strlen(kArticle);
    q.lang = "en";
    q.lang_len = 2;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list_page(catalog_, req, &q, &ids, &n, &t));
    ASSERT_EQ(1u, n);
    GDEFCORE_Access_Decision d = Decide(req, "read", ids[0]);
    EXPECT_EQ(1, d.allowed);
    EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_ROLE, d.source);
    gdefcore_access_free(catalog_, ids, n);
  }
}

/* Two modules decide one field. The grant is suspended by both, and
 * disabling one keeps it suspended; disabling both resumes it, and nothing was
 * stored to undo. */
TEST_F(Suspend, TwoModulesGovernOneFieldAndTheGrantResumesWhenNoneDoes) {
  std::string a1 = Article("Tides", "open");
  Role("clerk");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("clerk", kView, "(= field.body \"open\")"));
  std::string clerk = Principal("clerk");
  Install(Billing());
  Install(Ledger());
  auto lines_for = [&](const std::string & module, const char * label,
                       const char * cb, const char * publish_label) {
    std::vector<std::string> lines = {
        CallbackLine(module, label, cb, "field"),
        CallbackLine(module, publish_label, "pub", "operation")};
    for (const MRow & r : Rows()) {
      if (r.source == "role clerk" && r.condition.find("field.body") != std::string::npos) {
        std::string words = r.suspended ? r.explain.substr(0, r.explain.find(" This grant is suspended"))
                                        : r.explain;
        lines.push_back(Susp(module, "role clerk's", kView, words, "body", cb));
      }
    }
    return lines;
  };
  EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(clerk)));
  ASSERT_EQ(GDEFCORE_OK, Enable("billing", lines_for("billing", kBody, "paid", kPublish)))
      << last_error_;
  EXPECT_EQ((std::vector<std::string>{}), Titles(Req(clerk)));
  /* A second module that decides the same field lists the grant again. */
  ASSERT_EQ(GDEFCORE_OK,
      Enable("ledger", lines_for("ledger", kBodyLedger, "owed", kPublishLedger)))
      << last_error_;
  {
    const MRow * r = NULL;
    std::vector<MRow> rows = Rows();
    for (const MRow & row : rows) {
      if (row.source == "role clerk" && row.condition.find("field.body") != std::string::npos) {
        r = &row;
      }
    }
    ASSERT_NE((const MRow *)NULL, r);
    EXPECT_EQ(1, r->suspended);
    /* Every governing module is named, in order. */
    EXPECT_EQ("billing, ledger", r->by);
    EXPECT_NE(std::string::npos, r->explain.find("suspended by billing, ledger"))
        << r->explain;
  }
  ASSERT_EQ(GDEFCORE_OK, Disable("billing"));
  {
    std::vector<MRow> rows = Rows();
    int seen = 0;
    for (const MRow & row : rows) {
      if (row.source == "role clerk" && row.condition.find("field.body") != std::string::npos) {
        seen += 1;
        EXPECT_EQ(1, row.suspended);
        EXPECT_EQ("ledger", row.by);
      }
    }
    EXPECT_EQ(1, seen);
  }
  EXPECT_EQ((std::vector<std::string>{}), Titles(Req(clerk)))
      << "disabling one of two modules resumed the grant";
  ASSERT_EQ(GDEFCORE_OK, Disable("ledger"));
  EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(clerk)))
      << "the grant did not resume";
  for (const MRow & row : Rows()) {
    EXPECT_EQ(0, row.suspended) << row.source << " " << row.permission;
  }
  /* And it suspends again when a module decides the field again. */
  ASSERT_EQ(GDEFCORE_OK, Enable("billing", lines_for("billing", kBody, "paid", kPublish)))
      << last_error_;
  EXPECT_EQ((std::vector<std::string>{}), Titles(Req(clerk)));
}

/* The grants that name only fields nobody decides are never listed or
 * suspended: a module that decides the body leaves a grant on the title
 * alone, and its enable lists nothing for it. */
TEST_F(Suspend, AGrantThatNamesNoGovernedFieldIsNeverListedOrSuspended) {
  Article("Tides", "open");
  Role("clerk");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("clerk", kView, "(= field.title \"Tides\")"));
  std::string clerk = Principal("clerk");
  Install(Billing());
  EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(clerk)));
  /* Only the callbacks' own lines: the enable needs no more. */
  ASSERT_EQ(GDEFCORE_OK,
      Enable("billing", {CallbackLine("billing", kBody, "paid", "field"),
                            CallbackLine("billing", kPublish, "pub", "operation")}))
      << last_error_;
  EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(clerk)));
  for (const MRow & row : Rows()) {
    EXPECT_EQ(0, row.suspended) << row.source << " " << row.permission;
  }
}

/* A restored grant that names a governed field is held and reported, not
 * applied; the role keeps the rest. A control: with no module deciding the
 * field nothing is held. */
TEST_F(Suspend, ARestoredGrantNamingAGovernedFieldIsHeldAndReported) {
  Article("Tides", "open");
  Role("clerk");
  Declare(Perm("Edit article", "update", GDEFCORE_ACCESS_ANY, kArticle));
  Grant("clerk", "Edit article");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("clerk", kView, "(= field.body \"open\")"));
  std::string clerk = Principal("clerk");
  struct Told {
    std::vector<std::string> roles, labels, by, conf;
  } told;
  auto fn = [](void * ctx, const GDEFCORE_Access_Held * h) -> GDEFCORE_Result {
    Told * t = static_cast<Told *>(ctx);
    t->roles.push_back(std::string(h->role, h->role_len));
    t->labels.push_back(std::string(h->label, h->label_len));
    t->by.push_back(std::string(h->suspended_by, h->suspended_by_len));
    t->conf.push_back(std::string(h->confirmation, h->confirmation_len));
    return GDEFCORE_OK;
  };
  /* Control: nothing decides the body, so nothing is held, and the clerk
   * keeps both grants. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_hold_for_confirmation(catalog_, fn, &told));
  EXPECT_TRUE(told.labels.empty());
  EXPECT_NE(std::string::npos, RoleGrantsOf("clerk").find(kView));
  EXPECT_EQ((std::vector<std::string>{"Tides"}), Titles(Req(clerk)));
  Install(Billing());
  std::vector<MRow> rows = Rows();
  std::vector<std::string> lines = {CallbackLine("billing", kBody, "paid", "field"),
      CallbackLine("billing", kPublish, "pub", "operation")};
  for (const MRow & r : rows) {
    if (r.source == "role clerk" && r.condition.find("field.body") != std::string::npos) {
      lines.push_back(Susp("billing", "role clerk's", kView, r.explain, "body", "paid"));
    }
  }
  ASSERT_EQ(GDEFCORE_OK, Enable("billing", lines)) << last_error_;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_hold_for_confirmation(catalog_, fn, &told));
  ASSERT_EQ(1u, told.labels.size());
  EXPECT_EQ("clerk", told.roles[0]);
  EXPECT_EQ(kView, told.labels[0]);
  EXPECT_EQ("billing", told.by[0]);
  EXPECT_EQ("core.role", told.conf[0]);
  /* Held: the role no longer carries the suspended grant, and carries the
   * other. The matrix has no row for it. */
  std::string grants = RoleGrantsOf("clerk");
  EXPECT_EQ(std::string::npos, grants.find("#when:")) << grants;
  EXPECT_NE(std::string::npos, grants.find("Edit article")) << grants;
  for (const MRow & r : Rows()) {
    EXPECT_EQ(0, r.suspended) << r.source << " " << r.permission;
  }
  /* A second call finds nothing more to hold. */
  told = Told();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_hold_for_confirmation(catalog_, fn, &told));
  EXPECT_TRUE(told.labels.empty());
}

/* ---- the sources combine by union --------------------------------------------- */

enum Src { kNo = 0, kAllow = 1, kFail = 2 };

const char * SrcName(int s) {
  return s == kAllow ? "allow" : (s == kFail ? "fail" : "none");
}

/* One case of the combination test: how a role grant, a module grant and two
 * callbacks stand. The first source that allows is the one named; a callback
 * that fails before it is reported. */
struct Case {
  int role, module, bill, ledger;
  bool expect_allowed() const {
    return role == kAllow || module == kAllow || bill == kAllow ||
           ledger == kAllow;
  }
  /* GDEFCORE_ACCESS_SOURCE_ of the first that allows. */
  int source() const {
    if (role == kAllow) {
      return GDEFCORE_ACCESS_SOURCE_ROLE;
    }
    if (module == kAllow) {
      return GDEFCORE_ACCESS_SOURCE_MODULE;
    }
    if (bill == kAllow) {
      return GDEFCORE_ACCESS_SOURCE_CALLBACK;
    }
    if (ledger == kAllow) {
      return GDEFCORE_ACCESS_SOURCE_CALLBACK;
    }
    return GDEFCORE_ACCESS_SOURCE_NONE;
  }
  const char * holder() const {
    if (role == kAllow) {
      return "editor";
    }
    if (module == kAllow) {
      return "promo";
    }
    return bill == kAllow ? "billing" : (ledger == kAllow ? "ledger" : "");
  }
  /* A failing callback is reported when it was asked: when nothing before it
   * allowed. */
  bool expect_callback_failure() const {
    if (role == kAllow || module == kAllow) {
      return false;
    }
    if (bill == kFail) {
      return true;
    }
    return bill != kAllow && ledger == kFail;
  }
  std::string Text() const {
    return std::string("role=") + SrcName(role) + " module=" + SrcName(module) +
           " billing=" + SrcName(bill) + " ledger=" + SrcName(ledger);
  }
};

std::vector<Case> AllCases() {
  std::vector<Case> out;
  for (int r = kNo; r <= kAllow; r++) {
    for (int m = kNo; m <= kAllow; m++) {
      for (int b = kNo; b <= kFail; b++) {
        for (int l = kNo; l <= kFail; l++) {
          Case c = {r, m, b, l};
          out.push_back(c);
        }
      }
    }
  }
  return out;
}

/* A role's grant (editor), a module's grant (promo, on gold articles) and the
 * callbacks of two modules, each allowing or having no opinion or failing,
 * every combination: a field read, and an operation reached by a route. Any
 * allow grants; no opinion adds nothing; a failure grants nothing and cancels
 * no other source's allow; with all of them silent it is denied. */
class Combine : public Suspend {
 protected:
  void SetUpWorld() {
    Install(Billing());
    Install(Ledger());
    Install(Promo());
    ASSERT_EQ(GDEFCORE_OK,
        Enable("billing", {CallbackLine("billing", kBody, "paid", "field"),
                              CallbackLine("billing", kPublish, "pub", "operation")}))
        << last_error_;
    ASSERT_EQ(GDEFCORE_OK,
        Enable("ledger", {CallbackLine("ledger", kBodyLedger, "owed", "field"),
                             CallbackLine("ledger", kPublishLedger, "pub", "operation")}))
        << last_error_;
    ASSERT_EQ(GDEFCORE_OK,
        Enable("promo",
            {GrantLine("promo", kPromoBody,
                 Risk("read", "body", "(= field.tier \"gold\")"),
                 "(= field.tier \"gold\")"),
                GrantLine("promo", kPromoPublish,
                    Risk("publish", "", "(= field.tier \"gold\")"),
                    "(= field.tier \"gold\")")}))
        << last_error_;
    Role("editor");
    Grant("editor", kBody);
    Grant("editor", kPublish);
    Role("reader");
    Grant("reader", kView);
  }

  /* A principal and an article that set the sources up as @p c says. */
  struct Setup {
    std::string who, article;
  };

  Setup Arrange(const Case & c) {
    Setup s;
    s.who = Principal("reader");
    if (c.role == kAllow) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_access_principal_add_role(catalog_, s.who.data(), s.who.size(),
              "editor", 6));
    }
    s.article = Article("Tides", "the secret of the tides",
        c.module == kAllow ? "gold" : "basic");
    for (Cb * cb : {&bill_, &bill_pub_}) {
      cb->allow.clear();
      cb->mode = c.bill == kFail ? kTrap : kAnswer;
      if (c.bill == kAllow) {
        cb->allow.insert(std::make_pair(s.who, s.article));
      }
    }
    for (Cb * cb : {&ledg_, &ledg_pub_}) {
      cb->allow.clear();
      /* The ledger fails by answering what is no answer; billing by trapping. */
      cb->mode = c.ledger == kFail ? kMalformed : kAnswer;
      if (c.ledger == kAllow) {
        cb->allow.insert(std::make_pair(s.who, s.article));
      }
    }
    return s;
  }
};

TEST_F(Combine, AFieldReadCombinesRoleModuleAndTwoCallbacksByUnion) {
  SetUpWorld();
  ASSERT_FALSE(HasFatalFailure());
  int allowed_cases = 0;
  int denied_cases = 0;
  for (const Case & c : AllCases()) {
    Setup s = Arrange(c);
    GDEFCORE_Request * req = Req(s.who);
    std::string got = FieldOf(req, s.article);
    EXPECT_EQ(c.expect_allowed() ? "the secret of the tides" : "<absent>", got)
        << c.Text();
    EXPECT_EQ(c.expect_callback_failure(),
        !Note(req, "defiant.callback.failed").empty())
        << c.Text() << " note=" << Note(req, "defiant.callback.failed");
    /* The same decision, with its source. */
    GDEFCORE_Result rc = GDEFCORE_OK;
    GDEFCORE_Access_Decision d = Decide(Req(s.who), "read", s.article, "body", &rc);
    EXPECT_EQ(GDEFCORE_OK, rc) << c.Text();
    EXPECT_EQ(c.expect_allowed() ? 1 : 0, d.allowed) << c.Text();
    EXPECT_EQ(c.source(), d.source) << c.Text();
    EXPECT_EQ(c.holder(), std::string(d.holder, d.holder_len)) << c.Text();
    if (d.source == GDEFCORE_ACCESS_SOURCE_CALLBACK) {
      EXPECT_EQ(c.bill == kAllow ? "paid" : "owed",
          std::string(d.callback, d.callback_len))
          << c.Text();
    }
    allowed_cases += c.expect_allowed();
    denied_cases += !c.expect_allowed();
    bill_.mode = bill_pub_.mode = ledg_.mode = ledg_pub_.mode = kAnswer;
  }
  /* The sweep saw both answers, many times. */
  EXPECT_EQ(36, allowed_cases + denied_cases);
  EXPECT_GT(allowed_cases, 20);
  EXPECT_EQ(4, denied_cases);
}

TEST_F(Combine, AnOperationReachedByARouteCombinesTheSameWay) {
  SetUpWorld();
  ASSERT_FALSE(HasFatalFailure());
  for (const Case & c : AllCases()) {
    Setup s = Arrange(c);
    GDEFCORE_Request * req = Req(s.who);
    std::string got = Publish(req, s.article);
    EXPECT_EQ(c.expect_allowed() ? s.article : std::string(), got) << c.Text();
    EXPECT_EQ(c.expect_callback_failure(),
        !Note(req, "defiant.callback.failed").empty())
        << c.Text() << " note=" << Note(req, "defiant.callback.failed");
    /* can() agrees with the route, and names the source. */
    int allowed = -1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, Req(s.who), "publish", 7,
                               kArticle, strlen(kArticle), s.article.c_str(),
                               &allowed))
        << c.Text();
    EXPECT_EQ(c.expect_allowed() ? 1 : 0, allowed) << c.Text();
    GDEFCORE_Result rc = GDEFCORE_OK;
    GDEFCORE_Access_Decision d = Decide(Req(s.who), "publish", s.article, NULL, &rc);
    EXPECT_EQ(GDEFCORE_OK, rc) << c.Text();
    EXPECT_EQ(c.expect_allowed() ? 1 : 0, d.allowed) << c.Text();
    EXPECT_EQ(c.source(), d.source) << c.Text();
    EXPECT_EQ(c.holder(), std::string(d.holder, d.holder_len)) << c.Text();
    if (d.source == GDEFCORE_ACCESS_SOURCE_CALLBACK) {
      EXPECT_EQ("pub", std::string(d.callback, d.callback_len)) << c.Text();
    }
    bill_.mode = bill_pub_.mode = ledg_.mode = ledg_pub_.mode = kAnswer;
  }
}

/* Two callbacks of two modules on one field, one saying no and the other yes,
 * in one request, in either order: the memo keeps their answers apart. */
TEST_F(Combine, TwoCallbacksOnOneFieldKeepTheirAnswersApart) {
  SetUpWorld();
  ASSERT_FALSE(HasFatalFailure());
  std::string who = Principal("reader");
  std::string a1 = Article("Tides", "salt");
  std::string a2 = Article("Waves", "foam");
  /* Billing says no to the first and yes to the second; the ledger the other
   * way about. */
  bill_.allow.insert(std::make_pair(who, a2));
  ledg_.allow.insert(std::make_pair(who, a1));
  GDEFCORE_Request * req = Req(who);
  EXPECT_EQ("salt", FieldOf(req, a1));
  EXPECT_EQ("foam", FieldOf(req, a2));
  EXPECT_EQ("salt", FieldOf(req, a1));
  /* Nobody allows a third: the memo of an answer does not stand in for it. */
  std::string a3 = Article("Rain", "mist");
  EXPECT_EQ("<absent>", FieldOf(req, a3));
  /* The ledger alone allows, and billing was asked first and said no: its
   * answer is not the ledger's. */
  bill_.allow.clear();
  ledg_.allow.insert(std::make_pair(who, a3));
  EXPECT_EQ("mist", FieldOf(Req(who), a3));
  EXPECT_GT(bill_.calls, 0);
  EXPECT_GT(ledg_.calls, 0);
}

/* A callback beside a role's grant on the same entity: the role's allows
 * without asking it, and where the role does not, the callback decides. */
TEST_F(Combine, ACallbackBesideARoleGrantIsAskedOnlyWhereTheRoleDoesNotAllow) {
  SetUpWorld();
  ASSERT_FALSE(HasFatalFailure());
  std::string editor = Principal("reader");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, editor.data(),
                             editor.size(), "editor", 6));
  std::string reader = Principal("reader");
  std::string a1 = Article("Tides", "salt");
  bill_.allow.insert(std::make_pair(reader, a1));
  bill_.allow.insert(std::make_pair(editor, a1));
  bill_pub_.allow.insert(std::make_pair(reader, a1));
  bill_pub_.allow.insert(std::make_pair(editor, a1));
  bill_.calls = 0;
  bill_pub_.calls = 0;
  EXPECT_EQ("salt", FieldOf(Req(editor), a1));
  EXPECT_EQ(0, bill_.calls) << "the callback was asked beside a grant that holds";
  EXPECT_EQ("salt", FieldOf(Req(reader), a1));
  EXPECT_GT(bill_.calls, 0);
  /* The same for an operation reached by a route. */
  EXPECT_EQ(a1, Publish(Req(editor), a1));
  EXPECT_EQ(0, bill_pub_.calls) << "the callback was asked beside a grant that holds";
  EXPECT_EQ(a1, Publish(Req(reader), a1));
  EXPECT_GT(bill_pub_.calls, 0);
  GDEFCORE_Access_Decision d = Decide(Req(editor), "read", a1, "body");
  EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_ROLE, d.source);
  EXPECT_EQ("editor", std::string(d.holder, d.holder_len));
  EXPECT_EQ(kBody, std::string(d.permission, d.permission_len));
  d = Decide(Req(reader), "read", a1, "body");
  EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_CALLBACK, d.source);
  EXPECT_EQ("billing", std::string(d.holder, d.holder_len));
  EXPECT_EQ("paid", std::string(d.callback, d.callback_len));
  EXPECT_EQ(kBody, std::string(d.permission, d.permission_len));
}

/* The decision names its source, and a refused one names none; a field no
 * permission limits is allowed with none. */
TEST_F(Combine, TheDecisionNamesTheSourceThatAllowedIt) {
  SetUpWorld();
  ASSERT_FALSE(HasFatalFailure());
  std::string who = Principal("reader");
  std::string gold = Article("Tides", "salt", "gold");
  std::string basic = Article("Waves", "foam", "basic");
  GDEFCORE_Access_Decision d = Decide(Req(who), "read", gold, "body");
  EXPECT_EQ(1, d.allowed);
  EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_MODULE, d.source);
  EXPECT_EQ("promo", std::string(d.holder, d.holder_len));
  EXPECT_EQ(kPromoBody, std::string(d.permission, d.permission_len));
  EXPECT_EQ("", std::string(d.callback, d.callback_len));
  d = Decide(Req(who), "read", basic, "body");
  EXPECT_EQ(0, d.allowed);
  EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_NONE, d.source);
  EXPECT_EQ(0u, d.holder_len);
  EXPECT_EQ(0u, d.permission_len);
  /* The title is limited by no permission. */
  d = Decide(Req(who), "read", basic, "title");
  EXPECT_EQ(1, d.allowed);
  EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_NONE, d.source);
  /* The row: the reader role's grant. */
  d = Decide(Req(who), "read", basic);
  EXPECT_EQ(1, d.allowed);
  EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_ROLE, d.source);
  EXPECT_EQ("reader", std::string(d.holder, d.holder_len));
  EXPECT_EQ(kView, std::string(d.permission, d.permission_len));
  /* Type level, no entity. */
  d = Decide(Req(who), "read", std::string());
  EXPECT_EQ(1, d.allowed);
  EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_ROLE, d.source);
  /* The same answer as can(), and a bad size is refused. */
  int allowed = -1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, Req(who), "read", 4, kArticle,
                             strlen(kArticle), basic.c_str(), &allowed));
  EXPECT_EQ(1, allowed);
}

/* A source that cannot be decided beside a source that allows: the allow
 * stands, the failure is reported, and the decision is not an error. A role
 * grant on a relation whose module was disabled is such a source. With
 * nothing else to allow it, it is an undecided question, as it always was. */
TEST_F(Combine, AFailingConditionBesideAnAllowingCallbackIsNotAnError) {
  SetUpWorld();
  ASSERT_FALSE(HasFatalFailure());
  ModDef * rel = NewMod("rel");
  rel->Relation("rel.team", {{"who", GDEFCORE_RELATION_ENTITY, ""}});
  Install(rel);
  ASSERT_EQ(GDEFCORE_OK, Enable("rel", {}));
  Role("watcher");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("watcher", kPublish,
                             "(related \"rel.team\" (principal))"));
  Role("peeker");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("peeker", kBody,
                             "(related \"rel.team\" (principal))"));
  std::string who = Principal("reader");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, who.data(),
                             who.size(), "watcher", 7));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, who.data(),
                             who.size(), "peeker", 6));
  std::string a1 = Article("Tides", "salt");
  ASSERT_EQ(GDEFCORE_OK, Disable("rel"));
  /* Alone, the failing grant is an undecided question, not a no. */
  {
    int allowed = -1;
    EXPECT_NE(GDEFCORE_OK, gdefcore_access_can(catalog_, Req(who), "publish", 7,
                               kArticle, strlen(kArticle), a1.c_str(), &allowed));
    EXPECT_EQ(0, allowed);
    EXPECT_EQ("", Publish(Req(who), a1));
  }
  /* A callback that allows, beside it. */
  bill_pub_.allow.insert(std::make_pair(who, a1));
  {
    GDEFCORE_Request * req = Req(who);
    int allowed = -1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, req, "publish", 7, kArticle,
                               strlen(kArticle), a1.c_str(), &allowed));
    EXPECT_EQ(1, allowed);
    EXPECT_EQ("1", Note(req, "defiant.condition.failed"));
    EXPECT_EQ(a1, Publish(Req(who), a1));
    GDEFCORE_Result rc = GDEFCORE_OK;
    GDEFCORE_Access_Decision d = Decide(Req(who), "publish", a1, NULL, &rc);
    EXPECT_EQ(GDEFCORE_OK, rc);
    EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_CALLBACK, d.source);
  }
  /* The same for a field-level decision: alone it is undecided, beside an
   * allowing callback it is a yes. */
  {
    GDEFCORE_Result rc = GDEFCORE_OK;
    GDEFCORE_Access_Decision d = Decide(Req(who), "read", a1, "body", &rc);
    EXPECT_NE(GDEFCORE_OK, rc);
    EXPECT_EQ(0, d.allowed);
    bill_.allow.insert(std::make_pair(who, a1));
    d = Decide(Req(who), "read", a1, "body", &rc);
    EXPECT_EQ(GDEFCORE_OK, rc);
    EXPECT_EQ(1, d.allowed);
    EXPECT_EQ(GDEFCORE_ACCESS_SOURCE_CALLBACK, d.source);
    EXPECT_EQ("salt", FieldOf(Req(who), a1));
  }
}

/* AD-34: the decision is accepted at exactly its own size. */
TEST_F(Combine, TheDecisionIsAcceptedAtOnlyItsOwnSize) {
  SetUpWorld();
  ASSERT_FALSE(HasFatalFailure());
  std::string who = Principal("reader");
  std::string a1 = Article("Tides", "salt");
  const std::map<std::string, size_structs::Probe> probes = {
      GDEFCORE_SIZE_PROBE(GDEFCORE_Access_Decision, {
        GDEFCORE_Access_Decision d;
        memset(&d, 0, sizeof d);
        d.size = size;
        return gdefcore_access_decide(catalog_, Req(who), "read", 4, kArticle,
                   strlen(kArticle), a1.c_str(), NULL, 0, &d) == GDEFCORE_OK;
      }),
  };
  size_structs::Run("tests/test_suspend.cpp", probes);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
