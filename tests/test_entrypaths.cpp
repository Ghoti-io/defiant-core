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
 * Access-conditions story A5b, the entry paths (SPEC decisions 7 and 8).
 * Protection is on the path: a route that names a permission and the capture
 * of its entity, and a handler that calls library code, which asks nothing.
 * A condition is evaluated only on the stored entity the path names, never on
 * what was submitted. Every test here has a control (the same path, the same
 * principal, one thing different, and the answer differs), and the attacks
 * are run through the signed-form path with real accounts and real tokens.
 * tools/check-paths.sh plants a defect in the library for each rule and
 * requires the named test to fail.
 */

#include "grants_fixture.h"

#include <string>

namespace {

using namespace gfx;

const char kGroupA[] = "(= field.group \"a\")";
const char kArticle[] = "site.article";
const char kContainer[] = "test.container";
const char kPass[] = "correct horse";

/* What the signed-form handler did, for the test to read. */
struct SubmitRun {
  GDEFCORE_Catalog * catalog = nullptr;
  GDEFCORE_Keyring * keyring = nullptr;
  const uint8_t * root = nullptr;
  size_t root_len = 0;
  std::string session;
  std::string token;
  bool claim = true;       /* pass the captured id as the id the request names */
  int ran = 0;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  int allowed = 99;
  int conflict = 0;
};
SubmitRun g_submit;

void SubmitHandler(const GDEFCORE_Route_Call * call) {
  const char * idp = NULL;
  size_t idn = 0;
  bool have = gdefcore_route_call_capture(call, "id", 2, &idp, &idn) != 0;
  g_submit.ran = 1;
  g_submit.allowed = 99;
  g_submit.conflict = 0;
  g_submit.rc = gdefcore_form_submit_authorized(g_submit.catalog, call->request,
      g_submit.keyring, g_submit.root, g_submit.root_len, g_submit.session.data(),
      g_submit.session.size(), g_submit.token.data(), g_submit.token.size(),
      g_submit.claim && have ? idp : NULL, g_submit.claim && have ? idn : 0,
      &g_submit.allowed, &g_submit.conflict);
  gdefcore_request_set_resolution(call->request, call->machine, call->machine_len);
}

/* A create path: the container is the route's capture, the form is not asked. */
struct CreateRun {
  GDEFCORE_Catalog * catalog = nullptr;
  std::vector<std::string> fields;
  std::string form_container;   /* what the form claims; never consulted */
  int ran = 0;
  int allowed = 99;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
};
CreateRun g_create;

void CreateHandler(const GDEFCORE_Route_Call * call) {
  const char * idp = NULL;
  size_t idn = 0;
  std::vector<const char *> names;
  std::vector<size_t> lens;
  for (const std::string & f : g_create.fields) {
    names.push_back(f.c_str());
    lens.push_back(f.size());
  }
  g_create.ran = 1;
  g_create.allowed = 99;
  if (!gdefcore_route_call_capture(call, "id", 2, &idp, &idn)) {
    return;
  }
  g_create.rc = gdefcore_access_can_create(g_create.catalog, call->request, idp,
      idn, kPost, strlen(kPost), names.data(), lens.data(), names.size(),
      &g_create.allowed);
  gdefcore_request_set_resolution(call->request, call->machine, call->machine_len);
}

void PlainAnswer(const GDEFCORE_Route_Call * call) {
  gdefcore_request_set_resolution(call->request, call->machine, call->machine_len);
}

struct Who {
  std::string id;
  std::string session;
};

class EntryPath : public GrantsFixture {
 protected:
  GDEFCORE_Routes * routes_ = nullptr;
  GDEFCORE_Keyring * keyring_ = nullptr;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  int users_ = 0;

  void SetUp() override {
    GrantsFixture::SetUp();
    memset(root_, 0x42, sizeof root_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_create(root_, sizeof root_, NULL, &keyring_));
    g_submit = SubmitRun();
    g_submit.catalog = catalog_;
    g_submit.keyring = keyring_;
    g_submit.root = root_;
    g_submit.root_len = sizeof root_;
    g_create = CreateRun();
    g_create.catalog = catalog_;
    GDEFCORE_Field fields[3] = {Field("title"), Field("author"), Field("group")};
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, kArticle, strlen(kArticle),
            GDEFCORE_TYPE_CONTENT, fields, 3));
    GDEFCORE_Field kind = Field("kind");
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, kContainer, strlen(kContainer),
            GDEFCORE_TYPE_CONTENT, &kind, 1));
  }

  void TearDown() override {
    gdefcore_keyring_destroy(keyring_);
    gdefcore_routes_destroy(routes_);
    GrantsFixture::TearDown();
  }

  /** A principal with an account and a session. @p role may be NULL. */
  Who Person(const char * role) {
    Who who;
    char account[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * token = NULL;
    size_t n = 0;
    std::string user = "user" + std::to_string(users_++);
    who.id = Principal(role);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_,
            who.id.data(), who.id.size(), user.data(), user.size(), kPass,
            strlen(kPass), account));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_login(catalog_, keyring_, root_, sizeof root_,
            user.data(), user.size(), kPass, strlen(kPass), 3600, &token, &n));
    who.session.assign(token, n);
    gdefcore_text_free(catalog_, token);
    return who;
  }

  std::string FreshIdText() {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
    return std::string(id);
  }

  /** A fresh request for @p who, with the principal their session names. */
  GDEFCORE_Request * Request(const Who & who) {
    GDEFCORE_Request * req = Req();
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_check(catalog_, req, keyring_, root_, sizeof root_,
            who.session.data(), who.session.size()));
    return req;
  }

  void Route(const char * machine, const char * path, int kind, const char * permission,
      const char * capture, GDEFCORE_Route_Call_Fn fn) {
    GDEFCORE_Route_Spec spec;
    char * err = NULL;
    size_t err_len = 0;
    memset(&spec, 0, sizeof spec);
    spec.size = sizeof spec;
    spec.machine = machine;
    spec.machine_len = strlen(machine);
    spec.path = path;
    spec.path_len = strlen(path);
    spec.call_fn = fn;
    spec.kind = kind;
    if (permission != NULL) {
      spec.permission = permission;
      spec.permission_len = strlen(permission);
    }
    if (capture != NULL) {
      spec.entity_capture = capture;
      spec.entity_capture_len = strlen(capture);
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes_, &spec, &err, &err_len))
        << (err == NULL ? "" : err);
    gdefcore_routes_free(routes_, err);
  }

  /** The routes of the signed-form path: guarded by the entity, guarded by the
   * type only, and the container's create. */
  void Routes() {
    Route("post.submit", "/post/:id/submit", GDEFCORE_ROUTE_ACTION, "update", "id",
        SubmitHandler);
    Route("post.submit-any", "/submit", GDEFCORE_ROUTE_ACTION, "update", NULL,
        SubmitHandler);
    Route("container.new", "/container/:id/new", GDEFCORE_ROUTE_ACTION, "create",
        "id", CreateHandler);
    Route("type.new", "/new", GDEFCORE_ROUTE_ACTION, "create", NULL, PlainAnswer);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_routes_set_check(routes_, gdefcore_access_route_check, catalog_));
  }

  std::string Dispatch(GDEFCORE_Request * req, const std::string & path) {
    char * out = NULL;
    size_t n = 0;
    std::string text;
    if (gdefcore_form_resolve(routes_, catalog_, req, path.data(), path.size(),
            &out, &n) == GDEFCORE_OK &&
        out != NULL) {
      text.assign(out, n);
      gdefcore_text_free(catalog_, out);
    }
    return text;
  }

  /** An entity of @p type with these field values, saved (so published). */
  std::string Make(const char * type, const std::string & actor,
      const std::vector<std::pair<std::string, std::string> > & fields,
      bool draft = false) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> values(fields.size());
    std::vector<const char *> texts(fields.size());
    std::vector<size_t> lens(fields.size());
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, type, strlen(type), id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_, actor.empty() ? NULL : actor.data(),
            actor.size(), &cs));
    for (size_t i = 0; i < fields.size(); i++) {
      texts[i] = fields[i].second.c_str();
      lens[i] = fields[i].second.size();
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = fields[i].first.c_str();
      values[i].field_len = fields[i].first.size();
      values[i].texts = &texts[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK,
        (draft ? gdefcore_entity_save_draft : gdefcore_entity_save)(
            cs, id, strlen(id), "en", 2, values.data(), values.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  /** Stage a new draft of an existing entity, applied. */
  void Redraft(const std::string & id,
      const std::vector<std::pair<std::string, std::string> > & fields) {
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> values(fields.size());
    std::vector<const char *> texts(fields.size());
    std::vector<size_t> lens(fields.size());
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    for (size_t i = 0; i < fields.size(); i++) {
      texts[i] = fields[i].second.c_str();
      lens[i] = fields[i].second.size();
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = fields[i].first.c_str();
      values[i].field_len = fields[i].first.size();
      values[i].texts = &texts[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, id.data(), id.size(), "en", 2, values.data(),
            values.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }

  /** A form for @p target signed by @p who, carrying these values. */
  std::string Sign(const Who & who, const std::string & target,
      const std::vector<std::pair<std::string, std::string> > & fields) {
    std::vector<GDEFCORE_Value> values(fields.size());
    std::vector<const char *> texts(fields.size());
    std::vector<size_t> lens(fields.size());
    char * token = NULL;
    size_t n = 0;
    GDEFCORE_Request * req = Request(who);
    for (size_t i = 0; i < fields.size(); i++) {
      texts[i] = fields[i].second.c_str();
      lens[i] = fields[i].second.size();
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = fields[i].first.c_str();
      values[i].field_len = fields[i].first.size();
      values[i].texts = &texts[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_form_sign(catalog_, req, keyring_, root_, sizeof root_,
            who.session.data(), who.session.size(), "edit", 4, target.data(),
            target.size(), "en", 2, values.data(), values.size(), NULL, 0, &token,
            &n));
    std::string out(token == NULL ? "" : token, token == NULL ? 0 : n);
    gdefcore_text_free(catalog_, token);
    return out;
  }

  /** The head (VIEW_DRAFT) value of a field, or "<none>". */
  std::string Head(const std::string & id, const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    std::string out = "<none>";
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_DRAFT, id.data(),
            id.size(), "en", 2, field, strlen(field), &texts, &lens, &count) ==
            GDEFCORE_OK &&
        count > 0) {
      out.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return out;
  }

  /** The active revision's value of a field, or "<none>". */
  std::string Active(const std::string & id, const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    std::string out = "<none>";
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_ACTIVE, id.data(),
            id.size(), "en", 2, field, strlen(field), &texts, &lens, &count) ==
            GDEFCORE_OK &&
        count > 0) {
      out.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return out;
  }

  uint64_t Version(const std::string & id) {
    uint64_t v = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_version(catalog_, id.data(), id.size(), &v));
    return v;
  }

  /** The signed-form path: sign @p fields for @p target, then submit as @p who at
   * @p url. Says whether the handler ran and what it was told. */
  struct Result {
    bool served = false;
    bool written = false;     /* the target's version moved */
    int allowed = 99;
  };
  Result Submit(const Who & who, const std::string & url, const std::string & target,
      const std::vector<std::pair<std::string, std::string> > & fields,
      bool claim = true) {
    Result r;
    uint64_t before = Version(target);
    g_submit.session = who.session;
    g_submit.token = Sign(who, target, fields);
    g_submit.claim = claim;
    g_submit.ran = 0;
    g_submit.allowed = 99;
    g_submit.rc = GDEFCORE_ERR_INVALID;
    (void)Dispatch(Request(who), url);
    r.served = g_submit.ran != 0;
    r.allowed = g_submit.allowed;
    r.written = Version(target) != before;
    return r;
  }
};

typedef std::vector<std::pair<std::string, std::string> > Fields;

}  // namespace

/* ---- create is checked against the container the path names ---------------- */

TEST_F(EntryPath, CreateIsCheckedAgainstTheContainerThePathNames) {
  DefinePost();
  Declare(Perm("Create in containers", "create", GDEFCORE_ACCESS_ANY, kContainer));
  Role("creators");
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("creators", "Create in containers", "(= field.kind \"open\")"));
  Routes();
  Who who = Person("creators");
  Who nobody = Person(NULL);
  std::string open = Make(kContainer, Admin(), {{"kind", "open"}});
  std::string closed = Make(kContainer, Admin(), {{"kind", "closed"}});
  g_create.fields = {"title"};
  g_create.form_container = closed;
  g_create.ran = 0;
  /* The control: an open container. */
  EXPECT_EQ("container.new", Dispatch(Request(who), "/container/" + open + "/new"));
  EXPECT_EQ(1, g_create.allowed);
  /* The closed one is not a route at all, whatever the form claims. */
  g_create.ran = 0;
  g_create.allowed = 99;
  EXPECT_NE("container.new", Dispatch(Request(who), "/container/" + closed + "/new"));
  EXPECT_EQ(0, g_create.ran);
  /* The library's own answer for the same container, asked directly, agrees. */
  const char * fields[1] = {"title"};
  size_t lens[1] = {5};
  int allowed = 99;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(who), open.data(), open.size(),
          kPost, strlen(kPost), fields, lens, 1, &allowed));
  EXPECT_EQ(1, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(who), closed.data(), closed.size(),
          kPost, strlen(kPost), fields, lens, 1, &allowed));
  EXPECT_EQ(0, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(nobody), open.data(), open.size(),
          kPost, strlen(kPost), fields, lens, 1, &allowed));
  EXPECT_EQ(0, allowed);
  /* A container that does not exist, an id that is not an id, and a post named
   * as the container (the grant is on the container's type) are the same no. */
  std::string gone = FreshIdText();
  std::string post = Make(kPost, Admin(), {{"title", "p"}});
  for (const std::string * c : {&gone, &post}) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_can_create(catalog_, Request(who), c->data(), c->size(),
            kPost, strlen(kPost), fields, lens, 1, &allowed));
    EXPECT_EQ(0, allowed);
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(who), "not-an-id", 9, kPost,
          strlen(kPost), fields, lens, 1, &allowed));
  EXPECT_EQ(0, allowed);
}

TEST_F(EntryPath, ATypeLevelCreateAsksTheTypeNotAContainer) {
  DefinePost();
  Declare(Perm("Create posts", "create", GDEFCORE_ACCESS_ANY, kPost));
  Role("creators");
  Grant("creators", "Create posts");
  Who who = Person("creators");
  Who nobody = Person(NULL);
  const char * fields[1] = {"title"};
  size_t lens[1] = {5};
  int allowed = 99;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(who), NULL, 0, kPost,
          strlen(kPost), fields, lens, 1, &allowed));
  EXPECT_EQ(1, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(nobody), NULL, 0, kPost,
          strlen(kPost), fields, lens, 1, &allowed));
  EXPECT_EQ(0, allowed);
  /* The grant is for posts: it is not one for articles. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(who), NULL, 0, kArticle,
          strlen(kArticle), fields, lens, 1, &allowed));
  EXPECT_EQ(0, allowed);
}

TEST_F(EntryPath, ACreateCanBeLimitedFieldByField) {
  DefinePost();
  Declare(Perm("Create posts", "create", GDEFCORE_ACCESS_ANY, kPost));
  /* Only holders of this may supply `rank`. */
  Declare(Perm("Create with a rank", "create", GDEFCORE_ACCESS_ANY, kPost, "rank"));
  Role("creators");
  Role("rankers");
  Grant("creators", "Create posts");
  Grant("rankers", "Create posts");
  Grant("rankers", "Create with a rank");
  Who plain = Person("creators");
  Who ranker = Person("rankers");
  const char * title_only[1] = {"title"};
  size_t title_lens[1] = {5};
  const char * with_rank[2] = {"title", "rank"};
  size_t rank_lens[2] = {5, 4};
  int allowed = 99;
  /* The control: a field no permission limits is free. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(plain), NULL, 0, kPost,
          strlen(kPost), title_only, title_lens, 1, &allowed));
  EXPECT_EQ(1, allowed);
  /* `rank` is limited, and the plain creator does not hold its grant. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(plain), NULL, 0, kPost,
          strlen(kPost), with_rank, rank_lens, 2, &allowed));
  EXPECT_EQ(0, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_create(catalog_, Request(ranker), NULL, 0, kPost,
          strlen(kPost), with_rank, rank_lens, 2, &allowed));
  EXPECT_EQ(1, allowed);
  /* The field question on its own. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(plain), "create", 6, kPost,
          strlen(kPost), NULL, "rank", 4, &allowed));
  EXPECT_EQ(0, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(ranker), "create", 6, kPost,
          strlen(kPost), NULL, "rank", 4, &allowed));
  EXPECT_EQ(1, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(plain), "create", 6, kPost,
          strlen(kPost), NULL, "title", 5, &allowed));
  EXPECT_EQ(1, allowed);
  /* The limit is of `create`: an update of `rank` is not limited by it. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(plain), "update", 6, kPost,
          strlen(kPost), NULL, "rank", 4, &allowed));
  EXPECT_EQ(1, allowed);
}

TEST_F(EntryPath, AFieldGrantOnAnEntityIsDecidedOnTheStoredEntity) {
  DefinePost();
  Declare(Perm("Edit rank", "update", GDEFCORE_ACCESS_ANY, kPost, "rank"));
  Role("rankers");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("rankers", "Edit rank", kGroupA));
  Who who = Person("rankers");
  std::string a1 = Make(kPost, Admin(), {{"title", "a1"}, {"group", "a"}});
  std::string b1 = Make(kPost, Admin(), {{"title", "b1"}, {"group", "b"}});
  int allowed = 99;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(who), "update", 6, kPost,
          strlen(kPost), a1.c_str(), "rank", 4, &allowed));
  EXPECT_EQ(1, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(who), "update", 6, kPost,
          strlen(kPost), b1.c_str(), "rank", 4, &allowed));
  EXPECT_EQ(0, allowed);
  /* an entity that is not there, and one of another type: no */
  std::string gone = FreshIdText();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(who), "update", 6, kPost,
          strlen(kPost), gone.c_str(), "rank", 4, &allowed));
  EXPECT_EQ(0, allowed);
  std::string art = Make(kArticle, Admin(), {{"title", "x"}});
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can_field(catalog_, Request(who), "update", 6, kPost,
          strlen(kPost), art.c_str(), "rank", 4, &allowed));
  EXPECT_EQ(0, allowed);
  /* misuse */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_can_field(catalog_, NULL, "update", 6, kPost, strlen(kPost),
          NULL, "rank", 4, &allowed));
  EXPECT_EQ(0, allowed);
}

/* ---- the path helper itself ------------------------------------------------ */

TEST_F(EntryPath, AuthorizeAsksTheTokensTarget) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Publish posts", "publish", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  Role("publishers");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Grant("publishers", "Publish posts");
  Who ga = Person("group-a");
  Who pub = Person("publishers");
  std::string a1 = Make(kPost, Admin(), {{"title", "a1"}, {"group", "a"}});
  std::string b1 = Make(kPost, Admin(), {{"title", "b1"}, {"group", "b"}});
  auto Ask = [&](const Who & who, const std::string & target, const char * claimed,
                  const char * action) {
    std::string token = Sign(who, target, {{"title", "x"}});
    int allowed = 99;
    GDEFCORE_Result rc = gdefcore_form_authorize(catalog_, Request(who), keyring_,
        root_, sizeof root_, who.session.data(), who.session.size(), token.data(),
        token.size(), claimed, claimed == NULL ? 0 : strlen(claimed), action,
        strlen(action), &allowed);
    return rc == GDEFCORE_OK ? allowed : -1;
  };
  EXPECT_EQ(1, Ask(ga, a1, NULL, "update"));
  EXPECT_EQ(1, Ask(ga, a1, a1.c_str(), "update"));
  EXPECT_EQ(0, Ask(ga, b1, NULL, "update"));
  EXPECT_EQ(0, Ask(ga, b1, b1.c_str(), "update"));
  /* the id the request names is not the token's target: not about one entity */
  EXPECT_EQ(0, Ask(ga, b1, a1.c_str(), "update"));
  EXPECT_EQ(0, Ask(ga, a1, b1.c_str(), "update"));
  EXPECT_EQ(0, Ask(ga, a1, "not-an-id", "update"));
  /* another action is another question */
  EXPECT_EQ(0, Ask(ga, a1, NULL, "publish"));
  EXPECT_EQ(1, Ask(pub, a1, NULL, "publish"));
  EXPECT_EQ(0, Ask(pub, a1, NULL, "update"));
  /* a token that does not verify is an error, never a yes */
  int allowed = 99;
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_authorize(catalog_, Request(ga), keyring_, root_, sizeof root_,
          ga.session.data(), ga.session.size(), "junk", 4, NULL, 0, "update", 6,
          &allowed));
  EXPECT_EQ(0, allowed);
  /* another person's token is not usable by this one */
  std::string token = Sign(pub, a1, {{"title", "x"}});
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_authorize(catalog_, Request(ga), keyring_, root_, sizeof root_,
          ga.session.data(), ga.session.size(), token.data(), token.size(), NULL, 0,
          "update", 6, &allowed));
  EXPECT_EQ(0, allowed);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
