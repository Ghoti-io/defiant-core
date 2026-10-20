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

  /** The current revision's value of a field, or "<none>". */
  std::string Current(const std::string & id, const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    std::string out = "<none>";
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_CURRENT, id.data(),
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

/* ---- the attacks: a body cannot steer the check ---------------------------- */

TEST_F(EntryPath, AGroupBPostResubmittedAsGroupAIsRefused) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Routes();
  Who ga = Person("group-a");
  std::string a1 = Make(kPost, Admin(), {{"title", "a1"}, {"group", "a"}});
  std::string b1 = Make(kPost, Admin(), {{"title", "b1"}, {"group", "b"}});
  std::string a2 = Make(kPost, Admin(), {{"title", "a2"}, {"group", "a"}});

  /* The control: the principal edits a real group a post through the path. */
  Result ok = Submit(ga, "/post/" + a1 + "/submit", a1,
      {{"title", "a1 edited"}, {"group", "a"}});
  EXPECT_TRUE(ok.served);
  EXPECT_EQ(1, ok.allowed);
  EXPECT_TRUE(ok.written);
  EXPECT_EQ("a1 edited", Head(a1, "title"));

  /* The attack: the group b post, with the body saying group a. The route
   * check asks the stored post (group b) and the path is not served. */
  uint64_t before = Version(b1);
  Result attack = Submit(ga, "/post/" + b1 + "/submit", b1,
      {{"title", "pwned"}, {"group", "a"}});
  EXPECT_FALSE(attack.served);
  EXPECT_FALSE(attack.written);
  EXPECT_EQ(before, Version(b1));
  EXPECT_EQ("b1", Head(b1, "title"));
  EXPECT_EQ("b", Current(b1, "group"));
  /* and it is the answer for a post that does not exist */
  EXPECT_EQ(Dispatch(Request(ga), "/post/" + b1 + "/submit"),
      Dispatch(Request(ga), "/post/" + FreshIdText() + "/submit"));

  /* The same attack with a URL that is allowed (the group a post) and a form
   * for the group b post: the token's target decides, not the URL. */
  Result swapped = Submit(ga, "/post/" + a2 + "/submit", b1,
      {{"title", "pwned"}, {"group", "a"}});
  EXPECT_TRUE(swapped.served);          /* the route check passed: a2 is theirs */
  EXPECT_EQ(0, swapped.allowed);        /* the path refused: the form is for b1 */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, g_submit.rc);
  EXPECT_FALSE(swapped.written);
  EXPECT_EQ("b1", Head(b1, "title"));
  EXPECT_EQ("a2", Head(a2, "title"));

  /* And through a path that names no entity at all (only the type-level
   * question is asked of the route), the stored post still decides. */
  Result bare = Submit(ga, "/submit", b1, {{"title", "pwned"}, {"group", "a"}},
      false);
  EXPECT_TRUE(bare.served);
  EXPECT_EQ(0, bare.allowed);
  EXPECT_FALSE(bare.written);
  EXPECT_EQ("b1", Head(b1, "title"));
  /* The control for that route: the same bare path for a post that is theirs. */
  Result bare_ok = Submit(ga, "/submit", a2, {{"title", "a2 again"}, {"group", "a"}},
      false);
  EXPECT_TRUE(bare_ok.served);
  EXPECT_EQ(1, bare_ok.allowed);
  EXPECT_TRUE(bare_ok.written);
  EXPECT_EQ("a2 again", Head(a2, "title"));
}

TEST_F(EntryPath, TheCheckIsOnTheStoredPostBeforeTheChange) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Routes();
  Who ga = Person("group-a");
  std::string a1 = Make(kPost, Admin(), {{"title", "a1"}, {"group", "a"}});
  std::string a2 = Make(kPost, Admin(), {{"title", "a2"}, {"group", "a"}});
  /* Moving a post out of the group is allowed: the post, as stored, is
   * theirs. What the body says the group will be is not asked. */
  Result out = Submit(ga, "/post/" + a1 + "/submit", a1,
      {{"title", "moved"}, {"group", "b"}});
  EXPECT_TRUE(out.served);
  EXPECT_EQ(1, out.allowed);
  EXPECT_TRUE(out.written);
  EXPECT_EQ("moved", Head(a1, "title"));
  EXPECT_EQ("b", Head(a1, "group"));
  /* The write was a draft: the current revision, which conditions read, is
   * still group a, so the post is still theirs until it is activated. */
  EXPECT_EQ("a", Current(a1, "group"));
  EXPECT_TRUE(Submit(ga, "/post/" + a1 + "/submit", a1, {{"title", "again"}}).written);
  /* Control: publish the move, and the next edit is refused. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, a1.data(), a1.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ("b", Current(a1, "group"));
  Result late = Submit(ga, "/post/" + a1 + "/submit", a1, {{"title", "too late"}});
  EXPECT_FALSE(late.served);
  EXPECT_FALSE(late.written);
  EXPECT_NE("too late", Head(a1, "title"));
  (void)a2;
}

TEST_F(EntryPath, AnAuthorFieldSwappedToTheSubmittersIdIsRefused) {
  Declare(Perm("Edit by author", "update", GDEFCORE_ACCESS_ANY, kArticle));
  Declare(Perm("Edit own", "update", GDEFCORE_ACCESS_OWN, kArticle));
  Role("by-author-field");
  Role("owners");
  Routes();
  Who alice = Person("by-author-field");
  Who olive = Person("owners");
  Who bob = Person(NULL);
  /* The grant: update where the article's author field is the principal. */
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("by-author-field", "Edit by author",
          "(= field.author principal)"));
  Grant("owners", "Edit own");
  std::string bobs = Make(kArticle, bob.id, {{"title", "bobs"}, {"author", bob.id}});
  std::string alices = Make(kArticle, alice.id,
      {{"title", "alices"}, {"author", alice.id}});

  /* The control: her own article, through the path. */
  Result ok = Submit(alice, "/post/" + alices + "/submit", alices,
      {{"title", "alices edited"}, {"author", alice.id}});
  EXPECT_TRUE(ok.served);
  EXPECT_EQ(1, ok.allowed);
  EXPECT_TRUE(ok.written);
  EXPECT_EQ("alices edited", Head(alices, "title"));

  /* The attack: bob's article, the form's author set to alice. The stored
   * author is bob. */
  Result attack = Submit(alice, "/post/" + bobs + "/submit", bobs,
      {{"title", "pwned"}, {"author", alice.id}});
  EXPECT_FALSE(attack.served);
  EXPECT_FALSE(attack.written);
  EXPECT_EQ("bobs", Head(bobs, "title"));
  EXPECT_EQ(bob.id, Head(bobs, "author"));
  Result bare = Submit(alice, "/submit", bobs,
      {{"title", "pwned"}, {"author", alice.id}}, false);
  EXPECT_TRUE(bare.served);
  EXPECT_EQ(0, bare.allowed);
  EXPECT_FALSE(bare.written);
  EXPECT_EQ("bobs", Head(bobs, "title"));

  /* The same against `own`: it is the entity's creator, set by the system
   * when its first revision was written, and no field of a form can name it. */
  std::string olives = Make(kArticle, olive.id, {{"title", "olives"}, {"author", olive.id}});
  Result own_ok = Submit(olive, "/post/" + olives + "/submit", olives,
      {{"title", "olives edited"}, {"author", olive.id}});
  EXPECT_TRUE(own_ok.served);
  EXPECT_EQ(1, own_ok.allowed);
  EXPECT_TRUE(own_ok.written);
  Result own_attack = Submit(olive, "/post/" + bobs + "/submit", bobs,
      {{"title", "pwned"}, {"author", olive.id}});
  EXPECT_FALSE(own_attack.served);
  EXPECT_FALSE(own_attack.written);
  Result own_bare = Submit(olive, "/submit", bobs,
      {{"title", "pwned"}, {"author", olive.id}}, false);
  EXPECT_TRUE(own_bare.served);
  EXPECT_EQ(0, own_bare.allowed);
  EXPECT_FALSE(own_bare.written);
  EXPECT_EQ("bobs", Head(bobs, "title"));
  /* An edit by someone else does not hand the article over either: the
   * creator stays bob. */
  char * creator = NULL;
  size_t creator_len = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_creator(catalog_, bobs.data(), bobs.size(), &creator,
          &creator_len));
  EXPECT_EQ(bob.id, std::string(creator, creator_len));
  gdefcore_text_free(catalog_, creator);
}

TEST_F(EntryPath, TheCheckIsOnTheCurrentRevisionNotTheNewestDraft) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Routes();
  Who ga = Person("group-a");
  /* Theirs as published, with a newer draft that says group b. */
  std::string mine = Make(kPost, Admin(), {{"title", "mine"}, {"group", "a"}});
  Redraft(mine, {{"group", "b"}});
  EXPECT_EQ("b", Head(mine, "group"));
  EXPECT_EQ("a", Current(mine, "group"));
  Result ok = Submit(ga, "/post/" + mine + "/submit", mine, {{"title", "still mine"}});
  EXPECT_TRUE(ok.served);
  EXPECT_TRUE(ok.written);
  /* Not theirs as published, with a newer draft that says group a. */
  std::string theirs = Make(kPost, Admin(), {{"title", "theirs"}, {"group", "b"}});
  Redraft(theirs, {{"group", "a"}});
  EXPECT_EQ("a", Head(theirs, "group"));
  EXPECT_EQ("b", Current(theirs, "group"));
  Result no = Submit(ga, "/post/" + theirs + "/submit", theirs, {{"title", "mine now"}});
  EXPECT_FALSE(no.served);
  EXPECT_FALSE(no.written);
  Result bare = Submit(ga, "/submit", theirs, {{"title", "mine now"}}, false);
  EXPECT_EQ(0, bare.allowed);
  EXPECT_FALSE(bare.written);
}

TEST_F(EntryPath, AnOpenChangesetDoesNotSteerTheCheck) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Who ga = Person("group-a");
  std::string a1 = Make(kPost, Admin(), {{"title", "a1"}, {"group", "a"}});
  std::string b1 = Make(kPost, Admin(), {{"title", "b1"}, {"group", "b"}});
  int allowed = 99;
  /* The requests exist before the changeset does. */
  GDEFCORE_Request * for_b1 = Request(ga);
  GDEFCORE_Request * for_a1 = Request(ga);
  /* Staged, not applied: a changeset that would make b1 a group a post. */
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value value;
  const char * text = "a";
  size_t len = 1;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "group";
  value.field_len = 5;
  value.texts = &text;
  value.text_lens = &len;
  value.count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save_draft(cs, b1.data(), b1.size(), "en", 2, &value, 1));
  /* The staged data are visible to the unfiltered preview: the control. */
  {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(catalog_, cs, GDEFCORE_VIEW_CURRENT, b1.data(),
            b1.size(), "en", 2, "group", 5, &texts, &lens, &count));
    EXPECT_EQ("a", std::string(texts[0], lens[0]));
    gdefcore_values_free(catalog_, texts, lens, count);
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can(catalog_, for_b1, "update", 6, kPost, strlen(kPost),
          b1.c_str(), &allowed));
  EXPECT_EQ(0, allowed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_can(catalog_, for_a1, "update", 6, kPost, strlen(kPost),
          a1.c_str(), &allowed));
  EXPECT_EQ(1, allowed);   /* the control: the question is not just broken */
  gdefcore_changeset_destroy(cs);
}

TEST_F(EntryPath, TheStoredAuthorFieldDoesNotMakeAnOwner) {
  Declare(Perm("Edit own", "update", GDEFCORE_ACCESS_OWN, kArticle));
  Role("owners");
  Grant("owners", "Edit own");
  Routes();
  Who bob = Person("owners");
  Who eve = Person("owners");
  std::string bobs = Make(kArticle, bob.id, {{"title", "bobs"}, {"author", bob.id}});
  /* Someone with their own authority stores a revision whose author field
   * names eve and makes it the one in force. */
  Redraft(bobs, {{"author", eve.id}});
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, bobs.data(), bobs.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ(eve.id, Current(bobs, "author"));
  /* `own` is the entity's creator: bob still owns it (the control), and the
   * name in a field makes nobody its owner. */
  Result mine = Submit(bob, "/post/" + bobs + "/submit", bobs, {{"title", "bob again"}});
  EXPECT_TRUE(mine.served);
  EXPECT_EQ(1, mine.allowed);
  EXPECT_TRUE(mine.written);
  Result hers = Submit(eve, "/post/" + bobs + "/submit", bobs, {{"title", "eve's"}});
  EXPECT_FALSE(hers.served);
  EXPECT_FALSE(hers.written);
  Result bare = Submit(eve, "/submit", bobs, {{"title", "eve's"}}, false);
  EXPECT_EQ(0, bare.allowed);
  EXPECT_FALSE(bare.written);
  EXPECT_NE("eve's", Head(bobs, "title"));
}

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
