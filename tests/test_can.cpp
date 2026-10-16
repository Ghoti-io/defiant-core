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
 * Access-conditions story A5: one can(), memoized, shared by every caller.
 * One test (or group) per row of the story's matrix, and the equivalence
 * sweep: over a generated site, can() equals whether the operation it guards
 * succeeds, for an update, a publish, a delete, a route, a tab and a template
 * save. Each refusal has an allowed beside it, and the sweep counts both.
 */

#include "grants_fixture.h"

#include <set>

namespace {

using namespace gfx;

/* ---- a catalog allocator that can fail one allocation ------------------ */

struct FailAlloc {
  GCU_Allocator alloc;
  bool armed = false;
  long target = 0;
  long seen = 0;
};

bool Hit(FailAlloc * f) {
  if (!f->armed) {
    return false;
  }
  f->seen += 1;
  return f->target > 0 && f->seen == f->target;
}
void * FaMalloc(void * ctx, size_t n) {
  return Hit((FailAlloc *)ctx) ? NULL : malloc(n == 0 ? 1 : n);
}
void * FaCalloc(void * ctx, size_t count, size_t n) {
  return Hit((FailAlloc *)ctx) ? NULL
                               : calloc(count == 0 ? 1 : count, n == 0 ? 1 : n);
}
void * FaRealloc(void * ctx, void * p, size_t n) {
  return Hit((FailAlloc *)ctx) ? NULL : realloc(p, n == 0 ? 1 : n);
}
void FaFree(void *, void * p) { free(p); }

/* ---- routes ------------------------------------------------------------- */

/* A handler that owns the request and says which route answered. */
void Answer(const GDEFCORE_Route_Call * call) {
  gdefcore_request_set_resolution(call->request, call->machine, call->machine_len);
}

GDEFCORE_Routes * g_routes = NULL;

/* The page of a post: it answers with the tabs the request may use, drawn by
 * the library from this very call. */
void PageWithTabs(const GDEFCORE_Route_Call * call) {
  GDEFCORE_Route_Info * tabs = NULL;
  size_t n = 0;
  size_t i;
  std::string out = "tabs:";
  if (gdefcore_routes_tabs_visible(g_routes, "post.view", 9, call, &tabs, &n) ==
      GDEFCORE_OK) {
    for (i = 0; i < n; i++) {
      out += std::string(tabs[i].machine, tabs[i].machine_len) + ",";
    }
  }
  gdefcore_routes_free(g_routes, tabs);
  gdefcore_request_set_resolution(call->request, out.data(), out.size());
}

struct Ans {
  GDEFCORE_Result rc;
  int allowed;
  bool operator==(const Ans & o) const { return rc == o.rc && allowed == o.allowed; }
};

class Can : public GrantsFixture {
 protected:
  GDEFCORE_Routes * routes_ = NULL;

  void SetUp() override {
    GrantsFixture::SetUp();
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes_));
    g_routes = routes_;
  }

  std::string FreshIdText() {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
    return std::string(id);
  }

  void TearDown() override {
    gdefcore_routes_destroy(routes_);
    routes_ = NULL;
    GrantsFixture::TearDown();
  }

  Ans CanOn(GDEFCORE_Request * req, const char * permission, const std::string & id,
      const char * type = kPost) {
    Ans a;
    a.allowed = 99;
    a.rc = gdefcore_access_can(catalog_, req, permission, strlen(permission), type,
        strlen(type), id.empty() ? NULL : id.c_str(), &a.allowed);
    return a;
  }

  /** can() answers yes: no failure, allowed. */
  bool Yes(GDEFCORE_Request * req, const char * permission, const std::string & id,
      const char * type = kPost) {
    Ans a = CanOn(req, permission, id, type);
    return a.rc == GDEFCORE_OK && a.allowed == 1;
  }

  void Route(const char * machine, const char * path, int kind, const char * parent,
      const char * permission, const char * capture, int weight = 0,
      GDEFCORE_Route_Call_Fn fn = Answer) {
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
    spec.weight = weight;
    if (parent != NULL) {
      spec.parent = parent;
      spec.parent_len = strlen(parent);
    }
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

  /** The route that answered @p path for @p req, or "" when none did. */
  std::string Dispatch(GDEFCORE_Request * req, const std::string & path,
      GDEFCORE_Result * rc_out = NULL) {
    char * out = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_form_resolve(routes_, catalog_, req, path.data(),
        path.size(), &out, &n);
    std::string text;
    if (rc_out != NULL) {
      *rc_out = rc;
    }
    if (rc == GDEFCORE_OK && out != NULL) {
      text.assign(out, n);
      gdefcore_text_free(catalog_, out);
    }
    return text;
  }

  GDEFCORE_Request * Acting(const std::string & who, const std::string & agent) {
    return Req(who, agent);
  }

  size_t Revision(const std::string & id) {
    uint64_t seq = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision(catalog_, id.data(), id.size(), &seq));
    return (size_t)seq;
  }

  /** A guarded save of @p title, as @p req. */
  GDEFCORE_Result GuardedSave(GDEFCORE_Request * req, const std::string & id,
      const char * title) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value value;
    const char * text = title;
    size_t len = strlen(title);
    GDEFCORE_Result rc;
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "title";
    value.field_len = 5;
    value.texts = &text;
    value.text_lens = &len;
    value.count = 1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    gdefcore_changeset_set_request(cs, req);
    gdefcore_changeset_enforce_access(cs, 1);
    rc = gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, &value, 1);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result GuardedPublish(GDEFCORE_Request * req, const std::string & id) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    gdefcore_changeset_set_request(cs, req);
    gdefcore_changeset_enforce_access(cs, 1);
    rc = gdefcore_entity_publish(cs, id.data(), id.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /** A guarded revert of an entity that has one revision: a clear. */
  GDEFCORE_Result GuardedDelete(GDEFCORE_Request * req, const std::string & id) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc;
    rc = gdefcore_changeset_revert(catalog_, id.data(), id.size(), NULL, 0, &cs);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    gdefcore_changeset_set_request(cs, req);
    gdefcore_changeset_enforce_access(cs, 1);
    rc = gdefcore_changeset_apply(cs, "core.role", 9);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /** A post saved as a draft, so that it can be published. */
  std::string Draft(const std::string & actor, const char * title,
      const char * group) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[2];
    const char * texts[2] = {title, group};
    size_t lens[2] = {strlen(title), strlen(group)};
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPost, strlen(kPost), id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_, actor.empty() ? NULL : actor.data(),
            actor.size(), &cs));
    memset(values, 0, sizeof values);
    for (int i = 0; i < 2; i++) {
      values[i].size = sizeof values[i];
      values[i].field = i == 0 ? "title" : "group";
      values[i].field_len = 5;
      values[i].texts = &texts[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, id, strlen(id), "en", 2, values, 2));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }
};

const char kGroupA[] = "(= field.group \"a\")";
const char kGroupB[] = "(= field.group \"b\")";

}  // namespace

/* ---- the decision -------------------------------------------------------- */

TEST_F(Can, RoleAndModuleGrantsDecide) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Edit own posts", "update", GDEFCORE_ACCESS_OWN));
  Role("group-a");
  Role("authors");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Grant("authors", "Edit own posts");
  ModDef * m = NewMod("blog");
  m->Perm("blog.update", "update", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.update", kPost, kGroupB);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.update", "high", kGroupB)}))
      << last_error_;
  std::string grp = Principal("group-a");
  std::string author = Principal("authors");
  std::string nobody = Principal();
  std::string a1 = Save(author, "a1", "a");   /* author's, group a */
  std::string b1 = Save(grp, "b1", "b");      /* the grouper's, group b */
  std::string c1 = Save(Admin(), "c1", "c");  /* nobody's, group c */
  struct Row {
    const std::string * who;
    const std::string * entity;
    int want;
  };
  const Row rows[] = {
      {&grp, &a1, 1},     /* group a: the role's condition */
      {&grp, &b1, 1},     /* group b: the module's, held by everyone */
      {&grp, &c1, 0},
      {&author, &a1, 1},  /* their own */
      {&author, &b1, 1},  /* the module's */
      {&author, &c1, 0},
      {&nobody, &a1, 0},
      {&nobody, &b1, 1},  /* the module's, with no role at all */
      {&nobody, &c1, 0},
  };
  int yes = 0;
  int no = 0;
  for (const Row & r : rows) {
    Ans a = CanOn(Req(*r.who), "update", *r.entity);
    EXPECT_EQ(GDEFCORE_OK, a.rc);
    EXPECT_EQ(r.want, a.allowed) << "who " << (r.who == &grp ? "grp" : r.who == &author ? "author" : "nobody")
                                 << " entity " << (r.entity == &a1 ? "a1" : r.entity == &b1 ? "b1" : "c1");
    yes += a.allowed == 1;
    no += a.allowed == 0;
  }
  EXPECT_GT(yes, 0);
  EXPECT_GT(no, 0);
  /* The anonymous state has the module's grant too, and nothing else. */
  EXPECT_TRUE(Yes(Req(), "update", b1));
  EXPECT_FALSE(Yes(Req(), "update", a1));
  /* The permission is about the type given. */
  EXPECT_FALSE(Yes(Req(grp), "update", a1, "site.page"));
  /* Disabled, the module's grant is gone from the very next answer. */
  ASSERT_EQ(GDEFCORE_OK, Disable("blog"));
  EXPECT_FALSE(Yes(Req(nobody), "update", b1));
  EXPECT_TRUE(Yes(Req(grp), "update", a1));
}

TEST_F(Can, TypeLevelIsNotTheEntityQuestion) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  std::string grp = Principal("group-a");
  std::string a1 = Save(Admin(), "a1", "a");
  std::string b1 = Save(Admin(), "b1", "b");
  /* Could the principal hold it for some post? Yes: for the group a one. */
  EXPECT_TRUE(Yes(Req(grp), "update", std::string()));
  /* And for this particular post: only where it holds. The type-level answer
   * must not stand in for it. */
  EXPECT_TRUE(Yes(Req(grp), "update", a1));
  EXPECT_FALSE(Yes(Req(grp), "update", b1));
  /* Where no post is in the group, the type-level answer is a no as well. */
  Role("group-z");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-z", "Edit posts", "(= field.group \"z\")"));
  EXPECT_FALSE(Yes(Req(Principal("group-z")), "update", std::string()));
  /* It is the answer gdefcore_access_permits() gives. */
  EXPECT_EQ(Permits(grp, "update"), Yes(Req(grp), "update", std::string()) ? 1 : 0);
}

TEST_F(Can, UnknownMissingAndUnreadableAnswerAlike) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  std::string grp = Principal("group-a");
  std::string a1 = Save(Admin(), "a1", "a");
  std::string b1 = Save(Admin(), "b1", "b");   /* exists; no grant holds on it */
  std::string gone = FreshIdText();            /* never created */
  GDEFCORE_Request * req = Req(grp);
  /* The control: where a grant holds, it is a yes. */
  EXPECT_EQ((Ans{GDEFCORE_OK, 1}), CanOn(req, "update", a1));
  /* Each of these is the same no: a permission nobody declared, an entity that
   * does not exist, one on which no grant holds, an id that is not an id, the
   * wrong type. */
  const Ans no = {GDEFCORE_OK, 0};
  EXPECT_EQ(no, CanOn(req, "frobnicate", a1));
  EXPECT_EQ(no, CanOn(req, "update", gone));
  EXPECT_EQ(no, CanOn(req, "update", b1));
  EXPECT_EQ(no, CanOn(req, "update", "not-an-id"));
  EXPECT_EQ(no, CanOn(req, "update", a1, "site.page"));
  /* And to the anonymous state and to a principal who was removed. */
  EXPECT_EQ(no, CanOn(Req(), "update", a1));
  EXPECT_EQ(no, CanOn(Req(), "update", gone));
  std::string removed = Principal("group-a");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_remove(catalog_, removed.data(), removed.size()));
  EXPECT_EQ(no, CanOn(Req(removed), "update", a1));
  /* Bad arguments are misuse, not a no. */
  int allowed = 7;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_can(catalog_, req, NULL, 0, kPost, 9, NULL, &allowed));
  EXPECT_EQ(0, allowed);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_can(catalog_, NULL, "update", 6, kPost, 9, NULL, &allowed));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_can(catalog_, req, "update", 6, kPost, 9, NULL, NULL));
}

/* ---- the memo ------------------------------------------------------------- */

TEST_F(Can, MemoServesTheSecondQuestion) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  std::string grp = Principal("group-a");
  std::string a1 = Save(Admin(), "a1", "a");
  std::string b1 = Save(Admin(), "b1", "b");
  GDEFCORE_Request * req = Req(grp);
  size_t entries = 99;
  uint64_t hits = 99;
  gdefcore_request_memo_stats(req, &entries, &hits, NULL);
  EXPECT_EQ(0u, entries);
  EXPECT_EQ(0u, hits);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_fuel(req, 100));
  EXPECT_TRUE(Yes(req, "update", a1));
  gdefcore_request_memo_stats(req, &entries, &hits, NULL);
  EXPECT_EQ(1u, entries);
  EXPECT_EQ(0u, hits);
  EXPECT_EQ(100u - GDEFCORE_ACCESS_CAN_FUEL_MISS, gdefcore_request_fuel_left(req));
  /* The same question again: the same answer, from the memo, for less. */
  EXPECT_TRUE(Yes(req, "update", a1));
  gdefcore_request_memo_stats(req, &entries, &hits, NULL);
  EXPECT_EQ(1u, entries);
  EXPECT_EQ(1u, hits);
  EXPECT_EQ(100u - GDEFCORE_ACCESS_CAN_FUEL_MISS - GDEFCORE_ACCESS_CAN_FUEL_HIT,
      gdefcore_request_fuel_left(req));
  /* A different question is not a hit; a "no" is remembered as well. */
  EXPECT_FALSE(Yes(req, "update", b1));
  EXPECT_FALSE(Yes(req, "update", b1));
  gdefcore_request_memo_stats(req, &entries, &hits, NULL);
  EXPECT_EQ(2u, entries);
  EXPECT_EQ(2u, hits);
}

TEST_F(Can, AWriteInTheRequestIsANewQuestion) {
  DefinePost();
  Declare(Perm("Edit own posts", "update", GDEFCORE_ACCESS_OWN));
  Role("authors");
  Grant("authors", "Edit own posts");
  std::string me = Principal("authors");
  std::string you = Principal("authors");
  std::string post = Save(me, "mine", "a");
  GDEFCORE_Request * req = Req(me);
  size_t before = Revision(post);
  EXPECT_TRUE(Yes(req, "update", post));
  EXPECT_TRUE(Yes(req, "update", post));   /* remembered */
  /* Somebody else saves it: it is theirs now, by the revision the entity has. */
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value value;
    const char * text = "yours now";
    size_t len = strlen(text);
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "title";
    value.field_len = 5;
    value.texts = &text;
    value.text_lens = &len;
    value.count = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_, you.data(), you.size(), &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, post.data(), post.size(), "en", 2, &value, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_GT(Revision(post), before);
  /* The same request, the same question, a fresh answer. */
  EXPECT_FALSE(Yes(req, "update", post));
  EXPECT_TRUE(Yes(Req(you), "update", post));
  size_t entries = 0;
  gdefcore_request_memo_stats(req, &entries, NULL, NULL);
  EXPECT_EQ(2u, entries);   /* one per revision */
}

TEST_F(Can, MemoIsPerPrincipal) {
  DefinePost();
  Declare(Perm("Edit own posts", "update", GDEFCORE_ACCESS_OWN));
  Role("authors");
  Grant("authors", "Edit own posts");
  std::string me = Principal("authors");
  std::string you = Principal("authors");
  std::string post = Save(me, "mine", "a");
  GDEFCORE_Request * req = Req(me);
  EXPECT_TRUE(Yes(req, "update", post));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(req, you.data(), you.size()));
  EXPECT_FALSE(Yes(req, "update", post));   /* not the first one's answer */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(req, me.data(), me.size()));
  EXPECT_TRUE(Yes(req, "update", post));
  /* Nor across an acting principal. */
  std::string agent = Principal();          /* holds nothing: the ceiling is empty */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_acting_principal(req, agent.data(), agent.size()));
  EXPECT_FALSE(Yes(req, "update", post));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_acting_principal(req, NULL, 0));
  EXPECT_TRUE(Yes(req, "update", post));
}

TEST_F(Can, MemoIsBounded) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("editors");
  Grant("editors", "Edit posts");
  std::string ed = Principal("editors");
  std::string post = Save(Admin(), "p", "a");
  GDEFCORE_Request * req = Req(ed);
  const size_t total = GDEFCORE_REQUEST_MEMO_MAX * 3 + 10;
  size_t entries = 0;
  uint64_t restarts = 0;
  for (size_t i = 0; i < total; i++) {
    std::string name = "perm-" + std::to_string(i);
    EXPECT_FALSE(Yes(req, name.c_str(), post));
    gdefcore_request_memo_stats(req, &entries, NULL, NULL);
    ASSERT_LE(entries, (size_t)GDEFCORE_REQUEST_MEMO_MAX);
    if (i % 50 == 0) {
      /* The real question stays right whatever the memo has forgotten. */
      EXPECT_TRUE(Yes(req, "update", post)) << i;
    }
  }
  gdefcore_request_memo_stats(req, &entries, NULL, &restarts);
  EXPECT_GE(restarts, 2u);
  EXPECT_LE(entries, (size_t)GDEFCORE_REQUEST_MEMO_MAX);
  EXPECT_GT(entries, 0u);
}

/* ---- failure ------------------------------------------------------------- */

TEST_F(Can, NoFuelIsNotAYes) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("editors");
  Grant("editors", "Edit posts");
  std::string ed = Principal("editors");
  std::string post = Save(Admin(), "p", "a");
  /* The control: with fuel, a yes. */
  {
    GDEFCORE_Request * req = Req(ed);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_fuel(req, 100));
    EXPECT_EQ((Ans{GDEFCORE_OK, 1}), CanOn(req, "update", post));
  }
  /* Without enough, it is refused with a result and no yes, remembered or not. */
  for (uint64_t fuel = 0; fuel < GDEFCORE_ACCESS_CAN_FUEL_MISS; fuel++) {
    GDEFCORE_Request * req = Req(ed);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_fuel(req, fuel));
    Ans a = CanOn(req, "update", post);
    EXPECT_EQ(GDEFCORE_ERR_LIMIT, a.rc) << fuel;
    EXPECT_EQ(0, a.allowed) << fuel;
  }
  /* Once empty it stays empty, even for a question that was answered. */
  {
    GDEFCORE_Request * req = Req(ed);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_fuel(req, 5));
    EXPECT_EQ((Ans{GDEFCORE_OK, 1}), CanOn(req, "update", post));   /* 4 */
    EXPECT_EQ((Ans{GDEFCORE_OK, 1}), CanOn(req, "update", post));   /* hit: 1 */
    Ans a = CanOn(req, "update", post);                             /* none left */
    EXPECT_EQ(GDEFCORE_ERR_LIMIT, a.rc);
    EXPECT_EQ(0, a.allowed);
  }
}

TEST(CanFailures, AnAllocationThatFailsNeverGrants) {
  FailAlloc fa;
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Host * host = NULL;
  fa.alloc.ctx = &fa;
  fa.alloc.malloc_fn = FaMalloc;
  fa.alloc.calloc_fn = FaCalloc;
  fa.alloc.realloc_fn = FaRealloc;
  fa.alloc.free_fn = FaFree;
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store, (const uint8_t *)"t", 1, NULL, &fa.alloc,
          &catalog));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store, NULL, &host));
  gdefcore_catalog_bind_host(catalog, host);
  {
    GDEFCORE_Field f[2] = {Field("title"), Field("group")};
    GDEFCORE_Permission p = Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY);
    char who[GDEFCORE_PUBLIC_ID_LEN + 1];
    char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
    char a1[GDEFCORE_PUBLIC_ID_LEN + 1];
    char b1[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    const char * texts[2] = {"t", "a"};
    size_t lens[2] = {1, 1};
    GDEFCORE_Value values[2];
    long total;
    long n;
    int saw_failure = 0;
    int saw_yes = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog, kPost, strlen(kPost), GDEFCORE_TYPE_CONTENT,
            f, 2));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog, &p));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog, "ga", 2, NULL));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant_when(catalog, "ga", 2, "Edit posts", 10, kGroupA,
            strlen(kGroupA), "core.role", 9));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog, who));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_principal_add_role(catalog, who, strlen(who), "ga", 2));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog, admin));
    for (int k = 0; k < 2; k++) {
      char * id = k == 0 ? a1 : b1;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_entity_create(catalog, kPost, strlen(kPost), id, NULL));
      texts[1] = k == 0 ? "a" : "b";
      memset(values, 0, sizeof values);
      for (int i = 0; i < 2; i++) {
        values[i].size = sizeof values[i];
        values[i].field = i == 0 ? "title" : "group";
        values[i].field_len = 5;
        values[i].texts = &texts[i];
        values[i].text_lens = &lens[i];
        values[i].count = 1;
      }
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_changeset_prepare(catalog, admin, strlen(admin), &cs));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, values, 2));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
      gdefcore_changeset_destroy(cs);
    }
    /* Count the allocations one question makes. */
    {
      GDEFCORE_Request * req = NULL;
      int allowed = 9;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_request_create((const uint8_t *)"t", 1, 0, 0, NULL, &req));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(req, who, strlen(who)));
      fa.armed = true;
      fa.target = 0;
      fa.seen = 0;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_access_can(catalog, req, "update", 6, kPost, strlen(kPost), a1,
              &allowed));
      EXPECT_EQ(1, allowed);
      total = fa.seen;
      fa.armed = false;
      gdefcore_request_destroy(req);
    }
    ASSERT_GT(total, 5);
    /* A failure at each allocation: on the entity the grant does not cover, it
     * is never a yes; on the one it covers, a yes or a refusal that says why,
     * and a refusal is never a yes. */
    for (n = 1; n <= total; n++) {
      for (int k = 0; k < 2; k++) {
        GDEFCORE_Request * req = NULL;
        int allowed = 9;
        GDEFCORE_Result rc;
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_request_create((const uint8_t *)"t", 1, 0, 0, NULL, &req));
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_request_set_principal(req, who, strlen(who)));
        fa.armed = true;
        fa.target = n;
        fa.seen = 0;
        rc = gdefcore_access_can(catalog, req, "update", 6, kPost, strlen(kPost),
            k == 0 ? a1 : b1, &allowed);
        fa.armed = false;
        if (rc != GDEFCORE_OK) {
          EXPECT_EQ(0, allowed) << "a failure granted at allocation " << n;
          saw_failure = 1;
        }
        if (k == 1) {
          EXPECT_EQ(0, allowed) << "granted the uncovered entity at allocation " << n;
        } else if (rc == GDEFCORE_OK && allowed == 1) {
          saw_yes = 1;
        }
        gdefcore_request_destroy(req);
      }
    }
    EXPECT_EQ(1, saw_failure) << "no allocation failure reached the decision";
    EXPECT_EQ(1, saw_yes) << "the control never saw a yes";
  }
  gdefcore_catalog_bind_host(catalog, NULL);
  gdefcore_host_destroy(host);
  gdefcore_catalog_destroy(catalog);
  gdefstor_store_destroy(store);
}

TEST_F(Can, ACorruptConditionIsAFailureNotAYes) {
  /* The stored condition no longer parses: no answer, and the code says so. */
  DefinePost();
  Declare(Perm("Edit group a", "update", 0, kPost, NULL, kGroupA));
  Role("ga");
  Grant("ga", "Edit group a");
  std::string who = Principal("ga");
  std::string a1 = Save(Admin(), "a1", "a");
  EXPECT_EQ((Ans{GDEFCORE_OK, 1}), CanOn(Req(who), "update", a1));
  /* Overwrite the permission's stored condition with text that cannot parse. */
  {
    char ** ids = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(catalog_, "core.permission", 15, &ids, &n));
    for (size_t i = 0; i < n; i++) {
      char ** texts = NULL;
      size_t * lens = NULL;
      size_t c = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              strlen(ids[i]), "en", 2, "label", 5, &texts, &lens, &c) ==
          GDEFCORE_OK) {
        bool mine = c > 0 && std::string(texts[0], lens[0]) == "Edit group a";
        gdefcore_values_free(catalog_, texts, lens, c);
        if (mine) {
          GDEFCORE_Changeset * cs = NULL;
          GDEFCORE_Value value;
          const char * bad = "((";
          size_t bad_len = 2;
          memset(&value, 0, sizeof value);
          value.size = sizeof value;
          value.field = "condition";
          value.field_len = 9;
          value.texts = &bad;
          value.text_lens = &bad_len;
          value.count = 1;
          ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
          ASSERT_EQ(GDEFCORE_OK,
              gdefcore_entity_save(cs, ids[i], strlen(ids[i]), "en", 2, &value, 1));
          ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.permission", 15));
          gdefcore_changeset_destroy(cs);
        }
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
  }
  Ans a = CanOn(Req(who), "update", a1);
  EXPECT_NE(GDEFCORE_OK, a.rc);
  EXPECT_EQ(0, a.allowed);
  /* And it was not remembered: the next question fails the same way. */
  a = CanOn(Req(who), "update", a1);
  EXPECT_NE(GDEFCORE_OK, a.rc);
  EXPECT_EQ(0, a.allowed);
}

/* ---- the render key ------------------------------------------------------ */

TEST_F(Can, MarksTheRequestAndRecordsWhatItRead) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("editors");
  Grant("editors", "Edit posts");
  std::string ed = Principal("editors");
  std::string post = Save(Admin(), "p", "a");
  auto Key = [&](GDEFCORE_Request * r) {
    char * k = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(catalog_, r, NULL, 0, NULL, 0, &k, &n));
    std::string out(k, n);
    gdefcore_text_free(catalog_, k);
    return out;
  };
  GDEFCORE_Request * quiet = Req(ed);
  GDEFCORE_Request * asked = Req(ed);
  /* A request that asked nothing depends on nothing. */
  EXPECT_EQ(0, gdefcore_request_principal_dependent(quiet));
  EXPECT_EQ(0u, gdefcore_request_dependency_count(quiet));
  EXPECT_EQ(std::string::npos, Key(quiet).find("reads:"));
  /* One that called can() depends on its principal and on the entity it read,
   * at the revision it read. */
  EXPECT_TRUE(Yes(asked, "update", post));
  EXPECT_EQ(1, gdefcore_request_principal_dependent(asked));
  ASSERT_EQ(1u, gdefcore_request_dependency_count(asked));
  {
    const char * id = NULL;
    size_t id_len = 0;
    uint64_t revision = 0;
    ASSERT_EQ(1, gdefcore_request_dependency_at(asked, 0, &id, &id_len, &revision));
    EXPECT_EQ(post, std::string(id, id_len));
    EXPECT_EQ(Revision(post), (size_t)revision);
  }
  EXPECT_NE(std::string::npos, Key(asked).find("\nreads:"));
  EXPECT_NE(std::string::npos, Key(asked).find(std::string("\nprincipal:") + ed));
  EXPECT_EQ(std::string::npos, Key(quiet).find(std::string("\nprincipal:") + ed));
  /* The key moves when what was read moves. */
  std::string before = Key(asked);
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value value;
    const char * text = "changed";
    size_t len = strlen(text);
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "title";
    value.field_len = 5;
    value.texts = &text;
    value.text_lens = &len;
    value.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, post.data(), post.size(), "en", 2, &value, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  GDEFCORE_Request * later = Req(ed);
  EXPECT_TRUE(Yes(later, "update", post));
  EXPECT_NE(before, Key(later));
  /* A question about a missing entity reads nothing. */
  GDEFCORE_Request * missing = Req(ed);
  EXPECT_FALSE(Yes(missing, "update", FreshIdText()));
  EXPECT_EQ(0u, gdefcore_request_dependency_count(missing));
  EXPECT_EQ(1, gdefcore_request_principal_dependent(missing));
  /* The set is bounded, and says when it overflowed. */
  {
    GDEFCORE_Request * many = Req(ed);
    for (size_t i = 0; i < GDEFCORE_REQUEST_READS_MAX + 5; i++) {
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_request_record_dependency(many, id, strlen(id), 1));
    }
    EXPECT_EQ((size_t)GDEFCORE_REQUEST_READS_MAX, gdefcore_request_dependency_count(many));
    EXPECT_EQ(1, gdefcore_request_dependencies_overflowed(many));
    EXPECT_NE(std::string::npos, Key(many).find("+overflow"));
    EXPECT_EQ(std::string::npos, Key(asked).find("+overflow"));
  }
}

/* ---- routes and tabs ---------------------------------------------------- */

TEST_F(Can, RouteAndTabsFollowTheDecision) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Publish posts", "publish", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  Role("publisher");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Grant("publisher", "Publish posts");
  Route("post.view", "/post/:id", GDEFCORE_ROUTE_PAGE, NULL, NULL, NULL, 10,
      PageWithTabs);
  Route("post.edit", "/post/:id/edit", GDEFCORE_ROUTE_TAB, "post.view", "update",
      "id", 1);
  Route("post.publish", "/post/:id/publish", GDEFCORE_ROUTE_TAB, "post.view",
      "publish", "id", 2);
  Route("post.new", "/post-new", GDEFCORE_ROUTE_PAGE, NULL, "update", NULL);
  Route("post.mystery", "/post/:id/mystery", GDEFCORE_ROUTE_TAB, "post.view",
      "frobnicate", "id", 3);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_routes_set_check(routes_, gdefcore_access_route_check, catalog_));
  std::string ga = Principal("group-a");
  std::string pub = Principal("publisher");
  std::string both = Principal("group-a");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, both.data(), both.size(),
          "publisher", 9));
  std::string nobody = Principal();
  std::string a1 = Save(Admin(), "a1", "a");
  std::string b1 = Save(Admin(), "b1", "b");
  std::string gone = FreshIdText();
  int served = 0;
  int refused = 0;
  for (const std::string * who : {&ga, &pub, &both, &nobody}) {
    for (const std::string * id : {&a1, &b1, &gone}) {
      GDEFCORE_Request * req = Req(*who);
      bool edit = Yes(req, "update", *id);
      bool publish = Yes(req, "publish", *id);
      /* Dispatch serves a tab exactly when the decision says yes. A tab that
       * is refused does not match, so what answers is what answers a path
       * with no such tab: the page, which matches the paths below it. */
      std::string page = Dispatch(Req(*who), "/post/" + *id);
      EXPECT_EQ(edit ? "post.edit" : page,
          Dispatch(Req(*who), "/post/" + *id + "/edit"));
      EXPECT_EQ(publish ? "post.publish" : page,
          Dispatch(Req(*who), "/post/" + *id + "/publish"));
      EXPECT_EQ(page, Dispatch(Req(*who), "/post/" + *id + "/mystery"));
      served += edit + publish;
      refused += !edit + !publish;
      /* The menu: the tabs of the page, as dispatch would serve them. */
      EXPECT_EQ(std::string("tabs:") + (edit ? "post.edit," : "") +
                    (publish ? "post.publish," : ""),
          Dispatch(Req(*who), "/post/" + *id))
          << "menu for " << *id;
    }
  }
  /* The sweep saw both outcomes. */
  EXPECT_GT(served, 3);
  EXPECT_GT(refused, 3);
  /* A refusal is a missing route's answer: the denied entity and one that does
   * not exist look alike. */
  {
    GDEFCORE_Result rc_denied = GDEFCORE_OK;
    GDEFCORE_Result rc_missing = GDEFCORE_OK;
    std::string d = Dispatch(Req(ga), "/post/" + b1 + "/edit", &rc_denied);
    std::string m = Dispatch(Req(ga), "/post/" + gone + "/edit", &rc_missing);
    EXPECT_EQ(d, m);
    EXPECT_EQ(rc_denied, rc_missing);
    EXPECT_EQ("post.edit", Dispatch(Req(ga), "/post/" + a1 + "/edit"));   /* control */
    EXPECT_NE("post.edit", d);
  }
  /* A route with no capture asks the type-level question. */
  EXPECT_EQ("post.new", Dispatch(Req(ga), "/post-new"));
  EXPECT_EQ("", Dispatch(Req(nobody), "/post-new"));
  /* A capture that is not an entity id is a no: the tab does not match. */
  EXPECT_EQ("tabs:", Dispatch(Req(both), "/post/not-an-id/edit"));
}

TEST_F(Can, RouteSpecsKeepTheirMeaning) {
  /* An entity capture must name a capture of the pattern; a spec from before
   * the field existed is accepted and names none. */
  GDEFCORE_Route_Spec spec;
  char * err = NULL;
  size_t err_len = 0;
  memset(&spec, 0, sizeof spec);
  spec.size = sizeof spec;
  spec.machine = "a";
  spec.machine_len = 1;
  spec.path = "/a/:id";
  spec.path_len = 6;
  spec.call_fn = Answer;
  spec.permission = "update";
  spec.permission_len = 6;
  spec.entity_capture = "nope";
  spec.entity_capture_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &spec, &err, &err_len));
  gdefcore_routes_free(routes_, err);
  spec.entity_capture = "id";
  spec.entity_capture_len = 2;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes_, &spec, NULL, NULL));
  spec.machine = "b";
  spec.path = "/b/:id";
  spec.entity_capture = NULL;
  spec.entity_capture_len = 0;
  spec.size = GDEFCORE_ROUTE_SPEC_SIZE_V1;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes_, &spec, NULL, NULL));
  spec.machine = "c";
  spec.path = "/c/:id";
  spec.size = GDEFCORE_ROUTE_SPEC_SIZE_V1 - 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &spec, NULL, NULL));
}

/* ---- the ceiling ---------------------------------------------------------- */

TEST_F(Can, AnAgentIsBoundByItsCeiling) {
  /* An agent acting for a person has the intersection of the two sets, with
   * the person's conditions on the person's grants. */
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  Role("editors");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  Grant("editors", "Edit posts");
  std::string person = Principal("group-a");
  std::string agent_ok = Principal("editors");     /* may edit anything */
  std::string agent_none = Principal();            /* may edit nothing */
  std::string a1 = Save(Admin(), "a1", "a");
  std::string b1 = Save(Admin(), "b1", "b");
  EXPECT_TRUE(Yes(Req(person), "update", a1));
  EXPECT_FALSE(Yes(Req(person, agent_none), "update", a1));
  EXPECT_FALSE(Yes(Req(person, agent_none), "update", std::string()));
  EXPECT_TRUE(Yes(Req(person, agent_ok), "update", a1));
  /* The agent's wider set does not widen the person's. */
  EXPECT_TRUE(Yes(Req(agent_ok), "update", b1));
  EXPECT_FALSE(Yes(Req(person, agent_ok), "update", b1));
  /* Acting as oneself is not an agent. */
  EXPECT_TRUE(Yes(Req(person, person), "update", a1));
}

/* ---- the equivalence sweep ----------------------------------------------- */

namespace {

/* What a person's roles grant (bits), and what their agent's roles do. */
enum {
  kRoleRead = 1,
  kRoleGroupA = 2,   /* edit posts of group a */
  kRoleOwn = 4,      /* edit their own */
  kRolePublish = 8,
  kRoleDelete = 16
};
enum { kCeilRead = 1, kCeilUpdate = 2, kCeilPublish = 4, kCeilDelete = 8 };
enum { kOpUpdate, kOpPublish, kOpDelete, kOpRead };

struct Person {
  std::string name;
  std::string id;      /* the principal; empty is the anonymous state */
  std::string acting;  /* the acting principal, or empty */
  unsigned roles;
  unsigned ceiling;    /* what the acting principal's roles hold */
};

/*
 * The decision, written apart from the library: a second implementation of
 * the fixture's rules to compare with. The module grants update of posts in
 * group b to everyone; the roles are as the table says; an acting principal
 * must hold the same permission by its own roles (a module grant is not part
 * of its set); reading is of the published projection.
 */
bool Model(const Person & p, int op, char group, const std::string & actor,
    bool draft) {
  bool own = !p.id.empty() && actor == p.id;   /* the actor is the principal */
  bool mine = false;
  unsigned need = 0;
  switch (op) {
    case kOpUpdate:
      /* A condition that reads the entity reads the published projection, and
       * a draft that was never published has none (nor an actor). */
      mine = !draft && (((p.roles & kRoleGroupA) && group == 'a') ||
                           ((p.roles & kRoleOwn) && own) || group == 'b');
      need = kCeilUpdate;
      break;
    case kOpPublish:
      mine = (p.roles & kRolePublish) != 0;
      need = kCeilPublish;
      break;
    case kOpDelete:
      mine = (p.roles & kRoleDelete) != 0;
      need = kCeilDelete;
      break;
    default:
      mine = (p.roles & kRoleRead) != 0 && !draft;
      need = kCeilRead;
      break;
  }
  if (!p.acting.empty()) {
    mine = mine && (p.ceiling & need) != 0;
  }
  return mine;
}

}  // namespace

TEST_F(Can, TheDecisionIsTheOperation) {
  /* A generated site: principals with role grants, with module grants, with
   * own, any and field conditions, agents with a ceiling; entities that are
   * theirs or not, in each group, draft and published. For every (principal,
   * entity), the decision is asked first, then the operation is done with
   * access enforced on a changeset of that request, and the two must agree:
   * an update, a publish, a delete (a revert to nothing), a read, and the
   * route and the tab that stand for an edit and a publish. */
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Edit own posts", "update", GDEFCORE_ACCESS_OWN));
  Declare(Perm("Publish posts", "publish", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Delete posts", "delete", GDEFCORE_ACCESS_ANY));
  Role("r-read");
  Role("r-ga");
  Role("r-author");
  Role("r-pub");
  Role("r-del");
  Role("r-all");
  Role("r-pubonly");
  Grant("r-read", "Read posts");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("r-ga", "Edit posts", kGroupA));
  Grant("r-author", "Edit own posts");
  Grant("r-pub", "Publish posts");
  Grant("r-del", "Delete posts");
  for (const char * label : {"Read posts", "Edit posts", "Publish posts", "Delete posts"}) {
    Grant("r-all", label);
  }
  Grant("r-pubonly", "Publish posts");
  ModDef * m = NewMod("blog");
  m->Perm("blog.update", "update", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.update", kPost, kGroupB);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.update", "high", kGroupB)}))
      << last_error_;
  Route("post.view", "/post/:id", GDEFCORE_ROUTE_PAGE, NULL, NULL, NULL, 10,
      PageWithTabs);
  Route("post.edit", "/post/:id/edit", GDEFCORE_ROUTE_TAB, "post.view", "update",
      "id", 1);
  Route("post.publish", "/post/:id/publish", GDEFCORE_ROUTE_TAB, "post.view",
      "publish", "id", 2);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_routes_set_check(routes_, gdefcore_access_route_check, catalog_));
  std::string author = Principal("r-author");
  std::string ga = Principal("r-ga");
  std::string pub = Principal("r-pub");
  std::string del = Principal("r-del");
  std::string reader = Principal("r-read");
  std::string mixed = Principal("r-ga");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, mixed.data(), mixed.size(),
          "r-pub", 5));
  std::string nobody = Principal();
  std::string ag_all = Principal("r-all");
  std::string ag_pub = Principal("r-pubonly");
  std::string ag_none = Principal();
  const unsigned all = kCeilRead | kCeilUpdate | kCeilPublish | kCeilDelete;
  const Person people[] = {
      {"anonymous", "", "", 0, 0},
      {"nobody", nobody, "", 0, 0},
      {"reader", reader, "", kRoleRead, 0},
      {"author", author, "", kRoleOwn, 0},
      {"ga", ga, "", kRoleGroupA, 0},
      {"pub", pub, "", kRolePublish, 0},
      {"del", del, "", kRoleDelete, 0},
      {"mixed", mixed, "", kRoleGroupA | kRolePublish, 0},
      {"ga/all", ga, ag_all, kRoleGroupA, all},
      {"ga/none", ga, ag_none, kRoleGroupA, 0},
      {"mixed/pub", mixed, ag_pub, kRoleGroupA | kRolePublish, kCeilPublish},
      {"author/all", author, ag_all, kRoleOwn, all},
      {"del/pub", del, ag_pub, kRoleDelete, kCeilPublish},
      {"nobody/all", nobody, ag_all, 0, all},
      {"nobody/none", nobody, ag_none, 0, 0},
  };
  const char * groups[] = {"a", "b", "c"};
  int seen[7][2] = {};   /* operation x (no, yes) */
  enum { kUpdate, kPublish, kDelete, kRead, kRoute, kTabs, kPage };
  size_t checks = 0;
  for (const Person & who : people) {
    for (const char * group : groups) {
      /* theirs, someone's, no one's: the author varies only where an `own`
       * grant can tell (everyone else gets the one that is someone's). */
      const bool own_matters = who.id == author;
      for (int owner = own_matters ? 0 : 1; owner < (own_matters ? 3 : 2); owner++) {
        for (int draft = 0; draft < 2; draft++) {
          const std::string actor = owner == 0 ? who.id : owner == 1 ? author : "";
          std::string label = who.name + "/" + group + "/" + std::to_string(owner) +
                              "/" + (draft ? "draft" : "published");
          auto Make = [&]() {
            std::string id = draft ? Draft(actor, "t", group) : Save(actor, "t", group);
            return id;
          };
          /* update */
          {
            std::string id = Make();
            bool want = Yes(Req(who.id, who.acting), "update", id);
            bool got = GuardedSave(Req(who.id, who.acting), id, "changed") == GDEFCORE_OK;
            EXPECT_EQ(want, got) << "update " << label;
            EXPECT_EQ(Model(who, kOpUpdate, group[0], actor, draft != 0), want)
                << "update " << label;
            seen[kUpdate][want]++;
            checks++;
          }
          /* publish */
          {
            std::string id = Make();
            bool want = Yes(Req(who.id, who.acting), "publish", id);
            bool got = GuardedPublish(Req(who.id, who.acting), id) == GDEFCORE_OK;
            EXPECT_EQ(want, got) << "publish " << label;
            EXPECT_EQ(Model(who, kOpPublish, group[0], actor, draft != 0), want)
                << "publish " << label;
            seen[kPublish][want]++;
            checks++;
          }
          /* delete: a revert of an entity with one revision (of a published
           * one: a draft that was never published has nothing to revert to) */
          {
            std::string id = Save(actor, "t", group);
            bool want = Yes(Req(who.id, who.acting), "delete", id);
            bool got = GuardedDelete(Req(who.id, who.acting), id) == GDEFCORE_OK;
            EXPECT_EQ(want, got) << "delete " << label;
            EXPECT_EQ(Model(who, kOpDelete, group[0], actor, false), want)
                << "delete " << label;
            seen[kDelete][want]++;
            checks++;
          }
          /* read: the decision is the filtered read's */
          {
            std::string id = Make();
            bool want = Yes(Req(who.id, who.acting), "read", id);
            bool got = Read(Req(who.id, who.acting), id) != "<denied>";
            EXPECT_EQ(want, got) << "read " << label;
            EXPECT_EQ(Model(who, kOpRead, group[0], actor, draft != 0), want)
                << "read " << label;
            seen[kRead][want]++;
            checks++;
          }
          /* the route and the tab that stand for an edit and a publish */
          {
            std::string id = Make();
            bool edit = Yes(Req(who.id, who.acting), "update", id);
            bool publish = Yes(Req(who.id, who.acting), "publish", id);
            std::string page = Dispatch(Req(who.id, who.acting), "/post/" + id);
            EXPECT_EQ(edit ? "post.edit" : page,
                Dispatch(Req(who.id, who.acting), "/post/" + id + "/edit"))
                << "route " << label;
            EXPECT_EQ(publish ? "post.publish" : page,
                Dispatch(Req(who.id, who.acting), "/post/" + id + "/publish"))
                << "route " << label;
            seen[kRoute][edit]++;
            seen[kRoute][publish]++;
            EXPECT_EQ(std::string("tabs:") + (edit ? "post.edit," : "") +
                          (publish ? "post.publish," : ""),
                page)
                << "tabs " << label;
            seen[kTabs][edit || publish]++;
            checks += 3;
          }
        }
      }
    }
  }
  /* The sweep is wide, and saw both outcomes of each operation. */
  EXPECT_GE(checks, 500u);
  for (int op = kUpdate; op <= kTabs; op++) {
    EXPECT_GE(seen[op][0], 3) << "operation " << op << " never refused";
    EXPECT_GE(seen[op][1], 3) << "operation " << op << " never allowed";
  }
}

TEST_F(Can, TemplateSaveIsTheDecision) {
  /* The template editor asks the same question about the template entity. A
   * principal edits panes by a role, by a module's grant of the kernel's
   * permission, or not at all; an agent adds the ceiling. */
  uint8_t * bytes = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
  gdefcore_text_free(catalog_, (char *)bytes);
  char * label = NULL;
  size_t label_len = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_edit_label(catalog_, "core.pane", 9, &label, &label_len));
  std::string pane_label(label, label_len);
  gdefcore_text_free(catalog_, label);
  char name[300];
  size_t name_len = gdefcore_template_edit_name("core.pane", 9, name, sizeof name);
  ASSERT_GT(name_len, 0u);
  Role("pane-editors");
  Grant("pane-editors", pane_label.c_str());
  std::string editor = Principal("pane-editors");
  std::string nobody = Principal();
  std::string agent_ok = Principal("pane-editors");
  std::string agent_none = Principal();
  const std::string body = "<% use title; %><h2><%= title %></h2>";
  auto Try = [&](const std::string & who, const std::string & acting,
                  const char * template_name) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * slots[3] = {template_name, body.c_str(), "core.pane"};
    size_t lens[3] = {strlen(template_name), body.size(), 9};
    const char * fields[3] = {"name", "body", "kind"};
    GDEFCORE_Request * req = Req(who, acting);
    int want = 0;
    GDEFCORE_Result rc;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "core.template", 13, id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_can(catalog_, req, name, name_len, "core.template", 13, id,
            &want));
    memset(values, 0, sizeof values);
    for (int i = 0; i < 3; i++) {
      values[i].size = sizeof values[i];
      values[i].field = fields[i];
      values[i].field_len = strlen(fields[i]);
      values[i].texts = &slots[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    gdefcore_changeset_set_request(cs, req);
    rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 3);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, "core.template", 13);
    }
    gdefcore_changeset_destroy(cs);
    EXPECT_EQ(want == 1, rc == GDEFCORE_OK) << who << " acting " << acting;
    return want == 1;
  };
  int yes = 0;
  int no = 0;
  (Try(editor, "", "p1") ? yes : no)++;
  (Try(nobody, "", "p2") ? yes : no)++;
  (Try(editor, agent_ok, "p3") ? yes : no)++;
  (Try(editor, agent_none, "p4") ? yes : no)++;
  (Try(std::string(), "", "p5") ? yes : no)++;
  EXPECT_EQ(2, yes);
  EXPECT_EQ(3, no);
  /* A module may grant the kernel's permission, and that is an editor too:
   * for everyone it applies to, the decision and the editor say yes. */
  ModDef * m = NewMod("panes");
  m->Grant(pane_label, "core.template", "(= type \"core.template\")");
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("panes", {GrantLine("panes", pane_label, "high",
                           "(= type \"core.template\")")}))
      << last_error_;
  EXPECT_TRUE(Try(nobody, "", "p6"));
  EXPECT_TRUE(Try(std::string(), "", "p7"));
  /* ...but within the ceiling: an agent whose roles lack the permission. */
  EXPECT_FALSE(Try(nobody, agent_none, "p8"));
  EXPECT_TRUE(Try(nobody, agent_ok, "p9"));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
