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
 * The access model is read from the store once for a configuration epoch and
 * used by every decision made while the epoch is the same (access.md, "What is
 * kept"). Keeping it is safe only if a decision never uses a copy of what the
 * store no longer says, and never uses one made for somebody else. Each test
 * here makes a decision, changes what it rests on, and makes the decision
 * again, on the same request where the request is what holds the copy, with
 * the allowed answer beside the denied one so that a copy that is never
 * dropped, or never found, is a test failing by name (tools/check-model.sh).
 */

#include "grants_fixture.h"

namespace {

using namespace gfx;

/* A catalog allocator that fails the one allocation asked for. */
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

class Model : public GrantsFixture {
 protected:
  std::string clerk_;
  std::string post_;
  GDEFCORE_Request * req_ = NULL;

  /* A post a clerk may read, and a request of the clerk's that has read it. */
  void Clerk() {
    DefinePost();
    Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
    Role("clerk");
    Grant("clerk", "Read posts");
    clerk_ = Principal("clerk");
    post_ = Save(Admin(), "A-post", "a");
    req_ = Req(clerk_);
    ASSERT_EQ("A-post", Read(req_, post_));
  }

  GDEFCORE_Result Revoke() {
    return gdefcore_access_revoke(catalog_, "clerk", 5, "Read posts", 10);
  }
};

/* A grant is taken away in the middle of a request: the request's next
 * decision is made without it. */
TEST_F(Model, ARevokeInTheMiddleOfARequestIsSeenByTheNextDecision) {
  Clerk();
  ASSERT_EQ(GDEFCORE_OK, Revoke());
  EXPECT_EQ("<denied>", Read(req_, post_));
  /* The control: a grant made again is held again, by the same request. */
  Grant("clerk", "Read posts");
  EXPECT_EQ("A-post", Read(req_, post_));
}

/* A grant is made in the middle of a request: the next decision has it. */
TEST_F(Model, AGrantInTheMiddleOfARequestIsSeenByTheNextDecision) {
  Clerk();
  ASSERT_EQ(GDEFCORE_OK, Revoke());
  ASSERT_EQ("<denied>", Read(req_, post_));
  Grant("clerk", "Read posts");
  EXPECT_EQ("A-post", Read(req_, post_));
}

/* A role is added to, and taken from, a principal in the middle of its own
 * request. */
TEST_F(Model, ARoleOfAPrincipalChangedInTheMiddleOfARequestIsSeen) {
  Clerk();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_remove_role(catalog_, clerk_.data(),
          clerk_.size(), "clerk", 5));
  EXPECT_EQ("<denied>", Read(req_, post_));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, clerk_.data(), clerk_.size(),
          "clerk", 5));
  EXPECT_EQ("A-post", Read(req_, post_));
}

/* A principal that is retired holds nothing, the next decision on. */
TEST_F(Model, APrincipalRetiredInTheMiddleOfARequestIsSeen) {
  Clerk();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_remove(catalog_, clerk_.data(), clerk_.size()));
  EXPECT_EQ("<denied>", Read(req_, post_));
  /* The control: another principal of the role reads it. */
  std::string other = Principal("clerk");
  EXPECT_EQ("A-post", Read(Req(other), post_));
}

/* A role that is deleted grants nothing, the next decision on. */
TEST_F(Model, ARoleDeletedInTheMiddleOfARequestIsSeen) {
  Clerk();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_delete_role(catalog_, "clerk", 5));
  EXPECT_EQ("<denied>", Read(req_, post_));
  /* A role made again under the name is a new role, with no grants, and the
   * principal that was given the old one is not given the new. */
  Role("clerk");
  EXPECT_EQ("<denied>", Read(req_, post_));
  Grant("clerk", "Read posts");
  EXPECT_EQ("A-post", Read(req_, post_));
}

/* What a module grants comes from the module host, not from the model: a
 * module disabled in the middle of a request stops granting at once, and one
 * enabled starts. */
TEST_F(Model, AModuleDisabledInTheMiddleOfARequestStopsGranting) {
  DefinePost();
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, "(= field.group \"a\")");
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  std::string nobody = Principal();
  std::string a = Save(Admin(), "A-post", "a");
  GDEFCORE_Request * req = Req(nobody);
  ASSERT_EQ("<denied>", Read(req, a));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", "(= field.group \"a\")")}));
  EXPECT_EQ("A-post", Read(req, a));
  ASSERT_EQ(GDEFCORE_OK, Disable("blog"));
  EXPECT_EQ("<denied>", Read(req, a));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", "(= field.group \"a\")")}));
  EXPECT_EQ("A-post", Read(req, a));
}

/* A model that could not be read is a failure of the decision that needed it
 * and is not kept: the next decision, with nothing failing, reads it again and
 * is decided as it should be. The failure is put at each allocation of the
 * first decision of a catalog that has read nothing (the reads of the model
 * are most of them), and after each the same catalog is asked again. A
 * principal with no role is never allowed, whatever failed. */
TEST_F(Model, AModelThatFailedToReadIsNotKeptAndTheNextDecisionReadsItAgain) {
  Clerk();
  std::string nobody = Principal();
  FailAlloc fa;
  fa.alloc.ctx = &fa;
  fa.alloc.malloc_fn = FaMalloc;
  fa.alloc.calloc_fn = FaCalloc;
  fa.alloc.realloc_fn = FaRealloc;
  fa.alloc.free_fn = FaFree;
  auto Decide = [&](GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
                    std::string * title) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    GDEFCORE_Result rc = gdefcore_access_read(catalog, request, post_.data(),
        post_.size(), "en", 2, "title", 5, &texts, &lens, &count, NULL);
    title->clear();
    if (rc == GDEFCORE_OK && count > 0) {
      title->assign(texts[0], lens[0]);
    }
    if (rc == GDEFCORE_OK) {
      gdefcore_values_free(catalog, texts, lens, count);
    }
    return rc;
  };
  auto Fresh = [&](const std::string & who) {
    GDEFCORE_Request * request = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &request));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request, who.data(), who.size()));
    return request;
  };
  /* The allocations the first decision of a cold catalog makes. */
  long total = 0;
  {
    GDEFCORE_Catalog * cold = NULL;
    GDEFCORE_Request * request = Fresh(clerk_);
    std::string title;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL,
            &fa.alloc, &cold));
    fa.armed = true;
    fa.target = 0;
    fa.seen = 0;
    ASSERT_EQ(GDEFCORE_OK, Decide(cold, request, &title));
    EXPECT_EQ("A-post", title);
    total = fa.seen;
    fa.armed = false;
    gdefcore_request_destroy(request);
    gdefcore_catalog_destroy(cold);
  }
  ASSERT_GT(total, 20) << "the model's reads were not reached";
  int failed = 0;
  int succeeded = 0;
  for (long n = 1; n <= total + 1; n++) {
    GDEFCORE_Catalog * cold = NULL;
    GDEFCORE_Request * request = Fresh(clerk_);
    GDEFCORE_Request * nobody_request = Fresh(nobody);
    std::string title;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL,
            &fa.alloc, &cold));
    fa.armed = true;
    fa.target = n;
    fa.seen = 0;
    GDEFCORE_Result rc = Decide(cold, request, &title);
    fa.armed = false;
    if (rc == GDEFCORE_OK && title == "A-post") {
      succeeded += 1;
    } else {
      failed += 1;
      EXPECT_EQ("", title) << "a failed decision read something, allocation " << n;
    }
    /* The principal with no role is never allowed, failure or not. */
    fa.armed = true;
    fa.target = n;
    fa.seen = 0;
    (void)Decide(cold, nobody_request, &title);
    fa.armed = false;
    EXPECT_EQ("", title) << "a principal with no role was allowed, allocation " << n;
    /* Nothing is failing now: the same catalog decides as it should. */
    GDEFCORE_Request * again = Fresh(clerk_);
    EXPECT_EQ(GDEFCORE_OK, Decide(cold, again, &title)) << "allocation " << n;
    EXPECT_EQ("A-post", title)
        << "a model that failed to read was kept, allocation " << n;
    GDEFCORE_Request * again_nobody = Fresh(nobody);
    (void)Decide(cold, again_nobody, &title);
    EXPECT_EQ("", title) << "allocation " << n;
    gdefcore_request_destroy(again_nobody);
    gdefcore_request_destroy(again);
    gdefcore_request_destroy(nobody_request);
    gdefcore_request_destroy(request);
    gdefcore_catalog_destroy(cold);
  }
  EXPECT_GT(failed, 0) << "no failure reached the decision";
  EXPECT_GT(succeeded, 0) << "the control, the allocation past the last, never decided";
}

/* What a catalog keeps is for every request of the catalog: a revoke is seen
 * by a request that has not decided yet, which has no copy of its own to drop. */
TEST_F(Model, ARevokeIsSeenByARequestThatHasNotDecidedYet) {
  Clerk();
  std::string colleague = Principal("clerk");
  ASSERT_EQ("A-post", Read(Req(colleague), post_));
  ASSERT_EQ(GDEFCORE_OK, Revoke());
  EXPECT_EQ("<denied>", Read(Req(colleague), post_));
  EXPECT_EQ("<denied>", Read(Req(clerk_), post_));
  Grant("clerk", "Read posts");
  EXPECT_EQ("A-post", Read(Req(colleague), post_));
  EXPECT_EQ("A-post", Read(Req(clerk_), post_));
}

/* The model a request holds is the request's to free, whichever of the two is
 * destroyed first: a request that outlives its catalog frees it, and a
 * catalog that outlives its requests frees the one it kept. */
TEST_F(Model, ARequestThatOutlivesItsCatalogFreesWhatItHolds) {
  GDEFCORE_Catalog * other = NULL;
  GDEFCORE_Request * request = NULL;
  Clerk();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
          &other));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &request));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request, clerk_.data(), clerk_.size()));
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_read(other, request, post_.data(), post_.size(), "en", 2,
          "title", 5, &texts, &lens, &count, NULL));
  gdefcore_values_free(other, texts, lens, count);
  gdefcore_catalog_destroy(other);
  gdefcore_request_destroy(request);
  /* And the other way round: the catalog is left with the one it kept. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
          &other));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &request));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request, clerk_.data(), clerk_.size()));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_read(other, request, post_.data(), post_.size(), "en", 2,
          "title", 5, &texts, &lens, &count, NULL));
  gdefcore_values_free(other, texts, lens, count);
  gdefcore_request_destroy(request);
  gdefcore_catalog_destroy(other);
}

/* A second catalog over the same store writes: the first catalog's requests
 * see it at their next decision, because the epoch they are filed under is
 * the store's and not the catalog's. */
TEST_F(Model, AnotherCatalogsWriteIsSeenByTheNextDecision) {
  GDEFCORE_Catalog * other = NULL;
  Clerk();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
          &other));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_revoke(other, "clerk", 5, "Read posts", 10));
  EXPECT_EQ("<denied>", Read(req_, post_));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_grant(other, "clerk", 5, "Read posts", 10, "core.role", 9));
  EXPECT_EQ("A-post", Read(req_, post_));
  gdefcore_catalog_destroy(other);
}

/* Two principals asking one after the other, on requests that are alive
 * together, are each decided on their own roles: what is kept for one is never
 * used for the other. */
TEST_F(Model, OnePrincipalIsNeverGivenAnothersGrants) {
  Clerk();
  std::string nobody = Principal();
  GDEFCORE_Request * req_nobody = Req(nobody);
  GDEFCORE_Request * req_anon = Req();
  for (int round = 0; round < 3; round++) {
    EXPECT_EQ("A-post", Read(req_, post_)) << round;
    EXPECT_EQ("<denied>", Read(req_nobody, post_)) << round;
    EXPECT_EQ("<denied>", Read(req_anon, post_)) << round;
    EXPECT_EQ("A-post", Read(Req(clerk_), post_)) << round;
    EXPECT_EQ("<denied>", Read(Req(nobody), post_)) << round;
  }
}

/* A request acting for another principal is decided on the grants of both
 * (the acting principal's are a ceiling): the roles kept for the one are not
 * used for the other, though they are asked of the same copy in the same
 * decision. */
TEST_F(Model, AnActingPrincipalIsNotGivenThePrincipalsGrants) {
  Clerk();
  std::string nobody = Principal();
  std::string colleague = Principal("clerk");
  EXPECT_EQ("<denied>", Read(Req(clerk_, nobody), post_));
  EXPECT_EQ("A-post", Read(Req(clerk_, colleague), post_));
  /* The same request asked again, on the copy it kept. */
  GDEFCORE_Request * acting = Req(clerk_, nobody);
  EXPECT_EQ("<denied>", Read(acting, post_));
  EXPECT_EQ("<denied>", Read(acting, post_));
}

/* More principals than a model keeps: each is still decided on its own roles
 * as the oldest are replaced. */
TEST_F(Model, ManyMorePrincipalsThanAreKeptAreEachDecidedOnTheirOwnRoles) {
  Clerk();
  std::vector<std::string> readers;
  std::vector<std::string> others;
  for (int i = 0; i < 150; i++) {
    readers.push_back(Principal("clerk"));
    others.push_back(Principal());
  }
  for (int round = 0; round < 3; round++) {
    for (size_t i = 0; i < readers.size(); i++) {
      ASSERT_EQ("A-post", Read(Req(readers[i]), post_)) << round << " " << i;
      ASSERT_EQ("<denied>", Read(Req(others[i]), post_)) << round << " " << i;
    }
  }
}

/* A request used with two catalogs, of two stores, is decided by each catalog
 * on what its own store says: the copy made for the first is not the second's,
 * even when both are at the same epoch. */
class OtherWorld : public GrantsFixture {
 public:
  void TestBody() override {}
  void Start() {
    SetUp();
    DefinePost();
    Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
    Role("clerk");
  }
  void Finish() { TearDown(); }
  using GrantsFixture::Admin;
  using GrantsFixture::Epoch;
  using GrantsFixture::Grant;
  using GrantsFixture::Role;
  using GrantsFixture::Principal;
  using GrantsFixture::Read;
  using GrantsFixture::Save;
};

TEST_F(Model, ARequestUsedWithTwoCatalogsIsDecidedByEachOnItsOwnStore) {
  OtherWorld other;
  Clerk();
  other.Start();
  /* In the other world nobody may read: its clerk role holds no grant. The
   * principal is the same text, because the request is. */
  std::string other_post = other.Save(other.Admin(), "B-post", "b");
  /* Both worlds at the same epoch, so that the epoch is not what tells the two
   * apart: whichever is behind makes roles nobody uses until it is level. */
  for (int filler = 0; other.Epoch() < Epoch(); filler++) {
    other.Role(("filler-b" + std::to_string(filler)).c_str());
  }
  for (int filler = 0; Epoch() < other.Epoch(); filler++) {
    Role(("filler-a" + std::to_string(filler)).c_str());
  }
  ASSERT_EQ(Epoch(), other.Epoch());
  for (int round = 0; round < 3; round++) {
    EXPECT_EQ("A-post", Read(req_, post_)) << round;
    EXPECT_EQ("<denied>", other.Read(req_, other_post)) << round;
  }
  /* The control: the other world granting its clerks the read does not make
   * the principal one of its clerks, and this world is as it was. */
  other.Grant("clerk", "Read posts");
  EXPECT_EQ("<denied>", other.Read(req_, other_post));
  EXPECT_EQ("A-post", Read(req_, post_));
  other.Finish();
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
