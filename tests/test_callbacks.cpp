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
 * Access callbacks (access-conditions story A6, CAP-A5): a module registers a
 * callback that grants a field or an operation, per entity, for what data
 * cannot say ("has this reader paid for this article"). The paywall is the
 * fixture: articles with a title everyone who may read the article sees, and
 * a body the billing module's callback grants to those who paid.
 *
 * Every test has a control: the principal who paid beside the one who did
 * not, the field that is not governed beside the one that is, the callback
 * that answers beside the one that fails. tools/check-callbacks.sh plants a
 * defect in the source for each Never of the story and requires the named
 * test here to fail.
 */

#include "grants_fixture.h"
#include "size_structs.h"

#include <chrono>
#include <thread>

using namespace gfx;

namespace {

const char kArticle[] = "news.article";
const char kBodyPerm[] = "Read article body";
const char kEditPerm[] = "Edit article";
const char kViewPerm[] = "View articles";

/* What the billing callback knows, and what it was asked. */
struct BillingState {
  std::set<std::pair<std::string, std::string> > paid; /* (principal, id) */
  std::string token = "v1";
  int mode = 0;
  int calls = 0;
  size_t last_count = 0;
  size_t asked = 0;
  GDEFCORE_Catalog * catalog = NULL;
  std::string nested; /* what a read from inside the callback saw */
  size_t question_size = 0; /* the size of the question the host built */
  bool set_answer_size = false; /* answer in a block of this size instead */
  size_t answer_size = 0;
};

enum {
  kAnswer = 0,
  kTrap = 1,
  kOutOfFuel = 2,
  kSlow = 3,
  kMalformed = 4,
  kReenter = 5,
  kNoToken = 6
};

BillingState g_billing;

extern "C" GDEFCORE_Result PaidCallback(GDEFCORE_Callback_Call * call,
    GDEFCORE_Request * request, const GDEFCORE_Callback_Question * q,
    GDEFCORE_Callback_Answer * a, void * user) {
  BillingState * b = static_cast<BillingState *>(user);
  std::string who = q->principal == NULL
                        ? std::string()
                        : std::string(q->principal, q->principal_len);
  b->calls += 1;
  b->question_size = q->size;
  if (b->set_answer_size) {
    a->size = b->answer_size;
  }
  b->last_count = q->count;
  b->asked += q->count;
  for (size_t i = 0; i < q->count; i++) {
    /* Every failure below writes a grant first: failing closed means the
     * host throws the answer away, not that the callback wrote none. */
    a->granted[i] = b->paid.count(std::make_pair(who, std::string(q->entities[i]))) ? 1 : 0;
    if (b->mode != kAnswer && b->mode != kReenter) {
      a->granted[i] = 1;
    }
  }
  if (b->mode != kNoToken) {
    snprintf(a->token, sizeof a->token, "%s", b->token.c_str());
    a->token_len = b->token.size();
  }
  switch (b->mode) {
  case kTrap:
    return GDEFCORE_ERR_INTERNAL;
  case kOutOfFuel:
    for (int i = 0; i < 200; i++) {
      (void)gdefcore_callback_spend(call, 1);
    }
    return GDEFCORE_OK;
  case kSlow:
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    return GDEFCORE_OK;
  case kMalformed:
    a->granted[0] = 7;
    return GDEFCORE_OK;
  case kReenter: {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    int locked = 0;
    GDEFCORE_Result rc = gdefcore_access_read(b->catalog, request,
        q->entities[0], strlen(q->entities[0]), "en", 2, "body", 4, &texts,
        &lens, &n, &locked);
    b->nested = rc != GDEFCORE_OK ? "<denied>"
                                  : (n == 0 ? "<absent>" : std::string(texts[0], lens[0]));
    gdefcore_values_free(b->catalog, texts, lens, n);
    return GDEFCORE_OK;
  }
  default:
    return GDEFCORE_OK;
  }
}

/* An operation callback: grants `Edit article` on the entities in `paid`. */
extern "C" GDEFCORE_Result EditCallback(GDEFCORE_Callback_Call * call,
    GDEFCORE_Request * request, const GDEFCORE_Callback_Question * q,
    GDEFCORE_Callback_Answer * a, void * user) {
  return PaidCallback(call, request, q, a, user);
}

class Callbacks : public GrantsFixture {
 protected:
  std::string reader_;
  std::string editor_;
  std::string payer_;

  void SetUp() override {
    GrantsFixture::SetUp();
    g_billing = BillingState();
    g_billing.catalog = catalog_;
    GDEFCORE_Field f[3] = {Field("title"), Field("body"), Field("tier")};
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, kArticle, strlen(kArticle),
            GDEFCORE_TYPE_CONTENT, f, 3));
    Declare(Perm(kViewPerm, "read", GDEFCORE_ACCESS_ANY, kArticle));
    Role("reader");
    Grant("reader", kViewPerm);
    reader_ = Principal("reader");
    payer_ = Principal("reader");
  }

  /** The billing module: its body permission and the paid callback. */
  ModDef * BillingMod(int cache = GDEFCORE_CALLBACK_CACHE_TOKEN,
      int flags = GDEFCORE_CALLBACK_LOCKED) {
    ModDef * m = NewMod("billing");
    m->Perm(kBodyPerm, "read", GDEFCORE_ACCESS_ANY, kArticle, "body");
    m->Callback("paid", GDEFCORE_CALLBACK_FIELD, kBodyPerm, kArticle, "body",
        PaidCallback, &g_billing, cache, flags);
    return m;
  }

  static std::string Line(const std::string & label, const char * cb,
      const char * scope) {
    return "Module billing decides " + label + " per entity with its callback " +
           cb + " (" + scope + " scope, high risk): its breadth cannot be "
           "judged.";
  }

  void EnableBilling() {
    ASSERT_EQ(GDEFCORE_OK,
        Enable("billing", {Line(kBodyPerm, "paid", "field")}))
        << last_error_;
  }

  /** An editor: a role grant of the body permission (no callback needed). */
  void MakeEditor() {
    Role("editor");
    Grant("editor", kViewPerm);
    Grant("editor", kBodyPerm);
    editor_ = Principal("editor");
  }

  std::string Article(const std::string & title, const char * body) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[2];
    const char * texts[2] = {title.c_str(), body};
    size_t lens[2] = {title.size(), body == NULL ? 0 : strlen(body)};
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kArticle, strlen(kArticle), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    memset(values, 0, sizeof values);
    values[0].size = sizeof values[0];
    values[0].field = "title";
    values[0].field_len = 5;
    values[0].texts = &texts[0];
    values[0].text_lens = &lens[0];
    values[0].count = 1;
    values[1].size = sizeof values[1];
    values[1].field = "body";
    values[1].field_len = 4;
    values[1].texts = &texts[1];
    values[1].text_lens = &lens[1];
    values[1].count = 1;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, strlen(id), "en", 2, values,
            body == NULL ? 1 : 2));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  /** A field as @p req reads it: "<denied>", "<locked>", "<absent>", or the
   * first value. A locked answer that carries a value says so. */
  std::string Body(GDEFCORE_Request * req, const std::string & id,
      const char * field = "body") {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    int locked = -1;
    GDEFCORE_Result rc = gdefcore_access_read(catalog_, req, id.data(),
        id.size(), "en", 2, field, strlen(field), &texts, &lens, &count,
        &locked);
    std::string out;
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    if (locked == 1) {
      out = count == 0 ? "<locked>" : "<locked:" + std::string(texts[0], lens[0]) + ">";
    } else if (count == 0) {
      out = "<absent>";
    } else {
      out.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return out;
  }

  GDEFCORE_Access_List Query(uint64_t limit = 0) {
    GDEFCORE_Access_List q;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = kArticle;
    q.type_name_len = strlen(kArticle);
    q.lang = "en";
    q.lang_len = 2;
    q.sort_field = "title";
    q.sort_field_len = 5;
    q.limit = limit;
    return q;
  }

  GDEFCORE_Result ListRc(GDEFCORE_Request * req, const GDEFCORE_Access_List & q,
      std::vector<std::string> * out = NULL, uint64_t * total = NULL) {
    char ** ids = NULL;
    size_t n = 0;
    uint64_t t = 0;
    GDEFCORE_Result rc = gdefcore_access_list_page(catalog_, req, &q, &ids, &n,
        &t);
    for (size_t i = 0; rc == GDEFCORE_OK && out != NULL && i < n; i++) {
      out->push_back(ids[i]);
    }
    if (total != NULL) {
      *total = t;
    }
    gdefcore_access_free(catalog_, ids, n);
    return rc;
  }

  std::string Key(GDEFCORE_Request * req) {
    char * key = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(catalog_, req, NULL, 0, NULL, 0, &key, &n));
    std::string out(key == NULL ? "" : key, n);
    gdefcore_text_free(catalog_, key);
    return out;
  }

  std::string Note(GDEFCORE_Request * req) {
    size_t n = 0;
    const char * v = gdefcore_request_note(req, "defiant.callback.failed", 23, &n);
    return v == NULL ? std::string() : std::string(v, n);
  }
};

/* AD-34: a struct with a size member is accepted at exactly its own size. The
 * three here are a callback's: what the host asks, what the callback answers
 * (an answer in a block of another size is malformed and grants nothing), and
 * what the host enumerates of the callbacks a module registers
 * (size_structs.h lists every struct). */
TEST_F(Callbacks, TheStructsHereAreAcceptedAtOnlyTheirOwnSize) {
  Install(BillingMod());
  EnableBilling();
  std::string a = Article("Tides", "the secret of the tides");
  g_billing.paid.insert(std::make_pair(payer_, a));
  size_t tenant_len = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog_, &tenant_len);
  const std::map<std::string, size_structs::Probe> probes = {
      /* The host fills it: whether it filled the size asked about. */
      GDEFCORE_SIZE_PROBE(GDEFCORE_Callback_Question, {
        g_billing.question_size = 0;
        int before = g_billing.calls;
        (void)Body(Req(reader_), a);
        EXPECT_GT(g_billing.calls, before) << "the callback was not asked";
        return g_billing.question_size == size;
      }),
      GDEFCORE_SIZE_PROBE(GDEFCORE_Callback_Answer, {
        g_billing.set_answer_size = true;
        g_billing.answer_size = size;
        std::string body = Body(Req(payer_), a);
        g_billing.set_answer_size = false;
        return body == "the secret of the tides";
      }),
      GDEFCORE_SIZE_PROBE(GDEFCORE_Module_Declared_Callback, {
        const GDEFCORE_Module_Declared_Callback ** items = NULL;
        size_t n = 0;
        EXPECT_EQ(GDEFCORE_OK, gdefcore_module_callbacks(host_, tenant,
                                   tenant_len, NULL, &items, &n));
        EXPECT_EQ(1u, n);
        bool filled = n > 0 && items[0]->size == size;
        gdefcore_module_declared_free(host_, items);
        return filled;
      }),
  };
  size_structs::Run("tests/test_callbacks.cpp", probes);
}

/* Paywall: the title for everyone who may read the article, the body for the
 * one who paid, and for the one who did not a locked marker and never the
 * body, in a field read and in a tree read. */
TEST_F(Callbacks, APrincipalWhoHasNotPaidSeesTheTitleAndLockedNeverTheBody) {
  std::string a = Article("Tides", "the secret of the tides");
  std::string empty = Article("Empty", NULL);
  /* Before the module: the body is no one's to grant, so everyone reads it. */
  EXPECT_EQ("the secret of the tides", Body(Req(reader_), a));
  Install(BillingMod());
  EnableBilling();
  g_billing.paid.insert(std::make_pair(payer_, a));
  EXPECT_EQ("Tides", Body(Req(reader_), a, "title"));
  EXPECT_EQ("<locked>", Body(Req(reader_), a));
  EXPECT_EQ("the secret of the tides", Body(Req(payer_), a));
  /* Locked says a value is there: a body with none is plain absent. */
  EXPECT_EQ("<absent>", Body(Req(reader_), empty));
  /* Someone who may not read the article is told nothing at all. */
  EXPECT_EQ("<denied>", Body(Req(), a));
  {
    GDEFCORE_Tree * tree = NULL;
    const char * text = NULL;
    size_t len = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_tree(catalog_, Req(reader_), a.data(), a.size(), "en", 2,
            &tree));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_get(tree, 0, "body", 4, &text, &len));
    EXPECT_EQ(NULL, text);
    EXPECT_EQ(1, gdefcore_tree_locked(tree, 0, "body", 4));
    EXPECT_EQ(0, gdefcore_tree_locked(tree, 0, "title", 5));
    EXPECT_EQ(1u, gdefcore_tree_locked_count(tree));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_get(tree, 0, "title", 5, &text, &len));
    EXPECT_EQ("Tides", std::string(text == NULL ? "" : text, len));
    gdefcore_tree_free(tree);
  }
  {
    GDEFCORE_Tree * tree = NULL;
    const char * text = NULL;
    size_t len = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_tree(catalog_, Req(payer_), a.data(), a.size(), "en", 2,
            &tree));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_get(tree, 0, "body", 4, &text, &len));
    EXPECT_EQ("the secret of the tides",
        std::string(text == NULL ? "" : text, len));
    EXPECT_EQ(0u, gdefcore_tree_locked_count(tree));
    gdefcore_tree_free(tree);
  }
}

/* A field that does not opt in to the locked indicator is absent, as AD-11
 * has it: hidden and empty read alike. */
TEST_F(Callbacks, AFieldThatDoesNotOptInReadsAbsentNotLocked) {
  std::string a = Article("Tides", "the secret of the tides");
  Install(BillingMod(GDEFCORE_CALLBACK_CACHE_TOKEN, 0));
  EnableBilling();
  EXPECT_EQ("<absent>", Body(Req(reader_), a));
  g_billing.paid.insert(std::make_pair(reader_, a));
  EXPECT_EQ("the secret of the tides", Body(Req(reader_), a));
}

/* A list of articles counts and pages without calling the callback, planned
 * and evaluated; reading the page afterwards asks it once. */
TEST_F(Callbacks, AListCountsAndPagesWithoutCallingTheCallback) {
  std::vector<std::string> made;
  for (int i = 0; i < 30; i++) {
    char title[16];
    snprintf(title, sizeof title, "a%02d", i);
    made.push_back(Article(title, "body"));
  }
  Install(BillingMod());
  EnableBilling();
  for (int flags = 0; flags < 2; flags++) {
    GDEFCORE_Request * req = Req(reader_);
    GDEFCORE_Access_List q = Query(20);
    std::vector<std::string> ids;
    uint64_t total = 0;
    uint64_t counted = 0;
    q.flags = flags == 0 ? 0 : GDEFCORE_ACCESS_LIST_EVALUATE;
    g_billing.calls = 0;
    ASSERT_EQ(GDEFCORE_OK, ListRc(req, q, &ids, &total));
    EXPECT_EQ(20u, ids.size());
    EXPECT_EQ(30u, total);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(catalog_, req, &q, &counted));
    EXPECT_EQ(30u, counted);
    EXPECT_EQ(0, g_billing.calls) << "a list asked the callback (flags " << flags
                                  << ")";
    /* Control: reading the page does ask it, once. */
    for (const std::string & id : ids) {
      EXPECT_EQ("<locked>", Body(req, id));
    }
    EXPECT_EQ(1, g_billing.calls);
  }
}

/* The governed field is refused in a filter, a sort and a condition, to
 * anyone, including a principal who may read it; the field next to it is
 * not. Disabling the module ends it. */
TEST_F(Callbacks, AGovernedFieldIsRefusedInAFilterSortOrCondition) {
  Article("Tides", "salt");
  Install(BillingMod());
  EnableBilling();
  MakeEditor();
  EXPECT_EQ(1, gdefcore_access_field_governed(catalog_, kArticle,
                   strlen(kArticle), "body", 4));
  EXPECT_EQ(0, gdefcore_access_field_governed(catalog_, kArticle,
                   strlen(kArticle), "title", 5));
  /* The editor reads the body: the refusal below is not about reading. */
  EXPECT_EQ("foam", Body(Req(editor_), Article("Waves", "foam")));
  {
    /* An administrator is refused too. */
    GDEFCORE_Access_List q = Query();
    q.filter_field = "body";
    q.filter_field_len = 4;
    q.filter_text = "salt";
    q.filter_text_len = 4;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, ListRc(Req(Admin()), q));
  }
  for (const std::string & who : {editor_, reader_}) {
    GDEFCORE_Access_List q = Query();
    q.filter_field = "body";
    q.filter_field_len = 4;
    q.filter_text = "salt";
    q.filter_text_len = 4;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, ListRc(Req(who), q)) << "filter";
    q = Query();
    q.sort_field = "body";
    q.sort_field_len = 4;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, ListRc(Req(who), q)) << "sort";
    q = Query();
    q.sort2_field = "body";
    q.sort2_field_len = 4;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, ListRc(Req(who), q)) << "second sort";
    q = Query();
    q.condition = "(= field.body \"salt\")";
    q.condition_len = strlen(q.condition);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, ListRc(Req(who), q)) << "condition";
    /* Control: the title is a field like any other. */
    q = Query();
    q.filter_field = "title";
    q.filter_field_len = 5;
    q.filter_text = "Tides";
    q.filter_text_len = 5;
    std::vector<std::string> ids;
    EXPECT_EQ(GDEFCORE_OK, ListRc(Req(who), q, &ids));
    EXPECT_EQ(1u, ids.size());
  }
  /* A grant's condition is a filter too. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      GrantWhen("reader", kViewPerm, "(= field.body \"salt\")"));
  EXPECT_EQ(GDEFCORE_OK, GrantWhen("reader", kViewPerm, "(= field.title \"x\")"));
  ASSERT_EQ(GDEFCORE_OK, Disable("billing"));
  EXPECT_EQ(0, gdefcore_access_field_governed(catalog_, kArticle,
                   strlen(kArticle), "body", 4));
  {
    GDEFCORE_Access_List q = Query();
    std::vector<std::string> ids;
    q.filter_field = "body";
    q.filter_field_len = 4;
    q.filter_text = "salt";
    q.filter_text_len = 4;
    EXPECT_EQ(GDEFCORE_OK, ListRc(Req(editor_), q, &ids));
    EXPECT_EQ(1u, ids.size());
  }
}

/* A callback that traps, runs out of fuel, times out or answers malformed
 * grants nothing, for every entity of the call, and the failure is reported;
 * so does one asked with no request fuel left. Every one of them wrote a
 * grant before it failed. Another grant still grants. */
TEST_F(Callbacks, ACallbackThatTrapsRunsOutOfFuelOrTimesOutGrantsNothing) {
  std::string a = Article("Tides", "the secret of the tides");
  ModDef * m = BillingMod();
  m->callbacks.back().timeout_ms = 20;
  Install(m);
  EnableBilling();
  MakeEditor();
  g_billing.paid.insert(std::make_pair(payer_, a));
  /* Control: answering, the payer reads it, and nothing is reported. */
  {
    GDEFCORE_Request * req = Req(payer_);
    EXPECT_EQ("the secret of the tides", Body(req, a));
    EXPECT_EQ("", Note(req));
    EXPECT_EQ(1, gdefcore_request_cacheable(req));
  }
  const struct {
    int mode;
    const char * reason;
  } cases[] = {{kTrap, "trapped"}, {kOutOfFuel, "out-of-fuel"},
      {kSlow, "timed-out"}, {kMalformed, "malformed"}, {kNoToken, "malformed"}};
  for (const auto & c : cases) {
    GDEFCORE_Request * req = Req(reader_);
    g_billing.mode = c.mode;
    EXPECT_EQ("<locked>", Body(req, a)) << c.reason;
    EXPECT_EQ(std::string("billing.paid ") + c.reason, Note(req));
    EXPECT_EQ(0, gdefcore_request_cacheable(req)) << c.reason;
    EXPECT_NE(std::string::npos, Key(req).find("\ncache:none")) << c.reason;
    /* Remembered for the request: not asked again. */
    int calls = g_billing.calls;
    EXPECT_EQ("<locked>", Body(req, a));
    EXPECT_EQ(calls, g_billing.calls);
    /* Another grant still grants: a failed callback grants nothing, it does
     * not deny. */
    EXPECT_EQ("the secret of the tides", Body(Req(editor_), a)) << c.reason;
  }
  g_billing.mode = kAnswer;
  {
    GDEFCORE_Request * req = Req(payer_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_fuel(req, 3));
    EXPECT_EQ("<locked>", Body(req, a));
    EXPECT_EQ("billing.paid request-fuel", Note(req));
  }
  {
    /* Asked again from inside itself: the inner question grants nothing. */
    GDEFCORE_Request * req = Req(payer_);
    g_billing.mode = kReenter;
    EXPECT_EQ("the secret of the tides", Body(req, a));
    EXPECT_EQ("<absent>", g_billing.nested);
    EXPECT_EQ("billing.paid reentered", Note(req));
  }
}

/* A page of twenty is one call, asked about all twenty; a second read in the
 * request, of a field or a tree, asks nothing; a new request asks again, and
 * so does a changed entity. */
TEST_F(Callbacks, APageOfTwentyIsOneCallAndASecondReadIsMemoized) {
  for (int i = 0; i < 25; i++) {
    char title[16];
    snprintf(title, sizeof title, "a%02d", i);
    Article(title, "body");
  }
  Install(BillingMod());
  EnableBilling();
  GDEFCORE_Request * req = Req(reader_);
  std::vector<std::string> ids;
  ASSERT_EQ(GDEFCORE_OK, ListRc(req, Query(20), &ids));
  ASSERT_EQ(20u, ids.size());
  g_billing.calls = 0;
  for (int pass = 0; pass < 2; pass++) {
    for (const std::string & id : ids) {
      EXPECT_EQ("<locked>", Body(req, id));
      GDEFCORE_Tree * tree = NULL;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_tree(catalog_, req, id.data(),
                                 id.size(), "en", 2, &tree));
      EXPECT_EQ(1, gdefcore_tree_locked(tree, 0, "body", 4));
      gdefcore_tree_free(tree);
    }
  }
  EXPECT_EQ(1, g_billing.calls);
  EXPECT_EQ(20u, g_billing.last_count);
  /* With no list, one entity is one question. */
  GDEFCORE_Request * other = Req(reader_);
  g_billing.calls = 0;
  EXPECT_EQ("<locked>", Body(other, ids[0]));
  EXPECT_EQ("<locked>", Body(other, ids[1]));
  EXPECT_EQ(2, g_billing.calls);
  EXPECT_EQ(1u, g_billing.last_count);
  /* A changed entity is a new question. */
  g_billing.paid.insert(std::make_pair(reader_, ids[0]));
  EXPECT_EQ("<locked>", Body(other, ids[0]));
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v[2];
    const char * text[2] = {"new", "body"};
    size_t len[2] = {3, 4};
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    memset(v, 0, sizeof v);
    for (int k = 0; k < 2; k++) {
      v[k].size = sizeof v[k];
      v[k].field = k == 0 ? "title" : "body";
      v[k].field_len = k == 0 ? 5 : 4;
      v[k].texts = &text[k];
      v[k].text_lens = &len[k];
      v[k].count = 1;
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, ids[0].data(), ids[0].size(), "en", 2, v, 2));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ("body", Body(other, ids[0]));
}

/* A render that consulted a callback carries its validity token in the key:
 * a changed token is a different key, the same token the same key. A time to
 * live moves the key with the request's time, and a callback with no
 * cacheability makes the render uncacheable. */
TEST_F(Callbacks, ARenderThatConsultedACallbackCarriesItsValidityToken) {
  std::string a = Article("Tides", "salt");
  Install(BillingMod());
  EnableBilling();
  g_billing.paid.insert(std::make_pair(reader_, a));
  auto key_after_read = [&](const std::string & token) {
    GDEFCORE_Request * req = Req(reader_);
    g_billing.token = token;
    EXPECT_EQ("salt", Body(req, a));
    EXPECT_EQ(1, gdefcore_request_cacheable(req));
    return Key(req);
  };
  std::string k1 = key_after_read("v1");
  std::string k2 = key_after_read("v2");
  std::string k3 = key_after_read("v1");
  EXPECT_NE(std::string::npos, k1.find("\ncallbacks:"));
  EXPECT_NE(k1, k2);
  EXPECT_EQ(k1, k3);
  /* Control: a request that consulted no callback has no such line. */
  {
    GDEFCORE_Request * req = Req(reader_);
    EXPECT_EQ("Tides", Body(req, a, "title"));
    EXPECT_EQ(std::string::npos, Key(req).find("\ncallbacks:"));
  }
  /* The fragment cache keeps what may be kept, and refuses the rest. */
  GDEFCORE_FragmentCache * cache = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_cache_create(NULL, 8, &cache));
  {
    GDEFCORE_Request * req = Req(reader_);
    EXPECT_EQ("salt", Body(req, a));
    std::string k = Key(req);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_fragment_put(cache, req, k.data(), k.size(), "x", 1));
  }
  gdefcore_fragment_cache_destroy(cache);
}

TEST_F(Callbacks, ATimeToLiveMovesTheKeyAndNoCacheabilityIsUncacheable) {
  std::string a = Article("Tides", "salt");
  ModDef * m = NewMod("billing");
  m->Perm(kBodyPerm, "read", GDEFCORE_ACCESS_ANY, kArticle, "body");
  m->Callback("paid", GDEFCORE_CALLBACK_FIELD, kBodyPerm, kArticle, "body",
      PaidCallback, &g_billing, GDEFCORE_CALLBACK_CACHE_TTL);
  m->Callback("audit", GDEFCORE_CALLBACK_FIELD, kBodyPerm, kArticle, "body",
      PaidCallback, &g_billing, GDEFCORE_CALLBACK_CACHE_NONE);
  Install(m);
  ASSERT_EQ(GDEFCORE_OK,
      Enable("billing", {Line(kBodyPerm, "paid", "field"),
                            Line(kBodyPerm, "audit", "field")}))
      << last_error_;
  auto key_at = [&](int64_t t, int * cacheable) {
    GDEFCORE_Request * req = Req(reader_);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_time(req, t));
    EXPECT_EQ("<absent>", Body(req, a));
    *cacheable = gdefcore_request_cacheable(req);
    return Key(req);
  };
  int c0 = 0;
  int c1 = 0;
  int c2 = 0;
  /* Nobody paid: both callbacks are asked, `audit` (no cacheability) too. */
  std::string k0 = key_at(1200, &c0);
  std::string k1 = key_at(1230, &c1);
  std::string k2 = key_at(1260, &c2);
  EXPECT_EQ(0, c0);
  EXPECT_NE(std::string::npos, k0.find("\ncache:none"));
  EXPECT_EQ(k0, k1);
  EXPECT_NE(k1, k2);
  GDEFCORE_FragmentCache * cache = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_cache_create(NULL, 8, &cache));
  {
    GDEFCORE_Request * req = Req(reader_);
    EXPECT_EQ("<absent>", Body(req, a));
    std::string k = Key(req);
    EXPECT_EQ(GDEFCORE_ERR_LIMIT,
        gdefcore_fragment_put(cache, req, k.data(), k.size(), "x", 1));
    EXPECT_EQ(0u, gdefcore_fragment_count(cache));
  }
  gdefcore_fragment_cache_destroy(cache);
}

/* Registering a row-scope callback is refused, at install, in words; so is an
 * operation callback on a row action at enable. The operation and field
 * shapes beside them are accepted. */
TEST_F(Callbacks, RowScopeIsRefusedAtRegistration) {
  ModDef * row = NewMod("rowmod");
  row->Perm(kBodyPerm, "read", GDEFCORE_ACCESS_ANY, kArticle);
  row->Callback("rows", GDEFCORE_CALLBACK_ROW, kBodyPerm, kArticle, "",
      PaidCallback, &g_billing);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Install(row));
  {
    const char * err = gdefcore_module_error(host_, NULL);
    EXPECT_NE(std::string::npos, std::string(err == NULL ? "" : err).find("row scope"))
        << (err == NULL ? "" : err);
  }
  ModDef * reads = NewMod("readmod");
  reads->Perm("Read by callback", "read", GDEFCORE_ACCESS_ANY, kArticle);
  reads->Callback("reads", GDEFCORE_CALLBACK_OPERATION, "Read by callback",
      kArticle, "", PaidCallback, &g_billing);
  ASSERT_EQ(GDEFCORE_OK, Install(reads));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Enable("readmod", {}));
  EXPECT_NE(std::string::npos, last_error_.find("row scope")) << last_error_;
  ModDef * exports = NewMod("exportmod");
  exports->Perm("Export by callback", "news.export", GDEFCORE_ACCESS_ANY,
      kArticle);
  exports->Callback("exports", GDEFCORE_CALLBACK_OPERATION,
      "Export by callback", kArticle, "", PaidCallback, &g_billing);
  ASSERT_EQ(GDEFCORE_OK, Install(exports));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Enable("exportmod", {}));
  /* A field scope that names no field, and an operation that names one. */
  ModDef * shapeless = NewMod("shapeless");
  shapeless->Perm(kBodyPerm, "read", GDEFCORE_ACCESS_ANY, kArticle, "body");
  shapeless->Callback("nofield", GDEFCORE_CALLBACK_FIELD, kBodyPerm, kArticle,
      "", PaidCallback, &g_billing);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Install(shapeless));
  /* Control: the operation and the field shapes are accepted. */
  ModDef * ok = NewMod("billing");
  ok->Perm(kBodyPerm, "read", GDEFCORE_ACCESS_ANY, kArticle, "body");
  ok->Perm(kEditPerm, "update", GDEFCORE_ACCESS_ANY, kArticle);
  ok->Callback("paid", GDEFCORE_CALLBACK_FIELD, kBodyPerm, kArticle, "body",
      PaidCallback, &g_billing);
  ok->Callback("edit", GDEFCORE_CALLBACK_OPERATION, kEditPerm, kArticle, "",
      EditCallback, &g_billing);
  ASSERT_EQ(GDEFCORE_OK, Install(ok));
  EXPECT_EQ(GDEFCORE_OK,
      Enable("billing", {Line(kBodyPerm, "paid", "field"),
                            Line(kEditPerm, "edit", "operation")}))
      << last_error_;
}

/* The callback appears in the matrix, granted by its module, evaluated per
 * entity and rated high; the enable shows it, high, and is refused when the
 * confirmation leaves it out. */
TEST_F(Callbacks, TheMatrixShowsTheCallbackAndTheEnableRatesItHigh) {
  Install(BillingMod());
  EXPECT_NE(GDEFCORE_OK, EnableWith("billing", Confirmation("billing", {kBodyPerm})));
  EnableBilling();
  GDEFCORE_Access_Matrix_Row * rows = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_matrix(catalog_, Req(Admin()), &rows, &n));
  int found = 0;
  for (size_t i = 0; i < n; i++) {
    if (!rows[i].callback) {
      continue;
    }
    found += 1;
    EXPECT_EQ("module billing", std::string(rows[i].source, rows[i].source_len));
    EXPECT_EQ(kBodyPerm, std::string(rows[i].permission, rows[i].permission_len));
    EXPECT_EQ("body", std::string(rows[i].field, rows[i].field_len));
    EXPECT_EQ("callback billing.paid",
        std::string(rows[i].condition, rows[i].condition_len));
    EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, rows[i].risk);
    EXPECT_EQ(1, rows[i].from_module);
    EXPECT_NE(std::string::npos,
        std::string(rows[i].explain, rows[i].explain_len).find("evaluated per entity"));
  }
  gdefcore_access_matrix_free(catalog_, rows, n);
  EXPECT_EQ(1, found);
  ASSERT_EQ(GDEFCORE_OK, Disable("billing"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_matrix(catalog_, Req(Admin()), &rows, &n));
  for (size_t i = 0; i < n; i++) {
    EXPECT_EQ(0, rows[i].callback);
  }
  gdefcore_access_matrix_free(catalog_, rows, n);
}

/* An operation callback decides can() on one entity, batched and remembered
 * as a field's is; at type level there is no entity to ask, and it grants
 * nothing. */
TEST_F(Callbacks, AnOperationCallbackDecidesCanOnOneEntity) {
  std::string a = Article("Tides", "salt");
  std::string b = Article("Waves", "foam");
  ModDef * m = NewMod("billing");
  m->Perm(kEditPerm, "update", GDEFCORE_ACCESS_ANY, kArticle);
  m->Callback("edit", GDEFCORE_CALLBACK_OPERATION, kEditPerm, kArticle, "",
      EditCallback, &g_billing);
  Install(m);
  ASSERT_EQ(GDEFCORE_OK, Enable("billing", {Line(kEditPerm, "edit", "operation")}))
      << last_error_;
  g_billing.paid.insert(std::make_pair(reader_, a));
  int allowed = -1;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, Req(reader_), "update", 6,
                             kArticle, strlen(kArticle), a.c_str(), &allowed));
  EXPECT_EQ(1, allowed);
  EXPECT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, Req(reader_), "update", 6,
                             kArticle, strlen(kArticle), b.c_str(), &allowed));
  EXPECT_EQ(0, allowed);
  g_billing.calls = 0;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, Req(reader_), "update", 6,
                             kArticle, strlen(kArticle), NULL, &allowed));
  EXPECT_EQ(0, allowed);
  EXPECT_EQ(0, g_billing.calls);
  EXPECT_EQ(0, Permits(reader_, "update"));
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
