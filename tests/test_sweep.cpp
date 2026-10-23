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
 * The conditional access sweep (AD-25, access-conditions story A7, CAP-A6):
 * every value derived from a gated one is gated the same way.
 *
 * A canary is a value only an authorized reader may see: the body of a post,
 * or a whole post, behind a role's grant, a callback, a module's grant, a
 * condition on the post, the published flag or the time. Three principals
 * stand beside it. A meets the condition and is the one it will be taken
 * from; B meets it by another way and keeps it; U never meets it. For every
 * output the library derives from it (a read, a tree, a revision view, a
 * list, a count, an editor's form, the recent-posts page, an entity rendered
 * through a template, a fragment in the cache, a subject's export, a snapshot,
 * and the rows the store keeps) the answer U gets holds no trace of the
 * canary, and the answer A and B get does: a sweep that cannot see the canary
 * returns clean for the wrong reason. Then the condition changes (a grant
 * revoked, the published flag cleared, a callback's answer changed, a module
 * disabled, time passing) and A's answer holds no trace of it either, while
 * B's still does; anything cached or stored before the change must not carry
 * it across.
 *
 * Outputs that core does not have (search, an aggregate, a feed, an export of
 * entities) are listed as absent, and Sweep.EveryDerivedOutputIsListed fails,
 * naming it, when a public header declares one that the sweep does not list.
 *
 * tools/check-sweep.sh plants a defect in the source for each output that
 * makes it carry the canary, and requires the named test here to fail.
 */

#include "grants_fixture.h"
#include "gate_surface.h"

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/defiant-storage/keystore.h>
#include <ghoti.io/defiant-storage/model.h>

#include <dirent.h>

#include <fstream>
#include <sstream>

using namespace gfx;

namespace {

const char kMember[] = "sweep.member";
const char kCT[] = "Canary-Title-91c2";
const char kCB[] = "CANARY-BODY-7f3a";
const char kOpenTitle[] = "Open-Title-55d0";
const char kOpenBody[] = "open body text";
const char kEmail[] = "canary-mail-7f3a@example.test";
const char kOtherEmail[] = "other-mail-12ab@example.test";

const char kReadPosts[] = "Read posts";
const char kReadBody[] = "Read post body";
const char kHistory[] = "Post history";
const char kEditPosts[] = "Edit posts";

/* ---- a callback that answers from a table ------------------------------- */

struct Cb {
  std::set<std::pair<std::string, std::string> > allow; /* (principal, id) */
  std::string token = "v1";
  int calls = 0;
};

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
    a->granted[i] = cb->allow.count(std::make_pair(who, std::string(q->entities[i])))
                        ? 1
                        : 0;
  }
  snprintf(a->token, sizeof a->token, "%s", cb->token.c_str());
  a->token_len = cb->token.size();
  return GDEFCORE_OK;
}

/* ---- the operator routes ------------------------------------------------ */

/* What the last operator route produced. The routes are the paths that hand an
 * RA output (core's export and snapshot take no principal) to a principal:
 * protection is on the path (access SPEC decision 7). */
struct Ops {
  GDEFCORE_Subjects * subjects = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFSTOR_Store * store = NULL;
  std::string out;
};
Ops g_ops;

void ExportRoute(const GDEFCORE_Route_Call * call) {
  const char * value = NULL;
  size_t n = 0;
  char * json = NULL;
  size_t json_len = 0;
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  if (!gdefcore_route_call_capture(call, "id", 2, &value, &n) ||
      gdefcore_entity_subject(g_ops.catalog, value, n, sid) != GDEFCORE_OK) {
    return;
  }
  /* A member is its own subject: the export is of the person it names. */
  if (gdefcore_subject_export(g_ops.subjects, g_ops.catalog, sid, strlen(sid),
          &json, &json_len) == GDEFCORE_OK) {
    g_ops.out.assign(json, json_len);
    gdefcore_subject_free(g_ops.subjects, json);
    gdefcore_request_set_resolution(call->request, value, n);
  }
}

/* A zip as stored, then every member's name and body, so a compressed member
 * cannot hide a needle. */
std::string Unpacked(const uint8_t * zip, size_t n) {
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  std::string view(reinterpret_cast<const char *>(zip), n);
  if (garc_stream_create_memory(zip, n, &stream) != GARC_OK) {
    ADD_FAILURE() << "not a zip";
    return view;
  }
  if (garc_open(stream, NULL, &archive) != GARC_OK) {
    garc_stream_destroy(stream);
    ADD_FAILURE() << "not a zip";
    return view;
  }
  for (;;) {
    const GARC_Member * member = NULL;
    if (garc_next(archive, &member) != GARC_OK) {
      break;
    }
    std::string body(static_cast<size_t>(member->size), '\0');
    size_t total = 0;
    while (total < body.size()) {
      size_t got = 0;
      if (garc_read_member(archive, &body[total], body.size() - total, &got) !=
              GARC_OK ||
          got == 0) {
        ADD_FAILURE() << "short member";
        break;
      }
      total += got;
    }
    view += "\n" + std::string(member->name, member->name_length) + "\n" + body;
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return view;
}

void SnapshotRoute(const GDEFCORE_Route_Call * call) {
  uint8_t * zip = NULL;
  size_t n = 0;
  if (gdefcore_subject_snapshot(g_ops.subjects, g_ops.store, NULL, 0, &zip,
          &n) == GDEFCORE_OK) {
    g_ops.out = Unpacked(zip, n);
    gdefstor_bytes_free(NULL, zip);
    gdefcore_request_set_resolution(call->request, "snapshot", 8);
  }
}

bool Has(const std::string & text, const std::string & needle) {
  return text.find(needle) != std::string::npos;
}

/* ---- the gates, and what each says of the outputs --------------------------- */

enum Gate {
  kRoleField = 0,      /* the body, behind a role's field grant; revoked */
  kCallbackAnswer,     /* the body, behind a callback; its answer changes */
  kCallbackModule,     /* the body, behind a callback; its module is disabled */
  kModuleGrant,        /* the body, behind a module's grant; module disabled */
  kRoleRow,            /* the whole post, behind a role's conditional grant */
  kFlag,               /* the whole post, until it is unpublished */
  kTime,               /* the whole post, until a grant's condition expires */
  kGateCount
};

const char * GateName(int g) {
  static const char * const names[] = {"role-field", "callback-answer",
      "callback-module", "module-grant", "role-row", "flag", "time"};
  return names[g];
}

bool BodyGate(int g) {
  return g == kRoleField || g == kCallbackAnswer || g == kCallbackModule ||
         g == kModuleGrant;
}

/* Every output the sweep reads, by name. */
const char * const kOutputs[] = {"read", "tree", "revision", "list", "count",
    "form", "recent", "render", "cache"};

class Sweep : public GrantsFixture {
 protected:
  GDEFSTOR_KeyStore * keys_ = NULL;
  GDEFCORE_Keyring * ring_ = NULL;
  GDEFCORE_Subjects * subjects_ = NULL;
  GDEFCORE_FragmentCache * cache_ = NULL;
  GDEFCORE_Routes * routes_ = NULL;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  int64_t now_ = 1000;
  Cb paid_;
  std::string a_, b_, u_;      /* the principals */
  std::string canary_, open_;  /* the posts */
  int gate_ = kRoleField;

  void SetUp() override {
    memset(root_, 0x42, sizeof root_);
    Build();
  }

  void TearDown() override {
    Destroy();
    GrantsFixture::TearDown();
  }

  /* ---- the world --------------------------------------------------------- */

  void Build() {
    static GDEFSTOR_KeyCipher cipher;
    uint8_t * bytes = NULL;
    size_t n = 0;
    GrantsFixture::SetUp(); /* Defs cleared, the store, the catalog, the host */
    gdefcore_subject_cipher(&cipher);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_keystore_create(NULL, &cipher, &keys_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_create(root_, sizeof root_, NULL, &ring_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_open(keys_, store_,
        (const uint8_t *)kTenant, 1, root_, sizeof root_, ring_, NULL,
        &subjects_));
    gdefcore_catalog_bind_subjects(catalog_, subjects_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_cache_create(NULL, 0, &cache_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_bind_cache(subjects_, cache_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes_));
    g_ops.subjects = subjects_;
    g_ops.catalog = catalog_;
    g_ops.store = store_;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    /* The kit lets the anonymous state read posts: not here. */
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_revoke(catalog_, "anonymous", 9,
                               kReadPosts, strlen(kReadPosts)));
    DefineTypes();
    DefineTemplates();
    DeclarePermissions();
  }

  void Destroy() {
    gdefcore_routes_destroy(routes_);
    routes_ = NULL;
    gdefcore_subject_bind_cache(subjects_, NULL);
    gdefcore_fragment_cache_destroy(cache_);
    cache_ = NULL;
    gdefcore_catalog_bind_subjects(catalog_, NULL);
    gdefcore_subject_destroy(subjects_);
    subjects_ = NULL;
    gdefstor_keystore_destroy(keys_);
    keys_ = NULL;
    gdefcore_keyring_destroy(ring_);
    ring_ = NULL;
    g_ops = Ops();
  }

  /* Another world, from nothing. */
  void Rebuild() {
    Destroy();
    GrantsFixture::TearDown();
    paid_ = Cb();
    now_ = 1000;
    Build();
  }

  static GDEFCORE_Field Plain(const char * name, int type = 0) {
    GDEFCORE_Field f = Field(name);
    f.type = type;
    return f;
  }

  void DefineTypes() {
    /* The kit's post, with the fields the gates test. */
    GDEFCORE_Field post[5] = {Plain("title"), Plain("body"), Plain("summary"),
        Plain("tier"), Plain("expires", GDEFSTOR_FIELD_INTEGER)};
    post[0].required = 1;
    post[1].required = 1;
    {
      /* A type is defined again by a changeset, which names it. */
      GDEFCORE_Changeset * cs = NULL;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_define(cs, kPost, strlen(kPost),
                                 GDEFCORE_TYPE_CONTENT, post, 5));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kPost, strlen(kPost)));
      gdefcore_changeset_destroy(cs);
    }
    /* A person: the member is its own subject, and its email is personal. */
    GDEFCORE_Field member[2] = {Plain("title"), Field("email", 1)};
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kMember,
                               strlen(kMember),
                               GDEFCORE_TYPE_CONTENT | GDEFCORE_TYPE_SUBJECTS,
                               member, 2));
  }

  GDEFCORE_Result Put(const char * type,
      std::vector<std::pair<std::string, std::string> > values,
      const char * confirm) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> vs(values.size());
    std::vector<const char *> texts(values.size());
    std::vector<size_t> lens(values.size());
    for (size_t i = 0; i < values.size(); i++) {
      texts[i] = values[i].second.c_str();
      lens[i] = values[i].second.size();
      memset(&vs[i], 0, sizeof vs[i]);
      vs[i].size = sizeof vs[i];
      vs[i].field = values[i].first.c_str();
      vs[i].field_len = values[i].first.size();
      vs[i].texts = &texts[i];
      vs[i].text_lens = &lens[i];
      vs[i].count = 1;
    }
    GDEFCORE_Result rc = gdefcore_entity_create(catalog_, type, strlen(type), id,
        NULL);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2,
          vs.data(), vs.size());
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, confirm, strlen(confirm));
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* A template of posts that prints the title and the body: an entity rendered
   * through it is what a fragment in the cache holds. */
  void DefineTemplates() {
    ASSERT_EQ(GDEFCORE_OK,
        Put(GDEFCORE_TEMPLATE_KIND_TYPE,
            {{"name", "sweep.post"}, {"label", "Post"}, {"version", "1"},
                {"variables", "entity entity The post"}},
            GDEFCORE_TEMPLATE_KIND_TYPE));
    ASSERT_EQ(GDEFCORE_OK,
        Put(GDEFCORE_TEMPLATE_TYPE,
            {{"name", "card"},
                {"body", "<% use entity; %>[<%= entity.title %>|<%= entity.body %>]"},
                {"kind", "sweep.post"}},
            GDEFCORE_TEMPLATE_TYPE));
  }

  void DeclarePermissions() {
    Declare(Perm(kHistory, GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACCESS_ANY,
        kPost));
    Declare(Perm(kEditPosts, GDEFCORE_ACTION_UPDATE, GDEFCORE_ACCESS_ANY, kPost));
  }

  /* A post, published, as the system saved it. */
  std::string Post(const std::string & title, const std::string & body,
      const std::string & summary, const std::string & tier, int64_t expires) {
    std::vector<std::pair<std::string, std::string> > v = {{"title", title},
        {"body", body}, {"tier", tier}, {"expires", std::to_string(expires)}};
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> vs;
    std::vector<const char *> texts(5);
    std::vector<size_t> lens(5);
    if (!summary.empty()) {
      v.push_back(std::make_pair(std::string("summary"), summary));
    }
    vs.resize(v.size());
    for (size_t i = 0; i < v.size(); i++) {
      texts[i] = v[i].second.c_str();
      lens[i] = v[i].second.size();
      memset(&vs[i], 0, sizeof vs[i]);
      vs[i].size = sizeof vs[i];
      vs[i].field = v[i].first.c_str();
      vs[i].field_len = v[i].first.size();
      vs[i].texts = &texts[i];
      vs[i].text_lens = &lens[i];
      vs[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPost, strlen(kPost), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN,
                               "en", 2, vs.data(), vs.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  void Unpublish(const std::string & id) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_unpublish(cs, id.data(), id.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }

  std::string Describe(const std::string & who) const {
    return who == a_ ? "A" : (who == b_ ? "B" : (who == u_ ? "U" : "?"));
  }

  /* A module with the body permission, a callback on it, and so on. */
  ModDef * Billing() {
    ModDef * m = NewMod("billing");
    m->Perm(kReadBody, "read", GDEFCORE_ACCESS_ANY, kPost, "body");
    m->Callback("paid", GDEFCORE_CALLBACK_FIELD, kReadBody, kPost, "body",
        Answer, &paid_);
    return m;
  }

  ModDef * Promo(const std::string & a) {
    ModDef * m = NewMod("promo");
    m->Perm("Promo read body", "read", GDEFCORE_ACCESS_ANY, kPost, "body");
    m->Grant("Promo read body", kPost, "(= principal \"" + a + "\")", "body");
    return m;
  }

  /** The permissions and roles of a gate, its principals, its posts. */
  void Arrange(int gate) {
    gate_ = gate;
    if (gate == kRoleField) {
      /* The permission is the site's own; for the callback and the module
       * gates the module declares it (a module grants only what it owns). */
      Declare(Perm(kReadBody, "read", GDEFCORE_ACCESS_ANY, kPost, "body"));
      Role("staff");
      Role("staff2");
      Role("members");
      for (const char * r : {"staff", "staff2"}) {
        Grant(r, kReadPosts);
        Grant(r, kReadBody);
        Grant(r, kHistory);
        Grant(r, kEditPosts);
      }
      Grant("members", kReadPosts);
      Grant("members", kHistory);
      Grant("members", kEditPosts);
      a_ = Principal("staff");
      b_ = Principal("staff2");
      u_ = Principal("members");
    } else if (gate == kCallbackAnswer || gate == kCallbackModule) {
      Role("members");
      Grant("members", kReadPosts);
      Grant("members", kHistory);
      Grant("members", kEditPosts);
      a_ = Principal("members");
      b_ = Principal("members");
      u_ = Principal("members");
      Install(Billing());
      ASSERT_EQ(GDEFCORE_OK,
          Enable("billing", {Line("billing", kReadBody, "paid", "field")}))
          << last_error_;
    } else if (gate == kModuleGrant) {
      Role("members");
      Grant("members", kReadPosts);
      Grant("members", kHistory);
      Grant("members", kEditPosts);
      a_ = Principal("members");
      u_ = Principal("members");
      b_ = std::string();
      Install(Promo(a_));
      ASSERT_EQ(GDEFCORE_OK,
          Enable("promo",
              {GrantLine("promo", "Promo read body",
                  gdefcore_access_risk_name(gdefcore_access_grant_risk_on(
                      "read", 4, "body", 4, ("(= principal \"" + a_ + "\")").data(),
                      ("(= principal \"" + a_ + "\")").size(), 0)),
                  "(= principal \"" + a_ + "\")")}))
          << last_error_;
    } else if (gate == kRoleRow || gate == kFlag) {
      Role("staff");
      Role("staff2");
      Role("members");
      for (const char * r : {"staff", "staff2"}) {
        Grant(r, kReadPosts);
        Grant(r, kHistory);
      }
      ASSERT_EQ(GDEFCORE_OK, GrantWhen("members", kReadPosts,
                                 "(= field.tier \"open\")"));
      a_ = Principal("staff");
      b_ = gate == kFlag ? std::string() : Principal("staff2");
      u_ = Principal("members");
    } else {
      Role("staff");
      Role("timed");
      Role("members");
      Grant("staff", kReadPosts);
      Grant("staff", kHistory);
      Grant("timed", kHistory);
      ASSERT_EQ(GDEFCORE_OK, GrantWhen("timed", kReadPosts,
                                 "(< now field.expires)"));
      ASSERT_EQ(GDEFCORE_OK, GrantWhen("members", kReadPosts,
                                 "(= field.tier \"open\")"));
      a_ = Principal("timed");
      b_ = Principal("staff");
      u_ = Principal("members");
    }
    /* The open post anyone may read, and the canary. The recent-posts view
     * derives its summary from a body, so the canary has no summary field. */
    open_ = Post(kOpenTitle, kOpenBody, "An open post", "open", 100000);
    canary_ = Post(kCT, kCB, BodyGate(gate) ? "" : "A closed post", "closed",
        2000);
    if (gate == kCallbackAnswer || gate == kCallbackModule) {
      for (const std::string & who : {a_, b_}) {
        paid_.allow.insert(std::make_pair(who, canary_));
        paid_.allow.insert(std::make_pair(who, open_));
      }
    }
  }

  static std::string Line(const std::string & module, const std::string & label,
      const std::string & cb, const char * scope) {
    return "Module " + module + " decides " + label + " per entity with its "
           "callback " + cb + " (" + scope + " scope, high risk): its breadth "
           "cannot be judged.";
  }

  /** The change of condition the gate stands for. */
  void Change() {
    if (gate_ == kRoleField) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_revoke(catalog_, "staff", 5,
                                 kReadBody, strlen(kReadBody)));
    } else if (gate_ == kCallbackAnswer) {
      paid_.allow.erase(std::make_pair(a_, canary_));
      paid_.allow.erase(std::make_pair(a_, open_));
      paid_.token = "v2"; /* the callback says its answers changed */
    } else if (gate_ == kCallbackModule) {
      ASSERT_EQ(GDEFCORE_OK, Disable("billing"));
    } else if (gate_ == kModuleGrant) {
      ASSERT_EQ(GDEFCORE_OK, Disable("promo"));
    } else if (gate_ == kRoleRow) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_revoke(catalog_, "staff", 5,
                                 kReadPosts, strlen(kReadPosts)));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_revoke(catalog_, "staff", 5,
                                 kHistory, strlen(kHistory)));
    } else if (gate_ == kFlag) {
      Unpublish(canary_);
    } else {
      now_ = 2500; /* the canary's grant expired at 2000 */
    }
  }

  /* ---- what a principal gets from each output ---------------------------- */

  GDEFCORE_Request * Q(const std::string & who) {
    GDEFCORE_Request * r = Req(who);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_time(r, now_));
    return r;
  }

  static std::string Texts(GDEFCORE_Result rc, char ** texts, size_t * lens,
      size_t count) {
    std::string out;
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    if (count == 0) {
      return "<absent>";
    }
    for (size_t i = 0; i < count; i++) {
      out += "[" + std::string(texts[i], lens[i]) + "]";
    }
    return out;
  }

  std::string ReadOf(GDEFCORE_Request * req, const std::string & id,
      const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    GDEFCORE_Result rc = gdefcore_access_read(catalog_, req, id.data(), id.size(),
        "en", 2, field, strlen(field), &texts, &lens, &count, NULL);
    std::string out = Texts(rc, texts, lens, count);
    if (rc == GDEFCORE_OK) {
      gdefcore_values_free(catalog_, texts, lens, count);
    }
    return out;
  }

  std::string Read(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    std::string out;
    for (const char * f : {"title", "body", "summary"}) {
      out += std::string(f) + "=" + ReadOf(req, canary_, f) + ";";
    }
    return out;
  }

  std::string Tree(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    GDEFCORE_Tree * tree = NULL;
    std::string out;
    if (gdefcore_access_tree(catalog_, req, canary_.data(), canary_.size(), "en",
            2, &tree) != GDEFCORE_OK) {
      return "<denied>";
    }
    for (size_t i = 0; i < gdefcore_tree_item_count(tree); i++) {
      GDEFCORE_TreeItem it;
      memset(&it, 0, sizeof it);
      it.size = sizeof it;
      if (gdefcore_tree_item(tree, i, &it) != GDEFCORE_OK) {
        break;
      }
      for (size_t k = 0; k < it.value_count; k++) {
        const char * f = NULL;
        size_t fn = 0;
        const char * t = NULL;
        size_t tn = 0;
        if (gdefcore_tree_value(tree, i, k, &f, &fn, &t, &tn) == GDEFCORE_OK) {
          out += std::string(f, fn) + "=[" + std::string(t, tn) + "];";
        }
      }
    }
    gdefcore_tree_free(tree);
    return out;
  }

  std::string Revision(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    std::string out;
    for (const char * f : {"title", "body"}) {
      int status = 0;
      char ** texts = NULL;
      size_t * lens = NULL;
      size_t count = 0;
      GDEFCORE_Result rc = gdefcore_access_revision_values(catalog_, req,
          canary_.data(), canary_.size(), 1, "en", 2, f, strlen(f), &status,
          &texts, &lens, &count);
      out += std::string(f) + "=" + Texts(rc, texts, lens, count) + ";";
      if (rc == GDEFCORE_OK) {
        gdefcore_values_free(catalog_, texts, lens, count);
      }
    }
    return out;
  }

  GDEFCORE_Access_List Query() {
    GDEFCORE_Access_List q;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = kPost;
    q.type_name_len = strlen(kPost);
    q.lang = "en";
    q.lang_len = 2;
    q.sort_field = "title";
    q.sort_field_len = 5;
    return q;
  }

  /* The ids listed, as the canary id or "open", under a filter or none. */
  std::string Listed(GDEFCORE_Request * req, const GDEFCORE_Access_List & q) {
    char ** ids = NULL;
    size_t count = 0;
    GDEFCORE_Result rc = gdefcore_access_list(catalog_, req, &q, &ids, &count);
    std::string out = "rc=" + std::to_string(rc) + ":";
    for (size_t i = 0; rc == GDEFCORE_OK && i < count; i++) {
      out += std::string(i > 0 ? "," : "") + ids[i];
    }
    gdefcore_access_free(catalog_, ids, count);
    return out;
  }

  std::string List(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    std::string out = "all=" + Listed(req, Query()) + ";";
    {
      GDEFCORE_Access_List q = Query();
      q.filter_field = "title";
      q.filter_field_len = 5;
      q.filter_text = kCT;
      q.filter_text_len = strlen(kCT);
      out += "by-title=" + Listed(req, q) + ";";
    }
    {
      /* The body of a post is searched, when the principal may name it. */
      GDEFCORE_Access_List q = Query();
      q.filter_field = "body";
      q.filter_field_len = 4;
      q.filter_text = kCB;
      q.filter_text_len = strlen(kCB);
      out += "by-body=" + Listed(req, q) + ";";
    }
    {
      /* A condition names a field too. */
      GDEFCORE_Access_List q = Query();
      q.condition = "(= field.tier \"closed\")";
      q.condition_len = strlen(q.condition);
      out += "by-tier=" + Listed(req, q) + ";";
    }
    return out;
  }

  std::string Count(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    uint64_t n = 0;
    GDEFCORE_Access_List q = Query();
    std::string out;
    GDEFCORE_Result rc = gdefcore_access_count(catalog_, req, &q, &n);
    out = "count=" + (rc == GDEFCORE_OK ? std::to_string(n) : std::string("<denied>"));
    q.filter_field = "title";
    q.filter_field_len = 5;
    q.filter_text = kCT;
    q.filter_text_len = strlen(kCT);
    rc = gdefcore_access_count(catalog_, req, &q, &n);
    out += ";by-title=" + (rc == GDEFCORE_OK ? std::to_string(n) : std::string("<denied>"));
    /* The page and the count agree. */
    {
      uint64_t total = 0;
      char ** ids = NULL;
      size_t c = 0;
      GDEFCORE_Access_List all = Query();
      rc = gdefcore_access_list_page(catalog_, req, &all, &ids, &c, &total);
      out += ";total=" + (rc == GDEFCORE_OK ? std::to_string(total) : std::string("<denied>"));
      gdefcore_access_free(catalog_, ids, c);
    }
    return out;
  }

  std::string Form(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    GDEFCORE_Form * form = NULL;
    std::string out;
    GDEFCORE_Result rc = gdefcore_form_tree_for(catalog_, req, canary_.data(),
        canary_.size(), "en", 2, &form);
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    for (size_t i = 0; i < gdefcore_form_field_count(form); i++) {
      const char * name = NULL;
      size_t name_len = 0;
      int required = 0;
      int many = 0;
      int personal = 0;
      size_t min_len = 0;
      size_t max_len = 0;
      int has_range = 0;
      int64_t range_min = 0;
      int64_t range_max = 0;
      const char * pattern = NULL;
      size_t pattern_len = 0;
      const char * const * texts = NULL;
      const size_t * lens = NULL;
      size_t count = 0;
      if (gdefcore_form_field(form, i, &name, &name_len, &required, &many,
              &personal, &min_len, &max_len, &has_range, &range_min, &range_max,
              &pattern, &pattern_len, &texts, &lens, &count) != GDEFCORE_OK) {
        break;
      }
      out += std::string(name, name_len) + "=";
      for (size_t k = 0; k < count; k++) {
        out += "[" + std::string(texts[k], lens[k]) + "]";
      }
      out += ";";
    }
    gdefcore_form_destroy(form);
    return out;
  }

  std::string Recent(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_render_page(catalog_, NULL, req, "/", 1,
        GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
    std::string out;
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    out.assign(bytes, n);
    gdefcore_text_free(catalog_, bytes);
    return out;
  }

  /* The post rendered through a template; with @p key, the render key of the
   * request that rendered it. */
  std::string Render(GDEFCORE_Request * req, std::string * key = NULL) {
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_render_entity(catalog_, req, "card", 4,
        canary_.data(), canary_.size(), "en", 2, GDEFCORE_RENDER_PAGE_FUEL,
        &bytes, &n);
    std::string out;
    if (rc != GDEFCORE_OK) {
      out = "<denied>";
    } else {
      out.assign(bytes, n);
      gdefcore_text_free(catalog_, bytes);
    }
    if (key != NULL) {
      char * k = NULL;
      size_t kn = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_access_render_key(catalog_, req, NULL, 0, NULL, 0, &k, &kn));
      key->assign(k == NULL ? "" : k, kn);
      gdefcore_text_free(catalog_, k);
    }
    return out;
  }

  std::string RenderOf(const std::string & who) {
    return Render(Q(who));
  }

  /* What a host that keeps a fragment cache serves: the rendering of the
   * request, found under its render key when one is kept, else made and kept
   * (the key is made after the request has read what it reads). */
  std::string Cached(const std::string & who) {
    GDEFCORE_Request * req = Q(who);
    std::string key;
    std::string fresh = Render(req, &key);
    char * hit = NULL;
    size_t hit_len = 0;
    int found = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_fragment_get(cache_, key.data(), key.size(),
                               &hit, &hit_len, &found));
    if (found) {
      std::string out(hit, hit_len);
      gdefcore_fragment_free(cache_, hit);
      return out;
    }
    (void)gdefcore_fragment_put(cache_, req, key.data(), key.size(), fresh.data(),
        fresh.size());
    return fresh;
  }

  std::string Output(const std::string & name, const std::string & who) {
    if (name == "read") {
      return Read(who);
    }
    if (name == "tree") {
      return Tree(who);
    }
    if (name == "revision") {
      return Revision(who);
    }
    if (name == "list") {
      return List(who);
    }
    if (name == "count") {
      return Count(who);
    }
    if (name == "form") {
      return Form(who);
    }
    if (name == "recent") {
      return Recent(who);
    }
    if (name == "render") {
      return RenderOf(who);
    }
    if (name == "cache") {
      return Cached(who);
    }
    ADD_FAILURE() << "no output " << name;
    return std::string();
  }

  /* ---- what each output must hold and must not -------------------------------- */

  /** What the output of an authorized principal holds, or "" when the output
   * has nothing of the canary to show for this gate. */
  std::string Sees(const std::string & output, int gate) const {
    bool body = BodyGate(gate);
    bool governed = gate == kCallbackAnswer || gate == kCallbackModule;
    if (output == "read" || output == "tree" || output == "revision" ||
        output == "form" || output == "recent" || output == "render" ||
        output == "cache") {
      if (output == "form" && !body) {
        return std::string(); /* an editor's form: update decides, not read */
      }
      /* A body is shown where the body is the canary; a whole post where the
       * post is (its title). */
      return body ? kCB : kCT;
    }
    if (output == "list") {
      if (body) {
        /* The row is seen by all; the body is searched by whoever may name it:
         * not by anyone when a callback decides it (it would probe it). */
        return governed ? std::string() : "by-body=rc=0:" + canary_;
      }
      return "by-title=rc=0:" + canary_;
    }
    if (output == "count") {
      return body ? std::string() : "by-title=1";
    }
    return std::string();
  }

  /** What the output of a principal who is not authorized must not hold. */
  std::vector<std::string> Hidden(const std::string & output, int gate) const {
    std::vector<std::string> out;
    if (BodyGate(gate)) {
      out.push_back(kCB);
      if (output == "list") {
        out.push_back("by-body=rc=0:" + canary_);
      }
      return out;
    }
    out.push_back(kCT);
    out.push_back(kCB);
    if (output == "list") {
      out.push_back(canary_);
    }
    if (output == "count") {
      out.push_back("by-title=1");
    }
    return out;
  }

  /** The total the count and the page report to the authorized: the open post
   * and the canary. */
  bool CountsCanary(const std::string & count_out) const {
    return Has(count_out, "count=2") || Has(count_out, "by-title=1");
  }

  /* ---- the sweep of one output ------------------------------------------------- */

  /** @p who's answer holds none of what is hidden. */
  void ExpectNoTrace(const std::string & output, int gate, const std::string & who,
      const std::string & answer, const char * when) {
    for (const std::string & token : Hidden(output, gate)) {
      EXPECT_FALSE(Has(answer, token))
          << GateName(gate) << ": the " << output << " output carries \"" << token
          << "\" to " << Describe(who) << " " << when << ": " << answer;
    }
  }

  void ExpectSees(const std::string & output, int gate, const std::string & who,
      const std::string & answer, const char * when) {
    std::string want = Sees(output, gate);
    if (want.empty()) {
      return;
    }
    EXPECT_TRUE(Has(answer, want))
        << GateName(gate) << ": the " << output << " output does not show \""
        << want << "\" to " << Describe(who) << " " << when
        << ", so the sweep cannot see the canary there: " << answer;
  }

  void SweepOutput(const std::string & output) {
    for (int gate = 0; gate < kGateCount; gate++) {
      if (gate > 0) {
        Rebuild();
        ASSERT_FALSE(HasFatalFailure());
      }
      Arrange(gate);
      ASSERT_FALSE(HasFatalFailure()) << GateName(gate);
      /* A fragment kept for each of them, before anything changes. */
      if (output == "cache") {
        for (const std::string & who : {a_, b_, u_}) {
          if (!who.empty()) {
            (void)Cached(who);
          }
        }
      }
      /* Before: U sees none of it; A and B see it (the control). */
      std::string u0 = Output(output, u_);
      ExpectNoTrace(output, gate, u_, u0, "before the change");
      std::string a0 = Output(output, a_);
      ExpectSees(output, gate, a_, a0, "before the change");
      if (!b_.empty()) {
        ExpectSees(output, gate, b_, Output(output, b_), "before the change");
      }
      if (output == "count" && !BodyGate(gate)) {
        /* The control: the count tells the two apart where a row is hidden. */
        EXPECT_NE(Output(output, a_), Output(output, u_)) << GateName(gate);
      }
      Change();
      ASSERT_FALSE(HasFatalFailure()) << GateName(gate);
      /* After: A's answer holds none of it either, and U's still does not.
       * The history of a post is a permission of its own (access SPEC decision
       * 9): clearing the published flag, or time passing, takes away what
       * readers may read and leaves what a historian may. */
      if (!(output == "revision" && (gate == kFlag || gate == kTime))) {
        ExpectNoTrace(output, gate, a_, Output(output, a_), "after the change");
      }
      ExpectNoTrace(output, gate, u_, Output(output, u_), "after the change");
      /* B keeps what B is entitled to (the sweep still sees the canary):
       * unless the change took it from everyone, as clearing the flag and
       * disabling the module whose callback decided the body do. */
      if (!b_.empty() && gate != kFlag && gate != kCallbackModule) {
        ExpectSees(output, gate, b_, Output(output, b_), "after the change");
      }
    }
  }
};

TEST_F(Sweep, ReadCarriesNoCanary) { SweepOutput("read"); }
TEST_F(Sweep, TreeCarriesNoCanary) { SweepOutput("tree"); }
TEST_F(Sweep, RevisionCarriesNoCanary) { SweepOutput("revision"); }
TEST_F(Sweep, ListCarriesNoCanary) { SweepOutput("list"); }
TEST_F(Sweep, CountCarriesNoCanary) { SweepOutput("count"); }
TEST_F(Sweep, FormCarriesNoCanary) { SweepOutput("form"); }
TEST_F(Sweep, RecentPostsSummaryCarriesNoCanary) { SweepOutput("recent"); }
TEST_F(Sweep, RenderCarriesNoCanary) { SweepOutput("render"); }
TEST_F(Sweep, FragmentCacheCarriesNoCanary) { SweepOutput("cache"); }


/* ---- the outputs an operator takes, reached by a route --------------------------- */

std::string Hex(const std::string & raw) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : raw) {
    out.push_back(kDigits[c >> 4]);
    out.push_back(kDigits[c & 0x0f]);
  }
  return out;
}

/* Whether @p text holds @p plain as written, in hex, or in the hex of a hex
 * (a stored dump spells its strings in hex, and a sealed value is hex). */
bool Traces(const std::string & text, const std::string & plain) {
  return Has(text, plain) || Has(text, Hex(plain)) || Has(text, Hex(Hex(plain)));
}

/* Core's export of a person and its snapshot take no principal (they are RA in
 * gate_surface.h: protection is on the path, access SPEC decision 7). The
 * paths that hand them to a principal are routes that name a permission, and
 * the canary is swept across those: a person's export is reached only by the
 * person it is about (the permission `own`), a snapshot only by an operator. */
class SweepOps : public Sweep {
 protected:
  std::string s1_, s2_, op_, m1_, m2_;

  /** A person: a member made by @p creator, with its email sealed for it. */
  std::string Member(const std::string & creator, const char * title,
      const char * email) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    const char * texts[1] = {title};
    size_t lens[1] = {strlen(title)};
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kMember, strlen(kMember), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, creator.data(),
                               creator.size(), &cs));
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "title";
    v.field_len = 5;
    v.texts = texts;
    v.text_lens = lens;
    v.count = 1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, &v, 1));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_save(subjects_, catalog_, NULL, 0, id,
                               strlen(id), "email", 5, "en", 2, email,
                               strlen(email)));
    return std::string(id);
  }

  void AddRoute(const char * machine, const char * path, const char * permission,
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
    spec.permission = permission;
    spec.permission_len = strlen(permission);
    if (capture != NULL) {
      spec.entity_capture = capture;
      spec.entity_capture_len = strlen(capture);
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes_, &spec, &err, &err_len))
        << (err == NULL ? "" : err);
    gdefcore_routes_free(routes_, err);
  }

  void ArrangeOps() {
    Declare(Perm("Export own data", "export", GDEFCORE_ACCESS_OWN, kMember));
    Declare(Perm("Take snapshots", "snapshot", GDEFCORE_ACCESS_ANY, kPost));
    Role("selfserve");
    Grant("selfserve", "Export own data");
    Role("operators");
    Grant("operators", "Take snapshots");
    s1_ = Principal("selfserve");
    s2_ = Principal("selfserve");
    op_ = Principal("operators");
    m1_ = Member(s1_, "One", kOtherEmail);
    m2_ = Member(s2_, "Two", kEmail);
    Post(kCT, kCB, "", "closed", 2000);
    AddRoute("export", "/export/:id", "export", "id", ExportRoute);
    AddRoute("snapshot", "/snapshot", "snapshot", NULL, SnapshotRoute);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_routes_set_check(routes_, gdefcore_access_route_check, catalog_));
  }

  /** What the route handed @p who for @p path, or "<none>" when the route is
   * not there for them (and the handler never ran). */
  std::string Via(const std::string & who, const std::string & path) {
    char * out = NULL;
    size_t n = 0;
    g_ops.out.clear();
    GDEFCORE_Result rc = gdefcore_form_resolve(routes_, catalog_, Q(who),
        path.data(), path.size(), &out, &n);
    if (rc == GDEFCORE_OK) {
      gdefcore_text_free(catalog_, out);
      return g_ops.out;
    }
    EXPECT_EQ("", g_ops.out) << "the handler ran for a route that is not there";
    return "<none>";
  }

  std::string Dump(int which) {
    uint8_t * text = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK,
        gdefstor_model_dump(store_, kTenant, 1, which, &text, &n));
    std::string out(reinterpret_cast<const char *>(text), text == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, text);
    return out;
  }
};

TEST_F(SweepOps, SubjectExportCarriesNoCanaryToTheUnauthorized) {
  ArrangeOps();
  ASSERT_FALSE(HasFatalFailure());
  /* Control: a person is given their own export, canary and all. */
  std::string own = Via(s2_, "/export/" + m2_);
  EXPECT_TRUE(Has(own, kEmail)) << own;
  EXPECT_TRUE(Has(own, m2_)) << own;
  /* Another person is not given it, by the other person's id, and is given
   * theirs, which holds none of the first's. */
  EXPECT_EQ("<none>", Via(s1_, "/export/" + m2_));
  std::string mine = Via(s1_, "/export/" + m1_);
  EXPECT_TRUE(Has(mine, kOtherEmail)) << mine;
  EXPECT_FALSE(Has(mine, kEmail)) << mine;
  /* An operator is not the person. */
  EXPECT_EQ("<none>", Via(op_, "/export/" + m2_));
  /* The grant is revoked: the person no longer is given it. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_revoke(catalog_, "selfserve", 9,
                             "Export own data", 15));
  EXPECT_EQ("<none>", Via(s2_, "/export/" + m2_));
  EXPECT_EQ("<none>", Via(s1_, "/export/" + m2_));
  /* And an erased person's export is the marker, not the canary. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "selfserve", 9,
                             "Export own data", 15, "core.role", 9));
  std::string sid;
  {
    char buf[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_subject(catalog_, m2_.data(), m2_.size(), buf));
    sid = buf;
  }
  EXPECT_TRUE(Has(Via(s2_, "/export/" + m2_), kEmail));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_erase(subjects_, sid.data(), sid.size(),
                             sid.data(), sid.size()));
  std::string erased = Via(s2_, "/export/" + m2_);
  EXPECT_FALSE(Has(erased, kEmail)) << erased;
  EXPECT_TRUE(Has(erased, "erased")) << erased;
}

TEST_F(SweepOps, SnapshotCarriesNoCanaryToTheUnauthorized) {
  ArrangeOps();
  ASSERT_FALSE(HasFatalFailure());
  /* Control: an operator is given the backup, which holds the data (the
   * post's body is stored as it is) and holds a person's email only sealed. */
  std::string snap = Via(op_, "/snapshot");
  EXPECT_TRUE(Has(snap, kCB)) << "the sweep cannot see the canary in a snapshot";
  EXPECT_TRUE(Has(snap, "s1:") || Has(snap, Hex("s1:")))
      << "the snapshot holds no personal value at all, sealed or not";
  EXPECT_FALSE(Traces(snap, kEmail));
  EXPECT_FALSE(Traces(snap, kOtherEmail));
  /* Nobody else is given it. */
  EXPECT_EQ("<none>", Via(s1_, "/snapshot"));
  EXPECT_EQ("<none>", Via(s2_, "/snapshot"));
  EXPECT_EQ("<none>", Via(std::string(), "/snapshot"));
  /* The grant is revoked. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_revoke(catalog_, "operators", 9,
                             "Take snapshots", 14));
  EXPECT_EQ("<none>", Via(op_, "/snapshot"));
}

/* The rows the store keeps: the current tables, the blind index. A person's
 * email is in none of them as it is written (the sealed text is not it), the
 * blind index finds it by its MAC, and an erased person leaves neither. */
TEST_F(SweepOps, StoredProjectionHoldsNoPersonalPlaintext) {
  ArrangeOps();
  ASSERT_FALSE(HasFatalFailure());
  for (int which : {GDEFSTOR_MODEL_TRUTH, GDEFSTOR_MODEL_CURRENT}) {
    std::string dump = Dump(which);
    EXPECT_TRUE(Has(dump, Hex(kCB)) || Has(dump, kCB))
        << "the sweep cannot see a stored value in dump " << which;
    EXPECT_TRUE(Has(dump, Hex("s1:")))
        << "dump " << which << " holds no personal value at all, sealed or not";
    EXPECT_FALSE(Traces(dump, kEmail)) << which;
    EXPECT_FALSE(Traces(dump, kOtherEmail)) << which;
  }
  /* Control: the blind index holds a row for each, and finds them. */
  size_t blind = 0;
  {
    std::istringstream in(Dump(GDEFSTOR_MODEL_TRUTH));
    std::string line;
    while (std::getline(in, line)) {
      blind += line.size() > 1 && line[0] == 'B' && line[1] == ' ';
    }
  }
  EXPECT_GE(blind, 2u);
  char ** ids = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_find(subjects_, catalog_, kMember,
                             strlen(kMember), "email", 5, "en", 2, kEmail,
                             strlen(kEmail), &ids, &count));
  EXPECT_EQ(1u, count);
  gdefcore_ids_free(catalog_, ids, count);
  /* Erased: nothing is found, and nothing of the person is kept in a form
   * that gives them back. */
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_subject(catalog_, m2_.data(), m2_.size(), sid));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_erase(subjects_, sid, strlen(sid), sid,
                             strlen(sid)));
  ids = NULL;
  count = 99;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_find(subjects_, catalog_, kMember,
                             strlen(kMember), "email", 5, "en", 2, kEmail,
                             strlen(kEmail), &ids, &count));
  EXPECT_EQ(0u, count);
  gdefcore_ids_free(catalog_, ids, count);
  for (int which : {GDEFSTOR_MODEL_TRUTH, GDEFSTOR_MODEL_CURRENT}) {
    std::string dump = Dump(which);
    EXPECT_FALSE(Traces(dump, kEmail)) << which;
  }
}

/* ---- the list of outputs --------------------------------------------------------- */

struct Listed {
  const char * name;
  const char * covered;  ///< the test that sweeps it, or why it needs none
};

/* Every function a public header declares that answers a principal with a
 * value derived from stored ones, or that hands such a value to an operator,
 * and where the sweep covers it. A function that only answers yes or no
 * (a decision) is listed so; it carries no value. */
const Listed kListed[] = {
    {"gdefcore_access_read", "Sweep.ReadCarriesNoCanary"},
    {"gdefcore_access_tree", "Sweep.TreeCarriesNoCanary"},
    {"gdefcore_access_revision_values", "Sweep.RevisionCarriesNoCanary"},
    {"gdefcore_access_list", "Sweep.ListCarriesNoCanary"},
    {"gdefcore_access_list_page", "Sweep.ListCarriesNoCanary"},
    {"gdefcore_access_count", "Sweep.CountCarriesNoCanary"},
    {"gdefcore_form_tree_for", "Sweep.FormCarriesNoCanary"},
    {"gdefcore_render_page", "Sweep.RecentPostsSummaryCarriesNoCanary"},
    {"gdefcore_render_entity", "Sweep.RenderCarriesNoCanary"},
    {"gdefcore_access_render_key", "Sweep.FragmentCacheCarriesNoCanary"},
    {"gdefcore_fragment_put", "Sweep.FragmentCacheCarriesNoCanary"},
    {"gdefcore_fragment_get", "Sweep.FragmentCacheCarriesNoCanary"},
    {"gdefcore_subject_export", "Sweep.SubjectExportCarriesNoCanaryToTheUnauthorized"},
    {"gdefcore_subject_snapshot", "Sweep.SnapshotCarriesNoCanaryToTheUnauthorized"},
    {"gdefcore_subject_find", "Sweep.StoredProjectionHoldsNoPersonalPlaintext"},
    {"gdefcore_subject_reindex", "Sweep.StoredProjectionHoldsNoPersonalPlaintext"},
    {"gdefcore_subject_keyset", "keys, no data: the key set holds wrapped keys and a ledger"},
    {"gdefcore_keyring_export", "keys, no data: the keyring's wrap"},
    {"gdefcore_access_matrix", "decision: the grants themselves, for an administrator"},
    {"gdefcore_access_can", "decision: yes or no"},
    {"gdefcore_access_can_field", "decision: yes or no"},
    {"gdefcore_access_can_create", "decision: yes or no"},
    {"gdefcore_access_decide", "decision: yes or no, and its source"},
    {"gdefcore_access_permits", "decision: yes or no"},
    {"gdefcore_condition_eval", "decision: yes or no, as the system"},
    {"gdefcore_form_resolve", "Oracle.Entities: a path resolves to an id or to nothing"},
    {"gdefcore_module_enabled", "decision: yes or no"},
    {"gdefcore_module_service", "a module's own service, not an entity value"},
    {"gdefcore_hook_fire", "a hook, not an entity value"},
    {"gdefcore_template_may_edit", "decision: yes or no"},
    {"gdefcore_render_sample", "sample data, no entity value"},
};

/* Words in a function's name that say it derives a value from stored ones. */
const char * const kDerivedWords[] = {"search", "aggregate", "feed", "export",
    "snapshot", "summar", "project", "reindex", "suggest", "autocomplete",
    "facet", "rollup", "digest", "excerpt", "snippet"};

TEST(SweepList, EveryDerivedOutputIsListed) {
  /* Search, an aggregate, a feed and an export of entities do not exist in
   * core. Whatever adds one is named here, and the sweep has to cover it. */
  std::string dir;
  std::vector<std::string> names;
  std::vector<std::string> problems;
  std::vector<std::string> candidates;
  const char * env = getenv("GHOTI_DEFCORE_INCLUDE");
  std::string here = __FILE__;
  size_t slash = here.find_last_of("/\\");
  if (env != NULL) {
    candidates.push_back(env);
  }
  if (slash != std::string::npos) {
    candidates.push_back(here.substr(0, slash) +
                         "/../include/ghoti.io/defiant-core");
  }
  candidates.push_back("include/ghoti.io/defiant-core");
  candidates.push_back("../include/ghoti.io/defiant-core");
  for (const std::string & c : candidates) {
    std::ifstream probe(c + "/entity.h");
    if (probe) {
      dir = c;
      break;
    }
  }
  ASSERT_FALSE(dir.empty()) << "the public headers were not found";
  {
    DIR * d = opendir(dir.c_str());
    struct dirent * entry;
    ASSERT_NE((DIR *)NULL, d);
    while ((entry = readdir(d)) != NULL) {
      std::string file = entry->d_name;
      std::ifstream in((dir + "/" + file).c_str(), std::ios::binary);
      std::stringstream buf;
      size_t at = 0;
      if (file.size() < 3 || file.compare(file.size() - 2, 2, ".h") != 0 ||
          file == "namespace.h" || file == "libver.h" || file == "macros.h" ||
          !in) {
        continue;
      }
      buf << in.rdbuf();
      std::string text = buf.str();
      while ((at = text.find("GDEFCORE_API", at)) != std::string::npos) {
        size_t paren = text.find('(', at);
        size_t semi = text.find(';', at);
        size_t end;
        size_t start;
        at += 12;
        if (paren == std::string::npos || semi == std::string::npos ||
            paren > semi) {
          continue;
        }
        end = paren;
        while (end > 0 && text[end - 1] == ' ') {
          end -= 1;
        }
        start = end;
        while (start > 0 && (isalnum((unsigned char)text[start - 1]) ||
                                text[start - 1] == '_')) {
          start -= 1;
        }
        names.push_back(text.substr(start, end - start));
      }
    }
    closedir(d);
  }
  ASSERT_GE(names.size(), 150u) << "a scan that found little is not a denominator";
  auto listed = [](const std::string & name) {
    for (const Listed & l : kListed) {
      if (name == l.name) {
        return true;
      }
    }
    return false;
  };
  for (const std::string & name : names) {
    std::string lower = name;
    bool derived = false;
    for (char & c : lower) {
      c = (char)tolower((unsigned char)c);
    }
    for (const char * w : kDerivedWords) {
      derived = derived || lower.find(w) != std::string::npos;
    }
    if (derived && !listed(name)) {
      problems.push_back(name + " is declared in a public header, derives a value"
          " from stored ones by its name, and is not listed in the sweep"
          " (tests/test_sweep.cpp, kListed): swept or explained");
    }
  }
  for (const gate::Surface & s : gate::kSurface) {
    if (std::string(s.category) == "RF" && !listed(s.name)) {
      problems.push_back(std::string(s.name) + " is a read made for a principal"
          " (RF in gate_surface.h) and is not listed in the sweep"
          " (tests/test_sweep.cpp, kListed): swept or explained");
    }
  }
  for (const Listed & l : kListed) {
    bool declared = false;
    for (const std::string & name : names) {
      declared = declared || name == l.name;
    }
    if (!declared) {
      problems.push_back(std::string(l.name) + " is listed in the sweep and no"
          " public header declares it");
    }
  }
  {
    std::string all;
    for (const std::string & p : problems) {
      all += "\n  " + p;
    }
    EXPECT_TRUE(problems.empty()) << all;
  }
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
