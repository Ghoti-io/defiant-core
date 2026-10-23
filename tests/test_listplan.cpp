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
 * Story A2: a condition compiled into a filtered, counted and paged list, on
 * the storage port's entity query since story S6b.
 *
 * The evaluator (gdefcore_condition_eval(), and the entity-by-entity list it
 * decides) is the reference. Two generated sweeps hold the compiled form to
 * it on both storage backends (memory, and SQLite in a scratch directory),
 * and on Postgres when GDEFCORE_TEST_LISTPLAN=postgres (make
 * test-listplan-postgres, through defiant-storage-postgres's tools/pg-test.sh):
 * every random condition, over every entity, selects exactly the entities the
 * evaluator holds on, including where it cannot decide; and every random list
 * (grants, filter, sorts, condition, page) is the evaluated list, in the same
 * order, with the same total. The named tests are the rows of the story's
 * matrix.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage-sqlite/model.h>
#ifdef GDEFCORE_TEST_HAVE_PG
#include <ghoti.io/defiant-storage-postgres/model.h>
#endif

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace {

const char kBlog[] = "t.blog";
const char kVault[] = "t.vault";

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed * 6364136223846793005ull + 1442695040888963407ull) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
  uint64_t below(uint64_t n) { return n == 0 ? 0 : next() % n; }
  bool chance(unsigned percent) { return below(100) < percent; }
};

typedef std::vector<std::pair<std::string, std::vector<std::string> > > Vals;

Vals V(std::initializer_list<std::pair<std::string, std::string> > one) {
  Vals out;
  for (const auto & kv : one) {
    out.push_back({kv.first, {kv.second}});
  }
  return out;
}

GDEFCORE_Field Field(const char * name, int many = 0, int personal = 0,
    int type = 0) {
  GDEFCORE_Field f;
  memset(&f, 0, sizeof f);
  f.size = sizeof f;
  f.name = name;
  f.name_len = strlen(name);
  f.many = many;
  f.personal = personal;
  f.type = type;
  return f;
}

enum { kMemory = 0, kSqlite = 1, kPostgres = 2 };

/* The backends a test runs on: memory and SQLite, or Postgres alone when
 * GDEFCORE_TEST_LISTPLAN=postgres (it needs a server, so it is a target of its
 * own). */
std::vector<int> Backends() {
  const char * v = getenv("GDEFCORE_TEST_LISTPLAN");
  if (v != NULL && strcmp(v, "postgres") == 0) {
    return {kPostgres};
  }
  return {kMemory, kSqlite};
}

/** One tenant on a chosen backend, with two types and the helpers. */
struct Site {
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  std::string dir;
  std::string prefix;
  std::vector<GDEFCORE_Request *> reqs;
  int backend;

  explicit Site(int which, const GDEFCORE_Limits * limits = NULL)
      : backend(which) {
    if (backend == kPostgres) {
#ifdef GDEFCORE_TEST_HAVE_PG
      static unsigned n = 0;
      char buf[32];
      const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
      EXPECT_TRUE(ci != NULL && ci[0] != '\0');
      snprintf(buf, sizeof buf, "lp%x_%u_", (unsigned)getpid() & 0xfffffu, ++n);
      prefix = buf;
      GDEFSPG_Options o;
      gdefspg_options_default(&o);
      o.conninfo = ci;
      o.schema_prefix = prefix.c_str();
      EXPECT_EQ(GDEFSPG_OK, gdefspg_model_store_create(&o, NULL, NULL, &store));
#else
      ADD_FAILURE() << "the Postgres arm needs defiant-storage-postgres";
#endif
    } else if (backend == kSqlite) {
      std::error_code ec;
      std::filesystem::path base = std::filesystem::temp_directory_path(ec);
      std::random_device entropy;
      for (int i = 0; i < 100 && dir.empty(); i++) {
        std::filesystem::path p = base / ("gdefcore-listplan-" + std::to_string(entropy()));
        if (std::filesystem::create_directory(p, ec) && !ec) {
          dir = p.string();
        }
      }
      EXPECT_FALSE(dir.empty());
      GDEFSSQLITE_ModelOptions o;
      gdefssqlite_model_options_default(&o);
      o.synchronous = GDEFSSQLITE_SYNC_OFF; /* many stores; not about the disk */
      EXPECT_EQ(GDEFSSQLITE_OK,
          gdefssqlite_model_store_create(dir.c_str(), &o, NULL, NULL, &store));
    } else {
      EXPECT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store, (const uint8_t *)"t", 1, limits, NULL,
            &catalog));
    {
      /* rank and embargo are integers (access SPEC decision 12): an
       * ordering needs a number. */
      GDEFCORE_Field f[5] = {Field("title"), Field("group"),
          Field("rank", 0, 0, GDEFSTOR_FIELD_INTEGER),
          Field("embargo", 0, 0, GDEFSTOR_FIELD_INTEGER), Field("tags", 1)};
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_type_define(catalog, kBlog, strlen(kBlog),
              GDEFCORE_TYPE_CONTENT, f, 5));
    }
    {
      /* `ssn` names its subject source (story S7): the `who` beside it. */
      GDEFCORE_Field f[3] = {Field("name"), Field("ssn", 0, 1),
          Field("who", 0, 0, GDEFSTOR_FIELD_REFERENCE)};
      f[1].subject = "who";
      f[1].subject_len = 3;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_type_define(catalog, kVault, strlen(kVault),
              GDEFCORE_TYPE_CONTENT, f, 3));
    }
  }

  ~Site() {
    for (GDEFCORE_Request * r : reqs) {
      gdefcore_request_destroy(r);
    }
    gdefcore_catalog_destroy(catalog);
    gdefstor_store_destroy(store);
    if (!dir.empty()) {
      std::filesystem::remove_all(dir);
    }
  }

  GDEFCORE_Request * Req(const std::string & principal, int64_t now = 5000,
      const std::string & acting = std::string()) {
    GDEFCORE_Request * r = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)"t", 1, 0, 0, NULL, &r));
    if (!principal.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_principal(r, principal.data(), principal.size()));
    }
    if (!acting.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_acting_principal(r, acting.data(), acting.size()));
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_time(r, now));
    reqs.push_back(r);
    return r;
  }

  /** Create an entity (actor is its creator) and save it. Mode 0 saves it;
   * mode 1 saves it as a draft, so it has no revision and is in no list;
   * mode 2 saves it, unpublishes it and leaves a draft over it, which is
   * what a draft save used to leave (an unpublished first revision). */
  std::string Make(const char * type, const std::string & actor, const Vals & vals,
      int mode = 0, const char * lang = "en") {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    id[0] = '\0';
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog, type, strlen(type), id, NULL));
    Save(id, actor, vals, mode == 1 ? 1 : 0, lang);
    if (mode == 2) {
      Unpublish(id);
      Vals other = vals;
      for (auto & kv : other) {
        for (auto & v : kv.second) {
          v = "drafted-" + v;
        }
      }
      if (!other.empty() && other[0].first == "title") {
        Save(id, actor, {other[0]}, 1, lang);
      }
    }
    return std::string(id);
  }

  void Save(const std::string & id, const std::string & actor, const Vals & vals,
      int mode = 0, const char * lang = "en") {
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> values(vals.size());
    std::vector<std::vector<const char *> > texts(vals.size());
    std::vector<std::vector<size_t> > lens(vals.size());
    size_t i;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog, actor.empty() ? NULL : actor.data(),
            actor.size(), &cs));
    for (i = 0; i < vals.size(); i++) {
      size_t k;
      for (k = 0; k < vals[i].second.size(); k++) {
        texts[i].push_back(vals[i].second[k].c_str());
        lens[i].push_back(vals[i].second[k].size());
      }
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = vals[i].first.c_str();
      values[i].field_len = vals[i].first.size();
      values[i].texts = texts[i].data();
      values[i].text_lens = lens[i].data();
      values[i].count = texts[i].size();
    }
    if (mode == 1) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_entity_save_draft(cs, id.data(), id.size(), lang, strlen(lang),
              values.data(), values.size()));
    } else {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_entity_save(cs, id.data(), id.size(), lang, strlen(lang),
              values.data(), values.size()));
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }

  void Unpublish(const std::string & id) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &cs));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_unpublish(cs, id.data(), id.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }

  std::string Principal(const char * role = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    id[0] = '\0';
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog, id));
    if (role != NULL) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_access_principal_add_role(catalog, id, strlen(id), role,
              strlen(role)));
    }
    return std::string(id);
  }

  void Role(const char * name) {
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog, name, strlen(name), NULL));
  }

  GDEFCORE_Result Declare(const std::string & label, const char * action,
      int cond, const std::string & text, const char * type = kBlog,
      const char * field = NULL) {
    GDEFCORE_Permission p;
    memset(&p, 0, sizeof p);
    p.size = sizeof p;
    p.label = label.c_str();
    p.label_len = label.size();
    p.module_name = "notes";
    p.module_name_len = 5;
    p.action = action;
    p.action_len = strlen(action);
    p.condition = cond;
    p.type_name = type;
    p.type_name_len = strlen(type);
    if (field != NULL) {
      p.field = field;
      p.field_len = strlen(field);
    }
    if (!text.empty()) {
      p.condition_text = text.c_str();
      p.condition_text_len = text.size();
    }
    return gdefcore_access_declare(catalog, &p);
  }

  void Grant(const char * role, const std::string & label) {
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog, role, strlen(role), label.c_str(),
            label.size(), "core.role", 9));
  }
};

/** The note a list leaves on its request: how it was answered. */
std::string HowAnswered(GDEFCORE_Request * r) {
  size_t n = 0;
  const char * v = gdefcore_request_note(r, "defiant.access.list", 19, &n);
  return v == NULL ? std::string("none") : std::string(v, n);
}

struct Listed {
  GDEFCORE_Result rc = GDEFCORE_ERR_INTERNAL;
  std::vector<std::string> ids;
  uint64_t total = 12345;
  std::string how;
};

struct Q {
  std::string type = kBlog;
  std::string lang = "en";
  std::string filter_field;
  std::string filter_text;
  std::string sort1;
  std::string sort2;
  bool desc1 = false;
  bool desc2 = false;
  std::string condition;
  uint64_t offset = 0;
  uint64_t limit = 0;
  int flags = 0;
};

GDEFCORE_Access_List ToQuery(const Q & q) {
  GDEFCORE_Access_List a;
  memset(&a, 0, sizeof a);
  a.size = sizeof a;
  a.type_name = q.type.c_str();
  a.type_name_len = q.type.size();
  a.lang = q.lang.c_str();
  a.lang_len = q.lang.size();
  if (!q.filter_field.empty()) {
    a.filter_field = q.filter_field.c_str();
    a.filter_field_len = q.filter_field.size();
    a.filter_text = q.filter_text.data();
    a.filter_text_len = q.filter_text.size();
  }
  if (!q.sort1.empty()) {
    a.sort_field = q.sort1.c_str();
    a.sort_field_len = q.sort1.size();
  }
  if (!q.sort2.empty()) {
    a.sort2_field = q.sort2.c_str();
    a.sort2_field_len = q.sort2.size();
  }
  a.sort_descending = q.desc1;
  a.sort2_descending = q.desc2;
  if (!q.condition.empty()) {
    a.condition = q.condition.c_str();
    a.condition_len = q.condition.size();
  }
  a.offset = q.offset;
  a.limit = q.limit;
  a.flags = q.flags;
  return a;
}

Listed List(Site & site, GDEFCORE_Request * r, const Q & q) {
  Listed out;
  GDEFCORE_Access_List a = ToQuery(q);
  char ** ids = NULL;
  size_t count = 0;
  out.rc = gdefcore_access_list_page(site.catalog, r, &a, &ids, &count, &out.total);
  out.how = HowAnswered(r);
  if (out.rc == GDEFCORE_OK) {
    for (size_t i = 0; i < count; i++) {
      out.ids.push_back(ids[i]);
    }
    gdefcore_access_free(site.catalog, ids, count);
  }
  return out;
}

Listed Reference(Site & site, GDEFCORE_Request * r, Q q) {
  q.flags |= GDEFCORE_ACCESS_LIST_EVALUATE;
  return List(site, r, q);
}

/** The ids as the titles they carry, for messages and readable expectations. */
std::string Titles(Site & site, const std::vector<std::string> & ids) {
  std::string out;
  for (const std::string & id : ids) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    std::string t = "?";
    if (gdefcore_entity_values(site.catalog, NULL, GDEFCORE_VIEW_CURRENT, id.data(),
            id.size(), "en", 2, "title", 5, &texts, &lens, &n) == GDEFCORE_OK &&
        n > 0) {
      t.assign(texts[0], lens[0]);
      gdefcore_values_free(site.catalog, texts, lens, n);
    }
    out += (out.empty() ? "" : ",") + t;
  }
  return out;
}

/* ---- a random world ------------------------------------------------------ */

static const char * kTexts[] = {"", "a", "b", "g", "h", "7", "07", "abc", "-3", "10",
    "9", "100", "published", "draft", "t.blog", "x'y", "%", "_", "5000", "4999", "6000"};
static const size_t kNTexts = sizeof kTexts / sizeof kTexts[0];

struct World {
  std::vector<std::string> people;
  std::vector<std::string> blogs;
  std::vector<std::string> drafts;   /* never saved: no revision */
  std::vector<std::string> vaults;
};

bool Integer(const std::string & t, int64_t * out) {
  char * end = NULL;
  if (t.empty() || t.size() > 18) {
    return false;
  }
  long long v = strtoll(t.c_str(), &end, 10);
  if (end == NULL || *end != '\0') {
    return false;
  }
  *out = (int64_t)v;
  return true;
}

World MakeWorld(Site & site, Rng & rng, size_t nblogs) {
  World w;
  for (int i = 0; i < 4; i++) {
    w.people.push_back(site.Principal());
  }
  for (size_t i = 0; i < nblogs; i++) {
    Vals v;
    auto pick = [&]() { return std::string(kTexts[rng.below(kNTexts)]); };
    /* An integer field holds the texts that are integers ("07" is 7). */
    auto pick_number = [&]() {
      std::string t;
      int64_t x;
      do {
        t = kTexts[rng.below(kNTexts)];
      } while (t.empty() || !Integer(t, &x));
      return t;
    };
    if (rng.chance(90)) {
      v.push_back({"title", {"e" + std::to_string(i)}});
    }
    if (rng.chance(75)) {
      v.push_back({"group", {pick()}});
    }
    if (rng.chance(75)) {
      v.push_back({"rank", {pick_number()}});
    }
    if (rng.chance(60)) {
      v.push_back({"embargo", {pick_number()}});
    }
    if (rng.chance(70)) {
      std::vector<std::string> tags;
      size_t nt = rng.below(4);
      for (size_t k = 0; k < nt; k++) {
        tags.push_back(pick());
      }
      v.push_back({"tags", tags});
    }
    std::string creator = rng.chance(85) ? w.people[rng.below(w.people.size())] : "";
    /* Saved and published, saved with a draft over it and unpublished, or a
     * draft that was never saved (in no list, never a revision). */
    int mode = rng.chance(75) ? 0 : (rng.chance(80) ? 2 : 1);
    std::string id = site.Make(kBlog, creator, v, mode);
    if (mode == 1) {
      w.drafts.push_back(id);
      continue;
    }
    if (rng.chance(30)) {
      /* A second revision by someone else, in another language too. */
      Vals f = {{"title", {"fr" + std::to_string(i)}}, {"group", {pick()}}};
      site.Save(id, w.people[rng.below(w.people.size())], f, 0, "fr");
    }
    if (mode == 0 && rng.chance(12)) {
      site.Unpublish(id);
    }
    w.blogs.push_back(id);
  }
  for (int i = 0; i < 3; i++) {
    w.vaults.push_back(site.Make(kVault, "", V({{"name", "v" + std::to_string(i)}})));
  }
  return w;
}

/* ---- random conditions --------------------------------------------------- */

std::string Quote(const std::string & s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') {
      out += '\\';
    }
    out += c;
  }
  return out + "\"";
}

struct CondGen {
  Rng & rng;
  const World & w;
  bool bad_fields;   /* may name a personal field and a field the type lacks */

  std::string Constant() {
    switch (rng.below(5)) {
      case 0:
        return std::to_string((long long)rng.below(12) - 2);
      case 1:
        return Quote(w.people[rng.below(w.people.size())]);
      default:
        return Quote(kTexts[rng.below(kNTexts)]);
    }
  }

  std::string Operand() {
    static const char * fields[] = {"title", "group", "rank", "embargo", "tags"};
    switch (rng.below(11)) {
      case 0:
        return "type";
      case 1:
        return "state";
      case 2:
        return "creator";
      case 3:
        return "revision.creator";
      case 4:
        return "principal";
      case 5:
        return "now";
      case 6:
      case 7:
      case 8:
        if (bad_fields && rng.chance(12)) {
          return rng.chance(50) ? "field.ssn" : "field.nope";
        }
        return std::string("field.") + fields[rng.below(5)];
      default:
        return Constant();
    }
  }

  std::string Node(int depth) {
    unsigned pick = (unsigned)rng.below(depth > 0 ? 12 : 8);
    if (pick >= 8) {
      if (pick == 11) {
        return "(not " + Node(depth - 1) + ")";
      }
      std::string op = pick == 10 ? "or" : "and";
      std::string out = "(" + op;
      size_t k = 2 + rng.below(2);
      for (size_t i = 0; i < k; i++) {
        out += " " + Node(depth - 1);
      }
      return out + ")";
    }
    if (pick == 0 && rng.chance(25)) {
      return rng.chance(50) ? "true" : "false";
    }
    if (pick == 1) {
      std::string out = "(in " + Operand() + " (";
      size_t k = 1 + rng.below(3);
      for (size_t i = 0; i < k; i++) {
        out += (i ? " " : "") + (rng.chance(80) ? Quote(kTexts[rng.below(kNTexts)]) : Constant());
      }
      return out + "))";
    }
    static const char * ops[] = {"=", "!=", "<", "<=", ">", ">="};
    /* One draw per statement: the order of a call's arguments, the operands
     * of an overloaded +, is the compiler's, and GCC's differs between
     * targets (x86-64 draws the last first; s390x and SPARC64 the first), so
     * a big-endian host swept other conditions (story S10). Drawn in
     * x86-64's order, right to left. */
    std::string right = rng.chance(60) ? Constant() : Operand();
    std::string left = Operand();
    const char * op = ops[rng.below(6)];
    return std::string("(") + op + " " + left + " " + right + ")";
  }
};

/* ---- the compiled predicate against the evaluator ------------------------ */

/** The entities of @p type the compiled @p cond selects. */
std::set<std::string> Compiled(Site & site, GDEFCORE_Condition * cond,
    const std::string & principal, int64_t now, const char * type,
    const char * lang, bool * out_unsupported, bool * out_failed) {
  std::set<std::string> out;
  GDEFCORE_Plan * plan = NULL;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_plan_create(site.catalog, type, strlen(type), lang, strlen(lang),
          principal.empty() ? NULL : principal.data(), principal.size(), now,
          &plan));
  const GDEFSTOR_QueryNode * node = gdefcore_plan_condition(plan, cond);
  *out_unsupported = gdefcore_plan_unsupported(plan) != 0;
  *out_failed = gdefcore_plan_failed(plan) != 0;
  if (node != NULL) {
    GDEFSTOR_Query q;
    char ** ids = NULL;
    size_t n = 0;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.where = node;
    /* The plan reads fields in its language only when the query binds it
     * (the port's query binds one language, story S6a2). */
    q.language = lang;
    q.language_len = strlen(lang);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_query_current(site.catalog, type, strlen(type), &q, &ids,
            &n, NULL));
    for (size_t i = 0; i < n; i++) {
      out.insert(ids[i]);
    }
    gdefcore_ids_free(site.catalog, ids, n);
  }
  gdefcore_plan_free(plan);
  return out;
}

std::set<std::string> Evaluated(Site & site, GDEFCORE_Condition * cond,
    GDEFCORE_Request * req, const std::vector<std::string> & ids, const char * lang,
    bool * out_any_failed) {
  std::set<std::string> out;
  for (const std::string & id : ids) {
    GDEFCORE_Condition_Subject s;
    int failed = 0;
    memset(&s, 0, sizeof s);
    s.size = sizeof s;
    s.entity = id.data();
    s.entity_len = id.size();
    s.lang = lang;
    s.lang_len = strlen(lang);
    if (gdefcore_condition_eval(site.catalog, req, cond, &s, &failed)) {
      out.insert(id);
    }
    if (failed) {
      *out_any_failed = true;
    }
  }
  return out;
}

}  // namespace

TEST(ListPlan, ConditionsAgreeWithTheEvaluator) {
  size_t compared = 0;
  size_t nonempty = 0;
  size_t partial = 0;
  size_t with_failure = 0;
  for (int backend : Backends()) {
    Site site(backend);
    Rng rng(backend + 11);
    World w = MakeWorld(site, rng, 45);
    std::vector<std::string> all = w.blogs;
    for (int round = 0; round < 450; round++) {
      CondGen gen{rng, w, round % 3 == 0};
      std::string text = gen.Node(3);
      GDEFCORE_Condition * cond = NULL;
      GDEFCORE_Condition_Error err;
      memset(&err, 0, sizeof err);
      err.size = sizeof err;
      if (gdefcore_condition_parse(text.data(), text.size(), &cond, &err) != GDEFCORE_OK) {
        continue;
      }
      /* Anonymous, a person, and a clock either side of the embargoes. */
      const std::string who = rng.chance(20) ? "" : w.people[rng.below(w.people.size())];
      const int64_t now = rng.chance(50) ? 5000 : 6001;
      const char * lang = rng.chance(75) ? "en" : "fr";
      GDEFCORE_Request * req = site.Req(who, now);
      bool unsupported = false;
      bool plan_failed = false;
      bool eval_failed = false;
      std::set<std::string> got =
          Compiled(site, cond, who, now, kBlog, lang, &unsupported, &plan_failed);
      std::set<std::string> want = Evaluated(site, cond, req, all, lang, &eval_failed);
      ASSERT_FALSE(unsupported) << text;
      EXPECT_EQ(want, got) << "backend " << backend << " lang " << lang << " who "
                           << (who.empty() ? "anon" : "person") << " now " << now
                           << " : " << text;
      /* A failure the evaluator met was foreseen by the plan. */
      if (eval_failed) {
        EXPECT_TRUE(plan_failed) << text;
        with_failure += 1;
      }
      compared += 1;
      nonempty += want.empty() ? 0 : 1;
      partial += (!want.empty() && want.size() < all.size()) ? 1 : 0;
      gdefcore_condition_free(cond);
      if (HasFailure()) {
        return;
      }
    }
  }
  /* The bounds are for two backends; one (Postgres alone) has half. */
  const size_t nb = Backends().size();
  /* Printed, so a run on another target can be held to this one's sweep. */
  printf("condition sweep: %zu compared, %zu nonempty, %zu partial, %zu with "
         "a failure\n", compared, nonempty, partial, with_failure);
  EXPECT_GE(compared, 350u * nb);
  /* The sweep is not trivial: many conditions select some and not all, and
   * some reach a failure. */
  /* (125 per backend before fields were typed; an integer field now holds
   * only integers, so fewer random constants match anything.) */
  EXPECT_GE(nonempty, 100u * nb);
  EXPECT_GE(partial, 30u * nb);
  EXPECT_GE(with_failure, 8u * nb);
}

TEST(ListPlan, FailureNeverGrantsWhenCompiled) {
  for (int backend : Backends()) {
    Site site(backend);
    std::string e = site.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
    std::vector<std::string> ids = {e};
    GDEFCORE_Request * req = site.Req("");
    struct Row { const char * text; int holds; int failed; } rows[] = {
        /* A field the type lacks fails, and a failure is no grant under not. */
        {"(= field.nope \"x\")", 0, 1},
        {"(not (= field.nope \"x\"))", 0, 1},
        {"(!= field.nope \"x\")", 0, 1},
        /* An or whose first operand fails never reaches its true second one;
         * one whose first operand is true never reaches the failing one. */
        {"(or (= field.nope \"x\") true)", 0, 1},
        {"(or true (= field.nope \"x\"))", 1, 0},
        {"(and false (= field.nope \"x\"))", 0, 0},
        {"(and true (= field.nope \"x\"))", 0, 1},
        {"(or (= field.group \"a\") (= field.nope \"x\"))", 1, 0},
        {"(and (= field.group \"zz\") (= field.nope \"x\"))", 0, 0},
        {"(not (and (= field.group \"zz\") (= field.nope \"x\")))", 1, 0},
        /* Controls: the same shapes on a field the type has. */
        {"(not (= field.group \"x\"))", 1, 0},
        {"(or (= field.group \"zz\") true)", 1, 0},
    };
    for (const Row & row : rows) {
      GDEFCORE_Condition * cond = NULL;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_condition_parse(row.text, strlen(row.text), &cond, NULL));
      bool unsupported = false;
      bool plan_failed = false;
      bool eval_failed = false;
      std::set<std::string> got =
          Compiled(site, cond, "", 5000, kBlog, "en", &unsupported, &plan_failed);
      std::set<std::string> want = Evaluated(site, cond, req, ids, "en", &eval_failed);
      EXPECT_EQ(row.holds ? 1u : 0u, want.size()) << "evaluator: " << row.text;
      EXPECT_EQ(row.failed, eval_failed ? 1 : 0) << row.text;
      EXPECT_EQ(want, got) << "backend " << backend << " " << row.text;
      gdefcore_condition_free(cond);
    }
  }
}

TEST(ListPlan, APersonalFieldIsNeverComparedAndNeverGrants) {
  for (int backend : Backends()) {
    Site site(backend);
    std::string v = site.Make(kVault, "", V({{"name", "N"}}));
    GDEFCORE_Request * req = site.Req("");
    /* The personal field holds nothing here, so comparing it with the empty
     * text would be true if it were read; it is ciphertext and is never read. */
    for (const char * text : {"(= field.ssn \"\")", "(not (= field.ssn \"x\"))",
             "(in field.ssn (\"\"))"}) {
      GDEFCORE_Condition * cond = NULL;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_condition_parse(text, strlen(text), &cond, NULL));
      bool unsupported = false;
      bool plan_failed = false;
      bool eval_failed = false;
      std::set<std::string> got =
          Compiled(site, cond, "", 5000, kVault, "en", &unsupported, &plan_failed);
      std::set<std::string> want = Evaluated(site, cond, req, {v}, "en", &eval_failed);
      EXPECT_TRUE(want.empty()) << text;
      EXPECT_TRUE(eval_failed) << text;
      EXPECT_TRUE(got.empty()) << "backend " << backend << " " << text;
      EXPECT_TRUE(plan_failed) << text;
      gdefcore_condition_free(cond);
    }
    /* And not as a filter or a sort of the list, nor in its own condition. */
    GDEFCORE_Plan * plan = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_plan_create(site.catalog, kVault,
                               strlen(kVault), "en", 2, NULL, 0, 0, &plan));
    EXPECT_TRUE(gdefcore_plan_field_is(plan, "ssn", 3, "x", 1) == NULL);
    EXPECT_TRUE(gdefcore_plan_unsupported(plan));
    gdefcore_plan_free(plan);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_plan_create(site.catalog, kVault,
                               strlen(kVault), "en", 2, NULL, 0, 0, &plan));
    EXPECT_TRUE(gdefcore_plan_sort_field(plan, "ssn", 3, 0) == NULL);
    gdefcore_plan_free(plan);
    site.Role("r");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read vault", "read", GDEFCORE_ACCESS_ANY, "", kVault));
    site.Grant("r", "Read vault");
    std::string p = site.Principal("r");
    Q q;
    q.type = kVault;
    q.condition = "(= field.ssn \"\")";
    Listed l = List(site, site.Req(p), q);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, l.rc);
    q.condition = "(= field.nope \"\")";
    l = List(site, site.Req(p), q);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, l.rc);
    q.condition = "(= field.name \"N\")";
    l = List(site, site.Req(p), q);
    EXPECT_EQ(GDEFCORE_OK, l.rc);
    EXPECT_EQ(1u, l.ids.size());
  }
}

/* ---- the lists ----------------------------------------------------------- */

/** A person who reads blogs under the grants listed, one role per grant. */
std::string ReaderOf(Site & site, const std::string & role,
    const std::vector<std::pair<std::string, std::string> > & grants) {
  site.Role(role.c_str());
  for (size_t i = 0; i < grants.size(); i++) {
    std::string label = role + " grant " + std::to_string(i);
    int cond = 0;
    std::string text = grants[i].second;
    if (text == "any") {
      cond = GDEFCORE_ACCESS_ANY;
      text.clear();
    } else if (text == "own") {
      cond = GDEFCORE_ACCESS_OWN;
      text.clear();
    }
    /* A random condition may name a type or a state that does not exist, and
     * is then refused at definition: that grant is not made. */
    if (site.Declare(label, grants[i].first.c_str(), cond, text) == GDEFCORE_OK) {
      site.Grant(role.c_str(), label);
    }
  }
  return site.Principal(role.c_str());
}

TEST(ListPlan, ListsAgreeWithTheEvaluatedList) {
  size_t compared = 0;
  size_t planned = 0;
  size_t nonempty = 0;
  size_t paged = 0;
  for (int backend : Backends()) {
    Site site(backend);
    Rng rng(backend + 101);
    World w = MakeWorld(site, rng, 50);
    /* Principals with random read grants; some are agents of the people. */
    struct Who {
      std::string id;
      std::string name;
    };
    std::vector<Who> whos;
    for (int i = 0; i < 6; i++) {
      std::vector<std::pair<std::string, std::string> > grants;
      size_t ng = 2 + rng.below(3);
      for (size_t k = 0; k < ng; k++) {
        CondGen gen{rng, w, false};
        std::string text = rng.chance(30) ? (rng.chance(50) ? "any" : "own") : gen.Node(2);
        grants.push_back({"read", text});
      }
      std::string role = "r" + std::to_string(i);
      std::string id = ReaderOf(site, role, grants);
      whos.push_back({id, role});
    }
    for (int round = 0; round < 360; round++) {
      const Who & who = whos[rng.below(whos.size())];
      Q q;
      q.lang = rng.chance(75) ? "en" : "fr";
      static const char * sortable[] = {"title", "group", "rank", "embargo", "tags"};
      if (rng.chance(40)) {
        q.filter_field = sortable[rng.below(5)];
        q.filter_text = kTexts[rng.below(kNTexts)];
        if (q.filter_text.empty() && rng.chance(50)) {
          q.filter_text = "-";
        }
      }
      if (rng.chance(60)) {
        q.sort1 = sortable[rng.below(5)];
        q.desc1 = rng.chance(40);
        if (rng.chance(40)) {
          q.sort2 = sortable[rng.below(5)];
          q.desc2 = rng.chance(40);
        }
      }
      if (rng.chance(35)) {
        CondGen gen{rng, w, false};
        q.condition = gen.Node(2);
      }
      q.offset = rng.chance(50) ? 0 : rng.below(30);
      static const uint64_t limits[] = {0, 0, 1, 5, 20, 1000};
      q.limit = limits[rng.below(6)];
      /* A person's own request, or an agent acting for another person. */
      GDEFCORE_Request * req = rng.chance(85)
          ? site.Req(who.id, 5000)
          : site.Req(who.id, 5000, whos[rng.below(whos.size())].id);
      Listed got = List(site, req, q);
      Listed want = Reference(site, req, q);
      EXPECT_EQ(want.rc, got.rc) << "round " << round;
      EXPECT_EQ(want.ids, got.ids) << "backend " << backend << " round " << round
                                   << " role " << who.name << " cond [" << q.condition
                                   << "] filter " << q.filter_field << "=" << q.filter_text
                                   << " sort " << q.sort1 << "," << q.sort2
                                   << " offset " << q.offset << " limit " << q.limit;
      EXPECT_EQ(want.total, got.total) << "round " << round;
      if (want.rc == GDEFCORE_OK) {
        EXPECT_EQ("evaluated", want.how);
      }
      if (got.how == "planned") {
        planned += 1;
      }
      compared += 1;
      nonempty += want.ids.empty() ? 0 : 1;
      paged += (q.offset > 0 || q.limit > 0) && !want.ids.empty() ? 1 : 0;
      if (HasFailure()) {
        return;
      }
    }
  }
  EXPECT_EQ(360u * Backends().size(), compared);
  /* Almost every list is answered by the store: the sweep is of the compiled
   * list and not of the fallback agreeing with itself. */
  EXPECT_GE(planned, compared * 9 / 10);
  EXPECT_GE(nonempty, 100u * Backends().size());
  EXPECT_GE(paged, 50u * Backends().size());
}

TEST(ListPlan, CountCountsOnlyWhatIsVisible) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read three", "read", 0, "(= field.group \"yes\")"));
    site.Grant("seer", "Read three");
    std::string p = site.Principal("seer");
    for (int i = 0; i < 10; i++) {
      site.Make(kBlog, "", V({{"title", "t" + std::to_string(i)},
          {"group", i < 3 ? "yes" : "no"}}));
    }
    GDEFCORE_Request * r = site.Req(p);
    Q q;
    uint64_t total = 99;
    GDEFCORE_Access_List a = ToQuery(q);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(site.catalog, r, &a, &total));
    EXPECT_EQ(3u, total) << "backend " << backend;
    EXPECT_EQ("planned", HowAnswered(r));
    q.flags = GDEFCORE_ACCESS_LIST_EVALUATE;
    a = ToQuery(q);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(site.catalog, r, &a, &total));
    EXPECT_EQ(3u, total) << "backend " << backend;
    EXPECT_EQ("evaluated", HowAnswered(r));
    /* A page of one has the same total: three, never ten. */
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q page;
      page.flags = flags;
      page.limit = 1;
      page.offset = 1;
      Listed l = List(site, r, page);
      EXPECT_EQ(1u, l.ids.size());
      EXPECT_EQ(3u, l.total) << "flags " << flags;
    }
    /* Nothing granted: nothing counted. */
    std::string nobody = site.Principal();
    Q none;
    a = ToQuery(none);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(site.catalog, site.Req(nobody), &a, &total));
    EXPECT_EQ(0u, total);
  }
}

TEST(ListPlan, PagesAreSlicesOfTheEvaluatedList) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read open", "read", 0, "(= field.group \"open\")"));
    site.Grant("seer", "Read open");
    std::string p = site.Principal("seer");
    for (int i = 0; i < 250; i++) {
      site.Make(kBlog, "", V({{"title", "t" + std::to_string(i)}, {"group", "open"},
          {"rank", std::to_string(i % 7)}}));
    }
    for (int i = 0; i < 20; i++) {
      site.Make(kBlog, "", V({{"title", "x" + std::to_string(i)}, {"group", "shut"}}));
    }
    GDEFCORE_Request * r = site.Req(p);
    Q whole;
    whole.sort1 = "rank";
    Listed all = Reference(site, r, whole);
    ASSERT_EQ(250u, all.ids.size());
    EXPECT_EQ(250u, all.total);
    std::vector<std::string> joined;
    for (uint64_t off = 0; off < 260; off += 20) {
      Q page = whole;
      page.offset = off;
      page.limit = 20;
      Listed got = List(site, r, page);
      Listed ref = Reference(site, r, page);
      EXPECT_EQ(250u, got.total) << "offset " << off;
      EXPECT_EQ(250u, ref.total);
      EXPECT_EQ(ref.ids, got.ids) << "offset " << off;
      std::vector<std::string> slice;
      for (uint64_t i = off; i < std::min<uint64_t>(off + 20, 250); i++) {
        slice.push_back(all.ids[i]);
      }
      EXPECT_EQ(slice, got.ids) << "backend " << backend << " offset " << off;
      joined.insert(joined.end(), got.ids.begin(), got.ids.end());
    }
    EXPECT_EQ(all.ids, joined);
    /* A page past the end is empty and the total stays. */
    Q past = whole;
    past.offset = 1000;
    past.limit = 20;
    Listed l = List(site, r, past);
    EXPECT_TRUE(l.ids.empty());
    EXPECT_EQ(250u, l.total);
  }
}

TEST(ListPlan, TheLimitIsClamped) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    const size_t n = GDEFCORE_ACCESS_LIST_MAX_LIMIT + 5;
    for (size_t i = 0; i < n; i++) {
      site.Make(kBlog, "", V({{"title", "t" + std::to_string(i)}}));
    }
    GDEFCORE_Request * r = site.Req(p);
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q q;
      q.flags = flags;
      q.limit = 1000000;
      Listed l = List(site, r, q);
      EXPECT_EQ((size_t)GDEFCORE_ACCESS_LIST_MAX_LIMIT, l.ids.size()) << "flags " << flags;
      EXPECT_EQ(n, l.total);
      q.limit = 0;
      l = List(site, r, q);
      EXPECT_EQ(n, l.ids.size()) << "flags " << flags;
    }
  }
}

TEST(ListPlan, TheLastTiebreakIsCreationOrder) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    std::vector<std::string> made;
    /* Enough entities that the row numbers they were made with pass 100, so
     * that the order of their decimal digits and their numeric order differ. */
    for (int i = 0; i < 130; i++) {
      made.push_back(site.Make(kBlog, "", V({{"title", "t" + std::to_string(i)},
          {"group", i % 2 ? "b" : "a"}})));
    }
    GDEFCORE_Request * r = site.Req(p);
    /* Equal keys come in the order the entities were created, not the order of
     * their row numbers' digits. */
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q q;
      q.flags = flags;
      q.sort1 = "group";
      Listed l = List(site, r, q);
      std::vector<std::string> want;
      for (size_t i = 0; i < made.size(); i += 2) {
        want.push_back(made[i]);
      }
      for (size_t i = 1; i < made.size(); i += 2) {
        want.push_back(made[i]);
      }
      EXPECT_EQ(want, l.ids) << "backend " << backend << " flags " << flags;
      q.desc1 = true;
      l = List(site, r, q);
      std::vector<std::string> rev;
      for (size_t i = 1; i < made.size(); i += 2) {
        rev.push_back(made[i]);
      }
      for (size_t i = 0; i < made.size(); i += 2) {
        rev.push_back(made[i]);
      }
      EXPECT_EQ(rev, l.ids) << "descending, backend " << backend << " flags " << flags;
      /* No sort at all is creation order. */
      Q none;
      none.flags = flags;
      EXPECT_EQ(made, List(site, r, none).ids);
    }
  }
}

TEST(ListPlan, NumericComparisonIsOnIntegersOnly) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read low", "read", 0, "(< field.rank 10)"));
    site.Grant("seer", "Read low");
    std::string p = site.Principal("seer");
    site.Make(kBlog, "", V({{"title", "seven"}, {"rank", "7"}}));
    site.Make(kBlog, "", V({{"title", "absent"}}));
    site.Make(kBlog, "", V({{"title", "padded"}, {"rank", "007"}}));
    site.Make(kBlog, "", V({{"title", "big"}, {"rank", "12"}}));
    site.Make(kBlog, "", V({{"title", "negative"}, {"rank", "-4"}}));
    GDEFCORE_Request * r = site.Req(p);
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q q;
      q.flags = flags;
      Listed l = List(site, r, q);
      EXPECT_EQ("seven,padded,negative", Titles(site, l.ids))
          << "backend " << backend << " flags " << flags;
      /* "007" is the integer 7, so equality with "7" holds too. */
      q.condition = "(= field.rank \"7\")";
      l = List(site, r, q);
      EXPECT_EQ("seven,padded", Titles(site, l.ids)) << "flags " << flags;
    }
    /* An integer field holds integers: text that is not one is refused at
     * the save, and so is a fraction. */
    for (const char * bad : {"abc", "7.5", ""}) {
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_entity_create(site.catalog, kBlog, strlen(kBlog), id, NULL));
      GDEFCORE_Changeset * cs = NULL;
      const char * texts[1] = {bad};
      size_t lens[1] = {strlen(bad)};
      GDEFCORE_Value v;
      memset(&v, 0, sizeof v);
      v.size = sizeof v;
      v.field = "rank";
      v.field_len = 4;
      v.texts = texts;
      v.text_lens = lens;
      v.count = 1;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(site.catalog, NULL, 0, &cs));
      EXPECT_EQ(GDEFCORE_ERR_INVALID,
          gdefcore_entity_save(cs, id, strlen(id), "en", 2, &v, 1))
          << bad;
      gdefcore_changeset_destroy(cs);
    }
    /* An ordering of a text field is refused when it is checked against the
     * type (access SPEC decision 12): as a grant, and as a list's condition.
     * Control: the same ordering of the integer field is taken. */
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        site.Declare("Read early titles", "read", 0, "(< field.title 10)"));
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        site.Declare("Read rank by title", "read", 0, "(= field.rank field.title)"));
    EXPECT_EQ(GDEFCORE_OK,
        site.Declare("Read rank below twelve", "read", 0, "(< field.rank 12)"));
    Q text_order;
    text_order.condition = "(< field.title 10)";
    EXPECT_EQ(GDEFCORE_ERR_INVALID, List(site, r, text_order).rc);
    GDEFCORE_Condition * cond = NULL;
    GDEFCORE_Condition_Error err;
    memset(&err, 0, sizeof err);
    err.size = sizeof err;
    const char * text = "(and true (>= field.group 3))";
    ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_parse(text, strlen(text), &cond, &err));
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_condition_validate(site.catalog, cond, kBlog, strlen(kBlog), &err));
    EXPECT_EQ(strstr(text, "field.group") - text, (ptrdiff_t)err.offset)
        << "the refusal points at the field";
    gdefcore_condition_free(cond);
  }
}

TEST(ListPlan, ConstantsAreMatchedLiterally) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    std::string big(4000, 'q');
    big[1999] = '\'';
    std::vector<std::string> evil = {"it's", "'; DROP TABLE defiant_record; --", "100%",
        "a_c", "back\\slash", "\"quoted\"", big, "\x01ctl", "?"};
    std::vector<std::string> ids;
    for (size_t i = 0; i < evil.size(); i++) {
      ids.push_back(site.Make(kBlog, "", V({{"title", "e" + std::to_string(i)},
          {"group", evil[i]}})));
    }
    site.Make(kBlog, "", V({{"title", "plain"}, {"group", "abc"}}));
    site.Make(kBlog, "", V({{"title", "wild"}, {"group", "100 percent"}}));
    GDEFCORE_Request * r = site.Req(p);
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      for (size_t i = 0; i < evil.size(); i++) {
        Q q;
        q.flags = flags;
        q.filter_field = "group";
        q.filter_text = evil[i];
        Listed l = List(site, r, q);
        ASSERT_EQ(GDEFCORE_OK, l.rc) << i;
        EXPECT_EQ(std::vector<std::string>{ids[i]}, l.ids)
            << "backend " << backend << " flags " << flags << " #" << i;
        EXPECT_EQ(1u, l.total);
      }
    }
    /* In a condition: the written forms with quotes and escapes. */
    struct { const char * text; const char * want; } conds[] = {
        {"(= field.group \"it's\")", "e0"},
        {"(= field.group \"100%\")", "e2"},
        {"(= field.group \"a_c\")", "e3"},
        {"(= field.group \"back\\\\slash\")", "e4"},
        {"(= field.group \"\\\"quoted\\\"\")", "e5"},
        {"(in field.group (\"it's\" \"a_c\" \"?\"))", "e0,e3,e8"},
        {"(= field.group \"abc\")", "plain"},
    };
    for (const auto & c : conds) {
      for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
        Q q;
        q.flags = flags;
        q.condition = c.text;
        Listed l = List(site, r, q);
        ASSERT_EQ(GDEFCORE_OK, l.rc) << c.text;
        EXPECT_EQ(c.want, Titles(site, l.ids)) << c.text << " flags " << flags;
      }
    }
    /* Every row is still there afterwards. */
    Q all;
    EXPECT_EQ(evil.size() + 2, List(site, r, all).ids.size());
    /* A NUL in a text value is refused at the save (every backend's text
     * column refuses it: Postgres cannot hold one). */
    {
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_entity_create(site.catalog, kBlog, strlen(kBlog), id, NULL));
      GDEFCORE_Changeset * cs = NULL;
      std::string nul("nul\0byte", 8);
      const char * texts[1] = {nul.data()};
      size_t lens[1] = {nul.size()};
      GDEFCORE_Value v;
      memset(&v, 0, sizeof v);
      v.size = sizeof v;
      v.field = "group";
      v.field_len = 5;
      v.texts = texts;
      v.text_lens = lens;
      v.count = 1;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(site.catalog, NULL, 0, &cs));
      EXPECT_EQ(GDEFCORE_ERR_INVALID,
          gdefcore_entity_save(cs, id, strlen(id), "en", 2, &v, 1));
      gdefcore_changeset_destroy(cs);
    }
  }
}

TEST(ListPlan, AnUnpublishedEntityIsNeverListed) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    site.Make(kBlog, "", V({{"title", "live"}}));
    site.Make(kBlog, "", V({{"title", "draft"}}), 1);
    site.Make(kBlog, "", V({{"title", "held"}}), 2);
    std::string gone = site.Make(kBlog, "", V({{"title", "gone"}}));
    site.Unpublish(gone);
    GDEFCORE_Request * r = site.Req(p);
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q q;
      q.flags = flags;
      Listed l = List(site, r, q);
      EXPECT_EQ("live", Titles(site, l.ids)) << "flags " << flags;
      EXPECT_EQ(1u, l.total);
      q.condition = "(= state \"draft\")";
      l = List(site, r, q);
      EXPECT_TRUE(l.ids.empty()) << "a condition on state does not widen the list";
      EXPECT_EQ(0u, l.total);
    }
  }
}

TEST(ListPlan, AListOfAnotherSizeIsRefusedAndTheFullOneListsAsItAlwaysDid) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    for (int i = 0; i < 6; i++) {
      site.Make(kBlog, "", V({{"title", "t" + std::to_string(i)}, {"group", i < 3 ? "a" : "b"}}));
    }
    GDEFCORE_Request * r = site.Req(p);
    /* A struct that ends at sort_field_len, as the first version did, is a
     * caller built against another definition: refused, not read as far as
     * it goes. */
    struct OldList {
      size_t size;
      const char * type_name;
      size_t type_name_len;
      const char * lang;
      size_t lang_len;
      const char * filter_field;
      size_t filter_field_len;
      const char * filter_text;
      size_t filter_text_len;
      const char * sort_field;
      size_t sort_field_len;
    } old;
    memset(&old, 0, sizeof old);
    old.size = sizeof old;
    char ** ids = NULL;
    size_t count = 0;
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_access_list(site.catalog, r, (const GDEFCORE_Access_List *)&old, &ids, &count));
    /* The control: the same list in the full struct. */
    GDEFCORE_Access_List q;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = kBlog;
    q.type_name_len = strlen(kBlog);
    q.lang = "en";
    q.lang_len = 2;
    q.filter_field = "group";
    q.filter_field_len = 5;
    q.filter_text = "b";
    q.filter_text_len = 1;
    q.sort_field = "title";
    q.sort_field_len = 5;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list(site.catalog, r, &q, &ids, &count));
    std::vector<std::string> got;
    for (size_t i = 0; i < count; i++) {
      got.push_back(ids[i]);
    }
    gdefcore_access_free(site.catalog, ids, count);
    EXPECT_EQ("t3,t4,t5", Titles(site, got));
    EXPECT_EQ("planned", HowAnswered(r));
  }
}

TEST(ListPlan, AFieldWithAFieldGrantIsDecidedEntityByEntity) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read rank", "read", GDEFCORE_ACCESS_ANY, "", kBlog, "rank"));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    site.Role("blind");
    site.Grant("blind", "Read all");
    std::string q2 = site.Principal("blind");
    for (int i = 0; i < 5; i++) {
      site.Make(kBlog, "", V({{"title", "t" + std::to_string(i)}, {"rank", std::to_string(5 - i)}}));
    }
    /* The reader of the title alone may not sort by rank, and is refused. */
    Q q;
    q.sort1 = "rank";
    Listed l = List(site, site.Req(q2), q);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, l.rc);
    EXPECT_TRUE(l.ids.empty());
    /* Not hidden from a principal who has a grant for it: sorted by rank, and
     * answered entity by entity because the field has a grant of its own. */
    site.Grant("seer", "Read rank");
    GDEFCORE_Request * r = site.Req(p);
    l = List(site, r, q);
    EXPECT_EQ(GDEFCORE_OK, l.rc);
    EXPECT_EQ("t4,t3,t2,t1,t0", Titles(site, l.ids)) << "backend " << backend;
    EXPECT_EQ("evaluated", l.how);
    /* A grant of one field is not a grant of the entity: with only that, the
     * list is empty, whichever way it is answered. */
    site.Role("fieldonly");
    site.Grant("fieldonly", "Read rank");
    GDEFCORE_Request * fo = site.Req(site.Principal("fieldonly"));
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q none;
      none.flags = flags;
      Listed ln = List(site, fo, none);
      EXPECT_EQ(GDEFCORE_OK, ln.rc);
      EXPECT_TRUE(ln.ids.empty()) << "flags " << flags;
      EXPECT_EQ(0u, ln.total);
    }
    /* The condition may name only what the principal may read, too. */
    Q c;
    c.condition = "(< field.rank 3)";
    l = List(site, site.Req(q2), c);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, l.rc);
    l = List(site, r, c);
    EXPECT_EQ(GDEFCORE_OK, l.rc);
    EXPECT_EQ("t3,t4", Titles(site, l.ids));
  }
}

TEST(ListPlan, APlanThatCannotBePromisedIsEvaluatedInstead) {
  /* A catalog that lets a field hold more than 64 values: the evaluator fails
   * on such a field and the stored document does not say how many a save was
   * allowed, so the plan declines and the list is the evaluated one. */
  GDEFCORE_Limits limits;
  gdefcore_limits_default(&limits);
  limits.max_values = 100;
  for (int backend : Backends()) {
    Site site(backend, &limits);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read tagged", "read", 0, "(= field.tags \"x\")"));
    site.Grant("seer", "Read tagged");
    std::string p = site.Principal("seer");
    std::vector<std::string> many;
    for (int i = 0; i < 70; i++) {
      many.push_back(i == 3 ? "x" : "y" + std::to_string(i));
    }
    Vals v;
    v.push_back({"title", {"overfull"}});
    v.push_back({"tags", many});
    site.Make(kBlog, "", v);
    site.Make(kBlog, "", {{"title", {"fits"}}, {"tags", {"x", "z"}}});
    GDEFCORE_Request * r = site.Req(p);
    Q q;
    Listed l = List(site, r, q);
    EXPECT_EQ("fits", Titles(site, l.ids)) << "an entity the evaluator fails on is not listed";
    EXPECT_EQ("evaluated", l.how);
    EXPECT_EQ(l.ids, Reference(site, r, q).ids);
  }
}

TEST(ListPlan, AnAgentIsHeldToTheCeilingInTheCompiledList) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("wide");
    site.Role("narrow");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read a", "read", 0, "(= field.group \"a\")"));
    site.Grant("wide", "Read all");
    site.Grant("narrow", "Read a");
    std::string person = site.Principal("narrow");
    std::string agent = site.Principal("wide");
    for (int i = 0; i < 6; i++) {
      site.Make(kBlog, "", V({{"title", "t" + std::to_string(i)}, {"group", i < 2 ? "a" : "b"}}));
    }
    /* The agent alone sees everything; acting for the person it sees what
     * both may. */
    Q q;
    EXPECT_EQ("t0,t1,t2,t3,t4,t5", Titles(site, List(site, site.Req(agent), q).ids));
    GDEFCORE_Request * acting = site.Req(agent, 5000, person);
    Listed l = List(site, acting, q);
    Listed ref = Reference(site, acting, q);
    EXPECT_EQ(ref.ids, l.ids);
    EXPECT_EQ(ref.total, l.total);
    EXPECT_EQ("planned", l.how);
    EXPECT_LE(l.ids.size(), 6u);
  }
}

/* The compiled list is a query of the port's entities (story S6b): the
 * current tables, in the plan's language, with the published fact and the
 * creator the entity record holds. Asked here straight of the port, beside
 * the list, so a list that read anything else would disagree. */
TEST(ListPlan, TheQueryIsOfThePortsCurrentTables) {
  for (int backend : Backends()) {
    Site site(backend);
    const std::string alice = site.Principal();
    std::string id = site.Make(kBlog, alice, V({{"title", "T"}, {"rank", "3"}}));
    site.Make(kBlog, "", V({{"title", "U"}, {"rank", "4"}}));
    GDEFCORE_Plan * plan = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_plan_create(site.catalog, kBlog, strlen(kBlog),
                               "en", 2, alice.data(), alice.size(), 0, &plan));
    const GDEFSTOR_QueryNode * kids[2] = {gdefcore_plan_published(plan),
        gdefcore_plan_creator_is_principal(plan)};
    const GDEFSTOR_QueryNode * where = gdefcore_plan_and(plan, kids, 2);
    ASSERT_TRUE(where != NULL);
    GDEFSTOR_Query q;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.where = where;
    q.language = "en";
    q.language_len = 2;
    GDEFSTOR_QueryResult * r = NULL;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_entity_query(site.store, "t", 1, kBlog,
                               strlen(kBlog), &q, &r));
    ASSERT_EQ(1u, gdefstor_query_result_rows(r));
    const char * entity = NULL;
    size_t en = 0;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_query_result_entity(r, 0, &entity, &en));
    EXPECT_EQ(id, std::string(entity, en));
    gdefstor_query_result_free(r);
    /* The sort key is the field's typed value: rank 4 after rank 3. */
    const GDEFSTOR_QuerySort * sort = gdefcore_plan_sort_field(plan, "rank", 4, 1);
    ASSERT_TRUE(sort != NULL);
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.sorts = sort;
    q.sort_count = 1;
    q.language = "en";
    q.language_len = 2;
    char ** ids = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_query_current(site.catalog, kBlog, strlen(kBlog), &q, &ids,
            &n, NULL));
    EXPECT_EQ("U,T", Titles(site, std::vector<std::string>(ids, ids + n)));
    gdefcore_ids_free(site.catalog, ids, n);
    gdefcore_plan_free(plan);
  }
}

/* A list reads the newest revision and nothing older: an entity whose group
 * was "old" and is "new" is listed by "new" alone, by the store and by the
 * entity-by-entity reference, in its filter, its condition and its sort. */
TEST(ListPlan, AListReadsOnlyTheCurrentRevision) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    std::string moved = site.Make(kBlog, "", V({{"title", "moved"}, {"group", "old"}}));
    site.Save(moved, "", V({{"group", "new"}}));
    site.Make(kBlog, "", V({{"title", "stays"}, {"group", "old"}}));
    GDEFCORE_Request * r = site.Req(p);
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q q;
      q.flags = flags;
      q.filter_field = "group";
      q.filter_text = "old";
      EXPECT_EQ("stays", Titles(site, List(site, r, q).ids))
          << "backend " << backend << " flags " << flags;
      q.filter_text = "new";
      EXPECT_EQ("moved", Titles(site, List(site, r, q).ids)) << "flags " << flags;
      Q c;
      c.flags = flags;
      c.condition = "(= field.group \"old\")";
      EXPECT_EQ("stays", Titles(site, List(site, r, c).ids)) << "flags " << flags;
      Q s;
      s.flags = flags;
      s.sort1 = "group";
      EXPECT_EQ("moved,stays", Titles(site, List(site, r, s).ids)) << "flags " << flags;
    }
  }
}

/* A draft is never in a list: not as an entity (one never saved is in none),
 * and not as content (the draft over a published entity is not what its
 * filter, condition or sort read). */
TEST(ListPlan, ADraftIsNeverInAList) {
  for (int backend : Backends()) {
    Site site(backend);
    site.Role("seer");
    ASSERT_EQ(GDEFCORE_OK, site.Declare("Read all", "read", GDEFCORE_ACCESS_ANY, ""));
    site.Grant("seer", "Read all");
    std::string p = site.Principal("seer");
    std::string pub = site.Make(kBlog, "", V({{"title", "pub"}, {"group", "b"}}));
    site.Save(pub, "", V({{"group", "a"}}), 1);   /* a draft over it */
    site.Make(kBlog, "", V({{"title", "only"}, {"group", "a"}}), 1);
    site.Make(kBlog, "", V({{"title", "other"}, {"group", "c"}}));
    GDEFCORE_Request * r = site.Req(p);
    for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
      Q all;
      all.flags = flags;
      Listed l = List(site, r, all);
      EXPECT_EQ("pub,other", Titles(site, l.ids)) << "backend " << backend
                                                  << " flags " << flags;
      EXPECT_EQ(2u, l.total);
      Q f;
      f.flags = flags;
      f.filter_field = "group";
      f.filter_text = "a";
      EXPECT_TRUE(List(site, r, f).ids.empty()) << "flags " << flags;
      Q c;
      c.flags = flags;
      c.condition = "(= field.group \"a\")";
      EXPECT_TRUE(List(site, r, c).ids.empty()) << "flags " << flags;
      Q s;
      s.flags = flags;
      s.sort1 = "group";
      s.desc1 = true;
      EXPECT_EQ("other,pub", Titles(site, List(site, r, s).ids)) << "flags " << flags;
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
