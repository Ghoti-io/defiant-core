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
 * Core's list, count and create at 10,000 entities of one type on SQLite
 * (story S6b) and on Postgres (story S10), measured in rows and steps, never
 * in time.
 *
 * The same three calls are measured twice on one store: when it holds 1,000
 * entities of the type and when it holds 10,000. The filtered list and the
 * count have the same answer both times (the ten entities of group "g7" are
 * all among the first thousand), and a create is one entity either way, so a
 * call whose cost followed the table would cost about ten times as much the
 * second time. Each must instead take no more full-scan steps than it did at
 * 1,000 (a scan of the type's table would add 9,000), build no automatic
 * index, and take virtual-machine steps within a quarter of its cost at
 * 1,000. The cost of the grants, the type records and the counters that every
 * call also reads is the same at both sizes and so drops out. The control is
 * the same list filtered on a field nothing indexes ("note", which holds the
 * group): its cost must grow with the table, or the instrument cannot see a
 * scan.
 *
 * The same calls on Postgres (story S10), when GDEFCORE_TEST_SCALE=postgres
 * (make test-scale-postgres, through defiant-storage-postgres's
 * tools/pg-test.sh): suite ScalePostgres. Postgres has no step counter, so
 * the instrument is the server's own account of each statement the call ran.
 * Every statement the store executed is run again on a connection of the
 * test's own, with the parameters it ran with, under `EXPLAIN (ANALYZE)`
 * inside a transaction that is rolled back (a read), or under plain `EXPLAIN`
 * (a write, which must not run twice). The cost is the rows every scan node
 * read - the rows it returned and the rows its filter removed, times its
 * loops - and the number of sequential scans of a type's tables. A list, a
 * count and a create at 10,000 must read no more rows than at 1,000 (plus a
 * quarter and 100: the planner may change its plan between sizes) and plan
 * no more sequential scans of a type's table; the control (the unindexed
 * filter) must read at least 9,000 more. What is measured is the plan
 * Postgres chooses for each statement with its parameters, as a fresh plan:
 * the store's own connection may have kept a generic plan for a prepared
 * statement, which this does not see. The tables are analysed after each
 * load, as autovacuum would in time. Each measurement is printed, with its
 * figures at both sizes.
 *
 * GDEFCORE_SCALE_N sets another size for looking at costs by hand (the bounds
 * do not depend on it); GDEFCORE_SCALE_VERBOSE prints each measurement.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-sqlite/model.h>
#ifdef GDEFCORE_TEST_HAVE_PQ
#include <ghoti.io/defiant-storage-postgres/model.h>
#include <libpq-fe.h>
#include <unistd.h>
#endif

#include <gtest/gtest.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <filesystem>
#include <functional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace {

const char kItem[] = "t.item";
const uint8_t kTenant[] = {'t'};

size_t Size() {
  const char * e = getenv("GDEFCORE_SCALE_N");
  return e != NULL && atoi(e) > 1000 ? (size_t)atoi(e) : 10000;
}

struct Cost {
  uint64_t vm = 0;
  uint64_t fullscan = 0;
  uint64_t autoindex = 0;
  uint64_t statements = 0;
  /* Postgres: rows the scan nodes read, and sequential scans of a type's
   * tables. */
  uint64_t rows = 0;
  uint64_t seqscans = 0;
};

Cost g_cost;
bool g_counting = false;

bool PostgresArm() {
  const char * v = getenv("GDEFCORE_TEST_SCALE");
  return v != NULL && strcmp(v, "postgres") == 0;
}

void OnStatement(void *, const GDEFSSQLITE_StatementStats * s) {
  if (!g_counting || s->exec) {
    return;
  }
  g_cost.vm += s->vm_steps;
  g_cost.fullscan += s->fullscan_steps;
  g_cost.autoindex += s->autoindexes;
  g_cost.statements += 1;
}

Cost Measure(const std::function<void()> & call) {
  g_cost = Cost();
  g_counting = true;
  call();
  g_counting = false;
  return g_cost;
}

/* One store, grown from 1,000 entities to Size(), with the costs of each
 * call measured at both sizes. Built once for the suite. */
struct World {
  std::string dir;
  std::string prefix; /* Postgres: the schemas' prefix */
  std::function<Cost(const std::function<void()> &)> measure = Measure;
  std::function<void()> settle = []() {};
  int group_index = -1; /* GDEFSTOR_IndexState of "group" when measured */
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  std::string reader;
  size_t made = 0;
  Cost list_small, list_big;
  Cost count_small, count_big;
  Cost create_small, create_big;
  Cost scan_small, scan_big;
  std::vector<std::string> list_small_ids, list_big_ids;
  uint64_t total_small = 0, total_big = 0;
  uint64_t count_small_n = 0, count_big_n = 0;
  bool ok = false;

  std::function<void()> drop = []() {};

  ~World() {
    gdefcore_catalog_destroy(catalog);
    gdefstor_store_destroy(store);
    drop();
    if (!dir.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(dir, ec);
    }
  }
};

World * g_world = NULL;

std::string GroupOf(size_t i) {
  /* Ten entities in each of g0..g99 among the first thousand; the rest are
   * in h0..h99, so a filter on a g group has the same answer at any size. */
  return (i < 1000 ? "g" : "h") + std::to_string(i % 100);
}

bool MakeEntities(World * w, size_t upto) {
  while (w->made < upto) {
    size_t batch = upto - w->made < 100 ? upto - w->made : 100;
    std::vector<std::string> ids;
    for (size_t k = 0; k < batch; k++) {
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      if (gdefcore_entity_create(w->catalog, kItem, strlen(kItem), id, NULL) !=
          GDEFCORE_OK) {
        return false;
      }
      ids.push_back(id);
    }
    GDEFCORE_Changeset * cs = NULL;
    if (gdefcore_changeset_prepare(w->catalog, NULL, 0, &cs) != GDEFCORE_OK) {
      return false;
    }
    for (size_t k = 0; k < batch; k++) {
      size_t i = w->made + k;
      std::string title = "item " + std::to_string(i);
      std::string group = GroupOf(i);
      std::string rank = std::to_string(i % 37);
      const char * texts[4] = {title.c_str(), group.c_str(), rank.c_str(),
          group.c_str()};
      size_t lens[4] = {title.size(), group.size(), rank.size(), group.size()};
      const char * names[4] = {"title", "group", "rank", "note"};
      GDEFCORE_Value values[4];
      memset(values, 0, sizeof values);
      for (int f = 0; f < 4; f++) {
        values[f].size = sizeof values[f];
        values[f].field = names[f];
        values[f].field_len = strlen(names[f]);
        values[f].texts = &texts[f];
        values[f].text_lens = &lens[f];
        values[f].count = 1;
      }
      if (gdefcore_entity_save(cs, ids[k].c_str(), ids[k].size(), "en", 2, values,
              4) != GDEFCORE_OK) {
        gdefcore_changeset_destroy(cs);
        return false;
      }
    }
    GDEFCORE_Result rc = gdefcore_changeset_apply(cs, NULL, 0);
    gdefcore_changeset_destroy(cs);
    if (rc != GDEFCORE_OK) {
      return false;
    }
    w->made += batch;
  }
  return true;
}

GDEFCORE_Request * NewRequest(const std::string & principal) {
  GDEFCORE_Request * r = NULL;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_request_create(kTenant, 1, 0, 0, NULL, &r));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(r, principal.data(), principal.size()));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_time(r, 5000));
  return r;
}

GDEFCORE_Access_List FilteredPage() {
  GDEFCORE_Access_List q;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.type_name = kItem;
  q.type_name_len = strlen(kItem);
  q.lang = "en";
  q.lang_len = 2;
  q.filter_field = "group";
  q.filter_field_len = 5;
  q.filter_text = "g7";
  q.filter_text_len = 2;
  q.limit = 20;
  return q;
}

void MeasureAt(World * w, Cost * list, std::vector<std::string> * ids,
    uint64_t * total, Cost * count, uint64_t * counted, Cost * create,
    Cost * scan) {
  GDEFCORE_Request * r = NewRequest(w->reader);
  GDEFCORE_Access_List q = FilteredPage();
  const std::function<Cost(const std::function<void()> &)> & meter =
      w->measure;
  w->settle();
  w->group_index = -1;
  EXPECT_EQ(GDEFSTOR_OK, gdefstor_type_index_state(w->store,
      reinterpret_cast<const char *>(kTenant), 1, kItem,
      strlen(kItem), "group", 5, &w->group_index));
  /* Once unmeasured, so that what the first call sets up is not counted. */
  {
    char ** got = NULL;
    size_t n = 0;
    uint64_t t = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_list_page(w->catalog, r, &q, &got, &n, &t));
    gdefcore_access_free(w->catalog, got, n);
  }
  *list = meter([&]() {
    char ** got = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_list_page(w->catalog, r, &q, &got, &n, total));
    for (size_t i = 0; i < n; i++) {
      ids->push_back(got[i]);
    }
    gdefcore_access_free(w->catalog, got, n);
  });
  size_t note_n = 0;
  const char * how = gdefcore_request_note(r, "defiant.access.list", 19, &note_n);
  EXPECT_EQ("planned", std::string(how == NULL ? "" : how, note_n))
      << "the list is answered by the store";
  *count = meter([&]() {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(w->catalog, r, &q, counted));
  });
  {
    GDEFCORE_Access_List unindexed = q;
    unindexed.filter_field = "note";
    unindexed.filter_field_len = 4;
    *scan = meter([&]() {
      char ** got = NULL;
      size_t n = 0;
      uint64_t t = 0;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_access_list_page(w->catalog, r, &unindexed, &got, &n, &t));
      EXPECT_EQ(10u, t);
      gdefcore_access_free(w->catalog, got, n);
    });
  }
  *create = meter([&]() { ASSERT_TRUE(MakeEntities(w, w->made + 1)); });
  gdefcore_request_destroy(r);
}

/* The SQLite store, in a scratch directory, counted by OnStatement. */
bool OpenSqlite(World * w) {
  std::error_code ec;
  std::filesystem::path base = std::filesystem::temp_directory_path(ec);
  std::random_device entropy;
  for (int i = 0; i < 100 && w->dir.empty(); i++) {
    std::filesystem::path p = base / ("gdefcore-scale-" + std::to_string(entropy()));
    if (std::filesystem::create_directory(p, ec) && !ec) {
      w->dir = p.string();
    }
  }
  if (w->dir.empty()) {
    return false;
  }
  GDEFSSQLITE_ModelOptions o;
  gdefssqlite_model_options_default(&o);
  o.synchronous = GDEFSSQLITE_SYNC_OFF; /* the subject is rows, not the disk */
  o.on_statement = OnStatement;
  return gdefssqlite_model_store_create(w->dir.c_str(), &o, NULL, NULL,
             &w->store) == GDEFSSQLITE_OK;
}

/* ---- Postgres ------------------------------------------------------------ */

#ifdef GDEFCORE_TEST_HAVE_PQ

/* One statement the store ran: its text, parameters in the text format, and
 * whether it was the executor's exec (DDL, transaction statements). */
struct PgStatement {
  std::string sql;
  std::vector<std::string> params;
  bool exec = false;
};

std::vector<PgStatement> g_pg_statements;
bool g_pg_recording = false;

std::string DatumText(const GDEFSSQL_Datum & d) {
  char b[64];
  switch (d.kind) {
  case GDEFSSQL_DATUM_INT:
    snprintf(b, sizeof b, "%lld", (long long)d.integer);
    return b;
  case GDEFSSQL_DATUM_REAL:
    snprintf(b, sizeof b, "%.17g", d.real);
    return b;
  case GDEFSSQL_DATUM_TEXT:
    return std::string(reinterpret_cast<const char *>(d.bytes), d.len);
  default: {
    std::string h = "\\x";
    for (size_t i = 0; i < d.len; i++) {
      snprintf(b, sizeof b, "%02x", d.bytes[i]);
      h += b;
    }
    return h;
  }
  }
}

void OnPgStatement(void *, const GDEFSPG_StatementStats * s) {
  if (!g_pg_recording || s->keys) {
    return;
  }
  PgStatement st;
  st.sql.assign(s->sql, s->sql_len);
  st.exec = s->exec != 0;
  for (size_t i = 0; i < s->bind_count; i++) {
    st.params.push_back(DatumText(s->binds[i]));
  }
  g_pg_statements.push_back(st);
}

/* The test's own connection to the server, apart from the store's. */
struct PgSide {
  PGconn * c = NULL;
  PgSide() {
    const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
    c = PQconnectdb(ci == NULL ? "" : ci);
    if (Ok()) {
      PQclear(PQexec(c, "SET client_min_messages TO warning"));
    }
  }
  ~PgSide() {
    if (c != NULL) {
      PQfinish(c);
    }
  }
  PgSide(const PgSide &) = delete;
  PgSide & operator=(const PgSide &) = delete;
  bool Ok() const { return c != NULL && PQstatus(c) == CONNECTION_OK; }
  /* The first column of every row; an error is a test failure naming it. */
  std::vector<std::string> Rows(const std::string & sql,
      const std::vector<std::string> & params = {}) {
    std::vector<std::string> out;
    std::vector<const char *> v;
    for (const std::string & p : params) {
      v.push_back(p.c_str());
    }
    PGresult * r = PQexecParams(c, sql.c_str(), (int)v.size(), NULL,
        v.empty() ? NULL : v.data(), NULL, NULL, 0);
    ExecStatusType st = PQresultStatus(r);
    if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
      ADD_FAILURE() << "the test's statement failed: " << PQresultErrorMessage(r)
                    << "in: " << sql;
    } else {
      for (int i = 0; i < PQntuples(r); i++) {
        out.push_back(PQgetisnull(r, i, 0) ? "" : PQgetvalue(r, i, 0));
      }
    }
    PQclear(r);
    return out;
  }
  void Exec(const char * sql) { Rows(sql); }
};

PgSide * g_side = NULL;

/* The cost of one plan, read from EXPLAIN's text: the rows each scan node
 * read (returned, plus removed by its filter or recheck, each a per-loop
 * figure, times the loops) and the sequential scans of a type's table. */
void AddPlan(const std::vector<std::string> & lines, bool analyzed, Cost * c) {
  static const char * const scans[] = {"Seq Scan", "Parallel Seq Scan",
      "Index Scan", "Index Only Scan", "Parallel Index Scan",
      "Parallel Index Only Scan", "Bitmap Heap Scan",
      "Parallel Bitmap Heap Scan", "Tid Scan", "Tid Range Scan", "Sample Scan"};
  double loops = 0;
  bool in_scan = false;
  for (const std::string & raw : lines) {
    std::string l = raw;
    size_t at = l.find_first_not_of(' ');
    l = at == std::string::npos ? "" : l.substr(at);
    bool node = false;
    if (l.rfind("->  ", 0) == 0) {
      l = l.substr(4);
      node = true;
    } else if (&raw == &lines[0]) {
      node = true;
    }
    if (node) {
      in_scan = false;
      for (const char * k : scans) {
        if (l.rfind(k, 0) == 0) {
          in_scan = true;
        }
      }
      if ((l.rfind("Seq Scan on ", 0) == 0 ||
              l.rfind("Parallel Seq Scan on ", 0) == 0)) {
        /* "Seq Scan on t3_c0 ...": a type's table is t<number>_... */
        size_t on = l.find(" on ") + 4;
        if (on < l.size() && l[on] == 't' && on + 1 < l.size() &&
            isdigit((unsigned char)l[on + 1])) {
          c->seqscans += 1;
        }
      }
      loops = 0;
      if (in_scan && analyzed) {
        size_t r = l.find("actual rows=");
        size_t lp = l.find(" loops=");
        if (r != std::string::npos && lp != std::string::npos) {
          loops = strtod(l.c_str() + lp + 7, NULL);
          c->rows += (uint64_t)(strtod(l.c_str() + r + 12, NULL) * loops + 0.5);
        }
      }
      continue;
    }
    if (in_scan && analyzed) {
      for (const char * k : {"Rows Removed by Filter: ",
               "Rows Removed by Index Recheck: "}) {
        if (l.rfind(k, 0) == 0) {
          c->rows += (uint64_t)(strtod(l.c_str() + strlen(k), NULL) * loops + 0.5);
        }
      }
    }
  }
}

/* Every statement recorded during @p call, explained on the side
 * connection. */
Cost MeasurePg(const std::function<void()> & call) {
  g_pg_statements.clear();
  g_pg_recording = true;
  call();
  g_pg_recording = false;
  Cost c;
  for (const PgStatement & st : g_pg_statements) {
    if (st.exec) {
      continue;
    }
    bool read = st.sql.rfind("SELECT", 0) == 0;
    std::vector<std::string> plan;
    if (read) {
      g_side->Exec("BEGIN");
      plan = g_side->Rows(
          "EXPLAIN (ANALYZE, TIMING OFF, COSTS OFF, SUMMARY OFF) " + st.sql,
          st.params);
      g_side->Exec("ROLLBACK");
    } else {
      plan = g_side->Rows("EXPLAIN (COSTS OFF) " + st.sql, st.params);
    }
    EXPECT_FALSE(plan.empty()) << "no plan for: " << st.sql;
    if (getenv("GDEFCORE_SCALE_VERBOSE") != NULL) {
      printf("%s\n", st.sql.c_str());
      for (const std::string & l : plan) {
        printf("  %s\n", l.c_str());
      }
    }
    AddPlan(plan, read, &c);
    c.statements += 1;
  }
  g_pg_statements.clear();
  return c;
}

bool OpenPostgres(World * w) {
  const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
  if (ci == NULL || ci[0] == '\0' || g_side == NULL || !g_side->Ok()) {
    return false;
  }
  char buf[32];
  snprintf(buf, sizeof buf, "sc%x_", (unsigned)getpid() & 0xfffffu);
  w->prefix = buf;
  GDEFSPG_Options o;
  gdefspg_options_default(&o);
  o.conninfo = ci;
  o.schema_prefix = w->prefix.c_str();
  o.on_statement = OnPgStatement;
  if (gdefspg_model_store_create(&o, NULL, NULL, &w->store) != GDEFSPG_OK) {
    return false;
  }
  w->measure = MeasurePg;
  std::string like = w->prefix + "%";
  /* What autovacuum would have done by the time anyone lists. */
  w->settle = [like]() {
    for (const std::string & t : g_side->Rows("SELECT format('%I.%I', "
             "schemaname, tablename) FROM pg_tables WHERE schemaname LIKE $1",
             {like})) {
      g_side->Exec(("ANALYZE " + t).c_str());
    }
  };
  w->drop = [like]() {
    for (const std::string & n : g_side->Rows("SELECT quote_ident(nspname) "
             "FROM pg_namespace WHERE nspname LIKE $1", {like})) {
      g_side->Exec(("DROP SCHEMA " + n + " CASCADE").c_str());
    }
  };
  return true;
}

#else

bool OpenPostgres(World *) {
  return false;
}

#endif


World * Build(bool postgres) {
  World * w = new World();
  if (!(postgres ? OpenPostgres(w) : OpenSqlite(w)) ||
      gdefcore_catalog_open(w->store, kTenant, 1, NULL, NULL, &w->catalog) !=
          GDEFCORE_OK) {
    return w;
  }
  GDEFCORE_Field f[4];
  memset(f, 0, sizeof f);
  const char * names[4] = {"title", "group", "rank", "note"};
  for (int i = 0; i < 4; i++) {
    f[i].size = sizeof f[i];
    f[i].name = names[i];
    f[i].name_len = strlen(names[i]);
    f[i].indexed = i < 3;
  }
  f[2].type = GDEFSTOR_FIELD_INTEGER;
  if (gdefcore_type_define(w->catalog, kItem, strlen(kItem),
          GDEFCORE_TYPE_CONTENT, f, 4) != GDEFCORE_OK ||
      gdefcore_access_role_create(w->catalog, "readers", 7, NULL) != GDEFCORE_OK) {
    return w;
  }
  GDEFCORE_Permission p;
  memset(&p, 0, sizeof p);
  p.size = sizeof p;
  p.label = "Read items";
  p.label_len = strlen(p.label);
  p.module_name = "scale";
  p.module_name_len = 5;
  p.action = "read";
  p.action_len = 4;
  p.condition = GDEFCORE_ACCESS_ANY;
  p.type_name = kItem;
  p.type_name_len = strlen(kItem);
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  if (gdefcore_access_declare(w->catalog, &p) != GDEFCORE_OK ||
      gdefcore_access_grant(w->catalog, "readers", 7, p.label, p.label_len,
          "core.role", 9) != GDEFCORE_OK ||
      gdefcore_access_principal_create(w->catalog, id) != GDEFCORE_OK ||
      gdefcore_access_principal_add_role(w->catalog, id, strlen(id), "readers",
          7) != GDEFCORE_OK) {
    return w;
  }
  w->reader = id;
  if (!MakeEntities(w, 1000)) {
    return w;
  }
  MeasureAt(w, &w->list_small, &w->list_small_ids, &w->total_small,
      &w->count_small, &w->count_small_n, &w->create_small, &w->scan_small);
  if (!MakeEntities(w, Size())) {
    return w;
  }
  MeasureAt(w, &w->list_big, &w->list_big_ids, &w->total_big, &w->count_big,
      &w->count_big_n, &w->create_big, &w->scan_big);
  w->ok = true;
  return w;
}

class Scale : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (g_world == NULL && !PostgresArm()) {
      g_world = Build(false);
    }
  }
  static void TearDownTestSuite() {
    delete g_world;
    g_world = NULL;
  }
  void SetUp() override {
    if (PostgresArm()) {
      GTEST_SKIP() << "the SQLite suite; GDEFCORE_TEST_SCALE=postgres runs "
                      "ScalePostgres";
    }
    ASSERT_TRUE(g_world != NULL && g_world->ok) << "the store was not built";
  }

  /* A call at the large size against the same call at 1,000. */
  static void ExpectFlat(const Cost & small, const Cost & big, const char * what) {
    if (getenv("GDEFCORE_SCALE_VERBOSE") != NULL) {
      printf("%s: vm %llu -> %llu, fullscan %llu -> %llu, %llu -> %llu statements\n",
          what, (unsigned long long)small.vm, (unsigned long long)big.vm,
          (unsigned long long)small.fullscan, (unsigned long long)big.fullscan,
          (unsigned long long)small.statements, (unsigned long long)big.statements);
    }
    EXPECT_GT(small.statements, 0u) << what << ": nothing was measured";
    EXPECT_LE(big.fullscan, small.fullscan)
        << what << " scanned more rows at the large size: " << small.fullscan
        << " -> " << big.fullscan;
    EXPECT_EQ(0u, big.autoindex) << what << " built an index";
    EXPECT_LE(big.vm, small.vm + small.vm / 4)
        << what << " took steps that grew with the table: " << small.vm << " -> "
        << big.vm;
  }
};

}  // namespace

TEST_F(Scale, AFilteredListPageReadsItsAnswerNotTheTable) {
  EXPECT_EQ(10u, g_world->total_small);
  EXPECT_EQ(10u, g_world->total_big);
  EXPECT_EQ(g_world->list_small_ids, g_world->list_big_ids);
  EXPECT_EQ(10u, g_world->list_big_ids.size());
  ExpectFlat(g_world->list_small, g_world->list_big, "a filtered list page");
}

TEST_F(Scale, ACountReadsItsAnswerNotTheTable) {
  EXPECT_EQ(10u, g_world->count_small_n);
  EXPECT_EQ(10u, g_world->count_big_n);
  ExpectFlat(g_world->count_small, g_world->count_big, "a filtered count");
}

/* The control: a filter on a field nothing indexes reads the table, and the
 * measurement sees it grow. */
TEST_F(Scale, AnUnindexedFilterReadsTheTableAndIsSeenTo) {
  if (getenv("GDEFCORE_SCALE_VERBOSE") != NULL) {
    printf("an unindexed filter: vm %llu -> %llu, fullscan %llu -> %llu\n",
        (unsigned long long)g_world->scan_small.vm,
        (unsigned long long)g_world->scan_big.vm,
        (unsigned long long)g_world->scan_small.fullscan,
        (unsigned long long)g_world->scan_big.fullscan);
  }
  const uint64_t grown = (uint64_t)(Size() - 1000);
  EXPECT_GE(g_world->scan_big.vm, g_world->scan_small.vm + grown)
      << "a scan of the table did not show in the steps";
}

TEST_F(Scale, CreatingOneMoreEntityCostsWhatItDidAtAThousand) {
  EXPECT_GE(g_world->made, Size());
  ExpectFlat(g_world->create_small, g_world->create_big, "creating one entity");
}

/* ---- the same on Postgres ---------------------------------------------- */

namespace {

World * g_pg_world = NULL;

class ScalePostgres : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
#ifdef GDEFCORE_TEST_HAVE_PQ
    if (g_pg_world == NULL && PostgresArm()) {
      g_side = new PgSide();
      g_pg_world = Build(true);
    }
#endif
  }
  static void TearDownTestSuite() {
    delete g_pg_world;
    g_pg_world = NULL;
#ifdef GDEFCORE_TEST_HAVE_PQ
    delete g_side;
    g_side = NULL;
#endif
  }
  void SetUp() override {
    if (!PostgresArm()) {
      GTEST_SKIP() << "the Postgres arm is make test-scale-postgres "
                      "(GDEFCORE_TEST_SCALE=postgres)";
    }
    ASSERT_TRUE(g_pg_world != NULL && g_pg_world->ok)
        << "the store was not built";
  }

  /* Always printed: the figures are the evidence, and four lines. */
  static void Print(const char * what, const Cost & small, const Cost & big) {
    printf("%s: rows read %llu -> %llu, seq scans of a type's table %llu -> "
           "%llu, %llu -> %llu statements\n",
        what, (unsigned long long)small.rows, (unsigned long long)big.rows,
        (unsigned long long)small.seqscans, (unsigned long long)big.seqscans,
        (unsigned long long)small.statements,
        (unsigned long long)big.statements);
  }

  /* A call at the large size against the same call at 1,000: no more rows
   * read than then (a quarter and 100 of slack, since the planner may pick
   * another plan for the larger table) and no more sequential scans of a
   * type's table. A scan of the type adds 9,000 rows. */
  static void ExpectFlat(const Cost & small, const Cost & big, const char * what) {
    Print(what, small, big);
    EXPECT_GT(small.statements, 0u) << what << ": nothing was measured";
    EXPECT_LE(big.rows, small.rows + small.rows / 4 + 100)
        << what << " read rows that grew with the table: " << small.rows
        << " -> " << big.rows;
    EXPECT_LE(big.seqscans, small.seqscans)
        << what << " planned more sequential scans of a type's table at the "
        << "large size: " << small.seqscans << " -> " << big.seqscans;
  }
};

}  // namespace

TEST_F(ScalePostgres, TheFilteredFieldIsIndexedAtBothSizes) {
  EXPECT_EQ(GDEFSTOR_INDEX_READY, g_pg_world->group_index);
}

TEST_F(ScalePostgres, AFilteredListPageReadsItsAnswerNotTheTable) {
  EXPECT_EQ(10u, g_pg_world->total_small);
  EXPECT_EQ(10u, g_pg_world->total_big);
  EXPECT_EQ(g_pg_world->list_small_ids, g_pg_world->list_big_ids);
  EXPECT_EQ(10u, g_pg_world->list_big_ids.size());
  ExpectFlat(g_pg_world->list_small, g_pg_world->list_big,
      "a filtered list page");
}

TEST_F(ScalePostgres, ACountReadsItsAnswerNotTheTable) {
  EXPECT_EQ(10u, g_pg_world->count_small_n);
  EXPECT_EQ(10u, g_pg_world->count_big_n);
  ExpectFlat(g_pg_world->count_small, g_pg_world->count_big,
      "a filtered count");
}

/* The control: the instrument sees a scan grow with the table. */
TEST_F(ScalePostgres, AnUnindexedFilterReadsTheTableAndIsSeenTo) {
  Print("an unindexed filter", g_pg_world->scan_small, g_pg_world->scan_big);
  const uint64_t grown = (uint64_t)(Size() - 1000);
  EXPECT_GE(g_pg_world->scan_big.rows, g_pg_world->scan_small.rows + grown)
      << "a scan of the table did not show in the rows read: "
      << g_pg_world->scan_small.rows << " -> " << g_pg_world->scan_big.rows;
}

TEST_F(ScalePostgres, CreatingOneMoreEntityCostsWhatItDidAtAThousand) {
  EXPECT_GE(g_pg_world->made, Size());
  ExpectFlat(g_pg_world->create_small, g_pg_world->create_big,
      "creating one entity");
}

/* The Postgres arm needs the library and a server; without either it fails
 * naming the fix, never passes. */
int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  if (PostgresArm()) {
#ifndef GDEFCORE_TEST_HAVE_PQ
    fprintf(stderr, "the Postgres arm of the scale test needs "
                    "defiant-storage-postgres and libpq's headers "
                    "(pkg-config libpq), which its derived image has: run make "
                    "test-scale-postgres there, through that library's "
                    "tools/pg-test.sh\n");
    return 1;
#else
    const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
    if (ci == NULL || ci[0] == '\0') {
      fprintf(stderr, "GDEFSPG_TEST_CONNINFO is not set: the Postgres arm of "
                      "the scale test needs a server; run it through "
                      "defiant-storage-postgres's tools/pg-test.sh\n");
      return 1;
    }
#endif
  }
  return RUN_ALL_TESTS();
}
