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
 * (story S6b), measured in rows and steps, never in time.
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
 * GDEFCORE_SCALE_N sets another size for looking at costs by hand (the bounds
 * do not depend on it); GDEFCORE_SCALE_VERBOSE prints each measurement.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-sqlite/model.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <filesystem>
#include <functional>
#include <random>
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
};

Cost g_cost;
bool g_counting = false;

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

  ~World() {
    gdefcore_catalog_destroy(catalog);
    gdefstor_store_destroy(store);
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
  /* Once unmeasured, so that what the first call sets up is not counted. */
  {
    char ** got = NULL;
    size_t n = 0;
    uint64_t t = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_list_page(w->catalog, r, &q, &got, &n, &t));
    gdefcore_access_free(w->catalog, got, n);
  }
  *list = Measure([&]() {
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
  *count = Measure([&]() {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(w->catalog, r, &q, counted));
  });
  {
    GDEFCORE_Access_List unindexed = q;
    unindexed.filter_field = "note";
    unindexed.filter_field_len = 4;
    *scan = Measure([&]() {
      char ** got = NULL;
      size_t n = 0;
      uint64_t t = 0;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_access_list_page(w->catalog, r, &unindexed, &got, &n, &t));
      EXPECT_EQ(10u, t);
      gdefcore_access_free(w->catalog, got, n);
    });
  }
  *create = Measure([&]() { ASSERT_TRUE(MakeEntities(w, w->made + 1)); });
  gdefcore_request_destroy(r);
}

World * Build() {
  World * w = new World();
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
    return w;
  }
  GDEFSSQLITE_ModelOptions o;
  gdefssqlite_model_options_default(&o);
  o.synchronous = GDEFSSQLITE_SYNC_OFF; /* the subject is rows, not the disk */
  o.on_statement = OnStatement;
  if (gdefssqlite_model_store_create(w->dir.c_str(), &o, NULL, NULL, &w->store) !=
          GDEFSSQLITE_OK ||
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
    if (g_world == NULL) {
      g_world = Build();
    }
  }
  static void TearDownTestSuite() {
    delete g_world;
    g_world = NULL;
  }
  void SetUp() override {
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

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
