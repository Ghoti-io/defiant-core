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
 * Nested groups, multiples and order through core (story S6d, CAP-S3): the
 * purchase-order fixture of the storage design (lines with taxes and
 * discounts with breakdowns; shipments with packages with tracking events)
 * declared in core's field model, saved and read as trees, appended three
 * groups deep, reordered, reverted, listed through indexed fields and rendered
 * with the access filter applied in every item. Each rule is counted on the
 * port's own rows (gdefstor_model_dump()), not taken from core's word. Run by
 * tools/check-groups.sh, which plants a defect for each named rule.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/query.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage-sqlite/model.h>

#include <gtest/gtest.h>

#include "keystore_rig.h"

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

const char kTenant[] = "t";
const char kPo[] = "site.purchase_order";

/* ---- declaring --------------------------------------------------------- */

struct Def {
  std::string name;
  int type = 0;
  int scale = 0;
  int many = 0;
  int required = 0;
  int indexed = 0;
  int personal = 0;
  std::string subject;
  std::vector<Def> kids;
};

Def F(const char * name, int type, int scale = 0) {
  Def d;
  d.name = name;
  d.type = type;
  d.scale = scale;
  return d;
}

Def Many(Def d) {
  d.many = 1;
  return d;
}

Def Required(Def d) {
  d.required = 1;
  return d;
}

Def Indexed(Def d) {
  d.indexed = 1;
  return d;
}

Def G(const char * name, std::vector<Def> kids) {
  Def d;
  d.name = name;
  d.type = GDEFSTOR_FIELD_GROUP;
  d.many = 1;
  d.kids = std::move(kids);
  return d;
}

/* GDEFCORE_Field arrays for a tree of Defs; they live as long as this. */
struct Fields {
  std::vector<std::unique_ptr<std::vector<GDEFCORE_Field>>> arrays;

  const GDEFCORE_Field * Make(const std::vector<Def> & defs) {
    std::unique_ptr<std::vector<GDEFCORE_Field>> level(
        new std::vector<GDEFCORE_Field>(defs.size()));
    for (size_t i = 0; i < defs.size(); i++) {
      GDEFCORE_Field & f = (*level)[i];
      memset(&f, 0, sizeof f);
      f.size = sizeof f;
      f.name = defs[i].name.c_str();
      f.name_len = defs[i].name.size();
      f.required = defs[i].required;
      f.many = defs[i].many;
      f.personal = defs[i].personal;
      f.type = defs[i].type;
      f.scale = defs[i].scale;
      f.indexed = defs[i].indexed;
      if (!defs[i].kids.empty()) {
        f.children = Make(defs[i].kids);
        f.child_count = defs[i].kids.size();
      }
      if (!defs[i].subject.empty()) {
        f.subject = defs[i].subject.c_str();
        f.subject_len = defs[i].subject.size();
      }
    }
    arrays.push_back(std::move(level));
    return arrays.back()->data();
  }
};

std::vector<Def> PurchaseOrder() {
  const int T = GDEFSTOR_FIELD_TEXT;
  const int D = GDEFSTOR_FIELD_DECIMAL;
  return {
      Indexed(Required(F("number", T))),
      F("placed", GDEFSTOR_FIELD_DATE),
      F("total", D, 2),
      Indexed(F("customer", GDEFSTOR_FIELD_REFERENCE)),
      Many(F("notes", T)),
      G("lines",
          {Indexed(Required(F("sku", T))), F("qty", GDEFSTOR_FIELD_INTEGER),
              F("price", D, 2),
              G("taxes", {F("name", T), F("rate", D, 4), F("amount", D, 2)}),
              G("discounts",
                  {F("code", T), F("amount", D, 2),
                      G("breakdown", {F("reason", T), F("amount", D, 2)})})}),
      G("shipments",
          {F("carrier", T),
              G("packages",
                  {F("weight", GDEFSTOR_FIELD_FLOAT),
                      G("tracking", {F("at", GDEFSTOR_FIELD_DATETIME),
                                        Indexed(F("status", T))})})}),
  };
}

/* ---- trees as values ---------------------------------------------------- */

struct Node {
  uint64_t id = 0;
  std::map<std::string, std::string> vals;
  std::string own;
  bool has_own = false;
  std::vector<std::pair<std::string, Node>> kids;

  Node & Set(const std::string & f, const std::string & t) {
    vals[f] = t;
    return *this;
  }
  Node & Add(const std::string & f) {
    kids.push_back(std::make_pair(f, Node()));
    return kids.back().second;
  }
  Node & AddValue(const std::string & f, const std::string & t) {
    Node & n = Add(f);
    n.own = t;
    n.has_own = true;
    return n;
  }
  /* The k-th item under @p f. */
  Node & At(const std::string & f, size_t k) {
    for (auto & kv : kids) {
      if (kv.first == f) {
        if (k == 0) {
          return kv.second;
        }
        k -= 1;
      }
    }
    static Node none;
    ADD_FAILURE() << "no item " << f << "[" << k << "]";
    return none;
  }
  size_t Count(const std::string & f) const {
    size_t n = 0;
    for (const auto & kv : kids) {
      n += kv.first == f ? 1u : 0u;
    }
    return n;
  }
  bool operator==(const Node & o) const {
    return id == o.id && vals == o.vals && own == o.own &&
           has_own == o.has_own && kids == o.kids;
  }
};

void AddInto(GDEFCORE_Tree * t, size_t at, const Node & n) {
  for (const auto & kv : n.vals) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, at, kv.first.data(),
        kv.first.size(), kv.second.data(), kv.second.size()));
  }
  if (n.has_own) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_tree_set(t, at, NULL, 0, n.own.data(), n.own.size()));
  }
  for (const auto & kv : n.kids) {
    size_t item = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_add(t, at, kv.first.data(),
        kv.first.size(), kv.second.id, &item));
    AddInto(t, item, kv.second);
  }
}

GDEFCORE_Tree * Build(GDEFCORE_Catalog * cat, const Node & n) {
  GDEFCORE_Tree * t = NULL;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_create(cat, &t));
  if (t != NULL) {
    AddInto(t, 0, n);
  }
  return t;
}

Node ReadItem(const GDEFCORE_Tree * t, size_t at,
    const std::vector<std::vector<size_t>> & kids) {
  Node n;
  GDEFCORE_TreeItem it;
  memset(&it, 0, sizeof it);
  it.size = sizeof it;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_item(t, at, &it));
  n.id = at == 0 ? 0 : it.id;
  for (size_t k = 0; k < it.value_count; k++) {
    const char * f = NULL;
    size_t fn = 0;
    const char * v = NULL;
    size_t vn = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_value(t, at, k, &f, &fn, &v, &vn));
    if (fn == 0) {
      n.own.assign(v, vn);
      n.has_own = true;
    } else {
      n.vals[std::string(f, fn)] = std::string(v, vn);
    }
  }
  for (size_t c : kids[at]) {
    GDEFCORE_TreeItem ci;
    memset(&ci, 0, sizeof ci);
    ci.size = sizeof ci;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_item(t, c, &ci));
    n.kids.push_back(std::make_pair(std::string(ci.field, ci.field_len),
        ReadItem(t, c, kids)));
  }
  return n;
}

/* A read tree lists one field's items together; the order of fields among a
 * parent's children is not part of the content, so it is put in one order. */
void SortFields(Node * n) {
  std::stable_sort(n->kids.begin(), n->kids.end(),
      [](const std::pair<std::string, Node> & a,
          const std::pair<std::string, Node> & b) { return a.first < b.first; });
  for (auto & kv : n->kids) {
    SortFields(&kv.second);
  }
}

Node Read(const GDEFCORE_Tree * t) {
  size_t n = gdefcore_tree_item_count(t);
  std::vector<std::vector<size_t>> kids(n);
  for (size_t i = 1; i < n; i++) {
    GDEFCORE_TreeItem it;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_item(t, i, &it));
    kids[it.parent].push_back(i);
  }
  Node out = n == 0 ? Node() : ReadItem(t, 0, kids);
  SortFields(&out);
  return out;
}

Node NoIds(Node n) {
  n.id = 0;
  for (auto & kv : n.kids) {
    kv.second = NoIds(kv.second);
  }
  return n;
}

Node Line(const char * sku, const char * qty, const char * price) {
  Node l;
  l.Set("sku", sku).Set("qty", qty).Set("price", price);
  l.Add("taxes").Set("name", "vat").Set("rate", "0.2000").Set("amount", "5.00");
  Node & d = l.Add("discounts");
  d.Set("code", "spring").Set("amount", "1.00");
  d.Add("breakdown").Set("reason", "loyalty").Set("amount", "0.60");
  d.Add("breakdown").Set("reason", "season").Set("amount", "0.40");
  return l;
}

Node PoTree(const std::string & number, const std::string & customer) {
  Node po;
  po.Set("number", number).Set("placed", "2025-10-17").Set("total", "34.99");
  po.Set("customer", customer);
  po.AddValue("notes", "fragile");
  po.AddValue("notes", "call first");
  po.Add("lines") = Line("A-1", "2", "12.50");
  po.Add("lines") = Line("B-2", "1", "9.99");
  Node & s = po.Add("shipments");
  s.Set("carrier", "post");
  Node & p = s.Add("packages");
  p.Set("weight", "1.5");
  p.Add("tracking").Set("at", "2025-10-09T08:53:20Z").Set("status", "sent");
  SortFields(&po);
  return po;
}

/* ---- dumps -------------------------------------------------------------- */

std::vector<std::string> Words(const std::string & line) {
  std::vector<std::string> out;
  std::istringstream in(line);
  std::string w;
  while (in >> w) {
    out.push_back(w);
  }
  return out;
}

std::vector<std::string> Lines(const std::string & dump, char tag) {
  std::vector<std::string> out;
  std::istringstream in(dump);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line[0] == tag && line.size() > 1 && line[1] == ' ') {
      out.push_back(line);
    }
  }
  return out;
}

/* Rows of @p tag in @p after and not in @p before; an item version is known
 * by its row, group, item and valid_from. */
size_t NewRows(const std::string & before, const std::string & after,
    char tag) {
  std::set<std::string> was;
  size_t n = 0;
  auto key = [tag](const std::string & l) {
    if (tag != 'I') {
      return l;
    }
    std::vector<std::string> w = Words(l);
    return w.size() < 5 ? l : w[1] + " " + w[2] + " " + w[3] + " " + w[4];
  };
  for (const std::string & l : Lines(before, tag)) {
    was.insert(key(l));
  }
  for (const std::string & l : Lines(after, tag)) {
    n += was.count(key(l)) == 0 ? 1u : 0u;
  }
  return n;
}

/* ---- the site ----------------------------------------------------------- */

enum Backend { kMemory = 0, kSqlite = 1 };

class Site {
 public:
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  std::string dir;

  explicit Site(int backend) {
    if (backend == kSqlite) {
      std::error_code ec;
      std::filesystem::path base = std::filesystem::temp_directory_path(ec);
      std::random_device entropy;
      for (int i = 0; i < 100 && dir.empty(); i++) {
        std::filesystem::path p =
            base / ("gdefcore-groups-" + std::to_string(entropy()));
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
        gdefcore_catalog_open(store, (const uint8_t *)kTenant, 1, NULL, NULL,
            &catalog));
  }

  ~Site() {
    gdefcore_catalog_destroy(catalog);
    gdefstor_store_destroy(store);
    if (!dir.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(dir, ec);
    }
  }

  std::string Dump(int which = GDEFSTOR_MODEL_TRUTH) {
    uint8_t * text = NULL;
    size_t len = 0;
    if (gdefstor_model_dump(store, kTenant, 1, which, &text, &len) !=
        GDEFSTOR_OK) {
      return "<dump failed>";
    }
    std::string s(reinterpret_cast<const char *>(text), len);
    gdefstor_bytes_free(NULL, text);
    return s;
  }

  GDEFCORE_Result Define(const char * type, const std::vector<Def> & defs) {
    Fields f;
    const GDEFCORE_Field * fields = f.Make(defs);
    return gdefcore_type_define(catalog, type, strlen(type),
        GDEFCORE_TYPE_CONTENT, fields, defs.size());
  }

  std::string Create(const char * type) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog, type, strlen(type), id, NULL));
    return std::string(id);
  }

  /* Stage @p n as language @p lang of @p id and apply; 0 on success. */
  GDEFCORE_Result Save(const std::string & id, const Node & n,
      uint64_t * out_rev = NULL, bool draft = false,
      const char * lang = "en") {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Tree * t = Build(catalog, n);
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
    if (rc == GDEFCORE_OK) {
      rc = (draft ? gdefcore_tree_save_draft : gdefcore_tree_save)(cs,
          id.data(), id.size(), lang, strlen(lang), t);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    if (rc == GDEFCORE_OK && out_rev != NULL) {
      rc = gdefcore_changeset_revision(cs, id.data(), id.size(), out_rev);
    }
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
    return rc;
  }

  Node Current(const std::string & id, int view = GDEFCORE_VIEW_CURRENT) {
    GDEFCORE_Tree * t = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_tree(catalog, NULL, view, id.data(),
        id.size(), "en", 2, &t));
    Node n = t == NULL ? Node() : Read(t);
    gdefcore_tree_free(t);
    return n;
  }

  Node AtRevision(const std::string & id, uint64_t seq) {
    GDEFCORE_Tree * t = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_revision_tree(catalog, id.data(),
        id.size(), seq, "en", 2, &t));
    Node n = t == NULL ? Node() : Read(t);
    gdefcore_tree_free(t);
    return n;
  }

  uint64_t Head(const std::string & id) {
    uint64_t seq = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision(catalog, id.data(), id.size(), &seq));
    return seq;
  }

  /* The port's diff of two revisions: kind and what, per item. */
  std::vector<std::pair<int, unsigned>> Diff(const std::string & id,
      uint64_t from, uint64_t to) {
    std::vector<std::pair<int, unsigned>> out;
    GDEFSTOR_Diff * d = NULL;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_entity_diff(store, kTenant, 1, id.data(),
        id.size(), "en", 2, from, to, &d));
    for (size_t i = 0; d != NULL && i < gdefstor_diff_count(d); i++) {
      GDEFSTOR_DiffItem di;
      memset(&di, 0, sizeof di);
      di.size = sizeof di;
      EXPECT_EQ(GDEFSTOR_OK, gdefstor_diff_item(d, i, &di));
      out.push_back(std::make_pair(di.kind, di.what));
    }
    gdefstor_diff_free(d);
    return out;
  }

  std::vector<std::string> Query(const char * path, const char * text) {
    GDEFSTOR_Query q;
    GDEFSTOR_QueryNode eq;
    GDEFSTOR_Value v;
    char ** ids = NULL;
    size_t count = 0;
    std::vector<std::string> out;
    memset(&v, 0, sizeof v);
    v.type = GDEFSTOR_FIELD_TEXT;
    v.bytes = (const uint8_t *)text;
    v.len = strlen(text);
    memset(&eq, 0, sizeof eq);
    eq.op = GDEFSTOR_QUERY_EQ;
    eq.left.kind = GDEFSTOR_QUERY_FIELD;
    eq.left.field = path;
    eq.left.field_len = strlen(path);
    eq.right.kind = GDEFSTOR_QUERY_VALUES;
    eq.right.values = &v;
    eq.right.value_count = 1;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.where = &eq;
    q.language = "en";
    q.language_len = 2;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_query_current(catalog, kPo,
        strlen(kPo), &q, &ids, &count, NULL));
    for (size_t i = 0; i < count; i++) {
      out.push_back(ids[i]);
    }
    gdefcore_ids_free(catalog, ids, count);
    return out;
  }
};

std::string NewId() {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  EXPECT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
  return std::string(id);
}

/* ---- the declaration ---------------------------------------------------- */

TEST(GroupsDeclare, ANestedTypeIsDeclaredOnThePortAsItsFieldTree) {
  Site s(kMemory);
  ASSERT_EQ(GDEFCORE_OK, s.Define(kPo, PurchaseOrder()));
  GDEFSTOR_Type * type = NULL;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_type_get(s.store, kTenant, 1, kPo,
      strlen(kPo), &type));
  struct Want {
    const char * path;
    int type;
    int scale;
    unsigned flags;
  };
  const Want want[] = {
      {"notes", GDEFSTOR_FIELD_TEXT, 0, GDEFSTOR_FIELD_MULTIPLE},
      {"lines", GDEFSTOR_FIELD_GROUP, 0, GDEFSTOR_FIELD_MULTIPLE},
      {"lines.sku", GDEFSTOR_FIELD_TEXT, 0, GDEFSTOR_FIELD_INDEXED},
      {"lines.taxes", GDEFSTOR_FIELD_GROUP, 0, GDEFSTOR_FIELD_MULTIPLE},
      {"lines.taxes.rate", GDEFSTOR_FIELD_DECIMAL, 4, 0},
      {"lines.discounts.breakdown.reason", GDEFSTOR_FIELD_TEXT, 0, 0},
      {"shipments.packages.tracking.at", GDEFSTOR_FIELD_DATETIME, 0, 0},
      {"shipments.packages.tracking.status", GDEFSTOR_FIELD_TEXT, 0,
          GDEFSTOR_FIELD_INDEXED},
  };
  for (const Want & w : want) {
    size_t at = 0;
    GDEFSTOR_FieldInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_type_find(type, w.path, strlen(w.path),
        &at)) << w.path;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_type_field(type, at, &info));
    EXPECT_EQ(w.type, info.type) << w.path;
    EXPECT_EQ(w.scale, info.scale) << w.path;
    EXPECT_EQ(w.flags, info.flags) << w.path;
  }
  EXPECT_EQ(26u, gdefstor_type_field_count(type));
  gdefstor_type_free(type);
  /* Core's own view: every field at every depth, and the flat calls see only
   * the root's fields that hold values. */
  size_t all = 0;
  size_t flat = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_tree_field_count(s.catalog, kPo, strlen(kPo), &all));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_count(s.catalog, kPo, strlen(kPo), &flat));
  EXPECT_EQ(26u, all);
  EXPECT_EQ(5u, flat);
  std::vector<std::string> names;
  for (size_t i = 0; i < flat; i++) {
    char * name = NULL;
    size_t n = 0;
    int required = 0;
    int many = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_field(s.catalog, kPo, strlen(kPo), i,
        &name, &n, &required, &many));
    names.push_back(std::string(name, n));
    gdefcore_text_free(s.catalog, name);
  }
  EXPECT_EQ((std::vector<std::string>{"number", "placed", "total", "customer",
                "notes"}),
      names);
  GDEFCORE_FieldInfo fi;
  memset(&fi, 0, sizeof fi);
  fi.size = sizeof fi;
  bool found = false;
  for (size_t i = 0; i < all; i++) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_tree_field(s.catalog, kPo, strlen(kPo), i, &fi));
    if (std::string(fi.path) == "lines.discounts.breakdown.amount") {
      found = true;
      EXPECT_EQ(3u, fi.depth);
      EXPECT_EQ(GDEFSTOR_FIELD_DECIMAL, fi.type);
      EXPECT_EQ(2, fi.scale);
      EXPECT_EQ(std::string("amount"), std::string(fi.path + fi.name_at));
      GDEFCORE_FieldInfo up;
      memset(&up, 0, sizeof up);
      up.size = sizeof up;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_type_tree_field(s.catalog, kPo,
          strlen(kPo), fi.parent, &up));
      EXPECT_EQ(std::string("lines.discounts.breakdown"), std::string(up.path));
      EXPECT_EQ(GDEFSTOR_FIELD_GROUP, up.type);
      EXPECT_TRUE(up.many);
    }
  }
  EXPECT_TRUE(found);
}

TEST(GroupsDeclare, AGroupOrAFieldInOneThatIsWrongIsRefused) {
  Site s(kMemory);
  const int T = GDEFSTOR_FIELD_TEXT;
  Def empty = G("g", {});
  EXPECT_EQ(GDEFCORE_ERR_INVALID, s.Define("site.a", {empty}));
  Def personal = G("g", {F("x", T)});
  personal.personal = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, s.Define("site.b", {personal}));
  Def indexed = Indexed(G("g", {F("x", T)}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, s.Define("site.c", {indexed}));
  /* A personal field inside a group names its subject source. */
  Def note = F("note", T);
  note.personal = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, s.Define("site.d", {G("g", {note})}));
  Def who = F("who", GDEFSTOR_FIELD_REFERENCE);
  Def named = note;
  named.subject = "who";
  EXPECT_EQ(GDEFCORE_OK, s.Define("site.e", {G("g", {who, named})}));
  /* The source is a single, non-personal reference among the siblings. */
  Def wrong = note;
  wrong.subject = "label";
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      s.Define("site.f", {G("g", {F("label", T), wrong})}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      s.Define("site.g", {G("g", {Many(who), named})}));
  Def elsewhere = note;
  elsewhere.subject = "who";
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      s.Define("site.h", {who, G("g", {elsewhere})}));
  /* Two siblings of one name; a deeper tree than the port takes. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      s.Define("site.i", {G("g", {F("x", T), F("x", T)})}));
  Def deep = F("leaf", T);
  for (int i = 0; i < GDEFSTOR_MODEL_MAX_DEPTH + 1; i++) {
    deep = G(("g" + std::to_string(i)).c_str(), {deep});
  }
  EXPECT_EQ(GDEFCORE_ERR_LIMIT, s.Define("site.j", {deep}));
  /* A field that is not a group has no children. */
  Fields f;
  std::vector<Def> one = {F("x", T)};
  GDEFCORE_Field bad;
  memset(&bad, 0, sizeof bad);
  bad.size = sizeof bad;
  bad.name = "y";
  bad.name_len = 1;
  bad.children = f.Make(one);
  bad.child_count = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_type_define(s.catalog, "site.k", 6, GDEFCORE_TYPE_CONTENT, &bad,
          1));
  int kind = 0;
  for (const char * t : {"site.a", "site.b", "site.c", "site.d", "site.f",
           "site.g", "site.h", "site.i", "site.j", "site.k"}) {
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_type_kind(s.catalog, t, strlen(t), &kind))
        << t << " was stored";
  }
}

/* ---- the purchase order through core ------------------------------------ */

/* Every test of the purchase order runs on the memory backend and on SQLite,
 * as two suites with plain names, so a plant can name the one it turns red. */
class PoBase : public ::testing::Test {
 public:
  std::unique_ptr<Site> s;
  std::string po;
  std::string customer = NewId();

 protected:
  void Open(int backend) {
    s.reset(new Site(backend));
    ASSERT_EQ(GDEFCORE_OK, s->Define(kPo, PurchaseOrder()));
    po = s->Create(kPo);
    uint64_t rev = 0;
    ASSERT_EQ(GDEFCORE_OK, s->Save(po, PoTree("PO-1", customer), &rev));
    ASSERT_EQ(1u, rev);
  }
};

class GroupsPo : public PoBase {
 protected:
  void SetUp() override { Open(kMemory); }
};

class GroupsPoSqlite : public PoBase {
 protected:
  void SetUp() override { Open(kSqlite); }
};

#define PO_TEST(name)                                  \
  template <class Fx> static void name##Body(Fx * self); \
  TEST_F(GroupsPo, name) { name##Body(this); }           \
  TEST_F(GroupsPoSqlite, name) { name##Body(this); }     \
  template <class Fx> static void name##Body(Fx * self)

#define PO_LOCALS                                      \
  std::unique_ptr<Site> & s = self->s;                 \
  std::string & po = self->po;                         \
  std::string & customer = self->customer;             \
  (void)po;                                            \
  (void)customer

PO_TEST(ThePurchaseOrderRoundTripsAsItWasWritten) {
  PO_LOCALS;
  Node now = s->Current(po);
  EXPECT_EQ(NoIds(PoTree("PO-1", customer)), NoIds(now));
  /* Every item has the port's id, and the flat read sees the root. */
  EXPECT_NE(0u, now.At("lines", 1).id);
  EXPECT_NE(0u, now.At("lines", 0).At("discounts", 0).At("breakdown", 1).id);
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_values(s->catalog, NULL,
      GDEFCORE_VIEW_CURRENT, po.data(), po.size(), "en", 2, "notes", 5, &texts,
      &lens, &count));
  ASSERT_EQ(2u, count);
  EXPECT_EQ("fragile", std::string(texts[0], lens[0]));
  gdefcore_values_free(s->catalog, texts, lens, count);
  /* A group has no flat value. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_entity_values(s->catalog, NULL,
      GDEFCORE_VIEW_CURRENT, po.data(), po.size(), "en", 2, "lines", 5, &texts,
      &lens, &count));
  /* Values are read in their type's canonical text, at any depth. */
  Node again = now;
  again.At("lines", 0).Set("price", "12.5");
  again.At("lines", 0).At("taxes", 0).Set("rate", ".2");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, s->Save(po, again));
  again.At("lines", 0).At("taxes", 0).Set("rate", "0.2");
  uint64_t rev = 99;
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, again, &rev));
  EXPECT_EQ(0u, rev) << "12.5 and 0.2 are the values it holds";
}

PO_TEST(ATrackingEventThreeGroupsDeepWritesOneItemVersionAndOneRevision) {
  PO_LOCALS;
  std::string before = s->Dump();
  Node now = s->Current(po);
  now.At("shipments", 0).At("packages", 0).Add("tracking")
      .Set("at", "2025-10-09T09:00:00Z")
      .Set("status", "delivered");
  uint64_t rev = 0;
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, now, &rev));
  EXPECT_EQ(2u, rev);
  std::string after = s->Dump();
  EXPECT_EQ(1u, NewRows(before, after, 'I'));
  EXPECT_EQ(1u, NewRows(before, after, 'R'));
  Node got = s->Current(po);
  ASSERT_EQ(2u, got.At("shipments", 0).At("packages", 0).Count("tracking"));
  EXPECT_EQ("delivered", got.At("shipments", 0).At("packages", 0)
                             .At("tracking", 1).vals["status"]);
  /* And the same tree again writes nothing at all. */
  before = after;
  rev = 99;
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, got, &rev));
  EXPECT_EQ(0u, rev);
  after = s->Dump();
  EXPECT_EQ(0u, NewRows(before, after, 'I'));
  EXPECT_EQ(0u, NewRows(before, after, 'R'));
  EXPECT_EQ(0u, NewRows(before, after, 'S'));
}

PO_TEST(ItemIdsAreStableAcrossSavesAndOnlyTheChangedItemIsWritten) {
  PO_LOCALS;
  Node one = s->Current(po);
  Node two = one;
  two.At("lines", 1).At("taxes", 0).Set("amount", "2.00");
  std::string before = s->Dump();
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, two));
  std::string after = s->Dump();
  EXPECT_EQ(1u, NewRows(before, after, 'I'));
  Node got = s->Current(po);
  /* Every item keeps its id, the changed one included. */
  EXPECT_EQ(NoIds(two), NoIds(got));
  EXPECT_EQ(one.At("lines", 1).At("taxes", 0).id,
      got.At("lines", 1).At("taxes", 0).id);
  EXPECT_EQ(one.At("lines", 0).id, got.At("lines", 0).id);
  EXPECT_EQ(one.At("shipments", 0).At("packages", 0).At("tracking", 0).id,
      got.At("shipments", 0).At("packages", 0).At("tracking", 0).id);
  auto diff = s->Diff(po, 1, 2);
  ASSERT_EQ(1u, diff.size());
  EXPECT_EQ(GDEFSTOR_DIFF_CHANGED, diff[0].first);
  EXPECT_EQ(GDEFSTOR_DIFF_VALUES, diff[0].second);
  /* A new item gets a new id, and a removed one is closed. */
  Node three = got;
  three.Add("lines") = Line("C-3", "4", "1.00");
  three.kids.erase(three.kids.begin()); /* the first line */
  SortFields(&three);
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, three));
  Node four = s->Current(po);
  EXPECT_EQ(2u, four.Count("lines"));
  std::set<uint64_t> ids;
  for (size_t k = 0; k < four.Count("lines"); k++) {
    ids.insert(four.At("lines", k).id);
  }
  EXPECT_EQ(0u, ids.count(one.At("lines", 0).id)) << "a removed line came back";
  EXPECT_EQ(1u, ids.count(one.At("lines", 1).id));
}

PO_TEST(AReorderChangesOrderKeysOnly) {
  PO_LOCALS;
  Node one = s->Current(po);
  Node two = one;
  /* The lines and the notes, each in the other order: the same items, by
   * their ids. */
  std::vector<std::pair<std::string, Node>> lines;
  std::vector<std::pair<std::string, Node>> notes;
  std::vector<std::pair<std::string, Node>> rest;
  for (auto & kv : two.kids) {
    (kv.first == "lines" ? lines : kv.first == "notes" ? notes : rest)
        .push_back(kv);
  }
  std::reverse(lines.begin(), lines.end());
  std::reverse(notes.begin(), notes.end());
  two.kids = rest;
  two.kids.insert(two.kids.end(), lines.begin(), lines.end());
  two.kids.insert(two.kids.end(), notes.begin(), notes.end());
  SortFields(&two);
  std::string before = s->Dump();
  uint64_t rev = 0;
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, two, &rev));
  ASSERT_EQ(2u, rev);
  std::string after = s->Dump();
  Node got = s->Current(po);
  EXPECT_EQ(NoIds(two), NoIds(got));
  EXPECT_EQ("B-2", got.At("lines", 0).vals["sku"]);
  EXPECT_EQ("call first", got.At("notes", 0).own);
  EXPECT_EQ(one.At("lines", 1).id, got.At("lines", 0).id);
  EXPECT_EQ(one.At("notes", 1).id, got.At("notes", 0).id);
  /* What changed is order keys and nothing else: every item the diff names
   * changed its order only, and there is one new version for each. */
  auto diff = s->Diff(po, 1, 2);
  ASSERT_FALSE(diff.empty());
  EXPECT_LE(diff.size(), 4u);
  for (const auto & d : diff) {
    EXPECT_EQ(GDEFSTOR_DIFF_CHANGED, d.first);
    EXPECT_EQ(GDEFSTOR_DIFF_ORDER, d.second) << "a reorder rewrote values";
  }
  EXPECT_EQ(diff.size(), NewRows(before, after, 'I'));
  EXPECT_EQ(1u, NewRows(before, after, 'R'));
  /* The flat read follows the new order. */
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_values(s->catalog, NULL,
      GDEFCORE_VIEW_CURRENT, po.data(), po.size(), "en", 2, "notes", 5, &texts,
      &lens, &count));
  ASSERT_EQ(2u, count);
  EXPECT_EQ("call first", std::string(texts[0], lens[0]));
  gdefcore_values_free(s->catalog, texts, lens, count);
}

PO_TEST(ARevertWritesANewRevisionAndOldRevisionsReadAsTheyDid) {
  PO_LOCALS;
  Node one = s->Current(po);
  Node two = one;
  two.At("lines", 0).Set("qty", "3");
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, two));
  Node three = s->Current(po);
  three.At("shipments", 0).Set("carrier", "courier");
  three.At("shipments", 0).At("packages", 0).At("tracking", 0)
      .Set("status", "lost");
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, three));
  Node at2 = s->AtRevision(po, 2);
  Node at3 = s->AtRevision(po, 3);
  std::string before = s->Dump();
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_revert_to(s->catalog, po.data(),
      po.size(), 1, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(4u, s->Head(po));
  EXPECT_EQ(one, s->Current(po)) << "ids and values of revision 1";
  EXPECT_EQ(at2, s->AtRevision(po, 2));
  EXPECT_EQ(at3, s->AtRevision(po, 3));
  EXPECT_EQ(one, s->AtRevision(po, 1));
  /* A revert adds rows and never changes one (AD-14). */
  std::string after = s->Dump();
  std::set<std::string> now;
  for (const std::string & l : Lines(after, 'R')) {
    now.insert(l);
  }
  for (const std::string & l : Lines(before, 'R')) {
    EXPECT_EQ(1u, now.count(l)) << l;
  }
  EXPECT_EQ(1u, NewRows(before, after, 'R'));
  EXPECT_LE(NewRows(before, after, 'I'), 3u);
}

PO_TEST(TheOrderIsListedThroughItsIndexedFields) {
  PO_LOCALS;
  std::string other = s->Create(kPo);
  Node po2 = PoTree("PO-2", customer);
  po2.At("lines", 1).Set("sku", "Z-9");
  po2.At("shipments", 0).At("packages", 0).At("tracking", 0)
      .Set("status", "held");
  ASSERT_EQ(GDEFCORE_OK, s->Save(other, po2));
  EXPECT_EQ((std::vector<std::string>{po}), s->Query("lines.sku", "B-2"));
  EXPECT_EQ((std::vector<std::string>{other}), s->Query("lines.sku", "Z-9"));
  EXPECT_EQ((std::vector<std::string>{po, other}),
      s->Query("lines.sku", "A-1"));
  EXPECT_EQ((std::vector<std::string>{other}),
      s->Query("shipments.packages.tracking.status", "held"));
  EXPECT_EQ((std::vector<std::string>{po}), s->Query("number", "PO-1"));
  int state = 0;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_type_index_state(s->store, kTenant, 1, kPo,
      strlen(kPo), "lines.sku", 9, &state));
  EXPECT_NE(GDEFSTOR_INDEX_NONE, state);
  /* A current list: a change moves the answer. */
  Node now = s->Current(po);
  now.At("lines", 1).Set("sku", "B-3");
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, now));
  EXPECT_TRUE(s->Query("lines.sku", "B-2").empty());
  EXPECT_EQ((std::vector<std::string>{po}), s->Query("lines.sku", "B-3"));
}

PO_TEST(AFlatSaveOfANestedTypeKeepsItsGroupItems) {
  PO_LOCALS;
  Node one = s->Current(po);
  /* The control: the tree save stored the groups. */
  ASSERT_EQ(2u, one.Count("lines"));
  ASSERT_EQ(1u, one.Count("shipments"));
  std::string before = s->Dump();
  GDEFCORE_Changeset * cs = NULL;
  const char * texts[1] = {"PO-1b"};
  size_t lens[1] = {5};
  GDEFCORE_Value v;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  v.field = "number";
  v.field_len = 6;
  v.texts = texts;
  v.text_lens = lens;
  v.count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(s->catalog, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(cs, po.data(), po.size(), "en", 2, &v, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  std::string after = s->Dump();
  EXPECT_EQ(1u, NewRows(before, after, 'I')) << "only the root item";
  Node got = s->Current(po);
  one.Set("number", "PO-1b");
  EXPECT_EQ(one, got);
  EXPECT_EQ(2u, got.Count("lines"));
  /* The flat API refuses a group and a field inside one. */
  v.field = "lines";
  v.field_len = 5;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(s->catalog, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(cs, po.data(), po.size(), "en", 2, &v, 1));
  v.field = "lines.sku";
  v.field_len = 9;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(cs, po.data(), po.size(), "en", 2, &v, 1));
  gdefcore_changeset_destroy(cs);
}

PO_TEST(ADraftOfATreeIsPublishedAsOneRevision) {
  PO_LOCALS;
  Node now = s->Current(po);
  now.At("lines", 0).At("discounts", 0).Add("breakdown")
      .Set("reason", "bulk")
      .Set("amount", "0.10");
  std::string before = s->Dump();
  ASSERT_EQ(GDEFCORE_OK, s->Save(po, now, NULL, true));
  EXPECT_EQ(1u, s->Head(po)) << "a draft is not a revision";
  EXPECT_EQ(0u, NewRows(before, s->Dump(), 'I'));
  EXPECT_EQ(2u, s->Current(po).At("lines", 0).At("discounts", 0)
                    .Count("breakdown"));
  EXPECT_EQ(3u, s->Current(po, GDEFCORE_VIEW_DRAFT).At("lines", 0)
                    .At("discounts", 0).Count("breakdown"));
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(s->catalog, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, po.data(), po.size()));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(2u, s->Head(po));
  std::string after = s->Dump();
  EXPECT_EQ(1u, NewRows(before, after, 'I'));
  EXPECT_EQ(1u, NewRows(before, after, 'R'));
  EXPECT_EQ(NoIds(now), NoIds(s->Current(po)));
}

PO_TEST(ADiffNamesTheGroupThatChanged) {
  PO_LOCALS;
  Node now = s->Current(po);
  now.Add("lines") = Line("C-3", "1", "2.00");
  SortFields(&now);
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Tree * t = Build(s->catalog, now);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(s->catalog, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_save(cs, po.data(), po.size(), "en", 2,
      t));
  char * text = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_diff(cs, &text, &n));
  EXPECT_EQ("en lines: 2 items -> 3 items", std::string(text, n));
  gdefcore_text_free(s->catalog, text);
  /* What the changeset stages is read back as a tree. */
  GDEFCORE_Tree * staged = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_tree(s->catalog, cs,
      GDEFCORE_VIEW_CURRENT, po.data(), po.size(), "en", 2, &staged));
  EXPECT_EQ(3u, Read(staged).Count("lines"));
  gdefcore_tree_free(staged);
  /* The patch form has no file for a group's items yet: refused. */
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  EXPECT_EQ(GDEFCORE_ERR_UNSUPPORTED,
      gdefcore_changeset_serialize(cs, &files, &count));
  EXPECT_EQ(NULL, files);
  gdefcore_changeset_destroy(cs);
  gdefcore_tree_free(t);
}

PO_TEST(ATreeIsCheckedAgainstTheTypeAndAMisfitStagesNothing) {
  PO_LOCALS;
  Node good = s->Current(po);
  auto refused = [&](const Node & n) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Tree * t = Build(s->catalog, n);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(s->catalog, NULL, 0, &cs));
    GDEFCORE_Result rc = gdefcore_tree_save(cs, po.data(), po.size(), "en", 2,
        t);
    EXPECT_EQ(0u, gdefcore_changeset_touched_count(cs));
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
    return rc;
  };
  Node a = good;
  a.At("lines", 0).Set("nope", "x");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(a)) << "a field the group lacks";
  Node b = good;
  b.At("lines", 0).Set("qty", "two");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(b)) << "not an integer";
  Node c = good;
  c.Add("number").Set("x", "y");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(c)) << "an item under a single field";
  Node d = good;
  d.At("lines", 0).Set("taxes", "1");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(d)) << "a value on a group";
  Node e = good;
  e.At("lines", 0).vals.erase("sku");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(e)) << "a required field missing";
  Node f = good;
  f.vals.erase("number");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(f)) << "a required root field";
  Node g = good;
  g.Set("notes", "one");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(g)) << "a multiple as a single value";
  Node h = good;
  h.At("lines", 0).Add("qty");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused(h)) << "an item of a single field";
  /* A dotted name is not a field name: the tree itself refuses it. */
  GDEFCORE_Tree * t = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_create(s->catalog, &t));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_tree_add(t, 0, "lines.taxes", 11, 0, NULL));
  EXPECT_EQ(1u, gdefcore_tree_item_count(t));
  gdefcore_tree_free(t);
}

PO_TEST(AConditionOnANestedFieldIsRefusedAsAFieldTheTypeLacks) {
  PO_LOCALS;
  GDEFCORE_Condition * cond = NULL;
  GDEFCORE_Condition_Error err;
  memset(&err, 0, sizeof err);
  err.size = sizeof err;
  const char * text = "(= field.lines \"x\")";
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(text, strlen(text), &cond, &err));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_condition_validate(s->catalog, cond, kPo, strlen(kPo), &err));
  gdefcore_condition_free(cond);
  const char * root = "(= field.number \"PO-1\")";
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(root, strlen(root), &cond, &err));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_condition_validate(s->catalog, cond, kPo, strlen(kPo), &err));
  gdefcore_condition_free(cond);
}

/* ---- flat types --------------------------------------------------------- */

TEST(GroupsFlat, AFlatTypeIsDeclaredAndSavedAsBefore) {
  Site s(kMemory);
  ASSERT_EQ(GDEFCORE_OK,
      s.Define("site.note", {Required(F("title", GDEFSTOR_FIELD_TEXT)),
                                Many(F("tags", GDEFSTOR_FIELD_TEXT))}));
  size_t all = 0;
  size_t flat = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_tree_field_count(s.catalog, "site.note", 9, &all));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_field_count(s.catalog, "site.note", 9,
      &flat));
  EXPECT_EQ(2u, all);
  EXPECT_EQ(2u, flat);
  std::string id = s.Create("site.note");
  Node n;
  n.Set("title", "one");
  n.AddValue("tags", "a");
  n.AddValue("tags", "b");
  ASSERT_EQ(GDEFCORE_OK, s.Save(id, n));
  /* The flat API on the same tags: by position, as it always was. */
  GDEFCORE_Changeset * cs = NULL;
  const char * texts[2] = {"b", "a"};
  size_t lens[2] = {1, 1};
  GDEFCORE_Value v;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  v.field = "tags";
  v.field_len = 4;
  v.texts = texts;
  v.text_lens = lens;
  v.count = 2;
  std::string before = s.Dump();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(s.catalog, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, &v, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  /* Two values rewritten in place: the k-th value in the k-th item. */
  auto diff = s.Diff(id, 1, 2);
  ASSERT_EQ(2u, diff.size());
  for (const auto & d : diff) {
    EXPECT_EQ(GDEFSTOR_DIFF_VALUES, d.second);
  }
  EXPECT_EQ(2u, NewRows(before, s.Dump(), 'I'));
  /* And it serializes to a patch, as a flat type always did. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(s.catalog, NULL, 0, &cs));
  texts[0] = "c";
  v.count = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, &v, 1));
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(cs, &files, &count));
  gdefcore_patch_free(s.catalog, files, count);
  gdefcore_changeset_destroy(cs);
}

/* ---- personal fields inside groups -------------------------------------- */

class GroupsPersonal : public ::testing::Test {
 protected:
  GDEFSTOR_Store * registry_ = NULL;
  GDEFSTOR_Store * site_ = NULL;
  GDEFSTOR_KeyStore * keys_ = NULL;
  ksrig::Counts counts_;
  GDEFCORE_Inst * inst_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  GDEFCORE_Subjects * subjects_ = NULL;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t storage_[16];
  char tenant_[GDEFCORE_PUBLIC_ID_LEN + 1];

  void SetUp() override {
    memset(root_, 0x42, sizeof root_);
    memset(storage_, 0, sizeof storage_);
    memset(tenant_, 0, sizeof tenant_);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &registry_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &site_));
    ASSERT_EQ(GDEFSTOR_OK, ksrig::Open(ksrig::kMemory, &counts_, &keys_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_open_keys(registry_, site_, keys_, root_, sizeof root_, "",
            0, NULL, &inst_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(inst_, tenant_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_storage_key(inst_, tenant_, strlen(tenant_), storage_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_catalog_open(inst_, tenant_, strlen(tenant_), &catalog_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_open(keys_, site_, storage_, sizeof storage_, root_,
            sizeof root_,
            gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_)), NULL,
            &subjects_));
    gdefcore_catalog_bind_subjects(catalog_, subjects_);
    Def who = F("who", GDEFSTOR_FIELD_REFERENCE);
    Def note = F("note", GDEFSTOR_FIELD_TEXT);
    note.personal = 1;
    note.subject = "who";
    Fields f;
    std::vector<Def> defs = {Required(F("title", GDEFSTOR_FIELD_TEXT)),
        G("contacts", {who, note})};
    const GDEFCORE_Field * fields = f.Make(defs);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, "site.case", 9,
        GDEFCORE_TYPE_CONTENT, fields, defs.size()));
  }

  void TearDown() override {
    gdefcore_subject_destroy(subjects_);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_inst_destroy(inst_);
    gdefstor_keystore_destroy(keys_);
    gdefstor_store_destroy(site_);
    gdefstor_store_destroy(registry_);
  }

  std::string Seal(const std::string & subject, const char * field,
      const std::string & plain, uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN]) {
    char * text = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_seal(subjects_, subject.data(),
        subject.size(), field, strlen(field), plain.data(), plain.size(), &text,
        &n, mac));
    std::string out(text == NULL ? "" : text, n);
    gdefcore_subject_free(subjects_, text);
    return out;
  }

  GDEFCORE_Result SaveCase(const std::string & id, const Node & n,
      bool accept = true) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Tree * t = Build(catalog_, n);
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc == GDEFCORE_OK && accept) {
      rc = gdefcore_changeset_accept_sealed(cs);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_tree_save(cs, id.data(), id.size(), "en", 2, t);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
    return rc;
  }
};

TEST_F(GroupsPersonal, AValueInsideAGroupNamesTheSubjectItsItemNames) {
  char ann[GDEFCORE_PUBLIC_ID_LEN + 1];
  char bob[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, ann));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, bob));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.case", 9, id, NULL));
  /* Sealed for the field's path: a field inside a group is `contacts.note`. */
  std::string for_ann = Seal(ann, "contacts.note", "ann's number", mac);
  std::string for_bob = Seal(bob, "contacts.note", "bob's number", mac);
  Node n;
  n.Set("title", "case one");
  n.Add("contacts").Set("who", ann).Set("note", for_ann);
  n.Add("contacts").Set("who", bob).Set("note", for_bob);
  SortFields(&n);
  /* Plaintext, or a sealed value the changeset was not told to accept, is
   * refused. */
  Node plain = n;
  plain.At("contacts", 0).Set("note", "ann's number");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SaveCase(id, plain));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SaveCase(id, n, false));
  /* A value sealed for another subject than its item names. */
  Node crossed = n;
  crossed.At("contacts", 0).Set("note", for_bob);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SaveCase(id, crossed));
  /* Sealed for the field's name, not its path: it does not open. */
  Node by_name = n;
  by_name.At("contacts", 0).Set("note", Seal(ann, "note", "ann's number", mac));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SaveCase(id, by_name));
  ASSERT_EQ(GDEFCORE_OK, SaveCase(id, n));
  /* Each value is stored with its own subject, and "everything about this
   * person" finds it: the export opens it at its path. */
  char * json = NULL;
  size_t len = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_export(subjects_, catalog_, ann, strlen(ann), &json,
          &len));
  std::string doc(json, len);
  gdefcore_subject_free(subjects_, json);
  EXPECT_NE(std::string::npos, doc.find("ann's number")) << doc;
  EXPECT_EQ(std::string::npos, doc.find("bob's number")) << doc;
  EXPECT_NE(std::string::npos, doc.find("contacts.note")) << doc;
  /* And the blind index finds the entity by the plaintext, at the path. */
  char ** ids = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_find(subjects_, catalog_,
      "site.case", 9, "contacts.note", 13, "en", 2, "bob's number", 12, &ids,
      &count));
  ASSERT_EQ(1u, count);
  EXPECT_EQ(std::string(id), std::string(ids[0]));
  gdefcore_ids_free(catalog_, ids, count);
  /* Saving the tree read back writes nothing: an unchanged value is
   * unchanged, whatever was sealed. */
  GDEFCORE_Tree * t = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_tree(catalog_, NULL,
      GDEFCORE_VIEW_CURRENT, id, strlen(id), "en", 2, &t));
  Node back = Read(t);
  gdefcore_tree_free(t);
  uint64_t head = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_revision(catalog_, id, strlen(id),
      &head));
  ASSERT_EQ(GDEFCORE_OK, SaveCase(id, back));
  uint64_t again = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_revision(catalog_, id, strlen(id),
      &again));
  EXPECT_EQ(head, again);
}

/* ---- the render context ------------------------------------------------- */

class GroupsRender : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  GDEFCORE_Host * host_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  std::string po_;
  char buyer_[GDEFCORE_PUBLIC_ID_LEN + 1];
  char clerk_[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::vector<GDEFCORE_Request *> reqs_;

  GDEFCORE_Permission Perm(const char * label, const char * field) {
    GDEFCORE_Permission p;
    memset(&p, 0, sizeof p);
    p.size = sizeof p;
    p.label = label;
    p.label_len = strlen(label);
    p.module_name = "orders";
    p.module_name_len = 6;
    p.action = "read";
    p.action_len = 4;
    p.condition = GDEFCORE_ACCESS_ANY;
    p.type_name = kPo;
    p.type_name_len = strlen(kPo);
    if (field != NULL) {
      p.field = field;
      p.field_len = strlen(field);
    }
    return p;
  }

  GDEFCORE_Request * Req(const char * principal) {
    GDEFCORE_Request * r = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &r));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(r, principal, strlen(principal)));
    reqs_.push_back(r);
    return r;
  }

  GDEFCORE_Result Put(const char * type, std::vector<std::pair<std::string,
      std::vector<std::string>>> values, const char * confirm) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> vs(values.size());
    std::vector<std::vector<const char *>> texts(values.size());
    std::vector<std::vector<size_t>> lens(values.size());
    for (size_t i = 0; i < values.size(); i++) {
      for (const std::string & t : values[i].second) {
        texts[i].push_back(t.c_str());
        lens[i].push_back(t.size());
      }
      memset(&vs[i], 0, sizeof vs[i]);
      vs[i].size = sizeof vs[i];
      vs[i].field = values[i].first.c_str();
      vs[i].field_len = values[i].first.size();
      vs[i].texts = texts[i].data();
      vs[i].text_lens = lens[i].data();
      vs[i].count = texts[i].size();
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

  void SetUp() override {
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store_,
        (const uint8_t *)kTenant, 1, NULL, NULL, &catalog_));
    gdefcore_catalog_bind_host(catalog_, host_);
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    Fields f;
    std::vector<Def> defs = PurchaseOrder();
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kPo, strlen(kPo),
        GDEFCORE_TYPE_CONTENT, f.Make(defs), defs.size()));
    /* A kind whose templates see an order, and a template that walks its
     * lines and each line's taxes. */
    ASSERT_EQ(GDEFCORE_OK,
        Put(GDEFCORE_TEMPLATE_KIND_TYPE,
            {{"name", {"site.order"}}, {"label", {"Order"}}, {"version", {"1"}},
                {"variables", {"entity entity The order"}}},
            GDEFCORE_TEMPLATE_KIND_TYPE));
    ASSERT_EQ(GDEFCORE_OK,
        Put(GDEFCORE_TEMPLATE_TYPE,
            {{"name", {"order"}},
                {"body",
                    {"<% use entity; %>#<%= entity.number %>"
                     "<% for (line : entity.lines) { %>|<%= line.sku %>"
                     " x<%= line.qty %> @<%= line.price %>"
                     "<% for (tax : line.taxes) { %>[<%= tax.name %>"
                     " <%= tax.amount %>]<% } %><% } %>"
                     "<% for (note : entity.notes) { %>;<%= note %><% } %>"}},
                {"kind", {"site.order"}}},
            GDEFCORE_TEMPLATE_TYPE));
    /* Buyers read orders and prices; clerks read orders and not prices. */
    GDEFCORE_Permission read = Perm("Read orders", NULL);
    GDEFCORE_Permission price = Perm("Read prices", "lines.price");
    GDEFCORE_Permission amount = Perm("Read tax amounts", "lines.taxes.amount");
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &read));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &price));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &amount));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, "buyers", 6, NULL));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, "clerks", 6, NULL));
    for (const char * label : {"Read orders", "Read prices", "Read tax amounts"}) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "buyers", 6, label,
          strlen(label), "core.role", 9));
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "clerks", 6,
        "Read orders", 11, "core.role", 9));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, buyer_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, clerk_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, buyer_,
        strlen(buyer_), "buyers", 6));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, clerk_,
        strlen(clerk_), "clerks", 6));
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPo, strlen(kPo), id, NULL));
    po_ = id;
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Tree * t = Build(catalog_, PoTree("PO-7", NewId()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_save(cs, id, strlen(id), "en", 2, t));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
  }

  void TearDown() override {
    for (GDEFCORE_Request * r : reqs_) {
      gdefcore_request_destroy(r);
    }
    gdefcore_catalog_bind_host(catalog_, NULL);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_host_destroy(host_);
    gdefstor_store_destroy(store_);
  }

  std::string Render(GDEFCORE_Request * req, GDEFCORE_Result * out_rc = NULL) {
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_render_entity(catalog_, req, "order", 5,
        po_.data(), po_.size(), "en", 2, GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
    if (out_rc != NULL) {
      *out_rc = rc;
    } else {
      EXPECT_EQ(GDEFCORE_OK, rc);
    }
    std::string out(bytes == NULL ? "" : bytes, n);
    gdefcore_text_free(catalog_, bytes);
    return out;
  }

  Node Tree(GDEFCORE_Request * req, GDEFCORE_Result * out_rc = NULL) {
    GDEFCORE_Tree * t = NULL;
    GDEFCORE_Result rc = gdefcore_access_tree(catalog_, req, po_.data(),
        po_.size(), "en", 2, &t);
    if (out_rc != NULL) {
      *out_rc = rc;
    } else {
      EXPECT_EQ(GDEFCORE_OK, rc);
    }
    Node n = t == NULL ? Node() : Read(t);
    gdefcore_tree_free(t);
    return n;
  }
};

TEST_F(GroupsRender, ATemplateIteratesTheLinesAndTheirTaxes) {
  EXPECT_EQ("#PO-7|A-1 x2 @12.50[vat 5.00]|B-2 x1 @9.99[vat 5.00]"
            ";fragile;call first",
      Render(Req(buyer_)));
}

TEST_F(GroupsRender, AFieldTheReaderMayNotSeeIsAbsentInEveryItem) {
  /* The control: a buyer sees every line's price and every tax's amount. */
  Node all = Tree(Req(buyer_));
  ASSERT_EQ(2u, all.Count("lines"));
  EXPECT_EQ("12.50", all.At("lines", 0).vals["price"]);
  EXPECT_EQ("9.99", all.At("lines", 1).vals["price"]);
  EXPECT_EQ("5.00", all.At("lines", 1).At("taxes", 0).vals["amount"]);
  /* A clerk: the same lines, each without its price, each tax without its
   * amount, and nothing else missing. */
  Node some = Tree(Req(clerk_));
  ASSERT_EQ(2u, some.Count("lines"));
  for (size_t k = 0; k < 2; k++) {
    EXPECT_EQ(0u, some.At("lines", k).vals.count("price")) << "line " << k;
    EXPECT_EQ(all.At("lines", k).vals["sku"], some.At("lines", k).vals["sku"]);
    EXPECT_EQ(0u, some.At("lines", k).At("taxes", 0).vals.count("amount"))
        << "line " << k;
    EXPECT_EQ("vat", some.At("lines", k).At("taxes", 0).vals["name"]);
  }
  EXPECT_EQ("PO-7", some.vals["number"]);
  std::string page = Render(Req(clerk_));
  EXPECT_EQ("#PO-7|A-1 x2 @[vat ]|B-2 x1 @[vat ]"
            ";fragile;call first",
      page);
  EXPECT_EQ(std::string::npos, page.find("12.50"));
  EXPECT_EQ(std::string::npos, page.find("9.99"));
}

TEST_F(GroupsRender, AnOrderTheReaderMayNotSeeIsNotThere) {
  char stranger[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, stranger));
  GDEFCORE_Result hidden = GDEFCORE_OK;
  GDEFCORE_Result missing = GDEFCORE_OK;
  char * bytes = (char *)0x1;
  size_t n = 7;
  hidden = gdefcore_render_entity(catalog_, Req(stranger), "order", 5,
      po_.data(), po_.size(), "en", 2, GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
  EXPECT_EQ((char *)0x1, bytes);
  std::string none = NewId();
  missing = gdefcore_render_entity(catalog_, Req(buyer_), "order", 5,
      none.data(), none.size(), "en", 2, GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, hidden);
  EXPECT_EQ(hidden, missing);
  EXPECT_EQ((char *)0x1, bytes);
  GDEFCORE_Result rc = GDEFCORE_OK;
  Tree(Req(stranger), &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
