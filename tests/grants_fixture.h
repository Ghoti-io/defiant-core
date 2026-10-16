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
 * What the grants tests and the can() tests share: guest modules built from
 * data, and one tenant on the memory backend with the helpers they use.
 */

#ifndef GHOTI_DEFCORE_TEST_GRANTS_FIXTURE_H
#define GHOTI_DEFCORE_TEST_GRANTS_FIXTURE_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#define MODULE_STR2(x) #x
#define MODULE_STR(x) MODULE_STR2(x)

namespace gfx {

const char kTenant[] = "t";
const char kPost[] = "site.post";
const char kCoreToken[] = MODULE_STR(GHOTIIO_DEFCORE_NAME);

/* ---- guest modules built from data ------------------------------------- */

struct ModDef {
  std::string name;
  std::list<std::string> pool;
  std::vector<GDEFCORE_Module_Perm> perms;
  std::vector<GDEFCORE_Module_Grant> grants;
  std::vector<std::string> lines;   /* the confirmation lines the test expects */
  GDEFCORE_Module_Manifest man;

  const char * S(const std::string & s) {
    pool.push_back(s);
    return pool.back().c_str();
  }

  void Perm(const std::string & label, const std::string & action, int condition,
      const std::string & type, const std::string & field = std::string()) {
    GDEFCORE_Module_Perm p;
    memset(&p, 0, sizeof p);
    p.size = sizeof p;
    p.label = S(label);
    p.label_len = label.size();
    p.action = S(action);
    p.action_len = action.size();
    p.condition = condition;
    p.type_name = S(type);
    p.type_name_len = type.size();
    if (!field.empty()) {
      p.field = S(field);
      p.field_len = field.size();
    }
    perms.push_back(p);
    lines.push_back(label);
  }

  void Grant(const std::string & permission, const std::string & type,
      const std::string & condition, const std::string & field = std::string()) {
    GDEFCORE_Module_Grant g;
    memset(&g, 0, sizeof g);
    g.size = sizeof g;
    g.permission = S(permission);
    g.permission_len = permission.size();
    g.type_name = S(type);
    g.type_name_len = type.size();
    if (!field.empty()) {
      g.field = S(field);
      g.field_len = field.size();
    }
    g.condition = S(condition);
    g.condition_len = condition.size();
    grants.push_back(g);
  }

  void Finish() {
    memset(&man, 0, sizeof man);
    man.size = sizeof man;
    man.core_token = kCoreToken;
    man.core_token_len = strlen(kCoreToken);
    man.name = S(name);
    man.name_len = name.size();
    man.label = man.name;
    man.label_len = name.size();
    man.perms = perms.empty() ? NULL : &perms[0];
    man.nperms = perms.size();
    man.grants = grants.empty() ? NULL : &grants[0];
    man.ngrants = grants.size();
  }
};

inline std::vector<std::unique_ptr<ModDef> > & Defs() {
  static std::vector<std::unique_ptr<ModDef> > defs;
  return defs;
}

template <int N>
const GDEFCORE_Module_Manifest * Entry() {
  return &Defs()[N]->man;
}

typedef const GDEFCORE_Module_Manifest * (*EntryFn)(void);
const EntryFn kEntries[] = {Entry<0>, Entry<1>, Entry<2>, Entry<3>, Entry<4>,
    Entry<5>, Entry<6>, Entry<7>};

/* ---- one tenant -------------------------------------------------------- */

inline GDEFCORE_Permission Perm(const char * label, const char * action, int condition,
    const char * type = kPost, const char * field = NULL,
    const char * condition_text = NULL) {
  GDEFCORE_Permission p;
  memset(&p, 0, sizeof p);
  p.size = sizeof p;
  p.label = label;
  p.label_len = strlen(label);
  p.module_name = "site";
  p.module_name_len = 4;
  p.action = action;
  p.action_len = strlen(action);
  p.condition = condition;
  p.type_name = type;
  p.type_name_len = strlen(type);
  if (field != NULL) {
    p.field = field;
    p.field_len = strlen(field);
  }
  if (condition_text != NULL) {
    p.condition_text = condition_text;
    p.condition_text_len = strlen(condition_text);
  }
  return p;
}

inline GDEFCORE_Field Field(const char * name, int personal = 0) {
  GDEFCORE_Field f;
  memset(&f, 0, sizeof f);
  f.size = sizeof f;
  f.name = name;
  f.name_len = strlen(name);
  f.personal = personal;
  return f;
}

inline std::string Join(const std::vector<std::string> & v) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    out += (i > 0 ? "\n" : "") + v[i];
  }
  return out;
}

class GrantsFixture : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  GDEFCORE_Host * host_ = NULL;
  size_t installed_ = 0;
  std::string last_error_;
  std::vector<GDEFCORE_Request *> requests_;

  void SetUp() override {
    Defs().clear();
    Open();
  }

  void TearDown() override {
    Close();
    Defs().clear();
  }

  void Open() {
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
            &catalog_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
    gdefcore_catalog_bind_host(catalog_, host_);
    installed_ = 0;
  }

  void Close() {
    for (size_t i = 0; i < requests_.size(); i++) {
      gdefcore_request_destroy(requests_[i]);
    }
    requests_.clear();
    gdefcore_catalog_bind_host(catalog_, NULL);
    gdefcore_host_destroy(host_);
    gdefcore_catalog_destroy(catalog_);
    gdefstor_store_destroy(store_);
    host_ = NULL;
    catalog_ = NULL;
    store_ = NULL;
  }

  /** A request, anonymous when @p who is empty. Owned by the fixture. */
  GDEFCORE_Request * Req(const std::string & who = std::string(),
      const std::string & acting = std::string()) {
    GDEFCORE_Request * r = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &r));
    if (!who.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_principal(r, who.data(), who.size()));
    }
    if (!acting.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_acting_principal(r, acting.data(), acting.size()));
    }
    requests_.push_back(r);
    return r;
  }

  void DefinePost() {
    GDEFCORE_Field f[4] = {Field("title"), Field("group"), Field("rank"),
        Field("ssn", 1)};
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, kPost, strlen(kPost),
            GDEFCORE_TYPE_CONTENT, f, 4));
  }

  void Declare(const GDEFCORE_Permission & p) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &p));
  }

  void Role(const char * name) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, name, strlen(name), NULL));
  }

  void Grant(const char * role, const char * label) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, role, strlen(role), label, strlen(label),
            "core.role", 9));
  }

  GDEFCORE_Result GrantWhen(const char * role, const char * label,
      const std::string & condition, const char * confirm = "core.role") {
    return gdefcore_access_grant_when(catalog_, role, strlen(role), label,
        strlen(label), condition.data(), condition.size(), confirm,
        confirm == NULL ? 0 : strlen(confirm));
  }

  std::string Principal(const char * role = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    id[0] = '\0';
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, id));
    if (role != NULL) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_access_principal_add_role(catalog_, id, strlen(id), role,
              strlen(role)));
    }
    return std::string(id);
  }

  std::string Admin() {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, id));
    return std::string(id);
  }

  /** A post saved by @p actor. */
  std::string Save(const std::string & actor, const char * title,
      const char * group) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[2];
    const char * texts[2] = {title, group};
    size_t lens[2] = {strlen(title), group == NULL ? 0 : strlen(group)};
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPost, strlen(kPost), id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_,
            actor.empty() ? NULL : actor.data(), actor.size(), &cs));
    memset(values, 0, sizeof values);
    values[0].size = sizeof values[0];
    values[0].field = "title";
    values[0].field_len = 5;
    values[0].texts = &texts[0];
    values[0].text_lens = &lens[0];
    values[0].count = 1;
    values[1].size = sizeof values[1];
    values[1].field = "group";
    values[1].field_len = 5;
    values[1].texts = &texts[1];
    values[1].text_lens = &lens[1];
    values[1].count = group == NULL ? 0 : 1;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, strlen(id), "en", 2, values,
            group == NULL ? 1 : 2));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  /** The title as @p req reads it, or "<denied>" when the read is refused. */
  std::string Read(GDEFCORE_Request * req, const std::string & id,
      const char * field = "title") {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    GDEFCORE_Result rc = gdefcore_access_read(catalog_, req, id.data(), id.size(),
        "en", 2, field, strlen(field), &texts, &lens, &count);
    std::string out;
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    if (count == 0) {
      return "<absent>";
    }
    out.assign(texts[0], lens[0]);
    gdefcore_values_free(catalog_, texts, lens, count);
    return out;
  }

  std::string Read(const std::string & who, const std::string & id,
      const char * field = "title") {
    return Read(Req(who), id, field);
  }

  /** The titles of the posts @p who may list, in id order. */
  std::vector<std::string> List(const std::string & who) {
    GDEFCORE_Access_List q;
    char ** ids = NULL;
    size_t count = 0;
    std::vector<std::string> out;
    GDEFCORE_Request * req = Req(who);
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = kPost;
    q.type_name_len = strlen(kPost);
    q.lang = "en";
    q.lang_len = 2;
    q.sort_field = "title";
    q.sort_field_len = 5;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_list(catalog_, req, &q, &ids, &count));
    for (size_t i = 0; i < count; i++) {
      out.push_back(Read(req, ids[i]));
    }
    gdefcore_access_free(catalog_, ids, count);
    return out;
  }

  int Permits(const std::string & who, const char * action) {
    return gdefcore_access_permits(catalog_, Req(who), action, strlen(action));
  }

  /** Install a module built from @p def; the def is finished here. */
  GDEFCORE_Result Install(ModDef * def) {
    size_t at = Defs().size() - 1;
    def->Finish();
    EXPECT_LT(at, sizeof kEntries / sizeof kEntries[0]);
    return gdefcore_module_install_guest(host_, kEntries[at]);
  }

  ModDef * NewMod(const char * name) {
    Defs().push_back(std::unique_ptr<ModDef>(new ModDef()));
    Defs().back()->name = name;
    return Defs().back().get();
  }

  /** The line the confirmation shows for a grant. */
  static std::string GrantLine(const std::string & module,
      const std::string & label, const char * risk, const std::string & cond) {
    GDEFCORE_Condition * c = NULL;
    char * words = NULL;
    size_t n = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_condition_parse(cond.data(), cond.size(), &c, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_condition_explain(c, &words, &n));
    out = "Module " + module + " grants " + label + " (" + risk + " risk): " +
          std::string(words, n);
    gdefcore_condition_text_free(words);
    gdefcore_condition_free(c);
    return out;
  }

  static std::string Confirmation(const std::string & name,
      std::vector<std::string> lines) {
    std::vector<std::string> all;
    std::sort(lines.begin(), lines.end());
    lines.erase(std::unique(lines.begin(), lines.end()), lines.end());
    all.push_back(name);
    all.insert(all.end(), lines.begin(), lines.end());
    return Join(all);
  }

  /** Stage an enable. The changeset is left to the caller. */
  GDEFCORE_Result Stage(const std::string & name, GDEFCORE_Changeset ** cs) {
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, cs));
    return gdefcore_module_enable(host_, *cs, name.data(), name.size());
  }

  /** Enable with the confirmation @p text. */
  GDEFCORE_Result EnableWith(const std::string & name, const std::string & text) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc = Stage(name, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, text.data(), text.size());
    } else {
      const char * err = gdefcore_module_error(host_, NULL);
      last_error_ = err == NULL ? "" : err;
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /** Enable with the confirmation the module's declarations call for. The
   * lines are the expected words, in the test, for each grant. */
  GDEFCORE_Result Enable(const std::string & name,
      const std::vector<std::string> & grant_lines) {
    std::vector<std::string> lines = grant_lines;
    for (size_t i = 0; i < Defs().size(); i++) {
      if (Defs()[i]->name == name) {
        for (size_t k = 0; k < Defs()[i]->perms.size(); k++) {
          lines.push_back(Defs()[i]->lines[k]);
        }
      }
    }
    return EnableWith(name, Confirmation(name, lines));
  }

  GDEFCORE_Result Disable(const std::string & name) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    rc = gdefcore_module_disable(host_, cs, name.data(), name.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, name.data(), name.size());
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  uint64_t Epoch() {
    uint64_t e = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &e));
    return e;
  }

  struct Row {
    std::string source, permission, action, type, field, condition, explain;
    int risk;
    int from_module;
  };

  /** The matrix as the administrator reads it. */
  std::vector<Row> Matrix(GDEFCORE_Result * rc_out = NULL,
      const std::string & who = std::string()) {
    GDEFCORE_Access_Matrix_Row * rows = NULL;
    size_t n = 0;
    std::vector<Row> out;
    GDEFCORE_Result rc = gdefcore_access_matrix(catalog_,
        Req(who.empty() ? Admin() : who), &rows, &n);
    if (rc_out != NULL) {
      *rc_out = rc;
    }
    for (size_t i = 0; rc == GDEFCORE_OK && i < n; i++) {
      Row r;
      r.source.assign(rows[i].source, rows[i].source_len);
      r.permission.assign(rows[i].permission, rows[i].permission_len);
      r.action.assign(rows[i].action, rows[i].action_len);
      r.type.assign(rows[i].type_name, rows[i].type_name_len);
      r.field.assign(rows[i].field, rows[i].field_len);
      r.condition.assign(rows[i].condition, rows[i].condition_len);
      r.explain.assign(rows[i].explain, rows[i].explain_len);
      r.risk = rows[i].risk;
      r.from_module = rows[i].from_module;
      out.push_back(r);
    }
    gdefcore_access_matrix_free(catalog_, rows, n);
    return out;
  }

  static std::string Dump(const std::vector<Row> & rows) {
    std::string out;
    for (size_t i = 0; i < rows.size(); i++) {
      const Row & r = rows[i];
      out += r.source + "|" + r.permission + "|" + r.action + "|" + r.type + "|" +
             r.field + "|" + r.condition + "|" + r.explain + "|" +
             std::to_string(r.risk) + "|" + std::to_string(r.from_module) + "\n";
    }
    return out;
  }

  static const Row * Find(const std::vector<Row> & rows, const std::string & source,
      const std::string & permission) {
    for (size_t i = 0; i < rows.size(); i++) {
      if (rows[i].source == source && rows[i].permission == permission) {
        return &rows[i];
      }
    }
    return NULL;
  }
};

}  // namespace gfx

#endif /* GHOTI_DEFCORE_TEST_GRANTS_FIXTURE_H */
