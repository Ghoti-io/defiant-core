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
#include <ghoti.io/defiant-storage-sqlite/model.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <filesystem>
#include <list>
#include <map>
#include <memory>
#include <random>
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
  std::vector<GDEFCORE_Module_Relation> relations;
  std::list<std::vector<GDEFCORE_Module_Relation_Column> > relation_columns;
  std::vector<std::string> lines;   /* the confirmation lines the test expects */
  /* Access callbacks (story A6), each with the service that carries it. */
  std::list<GDEFCORE_Module_Access_Callback> callback_tables;
  std::vector<GDEFCORE_Module_Service> services;
  std::vector<GDEFCORE_Module_Callback> callbacks;
  std::vector<GDEFCORE_Module_Sub> subs;
  /* Routes and menu links (site admin story 5), and the one handler service
   * every route names: a handler that does nothing, as these tests only ask
   * what a path reaches. */
  struct RouteDef {
    std::string name, path, permission, title, parent, entity_capture;
    int weight = 0;
    int kind = GDEFCORE_ROUTE_PAGE;
    int is_default = 0;
    int admin = 0;
  };
  struct LinkDef {
    std::string name, menu, label, route, parent;
    int weight = 0;
    int kind = GDEFCORE_ROUTE_PAGE;
  };
  std::vector<RouteDef> route_defs;
  std::vector<LinkDef> link_defs;
  std::vector<GDEFCORE_Module_Route> routes;
  std::vector<GDEFCORE_Module_Link> links;
  GDEFCORE_Module_Route_Handler route_handler;
  /* Contributors and widget types (site admin story 7), each with the service
   * that carries its function. */
  std::vector<GDEFCORE_Module_Contributor> contributors;
  std::list<GDEFCORE_Module_Contributor_Handler> contributor_handlers;
  std::vector<GDEFCORE_Module_Widget> widgets;
  std::list<GDEFCORE_Module_Widget_Provider> widget_providers;
  GDEFCORE_Module_Manifest man;

  static void NoRoute(const GDEFCORE_Route_Call * call) { (void)call; }

  /** A route. A tab names its @p parent; a permission its entity capture. */
  RouteDef & Route(const std::string & route_name, const std::string & path,
      const std::string & title = std::string(),
      const std::string & permission = std::string(),
      const std::string & entity_capture = std::string()) {
    RouteDef r;
    r.name = route_name;
    r.path = path;
    r.title = title;
    r.permission = permission;
    r.entity_capture = entity_capture;
    route_defs.push_back(r);
    return route_defs.back();
  }

  /** A tab of @p parent. */
  RouteDef & Tab(const std::string & route_name, const std::string & path,
      const std::string & parent, const std::string & title, int weight = 0,
      const std::string & permission = std::string(),
      const std::string & entity_capture = std::string(), int is_default = 0) {
    RouteDef & r = Route(route_name, path, title, permission, entity_capture);
    r.kind = GDEFCORE_ROUTE_TAB;
    r.parent = parent;
    r.weight = weight;
    r.is_default = is_default;
    return r;
  }

  /** A menu link. */
  LinkDef & Link(const std::string & link_name, const std::string & menu,
      const std::string & label, const std::string & route, int weight = 0,
      const std::string & parent = std::string()) {
    LinkDef l;
    l.name = link_name;
    l.menu = menu;
    l.label = label;
    l.route = route;
    l.weight = weight;
    l.parent = parent;
    link_defs.push_back(l);
    return link_defs.back();
  }

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

  /** A contributor of @p kind at @p path (a route pattern), a function of the
   * module's, with the service that carries it named `<module>.c.<name>`. */
  GDEFCORE_Module_Contributor & Contributor(const std::string & contributor_name,
      const std::string & kind, const std::string & path,
      GDEFCORE_Contributor_Fn fn, void * data = NULL, int exact = 0,
      int weight = 0) {
    GDEFCORE_Module_Contributor_Handler h;
    GDEFCORE_Module_Service svc;
    GDEFCORE_Module_Contributor c;
    std::string service = name + ".c." + contributor_name;
    memset(&h, 0, sizeof h);
    h.size = sizeof h;
    h.fn = fn;
    h.data = data;
    contributor_handlers.push_back(h);
    memset(&svc, 0, sizeof svc);
    svc.size = sizeof svc;
    svc.name = S(service);
    svc.name_len = service.size();
    svc.version = GDEFCORE_MODULE_CONTRIBUTOR_HANDLER_VERSION;
    svc.table = &contributor_handlers.back();
    services.push_back(svc);
    memset(&c, 0, sizeof c);
    c.size = sizeof c;
    c.name = S(name + "." + contributor_name);
    c.name_len = name.size() + 1 + contributor_name.size();
    c.kind = S(kind);
    c.kind_len = kind.size();
    c.path = S(path);
    c.path_len = path.size();
    c.exact = exact;
    c.weight = weight;
    c.handler = svc.name;
    c.handler_len = svc.name_len;
    contributors.push_back(c);
    return contributors.back();
  }

  /** A widget type `<module>.<widget_name>` drawn with template kind @p kind. */
  GDEFCORE_Module_Widget & Widget(const std::string & widget_name,
      const std::string & kind, GDEFCORE_Widget_Fn fn, void * user = NULL,
      const std::string & permission = std::string(),
      const std::string & template_name = std::string()) {
    GDEFCORE_Module_Widget_Provider p;
    GDEFCORE_Module_Service svc;
    GDEFCORE_Module_Widget w;
    std::string service = name + ".w." + widget_name;
    memset(&p, 0, sizeof p);
    p.size = sizeof p;
    p.fn = fn;
    p.user = user;
    widget_providers.push_back(p);
    memset(&svc, 0, sizeof svc);
    svc.size = sizeof svc;
    svc.name = S(service);
    svc.name_len = service.size();
    svc.version = GDEFCORE_MODULE_WIDGET_PROVIDER_VERSION;
    svc.table = &widget_providers.back();
    services.push_back(svc);
    memset(&w, 0, sizeof w);
    w.size = sizeof w;
    w.name = S(name + "." + widget_name);
    w.name_len = name.size() + 1 + widget_name.size();
    w.kind = S(kind);
    w.kind_len = kind.size();
    if (!template_name.empty()) {
      w.template_name = S(template_name);
      w.template_len = template_name.size();
    }
    if (!permission.empty()) {
      w.permission = S(permission);
      w.permission_len = permission.size();
    }
    w.provider = svc.name;
    w.provider_len = svc.name_len;
    widgets.push_back(w);
    return widgets.back();
  }

  /** A subscription to a hook. */
  void Sub(const std::string & hook, int kind, GDEFCORE_Hook_Fn fn, void * user) {
    GDEFCORE_Module_Sub sub;
    memset(&sub, 0, sizeof sub);
    sub.size = sizeof sub;
    sub.hook = S(hook);
    sub.hook_len = hook.size();
    sub.kind = kind;
    sub.fn = fn;
    sub.user = user;
    subs.push_back(sub);
  }

  /** A relation: its columns as (name, kind, type). */
  struct Col {
    std::string name;
    int kind;
    std::string type;
  };

  void Relation(const std::string & relation_name, const std::vector<Col> & cols) {
    std::vector<GDEFCORE_Module_Relation_Column> columns;
    GDEFCORE_Module_Relation r;
    for (const Col & c : cols) {
      GDEFCORE_Module_Relation_Column column;
      memset(&column, 0, sizeof column);
      column.size = sizeof column;
      column.name = S(c.name);
      column.name_len = c.name.size();
      column.kind = c.kind;
      if (!c.type.empty()) {
        column.type_name = S(c.type);
        column.type_name_len = c.type.size();
      }
      columns.push_back(column);
    }
    relation_columns.push_back(columns);
    memset(&r, 0, sizeof r);
    r.size = sizeof r;
    r.name = S(relation_name);
    r.name_len = relation_name.size();
    r.columns = relation_columns.back().data();
    r.ncolumns = relation_columns.back().size();
    relations.push_back(r);
  }

  /** An access callback: its service is `<module>.cb.<name>`. */
  GDEFCORE_Module_Callback & Callback(const std::string & cb_name, int scope,
      const std::string & permission, const std::string & type,
      const std::string & field, GDEFCORE_Callback_Fn fn, void * user,
      int cache = GDEFCORE_CALLBACK_CACHE_TOKEN, int flags = 0) {
    GDEFCORE_Module_Access_Callback t;
    GDEFCORE_Module_Service svc;
    GDEFCORE_Module_Callback c;
    std::string service = name + ".cb." + cb_name;
    memset(&t, 0, sizeof t);
    t.size = sizeof t;
    t.fn = fn;
    t.user = user;
    callback_tables.push_back(t);
    memset(&svc, 0, sizeof svc);
    svc.size = sizeof svc;
    svc.name = S(service);
    svc.name_len = service.size();
    svc.version = GDEFCORE_MODULE_ACCESS_CALLBACK_VERSION;
    svc.table = &callback_tables.back();
    services.push_back(svc);
    memset(&c, 0, sizeof c);
    c.size = sizeof c;
    c.name = S(cb_name);
    c.name_len = cb_name.size();
    c.scope = scope;
    c.permission = S(permission);
    c.permission_len = permission.size();
    c.type_name = S(type);
    c.type_name_len = type.size();
    if (!field.empty()) {
      c.field = S(field);
      c.field_len = field.size();
    }
    c.service = svc.name;
    c.service_len = svc.name_len;
    c.fuel = 100;
    c.timeout_ms = 500;
    c.cache = cache;
    c.ttl_seconds = cache == GDEFCORE_CALLBACK_CACHE_TTL ? 60 : 0;
    c.flags = flags;
    callbacks.push_back(c);
    return callbacks.back();
  }

  void Finish() {
    std::string handler = name + ".route";
    routes.clear();
    links.clear();
    bool has_handler = false;
    for (const GDEFCORE_Module_Service & have : services) {
      has_handler = has_handler || (have.name_len == handler.size() &&
                                    memcmp(have.name, handler.data(), have.name_len) == 0);
    }
    if (!route_defs.empty() && !has_handler) {
      GDEFCORE_Module_Service svc;
      memset(&route_handler, 0, sizeof route_handler);
      route_handler.size = sizeof route_handler;
      route_handler.call_fn = NoRoute;
      memset(&svc, 0, sizeof svc);
      svc.size = sizeof svc;
      svc.name = S(handler);
      svc.name_len = handler.size();
      svc.version = GDEFCORE_MODULE_ROUTE_HANDLER_VERSION;
      svc.table = &route_handler;
      services.push_back(svc);
    }
    for (const RouteDef & d : route_defs) {
      GDEFCORE_Module_Route r;
      memset(&r, 0, sizeof r);
      r.size = sizeof r;
      r.name = S(d.name);
      r.name_len = d.name.size();
      r.path = S(d.path);
      r.path_len = d.path.size();
      r.weight = d.weight;
      if (!d.permission.empty()) {
        r.permission = S(d.permission);
        r.permission_len = d.permission.size();
      }
      if (!d.title.empty()) {
        r.title = S(d.title);
        r.title_len = d.title.size();
      }
      r.kind = d.kind;
      if (!d.parent.empty()) {
        r.parent = S(d.parent);
        r.parent_len = d.parent.size();
      }
      r.is_default = d.is_default;
      r.admin = d.admin;
      r.handler = S(handler);
      r.handler_len = handler.size();
      if (!d.entity_capture.empty()) {
        r.entity_capture = S(d.entity_capture);
        r.entity_capture_len = d.entity_capture.size();
      }
      routes.push_back(r);
    }
    for (const LinkDef & d : link_defs) {
      GDEFCORE_Module_Link l;
      memset(&l, 0, sizeof l);
      l.size = sizeof l;
      l.name = S(d.name);
      l.name_len = d.name.size();
      l.menu = S(d.menu);
      l.menu_len = d.menu.size();
      l.label = S(d.label);
      l.label_len = d.label.size();
      l.route = S(d.route);
      l.route_len = d.route.size();
      l.weight = d.weight;
      if (!d.parent.empty()) {
        l.parent = S(d.parent);
        l.parent_len = d.parent.size();
      }
      l.kind = d.kind;
      links.push_back(l);
    }
    memset(&man, 0, sizeof man);
    man.size = sizeof man;
    man.core_token = kCoreToken;
    man.core_token_len = strlen(kCoreToken);
    man.schema_version = 1;
    man.name = S(name);
    man.name_len = name.size();
    man.label = man.name;
    man.label_len = name.size();
    man.perms = perms.empty() ? NULL : &perms[0];
    man.nperms = perms.size();
    man.grants = grants.empty() ? NULL : &grants[0];
    man.ngrants = grants.size();
    man.relations = relations.empty() ? NULL : &relations[0];
    man.nrelations = relations.size();
    man.services = services.empty() ? NULL : &services[0];
    man.nservices = services.size();
    man.callbacks = callbacks.empty() ? NULL : &callbacks[0];
    man.ncallbacks = callbacks.size();
    man.subs = subs.empty() ? NULL : &subs[0];
    man.nsubs = subs.size();
    man.routes = routes.empty() ? NULL : &routes[0];
    man.nroutes = routes.size();
    man.links = links.empty() ? NULL : &links[0];
    man.nlinks = links.size();
    man.contributors = contributors.empty() ? NULL : &contributors[0];
    man.ncontributors = contributors.size();
    man.widgets = widgets.empty() ? NULL : &widgets[0];
    man.nwidgets = widgets.size();
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
  /* A test may ask for SQLite (in a directory made for it) or for a catalog
   * allocator of its own before it calls Open() again. */
  bool use_sqlite_ = false;
  std::string sqlite_dir_;
  const GDEFCORE_Allocator * catalog_alloc_ = NULL;

  void SetUp() override {
    Defs().clear();
    Open();
  }

  void TearDown() override {
    Close();
    Defs().clear();
  }

  void Open() {
    if (use_sqlite_) {
      std::error_code ec;
      std::filesystem::path base = std::filesystem::temp_directory_path(ec);
      std::random_device entropy;
      for (int i = 0; i < 100 && sqlite_dir_.empty(); i++) {
        std::filesystem::path p =
            base / ("gdefcore-grants-" + std::to_string(entropy()));
        if (std::filesystem::create_directory(p, ec) && !ec) {
          sqlite_dir_ = p.string();
        }
      }
      ASSERT_FALSE(sqlite_dir_.empty());
      /* The entity port's store (story S6b), with no fsync: these tests open
       * many stores and are not about the disk. */
      GDEFSSQLITE_ModelOptions o;
      gdefssqlite_model_options_default(&o);
      o.synchronous = GDEFSSQLITE_SYNC_OFF;
      ASSERT_EQ(GDEFSSQLITE_OK,
          gdefssqlite_model_store_create(sqlite_dir_.c_str(), &o, NULL, NULL,
              &store_));
    } else {
      ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL,
            catalog_alloc_, &catalog_));
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
    if (!sqlite_dir_.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(sqlite_dir_, ec);
      sqlite_dir_.clear();
    }
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

  /* `ssn` is personal: its subject is the `who` reference beside it (story
   * S7: every personal field names its subject source). */
  void DefinePost() {
    GDEFCORE_Field f[5] = {Field("title"), Field("group"), Field("rank"),
        Field("ssn", 1), Field("who")};
    f[3].subject = "who";
    f[3].subject_len = 3;
    f[4].type = GDEFSTOR_FIELD_REFERENCE;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, kPost, strlen(kPost),
            GDEFCORE_TYPE_CONTENT, f, 5));
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
        "en", 2, field, strlen(field), &texts, &lens, &count, NULL);
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
      if (rc != GDEFCORE_OK) {
        size_t why_len = 0;
        const char * why = gdefcore_changeset_refusal(cs, &why_len);
        const char * merr = gdefcore_module_error(host_, NULL);
        char * diff = NULL;
        size_t diff_len = 0;
        (void)gdefcore_changeset_diff(cs, &diff, &diff_len);
        last_error_ = std::string(why == NULL ? "" : std::string(why, why_len).c_str()) +
                      " | " + (merr == NULL ? "" : merr) + " | wanted: " + text +
                      " | diff: " + (diff == NULL ? "" : std::string(diff, diff_len));
        gdefcore_text_free(catalog_, diff);
      }
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
