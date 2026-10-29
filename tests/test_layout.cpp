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
 * Widget types and layouts chosen through the route trie (site admin story
 * 7). A layout places widgets into the regions its page template declares; a
 * rule or a module's contributor chooses it by path, most specific first, in an
 * order that does not depend on registration; an alter hook may refine the
 * choice and can deny nothing.
 *
 * Every test carries a CONTROL: the viewer, the module or the order that DOES
 * get the thing the others do not, so a refusal is a refusal and not an empty
 * page. The real-source plants are in tools/check-layout.sh, and each names the
 * test that must turn red.
 */

#include "grants_fixture.h"
#include "size_structs.h"

namespace {

using namespace gfx;

const char kRule[] = "core.layout-rule";
const char kDisplay[] = "core.display";

/* A route handler that owns the request, as a page does. */
void OwnPage(const GDEFCORE_Route_Call * call) {
  const char * v = NULL;
  size_t n = 0;
  if (gdefcore_route_call_capture(call, "id", 2, &v, &n)) {
    gdefcore_request_set_resolution(call->request, v, n);
  }
}

/* ---- contributors, widget providers and hooks the tests install ---------- */

struct Offering {
  const char * layout;
  int calls = 0;
  /* What the contributor tries besides offering. */
  const char * hijack = NULL;   /* a resolution to set */
  size_t seen_size = 0;         /* the size the call carried */
  GDEFCORE_Result own_offer = GDEFCORE_OK;
  bool sized = false;           /* offer at offer_size, not at sizeof */
  size_t offer_size = 0;
};

void Offer(const GDEFCORE_Contributor_Call * call) {
  Offering * o = (Offering *)call->data;
  GDEFCORE_Offer offer;
  o->calls += 1;
  o->seen_size = call->size;
  if (o->hijack != NULL) {
    (void)gdefcore_request_set_resolution(call->request, o->hijack,
        strlen(o->hijack));
    (void)gdefcore_request_set_note(call->request, "hijack", 6, "yes", 3);
  }
  memset(&offer, 0, sizeof offer);
  offer.size = o->sized ? o->offer_size : sizeof offer;
  offer.value = o->layout;
  offer.value_len = strlen(o->layout);
  o->own_offer = gdefcore_contributor_offer(call, &offer);
}

struct Ticker {
  int calls = 0;
  std::string target;
};

GDEFCORE_Result TickerFn(GDEFCORE_Request * request, const char * target,
    size_t target_len, GDEFCORE_Widget_Sink * sink, void * user) {
  Ticker * t = (Ticker *)user;
  std::string text = "Ticker:" + std::string(target, target_len);
  (void)request;
  t->calls += 1;
  t->target.assign(target, target_len);
  return gdefcore_widget_bind_text(sink, "title", 5, text.data(), text.size());
}

/* A refinement of the layout: for the principal named, another layout; with
 * `deny`, every wrong thing a hook could try. */
struct Refine {
  std::string who;       /* the principal it refines for ("" for everyone) */
  std::string when;      /* the layout it refines (""  for any) */
  std::string to;        /* the layout it names */
  int deny = 0;          /* report a denial as well */
  int fail = 0;          /* fail */
  int calls = 0;
  size_t seen_size = 0;
  std::string saw_path;
};

GDEFCORE_Result RefineFn(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  Refine * r = (Refine *)user;
  const GDEFCORE_Layout_Hook * hook = (const GDEFCORE_Layout_Hook *)args;
  size_t n = 0;
  const char * who = gdefcore_request_principal(request, &n);
  const char * text = NULL;
  size_t text_len = 0;
  r->calls += 1;
  r->seen_size = hook->size;
  r->saw_path.assign(hook->path, hook->path_len);
  if (r->deny) {
    out->decision = GDEFCORE_DECISION_DENY;
  }
  if (r->fail) {
    return GDEFCORE_ERR_INTERNAL;
  }
  (void)gdefcore_alter_text(alter, &text, &text_len);
  if ((r->who.empty() || (who != NULL && r->who == std::string(who, n))) &&
      (r->when.empty() || r->when == std::string(text, text_len))) {
    return gdefcore_alter_set(alter, r->to.data(), r->to.size());
  }
  return GDEFCORE_OK;
}

class Layouts : public GrantsFixture {
 protected:
  std::vector<GDEFCORE_Routes *> tables_;
  std::string alpha_, beta_;
  std::string reader_, vip_, layouter_;
  std::string refusal_;

  void SetUp() override {
    GrantsFixture::SetUp();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "authenticated", 13, "Read posts", 10,
            GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
            strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED)));
    Declare(Perm("Read news", "news.read", GDEFCORE_ACCESS_ANY));
    Role("layouters");
    Grant("layouters", GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL);
    Grant("layouters", GDEFCORE_LAYOUT_EDIT_RULE_LABEL);
    Role("newsreaders");
    Grant("newsreaders", "Read news");
    layouter_ = Principal("layouters");
    vip_ = Principal("newsreaders");
    reader_ = Principal();
    alpha_ = SaveNode("Alpha", "Alpha body");
    beta_ = SaveNode("Beta", "Beta body");
  }

  /* A world of its own with the kit installed, for a probe that wants one. */
  void Fresh() {
    for (GDEFCORE_Routes * t : tables_) {
      gdefcore_routes_destroy(t);
    }
    tables_.clear();
    Close();
    Defs().clear();
    Open();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
  }

  void TearDown() override {
    for (GDEFCORE_Routes * t : tables_) {
      gdefcore_routes_destroy(t);
    }
    tables_.clear();
    GrantsFixture::TearDown();
  }

  std::string SaveNode(const char * title, const char * body,
      GDEFCORE_Catalog * catalog = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[2];
    const char * slots[2] = {title, body};
    size_t lens[2] = {strlen(title), strlen(body)};
    GDEFCORE_Catalog * c = catalog != NULL ? catalog : catalog_;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_create(c, kPost, strlen(kPost), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(c, NULL, 0, &cs));
    for (int i = 0; i < 2; i++) {
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = i == 0 ? "title" : "body";
      values[i].field_len = i == 0 ? 5 : 4;
      values[i].texts = &slots[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, values, 2));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  /* A route table with the pages the tests go to: /page/<id> and /news/<id>
   * own the request and resolve to the entity, as a content handler does. The
   * enabled modules' contributors are added to it. */
  GDEFCORE_Routes * Table() {
    GDEFCORE_Routes * routes = NULL;
    char * err = NULL;
    size_t err_len = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes,
                               gdefcore_access_route_check, catalog_));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_module_add_routes(host_, (const uint8_t *)kTenant,
                               1, NULL, routes, &err, &err_len))
        << (err == NULL ? "" : std::string(err, err_len));
    gdefcore_routes_free(routes, err);
    for (const char * path : {"/page/:id", "/news/:id"}) {
      GDEFCORE_Route_Spec spec;
      memset(&spec, 0, sizeof spec);
      spec.size = sizeof spec;
      std::string machine = std::string("test.") + (path[1] == 'p' ? "page" : "news");
      spec.machine = machine.c_str();
      spec.machine_len = machine.size();
      spec.path = path;
      spec.path_len = strlen(path);
      spec.call_fn = OwnPage;
      spec.title = "Page";
      spec.title_len = 4;
      spec.permission = "read";
      spec.permission_len = 4;
      spec.entity_capture = "id";
      spec.entity_capture_len = 2;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes, &spec, NULL, NULL));
    }
    tables_.push_back(routes);
    return routes;
  }

  GDEFCORE_Request * TenantReq(const char * tenant, size_t tenant_len,
      const std::string & who = std::string()) {
    GDEFCORE_Request * r = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_create((const uint8_t *)tenant,
                               tenant_len, 0, 0, NULL, &r));
    requests_.push_back(r);
    if (!who.empty()) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(r, who.data(), who.size()));
    }
    return r;
  }

  /* The page as @p who sees it, "<error ...>" when there is none. */
  std::string Show(const std::string & who, const std::string & path,
      GDEFCORE_Routes * routes = NULL, GDEFCORE_Catalog * catalog = NULL,
      GDEFCORE_Request * request = NULL) {
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Catalog * c = catalog != NULL ? catalog : catalog_;
    GDEFCORE_Result rc = gdefcore_render_page(c, routes, request != NULL ? request : Req(who),
        path.data(), path.size(), GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
    if (rc != GDEFCORE_OK) {
      return std::string("<error ") + gdefcore_result_string(rc) + ">";
    }
    std::string out(bytes, n);
    gdefcore_text_free(c, bytes);
    return out;
  }

  /* The layout chosen for a page, "<none>" when no layout applies. */
  std::string Chosen(const std::string & who, const std::string & path,
      GDEFCORE_Routes * routes) {
    GDEFCORE_Request * req = Req(who);
    char * resolved = NULL;
    size_t resolved_len = 0;
    char * name = NULL;
    size_t name_len = 0;
    std::string out = "<none>";
    if (path != "/") {
      if (gdefcore_form_resolve(routes, catalog_, req, path.data(), path.size(),
              &resolved, &resolved_len) == GDEFCORE_OK) {
        gdefcore_request_set_resolution(req, resolved, resolved_len);
        gdefcore_text_free(catalog_, resolved);
      }
    }
    if (gdefcore_layout_select(catalog_, routes, req, path.data(), path.size(),
            &name, &name_len) == GDEFCORE_OK) {
      out.assign(name, name_len);
      gdefcore_text_free(catalog_, name);
    }
    return out;
  }

  std::string IdOf(const char * type, const char * name,
      GDEFCORE_Catalog * catalog = NULL) {
    GDEFCORE_Catalog * c = catalog != NULL ? catalog : catalog_;
    char ** ids = NULL;
    size_t n = 0;
    std::string found;
    if (gdefcore_entity_ids(c, type, strlen(type), &ids, &n) != GDEFCORE_OK) {
      return found;
    }
    for (size_t i = 0; i < n && found.empty(); i++) {
      char ** t = NULL;
      size_t * l = NULL;
      size_t cnt = 0;
      if (gdefcore_entity_values(c, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              strlen(ids[i]), "en", 2, "name", 4, &t, &l, &cnt) != GDEFCORE_OK) {
        continue;
      }
      if (cnt > 0 && std::string(t[0], l[0]) == name) {
        found = ids[i];
      }
      gdefcore_values_free(c, t, l, cnt);
    }
    gdefcore_ids_free(c, ids, n);
    return found;
  }

  /* Save a core.template, made if there is none. */
  GDEFCORE_Result PutTemplate(const char * name, const char * kind,
      const std::string & body) {
    std::string id = IdOf("core.template", name);
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * slots[3] = {name, body.c_str(), kind};
    size_t lens[3] = {strlen(name), body.size(), strlen(kind)};
    const char * fields[3] = {"name", "body", "kind"};
    char fresh[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (id.empty()) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, "core.template", 13,
                                 fresh, NULL));
      id = fresh;
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    for (int i = 0; i < 3; i++) {
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = fields[i];
      values[i].field_len = strlen(fields[i]);
      values[i].texts = &slots[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id.data(), id.size(), "en", 2,
                               values, 3));
    GDEFCORE_Result rc = gdefcore_changeset_apply(cs, "core.template", 13);
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  void Remember(GDEFCORE_Changeset * cs) {
    size_t n = 0;
    const char * why = gdefcore_changeset_refusal(cs, &n);
    refusal_ = why == NULL ? "" : std::string(why, n);
  }

  /* Save a layout (`core.display`) of page template @p tmpl with @p panes,
   * made if there is none. The result is apply's. */
  GDEFCORE_Result PutLayout(const char * name, const char * tmpl,
      const std::vector<std::string> & panes, GDEFCORE_Request * request = NULL,
      bool create = true) {
    std::string id = IdOf(kDisplay, name);
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[3];
    const char * slots1[1] = {name};
    size_t lens1[1] = {strlen(name)};
    const char * slots2[1] = {tmpl};
    size_t lens2[1] = {strlen(tmpl)};
    std::vector<const char *> slots3;
    std::vector<size_t> lens3;
    char fresh[GDEFCORE_PUBLIC_ID_LEN + 1];
    if (id.empty()) {
      if (!create) {
        return GDEFCORE_ERR_INVALID;
      }
      EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kDisplay, strlen(kDisplay),
                                 fresh, NULL));
      id = fresh;
    }
    for (const std::string & p : panes) {
      slots3.push_back(p.c_str());
      lens3.push_back(p.size());
    }
    memset(values, 0, sizeof values);
    values[0].size = sizeof values[0];
    values[0].field = "name";
    values[0].field_len = 4;
    values[0].texts = slots1;
    values[0].text_lens = lens1;
    values[0].count = 1;
    values[1].size = sizeof values[1];
    values[1].field = "layout";
    values[1].field_len = 6;
    values[1].texts = slots2;
    values[1].text_lens = lens2;
    values[1].count = 1;
    values[2].size = sizeof values[2];
    values[2].field = "panes";
    values[2].field_len = 5;
    values[2].texts = slots3.data();
    values[2].text_lens = lens3.data();
    values[2].count = slots3.size();
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_entity_save(cs, id.data(), id.size(), "en", 2,
        values, 3);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, kDisplay, strlen(kDisplay));
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* The panes of a stored layout, one per line. */
  std::string PanesOf(const char * name) {
    std::string id = IdOf(kDisplay, name);
    char ** t = NULL;
    size_t * l = NULL;
    size_t c = 0;
    std::string out;
    if (id.empty() || gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED,
                          id.data(), id.size(), "en", 2, "panes", 5, &t, &l, &c) !=
                          GDEFCORE_OK) {
      return "<none>";
    }
    for (size_t i = 0; i < c; i++) {
      out += std::string(t[i], l[i]) + "\n";
    }
    gdefcore_values_free(catalog_, t, l, c);
    return out;
  }

  /* A rule of the site. */
  GDEFCORE_Result PutRule(const char * name, const char * path, const char * layout,
      const char * type = NULL, int exact = 0, int weight = 0,
      GDEFCORE_Catalog * catalog = NULL, GDEFCORE_Request * request = NULL) {
    GDEFCORE_Catalog * c = catalog != NULL ? catalog : catalog_;
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Layout_Rule rule;
    memset(&rule, 0, sizeof rule);
    rule.size = sizeof rule;
    rule.path = path;
    rule.path_len = strlen(path);
    rule.layout = layout;
    rule.layout_len = strlen(layout);
    rule.type = type;
    rule.type_len = type == NULL ? 0 : strlen(type);
    rule.exact = exact;
    rule.weight = weight;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(c, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_layout_stage_rule(cs, name, strlen(name), &rule);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, kRule, strlen(kRule));
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Forget(const char * name) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    GDEFCORE_Result rc = gdefcore_layout_stage_forget(cs, name, strlen(name));
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, kRule, strlen(kRule));
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* The offers for a path, "value@source" in order. */
  std::string Offers(GDEFCORE_Routes * routes, const std::string & path,
      const std::string & who = std::string()) {
    GDEFCORE_Offers * offers = NULL;
    std::string out;
    GDEFCORE_Result rc = gdefcore_routes_offers(routes, catalog_, Req(who),
        GDEFCORE_CONTRIBUTOR_LAYOUT, sizeof GDEFCORE_CONTRIBUTOR_LAYOUT - 1,
        path.data(), path.size(), &offers);
    if (rc != GDEFCORE_OK) {
      return std::string("<error ") + gdefcore_result_string(rc) + ">";
    }
    for (size_t i = 0; i < gdefcore_offers_count(offers); i++) {
      const char * v = NULL;
      const char * s = NULL;
      size_t vl = 0;
      size_t sl = 0;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_offers_at(offers, i, &v, &vl, &s, &sl));
      out += (i > 0 ? " " : "") + std::string(v, vl) + "@" + std::string(s, sl);
    }
    gdefcore_offers_free(offers);
    return out;
  }

  GDEFCORE_Result AddContributor(GDEFCORE_Routes * routes, const char * machine,
      const char * path, GDEFCORE_Contributor_Fn fn, void * data, int exact = 0,
      int weight = 0, const char * kind = GDEFCORE_CONTRIBUTOR_LAYOUT) {
    GDEFCORE_Contributor_Spec spec;
    memset(&spec, 0, sizeof spec);
    spec.size = sizeof spec;
    spec.kind = kind;
    spec.kind_len = strlen(kind);
    spec.machine = machine;
    spec.machine_len = strlen(machine);
    spec.path = path;
    spec.path_len = strlen(path);
    spec.exact = exact;
    spec.weight = weight;
    spec.fn = fn;
    spec.data = data;
    return gdefcore_routes_add_contributor(routes, &spec, NULL, NULL);
  }
};

/* ---- the catalog ------------------------------------------------------------ */

TEST_F(Layouts, TheKitMovesTheFrontAndPostDisplaysOntoLayoutsChosenByRules) {
  GDEFCORE_Routes * routes = Table();
  /* The rules are data, and the displays are layouts. */
  EXPECT_FALSE(IdOf(kRule, "site.front").empty());
  EXPECT_FALSE(IdOf(kRule, "site.post").empty());
  EXPECT_EQ("front", Chosen("", "/", routes));
  EXPECT_EQ("post", Chosen("", "/page/" + alpha_, routes));
  std::string front = Show("", "/", routes);
  EXPECT_NE(std::string::npos, front.find("class=\"recent\"")) << front;
  EXPECT_NE(std::string::npos, front.find("Alpha")) << front;
  std::string post = Show("", "/page/" + alpha_, routes);
  EXPECT_NE(std::string::npos, post.find("<article class=\"post\"><h1>Alpha</h1>")) << post;
  EXPECT_EQ(std::string::npos, post.find("class=\"recent\"")) << post;
  /* CONTROL: no route table at all is the same two pages. */
  EXPECT_EQ(front, Show("", "/"));
  /* A page no rule reaches is what an unknown path is. */
  ASSERT_EQ(GDEFCORE_OK, Forget("site.post"));
  EXPECT_EQ("<none>", Chosen("", "/page/" + alpha_, routes));
  EXPECT_EQ("<error Invalid argument>", Show("", "/page/" + alpha_, routes));
  EXPECT_EQ(front, Show("", "/", routes)) << "the front page is a rule of its own";
}

TEST_F(Layouts, TheCatalogHasEightTypesAndAModuleAddsMore) {
  EXPECT_EQ(8u, gdefcore_layout_widget_count(catalog_));
  const char * kinds[8][2] = {{"sitename", "core.sitename"}, {"title", "core.title"},
      {"content", "core.pane"}, {"menu", "core.menu"}, {"tabs", "core.tabs"},
      {"breadcrumbs", "core.breadcrumbs"}, {"messages", "core.messages"},
      {"recent", "core.pane"}};
  for (size_t i = 0; i < 8; i++) {
    GDEFCORE_Layout_Widget w;
    memset(&w, 0, sizeof w);
    w.size = sizeof w;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_layout_widget_at(catalog_, i, &w));
    EXPECT_EQ(kinds[i][0], std::string(w.name, w.name_len));
    EXPECT_EQ(kinds[i][1], std::string(w.kind, w.kind_len));
    EXPECT_EQ(static_cast<int>(i) + 1, w.builtin);
    /* Each type's template kind and its default template are stored data. */
    EXPECT_FALSE(IdOf("core.template-kind", kinds[i][1]).empty()) << kinds[i][1];
    EXPECT_FALSE(IdOf("core.template", std::string(w.template_name, w.template_len).c_str()).empty())
        << std::string(w.template_name, w.template_len);
  }
  GDEFCORE_Layout_Widget past;
  memset(&past, 0, sizeof past);
  past.size = sizeof past;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_widget_at(catalog_, 8, &past));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_widget_find(catalog_, "news.ticker", 11, &past));
  /* A module adds one, with no change to the kernel; it is the module's while
   * it is enabled. */
  Ticker ticker;
  ModDef * news = NewMod("news");
  news->Widget("ticker", "core.pane", TickerFn, &ticker);
  ASSERT_EQ(GDEFCORE_OK, Install(news));
  EXPECT_EQ(8u, gdefcore_layout_widget_count(catalog_)) << "installed, not enabled";
  ASSERT_EQ(GDEFCORE_OK, Enable("news", {})) << last_error_;
  EXPECT_EQ(9u, gdefcore_layout_widget_count(catalog_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_layout_widget_find(catalog_, "news.ticker", 11, &past));
  EXPECT_EQ("news", std::string(past.module, past.module_len));
  EXPECT_EQ(0, past.builtin);
  EXPECT_EQ("news.ticker", std::string(past.template_name, past.template_len));
  ASSERT_EQ(GDEFCORE_OK, Disable("news"));
  EXPECT_EQ(8u, gdefcore_layout_widget_count(catalog_));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_widget_find(catalog_, "news.ticker", 11, &past));
}

TEST_F(Layouts, AModuleWidgetAndSelectorChangeAPageWithNoKernelChange) {
  Ticker ticker;
  Offering offering;
  offering.layout = "news";
  ModDef * news = NewMod("news");
  news->Widget("ticker", "core.pane", TickerFn, &ticker);
  news->Contributor("skin", GDEFCORE_CONTRIBUTOR_LAYOUT, "/news", Offer, &offering);
  ASSERT_EQ(GDEFCORE_OK, Install(news));
  /* A layout cannot place a module's widget before the module is enabled. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      PutLayout("news", "layout", {"main content", "side news.ticker"})) << refusal_;
  EXPECT_NE(std::string::npos, refusal_.find("news.ticker")) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Enable("news", {})) << last_error_;
  ASSERT_EQ(GDEFCORE_OK, PutTemplate("news.ticker", "core.pane",
      "<% use title; %><aside class=\"ticker\"><%= title %></aside>")) << refusal_;
  ASSERT_EQ(GDEFCORE_OK,
      PutLayout("news", "layout", {"main content", "side news.ticker"})) << refusal_;
  GDEFCORE_Routes * routes = Table();
  std::string plain = Show("", "/page/" + alpha_, routes);
  std::string news_page = Show("", "/news/" + alpha_, routes);
  EXPECT_EQ("news", Chosen("", "/news/" + alpha_, routes));
  EXPECT_EQ("post", Chosen("", "/page/" + alpha_, routes));
  EXPECT_NE(std::string::npos, news_page.find("<aside class=\"ticker\">Ticker:</aside>"))
      << news_page;
  EXPECT_EQ(std::string::npos, plain.find("ticker")) << "CONTROL: the other page";
  EXPECT_EQ(1, ticker.calls);
  /* The main content is the same bytes on both: the contributor and the widget
   * add around it. */
  const std::string article = "<article class=\"post\"><h1>Alpha</h1>";
  EXPECT_NE(std::string::npos, plain.find(article)) << plain;
  EXPECT_NE(std::string::npos, news_page.find(article)) << news_page;
  /* A placement's target goes to the provider. */
  ASSERT_EQ(GDEFCORE_OK,
      PutLayout("news", "layout", {"main content", "side news.ticker headlines"}));
  EXPECT_NE(std::string::npos,
      Show("", "/news/" + alpha_, routes).find("Ticker:headlines")) << "the target is the provider's";
  EXPECT_EQ("headlines", ticker.target);
  /* The module off: the layout it needs is refused, so it cannot be left in a
   * state a page would find broken. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Disable("news"));
  ASSERT_EQ(GDEFCORE_OK, PutLayout("news", "layout", {"main content"}));
  EXPECT_EQ(GDEFCORE_OK, Disable("news")) << "CONTROL: nothing places its widget";
  GDEFCORE_Routes * after = Table();
  EXPECT_EQ("post", Chosen("", "/news/" + alpha_, after)) << "no contributor, no skin";
}

TEST_F(Layouts, MessagesAndTheSiteNameAndTitleAreWidgets) {
  /* Messages has an empty source: it draws nothing, and not even a wrapper. */
  ASSERT_EQ(GDEFCORE_OK, PutLayout("post", "layout",
      {"main content", "side messages", "side sitename", "main title"}));
  std::string page = Show("", "/page/" + alpha_, Table());
  EXPECT_EQ(std::string::npos, page.find("message")) << page;
  EXPECT_NE(std::string::npos, page.find("<span class=\"site-name\"></span>")) << page;
  /* The site name is the base theme's, until settings supply it. */
  std::string theme = IdOf("core.theme", "base");
  ASSERT_FALSE(theme.empty());
  GDEFCORE_Changeset * cs = NULL;
  const char * name[1] = {"Gadget Works"};
  size_t name_len[1] = {12};
  GDEFCORE_Value v;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  v.field = "site_name";
  v.field_len = 9;
  v.texts = name;
  v.text_lens = name_len;
  v.count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, theme.data(), theme.size(), "en", 2, &v, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.theme", 10));
  gdefcore_changeset_destroy(cs);
  page = Show("", "/page/" + alpha_, Table());
  EXPECT_NE(std::string::npos, page.find("<span class=\"site-name\">Gadget Works</span>")) << page;
  /* The title is the entity's own, inert. */
  EXPECT_NE(std::string::npos, page.find("<h1>Alpha</h1>")) << page;
  std::string hostile = SaveNode("<script>t</script>", "b");
  std::string bad = Show("", "/page/" + hostile, Table());
  EXPECT_NE(std::string::npos, bad.find("&lt;script&gt;t&lt;/script&gt;")) << bad;
  EXPECT_EQ(std::string::npos, bad.find("<script")) << bad;
  /* The front page has no entity: its title is empty, and it is not a failure. */
  ASSERT_EQ(GDEFCORE_OK, PutLayout("front", "layout", {"side recent", "main title"}));
  EXPECT_NE(std::string::npos, Show("", "/", Table()).find("class=\"recent\""));
}

/* ---- layouts and rules are checked when they are saved ------------------------- */

TEST_F(Layouts, AnUnknownRegionIsRefusedAndNothingIsWritten) {
  const std::string before = PanesOf("post");
  ASSERT_NE("<none>", before);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      PutLayout("post", "layout", {"main content", "footer sitename"}));
  EXPECT_NE(std::string::npos, refusal_.find("footer")) << refusal_;
  EXPECT_NE(std::string::npos, refusal_.find("region")) << refusal_;
  EXPECT_EQ(before, PanesOf("post")) << "nothing was written";
  /* A new layout is not made either. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "layout", {"nowhere content"}));
  EXPECT_TRUE(IdOf(kDisplay, "fresh").empty());
  /* CONTROL: the regions the page template does declare. */
  EXPECT_EQ(GDEFCORE_OK, PutLayout("fresh", "layout", {"main content", "side recent"}))
      << refusal_;
  EXPECT_FALSE(IdOf(kDisplay, "fresh").empty());
  /* A widget nobody offers, a template that is not there, and a placement that
   * is not one. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "layout", {"main nothing"}));
  EXPECT_NE(std::string::npos, refusal_.find("nothing")) << refusal_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "nowhere", {"main content"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "layout", {"maincontent"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "layout", {"main  content"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "layout", {"main content a b"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "layout", {""}));
  EXPECT_EQ("main content\nside recent\n", PanesOf("fresh")) << "still what it was";
  /* A layout holds at most 32 placements. */
  std::vector<std::string> many(33, "main sitename");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLayout("fresh", "layout", many));
  many.pop_back();
  EXPECT_EQ(GDEFCORE_OK, PutLayout("fresh", "layout", many));
}

TEST_F(Layouts, ChangingAPageTemplateCannotLeaveALayoutBroken) {
  ASSERT_EQ(GDEFCORE_OK, PutTemplate("narrow", "core.page",
      "<% use region; %><div><%= region(\"main\") %></div>"));
  ASSERT_EQ(GDEFCORE_OK, PutLayout("slim", "narrow", {"main content"}));
  ASSERT_EQ(GDEFCORE_OK, PutLayout("slim", "narrow", {"main content"}));
  /* The template that gives up the region the layout places into. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutTemplate("narrow", "core.page",
      "<% use region; %><div>none</div>"));
  EXPECT_NE(std::string::npos, refusal_.find("slim")) << refusal_;
  EXPECT_NE(std::string::npos, refusal_.find("main")) << refusal_;
  /* The kit's layout is used by the front and post layouts, and keeps both. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutTemplate("layout", "core.page",
      "<% use region; %><i><%= region(\"main\") %></i>"));
  EXPECT_NE(std::string::npos, refusal_.find("side")) << refusal_;
  /* CONTROL: a template nobody places into, or one that keeps its regions. */
  EXPECT_EQ(GDEFCORE_OK, PutTemplate("narrow", "core.page",
      "<% use region; %><section><%= region(\"main\") %></section>"));
  EXPECT_EQ(GDEFCORE_OK, PutTemplate("unused", "core.page", "<% use region; %>x"));
  EXPECT_EQ(GDEFCORE_OK, PutTemplate("layout", "core.page",
      "<% use region; %><i><%= region(\"main\") %><%= region(\"side\") %></i>"));
}

TEST_F(Layouts, ARuleIsCheckedWhenItIsSavedAndPassedOverWhenItsLayoutIsGone) {
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRule("site.bad", "nopath", "front"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRule("site.bad", "/a/:/b", "front"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRule("site.bad", "/a/:x/:x", "front"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRule("site.bad", "/a", "Front Page"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRule("bad", "/a", "front"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRule("site.bad", "/a", "front", "notatype"));
  EXPECT_TRUE(IdOf(kRule, "site.bad").empty());
  /* The same through the entity port, where the helper does not stand guard. */
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kRule, strlen(kRule), id, NULL));
  GDEFCORE_Value v[4];
  const char * s[4] = {"site.raw", "nopath", "front", "yes"};
  size_t l[4] = {8, 6, 5, 3};
  const char * f[4] = {"name", "path", "layout", "exact"};
  memset(v, 0, sizeof v);
  for (int i = 0; i < 4; i++) {
    v[i].size = sizeof v[i];
    v[i].field = f[i];
    v[i].field_len = strlen(f[i]);
    v[i].texts = &s[i];
    v[i].text_lens = &l[i];
    v[i].count = 1;
  }
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, v, 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, kRule, strlen(kRule)));
  gdefcore_changeset_destroy(cs);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  s[1] = "/ok";
  l[1] = 3;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, v, 4));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, kRule, strlen(kRule)))
      << "exact is true or absent";
  gdefcore_changeset_destroy(cs);
  /* CONTROL: a rule that is well formed. */
  EXPECT_EQ(GDEFCORE_OK, PutRule("site.fine", "/a/:x/*", "front", "site.post", 1, -3))
      << refusal_;
  /* A rule whose layout is not there is not an error to save (a rule may be
   * staged ahead of its layout) and is passed over by a page it reaches. */
  GDEFCORE_Routes * routes = Table();
  EXPECT_EQ(GDEFCORE_OK, PutRule("site.later", "/page", "later"));
  EXPECT_EQ("post", Chosen("", "/page/" + alpha_, routes)) << "passed over";
  ASSERT_EQ(GDEFCORE_OK, PutLayout("later", "layout", {"main content", "side recent"}));
  EXPECT_EQ("later", Chosen("", "/page/" + alpha_, routes));
}

/* ---- selection through the trie ------------------------------------------------ */

TEST_F(Layouts, TheMoreSpecificRuleWinsAndTheOffersAreInOneOrder) {
  GDEFCORE_Routes * routes = Table();
  for (const char * name : {"a", "b", "ab"}) {
    ASSERT_EQ(GDEFCORE_OK, PutLayout(name, "layout", {"main content", "side recent"}));
  }
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.a", "/page/*", "a"));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.ab", "/page/x/*", "ab"));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.b", "/page", "b"));
  std::string ox = Offers(routes, "/page/x/y");
  EXPECT_EQ(0u, ox.find("ab@site.ab")) << ox;
  EXPECT_LT(ox.find("ab@site.ab"), ox.find("a@site.a")) << ox;
  EXPECT_LT(ox.find("a@site.a"), ox.find("b@site.b")) << ox;
  EXPECT_EQ(std::string::npos, ox.find("front@site.front"))
      << "the kit's front page rule is for the root alone";
  EXPECT_NE(std::string::npos, Offers(routes, "/").find("front@site.front"));
  /* The deeper path reaches the deeper rule; the shallower does not. */
  EXPECT_EQ(std::string::npos, Offers(routes, "/page/q").find("ab@")) << Offers(routes, "/page/q");
  EXPECT_NE(std::string::npos, Offers(routes, "/page/q").find("a@site.a"));
  /* An exact rule is for that path alone. */
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.only", "/page/q", "b", NULL, 1));
  EXPECT_NE(std::string::npos, Offers(routes, "/page/q").find("b@site.only"));
  EXPECT_EQ(std::string::npos, Offers(routes, "/page/q/r").find("b@site.only"))
      << Offers(routes, "/page/q/r");
  /* A named segment is any one segment; a rule of a type applies to a page of
   * that type and outranks the same pattern without one. */
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.named", "/page/:id", "a"));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.typed", "/page/:id", "b", "site.post"));
  GDEFCORE_Request * req = Req();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_resolution(req, alpha_.data(), alpha_.size()));
  GDEFCORE_Offers * with = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_offers(routes, catalog_, req,
                             GDEFCORE_CONTRIBUTOR_LAYOUT, 6, "/page/zz", 8, &with));
  std::string seq;
  for (size_t i = 0; i < gdefcore_offers_count(with); i++) {
    const char * src = NULL;
    size_t sl = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_offers_at(with, i, NULL, NULL, &src, &sl));
    seq += std::string(src, sl) + " ";
  }
  gdefcore_offers_free(with);
  EXPECT_LT(seq.find("site.typed"), seq.find("site.named")) << seq;
  EXPECT_EQ(std::string::npos, Offers(routes, "/page/zz").find("site.typed"))
      << "CONTROL: a page with no entity is not of that type";
  /* The weight breaks a tie of specificity, lowest first. */
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.heavy", "/w", "a", NULL, 0, 5));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.light", "/w", "b", NULL, 0, -5));
  std::string ow = Offers(routes, "/w/x");
  EXPECT_LT(ow.find("site.light"), ow.find("site.heavy")) << ow;
}

TEST_F(Layouts, OverlappingContributorsResolveTheSameWayWhateverTheRegistrationOrder) {
  Offering a, b, c, d;
  a.layout = "la";
  b.layout = "lb";
  c.layout = "lc";
  d.layout = "ld";
  /* Four contributors on one path, tied but for weight and name; and one that
   * is more specific. */
  struct Reg {
    const char * machine;
    const char * path;
    Offering * o;
    int weight;
  };
  std::vector<Reg> regs = {{"m.alpha", "/x", &a, 0}, {"m.beta", "/x", &b, 0},
      {"m.gamma", "/x", &c, -1}, {"m.delta", "/x/y", &d, 0}};
  std::string first;
  for (int order = 0; order < 6; order++) {
    std::vector<Reg> perm = regs;
    std::rotate(perm.begin(), perm.begin() + (order % 4), perm.end());
    if (order >= 4) {
      std::reverse(perm.begin(), perm.end());
    }
    GDEFCORE_Routes * t = Table();
    for (const Reg & r : perm) {
      ASSERT_EQ(GDEFCORE_OK, AddContributor(t, r.machine, r.path, Offer, r.o, 0, r.weight));
    }
    std::string got = Offers(t, "/x/y/z");
    if (order == 0) {
      first = got;
      EXPECT_EQ(0u, got.find("ld@m.delta")) << got;
      EXPECT_LT(got.find("lc@m.gamma"), got.find("la@m.alpha")) << got;
      EXPECT_LT(got.find("la@m.alpha"), got.find("lb@m.beta")) << got;
    }
    EXPECT_EQ(first, got) << "registration order " << order;
  }
  /* Two contributors may not share a machine name, and the error names them. */
  GDEFCORE_Routes * t = Table();
  char * err = NULL;
  size_t err_len = 0;
  GDEFCORE_Contributor_Spec spec;
  memset(&spec, 0, sizeof spec);
  spec.size = sizeof spec;
  spec.kind = "layout";
  spec.kind_len = 6;
  spec.machine = "m.alpha";
  spec.machine_len = 7;
  spec.path = "/x";
  spec.path_len = 2;
  spec.fn = Offer;
  spec.data = &a;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_add_contributor(t, &spec, NULL, NULL));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_routes_add_contributor(t, &spec, &err, &err_len));
  EXPECT_NE(nullptr, err);
  EXPECT_NE(std::string::npos, std::string(err, err_len).find("m.alpha"));
  gdefcore_routes_free(t, err);
  /* A kind or a pattern the table would refuse. */
  spec.machine = "m.other";
  spec.machine_len = 7;
  spec.kind = "Layout";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_routes_add_contributor(t, &spec, NULL, NULL));
  spec.kind = "layout";
  spec.path = "x";
  spec.path_len = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_routes_add_contributor(t, &spec, NULL, NULL));
  spec.path = "/x";
  spec.path_len = 2;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_add_contributor(t, &spec, NULL, NULL)) << "CONTROL";
  /* A contributor is not a route: it is not listed, not a page, not a tab. */
  GDEFCORE_Route_Info * list = NULL;
  size_t nlist = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_list(t, &list, &nlist));
  EXPECT_EQ(2u, nlist) << "the table's own two pages";
  gdefcore_routes_free(t, list);
}

TEST_F(Layouts, ModulesEnabledInAnyOrderGiveTheSameOffersAndTheSiteBeatsAModule) {
  Offering ma, mb;
  ma.layout = "fromA";
  mb.layout = "fromB";
  ModDef * a = NewMod("moda");
  a->Contributor("pick", GDEFCORE_CONTRIBUTOR_LAYOUT, "/x", Offer, &ma);
  ASSERT_EQ(GDEFCORE_OK, Install(a));
  ModDef * b = NewMod("modb");
  b->Contributor("pick", GDEFCORE_CONTRIBUTOR_LAYOUT, "/x", Offer, &mb);
  ASSERT_EQ(GDEFCORE_OK, Install(b));
  std::vector<std::string> seen;
  for (int round = 0; round < 3; round++) {
    const char * order[2] = {round == 1 ? "modb" : "moda", round == 1 ? "moda" : "modb"};
    ASSERT_EQ(GDEFCORE_OK, Enable(order[0], {})) << last_error_;
    ASSERT_EQ(GDEFCORE_OK, Enable(order[1], {})) << last_error_;
    if (round == 2) {
      /* Off and on again, twice. */
      ASSERT_EQ(GDEFCORE_OK, Disable("moda"));
      ASSERT_EQ(GDEFCORE_OK, Enable("moda", {})) << last_error_;
    }
    seen.push_back(Offers(Table(), "/x/y"));
    ASSERT_EQ(GDEFCORE_OK, Disable("moda"));
    ASSERT_EQ(GDEFCORE_OK, Disable("modb"));
    EXPECT_EQ("front@site.front", Offers(Table(), "/") + "")
        << "CONTROL: nothing of theirs is left";
  }
  EXPECT_EQ(seen[0], seen[1]);
  EXPECT_EQ(seen[0], seen[2]);
  EXPECT_NE(std::string::npos, seen[0].find("fromA@moda.pick")) << seen[0];
  EXPECT_NE(std::string::npos, seen[0].find("fromB@modb.pick")) << seen[0];
  EXPECT_LT(seen[0].find("fromA@"), seen[0].find("fromB@")) << seen[0];
  /* A rule of the site and a module's contributor on the same pattern: the
   * site's is first. */
  ASSERT_EQ(GDEFCORE_OK, Enable("moda", {}));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.mine", "/x", "mine"));
  std::string both = Offers(Table(), "/x/y");
  EXPECT_LT(both.find("mine@site.mine"), both.find("fromA@moda.pick")) << both;
}

TEST_F(Layouts, TheMainContentIsTheSameWithAndWithoutAContributor) {
  ASSERT_EQ(GDEFCORE_OK, PutLayout("wide", "layout", {"main content", "side sitename"}));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.wide", "/page", "wide"));
  const std::string article = "<article class=\"post\"><h1>Alpha</h1><div class=\"body\">Alpha body</div></article>";
  GDEFCORE_Routes * bare = Table();
  std::string without = Show("", "/page/" + alpha_, bare);
  ASSERT_NE(std::string::npos, without.find(article)) << without;
  /* Contributors that try everything: offer a layout, hijack the resolution,
   * leave notes. The page shows the same entity's bytes. */
  Offering polite, hijack;
  polite.layout = "wide";
  hijack.layout = "wide";
  hijack.hijack = beta_.c_str();
  GDEFCORE_Routes * t = Table();
  ASSERT_EQ(GDEFCORE_OK, AddContributor(t, "x.polite", "/page", Offer, &polite));
  ASSERT_EQ(GDEFCORE_OK, AddContributor(t, "x.hijack", "/page", Offer, &hijack, 0, -9));
  std::string with = Show("", "/page/" + alpha_, t);
  EXPECT_EQ(without, with) << with;
  EXPECT_EQ(std::string::npos, with.find("Beta")) << with;
  EXPECT_GT(hijack.calls, 0) << "CONTROL: the contributor ran";
  EXPECT_EQ(GDEFCORE_OK, hijack.own_offer);
  EXPECT_EQ(sizeof(GDEFCORE_Contributor_Call), hijack.seen_size);
  /* An offer carries a layout name and nothing else: a name that cannot be
   * applied is passed over. */
  Offering junk;
  junk.layout = "no-such-layout";
  ASSERT_EQ(GDEFCORE_OK, AddContributor(t, "x.junk", "/page/", Offer, &junk, 0, -50));
  EXPECT_EQ(without, Show("", "/page/" + alpha_, t));
  EXPECT_EQ("wide", Chosen("", "/page/" + alpha_, t));
}

/* ---- the alter hook ---------------------------------------------------------- */

TEST_F(Layouts, AnAlterHookRefinesTheLayoutForARoleAndCannotDenyAPage) {
  ASSERT_EQ(GDEFCORE_OK, PutLayout("vip", "layout", {"main content", "side sitename"}));
  ASSERT_EQ(GDEFCORE_OK, PutLayout("vip2", "layout", {"main content", "side title"}));
  Refine r1;
  r1.who = vip_;
  r1.to = "vip";
  ModDef * m = NewMod("hookone");
  m->Sub(GDEFCORE_HOOK_LAYOUT, GDEFCORE_HOOK_ALTER, RefineFn, &r1);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK, Enable("hookone", {})) << last_error_;
  GDEFCORE_Routes * routes = Table();
  const std::string page = "/page/" + alpha_;
  EXPECT_EQ("vip", Chosen(vip_, page, routes));
  EXPECT_EQ("post", Chosen(reader_, page, routes)) << "CONTROL: the others";
  EXPECT_EQ("post", Chosen("", page, routes));
  EXPECT_EQ(sizeof(GDEFCORE_Layout_Hook), r1.seen_size);
  EXPECT_EQ(page, r1.saw_path);
  std::string main_vip = Show(vip_, page, routes);
  std::string main_other = Show(reader_, page, routes);
  EXPECT_NE(std::string::npos, main_vip.find("class=\"site-name\"")) << main_vip;
  EXPECT_EQ(std::string::npos, main_other.find("class=\"site-name\""));
  const std::string article = "<article class=\"post\"><h1>Alpha</h1>";
  EXPECT_NE(std::string::npos, main_vip.find(article)) << "the main content is not touched";
  /* Another module's refinement composes in the host's one order: a later
   * module sees what the earlier one named. */
  Refine r2;
  r2.when = "vip";
  r2.to = "vip2";
  ModDef * m2 = NewMod("hooktwo");
  m2->Sub(GDEFCORE_HOOK_LAYOUT, GDEFCORE_HOOK_ALTER, RefineFn, &r2);
  ASSERT_EQ(GDEFCORE_OK, Install(m2));
  ASSERT_EQ(GDEFCORE_OK, Enable("hooktwo", {})) << last_error_;
  EXPECT_EQ("vip2", Chosen(vip_, page, routes)) << "hookone, then hooktwo";
  EXPECT_EQ("post", Chosen(reader_, page, routes));
  /* Every wrong thing a hook can do: report a denial, fail, name a layout that
   * cannot be applied, name nothing. The page is drawn, as chosen. */
  r2.deny = 1;
  EXPECT_EQ("vip2", Chosen(vip_, page, routes));
  EXPECT_NE(std::string::npos, Show(vip_, page, routes).find(article));
  r2.fail = 1;
  EXPECT_EQ("vip", Chosen(vip_, page, routes)) << "a failing subscriber is skipped";
  EXPECT_NE(std::string::npos, Show(vip_, page, routes).find(article));
  r2.fail = 0;
  r2.deny = 0;
  r2.to = "no-such-layout";
  EXPECT_EQ("post", Chosen(vip_, page, routes))
      << "a final name that cannot be applied is ignored: the choice before the hook stands";
  EXPECT_NE(std::string::npos, Show(vip_, page, routes).find(article));
  r2.to = "";
  EXPECT_EQ("post", Chosen(vip_, page, routes)) << "an empty name denies nothing";
  EXPECT_NE(std::string::npos, Show(vip_, page, routes).find(article));
  r2.to = "main";
  EXPECT_EQ("post", Chosen(vip_, page, routes));
  r2.to = "vip2";
  EXPECT_EQ("vip2", Chosen(vip_, page, routes)) << "CONTROL: a layout that can be applied";
  /* A hook that is not an alter is not fired as one: it changes nothing. */
  ASSERT_EQ(GDEFCORE_OK, Disable("hooktwo"));
  ASSERT_EQ(GDEFCORE_OK, Disable("hookone"));
  EXPECT_EQ("post", Chosen(vip_, page, routes)) << "disabled, the refinement is gone";
  ModDef * m3 = NewMod("hookevent");
  m3->Sub(GDEFCORE_HOOK_LAYOUT, GDEFCORE_HOOK_EVENT, RefineFn, &r1);
  ASSERT_EQ(GDEFCORE_OK, Install(m3));
  ASSERT_EQ(GDEFCORE_OK, Enable("hookevent", {})) << last_error_;
  EXPECT_EQ("post", Chosen(vip_, page, routes));
  EXPECT_NE(std::string::npos, Show(vip_, page, routes).find(article));
}

/* ---- visibility ---------------------------------------------------------------- */

TEST_F(Layouts, AHiddenWidgetRendersNothingAndRevealsNothing) {
  Ticker ticker;
  ModDef * news = NewMod("news");
  news->Widget("ticker", "core.pane", TickerFn, &ticker, "news.read");
  ASSERT_EQ(GDEFCORE_OK, Install(news));
  ASSERT_EQ(GDEFCORE_OK, Enable("news", {})) << last_error_;
  ASSERT_EQ(GDEFCORE_OK, PutTemplate("news.ticker", "core.pane",
      "<% use title; %><aside class=\"ticker\"><%= title %></aside>"));
  ASSERT_EQ(GDEFCORE_OK, PutLayout("post", "layout", {"main content", "side news.ticker"}));
  GDEFCORE_Routes * routes = Table();
  const std::string page = "/page/" + alpha_;
  std::string anon = Show("", page, routes);
  EXPECT_EQ(std::string::npos, anon.find("ticker")) << anon;
  EXPECT_EQ(std::string::npos, anon.find("Ticker")) << anon;
  EXPECT_EQ(0, ticker.calls) << "the provider is not even asked";
  std::string reader = Show(reader_, page, routes);
  EXPECT_EQ(anon, reader);
  EXPECT_EQ(0, ticker.calls);
  std::string vip = Show(vip_, page, routes);
  EXPECT_NE(std::string::npos, vip.find("<aside class=\"ticker\">Ticker:</aside>")) << vip;
  EXPECT_EQ(1, ticker.calls) << "CONTROL: whoever holds the permission is shown it";
  /* The main content is the same either way. */
  EXPECT_NE(std::string::npos, anon.find("<article class=\"post\"><h1>Alpha</h1>"));
  /* A provider that fails, and a template that is not of the widget's kind,
   * draw nothing and do not take the page down. */
  ASSERT_EQ(GDEFCORE_OK, PutTemplate("news.ticker", "core.title", "<% use title; %>x"));
  std::string wrong = Show(vip_, page, routes);
  EXPECT_EQ(std::string::npos, wrong.find("Ticker")) << wrong;
  EXPECT_NE(std::string::npos, wrong.find("<article class=\"post\">")) << wrong;
  /* A post the viewer may not read is no page at all (its title and content
   * are the entity's, through the access filter). */
  ASSERT_EQ(GDEFCORE_OK, Forget("site.post"));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.post", "/page", "post", "site.post"));
  EXPECT_NE(std::string::npos, Show("", page, routes).find("Alpha"));
}

TEST_F(Layouts, TwoTenantsLayoutsNeverMix) {
  GDEFCORE_Catalog * tenants[2] = {NULL, NULL};
  const char * names[2] = {"ta", "tb"};
  std::string posts[2];
  GDEFCORE_Routes * shared = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &shared));
  tables_.push_back(shared);
  GDEFCORE_Route_Spec spec;
  memset(&spec, 0, sizeof spec);
  spec.size = sizeof spec;
  spec.machine = "test.page";
  spec.machine_len = 9;
  spec.path = "/page/:id";
  spec.path_len = 9;
  spec.call_fn = OwnPage;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(shared, &spec, NULL, NULL));
  for (int i = 0; i < 2; i++) {
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store_, (const uint8_t *)names[i], 2,
                               NULL, NULL, &tenants[i]));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(tenants[i], &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(tenants[i], bytes, n));
    gdefcore_text_free(tenants[i], (char *)bytes);
    posts[i] = SaveNode(i == 0 ? "Alpha tenant post" : "Beta tenant post", "b", tenants[i]);
  }
  /* Both tenants have layouts of the same two names, and the rules of each
   * choose a different one: what leaks is a rule, and the name it chooses
   * exists on both sides. */
  GDEFCORE_Changeset * cs = NULL;
  const char * layout_names[2] = {"only-a", "only-b"};
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      char fresh[GDEFCORE_PUBLIC_ID_LEN + 1];
      const char * panes[2] = {"main content", j == 0 ? "side sitename" : "side title"};
      size_t plens[2] = {strlen(panes[0]), strlen(panes[1])};
      const char * nm[1] = {layout_names[j]};
      size_t nl[1] = {strlen(layout_names[j])};
      const char * tm[1] = {"layout"};
      size_t tl[1] = {6};
      GDEFCORE_Value v[3];
      ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(tenants[i], kDisplay, strlen(kDisplay), fresh, NULL));
      memset(v, 0, sizeof v);
      v[0].size = sizeof v[0];
      v[0].field = "name";
      v[0].field_len = 4;
      v[0].texts = nm;
      v[0].text_lens = nl;
      v[0].count = 1;
      v[1].size = sizeof v[1];
      v[1].field = "layout";
      v[1].field_len = 6;
      v[1].texts = tm;
      v[1].text_lens = tl;
      v[1].count = 1;
      v[2].size = sizeof v[2];
      v[2].field = "panes";
      v[2].field_len = 5;
      v[2].texts = panes;
      v[2].text_lens = plens;
      v[2].count = 2;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(tenants[i], NULL, 0, &cs));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, fresh, strlen(fresh), "en", 2, v, 3));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kDisplay, strlen(kDisplay)));
      gdefcore_changeset_destroy(cs);
    }
    ASSERT_EQ(GDEFCORE_OK, PutRule("site.mine", "/page", layout_names[i], NULL, 0, 0, tenants[i]));
    /* The front page is each tenant's own, by the one rule name the kit uses. */
    ASSERT_EQ(GDEFCORE_OK, PutRule("site.front", "/", layout_names[i], NULL, 1, 0, tenants[i]));
  }
  for (int round = 0; round < 2; round++) {
    for (int i = 0; i < 2; i++) {
      int o = 1 - i;
      /* One route table serves both tenants, in either order. */
      GDEFCORE_Request * req = TenantReq(names[i], 2);
      std::string page = Show("", "/page/" + posts[i], shared, tenants[i], req);
      EXPECT_EQ(i == 0, page.find("class=\"site-name\"") != std::string::npos)
          << names[i] << ": " << page;
      EXPECT_NE(std::string::npos, page.find(i == 0 ? "Alpha tenant post" : "Beta tenant post"))
          << page;
      EXPECT_EQ(std::string::npos, page.find(i == 0 ? "Beta tenant post" : "Alpha tenant post"))
          << page;
      GDEFCORE_Request * r2 = TenantReq(names[i], 2);
      char * name = NULL;
      size_t name_len = 0;
      char * resolved = NULL;
      size_t resolved_len = 0;
      std::string path = "/page/" + posts[i];
      ASSERT_EQ(GDEFCORE_OK, gdefcore_form_resolve(shared, tenants[i], r2, path.data(),
                                 path.size(), &resolved, &resolved_len));
      gdefcore_request_set_resolution(r2, resolved, resolved_len);
      gdefcore_text_free(tenants[i], resolved);
      ASSERT_EQ(GDEFCORE_OK, gdefcore_layout_select(tenants[i], shared, r2, path.data(),
                                 path.size(), &name, &name_len));
      EXPECT_EQ(layout_names[i], std::string(name, name_len));
      EXPECT_NE(layout_names[o], std::string(name, name_len));
      gdefcore_text_free(tenants[i], name);
    }
  }
  for (int round = 0; round < 2; round++) {
    for (int k = 0; k < 2; k++) {
      int i = round == 0 ? k : 1 - k;
      std::string front = Show("", "/", shared, tenants[i], TenantReq(names[i], 2));
      EXPECT_EQ(i == 0, front.find("class=\"site-name\"") != std::string::npos)
          << names[i] << " front page: " << front;
    }
  }
  /* The default tenant has neither rule. */
  EXPECT_TRUE(IdOf(kRule, "site.mine").empty());
  EXPECT_FALSE(IdOf(kRule, "site.mine", tenants[0]).empty());
  for (int i = 0; i < 2; i++) {
    gdefcore_catalog_destroy(tenants[i]);
  }
}

/* ---- who may edit, and the key -------------------------------------------------- */

TEST_F(Layouts, EditingLayoutsIsOnePermissionCheckedAtApplyForAChangesetWithARequest) {
  GDEFCORE_Request * nobody = Req(reader_);
  GDEFCORE_Request * layouter = Req(layouter_);
  const std::string before = PanesOf("front");
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      PutLayout("front", "layout", {"main content"}, nobody));
  EXPECT_NE(std::string::npos, refusal_.find("not allowed")) << refusal_;
  EXPECT_EQ(before, PanesOf("front"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRule("site.mine", "/m", "front", NULL, 0, 0, NULL, nobody));
  EXPECT_TRUE(IdOf(kRule, "site.mine").empty());
  EXPECT_EQ(GDEFCORE_OK, PutLayout("front", "layout", {"main content"}, layouter))
      << refusal_;
  EXPECT_EQ("main content\n", PanesOf("front")) << "CONTROL: the layouter";
  EXPECT_EQ(GDEFCORE_OK, PutRule("site.mine", "/m", "front", NULL, 0, 0, NULL, layouter));
  /* The decision the editor's button asks, the same permission. */
  EXPECT_TRUE(gdefcore_layout_may_edit(catalog_, layouter));
  EXPECT_FALSE(gdefcore_layout_may_edit(catalog_, nobody));
  /* A grant narrowed to one layout edits that layout and not another. */
  Role("frontonly");
  EXPECT_EQ(GDEFCORE_OK, GrantWhen("frontonly", GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL,
                             "(= field.name \"front\")"));
  std::string fronter = Principal("frontonly");
  EXPECT_EQ(GDEFCORE_OK, PutLayout("front", "layout", {"main content", "side recent"},
                             Req(fronter))) << refusal_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      PutLayout("post", "layout", {"main content", "side recent"}, Req(fronter)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      PutLayout("brandnew", "layout", {"main content"}, Req(fronter)));
}

TEST_F(Layouts, AChangeToALayoutIsAChangeToTheKey) {
  GDEFCORE_Request * req = Req();
  char * key1 = NULL;
  char * key2 = NULL;
  size_t n1 = 0;
  size_t n2 = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_render_key(catalog_, req, NULL, 0, NULL, 0, &key1, &n1));
  ASSERT_EQ(GDEFCORE_OK, PutRule("site.z", "/z", "front"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_render_key(catalog_, req, NULL, 0, NULL, 0, &key2, &n2));
  EXPECT_NE(std::string(key1, n1), std::string(key2, n2));
  /* CONTROL: nothing written, the same key. */
  char * key3 = NULL;
  size_t n3 = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_render_key(catalog_, req, NULL, 0, NULL, 0, &key3, &n3));
  EXPECT_EQ(std::string(key2, n2), std::string(key3, n3));
  gdefcore_text_free(catalog_, key1);
  gdefcore_text_free(catalog_, key2);
  gdefcore_text_free(catalog_, key3);
}

/* ---- sizes ------------------------------------------------------------------------ */

TEST_F(Layouts, TheStructsHereAreAcceptedAtOnlyTheirOwnSize) {
  using size_structs::Probe;
  std::map<std::string, Probe> probes;
  /* A manifest entry is accepted at install at its own size only. */
  auto entry = [&, this](std::function<void(ModDef *, size_t)> mutate,
                   const char * struct_name) {
    return [=, this](size_t size) {
      Fresh();
      ModDef * m = NewMod("szm");
      Ticker t;
      Offering o;
      o.layout = "x";
      m->Widget("w", "core.pane", TickerFn, &t);
      m->Contributor("c", GDEFCORE_CONTRIBUTOR_LAYOUT, "/x", Offer, &o);
      m->Finish();
      mutate(m, size);
      GDEFCORE_Result rc = gdefcore_module_install_guest(host_, kEntries[0]);
      if (size != 0 && rc != GDEFCORE_OK) {
        const char * err = gdefcore_module_error(host_, NULL);
        EXPECT_NE(nullptr, err);
        if (err != NULL) {
          EXPECT_NE(std::string::npos, std::string(err).find(struct_name)) << err;
        }
      }
      return rc == GDEFCORE_OK;
    };
  };
  /* A service table is read when the module is enabled. */
  auto table = [&, this](std::function<void(ModDef *, size_t)> mutate) {
    return [=, this](size_t size) {
      Fresh();
      ModDef * m = NewMod("szt");
      Ticker t;
      Offering o;
      o.layout = "x";
      m->Widget("w", "core.pane", TickerFn, &t);
      m->Contributor("c", GDEFCORE_CONTRIBUTOR_LAYOUT, "/x", Offer, &o);
      m->Finish();
      mutate(m, size);
      EXPECT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, kEntries[0]));
      return Enable("szt", {}) == GDEFCORE_OK;
    };
  };
  /* What the host enumerates, once the module is enabled. */
  auto enabled = [&, this](std::function<bool(size_t)> look) {
    return [=, this](size_t size) {
      Fresh();
      ModDef * m = NewMod("sze");
      Ticker t;
      Offering o;
      o.layout = "x";
      m->Widget("w", "core.pane", TickerFn, &t);
      m->Contributor("c", GDEFCORE_CONTRIBUTOR_LAYOUT, "/x", Offer, &o);
      EXPECT_EQ(GDEFCORE_OK, Install(m));
      EXPECT_EQ(GDEFCORE_OK, Enable("sze", {})) << last_error_;
      return look(size);
    };
  };
  const uint8_t tenant[] = {'t'};
  probes["GDEFCORE_Module_Contributor"] = entry(
      [](ModDef * m, size_t size) { m->contributors[0].size = size; },
      "GDEFCORE_Module_Contributor");
  probes["GDEFCORE_Module_Widget"] = entry(
      [](ModDef * m, size_t size) { m->widgets[0].size = size; },
      "GDEFCORE_Module_Widget");
  probes["GDEFCORE_Module_Contributor_Handler"] = table(
      [](ModDef * m, size_t size) { m->contributor_handlers.front().size = size; });
  probes["GDEFCORE_Module_Widget_Provider"] = table(
      [](ModDef * m, size_t size) { m->widget_providers.front().size = size; });
  probes["GDEFCORE_Module_Declared_Contributor"] = enabled([&](size_t size) {
    const GDEFCORE_Module_Declared_Contributor ** items = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_module_contributors(host_, tenant, 1, NULL, &items, &n));
    EXPECT_GT(n, 0u);
    bool filled = n > 0 && items[0]->size == size;
    gdefcore_module_declared_free(host_, items);
    return filled;
  });
  probes["GDEFCORE_Module_Declared_Widget"] = enabled([&](size_t size) {
    const GDEFCORE_Module_Declared_Widget ** items = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_module_widgets(host_, tenant, 1, NULL, &items, &n));
    EXPECT_GT(n, 0u);
    bool filled = n > 0 && items[0]->size == size;
    gdefcore_module_declared_free(host_, items);
    return filled;
  });
  probes["GDEFCORE_Layout_Widget"] = [&, this](size_t size) {
    Fresh();
    GDEFCORE_Layout_Widget w;
    memset(&w, 0, sizeof w);
    w.size = size;
    return gdefcore_layout_widget_at(catalog_, 0, &w) == GDEFCORE_OK &&
           gdefcore_layout_widget_find(catalog_, "menu", 4, &w) == GDEFCORE_OK;
  };
  probes["GDEFCORE_Layout_Rule"] = [&, this](size_t size) {
    Fresh();
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Layout_Rule rule;
    memset(&rule, 0, sizeof rule);
    rule.size = size;
    rule.path = "/x";
    rule.path_len = 2;
    rule.layout = "front";
    rule.layout_len = 5;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    bool ok = gdefcore_layout_stage_rule(cs, "site.sz", 7, &rule) == GDEFCORE_OK;
    gdefcore_changeset_destroy(cs);
    return ok;
  };
  /* The ones the core fills, in a call to a function of the test's. */
  probes["GDEFCORE_Contributor_Call"] = [&, this](size_t size) {
    Fresh();
    Offering o;
    o.layout = "x";
    GDEFCORE_Routes * t = Table();
    EXPECT_EQ(GDEFCORE_OK, AddContributor(t, "sz.call", "/x", Offer, &o));
    (void)Offers(t, "/x");
    return o.seen_size == size;
  };
  probes["GDEFCORE_Contributor_Spec"] = [&, this](size_t size) {
    Fresh();
    GDEFCORE_Routes * t = Table();
    GDEFCORE_Contributor_Spec spec;
    Offering o;
    memset(&spec, 0, sizeof spec);
    spec.size = size;
    spec.kind = "layout";
    spec.kind_len = 6;
    spec.machine = "sz.spec";
    spec.machine_len = 7;
    spec.path = "/x";
    spec.path_len = 2;
    spec.fn = Offer;
    spec.data = &o;
    return gdefcore_routes_add_contributor(t, &spec, NULL, NULL) == GDEFCORE_OK;
  };
  probes["GDEFCORE_Offer"] = [&, this](size_t size) {
    Fresh();
    Offering o;
    o.layout = "x";
    o.sized = true;
    o.offer_size = size;
    GDEFCORE_Routes * t = Table();
    EXPECT_EQ(GDEFCORE_OK, AddContributor(t, "sz.offer", "/x", Offer, &o));
    (void)Offers(t, "/x");
    return o.own_offer == GDEFCORE_OK;
  };
  probes["GDEFCORE_Layout_Hook"] = [&, this](size_t size) {
    Fresh();
    Refine r;
    r.to = "front";
    ModDef * m = NewMod("szh");
    m->Sub(GDEFCORE_HOOK_LAYOUT, GDEFCORE_HOOK_ALTER, RefineFn, &r);
    EXPECT_EQ(GDEFCORE_OK, Install(m));
    EXPECT_EQ(GDEFCORE_OK, Enable("szh", {})) << last_error_;
    GDEFCORE_Request * req = Req();
    char * name = NULL;
    size_t name_len = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_layout_select(catalog_, NULL, req, "/", 1, &name, &name_len));
    gdefcore_text_free(catalog_, name);
    return r.seen_size == size;
  };
  size_structs::Run("tests/test_layout.cpp", probes);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
