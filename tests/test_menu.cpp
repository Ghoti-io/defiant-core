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
 * Menus, tabs and breadcrumbs (site admin story 6). A menu is a tree computed
 * from what is declared and what the site stored; an entry is shown when its
 * target route's own check passes for the page's values; the site changes a
 * generated entry with an override that stores only what it changed.
 *
 * Every test carries a CONTROL: the viewer who is shown the thing the others
 * are not, so a refusal is a refusal and not an empty page. The real-source
 * plants are in tools/check-menu.sh, and each names the test that must turn
 * red.
 */

#include "grants_fixture.h"
#include "size_structs.h"

namespace {

using namespace gfx;

const char kEntry[] = "core.menu-entry";
const char kOverride[] = "core.menu-override";
const char kBoth[] = "core.menu-entry\ncore.menu-override";

class Menus : public GrantsFixture {
 protected:
  std::vector<GDEFCORE_Routes *> tables_;
  std::string alpha_, beta_;   /* two nodes, made by the admin */
  std::string author_;         /* may edit only the nodes they made */
  std::string author_node_;
  std::string editor_;         /* may edit every node */
  std::string wikiadmin_;      /* may use the wiki's settings */
  std::string menuman_;        /* may edit menus */
  std::string reader_;         /* holds no role */

  /* Set by a fixture that wants the render kit. The kit defines site.post
   * itself, with a required body. */
  bool use_kit_ = false;

  void SetUp() override {
    GrantsFixture::SetUp();
    if (use_kit_) {
      uint8_t * bytes = NULL;
      size_t n = 0;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
      gdefcore_text_free(catalog_, (char *)bytes);
    } else {
      DefinePost();
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_declare(catalog_));
    Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
    Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
    Declare(Perm("Edit own posts", "update", GDEFCORE_ACCESS_OWN));
    Declare(Perm("Administer the wiki", "wiki.admin", GDEFCORE_ACCESS_ANY));
    if (!use_kit_) {
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_access_grant(catalog_, "anonymous", 9, "Read posts", 10,
              GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
              strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "authenticated", 13, "Read posts", 10,
            GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
            strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED)));
    Role("editors");
    Grant("editors", "Edit posts");
    Role("authors");
    Grant("authors", "Edit own posts");
    Role("wikiadmins");
    Grant("wikiadmins", "Administer the wiki");
    Role("menumen");
    Grant("menumen", GDEFCORE_MENU_EDIT_ENTRY_LABEL);
    Grant("menumen", GDEFCORE_MENU_EDIT_OVERRIDE_LABEL);
    editor_ = Principal("editors");
    author_ = Principal("authors");
    wikiadmin_ = Principal("wikiadmins");
    menuman_ = Principal("menumen");
    reader_ = Principal();
    alpha_ = SaveNode(Admin(), "Alpha");
    beta_ = SaveNode(Admin(), "Beta");
    author_node_ = SaveNode(author_, "Mine");
  }

  /* A node: a post with a title (and the body the kit requires). */
  std::string SaveNode(const std::string & actor, const char * title) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[2];
    const char * slots[2] = {title, "body"};
    size_t lens[2] = {strlen(title), 4};
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kPost, strlen(kPost), id,
                               NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, actor.data(),
                               actor.size(), &cs));
    for (int i = 0; i < 2; i++) {
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = i == 0 ? "title" : "body";
      values[i].field_len = i == 0 ? 5 : 4;
      values[i].texts = &slots[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, values,
                               use_kit_ ? 2 : 1));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  void TearDown() override {
    for (GDEFCORE_Routes * t : tables_) {
      gdefcore_routes_destroy(t);
    }
    tables_.clear();
    GrantsFixture::TearDown();
  }

  /* The module that owns the wiki's pages, its tabs and its links. */
  void InstallWiki(const char * label = "Wiki") {
    ModDef * m = NewMod("wiki");
    m->Route("wiki.index", "/wiki", "Wiki", "read");
    m->Route("wiki.node", "/node/:id", "Node", "read", "id");
    m->Route("wiki.slug", "/wiki/:slug", "Wiki page");
    m->Tab("wiki.view", "/node/:id/view", "wiki.node", "View", 0, "read", "id", 1);
    m->Tab("wiki.edit", "/node/:id/edit", "wiki.node", "Edit", 2, "update", "id");
    m->Tab("wiki.history", "/node/:id/history", "wiki.node", "History", 3,
        "update", "id");
    m->Route("wiki.admin", "/admin/wiki", "Wiki settings", "wiki.admin");
    m->Route("wiki.admin-sub", "/admin/wiki/sub", "Sub settings", "wiki.admin");
    m->Link("wiki.l-index", "main", label, "wiki.index", 0);
    m->Link("wiki.l-recent", "main", "Recent", "wiki.index", 1, "wiki.l-index");
    m->Link("wiki.l-this", "main", "This node", "wiki.node", 5);
    m->Link("wiki.l-slug", "main", "This wiki page", "wiki.slug", 6);
    m->Link("wiki.l-admin", "admin", "Wiki settings", "wiki.admin", 2);
    m->Link("wiki.l-sub", "admin", "Sub settings", "wiki.admin-sub", 0,
        "wiki.l-admin");
    ASSERT_EQ(GDEFCORE_OK, Install(m)) << gdefcore_module_error(host_, NULL);
  }

  void EnableWiki() {
    ASSERT_EQ(GDEFCORE_OK, Enable("wiki", {})) << last_error_;
  }

  /* A fresh route table: the enabled modules' routes and the kernel's own. */
  GDEFCORE_Routes * Table(const char * start_label = "Start") {
    GDEFCORE_Routes * routes = NULL;
    char * err = NULL;
    size_t err_len = 0;
    GDEFCORE_Route_Spec spec;
    GDEFCORE_Route_Link link;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes,
                               gdefcore_access_route_check, catalog_));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_module_add_routes(host_,
                               (const uint8_t *)kTenant, 1, NULL, routes, &err,
                               &err_len))
        << (err == NULL ? "" : std::string(err, err_len));
    gdefcore_routes_free(routes, err);
    memset(&spec, 0, sizeof spec);
    spec.size = sizeof spec;
    spec.machine = "core.start";
    spec.machine_len = 10;
    spec.path = "/start";
    spec.path_len = 6;
    spec.call_fn = ModDef::NoRoute;
    spec.title = start_label;
    spec.title_len = strlen(start_label);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes, &spec, NULL, NULL));
    memset(&spec, 0, sizeof spec);
    spec.size = sizeof spec;
    spec.machine = "core.menus";
    spec.machine_len = 10;
    spec.path = "/admin/menus";
    spec.path_len = 12;
    spec.call_fn = ModDef::NoRoute;
    spec.title = "Menus";
    spec.title_len = 5;
    spec.permission = GDEFCORE_MENU_EDIT;
    spec.permission_len = sizeof GDEFCORE_MENU_EDIT - 1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes, &spec, NULL, NULL));
    memset(&link, 0, sizeof link);
    link.size = sizeof link;
    link.name = "core.l-start";
    link.name_len = 12;
    link.menu = "main";
    link.menu_len = 4;
    link.label = start_label;
    link.label_len = strlen(start_label);
    link.route = "core.start";
    link.route_len = 10;
    link.weight = -10;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_add_link(routes, &link));
    link.name = "core.l-menus";
    link.name_len = 12;
    link.menu = "admin";
    link.menu_len = 5;
    link.label = "Menus";
    link.label_len = 5;
    link.route = "core.menus";
    link.route_len = 10;
    link.weight = 1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_add_link(routes, &link));
    tables_.push_back(routes);
    return routes;
  }

  /* What a computed menu holds, one line per item: indent, label, path, and
   * the marks (* the page, ^ above the page, ! hidden, ? not shown). */
  static std::string Dump(GDEFCORE_Menu * menu) {
    std::string out;
    for (size_t i = 0; i < gdefcore_menu_count(menu); i++) {
      GDEFCORE_Menu_Item it;
      memset(&it, 0, sizeof it);
      it.size = sizeof it;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_item(menu, i, &it));
      out += std::string(it.depth * 2, ' ') + std::string(it.label, it.label_len);
      if (it.href_len > 0) {
        out += " " + std::string(it.href, it.href_len);
      }
      out += std::string(it.current ? " *" : "") + (it.trail ? " ^" : "") +
             (it.hidden ? " !" : "") + (it.visible ? "" : " ?") + "\n";
    }
    return out;
  }

  GDEFCORE_Route_Match * Match(GDEFCORE_Routes * routes, GDEFCORE_Request * req,
      const std::string & path) {
    GDEFCORE_Route_Match * match = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_match(routes, req, path.data(),
                               path.size(), &match));
    return match;
  }

  /* The menu as @p who sees it on @p path. */
  std::string Tree(const std::string & who, const std::string & path,
      const char * menu, GDEFCORE_Routes * routes = NULL) {
    GDEFCORE_Request * req = Req(who);
    GDEFCORE_Routes * table = routes != NULL ? routes : Table();
    GDEFCORE_Route_Match * match = Match(table, req, path);
    GDEFCORE_Menu * m = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_tree(catalog_, table, req, match, menu,
                               strlen(menu), &m));
    std::string out = Dump(m);
    gdefcore_menu_free(m);
    gdefcore_route_match_free(match);
    return out;
  }

  std::string Tabs(const std::string & who, const std::string & path) {
    GDEFCORE_Request * req = Req(who);
    GDEFCORE_Routes * table = Table();
    GDEFCORE_Route_Match * match = Match(table, req, path);
    GDEFCORE_Menu * m = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_tabs(catalog_, table, req, match, &m));
    std::string out = Dump(m);
    gdefcore_menu_free(m);
    gdefcore_route_match_free(match);
    return out;
  }

  std::string Crumbs(const std::string & who, const std::string & path,
      const char * menu = NULL) {
    GDEFCORE_Request * req = Req(who);
    GDEFCORE_Routes * table = Table();
    GDEFCORE_Route_Match * match = Match(table, req, path);
    GDEFCORE_Menu * m = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_breadcrumbs(catalog_, table, req, match,
                               menu, menu == NULL ? 0 : strlen(menu), &m));
    std::string out = Dump(m);
    gdefcore_menu_free(m);
    gdefcore_route_match_free(match);
    return out;
  }

  /* The editor's list. */
  std::string Entries(const std::string & who, const std::string & path,
      GDEFCORE_Result * rc_out = NULL) {
    GDEFCORE_Request * req = Req(who);
    GDEFCORE_Routes * table = Table();
    GDEFCORE_Route_Match * match = Match(table, req, path);
    GDEFCORE_Menu * m = NULL;
    GDEFCORE_Result rc = gdefcore_menu_entries(catalog_, table, req, match, &m);
    std::string out = rc == GDEFCORE_OK ? Dump(m) : std::string();
    if (rc_out != NULL) {
      *rc_out = rc;
    } else {
      EXPECT_EQ(GDEFCORE_OK, rc);
    }
    gdefcore_menu_free(m);
    gdefcore_route_match_free(match);
    return out;
  }

  /* One changeset, staged by @p stage, applied as @p who (empty: the
   * operator's, which carries no request). */
  GDEFCORE_Result Change(const std::string & who,
      const std::function<void(GDEFCORE_Changeset *)> & stage,
      const char * confirm = kBoth) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (!who.empty()) {
      gdefcore_changeset_set_request(cs, Req(who));
    }
    stage(cs);
    rc = gdefcore_changeset_apply(cs, confirm, strlen(confirm));
    size_t rn = 0;
    const char * r = gdefcore_changeset_refusal(cs, &rn);
    refusal_.assign(r == NULL ? "" : r, rn);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  std::string refusal_;

  GDEFCORE_Result SiteEntry(const std::string & who, const char * name,
      const char * menu, const char * label, const char * route = "",
      const char * parent = "", int weight = 0) {
    return Change(who, [&](GDEFCORE_Changeset * cs) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_menu_stage_entry(cs, name, strlen(name), menu, strlen(menu),
              label, strlen(label), route, strlen(route), parent, strlen(parent),
              weight));
    }, kEntry);
  }

  struct Ov {
    const char * label = NULL;
    bool has_weight = false;
    int weight = 0;
    int hidden = -1;
    const char * parent = NULL;
    const char * menu = NULL;
  };

  GDEFCORE_Result Override(const std::string & who, const char * name,
      const Ov & ov) {
    return Change(who, [&](GDEFCORE_Changeset * cs) {
      GDEFCORE_Menu_Override o;
      memset(&o, 0, sizeof o);
      o.size = sizeof o;
      o.label = ov.label;
      o.label_len = ov.label == NULL ? 0 : strlen(ov.label);
      o.has_weight = ov.has_weight;
      o.weight = ov.weight;
      o.hidden = ov.hidden;
      o.parent = ov.parent;
      o.parent_len = ov.parent == NULL ? 0 : strlen(ov.parent);
      o.menu = ov.menu;
      o.menu_len = ov.menu == NULL ? 0 : strlen(ov.menu);
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_menu_stage_override(cs, name, strlen(name), &o));
    }, kOverride);
  }

  GDEFCORE_Result Forget(const std::string & who, const char * name,
      const char * type) {
    return Change(who, [&](GDEFCORE_Changeset * cs) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_stage_forget(cs, name, strlen(name)));
    }, type);
  }

  /* The fields stored for the override of @p name, as "field=value;". */
  std::string StoredOverride(const char * name) {
    char ** ids = NULL;
    size_t n = 0;
    std::string out = "<none>";
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(catalog_, kOverride, strlen(kOverride), &ids, &n));
    for (size_t i = 0; i < n; i++) {
      std::string fields;
      bool mine = false;
      for (const char * f : {"name", "label", "weight", "hidden", "parent", "menu"}) {
        char ** t = NULL;
        size_t * l = NULL;
        size_t c = 0;
        if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED,
                ids[i], strlen(ids[i]), "en", 2, f, strlen(f), &t, &l, &c) ==
            GDEFCORE_OK) {
          if (c > 0) {
            fields += std::string(f) + "=" + std::string(t[0], l[0]) + ";";
            mine = mine || (std::string(f) == "name" &&
                               std::string(t[0], l[0]) == name);
          }
          gdefcore_values_free(catalog_, t, l, c);
        }
      }
      if (mine) {
        out = fields;
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    return out;
  }
};

/* ---- what a menu is --------------------------------------------------------- */

TEST_F(Menus, AMenuIsATreeOfTheEntriesDeclaredAndTheSitesOwn) {
  InstallWiki();
  EnableWiki();
  /* Weights order siblings, a child sits under its parent, the page's own
   * entry is marked and so is the way down to it. */
  EXPECT_EQ("Start /start\n"
            "Wiki /wiki\n"
            "  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  EXPECT_EQ("Start /start\n"
            "Wiki /wiki * ^\n"
            "  Recent /wiki *\n",
      Tree(reader_, "/wiki", "main"))
      << "both entries go to the page, and the child is below the parent";
  /* A site entry joins the tree where it says, nested under a generated one. */
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.about", "main", "About us",
                             "core.start", "wiki.l-index", 5));
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.deeper", "main", "Team", "core.start",
                             "site.about", 0));
  EXPECT_EQ("Start /start\n"
            "Wiki /wiki\n"
            "  Recent /wiki\n"
            "  About us /start\n"
            "    Team /start\n",
      Tree(reader_, "/nowhere", "main"));
  /* A menu nobody declared is empty, not an error. */
  EXPECT_EQ("", Tree(reader_, "/nowhere", "nothing"));
}

TEST_F(Menus, AnEntryThatOnlyGroupsOthersIsShownOnlyWithSomethingUnderIt) {
  InstallWiki();
  EnableWiki();
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.tools", "main", "Tools"));
  /* Nothing under it: not there. */
  EXPECT_EQ("Start /start\nWiki /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  /* One entry under it that this viewer may follow: it is. */
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.tool-a", "main", "Settings",
                             "wiki.admin", "site.tools", 0));
  EXPECT_EQ("Start /start\nWiki /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"))
      << "the one entry under the group is the wiki's settings";
  EXPECT_EQ("Start /start\nTools\n  Settings /admin/wiki\nWiki /wiki\n"
            "  Recent /wiki\n",
      Tree(wikiadmin_, "/nowhere", "main"))
      << "CONTROL: the viewer who may follow the entry sees the group";
}

TEST_F(Menus, TheKernelsLinksAreEntriesToo) {
  InstallWiki();
  EnableWiki();
  EXPECT_EQ("", Tree(reader_, "/nowhere", "admin"));
  EXPECT_EQ("Menus /admin/menus\n", Tree(menuman_, "/nowhere", "admin"));
}

/* ---- visibility is the route's own check ----------------------------------------- */

TEST_F(Menus, AnAnonymousVisitorSeesNoAdminEntryAnywhere) {
  InstallWiki();
  EnableWiki();
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.settings", "main", "Settings",
                             "wiki.admin"));
  /* Menus, tabs and breadcrumbs, as the visitor and as the one who may. */
  for (const char * path : {"/nowhere", "/admin/wiki", "/admin/wiki/sub",
           "/admin/menus", "/node/" /* + id below */}) {
    std::string full = path;
    if (full == "/node/") {
      full += alpha_ + "/edit";
    }
    std::string seen = Tree("", full, "admin") + Tree("", full, "main") +
                       Tabs("", full) + Crumbs("", full);
    EXPECT_EQ(std::string::npos, seen.find("settings")) << full << "\n" << seen;
    EXPECT_EQ(std::string::npos, seen.find("Settings")) << full << "\n" << seen;
    EXPECT_EQ(std::string::npos, seen.find("Menus")) << full << "\n" << seen;
    EXPECT_EQ(std::string::npos, seen.find("Edit")) << full << "\n" << seen;
  }
  /* CONTROL: those who may follow the routes see them. */
  EXPECT_NE(std::string::npos,
      Tree(wikiadmin_, "/nowhere", "admin").find("Wiki settings"));
  EXPECT_NE(std::string::npos, Tree(wikiadmin_, "/nowhere", "main").find("Settings"));
  EXPECT_NE(std::string::npos, Tree(menuman_, "/nowhere", "admin").find("Menus"));
  EXPECT_NE(std::string::npos,
      Tabs(editor_, "/node/" + alpha_).find("Edit"));
  EXPECT_EQ("", Tree("", "/admin/wiki", "admin"));
}

TEST_F(Menus, ATabIsShownOnlyForAnXTheRouteAllows) {
  InstallWiki();
  EnableWiki();
  const std::string a = alpha_;
  const std::string b = beta_;
  /* The visitor reads, so the view tab is the page itself; the edit and
   * history tabs need `update` of that node. */
  EXPECT_EQ("View /node/" + a + " *\n", Tabs("", "/node/" + a));
  /* An editor may edit every node: three tabs, the values put in. */
  EXPECT_EQ("View /node/" + a + " *\n"
            "Edit /node/" + a + "/edit\n"
            "History /node/" + a + "/history\n",
      Tabs(editor_, "/node/" + a));
  EXPECT_EQ("View /node/" + b + " *\n"
            "Edit /node/" + b + "/edit\n"
            "History /node/" + b + "/history\n",
      Tabs(editor_, "/node/" + b));
  /* An author may edit what they made, and the tab for another's node is not
   * there: the same viewer, two values of X. */
  EXPECT_EQ("View /node/" + author_node_ + " *\n"
            "Edit /node/" + author_node_ + "/edit\n"
            "History /node/" + author_node_ + "/history\n",
      Tabs(author_, "/node/" + author_node_));
  EXPECT_EQ("View /node/" + a + " *\n", Tabs(author_, "/node/" + a));
  /* The strip is the same on any tab of the page, and the tab the page is on is
   * the one marked. */
  EXPECT_EQ("View /node/" + a + "\n"
            "Edit /node/" + a + "/edit *\n"
            "History /node/" + a + "/history\n",
      Tabs(editor_, "/node/" + a + "/edit"));
  /* A path with no such node, and a page with no tabs, have none to show. */
  EXPECT_EQ("", Tabs(editor_, "/node/not-a-node"));
  EXPECT_EQ("", Tabs(editor_, "/wiki"));
}

TEST_F(Menus, VisibilityIsWhatTheRouteTableSaysAboutThatRoute) {
  InstallWiki();
  EnableWiki();
  /* Not a second predicate: for every viewer and every node, an entry is shown
   * exactly when the route table, asked about that route with that page's
   * values, says the viewer may follow it. */
  GDEFCORE_Routes * routes = Table();
  int shown_somewhere = 0;
  int hidden_somewhere = 0;
  for (const std::string & who : {std::string(), reader_, editor_, author_,
           wikiadmin_, menuman_}) {
    for (const std::string & id : {alpha_, beta_, author_node_}) {
      GDEFCORE_Request * req = Req(who);
      GDEFCORE_Route_Match * match = Match(routes, req, "/node/" + id);
      GDEFCORE_Menu * tabs = NULL;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_menu_tabs(catalog_, routes, req, match, &tabs));
      for (const char * tab : {"wiki.view", "wiki.edit", "wiki.history"}) {
        int allowed = 99;
        bool in_menu = false;
        ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_permits(routes, req, tab,
                                   strlen(tab), match, &allowed));
        for (size_t i = 0; i < gdefcore_menu_count(tabs); i++) {
          GDEFCORE_Menu_Item it;
          memset(&it, 0, sizeof it);
          it.size = sizeof it;
          ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_item(tabs, i, &it));
          in_menu = in_menu || std::string(it.route, it.route_len) == tab;
        }
        EXPECT_EQ(allowed != 0, in_menu) << tab << " for " << who << " on " << id;
        shown_somewhere += in_menu;
        hidden_somewhere += !in_menu;
      }
      gdefcore_menu_free(tabs);
      gdefcore_route_match_free(match);
    }
  }
  EXPECT_GT(shown_somewhere, 0) << "CONTROL: some tab is shown";
  EXPECT_GT(hidden_somewhere, 0) << "CONTROL: some tab is not";
}

TEST_F(Menus, AnEntryWhoseRouteNeedsAValueThePageDidNotCaptureIsNotShown) {
  InstallWiki();
  EnableWiki();
  EXPECT_EQ("Start /start\nWiki /wiki * ^\n  Recent /wiki *\n",
      Tree(editor_, "/wiki", "main"));
  /* On a node's page the link to "this node" has a path. */
  EXPECT_EQ("Start /start\nWiki /wiki\n  Recent /wiki\nThis node /node/" + alpha_ +
                " *\n",
      Tree(reader_, "/node/" + alpha_, "main"));
  EXPECT_EQ("Start /start\nWiki /wiki\n  Recent /wiki\nThis node /node/" + beta_ +
                " *\n",
      Tree(reader_, "/node/" + beta_, "main"))
      << "CONTROL: the value is the page's";
}

/* ---- the site's changes: overrides ---------------------------------------------- */

TEST_F(Menus, OverridesRenameReweightHideAndMoveAndOnlyThose) {
  InstallWiki();
  EnableWiki();
  Ov rename;
  rename.label = "Pages";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", rename));
  EXPECT_EQ("Start /start\nPages /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  Ov weigh;
  weigh.has_weight = true;
  weigh.weight = -20;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", weigh));
  EXPECT_EQ("Wiki /wiki\n  Recent /wiki\nStart /start\n",
      Tree(reader_, "/nowhere", "main"))
      << "the second override is the override: the label is the module's again";
  Ov both;
  both.label = "Pages";
  both.has_weight = true;
  both.weight = -20;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", both));
  EXPECT_EQ("Pages /wiki\n  Recent /wiki\nStart /start\n",
      Tree(reader_, "/nowhere", "main"));
  /* Move: a child to the top, and an entry to another menu. */
  Ov up;
  up.parent = GDEFCORE_MENU_TOP;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-recent", up));
  EXPECT_EQ("Pages /wiki\nStart /start\nRecent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  Ov away;
  away.menu = "footer";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-recent", away));
  EXPECT_EQ("Pages /wiki\nStart /start\n", Tree(reader_, "/nowhere", "main"));
  EXPECT_EQ("Recent /wiki\n", Tree(reader_, "/nowhere", "footer"));
  /* Under a parent of another menu is under no parent. */
  Ov under;
  under.parent = "core.l-start";
  under.menu = "main";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-recent", under));
  EXPECT_EQ("Pages /wiki\nStart /start\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  /* Reset: forget the override, and the entry is the module's. */
  ASSERT_EQ(GDEFCORE_OK, Forget("", "wiki.l-recent", kOverride));
  ASSERT_EQ(GDEFCORE_OK, Forget("", "wiki.l-index", kOverride));
  EXPECT_EQ("Start /start\nWiki /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
}

TEST_F(Menus, HidingAnEntryRemovesItFromEveryOutputButNotTheRoute) {
  InstallWiki();
  EnableWiki();
  GDEFCORE_Routes * routes = Table();
  Ov hide;
  hide.hidden = 1;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.edit", hide));
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-admin", hide));
  const std::string a = alpha_;
  /* The tab is gone for the editor who may edit, on every tab of the page. */
  EXPECT_EQ("View /node/" + a + " *\nHistory /node/" + a + "/history\n",
      Tabs(editor_, "/node/" + a));
  EXPECT_EQ("View /node/" + a + "\nHistory /node/" + a + "/history\n",
      Tabs(editor_, "/node/" + a + "/edit"));
  /* The hidden link is gone for the one who may follow it, and so is what is
   * under it, and the breadcrumbs leave it out. */
  EXPECT_EQ("", Tree(wikiadmin_, "/nowhere", "admin"));
  EXPECT_EQ("", Crumbs(wikiadmin_, "/admin/wiki"))
      << "the crumb of the page itself is hidden too";
  /* The route is still served: the page is there, to someone who may. */
  GDEFCORE_Request * req = Req(wikiadmin_);
  GDEFCORE_Route_Match * match = Match(routes, req, "/admin/wiki");
  ASSERT_EQ(1u, gdefcore_route_match_route_count(match));
  const char * m = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_route_match_route(match, 0, &m, &n));
  EXPECT_EQ("wiki.admin", std::string(m, n));
  gdefcore_route_match_free(match);
  /* And the editor's list still has it, marked. */
  EXPECT_NE(std::string::npos,
      Entries(menuman_, "/nowhere").find("Wiki settings /admin/wiki ! ?"));
  /* CONTROL: the entry nobody hid is still shown. */
  EXPECT_NE(std::string::npos, Tabs(editor_, "/node/" + a).find("History"));
}

TEST_F(Menus, AnOverrideStoresOnlyWhatTheSiteChangedAndFollowsTheEntryThroughAnUpgrade) {
  InstallWiki();
  EnableWiki();
  Ov weigh;
  weigh.has_weight = true;
  weigh.weight = 9;
  ASSERT_EQ(GDEFCORE_OK, Override("", "core.l-start", weigh));
  /* What is stored: the name and the weight; no label, no route, no copy. */
  EXPECT_EQ("name=core.l-start;weight=9;", StoredOverride("core.l-start"));
  EXPECT_EQ("Wiki /wiki\n  Recent /wiki\nStart /start\n",
      Tree(reader_, "/nowhere", "main"));
  /* The kernel is upgraded: the entry's label is another one. The override
   * holds nothing the entry says, so the new label shows, with the old weight. */
  GDEFCORE_Routes * upgraded = Table("Begin");
  EXPECT_EQ("Wiki /wiki\n  Recent /wiki\nBegin /start\n",
      Tree(reader_, "/nowhere", "main", upgraded));
  /* CONTROL: an override that does set the label keeps the site's. */
  Ov rename;
  rename.label = "Home";
  ASSERT_EQ(GDEFCORE_OK, Override("", "core.l-start", rename));
  EXPECT_EQ("name=core.l-start;label=Home;", StoredOverride("core.l-start"));
  EXPECT_EQ("Home /start\nWiki /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main", Table("Begin")));
}

TEST_F(Menus, AnOverrideSurvivesDisablingAndEnablingTheModule) {
  InstallWiki();
  EnableWiki();
  Ov all;
  all.label = "Pages";
  all.has_weight = true;
  all.weight = 7;
  all.parent = GDEFCORE_MENU_TOP;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-recent", all));
  Ov hide;
  hide.hidden = 1;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-this", hide));
  const std::string before = Tree(reader_, "/node/" + alpha_, "main");
  EXPECT_EQ("Start /start\nWiki /wiki\nPages /wiki\n", before);
  /* Disabled: the entries are gone, and the overrides are not applied to
   * anything. The site's other entries are untouched. */
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.keep", "main", "Keep", "core.start"));
  ASSERT_EQ(GDEFCORE_OK, Disable("wiki"));
  EXPECT_EQ("Start /start\nKeep /start\n",
      Tree(reader_, "/node/" + alpha_, "main", Table()));
  EXPECT_EQ("name=wiki.l-recent;label=Pages;weight=7;parent=-;",
      StoredOverride("wiki.l-recent"))
      << "the override is still stored";
  /* Enabled again: the same menu, twice over. */
  EnableWiki();
  EXPECT_EQ("Start /start\nKeep /start\nWiki /wiki\nPages /wiki\n",
      Tree(reader_, "/node/" + alpha_, "main"));
  ASSERT_EQ(GDEFCORE_OK, Disable("wiki"));
  EnableWiki();
  EXPECT_EQ("Start /start\nKeep /start\nWiki /wiki\nPages /wiki\n",
      Tree(reader_, "/node/" + alpha_, "main"));
}

TEST_F(Menus, TheMenuDoesNotDependOnTheOrderModulesWereEnabledIn) {
  /* Two modules each with links in the same menu, enabled in either order,
   * twice, and off and on again: one menu. */
  std::string first;
  for (int order = 0; order < 4; order++) {
    Defs().clear();
    Close();
    Open();
    DefinePost();
    ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_declare(catalog_));
    Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "anonymous", 9, "Read posts", 10,
            GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
            strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
    ModDef * one = NewMod("alpha");
    one->Route("alpha.page", "/alpha", "Alpha", "read");
    one->Link("alpha.link", "main", "Alpha", "alpha.page", 3);
    one->Link("alpha.link2", "main", "Alpha child", "alpha.page", 0, "alpha.link");
    ASSERT_EQ(GDEFCORE_OK, Install(one));
    ModDef * two = NewMod("beta");
    two->Route("beta.page", "/beta", "Beta", "read");
    two->Link("beta.link", "main", "Beta", "beta.page", 3);
    two->Link("beta.link2", "main", "Beta child", "beta.page", 0, "beta.link");
    ASSERT_EQ(GDEFCORE_OK, Install(two));
    if (order == 1) {
      ASSERT_EQ(GDEFCORE_OK, Enable("beta", {}));
      ASSERT_EQ(GDEFCORE_OK, Enable("alpha", {}));
    } else {
      ASSERT_EQ(GDEFCORE_OK, Enable("alpha", {}));
      ASSERT_EQ(GDEFCORE_OK, Enable("beta", {}));
    }
    if (order == 2) {
      ASSERT_EQ(GDEFCORE_OK, Disable("alpha"));
      ASSERT_EQ(GDEFCORE_OK, Enable("alpha", {}));
    }
    if (order == 3) {
      /* Enabled a second time: refused or a no-op, and the menu is the same. */
      (void)Enable("alpha", {});
      (void)Enable("beta", {});
    }
    std::string now = Tree("", "/nowhere", "main");
    EXPECT_EQ("Alpha /alpha\n  Alpha child /alpha\nBeta /beta\n  Beta child /beta\n",
        now.substr(now.find("Alpha /alpha")))
        << "after the kernel's own link";
    if (order == 0) {
      first = now;
    }
    EXPECT_EQ(first, now) << "order " << order;
  }
}

TEST_F(Menus, AnOverrideThatWouldMakeALoopLeavesTheEntryAtTheTop) {
  InstallWiki();
  EnableWiki();
  Ov a;
  a.parent = "wiki.l-recent";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", a));   /* index under recent */
  /* recent is under index, index under recent: a loop. Neither is lost. */
  std::string seen = Tree(reader_, "/nowhere", "main");
  EXPECT_NE(std::string::npos, seen.find("Wiki /wiki")) << seen;
  EXPECT_NE(std::string::npos, seen.find("Recent /wiki")) << seen;
  /* An entry under itself is at the top. */
  Ov self;
  self.parent = "core.l-start";
  ASSERT_EQ(GDEFCORE_OK, Override("", "core.l-start", self));
  EXPECT_NE(std::string::npos, Tree(reader_, "/nowhere", "main").find("Start /start"));
}

/* ---- tenants ------------------------------------------------------------------------ */

TEST_F(Menus, TwoTenantsMenusEntriesAndOverridesNeverMix) {
  InstallWiki();
  EnableWiki();
  GDEFCORE_Catalog * other = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store_, (const uint8_t *)"u", 1,
                             NULL, NULL, &other));
  gdefcore_catalog_bind_host(other, host_);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_declare(other));
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.mine", "main", "Tenant T only",
                             "core.start"));
  Ov rename;
  rename.label = "T's start";
  ASSERT_EQ(GDEFCORE_OK, Override("", "core.l-start", rename));
  /* The other tenant's own entry and override. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(other, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_stage_entry(cs, "site.theirs", 11, "main",
                               4, "Tenant U only", 13, "core.start", 10, "", 0, 0));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kEntry, strlen(kEntry)));
    gdefcore_changeset_destroy(cs);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(other, NULL, 0, &cs));
    GDEFCORE_Menu_Override o;
    memset(&o, 0, sizeof o);
    o.size = sizeof o;
    o.hidden = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_menu_stage_override(cs, "core.l-start", 12, &o));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_apply(cs, kOverride, strlen(kOverride)));
    gdefcore_changeset_destroy(cs);
  }
  auto tree_of = [&](GDEFCORE_Catalog * catalog, const char * tenant) {
    GDEFCORE_Request * req = NULL;
    GDEFCORE_Routes * routes = Table();
    GDEFCORE_Menu * m = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_create((const uint8_t *)tenant, 1, 0, 0,
                               NULL, &req));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_menu_tree(catalog, routes, req, NULL, "main", 4, &m));
    std::string out = Dump(m);
    gdefcore_menu_free(m);
    gdefcore_request_destroy(req);
    return out;
  };
  /* Each sees its own entry and its own override, and the wiki module is
   * enabled for tenant t only (the other tenant's table has the kernel's
   * links alone). */
  EXPECT_EQ("T's start /start\nTenant T only /start\nWiki /wiki\n  Recent /wiki\n",
      tree_of(catalog_, "t"));
  EXPECT_EQ("Tenant U only /start\n", tree_of(other, "u"))
      << "u's override hid the start link; t's entry and label are not here";
  gdefcore_catalog_bind_host(other, NULL);
  gdefcore_catalog_destroy(other);
}

/* ---- breadcrumbs -------------------------------------------------------------------- */

TEST_F(Menus, BreadcrumbsComeFromTheSameTree) {
  InstallWiki();
  EnableWiki();
  /* A page, its parent entry above it, and a tab through the page it shows on. */
  EXPECT_EQ("Wiki /wiki *\n", Crumbs(reader_, "/wiki"))
      << "two entries go to the page; the first by weight is its entry";
  EXPECT_EQ("Wiki settings /admin/wiki *\n", Crumbs(wikiadmin_, "/admin/wiki"));
  EXPECT_EQ("Wiki settings /admin/wiki\nSub settings /admin/wiki/sub *\n",
      Crumbs(wikiadmin_, "/admin/wiki/sub"));
  /* A page with a title and no entry is its own trail; a path no route reaches
   * has none. */
  EXPECT_EQ("Start /start *\n", Crumbs(reader_, "/start"));
  EXPECT_EQ("", Crumbs(reader_, "/nowhere"));
  /* A tab: the page it is a tab of comes first, then the tab. */
  EXPECT_EQ("This node /node/" + alpha_ + "\nEdit /node/" + alpha_ + "/edit *\n",
      Crumbs(editor_, "/node/" + alpha_ + "/edit"));
  /* The entry above the page is the site's to move. */
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.top", "main", "Top", "core.start"));
  Ov under;
  under.parent = "site.top";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", under));
  EXPECT_EQ("Top /start\nWiki /wiki *\n", Crumbs(reader_, "/wiki"));
}

TEST_F(Menus, ACrumbAboveThePageThatIsHiddenOrUnreachableIsLeftOutWithoutATrace) {
  InstallWiki();
  EnableWiki();
  /* A child of the wiki's admin link: the parent needs wiki.admin, the child
   * (a site entry) goes to a route anyone may follow. */
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.under-admin", "admin", "Docs",
                             "wiki.index", "wiki.l-admin"));
  /* The visitor never sees the admin link, and the trail of the page under it
   * has no gap or mark where it was. */
  std::string visitor = Crumbs("", "/wiki", "admin");
  EXPECT_EQ("Docs /wiki *\n", visitor);
  EXPECT_EQ(std::string::npos, visitor.find("settings"));
  /* CONTROL: the one who may follow the admin link has it in the trail. */
  EXPECT_EQ("Wiki settings /admin/wiki\nDocs /wiki *\n",
      Crumbs(wikiadmin_, "/wiki", "admin"));
  /* Hiding it leaves it out for the one who may follow it too. */
  Ov hide;
  hide.hidden = 1;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-admin", hide));
  EXPECT_EQ("Docs /wiki *\n", Crumbs(wikiadmin_, "/wiki", "admin"));
  /* The hidden page itself is not a crumb either. */
  EXPECT_EQ("", Crumbs(wikiadmin_, "/admin/wiki", "admin"));
}

/* ---- who may edit ------------------------------------------------------------------- */

TEST_F(Menus, EditingMenusIsOnePermissionCheckedAtApplyForAChangesetWithARequest) {
  InstallWiki();
  EnableWiki();
  Ov rename;
  rename.label = "Pages";
  /* The operator's changeset carries no request and is not asked. A request
   * that holds no grant is refused with the one sentence, and nothing is
   * written; the principal who holds the permission writes. */
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.op", "main", "Operator", "core.start"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      SiteEntry(reader_, "site.nope", "main", "Nope", "core.start"));
  EXPECT_EQ("That edit is not allowed.", refusal_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Override(reader_, "wiki.l-index", rename));
  EXPECT_EQ("That edit is not allowed.", refusal_);
  std::string seen = Tree(reader_, "/nowhere", "main");
  EXPECT_NE(std::string::npos, seen.find("Operator /start")) << seen;
  EXPECT_EQ(std::string::npos, seen.find("Nope")) << seen;
  EXPECT_EQ("<none>", StoredOverride("wiki.l-index"));
  /* CONTROL: the menu manager may. */
  EXPECT_EQ(GDEFCORE_OK,
      SiteEntry(menuman_, "site.mine", "main", "Mine", "core.start"));
  EXPECT_EQ(GDEFCORE_OK, Override(menuman_, "wiki.l-index", rename));
  EXPECT_EQ("name=wiki.l-index;label=Pages;", StoredOverride("wiki.l-index"));
  /* A permitted change still needs the typed confirmation of any configuration
   * write, and says nothing about permission when it is missing. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Change(menuman_, [&](GDEFCORE_Changeset * cs) {
        EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_stage_entry(cs, "site.more", 9, "main",
                                   4, "More", 4, "core.start", 10, "", 0, 0));
      }, "yes"));
  EXPECT_EQ("", refusal_);
  EXPECT_EQ(std::string::npos,
      Tree(reader_, "/nowhere", "main").find("More"));
}

TEST_F(Menus, AGrantNarrowedToOneMenuEditsThatMenuAndCannotMoveAnEntryOutOfIt) {
  InstallWiki();
  EnableWiki();
  Role("mainonly");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("mainonly", GDEFCORE_MENU_EDIT_ENTRY_LABEL,
                             "(= field.menu \"main\")"));
  std::string who = Principal("mainonly");
  EXPECT_EQ(GDEFCORE_OK, SiteEntry(who, "site.a", "main", "A", "core.start"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      SiteEntry(who, "site.b", "admin", "B", "core.start"));
  EXPECT_EQ("That edit is not allowed.", refusal_);
  /* The entry it made, moved to another menu: refused, since the menu it
   * becomes is not one the grant covers; the stored entry is unchanged. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      SiteEntry(who, "site.a", "admin", "A", "core.start"));
  EXPECT_NE(std::string::npos, Tree(reader_, "/nowhere", "main").find("A /start"));
  /* And an entry of another menu cannot be pulled into this one and so edited:
   * a new entry in admin is refused whatever it is called. */
  EXPECT_EQ(GDEFCORE_OK, SiteEntry(menuman_, "site.c", "admin", "C", "core.start"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      SiteEntry(who, "site.c", "main", "C", "core.start"))
      << "it is stored in admin, and the grant is for main";
  /* An override has its own grant: this role holds none of it. */
  Ov rename;
  rename.label = "x";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Override(who, "wiki.l-index", rename));
}

/* ---- the staging rules -------------------------------------------------------------------- */

TEST_F(Menus, StagingRefusesWhatCannotBeAnEntryOrAnOverride) {
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  auto entry = [&](const std::string & name, const std::string & menu,
                   const std::string & label, const std::string & route,
                   const std::string & parent, int weight) {
    return gdefcore_menu_stage_entry(cs, name.data(), name.size(), menu.data(),
        menu.size(), label.data(), label.size(), route.data(), route.size(),
        parent.data(), parent.size(), weight);
  };
  EXPECT_EQ(GDEFCORE_OK, entry("site.ok", "main", "Fine", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("wiki.x", "main", "L", "", "", 0))
      << "a site entry is site.<name>";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.", "main", "L", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.UP", "main", "L", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "Main", "L", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "", "L", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "main", "", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "main", "bad\nlabel", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      entry("site.y", "main", std::string(GDEFCORE_MENU_LABEL_MAX + 1, 'x'), "", "", 0));
  EXPECT_EQ(GDEFCORE_OK,
      entry("site.y", "main", std::string(GDEFCORE_MENU_LABEL_MAX, 'x'), "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "main", "\xc0\xaf", "", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "main", "L", "Bad Route", "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "main", "L", "", "Bad Parent", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, entry("site.y", "main", "L", "", "", 1000000000));
  GDEFCORE_Menu_Override o;
  memset(&o, 0, sizeof o);
  o.size = sizeof o;
  o.hidden = -1;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_stage_override(cs, "wiki.l-index", 12, &o));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_menu_stage_override(cs, "site.ok", 7, &o))
      << "a site entry is changed itself, not overridden";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_menu_stage_override(cs, "plain", 5, &o))
      << "a generated name has an owner";
  o.hidden = 2;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_menu_stage_override(cs, "wiki.l-recent", 13, &o));
  o.hidden = -1;
  o.parent = "Bad Parent";
  o.parent_len = 10;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_menu_stage_override(cs, "wiki.l-recent", 13, &o));
  o.parent = GDEFCORE_MENU_TOP;
  o.parent_len = 1;
  o.menu = "No Menu";
  o.menu_len = 7;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_menu_stage_override(cs, "wiki.l-recent", 13, &o));
  o.size = sizeof o - 1;
  o.menu = NULL;
  o.menu_len = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_menu_stage_override(cs, "wiki.l-recent", 13, &o));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_menu_stage_forget(cs, "site.nothing", 12));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_menu_stage_forget(cs, "wiki.never", 10));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_menu_stage_forget(cs, "", 0));
  gdefcore_changeset_destroy(cs);
  /* Nothing was applied: no entry exists but the kernel's. */
  EXPECT_EQ("Start /start\n", Tree(reader_, "/nowhere", "main"));
}

TEST_F(Menus, StagingNeedsTheTypesToBeDeclared) {
  Close();
  Open();
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_menu_stage_entry(cs, "site.a", 6, "main",
                                      4, "A", 1, "", 0, "", 0, 0));
  gdefcore_changeset_destroy(cs);
  /* Reading needs none of it. */
  GDEFCORE_Routes * routes = Table();
  GDEFCORE_Menu * m = NULL;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_menu_tree(catalog_, routes, Req(), NULL, "main", 4, &m));
  EXPECT_EQ("Start /start\n", Dump(m));
  gdefcore_menu_free(m);
  /* Declaring twice changes nothing. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_declare(catalog_));
  uint64_t epoch = Epoch();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_declare(catalog_));
  EXPECT_EQ(epoch, Epoch());
}

TEST_F(Menus, TheEditorsListIsForThoseWhoMayEditAndShowsWhatIsHidden) {
  InstallWiki();
  EnableWiki();
  Ov hide;
  hide.hidden = 1;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-recent", hide));
  GDEFCORE_Result rc = GDEFCORE_OK;
  EXPECT_EQ("", Entries(reader_, "/nowhere", &rc));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  EXPECT_EQ("", Entries("", "/nowhere", &rc));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  std::string all = Entries(menuman_, "/nowhere");
  EXPECT_EQ("Menus /admin/menus\n"
            "Wiki settings /admin/wiki ?\n"
            "  Sub settings /admin/wiki/sub ?\n"
            "Start /start\n"
            "Wiki /wiki\n"
            "  Recent /wiki ! ?\n"
            "This node ?\n"
            "This wiki page ?\n"
            "View ?\n"
            "Edit ?\n"
            "History ?\n",
      all);
  EXPECT_TRUE(gdefcore_menu_may_edit(catalog_, Req(menuman_)));
  EXPECT_FALSE(gdefcore_menu_may_edit(catalog_, Req(reader_)));
  EXPECT_FALSE(gdefcore_menu_may_edit(catalog_, Req()));
}

TEST_F(Menus, ATabIsAnEntryLikeAnyOtherWithTheSameOverrides) {
  InstallWiki();
  EnableWiki();
  const std::string a = alpha_;
  Ov rename;
  rename.label = "Change";
  rename.has_weight = true;
  rename.weight = -5;
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.edit", rename));
  EXPECT_EQ("Change /node/" + a + "/edit\nView /node/" + a + " *\nHistory /node/" +
                a + "/history\n",
      Tabs(editor_, "/node/" + a));
  EXPECT_EQ("View /node/" + a + " *\n", Tabs("", "/node/" + a))
      << "CONTROL: the renamed tab is still the route's to allow";
  /* Moved to a page that has no value to put in it, a tab has no path there
   * and is not shown; moved to the page it is on, it is where it was. */
  Ov away;
  away.parent = "wiki.index";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.edit", away));
  EXPECT_EQ("View /node/" + a + " *\nHistory /node/" + a + "/history\n",
      Tabs(editor_, "/node/" + a));
  EXPECT_EQ("", Tabs(editor_, "/wiki"));
  Ov back;
  back.parent = "wiki.node";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.edit", back));
  EXPECT_EQ("View /node/" + a + " *\nEdit /node/" + a + "/edit\nHistory /node/" + a +
                "/history\n",
      Tabs(editor_, "/node/" + a));
  /* A tab moved under a parent that is nothing at all is shown nowhere. */
  Ov lost;
  lost.parent = "nothing.here";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.edit", lost));
  EXPECT_EQ("View /node/" + a + " *\nHistory /node/" + a + "/history\n",
      Tabs(editor_, "/node/" + a));
}

TEST_F(Menus, WhatIsStoredBadlyIsIgnoredAndNeverShownOrTrusted) {
  InstallWiki();
  EnableWiki();
  /* Written straight to the port, past the staging that would refuse them. */
  auto raw = [&](const char * type, std::vector<std::pair<std::string, std::string> > fields) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> values(fields.size());
    std::vector<const char *> slots(fields.size());
    std::vector<size_t> lens(fields.size());
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, type, strlen(type), id, NULL));
    for (size_t i = 0; i < fields.size(); i++) {
      memset(&values[i], 0, sizeof values[i]);
      slots[i] = fields[i].second.c_str();
      lens[i] = fields[i].second.size();
      values[i].size = sizeof values[i];
      values[i].field = fields[i].first.c_str();
      values[i].field_len = fields[i].first.size();
      values[i].texts = &slots[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en",
                               2, values.data(), values.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, type, strlen(type)));
    gdefcore_changeset_destroy(cs);
  };
  /* Entries: a name outside site.*, a menu that is not a name, a label with a
   * control byte, one that is fine. */
  raw(kEntry, {{"name", "wiki.sneaky"}, {"menu", "main"}, {"label", "Sneaky"}, {"route", "core.start"}});
  raw(kEntry, {{"name", "site.bad-menu"}, {"menu", "Main Menu"}, {"label", "Bad menu"}, {"route", "core.start"}});
  raw(kEntry, {{"name", "site.bad-label"}, {"menu", "main"}, {"label", "bad\nlabel"}, {"route", "core.start"}});
  raw(kEntry, {{"name", "site.fine"}, {"menu", "main"}, {"label", "Fine"}, {"route", "core.start"}, {"weight", "banana"}});
  /* Overrides: a label that is too long, a weight that is not a number, a
   * hidden that is not 0 or 1, a parent that is not a name. Only the valid
   * field of each applies. */
  raw(kOverride, {{"name", "core.l-start"}, {"label", std::string(300, 'x')}, {"weight", "1e9"}, {"hidden", "yes"}, {"parent", "Not A Name"}});
  raw(kOverride, {{"name", "Not A Name"}, {"label", "Ghost"}});
  std::string seen = Tree(reader_, "/nowhere", "main");
  EXPECT_EQ(std::string::npos, seen.find("Sneaky")) << seen;
  EXPECT_EQ(std::string::npos, seen.find("Bad menu")) << seen;
  EXPECT_EQ(std::string::npos, seen.find("bad")) << seen;
  EXPECT_EQ(std::string::npos, seen.find("Ghost")) << seen;
  EXPECT_NE(std::string::npos, seen.find("Fine /start")) << "CONTROL: " << seen;
  EXPECT_NE(std::string::npos, seen.find("Start /start")) << seen;
  EXPECT_EQ(std::string::npos, seen.find("xxx")) << seen;
}

TEST_F(Menus, EveryWriteIsARevisionAndUndoRestoresTheMenu) {
  InstallWiki();
  EnableWiki();
  Ov first;
  first.label = "Pages";
  Ov second;
  second.label = "Docs";
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", first));
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", second));
  EXPECT_EQ("Start /start\nDocs /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  /* The override is one entity, with a revision for each write. */
  char ** ids = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, kOverride, strlen(kOverride),
                             &ids, &n));
  ASSERT_EQ(1u, n);
  std::string id = ids[0];
  gdefcore_ids_free(catalog_, ids, n);
  size_t revisions = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_revision_count(catalog_, id.c_str(),
                             id.size(), &revisions));
  EXPECT_EQ(2u, revisions);
  auto undo = [&]() {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_revert(catalog_, id.c_str(), id.size(),
                               NULL, 0, &cs));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kOverride, strlen(kOverride)));
    gdefcore_changeset_destroy(cs);
  };
  undo();
  EXPECT_EQ("Start /start\nPages /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  /* Undo is a revision too, so it can be undone: the label the second write
   * made is back. */
  undo();
  EXPECT_EQ("Start /start\nDocs /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  /* Forgetting the override is a clear, so history keeps it: the entry is the
   * module's again, and the next override of it is made afresh. */
  ASSERT_EQ(GDEFCORE_OK, Forget("", "wiki.l-index", kOverride));
  EXPECT_EQ("Start /start\nWiki /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  ASSERT_EQ(GDEFCORE_OK, Override("", "wiki.l-index", first));
  EXPECT_EQ("Start /start\nPages /wiki\n  Recent /wiki\n",
      Tree(reader_, "/nowhere", "main"));
  /* A forgotten site entry is gone from the menu. */
  ASSERT_EQ(GDEFCORE_OK, SiteEntry("", "site.tmp", "main", "Temporary", "core.start"));
  ASSERT_EQ(GDEFCORE_OK, Forget("", "site.tmp", kEntry));
  EXPECT_EQ(std::string::npos, Tree(reader_, "/nowhere", "main").find("Temporary"));
}

class MenusWithTheKit : public Menus {
 protected:
  MenusWithTheKit() { use_kit_ = true; }
};

TEST_F(MenusWithTheKit, InstallingTheKitDeclaresTheTypesAndThePermission) {
  /* SetUp installed the kit and then declared again: once is all there is. */
  int kind = 0;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, kEntry, strlen(kEntry), &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONFIG, kind);
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_type_kind(catalog_, kOverride, strlen(kOverride), &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONFIG, kind);
  /* Nobody holds the permission, admin included, until a role is granted it
   * (CONTROL: the role the fixture made holds it). */
  EXPECT_EQ(0, gdefcore_menu_may_edit(catalog_, Req(Admin())));
  EXPECT_EQ(0, gdefcore_menu_may_edit(catalog_, Req(reader_)));
  EXPECT_EQ(1, gdefcore_menu_may_edit(catalog_, Req(menuman_)));
  /* The site entry is written to a catalog that took the kit. */
  EXPECT_EQ(GDEFCORE_OK, SiteEntry("", "site.kit", "main", "Kit", "core.start"));
  EXPECT_NE(std::string::npos, Tree(reader_, "/nowhere", "main").find("Kit /start"));
}

TEST_F(Menus, TheStructsHereAreAcceptedAtOnlyTheirOwnSize) {
  InstallWiki();
  EnableWiki();
  GDEFCORE_Routes * routes = Table();
  GDEFCORE_Menu * menu = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_tree(catalog_, routes, Req(), NULL, "main",
                             4, &menu));
  ASSERT_GT(gdefcore_menu_count(menu), 0u);
  int n = 0;
  const std::map<std::string, size_structs::Probe> probes = {
      GDEFCORE_SIZE_PROBE(GDEFCORE_Menu_Item, {
        GDEFCORE_Menu_Item it;
        memset(&it, 0, sizeof it);
        it.size = size;
        return gdefcore_menu_item(menu, 0, &it) == GDEFCORE_OK;
      }),
      GDEFCORE_SIZE_PROBE(GDEFCORE_Menu_Override, {
        GDEFCORE_Changeset * cs = NULL;
        std::string name = "wiki.size" + std::to_string(n++);
        GDEFCORE_Menu_Override o;
        memset(&o, 0, sizeof o);
        o.size = size;
        o.hidden = -1;
        EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
        bool ok = gdefcore_menu_stage_override(cs, name.data(), name.size(), &o) ==
                  GDEFCORE_OK;
        gdefcore_changeset_destroy(cs);
        return ok;
      }),
  };
  size_structs::Run("tests/test_menu.cpp", probes);
  gdefcore_menu_free(menu);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
