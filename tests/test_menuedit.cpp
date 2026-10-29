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
 * Editing menus (site admin story 10): add, rename, hide, remove, move, and
 * the moves the keyboard makes, each one changeset; a generated entry changes
 * by an override keyed by its machine name and never by a copy; a stale edit,
 * a move into the entry's own subtree and a move under an entry that is not
 * there are refused with nothing written; and the last edit is undone in one
 * changeset.
 *
 * Every test carries a CONTROL: the same call that is refused with the thing
 * wrong is accepted with it right, so a refusal is a refusal and not a call
 * that could never work. The real-source plants are in tools/check-menuedit.sh,
 * and each names the test that must turn red.
 */

#include "grants_fixture.h"
#include "size_structs.h"

namespace {

using namespace gfx;

const char kEntry[] = "core.menu-entry";
const char kOverride[] = "core.menu-override";
const char kChange[] = "core.menu-change";

class MenuEdit : public GrantsFixture {
 protected:
  std::vector<GDEFCORE_Routes *> tables_;
  std::string menuman_;   /* may edit menus */
  std::string reader_;    /* holds no role */
  std::string refusal_;
  bool staged_ = false;   /* the last Edit got as far as an apply */

  void SetUp() override {
    GrantsFixture::SetUp();
    DefinePost();
    ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_declare(catalog_));
    Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "anonymous", 9, "Read posts", 10,
            GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
            strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "authenticated", 13, "Read posts", 10,
            GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
            strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED)));
    Role("menumen");
    Grant("menumen", GDEFCORE_MENU_EDIT_ENTRY_LABEL);
    Grant("menumen", GDEFCORE_MENU_EDIT_OVERRIDE_LABEL);
    menuman_ = Principal("menumen");
    reader_ = Principal();
    ModDef * m = NewMod("wiki");
    m->Route("wiki.index", "/wiki", "Wiki", "read");
    m->Route("wiki.node", "/node/:id", "Node", "read", "id");
    m->Route("wiki.slug", "/wiki/:slug", "Wiki page");
    m->Tab("wiki.view", "/node/:id/view", "wiki.node", "View", 0, "read", "id", 1);
    m->Link("wiki.l-index", "main", "Wiki", "wiki.index", 0);
    m->Link("wiki.l-recent", "main", "Recent", "wiki.index", 1, "wiki.l-index");
    m->Link("wiki.l-this", "main", "This node", "wiki.node", 5);
    m->Link("wiki.l-slug", "main", "This wiki page", "wiki.slug", 6);
    ASSERT_EQ(GDEFCORE_OK, Install(m)) << gdefcore_module_error(host_, NULL);
    ASSERT_EQ(GDEFCORE_OK, Enable("wiki", {})) << last_error_;
  }

  void TearDown() override {
    for (GDEFCORE_Routes * t : tables_) {
      gdefcore_routes_destroy(t);
    }
    tables_.clear();
    GrantsFixture::TearDown();
  }

  GDEFCORE_Routes * Table() {
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
    spec.title = "Start";
    spec.title_len = 5;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes, &spec, NULL, NULL));
    memset(&link, 0, sizeof link);
    link.size = sizeof link;
    link.name = "core.l-start";
    link.name_len = 12;
    link.menu = "main";
    link.menu_len = 4;
    link.label = "Start";
    link.label_len = 5;
    link.route = "core.start";
    link.route_len = 10;
    link.weight = -10;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_add_link(routes, &link));
    tables_.push_back(routes);
    return routes;
  }

  /* The editor's list of the main menu as @p who sees it: one line for each
   * entry, indented by depth, with name, weight and whether it is hidden. */
  std::string Shape(const std::string & who, const char * menu_name = "main") {
    GDEFCORE_Request * req = Req(who);
    GDEFCORE_Routes * table = Table();
    GDEFCORE_Route_Match * match = NULL;
    GDEFCORE_Menu * m = NULL;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_match(table, req, "/nowhere", 8, &match));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_entries(catalog_, table, req, match, &m));
    for (size_t i = 0; i < gdefcore_menu_count(m); i++) {
      GDEFCORE_Menu_Item it;
      memset(&it, 0, sizeof it);
      it.size = sizeof it;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_item(m, i, &it));
      if (std::string(it.menu, it.menu_len) != menu_name) {
        continue;
      }
      out += std::string(it.depth * 2, ' ') + std::string(it.name, it.name_len) +
             " " + std::to_string(it.weight) + (it.hidden ? " !" : "") + "\n";
    }
    gdefcore_menu_free(m);
    gdefcore_route_match_free(match);
    return out;
  }

  /* The labels the public sees in the menu, in order. */
  std::string Seen(const char * menu_name = "main") {
    GDEFCORE_Request * req = Req(reader_);
    GDEFCORE_Routes * table = Table();
    GDEFCORE_Route_Match * match = NULL;
    GDEFCORE_Menu * m = NULL;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_match(table, req, "/nowhere", 8, &match));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_tree(catalog_, table, req, match,
                               menu_name, strlen(menu_name), &m));
    for (size_t i = 0; i < gdefcore_menu_count(m); i++) {
      GDEFCORE_Menu_Item it;
      memset(&it, 0, sizeof it);
      it.size = sizeof it;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_item(m, i, &it));
      out += std::string(it.depth * 2, ' ') + std::string(it.label, it.label_len) +
             "\n";
    }
    gdefcore_menu_free(m);
    gdefcore_route_match_free(match);
    return out;
  }

  std::string Version() {
    GDEFCORE_Request * req = Req(menuman_);
    GDEFCORE_Routes * table = Table();
    GDEFCORE_Route_Match * match = NULL;
    GDEFCORE_Menu * m = NULL;
    char version[GDEFCORE_MENU_VERSION_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_match(table, req, "/nowhere", 8, &match));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_entries(catalog_, table, req, match, &m));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_version(m, version, sizeof version));
    gdefcore_menu_free(m);
    gdefcore_route_match_free(match);
    return version;
  }

  /* The types a changeset writes, sorted, one to a line: the typed
   * confirmation of a configuration write. */
  static std::string Confirm(GDEFCORE_Changeset * cs) {
    std::set<std::string> types;
    for (size_t i = 0; i < gdefcore_changeset_touched_count(cs); i++) {
      const char * type = NULL;
      size_t type_len = 0;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_touched_at(cs, i, NULL, NULL, &type,
                                 &type_len, NULL));
      types.insert(std::string(type, type_len));
    }
    std::string out;
    for (const std::string & t : types) {
      out += (out.empty() ? "" : "\n") + t;
    }
    return out;
  }

  struct Args {
    int action = 0;
    std::string name, label, menu = "main", route, parent;
    size_t position = 0;
    const char * version = NULL;   /* NULL: the version of the menus now */
  };

  size_t Touched_ = 0;

  /* Stage one edit as @p who and apply it. The result is the stage's when that
   * failed, else the apply's. */
  GDEFCORE_Result Edit(const std::string & who, const Args & a) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Request * req = Req(who);
    GDEFCORE_Routes * table = Table();
    GDEFCORE_Route_Match * match = NULL;
    GDEFCORE_Menu_Edit e;
    std::string version = a.version != NULL ? std::string(a.version) : Version();
    GDEFCORE_Result rc;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_match(table, req, "/nowhere", 8, &match));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    gdefcore_changeset_set_request(cs, req);
    memset(&e, 0, sizeof e);
    e.size = sizeof e;
    e.action = a.action;
    e.name = a.name.data();
    e.name_len = a.name.size();
    e.label = a.label.data();
    e.label_len = a.label.size();
    e.menu = a.menu.data();
    e.menu_len = a.menu.size();
    e.route = a.route.data();
    e.route_len = a.route.size();
    e.parent = a.parent.data();
    e.parent_len = a.parent.size();
    e.position = a.position;
    e.version = version.data();
    e.version_len = version.size();
    staged_ = false;
    rc = gdefcore_menu_stage_edit(cs, table, req, match, &e);
    Touched_ = gdefcore_changeset_touched_count(cs);
    if (rc == GDEFCORE_OK && Touched_ > 0) {
      std::string confirm = Confirm(cs);
      staged_ = true;
      rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    }
    size_t rn = 0;
    const char * r = gdefcore_changeset_refusal(cs, &rn);
    refusal_.assign(r == NULL ? "" : r, rn);
    gdefcore_changeset_destroy(cs);
    gdefcore_route_match_free(match);
    return rc;
  }

  GDEFCORE_Result Undo(const std::string & who) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Request * req = Req(who);
    GDEFCORE_Result rc;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    gdefcore_changeset_set_request(cs, req);
    rc = gdefcore_menu_stage_undo(cs, req);
    Touched_ = gdefcore_changeset_touched_count(cs);
    if (rc == GDEFCORE_OK) {
      std::string confirm = Confirm(cs);
      rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    }
    size_t rn = 0;
    const char * r = gdefcore_changeset_refusal(cs, &rn);
    refusal_.assign(r == NULL ? "" : r, rn);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Move(const char * name, const char * parent, size_t position,
      const std::string & who = std::string()) {
    Args a;
    a.action = GDEFCORE_MENU_ACT_MOVE;
    a.name = name;
    a.parent = parent;
    a.position = position;
    return Edit(who.empty() ? menuman_ : who, a);
  }

  GDEFCORE_Result Act(int action, const char * name, const char * label = "",
      const std::string & who = std::string()) {
    Args a;
    a.action = action;
    a.name = name;
    a.label = label;
    return Edit(who.empty() ? menuman_ : who, a);
  }

  /* A site entry in the main menu, added by the editor. */
  void Add(const char * name, const char * label, const char * parent = "",
      const char * route = "core.start") {
    Args a;
    a.action = GDEFCORE_MENU_ACT_ADD;
    a.name = name;
    a.label = label;
    a.parent = parent;
    a.route = route;
    ASSERT_EQ(GDEFCORE_OK, Edit(menuman_, a)) << refusal_;
  }

  /* How many entities of @p type there are, and their revisions. */
  std::string Counts(const char * type) {
    char ** ids = NULL;
    size_t n = 0;
    size_t revisions = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(catalog_, type, strlen(type), &ids, &n));
    for (size_t i = 0; i < n; i++) {
      size_t c = 0;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_revision_count(catalog_, ids[i],
                                 strlen(ids[i]), &c));
      revisions += c;
    }
    gdefcore_ids_free(catalog_, ids, n);
    return std::to_string(n) + " entities, " + std::to_string(revisions) +
           " revisions";
  }

  /* How many revisions every entity of @p type has, summed. */
  size_t Revs(const char * type) {
    char ** ids = NULL;
    size_t n = 0;
    size_t revisions = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(catalog_, type, strlen(type), &ids, &n));
    for (size_t i = 0; i < n; i++) {
      size_t c = 0;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_revision_count(catalog_, ids[i],
                                 strlen(ids[i]), &c));
      revisions += c;
    }
    gdefcore_ids_free(catalog_, ids, n);
    return revisions;
  }

  /* A site entry as the operator makes it (no request), with a weight of its
   * own, so that a test can have entries that tie. */
  void Raw(const char * name, const char * menu_name, int weight) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_menu_stage_entry(cs, name, strlen(name), menu_name,
            strlen(menu_name), name, strlen(name), "core.start", 10, "", 0, weight));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kEntry, strlen(kEntry)));
    gdefcore_changeset_destroy(cs);
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

const char kBase[] =
    "core.l-start -10\n"
    "wiki.l-index 0\n"
    "  wiki.l-recent 1\n"
    "wiki.l-this 5\n"
    "wiki.l-slug 6\n";

/* ---- the version ------------------------------------------------------------ */

TEST_F(MenuEdit, TheVersionIsSixteenLettersAndMovesWithWhatAnEditDependsOn) {
  EXPECT_EQ(kBase, Shape(menuman_));
  std::string v0 = Version();
  ASSERT_EQ(size_t(GDEFCORE_MENU_VERSION_LEN), v0.size());
  EXPECT_EQ(std::string::npos, v0.find_first_not_of("abcdefghijklmnop")) << v0;
  EXPECT_EQ(v0, Version()) << "CONTROL: asking twice is the same version";
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Latest"))
      << refusal_;
  std::string v1 = Version();
  EXPECT_NE(v0, v1) << "a label";
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_HIDE, "wiki.l-this")) << refusal_;
  std::string v2 = Version();
  EXPECT_NE(v1, v2) << "hiding";
  ASSERT_EQ(GDEFCORE_OK, Move("wiki.l-slug", "", 0)) << refusal_;
  EXPECT_NE(v2, Version()) << "an order";
  char text[GDEFCORE_MENU_VERSION_LEN + 1];
  EXPECT_NE(GDEFCORE_OK, gdefcore_menu_version(NULL, text, sizeof text));
}

/* ---- generated entries: an override by machine name ---------------------------- */

TEST_F(MenuEdit, RenamingAGeneratedEntryWritesOneOverrideByMachineNameAndNeverACopy) {
  EXPECT_EQ("<none>", StoredOverride("wiki.l-recent"));
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Latest"))
      << refusal_;
  EXPECT_EQ("name=wiki.l-recent;label=Latest;", StoredOverride("wiki.l-recent"))
      << "only the field the editor changed, keyed by the entry's machine name";
  EXPECT_EQ("Start\nWiki\n  Latest\n", Seen());
  EXPECT_EQ("1 entities, 1 revisions", Counts(kOverride));
  /* The second rename is the same override, one revision more. */
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Newest"))
      << refusal_;
  EXPECT_EQ("name=wiki.l-recent;label=Newest;", StoredOverride("wiki.l-recent"));
  EXPECT_EQ("1 entities, 2 revisions", Counts(kOverride));
  /* CONTROL: a site entry is edited as it is, and has no override. */
  Add("site.about", "About");
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "site.about", "About us"))
      << refusal_;
  EXPECT_EQ("<none>", StoredOverride("site.about"));
  EXPECT_NE(std::string::npos, Seen().find("About us"));
  EXPECT_EQ("1 entities, 2 revisions", Counts(kOverride));
  EXPECT_EQ("1 entities, 2 revisions", Counts(kEntry));
  /* Renaming to the label it has writes nothing. */
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "site.about", "About us"));
  EXPECT_EQ(0u, Touched_);
  EXPECT_EQ("1 entities, 2 revisions", Counts(kEntry));
}

TEST_F(MenuEdit, MovingAGeneratedEntryKeepsWhatItsOverrideHeldAndAddsOnlyWhatMoved) {
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Latest"))
      << refusal_;
  /* Out from under Wiki to the top level, after "This node". The room between
   * 5 and 6 is none, so the siblings are numbered again. */
  ASSERT_EQ(GDEFCORE_OK, Move("wiki.l-recent", "", 3)) << refusal_;
  EXPECT_EQ("core.l-start 10\n"
            "wiki.l-index 20\n"
            "wiki.l-this 30\n"
            "wiki.l-recent 40\n"
            "wiki.l-slug 50\n",
      Shape(menuman_));
  EXPECT_EQ("name=wiki.l-recent;label=Latest;weight=40;parent=-;",
      StoredOverride("wiki.l-recent"))
      << "the rename is kept, the move adds its weight and its parent";
  EXPECT_EQ("name=wiki.l-slug;weight=50;", StoredOverride("wiki.l-slug"))
      << "a renumbered sibling gets its weight and nothing else";
  EXPECT_EQ("Start\nWiki\nLatest\n", Seen())
      << "the viewer sees what is the viewer's to see, in the new order";
}

TEST_F(MenuEdit, AMoveWithRoomBetweenItsNeighboursWritesOnlyTheEntryThatMoved) {
  Add("site.a", "A");
  Add("site.b", "B");
  Add("site.c", "C");
  EXPECT_EQ(std::string(kBase) + "site.a 16\nsite.b 26\nsite.c 36\n",
      Shape(menuman_));
  size_t before = Revs(kEntry);
  ASSERT_EQ(GDEFCORE_OK, Move("site.c", "", 5)) << refusal_;
  EXPECT_EQ(1u, Touched_ - 1) << "the entry and the record of the edit";
  EXPECT_EQ(std::string(kBase) + "site.a 16\nsite.c 21\nsite.b 26\n",
      Shape(menuman_));
  EXPECT_EQ(before + 1, Revs(kEntry));
  EXPECT_EQ("<none>", StoredOverride("wiki.l-index")) << "no generated entry written";
  /* Moving it to where it is writes nothing. */
  ASSERT_EQ(GDEFCORE_OK, Move("site.c", "", 5));
  EXPECT_EQ(0u, Touched_);
}

TEST_F(MenuEdit, MovingBetweenTiedEntriesNumbersEverySiblingInOneChangesetOrNone) {
  Raw("site.a", "m2", 0);
  Raw("site.b", "m2", 0);
  Raw("site.c", "m2", 0);
  EXPECT_EQ("site.a 0\nsite.b 0\nsite.c 0\n", Shape(menuman_, "m2"));
  size_t before = Revs(kEntry);
  /* The wiki's author, who may edit overrides and not entries: the move is
   * refused when it is applied, and not one of the three is written. */
  Role("overriders");
  Grant("overriders", GDEFCORE_MENU_EDIT_OVERRIDE_LABEL);
  std::string overrider = Principal("overriders");
  Args a;
  a.action = GDEFCORE_MENU_ACT_MOVE;
  a.name = "site.c";
  a.menu = "m2";
  a.position = 1;
  EXPECT_NE(GDEFCORE_OK, Edit(overrider, a));
  EXPECT_TRUE(staged_) << "it got as far as the apply, which refused";
  EXPECT_EQ(before, Revs(kEntry)) << "nothing of the move was written";
  EXPECT_EQ("site.a 0\nsite.b 0\nsite.c 0\n", Shape(menuman_, "m2"));
  /* CONTROL: who may edit entries moves it, and all three are written. */
  ASSERT_EQ(GDEFCORE_OK, Edit(menuman_, a)) << refusal_;
  EXPECT_EQ("site.a 10\nsite.c 20\nsite.b 30\n", Shape(menuman_, "m2"));
  EXPECT_EQ(before + 3, Revs(kEntry));
}

TEST_F(MenuEdit, TheKeysMakeTheSameMovesADragMakes) {
  struct Pair {
    int action;
    const char * name;
    const char * parent;
    size_t position;
  };
  const Pair pairs[] = {
      {GDEFCORE_MENU_ACT_UP, "wiki.l-slug", "", 2},
      {GDEFCORE_MENU_ACT_DOWN, "wiki.l-index", "", 2},
      {GDEFCORE_MENU_ACT_INDENT, "wiki.l-this", "wiki.l-index", 1},
      {GDEFCORE_MENU_ACT_OUTDENT, "wiki.l-recent", "", 2},
  };
  std::string base = Shape(menuman_);
  for (const Pair & p : pairs) {
    SCOPED_TRACE(p.name);
    ASSERT_EQ(GDEFCORE_OK, Act(p.action, p.name)) << refusal_;
    std::string key = Shape(menuman_);
    EXPECT_NE(base, key) << "the key moved it";
    ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
    EXPECT_EQ(base, Shape(menuman_)) << "CONTROL: undone";
    ASSERT_EQ(GDEFCORE_OK, Move(p.name, p.parent, p.position)) << refusal_;
    EXPECT_EQ(key, Shape(menuman_)) << "the drag gives the same tree";
    ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
    EXPECT_EQ(base, Shape(menuman_));
  }
  /* An end of the list is refused, not wrapped. */
  EXPECT_NE(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_UP, "core.l-start"));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PLACE, refusal_);
  EXPECT_NE(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_DOWN, "wiki.l-slug"));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PLACE, refusal_);
  EXPECT_NE(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_INDENT, "core.l-start"))
      << "nothing before it to go under";
  EXPECT_NE(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_OUTDENT, "core.l-start"))
      << "already at the top";
  EXPECT_EQ(base, Shape(menuman_));
}

/* ---- what is refused ------------------------------------------------------------ */

TEST_F(MenuEdit, AMoveUnderItsOwnSubtreeOrUnderNothingIsRefusedAndNothingIsWritten) {
  Add("site.p", "P");
  Add("site.q", "Q", "site.p");
  Add("site.r", "R", "site.q");
  std::string before = Shape(menuman_);
  size_t revs = Revs(kEntry);
  EXPECT_NE(GDEFCORE_OK, Move("site.p", "site.r", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_CYCLE, refusal_) << "under its own grandchild";
  EXPECT_NE(GDEFCORE_OK, Move("site.p", "site.q", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_CYCLE, refusal_) << "under its own child";
  EXPECT_NE(GDEFCORE_OK, Move("site.p", "site.p", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_CYCLE, refusal_) << "under itself";
  EXPECT_NE(GDEFCORE_OK, Move("site.q", "site.nothing", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PARENT, refusal_) << "a parent that is not there";
  EXPECT_NE(GDEFCORE_OK, Move("site.q", "wiki.view", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PARENT, refusal_) << "a tab is no parent";
  EXPECT_NE(GDEFCORE_OK, Move("site.q", "", 99));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PLACE, refusal_) << "a position that is not there";
  EXPECT_NE(GDEFCORE_OK, Move("wiki.view", "", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_ENTRY, refusal_) << "a tab does not move";
  EXPECT_NE(GDEFCORE_OK, Move("site.nothing", "", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_ENTRY, refusal_) << "an entry that is not there";
  EXPECT_EQ(before, Shape(menuman_));
  EXPECT_EQ(revs, Revs(kEntry));
  EXPECT_EQ("0 entities, 0 revisions", Counts(kOverride));
  /* CONTROL: the move that is not a cycle is made. */
  ASSERT_EQ(GDEFCORE_OK, Move("site.r", "site.p", 0)) << refusal_;
  EXPECT_NE(before, Shape(menuman_));
}

TEST_F(MenuEdit, AnEntryTooDeepToBeShownIsRefused) {
  std::string parent;
  for (int i = 0; i < GDEFCORE_MENU_DEPTH_MAX; i++) {
    std::string name = "site.d" + std::to_string(i);
    Args a;
    a.action = GDEFCORE_MENU_ACT_ADD;
    a.name = name;
    a.label = name;
    a.parent = parent;
    ASSERT_EQ(GDEFCORE_OK, Edit(menuman_, a)) << i << ": " << refusal_;
    parent = name;
  }
  Args deeper;
  deeper.action = GDEFCORE_MENU_ACT_ADD;
  deeper.name = "site.deeper";
  deeper.label = "Deeper";
  deeper.parent = parent;
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, deeper));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PLACE, refusal_);
  /* Moving the whole chain one level down is as deep. */
  EXPECT_NE(GDEFCORE_OK, Move("site.d0", "wiki.l-index", 0));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PLACE, refusal_);
}

TEST_F(MenuEdit, AFormBasedOnAnOlderVersionOfTheMenuIsRefusedAndNothingIsWritten) {
  std::string old = Version();
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Latest"))
      << refusal_;
  size_t revs = Revs(kOverride);
  Args a;
  a.action = GDEFCORE_MENU_ACT_HIDE;
  a.name = "wiki.l-this";
  a.version = old.c_str();
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, a));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_STALE, refusal_);
  EXPECT_EQ(0u, Touched_) << "not even staged";
  EXPECT_EQ(revs, Revs(kOverride));
  a.version = "aaaaaaaaaaaaaaaa";
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, a)) << "a version that never was";
  a.version = "";
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, a)) << "no version at all";
  /* CONTROL: the version of now is accepted. */
  a.version = NULL;
  ASSERT_EQ(GDEFCORE_OK, Edit(menuman_, a)) << refusal_;
  EXPECT_NE(std::string::npos, Shape(menuman_).find("wiki.l-this 5 !"));
}

/* ---- hide, show, remove, add ------------------------------------------------------ */

TEST_F(MenuEdit, HidingHidesFromEveryOutputAndShowingBringsItBack) {
  EXPECT_EQ("Start\nWiki\n  Recent\n", Seen());
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_HIDE, "wiki.l-recent")) << refusal_;
  EXPECT_EQ("Start\nWiki\n", Seen());
  EXPECT_EQ("name=wiki.l-recent;hidden=1;", StoredOverride("wiki.l-recent"));
  EXPECT_NE(std::string::npos, Shape(menuman_).find("wiki.l-recent 1 !"))
      << "the editor still lists it";
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_HIDE, "wiki.l-recent"));
  EXPECT_EQ(0u, Touched_) << "hiding what is hidden writes nothing";
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_SHOW, "wiki.l-recent")) << refusal_;
  EXPECT_EQ("Start\nWiki\n  Recent\n", Seen());
  EXPECT_EQ("<none>", StoredOverride("wiki.l-recent"))
      << "an override left holding nothing is forgotten";
  /* A site entry: the entry itself says it is hidden. */
  Add("site.x", "X");
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_HIDE, "site.x")) << refusal_;
  EXPECT_EQ(std::string::npos, Seen().find("X"));
  EXPECT_NE(std::string::npos, Shape(menuman_).find("site.x 16 !"));
  EXPECT_EQ("<none>", StoredOverride("site.x")) << "a site entry has no override";
  /* Editing a hidden entry through the old call does not show it. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_menu_stage_entry(cs, "site.x", 6, "main", 4, "Ex", 2, "core.start",
            10, "", 0, 16));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kEntry, strlen(kEntry)));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_NE(std::string::npos, Shape(menuman_).find("site.x 16 !"));
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_SHOW, "site.x")) << refusal_;
  EXPECT_NE(std::string::npos, Seen().find("Ex"));
}

TEST_F(MenuEdit, OnlyASiteEntryIsRemovedAndAGeneratedOneIsHiddenInstead) {
  Add("site.x", "X");
  EXPECT_NE(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_REMOVE, "wiki.l-recent"));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_REMOVE, refusal_);
  EXPECT_NE(std::string::npos, Seen().find("Recent"));
  EXPECT_EQ("0 entities, 0 revisions", Counts(kOverride));
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_REMOVE, "site.x")) << refusal_;
  EXPECT_EQ(std::string::npos, Seen().find("X"));
  EXPECT_EQ(std::string(kBase), Shape(menuman_));
}

TEST_F(MenuEdit, AddAppendsAtTheEndOfItsSiblingsAndRefusesATakenName) {
  Add("site.a", "A");
  Add("site.b", "B", "wiki.l-index");
  EXPECT_EQ("core.l-start -10\n"
            "wiki.l-index 0\n"
            "  wiki.l-recent 1\n"
            "  site.b 11\n"
            "wiki.l-this 5\n"
            "wiki.l-slug 6\n"
            "site.a 16\n",
      Shape(menuman_));
  Args dup;
  dup.action = GDEFCORE_MENU_ACT_ADD;
  dup.name = "site.a";
  dup.label = "Again";
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, dup));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_ENTRY, refusal_);
  dup.name = "wiki.l-index";
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, dup)) << "not a site name";
  dup.name = "site.c";
  dup.parent = "site.nothing";
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, dup));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_PARENT, refusal_);
  dup.parent = "";
  dup.label = "";
  EXPECT_NE(GDEFCORE_OK, Edit(menuman_, dup)) << "a label is required";
  dup.label = "<b>C</b>";
  dup.route = "core.start";
  ASSERT_EQ(GDEFCORE_OK, Edit(menuman_, dup)) << refusal_;
  EXPECT_NE(std::string::npos, Seen().find("<b>C</b>"))
      << "the label is text, kept as typed (the pages escape it)";
}

/* ---- who may ------------------------------------------------------------------ */

TEST_F(MenuEdit, WhoMayNotEditMenusIsRefusedBeforeAnythingIsStagedAndAfterwardsNothingIsWritten) {
  std::string before = Shape(menuman_);
  EXPECT_NE(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Hacked",
                             reader_));
  EXPECT_EQ("That edit is not allowed.", refusal_);
  EXPECT_EQ(0u, Touched_);
  EXPECT_EQ("0 entities, 0 revisions", Counts(kOverride));
  EXPECT_EQ(before, Shape(menuman_));
  /* CONTROL: the same call as who may. */
  EXPECT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Fine"));
  EXPECT_EQ("name=wiki.l-recent;label=Fine;", StoredOverride("wiki.l-recent"));
}

/* ---- undo --------------------------------------------------------------------- */

TEST_F(MenuEdit, UndoPutsEveryEntryTheLastEditWroteBackInOneChangeset) {
  Add("site.a", "A");
  std::string base = Shape(menuman_);
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Latest"))
      << refusal_;
  /* A move that numbers five entries again, two of them with an override of
   * their own already, and that makes four overrides. */
  ASSERT_EQ(GDEFCORE_OK, Move("wiki.l-recent", "", 3)) << refusal_;
  EXPECT_NE(base, Shape(menuman_));
  EXPECT_GT(Revs(kChange), 0u) << "the edit left the record undo reads";
  ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
  EXPECT_EQ(base, Shape(menuman_)) << "the earlier tree, weights and all";
  EXPECT_EQ("name=wiki.l-recent;label=Latest;", StoredOverride("wiki.l-recent"))
      << "the rename before it stands";
  EXPECT_EQ("<none>", StoredOverride("wiki.l-slug"))
      << "an override the edit made is cleared";
  /* It is a revision, and it is once. */
  EXPECT_NE(GDEFCORE_OK, Undo(menuman_));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_NOTHING, refusal_);
  /* Undo the rename: back to the module's label. */
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Newest"));
  ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
  EXPECT_EQ("name=wiki.l-recent;label=Latest;", StoredOverride("wiki.l-recent"));
  /* A removal is undone: the entry is back. */
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_REMOVE, "site.a")) << refusal_;
  EXPECT_EQ(std::string::npos, Shape(menuman_).find("site.a"));
  ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
  EXPECT_EQ(base, Shape(menuman_));
  EXPECT_NE(std::string::npos, Seen().find("A\n"));
  /* An add is undone: the entry it made is cleared. */
  Add("site.z", "Z");
  EXPECT_NE(std::string::npos, Shape(menuman_).find("site.z"));
  ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
  EXPECT_EQ(std::string::npos, Shape(menuman_).find("site.z"));
}

TEST_F(MenuEdit, AWriteStagedByHandIsUndoneWhenItsChangesetIsRecorded) {
  auto by_hand = [&](const char * name, bool record) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_menu_stage_entry(cs, name, strlen(name), "main", 4, "By hand", 7,
            "core.start", 10, "", 0, 3));
    if (record) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_menu_stage_record(cs));
    }
    std::string confirm = Confirm(cs);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, confirm.data(), confirm.size()));
    gdefcore_changeset_destroy(cs);
  };
  by_hand("site.hand", true);
  EXPECT_NE(std::string::npos, Shape(menuman_).find("site.hand"));
  ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
  EXPECT_EQ(std::string::npos, Shape(menuman_).find("site.hand"));
  /* A write that was not recorded leaves nothing to undo. */
  by_hand("site.unrecorded", false);
  EXPECT_NE(GDEFCORE_OK, Undo(menuman_));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_NOTHING, refusal_);
  EXPECT_NE(std::string::npos, Shape(menuman_).find("site.unrecorded"));
  /* A changeset that writes no entry records nothing. */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_menu_stage_record(cs));
  EXPECT_EQ(0u, gdefcore_changeset_touched_count(cs));
  gdefcore_changeset_destroy(cs);
}

TEST_F(MenuEdit, UndoIsRefusedWhenAnythingTheEditWroteHasBeenWrittenSince) {
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Latest"))
      << refusal_;
  /* Someone else writes the same override afterwards, by hand. */
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Menu_Override o;
    memset(&o, 0, sizeof o);
    o.size = sizeof o;
    o.hidden = -1;
    o.label = "Theirs";
    o.label_len = 6;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_menu_stage_override(cs, "wiki.l-recent", 13, &o));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kOverride, strlen(kOverride)));
    gdefcore_changeset_destroy(cs);
  }
  size_t revs = Revs(kOverride);
  EXPECT_NE(GDEFCORE_OK, Undo(menuman_));
  EXPECT_EQ(GDEFCORE_MENU_REFUSED_UNDO, refusal_);
  EXPECT_EQ(revs, Revs(kOverride)) << "nothing was written";
  EXPECT_EQ("name=wiki.l-recent;label=Theirs;", StoredOverride("wiki.l-recent"));
  /* CONTROL: with no later write it is undone (the next edit's). */
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Mine"));
  ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
  EXPECT_EQ("name=wiki.l-recent;label=Theirs;", StoredOverride("wiki.l-recent"));
}

TEST_F(MenuEdit, UndoIsDecidedAgainAtApplyForWhoAsksIt) {
  ASSERT_EQ(GDEFCORE_OK, Act(GDEFCORE_MENU_ACT_RENAME, "wiki.l-recent", "Latest"))
      << refusal_;
  size_t revs = Revs(kOverride);
  EXPECT_NE(GDEFCORE_OK, Undo(reader_));
  EXPECT_EQ("That edit is not allowed.", refusal_) << "told nothing of the last edit";
  EXPECT_EQ(0u, Touched_) << "not even staged";
  EXPECT_EQ(revs, Revs(kOverride));
  /* Who may edit entries and not overrides is let as far as the staging, and is
   * refused at the apply of the override the edit wrote. */
  Role("entrymen");
  Grant("entrymen", GDEFCORE_MENU_EDIT_ENTRY_LABEL);
  EXPECT_NE(GDEFCORE_OK, Undo(Principal("entrymen")));
  EXPECT_EQ(revs, Revs(kOverride));
  EXPECT_EQ("name=wiki.l-recent;label=Latest;", StoredOverride("wiki.l-recent"));
  ASSERT_EQ(GDEFCORE_OK, Undo(menuman_)) << refusal_;
  EXPECT_EQ("<none>", StoredOverride("wiki.l-recent"));
}

/* ---- the struct --------------------------------------------------------------- */

TEST_F(MenuEdit, TheEditStructIsAcceptedAtOnlyItsOwnSize) {
  const std::map<std::string, size_structs::Probe> probes = {
      GDEFCORE_SIZE_PROBE(GDEFCORE_Menu_Edit, {
        GDEFCORE_Changeset * cs = NULL;
        GDEFCORE_Request * req = Req(menuman_);
        GDEFCORE_Routes * table = Table();
        std::string version = Version();
        GDEFCORE_Menu_Edit e;
        memset(&e, 0, sizeof e);
        e.size = size;
        e.action = GDEFCORE_MENU_ACT_HIDE;
        e.name = "wiki.l-recent";
        e.name_len = 13;
        e.version = version.data();
        e.version_len = version.size();
        EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
        bool ok = gdefcore_menu_stage_edit(cs, table, req, NULL, &e) == GDEFCORE_OK;
        gdefcore_changeset_destroy(cs);
        return ok;
      }),
  };
  size_structs::Run("tests/test_menuedit.cpp", probes);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
