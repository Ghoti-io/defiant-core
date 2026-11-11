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
 * Changing a layout one placement at a time (layoutedit.h): the layout as an
 * editor draws it, each action as one changeset and one revision, a stale edit
 * refused with the fixed sentence, and the apply's permission and vet standing
 * behind every one.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <gtest/gtest.h>

#include <chrono>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "grants_fixture.h"
#include "size_structs.h"

using namespace gfx;

namespace {
const char kDisplay[] = "core.display";
}  // namespace

class LayoutEdit : public GrantsFixture {
 protected:
  std::string refusal_;
  std::string layouter_, nobody_;
  std::string version_;   /* what the last edit built names, kept alive for it */

  void SetUp() override {
    GrantsFixture::SetUp();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    Role("layouters");
    Grant("layouters", GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL);
    layouter_ = Principal("layouters");
    nobody_ = Principal();
  }

  void Remember(GDEFCORE_Changeset * cs) {
    size_t n = 0;
    const char * why = gdefcore_changeset_refusal(cs, &n);
    refusal_ = why == NULL ? "" : std::string(why, n);
  }

  /* "region widget [target]" lines of the layout as published, newline-joined. */
  std::string Lines(const char * name, bool unplaced = false) {
    GDEFCORE_Layout_View v;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    if (gdefcore_layout_view(catalog_, name, strlen(name), &v) != GDEFCORE_OK) {
      return "<none>";
    }
    std::string out;
    const GDEFCORE_Placement * list = unplaced ? v.unplaced : v.placed;
    size_t n = unplaced ? v.nunplaced : v.nplaced;
    for (size_t i = 0; i < n; i++) {
      char line[1024];
      size_t len = gdefcore_placement_format(&list[i], unplaced ? 0 : 1, line, sizeof line);
      out += std::string(line, len) + "\n";
    }
    gdefcore_layout_view_free(&v);
    return out;
  }

  std::string Version(const char * name) {
    GDEFCORE_Layout_View v;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_layout_view(catalog_, name, strlen(name), &v));
    std::string out = v.version;
    gdefcore_layout_view_free(&v);
    return out;
  }

  static GDEFCORE_Placement Placement(const char * widget, const char * target = "") {
    GDEFCORE_Placement p;
    memset(&p, 0, sizeof p);
    p.size = sizeof p;
    snprintf(p.widget, sizeof p.widget, "%s", widget);
    snprintf(p.target, sizeof p.target, "%s", target);
    return p;
  }

  GDEFCORE_Layout_Edit Edit(int action, const char * layout, const std::string & version) {
    GDEFCORE_Layout_Edit e;
    memset(&e, 0, sizeof e);
    e.size = sizeof e;
    e.action = action;
    e.layout = layout;
    e.layout_len = strlen(layout);
    version_ = version;
    e.version = version_.c_str();
    e.version_len = version_.size();
    e.placement = Placement("");
    return e;
  }

  /* Stage and apply @p e. The result of the stage, or of the apply; with
   * @p touched the number of entities the stage wrote. */
  GDEFCORE_Result Do(const GDEFCORE_Layout_Edit & e, GDEFCORE_Request * request = NULL,
      size_t * touched = NULL) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_layout_stage_edit(cs, &e);
    if (touched != NULL) {
      *touched = gdefcore_changeset_touched_count(cs);
    }
    if (rc == GDEFCORE_OK && gdefcore_changeset_touched_count(cs) > 0) {
      rc = gdefcore_changeset_apply(cs, kDisplay, strlen(kDisplay));
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Place(const char * layout, const char * widget, const char * region,
      size_t position, const GDEFCORE_Placement * settings = NULL) {
    GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_PLACE, layout, Version(layout));
    e.placement = settings != NULL ? *settings : Placement(widget);
    snprintf(e.placement.widget, sizeof e.placement.widget, "%s", widget);
    e.region = region;
    e.region_len = strlen(region);
    e.position = position;
    return Do(e);
  }


  /* ---- structure edits: the page template "layout" ---------------------------------- */

  GDEFCORE_Structure_Edit SEdit(int act, const std::string & version) {
    GDEFCORE_Structure_Edit e;
    memset(&e, 0, sizeof e);
    e.size = sizeof e;
    e.act = act;
    version_ = version;
    e.version = version_.c_str();
    e.version_len = version_.size();
    return e;
  }

  std::string SVersion(const char * name = "layout") {
    GDEFCORE_Structure_View v;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_structure_view(catalog_, name, strlen(name), &v));
    std::string out = v.version;
    gdefcore_structure_view_free(&v);
    return out;
  }

  std::string Document(const char * name = "layout") {
    GDEFCORE_Structure_View v;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    if (gdefcore_structure_view(catalog_, name, strlen(name), &v) != GDEFCORE_OK) {
      return "<none>";
    }
    std::string out(v.document, v.document_len);
    gdefcore_structure_view_free(&v);
    return out;
  }

  /* Stage and apply a structure edit; the stage's result, or the apply's. */
  GDEFCORE_Result SDo(const GDEFCORE_Structure_Edit & e, GDEFCORE_Request * request = NULL,
      const char * name = "layout") {
    GDEFCORE_Changeset * cs = NULL;
    char * moved = NULL;
    size_t moved_len = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_structure_stage_edit(cs, name, strlen(name), &e, &moved,
        &moved_len);
    if (rc == GDEFCORE_OK) {
      /* The confirmation is the touched machine names, so it is read off the stage. */
      std::set<std::string> types;
      for (size_t i = 0; i < gdefcore_changeset_touched_count(cs); i++) {
        const char * id;
        size_t id_len;
        const char * type;
        size_t type_len;
        int op;
        EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_touched_at(cs, i, &id, &id_len, &type, &type_len, &op));
        types.insert(std::string(type, type_len));
      }
      std::string confirm;
      for (const std::string & t : types) {
        confirm += (confirm.empty() ? "" : "\n") + t;
      }
      rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    }
    moved_ = moved == NULL ? "" : std::string(moved, moved_len);
    free(moved);
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result SStart(const char * point, const char * name = "layout") {
    GDEFCORE_Structure_Edit e = SEdit(GDEFCORE_STRUCTURE_ACT_START, SVersion(name));
    e.region = point;
    e.region_len = strlen(point);
    return SDo(e, NULL, name);
  }

  std::string moved_;

  size_t Revisions(const char * name) {
    char ** ids = NULL;
    size_t n = 0;
    size_t out = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, kDisplay, strlen(kDisplay), &ids, &n));
    for (size_t i = 0; i < n; i++) {
      char ** t = NULL;
      size_t * l = NULL;
      size_t c = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], strlen(ids[i]),
              "en", 2, "name", 4, &t, &l, &c) == GDEFCORE_OK && c > 0 &&
          std::string(t[0], l[0]) == name) {
        EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_revision_count(catalog_, ids[i], strlen(ids[i]), &out));
      }
      if (c > 0) {
        gdefcore_values_free(catalog_, t, l, c);
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    return out;
  }
};

TEST_F(LayoutEdit, ALayoutIsReadAsItsRegionsItsPlacementsAndItsNotPlacedList) {
  GDEFCORE_Layout_View v;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_layout_view(catalog_, "post", 4, &v));
  EXPECT_STREQ("layout", v.template_name);
  ASSERT_EQ(2u, v.nregions);
  EXPECT_STREQ("main", v.regions[0]);
  EXPECT_STREQ("side", v.regions[1]);
  ASSERT_EQ(1u, v.nplaced);
  EXPECT_STREQ("main", v.placed[0].region);
  EXPECT_STREQ("content", v.placed[0].widget);
  EXPECT_EQ(0u, v.nunplaced);
  EXPECT_EQ((size_t)GDEFCORE_LAYOUT_VERSION_LEN, strlen(v.version));
  const std::string post_version = v.version;
  gdefcore_layout_view_free(&v);
  /* Each layout has a version of its own, and the same layout the same one. */
  EXPECT_NE(post_version, Version("front"));
  EXPECT_EQ(post_version, Version("post"));
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_view(catalog_, "no-such", 7, &v));
  EXPECT_EQ(nullptr, v.template_name);
  v.size = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_view(catalog_, "post", 4, &v));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_view(NULL, "post", 4, &v));
}

TEST_F(LayoutEdit, APlacementIsParsedAndWrittenBackAsItself) {
  const struct {
    const char * line;
    int region;
  } good[] = {
      {"main content", 1}, {"side recent mine", 1},
      {"side menu ~title=Site%20menu ~path=/x/:id ~type=site.post ~role=a ~role=b", 1},
      {"menu", 0}, {"menu primary ~title=T", 0}, {"menu ~role=editor", 0}};
  for (const auto & c : good) {
    GDEFCORE_Placement p;
    char line[1024];
    ASSERT_EQ(1, gdefcore_placement_parse(c.line, strlen(c.line), c.region, &p)) << c.line;
    ASSERT_EQ(strlen(c.line), gdefcore_placement_format(&p, c.region, line, sizeof line))
        << c.line;
    EXPECT_EQ(std::string(c.line), std::string(line)) << "the canonical spelling of itself";
  }
  GDEFCORE_Placement p;
  ASSERT_EQ(1, gdefcore_placement_parse("side menu ~title=Site%20menu", strlen("side menu ~title=Site%20menu"), 1, &p));
  EXPECT_STREQ("side", p.region);
  EXPECT_STREQ("menu", p.widget);
  EXPECT_STREQ("Site menu", p.title);
  const char * bad[] = {"", "side", "side menu extra extra", "side menu ~foo=1", "side menu ~title="};
  for (const char * line : bad) {
    EXPECT_EQ(0, gdefcore_placement_parse(line, strlen(line), 1, &p)) << line;
  }
  EXPECT_EQ(0, gdefcore_placement_parse(NULL, 0, 1, &p));
  EXPECT_EQ(0, gdefcore_placement_parse("a b", 3, 1, NULL));
  /* A title that is a space, a percent sign and a tilde goes through the encoding. */
  GDEFCORE_Placement q = Placement("menu");
  snprintf(q.region, sizeof q.region, "side");
  snprintf(q.title, sizeof q.title, "A 100%% ~odd~ caf\xC3\xA9");
  char line[1024];
  size_t n = gdefcore_placement_format(&q, 1, line, sizeof line);
  ASSERT_GT(n, 0u);
  GDEFCORE_Placement back;
  ASSERT_EQ(1, gdefcore_placement_parse(line, n, 1, &back));
  EXPECT_STREQ(q.title, back.title);
  /* A buffer too small, a placement with no widget, and one with no region. */
  EXPECT_EQ(0u, gdefcore_placement_format(&q, 1, line, 5));
  GDEFCORE_Placement empty = Placement("");
  EXPECT_EQ(0u, gdefcore_placement_format(&empty, 0, line, sizeof line));
  GDEFCORE_Placement no_region = Placement("menu");
  EXPECT_EQ(0u, gdefcore_placement_format(&no_region, 1, line, sizeof line));
  EXPECT_GT(gdefcore_placement_format(&no_region, 0, line, sizeof line), 0u);
}

TEST_F(LayoutEdit, PlacingAWidgetIsOneChangesetAtThePositionAsked) {
  const size_t before = Revisions("post");
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "main", 0)) << refusal_;
  EXPECT_EQ("main recent\nmain content\n", Lines("post"));
  EXPECT_EQ(before + 1, Revisions("post")) << "one edit, one revision";
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "main", 1)) << refusal_;
  EXPECT_EQ("main recent\nmain menu\nmain content\n", Lines("post"));
  /* A position past the last is the last; another region starts its own list. */
  ASSERT_EQ(GDEFCORE_OK, Place("post", "title", "main", 99)) << refusal_;
  EXPECT_EQ("main recent\nmain menu\nmain content\nmain title\n", Lines("post"));
  ASSERT_EQ(GDEFCORE_OK, Place("post", "tabs", "side", 0)) << refusal_;
  EXPECT_EQ("main recent\nmain menu\nmain content\nmain title\nside tabs\n", Lines("post"));
  /* With settings. */
  GDEFCORE_Placement settings = Placement("menu", "primary");
  snprintf(settings.title, sizeof settings.title, "Main menu");
  snprintf(settings.roles[0], sizeof settings.roles[0], "editor");
  settings.nroles = 1;
  snprintf(settings.path, sizeof settings.path, "/admin/**");
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "side", 0, &settings)) << refusal_;
  EXPECT_EQ("side menu primary ~title=Main%20menu ~path=/admin/** ~role=editor\n",
      Lines("post").substr(Lines("post").find("side menu")).substr(0, 66));
  EXPECT_EQ(GDEFCORE_OK, [&] {
    GDEFCORE_Layout_View v;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    GDEFCORE_Result rc = gdefcore_layout_view(catalog_, "post", 4, &v);
    EXPECT_EQ(6u, v.nplaced);
    gdefcore_layout_view_free(&v);
    return rc;
  }());
}

TEST_F(LayoutEdit, APlacementThatBreaksARuleIsRefusedWithItsSentenceAndNothingIsWritten) {
  const std::string before = Lines("post");
  const size_t revisions = Revisions("post");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "recent", "nowhere", 0));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_REGION, refusal_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "recent", "", 0));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_REGION, refusal_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "no.such.widget", "main", 0));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_WIDGET, refusal_);
  GDEFCORE_Placement bad = Placement("menu");
  snprintf(bad.title, sizeof bad.title, "a\x07");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "menu", "main", 0, &bad));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_PART, refusal_);
  GDEFCORE_Placement bad_path = Placement("menu");
  snprintf(bad_path.path, sizeof bad_path.path, "admin");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "menu", "main", 0, &bad_path));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_PART, refusal_);
  GDEFCORE_Placement bad_role = Placement("menu");
  snprintf(bad_role.roles[0], sizeof bad_role.roles[0], "Bad Role");
  bad_role.nroles = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "menu", "main", 0, &bad_role));
  GDEFCORE_Placement spaced = Placement("menu", "two words");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "menu", "main", 0, &spaced));
  EXPECT_EQ(before, Lines("post"));
  EXPECT_EQ(revisions, Revisions("post"));
  /* A layout holds 32. */
  for (int i = 0; i < 31; i++) {
    ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "side", 0)) << i << refusal_;
  }
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Place("post", "menu", "side", 0));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_FULL, refusal_);
  /* An edit of a size the build does not have, and of no action. */
  GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_PLACE, "post", Version("post"));
  e.size = 1;
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_stage_edit(cs, &e));
  e.size = sizeof e;
  e.action = 99;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_stage_edit(cs, &e));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_stage_edit(NULL, &e));
  gdefcore_changeset_destroy(cs);
}

TEST_F(LayoutEdit, AMoveGoesToARegionAndAPositionAndAMoveToWhereItIsStagesNothing) {
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "side", 0)) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "side", 1)) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Place("post", "title", "main", 1)) << refusal_;
  EXPECT_EQ("main content\nmain title\nside recent\nside menu\n", Lines("post"));
  /* Across regions: the first of side's goes to main, last. */
  GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_MOVE, "post", Version("post"));
  e.index = 2;
  e.region = "main";
  e.region_len = 4;
  e.position = 99;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main content\nmain title\nmain recent\nside menu\n", Lines("post"));
  /* Within a region: the last of main goes first. */
  e = Edit(GDEFCORE_LAYOUT_ACT_MOVE, "post", Version("post"));
  e.index = 2;
  e.region = "main";
  e.region_len = 4;
  e.position = 0;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main recent\nmain content\nmain title\nside menu\n", Lines("post"));
  /* To a region that is empty. */
  e = Edit(GDEFCORE_LAYOUT_ACT_MOVE, "post", Version("post"));
  e.index = 0;
  e.region = "side";
  e.region_len = 4;
  e.position = 0;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main content\nmain title\nside recent\nside menu\n", Lines("post"));
  /* Where it already is: success, and nothing staged. */
  const size_t revisions = Revisions("post");
  e = Edit(GDEFCORE_LAYOUT_ACT_MOVE, "post", Version("post"));
  e.index = 2;
  e.region = "side";
  e.region_len = 4;
  e.position = 0;
  size_t touched = 99;
  EXPECT_EQ(GDEFCORE_OK, Do(e, NULL, &touched));
  EXPECT_EQ(0u, touched);
  EXPECT_EQ(revisions, Revisions("post"));
  /* A region the template does not name, a placement that is not there. */
  e.region = "nowhere";
  e.region_len = 7;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_REGION, refusal_);
  e.region = "side";
  e.region_len = 4;
  e.index = 9;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_THERE, refusal_);
}

TEST_F(LayoutEdit, ConfiguringReplacesTheSettingsAndKeepsTheRegionAndTheWidget) {
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "side", 0)) << refusal_;
  GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_CONFIGURE, "post", Version("post"));
  e.index = 1;
  e.placement = Placement("ignored", "primary");
  snprintf(e.placement.title, sizeof e.placement.title, "Menu");
  snprintf(e.placement.type, sizeof e.placement.type, "site.post");
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main content\nside menu primary ~title=Menu ~type=site.post\n", Lines("post"));
  /* Settings are replaced whole: what is not given is taken away. */
  e = Edit(GDEFCORE_LAYOUT_ACT_CONFIGURE, "post", Version("post"));
  e.index = 1;
  e.placement = Placement("ignored");
  snprintf(e.placement.title, sizeof e.placement.title, "Again");
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main content\nside menu ~title=Again\n", Lines("post"));
  /* A setting that is not one is refused; a placement that is not there. */
  e = Edit(GDEFCORE_LAYOUT_ACT_CONFIGURE, "post", Version("post"));
  e.index = 1;
  e.placement = Placement("x");
  snprintf(e.placement.path, sizeof e.placement.path, "nope");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_PART, refusal_);
  e.index = 7;
  e.placement = Placement("x");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_THERE, refusal_);
  EXPECT_EQ("main content\nside menu ~title=Again\n", Lines("post"));
}

TEST_F(LayoutEdit, APlacementIsRemovedOrSetAsideAndAPlacedEntryComesBack) {
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "side", 0)) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "side", 1)) << refusal_;
  /* Set aside: it keeps its settings and loses its region. */
  GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_UNPLACE, "post", Version("post"));
  e.index = 1;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main content\nside recent\n", Lines("post"));
  EXPECT_EQ("menu\n", Lines("post", true));
  /* Placed again from the list, where the editor says. */
  e = Edit(GDEFCORE_LAYOUT_ACT_PLACE_UNPLACED, "post", Version("post"));
  e.index = 0;
  e.region = "main";
  e.region_len = 4;
  e.position = 0;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main menu\nmain content\nside recent\n", Lines("post"));
  EXPECT_EQ("", Lines("post", true));
  /* Removed: gone, from either list. */
  e = Edit(GDEFCORE_LAYOUT_ACT_REMOVE, "post", Version("post"));
  e.index = 2;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("main menu\nmain content\n", Lines("post"));
  e = Edit(GDEFCORE_LAYOUT_ACT_UNPLACE, "post", Version("post"));
  e.index = 0;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  e = Edit(GDEFCORE_LAYOUT_ACT_REMOVE, "post", Version("post"));
  e.index = 0;
  e.from_unplaced = 1;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("", Lines("post", true));
  EXPECT_EQ("main content\n", Lines("post"));
  /* What is not there. */
  e = Edit(GDEFCORE_LAYOUT_ACT_REMOVE, "post", Version("post"));
  e.index = 5;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_THERE, refusal_);
  e.from_unplaced = 1;
  e.index = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  e = Edit(GDEFCORE_LAYOUT_ACT_PLACE_UNPLACED, "post", Version("post"));
  e.index = 0;
  e.region = "main";
  e.region_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_THERE, refusal_);
}

TEST_F(LayoutEdit, ANotPlacedEntryWhoseWidgetIsGoneIsKeptAndCannotBePlaced) {
  /* The widget of a module that is disabled: written straight to the list. */
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  {
    char ** ids = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, kDisplay, strlen(kDisplay), &ids, &n));
    id[0] = '\0';
    for (size_t i = 0; i < n && id[0] == '\0'; i++) {
      char ** t = NULL;
      size_t * l = NULL;
      size_t c = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], strlen(ids[i]),
              "en", 2, "name", 4, &t, &l, &c) == GDEFCORE_OK && c > 0 &&
          std::string(t[0], l[0]) == "post") {
        snprintf(id, sizeof id, "%s", ids[i]);
      }
      if (c > 0) {
        gdefcore_values_free(catalog_, t, l, c);
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
  }
  ASSERT_NE('\0', id[0]);
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value value;
  const char * slot = "ghost.widget ~title=Left%20behind";
  size_t len = strlen(slot);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "unplaced";
  value.field_len = 8;
  value.texts = &slot;
  value.text_lens = &len;
  value.count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kDisplay, strlen(kDisplay)));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("ghost.widget ~title=Left%20behind\n", Lines("post", true));
  GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_PLACE_UNPLACED, "post", Version("post"));
  e.index = 0;
  e.region = "main";
  e.region_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_WIDGET, refusal_) << "it is not available now";
  /* It can be configured, and it can be removed. */
  e = Edit(GDEFCORE_LAYOUT_ACT_CONFIGURE, "post", Version("post"));
  e.index = 0;
  e.from_unplaced = 1;
  e.placement = Placement("x");
  snprintf(e.placement.title, sizeof e.placement.title, "Still here");
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("ghost.widget ~title=Still%20here\n", Lines("post", true));
  e = Edit(GDEFCORE_LAYOUT_ACT_REMOVE, "post", Version("post"));
  e.index = 0;
  e.from_unplaced = 1;
  ASSERT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  EXPECT_EQ("", Lines("post", true));
}

TEST_F(LayoutEdit, AnEditOfALayoutThatChangedSinceItWasDrawnIsRefusedAndWritesNothing) {
  const std::string drawn = Version("post");
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "side", 0)) << refusal_;
  const std::string after = Lines("post");
  const size_t revisions = Revisions("post");
  EXPECT_NE(drawn, Version("post"));
  GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_PLACE, "post", drawn);
  e.placement = Placement("menu");
  e.region = "main";
  e.region_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
  EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_STALE, refusal_);
  EXPECT_EQ(after, Lines("post"));
  EXPECT_EQ(revisions, Revisions("post"));
  /* CONTROL: the same edit with the version of now. */
  e = Edit(GDEFCORE_LAYOUT_ACT_PLACE, "post", Version("post"));
  e.placement = Placement("menu");
  e.region = "main";
  e.region_len = 4;
  EXPECT_EQ(GDEFCORE_OK, Do(e)) << refusal_;
  /* A version that is not one, or none. */
  for (const char * bad : {"", "short", "00000000000000000000000000000000"}) {
    e = Edit(GDEFCORE_LAYOUT_ACT_REMOVE, "post", bad);
    e.index = 0;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e)) << bad;
    EXPECT_EQ(GDEFCORE_LAYOUT_REFUSED_STALE, refusal_) << bad;
  }
}

TEST_F(LayoutEdit, EachEditIsUndoneWholeByRevertingTheLayout) {
  const std::string before = Lines("post");
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "side", 0)) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "main", 0)) << refusal_;
  EXPECT_EQ("main menu\nmain content\nside recent\n", Lines("post"));
  char ** ids = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, kDisplay, strlen(kDisplay), &ids, &n));
  std::string id;
  for (size_t i = 0; i < n && id.empty(); i++) {
    char ** t = NULL;
    size_t * l = NULL;
    size_t c = 0;
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], strlen(ids[i]), "en",
            2, "name", 4, &t, &l, &c) == GDEFCORE_OK && c > 0 && std::string(t[0], l[0]) == "post") {
      id = ids[i];
    }
    if (c > 0) {
      gdefcore_values_free(catalog_, t, l, c);
    }
  }
  gdefcore_ids_free(catalog_, ids, n);
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_revert(catalog_, id.data(), id.size(), NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kDisplay, strlen(kDisplay)));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("main content\nside recent\n", Lines("post"));
  /* The revert is itself the latest revision, so reverting again is the redo. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_revert(catalog_, id.data(), id.size(), NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kDisplay, strlen(kDisplay)));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("main menu\nmain content\nside recent\n", Lines("post"));
  EXPECT_NE(before, Lines("post"));
}

TEST_F(LayoutEdit, TheApplyStillAsksThePermissionAndChecksTheLayoutAsItIsLeft) {
  GDEFCORE_Request * layouter = Req(layouter_);
  GDEFCORE_Request * nobody = Req(nobody_);
  GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_PLACE, "post", Version("post"));
  e.placement = Placement("recent");
  e.region = "side";
  e.region_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e, nobody));
  EXPECT_NE(std::string::npos, refusal_.find("That edit is not allowed.")) << refusal_;
  EXPECT_EQ("main content\n", Lines("post"));
  EXPECT_EQ(GDEFCORE_OK, Do(e, layouter)) << refusal_;
  EXPECT_EQ("main content\nside recent\n", Lines("post"));
  /* A layout that is not there is no layout. */
  e = Edit(GDEFCORE_LAYOUT_ACT_PLACE, "no-such", Version("post"));
  e.placement = Placement("recent");
  e.region = "side";
  e.region_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Do(e));
}


TEST_F(LayoutEdit, EveryStartingPointIsAValidStructureAndTheTableIsTheSameEveryTime) {
  std::set<std::string> names;
  size_t count = 0;
  const char * name;
  const char * label;
  const char * document;
  while (gdefcore_structure_starting_point(count, &name, &label, &document)) {
    char why[200];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_structure_check(document, strlen(document), NULL, NULL, why,
                               sizeof why)) << name << ": " << why;
    EXPECT_TRUE(names.insert(name).second) << name << " twice";
    EXPECT_GT(strlen(label), 0u);
    const char * again;
    ASSERT_EQ(1, gdefcore_structure_starting_point(count, NULL, NULL, &again));
    EXPECT_STREQ(document, again);
    count++;
  }
  EXPECT_EQ(7u, count);
  EXPECT_EQ(0, gdefcore_structure_starting_point(count, &name, &label, &document));
}

TEST_F(LayoutEdit, AStructureIsReadAsRowsAndEveryEditIsOneChangesetOneRevisionOnTheTemplate) {
  GDEFCORE_Structure_View v;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_structure_view(catalog_, "layout", 6, &v));
  EXPECT_EQ(GDEFCORE_STRUCTURE_KIND_NONE, v.kind);
  gdefcore_structure_view_free(&v);
  ASSERT_EQ(GDEFCORE_OK, SStart("two-columns-right")) << refusal_;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_structure_view(catalog_, "layout", 6, &v));
  EXPECT_EQ(GDEFCORE_STRUCTURE_KIND_DOCUMENT, v.kind);
  ASSERT_EQ(1u, v.nrows);
  EXPECT_EQ(GDEFCORE_STRUCTURE_STACK, v.rows[0].behavior);
  EXPECT_EQ(GDEFCORE_STRUCTURE_MEDIUM, v.rows[0].breakpoint);
  ASSERT_EQ(2u, v.rows[0].ncells);
  EXPECT_STREQ("main", v.rows[0].cells[0].region);
  EXPECT_EQ(8, v.rows[0].cells[0].width);
  gdefcore_structure_view_free(&v);
  /* A row, a cell that does not fit, one that does, a move and a stacked place. */
  GDEFCORE_Structure_Edit e = SEdit(GDEFCORE_STRUCTURE_ACT_ADD_ROW, SVersion());
  e.behavior = GDEFCORE_STRUCTURE_FIXED;
  e.row = 99;
  e.region = "footer";
  e.region_len = 6;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 8 1\ncell side 4 2\nrow fixed\ncell footer 12\n", Document());
}


TEST_F(LayoutEdit, TheCellsOfARowAreWidenedMovedAndStackedAndARowNeverPassesTwelve) {
  ASSERT_EQ(GDEFCORE_OK, SStart("two-columns-right")) << refusal_;
  /* 8 + 4 is 12: a third cell does not fit until main gives some up. */
  GDEFCORE_Structure_Edit e = SEdit(GDEFCORE_STRUCTURE_ACT_ADD_CELL, SVersion());
  e.row = 0;
  e.region = "extra";
  e.region_len = 5;
  e.width = 2;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SDo(e));
  EXPECT_NE(std::string::npos, refusal_.find("more than 12")) << refusal_;
  const std::string before = Document();
  e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_WIDTH, SVersion());
  e.row = 0;
  e.cell = 0;
  e.width = 6;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 1\ncell side 4 2\n", Document());
  e = SEdit(GDEFCORE_STRUCTURE_ACT_ADD_CELL, SVersion());
  e.region = "extra";
  e.region_len = 5;
  e.width = 2;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 1\ncell side 4 2\ncell extra 2 3\n", Document());
  /* The third cell stacks first. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_STACKED, SVersion());
  e.cell = 2;
  e.stacked = 1;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 3\ncell side 4 2\ncell extra 2 1\n", Document());
  e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_STACKED, SVersion());
  e.cell = 2;
  e.stacked = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SDo(e));
  /* Move the last cell first. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_MOVE_CELL, SVersion());
  e.cell = 2;
  e.to_row = 0;
  e.to_cell = 0;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell extra 2 1\ncell main 6 3\ncell side 4 2\n", Document());
  /* A second row, a cell moved to it, and the row it left stays. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_ADD_ROW, SVersion());
  e.behavior = GDEFCORE_STRUCTURE_WRAP;
  e.region = "card";
  e.region_len = 4;
  e.row = 99;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell extra 2 1\ncell main 6 3\ncell side 4 2\nrow wrap\ncell card\n",
      Document());
  e = SEdit(GDEFCORE_STRUCTURE_ACT_MOVE_CELL, SVersion());
  e.cell = 0;
  e.to_row = 1;
  e.to_cell = 0;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 2\ncell side 4 1\nrow wrap\ncell extra\ncell card\n",
      Document());
  /* A wrap row made a stack row gets widths that fit; made a wrap row again, none. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_ROW, SVersion());
  e.row = 1;
  e.behavior = GDEFCORE_STRUCTURE_STACK;
  e.breakpoint = GDEFCORE_STRUCTURE_WIDE;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 2\ncell side 4 1\nrow stack wide\ncell extra 6 1\ncell card 6 2\n",
      Document());
  /* Moving the only cell of a row takes the row with it. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_REMOVE_CELL, SVersion());
  e.row = 1;
  e.cell = 1;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  e = SEdit(GDEFCORE_STRUCTURE_ACT_MOVE_CELL, SVersion());
  e.row = 1;
  e.cell = 0;
  e.to_row = 0;
  e.to_cell = 9;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 2\ncell side 4 1\ncell extra 2 3\n", Document());
  /* Removing the only cell of a row takes the row. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_ADD_ROW, SVersion());
  e.behavior = GDEFCORE_STRUCTURE_FIXED;
  e.region = "tmp";
  e.region_len = 3;
  e.row = 99;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  e = SEdit(GDEFCORE_STRUCTURE_ACT_REMOVE_CELL, SVersion());
  e.row = 1;
  e.cell = 0;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 2\ncell side 4 1\ncell extra 2 3\n", Document());
  /* Rows move. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_ADD_ROW, SVersion());
  e.behavior = GDEFCORE_STRUCTURE_FIXED;
  e.region = "header";
  e.region_len = 6;
  e.row = 0;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row fixed\ncell header 12\nrow stack medium\ncell main 6 2\ncell side 4 1\ncell extra 2 3\n",
      Document());
  e = SEdit(GDEFCORE_STRUCTURE_ACT_MOVE_ROW, SVersion());
  e.row = 0;
  e.to_row = 1;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 6 2\ncell side 4 1\ncell extra 2 3\nrow fixed\ncell header 12\n",
      Document());
  /* Out of range is not there. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_REMOVE_ROW, SVersion());
  e.row = 7;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SDo(e));
  EXPECT_EQ(GDEFCORE_STRUCTURE_REFUSED_THERE, refusal_);
  (void)before;
}

TEST_F(LayoutEdit, RenamingACellCarriesEveryLayoutsPlacementsAndRemovingOneSetsThemAside) {
  ASSERT_EQ(GDEFCORE_OK, SStart("two-columns-right")) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "side", 0)) << refusal_;
  EXPECT_EQ("main content\nside recent\n", Lines("post"));
  const size_t revisions = Revisions("post");
  /* A rename: the placements follow, in the same changeset. */
  GDEFCORE_Structure_Edit e = SEdit(GDEFCORE_STRUCTURE_ACT_RENAME_CELL, SVersion());
  e.row = 0;
  e.cell = 1;
  e.region = "rail";
  e.region_len = 4;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 8 1\ncell rail 4 2\n", Document());
  EXPECT_EQ("main content\nrail recent\n", Lines("post"));
  EXPECT_EQ("", Lines("post", true));
  EXPECT_EQ("", moved_);
  EXPECT_EQ(revisions + 1, Revisions("post")) << "one revision for the layout";
  /* A region used elsewhere cannot be the new name. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_RENAME_CELL, SVersion());
  e.cell = 1;
  e.region = "main";
  e.region_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SDo(e));
  EXPECT_NE(std::string::npos, refusal_.find("used once")) << refusal_;
  EXPECT_EQ("main content\nrail recent\n", Lines("post"));
  /* Removing a cell sets its placements aside and says so. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_REMOVE_CELL, SVersion());
  e.cell = 1;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 8 1\n", Document());
  EXPECT_EQ("main content\n", Lines("post"));
  EXPECT_EQ("recent\n", Lines("post", true));
  EXPECT_EQ("post recent rail\n", moved_);
  /* A cell that is added again does not take them back: they are set aside until placed. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_ADD_CELL, SVersion());
  e.region = "rail";
  e.region_len = 4;
  e.width = 4;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("main content\n", Lines("post"));
  EXPECT_EQ("recent\n", Lines("post", true));
}

TEST_F(LayoutEdit, AStaleStructureFormAHandWrittenTemplateAndAMissingPermissionWriteNothing) {
  ASSERT_EQ(GDEFCORE_OK, SStart("two-columns-right")) << refusal_;
  const std::string old_version = SVersion();
  GDEFCORE_Structure_Edit e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_WIDTH, old_version);
  e.cell = 0;
  e.width = 6;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  /* The same form again is stale. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_WIDTH, old_version);
  e.cell = 0;
  e.width = 5;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SDo(e));
  EXPECT_EQ(GDEFCORE_STRUCTURE_REFUSED_STALE, refusal_);
  EXPECT_EQ("row stack medium\ncell main 6 1\ncell side 4 2\n", Document());
  /* No permission to the template or the stylesheet: nothing is written. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_WIDTH, SVersion());
  e.cell = 0;
  e.width = 5;
  GDEFCORE_Request * layouter = Req(layouter_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SDo(e, layouter));
  EXPECT_EQ("row stack medium\ncell main 6 1\ncell side 4 2\n", Document());
  /* A starting point that is not one. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SStart("no-such-point"));
  EXPECT_EQ(GDEFCORE_STRUCTURE_REFUSED_START, refusal_);
  /* Written by hand: every edit but a new start is refused, and a start takes over. */
  e = SEdit(GDEFCORE_STRUCTURE_ACT_CUSTOM, SVersion());
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("custom", Document());
  e = SEdit(GDEFCORE_STRUCTURE_ACT_SET_WIDTH, SVersion());
  e.cell = 0;
  e.width = 5;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SDo(e));
  EXPECT_EQ(GDEFCORE_STRUCTURE_REFUSED_CUSTOM, refusal_);
  e = SEdit(GDEFCORE_STRUCTURE_ACT_START_NEW, SVersion());
  e.region = "main";
  e.region_len = 4;
  ASSERT_EQ(GDEFCORE_OK, SDo(e)) << refusal_;
  EXPECT_EQ("row stack medium\ncell main 12 1\n", Document());
  EXPECT_EQ("<none>", Document("no-such-template"));
}


TEST_F(LayoutEdit, APreviewShowsWhatAVisitorWouldSeeAndNeverNamesWhatItHides) {
  GDEFCORE_Placement editors = Placement("recent");
  editors.nroles = 1;
  snprintf(editors.roles[0], sizeof editors.roles[0], "editors");
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "side", 0, &editors)) << refusal_;
  GDEFCORE_Placement signed_in = Placement("menu");
  signed_in.nroles = 1;
  snprintf(signed_in.roles[0], sizeof signed_in.roles[0], "authenticated");
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "side", 1, &signed_in)) << refusal_;
  GDEFCORE_Placement blog = Placement("menu");
  snprintf(blog.path, sizeof blog.path, "/blog/**");
  ASSERT_EQ(GDEFCORE_OK, Place("post", "menu", "main", 1, &blog)) << refusal_;
  const size_t revisions = Revisions("post");
  auto look = [this](const char * role, const char * path) {
    GDEFCORE_Preview_Viewer viewer;
    GDEFCORE_Layout_Preview pv;
    memset(&viewer, 0, sizeof viewer);
    viewer.size = sizeof viewer;
    viewer.role = role;
    viewer.role_len = strlen(role);
    viewer.path = path;
    viewer.path_len = strlen(path);
    memset(&pv, 0, sizeof pv);
    pv.size = sizeof pv;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_layout_preview(catalog_, "post", 4, &viewer, &pv));
    std::string out;
    for (size_t i = 0; i < pv.view.nplaced; i++) {
      if (pv.shown[i]) {
        out += std::string(pv.view.placed[i].region) + ":" + pv.view.placed[i].widget + " ";
      }
    }
    out += "hidden=" + std::to_string(pv.nhidden);
    gdefcore_layout_preview_free(&pv);
    return out;
  };
  /* Anyone: the page's own content only. */
  EXPECT_EQ("main:content hidden=3 ", look("", "/other") + " ");
  EXPECT_EQ("main:content main:menu hidden=2 ", look("", "/blog/x") + " ");
  /* Signed in with no named role: the placement for everyone signed in. */
  EXPECT_EQ("main:content side:menu hidden=2 ", look("authenticated", "/other") + " ");
  /* A holder of the role sees both of the role's. */
  EXPECT_EQ("main:content side:recent side:menu hidden=1 ", look("editors", "/other") + " ");
  EXPECT_EQ("main:content main:menu side:recent side:menu hidden=0 ", look("editors", "/blog/y") + " ");
  /* A role nobody's placement names is no more than signed in. */
  EXPECT_EQ(look("authenticated", "/other"), look("somebody-else", "/other"));
  /* Previewing writes nothing and changes nothing. */
  EXPECT_EQ(revisions, Revisions("post"));
  /* A layout that is not there. */
  GDEFCORE_Preview_Viewer viewer;
  GDEFCORE_Layout_Preview pv;
  memset(&viewer, 0, sizeof viewer);
  viewer.size = sizeof viewer;
  memset(&pv, 0, sizeof pv);
  pv.size = sizeof pv;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_layout_preview(catalog_, "no-such", 7, &viewer, &pv));
}

TEST_F(LayoutEdit, ThePreviewOfALayoutOfThirtyPlacementsIsMeasuredForEveryRole) {
  /* The cost of previewing as a role: a full layout, asked 2000 times. */
  for (int i = 0; i < 30; i++) {
    GDEFCORE_Placement p = Placement(i % 2 ? "menu" : "recent");
    p.nroles = 1;
    snprintf(p.roles[0], sizeof p.roles[0], "role%d", i % 5);
    ASSERT_EQ(GDEFCORE_OK, Place("post", i % 2 ? "menu" : "recent", i % 3 ? "main" : "side", 0, &p)) << i << refusal_;
  }
  GDEFCORE_Preview_Viewer viewer;
  memset(&viewer, 0, sizeof viewer);
  viewer.size = sizeof viewer;
  viewer.role = "role2";
  viewer.role_len = 5;
  viewer.path = "/x";
  viewer.path_len = 2;
  size_t shown = 0;
  const auto start = std::chrono::steady_clock::now();
  const int rounds = 2000;
  for (int r = 0; r < rounds; r++) {
    GDEFCORE_Layout_Preview pv;
    memset(&pv, 0, sizeof pv);
    pv.size = sizeof pv;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_layout_preview(catalog_, "post", 4, &viewer, &pv));
    shown = pv.nshown;
    EXPECT_EQ(pv.view.nplaced, pv.nshown + pv.nhidden);
    gdefcore_layout_preview_free(&pv);
  }
  const double micros = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count() / rounds;
  /* content + the six placements of role2 (30 placements, five roles). */
  EXPECT_EQ(7u, shown);
  fprintf(stderr, "preview-as-role: 31 placements, %.1f microseconds a preview\n", micros);
  EXPECT_LT(micros, 20000.0) << "a preview is a read of one layout and a loop";
}


TEST_F(LayoutEdit, ATemplateEditThatDropsARegionSetsItsPlacementsAsideAndLosesNone) {
  ASSERT_EQ(GDEFCORE_OK, Place("post", "recent", "side", 0)) << refusal_;
  EXPECT_EQ("main content\nside recent\n", Lines("post"));
  /* The template "layout" is edited to call only the main region. */
  char ** ids = NULL;
  size_t n = 0;
  std::string tid;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, "core.template", 13, &ids, &n));
  for (size_t i = 0; i < n && tid.empty(); i++) {
    char ** t = NULL;
    size_t * l = NULL;
    size_t c = 0;
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], strlen(ids[i]), "en", 2,
            "name", 4, &t, &l, &c) == GDEFCORE_OK && c > 0 && std::string(t[0], l[0]) == "layout") {
      tid = ids[i];
    }
    if (c > 0) {
      gdefcore_values_free(catalog_, t, l, c);
    }
  }
  gdefcore_ids_free(catalog_, ids, n);
  ASSERT_FALSE(tid.empty());
  const std::string body = "<% use region; %><div><%= region(\"main\") %></div>";
  const char * slot = body.c_str();
  size_t len = body.size();
  GDEFCORE_Value value;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "body";
  value.field_len = 4;
  value.texts = &slot;
  value.text_lens = &len;
  value.count = 1;
  GDEFCORE_Changeset * cs = NULL;
  char * moved = NULL;
  size_t moved_len = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, tid.data(), tid.size(), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_layout_stage_template_carry(cs, "layout", 6, body.data(), body.size(),
                             &moved, &moved_len));
  EXPECT_EQ("post recent side\n", std::string(moved, moved_len));
  free(moved);
  std::set<std::string> types;
  for (size_t i = 0; i < gdefcore_changeset_touched_count(cs); i++) {
    const char * id;
    size_t id_len;
    const char * type;
    size_t type_len;
    int op;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_touched_at(cs, i, &id, &id_len, &type, &type_len, &op));
    types.insert(std::string(type, type_len));
  }
  std::string confirm;
  for (const std::string & t : types) {
    confirm += (confirm.empty() ? "" : "\n") + t;
  }
  EXPECT_EQ("core.display\ncore.template", confirm);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, confirm.data(), confirm.size())) << [&] {
    size_t rn = 0;
    const char * r = gdefcore_changeset_refusal(cs, &rn);
    return r == NULL ? std::string() : std::string(r, rn);
  }();
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("main content\n", Lines("post"));
  EXPECT_EQ("recent\n", Lines("post", true)) << "nothing is lost";
  /* A body that keeps every region stages nothing for the layout. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_layout_stage_template_carry(cs, "layout", 6, body.data(), body.size(),
                             NULL, NULL));
  EXPECT_EQ(0u, gdefcore_changeset_touched_count(cs));
  gdefcore_changeset_destroy(cs);
}

TEST_F(LayoutEdit, TheStructsHereAreAcceptedAtOnlyTheirOwnSize) {
  auto placement = [](size_t size) {
    GDEFCORE_Placement p;
    char line[256];
    memset(&p, 0, sizeof p);
    p.size = size;
    snprintf(p.widget, sizeof p.widget, "menu");
    return gdefcore_placement_format(&p, 0, line, sizeof line) > 0;
  };
  auto view = [this](size_t size) {
    GDEFCORE_Layout_View v;
    memset(&v, 0, sizeof v);
    v.size = size;
    GDEFCORE_Result rc = gdefcore_layout_view(catalog_, "post", 4, &v);
    if (rc == GDEFCORE_OK) {
      gdefcore_layout_view_free(&v);
    }
    return rc == GDEFCORE_OK;
  };
  auto edit = [this](size_t size) {
    GDEFCORE_Layout_Edit e = Edit(GDEFCORE_LAYOUT_ACT_PLACE, "post", Version("post"));
    GDEFCORE_Changeset * cs = NULL;
    e.placement = Placement("menu");
    e.region = "main";
    e.region_len = 4;
    e.size = size;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    bool ok = gdefcore_layout_stage_edit(cs, &e) == GDEFCORE_OK;
    gdefcore_changeset_destroy(cs);
    return ok;
  };
  auto sview = [this](size_t size) {
    GDEFCORE_Structure_View v;
    memset(&v, 0, sizeof v);
    v.size = size;
    GDEFCORE_Result rc = gdefcore_structure_view(catalog_, "layout", 6, &v);
    if (rc == GDEFCORE_OK) {
      gdefcore_structure_view_free(&v);
    }
    return rc == GDEFCORE_OK;
  };
  auto sedit = [this](size_t size) {
    GDEFCORE_Structure_Edit e = SEdit(GDEFCORE_STRUCTURE_ACT_START, SVersion());
    GDEFCORE_Changeset * cs = NULL;
    e.region = "one-column";
    e.region_len = 10;
    e.size = size;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    bool ok = gdefcore_structure_stage_edit(cs, "layout", 6, &e, NULL, NULL) == GDEFCORE_OK;
    gdefcore_changeset_destroy(cs);
    return ok;
  };
  auto pviewer = [this](size_t size) {
    GDEFCORE_Preview_Viewer viewer;
    GDEFCORE_Layout_Preview pv;
    memset(&viewer, 0, sizeof viewer);
    viewer.size = size;
    memset(&pv, 0, sizeof pv);
    pv.size = sizeof pv;
    GDEFCORE_Result rc = gdefcore_layout_preview(catalog_, "post", 4, &viewer, &pv);
    if (rc == GDEFCORE_OK) {
      gdefcore_layout_preview_free(&pv);
    }
    return rc == GDEFCORE_OK;
  };
  auto ppreview = [this](size_t size) {
    GDEFCORE_Preview_Viewer viewer;
    GDEFCORE_Layout_Preview pv;
    memset(&viewer, 0, sizeof viewer);
    viewer.size = sizeof viewer;
    memset(&pv, 0, sizeof pv);
    pv.size = size;
    GDEFCORE_Result rc = gdefcore_layout_preview(catalog_, "post", 4, &viewer, &pv);
    if (rc == GDEFCORE_OK) {
      gdefcore_layout_preview_free(&pv);
    }
    return rc == GDEFCORE_OK;
  };
  size_structs::Run("tests/test_layoutedit.cpp",
      {{"GDEFCORE_Preview_Viewer", pviewer}, {"GDEFCORE_Layout_Preview", ppreview},
          {"GDEFCORE_Placement", placement}, {"GDEFCORE_Layout_View", view},
          {"GDEFCORE_Layout_Edit", edit}, {"GDEFCORE_Structure_View", sview},
          {"GDEFCORE_Structure_Edit", sedit}});
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
