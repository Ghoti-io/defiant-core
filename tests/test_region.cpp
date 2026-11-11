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
 * What an editor calls a region (region.h): a label and a help text from the
 * template's own list, then the shared catalog, then the name made readable;
 * written only by changeset under the layout permission; and a layout's Not
 * placed list, which is only ever data.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include "grants_fixture.h"
#include "size_structs.h"

using namespace gfx;

namespace {
const char kDescriptor[] = GDEFCORE_REGION_DESCRIPTOR_TYPE;
const char kDisplay[] = "core.display";
const char kTemplate[] = "core.template";
}  // namespace

class Regions : public GrantsFixture {
 protected:
  std::string refusal_;
  std::string editor_, reader_;

  void SetUp() override {
    GrantsFixture::SetUp();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    Role("regioners");
    Grant("regioners", GDEFCORE_REGION_EDIT_LABEL);
    editor_ = Principal("regioners");
    reader_ = Principal();
  }

  void Remember(GDEFCORE_Changeset * cs) {
    size_t n = 0;
    const char * why = gdefcore_changeset_refusal(cs, &n);
    refusal_ = why == NULL ? "" : std::string(why, n);
  }

  /* "label|description|source" as an editor is shown it. */
  std::string Describe(const char * tmpl, const std::string & region) {
    GDEFCORE_Region_Info info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (gdefcore_region_describe(catalog_, tmpl, tmpl == NULL ? 0 : strlen(tmpl),
            region.data(), region.size(), &info) != GDEFCORE_OK) {
      return std::string();
    }
    std::string out = std::string(info.label, info.label_len) + "|" +
        std::string(info.description, info.description_len) + "|" +
        std::to_string(info.source);
    gdefcore_region_info_free(catalog_, &info);
    return out;
  }

  GDEFCORE_Result Shared(const std::string & name, const std::string & label,
      const std::string & description, GDEFCORE_Request * request = NULL) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_region_stage_shared(cs, name.data(), name.size(),
        label.data(), label.size(), description.data(), description.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, kDescriptor, strlen(kDescriptor));
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Forget(const std::string & name, GDEFCORE_Request * request = NULL) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_region_stage_shared_forget(cs, name.data(), name.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, kDescriptor, strlen(kDescriptor));
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* A template's own descriptor, written with the template. */
  GDEFCORE_Result Own(const char * tmpl, const std::string & region,
      const std::string & label, const std::string & description) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    GDEFCORE_Result rc = gdefcore_region_stage_template(cs, tmpl, strlen(tmpl),
        region.data(), region.size(), label.empty() ? NULL : label.data(), label.size(),
        description.data(), description.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, kTemplate, strlen(kTemplate));
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  std::string IdOf(const char * type, const char * name) {
    char ** ids = NULL;
    size_t n = 0;
    std::string found;
    if (gdefcore_entity_ids(catalog_, type, strlen(type), &ids, &n) != GDEFCORE_OK) {
      return found;
    }
    for (size_t i = 0; i < n && found.empty(); i++) {
      char ** t = NULL;
      size_t * l = NULL;
      size_t cnt = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              strlen(ids[i]), "en", 2, "name", 4, &t, &l, &cnt) != GDEFCORE_OK) {
        continue;
      }
      if (cnt > 0 && std::string(t[0], l[0]) == name) {
        found = ids[i];
      }
      gdefcore_values_free(catalog_, t, l, cnt);
    }
    gdefcore_ids_free(catalog_, ids, n);
    return found;
  }

  /* Save `field` of the entity @p id with @p lines, by the port, with no staging
   * call between, to reach the vet that stands behind the staging. */
  GDEFCORE_Result PutLines(const std::string & id, const char * field,
      const std::vector<std::string> & lines, const char * confirm) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value value;
    std::vector<const char *> slots;
    std::vector<size_t> lens;
    for (const std::string & l : lines) {
      slots.push_back(l.c_str());
      lens.push_back(l.size());
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = field;
    value.field_len = strlen(field);
    value.texts = slots.data();
    value.text_lens = lens.data();
    value.count = lines.size();
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, &value, 1));
    GDEFCORE_Result rc = gdefcore_changeset_apply(cs, confirm, strlen(confirm));
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }
};

TEST_F(Regions, ANewSiteStartsWithTheFiveSharedDescriptors) {
  EXPECT_EQ("Main content area|Where the page's own content goes.|2", Describe(NULL, "main"));
  EXPECT_EQ("Side area|Shown beside the main content.|2", Describe(NULL, "side"));
  EXPECT_EQ("Header|The top of the page.|2", Describe(NULL, "header"));
  EXPECT_EQ("Navigation|Menus and ways around the site.|2", Describe(NULL, "navigation"));
  EXPECT_EQ("Footer|The bottom of the page.|2", Describe(NULL, "footer"));
  /* A region nobody described is its name, made readable. */
  EXPECT_EQ("Footer links||3", Describe(NULL, "footer_links"));
  EXPECT_EQ("Two words||3", Describe(NULL, "two-words"));
  EXPECT_EQ("A1||3", Describe(NULL, "a1"));
  /* A name that is not a region name is not described. */
  for (const char * bad : {"", "Main", "1a", "a b", "a.b", "../x", "a%20b"}) {
    EXPECT_EQ("", Describe(NULL, bad)) << bad;
  }
  EXPECT_EQ("", Describe(NULL, std::string(64, 'a')));
  EXPECT_NE("", Describe(NULL, std::string(63, 'a'))) << "CONTROL: the longest";
}

TEST_F(Regions, ATemplatesOwnDescriptorBeatsASharedOneWhichBeatsTheName) {
  ASSERT_EQ(GDEFCORE_OK, Own("layout", "side", "Right rail", "On the right.")) << refusal_;
  EXPECT_EQ("Right rail|On the right.|1", Describe("layout", "side"));
  EXPECT_EQ("Side area|Shown beside the main content.|2", Describe("entity", "side"))
      << "another template's region of the same name";
  EXPECT_EQ("Side area|Shown beside the main content.|2", Describe(NULL, "side"));
  EXPECT_EQ("Side area|Shown beside the main content.|2", Describe("no-such-template", "side"));
  /* Several on one template, each its own. */
  ASSERT_EQ(GDEFCORE_OK, Own("layout", "banner", "Top banner", "")) << refusal_;
  EXPECT_EQ("Top banner||1", Describe("layout", "banner"));
  EXPECT_EQ("Right rail|On the right.|1", Describe("layout", "side"));
  /* Replaced, and taken away. */
  ASSERT_EQ(GDEFCORE_OK, Own("layout", "side", "Rail", "")) << refusal_;
  EXPECT_EQ("Rail||1", Describe("layout", "side"));
  ASSERT_EQ(GDEFCORE_OK, Own("layout", "side", "", "")) << refusal_;
  EXPECT_EQ("Side area|Shown beside the main content.|2", Describe("layout", "side"));
  EXPECT_EQ("Top banner||1", Describe("layout", "banner"));
  /* A text with a space, a percent sign, a tilde and a non-ASCII letter comes
   * back as it went in. */
  const std::string odd = "A 100% ~odd~ caf\xC3\xA9 label";
  ASSERT_EQ(GDEFCORE_OK, Own("layout", "main", odd, "Two  spaces & <b>")) << refusal_;
  EXPECT_EQ(odd + "|Two  spaces & <b>|1", Describe("layout", "main"));
}

TEST_F(Regions, ASharedDescriptorIsMadeChangedAndRemovedByChangeset) {
  ASSERT_EQ(GDEFCORE_OK, Shared("promo", "Promotion", "Shown on sale days.")) << refusal_;
  EXPECT_EQ("Promotion|Shown on sale days.|2", Describe(NULL, "promo"));
  ASSERT_EQ(GDEFCORE_OK, Shared("promo", "Promo", "")) << refusal_;
  EXPECT_EQ("Promo||2", Describe(NULL, "promo")) << "the description is taken away";
  /* A site's own descriptor for a default name wins, and the seed leaves it. */
  ASSERT_EQ(GDEFCORE_OK, Shared("main", "The content", "Mine.")) << refusal_;
  {
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
  }
  EXPECT_EQ("The content|Mine.|2", Describe(NULL, "main"));
  /* Removing a default leaves the name. */
  ASSERT_EQ(GDEFCORE_OK, Forget("promo")) << refusal_;
  EXPECT_EQ("Promo||3", Describe(NULL, "promo"));
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared_forget(cs, "promo", 5));
  gdefcore_changeset_destroy(cs);
}

TEST_F(Regions, ADescriptorThatIsNotOneIsRefusedAtStageAndAtApply) {
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  const std::string long_label(GDEFCORE_REGION_LABEL_MAX + 1, 'a');
  const std::string long_description(GDEFCORE_REGION_DESCRIPTION_MAX + 1, 'a');
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared(cs, "Bad", 3, "L", 1, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared(cs, "ok", 2, "", 0, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared(cs, "ok", 2, "a\x07", 2, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared(cs, "ok", 2, "a\xff", 2, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared(cs, "ok", 2, long_label.data(),
                                      long_label.size(), "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared(cs, "ok", 2, "L", 1,
                                      long_description.data(), long_description.size()));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_shared(NULL, "ok", 2, "L", 1, "", 0));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_region_stage_shared(cs, "ok", 2,
                             std::string(GDEFCORE_REGION_LABEL_MAX, 'a').c_str(),
                             GDEFCORE_REGION_LABEL_MAX, "", 0)) << "CONTROL: the longest label";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_template(cs, "no-such", 7, "side", 4, "L", 1, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_template(cs, "layout", 6, "Side", 4, "L", 1, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_region_stage_template(cs, "layout", 6, "side", 4,
                                      long_label.data(), long_label.size(), "", 0));
  gdefcore_changeset_destroy(cs);
  /* The vet stands behind the staging: what the port is given directly. */
  const std::string shared = IdOf(kDescriptor, "main");
  ASSERT_FALSE(shared.empty());
  const std::string tmpl = IdOf(kTemplate, "layout");
  ASSERT_FALSE(tmpl.empty());
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLines(tmpl, "regions", {"side"}, kTemplate));
  EXPECT_NE(std::string::npos, refusal_.find("~label")) << refusal_;
  const char * bad[] = {"Side ~label=L", "side ~label=", "side ~description=d", "side ~label=L ~label=M",
      "side ~label=L ~foo=x", "side ~label=%zz", "side  ~label=L", "side ~label=L "};
  for (const char * line : bad) {
    EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLines(tmpl, "regions", {line}, kTemplate)) << line;
  }
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      PutLines(tmpl, "regions", {"side ~label=A", "side ~label=B"}, kTemplate));
  EXPECT_NE(std::string::npos, refusal_.find("twice")) << refusal_;
  EXPECT_EQ(GDEFCORE_OK, PutLines(tmpl, "regions", {"side ~label=A", "main ~label=B ~description=C"}, kTemplate))
      << refusal_;
  EXPECT_EQ("A||1", Describe("layout", "side"));
  /* The port holds 32 values of one field, so that is how many descriptors a
   * template keeps. */
  std::vector<std::string> many;
  for (int i = 0; i < 32; i++) {
    many.push_back("r" + std::to_string(i) + " ~label=L");
  }
  EXPECT_EQ(GDEFCORE_OK, PutLines(tmpl, "regions", many, kTemplate)) << "CONTROL: 32";
  GDEFCORE_Changeset * big = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &big));
  for (int i = 0; i < 32; i++) {
    const std::string r = "r" + std::to_string(i);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_region_stage_template(big, "layout", 6, r.data(), r.size(),
                               "L", 1, "", 0));
  }
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_region_stage_template(big, "layout", 6, "extra", 5, "L", 1, "", 0))
      << "a 33rd is refused by the stage";
  gdefcore_changeset_destroy(big);
  /* The shared type's own fields. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLines(shared, "label", {""}, kDescriptor)) << "an empty label";
  EXPECT_EQ("Main content area|Where the page's own content goes.|2", Describe(NULL, "main"));
}

TEST_F(Regions, SharedDescriptorsAreWrittenOnTheirOwnPermissionAndTemplatesOnTheTemplates) {
  GDEFCORE_Request * editor = Req(editor_);
  GDEFCORE_Request * reader = Req(reader_);
  EXPECT_TRUE(gdefcore_region_may_edit(catalog_, editor));
  EXPECT_FALSE(gdefcore_region_may_edit(catalog_, reader));
  EXPECT_FALSE(gdefcore_region_may_edit(NULL, editor));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Shared("promo", "Promo", "", reader));
  EXPECT_NE(std::string::npos, refusal_.find("That edit is not allowed.")) << refusal_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Forget("main", reader));
  EXPECT_EQ("Main content area|Where the page's own content goes.|2", Describe(NULL, "main"));
  EXPECT_EQ("Promo||3", Describe(NULL, "promo"));
  EXPECT_EQ(GDEFCORE_OK, Shared("promo", "Promo", "", editor)) << refusal_;
  EXPECT_EQ("Promo||2", Describe(NULL, "promo"));
  EXPECT_EQ(GDEFCORE_OK, Forget("promo", editor)) << refusal_;
  /* The layout editor's other permissions are not this one. */
  Role("layouters");
  Grant("layouters", GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL);
  Grant("layouters", GDEFCORE_LAYOUT_EDIT_RULE_LABEL);
  GDEFCORE_Request * layouter = Req(Principal("layouters"));
  EXPECT_FALSE(gdefcore_region_may_edit(catalog_, layouter));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Shared("promo", "Promo", "", layouter));
}

TEST_F(Regions, ADescriptorChangesWhatAnEditorSeesAndNeverHowAPageRenders) {
  const auto page = [&]() {
    char * out = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_render_page(catalog_, NULL, Req(), "/", 1,
                               GDEFCORE_RENDER_PAGE_FUEL, &out, &n));
    std::string text(out, n);
    gdefcore_text_free(catalog_, out);
    return text;
  };
  const std::string before = page();
  ASSERT_FALSE(before.empty());
  ASSERT_EQ(GDEFCORE_OK, Shared("side", "Entirely different", "Nothing like it.")) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Own("layout", "side", "Mine", "Also different")) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Forget("main")) << refusal_;
  EXPECT_EQ(before, page());
  /* Nor does it touch a placement: the layouts are as they were. */
  GDEFCORE_Request * none = Req();
  char * out = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_page(catalog_, NULL, none, "/", 1,
                             GDEFCORE_RENDER_PAGE_FUEL, &out, &n));
  gdefcore_text_free(catalog_, out);
}

TEST_F(Regions, ALayoutsNotPlacedListIsOnlyDataAndIsCheckedForItsShape) {
  const std::string post = IdOf(kDisplay, "post");
  ASSERT_FALSE(post.empty());
  const auto render = [&]() {
    char * out = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_render_page(catalog_, NULL, Req(), "/", 1,
                               GDEFCORE_RENDER_PAGE_FUEL, &out, &n));
    std::string text(out, n);
    gdefcore_text_free(catalog_, out);
    return text;
  };
  const std::string before = render();
  ASSERT_EQ(GDEFCORE_OK,
      PutLines(post, "unplaced", {"menu", "ghost.widget target ~title=Left%20behind",
                                     "recent ~role=editor"}, kDisplay))
      << refusal_;
  EXPECT_EQ(before, render()) << "an unplaced widget draws nothing";
  /* A widget no module offers is allowed here: a module that is disabled keeps
   * its placements, unavailable. */
  const char * bad[] = {"", "main widget extra extra", "recent ~foo=1", "recent ~title=",
      "recent ~path=admin", "two words ~role=Bad", "recent  ~title=x"};
  for (const char * line : bad) {
    EXPECT_EQ(GDEFCORE_ERR_INVALID, PutLines(post, "unplaced", {line}, kDisplay))
        << "[" << line << "]";
  }
  std::vector<std::string> ok(32, "menu");
  EXPECT_EQ(GDEFCORE_OK, PutLines(post, "unplaced", ok, kDisplay)) << "CONTROL: 32";
}

TEST_F(Regions, TheStructsHereAreAcceptedAtOnlyTheirOwnSize) {
  auto described = [this](size_t size) {
    GDEFCORE_Region_Info info;
    memset(&info, 0, sizeof info);
    info.size = size;
    GDEFCORE_Result rc = gdefcore_region_describe(catalog_, NULL, 0, "main", 4, &info);
    if (rc == GDEFCORE_OK) {
      gdefcore_region_info_free(catalog_, &info);
    }
    return rc == GDEFCORE_OK;
  };
  size_structs::Run("tests/test_region.cpp", {{"GDEFCORE_Region_Info", described}});
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
