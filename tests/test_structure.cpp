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
 * A page template's structure (structure.h): the document and its rules, the
 * source and stylesheet it makes (the same bytes every time, the regions of the
 * source exactly its cells), the one changeset that writes them, a template that
 * a person wrote by hand, and what the apply refuses.
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

const char kTemplate[] = "core.template";
const char kCss[] = GDEFCORE_ASSET_CSS_TYPE;
const std::string kBoth = std::string(kCss) + "\n" + kTemplate;

/* Header, two columns that fold at medium (the side after the main content on a
 * phone), and a footer. */
const char kGrail[] =
    "row fixed\ncell header 12\n"
    "row stack medium\ncell main 8 1\ncell side 4 2\n"
    "row fixed\ncell footer 12\n";

}  // namespace

class Structures : public GrantsFixture {
 protected:
  std::string refusal_;

  void SetUp() override {
    GrantsFixture::SetUp();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
  }

  void Remember(GDEFCORE_Changeset * cs) {
    size_t n = 0;
    const char * why = gdefcore_changeset_refusal(cs, &n);
    refusal_ = why == NULL ? "" : std::string(why, n);
  }

  GDEFCORE_Result Stage(const std::string & name, const std::string & doc,
      int replace = 0, const std::string & confirm = kBoth) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    GDEFCORE_Result rc = gdefcore_structure_stage(cs, name.data(), name.size(), doc.data(),
        doc.size(), replace);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Custom(const std::string & name, const std::string & confirm = kBoth) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    GDEFCORE_Result rc = gdefcore_structure_stage_custom(cs, name.data(), name.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  std::string Read(const std::string & name) {
    char * text = NULL;
    size_t n = 0;
    if (gdefcore_structure_read(catalog_, name.data(), name.size(), &text, &n) != GDEFCORE_OK) {
      return "<none>";
    }
    std::string out(text, n);
    gdefcore_text_free(catalog_, text);
    return out;
  }

  std::string Field(const std::string & id, const char * field) {
    char ** t = NULL;
    size_t * l = NULL;
    size_t n = 0;
    std::string out;
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id.data(), id.size(),
            "en", 2, field, strlen(field), &t, &l, &n) == GDEFCORE_OK && n > 0) {
      out.assign(t[0], l[0]);
    }
    if (n > 0) {
      gdefcore_values_free(catalog_, t, l, n);
    }
    return out;
  }

  std::string IdOf(const char * type, const char * name) {
    char ** ids = NULL;
    size_t n = 0;
    std::string found;
    if (gdefcore_entity_ids(catalog_, type, strlen(type), &ids, &n) != GDEFCORE_OK) {
      return found;
    }
    for (size_t i = 0; i < n && found.empty(); i++) {
      if (Field(ids[i], "name") == name) {
        found = ids[i];
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    return found;
  }

  std::string Body(const char * name) { return Field(IdOf(kTemplate, name), "body"); }

  std::string Css(const std::string & name) {
    GDEFCORE_Asset a;
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    const std::string ref = "site/layout-" + name + ".css";
    if (gdefcore_asset_find(catalog_, NULL, ref.data(), ref.size(), &a) != GDEFCORE_OK) {
      return "<none>";
    }
    std::string out((const char *)a.bytes, a.bytes_len);
    gdefcore_asset_release(&a);
    return out;
  }

  std::string Check(const std::string & doc, std::string * why = NULL) {
    char * canon = NULL;
    size_t n = 0;
    char reason[300];
    reason[0] = '\0';
    GDEFCORE_Result rc = gdefcore_structure_check(doc.data(), doc.size(), &canon, &n, reason,
        sizeof reason);
    if (why != NULL) {
      *why = reason;
    }
    if (rc != GDEFCORE_OK) {
      return "";
    }
    std::string out(canon, n);
    gdefcore_text_free(catalog_, canon);
    return out;
  }

  /* The regions the source of template @p name names, in the order it names them. */
  std::vector<std::string> Regions(const char * name) {
    char ** names = NULL;
    size_t n = 0;
    std::vector<std::string> out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_render_regions(catalog_, name, strlen(name), &names, &n));
    for (size_t i = 0; i < n; i++) {
      out.push_back(names[i]);
    }
    gdefcore_render_names_free(catalog_, names, n);
    return out;
  }

  GDEFCORE_Result PutRaw(const std::string & id, const char * field, const std::string & text,
      const std::string & confirm) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value value;
    const char * slot = text.c_str();
    size_t len = text.size();
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = field;
    value.field_len = strlen(field);
    value.texts = &slot;
    value.text_lens = &len;
    value.count = 1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, &value, 1));
    GDEFCORE_Result rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }
};

TEST_F(Structures, TheSameStructureMakesTheSameBytesAndTheCellsAreTheRegions) {
  char * src1 = NULL;
  char * css1 = NULL;
  char * src2 = NULL;
  char * css2 = NULL;
  size_t s1 = 0, c1 = 0, s2 = 0, c2 = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_structure_generate("grail", 5, kGrail, strlen(kGrail), &src1,
                             &s1, &css1, &c1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_structure_generate("grail", 5, kGrail, strlen(kGrail), &src2,
                             &s2, &css2, &c2));
  EXPECT_EQ(std::string(src1, s1), std::string(src2, s2));
  EXPECT_EQ(std::string(css1, c1), std::string(css2, c2));
  const std::string source(src1, s1);
  const std::string css(css1, c1);
  free(src1);
  free(css1);
  free(src2);
  free(css2);
  /* A known answer: the whole of both. */
  EXPECT_EQ(
      "<% use region; %><div class=\"pg pg-grail\">\n"
      "<div class=\"row-box\"><div class=\"row row-fixed r1\">\n"
      "<div class=\"cell cell-header w12\"><%= region(\"header\") %></div>\n"
      "</div></div>\n"
      "<div class=\"row-box\"><div class=\"row row-stack bp-medium r2\">\n"
      "<div class=\"cell cell-main w8\"><%= region(\"main\") %></div>\n"
      "<div class=\"cell cell-side w4\"><%= region(\"side\") %></div>\n"
      "</div></div>\n"
      "<div class=\"row-box\"><div class=\"row row-fixed r3\">\n"
      "<div class=\"cell cell-footer w12\"><%= region(\"footer\") %></div>\n"
      "</div></div>\n"
      "</div>\n",
      source);
  EXPECT_EQ(
      "/* Generated from the structure of the page template grail. Do not edit it: change the "
      "structure. */\n"
      ".pg-grail .row-box { container-type: inline-size; }\n"
      ".pg-grail .row { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 1rem; }\n"
      ".pg-grail .cell { min-width: 0; }\n"
      ".pg-grail .row-wrap { grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }\n"
      ".pg-grail .row-wrap > .cell { grid-column: auto; }\n"
      ".pg-grail .w4 { grid-column: span 4; }\n"
      ".pg-grail .w8 { grid-column: span 8; }\n"
      ".pg-grail .w12 { grid-column: span 12; }\n"
      "@container (max-width: 720px) {\n"
      "  .pg-grail .row-stack.bp-medium { grid-template-columns: minmax(0, 1fr); }\n"
      "  .pg-grail .row-stack.bp-medium > .cell { grid-column: auto; }\n"
      "  .pg-grail .r2 > .cell-main { order: 1; }\n"
      "  .pg-grail .r2 > .cell-side { order: 2; }\n"
      "}\n",
      css);
  /* A different name is different bytes, and the same name is the same. */
  char * other_src = NULL;
  char * other_css = NULL;
  size_t os = 0, oc = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_structure_generate("home", 4, kGrail, strlen(kGrail), &other_src,
                             &os, &other_css, &oc));
  EXPECT_NE(source, std::string(other_src, os));
  free(other_src);
  free(other_css);
  /* A document that leaves the stacked positions out is the one that writes them. */
  const std::string plain =
      "row fixed\ncell header 12\nrow stack medium\ncell main 8\ncell side 4\nrow fixed\ncell footer 12\n";
  EXPECT_EQ(kGrail, Check(plain));
  EXPECT_EQ(kGrail, Check(kGrail)) << "the canonical form is its own";
  /* The regions found by reading the source are exactly the cells, in order. */
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", kGrail)) << refusal_;
  EXPECT_EQ((std::vector<std::string>{"header", "main", "side", "footer"}), Regions("grail"));
}

TEST_F(Structures, AStructureWritesTheTemplateTheStructureAndTheStylesheetInOneChangeset) {
  EXPECT_EQ("<none>", Read("grail"));
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", kGrail)) << refusal_;
  EXPECT_EQ(kGrail, Read("grail"));
  char * src = NULL;
  char * css = NULL;
  size_t s = 0, c = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_structure_generate("grail", 5, kGrail, strlen(kGrail), &src, &s,
                             &css, &c));
  EXPECT_EQ(std::string(src, s), Body("grail"));
  EXPECT_EQ(std::string(css, c), Css("grail"));
  EXPECT_EQ("core.page", Field(IdOf(kTemplate, "grail"), "kind"));
  free(src);
  free(css);
  /* The stylesheet is a site file like any other to a page that names it. */
  GDEFCORE_Asset a;
  memset(&a, 0, sizeof a);
  a.size = sizeof a;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_asset_find(catalog_, NULL, "site/layout-grail.css", 21, &a));
  EXPECT_EQ(GDEFCORE_ASSET_CSS, a.kind);
  gdefcore_asset_release(&a);
  /* The same structure again changes nothing: the same bytes, and the hash. */
  char * url1 = NULL;
  char * url2 = NULL;
  size_t u1 = 0, u2 = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_asset_url(catalog_, NULL, "site/layout-grail.css", 21, &url1, &u1));
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", kGrail)) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_asset_url(catalog_, NULL, "site/layout-grail.css", 21, &url2, &u2));
  EXPECT_EQ(std::string(url1, u1), std::string(url2, u2));
  gdefcore_text_free(catalog_, url1);
  gdefcore_text_free(catalog_, url2);
  /* A new structure replaces the old whole. */
  const std::string two = "row stack narrow\ncell a 6\ncell b 6 2\n";
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", two)) << refusal_;
  EXPECT_EQ((std::vector<std::string>{"a", "b"}), Regions("grail"));
  EXPECT_NE(std::string::npos, Css("grail").find("(max-width: 480px)"));
  EXPECT_EQ(std::string::npos, Css("grail").find("720px"));
}

TEST_F(Structures, ADocumentThatBreaksARuleIsRefusedAndTheErrorNamesIt) {
  std::string why;
  struct Case {
    std::string doc;
    const char * says;
  };
  std::string rows33;
  for (int i = 0; i < 33; i++) {
    rows33 += "row fixed\ncell r" + std::to_string(i) + " 12\n";
  }
  std::string cells13 = "row stack wide\n";
  for (int i = 0; i < 13; i++) {
    cells13 += "cell c" + std::to_string(i) + " 1\n";
  }
  std::string cells65;
  for (int r = 0; r < 6; r++) {
    cells65 += "row fixed\n";
    for (int i = 0; i < 11; i++) {
      cells65 += "cell r" + std::to_string(r) + "c" + std::to_string(i) + " 1\n";
    }
  }
  const Case cases[] = {
      {"", "1 to 4096"},
      {"row fixed\n", "has a cell"},
      {"cell a 12\n", "a row comes first"},
      {"row fixed\ncell a 7\ncell b 6\n", "more than 12 columns"},
      {"row fixed\ncell a 12\ncell a 1\n", "used once"},
      {"row fixed\ncell a 6\nrow fixed\ncell a 6\n", "used once"},
      {"row fixed\ncell Bad 12\n", "names a region"},
      {"row fixed\ncell a 0\n", "width of 1 to 12"},
      {"row fixed\ncell a 13\n", "width of 1 to 12"},
      {"row fixed\ncell a 012\n", "width of 1 to 12"},
      {"row fixed\ncell a x\n", "width of 1 to 12"},
      {"row stack\ncell a 12\n", "row stack narrow"},
      {"row stack huge\ncell a 12\n", "narrow, medium or wide"},
      {"row stack medium extra\ncell a 12\n", "row stack narrow"},
      {"row wrap medium\ncell a\n", "row stack"},
      {"row flow\ncell a 12\n", "row stack"},
      {"row wrap\ncell a 4\n", "no width"},
      {"row fixed\ncell a 6 1\ncell b 6\n", "never stacks"},
      {"row stack wide\ncell a 6 0\ncell b 6\n", "stacked position"},
      {"row stack wide\ncell a 6 3\ncell b 6\n", "at most the number of cells"},
      {"row stack wide\ncell a 6 1\ncell b 6 1\n", "same position"},
      {"row stack wide\ncell a 6\ncell b 6 1\n", "same position"},
      {"row fixed\ncell a 12\n\n", "not empty"},
      {"row fixed\ncell a 12\r\n", "width of 1 to 12"},
      {"row  fixed\ncell a 12\n", "one space"},
      {"row fixed \ncell a 12\n", "one space"},
      {"row fixed\ncell a 12 1 1\n", "cell <region>"},
      {"column fixed\ncell a 12\n", "'row' or a 'cell'"},
      {rows33, "at most 32 rows"},
      {cells13, "at most 12 cells"},
      {cells65, "at most 12 cells and a structure 64"},
      {std::string(GDEFCORE_STRUCTURE_BYTES_MAX + 1, 'a'), "1 to 4096"},
  };
  for (const Case & c : cases) {
    EXPECT_EQ("", Check(c.doc, &why)) << c.doc;
    EXPECT_NE(std::string::npos, why.find(c.says)) << c.doc << " -> " << why;
  }
  /* CONTROLS: exactly twelve columns, twelve cells, thirty-two rows. */
  EXPECT_NE("", Check("row fixed\ncell a 7\ncell b 5\n"));
  std::string twelve = "row stack wide\n";
  for (int i = 0; i < 12; i++) {
    twelve += "cell c" + std::to_string(i) + " 1\n";
  }
  EXPECT_NE("", Check(twelve));
  std::string rows32;
  for (int i = 0; i < 32; i++) {
    rows32 += "row fixed\ncell r" + std::to_string(i) + " 12\n";
  }
  EXPECT_NE("", Check(rows32));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_structure_check(NULL, 0, NULL, NULL, NULL, 0));
  /* A refused document stages nothing, and a name that is not one is refused. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Stage("grail", "row fixed\ncell a 13\n"));
  EXPECT_EQ("<none>", Read("grail"));
  EXPECT_EQ("<none>", Css("grail"));
  for (const char * bad : {"Grail", "1grail", "gr_ail", "gr.ail", "", "a b"}) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_structure_stage(cs, bad, strlen(bad), kGrail,
                                        strlen(kGrail), 0)) << bad;
    gdefcore_changeset_destroy(cs);
    EXPECT_FALSE(gdefcore_structure_name_ok(bad, strlen(bad))) << bad;
  }
  EXPECT_TRUE(gdefcore_structure_name_ok("a-b-1", 5));
}

TEST_F(Structures, TheStackedPositionIsWhereACellGoesWhenTheRowFolds) {
  const std::string reversed = "row stack medium\ncell main 8 2\ncell side 4 1\n";
  ASSERT_EQ(GDEFCORE_OK, Stage("two", reversed)) << refusal_;
  const std::string css = Css("two");
  EXPECT_NE(std::string::npos, css.find(".pg-two .r1 > .cell-main { order: 2; }"));
  EXPECT_NE(std::string::npos, css.find(".pg-two .r1 > .cell-side { order: 1; }"));
  /* CONTROL: left out, a cell goes where it is. */
  ASSERT_EQ(GDEFCORE_OK, Stage("three", "row stack medium\ncell main 8\ncell side 4\n")) << refusal_;
  EXPECT_NE(std::string::npos, Css("three").find(".pg-three .r1 > .cell-main { order: 1; }"));
  /* A wrap row has no breakpoint and no order, and a fixed row never folds. */
  ASSERT_EQ(GDEFCORE_OK, Stage("cards", "row wrap\ncell a\ncell b\ncell c\n")) << refusal_;
  EXPECT_EQ(std::string::npos, Css("cards").find("@container"));
  EXPECT_EQ(std::string::npos, Css("cards").find("order:"));
  EXPECT_NE(std::string::npos, Body("cards").find("row-wrap"));
}

TEST_F(Structures, ATemplateWhoseSourceIsNotWhatItsStructureMakesIsRefusedUntilItIsCustom) {
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", kGrail)) << refusal_;
  const std::string tid = IdOf(kTemplate, "grail");
  ASSERT_FALSE(tid.empty());
  const std::string body = Body("grail");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRaw(tid, "body", body + "<!-- edited -->", kTemplate));
  EXPECT_NE(std::string::npos, refusal_.find("not what its structure makes")) << refusal_;
  EXPECT_EQ(body, Body("grail"));
  /* The stylesheet is read only the same way: by the port, by the site-file call. */
  const std::string cid = IdOf(kCss, "layout-grail.css");
  ASSERT_FALSE(cid.empty());
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRaw(cid, "text", "body { color: red }", kCss));
  EXPECT_NE(std::string::npos, refusal_.find("stylesheet")) << refusal_;
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_siteasset_stage(cs, "layout-grail.css", 16,
                                      GDEFCORE_ASSET_CSS, "a{}", 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_siteasset_stage_forget(cs, "layout-grail.css", 16));
  gdefcore_changeset_destroy(cs);
  /* A structure that no longer matches the source it came with. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      PutRaw(tid, "structure", "row fixed\ncell only 12\n", kTemplate));
  EXPECT_NE(std::string::npos, refusal_.find("refused")) << refusal_;
  EXPECT_EQ(kGrail, Read("grail"));
  /* Made custom, the source is the person's to write. */
  ASSERT_EQ(GDEFCORE_OK, Custom("grail")) << "refusal: " << refusal_;
  EXPECT_EQ("custom", Read("grail"));
  EXPECT_EQ(GDEFCORE_OK, PutRaw(tid, "body", body + "<!-- edited -->", kTemplate)) << refusal_;
  EXPECT_NE(std::string::npos, Body("grail").find("<!-- edited -->"));
  /* And its stylesheet is a file the site may change. */
  EXPECT_EQ(GDEFCORE_OK, PutRaw(cid, "text", "body { color: red }", kCss)) << refusal_;
  EXPECT_EQ("body { color: red }", Css("grail"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_siteasset_stage(cs, "layout-grail.css", 16,
                             GDEFCORE_ASSET_CSS, "a{}", 3));
  gdefcore_changeset_destroy(cs);
}

TEST_F(Structures, ACustomTemplateIsNeverOverwrittenExceptByAnExplicitNewStructure) {
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Custom("grail")) << "no structure to take over";
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", kGrail)) << refusal_;
  ASSERT_EQ(GDEFCORE_OK, Custom("grail")) << refusal_;
  const std::string tid = IdOf(kTemplate, "grail");
  ASSERT_EQ(GDEFCORE_OK, PutRaw(tid, "body", "<% use region; %><div><%= region(\"main\") %></div>",
                             kTemplate)) << refusal_;
  const std::string mine = Body("grail");
  const std::string two = "row fixed\ncell main 12\n";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Stage("grail", two)) << "not without saying so";
  EXPECT_EQ(mine, Body("grail"));
  EXPECT_EQ("custom", Read("grail"));
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", two, 1)) << refusal_;
  EXPECT_NE(mine, Body("grail"));
  EXPECT_EQ(two, Read("grail"));
  EXPECT_NE("<none>", Css("grail"));
  /* A site's own file of the name a stylesheet would take is not overwritten
   * unless the caller says to. */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_siteasset_stage(cs, "layout-mine.css", 15, GDEFCORE_ASSET_CSS,
                             "mine{}", 6));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kCss, strlen(kCss)));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Stage("mine", two));
  EXPECT_EQ("mine{}", Css("mine"));
  EXPECT_EQ(GDEFCORE_OK, Stage("mine", two, 1)) << refusal_;
  EXPECT_NE("mine{}", Css("mine"));
}

TEST_F(Structures, ASiteFileSaysWhichTemplateGeneratedIt) {
  char owner[GDEFCORE_ASSET_NAME_MAX + 1];
  EXPECT_EQ(0, gdefcore_siteasset_generator(catalog_, "layout-grail.css", 16, owner));
  ASSERT_EQ(GDEFCORE_OK, Stage("grail", kGrail)) << refusal_;
  EXPECT_EQ(1, gdefcore_siteasset_generator(catalog_, "layout-grail.css", 16, owner));
  EXPECT_STREQ("grail", owner);
  EXPECT_EQ(0, gdefcore_siteasset_generator(catalog_, "layout-other.css", 16, owner));
  EXPECT_EQ(0, gdefcore_siteasset_generator(catalog_, "../x", 4, owner));
  EXPECT_EQ(0, gdefcore_siteasset_generator(NULL, "layout-grail.css", 16, owner));
  ASSERT_EQ(GDEFCORE_OK, Custom("grail")) << refusal_;
  EXPECT_EQ(0, gdefcore_siteasset_generator(catalog_, "layout-grail.css", 16, owner))
      << "a custom template's stylesheet is the site's";
}

TEST_F(Structures, OnlyAPageTemplateTakesAStructure) {
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  /* The kit's own pane template is not a page. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_structure_stage(cs, "entity", 6, kGrail, strlen(kGrail), 1));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("<none>", Css("entity"));
  /* The kit's page template has none until it is given one. */
  EXPECT_EQ("", Read("layout"));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
