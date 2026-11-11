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
 * The site's own stylesheets and scripts: found under the owner `site` like a
 * module's file, with the hash of the stored text so that an edit changes the
 * address at once; written only by changeset; two permissions that are not each
 * other's; a name that is a file name and is used once.
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

const char kCss[] = GDEFCORE_ASSET_CSS_TYPE;
const char kJs[] = GDEFCORE_ASSET_JS_TYPE;

}  // namespace

class SiteAssets : public GrantsFixture {
 protected:
  std::string refusal_;
  std::string css_, js_, both_, nobody_;

  void SetUp() override {
    GrantsFixture::SetUp();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    Role("stylists");
    Grant("stylists", GDEFCORE_ASSET_CSS_EDIT_LABEL);
    Role("scripters");
    Grant("scripters", GDEFCORE_ASSET_JS_EDIT_LABEL);
    Role("webmasters");
    Grant("webmasters", GDEFCORE_ASSET_CSS_EDIT_LABEL);
    Grant("webmasters", GDEFCORE_ASSET_JS_EDIT_LABEL);
    css_ = Principal("stylists");
    js_ = Principal("scripters");
    both_ = Principal("webmasters");
    nobody_ = Principal();
  }

  /* The confirmation a changeset that writes a file of this type is applied with. */
  static std::string Confirm(int kind) {
    return kind == GDEFCORE_ASSET_CSS ? kCss : kJs;
  }

  void Remember(GDEFCORE_Changeset * cs) {
    size_t n = 0;
    const char * why = gdefcore_changeset_refusal(cs, &n);
    refusal_ = why == NULL ? "" : std::string(why, n);
  }

  /* Stage and apply one file; the result of the stage, or of the apply. */
  GDEFCORE_Result Put(const std::string & name, int kind, const std::string & text,
      GDEFCORE_Request * request = NULL) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_siteasset_stage(cs, name.data(), name.size(), kind,
        text.data(), text.size());
    if (rc == GDEFCORE_OK) {
      std::string confirm = Confirm(kind);
      rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Forget(const std::string & name, int kind,
      GDEFCORE_Request * request = NULL) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    GDEFCORE_Result rc = gdefcore_siteasset_stage_forget(cs, name.data(), name.size());
    if (rc == GDEFCORE_OK) {
      std::string confirm = Confirm(kind);
      rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    }
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* A file as the entity port is given it with no staging call in between, to
   * reach the vet that stands behind it. */
  GDEFCORE_Result PutRaw(const std::string & type, const std::string & name,
      const std::string & text, GDEFCORE_Request * request = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[2];
    const char * slots[2] = {name.c_str(), text.c_str()};
    size_t lens[2] = {name.size(), text.size()};
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, type.c_str(), type.size(), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    if (request != NULL) {
      gdefcore_changeset_set_request(cs, request);
    }
    for (int i = 0; i < 2; i++) {
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = i == 0 ? "name" : "text";
      values[i].field_len = 4;
      values[i].texts = &slots[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, strlen(id), "en", 2, values, 2));
    GDEFCORE_Result rc = gdefcore_changeset_apply(cs, type.data(), type.size());
    Remember(cs);
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* The file as a lookup gives it: "kind|media|hash|text", "" when there is none. */
  std::string Found(const std::string & ref,
      const GDEFCORE_Changeset * projection = NULL) {
    GDEFCORE_Asset a;
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    if (gdefcore_asset_find(catalog_, projection, ref.data(), ref.size(), &a) !=
        GDEFCORE_OK) {
      return std::string();
    }
    std::string out = std::to_string(a.kind) + "|" +
        std::string(a.media_type, a.media_type_len) + "|" + a.hash + "|" +
        std::string((const char *)a.bytes, a.bytes_len) + "|" +
        std::string(a.module, a.module_len) + "/" + std::string(a.name, a.name_len);
    gdefcore_asset_release(&a);
    return out;
  }

  std::string Url(const std::string & ref) {
    char * url = NULL;
    size_t n = 0;
    if (gdefcore_asset_url(catalog_, NULL, ref.data(), ref.size(), &url, &n) !=
        GDEFCORE_OK) {
      return std::string();
    }
    std::string out(url, n);
    gdefcore_text_free(catalog_, url);
    return out;
  }

  GDEFCORE_Request * As(const std::string & who) { return Req(who); }
};

TEST_F(SiteAssets, AFileTheSiteWritesIsFoundUnderTheOwnerSiteWithTheHashOfItsText) {
  EXPECT_EQ("", Found("site/site.css")) << "CONTROL: nothing yet";
  ASSERT_EQ(GDEFCORE_OK, Put("site.css", GDEFCORE_ASSET_CSS, "abc")) << refusal_;
  /* The hash is the first 128 bits of the SHA-256 of the text: a known answer. */
  EXPECT_EQ("1|text/css; charset=utf-8|ba7816bf8f01cfea414140de5dae2223|abc|site/site.css",
      Found("site/site.css"));
  ASSERT_EQ(GDEFCORE_OK, Put("app.js", GDEFCORE_ASSET_JS, "x()")) << refusal_;
  std::string js = Found("site/app.js");
  EXPECT_EQ(0u, js.find("2|text/javascript; charset=utf-8|")) << js;
  EXPECT_EQ("/assets/site/site.css?v=ba7816bf8f01cfea414140de5dae2223",
      Url("site/site.css"));
  /* A name that is not the site's is not found, whatever it is spelled like. */
  EXPECT_EQ("", Found("site/nope.css"));
  EXPECT_EQ("", Found("sit/site.css"));
  EXPECT_EQ("", Found("site/SITE.CSS"));
  EXPECT_EQ("", Found("other/site.css"));
}

TEST_F(SiteAssets, AnEditChangesTheAddressAtOnceAndARemovalEndsIt) {
  ASSERT_EQ(GDEFCORE_OK, Put("site.css", GDEFCORE_ASSET_CSS, "body{color:red}"));
  const std::string before = Url("site/site.css");
  ASSERT_FALSE(before.empty());
  ASSERT_EQ(GDEFCORE_OK, Put("site.css", GDEFCORE_ASSET_CSS, "body{color:blue}"));
  const std::string after = Url("site/site.css");
  EXPECT_NE(before, after);
  EXPECT_NE(std::string::npos, Found("site/site.css").find("body{color:blue}"));
  /* CONTROL: the same text again is the same address. */
  ASSERT_EQ(GDEFCORE_OK, Put("site.css", GDEFCORE_ASSET_CSS, "body{color:blue}"));
  EXPECT_EQ(after, Url("site/site.css"));
  ASSERT_EQ(GDEFCORE_OK, Forget("site.css", GDEFCORE_ASSET_CSS)) << refusal_;
  EXPECT_EQ("", Found("site/site.css"));
  EXPECT_EQ("", Url("site/site.css"));
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_siteasset_stage_forget(cs, "site.css", 8));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_siteasset_stage_forget(cs, "../x", 4));
  gdefcore_changeset_destroy(cs);
}

TEST_F(SiteAssets, AStagedFileIsSeenThroughItsChangesetAndNotWithout) {
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_siteasset_stage(cs, "new.css", 7, GDEFCORE_ASSET_CSS, "a{}", 3));
  EXPECT_NE("", Found("site/new.css", cs)) << "through the changeset";
  EXPECT_EQ("", Found("site/new.css")) << "CONTROL: not yet written";
  /* A second stage of the same name in the same changeset replaces the first. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_siteasset_stage(cs, "new.css", 7, GDEFCORE_ASSET_CSS, "b{}", 3));
  EXPECT_NE(std::string::npos, Found("site/new.css", cs).find("|b{}|"));
  /* And the name is taken, as the other kind. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "new.css", 7, GDEFCORE_ASSET_JS, "x", 1));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("", Found("site/new.css"));
}

TEST_F(SiteAssets, AFileThatBreaksARuleIsRefusedAtStageAndAtApply) {
  const std::string long_name(GDEFCORE_ASSET_NAME_MAX + 1, 'a');
  const char * bad_names[] = {"", "A.css", "-a.css", ".a.css", "a..css", "a/b.css",
      "a b.css", "a\\b.css", "a%2eb.css", "../a.css", "é.css", "a\x01.css"};
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  for (const char * name : bad_names) {
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_siteasset_stage(cs, name, strlen(name), GDEFCORE_ASSET_CSS, "a{}", 3))
        << name;
  }
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_siteasset_stage(cs, long_name.data(),
                                      long_name.size(), GDEFCORE_ASSET_CSS, "a", 1));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_siteasset_stage(cs, "ok-1_a.b.css", 12,
                             GDEFCORE_ASSET_CSS, "a{}", 3)) << "CONTROL";
  /* A kind that is neither, an empty text, a NUL, bytes that are not UTF-8, a
   * control character, and a text over the limit. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "k.css", 5, 0, "a{}", 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "k.css", 5, GDEFCORE_ASSET_IMAGE, "a{}", 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "k.css", 5, GDEFCORE_ASSET_FONT, "a{}", 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "k.css", 5, GDEFCORE_ASSET_CSS, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "k.css", 5, GDEFCORE_ASSET_CSS, "a\0b", 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "k.css", 5, GDEFCORE_ASSET_CSS, "a\xff{}", 4));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(cs, "k.css", 5, GDEFCORE_ASSET_CSS, "a\x07" "{}", 4));
  const std::string big(GDEFCORE_ASSET_BYTES_MAX + 1, 'a');
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_siteasset_stage(cs, "k.css", 5,
                                      GDEFCORE_ASSET_CSS, big.data(), big.size()));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_siteasset_stage(NULL, "k.css", 5, GDEFCORE_ASSET_CSS, "a", 1));
  gdefcore_changeset_destroy(cs);
  /* A form posts its line ends as CRLF; a tab is text, and non-ASCII UTF-8. */
  EXPECT_EQ(GDEFCORE_OK, Put("crlf.css", GDEFCORE_ASSET_CSS, "a {\r\n\tcolor: red;\r\n}\r\n")) << refusal_;
  EXPECT_EQ(GDEFCORE_OK, Put("utf.css", GDEFCORE_ASSET_CSS, "a::after{content:\"é\"}")) << refusal_;
  /* The vet stands behind the staging: a file the port is given directly is
   * refused with a sentence that names it, and nothing is written. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRaw(kCss, "BAD NAME", "a{}"));
  EXPECT_NE(std::string::npos, refusal_.find("'BAD NAME'")) << refusal_;
  EXPECT_NE(std::string::npos, refusal_.find("name")) << refusal_;
  /* (The port itself refuses bytes that are not UTF-8, before any vet.) */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRaw(kJs, "x.js", std::string("a\x07", 2) + "b"));
  EXPECT_NE(std::string::npos, refusal_.find("UTF-8 text")) << refusal_;
  EXPECT_EQ("", Found("site/BAD NAME"));
  EXPECT_EQ("", Found("site/x.js"));
}

TEST_F(SiteAssets, TheNameRuleIsTheOneAModulesFileHas) {
  EXPECT_TRUE(gdefcore_siteasset_name_ok("site.css", 8));
  EXPECT_TRUE(gdefcore_siteasset_name_ok("0-a_b.c", 7));
  EXPECT_FALSE(gdefcore_siteasset_name_ok("", 0));
  EXPECT_FALSE(gdefcore_siteasset_name_ok(NULL, 3));
  EXPECT_FALSE(gdefcore_siteasset_name_ok("A.css", 5));
  EXPECT_FALSE(gdefcore_siteasset_name_ok("a/b", 3));
  EXPECT_FALSE(gdefcore_siteasset_name_ok("a..b", 4));
  EXPECT_FALSE(gdefcore_siteasset_name_ok("-a", 2));
  EXPECT_FALSE(gdefcore_siteasset_name_ok("a\0b", 3));
}

TEST_F(SiteAssets, ANameIsUsedOnceAcrossBothKindsAndEverywhereAnEntityCanComeFrom) {
  ASSERT_EQ(GDEFCORE_OK, Put("one.txt", GDEFCORE_ASSET_CSS, "a{}"));
  /* The staging call refuses the other kind; so does the vet when the entity is
   * handed to the port by another road. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Put("one.txt", GDEFCORE_ASSET_JS, "x"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRaw(kJs, "one.txt", "x"));
  EXPECT_NE(std::string::npos, refusal_.find("already has a file")) << refusal_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, PutRaw(kCss, "one.txt", "b{}"));
  EXPECT_NE(std::string::npos, refusal_.find("already has a file")) << refusal_;
  EXPECT_NE(std::string::npos, Found("site/one.txt").find("|a{}|")) << "unchanged";
  /* Freeing the name frees it for the other kind. */
  ASSERT_EQ(GDEFCORE_OK, Forget("one.txt", GDEFCORE_ASSET_CSS));
  EXPECT_EQ(GDEFCORE_OK, Put("one.txt", GDEFCORE_ASSET_JS, "x")) << refusal_;
  EXPECT_EQ(0u, Found("site/one.txt").find("2|"));
}

TEST_F(SiteAssets, TheTwoKindsHaveTwoPermissionsAndNeitherIsTheOthersOrLayoutEdit) {
  GDEFCORE_Request * css = As(css_);
  GDEFCORE_Request * js = As(js_);
  GDEFCORE_Request * both = As(both_);
  GDEFCORE_Request * none = As(nobody_);
  EXPECT_TRUE(gdefcore_siteasset_may_edit(catalog_, css, GDEFCORE_ASSET_CSS));
  EXPECT_FALSE(gdefcore_siteasset_may_edit(catalog_, css, GDEFCORE_ASSET_JS));
  EXPECT_TRUE(gdefcore_siteasset_may_edit(catalog_, js, GDEFCORE_ASSET_JS));
  EXPECT_FALSE(gdefcore_siteasset_may_edit(catalog_, js, GDEFCORE_ASSET_CSS));
  EXPECT_TRUE(gdefcore_siteasset_may_edit(catalog_, both, GDEFCORE_ASSET_CSS));
  EXPECT_TRUE(gdefcore_siteasset_may_edit(catalog_, both, GDEFCORE_ASSET_JS));
  EXPECT_FALSE(gdefcore_siteasset_may_edit(catalog_, none, GDEFCORE_ASSET_CSS));
  EXPECT_FALSE(gdefcore_siteasset_may_edit(catalog_, none, GDEFCORE_ASSET_JS));
  EXPECT_FALSE(gdefcore_siteasset_may_edit(catalog_, both, 0));
  EXPECT_FALSE(gdefcore_siteasset_may_edit(catalog_, both, GDEFCORE_ASSET_IMAGE));
  EXPECT_FALSE(gdefcore_siteasset_may_edit(NULL, both, GDEFCORE_ASSET_CSS));
  /* The permission is asked at apply, for each file, with the one sentence. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Put("a.css", GDEFCORE_ASSET_CSS, "a{}", none));
  EXPECT_NE(std::string::npos, refusal_.find("That edit is not allowed.")) << refusal_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Put("a.css", GDEFCORE_ASSET_CSS, "a{}", js));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Put("a.js", GDEFCORE_ASSET_JS, "x", css));
  EXPECT_EQ("", Found("site/a.css"));
  EXPECT_EQ("", Found("site/a.js"));
  EXPECT_EQ(GDEFCORE_OK, Put("a.css", GDEFCORE_ASSET_CSS, "a{}", css)) << refusal_;
  EXPECT_EQ(GDEFCORE_OK, Put("a.js", GDEFCORE_ASSET_JS, "x", js)) << refusal_;
  /* The one who may write a stylesheet may not edit or remove a script. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Put("a.js", GDEFCORE_ASSET_JS, "y", css));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Forget("a.js", GDEFCORE_ASSET_JS, css));
  EXPECT_NE(std::string::npos, Found("site/a.js").find("|x|"));
  EXPECT_EQ(GDEFCORE_OK, Forget("a.js", GDEFCORE_ASSET_JS, js)) << refusal_;
  /* A changeset with a stylesheet and a script needs both. */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  gdefcore_changeset_set_request(cs, css);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_siteasset_stage(cs, "m.css", 5, GDEFCORE_ASSET_CSS, "a{}", 3));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_siteasset_stage(cs, "m.js", 4, GDEFCORE_ASSET_JS, "x", 1));
  std::string confirm = std::string(kCss) + "\n" + kJs;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_apply(cs, confirm.data(), confirm.size()));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("", Found("site/m.css"));
}

TEST_F(SiteAssets, AFileIsWrittenOnlyWithTheTypedConfirmationOfItsType) {
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_siteasset_stage(cs, "c.css", 5, GDEFCORE_ASSET_CSS, "a{}", 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, NULL, 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, "", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, kJs, strlen(kJs)));
  EXPECT_EQ("", Found("site/c.css"));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kCss, strlen(kCss)));
  gdefcore_changeset_destroy(cs);
  EXPECT_NE("", Found("site/c.css"));
}

TEST_F(SiteAssets, AModuleCannotBeCalledSiteAndShipFilesTheSiteWouldThenShadow) {
  ModDef * m = NewMod("site");
  m->Asset("style.css", GDEFCORE_ASSET_CSS, "a{}");
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  EXPECT_NE(GDEFCORE_OK, Enable("site", {}));
  EXPECT_NE(std::string::npos, last_error_.find("'site'")) << last_error_;
}

TEST_F(SiteAssets, ATemplateMayNameASiteFileOnlyWhileTheSiteHasIt) {
  auto issues = [&](const GDEFCORE_Changeset * projection) {
    const std::string body =
        "<% use region; use asset; %><link href=\"<%= asset(\"site/x.css\") %>\">"
        "<%= region(\"main\") %>";
    GDEFCORE_Template_Report * rep = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_template_validate(catalog_, projection, "core.page",
                               9, body.data(), body.size(), &rep));
    size_t n = 0;
    const char * t = gdefcore_template_report_text(rep, &n);
    std::string text = t == NULL ? "" : std::string(t, n);
    gdefcore_template_report_free(rep);
    return text;
  };
  EXPECT_NE(std::string::npos, issues(NULL).find("site/x.css")) << "no such file yet";
  /* The file a changeset stages is the file a template saved in that changeset
   * may name. */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_siteasset_stage(cs, "x.css", 5, GDEFCORE_ASSET_CSS, "a{}", 3));
  EXPECT_EQ("", issues(cs));
  EXPECT_NE(std::string::npos, issues(NULL).find("site/x.css")) << "CONTROL: not applied";
  gdefcore_changeset_destroy(cs);
  ASSERT_EQ(GDEFCORE_OK, Put("x.css", GDEFCORE_ASSET_CSS, "a{}"));
  EXPECT_EQ("", issues(NULL));
  ASSERT_EQ(GDEFCORE_OK, Forget("x.css", GDEFCORE_ASSET_CSS));
  EXPECT_NE(std::string::npos, issues(NULL).find("site/x.css")) << "removed again";
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
