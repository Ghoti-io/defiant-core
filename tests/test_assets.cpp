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
 * Files a module ships (site admin story 18): stylesheets, scripts, images and
 * fonts compiled into the module and declared in its manifest. They exist for a
 * tenant only while the module is enabled, are named by their owner, carry a
 * content hash, and are refused at install when a rule is broken.
 *
 * Every refusal case has its CONTROL in the same test: a manifest that
 * differs only in the thing under test and is accepted, so a refusal is a
 * refusal and not a manifest that was broken anyway.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "grants_fixture.h"
#include "size_structs.h"

using namespace gfx;

class Assets : public GrantsFixture {
 protected:
  /* A world of its own, for a case that wants nothing left from the last. */
  void Fresh() {
    Close();
    Defs().clear();
    Open();
  }

  /* Every asset the tenant has, as "module/name:kind:media:hash". */
  std::vector<std::string> Listed() {
    const GDEFCORE_Module_Declared_Asset ** items = NULL;
    size_t n = 0;
    std::vector<std::string> out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_module_assets(host_, (const uint8_t *)kTenant, 1, NULL, &items, &n));
    for (size_t i = 0; i < n; i++) {
      out.push_back(std::string(items[i]->module, items[i]->module_len) + "/" +
          std::string(items[i]->name, items[i]->name_len) + ":" +
          std::to_string(items[i]->kind) + ":" +
          std::string(items[i]->media_type, items[i]->media_type_len) + ":" +
          items[i]->hash);
    }
    gdefcore_module_declared_free(host_, items);
    return out;
  }

  /* Install a module with one asset and return what the host said, empty when
   * it was accepted. */
  std::string Refusal(const std::string & file, int kind,
      const std::string & bytes, const std::string & media = std::string()) {
    ModDef * m = NewMod("shp");
    m->Asset(file, kind, bytes, media);
    GDEFCORE_Result rc = Install(m);
    if (rc == GDEFCORE_OK) {
      rc = Enable("shp", {});
      if (rc == GDEFCORE_OK) {
        return "";
      }
      return last_error_.empty() ? "refused" : last_error_;
    }
    const char * err = gdefcore_module_error(host_, NULL);
    return err == NULL ? "refused" : err;
  }
};

/* The SHA-256 of "abc" begins ba7816bf 8f01cfea 414140de 5dae2223; the hash is
 * those sixteen bytes in hexadecimal. A known answer, so the digest and the
 * truncation are both checked. */
TEST_F(Assets, AShippedFileIsListedWithItsTypeAndAContentHashWhileItsModuleIsEnabled) {
  ModDef * m = NewMod("shp");
  m->Asset("site.css", GDEFCORE_ASSET_CSS, "abc");
  m->Asset("app.js", GDEFCORE_ASSET_JS, "var x = 1;\n");
  m->Asset("logo.svg", GDEFCORE_ASSET_IMAGE, "<svg/>", "image/svg+xml");
  m->Asset("face.woff2", GDEFCORE_ASSET_FONT, "wOF2", "font/woff2");
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  EXPECT_TRUE(Listed().empty()) << "installed is not enabled";
  ASSERT_EQ(GDEFCORE_OK, Enable("shp", {})) << last_error_;
  std::vector<std::string> got = Listed();
  ASSERT_EQ(4u, got.size());
  /* By name within the module. */
  EXPECT_EQ(0u, got[0].find("shp/app.js:2:text/javascript; charset=utf-8:"));
  EXPECT_EQ(0u, got[1].find("shp/face.woff2:4:font/woff2:"));
  EXPECT_EQ(0u, got[2].find("shp/logo.svg:3:image/svg+xml:"));
  EXPECT_EQ("shp/site.css:1:text/css; charset=utf-8:ba7816bf8f01cfea414140de5dae2223",
      got[3]);
  EXPECT_EQ(GDEFCORE_OK, Disable("shp"));
  EXPECT_TRUE(Listed().empty()) << "a disabled module ships nothing";
  ASSERT_EQ(GDEFCORE_OK, Enable("shp", {})) << last_error_;
  EXPECT_EQ(got, Listed()) << "and it is back, unchanged, on enable";
}

TEST_F(Assets, TwoModulesMayShipTheSameFileNameAndNeitherIsTheOther) {
  ModDef * a = NewMod("aaa");
  a->Asset("logo.svg", GDEFCORE_ASSET_IMAGE, "<svg id='a'/>", "image/svg+xml");
  ASSERT_EQ(GDEFCORE_OK, Install(a));
  ModDef * b = NewMod("bbb");
  b->Asset("logo.svg", GDEFCORE_ASSET_IMAGE, "<svg id='b'/>", "image/svg+xml");
  ASSERT_EQ(GDEFCORE_OK, Install(b));
  ASSERT_EQ(GDEFCORE_OK, Enable("aaa", {})) << last_error_;
  ASSERT_EQ(GDEFCORE_OK, Enable("bbb", {})) << last_error_;
  std::vector<std::string> got = Listed();
  ASSERT_EQ(2u, got.size());
  EXPECT_EQ(0u, got[0].find("aaa/logo.svg:"));
  EXPECT_EQ(0u, got[1].find("bbb/logo.svg:"));
  EXPECT_NE(got[0].substr(got[0].rfind(':')), got[1].substr(got[1].rfind(':')))
      << "different bytes, different hash";
  EXPECT_EQ(GDEFCORE_OK, Disable("aaa"));
  got = Listed();
  ASSERT_EQ(1u, got.size());
  EXPECT_EQ(0u, got[0].find("bbb/logo.svg:")) << "only the enabled module's";
}

TEST_F(Assets, TheSameBytesGiveTheSameHashInAnyModule) {
  ModDef * a = NewMod("aaa");
  a->Asset("one.css", GDEFCORE_ASSET_CSS, "p { margin: 0 }");
  ASSERT_EQ(GDEFCORE_OK, Install(a));
  ModDef * b = NewMod("bbb");
  b->Asset("two.css", GDEFCORE_ASSET_CSS, "p { margin: 0 }");
  b->Asset("three.css", GDEFCORE_ASSET_CSS, "p { margin: 1px }");
  ASSERT_EQ(GDEFCORE_OK, Install(b));
  ASSERT_EQ(GDEFCORE_OK, Enable("aaa", {}));
  ASSERT_EQ(GDEFCORE_OK, Enable("bbb", {}));
  std::vector<std::string> got = Listed();
  ASSERT_EQ(3u, got.size());
  auto hash = [](const std::string & s) { return s.substr(s.rfind(':') + 1); };
  EXPECT_EQ(hash(got[0]), hash(got[2])) << "aaa/one.css and bbb/two.css";
  EXPECT_NE(hash(got[0]), hash(got[1]));
}

TEST_F(Assets, AnAssetThatBreaksARuleIsRefusedAndTheErrorNamesIt) {
  struct Case {
    const char * why;
    std::string file;
    int kind;
    std::string bytes;
    std::string media;
    const char * words;
  };
  const std::vector<Case> cases = {
      {"a path in the name", "../x.css", GDEFCORE_ASSET_CSS, "a", "", "'../x.css'"},
      {"a slash in the name", "a/b.css", GDEFCORE_ASSET_CSS, "a", "", "'a/b.css'"},
      {"two dots", "a..b.css", GDEFCORE_ASSET_CSS, "a", "", "'a..b.css'"},
      {"upper case", "Site.css", GDEFCORE_ASSET_CSS, "a", "", "'Site.css'"},
      {"a leading dot", ".hidden.css", GDEFCORE_ASSET_CSS, "a", "", "'.hidden.css'"},
      {"a space", "my file.css", GDEFCORE_ASSET_CSS, "a", "", "name that is not"},
      {"an empty name", "", GDEFCORE_ASSET_CSS, "a", "", "name that is not"},
      {"a name past the limit", std::string(129, 'a') + ".css",
          GDEFCORE_ASSET_CSS, "a", "", "name that is not"},
      {"a media type on a stylesheet", "s.css", GDEFCORE_ASSET_CSS, "a",
          "text/css", "takes from its kind"},
      {"a media type on a script", "s.js", GDEFCORE_ASSET_JS, "a",
          "text/javascript", "takes from its kind"},
      {"a stylesheet that is not text", "s.css", GDEFCORE_ASSET_CSS,
          std::string("a\xff\xfe"), "", "not UTF-8 text"},
      {"a script with a NUL", "s.js", GDEFCORE_ASSET_JS, std::string("a\0b", 3),
          "", "not UTF-8 text"},
      {"an image with no type", "i.png", GDEFCORE_ASSET_IMAGE, "x", "",
          "image and names a media type outside"},
      {"an image of a type that is not listed", "i.html", GDEFCORE_ASSET_IMAGE,
          "x", "text/html", "image and names a media type outside"},
      {"an image of a script's type", "i.js", GDEFCORE_ASSET_IMAGE, "x",
          "text/javascript", "image and names a media type outside"},
      {"a font of an image type", "f.woff2", GDEFCORE_ASSET_FONT, "x",
          "image/png", "font and names a media type outside"},
      {"a kind that does not exist", "x.bin", 9, "x", "", "a kind that is not"},
      {"a kind of zero", "x.bin", 0, "x", "", "a kind that is not"},
  };
  for (const Case & c : cases) {
    Fresh();
    std::string said = Refusal(c.file, c.kind, c.bytes, c.media);
    EXPECT_NE("", said) << c.why << " was accepted";
    EXPECT_NE(std::string::npos, said.find(c.words)) << c.why << ": " << said;
    EXPECT_NE(std::string::npos, said.find("shp")) << c.why << ": " << said;
    EXPECT_TRUE(Listed().empty()) << c.why << " left an asset listed";
  }
}

TEST_F(Assets, EmptyOversizeAndRepeatedAssetsAreRefused) {
  EXPECT_NE("", Refusal("a.css", GDEFCORE_ASSET_CSS, "")) << "no bytes";
  Fresh();
  EXPECT_NE("", Refusal("a.png", GDEFCORE_ASSET_IMAGE,
      std::string(GDEFCORE_ASSET_BYTES_MAX + 1, 'x'), "image/png"))
      << "one byte past the limit";
  Fresh();
  EXPECT_EQ("", Refusal("a.png", GDEFCORE_ASSET_IMAGE,
      std::string(GDEFCORE_ASSET_BYTES_MAX, 'x'), "image/png"))
      << "exactly the limit";
  Fresh();
  ModDef * m = NewMod("shp");
  m->Asset("a.css", GDEFCORE_ASSET_CSS, "1");
  m->Asset("a.css", GDEFCORE_ASSET_CSS, "2");
  GDEFCORE_Result rc = Install(m);
  const char * err = gdefcore_module_error(host_, NULL);
  if (rc == GDEFCORE_OK) {
    rc = Enable("shp", {});
    err = last_error_.c_str();
  }
  EXPECT_NE(GDEFCORE_OK, rc) << "a name twice";
  EXPECT_NE(nullptr, err);
  EXPECT_NE(std::string::npos, std::string(err ? err : "").find("twice"));
  Fresh();
  m = NewMod("shp");
  for (int i = 0; i <= GDEFCORE_MODULE_ASSETS_MAX; i++) {
    m->Asset("f" + std::to_string(i) + ".css", GDEFCORE_ASSET_CSS, "x");
  }
  EXPECT_NE(GDEFCORE_OK, Install(m)) << "one past the most a manifest declares";
  Fresh();
  m = NewMod("shp");
  for (int i = 0; i < GDEFCORE_MODULE_ASSETS_MAX; i++) {
    m->Asset("f" + std::to_string(i) + ".css", GDEFCORE_ASSET_CSS, "x");
  }
  EXPECT_EQ(GDEFCORE_OK, Install(m)) << "the most a manifest declares";
}

TEST_F(Assets, AReferenceFindsOnlyAFileOfThatOwnerAndNothingMalformedFindsAnything) {
  ModDef * a = NewMod("aaa");
  a->Asset("logo.svg", GDEFCORE_ASSET_IMAGE, "<svg id='a'/>", "image/svg+xml");
  ASSERT_EQ(GDEFCORE_OK, Install(a));
  ModDef * b = NewMod("bbb");
  b->Asset("logo.svg", GDEFCORE_ASSET_IMAGE, "<svg id='b'/>", "image/svg+xml");
  ASSERT_EQ(GDEFCORE_OK, Install(b));
  ASSERT_EQ(GDEFCORE_OK, Enable("aaa", {}));
  auto find = [this](const std::string & ref, GDEFCORE_Asset * out) {
    memset(out, 0, sizeof *out);
    out->size = sizeof *out;
    return gdefcore_asset_find(catalog_, NULL, ref.data(), ref.size(), out);
  };
  GDEFCORE_Asset got;
  ASSERT_EQ(GDEFCORE_OK, find("aaa/logo.svg", &got)) << "CONTROL";
  EXPECT_EQ("<svg id='a'/>", std::string((const char *)got.bytes, got.bytes_len));
  EXPECT_EQ(GDEFCORE_ASSET_IMAGE, got.kind);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("bbb/logo.svg", &got)) << "installed, not enabled";
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("logo.svg", &got));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("/logo.svg", &got));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("aaa/", &got));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("aaa/logo.svg/", &got));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("aaa//logo.svg", &got));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("aaa/../aaa/logo.svg", &got));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("aa/logo.svg", &got));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, find("", &got));
  got.size = sizeof got + 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_asset_find(catalog_, NULL, "aaa/logo.svg", 12, &got))
      << "any size but its own";
  char * url = NULL;
  size_t url_len = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_asset_url(catalog_, NULL, "aaa/logo.svg", 12, &url, &url_len));
  EXPECT_EQ("/assets/aaa/logo.svg?v=", std::string(url, 23));
  EXPECT_EQ(23u + GDEFCORE_ASSET_HASH_LEN, url_len);
  gdefcore_text_free(catalog_, url);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_asset_url(catalog_, NULL, "bbb/logo.svg", 12, &url, &url_len));
  EXPECT_EQ(nullptr, url);
}

TEST_F(Assets, AManifestAndAnEnumerationAreAcceptedAtTheirOwnSizeOnly) {
  auto entry = [this](size_t size) {
    Fresh();
    ModDef * m = NewMod("szm");
    m->Asset("a.css", GDEFCORE_ASSET_CSS, "x");
    m->Finish();
    m->assets[0].size = size;
    return gdefcore_module_install_guest(host_, kEntries[0]) == GDEFCORE_OK;
  };
  auto declared = [this](size_t size) {
    Fresh();
    ModDef * m = NewMod("szd");
    m->Asset("a.css", GDEFCORE_ASSET_CSS, "x");
    EXPECT_EQ(GDEFCORE_OK, Install(m));
    EXPECT_EQ(GDEFCORE_OK, Enable("szd", {}));
    const GDEFCORE_Module_Declared_Asset ** items = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_module_assets(host_, (const uint8_t *)kTenant, 1, NULL, &items, &n));
    bool filled = n == 1 && items[0]->size == size;
    gdefcore_module_declared_free(host_, items);
    return filled;
  };
  auto found = [this](size_t size) {
    Fresh();
    ModDef * m = NewMod("szf");
    m->Asset("a.css", GDEFCORE_ASSET_CSS, "x");
    EXPECT_EQ(GDEFCORE_OK, Install(m));
    EXPECT_EQ(GDEFCORE_OK, Enable("szf", {}));
    GDEFCORE_Asset a;
    memset(&a, 0, sizeof a);
    a.size = size;
    return gdefcore_asset_find(catalog_, NULL, "szf/a.css", 9, &a) == GDEFCORE_OK;
  };
  size_structs::Run("tests/test_assets.cpp",
      {{"GDEFCORE_Module_Asset", entry}, {"GDEFCORE_Asset", found},
          {"GDEFCORE_Module_Declared_Asset", declared}});
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
