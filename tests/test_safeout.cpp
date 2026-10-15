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
 * Render-safe output by default (site-admin story 1). Every value the render
 * layer binds into a template is tagged for the strictest encoding, so a
 * template that never calls a tag method still prints it inert, in element
 * text and in either quote style of an attribute; `url()` refuses script
 * schemes; and the layout's paste of a pane's rendered HTML is the one
 * trusted insertion, so it is neither escaped twice nor opened up.
 *
 * Every assertion that something is NOT present has a control: the same
 * template with `.raw`, which does leak, so a test that cannot see a leak is
 * not passing by accident.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/stream.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>

#include <string>

#include <vector>

namespace {

const uint64_t kLife = 3600;

void OneValue(GDEFCORE_Value * value, const char * field, const char * text,
    const char ** slot, size_t * len_slot) {
  memset(value, 0, sizeof *value);
  *slot = text;
  *len_slot = strlen(text);
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = slot;
  value->text_lens = len_slot;
  value->count = 1;
}

class SafeOut : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Request * request_;
  GDEFCORE_Request * anon_;
  GDEFCORE_Keyring * keyring_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  std::string session_;
  int posts_ = 0;

  void SetUp() override {
    const uint8_t tenant[] = {'t'};
    store_ = NULL;
    catalog_ = NULL;
    request_ = NULL;
    anon_ = NULL;
    keyring_ = NULL;
    memset(root_, 0x42, sizeof root_);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, tenant, 1, NULL, NULL, &catalog_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant, 1, 0, 0, NULL, &request_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant, 1, 0, 0, NULL, &anon_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_create(root_, sizeof root_, NULL, &keyring_));
  }

  void TearDown() override {
    gdefcore_keyring_destroy(keyring_);
    gdefcore_request_destroy(anon_);
    gdefcore_request_destroy(request_);
    gdefcore_catalog_destroy(catalog_);
    gdefstor_store_destroy(store_);
  }

  void Login() {
    char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * token = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
            strlen(admin), "ada", 3, "secret", 6, id));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_login(catalog_, keyring_, root_, sizeof root_, "ada", 3,
            "secret", 6, kLife, &token, &n));
    session_.assign(token, n);
    gdefcore_text_free(catalog_, token);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
            session_.data(), session_.size()));
  }

  void Install() {
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
  }

  void Save(const char * alias, const char * title, const char * body,
      const char * summary, int publish, char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
    GDEFCORE_Value values[3];
    const char * slots[3];
    size_t lens[3];
    size_t count = 0;
    int conflict = 1;
    char * token = NULL;
    size_t token_len = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.post", 9, id, NULL));
    OneValue(&values[count], "title", title, &slots[count], &lens[count]);
    count += 1;
    OneValue(&values[count], "body", body, &slots[count], &lens[count]);
    count += 1;
    if (summary != NULL) {
      OneValue(&values[count], "summary", summary, &slots[count], &lens[count]);
      count += 1;
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
            session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
            values, count, alias, strlen(alias), &token, &token_len));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_submit(catalog_, request_, keyring_, root_, sizeof root_,
            session_.data(), session_.size(), token, token_len, &conflict));
    gdefcore_text_free(catalog_, token);
    EXPECT_EQ(0, conflict);
    if (publish) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_form_publish(catalog_, id, strlen(id)));
    }
  }


  /* A new revision of the named config entity, published. */
  void Revise(const char * type, const char * name, const char * field,
      const char ** texts, size_t count) {
    char ** ids = NULL;
    size_t n = 0;
    char found[GDEFCORE_PUBLIC_ID_LEN + 1];
    bool have = false;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, type, strlen(type), &ids, &n));
    for (size_t i = 0; i < n && !have; i++) {
      char ** vals = NULL;
      size_t * lens = NULL;
      size_t c = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              strlen(ids[i]), "en", 2, "name", 4, &vals, &lens, &c) ==
          GDEFCORE_OK) {
        if (c > 0 && lens[0] == strlen(name) && memcmp(vals[0], name, lens[0]) == 0) {
          memcpy(found, ids[i], strlen(ids[i]) + 1);
          have = true;
        }
        gdefcore_values_free(catalog_, vals, lens, c);
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    ASSERT_TRUE(have) << name;
    GDEFCORE_Value values[2];
    const char * name_slot = name;
    size_t name_len = strlen(name);
    std::vector<size_t> lens(count);
    for (size_t i = 0; i < count; i++) {
      lens[i] = strlen(texts[i]);
    }
    memset(values, 0, sizeof values);
    values[0].size = sizeof values[0];
    values[0].field = "name";
    values[0].field_len = 4;
    values[0].texts = &name_slot;
    values[0].text_lens = &name_len;
    values[0].count = 1;
    values[1].size = sizeof values[1];
    values[1].field = field;
    values[1].field_len = strlen(field);
    values[1].texts = texts;
    values[1].text_lens = lens.data();
    values[1].count = count;
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, found, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 2));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, type, strlen(type)));
    gdefcore_changeset_destroy(cs);
  }

  void SetTemplate(const char * name, const char * body) {
    const char * one[1] = {body};
    Revise("core.template", name, "body", one, 1);
  }

  void SetPanes(const char * display, const char * pane) {
    const char * one[1] = {pane};
    Revise("core.display", display, "panes", one, 1);
  }

  /* One published post with the template "entity" replaced. */
  std::string Post(const char * tmpl, const char * title, const char * body,
      GDEFCORE_Result * rc = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    SetTemplate("entity", tmpl);
    std::string alias = "p" + std::to_string(++posts_);
    Save(alias.c_str(), title, body, NULL, 1, id);
    return Show(anon_, alias.c_str(), rc);
  }

  std::string Show(GDEFCORE_Request * request, const char * path,
      GDEFCORE_Result * rc) {
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Result result = gdefcore_render_page(catalog_, NULL, request, path,
        strlen(path), GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
    std::string page;
    if (rc != NULL) {
      *rc = result;
    }
    if (result == GDEFCORE_OK && bytes != NULL) {
      page.assign(bytes, n);
    }
    gdefcore_text_free(catalog_, bytes);
    return page;
  }
};


const char * const kLead = "<% use title; use body; use url; %>";

std::string Text(const char * expr) {
  return std::string(kLead) + "[<%= " + expr + " %>]";
}

std::string DoubleQuoted(const char * expr) {
  return std::string(kLead) + "<a title=\"<%= " + expr + " %>\">x</a>";
}

std::string SingleQuoted(const char * expr) {
  return std::string(kLead) + "<a title='<%= " + expr + " %>'>x</a>";
}

std::string Href(const char * expr) {
  return std::string(kLead) + "<a href=\"<%= " + expr + " %>\">x</a>";
}

/* The text between the first `open` and the next `close`; "!" when absent. */
std::string Between(const std::string & page, const std::string & open,
    const std::string & close) {
  size_t a = page.find(open);
  if (a == std::string::npos) {
    return "!";
  }
  a += open.size();
  size_t b = page.find(close, a);
  if (b == std::string::npos) {
    return "!";
  }
  return page.substr(a, b - a);
}

/* No markup or quote survives and every ampersand opens an entity. */
bool Inert(const std::string & v) {
  for (size_t i = 0; i < v.size(); i++) {
    char c = v[i];
    if (c == '<' || c == '>' || c == '"' || c == '\'') {
      return false;
    }
    if (c == '&') {
      size_t j = i + 1;
      if (j < v.size() && v[j] == '#') {
        j++;
        if (j < v.size() && (v[j] == 'x' || v[j] == 'X')) {
          j++;
        }
      }
      size_t start = j;
      while (j < v.size() && isalnum((unsigned char)v[j])) {
        j++;
      }
      if (j == start || j >= v.size() || v[j] != ';') {
        return false;
      }
    }
  }
  return true;
}

const char * const kHostile[] = {
    "<script>alert(1)</script>",
    "x\" onmouseover=\"a",
    "x' onmouseover='a",
    "a&b &amp; &#60; &lt;",
    "ctl\t\x01\x1f\x7f end",
    "</a><img src=x onerror=1>",
    "`a` {{b}} <%= 1 %> ${c}",
    "\"'><svg/onload=alert(1)>",
};

TEST_F(SafeOut, ForgottenCall) {
  Install();
  Login();
  /* A template that never calls a tag method still prints the value inert. */
  std::string page = Post(Text("title").c_str(), "<script>x</script>", "b");
  EXPECT_EQ("&lt;script&gt;x&lt;/script&gt;", Between(page, "[", "]"));
  EXPECT_EQ(std::string::npos, page.find("<script"));
  /* Control: the same template with .raw leaks, so the test can see a leak. */
  page = Post(Text("title.raw").c_str(), "<script>x</script>", "b");
  EXPECT_NE(std::string::npos, page.find("[<script>x</script>]"));
}

TEST_F(SafeOut, AttributeDoubleQuoted) {
  Install();
  Login();
  std::string page = Post(DoubleQuoted("title").c_str(), "x\" onmouseover=\"a", "b");
  std::string v = Between(page, "<a title=\"", "\">x</a>");
  EXPECT_NE(std::string::npos, v.find("&quot;"));
  EXPECT_TRUE(Inert(v)) << v;
  EXPECT_NE(std::string::npos, v.find("onmouseover"));
  /* Control: .raw breaks out of the attribute. */
  page = Post(DoubleQuoted("title.raw").c_str(), "x\" onmouseover=\"a", "b");
  EXPECT_NE(std::string::npos, page.find("<a title=\"x\" onmouseover=\"a\">x</a>"));
}

TEST_F(SafeOut, AttributeSingleQuoted) {
  Install();
  Login();
  std::string page = Post(SingleQuoted("title").c_str(), "x' onmouseover='a", "b");
  std::string v = Between(page, "<a title='", "'>x</a>");
  EXPECT_TRUE(Inert(v)) << v;
  EXPECT_NE(std::string::npos, v.find("onmouseover"));
  EXPECT_EQ(std::string::npos, v.find('\''));
  /* Control: the plain .html tag does not escape a quote in an attribute. */
  page = Post(SingleQuoted("title.html").c_str(), "x' onmouseover='a", "b");
  EXPECT_NE(std::string::npos, page.find("<a title='x' onmouseover='a'>x</a>"));
  page = Post(SingleQuoted("title.raw").c_str(), "x' onmouseover='a", "b");
  EXPECT_NE(std::string::npos, page.find("<a title='x' onmouseover='a'>x</a>"));
}

TEST_F(SafeOut, NonAscii) {
  Install();
  Login();
  const char * v = "caf\xc3\xa9 \xe2\x98\x83";
  std::string page = Post(Text("title").c_str(), v, "b");
  EXPECT_EQ(v, Between(page, "[", "]"));
  page = Post(DoubleQuoted("title").c_str(), v, "b");
  EXPECT_EQ(v, Between(page, "<a title=\"", "\">x</a>"));
  page = Post(SingleQuoted("title").c_str(), v, "b");
  EXPECT_EQ(v, Between(page, "<a title='", "'>x</a>"));
}

TEST_F(SafeOut, HostileEverywhere) {
  Install();
  Login();
  for (const char * h : kHostile) {
    SCOPED_TRACE(h);
    std::string page = Post(Text("title").c_str(), h, "b");
    std::string v = Between(page, "[", "]");
    EXPECT_NE("!", v);
    EXPECT_TRUE(Inert(v)) << v;
    page = Post(DoubleQuoted("title").c_str(), h, "b");
    v = Between(page, "<a title=\"", "\">x</a>");
    EXPECT_NE("!", v);
    EXPECT_TRUE(Inert(v)) << v;
    page = Post(SingleQuoted("title").c_str(), h, "b");
    v = Between(page, "<a title='", "'>x</a>");
    EXPECT_NE("!", v);
    EXPECT_TRUE(Inert(v)) << v;
    /* The body binding is tagged the same way. */
    page = Post(Text("body").c_str(), "t", h);
    v = Between(page, "[", "]");
    EXPECT_NE("!", v);
    EXPECT_TRUE(Inert(v)) << v;
  }
  /* Control: the checker sees the leak under .raw for the markup-bearing ones. */
  std::string page = Post(Text("title.raw").c_str(), kHostile[0], "b");
  EXPECT_FALSE(Inert(Between(page, "[", "]")));
  page = Post(DoubleQuoted("title.raw").c_str(), kHostile[1], "b");
  EXPECT_FALSE(Inert(Between(page, "<a title=\"", "\">x</a>")));
  page = Post(SingleQuoted("title.raw").c_str(), kHostile[2], "b");
  EXPECT_FALSE(Inert(Between(page, "<a title='", "'>x</a>")));
}

TEST_F(SafeOut, ExplicitForms) {
  Install();
  Login();
  /* Existing templates keep working: .html, .raw, .javascript are still methods. */
  std::string page = Post(
      (std::string(kLead) + "[<%= title.raw %>][<%= title.html %>]").c_str(),
      "<b>", "x");
  EXPECT_NE(std::string::npos, page.find("[<b>][&lt;b&gt;]")) << page;
  /* A value in a script string needs .javascript; no built-in produces one. */
  const char * hostile = "';alert(1);//</script><b>";
  page = Post((std::string(kLead) +
                  "<script>var t='<%= title.javascript %>';</script>").c_str(),
      hostile, "x");
  EXPECT_NE(std::string::npos, page.find("<script>var t='"));
  EXPECT_NE(std::string::npos, page.find("var t='\\';alert(1);//")) << page;
  EXPECT_EQ(std::string::npos, page.find("</script><b>"));
  page = Post((std::string(kLead) +
                  "<script>var t='<%= title.raw %>';</script>").c_str(),
      hostile, "x");
  EXPECT_NE(std::string::npos, page.find("var t='';alert(1);//"));
}

TEST_F(SafeOut, BuiltinPost) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  /* The post body is escaped text today (it was printed .html); it still is. */
  Save("hostile", "<script>t</script>", "<img src=x onerror=1><script>b</script>",
      NULL, 1, id);
  std::string page = Show(anon_, "hostile", &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("<article class=\"post\"><h1>"));
  EXPECT_NE(std::string::npos, page.find("&lt;script&gt;t&lt;/script&gt;"));
  EXPECT_NE(std::string::npos, page.find("&lt;img src=x onerror=1&gt;"));
  EXPECT_EQ(std::string::npos, page.find("<script"));
  EXPECT_EQ(std::string::npos, page.find("<img"));
  /* Control: the same post through a template that prints .raw leaks. */
  SetTemplate("entity", "<% use title; use body; %><h1><%= title.raw %></h1>");
  page = Show(anon_, "hostile", &rc);
  EXPECT_NE(std::string::npos, page.find("<h1><script>t</script></h1>"));
}

TEST_F(SafeOut, BuiltinRecent) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("one", "<script>t</script>", "body", "<img src=x onerror=1>", 1, id);
  Save("two", "T2", "<script>derived summary</script>", NULL, 1, id);
  std::string page = Show(anon_, "/", &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("<article class=\"recent\"><h2>"));
  EXPECT_NE(std::string::npos, page.find("&lt;script&gt;t&lt;/script&gt;"));
  EXPECT_NE(std::string::npos, page.find("&lt;img src=x onerror=1&gt;"));
  EXPECT_NE(std::string::npos, page.find("&lt;script&gt;derived summary&lt;/script&gt;"));
  EXPECT_EQ(std::string::npos, page.find("<script"));
  EXPECT_EQ(std::string::npos, page.find("<img"));
  /* Control. */
  SetTemplate("recent",
      "<% use title; use summary; %><h2><%= title.raw %></h2><p><%= summary.raw %></p>");
  page = Show(anon_, "/", &rc);
  EXPECT_NE(std::string::npos, page.find("<h2><script>t</script></h2>"));
  EXPECT_NE(std::string::npos, page.find("<p><img src=x onerror=1></p>"));
}

TEST_F(SafeOut, BuiltinField) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("f", "<script>t</script>", "b", NULL, 1, id);
  SetPanes("post", "main field title");
  std::string page = Show(anon_, "f", &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("&lt;script&gt;t&lt;/script&gt;"));
  EXPECT_EQ(std::string::npos, page.find("<script"));
  SetTemplate("field", "<% use value; %><%= value.raw %>");
  page = Show(anon_, "f", &rc);
  EXPECT_NE(std::string::npos, page.find("<script>t</script>"));
}

TEST_F(SafeOut, PathIsNotReflected) {
  GDEFCORE_Result rc = GDEFCORE_OK;
  Install();
  Login();
  std::string page = Show(anon_, "<script>alert(1)</script>", &rc);
  EXPECT_EQ(std::string::npos, page.find("<script"));
  page = Show(anon_, "\"><img src=x onerror=1>", &rc);
  EXPECT_EQ(std::string::npos, page.find("<img"));
}

TEST_F(SafeOut, RegionNotDoubleEscaped) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("amp", "A & B <i>", "x & y", NULL, 1, id);
  std::string page = Show(anon_, "amp", &rc);
  ASSERT_EQ(GDEFCORE_OK, rc);
  /* The pane's markup arrives as markup and its text arrives escaped once. */
  EXPECT_NE(std::string::npos, page.find("<div class=\"main\"><article class=\"post\"><h1>A &amp; B &lt;i&gt;</h1>"));
  EXPECT_EQ(std::string::npos, page.find("&amp;amp;"));
  EXPECT_EQ(std::string::npos, page.find("&amp;lt;"));
  EXPECT_EQ(std::string::npos, page.find("&lt;article"));
  EXPECT_EQ(std::string::npos, page.find("&lt;div"));
  /* The recent-posts pane too, pasted through the same region call. */
  page = Show(anon_, "/", &rc);
  EXPECT_NE(std::string::npos, page.find("<article class=\"recent\"><h2>A &amp; B &lt;i&gt;</h2>"));
  EXPECT_EQ(std::string::npos, page.find("&amp;amp;"));
  EXPECT_EQ(std::string::npos, page.find("&lt;article"));
  /* Control: a layout that escapes the pasted region again is seen. */
  SetTemplate("layout",
      "<% use region; %><div class=\"main\"><%= region(\"main\").html %></div>");
  page = Show(anon_, "amp", &rc);
  EXPECT_NE(std::string::npos, page.find("&lt;article")) << page;
}

struct UrlRow {
  const char * in;
  const char * out;
};

TEST_F(SafeOut, UrlRows) {
  static const UrlRow kRows[] = {
      {"https://a/b", "https://a/b"},
      {"HTTP://A/b", "HTTP://A/b"},
      {"mailto:a@b", "mailto:a@b"},
      {"/x", "/x"},
      {"?q=1", "?q=1"},
      {"#f", "#f"},
      {"../y", "../y"},
      {"./z", "./z"},
      {"x/y:z", "x/y:z"},
      {"caf\xc3\xa9/\xe2\x98\x83", "caf\xc3\xa9/\xe2\x98\x83"},
      {"javascript:alert(1)", "#"},
      {"JAVASCRIPT:x", "#"},
      {" JaVa\tScript:x", "#"},
      {"java\nscript:x", "#"},
      {"\x01javascript:x", "#"},
      {" data:text/html,<b>", "#"},
      {"data:text/html;base64,AA", "#"},
      {"vbscript:x", "#"},
      {"file:///etc/passwd", "#"},
      {"ftp://x/y", "#"},
      {"//host", "#"},
      {"  //host", "#"},
      {"/\\host", "#"},
      {"\\\\host", "#"},
      {"/\t/host", "#"},
  };
  Install();
  Login();
  for (const UrlRow & row : kRows) {
    SCOPED_TRACE(row.in);
    std::string page = Post(Href("url(title)").c_str(), row.in, "b");
    EXPECT_NE(std::string::npos, page.find(std::string("<a href=\"") + row.out + "\">x</a>"));
  }
  /* Control: with .raw the script rows do reach the href, so a "#" above means
   * url() refused it and not that the value never got there. */
  std::string page = Post(Href("title.raw").c_str(), "javascript:alert(1)", "b");
  EXPECT_NE(std::string::npos, page.find("<a href=\"javascript:alert(1)\">x</a>"));
  page = Post(Href("title.raw").c_str(), "//host", "b");
  EXPECT_NE(std::string::npos, page.find("<a href=\"//host\">x</a>"));
}

TEST_F(SafeOut, UrlStaysEscaped) {
  Install();
  Login();
  /* An allowed URL still carries the attribute tag: quotes and ampersands. */
  std::string page = Post(Href("url(title)").c_str(),
      "https://a/?q=\"x\" onmouseover=\"b&c=d", "b");
  std::string v = Between(page, "<a href=\"", "\">x</a>");
  EXPECT_TRUE(Inert(v)) << v;
  EXPECT_NE(std::string::npos, v.find("onmouseover"));
  EXPECT_NE(std::string::npos, v.find("&amp;c=d"));
  page = Post((std::string(kLead) + "<a href='<%= url(title) %>'>x</a>").c_str(),
      "https://a/?q='x' onmouseover='b", "b");
  v = Between(page, "<a href='", "'>x</a>");
  EXPECT_TRUE(Inert(v)) << v;
  EXPECT_NE(std::string::npos, v.find("onmouseover"));
  /* The result of a refusal is also a plain "#", and a non-string is refused. */
  page = Post(Href("url(5)").c_str(), "https://a/", "b");
  EXPECT_NE(std::string::npos, page.find("<a href=\"#\">x</a>"));
  page = Post(Href("url(null)").c_str(), "https://a/", "b");
  EXPECT_NE(std::string::npos, page.find("<a href=\"#\">x</a>"));
  page = Post(Href("url()").c_str(), "https://a/", "b");
  EXPECT_NE(std::string::npos, page.find("<a href=\"#\">x</a>"));
  page = Post(Href("url(title, title)").c_str(), "https://a/", "b");
  EXPECT_NE(std::string::npos, page.find("<a href=\"#\">x</a>"));
  /* Control: the same template with a string argument passes the URL. */
  page = Post(Href("url(title)").c_str(), "https://a/", "b");
  EXPECT_NE(std::string::npos, page.find("<a href=\"https://a/\">x</a>"));
}

} /* namespace */

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
