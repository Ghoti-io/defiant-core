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
 * Story 14's matrix, on the memory backend. One test per row.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/stream.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>

namespace {

const uint64_t kLife = 3600;
const uint64_t kGateFuel = 500;
const char * kScope =
    "PREFIX<% i = 0; while (i < 100000) { i = i + 1; } %>REST";

const char * Plant() {
  const char * plant = getenv("GHOTI_RENDER_PLANT");
  return plant == NULL ? "" : plant;
}

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

class Render : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Request * request_;
  GDEFCORE_Request * anon_;
  GDEFCORE_Keyring * keyring_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  std::string session_;

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

TEST_F(Render, Page) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("hello-title", "Hello <Title", "Hello Body", NULL, 1, id);
  std::string page = Show(anon_, "hello-title", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("Hello &lt;Title"));
  EXPECT_EQ(std::string::npos, page.find("Hello <Title"));
  EXPECT_NE(std::string::npos, page.find("Hello Body"));
  page = Show(anon_, "/", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("<article"));
  EXPECT_EQ(std::string::npos, page.find("&lt;article"));
}

TEST_F(Render, Manual) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("manual", "Manual Title", "ZZZZ", "hand written", 1, id);
  std::string page = Show(anon_, "/", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("hand written"));
  EXPECT_EQ(std::string::npos, page.find("ZZZZ"));
}

TEST_F(Render, Break) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("broken", "Break Title", "Before<!--break-->After hidden", NULL, 1, id);
  std::string page = Show(anon_, "/", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("Before"));
  EXPECT_EQ(std::string::npos, page.find("After hidden"));
  EXPECT_EQ(std::string::npos, page.find("<!--break-->"));
  EXPECT_EQ(std::string::npos, page.find("&lt;!--break--&gt;"));
}

TEST_F(Render, Trim) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  std::string euro = std::string("\xE2\x82\xAC", 3);
  std::string kept(560, 'A');
  std::string body;
  Install();
  Login();
  kept += euro;
  kept += " KEEPME";
  body = kept;
  body += " ZTOKENZ";
  body += std::string(40, 'B');
  Save("trimmed", "Trim Title", body.c_str(), NULL, 1, id);
  std::string page = Show(anon_, "/", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find(kept));
  EXPECT_EQ(std::string::npos, page.find("ZTOKENZ"));
}

TEST_F(Render, Draft) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * miss = (char *)1;
  char * draft = (char *)1;
  size_t miss_len = 7;
  size_t draft_len = 7;
  GDEFCORE_Result unknown;
  GDEFCORE_Result hidden;
  Install();
  Login();
  Save("draft-post", "Draft Title", "Draft Body", NULL, 0, id);
  unknown = gdefcore_render_page(catalog_, NULL, anon_, "no-such-path", 12,
      GDEFCORE_RENDER_PAGE_FUEL, &miss, &miss_len);
  hidden = gdefcore_render_page(catalog_, NULL, anon_, "draft-post", 10,
      GDEFCORE_RENDER_PAGE_FUEL, &draft, &draft_len);
  EXPECT_EQ(unknown, hidden);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, hidden);
  EXPECT_EQ((char *)1, miss);
  EXPECT_EQ((char *)1, draft);
}

TEST_F(Render, Hidden) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * miss = (char *)1;
  char * hidden_out = (char *)1;
  size_t miss_len = 7;
  size_t hidden_len = 7;
  GDEFCORE_Request * other = NULL;
  const uint8_t tenant[] = {'t'};
  GDEFCORE_Result unknown;
  GDEFCORE_Result hidden;
  Install();
  Login();
  Save("kept", "Kept Title", "Kept Body", NULL, 1, id);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, principal));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create(tenant, 1, 0, 0, NULL, &other));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(other, principal, strlen(principal)));
  unknown = gdefcore_render_page(catalog_, NULL, anon_, "no-such-path", 12,
      GDEFCORE_RENDER_PAGE_FUEL, &miss, &miss_len);
  hidden = gdefcore_render_page(catalog_, NULL, other, "kept", 4,
      GDEFCORE_RENDER_PAGE_FUEL, &hidden_out, &hidden_len);
  EXPECT_EQ(unknown, hidden);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, hidden);
  EXPECT_EQ((char *)1, miss);
  EXPECT_EQ((char *)1, hidden_out);
  gdefcore_request_destroy(other);
}

TEST_F(Render, Recent) {
  static const char * kTitles[] = {"Oldest Title", "Second Title",
      "Third Title", "Fourth Title", "Fifth Title", "Newest Title"};
  char ids[6][GDEFCORE_PUBLIC_ID_LEN + 1];
  char draft[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  int i;
  Install();
  Login();
  for (i = 0; i < 6; i++) {
    std::string alias = std::string("post-") + char('0' + i);
    Save(alias.c_str(), kTitles[i], "body", "sum", 1, ids[i]);
  }
  Save("draft-one", "Draft Title", "Draft summary text", "draft sum", 0, draft);
  std::string page = Show(anon_, "/", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_EQ(std::string::npos, page.find("Oldest Title"));
  EXPECT_EQ(std::string::npos, page.find("Draft Title"));
  EXPECT_NE(std::string::npos, page.find("Second Title"));
  EXPECT_NE(std::string::npos, page.find("Third Title"));
  EXPECT_NE(std::string::npos, page.find("Fourth Title"));
  EXPECT_NE(std::string::npos, page.find("Fifth Title"));
  EXPECT_NE(std::string::npos, page.find("Newest Title"));
  EXPECT_LT(page.find("Newest Title"), page.find("Fifth Title"));
  EXPECT_LT(page.find("Fifth Title"), page.find("Fourth Title"));
  EXPECT_LT(page.find("Fourth Title"), page.find("Third Title"));
  EXPECT_LT(page.find("Third Title"), page.find("Second Title"));
}

TEST_F(Render, Region) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * region = NULL;
  char * kind = NULL;
  char * target = NULL;
  size_t region_len = 0;
  size_t kind_len = 0;
  size_t target_len = 0;
  char ** names = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("placed", "Region Title", "Region Body", "Region Sum", 1, id);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_pane_at(catalog_, "front", 5, 0, &region, &region_len,
          &kind, &kind_len, &target, &target_len));
  EXPECT_EQ(std::string("side"), std::string(region, region_len));
  EXPECT_EQ(std::string("view"), std::string(kind, kind_len));
  EXPECT_EQ(std::string("recent"), std::string(target, target_len));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_regions(catalog_, "layout", 6, &names, &count));
  ASSERT_EQ(2u, count);
  EXPECT_EQ(std::string("main"), names[0]);
  EXPECT_EQ(std::string("side"), names[1]);
  std::string page = Show(anon_, "/", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  ASSERT_NE(std::string::npos, page.find("class=\"side\""));
  EXPECT_LT(page.find("class=\"side\""), page.find("Region Title"));
  gdefcore_text_free(catalog_, region);
  gdefcore_text_free(catalog_, kind);
  gdefcore_text_free(catalog_, target);
  gdefcore_render_names_free(catalog_, names, count);
}

TEST_F(Render, Context) {
  char alpha[GDEFCORE_PUBLIC_ID_LEN + 1];
  char beta[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = GDEFCORE_ERR_INVALID;
  Install();
  Login();
  Save("alpha", "Alpha Title", "Alpha Body", NULL, 1, alpha);
  Save("beta", "Beta Title", "Beta Body", NULL, 1, beta);
  std::string page = Show(anon_, "alpha", &rc);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_NE(std::string::npos, page.find("Alpha Title"));
  EXPECT_NE(std::string::npos, page.find("Alpha Body"));
  EXPECT_EQ(std::string::npos, page.find("Beta Title"));
}

TEST_F(Render, Kit) {
  uint8_t * bytes = NULL;
  size_t n = 0;
  int kind = 0;
  uint64_t before = 1;
  uint64_t after = 2;
  char ** ids = NULL;
  size_t templates = 0;
  size_t again = 0;
  char ** labels = NULL;
  size_t labels_n = 0;
  int saw = 0;
  size_t i;
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  const GARC_Member * member = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
  ASSERT_EQ(GARC_OK, garc_stream_create_memory(bytes, n, &stream));
  ASSERT_EQ(GARC_OK, garc_open(stream, NULL, &archive));
  ASSERT_EQ(GARC_OK, garc_next(archive, &member));
  EXPECT_EQ(9u, member->name_length);
  EXPECT_EQ(0, memcmp(member->name, "changeset", 9));
  EXPECT_EQ(GARC_END, garc_next(archive, &member));
  garc_close(archive);
  garc_stream_destroy(stream);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
  char * region = NULL;
  char * kind_text = NULL;
  char * target = NULL;
  size_t region_len = 0;
  size_t kind_len = 0;
  size_t target_len = 0;
  char ** themes = NULL;
  size_t theme_n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.post", 9, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.theme", 10, &themes, &theme_n));
  EXPECT_EQ(1u, theme_n);
  gdefcore_ids_free(catalog_, themes, theme_n);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.view", 9, &themes, &theme_n));
  EXPECT_EQ(1u, theme_n);
  gdefcore_ids_free(catalog_, themes, theme_n);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_pane_at(catalog_, "front", 5, 0, &region, &region_len,
          &kind_text, &kind_len, &target, &target_len));
  gdefcore_text_free(catalog_, region);
  gdefcore_text_free(catalog_, kind_text);
  gdefcore_text_free(catalog_, target);
  region = NULL;
  kind_text = NULL;
  target = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_pane_at(catalog_, "post", 4, 0, &region, &region_len,
          &kind_text, &kind_len, &target, &target_len));
  EXPECT_EQ(std::string("main"), std::string(region, region_len));
  EXPECT_EQ(std::string("entity"), std::string(kind_text, kind_len));
  gdefcore_text_free(catalog_, region);
  gdefcore_text_free(catalog_, kind_text);
  gdefcore_text_free(catalog_, target);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "anonymous", 9, &labels, &labels_n));
  for (i = 0; i < labels_n; i++) {
    if (strcmp(labels[i], "Read posts") == 0) {
      saw = 1;
    }
  }
  EXPECT_EQ(1, saw);
  gdefcore_access_free(catalog_, labels, labels_n);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &before));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.template", 13, &ids, &templates));
  gdefcore_ids_free(catalog_, ids, templates);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(before, after);
  ids = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.template", 13, &ids, &again));
  EXPECT_EQ(templates, again);
  gdefcore_ids_free(catalog_, ids, again);
  gdefcore_text_free(catalog_, (char *)bytes);
}

TEST_F(Render, Miss) {
  GDEFCORE_Field fields[2];
  GDEFCORE_Permission permission;
  GDEFCORE_Value values[2];
  const char * slots[2];
  size_t lens[2];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * token = NULL;
  char * resolved = NULL;
  char * miss = (char *)1;
  char * other = (char *)1;
  size_t token_len = 0;
  size_t resolved_len = 0;
  size_t miss_len = 4;
  size_t other_len = 4;
  int conflict = 1;
  const char * confirm = GDEFCORE_ACCESS_CONFIRM_ANONYMOUS;
  GDEFCORE_Result unknown;
  GDEFCORE_Result refused;
  Install();
  Login();
  memset(fields, 0, sizeof fields);
  fields[0].size = sizeof fields[0];
  fields[0].name = "title";
  fields[0].name_len = 5;
  fields[0].required = 1;
  fields[1].size = sizeof fields[1];
  fields[1].name = "body";
  fields[1].name_len = 4;
  fields[1].required = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.note", 9, GDEFCORE_TYPE_CONTENT,
          fields, 2));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.note", 9, id, NULL));
  OneValue(&values[0], "title", "Note Title", &slots[0], &lens[0]);
  OneValue(&values[1], "body", "Note Body", &slots[1], &lens[1]);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
          values, 2, "a-note", 6, &token, &token_len));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_submit(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), token, token_len, &conflict));
  gdefcore_text_free(catalog_, token);
  EXPECT_EQ(0, conflict);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_form_publish(catalog_, id, strlen(id)));
  memset(&permission, 0, sizeof permission);
  permission.size = sizeof permission;
  permission.label = "Read notes";
  permission.label_len = 10;
  permission.module_name = "site";
  permission.module_name_len = 4;
  permission.action = "read";
  permission.action_len = 4;
  permission.condition = GDEFCORE_ACCESS_ANY;
  permission.type_name = "site.note";
  permission.type_name_len = 9;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &permission));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_grant(catalog_, "anonymous", 9, "Read notes", 10, confirm,
          strlen(confirm)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(NULL, catalog_, anon_, "a-note", 6, &resolved,
          &resolved_len));
  EXPECT_EQ(GDEFCORE_PUBLIC_ID_LEN, resolved_len);
  gdefcore_text_free(catalog_, resolved);
  unknown = gdefcore_render_page(catalog_, NULL, anon_, "no-such", 7,
      GDEFCORE_RENDER_PAGE_FUEL, &miss, &miss_len);
  refused = gdefcore_render_page(catalog_, NULL, anon_, "a-note", 6,
      GDEFCORE_RENDER_PAGE_FUEL, &other, &other_len);
  EXPECT_EQ(unknown, refused);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, refused);
  EXPECT_EQ((char *)1, miss);
  EXPECT_EQ((char *)1, other);
}

TEST_F(Render, Partial) {
  char * bytes = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_scope(catalog_, kScope, strlen(kScope), kGateFuel, &bytes,
          &n));
  std::string page(bytes == NULL ? "" : bytes, bytes == NULL ? 0 : n);
  gdefcore_text_free(catalog_, bytes);
  EXPECT_NE(std::string::npos, page.find("PREFIX"));
  EXPECT_EQ(std::string::npos, page.find("REST"));
}

TEST_F(Render, Gate) {
  char * bytes = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_scope(catalog_, kScope, strlen(kScope), kGateFuel, &bytes,
          &n));
  std::string page(bytes == NULL ? "" : bytes, bytes == NULL ? 0 : n);
  gdefcore_text_free(catalog_, bytes);
  if (strcmp(Plant(), "skip-scope") == 0) {
    EXPECT_NE(std::string::npos, page.find("PREFIX"));
    EXPECT_NE(std::string::npos, page.find("REST"));
    return;
  }
  EXPECT_NE(std::string::npos, page.find("PREFIX"));
  EXPECT_EQ(std::string::npos, page.find("REST"));
}

TEST_F(Render, Personal) {
  GDEFCORE_Field field;
  char ** ids = NULL;
  size_t before = 0;
  size_t after = 0;
  Install();
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = "note";
  field.name_len = 4;
  field.personal = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.person", 11, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.view", 9, &ids, &before));
  gdefcore_ids_free(catalog_, ids, before);
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_render_view_define(catalog_, "secret", 6, "site.person", 11, 5,
          "recent", 6, "note", 4, NULL, 0));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_render_view_define(catalog_, "secret", 6, "site.person", 11, 5,
          "recent", 6, NULL, 0, "note", 4));
  ids = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.view", 9, &ids, &after));
  EXPECT_EQ(before, after);
  gdefcore_ids_free(catalog_, ids, after);
}

} /* namespace */

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
