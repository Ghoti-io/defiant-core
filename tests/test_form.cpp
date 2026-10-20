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
 * Story 13's matrix, on the memory backend. One test per row.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage/snapshot.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <string>

namespace {

const uint64_t kLife = 3600;
const char * kPost = "site.post";

GDEFCORE_Field Field(const char * name, int required, size_t min_len,
    size_t max_len, int has_range, int64_t range_min, int64_t range_max,
    const char * pattern) {
  GDEFCORE_Field field;
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = name;
  field.name_len = strlen(name);
  field.required = required;
  field.min_len = min_len;
  field.max_len = max_len;
  field.has_range = has_range;
  field.range_min = range_min;
  field.range_max = range_max;
  if (pattern != NULL) {
    field.pattern = pattern;
    field.pattern_len = strlen(pattern);
  }
  return field;
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

class Form : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Request * request_;
  GDEFCORE_Keyring * keyring_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  std::string session_;

  void SetUp() override {
    const uint8_t tenant[] = {'t'};
    store_ = NULL;
    catalog_ = NULL;
    request_ = NULL;
    keyring_ = NULL;
    memset(root_, 0x42, sizeof root_);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, tenant, 1, NULL, NULL, &catalog_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant, 1, 0, 0, NULL, &request_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_create(root_, sizeof root_, NULL, &keyring_));
  }

  void TearDown() override {
    gdefcore_keyring_destroy(keyring_);
    gdefcore_request_destroy(request_);
    gdefcore_catalog_destroy(catalog_);
    gdefstor_store_destroy(store_);
  }

  void LoginFor(uint64_t life) {
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
            "secret", 6, life, &token, &n));
    session_.assign(token, n);
    gdefcore_text_free(catalog_, token);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
            session_.data(), session_.size()));
  }

  void Login() { LoginFor(kLife); }

  void Define(const GDEFCORE_Field * fields, size_t count) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, kPost, strlen(kPost), GDEFCORE_TYPE_CONTENT,
            fields, count));
  }

  void Create(char id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPost, strlen(kPost), id, NULL));
  }

  std::string Sign(const char * id, const GDEFCORE_Value * values, size_t count,
      const char * alias, size_t alias_len) {
    char * token = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
            session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
            values, count, alias, alias_len, &token, &n));
    std::string out(token == NULL ? "" : token, token == NULL ? 0 : n);
    gdefcore_text_free(catalog_, token);
    return out;
  }

  GDEFCORE_Result Submit(const std::string & token, int * conflict) {
    return gdefcore_form_submit(catalog_, request_, keyring_, root_, sizeof root_,
        session_.data(), session_.size(), token.data(), token.size(), conflict);
  }

  std::string Read(const char * id, const char * field, int view, int * ok) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    GDEFCORE_Result rc = gdefcore_entity_values(catalog_, NULL, view, id,
        strlen(id), "en", 2, field, strlen(field), &texts, &lens, &count);
    std::string value;
    if (ok != NULL) {
      *ok = rc == GDEFCORE_OK;
    }
    if (rc == GDEFCORE_OK && count > 0) {
      value.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return value;
  }

  /* The entity's version: every write moves it, a draft included (a form
   * submit writes a draft, which is never a revision). */
  uint64_t Version(const char * id) {
    uint64_t v = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_version(catalog_, id, strlen(id), &v));
    return v;
  }

  /* The newest revision. */
  uint64_t Head(const char * id) {
    uint64_t seq = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision(catalog_, id, strlen(id), &seq));
    return seq;
  }

  void GrantRead() {
    GDEFCORE_Permission permission;
    memset(&permission, 0, sizeof permission);
    permission.size = sizeof permission;
    permission.label = "Read posts";
    permission.label_len = strlen(permission.label);
    permission.module_name = "site";
    permission.module_name_len = 4;
    permission.action = "read";
    permission.action_len = 4;
    permission.condition = GDEFCORE_ACCESS_ANY;
    permission.type_name = kPost;
    permission.type_name_len = strlen(kPost);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &permission));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "admin", 5, "Read posts", 10, "core.role",
            9));
  }
};

void NoteRoot(GDEFCORE_Request * request, const char * machine, size_t machine_len,
    void * data) {
  (void)machine;
  (void)machine_len;
  (void)data;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_note(request, "seen", 4, "yes", 3));
}

void OwnFoo(GDEFCORE_Request * request, const char * machine, size_t machine_len,
    void * data) {
  (void)data;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_resolution(request, machine, machine_len));
}

void NoteLater(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  (void)machine;
  (void)machine_len;
  (void)data;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_note(request, "later", 5, "ran", 3));
}

void NoteAfter(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  (void)machine;
  (void)machine_len;
  (void)data;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_note(request, "after", 5, "yes", 3));
}

void NoteExact(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  (void)machine;
  (void)machine_len;
  (void)data;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_note(request, "which", 5, "exact", 5));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_resolution(request, "core.exact", 10));
}

void NoteWild(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  (void)machine;
  (void)machine_len;
  (void)data;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_note(request, "which", 5, "wild", 4));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_resolution(request, "core.wild", 9));
}

void CountRun(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  int * hits = (int *)data;
  *hits += 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_resolution(request, machine, machine_len));
}

}  // namespace

TEST_F(Form, Tree) {
  GDEFCORE_Field field = Field("title", 1, 2, 8, 0, 0, 0, NULL);
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Form * form = NULL;
  const char * name = NULL;
  size_t name_len = 0;
  int required = 0;
  int many = 1;
  int personal = 1;
  size_t min_len = 0;
  size_t max_len = 0;
  int has_range = 1;
  const char * const * texts = NULL;
  const size_t * lens = NULL;
  size_t count = 0;
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save_draft(changeset, id, strlen(id), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_tree(catalog_, kPost, strlen(kPost), id, strlen(id), "en", 2,
          &form));
  ASSERT_EQ(1u, gdefcore_form_field_count(form));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_field(form, 0, &name, &name_len, &required, &many, &personal,
          &min_len, &max_len, &has_range, NULL, NULL, NULL, NULL, &texts, &lens,
          &count));
  EXPECT_EQ(std::string("title"), std::string(name, name_len));
  EXPECT_EQ(1, required);
  EXPECT_EQ(0, many);
  EXPECT_EQ(0, personal);
  EXPECT_EQ(2u, min_len);
  EXPECT_EQ(8u, max_len);
  EXPECT_EQ(0, has_range);
  ASSERT_EQ(1u, count);
  EXPECT_EQ(std::string("Hello"), std::string(texts[0], lens[0]));
  gdefcore_form_destroy(form);
}

/* The tree shows what an editor is editing: the head revision, and when a
 * clear removed the head, the current revision, whether or not it is published
 * (it used to look for a published one, so a restored but unpublished entity
 * opened as an empty form). */
TEST_F(Form, TreeFallsBackToTheCurrentRevision) {
  GDEFCORE_Field field = Field("title", 1, 2, 12, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  auto Apply = [&](GDEFCORE_Changeset * cs) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  };
  auto Shown = [&]() {
    GDEFCORE_Form * form = NULL;
    const char * const * texts = NULL;
    const size_t * lens = NULL;
    size_t count = 99;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_form_tree(catalog_, kPost, strlen(kPost), id, strlen(id), "en", 2,
            &form));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_form_field(form, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, &texts, &lens, &count));
    out = count == 0 ? "<none>" : std::string(texts[0], lens[0]);
    gdefcore_form_destroy(form);
    return out;
  };
  Define(&field, 1);
  Create(id);
  for (const char * text : {"First", "Second"}) {
    GDEFCORE_Changeset * cs = NULL;
    OneValue(&value, "title", text, &slot, &len_slot);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, strlen(id), "en", 2, &value, 1));
    Apply(cs);
  }
  EXPECT_EQ("Second", Shown());   /* control: the newest revision */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_clear(cs, id, strlen(id)));
  Apply(cs);
  EXPECT_EQ("<none>", Shown());   /* cleared: nothing to edit */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert_to(catalog_, id, strlen(id), 1, NULL, 0, &cs));
  Apply(cs);                       /* restored as a new revision, not published */
  int state = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_state(catalog_, id, strlen(id), &state));
  ASSERT_EQ(GDEFCORE_STATE_DRAFT, state);
  EXPECT_EQ("First", Shown());
  /* A draft over it is what the form opens. */
  OneValue(&value, "title", "Third", &slot, &len_slot);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save_draft(cs, id, strlen(id), "en", 2, &value, 1));
  Apply(cs);
  EXPECT_EQ("Third", Shown());
}

TEST_F(Form, Constraint) {
  GDEFCORE_Field field = Field("title", 1, 3, 5, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * token = (char *)0x1;
  size_t n = 99;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "ab", &slot, &len_slot);
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
          &value, 1, NULL, 0, &token, &n));
  EXPECT_EQ(0u, Version(id));
  OneValue(&value, "title", "abcdef", &slot, &len_slot);
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
          &value, 1, NULL, 0, &token, &n));
  OneValue(&value, "title", "abcd", &slot, &len_slot);
  EXPECT_FALSE(Sign(id, &value, 1, NULL, 0).empty());
  EXPECT_EQ(0u, Version(id));
}

TEST_F(Form, Range) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 1, 10, 20, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * token = NULL;
  size_t n = 0;
  const char * bad[] = {"9", "21", "10a", " 10", "+10", ""};
  size_t i;
  Login();
  Define(&field, 1);
  Create(id);
  for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    OneValue(&value, "title", bad[i], &slot, &len_slot);
    token = (char *)0x1;
    n = 7;
    EXPECT_NE(GDEFCORE_OK,
        gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
            session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
            &value, 1, NULL, 0, &token, &n));
  }
  OneValue(&value, "title", "10", &slot, &len_slot);
  EXPECT_FALSE(Sign(id, &value, 1, NULL, 0).empty());
  OneValue(&value, "title", "20", &slot, &len_slot);
  EXPECT_FALSE(Sign(id, &value, 1, NULL, 0).empty());
  EXPECT_EQ(0u, Version(id));
}

TEST_F(Form, Pattern) {
  GDEFCORE_Field bad = Field("title", 1, 0, 0, 0, 0, 0, "[");
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, "ab");
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * token = (char *)0x1;
  size_t n = 3;
  int kind = 0;
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_type_define(catalog_, kPost, strlen(kPost), GDEFCORE_TYPE_CONTENT,
          &bad, 1));
  EXPECT_NE(GDEFCORE_OK, gdefcore_type_kind(catalog_, kPost, strlen(kPost), &kind));
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "abc", &slot, &len_slot);
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
          &value, 1, NULL, 0, &token, &n));
  OneValue(&value, "title", "xab", &slot, &len_slot);
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_sign(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), "edit", 4, id, strlen(id), "en", 2,
          &value, 1, NULL, 0, &token, &n));
  OneValue(&value, "title", "ab", &slot, &len_slot);
  EXPECT_FALSE(Sign(id, &value, 1, NULL, 0).empty());
  EXPECT_EQ(0u, Version(id));
}

TEST_F(Form, Sign) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t expiry = 0;
  uint64_t session_expiry = 0;
  uint64_t now = 0;
  std::string token;
  int published = 1;
  LoginFor(GDEFCORE_FORM_LIFETIME + 3600);
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  now = (uint64_t)time(NULL);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_FALSE(token.empty());
  EXPECT_EQ(0u, Version(id));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_form_check(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), token.data(), token.size(), &expiry));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_account_session_expiry(catalog_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), &session_expiry));
  EXPECT_GE(expiry, now + GDEFCORE_FORM_LIFETIME);
  EXPECT_LE(expiry, now + GDEFCORE_FORM_LIFETIME + 2);
  EXPECT_LT(expiry, session_expiry);
  Read(id, "title", GDEFCORE_VIEW_PUBLISHED, &published);
  EXPECT_EQ(0, published);
}

TEST_F(Form, Tamper) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 1;
  int draft = 1;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_GT(token.size(), 8u);
  token[token.size() / 2] = (char)(token[token.size() / 2] ^ 0x01);
  EXPECT_NE(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(0u, Version(id));
  Read(id, "title", GDEFCORE_VIEW_DRAFT, &draft);
  EXPECT_EQ(0, draft);
}

TEST_F(Form, OtherSession) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * other = NULL;
  size_t other_len = 0;
  std::string token;
  int conflict = 1;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_login(catalog_, keyring_, root_, sizeof root_, "ada", 3,
          "secret", 6, kLife, &other, &other_len));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_submit(catalog_, request_, keyring_, root_, sizeof root_, other,
          other_len, token.data(), token.size(), &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(0u, Version(id));
  gdefcore_text_free(catalog_, other);
  /* The control: the session the token was signed under still submits it. */
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(1u, Version(id));
}

TEST_F(Form, OtherTenant) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const uint8_t other_tenant[] = {'u'};
  GDEFSTOR_Store * other_store = NULL;
  GDEFCORE_Catalog * other = NULL;
  GDEFCORE_Request * other_request = NULL;
  std::string token;
  int conflict = 1;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &other_store));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(other_store, other_tenant, 1, NULL, NULL, &other));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create(other_tenant, 1, 0, 0, NULL, &other_request));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_submit(other, other_request, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), token.data(), token.size(),
          &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(0u, Version(id));
  gdefcore_request_destroy(other_request);
  gdefcore_catalog_destroy(other);
  gdefstor_store_destroy(other_store);

  /*
   * The same session and token under a tenant holding a copy of every row.
   * Only the tenant bytes differ, so the associated data is the one thing
   * that can refuse it. The separate empty store above is refused for want
   * of an account, whatever the token says.
   */
  {
    uint8_t * zip = NULL;
    size_t zip_len = 0;
    const char tenant_t[] = {'t'};
    const uint8_t clone[] = {'v'};
    GDEFCORE_Catalog * twin = NULL;
    GDEFCORE_Request * twin_request = NULL;
    uint64_t seq = 99;
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_export(store_, tenant_t, 1, NULL, &zip, &zip_len));
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_import(store_, "v", 1, zip, zip_len, NULL));
    gdefstor_bytes_free(NULL, zip);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, clone, 1, NULL, NULL, &twin));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(clone, 1, 0, 0, NULL, &twin_request));
    conflict = 1;
    EXPECT_NE(GDEFCORE_OK,
        gdefcore_form_submit(twin, twin_request, keyring_, root_, sizeof root_,
            session_.data(), session_.size(), token.data(), token.size(),
            &conflict));
    EXPECT_EQ(0, conflict);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision(twin, id, strlen(id), &seq));
    EXPECT_EQ(0u, seq);
    gdefcore_request_destroy(twin_request);
    gdefcore_catalog_destroy(twin);
  }
}

TEST_F(Form, Unsigned) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int conflict = 1;
  Login();
  Define(&field, 1);
  Create(id);
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_submit(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), NULL, 0, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(0u, Version(id));
}

TEST_F(Form, Replay) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 0;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(1u, Version(id));
  EXPECT_EQ(std::string("Hello"), Read(id, "title", GDEFCORE_VIEW_DRAFT, NULL));
  EXPECT_NE(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(1, conflict);
  EXPECT_EQ(1u, Version(id));
  EXPECT_EQ(std::string("Hello"), Read(id, "title", GDEFCORE_VIEW_DRAFT, NULL));
}

/*
 * A form signed against revision N is refused once the entity is at N+1, and
 * the refusal says conflict, not tamper. The fresh form is the control.
 */
TEST_F(Form, StaleBase) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string stale;
  std::string fresh;
  int conflict = 0;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "one", &slot, &len_slot);
  stale = Sign(id, &value, 1, NULL, 0);
  OneValue(&value, "title", "two", &slot, &len_slot);
  fresh = Sign(id, &value, 1, NULL, 0);
  ASSERT_FALSE(stale.empty());
  ASSERT_FALSE(fresh.empty());
  ASSERT_EQ(GDEFCORE_OK, Submit(fresh, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(1u, Version(id));
  conflict = 0;
  EXPECT_NE(GDEFCORE_OK, Submit(stale, &conflict));
  EXPECT_EQ(1, conflict);
  EXPECT_EQ(1u, Version(id));
  EXPECT_EQ(std::string("two"), Read(id, "title", GDEFCORE_VIEW_DRAFT, NULL));
  OneValue(&value, "title", "three", &slot, &len_slot);
  fresh = Sign(id, &value, 1, NULL, 0);
  conflict = 1;
  ASSERT_EQ(GDEFCORE_OK, Submit(fresh, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(2u, Version(id));
}

/*
 * A form is capped at its session's expiry, so an expired form is refused
 * whichever layer sees it first. The form's own expiry compare is behind the
 * session check and cannot be reached alone; this test is the observable
 * behaviour, not a plant target.
 */
TEST_F(Form, Expired) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 1;
  LoginFor(1);
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "late", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_FALSE(token.empty());
  sleep(2);
  EXPECT_NE(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(0u, Version(id));
}

TEST_F(Form, Resign) {
  GDEFCORE_Field field = Field("title", 1, 3, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * again = NULL;
  size_t again_len = 0;
  std::string token;
  int draft = 1;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  OneValue(&value, "title", "There", &slot, &len_slot);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resign(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), token.data(), token.size(), &value, 1,
          &again, &again_len));
  EXPECT_EQ(0u, Version(id));
  Read(id, "title", GDEFCORE_VIEW_DRAFT, &draft);
  EXPECT_EQ(0, draft);
  gdefcore_text_free(catalog_, again);
  OneValue(&value, "title", "ab", &slot, &len_slot);
  again = (char *)0x1;
  again_len = 4;
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_resign(catalog_, request_, keyring_, root_, sizeof root_,
          session_.data(), session_.size(), token.data(), token.size(), &value, 1,
          &again, &again_len));
  EXPECT_EQ(0u, Version(id));
}

TEST_F(Form, Draft) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 1;
  int published = 1;
  char * resolved = (char *)0x1;
  size_t resolved_len = 9;
  GDEFCORE_Request * anon = NULL;
  const uint8_t tenant[] = {'t'};
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello World", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(std::string("Hello World"), Read(id, "title", GDEFCORE_VIEW_DRAFT, NULL));
  {
    char * path = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_form_alias(catalog_, id, strlen(id), &path, &n));
    EXPECT_EQ(std::string("hello-world"), std::string(path, n));
    gdefcore_text_free(catalog_, path);
  }
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_resolve(NULL, catalog_, request_, "hello-world", 11, &resolved,
          &resolved_len));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_create(tenant, 1, 0, 0, NULL, &anon));
  resolved = (char *)0x1;
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_resolve(NULL, catalog_, anon, "hello-world", 11, &resolved,
          &resolved_len));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_resolve(NULL, catalog_, anon, "/no-such", 8, &resolved,
          &resolved_len));
  Read(id, "title", GDEFCORE_VIEW_PUBLISHED, &published);
  EXPECT_EQ(0, published);
  gdefcore_request_destroy(anon);
}

TEST_F(Form, Given) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 0;
  char * path = NULL;
  size_t n = 0;
  const char * alias = "/Keep Me";
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "Hello", &slot, &len_slot);
  token = Sign(id, &value, 1, alias, strlen(alias));
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_form_alias(catalog_, id, strlen(id), &path, &n));
  EXPECT_EQ(std::string(alias), std::string(path, n));
  gdefcore_text_free(catalog_, path);
}

TEST_F(Form, Slug) {
  GDEFCORE_Field fields[2];
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char bare[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 0;
  char * path = NULL;
  size_t n = 0;
  fields[0] = Field("title", 0, 0, 0, 0, 0, 0, NULL);
  fields[1] = Field("body", 1, 0, 0, 0, 0, 0, NULL);
  Login();
  Define(fields, 2);
  Create(id);
  {
    GDEFCORE_Value both[2];
    const char * slots[2] = {NULL, NULL};
    size_t lens[2] = {0, 0};
    OneValue(&both[0], "title", "Hello World", &slots[0], &lens[0]);
    OneValue(&both[1], "body", "text", &slots[1], &lens[1]);
    token = Sign(id, both, 2, NULL, 0);
  }
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_form_alias(catalog_, id, strlen(id), &path, &n));
  EXPECT_EQ(std::string("hello-world"), std::string(path, n));
  gdefcore_text_free(catalog_, path);
  Create(bare);
  OneValue(&value, "body", "only", &slot, &len_slot);
  token = Sign(bare, &value, 1, NULL, 0);
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  path = (char *)0x1;
  EXPECT_NE(GDEFCORE_OK, gdefcore_form_alias(catalog_, bare, strlen(bare), &path, &n));
}

TEST_F(Form, Publish) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char first[GDEFCORE_PUBLIC_ID_LEN + 1];
  char second[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 0;
  char * path = NULL;
  size_t n = 0;
  char * resolved = NULL;
  size_t resolved_len = 0;
  char bare[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t revision = 0;
  int published = 1;
  GDEFCORE_Request * anon = NULL;
  GDEFCORE_Routes * routes = NULL;
  GDEFCORE_Result hidden = GDEFCORE_OK;
  GDEFCORE_Result unknown = GDEFCORE_OK;
  const uint8_t tenant[] = {'t'};
  Login();
  GrantRead();
  Define(&field, 1);
  Create(first);
  Create(second);
  Create(bare);
  OneValue(&value, "title", "Hello World", &slot, &len_slot);
  token = Sign(first, &value, 1, NULL, 0);
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  revision = Head(first);
  EXPECT_EQ(0u, revision);   /* the submit wrote a draft */
  token = Sign(second, &value, 1, NULL, 0);
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_NE(GDEFCORE_OK, gdefcore_form_publish(catalog_, bare, strlen(bare)));
  EXPECT_EQ(0u, Version(bare));
  Read(bare, "title", GDEFCORE_VIEW_PUBLISHED, &published);
  EXPECT_EQ(0, published);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_form_publish(catalog_, first, strlen(first)));
  EXPECT_EQ(revision + 1, Head(first));   /* the publish applied the draft */
  EXPECT_EQ(std::string("Hello World"),
      Read(first, "title", GDEFCORE_VIEW_PUBLISHED, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(NULL, catalog_, request_, "hello-world", 11, &resolved,
          &resolved_len));
  EXPECT_EQ(std::string(first), std::string(resolved, resolved_len));
  gdefcore_text_free(catalog_, resolved);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_form_publish(catalog_, second, strlen(second)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_alias(catalog_, second, strlen(second), &path, &n));
  EXPECT_EQ(0, memcmp(path, "hello-world-", 12));
  EXPECT_EQ(16u, n);
  resolved = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(NULL, catalog_, request_, path, n, &resolved,
          &resolved_len));
  EXPECT_EQ(std::string(second), std::string(resolved, resolved_len));
  gdefcore_text_free(catalog_, resolved);
  gdefcore_text_free(catalog_, path);
  resolved = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(NULL, catalog_, request_, "hello-world", 11, &resolved,
          &resolved_len));
  EXPECT_EQ(std::string(first), std::string(resolved, resolved_len));
  gdefcore_text_free(catalog_, resolved);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
  resolved = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(routes, catalog_, request_, "hello-world", 11,
          &resolved, &resolved_len));
  EXPECT_EQ(std::string(first), std::string(resolved, resolved_len));
  gdefcore_text_free(catalog_, resolved);
  gdefcore_routes_destroy(routes);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_create(tenant, 1, 0, 0, NULL, &anon));
  resolved = (char *)0x1;
  resolved_len = 9;
  hidden = gdefcore_form_resolve(NULL, catalog_, anon, "hello-world", 11,
      &resolved, &resolved_len);
  unknown = gdefcore_form_resolve(NULL, catalog_, anon, "/no-such", 8, &resolved,
      &resolved_len);
  EXPECT_NE(GDEFCORE_OK, hidden);
  EXPECT_EQ(hidden, unknown);
  gdefcore_request_destroy(anon);
}

TEST_F(Form, Chain) {
  GDEFCORE_Routes * routes = NULL;
  char * resolved = NULL;
  size_t n = 0;
  const char * note = NULL;
  size_t note_len = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.root", 9, "/", 1, 0, 0, NoteRoot, NULL, NULL,
          NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.foo", 8, "/foo", 4, 1, 0, OwnFoo, NULL, NULL,
          NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.later", 10, "/foo", 4, 2, 0, NoteLater, NULL,
          NULL, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.after", 10, "/foo", 4, 3, 1, NoteAfter, NULL,
          NULL, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(routes, catalog_, request_, "/foo", 4, &resolved, &n));
  EXPECT_EQ(std::string("core.foo"), std::string(resolved, n));
  note = gdefcore_request_note(request_, "seen", 4, &note_len);
  ASSERT_NE(nullptr, note);
  EXPECT_EQ(std::string("yes"), std::string(note, note_len));
  EXPECT_EQ(nullptr, gdefcore_request_note(request_, "later", 5, &note_len));
  note = gdefcore_request_note(request_, "after", 5, &note_len);
  ASSERT_NE(nullptr, note);
  EXPECT_EQ(std::string("yes"), std::string(note, note_len));
  gdefcore_text_free(catalog_, resolved);
  gdefcore_routes_destroy(routes);
}

TEST_F(Form, Wildcard) {
  GDEFCORE_Routes * routes = NULL;
  char * resolved = NULL;
  size_t n = 0;
  const char * note = NULL;
  size_t note_len = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.wild", 9, "/*", 2, 5, 0, NoteWild, NULL, NULL,
          NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.exact", 10, "/foo", 4, 5, 0, NoteExact, NULL,
          NULL, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(routes, catalog_, request_, "/foo", 4, &resolved, &n));
  EXPECT_EQ(std::string("core.exact"), std::string(resolved, n));
  note = gdefcore_request_note(request_, "which", 5, &note_len);
  ASSERT_NE(nullptr, note);
  EXPECT_EQ(std::string("exact"), std::string(note, note_len));
  gdefcore_text_free(catalog_, resolved);
  gdefcore_routes_destroy(routes);
}

TEST_F(Form, Name) {
  GDEFCORE_Routes * routes = NULL;
  char * error = NULL;
  size_t error_len = 0;
  int hits = 0;
  char * resolved = (char *)0x1;
  size_t n = 3;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.front", 10, "/a", 2, 0, 0, CountRun, &hits,
          NULL, NULL));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_route_add(routes, "core.front", 10, "/b", 2, 0, 0, CountRun, &hits,
          &error, &error_len));
  ASSERT_NE(nullptr, error);
  EXPECT_NE(std::string::npos, std::string(error, error_len).find("/a"));
  EXPECT_NE(std::string::npos, std::string(error, error_len).find("/b"));
  EXPECT_NE(std::string::npos, std::string(error, error_len).find("core.front"));
  gdefcore_routes_free(routes, error);
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_form_resolve(routes, catalog_, request_, "/b", 2, &resolved, &n));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_resolve(routes, catalog_, request_, "/a", 2, &resolved, &n));
  EXPECT_EQ(1, hits);
  gdefcore_text_free(catalog_, resolved);
  gdefcore_routes_destroy(routes);
}

TEST_F(Form, Gate) {
  GDEFCORE_Field field = Field("title", 1, 0, 0, 0, 0, 0, NULL);
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t len_slot = 0;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  int conflict = 1;
  int published = 1;
  Login();
  Define(&field, 1);
  Create(id);
  OneValue(&value, "title", "kept", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_FALSE(token.empty());
  ASSERT_EQ(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(std::string("kept"), Read(id, "title", GDEFCORE_VIEW_DRAFT, NULL));
  Read(id, "title", GDEFCORE_VIEW_PUBLISHED, &published);
  EXPECT_EQ(0, published);
  OneValue(&value, "title", "other", &slot, &len_slot);
  token = Sign(id, &value, 1, NULL, 0);
  ASSERT_FALSE(token.empty());
  token[token.size() - 1] = (char)(token[token.size() - 1] ^ 0x01);
  EXPECT_NE(GDEFCORE_OK, Submit(token, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(std::string("kept"), Read(id, "title", GDEFCORE_VIEW_DRAFT, NULL));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
