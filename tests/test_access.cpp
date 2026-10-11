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
 * Story 9's matrix, on the memory backend. One test per row.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#define MODULE_STR2(x) #x
#define MODULE_STR(x) MODULE_STR2(x)

namespace {

const char kTenant[] = "t";
const char kNote[] = "site.note";
static const char kCoreToken[] = MODULE_STR(GHOTIIO_DEFCORE_NAME);

static GDEFCORE_Module_Manifest g_man;
static GDEFCORE_Module_Perm g_perms[2];
static const GDEFCORE_Module_Manifest * g_current;

extern "C" const GDEFCORE_Module_Manifest * TestGuest(void) {
  return g_current;
}

const char * Plant() {
  const char * plant = getenv("GHOTI_ACCESS_PLANT");
  return plant == NULL ? "" : plant;
}

uint64_t Epoch(GDEFCORE_Catalog * catalog) {
  uint64_t epoch = 0;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog, &epoch));
  return epoch;
}

bool Has(char ** names, size_t count, const char * want) {
  size_t i;
  for (i = 0; i < count; i++) {
    if (strcmp(names[i], want) == 0) {
      return true;
    }
  }
  return false;
}

void DefineNote(GDEFCORE_Catalog * catalog, int with_secret) {
  GDEFCORE_Field fields[2];
  memset(fields, 0, sizeof fields);
  fields[0].size = sizeof fields[0];
  fields[0].name = "title";
  fields[0].name_len = 5;
  fields[0].required = 1;
  fields[1].size = sizeof fields[1];
  fields[1].name = "secret";
  fields[1].name_len = 6;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog, kNote, strlen(kNote), GDEFCORE_TYPE_CONTENT,
          fields, with_secret ? 2 : 1));
}

void SaveTitle(GDEFCORE_Catalog * catalog, const char * id, const char * actor,
    const char * title, const char * secret) {
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Value values[2];
  const char * texts[2];
  size_t lens[2];
  size_t n = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog, actor,
          actor == NULL ? 0 : strlen(actor), &changeset));
  texts[0] = title;
  lens[0] = strlen(title);
  memset(&values[0], 0, sizeof values[0]);
  values[0].size = sizeof values[0];
  values[0].field = "title";
  values[0].field_len = 5;
  values[0].texts = &texts[0];
  values[0].text_lens = &lens[0];
  values[0].count = 1;
  if (secret != NULL) {
    texts[1] = secret;
    lens[1] = strlen(secret);
    memset(&values[1], 0, sizeof values[1]);
    values[1].size = sizeof values[1];
    values[1].field = "secret";
    values[1].field_len = 6;
    values[1].texts = &texts[1];
    values[1].text_lens = &lens[1];
    values[1].count = 1;
    n = 2;
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, values, n));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
}

GDEFCORE_Permission Perm(const char * label, const char * action, int condition,
    const char * field) {
  GDEFCORE_Permission permission;
  memset(&permission, 0, sizeof permission);
  permission.size = sizeof permission;
  permission.label = label;
  permission.label_len = strlen(label);
  permission.module_name = "notes";
  permission.module_name_len = 5;
  permission.action = action;
  permission.action_len = strlen(action);
  permission.condition = condition;
  permission.type_name = kNote;
  permission.type_name_len = strlen(kNote);
  if (field != NULL) {
    permission.field = field;
    permission.field_len = strlen(field);
  }
  return permission;
}

void Declare(GDEFCORE_Catalog * catalog, const GDEFCORE_Permission * permission) {
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog, permission));
}

void Grant(GDEFCORE_Catalog * catalog, const char * role, const char * label,
    const char * confirmation) {
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_grant(catalog, role, strlen(role), label, strlen(label),
          confirmation, confirmation == NULL ? 0 : strlen(confirmation)));
}

std::string Filtered(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const char * id, const char * field, GDEFCORE_Result * out_rc,
    size_t * out_count) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = gdefcore_access_read(catalog, request, id, strlen(id),
      "en", 2, field, strlen(field), &texts, &lens, &count);
  if (out_rc != NULL) {
    *out_rc = rc;
  }
  if (out_count != NULL) {
    *out_count = count;
  }
  if (rc != GDEFCORE_OK || count == 0) {
    gdefcore_values_free(catalog, texts, lens, count);
    return std::string();
  }
  std::string value(texts[0], lens[0]);
  gdefcore_values_free(catalog, texts, lens, count);
  return value;
}

GDEFCORE_Result ReadUntouched(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, const char * field) {
  char ** texts = (char **)0x1;
  size_t * lens = (size_t *)0x1;
  size_t count = 99;
  GDEFCORE_Result rc = gdefcore_access_read(catalog, request, id, strlen(id),
      "en", 2, field, strlen(field), &texts, &lens, &count);
  EXPECT_EQ((char **)0x1, texts);
  EXPECT_EQ((size_t *)0x1, lens);
  EXPECT_EQ(99u, count);
  return rc;
}

std::string Key(GDEFCORE_Catalog * catalog, GDEFCORE_Request * request,
    const char * overlay, const uint8_t * bytes, size_t n) {
  char * key = NULL;
  size_t len = 0;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_access_render_key(catalog, request, overlay,
          overlay == NULL ? 0 : strlen(overlay), bytes, n, &key, &len));
  std::string value(key == NULL ? "" : key, len);
  gdefcore_text_free(catalog, key);
  return value;
}

std::string OmitPrincipal(std::string key) {
  const std::string mark = "\nprincipal:";
  size_t at = key.find(mark);
  size_t end;
  if (at == std::string::npos) {
    return key;
  }
  end = key.find('\n', at + mark.size());
  if (end == std::string::npos) {
    end = key.size();
  }
  key.replace(at, end - at, "\nprincipal:-");
  return key;
}

class Access : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Host * host_;
  GDEFCORE_Request * request_;

  void SetUp() override {
    store_ = NULL;
    catalog_ = NULL;
    host_ = NULL;
    request_ = NULL;
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
            &catalog_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
    gdefcore_catalog_bind_host(catalog_, host_);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL,
            &request_));
  }

  void TearDown() override {
    gdefcore_request_destroy(request_);
    gdefcore_catalog_bind_host(catalog_, NULL);
    gdefcore_host_destroy(host_);
    gdefcore_catalog_destroy(catalog_);
    gdefstor_store_destroy(store_);
  }
};

}  // namespace

TEST_F(Access, Seed) {
  char ** names = NULL;
  size_t count = 0;
  char ** grants = NULL;
  size_t ngrants = 0;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t epoch;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_roles(catalog_, &names, &count));
  EXPECT_TRUE(Has(names, count, "admin"));
  EXPECT_TRUE(Has(names, count, "authenticated"));
  EXPECT_TRUE(Has(names, count, "anonymous"));
  gdefcore_access_free(catalog_, names, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  EXPECT_EQ(GDEFCORE_PUBLIC_ID_LEN, strlen(admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "admin", 5, &grants, &ngrants));
  EXPECT_EQ(0u, ngrants);
  gdefcore_access_free(catalog_, grants, ngrants);
  epoch = Epoch(catalog_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_access_delete_role(catalog_, "anonymous", 9));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_delete_role(catalog_, "authenticated", 13));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_access_delete_role(catalog_, "admin", 5));
  EXPECT_EQ(epoch, Epoch(catalog_));
  {
    char again[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, again));
    EXPECT_STREQ(admin, again);
  }
}

TEST_F(Access, LastAdmin) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** roles = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_principal_remove_role(catalog_, admin, strlen(admin),
          "admin", 5));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_principal_remove(catalog_, admin, strlen(admin)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_roles(catalog_, admin, strlen(admin), &roles,
          &count));
  EXPECT_TRUE(Has(roles, count, "admin"));
  gdefcore_access_free(catalog_, roles, count);
}

TEST_F(Access, Editor) {
  char first[GDEFCORE_PUBLIC_ID_LEN + 1];
  char second[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** grants = NULL;
  size_t count = 0;
  uint64_t epoch;
  GDEFCORE_Permission planted =
      Perm("Edit own content", "delete", GDEFCORE_ACCESS_ANY, NULL);
  char ** grant_text = NULL;
  size_t * grant_lens = NULL;
  size_t grant_n = 0;
  std::string encoded;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_roles(catalog_, &grants, &count));
  gdefcore_access_free(catalog_, grants, count);
  Declare(catalog_, &planted);
  epoch = Epoch(catalog_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_copy_template(catalog_, "Moderator", 9, first));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_copy_template(catalog_, "Usher", 5, first));
  EXPECT_EQ(epoch, Epoch(catalog_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_copy_template(catalog_, "Editor", 6, first));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, first,
          strlen(first), "en", 2, "grant", 5, &grant_text, &grant_lens,
          &grant_n));
  ASSERT_EQ(1u, grant_n);
  encoded.assign(grant_text[0], grant_lens[0]);
  EXPECT_NE(std::string::npos, encoded.find("update"));
  EXPECT_NE(std::string::npos, encoded.find("core.node"));
  EXPECT_EQ(std::string::npos, encoded.find("delete"));
  gdefcore_values_free(catalog_, grant_text, grant_lens, grant_n);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "editor", 6, &grants, &count));
  EXPECT_TRUE(Has(grants, count, "Edit own content"));
  gdefcore_access_free(catalog_, grants, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_copy_template(catalog_, "Editor", 6, second));
  EXPECT_STRNE(first, second);
}

TEST_F(Access, Own) {
  char role[GDEFCORE_PUBLIC_ID_LEN + 1];
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char mine[GDEFCORE_PUBLIC_ID_LEN + 1];
  char theirs[GDEFCORE_PUBLIC_ID_LEN + 1];
  char missing[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Permission permission = Perm("Read own notes", "read", GDEFCORE_ACCESS_OWN, NULL);
  GDEFCORE_Result hidden;
  GDEFCORE_Result absent;
  DefineNote(catalog_, 0);
  Declare(catalog_, &permission);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog_, "writers", 7, role));
  Grant(catalog_, "writers", "Read own notes", "core.role");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, a, strlen(a), "writers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, b, strlen(b), "writers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), mine, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), theirs, NULL));
  SaveTitle(catalog_, mine, a, "mine", NULL);
  SaveTitle(catalog_, theirs, b, "theirs", NULL);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request_, a, strlen(a)));
  EXPECT_EQ("mine", Filtered(catalog_, request_, mine, "title", NULL, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(missing));
  hidden = ReadUntouched(catalog_, request_, theirs, "title");
  absent = ReadUntouched(catalog_, request_, missing, "title");
  EXPECT_EQ(hidden, absent);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, hidden);
  {
    char bare[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kNote, strlen(kNote), bare, NULL));
    SaveTitle(catalog_, bare, NULL, "bare", NULL);
    EXPECT_EQ(ReadUntouched(catalog_, request_, bare, "title"),
        ReadUntouched(catalog_, request_, missing, "title"));
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        ReadUntouched(catalog_, request_, bare, "title"));
  }
}

TEST_F(Access, Any) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char note[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Permission permission = Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, NULL);
  DefineNote(catalog_, 0);
  Declare(catalog_, &permission);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog_, "readers", 7, NULL));
  Grant(catalog_, "readers", "Read notes", "core.role");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, a, strlen(a), "readers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), note, NULL));
  SaveTitle(catalog_, note, b, "shared", NULL);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request_, a, strlen(a)));
  EXPECT_EQ("shared", Filtered(catalog_, request_, note, "title", NULL, NULL));
}

TEST_F(Access, AbsentField) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char who[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Permission read_note = Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, NULL);
  GDEFCORE_Permission secret = Perm("Read secret", "read", GDEFCORE_ACCESS_ANY, "secret");
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t filtered_count = 99;
  GDEFCORE_Result rc;
  DefineNote(catalog_, 1);
  Declare(catalog_, &read_note);
  Declare(catalog_, &secret);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog_, "readers", 7, NULL));
  Grant(catalog_, "readers", "Read notes", "core.role");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, who));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, who, strlen(who), "readers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), id, NULL));
  SaveTitle(catalog_, id, who, "visible", "hidden");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request_, who, strlen(who)));
  EXPECT_EQ("visible", Filtered(catalog_, request_, id, "title", NULL, NULL));
  rc = GDEFCORE_OK;
  EXPECT_EQ("", Filtered(catalog_, request_, id, "secret", &rc, &filtered_count));
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_EQ(0u, filtered_count);
  {
    char peek[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, "peekers", 7, NULL));
    Grant(catalog_, "peekers", "Read secret", "core.role");
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, peek));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_principal_add_role(catalog_, peek, strlen(peek),
            "peekers", 7));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request_, peek, strlen(peek)));
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        ReadUntouched(catalog_, request_, id, "secret"));
    EXPECT_EQ(GDEFCORE_ERR_INVALID, ReadUntouched(catalog_, request_, id, "title"));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request_, who, strlen(who)));
  }
  Grant(catalog_, "readers", "Read secret", "core.role");
  EXPECT_EQ("hidden", Filtered(catalog_, request_, id, "secret", NULL, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id,
          strlen(id), "en", 2, "secret", 6, &texts, &lens, &count));
  ASSERT_EQ(1u, count);
  EXPECT_EQ(0, memcmp(texts[0], "hidden", lens[0]));
  gdefcore_values_free(catalog_, texts, lens, count);
}

TEST_F(Access, UnreadableFilter) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char who[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Permission read_note = Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, NULL);
  GDEFCORE_Permission secret = Perm("Read secret", "read", GDEFCORE_ACCESS_ANY, "secret");
  GDEFCORE_Access_List query;
  const char * fields[4] = {"secret", "secret", "nope", "nope"};
  int which;
  DefineNote(catalog_, 1);
  Declare(catalog_, &read_note);
  Declare(catalog_, &secret);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog_, "readers", 7, NULL));
  Grant(catalog_, "readers", "Read notes", "core.role");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, who));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, who, strlen(who), "readers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), id, NULL));
  SaveTitle(catalog_, id, who, "visible", "hidden");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request_, who, strlen(who)));
  for (which = 0; which < 4; which++) {
    char ** ids = (char **)0x1;
    size_t count = 99;
    memset(&query, 0, sizeof query);
    query.size = sizeof query;
    query.type_name = kNote;
    query.type_name_len = strlen(kNote);
    query.lang = "en";
    query.lang_len = 2;
    if (which % 2 == 0) {
      query.filter_field = fields[which];
      query.filter_field_len = strlen(fields[which]);
      query.filter_text = "hidden";
      query.filter_text_len = 6;
    } else {
      query.sort_field = fields[which];
      query.sort_field_len = strlen(fields[which]);
    }
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_access_list(catalog_, request_, &query, &ids, &count));
    EXPECT_EQ(NULL, ids);
    EXPECT_EQ(0u, count);
  }
}

TEST_F(Access, Count) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char mine[GDEFCORE_PUBLIC_ID_LEN + 1];
  char theirs[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** ids = NULL;
  size_t count = 0;
  GDEFCORE_Permission permission = Perm("Read own notes", "read", GDEFCORE_ACCESS_OWN, NULL);
  GDEFCORE_Access_List query;
  DefineNote(catalog_, 0);
  Declare(catalog_, &permission);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog_, "writers", 7, NULL));
  Grant(catalog_, "writers", "Read own notes", "core.role");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, a, strlen(a), "writers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), mine, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), theirs, NULL));
  SaveTitle(catalog_, mine, a, "mine", NULL);
  SaveTitle(catalog_, theirs, b, "theirs", NULL);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request_, a, strlen(a)));
  memset(&query, 0, sizeof query);
  query.size = sizeof query;
  query.type_name = kNote;
  query.type_name_len = strlen(kNote);
  query.lang = "en";
  query.lang_len = 2;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_list(catalog_, request_, &query, &ids, &count));
  ASSERT_EQ(1u, count);
  EXPECT_STREQ(mine, ids[0]);
  gdefcore_access_free(catalog_, ids, count);
}

TEST_F(Access, GrantState) {
  GDEFCORE_Permission permission = Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, NULL);
  char ** grants = NULL;
  size_t count = 0;
  uint64_t epoch;
  DefineNote(catalog_, 0);
  Declare(catalog_, &permission);
  epoch = Epoch(catalog_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_grant(catalog_, "authenticated", 13, "Read notes", 10, NULL,
          0));
  EXPECT_EQ(epoch, Epoch(catalog_));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_grant(catalog_, "authenticated", 13, "Read notes", 10,
          GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
          strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED)));
  EXPECT_NE(epoch, Epoch(catalog_));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "authenticated", 13, &grants, &count));
  EXPECT_TRUE(Has(grants, count, "Read notes"));
  gdefcore_access_free(catalog_, grants, count);
  epoch = Epoch(catalog_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_grant(catalog_, "authenticated", 13, "Read notes", 10,
          "authenticated means something else",
          strlen("authenticated means something else")));
  EXPECT_EQ(epoch, Epoch(catalog_));
  {
    char who[GDEFCORE_PUBLIC_ID_LEN + 1];
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, who));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kNote, strlen(kNote), id, NULL));
    SaveTitle(catalog_, id, who, "seen", NULL);
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        ReadUntouched(catalog_, request_, id, "title"));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request_, who, strlen(who)));
    EXPECT_EQ("seen", Filtered(catalog_, request_, id, "title", NULL, NULL));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_principal_remove(catalog_, who, strlen(who)));
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        ReadUntouched(catalog_, request_, id, "title"));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request_, NULL, 0));
    epoch = Epoch(catalog_);
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_access_grant(catalog_, "anonymous", 9, "Read notes", 10, NULL,
            strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
    EXPECT_EQ(epoch, Epoch(catalog_));
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_access_grant(catalog_, "anonymous", 9, "Read notes", 10,
            "anonymous means something else",
            strlen("anonymous means something else")));
    EXPECT_EQ(epoch, Epoch(catalog_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "anonymous", 9, "Read notes", 10,
            GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
            strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
    EXPECT_EQ("seen", Filtered(catalog_, request_, id, "title", NULL, NULL));
  }
}

TEST_F(Access, ModuleGrant) {
  char ** grants = NULL;
  size_t count = 0;
  const char * name = "example";
  GDEFCORE_Changeset * changeset = NULL;
  int on = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_roles(catalog_, &grants, &count));
  gdefcore_access_free(catalog_, grants, count);
  memset(g_perms, 0, sizeof g_perms);
  g_perms[0].size = sizeof g_perms[0];
  g_perms[0].label = "example.zeta";
  g_perms[0].label_len = strlen(g_perms[0].label);
  g_perms[0].action = "read";
  g_perms[0].action_len = 4;
  g_perms[0].condition = GDEFCORE_ACCESS_ANY;
  g_perms[0].type_name = kNote;
  g_perms[0].type_name_len = strlen(kNote);
  g_perms[1].size = sizeof g_perms[1];
  g_perms[1].label = "example.note";
  g_perms[1].label_len = strlen(g_perms[1].label);
  g_perms[1].action = "read";
  g_perms[1].action_len = 4;
  g_perms[1].condition = GDEFCORE_ACCESS_ANY;
  g_perms[1].type_name = kNote;
  g_perms[1].type_name_len = strlen(kNote);
  memset(&g_man, 0, sizeof g_man);
  g_man.size = sizeof g_man;
  g_man.core_token = kCoreToken;
  g_man.core_token_len = strlen(kCoreToken);
  g_man.name = name;
  g_man.name_len = strlen(name);
  g_man.label = name;
  g_man.label_len = strlen(name);
  g_man.perms = g_perms;
  g_man.nperms = 2;
  g_current = &g_man;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, TestGuest));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "admin", 5, &grants, &count));
  EXPECT_FALSE(Has(grants, count, "example.note"));
  EXPECT_FALSE(Has(grants, count, "example.zeta"));
  gdefcore_access_free(catalog_, grants, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, changeset, name, strlen(name)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "admin", 5, &grants, &count));
  EXPECT_FALSE(Has(grants, count, "example.note"));
  gdefcore_access_free(catalog_, grants, count);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, "example", 7));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, changeset, name, strlen(name)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_apply(changeset, "example\nexample.zeta\nexample.note",
          strlen("example\nexample.zeta\nexample.note")));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_enabled(host_, request_, name, strlen(name), &on));
  EXPECT_EQ(0, on);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, changeset, name, strlen(name)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_apply(changeset, "example\nexample.note\nexample.zeta",
          strlen("example\nexample.note\nexample.zeta")));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_enabled(host_, request_, name, strlen(name), &on));
  EXPECT_EQ(1, on);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "admin", 5, &grants, &count));
  EXPECT_TRUE(Has(grants, count, "example.note"));
  EXPECT_TRUE(Has(grants, count, "example.zeta"));
  gdefcore_access_free(catalog_, grants, count);
}

TEST_F(Access, RenderKey) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Request * other = NULL;
  GDEFCORE_Permission any = Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, NULL);
  GDEFCORE_Permission own = Perm("Read own notes", "read", GDEFCORE_ACCESS_OWN, NULL);
  const uint8_t bytes_a[] = {'n', 'o', 't', '-', 'a', '-', 'h', 'a', 's', 'h',
      '-', 'n', 'a', 'm', 'e'};
  const uint8_t bytes_b[] = {'n', 'o', 't', '-', 'a', '-', 'h', 'a', 's', 'h',
      '-', 'n', 'a', 'm', 'f'};
  std::string left;
  std::string right;
  std::string with_bytes;
  std::string other_bytes;
  DefineNote(catalog_, 0);
  Declare(catalog_, &any);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog_, "readers", 7, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(catalog_, "viewers", 7, NULL));
  Grant(catalog_, "readers", "Read notes", "core.role");
  Grant(catalog_, "viewers", "Read notes", "core.role");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, a, strlen(a), "readers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, a, strlen(a), "viewers", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, b, strlen(b), "viewers", 7));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request_, a, strlen(a)));
  {
    size_t acting_len = 0;
    const char * acting =
        gdefcore_request_acting_principal(request_, &acting_len);
    EXPECT_EQ(nullptr, acting);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_acting_principal(request_, a, strlen(a)));
    acting = gdefcore_request_acting_principal(request_, &acting_len);
    ASSERT_NE(acting, nullptr);
    EXPECT_EQ(std::string(a), std::string(acting, acting_len));
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &other));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(other, b, strlen(b)));
  left = Key(catalog_, request_, NULL, NULL, 0);
  right = Key(catalog_, other, "live", NULL, 0);
  EXPECT_EQ(left, right);
  EXPECT_NE(std::string::npos, left.find("tenant:74\n"));
  EXPECT_NE(std::string::npos,
      left.find(std::string("\nepoch:") + std::to_string(Epoch(catalog_)) +
          "\n"));
  EXPECT_EQ(std::string::npos, left.find("readers"));
  EXPECT_EQ(std::string::npos, left.find("viewers"));
  EXPECT_NE(std::string::npos, left.find("\nedition:\n"));
  EXPECT_EQ(1, gdefcore_access_shared_cache(NULL, 0));
  EXPECT_EQ(1, gdefcore_access_shared_cache("live", 4));
  EXPECT_EQ(0, gdefcore_access_shared_cache("preview", 7));
  with_bytes = Key(catalog_, request_, "preview", bytes_a, sizeof bytes_a);
  other_bytes = Key(catalog_, request_, "preview", bytes_b, sizeof bytes_b);
  EXPECT_NE(with_bytes, other_bytes);
  EXPECT_EQ(std::string::npos, with_bytes.find("not-a-hash-name"));
  EXPECT_NE(std::string::npos, with_bytes.find("\noverlay:preview\n"));
  Declare(catalog_, &own);
  Grant(catalog_, "viewers", "Read own notes", "core.role");
  left = Key(catalog_, request_, "live", NULL, 0);
  right = Key(catalog_, other, "live", NULL, 0);
  EXPECT_NE(left, right);
  EXPECT_NE(std::string::npos, left.find(std::string("\nprincipal:") + a));
  if (strcmp(Plant(), "omit") == 0) {
    EXPECT_NE(OmitPrincipal(left), OmitPrincipal(right));
  }
  gdefcore_request_destroy(other);
}

TEST_F(Access, Revert) {
  char role[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Permission permission = Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, NULL);
  char ** grants = NULL;
  size_t count = 0;
  int risk = 0;
  DefineNote(catalog_, 0);
  Declare(catalog_, &permission);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_id(catalog_, "admin", 5, role));
  Grant(catalog_, "admin", "Read notes", "core.role");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "admin", 5, &grants, &count));
  EXPECT_TRUE(Has(grants, count, "Read notes"));
  gdefcore_access_free(catalog_, grants, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, role, strlen(role), NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_rate(changeset, &risk));
  EXPECT_EQ(GDEFCORE_RISK_HIGH, risk);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "core.role", 9));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "admin", 5, &grants, &count));
  EXPECT_FALSE(Has(grants, count, "Read notes"));
  gdefcore_access_free(catalog_, grants, count);
}

TEST_F(Access, Bypass) {
  char who[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char missing[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  DefineNote(catalog_, 0);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, who));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), id, NULL));
  SaveTitle(catalog_, id, who, "present", NULL);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(request_, who, strlen(who)));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(missing));
  EXPECT_EQ(ReadUntouched(catalog_, request_, id, "title"),
      ReadUntouched(catalog_, request_, missing, "title"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, ReadUntouched(catalog_, request_, id, "title"));
  if (strcmp(Plant(), "skip") == 0) {
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id,
            strlen(id), "en", 2, "title", 5, &texts, &lens, &count));
  }
}

TEST_F(Access, EighthRole) {
  char who[GDEFCORE_PUBLIC_ID_LEN + 1];
  char note[GDEFCORE_PUBLIC_ID_LEN + 1];
  const char * roles[8] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"};
  GDEFCORE_Permission permission =
      Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, NULL);
  int i;
  DefineNote(catalog_, 0);
  Declare(catalog_, &permission);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, who));
  for (i = 0; i < 8; i++) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, roles[i], strlen(roles[i]), NULL));
    if (i == 7) {
      Grant(catalog_, roles[i], "Read notes", "core.role");
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_principal_add_role(catalog_, who, strlen(who), roles[i],
            strlen(roles[i])));
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), note, NULL));
  SaveTitle(catalog_, note, who, "eighth", NULL);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request_, who, strlen(who)));
  EXPECT_EQ("eighth", Filtered(catalog_, request_, note, "title", NULL, NULL));
}

TEST_F(Access, LowRiskStage) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** grants = NULL;
  size_t count = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Value value;
  const char * text = "plain";
  size_t text_len = 5;
  DefineNote(catalog_, 0);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_roles(catalog_, &grants, &count));
  gdefcore_access_free(catalog_, grants, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, kNote, strlen(kNote), id, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "title";
  value.field_len = 5;
  value.texts = &text;
  value.text_lens = &text_len;
  value.count = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_stage_module_permission(changeset, "example", 7,
          "staged.note", 11, "read", 4, GDEFCORE_ACCESS_ANY, kNote,
          strlen(kNote), NULL, 0));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_grants(catalog_, "admin", 5, &grants, &count));
  EXPECT_FALSE(Has(grants, count, "staged.note"));
  gdefcore_access_free(catalog_, grants, count);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
