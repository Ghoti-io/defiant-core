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
 * Story 7's matrix, on the memory backend. One test per row.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage/projection.h>
#include <ghoti.io/defiant-storage/revision.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <string.h>

#include <string>
#include <vector>

namespace {

const char kTenant[] = "t";

GDEFCORE_Field TitleField() {
  GDEFCORE_Field field;
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = "title";
  field.name_len = 5;
  field.required = 1;
  field.many = 0;
  return field;
}

void DefineType(GDEFCORE_Catalog * catalog, const char * name, int kind) {
  GDEFCORE_Field field = TitleField();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog, name, strlen(name), kind, &field, 1));
}

void CreateEntity(GDEFCORE_Catalog * catalog, const char * type, char * id,
    uint64_t * row) {
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog, type, strlen(type), id, row));
}

void SaveTitle(GDEFCORE_Changeset * changeset, const char * id, const char * lang,
    const char * text) {
  const char * texts[1];
  size_t lens[1];
  GDEFCORE_Value value;
  texts[0] = text;
  lens[0] = strlen(text);
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "title";
  value.field_len = 5;
  value.texts = texts;
  value.text_lens = lens;
  value.count = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, id, strlen(id), lang, strlen(lang), &value,
          1));
}

std::string ReadTitle(GDEFCORE_Catalog * catalog, const GDEFCORE_Changeset * changeset,
    int view, const char * id, const char * lang, GDEFCORE_Result * out_rc) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, changeset, view, id,
      strlen(id), lang, strlen(lang), "title", 5, &texts, &lens, &count);
  if (out_rc != NULL) {
    *out_rc = rc;
  }
  if (rc != GDEFCORE_OK) {
    return std::string();
  }
  std::string value(texts[0], lens[0]);
  gdefcore_values_free(catalog, texts, lens, count);
  return value;
}

std::string ReadField(GDEFCORE_Catalog * catalog, const GDEFCORE_Changeset * changeset,
    int view, const char * id, const char * lang, const char * field,
    GDEFCORE_Result * out_rc) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, changeset, view, id,
      strlen(id), lang, strlen(lang), field, strlen(field), &texts, &lens,
      &count);
  if (out_rc != NULL) {
    *out_rc = rc;
  }
  if (rc != GDEFCORE_OK || count == 0) {
    return std::string();
  }
  std::string value(texts[0], lens[0]);
  gdefcore_values_free(catalog, texts, lens, count);
  return value;
}

std::string HyphenEvery4(const std::string & id) {
  std::string out;
  size_t i;
  for (i = 0; i < id.size(); i++) {
    if (i > 0 && i % 4 == 0) {
      out.push_back('-');
    }
    out.push_back(id[i]);
  }
  return out;
}

class Entity : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_;
  GDEFCORE_Catalog * catalog_;

  void SetUp() override {
    store_ = NULL;
    catalog_ = NULL;
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
            &catalog_));
  }

  void TearDown() override {
    gdefcore_catalog_destroy(catalog_);
    gdefstor_store_destroy(store_);
  }
};

}  // namespace

TEST(EntityId, Vector) {
  uint8_t raw[16];
  char out[GDEFCORE_PUBLIC_ID_LEN + 1];
  int i;
  for (i = 0; i < 16; i++) {
    raw[i] = (uint8_t)i;
  }
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_encode(raw, out));
  EXPECT_STREQ("00041061050R3GG28A1C60T3GFGB", out);
}

TEST_F(Entity, OldFieldLine) {
  GDEFSTOR_Write * write = NULL;
  GDEFSTOR_Column columns[4];
  char * name = NULL;
  size_t name_len = 0;
  int required = 0;
  int many = 0;
  int personal = 1;
  const char * fields = "title 1 0\n";
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_begin(store_, kTenant, 1, NULL, &write));
  memset(columns, 0, sizeof columns);
  columns[0].name = "kind";
  columns[0].name_len = 4;
  columns[0].value = (const uint8_t *)"content";
  columns[0].value_len = 7;
  columns[1].name = "fields";
  columns[1].name_len = 6;
  columns[1].value = (const uint8_t *)fields;
  columns[1].value_len = strlen(fields);
  columns[2].name = "id";
  columns[2].name_len = 2;
  columns[2].value = (const uint8_t *)"x";
  columns[2].value_len = 1;
  columns[3].name = "row";
  columns[3].name_len = 3;
  columns[3].value = (const uint8_t *)"1";
  columns[3].value_len = 1;
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_projection_put(write, "m", 1, "site.old", 8, columns, 4));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(write));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field(catalog_, "site.old", 8, 0, &name, &name_len, &required,
          &many));
  EXPECT_EQ(std::string("title"), std::string(name, name_len));
  EXPECT_EQ(1, required);
  EXPECT_EQ(0, many);
  gdefcore_text_free(catalog_, name);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_personal(catalog_, "site.old", 8, 0, &personal));
  EXPECT_EQ(0, personal);
  {
    size_t min_len = 9;
    size_t max_len = 9;
    int has_range = 1;
    int64_t range_min = 3;
    int64_t range_max = 4;
    char * pattern = (char *)0x1;
    size_t pattern_len = 4;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_field_constraints(catalog_, "site.old", 8, 0, &min_len,
            &max_len, &has_range, &range_min, &range_max, &pattern, &pattern_len));
    EXPECT_EQ(0u, min_len);
    EXPECT_EQ(0u, max_len);
    EXPECT_EQ(0, has_range);
    EXPECT_EQ(nullptr, pattern);
    EXPECT_EQ(0u, pattern_len);
  }
}

TEST_F(Entity, FieldConstraints) {
  GDEFCORE_Field field = TitleField();
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  size_t min_len = 0;
  size_t max_len = 0;
  int has_range = 0;
  int64_t range_min = 0;
  int64_t range_max = 0;
  char * pattern = NULL;
  size_t pattern_len = 0;
  field.min_len = 2;
  field.max_len = 8;
  field.has_range = 1;
  field.range_min = 10;
  field.range_max = 20;
  field.pattern = "a+";
  field.pattern_len = 2;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.bound", 10, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_changeset_destroy(changeset);
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, "site.bound", 10));
  gdefcore_changeset_destroy(parsed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_constraints(catalog_, "site.bound", 10, 0, &min_len,
          &max_len, &has_range, &range_min, &range_max, &pattern, &pattern_len));
  EXPECT_EQ(2u, min_len);
  EXPECT_EQ(8u, max_len);
  EXPECT_EQ(1, has_range);
  EXPECT_EQ(10, range_min);
  EXPECT_EQ(20, range_max);
  ASSERT_NE(nullptr, pattern);
  EXPECT_EQ(std::string("a+"), std::string(pattern, pattern_len));
  gdefcore_text_free(catalog_, pattern);
}

TEST_F(Entity, DraftRoundTrip) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  const char * texts[1];
  size_t lens[1];
  GDEFCORE_Value value;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  texts[0] = "Hello";
  lens[0] = 5;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "title";
  value.field_len = 5;
  value.texts = texts;
  value.text_lens = lens;
  value.count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save_draft(changeset, id, strlen(id), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_changeset_destroy(changeset);
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, NULL, 0));
  gdefcore_changeset_destroy(parsed);
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_DRAFT, id, "en", &rc));
  EXPECT_EQ(GDEFCORE_OK, rc);
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
}

TEST_F(Entity, PersonalChangeset) {
  GDEFCORE_Field field = TitleField();
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  int personal = 0;
  field.personal = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.person", 11, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_changeset_destroy(changeset);
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, "site.person", 11));
  gdefcore_changeset_destroy(parsed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_personal(catalog_, "site.person", 11, 0, &personal));
  EXPECT_EQ(1, personal);
}

TEST_F(Entity, Define) {
  int kind = 0;
  char * name = NULL;
  size_t name_len = 0;
  int required = 0;
  int many = 0;
  size_t count = 0;
  uint64_t epoch = 99;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  DefineType(catalog_, "site.settings", GDEFCORE_TYPE_CONFIG);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.note", 9, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_kind(catalog_, "site.settings", 13, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONFIG, kind);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_count(catalog_, "site.note", 9, &count));
  EXPECT_EQ(1u, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field(catalog_, "site.note", 9, 0, &name, &name_len,
          &required, &many));
  EXPECT_EQ(std::string("title"), std::string(name, name_len));
  EXPECT_EQ(1, required);
  EXPECT_EQ(0, many);
  gdefcore_text_free(catalog_, name);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_type_define(catalog_, "site.note", 9, GDEFCORE_TYPE_CONFIG, NULL,
          0));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.note", 9, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
}

TEST_F(Entity, Create) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  EXPECT_GT(row, 0u);
  EXPECT_EQ(GDEFCORE_PUBLIC_ID_LEN, strlen(id));
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_create(catalog_, "core.entity_type", 16, id, &row));
}

TEST_F(Entity, BadId) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  std::string folded;
  std::string broken;
  size_t i;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  folded = id;
  for (i = 0; i < folded.size(); i++) {
    if (folded[i] >= 'A' && folded[i] <= 'Z') {
      folded[i] = (char)(folded[i] - 'A' + 'a');
      break;
    }
  }
  folded.insert(4, "-");
  for (i = 0; i < folded.size(); i++) {
    if (folded[i] == '0') {
      folded[i] = 'O';
      break;
    }
  }
  for (i = 0; i < folded.size(); i++) {
    if (folded[i] == '1') {
      folded[i] = 'L';
      break;
    }
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_id_canonical(folded.data(), folded.size(), canon));
  EXPECT_STREQ(id, canon);
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, folded.c_str(), "en",
          &rc));
  EXPECT_EQ(GDEFCORE_OK, rc);
  broken = id;
  broken[GDEFCORE_PUBLIC_ID_LEN - 1] =
      broken[GDEFCORE_PUBLIC_ID_LEN - 1] == '0' ? '1' : '0';
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, broken.c_str(), "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
}

TEST_F(Entity, Save) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  GDEFCORE_Value extra;
  const char * texts[1];
  size_t lens[1];
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(changeset, id, strlen(id), "", 0, NULL, 0));
  memset(&extra, 0, sizeof extra);
  extra.size = sizeof extra;
  extra.field = "body";
  extra.field_len = 4;
  texts[0] = "nope";
  lens[0] = 4;
  extra.texts = texts;
  extra.text_lens = lens;
  extra.count = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, &extra, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, NULL, 0));
  SaveTitle(changeset, id, "en", "Hello");
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, &extra, 1));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, changeset, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, SecondLanguage) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  SaveTitle(changeset, id, "fr", "Bonjour");
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, changeset, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  EXPECT_EQ("Bonjour",
      ReadTitle(catalog_, changeset, GDEFCORE_VIEW_PUBLISHED, id, "fr", &rc));
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, Preview) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char other[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  GDEFCORE_Changeset * first = NULL;
  GDEFCORE_Changeset * second = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  CreateEntity(catalog_, "site.note", other, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &first));
  SaveTitle(first, other, "en", "Published");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(first, NULL, 0));
  gdefcore_changeset_destroy(first);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &second));
  SaveTitle(second, id, "en", "Draft");
  EXPECT_EQ("Draft",
      ReadTitle(catalog_, second, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  EXPECT_EQ("Published",
      ReadTitle(catalog_, second, GDEFCORE_VIEW_PUBLISHED, other, "en", &rc));
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(1u, epoch);
  gdefcore_changeset_destroy(second);
}

TEST_F(Entity, Diff) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  char * text = NULL;
  size_t len = 0;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Bonjour");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_diff(changeset, &text, &len));
  EXPECT_EQ(std::string("en title: Hello -> Bonjour"), std::string(text, len));
  gdefcore_text_free(catalog_, text);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, LowApply) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  int risk = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_rate(changeset, &risk));
  EXPECT_EQ(GDEFCORE_RISK_LOW, risk);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "ignored", 7));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(1u, epoch);
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_DRAFT, id, "en", &rc));
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, HighApply) {
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Field field = TitleField();
  int kind = 0;
  int risk = 0;
  uint64_t epoch = 99;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.page", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_rate(changeset, &risk));
  EXPECT_EQ(GDEFCORE_RISK_HIGH, risk);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, NULL, 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_type_kind(catalog_, "site.page", 9, &kind));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_apply(changeset, "site.note", 9));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_type_kind(catalog_, "site.page", 9, &kind));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "site.page", 9));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.page", 9, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(1u, epoch);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, Conflict) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * first = NULL;
  GDEFCORE_Changeset * second = NULL;
  const char * names = NULL;
  size_t names_len = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &first));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &second));
  SaveTitle(first, id, "en", "Hello");
  SaveTitle(second, id, "en", "Bonjour");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(first, NULL, 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(second, NULL, 0));
  names = gdefcore_changeset_conflict(second, &names_len);
  ASSERT_NE(names, nullptr);
  EXPECT_EQ(std::string(id), std::string(names, names_len));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  gdefcore_changeset_destroy(first);
  gdefcore_changeset_destroy(second);
}

TEST_F(Entity, Rebase) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t seq = 99;
  GDEFCORE_Changeset * first = NULL;
  GDEFCORE_Changeset * second = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &first));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &second));
  SaveTitle(first, id, "en", "Hello");
  SaveTitle(second, id, "en", "Bonjour");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(first, NULL, 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(second, NULL, 0));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_rebase(second));
  EXPECT_EQ(1u, gdefcore_changeset_epoch(second));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_base_seq(second, id, strlen(id), &seq));
  EXPECT_EQ(1u, seq);
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  EXPECT_EQ("Bonjour",
      ReadTitle(catalog_, second, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  gdefcore_changeset_destroy(first);
  gdefcore_changeset_destroy(second);
}

TEST(EntityRollback, PortRefusesAppend) {
  GDEFSTOR_Limits limits;
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Changeset * changeset = NULL;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  GDEFCORE_Result rc = GDEFCORE_OK;
  gdefstor_limits_default(&limits);
  limits.max_revisions = 2;
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, &limits, &store));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store, (const uint8_t *)kTenant, 1, NULL, NULL,
          &catalog));
  DefineType(catalog, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Bonjour");
  EXPECT_EQ(GDEFCORE_ERR_LIMIT, gdefcore_changeset_apply(changeset, NULL, 0));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog, &epoch));
  EXPECT_EQ(1u, epoch);
  EXPECT_EQ("Hello",
      ReadTitle(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  gdefcore_changeset_destroy(changeset);
  gdefcore_catalog_destroy(catalog);
  gdefstor_store_destroy(store);
}

TEST_F(Entity, Revert) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Bonjour");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, id, strlen(id), NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, RevertFirst) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char row_text[32];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFSTOR_Revision * revision = NULL;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, id, strlen(id), NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_DRAFT, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  snprintf(row_text, sizeof row_text, "%llu", (unsigned long long)row);
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_revision_get(store_, kTenant, 1, row_text, strlen(row_text), 1,
          &bytes, &len));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_revision_parse(bytes, len, NULL, NULL, &revision));
  EXPECT_EQ(1u, gdefstor_revision_seq(revision));
  gdefstor_revision_free(revision);
  gdefstor_bytes_free(NULL, bytes);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Again");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_base_seq(changeset, id, strlen(id), &row));
  EXPECT_EQ(1u, row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_revision_get(store_, kTenant, 1, row_text, strlen(row_text), 2,
          &bytes, &len));
  gdefstor_bytes_free(NULL, bytes);
  EXPECT_EQ(GDEFSTOR_ERR_INVALID,
      gdefstor_revision_get(store_, kTenant, 1, row_text, strlen(row_text), 3,
          &bytes, &len));
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, Patch) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  GDEFCORE_Patch bad;
  size_t count = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  const char * bad_id = "entity/NOT-A-PUBLIC-ID/op";
  const uint8_t binary[] = {0xff, 0xfe};
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, parsed, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  gdefcore_changeset_destroy(parsed);
  gdefcore_patch_free(catalog_, files, count);
  gdefcore_changeset_destroy(changeset);
  memset(&bad, 0, sizeof bad);
  bad.size = sizeof bad;
  bad.path = (char *)"..";
  bad.path_len = 2;
  bad.bytes = (uint8_t *)"x";
  bad.len = 1;
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_changeset_parse(catalog_, &bad, 1, NULL, &parsed));
  bad.path = (char *)"/tmp/x";
  bad.path_len = 6;
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_changeset_parse(catalog_, &bad, 1, NULL, &parsed));
  bad.path = (char *)bad_id;
  bad.path_len = strlen(bad_id);
  bad.bytes = (uint8_t *)"save";
  bad.len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_parse(catalog_, &bad, 1, NULL, &parsed));
  bad.path = (char *)"format";
  bad.path_len = 6;
  bad.bytes = (uint8_t *)binary;
  bad.len = 2;
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_changeset_parse(catalog_, &bad, 1, NULL, &parsed));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
}

TEST_F(Entity, Key) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char row_text[32];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFSTOR_Revision * revision = NULL;
  const char * entity = NULL;
  size_t entity_len = 0;
  GDEFSTOR_Projection * index = NULL;
  GDEFSTOR_Write * write = NULL;
  const char missing[] =
      "{\"format\":\"defiant-revision/1\",\"seq\":1,\"entity\":\"post1\","
      "\"type\":\"site.note\",\"lang\":{},\"body\":\"\"}";
  size_t i;
  int saw_row = 0;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  snprintf(row_text, sizeof row_text, "%llu", (unsigned long long)row);
  EXPECT_EQ(GDEFSTOR_ERR_INVALID,
      gdefstor_revision_get(store_, kTenant, 1, id, strlen(id), 1, &bytes, &len));
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_revision_get(store_, kTenant, 1, row_text, strlen(row_text), 1,
          &bytes, &len));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_revision_parse(bytes, len, NULL, NULL, &revision));
  EXPECT_EQ(row, gdefstor_revision_row(revision));
  entity = gdefstor_revision_entity(revision, &entity_len);
  EXPECT_EQ(std::string(id), std::string(entity, entity_len));
  gdefstor_revision_free(revision);
  gdefstor_bytes_free(NULL, bytes);
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_projection_get(store_, kTenant, 1, "i", 1, id, strlen(id), &index));
  for (i = 0; i < gdefstor_projection_column_count(index); i++) {
    GDEFSTOR_Column column;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_projection_column(index, i, &column));
    if (column.name_len == 3 && memcmp(column.name, "row", 3) == 0) {
      EXPECT_EQ(std::string(row_text),
          std::string((const char *)column.value, column.value_len));
      saw_row = 1;
    }
  }
  EXPECT_EQ(1, saw_row);
  gdefstor_projection_free(index);
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_write_begin(store_, kTenant, 1, NULL, &write));
  EXPECT_EQ(GDEFSTOR_ERR_CORRUPT,
      gdefstor_revision_append(write, (const uint8_t *)missing, strlen(missing)));
  gdefstor_write_abort(write);
  EXPECT_EQ(GDEFSTOR_ERR_INVALID,
      gdefstor_revision_get(store_, kTenant, 1, "99", 2, 1, &bytes, &len));
}

TEST_F(Entity, ConfigSaveNeedsTypeName) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  int risk = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.settings", GDEFCORE_TYPE_CONFIG);
  CreateEntity(catalog_, "site.settings", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_rate(changeset, &risk));
  EXPECT_EQ(GDEFCORE_RISK_HIGH, risk);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, NULL, 0));
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_apply(changeset, "site.settings", 13));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(1u, epoch);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, PatchSavesRequiredAfterOptional) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Field fields[2];
  GDEFCORE_Value values[2];
  const char * title_texts[1];
  const char * body_texts[1];
  size_t title_lens[1];
  size_t body_lens[1];
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  memset(fields, 0, sizeof fields);
  fields[0] = TitleField();
  fields[1].size = sizeof fields[1];
  fields[1].name = "body";
  fields[1].name_len = 4;
  fields[1].required = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.note", 9, GDEFCORE_TYPE_CONTENT,
          fields, 2));
  CreateEntity(catalog_, "site.note", id, &row);
  title_texts[0] = "Hello";
  title_lens[0] = 5;
  body_texts[0] = "World";
  body_lens[0] = 5;
  memset(values, 0, sizeof values);
  values[0].size = sizeof values[0];
  values[0].field = "title";
  values[0].field_len = 5;
  values[0].texts = title_texts;
  values[0].text_lens = title_lens;
  values[0].count = 1;
  values[1].size = sizeof values[1];
  values[1].field = "body";
  values[1].field_len = 4;
  values[1].texts = body_texts;
  values[1].text_lens = body_lens;
  values[1].count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, values, 2));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, parsed, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  EXPECT_EQ("World",
      ReadField(catalog_, parsed, GDEFCORE_VIEW_PUBLISHED, id, "en", "body",
          &rc));
  gdefcore_changeset_destroy(parsed);
  gdefcore_patch_free(catalog_, files, count);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, HyphenatedIdParses) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  std::string dashed;
  std::string from;
  std::vector<std::string> paths;
  std::vector<GDEFCORE_Patch> copy;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  dashed = HyphenEvery4(id);
  from = std::string("entity/") + id + "/";
  paths.resize(count);
  copy.resize(count);
  for (i = 0; i < count; i++) {
    paths[i].assign(files[i].path, files[i].path_len);
    size_t at = paths[i].find(from);
    if (at != std::string::npos) {
      paths[i].replace(at, from.size(), std::string("entity/") + dashed + "/");
    }
    copy[i] = files[i];
    copy[i].path = &paths[i][0];
    copy[i].path_len = paths[i].size();
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, copy.data(), count, NULL, &parsed));
  EXPECT_EQ("Hello",
      ReadTitle(catalog_, parsed, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  gdefcore_changeset_destroy(parsed);
  gdefcore_patch_free(catalog_, files, count);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, TypeFileMustMatch) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  for (i = 0; i < count; i++) {
    if (files[i].path_len >= 5 &&
        memcmp(files[i].path + files[i].path_len - 5, "/type", 5) == 0) {
      ASSERT_EQ(9u, files[i].len);
      memcpy(files[i].bytes, "site.page", 9);
    }
  }
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  gdefcore_patch_free(catalog_, files, count);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, UnknownEntitySuffix) {
  GDEFCORE_Patch file;
  GDEFCORE_Changeset * parsed = NULL;
  const char * path = "entity/00041061050R3GG28A1C60T3GFGB/nope";
  memset(&file, 0, sizeof file);
  file.size = sizeof file;
  file.path = (char *)path;
  file.path_len = strlen(path);
  file.bytes = (uint8_t *)"x";
  file.len = 1;
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_changeset_parse(catalog_, &file, 1, NULL, &parsed));
}

TEST_F(Entity, LanguageShape) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  std::string long_lang(36, 'a');
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(changeset, id, strlen(id), long_lang.c_str(),
          long_lang.size(), NULL, 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(changeset, id, strlen(id), "en_US", 5, NULL, 0));
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, ManyValuesRoundTrip) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Field field;
  GDEFCORE_Value value;
  const char * texts[2];
  size_t lens[2];
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  char ** out = NULL;
  size_t * out_lens = NULL;
  size_t count = 0;
  size_t nfiles = 0;
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = "tag";
  field.name_len = 3;
  field.required = 1;
  field.many = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.note", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  CreateEntity(catalog_, "site.note", id, &row);
  texts[0] = "a";
  texts[1] = "b";
  lens[0] = 1;
  lens[1] = 1;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "tag";
  value.field_len = 3;
  value.texts = texts;
  value.text_lens = lens;
  value.count = 2;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &nfiles));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, nfiles, NULL, &parsed));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_values(catalog_, parsed, GDEFCORE_VIEW_PUBLISHED, id,
          strlen(id), "en", 2, "tag", 3, &out, &out_lens, &count));
  EXPECT_EQ(2u, count);
  gdefcore_values_free(catalog_, out, out_lens, count);
  gdefcore_changeset_destroy(parsed);
  gdefcore_patch_free(catalog_, files, nfiles);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, DefineExistingPublishesFields) {
  GDEFCORE_Field fields[2];
  GDEFCORE_Changeset * changeset = NULL;
  size_t count = 0;
  uint64_t epoch = 99;
  memset(fields, 0, sizeof fields);
  fields[0] = TitleField();
  fields[1].size = sizeof fields[1];
  fields[1].name = "body";
  fields[1].name_len = 4;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.note", 9, GDEFCORE_TYPE_CONTENT,
          &fields[0], 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(0u, epoch);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.note", 9, GDEFCORE_TYPE_CONTENT,
          fields, 2));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "site.note", 9));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_field_count(catalog_, "site.note", 9, &count));
  EXPECT_EQ(2u, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(1u, epoch);
  gdefcore_changeset_destroy(changeset);
}

TEST_F(Entity, ActorOnProjection) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char row_text[32];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFSTOR_Projection * projection = NULL;
  const char * actor = "00041061050R3GG28A1C60T3GFGB";
  int saw = 0;
  size_t i;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_prepare(catalog_, "nope", 4, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, actor, strlen(actor), &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  snprintf(row_text, sizeof row_text, "%llu", (unsigned long long)row);
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_projection_get(store_, kTenant, 1, "p:site.note", 11, row_text,
          strlen(row_text), &projection));
  for (i = 0; i < gdefstor_projection_column_count(projection); i++) {
    GDEFSTOR_Column column;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_projection_column(projection, i, &column));
    if (column.name_len == 5 && memcmp(column.name, "actor", 5) == 0) {
      EXPECT_EQ(std::string(actor),
          std::string((const char *)column.value, column.value_len));
      saw = 1;
    }
  }
  EXPECT_EQ(1, saw);
  gdefstor_projection_free(projection);
}

TEST_F(Entity, ConfirmationSortsMachineNames) {
  GDEFCORE_Field field = TitleField();
  GDEFCORE_Changeset * changeset = NULL;
  const char * wrong = "site.page\nsite.note";
  const char * right = "site.note\nsite.page";
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.page", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.note", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_apply(changeset, wrong, strlen(wrong)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_apply(changeset, right, strlen(right)));
  gdefcore_changeset_destroy(changeset);
}

TEST(EntityId, FoldsI) {
  char folded[] = "00041061050R3GG28A1C60T3GFGB";
  char out[GDEFCORE_PUBLIC_ID_LEN + 1];
  folded[4] = 'I';
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_canonical(folded, GDEFCORE_PUBLIC_ID_LEN, out));
  EXPECT_STREQ("00041061050R3GG28A1C60T3GFGB", out);
}

TEST_F(Entity, TypeAndClearPatchesRoundTrip) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  int kind = 0;
  GDEFCORE_Field field = TitleField();
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.widget", 11,
          GDEFCORE_TYPE_CONTENT, &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_changeset_destroy(changeset);
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, "site.widget", 11));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.widget", 11, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
  gdefcore_changeset_destroy(parsed);
  CreateEntity(catalog_, "site.widget", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, id, strlen(id), NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_changeset_destroy(changeset);
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, NULL, 0));
  gdefcore_changeset_destroy(parsed);
  ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
}

TEST_F(Entity, MachineNameDots) {
  GDEFCORE_Field field = TitleField();
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_type_define(catalog_, "note", 4, GDEFCORE_TYPE_CONTENT, &field,
          1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_type_define(catalog_, "site.note.extra", 15, GDEFCORE_TYPE_CONTENT,
          &field, 1));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
