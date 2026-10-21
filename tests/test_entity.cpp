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
#include <ghoti.io/defiant-storage/model.h>
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

/* A type is a record (`core.type`, story S6b) in one format: one that is not
 * that format is corrupt, never read as a type with fewer facts. (The old
 * projection's field lines, read with defaults for the members they lacked,
 * went with the projection.) */
TEST_F(Entity, ATypeRecordInAnotherFormatIsCorrupt) {
  GDEFSTOR_Write * write = NULL;
  const char * bad = "defiant-core-type/0\nkind content\n";
  int kind = 0;
  size_t count = 0;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_begin(store_, kTenant, 1, NULL, &write));
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_record_put(write, "core.type", 9, "site.old", 8,
          "core/1", 6,
          (const uint8_t *)bad, strlen(bad)));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(write));
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT, gdefcore_type_kind(catalog_, "site.old", 8, &kind));
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_type_field_count(catalog_, "site.old", 8, &count));
  /* control: a defined type reads */
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  EXPECT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.note", 9, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
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

/* A field may be called kind: its file ends in /kind like a type's own. */
TEST_F(Entity, FieldNamedKind) {
  GDEFCORE_Field fields[2];
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  size_t nfields = 0;
  int kind = 0;
  fields[0] = TitleField();
  fields[1] = TitleField();
  fields[1].name = "kind";
  fields[1].name_len = 4;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.kinded", 11,
          GDEFCORE_TYPE_CONFIG, fields, 2));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  /* The wire form has both: the type's kind and a field of that name. */
  bool type_kind = false;
  bool field_kind = false;
  for (size_t i = 0; i < count; i++) {
    std::string path(files[i].path, files[i].path_len);
    type_kind = type_kind || path == "type/site.kinded/kind";
    field_kind = field_kind || path == "type/site.kinded/field/kind";
  }
  EXPECT_TRUE(type_kind);
  EXPECT_TRUE(field_kind);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_changeset_destroy(changeset);
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, "site.kinded", 11));
  gdefcore_changeset_destroy(parsed);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.kinded", 11, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONFIG, kind);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_count(catalog_, "site.kinded", 11, &nfields));
  EXPECT_EQ(2u, nfields);
}

/* A hyphen is allowed in the local part of a type name, and nowhere else. */
TEST_F(Entity, HyphenInTypeName) {
  GDEFCORE_Field field = TitleField();
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  int kind = 0;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.a-b", 8, GDEFCORE_TYPE_CONFIG, &field, 1));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.-ab", 8, GDEFCORE_TYPE_CONFIG, &field, 1));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.ab-", 8, GDEFCORE_TYPE_CONFIG, &field, 1));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "si-te.ab", 8, GDEFCORE_TYPE_CONFIG, &field, 1));
  /* Control: the name without a hyphen was always fine. */
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.ab", 7, GDEFCORE_TYPE_CONFIG, &field, 1));
  /* And a changeset carries it through its wire form. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.c-d", 8, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_changeset_destroy(changeset);
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, "site.c-d", 8));
  gdefcore_changeset_destroy(parsed);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.c-d", 8, &kind));
  EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
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
  /* A personal field with no subject reference takes the entity's own
   * subject, which only a type whose entities are subjects has (story S7):
   * declared so, and carried through the patch form. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_define(changeset, "site.person", 11, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(changeset, "site.person", 11,
          GDEFCORE_TYPE_CONTENT | GDEFCORE_TYPE_SUBJECTS, &field, 1));
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
  {
    int subjects = 0;
    int kind = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_subjects(catalog_, "site.person", 11, &subjects));
    EXPECT_EQ(1, subjects);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog_, "site.person", 11, &kind));
    EXPECT_EQ(GDEFCORE_TYPE_CONTENT, kind);
  }
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
  row = 99;
  CreateEntity(catalog_, "site.note", id, &row);
  EXPECT_EQ(0u, row);   /* the row is the port's, made at the first save */
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

/* The port refuses a write the core limits allowed (more languages than the
 * port keeps): the changeset rolls back whole, and the epoch does not move. */
TEST(EntityRollback, PortRefusesTheWrite) {
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Limits limits;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  GDEFCORE_Result rc = GDEFCORE_OK;
  gdefcore_limits_default(&limits);
  limits.max_languages = 2 * GDEFSTOR_MODEL_MAX_LANGUAGES;
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store, (const uint8_t *)kTenant, 1, &limits, NULL,
          &catalog));
  DefineType(catalog, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog, &epoch));
  EXPECT_EQ(1u, epoch);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &changeset));
  for (int i = 0; i <= GDEFSTOR_MODEL_MAX_LANGUAGES; i++) {
    char lang[3] = {(char)('a' + i / 26), (char)('a' + i % 26), '\0'};
    SaveTitle(changeset, id, lang, "Many");
  }
  EXPECT_EQ(GDEFCORE_ERR_LIMIT, gdefcore_changeset_apply(changeset, NULL, 0));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog, &epoch));
  EXPECT_EQ(1u, epoch);
  EXPECT_EQ("Hello",
      ReadTitle(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
  gdefcore_changeset_destroy(changeset);
  gdefcore_catalog_destroy(catalog);
  gdefstor_store_destroy(store);
}

/* A type's record is written in the write of the changeset that defines it
 * (AD-31: a system record has no write of its own), so a changeset the port
 * refuses leaves no type behind. */
TEST(EntityRollback, ATypeRecordIsWrittenInItsChangesetsWrite) {
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Limits limits;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t epoch = 99;
  int kind = 0;
  GDEFCORE_Field field = TitleField();
  gdefcore_limits_default(&limits);
  limits.max_languages = 2 * GDEFSTOR_MODEL_MAX_LANGUAGES;
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store, (const uint8_t *)kTenant, 1, &limits, NULL,
          &catalog));
  DefineType(catalog, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog, &epoch));
  const uint64_t before = epoch;
  for (int refused = 1; refused >= 0; refused--) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &changeset));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_define(changeset, "site.extra", 10,
            GDEFCORE_TYPE_CONTENT, &field, 1));
    for (int i = 0; i <= (refused ? GDEFSTOR_MODEL_MAX_LANGUAGES : 0); i++) {
      char lang[3] = {(char)('a' + i / 26), (char)('a' + i % 26), '\0'};
      SaveTitle(changeset, id, lang, "Many");
    }
    GDEFCORE_Result rc = gdefcore_changeset_apply(changeset, "site.extra", 10);
    gdefcore_changeset_destroy(changeset);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog, &epoch));
    if (refused) {
      EXPECT_EQ(GDEFCORE_ERR_LIMIT, rc);
      EXPECT_EQ(GDEFCORE_ERR_INVALID,
          gdefcore_type_kind(catalog, "site.extra", 10, &kind));
      EXPECT_EQ(before, epoch);
    } else {
      /* control: the same changeset, which the port takes, defines it */
      EXPECT_EQ(GDEFCORE_OK, rc);
      EXPECT_EQ(GDEFCORE_OK, gdefcore_type_kind(catalog, "site.extra", 10, &kind));
      EXPECT_EQ(before + 1, epoch);
    }
  }
  gdefcore_catalog_destroy(catalog);
  gdefstor_store_destroy(store);
}

/* A field's logical type, its scale and the index hint travel in a patch
 * (story S6b): a definition parsed from its own serialization declares the
 * same field types. Control: a text field stays text. */
TEST_F(Entity, ATypesFieldTypesRoundTripThroughAPatch) {
  GDEFCORE_Field f[4];
  memset(f, 0, sizeof f);
  const char * names[4] = {"title", "rank", "price", "when"};
  const int types[4] = {0, GDEFSTOR_FIELD_INTEGER, GDEFSTOR_FIELD_DECIMAL,
      GDEFSTOR_FIELD_DATETIME};
  for (int i = 0; i < 4; i++) {
    f[i].size = sizeof f[i];
    f[i].name = names[i];
    f[i].name_len = strlen(names[i]);
    f[i].type = types[i];
    f[i].indexed = i % 2;
  }
  f[2].scale = 2;
  f[3].many = 1;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Changeset * parsed = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(cs, "site.typed", 10, GDEFCORE_TYPE_CONTENT, f, 4));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(cs, &files, &count));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  gdefcore_patch_free(catalog_, files, count);
  gdefcore_changeset_destroy(cs);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, "site.typed", 10));
  gdefcore_changeset_destroy(parsed);
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_field_count(catalog_, "site.typed", 10, &n));
  ASSERT_EQ(4u, n);
  for (size_t k = 0; k < n; k++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int type = -1;
    int scale = -1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_field(catalog_, "site.typed", 10, k, &name,
                               &name_len, &required, &many));
    std::string got(name, name_len);
    gdefcore_text_free(catalog_, name);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_field_type(catalog_, "site.typed", 10, k, &type, &scale));
    size_t i = 0;
    while (i < 4 && got != names[i]) {
      i++;
    }
    ASSERT_LT(i, 4u) << got;
    EXPECT_EQ(types[i] == 0 ? GDEFSTOR_FIELD_TEXT : types[i], type) << got;
    EXPECT_EQ(i == 2 ? 2 : 0, scale) << got;
    EXPECT_EQ(i == 3 ? 1 : 0, many) << got;
  }
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
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = GDEFCORE_OK;
  size_t count = 0;
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
  /* The revision is still recorded: a clear is a soft delete. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_revision_count(catalog_, id, strlen(id), &count));
  EXPECT_EQ(1u, count);
  {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision_values(catalog_, id, strlen(id), 1, "en", 2,
            "title", 5, &texts, &lens, &n));
    ASSERT_EQ(1u, n);
    EXPECT_EQ("Hello", std::string(texts[0], lens[0]));
    gdefcore_values_free(catalog_, texts, lens, n);
  }
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Again");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_base_seq(changeset, id, strlen(id), &row));
  EXPECT_EQ(1u, row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_revision_count(catalog_, id, strlen(id), &count));
  EXPECT_EQ(2u, count);
  EXPECT_EQ("Again",
      ReadTitle(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id, "en", &rc));
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

/* An entity is the port's record, found by its public id; its revisions are
 * the port's history of it. A public id nobody created is no record. */
TEST_F(Entity, TheEntityIsThePortsRecord) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char other[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFSTOR_Entity * e = NULL;
  GDEFSTOR_History * h = NULL;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_entity_get(store_, kTenant, 1, id, strlen(id), &e));
  GDEFSTOR_EntityInfo info;
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_entity_info(e, &info));
  EXPECT_EQ("site.note", std::string(info.type, info.type_len));
  EXPECT_EQ(std::string(id), std::string(info.public_id, info.public_id_len));
  EXPECT_EQ(1u, info.revision);
  EXPECT_EQ(1, info.published);
  gdefstor_entity_free(e);
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_entity_history(store_, kTenant, 1, id, strlen(id), "en", 2, &h));
  EXPECT_EQ(1u, gdefstor_history_revision_count(h));
  gdefstor_history_free(h);
  /* control: an id never created */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(other));
  EXPECT_EQ(GDEFSTOR_ERR_INVALID,
      gdefstor_entity_get(store_, kTenant, 1, other, strlen(other), &e));
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

TEST_F(Entity, TheActorIsTheRevisionsAuthor) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  const char * actor = "00041061050R3GG28A1C60T3GFGB";
  GDEFSTOR_History * h = NULL;
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_prepare(catalog_, "nope", 4, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, actor, strlen(actor), &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_entity_history(store_, kTenant, 1, id, strlen(id), "en", 2, &h));
  ASSERT_EQ(1u, gdefstor_history_revision_count(h));
  GDEFSTOR_RevisionInfo r;
  memset(&r, 0, sizeof r);
  r.size = sizeof r;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_history_revision(h, 0, &r));
  EXPECT_EQ(std::string(actor), std::string(r.who, r.who_len));
  gdefstor_history_free(h);
}

TEST_F(Entity, RevisionActors) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  uint64_t seq = 0;
  size_t count = 99;
  size_t actor_n = 0;
  char * actor = NULL;
  GDEFCORE_Changeset * changeset = NULL;
  const char * ada = "00041061050R3GG28A1C60T3GFGB";
  char bob[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(bob));
  DefineType(catalog_, "site.note", GDEFCORE_TYPE_CONTENT);
  CreateEntity(catalog_, "site.note", id, &row);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_count(catalog_, id, strlen(id), &count));
  EXPECT_EQ(0u, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, ada, strlen(ada), &changeset));
  SaveTitle(changeset, id, "en", "Hello");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  SaveTitle(changeset, id, "en", "Bonjour");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, bob, strlen(bob), &changeset));
  SaveTitle(changeset, id, "en", "Hola");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_count(catalog_, id, strlen(id), &count));
  EXPECT_EQ(3u, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_at(catalog_, id, strlen(id), 0, &seq, &actor,
          &actor_n));
  EXPECT_EQ(1u, seq);
  ASSERT_NE(actor, nullptr);
  EXPECT_EQ(std::string(ada), std::string(actor, actor_n));
  gdefcore_text_free(catalog_, actor);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_at(catalog_, id, strlen(id), 1, &seq, &actor,
          &actor_n));
  EXPECT_EQ(2u, seq);
  EXPECT_EQ(actor, nullptr);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_at(catalog_, id, strlen(id), 2, &seq, &actor,
          &actor_n));
  EXPECT_EQ(3u, seq);
  ASSERT_NE(actor, nullptr);
  EXPECT_EQ(std::string(bob), std::string(actor, actor_n));
  gdefcore_text_free(catalog_, actor);
  seq = 77;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_revision_at(catalog_, id, strlen(id), 3, &seq, &actor,
          &actor_n));
  EXPECT_EQ(77u, seq);
  count = 99;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_revision_count(catalog_, "nope", 4, &count));
  EXPECT_EQ(99u, count);
}

TEST_F(Entity, ManyFieldClears) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t row = 0;
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Value value;
  GDEFCORE_Field field;
  const char * two[2] = {"a", "b"};
  size_t lens[2] = {1, 1};
  char ** texts = NULL;
  size_t * out_lens = NULL;
  size_t count = 0;
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = "tags";
  field.name_len = 4;
  field.many = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.tagged", 11, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  CreateEntity(catalog_, "site.tagged", id, &row);
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = "tags";
  value.field_len = 4;
  value.texts = two;
  value.text_lens = lens;
  value.count = 2;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  value.texts = NULL;
  value.text_lens = NULL;
  value.count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  /* A cleared many field reads as absent, the same as one never set. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id,
          strlen(id), "en", 2, "tags", 4, &texts, &out_lens, &count));
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
