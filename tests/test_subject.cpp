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
 * Story 12's matrix, on the memory backend. One test per row.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage/projection.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#include <ghoti.io/defiant-storage/store.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>

namespace {

const char kPlain[] = "platypus-secret";
const char kField[] = "name";

bool HasBytes(const uint8_t * hay, size_t n, const void * needle, size_t m) {
  size_t i;
  if (needle == NULL || m == 0 || m > n) {
    return false;
  }
  for (i = 0; i + m <= n; i++) {
    if (memcmp(hay + i, needle, m) == 0) {
      return true;
    }
  }
  return false;
}

class Subject : public ::testing::Test {
 protected:
  GDEFSTOR_Store * registry_;
  GDEFSTOR_Store * site_;
  GDEFSTOR_Store * side_;
  GDEFCORE_Inst * inst_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Subjects * subjects_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t storage_[16];
  char tenant_[GDEFCORE_PUBLIC_ID_LEN + 1];

  void SetUp() override {
    registry_ = NULL;
    site_ = NULL;
    side_ = NULL;
    inst_ = NULL;
    catalog_ = NULL;
    subjects_ = NULL;
    memset(root_, 0x42, sizeof root_);
    memset(storage_, 0, sizeof storage_);
    memset(tenant_, 0, sizeof tenant_);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &registry_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &site_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &side_));
  }

  void TearDown() override {
    gdefcore_subject_destroy(subjects_);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_inst_destroy(inst_);
    gdefstor_store_destroy(side_);
    gdefstor_store_destroy(site_);
    gdefstor_store_destroy(registry_);
  }

  void Open() {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_open_side(registry_, site_, side_, root_, sizeof root_, "",
            0, NULL, &inst_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(inst_, tenant_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_storage_key(inst_, tenant_, strlen(tenant_), storage_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_catalog_open(inst_, tenant_, strlen(tenant_), &catalog_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_open(side_, storage_, sizeof storage_, root_,
            sizeof root_,
            gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_)), NULL,
            &subjects_));
  }

  void CloseHandles() {
    gdefcore_subject_destroy(subjects_);
    subjects_ = NULL;
    gdefcore_catalog_destroy(catalog_);
    catalog_ = NULL;
    gdefcore_inst_destroy(inst_);
    inst_ = NULL;
  }

  void DefinePerson() {
    GDEFCORE_Field field;
    int personal = 0;
    memset(&field, 0, sizeof field);
    field.size = sizeof field;
    field.name = kField;
    field.name_len = strlen(kField);
    field.required = 1;
    field.personal = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, "site.person", 11, GDEFCORE_TYPE_CONTENT,
            &field, 1));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_field_personal(catalog_, "site.person", 11, 0, &personal));
    EXPECT_EQ(1, personal);
  }

  void MakeEntity(char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.person", 11, out_id, NULL));
  }

  void Save(const char * subject, const char * entity) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_save(subjects_, catalog_, subject, strlen(subject),
            entity, strlen(entity), kField, strlen(kField), "en", 2, kPlain,
            strlen(kPlain)));
  }

  std::string Stored(const char * entity) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    std::string value;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, entity,
            strlen(entity), "en", 2, kField, strlen(kField), &texts, &lens,
            &count));
    if (count == 1 && texts != NULL && texts[0] != NULL && lens != NULL) {
      value.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return value;
  }

  bool ReadIs(GDEFCORE_Catalog * catalog, const char * subject, const char * entity,
      const char * expect) {
    char * text = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_subject_read(subjects_, catalog, subject,
        strlen(subject), entity, strlen(entity), kField, strlen(kField), "en", 2,
        &text, &n);
    bool ok = rc == GDEFCORE_OK && text != NULL && n == strlen(expect) &&
              memcmp(text, expect, n) == 0;
    gdefcore_subject_free(subjects_, text);
    return ok;
  }

  void Snapshot(uint8_t ** out, size_t * out_len) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_snapshot(subjects_, site_, out, out_len));
  }

  bool BlindRow(const char * subject, const uint8_t mac[32]) {
    static const char kHex[] = "0123456789abcdef";
    char id[GDEFCORE_PUBLIC_ID_LEN + 64];
    char hex[65];
    GDEFSTOR_Projection * row = NULL;
    GDEFSTOR_Result rc;
    int i;
    for (i = 0; i < 32; i++) {
      hex[i * 2] = kHex[mac[i] >> 4];
      hex[i * 2 + 1] = kHex[mac[i] & 0x0f];
    }
    memcpy(id, subject, GDEFCORE_PUBLIC_ID_LEN);
    memcpy(id + GDEFCORE_PUBLIC_ID_LEN, hex, 64);
    rc = gdefstor_projection_get(side_, (const char *)storage_, sizeof storage_,
        "core.blind", 10, id, GDEFCORE_PUBLIC_ID_LEN + 64, &row);
    if (rc == GDEFSTOR_OK) {
      gdefstor_projection_free(row);
      return true;
    }
    return false;
  }

  void PlantLedger(const uint8_t * zip, size_t zip_len) {
    uint8_t * ledger = NULL;
    size_t ledger_len = 0;
    GDEFSTOR_Write * write = NULL;
    GDEFSTOR_Column column;
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_ledger(site_, zip, zip_len, NULL, &ledger, &ledger_len));
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_write_begin(side_, (const char *)storage_, sizeof storage_, NULL,
            &write));
    memset(&column, 0, sizeof column);
    column.name = "text";
    column.name_len = 4;
    column.value = ledger_len == 0 ? (const uint8_t *)"" : ledger;
    column.value_len = ledger_len;
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_projection_put(write, GDEFCORE_SUBJECT_LEDGER_TYPE,
            strlen(GDEFCORE_SUBJECT_LEDGER_TYPE), GDEFCORE_SUBJECT_LEDGER_ID,
            strlen(GDEFCORE_SUBJECT_LEDGER_ID), &column, 1));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(write));
    gdefstor_bytes_free(NULL, ledger);
  }
};

}  // namespace

TEST_F(Subject, Ciphertext) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string stored;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  stored = Stored(entity);
  EXPECT_EQ(0, stored.compare(0, 3, "s1:"));
  EXPECT_EQ(std::string::npos, stored.find(kPlain));
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, kPlain));
}

TEST_F(Subject, Read) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t wrap[GDEFCORE_KEYRING_WRAP_LEN];
  uint8_t again[GDEFCORE_KEYRING_WRAP_LEN];
  std::string stored;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_keyring_export(
          gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_)), wrap,
          sizeof wrap));
  CloseHandles();
  Open();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_keyring_export(
          gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_)), again,
          sizeof again));
  EXPECT_EQ(0, memcmp(wrap, again, sizeof wrap));
  stored = Stored(entity);
  EXPECT_EQ(std::string::npos, stored.find(kPlain));
  EXPECT_EQ(0, stored.compare(0, 3, "s1:"));
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, kPlain));
}

TEST_F(Subject, BlindIndex) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char other[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char other_entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t mac[32];
  uint8_t other_mac[32];
  size_t count = 0;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, other));
  MakeEntity(entity);
  MakeEntity(other_entity);
  Save(subject, entity);
  Save(other, other_entity);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_blind_count(subjects_, subject, strlen(subject), &count));
  EXPECT_EQ(1u, count);
  memset(mac, 0, sizeof mac);
  memset(other_mac, 0, sizeof other_mac);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_blind(subjects_, subject, strlen(subject), 0, mac));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_blind(subjects_, other, strlen(other), 0, other_mac));
  EXPECT_FALSE(HasBytes(mac, sizeof mac, kPlain, strlen(kPlain)));
  EXPECT_EQ(0, memcmp(mac, other_mac, sizeof mac));
  EXPECT_TRUE(BlindRow(subject, mac));
  EXPECT_TRUE(BlindRow(other, other_mac));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_blind_count(subjects_, subject, strlen(subject), &count));
  EXPECT_EQ(0u, count);
  EXPECT_FALSE(BlindRow(subject, mac));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_blind_count(subjects_, other, strlen(other), &count));
  EXPECT_EQ(1u, count);
  EXPECT_TRUE(BlindRow(other, other_mac));
}

TEST_F(Subject, OtherKey) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t other[GDEFCORE_ACCOUNT_ROOT_LEN];
  GDEFCORE_Subjects * bad = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  memset(other, 0x24, sizeof other);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_subject_open(side_, storage_, sizeof storage_, other, sizeof other,
          NULL, NULL, &bad));
  EXPECT_EQ(nullptr, bad);
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, kPlain));
}

TEST_F(Subject, Erase) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char wrong[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t raw[GDEFCORE_SUBJECT_KEY_LEN];
  std::string stored;
  memset(wrong, 'x', GDEFCORE_PUBLIC_ID_LEN);
  wrong[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), wrong,
          GDEFCORE_PUBLIC_ID_LEN));
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, kPlain));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_key(subjects_, subject, strlen(subject), raw));
  memset(raw, 0, sizeof raw);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, GDEFCORE_SUBJECT_ERASED));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_subject_key(subjects_, subject, strlen(subject), raw));
  stored = Stored(entity);
  EXPECT_EQ(0, stored.compare(0, 3, "s1:"));
  EXPECT_EQ(std::string::npos, stored.find(kPlain));
}

TEST_F(Subject, NotPersonal) {
  GDEFCORE_Field field;
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  const char * texts[1];
  size_t lens[1];
  GDEFCORE_Value value;
  GDEFCORE_Changeset * changeset = NULL;
  Open();
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = kField;
  field.name_len = strlen(kField);
  field.required = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.plain", 10, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.plain", 10, entity, NULL));
  texts[0] = "kept";
  lens[0] = 4;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  value.field = kField;
  value.field_len = strlen(kField);
  value.texts = texts;
  value.text_lens = lens;
  value.count = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(changeset, entity, strlen(entity), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_subject_save(subjects_, catalog_, subject, strlen(subject), entity,
          strlen(entity), kField, strlen(kField), "en", 2, kPlain, strlen(kPlain)));
  EXPECT_EQ(std::string("kept"), Stored(entity));
}

TEST_F(Subject, Export) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * json = NULL;
  size_t n = 0;
  std::string stored;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_export(subjects_, catalog_, subject, strlen(subject), &json,
          &n));
  ASSERT_NE(json, nullptr);
  EXPECT_NE(std::string::npos, std::string(json, n).find(kPlain));
  gdefcore_subject_free(subjects_, json);
  json = NULL;
  stored = Stored(entity);
  EXPECT_EQ(std::string::npos, stored.find(kPlain));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_export(subjects_, catalog_, subject, strlen(subject), &json,
          &n));
  ASSERT_NE(json, nullptr);
  EXPECT_EQ(std::string("{\"erased\":\"[erased]\"}"), std::string(json, n));
  EXPECT_EQ(std::string::npos, std::string(json, n).find(kPlain));
  gdefcore_subject_free(subjects_, json);
}

TEST_F(Subject, Restore) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t * zip = NULL;
  size_t zip_len = 0;
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  Snapshot(&zip, &zip_len);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_import(subjects_, empty, zip, zip_len));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  EXPECT_TRUE(ReadIs(restored, subject, entity, GDEFCORE_SUBJECT_ERASED));
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
  gdefstor_bytes_free(NULL, zip);
}

TEST_F(Subject, SnapshotLedger) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char line[64];
  uint8_t raw[GDEFCORE_SUBJECT_KEY_LEN];
  uint8_t * zip = NULL;
  size_t zip_len = 0;
  size_t count = 99;
  int kn;
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_key(subjects_, subject, strlen(subject), raw));
  memset(raw, 0, sizeof raw);
  kn = snprintf(line, sizeof line, "%s 1\n", subject);
  ASSERT_GT(kn, 0);
  ASSERT_LT((size_t)kn, sizeof line);
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_snapshot_export_ledger(site_, (const char *)storage_,
          sizeof storage_, NULL, (const uint8_t *)line, (size_t)kn, &zip,
          &zip_len));
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_import(subjects_, empty, zip, zip_len));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  EXPECT_TRUE(ReadIs(restored, subject, entity, GDEFCORE_SUBJECT_ERASED));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_subject_key(subjects_, subject, strlen(subject), raw));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_blind_count(subjects_, subject, strlen(subject), &count));
  EXPECT_EQ(0u, count);
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
  gdefstor_bytes_free(NULL, zip);
}

TEST_F(Subject, NoKey) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t * zip = NULL;
  size_t zip_len = 0;
  uint8_t * ledger = NULL;
  size_t ledger_len = 0;
  uint8_t wrap[GDEFCORE_KEYRING_WRAP_LEN];
  uint8_t raw[GDEFCORE_SUBJECT_KEY_LEN];
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_keyring_export(
          gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_)), wrap,
          sizeof wrap));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_key(subjects_, subject, strlen(subject), raw));
  Snapshot(&zip, &zip_len);
  EXPECT_FALSE(HasBytes(zip, zip_len, raw, sizeof raw));
  EXPECT_FALSE(HasBytes(zip, zip_len, wrap, sizeof wrap));
  EXPECT_FALSE(HasBytes(zip, zip_len, kPlain, strlen(kPlain)));
  EXPECT_TRUE(HasBytes(zip, zip_len, "ledger", 6));
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_snapshot_ledger(site_, zip, zip_len, NULL, &ledger, &ledger_len));
  EXPECT_NE(ledger, nullptr);
  gdefstor_bytes_free(NULL, ledger);
  gdefstor_bytes_free(NULL, zip);
  memset(raw, 0, sizeof raw);
  memset(wrap, 0, sizeof wrap);
}

TEST_F(Subject, Gate) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t * zip = NULL;
  size_t zip_len = 0;
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  const char * plant = getenv("GHOTI_SUBJECT_PLANT");
  int erased = 0;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  Snapshot(&zip, &zip_len);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  if (plant != NULL && strcmp(plant, "snapshot-ledger") == 0) {
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_import(empty, (const char *)storage_, sizeof storage_,
            zip, zip_len, NULL));
    PlantLedger(zip, zip_len);
  } else {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_import(subjects_, empty, zip, zip_len));
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  erased = ReadIs(restored, subject, entity, GDEFCORE_SUBJECT_ERASED) ? 1 : 0;
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
  gdefstor_bytes_free(NULL, zip);
  EXPECT_EQ(1, erased);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
