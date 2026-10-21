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
 * Story 12's matrix, and story S5b's: subject keys, the keyring's wrap and
 * the ledger in the key store (keystore_rig.h picks memory, SQLite or
 * Postgres), the erasure order, and the backup pair; and story S6c's: the
 * blind index on the tenant's entity port (its blind table, read here from
 * the port's dump), blind equality after a save and a draft apply, no row for
 * an erased subject, and the rebuild. One test per row.
 */

#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#include <ghoti.io/defiant-storage/store.h>

#include <gtest/gtest.h>

#include "keystore_rig.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <chrono>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

const char kPlain[] = "platypus-secret";
const char kField[] = "name";
/* The reference that names whose a person's `name` is (story S7: every
 * personal field names its subject source). */
const char kWho[] = "person";

typedef std::string Bytes;

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

bool Has(const Bytes & hay, const Bytes & needle) {
  return !needle.empty() && hay.find(needle) != Bytes::npos;
}

Bytes Hex(const Bytes & raw) {
  static const char kDigits[] = "0123456789abcdef";
  Bytes out;
  for (unsigned char c : raw) {
    out.push_back(kDigits[c >> 4]);
    out.push_back(kDigits[c & 0x0f]);
  }
  return out;
}

/* A zip as stored, then every member's name and body, so a compressed member
 * cannot hide a needle. */
Bytes Unpacked(const uint8_t * zip, size_t n) {
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  Bytes view(reinterpret_cast<const char *>(zip), n);
  if (garc_stream_create_memory(zip, n, &stream) != GARC_OK) {
    ADD_FAILURE() << "not a zip";
    return view;
  }
  if (garc_open(stream, NULL, &archive) != GARC_OK) {
    garc_stream_destroy(stream);
    ADD_FAILURE() << "not a zip";
    return view;
  }
  for (;;) {
    const GARC_Member * member = NULL;
    GARC_Result gr = garc_next(archive, &member);
    if (gr != GARC_OK) {
      EXPECT_EQ(GARC_END, gr);
      break;
    }
    Bytes body(static_cast<size_t>(member->size), '\0');
    size_t total = 0;
    while (total < body.size()) {
      size_t got = 0;
      if (garc_read_member(archive, &body[total], body.size() - total, &got) !=
              GARC_OK ||
          got == 0) {
        ADD_FAILURE() << "short member";
        break;
      }
      total += got;
    }
    view += "\n" + Bytes(member->name, member->name_length) + "\n" + body;
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return view;
}

class Subject : public ::testing::Test {
 protected:
  GDEFSTOR_Store * registry_;
  GDEFSTOR_Store * site_;
  GDEFSTOR_KeyStore * keys_;
  ksrig::Counts counts_;
  GDEFCORE_Inst * inst_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Subjects * subjects_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t storage_[16];
  char tenant_[GDEFCORE_PUBLIC_ID_LEN + 1];

  void SetUp() override {
    registry_ = NULL;
    site_ = NULL;
    keys_ = NULL;
    inst_ = NULL;
    catalog_ = NULL;
    subjects_ = NULL;
    memset(root_, 0x42, sizeof root_);
    memset(storage_, 0, sizeof storage_);
    memset(tenant_, 0, sizeof tenant_);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &registry_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &site_));
    ASSERT_EQ(GDEFSTOR_OK, ksrig::Open(ksrig::Chosen(), &counts_, &keys_));
  }

  void TearDown() override {
    gdefcore_subject_destroy(subjects_);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_inst_destroy(inst_);
    gdefstor_keystore_destroy(keys_);
    gdefstor_store_destroy(site_);
    gdefstor_store_destroy(registry_);
  }

  void Open() {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_open_keys(registry_, site_, keys_, root_, sizeof root_, "",
            0, NULL, &inst_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(inst_, tenant_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_storage_key(inst_, tenant_, strlen(tenant_), storage_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_catalog_open(inst_, tenant_, strlen(tenant_), &catalog_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_open(keys_, site_, storage_, sizeof storage_, root_,
            sizeof root_,
            gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_)), NULL,
            &subjects_));
    gdefcore_catalog_bind_subjects(catalog_, subjects_);
  }

  void CloseHandles() {
    gdefcore_subject_destroy(subjects_);
    subjects_ = NULL;
    gdefcore_catalog_destroy(catalog_);
    catalog_ = NULL;
    gdefcore_inst_destroy(inst_);
    inst_ = NULL;
  }

  /* A person's `name`, whose subject is the `person` reference beside it,
   * which gdefcore_subject_save() sets on a first save (story S7). */
  void DefinePerson() {
    GDEFCORE_Field fields[2];
    int personal = 0;
    memset(fields, 0, sizeof fields);
    fields[0].size = sizeof fields[0];
    fields[0].name = kField;
    fields[0].name_len = strlen(kField);
    fields[0].required = 1;
    fields[0].personal = 1;
    fields[0].subject = kWho;
    fields[0].subject_len = strlen(kWho);
    fields[1].size = sizeof fields[1];
    fields[1].name = kWho;
    fields[1].name_len = strlen(kWho);
    fields[1].type = GDEFSTOR_FIELD_REFERENCE;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, "site.person", 11, GDEFCORE_TYPE_CONTENT,
            fields, 2));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_field_personal(catalog_, "site.person", 11, 0, &personal));
    EXPECT_EQ(1, personal);
  }

  void MakeEntity(char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.person", 11, out_id, NULL));
  }

  void Save(const char * subject, const char * entity,
      const char * lang = "en") {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_save(subjects_, catalog_, subject, strlen(subject),
            entity, strlen(entity), kField, strlen(kField), lang, strlen(lang),
            kPlain, strlen(kPlain)));
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

  /* The data set of a backup pair. */
  Bytes Snapshot() {
    uint8_t * zip = NULL;
    size_t zip_len = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_subject_snapshot(subjects_, site_, &zip, &zip_len));
    Bytes out(reinterpret_cast<const char *>(zip), zip == NULL ? 0 : zip_len);
    gdefstor_bytes_free(NULL, zip);
    return out;
  }

  /* The key set of a backup pair. */
  Bytes Keyset() {
    uint8_t * set = NULL;
    size_t set_len = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_keyset(subjects_, &set, &set_len));
    Bytes out(reinterpret_cast<const char *>(set), set == NULL ? 0 : set_len);
    gdefstor_bytes_free(NULL, set);
    return out;
  }

  static const uint8_t * U(const Bytes & b) {
    return reinterpret_cast<const uint8_t *>(b.data());
  }

  GDEFCORE_Result Restore(GDEFSTOR_Store * into, const Bytes & data,
      const Bytes & keys) {
    return gdefcore_subject_restore(subjects_, into, U(data), data.size(),
        U(keys), keys.size());
  }

  /* Until the clock has moved on by a millisecond or more: a set taken after
   * this is newer than one taken before. */
  static void NextMillisecond() {
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
  }

  static std::string HexOf(const void * p, size_t n) {
    static const char kHex[] = "0123456789abcdef";
    const unsigned char * b = static_cast<const unsigned char *>(p);
    std::string out;
    for (size_t i = 0; i < n; i++) {
      out += kHex[b[i] >> 4];
      out += kHex[b[i] & 0x0f];
    }
    return out;
  }

  /* The blind rows of a data store's tenant, read from the store itself (the
   * port's dump), not through the library: what is there at the moment it is
   * asked. Each is "B row item valid_from field subject mac key version
   * language", strings in hex. */
  std::vector<std::vector<std::string>> BlindRowsIn(GDEFSTOR_Store * store) {
    std::vector<std::vector<std::string>> out;
    uint8_t * text = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_model_dump(store, (const char *)storage_,
        sizeof storage_, GDEFSTOR_MODEL_TRUTH, &text, &n));
    std::istringstream in(std::string(reinterpret_cast<const char *>(text),
        text == NULL ? 0 : n));
    gdefstor_bytes_free(NULL, text);
    std::string line;
    while (std::getline(in, line)) {
      if (line.compare(0, 2, "B ") != 0) {
        continue;
      }
      std::istringstream words(line);
      std::vector<std::string> w;
      std::string word;
      while (words >> word) {
        w.push_back(word);
      }
      out.push_back(w);
    }
    return out;
  }

  size_t BlindLinesIn(GDEFSTOR_Store * store, const char * subject) {
    size_t lines = 0;
    for (const auto & w : BlindRowsIn(store)) {
      lines += w.size() > 5 && w[5] == HexOf(subject, strlen(subject));
    }
    return lines;
  }

  size_t BlindLinesInTheStore(const char * subject) {
    return BlindLinesIn(site_, subject);
  }

  size_t BlindCount(const char * subject) {
    return BlindLinesInTheStore(subject);
  }

  bool BlindRow(const char * subject, const uint8_t mac[32]) {
    for (const auto & w : BlindRowsIn(site_)) {
      if (w.size() > 6 && w[5] == HexOf(subject, strlen(subject)) &&
          w[6] == HexOf(mac, 32)) {
        return true;
      }
    }
    return false;
  }

  /* Blind equality, as a lookup by a value asks it. */
  std::vector<std::string> Find(GDEFCORE_Catalog * catalog, const char * plain,
      const char * type = "site.person", const char * lang = "en") {
    char ** ids = NULL;
    size_t n = 0;
    std::vector<std::string> out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_subject_find(subjects_, catalog, type, strlen(type), kField,
            strlen(kField), lang, strlen(lang), plain, strlen(plain), &ids, &n));
    for (size_t i = 0; i < n; i++) {
      out.push_back(ids[i]);
    }
    gdefcore_ids_free(catalog, ids, n);
    return out;
  }

  /* Stage @p plain for @p subject in a changeset of the caller's, as the
   * subject routes do: sealed, told whose it is, and saved or drafted, with
   * the `person` reference naming @p subject (story S7: the declaration says
   * whose the value is). */
  GDEFCORE_Result Stage(GDEFCORE_Changeset * cs, const char * subject,
      const char * entity, const char * plain, bool draft, bool with_mac = true) {
    char * text = NULL;
    size_t text_len = 0;
    uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN];
    const char * texts[2];
    size_t lens[2];
    GDEFCORE_Value value[2];
    GDEFCORE_Result rc = gdefcore_subject_seal(subjects_, subject,
        strlen(subject), kField, strlen(kField), plain, strlen(plain), &text,
        &text_len, mac);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_accept_sealed(cs);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_note_sealed(cs, subjects_, text, text_len,
          subject, strlen(subject), with_mac ? mac : NULL);
    }
    if (rc == GDEFCORE_OK) {
      texts[0] = text;
      lens[0] = text_len;
      texts[1] = subject;
      lens[1] = strlen(subject);
      memset(value, 0, sizeof value);
      value[0].size = sizeof value[0];
      value[0].field = kField;
      value[0].field_len = strlen(kField);
      value[0].texts = &texts[0];
      value[0].text_lens = &lens[0];
      value[0].count = 1;
      value[1].size = sizeof value[1];
      value[1].field = kWho;
      value[1].field_len = strlen(kWho);
      value[1].texts = &texts[1];
      value[1].text_lens = &lens[1];
      value[1].count = 1;
      rc = (draft ? gdefcore_entity_save_draft : gdefcore_entity_save)(cs,
          entity, strlen(entity), "en", 2, value, 2);
    }
    gdefcore_subject_free(subjects_, text);
    return rc;
  }

  GDEFCORE_Result Publish(const char * entity) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_entity_publish(cs, entity, strlen(entity));
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    if (rc != GDEFCORE_OK) {
      size_t n = 0;
      const char * why = gdefcore_changeset_refusal(cs, &n);
      last_refusal_.assign(why == NULL ? "" : why, n);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  std::string last_refusal_;

  /* The port's dump of a data store's tenant: every row it holds, the blind
   * table's included (a snapshot leaves those out). */
  Bytes TruthDump(GDEFSTOR_Store * store) {
    uint8_t * text = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_model_dump(store, (const char *)storage_,
        sizeof storage_, GDEFSTOR_MODEL_TRUTH, &text, &n));
    Bytes out(reinterpret_cast<const char *>(text), text == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, text);
    return "\n" + out;
  }

  /* Every byte of a data store's tenant, members unpacked. */
  Bytes StoreBytes(GDEFSTOR_Store * store, const uint8_t * tenant,
      size_t tenant_len) {
    uint8_t * zip = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_export(store, (const char *)tenant, tenant_len, NULL,
            &zip, &n));
    Bytes out = zip == NULL ? Bytes() : Unpacked(zip, n);
    gdefstor_bytes_free(NULL, zip);
    return out;
  }

  /* The sealed rows of a key set: each subject's key wrapped under the
   * keyring, as the key store holds it. */
  std::vector<Bytes> SealedIn(const Bytes & set) {
    std::vector<Bytes> out;
    GDEFSTOR_KeySet * parsed = NULL;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_keyset_parse(NULL, U(set), set.size(),
        &parsed));
    for (size_t i = 0; i < gdefstor_keyset_count(parsed); i++) {
      GDEFSTOR_KeyRow row;
      if (gdefstor_keyset_row(parsed, i, &row) == GDEFSTOR_OK &&
          row.kind == GDEFSTOR_KEYROW_SEALED) {
        out.push_back(Bytes(reinterpret_cast<const char *>(row.bytes), row.len));
      }
    }
    gdefstor_keyset_free(parsed);
    return out;
  }

  /* An erasure stopped after its first step, as a crash would leave it: the
   * key store has destroyed the key and written the ledger row, and nothing
   * after that ran. */
  void EraseKeyOnly(const char * subject) {
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_keystore_erase(keys_, (const char *)storage_, sizeof storage_,
            subject, strlen(subject), 1));
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
  count = BlindCount(subject);
  EXPECT_EQ(1u, count);
  memset(mac, 0, sizeof mac);
  memset(other_mac, 0, sizeof other_mac);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_mac(subjects_, kField, strlen(kField), kPlain,
          strlen(kPlain), mac));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_mac(subjects_, kField, strlen(kField), kPlain,
          strlen(kPlain), other_mac));
  EXPECT_FALSE(HasBytes(mac, sizeof mac, kPlain, strlen(kPlain)));
  EXPECT_EQ(0, memcmp(mac, other_mac, sizeof mac));
  EXPECT_TRUE(BlindRow(subject, mac));
  EXPECT_TRUE(BlindRow(other, other_mac));
  EXPECT_EQ((std::vector<std::string>{entity, other_entity}).size(),
      Find(catalog_, kPlain).size());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  count = BlindCount(subject);
  EXPECT_EQ(0u, count);
  EXPECT_FALSE(BlindRow(subject, mac));
  count = BlindCount(other);
  EXPECT_EQ(1u, count);
  EXPECT_TRUE(BlindRow(other, other_mac));
  EXPECT_EQ(std::vector<std::string>{other_entity}, Find(catalog_, kPlain));
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
      gdefcore_subject_open(keys_, site_, storage_, sizeof storage_, other,
          sizeof other, NULL, NULL, &bad));
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
  /* Erasing again writes no second ledger row. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  {
    GDEFSTOR_Ledger * l = NULL;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_keystore_ledger(keys_,
        (const char *)storage_, sizeof storage_, &l));
    EXPECT_EQ(1u, gdefstor_ledger_count(l));
    gdefstor_ledger_free(l);
  }
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

/* A pair taken while the subject lives, an erasure, a restore: erased. */
TEST_F(Subject, Restore) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  Bytes data = Snapshot();
  Bytes keys = Keyset();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  ASSERT_EQ(GDEFCORE_OK, Restore(empty, data, keys));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  EXPECT_TRUE(ReadIs(restored, subject, entity, GDEFCORE_SUBJECT_ERASED));
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
}

/* A key set whose ledger names a subject the live store still has: the
 * restore replays it, so the subject is erased here too, its key is gone and
 * so are its blind rows. */
TEST_F(Subject, SnapshotLedger) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t raw[GDEFCORE_SUBJECT_KEY_LEN];
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  GDEFSTOR_KeyStore * elsewhere = NULL;
  uint8_t * theirs = NULL;
  size_t theirs_len = 0;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_key(subjects_, subject, strlen(subject), raw));
  memset(raw, 0, sizeof raw);
  ASSERT_EQ(1u, BlindCount(subject));
  Bytes data = Snapshot();
  /* The same tenant's key store elsewhere, where the subject was erased. */
  NextMillisecond();
  Bytes mine = Keyset();
  ASSERT_EQ(GDEFSTOR_OK, ksrig::OpenInner(ksrig::kMemory, &elsewhere));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_keystore_import(elsewhere,
      (const char *)storage_, sizeof storage_, U(mine), mine.size()));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_keystore_erase(elsewhere,
      (const char *)storage_, sizeof storage_, subject, strlen(subject), 1));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_keystore_export(elsewhere,
      (const char *)storage_, sizeof storage_, 0x7fffffffffffLL, &theirs,
      &theirs_len));
  Bytes keys(reinterpret_cast<const char *>(theirs), theirs_len);
  gdefstor_bytes_free(NULL, theirs);
  gdefstor_keystore_destroy(elsewhere);
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  ASSERT_EQ(GDEFCORE_OK, Restore(empty, data, keys));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  EXPECT_TRUE(ReadIs(restored, subject, entity, GDEFCORE_SUBJECT_ERASED));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_subject_key(subjects_, subject, strlen(subject), raw));
  EXPECT_EQ(0u, BlindCount(subject));
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
}

/* The data set holds no key, no wrap, no plaintext and no ledger; the key
 * set holds the wrapped key, the keyring's wrap and the ledger, and no raw
 * key and no plaintext. */
TEST_F(Subject, NoKey) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t * ledger = NULL;
  size_t ledger_len = 9;
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
  Bytes zip = Snapshot();
  Bytes data = Unpacked(U(zip), zip.size());
  Bytes rawb(reinterpret_cast<const char *>(raw), sizeof raw);
  Bytes wrapb(reinterpret_cast<const char *>(wrap), sizeof wrap);
  EXPECT_FALSE(Has(data, rawb));
  EXPECT_FALSE(Has(data, Hex(rawb)));
  EXPECT_FALSE(Has(data, wrapb));
  EXPECT_FALSE(Has(data, Hex(wrapb)));
  EXPECT_FALSE(Has(data, kPlain));
  /* A personal value is "@c": the hex of its sealed text, and "@s": its
   * subject (story S6c). */
  EXPECT_TRUE(Has(data, Hex("s1:"))) << "the data set holds the ciphertext";
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_snapshot_ledger(site_, U(zip), zip.size(), NULL, &ledger,
          &ledger_len));
  EXPECT_EQ(0u, ledger_len) << "the data set carries no ledger";
  gdefstor_bytes_free(NULL, ledger);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  Bytes keys = Keyset();
  EXPECT_TRUE(Has(keys, Hex(wrapb))) << "the key set holds the keyring wrap";
  EXPECT_TRUE(Has(keys, "\nledger " + std::string(subject) + " "));
  EXPECT_FALSE(Has(keys, Hex(rawb)));
  EXPECT_FALSE(Has(keys, rawb));
  EXPECT_FALSE(Has(keys, kPlain));
  memset(raw, 0, sizeof raw);
  memset(wrap, 0, sizeof wrap);
}

TEST_F(Subject, Gate) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  const char * plant = getenv("GHOTI_SUBJECT_PLANT");
  int erased = 0;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  Bytes data = Snapshot();
  Bytes keys = Keyset();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  if (plant != NULL && strcmp(plant, "snapshot-ledger") == 0) {
    /* The planted restore reads the ledger from the backup only: the pair
     * goes into a key store of its own, and the live ledger, which holds the
     * newer erasure, is never consulted. */
    GDEFSTOR_KeyStore * fresh = NULL;
    ASSERT_EQ(GDEFSTOR_OK, ksrig::OpenInner(ksrig::kMemory, &fresh));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_keystore_import(fresh,
        (const char *)storage_, sizeof storage_, U(keys), keys.size()));
    gdefcore_subject_destroy(subjects_);
    subjects_ = NULL;
    gdefstor_keystore_destroy(keys_);
    keys_ = fresh;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_open(keys_, site_, storage_, sizeof storage_, root_,
            sizeof root_, NULL, NULL, &subjects_));
    gdefcore_catalog_bind_subjects(catalog_, subjects_);
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_import(empty, (const char *)storage_, sizeof storage_,
            U(data), data.size(), NULL));
  } else {
    ASSERT_EQ(GDEFCORE_OK, Restore(empty, data, keys));
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  erased = ReadIs(restored, subject, entity, GDEFCORE_SUBJECT_ERASED) ? 1 : 0;
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
  EXPECT_EQ(1, erased);
}

/* ---- story S5b ------------------------------------------------------------ */

/* Separation: whatever is saved and erased, no data store (the tenant store,
 * with its blind table, and the registry) holds a subject key, raw or
 * wrapped, the keyring's wrap, or a ledger row. The key set, where they
 * belong, is the control: the same search finds each of them there. */
TEST_F(Subject, KeysNeverReachADataStore) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ea[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eb[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t raw[GDEFCORE_SUBJECT_KEY_LEN];
  uint8_t wrap[GDEFCORE_KEYRING_WRAP_LEN];
  static const uint8_t kRegistry[] = {0x02};
  std::vector<std::pair<std::string, Bytes>> needles;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, b));
  MakeEntity(ea);
  MakeEntity(eb);
  Save(a, ea);
  Save(a, ea, "fr");
  Save(b, eb);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_keyring_export(
      gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_)), wrap,
      sizeof wrap));
  needles.push_back({"keyring wrap", Bytes((const char *)wrap, sizeof wrap)});
  for (const char * s : {(const char *)a, (const char *)b}) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_key(subjects_, s, strlen(s), raw));
    needles.push_back({std::string("raw key of ") + s,
        Bytes((const char *)raw, sizeof raw)});
  }
  Bytes before = Keyset();
  std::vector<Bytes> sealed = SealedIn(before);
  ASSERT_EQ(2u, sealed.size());
  for (const Bytes & w : sealed) {
    needles.push_back({"wrapped subject key", w});
  }
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_erase(subjects_, a, strlen(a), a,
      strlen(a)));
  Save(b, eb, "fr");
  Bytes after = Keyset();
  /* The ledger row as text, the way a store would hold it. */
  {
    GDEFSTOR_Ledger * l = NULL;
    const char * s = NULL;
    size_t sl = 0;
    int64_t when = 0;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_keystore_ledger(keys_,
        (const char *)storage_, sizeof storage_, &l));
    ASSERT_EQ(1u, gdefstor_ledger_count(l));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_ledger_row(l, 0, &s, &sl, &when));
    needles.push_back({"ledger row", std::string(s, sl) + " " +
        std::to_string(when)});
    needles.push_back({"ledger row in seconds", std::string(s, sl) + " " +
        std::to_string(when / 1000)});
    needles.push_back({"ledger projection", "core.ledger"});
    gdefstor_ledger_free(l);
  }
  struct Hay {
    const char * name;
    Bytes bytes;
  } hays[] = {
      {"tenant store", StoreBytes(site_, storage_, sizeof storage_)},
      {"tenant store's rows, the blind table's with them", TruthDump(site_)},
      {"registry", StoreBytes(registry_, kRegistry, sizeof kRegistry)},
  };
  /* Control: the search sees what it looks for, where it belongs. */
  for (const Bytes & w : sealed) {
    EXPECT_TRUE(Has(before, Hex(w))) << "the key set holds each wrapped key";
  }
  EXPECT_TRUE(Has(after, Hex(Bytes((const char *)wrap, sizeof wrap))));
  EXPECT_TRUE(Has(after, "\nledger " + std::string(a) + " "));
  EXPECT_TRUE(Has(hays[1].bytes, "\nB ")) << "the blind table is searched";
  EXPECT_TRUE(Has(hays[0].bytes, Hex("s1:"))) << "the tenant store is searched";
  for (const Hay & h : hays) {
    for (const auto & n : needles) {
      EXPECT_FALSE(Has(h.bytes, n.second)) << n.first << " in the " << h.name;
      EXPECT_FALSE(Has(h.bytes, Hex(n.second)))
          << n.first << " (hex) in the " << h.name;
    }
  }
  memset(raw, 0, sizeof raw);
  memset(wrap, 0, sizeof wrap);
}

/* Save: a save of personal data on an existing subject writes nothing to the
 * key store, counted at the port; it does read it (the control), and making
 * the subject is the write it is not. */
TEST_F(Subject, ASaveWritesNothingToTheKeyStore) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * text = NULL;
  size_t text_len = 0;
  uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN];
  Open();
  DefinePerson();
  int writes = counts_.writes;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  EXPECT_EQ(writes + 1, counts_.writes) << "the window does not see writes";
  MakeEntity(entity);
  writes = counts_.writes;
  int reads = counts_.reads;
  Save(subject, entity);
  Save(subject, entity, "fr");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_seal(subjects_, subject, strlen(subject), kField,
          strlen(kField), "x", 1, &text, &text_len, mac));
  gdefcore_subject_free(subjects_, text);
  /* A draft, and its publish, which computes a MAC from the key it reads. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, Stage(cs, subject, entity, "y", true, false));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    ASSERT_EQ(GDEFCORE_OK, Publish(entity));
  }
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, "y"));
  EXPECT_EQ(writes, counts_.writes) << "a save wrote to the key store";
  EXPECT_LT(reads, counts_.reads) << "the window does not see reads";
}

/* Order: the key store destroys the key while the blind rows are still in
 * the blind store, and when it cannot, the blind rows stay and the value
 * still reads. */
TEST_F(Subject, ErasureDestroysTheKeyBeforeTheBlindRows) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ea[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eb[GDEFCORE_PUBLIC_ID_LEN + 1];
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, b));
  MakeEntity(ea);
  MakeEntity(eb);
  Save(a, ea);
  Save(a, ea, "fr");
  Save(b, eb);
  ASSERT_EQ(2u, BlindLinesInTheStore(a)) << "the store read cannot see rows";
  size_t at_erase = 99;
  counts_.on_erase = [&]() { at_erase = BlindLinesInTheStore(a); };
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_erase(subjects_, a, strlen(a), a,
      strlen(a)));
  counts_.on_erase = nullptr;
  EXPECT_EQ(2u, at_erase) << "blind rows deleted before the key was destroyed";
  EXPECT_EQ(0u, BlindLinesInTheStore(a));
  /* A key store that cannot erase: nothing after the first step runs. */
  counts_.fail_next_erase = 1;
  EXPECT_NE(GDEFCORE_OK, gdefcore_subject_erase(subjects_, b, strlen(b), b,
      strlen(b)));
  EXPECT_EQ(1u, BlindLinesInTheStore(b))
      << "blind rows deleted although the key was not destroyed";
  EXPECT_TRUE(ReadIs(catalog_, b, eb, kPlain));
}

/* Erasure: every value reads [erased] the moment the key store has erased,
 * and an erasure stopped there is finished by the next open. */
TEST_F(Subject, AnErasureCutShortAfterTheKeyIsFinishedOnTheNextOpen) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  Save(subject, entity, "fr");
  EraseKeyOnly(subject);
  if (HasFatalFailure()) {
    return;
  }
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, GDEFCORE_SUBJECT_ERASED));
  EXPECT_EQ(2u, BlindLinesInTheStore(subject)) << "nothing after step 1 ran";
  CloseHandles();
  Open();
  EXPECT_EQ(0u, BlindLinesInTheStore(subject));
  EXPECT_EQ(0u, BlindCount(subject));
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, GDEFCORE_SUBJECT_ERASED));
}

/* Backup pair: a key set older than its data set is refused by name and
 * restores nothing; a newer one restores, and an erasure newer than the data
 * set still reads [erased]. */
TEST_F(Subject, ARestoreRefusesAnOlderKeySet) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ea[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eb[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, b));
  MakeEntity(ea);
  MakeEntity(eb);
  Save(a, ea);
  Save(b, eb);
  Bytes old_keys = Keyset();
  NextMillisecond();
  Bytes data = Snapshot();
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  int writes = counts_.writes;
  EXPECT_EQ(GDEFCORE_ERR_STALE, Restore(empty, data, old_keys));
  EXPECT_EQ(writes, counts_.writes) << "a refused restore wrote the key store";
  {
    uint8_t * zip = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_snapshot_export(empty, (const char *)storage_,
        sizeof storage_, NULL, &zip, &n));
    Bytes view = Unpacked(zip, n);
    gdefstor_bytes_free(NULL, zip);
    EXPECT_FALSE(Has(view, Hex("s1:"))) << "a refused restore imported the data";
  }
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_erase(subjects_, a, strlen(a), a,
      strlen(a)));
  NextMillisecond();
  Bytes keys = Keyset();
  ASSERT_EQ(GDEFCORE_OK, Restore(empty, data, keys));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  EXPECT_TRUE(ReadIs(restored, a, ea, GDEFCORE_SUBJECT_ERASED));
  EXPECT_TRUE(ReadIs(restored, b, eb, kPlain));
  gdefcore_catalog_destroy(restored);
  /* A plain storage snapshot says nothing of when it was taken. */
  {
    uint8_t * zip = NULL;
    size_t n = 0;
    GDEFSTOR_Store * other = NULL;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_snapshot_export(site_, (const char *)storage_,
        sizeof storage_, NULL, &zip, &n));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &other));
    EXPECT_EQ(GDEFCORE_ERR_FORMAT, gdefcore_subject_restore(subjects_, other,
        zip, n, U(keys), keys.size()));
    gdefstor_bytes_free(NULL, zip);
    gdefstor_store_destroy(other);
  }
  gdefstor_store_destroy(empty);
}

/* A restore replays the ledger before it returns: an erasure the backup's
 * key set records, cut short before its blind rows went, is finished by the
 * time the restored tenant can be read. */
TEST_F(Subject, ARestoreReplaysTheLedgerBeforeItReturns) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFSTOR_Store * empty = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  Save(subject, entity);
  Bytes data = Snapshot();
  EraseKeyOnly(subject);
  if (HasFatalFailure()) {
    return;
  }
  ASSERT_EQ(1u, BlindLinesInTheStore(subject));
  NextMillisecond();
  Bytes keys = Keyset();
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  ASSERT_EQ(GDEFCORE_OK, Restore(empty, data, keys));
  EXPECT_EQ(0u, BlindLinesInTheStore(subject))
      << "the restore returned before the ledger was replayed";
  gdefstor_store_destroy(empty);
}

/* ---- story S6c: the blind index on the port --------------------------- */

/* Blind equality finds an entity by its current value only: after a save of
 * a new value the old one finds nothing; a draft's value is found only once
 * the draft is applied, and then the value it replaced is not. */
TEST_F(Subject, BlindEqualityFindsOnlyTheNewValueAfterASaveAndADraftApply) {
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  MakeEntity(entity);
  const std::vector<std::string> it{entity};
  const std::vector<std::string> none;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_save(subjects_, catalog_, subject, strlen(subject),
          entity, strlen(entity), kField, strlen(kField), "en", 2, "ann", 3));
  EXPECT_EQ(it, Find(catalog_, "ann"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_save(subjects_, catalog_, subject, strlen(subject),
          entity, strlen(entity), kField, strlen(kField), "en", 2, "bob", 3));
  EXPECT_EQ(none, Find(catalog_, "ann"));
  EXPECT_EQ(it, Find(catalog_, "bob"));
  /* Each value version has its row: the history keeps "ann". */
  EXPECT_EQ(2u, BlindCount(subject));
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, Stage(cs, subject, entity, "cy", true, false));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  /* A draft is never a revision and carries no blind row. */
  EXPECT_EQ(none, Find(catalog_, "cy"));
  EXPECT_EQ(it, Find(catalog_, "bob"));
  EXPECT_EQ(2u, BlindCount(subject));
  ASSERT_EQ(GDEFCORE_OK, Publish(entity));
  EXPECT_EQ(it, Find(catalog_, "cy"));
  EXPECT_EQ(none, Find(catalog_, "bob"));
  EXPECT_EQ(3u, BlindCount(subject));
  /* Another language's value is another language's. */
  EXPECT_EQ(none, Find(catalog_, "cy", "site.person", "fr"));
}

/* No blind row is ever written for an erased subject. A value sealed, told
 * to a changeset with its MAC, and applied after its subject was erased is
 * refused inside the apply's write, and the store holds no row of theirs; the
 * same flow for a living subject writes one (the control). */
TEST_F(Subject, ABlindRowIsNeverWrittenForAnErasedSubject) {
  char gone[GDEFCORE_PUBLIC_ID_LEN + 1];
  char alive[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eg[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ea[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * late = NULL;
  GDEFCORE_Changeset * ok = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, gone));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, alive));
  MakeEntity(eg);
  MakeEntity(ea);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &late));
  ASSERT_EQ(GDEFCORE_OK, Stage(late, gone, eg, kPlain, false));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &ok));
  ASSERT_EQ(GDEFCORE_OK, Stage(ok, alive, ea, kPlain, false));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, gone, strlen(gone), gone, strlen(gone)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(late, NULL, 0));
  size_t why_len = 0;
  const char * why = gdefcore_changeset_refusal(late, &why_len);
  EXPECT_NE(std::string::npos,
      std::string(why == NULL ? "" : why, why_len).find("erased"));
  gdefcore_changeset_destroy(late);
  EXPECT_EQ(0u, BlindLinesInTheStore(gone)) << "a blind row for an erased subject";
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(ok, NULL, 0));
  gdefcore_changeset_destroy(ok);
  EXPECT_EQ(1u, BlindLinesInTheStore(alive)) << "the store read cannot see rows";
  EXPECT_EQ(std::vector<std::string>{ea}, Find(catalog_, kPlain));
}

/* The decision for a draft that names an erased subject (story S6c): it is
 * refused, not applied with "[erased]" in place of the value. A new value of
 * someone erased would be a write for a subject whose key is gone (AD-19:
 * the key is present at every write), and could get no blind row. The draft
 * is kept, so an editor can replace the value; a draft that leaves an erased
 * subject's value as it is (another field changed) applies, and that value
 * still reads [erased]. */
TEST_F(Subject, ADraftNamingAnErasedSubjectIsRefusedAndKept) {
  GDEFCORE_Field fields[3];
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  char later[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char other[GDEFCORE_PUBLIC_ID_LEN + 1];
  Open();
  memset(fields, 0, sizeof fields);
  fields[0].size = sizeof fields[0];
  fields[0].name = kField;
  fields[0].name_len = strlen(kField);
  fields[0].personal = 1;
  fields[0].subject = kWho;
  fields[0].subject_len = strlen(kWho);
  fields[1].size = sizeof fields[1];
  fields[1].name = "note";
  fields[1].name_len = 4;
  fields[2].size = sizeof fields[2];
  fields[2].name = kWho;
  fields[2].name_len = strlen(kWho);
  fields[2].type = GDEFSTOR_FIELD_REFERENCE;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.person", 11, GDEFCORE_TYPE_CONTENT,
          fields, 3));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, later));
  MakeEntity(entity);
  MakeEntity(other);
  Save(subject, entity);
  Save(later, other);
  /* A draft of a new value for `later`, made while they are alive. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, Stage(cs, later, other, "new words", true, false));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  /* A draft of `subject`'s entity that changes only the other field. */
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value value;
    const char * texts[1] = {"a note"};
    size_t lens[1] = {6};
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "note";
    value.field_len = 4;
    value.texts = texts;
    value.text_lens = lens;
    value.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, entity, strlen(entity), "en", 2, &value,
            1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  size_t before = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_count(catalog_, other, strlen(other), &before));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, later, strlen(later), later,
          strlen(later)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
          strlen(subject)));
  /* Refused, in words; nothing written; the draft is still there. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Publish(other));
  EXPECT_NE(std::string::npos, last_refusal_.find("erased")) << last_refusal_;
  size_t after = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_count(catalog_, other, strlen(other), &after));
  EXPECT_EQ(before, after);
  EXPECT_EQ(0u, BlindLinesInTheStore(later));
  {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_DRAFT, other,
            strlen(other), "en", 2, kField, strlen(kField), &texts, &lens, &n));
    EXPECT_EQ(1u, n);
    EXPECT_NE(Stored(other), std::string(texts[0], lens[0]))
        << "the draft's value is not the published one";
    gdefcore_values_free(catalog_, texts, lens, n);
  }
  /* The draft that leaves the erased value as it is applies. */
  EXPECT_EQ(GDEFCORE_OK, Publish(entity)) << last_refusal_;
  EXPECT_TRUE(ReadIs(catalog_, subject, entity, GDEFCORE_SUBJECT_ERASED));
  EXPECT_EQ(0u, BlindLinesInTheStore(subject));
}

/* The rebuild: every row deleted, then put back from the values that can be
 * decrypted, gives the blind table it was; run on a live tenant it changes
 * nothing; and an erased subject gets no row back. */
TEST_F(Subject, AReindexPutsBackEveryRowThatCanBeDecrypted) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char c[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ea[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eb[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ec[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t rows = 0;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, b));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, c));
  MakeEntity(ea);
  MakeEntity(eb);
  MakeEntity(ec);
  Save(a, ea);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_save(subjects_, catalog_, a, strlen(a), ea, strlen(ea),
          kField, strlen(kField), "en", 2, "later", 5));
  Save(a, ea, "fr");
  Save(b, eb);
  Save(c, ec);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erase(subjects_, c, strlen(c), c, strlen(c)));
  auto rows_now = BlindRowsIn(site_);
  ASSERT_EQ(4u, rows_now.size());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_reindex(subjects_, site_, &rows));
  EXPECT_EQ(4u, rows);
  EXPECT_EQ(rows_now, BlindRowsIn(site_));
  for (const char * s : {(const char *)a, (const char *)b, (const char *)c}) {
    GDEFSTOR_Write * w = NULL;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_begin(site_, (const char *)storage_,
        sizeof storage_, NULL, &w));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_blind_delete_subject(w, s, strlen(s)));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(w));
  }
  ASSERT_TRUE(BlindRowsIn(site_).empty());
  EXPECT_TRUE(Find(catalog_, "later").empty());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_reindex(subjects_, site_, &rows));
  EXPECT_EQ(4u, rows);
  EXPECT_EQ(rows_now, BlindRowsIn(site_));
  EXPECT_EQ(std::vector<std::string>{ea}, Find(catalog_, "later"));
  EXPECT_EQ(std::vector<std::string>{eb}, Find(catalog_, kPlain));
  EXPECT_EQ(0u, BlindLinesInTheStore(c));
}

/* A restore rebuilds the blind index a data set does not carry: a living
 * subject's value is found again in the restored tenant, an erased one's is
 * not, and the restored store holds rows for the living only. */
TEST_F(Subject, ARestoreRebuildsTheBlindIndexOfWhatCanBeDecrypted) {
  char a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ea[GDEFCORE_PUBLIC_ID_LEN + 1];
  char eb[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  Open();
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, b));
  MakeEntity(ea);
  MakeEntity(eb);
  Save(a, ea);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_save(subjects_, catalog_, b, strlen(b), eb, strlen(eb),
          kField, strlen(kField), "en", 2, "bea", 3));
  Bytes data = Snapshot();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_erase(subjects_, a, strlen(a), a,
      strlen(a)));
  NextMillisecond();
  Bytes keys = Keyset();
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  ASSERT_EQ(GDEFCORE_OK, Restore(empty, data, keys));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  EXPECT_EQ(std::vector<std::string>{eb}, Find(restored, "bea"));
  EXPECT_TRUE(Find(restored, kPlain).empty());
  EXPECT_EQ(1u, BlindLinesIn(empty, b));
  EXPECT_EQ(0u, BlindLinesIn(empty, a));
  EXPECT_TRUE(ReadIs(restored, a, ea, GDEFCORE_SUBJECT_ERASED));
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return ksrig::RunAll();
}
