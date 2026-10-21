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
 * The erasure sweep (AD-19, AD-25). A canary personal value goes through
 * every place the library writes a personal value: entity fields in two
 * languages, a superseded revision, the blind index and the subject row.
 * The subject is then erased and every byte the library can hand back is
 * searched for the canary as plaintext, hex and base64, as the blind-index
 * HMAC and every other tenant-key HMAC or hash of it, and for the subject's
 * key. "Every byte" is: both data stores exported to snapshots (and
 * unpacked, so a compressed member cannot hide a hit), the tenant store's
 * every row as the port dumps it (the blind table's with them, which a
 * snapshot leaves out: story S6c moved the blind index there from a store of
 * its own), the data set and the
 * key set the library itself makes, each revision document, each value read
 * back, the subject export, rendered pages, and what the process wrote to
 * standard output and standard error. The key store (keystore_rig.h picks its
 * backend) is where keys belong: its key set is searched too, and after the
 * erasure it must hold nothing of the subject but the ledger row.
 *
 * A sweep that cannot see passes. So before erasure each test requires
 * that the same machinery finds the canary where it must be (the export,
 * the blind table, the key set, the revision ciphertext), and that a
 * survivor's data is
 * still found after the erasure. The scanner is itself checked against
 * synthetic haystacks. tools/check-erasure.sh plants the defects.
 */

#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/query.h>
#include <ghoti.io/defiant-storage/revision.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#include <ghoti.io/defiant-storage/store.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/sha256.h>

#include <gtest/gtest.h>

#include "keystore_rig.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

namespace {

const char kCanary[] = "zq-canary-7f3a91c4-platypus";
const char kCanaryLater[] = "zq-canary-7f3a91c4-platypus-v2";
const char kCanaryFr[] = "zq-canary-7f3a91c4-ornithorynque";
const char kCanaryForm[] = "zq-canary-7f3a91c4-form-route-narwhal";
const char kCanaryEdit[] = "zq-canary-7f3a91c4-form-edited-manatee";
const char kSurvivor[] = "keep-me-survivor-55d0e2b8";
const char kSurvivorEdit[] = "keep-me-survivor-edited-91ac44f0";
const char kField[] = "name";
const uint8_t kRegistryTenant[] = {0x02};

typedef std::string Bytes;

Bytes B(const void * p, size_t n) {
  return Bytes(static_cast<const char *>(p), n);
}

Bytes Hex(const Bytes & raw, bool upper) {
  const char * digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  Bytes out;
  size_t i;
  for (i = 0; i < raw.size(); i++) {
    unsigned char c = static_cast<unsigned char>(raw[i]);
    out.push_back(digits[c >> 4]);
    out.push_back(digits[c & 0x0f]);
  }
  return out;
}

bool HexDecode(const Bytes & text, Bytes * out) {
  size_t i;
  out->clear();
  if (text.empty() || text.size() % 2 != 0) {
    return false;
  }
  for (i = 0; i < text.size(); i += 2) {
    int v[2];
    int j;
    for (j = 0; j < 2; j++) {
      char c = text[i + j];
      if (c >= '0' && c <= '9') {
        v[j] = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        v[j] = c - 'a' + 10;
      } else if (c >= 'A' && c <= 'F') {
        v[j] = c - 'A' + 10;
      } else {
        return false;
      }
    }
    out->push_back(static_cast<char>(v[0] * 16 + v[1]));
  }
  return true;
}

Bytes Base64(const Bytes & raw) {
  static const char kDigits[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  Bytes out;
  size_t i;
  for (i = 0; i < raw.size(); i += 3) {
    uint32_t v = static_cast<unsigned char>(raw[i]) << 16;
    size_t left = raw.size() - i;
    if (left > 1) {
      v |= static_cast<uint32_t>(static_cast<unsigned char>(raw[i + 1])) << 8;
    }
    if (left > 2) {
      v |= static_cast<unsigned char>(raw[i + 2]);
    }
    out.push_back(kDigits[(v >> 18) & 63]);
    out.push_back(kDigits[(v >> 12) & 63]);
    out.push_back(left > 1 ? kDigits[(v >> 6) & 63] : '=');
    out.push_back(left > 2 ? kDigits[v & 63] : '=');
  }
  return out;
}

Bytes UrlSafe(Bytes text) {
  size_t i;
  for (i = 0; i < text.size(); i++) {
    if (text[i] == '+') {
      text[i] = '-';
    } else if (text[i] == '/') {
      text[i] = '_';
    }
  }
  return text;
}

/* A needle that is a substring of a base64 stream, whatever the offset of
 * the value in that stream: encode with 0, 1 and 2 leading bytes, and keep
 * only the groups that do not depend on the neighbours. */
std::vector<Bytes> Base64Middles(const Bytes & raw) {
  std::vector<Bytes> out;
  size_t k;
  for (k = 0; k < 3; k++) {
    Bytes enc = Base64(Bytes(k, '\0') + raw);
    size_t head = k == 0 ? 0 : 4;
    while (!enc.empty() && enc[enc.size() - 1] == '=') {
      enc.erase(enc.size() - 1);
    }
    if (enc.size() < head + 4 + 8) {
      continue;
    }
    enc = enc.substr(head, enc.size() - head - 4);
    out.push_back(enc);
    out.push_back(UrlSafe(enc));
  }
  return out;
}

struct Needle {
  std::string label;
  Bytes bytes;
  bool tenant_only;  // may legitimately sit in the key set or the registry
};

void AddForms(std::vector<Needle> * out, const std::string & label,
    const Bytes & raw, bool tenant_only) {
  std::vector<Bytes> middles = Base64Middles(raw);
  size_t i;
  Needle n;
  n.tenant_only = tenant_only;
  n.label = label + " raw";
  n.bytes = raw;
  out->push_back(n);
  n.label = label + " hex";
  n.bytes = Hex(raw, false);
  out->push_back(n);
  n.label = label + " HEX";
  n.bytes = Hex(raw, true);
  out->push_back(n);
  for (i = 0; i < middles.size(); i++) {
    n.label = label + " base64";
    n.bytes = middles[i];
    out->push_back(n);
  }
}

Bytes Hmac(const Bytes & key, const Bytes & message) {
  unsigned char mac[32];
  if (gsec_hmac(GSEC_HMAC_SHA256, key.data(), key.size(), message.data(),
          message.size(), mac) != GSEC_OK) {
    return Bytes();
  }
  return B(mac, sizeof mac);
}

Bytes Sha256(const Bytes & message) {
  unsigned char digest[32];
  if (gsec_sha256(message.data(), message.size(), digest) != GSEC_OK) {
    return Bytes();
  }
  return B(digest, sizeof digest);
}

struct Artifact {
  std::string label;
  Bytes view;         // every byte, members unpacked
  bool tenant_data;   // false for the key set and the registry
};

/* The archive, as stored, followed by each member's name (hex keys also
 * decoded) and its body. */
bool Unpack(const Bytes & zip, Bytes * view) {
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  *view = zip;
  if (garc_stream_create_memory(reinterpret_cast<const uint8_t *>(zip.data()),
          zip.size(), &stream) != GARC_OK) {
    return false;
  }
  if (garc_open(stream, NULL, &archive) != GARC_OK) {
    garc_stream_destroy(stream);
    return false;
  }
  for (;;) {
    const GARC_Member * member = NULL;
    GARC_Result gr = garc_next(archive, &member);
    Bytes name;
    Bytes decoded;
    Bytes body;
    if (gr == GARC_END) {
      break;
    }
    if (gr != GARC_OK) {
      garc_close(archive);
      garc_stream_destroy(stream);
      return false;
    }
    name = B(member->name, member->name_length);
    if (HexDecode(name.substr(name.find(':') == Bytes::npos ? 0 : name.find(':') + 1),
            &decoded)) {
      name += "\n" + decoded;
    }
    body.resize(static_cast<size_t>(member->size));
    {
      size_t total = 0;
      while (total < body.size()) {
        size_t got = 0;
        gr = garc_read_member(archive, &body[total], body.size() - total, &got);
        if (gr != GARC_OK || got == 0) {
          garc_close(archive);
          garc_stream_destroy(stream);
          return false;
        }
        total += got;
      }
    }
    *view += "\n" + name + "\n" + body;
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return true;
}

bool Contains(const Bytes & hay, const Bytes & needle) {
  return !needle.empty() && hay.find(needle) != Bytes::npos;
}

/* The sweep: every needle against every artifact it may not be in. */
std::vector<std::string> Sweep(const std::vector<Artifact> & artifacts,
    const std::vector<Needle> & needles) {
  std::vector<std::string> found;
  size_t a;
  size_t n;
  for (a = 0; a < artifacts.size(); a++) {
    for (n = 0; n < needles.size(); n++) {
      if (needles[n].tenant_only && !artifacts[a].tenant_data) {
        continue;
      }
      if (Contains(artifacts[a].view, needles[n].bytes)) {
        found.push_back(needles[n].label + " in " + artifacts[a].label);
      }
    }
  }
  return found;
}

bool FoundIn(const std::vector<Artifact> & artifacts, const Bytes & needle,
    const std::string & label_prefix) {
  size_t a;
  for (a = 0; a < artifacts.size(); a++) {
    if (artifacts[a].label.compare(0, label_prefix.size(), label_prefix) == 0 &&
        Contains(artifacts[a].view, needle)) {
      return true;
    }
  }
  return false;
}

std::string Joined(const std::vector<std::string> & lines) {
  std::string out;
  size_t i;
  for (i = 0; i < lines.size(); i++) {
    out += "\n  leak: " + lines[i];
  }
  return out;
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

class Erasure : public ::testing::Test {
 protected:
  GDEFSTOR_Store * registry_;
  GDEFSTOR_Store * site_;    // the tenant's data store, its blind table too
  GDEFSTOR_KeyStore * keys_;
  ksrig::Counts counts_;
  GDEFCORE_Inst * inst_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Subjects * subjects_;
  GDEFCORE_Request * request_;
  GDEFCORE_Request * anon_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t storage_[16];
  char tenant_[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string session_;
  char a_[GDEFCORE_PUBLIC_ID_LEN + 1];       // the subject to be erased
  char b_[GDEFCORE_PUBLIC_ID_LEN + 1];       // the survivor
  char ea_[GDEFCORE_PUBLIC_ID_LEN + 1];      // a's entity
  char eb_[GDEFCORE_PUBLIC_ID_LEN + 1];      // b's entity
  char post_[GDEFCORE_PUBLIC_ID_LEN + 1];    // a published page
  char ef_[GDEFCORE_PUBLIC_ID_LEN + 1];      // a's entity, written by a form
  std::vector<Needle> needles_;
  std::vector<Needle> survivor_;

  void SetUp() override {
    registry_ = NULL;
    site_ = NULL;
    keys_ = NULL;
    inst_ = NULL;
    catalog_ = NULL;
    subjects_ = NULL;
    request_ = NULL;
    anon_ = NULL;
    memset(root_, 0x42, sizeof root_);
    memset(storage_, 0, sizeof storage_);
    memset(tenant_, 0, sizeof tenant_);
    memset(ef_, 0, sizeof ef_);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &registry_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &site_));
    ASSERT_EQ(GDEFSTOR_OK, ksrig::Open(ksrig::Chosen(), &counts_, &keys_));
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
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(storage_, sizeof storage_, 0, 0, NULL, &request_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(storage_, sizeof storage_, 0, 0, NULL, &anon_));
  }

  void TearDown() override {
    gdefcore_request_destroy(anon_);
    gdefcore_request_destroy(request_);
    gdefcore_subject_destroy(subjects_);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_inst_destroy(inst_);
    gdefstor_keystore_destroy(keys_);
    gdefstor_store_destroy(site_);
    gdefstor_store_destroy(registry_);
  }

  /* The key set, as the library takes it: wrapped keys, the keyring's wrap
   * and the ledger. Not tenant data. */
  Bytes Keyset() {
    uint8_t * set = NULL;
    size_t n = 0;
    Bytes out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_keyset(subjects_, &set, &n));
    if (set != NULL) {
      out = B(set, n);
    }
    gdefstor_bytes_free(NULL, set);
    return out;
  }

  /* The key set as hex is how its bytes are written; a needle in raw form is
   * found in it decoded, so both are searched. */
  void AddKeyset(std::vector<Artifact> * out, const std::string & label) {
    Artifact art;
    Bytes set = Keyset();
    Bytes decoded;
    size_t at = 0;
    art.label = label;
    art.tenant_data = false;
    art.view = set;
    while (at < set.size()) {
      size_t nl = set.find('\n', at);
      size_t sp = set.rfind(' ', nl == Bytes::npos ? Bytes::npos : nl);
      if (nl == Bytes::npos) {
        nl = set.size();
      }
      if (sp != Bytes::npos && sp >= at && HexDecode(set.substr(sp + 1, nl - sp - 1),
              &decoded)) {
        art.view += "\n" + decoded;
      }
      at = nl + 1;
    }
    EXPECT_GT(set.size(), 0u) << label;
    out->push_back(art);
  }

  GDEFCORE_Keyring * Ring() {
    return gdefcore_inst_tenant_keyring(inst_, tenant_, strlen(tenant_));
  }

  void Login() {
    char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * token = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_bind(catalog_, Ring(), root_, sizeof root_, admin,
            strlen(admin), "ada", 3, "secret", 6, id));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_login(catalog_, Ring(), root_, sizeof root_, "ada", 3,
            "secret", 6, 3600, &token, &n));
    session_.assign(token, n);
    gdefcore_text_free(catalog_, token);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_check(catalog_, request_, Ring(), root_, sizeof root_,
            session_.data(), session_.size()));
  }

  void DefinePerson() {
    GDEFCORE_Field field;
    memset(&field, 0, sizeof field);
    field.size = sizeof field;
    field.name = kField;
    field.name_len = strlen(kField);
    field.required = 1;
    field.personal = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, "site.person", 11, GDEFCORE_TYPE_CONTENT,
            &field, 1));
  }

  void SaveValue(const char * subject, const char * entity, const char * lang,
      const char * plain) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_save(subjects_, catalog_, subject, strlen(subject),
            entity, strlen(entity), kField, strlen(kField), lang, strlen(lang),
            plain, strlen(plain)));
  }

  /* A published page, written the way the admin writes one: a form. */
  void PublishPost() {
    GDEFCORE_Value values[2];
    const char * slots[2];
    size_t lens[2];
    int conflict = 1;
    char * token = NULL;
    size_t token_len = 0;
    uint8_t * kit = NULL;
    size_t kit_len = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &kit, &kit_len));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, kit, kit_len));
    gdefcore_text_free(catalog_, reinterpret_cast<char *>(kit));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.post", 9, post_, NULL));
    OneValue(&values[0], "title", "Welcome to the parish", &slots[0], &lens[0]);
    OneValue(&values[1], "body", "Doors open at nine.", &slots[1], &lens[1]);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_sign(catalog_, request_, Ring(), root_, sizeof root_,
            session_.data(), session_.size(), "edit", 4, post_, strlen(post_),
            "en", 2, values, 2, "welcome", 7, &token, &token_len));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_submit(catalog_, request_, Ring(), root_, sizeof root_,
            session_.data(), session_.size(), token, token_len, &conflict));
    gdefcore_text_free(catalog_, token);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_form_publish(catalog_, post_, strlen(post_)));
  }

  Bytes Page(const char * path) {
    char * bytes = NULL;
    size_t n = 0;
    Bytes out;
    if (gdefcore_render_page(catalog_, NULL, anon_, path, strlen(path),
            GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n) == GDEFCORE_OK &&
        bytes != NULL) {
      out.assign(bytes, n);
    }
    gdefcore_text_free(catalog_, bytes);
    return out;
  }

  Bytes StorageExport(GDEFSTOR_Store * store, const uint8_t * tenant,
      size_t tenant_len) {
    uint8_t * zip = NULL;
    size_t n = 0;
    Bytes out;
    EXPECT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_export(store, reinterpret_cast<const char *>(tenant),
            tenant_len, NULL, &zip, &n));
    if (zip != NULL) {
      out = B(zip, n);
    }
    gdefstor_bytes_free(NULL, zip);
    return out;
  }

  void AddZip(std::vector<Artifact> * out, const std::string & label,
      const Bytes & zip, bool tenant_data) {
    Artifact art;
    art.label = label;
    art.tenant_data = tenant_data;
    EXPECT_TRUE(Unpack(zip, &art.view)) << "cannot unpack " << label;
    EXPECT_GT(zip.size(), 0u) << label;
    out->push_back(art);
  }

  void AddText(std::vector<Artifact> * out, const std::string & label,
      const Bytes & text) {
    Artifact art;
    art.label = label;
    art.view = text;
    art.tenant_data = true;
    out->push_back(art);
  }

  /* Everything the library can hand back, as artifacts. */
  void Collect(std::vector<Artifact> * out, const std::string & stage) {
    uint8_t * zip = NULL;
    size_t zip_len = 0;
    const char * ids[2] = {ea_, eb_};
    const char * langs[2] = {"en", "fr"};
    const char * subjects[2] = {a_, b_};
    size_t i;
    size_t j;
    out->clear();
    AddZip(out, "site storage snapshot " + stage,
        StorageExport(site_, storage_, sizeof storage_), true);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_snapshot(subjects_, site_, &zip, &zip_len));
    AddZip(out, "library subject snapshot " + stage, B(zip, zip_len), true);
    gdefstor_bytes_free(NULL, zip);
    AddText(out, "tenant store rows " + stage, Rows(site_));
    AddKeyset(out, "key set " + stage);
    AddZip(out, "registry snapshot " + stage,
        StorageExport(registry_, kRegistryTenant, sizeof kRegistryTenant), false);
    /* Every recorded revision of every entity, in each language, as the
     * port hands it back, and every draft (story S6b: the port's revisions
     * replace core's revision documents). Walked by type, from the type
     * records core keeps, so no entity is reached only through a list. */
    {
      size_t docs = 0;
      const char * tenant = reinterpret_cast<const char *>(storage_);
      GDEFSTOR_RecordList * types = NULL;
      ASSERT_EQ(GDEFSTOR_OK,
          gdefstor_record_list(site_, tenant, sizeof storage_, "core.type", 9,
              "", 0, 0, GDEFSTOR_RECORD_MAX_PAGE, &types));
      for (size_t ti = 0; ti < gdefstor_record_list_count(types); ti++) {
        const char * tk = NULL;
        size_t tkn = 0;
        const uint8_t * tb = NULL;
        size_t tbn = 0;
        ASSERT_EQ(GDEFSTOR_OK,
            gdefstor_record_list_item(types, ti, &tk, &tkn, &tb, &tbn));
        GDEFSTOR_Type * type = NULL;
        if (gdefstor_type_get(site_, tenant, sizeof storage_, tk, tkn, &type) !=
            GDEFSTOR_OK) {
          continue;
        }
        GDEFSTOR_Query q;
        memset(&q, 0, sizeof q);
        q.size = sizeof q;
        q.language = "en";
        q.language_len = 2;
        GDEFSTOR_QueryResult * r = NULL;
        ASSERT_EQ(GDEFSTOR_OK,
            gdefstor_entity_query(site_, tenant, sizeof storage_, tk, tkn, &q, &r));
        for (size_t ri = 0; ri < gdefstor_query_result_rows(r); ri++) {
          const char * pid = NULL;
          size_t pn = 0;
          ASSERT_EQ(GDEFSTOR_OK, gdefstor_query_result_entity(r, ri, &pid, &pn));
          const std::string id(pid, pn);
          for (const char * lang : {"en", "fr"}) {
            GDEFSTOR_History * h = NULL;
            if (gdefstor_entity_history(site_, tenant, sizeof storage_, id.data(),
                    id.size(), lang, 2, &h) != GDEFSTOR_OK) {
              continue;
            }
            for (size_t hi = 0; hi < gdefstor_history_revision_count(h); hi++) {
              GDEFSTOR_RevisionInfo info;
              memset(&info, 0, sizeof info);
              info.size = sizeof info;
              GDEFSTOR_Tree * tree = NULL;
              uint8_t * json = NULL;
              size_t jn = 0;
              if (gdefstor_history_revision(h, hi, &info) != GDEFSTOR_OK ||
                  gdefstor_entity_tree(site_, tenant, sizeof storage_, id.data(),
                      id.size(), lang, 2, info.revision, &tree) != GDEFSTOR_OK) {
                continue;
              }
              if (gdefstor_tree_to_json(type, tree, &json, &jn) == GDEFSTOR_OK) {
                AddText(out, "revision document " + id + " #" +
                                 std::to_string(info.revision) + " " + lang + " " +
                                 stage,
                    B(json, jn));
                docs += 1;
              }
              gdefstor_bytes_free(NULL, json);
              gdefstor_tree_free(tree);
            }
            gdefstor_history_free(h);
          }
          GDEFSTOR_Draft * d = NULL;
          if (gdefstor_draft_get(site_, tenant, sizeof storage_, id.data(),
                  id.size(), &d) == GDEFSTOR_OK) {
            GDEFSTOR_DraftInfo di;
            memset(&di, 0, sizeof di);
            di.size = sizeof di;
            if (gdefstor_draft_info(d, &di) == GDEFSTOR_OK) {
              for (size_t k = 0; k < di.language_count; k++) {
                GDEFSTOR_DraftTree dt;
                memset(&dt, 0, sizeof dt);
                dt.size = sizeof dt;
                if (gdefstor_draft_tree(d, k, &dt) == GDEFSTOR_OK) {
                  AddText(out, "revision document draft " + id + " " + stage,
                      B(dt.json, dt.json_len));
                }
              }
            }
            gdefstor_draft_free(d);
          }
        }
        gdefstor_query_result_free(r);
        gdefstor_type_free(type);
      }
      gdefstor_record_list_free(types);
      EXPECT_GE(docs, 8u) << "the revision walk found too few documents";
    }
    for (i = 0; i < 2; i++) {
      for (j = 0; j < 2; j++) {
        int view;
        for (view = 0; view < 3; view++) {
          char ** texts = NULL;
          size_t * lens = NULL;
          size_t n = 0;
          Bytes joined;
          size_t t;
          if (gdefcore_entity_values(catalog_, NULL,
                  view == 0   ? GDEFCORE_VIEW_PUBLISHED
                  : view == 1 ? GDEFCORE_VIEW_DRAFT
                              : GDEFCORE_VIEW_CURRENT,
                  ids[i], strlen(ids[i]), langs[j], 2, kField, strlen(kField),
                  &texts, &lens, &n) == GDEFCORE_OK) {
            for (t = 0; t < n; t++) {
              joined += B(texts[t], lens[t]) + "\n";
            }
          }
          gdefcore_values_free(catalog_, texts, lens, n);
          AddText(out, "entity values " + stage, joined);
        }
      }
    }
    if (ef_[0] != '\0') {
      for (j = 0; j < 2; j++) {
        int view;
        for (view = 0; view < 3; view++) {
          char ** texts = NULL;
          size_t * lens = NULL;
          size_t n = 0;
          Bytes joined;
          size_t t;
          if (gdefcore_entity_values(catalog_, NULL,
                  view == 0   ? GDEFCORE_VIEW_PUBLISHED
                  : view == 1 ? GDEFCORE_VIEW_DRAFT
                              : GDEFCORE_VIEW_CURRENT,
                  ef_, strlen(ef_), langs[j], 2, kField, strlen(kField), &texts,
                  &lens, &n) == GDEFCORE_OK) {
            for (t = 0; t < n; t++) {
              joined += B(texts[t], lens[t]) + "\n";
            }
          }
          gdefcore_values_free(catalog_, texts, lens, n);
          AddText(out, "entity values (form route) " + stage, joined);
        }
      }
      for (j = 0; j < 2; j++) {
        char * text = NULL;
        size_t tn = 0;
        if (gdefcore_subject_read(subjects_, catalog_, a_, strlen(a_), ef_,
                strlen(ef_), kField, strlen(kField), langs[j], 2, &text, &tn) ==
            GDEFCORE_OK) {
          AddText(out, "output: read of a (form route) " + stage, B(text, tn));
        }
        gdefcore_subject_free(subjects_, text);
      }
    }
    /* The revision views: every recorded revision of every entity, in both
     * languages, as the logged-in administrator is shown it, with the erased
     * marker where the person is erased. A view must not hold the value, the
     * ciphertext or anything made from either. */
    {
      const char * viewed[3] = {ea_, eb_, ef_};
      const char * owners[3] = {a_, b_, a_};
      size_t v;
      for (v = 0; v < 3; v++) {
        size_t count = 0;
        size_t seq;
        if (viewed[v][0] == '\0' ||
            gdefcore_entity_revision_count(catalog_, viewed[v], strlen(viewed[v]),
                &count) != GDEFCORE_OK) {
          continue;
        }
        for (seq = 1; seq <= count; seq++) {
          for (j = 0; j < 2; j++) {
            AddText(out,
                std::string("output: revision view of ") + (v == 1 ? "b " : "a ") +
                    stage,
                Bytes(RevisionView(viewed[v], seq, langs[j], owners[v])));
          }
        }
      }
    }
    for (i = 0; i < 2; i++) {
      char * json = NULL;
      size_t n = 0;
      if (gdefcore_subject_export(subjects_, catalog_, subjects[i],
              strlen(subjects[i]), &json, &n) == GDEFCORE_OK) {
        AddText(out, std::string("output: export of ") + (i == 0 ? "a " : "b ") + stage,
            B(json, n));
      }
      gdefcore_subject_free(subjects_, json);
      for (j = 0; j < 2; j++) {
        char * text = NULL;
        size_t tn = 0;
        if (gdefcore_subject_read(subjects_, catalog_, subjects[i],
                strlen(subjects[i]), ids[i], strlen(ids[i]), kField,
                strlen(kField), langs[j], 2, &text, &tn) == GDEFCORE_OK) {
          AddText(out, std::string("output: read of ") + (i == 0 ? "a " : "b ") + stage,
              B(text, tn));
        }
        gdefcore_subject_free(subjects_, text);
      }
    }
    AddText(out, "rendered page / " + stage, Page("/"));
    AddText(out, "rendered page welcome " + stage, Page("welcome"));
  }

  /* Let the logged-in admin view the revisions of a person. */
  void GrantHistory() {
    GDEFCORE_Permission permission;
    memset(&permission, 0, sizeof permission);
    permission.size = sizeof permission;
    permission.label = "View person history";
    permission.label_len = strlen(permission.label);
    permission.module_name = "site";
    permission.module_name_len = 4;
    permission.action = GDEFCORE_ACTION_REVISIONS_READ;
    permission.action_len = strlen(GDEFCORE_ACTION_REVISIONS_READ);
    permission.condition = GDEFCORE_ACCESS_ANY;
    permission.type_name = "site.person";
    permission.type_name_len = 11;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &permission));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog_, "admin", 5, permission.label,
            permission.label_len, "core.role", 9));
  }

  /* What a revision view shows of the personal field of one revision, for the
   * person named: "personal", "erased:[erased]", "absent", "shown:<text>" or
   * "<denied>". The subject store only ever turns "personal" into "erased". */
  std::string RevisionView(const char * entity, uint64_t seq, const char * lang,
      const char * subject) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    int status = 0;
    std::string out;
    GDEFCORE_Result rc = gdefcore_access_revision_values(catalog_, request_, entity,
        strlen(entity), seq, lang, 2, kField, strlen(kField), &status, &texts,
        &lens, &n);
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    if (status == GDEFCORE_REVISION_PERSONAL && subject != NULL) {
      char * text = NULL;
      size_t tn = 0;
      int shown = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_subject_revision_marker(subjects_, subject, strlen(subject),
              status, &shown, &text, &tn));
      status = shown;
      if (text != NULL) {
        out = ":" + std::string(text, tn);
      }
      gdefcore_subject_free(subjects_, text);
    }
    for (size_t t = 0; t < n; t++) {
      out += ":" + std::string(texts[t], lens[t]);
    }
    gdefcore_values_free(catalog_, texts, lens, n);
    return std::string(status == GDEFCORE_REVISION_SHOWN     ? "shown"
                       : status == GDEFCORE_REVISION_ABSENT   ? "absent"
                       : status == GDEFCORE_REVISION_PERSONAL ? "personal"
                       : status == GDEFCORE_REVISION_ERASED   ? "erased"
                                                              : "?") +
           out;
  }

  /* The forms of a subject's data that must be gone after erasure. */
  void Needles(const char * subject, const std::vector<std::string> & values,
      const Bytes & wrapped_key, std::vector<Needle> * out) {
    GDEFCORE_Keyring * ring = Ring();
    const char * infos[] = {"blind-index:name", "subject-wrap", "form"};
    std::vector<Bytes> keys;
    std::vector<std::string> key_labels;
    size_t i;
    size_t v;
    uint8_t raw[GDEFCORE_SUBJECT_KEY_LEN];
    uint8_t derived[GDEFCORE_KEYRING_KEY_LEN];
    uint8_t wrap[GDEFCORE_KEYRING_WRAP_LEN];
    for (i = 0; i < sizeof infos / sizeof infos[0]; i++) {
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_keyring_derive(ring, root_, sizeof root_, infos[i],
              strlen(infos[i]), derived, sizeof derived));
      keys.push_back(B(derived, sizeof derived));
      key_labels.push_back(std::string("key[") + infos[i] + "]");
      AddForms(out, std::string("derived ") + infos[i] + " key", keys.back(), false);
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_keyring_export(ring, wrap, sizeof wrap));
    keys.push_back(B(wrap, sizeof wrap));
    key_labels.push_back("key[tenant keyring wrap]");
    AddForms(out, "tenant keyring wrap", keys.back(), true);
    keys.push_back(B(root_, sizeof root_));
    key_labels.push_back("key[account root]");
    AddForms(out, "account root", keys.back(), false);
    keys.push_back(B(storage_, sizeof storage_));
    key_labels.push_back("key[storage tenant key]");
    keys.push_back(Bytes(tenant_));
    key_labels.push_back("key[tenant id]");
    if (gdefcore_subject_key(subjects_, subject, strlen(subject), raw) ==
        GDEFCORE_OK) {
      keys.push_back(B(raw, sizeof raw));
      key_labels.push_back("key[subject key]");
      AddForms(out, "subject key", keys.back(), false);
      memset(raw, 0, sizeof raw);
    }
    if (!wrapped_key.empty()) {
      AddForms(out, "wrapped subject key", wrapped_key, false);
    }
    for (v = 0; v < values.size(); v++) {
      const std::string label = "value '" + values[v] + "'";
      Needle plain;
      plain.label = label + " plaintext";
      plain.bytes = values[v];
      plain.tenant_only = false;
      out->push_back(plain);
      AddForms(out, label + " as hex/base64", values[v], false);
      AddForms(out, label + " sha256", Sha256(values[v]), false);
      for (i = 0; i < keys.size(); i++) {
        AddForms(out, label + " hmac " + key_labels[i], Hmac(keys[i], values[v]),
            false);
      }
    }
  }

  /* The subject's wrapped key, exactly as the key store holds it. */
  Bytes WrappedKey(const char * subject) {
    uint8_t * got = NULL;
    size_t n = 0;
    int erased = 0;
    Bytes out;
    if (gdefstor_keystore_subject_sealed(keys_,
            reinterpret_cast<const char *>(storage_), sizeof storage_, subject,
            strlen(subject), &erased, &got, &n) == GDEFSTOR_OK &&
        got != NULL) {
      out = B(got, n);
    }
    gdefstor_bytes_free(NULL, got);
    return out;
  }

  /* The state every sweep starts from: subject a, with a value in two
   * languages and a superseded revision, and a survivor b. */
  void Populate() {
    DefinePerson();
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, b_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.person", 11, ea_, NULL));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.person", 11, eb_, NULL));
    SaveValue(a_, ea_, "en", kCanary);
    SaveValue(a_, ea_, "en", kCanaryLater);
    SaveValue(a_, ea_, "fr", kCanaryFr);
    SaveValue(b_, eb_, "en", kSurvivor);
    SaveValue(b_, eb_, "fr", kSurvivor);
    Login();
    GrantHistory();
    PublishPost();
  }

  /* The subject route of a form: sign for a subject, submit with the store. */
  GDEFCORE_Result SignFor(const char * subject, const char * entity,
      const char * text, std::string * token) {
    GDEFCORE_Value value;
    const char * slot = NULL;
    size_t slot_len = 0;
    char * out = NULL;
    size_t out_len = 0;
    GDEFCORE_Result rc;
    OneValue(&value, kField, text, &slot, &slot_len);
    rc = gdefcore_form_sign_subject(catalog_, request_, Ring(), root_,
        sizeof root_, session_.data(), session_.size(), "edit", 4, entity,
        strlen(entity), "en", 2, &value, 1, NULL, 0, subject, strlen(subject),
        &out, &out_len);
    if (rc == GDEFCORE_OK) {
      token->assign(out, out_len);
      gdefcore_text_free(catalog_, out);
    }
    return rc;
  }

  GDEFCORE_Result SubmitFor(const std::string & token, int * conflict) {
    return gdefcore_form_submit_subject(catalog_, request_, Ring(), root_,
        sizeof root_, session_.data(), session_.size(), token.data(),
        token.size(), subjects_, conflict);
  }

  GDEFCORE_Result SubmitPlain(const std::string & token, int * conflict) {
    return gdefcore_form_submit(catalog_, request_, Ring(), root_, sizeof root_,
        session_.data(), session_.size(), token.data(), token.size(), conflict);
  }

  void Publish(const char * entity) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_publish(catalog_, entity, strlen(entity)));
  }

  /* What the subject reads, or "<error N>". */
  std::string ReadAs(const char * subject, const char * entity) {
    char * text = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_subject_read(subjects_, catalog_, subject,
        strlen(subject), entity, strlen(entity), kField, strlen(kField), "en", 2,
        &text, &n);
    std::string out;
    if (rc != GDEFCORE_OK) {
      return "<error " + std::to_string(static_cast<int>(rc)) + ">";
    }
    out.assign(text, n);
    gdefcore_subject_free(subjects_, text);
    return out;
  }

  /* The text stored for the field in one view, "" when there is none. */
  std::string Stored(const char * entity, int view) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    std::string out;
    if (gdefcore_entity_values(catalog_, NULL, view, entity, strlen(entity),
            "en", 2, kField, strlen(kField), &texts, &lens, &n) == GDEFCORE_OK &&
        n == 1) {
      out.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, n);
    return out;
  }

  size_t Revisions(const char * entity) {
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision_count(catalog_, entity, strlen(entity), &n));
    return n;
  }

  /* Every write moves it, a draft included (a form submit writes one). */
  uint64_t Version(const char * entity) {
    uint64_t v = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_version(catalog_, entity, strlen(entity), &v));
    return v;
  }

  /* Every row of the tenant in @p store as the port dumps it: the blind
   * table's too, which no snapshot carries (AD-23). */
  Bytes Rows(GDEFSTOR_Store * store) {
    uint8_t * text = NULL;
    size_t n = 0;
    Bytes out;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_model_dump(store,
        reinterpret_cast<const char *>(storage_), sizeof storage_,
        GDEFSTOR_MODEL_TRUTH, &text, &n));
    if (text != NULL) {
      out = B(text, n);
    }
    gdefstor_bytes_free(NULL, text);
    return out;
  }

  /* The blind rows of a subject in the tenant store, read from the store
   * itself: "B row item valid_from field <subject hex> <mac hex> ...". */
  size_t BlindCount(const char * subject) {
    Bytes rows = "\n" + Rows(site_);
    Bytes want = " " + Hex(Bytes(subject), false) + " ";
    size_t n = 0;
    size_t at = 0;
    while ((at = rows.find("\nB ", at)) != Bytes::npos) {
      size_t end = rows.find('\n', at + 1);
      Bytes line = rows.substr(at, end == Bytes::npos ? Bytes::npos : end - at);
      n += line.find(want) != Bytes::npos;
      at += 1;
    }
    return n;
  }

  void NewPerson(char out[GDEFCORE_PUBLIC_ID_LEN + 1]) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.person", 11, out, NULL));
  }

  Bytes TenantExport() {
    return StorageExport(site_, storage_, sizeof storage_);
  }

  /* The form route: a value for subject a, written by a form through the
   * subject functions and published. Extends Populate. */
  void PopulateForm() {
    std::string token;
    int conflict = 0;
    NewPerson(ef_);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_EQ(GDEFCORE_OK, SignFor(a_, ef_, kCanaryForm, &token));
    ASSERT_EQ(GDEFCORE_OK, SubmitFor(token, &conflict));
    Publish(ef_);
  }

  void Erase(const char * subject) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_erase(subjects_, subject, strlen(subject), subject,
            strlen(subject)));
  }

  /* The blind-index value of @p plain, as the library computes it. */
  Bytes BlindMac(const char * plain) {
    uint8_t mac[32];
    memset(mac, 0, sizeof mac);
    if (gdefcore_subject_mac(subjects_, kField, strlen(kField), plain,
            strlen(plain), mac) != GDEFCORE_OK) {
      return Bytes();
    }
    return B(mac, sizeof mac);
  }

  /* Whether the tenant store holds a blind row of @p subject with @p mac. */
  bool BlindRowHas(const char * subject, const Bytes & mac) {
    Bytes rows = Rows(site_);
    return rows.find(" " + Hex(Bytes(subject), false) + " " + Hex(mac, false) +
                     " ") != Bytes::npos;
  }
};

}  // namespace

/* The scanner finds every form it claims to, wherever the value sits. */
TEST_F(Erasure, Scanner) {
  const Bytes secret = "zq-canary-scanner-0123456789abcdef";
  std::vector<Needle> needles;
  size_t n;
  size_t k;
  Needle lone;
  AddForms(&needles, "scanner canary", secret, false);
  ASSERT_GE(needles.size(), 9u);
  for (n = 0; n < needles.size(); n++) {
    const Needle & needle = needles[n];
    Bytes hay = "...before " + needle.bytes + " after...";
    std::vector<Artifact> arts(1);
    arts[0].label = "synthetic";
    arts[0].view = hay;
    arts[0].tenant_data = true;
    EXPECT_EQ(1u, Sweep(arts, std::vector<Needle>(1, needle)).size())
        << needle.label;
  }
  /* A base64 stream carries the value at any of the three alignments. */
  for (k = 0; k < 3; k++) {
    std::vector<Artifact> arts(1);
    arts[0].label = "base64 stream";
    arts[0].view = Base64(Bytes(k, 'x') + secret + "tail");
    arts[0].tenant_data = true;
    EXPECT_FALSE(Sweep(arts, needles).empty()) << "alignment " << k;
  }
  /* And a haystack without it is clean. */
  {
    std::vector<Artifact> arts(1);
    arts[0].label = "clean";
    arts[0].view = "nothing to see here, not even zq-canary-scanner-0123456789abcde";
    arts[0].tenant_data = true;
    EXPECT_TRUE(Sweep(arts, needles).empty());
  }
  /* A side-store-only needle is not charged to the side store. */
  lone.label = "tenant wrap";
  lone.bytes = "wrapwrapwrap";
  lone.tenant_only = true;
  {
    std::vector<Artifact> arts(2);
    arts[0].label = "side";
    arts[0].view = "xx wrapwrapwrap xx";
    arts[0].tenant_data = false;
    arts[1].label = "site";
    arts[1].view = "xx wrapwrapwrap xx";
    arts[1].tenant_data = true;
    std::vector<std::string> hits = Sweep(arts, std::vector<Needle>(1, lone));
    ASSERT_EQ(1u, hits.size());
    EXPECT_NE(std::string::npos, hits[0].find("in site"));
  }
}

/* The scanner reads standard output, standard error, a rendered scope and a
 * zip member: the channels the sweep claims to cover. */
TEST_F(Erasure, Channels) {
  std::vector<Needle> needles;
  std::vector<Artifact> arts;
  Bytes zip;
  Bytes view;
  char * page = NULL;
  size_t page_len = 0;
  std::string src = std::string("<p>") + kCanary + "</p>";
  AddForms(&needles, "canary", kCanary, false);
  testing::internal::CaptureStdout();
  printf("log line: %s\n", kCanary);
  AddText(&arts, "stdout", testing::internal::GetCapturedStdout());
  testing::internal::CaptureStderr();
  fprintf(stderr, "warn line: %s\n", kCanary);
  AddText(&arts, "stderr", testing::internal::GetCapturedStderr());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_scope(catalog_, src.data(), src.size(), 500, &page,
          &page_len));
  AddText(&arts, "rendered scope", B(page, page_len));
  gdefcore_text_free(catalog_, page);
  /* A record written through the port with the canary as its value, then
   * exported and unpacked. */
  {
    GDEFSTOR_Write * write = NULL;
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_write_begin(site_, reinterpret_cast<const char *>(storage_),
            sizeof storage_, NULL, &write));
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_record_put(write, "x.test", 6, "row", 3,
            reinterpret_cast<const uint8_t *>(kCanary), strlen(kCanary)));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(write));
    zip = StorageExport(site_, storage_, sizeof storage_);
    ASSERT_FALSE(zip.empty());
    EXPECT_TRUE(Unpack(zip, &view));
    AddText(&arts, "unpacked member", view);
  }
  EXPECT_EQ(arts.size(), 4u);
  {
    size_t a;
    for (a = 0; a < arts.size(); a++) {
      std::vector<Artifact> one(1, arts[a]);
      EXPECT_FALSE(Sweep(one, needles).empty()) << arts[a].label;
    }
  }
}

/* The sweep. Control first, erase, then every artifact again. */
TEST_F(Erasure, Sweep) {
  std::vector<Artifact> pre;
  std::vector<Artifact> post;
  std::vector<std::string> values;
  std::vector<std::string> leaks;
  std::vector<Needle> survivor;
  Bytes wrapped;
  Bytes survivor_wrapped;
  Bytes mac_later;
  Bytes mac_fr;
  Bytes mac_first;
  Bytes mac_survivor;
  Bytes mac_form;
  size_t count = 0;
  Populate();
  if (HasFatalFailure()) {
    return;
  }
  PopulateForm();
  if (HasFatalFailure()) {
    return;
  }
  /* One blind row per value version (story S6c): the first value, the one
   * that superseded it, the French one and the form's. */
  count = BlindCount(a_);
  ASSERT_EQ(4u, count);
  mac_later = BlindMac(kCanaryLater);
  mac_fr = BlindMac(kCanaryFr);
  mac_form = BlindMac(kCanaryForm);
  mac_survivor = BlindMac(kSurvivor);
  ASSERT_EQ(32u, mac_later.size());
  ASSERT_EQ(32u, mac_fr.size());
  ASSERT_EQ(32u, mac_form.size());
  ASSERT_EQ(32u, mac_survivor.size());
  EXPECT_TRUE(BlindRowHas(a_, mac_later));
  EXPECT_TRUE(BlindRowHas(a_, mac_fr));
  EXPECT_TRUE(BlindRowHas(a_, mac_form));
  EXPECT_TRUE(BlindRowHas(b_, mac_survivor));
  /* The first value was superseded; its version keeps its row while the
   * subject exists (history is searchable), and its HMAC is a form of the
   * canary. Compute it independently, and check that the same computation
   * reproduces the library's own for the others. */
  {
    uint8_t key[GDEFCORE_KEYRING_KEY_LEN];
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_derive(Ring(), root_, sizeof root_, "blind-index:name",
            strlen("blind-index:name"), key, sizeof key));
    mac_first = Hmac(B(key, sizeof key), kCanary);
    EXPECT_EQ(mac_later, Hmac(B(key, sizeof key), kCanaryLater));
    EXPECT_EQ(mac_fr, Hmac(B(key, sizeof key), kCanaryFr));
    EXPECT_EQ(mac_form, Hmac(B(key, sizeof key), kCanaryForm));
    EXPECT_EQ(mac_survivor, Hmac(B(key, sizeof key), kSurvivor));
  }
  wrapped = WrappedKey(a_);
  survivor_wrapped = WrappedKey(b_);
  ASSERT_EQ(static_cast<size_t>(GDEFCORE_KEYRING_WRAP_LEN), wrapped.size());
  values.push_back(kCanary);
  values.push_back(kCanaryLater);
  values.push_back(kCanaryFr);
  values.push_back(kCanaryForm);
  Needles(a_, values, wrapped, &needles_);
  ASSERT_FALSE(HasFatalFailure());
  {
    std::vector<std::string> sv(1, kSurvivor);
    Needles(b_, sv, survivor_wrapped, &survivor);
  }
  ASSERT_FALSE(HasFatalFailure());

  /* CONTROL, before erasure: the sweep must see the canary where the
   * library puts it, or its clean answer afterwards means nothing. */
  Collect(&pre, "before");
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_TRUE(FoundIn(pre, kCanary, "output: export of a"));
  EXPECT_TRUE(FoundIn(pre, kCanaryLater, "output: export of a"));
  EXPECT_TRUE(FoundIn(pre, kCanaryFr, "output: read of a"));
  EXPECT_TRUE(FoundIn(pre, kCanaryForm, "output: export of a"));
  EXPECT_TRUE(FoundIn(pre, kCanaryForm, "output: read of a (form route)"));
  EXPECT_TRUE(FoundIn(pre, Bytes("s1:"), "entity values (form route)"));
  EXPECT_TRUE(FoundIn(pre, Hex(mac_form, false), "tenant store rows"));
  EXPECT_TRUE(FoundIn(pre, Hex(mac_later, false), "tenant store rows"));
  EXPECT_TRUE(FoundIn(pre, Hex(mac_fr, false), "tenant store rows"));
  EXPECT_TRUE(FoundIn(pre, Hex(mac_first, false), "tenant store rows"));
  EXPECT_TRUE(FoundIn(pre, wrapped, "key set"));
  /* A snapshot and a revision document hold a personal value as "@c": the
   * hex of its sealed text (story S6c). */
  EXPECT_TRUE(FoundIn(pre, Hex(Bytes("s1:"), false), "site storage snapshot"));
  EXPECT_TRUE(FoundIn(pre, Hex(Bytes("s1:"), false), "revision document"));
  EXPECT_TRUE(FoundIn(pre, Hex(Bytes("s1:"), false), "library subject snapshot"));
  EXPECT_TRUE(FoundIn(pre, Bytes("Welcome to the parish"), "rendered page"));
  EXPECT_TRUE(FoundIn(pre, Hex(mac_survivor, false), "tenant store rows"));
  EXPECT_TRUE(FoundIn(pre, kSurvivor, "output: export of b"));
  EXPECT_FALSE(Sweep(pre, needles_).empty())
      << "the control found nothing: the sweep cannot see";
  {
    /* The whole control, by name: the value is in the outputs, the HMAC is
     * in the blind table, the wrapped key in the key set, and nothing is yet
     * in the tenant data. */
    std::vector<std::string> before = Sweep(pre, needles_);
    size_t i;
    bool export_has_plain = false;
    bool side_has_mac = false;
    bool side_has_key = false;
    for (i = 0; i < before.size(); i++) {
      if (before[i].find("plaintext in output: export of a") != std::string::npos) {
        export_has_plain = true;
      }
      if (before[i].find("hmac key[blind-index:name] hex in tenant store rows") !=
          std::string::npos) {
        side_has_mac = true;
      }
      if (before[i].find("wrapped subject key raw in key set") !=
          std::string::npos) {
        side_has_key = true;
      }
    }
    EXPECT_TRUE(export_has_plain) << Joined(before);
    EXPECT_TRUE(side_has_mac) << Joined(before);
    EXPECT_TRUE(side_has_key) << Joined(before);
  }

  /* ERASE, with the process's own output captured. */
  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  Erase(a_);
  Collect(&post, "after");
  AddText(&post, "standard output", testing::internal::GetCapturedStdout());
  AddText(&post, "standard error", testing::internal::GetCapturedStderr());
  ASSERT_FALSE(HasFatalFailure());

  /* The sweep. */
  leaks = Sweep(post, needles_);
  EXPECT_TRUE(leaks.empty()) << "erased subject's data is still reachable:"
                             << Joined(leaks);
  leaks = Sweep(post, survivor);

  /* The survivor is not a casualty, and the sweep still sees it: a sweep
   * that went blind between the two halves would fail here. */
  EXPECT_FALSE(leaks.empty()) << "the sweep no longer sees the survivor";
  EXPECT_TRUE(FoundIn(post, Hex(mac_survivor, false), "tenant store rows"));
  EXPECT_TRUE(FoundIn(post, survivor_wrapped, "key set"));
  EXPECT_TRUE(FoundIn(post, kSurvivor, "output: export of b"));
  EXPECT_TRUE(FoundIn(post, Hex(Bytes("s1:"), false), "site storage snapshot"));
  EXPECT_TRUE(FoundIn(post, Bytes("[erased]"), "output: read of a"));
  EXPECT_TRUE(FoundIn(post, Bytes("{\"erased\":\"[erased]\"}"),
      "output: export of a"));
  count = BlindCount(a_);
  EXPECT_EQ(0u, count);
  ASSERT_EQ(32u, mac_first.size());
  EXPECT_FALSE(FoundIn(post, Hex(mac_first, false), "tenant store rows"));
  EXPECT_FALSE(FoundIn(post, Hex(mac_first, false), ""));
}

/* Erasure survives restore (AD-19). The data set holds ciphertext and no key
 * of any kind: not the subject's, not the tenant's, not a key derived from
 * it, and no ledger (the key set carries that). The restore of the pair then
 * reads as erased and brings no key back, into the key store or anywhere. */
TEST_F(Erasure, SnapshotCarriesNoKey) {
  std::vector<Artifact> snap;
  std::vector<Artifact> after;
  std::vector<std::string> values;
  std::vector<std::string> leaks;
  std::vector<Needle> needles;
  Bytes wrapped;
  uint8_t * zip = NULL;
  size_t zip_len = 0;
  Bytes taken;
  GDEFSTOR_Store * empty = NULL;
  GDEFCORE_Catalog * restored = NULL;
  Populate();
  if (HasFatalFailure()) {
    return;
  }
  PopulateForm();
  if (HasFatalFailure()) {
    return;
  }
  wrapped = WrappedKey(a_);
  ASSERT_EQ(static_cast<size_t>(GDEFCORE_KEYRING_WRAP_LEN), wrapped.size());
  values.push_back(kCanary);
  values.push_back(kCanaryLater);
  values.push_back(kCanaryFr);
  values.push_back(kCanaryForm);
  Needles(a_, values, wrapped, &needles);
  ASSERT_FALSE(HasFatalFailure());

  /* The pair, taken while the subject is alive: the data set, then the key
   * set. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_snapshot(subjects_, site_, &zip, &zip_len));
  taken = B(zip, zip_len);
  gdefstor_bytes_free(NULL, zip);
  zip = NULL;
  Bytes keys = Keyset();
  AddZip(&snap, "library subject snapshot", taken, true);
  AddZip(&snap, "storage snapshot of the tenant store",
      StorageExport(site_, storage_, sizeof storage_), true);
  /* Control: the keys are real, and the scanner finds them where they live:
   * the key set. */
  {
    std::vector<Artifact> kept;
    AddKeyset(&kept, "key set");
    EXPECT_TRUE(FoundIn(kept, wrapped, "key set"));
    {
      uint8_t wrap[GDEFCORE_KEYRING_WRAP_LEN];
      ASSERT_EQ(GDEFCORE_OK, gdefcore_keyring_export(Ring(), wrap, sizeof wrap));
      EXPECT_TRUE(FoundIn(kept, B(wrap, sizeof wrap), "key set"));
      EXPECT_FALSE(FoundIn(snap, B(wrap, sizeof wrap), "library subject"))
          << "the snapshot carries the tenant keyring wrap";
    }
  }
  EXPECT_TRUE(FoundIn(snap, Bytes("taken_ms"), "library subject snapshot"));
  EXPECT_TRUE(FoundIn(snap, Hex(Bytes("s1:"), false), "library subject snapshot"));
  {
    uint8_t * ledger = NULL;
    size_t ledger_len = 9;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_snapshot_ledger(site_,
        reinterpret_cast<const uint8_t *>(taken.data()), taken.size(), NULL,
        &ledger, &ledger_len));
    EXPECT_EQ(0u, ledger_len) << "the data set carries a ledger";
    gdefstor_bytes_free(NULL, ledger);
  }
  leaks = Sweep(snap, needles);
  EXPECT_TRUE(leaks.empty()) << "a snapshot carries a key or a value:"
                             << Joined(leaks);

  /* Erase, restore into an empty tenant, and look again. */
  Erase(a_);
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &empty));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_restore(subjects_, empty,
          reinterpret_cast<const uint8_t *>(taken.data()), taken.size(),
          reinterpret_cast<const uint8_t *>(keys.data()), keys.size()));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(empty, storage_, sizeof storage_, NULL, NULL,
          &restored));
  {
    char * text = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_read(subjects_, restored, a_, strlen(a_), ea_, strlen(ea_),
            kField, strlen(kField), "en", 2, &text, &n));
    EXPECT_EQ(Bytes(GDEFCORE_SUBJECT_ERASED), B(text, n));
    gdefcore_subject_free(subjects_, text);
    text = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_subject_read(subjects_, restored, b_, strlen(b_), eb_, strlen(eb_),
            kField, strlen(kField), "en", 2, &text, &n));
    EXPECT_EQ(Bytes(kSurvivor), B(text, n));
    gdefcore_subject_free(subjects_, text);
  }
  {
    uint8_t raw[GDEFCORE_SUBJECT_KEY_LEN];
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_subject_key(subjects_, a_, strlen(a_), raw));
  }
  AddZip(&after, "restored tenant store snapshot",
      StorageExport(empty, storage_, sizeof storage_), true);
  /* Every row of both tenants, the rebuilt blind table's with them. */
  AddText(&after, "restored tenant store rows", Rows(empty));
  AddText(&after, "live tenant store rows after restore", Rows(site_));
  AddKeyset(&after, "key set after restore");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_snapshot(subjects_, empty, &zip, &zip_len));
  AddZip(&after, "library subject snapshot after restore", B(zip, zip_len), true);
  gdefstor_bytes_free(NULL, zip);
  leaks = Sweep(after, needles);
  EXPECT_TRUE(leaks.empty()) << "a restore brought data or a key back:"
                             << Joined(leaks);
  gdefcore_catalog_destroy(restored);
  gdefstor_store_destroy(empty);
}

/* AD-19, the plain form route. A personal field is never stored as the
 * caller's text: the plain sign and the plain submit refuse it and write
 * nothing, and the fields that are not personal go through as before. */
TEST_F(Erasure, FormPersonalField) {
  std::vector<Needle> needles;
  std::vector<Artifact> arts;
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t slot_len = 0;
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * token = NULL;
  size_t token_len = 0;
  std::string held;
  int conflict = 7;
  uint64_t before;
  DefinePerson();
  Login();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a_));
  NewPerson(entity);
  ASSERT_FALSE(HasFatalFailure());
  before = Version(entity);

  /* The plain sign has no subject to seal for. */
  OneValue(&value, kField, kCanary, &slot, &slot_len);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_form_sign(catalog_, request_, Ring(), root_, sizeof root_,
          session_.data(), session_.size(), "edit", 4, entity, strlen(entity),
          "en", 2, &value, 1, NULL, 0, &token, &token_len));
  EXPECT_EQ(NULL, token);

  /* A token that does hold a personal value (it has a subject) is not
   * accepted by the plain submit either: nothing is written, and the
   * refusal is not a conflict. */
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, entity, kCanary, &held));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitPlain(held, &conflict));
  EXPECT_EQ(0, conflict);
  EXPECT_EQ(before, Version(entity));
  EXPECT_EQ("", Stored(entity, GDEFCORE_VIEW_DRAFT));
  EXPECT_EQ("", Stored(entity, GDEFCORE_VIEW_PUBLISHED));
  EXPECT_EQ(0u, BlindCount(a_));

  /* The same token still goes through the subject route: the refusal was
   * about the route, not the token. */
  ASSERT_EQ(GDEFCORE_OK, SubmitFor(held, &conflict));
  EXPECT_EQ(before + 1, Version(entity));

  AddForms(&needles, "canary", kCanary, false);
  AddZip(&arts, "tenant store snapshot", TenantExport(), true);
  EXPECT_TRUE(Sweep(arts, needles).empty())
      << "a personal field written through a form is stored as plaintext";
  EXPECT_TRUE(FoundIn(arts, Hex(Bytes("s1:"), false), "tenant store snapshot"));
}

/* The plain form route keeps working for every field that is not personal,
 * on a type that has a personal field it leaves empty. */
TEST_F(Erasure, FormPlainRouteOtherFields) {
  GDEFCORE_Field fields[2];
  GDEFCORE_Value values[1];
  const char * slot = NULL;
  size_t slot_len = 0;
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * token = NULL;
  size_t token_len = 0;
  int conflict = 0;
  memset(fields, 0, sizeof fields);
  fields[0].size = sizeof fields[0];
  fields[0].name = "title";
  fields[0].name_len = 5;
  fields[0].required = 1;
  fields[1].size = sizeof fields[1];
  fields[1].name = "secret";
  fields[1].name_len = 6;
  fields[1].personal = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.mixed", 10, GDEFCORE_TYPE_CONTENT,
          fields, 2));
  Login();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.mixed", 10, entity, NULL));
  OneValue(&values[0], "title", "Parish notices", &slot, &slot_len);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_sign(catalog_, request_, Ring(), root_, sizeof root_,
          session_.data(), session_.size(), "edit", 4, entity, strlen(entity),
          "en", 2, values, 1, NULL, 0, &token, &token_len));
  /* A token with no subject keeps the layout it always had: a reader of the
   * clear header (the admin's) sees version 1. */
  EXPECT_EQ(1, static_cast<int>(static_cast<unsigned char>(token[0])));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_form_submit(catalog_, request_, Ring(), root_, sizeof root_,
          session_.data(), session_.size(), token, token_len, &conflict));
  gdefcore_text_free(catalog_, token);
  {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_DRAFT, entity,
            strlen(entity), "en", 2, "title", 5, &texts, &lens, &n));
    ASSERT_EQ(1u, n);
    EXPECT_EQ("Parish notices", std::string(texts[0], lens[0]));
    gdefcore_values_free(catalog_, texts, lens, n);
  }
}

/* The entity layer, writer by writer. gdefcore_entity_save and its draft
 * form refuse a personal value; a changeset that was told to accept sealed
 * values still refuses plaintext; a patch is parsed under the same rule; a
 * revert restores ciphertext and does not seal it again. */
TEST_F(Erasure, EntitySavePersonal) {
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t slot_len = 0;
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * cs = NULL;
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a_));
  NewPerson(entity);
  ASSERT_FALSE(HasFatalFailure());
  OneValue(&value, kField, kCanary, &slot, &slot_len);

  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(cs, entity, strlen(entity), "en", 2, &value, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save_draft(cs, entity, strlen(entity), "en", 2, &value, 1));
  /* The refusal staged nothing: applying the changeset changes nothing. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(0u, Revisions(entity));
  EXPECT_EQ("", Stored(entity, GDEFCORE_VIEW_PUBLISHED));
  EXPECT_EQ("", Stored(entity, GDEFCORE_VIEW_DRAFT));

  /* Accepting sealed values is not accepting plaintext. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(cs, entity, strlen(entity), "en", 2, &value, 1));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save_draft(cs, entity, strlen(entity), "en", 2, &value, 1));
  OneValue(&value, kField, "s1:short", &slot, &slot_len);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_save(cs, entity, strlen(entity), "en", 2, &value, 1));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(0u, Revisions(entity));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_accept_sealed(NULL));
}

/* A revert restores an earlier revision whose personal value is already
 * ciphertext. It must keep working, and what it restores is that ciphertext:
 * the subject reads the earlier plaintext, not a sealed copy of the sealed
 * text. */
TEST_F(Erasure, RevertKeepsCiphertext) {
  GDEFCORE_Changeset * cs = NULL;
  std::string first_stored;
  std::string second_stored;
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a_));
  NewPerson(ea_);
  ASSERT_FALSE(HasFatalFailure());
  SaveValue(a_, ea_, "en", kCanary);
  first_stored = Stored(ea_, GDEFCORE_VIEW_PUBLISHED);
  SaveValue(a_, ea_, "en", kCanaryLater);
  second_stored = Stored(ea_, GDEFCORE_VIEW_PUBLISHED);
  ASSERT_NE(first_stored, second_stored);
  EXPECT_EQ(kCanaryLater, ReadAs(a_, ea_));

  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, ea_, strlen(ea_), NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(first_stored, Stored(ea_, GDEFCORE_VIEW_PUBLISHED))
      << "the revert did not restore the stored text byte for byte";
  EXPECT_EQ(kCanary, ReadAs(a_, ea_));
  EXPECT_EQ(0u, Stored(ea_, GDEFCORE_VIEW_PUBLISHED).compare(0, 3, "s1:"));
}

/* A type can be redefined, after which a field that held plaintext is
 * personal. What was stored stays as it is (nothing here rewrites history),
 * but the paths that would carry it into a new revision refuse: a revert
 * does not restore plaintext into a personal field, and a draft that holds
 * plaintext for one is not published. */
TEST_F(Erasure, PlaintextHistoryIsNotRestored) {
  GDEFCORE_Field field;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t slot_len = 0;
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t revisions;
  std::string published;
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = kField;
  field.name_len = strlen(kField);
  field.required = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.late", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.late", 9, entity, NULL));
  /* Plaintext history: two published revisions and a draft. */
  OneValue(&value, kField, "plain-one", &slot, &slot_len);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(cs, entity, strlen(entity), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  OneValue(&value, kField, "plain-two", &slot, &slot_len);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(cs, entity, strlen(entity), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  OneValue(&value, kField, "plain-draft", &slot, &slot_len);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save_draft(cs, entity, strlen(entity), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);

  /* The field becomes personal. */
  field.personal = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(cs, "site.late", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "site.late", 9));
  gdefcore_changeset_destroy(cs);
  {
    int personal = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_field_personal(catalog_, "site.late", 9, 0, &personal));
    ASSERT_EQ(1, personal) << "the redefinition did not take";
  }
  revisions = Revisions(entity);
  published = Stored(entity, GDEFCORE_VIEW_PUBLISHED);
  ASSERT_EQ("plain-two", published);

  /* A revert would put "plain-one" back into a personal field. */
  cs = NULL;
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, entity, strlen(entity), NULL, 0, &cs));
  gdefcore_changeset_destroy(cs);
  /* A publish would copy the plaintext draft onto the published row. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_NE(GDEFCORE_OK, gdefcore_entity_publish(cs, entity, strlen(entity)));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(revisions, Revisions(entity));
  EXPECT_EQ(published, Stored(entity, GDEFCORE_VIEW_PUBLISHED));
}

/* A revert to a revision from before the field was personal, which holds
 * plaintext, is refused: there is no other way to make an old revision the
 * content (access SPEC decision 13 retired `activate`, which this gate used to
 * hold to the same rule). */
TEST_F(Erasure, PlaintextRevisionCannotBecomeTheContentAgain) {
  GDEFCORE_Field field;
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t slot_len = 0;
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t revisions;
  std::string stored;
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = kField;
  field.name_len = strlen(kField);
  field.required = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog_, "site.late", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.late", 9, entity, NULL));
  for (const char * text : {"plain-one", "plain-two"}) {
    OneValue(&value, kField, text, &slot, &slot_len);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, entity, strlen(entity), "en", 2, &value, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  /* control, before the field is personal: the revert is allowed */
  cs = NULL;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert_to(catalog_, entity, strlen(entity), 1, NULL, 0,
          &cs));
  gdefcore_changeset_destroy(cs);
  /* The field becomes personal. */
  field.personal = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_define(cs, "site.late", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "site.late", 9));
  gdefcore_changeset_destroy(cs);
  revisions = Revisions(entity);
  stored = Stored(entity, GDEFCORE_VIEW_PUBLISHED);
  ASSERT_EQ("plain-two", stored);
  /* neither plaintext revision can be restored */
  for (uint64_t seq : {1u, 2u}) {
    cs = NULL;
    EXPECT_NE(GDEFCORE_OK,
        gdefcore_changeset_revert_to(catalog_, entity, strlen(entity), seq, NULL,
            0, &cs))
        << seq;
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ(revisions, Revisions(entity));
  EXPECT_EQ(stored, Stored(entity, GDEFCORE_VIEW_PUBLISHED));
}

/* A patch is untrusted input. Parsed under the same rule: its personal value
 * is accepted only when it is sealed, and a patch that carries plaintext for
 * a personal field is refused. */
/* A revision view is an output like any other (story A5b task 8). Before the
 * person is erased it says a personal value is there and shows none of it; after
 * it says [erased]; the survivor's is not touched. Reverting to an old revision
 * of the erased person (a new revision that copies it: there is no activate
 * since access SPEC decision 13) puts its ciphertext in front of readers and
 * nothing else: no output carries the value, the ciphertext, or a form of
 * either. */
TEST_F(Erasure, RevisionViewsAndARestoredOldRevisionOfAnErasedSubject) {
  std::vector<Artifact> pre;
  std::vector<Artifact> post;
  std::vector<Artifact> restored;
  std::vector<std::string> values;
  std::vector<std::string> leaks;
  Populate();
  if (HasFatalFailure()) {
    return;
  }
  PopulateForm();
  if (HasFatalFailure()) {
    return;
  }
  values.push_back(kCanary);
  values.push_back(kCanaryLater);
  values.push_back(kCanaryFr);
  values.push_back(kCanaryForm);
  Needles(a_, values, WrappedKey(a_), &needles_);
  ASSERT_FALSE(HasFatalFailure());

  /* CONTROLS, before erasure. The view of the first revision says a personal
   * value is there; it does not show it, and it is not the survivor's. */
  ASSERT_EQ(3u, Revisions(ea_));
  EXPECT_EQ("personal", RevisionView(ea_, 1, "en", a_));
  EXPECT_EQ("personal", RevisionView(ea_, 3, "fr", a_));
  EXPECT_EQ("personal", RevisionView(eb_, 1, "en", b_));
  EXPECT_EQ("<denied>", RevisionView(ea_, 9, "en", a_));     /* no such revision */
  Collect(&pre, "before");
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_TRUE(FoundIn(pre, Bytes("personal"), "output: revision view of a"));
  EXPECT_FALSE(FoundIn(pre, Bytes("erased"), "output: revision view of a"));
  EXPECT_FALSE(FoundIn(pre, Bytes("s1:"), "output: revision view of a"))
      << "a revision view showed the stored ciphertext";
  EXPECT_TRUE(FoundIn(pre, Bytes("s1:"), "entity values"));

  Erase(a_);

  /* After: the same view is the marker, for a, and only for a. */
  EXPECT_EQ("erased:[erased]", RevisionView(ea_, 1, "en", a_));
  EXPECT_EQ("erased:[erased]", RevisionView(ef_, 1, "en", a_));
  EXPECT_EQ("personal", RevisionView(eb_, 1, "en", b_));
  EXPECT_EQ("personal", RevisionView(ea_, 1, "en", NULL));   /* no subject named */
  Collect(&post, "after");
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_TRUE(FoundIn(post, Bytes("erased:[erased]"), "output: revision view of a"));
  EXPECT_TRUE(FoundIn(post, Bytes("personal"), "output: revision view of b"));
  EXPECT_FALSE(FoundIn(post, Bytes("s1:"), "output: revision view"));
  leaks = Sweep(post, needles_);
  EXPECT_TRUE(leaks.empty()) << Joined(leaks);

  /* Make the first revision (the first canary's ciphertext) the content
   * again. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revert_to(catalog_, ea_, strlen(ea_), 1, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ(0u, Stored(ea_, GDEFCORE_VIEW_CURRENT).compare(0, 3, "s1:"));
  EXPECT_EQ(GDEFCORE_SUBJECT_ERASED, ReadAs(a_, ea_));
  EXPECT_EQ("erased:[erased]", RevisionView(ea_, 1, "en", a_));
  Collect(&restored, "restored");
  ASSERT_FALSE(HasFatalFailure());
  leaks = Sweep(restored, needles_);
  EXPECT_TRUE(leaks.empty()) << "a restored old revision of an erased subject "
                                "reached an output:" << Joined(leaks);
  /* The sweep still sees the survivor: it did not go blind. */
  EXPECT_FALSE(FoundIn(restored, Bytes("s1:"), "output: revision view"));
  EXPECT_TRUE(FoundIn(restored, kSurvivor, "output: export of b"));
}

/*
 * A3: a relation row names a person by public id, which is not a personal value
 * (SPEC decision 6). Erasing the subject deletes the key; the row keeps the id
 * and nothing of the person is in it, so no sweep of any store finds a value.
 */
TEST_F(Erasure, ARelationRowNamesAnErasedSubjectByItsPublicIdOnly) {
  std::vector<Artifact> post;
  std::vector<std::string> values;
  std::vector<std::string> leaks;
  Populate();
  if (HasFatalFailure()) {
    return;
  }
  values.push_back(kCanary);
  values.push_back(kCanaryLater);
  values.push_back(kCanaryFr);
  Needles(a_, values, WrappedKey(a_), &needles_);
  ASSERT_FALSE(HasFatalFailure());
  /* The rows a module's relation would hold, written as the kernel stores them
   * (relation.h): the relation's name and a public id per entity column. */
  {
    GDEFCORE_Field f[3];
    char row[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * texts[3] = {"blog.fan", a_, "gold"};
    size_t lens[3] = {8, strlen(a_), 4};
    const char * fields[3] = {"relation", "c0", "c1"};
    GDEFCORE_Value v[3];
    GDEFCORE_Changeset * cs = NULL;
    size_t i;
    memset(f, 0, sizeof f);
    for (i = 0; i < 3; i++) {
      f[i].size = sizeof f[i];
      f[i].name = fields[i];
      f[i].name_len = strlen(fields[i]);
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, GDEFCORE_RELATION_ROW_TYPE,
            strlen(GDEFCORE_RELATION_ROW_TYPE), GDEFCORE_TYPE_CONTENT, f, 3));
    for (i = 0; i < 3; i++) {
      memset(&v[i], 0, sizeof v[i]);
      v[i].size = sizeof v[i];
      v[i].field = fields[i];
      v[i].field_len = strlen(fields[i]);
      v[i].texts = &texts[i];
      v[i].text_lens = &lens[i];
      v[i].count = 1;
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, GDEFCORE_RELATION_ROW_TYPE,
            strlen(GDEFCORE_RELATION_ROW_TYPE), row, NULL));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, row, strlen(row), "en", 2, v, 3));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  Erase(a_);
  /* The row still names the person, by the id and by nothing else. */
  {
    char ** ids = NULL;
    size_t n = 0;
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(catalog_, GDEFCORE_RELATION_ROW_TYPE,
            strlen(GDEFCORE_RELATION_ROW_TYPE), &ids, &n));
    ASSERT_EQ(1u, n);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_CURRENT, ids[0],
            GDEFCORE_PUBLIC_ID_LEN, "en", 2, "c0", 2, &texts, &lens, &count));
    ASSERT_EQ(1u, count);
    EXPECT_EQ(std::string(a_), std::string(texts[0], lens[0]));
    gdefcore_values_free(catalog_, texts, lens, count);
    gdefcore_ids_free(catalog_, ids, n);
  }
  Collect(&post, "after");
  ASSERT_FALSE(HasFatalFailure());
  leaks = Sweep(post, needles_);
  EXPECT_TRUE(leaks.empty()) << Joined(leaks);
  /* The sweep is not blind: the survivor's value is still found where it sits. */
  EXPECT_TRUE(FoundIn(post, kSurvivor, "output: export of b"));
}

TEST_F(Erasure, ParsePersonalPatch) {
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t nfiles = 0;
  GDEFCORE_Value value;
  const char * slot = NULL;
  size_t slot_len = 0;
  char * sealed = NULL;
  size_t sealed_len = 0;
  uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN];
  size_t i;
  bool edited = false;
  DefinePerson();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a_));
  NewPerson(ea_);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_seal(subjects_, a_, strlen(a_), kField, strlen(kField),
          kCanary, strlen(kCanary), &sealed, &sealed_len, mac));
  OneValue(&value, kField, sealed, &slot, &slot_len);
  value.text_lens = &sealed_len;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
  /* Whose the value is travels with it (story S6c). */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_note_sealed(cs, subjects_, sealed, sealed_len, a_,
          strlen(a_), mac));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_save(cs, ea_, strlen(ea_), "en", 2, &value, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(cs, &files, &nfiles));
  gdefcore_changeset_destroy(cs);
  cs = NULL;
  {
    bool named = false;
    for (i = 0; i < nfiles; i++) {
      named |= files[i].len == strlen(a_) &&
               memcmp(files[i].bytes, a_, strlen(a_)) == 0 &&
               std::string(files[i].path, files[i].path_len).find("/subject/") !=
                   std::string::npos;
    }
    EXPECT_TRUE(named) << "the patch does not say whose the value is";
  }

  /* Sealed: the patch parses and applies, and the subject reads it. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, nfiles, NULL, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  cs = NULL;
  EXPECT_EQ(kCanary, ReadAs(a_, ea_));

  /* The same patch with the value replaced by plaintext. */
  for (i = 0; i < nfiles; i++) {
    if (files[i].len == sealed_len &&
        memcmp(files[i].bytes, sealed, sealed_len) == 0) {
      free(files[i].bytes);
      files[i].bytes = static_cast<uint8_t *>(malloc(strlen(kCanaryLater)));
      memcpy(files[i].bytes, kCanaryLater, strlen(kCanaryLater));
      files[i].len = strlen(kCanaryLater);
      edited = true;
    }
  }
  ASSERT_TRUE(edited) << "the patch does not carry the sealed value";
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, nfiles, NULL, &cs));
  EXPECT_EQ(NULL, cs);
  EXPECT_EQ(kCanary, ReadAs(a_, ea_));
  gdefcore_patch_free(catalog_, files, nfiles);
  gdefcore_subject_free(subjects_, sealed);
}

/* AD-19, the subject route of a form. A personal value is sealed under its
 * subject's key as gdefcore_subject_save does, the blind index is recorded,
 * an editor can open the form with the current value and change it, and the
 * stored text stays ciphertext throughout. Erasing the subject then leaves
 * nothing of the canary anywhere the sweep looks, and another subject is
 * untouched. */
TEST_F(Erasure, FormSubjectRoute) {
  std::vector<Artifact> pre;
  std::vector<Artifact> post;
  std::vector<Needle> needles;
  std::vector<Needle> survivor;
  std::vector<std::string> values;
  std::vector<std::string> leaks;
  std::string token;
  std::string stored;
  std::string draft;
  Bytes wrapped;
  Bytes survivor_wrapped;
  Bytes tenant_before;
  size_t blinds_before;
  size_t revisions;
  int conflict = 9;
  Populate();
  if (HasFatalFailure()) {
    return;
  }
  NewPerson(ef_);
  ASSERT_FALSE(HasFatalFailure());
  blinds_before = BlindCount(a_);
  ASSERT_EQ(3u, blinds_before);

  /* Create through the form. The draft holds ciphertext, the published row
   * holds nothing yet, and the index has no row for it: a draft is never a
   * revision and carries no MAC (story S6c). Publishing it writes the row. */
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, ef_, kCanaryForm, &token));
  ASSERT_EQ(GDEFCORE_OK, SubmitFor(token, &conflict));
  EXPECT_EQ(0, conflict);
  draft = Stored(ef_, GDEFCORE_VIEW_DRAFT);
  ASSERT_GT(draft.size(), 3u);
  EXPECT_EQ("s1:", draft.substr(0, 3));
  EXPECT_EQ(std::string::npos, draft.find(kCanaryForm));
  EXPECT_EQ("", Stored(ef_, GDEFCORE_VIEW_PUBLISHED));
  EXPECT_EQ(blinds_before, BlindCount(a_));
  Publish(ef_);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(blinds_before + 1, BlindCount(a_));
  stored = Stored(ef_, GDEFCORE_VIEW_PUBLISHED);
  EXPECT_EQ(draft, stored);
  EXPECT_EQ(kCanaryForm, ReadAs(a_, ef_));

  /* The same key and format as gdefcore_subject_save: the text the form
   * stored is what subject_read decrypts for the subject, and the survivor's
   * key does not open it. */
  {
    uint8_t key[GDEFCORE_KEYRING_KEY_LEN];
    Bytes expect;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_derive(Ring(), root_, sizeof root_, "blind-index:name",
            strlen("blind-index:name"), key, sizeof key));
    expect = Hmac(B(key, sizeof key), kCanaryForm);
    ASSERT_EQ(32u, expect.size());
    EXPECT_EQ(expect, BlindMac(kCanaryForm));
    EXPECT_TRUE(BlindRowHas(a_, expect));
  }

  /* The editing round trip. The tree shows what is stored, which is
   * ciphertext; the editor's current value comes from subject_read. */
  {
    GDEFCORE_Form * form = NULL;
    const char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int personal = 0;
    size_t min_len = 0;
    size_t max_len = 0;
    int has_range = 0;
    int64_t range_min = 0;
    int64_t range_max = 0;
    const char * pattern = NULL;
    size_t pattern_len = 0;
    const char * const * texts = NULL;
    const size_t * lens = NULL;
    size_t count = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_tree(catalog_, "site.person", 11, ef_, strlen(ef_), "en",
            2, &form));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_field(form, 0, &name, &name_len, &required, &many,
            &personal, &min_len, &max_len, &has_range, &range_min, &range_max,
            &pattern, &pattern_len, &texts, &lens, &count));
    EXPECT_EQ(1, personal);
    ASSERT_EQ(1u, count);
    EXPECT_EQ(stored, std::string(texts[0], lens[0]));
    gdefcore_form_destroy(form);
  }
  revisions = Revisions(ef_);
  /* What the tree shows is ciphertext. Passed back as the value, it is
   * refused, not sealed over itself, and nothing is written. */
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, ef_, stored.c_str(), &token));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitFor(token, &conflict));
  EXPECT_EQ(revisions, Revisions(ef_));
  EXPECT_EQ(kCanaryForm, ReadAs(a_, ef_));
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, ef_, ReadAs(a_, ef_).c_str(), &token));
  {
    /* An unchanged edit seals the plaintext again: new nonce, same value,
     * so a new value version (whether a value changed is decided on the
     * ciphertext until story S7), and with it a row of its own; the
     * version it superseded keeps its row while the subject exists. */
    ASSERT_EQ(GDEFCORE_OK, SubmitFor(token, &conflict));
    Publish(ef_);
    EXPECT_NE(stored, Stored(ef_, GDEFCORE_VIEW_PUBLISHED));
    EXPECT_EQ(kCanaryForm, ReadAs(a_, ef_));
    EXPECT_EQ(blinds_before + 2, BlindCount(a_));
  }
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, ef_, kCanaryEdit, &token));
  {
    /* The form goes through a resign on the way, as an editor's would. */
    GDEFCORE_Value value;
    const char * slot = NULL;
    size_t slot_len = 0;
    char * again = NULL;
    size_t again_len = 0;
    OneValue(&value, kField, kCanaryEdit, &slot, &slot_len);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_form_resign(catalog_, request_, Ring(), root_, sizeof root_,
            session_.data(), session_.size(), token.data(), token.size(),
            &value, 1, &again, &again_len));
    token.assign(again, again_len);
    gdefcore_text_free(catalog_, again);
  }
  ASSERT_EQ(GDEFCORE_OK, SubmitFor(token, &conflict));
  Publish(ef_);
  EXPECT_GT(Revisions(ef_), revisions);
  EXPECT_EQ(kCanaryEdit, ReadAs(a_, ef_));
  EXPECT_EQ("s1:", Stored(ef_, GDEFCORE_VIEW_PUBLISHED).substr(0, 3));
  EXPECT_EQ(blinds_before + 3, BlindCount(a_));

  /* The survivor edits through the same route and is only ever themself. */
  {
    std::string t;
    ASSERT_EQ(GDEFCORE_OK, SignFor(b_, eb_, kSurvivorEdit, &t));
    ASSERT_EQ(GDEFCORE_OK, SubmitFor(t, &conflict));
    Publish(eb_);
    EXPECT_EQ(kSurvivorEdit, ReadAs(b_, eb_));
  }
  EXPECT_EQ(kCanaryEdit, ReadAs(a_, ef_));
  EXPECT_EQ(std::string(kCanaryFr), [&] {
    char * text = NULL;
    size_t n = 0;
    std::string out;
    if (gdefcore_subject_read(subjects_, catalog_, a_, strlen(a_), ea_,
            strlen(ea_), kField, strlen(kField), "fr", 2, &text, &n) ==
        GDEFCORE_OK) {
      out.assign(text, n);
      gdefcore_subject_free(subjects_, text);
    }
    return out;
  }());

  /* Needles for every value subject a ever held, the form ones included. */
  wrapped = WrappedKey(a_);
  survivor_wrapped = WrappedKey(b_);
  values.push_back(kCanary);
  values.push_back(kCanaryLater);
  values.push_back(kCanaryFr);
  values.push_back(kCanaryForm);
  values.push_back(kCanaryEdit);
  Needles(a_, values, wrapped, &needles);
  ASSERT_FALSE(HasFatalFailure());
  {
    std::vector<std::string> sv;
    sv.push_back(kSurvivor);
    sv.push_back(kSurvivorEdit);
    Needles(b_, sv, survivor_wrapped, &survivor);
  }
  ASSERT_FALSE(HasFatalFailure());

  /* CONTROL: the sweep sees the form route's value where it must. */
  Collect(&pre, "before");
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_TRUE(FoundIn(pre, kCanaryEdit, "output: export of a"));
  EXPECT_TRUE(FoundIn(pre, kCanaryEdit, "output: read of a (form route)"));
  EXPECT_TRUE(FoundIn(pre, Bytes("s1:"), "entity values (form route)"));
  EXPECT_TRUE(FoundIn(pre, Hex(Bytes("s1:"), false), "revision document"));
  EXPECT_FALSE(Sweep(pre, needles).empty());
  {
    /* No form-route value is plaintext in tenant data, before erasure. */
    std::vector<Needle> plain;
    std::vector<Artifact> tenant;
    size_t a;
    for (a = 0; a < pre.size(); a++) {
      if (pre[a].tenant_data &&
          pre[a].label.compare(0, 7, "output:") != 0) {
        tenant.push_back(pre[a]);
      }
    }
    AddForms(&plain, "form canary", kCanaryForm, false);
    AddForms(&plain, "edited form canary", kCanaryEdit, false);
    AddForms(&plain, "survivor edit", kSurvivorEdit, false);
    leaks = Sweep(tenant, plain);
    EXPECT_TRUE(leaks.empty()) << "the form route stored plaintext:"
                               << Joined(leaks);
    EXPECT_FALSE(tenant.empty());
  }

  /* ERASE. */
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, ef_, "late edit by a", &token));
  tenant_before = TenantExport();
  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  Erase(a_);
  Collect(&post, "after");
  AddText(&post, "standard output", testing::internal::GetCapturedStdout());
  AddText(&post, "standard error", testing::internal::GetCapturedStderr());
  ASSERT_FALSE(HasFatalFailure());
  leaks = Sweep(post, needles);
  EXPECT_TRUE(leaks.empty()) << "erased subject's data is still reachable:"
                             << Joined(leaks);
  EXPECT_FALSE(Sweep(post, survivor).empty())
      << "the sweep no longer sees the survivor";
  EXPECT_TRUE(FoundIn(post, Bytes("[erased]"), "output: read of a (form route)"));
  EXPECT_EQ(kSurvivorEdit, ReadAs(b_, eb_));
  EXPECT_EQ(0u, BlindCount(a_));

  /* A form signed before the erasure cannot be submitted after it, and
   * neither can a fresh one: nothing is written, and nothing falls back to
   * the plain text. */
  revisions = Revisions(ef_);
  tenant_before = TenantExport();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitFor(token, &conflict));
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, ef_, "after erasure", &token));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitFor(token, &conflict));
  EXPECT_EQ(revisions, Revisions(ef_));
  EXPECT_EQ(0u, BlindCount(a_));
  {
    std::vector<Artifact> arts;
    std::vector<Needle> late;
    AddForms(&late, "late edit", "late edit by a", false);
    AddForms(&late, "after erasure", "after erasure", false);
    AddZip(&arts, "tenant store snapshot", TenantExport(), true);
    EXPECT_TRUE(Sweep(arts, late).empty());
  }
}

/* A subject the store does not know: the sign takes the id on trust, the
 * submit refuses it, and nothing is written. */
TEST_F(Erasure, FormUnknownSubject) {
  std::string token;
  char ghost[GDEFCORE_PUBLIC_ID_LEN + 1];
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  int conflict = 3;
  size_t before;
  DefinePerson();
  Login();
  NewPerson(entity);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(ghost));
  ASSERT_EQ(GDEFCORE_OK, SignFor(ghost, entity, kCanary, &token));
  before = Revisions(entity);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitFor(token, &conflict));
  EXPECT_EQ(before, Revisions(entity));
  EXPECT_EQ("", Stored(entity, GDEFCORE_VIEW_DRAFT));
  {
    std::vector<Needle> needles;
    std::vector<Artifact> arts;
    AddForms(&needles, "canary", kCanary, false);
    AddZip(&arts, "tenant store snapshot", TenantExport(), true);
    EXPECT_TRUE(Sweep(arts, needles).empty());
  }
  /* A sign without a subject, a NULL store, and a bad id are refused. */
  {
    GDEFCORE_Value value;
    const char * slot = NULL;
    size_t slot_len = 0;
    char * out = NULL;
    size_t out_len = 0;
    OneValue(&value, kField, kCanary, &slot, &slot_len);
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_form_sign_subject(catalog_, request_, Ring(), root_,
            sizeof root_, session_.data(), session_.size(), "edit", 4, entity,
            strlen(entity), "en", 2, &value, 1, NULL, 0, NULL, 0, &out,
            &out_len));
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_form_sign_subject(catalog_, request_, Ring(), root_,
            sizeof root_, session_.data(), session_.size(), "edit", 4, entity,
            strlen(entity), "en", 2, &value, 1, NULL, 0, "not-an-id", 9, &out,
            &out_len));
    EXPECT_EQ(NULL, out);
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_form_submit_subject(catalog_, request_, Ring(), root_,
            sizeof root_, session_.data(), session_.size(), token.data(),
            token.size(), NULL, &conflict));
  }
}

/* The subject is in what the token authenticates, like the session and the
 * tenant. A form signed for one subject cannot be submitted for another, and
 * cannot be made to claim none. */
TEST_F(Erasure, FormSubjectBinding) {
  std::string token;
  std::string moved;
  char entity[GDEFCORE_PUBLIC_ID_LEN + 1];
  int conflict = 0;
  size_t at;
  size_t before;
  DefinePerson();
  Login();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, a_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, b_));
  NewPerson(entity);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(GDEFCORE_OK, SignFor(a_, entity, kCanary, &token));
  EXPECT_EQ(2, static_cast<int>(token[0]));
  at = token.find(a_);
  ASSERT_NE(std::string::npos, at) << "the subject is not in the token header";
  before = Revisions(entity);

  /* Moved to the other subject. */
  moved = token;
  moved.replace(at, strlen(b_), b_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitFor(moved, &conflict));
  /* Made to claim no subject. */
  moved = token;
  moved.replace(at, GDEFCORE_PUBLIC_ID_LEN, std::string(GDEFCORE_PUBLIC_ID_LEN, '\0'));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitFor(moved, &conflict));
  /* Made to claim no subject by the older layout: the version byte says 1 and
   * the subject's bytes are cut out. */
  moved = token;
  moved.erase(at, GDEFCORE_PUBLIC_ID_LEN);
  moved[0] = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, SubmitFor(moved, &conflict));
  EXPECT_EQ(before, Revisions(entity));
  EXPECT_EQ(0u, BlindCount(a_));
  EXPECT_EQ(0u, BlindCount(b_));
  EXPECT_EQ("", Stored(entity, GDEFCORE_VIEW_DRAFT));

  /* The untouched token is the control: it submits, for a and only a (the
   * draft has no blind row; its publish writes one). */
  ASSERT_EQ(GDEFCORE_OK, SubmitFor(token, &conflict));
  EXPECT_EQ(0u, BlindCount(a_));
  Publish(entity);
  EXPECT_EQ(1u, BlindCount(a_));
  EXPECT_EQ(0u, BlindCount(b_));
  EXPECT_EQ(kCanary, ReadAs(a_, entity));
  EXPECT_NE(kCanary, ReadAs(b_, entity));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return ksrig::RunAll();
}
