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
 * Story S7 (AD-19, CAP-S5): personal data names its subject on every field
 * and is decrypted only in the application's read path. One test per row of
 * the story's matrix, and one per gate tools/check-personal.sh plants a defect
 * for:
 *
 *  - a subject source on every personal field: a sibling reference, else the
 *    entity's own subject, which a type whose entities are subjects keeps
 *    with each entity; a personal field with neither is refused;
 *  - decryption in every read surface (a read, a tree, a render, a revision
 *    view, the editor's form) only after the access filter allowed the
 *    field, and `[erased]` for an erased subject;
 *  - "unchanged" decided by plaintext at write;
 *  - a render records each subject it decrypted, and erasing one purges every
 *    cached fragment that depends on it;
 *  - "everything about this person" across types, groups and history.
 *
 * Every rule is counted on the port's own rows (gdefstor_model_dump()) or on
 * the key store, not taken from core's word.
 */

#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#include <ghoti.io/defiant-storage/store.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <string.h>

#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

const char kTenant[] = "t";
const char kMember[] = "site.member";
const char kCase[] = "site.case";

std::string Hex(const std::string & raw) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : raw) {
    out.push_back(kDigits[c >> 4]);
    out.push_back(kDigits[c & 0x0f]);
  }
  return out;
}

/* A zip as stored, then every member's name and body, so a compressed member
 * cannot hide a needle. */
std::string Unpacked(const uint8_t * zip, size_t n) {
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  std::string view(reinterpret_cast<const char *>(zip), n);
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
    if (garc_next(archive, &member) != GARC_OK) {
      break;
    }
    std::string body(static_cast<size_t>(member->size), '\0');
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
    view += "\n" + std::string(member->name, member->name_length) + "\n" + body;
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return view;
}

GDEFCORE_Field Plain(const char * name, int type = 0) {
  GDEFCORE_Field f;
  memset(&f, 0, sizeof f);
  f.size = sizeof f;
  f.name = name;
  f.name_len = strlen(name);
  f.type = type;
  return f;
}

GDEFCORE_Field Secret(const char * name, const char * subject = NULL) {
  GDEFCORE_Field f = Plain(name);
  f.personal = 1;
  if (subject != NULL) {
    f.subject = subject;
    f.subject_len = strlen(subject);
  }
  return f;
}

class Personal : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  GDEFSTOR_KeyStore * keys_ = NULL;
  GDEFCORE_Keyring * ring_ = NULL;
  GDEFCORE_Host * host_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  GDEFCORE_Subjects * subjects_ = NULL;
  GDEFCORE_FragmentCache * cache_ = NULL;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  char staff_[GDEFCORE_PUBLIC_ID_LEN + 1];
  char clerk_[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::vector<GDEFCORE_Request *> reqs_;

  static GDEFCORE_Permission Perm(const char * label, const char * action,
      const char * type, const char * field) {
    GDEFCORE_Permission p;
    memset(&p, 0, sizeof p);
    p.size = sizeof p;
    p.label = label;
    p.label_len = strlen(label);
    p.module_name = "people";
    p.module_name_len = 6;
    p.action = action;
    p.action_len = strlen(action);
    p.condition = GDEFCORE_ACCESS_ANY;
    p.type_name = type;
    p.type_name_len = strlen(type);
    if (field != NULL) {
      p.field = field;
      p.field_len = strlen(field);
    }
    return p;
  }

  void SetUp() override {
    static GDEFSTOR_KeyCipher cipher;
    memset(root_, 0x42, sizeof root_);
    gdefcore_subject_cipher(&cipher);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_keystore_create(NULL, &cipher, &keys_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_create(root_, sizeof root_, NULL, &ring_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store_,
        (const uint8_t *)kTenant, 1, NULL, NULL, &catalog_));
    gdefcore_catalog_bind_host(catalog_, host_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_open(keys_, store_,
        (const uint8_t *)kTenant, 1, root_, sizeof root_, ring_, NULL,
        &subjects_));
    gdefcore_catalog_bind_subjects(catalog_, subjects_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_cache_create(NULL, 0, &cache_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_bind_cache(subjects_, cache_));
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    DefineTypes();
    ASSERT_FALSE(HasFatalFailure());
    DefineAccess();
    ASSERT_FALSE(HasFatalFailure());
    DefineTemplates();
  }

  void TearDown() override {
    for (GDEFCORE_Request * r : reqs_) {
      gdefcore_request_destroy(r);
    }
    gdefcore_subject_bind_cache(subjects_, NULL);
    gdefcore_fragment_cache_destroy(cache_);
    gdefcore_catalog_bind_subjects(catalog_, NULL);
    gdefcore_catalog_bind_host(catalog_, NULL);
    gdefcore_subject_destroy(subjects_);
    gdefcore_catalog_destroy(catalog_);
    gdefcore_host_destroy(host_);
    gdefstor_keystore_destroy(keys_);
    gdefcore_keyring_destroy(ring_);
    gdefstor_store_destroy(store_);
  }

  /* A member is a subject: `name` and `email` take the member's own subject.
   * A case names whose its `note` is by its `who` reference, and so does
   * each of its contacts, by the `who` in the same item. */
  void DefineTypes() {
    GDEFCORE_Field member[3] = {Plain("title"), Secret("name"),
        Secret("email")};
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kMember,
        strlen(kMember), GDEFCORE_TYPE_CONTENT | GDEFCORE_TYPE_SUBJECTS, member,
        3));
    GDEFCORE_Field contact[2] = {Plain("who", GDEFSTOR_FIELD_REFERENCE),
        Secret("note", "who")};
    GDEFCORE_Field contacts = Plain("contacts", GDEFSTOR_FIELD_GROUP);
    contacts.many = 1;
    contacts.children = contact;
    contacts.child_count = 2;
    GDEFCORE_Field kase[4] = {Plain("title"),
        Plain("who", GDEFSTOR_FIELD_REFERENCE), Secret("note", "who"),
        contacts};
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kCase, strlen(kCase),
        GDEFCORE_TYPE_CONTENT, kase, 4));
  }

  /* Staff read members and cases, every field, see history and edit; clerks
   * read members and cases but not a member's email. */
  void DefineAccess() {
    GDEFCORE_Permission perms[] = {
        Perm("Read members", "read", kMember, NULL),
        Perm("Read member email", "read", kMember, "email"),
        Perm("Read cases", "read", kCase, NULL),
        Perm("Member history", GDEFCORE_ACTION_REVISIONS_READ, kMember, NULL),
        Perm("Edit members", GDEFCORE_ACTION_UPDATE, kMember, NULL),
    };
    for (const GDEFCORE_Permission & p : perms) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &p));
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, "staff", 5, NULL));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, "clerks", 6, NULL));
    for (const GDEFCORE_Permission & p : perms) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "staff", 5,
          p.label, p.label_len, "core.role", 9));
    }
    for (const char * label :
        {"Read members", "Read cases", "Member history", "Edit members"}) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "clerks", 6,
          label, strlen(label), "core.role", 9));
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, staff_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, clerk_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, staff_,
        strlen(staff_), "staff", 5));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, clerk_,
        strlen(clerk_), "clerks", 6));
  }

  GDEFCORE_Result Put(const char * type,
      std::vector<std::pair<std::string, std::string>> values,
      const char * confirm) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> vs(values.size());
    std::vector<const char *> texts(values.size());
    std::vector<size_t> lens(values.size());
    for (size_t i = 0; i < values.size(); i++) {
      texts[i] = values[i].second.c_str();
      lens[i] = values[i].second.size();
      memset(&vs[i], 0, sizeof vs[i]);
      vs[i].size = sizeof vs[i];
      vs[i].field = values[i].first.c_str();
      vs[i].field_len = values[i].first.size();
      vs[i].texts = &texts[i];
      vs[i].text_lens = &lens[i];
      vs[i].count = 1;
    }
    GDEFCORE_Result rc = gdefcore_entity_create(catalog_, type, strlen(type), id,
        NULL);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2,
          vs.data(), vs.size());
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, confirm, strlen(confirm));
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* A template of members that prints the name and the email, and one that
   * prints the title alone. */
  void DefineTemplates() {
    ASSERT_EQ(GDEFCORE_OK,
        Put(GDEFCORE_TEMPLATE_KIND_TYPE,
            {{"name", "site.member"}, {"label", "Member"}, {"version", "1"},
                {"variables", "entity entity The member"}},
            GDEFCORE_TEMPLATE_KIND_TYPE));
    ASSERT_EQ(GDEFCORE_OK,
        Put(GDEFCORE_TEMPLATE_TYPE,
            {{"name", "card"},
                {"body",
                    "<% use entity; %>[<%= entity.name %>|<%= entity.email %>]"},
                {"kind", "site.member"}},
            GDEFCORE_TEMPLATE_TYPE));
    ASSERT_EQ(GDEFCORE_OK,
        Put(GDEFCORE_TEMPLATE_TYPE,
            {{"name", "badge"}, {"body", "<% use entity; %>{<%= entity.title %>}"},
                {"kind", "site.member"}},
            GDEFCORE_TEMPLATE_TYPE));
  }

  GDEFCORE_Request * Req(const char * principal) {
    GDEFCORE_Request * r = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &r));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(r, principal, strlen(principal)));
    reqs_.push_back(r);
    return r;
  }

  /* A member, with its own subject. */
  std::string Member(std::string * out_subject = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kMember, strlen(kMember), id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_subject(catalog_, id, strlen(id), sid));
    if (out_subject != NULL) {
      *out_subject = sid;
    }
    return id;
  }

  /* gdefcore_subject_save() of one personal field, the subject left for the
   * declaration to name. */
  GDEFCORE_Result Say(const std::string & id, const char * field,
      const std::string & plain, const char * lang = "en") {
    return gdefcore_subject_save(subjects_, catalog_, NULL, 0, id.data(),
        id.size(), field, strlen(field), lang, strlen(lang), plain.data(),
        plain.size());
  }

  GDEFCORE_Result SetPlain(const std::string & id, const char * field,
      const std::string & text) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    const char * texts[1] = {text.c_str()};
    size_t lens[1] = {text.size()};
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = field;
    v.field_len = strlen(field);
    v.texts = texts;
    v.text_lens = lens;
    v.count = 1;
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, &v, 1);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  std::string Seal(const std::string & subject, const char * field,
      const std::string & plain, uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN] = NULL) {
    uint8_t scratch[GDEFCORE_SUBJECT_MAC_LEN];
    char * text = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_seal(subjects_, subject.data(),
        subject.size(), field, strlen(field), plain.data(), plain.size(), &text,
        &n, mac == NULL ? scratch : mac));
    std::string out(text == NULL ? "" : text, n);
    gdefcore_subject_free(subjects_, text);
    return out;
  }

  /* A case for @p who: its note, and one contact per entry of @p contacts,
   * each value sealed for the subject its item names. */
  GDEFCORE_Result SaveCase(const std::string & id, const std::string & who,
      const std::string & note,
      const std::vector<std::pair<std::string, std::string>> & contacts) {
    GDEFCORE_Tree * t = NULL;
    GDEFCORE_Changeset * cs = NULL;
    std::string sealed = Seal(who, "note", note);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_create(catalog_, &t));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "title", 5, "case", 4));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "who", 3, who.data(),
        who.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "note", 4, sealed.data(),
        sealed.size()));
    for (const auto & c : contacts) {
      size_t item = 0;
      std::string cn = Seal(c.first, "contacts.note", c.second);
      EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_add(t, 0, "contacts", 8, 0, &item));
      EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, item, "who", 3,
          c.first.data(), c.first.size()));
      EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, item, "note", 4, cn.data(),
          cn.size()));
    }
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_accept_sealed(cs);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_tree_save(cs, id.data(), id.size(), "en", 2, t);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
    return rc;
  }

  std::string NewCase() {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kCase, strlen(kCase), id, NULL));
    return id;
  }

  std::string NewSubject() {
    char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, sid));
    return sid;
  }

  /* gdefcore_access_read(): "<invalid>", or the values joined by `,`. */
  std::string Read(GDEFCORE_Request * req, const std::string & id,
      const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_access_read(catalog_, req, id.data(),
        id.size(), "en", 2, field, strlen(field), &texts, &lens, &n, NULL);
    if (rc != GDEFCORE_OK) {
      return "<" + std::to_string(static_cast<int>(rc)) + ">";
    }
    std::string out;
    for (size_t i = 0; i < n; i++) {
      out += (i > 0 ? "," : "") + std::string(texts[i], lens[i]);
    }
    gdefcore_values_free(catalog_, texts, lens, n);
    return out;
  }

  /* gdefcore_access_tree(): every value, "path=text", sorted. */
  std::set<std::string> Tree(GDEFCORE_Request * req, const std::string & id) {
    GDEFCORE_Tree * t = NULL;
    std::set<std::string> out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_tree(catalog_, req, id.data(),
        id.size(), "en", 2, &t));
    for (size_t i = 0; t != NULL && i < gdefcore_tree_item_count(t); i++) {
      GDEFCORE_TreeItem it;
      memset(&it, 0, sizeof it);
      it.size = sizeof it;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_item(t, i, &it));
      for (size_t k = 0; k < it.value_count; k++) {
        const char * f = NULL;
        size_t fn = 0;
        const char * v = NULL;
        size_t vn = 0;
        EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_value(t, i, k, &f, &fn, &v, &vn));
        std::string path(it.path, it.path_len);
        if (fn > 0) {
          path += (path.empty() ? "" : ".") + std::string(f, fn);
        }
        out.insert(path + "=" + std::string(v, vn));
      }
    }
    gdefcore_tree_free(t);
    return out;
  }

  std::string Render(GDEFCORE_Request * req, const std::string & id,
      const char * tmpl = "card") {
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_render_entity(catalog_, req, tmpl,
        strlen(tmpl), id.data(), id.size(), "en", 2, GDEFCORE_RENDER_PAGE_FUEL,
        &bytes, &n);
    if (rc != GDEFCORE_OK) {
      return "<" + std::to_string(static_cast<int>(rc)) + ">";
    }
    std::string out(bytes, n);
    gdefcore_text_free(catalog_, bytes);
    return out;
  }

  /* A revision view: "<status>:<texts>". */
  std::string View(GDEFCORE_Request * req, const std::string & id,
      uint64_t seq, const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    int status = 0;
    GDEFCORE_Result rc = gdefcore_access_revision_values(catalog_, req,
        id.data(), id.size(), seq, "en", 2, field, strlen(field), &status,
        &texts, &lens, &n);
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    std::string out = status == GDEFCORE_REVISION_SHOWN      ? "shown"
                      : status == GDEFCORE_REVISION_ABSENT   ? "absent"
                      : status == GDEFCORE_REVISION_PERSONAL ? "personal"
                      : status == GDEFCORE_REVISION_ERASED   ? "erased"
                                                             : "?";
    for (size_t i = 0; i < n; i++) {
      out += ":" + std::string(texts[i], lens[i]);
    }
    gdefcore_values_free(catalog_, texts, lens, n);
    return out;
  }

  /* The editor's form: "field=[value]..." for every field. */
  std::string Form(GDEFCORE_Request * req, const std::string & id) {
    GDEFCORE_Form * form = NULL;
    GDEFCORE_Result rc = gdefcore_form_tree_for(catalog_, req, id.data(),
        id.size(), "en", 2, &form);
    if (rc != GDEFCORE_OK) {
      return "<" + std::to_string(static_cast<int>(rc)) + ">";
    }
    std::string out;
    for (size_t i = 0; i < gdefcore_form_field_count(form); i++) {
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
      EXPECT_EQ(GDEFCORE_OK, gdefcore_form_field(form, i, &name, &name_len,
          &required, &many, &personal, &min_len, &max_len, &has_range,
          &range_min, &range_max, &pattern, &pattern_len, &texts, &lens,
          &count));
      out += std::string(name, name_len) + "=";
      for (size_t k = 0; k < count; k++) {
        out += "[" + std::string(texts[k], lens[k]) + "]";
      }
      out += " ";
    }
    gdefcore_form_destroy(form);
    return out;
  }

  std::string Dump(int which = GDEFSTOR_MODEL_TRUTH) {
    uint8_t * text = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK,
        gdefstor_model_dump(store_, kTenant, 1, which, &text, &n));
    std::string out(reinterpret_cast<const char *>(text), text == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, text);
    return out;
  }

  std::vector<std::string> Lines(const std::string & dump, char tag) {
    std::vector<std::string> out;
    std::istringstream in(dump);
    std::string line;
    while (std::getline(in, line)) {
      if (line.size() > 1 && line[0] == tag && line[1] == ' ') {
        out.push_back(line);
      }
    }
    return out;
  }

  size_t Revisions(const std::string & id) {
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision_count(catalog_, id.data(), id.size(), &n));
    return n;
  }

  /* The blind rows of @p subject, read from the store. */
  size_t BlindRows(const std::string & subject) {
    size_t n = 0;
    for (const std::string & l : Lines(Dump(), 'B')) {
      n += l.find(" " + Hex(subject) + " ") != std::string::npos;
    }
    return n;
  }

  /* The value versions the port's subject lookup finds for @p subject. */
  size_t Versions(const std::string & subject) {
    GDEFSTOR_SubjectHits * hits = NULL;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_subject_lookup(store_, kTenant, 1,
        subject.data(), subject.size(), &hits));
    size_t n = gdefstor_subject_hits_count(hits);
    gdefstor_subject_hits_free(hits);
    return n;
  }

  void Erase(const std::string & subject) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_erase(subjects_, subject.data(),
        subject.size(), subject.data(), subject.size()));
  }

  std::string SubjectRead(const std::string & subject, const std::string & id,
      const char * field) {
    char * text = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_subject_read(subjects_, catalog_,
        subject.data(), subject.size(), id.data(), id.size(), field,
        strlen(field), "en", 2, &text, &n);
    if (rc != GDEFCORE_OK) {
      return "<" + std::to_string(static_cast<int>(rc)) + ">";
    }
    std::string out(text, n);
    gdefcore_subject_free(subjects_, text);
    return out;
  }

  std::string Export(const std::string & subject) {
    char * json = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_export(subjects_, catalog_,
        subject.data(), subject.size(), &json, &n));
    std::string out(json == NULL ? "" : json, n);
    gdefcore_subject_free(subjects_, json);
    return out;
  }

  /* Render @p id with @p tmpl for @p who and keep the fragment under the
   * request's render key; the key is returned. */
  std::string RenderAndCache(const char * who, const std::string & id,
      const char * tmpl, std::string * out_page = NULL) {
    GDEFCORE_Request * r = Req(who);
    std::string page = Render(r, id, tmpl);
    char * key = NULL;
    size_t key_len = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_render_key(catalog_, r, NULL, 0,
        NULL, 0, &key, &key_len));
    std::string k(key == NULL ? "" : key, key_len);
    gdefcore_text_free(catalog_, key);
    /* One fragment per (entity, template): the render key names the
     * principal's permissions, not what was rendered. */
    k += "|" + id + "|" + tmpl;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_fragment_put(cache_, r, k.data(), k.size(),
        page.data(), page.size()));
    if (out_page != NULL) {
      *out_page = page;
    }
    return k;
  }

  bool Cached(const std::string & key, std::string * out = NULL) {
    char * bytes = NULL;
    size_t n = 0;
    int found = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_fragment_get(cache_, key.data(), key.size(),
        &bytes, &n, &found));
    if (found && out != NULL) {
      out->assign(bytes, n);
    }
    gdefcore_fragment_free(cache_, bytes);
    return found != 0;
  }
};

/* ---- subject sources ------------------------------------------------------ */

/* AD-19: every personal value names its subject, through a reference declared
 * on the field, else the entity's own subject; a personal field with neither
 * is refused when it is declared, and so is changing what a stored type or
 * field is. */
TEST_F(Personal, APersonalFieldWithNoSubjectSourceIsRefusedAtDeclaration) {
  GDEFCORE_Field orphan[2] = {Plain("title"), Secret("secret")};
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_type_define(catalog_, "site.a", 6,
      GDEFCORE_TYPE_CONTENT, orphan, 2));
  int kind = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_type_kind(catalog_, "site.a", 6, &kind));
  /* The control: the same field with a reference, and on a subjects type. */
  GDEFCORE_Field named[3] = {Plain("title"), Secret("secret", "who"),
      Plain("who", GDEFSTOR_FIELD_REFERENCE)};
  EXPECT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, "site.b", 6,
      GDEFCORE_TYPE_CONTENT, named, 3));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, "site.c", 6,
      GDEFCORE_TYPE_CONTENT | GDEFCORE_TYPE_SUBJECTS, orphan, 2));
  int subjects = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_subjects(catalog_, "site.c", 6,
      &subjects));
  EXPECT_EQ(1, subjects);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_subjects(catalog_, "site.b", 6,
      &subjects));
  EXPECT_EQ(0, subjects);
  /* A changeset is held to the same rule. */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_define(cs, "site.d", 6,
      GDEFCORE_TYPE_CONTENT, orphan, 2));
  /* Whether a type's entities are subjects cannot change once it is
   * stored: each one's subject was made with it, or was not. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_define(cs, "site.c", 6,
      GDEFCORE_TYPE_CONTENT, named, 3));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_define(cs, "site.b", 6,
      GDEFCORE_TYPE_CONTENT | GDEFCORE_TYPE_SUBJECTS, named, 3));
  gdefcore_changeset_destroy(cs);
  /* A plain field cannot become personal in place, nor the reverse. */
  GDEFCORE_Field plain[3] = {Plain("title"), Plain("secret"),
      Plain("who", GDEFSTOR_FIELD_REFERENCE)};
  EXPECT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, "site.e", 6,
      GDEFCORE_TYPE_CONTENT, plain, 3));
  for (const char * t : {"site.e", "site.b"}) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_define(cs, t, 6,
        GDEFCORE_TYPE_CONTENT, std::string(t) == "site.e" ? named : plain, 3));
    EXPECT_NE(GDEFCORE_OK, gdefcore_changeset_apply(cs, t, 6)) << t;
    gdefcore_changeset_destroy(cs);
  }
  int personal = 9;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_personal(catalog_, "site.e", 6, 1, &personal));
  EXPECT_EQ(0, personal);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_field_personal(catalog_, "site.b", 6, 1, &personal));
  EXPECT_EQ(1, personal);
}

/* A type whose entities are subjects: each entity's subject is made with it
 * and kept with it, and every value of its personal fields is stored under
 * it. Erasing it makes every one of them read [erased] everywhere; another
 * member is not touched. */
TEST_F(Personal, AnEntityOfASubjectTypeIsItsOwnSubject) {
  std::string sa;
  std::string sb;
  std::string a = Member(&sa);
  std::string b = Member(&sb);
  ASSERT_EQ(GDEFCORE_PUBLIC_ID_LEN, sa.size());
  EXPECT_NE(sa, sb);
  EXPECT_NE(a, sa);
  int erased = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_subject_erased(subjects_, sa.data(), sa.size(), &erased));
  EXPECT_EQ(0, erased);
  /* Kept with the entity: a record of it, not a value of a field. */
  EXPECT_NE(std::string::npos, Dump().find(Hex(sa)));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann Ash"));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "email", "ann@example.org"));
  ASSERT_EQ(GDEFCORE_OK, Say(b, "name", "Bob Birch"));
  ASSERT_EQ(GDEFCORE_OK, SetPlain(a, "title", "deacon"));
  /* Under the entity's subject: the lookup finds a's values under sa (each
   * version with its blind row), and b's under sb. */
  EXPECT_GE(Versions(sa), 2u);
  EXPECT_EQ(BlindRows(sa), Versions(sa));
  EXPECT_EQ(1u, Versions(sb));
  /* A subject given that is not the one the declaration names is refused. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_subject_save(subjects_, catalog_, sb.data(), sb.size(),
          a.data(), a.size(), "name", 4, "en", 2, "Bob", 3));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_subject_save(subjects_, catalog_, sa.data(), sa.size(),
          a.data(), a.size(), "name", 4, "en", 2, "Ann Ash", 7));
  GDEFCORE_Request * staff = Req(staff_);
  EXPECT_EQ("Ann Ash", Read(staff, a, "name"));
  EXPECT_EQ("[Ann Ash|ann@example.org]", Render(staff, a));
  Erase(sa);
  ASSERT_FALSE(HasFatalFailure());
  /* Everywhere a reader is shown it, it is [erased]. */
  EXPECT_EQ(GDEFCORE_SUBJECT_ERASED, Read(staff, a, "name"));
  EXPECT_EQ(GDEFCORE_SUBJECT_ERASED, Read(staff, a, "email"));
  std::set<std::string> tree = Tree(staff, a);
  EXPECT_EQ(1u, tree.count("name=[erased]"));
  EXPECT_EQ(1u, tree.count("email=[erased]"));
  EXPECT_EQ(1u, tree.count("title=deacon"));
  EXPECT_EQ("[[erased]|[erased]]", Render(staff, a));
  EXPECT_EQ("erased:[erased]", View(staff, a, 1, "name"));
  EXPECT_EQ("title=[deacon] name=[[erased]] email=[[erased]] ", Form(staff, a));
  EXPECT_EQ(GDEFCORE_SUBJECT_ERASED, SubjectRead(sa, a, "name"));
  EXPECT_EQ("{\"erased\":\"[erased]\"}", Export(sa));
  /* The other member is themself. */
  EXPECT_EQ("Bob Birch", Read(staff, b, "name"));
  EXPECT_EQ("[Bob Birch|]", Render(staff, b));
  /* A new entity of a subjects type needs the keys to make its subject. */
  gdefcore_catalog_bind_subjects(catalog_, NULL);
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_create(catalog_, kMember, strlen(kMember), id, NULL));
  gdefcore_catalog_bind_subjects(catalog_, subjects_);
  /* An entity of a type that keeps none has none. */
  std::string kase = NewCase();
  char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_subject(catalog_, kase.data(), kase.size(), sid));
}

/* A field naming a reference stores under the referenced subject, at the root
 * and in every group item; erasing that subject affects only those values. */
TEST_F(Personal, AFieldNamingAReferenceStoresUnderTheReferencedSubject) {
  std::string ann = NewSubject();
  std::string bob = NewSubject();
  std::string c1 = NewCase();
  std::string c2 = NewCase();
  ASSERT_EQ(GDEFCORE_OK,
      SaveCase(c1, ann, "ann's case", {{ann, "ann's phone"}, {bob, "bob's phone"}}));
  ASSERT_EQ(GDEFCORE_OK, SaveCase(c2, bob, "bob's case", {}));
  EXPECT_EQ(2u, Versions(ann));
  EXPECT_EQ(2u, Versions(bob));
  /* At any depth, the system read finds the value stored for the subject. */
  EXPECT_EQ("ann's phone", SubjectRead(ann, c1, "contacts.note"));
  EXPECT_EQ("bob's phone", SubjectRead(bob, c1, "contacts.note"));
  EXPECT_EQ("ann's case", SubjectRead(ann, c1, "note"));
  GDEFCORE_Request * staff = Req(staff_);
  std::set<std::string> tree = Tree(staff, c1);
  EXPECT_EQ(1u, tree.count("note=ann's case"));
  EXPECT_EQ(1u, tree.count("contacts.note=ann's phone"));
  EXPECT_EQ(1u, tree.count("contacts.note=bob's phone"));
  Erase(ann);
  ASSERT_FALSE(HasFatalFailure());
  tree = Tree(staff, c1);
  EXPECT_EQ(1u, tree.count("note=[erased]"));
  EXPECT_EQ(1u, tree.count("contacts.note=[erased]"));
  EXPECT_EQ(1u, tree.count("contacts.note=bob's phone"));
  EXPECT_EQ("bob's case", Read(staff, c2, "note"));
  EXPECT_EQ(GDEFCORE_SUBJECT_ERASED, Read(staff, c1, "note"));
  EXPECT_EQ("bob's phone", SubjectRead(bob, c1, "contacts.note"));
}

/* Whose a value is, is the declaration's to say: a value sealed for anyone
 * else is refused, and writes nothing. With the subject the declaration
 * names, every value version is found under it. */
TEST_F(Personal, EveryValueIsStoredUnderTheSubjectItsDeclarationNames) {
  std::string sa;
  std::string a = Member(&sa);
  std::string other = NewSubject();
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  std::string before = Dump();
  {
    /* A value sealed for someone else, and told as theirs. */
    uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN];
    std::string sealed = Seal(other, "name", "Not Ann", mac);
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    const char * texts[1] = {sealed.c_str()};
    size_t lens[1] = {sealed.size()};
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "name";
    v.field_len = 4;
    v.texts = texts;
    v.text_lens = lens;
    v.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_note_sealed(cs, subjects_,
        sealed.data(), sealed.size(), other.data(), other.size(), mac));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, a.data(), a.size(), "en", 2, &v, 1));
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ(before, Dump()) << "a value of someone else was written";
  EXPECT_EQ(0u, Versions(other));
  /* The same for a value sealed for its reference's subject, in a case
   * whose `who` names another. */
  std::string ann = NewSubject();
  std::string c = NewCase();
  ASSERT_EQ(GDEFCORE_OK, SaveCase(c, ann, "ann's", {}));
  {
    GDEFCORE_Tree * t = NULL;
    GDEFCORE_Changeset * cs = NULL;
    std::string crossed = Seal(other, "note", "not ann's");
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_create(catalog_, &t));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "title", 5, "case", 4));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "who", 3, ann.data(),
        ann.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "note", 4, crossed.data(),
        crossed.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_save(cs, c.data(), c.size(), "en", 2,
        t));
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
  }
  EXPECT_EQ(0u, Versions(other));
  /* Every personal value version the store holds names its subject: the
   * subject lookups find one per version, each with its blind row, and
   * together every personal value of the store. */
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann Ash"));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "email", "ann@example.org"));
  EXPECT_GE(Versions(sa), 3u);
  EXPECT_EQ(BlindRows(sa), Versions(sa));
  EXPECT_EQ(1u, Versions(ann));
  EXPECT_EQ(Lines(Dump(), 'B').size(), Versions(sa) + Versions(ann))
      << "a value is stored under a subject no lookup asks for";
}

/* ---- the read path -------------------------------------------------------- */

/* A reader the filter allows sees the plaintext; a reader without the field
 * sees it absent; an erased subject reads [erased]. */
TEST_F(Personal, AnAllowedReaderSeesThePlaintextAndAnErasedSubjectReadsErased) {
  std::string sa;
  std::string a = Member(&sa);
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "email", "ann@example.org"));
  GDEFCORE_Request * staff = Req(staff_);
  GDEFCORE_Request * clerk = Req(clerk_);
  EXPECT_EQ("ann@example.org", Read(staff, a, "email"));
  EXPECT_EQ("", Read(clerk, a, "email"));
  EXPECT_EQ("Ann", Read(clerk, a, "name"));
  EXPECT_EQ(0u, Tree(clerk, a).count("email=ann@example.org"));
  EXPECT_EQ(1u, Tree(staff, a).count("email=ann@example.org"));
  EXPECT_EQ("[Ann|]", Render(clerk, a));
  EXPECT_EQ("[Ann|ann@example.org]", Render(staff, a));
  EXPECT_EQ("absent", View(clerk, a, 2, "email"));
  EXPECT_EQ("shown:ann@example.org", View(staff, a, 2, "email"));
  EXPECT_EQ("shown:Ann", View(clerk, a, 1, "name"));
  EXPECT_EQ("title= name=[Ann] email= ", Form(clerk, a));
  EXPECT_EQ("title= name=[Ann] email=[ann@example.org] ", Form(staff, a));
  /* Never the ciphertext, on any surface. */
  for (const std::string & s :
      {Read(staff, a, "email"), Render(staff, a), View(staff, a, 2, "email"),
          Form(staff, a)}) {
    EXPECT_EQ(std::string::npos, s.find("s1:")) << s;
  }
  /* A catalog with no subjects shows no personal value at all. */
  gdefcore_catalog_bind_subjects(catalog_, NULL);
  EXPECT_EQ("", Read(staff, a, "email"));
  EXPECT_EQ("[|]", Render(staff, a));
  EXPECT_EQ("personal", View(staff, a, 2, "email"));
  gdefcore_catalog_bind_subjects(catalog_, subjects_);
  Erase(sa);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(GDEFCORE_SUBJECT_ERASED, Read(staff, a, "email"));
  EXPECT_EQ("", Read(clerk, a, "email"));
  EXPECT_EQ("[[erased]|]", Render(clerk, a));
}

/* AD-19: decryption happens only after the access filter has allowed the
 * field. A reader who may not see it causes none, on any read surface; the
 * control, a reader who may, causes one per value. */
TEST_F(Personal, AReaderWhoMayNotSeeTheFieldCausesNoDecryption) {
  std::string sa;
  std::string a = Member(&sa);
  ASSERT_EQ(GDEFCORE_OK, SetPlain(a, "title", "deacon"));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "email", "ann@example.org"));
  GDEFCORE_Request * clerk = Req(clerk_);
  uint64_t before = gdefcore_subject_open_count(subjects_);
  EXPECT_EQ("", Read(clerk, a, "email"));
  std::set<std::string> tree = Tree(clerk, a);
  EXPECT_EQ(1u, tree.count("title=deacon"));
  EXPECT_EQ(1u, tree.size());
  EXPECT_EQ("[|]", Render(clerk, a));
  EXPECT_EQ("absent", View(clerk, a, 2, "email"));
  EXPECT_EQ("title=[deacon] name= email= ", Form(clerk, a));
  EXPECT_EQ(before, gdefcore_subject_open_count(subjects_))
      << "a value the reader may not see was decrypted";
  EXPECT_EQ(0u, gdefcore_request_subject_count(clerk));
  /* The control: the instrument moves when a reader may see it. */
  GDEFCORE_Request * staff = Req(staff_);
  EXPECT_EQ(1u, Tree(staff, a).count("email=ann@example.org"));
  EXPECT_EQ(before + 1, gdefcore_subject_open_count(subjects_));
  EXPECT_EQ(1u, gdefcore_request_subject_count(staff));
}

/* ---- unchanged by plaintext ------------------------------------------------ */

/* Whether a personal value changed is decided on its plaintext at write
 * (AD-19): encryption is randomized, so the same value sealed again is
 * another ciphertext, and still writes nothing: no item version, no
 * revision, no blind row. By the subject save, a tree save, and a draft's
 * publish; a different value writes one of each (the control). */
TEST_F(Personal, AnUnchangedPersonalValueWritesNothing) {
  std::string sa;
  std::string a = Member(&sa);
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  size_t revisions = Revisions(a);
  std::string truth = Dump();
  /* What a value's change writes: item versions, blind rows and revisions.
   * (Every apply moves the config epoch, a counter, whatever it writes.) */
  auto same = [&](const std::string & now) {
    return Lines(truth, 'I') == Lines(now, 'I') &&
           Lines(truth, 'B') == Lines(now, 'B') &&
           Lines(truth, 'R') == Lines(now, 'R');
  };
  /* The subject route, again. */
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  EXPECT_EQ(revisions, Revisions(a));
  EXPECT_TRUE(same(Dump())) << "an unchanged personal value wrote a row";
  /* A tree of the entity with the value sealed again. */
  {
    GDEFCORE_Tree * t = NULL;
    GDEFCORE_Changeset * cs = NULL;
    std::string again = Seal(sa, "name", "Ann");
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_create(catalog_, &t));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "name", 4, again.data(),
        again.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_save(cs, a.data(), a.size(), "en", 2,
        t));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    uint64_t wrote = 99;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revision(cs, a.data(), a.size(), &wrote));
    EXPECT_EQ(0u, wrote);
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
  }
  EXPECT_EQ(revisions, Revisions(a));
  EXPECT_TRUE(same(Dump()));
  /* A draft of the same value, published. */
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    std::string again = Seal(sa, "name", "Ann");
    const char * texts[1] = {again.c_str()};
    size_t lens[1] = {again.size()};
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "name";
    v.field_len = 4;
    v.texts = texts;
    v.text_lens = lens;
    v.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, a.data(), a.size(), "en", 2, &v, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, a.data(), a.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ(revisions, Revisions(a));
  EXPECT_TRUE(same(Dump()))
      << "a draft of an unchanged value wrote an item version";
  /* The control: another value is a revision, a version and a row. */
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Anne"));
  EXPECT_EQ(revisions + 1, Revisions(a));
  EXPECT_EQ(Lines(truth, 'B').size() + 1, Lines(Dump(), 'B').size());
  EXPECT_EQ("Anne", Read(Req(staff_), a, "name"));
}

/* ---- renders and erasure ---------------------------------------------------- */

/* A render that decrypted a subject records it, and a fragment cached from
 * it depends on it: erasing the subject purges that fragment and keeps the
 * rest (one that decrypted another subject, one that decrypted nothing). A
 * cache bound after an erasure is purged of what it held of that subject. */
TEST_F(Personal, ACachedRenderThatDecryptedASubjectIsPurgedWhenItIsErased) {
  std::string sa;
  std::string sb;
  std::string a = Member(&sa);
  std::string b = Member(&sb);
  std::string t = Member();
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  ASSERT_EQ(GDEFCORE_OK, Say(b, "name", "Bob"));
  ASSERT_EQ(GDEFCORE_OK, SetPlain(t, "title", "deacon"));
  std::string page;
  std::string ka = RenderAndCache(staff_, a, "card", &page);
  EXPECT_EQ("[Ann|]", page);
  std::string kb = RenderAndCache(staff_, b, "card", &page);
  EXPECT_EQ("[Bob|]", page);
  /* A render that decrypts nothing: a member with no personal value. */
  std::string kt = RenderAndCache(staff_, t, "badge", &page);
  EXPECT_EQ("{deacon}", page);
  ASSERT_EQ(3u, gdefcore_fragment_count(cache_));
  Erase(sa);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_FALSE(Cached(ka)) << "a fragment survived its subject's erasure";
  EXPECT_TRUE(Cached(kb));
  std::string kept;
  EXPECT_TRUE(Cached(kt, &kept));
  EXPECT_EQ("{deacon}", kept);
  /* A render now shows the marker, and depends on nobody. */
  GDEFCORE_Request * r = Req(staff_);
  EXPECT_EQ("[[erased]|]", Render(r, a));
  EXPECT_EQ(0u, gdefcore_request_subject_count(r));
  /* A cache that held b's fragment before b was erased, bound afterwards. */
  GDEFCORE_FragmentCache * later = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_cache_create(NULL, 4, &later));
  GDEFCORE_Request * rb = Req(staff_);
  std::string pb = Render(rb, b);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_put(later, rb, "b", 1, pb.data(),
      pb.size()));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_bind_cache(subjects_, NULL));
  Erase(sb);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(1u, gdefcore_fragment_count(later));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_bind_cache(subjects_, later));
  EXPECT_EQ(0u, gdefcore_fragment_count(later))
      << "binding a cache did not replay the ledger into it";
  ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_bind_cache(subjects_, cache_));
  gdefcore_fragment_cache_destroy(later);
}

/* A revision view of an erased subject's value says so, in its status as well
 * as its text. */
TEST_F(Personal, ARevisionViewOfAnErasedSubjectSaysErased) {
  std::string sa;
  std::string a = Member(&sa);
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Anne"));
  GDEFCORE_Request * staff = Req(staff_);
  EXPECT_EQ("shown:Ann", View(staff, a, 1, "name"));
  EXPECT_EQ("shown:Anne", View(staff, a, 2, "name"));
  Erase(sa);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ("erased:[erased]", View(staff, a, 1, "name"));
  EXPECT_EQ("erased:[erased]", View(staff, a, 2, "name"));
}

/* ---- everything about this person ----------------------------------------- */

/* "Everything about this person" by the subject column, through core: every
 * value stored for the subject, in every type, in groups, and every version
 * history kept. */
TEST_F(Personal, EverythingAboutThisPersonListsEveryValueAcrossTypesGroupsAndHistory) {
  std::string sa;
  std::string a = Member(&sa);
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Anne"));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "email", "ann@example.org", "fr"));
  std::string other = NewSubject();
  std::string c = NewCase();
  ASSERT_EQ(GDEFCORE_OK,
      SaveCase(c, sa, "anne's case", {{sa, "anne's phone"}, {other, "theirs"}}));
  std::string doc = Export(sa);
  for (const char * want : {"\"text\":\"Ann\"", "\"text\":\"Anne\"",
           "\"text\":\"ann@example.org\"", "\"text\":\"anne's case\"",
           "\"text\":\"anne's phone\"", "\"type\":\"site.member\"",
           "\"type\":\"site.case\"", "\"field\":\"contacts.note\"",
           "\"lang\":\"fr\"", "\"to\":null"}) {
    EXPECT_NE(std::string::npos, doc.find(want)) << want << " in " << doc;
  }
  /* History: the superseded name says when it was replaced. */
  {
    size_t at = doc.find("\"text\":\"Ann\"");
    ASSERT_NE(std::string::npos, at);
    size_t open = doc.rfind('{', at);
    std::string entry = doc.substr(open, at - open);
    EXPECT_EQ(std::string::npos, entry.find("\"to\":null")) << entry;
  }
  EXPECT_EQ(std::string::npos, doc.find("theirs")) << "another person's value";
  EXPECT_EQ(Versions(sa), [&] {
    size_t n = 0;
    size_t at = 0;
    while ((at = doc.find("\"text\":", at)) != std::string::npos) {
      n += 1;
      at += 1;
    }
    return n;
  }());
}

/* "Everything about this person" lists a draft's values too (story S8): a
 * draft is JSON outside the revision tables, so the subject lookup does not
 * see it. The draft of a published member and the draft that reserves a case
 * never saved are both listed, at every depth, with the draft's base; another
 * person's value in the same draft is not, and is in theirs (the control). */
TEST_F(Personal, EverythingAboutThisPersonListsEveryDraftsValues) {
  std::string sa;
  std::string a = Member(&sa);
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", "Ann"));
  std::string other = NewSubject();
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    std::string sealed = Seal(sa, "name", "Annie-draft");
    const char * texts[1] = {sealed.c_str()};
    size_t lens[1] = {sealed.size()};
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "name";
    v.field_len = 4;
    v.texts = texts;
    v.text_lens = lens;
    v.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, a.data(), a.size(), "en", 2, &v, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  std::string c = NewCase();
  {
    GDEFCORE_Tree * t = NULL;
    GDEFCORE_Changeset * cs = NULL;
    std::string note = Seal(sa, "note", "drafted case note");
    std::string mine = Seal(sa, "contacts.note", "drafted phone");
    std::string theirs = Seal(other, "contacts.note", "theirs-drafted");
    size_t item = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_create(catalog_, &t));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "title", 5, "case", 4));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "who", 3, sa.data(),
        sa.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "note", 4, note.data(),
        note.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_add(t, 0, "contacts", 8, 0, &item));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, item, "who", 3, sa.data(),
        sa.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, item, "note", 4, mine.data(),
        mine.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_add(t, 0, "contacts", 8, 0, &item));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, item, "who", 3,
        other.data(), other.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, item, "note", 4,
        theirs.data(), theirs.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_tree_save_draft(cs, c.data(), c.size(), "en", 2, t));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
  }
  std::string doc = Export(sa);
  size_t at = doc.find("\"drafts\":[");
  ASSERT_NE(std::string::npos, at) << doc;
  std::string values = doc.substr(0, at);
  std::string drafts = doc.substr(at);
  EXPECT_NE(std::string::npos, values.find("\"text\":\"Ann\"")) << doc;
  EXPECT_EQ(std::string::npos, values.find("Annie-draft"))
      << "a draft holds no version";
  for (const char * want : {"\"text\":\"Annie-draft\"",
           "\"text\":\"drafted case note\"", "\"text\":\"drafted phone\"",
           "\"field\":\"contacts.note\"", "\"type\":\"site.case\"",
           "\"type\":\"site.member\"", "\"base\":0", "\"lang\":\"en\""}) {
    EXPECT_NE(std::string::npos, drafts.find(want)) << want << " in " << doc;
  }
  EXPECT_NE(std::string::npos, drafts.find("\"entity\":\"" + a + "\""));
  EXPECT_NE(std::string::npos, drafts.find("\"entity\":\"" + c + "\""));
  EXPECT_EQ(std::string::npos, doc.find("theirs-drafted"))
      << "another person's value";
  std::string theirs = Export(other);
  EXPECT_NE(std::string::npos, theirs.find("\"text\":\"theirs-drafted\""))
      << theirs;
  EXPECT_EQ(std::string::npos, theirs.find("drafted phone"));
}

/* ---- no plaintext in any stored row ---------------------------------------- */

/* AD-19: the database never holds a plaintext. A canary goes through every
 * write path (the subject save, a tree save into a group, a draft and its
 * publish, an unchanged resave, a revert) and then is searched for, raw and
 * as hex, in every row the store holds, current and truth, blind rows,
 * drafts and records, and in the store's snapshot. The control: the export
 * opens it, so the canary is a value the search would see. */
TEST_F(Personal, NoStoredRowHoldsAPlaintext) {
  const std::string canary = "zq-s7-canary-otter";
  const std::string canary2 = "zq-s7-canary-heron";
  std::string sa;
  std::string a = Member(&sa);
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", canary));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "name", canary));
  ASSERT_EQ(GDEFCORE_OK, Say(a, "email", canary2));
  std::string c = NewCase();
  ASSERT_EQ(GDEFCORE_OK, SaveCase(c, sa, canary, {{sa, canary2}}));
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    std::string sealed = Seal(sa, "name", canary2);
    const char * texts[1] = {sealed.c_str()};
    size_t lens[1] = {sealed.size()};
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "name";
    v.field_len = 4;
    v.texts = texts;
    v.text_lens = lens;
    v.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, a.data(), a.size(), "en", 2, &v, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  std::string with_draft = Dump();
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, a.data(), a.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revert(catalog_, a.data(), a.size(), NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  std::string stored = with_draft + "\n" + Dump() + "\n" +
                       Dump(GDEFSTOR_MODEL_CURRENT);
  {
    uint8_t * zip = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_export(store_, kTenant, 1, NULL, &zip, &n));
    stored += "\n" + Unpacked(zip, n);
    gdefstor_bytes_free(NULL, zip);
  }
  /* The control: the canaries are values core holds and opens. */
  std::string doc = Export(sa);
  ASSERT_NE(std::string::npos, doc.find(canary));
  ASSERT_NE(std::string::npos, doc.find(canary2));
  ASSERT_NE(std::string::npos, stored.find(Hex("s1:")))
      << "the search reads no personal value at all";
  for (const std::string & needle :
      {canary, canary2, Hex(canary), Hex(canary2),
          Hex(canary).substr(0, 24), Hex(canary2).substr(0, 24)}) {
    EXPECT_EQ(std::string::npos, stored.find(needle))
        << "a stored row holds a plaintext personal value: " << needle;
  }
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
