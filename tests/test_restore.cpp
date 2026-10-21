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
 * Story S8: the restore of a backup pair through core, end to end, as AD-23
 * and AD-37 say. A tenant is taken on the memory backend and restored through
 * gdefcore_subject_restore() into an empty tenant of another backend: memory
 * and SQLite here, and Postgres alone when GDEFCORE_TEST_RESTORE=postgres
 * (make test-restore-postgres, through defiant-storage-postgres's
 * tools/pg-test.sh). One test per row of the story's matrix:
 *
 *  - cross-backend: entities, revisions, records, drafts, subjects, lists and
 *    blind lookups agree with the source;
 *  - order: every step has run when the restore returns (keys merged, data
 *    imported, modules migrated, ledger replayed, blind index rebuilt), and an
 *    erased subject stays erased;
 *  - modules: a data set whose data for a module is newer than the module
 *    installed is refused, naming the module and both versions;
 *  - grants: a restored grant to anonymous (or authenticated) is reported for
 *    its typed confirmation and not applied, and applies with it.
 *
 * Each refusal is asserted beside the control that passes. tools/check-restore.sh
 * plants each defect the story names in the real source and requires these
 * tests to fail by name.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage-sqlite/model.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#ifdef GDEFCORE_TEST_HAVE_PG
#include <ghoti.io/defiant-storage-postgres/model.h>
#endif

#include <gtest/gtest.h>

#include "keystore_rig.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define RESTORE_STR2(x) #x
#define RESTORE_STR(x) RESTORE_STR2(x)

namespace {

const char kTenant[] = "t";
const char kPerson[] = "site.person";
const char kPost[] = "site.post";
const char kEdition[] = "defiant-edition/1";
const char kCoreToken[] = RESTORE_STR(GHOTIIO_DEFCORE_NAME);

/* ---- the module `blog`, at the stored-data schema version a test asks ---- */

template <uint32_t V>
const GDEFCORE_Module_Manifest * Blog() {
  static GDEFCORE_Module_Manifest m;
  memset(&m, 0, sizeof m);
  m.size = sizeof m;
  m.core_token = kCoreToken;
  m.core_token_len = strlen(kCoreToken);
  m.name = "blog";
  m.name_len = 4;
  m.label = "Blog";
  m.label_len = 4;
  m.schema_version = V;
  return &m;
}

enum { kMemory = 0, kSqlite = 1, kPostgres = 2 };

const char * BackendName(int b) {
  return b == kPostgres ? "postgres" : b == kSqlite ? "sqlite" : "memory";
}

/* The backends a restore goes into: memory and SQLite, or Postgres alone
 * when GDEFCORE_TEST_RESTORE=postgres (it needs a server, so it is a target
 * of its own). */
std::vector<int> Backends() {
  const char * v = getenv("GDEFCORE_TEST_RESTORE");
  if (v != NULL && strcmp(v, "postgres") == 0) {
    return {kPostgres};
  }
  return {kMemory, kSqlite};
}

/* An empty store of one backend, removed with it. */
struct Dest {
  int backend;
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Host * host = NULL;
  std::string dir;
  std::string prefix;

  explicit Dest(int which) : backend(which) {
    if (backend == kPostgres) {
#ifdef GDEFCORE_TEST_HAVE_PG
      static unsigned n = 0;
      char buf[32];
      const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
      EXPECT_TRUE(ci != NULL && ci[0] != '\0');
      snprintf(buf, sizeof buf, "rs%x_%u_", (unsigned)getpid() & 0xfffffu, ++n);
      prefix = buf;
      GDEFSPG_Options o;
      gdefspg_options_default(&o);
      o.conninfo = ci;
      o.schema_prefix = prefix.c_str();
      EXPECT_EQ(GDEFSPG_OK, gdefspg_model_store_create(&o, NULL, NULL, &store));
#else
      ADD_FAILURE() << "the Postgres arm needs defiant-storage-postgres";
#endif
    } else if (backend == kSqlite) {
      std::error_code ec;
      std::filesystem::path base = std::filesystem::temp_directory_path(ec);
      std::random_device entropy;
      for (int i = 0; i < 100 && dir.empty(); i++) {
        std::filesystem::path p =
            base / ("gdefcore-restore-" + std::to_string(entropy()));
        if (std::filesystem::create_directory(p, ec) && !ec) {
          dir = p.string();
        }
      }
      EXPECT_FALSE(dir.empty());
      GDEFSSQLITE_ModelOptions o;
      gdefssqlite_model_options_default(&o);
      o.synchronous = GDEFSSQLITE_SYNC_OFF; /* many stores; not about the disk */
      EXPECT_EQ(GDEFSSQLITE_OK,
          gdefssqlite_model_store_create(dir.c_str(), &o, NULL, NULL, &store));
    } else {
      EXPECT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
    }
    if (store != NULL) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_host_open(store, NULL, &host));
    }
  }

  ~Dest() {
    gdefcore_host_destroy(host);
    gdefstor_store_destroy(store);
    if (!dir.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(dir, ec);
    }
  }

  void Install(GDEFCORE_Module_Entry entry) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host, entry));
  }
};

GDEFCORE_Field Plain(const char * name) {
  GDEFCORE_Field f;
  memset(&f, 0, sizeof f);
  f.size = sizeof f;
  f.name = name;
  f.name_len = strlen(name);
  return f;
}

GDEFCORE_Permission Perm(const char * label, const char * action) {
  GDEFCORE_Permission p;
  memset(&p, 0, sizeof p);
  p.size = sizeof p;
  p.label = label;
  p.label_len = strlen(label);
  p.module_name = "site";
  p.module_name_len = 4;
  p.action = action;
  p.action_len = strlen(action);
  p.condition = GDEFCORE_ACCESS_ANY;
  p.type_name = kPost;
  p.type_name_len = strlen(kPost);
  return p;
}

typedef std::string Bytes;

const uint8_t * U(const Bytes & b) {
  return reinterpret_cast<const uint8_t *>(b.data());
}

std::string HexOf(const std::string & s) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : s) {
    out += kHex[c >> 4];
    out += kHex[c & 0x0f];
  }
  return out;
}

class Restore : public ::testing::Test {
 protected:
  GDEFSTOR_Store * site_ = NULL;
  GDEFSTOR_KeyStore * keys_ = NULL;
  ksrig::Counts counts_;
  GDEFCORE_Keyring * ring_ = NULL;
  GDEFCORE_Host * host_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  GDEFCORE_Subjects * subjects_ = NULL;
  GDEFCORE_FragmentCache * cache_ = NULL;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  std::vector<GDEFCORE_Request *> reqs_;
  std::string editor_;
  std::string ann_, sann_, bob_, sbob_;
  std::vector<std::string> posts_;

  void SetUp() override {
    memset(root_, 0x42, sizeof root_);
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &site_));
    ASSERT_EQ(GDEFSTOR_OK, ksrig::Open(ksrig::Chosen(), &counts_, &keys_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_keyring_create(root_, sizeof root_, NULL, &ring_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(site_, NULL, &host_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(site_,
        (const uint8_t *)kTenant, 1, NULL, NULL, &catalog_));
    gdefcore_catalog_bind_host(catalog_, host_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_open(keys_, site_,
        (const uint8_t *)kTenant, 1, root_, sizeof root_, ring_, NULL,
        &subjects_));
    gdefcore_catalog_bind_subjects(catalog_, subjects_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_cache_create(NULL, 0, &cache_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_bind_cache(subjects_, cache_));
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
    gdefstor_store_destroy(site_);
  }

  GDEFCORE_Request * Req(const std::string & who = std::string()) {
    GDEFCORE_Request * r = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL, &r));
    if (!who.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_principal(r, who.data(), who.size()));
    }
    reqs_.push_back(r);
    return r;
  }

  /* Enable `blog` on the source, at the version @p entry declares. */
  void EnableBlog(GDEFCORE_Module_Entry entry) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, entry));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, cs, "blog", 4));
    GDEFCORE_Result rc = gdefcore_changeset_apply(cs, "blog", 4);
    gdefcore_changeset_destroy(cs);
    ASSERT_EQ(GDEFCORE_OK, rc);
  }

  GDEFCORE_Result SaveValues(const std::string & id,
      const std::vector<std::pair<const char *, std::string>> & values) {
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> vs(values.size());
    std::vector<const char *> texts(values.size());
    std::vector<size_t> lens(values.size());
    for (size_t i = 0; i < values.size(); i++) {
      texts[i] = values[i].second.c_str();
      lens[i] = values[i].second.size();
      memset(&vs[i], 0, sizeof vs[i]);
      vs[i].size = sizeof vs[i];
      vs[i].field = values[i].first;
      vs[i].field_len = strlen(values[i].first);
      vs[i].texts = &texts[i];
      vs[i].text_lens = &lens[i];
      vs[i].count = 1;
    }
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, vs.data(),
          vs.size());
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  std::string NewPost(const std::string & title, const std::string & group) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPost, strlen(kPost), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, SaveValues(id, {{"title", title}, {"group", group}}));
    return id;
  }

  std::string NewPerson(const std::string & name, std::string * out_subject) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    char sid[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPerson, strlen(kPerson), id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_subject(catalog_, id, strlen(id), sid));
    *out_subject = sid;
    EXPECT_EQ(GDEFCORE_OK, Say(id, name));
    return id;
  }

  GDEFCORE_Result Say(const std::string & id, const std::string & plain) {
    return gdefcore_subject_save(subjects_, catalog_, NULL, 0, id.data(),
        id.size(), "name", 4, "en", 2, plain.data(), plain.size());
  }

  /* A draft of @p id whose name is @p plain, sealed for @p subject. */
  void DraftName(const std::string & id, const std::string & subject,
      const std::string & title, const std::string & plain) {
    char * sealed = NULL;
    size_t sealed_len = 0;
    uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN];
    GDEFCORE_Tree * t = NULL;
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_seal(subjects_, subject.data(),
        subject.size(), "name", 4, plain.data(), plain.size(), &sealed,
        &sealed_len, mac));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_create(catalog_, &t));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "title", 5, title.data(),
        title.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_tree_set(t, 0, "name", 4, sealed,
        sealed_len));
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog_, NULL, 0, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_accept_sealed(cs);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_tree_save_draft(cs, id.data(), id.size(), "en", 2, t);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    gdefcore_tree_free(t);
    gdefcore_subject_free(subjects_, sealed);
    ASSERT_EQ(GDEFCORE_OK, rc);
  }

  /* The source tenant: two types, a role with grants and a principal in it,
   * posts, two people (one with a name changed, so with history), a draft of
   * a personal value, and the module `blog` enabled at @p blog's version. */
  void Populate(GDEFCORE_Module_Entry blog = Blog<1>) {
    GDEFCORE_Field person[2] = {Plain("title"), Plain("name")};
    person[1].personal = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kPerson,
        strlen(kPerson), GDEFCORE_TYPE_CONTENT | GDEFCORE_TYPE_SUBJECTS, person,
        2));
    GDEFCORE_Field post[2] = {Plain("title"), Plain("group")};
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kPost, strlen(kPost),
        GDEFCORE_TYPE_CONTENT, post, 2));
    for (const GDEFCORE_Permission & p :
        {Perm("Read posts", "read"), Perm("Edit posts", "update")}) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog_, &p));
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog_, "editors", 7, NULL));
    for (const char * label : {"Read posts", "Edit posts"}) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "editors", 7,
          label, strlen(label), "core.role", 9));
    }
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog_, id));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, id,
        strlen(id), "editors", 7));
    editor_ = id;
    posts_.push_back(NewPost("Charlie", "b"));
    posts_.push_back(NewPost("Alpha", "a"));
    posts_.push_back(NewPost("Bravo", "a"));
    ann_ = NewPerson("Ann", &sann_);
    ASSERT_EQ(GDEFCORE_OK, Say(ann_, "Anne"));
    bob_ = NewPerson("Bob", &sbob_);
    DraftName(ann_, sann_, "draft", "Annie");
    ASSERT_FALSE(HasFatalFailure());
    EnableBlog(blog);
  }

  Bytes Snapshot(const char * edition = kEdition) {
    uint8_t * zip = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_snapshot(subjects_, site_, edition,
        edition == NULL ? 0 : strlen(edition), &zip, &n));
    Bytes out(reinterpret_cast<const char *>(zip), zip == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, zip);
    return out;
  }

  /* Until the clock has moved on: a key set taken after this is newer than
   * a data set taken before. */
  static void NextMillisecond() {
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
  }

  Bytes Keyset() {
    uint8_t * set = NULL;
    size_t n = 0;
    NextMillisecond();
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_keyset(subjects_, &set, &n));
    Bytes out(reinterpret_cast<const char *>(set), set == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, set);
    return out;
  }

  GDEFCORE_Result RestoreInto(Dest * d, const Bytes & data, const Bytes & keys,
      GDEFCORE_Restore ** report) {
    return gdefcore_subject_restore(subjects_, d->host, d->store, U(data),
        data.size(), U(keys), keys.size(), report);
  }

  static std::string Reason(const GDEFCORE_Restore * r) {
    size_t n = 0;
    const char * why = gdefcore_restore_reason(r, &n);
    return why == NULL ? std::string() : std::string(why, n);
  }

  /* The tenant's truth, as its snapshot holds it: the same truth gives the
   * same bytes, whichever backend holds it. */
  static Bytes Truth(GDEFSTOR_Store * store) {
    uint8_t * zip = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_export(store, kTenant, 1, NULL, &zip, &n));
    Bytes out(reinterpret_cast<const char *>(zip), zip == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, zip);
    return out;
  }

  static std::string Dump(GDEFSTOR_Store * store) {
    uint8_t * text = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_model_dump(store, kTenant, 1,
        GDEFSTOR_MODEL_TRUTH, &text, &n));
    std::string out(reinterpret_cast<const char *>(text), text == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, text);
    return out;
  }

  /* The blind rows of a store that name @p subject, read from the store. */
  static size_t BlindLines(GDEFSTOR_Store * store, const std::string & subject) {
    std::istringstream in(Dump(store));
    std::string line;
    size_t n = 0;
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
      n += w.size() > 5 && w[5] == HexOf(subject);
    }
    return n;
  }

  std::vector<std::string> Find(GDEFCORE_Catalog * catalog,
      const std::string & plain) {
    char ** ids = NULL;
    size_t n = 0;
    std::vector<std::string> out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_find(subjects_, catalog, kPerson,
        strlen(kPerson), "name", 4, "en", 2, plain.data(), plain.size(), &ids,
        &n));
    for (size_t i = 0; i < n; i++) {
      out.push_back(ids[i]);
    }
    gdefcore_ids_free(catalog, ids, n);
    return out;
  }

  std::string NameOf(GDEFCORE_Catalog * catalog, const std::string & subject,
      const std::string & id) {
    char * text = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_subject_read(subjects_, catalog,
        subject.data(), subject.size(), id.data(), id.size(), "name", 4, "en",
        2, &text, &n);
    if (rc != GDEFCORE_OK) {
      return "<" + std::string(gdefcore_result_string(rc)) + ">";
    }
    std::string out(text, n);
    gdefcore_subject_free(subjects_, text);
    return out;
  }

  static std::string ExportOf(GDEFCORE_Subjects * subjects,
      GDEFCORE_Catalog * catalog, const std::string & subject) {
    char * json = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_subject_export(subjects, catalog,
        subject.data(), subject.size(), &json, &n);
    if (rc != GDEFCORE_OK) {
      return "<" + std::string(gdefcore_result_string(rc)) + ">";
    }
    std::string out(json, n);
    gdefcore_subject_free(subjects, json);
    return out;
  }

  /* The posts @p who may list, sorted by title, as ids. */
  std::vector<std::string> List(GDEFCORE_Catalog * catalog,
      const std::string & who) {
    GDEFCORE_Access_List q;
    char ** ids = NULL;
    size_t count = 0;
    std::vector<std::string> out;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = kPost;
    q.type_name_len = strlen(kPost);
    q.lang = "en";
    q.lang_len = 2;
    q.sort_field = "title";
    q.sort_field_len = 5;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_list(catalog, Req(who), &q, &ids, &count));
    for (size_t i = 0; i < count; i++) {
      out.push_back(ids[i]);
    }
    gdefcore_access_free(catalog, ids, count);
    return out;
  }

  /* The title @p who reads, or "<denied>". */
  std::string ReadTitle(GDEFCORE_Catalog * catalog, const std::string & who,
      const std::string & id) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_access_read(catalog, Req(who), id.data(),
        id.size(), "en", 2, "title", 5, &texts, &lens, &n);
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    std::string out = n == 0 ? "<absent>" : std::string(texts[0], lens[0]);
    gdefcore_values_free(catalog, texts, lens, n);
    return out;
  }

  static std::string Record(GDEFSTOR_Store * store, const char * ns,
      const char * key) {
    int found = 0;
    uint8_t * bytes = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_record_get(store, kTenant, 1, ns,
        strlen(ns), key, strlen(key), &found, &bytes, &n));
    std::string out = found ? std::string(reinterpret_cast<const char *>(bytes),
                                  n)
                            : std::string("<none>");
    gdefstor_bytes_free(NULL, bytes);
    return out;
  }

  static std::vector<std::string> RoleGrants(GDEFCORE_Catalog * catalog,
      const char * role) {
    char ** labels = NULL;
    size_t n = 0;
    std::vector<std::string> out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_role_grants(catalog, role,
        strlen(role), &labels, &n));
    for (size_t i = 0; i < n; i++) {
      out.push_back(labels[i]);
    }
    gdefcore_access_free(catalog, labels, n);
    return out;
  }

  GDEFCORE_Catalog * OpenCatalog(GDEFSTOR_Store * store) {
    GDEFCORE_Catalog * c = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store,
        (const uint8_t *)kTenant, 1, NULL, NULL, &c));
    if (c != NULL) {
      gdefcore_catalog_bind_subjects(c, subjects_);
    }
    return c;
  }
};

}  // namespace

/* ---- cross-backend ------------------------------------------------------- */

/* A tenant taken on memory comes back through core on every backend: the
 * truth (entities, their states, revisions and item versions, the draft, the
 * records, counters) exports to the same bytes; each person reads as they did
 * and "everything about this person" is the same document, history and draft
 * included; a list is the same list in the same order; blind lookups find the
 * same entities, the blind index having been rebuilt from what can be
 * decrypted; and the report says the edition and that nothing was held. */
TEST_F(Restore, ATenantTakenOnMemoryComesBackThroughCoreOnEveryBackend) {
  Populate();
  ASSERT_FALSE(HasFatalFailure());
  Bytes data = Snapshot();
  Bytes keys = Keyset();
  Bytes truth = Truth(site_);
  std::string ann_doc = ExportOf(subjects_, catalog_, sann_);
  std::vector<std::string> listed = List(catalog_, editor_);
  ASSERT_EQ(3u, listed.size());
  ASSERT_EQ(std::vector<std::string>({ann_}), Find(catalog_, "Anne"));
  ASSERT_EQ(std::vector<std::string>({bob_}), Find(catalog_, "Bob"));
  ASSERT_NE(std::string::npos, ann_doc.find("\"text\":\"Annie\""));
  for (int backend : Backends()) {
    SCOPED_TRACE(BackendName(backend));
    Dest d(backend);
    ASSERT_NE(nullptr, d.store);
    d.Install(Blog<1>);
    GDEFCORE_Restore * report = NULL;
    ASSERT_EQ(GDEFCORE_OK, RestoreInto(&d, data, keys, &report))
        << Reason(report);
    EXPECT_EQ("", Reason(report));
    EXPECT_EQ(0u, gdefcore_restore_held_count(report));
    EXPECT_EQ(0u, gdefcore_restore_migrated_count(report));
    size_t en = 0;
    const char * ed = gdefcore_restore_edition(report, &en);
    EXPECT_EQ(std::string(kEdition), std::string(ed, en));
    gdefcore_restore_free(report);
    /* Entities, revisions, records, drafts: the same truth. */
    EXPECT_EQ(truth, Truth(d.store));
    EXPECT_EQ("1", Record(d.store, GDEFCORE_MODULE_ENABLED_TYPE, "blog"));
    GDEFCORE_Catalog * dc = OpenCatalog(d.store);
    ASSERT_NE(nullptr, dc);
    /* Subjects. */
    EXPECT_EQ("Anne", NameOf(dc, sann_, ann_));
    EXPECT_EQ("Bob", NameOf(dc, sbob_, bob_));
    {
      GDEFCORE_Subjects * ds = NULL;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_open(keys_, d.store,
          (const uint8_t *)kTenant, 1, root_, sizeof root_, ring_, NULL, &ds));
      EXPECT_EQ(ann_doc, ExportOf(ds, dc, sann_));
      EXPECT_EQ(ExportOf(subjects_, catalog_, sbob_), ExportOf(ds, dc, sbob_));
      gdefcore_subject_destroy(ds);
    }
    /* Lists, compiled into the backend's query over its current tables. */
    EXPECT_EQ(listed, List(dc, editor_));
    /* Blind lookups: the index a data set does not carry, rebuilt. */
    EXPECT_EQ(std::vector<std::string>({ann_}), Find(dc, "Anne"));
    EXPECT_EQ(std::vector<std::string>({bob_}), Find(dc, "Bob"));
    EXPECT_TRUE(Find(dc, "Ann").empty()) << "an older value is not current";
    EXPECT_TRUE(Find(dc, "Annie").empty()) << "a draft has no blind row";
    EXPECT_EQ(BlindLines(site_, sann_), BlindLines(d.store, sann_));
    EXPECT_EQ(BlindLines(site_, sbob_), BlindLines(d.store, sbob_));
    gdefcore_catalog_bind_subjects(dc, NULL);
    gdefcore_catalog_destroy(dc);
  }
}

/* ---- order --------------------------------------------------------------- */

/* Every step has run when the restore returns, and the tenant may then be
 * served: the key set merged (a person reads), the data imported, the module
 * whose data is older than the one installed recorded at the installed
 * version, the merged ledger replayed (an erasure cut short after its key
 * step, newer than the data set, is finished: the live store's blind rows of
 * the person go and the fragment cache is purged of them), and the blind index
 * rebuilt from what can be decrypted, the erased person staying erased. */
TEST_F(Restore, EveryStepRunsInOrderBeforeTheRestoreReturns) {
  Populate();
  ASSERT_FALSE(HasFatalFailure());
  GDEFCORE_Request * seen = Req(editor_);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_record_subject(seen, sbob_.data(), sbob_.size()));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_put(cache_, seen, "bob", 3, "Bob",
      3));
  Bytes data = Snapshot();
  /* Erased after the data set, and cut short after the key step, as a crash
   * would leave it: the key and the ledger row are gone and written, the
   * blind rows and the fragment are still there. */
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_keystore_erase(keys_, kTenant, 1,
      sbob_.data(), sbob_.size(), 1));
  ASSERT_GT(BlindLines(site_, sbob_), 0u);
  ASSERT_EQ(1u, gdefcore_fragment_count(cache_));
  Bytes keys = Keyset();
  for (int backend : Backends()) {
    SCOPED_TRACE(BackendName(backend));
    Dest d(backend);
    ASSERT_NE(nullptr, d.store);
    d.Install(Blog<2>);
    GDEFCORE_Restore * report = NULL;
    ASSERT_EQ(GDEFCORE_OK, RestoreInto(&d, data, keys, &report))
        << Reason(report);
    /* Migrated: the data was at 1, the module here is at 2. */
    EXPECT_EQ(1u, gdefcore_restore_migrated_count(report));
    gdefcore_restore_free(report);
    EXPECT_EQ("2", Record(d.store, GDEFCORE_MODULE_ENABLED_TYPE, "blog"));
    /* Replayed: the erasure is finished in the live store and the cache. */
    EXPECT_EQ(0u, BlindLines(site_, sbob_));
    EXPECT_EQ(0u, gdefcore_fragment_count(cache_));
    /* Merged and imported: a person with a key reads; rebuilt: their blind
     * rows are back, and the erased person has none and reads erased. */
    GDEFCORE_Catalog * dc = OpenCatalog(d.store);
    ASSERT_NE(nullptr, dc);
    EXPECT_EQ("Anne", NameOf(dc, sann_, ann_));
    EXPECT_EQ(GDEFCORE_SUBJECT_ERASED, NameOf(dc, sbob_, bob_));
    EXPECT_EQ(std::vector<std::string>({ann_}), Find(dc, "Anne"));
    EXPECT_TRUE(Find(dc, "Bob").empty());
    EXPECT_GT(BlindLines(d.store, sann_), 0u);
    EXPECT_EQ(0u, BlindLines(d.store, sbob_));
    gdefcore_catalog_bind_subjects(dc, NULL);
    gdefcore_catalog_destroy(dc);
    /* The next restore finds the cache empty and the live store clean
     * again: put the fragment back for it. */
    ASSERT_EQ(GDEFCORE_OK, gdefcore_fragment_put(cache_, seen, "bob", 3,
        "Bob", 3));
  }
}

/* ---- modules ------------------------------------------------------------- */

/* A data set whose data for a module is at a stored-data schema version newer
 * than the module installed here is refused, in words naming the module and
 * both versions, and nothing is written; so is one needing a module that is
 * not installed here. The controls: the same version here restores, and a
 * newer one here restores and records the module at it. */
TEST_F(Restore, ADataSetNewerThanAModuleHereIsRefusedNamingItsVersions) {
  Populate(Blog<3>);
  ASSERT_FALSE(HasFatalFailure());
  Bytes data = Snapshot();
  Bytes keys = Keyset();
  int backend = Backends()[0];
  {
    Dest d(backend);
    d.Install(Blog<2>);
    GDEFCORE_Restore * report = NULL;
    EXPECT_EQ(GDEFCORE_ERR_UNSUPPORTED, RestoreInto(&d, data, keys, &report));
    std::string why = Reason(report);
    gdefcore_restore_free(report);
    EXPECT_NE(std::string::npos, why.find("module blog")) << why;
    EXPECT_NE(std::string::npos, why.find("version 3")) << why;
    EXPECT_NE(std::string::npos, why.find("version 2")) << why;
    EXPECT_NE(std::string::npos, why.find("nothing was restored")) << why;
    EXPECT_EQ("", Dump(d.store)) << "a refused restore wrote to the tenant";
  }
  {
    Dest d(backend);
    GDEFCORE_Restore * report = NULL;
    EXPECT_EQ(GDEFCORE_ERR_UNSUPPORTED, RestoreInto(&d, data, keys, &report));
    std::string why = Reason(report);
    gdefcore_restore_free(report);
    EXPECT_NE(std::string::npos, why.find("not installed here")) << why;
    EXPECT_NE(std::string::npos, why.find("blog")) << why;
    EXPECT_EQ("", Dump(d.store));
  }
  {
    Dest d(backend);
    d.Install(Blog<3>);
    GDEFCORE_Restore * report = NULL;
    EXPECT_EQ(GDEFCORE_OK, RestoreInto(&d, data, keys, &report))
        << Reason(report);
    EXPECT_EQ(0u, gdefcore_restore_migrated_count(report));
    gdefcore_restore_free(report);
    EXPECT_EQ("3", Record(d.store, GDEFCORE_MODULE_ENABLED_TYPE, "blog"));
  }
  {
    Dest d(backend);
    d.Install(Blog<4>);
    EXPECT_EQ(GDEFCORE_OK, RestoreInto(&d, data, keys, NULL));
    EXPECT_EQ("4", Record(d.store, GDEFCORE_MODULE_ENABLED_TYPE, "blog"));
  }
}

/* A data set whose manifest does not say what its records enable is refused
 * before anything is written: a manifest that leaves an enabled module out,
 * one naming a module the records do not enable, one at another version, and
 * a plain storage snapshot that names no module at all. */
TEST_F(Restore, AManifestThatDisagreesWithItsRecordsIsRefused) {
  Populate();
  ASSERT_FALSE(HasFatalFailure());
  auto exported = [&](const std::vector<GDEFSTOR_SnapshotModule> & mods) {
    uint8_t * zip = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_snapshot_export_tenant(site_, kTenant, 1,
        NULL, 1, NULL, 0, mods.empty() ? NULL : mods.data(), mods.size(), &zip,
        &n));
    Bytes out(reinterpret_cast<const char *>(zip), zip == NULL ? 0 : n);
    gdefstor_bytes_free(NULL, zip);
    return out;
  };
  Bytes keys = Keyset();
  int backend = Backends()[0];
  const std::vector<std::vector<GDEFSTOR_SnapshotModule>> bad = {
      {}, {{"blog", 4, 1}, {"shop", 4, 1}}, {{"blog", 4, 2}}};
  for (const auto & mods : bad) {
    Dest d(backend);
    d.Install(Blog<4>);
    GDEFCORE_Restore * report = NULL;
    EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
        RestoreInto(&d, exported(mods), keys, &report));
    EXPECT_NE(std::string::npos, Reason(report).find("records"))
        << Reason(report);
    gdefcore_restore_free(report);
    EXPECT_EQ("", Dump(d.store));
  }
  {
    Dest d(backend);
    d.Install(Blog<4>);
    EXPECT_EQ(GDEFCORE_OK,
        RestoreInto(&d, exported({{"blog", 4, 1}}), keys, NULL));
  }
  {
    Dest d(backend);
    d.Install(Blog<4>);
    uint8_t * zip = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_snapshot_export_at(site_, kTenant, 1, NULL,
        1, &zip, &n));
    Bytes plain(reinterpret_cast<const char *>(zip), n);
    gdefstor_bytes_free(NULL, zip);
    GDEFCORE_Restore * report = NULL;
    EXPECT_EQ(GDEFCORE_ERR_FORMAT, RestoreInto(&d, plain, keys, &report));
    EXPECT_NE(std::string::npos, Reason(report).find("not the data set"))
        << Reason(report);
    gdefcore_restore_free(report);
    EXPECT_EQ("", Dump(d.store));
  }
}

/* ---- grants -------------------------------------------------------------- */

/* A grant the restored data gives a state is rated like the admin edit,
 * reported in words for its typed confirmation and not applied, whether or
 * not anyone asked for the report; a grant to any other role is restored as
 * it was. The caller applies a held grant with the admin edit and the same
 * confirmation, which nothing else satisfies. */
TEST_F(Restore, ARestoredGrantToAStateIsHeldForItsTypedConfirmation) {
  Populate();
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "anonymous", 9,
      "Read posts", 10, GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
      strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(catalog_, "authenticated", 13,
      "Edit posts", 10, GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
      strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED)));
  /* The control on the source: anyone at all reads a post. */
  ASSERT_EQ("Charlie", ReadTitle(catalog_, std::string(), posts_[0]));
  std::map<std::string, int> source_risk;
  {
    char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Access_Matrix_Row * rows = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_matrix(catalog_, Req(admin), &rows, &n));
    for (size_t i = 0; i < n; i++) {
      source_risk[std::string(rows[i].source, rows[i].source_len) + "|" +
                  std::string(rows[i].permission, rows[i].permission_len)] =
          rows[i].risk;
    }
    gdefcore_access_matrix_free(catalog_, rows, n);
    ASSERT_EQ(1u, source_risk.count("role anonymous|Read posts"));
    ASSERT_EQ(1u, source_risk.count("role authenticated|Edit posts"));
  }
  Bytes data = Snapshot();
  Bytes keys = Keyset();
  for (int backend : Backends()) {
    SCOPED_TRACE(BackendName(backend));
    Dest d(backend);
    d.Install(Blog<1>);
    GDEFCORE_Restore * report = NULL;
    ASSERT_EQ(GDEFCORE_OK, RestoreInto(&d, data, keys, &report))
        << Reason(report);
    ASSERT_EQ(2u, gdefcore_restore_held_count(report));
    bool saw_anonymous = false;
    bool saw_authenticated = false;
    for (size_t i = 0; i < gdefcore_restore_held_count(report); i++) {
      GDEFCORE_Restore_Held h;
      memset(&h, 0, sizeof h);
      h.size = sizeof h;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_restore_held(report, i, &h));
      std::string role(h.role, h.role_len);
      std::string perm(h.permission, h.permission_len);
      std::string confirm(h.confirmation, h.confirmation_len);
      std::string words(h.sentence, h.sentence_len);
      EXPECT_NE(std::string::npos, words.find(perm)) << words;
      EXPECT_NE(std::string::npos, words.find("to " + role)) << words;
      EXPECT_NE(std::string::npos, words.find("not applied")) << words;
      EXPECT_NE(std::string::npos, words.find(confirm)) << words;
      EXPECT_NE(std::string::npos,
          words.find(std::string(gdefcore_access_risk_name(h.risk)) + " risk"))
          << words;
      if (role == "anonymous") {
        saw_anonymous = true;
        EXPECT_EQ("Read posts", perm);
        EXPECT_EQ(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS, confirm);
      } else {
        saw_authenticated = role == "authenticated";
        EXPECT_EQ("Edit posts", perm);
        EXPECT_EQ(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED, confirm);
      }
      /* Rated as the admin's matrix rated the same grant on the source. */
      EXPECT_EQ(source_risk["role " + role + "|" + perm], h.risk) << words;
    }
    EXPECT_TRUE(saw_anonymous && saw_authenticated);
    GDEFCORE_Restore_Held past;
    memset(&past, 0, sizeof past);
    past.size = sizeof past;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_restore_held(report, 2, &past));
    gdefcore_restore_free(report);
    GDEFCORE_Catalog * dc = OpenCatalog(d.store);
    ASSERT_NE(nullptr, dc);
    /* Not applied: nobody without an account reads a post, and the states
     * hold nothing; the editors' grants came back as they were. */
    EXPECT_EQ("<denied>", ReadTitle(dc, std::string(), posts_[0]));
    EXPECT_TRUE(RoleGrants(dc, "anonymous").empty());
    EXPECT_TRUE(RoleGrants(dc, "authenticated").empty());
    EXPECT_EQ(2u, RoleGrants(dc, "editors").size());
    EXPECT_EQ("Charlie", ReadTitle(dc, editor_, posts_[0]));
    /* Applied with the admin edit: the role change's own confirmation is not
     * the state's, and the state's is. */
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_access_grant(dc, "anonymous", 9,
        "Read posts", 10, "core.role", 9));
    EXPECT_EQ("<denied>", ReadTitle(dc, std::string(), posts_[0]));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_grant(dc, "anonymous", 9,
        "Read posts", 10, GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
        strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
    EXPECT_EQ("Charlie", ReadTitle(dc, std::string(), posts_[0]));
    gdefcore_catalog_bind_subjects(dc, NULL);
    gdefcore_catalog_destroy(dc);
  }
  /* Unattended: no report asked for, and still nothing applied. */
  Dest d(Backends()[0]);
  d.Install(Blog<1>);
  ASSERT_EQ(GDEFCORE_OK, RestoreInto(&d, data, keys, NULL));
  GDEFCORE_Catalog * dc = OpenCatalog(d.store);
  ASSERT_NE(nullptr, dc);
  EXPECT_EQ("<denied>", ReadTitle(dc, std::string(), posts_[0]));
  EXPECT_TRUE(RoleGrants(dc, "anonymous").empty());
  gdefcore_catalog_bind_subjects(dc, NULL);
  gdefcore_catalog_destroy(dc);
}

/* ---- the version a module says ------------------------------------------ */

/* An installed module answers the stored-data schema version its manifest
 * says, 0 reading as 1; an unknown module and no host answer nothing; and
 * enabling it records that version as the tenant's (the record a snapshot
 * carries). */
TEST_F(Restore, AModuleSaysItsStoredDataSchemaVersion) {
  uint32_t v = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_module_schema(host_, "blog", 4, &v));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_module_schema(NULL, "blog", 4, &v));
  EnableBlog(Blog<0>);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_schema(host_, "blog", 4, &v));
  EXPECT_EQ(1u, v);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_module_schema(host_, "shop", 4, &v));
  EXPECT_EQ("1", Record(site_, GDEFCORE_MODULE_ENABLED_TYPE, "blog"));
  Dest d(Backends()[0]);
  d.Install(Blog<7>);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_schema(d.host, "blog", 4, &v));
  EXPECT_EQ(7u, v);
}

/* What the Postgres arm needs, else the backends of the default run. */
int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  const char * v = getenv("GDEFCORE_TEST_RESTORE");
  if (v != NULL && strcmp(v, "postgres") == 0) {
#ifndef GDEFCORE_TEST_HAVE_PG
    fprintf(stderr, "the Postgres arm of the restore needs "
                    "defiant-storage-postgres, which builds in its derived "
                    "image (libpq): run make test-restore-postgres there, "
                    "through that library's tools/pg-test.sh\n");
    return 1;
#else
    const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
    if (ci == NULL || ci[0] == '\0') {
      fprintf(stderr, "GDEFSPG_TEST_CONNINFO is not set: the Postgres arm of "
                      "the restore needs a server; run it through "
                      "defiant-storage-postgres's tools/pg-test.sh\n");
      return 1;
    }
#endif
  }
  printf("restore into: ");
  for (int b : Backends()) {
    printf("%s ", BackendName(b));
  }
  printf("\n");
  fflush(stdout);
  return ksrig::RunAll();
}
