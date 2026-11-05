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
 * Story 10's matrix, on the memory backend. One test per row.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage-sqlite/model.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/model_backend.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#include <ghoti.io/defiant-storage/store.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace {

const uint64_t kLife = 3600;

/* The record namespaces of the revocation list (documentation/accounts.md). */
const char kRevokedNs[] = "core.session.revoked";
const char kRevokedExpNs[] = "core.session.revoked.exp";
const char kTenantT[] = {'t'};

size_t CountRecords(GDEFSTOR_Store * store, const char * tenant, const char * ns) {
  GDEFSTOR_RecordList * list = NULL;
  size_t n = 0;
  EXPECT_EQ(GDEFSTOR_OK,
      gdefstor_record_list(store, tenant, 1, ns, strlen(ns), "", 0, 0,
          GDEFSTOR_RECORD_MAX_PAGE, &list));
  n = gdefstor_record_list_count(list);
  gdefstor_record_list_free(list);
  return n;
}

bool HasRecord(GDEFSTOR_Store * store, const char * ns, const std::string & key) {
  int found = 0;
  uint8_t * bytes = NULL;
  size_t n = 0;
  EXPECT_EQ(GDEFSTOR_OK,
      gdefstor_record_get(store, kTenantT, 1, ns, strlen(ns), key.data(),
          key.size(), &found, &bytes, &n, NULL, NULL));
  gdefstor_bytes_free(NULL, bytes);
  return found != 0;
}

/* Put a record straight into the list, as an earlier revocation would have
 * left it, so that a purge has something old to find without waiting for a
 * token to expire. */
void PutRecord(GDEFSTOR_Store * store, const char * ns, const std::string & key,
    const std::string & value) {
  GDEFSTOR_Write * write = NULL;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_begin(store, kTenantT, 1, NULL, &write));
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_record_put(write, ns, strlen(ns), key.data(), key.size(),
          GDEFCORE_SCHEMA_CORE_STAMP, sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1,
          (const uint8_t *)value.data(), value.size()));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(write));
}

std::string SidHex(unsigned n) {
  char buf[40];
  snprintf(buf, sizeof buf, "%032x", n);
  return buf;
}

std::string ExpKey(uint64_t expiry, const std::string & sid) {
  char buf[64];
  snprintf(buf, sizeof buf, "%020llu.", (unsigned long long)expiry);
  return std::string(buf) + sid;
}

/* A store whose revocation list can be made unreadable or unwritable: a
 * SQLite backend with record_get and record_put wrapped. Only the revocation
 * namespace is touched, so every other read and write is the real one. */
struct Faults {
  bool fail_get = false;
  bool fail_put = false;
  GDEFSTOR_Result (*get)(void *, void *, const char *, size_t, const char *,
      size_t, const char *, size_t, const GDEFSTOR_ModelVisitor *) = NULL;
  GDEFSTOR_Result (*put)(void *, void *, const GDEFSTOR_ModelRecord *) = NULL;
};
Faults g_faults;

bool IsRevokedNs(const char * ns, size_t n) {
  return n == strlen(kRevokedNs) && memcmp(ns, kRevokedNs, n) == 0;
}

GDEFSTOR_Result FaultGet(void * ctx, void * txn, const char * tenant,
    size_t tenant_len, const char * ns, size_t ns_len, const char * key,
    size_t key_len, const GDEFSTOR_ModelVisitor * visitor) {
  if (g_faults.fail_get && IsRevokedNs(ns, ns_len)) {
    return GDEFSTOR_ERR_IO;
  }
  return g_faults.get(ctx, txn, tenant, tenant_len, ns, ns_len, key, key_len,
      visitor);
}

GDEFSTOR_Result FaultPut(void * ctx, void * txn, const GDEFSTOR_ModelRecord * r) {
  if (g_faults.fail_put && IsRevokedNs(r->ns, r->ns_len)) {
    return GDEFSTOR_ERR_IO;
  }
  return g_faults.put(ctx, txn, r);
}

/* A directory of SQLite tenant files, removed with it. */
struct TempDir {
  std::string path;
  TempDir() {
    std::error_code ec;
    std::string tmpl =
        (std::filesystem::temp_directory_path(ec) / "gdefcore-account-XXXXXX")
            .string();
    const char * made = mkdtemp(&tmpl[0]);
    EXPECT_NE(made, nullptr);
    if (made != NULL) {
      path = made;
    }
  }
  ~TempDir() {
    std::error_code ec;
    if (!path.empty()) {
      std::filesystem::remove_all(path, ec);
    }
  }
};

GDEFSTOR_Store * OpenSqlite(const std::string & dir, bool faults) {
  GDEFSSQLITE_ModelOptions o;
  GDEFSTOR_ModelBackend mb;
  GDEFSTOR_Store * store = NULL;
  gdefssqlite_model_options_default(&o);
  o.synchronous = GDEFSSQLITE_SYNC_OFF;
  EXPECT_EQ(GDEFSSQLITE_OK,
      gdefssqlite_model_backend(dir.c_str(), &o, NULL, &mb));
  if (faults) {
    g_faults.get = mb.record_get;
    g_faults.put = mb.record_put;
    mb.record_get = FaultGet;
    mb.record_put = FaultPut;
  }
  if (gdefstor_store_open(&mb, NULL, NULL, &store) != GDEFSTOR_OK) {
    mb.destroy(mb.ctx);
    return NULL;
  }
  return store;
}

int HexNibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

std::string HexDecode(const std::string & hex) {
  std::string out;
  size_t i;
  if (hex.size() % 2 != 0) {
    return out;
  }
  out.resize(hex.size() / 2);
  for (i = 0; i < hex.size(); i += 2) {
    int hi = HexNibble(hex[i]);
    int lo = HexNibble(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return std::string();
    }
    out[i / 2] = (char)((hi << 4) | lo);
  }
  return out;
}

class Account : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Request * request_;
  GDEFCORE_Keyring * keyring_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t other_root_[GDEFCORE_ACCOUNT_ROOT_LEN];

  void SetUp() override {
    const uint8_t tenant[] = {'t'};
    store_ = NULL;
    catalog_ = NULL;
    request_ = NULL;
    keyring_ = NULL;
    memset(root_, 0x42, sizeof root_);
    memset(other_root_, 0x24, sizeof other_root_);
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

  std::string Field(const char * id, const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    std::string value;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id,
            strlen(id), "en", 2, field, strlen(field), &texts, &lens, &count));
    if (count > 0 && texts != NULL && lens != NULL) {
      value.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return value;
  }

  uint64_t Epoch(const char * id) {
    uint64_t epoch = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_epoch(catalog_, id, strlen(id), &epoch));
    return epoch;
  }

  std::string Login(const char * username, const char * password) {
    char * token = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_login(catalog_, keyring_, root_, sizeof root_,
            username, strlen(username), password, strlen(password), kLife,
            &token, &n));
    std::string out(token == NULL ? "" : token, n);
    gdefcore_text_free(catalog_, token);
    return out;
  }

  const char * Principal(size_t * out_len) {
    return gdefcore_request_principal(request_, out_len);
  }

  /*
   * The positive control. A token that is live names its principal. Every
   * revocation test starts here, so that "anonymous afterwards" cannot be a
   * check that has always answered anonymous.
   */
  void ExpectLive(const std::string & token, const char * principal) {
    size_t n = 0;
    const char * who = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_check(catalog_, request_, keyring_, root_,
            sizeof root_, token.data(), token.size()));
    who = Principal(&n);
    ASSERT_NE(who, nullptr);
    EXPECT_EQ(std::string(principal), std::string(who, n));
  }

  /*
   * The request starts as someone else, so a check that left the request
   * alone would read as a failure here rather than as anonymous.
   */
  void ExpectAnonymous(const std::string & token, const char * stand_in) {
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request_, stand_in, strlen(stand_in)));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_check(catalog_, request_, keyring_, root_,
            sizeof root_, token.data(), token.size()));
    EXPECT_EQ(Principal(&n), nullptr);
  }

  GDEFCORE_Result Revoke(const std::string & token) {
    return gdefcore_account_session_revoke(catalog_, request_, keyring_, root_,
        sizeof root_, token.data(), token.size());
  }

  size_t Revoked() { return CountRecords(store_, kTenantT, kRevokedNs); }
  size_t RevokedByExpiry() {
    return CountRecords(store_, kTenantT, kRevokedExpNs);
  }

  /* Replace the fixture's memory store (and the catalog over it) with
   * @p store. The request and the keyring stay: they are tenant `t` and the
   * root key, which is all a session needs to be the same one. */
  void UseStore(GDEFSTOR_Store * store) {
    const uint8_t tenant[] = {'t'};
    gdefcore_catalog_destroy(catalog_);
    catalog_ = NULL;
    gdefstor_store_destroy(store_);
    store_ = store;
    ASSERT_NE(store_, nullptr);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, tenant, 1, NULL, NULL, &catalog_));
  }

  /* A signed-in account with a role, so that "live" means something. */
  void MakeAccount(const char * name, std::string * principal, std::string * id) {
    char p[GDEFCORE_PUBLIC_ID_LEN + 1];
    char i[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_create(catalog_, keyring_, root_, sizeof root_, name,
            strlen(name), "secret", 6, p, i));
    *principal = p;
    *id = i;
  }
};

}  // namespace

TEST_F(Account, AdminLogin) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * wrong_token = (char *)0x1;
  char * missing_token = (char *)0x1;
  size_t wrong_len = 99;
  size_t missing_len = 99;
  size_t n = 0;
  const char * who = NULL;
  const char * acting = NULL;
  GDEFCORE_Result wrong;
  GDEFCORE_Result missing;
  std::string token;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  token = Login("ada", "secret");
  EXPECT_FALSE(token.empty());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_acting_principal(request_, admin, strlen(admin)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
          token.data(), token.size()));
  who = Principal(&n);
  ASSERT_NE(who, nullptr);
  EXPECT_EQ(std::string(admin), std::string(who, n));
  acting = gdefcore_request_acting_principal(request_, &n);
  EXPECT_EQ(acting, nullptr);
  wrong = gdefcore_account_login(catalog_, keyring_, root_, sizeof root_,
      "ada", 3, "nope", 4, kLife, &wrong_token, &wrong_len);
  missing = gdefcore_account_login(catalog_, keyring_, root_, sizeof root_,
      "nobody", 6, "nope", 4, kLife, &missing_token, &missing_len);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, wrong);
  EXPECT_EQ(wrong, missing);
  EXPECT_EQ((char *)0x1, wrong_token);
  EXPECT_EQ((char *)0x1, missing_token);
  EXPECT_EQ(99u, wrong_len);
  EXPECT_EQ(99u, missing_len);
}

TEST_F(Account, EmptyPassword) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** ids = NULL;
  size_t count = 0;
  std::string stored;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "", 0, id));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.account", strlen("core.account"),
          &ids, &count));
  EXPECT_EQ(0u, count);
  gdefcore_ids_free(catalog_, ids, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "x", 1, id));
  stored = Field(id, "password");
  EXPECT_FALSE(stored.empty());
}

TEST_F(Account, Ciphertext) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const char * password = "correct horse";
  std::string stored;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, password, strlen(password), id));
  stored = Field(id, "password");
  EXPECT_EQ(std::string::npos, stored.find("$argon2"));
  EXPECT_NE(stored, password);
  EXPECT_FALSE(stored.empty());
  {
    std::string decoded = HexDecode(stored);
    EXPECT_FALSE(decoded.empty());
    EXPECT_EQ(std::string::npos, decoded.find("$argon2"));
    EXPECT_NE(decoded, password);
  }
  EXPECT_FALSE(Login("ada", password).empty());
}

TEST_F(Account, OtherTenant) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const uint8_t other[] = {'u'};
  GDEFCORE_Catalog * catalog_b = NULL;
  GDEFCORE_Request * request_b = NULL;
  std::string token;
  size_t n = 99;
  const char * who = (const char *)0x1;
  GDEFCORE_Result rc;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  token = Login("ada", "secret");
  ASSERT_FALSE(token.empty());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store_, other, 1, NULL, NULL, &catalog_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create(other, 1, 0, 0, NULL, &request_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request_b, admin, strlen(admin)));
  rc = gdefcore_account_check(catalog_b, request_b, keyring_, root_,
      sizeof root_, token.data(), token.size());
  who = gdefcore_request_principal(request_b, &n);
  gdefcore_request_destroy(request_b);
  gdefcore_catalog_destroy(catalog_b);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  EXPECT_EQ(who, nullptr);

  /*
   * The same session under a tenant that holds a copy of every row, the
   * account, its principal and its epoch included. Nothing is different
   * but the tenant bytes, so the tenant in the associated data is the only
   * thing standing in the way. The empty tenant above is refused for want of
   * an account, whatever the token says.
   */
  {
    uint8_t * zip = NULL;
    size_t zip_len = 0;
    const char tenant_t[] = {'t'};
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_export(store_, tenant_t, 1, NULL, &zip, &zip_len));
    ASSERT_EQ(GDEFSTOR_OK,
        gdefstor_snapshot_import(store_, "v", 1, zip, zip_len, NULL));
    gdefstor_bytes_free(NULL, zip);
  }
  {
    const uint8_t clone[] = {'v'};
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, clone, 1, NULL, NULL, &catalog_b));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create(clone, 1, 0, 0, NULL, &request_b));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request_b, admin, strlen(admin)));
    /* The control: the clone holds the account and its epoch. */
    {
      uint64_t copied = 0;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_account_epoch(catalog_b, id, strlen(id), &copied));
      EXPECT_EQ(Epoch(id), copied);
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_set_principal(request_b, admin, strlen(admin)));
    rc = gdefcore_account_check(catalog_b, request_b, keyring_, root_,
        sizeof root_, token.data(), token.size());
    who = gdefcore_request_principal(request_b, &n);
    gdefcore_request_destroy(request_b);
    gdefcore_catalog_destroy(catalog_b);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
    EXPECT_EQ(who, nullptr);
  }
}

TEST_F(Account, OtherKey) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  token = Login("ada", "secret");
  ASSERT_FALSE(token.empty());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request_, admin, strlen(admin)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_check(catalog_, request_, keyring_, other_root_,
          sizeof other_root_, token.data(), token.size()));
  EXPECT_EQ(Principal(&n), nullptr);
}

TEST_F(Account, Epoch) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string before;
  std::string token;
  uint64_t epoch = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  EXPECT_EQ(1u, Epoch(id));
  before = Field(id, "password");
  token = Login("ada", "secret");
  ExpectLive(token, admin);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_password(catalog_, keyring_, root_, sizeof root_, id,
          strlen(id), "next", 4, "nope", 4));
  EXPECT_EQ(1u, Epoch(id));
  EXPECT_EQ(before, Field(id, "password"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_password(catalog_, keyring_, root_, sizeof root_, id,
          strlen(id), "next", 4, "ada", 3));
  epoch = Epoch(id);
  EXPECT_GT(epoch, 1u);
  EXPECT_NE(before, Field(id, "password"));
  ExpectAnonymous(token, admin);
  EXPECT_FALSE(Login("ada", "next").empty());
  {
    char * old = (char *)0x1;
    size_t old_n = 99;
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_account_login(catalog_, keyring_, root_, sizeof root_, "ada",
            3, "secret", 6, kLife, &old, &old_n));
    EXPECT_EQ((char *)0x1, old);
    EXPECT_EQ(99u, old_n);
  }
}

TEST_F(Account, LogOut) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  token = Login("ada", "secret");
  ExpectLive(token, admin);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_logout_everywhere(catalog_, id, strlen(id), "nope", 4));
  EXPECT_EQ(1u, Epoch(id));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_logout_everywhere(catalog_, id, strlen(id), "ada", 3));
  EXPECT_GT(Epoch(id), 1u);
  ExpectAnonymous(token, admin);
}

TEST_F(Account, Demotion) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** roles = NULL;
  size_t count = 0;
  std::string token;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_create(catalog_, keyring_, root_, sizeof root_, "ada",
          3, "secret", 6, principal, id));
  EXPECT_NE(std::string(admin), std::string(principal));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_create(catalog_, "editor", 6, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, principal, strlen(principal),
          "editor", 6));
  token = Login("ada", "secret");
  ExpectLive(token, principal);
  EXPECT_EQ(1u, Epoch(id));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_remove_role(catalog_, id, strlen(id), "editor", 6));
  EXPECT_GT(Epoch(id), 1u);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_roles(catalog_, principal, strlen(principal),
          &roles, &count));
  EXPECT_EQ(0u, count);
  gdefcore_access_free(catalog_, roles, count);
  ExpectAnonymous(token, principal);
}

TEST_F(Account, LastIdentifier) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  EXPECT_EQ(1u, Epoch(id));
  token = Login("ada", "secret");
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_remove_identifier(catalog_, id, strlen(id), "ada", 3));
  EXPECT_EQ(1u, Epoch(id));
  EXPECT_EQ("ada", Field(id, "username"));
  ExpectLive(token, admin);
}

TEST_F(Account, Revert) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string original;
  std::string token;
  uint64_t raised = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  original = Field(id, "password");
  token = Login("ada", "secret");
  ExpectLive(token, admin);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_password(catalog_, keyring_, root_, sizeof root_, id,
          strlen(id), "next", 4, "ada", 3));
  raised = Epoch(id);
  EXPECT_GT(raised, 1u);
  EXPECT_NE(original, Field(id, "password"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_account_revert(catalog_, id, strlen(id)));
  EXPECT_EQ(raised, Epoch(id));
  EXPECT_EQ(original, Field(id, "password"));
  ExpectAnonymous(token, admin);
}

/*
 * The session-revocation gate. Every trigger the library offers moves the
 * security epoch, and the next request on an older token is anonymous. A
 * fresh login after the trigger is live again, which is the control that
 * says the check still lets a good session through.
 *
 * Triggers with no function in this library, so no test here: account
 * recovery, a revoked delegation, and erasure of a subject. Removing a login
 * identifier is refused (the only identifier is the last one), so its test is
 * that the refusal leaves the session alone.
 */
TEST_F(Account, Revocation) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string first;
  std::string second;
  std::string third;
  std::string fourth;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_create(catalog_, keyring_, root_, sizeof root_, "ada", 3,
          "secret", 6, principal, id));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_role_create(catalog_, "editor", 6, NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(catalog_, principal, strlen(principal),
          "editor", 6));

  /* Password change. */
  first = Login("ada", "secret");
  ExpectLive(first, principal);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_password(catalog_, keyring_, root_, sizeof root_, id,
          strlen(id), "next", 4, "ada", 3));
  EXPECT_GT(Epoch(id), 1u);
  ExpectAnonymous(first, admin);

  /* Log out everywhere. */
  second = Login("ada", "next");
  ExpectLive(second, principal);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_logout_everywhere(catalog_, id, strlen(id), "ada", 3));
  ExpectAnonymous(second, admin);
  ExpectAnonymous(first, admin);

  /* Demotion. */
  third = Login("ada", "next");
  ExpectLive(third, principal);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_remove_role(catalog_, id, strlen(id), "editor", 6));
  ExpectAnonymous(third, admin);

  /* Removing the only login identifier is refused and ends nothing. */
  fourth = Login("ada", "next");
  ExpectLive(fourth, principal);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_remove_identifier(catalog_, id, strlen(id), "ada", 3));
  ExpectLive(fourth, principal);
  ExpectAnonymous(third, admin);
}

TEST_F(Account, ArgonCosts) {
  EXPECT_EQ(19456u, GDEFCORE_ACCOUNT_ARGON_MEMORY);
  EXPECT_EQ(2u, GDEFCORE_ACCOUNT_ARGON_PASSES);
  EXPECT_EQ(1u, GDEFCORE_ACCOUNT_ARGON_LANES);
  EXPECT_EQ(32u, GDEFCORE_ACCOUNT_ARGON_TAG);
}

TEST_F(Account, Lifetime) {
  char * token = (char *)0x1;
  size_t n = 99;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_login(catalog_, keyring_, root_, sizeof root_, "ada", 3,
          "secret", 6, 0, &token, &n));
  EXPECT_EQ((char *)0x1, token);
  EXPECT_EQ(99u, n);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_login(catalog_, keyring_, root_, sizeof root_, "ada", 3,
          "secret", 6, GDEFCORE_ACCOUNT_SESSION_MAX + 1, &token, &n));
  EXPECT_EQ((char *)0x1, token);
  EXPECT_EQ(99u, n);
}

TEST_F(Account, Expired) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * token = NULL;
  size_t n = 0;
  size_t who = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_login(catalog_, keyring_, root_, sizeof root_, "ada", 3,
          "secret", 6, 1, &token, &n));
  ASSERT_NE(token, nullptr);
  sleep(1);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request_, admin, strlen(admin)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
          token, n));
  EXPECT_EQ(Principal(&who), nullptr);
  gdefcore_text_free(catalog_, token);
}

TEST_F(Account, Purpose) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  token = Login("ada", "secret");
  ASSERT_GE(token.size(), 11u);
  token.replace(4, 7, 7, 'X');
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request_, admin, strlen(admin)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
          token.data(), token.size()));
  EXPECT_EQ(Principal(&n), nullptr);
}

TEST_F(Account, DuplicateUsername) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char again[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** ids = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, "secret", 6, id));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_create(catalog_, keyring_, root_, sizeof root_, "ada",
          3, "other", 5, principal, again));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.account", strlen("core.account"),
          &ids, &count));
  EXPECT_EQ(1u, count);
  gdefcore_ids_free(catalog_, ids, count);
}

TEST_F(Account, MissingRole) {
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string token;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_create(catalog_, keyring_, root_, sizeof root_, "ada",
          3, "secret", 6, principal, id));
  token = Login("ada", "secret");
  EXPECT_EQ(1u, Epoch(id));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_remove_role(catalog_, id, strlen(id), "editor", 6));
  EXPECT_EQ(1u, Epoch(id));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
          token.data(), token.size()));
  EXPECT_NE(Principal(&n), nullptr);
}

TEST_F(Account, PasswordLength) {
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** ids = NULL;
  size_t count = 0;
  std::string long_password(1024, 'p');
  std::string too_long(1025, 'q');
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  EXPECT_EQ(GDEFCORE_ERR_LIMIT,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, too_long.data(), too_long.size(), id));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_ids(catalog_, "core.account", strlen("core.account"),
          &ids, &count));
  EXPECT_EQ(0u, count);
  gdefcore_ids_free(catalog_, ids, count);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(catalog_, keyring_, root_, sizeof root_, admin,
          strlen(admin), "ada", 3, long_password.data(), long_password.size(),
          id));
  EXPECT_FALSE(Login("ada", long_password.c_str()).empty());
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

/* ---- one session at a time (story 17) ------------------------------------ */

/* Gate 1. Two live sessions of one account: revoking one refuses that token
 * and leaves the other, and a third sign-in of a different account, alone. */
TEST_F(Account, RevokeOneOfTwoLeavesTheOtherLive) {
  std::string principal, id, other_principal, other_id;
  std::string first, second, third;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  MakeAccount("ada", &principal, &id);
  MakeAccount("bob", &other_principal, &other_id);
  first = Login("ada", "secret");
  second = Login("ada", "secret");
  third = Login("bob", "secret");
  EXPECT_NE(first, second) << "two logins made the same token";
  ExpectLive(first, principal.c_str());
  ExpectLive(second, principal.c_str());
  ExpectLive(third, other_principal.c_str());
  ASSERT_EQ(GDEFCORE_OK, Revoke(first));
  ExpectAnonymous(first, admin);
  ExpectLive(second, principal.c_str());
  ExpectLive(third, other_principal.c_str());
  /* The same token stays refused on every later request. */
  ExpectAnonymous(first, admin);
  EXPECT_EQ(1u, Revoked());
}

/* Gate 2. Revoking twice succeeds and changes nothing: not the list, not the
 * epoch, not another sign-in. */
TEST_F(Account, RevokeIsIdempotentAndNeverRaisesTheEpoch) {
  std::string principal, id;
  std::string first, second;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t before;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  MakeAccount("ada", &principal, &id);
  first = Login("ada", "secret");
  second = Login("ada", "secret");
  before = Epoch(id.c_str());
  ASSERT_EQ(GDEFCORE_OK, Revoke(first));
  EXPECT_EQ(before, Epoch(id.c_str())) << "a revoke raised the epoch";
  EXPECT_EQ(1u, Revoked());
  EXPECT_EQ(1u, RevokedByExpiry());
  ASSERT_EQ(GDEFCORE_OK, Revoke(first));
  EXPECT_EQ(before, Epoch(id.c_str()));
  EXPECT_EQ(1u, Revoked());
  EXPECT_EQ(1u, RevokedByExpiry());
  ExpectAnonymous(first, admin);
  ExpectLive(second, principal.c_str());
}

/* Gate 3. What check refuses, revoke refuses, and writes nothing. The control
 * is the same call on a good token, which writes its one record. */
TEST_F(Account, RevokeRefusesABadTokenAndWritesNothing) {
  std::string principal, id;
  std::string token, damaged;
  const uint8_t other_tenant[] = {'u'};
  GDEFCORE_Catalog * catalog_b = NULL;
  GDEFCORE_Request * request_b = NULL;
  char * short_life = NULL;
  size_t short_len = 0;
  MakeAccount("bob", &principal, &id);
  token = Login("bob", "secret");
  ASSERT_FALSE(token.empty());

  /* A flipped tag byte, and a flipped ciphertext byte. */
  damaged = token;
  damaged[damaged.size() - 1] ^= 0x01;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Revoke(damaged));
  damaged = token;
  damaged[damaged.size() / 2] ^= 0x80;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Revoke(damaged));
  /* Too short, empty, a token under another root key. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Revoke(token.substr(0, token.size() - 1)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Revoke(std::string()));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_session_revoke(catalog_, request_, keyring_, other_root_,
          sizeof other_root_, token.data(), token.size()));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_session_revoke(catalog_, request_, keyring_, root_,
          sizeof root_, NULL, 0));
  /* A token of another tenant: refused by the tenant in its associated data,
   * and by a request that is not for the catalog's tenant. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store_, other_tenant, 1, NULL, NULL, &catalog_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create(other_tenant, 1, 0, 0, NULL, &request_b));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_session_revoke(catalog_b, request_b, keyring_, root_,
          sizeof root_, token.data(), token.size()));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_session_revoke(catalog_, request_b, keyring_, root_,
          sizeof root_, token.data(), token.size()));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_session_revoke(catalog_b, request_, keyring_, root_,
          sizeof root_, token.data(), token.size()));
  EXPECT_EQ(0u, CountRecords(store_, "u", kRevokedNs));
  gdefcore_request_destroy(request_b);
  gdefcore_catalog_destroy(catalog_b);
  /* An expired token. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_login(catalog_, keyring_, root_, sizeof root_, "bob", 3,
          "secret", 6, 1, &short_life, &short_len));
  sleep(1);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Revoke(std::string(short_life, short_len)));
  gdefcore_text_free(catalog_, short_life);

  EXPECT_EQ(0u, Revoked()) << "a refused revoke wrote a record";
  EXPECT_EQ(0u, RevokedByExpiry());
  /* The control: the good token is revoked, once. */
  ExpectLive(token, principal.c_str());
  EXPECT_EQ(GDEFCORE_OK, Revoke(token));
  EXPECT_EQ(1u, Revoked());
  EXPECT_EQ(1u, RevokedByExpiry());
}

/* A session an older epoch has already ended is as ended as a revocation
 * would make it: revoking it succeeds and records nothing. */
TEST_F(Account, RevokingASessionAnEpochEndedRecordsNothing) {
  std::string principal, id;
  std::string old_token;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  MakeAccount("ada", &principal, &id);
  old_token = Login("ada", "secret");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_logout_everywhere(catalog_, id.c_str(), id.size(), "ada",
          3));
  ExpectAnonymous(old_token, admin);
  EXPECT_EQ(GDEFCORE_OK, Revoke(old_token));
  EXPECT_EQ(0u, Revoked());
  EXPECT_EQ(0u, RevokedByExpiry());
}

/* Gate 7. Logging out everywhere still ends every session of the account,
 * revoked or not, and a session started afterwards is a new one. */
TEST_F(Account, LogOutEverywhereStillEndsEverySession) {
  std::string principal, id;
  std::string first, second, later;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t before;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  MakeAccount("ada", &principal, &id);
  first = Login("ada", "secret");
  second = Login("ada", "secret");
  ASSERT_EQ(GDEFCORE_OK, Revoke(first));
  ExpectLive(second, principal.c_str());
  before = Epoch(id.c_str());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_logout_everywhere(catalog_, id.c_str(), id.size(), "ada",
          3));
  EXPECT_EQ(before + 1, Epoch(id.c_str()));
  ExpectAnonymous(first, admin);
  ExpectAnonymous(second, admin);
  later = Login("ada", "secret");
  ExpectLive(later, principal.c_str());
  ExpectAnonymous(first, admin);
}

/* Gate 4, restart half. The list is in the tenant's storage, not in the
 * process: a store closed and opened again over the same files still refuses
 * the revoked token and still accepts the other one. */
TEST_F(Account, ARevokedSessionStaysRevokedAcrossARestart) {
  TempDir dir;
  std::string principal, id;
  std::string first, second;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_FALSE(dir.path.empty());
  UseStore(OpenSqlite(dir.path, false));
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  MakeAccount("ada", &principal, &id);
  first = Login("ada", "secret");
  second = Login("ada", "secret");
  ASSERT_EQ(GDEFCORE_OK, Revoke(first));
  ExpectAnonymous(first, admin);
  ExpectLive(second, principal.c_str());
  UseStore(OpenSqlite(dir.path, false));
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(1u, Revoked());
  ExpectAnonymous(first, admin);
  ExpectLive(second, principal.c_str());
}

/* Gate 5. Fail closed. With the revocation list unreadable, a token that was
 * live is refused (an error, no principal), and so is the revoked one; with
 * it readable again the live one passes. Revoking when the list cannot be
 * written is an error, and the session is still live afterwards, so a caller
 * that sees the error knows not to say it signed out. */
TEST_F(Account, AnUnreadableRevocationListRefusesEveryToken) {
  TempDir dir;
  std::string principal, id;
  std::string revoked, live;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t n = 0;
  ASSERT_FALSE(dir.path.empty());
  g_faults = Faults();
  UseStore(OpenSqlite(dir.path, true));
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog_, admin));
  MakeAccount("ada", &principal, &id);
  revoked = Login("ada", "secret");
  live = Login("ada", "secret");
  ASSERT_EQ(GDEFCORE_OK, Revoke(revoked));
  /* Controls: with the list readable the live token passes, the revoked
   * does not. */
  ExpectLive(live, principal.c_str());
  ExpectAnonymous(revoked, admin);

  g_faults.fail_get = true;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request_, admin, strlen(admin)));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
          live.data(), live.size()));
  EXPECT_EQ(Principal(&n), nullptr) << "an unreadable list let a token in";
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_set_principal(request_, admin, strlen(admin)));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_account_check(catalog_, request_, keyring_, root_, sizeof root_,
          revoked.data(), revoked.size()));
  EXPECT_EQ(Principal(&n), nullptr) << "an unreadable list let a revoked token in";
  g_faults.fail_get = false;
  ExpectLive(live, principal.c_str());

  g_faults.fail_put = true;
  EXPECT_NE(GDEFCORE_OK, Revoke(live));
  g_faults.fail_put = false;
  EXPECT_EQ(1u, Revoked()) << "a failed revoke left a record";
  EXPECT_EQ(1u, RevokedByExpiry());
  ExpectLive(live, principal.c_str());
  g_faults = Faults();
}

/* Gate 6. The list stays bounded. Each revocation reads at most one page of
 * the oldest expiries and drops the ones whose tokens expired (and have been
 * expired for the grace); a live one, one inside the grace, and everything
 * after them stay. Records are put in as an earlier revocation left them, a
 * day old, because a purge cannot be seen by waiting out a real token. */
TEST_F(Account, ExpiredRevocationsArePurgedAndLiveOnesStay) {
  std::string principal, id;
  std::string t1, t2, t3;
  const uint64_t now = (uint64_t)time(NULL);
  const unsigned kOld = 100;
  const unsigned kLive = 10;
  const std::string recent = SidHex(5000);
  unsigned i;
  MakeAccount("ada", &principal, &id);
  for (i = 0; i < kOld; i++) {
    uint64_t expiry = now - 86400 + i;
    PutRecord(store_, kRevokedNs, SidHex(i), std::to_string(expiry));
    PutRecord(store_, kRevokedExpNs, ExpKey(expiry, SidHex(i)), "");
  }
  /* Expired a moment ago: inside the grace, so it must stay. */
  PutRecord(store_, kRevokedNs, recent, std::to_string(now - 10));
  PutRecord(store_, kRevokedExpNs, ExpKey(now - 10, recent), "");
  for (i = 0; i < kLive; i++) {
    uint64_t expiry = now + 3600 + i;
    PutRecord(store_, kRevokedNs, SidHex(1000 + i), std::to_string(expiry));
    PutRecord(store_, kRevokedExpNs, ExpKey(expiry, SidHex(1000 + i)), "");
  }
  /* A key that cannot be one of ours sorts first and goes with the dead. */
  PutRecord(store_, kRevokedExpNs, "0-not-an-index-key", "");
  ASSERT_EQ(kOld + 1 + kLive, Revoked());
  ASSERT_EQ(kOld + 1 + kLive + 1, RevokedByExpiry());

  t1 = Login("ada", "secret");
  ASSERT_EQ(GDEFCORE_OK, Revoke(t1));
  /* One page of 64 index entries went (the stray key and the 63 oldest, whose
   * records went with them) and the new session came. */
  EXPECT_EQ(kOld + 1 + kLive - 63u + 1u, Revoked());
  EXPECT_EQ(kOld + 1 + kLive + 1 - 64u + 1u, RevokedByExpiry());
  t2 = Login("ada", "secret");
  ASSERT_EQ(GDEFCORE_OK, Revoke(t2));
  t3 = Login("ada", "secret");
  ASSERT_EQ(GDEFCORE_OK, Revoke(t3));
  /* Every dead record is gone; the recent one, the live ones and the three
   * real sessions are all that is left. */
  EXPECT_EQ(1u + kLive + 3u, Revoked());
  EXPECT_EQ(1u + kLive + 3u, RevokedByExpiry());
  for (i = 0; i < kOld; i++) {
    EXPECT_FALSE(HasRecord(store_, kRevokedNs, SidHex(i)));
  }
  EXPECT_TRUE(HasRecord(store_, kRevokedNs, recent));
  for (i = 0; i < kLive; i++) {
    EXPECT_TRUE(HasRecord(store_, kRevokedNs, SidHex(1000 + i)));
  }
}
