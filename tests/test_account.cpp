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
#include <ghoti.io/defiant-storage/snapshot.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

namespace {

const uint64_t kLife = 3600;

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
