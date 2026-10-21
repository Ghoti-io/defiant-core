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
 * Story 11's matrix, on the memory backend. One test per row.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif
#include "portable.h"
#include <unistd.h>

#include <string>

namespace {

const uint64_t kLife = 3600;

const char * Plant() {
  const char * plant = getenv("GHOTI_INST_PLANT");
  return plant == NULL ? "" : plant;
}

void ClearEnv() {
  unsetenv("DEFIANT_ROLES");
  unsetenv("DEFIANT_STORE");
  unsetenv("DEFIANT_LISTEN");
  unsetenv("DEFIANT_TRUSTED_PROXIES");
  unsetenv("DEFIANT_SECRET");
  unsetenv("DEFIANT_SECRET_FILE");
  unsetenv("DEFIANT_CONFIG");
}

std::string HexEncode(const uint8_t * raw, size_t n) {
  static const char kHex[] = "0123456789abcdef";
  std::string out(n * 2, '0');
  size_t i;
  for (i = 0; i < n; i++) {
    out[i * 2] = kHex[raw[i] >> 4];
    out[i * 2 + 1] = kHex[raw[i] & 0x0f];
  }
  return out;
}

bool WriteBytes(const std::string & path, const void * bytes, size_t n) {
  FILE * fp = fopen(path.c_str(), "wb");
  if (fp == NULL) {
    return false;
  }
  if (fwrite(bytes, 1, n, fp) != n) {
    fclose(fp);
    return false;
  }
  return fclose(fp) == 0;
}

bool WriteText(const std::string & path, const std::string & text) {
  return WriteBytes(path, text.data(), text.size());
}

std::string RunConfig(const std::string & path, char * const * envp) {
#ifdef _WIN32
  /* No fork or execve: the caller skips the test. */
  (void)path;
  (void)envp;
  return std::string();
#else
  int fds[2];
  pid_t pid;
  std::string out;
  char buf[256];
  ssize_t n;
  int status = 0;
  char * argv[2];
  if (pipe(fds) != 0) {
    return out;
  }
  pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return out;
  }
  if (pid == 0) {
    if (dup2(fds[1], 1) < 0) {
      _exit(127);
    }
    close(fds[0]);
    close(fds[1]);
    argv[0] = const_cast<char *>(path.c_str());
    argv[1] = NULL;
    execve(path.c_str(), argv, envp);
    _exit(127);
  }
  close(fds[1]);
  while ((n = read(fds[0], buf, sizeof buf)) > 0) {
    out.append(buf, (size_t)n);
  }
  close(fds[0]);
  if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    return std::string();
  }
  return out;
#endif
}

class Inst : public ::testing::Test {
 protected:
  GDEFSTOR_Store * registry_;
  GDEFSTOR_Store * site_;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  char tmp_[64];

  void SetUp() override {
    registry_ = NULL;
    site_ = NULL;
    memset(root_, 0x42, sizeof root_);
    memset(tmp_, 0, sizeof tmp_);
    ClearEnv();
    ASSERT_EQ(GDEFSMEMORY_OK,
        gdefsmemory_store_create(NULL, NULL, &registry_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &site_));
    memcpy(tmp_, "/tmp/gdefcore-inst-XXXXXX", 26);
    ASSERT_NE(mkdtemp(tmp_), nullptr);
  }

  void TearDown() override {
    ClearEnv();
    DIR * dir;
    struct dirent * ent;
    gdefstor_store_destroy(site_);
    gdefstor_store_destroy(registry_);
    dir = opendir(tmp_);
    if (dir != NULL) {
      while ((ent = readdir(dir)) != NULL) {
        std::string path;
        if (ent->d_name[0] == '.') {
          continue;
        }
        path = std::string(tmp_) + "/" + ent->d_name;
        unlink(path.c_str());
      }
      closedir(dir);
      rmdir(tmp_);
    }
  }

  std::string Tmp(const char * name) {
    return std::string(tmp_) + "/" + name;
  }

  void SaveNote(GDEFCORE_Catalog * catalog, const char * title, char * out_id) {
    GDEFCORE_Field field;
    GDEFCORE_Value value;
    const char * texts[1];
    size_t lens[1];
    GDEFCORE_Changeset * changeset = NULL;
    memset(&field, 0, sizeof field);
    field.size = sizeof field;
    field.name = "title";
    field.name_len = 5;
    field.required = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog, "site.note", 9, GDEFCORE_TYPE_CONTENT,
            &field, 1));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog, "site.note", 9, out_id, NULL));
    texts[0] = title;
    lens[0] = strlen(title);
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "title";
    value.field_len = 5;
    value.texts = texts;
    value.text_lens = lens;
    value.count = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog, NULL, 0, &changeset));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(changeset, out_id, strlen(out_id), "en", 2, &value,
            1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
    gdefcore_changeset_destroy(changeset);
  }

  std::string Title(GDEFCORE_Catalog * catalog, const char * id) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    std::string value;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
            strlen(id), "en", 2, "title", 5, &texts, &lens, &count));
    if (count > 0 && texts != NULL && lens != NULL && texts[0] != NULL) {
      value.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog, texts, lens, count);
    return value;
  }

  size_t NoteCount(GDEFCORE_Catalog * catalog) {
    char ** ids = NULL;
    size_t count = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(catalog, "site.note", 9, &ids, &count));
    gdefcore_ids_free(catalog, ids, count);
    return count;
  }

  std::string Login(GDEFCORE_Catalog * catalog, GDEFCORE_Keyring * keyring) {
    char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * token = NULL;
    size_t n = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog, admin));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_bind(catalog, keyring, root_, sizeof root_, admin,
            strlen(admin), "ada", 3, "secret", 6, id));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_login(catalog, keyring, root_, sizeof root_, "ada", 3,
            "secret", 6, kLife, &token, &n));
    if (token != NULL) {
      out.assign(token, n);
    }
    gdefcore_text_free(catalog, token);
    return out;
  }
};

}  // namespace

TEST_F(Inst, DefaultTenant) {
  GDEFCORE_Inst * first = NULL;
  GDEFCORE_Inst * second = NULL;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char again[GDEFCORE_PUBLIC_ID_LEN + 1];
  char encoded[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t key[16];
  std::string place = Tmp("tenant");
  std::string other = Tmp("other");
  ASSERT_NE(access(place.c_str(), F_OK), 0);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, root_, sizeof root_, place.c_str(),
          place.size(), NULL, &first));
  ASSERT_NE(access(place.c_str(), F_OK), 0);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(first, id));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(first, id, strlen(id), key));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_encode(key, encoded));
  EXPECT_STREQ(id, encoded);
  EXPECT_NE(gdefcore_inst_keyring(first), nullptr);
  EXPECT_NE(gdefcore_inst_tenant_keyring(first, id, strlen(id)), nullptr);
  gdefcore_inst_destroy(first);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, root_, sizeof root_, other.c_str(),
          other.size(), NULL, &second));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(second, again));
  EXPECT_STREQ(id, again);
  ASSERT_NE(access(place.c_str(), F_OK), 0);
  ASSERT_NE(access(other.c_str(), F_OK), 0);
  gdefcore_inst_destroy(second);
}

TEST_F(Inst, SecondTenant) {
  GDEFCORE_Inst * inst = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Keyring * ring = NULL;
  GDEFSTOR_Limits limits;
  GDEFSTOR_Limits expect;
  char id_a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id_b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char note[GDEFCORE_PUBLIC_ID_LEN + 1];
  char resolved[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * placement = NULL;
  char * edition = NULL;
  char * status = NULL;
  size_t placement_n = 0;
  size_t edition_n = 0;
  size_t status_n = 0;
  uint8_t key_before[16];
  uint8_t key_after[16];
  uint8_t key_b[16];
  std::string where = Tmp("b");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, root_, sizeof root_, "", 0, NULL,
          &inst));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(inst, id_a));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(inst, id_a, strlen(id_a), key_before));
  ring = gdefcore_inst_tenant_keyring(inst, id_a, strlen(id_a));
  ASSERT_NE(ring, nullptr);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_catalog_open(inst, id_a, strlen(id_a), &catalog));
  SaveNote(catalog, "kept", note);
  if (HasFailure()) {
    gdefcore_catalog_destroy(catalog);
    gdefcore_inst_destroy(inst);
    return;
  }
  EXPECT_EQ(std::string("kept"), Title(catalog, note));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_tenant_create(inst, "acme", 4, where.c_str(), where.size(),
          id_b));
  EXPECT_EQ(ring, gdefcore_inst_tenant_keyring(inst, id_a, strlen(id_a)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(inst, id_a, strlen(id_a), key_after));
  EXPECT_EQ(0, memcmp(key_before, key_after, sizeof key_before));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(inst, id_b, strlen(id_b), key_b));
  EXPECT_NE(0, memcmp(key_before, key_b, sizeof key_before));
  EXPECT_EQ(std::string("kept"), Title(catalog, note));
  EXPECT_EQ(1u, NoteCount(catalog));
  memset(&expect, 0, sizeof expect);
  gdefstor_limits_default(&expect);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_resolve(inst, "acme", 4, resolved, &placement, &placement_n,
          &edition, &edition_n, &status, &status_n, &limits));
  EXPECT_STREQ(id_b, resolved);
  EXPECT_EQ(where, std::string(placement, placement_n));
  EXPECT_EQ(0u, edition_n);
  EXPECT_EQ(std::string("active"), std::string(status, status_n));
  EXPECT_EQ(expect.max_members, limits.max_members);
  EXPECT_EQ(expect.max_snapshot_bytes, limits.max_snapshot_bytes);
  gdefcore_inst_text_free(inst, placement);
  gdefcore_inst_text_free(inst, edition);
  gdefcore_inst_text_free(inst, status);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_limit_set(inst, id_b, strlen(id_b), "max_members", 11,
          7));
  placement = NULL;
  edition = NULL;
  status = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_resolve(inst, "acme", 4, resolved, &placement, &placement_n,
          &edition, &edition_n, &status, &status_n, &limits));
  EXPECT_EQ(7u, limits.max_members);
  EXPECT_EQ(expect.max_snapshot_bytes, limits.max_snapshot_bytes);
  ASSERT_NE(access(where.c_str(), F_OK), 0);
  gdefcore_inst_text_free(inst, placement);
  gdefcore_inst_text_free(inst, edition);
  gdefcore_inst_text_free(inst, status);
  gdefcore_catalog_destroy(catalog);
  gdefcore_inst_destroy(inst);
  inst = NULL;
  placement = NULL;
  edition = NULL;
  status = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, root_, sizeof root_, "", 0, NULL,
          &inst));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_resolve(inst, "acme", 4, resolved, &placement, &placement_n,
          &edition, &edition_n, &status, &status_n, &limits));
  EXPECT_STREQ(id_b, resolved);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(inst, resolved, strlen(resolved), key_after));
  EXPECT_EQ(0, memcmp(key_b, key_after, sizeof key_b));
  EXPECT_EQ(where, std::string(placement, placement_n));
  EXPECT_EQ(std::string("active"), std::string(status, status_n));
  EXPECT_EQ(7u, limits.max_members);
  gdefcore_inst_text_free(inst, placement);
  gdefcore_inst_text_free(inst, edition);
  gdefcore_inst_text_free(inst, status);
  gdefcore_inst_destroy(inst);
}

TEST_F(Inst, Isolation) {
  GDEFCORE_Inst * inst = NULL;
  GDEFCORE_Catalog * catalog_a = NULL;
  GDEFCORE_Catalog * catalog_b = NULL;
  GDEFCORE_Request * request = NULL;
  GDEFCORE_Keyring * ring_b = NULL;
  char id_a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id_b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char note[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t key_b[16];
  size_t n = 0;
  std::string token;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, root_, sizeof root_, "", 0, NULL,
          &inst));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(inst, id_a));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_tenant_create(inst, "bee", 3, "", 0, id_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_catalog_open(inst, id_a, strlen(id_a), &catalog_a));
  SaveNote(catalog_a, "only-a", note);
  if (HasFailure()) {
    gdefcore_catalog_destroy(catalog_a);
    gdefcore_inst_destroy(inst);
    return;
  }
  token = Login(catalog_a, gdefcore_inst_tenant_keyring(inst, id_a, strlen(id_a)));
  ASSERT_FALSE(token.empty());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_catalog_open(inst, id_b, strlen(id_b), &catalog_b));
  EXPECT_EQ(0u, NoteCount(catalog_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(inst, id_b, strlen(id_b), key_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create(key_b, sizeof key_b, 0, 0, NULL, &request));
  ring_b = gdefcore_inst_tenant_keyring(inst, id_b, strlen(id_b));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_check(catalog_b, request, ring_b, root_, sizeof root_,
          token.data(), token.size()));
  EXPECT_EQ(gdefcore_request_principal(request, &n), nullptr);
  gdefcore_request_destroy(request);
  gdefcore_catalog_destroy(catalog_b);
  gdefcore_catalog_destroy(catalog_a);
  gdefcore_inst_destroy(inst);
}

TEST_F(Inst, Hidden) {
  GDEFCORE_Inst * inst = NULL;
  char id_b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char out_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * placement = (char *)0x1;
  char * edition = (char *)0x1;
  char * status = (char *)0x1;
  size_t placement_n = 99;
  size_t edition_n = 99;
  size_t status_n = 99;
  GDEFSTOR_Limits limits;
  GDEFCORE_Result unknown;
  GDEFCORE_Result malformed;
  const char bad[] = {'\x7f'};
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, root_, sizeof root_, "", 0, NULL,
          &inst));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_tenant_create(inst, "kept", 4, "", 0, id_b));
  memset(out_id, 'Z', GDEFCORE_PUBLIC_ID_LEN);
  out_id[GDEFCORE_PUBLIC_ID_LEN] = '\0';
  memset(&limits, 0x5a, sizeof limits);
  unknown = gdefcore_inst_resolve(inst, "never-set", 9, out_id, &placement,
      &placement_n, &edition, &edition_n, &status, &status_n, &limits);
  malformed = gdefcore_inst_resolve(inst, bad, 1, out_id, &placement,
      &placement_n, &edition, &edition_n, &status, &status_n, &limits);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, unknown);
  EXPECT_EQ(unknown, malformed);
  EXPECT_EQ(std::string(GDEFCORE_PUBLIC_ID_LEN, 'Z'), std::string(out_id));
  EXPECT_NE(std::string(out_id), std::string(id_b));
  EXPECT_EQ((char *)0x1, placement);
  EXPECT_EQ((char *)0x1, edition);
  EXPECT_EQ((char *)0x1, status);
  EXPECT_EQ(99u, placement_n);
  EXPECT_EQ(99u, edition_n);
  EXPECT_EQ(99u, status_n);
  EXPECT_EQ((unsigned char)0x5a, ((unsigned char *)&limits)[0]);
  gdefcore_inst_destroy(inst);
}

TEST_F(Inst, OtherRoot) {
  GDEFCORE_Inst_Config * config = NULL;
  GDEFCORE_Inst * inst = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Request * request = NULL;
  GDEFCORE_Keyring * ring = NULL;
  uint8_t file_root[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t other[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t loaded[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t key[16];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t n = 0;
  std::string path = Tmp("root.key");
  std::string token;
  memset(file_root, 0x11, sizeof file_root);
  memset(other, 0x22, sizeof other);
  ASSERT_TRUE(WriteBytes(path, file_root, sizeof file_root));
  ASSERT_EQ(0, setenv("DEFIANT_SECRET_FILE", path.c_str(), 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_load(NULL, &config));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_root(config, loaded));
  EXPECT_EQ(0, memcmp(loaded, file_root, sizeof file_root));
  memcpy(root_, file_root, sizeof root_);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, file_root, sizeof file_root, "", 0,
          NULL, &inst));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(inst, id));
  ring = gdefcore_inst_keyring(inst);
  ASSERT_NE(ring, nullptr);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_catalog_open(inst, id, strlen(id), &catalog));
  token = Login(catalog, ring);
  ASSERT_FALSE(token.empty());
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_storage_key(inst, id, strlen(id), key));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create(key, sizeof key, 0, 0, NULL, &request));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_account_check(catalog, request, ring, file_root, sizeof file_root,
          token.data(), token.size()));
  EXPECT_NE(gdefcore_request_principal(request, &n), nullptr);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_check(catalog, request, ring, other, sizeof other,
          token.data(), token.size()));
  EXPECT_EQ(gdefcore_request_principal(request, &n), nullptr);
  gdefcore_request_destroy(request);
  gdefcore_catalog_destroy(catalog);
  gdefcore_inst_destroy(inst);
  gdefcore_inst_config_destroy(config);
}

TEST_F(Inst, SecretEnv) {
  GDEFCORE_Inst_Config * config = NULL;
  uint8_t want[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t loaded[GDEFCORE_ACCOUNT_ROOT_LEN];
  char * held = NULL;
  char * text = NULL;
  size_t held_n = 0;
  size_t n = 0;
  size_t i;
  std::string hex;
  std::string body;
  memset(want, 0x3c, sizeof want);
  hex = HexEncode(want, sizeof want);
  ASSERT_EQ(64u, hex.size());
  ASSERT_EQ(0, setenv("DEFIANT_SECRET", hex.c_str(), 1));
  ASSERT_EQ(0, setenv("DEFIANT_SECRET_FILE", "/no/such/defiant-secret-file", 1));
  held = getenv("DEFIANT_SECRET");
  ASSERT_NE(held, nullptr);
  held_n = strlen(held);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_load(NULL, &config));
  EXPECT_EQ(getenv("DEFIANT_SECRET"), nullptr);
  for (i = 0; i < held_n; i++) {
    EXPECT_EQ('\0', held[i]);
  }
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_root(config, loaded));
  EXPECT_EQ(0, memcmp(loaded, want, sizeof want));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_format(config, &text, &n));
  body.assign(text, n);
  EXPECT_EQ(std::string(
      "DEFIANT_ROLES= source=default\n"
      "DEFIANT_STORE= source=default\n"
      "DEFIANT_LISTEN= source=default\n"
      "DEFIANT_TRUSTED_PROXIES= source=default\n"
      "DEFIANT_SECRET= source=env\n"
      "DEFIANT_SECRET_FILE=/no/such/defiant-secret-file source=env\n"),
      body);
  gdefcore_inst_config_free(config, text);
  gdefcore_inst_config_destroy(config);
}

TEST_F(Inst, Effective) {
#ifdef _WIN32
  GTEST_SKIP() << "the effective-config example is run with a chosen environment through fork and execve";
#endif
  uint8_t secret[GDEFCORE_ACCOUNT_ROOT_LEN];
  std::string path = Tmp("secret");
  std::string listen = "DEFIANT_LISTEN=10.1.2.3:4242";
  std::string file;
  std::string libs;
  std::string hex;
  std::string out;
  char * envp[4];
  int nenv = 0;
  const char * ld = getenv("LD_LIBRARY_PATH");
  memset(secret, 0xab, sizeof secret);
  hex = HexEncode(secret, sizeof secret);
  ASSERT_TRUE(WriteBytes(path, secret, sizeof secret));
  file = "DEFIANT_SECRET_FILE=" + path;
  envp[nenv++] = listen.data();
  envp[nenv++] = file.data();
  if (ld != NULL && ld[0] != '\0') {
    libs = std::string("LD_LIBRARY_PATH=") + ld;
    envp[nenv++] = libs.data();
  }
  envp[nenv] = NULL;
  out = RunConfig(GDEFCORE_EFFECTIVE_CONFIG, envp);
  EXPECT_EQ(std::string(
                "DEFIANT_ROLES= source=default\n"
                "DEFIANT_STORE= source=default\n"
                "DEFIANT_LISTEN=10.1.2.3:4242 source=env\n"
                "DEFIANT_TRUSTED_PROXIES= source=default\n"
                "DEFIANT_SECRET= source=file\n"
                "DEFIANT_SECRET_FILE=" + path + " source=env\n"),
      out);
  EXPECT_EQ(out.find(hex), std::string::npos);
  EXPECT_EQ(out.find("\xab"), std::string::npos);
}

TEST_F(Inst, FileWins) {
  GDEFCORE_Inst_Config * config = NULL;
  char * text = NULL;
  size_t n = 0;
  std::string path = Tmp("defiant.toml");
  std::string body;
  ASSERT_TRUE(WriteText(path,
      "STORE = \"/srv/defiant\"\nLISTEN = \"127.0.0.1:7\"\n"));
  ASSERT_EQ(0, setenv("DEFIANT_CONFIG", path.c_str(), 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_load(NULL, &config));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_format(config, &text, &n));
  body.assign(text, n);
  EXPECT_EQ(std::string(
                "DEFIANT_ROLES= source=default\n"
                "DEFIANT_STORE=/srv/defiant source=file\n"
                "DEFIANT_LISTEN=127.0.0.1:7 source=file\n"
                "DEFIANT_TRUSTED_PROXIES= source=default\n"
                "DEFIANT_SECRET= source=default\n"
                "DEFIANT_SECRET_FILE= source=default\n"),
      body);
  gdefcore_inst_config_free(config, text);
  gdefcore_inst_config_destroy(config);
  config = NULL;
  text = NULL;
  ASSERT_EQ(0, setenv("DEFIANT_STORE", "/from-env", 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_load(NULL, &config));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_format(config, &text, &n));
  body.assign(text, n);
  EXPECT_EQ(std::string(
                "DEFIANT_ROLES= source=default\n"
                "DEFIANT_STORE=/from-env source=env\n"
                "DEFIANT_LISTEN=127.0.0.1:7 source=file\n"
                "DEFIANT_TRUSTED_PROXIES= source=default\n"
                "DEFIANT_SECRET= source=default\n"
                "DEFIANT_SECRET_FILE= source=default\n"),
      body);
  gdefcore_inst_config_free(config, text);
  gdefcore_inst_config_destroy(config);
}

TEST_F(Inst, TomlSecret) {
  GDEFCORE_Inst_Config * config = NULL;
  uint8_t want[GDEFCORE_ACCOUNT_ROOT_LEN];
  uint8_t loaded[GDEFCORE_ACCOUNT_ROOT_LEN];
  char * text = NULL;
  size_t n = 0;
  std::string hex;
  std::string body;
  std::string path = Tmp("secret.toml");
  memset(want, 0x5a, sizeof want);
  hex = HexEncode(want, sizeof want);
  ASSERT_TRUE(WriteText(path, "SECRET = \"" + hex + "\"\n"));
  ASSERT_EQ(0, setenv("DEFIANT_CONFIG", path.c_str(), 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_load(NULL, &config));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_root(config, loaded));
  EXPECT_EQ(0, memcmp(loaded, want, sizeof want));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_config_format(config, &text, &n));
  body.assign(text, n);
  EXPECT_EQ(std::string(
                "DEFIANT_ROLES= source=default\n"
                "DEFIANT_STORE= source=default\n"
                "DEFIANT_LISTEN= source=default\n"
                "DEFIANT_TRUSTED_PROXIES= source=default\n"
                "DEFIANT_SECRET= source=file\n"
                "DEFIANT_SECRET_FILE= source=default\n"),
      body);
  EXPECT_EQ(body.find(hex), std::string::npos);
  gdefcore_inst_config_free(config, text);
  gdefcore_inst_config_destroy(config);
}

TEST_F(Inst, Gate) {
  GDEFCORE_Inst * inst = NULL;
  GDEFCORE_Catalog * catalog_a = NULL;
  GDEFCORE_Catalog * seen = NULL;
  GDEFCORE_Request * request = NULL;
  char id_a[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id_b[GDEFCORE_PUBLIC_ID_LEN + 1];
  char note[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t key_a[16];
  uint8_t key_b[16];
  size_t n = 0;
  std::string token;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_open(registry_, site_, root_, sizeof root_, "", 0, NULL,
          &inst));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_inst_default(inst, id_a));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_tenant_create(inst, "bee", 3, "", 0, id_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(inst, id_a, strlen(id_a), key_a));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_storage_key(inst, id_b, strlen(id_b), key_b));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_inst_catalog_open(inst, id_a, strlen(id_a), &catalog_a));
  SaveNote(catalog_a, "only-a", note);
  if (HasFailure()) {
    gdefcore_catalog_destroy(catalog_a);
    gdefcore_inst_destroy(inst);
    return;
  }
  token = Login(catalog_a, gdefcore_inst_tenant_keyring(inst, id_a, strlen(id_a)));
  ASSERT_FALSE(token.empty());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create(key_b, sizeof key_b, 0, 0, NULL, &request));
  if (strcmp(Plant(), "other-key") == 0) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(site_, key_a, sizeof key_a, NULL, NULL, &seen));
  } else {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_inst_catalog_open(inst, id_b, strlen(id_b), &seen));
  }
  EXPECT_EQ(0u, NoteCount(seen));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_account_check(seen, request,
          gdefcore_inst_tenant_keyring(inst, id_b, strlen(id_b)), root_,
          sizeof root_, token.data(), token.size()));
  EXPECT_EQ(gdefcore_request_principal(request, &n), nullptr);
  gdefcore_request_destroy(request);
  gdefcore_catalog_destroy(seen);
  gdefcore_catalog_destroy(catalog_a);
  gdefcore_inst_destroy(inst);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
