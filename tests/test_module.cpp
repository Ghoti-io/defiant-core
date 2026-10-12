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
 * Story 8's matrix, on the memory backend. One test per row. The example
 * module is compiled into this process as a guest and built again as a
 * native library.
 */

#ifdef _WIN32
#include <windows.h>
#endif
#include <ghoti.io/cutil/library.h>
#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage/projection.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "module_example.c"

#ifndef GDEFCORE_MODULE_EXAMPLE
#error GDEFCORE_MODULE_EXAMPLE is the native example library
#endif

#define MODULE_STR2(x) #x
#define MODULE_STR(x) MODULE_STR2(x)

static const char kCoreToken[] = MODULE_STR(GHOTIIO_DEFCORE_NAME);
static const char kTenant[] = "t";

struct Vote {
  int calls;
  int decision;
  int fail;
  int access;
  int saw_request;
  int saw_block;
  char arg_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t arg_id_len;
  char arg_type[32];
  size_t arg_type_len;
  uint64_t arg_seq;
  GDEFCORE_Catalog * catalog;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char seen[64];
  size_t seen_len;
  GDEFCORE_Result seen_rc;
};

static GDEFCORE_Module_Manifest g_man;
static GDEFCORE_Module_Rel g_rel;
static GDEFCORE_Module_Sub g_sub;
static const GDEFCORE_Module_Manifest * g_current;
static const char * g_before;
static int g_entered_seen = -1;
static GDEFSTOR_Store * g_probe_store;

struct AppendState {
  int calls;
  const char * extra;
};

extern "C" const GDEFCORE_Module_Manifest * TestGuest(void) {
  return g_current;
}

extern "C" GDEFCORE_Result OnVote(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  Vote * vote = (Vote *)user;
  (void)alter;
  vote->calls += 1;
  if (args != NULL) {
    const GDEFCORE_Write_Hook * block = (const GDEFCORE_Write_Hook *)args;
    if (block->size >=
        offsetof(GDEFCORE_Write_Hook, base_seq) + sizeof(uint64_t)) {
      vote->saw_block = 1;
      vote->arg_seq = block->base_seq;
      vote->arg_id_len = 0;
      vote->arg_type_len = 0;
      if (block->entity_id != NULL &&
          block->entity_id_len <= GDEFCORE_PUBLIC_ID_LEN) {
        memcpy(vote->arg_id, block->entity_id, block->entity_id_len);
        vote->arg_id_len = block->entity_id_len;
      }
      if (block->type_name != NULL && block->type_name_len < sizeof vote->arg_type) {
        memcpy(vote->arg_type, block->type_name, block->type_name_len);
        vote->arg_type_len = block->type_name_len;
      }
    }
  }
  vote->saw_request = request != NULL;
  if (out != NULL) {
    out->decision = vote->decision;
    if (vote->access) {
      out->access = 1;
    }
  }
  if (vote->fail) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

extern "C" GDEFCORE_Result OnAppend(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  const char * text = NULL;
  size_t len = 0;
  const char * extra = (const char *)user;
  char buf[64];
  size_t extra_len;
  (void)request;
  (void)args;
  (void)out;
  if (gdefcore_alter_text(alter, &text, &len) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  extra_len = strlen(extra);
  if (len + extra_len >= sizeof buf) {
    return GDEFCORE_ERR_LIMIT;
  }
  memcpy(buf, text, len);
  memcpy(buf + len, extra, extra_len);
  return gdefcore_alter_set(alter, buf, len + extra_len);
}

extern "C" GDEFCORE_Result OnAppendCount(GDEFCORE_Request * request,
    const void * args, GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out,
    void * user) {
  AppendState * state = (AppendState *)user;
  state->calls += 1;
  return OnAppend(request, args, alter, out, (void *)state->extra);
}

extern "C" GDEFCORE_Result OnAppendThenFail(GDEFCORE_Request * request,
    const void * args, GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out,
    void * user) {
  GDEFCORE_Result rc = OnAppend(request, args, alter, out, user);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return GDEFCORE_ERR_INVALID;
}

extern "C" void ProbeEntered(void) {
  GDEFSTOR_Projection * row = NULL;
  size_t i;
  size_t n;
  g_entered_seen = -1;
  if (g_probe_store == NULL ||
      gdefstor_projection_get(g_probe_store, "\x01", 1, "core.module.install",
          19, "example", 7, &row) != GDEFSTOR_OK) {
    return;
  }
  n = gdefstor_projection_column_count(row);
  for (i = 0; i < n; i++) {
    GDEFSTOR_Column column;
    if (gdefstor_projection_column(row, i, &column) != GDEFSTOR_OK) {
      continue;
    }
    if (column.name_len == 7 && memcmp(column.name, "entered", 7) == 0 &&
        column.value != NULL && column.value_len >= 1) {
      g_entered_seen = column.value[0];
    }
  }
  gdefstor_projection_free(row);
}

extern "C" GDEFCORE_Result OnAfter(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  Vote * vote = (Vote *)user;
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  (void)args;
  (void)alter;
  (void)out;
  vote->calls += 1;
  vote->saw_request = request != NULL;
  vote->seen_rc = gdefcore_entity_values(vote->catalog, NULL,
      GDEFCORE_VIEW_PUBLISHED, vote->id, strlen(vote->id), "en", 2, "title", 5,
      &texts, &lens, &count);
  vote->seen_len = 0;
  if (vote->seen_rc == GDEFCORE_OK && count > 0 && lens[0] < sizeof vote->seen) {
    memcpy(vote->seen, texts[0], lens[0]);
    vote->seen_len = lens[0];
  }
  if (vote->seen_rc == GDEFCORE_OK) {
    gdefcore_values_free(vote->catalog, texts, lens, count);
  }
  return GDEFCORE_ERR_IO;
}

namespace {

std::string HostError(const GDEFCORE_Host * host) {
  size_t n = 0;
  const char * text = gdefcore_module_error(host, &n);
  if (text == NULL) {
    return std::string();
  }
  return std::string(text, n);
}

std::string HostNotice(const GDEFCORE_Host * host) {
  size_t n = 0;
  const char * text = gdefcore_module_notice(host, &n);
  if (text == NULL) {
    return std::string();
  }
  return std::string(text, n);
}

#ifdef _WIN32
bool Mapped(const std::string & path) {
  /* The loader knows a module by its file name. */
  size_t slash = path.find_last_of("/\\");
  return GetModuleHandleA(slash == std::string::npos ? path.c_str() : path.c_str() + slash + 1) !=
         NULL;
}
#else
bool Mapped(const std::string & path) {
  std::ifstream in("/proc/self/maps");
  std::string line;
  while (std::getline(in, line)) {
    if (line.find(path) != std::string::npos) {
      return true;
    }
  }
  return false;
}
#endif

void InstallGuest(GDEFCORE_Host * host, const char * name, const char * token,
    const char * hook, int kind, int weight, int access, const char * after,
    GDEFCORE_Hook_Fn fn, void * user, int rel_kind, const char * rel) {
  memset(&g_man, 0, sizeof g_man);
  memset(&g_rel, 0, sizeof g_rel);
  memset(&g_sub, 0, sizeof g_sub);
  g_sub.size = sizeof g_sub;
  if (hook != NULL) {
    g_sub.hook = hook;
    g_sub.hook_len = strlen(hook);
    g_sub.kind = kind;
    g_sub.weight = weight;
    g_sub.access_relevant = access;
    g_sub.fn = fn;
    g_sub.user = user;
    if (after != NULL) {
      g_sub.after = after;
      g_sub.after_len = strlen(after);
    }
    if (g_before != NULL) {
      g_sub.before = g_before;
      g_sub.before_len = strlen(g_before);
      g_before = NULL;
    }
  }
  g_man.size = sizeof g_man;
  g_man.core_token = token;
  g_man.core_token_len = strlen(token);
  g_man.name = name;
  g_man.name_len = strlen(name);
  g_man.label = name;
  g_man.label_len = strlen(name);
  if (hook != NULL) {
    g_man.subs = &g_sub;
    g_man.nsubs = 1;
  }
  if (rel != NULL) {
    g_rel.size = sizeof g_rel;
    g_rel.kind = rel_kind;
    g_rel.name = rel;
    g_rel.name_len = strlen(rel);
    g_man.rels = &g_rel;
    g_man.nrels = 1;
  }
  g_current = &g_man;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host, TestGuest));
}

GDEFCORE_Result ApplyModules(GDEFCORE_Host * host, GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * const * names, size_t count,
    const char * confirm) {
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc;
  size_t i;
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  gdefcore_changeset_set_request(changeset, request);
  for (i = 0; i < count; i++) {
    rc = gdefcore_module_enable(host, changeset, names[i], strlen(names[i]));
    if (rc != GDEFCORE_OK) {
      gdefcore_changeset_destroy(changeset);
      return rc;
    }
  }
  rc = gdefcore_changeset_apply(changeset, confirm,
      confirm == NULL ? 0 : strlen(confirm));
  gdefcore_changeset_destroy(changeset);
  return rc;
}

int IsEnabled(GDEFCORE_Host * host, GDEFCORE_Request * request, const char * name) {
  int on = 0;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_module_enabled(host, request, name, strlen(name), &on));
  return on;
}

std::string AlterText(GDEFCORE_Host * host, GDEFCORE_Request * request,
    GDEFCORE_Catalog * catalog, const char * hook, const char * initial) {
  GDEFCORE_Alter * alter = NULL;
  const char * text = NULL;
  size_t len = 0;
  std::string out;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_alter_create(host, initial, strlen(initial), &alter));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host, request, catalog, hook, strlen(hook),
          GDEFCORE_HOOK_ALTER, NULL, alter, NULL));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_alter_text(alter, &text, &len));
  if (text != NULL) {
    out.assign(text, len);
  }
  gdefcore_alter_destroy(host, alter);
  return out;
}

void DefineNote(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field field;
  memset(&field, 0, sizeof field);
  field.size = sizeof field;
  field.name = "title";
  field.name_len = 5;
  field.required = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_type_define(catalog, "site.note", 9, GDEFCORE_TYPE_CONTENT,
          &field, 1));
}

void SaveTitle(GDEFCORE_Changeset * changeset, const char * id, const char * text) {
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
      gdefcore_entity_save(changeset, id, strlen(id), "en", 2, &value, 1));
}

std::string PublishedTitle(GDEFCORE_Catalog * catalog, const char * id) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = gdefcore_entity_values(catalog, NULL,
      GDEFCORE_VIEW_PUBLISHED, id, strlen(id), "en", 2, "title", 5, &texts,
      &lens, &count);
  if (rc != GDEFCORE_OK || count == 0) {
    return std::string();
  }
  std::string value(texts[0], lens[0]);
  gdefcore_values_free(catalog, texts, lens, count);
  return value;
}

class Module : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_;
  GDEFCORE_Catalog * catalog_;
  GDEFCORE_Host * host_;
  GDEFCORE_Request * request_;

  void SetUp() override {
    store_ = NULL;
    catalog_ = NULL;
    host_ = NULL;
    request_ = NULL;
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
            &catalog_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
    gdefcore_catalog_bind_host(catalog_, host_);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL,
            &request_));
  }

  void TearDown() override {
    gdefcore_request_destroy(request_);
    gdefcore_catalog_bind_host(catalog_, NULL);
    gdefcore_host_destroy(host_);
    gdefcore_catalog_destroy(catalog_);
    gdefstor_store_destroy(store_);
  }
};

}  // namespace

TEST_F(Module, Event) {
  Vote one;
  Vote two;
  const char * names[] = {"one", "two"};
  memset(&one, 0, sizeof one);
  memset(&two, 0, sizeof two);
  InstallGuest(host_, "one", kCoreToken, "demo.event", GDEFCORE_HOOK_EVENT, 0, 0,
      NULL, OnVote, &one, 0, NULL);
  InstallGuest(host_, "two", kCoreToken, "demo.event", GDEFCORE_HOOK_EVENT, 0, 0,
      NULL, OnVote, &two, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "one\ntwo"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.event", 10,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
  EXPECT_EQ(1, one.calls);
  EXPECT_EQ(1, two.calls);
  EXPECT_EQ(1, one.saw_request);
  EXPECT_EQ(1, two.saw_request);
  one.fail = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.event", 10,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
  EXPECT_EQ(2, one.calls);
  EXPECT_EQ(2, two.calls);
  EXPECT_EQ(1u, gdefcore_hook_skipped(host_));
  {
    size_t n = 0;
    const char * skipped = gdefcore_hook_skipped_names(host_, &n);
    ASSERT_NE(nullptr, skipped);
    EXPECT_EQ(std::string("one"), std::string(skipped, n));
  }
}

TEST_F(Module, Alter) {
  const char * names[] = {"a", "b"};
  InstallGuest(host_, "b", kCoreToken, "demo.alter", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnAppend, (void *)"b", 0, NULL);
  InstallGuest(host_, "a", kCoreToken, "demo.alter", GDEFCORE_HOOK_ALTER, 1, 0, NULL,
      OnAppend, (void *)"a", 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "a\nb"));
  EXPECT_EQ(std::string("xba"),
      AlterText(host_, request_, catalog_, "demo.alter", "x"));
}

TEST_F(Module, Decision) {
  Vote nay;
  Vote aye;
  const char * names[] = {"aye", "nay"};
  int decision = GDEFCORE_DECISION_ALLOW;
  memset(&nay, 0, sizeof nay);
  memset(&aye, 0, sizeof aye);
  nay.decision = GDEFCORE_DECISION_DENY;
  aye.decision = GDEFCORE_DECISION_ALLOW;
  InstallGuest(host_, "nay", kCoreToken, "demo.decide", GDEFCORE_HOOK_DECISION, 0, 0,
      NULL, OnVote, &nay, 0, NULL);
  InstallGuest(host_, "aye", kCoreToken, "demo.decide", GDEFCORE_HOOK_DECISION, 0, 0,
      NULL, OnVote, &aye, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "aye\nnay"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.decide", 11,
          GDEFCORE_HOOK_DECISION, NULL, NULL, &decision));
  EXPECT_EQ(GDEFCORE_DECISION_DENY, decision);
  decision = GDEFCORE_DECISION_ALLOW;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.none", 9,
          GDEFCORE_HOOK_DECISION, NULL, NULL, &decision));
  EXPECT_EQ(GDEFCORE_DECISION_DENY, decision);
}

TEST_F(Module, DecisionAllow) {
  Vote aye;
  Vote mute;
  const char * names[] = {"aye", "mute"};
  int decision = GDEFCORE_DECISION_DENY;
  memset(&aye, 0, sizeof aye);
  memset(&mute, 0, sizeof mute);
  aye.decision = GDEFCORE_DECISION_ALLOW;
  mute.decision = GDEFCORE_DECISION_NONE;
  InstallGuest(host_, "aye", kCoreToken, "demo.allow", GDEFCORE_HOOK_DECISION, 0, 0,
      NULL, OnVote, &aye, 0, NULL);
  InstallGuest(host_, "mute", kCoreToken, "demo.allow", GDEFCORE_HOOK_DECISION, 0, 0,
      NULL, OnVote, &mute, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "aye\nmute"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.allow", 10,
          GDEFCORE_HOOK_DECISION, NULL, NULL, &decision));
  EXPECT_EQ(GDEFCORE_DECISION_ALLOW, decision);
}

TEST_F(Module, Cycle) {
  Vote unused;
  const char * names[] = {"a", "b"};
  uint64_t epoch = 0;
  GDEFCORE_Catalog * other = NULL;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * changeset = NULL;
  memset(&unused, 0, sizeof unused);
  InstallGuest(host_, "a", kCoreToken, "demo.cycle", GDEFCORE_HOOK_EVENT, 0, 0, "b",
      OnVote, &unused, 0, NULL);
  InstallGuest(host_, "b", kCoreToken, "demo.cycle", GDEFCORE_HOOK_EVENT, 0, 0, "a",
      OnVote, &unused, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  ASSERT_EQ(GDEFCORE_ERR_INVALID,
      ApplyModules(host_, catalog_, request_, names, 2, "a\nb"));
  EXPECT_NE(std::string::npos, HostError(host_).find(" a"));
  EXPECT_NE(std::string::npos, HostError(host_).find(" b"));
  EXPECT_EQ(0, IsEnabled(host_, request_, "a"));
  EXPECT_EQ(0, IsEnabled(host_, request_, "b"));
  {
    uint64_t after = 99;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
    EXPECT_EQ(epoch, after);
  }
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(store_, (const uint8_t *)"u", 1, NULL, NULL, &other));
  DefineNote(other);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(other, "site.note", 9, id, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(other, NULL, 0, &changeset));
  SaveTitle(changeset, id, "ready");
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  EXPECT_EQ(std::string("ready"), PublishedTitle(other, id));
  gdefcore_changeset_destroy(changeset);
  gdefcore_catalog_destroy(other);
}

TEST_F(Module, Enhances) {
  const char * names[] = {"example"};
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, gdefcore_module_manifest));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "example"));
  EXPECT_EQ(std::string("Module example enhances missing, which is not installed."),
      HostNotice(host_));
  EXPECT_EQ(1, IsEnabled(host_, request_, "example"));
}

TEST_F(Module, Requires) {
  const char * names[] = {"need"};
  uint64_t epoch = 0;
  InstallGuest(host_, "need", kCoreToken, "demo.need", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, NULL, GDEFCORE_REL_REQUIRES, "gone");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  ASSERT_EQ(GDEFCORE_ERR_INVALID,
      ApplyModules(host_, catalog_, request_, names, 1, "need"));
  EXPECT_NE(std::string::npos, HostError(host_).find("gone"));
  EXPECT_EQ(0, IsEnabled(host_, request_, "need"));
  {
    uint64_t after = 99;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
    EXPECT_EQ(epoch, after);
  }
}

TEST_F(Module, Trust) {
  char tmpl[] = "/tmp/gdefcore-mod-XXXXXX\0.dll.pad";
  int fd = mkstemp(tmpl);
  std::ifstream in(GDEFCORE_MODULE_EXAMPLE, std::ios::binary);
  std::string bytes((std::istreambuf_iterator<char>(in)),
      std::istreambuf_iterator<char>());
  ASSERT_GE(fd, 0);
  ASSERT_FALSE(bytes.empty());
  ASSERT_EQ((ssize_t)bytes.size(), write(fd, bytes.data(), bytes.size()));
  ASSERT_EQ(0, close(fd));
#ifdef _WIN32
  /* LoadLibrary adds .dll to a name that has no extension, so the copy has one. */
  {
    std::string named = std::string(tmpl) + ".dll";
    ASSERT_EQ(0, rename(tmpl, named.c_str()));
    ASSERT_LT(named.size(), sizeof tmpl + 8);
    strcpy(tmpl, named.c_str());
  }
#endif
  EXPECT_FALSE(Mapped(tmpl));
  ASSERT_EQ(GDEFCORE_ERR_INVALID, gdefcore_module_install_native(host_, tmpl, 0));
  EXPECT_EQ(std::string("Native install requires full trust."), HostError(host_));
  EXPECT_FALSE(Mapped(tmpl));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(host_, tmpl, GDEFCORE_MODULE_TRUST_FULL));
  EXPECT_TRUE(Mapped(tmpl));
  unlink(tmpl);
}

TEST_F(Module, Namespace) {
  Vote vote;
  memset(&vote, 0, sizeof vote);
  memset(&g_man, 0, sizeof g_man);
  memset(&g_sub, 0, sizeof g_sub);
  g_sub.size = sizeof g_sub;
  g_sub.hook = "demo.token";
  g_sub.hook_len = 10;
  g_sub.kind = GDEFCORE_HOOK_EVENT;
  g_sub.fn = OnVote;
  g_sub.user = &vote;
  g_man.size = sizeof g_man;
  g_man.core_token = "other-core";
  g_man.core_token_len = 10;
  g_man.name = "foreign";
  g_man.name_len = 7;
  g_man.subs = &g_sub;
  g_man.nsubs = 1;
  g_current = &g_man;
  ASSERT_EQ(GDEFCORE_ERR_INVALID, gdefcore_module_install_guest(host_, TestGuest));
  EXPECT_EQ(0, vote.calls);
  EXPECT_NE(std::string::npos, HostError(host_).find("other-core"));
  EXPECT_NE(std::string::npos, HostError(host_).find(kCoreToken));
}

TEST_F(Module, Quarantine) {
  const char * names[] = {"example"};
  ASSERT_FALSE(Mapped(GDEFCORE_MODULE_EXAMPLE));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(host_, GDEFCORE_MODULE_EXAMPLE,
          GDEFCORE_MODULE_TRUST_FULL));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "example"));
  EXPECT_EQ(std::string("alpha:touched"),
      AlterText(host_, request_, catalog_, "example.alter", "alpha"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_mark_entered(host_, "example", 7));
  gdefcore_catalog_bind_host(catalog_, NULL);
  gdefcore_host_destroy(host_);
  host_ = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
  gdefcore_catalog_bind_host(catalog_, host_);
  EXPECT_FALSE(Mapped(GDEFCORE_MODULE_EXAMPLE));
  EXPECT_EQ(0, IsEnabled(host_, request_, "example"));
  EXPECT_EQ(std::string("alpha"),
      AlterText(host_, request_, catalog_, "example.alter", "alpha"));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "example"));
  EXPECT_EQ(1, IsEnabled(host_, request_, "example"));
  EXPECT_EQ(std::string("alpha:touched"),
      AlterText(host_, request_, catalog_, "example.alter", "alpha"));
}

TEST_F(Module, Enable) {
  const char * names[] = {"example"};
  GDEFCORE_Changeset * changeset = NULL;
  uint64_t before = 0;
  uint64_t after = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, gdefcore_module_manifest));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, changeset, "example", 7));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &before));
  ASSERT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, "nope", 4));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(before, after);
  EXPECT_EQ(0, IsEnabled(host_, request_, "example"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "example", 7));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_NE(before, after);
  EXPECT_EQ(1, IsEnabled(host_, request_, "example"));
  gdefcore_changeset_destroy(changeset);
  (void)names;
}

TEST_F(Module, Access) {
  Vote guard;
  Vote sneak;
  const char * guard_name[] = {"guard"};
  const char * sneak_name[] = {"sneak"};
  memset(&guard, 0, sizeof guard);
  memset(&sneak, 0, sizeof sneak);
  guard.fail = 1;
  sneak.access = 1;
  InstallGuest(host_, "guard", kCoreToken, "demo.guard", GDEFCORE_HOOK_EVENT, 0, 1,
      NULL, OnVote, &guard, 0, NULL);
  InstallGuest(host_, "sneak", kCoreToken, "demo.sneak", GDEFCORE_HOOK_EVENT, 0, 0,
      NULL, OnVote, &sneak, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK,
      ApplyModules(host_, catalog_, request_, guard_name, 1, "guard"));
  ASSERT_EQ(GDEFCORE_OK,
      ApplyModules(host_, catalog_, request_, sneak_name, 1, "sneak"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.guard", 10,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
  EXPECT_EQ(1, guard.calls);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.sneak", 10,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
  EXPECT_EQ(1, sneak.calls);
  EXPECT_NE(std::string::npos, HostError(host_).find("Access"));
}

TEST_F(Module, WritePath) {
  Vote vote;
  const char * names[] = {"gate"};
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * changeset = NULL;
  uint64_t epoch = 0;
  uint64_t after = 0;
  memset(&vote, 0, sizeof vote);
  DefineNote(catalog_);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.note", 9, id, NULL));
  InstallGuest(host_, "gate", kCoreToken, "presave", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &vote, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "gate"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  SaveTitle(changeset, id, "old");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  changeset = NULL;
  EXPECT_EQ(1, vote.saw_request);
  EXPECT_EQ(std::string("old"), PublishedTitle(catalog_, id));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  vote.fail = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  SaveTitle(changeset, id, "new");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  EXPECT_EQ(std::string("old"), PublishedTitle(catalog_, id));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(epoch, after);
}

TEST_F(Module, AfterCommit) {
  Vote vote;
  const char * names[] = {"later"};
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * changeset = NULL;
  uint64_t before = 0;
  uint64_t after = 0;
  memset(&vote, 0, sizeof vote);
  vote.catalog = catalog_;
  DefineNote(catalog_);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(catalog_, "site.note", 9, id, NULL));
  memcpy(vote.id, id, sizeof vote.id);
  InstallGuest(host_, "later", kCoreToken, "after-commit", GDEFCORE_HOOK_EVENT, 0, 0,
      NULL, OnAfter, &vote, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "later"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  SaveTitle(changeset, id, "new");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &before));
  EXPECT_EQ(GDEFCORE_ERR_IO, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  EXPECT_EQ(1, vote.calls);
  EXPECT_EQ(1, vote.saw_request);
  EXPECT_EQ(GDEFCORE_OK, vote.seen_rc);
  EXPECT_EQ(std::string("new"), std::string(vote.seen, vote.seen_len));
  EXPECT_EQ(std::string("new"), PublishedTitle(catalog_, id));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_NE(before, after);
}

TEST_F(Module, SameOutput) {
  const char * names[] = {"example"};
  GDEFSTOR_Store * other_store = NULL;
  GDEFCORE_Catalog * other_catalog = NULL;
  GDEFCORE_Host * other_host = NULL;
  GDEFCORE_Request * other_request = NULL;
  const ExampleApi * api;
  char buf[32];
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, gdefcore_module_manifest));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "example"));
  EXPECT_EQ(std::string("alpha:touched"),
      AlterText(host_, request_, catalog_, "example.alter", "alpha"));
  api = (const ExampleApi *)gdefcore_module_service(host_, request_, "example.api",
      11, 1);
  ASSERT_NE(nullptr, api);
  ASSERT_EQ(0, api->append(buf, sizeof buf, "alpha", 5, &n));
  EXPECT_EQ(std::string("alpha:touched"), std::string(buf, n));
  EXPECT_EQ(nullptr,
      gdefcore_module_service(host_, request_, "example.api", 11, 99));
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &other_store));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(other_store, (const uint8_t *)kTenant, 1, NULL, NULL,
          &other_catalog));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(other_store, NULL, &other_host));
  gdefcore_catalog_bind_host(other_catalog, other_host);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_request_create((const uint8_t *)kTenant, 1, 0, 0, NULL,
          &other_request));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(other_host, GDEFCORE_MODULE_EXAMPLE,
          GDEFCORE_MODULE_TRUST_FULL));
  ASSERT_EQ(GDEFCORE_OK,
      ApplyModules(other_host, other_catalog, other_request, names, 1, "example"));
  EXPECT_EQ(std::string("alpha:touched"),
      AlterText(other_host, other_request, other_catalog, "example.alter", "alpha"));
  gdefcore_request_destroy(other_request);
  gdefcore_catalog_bind_host(other_catalog, NULL);
  gdefcore_host_destroy(other_host);
  gdefcore_catalog_destroy(other_catalog);
  gdefstor_store_destroy(other_store);
}

TEST_F(Module, WriteHooks) {
  Vote pre;
  Vote val;
  Vote sav;
  Vote rev;
  Vote del;
  const char * names[] = {"del", "pre", "rev", "sav", "val"};
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Changeset * changeset = NULL;
  uint64_t base = 99;
  uint64_t epoch = 0;
  uint64_t after = 0;
  memset(&pre, 0, sizeof pre);
  memset(&val, 0, sizeof val);
  memset(&sav, 0, sizeof sav);
  memset(&rev, 0, sizeof rev);
  memset(&del, 0, sizeof del);
  DefineNote(catalog_);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, "site.note", 9, id, NULL));
  InstallGuest(host_, "pre", kCoreToken, "presave", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &pre, 0, NULL);
  InstallGuest(host_, "val", kCoreToken, "validate", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &val, 0, NULL);
  InstallGuest(host_, "sav", kCoreToken, "save", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &sav, 0, NULL);
  InstallGuest(host_, "rev", kCoreToken, "revision", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &rev, 0, NULL);
  InstallGuest(host_, "del", kCoreToken, "delete", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &del, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK,
      ApplyModules(host_, catalog_, request_, names, 5, "del\npre\nrev\nsav\nval"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  SaveTitle(changeset, id, "kept");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_base_seq(changeset, id, strlen(id), &base));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  changeset = NULL;
  EXPECT_EQ(1, pre.calls);
  EXPECT_EQ(1, val.calls);
  EXPECT_EQ(1, sav.calls);
  EXPECT_EQ(1, rev.calls);
  EXPECT_EQ(0, del.calls);
  EXPECT_EQ(1, pre.saw_block);
  EXPECT_EQ(std::string(id), std::string(pre.arg_id, pre.arg_id_len));
  EXPECT_EQ(std::string("site.note"), std::string(pre.arg_type, pre.arg_type_len));
  EXPECT_EQ(base, pre.arg_seq);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  val.fail = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  SaveTitle(changeset, id, "next");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  changeset = NULL;
  EXPECT_EQ(2, val.calls);
  EXPECT_EQ(1, sav.calls);
  EXPECT_EQ(std::string("kept"), PublishedTitle(catalog_, id));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(epoch, after);
  val.fail = 0;
  sav.fail = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  SaveTitle(changeset, id, "next");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  changeset = NULL;
  EXPECT_EQ(2, sav.calls);
  EXPECT_EQ(1, rev.calls);
  EXPECT_EQ(std::string("kept"), PublishedTitle(catalog_, id));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(epoch, after);
  sav.fail = 0;
  rev.fail = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  SaveTitle(changeset, id, "next");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  changeset = NULL;
  EXPECT_EQ(2, rev.calls);
  EXPECT_EQ(std::string("kept"), PublishedTitle(catalog_, id));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(epoch, after);
  rev.fail = 0;
  del.fail = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, id, strlen(id), NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  changeset = NULL;
  EXPECT_EQ(1, del.calls);
  EXPECT_EQ(std::string("kept"), PublishedTitle(catalog_, id));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(epoch, after);
  del.fail = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_revert(catalog_, id, strlen(id), NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request_);
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
  gdefcore_changeset_destroy(changeset);
  EXPECT_EQ(2, del.calls);
  EXPECT_EQ(std::string(), PublishedTitle(catalog_, id));
}

TEST_F(Module, Disable) {
  Vote vote;
  const char * names[] = {"off"};
  GDEFCORE_Changeset * changeset = NULL;
  memset(&vote, 0, sizeof vote);
  InstallGuest(host_, "off", kCoreToken, "demo.off", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &vote, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "off"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.off", 8, GDEFCORE_HOOK_EVENT,
          NULL, NULL, NULL));
  EXPECT_EQ(1, vote.calls);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_disable(host_, changeset, "off", 3));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "off", 3));
  gdefcore_changeset_destroy(changeset);
  EXPECT_EQ(0, IsEnabled(host_, request_, "off"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.off", 8, GDEFCORE_HOOK_EVENT,
          NULL, NULL, NULL));
  EXPECT_EQ(1, vote.calls);
}

TEST_F(Module, RequiresInstalled) {
  const char * gone[] = {"gone"};
  const char * need[] = {"need"};
  InstallGuest(host_, "gone", kCoreToken, "demo.gone", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, NULL, 0, NULL);
  InstallGuest(host_, "need", kCoreToken, "demo.need", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, NULL, GDEFCORE_REL_REQUIRES, "gone");
  ASSERT_EQ(GDEFCORE_ERR_INVALID,
      ApplyModules(host_, catalog_, request_, need, 1, "need"));
  EXPECT_NE(std::string::npos, HostError(host_).find("absent"));
  EXPECT_EQ(0, IsEnabled(host_, request_, "need"));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, gone, 1, "gone"));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, need, 1, "need"));
  EXPECT_EQ(1, IsEnabled(host_, request_, "gone"));
  EXPECT_EQ(1, IsEnabled(host_, request_, "need"));
}

TEST_F(Module, EqualWeight) {
  const char * names[] = {"a", "b"};
  InstallGuest(host_, "b", kCoreToken, "demo.tie", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnAppend, (void *)"b", 0, NULL);
  InstallGuest(host_, "a", kCoreToken, "demo.tie", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnAppend, (void *)"a", 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "a\nb"));
  EXPECT_EQ(std::string("xab"), AlterText(host_, request_, catalog_, "demo.tie", "x"));
}

TEST_F(Module, Before) {
  const char * names[] = {"a", "b"};
  g_before = "a";
  InstallGuest(host_, "b", kCoreToken, "demo.before", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnAppend, (void *)"b", 0, NULL);
  InstallGuest(host_, "a", kCoreToken, "demo.before", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnAppend, (void *)"a", 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "a\nb"));
  EXPECT_EQ(std::string("xba"),
      AlterText(host_, request_, catalog_, "demo.before", "x"));
}

TEST_F(Module, BeforeCycle) {
  Vote unused;
  const char * names[] = {"a", "b"};
  uint64_t epoch = 0;
  memset(&unused, 0, sizeof unused);
  g_before = "b";
  InstallGuest(host_, "a", kCoreToken, "demo.bcycle", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnVote, &unused, 0, NULL);
  g_before = "a";
  InstallGuest(host_, "b", kCoreToken, "demo.bcycle", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnVote, &unused, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  ASSERT_EQ(GDEFCORE_ERR_INVALID,
      ApplyModules(host_, catalog_, request_, names, 2, "a\nb"));
  EXPECT_NE(std::string::npos, HostError(host_).find(" a"));
  EXPECT_NE(std::string::npos, HostError(host_).find(" b"));
  EXPECT_EQ(0, IsEnabled(host_, request_, "a"));
  {
    uint64_t after = 99;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
    EXPECT_EQ(epoch, after);
  }
}

TEST_F(Module, AlterSkip) {
  AppendState good;
  const char * names[] = {"bad", "good"};
  memset(&good, 0, sizeof good);
  good.extra = "Y";
  InstallGuest(host_, "bad", kCoreToken, "demo.skip", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnAppendThenFail, (void *)"Z", 0, NULL);
  InstallGuest(host_, "good", kCoreToken, "demo.skip", GDEFCORE_HOOK_ALTER, 0, 0, NULL,
      OnAppendCount, &good, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "bad\ngood"));
  EXPECT_EQ(std::string("xY"), AlterText(host_, request_, catalog_, "demo.skip", "x"));
  EXPECT_EQ(1, good.calls);
  {
    size_t n = 0;
    const char * skipped = gdefcore_hook_skipped_names(host_, &n);
    ASSERT_NE(nullptr, skipped);
    EXPECT_NE(std::string::npos, std::string(skipped, n).find("bad"));
  }
}

TEST_F(Module, DecisionFail) {
  Vote vote;
  const char * names[] = {"nope"};
  int decision = GDEFCORE_DECISION_ALLOW;
  memset(&vote, 0, sizeof vote);
  vote.fail = 1;
  vote.decision = GDEFCORE_DECISION_DENY;
  InstallGuest(host_, "nope", kCoreToken, "demo.dfail", GDEFCORE_HOOK_DECISION, 0, 0,
      NULL, OnVote, &vote, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "nope"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.dfail", 10,
          GDEFCORE_HOOK_DECISION, NULL, NULL, &decision));
  EXPECT_EQ(1, vote.calls);
}

TEST_F(Module, DecisionAbstain) {
  Vote one;
  Vote two;
  const char * names[] = {"one", "two"};
  int decision = GDEFCORE_DECISION_ALLOW;
  memset(&one, 0, sizeof one);
  memset(&two, 0, sizeof two);
  one.decision = GDEFCORE_DECISION_NONE;
  two.decision = GDEFCORE_DECISION_NONE;
  InstallGuest(host_, "one", kCoreToken, "demo.abstain", GDEFCORE_HOOK_DECISION, 0, 0,
      NULL, OnVote, &one, 0, NULL);
  InstallGuest(host_, "two", kCoreToken, "demo.abstain", GDEFCORE_HOOK_DECISION, 0, 0,
      NULL, OnVote, &two, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 2, "one\ntwo"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.abstain", 12,
          GDEFCORE_HOOK_DECISION, NULL, NULL, &decision));
  EXPECT_EQ(GDEFCORE_DECISION_DENY, decision);
  EXPECT_EQ(1, one.calls);
  EXPECT_EQ(1, two.calls);
}

TEST_F(Module, ServiceGate) {
  const char * names[] = {"example"};
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, gdefcore_module_manifest));
  EXPECT_EQ(nullptr, gdefcore_module_service(host_, request_, "example.api", 11, 1));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "example"));
  EXPECT_NE(nullptr, gdefcore_module_service(host_, request_, "example.api", 11, 1));
}

TEST_F(Module, ModulePatch) {
  Vote unused;
  const char * first[] = {"a"};
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  memset(&unused, 0, sizeof unused);
  InstallGuest(host_, "a", kCoreToken, "demo.patch", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &unused, 0, NULL);
  InstallGuest(host_, "b", kCoreToken, "demo.patch", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &unused, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, first, 1, "a"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_disable(host_, changeset, "a", 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, changeset, "b", 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(changeset, &files, &count));
  gdefcore_changeset_destroy(changeset);
  changeset = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_parse(catalog_, files, count, NULL, &changeset));
  gdefcore_patch_free(catalog_, files, count);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "a\nb", 3));
  gdefcore_changeset_destroy(changeset);
  EXPECT_EQ(0, IsEnabled(host_, request_, "a"));
  EXPECT_EQ(1, IsEnabled(host_, request_, "b"));
}

TEST_F(Module, ConfirmOrder) {
  Vote unused;
  GDEFCORE_Changeset * changeset = NULL;
  uint64_t epoch = 0;
  uint64_t after = 0;
  memset(&unused, 0, sizeof unused);
  InstallGuest(host_, "a", kCoreToken, "demo.confirm", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &unused, 0, NULL);
  InstallGuest(host_, "b", kCoreToken, "demo.confirm", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &unused, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &changeset));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, changeset, "b", 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, changeset, "a", 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &epoch));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(changeset, "b\na", 3));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(catalog_, &after));
  EXPECT_EQ(epoch, after);
  EXPECT_EQ(0, IsEnabled(host_, request_, "a"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "a\nb", 3));
  gdefcore_changeset_destroy(changeset);
  EXPECT_EQ(1, IsEnabled(host_, request_, "a"));
  EXPECT_EQ(1, IsEnabled(host_, request_, "b"));
}

TEST_F(Module, EnteredFlag) {
  const char * names[] = {"example"};
  GCU_Library library;
  typedef void (*SetDuring)(void (*)(void));
  SetDuring set_during;
  ASSERT_EQ(0, gcu_library_open(&library, GDEFCORE_MODULE_EXAMPLE));
  set_during = (SetDuring)gcu_library_symbol(library, "gdefcore_module_example_set_during");
  ASSERT_TRUE(set_during != NULL);
  g_probe_store = store_;
  g_entered_seen = -1;
  set_during(ProbeEntered);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(host_, GDEFCORE_MODULE_EXAMPLE,
          GDEFCORE_MODULE_TRUST_FULL));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "example"));
  EXPECT_EQ(std::string("alpha:touched"),
      AlterText(host_, request_, catalog_, "example.alter", "alpha"));
  EXPECT_EQ('1', g_entered_seen);
  ProbeEntered();
  EXPECT_EQ('0', g_entered_seen);
  set_during(NULL);
  g_probe_store = NULL;
  gcu_library_close(&library);
}

TEST_F(Module, SecondSubscriber) {
  Vote one;
  Vote two;
  const char * first[] = {"one"};
  const char * second[] = {"two"};
  memset(&one, 0, sizeof one);
  memset(&two, 0, sizeof two);
  InstallGuest(host_, "one", kCoreToken, "demo.more", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &one, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, first, 1, "one"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.more", 9, GDEFCORE_HOOK_EVENT,
          NULL, NULL, NULL));
  EXPECT_EQ(1, one.calls);
  InstallGuest(host_, "two", kCoreToken, "demo.more", GDEFCORE_HOOK_EVENT, 0, 0, NULL,
      OnVote, &two, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, second, 1, "two"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_hook_fire(host_, request_, catalog_, "demo.more", 9, GDEFCORE_HOOK_EVENT,
          NULL, NULL, NULL));
  EXPECT_EQ(2, one.calls);
  EXPECT_EQ(1, two.calls);
}

TEST_F(Module, RebindGuest) {
  const char * names[] = {"example"};
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, gdefcore_module_manifest));
  ASSERT_EQ(GDEFCORE_OK, ApplyModules(host_, catalog_, request_, names, 1, "example"));
  EXPECT_EQ(std::string("alpha:touched"),
      AlterText(host_, request_, catalog_, "example.alter", "alpha"));
  gdefcore_catalog_bind_host(catalog_, NULL);
  gdefcore_host_destroy(host_);
  host_ = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
  gdefcore_catalog_bind_host(catalog_, host_);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host_, gdefcore_module_manifest));
  EXPECT_EQ(1, IsEnabled(host_, request_, "example"));
  EXPECT_EQ(std::string("alpha:touched"),
      AlterText(host_, request_, catalog_, "example.alter", "alpha"));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
