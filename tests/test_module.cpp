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
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include "size_structs.h"

#include <gtest/gtest.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

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
  int found = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  g_entered_seen = -1;
  /* The installation's record of the module (a system record since story
   * S6b): one line per fact, `entered <hex>`. */
  if (g_probe_store == NULL ||
      gdefstor_record_get(g_probe_store, "\x01", 1, "core.module.install", 19,
          "example", 7, &found, &bytes, &len, NULL, NULL) != GDEFSTOR_OK ||
      !found) {
    gdefstor_bytes_free(NULL, bytes);
    return;
  }
  std::string text((const char *)bytes, len);
  gdefstor_bytes_free(NULL, bytes);
  size_t at = text.find("entered ");
  if (at != std::string::npos && (at == 0 || text[at - 1] == '\n') &&
      at + 10 <= text.size()) {
    g_entered_seen = (int)strtol(text.substr(at + 8, 2).c_str(), NULL, 16);
  }
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
  g_man.schema_version = 1;
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

void InstallKit(GDEFCORE_Catalog * catalog) {
  uint8_t * kit = NULL;
  size_t kit_len = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog, &kit, &kit_len));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog, kit, kit_len));
  gdefcore_text_free(catalog, (char *)kit);
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
    /* The example module declares a variable for the built-in `core.page`
     * kind, and enabling a module whose variable names a kind that does not
     * exist is refused. */
    InstallKit(catalog_);
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
  g_man.schema_version = 1;
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
  InstallKit(other_catalog);
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


/* ==========================================================================
 * The tables a manifest declares (site-admin epic, story 5): routes, menu
 * links, settings and template variables. One test per row of the story's
 * matrix. Every refusal has a control (the same module with the one fault
 * removed is accepted), and every "nothing changed" is read from the
 * canonical dump of every enumeration, taken before and after. The real-source
 * plants are in tools/check-manifest.sh.
 * ======================================================================== */

namespace manifest {

struct RouteDef {
  std::string name;
  std::string path;
  int weight = 0;
  int after = 0;
  std::string permission;
  std::string title;
  int kind = GDEFCORE_ROUTE_PAGE;
  std::string parent;
  int is_default = 0;
  int admin = 0;
  std::string handler = "@"; /* "@" is this module's handler service */
};

struct LinkDef {
  std::string name;
  std::string menu = "main";
  std::string label = "Link";
  std::string route;
  int weight = 0;
  std::string parent;
  int kind = GDEFCORE_ROUTE_PAGE;
};

struct SettingDef {
  std::string name;
  std::string type = "text";
  std::string value;
  std::string label = "Setting";
  std::string description;
  int local = 0;
  std::string group;
};

struct VarDef {
  std::string kind = "core.page";
  std::string name;
  std::string type = "number";
  std::string description;
  std::string provider = "@"; /* "@" is this module's provider service */
  int principal_free = 1;
};

extern "C" void GuestRoute(const GDEFCORE_Route_Call * call) {
  const char * id = NULL;
  size_t id_len = 0;
  gdefcore_request_set_resolution(call->request, call->machine,
      call->machine_len);
  if (gdefcore_route_call_capture(call, "id", 2, &id, &id_len)) {
    gdefcore_request_set_note(call->request, "id", 2, id, id_len);
  }
  if (call->data != NULL) {
    gdefcore_request_set_note(call->request, "tag", 3, (const char *)call->data,
        strlen((const char *)call->data));
  }
}

extern "C" GDEFCORE_Result GuestProvide(GDEFCORE_Request * request, void * user,
    GDEFCORE_Contribution_Value * out) {
  (void)request;
  (void)user;
  out->kind = GDEFCORE_CONTRIBUTION_INTEGER;
  out->integer = 7;
  return GDEFCORE_OK;
}

extern "C" GDEFCORE_Result GuestHook(GDEFCORE_Request * request,
    const void * args, GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out,
    void * user) {
  (void)request;
  (void)args;
  (void)alter;
  (void)out;
  (void)user;
  return GDEFCORE_OK;
}

extern "C" GDEFCORE_Result SizeCallback(GDEFCORE_Callback_Call * call,
    GDEFCORE_Request * request, const GDEFCORE_Callback_Question * question,
    GDEFCORE_Callback_Answer * answer, void * user) {
  (void)call;
  (void)request;
  (void)question;
  (void)answer;
  (void)user;
  return GDEFCORE_OK;
}

extern "C" GDEFCORE_Result SizeStep(GDEFCORE_Migration * migration, void * user) {
  (void)migration;
  (void)user;
  return GDEFCORE_OK;
}

extern "C" GDEFCORE_Result SizeUp(const char * type, size_t type_len,
    const GDEFSTOR_Type * decl, GDEFSTOR_Tree * tree, void * user) {
  (void)type;
  (void)type_len;
  (void)decl;
  (void)tree;
  (void)user;
  return GDEFCORE_OK;
}

template <class T>
T Sized() {
  T value;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  return value;
}

/** What a manifest declares beyond the tables a Guest builds from its defs:
 * one of each remaining entry, for the sizes test to mutate. */
struct Extra {
  std::vector<GDEFCORE_Module_Rel> rels;
  std::vector<GDEFCORE_Module_Perm> perms;
  std::vector<GDEFCORE_Module_Grant> grants;
  std::vector<GDEFCORE_Module_Relation> relations;
  std::vector<GDEFCORE_Module_Relation_Column> cols;
  std::vector<GDEFCORE_Module_Callback> callbacks;
  GDEFCORE_Module_Access_Callback cbtable;
  std::vector<GDEFCORE_Module_Step> steps;
  std::vector<GDEFCORE_Module_Upcaster> ups;
  std::string cbservice;
};

/** One guest module: its definitions, and the C tables built from them. */
struct Guest {
  int slot = 0;
  std::string name;
  std::string tag;
  std::string before;
  std::string after;
  std::vector<RouteDef> routes;
  std::vector<LinkDef> links;
  std::vector<SettingDef> settings;
  std::vector<VarDef> vars;
  std::vector<GDEFCORE_Module_Route> croutes;
  std::vector<GDEFCORE_Module_Link> clinks;
  std::vector<GDEFCORE_Module_Setting> csettings;
  std::vector<GDEFCORE_Module_Variable> cvars;
  std::vector<GDEFCORE_Module_Service> svcs;
  std::string handler_name;
  std::string provider_name;
  std::string hook_name;
  GDEFCORE_Module_Route_Handler handler;
  GDEFCORE_Module_Variable_Provider provider;
  GDEFCORE_Module_Sub sub;
  GDEFCORE_Module_Manifest man;
  Extra extra;

  /** Add one entry of every kind the defs do not build (call after Build). */
  void Extras() {
    Extra & x = extra;
    x.rels = {Sized<GDEFCORE_Module_Rel>()};
    x.rels[0].kind = GDEFCORE_REL_ENHANCES;
    x.rels[0].name = "other";
    x.rels[0].name_len = 5;
    x.perms = {Sized<GDEFCORE_Module_Perm>()};
    x.perms[0].label = "size probe perm";
    x.perms[0].label_len = 15;
    x.perms[0].action = "read";
    x.perms[0].action_len = 4;
    x.perms[0].type_name = "t.size";
    x.perms[0].type_name_len = 6;
    x.perms[0].condition = GDEFCORE_ACCESS_ANY;
    x.grants = {Sized<GDEFCORE_Module_Grant>()};
    x.grants[0].permission = "size probe perm";
    x.grants[0].permission_len = 15;
    x.grants[0].type_name = "t.size";
    x.grants[0].type_name_len = 6;
    x.grants[0].condition = "true";
    x.grants[0].condition_len = 4;
    x.cols = {Sized<GDEFCORE_Module_Relation_Column>(),
        Sized<GDEFCORE_Module_Relation_Column>()};
    x.cols[0].name = "a";
    x.cols[0].name_len = 1;
    x.cols[0].kind = GDEFCORE_RELATION_ENTITY;
    x.cols[0].type_name = "t.size";
    x.cols[0].type_name_len = 6;
    x.cols[1].name = "b";
    x.cols[1].name_len = 1;
    x.cols[1].kind = GDEFCORE_RELATION_TEXT;
    x.relations = {Sized<GDEFCORE_Module_Relation>()};
    x.relations[0].name = "link";
    x.relations[0].name_len = 4;
    x.relations[0].columns = x.cols.data();
    x.relations[0].ncolumns = x.cols.size();
    x.cbtable = Sized<GDEFCORE_Module_Access_Callback>();
    x.cbtable.fn = SizeCallback;
    x.cbservice = name + ".cb.paid";
    {
      GDEFCORE_Module_Service s = Sized<GDEFCORE_Module_Service>();
      s.name = x.cbservice.data();
      s.name_len = x.cbservice.size();
      s.version = GDEFCORE_MODULE_ACCESS_CALLBACK_VERSION;
      s.table = &x.cbtable;
      svcs.push_back(s);
    }
    x.callbacks = {Sized<GDEFCORE_Module_Callback>()};
    x.callbacks[0].name = "paid";
    x.callbacks[0].name_len = 4;
    x.callbacks[0].scope = GDEFCORE_CALLBACK_FIELD;
    x.callbacks[0].permission = "size probe perm";
    x.callbacks[0].permission_len = 15;
    x.callbacks[0].type_name = "t.size";
    x.callbacks[0].type_name_len = 6;
    x.callbacks[0].field = "body";
    x.callbacks[0].field_len = 4;
    x.callbacks[0].service = x.cbservice.data();
    x.callbacks[0].service_len = x.cbservice.size();
    x.callbacks[0].fuel = 100;
    x.callbacks[0].timeout_ms = 500;
    x.callbacks[0].cache = GDEFCORE_CALLBACK_CACHE_TOKEN;
    x.steps = {Sized<GDEFCORE_Module_Step>()};
    x.steps[0].from = 1;
    x.steps[0].fn = SizeStep;
    x.ups = {Sized<GDEFCORE_Module_Upcaster>()};
    x.ups[0].from = 1;
    x.ups[0].fn = SizeUp;
    man.schema_version = 2;
    man.rels = x.rels.data();
    man.nrels = x.rels.size();
    man.perms = x.perms.data();
    man.nperms = x.perms.size();
    man.grants = x.grants.data();
    man.ngrants = x.grants.size();
    man.relations = x.relations.data();
    man.nrelations = x.relations.size();
    man.callbacks = x.callbacks.data();
    man.ncallbacks = x.callbacks.size();
    man.steps = x.steps.data();
    man.nsteps = x.steps.size();
    man.upcasters = x.ups.data();
    man.nupcasters = x.ups.size();
    man.services = svcs.data();
    man.nservices = svcs.size();
  }

  void Build() {
    handler_name = name + ".handler";
    provider_name = name + ".provider";
    hook_name = name + ".event";
    for (RouteDef & r : routes) {
      if (r.handler == "@") {
        r.handler = handler_name;
      }
    }
    for (VarDef & v : vars) {
      if (v.provider == "@") {
        v.provider = provider_name;
      }
    }
    croutes.clear();
    for (const RouteDef & r : routes) {
      GDEFCORE_Module_Route c;
      memset(&c, 0, sizeof c);
      c.size = sizeof c;
      c.name = r.name.data();
      c.name_len = r.name.size();
      c.path = r.path.data();
      c.path_len = r.path.size();
      c.weight = r.weight;
      c.after = r.after;
      if (!r.permission.empty()) {
        c.permission = r.permission.data();
        c.permission_len = r.permission.size();
      }
      if (!r.title.empty()) {
        c.title = r.title.data();
        c.title_len = r.title.size();
      }
      c.kind = r.kind;
      if (!r.parent.empty()) {
        c.parent = r.parent.data();
        c.parent_len = r.parent.size();
      }
      c.is_default = r.is_default;
      c.admin = r.admin;
      c.handler = r.handler.data();
      c.handler_len = r.handler.size();
      croutes.push_back(c);
    }
    clinks.clear();
    for (const LinkDef & l : links) {
      GDEFCORE_Module_Link c;
      memset(&c, 0, sizeof c);
      c.size = sizeof c;
      c.name = l.name.data();
      c.name_len = l.name.size();
      c.menu = l.menu.data();
      c.menu_len = l.menu.size();
      c.label = l.label.data();
      c.label_len = l.label.size();
      c.route = l.route.data();
      c.route_len = l.route.size();
      c.weight = l.weight;
      c.parent = l.parent.data();
      c.parent_len = l.parent.size();
      c.kind = l.kind;
      clinks.push_back(c);
    }
    csettings.clear();
    for (const SettingDef & t : settings) {
      GDEFCORE_Module_Setting c;
      memset(&c, 0, sizeof c);
      c.size = sizeof c;
      c.name = t.name.data();
      c.name_len = t.name.size();
      c.type = t.type.data();
      c.type_len = t.type.size();
      c.default_value = t.value.data();
      c.default_len = t.value.size();
      c.label = t.label.data();
      c.label_len = t.label.size();
      c.description = t.description.data();
      c.description_len = t.description.size();
      c.environment_local = t.local;
      c.group = t.group.data();
      c.group_len = t.group.size();
      csettings.push_back(c);
    }
    cvars.clear();
    for (const VarDef & v : vars) {
      GDEFCORE_Module_Variable c;
      memset(&c, 0, sizeof c);
      c.size = sizeof c;
      c.kind = v.kind.data();
      c.kind_len = v.kind.size();
      c.name = v.name.data();
      c.name_len = v.name.size();
      c.type = v.type.data();
      c.type_len = v.type.size();
      c.description = v.description.data();
      c.description_len = v.description.size();
      c.provider = v.provider.data();
      c.provider_len = v.provider.size();
      c.principal_free = v.principal_free;
      cvars.push_back(c);
    }
    memset(&handler, 0, sizeof handler);
    handler.size = sizeof handler;
    handler.call_fn = GuestRoute;
    handler.data = (void *)tag.c_str();
    memset(&provider, 0, sizeof provider);
    provider.size = sizeof provider;
    provider.provider = GuestProvide;
    svcs.clear();
    {
      GDEFCORE_Module_Service s;
      memset(&s, 0, sizeof s);
      s.size = sizeof s;
      s.name = handler_name.data();
      s.name_len = handler_name.size();
      s.version = GDEFCORE_MODULE_ROUTE_HANDLER_VERSION;
      s.table = &handler;
      svcs.push_back(s);
      s.name = provider_name.data();
      s.name_len = provider_name.size();
      s.version = GDEFCORE_MODULE_VARIABLE_PROVIDER_VERSION;
      s.table = &provider;
      svcs.push_back(s);
    }
    memset(&sub, 0, sizeof sub);
    sub.size = sizeof sub;
    sub.hook = hook_name.data();
    sub.hook_len = hook_name.size();
    sub.kind = GDEFCORE_HOOK_EVENT;
    sub.fn = GuestHook;
    if (!before.empty()) {
      sub.before = before.data();
      sub.before_len = before.size();
    }
    if (!after.empty()) {
      sub.after = after.data();
      sub.after_len = after.size();
    }
    memset(&man, 0, sizeof man);
    man.size = sizeof man;
    man.core_token = kCoreToken;
    man.core_token_len = strlen(kCoreToken);
    man.schema_version = 1;
    man.name = name.data();
    man.name_len = name.size();
    man.label = name.data();
    man.label_len = name.size();
    man.subs = &sub;
    man.nsubs = 1;
    man.services = svcs.data();
    man.nservices = svcs.size();
    man.routes = croutes.data();
    man.nroutes = croutes.size();
    man.links = clinks.data();
    man.nlinks = clinks.size();
    man.settings = csettings.data();
    man.nsettings = csettings.size();
    man.variables = cvars.data();
    man.nvariables = cvars.size();
  }
};

const int kPool = 160;
Guest * g_guest[kPool];

template <int I>
const GDEFCORE_Module_Manifest * PoolEntry(void) {
  return &g_guest[I]->man;
}

template <int... I>
std::array<GDEFCORE_Module_Entry, sizeof...(I)> MakeEntries(
    std::integer_sequence<int, I...>) {
  return {{PoolEntry<I>...}};
}

const std::array<GDEFCORE_Module_Entry, kPool> kEntries =
    MakeEntries(std::make_integer_sequence<int, kPool>());

/** Owns the guests of one test. Their entries are fixed slots. */
class Pool {
 public:
  Guest * Add(const std::string & name) {
    int slot = (int)guests_.size();
    guests_.emplace_back(new Guest());
    Guest * g = guests_.back().get();
    g->slot = slot;
    g->name = name;
    g->tag = name + "-tag";
    g_guest[slot] = g;
    return g;
  }
  void Reset() {
    guests_.clear();
    memset(g_guest, 0, sizeof g_guest);
  }

 private:
  std::vector<std::unique_ptr<Guest>> guests_;
};

Pool & ThePool() {
  static Pool pool;
  return pool;
}

const std::string bad8 = "\xff\xfe";

std::string Rep(char c, size_t n) {
  return std::string(n, c);
}

std::string Join(const std::vector<std::string> & v, const char * sep) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    out += (i == 0 ? "" : sep) + v[i];
  }
  return out;
}

uint64_t Fnv(const std::string & text) {
  uint64_t h = 1469598103934665603ULL;
  for (unsigned char c : text) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  return h;
}

/** A module with something in every table. */
Guest * Rich(const std::string & n, const std::string & before = "",
    const std::string & after = "", bool edge = false) {
  Guest * g = ThePool().Add(n);
  g->before = before;
  g->after = after;
  RouteDef page;
  page.name = n + ".zpage";
  page.path = "/" + n + "/:id";
  page.permission = "view " + n;
  page.title = "Z page";
  RouteDef a;
  a.name = n + ".atab";
  a.path = "/" + n + "/:id/a";
  a.kind = GDEFCORE_ROUTE_TAB;
  a.parent = n + ".zpage";
  a.is_default = 1;
  a.title = "A tab";
  RouteDef b;
  b.name = n + ".btab";
  b.path = "/" + n + "/:id/b";
  b.kind = GDEFCORE_ROUTE_TAB;
  b.parent = n + ".zpage";
  b.weight = 1;
  b.permission = "edit " + n;
  b.title = "B tab";
  RouteDef add;
  add.name = n + ".add";
  add.path = "/" + n + "/add";
  add.kind = GDEFCORE_ROUTE_ACTION;
  add.title = "Add";
  add.permission = "add " + n;
  RouteDef admin;
  admin.name = n + ".admin";
  admin.path = "/admin/" + n;
  admin.admin = 1;
  admin.title = n + " admin";
  g->routes = {page, a, b, add, admin};
  LinkDef main;
  main.name = n + ".l.main";
  main.label = "Main " + n;
  main.route = n + ".zpage";
  LinkDef sub;
  sub.name = n + ".l.sub";
  sub.label = "Sub " + n;
  sub.route = n + ".btab";
  sub.weight = 1;
  sub.parent = n + ".l.main";
  sub.kind = GDEFCORE_ROUTE_TAB;
  LinkDef adm;
  adm.name = n + ".l.admin";
  adm.menu = "admin";
  adm.label = n;
  adm.route = n + ".admin";
  adm.weight = 3;
  g->links = {main, sub, adm};
  SettingDef title;
  title.name = n + ".title";
  title.value = "T-" + n;
  title.label = "Title";
  title.description = "The title.";
  title.group = "general";
  SettingDef secret;
  secret.name = n + ".secret";
  secret.label = "Secret";
  secret.local = 1;
  secret.group = "keys";
  SettingDef mx;
  mx.name = n + ".max";
  mx.type = "number";
  mx.value = "5";
  SettingDef on;
  on.name = n + ".on";
  on.type = "boolean";
  on.value = "true";
  g->settings = {title, secret, mx, on};
  VarDef count;
  count.kind = "core.pane";
  count.name = n + ".count";
  count.description = "How many.";
  VarDef motd;
  motd.kind = "core.page";
  motd.name = n + ".motd";
  motd.type = "text";
  motd.principal_free = 0;
  g->vars = {count, motd};
  if (edge) {
    /* Every limit, exactly: accepted, where one more byte is refused below. */
    RouteDef e;
    e.name = n + "." + Rep('r', GDEFCORE_MODULE_DECL_NAME_MAX - n.size() - 1);
    e.path = "/" + Rep('e', GDEFCORE_ROUTE_PATH_MAX - 1);
    for (int i = 0; i < GDEFCORE_ROUTE_TITLE_MAX / 2; i++) {
      e.title += "\xc3\xa9";
    }
    e.permission = Rep('p', GDEFCORE_ROUTE_PERMISSION_MAX);
    g->routes.push_back(e);
    LinkDef l;
    l.name = n + "." + Rep('l', GDEFCORE_MODULE_DECL_NAME_MAX - n.size() - 1);
    l.route = e.name;
    l.label.clear();
    for (int i = 0; i < GDEFCORE_MODULE_DECL_LABEL_MAX / 2; i++) {
      l.label += "\xc3\xa9";
    }
    g->links.push_back(l);
    SettingDef s;
    s.name = n + "." + Rep('s', GDEFCORE_MODULE_DECL_NAME_MAX - n.size() - 1);
    s.value = Rep('v', GDEFCORE_MODULE_DECL_TEXT_MAX - 1) + "\n";
    s.description = Rep('d', GDEFCORE_MODULE_DECL_TEXT_MAX - 1) + "\t";
    s.label.clear();
    for (int i = 0; i < GDEFCORE_MODULE_DECL_LABEL_MAX / 2; i++) {
      s.label += "\xc3\xa9";
    }
    s.group = Rep('g', 64);
    g->settings.push_back(s);
    VarDef v;
    v.name = n + ".v";
    v.kind = "core.pane";
    v.type = "markup";
    v.description = Rep('x', 256);
    g->vars.push_back(v);
  }
  g->Build();
  return g;
}

/** The smallest module that declares one of everything, for mutation. */
Guest * Mini(const std::string & n) {
  Guest * g = ThePool().Add(n);
  RouteDef page;
  page.name = n + ".page";
  page.path = "/" + n + "/:id";
  RouteDef tab;
  tab.name = n + ".tab";
  tab.path = "/" + n + "/:id/t";
  tab.kind = GDEFCORE_ROUTE_TAB;
  tab.parent = n + ".page";
  g->routes = {page, tab};
  LinkDef l;
  l.name = n + ".l";
  l.route = n + ".page";
  g->links = {l};
  SettingDef s;
  s.name = n + ".s";
  s.value = "x";
  g->settings = {s};
  VarDef v;
  v.name = n + ".v";
  g->vars = {v};
  return g;
}

/** The world a test runs in: a store, a catalog with the kit, a host. */
struct World {
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Host * host = NULL;
  GDEFCORE_Request * request = NULL;
  /** Where the last operation was refused, "enable", "apply" or "". */
  std::string where;
  std::string message;
  /** A principal that exists: the one a policy lets in. */
  std::string editor;

  void Open(GDEFSTOR_Store * shared = NULL) {
    const uint8_t tenant[] = {'t'};
    if (shared == NULL) {
      EXPECT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
    } else {
      store = shared;
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store, tenant, 1, NULL, NULL, &catalog));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_host_open(store, NULL, &host));
    gdefcore_catalog_bind_host(catalog, host);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create(tenant, 1, 0, 0, NULL, &request));
    if (shared == NULL) {
      InstallKit(catalog);
    }
    {
      char who[GDEFCORE_PUBLIC_ID_LEN + 1];
      EXPECT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog, who));
      editor = who;
    }
  }

  void Close(bool destroy_store = true) {
    gdefcore_request_destroy(request);
    gdefcore_catalog_bind_host(catalog, NULL);
    gdefcore_host_destroy(host);
    gdefcore_catalog_destroy(catalog);
    if (destroy_store) {
      gdefstor_store_destroy(store);
    }
    request = NULL;
    host = NULL;
    catalog = NULL;
  }

  void Install(Guest * g) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_module_install_guest(host, kEntries[g->slot]))
        << HostError(host);
  }

  /** Enable or disable each name in one changeset. */
  GDEFCORE_Result Ops(const std::vector<std::pair<std::string, bool>> & ops,
      bool via_stage_module = false) {
    GDEFCORE_Changeset * cs = NULL;
    std::vector<std::string> names;
    GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog, NULL, 0, &cs);
    where.clear();
    message.clear();
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    gdefcore_changeset_set_request(cs, request);
    for (const auto & op : ops) {
      names.push_back(op.first);
      if (via_stage_module) {
        /* Past the check enable makes, so apply has to make its own. */
        rc = gdefcore_changeset_stage_module(cs, op.first.data(),
            op.first.size(), op.second ? 1 : 0);
      } else if (op.second) {
        rc = gdefcore_module_enable(host, cs, op.first.data(), op.first.size());
      } else {
        rc = gdefcore_module_disable(host, cs, op.first.data(), op.first.size());
      }
      if (rc != GDEFCORE_OK) {
        where = "stage";
        message = HostError(host);
        EXPECT_EQ(0u, gdefcore_changeset_module_count(cs) -
                          (size_t)(&op - &ops[0]))
            << "a refusal stages nothing for the refused module";
        gdefcore_changeset_destroy(cs);
        return rc;
      }
    }
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    std::string confirm = Join(names, "\n");
    rc = gdefcore_changeset_apply(cs, confirm.data(), confirm.size());
    if (rc != GDEFCORE_OK) {
      size_t n = 0;
      const char * r = gdefcore_changeset_refusal(cs, &n);
      where = "apply";
      message = (r == NULL ? std::string() : std::string(r, n)) + " " +
                HostError(host);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Enable(const std::string & name, bool via_stage = false) {
    return Ops({{name, true}}, via_stage);
  }

  GDEFCORE_Result Disable(const std::string & name) {
    return Ops({{name, false}});
  }

  /** A changeset that has staged ops and is not applied. */
  GDEFCORE_Changeset * Staged(const std::vector<std::pair<std::string, bool>> & ops) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &cs));
    for (const auto & op : ops) {
      EXPECT_EQ(GDEFCORE_OK,
          op.second ? gdefcore_module_enable(host, cs, op.first.data(),
                          op.first.size())
                    : gdefcore_module_disable(host, cs, op.first.data(),
                          op.first.size()));
    }
    return cs;
  }

  /** The canonical dump of every enumeration. Nothing in it is a pointer. */
  std::string Dump(const GDEFCORE_Changeset * projection = NULL) {
    const uint8_t t[] = {'t'};
    std::string out;
    {
      const GDEFCORE_Module_Declared_Route ** items = NULL;
      size_t n = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_module_routes(host, t, 1, projection, &items, &n));
      for (size_t i = 0; i < n; i++) {
        const GDEFCORE_Module_Declared_Route * r = items[i];
        const GDEFCORE_Route_Spec & s = r->spec;
        out += "route " + std::string(r->module, r->module_len) + " " +
               std::string(s.machine, s.machine_len) + " " +
               std::string(s.path, s.path_len) + " w=" +
               std::to_string(s.weight) + " after=" + std::to_string(s.after) +
               " perm=" + (s.permission == NULL ? std::string("-")
                                                : std::string(s.permission, s.permission_len)) +
               " title=" + (s.title == NULL ? std::string("-")
                                            : std::string(s.title, s.title_len)) +
               " kind=" + std::to_string(s.kind) + " parent=" +
               (s.parent == NULL ? std::string("-")
                                 : std::string(s.parent, s.parent_len)) +
               " default=" + std::to_string(s.is_default) + " admin=" +
               std::to_string(r->admin) + " fn=" +
               std::to_string(s.call_fn != NULL) + " data=" +
               (s.data == NULL ? std::string("-") : std::string((const char *)s.data)) +
               "\n";
      }
      gdefcore_module_declared_free(host, items);
    }
    {
      const GDEFCORE_Module_Declared_Link ** items = NULL;
      size_t n = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_module_links(host, t, 1, projection, &items, &n));
      for (size_t i = 0; i < n; i++) {
        const GDEFCORE_Module_Declared_Link * l = items[i];
        out += "link " + std::string(l->module, l->module_len) + " " +
               std::string(l->name, l->name_len) + " menu=" +
               std::string(l->menu, l->menu_len) + " label=" +
               std::string(l->label, l->label_len) + " route=" +
               std::string(l->route, l->route_len) + " w=" +
               std::to_string(l->weight) + " parent=" +
               std::string(l->parent, l->parent_len) + " kind=" +
               std::to_string(l->kind) + "\n";
      }
      gdefcore_module_declared_free(host, items);
    }
    {
      const GDEFCORE_Module_Declared_Setting ** items = NULL;
      size_t n = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_module_settings(host, t, 1, projection, &items, &n));
      for (size_t i = 0; i < n; i++) {
        const GDEFCORE_Module_Declared_Setting * s = items[i];
        out += "setting " + std::string(s->module, s->module_len) + " " +
               std::string(s->name, s->name_len) + " type=" +
               std::string(s->type, s->type_len) + " default=[" +
               std::string(s->default_value, s->default_len) + "] label=" +
               std::string(s->label, s->label_len) + " desc=[" +
               std::string(s->description, s->description_len) + "] local=" +
               std::to_string(s->environment_local) + " group=" +
               std::string(s->group, s->group_len) + "\n";
      }
      gdefcore_module_declared_free(host, items);
    }
    {
      const GDEFCORE_Module_Contributed ** items = NULL;
      size_t n = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_module_variables(host, t, 1, projection, &items, &n));
      for (size_t i = 0; i < n; i++) {
        const GDEFCORE_Module_Contributed * v = items[i];
        GDEFCORE_Contribution_Value value;
        memset(&value, 0, sizeof value);
        value.size = sizeof value;
        GDEFCORE_Result rc = v->provider(NULL, v->user, &value);
        out += "variable " + std::string(v->module, v->module_len) + " " +
               std::string(v->kind, v->kind_len) + " " +
               std::string(v->name, v->name_len) + " type=" +
               std::string(v->type, v->type_len) + " desc=[" +
               std::string(v->description, v->description_len) + "] free=" +
               std::to_string(v->principal_free) + " answer=" +
               std::to_string(rc) + "/" + std::to_string(value.kind) + "/" +
               std::to_string((long long)value.integer) + "\n";
      }
      gdefcore_module_declared_free(host, items);
    }
    for (const char * kind : {"core.page", "core.pane"}) {
      const GDEFCORE_Module_Contributed ** items = NULL;
      size_t n = 0;
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_module_contributions(host, t, 1, projection, kind,
              strlen(kind), &items, &n));
      out += std::string("contributions ") + kind + ":";
      for (size_t i = 0; i < n; i++) {
        out += " " + std::string(items[i]->name, items[i]->name_len);
      }
      out += "\n";
      gdefcore_module_contributions_free(host, items);
    }
    return out;
  }

  /** The route table the enabled modules make, probed. */
  std::string TableDump() {
    const uint8_t t[] = {'t'};
    GDEFCORE_Routes * routes = NULL;
    const GDEFCORE_Module_Declared_Route ** items = NULL;
    size_t n = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_routes_set_check(routes, AllowAll, NULL));
    char * error = NULL;
    size_t error_len = 0;
    GDEFCORE_Result rc =
        gdefcore_module_add_routes(host, t, 1, NULL, routes, &error, &error_len);
    EXPECT_EQ(GDEFCORE_OK, rc) << (error == NULL ? "" : std::string(error, error_len));
    gdefcore_routes_free(routes, error);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_module_routes(host, t, 1, NULL, &items, &n));
    for (size_t i = 0; i < n; i++) {
      std::string path(items[i]->spec.path, items[i]->spec.path_len);
      std::string probe;
      size_t at = 0;
      while (at < path.size()) {
        size_t end = path.find('/', at + 1);
        std::string seg = path.substr(at, end == std::string::npos
                                              ? std::string::npos : end - at);
        if (seg.size() > 1 && seg[1] == ':') {
          seg = "/7";
        } else if (seg == "/*") {
          seg = "/s";
        }
        probe += seg;
        at = end == std::string::npos ? path.size() : end;
      }
      out += "probe " + probe + " ->" + Resolve(routes, probe, "p") + "\n";
      if (items[i]->spec.kind == GDEFCORE_ROUTE_PAGE) {
        GDEFCORE_Route_Info * info = NULL;
        size_t count = 0;
        EXPECT_EQ(GDEFCORE_OK,
            gdefcore_routes_tabs(routes, items[i]->spec.machine,
                items[i]->spec.machine_len, &info, &count));
        out += "tabs of " + std::string(items[i]->spec.machine,
                                 items[i]->spec.machine_len) + ":";
        for (size_t k = 0; k < count; k++) {
          out += " " + std::string(info[k].machine, info[k].machine_len) +
                 (info[k].is_default ? "*" : "");
        }
        out += "\n";
        gdefcore_routes_free(routes, info);
      }
    }
    gdefcore_module_declared_free(host, items);
    gdefcore_routes_destroy(routes);
    return out;
  }

  /** What one request to the table observes. */
  std::string Resolve(GDEFCORE_Routes * routes, const std::string & path,
      const std::string & principal) {
    GDEFCORE_Request * req = NULL;
    const uint8_t t[] = {'t'};
    char * res = NULL;
    size_t res_len = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_create(t, 1, 0, 0, NULL, &req));
    if (!principal.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_principal(req, editor.data(), editor.size()));
    }
    GDEFCORE_Result rc = gdefcore_form_resolve(routes, catalog, req, path.data(),
        path.size(), &res, &res_len);
    out = rc == GDEFCORE_OK ? std::string(" rc=ok") : std::string(" rc=none");
    if (rc == GDEFCORE_OK) {
      out += " res=" + std::string(res, res_len);
      gdefcore_text_free(catalog, res);
    }
    for (const char * key : {"id", "tag", "example.id", "example.data"}) {
      size_t len = 0;
      const char * v = gdefcore_request_note(req, key, strlen(key), &len);
      if (v != NULL) {
        out += std::string(" ") + key + "=" + std::string(v, len);
      }
    }
    gdefcore_request_destroy(req);
    return out;
  }

  static int AllowAll(const GDEFCORE_Route_Call * call, const char * permission,
      size_t permission_len, void * data) {
    (void)call;
    (void)permission;
    (void)permission_len;
    (void)data;
    return 1;
  }
};

/** Find the first line of @p dump that contains @p needle. */
size_t Count(const std::string & text, const std::string & needle) {
  size_t n = 0;
  size_t at = 0;
  while ((at = text.find(needle, at)) != std::string::npos) {
    n += 1;
    at += needle.size();
  }
  return n;
}

/** The module names, in the order the dump lists a table's lines. */
std::vector<std::string> ModuleOrder(const std::string & dump,
    const std::string & table) {
  std::vector<std::string> out;
  size_t at = 0;
  while (at < dump.size()) {
    size_t end = dump.find('\n', at);
    std::string line = dump.substr(at, end - at);
    if (line.compare(0, table.size() + 1, table + " ") == 0) {
      size_t a = table.size() + 1;
      std::string m = line.substr(a, line.find(' ', a) - a);
      if (out.empty() || out.back() != m) {
        out.push_back(m);
      }
    }
    at = end == std::string::npos ? dump.size() : end + 1;
  }
  return out;
}

/** The second field of each line of one table, in the order listed. */
std::vector<std::string> Names(const std::string & dump, const std::string & table) {
  std::vector<std::string> out;
  size_t at = 0;
  while (at < dump.size()) {
    size_t end = dump.find('\n', at);
    std::string line = dump.substr(at, end - at);
    if (line.compare(0, table.size() + 1, table + " ") == 0) {
      size_t a = line.find(' ', table.size() + 1) + 1;
      size_t b = line.find(' ', a);
      if (table == "variable") {
        a = line.find(' ', a) + 1;
        b = line.find(' ', a);
      }
      out.push_back(line.substr(a, b - a));
    }
    at = end == std::string::npos ? dump.size() : end + 1;
  }
  return out;
}

class Manifest : public ::testing::Test {
 protected:
  World w_;

  void SetUp() override {
    ThePool().Reset();
    w_.Open();
  }

  void TearDown() override {
    w_.Close();
    ThePool().Reset();
  }

  /** The module is refused, at stage or at apply, naming @p needle; nothing
   * about the site changed. */
  void ExpectRefused(Guest * g, const std::string & needle,
      const char * stage = NULL, bool via_stage = false) {
    std::string before = w_.Dump();
    GDEFCORE_Result rc = w_.Enable(g->name, via_stage);
    EXPECT_NE(GDEFCORE_OK, rc) << g->name << " was accepted; wanted: " << needle;
    EXPECT_NE(std::string::npos, w_.message.find(g->name))
        << "the refusal does not name the module: " << w_.message;
    EXPECT_NE(std::string::npos, w_.message.find(needle))
        << "the refusal does not say: " << needle << "\n  got: " << w_.message;
    if (stage != NULL) {
      EXPECT_EQ(std::string(stage), w_.where) << w_.message;
    }
    EXPECT_EQ(before, w_.Dump()) << "a refused module changed the site";
    int on = 1;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_module_enabled(w_.host, w_.request, g->name.data(),
            g->name.size(), &on));
    EXPECT_EQ(0, on) << "a refused module is enabled";
  }
};

TEST_F(Manifest, Declare) {
  /* CONTROL: a module that is installed and not enabled declares nothing. */
  Guest * g = Rich("zeta");
  w_.Install(g);
  EXPECT_EQ("contributions core.page:\ncontributions core.pane:\n", w_.Dump());
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("zeta")) << w_.message;
  std::string dump = w_.Dump();
  EXPECT_EQ(5u, Count(dump, "route zeta "));
  EXPECT_EQ(3u, Count(dump, "link zeta "));
  EXPECT_EQ(4u, Count(dump, "setting zeta "));
  EXPECT_EQ(2u, Count(dump, "variable zeta "));
  /* Each table is in machine-name order, whatever order the manifest used. */
  EXPECT_EQ((std::vector<std::string>{"zeta.add", "zeta.admin", "zeta.atab",
                "zeta.btab", "zeta.zpage"}),
      Names(dump, "route"));
  EXPECT_EQ((std::vector<std::string>{"zeta.l.admin", "zeta.l.main", "zeta.l.sub"}),
      Names(dump, "link"));
  EXPECT_EQ((std::vector<std::string>{"zeta.max", "zeta.on", "zeta.secret",
                "zeta.title"}),
      Names(dump, "setting"));
  /* Field by field: one route, one link, one setting, one variable. */
  EXPECT_NE(std::string::npos,
      dump.find("route zeta zeta.btab /zeta/:id/b w=1 after=0 perm=edit zeta "
                "title=B tab kind=1 parent=zeta.zpage default=0 admin=0 fn=1 "
                "data=zeta-tag\n"));
  EXPECT_NE(std::string::npos,
      dump.find("route zeta zeta.admin /admin/zeta w=0 after=0 perm=- "
                "title=zeta admin kind=0 parent=- default=0 admin=1"));
  EXPECT_NE(std::string::npos,
      dump.find("link zeta zeta.l.sub menu=main label=Sub zeta route=zeta.btab "
                "w=1 parent=zeta.l.main kind=1\n"));
  EXPECT_NE(std::string::npos,
      dump.find("setting zeta zeta.secret type=text default=[] label=Secret "
                "desc=[] local=1 group=keys\n"));
  EXPECT_NE(std::string::npos,
      dump.find("setting zeta zeta.title type=text default=[T-zeta] label=Title "
                "desc=[The title.] local=0 group=general\n"));
  EXPECT_NE(std::string::npos,
      dump.find("variable zeta core.pane zeta.count type=number desc=[How many.] "
                "free=1 answer=0/2/7\n"));
  EXPECT_NE(std::string::npos,
      dump.find("variable zeta core.page zeta.motd type=text desc=[] free=0 "
                "answer=0/2/7\n"));
  /* The variables are story 2's contributions to those kinds. */
  EXPECT_NE(std::string::npos,
      dump.find("contributions core.pane: zeta.count\n"));
  EXPECT_NE(std::string::npos,
      dump.find("contributions core.page: zeta.motd\n"));
}

TEST_F(Manifest, ModuleOrder) {
  /* Installed zeta, alpha, mid; enabled in the reverse of that. Modules with
   * nothing between them are in name order. */
  Guest * z = Rich("zeta");
  Guest * a = Rich("alpha");
  Guest * m = Rich("mid");
  w_.Install(z);
  w_.Install(a);
  w_.Install(m);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("mid"));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("alpha"));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("zeta"));
  std::string dump = w_.Dump();
  const std::vector<std::string> want = {"alpha", "mid", "zeta"};
  for (const char * table : {"route", "link", "setting", "variable"}) {
    EXPECT_EQ(want, ModuleOrder(dump, table)) << table;
  }
  EXPECT_EQ("contributions core.page: alpha.motd mid.motd zeta.motd",
      dump.substr(dump.find("contributions core.page:"),
          std::string("contributions core.page: alpha.motd mid.motd zeta.motd").size()));
}

TEST_F(Manifest, ModuleOrderFollowsRelationships) {
  /* AD-10: a subscription's after and before put modules in order, and the
   * name decides among the rest. alpha after zeta: mid, zeta, alpha.
   * CONTROL: the same three without the relationship are alpha, mid, zeta. */
  World c;
  c.Open();
  Guest * cz = Rich("zeta");
  Guest * ca = Rich("alpha");
  Guest * cm = Rich("mid");
  Guest * z = Rich("zeta", "", "");
  Guest * a = Rich("alpha", "", "zeta");
  Guest * m = Rich("mid");
  /* The slots differ per world: install the control's guests there. */
  c.Install(cz);
  c.Install(ca);
  c.Install(cm);
  ASSERT_EQ(GDEFCORE_OK, c.Ops({{"zeta", true}, {"alpha", true}, {"mid", true}}));
  EXPECT_EQ((std::vector<std::string>{"alpha", "mid", "zeta"}),
      ModuleOrder(c.Dump(), "route"));
  c.Close();
  w_.Install(z);
  w_.Install(a);
  w_.Install(m);
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"zeta", true}, {"alpha", true}, {"mid", true}}));
  EXPECT_EQ((std::vector<std::string>{"mid", "zeta", "alpha"}),
      ModuleOrder(w_.Dump(), "route"));
  EXPECT_EQ((std::vector<std::string>{"mid", "zeta", "alpha"}),
      ModuleOrder(w_.Dump(), "setting"));
}

TEST_F(Manifest, ModuleOrderBefore) {
  Guest * z = Rich("zeta");
  Guest * a = Rich("alpha");
  Guest * m = Rich("mid", "alpha", "");
  w_.Install(z);
  w_.Install(a);
  w_.Install(m);
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"zeta", true}, {"alpha", true}, {"mid", true}}));
  EXPECT_EQ((std::vector<std::string>{"mid", "alpha", "zeta"}),
      ModuleOrder(w_.Dump(), "link"));
}

TEST_F(Manifest, ModuleOrderCycleIsStillTotal) {
  /* Two hooks may disagree; the declarations take one order whatever the
   * relationships say: here a before b and b before a, and the answer is
   * the same for every enable order. */
  Guest * a = Rich("alpha", "mid", "");
  Guest * m = Rich("mid", "alpha", "");
  w_.Install(a);
  w_.Install(m);
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"mid", true}, {"alpha", true}}));
  std::string first = w_.Dump();
  EXPECT_EQ((std::vector<std::string>{"alpha", "mid"}), ModuleOrder(first, "route"));
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"alpha", false}, {"mid", false}}));
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"alpha", true}, {"mid", true}}));
  EXPECT_EQ(first, w_.Dump());
}

TEST_F(Manifest, OrderIndependence) {
  /* Modules A, B, C enabled in all six orders: identical canonical dumps. One
   * world per order, the guests installed the same way in each. */
  const std::vector<std::string> names = {"zeta", "alpha", "mid"};
  std::vector<int> order = {0, 1, 2};
  std::set<uint64_t> hashes;
  std::string canonical;
  int runs = 0;
  /* CONTROL: a world with one module fewer has another dump, so the hash
   * can tell two sites apart. */
  Guest * z = Rich("zeta");
  Guest * a = Rich("alpha");
  Guest * m = Rich("mid", "", "", true);
  do {
    World w;
    w.Open();
    w.Install(z);
    w.Install(a);
    w.Install(m);
    for (int i : order) {
      ASSERT_EQ(GDEFCORE_OK, w.Enable(names[i])) << w.message;
    }
    std::string dump = w.Dump() + w.TableDump();
    hashes.insert(Fnv(dump));
    if (canonical.empty()) {
      canonical = dump;
    }
    EXPECT_EQ(canonical, dump) << "order " << order[0] << order[1] << order[2];
    w.Close();
    runs += 1;
  } while (std::next_permutation(order.begin(), order.end()));
  EXPECT_EQ(6, runs);
  EXPECT_EQ(1u, hashes.size());
  /* And the one changeset that enables all three, in every op order. */
  order = {0, 1, 2};
  do {
    World w;
    w.Open();
    w.Install(z);
    w.Install(a);
    w.Install(m);
    ASSERT_EQ(GDEFCORE_OK,
        w.Ops({{names[order[0]], true}, {names[order[1]], true},
            {names[order[2]], true}}))
        << w.message;
    EXPECT_EQ(canonical, w.Dump() + w.TableDump());
    w.Close();
  } while (std::next_permutation(order.begin(), order.end()));
  {
    World w;
    w.Open();
    w.Install(z);
    w.Install(a);
    w.Install(m);
    ASSERT_EQ(GDEFCORE_OK, w.Enable("alpha"));
    ASSERT_EQ(GDEFCORE_OK, w.Enable("mid"));
    EXPECT_NE(canonical, w.Dump() + w.TableDump());
    w.Close();
  }
  /* The install order does not matter either (it is not the enable order). */
  {
    World w;
    w.Open();
    w.Install(m);
    w.Install(z);
    w.Install(a);
    ASSERT_EQ(GDEFCORE_OK, w.Ops({{"zeta", true}, {"alpha", true}, {"mid", true}}));
    EXPECT_EQ(canonical, w.Dump() + w.TableDump());
    w.Close();
  }
}

TEST_F(Manifest, Twice) {
  Guest * z = Rich("zeta");
  Guest * a = Rich("alpha");
  w_.Install(z);
  w_.Install(a);
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"alpha", true}, {"zeta", true}}));
  std::string once = w_.Dump() + w_.TableDump();
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("alpha"));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("zeta"));
  EXPECT_EQ(once, w_.Dump() + w_.TableDump());
  /* Twice in one changeset. */
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"alpha", true}, {"alpha", true}}));
  EXPECT_EQ(once, w_.Dump() + w_.TableDump());
  EXPECT_EQ(5u, Count(w_.Dump(), "route alpha "));
  /* CONTROL: the dump does change when something is enabled. */
  EXPECT_NE(std::string::npos, once.find("route zeta "));
}

TEST_F(Manifest, OffAndOn) {
  Guest * z = Rich("zeta");
  Guest * a = Rich("alpha");
  w_.Install(z);
  w_.Install(a);
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"alpha", true}, {"zeta", true}}));
  std::string both = w_.Dump() + w_.TableDump();
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("zeta"));
  std::string off = w_.Dump();
  EXPECT_EQ(0u, Count(off, "zeta")) << "disable left declarations behind";
  EXPECT_EQ(5u, Count(off, "route alpha "));
  EXPECT_EQ(0u, Count(w_.TableDump(), "zeta"));
  EXPECT_NE(both, off + w_.TableDump());
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("zeta"));
  EXPECT_EQ(both, w_.Dump() + w_.TableDump());
  /* A site that never had zeta is the same as one that had and lost it. */
  World fresh;
  fresh.Open();
  fresh.Install(z);
  fresh.Install(a);
  ASSERT_EQ(GDEFCORE_OK, fresh.Enable("alpha"));
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("zeta"));
  EXPECT_EQ(fresh.Dump() + fresh.TableDump(), w_.Dump() + w_.TableDump());
  fresh.Close();
  /* Both off: nothing. */
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("alpha"));
  EXPECT_EQ("contributions core.page:\ncontributions core.pane:\n", w_.Dump());
}

TEST_F(Manifest, Prefix) {
  /* A route `other.page` declared by module `m` is refused, naming m and the
   * entry. CONTROL: the same module with the name under it is accepted. */
  Guest * good = Mini("m");
  good->Build();
  w_.Install(good);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("m")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("m"));

  Guest * route = Mini("r");
  route->routes[0].name = "other.page";
  route->routes[1].parent = "other.page";
  route->Build();
  w_.Install(route);
  ExpectRefused(route, "route 'other.page' is not named r.<name>", "stage");

  Guest * link = Mini("l");
  link->links[0].name = "other.link";
  link->Build();
  w_.Install(link);
  ExpectRefused(link, "menu link 'other.link' is not named l.<name>", "stage");

  Guest * setting = Mini("s");
  setting->settings[0].name = "other.setting";
  setting->Build();
  w_.Install(setting);
  ExpectRefused(setting, "setting 'other.setting' is not named s.<name>", "stage");

  Guest * var = Mini("v");
  var->vars[0].name = "other.count";
  var->Build();
  w_.Install(var);
  ExpectRefused(var, "template variable 'other.count' is not named v.<name>",
      "stage");

  /* Another module's name as a prefix is not the module's own: `mm` is not
   * `m`, and a prefix without the dot is not a prefix. */
  Guest * near = Mini("nn");
  near->routes[0].name = "nnx.page";
  near->routes[1].parent = "nnx.page";
  near->Build();
  w_.Install(near);
  ExpectRefused(near, "route 'nnx.page' is not named nn.<name>", "stage");

  /* Apply is the authority: staged past enable's check, the changeset is
   * refused the same way and names the module and the entry. */
  Guest * late = Mini("late");
  late->routes[0].name = "other.page";
  late->routes[1].parent = "other.page";
  late->Build();
  w_.Install(late);
  std::string before = w_.Dump();
  EXPECT_NE(GDEFCORE_OK, w_.Enable("late", true));
  EXPECT_EQ("apply", w_.where);
  EXPECT_NE(std::string::npos, w_.message.find("late"));
  EXPECT_NE(std::string::npos, w_.message.find("other.page"));
  EXPECT_EQ(before, w_.Dump());
}

TEST_F(Manifest, Clash) {
  /* Two entries with one machine name are one name declared twice, and the
   * refusal names the module and the name. (Names are prefixed by the module,
   * so two modules cannot declare one name: the prefix check refuses first;
   * see Prefix.) CONTROL: the same entries under two names are accepted. */
  Guest * ok = Mini("ok");
  ok->routes.push_back(ok->routes[0]);
  ok->routes.back().name = "ok.page2";
  ok->routes.back().path = "/ok2/:id";
  ok->Build();
  w_.Install(ok);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("ok")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("ok"));

  Guest * r = Mini("r");
  r->routes.push_back(r->routes[0]);
  r->routes.back().path = "/elsewhere/:id";
  r->Build();
  w_.Install(r);
  ExpectRefused(r, "route 'r.page' is declared twice");

  Guest * l = Mini("l");
  l->links.push_back(l->links[0]);
  l->Build();
  w_.Install(l);
  ExpectRefused(l, "menu link 'l.l' is declared twice");

  Guest * s = Mini("s");
  s->settings.push_back(s->settings[0]);
  s->Build();
  w_.Install(s);
  ExpectRefused(s, "setting 's.s' is declared twice");

  Guest * v = Mini("v");
  v->vars.push_back(v->vars[0]);
  v->Build();
  w_.Install(v);
  ExpectRefused(v, "template variable 'v.v' is declared twice");

  /* One variable name under two kinds is two variables. */
  Guest * k = Mini("k");
  k->vars.push_back(k->vars[0]);
  k->vars.back().kind = "core.pane";
  k->Build();
  w_.Install(k);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("k")) << w_.message;
}

TEST_F(Manifest, ClashWithARegisteredRoute) {
  /* A declared route against one already in the table: the route table says
   * so, naming both, and what was added before stays (a table never loses a
   * route). CONTROL: the same module into an empty table. */
  const uint8_t t[] = {'t'};
  Guest * m = Mini("m");
  m->Build();
  w_.Install(m);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("m"));
  GDEFCORE_Routes * clean = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &clean));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_add_routes(w_.host, t, 1, NULL, clean, NULL, NULL));
  gdefcore_routes_destroy(clean);
  GDEFCORE_Routes * routes = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes, "m.page", 6, "/by-hand", 8, 0, 0,
          [](GDEFCORE_Request *, const char *, size_t, void *) {}, NULL, NULL,
          NULL));
  char * error = NULL;
  size_t error_len = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_module_add_routes(w_.host, t, 1, NULL, routes, &error,
          &error_len));
  ASSERT_NE(nullptr, error);
  std::string text(error, error_len);
  EXPECT_NE(std::string::npos, text.find("m.page /by-hand")) << text;
  EXPECT_NE(std::string::npos, text.find("m.page /m/:id")) << text;
  gdefcore_routes_free(routes, error);
  gdefcore_routes_destroy(routes);
}

TEST_F(Manifest, OrphanTab) {
  /* A tab whose parent route is absent is refused. CONTROL: with the parent,
   * accepted. */
  Guest * ok = Mini("ok");
  ok->Build();
  w_.Install(ok);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("ok")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("ok"));

  Guest * o = Mini("orph");
  o->routes[1].parent = "orph.nothing";
  o->Build();
  w_.Install(o);
  ExpectRefused(o, "route 'orph.tab' is a tab of 'orph.nothing', which no "
                   "enabled module declares as a route", "apply");

  /* A parent that an installed module declares and nobody enabled is absent. */
  Guest * p = Mini("par");
  p->Build();
  Guest * c = ThePool().Add("child");
  RouteDef tab;
  tab.name = "child.tab";
  tab.path = "/par/:id/c";
  tab.kind = GDEFCORE_ROUTE_TAB;
  tab.parent = "par.page";
  c->routes = {tab};
  c->Build();
  w_.Install(p);
  w_.Install(c);
  ExpectRefused(c, "is a tab of 'par.page'");
  /* Enabled together, in one changeset, they hold; so do they in two. */
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"child", true}, {"par", true}})) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"child", false}, {"par", false}}));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("par"));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("child")) << w_.message;
  /* And the parent's module cannot go while a tab of it stays. */
  std::string before = w_.Dump();
  EXPECT_NE(GDEFCORE_OK, w_.Disable("par"));
  EXPECT_NE(std::string::npos, w_.message.find("child"));
  EXPECT_NE(std::string::npos, w_.message.find("child.tab"));
  EXPECT_EQ(before, w_.Dump());
  ASSERT_EQ(GDEFCORE_OK, w_.Ops({{"child", false}, {"par", false}}));

  /* A tab whose parent is a menu link's name, not a route's. */
  Guest * h = Mini("hl");
  h->routes[1].parent = "hl.l";
  h->Build();
  w_.Install(h);
  ExpectRefused(h, "route 'hl.tab' is a tab of 'hl.l'");
}

TEST_F(Manifest, TwoDefaults) {
  /* Two default tabs for one parent are refused, within a module and across
   * two. CONTROL: one default and one plain tab are accepted. */
  Guest * ok = Mini("ok");
  ok->routes.push_back(ok->routes[1]);
  ok->routes.back().name = "ok.tab2";
  ok->routes.back().path = "/ok/:id/t2";
  ok->routes[1].is_default = 1;
  ok->Build();
  w_.Install(ok);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("ok")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("ok"));

  Guest * both = Mini("both");
  both->routes.push_back(both->routes[1]);
  both->routes.back().name = "both.tab2";
  both->routes.back().path = "/both/:id/t2";
  both->routes[1].is_default = 1;
  both->routes[2].is_default = 1;
  both->Build();
  w_.Install(both);
  ExpectRefused(both, "refused as a route: second default tab for one parent");

  /* Across modules: a has the parent and a default tab, b adds another. */
  Guest * a = Mini("aa");
  a->routes[1].is_default = 1;
  a->Build();
  Guest * b = ThePool().Add("bb");
  RouteDef tab;
  tab.name = "bb.tab";
  tab.path = "/aa/:id/b";
  tab.kind = GDEFCORE_ROUTE_TAB;
  tab.parent = "aa.page";
  tab.is_default = 1;
  b->routes = {tab};
  b->Build();
  w_.Install(a);
  w_.Install(b);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("aa"));
  ExpectRefused(b, "second default tab for one parent");
  /* The same tab, not default, is fine. */
  Guest * c = ThePool().Add("cc");
  tab.name = "cc.tab";
  tab.is_default = 0;
  c->routes = {tab};
  c->Build();
  w_.Install(c);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("cc")) << w_.message;
  /* A default tab that captures a name its parent does not. */
  Guest * d = ThePool().Add("dd");
  tab.name = "dd.tab";
  tab.is_default = 1;
  tab.parent = "cc.tab";
  tab.path = "/aa/:id/b/:other";
  d->routes = {tab};
  d->Build();
  w_.Install(d);
  ExpectRefused(d, "default tab captures a name its parent does not");
}

TEST_F(Manifest, BadLink) {
  /* A menu link naming a missing route is refused; with the route, accepted. */
  Guest * ok = Mini("ok");
  ok->Build();
  w_.Install(ok);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("ok"));
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("ok"));

  Guest * g = Mini("bl");
  g->links[0].route = "bl.missing";
  g->Build();
  w_.Install(g);
  ExpectRefused(g, "menu link 'bl.l' targets route 'bl.missing', which no "
                   "enabled module declares", "apply");

  /* A link to another module's route needs that module enabled. */
  Guest * target = Mini("tg");
  target->Build();
  Guest * pointer = ThePool().Add("pt");
  LinkDef l;
  l.name = "pt.l";
  l.route = "tg.page";
  pointer->links = {l};
  pointer->Build();
  w_.Install(target);
  w_.Install(pointer);
  ExpectRefused(pointer, "targets route 'tg.page'");
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("tg"));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("pt")) << w_.message;
  /* ... and the target cannot be taken away from under the link. */
  std::string before = w_.Dump();
  EXPECT_NE(GDEFCORE_OK, w_.Disable("tg"));
  EXPECT_NE(std::string::npos, w_.message.find("pt.l"));
  EXPECT_EQ(before, w_.Dump());

  /* A link takes no route's name (an entry is known by one name), neither
   * its own module's page nor its tab. */
  Guest * nm = Mini("nm");
  nm->links[0].name = "nm.page";
  nm->Build();
  w_.Install(nm);
  ExpectRefused(nm, "menu link 'nm.page' has the name of a route");
  Guest * nt = Mini("nt");
  nt->links[0].name = "nt.tab";
  nt->Build();
  w_.Install(nt);
  ExpectRefused(nt, "menu link 'nt.tab' has the name of a route");

  /* Parent links: missing, in another menu, a loop. */
  Guest * pm = Mini("pm");
  pm->links[0].parent = "pm.gone";
  pm->Build();
  w_.Install(pm);
  ExpectRefused(pm, "menu link 'pm.l' has parent link 'pm.gone'");
  Guest * po = Mini("po");
  LinkDef other = po->links[0];
  other.name = "po.m";
  other.menu = "admin";
  po->links[0].parent = "po.m";
  po->links.push_back(other);
  po->Build();
  w_.Install(po);
  ExpectRefused(po, "has a parent in another menu");
  Guest * pl = Mini("pl");
  LinkDef second = pl->links[0];
  second.name = "pl.m";
  second.parent = "pl.l";
  pl->links[0].parent = "pl.m";
  pl->links.push_back(second);
  pl->Build();
  w_.Install(pl);
  ExpectRefused(pl, "is its own ancestor");
  Guest * ps = Mini("ps");
  ps->links[0].parent = "ps.l";
  ps->Build();
  w_.Install(ps);
  ExpectRefused(ps, "is its own ancestor");
  /* CONTROL: a real parent in the same menu holds. */
  Guest * pg = Mini("pg");
  LinkDef child = pg->links[0];
  child.name = "pg.c";
  child.parent = "pg.l";
  pg->links.push_back(child);
  pg->Build();
  w_.Install(pg);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("pg")) << w_.message;
}

TEST_F(Manifest, TemplateVariable) {
  /* A module contributes m.count to core.pane: story 2's contract includes it
   * while m is enabled, with the provider the module's service names. */
  Guest * g = Rich("zeta");
  w_.Install(g);
  GDEFCORE_Contract * contract = NULL;
  GDEFCORE_Contract_Var v;
  /* CONTROL: before the enable the contract is the base alone. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_contract_open(w_.catalog, NULL, "core.pane", 9, &contract,
          NULL));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_template_contract_var(contract, "zeta.count", 10, &v));
  gdefcore_template_contract_close(contract);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("zeta")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_contract_open(w_.catalog, NULL, "core.pane", 9, &contract,
          NULL));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_contract_var(contract, "zeta.count", 10, &v));
  EXPECT_EQ(GDEFCORE_TEMPLATE_NUMBER, v.type);
  ASSERT_NE(nullptr, v.contributed);
  EXPECT_EQ(std::string("zeta"),
      std::string(v.contributed->module, v.contributed->module_len));
  GDEFCORE_Contribution_Value value;
  memset(&value, 0, sizeof value);
  value.size = sizeof value;
  ASSERT_EQ(GDEFCORE_OK, v.contributed->provider(NULL, v.contributed->user, &value));
  EXPECT_EQ(7, value.integer);
  /* A variable of another kind is not in this kind's contract. */
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_template_contract_var(contract, "zeta.motd", 9, &v));
  gdefcore_template_contract_close(contract);
  /* A template that uses it validates; after the disable it does not. */
  GDEFCORE_Template_Report * rep = NULL;
  const char * body = "<% use zeta.count as c; %><%= c %>";
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_validate(w_.catalog, NULL, "core.pane", 9, body,
          strlen(body), &rep));
  EXPECT_EQ(0u, gdefcore_template_report_count(rep));
  gdefcore_template_report_free(rep);
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("zeta"));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_template_validate(w_.catalog, NULL, "core.pane", 9, body,
          strlen(body), &rep));
  EXPECT_GT(gdefcore_template_report_count(rep), 0u);
  gdefcore_template_report_free(rep);
}

TEST_F(Manifest, TemplateVariableKinds) {
  /* A variable for a kind that does not exist refuses the enable, naming the
   * module, the variable and the kind. CONTROL: the same variable on a kind
   * that exists. */
  Guest * ok = Mini("ok");
  ok->Build();
  w_.Install(ok);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("ok")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("ok"));

  Guest * g = Mini("uk");
  g->vars[0].kind = "no.such";
  g->Build();
  w_.Install(g);
  ExpectRefused(g, "template variable uk.v for kind no.such, which does not exist",
      "apply");

  /* A name the kind's base already has. */
  GDEFCORE_Changeset * cs = NULL;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_create(w_.catalog, GDEFCORE_TEMPLATE_KIND_TYPE, 18, id,
          NULL));
  {
    const char * name = "site.thing";
    const char * label = "Thing";
    const char * version = "1";
    const char * var = "bc.v number The base has it.";
    size_t nl = strlen(name), ll = strlen(label), vl = 1, bl = strlen(var);
    GDEFCORE_Value values[4];
    const char * slots[4] = {name, label, version, var};
    size_t lens[4] = {nl, ll, vl, bl};
    const char * fields[4] = {"name", "label", "version", "variables"};
    for (int i = 0; i < 4; i++) {
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = fields[i];
      values[i].field_len = strlen(fields[i]);
      values[i].texts = &slots[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(w_.catalog, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, values, 4));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_apply(cs, GDEFCORE_TEMPLATE_KIND_TYPE, 18));
    gdefcore_changeset_destroy(cs);
  }
  Guest * c = Mini("bc");
  c->vars[0].kind = "site.thing";
  c->vars[0].name = "bc.v";
  c->Build();
  w_.Install(c);
  ExpectRefused(c, "cannot contribute bc.v: the base of site.thing already "
                   "declares it", "apply");
  /* CONTROL: another name on that kind is fine. */
  Guest * d = Mini("bd");
  d->vars[0].kind = "site.thing";
  d->Build();
  w_.Install(d);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("bd")) << w_.message;
}

TEST_F(Manifest, VariableAndCodeContributionClash) {
  /* A variable declared in the manifest and contributed in code is one name
   * registered twice. */
  Guest * g = Mini("dup");
  g->Build();
  w_.Install(g);
  GDEFCORE_Module_Contribution c;
  memset(&c, 0, sizeof c);
  c.size = sizeof c;
  c.kind = "core.page";
  c.kind_len = 9;
  c.name = "dup.v";
  c.name_len = 5;
  c.type = "number";
  c.type_len = 6;
  c.provider = GuestProvide;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_contribute(w_.host, "dup", 3, &c));
  ExpectRefused(g, "template variable dup.v is declared in the manifest and also "
                   "contributed in code");
  /* CONTROL: a different name in code, no clash. */
  Guest * h = Mini("dup2");
  h->Build();
  w_.Install(h);
  c.name = "dup2.other";
  c.name_len = 10;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_contribute(w_.host, "dup2", 4, &c));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("dup2")) << w_.message;
}

TEST_F(Manifest, AManifestOfAnotherSizeIsRefused) {
  /* A manifest is accepted at exactly sizeof(GDEFCORE_Module_Manifest): one
   * that stops before a member, and one that claims more than this build has,
   * are refused at install, in words that name the struct and both sizes, and
   * install nothing. A manifest that leaves the schema version 0 is refused
   * too (core story S11); the full one installs and works. */
  for (size_t size : {offsetof(GDEFCORE_Module_Manifest, services),
           offsetof(GDEFCORE_Module_Manifest, routes),
           offsetof(GDEFCORE_Module_Manifest, schema_version),
           sizeof(GDEFCORE_Module_Manifest) + sizeof(size_t)}) {
    Guest * g = Rich("zeta");
    g->man.size = size;
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_module_install_guest(w_.host, kEntries[g->slot]));
    EXPECT_NE(std::string::npos,
        HostError(w_.host).find("GDEFCORE_Module_Manifest has size " +
            std::to_string(size) + ", but this build's is " +
            std::to_string(sizeof(GDEFCORE_Module_Manifest)) + "."))
        << HostError(w_.host);
    uint32_t v = 0;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_module_schema(w_.host, "zeta", 4,
        &v)) << "a refused manifest was installed";
  }
  Guest * zero = Rich("zero");
  zero->man.schema_version = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_module_install_guest(w_.host, kEntries[zero->slot]));
  /* CONTROL: full size, version 1, declares and works. */
  Guest * full = Rich("full");
  w_.Install(full);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("full"));
  EXPECT_EQ(5u, Count(w_.Dump(), "route full "));
}

TEST_F(Manifest, BothLoaders) {
  /* The same declarations from a native library and from the guest table of
   * this process: identical enumerations, and identical behaviour when the
   * routes they add are dispatched. */
  World native;
  native.Open();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_guest(w_.host, gdefcore_module_manifest))
      << HostError(w_.host);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(native.host, GDEFCORE_MODULE_EXAMPLE,
          GDEFCORE_MODULE_TRUST_FULL))
      << HostError(native.host);
  /* CONTROL: not enabled, both are empty, and enabled both are not. */
  EXPECT_EQ(w_.Dump(), native.Dump());
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("example")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, native.Enable("example")) << native.message;
  std::string guest = w_.Dump();
  std::string lib = native.Dump();
  EXPECT_EQ(guest, lib);
  EXPECT_EQ(Fnv(guest), Fnv(lib));
  EXPECT_EQ(5u, Count(guest, "route example "));
  EXPECT_EQ(3u, Count(guest, "link example "));
  EXPECT_EQ(3u, Count(guest, "setting example "));
  EXPECT_EQ(1u, Count(guest, "variable example "));
  EXPECT_NE(std::string::npos,
      guest.find("route example example.node.edit /example/:id/edit w=0 after=0 "
                 "perm=edit example title=Edit kind=1 parent=example.node "
                 "default=0 admin=0 fn=1 data=example-handler-data\n"));
  EXPECT_NE(std::string::npos,
      guest.find("variable example core.page example.count type=number "
                 "desc=[How many examples.] free=1 answer=0/2/42\n"));
  EXPECT_EQ(w_.TableDump(), native.TableDump());
  /* The handler a route carries is the table the public service lookup gives
   * for the service's name, in both. */
  for (World * world : {&w_, &native}) {
    const uint8_t t[] = {'t'};
    const GDEFCORE_Module_Declared_Route ** items = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_routes(world->host, t, 1, NULL, &items, &n));
    const GDEFCORE_Module_Route_Handler * table =
        (const GDEFCORE_Module_Route_Handler *)gdefcore_module_service(
            world->host, world->request, "example.handler", 15,
            GDEFCORE_MODULE_ROUTE_HANDLER_VERSION);
    ASSERT_NE(nullptr, table);
    ASSERT_GT(n, 0u);
    for (size_t i = 0; i < n; i++) {
      EXPECT_EQ(table->call_fn, items[i]->spec.call_fn);
      EXPECT_EQ(table->data, items[i]->spec.data);
    }
    gdefcore_module_declared_free(world->host, items);
  }
  native.Close();
}

TEST_F(Manifest, AddRoutes) {
  /* Dispatch works for a declared route with a capture and a permission, as
   * guest and as native, with the same answers. */
  struct Policy {
    std::vector<std::string> asked;
    std::string editor;
  } policy;
  auto check = [](const GDEFCORE_Route_Call * call, const char * permission,
                   size_t permission_len, void * data) -> int {
    Policy * p = (Policy *)data;
    const char * id = NULL;
    size_t id_len = 0;
    size_t who_len = 0;
    const char * who = gdefcore_request_principal(call->request, &who_len);
    std::string perm(permission, permission_len);
    std::string v = gdefcore_route_call_capture(call, "id", 2, &id, &id_len)
        ? std::string(id, id_len) : std::string("-");
    p->asked.push_back(perm + "/" + v);
    if (perm == "view example") {
      return v != "13";
    }
    return who != NULL && std::string(who, who_len) == p->editor;
  };
  World native;
  native.Open();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_guest(w_.host, gdefcore_module_manifest));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(native.host, GDEFCORE_MODULE_EXAMPLE,
          GDEFCORE_MODULE_TRUST_FULL));
  const uint8_t t[] = {'t'};
  std::string answers[2];
  std::string asked[2];
  World * worlds[2] = {&w_, &native};
  for (int k = 0; k < 2; k++) {
    World & world = *worlds[k];
    policy.asked.clear();
    policy.editor = world.editor;
    ASSERT_EQ(GDEFCORE_OK, world.Enable("example")) << world.message;
    GDEFCORE_Routes * routes = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes, check, &policy));
    char * error = NULL;
    size_t error_len = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_module_add_routes(world.host, t, 1, NULL, routes, &error,
            &error_len));
    for (const char * path : {"/example/7", "/example/13", "/example/7/edit",
             "/example/7/view", "/example/add", "/admin/example", "/nothing"}) {
      for (const char * who : {"", "editor"}) {
        answers[k] += std::string(path) + " as [" + who + "]:" +
                      world.Resolve(routes, path, who) + "\n";
      }
    }
    asked[k] = Join(policy.asked, ",");
    gdefcore_routes_destroy(routes);
  }
  EXPECT_EQ(answers[0], answers[1]);
  EXPECT_EQ(asked[0], asked[1]);
  const std::string & a = answers[0];
  /* The capture reached the module's function (and its data pointer). */
  EXPECT_NE(std::string::npos,
      a.find("/example/7/edit as [editor]: rc=ok res=example.node.edit "
             "example.id=7 example.data=example-handler-data"))
      << a;
  /* A permission that fails is a missing route, whatever the value. */
  EXPECT_NE(std::string::npos, a.find("/example/13 as [editor]: rc=none"))
      << a;
  EXPECT_NE(std::string::npos,
      a.find("/example/7/edit as []: rc=ok res=example.node example.id=7 "
             "example.data=example-handler-data"))
      << a;
  /* CONTROL: the same route, allowed, runs; and the check saw the capture. */
  EXPECT_NE(std::string::npos, asked[0].find("view example/7"));
  EXPECT_NE(std::string::npos, asked[0].find("view example/13"));
  EXPECT_NE(std::string::npos, asked[0].find("edit example/7"));
  /* The default tab answers the parent's path. */
  EXPECT_NE(std::string::npos,
      a.find("/example/7 as [editor]: rc=ok res=example.node.view")) << a;
  native.Close();
}

TEST_F(Manifest, AddRoutesPutsTabsAfterTheirParents) {
  /* A tab whose name sorts before its parent's is added after it. CONTROL:
   * the order of the enumeration is by name, so the tab does come first. */
  const uint8_t t[] = {'t'};
  Guest * g = ThePool().Add("tt");
  RouteDef parent;
  parent.name = "tt.zparent";
  parent.path = "/tt/:id";
  RouteDef tab;
  tab.name = "tt.atab";
  tab.path = "/tt/:id/a";
  tab.kind = GDEFCORE_ROUTE_TAB;
  tab.parent = "tt.zparent";
  RouteDef sub;
  sub.name = "tt.0sub";
  sub.path = "/tt/:id/a/s";
  sub.kind = GDEFCORE_ROUTE_TAB;
  sub.parent = "tt.atab";
  g->routes = {parent, tab, sub};
  g->Build();
  w_.Install(g);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("tt")) << w_.message;
  EXPECT_EQ((std::vector<std::string>{"tt.0sub", "tt.atab", "tt.zparent"}),
      Names(w_.Dump(), "route"));
  GDEFCORE_Routes * routes = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
  char * error = NULL;
  size_t error_len = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_add_routes(w_.host, t, 1, NULL, routes, &error, &error_len))
      << (error == NULL ? "" : std::string(error, error_len));
  GDEFCORE_Route_Info * info = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_routes_tabs(routes, "tt.zparent", 10, &info, &count));
  EXPECT_EQ(1u, count);
  gdefcore_routes_free(routes, info);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_tabs(routes, "tt.atab", 7, &info, &count));
  EXPECT_EQ(1u, count);
  gdefcore_routes_free(routes, info);
  gdefcore_routes_destroy(routes);
}

TEST_F(Manifest, ServiceResolution) {
  /* A handler is a service of the route's own module. A service of another
   * module under the same name is not it, and a name no module declares is
   * not it. CONTROL: the module's own service resolves. */
  Guest * a = Mini("aa");
  Guest * b = Mini("bb");
  /* bb declares the route and names aa's handler service. */
  b->routes[0].handler = "aa.handler";
  b->routes[1].handler = "aa.handler";
  a->Build();
  b->Build();
  w_.Install(a);
  w_.Install(b);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("aa"));
  /* The public lookup does find aa's table under that name... */
  EXPECT_NE(nullptr,
      gdefcore_module_service(w_.host, w_.request, "aa.handler", 10,
          GDEFCORE_MODULE_ROUTE_HANDLER_VERSION));
  /* ... and bb still may not use it. */
  ExpectRefused(b, "route 'bb.page' handler names a service the module does not "
                   "declare ('aa.handler')");
  /* A provider is the same. */
  Guest * c = Mini("cc");
  c->vars[0].provider = "aa.provider";
  c->Build();
  w_.Install(c);
  ExpectRefused(c, "template variable 'cc.v' provider names a service the module "
                   "does not declare ('aa.provider')");
  /* Versions: a handler service at version 2 is not a handler table. */
  Guest * d = Mini("dd");
  d->Build();
  d->svcs[0].version = 2;
  w_.Install(d);
  ExpectRefused(d, "handler names a service declared at another version");
  Guest * e = Mini("ee");
  e->Build();
  e->svcs[1].version = 9;
  w_.Install(e);
  ExpectRefused(e, "provider names a service declared at another version");
  /* A table without the function. */
  Guest * f = Mini("ff");
  f->Build();
  f->handler.call_fn = NULL;
  w_.Install(f);
  ExpectRefused(f, "handler names a service whose table does not carry the "
                   "function");
  Guest * g = Mini("gg");
  g->Build();
  g->svcs[0].table = NULL;
  w_.Install(g);
  ExpectRefused(g, "handler names a service whose table does not carry the "
                   "function");
  Guest * h = Mini("hh");
  h->Build();
  h->provider.provider = NULL;
  w_.Install(h);
  ExpectRefused(h, "provider names a service whose table does not carry the "
                   "function");
  /* A table is read at exactly its size: a handler table that stops before
   * its data pointer is refused, and so is one that claims more. */
  Guest * i = Mini("ii");
  i->Build();
  i->handler.size = offsetof(GDEFCORE_Module_Route_Handler, data);
  w_.Install(i);
  ExpectRefused(i, "handler names a service whose table has another size than "
                   "this build's");
  Guest * k = Mini("kk");
  k->Build();
  k->handler.size = sizeof(GDEFCORE_Module_Route_Handler) + sizeof(void *);
  w_.Install(k);
  ExpectRefused(k, "handler names a service whose table has another size than "
                   "this build's");
}

TEST_F(Manifest, VetIsTheAuthority) {
  /* Enable checks, and so does apply: a changeset staged by the lower call
   * (which checks nothing) is refused at apply, naming module and entry, for
   * every kind of fault; and the clean one goes through. CONTROL included. */
  Guest * ok = Mini("ok");
  ok->Build();
  w_.Install(ok);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("ok", true)) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("ok"));
  Guest * orphan = Mini("or");
  orphan->routes[1].parent = "or.gone";
  orphan->Build();
  w_.Install(orphan);
  std::string before = w_.Dump();
  EXPECT_NE(GDEFCORE_OK, w_.Enable("or", true));
  EXPECT_EQ("apply", w_.where);
  EXPECT_NE(std::string::npos, w_.message.find("or.tab"));
  EXPECT_NE(std::string::npos, w_.message.find("or.gone"));
  EXPECT_EQ(before, w_.Dump());
  Guest * link = Mini("lk");
  link->links[0].route = "lk.gone";
  link->Build();
  w_.Install(link);
  EXPECT_NE(GDEFCORE_OK, w_.Enable("lk", true));
  EXPECT_EQ("apply", w_.where);
  EXPECT_NE(std::string::npos, w_.message.find("lk.l"));
  EXPECT_EQ(before, w_.Dump());
}

TEST_F(Manifest, Projection) {
  /* A changeset that is staged and not applied is previewed by passing it:
   * the enumeration shows the site it would leave, and the site is not
   * changed. */
  const uint8_t t[] = {'t'};
  Guest * z = Rich("zeta");
  Guest * a = Rich("alpha");
  w_.Install(z);
  w_.Install(a);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("alpha"));
  std::string now = w_.Dump();
  GDEFCORE_Changeset * enabling = w_.Staged({{"zeta", true}});
  std::string preview = w_.Dump(enabling);
  EXPECT_NE(now, preview);
  EXPECT_EQ(5u, Count(preview, "route zeta "));
  EXPECT_EQ(5u, Count(preview, "route alpha "));
  EXPECT_EQ(now, w_.Dump());
  gdefcore_changeset_destroy(enabling);
  GDEFCORE_Changeset * disabling = w_.Staged({{"alpha", false}});
  EXPECT_EQ(0u, Count(w_.Dump(disabling), "alpha"));
  EXPECT_EQ(now, w_.Dump());
  gdefcore_changeset_destroy(disabling);
  /* Arguments. */
  const GDEFCORE_Module_Declared_Route ** items = NULL;
  size_t n = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_module_routes(NULL, t, 1, NULL, &items, &n));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_module_routes(w_.host, NULL, 0, NULL, &items, &n));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_module_routes(w_.host, t, 1, NULL, NULL, &n));
  gdefcore_module_declared_free(w_.host, NULL);
}

TEST_F(Manifest, Quarantine) {
  /* A quarantined module declares nothing, and declares again when a human
   * enables it. */
  World native;
  native.Open();
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(native.host, GDEFCORE_MODULE_EXAMPLE,
          GDEFCORE_MODULE_TRUST_FULL));
  ASSERT_EQ(GDEFCORE_OK, native.Enable("example"));
  std::string on = native.Dump();
  EXPECT_EQ(5u, Count(on, "route example "));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_mark_entered(native.host, "example", 7));
  EXPECT_EQ("contributions core.page:\ncontributions core.pane:\n", native.Dump());
  ASSERT_EQ(GDEFCORE_OK, native.Enable("example")) << native.message;
  EXPECT_EQ(on, native.Dump());
  native.Close();
}

TEST_F(Manifest, ReopenedHost) {
  /* A native module's declarations come back when the host is opened again on
   * the same store; a guest's do when it is installed again. */
  GDEFSTOR_Store * store = w_.store;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_native(w_.host, GDEFCORE_MODULE_EXAMPLE,
          GDEFCORE_MODULE_TRUST_FULL));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("example"));
  std::string before = w_.Dump();
  EXPECT_EQ(5u, Count(before, "route example "));
  gdefcore_catalog_bind_host(w_.catalog, NULL);
  gdefcore_host_destroy(w_.host);
  w_.host = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store, NULL, &w_.host));
  gdefcore_catalog_bind_host(w_.catalog, w_.host);
  EXPECT_EQ(before, w_.Dump());
  EXPECT_NE(std::string::npos,
      w_.TableDump().find("probe /example/7 -> rc=ok res=example.node.view"));
}

TEST_F(Manifest, ReopenedHostGuest) {
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_guest(w_.host, gdefcore_module_manifest));
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("example"));
  std::string before = w_.Dump();
  gdefcore_catalog_bind_host(w_.catalog, NULL);
  gdefcore_host_destroy(w_.host);
  w_.host = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(w_.store, NULL, &w_.host));
  gdefcore_catalog_bind_host(w_.catalog, w_.host);
  /* The entry is not known until the guest is handed over again. */
  EXPECT_EQ("contributions core.page:\ncontributions core.pane:\n", w_.Dump());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_install_guest(w_.host, gdefcore_module_manifest));
  EXPECT_EQ(before, w_.Dump());
}

TEST_F(Manifest, Limits) {
  /* The limits that exist hold at the edge: a table of exactly its maximum is
   * installed, one more is refused with a limit and the module is not
   * installed; the longest name, path, title, permission, label, default and
   * description are accepted, and one byte more is refused when the module is
   * enabled, naming it. */
  Guest * full = ThePool().Add("full");
  for (int i = 0; i < GDEFCORE_MODULE_ROUTES_MAX; i++) {
    RouteDef r;
    r.name = "full.r" + std::to_string(i);
    r.path = "/full/" + std::to_string(i);
    full->routes.push_back(r);
  }
  for (int i = 0; i < GDEFCORE_MODULE_LINKS_MAX; i++) {
    LinkDef l;
    l.name = "full.l" + std::to_string(i);
    l.route = "full.r0";
    full->links.push_back(l);
  }
  for (int i = 0; i < GDEFCORE_MODULE_SETTINGS_MAX; i++) {
    SettingDef s;
    s.name = "full.s" + std::to_string(i);
    full->settings.push_back(s);
  }
  for (int i = 0; i < GDEFCORE_MODULE_VARIABLES_MAX; i++) {
    VarDef v;
    v.name = "full.v" + std::to_string(i);
    full->vars.push_back(v);
  }
  full->Build();
  w_.Install(full);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("full")) << w_.message;
  std::string dump = w_.Dump();
  EXPECT_EQ((size_t)GDEFCORE_MODULE_ROUTES_MAX, Count(dump, "route full "));
  EXPECT_EQ((size_t)GDEFCORE_MODULE_VARIABLES_MAX, Count(dump, "variable full "));

  for (int table = 0; table < 4; table++) {
    Guest * over = ThePool().Add("over" + std::to_string(table));
    const std::string n = over->name;
    int count = table == 0 ? GDEFCORE_MODULE_ROUTES_MAX
        : (table == 1 ? GDEFCORE_MODULE_LINKS_MAX
                      : (table == 2 ? GDEFCORE_MODULE_SETTINGS_MAX
                                    : GDEFCORE_MODULE_VARIABLES_MAX));
    for (int i = 0; i <= count; i++) {
      if (table == 0) {
        RouteDef r;
        r.name = n + ".r" + std::to_string(i);
        r.path = "/" + n + "/" + std::to_string(i);
        over->routes.push_back(r);
      } else if (table == 1) {
        LinkDef l;
        l.name = n + ".l" + std::to_string(i);
        l.route = n + ".r";
        over->links.push_back(l);
      } else if (table == 2) {
        SettingDef s;
        s.name = n + ".s" + std::to_string(i);
        over->settings.push_back(s);
      } else {
        VarDef v;
        v.name = n + ".v" + std::to_string(i);
        over->vars.push_back(v);
      }
    }
    over->Build();
    EXPECT_EQ(GDEFCORE_ERR_LIMIT,
        gdefcore_module_install_guest(w_.host, kEntries[over->slot]))
        << table;
    EXPECT_NE(std::string::npos, HostError(w_.host).find(n)) << table;
    int on = 1;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_module_enabled(w_.host, w_.request, n.data(), n.size(), &on));
    EXPECT_EQ(0, on);
    EXPECT_NE(GDEFCORE_OK, w_.Enable(n)) << "not installed";
  }

  /* A string past what the host will copy at all. */
  Guest * big = Mini("big");
  big->routes[0].title = Rep('t', 70000);
  big->Build();
  EXPECT_EQ(GDEFCORE_ERR_LIMIT,
      gdefcore_module_install_guest(w_.host, kEntries[big->slot]));

  /* At the limit: accepted. */
  Guest * edge = Rich("edge", "", "", true);
  w_.Install(edge);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("edge")) << w_.message;
  std::string d = w_.Dump();
  EXPECT_EQ(1u, Count(d, " title=" + std::string("\xc3\xa9\xc3\xa9") ));
  /* One byte over each limit, one at a time. */
  struct Over {
    const char * what;
    std::function<void(Guest *)> make;
    const char * needle;
  };
  const std::vector<Over> overs = {
      {"route name", [](Guest * g) { g->routes[0].name = g->name + "." + Rep('a', GDEFCORE_MODULE_DECL_NAME_MAX - g->name.size()); g->routes[1].parent = g->routes[0].name; }, "name over 128 bytes"},
      {"route path", [](Guest * g) { g->routes[0].path = "/" + Rep('e', GDEFCORE_ROUTE_PATH_MAX); }, "refused as a route"},
      {"route title", [](Guest * g) { g->routes[0].title = Rep('t', GDEFCORE_ROUTE_TITLE_MAX + 1); }, "refused as a route"},
      {"route permission", [](Guest * g) { g->routes[0].permission = Rep('p', GDEFCORE_ROUTE_PERMISSION_MAX + 1); }, "refused as a route"},
      {"link name", [](Guest * g) { g->links[0].name = g->name + "." + Rep('l', GDEFCORE_MODULE_DECL_NAME_MAX - g->name.size()); }, "name over 128 bytes"},
      {"link label", [](Guest * g) { g->links[0].label = Rep('l', GDEFCORE_MODULE_DECL_LABEL_MAX + 1); }, "no label, or one that is over 256 bytes"},
      {"setting name", [](Guest * g) { g->settings[0].name = g->name + "." + Rep('s', GDEFCORE_MODULE_DECL_NAME_MAX - g->name.size()); }, "name over 128 bytes"},
      {"setting default", [](Guest * g) { g->settings[0].value = Rep('v', GDEFCORE_MODULE_DECL_TEXT_MAX + 1); }, "default that is not a valid text"},
      {"setting description", [](Guest * g) { g->settings[0].description = Rep('d', GDEFCORE_MODULE_DECL_TEXT_MAX + 1); }, "description that is over 1024"},
      {"variable description", [](Guest * g) { g->vars[0].description = Rep('x', 257); }, "description over 256"},
      {"setting group", [](Guest * g) { g->settings[0].group = Rep('g', 65); }, "group that is not"},
  };
  int index = 0;
  for (const Over & o : overs) {
    Guest * g = Mini("ov" + std::to_string(index++));
    o.make(g);
    g->Build();
    w_.Install(g);
    ExpectRefused(g, o.needle);
    SCOPED_TRACE(o.what);
  }
}

TEST_F(Manifest, Hostile) {
  /* One bad field at a time in an otherwise sound module: each is refused,
   * naming the module and what is wrong, nothing is staged, nothing changes,
   * and the host keeps working. CONTROL: the sound module is accepted. */
  struct Case {
    const char * what;
    std::function<void(Guest *)> pre;
    std::function<void(Guest *)> post;
    std::string needle;
    const char * stage;
  };
  const std::vector<Case> cases = {
      {"route empty name", [](Guest * g) { g->routes[0].name = ""; g->routes[1].parent = ""; }, nullptr, "route has an empty name", "stage"},
      {"route huge name", [](Guest * g) { g->routes[0].name += Rep('a', 5000); g->routes[1].parent = g->routes[0].name; }, nullptr, "name over 128 bytes", "stage"},
      {"route bad UTF-8 name", [](Guest * g) { g->routes[0].name += bad8; g->routes[1].parent = g->routes[0].name; }, nullptr, "character outside", "stage"},
      {"route uppercase name", [](Guest * g) { g->routes[0].name += "X"; g->routes[1].parent = g->routes[0].name; }, nullptr, "character outside", "stage"},
      {"route name is the prefix only", [](Guest * g) { g->routes[0].name = g->name + "."; g->routes[1].parent = g->routes[0].name; }, nullptr, "is not named", "stage"},
      {"route empty path", [](Guest * g) { g->routes[0].path = ""; }, nullptr, "refused as a route", "stage"},
      {"route huge path", [](Guest * g) { g->routes[0].path = "/" + Rep('p', 3000); }, nullptr, "refused as a route", "stage"},
      {"route empty capture name", [](Guest * g) { g->routes[0].path = "/a/:/b"; }, nullptr, "refused as a route", "stage"},
      {"route repeated capture", [](Guest * g) { g->routes[0].path = "/a/:x/:x"; }, nullptr, "refused as a route", "stage"},
      {"route huge title", [](Guest * g) { g->routes[0].title = Rep('t', 300); }, nullptr, "refused as a route", "stage"},
      {"route bad UTF-8 title", [](Guest * g) { g->routes[0].title = bad8; }, nullptr, "refused as a route", "stage"},
      {"route control character in title", [](Guest * g) { g->routes[0].title = "a\nb"; }, nullptr, "refused as a route", "stage"},
      {"route huge permission", [](Guest * g) { g->routes[0].permission = Rep('p', 300); }, nullptr, "refused as a route", "stage"},
      {"route unknown kind", [](Guest * g) { g->routes[0].kind = 7; }, nullptr, "unknown kind 7", "stage"},
      {"route negative kind", [](Guest * g) { g->routes[0].kind = -1; }, nullptr, "unknown kind -1", "stage"},
      {"tab pointing at a menu link", [](Guest * g) { g->routes[1].parent = g->name + ".l"; }, nullptr, "is a tab of", "apply"},
      {"tab with no parent", [](Guest * g) { g->routes[1].parent = ""; }, nullptr, "refused as a route", "stage"},
      {"page with a parent", [](Guest * g) { g->routes[0].parent = g->name + ".tab"; }, nullptr, "refused as a route", "stage"},
      {"page marked default", [](Guest * g) { g->routes[0].is_default = 1; }, nullptr, "refused as a route", "stage"},
      {"route no handler", [](Guest * g) { g->routes[0].handler = ""; }, nullptr, "names no service", "stage"},
      {"route unknown handler", [](Guest * g) { g->routes[0].handler = "nowhere.handler"; }, nullptr, "does not declare", "stage"},
      {"route handler version", nullptr, [](Guest * g) { g->svcs[0].version = 3; }, "another version", "stage"},
      {"route handler null table", nullptr, [](Guest * g) { g->svcs[0].table = NULL; }, "does not carry the function", "stage"},
      {"link empty name", [](Guest * g) { g->links[0].name = ""; }, nullptr, "menu link has an empty name", "stage"},
      {"link huge name", [](Guest * g) { g->links[0].name += Rep('a', 5000); }, nullptr, "name over 128 bytes", "stage"},
      {"link bad UTF-8 name", [](Guest * g) { g->links[0].name += bad8; }, nullptr, "character outside", "stage"},
      {"link unprefixed", [](Guest * g) { g->links[0].name = "x.l"; }, nullptr, "is not named", "stage"},
      {"link no menu", [](Guest * g) { g->links[0].menu = ""; }, nullptr, "names a menu that is not", "stage"},
      {"link uppercase menu", [](Guest * g) { g->links[0].menu = "Main"; }, nullptr, "names a menu that is not", "stage"},
      {"link huge menu", [](Guest * g) { g->links[0].menu = Rep('m', 65); }, nullptr, "names a menu that is not", "stage"},
      {"link no label", [](Guest * g) { g->links[0].label = ""; }, nullptr, "no label", "stage"},
      {"link bad UTF-8 label", [](Guest * g) { g->links[0].label = bad8; }, nullptr, "not UTF-8", "stage"},
      {"link newline in label", [](Guest * g) { g->links[0].label = "a\nb"; }, nullptr, "not UTF-8", "stage"},
      {"link overlong UTF-8 label", [](Guest * g) { g->links[0].label = "\xc0\x80"; }, nullptr, "not UTF-8", "stage"},
      {"link surrogate label", [](Guest * g) { g->links[0].label = "\xed\xa0\x80"; }, nullptr, "not UTF-8", "stage"},
      {"link no route", [](Guest * g) { g->links[0].route = ""; }, nullptr, "targets route ''", "apply"},
      {"link route elsewhere", [](Guest * g) { g->links[0].route = "zzz.page"; }, nullptr, "targets route 'zzz.page'", "apply"},
      {"link unknown kind", [](Guest * g) { g->links[0].kind = 9; }, nullptr, "unknown kind 9", "stage"},
      {"setting empty name", [](Guest * g) { g->settings[0].name = ""; }, nullptr, "setting has an empty name", "stage"},
      {"setting unprefixed", [](Guest * g) { g->settings[0].name = "x.s"; }, nullptr, "is not named", "stage"},
      {"setting unknown type", [](Guest * g) { g->settings[0].type = "list"; }, nullptr, "type that is not", "stage"},
      {"setting number default", [](Guest * g) { g->settings[0].type = "number"; g->settings[0].value = "abc"; }, nullptr, "not a valid number", "stage"},
      {"setting empty number default", [](Guest * g) { g->settings[0].type = "number"; g->settings[0].value = ""; }, nullptr, "not a valid number", "stage"},
      {"setting boolean default", [](Guest * g) { g->settings[0].type = "boolean"; g->settings[0].value = "yes"; }, nullptr, "not a valid boolean", "stage"},
      {"setting bad UTF-8 default", [](Guest * g) { g->settings[0].value = bad8; }, nullptr, "not a valid text", "stage"},
      {"setting no label", [](Guest * g) { g->settings[0].label = ""; }, nullptr, "no label", "stage"},
      {"setting bad group", [](Guest * g) { g->settings[0].group = "Bad Group"; }, nullptr, "group that is not", "stage"},
      {"variable no kind", [](Guest * g) { g->vars[0].kind = ""; }, nullptr, "kind that is not a dotted identifier", "stage"},
      {"variable doubled dot kind", [](Guest * g) { g->vars[0].kind = "core..page"; }, nullptr, "kind that is not a dotted identifier", "stage"},
      {"variable bad UTF-8 kind", [](Guest * g) { g->vars[0].kind = bad8; }, nullptr, "kind that is not a dotted identifier", "stage"},
      {"variable unprefixed", [](Guest * g) { g->vars[0].name = "x.v"; }, nullptr, "is not named", "stage"},
      {"variable extra dot", [](Guest * g) { g->vars[0].name = g->name + ".a.b"; }, nullptr, "is not named", "stage"},
      {"variable empty name", [](Guest * g) { g->vars[0].name = ""; }, nullptr, "has an empty name", "stage"},
      {"variable type list", [](Guest * g) { g->vars[0].type = "list"; }, nullptr, "is not text, markup or number", "stage"},
      {"variable no provider", [](Guest * g) { g->vars[0].provider = ""; }, nullptr, "names no service", "stage"},
      {"variable unknown kind", [](Guest * g) { g->vars[0].kind = "no.such"; }, nullptr, "for kind no.such, which does not exist", "apply"},
  };
  Guest * ok = Mini("okay");
  ok->Build();
  w_.Install(ok);
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("okay")) << w_.message;
  ASSERT_EQ(GDEFCORE_OK, w_.Disable("okay"));
  std::string before = w_.Dump();
  int index = 0;
  for (const Case & c : cases) {
    char name[16];
    snprintf(name, sizeof name, "h%02d", index++);
    Guest * g = Mini(name);
    if (c.pre) {
      c.pre(g);
    }
    g->Build();
    if (c.post) {
      c.post(g);
    }
    w_.Install(g);
    SCOPED_TRACE(c.what);
    ExpectRefused(g, c.needle, c.stage);
  }
  EXPECT_EQ(before, w_.Dump());
  /* And the host is still sound: the control module goes in again. */
  ASSERT_EQ(GDEFCORE_OK, w_.Enable("okay")) << w_.message;
  EXPECT_EQ(2u, Count(w_.Dump(), "route okay "));
  EXPECT_GE(cases.size(), 50u);
}

TEST_F(Manifest, MalformedTables) {
  /* A table that cannot be read is refused at install, not enabled. */
  Guest * g = Mini("bad");
  g->Build();
  g->man.routes = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_module_install_guest(w_.host, kEntries[g->slot]));
  EXPECT_NE(std::string::npos, HostError(w_.host).find("bad"));
  Guest * h = Mini("bad2");
  h->Build();
  h->croutes[0].name = NULL;
  h->croutes[0].name_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_module_install_guest(w_.host, kEntries[h->slot]));
  /* CONTROL: the sound one installs. */
  Guest * ok = Mini("fine");
  ok->Build();
  w_.Install(ok);
}

TEST_F(Manifest, Determinism) {
  /* The gate: a hash of the canonical dump of every enumeration and of the
   * route table, across all six enable orders of three modules, enabling
   * twice, and disable then enable; with a sweep of hostile modules (each
   * refused) tried between every step. No refusal changes a byte. */
  const std::vector<std::string> names = {"zeta", "alpha", "mid"};
  Guest * z = Rich("zeta");
  Guest * a = Rich("alpha", "", "mid");
  Guest * m = Rich("mid", "", "", true);
  std::vector<Guest *> hostile;
  const std::vector<std::function<void(Guest *)>> mutations = {
      [](Guest * g) { g->routes[0].name = ""; g->routes[1].parent = ""; },
      [](Guest * g) { g->routes[0].name += Rep('a', 5000); g->routes[1].parent = g->routes[0].name; },
      [](Guest * g) { g->routes[0].name += bad8; g->routes[1].parent = g->routes[0].name; },
      [](Guest * g) { g->routes[1].parent = g->name + ".l"; },
      [](Guest * g) { g->routes[0].kind = 7; },
      [](Guest * g) { g->routes[0].kind = -3; },
      [](Guest * g) { g->routes[0].path = "/" + Rep('p', 3000); },
      [](Guest * g) { g->routes[0].title = Rep('t', 300); },
      [](Guest * g) { g->links[0].name = ""; },
      [](Guest * g) { g->links[0].name += Rep('a', 5000); },
      [](Guest * g) { g->links[0].label = bad8; },
      [](Guest * g) { g->links[0].kind = 9; },
      [](Guest * g) { g->links[0].route = "alpha.zpage-gone"; },
      [](Guest * g) { g->settings[0].name = ""; },
      [](Guest * g) { g->settings[0].type = "list"; },
      [](Guest * g) { g->settings[0].value = bad8; },
      [](Guest * g) { g->vars[0].kind = "no.such"; },
      [](Guest * g) { g->vars[0].name = "x.v"; },
      [](Guest * g) { g->vars[0].provider = ""; },
      [](Guest * g) { g->routes.push_back(g->routes[0]); },
  };
  int index = 0;
  for (const auto & mutate : mutations) {
    char name[16];
    snprintf(name, sizeof name, "h%02d", index++);
    Guest * g = Mini(name);
    mutate(g);
    g->Build();
    hostile.push_back(g);
  }
  auto Setup = [&](World & w) {
    w.Install(z);
    w.Install(a);
    w.Install(m);
    for (Guest * h : hostile) {
      w.Install(h);
    }
  };
  auto Sweep = [&](World & w, const std::string & state) {
    for (Guest * h : hostile) {
      EXPECT_NE(GDEFCORE_OK, w.Enable(h->name)) << h->name;
      EXPECT_EQ(state, w.Dump() + w.TableDump())
          << "after refusing " << h->name;
      EXPECT_NE(GDEFCORE_OK, w.Enable(h->name, true)) << h->name << " at apply";
      EXPECT_EQ(state, w.Dump() + w.TableDump())
          << "after refusing at apply " << h->name;
    }
  };
  std::vector<int> order = {0, 1, 2};
  std::set<uint64_t> hashes;
  std::string canonical;
  do {
    World w;
    w.Open();
    Setup(w);
    for (int i : order) {
      ASSERT_EQ(GDEFCORE_OK, w.Enable(names[i])) << w.message;
      Sweep(w, w.Dump() + w.TableDump());
    }
    std::string dump = w.Dump() + w.TableDump();
    hashes.insert(Fnv(dump));
    if (canonical.empty()) {
      canonical = dump;
    }
    EXPECT_EQ(canonical, dump) << order[0] << order[1] << order[2];
    w.Close();
  } while (std::next_permutation(order.begin(), order.end()));
  EXPECT_EQ(1u, hashes.size());
  EXPECT_GT(canonical.size(), 2000u);
  {
    /* Twice, and twice with the sweep between. */
    World w;
    w.Open();
    Setup(w);
    for (const std::string & n : names) {
      ASSERT_EQ(GDEFCORE_OK, w.Enable(n));
    }
    for (const std::string & n : names) {
      ASSERT_EQ(GDEFCORE_OK, w.Enable(n));
      EXPECT_EQ(canonical, w.Dump() + w.TableDump());
    }
    Sweep(w, canonical);
    w.Close();
  }
  {
    /* Disable then enable, each of the three in turn. */
    for (const std::string & n : names) {
      World w;
      w.Open();
      Setup(w);
      ASSERT_EQ(GDEFCORE_OK, w.Ops({{"zeta", true}, {"alpha", true}, {"mid", true}}));
      ASSERT_EQ(GDEFCORE_OK, w.Disable(n));
      EXPECT_NE(canonical, w.Dump() + w.TableDump());
      Sweep(w, w.Dump() + w.TableDump());
      ASSERT_EQ(GDEFCORE_OK, w.Enable(n));
      EXPECT_EQ(canonical, w.Dump() + w.TableDump()) << n;
      w.Close();
    }
  }
}

}  // namespace manifest

namespace manifest {

/* What a hook subscriber is asked to do about its out block. */
struct SizeHookState {
  bool set = false;
  size_t out_size = 0;
};

extern "C" GDEFCORE_Result OnSizeHook(GDEFCORE_Request * request,
    const void * args, GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out,
    void * user) {
  SizeHookState * state = static_cast<SizeHookState *>(user);
  (void)request;
  (void)args;
  (void)alter;
  if (state->set) {
    out->size = state->out_size;
  }
  return GDEFCORE_OK;
}

/* Whether a module of this shape installs, and, when the table is checked at
 * the enable, stages. A refused size is refused in words that name the struct
 * and both sizes (or, for a service table, say its size is another). */
static bool ManifestAccepts(bool stage, bool extras, const char * name, size_t own,
    size_t size, const std::string & phrase,
    const std::function<void(Guest *, size_t)> & mutate) {
  ThePool().Reset();
  World w;
  w.Open();
  Guest * g = Rich("zsz");
  if (extras) {
    g->Extras();
  }
  mutate(g, size);
  GDEFCORE_Result rc = gdefcore_module_install_guest(w.host, kEntries[g->slot]);
  std::string why = HostError(w.host);
  if (rc == GDEFCORE_OK && stage) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(w.catalog, NULL, 0, &cs));
    gdefcore_changeset_set_request(cs, w.request);
    rc = gdefcore_module_enable(w.host, cs, "zsz", 3);
    why = HostError(w.host);
    gdefcore_changeset_destroy(cs);
  }
  if (size != own) {
    std::string wanted = phrase.empty()
        ? std::string(name) + " has size " + std::to_string(size) +
              ", but this build's is " + std::to_string(own) + "."
        : phrase;
    EXPECT_NE(std::string::npos, why.find(wanted))
        << name << " at size " << size << " was refused, but not in words: "
        << why;
  }
  w.Close();
  ThePool().Reset();
  return rc == GDEFCORE_OK;
}

}  // namespace manifest

/* AD-34: a struct with a size member is accepted at exactly its own size. The
 * module host's are here (size_structs.h lists every struct): the hook blocks,
 * every entry of a manifest, the tables of services, contributions, and what
 * the host enumerates. */
TEST_F(Module, TheStructsHereAreAcceptedAtOnlyTheirOwnSize) {
  using namespace manifest;
  SizeHookState state;
  int named = 0;
  const char * names[] = {"szhook"};
  InstallGuest(host_, "szhook", kCoreToken, "demo.size", GDEFCORE_HOOK_EVENT, 0, 0,
      NULL, OnSizeHook, &state, 0, NULL);
  ASSERT_EQ(GDEFCORE_OK,
      ApplyModules(host_, catalog_, request_, names, 1, "szhook"));
  const std::string table_phrase =
      "names a service whose table has another size than this build's";
  /* One entry of a manifest: install it with the size in that entry. */
  auto entry = [&](const char * struct_name, size_t own,
                   std::function<void(Guest *, size_t)> mutate) {
    return [=](size_t size) {
      return ManifestAccepts(false, true, struct_name, own, size, "", mutate);
    };
  };
  /* A service table is read when the module is enabled. */
  auto table = [&](size_t own, std::function<void(Guest *, size_t)> mutate) {
    return [=](size_t size) {
      return ManifestAccepts(true, false, "", own, size, table_phrase, mutate);
    };
  };
  /* What the host enumerates, once the module is enabled. */
  auto enabled = [&](std::function<bool(World &, size_t)> look) {
    return [=](size_t size) {
      ThePool().Reset();
      World w;
      w.Open();
      Guest * g = Rich("zsz");
      w.Install(g);
      EXPECT_EQ(GDEFCORE_OK, w.Enable("zsz")) << w.message;
      bool filled = look(w, size);
      w.Close();
      ThePool().Reset();
      return filled;
    };
  };
  const uint8_t tenant[] = {'t'};
  const std::map<std::string, size_structs::Probe> probes = {
      {"GDEFCORE_Hook_Out", [&](size_t size) {
         state.set = true;
         state.out_size = size;
         GDEFCORE_Result rc = gdefcore_hook_fire(host_, request_, catalog_,
             "demo.size", 9, GDEFCORE_HOOK_EVENT, NULL, NULL, NULL);
         state.set = false;
         if (size != sizeof(GDEFCORE_Hook_Out)) {
           EXPECT_NE(std::string::npos,
               HostError(host_).find("GDEFCORE_Hook_Out has size " +
                   std::to_string(size)))
               << HostError(host_);
         }
         return rc == GDEFCORE_OK;
       }},
      {"GDEFCORE_Write_Hook", [&](size_t size) {
         GDEFCORE_Write_Hook args;
         memset(&args, 0, sizeof args);
         args.size = size;
         return gdefcore_module_fire_write(host_, request_, catalog_,
                    "demo.size", 9, &args) == GDEFCORE_OK;
       }},
      {"GDEFCORE_Module_Manifest", entry("GDEFCORE_Module_Manifest",
           sizeof(GDEFCORE_Module_Manifest),
           [](Guest * g, size_t size) { g->man.size = size; })},
      {"GDEFCORE_Module_Rel", entry("GDEFCORE_Module_Rel",
           sizeof(GDEFCORE_Module_Rel),
           [](Guest * g, size_t size) { g->extra.rels[0].size = size; })},
      {"GDEFCORE_Module_Sub", entry("GDEFCORE_Module_Sub",
           sizeof(GDEFCORE_Module_Sub),
           [](Guest * g, size_t size) { g->sub.size = size; })},
      {"GDEFCORE_Module_Service", entry("GDEFCORE_Module_Service",
           sizeof(GDEFCORE_Module_Service),
           [](Guest * g, size_t size) { g->svcs[0].size = size; })},
      {"GDEFCORE_Module_Perm", entry("GDEFCORE_Module_Perm",
           sizeof(GDEFCORE_Module_Perm),
           [](Guest * g, size_t size) { g->extra.perms[0].size = size; })},
      {"GDEFCORE_Module_Grant", entry("GDEFCORE_Module_Grant",
           sizeof(GDEFCORE_Module_Grant),
           [](Guest * g, size_t size) { g->extra.grants[0].size = size; })},
      {"GDEFCORE_Module_Relation", entry("GDEFCORE_Module_Relation",
           sizeof(GDEFCORE_Module_Relation),
           [](Guest * g, size_t size) { g->extra.relations[0].size = size; })},
      {"GDEFCORE_Module_Relation_Column", entry(
           "GDEFCORE_Module_Relation_Column",
           sizeof(GDEFCORE_Module_Relation_Column),
           [](Guest * g, size_t size) { g->extra.cols[0].size = size; })},
      {"GDEFCORE_Module_Callback", entry("GDEFCORE_Module_Callback",
           sizeof(GDEFCORE_Module_Callback),
           [](Guest * g, size_t size) { g->extra.callbacks[0].size = size; })},
      {"GDEFCORE_Module_Step", entry("GDEFCORE_Module_Step",
           sizeof(GDEFCORE_Module_Step),
           [](Guest * g, size_t size) { g->extra.steps[0].size = size; })},
      {"GDEFCORE_Module_Upcaster", entry("GDEFCORE_Module_Upcaster",
           sizeof(GDEFCORE_Module_Upcaster),
           [](Guest * g, size_t size) { g->extra.ups[0].size = size; })},
      {"GDEFCORE_Module_Route", entry("GDEFCORE_Module_Route",
           sizeof(GDEFCORE_Module_Route),
           [](Guest * g, size_t size) { g->croutes[0].size = size; })},
      {"GDEFCORE_Module_Link", entry("GDEFCORE_Module_Link",
           sizeof(GDEFCORE_Module_Link),
           [](Guest * g, size_t size) { g->clinks[0].size = size; })},
      {"GDEFCORE_Module_Setting", entry("GDEFCORE_Module_Setting",
           sizeof(GDEFCORE_Module_Setting),
           [](Guest * g, size_t size) { g->csettings[0].size = size; })},
      {"GDEFCORE_Module_Variable", entry("GDEFCORE_Module_Variable",
           sizeof(GDEFCORE_Module_Variable),
           [](Guest * g, size_t size) { g->cvars[0].size = size; })},
      /* The tables a service carries. A callback's is read at install, the
       * others when the module is enabled. */
      {"GDEFCORE_Module_Access_Callback", [=](size_t size) {
         return ManifestAccepts(false, true, "", sizeof(GDEFCORE_Module_Access_Callback),
             size, table_phrase,
             [](Guest * g, size_t s) { g->extra.cbtable.size = s; });
       }},
      {"GDEFCORE_Module_Route_Handler", table(
           sizeof(GDEFCORE_Module_Route_Handler),
           [](Guest * g, size_t size) { g->handler.size = size; })},
      {"GDEFCORE_Module_Variable_Provider", table(
           sizeof(GDEFCORE_Module_Variable_Provider),
           [](Guest * g, size_t size) { g->provider.size = size; })},
      {"GDEFCORE_Module_Contribution", [&](size_t size) {
         ThePool().Reset();
         World w;
         w.Open();
         Guest * g = Rich("zsz");
         w.Install(g);
         std::string variable = "zsz.c" + std::to_string(named++);
         GDEFCORE_Module_Contribution c;
         memset(&c, 0, sizeof c);
         c.size = size;
         c.kind = "core.page";
         c.kind_len = 9;
         c.name = variable.data();
         c.name_len = variable.size();
         c.type = "number";
         c.type_len = 6;
         c.provider = GuestProvide;
         GDEFCORE_Result rc = gdefcore_module_contribute(w.host, "zsz", 3, &c);
         if (size != sizeof c) {
           EXPECT_NE(std::string::npos,
               HostError(w.host).find("GDEFCORE_Module_Contribution has size " +
                   std::to_string(size)))
               << HostError(w.host);
         }
         w.Close();
         ThePool().Reset();
         return rc == GDEFCORE_OK;
       }},
      {"GDEFCORE_Module_Contributed", enabled([&](World & w, size_t size) {
         const GDEFCORE_Module_Contributed ** items = NULL;
         size_t n = 0;
         EXPECT_EQ(GDEFCORE_OK,
             gdefcore_module_variables(w.host, tenant, 1, NULL, &items, &n));
         EXPECT_GT(n, 0u);
         bool filled = n > 0 && items[0]->size == size;
         gdefcore_module_contributions_free(w.host, items);
         return filled;
       })},
      {"GDEFCORE_Module_Declared_Route", enabled([&](World & w, size_t size) {
         const GDEFCORE_Module_Declared_Route ** items = NULL;
         size_t n = 0;
         EXPECT_EQ(GDEFCORE_OK,
             gdefcore_module_routes(w.host, tenant, 1, NULL, &items, &n));
         EXPECT_GT(n, 0u);
         bool filled = n > 0 && items[0]->size == size;
         gdefcore_module_declared_free(w.host, items);
         return filled;
       })},
      {"GDEFCORE_Module_Declared_Link", enabled([&](World & w, size_t size) {
         const GDEFCORE_Module_Declared_Link ** items = NULL;
         size_t n = 0;
         EXPECT_EQ(GDEFCORE_OK,
             gdefcore_module_links(w.host, tenant, 1, NULL, &items, &n));
         EXPECT_GT(n, 0u);
         bool filled = n > 0 && items[0]->size == size;
         gdefcore_module_declared_free(w.host, items);
         return filled;
       })},
      {"GDEFCORE_Module_Declared_Setting", enabled([&](World & w, size_t size) {
         const GDEFCORE_Module_Declared_Setting ** items = NULL;
         size_t n = 0;
         EXPECT_EQ(GDEFCORE_OK,
             gdefcore_module_settings(w.host, tenant, 1, NULL, &items, &n));
         EXPECT_GT(n, 0u);
         bool filled = n > 0 && items[0]->size == size;
         gdefcore_module_declared_free(w.host, items);
         return filled;
       })},
  };
  size_structs::Run("tests/test_module.cpp", probes);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
