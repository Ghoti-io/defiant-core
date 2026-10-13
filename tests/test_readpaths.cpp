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
 * The access-filter bypass gate (AD-25): every read path, as a principal who
 * may see nothing; an access-relevant alter that traps fails closed; and the
 * render key tells two principals of one permission set apart when "own"
 * makes their output differ.
 *
 *  - Paths.EveryPublicFunctionIsFiled is the denominator. It reads the public
 *    headers, and every function they declare must be filed in gate_surface.h
 *    as a read made for a principal (RF), an unfiltered read with no
 *    principal parameter (RA), a write (W) or an accessor (P). A new read
 *    that nobody filed fails here.
 *  - Paths.NoPermission calls every RF function as a principal who may see
 *    nothing, over entities that exist, and requires that no canary of theirs
 *    shows in any answer.
 *  - Paths.AdminReadsAreUnfilteredByContract shows what RA means: the same
 *    hidden entities, read with no principal, are all there.
 *  - Paths.AlterThatTraps, Paths.DecisionThatTraps and Paths.UndeclaredAccess
 *    are the fail-closed rows of the hook bus.
 *  - Principals.OwnOutputDiffers is the same-grants gate on real output.
 */

#include "gate_fixture.h"
#include "gate_surface.h"

#include <dirent.h>
#include <stdio.h>

#include <fstream>
#include <regex>
#include <sstream>

#define MODULE_STR2(x) #x
#define MODULE_STR(x) MODULE_STR2(x)

namespace {

using namespace gate;

const char kCoreToken[] = MODULE_STR(GHOTIIO_DEFCORE_NAME);

std::string Join(const std::vector<std::string> & lines) {
  std::string out;
  size_t i;
  for (i = 0; i < lines.size(); i++) {
    out += "\n  " + lines[i];
  }
  return out;
}

struct Proto {
  std::string name;
  std::string text;
};

bool ReadFile(const std::string & path, std::string * out) {
  std::ifstream in(path.c_str(), std::ios::binary);
  std::stringstream buf;
  if (!in) {
    return false;
  }
  buf << in.rdbuf();
  *out = buf.str();
  return true;
}

/* Where the public headers are: beside this file, or under the working
 * directory. No guess is a failure, not a skip. */
std::string HeaderDir() {
  std::vector<std::string> candidates;
  std::string here = __FILE__;
  size_t slash = here.find_last_of("/\\");
  const char * env = getenv("GHOTI_DEFCORE_INCLUDE");
  size_t i;
  if (env != NULL) {
    candidates.push_back(env);
  }
  if (slash != std::string::npos) {
    candidates.push_back(here.substr(0, slash) +
                         "/../include/ghoti.io/defiant-core");
  }
  candidates.push_back("include/ghoti.io/defiant-core");
  candidates.push_back("../include/ghoti.io/defiant-core");
  for (i = 0; i < candidates.size(); i++) {
    std::string probe;
    if (ReadFile(candidates[i] + "/entity.h", &probe)) {
      return candidates[i];
    }
  }
  return std::string();
}

std::vector<Proto> ScanHeaders(const std::string & dir,
    std::vector<std::string> * files_seen) {
  std::vector<Proto> out;
  DIR * d = opendir(dir.c_str());
  struct dirent * entry;
  if (d == NULL) {
    return out;
  }
  while ((entry = readdir(d)) != NULL) {
    std::string file = entry->d_name;
    std::string text;
    size_t at = 0;
    if (file.size() < 3 || file.compare(file.size() - 2, 2, ".h") != 0 ||
        file == "namespace.h" || file == "libver.h" || file == "macros.h") {
      continue;
    }
    if (!ReadFile(dir + "/" + file, &text)) {
      continue;
    }
    files_seen->push_back(file);
    while ((at = text.find("GDEFCORE_API", at)) != std::string::npos) {
      size_t semi = text.find(';', at);
      size_t paren = text.find('(', at);
      size_t i;
      Proto p;
      if (semi == std::string::npos || paren == std::string::npos ||
          paren > semi) {
        at += 12;
        continue;
      }
      i = paren;
      while (i > at && text[i - 1] == ' ') {
        i -= 1;
      }
      size_t end = i;
      while (i > at && (isalnum((unsigned char)text[i - 1]) || text[i - 1] == '_')) {
        i -= 1;
      }
      p.name = text.substr(i, end - i);
      p.text = text.substr(at, semi - at);
      out.push_back(p);
      at = semi;
    }
  }
  closedir(d);
  return out;
}

const Surface * Find(const std::string & name) {
  size_t i;
  for (i = 0; i < sizeof kSurface / sizeof kSurface[0]; i++) {
    if (name == kSurface[i].name) {
      return &kSurface[i];
    }
  }
  return NULL;
}

/* Canaries: text of entities the principal may not read. */
const char * const kCanaries[] = {"Hidden Note One", "Hidden Note Two",
    "S-ONE-CANARY", "S-TWO-CANARY", "PubHiddenTitle", "PubBodyCanary",
    "DraftHiddenTitle", "DraftBodyCanary", "DupHiddenTitle", "DupBodyCanary",
    "<note1>", "<note2>", "<pub>", "<draft>", "<dup>"};

std::vector<std::string> Leaks(const Obs & o) {
  std::vector<std::string> out;
  std::map<std::string, std::string>::const_iterator it;
  size_t i;
  for (it = o.kv.begin(); it != o.kv.end(); ++it) {
    for (i = 0; i < sizeof kCanaries / sizeof kCanaries[0]; i++) {
      if (it->second.find(kCanaries[i]) != std::string::npos) {
        out.push_back(it->first + " shows " + kCanaries[i] + ": " + it->second);
      }
    }
  }
  return out;
}

/* The render key as the library wrote it, principal and all. */
std::string RawKey(World & w, const std::string & who) {
  Fresh fresh(w, who);
  char * key = NULL;
  size_t n = 0;
  std::string out;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_access_render_key(w.site.catalog, fresh.req, NULL, 0, NULL, 0,
          &key, &n));
  if (key != NULL) {
    out.assign(key, n);
    gdefcore_text_free(w.site.catalog, key);
  }
  return out;
}

/* A guest module with one subscription. */
GDEFCORE_Module_Manifest g_man;
GDEFCORE_Module_Sub g_sub;
const GDEFCORE_Module_Manifest * g_current;

extern "C" const GDEFCORE_Module_Manifest * TestGuest(void) {
  return g_current;
}

struct Calls {
  int calls = 0;
  int set_access = 0;
};

/* Writes into the alter, then traps. */
extern "C" GDEFCORE_Result TrapAlter(GDEFCORE_Request * request, const void * args,
    GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out, void * user) {
  Calls * calls = (Calls *)user;
  (void)request;
  (void)args;
  (void)out;
  calls->calls += 1;
  if (alter != NULL) {
    gdefcore_alter_set(alter, "TAINTED", 7);
  }
  return GDEFCORE_ERR_INTERNAL;
}

/* Allows, and claims an access contribution. */
extern "C" GDEFCORE_Result ClaimAccess(GDEFCORE_Request * request,
    const void * args, GDEFCORE_Alter * alter, GDEFCORE_Hook_Out * out,
    void * user) {
  Calls * calls = (Calls *)user;
  (void)request;
  (void)args;
  (void)alter;
  calls->calls += 1;
  out->decision = GDEFCORE_DECISION_ALLOW;
  out->access = 1;
  return GDEFCORE_OK;
}

void InstallGuest(GDEFCORE_Host * host, const char * name, const char * hook,
    int kind, int access, GDEFCORE_Hook_Fn fn, void * user) {
  memset(&g_man, 0, sizeof g_man);
  memset(&g_sub, 0, sizeof g_sub);
  g_sub.size = sizeof g_sub;
  g_sub.hook = hook;
  g_sub.hook_len = strlen(hook);
  g_sub.kind = kind;
  g_sub.access_relevant = access;
  g_sub.fn = fn;
  g_sub.user = user;
  g_man.size = sizeof g_man;
  g_man.core_token = kCoreToken;
  g_man.core_token_len = strlen(kCoreToken);
  g_man.name = name;
  g_man.name_len = strlen(name);
  g_man.label = name;
  g_man.label_len = strlen(name);
  g_man.subs = &g_sub;
  g_man.nsubs = 1;
  g_current = &g_man;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(host, TestGuest));
}

void Enable(World * w, GDEFCORE_Request * request, const char * name) {
  GDEFCORE_Changeset * changeset = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(w->site.catalog, NULL, 0, &changeset));
  gdefcore_changeset_set_request(changeset, request);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_enable(w->host, changeset, name, strlen(name)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_apply(changeset, name, strlen(name)));
  gdefcore_changeset_destroy(changeset);
}

}  // namespace

TEST(Paths, EveryPublicFunctionIsFiled) {
  std::string dir = HeaderDir();
  std::vector<std::string> files;
  std::vector<Proto> protos;
  std::vector<std::string> problems;
  std::set<std::string> seen;
  size_t i;
  std::regex read_shaped(
      "_(read|list|values|ids|resolve|page|render_key|export|snapshot|tree|"
      "alias|roles|grants|type|actor|revision|revision_count|revision_at|diff|"
      "serialize|regions|pane_at|kit|blind|blind_count|epoch|base_seq)$");
  ASSERT_FALSE(dir.empty()) << "the public headers were not found";
  protos = ScanHeaders(dir, &files);
  /* A scan that found nothing, or one header's worth, is not a denominator. */
  ASSERT_GE(files.size(), 13u) << "headers found in " << dir;
  ASSERT_GE(protos.size(), 150u);
  for (i = 0; i < protos.size(); i++) {
    const Proto & p = protos[i];
    const Surface * row = Find(p.name);
    std::string cat;
    bool takes_request = p.text.find("GDEFCORE_Request") != std::string::npos;
    bool request_accessor = p.name.compare(0, 16, "gdefcore_request") == 0;
    seen.insert(p.name);
    if (row == NULL) {
      problems.push_back(p.name +
          " is declared in a public header and is not filed in gate_surface.h:"
          " say whether it is a filtered read (RF), an unfiltered read (RA),"
          " a write (W) or an accessor (P)");
      continue;
    }
    cat = row->category;
    if (cat == "RF" && !takes_request) {
      problems.push_back(p.name + " is filed RF and takes no GDEFCORE_Request");
    }
    if (cat == "RA" && takes_request) {
      problems.push_back(p.name +
          " is filed RA (unfiltered, no principal) and now takes a request:"
          " it is a filtered read, file it RF and make the sweep call it");
    }
    if (takes_request && !request_accessor && cat != "RF" && cat != "W") {
      problems.push_back(p.name + " takes a request and is filed " + cat +
          ": only RF and W may");
    }
    if (cat == "W" && std::regex_search(p.name, read_shaped)) {
      problems.push_back(p.name +
          " is filed W and is named like a read: file it RF or RA");
    }
  }
  for (i = 0; i < sizeof kSurface / sizeof kSurface[0]; i++) {
    if (seen.count(kSurface[i].name) == 0) {
      problems.push_back(std::string(kSurface[i].name) +
          " is filed in gate_surface.h and no public header declares it");
    }
  }
  EXPECT_TRUE(problems.empty()) << Join(problems);
}

TEST(Paths, NoPermission) {
  /* Every RF function, as a principal who may see nothing, over entities that
   * exist: two notes, a published post, a draft post, a post behind a route
   * that declines. None of their text may show in any answer. */
  World w;
  BuildS(&w, true);
  {
    Ask ask;
    ask.posts = true;
    ask.targets = {"note1", "note2", "pub", "draft", "dup", "missing"};
    Obs o = Observe(w, w.principal["none"], ask);
    std::map<std::string, std::string>::const_iterator it;
    EXPECT_GT(o.kv.size(), 60u);
    EXPECT_TRUE(Leaks(o).empty()) << "a hidden entity showed:" << Join(Leaks(o));
    for (it = o.kv.begin(); it != o.kv.end(); ++it) {
      const std::string & key = it->first;
      const std::string & v = it->second;
      if (key.compare(0, 2, "t:") == 0 &&
          (key.find(":read.") != std::string::npos ||
              key.find(":page.echo") != std::string::npos)) {
        EXPECT_NE(std::string::npos, v.find("rc=Invalid")) << key << ": " << v;
      }
      if (key.compare(0, 7, "g:list.") == 0) {
        bool refused = v.find("rc=Invalid") != std::string::npos;
        bool empty = v.find("rc=No error count=0") != std::string::npos;
        EXPECT_TRUE(refused || empty) << key << ": " << v;
      }
      if (key.compare(0, 6, "g:page") == 0 && key != "g:page/" &&
          key != "g:page-noroutes/") {
        EXPECT_NE(std::string::npos, v.find("rc=Invalid")) << key << ": " << v;
      }
      if (key.compare(0, 9, "g:resolve") == 0 &&
          key.find("/dup-hidden") != std::string::npos) {
        /* The route declines; the alias behind it is hidden. */
        EXPECT_NE(std::string::npos, v.find("rc=Invalid")) << key << ": " << v;
      }
    }
    /* The front page renders for them, with no post in it. */
    EXPECT_NE(std::string::npos, o.kv["g:page/"].find("rc=No error"))
        << o.kv["g:page/"];
  }
  {
    /* The anonymous state: notes and the draft are not readable. */
    Ask ask;
    ask.posts = false;
    ask.targets = {"note1", "note2", "draft", "missing"};
    Obs o = Observe(w, "", ask);
    EXPECT_TRUE(Leaks(o).empty()) << "a hidden entity showed to anonymous:"
                                  << Join(Leaks(o));
  }
  w.Close();
}

TEST(Paths, AdminReadsAreUnfilteredByContract) {
  /* What RA means. These read the same hidden entities with no principal, and
   * find them: nothing here can be handed a principal. If one of them is ever
   * reachable from a request, it has to move to RF and into the sweep. */
  World w;
  BuildS(&w, true);
  {
    char ** ids = NULL;
    size_t count = 0;
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    uint64_t seq = 0;
    size_t revs = 0;
    char * type = NULL;
    size_t type_len = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(w.site.catalog, "site.note", 9, &ids, &count));
    EXPECT_EQ(2u, count);
    gdefcore_ids_free(w.site.catalog, ids, count);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_values(w.site.catalog, NULL, GDEFCORE_VIEW_PUBLISHED,
            w.id["note1"].data(), w.id["note1"].size(), "en", 2, "secret", 6,
            &texts, &lens, &n));
    ASSERT_EQ(1u, n);
    EXPECT_EQ("S-ONE-CANARY", std::string(texts[0], lens[0]));
    gdefcore_values_free(w.site.catalog, texts, lens, n);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision(w.site.catalog, w.id["note1"].data(),
            w.id["note1"].size(), &seq));
    EXPECT_GE(seq, 1u);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision_count(w.site.catalog, w.id["note1"].data(),
            w.id["note1"].size(), &revs));
    EXPECT_GE(revs, 1u);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_type(w.site.catalog, w.id["pub"].data(),
            w.id["pub"].size(), &type, &type_len));
    EXPECT_EQ("site.post", std::string(type, type_len));
    gdefcore_text_free(w.site.catalog, type);
  }
  w.Close();
}

TEST(Paths, AlterThatTraps) {
  /* An alter whose subscriber is access-relevant and traps fails the call.
   * It does not skip the subscriber and let the call go through unchecked,
   * which is what a non-access alter that traps gets (and is the control). */
  World w;
  Calls guard;
  Calls soft;
  GDEFCORE_Request * req;
  GDEFCORE_Alter * alter = NULL;
  const char * text = NULL;
  size_t len = 0;
  GDEFCORE_Result rc;
  w.Open();
  req = w.Req();
  InstallGuest(w.host, "guard", "access.alter", GDEFCORE_HOOK_ALTER, 1,
      TrapAlter, &guard);
  Enable(&w, req, "guard");
  InstallGuest(w.host, "soft", "soft.alter", GDEFCORE_HOOK_ALTER, 0, TrapAlter,
      &soft);
  Enable(&w, req, "soft");
  /* The control: an alter that is not access-relevant is skipped, counted and
   * named, and the call goes on with the value as it was. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_alter_create(w.host, "clean", 5, &alter));
  rc = gdefcore_hook_fire(w.host, req, w.site.catalog, "soft.alter", 10,
      GDEFCORE_HOOK_ALTER, NULL, alter, NULL);
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_EQ(1, soft.calls);
  EXPECT_EQ(1u, gdefcore_hook_skipped(w.host));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_alter_text(alter, &text, &len));
  EXPECT_EQ("clean", std::string(text, len));
  gdefcore_alter_destroy(w.host, alter);
  /* The gate: the access-relevant alter that traps fails the call, nothing is
   * skipped, and the value it half-wrote is put back. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_alter_create(w.host, "clean", 5, &alter));
  rc = gdefcore_hook_fire(w.host, req, w.site.catalog, "access.alter", 12,
      GDEFCORE_HOOK_ALTER, NULL, alter, NULL);
  EXPECT_NE(GDEFCORE_OK, rc) << "an access-relevant alter that trapped let the call go through";
  EXPECT_EQ(GDEFCORE_ERR_INTERNAL, rc);
  EXPECT_EQ(1, guard.calls);
  EXPECT_EQ(0u, gdefcore_hook_skipped(w.host));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_alter_text(alter, &text, &len));
  EXPECT_EQ("clean", std::string(text, len));
  gdefcore_alter_destroy(w.host, alter);
  gdefcore_request_destroy(req);
  w.Close();
}

TEST(Paths, DecisionThatTraps) {
  /* A decision that traps fails the call and never allows, access-relevant
   * or not: unlike an alter, a decision is never skipped. Declared here as not
   * access-relevant, so it is the decision rule that is under test. */
  World w;
  Calls trap;
  GDEFCORE_Request * req;
  int decision = GDEFCORE_DECISION_NONE;
  GDEFCORE_Result rc;
  w.Open();
  req = w.Req();
  InstallGuest(w.host, "judge", "access.decide", GDEFCORE_HOOK_DECISION, 0,
      TrapAlter, &trap);
  Enable(&w, req, "judge");
  rc = gdefcore_hook_fire(w.host, req, w.site.catalog, "access.decide", 13,
      GDEFCORE_HOOK_DECISION, NULL, NULL, &decision);
  EXPECT_NE(GDEFCORE_OK, rc);
  EXPECT_NE(GDEFCORE_DECISION_ALLOW, decision);
  EXPECT_EQ(1, trap.calls);
  gdefcore_request_destroy(req);
  w.Close();
}

TEST(Paths, UndeclaredAccess) {
  /* A subscriber that did not declare itself access-relevant and reports an
   * access contribution is refused, not believed. */
  World w;
  Calls claim;
  GDEFCORE_Request * req;
  int decision = GDEFCORE_DECISION_NONE;
  GDEFCORE_Result rc;
  w.Open();
  req = w.Req();
  InstallGuest(w.host, "sneak", "access.sneak", GDEFCORE_HOOK_DECISION, 0,
      ClaimAccess, &claim);
  Enable(&w, req, "sneak");
  rc = gdefcore_hook_fire(w.host, req, w.site.catalog, "access.sneak", 12,
      GDEFCORE_HOOK_DECISION, NULL, NULL, &decision);
  EXPECT_NE(GDEFCORE_OK, rc);
  EXPECT_NE(GDEFCORE_DECISION_ALLOW, decision);
  gdefcore_request_destroy(req);
  w.Close();
}

TEST(Principals, OwnOutputDiffers) {
  /* Two principals hold the same role, so the same grants, and the grant is
   * "own": what each reads differs. Their render keys must differ too, or a
   * cache keyed by the render key would serve one the other's page. A pair of
   * principals under an "any" grant must share a key, so the key is not just
   * unique to everyone. */
  World w;
  std::string a;
  std::string b;
  std::string c;
  std::string d;
  w.Open();
  w.site.DefineNote();
  w.site.Declare(Perm("Read own notes", "read", GDEFCORE_ACCESS_OWN, "site.note",
      NULL));
  w.site.Declare(Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, "site.note",
      NULL));
  w.site.Role("writers");
  w.site.Grant("writers", "Read own notes");
  w.site.Role("readers");
  w.site.Grant("readers", "Read notes");
  a = w.site.Principal("writers");
  b = w.site.Principal("writers");
  c = w.site.Principal("readers");
  d = w.site.Principal("readers");
  w.Target("na", w.site.SaveNote(a, "alpha note", "s1"), false);
  w.Target("nb", w.site.SaveNote(b, "beta note", "s2"), false);
  w.Target("missing", "", false);
  {
    std::string la = ListLine(w, a, "site.note", NULL, "", NULL);
    std::string lb = ListLine(w, b, "site.note", NULL, "", NULL);
    EXPECT_NE(std::string::npos, la.find("ids=na")) << la;
    EXPECT_NE(std::string::npos, lb.find("ids=nb")) << lb;
    EXPECT_EQ(std::string::npos, la.find("nb")) << la;
    EXPECT_EQ(std::string::npos, lb.find("na")) << lb;
  }
  {
    std::string ka = RawKey(w, a);
    std::string kb = RawKey(w, b);
    std::string kc = RawKey(w, c);
    std::string kd = RawKey(w, d);
    EXPECT_NE(ka, kb) << "two principals whose own output differs share a render key";
    EXPECT_EQ(kc, kd) << "two principals under an 'any' grant should share a key";
    EXPECT_NE(ka, kc);
  }
  w.Close();
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
