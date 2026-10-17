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
 * The oracle sweep (AD-25): filter, sort, alias collision and diagnostics
 * behave alike for an entity or a field that exists but may not be read and
 * for one that does not exist.
 *
 * Two worlds are built by one recipe. They differ only in what the probed
 * principal may not read. Every principal-parameterized read surface of
 * defiant-core is asked the same questions in both, and the answers written
 * down must be identical. Inside one world, the answers for a hidden id must
 * equal the answers for an id that was never created.
 *
 * Oracle.Control is what keeps the sweep from being blind: a principal who may
 * read the entities must see the two worlds differ, on named lines.
 *
 * There is no trace or explain surface in defiant-core. What it has that
 * reports on a call is the request status and resolution, the host error text
 * and the skipped-hook count; every probe line carries all four.
 */

#include "gate_fixture.h"
#include "gate_surface.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace gate;

std::string Join(const std::vector<std::string> & lines) {
  std::string out;
  size_t i;
  for (i = 0; i < lines.size(); i++) {
    out += "\n  " + lines[i];
  }
  return out;
}

bool HasKey(const std::vector<std::string> & diffs, const std::string & key) {
  size_t i;
  for (i = 0; i < diffs.size(); i++) {
    if (diffs[i].compare(0, key.size() + 1, key + ":") == 0) {
      return true;
    }
  }
  return false;
}

Ask AskEverything(bool posts, const std::vector<std::string> & targets) {
  Ask ask;
  ask.posts = posts;
  ask.targets = targets;
  return ask;
}

/* ---- a module that grants (access-conditions story A4) ------------------ */

#define MODULE_STR2(x) #x
#define MODULE_STR(x) MODULE_STR2(x)

struct OracleModule {
  std::string condition;
  GDEFCORE_Module_Perm perm;
  GDEFCORE_Module_Grant grant;
  GDEFCORE_Module_Manifest man;
};

OracleModule g_module;

extern "C" const GDEFCORE_Module_Manifest * OracleGuest(void) {
  return &g_module.man;
}

/** Install and enable a module that grants `read` of notes under @p condition. */
void EnableGranting(World * w, const std::string & condition) {
  static const char kCoreToken[] = MODULE_STR(GHOTIIO_DEFCORE_NAME);
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Condition * parsed = NULL;
  char * words = NULL;
  size_t words_len = 0;
  std::vector<std::string> lines;
  std::string text = "oracle";
  size_t i;
  g_module.condition = condition;
  memset(&g_module.perm, 0, sizeof g_module.perm);
  g_module.perm.size = sizeof g_module.perm;
  g_module.perm.label = "oracle.read";
  g_module.perm.label_len = 11;
  g_module.perm.action = "read";
  g_module.perm.action_len = 4;
  g_module.perm.condition = GDEFCORE_ACCESS_ANY;
  g_module.perm.type_name = "site.note";
  g_module.perm.type_name_len = 9;
  memset(&g_module.grant, 0, sizeof g_module.grant);
  g_module.grant.size = sizeof g_module.grant;
  g_module.grant.permission = "oracle.read";
  g_module.grant.permission_len = 11;
  g_module.grant.type_name = "site.note";
  g_module.grant.type_name_len = 9;
  g_module.grant.condition = g_module.condition.c_str();
  g_module.grant.condition_len = g_module.condition.size();
  memset(&g_module.man, 0, sizeof g_module.man);
  g_module.man.size = sizeof g_module.man;
  g_module.man.core_token = kCoreToken;
  g_module.man.core_token_len = strlen(kCoreToken);
  g_module.man.name = "oracle";
  g_module.man.name_len = 6;
  g_module.man.label = "oracle";
  g_module.man.label_len = 6;
  g_module.man.perms = &g_module.perm;
  g_module.man.nperms = 1;
  g_module.man.grants = &g_module.grant;
  g_module.man.ngrants = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(w->host, OracleGuest));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(condition.data(), condition.size(), &parsed, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_explain(parsed, &words, &words_len));
  /* A condition on the note's own data, read alone: low. */
  lines.push_back("Module oracle grants oracle.read (low risk): " +
                  std::string(words, words_len));
  lines.push_back("oracle.read");
  std::sort(lines.begin(), lines.end());
  for (i = 0; i < lines.size(); i++) {
    text += "\n" + lines[i];
  }
  gdefcore_condition_text_free(words);
  gdefcore_condition_free(parsed);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(w->site.catalog, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(w->host, cs, "oracle", 6));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, text.data(), text.size()));
  gdefcore_changeset_destroy(cs);
}

}  // namespace

TEST(Oracle, Entities) {
  World hidden;
  World absent;
  BuildS(&hidden, true);
  BuildS(&absent, false);
  {
    /* A principal who may see nothing: every entity is hidden from them. */
    Ask ask = AskEverything(true,
        {"note1", "note2", "pub", "draft", "dup", "missing"});
    Obs a = Observe(hidden, hidden.principal["none"], ask);
    Obs b = Observe(absent, absent.principal["none"], ask);
    EXPECT_GT(a.kv.size(), 60u) << "the sweep asked too little to mean anything";
    EXPECT_EQ(a.kv.size(), b.kv.size());
    EXPECT_TRUE(Differences(a, b).empty())
        << "hidden entities changed an answer:" << Join(Differences(a, b));
    EXPECT_TRUE(HiddenVsMissing(hidden, a).empty())
        << "a hidden id answers unlike a missing one:"
        << Join(HiddenVsMissing(hidden, a));
    EXPECT_TRUE(HiddenVsMissing(absent, b).empty())
        << Join(HiddenVsMissing(absent, b));
  }
  {
    /* The anonymous state sees published posts, never notes or drafts. */
    Ask ask = AskEverything(false, {"note1", "note2", "draft", "missing"});
    Obs a = Observe(hidden, "", ask);
    Obs b = Observe(absent, "", ask);
    EXPECT_GT(a.kv.size(), 25u);
    EXPECT_TRUE(Differences(a, b).empty())
        << "hidden entities changed an anonymous answer:"
        << Join(Differences(a, b));
    EXPECT_TRUE(HiddenVsMissing(hidden, a).empty())
        << Join(HiddenVsMissing(hidden, a));
  }
  hidden.Close();
  absent.Close();
}

/* An entity that readers may not see because it is not published (never
 * published, or unpublished) answers every surface as one that was never
 * created, to a reader who may read every post. The control is the published
 * post both worlds hold: it is listed, and read, in both, so the sweep can
 * see a post at all. */
TEST(Oracle, Unpublished) {
  World hidden;
  World absent;
  BuildU(&hidden, true);
  BuildU(&absent, false);
  Ask ask = AskEverything(true, {"pub", "draft", "unpub", "note1", "note2", "missing"});
  Obs a = Observe(hidden, "", ask);
  Obs b = Observe(absent, "", ask);
  EXPECT_GT(a.kv.size(), 60u) << "the sweep asked too little to mean anything";
  EXPECT_EQ(a.kv.size(), b.kv.size());
  EXPECT_TRUE(Differences(a, b).empty())
      << "an unpublished entity changed an answer:" << Join(Differences(a, b));
  EXPECT_TRUE(HiddenVsMissing(hidden, a).empty())
      << "an unpublished id answers unlike a missing one:"
      << Join(HiddenVsMissing(hidden, a));
  EXPECT_TRUE(HiddenVsMissing(absent, b).empty()) << Join(HiddenVsMissing(absent, b));
  /* Control: the published post is there in both, by the list and by a read. */
  EXPECT_NE(std::string::npos, a.kv["g:list.posts"].find("ids=pub"))
      << a.kv["g:list.posts"];
  EXPECT_NE(std::string::npos, b.kv["g:list.posts"].find("ids=pub"))
      << b.kv["g:list.posts"];
  EXPECT_NE(std::string::npos, a.kv["t:pub:read.title"].find("count=1"))
      << a.kv["t:pub:read.title"];
  EXPECT_NE(std::string::npos, b.kv["t:pub:read.title"].find("count=1"))
      << b.kv["t:pub:read.title"];
  /* and the hidden ones are not in it */
  EXPECT_EQ(std::string::npos, a.kv["g:list.posts"].find("draft"));
  EXPECT_EQ(std::string::npos, a.kv["g:list.posts"].find("unpub"));
  hidden.Close();
  absent.Close();
}

TEST(Oracle, Fields) {
  /* The principal may read their own notes and may not read `secret`. The
   * two worlds hold other people's notes in one and not in the other, and
   * swap the secrets on the principal's own notes. */
  World x;
  World y;
  BuildT(&x, true);
  BuildT(&y, false);
  {
    Ask ask = AskEverything(false,
        {"mine", "mine2", "theirs1", "theirs2", "missing"});
    Obs a = Observe(x, x.principal["writer"], ask);
    Obs b = Observe(y, y.principal["writer"], ask);
    EXPECT_GT(a.kv.size(), 40u);
    EXPECT_TRUE(Differences(a, b).empty())
        << "a field or entity the principal may not read changed an answer:"
        << Join(Differences(a, b));
    EXPECT_TRUE(HiddenVsMissing(x, a).empty()) << Join(HiddenVsMissing(x, a));
    /* The refusals the sweep is comparing are real ones, not two shrugs. */
    EXPECT_NE(std::string::npos,
        a.kv["g:list.notes.secret=alpha"].find("rc=Invalid"))
        << a.kv["g:list.notes.secret=alpha"];
    EXPECT_NE(std::string::npos,
        a.kv["g:list.notes.sort-secret"].find("rc=Invalid"))
        << a.kv["g:list.notes.sort-secret"];
    EXPECT_NE(std::string::npos,
        a.kv["t:mine:read.secret"].find("rc=No error count=0"))
        << a.kv["t:mine:read.secret"];
    EXPECT_NE(std::string::npos, a.kv["g:list.notes"].find("ids=mine,mine2"))
        << a.kv["g:list.notes"];
  }
  x.Close();
  y.Close();
}

TEST(Oracle, Control) {
  /* The same sweep, as principals who may read what the others may not. The
   * worlds must now differ, on the lines that carry the difference. A sweep
   * that came back empty here would be a sweep that cannot see. */
  {
    World hidden;
    World absent;
    BuildS(&hidden, true);
    BuildS(&absent, false);
    {
      Ask ask = AskEverything(false, {"note1", "note2", "missing"});
      ask.cond_true = true;
      Obs a = Observe(hidden, hidden.principal["readers"], ask);
      Obs b = Observe(absent, absent.principal["readers"], ask);
      std::vector<std::string> diffs = Differences(a, b);
      EXPECT_TRUE(HasKey(diffs, "t:note1:read.title")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "t:note1:read.secret")) << Join(diffs);
      /* The one decision sees the note, and so does the route guarded by it;
       * a permission the readers lack is a no for both worlds. */
      EXPECT_TRUE(HasKey(diffs, "t:note1:can.read")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "t:note1:resolve.guard")) << Join(diffs);
      EXPECT_FALSE(HasKey(diffs, "t:note1:can.update")) << Join(diffs);
      EXPECT_NE(std::string::npos,
          a.kv["t:note1:can.read"].find("allowed=1"))
          << a.kv["t:note1:can.read"];
      EXPECT_NE(std::string::npos, a.kv["t:note1:resolve.guard"].find("rc=No error"))
          << a.kv["t:note1:resolve.guard"];
      EXPECT_NE(std::string::npos, b.kv["t:note1:resolve.guard"].find("rc=Invalid"))
          << b.kv["t:note1:resolve.guard"];
      /* The condition evaluator is a system read: a condition that holds
       * answers 1 for an entity that exists and 0 for one that does not, so
       * the sweep sees the difference. The false condition (asked of every
       * principal in every other test) is what must not. */
      EXPECT_TRUE(HasKey(diffs, "t:note1:cond.true")) << Join(diffs);
      EXPECT_FALSE(HasKey(diffs, "t:note1:cond.false")) << Join(diffs);
      EXPECT_NE(std::string::npos,
          a.kv["t:note1:cond.true"].find("allow=1 failed=0"))
          << a.kv["t:note1:cond.true"];
      EXPECT_NE(std::string::npos,
          a.kv["t:note1:cond.false"].find("allow=0 failed=0"))
          << a.kv["t:note1:cond.false"];
      EXPECT_NE(std::string::npos,
          a.kv["t:missing:cond.true"].find("allow=0 failed=0"))
          << a.kv["t:missing:cond.true"];
      EXPECT_TRUE(HasKey(diffs, "g:list.notes")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "g:list.notes.title=Hidden Note One"))
          << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "g:list.notes.sort-title")) << Join(diffs);
      EXPECT_FALSE(HiddenVsMissing(hidden, a).empty());
    }
    {
      /* The anonymous state may read a published post. */
      Ask ask = AskEverything(true, {"pub", "draft", "missing"});
      Obs a = Observe(hidden, "", ask);
      Obs b = Observe(absent, "", ask);
      std::vector<std::string> diffs = Differences(a, b);
      EXPECT_TRUE(HasKey(diffs, "t:pub:read.title")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "g:page/")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "g:page/pub-hidden")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "g:resolve/pub-hidden")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "g:list.posts")) << Join(diffs);
      /* The draft is not published: still invisible, still alike. */
      EXPECT_FALSE(HasKey(diffs, "t:draft:read.title")) << Join(diffs);
      EXPECT_FALSE(HasKey(diffs, "g:page/draft-hidden")) << Join(diffs);
    }
    hidden.Close();
    absent.Close();
  }
  {
    World x;
    World y;
    BuildT(&x, true);
    BuildT(&y, false);
    Ask ask = AskEverything(false,
        {"mine", "mine2", "theirs1", "theirs2", "missing"});
    Obs a = Observe(x, x.principal["all"], ask);
    Obs b = Observe(y, y.principal["all"], ask);
    std::vector<std::string> diffs = Differences(a, b);
    EXPECT_TRUE(HasKey(diffs, "t:mine:read.secret")) << Join(diffs);
    EXPECT_TRUE(HasKey(diffs, "t:theirs1:read.title")) << Join(diffs);
    EXPECT_TRUE(HasKey(diffs, "g:list.notes.secret=alpha")) << Join(diffs);
    EXPECT_TRUE(HasKey(diffs, "g:list.notes.sort-secret")) << Join(diffs);
    EXPECT_FALSE(HiddenVsMissing(x, a).empty());
    x.Close();
    y.Close();
  }
}

TEST(Oracle, ModuleGrant) {
  /* A module grant that does not hold on an existing note answers like a note
   * that does not exist: the principal has no role, the module grants reads
   * of notes titled something no note is titled, and so the two worlds are
   * the same to them. */
  {
    World hidden;
    World absent;
    BuildS(&hidden, true);
    BuildS(&absent, false);
    EnableGranting(&hidden, "(= field.title \"no-such-title-anywhere\")");
    EnableGranting(&absent, "(= field.title \"no-such-title-anywhere\")");
    Ask ask = AskEverything(false, {"note1", "note2", "missing"});
    Obs a = Observe(hidden, hidden.principal["none"], ask);
    Obs b = Observe(absent, absent.principal["none"], ask);
    EXPECT_GT(a.kv.size(), 25u);
    EXPECT_TRUE(Differences(a, b).empty())
        << "a module grant that does not hold changed an answer:"
        << Join(Differences(a, b));
    EXPECT_TRUE(HiddenVsMissing(hidden, a).empty())
        << "a hidden id answers unlike a missing one:"
        << Join(HiddenVsMissing(hidden, a));
    EXPECT_NE(std::string::npos,
        a.kv["t:note1:read.title"].find("rc=Invalid"))
        << a.kv["t:note1:read.title"];
    hidden.Close();
    absent.Close();
  }
  {
    /* The control: the same module with a condition that holds on one note.
     * The worlds now differ on that note, and only there. */
    World hidden;
    World absent;
    BuildS(&hidden, true);
    BuildS(&absent, false);
    EnableGranting(&hidden, "(= field.title \"Hidden Note One\")");
    EnableGranting(&absent, "(= field.title \"Hidden Note One\")");
    Ask ask = AskEverything(false, {"note1", "note2", "missing"});
    Obs a = Obs(Observe(hidden, hidden.principal["none"], ask));
    Obs b = Obs(Observe(absent, absent.principal["none"], ask));
    std::vector<std::string> diffs = Differences(a, b);
    EXPECT_TRUE(HasKey(diffs, "t:note1:read.title")) << Join(diffs);
    EXPECT_TRUE(HasKey(diffs, "g:list.notes")) << Join(diffs);
    EXPECT_FALSE(HasKey(diffs, "t:note2:read.title")) << Join(diffs);
    EXPECT_NE(std::string::npos, a.kv["t:note1:read.title"].find("rc=No error"))
        << a.kv["t:note1:read.title"];
    EXPECT_FALSE(HiddenVsMissing(hidden, a).empty());
    hidden.Close();
    absent.Close();
  }
}

TEST(Oracle, MatrixIsForAdministrators) {
  /* The matrix of grants is asked as a principal who may see nothing and
   * answers alike in both worlds; as the administrator it has rows (the
   * control that the probe can see one). */
  World hidden;
  World absent;
  BuildS(&hidden, true);
  BuildS(&absent, false);
  {
    Ask ask = AskEverything(false, {"missing"});
    Obs a = Observe(hidden, hidden.principal["none"], ask);
    Obs b = Observe(absent, absent.principal["none"], ask);
    EXPECT_NE(std::string::npos, a.kv["g:matrix"].find("rc=Invalid argument null n=0"))
        << a.kv["g:matrix"];
    EXPECT_EQ(a.kv["g:matrix"], b.kv["g:matrix"]);
    a = Observe(hidden, "", ask);
    EXPECT_NE(std::string::npos, a.kv["g:matrix"].find("rc=Invalid argument null n=0"))
        << a.kv["g:matrix"];
  }
  {
    char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_admin_principal(hidden.site.catalog, admin));
    Ask ask = AskEverything(false, {"missing"});
    Obs a = Observe(hidden, admin, ask);
    EXPECT_NE(std::string::npos, a.kv["g:matrix"].find("rc=No error rows="))
        << a.kv["g:matrix"];
    EXPECT_EQ(std::string::npos, a.kv["g:matrix"].find("rows=0"))
        << a.kv["g:matrix"];
  }
  hidden.Close();
  absent.Close();
}

TEST(Oracle, EverySurfaceIsAsked) {
  /* The denominator: the sweep calls every RF function of gate_surface.h. A
   * public read that takes a request and is not asked here fails. */
  World w;
  size_t i;
  std::vector<std::string> missing;
  Called().clear();
  BuildS(&w, true);
  {
    Ask ask = AskEverything(true, {"note1", "pub", "draft", "missing"});
    Observe(w, w.principal["none"], ask);
  }
  for (i = 0; i < sizeof kSurface / sizeof kSurface[0]; i++) {
    if (std::string(kSurface[i].category) == "RF" &&
        Called().count(kSurface[i].name) == 0) {
      missing.push_back(kSurface[i].name);
    }
  }
  EXPECT_TRUE(missing.empty())
      << "RF surfaces the sweep never called:" << Join(missing);
  w.Close();
}

TEST(Oracle, RenderKeyEpoch) {
  /* Known and recorded, not settled: the render key carries the tenant epoch,
   * and every applied changeset bumps it, content saves included. So a
   * principal who may see nothing, and who can see their own render key, can
   * count the writes made to entities they may not read. Everything else in
   * the key is alike in the two worlds (Oracle.Entities compares it with the
   * epoch masked). Whether the key ever reaches a client (an ETag, a header)
   * is decided above this library; if the epoch is ever split into a config
   * epoch and a content counter, this test is the one to invert. */
  World hidden;
  World absent;
  BuildS(&hidden, true);
  BuildS(&absent, false);
  uint64_t eh = 0;
  uint64_t em = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(hidden.site.catalog, &eh));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(absent.site.catalog, &em));
  EXPECT_GT(eh, em);
  hidden.Close();
  absent.Close();
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
