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
      Obs a = Observe(hidden, hidden.principal["readers"], ask);
      Obs b = Observe(absent, absent.principal["readers"], ask);
      std::vector<std::string> diffs = Differences(a, b);
      EXPECT_TRUE(HasKey(diffs, "t:note1:read.title")) << Join(diffs);
      EXPECT_TRUE(HasKey(diffs, "t:note1:read.secret")) << Join(diffs);
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
