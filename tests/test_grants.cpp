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
 * Access-conditions story A4: grants carry conditions, modules grant, and the
 * matrix says what is granted. One test (or group) per row of the story's
 * matrix. Each test that asserts a refusal or a "denied" asserts the matching
 * "allowed" beside it, so a planted defect is a test failing by name.
 */

/**
 * @file
 *
 * Access-conditions story A4: grants carry conditions, modules grant, and the
 * matrix says what is granted. One test (or group) per row of the story's
 * matrix. Each test that asserts a refusal or a "denied" asserts the matching
 * "allowed" beside it, so a planted defect is a test failing by name.
 */

#include "grants_fixture.h"

namespace {

using namespace gfx;

class Grants : public GrantsFixture {};

const char kGroupA[] = "(= field.group \"a\")";

}  // namespace

/* ---- role grants with a condition ---------------------------------------- */

TEST_F(Grants, RoleGrantWithCondition) {
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Read posts", "(= field.group \"a\")"));
  std::string holder = Principal("group-a");
  std::string other = Principal();
  std::string a = Save(Admin(), "A-post", "a");
  std::string b = Save(Admin(), "B-post", "b");
  std::string none = Save(Admin(), "No-group", NULL);
  /* The holder reads group a, and not b, and not a post with no group. */
  EXPECT_EQ("A-post", Read(holder, a));
  EXPECT_EQ("<denied>", Read(holder, b));
  EXPECT_EQ("<denied>", Read(holder, none));
  /* Without the role the same post is not readable: it is the grant that
   * allows it (the control). */
  EXPECT_EQ("<denied>", Read(other, a));
  EXPECT_EQ(std::vector<std::string>({"A-post"}), List(holder));
  EXPECT_TRUE(List(other).empty());
  /* A permission of the type could apply to some post: held. For a group no
   * post is in, it could not. */
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Role("group-z");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-z", "Edit posts", "(= field.group \"z\")"));
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", "(= field.group \"a\")"));
  EXPECT_EQ(1, Permits(holder, "update"));
  EXPECT_EQ(0, Permits(Principal("group-z"), "update"));
  EXPECT_EQ(0, Permits(other, "update"));
}

TEST_F(Grants, RoleGrantOnlyNarrows) {
  /* A permission declared `own` stays `own` under a condition of the grant's
   * own: the grant is held where both hold. */
  DefinePost();
  Declare(Perm("Read own posts", "read", GDEFCORE_ACCESS_OWN));
  Role("writers");
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("writers", "Read own posts", "(= field.group \"a\")"));
  std::string me = Principal("writers");
  std::string you = Principal("writers");
  std::string mine_a = Save(me, "mine-a", "a");
  std::string mine_b = Save(me, "mine-b", "b");
  std::string yours_a = Save(you, "yours-a", "a");
  EXPECT_EQ("mine-a", Read(me, mine_a));
  EXPECT_EQ("<denied>", Read(me, mine_b));     /* own, but not group a */
  EXPECT_EQ("<denied>", Read(me, yours_a));    /* group a, but not own */
  EXPECT_EQ(std::vector<std::string>({"mine-a"}), List(me));
}

TEST_F(Grants, RoleGrantRefusals) {
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("r");
  uint64_t epoch = Epoch();
  /* Not valid for the type, or not valid at all: nothing is written. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, GrantWhen("r", "Read posts", "(= field.nope \"a\")"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, GrantWhen("r", "Read posts", "(= field.ssn \"a\")"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      GrantWhen("r", "Read posts", "(related field.group \"a\")"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, GrantWhen("r", "Read posts", "(= field.group"));
  /* A wrong confirmation, an unknown role, an unknown permission. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      GrantWhen("r", "Read posts", "(= field.group \"a\")", "nope"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      GrantWhen("r", "Read posts", "(= field.group \"a\")", NULL));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      GrantWhen("nobody", "Read posts", "(= field.group \"a\")"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      GrantWhen("r", "No such permission", "(= field.group \"a\")"));
  EXPECT_EQ(epoch, Epoch());
  /* The control: the same call with a valid condition and confirmation. */
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("r", "Read posts", "(= field.group \"a\")"));
  EXPECT_GT(Epoch(), epoch);
  /* The states need their typed confirmations, as for any grant. */
  epoch = Epoch();
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      GrantWhen("anonymous", "Read posts", "(= field.group \"a\")", "core.role"));
  EXPECT_EQ(epoch, Epoch());
  EXPECT_EQ(GDEFCORE_OK,
      GrantWhen("anonymous", "Read posts", "(= field.group \"a\")",
          GDEFCORE_ACCESS_CONFIRM_ANONYMOUS));
  /* The same condition twice is one grant. */
  epoch = Epoch();
  EXPECT_EQ(GDEFCORE_OK, GrantWhen("r", "Read posts", "(= field.group \"a\")"));
  {
    char ** labels = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_grants(catalog_, "r", 1, &labels, &n));
    EXPECT_EQ(1u, n);
    gdefcore_access_free(catalog_, labels, n);
  }
}

/* ---- module grants ------------------------------------------------------- */

TEST_F(Grants, ModuleGrantWorks) {
  DefinePost();
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  std::string nobody = Principal();     /* a principal with no role */
  std::string a = Save(Admin(), "A-post", "a");
  std::string b = Save(Admin(), "B-post", "b");
  /* Installed is not enabled: nothing is granted yet. */
  EXPECT_EQ("<denied>", Read(nobody, a));
  EXPECT_EQ("<denied>", Read(std::string(), a));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  /* Anyone who meets the condition, role or none, signed in or not. */
  EXPECT_EQ("A-post", Read(nobody, a));
  EXPECT_EQ("A-post", Read(std::string(), a));
  EXPECT_EQ("<denied>", Read(nobody, b));
  EXPECT_EQ(std::vector<std::string>({"A-post"}), List(nobody));
  EXPECT_EQ(1, Permits(nobody, "read"));
  /* The matrix names the module. */
  {
    std::vector<Row> rows = Matrix();
    const Row * r = Find(rows, "module blog", "blog.read");
    ASSERT_NE(r, nullptr) << Dump(rows);
    EXPECT_EQ(1, r->from_module);
    EXPECT_EQ(kGroupA, r->condition);
    EXPECT_EQ("read", r->action);
    EXPECT_EQ(kPost, r->type);
  }
}

TEST_F(Grants, ModuleGrantDisappears) {
  DefinePost();
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  std::string nobody = Principal();
  std::string a = Save(Admin(), "A-post", "a");
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  EXPECT_EQ("A-post", Read(nobody, a));
  ASSERT_EQ(GDEFCORE_OK, Disable("blog"));
  /* After the same changeset: nobody, by this route, and nothing left over. */
  EXPECT_EQ("<denied>", Read(nobody, a));
  EXPECT_EQ("<denied>", Read(std::string(), a));
  EXPECT_TRUE(List(nobody).empty());
  EXPECT_EQ(0, Permits(nobody, "read"));
  EXPECT_EQ(NULL, Find(Matrix(), "module blog", "blog.read"));
  /* Enabled again, it is back (the control: the removal was the module). */
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  EXPECT_EQ("A-post", Read(nobody, a));
}

TEST_F(Grants, ModuleGrantNotSilent) {
  DefinePost();
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  std::string nobody = Principal();
  std::string a = Save(Admin(), "A-post", "a");
  std::string line = GrantLine("blog", "blog.read", "low", kGroupA);
  uint64_t epoch = Epoch();
  int on = 1;
  /* The words name the grant and its breadth. */
  EXPECT_NE(std::string::npos, line.find("blog.read"));
  EXPECT_NE(std::string::npos, line.find("low risk"));
  EXPECT_NE(std::string::npos, line.find("group"));
  /* Without the grant's words, and with them wrong: refused, nothing written. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      EnableWith("blog", Confirmation("blog", {"blog.read"})));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, EnableWith("blog", "blog"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      EnableWith("blog", Confirmation("blog", {"blog.read",
          GrantLine("blog", "blog.read", "high", kGroupA)})));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      EnableWith("blog", Confirmation("blog", {"blog.read",
          GrantLine("blog", "blog.read", "low", "(= field.group \"b\")")})));
  EXPECT_EQ(epoch, Epoch());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_module_enabled(host_, Req(), "blog", 4, &on));
  EXPECT_EQ(0, on);
  EXPECT_EQ("<denied>", Read(nobody, a));
  EXPECT_EQ(NULL, Find(Matrix(), "module blog", "blog.read"));
  /* The right words enable it (the control). */
  ASSERT_EQ(GDEFCORE_OK,
      EnableWith("blog", Confirmation("blog", {"blog.read", line})));
  EXPECT_EQ("A-post", Read(nobody, a));
}

TEST_F(Grants, ModuleGrantForeignPermission) {
  DefinePost();
  ModDef * owner = NewMod("shop");
  owner->Perm("shop.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  ASSERT_EQ(GDEFCORE_OK, Install(owner));
  ModDef * thief = NewMod("blog");
  thief->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  thief->Grant("shop.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(thief));
  GDEFCORE_Changeset * cs = NULL;
  uint64_t epoch = Epoch();
  /* Another module's permission, declared by an installed manifest: refused,
   * the error names both. */
  ASSERT_EQ(GDEFCORE_ERR_INVALID, Stage("blog", &cs));
  {
    const char * err = gdefcore_module_error(host_, NULL);
    ASSERT_NE(err, nullptr);
    EXPECT_NE(std::string::npos, std::string(err).find("blog")) << err;
    EXPECT_NE(std::string::npos, std::string(err).find("shop")) << err;
    EXPECT_NE(std::string::npos, std::string(err).find("shop.read")) << err;
  }
  EXPECT_EQ(0u, gdefcore_changeset_module_count(cs));
  gdefcore_changeset_destroy(cs);
  /* Declared by the catalog (the owner enabled): still refused, still named. */
  ASSERT_EQ(GDEFCORE_OK, Enable("shop", {}));
  ASSERT_EQ(GDEFCORE_ERR_INVALID, Stage("blog", &cs));
  {
    const char * err = gdefcore_module_error(host_, NULL);
    ASSERT_NE(err, nullptr);
    EXPECT_NE(std::string::npos, std::string(err).find("blog")) << err;
    EXPECT_NE(std::string::npos, std::string(err).find("shop")) << err;
  }
  gdefcore_changeset_destroy(cs);
  EXPECT_GT(Epoch(), epoch);   /* only the owner's enable wrote anything */
  /* A permission nobody declares is refused too. */
  ModDef * dreamer = NewMod("dream");
  dreamer->Grant("dream.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(dreamer));
  ASSERT_EQ(GDEFCORE_ERR_INVALID, Stage("dream", &cs));
  EXPECT_EQ(0u, gdefcore_changeset_module_count(cs));
  gdefcore_changeset_destroy(cs);
  /* The control: the same grant, on the module's own permission, is accepted,
   * and so is a grant of a core permission. */
  ModDef * fine = NewMod("fine");
  fine->Perm("fine.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  fine->Grant("fine.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(fine));
  ASSERT_EQ(GDEFCORE_OK, Stage("fine", &cs));
  gdefcore_changeset_destroy(cs);
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  {
    GDEFCORE_Permission core = Perm("Core read", "read", GDEFCORE_ACCESS_ANY);
    core.module_name = "core";
    core.module_name_len = 4;
    Declare(core);
  }
  ModDef * kernel = NewMod("kern");
  kernel->Grant("Core read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(kernel));
  ASSERT_EQ(GDEFCORE_OK, Stage("kern", &cs));
  gdefcore_changeset_destroy(cs);
  /* And on the permission's own type and field, not another. */
  ModDef * wrong = NewMod("wrong");
  wrong->Perm("wrong.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  wrong->Grant("wrong.read", "site.page", kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(wrong));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Stage("wrong", &cs));
  gdefcore_changeset_destroy(cs);
}

TEST_F(Grants, ModuleGrantBadCondition) {
  DefinePost();
  const char * bad[] = {
      "(= field.nope \"a\")",                 /* a field the type lacks */
      "(= field.ssn \"a\")",                  /* a personal field */
      "(related field.group \"a\")",          /* relations are not here yet */
      "(= field.group",                       /* not a condition */
      "(= type \"no.such.type\")",            /* a type that is not defined */
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    std::string name = "bad" + std::to_string(i);
    ModDef * m = NewMod(name.c_str());
    GDEFCORE_Changeset * cs = NULL;
    uint64_t epoch = Epoch();
    m->Perm(name + ".read", "read", GDEFCORE_ACCESS_ANY, kPost);
    m->Grant(name + ".read", kPost, bad[i]);
    ASSERT_EQ(GDEFCORE_OK, Install(m)) << bad[i];
    EXPECT_EQ(GDEFCORE_ERR_INVALID, Stage(name, &cs)) << bad[i];
    EXPECT_EQ(0u, gdefcore_changeset_module_count(cs)) << bad[i];
    gdefcore_changeset_destroy(cs);
    EXPECT_EQ(epoch, Epoch());
    {
      const char * err = gdefcore_module_error(host_, NULL);
      ASSERT_NE(err, nullptr) << bad[i];
      EXPECT_NE(std::string::npos, std::string(err).find(name)) << err;
    }
  }
  /* The control: a valid sibling is accepted. */
  ModDef * ok = NewMod("good");
  GDEFCORE_Changeset * cs = NULL;
  ok->Perm("good.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  ok->Grant("good.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(ok));
  EXPECT_EQ(GDEFCORE_OK, Stage("good", &cs));
  gdefcore_changeset_destroy(cs);
}

TEST_F(Grants, ModuleGrantOrderAndSweep) {
  /* The decisions and the matrix depend on which modules are enabled, never
   * on the order they were enabled or disabled in. A random walk over four
   * modules reaches every subset by many histories; each subset must always
   * show the same decisions and the same matrix. */
  DefinePost();
  const char * conds[] = {"(= field.group \"a\")", "(= field.group \"b\")",
      "(in field.group (\"a\" \"c\"))", "(= field.title \"A-post\")"};
  std::string pa;
  std::string pb;
  std::string pc;
  std::string probes[3];
  std::map<unsigned, std::string> seen;
  unsigned state = 0;
  unsigned long rng = 12345;
  size_t checks = 0;
  size_t distinct = 0;
  for (int k = 0; k < 4; k++) {
    std::string name = "m" + std::to_string(k);
    ModDef * m = NewMod(name.c_str());
    m->Perm(name + ".read", "read", GDEFCORE_ACCESS_ANY, kPost);
    m->Grant(name + ".read", kPost, conds[k]);
    ASSERT_EQ(GDEFCORE_OK, Install(m));
  }
  probes[0] = std::string();
  probes[1] = Principal();
  probes[2] = Principal();
  pa = Save(Admin(), "A-post", "a");
  pb = Save(Admin(), "B-post", "b");
  pc = Save(Admin(), "C-post", "c");
  for (int step = 0; step < 120; step++) {
    int k;
    std::string name;
    std::string snap;
    rng = rng * 6364136223846793005UL + 1442695040888963407UL;
    k = (int)((rng >> 33) % 4);
    name = "m" + std::to_string(k);
    if (state & (1u << k)) {
      ASSERT_EQ(GDEFCORE_OK, Disable(name));
    } else {
      std::string line = GrantLine(name, name + ".read", "low", conds[k]);
      ASSERT_EQ(GDEFCORE_OK, Enable(name, {line}));
    }
    state ^= 1u << k;
    for (int p = 0; p < 3; p++) {
      snap += Read(probes[p], pa) + "," + Read(probes[p], pb) + "," +
              Read(probes[p], pc) + ";" + Join(List(probes[p])) + "\n";
      /* An evaluator written apart from the library: a post is readable when
       * any enabled module's condition holds on it. */
      {
        bool want_a = (state & 1) || (state & 4) || (state & 8);
        bool want_b = (state & 2) != 0;
        bool want_c = (state & 4) != 0;
        EXPECT_EQ(want_a ? "A-post" : "<denied>", Read(probes[p], pa))
            << "subset " << state;
        EXPECT_EQ(want_b ? "B-post" : "<denied>", Read(probes[p], pb))
            << "subset " << state;
        EXPECT_EQ(want_c ? "C-post" : "<denied>", Read(probes[p], pc))
            << "subset " << state;
      }
    }
    /* The module rows only: enabling a module also grants its permissions to
     * admin, and disabling it leaves that grant, as it always has, so the
     * admin's rows depend on history. What the modules grant does not. */
    {
      std::vector<Row> rows = Matrix();
      std::vector<Row> mine;
      for (size_t i = 0; i < rows.size(); i++) {
        if (rows[i].from_module) {
          mine.push_back(rows[i]);
        }
      }
      snap += Dump(mine);
    }
    if (seen.count(state) == 0) {
      seen[state] = snap;
      distinct += 1;
    } else {
      EXPECT_EQ(seen[state], snap) << "subset " << state;
      checks += 1;
    }
  }
  /* The walk must really have revisited subsets by other histories, and the
   * subsets must really differ (a sweep that sees one answer sees nothing). */
  EXPECT_GE(distinct, 10u);
  EXPECT_GE(checks, 50u);
  {
    std::set<std::string> answers;
    for (std::map<unsigned, std::string>::const_iterator it = seen.begin();
         it != seen.end(); ++it) {
      answers.insert(it->second);
    }
    EXPECT_EQ(seen.size(), answers.size());
  }
}

TEST_F(Grants, GrantsAreAUnion) {
  /* Any grant that holds allows; order never matters. A role grant that does
   * not hold on a post does not shadow a module grant that does, and the
   * other way round. */
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("group-b");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-b", "Read posts", "(= field.group \"b\")"));
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  std::string both = Principal("group-b");     /* the role: b; the module: a */
  std::string only_module = Principal();
  std::string a = Save(Admin(), "A-post", "a");
  std::string b = Save(Admin(), "B-post", "b");
  std::string c = Save(Admin(), "C-post", "c");
  EXPECT_EQ("A-post", Read(both, a));
  EXPECT_EQ("B-post", Read(both, b));
  EXPECT_EQ("<denied>", Read(both, c));
  EXPECT_EQ("A-post", Read(only_module, a));
  EXPECT_EQ("<denied>", Read(only_module, b));
  EXPECT_EQ((std::vector<std::string>{"A-post", "B-post"}), List(both));
  /* The same with the module granted first and the role granted last. */
  Close();
  Open();
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  Role("group-b");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-b", "Read posts", "(= field.group \"b\")"));
  both = Principal("group-b");
  a = Save(Admin(), "A-post", "a");
  b = Save(Admin(), "B-post", "b");
  EXPECT_EQ("A-post", Read(both, a));
  EXPECT_EQ("B-post", Read(both, b));
}

TEST_F(Grants, ModuleGrantCeiling) {
  /* An agent acting for a person has the intersection of the two sets. A
   * module grant is held by the person, and is within the agent's ceiling only
   * if the agent's own roles hold the permission. */
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  Role("agents");
  Role("readers");
  Grant("readers", "Read posts");
  std::string person = Principal();
  std::string agent_bare = Principal();             /* no roles */
  std::string agent_reader = Principal("readers");  /* holds read on posts */
  std::string a = Save(Admin(), "A-post", "a");
  std::string b = Save(Admin(), "B-post", "b");
  /* The person alone: the module grant lets them read group a. */
  EXPECT_EQ("A-post", Read(Req(person), a));
  EXPECT_EQ("<denied>", Read(Req(person), b));
  /* Acting through an agent whose ceiling lacks the permission: denied. */
  EXPECT_EQ("<denied>", Read(Req(person, agent_bare), a));
  EXPECT_TRUE(
      [&] {
        GDEFCORE_Access_List q;
        char ** ids = NULL;
        size_t n = 0;
        memset(&q, 0, sizeof q);
        q.size = sizeof q;
        q.type_name = kPost;
        q.type_name_len = strlen(kPost);
        q.lang = "en";
        q.lang_len = 2;
        EXPECT_EQ(GDEFCORE_OK,
            gdefcore_access_list(catalog_, Req(person, agent_bare), &q, &ids, &n));
        gdefcore_access_free(catalog_, ids, n);
        return n == 0;
      }());
  EXPECT_EQ(0, gdefcore_access_permits(catalog_, Req(person, agent_bare), "read", 4));
  /* An agent whose roles hold it: the person's grant stands, within the
   * person's condition (the control). */
  EXPECT_EQ("A-post", Read(Req(person, agent_reader), a));
  EXPECT_EQ("<denied>", Read(Req(person, agent_reader), b));
  EXPECT_EQ(1, gdefcore_access_permits(catalog_, Req(person, agent_reader), "read", 4));
  /* A role grant of the person's is bounded the same way. */
  Role("group-b");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-b", "Read posts", "(= field.group \"b\")"));
  std::string reader_b = Principal("group-b");
  EXPECT_EQ("B-post", Read(Req(reader_b), b));
  EXPECT_EQ("<denied>", Read(Req(reader_b, agent_bare), b));
  EXPECT_EQ("B-post", Read(Req(reader_b, agent_reader), b));
  /* The person acting as themselves is not an agent. */
  EXPECT_EQ("A-post", Read(Req(person, person), a));
  /* The render key depends on the acting principal. */
  {
    char * k1 = NULL;
    char * k2 = NULL;
    size_t n1 = 0;
    size_t n2 = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(catalog_, Req(person), NULL, 0, NULL, 0, &k1, &n1));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(catalog_, Req(person, agent_bare), NULL, 0, NULL,
            0, &k2, &n2));
    EXPECT_NE(std::string(k1, n1), std::string(k2, n2));
    gdefcore_text_free(catalog_, k1);
    gdefcore_text_free(catalog_, k2);
  }
}

TEST_F(Grants, ModuleGrantFailsClosed) {
  /* A grant whose permission is declared by someone else (a label another
   * module already holds) is inert: skipped, never widened. Enable accepts it
   * because the module's own manifest declares the label; the catalog's
   * declaration, which came first, is what decides. */
  DefinePost();
  Declare(Perm("blog.read", "read", GDEFCORE_ACCESS_ANY));   /* module "site" */
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  std::string nobody = Principal();
  std::string a = Save(Admin(), "A-post", "a");
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}))
      << last_error_;
  EXPECT_EQ("<denied>", Read(nobody, a));
  EXPECT_EQ(0, Permits(nobody, "read"));
  /* The control: the same module on a catalog where the label is its own. */
  Close();
  Open();
  DefinePost();
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  a = Save(Admin(), "A-post", "a");
  nobody = Principal();
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  EXPECT_EQ("A-post", Read(nobody, a));
}

/* ---- the matrix ---------------------------------------------------------- */

TEST_F(Grants, MatrixRolesAndModules) {
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Edit own posts", "update", GDEFCORE_ACCESS_OWN));
  Declare(Perm("Delete posts", "delete", GDEFCORE_ACCESS_ANY));
  Role("editors");
  Role("deleters");
  Grant("editors", "Read posts");
  Grant("editors", "Edit own posts");
  Grant("deleters", "Delete posts");
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("editors", "Delete posts", "(= field.group \"a\")"));
  ModDef * m = NewMod("blog");
  m->Perm("blog.read", "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.read", kPost, kGroupA);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK,
      Enable("blog", {GrantLine("blog", "blog.read", "low", kGroupA)}));
  std::vector<Row> rows = Matrix();
  const Row * r;
  /* Rows for both kinds of source, each naming it. */
  r = Find(rows, "role editors", "Read posts");
  ASSERT_NE(r, nullptr) << Dump(rows);
  EXPECT_EQ("(= type \"site.post\")", r->condition);
  EXPECT_EQ(0, r->from_module);
  EXPECT_FALSE(r->explain.empty());
  r = Find(rows, "role editors", "Edit own posts");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW, r->risk);
  r = Find(rows, "role deleters", "Delete posts");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, r->risk);   /* delete, nothing narrows it */
  r = Find(rows, "module blog", "blog.read");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(1, r->from_module);
  /* A role grant with a condition of its own shows the label as declared and
   * the condition that applies. */
  r = Find(rows, "role editors", "Delete posts");
  ASSERT_NE(r, nullptr) << Dump(rows);
  EXPECT_NE(std::string::npos, r->condition.find("field.group"));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, r->risk);
  /* Deterministic order. */
  for (size_t i = 1; i < rows.size(); i++) {
    EXPECT_LE(rows[i - 1].source, rows[i].source) << Dump(rows);
  }
  EXPECT_EQ(Dump(rows), Dump(Matrix()));
}

TEST_F(Grants, MatrixOnlyForAdmin) {
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("editors");
  Grant("editors", "Read posts");
  GDEFCORE_Result rc = GDEFCORE_ERR_INTERNAL;
  /* The control: the administrator reads it, and it has rows. */
  EXPECT_FALSE(Matrix(&rc).empty());
  EXPECT_EQ(GDEFCORE_OK, rc);
  /* Anyone else is told what a page that is not there is told, with no row. */
  std::string editor = Principal("editors");
  std::string nobody = Principal();
  EXPECT_TRUE(Matrix(&rc, editor).empty());
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  EXPECT_TRUE(Matrix(&rc, nobody).empty());
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  {
    GDEFCORE_Access_Matrix_Row * rows = (GDEFCORE_Access_Matrix_Row *)0x1;
    size_t n = 99;
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_access_matrix(catalog_, Req(), &rows, &n));   /* anonymous */
    EXPECT_EQ(NULL, rows);
    EXPECT_EQ(0u, n);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_access_matrix(catalog_, NULL, &rows, &n));
  }
  /* An agent acting for the administrator is not the administrator. */
  {
    GDEFCORE_Access_Matrix_Row * rows = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_ERR_INVALID,
        gdefcore_access_matrix(catalog_, Req(Admin(), nobody), &rows, &n));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_matrix(catalog_, Req(Admin(), Admin()), &rows, &n));
    gdefcore_access_matrix_free(catalog_, rows, n);
  }
}

TEST_F(Grants, MatrixKeepsHostileText) {
  /* The matrix holds plain text; escaping is the page's job. Markup in a
   * module's name, label and condition constant arrives untouched. */
  DefinePost();
  ModDef * m = NewMod("blog");
  std::string label = "blog.<b>read</b>";
  std::string cond = "(= field.group \"<script>x</script>\")";
  m->Perm(label, "read", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant(label, kPost, cond);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK, Enable("blog", {GrantLine("blog", label, "low", cond)}))
      << last_error_;
  std::vector<Row> rows = Matrix();
  const Row * r = Find(rows, "module blog", label);
  ASSERT_NE(r, nullptr) << Dump(rows);
  EXPECT_NE(std::string::npos, r->condition.find("<script>x</script>"));
  EXPECT_NE(std::string::npos, r->explain.find("<script>x</script>"));
}

TEST_F(Grants, RiskRatings) {
  struct Case {
    const char * action;
    int field;
    const char * cond;
    int anon;
    int want;
  };
  const Case cases[] = {
      /* High: a condition that bounds nothing. */
      {"read", 0, "true", 0, GDEFCORE_ACCESS_RISK_HIGH},
      {"read", 0, "(= principal \"x\")", 0, GDEFCORE_ACCESS_RISK_HIGH},
      {"update", 0, "(< now 100)", 0, GDEFCORE_ACCESS_RISK_HIGH},
      {"update", 0, "(not (= type \"t\"))", 0, GDEFCORE_ACCESS_RISK_HIGH},
      /* A type is not named but the entity's data bounds it. */
      {"read", 0, "(= field.group \"a\")", 0, GDEFCORE_ACCESS_RISK_LOW},
      {"update", 0, "(or (= type \"t\") (= field.group \"a\"))", 0,
          GDEFCORE_ACCESS_RISK_MEDIUM},
      /* High: anonymous, and not a read. */
      {"update", 0, "(and (= type \"t\") (= field.group \"a\"))", 1,
          GDEFCORE_ACCESS_RISK_HIGH},
      {"core.template.edit.core.pane", 0, "(= type \"t\")", 1,
          GDEFCORE_ACCESS_RISK_HIGH},
      /* High: a strong action nothing narrows. */
      {"delete", 0, "(= type \"t\")", 0, GDEFCORE_ACCESS_RISK_HIGH},
      {"publish", 0, "(= type \"t\")", 0, GDEFCORE_ACCESS_RISK_HIGH},
      {"core.admin.something", 0, "(= type \"t\")", 0, GDEFCORE_ACCESS_RISK_HIGH},
      {"mystery", 0, "(= type \"t\")", 0, GDEFCORE_ACCESS_RISK_HIGH},
      {"read", 0, "(= type", 0, GDEFCORE_ACCESS_RISK_HIGH},   /* unreadable */
      /* Medium: an edit nothing narrows, a read nothing narrows, a field. */
      {"update", 0, "(= type \"t\")", 0, GDEFCORE_ACCESS_RISK_MEDIUM},
      {"core.template.edit.core.pane", 0, "(= type \"t\")", 0,
          GDEFCORE_ACCESS_RISK_MEDIUM},
      {"read", 0, "(= type \"t\")", 0, GDEFCORE_ACCESS_RISK_MEDIUM},
      {"read", 1, "(= type \"t\")", 0, GDEFCORE_ACCESS_RISK_MEDIUM},
      {"read", 1, "(and (= type \"t\") (= field.group \"a\"))", 0,
          GDEFCORE_ACCESS_RISK_MEDIUM},
      {"update", 0, "(and (= type \"t\") (= field.group \"a\"))", 0,
          GDEFCORE_ACCESS_RISK_MEDIUM},
      {"delete", 0, "(and (= type \"t\") (= field.group \"a\"))", 0,
          GDEFCORE_ACCESS_RISK_MEDIUM},
      /* Low: a read that is narrowed; own. */
      {"read", 0, "(and (= type \"t\") (= field.group \"a\"))", 0,
          GDEFCORE_ACCESS_RISK_LOW},
      {"read", 0, "(and (= type \"t\") (= principal \"x\"))", 0,
          GDEFCORE_ACCESS_RISK_LOW},
      {"read", 1, "(and (= type \"t\") (= creator principal))", 0,
          GDEFCORE_ACCESS_RISK_LOW},
      {"update", 0, "(and (= type \"t\") (= creator principal))", 0,
          GDEFCORE_ACCESS_RISK_LOW},
      {"delete", 0, "(and (= type \"t\") (= creator principal))", 0,
          GDEFCORE_ACCESS_RISK_LOW},
      /* The revision's creator is as personal as the entity's. */
      {"update", 0, "(and (= type \"t\") (= revision.creator principal))", 0,
          GDEFCORE_ACCESS_RISK_LOW},
      /* A read reaches the anonymous state without raising the rating. */
      {"read", 0, "(and (= type \"t\") (= field.group \"a\"))", 1,
          GDEFCORE_ACCESS_RISK_LOW},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    const Case & c = cases[i];
    EXPECT_EQ(c.want,
        gdefcore_access_grant_risk(c.action, strlen(c.action), c.field, c.cond,
            strlen(c.cond), c.anon))
        << c.action << " field=" << c.field << " " << c.cond << " anon=" << c.anon;
  }
  EXPECT_STREQ("low", gdefcore_access_risk_name(GDEFCORE_ACCESS_RISK_LOW));
  EXPECT_STREQ("medium", gdefcore_access_risk_name(GDEFCORE_ACCESS_RISK_MEDIUM));
  EXPECT_STREQ("high", gdefcore_access_risk_name(GDEFCORE_ACCESS_RISK_HIGH));
  EXPECT_STREQ("unknown", gdefcore_access_risk_name(0));
}

TEST_F(Grants, RiskInTheMatrixAndTheConfirmation) {
  /* An unconstrained write grant by a module is high in both places: the
   * confirmation says so in its words, and the matrix rates it so. */
  DefinePost();
  ModDef * m = NewMod("blog");
  m->Perm("blog.delete", "delete", GDEFCORE_ACCESS_ANY, kPost);
  m->Perm("blog.edit", "update", GDEFCORE_ACCESS_ANY, kPost);
  m->Grant("blog.delete", kPost, "(= type \"site.post\")");
  m->Grant("blog.edit", kPost, "(and (= type \"site.post\") (= field.group \"a\"))");
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  std::string high = GrantLine("blog", "blog.delete", "high",
      "(= type \"site.post\")");
  std::string medium = GrantLine("blog", "blog.edit", "high",
      "(and (= type \"site.post\") (= field.group \"a\"))");
  /* Both reach the anonymous state (neither reads the principal): an edit of
   * group a by anyone at all is high as well. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      EnableWith("blog", Confirmation("blog", {"blog.delete", "blog.edit",
          GrantLine("blog", "blog.delete", "low", "(= type \"site.post\")"),
          medium})));
  ASSERT_EQ(GDEFCORE_OK, Enable("blog", {high, medium})) << last_error_;
  std::vector<Row> rows = Matrix();
  const Row * r = Find(rows, "module blog", "blog.delete");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, r->risk);
  r = Find(rows, "module blog", "blog.edit");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, r->risk);
}

TEST_F(Grants, OldApiUnchanged) {
  /* The integer conditions and gdefcore_access_grant keep their meaning. */
  DefinePost();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Read own posts", "read", GDEFCORE_ACCESS_OWN));
  Role("anyr");
  Role("ownr");
  Grant("anyr", "Read posts");
  Grant("ownr", "Read own posts");
  std::string me = Principal("ownr");
  std::string reader = Principal("anyr");
  std::string mine = Save(me, "mine", "a");
  std::string theirs = Save(Admin(), "theirs", "a");
  EXPECT_EQ("mine", Read(me, mine));
  EXPECT_EQ("<denied>", Read(me, theirs));
  EXPECT_EQ("mine", Read(reader, mine));
  EXPECT_EQ("theirs", Read(reader, theirs));
  /* With no module host bound there are no module grants and nothing breaks. */
  gdefcore_catalog_bind_host(catalog_, NULL);
  EXPECT_EQ("theirs", Read(reader, theirs));
  gdefcore_catalog_bind_host(catalog_, host_);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
