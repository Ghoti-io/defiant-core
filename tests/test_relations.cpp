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
 * Story A3: relations, declared by modules, read as the system. One test (or
 * group) per row of the story's matrix. Each test that asserts a refusal or a
 * "denied" asserts the matching "allowed" beside it, so a planted defect is a
 * test failing by name. A generated sweep holds the compiled list that rests
 * on a relation to the evaluated one, on memory and on SQLite.
 */

#include "grants_fixture.h"

#include <fstream>
#include <sstream>

namespace {

using namespace gfx;

const char kEditor[] = "t.editor";
const char kViewer[] = "t.viewer";
const char kOwn[] = "(related \"t.editor\" (principal field.group))";

/** A catalog allocator that fails one allocation (the ordinal in `target`). */
struct FailAlloc {
  GCU_Allocator alloc;
  bool armed = false;
  long target = 0;
  long seen = 0;
};

bool Hit(FailAlloc * f) {
  if (!f->armed) {
    return false;
  }
  f->seen += 1;
  return f->target > 0 && f->seen == f->target;
}

void * FaMalloc(void * ctx, size_t n) {
  return Hit((FailAlloc *)ctx) ? NULL : malloc(n == 0 ? 1 : n);
}

void * FaCalloc(void * ctx, size_t count, size_t n) {
  return Hit((FailAlloc *)ctx) ? NULL : calloc(count == 0 ? 1 : count, n == 0 ? 1 : n);
}

void * FaRealloc(void * ctx, void * p, size_t n) {
  return Hit((FailAlloc *)ctx) ? NULL : realloc(p, n == 0 ? 1 : n);
}

void FaFree(void *, void * p) {
  free(p);
}

class Relations : public GrantsFixture {
 protected:
  /** The module `t`: two relations, a permission to edit posts, and a grant
   * of it to the editors of a post's group. */
  ModDef * Declare_t(bool with_grant = true, const std::string & cond = kOwn) {
    ModDef * m = NewMod("t");
    m->Relation(kEditor, {{"who", GDEFCORE_RELATION_ENTITY, ""},
                             {"group", GDEFCORE_RELATION_TEXT, ""}});
    m->Relation(kViewer, {{"who", GDEFCORE_RELATION_ENTITY, ""}});
    m->Perm("t.edit", "update", GDEFCORE_ACCESS_ANY, kPost);
    m->Perm("t.see", "read", GDEFCORE_ACCESS_ANY, kPost);
    if (with_grant) {
      m->Grant("t.edit", kPost, cond);
      m->Grant("t.see", kPost, cond);
    }
    return m;
  }

  static std::string Note(const std::string & relation) {
    return "Its breadth depends on who may add rows to the relation " + relation +
           ": anyone who can add a row widens this grant.";
  }

  /** The confirmation line a module's grant on @p cond shows, with the note. */
  static std::string RelGrantLine(const std::string & module,
      const std::string & label, const char * risk, const std::string & cond,
      const std::string & relation) {
    return GrantLine(module, label, risk, cond) + " " + Note(relation);
  }

  /** Boot: the post type, the module installed and enabled. */
  void Boot(bool with_grant = true, const std::string & cond = kOwn) {
    DefinePost();
    ModDef * m = Declare_t(with_grant, cond);
    ASSERT_EQ(GDEFCORE_OK, Install(m));
    ASSERT_EQ(GDEFCORE_OK, Enable("t", GrantLines(with_grant, cond))) << last_error_;
  }

  /** The two grants' lines: an update that can change the field it tests is
   * rated a step up, a read is not. */
  static std::vector<std::string> GrantLines(bool with_grant, const std::string & cond) {
    std::vector<std::string> lines;
    if (with_grant) {
      lines.push_back(RelGrantLine("t", "t.edit", "high", cond, kEditor));
      lines.push_back(RelGrantLine("t", "t.see", "medium", cond, kEditor));
    }
    return lines;
  }

  GDEFCORE_Result Add(const char * relation, const std::vector<std::string> & v,
      const std::string & module = "t", const std::string & actor = std::string(),
      int * added = NULL) {
    std::vector<const char *> p;
    std::vector<size_t> n;
    for (const std::string & s : v) {
      p.push_back(s.c_str());
      n.push_back(s.size());
    }
    return gdefcore_relation_add(catalog_, module.data(), module.size(), relation,
        strlen(relation), p.data(), n.data(), p.size(),
        actor.empty() ? NULL : actor.data(), actor.size(), added);
  }

  /** Remove; a NULL-like entry (the string "\0*") is a column left free. */
  GDEFCORE_Result Remove(const char * relation, const std::vector<std::string> & v,
      size_t * removed = NULL, const std::string & module = "t") {
    std::vector<const char *> p;
    std::vector<size_t> n;
    for (const std::string & s : v) {
      p.push_back(s == "*" ? NULL : s.c_str());
      n.push_back(s.size());
    }
    return gdefcore_relation_remove(catalog_, module.data(), module.size(),
        relation, strlen(relation), p.data(), n.data(), p.size(), NULL, 0, removed);
  }

  bool Can(const std::string & who, const std::string & post,
      const char * action = "update") {
    int allowed = -1;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_can(catalog_, Req(who), action, strlen(action), kPost,
            strlen(kPost), post.c_str(), &allowed));
    return allowed == 1;
  }

  uint64_t Version(const char * relation) {
    uint64_t v = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_relation_version(catalog_, relation, strlen(relation), &v));
    return v;
  }

  /** How many rows there are: the ones with a current revision, not the ones
   * a removal cleared. */
  size_t Rows() {
    GDEFSTOR_Query q;
    char ** ids = NULL;
    size_t n = 0;
    uint64_t total = 0;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_query_current(catalog_, GDEFCORE_RELATION_ROW_TYPE,
            strlen(GDEFCORE_RELATION_ROW_TYPE), &q, &ids, &n, &total));
    gdefcore_ids_free(catalog_, ids, n);
    return (size_t)total;
  }

  std::string RenderKey(GDEFCORE_Request * r) {
    char * k = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(catalog_, r, NULL, 0, NULL, 0, &k, &n));
    std::string out(k, n);
    gdefcore_text_free(catalog_, k);
    return out;
  }

  /** The `reads:` line of a key, the digest of what a request read. */
  static std::string Reads(const std::string & key) {
    size_t at = key.find("\nreads:");
    if (at == std::string::npos) {
      return "";
    }
    size_t end = key.find('\n', at + 1);
    return key.substr(at, end == std::string::npos ? std::string::npos : end - at);
  }

  /** The validation of a written condition on the post type. */
  std::string Check(const std::string & text, GDEFCORE_Result * rc_out = NULL) {
    GDEFCORE_Condition * c = NULL;
    GDEFCORE_Condition_Error err;
    memset(&err, 0, sizeof err);
    err.size = sizeof err;
    GDEFCORE_Result rc = gdefcore_condition_parse(text.data(), text.size(), &c, &err);
    if (rc != GDEFCORE_OK) {
      if (rc_out != NULL) {
        *rc_out = rc;
      }
      return std::string("parse: ") + err.message + " @" + std::to_string(err.offset);
    }
    rc = gdefcore_condition_validate(catalog_, c, kPost, strlen(kPost), &err);
    gdefcore_condition_free(c);
    if (rc_out != NULL) {
      *rc_out = rc;
    }
    if (rc == GDEFCORE_OK) {
      return "ok";
    }
    return std::string(err.message) + " @" + std::to_string(err.offset);
  }
};

}  // namespace

/* ---- the manifest -------------------------------------------------------- */

TEST_F(Relations, TheManifestDeclaresRelationsAndTheHostEnumeratesThem) {
  DefinePost();
  ModDef * m = Declare_t(false);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  const GDEFCORE_Module_Declared_Relation ** items = NULL;
  size_t n = 0;
  size_t tenant_len = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(catalog_, &tenant_len);
  /* Installed is not enabled: nothing is declared yet. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_relations(host_, tenant, tenant_len, NULL, &items, &n));
  EXPECT_EQ(0u, n);
  ASSERT_EQ(GDEFCORE_OK, Enable("t", {}));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_relations(host_, tenant, tenant_len, NULL, &items, &n));
  ASSERT_EQ(2u, n);
  EXPECT_EQ("t.editor", std::string(items[0]->name, items[0]->name_len));
  EXPECT_EQ("t", std::string(items[0]->module, items[0]->module_len));
  ASSERT_EQ(2u, items[0]->ncolumns);
  EXPECT_EQ("who", std::string(items[0]->columns[0].name, items[0]->columns[0].name_len));
  EXPECT_EQ(GDEFCORE_RELATION_ENTITY, items[0]->columns[0].kind);
  EXPECT_EQ(GDEFCORE_RELATION_TEXT, items[0]->columns[1].kind);
  EXPECT_EQ("t.viewer", std::string(items[1]->name, items[1]->name_len));
  EXPECT_EQ(1u, items[1]->ncolumns);
  gdefcore_module_declared_free(host_, items);
  /* Disabled, they are gone from the enumeration. */
  ASSERT_EQ(GDEFCORE_OK, Disable("t"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_module_relations(host_, tenant, tenant_len, NULL, &items, &n));
  EXPECT_EQ(0u, n);
}

TEST_F(Relations, ABadDeclarationRefusesTheInstallOrTheEnable) {
  struct Case {
    const char * what;
    std::string name;
    std::vector<ModDef::Col> cols;
  };
  std::vector<Case> cases = {
      {"a name outside the module", "other.editor", {{"who", 1, ""}}},
      {"no columns", "m.none", {}},
      {"five columns", "m.wide",
          {{"a", 2, ""}, {"b", 2, ""}, {"c", 2, ""}, {"d", 2, ""}, {"e", 2, ""}}},
      {"a column kind that is not one", "m.kind", {{"a", 9, ""}}},
      {"a column name with a capital", "m.cap", {{"Who", 1, ""}}},
      {"two columns of one name", "m.dup", {{"who", 1, ""}, {"who", 2, ""}}},
      {"a type on a text column", "m.typed", {{"who", 2, "site.post"}}},
  };
  for (const Case & c : cases) {
    Close();
    Defs().clear();
    Open();
    DefinePost();
    ModDef * m = NewMod("m");
    m->Relation(c.name, c.cols);
    GDEFCORE_Result rc = Install(m);
    if (rc == GDEFCORE_OK) {
      rc = Enable("m", {});
    }
    EXPECT_NE(GDEFCORE_OK, rc) << c.what;
  }
  /* The control: a well formed relation installs and enables. */
  Close();
  Defs().clear();
  Open();
  DefinePost();
  ModDef * ok = NewMod("m");
  ok->Relation("m.fine", {{"who", 1, "site.post"}, {"n", 3, ""}});
  ASSERT_EQ(GDEFCORE_OK, Install(ok));
  EXPECT_EQ(GDEFCORE_OK, Enable("m", {})) << last_error_;
  /* A relation declared twice by one module is refused when it is enabled. */
  Close();
  Defs().clear();
  Open();
  ModDef * twice = NewMod("m");
  twice->Relation("m.same", {{"who", 1, ""}});
  twice->Relation("m.same", {{"who", 1, ""}});
  ASSERT_EQ(GDEFCORE_OK, Install(twice));
  EXPECT_NE(GDEFCORE_OK, Enable("m", {}));
}

TEST_F(Relations, AnEntityColumnNamesATypeThatIsDefinedOrTheModulesOwn) {
  ModDef * m = NewMod("t");
  m->Relation("t.ref", {{"post", GDEFCORE_RELATION_ENTITY, "site.post"}});
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  /* site.post is not defined yet. */
  EXPECT_NE(GDEFCORE_OK, Enable("t", {}));
  EXPECT_NE(std::string::npos, last_error_.find("site.post")) << last_error_;
  DefinePost();
  EXPECT_EQ(GDEFCORE_OK, Enable("t", {})) << last_error_;
  /* A type in the module's own namespace is allowed before it is defined. */
  Defs().clear();
  ModDef * own = NewMod("u");
  own->Relation("u.ref", {{"thing", GDEFCORE_RELATION_ENTITY, "u.thing"}});
  ASSERT_EQ(GDEFCORE_OK, Install(own));
  EXPECT_EQ(GDEFCORE_OK, Enable("u", {})) << last_error_;
}

/* ---- the language -------------------------------------------------------- */

TEST_F(Relations, TheValidatorChecksTheRelationTheArityAndTheKinds) {
  Boot(false);
  EXPECT_EQ("ok", Check(kOwn));
  EXPECT_EQ("ok", Check("(related \"t.editor\" (_ \"g1\"))"));
  EXPECT_EQ("ok", Check("(related \"t.editor\" (principal _))"));
  EXPECT_EQ("ok", Check("(related \"t.viewer\" (creator))"));
  EXPECT_EQ("ok", Check("(related \"t.viewer\" (revision.creator))"));
  /* A relation no enabled module declares. */
  EXPECT_EQ("no such relation @0", Check("(related \"t.ghost\" (principal))"));
  EXPECT_EQ("no such relation @5", Check("(and (related \"t.ghost\" (principal)) true)"));
  /* The wrong number of operands. */
  EXPECT_EQ("the number of operands is not the number of columns @0",
      Check("(related \"t.editor\" (principal))"));
  EXPECT_EQ("the number of operands is not the number of columns @0",
      Check("(related \"t.editor\" (principal field.group field.title))"));
  /* An operand that does not suit its column, at the operand. */
  EXPECT_EQ("this operand does not suit the column @21",
      Check("(related \"t.editor\" (now field.group))"));
  EXPECT_EQ("this operand does not suit the column @21",
      Check("(related \"t.editor\" (3 field.group))"));
  EXPECT_EQ("this operand does not suit the column @21",
      Check("(related \"t.editor\" (\"alice\" field.group))"));
  EXPECT_EQ("this operand does not suit the column @21",
      Check("(related \"t.editor\" (type field.group))"));
  /* A personal field is refused where any field is. */
  EXPECT_EQ("no such field @21",
      Check("(related \"t.editor\" (field.ssn field.group))"));
  EXPECT_EQ("no such field @21",
      Check("(related \"t.editor\" (field.nope field.group))"));
  /* Control: a canonical public id suits an entity column. */
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
  EXPECT_EQ("ok", Check(std::string("(related \"t.editor\" (\"") + id + "\" _))"));
}

TEST_F(Relations, ParsingHasItsLimitsAndItsOwnMessages) {
  GDEFCORE_Condition_Error err;
  auto parse = [&](const std::string & text) {
    memset(&err, 0, sizeof err);
    err.size = sizeof err;
    GDEFCORE_Condition * c = NULL;
    GDEFCORE_Result rc = gdefcore_condition_parse(text.data(), text.size(), &c, &err);
    gdefcore_condition_free(c);
    return rc == GDEFCORE_OK ? std::string("ok")
                             : std::string(err.message) + " @" + std::to_string(err.offset);
  };
  EXPECT_EQ("ok", parse("(related \"r\" (principal))"));
  EXPECT_EQ("ok", parse("(related \"r\" (principal _ _ _))"));
  EXPECT_EQ("a related takes one to four operands in a list @30",
      parse("(related \"r\" (principal _ _ _ _))"));
  EXPECT_EQ("a related takes one to four operands in a list @14",
      parse("(related \"r\" ())"));
  EXPECT_EQ("a relation name in quotes was expected @9",
      parse("(related r (principal))"));
  EXPECT_EQ("related is written (related \"relation\" (operand ...)) @3",
      parse("(= related 1)"));
  EXPECT_NE("ok", parse("related"));
  EXPECT_NE("ok", parse("(and related)"));
  /* Four relations in one condition; the fifth is refused. */
  std::string four = "(and";
  for (int i = 0; i < 4; i++) {
    four += " (related \"r" + std::to_string(i) + "\" (principal))";
  }
  EXPECT_EQ("ok", parse(four + ")"));
  EXPECT_NE(std::string::npos,
      parse(four.substr(0, four.size()) + " (related \"r4\" (principal)))")
          .find("at most four relations"));
  /* The same relation twice is two uses. */
  EXPECT_NE("ok", parse("(and (related \"r\" (principal)) (related \"r\" (principal)) "
                        "(related \"r\" (principal)) (related \"r\" (principal)) "
                        "(related \"r\" (principal)))"));
  /* `_` is an operand of a related and of nothing else. */
  EXPECT_NE("ok", parse("(= _ 1)"));
  EXPECT_NE("ok", parse("(in _ (\"a\"))"));
}

TEST_F(Relations, CanonicalTextExplainAndHash) {
  GDEFCORE_Condition * c = NULL;
  const std::string a = "(related   \"t.editor\"   (principal    field.group))";
  const std::string b = "(related \"t.editor\" (principal field.group))";
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_parse(a.data(), a.size(), &c, NULL));
  char * canon = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_canonical(c, &canon, &n));
  EXPECT_EQ(b, std::string(canon, n));
  gdefcore_condition_text_free(canon);
  char * words = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_explain(c, &words, &n));
  EXPECT_EQ("there is a row of t.editor listing the person and the group field",
      std::string(words, n));
  gdefcore_condition_text_free(words);
  EXPECT_EQ(GDEFCORE_CONDITION_USES_PRINCIPAL | GDEFCORE_CONDITION_USES_ENTITY |
                GDEFCORE_CONDITION_USES_RELATION,
      gdefcore_condition_uses(c));
  const char * name = NULL;
  ASSERT_EQ(1, gdefcore_condition_relation_at(c, 0, &name, &n));
  EXPECT_EQ("t.editor", std::string(name, n));
  EXPECT_EQ(0, gdefcore_condition_relation_at(c, 1, &name, &n));
  gdefcore_condition_free(c);
  char h1[GDEFCORE_CONDITION_HASH_LEN + 1];
  char h2[GDEFCORE_CONDITION_HASH_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_hash(a.data(), a.size(), h1, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_hash(b.data(), b.size(), h2, NULL));
  EXPECT_STREQ(h1, h2);
  /* Operands keep their order: they are the columns. */
  const std::string swapped = "(related \"t.editor\" (field.group principal))";
  char h3[GDEFCORE_CONDITION_HASH_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_hash(swapped.data(), swapped.size(), h3, NULL));
  EXPECT_STRNE(h2, h3);
  /* A free column is written `_` and read back. */
  const std::string free_col = "(related \"t.editor\" (_ \"g1\"))";
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_parse(free_col.data(), free_col.size(), &c, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_explain(c, &words, &n));
  EXPECT_EQ("there is a row of t.editor listing anything and g1", std::string(words, n));
  gdefcore_condition_text_free(words);
  gdefcore_condition_free(c);
}

/* ---- membership ---------------------------------------------------------- */

TEST_F(Relations, MembershipGrantsAndOnlyForTheRowsOwner) {
  Boot();
  std::string alice = Principal();
  std::string bob = Principal();
  std::string g1 = Save(Admin(), "p1", "g1");
  std::string g2 = Save(Admin(), "p2", "g2");
  /* No row yet: nobody may. */
  EXPECT_FALSE(Can(alice, g1));
  EXPECT_FALSE(Can(bob, g1));
  int added = -1;
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}, "t", Admin(), &added));
  EXPECT_EQ(1, added);
  EXPECT_TRUE(Can(alice, g1));      /* her group */
  EXPECT_FALSE(Can(alice, g2));     /* not her group */
  EXPECT_FALSE(Can(bob, g1));       /* not listed */
  EXPECT_FALSE(Can(std::string(), g1)); /* anonymous is nobody */
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {bob, "g2"}));
  EXPECT_TRUE(Can(bob, g2));
  EXPECT_FALSE(Can(bob, g1));
  EXPECT_TRUE(Can(alice, g1));
  /* Taking the row away takes the access away, at once. */
  size_t removed = 0;
  ASSERT_EQ(GDEFCORE_OK, Remove(kEditor, {alice, "g1"}, &removed));
  EXPECT_EQ(1u, removed);
  EXPECT_FALSE(Can(alice, g1));
  EXPECT_TRUE(Can(bob, g2));
  /* The post that has no group is in nobody's group. */
  std::string loose = Save(Admin(), "p3", NULL);
  EXPECT_FALSE(Can(bob, loose));
}

TEST_F(Relations, ListsAndCountsFollowTheRelationToo) {
  Boot();
  /* The permission is an update; a read grant over the same relation. */
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("readers");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("readers", "Read posts", kOwn));
  std::string alice = Principal("readers");
  std::string bob = Principal("readers");
  Save(Admin(), "p1", "g1");
  Save(Admin(), "p2", "g1");
  Save(Admin(), "p3", "g2");
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {bob, "g2"}));
  EXPECT_EQ(std::vector<std::string>({"p1", "p2"}), List(alice));
  EXPECT_EQ(std::vector<std::string>({"p3"}), List(bob));
  /* The same through a count, and for a principal who is nobody's editor. */
  GDEFCORE_Access_List q;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.type_name = kPost;
  q.type_name_len = strlen(kPost);
  q.lang = "en";
  q.lang_len = 2;
  uint64_t total = 9;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(catalog_, Req(alice), &q, &total));
  EXPECT_EQ(2u, total);
  GDEFCORE_Request * r = Req(Principal("readers"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(catalog_, r, &q, &total));
  EXPECT_EQ(0u, total);
}

TEST_F(Relations, ADisabledModulesRelationDecidesNothing) {
  Boot(false);
  /* A grant of a role that rests on a relation; and one on its negation. */
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("members");
  Role("outsiders");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("members", "Read posts", kOwn));
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("outsiders", "Read posts",
          "(not (related \"t.editor\" (principal field.group)))"));
  std::string alice = Principal("members");
  std::string bob = Principal("outsiders");
  std::string post = Save(Admin(), "p1", "g1");
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  /* Alice is listed and reads; bob is not, and an outsider is one who is not. */
  EXPECT_EQ("p1", Read(alice, post));
  EXPECT_EQ("p1", Read(bob, post));
  /* List bob, and the negation stops holding for him. */
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {bob, "g1"}));
  EXPECT_EQ("<denied>", Read(bob, post));
  ASSERT_EQ(GDEFCORE_OK, Remove(kEditor, {bob, "*"}));
  EXPECT_EQ("p1", Read(bob, post));
  /* Disable the module, in one changeset: no relation, no decision. */
  ASSERT_EQ(GDEFCORE_OK, Disable("t"));
  EXPECT_EQ("<denied>", Read(alice, post));
  EXPECT_EQ("<denied>", Read(bob, post))
      << "a relation that is gone must not turn `not` into a grant";
  EXPECT_TRUE(List(alice).empty());
  EXPECT_TRUE(List(bob).empty());
  EXPECT_EQ(0, Permits(alice, "read"));
  /* The rows stayed; back with the module. */
  EXPECT_EQ(1u, Rows());
  ASSERT_EQ(GDEFCORE_OK, Enable("t", GrantLines(false, kOwn))) << last_error_;
  EXPECT_EQ("p1", Read(alice, post));
  EXPECT_EQ("p1", Read(bob, post));
}

TEST_F(Relations, AnUndeclaredRelationIsNeverRead) {
  Boot(false);
  std::string alice = Principal();
  std::string post = Save(Admin(), "p1", "g1");
  /* Rows of a relation nobody declares, written as entities all the same. */
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  {
    GDEFCORE_Changeset * cs = NULL;
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    const char * texts[3] = {"t.ghost", alice.c_str(), "g1"};
    size_t lens[3] = {7, alice.size(), 2};
    GDEFCORE_Value v[3];
    const char * fields[3] = {"relation", "c0", "c1"};
    for (int i = 0; i < 3; i++) {
      memset(&v[i], 0, sizeof v[i]);
      v[i].size = sizeof v[i];
      v[i].field = fields[i];
      v[i].field_len = strlen(fields[i]);
      v[i].texts = &texts[i];
      v[i].text_lens = &lens[i];
      v[i].count = 1;
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, GDEFCORE_RELATION_ROW_TYPE,
                               strlen(GDEFCORE_RELATION_ROW_TYPE), id, NULL));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2, v, 3));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  const char * texts[] = {
      "(related \"t.ghost\" (principal field.group))",      /* no such relation */
      "(not (related \"t.ghost\" (principal field.group)))",
      "(related \"t.editor\" (principal))",                  /* wrong arity */
      "(not (related \"t.editor\" (principal)))",
      "(related \"t.editor\" (principal field.group))"};     /* the control */
  for (int i = 0; i < 5; i++) {
    GDEFCORE_Condition * c = NULL;
    GDEFCORE_Condition_Subject s;
    int failed = -1;
    int holds;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_parse(texts[i], strlen(texts[i]), &c, NULL));
    memset(&s, 0, sizeof s);
    s.size = sizeof s;
    s.entity = post.data();
    s.entity_len = post.size();
    holds = gdefcore_condition_eval(catalog_, Req(alice), c, &s, &failed);
    if (i < 4) {
      EXPECT_EQ(0, holds) << texts[i];
      EXPECT_EQ(1, failed) << texts[i];
    } else {
      EXPECT_EQ(1, holds) << texts[i];
      EXPECT_EQ(0, failed) << texts[i];
    }
    gdefcore_condition_free(c);
  }
}

TEST_F(Relations, RowsAreHiddenFromTheManWhoseAccessTheyGive) {
  Boot();
  std::string alice = Principal();
  std::string post = Save(Admin(), "p1", "g1");
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  ASSERT_TRUE(Can(alice, post));
  /* She has the access, and she cannot list the rows or read one. */
  char ** rows = NULL;
  size_t nrows = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, GDEFCORE_RELATION_ROW_TYPE,
                             strlen(GDEFCORE_RELATION_ROW_TYPE), &rows, &nrows));
  ASSERT_EQ(1u, nrows);
  std::string row = rows[0];
  gdefcore_ids_free(catalog_, rows, nrows);
  GDEFCORE_Request * r = Req(alice);
  GDEFCORE_Access_List q;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.type_name = GDEFCORE_RELATION_ROW_TYPE;
  q.type_name_len = strlen(GDEFCORE_RELATION_ROW_TYPE);
  q.lang = "en";
  q.lang_len = 2;
  char ** ids = NULL;
  size_t n = 5;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list(catalog_, r, &q, &ids, &n));
  EXPECT_EQ(0u, n);
  gdefcore_access_free(catalog_, ids, n);
  uint64_t total = 7;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(catalog_, r, &q, &total));
  EXPECT_EQ(0u, total);
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 9;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_access_read(catalog_, r, row.data(), row.size(), "en", 2, "c0", 2,
          &texts, &lens, &count));
  /* The relation's state entity is as hidden. */
  q.type_name = GDEFCORE_RELATION_STATE_TYPE;
  q.type_name_len = strlen(GDEFCORE_RELATION_STATE_TYPE);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_count(catalog_, r, &q, &total));
  EXPECT_EQ(0u, total);
}

TEST_F(Relations, HiddenEqualsMissingWhenARelationDenies) {
  Boot();
  std::string alice = Principal();
  std::string bob = Principal();
  std::string post = Save(Admin(), "p1", "g1");
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("members");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("members", "Read posts", kOwn));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_, bob.data(),
                             bob.size(), "members", 7));
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g2"}));
  /* Bob is listed in nothing: the post exists and he is told what he is told
   * of a post that was never made. */
  char missing[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(missing));
  EXPECT_EQ(Read(bob, post), Read(bob, missing));
  EXPECT_EQ("<denied>", Read(bob, post));
  EXPECT_EQ(Can(bob, post), Can(bob, missing));
  EXPECT_FALSE(Can(bob, post));
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {bob, "g1"}));
  EXPECT_EQ("p1", Read(bob, post));        /* the control: now listed */
  EXPECT_EQ("<denied>", Read(bob, missing));
}

TEST_F(Relations, AFailureWhileReadingGrantsNothing) {
  /* Every allocation of the catalog, failed in turn, over decisions that rest
   * on a relation and on its negation. A failure is never a yes that is not the
   * truth, and `not` of a failure is not a yes. */
  FailAlloc fa;
  fa.alloc.ctx = &fa;
  fa.alloc.malloc_fn = FaMalloc;
  fa.alloc.calloc_fn = FaCalloc;
  fa.alloc.realloc_fn = FaRealloc;
  fa.alloc.free_fn = FaFree;
  Close();
  catalog_alloc_ = &fa.alloc;
  Open();
  DefinePost();
  ModDef * m = Declare_t(false);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK, Enable("t", {}));
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("members");
  Role("outsiders");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("members", "Read posts", kOwn));
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("outsiders", "Read posts",
          "(not (related \"t.editor\" (principal field.group)))"));
  std::string alice = Principal("members");    /* listed:  yes  */
  std::string carol = Principal("members");    /* not:     no   */
  std::string dave = Principal("outsiders");   /* not:     yes (negation) */
  std::string erin = Principal("outsiders");   /* listed:  no (negation) */
  std::string post = Save(Admin(), "p1", "g1");
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {erin, "g1"}));
  ASSERT_EQ("p1", Read(alice, post));
  ASSERT_EQ("<denied>", Read(carol, post));
  ASSERT_EQ("p1", Read(dave, post));
  ASSERT_EQ("<denied>", Read(erin, post));
  fa.armed = true;
  fa.target = 0;
  fa.seen = 0;
  (void)Read(dave, post);
  long total = fa.seen;
  ASSERT_GT(total, 3);
  bool dave_lost = false;
  bool alice_lost = false;
  for (long n = 1; n <= total + 1; n++) {
    std::string results[4];
    const std::string * who[4] = {&alice, &carol, &dave, &erin};
    for (int i = 0; i < 4; i++) {
      fa.armed = true;
      fa.target = n;
      fa.seen = 0;
      results[i] = Read(*who[i], post);
      fa.armed = false;
    }
    EXPECT_EQ("<denied>", results[1]) << "carol, allocation " << n << " of " << total;
    EXPECT_EQ("<denied>", results[3]) << "erin, allocation " << n << " of " << total;
    EXPECT_TRUE(results[0] == "p1" || results[0] == "<denied>");
    EXPECT_TRUE(results[2] == "p1" || results[2] == "<denied>");
    dave_lost = dave_lost || results[2] == "<denied>";
    alice_lost = alice_lost || results[0] == "<denied>";
  }
  EXPECT_TRUE(dave_lost) << "no allocation failure reached a negated relation";
  EXPECT_TRUE(alice_lost) << "no allocation failure reached a relation";
  fa.armed = false;
}

/* ---- who writes ---------------------------------------------------------- */

TEST_F(Relations, OnlyTheOwningModuleWritesItsRelation) {
  Boot();
  /* A second module, with a relation of its own. */
  ModDef * other = NewMod("u");
  other->Relation("u.fan", {{"who", GDEFCORE_RELATION_ENTITY, ""}});
  ASSERT_EQ(GDEFCORE_OK, Install(other));
  ASSERT_EQ(GDEFCORE_OK, Enable("u", {}));
  std::string alice = Principal();
  /* The owner writes. */
  EXPECT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}, "t"));
  EXPECT_EQ(GDEFCORE_OK, Add("u.fan", {alice}, "u"));
  /* Another module's name on the call is refused, and writes nothing. */
  size_t before = Rows();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(kEditor, {Principal(), "g9"}, "u"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("u.fan", {alice}, "t"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Remove(kEditor, {"*", "*"}, NULL, "u"));
  EXPECT_EQ(before, Rows());
  /* A relation that is declared by no one. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("t.ghost", {alice}, "t"));
  /* A module that is not enabled writes nothing, however it names itself. */
  ASSERT_EQ(GDEFCORE_OK, Disable("u"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("u.fan", {Principal()}, "u"));
}

TEST_F(Relations, ValuesAreCheckedAgainstTheirColumns) {
  DefinePost();
  ModDef * m = NewMod("t");
  m->Relation("t.mix", {{"who", GDEFCORE_RELATION_ENTITY, ""},
                           {"label", GDEFCORE_RELATION_TEXT, ""},
                           {"level", GDEFCORE_RELATION_INTEGER, ""}});
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  ASSERT_EQ(GDEFCORE_OK, Enable("t", {}));
  std::string alice = Principal();
  int added = -1;
  EXPECT_EQ(GDEFCORE_OK, Add("t.mix", {alice, "gold", "007"}, "t", "", &added));
  EXPECT_EQ(1, added);
  /* An integer is stored without leading zeros, so a second spelling of it is
   * the same row. */
  EXPECT_EQ(GDEFCORE_OK, Add("t.mix", {alice, "gold", "7"}, "t", "", &added));
  EXPECT_EQ(0, added);
  EXPECT_EQ(1u, Rows());
  /* An entity column holds the canonical id, however it was written. */
  std::string lower = alice;
  for (char & ch : lower) {
    ch = (char)tolower((unsigned char)ch);
  }
  EXPECT_EQ(GDEFCORE_OK, Add("t.mix", {lower, "gold", "7"}, "t", "", &added));
  EXPECT_EQ(0, added);
  /* What does not suit the column is refused and writes nothing. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("t.mix", {"not an id", "gold", "7"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("t.mix", {alice, "gold", "seven"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("t.mix", {alice, "gold", "1234567890123456789"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("t.mix", {alice, std::string(257, 'x'), "7"}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("t.mix", {alice, "gold"}));          /* too few */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add("t.mix", {alice, "gold", "7", "x"})); /* too many */
  EXPECT_EQ(1u, Rows());
  EXPECT_EQ(GDEFCORE_OK, Add("t.mix", {alice, "gold", "-3"}));
  EXPECT_EQ(2u, Rows());
}

TEST_F(Relations, TheVersionMovesWithTheRowsAndOnlyThen) {
  Boot();
  std::string alice = Principal();
  std::string bob = Principal();
  EXPECT_EQ(0u, Version(kEditor));
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  uint64_t v1 = Version(kEditor);
  EXPECT_GT(v1, 0u);
  /* The same row again is no change. */
  int added = -1;
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}, "t", "", &added));
  EXPECT_EQ(0, added);
  EXPECT_EQ(v1, Version(kEditor));
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {bob, "g1"}));
  uint64_t v2 = Version(kEditor);
  EXPECT_GT(v2, v1);
  /* Another relation's rows are another counter. */
  ASSERT_EQ(GDEFCORE_OK, Add(kViewer, {alice}));
  EXPECT_EQ(v2, Version(kEditor));
  EXPECT_GT(Version(kViewer), 0u);
  /* A removal that matches moves it; one that matches nothing does not. */
  size_t removed = 7;
  ASSERT_EQ(GDEFCORE_OK, Remove(kEditor, {alice, "no-such-group"}, &removed));
  EXPECT_EQ(0u, removed);
  EXPECT_EQ(v2, Version(kEditor));
  ASSERT_EQ(GDEFCORE_OK, Remove(kEditor, {alice, "g1"}, &removed));
  EXPECT_EQ(1u, removed);
  EXPECT_GT(Version(kEditor), v2);
  /* "*" frees a column: everything of bob's. */
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {bob, "g2"}));
  uint64_t v3 = Version(kEditor);
  ASSERT_EQ(GDEFCORE_OK, Remove(kEditor, {bob, "*"}, &removed));
  EXPECT_EQ(2u, removed);
  EXPECT_GT(Version(kEditor), v3);
}

TEST_F(Relations, TheRowRecordsTheActorAndNoPersonalValue) {
  Boot();
  std::string alice = Principal();
  std::string admin = Admin();
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}, "t", admin));
  char ** rows = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, GDEFCORE_RELATION_ROW_TYPE,
                             strlen(GDEFCORE_RELATION_ROW_TYPE), &rows, &n));
  ASSERT_EQ(1u, n);
  char * creator = NULL;
  size_t creator_len = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_creator(catalog_, rows[0], GDEFCORE_PUBLIC_ID_LEN,
                             &creator, &creator_len));
  EXPECT_EQ(admin, std::string(creator, creator_len));
  gdefcore_text_free(catalog_, creator);
  /* The row holds the relation's name and the public id, nothing of the person. */
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_CURRENT,
                             rows[0], GDEFCORE_PUBLIC_ID_LEN, "en", 2, "c0", 2,
                             &texts, &lens, &count));
  ASSERT_EQ(1u, count);
  EXPECT_EQ(alice, std::string(texts[0], lens[0]));
  gdefcore_values_free(catalog_, texts, lens, count);
  gdefcore_ids_free(catalog_, rows, n);
}

/* ---- invalidation -------------------------------------------------------- */

TEST_F(Relations, ARowChangesTheKeysReadsDigestAndOnlyForTheRelationRead) {
  Boot();
  std::string alice = Principal();
  std::string post = Save(Admin(), "p1", "g1");
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  GDEFCORE_Request * first = Req(alice);
  EXPECT_TRUE(Can(alice, post));
  /* The request that decided read the relation, at its version. */
  GDEFCORE_Request * r1 = Req(alice);
  int allowed = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, r1, "update", 6, kPost,
                             strlen(kPost), post.c_str(), &allowed));
  EXPECT_EQ(1, allowed);
  size_t deps = gdefcore_request_dependency_count(r1);
  EXPECT_GE(deps, 2u);   /* the post, and the relation */
  std::string before = Reads(RenderKey(r1));
  EXPECT_FALSE(before.empty());
  /* The same read again, nothing changed: the digest is the same. */
  GDEFCORE_Request * r2 = Req(alice);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, r2, "update", 6, kPost,
                             strlen(kPost), post.c_str(), &allowed));
  EXPECT_EQ(before, Reads(RenderKey(r2)));
  /* Another relation's row: the digest of a request that did not read it holds. */
  ASSERT_EQ(GDEFCORE_OK, Add(kViewer, {alice}));
  GDEFCORE_Request * r3 = Req(alice);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, r3, "update", 6, kPost,
                             strlen(kPost), post.c_str(), &allowed));
  /* (The post's own version is unchanged too; only the relation was touched.) */
  EXPECT_EQ(before, Reads(RenderKey(r3)));
  /* A row of the relation that was read: the digest moves. */
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {Principal(), "g7"}));
  GDEFCORE_Request * r4 = Req(alice);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_can(catalog_, r4, "update", 6, kPost,
                             strlen(kPost), post.c_str(), &allowed));
  EXPECT_NE(before, Reads(RenderKey(r4)))
      << "the relation changed and the key's reads digest did not";
  (void)first;
}

TEST_F(Relations, AListThatRestsOnARelationReadsItsVersionToo) {
  Boot();
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("members");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("members", "Read posts", kOwn));
  std::string alice = Principal("members");
  Save(Admin(), "p1", "g1");
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  GDEFCORE_Access_List q;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.type_name = kPost;
  q.type_name_len = strlen(kPost);
  q.lang = "en";
  q.lang_len = 2;
  GDEFCORE_Request * r1 = Req(alice);
  char ** ids = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list(catalog_, r1, &q, &ids, &n));
  gdefcore_access_free(catalog_, ids, n);
  EXPECT_EQ(1u, n);
  EXPECT_GE(gdefcore_request_dependency_count(r1), 1u);
  std::string before = Reads(RenderKey(r1));
  EXPECT_FALSE(before.empty());
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {Principal(), "g9"}));
  GDEFCORE_Request * r2 = Req(alice);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list(catalog_, r2, &q, &ids, &n));
  gdefcore_access_free(catalog_, ids, n);
  EXPECT_NE(before, Reads(RenderKey(r2)));
}

/* ---- the matrix and the risk --------------------------------------------- */

TEST_F(Relations, TheMatrixSaysInWordsWhatRestsOnARelationAndRatesItAtLeastMedium) {
  Boot();
  std::vector<Row> rows = Matrix();
  const Row * see = Find(rows, "module t", "t.see");
  ASSERT_NE(see, nullptr) << Dump(rows);
  EXPECT_EQ(kOwn, see->condition);
  EXPECT_EQ("there is a row of t.editor listing the person and the group field" +
                Note(kEditor).insert(0, " "),
      see->explain);
  /* An `own`-like narrowing of a read is low; a relation under it is not. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, see->risk);
  /* An update that can change the field it tests is a step higher again. */
  const Row * edit = Find(rows, "module t", "t.edit");
  ASSERT_NE(edit, nullptr) << Dump(rows);
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, edit->risk);
  EXPECT_NE(std::string::npos, edit->explain.find("rated one step higher"));
  EXPECT_NE(std::string::npos, edit->explain.find(Note(kEditor)));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW,
      gdefcore_access_grant_risk("read", 4, 0,
          "(and (= type \"site.post\") (= creator principal))", 48, 0));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM,
      gdefcore_access_grant_risk("read", 4, 0, kOwn, strlen(kOwn), 0));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW,
      gdefcore_access_grant_risk("read", 4, 0, "(= field.group \"g1\")", 20, 0));
  /* A relation that bounds nothing of the entity is high for a strong action. */
  const char * loose = "(related \"t.viewer\" (principal))";
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH,
      gdefcore_access_grant_risk("delete", 6, 0, loose, strlen(loose), 0));
  /* A condition with no relation has no note. */
  ModDef * plain = NewMod("p");
  plain->Perm("p.see", "read", GDEFCORE_ACCESS_ANY, kPost);
  plain->Grant("p.see", kPost, "(= field.group \"g1\")");
  ASSERT_EQ(GDEFCORE_OK, Install(plain));
  ASSERT_EQ(GDEFCORE_OK, Enable("p", {GrantLine("p", "p.see", "low", "(= field.group \"g1\")")}))
      << last_error_;
  const std::vector<Row> matrix = Matrix();
  const Row * quiet = Find(matrix, "module p", "p.see");
  ASSERT_NE(quiet, nullptr);
  EXPECT_EQ(std::string::npos, quiet->explain.find("Its breadth"));
}

TEST_F(Relations, EnablingTheModuleOffersTheGrantWithItsNote) {
  DefinePost();
  ModDef * m = Declare_t(true);
  ASSERT_EQ(GDEFCORE_OK, Install(m));
  /* The words the administrator types back include the note about the rows. */
  EXPECT_NE(GDEFCORE_OK, Enable("t", {GrantLine("t", "t.edit", "high", kOwn),
                             GrantLine("t", "t.see", "medium", kOwn)}));
  EXPECT_EQ(GDEFCORE_OK, Enable("t", GrantLines(true, kOwn))) << last_error_;
}

TEST_F(Relations, AModuleGrantCanTestItsOwnRelationInTheChangesetThatEnablesIt) {
  /* The relation is not enabled when the grant is judged; the changeset that
   * enables the module brings both. And a grant that names another module's
   * relation which is not enabled is refused. */
  DefinePost();
  ModDef * a = NewMod("a");
  a->Relation("a.rel", {{"who", GDEFCORE_RELATION_ENTITY, ""}});
  ASSERT_EQ(GDEFCORE_OK, Install(a));
  ModDef * b = NewMod("b");
  b->Perm("b.edit", "update", GDEFCORE_ACCESS_ANY, kPost);
  b->Grant("b.edit", kPost, "(related \"a.rel\" (principal))");
  ASSERT_EQ(GDEFCORE_OK, Install(b));
  EXPECT_NE(GDEFCORE_OK, Enable("b", {})) << "a.rel is not enabled";
  EXPECT_NE(std::string::npos, last_error_.find("no such relation")) << last_error_;
  ASSERT_EQ(GDEFCORE_OK, Enable("a", {}));
  std::string line = RelGrantLine("b", "b.edit", "high", "(related \"a.rel\" (principal))", "a.rel");
  EXPECT_EQ(GDEFCORE_OK, Enable("b", {line})) << last_error_;
}

/* ---- the public surface -------------------------------------------------- */

TEST(RelationsSurface, NoCallReadsRowsPastTheFilter) {
  /* The relation header is the whole surface of rows: it writes them, counts
   * their changes, and notes a read. A function that returned rows would be a
   * handler-facing read of what the access layer reads as the system. */
  std::string text;
  const char * candidates[] = {"include/ghoti.io/defiant-core/relation.h",
      "../include/ghoti.io/defiant-core/relation.h"};
  for (const char * path : candidates) {
    std::ifstream in(path);
    if (in) {
      std::stringstream ss;
      ss << in.rdbuf();
      text = ss.str();
      break;
    }
  }
  ASSERT_FALSE(text.empty()) << "relation.h not found";
  std::set<std::string> found;
  size_t at = 0;
  while ((at = text.find("gdefcore_relation_", at)) != std::string::npos) {
    size_t end = at;
    while (end < text.size() && (isalnum((unsigned char)text[end]) || text[end] == '_')) {
      end += 1;
    }
    /* Only declarations: a name followed by an opening parenthesis. */
    size_t paren = end;
    while (paren < text.size() && (text[paren] == ' ' || text[paren] == '\n')) {
      paren += 1;
    }
    if (paren < text.size() && text[paren] == '(') {
      found.insert(text.substr(at, end - at));
    }
    at = end;
  }
  std::set<std::string> want = {"gdefcore_relation_column_field",
      "gdefcore_relation_number_field", "gdefcore_relation_add",
      "gdefcore_relation_remove", "gdefcore_relation_version",
      "gdefcore_relation_note_dependency"};
  EXPECT_EQ(want, found);
}

/* ---- lists that rest on a relation, compiled and evaluated --------------- */

namespace {

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed * 2685821657736338717ull + 7) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
  uint64_t below(uint64_t n) { return n == 0 ? 0 : next() % n; }
  bool chance(unsigned p) { return below(100) < p; }
};

}  // namespace

TEST_F(Relations, ListsThatRestOnARelationAgreeWithTheEvaluatedList) {
  size_t compared = 0;
  size_t planned = 0;
  size_t nonempty = 0;
  for (int backend = 0; backend < 2; backend++) {
    Close();
    use_sqlite_ = backend == 1;
    Open();
    Rng rng(backend + 5);
    DefinePost();
    ModDef * m = NewMod("t");
    m->Relation(kEditor, {{"who", GDEFCORE_RELATION_ENTITY, ""},
                             {"group", GDEFCORE_RELATION_TEXT, ""}});
    m->Relation(kViewer, {{"who", GDEFCORE_RELATION_ENTITY, ""}});
    ASSERT_EQ(GDEFCORE_OK, Install(m));
    ASSERT_EQ(GDEFCORE_OK, Enable("t", {}));
    std::vector<std::string> people;
    for (int i = 0; i < 4; i++) {
      people.push_back(Principal());
    }
    static const char * groups[] = {"g1", "g2", "g3", ""};
    std::vector<std::string> posts;
    for (int i = 0; i < 30; i++) {
      const char * g = groups[rng.below(4)];
      std::string creator = rng.chance(80) ? people[rng.below(4)] : "";
      posts.push_back(Save(creator, ("p" + std::to_string(i)).c_str(),
          g[0] == '\0' ? NULL : g));
    }
    for (int i = 0; i < 9; i++) {
      ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {people[rng.below(4)], groups[rng.below(3)]}));
    }
    for (int i = 0; i < 2; i++) {
      ASSERT_EQ(GDEFCORE_OK, Add(kViewer, {people[rng.below(4)]}));
    }
    static const char * conditions[] = {
        "(related \"t.editor\" (principal field.group))",
        "(related \"t.editor\" (principal _))",
        "(related \"t.editor\" (_ field.group))",
        "(related \"t.editor\" (creator field.group))",
        "(related \"t.editor\" (revision.creator \"g1\"))",
        "(related \"t.viewer\" (principal))",
        "(related \"t.viewer\" (creator))",
        "(not (related \"t.editor\" (principal field.group)))",
        "(and (related \"t.viewer\" (principal)) (related \"t.editor\" (_ field.group)))",
        "(or (related \"t.editor\" (principal \"g2\")) (= field.group \"g3\"))",
        "(and (related \"t.editor\" (principal field.group)) (= state \"published\"))",
        "(related \"t.editor\" (principal state))",
        "(related \"t.editor\" (principal field.title))",
    };
    const int kConds = sizeof conditions / sizeof conditions[0];
    std::vector<std::string> roles;
    for (int i = 0; i < kConds; i++) {
      std::string role = "r" + std::to_string(i);
      std::string label = "Read via " + std::to_string(i);
      Role(role.c_str());
      Declare(Perm(label.c_str(), "read", GDEFCORE_ACCESS_ANY));
      if (GrantWhen(role.c_str(), label.c_str(), conditions[i]) == GDEFCORE_OK) {
        roles.push_back(role);
      }
    }
    ASSERT_GE(roles.size(), 11u);
    for (int round = 0; round < 30; round++) {
      /* Change the rows between rounds: the lists follow them. */
      if (round % 8 == 0 && round > 0) {
        ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {people[rng.below(4)], groups[rng.below(3)]}));
        size_t removed = 0;
        ASSERT_EQ(GDEFCORE_OK, Remove(kEditor, {people[rng.below(4)], "*"}, &removed));
      }
      for (const std::string & role : roles) {
        std::string who = Principal(role.c_str());
        // The relation is about people; make this principal one of the four by
        // acting as one of them: grant its role to that person instead.
        std::string person = people[rng.below(4)];
        ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(catalog_,
                                   person.data(), person.size(), role.c_str(),
                                   role.size()));
        GDEFCORE_Request * req = Req(person);
        GDEFCORE_Access_List q;
        memset(&q, 0, sizeof q);
        q.size = sizeof q;
        q.type_name = kPost;
        q.type_name_len = strlen(kPost);
        q.lang = "en";
        q.lang_len = 2;
        q.sort_field = "title";
        q.sort_field_len = 5;
        q.offset = rng.chance(30) ? rng.below(5) : 0;
        q.limit = rng.chance(30) ? 1 + rng.below(6) : 0;
        char ** ids = NULL;
        size_t n = 0;
        uint64_t total = 1;
        ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list_page(catalog_, req, &q, &ids, &n, &total));
        std::string how;
        {
          size_t hn = 0;
          const char * h = gdefcore_request_note(req, "defiant.access.list", 19, &hn);
          how = h == NULL ? "none" : std::string(h, hn);
        }
        std::vector<std::string> got;
        for (size_t i = 0; i < n; i++) {
          got.push_back(ids[i]);
        }
        gdefcore_access_free(catalog_, ids, n);
        q.flags = GDEFCORE_ACCESS_LIST_EVALUATE;
        GDEFCORE_Request * req2 = Req(person);
        uint64_t want_total = 2;
        ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list_page(catalog_, req2, &q, &ids, &n, &want_total));
        std::vector<std::string> want;
        for (size_t i = 0; i < n; i++) {
          want.push_back(ids[i]);
        }
        gdefcore_access_free(catalog_, ids, n);
        EXPECT_EQ(want, got) << "backend " << backend << " role " << role << " round " << round;
        EXPECT_EQ(want_total, total);
        compared += 1;
        planned += how == "planned" ? 1 : 0;
        nonempty += want.empty() ? 0 : 1;
        ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_remove_role(catalog_,
                                   person.data(), person.size(), role.c_str(),
                                   role.size()));
        (void)who;
        if (HasFailure()) {
          return;
        }
      }
    }
  }
  EXPECT_GE(compared, 700u);
  EXPECT_GE(planned, compared * 9 / 10) << "the sweep must be of the compiled list";
  EXPECT_GE(nonempty, 100u);
}

TEST_F(Relations, TheCompiledListReadsAnUndeclaredRelationAsAFailure) {
  /* A stored grant whose relation has gone with its module: the list, compiled
   * or not, lists nothing for it and never turns `not` into a grant. */
  Boot(false);
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("members");
  Role("outsiders");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("members", "Read posts", kOwn));
  ASSERT_EQ(GDEFCORE_OK,
      GrantWhen("outsiders", "Read posts",
          "(not (related \"t.editor\" (principal field.group)))"));
  std::string alice = Principal("members");
  std::string bob = Principal("outsiders");
  Save(Admin(), "p1", "g1");
  ASSERT_EQ(GDEFCORE_OK, Add(kEditor, {alice, "g1"}));
  EXPECT_EQ(std::vector<std::string>({"p1"}), List(alice));
  EXPECT_EQ(std::vector<std::string>({"p1"}), List(bob));
  ASSERT_EQ(GDEFCORE_OK, Disable("t"));
  for (int flags : {0, (int)GDEFCORE_ACCESS_LIST_EVALUATE}) {
    for (const std::string & who : {alice, bob}) {
      GDEFCORE_Access_List q;
      memset(&q, 0, sizeof q);
      q.size = sizeof q;
      q.type_name = kPost;
      q.type_name_len = strlen(kPost);
      q.lang = "en";
      q.lang_len = 2;
      q.flags = flags;
      char ** ids = NULL;
      size_t n = 9;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_list(catalog_, Req(who), &q, &ids, &n));
      EXPECT_EQ(0u, n) << "flags " << flags;
      gdefcore_access_free(catalog_, ids, n);
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
