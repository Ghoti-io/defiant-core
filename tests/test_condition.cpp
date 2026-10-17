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
 * Story A1: conditions as data. The language (parse, refuse, canonical text,
 * hash), validation against the catalog, the evaluator on one entity, the
 * built-in any and own, the grants that carry an expression (read, list,
 * permits, render key), failure that never grants, and a seeded sweep of
 * hostile and random input.
 *
 * Every row of the story's matrix has a test here. Each test that asserts a
 * refusal or a "false" also asserts the matching "true" beside it (a control),
 * so a plant that breaks the feature is a test failing by name.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <chrono>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {

const char kBlog[] = "t.blog";
const char kVault[] = "t.vault";

/* ---- a catalog allocator that can fail one allocation ------------------ */

struct FailAlloc {
  GCU_Allocator alloc;
  bool armed = false;
  long target = 0;   /* fail the allocation with this ordinal, 0: none */
  long seen = 0;     /* allocations since arming */
};

bool Hit(FailAlloc * f) {
  if (!f->armed) {
    return false;
  }
  f->seen += 1;
  return f->target > 0 && f->seen == f->target;
}

void * FaMalloc(void * ctx, size_t n) {
  if (Hit((FailAlloc *)ctx)) {
    return NULL;
  }
  return malloc(n == 0 ? 1 : n);
}

void * FaCalloc(void * ctx, size_t count, size_t n) {
  if (Hit((FailAlloc *)ctx)) {
    return NULL;
  }
  return calloc(count == 0 ? 1 : count, n == 0 ? 1 : n);
}

void * FaRealloc(void * ctx, void * p, size_t n) {
  if (Hit((FailAlloc *)ctx)) {
    return NULL;
  }
  return realloc(p, n == 0 ? 1 : n);
}

void FaFree(void *, void * p) {
  free(p);
}

typedef std::vector<std::pair<std::string, std::vector<std::string> > > Vals;

Vals V(std::initializer_list<std::pair<std::string, std::string> > one) {
  Vals out;
  for (const auto & kv : one) {
    out.push_back({kv.first, {kv.second}});
  }
  return out;
}

GDEFCORE_Field Field(const char * name, int many = 0, int personal = 0) {
  GDEFCORE_Field f;
  memset(&f, 0, sizeof f);
  f.size = sizeof f;
  f.name = name;
  f.name_len = strlen(name);
  f.many = many;
  f.personal = personal;
  return f;
}

/** One tenant on the memory backend, with two types and some helpers. */
struct Env {
  FailAlloc fa;
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Request * req = NULL;
  std::vector<GDEFCORE_Request *> extra;

  Env() {
    fa.alloc.ctx = &fa;
    fa.alloc.malloc_fn = FaMalloc;
    fa.alloc.calloc_fn = FaCalloc;
    fa.alloc.realloc_fn = FaRealloc;
    fa.alloc.free_fn = FaFree;
    EXPECT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store, (const uint8_t *)"t", 1, NULL, &fa.alloc,
            &catalog));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)"t", 1, 0, 0, NULL, &req));
    {
      GDEFCORE_Field f[5] = {Field("title"), Field("group"), Field("rank"),
          Field("embargo"), Field("tags", 1)};
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_type_define(catalog, kBlog, strlen(kBlog),
              GDEFCORE_TYPE_CONTENT, f, 5));
    }
    {
      GDEFCORE_Field f[2] = {Field("name"), Field("ssn", 0, 1)};
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_type_define(catalog, kVault, strlen(kVault),
              GDEFCORE_TYPE_CONTENT, f, 2));
    }
  }

  ~Env() {
    size_t i;
    for (i = 0; i < extra.size(); i++) {
      gdefcore_request_destroy(extra[i]);
    }
    gdefcore_request_destroy(req);
    gdefcore_catalog_destroy(catalog);
    gdefstor_store_destroy(store);
  }

  /** A request with a principal (empty: anonymous) and a fixed clock. */
  GDEFCORE_Request * Req(const std::string & principal, int64_t now = 5000) {
    GDEFCORE_Request * r = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)"t", 1, 0, 0, NULL, &r));
    if (!principal.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_principal(r, principal.data(), principal.size()));
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_time(r, now));
    extra.push_back(r);
    return r;
  }

  /** mode 0: save (published). 1: draft only. */
  std::string Make(const char * type, const std::string & actor, const Vals & vals,
      int mode = 0, const char * lang = "en") {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> values(vals.size());
    std::vector<std::vector<const char *> > texts(vals.size());
    std::vector<std::vector<size_t> > lens(vals.size());
    size_t i;
    id[0] = '\0';
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog, type, strlen(type), id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog, actor.empty() ? NULL : actor.data(),
            actor.size(), &cs));
    for (i = 0; i < vals.size(); i++) {
      size_t k;
      for (k = 0; k < vals[i].second.size(); k++) {
        texts[i].push_back(vals[i].second[k].c_str());
        lens[i].push_back(vals[i].second[k].size());
      }
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = vals[i].first.c_str();
      values[i].field_len = vals[i].first.size();
      values[i].texts = texts[i].data();
      values[i].text_lens = lens[i].data();
      values[i].count = texts[i].size();
    }
    if (mode == 1) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_entity_save_draft(cs, id, strlen(id), lang, strlen(lang),
              values.data(), values.size()));
    } else {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_entity_save(cs, id, strlen(id), lang, strlen(lang),
              values.data(), values.size()));
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  void Publish(const std::string & id) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog, NULL, 0, &cs));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, id.data(), id.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
};

struct Answer {
  int allow;
  int failed;
  bool operator==(const Answer & o) const {
    return allow == o.allow && failed == o.failed;
  }
};

/** Parse (which must succeed) and evaluate. */
Answer Eval(Env & env, const std::string & text, const std::string & id,
    GDEFCORE_Request * req = NULL, const char * lang = NULL) {
  GDEFCORE_Condition * cond = NULL;
  GDEFCORE_Condition_Error err;
  GDEFCORE_Condition_Subject subject;
  Answer a = {-1, -1};
  memset(&err, 0, sizeof err);
  err.size = sizeof err;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(text.data(), text.size(), &cond, &err))
      << text << " -> " << (err.message == NULL ? "" : err.message) << " at "
      << err.offset;
  if (cond == NULL) {
    return a;
  }
  memset(&subject, 0, sizeof subject);
  subject.size = sizeof subject;
  subject.entity = id.data();
  subject.entity_len = id.size();
  subject.lang = lang;
  subject.lang_len = lang == NULL ? 0 : strlen(lang);
  a.failed = 7;
  a.allow = gdefcore_condition_eval(env.catalog, req == NULL ? env.req : req,
      cond, &subject, &a.failed);
  gdefcore_condition_free(cond);
  return a;
}

/** Canonical text of @p text, or "<refused: message @offset>". */
std::string Canon(const std::string & text) {
  GDEFCORE_Condition * cond = NULL;
  GDEFCORE_Condition_Error err;
  char * out = NULL;
  size_t n = 0;
  std::string s;
  memset(&err, 0, sizeof err);
  err.size = sizeof err;
  if (gdefcore_condition_parse(text.data(), text.size(), &cond, &err) !=
      GDEFCORE_OK) {
    return std::string("<refused: ") + err.message + " @" +
           std::to_string(err.offset) + ">";
  }
  EXPECT_EQ(GDEFCORE_OK, gdefcore_condition_canonical(cond, &out, &n));
  if (out != NULL) {
    s.assign(out, n);
    gdefcore_condition_text_free(out);
  }
  gdefcore_condition_free(cond);
  return s;
}

std::string Hash(const std::string & text) {
  char h[GDEFCORE_CONDITION_HASH_LEN + 1];
  if (gdefcore_condition_hash(text.data(), text.size(), h, NULL) != GDEFCORE_OK) {
    return "<refused>";
  }
  return std::string(h);
}

std::string Explain(const std::string & text) {
  GDEFCORE_Condition * cond = NULL;
  char * out = NULL;
  size_t n = 0;
  std::string s;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(text.data(), text.size(), &cond, NULL));
  if (cond != NULL) {
    EXPECT_EQ(GDEFCORE_OK, gdefcore_condition_explain(cond, &out, &n));
    if (out != NULL) {
      s.assign(out, n);
      gdefcore_condition_text_free(out);
    }
    gdefcore_condition_free(cond);
  }
  return s;
}

/** Validate against a type: "" on success, else "message@offset". */
std::string Validate(Env & env, const std::string & text, const char * type) {
  GDEFCORE_Condition * cond = NULL;
  GDEFCORE_Condition_Error err;
  GDEFCORE_Result rc;
  memset(&err, 0, sizeof err);
  err.size = sizeof err;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(text.data(), text.size(), &cond, NULL))
      << text;
  if (cond == NULL) {
    return "<parse>";
  }
  rc = gdefcore_condition_validate(env.catalog, cond, type, strlen(type), &err);
  gdefcore_condition_free(cond);
  if (rc == GDEFCORE_OK) {
    return "";
  }
  EXPECT_EQ(GDEFCORE_ERR_INVALID, rc);
  return std::string(err.message) + "@" + std::to_string(err.offset);
}

/** Parse text that must be valid. */
GDEFCORE_Condition * P(const std::string & text) {
  GDEFCORE_Condition * c = NULL;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(text.data(), text.size(), &c, NULL)) << text;
  return c;
}

std::string FreshId() {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  EXPECT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
  return std::string(id);
}

std::string Nest(int levels) {
  std::string s;
  int i;
  for (i = 0; i < levels; i++) {
    s += "(not ";
  }
  s += "true";
  for (i = 0; i < levels; i++) {
    s += ")";
  }
  return s;
}

/** (or true false true ...) with exactly @p total nodes, padded to @p bytes. */
std::string Wide(int total, size_t bytes = 0) {
  std::string s = "(or";
  int i;
  for (i = 1; i < total; i++) {
    s += (i % 2) ? " true" : " false";
  }
  s += ")";
  if (bytes > s.size()) {
    s += std::string(bytes - s.size(), ' ');
  }
  return s;
}

}  // namespace

/* ---------------------------------------------------------------------- */
/* The language                                                           */
/* ---------------------------------------------------------------------- */

TEST(Cond, AcceptsAndNormalizes) {
  /* Whitespace is normalized, and so is the order of and/or operands. */
  EXPECT_EQ("true", Canon("true"));
  EXPECT_EQ("false", Canon(" \n false\t"));
  EXPECT_EQ("(and (= field.x 1) (= type \"a\"))",
      Canon("  ( and   (= type \"a\")  \n (=  field.x 1 ) ) "));
  EXPECT_EQ("(or (= type \"a\") (= type \"b\"))",
      Canon("(or (= type \"b\") (= type \"a\"))"));
  /* Repeats collapse; an and of one thing is that thing. */
  EXPECT_EQ("true", Canon("(and true true)"));
  EXPECT_EQ("(and false true)", Canon("(and true (and false true))"));
  /* A nested and left by a collapsing or is merged on the next pass. */
  EXPECT_EQ("(and (= type \"a\") false true)",
      Canon("(and (= type \"a\") (or (and true false)))"));
  /* in: sorted, de-duplicated. */
  EXPECT_EQ("(in field.g (\"a\" \"b\" 3))",
      Canon("(in field.g (\"b\" \"a\" \"b\" 3 03))"));
  /* Integers lose leading zeros and a negative zero. */
  EXPECT_EQ("(= field.r 7)", Canon("(= field.r 007)"));
  EXPECT_EQ("(= field.r 0)", Canon("(= field.r -0)"));
  EXPECT_EQ("(= field.r -5)", Canon("(= field.r -5)"));
  EXPECT_EQ("(not true)", Canon("(not   true)"));
  /* Text with every escape, and non-ASCII text, survive. */
  EXPECT_EQ("(= type \"a\\\"b\\\\c\\nd\\te\")",
      Canon("(= type \"a\\\"b\\\\c\\nd\\te\")"));
  EXPECT_EQ("(= type \"caf\xC3\xA9 \xF0\x9F\x99\x82\")",
      Canon("(= type \"caf\xC3\xA9 \xF0\x9F\x99\x82\")"));
  /* Every comparison operator. */
  EXPECT_EQ("(< field.r 1)", Canon("(< field.r 1)"));
  EXPECT_EQ("(<= field.r 1)", Canon("(<= field.r 1)"));
  EXPECT_EQ("(> field.r 1)", Canon("(> field.r 1)"));
  EXPECT_EQ("(>= field.r 1)", Canon("(>= field.r 1)"));
  EXPECT_EQ("(!= creator principal)", Canon("(!= creator principal)"));
  EXPECT_EQ("(< now field.embargo)", Canon("(< now field.embargo)"));
}

TEST(Cond, CanonicalAndHash) {
  /* Two spellings of one expression have one canonical text and one hash. */
  const char * const spellings[] = {
      "(and (= type \"t.blog\") (in field.group (\"a\" \"b\")))",
      "(and\n  (in field.group (\"b\"   \"a\"))\n  (= type \"t.blog\"))",
      "(and (and (= type \"t.blog\")) (in field.group (\"a\" \"b\" \"a\")) "
      "(= type \"t.blog\"))",
  };
  size_t i;
  std::string canon = Canon(spellings[0]);
  std::string hash = Hash(spellings[0]);
  EXPECT_EQ("(and (= type \"t.blog\") (in field.group (\"a\" \"b\")))", canon);
  EXPECT_EQ(64u, hash.size());
  for (i = 1; i < sizeof spellings / sizeof spellings[0]; i++) {
    EXPECT_EQ(canon, Canon(spellings[i])) << spellings[i];
    EXPECT_EQ(hash, Hash(spellings[i])) << spellings[i];
  }
  /* Stable: serialize(parse(canon)) == canon, and the hash is of the canon. */
  EXPECT_EQ(canon, Canon(canon));
  EXPECT_EQ(hash, Hash(canon));
  /* Control: a different expression has a different hash. */
  EXPECT_NE(hash, Hash("(and (= type \"t.blog\") (in field.group (\"a\")))"));
  EXPECT_NE(hash, Hash("(or (= type \"t.blog\") (in field.group (\"a\" \"b\")))"));
  /* The hash of refused text is a refusal, not a hash of nothing. */
  EXPECT_EQ("<refused>", Hash("(and"));
}

TEST(Cond, RefusesBadSyntax) {
  struct Row {
    std::string text;
    std::string want;
  };
  std::vector<Row> rows;
  rows.push_back({"", "<refused: the condition is empty @0>"});
  rows.push_back({"(", "<refused: an operator was expected @1>"});
  rows.push_back({"(and", "<refused: a condition was expected @4>"});
  rows.push_back({"(and true",
      "<refused: a condition was expected @9>"});
  rows.push_back({"(not true",
      "<refused: a closing parenthesis was expected @9>"});
  rows.push_back({"(not true true)",
      "<refused: a closing parenthesis was expected @10>"});
  rows.push_back({"(and)", "<refused: a condition was expected @4>"});
  /* Trailing garbage: a second expression, a stray parenthesis, text. */
  rows.push_back({"true false", "<refused: unexpected text after the condition @5>"});
  rows.push_back({"true)", "<refused: unexpected text after the condition @4>"});
  rows.push_back({"(= type \"a\")x",
      "<refused: unexpected text after the condition @12>"});
  rows.push_back({"(and true) (and true)",
      "<refused: unexpected text after the condition @11>"});
  /* Operands, operators, words. */
  rows.push_back({"(= type)", "<refused: an operand was expected @7>"});
  rows.push_back({"(= type \"a\" \"b\")",
      "<refused: a closing parenthesis was expected @12>"});
  rows.push_back({"(foo true)", "<refused: an unknown operator @1>"});
  rows.push_back({"(= nope 1)", "<refused: an unknown operand @3>"});
  rows.push_back({"(= type true)", "<refused: an unknown operand @8>"});
  rows.push_back({"type", "<refused: a condition was expected @0>"});
  rows.push_back({"(\"and\" true)", "<refused: an operator was expected @1>"});
  rows.push_back({"((and true))", "<refused: an operator was expected @1>"});
  rows.push_back({"(in type \"a\")", "<refused: a list of constants was expected @9>"});
  rows.push_back({"(in type ())", "<refused: a constant was expected @10>"});
  rows.push_back({"(in type (field.x))", "<refused: a constant was expected @10>"});
  rows.push_back({"(= field. 1)", "<refused: a field name was expected after field. @3>"});
  rows.push_back({"(= field.a-b 1)", "<refused: a field name was expected after field. @3>"});
  /* Relations are reserved. */
  rows.push_back({"(related field.x)", "<refused: relations are not available yet @1>"});
  rows.push_back({"related(field.x)", "<refused: relations are not available yet @0>"});
  rows.push_back({"(= related 1)", "<refused: relations are not available yet @3>"});
  rows.push_back({"(and true related)", "<refused: relations are not available yet @10>"});
  rows.push_back({"(in type (related))", "<refused: relations are not available yet @10>"});
  /* Text and integers. */
  rows.push_back({"(= type \"abc", "<refused: a text constant is not closed @8>"});
  rows.push_back({"(= type \"a\\qb\")", "<refused: an unknown escape in a text constant @10>"});
  rows.push_back({"(= type \"a\x01\")",
      "<refused: a control character in a text constant @10>"});
  rows.push_back({"(= field.r 1x)", "<refused: an invalid integer @11>"});
  rows.push_back({"(= field.r -)", "<refused: an invalid integer @11>"});
  rows.push_back({"(= field.r 1234567890123456789)",
      "<refused: an integer is too large @11>"});
  rows.push_back({"(and \xC3\xA9)", "<refused: an unexpected character @5>"});
  rows.push_back({"\x01", "<refused: an unexpected character @0>"});
  rows.push_back({"(= type 'a')", "<refused: an unexpected character @8>"});
  for (const Row & row : rows) {
    EXPECT_EQ(row.want, Canon(row.text)) << "input: " << row.text;
  }
  /* Control for the table above: the same shapes, made valid, are accepted. */
  EXPECT_EQ("true", Canon("true"));
  EXPECT_EQ("(not true)", Canon("(not true)"));
  EXPECT_EQ("(= type \"a\")", Canon("(= type \"a\")"));
  EXPECT_EQ("(in type (\"a\"))", Canon("(in type (\"a\"))"));
  EXPECT_EQ("(= field.r 1)", Canon("(= field.r 1)"));
}

TEST(Cond, RefusesBadBytes) {
  /* NUL, and every kind of invalid UTF-8: refused with an offset, never a
   * crash. Control: valid UTF-8 of every length is accepted in a constant. */
  struct Row {
    std::string bytes;
    std::string want;
  };
  std::vector<Row> rows;
  rows.push_back({std::string("(and true\0 false)", 17),
      "<refused: a NUL byte is not allowed @9>"});
  rows.push_back({std::string("\0", 1), "<refused: a NUL byte is not allowed @0>"});
  rows.push_back({"(= type \"\xC3\x28\")", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"(= type \"\xC0\xAF\")", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"(= type \"\xE0\x80\xAF\")", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"(= type \"\xED\xA0\x80\")", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"(= type \"\xF4\x90\x80\x80\")", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"(= type \"\xF8\x88\x80\x80\x80\")", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"(= type \"\x80\")", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"(= type \"\xE2\x82", "<refused: the text is not valid UTF-8 @9>"});
  rows.push_back({"\xFF", "<refused: the text is not valid UTF-8 @0>"});
  for (const Row & row : rows) {
    EXPECT_EQ(row.want, Canon(row.bytes)) << "input of " << row.bytes.size();
  }
  EXPECT_EQ("(= type \"\xC3\xA9\xE2\x82\xAC\xF0\x9F\x99\x82\")",
      Canon("(= type \"\xC3\xA9\xE2\x82\xAC\xF0\x9F\x99\x82\")"));
}

TEST(Cond, LimitDepth) {
  /* Depth 16 is accepted, 17 refused (at the 17th parenthesis), and a
   * thousand refused at once, without recursing a thousand deep. */
  EXPECT_EQ(std::string::npos, Canon(Nest(15)).find("refused"));
  EXPECT_EQ(std::string::npos, Canon(Nest(16)).find("refused"));
  EXPECT_EQ(Nest(16).substr(0, 5), Canon(Nest(16)).substr(0, 5));
  EXPECT_EQ("<refused: the condition is nested more than 16 levels deep @80>",
      Canon(Nest(17)));
  EXPECT_EQ("<refused: the condition is nested more than 16 levels deep @80>",
      Canon(Nest(600)));
  /* An in-list is a level too. */
  {
    std::string s = "(in type (\"a\"))";
    int i;
    for (i = 0; i < 14; i++) {
      s = "(not " + s + ")";
    }
    /* 14 nots + in + list = 16 levels: accepted. One more: refused. */
    EXPECT_EQ(std::string::npos, Canon(s).find("refused"));
    EXPECT_NE(std::string::npos, Canon("(not " + s + ")").find("nested"));
  }
}

TEST(Cond, LimitNodes) {
  EXPECT_EQ(std::string::npos, Canon(Wide(255)).find("refused"));
  EXPECT_EQ(std::string::npos, Canon(Wide(256)).find("refused"));
  EXPECT_NE(std::string::npos, Canon(Wide(257)).find("more than 256 nodes"));
  EXPECT_NE(std::string::npos, Canon(Wide(300)).find("more than 256 nodes"));
  /* The in-list members are nodes too: 1 in + 1 operand + 254 members. */
  {
    std::string s = "(in type (";
    int i;
    for (i = 0; i < 254; i++) {
      s += (i ? " " : "") + std::to_string(i);
    }
    EXPECT_EQ(std::string::npos, Canon(s + "))").find("refused"));
    EXPECT_NE(std::string::npos,
        Canon(s + " 999))").find("more than 256 nodes"));
  }
}

TEST(Cond, LimitBytes) {
  EXPECT_EQ(std::string::npos, Canon(Wide(10, 4095)).find("refused"));
  EXPECT_EQ(std::string::npos, Canon(Wide(10, 4096)).find("refused"));
  EXPECT_EQ("<refused: the condition is longer than 4096 bytes @4096>",
      Canon(Wide(10, 4097)));
  /* A very large input is refused by length at once. */
  EXPECT_EQ("<refused: the condition is longer than 4096 bytes @4096>",
      Canon(std::string(5u << 20, '(')));
  /* A constant: 256 bytes accepted (escapes are decoded first), 257 refused. */
  EXPECT_EQ(std::string::npos,
      Canon("(= type \"" + std::string(256, 'a') + "\")").find("refused"));
  EXPECT_NE(std::string::npos,
      Canon("(= type \"" + std::string(257, 'a') + "\")")
          .find("longer than 256 bytes"));
  {
    std::string esc;
    int i;
    for (i = 0; i < 256; i++) {
      esc += "\\\\";
    }
    /* 512 bytes of text that decode to 256. */
    EXPECT_EQ(std::string::npos,
        Canon("(= type \"" + esc + "\")").find("refused"));
    EXPECT_NE(std::string::npos,
        Canon("(= type \"" + esc + "\\\\\")").find("longer than 256 bytes"));
  }
}

TEST(Cond, ExplainsInPlainEnglish) {
  EXPECT_EQ("the type is t.blog and the group field is one of: a, b",
      Explain("(and (= type \"t.blog\") (in field.group (\"b\" \"a\")))"));
  EXPECT_EQ("the creator is the person and the type is t.blog",
      Explain(std::string("(and (= type \"t.blog\") (= creator principal))")));
  EXPECT_EQ("the current time is less than the embargo field",
      Explain("(< now field.embargo)"));
  EXPECT_EQ("the state is published or the rank field is at least 3",
      Explain("(or (>= field.rank 3) (= state \"published\"))"));
  EXPECT_EQ("not (the state is draft)", Explain("(not (= state \"draft\"))"));
  EXPECT_EQ("the type is c and (the type is a or the type is b)",
      Explain("(and (or (= type \"a\") (= type \"b\")) (= type \"c\"))"));
  EXPECT_EQ("always", Explain("true"));
  EXPECT_EQ("never", Explain("false"));
  /* A constant with a space or a quote is shown quoted. */
  EXPECT_EQ("the title field is \"two words\"",
      Explain("(= field.title \"two words\")"));
  /* Two spellings of one expression read alike. */
  EXPECT_EQ(Explain("(and (= type \"a\") (= state \"draft\"))"),
      Explain("(and (= state \"draft\") (and (= type \"a\")))"));
  /* The explanation carries no entity value: it is built from the condition
   * alone, so there is nothing of an entity for it to print. */
  EXPECT_EQ(std::string::npos, Explain("(= field.ssn \"123\")").find("ssn\""));
}

TEST(Cond, BuiltinsAreExpressions) {
  char * any = NULL;
  char * own = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_condition_builtin(GDEFCORE_CONDITION_BUILTIN_ANY, kBlog,
          strlen(kBlog), &any, &n));
  EXPECT_EQ("(= type \"t.blog\")", std::string(any, n));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_condition_builtin(GDEFCORE_CONDITION_BUILTIN_OWN, kBlog,
          strlen(kBlog), &own, &n));
  EXPECT_EQ("(and (= creator principal) (= type \"t.blog\"))", std::string(own, n));
  gdefcore_condition_text_free(any);
  gdefcore_condition_text_free(own);
  char * none = (char *)0x1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_condition_builtin(7, kBlog, strlen(kBlog), &none, &n));
  /* What a condition reads. */
  {
    GDEFCORE_Condition * c = NULL;
    c = P("(= creator principal)");
    EXPECT_EQ(GDEFCORE_CONDITION_USES_PRINCIPAL | GDEFCORE_CONDITION_USES_ENTITY,
        gdefcore_condition_uses(c));
    gdefcore_condition_free(c);
    c = P("(< now field.embargo)");
    EXPECT_EQ(GDEFCORE_CONDITION_USES_TIME | GDEFCORE_CONDITION_USES_ENTITY,
        gdefcore_condition_uses(c));
    gdefcore_condition_free(c);
    c = P("(= type \"a\")");
    EXPECT_EQ(0u, gdefcore_condition_uses(c));
    gdefcore_condition_free(c);
    EXPECT_EQ(0u, gdefcore_condition_uses(NULL));
  }
}

/* ---------------------------------------------------------------------- */
/* Validation                                                             */
/* ---------------------------------------------------------------------- */

TEST(Cond, ValidatesAgainstTheType) {
  Env env;
  EXPECT_EQ("", Validate(env, "(= field.group \"x\")", kBlog));
  EXPECT_EQ("", Validate(env, "(and (= type \"t.blog\") (in field.tags (\"a\")))", kBlog));
  /* An unknown field is refused with the offset of the field. */
  EXPECT_EQ("no such field@3", Validate(env, "(= field.nope \"x\")", kBlog));
  EXPECT_EQ("no such field@26",
      Validate(env, "(and (= type \"t.blog\") (= field.nope 1))", kBlog));
  /* A type constant that names no type, and one that does. */
  EXPECT_EQ("no such type@8", Validate(env, "(= type \"t.nothing\")", kBlog));
  EXPECT_EQ("no such type@20",
      Validate(env, "(in type (\"t.vault\" \"zzz\"))", kBlog));
  EXPECT_EQ("", Validate(env, "(= type \"t.vault\")", kBlog));
  EXPECT_EQ("no such type@3", Validate(env, "(= \"nope\" type)", kBlog));
  /* A state constant. */
  EXPECT_EQ("", Validate(env, "(= state \"published\")", kBlog));
  EXPECT_EQ("", Validate(env, "(in state (\"draft\" \"published\"))", kBlog));
  EXPECT_EQ("no such state@9", Validate(env, "(= state \"pubished\")", kBlog));
  /* A field of a type that is not defined. */
  EXPECT_EQ("no such field@3", Validate(env, "(= field.group 1)", "t.undefined"));
  /* No field operand: any type name is fine for validation. */
  EXPECT_EQ("", Validate(env, "(= creator principal)", "t.undefined"));
}

TEST(Cond, PersonalFieldRefused) {
  Env env;
  /* A personal field is refused with the very message and offset of a field
   * the type does not have (AD-19). The control is the same shape on the
   * non-personal field of the same type, which is accepted. */
  std::string personal = Validate(env, "(= field.ssn \"1\")", kVault);
  std::string absent = Validate(env, "(= field.zzz \"1\")", kVault);
  EXPECT_EQ("", Validate(env, "(= field.name \"1\")", kVault));
  EXPECT_EQ("no such field@3", personal);
  EXPECT_EQ(absent, personal);
  {
    const std::string text = "(and (= type \"t.vault\") (in field.ssn (\"1\")))";
    EXPECT_EQ("no such field@" + std::to_string(text.find("field.ssn")),
        Validate(env, text, kVault));
  }
}

/* ---------------------------------------------------------------------- */
/* Evaluation on one entity                                               */
/* ---------------------------------------------------------------------- */

TEST(Cond, FieldEquality) {
  Env env;
  std::string x = env.Make(kBlog, "", V({{"title", "T"}, {"group", "x"}}));
  std::string y = env.Make(kBlog, "", V({{"title", "T"}, {"group", "y"}}));
  std::string none = env.Make(kBlog, "", V({{"title", "T"}}));
  const std::string eq = "(= field.group \"x\")";
  EXPECT_EQ((Answer{1, 0}), Eval(env, eq, x));
  EXPECT_EQ((Answer{0, 0}), Eval(env, eq, y));
  EXPECT_EQ((Answer{0, 0}), Eval(env, eq, none));
  /* Bytes, not meaning: case and a prefix do not match. */
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group \"X\")", x));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group \"\")", x));
  /* An absent field is the empty text. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"\")", none));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.embargo \"\")", x));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.embargo \"x\")", x));
}

TEST(Cond, NotEqual) {
  Env env;
  std::string x = env.Make(kBlog, "", V({{"title", "T"}, {"group", "x"}}));
  std::string y = env.Make(kBlog, "", V({{"title", "T"}, {"group", "y"}}));
  std::string none = env.Make(kBlog, "", V({{"title", "T"}}));
  const std::string ne = "(!= field.group \"x\")";
  EXPECT_EQ((Answer{0, 0}), Eval(env, ne, x));
  EXPECT_EQ((Answer{1, 0}), Eval(env, ne, y));
  EXPECT_EQ((Answer{1, 0}), Eval(env, ne, none));
  /* != is exactly not of =, on every operand shape. */
  EXPECT_EQ(Eval(env, "(not (= field.group \"x\"))", y),
      Eval(env, "(!= field.group \"x\")", y));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(!= type \"t.vault\")", x));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(!= type \"t.blog\")", x));
}

TEST(Cond, InList) {
  Env env;
  std::string a = env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
  std::string b = env.Make(kBlog, "", V({{"title", "T"}, {"group", "b"}}));
  std::string c = env.Make(kBlog, "", V({{"title", "T"}, {"group", "c"}}));
  std::string none = env.Make(kBlog, "", V({{"title", "T"}}));
  const std::string in = "(in field.group (\"a\" \"b\"))";
  EXPECT_EQ((Answer{1, 0}), Eval(env, in, a));
  EXPECT_EQ((Answer{1, 0}), Eval(env, in, b));
  EXPECT_EQ((Answer{0, 0}), Eval(env, in, c));
  EXPECT_EQ((Answer{0, 0}), Eval(env, in, none));
  /* Every position of a longer list, first and last included. */
  {
    const char * const members[] = {"m0", "m1", "m2", "m3", "m4"};
    size_t i;
    std::string list = "(in field.group (\"m0\" \"m1\" \"m2\" \"m3\" \"m4\"))";
    for (i = 0; i < 5; i++) {
      std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"group", members[i]}}));
      EXPECT_EQ((Answer{1, 0}), Eval(env, list, e)) << members[i];
    }
    EXPECT_EQ((Answer{0, 0}), Eval(env, list,
        env.Make(kBlog, "", V({{"title", "T"}, {"group", "m5"}}))));
  }
  /* A one-member list is equality. The empty text is not in a list that has
   * only non-empty members. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(in field.group (\"c\"))", c));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(in field.group (\"c\"))", a));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(in field.group (\"c\" \"\"))", none));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(in type (\"t.vault\" \"t.blog\"))", a));
}

TEST(Cond, ManyValuedFields) {
  Env env;
  std::string e = env.Make(kBlog, "", {{"title", {"T"}}, {"tags", {"x", "y"}}});
  /* A comparison holds when some value does; != is the negation of =. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.tags \"y\")", e));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.tags \"x\")", e));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.tags \"z\")", e));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(!= field.tags \"y\")", e));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(!= field.tags \"z\")", e));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(in field.tags (\"z\" \"x\"))", e));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(in field.tags (\"z\" \"w\"))", e));
}

TEST(Cond, Numeric) {
  Env env;
  std::string seven = env.Make(kBlog, "", V({{"title", "T"}, {"rank", "7"}}));
  std::string word = env.Make(kBlog, "", V({{"title", "T"}, {"rank", "abc"}}));
  std::string none = env.Make(kBlog, "", V({{"title", "T"}}));
  std::string ten = env.Make(kBlog, "", V({{"title", "T"}, {"rank", "10"}}));
  std::string neg = env.Make(kBlog, "", V({{"title", "T"}, {"rank", "-3"}}));
  std::string lead = env.Make(kBlog, "", V({{"title", "T"}, {"rank", "07"}}));
  const std::string lt = "(< field.rank 10)";
  EXPECT_EQ((Answer{1, 0}), Eval(env, lt, seven));
  EXPECT_EQ((Answer{0, 0}), Eval(env, lt, word));
  EXPECT_EQ((Answer{0, 0}), Eval(env, lt, none));
  EXPECT_EQ((Answer{0, 0}), Eval(env, lt, ten));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(<= field.rank 10)", ten));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(> field.rank 7)", ten));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(> field.rank 7)", seven));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(>= field.rank 7)", seven));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(< field.rank 0)", neg));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(>= field.rank -3)", neg));
  /* Either side not an integer: the comparison is false, never an error. */
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(< field.rank \"abc\")", seven));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(>= field.rank \"abc\")", word));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(<= \"x\" 2)", seven));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(< 1 2)", seven));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(< \"1\" \"2\")", seven));
  /* Numeric comparison reads "07" as 7; = compares bytes and does not. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(<= field.rank 7)", lead));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(>= field.rank 7)", lead));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.rank 7)", lead));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.rank 7)", seven));
  /* The false comparison inverts under not, as any false does. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(not (< field.rank 10))", word));
}

TEST(Cond, TimeIsTheRequestClock) {
  Env env;
  std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"embargo", "1000"}}));
  const std::string before = "(< now field.embargo)";
  EXPECT_EQ((Answer{1, 0}), Eval(env, before, e, env.Req("", 999)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, before, e, env.Req("", 1000)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, before, e, env.Req("", 1001)));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(>= now field.embargo)", e, env.Req("", 1000)));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= now \"1000\")", e, env.Req("", 1000)));
  /* The clock is fixed for the request: it can be set, reset, and once read
   * without being set it stays where it was read. */
  {
    GDEFCORE_Request * r = env.Req("", 7);
    EXPECT_EQ(7, gdefcore_request_time(r));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_time(r, -4));
    EXPECT_EQ(-4, gdefcore_request_time(r));
    EXPECT_EQ(0, gdefcore_request_time(NULL));
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_request_set_time(NULL, 1));
    GDEFCORE_Request * fresh = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)"t", 1, 0, 0, NULL, &fresh));
    int64_t first = gdefcore_request_time(fresh);
    EXPECT_GT(first, 1700000000);
    EXPECT_EQ(first, gdefcore_request_time(fresh));
    gdefcore_request_destroy(fresh);
  }
}

TEST(Cond, StateFollowsTheProjection) {
  Env env;
  std::string pub = env.Make(kBlog, "", V({{"title", "T"}}));
  std::string draft = env.Make(kBlog, "", V({{"title", "T"}}), 1);
  int state = 0;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_entity_state(env.catalog, pub.data(), pub.size(), &state));
  EXPECT_EQ(GDEFCORE_STATE_PUBLISHED, state);
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_entity_state(env.catalog, draft.data(), draft.size(), &state));
  EXPECT_EQ(GDEFCORE_STATE_DRAFT, state);
  state = 55;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_entity_state(env.catalog, "00000000000000000000000000", 26, &state));
  EXPECT_EQ(55, state);
  const std::string published = "(= state \"published\")";
  const std::string drafted = "(= state \"draft\")";
  EXPECT_EQ((Answer{1, 0}), Eval(env, published, pub));
  EXPECT_EQ((Answer{0, 0}), Eval(env, drafted, pub));
  EXPECT_EQ((Answer{0, 0}), Eval(env, published, draft));
  EXPECT_EQ((Answer{1, 0}), Eval(env, drafted, draft));
  /* Publishing moves it; a draft beside a published row does not. */
  env.Publish(draft);
  EXPECT_EQ((Answer{1, 0}), Eval(env, published, draft));
  EXPECT_EQ((Answer{0, 0}), Eval(env, drafted, draft));
  {
    char id2[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    const char * t = "T2";
    size_t tl = 2;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "title";
    v.field_len = 5;
    v.texts = &t;
    v.text_lens = &tl;
    v.count = 1;
    (void)id2;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(env.catalog, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save_draft(cs, pub.data(), pub.size(), "en", 2, &v, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    EXPECT_EQ((Answer{1, 0}), Eval(env, published, pub));
    EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.title \"T\")", pub));
  }
}

/* Write another revision of an existing entity: a save (published, active) or
 * a draft (head only), by @p actor. */
void Resave(Env & env, const std::string & id, const std::string & actor,
    const char * field, const char * value, bool draft) {
  GDEFCORE_Changeset * cs = NULL;
  GDEFCORE_Value v;
  const char * t = value;
  size_t tl = strlen(value);
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  v.field = field;
  v.field_len = strlen(field);
  v.texts = &t;
  v.text_lens = &tl;
  v.count = 1;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_changeset_prepare(env.catalog, actor.empty() ? NULL : actor.data(),
          actor.size(), &cs));
  ASSERT_EQ(GDEFCORE_OK,
      (draft ? gdefcore_entity_save_draft : gdefcore_entity_save)(
          cs, id.data(), id.size(), "en", 2, &v, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
}

/* An unpublished entity is evaluated on its active revision, so a grant can
 * hold for it, and `state` still says it is a draft. A newer draft beside the
 * active revision is not what a condition reads. */
TEST(Cond, TheActiveRevisionIsWhatIsRead) {
  Env env;
  const std::string group_a = "(= field.group \"a\")";
  const std::string published = "(= state \"published\")";
  std::string unpublished =
      env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}), 1);
  /* control: the same entity on the old rule, where nothing of it was read */
  EXPECT_EQ((Answer{1, 0}), Eval(env, group_a, unpublished));
  EXPECT_EQ((Answer{0, 0}), Eval(env, published, unpublished));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group \"b\")", unpublished));
  /* A published entity with a newer draft: the conditions read the active. */
  std::string pub = env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
  Resave(env, pub, "", "group", "b", true);
  EXPECT_EQ((Answer{1, 0}), Eval(env, group_a, pub));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group \"b\")", pub));
  EXPECT_EQ((Answer{1, 0}), Eval(env, published, pub));
  /* Publishing the draft moves what is read. */
  env.Publish(pub);
  EXPECT_EQ((Answer{0, 0}), Eval(env, group_a, pub));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"b\")", pub));
  /* Unpublishing keeps what is read and changes the state. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(env.catalog, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_unpublish(cs, pub.data(), pub.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"b\")", pub));
  EXPECT_EQ((Answer{0, 0}), Eval(env, published, pub));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= state \"draft\")", pub));
  /* A cleared entity has no active revision: a field condition cannot hold. */
  std::string gone = env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revert(env.catalog, gone.data(), gone.size(), NULL, 0,
            &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ((Answer{0, 0}), Eval(env, group_a, gone));
}

/* `creator` is who created the entity and never changes; `revision.creator` is
 * who wrote the revision that is active. An editor who saves someone's entity
 * becomes the second and not the first. */
TEST(Cond, CreatorIsTheEntitysAndRevisionCreatorIsTheRevisions) {
  Env env;
  const std::string alice = FreshId();
  const std::string bob = FreshId();
  const std::string by_creator = "(= creator principal)";
  const std::string by_revision = "(= revision.creator principal)";
  std::string e = env.Make(kBlog, alice, V({{"title", "T"}}));
  EXPECT_EQ((Answer{1, 0}), Eval(env, by_creator, e, env.Req(alice)));
  EXPECT_EQ((Answer{1, 0}), Eval(env, by_revision, e, env.Req(alice)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_creator, e, env.Req(bob)));
  Resave(env, e, bob, "title", "edited", false);
  EXPECT_EQ((Answer{1, 0}), Eval(env, by_creator, e, env.Req(alice)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_creator, e, env.Req(bob)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_revision, e, env.Req(alice)));
  EXPECT_EQ((Answer{1, 0}), Eval(env, by_revision, e, env.Req(bob)));
  /* A draft beside the active revision is by neither: the active one is read. */
  Resave(env, e, alice, "title", "later draft", true);
  EXPECT_EQ((Answer{1, 0}), Eval(env, by_revision, e, env.Req(bob)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_revision, e, env.Req(alice)));
  /* An entity with no creator is nobody's, and an anonymous request is not
   * equal to it. */
  std::string anon = env.Make(kBlog, "", V({{"title", "T"}}));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_creator, anon, env.Req(alice)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_creator, anon, env.Req("")));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_revision, anon, env.Req(alice)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, by_revision, anon, env.Req("")));
  /* The operands read the entity and the person. */
  GDEFCORE_Condition * c = P(by_creator);
  EXPECT_EQ(GDEFCORE_CONDITION_USES_PRINCIPAL | GDEFCORE_CONDITION_USES_ENTITY,
      gdefcore_condition_uses(c));
  gdefcore_condition_free(c);
  c = P(by_revision);
  EXPECT_EQ(GDEFCORE_CONDITION_USES_PRINCIPAL | GDEFCORE_CONDITION_USES_ENTITY,
      gdefcore_condition_uses(c));
  gdefcore_condition_free(c);
  EXPECT_EQ("(= creator principal)", Canon(by_creator));
  EXPECT_EQ("(= revision.creator principal)", Canon(by_revision));
  EXPECT_EQ("the creator is the person", Explain(by_creator));
  EXPECT_EQ("the author of the revision is the person", Explain(by_revision));
}

/* Edition 2 renamed `actor`. Text a person writes now is refused with a
 * message that says where it went; text stored in edition 1 is upcast, which
 * is a rename of that one operand and leaves text constants and fields named
 * actor alone; edition 2 text passes through untouched. */
TEST(Cond, EditionOneActorIsUpcastAndNotWrittenAnyMore) {
  GDEFCORE_Condition * c = NULL;
  GDEFCORE_Condition_Error err;
  memset(&err, 0, sizeof err);
  err.size = sizeof err;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_condition_parse("(= actor principal)", 19, &c, &err));
  EXPECT_NE(nullptr, err.message);
  EXPECT_NE(std::string::npos, std::string(err.message).find("revision.creator"));
  EXPECT_EQ(3u, err.offset);
  auto Up = [](const std::string & text, int from) {
    char * out = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_condition_upcast(text.data(), text.size(), from, &out, &n);
    std::string s = rc == GDEFCORE_OK ? std::string(out, n) : "<refused>";
    gdefcore_condition_text_free(out);
    return s;
  };
  EXPECT_EQ("(= revision.creator principal)", Up("(= actor principal)", 1));
  EXPECT_EQ("(and (= type \"t\") (!= revision.creator \"x\"))",
      Up("(and (= type \"t\") (!= actor \"x\"))", 1));
  /* only the operand: not a constant, not a longer word, not a field */
  EXPECT_EQ("(= field.title \"actor\")", Up("(= field.title \"actor\")", 1));
  EXPECT_EQ("(= field.actor \"x\")", Up("(= field.actor \"x\")", 1));
  EXPECT_EQ("(= type \"a\\\" actor\")", Up("(= type \"a\\\" actor\")", 1));
  EXPECT_EQ("(= field.f actors)", Up("(= field.f actors)", 1));
  EXPECT_EQ("(in revision.creator (\"actor\"))", Up("(in actor (\"actor\"))", 1));
  /* edition 2 is the identity, and so is the upcast of an upcast */
  EXPECT_EQ("(= creator principal)", Up("(= creator principal)", 2));
  EXPECT_EQ("(= actor principal)", Up("(= actor principal)", 2));   /* copied */
  EXPECT_EQ(Up("(= revision.creator principal)", 1),
      Up(Up("(= actor principal)", 1), 1));
  EXPECT_EQ("<refused>", Up("x", 3));
  EXPECT_EQ("<refused>", Up("x", 0));
  EXPECT_EQ("", Up("", 1));
  /* the stored form parses as the new operand and evaluates as it */
  Env env;
  const std::string alice = FreshId();
  const std::string bob = FreshId();
  std::string e = env.Make(kBlog, alice, V({{"title", "T"}}));
  Resave(env, e, bob, "title", "edited", false);
  GDEFCORE_Condition * stored = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse_stored("(= actor principal)", 19, &stored, NULL));
  GDEFCORE_Condition_Subject subject;
  memset(&subject, 0, sizeof subject);
  subject.size = sizeof subject;
  subject.entity = e.data();
  subject.entity_len = e.size();
  int failed = 0;
  EXPECT_EQ(0, gdefcore_condition_eval(env.catalog, env.Req(alice), stored,
                   &subject, &failed));
  EXPECT_EQ(1, gdefcore_condition_eval(env.catalog, env.Req(bob), stored,
                   &subject, &failed));
  gdefcore_condition_free(stored);
  /* parse_stored does not loosen what a person may write */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_condition_parse_stored("(= bogus principal)", 19, &stored, NULL));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse_stored("(= creator principal)", 21, &stored, NULL));
  gdefcore_condition_free(stored);
  EXPECT_STREQ("defiant-condition/2", GDEFCORE_CONDITION_FORMAT);
  EXPECT_STREQ("defiant-condition/1", GDEFCORE_CONDITION_FORMAT_PREVIOUS);
}

TEST(Cond, BooleanTruthTables) {
  Env env;
  std::string e = env.Make(kBlog, "", V({{"title", "T"}}));
  const char * const tf[2] = {"false", "true"};
  int a;
  int b;
  int c;
  for (a = 0; a < 2; a++) {
    EXPECT_EQ((Answer{!a, 0}), Eval(env, std::string("(not ") + tf[a] + ")", e));
    for (b = 0; b < 2; b++) {
      std::string pair = std::string(tf[a]) + " " + tf[b];
      EXPECT_EQ((Answer{a && b, 0}), Eval(env, "(and " + pair + ")", e)) << pair;
      EXPECT_EQ((Answer{a || b, 0}), Eval(env, "(or " + pair + ")", e)) << pair;
      for (c = 0; c < 2; c++) {
        std::string tri = pair + " " + tf[c];
        EXPECT_EQ((Answer{a && b && c, 0}), Eval(env, "(and " + tri + ")", e));
        EXPECT_EQ((Answer{a || b || c, 0}), Eval(env, "(or " + tri + ")", e));
        EXPECT_EQ((Answer{(a && b) || c, 0}),
            Eval(env, std::string("(or (and ") + pair + ") " + tf[c] + ")", e));
        EXPECT_EQ((Answer{!(a || b) && c, 0}),
            Eval(env, std::string("(and (not (or ") + pair + ")) " + tf[c] + ")", e));
      }
    }
  }
  /* The same, over real comparisons: control that the table is not all true
   * or all false by accident. */
  EXPECT_EQ((Answer{1, 0}),
      Eval(env, "(and (= type \"t.blog\") (not (= field.title \"U\")))", e));
  EXPECT_EQ((Answer{0, 0}),
      Eval(env, "(and (= type \"t.blog\") (= field.title \"U\"))", e));
  EXPECT_EQ((Answer{1, 0}),
      Eval(env, "(or (= type \"t.vault\") (= field.title \"T\"))", e));
}

TEST(Cond, OwnNeedsAnActor) {
  Env env;
  const std::string alice = FreshId();
  const std::string bob = FreshId();
  std::string mine = env.Make(kBlog, alice, V({{"title", "T"}}));
  std::string noactor = env.Make(kBlog, "", V({{"title", "T"}}));
  const std::string own = "(and (= type \"t.blog\") (= creator principal))";
  EXPECT_EQ((Answer{1, 0}), Eval(env, own, mine, env.Req(alice)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, own, mine, env.Req(bob)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, own, mine, env.Req("")));
  /* An entity with no actor is nobody's own: not a named principal's, and
   * not an anonymous request's either. */
  EXPECT_EQ((Answer{0, 0}), Eval(env, own, noactor, env.Req(alice)));
  EXPECT_EQ((Answer{0, 0}), Eval(env, own, noactor, env.Req("")));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= creator \"\")", noactor, env.Req("")));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= principal \"\")", mine, env.Req("")));
  /* The same absence read the other way: != is the negation. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(!= creator principal)", noactor, env.Req(alice)));
}

TEST(Cond, AbsentFieldIsNotAWildcard) {
  Env env;
  std::string none = env.Make(kBlog, "", V({{"title", "T"}}));
  std::string x = env.Make(kBlog, "", V({{"title", "T"}, {"group", "x"}}));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group \"x\")", none));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(in field.group (\"x\" \"y\"))", none));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group 7)", none));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= \"x\" field.group)", none));
  /* Control: the same shapes on a present value hold. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"x\")", x));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(in field.group (\"x\" \"y\"))", x));
}

TEST(Cond, ReadsTheLanguageOfTheCall) {
  Env env;
  std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"group", "en-g"}}));
  {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v;
    const char * t = "fr-g";
    size_t tl = 4;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "group";
    v.field_len = 5;
    v.texts = &t;
    v.text_lens = &tl;
    v.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(env.catalog, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, e.data(), e.size(), "fr", 2, &v, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"en-g\")", e));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"en-g\")", e, NULL, "en"));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"fr-g\")", e, NULL, "fr"));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group \"en-g\")", e, NULL, "fr"));
  /* A language the entity has nothing in reads as absent. */
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= field.group \"en-g\")", e, NULL, "de"));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.group \"\")", e, NULL, "de"));
}

TEST(Cond, HiddenEqualsMissing) {
  Env env;
  std::string exists = env.Make(kBlog, "", V({{"title", "T"}}));
  const std::string never = FreshId();
  const std::string junk = "not an id";
  const std::string cond =
      "(or (= field.title \"no-such\") (= type \"t.vault\") (= state \"draft\") "
      "(= creator \"nobody\"))";
  /* False on an entity that exists, and on ids that do not: one answer. */
  EXPECT_EQ((Answer{0, 0}), Eval(env, cond, exists));
  EXPECT_EQ((Answer{0, 0}), Eval(env, cond, never));
  EXPECT_EQ((Answer{0, 0}), Eval(env, cond, junk));
  EXPECT_EQ((Answer{0, 0}), Eval(env, cond, ""));
  /* Control: a condition that holds sees the entity that exists and only it. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= type \"t.blog\")", exists));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(= type \"t.blog\")", never));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "(not (= type \"t.vault\"))", never));
  EXPECT_EQ((Answer{0, 0}), Eval(env, "true", never));
}

TEST(Cond, HypotheticalEntity) {
  Env env;
  GDEFCORE_Condition * c = NULL;
  GDEFCORE_Condition_Subject s;
  int failed = 9;
  memset(&s, 0, sizeof s);
  s.size = sizeof s;
  s.type_name = kBlog;
  s.type_name_len = strlen(kBlog);
  c = P("(= type \"t.blog\")");
  ASSERT_TRUE(c != NULL);
  EXPECT_EQ(1, gdefcore_condition_eval(env.catalog, env.req, c, &s, &failed));
  EXPECT_EQ(0, failed);
  gdefcore_condition_free(c);
  /* No state, no actor, no values. */
  c = P("(or (= state \"published\") (= creator principal) (= field.group \"x\"))");
  ASSERT_TRUE(c != NULL);
  EXPECT_EQ(0, gdefcore_condition_eval(env.catalog, env.req, c, &s, &failed));
  EXPECT_EQ(0, failed);
  gdefcore_condition_free(c);
  /* Nothing to evaluate on: does not hold, and is not a failure. */
  memset(&s, 0, sizeof s);
  s.size = sizeof s;
  c = P("true");
  ASSERT_TRUE(c != NULL);
  EXPECT_EQ(0, gdefcore_condition_eval(env.catalog, env.req, c, &s, &failed));
  EXPECT_EQ(0, failed);
  EXPECT_EQ(0, gdefcore_condition_eval(NULL, env.req, c, &s, &failed));
  EXPECT_EQ(0, gdefcore_condition_eval(env.catalog, NULL, c, &s, &failed));
  EXPECT_EQ(0, gdefcore_condition_eval(env.catalog, env.req, NULL, &s, &failed));
  EXPECT_EQ(0, gdefcore_condition_eval(env.catalog, env.req, c, NULL, &failed));
  EXPECT_EQ(0, gdefcore_condition_eval(env.catalog, env.req, c, &s, NULL));
  gdefcore_condition_free(c);
}

TEST(Cond, FailureNeverGrants) {
  Env env;
  std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
  std::string v = env.Make(kVault, "", V({{"name", "N"}}));
  /* A field the type lacks, and a personal field (its value is ciphertext):
   * evaluation fails, and a failure is no grant, even under not. */
  EXPECT_EQ((Answer{0, 1}), Eval(env, "(= field.nope \"x\")", e));
  EXPECT_EQ((Answer{0, 1}), Eval(env, "(not (= field.nope \"x\"))", e));
  EXPECT_EQ((Answer{0, 1}), Eval(env, "(!= field.nope \"x\")", e));
  EXPECT_EQ((Answer{0, 1}), Eval(env, "(= field.ssn \"x\")", v));
  EXPECT_EQ((Answer{0, 1}), Eval(env, "(not (= field.ssn \"x\"))", v));
  /* A failure in one branch of an or does not become a grant from the other
   * branch's failure, and does not hide a true branch that was reached. */
  EXPECT_EQ((Answer{0, 1}), Eval(env, "(or (= field.nope \"x\") true)", e));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(or true (= field.nope \"x\"))", e));
  /* Control: the same shapes on a field the type has hold or fail as they
   * should, with no failure flag. */
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(not (= field.group \"x\"))", e));
  EXPECT_EQ((Answer{1, 0}), Eval(env, "(= field.name \"N\")", v));
  /* An allocation that fails at each point in turn. The condition below is
   * false for this entity and its negation is true; at no point may either
   * answer be a grant that is not true, and a failure sets the flag. */
  {
    const std::string neg = "(and (not (= field.group \"zzz\")) (= state \"draft\"))";
    const std::string pos = "(or (= field.group \"zzz\") (= state \"draft\"))";
    long total = 0;
    long n;
    int saw_failure = 0;
    int saw_clean = 0;
    env.fa.armed = true;
    env.fa.target = 0;
    env.fa.seen = 0;
    EXPECT_EQ((Answer{0, 0}), Eval(env, neg, e));
    total = env.fa.seen;
    ASSERT_GT(total, 3);
    /* One past the last allocation is the control: nothing fails there. */
    for (n = 1; n <= total + 1; n++) {
      Answer a;
      Answer b;
      env.fa.armed = true;
      env.fa.target = n;
      env.fa.seen = 0;
      a = Eval(env, neg, e);
      env.fa.seen = 0;
      b = Eval(env, pos, e);
      env.fa.armed = false;
      /* The truth is 0 for both (the entity is published, not a draft). */
      EXPECT_EQ(0, a.allow) << "allocation " << n << " of " << total;
      EXPECT_EQ(0, b.allow) << "allocation " << n << " of " << total;
      if (a.failed || b.failed) {
        saw_failure = 1;
      } else {
        saw_clean = 1;
      }
    }
    EXPECT_EQ(1, saw_failure) << "no allocation failure reached the evaluator";
    EXPECT_EQ(1, saw_clean);
    env.fa.armed = false;
  }
  /* And a plain Control: with nothing failing the answers are as computed. */
  EXPECT_EQ((Answer{1, 0}),
      Eval(env, "(and (not (= field.group \"zzz\")) (= state \"published\"))", e));
}

/* ---------------------------------------------------------------------- */
/* Grants that carry an expression                                        */
/* ---------------------------------------------------------------------- */

namespace {

/** Roles, principals and permissions on top of Env. */
struct AEnv : Env {
  void Role(const char * name) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_role_create(catalog, name, strlen(name), NULL));
  }

  std::string Principal(const char * role = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    id[0] = '\0';
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(catalog, id));
    if (role != NULL) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_access_principal_add_role(catalog, id, strlen(id), role,
              strlen(role)));
    }
    return std::string(id);
  }

  GDEFCORE_Result Declare(const char * label, const char * action, int cond,
      const char * text, const char * type = kBlog, const char * field = NULL) {
    GDEFCORE_Permission p;
    memset(&p, 0, sizeof p);
    p.size = sizeof p;
    p.label = label;
    p.label_len = strlen(label);
    p.module_name = "notes";
    p.module_name_len = 5;
    p.action = action;
    p.action_len = strlen(action);
    p.condition = cond;
    p.type_name = type;
    p.type_name_len = strlen(type);
    if (field != NULL) {
      p.field = field;
      p.field_len = strlen(field);
    }
    if (text != NULL) {
      p.condition_text = text;
      p.condition_text_len = strlen(text);
    }
    return gdefcore_access_declare(catalog, &p);
  }

  void DeclareOk(const char * label, const char * action, int cond,
      const char * text, const char * type = kBlog, const char * field = NULL) {
    ASSERT_EQ(GDEFCORE_OK, Declare(label, action, cond, text, type, field))
        << label;
  }

  void Grant(const char * role, const char * label) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog, role, strlen(role), label, strlen(label),
            "core.role", 9));
  }

  /** "rc|count|text0,text1" for a filtered read of @p field. */
  std::string Read(GDEFCORE_Request * r, const std::string & id,
      const char * field) {
    char ** texts = (char **)0x1;
    size_t * lens = (size_t *)0x1;
    size_t count = 99;
    GDEFCORE_Result rc = gdefcore_access_read(catalog, r, id.data(), id.size(),
        "en", 2, field, strlen(field), &texts, &lens, &count);
    std::string out = gdefcore_result_string(rc);
    if (texts == (char **)0x1 && lens == (size_t *)0x1 && count == 99) {
      out += "|untouched";
    } else if (rc == GDEFCORE_OK) {
      size_t i;
      out += "|" + std::to_string(count) + "|";
      for (i = 0; i < count; i++) {
        out += (i ? "," : "") + std::string(texts[i], lens[i]);
      }
      gdefcore_values_free(catalog, texts, lens, count);
    } else {
      out += "|WROTE";
    }
    return out;
  }

  /** The ids a list returns, as a sorted ", "-joined string of titles, plus
   * the count the call reports. */
  std::string List(GDEFCORE_Request * r, const char * type = kBlog,
      size_t * out_count = NULL, GDEFCORE_Result * out_rc = NULL) {
    GDEFCORE_Access_List q;
    char ** ids = NULL;
    size_t count = 0;
    std::string out;
    size_t i;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.type_name = type;
    q.type_name_len = strlen(type);
    q.lang = "en";
    q.lang_len = 2;
    GDEFCORE_Result rc = gdefcore_access_list(catalog, r, &q, &ids, &count);
    if (out_count != NULL) {
      *out_count = count;
    }
    if (out_rc != NULL) {
      *out_rc = rc;
    }
    if (rc != GDEFCORE_OK) {
      return std::string("rc=") + gdefcore_result_string(rc);
    }
    EXPECT_EQ(count, count);
    for (i = 0; i < count; i++) {
      char ** texts = NULL;
      size_t * lens = NULL;
      size_t n = 0;
      std::string title = "?";
      if (gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              GDEFCORE_PUBLIC_ID_LEN, "en", 2, "title", 5, &texts, &lens, &n) ==
          GDEFCORE_OK && n > 0) {
        title.assign(texts[0], lens[0]);
        gdefcore_values_free(catalog, texts, lens, n);
      }
      out += (i ? "," : "") + title;
    }
    gdefcore_access_free(catalog, ids, count);
    return out;
  }

  int Permits(GDEFCORE_Request * r, const char * action) {
    return gdefcore_access_permits(catalog, r, action, strlen(action));
  }

  std::string Key(GDEFCORE_Request * r) {
    char * key = NULL;
    size_t n = 0;
    std::string out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(catalog, r, NULL, 0, NULL, 0, &key, &n));
    if (key != NULL) {
      out.assign(key, n);
      gdefcore_text_free(catalog, key);
    }
    return out;
  }

  /** Replace the stored condition text of a declared permission, as a
   * corrupted or stale store would hold it. */
  void Corrupt(const char * label, const std::string & text) {
    char ** ids = NULL;
    size_t count = 0;
    size_t i;
    bool done = false;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(catalog, "core.permission", 15, &ids, &count));
    for (i = 0; i < count && !done; i++) {
      char ** texts = NULL;
      size_t * lens = NULL;
      size_t n = 0;
      if (gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              GDEFCORE_PUBLIC_ID_LEN, "en", 2, "label", 5, &texts, &lens, &n) !=
          GDEFCORE_OK) {
        continue;
      }
      bool match = n > 0 && std::string(texts[0], lens[0]) == label;
      gdefcore_values_free(catalog, texts, lens, n);
      if (match) {
        GDEFCORE_Changeset * cs = NULL;
        GDEFCORE_Value v;
        const char * t = text.c_str();
        size_t tl = text.size();
        memset(&v, 0, sizeof v);
        v.size = sizeof v;
        v.field = "condition";
        v.field_len = 9;
        v.texts = &t;
        v.text_lens = &tl;
        v.count = 1;
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_changeset_prepare(catalog, NULL, 0, &cs));
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_entity_save(cs, ids[i], GDEFCORE_PUBLIC_ID_LEN, "en", 2,
                &v, 1));
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_changeset_apply(cs, "core.permission", 15));
        gdefcore_changeset_destroy(cs);
        done = true;
      }
    }
    gdefcore_ids_free(catalog, ids, count);
    ASSERT_TRUE(done) << label;
  }
};

/** The note a failed condition leaves on the request, or "<none>". */
std::string Note(GDEFCORE_Request * r) {
  size_t n = 0;
  const char * v = gdefcore_request_note(r, "defiant.condition.failed", 24, &n);
  return v == NULL ? std::string("<none>") : std::string(v, n);
}

}  // namespace

TEST(CondAccess, DeclareRefusals) {
  AEnv env;
  /* Both the integer and the text: an error. Neither: an error. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      env.Declare("both", "read", GDEFCORE_ACCESS_ANY, "(= type \"t.blog\")"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, env.Declare("neither", "read", 0, NULL));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, env.Declare("bad int", "read", 9, NULL));
  /* A text that does not parse, or names a field the type lacks, or a
   * personal one, or a relation: refused, and nothing was declared. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, env.Declare("syntax", "read", 0, "(and"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      env.Declare("nofield", "read", 0, "(= field.nope \"x\")"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      env.Declare("personal", "read", 0, "(= field.ssn \"x\")", kVault));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      env.Declare("rel", "read", 0, "(related field.group)"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      env.Declare("notype", "read", 0, "(= type \"t.nothing\")"));
  /* Control: the right shape of each is declared. */
  EXPECT_EQ(GDEFCORE_OK,
      env.Declare("ok text", "read", 0, "(= field.group \"x\")"));
  EXPECT_EQ(GDEFCORE_OK,
      env.Declare("ok int", "read", GDEFCORE_ACCESS_ANY, NULL));
  EXPECT_EQ(GDEFCORE_OK, env.Declare("ok vault", "read", 0,
      "(= field.name \"x\")", kVault));
  /* Nothing from the refusals was written, and a role can be granted the
   * ones that were declared, and only those. */
  env.Role("r");
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_access_grant(env.catalog, "r", 1, "syntax", 6, "core.role", 9));
  EXPECT_NE(GDEFCORE_OK,
      gdefcore_access_grant(env.catalog, "r", 1, "both", 4, "core.role", 9));
  env.Grant("r", "ok text");
  /* A second declare of the same label leaves the first in place. */
  EXPECT_EQ(GDEFCORE_OK,
      env.Declare("ok text", "read", 0, "(= field.group \"y\")"));
  {
    std::string p = env.Principal("r");
    std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"group", "x"}}));
    EXPECT_EQ("No error|1|T", env.Read(env.Req(p), e, "title"));
  }
  /* A struct from before condition_text existed: its size stops short. */
  {
    GDEFCORE_Permission p;
    memset(&p, 0, sizeof p);
    p.size = offsetof(GDEFCORE_Permission, condition_text);
    p.label = "old caller";
    p.label_len = 10;
    p.module_name = "notes";
    p.module_name_len = 5;
    p.action = "read";
    p.action_len = 4;
    p.condition = GDEFCORE_ACCESS_OWN;
    p.type_name = kBlog;
    p.type_name_len = strlen(kBlog);
    p.condition_text = "garbage that must not be read";
    p.condition_text_len = 29;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_declare(env.catalog, &p));
  }
}

TEST(CondAccess, ReadAndListHonorTheExpression) {
  AEnv env;
  std::string a1 = env.Make(kBlog, "", V({{"title", "a1"}, {"group", "a"}}));
  std::string a2 = env.Make(kBlog, "", V({{"title", "a2"}, {"group", "a"}}));
  std::string b1 = env.Make(kBlog, "", V({{"title", "b1"}, {"group", "b"}}));
  std::string none = env.Make(kBlog, "", V({{"title", "none"}}));
  std::string drafted = env.Make(kBlog, "", V({{"title", "dr"}, {"group", "a"}}), 1);
  (void)a1;
  (void)a2;
  (void)b1;
  (void)none;
  (void)drafted;
  env.DeclareOk("Read group a", "read", 0, "(= field.group \"a\")");
  env.DeclareOk("Read all", "read", GDEFCORE_ACCESS_ANY, NULL);
  env.Role("a-readers");
  env.Role("all-readers");
  env.Grant("a-readers", "Read group a");
  env.Grant("all-readers", "Read all");
  std::string pa = env.Principal("a-readers");
  std::string pall = env.Principal("all-readers");
  std::string pnone = env.Principal();
  /* One entity at a time. */
  EXPECT_EQ("No error|1|a1", env.Read(env.Req(pa), a1, "title"));
  EXPECT_EQ("No error|1|a2", env.Read(env.Req(pa), a2, "title"));
  EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(pa), b1, "title"));
  EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(pa), none, "title"));
  /* A draft-only entity is not published, so a reader does not see it, even
   * though its active revision is in group a (the condition holds on it: the
   * control below publishes it and the same principal reads it). */
  EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(pa), drafted, "title"));
  /* Controls: the int grant sees them all; a principal with no role none. */
  EXPECT_EQ("No error|1|b1", env.Read(env.Req(pall), b1, "title"));
  EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(pnone), a1, "title"));
  /* A list, and its count, are what the grant holds for. */
  size_t count = 0;
  EXPECT_EQ("a1,a2", env.List(env.Req(pa), kBlog, &count));
  EXPECT_EQ(2u, count);
  /* The draft-only entity is not listed. It used to be (the list never asked
   * whether an entity was published, so an `any` reader was told the id of
   * one that a direct read refused). The list now asks, as a read does. */
  EXPECT_EQ("a1,a2,b1,none", env.List(env.Req(pall), kBlog, &count));
  EXPECT_EQ(4u, count);
  EXPECT_EQ("", env.List(env.Req(pnone), kBlog, &count));
  EXPECT_EQ(0u, count);
  /* The anonymous state holds no role grant here. */
  EXPECT_EQ("", env.List(env.Req(""), kBlog, &count));
  EXPECT_EQ(0u, count);
  /* Control: the same entity, published, is read by the group a reader and
   * listed to both: it was the flag that hid it, not the grant. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(env.catalog, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_publish(cs, drafted.data(), drafted.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ("No error|1|dr", env.Read(env.Req(pa), drafted, "title"));
  EXPECT_EQ("a1,a2,dr", env.List(env.Req(pa), kBlog, &count));
  EXPECT_EQ(3u, count);
  EXPECT_EQ(5u, [&] { env.List(env.Req(pall), kBlog, &count); return count; }());
}

TEST(CondAccess, ListCountsWhatIsGranted) {
  AEnv env;
  int i;
  env.DeclareOk("Read even", "read", 0, "(in field.rank (\"0\" \"2\" \"4\" \"6\" \"8\"))");
  env.Role("r");
  env.Grant("r", "Read even");
  std::string p = env.Principal("r");
  for (i = 0; i < 20; i++) {
    env.Make(kBlog, "", V({{"title", "e" + std::to_string(i)},
        {"rank", std::to_string(i % 10)}}));
  }
  size_t count = 0;
  GDEFCORE_Result rc = GDEFCORE_ERR_INTERNAL;
  std::string got = env.List(env.Req(p), kBlog, &count, &rc);
  /* Ranks 0,2,4,6,8 of ten, twice over: ten entities, not twenty. */
  ASSERT_EQ(GDEFCORE_OK, rc);
  ASSERT_EQ(10u, count);
  EXPECT_EQ("e0,e2,e4,e6,e8,e10,e12,e14,e16,e18", got);
  /* The count and the ids agree for a principal who is granted nothing. */
  std::string nobody = env.Principal();
  EXPECT_EQ("", env.List(env.Req(nobody), kBlog, &count, &rc));
  EXPECT_EQ(GDEFCORE_OK, rc);
  EXPECT_EQ(0u, count);
}

TEST(CondAccess, AnyAndOwnAsExpressionsMatchTheIntegers) {
  /* The integer fast path and the expression form are one meaning. Over
   * every principal and every entity the answers to read, list and permits
   * are the same strings. */
  AEnv env;
  std::string alice = env.Principal();
  std::string bob = env.Principal();
  std::string anyexpr_text;
  std::string ownexpr_text;
  {
    char * t = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_condition_builtin(GDEFCORE_CONDITION_BUILTIN_ANY, kBlog,
            strlen(kBlog), &t, &n));
    anyexpr_text.assign(t, n);
    gdefcore_condition_text_free(t);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_condition_builtin(GDEFCORE_CONDITION_BUILTIN_OWN, kBlog,
            strlen(kBlog), &t, &n));
    ownexpr_text.assign(t, n);
    gdefcore_condition_text_free(t);
  }
  std::string e1 = env.Make(kBlog, alice, V({{"title", "alice1"}, {"group", "g"}}));
  std::string e2 = env.Make(kBlog, bob, V({{"title", "bob1"}, {"group", "g"}}));
  std::string e3 = env.Make(kBlog, "", V({{"title", "nobody1"}}));
  std::string e4 = env.Make(kBlog, alice, V({{"title", "alice-draft"}}), 1);
  std::string e5 = env.Make(kBlog, alice, V({{"title", "alice2"}, {"group", "h"}}));
  std::vector<std::string> ents = {e1, e2, e3, e4, e5, FreshId()};
  /* Entity-wide and field-level, any and own, as ints and as expressions. */
  env.DeclareOk("int any", "read", GDEFCORE_ACCESS_ANY, NULL);
  env.DeclareOk("expr any", "read", 0, anyexpr_text.c_str());
  env.DeclareOk("int own", "read", GDEFCORE_ACCESS_OWN, NULL);
  env.DeclareOk("expr own", "read", 0, ownexpr_text.c_str());
  env.DeclareOk("int own group", "read", GDEFCORE_ACCESS_OWN, NULL, kBlog, "group");
  env.DeclareOk("expr own group", "read", 0, ownexpr_text.c_str(), kBlog, "group");
  env.DeclareOk("int any group", "read", GDEFCORE_ACCESS_ANY, NULL, kBlog, "group");
  env.DeclareOk("expr any group", "read", 0, anyexpr_text.c_str(), kBlog, "group");
  env.DeclareOk("int act", "core.act", GDEFCORE_ACCESS_OWN, NULL);
  env.DeclareOk("expr act", "core.act2", 0, ownexpr_text.c_str());
  struct Pair {
    const char * role_int;
    const char * role_expr;
    std::vector<const char *> ints;
    std::vector<const char *> exprs;
  };
  std::vector<Pair> pairs = {
      {"i-any", "x-any", {"int any"}, {"expr any"}},
      {"i-own", "x-own", {"int own"}, {"expr own"}},
      {"i-own-g", "x-own-g", {"int own", "int own group"}, {"expr own", "expr own group"}},
      {"i-any-g", "x-any-g", {"int own", "int any group"}, {"expr own", "expr any group"}},
      {"i-act", "x-act", {"int own", "int act"}, {"expr own", "expr act"}},
  };
  for (const Pair & p : pairs) {
    env.Role(p.role_int);
    env.Role(p.role_expr);
    for (const char * l : p.ints) {
      env.Grant(p.role_int, l);
    }
    for (const char * l : p.exprs) {
      env.Grant(p.role_expr, l);
    }
  }
  size_t checked = 0;
  size_t nonempty = 0;
  /* The same principal holds one role at a time: the integer role in one
   * pass, the expression role in the next, and the answers are compared. */
  for (const Pair & p : pairs) {
    for (const std::string & who : {alice, bob}) {
      std::string by_int;
      std::string by_expr;
      for (int pass = 0; pass < 2; pass++) {
        const char * add = pass == 0 ? p.role_int : p.role_expr;
        std::string & out = pass == 0 ? by_int : by_expr;
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_access_principal_add_role(env.catalog, who.data(), who.size(),
                add, strlen(add)));
        GDEFCORE_Request * r = env.Req(who);
        for (const std::string & e : ents) {
          out += env.Read(r, e, "title") + ";" + env.Read(r, e, "group") + ";";
        }
        out += env.List(r) + ";";
        {
          GDEFCORE_Access_List q;
          char ** ids = NULL;
          size_t count = 0;
          memset(&q, 0, sizeof q);
          q.size = sizeof q;
          q.type_name = kBlog;
          q.type_name_len = strlen(kBlog);
          q.lang = "en";
          q.lang_len = 2;
          q.filter_field = "group";
          q.filter_field_len = 5;
          q.filter_text = "g";
          q.filter_text_len = 1;
          GDEFCORE_Result rc = gdefcore_access_list(env.catalog, r, &q, &ids, &count);
          out += std::string(gdefcore_result_string(rc)) + std::to_string(count) + ";";
          gdefcore_access_free(env.catalog, ids, count);
        }
        out += std::to_string(env.Permits(r, pass == 0 ? "core.act" : "core.act2")) +
               ";";
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_access_principal_remove_role(env.catalog, who.data(),
                who.size(), add, strlen(add)));
      }
      std::string left = by_int;
      std::string right = by_expr;
      EXPECT_EQ(left, right) << p.role_int << " / " << p.role_expr << " as "
                              << (who == alice ? "alice" : "bob");
      checked += 1;
      if (by_int.find("No error|1|") != std::string::npos) {
        nonempty += 1;
      }
    }
  }
  EXPECT_EQ(pairs.size() * 2, checked);
  /* Control: the comparison is not empty. */
  EXPECT_GE(nonempty, 6u);
  /* And what own means, spelled out: bob sees only his own entity. */
  {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_principal_add_role(env.catalog, bob.data(), bob.size(),
            "x-own", 5));
    EXPECT_EQ("bob1", env.List(env.Req(bob)));
    EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(bob), e3, "title"));
    EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(""), e3, "title"));
  }
}

TEST(CondAccess, OwnExpressionNeedsAnActor) {
  /* The anonymous state granted an own expression sees nothing: an entity with
   * no actor is nobody's own, and a request with no principal is nobody. */
  AEnv env;
  char * own = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_condition_builtin(GDEFCORE_CONDITION_BUILTIN_OWN, kBlog,
          strlen(kBlog), &own, &n));
  std::string text(own, n);
  gdefcore_condition_text_free(own);
  std::string alice = env.Principal();
  std::string mine = env.Make(kBlog, alice, V({{"title", "mine"}}));
  std::string orphan = env.Make(kBlog, "", V({{"title", "orphan"}}));
  env.DeclareOk("Read own", "read", 0, text.c_str());
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_grant(env.catalog, "anonymous", 9, "Read own", 8,
          GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
          strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS)));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_grant(env.catalog, "authenticated", 13, "Read own", 8,
          GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
          strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED)));
  EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(""), orphan, "title"));
  EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(""), mine, "title"));
  EXPECT_EQ("", env.List(env.Req("")));
  EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(alice), orphan, "title"));
  /* Control: the same grant lets the author read their own. */
  EXPECT_EQ("No error|1|mine", env.Read(env.Req(alice), mine, "title"));
  EXPECT_EQ("mine", env.List(env.Req(alice)));
}

TEST(CondAccess, FieldGrantWithAnExpression) {
  /* A field only a condition lets you name: filter and sort by it, and read
   * it, only where the expression holds. */
  AEnv env;
  std::string a = env.Make(kBlog, "", V({{"title", "ta"}, {"group", "a"}, {"rank", "1"}}));
  std::string b = env.Make(kBlog, "", V({{"title", "tb"}, {"group", "b"}, {"rank", "2"}}));
  env.DeclareOk("Read all", "read", GDEFCORE_ACCESS_ANY, NULL);
  env.DeclareOk("Read rank of a", "read", 0, "(= field.group \"a\")", kBlog, "rank");
  env.Role("viewer");
  env.Role("ranker");
  env.Grant("viewer", "Read all");
  env.Grant("ranker", "Read all");
  env.Grant("ranker", "Read rank of a");
  std::string pv = env.Principal("viewer");
  std::string pr = env.Principal("ranker");
  /* The field is restricted, so without a grant it is absent. */
  EXPECT_EQ("No error|0|", env.Read(env.Req(pv), a, "rank"));
  EXPECT_EQ("No error|1|1", env.Read(env.Req(pr), a, "rank"));
  EXPECT_EQ("No error|0|", env.Read(env.Req(pr), b, "rank"));
  EXPECT_EQ("No error|1|ta", env.Read(env.Req(pr), a, "title"));
}

TEST(CondAccess, PermitsFollowsTheExpression) {
  AEnv env;
  env.DeclareOk("Edit group a", "demo.edit.a", 0, "(= field.group \"a\")");
  env.DeclareOk("Edit any blog", "demo.edit.any", 0, "(= type \"t.blog\")");
  env.DeclareOk("Edit empty", "demo.edit.never", 0, "false");
  env.DeclareOk("Edit int", "demo.edit.int", GDEFCORE_ACCESS_ANY, NULL);
  env.Role("r");
  env.Grant("r", "Edit group a");
  env.Grant("r", "Edit any blog");
  env.Grant("r", "Edit empty");
  env.Grant("r", "Edit int");
  std::string p = env.Principal("r");
  /* No blog yet: the type-only expression could apply to one; a field one
   * has nothing to be true of; false never holds; the int is as it was. */
  EXPECT_EQ(0, env.Permits(env.Req(p), "demo.edit.a"));
  EXPECT_EQ(1, env.Permits(env.Req(p), "demo.edit.any"));
  EXPECT_EQ(0, env.Permits(env.Req(p), "demo.edit.never"));
  EXPECT_EQ(1, env.Permits(env.Req(p), "demo.edit.int"));
  env.Make(kBlog, "", V({{"title", "T"}, {"group", "b"}}));
  EXPECT_EQ(0, env.Permits(env.Req(p), "demo.edit.a"));
  std::string a = env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
  EXPECT_EQ(1, env.Permits(env.Req(p), "demo.edit.a"));
  EXPECT_EQ(0, env.Permits(env.Req(p), "demo.edit.never"));
  /* A principal without the role holds none of them, and nobody is held to
   * a name nobody declared. */
  EXPECT_EQ(0, env.Permits(env.Req(env.Principal()), "demo.edit.a"));
  EXPECT_EQ(0, env.Permits(env.Req(p), "demo.edit.nope"));
}

/* A grant stored before edition 2 says `actor`. It still means what it read:
 * who wrote the revision readers see, which is now `revision.creator`. A grant
 * written in edition 2 as `creator` is the entity's, and an editor who saves
 * someone's entity does not become its creator. */
TEST(CondAccess, AStoredEditionOneGrantStillMeansWhatItMeant) {
  AEnv env;
  env.DeclareOk("Edit what I wrote last", "update", 0,
      "(= revision.creator principal)");
  env.DeclareOk("Edit what I created", "update", 0, "(= creator principal)");
  env.DeclareOk("Edit by int own", "demo.own", GDEFCORE_ACCESS_OWN, NULL);
  env.Role("last");
  env.Role("created");
  env.Grant("last", "Edit what I wrote last");
  env.Grant("created", "Edit what I created");
  /* Rewrite the first permission's stored text as edition 1 wrote it. */
  {
    char ** ids = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_ids(env.catalog, "core.permission", 15, &ids, &n));
    bool done = false;
    for (size_t i = 0; i < n && !done; i++) {
      char ** vals = NULL;
      size_t * lens = NULL;
      size_t c = 0;
      if (gdefcore_entity_values(env.catalog, NULL, GDEFCORE_VIEW_PUBLISHED,
              ids[i], GDEFCORE_PUBLIC_ID_LEN, "en", 2, "label", 5, &vals, &lens,
              &c) != GDEFCORE_OK) {
        continue;
      }
      if (c > 0 && std::string(vals[0], lens[0]) == "Edit what I wrote last") {
        const char * text = "(and (= type \"t.blog\") (= actor principal))";
        size_t len = strlen(text);
        GDEFCORE_Value value;
        GDEFCORE_Changeset * cs = NULL;
        memset(&value, 0, sizeof value);
        value.size = sizeof value;
        value.field = "condition";
        value.field_len = 9;
        value.texts = &text;
        value.text_lens = &len;
        value.count = 1;
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_changeset_prepare(env.catalog, NULL, 0, &cs));
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_entity_save(cs, ids[i], GDEFCORE_PUBLIC_ID_LEN, "en", 2,
                &value, 1));
        ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.permission", 15));
        gdefcore_changeset_destroy(cs);
        done = true;
      }
      gdefcore_values_free(env.catalog, vals, lens, c);
    }
    gdefcore_ids_free(env.catalog, ids, n);
    ASSERT_TRUE(done);
  }
  std::string alice = env.Principal("last");
  std::string bob = env.Principal("last");
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(env.catalog, alice.data(), alice.size(),
          "created", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(env.catalog, bob.data(), bob.size(),
          "created", 7));
  /* alice creates it, bob edits it */
  std::string e = env.Make(kBlog, alice, V({{"title", "T"}}));
  Resave(env, e, bob, "title", "edited", false);
  auto Can = [&](const std::string & who) {
    int allowed = -1;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_can(env.catalog, env.Req(who), "update", 6, kBlog,
            strlen(kBlog), e.c_str(), &allowed));
    return allowed;
  };
  /* Both grants are held by both of them: update is asked once, and the
   * answer is the union. So take each grant alone. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_remove_role(env.catalog, alice.data(), alice.size(),
          "created", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_remove_role(env.catalog, bob.data(), bob.size(),
          "created", 7));
  EXPECT_EQ(0, Can(alice));   /* stored `actor` = revision.creator = bob */
  EXPECT_EQ(1, Can(bob));
  /* control: the same two people under the edition 2 grant on creator */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_remove_role(env.catalog, alice.data(), alice.size(),
          "last", 4));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_remove_role(env.catalog, bob.data(), bob.size(),
          "last", 4));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(env.catalog, alice.data(), alice.size(),
          "created", 7));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_access_principal_add_role(env.catalog, bob.data(), bob.size(),
          "created", 7));
  EXPECT_EQ(1, Can(alice));
  EXPECT_EQ(0, Can(bob));
}

TEST(CondAccess, RenderKeyNamesTheExpression) {
  /* The key carries the canonical expression, so two spellings of one
   * condition give one key, and a different condition gives another. Three
   * worlds run the same steps; only the spelling or the condition differs. */
  auto key_of = [](const char * text) {
    AEnv env;
    env.DeclareOk("Read a", "read", 0, text);
    env.Role("r");
    env.Grant("r", "Read a");
    std::string p = env.Principal("r");
    return env.Key(env.Req(p));
  };
  std::string base = key_of("(and (= type \"t.blog\") (= field.group \"a\"))");
  EXPECT_EQ(base, key_of("(and   (= field.group \"a\")\n (= type \"t.blog\"))"));
  EXPECT_EQ(base, key_of("(and (and (= field.group \"a\")) (= type \"t.blog\") "
                         "(= field.group \"a\"))"));
  EXPECT_NE(base, key_of("(and (= type \"t.blog\") (= field.group \"b\"))"));
  EXPECT_NE(base, key_of("(or (= type \"t.blog\") (= field.group \"a\"))"));
  EXPECT_NE(base, key_of("(= type \"t.blog\")"));
  /* A condition that reads the principal makes the key depend on who asks;
   * one that does not, does not. */
  {
    AEnv env;
    env.DeclareOk("Read mine", "read", 0, "(and (= type \"t.blog\") (= creator principal))");
    env.DeclareOk("Read a", "read", 0, "(= field.group \"a\")");
    env.Role("rm");
    env.Role("ra");
    env.Grant("rm", "Read mine");
    env.Grant("ra", "Read a");
    std::string m1 = env.Principal("rm");
    std::string m2 = env.Principal("rm");
    std::string a1 = env.Principal("ra");
    std::string a2 = env.Principal("ra");
    EXPECT_NE(env.Key(env.Req(m1)), env.Key(env.Req(m2)));
    EXPECT_EQ(env.Key(env.Req(a1)), env.Key(env.Req(a2)));
    EXPECT_EQ(env.Key(env.Req(m1)), env.Key(env.Req(m1)));
  }
}

TEST(CondAccess, FailureNeverGrants) {
  AEnv env;
  std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
  env.DeclareOk("Read a", "read", 0, "(= field.group \"a\")");
  env.DeclareOk("Read all", "read", GDEFCORE_ACCESS_ANY, NULL);
  env.Role("r");
  env.Role("control");
  env.Grant("r", "Read a");
  env.Grant("control", "Read all");
  std::string p = env.Principal("r");
  std::string pc = env.Principal("control");
  /* Control: the grant holds, and no failure is noted. */
  {
    GDEFCORE_Request * r = env.Req(p);
    EXPECT_EQ("No error|1|T", env.Read(r, e, "title"));
    EXPECT_EQ("<none>", Note(r));
  }
  /* The stored text is corrupted: unreadable, then naming a field that is
   * gone. A condition that cannot be decided has not granted, even one that
   * is a negation, and the request carries a note saying so. */
  const char * const bad[] = {"((", "(not (= field.nope \"x\"))", "(= field.ssn 1)",
      "garbage", "(related x)", "(not false)x"};
  for (const char * text : bad) {
    GDEFCORE_Request * r = env.Req(p);
    env.Corrupt("Read a", text);
    EXPECT_EQ("Invalid argument|untouched", env.Read(r, e, "title")) << text;
    EXPECT_EQ("1", Note(r)) << text;
    {
      size_t count = 9;
      GDEFCORE_Request * r2 = env.Req(p);
      EXPECT_EQ("", env.List(r2, kBlog, &count)) << text;
      EXPECT_EQ(0u, count) << text;
      EXPECT_EQ("1", Note(r2)) << text;
    }
    EXPECT_EQ(0, env.Permits(env.Req(p), "read")) << text;
    /* The principal who holds the integer grant is unaffected. */
    EXPECT_EQ("No error|1|T", env.Read(env.Req(pc), e, "title")) << text;
  }
  /* An allocation that fails at each point of a filtered read: the entity is
   * hidden from this principal (their condition is false), so no failure may
   * turn that into a read. */
  {
    env.Corrupt("Read a", "(= field.group \"nope\")");
    long total;
    long n;
    int saw_note = 0;
    env.fa.armed = true;
    env.fa.target = 0;
    env.fa.seen = 0;
    EXPECT_EQ("Invalid argument|untouched", env.Read(env.Req(p), e, "title"));
    total = env.fa.seen;
    ASSERT_GT(total, 10);
    for (n = 1; n <= total; n++) {
      GDEFCORE_Request * r = env.Req(p);
      std::string got;
      size_t count = 0;
      std::string listed;
      env.fa.armed = true;
      env.fa.target = n;
      env.fa.seen = 0;
      got = env.Read(r, e, "title");
      env.fa.seen = 0;
      listed = env.List(r, kBlog, &count);
      env.fa.armed = false;
      EXPECT_NE(0u, got.find("No error|1|")) << "read granted at allocation " << n;
      EXPECT_EQ(0u, count) << "list granted at allocation " << n;
      EXPECT_TRUE(listed.empty() || listed.compare(0, 3, "rc=") == 0)
          << listed << " at allocation " << n;
      if (Note(r) == "1") {
        saw_note = 1;
      }
    }
    EXPECT_EQ(1, saw_note) << "no allocation failure reached a condition";
    env.fa.armed = false;
    /* A lookup that fails must not be taken for "not seeded yet": the sweep
     * above failed the admin-role lookup at some point, and re-seeding on
     * top would have made a second admin role and a second admin. The three
     * seeded roles and the two this test made are all there are. */
    {
      char ** names = NULL;
      size_t count = 0;
      size_t admins = 0;
      size_t i;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_roles(env.catalog, &names, &count));
      for (i = 0; i < count; i++) {
        admins += strcmp(names[i], "admin") == 0;
      }
      EXPECT_EQ(5u, count);
      EXPECT_EQ(1u, admins);
      gdefcore_access_free(env.catalog, names, count);
    }
  }
}

TEST(CondAccess, HiddenEqualsMissing) {
  /* A principal whose only grant has a false condition gets, for an existing
   * entity, the very answers an id that was never created gets. */
  AEnv env;
  std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"group", "other"}}));
  const std::string never = FreshId();
  env.DeclareOk("Read a", "read", 0, "(= field.group \"a\")");
  env.Role("r");
  env.Grant("r", "Read a");
  std::string p = env.Principal("r");
  std::string seen = env.Make(kBlog, "", V({{"title", "S"}, {"group", "a"}}));
  EXPECT_EQ(env.Read(env.Req(p), never, "title"), env.Read(env.Req(p), e, "title"));
  EXPECT_EQ(env.Read(env.Req(p), never, "nope"), env.Read(env.Req(p), e, "nope"));
  EXPECT_EQ(env.Read(env.Req(p), never, "group"), env.Read(env.Req(p), e, "group"));
  /* Control: the entity the grant covers is readable, so the equality above
   * is not "everything is refused". */
  EXPECT_EQ("No error|1|S", env.Read(env.Req(p), seen, "title"));
  EXPECT_EQ("S", env.List(env.Req(p)));
}

/* ---------------------------------------------------------------------- */
/* The seeded sweep: random trees against a second evaluator, and hostile  */
/* bytes                                                                   */
/* ---------------------------------------------------------------------- */

namespace {

/** xorshift64*: the same stream on every machine. */
struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 1) {}
  uint64_t Next() {
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    return s * 2685821657736338717ull;
  }
  size_t Below(size_t n) { return n == 0 ? 0 : (size_t)(Next() % n); }
  bool Coin() { return (Next() >> 33) & 1; }
};

/** A tree the test builds, prints, and evaluates with its own interpreter. */
struct T {
  enum K { True, False, And, Or, Not, Cmp, In, Type, State, Actor, Principal, Now,
      Field, Text, Int } k = True;
  std::string s;              /* text, or the field name */
  int64_t n = 0;              /* integer */
  std::string op;             /* comparison operator */
  std::vector<T> kids;
};

/** The facts the reference interpreter knows: one fixed entity and request. */
struct Facts {
  std::string type = kBlog;
  std::string state = "published";
  std::string actor;          /* empty: none */
  std::string principal;      /* empty: none */
  int64_t now = 5000;
  std::map<std::string, std::vector<std::string> > fields;
};

bool ToInt(const std::string & s, int64_t * out) {
  size_t i = 0;
  int64_t v = 0;
  bool neg = false;
  if (!s.empty() && s[0] == '-') {
    neg = true;
    i = 1;
  }
  if (s.size() - i < 1 || s.size() - i > 18) {
    return false;
  }
  for (; i < s.size(); i++) {
    if (s[i] < '0' || s[i] > '9') {
      return false;
    }
    v = v * 10 + (s[i] - '0');
  }
  *out = neg ? -v : v;
  return true;
}

std::vector<std::string> Operand(const T & t, const Facts & f) {
  std::vector<std::string> out;
  switch (t.k) {
    case T::Type:
      out.push_back(f.type);
      break;
    case T::State:
      out.push_back(f.state);
      break;
    case T::Actor:
      if (!f.actor.empty()) {
        out.push_back(f.actor);
      }
      break;
    case T::Principal:
      if (!f.principal.empty()) {
        out.push_back(f.principal);
      }
      break;
    case T::Now:
      out.push_back(std::to_string(f.now));
      break;
    case T::Field: {
      std::map<std::string, std::vector<std::string> >::const_iterator it =
          f.fields.find(t.s);
      if (it == f.fields.end() || it->second.empty()) {
        out.push_back("");
      } else {
        out = it->second;
      }
      break;
    }
    case T::Text:
      out.push_back(t.s);
      break;
    case T::Int:
      out.push_back(std::to_string(t.n));
      break;
    default:
      break;
  }
  return out;
}

bool Ref(const T & t, const Facts & f) {
  size_t i;
  size_t j;
  switch (t.k) {
    case T::True:
      return true;
    case T::False:
      return false;
    case T::Not:
      return !Ref(t.kids[0], f);
    case T::And:
      for (i = 0; i < t.kids.size(); i++) {
        if (!Ref(t.kids[i], f)) {
          return false;
        }
      }
      return true;
    case T::Or:
      for (i = 0; i < t.kids.size(); i++) {
        if (Ref(t.kids[i], f)) {
          return true;
        }
      }
      return false;
    case T::Cmp: {
      std::vector<std::string> a = Operand(t.kids[0], f);
      std::vector<std::string> b = Operand(t.kids[1], f);
      bool eq = false;
      for (i = 0; i < a.size(); i++) {
        for (j = 0; j < b.size(); j++) {
          eq = eq || a[i] == b[j];
        }
      }
      if (t.op == "=") {
        return eq;
      }
      if (t.op == "!=") {
        return !eq;
      }
      for (i = 0; i < a.size(); i++) {
        int64_t x;
        if (!ToInt(a[i], &x)) {
          continue;
        }
        for (j = 0; j < b.size(); j++) {
          int64_t y;
          if (!ToInt(b[j], &y)) {
            continue;
          }
          if ((t.op == "<" && x < y) || (t.op == "<=" && x <= y) ||
              (t.op == ">" && x > y) || (t.op == ">=" && x >= y)) {
            return true;
          }
        }
      }
      return false;
    }
    case T::In: {
      std::vector<std::string> a = Operand(t.kids[0], f);
      for (i = 1; i < t.kids.size(); i++) {
        std::vector<std::string> m = Operand(t.kids[i], f);
        for (j = 0; j < a.size(); j++) {
          if (!m.empty() && a[j] == m[0]) {
            return true;
          }
        }
      }
      return false;
    }
    default:
      return false;
  }
}

const char * const kFields[] = {"title", "group", "rank", "embargo", "tags"};
const char * const kTexts[] = {"a", "x", "T", "published", "draft", "t.blog",
    "t.vault", "", "7", "1000", "abc", "x y", "q\"uote", "back\\slash",
    "line\nbreak", "caf\xC3\xA9"};

T GenOperand(Rng & r) {
  T t;
  switch (r.Below(9)) {
    case 0:
      t.k = T::Type;
      break;
    case 1:
      t.k = T::State;
      break;
    case 2:
      t.k = T::Actor;
      break;
    case 3:
      t.k = T::Principal;
      break;
    case 4:
      t.k = T::Now;
      break;
    case 5:
    case 6:
      t.k = T::Field;
      t.s = kFields[r.Below(5)];
      break;
    case 7:
      t.k = T::Text;
      t.s = kTexts[r.Below(sizeof kTexts / sizeof kTexts[0])];
      break;
    default:
      t.k = T::Int;
      t.n = (int64_t)r.Below(20) - 5;
      if (r.Below(4) == 0) {
        t.n = 5000 + (int64_t)r.Below(3) - 1;
      }
      break;
  }
  return t;
}

T GenConst(Rng & r) {
  T t;
  if (r.Coin()) {
    t.k = T::Text;
    t.s = kTexts[r.Below(sizeof kTexts / sizeof kTexts[0])];
  } else {
    t.k = T::Int;
    t.n = (int64_t)r.Below(12) - 2;
  }
  return t;
}

T GenBool(Rng & r, int depth, int * budget) {
  T t;
  size_t pick = r.Below(depth <= 0 || *budget <= 4 ? 4 : 9);
  *budget -= 1;
  switch (pick) {
    case 0:
      t.k = T::True;
      return t;
    case 1:
      t.k = T::False;
      return t;
    case 2:
    case 3: {
      static const char * const ops[] = {"=", "!=", "<", "<=", ">", ">="};
      t.k = T::Cmp;
      t.op = ops[r.Below(6)];
      t.kids.push_back(GenOperand(r));
      t.kids.push_back(GenOperand(r));
      *budget -= 2;
      return t;
    }
    case 4:
      t.k = T::In;
      t.kids.push_back(GenOperand(r));
      {
        size_t n = 1 + r.Below(4);
        size_t i;
        for (i = 0; i < n; i++) {
          t.kids.push_back(GenConst(r));
        }
        *budget -= (int)n + 1;
      }
      return t;
    case 5:
      t.k = T::Not;
      t.kids.push_back(GenBool(r, depth - 1, budget));
      return t;
    default: {
      size_t n = 1 + r.Below(4);
      size_t i;
      t.k = r.Coin() ? T::And : T::Or;
      for (i = 0; i < n; i++) {
        t.kids.push_back(GenBool(r, depth - 1, budget));
      }
      return t;
    }
  }
}

/** Print with random whitespace; a space only where tokens would fuse. */
void Print(const T & t, Rng & r, std::string * out, bool * last_atom) {
  static const char * const ws[] = {" ", "  ", "\n", "\t", " \r\n ", "   \t"};
  auto atom = [&](const std::string & a) {
    if (*last_atom) {
      *out += ws[r.Below(6)];
    }
    *out += a;
    *last_atom = true;
  };
  auto punct = [&](const char * p) {
    if (r.Below(3) == 0) {
      *out += ws[r.Below(6)];
    }
    *out += p;
    *last_atom = false;
  };
  auto quoted = [&](const std::string & s) {
    std::string q = "\"";
    size_t i;
    for (i = 0; i < s.size(); i++) {
      if (s[i] == '"') {
        q += "\\\"";
      } else if (s[i] == '\\') {
        q += "\\\\";
      } else if (s[i] == '\n') {
        q += "\\n";
      } else {
        q += s[i];
      }
    }
    q += "\"";
    if (r.Below(3) == 0) {
      *out += ws[r.Below(6)];
    }
    *out += q;
    *last_atom = false;
  };
  auto operand = [&](const T & o) {
    switch (o.k) {
      case T::Type:
        atom("type");
        break;
      case T::State:
        atom("state");
        break;
      case T::Actor:
        atom("creator");
        break;
      case T::Principal:
        atom("principal");
        break;
      case T::Now:
        atom("now");
        break;
      case T::Field:
        atom("field." + o.s);
        break;
      case T::Text:
        quoted(o.s);
        break;
      default: {
        std::string digits = std::to_string(o.n < 0 ? -o.n : o.n);
        if (r.Below(3) == 0) {
          digits = "00" + digits;
        }
        atom((o.n < 0 ? "-" : "") + digits);
        break;
      }
    }
  };
  size_t i;
  switch (t.k) {
    case T::True:
      atom("true");
      break;
    case T::False:
      atom("false");
      break;
    case T::Not:
      punct("(");
      atom("not");
      Print(t.kids[0], r, out, last_atom);
      punct(")");
      break;
    case T::And:
    case T::Or:
      punct("(");
      atom(t.k == T::And ? "and" : "or");
      for (i = 0; i < t.kids.size(); i++) {
        Print(t.kids[i], r, out, last_atom);
      }
      punct(")");
      break;
    case T::Cmp:
      punct("(");
      atom(t.op);
      operand(t.kids[0]);
      operand(t.kids[1]);
      punct(")");
      break;
    case T::In:
      punct("(");
      atom("in");
      operand(t.kids[0]);
      punct("(");
      for (i = 1; i < t.kids.size(); i++) {
        operand(t.kids[i]);
      }
      punct(")");
      punct(")");
      break;
    default:
      break;
  }
}

}  // namespace

TEST(CondSweep, RandomTreesAgreeWithAnIndependentEvaluator) {
  Env env;
  const std::string alice = FreshId();
  std::string e = env.Make(kBlog, alice,
      {{"title", {"T"}}, {"group", {"a"}}, {"rank", {"7"}}, {"tags", {"x", "y"}}});
  Facts f;
  Rng r(0x5eed1234abcdULL);
  int trues = 0;
  int falses = 0;
  int too_big = 0;
  int round;
  f.actor = alice;
  f.principal = alice;
  f.fields["title"] = {"T"};
  f.fields["group"] = {"a"};
  f.fields["rank"] = {"7"};
  f.fields["tags"] = {"x", "y"};
  GDEFCORE_Request * req = env.Req(alice, 5000);
  auto t0 = std::chrono::steady_clock::now();
  for (round = 0; round < 4000; round++) {
    int budget = 20 + (int)r.Below(40);
    T t = GenBool(r, 5, &budget);
    std::string text;
    bool last = false;
    bool want = Ref(t, f);
    Print(t, r, &text, &last);
    std::string canon = Canon(text);
    if (canon.find("more than 256 nodes") != std::string::npos) {
      too_big += 1;
      continue;
    }
    ASSERT_EQ(std::string::npos, canon.find("<refused")) << text << " -> " << canon;
    /* Canonical text is stable and keeps the meaning. */
    ASSERT_EQ(canon, Canon(canon)) << text;
    ASSERT_EQ(Hash(text), Hash(canon)) << text;
    ASSERT_LE(canon.size(), (size_t)GDEFCORE_CONDITION_MAX_BYTES) << text;
    {
      Answer a = Eval(env, text, e, req);
      Answer b = Eval(env, canon, e, req);
      ASSERT_EQ(want ? 1 : 0, a.allow) << text;
      ASSERT_EQ(0, a.failed) << text;
      ASSERT_EQ(a, b) << text << " / " << canon;
    }
    want ? trues++ : falses++;
    /* Reordering and/or operands is not a different expression. */
    if (t.k == T::And || t.k == T::Or) {
      T u = t;
      size_t i;
      for (i = u.kids.size(); i > 1; i--) {
        std::swap(u.kids[i - 1], u.kids[r.Below(i)]);
      }
      std::string text2;
      bool last2 = false;
      Print(u, r, &text2, &last2);
      ASSERT_EQ(canon, Canon(text2)) << text << " vs " << text2;
    }
  }
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0).count();
  /* The control: the sweep saw both answers, plenty of each. */
  EXPECT_GT(trues, 400);
  EXPECT_GT(falses, 400);
  EXPECT_LT(too_big, 200) << "most generated trees must fit the node limit";
  EXPECT_LT(ms, 60000) << "4000 trees took " << ms << " ms";
}

TEST(CondSweep, HostileBytesNeverCrashAndStayBounded) {
  Env env;
  std::string e = env.Make(kBlog, "", V({{"title", "T"}, {"group", "a"}}));
  Rng r(0xbadc0ffee0ddf00dULL);
  static const char * const pieces[] = {"(", ")", "(and ", "(or ", "(not ",
      "(= ", "(!= ", "(< ", "(in ", " ", "\n", "\"", "\\", "\"a\"", "type",
      "state", "actor", "creator", "revision.creator", "principal", "now", "field.group", "field.", "true",
      "false", "0", "-", "12", "related", "\xC3\xA9", "\xFF", "\x01", "\x7f",
      "\"\\\"", "(in type (", "))", "((((((((((((((((((", "1234567890123456789"};
  const size_t npieces = sizeof pieces / sizeof pieces[0];
  size_t accepted = 0;
  size_t refused = 0;
  size_t i;
  auto t0 = std::chrono::steady_clock::now();
  double worst_us = 0;
  for (i = 0; i < 20000; i++) {
    std::string s;
    size_t mode = r.Below(4);
    size_t n = r.Below(mode == 3 ? 700 : 120);
    size_t k;
    if (mode == 0) {
      for (k = 0; k < n; k++) {
        s += (char)r.Below(256);
      }
    } else if (mode == 1 || mode == 3) {
      for (k = 0; k < n; k++) {
        s += pieces[r.Below(npieces)];
      }
    } else {
      /* A valid tree with a byte flipped, dropped or inserted. */
      int budget = 30 + (int)r.Below(40);
      T t = GenBool(r, 4, &budget);
      bool last = false;
      Print(t, r, &s, &last);
      for (k = 0; k < 1 + r.Below(3) && !s.empty(); k++) {
        size_t at = r.Below(s.size());
        switch (r.Below(3)) {
          case 0:
            s[at] = (char)r.Below(256);
            break;
          case 1:
            s.erase(at, 1);
            break;
          default:
            s.insert(at, 1, (char)r.Below(256));
            break;
        }
      }
    }
    auto a0 = std::chrono::steady_clock::now();
    GDEFCORE_Condition * c = NULL;
    GDEFCORE_Condition_Error err;
    memset(&err, 0, sizeof err);
    err.size = sizeof err;
    GDEFCORE_Result rc = gdefcore_condition_parse(s.data(), s.size(), &c, &err);
    if (rc != GDEFCORE_OK) {
      refused += 1;
      ASSERT_EQ(GDEFCORE_ERR_INVALID, rc);
      ASSERT_TRUE(c == NULL);
      ASSERT_TRUE(err.message != NULL);
      ASSERT_LE(err.offset, s.size() > 4096 ? 4096 : s.size());
    } else {
      char * canon = NULL;
      size_t cn = 0;
      accepted += 1;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_canonical(c, &canon, &cn));
      ASSERT_LE(cn, (size_t)GDEFCORE_CONDITION_MAX_BYTES);
      /* Stable, and re-parseable within the same limits. */
      ASSERT_EQ(std::string(canon, cn), Canon(std::string(canon, cn))) << s;
      /* Evaluating whatever was accepted is bounded and answers 0 or 1;
       * a failure (an unknown field) is a flag and a 0. */
      {
        GDEFCORE_Condition_Subject subject;
        int failed = 5;
        int allow;
        memset(&subject, 0, sizeof subject);
        subject.size = sizeof subject;
        subject.entity = e.data();
        subject.entity_len = e.size();
        allow = gdefcore_condition_eval(env.catalog, env.req, c, &subject, &failed);
        ASSERT_TRUE(allow == 0 || allow == 1);
        ASSERT_TRUE(failed == 0 || failed == 1);
        ASSERT_TRUE(failed == 0 || allow == 0);
      }
      {
        char * ex = NULL;
        size_t en = 0;
        ASSERT_EQ(GDEFCORE_OK, gdefcore_condition_explain(c, &ex, &en));
        ASSERT_EQ(en, strlen(ex));
        gdefcore_condition_text_free(ex);
      }
      gdefcore_condition_text_free(canon);
      gdefcore_condition_free(c);
    }
    {
      double us = std::chrono::duration<double, std::micro>(
          std::chrono::steady_clock::now() - a0).count();
      if (us > worst_us) {
        worst_us = us;
      }
    }
  }
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0).count();
  /* The control: both outcomes happened a lot, so the sweep is not blind. */
  EXPECT_GT(accepted, 200u);
  EXPECT_GT(refused, 5000u);
  EXPECT_LT(ms, 60000);
  EXPECT_LT(worst_us, 2.0e6) << "one input took " << worst_us << " us";
}

TEST(CondSweep, BoundaryValuesAreExact) {
  /* Each limit, one under, at, and one over, in every combination of shape
   * that reaches it. */
  struct Row {
    std::string text;
    bool ok;
  };
  std::vector<Row> rows;
  int d;
  for (d = 14; d <= 18; d++) {
    rows.push_back({Nest(d), d <= 16});
  }
  for (d = 254; d <= 258; d++) {
    rows.push_back({Wide(d), d <= 256});
  }
  for (d = 4094; d <= 4098; d++) {
    rows.push_back({Wide(20, (size_t)d), d <= 4096});
  }
  for (d = 254; d <= 258; d++) {
    rows.push_back({"(= type \"" + std::string((size_t)d, 'z') + "\")", d <= 256});
  }
  /* A wide tree that is also deep, at the corner of both. */
  {
    std::string s = "true";
    int i;
    for (i = 0; i < 16; i++) {
      s = "(and " + s + " false)";
    }
    rows.push_back({s, true});            /* 16 levels */
    rows.push_back({"(not " + s + ")", false});
  }
  for (const Row & row : rows) {
    std::string c = Canon(row.text);
    EXPECT_EQ(row.ok, c.find("<refused") == std::string::npos)
        << "input of " << row.text.size() << " bytes: " << c.substr(0, 90);
    if (row.ok) {
      EXPECT_EQ(c, Canon(c));
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
