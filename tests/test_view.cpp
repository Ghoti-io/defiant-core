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
 * Views as data (view.h): a
 * stored list with a condition tree, arguments, columns and formatters, run
 * through the access filter. Run by tools/check-view.sh, which plants a defect
 * for each rule named here.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-core/view.h>

#include <gtest/gtest.h>

#include "grants_fixture.h"
#include "size_structs.h"

#include <string.h>

#include <string>
#include <vector>

using namespace gfx;

namespace {

const char kItem[] = "site.item";

class Views : public GrantsFixture {
 protected:
  std::string admin_;

  /* An item type with a field of every kind a view may show or filter by. */
  void DefineItem() {
    GDEFCORE_Field f[12];
    memset(f, 0, sizeof f);
    const char * names[12] = {"title", "kind", "qty", "done", "due", "tags", "who",
        "secret", "note", "price", "at", "ratio"};
    for (int i = 0; i < 12; i++) {
      f[i] = Field(names[i]);
    }
    f[2].type = GDEFSTOR_FIELD_INTEGER;
    f[3].type = GDEFSTOR_FIELD_BOOLEAN;
    f[4].type = GDEFSTOR_FIELD_DATE;
    f[5].many = 1;
    f[6].type = GDEFSTOR_FIELD_REFERENCE;
    f[7].personal = 1;
    f[7].subject = "who";
    f[7].subject_len = 3;
    f[9].type = GDEFSTOR_FIELD_DECIMAL;
    f[9].scale = 2;
    f[10].type = GDEFSTOR_FIELD_DATETIME;
    f[11].type = GDEFSTOR_FIELD_FLOAT;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kItem, strlen(kItem),
        GDEFCORE_TYPE_CONTENT, f, 12));
    Declare(Perm("Read items", "read", GDEFCORE_ACCESS_ANY, kItem));
    Declare(Perm("Read item notes", "read", GDEFCORE_ACCESS_ANY, kItem, "note"));
    admin_ = Admin();
  }

  std::string Item(const std::string & actor, const char * title, const char * kind,
      const char * qty, const char * done, const char * due,
      std::vector<std::string> tags = {}, const char * note = NULL) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    std::vector<GDEFCORE_Value> values;
    std::vector<std::vector<const char *>> texts;
    std::vector<std::vector<size_t>> lens;
    auto add = [&](const char * field, std::vector<std::string> v) {
      static std::vector<std::string> keep;
      texts.emplace_back();
      lens.emplace_back();
      for (const std::string & s : v) {
        keep.push_back(s);
      }
      /* the strings must outlive the call: copy into a stable store */
      for (size_t i = 0; i < v.size(); i++) {
        keep.push_back(v[i]);
      }
      (void)field;
    };
    (void)add;
    struct One {
      const char * field;
      std::vector<std::string> v;
    };
    std::vector<One> ones;
    ones.push_back({"title", {title}});
    ones.push_back({"kind", {kind}});
    ones.push_back({"qty", {qty}});
    ones.push_back({"done", {done}});
    ones.push_back({"due", {due}});
    if (!tags.empty()) {
      ones.push_back({"tags", tags});
    }
    if (note != NULL) {
      ones.push_back({"note", {note}});
    }
    std::vector<std::vector<const char *>> t(ones.size());
    std::vector<std::vector<size_t>> l(ones.size());
    values.resize(ones.size());
    for (size_t i = 0; i < ones.size(); i++) {
      for (const std::string & s : ones[i].v) {
        t[i].push_back(s.c_str());
        l[i].push_back(s.size());
      }
      memset(&values[i], 0, sizeof values[i]);
      values[i].size = sizeof values[i];
      values[i].field = ones[i].field;
      values[i].field_len = strlen(ones[i].field);
      values[i].texts = t[i].data();
      values[i].text_lens = l[i].data();
      values[i].count = t[i].size();
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kItem, strlen(kItem), id, NULL));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_,
        actor.empty() ? NULL : actor.data(), actor.size(), &cs));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, strlen(id), "en", 2,
        values.data(), values.size()));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  /* A view definition built from text, the strings kept alive by the test. */
  struct Spec {
    std::string name = "items";
    std::string type = kItem;
    std::string condition;
    std::string sort;
    bool sort_desc = false;
    std::string sort2;
    bool sort2_desc = false;
    struct Col {
      std::string field, formatter, label;
    };
    std::vector<Col> columns = {{"title", "", ""}};
    struct Arg {
      std::string name;
      int source;
      std::string fixed;
    };
    std::vector<Arg> args;
    int format = GDEFCORE_VIEW_FORMAT_TABLE;
    uint64_t limit = 50;
  };

  GDEFCORE_Result Build(const Spec & s, std::string * why, bool apply,
      GDEFCORE_Changeset ** keep = NULL) {
    std::vector<GDEFCORE_View_Column> cols(s.columns.size());
    for (size_t i = 0; i < cols.size(); i++) {
      memset(&cols[i], 0, sizeof cols[i]);
      cols[i].size = sizeof cols[i];
      cols[i].field = s.columns[i].field.c_str();
      cols[i].field_len = s.columns[i].field.size();
      cols[i].formatter = s.columns[i].formatter.c_str();
      cols[i].formatter_len = s.columns[i].formatter.size();
      cols[i].label = s.columns[i].label.c_str();
      cols[i].label_len = s.columns[i].label.size();
    }
    std::vector<GDEFCORE_View_Arg> args(s.args.size());
    for (size_t i = 0; i < args.size(); i++) {
      memset(&args[i], 0, sizeof args[i]);
      args[i].size = sizeof args[i];
      args[i].name = s.args[i].name.c_str();
      args[i].name_len = s.args[i].name.size();
      args[i].source = s.args[i].source;
      args[i].fixed = s.args[i].fixed.c_str();
      args[i].fixed_len = s.args[i].fixed.size();
    }
    GDEFCORE_View_Def d;
    memset(&d, 0, sizeof d);
    d.size = sizeof d;
    d.name = s.name.c_str();
    d.name_len = s.name.size();
    d.type = s.type.c_str();
    d.type_len = s.type.size();
    d.condition = s.condition.c_str();
    d.condition_len = s.condition.size();
    d.sort = s.sort.c_str();
    d.sort_len = s.sort.size();
    d.sort_descending = s.sort_desc;
    d.sort2 = s.sort2.c_str();
    d.sort2_len = s.sort2.size();
    d.sort2_descending = s.sort2_desc;
    d.columns = cols.data();
    d.column_count = cols.size();
    d.args = args.empty() ? NULL : args.data();
    d.arg_count = args.size();
    d.format = s.format;
    d.limit = s.limit;
    char buf[256];
    GDEFCORE_Result rc = gdefcore_view_validate(catalog_, &d, buf, sizeof buf);
    if (why != NULL) {
      *why = buf;
    }
    if (!apply) {
      return rc;
    }
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
    rc = gdefcore_view_stage(cs, &d);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, GDEFCORE_VIEW_TYPE, strlen(GDEFCORE_VIEW_TYPE));
    } else if (why != NULL) {
      size_t n = 0;
      const char * r = gdefcore_changeset_refusal(cs, &n);
      *why = r == NULL ? "" : std::string(r, n);
    }
    if (keep != NULL) {
      *keep = cs;
    } else {
      gdefcore_changeset_destroy(cs);
    }
    return rc;
  }

  void Save(const Spec & s) {
    std::string why;
    ASSERT_EQ(GDEFCORE_OK, Build(s, &why, true)) << why;
  }

  struct Out {
    GDEFCORE_Result rc = GDEFCORE_OK;
    std::vector<std::string> labels;
    std::vector<std::vector<std::string>> cells;
    std::vector<std::string> ids;
    uint64_t total = 0;
    std::string text;
  };

  Out Run(const std::string & who, const char * name,
      std::vector<std::pair<std::string, std::string>> params = {}, uint64_t offset = 0) {
    Out out;
    std::vector<GDEFCORE_View_Param> ps(params.size());
    for (size_t i = 0; i < params.size(); i++) {
      memset(&ps[i], 0, sizeof ps[i]);
      ps[i].size = sizeof ps[i];
      ps[i].name = params[i].first.c_str();
      ps[i].name_len = params[i].first.size();
      ps[i].value = params[i].second.c_str();
      ps[i].value_len = params[i].second.size();
    }
    GDEFCORE_View_Result * r = NULL;
    out.rc = gdefcore_view_run(catalog_, Req(who), name, strlen(name), ps.data(), ps.size(),
        offset, &r);
    if (out.rc != GDEFCORE_OK) {
      return out;
    }
    out.total = gdefcore_view_result_total(r);
    for (size_t c = 0; c < gdefcore_view_result_columns(r); c++) {
      size_t n = 0;
      const char * l = gdefcore_view_result_label(r, c, &n);
      out.labels.push_back(std::string(l, n));
    }
    for (size_t row = 0; row < gdefcore_view_result_rows(r); row++) {
      out.ids.push_back(gdefcore_view_result_id(r, row));
      std::vector<std::string> line;
      for (size_t c = 0; c < gdefcore_view_result_columns(r); c++) {
        size_t n = 0;
        const char * v = gdefcore_view_result_cell(r, row, c, &n);
        line.push_back(std::string(v, n));
      }
      out.cells.push_back(line);
    }
    int f = gdefcore_view_result_format(r);
    if (f == GDEFCORE_VIEW_FORMAT_CSV || f == GDEFCORE_VIEW_FORMAT_JSON) {
      char * t = NULL;
      size_t n = 0;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_view_result_text(catalog_, r, &t, &n));
      if (t != NULL) {
        out.text.assign(t, n);
        gdefcore_text_free(catalog_, t);
      }
    } else {
      char * t = NULL;
      size_t n = 0;
      EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_view_result_text(catalog_, r, &t, &n));
    }
    gdefcore_view_result_free(r);
    return out;
  }

  std::vector<std::string> Col0(const Out & o) {
    std::vector<std::string> v;
    for (const auto & row : o.cells) {
      v.push_back(row[0]);
    }
    return v;
  }

  std::string Reader() {
    Role("reader");
    Grant("reader", "Read items");
    return Principal("reader");
  }
};

}  // namespace

/* ---- the stored form ------------------------------------------------------------ */

TEST_F(Views, AViewIsStoredReadBackAndReplacedByItsName) {
  DefineItem();
  Spec s;
  s.condition = "(and (= field.kind $kind) (or (>= field.qty $min) (= field.done \"true\")))";
  s.sort = "qty";
  s.sort_desc = true;
  s.sort2 = "title";
  s.columns = {{"title", "upper", "Name"}, {"qty", "", ""}, {"tags", "join", "Tags"}};
  s.args = {{"kind", GDEFCORE_VIEW_SOURCE_URL, ""}, {"min", GDEFCORE_VIEW_SOURCE_EXPOSED, "1"}};
  s.format = GDEFCORE_VIEW_FORMAT_LIST;
  s.limit = 7;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_view_declare(catalog_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_view_declare(catalog_)) << "declaring twice is fine";
  Save(s);
  GDEFCORE_View_Def d;
  void * owner = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_view_get(catalog_, "items", 5, &d, &owner));
  EXPECT_EQ(s.condition, std::string(d.condition, d.condition_len));
  EXPECT_EQ("qty", std::string(d.sort, d.sort_len));
  EXPECT_TRUE(d.sort_descending);
  EXPECT_EQ("title", std::string(d.sort2, d.sort2_len));
  EXPECT_FALSE(d.sort2_descending);
  ASSERT_EQ(3u, d.column_count);
  EXPECT_EQ("upper", std::string(d.columns[0].formatter, d.columns[0].formatter_len));
  EXPECT_EQ("Name", std::string(d.columns[0].label, d.columns[0].label_len));
  EXPECT_EQ("raw", std::string(d.columns[1].formatter, d.columns[1].formatter_len));
  ASSERT_EQ(2u, d.arg_count);
  EXPECT_EQ(GDEFCORE_VIEW_SOURCE_EXPOSED, d.args[1].source);
  EXPECT_EQ("1", std::string(d.args[1].fixed, d.args[1].fixed_len));
  EXPECT_EQ(GDEFCORE_VIEW_FORMAT_LIST, d.format);
  EXPECT_EQ(7u, d.limit);
  gdefcore_view_def_free(catalog_, owner);
  /* The same name again is the next revision of the one view, not a second. */
  s.limit = 9;
  Save(s);
  char ** names = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_view_names(catalog_, &names, &n));
  ASSERT_EQ(1u, n);
  EXPECT_EQ("items", std::string(names[0]));
  gdefcore_view_names_free(catalog_, names, n);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_view_get(catalog_, "items", 5, &d, &owner));
  EXPECT_EQ(9u, d.limit);
  gdefcore_view_def_free(catalog_, owner);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_view_get(catalog_, "nope", 4, &d, &owner));
}

TEST_F(Views, ASaveNeedsTheTypedConfirmationOfAConfigurationChange) {
  DefineItem();
  Spec s;
  std::string why;
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, Build(s, &why, false));
  /* Build(apply) confirms; here the apply is tried without it. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_view_declare(catalog_));
  GDEFCORE_View_Column c;
  memset(&c, 0, sizeof c);
  c.size = sizeof c;
  c.field = "title";
  c.field_len = 5;
  GDEFCORE_View_Def d;
  memset(&d, 0, sizeof d);
  d.size = sizeof d;
  d.name = "plain";
  d.name_len = 5;
  d.type = kItem;
  d.type_len = strlen(kItem);
  d.columns = &c;
  d.column_count = 1;
  d.format = GDEFCORE_VIEW_FORMAT_TABLE;
  d.limit = 10;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_view_stage(cs, &d));
  EXPECT_NE(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, GDEFCORE_VIEW_TYPE, strlen(GDEFCORE_VIEW_TYPE)));
  gdefcore_changeset_destroy(cs);
}

/* ---- refusals at save ----------------------------------------------------------- */

TEST_F(Views, ASaveIsRefusedWithTheReasonForEveryWayAViewCanBeWrong) {
  DefineItem();
  struct Case {
    const char * what;
    void (*edit)(Spec *);
    const char * reason;
  };
  const Case cases[] = {
      {"a name with a capital", [](Spec * s) { s->name = "Items"; }, "name"},
      {"no name", [](Spec * s) { s->name = ""; }, "name"},
      {"an unknown type", [](Spec * s) { s->type = "site.none"; }, "no type"},
      {"no columns", [](Spec * s) { s->columns.clear(); }, "columns"},
      {"an unknown column", [](Spec * s) { s->columns = {{"nope", "", ""}}; }, "nope"},
      {"a personal column", [](Spec * s) { s->columns = {{"secret", "", ""}}; }, "personal"},
      {"a formatter for another kind", [](Spec * s) { s->columns = {{"title", "yesno", ""}}; }, "formatter"},
      {"raw on a many field", [](Spec * s) { s->columns = {{"tags", "raw", ""}}; }, "formatter"},
      {"join on a single field", [](Spec * s) { s->columns = {{"title", "join", ""}}; }, "formatter"},
      {"truncate with no number", [](Spec * s) { s->columns = {{"title", "truncate-", ""}}; }, "formatter"},
      {"truncate with zero", [](Spec * s) { s->columns = {{"title", "truncate-0", ""}}; }, "formatter"},
      {"an unknown formatter", [](Spec * s) { s->columns = {{"title", "shout", ""}}; }, "formatter"},
      {"two columns with one heading", [](Spec * s) { s->columns = {{"title", "", ""}, {"title", "upper", ""}}; }, "headed"},
      {"a personal sort", [](Spec * s) { s->sort = "secret"; }, "personal"},
      {"a many sort", [](Spec * s) { s->sort = "tags"; }, "many"},
      {"an unknown sort", [](Spec * s) { s->sort = "nope"; }, "nope"},
      {"a second sort alone", [](Spec * s) { s->sort2 = "title"; }, "second"},
      {"a limit of zero", [](Spec * s) { s->limit = 0; }, "page size"},
      {"a limit over the most", [](Spec * s) { s->limit = 201; }, "page size"},
      {"a format that is not one", [](Spec * s) { s->format = 9; }, "format"},
      {"a condition that does not parse", [](Spec * s) { s->condition = "(= field.title"; }, "condition"},
      {"a condition on an unknown field", [](Spec * s) { s->condition = "(= field.nope \"x\")"; }, "condition"},
      {"a condition on a personal field", [](Spec * s) { s->condition = "(= field.secret \"x\")"; }, "condition"},
      {"an ordering of a text field", [](Spec * s) { s->condition = "(< field.title \"m\")"; }, "condition"},
      {"an argument not declared", [](Spec * s) { s->condition = "(= field.title $who)"; }, "not declared"},
      {"an argument declared and not used", [](Spec * s) { s->args = {{"x", GDEFCORE_VIEW_SOURCE_URL, ""}}; }, "never uses"},
      {"a bare dollar", [](Spec * s) { s->condition = "(= field.title $)"; }, "names no argument"},
      {"a fixed argument with no value", [](Spec * s) {
         s->condition = "(= field.title $x)";
         s->args = {{"x", GDEFCORE_VIEW_SOURCE_FIXED, ""}};
       }, "no value"},
      {"two arguments of one name", [](Spec * s) {
         s->condition = "(= field.title $x)";
         s->args = {{"x", GDEFCORE_VIEW_SOURCE_URL, ""}, {"x", GDEFCORE_VIEW_SOURCE_URL, ""}};
       }, "twice"},
      {"an argument with no source", [](Spec * s) {
         s->condition = "(= field.title $x)";
         s->args = {{"x", 0, ""}};
       }, "source"},
  };
  for (const Case & c : cases) {
    Spec s;
    c.edit(&s);
    std::string why;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, Build(s, &why, false)) << c.what;
    EXPECT_NE(std::string::npos, why.find(c.reason)) << c.what << ": " << why;
    /* A refused view stages nothing and its reason is the changeset's. */
    std::string refusal;
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_ERR_INVALID, Build(s, &refusal, true, &cs)) << c.what;
    EXPECT_EQ(0u, gdefcore_changeset_touched_count(cs)) << c.what;
    EXPECT_NE(std::string::npos, refusal.find(c.reason)) << c.what << ": " << refusal;
    gdefcore_changeset_destroy(cs);
  }
  /* Too many columns. */
  Spec many;
  many.columns.clear();
  for (int i = 0; i < 17; i++) {
    many.columns.push_back({"title", "", "h" + std::to_string(i)});
  }
  std::string why;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Build(many, &why, false));
  /* The control: none of the above is the reason a good one is saved. */
  Spec good;
  EXPECT_EQ(GDEFCORE_OK, Build(good, &why, false)) << why;
}

TEST_F(Views, TheOperatorAndFormatterTablesAreWhatTheSaveAccepts) {
  DefineItem();
  const struct {
    const char * field;
    int type;
    int many;
    const char * constant;
  } kinds[] = {
      {"title", GDEFSTOR_FIELD_TEXT, 0, "\"a\""},
      {"qty", GDEFSTOR_FIELD_INTEGER, 0, "\"1\""},
      {"price", GDEFSTOR_FIELD_DECIMAL, 0, "\"1.50\""},
      {"ratio", GDEFSTOR_FIELD_FLOAT, 0, "\"1.5\""},
      {"done", GDEFSTOR_FIELD_BOOLEAN, 0, "\"true\""},
      {"due", GDEFSTOR_FIELD_DATE, 0, "\"2025-10-17\""},
      {"at", GDEFSTOR_FIELD_DATETIME, 0, "\"2025-10-09T08:53:20Z\""},
      {"who", GDEFSTOR_FIELD_REFERENCE, 0, "\"x\""},
  };
  const char * all_ops[] = {"=", "!=", "<", "<=", ">", ">=", "in"};
  for (const auto & k : kinds) {
    size_t n = 0;
    const char * const * ops = gdefcore_view_operators(k.type, &n);
    for (const char * op : all_ops) {
      bool listed = false;
      for (size_t i = 0; i < n; i++) {
        listed = listed || strcmp(ops[i], op) == 0;
      }
      Spec s;
      std::string cond = strcmp(op, "in") == 0
          ? std::string("(in field.") + k.field + " (" + k.constant + "))"
          : std::string("(") + op + " field." + k.field + " " + k.constant + ")";
      s.condition = cond;
      std::string why;
      EXPECT_EQ(listed ? GDEFCORE_OK : GDEFCORE_ERR_INVALID, Build(s, &why, false))
          << k.field << " " << op << ": " << why;
    }
    /* Formatters: each listed one is accepted, each unlisted one refused. */
    size_t fn = 0;
    const char * const * fs = gdefcore_view_formatters(k.type, k.many, &fn);
    const char * all_fs[] = {"raw", "upper", "lower", "truncate-5", "yesno", "date",
        "join", "count"};
    for (const char * f : all_fs) {
      bool listed = false;
      for (size_t i = 0; i < fn; i++) {
        listed = listed || strcmp(fs[i], f) == 0 ||
                 (strcmp(fs[i], "truncate-N") == 0 && strncmp(f, "truncate-", 9) == 0);
      }
      Spec s;
      s.columns = {{k.field, f, ""}};
      std::string why;
      EXPECT_EQ(listed ? GDEFCORE_OK : GDEFCORE_ERR_INVALID, Build(s, &why, false))
          << k.field << " " << f << ": " << why;
    }
  }
  /* A many-valued field takes join and count only. */
  size_t fn = 0;
  const char * const * fs = gdefcore_view_formatters(GDEFSTOR_FIELD_TEXT, 1, &fn);
  ASSERT_EQ(2u, fn);
  EXPECT_STREQ("join", fs[0]);
  for (const char * f : {"join", "count"}) {
    Spec s;
    s.columns = {{"tags", f, ""}};
    std::string why;
    EXPECT_EQ(GDEFCORE_OK, Build(s, &why, false)) << why;
  }
}

/* ---- running --------------------------------------------------------------------- */

TEST_F(Views, ARunGivesTheRowsInOrderWithEachColumnFormatted) {
  DefineItem();
  std::string who = Reader();
  Item(admin_, "bravo apple", "a", "2", "true", "2025-10-17", {"x", "y"});
  Item(admin_, "alpha", "b", "10", "false", "2025-11-02", {});
  Item(admin_, "charlie", "a", "1", "true", "2024-01-31", {"z"});
  Spec s;
  s.sort = "qty";
  s.sort_desc = true;
  s.columns = {{"title", "upper", "Name"}, {"title", "truncate-5", "Short"},
      {"done", "yesno", "Done"}, {"due", "date", "Due"}, {"tags", "join", "Tags"},
      {"tags", "count", "How many"}, {"qty", "", "Qty"}};
  Save(s);
  Out o = Run(who, "items");
  ASSERT_EQ(GDEFCORE_OK, o.rc);
  EXPECT_EQ(std::vector<std::string>({"Name", "Short", "Done", "Due", "Tags", "How many", "Qty"}), o.labels);
  ASSERT_EQ(3u, o.cells.size()) << (o.cells.empty() ? "" : o.cells[0][0]) << " " << (o.cells.size() > 1 ? o.cells[1][0] : "");
  EXPECT_EQ(3u, o.total);
  /* qty descending is a text compare of numbers? no: the store orders by value */
  EXPECT_EQ(std::vector<std::string>({"BRAVO APPLE", "bravo...", "yes", "2025-10-17", "x, y", "2", "2"}), o.cells[1]);
  EXPECT_EQ("ALPHA", o.cells[0][0]);
  EXPECT_EQ("alpha", o.cells[0][1]) << "a short value is not cut and gets no mark";
  EXPECT_EQ("no", o.cells[0][2]);
  EXPECT_EQ("2025-11-02", o.cells[0][3]);
  EXPECT_EQ("", o.cells[0][4]) << "no tags is an empty cell";
  EXPECT_EQ("0", o.cells[0][5]);
  /* The page, the offset and the total. */
  s.limit = 2;
  Save(s);
  Out p1 = Run(who, "items");
  EXPECT_EQ(2u, p1.cells.size());
  EXPECT_EQ(3u, p1.total);
  Out p2 = Run(who, "items", {}, 2);
  ASSERT_EQ(1u, p2.cells.size());
  EXPECT_EQ(3u, p2.total);
  EXPECT_NE(p1.ids[0], p2.ids[0]);
  EXPECT_NE(p1.ids[1], p2.ids[0]);
}

TEST_F(Views, TheConditionTreeAndItsArgumentsNarrowTheRows) {
  DefineItem();
  std::string who = Reader();
  Item(admin_, "a1", "a", "5", "false", "2025-01-01");
  Item(admin_, "a2", "a", "1", "true", "2025-01-02");
  Item(admin_, "a3", "a", "1", "false", "2025-01-03");
  Item(admin_, "b1", "b", "9", "true", "2025-01-04");
  Spec s;
  s.condition = "(and (= field.kind $kind) (or (>= field.qty $min) (= field.done \"true\")))";
  s.args = {{"kind", GDEFCORE_VIEW_SOURCE_URL, ""}, {"min", GDEFCORE_VIEW_SOURCE_EXPOSED, "4"}};
  s.sort = "title";
  Save(s);
  EXPECT_EQ(std::vector<std::string>({"a1", "a2"}), Col0(Run(who, "items", {{"kind", "a"}})));
  EXPECT_EQ(std::vector<std::string>({"a1", "a2", "a3"}), Col0(Run(who, "items", {{"kind", "a"}, {"min", "1"}})));
  EXPECT_EQ(std::vector<std::string>({"b1"}), Col0(Run(who, "items", {{"kind", "b"}})));
  /* An argument with no value and no default is no rows, never every row. */
  Out none = Run(who, "items", {});
  ASSERT_EQ(GDEFCORE_OK, none.rc);
  EXPECT_TRUE(none.cells.empty());
  EXPECT_EQ(0u, none.total);
  /* A `not` and a fixed argument. */
  Spec n;
  n.name = "notfixed";
  n.condition = "(and (not (= field.kind $skip)) (in field.title (\"a1\" \"b1\" $extra)))";
  n.args = {{"skip", GDEFCORE_VIEW_SOURCE_FIXED, "b"}, {"extra", GDEFCORE_VIEW_SOURCE_URL, "a3"}};
  n.sort = "title";
  Save(n);
  EXPECT_EQ(std::vector<std::string>({"a1", "a3"}), Col0(Run(who, "notfixed")));
}

TEST_F(Views, TheCurrentPrincipalIsAnArgumentAndAnonymousIsNoRows) {
  DefineItem();
  Role("writer");
  Grant("writer", "Read items");
  std::string ann = Principal("writer");
  std::string bob = Principal("writer");
  Item(ann, "ann-1", "a", "1", "true", "2025-01-01");
  Item(ann, "ann-2", "a", "2", "true", "2025-01-02");
  Item(bob, "bob-1", "a", "3", "true", "2025-01-03");
  Spec s;
  s.name = "mine";
  s.condition = "(= creator $me)";
  s.args = {{"me", GDEFCORE_VIEW_SOURCE_PRINCIPAL, ""}};
  s.sort = "title";
  Save(s);
  EXPECT_EQ(std::vector<std::string>({"ann-1", "ann-2"}), Col0(Run(ann, "mine")));
  EXPECT_EQ(std::vector<std::string>({"bob-1"}), Col0(Run(bob, "mine")));
  /* No principal: no rows, not every row. */
  Out anon = Run("", "mine");
  ASSERT_EQ(GDEFCORE_OK, anon.rc);
  EXPECT_TRUE(anon.cells.empty());
  EXPECT_EQ(0u, anon.total);
  /* A caller cannot name the principal: a parameter of that name is not read. */
  EXPECT_EQ(std::vector<std::string>({"bob-1"}), Col0(Run(bob, "mine", {{"me", ann}})));
}

TEST_F(Views, ARowThePrincipalMayNotSeeIsNotInTheRowsOrTheTotal) {
  DefineItem();
  Role("a-only");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("a-only", "Read items", "(= field.kind \"a\")"));
  std::string who = Principal("a-only");
  Item(admin_, "visible-1", "a", "1", "true", "2025-01-01");
  Item(admin_, "visible-2", "a", "2", "true", "2025-01-02");
  Item(admin_, "hidden-1", "b", "3", "true", "2025-01-03");
  Item(admin_, "hidden-2", "c", "4", "true", "2025-01-04");
  Spec s;
  s.sort = "title";
  Save(s);
  Out o = Run(who, "items");
  EXPECT_EQ(std::vector<std::string>({"visible-1", "visible-2"}), Col0(o));
  EXPECT_EQ(2u, o.total) << "the total counts only what the principal may see";
  /* The view's own condition asking for the hidden rows gets none of them. */
  Spec ask;
  ask.name = "asks";
  ask.condition = "(= field.kind \"b\")";
  Save(ask);
  Out hidden = Run(who, "asks");
  EXPECT_TRUE(hidden.cells.empty());
  EXPECT_EQ(0u, hidden.total);
  /* Anonymous sees nothing at all. */
  EXPECT_TRUE(Run("", "items").cells.empty());
  /* Someone who may read every item sees all four (the control: they are there). */
  Role("everyone");
  Grant("everyone", "Read items");
  std::string all = Principal("everyone");
  EXPECT_EQ(4u, Run(all, "items").cells.size());
  EXPECT_EQ(4u, Run(all, "items").total);
}

TEST_F(Views, AFieldThePrincipalMayNotReadIsAnEmptyCellAndAFieldTheyMayIsShown) {
  DefineItem();
  Role("plain");
  Grant("plain", "Read items");
  Role("noter");
  Grant("noter", "Read items");
  Grant("noter", "Read item notes");
  std::string plain = Principal("plain");
  std::string noter = Principal("noter");
  Item(admin_, "one", "a", "1", "true", "2025-01-01", {}, "private words");
  Spec s;
  s.columns = {{"title", "", ""}, {"note", "", ""}};
  Save(s);
  Out p = Run(plain, "items");
  ASSERT_EQ(1u, p.cells.size());
  EXPECT_EQ("one", p.cells[0][0]);
  EXPECT_EQ("", p.cells[0][1]);
  Out n = Run(noter, "items");
  ASSERT_EQ(1u, n.cells.size());
  EXPECT_EQ("private words", n.cells[0][1]);
}

TEST_F(Views, AnArgumentValueIsAConstantAndNeverPartOfTheCondition) {
  DefineItem();
  std::string who = Reader();
  Item(admin_, "plain", "a", "1", "true", "2025-01-01");
  Item(admin_, "has \"quote\" and \\ slash", "a", "2", "true", "2025-01-02");
  Item(admin_, "other", "b", "3", "true", "2025-01-03");
  Spec s;
  s.condition = "(= field.title $t)";
  s.args = {{"t", GDEFCORE_VIEW_SOURCE_EXPOSED, "plain"}};
  Save(s);
  /* A value that tries to close the constant and add a clause finds nothing,
   * and is not an error: it is only a title nobody has. */
  for (const char * evil : {"x\") (or true", "x\" ) (= field.kind \"a", "plain\" (= field.kind \"b\")",
           "\\", "\\\"", "a\\\"b"}) {
    Out o = Run(who, "items", {{"t", evil}});
    EXPECT_EQ(GDEFCORE_OK, o.rc) << evil;
    EXPECT_TRUE(o.cells.empty()) << evil;
    EXPECT_EQ(0u, o.total) << evil;
  }
  /* A title that holds quote and backslash is matched exactly. */
  Out q = Run(who, "items", {{"t", "has \"quote\" and \\ slash"}});
  ASSERT_EQ(1u, q.cells.size());
  EXPECT_EQ("has \"quote\" and \\ slash", q.cells[0][0]);
  /* The default is used when the caller gave none. */
  EXPECT_EQ(std::vector<std::string>({"plain"}), Col0(Run(who, "items")));
  /* A value the condition language cannot hold is refused outright. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Run(who, "items", {{"t", std::string("a\nb")}}).rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Run(who, "items", {{"t", std::string("a\tb")}}).rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Run(who, "items", {{"t", std::string(257, 'x')}}).rc);
  EXPECT_EQ(GDEFCORE_OK, Run(who, "items", {{"t", std::string(256, 'x')}}).rc);
  /* A `$` inside a quoted constant of the stored condition is that constant's. */
  Spec lit;
  lit.name = "dollar";
  lit.condition = "(= field.title \"$t\")";
  Save(lit);
  EXPECT_TRUE(Run(who, "dollar").cells.empty());
  Item(admin_, "$t", "a", "4", "true", "2025-01-04");
  EXPECT_EQ(1u, Run(who, "dollar").cells.size());
}

TEST_F(Views, AStoredViewThatNoLongerFitsItsTypeIsNeverRunLoosely) {
  DefineItem();
  std::string who = Reader();
  Item(admin_, "one", "a", "1", "true", "2025-01-01");
  Spec s;
  Save(s);
  ASSERT_EQ(GDEFCORE_OK, Run(who, "items").rc);
  /* Written past the checks, as a type that lost a field would leave it. */
  char ** ids = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, GDEFCORE_VIEW_TYPE,
      strlen(GDEFCORE_VIEW_TYPE), &ids, &count));
  ASSERT_EQ(1u, count);
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
  const char * bad = "gone|raw|Gone";
  size_t bad_len = strlen(bad);
  GDEFCORE_Value v;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  v.field = "columns";
  v.field_len = 7;
  v.texts = &bad;
  v.text_lens = &bad_len;
  v.count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, ids[0], strlen(ids[0]), "en", 2, &v, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, GDEFCORE_VIEW_TYPE, strlen(GDEFCORE_VIEW_TYPE)));
  gdefcore_changeset_destroy(cs);
  gdefcore_ids_free(catalog_, ids, count);
  char ** ids2 = NULL;
  size_t count2 = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, GDEFCORE_VIEW_TYPE,
      strlen(GDEFCORE_VIEW_TYPE), &ids2, &count2));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Run(who, "items").rc);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Run(who, "nope").rc);
  /* A column that names a field the type has, with a formatter that does not
   * suit it: nothing but the check of the whole view stops it (a cell would
   * simply be written wrong). */
  cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
  const char * odd = "title|yesno|Title";
  size_t odd_len = strlen(odd);
  v.texts = &odd;
  v.text_lens = &odd_len;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, ids2[0], strlen(ids2[0]), "en", 2, &v, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, GDEFCORE_VIEW_TYPE, strlen(GDEFCORE_VIEW_TYPE)));
  gdefcore_changeset_destroy(cs);
  gdefcore_ids_free(catalog_, ids2, count2);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Run(who, "items").rc);
}

TEST_F(Views, CsvAndJsonAreQuotedEscapedAndSafeToOpenInASpreadsheet) {
  DefineItem();
  std::string who = Reader();
  Item(admin_, "plain", "a", "1", "true", "2025-01-01");
  Item(admin_, "comma, and \"quote\"", "a", "2", "true", "2025-01-02");
  Item(admin_, "=SUM(A1)", "a", "3", "true", "2025-01-03");
  Item(admin_, "-1+1", "a", "4", "true", "2025-01-04");
  Item(admin_, "line\nbreak", "a", "5", "true", "2025-01-05");
  Item(admin_, "<b>&</b>", "a", "6", "true", "2025-01-06");
  Spec s;
  s.sort = "qty";
  s.columns = {{"title", "", "Name"}, {"qty", "", "Qty"}};
  s.format = GDEFCORE_VIEW_FORMAT_CSV;
  Save(s);
  Out csv = Run(who, "items");
  ASSERT_EQ(GDEFCORE_OK, csv.rc);
  EXPECT_EQ(
      "Name,Qty\r\n"
      "plain,1\r\n"
      "\"comma, and \"\"quote\"\"\",2\r\n"
      "\"'=SUM(A1)\",3\r\n"
      "\"'-1+1\",4\r\n"
      "\"line\nbreak\",5\r\n"
      "<b>&</b>,6\r\n",
      csv.text);
  s.format = GDEFCORE_VIEW_FORMAT_JSON;
  s.columns = {{"title", "", "Name"}, {"qty", "", "Qty"}};
  Save(s);
  Out js = Run(who, "items");
  ASSERT_EQ(GDEFCORE_OK, js.rc);
  EXPECT_EQ(
      "[{\"Name\":\"plain\",\"Qty\":\"1\"},"
      "{\"Name\":\"comma, and \\\"quote\\\"\",\"Qty\":\"2\"},"
      "{\"Name\":\"=SUM(A1)\",\"Qty\":\"3\"},"
      "{\"Name\":\"-1+1\",\"Qty\":\"4\"},"
      "{\"Name\":\"line\\u000abreak\",\"Qty\":\"5\"},"
      "{\"Name\":\"\\u003cb\\u003e\\u0026\\u003c/b\\u003e\",\"Qty\":\"6\"}]",
      js.text);
}

TEST_F(Views, TheStructsOfAViewAreAcceptedAtOnlyTheirOwnSize) {
  DefineItem();
  std::string who = Reader();
  Item(admin_, "one", "a", "1", "true", "2025-01-01");
  Spec s;
  s.condition = "(= field.title $t)";
  s.args = {{"t", GDEFCORE_VIEW_SOURCE_URL, ""}};
  Save(s);
  auto valid = [&](size_t def_size, size_t col_size, size_t arg_size) {
    GDEFCORE_View_Column c;
    memset(&c, 0, sizeof c);
    c.size = col_size;
    c.field = "title";
    c.field_len = 5;
    GDEFCORE_View_Arg a;
    memset(&a, 0, sizeof a);
    a.size = arg_size;
    a.name = "t";
    a.name_len = 1;
    a.source = GDEFCORE_VIEW_SOURCE_URL;
    GDEFCORE_View_Def d;
    memset(&d, 0, sizeof d);
    d.size = def_size;
    d.name = "sized";
    d.name_len = 5;
    d.type = kItem;
    d.type_len = strlen(kItem);
    d.condition = "(= field.title $t)";
    d.condition_len = strlen(d.condition);
    d.columns = &c;
    d.column_count = 1;
    d.args = &a;
    d.arg_count = 1;
    d.format = GDEFCORE_VIEW_FORMAT_TABLE;
    d.limit = 10;
    char why[64];
    return gdefcore_view_validate(catalog_, &d, why, sizeof why) == GDEFCORE_OK;
  };
  size_structs::Run("tests/test_view.cpp",
      {
          {"GDEFCORE_View_Def", [&](size_t n) { return valid(n, sizeof(GDEFCORE_View_Column), sizeof(GDEFCORE_View_Arg)); }},
          {"GDEFCORE_View_Column", [&](size_t n) { return valid(sizeof(GDEFCORE_View_Def), n, sizeof(GDEFCORE_View_Arg)); }},
          {"GDEFCORE_View_Arg", [&](size_t n) { return valid(sizeof(GDEFCORE_View_Def), sizeof(GDEFCORE_View_Column), n); }},
          {"GDEFCORE_View_Param", [&](size_t n) {
             GDEFCORE_View_Param p;
             memset(&p, 0, sizeof p);
             p.size = n;
             p.name = "t";
             p.name_len = 1;
             p.value = "one";
             p.value_len = 3;
             GDEFCORE_View_Result * r = NULL;
             GDEFCORE_Result rc = gdefcore_view_run(catalog_, Req(who), "items", 5, &p, 1, 0, &r);
             gdefcore_view_result_free(r);
             return rc == GDEFCORE_OK;
           }},
      });
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
