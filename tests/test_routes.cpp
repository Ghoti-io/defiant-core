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
 * Route patterns with named segments, route kinds, permission and title (site
 * admin epic, story 4). One test per row of the story's matrix, the old
 * gdefcore_route_add unchanged, and a hostile-input sweep over patterns.
 *
 * Each test carries a CONTROL: the observation that shows the thing it looks
 * for can be seen (a different request captures a different value, an allowed
 * principal does run the handler, the table is usable after an error). The
 * real-source plants are in tools/check-routes.sh.
 */

#include "gate_fixture.h"


namespace {

using namespace gate;

std::vector<std::string> & Log() {
  static std::vector<std::string> log;
  return log;
}

/** What a handler is: a tag for the log, and whether it owns the request. */
struct H {
  const char * tag;
  bool own;
};

const char * const kNames[] = {"id", "x", "y", "rev", "name"};

/** Logs "tag name=value ..." for each capture the call has, in kNames order. */
void RunCall(const GDEFCORE_Route_Call * call) {
  const H * h = (const H *)call->data;
  std::string line = h->tag;
  size_t i;
  for (i = 0; i < sizeof kNames / sizeof kNames[0]; i++) {
    const char * v = NULL;
    size_t n = 0;
    if (gdefcore_route_call_capture(call, kNames[i], strlen(kNames[i]), &v, &n)) {
      line += std::string(" ") + kNames[i] + "=" + std::string(v, n);
    }
  }
  Log().push_back(line);
  if (h->own) {
    gdefcore_request_set_resolution(call->request, call->machine,
        call->machine_len);
  }
}

void OldRun(GDEFCORE_Request * request, const char * machine, size_t machine_len,
    void * data) {
  const H * h = (const H *)data;
  Log().push_back(std::string("old:") + h->tag);
  if (h->own) {
    gdefcore_request_set_resolution(request, machine, machine_len);
  }
}

void NoteRootFn(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  (void)machine;
  (void)machine_len;
  (void)data;
  Log().push_back("root");
  gdefcore_request_set_note(request, "root", 4, "1", 1);
}

/** Everything a caller can observe of one resolve. */
struct Seen {
  GDEFCORE_Result rc;
  GDEFCORE_Result status;
  std::string resolution;
  std::string notes;
  std::string ran;
  bool operator==(const Seen & o) const {
    return rc == o.rc && status == o.status && resolution == o.resolution &&
           notes == o.notes && ran == o.ran;
  }
  std::string Str() const {
    return std::string("rc=") + Rc(rc) + " status=" + Rc(status) + " res=[" +
           resolution + "] notes=[" + notes + "] ran=[" + ran + "]";
  }
};

const char * const kProbeNotes[] = {"root", "denied", "route.denied", "forbidden",
    "seen", "error", "status", "route"};

class Routes : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  Site s_;
  GDEFCORE_Routes * routes_ = NULL;
  H own_{"own", true};
  H pass_{"pass", false};

  void SetUp() override {
    Log().clear();
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    s_.Open(store_, "t", 0x42);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes_));
  }

  void TearDown() override {
    gdefcore_routes_destroy(routes_);
    s_.Close();
    gdefstor_store_destroy(store_);
  }

  static GDEFCORE_Route_Spec Spec(const char * machine, const char * path,
      GDEFCORE_Route_Call_Fn fn, void * data) {
    GDEFCORE_Route_Spec spec;
    memset(&spec, 0, sizeof spec);
    spec.size = sizeof spec;
    spec.machine = machine;
    spec.machine_len = strlen(machine);
    spec.path = path;
    spec.path_len = strlen(path);
    spec.call_fn = fn;
    spec.data = data;
    return spec;
  }

  GDEFCORE_Result Add(const GDEFCORE_Route_Spec & spec, std::string * error = NULL) {
    char * text = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_route_add_spec(routes_, &spec, &text, &n);
    if (error != NULL) {
      *error = text == NULL ? std::string("<none>") : std::string(text, n);
    }
    gdefcore_routes_free(routes_, text);
    return rc;
  }

  GDEFCORE_Result AddPage(const char * machine, const char * path, H * h,
      int weight = 0) {
    GDEFCORE_Route_Spec spec = Spec(machine, path, RunCall, h);
    spec.weight = weight;
    return Add(spec);
  }

  Seen Resolve(const std::string & path, GDEFCORE_Request * request) {
    Seen seen;
    char * out = NULL;
    size_t n = 0;
    size_t i;
    Log().clear();
    seen.rc = gdefcore_form_resolve(routes_, s_.catalog, request, path.data(),
        path.size(), &out, &n);
    if (seen.rc == GDEFCORE_OK) {
      seen.resolution.assign(out, n);
      gdefcore_text_free(s_.catalog, out);
    }
    seen.status = gdefcore_request_status(request);
    for (i = 0; i < sizeof kProbeNotes / sizeof kProbeNotes[0]; i++) {
      size_t len = 0;
      const char * v = gdefcore_request_note(request, kProbeNotes[i],
          strlen(kProbeNotes[i]), &len);
      if (v != NULL) {
        seen.notes += std::string(kProbeNotes[i]) + "=" + std::string(v, len) + ";";
      }
    }
    for (i = 0; i < Log().size(); i++) {
      seen.ran += Log()[i] + "|";
    }
    return seen;
  }

  Seen ResolveAs(const std::string & path, const std::string & principal = "") {
    GDEFCORE_Request * request = s_.NewRequest(principal);
    Seen seen = Resolve(path, request);
    gdefcore_request_destroy(request);
    return seen;
  }

  std::vector<std::string> Tabs(const char * parent, std::vector<std::string> * extra = NULL) {
    GDEFCORE_Route_Info * info = NULL;
    size_t count = 99;
    size_t i;
    std::vector<std::string> out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_routes_tabs(routes_, parent, strlen(parent), &info, &count));
    for (i = 0; i < count; i++) {
      out.push_back(std::string(info[i].machine, info[i].machine_len));
      if (extra != NULL) {
        extra->push_back(std::string(info[i].machine, info[i].machine_len) + "|" +
                         std::string(info[i].path, info[i].path_len) + "|" +
                         std::string(info[i].title, info[i].title_len) + "|" +
                         std::string(info[i].permission, info[i].permission_len) +
                         "|kind=" + std::to_string(info[i].kind) + "|def=" +
                         std::to_string(info[i].is_default != 0) + "|w=" +
                         std::to_string(info[i].weight));
      }
    }
    gdefcore_routes_free(routes_, info);
    return out;
  }
};

TEST_F(Routes, Capture) {
  /* CONTROL inside: another request captures another value, so the log can
   * tell 42 from 43, and a name the pattern does not have is absent. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("node.edit", "/node/:id/edit", &own_));
  Seen a = ResolveAs("/node/42/edit");
  EXPECT_EQ("node.edit", a.resolution);
  EXPECT_EQ("own id=42|", a.ran);
  Seen b = ResolveAs("/node/43/edit");
  EXPECT_EQ("own id=43|", b.ran);
  EXPECT_NE(a.ran, b.ran);
  Seen c = ResolveAs("/node/42/view");
  EXPECT_EQ("", c.ran);
  EXPECT_NE(GDEFCORE_OK, c.rc);
  /* A prefix match (an ancestor) captures from the segments it covers. */
  Seen d = ResolveAs("/node/42/edit/more");
  EXPECT_EQ("own id=42|", d.ran);
}

TEST_F(Routes, TwoCaptures) {
  ASSERT_EQ(GDEFCORE_OK, AddPage("ab", "/a/:x/b/:y", &own_));
  EXPECT_EQ("own x=1 y=2|", ResolveAs("/a/1/b/2").ran);
  /* The names are not positions: swapped values swap the captures. */
  EXPECT_EQ("own x=2 y=1|", ResolveAs("/a/2/b/1").ran);
  EXPECT_EQ("", ResolveAs("/a/1/c/2").ran);
}

TEST_F(Routes, UnnamedStar) {
  ASSERT_EQ(GDEFCORE_OK, AddPage("star", "/a/*/b", &own_));
  Seen s = ResolveAs("/a/7/b");
  EXPECT_EQ("star", s.resolution);
  EXPECT_EQ("own|", s.ran);
  /* CONTROL: the accessor does see a named segment in the same position. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("named", "/c/:id/b", &own_));
  EXPECT_EQ("own id=7|", ResolveAs("/c/7/b").ran);
  /* `*` is not a name, and a lookup of "*" or of "" finds nothing. */
  struct Look {
    static void Fn(const GDEFCORE_Route_Call * call) {
      const char * v = NULL;
      size_t n = 0;
      Log().push_back(std::string("star=") +
                      std::to_string(gdefcore_route_call_capture(call, "*", 1, &v, &n)) +
                      " empty=" +
                      std::to_string(gdefcore_route_call_capture(call, "", 0, &v, &n)));
    }
  };
  ASSERT_EQ(GDEFCORE_OK, Add(Spec("look", "/d/*", Look::Fn, NULL)));
  EXPECT_EQ("star=0 empty=0|", ResolveAs("/d/q").ran);
}

TEST_F(Routes, BadNamesAreRefused) {
  struct Case {
    const char * path;
    const char * why;
  };
  const Case cases[] = {
      {"/a/:Id", "capture name must be"},
      {"/a/:x/:x", "repeated capture name"},
      {"/a/:", "empty capture name"},
      {"/a/:1", "capture name must be"},
      {"/a/:_x", "capture name must be"},
      {"/a/:x-y", "capture name must be"},
      {"/a/:x%41", "capture name must be"},
      {"/a/:\xc3\xa9", "capture name must be"},
      {"/a/:x y", "capture name must be"},
      {"a/:x", "path must start with /"},
  };
  size_t i;
  for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    std::string error;
    GDEFCORE_Result rc = Add(Spec("bad", cases[i].path, RunCall, &own_), &error);
    EXPECT_EQ(GDEFCORE_ERR_INVALID, rc) << cases[i].path;
    EXPECT_NE(std::string::npos, error.find(cases[i].why))
        << cases[i].path << " -> " << error;
    EXPECT_NE(std::string::npos, error.find("bad")) << error;
    /* Nothing was added: the same machine name is still free (CONTROL). */
    EXPECT_EQ(GDEFCORE_OK, AddPage("bad", "/ok/:x", &own_)) << cases[i].path;
    gdefcore_routes_destroy(routes_);
    routes_ = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes_));
  }
  /* The valid spellings next to them are accepted. */
  EXPECT_EQ(GDEFCORE_OK, AddPage("good1", "/a/:x_1/:y2", &own_));
  EXPECT_EQ(GDEFCORE_OK, AddPage("good2", "/a/:x/*/:y", &own_));
}

TEST_F(Routes, OldPathKeepsColonLiteral) {
  /* gdefcore_route_add does not read `:`: it matches the text ":id". */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes_, "old", 3, "/a/:id", 6, 0, 0, OldRun, &own_, NULL,
          NULL));
  EXPECT_EQ("old", ResolveAs("/a/:id").resolution);
  EXPECT_EQ("old:own|", ResolveAs("/a/:id").ran);
  EXPECT_EQ("", ResolveAs("/a/5").ran);
  /* Old behaviours: an old handler on a named-segment route still runs, and
   * the duplicate-machine error text is as it was. */
  GDEFCORE_Route_Spec spec = Spec("new", "/n/:id", NULL, &own_);
  spec.fn = OldRun;
  EXPECT_EQ(GDEFCORE_OK, Add(spec));
  EXPECT_EQ("old:own|", ResolveAs("/n/9").ran);
  char * error = NULL;
  size_t n = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_route_add(routes_, "old", 3, "/b", 2, 0, 0, OldRun, NULL, &error, &n));
  ASSERT_NE(nullptr, error);
  EXPECT_EQ(std::string("old /a/:id\nold /b"), std::string(error, n));
  gdefcore_routes_free(routes_, error);
  /* The same name through the new call names both routes the same way. */
  std::string text;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(Spec("old", "/c", RunCall, NULL), &text));
  EXPECT_EQ("old /a/:id\nold /c", text);
}

TEST_F(Routes, SpecArgumentsAreChecked) {
  GDEFCORE_Route_Spec spec = Spec("m", "/m", RunCall, &own_);
  GDEFCORE_Route_Spec bad;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(NULL, &spec, NULL, NULL));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, NULL, NULL, NULL));
  bad = spec;
  bad.size = sizeof bad - 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &bad, NULL, NULL));
  bad = spec;
  bad.call_fn = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &bad, NULL, NULL));
  bad = spec;
  bad.fn = OldRun;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &bad, NULL, NULL));
  bad = spec;
  bad.machine_len = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &bad, NULL, NULL));
  bad = spec;
  bad.kind = 7;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &bad, NULL, NULL));
  bad = spec;
  bad.title = "\xff\xfe";
  bad.title_len = 2;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_route_add_spec(routes_, &bad, NULL, NULL));
  bad = spec;
  bad.title = "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x99\x82";
  bad.title_len = strlen(bad.title);
  /* CONTROL: after all that refusing, the good spec and a UTF-8 title go in. */
  EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes_, &spec, NULL, NULL));
  bad.machine = "m2";
  bad.machine_len = 2;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_route_add_spec(routes_, &bad, NULL, NULL));
}

TEST_F(Routes, TitleAndPermissionBounds) {
  GDEFCORE_Route_Spec spec = Spec("t", "/t", RunCall, &own_);
  std::string big(GDEFCORE_ROUTE_TITLE_MAX, 'a');
  std::string toobig(GDEFCORE_ROUTE_TITLE_MAX + 1, 'a');
  spec.title = big.data();
  spec.title_len = big.size();
  EXPECT_EQ(GDEFCORE_OK, Add(spec));
  spec.machine = "t2";
  spec.machine_len = 2;
  spec.title = toobig.data();
  spec.title_len = toobig.size();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec));
  spec.title = "bad\nnewline";
  spec.title_len = strlen(spec.title);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec));
  spec.title = "overlong \xc0\xaf";
  spec.title_len = strlen(spec.title);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec));
  spec.title = "surrogate \xed\xa0\x80";
  spec.title_len = strlen(spec.title);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec));
  spec.title = "truncated \xe2\x82";
  spec.title_len = strlen(spec.title);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec));
  spec.title = NULL;
  spec.title_len = 0;
  std::string perm(GDEFCORE_ROUTE_PERMISSION_MAX + 1, 'p');
  spec.permission = perm.data();
  spec.permission_len = perm.size();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec));
  spec.permission_len = GDEFCORE_ROUTE_PERMISSION_MAX;
  EXPECT_EQ(GDEFCORE_OK, Add(spec));
}

/* A check that records what it was given and answers from a table. */
struct Gate {
  std::vector<std::string> seen;
  int allow = 1;
};

int GateCheck(const GDEFCORE_Route_Call * call, const char * permission,
    size_t permission_len, void * data) {
  Gate * gate = (Gate *)data;
  const char * v = NULL;
  size_t n = 0;
  size_t pn = 0;
  const char * principal = gdefcore_request_principal(call->request, &pn);
  std::string cap = gdefcore_route_call_capture(call, "id", 2, &v, &n)
                        ? std::string(v, n)
                        : std::string("<none>");
  gate->seen.push_back(std::string(permission, permission_len) + "|" + cap + "|" +
                       std::string(principal == NULL ? "" : principal, pn));
  return gate->allow;
}

TEST_F(Routes, NoPermissionIsUnchanged) {
  Gate gate;
  gate.allow = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes_, GateCheck, &gate));
  ASSERT_EQ(GDEFCORE_OK, AddPage("free", "/free/:id", &own_));
  Seen seen = ResolveAs("/free/5");
  EXPECT_EQ("free", seen.resolution);
  EXPECT_TRUE(gate.seen.empty()) << "a route with no permission asked the check";
  /* CONTROL: a route with a permission does ask it, and is refused. */
  GDEFCORE_Route_Spec spec = Spec("held", "/held/:id", RunCall, &own_);
  spec.permission = "Read posts";
  spec.permission_len = 10;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  seen = ResolveAs("/held/5");
  EXPECT_NE(GDEFCORE_OK, seen.rc);
  ASSERT_EQ(1u, gate.seen.size());
  EXPECT_EQ("Read posts|5|", gate.seen[0]);
}

TEST_F(Routes, PermissionWithoutACheckNeverMatches) {
  GDEFCORE_Route_Spec spec = Spec("held", "/held", RunCall, &own_);
  spec.permission = "P";
  spec.permission_len = 1;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  EXPECT_EQ("", ResolveAs("/held").ran);
  Gate gate;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes_, GateCheck, &gate));
  EXPECT_EQ("held", ResolveAs("/held").resolution);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes_, NULL, NULL));
  EXPECT_EQ("", ResolveAs("/held").ran);
}

TEST_F(Routes, CheckIsAskedOnlyForAPathThatMatched) {
  Gate gate;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes_, GateCheck, &gate));
  GDEFCORE_Route_Spec spec = Spec("held", "/held/:id/x", RunCall, &own_);
  spec.permission = "P";
  spec.permission_len = 1;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  ResolveAs("/other/1/x");
  ResolveAs("/held/1/y");
  EXPECT_TRUE(gate.seen.empty());
  ResolveAs("/held/1/x");
  ASSERT_EQ(1u, gate.seen.size()) << "CONTROL: a matching path does ask";
  EXPECT_EQ("P|1|", gate.seen[0]);
}

/* The caller's check, built on the access layer as a caller would: it reads
 * the captured entity id and asks whether this principal may read the entity.
 * (access.h has no "does P hold permission X on entity E"; see forms.md.) */
struct AccessGate {
  GDEFCORE_Catalog * catalog;
  std::vector<std::string> ids;
};

int AccessCheck(const GDEFCORE_Route_Call * call, const char * permission,
    size_t permission_len, void * data) {
  AccessGate * gate = (AccessGate *)data;
  const char * v = NULL;
  size_t n = 0;
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc;
  (void)permission;
  (void)permission_len;
  if (!gdefcore_route_call_capture(call, "id", 2, &v, &n)) {
    return 0;
  }
  gate->ids.push_back(std::string(v, n));
  rc = gdefcore_access_read(gate->catalog, call->request, v, n, "en", 2, "title", 5,
      &texts, &lens, &count, NULL);
  if (rc != GDEFCORE_OK) {
    return 0;
  }
  gdefcore_values_free(gate->catalog, texts, lens, count);
  return count > 0;
}

TEST_F(Routes, PermissionWithValue) {
  AccessGate gate;
  std::string editor_a;
  std::string editor_b;
  std::string nobody;
  std::string note_a;
  std::string note_b;
  gate.catalog = s_.catalog;
  s_.DefineNote();
  s_.Declare(Perm("Read own notes", "read", GDEFCORE_ACCESS_OWN, "site.note", NULL));
  s_.Role("writers");
  s_.Grant("writers", "Read own notes");
  editor_a = s_.Principal("writers");
  editor_b = s_.Principal("writers");
  nobody = s_.Principal();
  note_a = s_.SaveNote(editor_a, "A", "sa");
  note_b = s_.SaveNote(editor_b, "B", "sb");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes_, AccessCheck, &gate));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_route_add(routes_, "root", 4, "/", 1, 9, 0, NoteRootFn,
                             NULL, NULL, NULL));
  GDEFCORE_Route_Spec spec = Spec("note.edit", "/note/:id/edit", RunCall, &own_);
  spec.permission = "Read own notes";
  spec.permission_len = 14;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  /* CONTROL: the same route with no permission runs for everyone, so what
   * the other observations lack is the permission and not the route. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("note.open", "/open/:id", &own_));
  EXPECT_EQ("note.open", ResolveAs("/open/" + note_a, nobody).resolution);

  /* The editor of A may edit A, and the check saw A's id. */
  Seen yes = ResolveAs("/note/" + note_a + "/edit", editor_a);
  EXPECT_EQ("note.edit", yes.resolution);
  EXPECT_EQ("own id=" + note_a + "|", yes.ran);
  EXPECT_EQ(note_a, gate.ids.empty() ? std::string("<none>") : gate.ids.back());
  /* The same principal does not get B: the matched value decides. */
  Seen other_value = ResolveAs("/note/" + note_b + "/edit", editor_a);
  EXPECT_NE("note.edit", other_value.resolution);
  EXPECT_EQ(note_b, gate.ids.empty() ? std::string("<none>") : gate.ids.back());
  /* Another principal with the same role, and one with none, do not get A. */
  Seen same_role = ResolveAs("/note/" + note_a + "/edit", editor_b);
  Seen none = ResolveAs("/note/" + note_a + "/edit", nobody);
  EXPECT_NE("note.edit", same_role.resolution);
  EXPECT_NE("note.edit", none.resolution);
  /* The editor of B gets B (CONTROL for "another principal"). */
  EXPECT_EQ("note.edit", ResolveAs("/note/" + note_b + "/edit", editor_b).resolution);
}

TEST_F(Routes, RefusalIsAMissingRoute) {
  /* A refused route and a route that never existed answer alike in every
   * channel a caller has: the return code, the resolution, the request status
   * and the notes, and the handlers that ran (the fall-through root). */
  Gate gate;
  std::string someone = s_.Principal();
  gate.allow = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes_, GateCheck, &gate));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_route_add(routes_, "root", 4, "/", 1, 9, 0, NoteRootFn,
                             NULL, NULL, NULL));
  GDEFCORE_Route_Spec spec = Spec("secret", "/secret/:id/edit", RunCall, &own_);
  spec.permission = "Edit secrets";
  spec.permission_len = 12;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  Seen refused = ResolveAs("/secret/9/edit", someone);
  Seen missing = ResolveAs("/nothing/9/edit", someone);
  ASSERT_EQ(1u, gate.seen.size()) << "the refusal path never asked the check";
  EXPECT_EQ(refused.Str(), missing.Str());
  EXPECT_TRUE(refused == missing) << refused.Str() << " vs " << missing.Str();
  /* The observation can see: the root fall-through is in both, and an
   * allowed request differs from both. */
  EXPECT_EQ("root|", refused.ran);
  EXPECT_EQ("root=1;", refused.notes);
  gate.allow = 1;
  Seen allowed = ResolveAs("/secret/9/edit", someone);
  EXPECT_FALSE(allowed == missing) << allowed.Str();
  EXPECT_EQ("secret", allowed.resolution);
  /* And a refusal with a lower route behind it falls through to that route
   * as a missing route would. */
  gate.allow = 0;
  ASSERT_EQ(GDEFCORE_OK, AddPage("secret.fallback", "/secret/:id", &own_, 20));
  Seen behind = ResolveAs("/secret/9/edit", someone);
  EXPECT_EQ("secret.fallback", behind.resolution);
  EXPECT_EQ("root|own id=9|", behind.ran);
}

TEST_F(Routes, DefaultTab) {
  H view{"view", true};
  H edit{"edit", true};
  H parent{"parent", true};
  GDEFCORE_Route_Spec spec;
  /* The parent owns, so it must come after its tabs (a higher weight): weight
   * orders dispatch as it always did. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("node", "/node/:id", &parent, 10));
  spec = Spec("node.view", "/node/:id/view", RunCall, &view);
  spec.kind = GDEFCORE_ROUTE_TAB;
  spec.parent = "node";
  spec.parent_len = 4;
  spec.is_default = 1;
  spec.title = "View";
  spec.title_len = 4;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  spec = Spec("node.edit", "/node/:id/edit", RunCall, &edit);
  spec.kind = GDEFCORE_ROUTE_TAB;
  spec.parent = "node";
  spec.parent_len = 4;
  spec.weight = 1;
  spec.title = "Edit";
  spec.title_len = 4;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));

  /* The parent's path is served by the default tab, with its captures. */
  Seen at_parent = ResolveAs("/node/42");
  EXPECT_EQ("node.view", at_parent.resolution);
  EXPECT_EQ("view id=42|", at_parent.ran);
  /* Its own path resolves to the same handler. */
  Seen at_view = ResolveAs("/node/42/view");
  EXPECT_EQ("node.view", at_view.resolution);
  EXPECT_EQ("view id=42|", at_view.ran);
  /* The other tab runs its own handler, and not the view. */
  Seen at_edit = ResolveAs("/node/42/edit");
  EXPECT_EQ("node.edit", at_edit.resolution);
  EXPECT_EQ("edit id=42|", at_edit.ran);
  /* CONTROL: the parent's own handler is live on a path the view does not
   * answer (the alias is exact; an ancestor match is the parent's). */
  Seen deeper = ResolveAs("/node/42/other");
  EXPECT_EQ("node", deeper.resolution);
  EXPECT_EQ("parent id=42|", deeper.ran);
  /* The enumeration: view (default) then edit. */
  std::vector<std::string> rows;
  std::vector<std::string> names = Tabs("node", &rows);
  ASSERT_EQ(2u, names.size());
  EXPECT_EQ("node.view|/node/:id/view|View||kind=1|def=1|w=0", rows[0]);
  EXPECT_EQ("node.edit|/node/:id/edit|Edit||kind=1|def=0|w=1", rows[1]);
}

TEST_F(Routes, DefaultTabIsExactAndFallThroughIsHonest) {
  H view{"view", true};
  H edit{"edit", false};
  GDEFCORE_Route_Spec spec;
  ASSERT_EQ(GDEFCORE_OK, AddPage("node", "/node/:id", &pass_));
  spec = Spec("node.view", "/node/:id/view", RunCall, &view);
  spec.kind = GDEFCORE_ROUTE_TAB;
  spec.parent = "node";
  spec.parent_len = 4;
  spec.is_default = 1;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  spec = Spec("node.edit", "/node/:id/edit", RunCall, &edit);
  spec.kind = GDEFCORE_ROUTE_TAB;
  spec.parent = "node";
  spec.parent_len = 4;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  /* An edit handler that falls through does not hand the request to the
   * view tab: the view's parent-path alias is not an ancestor match. */
  Seen at_edit = ResolveAs("/node/42/edit");
  EXPECT_EQ("edit id=42|pass id=42|", at_edit.ran);
  EXPECT_EQ(std::string::npos, at_edit.ran.find("view"));
  /* CONTROL: at the parent's path the view does run, ahead of the parent. */
  Seen at_parent = ResolveAs("/node/42");
  EXPECT_EQ("view id=42|", at_parent.ran);
  EXPECT_EQ("node.view", at_parent.resolution);
}

TEST_F(Routes, DefaultTabPermissionSeesTheParentPathCaptures) {
  Gate gate;
  std::string who = s_.Principal();
  H view{"view", true};
  GDEFCORE_Route_Spec spec;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_set_check(routes_, GateCheck, &gate));
  ASSERT_EQ(GDEFCORE_OK, AddPage("node", "/node/:id", &pass_));
  spec = Spec("node.view", "/node/:id/view", RunCall, &view);
  spec.kind = GDEFCORE_ROUTE_TAB;
  spec.parent = "node";
  spec.parent_len = 4;
  spec.is_default = 1;
  spec.permission = "View nodes";
  spec.permission_len = 10;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  EXPECT_EQ("node.view", ResolveAs("/node/42", who).resolution);
  ASSERT_EQ(1u, gate.seen.size());
  EXPECT_EQ("View nodes|42|" + who, gate.seen[0]);
  /* Refused at the parent's path, the parent's own handler is what remains. */
  gate.allow = 0;
  Seen refused = ResolveAs("/node/42", who);
  EXPECT_EQ("pass id=42|", refused.ran);
}

TEST_F(Routes, TabErrors) {
  H view{"view", true};
  std::string error;
  GDEFCORE_Route_Spec spec = Spec("node.view", "/node/:id/view", RunCall, &view);
  spec.kind = GDEFCORE_ROUTE_TAB;
  spec.parent = "node";
  spec.parent_len = 4;
  /* Orphan, default and plain: both names are in the message. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec, &error));
  EXPECT_NE(std::string::npos, error.find("node.view")) << error;
  EXPECT_NE(std::string::npos, error.find("node")) << error;
  spec.is_default = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(spec, &error));
  EXPECT_NE(std::string::npos, error.find("node.view")) << error;
  EXPECT_NE(std::string::npos, error.find("(not registered)")) << error;
  EXPECT_TRUE(Tabs("node").empty());
  /* CONTROL: with the parent registered the same spec is accepted. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("node", "/node/:id", &pass_));
  EXPECT_EQ(GDEFCORE_OK, Add(spec));
  /* A second default for one parent names both tabs. */
  GDEFCORE_Route_Spec second = Spec("node.other", "/node/:id/other", RunCall, &view);
  second.kind = GDEFCORE_ROUTE_TAB;
  second.parent = "node";
  second.parent_len = 4;
  second.is_default = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(second, &error));
  EXPECT_NE(std::string::npos, error.find("node.other")) << error;
  EXPECT_NE(std::string::npos, error.find("node.view")) << error;
  /* CONTROL: not as a default, it is fine; two non-default tabs are fine. */
  second.is_default = 0;
  EXPECT_EQ(GDEFCORE_OK, Add(second));
  EXPECT_EQ(2u, Tabs("node").size());
  /* A parent on a page or an action, a default page, a tab with no parent. */
  GDEFCORE_Route_Spec page = Spec("p1", "/p1", RunCall, &view);
  page.parent = "node";
  page.parent_len = 4;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(page, &error));
  page.parent = NULL;
  page.parent_len = 0;
  page.is_default = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(page, &error));
  page.is_default = 0;
  page.kind = GDEFCORE_ROUTE_TAB;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(page, &error));
  /* A default tab may not capture a name its parent does not. */
  GDEFCORE_Route_Spec wide = Spec("w", "/node/:id/rev/:rev", RunCall, &view);
  wide.kind = GDEFCORE_ROUTE_TAB;
  wide.parent = "node";
  wide.parent_len = 4;
  GDEFCORE_Route_Spec solo = Spec("node2", "/node2", RunCall, &view);
  ASSERT_EQ(GDEFCORE_OK, Add(solo));
  wide.parent = "node2";
  wide.parent_len = 5;
  wide.is_default = 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(wide, &error));
  EXPECT_NE(std::string::npos, error.find("node2")) << error;
  wide.is_default = 0;
  EXPECT_EQ(GDEFCORE_OK, Add(wide));
  /* Nothing from any refusal is in the table. */
  EXPECT_EQ(0u, Tabs("p1").size());
  EXPECT_EQ(1u, Tabs("node2").size());
}

TEST_F(Routes, OrphanTab) {
  H view{"view", true};
  GDEFCORE_Route_Spec spec = Spec("t1", "/a/:id/t", RunCall, &view);
  spec.kind = GDEFCORE_ROUTE_TAB;
  spec.parent = "ghost";
  spec.parent_len = 5;
  EXPECT_NE(GDEFCORE_OK, Add(spec));
  spec.is_default = 1;
  spec.machine = "t2";
  spec.machine_len = 2;
  EXPECT_NE(GDEFCORE_OK, Add(spec));
  /* A tab cannot be its own parent. */
  spec.machine = "ghost";
  spec.machine_len = 5;
  EXPECT_NE(GDEFCORE_OK, Add(spec));
  EXPECT_TRUE(Tabs("ghost").empty());
  EXPECT_EQ("", ResolveAs("/a/1/t").ran);
  /* CONTROL: a parent registered first makes the same tab acceptable. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("ghost", "/a/:id", &pass_));
  spec.machine = "t3";
  spec.machine_len = 2;
  EXPECT_EQ(GDEFCORE_OK, Add(spec));
  EXPECT_EQ(1u, Tabs("ghost").size());
}

TEST_F(Routes, Exactness) {
  H named{"named", true};
  H literal{"literal", true};
  /* Registered named first, so the tie rule (registration order) would pick
   * it if exactness did not. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("named", "/node/:id/edit", &named));
  ASSERT_EQ(GDEFCORE_OK, AddPage("literal", "/node/42/edit", &literal));
  EXPECT_EQ("literal", ResolveAs("/node/42/edit").resolution);
  EXPECT_EQ("literal|", ResolveAs("/node/42/edit").ran);
  /* CONTROL: another id reaches the named route. */
  EXPECT_EQ("named", ResolveAs("/node/43/edit").resolution);
  /* Equal weight and equal exactness: registration order, as before. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("n2", "/q/:id", &named));
  ASSERT_EQ(GDEFCORE_OK, AddPage("n3", "/q/:x", &literal));
  EXPECT_EQ("n2", ResolveAs("/q/1").resolution);
  /* A named segment and `*` score alike: `*` registered first wins the tie. */
  ASSERT_EQ(GDEFCORE_OK, AddPage("s1", "/r/*", &literal));
  ASSERT_EQ(GDEFCORE_OK, AddPage("s2", "/r/:id", &named));
  EXPECT_EQ("s1", ResolveAs("/r/1").resolution);
}

TEST_F(Routes, KindsAndEnumeration) {
  H h{"h", true};
  GDEFCORE_Route_Spec spec;
  ASSERT_EQ(GDEFCORE_OK, AddPage("p", "/p/:id", &h));
  const char * names[] = {"b.tab", "a.tab", "c.tab", "d.tab"};
  int weights[] = {2, 2, 1, 2};
  size_t i;
  for (i = 0; i < 4; i++) {
    spec = Spec(names[i], "/p/:id/t", RunCall, &h);
    spec.kind = GDEFCORE_ROUTE_TAB;
    spec.parent = "p";
    spec.parent_len = 1;
    spec.weight = weights[i];
    spec.permission = "Perm";
    spec.permission_len = 4;
    spec.title = "T\xc3\xa9";
    spec.title_len = 3;
    ASSERT_EQ(GDEFCORE_OK, Add(spec)) << names[i];
  }
  /* An action and a page: kinds that a tab list must not include. */
  spec = Spec("act", "/p/:id/add", RunCall, &h);
  spec.kind = GDEFCORE_ROUTE_ACTION;
  ASSERT_EQ(GDEFCORE_OK, Add(spec));
  /* Weight order, then machine name: c(1) then a, b, d (2). */
  std::vector<std::string> rows;
  std::vector<std::string> got = Tabs("p", &rows);
  ASSERT_EQ(4u, got.size());
  EXPECT_EQ("c.tab", got[0]);
  EXPECT_EQ("a.tab", got[1]);
  EXPECT_EQ("b.tab", got[2]);
  EXPECT_EQ("d.tab", got[3]);
  EXPECT_EQ("c.tab|/p/:id/t|T\xc3\xa9|Perm|kind=1|def=0|w=1", rows[0]);
  /* The kind does not change dispatch: the action answers like a page. */
  EXPECT_EQ("act", ResolveAs("/p/3/add").resolution);
  /* An unknown parent and a parent with no tabs: success, nothing. */
  EXPECT_TRUE(Tabs("nope").empty());
  EXPECT_TRUE(Tabs("act").empty());
  GDEFCORE_Route_Info * info = (GDEFCORE_Route_Info *)0x1;
  size_t count = 5;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_tabs(routes_, "nope", 4, &info, &count));
  EXPECT_EQ(nullptr, info);
  EXPECT_EQ(0u, count);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_routes_tabs(NULL, "p", 1, &info, &count));
}

TEST_F(Routes, CapturesAreRawSegments) {
  ASSERT_EQ(GDEFCORE_OK, AddPage("c", "/c/:id/x", &own_));
  /* Percent-encoded segments are not decoded. */
  EXPECT_EQ("own id=%34%32|", ResolveAs("/c/%34%32/x").ran);
  EXPECT_EQ("own id=a%2Fb|", ResolveAs("/c/a%2Fb/x").ran);
  /* Empty segments do not exist: // collapses, as it always did. */
  EXPECT_EQ("own id=7|", ResolveAs("//c///7//x//").ran);
  /* A segment that is itself ":id" or "*" is a value. */
  EXPECT_EQ("own id=:id|", ResolveAs("/c/:id/x").ran);
  EXPECT_EQ("own id=*|", ResolveAs("/c/*/x").ran);
  /* A very long segment and a very long request are captured whole. */
  std::string big(100000, 'z');
  EXPECT_EQ("own id=" + big + "|", ResolveAs("/c/" + big + "/x").ran);
  std::string many = "/c/1/x";
  for (int i = 0; i < 5000; i++) {
    many += "/s" + std::to_string(i);
  }
  EXPECT_EQ("own id=1|", ResolveAs(many).ran);
  /* UTF-8 in a value is a value. */
  EXPECT_EQ("own id=caf\xc3\xa9|", ResolveAs("/c/caf\xc3\xa9/x").ran);
}

TEST_F(Routes, PatternLimits) {
  std::string name64(GDEFCORE_ROUTE_NAME_MAX, 'a');
  std::string name65(GDEFCORE_ROUTE_NAME_MAX + 1, 'a');
  EXPECT_EQ(GDEFCORE_OK, Add(Spec("n64", ("/p/:" + name64).c_str(), RunCall, &own_)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      Add(Spec("n65", ("/p/:" + name65).c_str(), RunCall, &own_)));
  std::string caps16 = "/m";
  std::string caps17;
  int i;
  for (i = 0; i < GDEFCORE_ROUTE_CAPTURE_MAX; i++) {
    caps16 += "/:c" + std::to_string(i);
  }
  caps17 = caps16 + "/:extra";
  EXPECT_EQ(GDEFCORE_OK, Add(Spec("c16", caps16.c_str(), RunCall, &own_)));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(Spec("c17", caps17.c_str(), RunCall, &own_)));
  /* Literals and stars are not captures: many of them are fine. */
  std::string stars = "/s";
  for (i = 0; i < 40; i++) {
    stars += "/*";
  }
  EXPECT_EQ(GDEFCORE_OK, Add(Spec("stars", stars.c_str(), RunCall, &own_)));
  /* A pattern past the path limit is refused by the new call, and the old
   * call has no such limit (it is unchanged). */
  std::string longp = "/" + std::string(GDEFCORE_ROUTE_PATH_MAX, 'l');
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Add(Spec("long", longp.c_str(), RunCall, &own_)));
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_route_add(routes_, "oldlong", 7, longp.data(), longp.size(), 0, 0,
          OldRun, &own_, NULL, NULL));
}

/* An independent statement of what a pattern is, to compare the library to. */
bool RefValid(const std::string & path, std::vector<std::string> * names) {
  size_t i = 0;
  names->clear();
  if (path.empty() || path[0] != '/' || path.size() > GDEFCORE_ROUTE_PATH_MAX) {
    return false;
  }
  /* [a-z][a-z0-9_]{0,63} */
  auto name_ok = [](const std::string & name) {
    if (name.empty() || name.size() > 64 || name[0] < 'a' || name[0] > 'z') {
      return false;
    }
    for (char c : name) {
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
        return false;
      }
    }
    return true;
  };
  while (i < path.size()) {
    size_t j;
    std::string seg;
    if (path[i] == '/') {
      i++;
      continue;
    }
    j = path.find('/', i);
    if (j == std::string::npos) {
      j = path.size();
    }
    seg = path.substr(i, j - i);
    i = j;
    if (seg[0] == ':') {
      std::string name = seg.substr(1);
      if (!name_ok(name)) {
        return false;
      }
      for (size_t k = 0; k < names->size(); k++) {
        if ((*names)[k] == name) {
          return false;
        }
      }
      if (names->size() == GDEFCORE_ROUTE_CAPTURE_MAX) {
        return false;
      }
      names->push_back(name);
    }
  }
  return true;
}

TEST_F(Routes, HostilePatternSweep) {
  static const char * const kTok[] = {"/", "/", "//", "a", "b", ":x", ":y", ":X",
      ":", ":1", ":\xc3\xa9", "*", "%41", ":%41", ":a_b", ":x", ":_", ":a-b",
      ":a b", ":A", "\x01", ":z9", "x:y"};
  uint32_t state = 12345;
  size_t made = 0;
  size_t accepted = 0;
  size_t refused = 0;
  size_t verified = 0;
  size_t round;
  auto next = [&state]() {
    state = state * 1664525u + 1013904223u;
    return state >> 8;
  };
  for (round = 0; round < 6000; round++) {
    std::string pattern = "/";
    std::vector<std::string> names;
    size_t parts = 1 + next() % 8;
    size_t k;
    GDEFCORE_Route_Spec spec;
    GDEFCORE_Result rc;
    std::string machine = "m" + std::to_string(round);
    if (next() % 7 == 0) {
      pattern = "";
    }
    for (k = 0; k < parts; k++) {
      pattern += kTok[next() % (sizeof kTok / sizeof kTok[0])];
      if (next() % 3 != 0) {
        pattern += "/";
      }
    }
    if (next() % 41 == 0) {
      pattern += "/:" + std::string(60 + next() % 10, 'n');
    }
    spec = Spec(machine.c_str(), pattern.c_str(), RunCall, &own_);
    spec.path_len = pattern.size();
    bool expect = RefValid(pattern, &names);
    rc = Add(spec);
    made++;
    ASSERT_EQ(expect ? GDEFCORE_OK : GDEFCORE_ERR_INVALID, rc)
        << "pattern [" << pattern << "] reference says " << expect;
    if (rc != GDEFCORE_OK) {
      refused++;
      continue;
    }
    accepted++;
    if (verified < 300 && names.size() <= 5 && pattern.find('%') == std::string::npos) {
      /* Build the request that fills each capture, in a table of its own so
       * no other route answers, and compare the captures with the pattern's. */
      GDEFCORE_Routes * own_table = NULL;
      GDEFCORE_Routes * saved = routes_;
      std::string request;
      std::string expect_line = "own";
      size_t i = 0;
      std::string vals;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &own_table));
      routes_ = own_table;
      ASSERT_EQ(GDEFCORE_OK, Add(spec));
      while (i < pattern.size()) {
        size_t j;
        std::string seg;
        if (pattern[i] == '/') {
          i++;
          continue;
        }
        j = pattern.find('/', i);
        if (j == std::string::npos) {
          j = pattern.size();
        }
        seg = pattern.substr(i, j - i);
        i = j;
        if (seg[0] == ':') {
          std::string v = "v" + std::to_string(request.size());
          request += "/" + v;
          if (seg.substr(1) == "id" || seg.substr(1) == "x" || seg.substr(1) == "y" ||
              seg.substr(1) == "rev" || seg.substr(1) == "name") {
            vals += " " + seg.substr(1) + "=" + v;
          }
        } else if (seg == "*") {
          request += "/w";
        } else {
          request += "/" + seg;
        }
      }
      if (request.empty()) {
        request = "/";
      }
      /* The log lists captures in kNames order. */
      std::string ordered;
      for (size_t n = 0; n < sizeof kNames / sizeof kNames[0]; n++) {
        size_t at = vals.find(std::string(" ") + kNames[n] + "=");
        if (at != std::string::npos) {
          size_t end = vals.find(' ', at + 1);
          ordered += vals.substr(at, end == std::string::npos ? end : end - at);
        }
      }
      Seen seen = ResolveAs(request);
      EXPECT_EQ("own" + ordered + "|", seen.ran) << pattern << " <- " << request;
      routes_ = saved;
      gdefcore_routes_destroy(own_table);
      verified++;
    }
  }
  /* The sweep saw both sides (a sweep with one side proves nothing). */
  EXPECT_GT(accepted, 200u);
  EXPECT_GT(refused, 200u);
  EXPECT_GT(verified, 50u);
  EXPECT_EQ(made, accepted + refused);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
