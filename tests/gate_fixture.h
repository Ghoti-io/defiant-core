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
 * What the AD-25 gates that read as a principal share: one site on the memory
 * backend (Site), two worlds that differ only in what a principal may not see
 * (World), and a probe (Observe) that asks every principal-parameterized read
 * surface of defiant-core the same questions and writes the answers down.
 *
 * Header only. Every function is inline so a test file that does not use one
 * does not warn.
 */

#ifndef GHOTI_DEFCORE_TEST_GATE_FIXTURE_H
#define GHOTI_DEFCORE_TEST_GATE_FIXTURE_H

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace gate {

const uint64_t kLife = 3600;

/* The functions the probe has called, by public name. A gate that claims to
 * cover a surface is held to having called it. */
inline std::set<std::string> & Called() {
  static std::set<std::string> names;
  return names;
}

inline void Note(const char * name) {
  Called().insert(name);
}

inline std::string Rc(GDEFCORE_Result rc) {
  return gdefcore_result_string(rc);
}

inline void OneValue(GDEFCORE_Value * value, const char * field,
    const char * text, const char ** slot, size_t * len_slot) {
  memset(value, 0, sizeof *value);
  *slot = text;
  *len_slot = strlen(text);
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = slot;
  value->text_lens = len_slot;
  value->count = 1;
}

inline GDEFCORE_Permission Perm(const char * label, const char * action,
    int condition, const char * type, const char * field) {
  GDEFCORE_Permission permission;
  memset(&permission, 0, sizeof permission);
  permission.size = sizeof permission;
  permission.label = label;
  permission.label_len = strlen(label);
  permission.module_name = "notes";
  permission.module_name_len = 5;
  permission.action = action;
  permission.action_len = strlen(action);
  permission.condition = condition;
  permission.type_name = type;
  permission.type_name_len = strlen(type);
  if (field != NULL) {
    permission.field = field;
    permission.field_len = strlen(field);
  }
  return permission;
}

/** One tenant on a store: catalog, keyring, a logged-in admin request. */
struct Site {
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Keyring * keyring = NULL;
  uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
  std::string tenant;
  std::string session;
  GDEFCORE_Request * admin = NULL;

  /** The store is borrowed. */
  void Open(GDEFSTOR_Store * s, const std::string & name, uint8_t root_byte) {
    store = s;
    tenant = name;
    memset(root, root_byte, sizeof root);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store, (const uint8_t *)tenant.data(),
            tenant.size(), NULL, NULL, &catalog));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_keyring_create(root, sizeof root, NULL, &keyring));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)tenant.data(), tenant.size(),
            0, 0, NULL, &admin));
  }

  void Close() {
    gdefcore_request_destroy(admin);
    gdefcore_keyring_destroy(keyring);
    gdefcore_catalog_destroy(catalog);
    admin = NULL;
    keyring = NULL;
    catalog = NULL;
  }

  GDEFCORE_Request * NewRequest(const std::string & principal = std::string()) {
    GDEFCORE_Request * request = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create((const uint8_t *)tenant.data(), tenant.size(),
            0, 0, NULL, &request));
    if (!principal.empty()) {
      EXPECT_EQ(GDEFCORE_OK,
          gdefcore_request_set_principal(request, principal.data(),
              principal.size()));
    }
    return request;
  }

  void Login() {
    char who[GDEFCORE_PUBLIC_ID_LEN + 1];
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    char * token = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(catalog, who));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_bind(catalog, keyring, root, sizeof root, who,
            strlen(who), "ada", 3, "secret", 6, id));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_login(catalog, keyring, root, sizeof root, "ada", 3,
            "secret", 6, kLife, &token, &n));
    session.assign(token, n);
    gdefcore_text_free(catalog, token);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_account_check(catalog, admin, keyring, root, sizeof root,
            session.data(), session.size()));
  }

  void InstallKit() {
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog, bytes, n));
    gdefcore_text_free(catalog, (char *)bytes);
  }

  /** Make a site.post through a signed form, as Render's tests do. */
  std::string Post(const char * alias, const char * title, const char * body,
      bool publish) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Value values[2];
    const char * slots[2];
    size_t lens[2];
    int conflict = 1;
    char * token = NULL;
    size_t token_len = 0;
    id[0] = '\0';
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog, "site.post", 9, id, NULL));
    OneValue(&values[0], "title", title, &slots[0], &lens[0]);
    OneValue(&values[1], "body", body, &slots[1], &lens[1]);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_form_sign(catalog, admin, keyring, root, sizeof root,
            session.data(), session.size(), "edit", 4, id, strlen(id), "en", 2,
            values, 2, alias, strlen(alias), &token, &token_len));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_form_submit(catalog, admin, keyring, root, sizeof root,
            session.data(), session.size(), token, token_len, &conflict));
    gdefcore_text_free(catalog, token);
    if (publish) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_form_publish(catalog, id, strlen(id)));
    }
    return std::string(id);
  }

  void DefineNote() {
    GDEFCORE_Field fields[2];
    memset(fields, 0, sizeof fields);
    fields[0].size = sizeof fields[0];
    fields[0].name = "title";
    fields[0].name_len = 5;
    fields[0].required = 1;
    fields[1].size = sizeof fields[1];
    fields[1].name = "secret";
    fields[1].name_len = 6;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog, "site.note", 9, GDEFCORE_TYPE_CONTENT,
            fields, 2));
  }

  void Declare(const GDEFCORE_Permission & permission) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_declare(catalog, &permission));
  }

  void Grant(const char * role, const char * label) {
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_grant(catalog, role, strlen(role), label, strlen(label),
            "core.role", 9));
  }

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

  /** A site.note saved by @p actor (empty: no actor). */
  std::string SaveNote(const std::string & actor, const char * title,
      const char * secret) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * changeset = NULL;
    GDEFCORE_Value values[2];
    const char * slots[2];
    size_t lens[2];
    id[0] = '\0';
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog, "site.note", 9, id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog, actor.empty() ? NULL : actor.data(),
            actor.size(), &changeset));
    OneValue(&values[0], "title", title, &slots[0], &lens[0]);
    OneValue(&values[1], "secret", secret, &slots[1], &lens[1]);
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(changeset, id, strlen(id), "en", 2, values, 2));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, NULL, 0));
    gdefcore_changeset_destroy(changeset);
    return std::string(id);
  }
};

inline std::string FreshId() {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  EXPECT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
  return std::string(id);
}

/** A route handler that owns the request and resolves to the id in @p data. */
inline void EchoRoute(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  const std::string * id = (const std::string *)data;
  (void)machine;
  (void)machine_len;
  gdefcore_request_set_resolution(request, id->data(), id->size());
}

/** A guarded route's handler: it owns the request and resolves to the id its
 * `:id` segment holds. Reached only where the access check says yes. */
inline void GuardRoute(const GDEFCORE_Route_Call * call) {
  const char * value = NULL;
  size_t n = 0;
  if (gdefcore_route_call_capture(call, "id", 2, &value, &n)) {
    gdefcore_request_set_resolution(call->request, value, n);
  }
}

/** A route handler that sets nothing and falls through. */
inline void DeclineRoute(GDEFCORE_Request * request, const char * machine,
    size_t machine_len, void * data) {
  (void)request;
  (void)machine;
  (void)machine_len;
  (void)data;
}

/**
 * One site plus a module host, a route table and the names of the entities a
 * probe aims at. Two worlds built by the same recipe differ only in whether
 * the entities a principal may not see exist; where they do not, the name
 * maps to an id that was never created.
 */
struct World {
  GDEFSTOR_Store * store = NULL;
  Site site;
  GDEFCORE_Host * host = NULL;
  GDEFCORE_Routes * routes = NULL;
  bool posts = false;                      ///< The Post kit is installed.
  std::map<std::string, std::string> id;   ///< target name -> public id
  std::map<std::string, std::string> label; ///< public id -> target name
  std::set<std::string> hidden;            ///< targets the probed principal may not see
  std::vector<std::string> titles;         ///< title texts to filter by
  std::vector<std::string> secrets;        ///< secret texts to filter by
  std::map<std::string, std::string> principal; ///< role name -> principal id

  void Open() {
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store));
    site.Open(store, "t", 0x42);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store, NULL, &host));
    gdefcore_catalog_bind_host(site.catalog, host);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
  }

  void Close() {
    gdefcore_routes_destroy(routes);
    gdefcore_catalog_bind_host(site.catalog, NULL);
    gdefcore_host_destroy(host);
    site.Close();
    gdefstor_store_destroy(store);
    routes = NULL;
    host = NULL;
    store = NULL;
  }

  /** Name a target. @p real empty makes it an id that was never created. */
  void Target(const std::string & name, const std::string & real,
      bool is_hidden) {
    std::string use = real.empty() ? FreshId() : real;
    id[name] = use;
    label[use] = name;
    if (is_hidden) {
      hidden.insert(name);
    }
  }

  /** Register an echo route per target and the decline route. */
  void Routes() {
    std::map<std::string, std::string>::iterator it;
    char * err = NULL;
    size_t err_len = 0;
    for (it = id.begin(); it != id.end(); ++it) {
      std::string path = "/echo/" + it->first;
      std::string machine = "echo-" + it->first;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_route_add(routes, machine.data(), machine.size(),
              path.data(), path.size(), 0, 0, EchoRoute, &it->second, &err,
              &err_len));
    }
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_route_add(routes, "decline", 7, "/dup-hidden", 11, 0, 0,
            DeclineRoute, NULL, &err, &err_len));
    /* A route that is there only for a principal who holds `read` for the
     * entity its :id names: the ready-made access check decides. */
    {
      GDEFCORE_Route_Spec spec;
      memset(&spec, 0, sizeof spec);
      spec.size = sizeof spec;
      spec.machine = "guard";
      spec.machine_len = 5;
      spec.path = "/guard/:id";
      spec.path_len = 10;
      spec.call_fn = GuardRoute;
      spec.permission = "read";
      spec.permission_len = 4;
      spec.entity_capture = "id";
      spec.entity_capture_len = 2;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_route_add_spec(routes, &spec, &err, &err_len));
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_routes_set_check(routes, gdefcore_access_route_check,
              site.catalog));
    }
  }

  GDEFCORE_Request * Req(const std::string & who = std::string()) {
    return site.NewRequest(who);
  }
};

/**
 * World "S": a principal who may see nothing. Entities that exist but that
 * principal may not read: two notes (no role holds a grant on them), a
 * published post (the kit grants only the anonymous state, and the
 * principal is not anonymous), a draft post, and a published post whose alias
 * a route handler also claims. With @p with_hidden false none of them exist.
 *
 * Roles for the controls: "readers" may read every note.
 */
inline void BuildS(World * w, bool with_hidden) {
  Site & s = w->site;
  w->Open();
  s.DefineNote();
  s.Declare(Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, "site.note", NULL));
  s.Role("readers");
  s.Grant("readers", "Read notes");
  s.InstallKit();
  w->posts = true;
  s.Login();
  w->principal["none"] = s.Principal();
  w->principal["other"] = s.Principal();
  w->principal["readers"] = s.Principal("readers");
  w->titles = {"Hidden Note One", "Hidden Note Two", "nothing"};
  w->secrets = {"S-ONE-CANARY", "S-TWO-CANARY"};
  w->Target("note1",
      with_hidden ? s.SaveNote(w->principal["other"], "Hidden Note One",
                        "S-ONE-CANARY")
                  : "",
      true);
  w->Target("note2",
      with_hidden ? s.SaveNote(w->principal["other"], "Hidden Note Two",
                        "S-TWO-CANARY")
                  : "",
      true);
  w->Target("pub",
      with_hidden ? s.Post("/pub-hidden", "PubHiddenTitle", "PubBodyCanary", true)
                  : "",
      true);
  w->Target("draft",
      with_hidden ? s.Post("/draft-hidden", "DraftHiddenTitle",
                        "DraftBodyCanary", false)
                  : "",
      true);
  w->Target("dup",
      with_hidden ? s.Post("/dup-hidden", "DupHiddenTitle", "DupBodyCanary", true)
                  : "",
      true);
  w->Target("missing", "", false);
  w->Routes();
}

/**
 * World "T": a principal who may read their own notes and not the field
 * `secret`. Variant X also holds other people's notes; variant Y does not,
 * and the two own notes carry swapped secrets, so the only differences are
 * things the principal may not read. "all" may read every note and the secret.
 */
inline void BuildT(World * w, bool variant_x) {
  Site & s = w->site;
  w->Open();
  s.DefineNote();
  s.Declare(Perm("Read own notes", "read", GDEFCORE_ACCESS_OWN, "site.note",
      NULL));
  s.Declare(Perm("Read notes", "read", GDEFCORE_ACCESS_ANY, "site.note", NULL));
  s.Declare(Perm("Read secret", "read", GDEFCORE_ACCESS_ANY, "site.note",
      "secret"));
  s.Role("writers");
  s.Grant("writers", "Read own notes");
  s.Role("all");
  s.Grant("all", "Read notes");
  s.Grant("all", "Read secret");
  w->principal["writer"] = s.Principal("writers");
  w->principal["other"] = s.Principal();
  w->principal["all"] = s.Principal("all");
  w->titles = {"mine", "mine2", "theirs1", "theirs2", "nothing"};
  w->secrets = {"alpha", "omega", "beta", "gamma"};
  w->Target("mine",
      s.SaveNote(w->principal["writer"], "mine", variant_x ? "alpha" : "omega"),
      false);
  w->Target("mine2",
      s.SaveNote(w->principal["writer"], "mine2", variant_x ? "omega" : "alpha"),
      false);
  w->Target("theirs1",
      variant_x ? s.SaveNote(w->principal["other"], "theirs1", "beta") : "",
      true);
  w->Target("theirs2",
      variant_x ? s.SaveNote(w->principal["other"], "theirs2", "gamma") : "",
      true);
  w->Target("missing", "", false);
  w->Routes();
}

/** Replace every id in @p text by its target name, or by <ID?>. */
inline std::string Norm(const World & w, std::string text,
    bool blank_all = false) {
  static const char kAlpha[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  std::map<std::string, std::string>::const_iterator it;
  size_t at;
  std::string out;
  if (blank_all) {
    for (it = w.label.begin(); it != w.label.end(); ++it) {
      while ((at = text.find(it->first)) != std::string::npos) {
        text.replace(at, it->first.size(), "<ID>");
      }
    }
  } else {
    for (it = w.label.begin(); it != w.label.end(); ++it) {
      while ((at = text.find(it->first)) != std::string::npos) {
        text.replace(at, it->first.size(), "<" + it->second + ">");
      }
    }
  }
  /* Principals and any other id: a run of 28 symbols. */
  {
    size_t i = 0;
    while (i < text.size()) {
      size_t j = i;
      while (j < text.size() && text[j] != '\0' &&
             strchr(kAlpha, text[j]) != NULL) {
        j += 1;
      }
      if (j - i >= (size_t)GDEFCORE_PUBLIC_ID_LEN) {
        out += "<ID?>";
        i = j;
      } else {
        out += text.substr(i, j > i ? j - i : 1);
        i = j > i ? j : i + 1;
      }
    }
  }
  return out;
}

/** What one probe wrote down. */
struct Obs {
  std::map<std::string, std::string> kv;
};

/** A fresh request for one probe, so no probe sees another's leftovers. */
struct Fresh {
  GDEFCORE_Request * req;
  Fresh(World & w, const std::string & who) : req(w.Req(who)) {}
  ~Fresh() { gdefcore_request_destroy(req); }
  Fresh(const Fresh &) = delete;
  Fresh & operator=(const Fresh &) = delete;
};

inline std::string Diag(World & w, GDEFCORE_Request * req) {
  size_t n = 0;
  const char * res = gdefcore_request_resolution(req, &n);
  const char * err = gdefcore_module_error(w.host, NULL);
  std::string out = " | status=" + Rc(gdefcore_request_status(req));
  out += " res=" + (res == NULL ? std::string("-") : Norm(w, std::string(res, n), true));
  out += " err=" + std::string(err == NULL ? "-" : err);
  out += " skipped=" + std::to_string(gdefcore_hook_skipped(w.host));
  return out;
}

inline std::string ReadLine(World & w, const std::string & who,
    const std::string & id, const char * field) {
  Fresh fresh(w, who);
  GDEFCORE_Request * req = fresh.req;
  char ** texts = (char **)0x1;
  size_t * lens = (size_t *)0x1;
  size_t count = 99;
  std::string out;
  GDEFCORE_Result rc;
  Note("gdefcore_access_read");
  rc = gdefcore_access_read(w.site.catalog, req, id.data(), id.size(), "en", 2,
      field, strlen(field), &texts, &lens, &count);
  out = "rc=" + Rc(rc);
  if (texts == (char **)0x1 && lens == (size_t *)0x1 && count == 99) {
    out += " untouched";
  } else if (rc != GDEFCORE_OK) {
    out += " WROTE-ON-FAILURE";
  }
  if (rc == GDEFCORE_OK) {
    size_t i;
    out += " count=" + std::to_string(count);
    for (i = 0; i < count; i++) {
      out += " [" + std::string(texts[i], lens[i]) + "]";
    }
    gdefcore_values_free(w.site.catalog, texts, lens, count);
  }
  return out + Diag(w, req);
}

inline std::string ListLine(World & w, const std::string & who, const char * type,
    const char * ff, const std::string & ft, const char * sf,
    const char * lang = "en") {
  Fresh fresh(w, who);
  GDEFCORE_Request * req = fresh.req;
  GDEFCORE_Access_List q;
  char ** ids = (char **)0x1;
  size_t count = 99;
  std::string out;
  GDEFCORE_Result rc;
  memset(&q, 0, sizeof q);
  q.size = sizeof q;
  q.type_name = type;
  q.type_name_len = strlen(type);
  q.lang = lang;
  q.lang_len = strlen(lang);
  if (ff != NULL) {
    q.filter_field = ff;
    q.filter_field_len = strlen(ff);
    q.filter_text = ft.c_str();
    q.filter_text_len = ft.size();
  }
  if (sf != NULL) {
    q.sort_field = sf;
    q.sort_field_len = strlen(sf);
  }
  Note("gdefcore_access_list");
  rc = gdefcore_access_list(w.site.catalog, req, &q, &ids, &count);
  out = "rc=" + Rc(rc);
  if (rc != GDEFCORE_OK) {
    /* The contract: a refusal returns no rows, as a null list and zero. */
    out += " ids=" + std::string(ids == NULL ? "null" : "set") +
           " count=" + std::to_string(count);
  } else {
    size_t i;
    out += " count=" + std::to_string(count) + " ids=";
    for (i = 0; i < count; i++) {
      std::map<std::string, std::string>::const_iterator at =
          w.label.find(ids[i]);
      out += (i > 0 ? "," : "") +
             (at == w.label.end() ? std::string("?") : at->second);
    }
    gdefcore_access_free(w.site.catalog, ids, count);
  }
  return out + Diag(w, req);
}

inline std::string PageLine(World & w, const std::string & who, bool with_routes,
    const std::string & path) {
  Fresh fresh(w, who);
  GDEFCORE_Request * req = fresh.req;
  char * bytes = (char *)0x1;
  size_t n = 99;
  std::string out;
  GDEFCORE_Result rc;
  Note("gdefcore_render_page");
  rc = gdefcore_render_page(w.site.catalog, with_routes ? w.routes : NULL, req,
      path.data(), path.size(), GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
  out = "rc=" + Rc(rc);
  if (bytes == (char *)0x1 && n == 99) {
    out += " untouched";
  } else if (rc != GDEFCORE_OK) {
    out += " WROTE-ON-FAILURE";
  }
  if (rc == GDEFCORE_OK && bytes != NULL) {
    out += " bytes=" + Norm(w, std::string(bytes, n));
    gdefcore_text_free(w.site.catalog, bytes);
  }
  return out + Diag(w, req);
}

inline std::string ResolveLine(World & w, const std::string & who,
    bool with_routes, const std::string & path, bool blank_ids) {
  Fresh fresh(w, who);
  GDEFCORE_Request * req = fresh.req;
  char * out_text = (char *)0x1;
  size_t n = 99;
  std::string out;
  GDEFCORE_Result rc;
  Note("gdefcore_form_resolve");
  rc = gdefcore_form_resolve(with_routes ? w.routes : NULL, w.site.catalog, req,
      path.data(), path.size(), &out_text, &n);
  out = "rc=" + Rc(rc);
  if (out_text == (char *)0x1 && n == 99) {
    out += " untouched";
  } else if (rc != GDEFCORE_OK) {
    out += " WROTE-ON-FAILURE";
  }
  if (rc == GDEFCORE_OK && out_text != NULL) {
    out += " id=" + Norm(w, std::string(out_text, n), blank_ids);
    gdefcore_text_free(w.site.catalog, out_text);
  }
  return out + Diag(w, req);
}

inline std::string KeyLine(World & w, const std::string & who) {
  Fresh fresh(w, who);
  GDEFCORE_Request * req = fresh.req;
  char * key = NULL;
  size_t n = 0;
  std::string out;
  GDEFCORE_Result rc;
  Note("gdefcore_access_render_key");
  rc = gdefcore_access_render_key(w.site.catalog, req, NULL, 0, NULL, 0, &key,
      &n);
  out = "rc=" + Rc(rc);
  if (rc == GDEFCORE_OK && key != NULL) {
    std::string text(key, n);
    size_t at = text.find("\nepoch:");
    if (at != std::string::npos) {
      size_t end = text.find('\n', at + 1);
      /* The epoch counts every applied changeset, hidden ones included: see
       * Oracle.RenderKeyEpoch. Masked here so the rest of the key is compared. */
      text.replace(at, end == std::string::npos ? std::string::npos : end - at,
          "\nepoch:N");
    }
    out += " key=" + Norm(w, text);
    gdefcore_text_free(w.site.catalog, key);
  }
  return out;
}

/**
 * One condition evaluated on one id, as the principal's request. The false
 * condition reads every operand the entity offers (type, state, actor, a
 * field) and holds for nothing, so a hidden entity and a missing one must
 * answer alike. The true one (only when asked) holds for any note or post
 * that exists: a control, which shows the sweep can see an entity at all.
 */
inline std::string CondLine(World & w, const std::string & who,
    const std::string & id, bool holds) {
  static const char kFalse[] =
      "(or (= field.title \"no-such-title-anywhere\") (= type \"no.such.type\")"
      " (= state \"nonesuch\") (= actor \"nobody\") (= principal \"nobody\"))";
  static const char kTrue[] = "(in type (\"site.note\" \"site.post\"))";
  const char * text = holds ? kTrue : kFalse;
  Fresh fresh(w, who);
  GDEFCORE_Condition * cond = NULL;
  GDEFCORE_Condition_Subject subject;
  int failed = 99;
  int allow;
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_condition_parse(text, strlen(text), &cond, NULL));
  memset(&subject, 0, sizeof subject);
  subject.size = sizeof subject;
  subject.entity = id.data();
  subject.entity_len = id.size();
  Note("gdefcore_condition_eval");
  allow = gdefcore_condition_eval(w.site.catalog, fresh.req, cond, &subject,
      &failed);
  gdefcore_condition_free(cond);
  return "allow=" + std::to_string(allow) + " failed=" + std::to_string(failed) +
         Diag(w, fresh.req);
}

/** gdefcore_access_can for one permission of one type, on an id (or none). */
inline std::string CanLine(World & w, const std::string & who,
    const std::string & id, const char * permission, const char * type) {
  Fresh fresh(w, who);
  int allowed = 99;
  GDEFCORE_Result rc;
  Note("gdefcore_access_can");
  rc = gdefcore_access_can(w.site.catalog, fresh.req, permission,
      strlen(permission), type, strlen(type), id.empty() ? NULL : id.c_str(),
      &allowed);
  return "rc=" + Rc(rc) + " allowed=" + std::to_string(allowed) +
         Diag(w, fresh.req);
}

/** What to ask. */
struct Ask {
  bool posts = false;                 ///< Ask the site.post surfaces too.
  std::vector<std::string> targets;   ///< Target names to aim per-target probes at.
  bool cond_true = false;             ///< Also ask a condition that HOLDS (a control).
};

/**
 * Ask every principal-parameterized read surface the same questions and
 * write the answers down. Keys beginning "t:<name>:" are per target; the
 * rest are global. The surfaces are the RF rows of gate_surface.h.
 */
inline Obs Observe(World & w, const std::string & who, const Ask & ask) {
  Obs o;
  std::vector<std::string>::const_iterator t;
  size_t i;
  for (t = ask.targets.begin(); t != ask.targets.end(); ++t) {
    const std::string & name = *t;
    const std::string & target = w.id[name];
    std::string pre = "t:" + name + ":";
    o.kv[pre + "read.title"] = ReadLine(w, who, target, "title");
    o.kv[pre + "read.secret"] = ReadLine(w, who, target, "secret");
    o.kv[pre + "read.nope"] = ReadLine(w, who, target, "nope");
    o.kv[pre + "resolve.echo"] =
        ResolveLine(w, who, true, "/echo/" + name, true);
    o.kv[pre + "cond.false"] = CondLine(w, who, target, false);
    o.kv[pre + "can.read"] = CanLine(w, who, target, "read", "site.note");
    o.kv[pre + "can.update"] = CanLine(w, who, target, "update", "site.note");
    o.kv[pre + "resolve.guard"] =
        ResolveLine(w, who, true, "/guard/" + target, true);
    if (ask.cond_true) {
      o.kv[pre + "cond.true"] = CondLine(w, who, target, true);
    }
    if (ask.posts) {
      o.kv[pre + "page.echo"] = PageLine(w, who, true, "/echo/" + name);
    }
  }
  {
    std::string notes = "site.note";
    o.kv["g:list.notes"] = ListLine(w, who, "site.note", NULL, "", NULL);
    o.kv["g:list.notes.fr"] = ListLine(w, who, "site.note", NULL, "", NULL, "fr");
    for (i = 0; i < w.titles.size(); i++) {
      o.kv["g:list.notes.title=" + w.titles[i]] =
          ListLine(w, who, "site.note", "title", w.titles[i], NULL);
    }
    for (i = 0; i < w.secrets.size(); i++) {
      o.kv["g:list.notes.secret=" + w.secrets[i]] =
          ListLine(w, who, "site.note", "secret", w.secrets[i], NULL);
    }
    o.kv["g:list.notes.filter-nope"] =
        ListLine(w, who, "site.note", "nope", "x", NULL);
    o.kv["g:list.notes.sort-title"] =
        ListLine(w, who, "site.note", NULL, "", "title");
    o.kv["g:list.notes.sort-secret"] =
        ListLine(w, who, "site.note", NULL, "", "secret");
    o.kv["g:list.notes.sort-nope"] =
        ListLine(w, who, "site.note", NULL, "", "nope");
    o.kv["g:list.notes.title+sort-secret"] =
        ListLine(w, who, "site.note", "title", w.titles[0], "secret");
    o.kv["g:list.notes.secret+sort-title"] =
        ListLine(w, who, "site.note", "secret", w.secrets[0], "title");
  }
  o.kv["g:render-key"] = KeyLine(w, who);
  o.kv["g:can-type.read"] = CanLine(w, who, std::string(), "read", "site.note");
  o.kv["g:can-type.undeclared"] =
      CanLine(w, who, std::string(), "frobnicate", "site.note");
  {
    /* The permission to edit templates is held by nobody here, and a preview
     * of a body is the answer a missing kind gets. */
    static const char kEdit[] = "core.template.edit.core.pane";
    static const char kBody[] = "<p>sweep</p>";
    char * bytes = (char *)0x1;
    size_t n = 99;
    int shareable = 99;
    GDEFCORE_Result rc;
    Fresh f(w, who);
    Note("gdefcore_access_permits");
    o.kv["g:permits"] = "held=" +
        std::to_string(gdefcore_access_permits(w.site.catalog, f.req, kEdit,
            strlen(kEdit))) + Diag(w, f.req);
    Note("gdefcore_template_may_edit");
    o.kv["g:may-edit"] = "held=" +
        std::to_string(gdefcore_template_may_edit(w.site.catalog, f.req,
            "core.pane", 9)) + Diag(w, f.req);
    Note("gdefcore_render_sample");
    rc = gdefcore_render_sample(w.site.catalog, f.req, "core.pane", 9, kBody,
        strlen(kBody), "preview", 7, GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n,
        &shareable);
    o.kv["g:render-sample"] = "rc=" + Rc(rc) +
        (bytes == (char *)0x1 && n == 99 ? " untouched" : " WROTE") +
        " shareable=" + std::to_string(shareable) + Diag(w, f.req);
    if (rc == GDEFCORE_OK) {
      gdefcore_text_free(w.site.catalog, bytes);
    }
  }
  {
    /* The matrix of grants is for administrators: anyone else is told what a
     * page that is not there is told, and gets no row. */
    GDEFCORE_Access_Matrix_Row * rows = (GDEFCORE_Access_Matrix_Row *)0x1;
    size_t n = 99;
    GDEFCORE_Result rc;
    Fresh f(w, who);
    Note("gdefcore_access_matrix");
    rc = gdefcore_access_matrix(w.site.catalog, f.req, &rows, &n);
    o.kv["g:matrix"] = "rc=" + Rc(rc) +
        (rc == GDEFCORE_OK ? " rows=" + std::to_string(n)
                           : std::string(rows == NULL ? " null" : " SET") +
                                 " n=" + std::to_string(n)) +
        Diag(w, f.req);
    if (rc == GDEFCORE_OK) {
      gdefcore_access_matrix_free(w.site.catalog, rows, n);
    }
  }
  if (ask.posts) {
    o.kv["g:list.posts"] = ListLine(w, who, "site.post", NULL, "", NULL);
    o.kv["g:list.posts.title"] =
        ListLine(w, who, "site.post", "title", "DraftHiddenTitle", NULL);
    o.kv["g:list.posts.body"] =
        ListLine(w, who, "site.post", "body", "PubBodyCanary", NULL);
    o.kv["g:list.posts.sort-title"] =
        ListLine(w, who, "site.post", NULL, "", "title");
    {
      static const char * const kPaths[] = {"/", "/pub-hidden", "/draft-hidden",
          "/dup-hidden", "/no-such", "/pub-hidden/", "/echo/missing"};
      for (i = 0; i < sizeof kPaths / sizeof kPaths[0]; i++) {
        o.kv[std::string("g:page") + kPaths[i]] = PageLine(w, who, true, kPaths[i]);
        o.kv[std::string("g:page-noroutes") + kPaths[i]] =
            PageLine(w, who, false, kPaths[i]);
        o.kv[std::string("g:resolve") + kPaths[i]] =
            ResolveLine(w, who, true, kPaths[i], false);
        o.kv[std::string("g:resolve-noroutes") + kPaths[i]] =
            ResolveLine(w, who, false, kPaths[i], false);
      }
    }
  }
  {
    int on = 99;
    GDEFCORE_Result rc;
    int decision = 99;
    {
      Fresh f(w, who);
      Note("gdefcore_module_enabled");
      rc = gdefcore_module_enabled(w.host, f.req, "alpha", 5, &on);
      o.kv["g:module-enabled"] = "rc=" + Rc(rc) + " on=" + std::to_string(on) +
                                 Diag(w, f.req);
    }
    {
      Fresh f(w, who);
      Note("gdefcore_module_service");
      o.kv["g:module-service"] =
          std::string(gdefcore_module_service(w.host, f.req, "svc", 3, 1) == NULL
                          ? "null"
                          : "table") +
          Diag(w, f.req);
    }
    {
      Fresh f(w, who);
      Note("gdefcore_hook_fire");
      rc = gdefcore_hook_fire(w.host, f.req, w.site.catalog, "demo.none", 9,
          GDEFCORE_HOOK_DECISION, NULL, NULL, &decision);
      o.kv["g:hook-decision"] = "rc=" + Rc(rc) + " decision=" +
                                std::to_string(decision) + Diag(w, f.req);
    }
    {
      Fresh f(w, who);
      rc = gdefcore_hook_fire(w.host, f.req, w.site.catalog, "demo.none", 9,
          GDEFCORE_HOOK_EVENT, NULL, NULL, NULL);
      o.kv["g:hook-event"] = "rc=" + Rc(rc) + Diag(w, f.req);
    }
  }
  return o;
}

/** Keys on which two observations differ, with both values. */
inline std::vector<std::string> Differences(const Obs & a, const Obs & b) {
  std::vector<std::string> out;
  std::map<std::string, std::string>::const_iterator it;
  for (it = a.kv.begin(); it != a.kv.end(); ++it) {
    std::map<std::string, std::string>::const_iterator at = b.kv.find(it->first);
    if (at == b.kv.end()) {
      out.push_back(it->first + ": absent on the other side");
    } else if (at->second != it->second) {
      out.push_back(it->first + ": {" + it->second + "} vs {" + at->second + "}");
    }
  }
  for (it = b.kv.begin(); it != b.kv.end(); ++it) {
    if (a.kv.find(it->first) == a.kv.end()) {
      out.push_back(it->first + ": absent on the first side");
    }
  }
  return out;
}

/**
 * Within one world: every per-target answer for a hidden target equals the
 * answer for the id that was never created.
 */
inline std::vector<std::string> HiddenVsMissing(const World & w, const Obs & o) {
  std::vector<std::string> out;
  std::set<std::string>::const_iterator h;
  std::map<std::string, std::string>::const_iterator it;
  for (h = w.hidden.begin(); h != w.hidden.end(); ++h) {
    std::string pre = "t:" + *h + ":";
    for (it = o.kv.begin(); it != o.kv.end(); ++it) {
      if (it->first.compare(0, pre.size(), pre) != 0) {
        continue;
      }
      std::string other = "t:missing:" + it->first.substr(pre.size());
      std::map<std::string, std::string>::const_iterator at = o.kv.find(other);
      if (at == o.kv.end()) {
        out.push_back(it->first + ": no missing-id answer to compare with");
      } else if (at->second != it->second) {
        out.push_back(it->first + ": {" + it->second + "} vs missing {" +
                      at->second + "}");
      }
    }
  }
  return out;
}

}  // namespace gate

#endif /* GHOTI_DEFCORE_TEST_GATE_FIXTURE_H */
