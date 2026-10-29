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
 * Settings (site admin story 8): declared by the kernel and by modules, stored
 * only when changed, saved through a generated form with one permission and a
 * version a stale form fails, environment-local values that are never in the
 * tenant's truth, and the configuration export and import.
 *
 * Every test carries a CONTROL (the save that is allowed, the value that is
 * valid, the tenant that does see it), so a refusal is a refusal. The
 * real-source plants are in tools/check-settings.sh, and each names the test
 * that must turn red.
 */

#include "grants_fixture.h"
#include "size_structs.h"

#include <ghoti.io/defiant-storage/snapshot.h>

namespace {

using namespace gfx;

const char kSetting[] = "core.setting";
const char kSecret[] = "sk_live_TOPSECRET_9f3a";

/* The form as a browser reads it: digits written as character references are
 * the digits. */
std::string Decoded(const std::string & html) {
  std::string out;
  for (size_t i = 0; i < html.size();) {
    if (html.compare(i, 2, "&#") == 0 && i + 5 <= html.size() && html[i + 4] == ';') {
      int code = atoi(html.substr(i + 2, 2).c_str());
      if (code >= 48 && code <= 57) {
        out += (char)code;
        i += 5;
        continue;
      }
    }
    out += html[i++];
  }
  return out;
}

class Settings : public GrantsFixture {
 protected:
  std::string editor_, limiter_, reader_;
  std::string message_;

  void SetUp() override {
    GrantsFixture::SetUp();
    Kit(catalog_);
    ModDef * shop = NewMod("shop");
    shop->Setting("limit", "number", "10", "limits", "Order limit").minimum = "1";
    shop->setting_defs.back().maximum = "100";
    shop->setting_defs.back().description = "How many a customer may order.";
    shop->Setting("sale", "boolean", "false", "limits", "On sale");
    ModDef::SettingDef & key = shop->Setting("api_key", "text", "", "keys", "API key");
    key.local = 1;
    key.secret = 1;
    ModDef::SettingDef & banner = shop->Setting("banner", "text", "", "keys", "Banner");
    banner.local = 1;
    ModDef::SettingDef & note = shop->Setting("note", "text", "hello", "limits", "Note");
    note.max_length = 10;
    EXPECT_EQ(GDEFCORE_OK, Install(shop));
    EXPECT_EQ(GDEFCORE_OK, Enable("shop", {})) << last_error_;
    Role("settings-editors");
    Grant("settings-editors", GDEFCORE_SETTINGS_EDIT_LABEL);
    editor_ = Principal("settings-editors");
    reader_ = Principal();
    limiter_ = std::string();
  }

  void Kit(GDEFCORE_Catalog * catalog) {
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog, bytes, n));
    gdefcore_text_free(catalog, (char *)bytes);
  }

  static GDEFCORE_Setting_Change Change(const std::string & name,
      const std::string & value) {
    GDEFCORE_Setting_Change c;
    memset(&c, 0, sizeof c);
    c.size = sizeof c;
    c.name = name.data();
    c.name_len = name.size();
    c.value = value.data();
    c.value_len = value.size();
    return c;
  }

  /* One setting's effective value, "<invalid>" for none; the source too. */
  std::string Get(const std::string & name, int * source = NULL,
      GDEFCORE_Catalog * catalog = NULL) {
    char * v = NULL;
    size_t n = 0;
    int src = -1;
    GDEFCORE_Catalog * c = catalog != NULL ? catalog : catalog_;
    if (gdefcore_settings_get(c, name.data(), name.size(), &v, &n, &src) !=
        GDEFCORE_OK) {
      return "<invalid>";
    }
    std::string out(v, n);
    gdefcore_text_free(c, v);
    if (source != NULL) {
      *source = src;
    }
    return out;
  }

  /* Save @p changes as @p who. The result is the core's; the message too. */
  GDEFCORE_Result Save(const std::string & who, const std::string & group,
      const std::vector<std::pair<std::string, std::string> > & changes,
      const char * version = NULL, size_t * written = NULL,
      GDEFCORE_Catalog * catalog = NULL, GDEFCORE_Request * request = NULL) {
    std::vector<GDEFCORE_Setting_Change> list;
    for (const auto & c : changes) {
      list.push_back(Change(c.first, c.second));
    }
    char * msg = NULL;
    size_t msg_len = 0;
    GDEFCORE_Catalog * cat = catalog != NULL ? catalog : catalog_;
    size_t w = 99;
    GDEFCORE_Result rc = gdefcore_settings_save(cat,
        request != NULL ? request : Req(who), group.empty() ? NULL : group.data(),
        group.size(), version, list.data(), list.size(), &w, &msg, &msg_len);
    message_ = msg == NULL ? "" : std::string(msg, msg_len);
    gdefcore_text_free(cat, msg);
    if (written != NULL) {
      *written = w;
    }
    return rc;
  }

  std::string Version(const std::string & group) {
    char v[17];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_settings_group_version(catalog_, group.data(),
                               group.size(), v));
    return v;
  }

  size_t Entities(GDEFCORE_Catalog * catalog = NULL) {
    GDEFCORE_Catalog * c = catalog != NULL ? catalog : catalog_;
    char ** ids = NULL;
    size_t n = 0;
    size_t live = 0;
    if (gdefcore_entity_ids(c, kSetting, strlen(kSetting), &ids, &n) != GDEFCORE_OK) {
      return 0;
    }
    for (size_t i = 0; i < n; i++) {
      char ** t = NULL;
      size_t * l = NULL;
      size_t cnt = 0;
      if (gdefcore_entity_values(c, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              strlen(ids[i]), "en", 2, "name", 4, &t, &l, &cnt) == GDEFCORE_OK) {
        live += cnt > 0 ? 1 : 0;
        gdefcore_values_free(c, t, l, cnt);
      }
    }
    gdefcore_ids_free(c, ids, n);
    return live;
  }

  /* Every value of every field of every setting entity, one string. */
  std::string EntityText(GDEFCORE_Catalog * catalog = NULL) {
    GDEFCORE_Catalog * c = catalog != NULL ? catalog : catalog_;
    char ** ids = NULL;
    size_t n = 0;
    std::string out;
    if (gdefcore_entity_ids(c, kSetting, strlen(kSetting), &ids, &n) != GDEFCORE_OK) {
      return out;
    }
    for (size_t i = 0; i < n; i++) {
      for (const char * f : {"name", "group", "value", "serial"}) {
        for (size_t rev = 1;; rev++) {
          char ** t = NULL;
          size_t * l = NULL;
          size_t cnt = 0;
          if (gdefcore_entity_revision_values(c, ids[i], strlen(ids[i]), rev, "en", 2,
                  f, strlen(f), &t, &l, &cnt) != GDEFCORE_OK) {
            break;
          }
          for (size_t k = 0; k < cnt; k++) {
            out += std::string(f) + "=" + std::string(t[k], l[k]) + "\n";
          }
          gdefcore_values_free(c, t, l, cnt);
        }
      }
    }
    gdefcore_ids_free(c, ids, n);
    return out;
  }

  /* A layout that draws the site name and the page title. */
  void PlaceSiteName() {
    std::string id;
    char ** ids = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, "core.display", 12, &ids, &n));
    for (size_t i = 0; i < n && id.empty(); i++) {
      char ** t = NULL;
      size_t * l = NULL;
      size_t cnt = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i],
              strlen(ids[i]), "en", 2, "name", 4, &t, &l, &cnt) == GDEFCORE_OK) {
        if (cnt > 0 && std::string(t[0], l[0]) == "front") {
          id = ids[i];
        }
        gdefcore_values_free(catalog_, t, l, cnt);
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    ASSERT_FALSE(id.empty());
    const char * panes[2] = {"main sitename", "side recent"};
    size_t lens[2] = {strlen(panes[0]), strlen(panes[1])};
    GDEFCORE_Value v;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "panes";
    v.field_len = 5;
    v.texts = panes;
    v.text_lens = lens;
    v.count = 2;
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id.data(), id.size(), "en", 2, &v, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.display", 12));
    gdefcore_changeset_destroy(cs);
  }

  std::string Front(const std::string & who = std::string()) {
    char * bytes = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_render_page(catalog_, NULL, Req(who), "/", 1,
        GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
    if (rc != GDEFCORE_OK) {
      return std::string("<error ") + gdefcore_result_string(rc) + ">";
    }
    std::string out(bytes, n);
    gdefcore_text_free(catalog_, bytes);
    return out;
  }

  std::string Key(const std::string & who) {
    char * key = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_access_render_key(catalog_, Req(who), NULL, 0,
                               NULL, 0, &key, &n));
    std::string out(key, n);
    gdefcore_text_free(catalog_, key);
    return out;
  }
};

/* ---- declared ---------------------------------------------------------------- */

TEST_F(Settings, TheKernelDeclaresTheTitleAndATaglineAndAModuleAddsItsOwn) {
  GDEFCORE_Setting s;
  memset(&s, 0, sizeof s);
  s.size = sizeof s;
  EXPECT_EQ(7u, gdefcore_settings_count(catalog_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_at(catalog_, 0, &s));
  EXPECT_EQ("core.site_title", std::string(s.name, s.name_len));
  EXPECT_EQ("core.site", std::string(s.group, s.group_len));
  EXPECT_EQ("My site", Get("core.site_title"));
  EXPECT_EQ("", Get("core.tagline"));
  EXPECT_EQ("10", Get("shop.limit"));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_find(catalog_, "shop.limit", 10, &s));
  EXPECT_EQ("1", std::string(s.minimum, s.minimum_len));
  EXPECT_EQ("100", std::string(s.maximum, s.maximum_len));
  EXPECT_EQ("shop.limits", std::string(s.group, s.group_len));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_find(catalog_, "shop.api_key", 12, &s));
  EXPECT_TRUE(s.local && s.secret);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_settings_find(catalog_, "nope.x", 6, &s));
  /* The groups: the kernel's first, then by key. */
  GDEFCORE_Settings_Group g;
  memset(&g, 0, sizeof g);
  g.size = sizeof g;
  ASSERT_EQ(3u, gdefcore_settings_group_count(catalog_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_group_at(catalog_, 0, &g));
  EXPECT_EQ("core.site", std::string(g.key, g.key_len));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_group_at(catalog_, 1, &g));
  EXPECT_EQ("shop.keys", std::string(g.key, g.key_len));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_group_at(catalog_, 2, &g));
  EXPECT_EQ("shop.limits", std::string(g.key, g.key_len));
  EXPECT_EQ(3u, g.count);
  /* A module that is disabled declares nothing: its setting is none. */
  ASSERT_EQ(GDEFCORE_OK, Disable("shop"));
  EXPECT_EQ(2u, gdefcore_settings_count(catalog_));
  EXPECT_EQ("<invalid>", Get("shop.limit"));
}

TEST_F(Settings, TheDecimalAndTheValueRulesAreNotLocaleDependent) {
  EXPECT_EQ(0, gdefcore_settings_decimal_cmp("5", 1, "5.0", 3));
  EXPECT_EQ(0, gdefcore_settings_decimal_cmp("-0", 2, "0", 1));
  EXPECT_EQ(-1, gdefcore_settings_decimal_cmp("-2", 2, "1", 1));
  EXPECT_EQ(1, gdefcore_settings_decimal_cmp("10", 2, "9.99", 4));
  EXPECT_EQ(-1, gdefcore_settings_decimal_cmp("-10", 3, "-9", 2));
  EXPECT_EQ(2, gdefcore_settings_decimal_cmp("x", 1, "1", 1));
  const char * why = NULL;
  EXPECT_TRUE(gdefcore_settings_check("number", 6, "1", 1, "100", 3, 0, "50", 2, &why));
  EXPECT_FALSE(gdefcore_settings_check("number", 6, "1", 1, "100", 3, 0, "0.99", 4, &why));
  EXPECT_FALSE(gdefcore_settings_check("number", 6, "1", 1, "100", 3, 0, "100.5", 5, &why));
  EXPECT_FALSE(gdefcore_settings_check("number", 6, "", 0, "", 0, 0, "1,5", 3, &why));
  EXPECT_FALSE(gdefcore_settings_check("boolean", 7, "", 0, "", 0, 0, "yes", 3, &why));
  EXPECT_TRUE(gdefcore_settings_check("boolean", 7, "", 0, "", 0, 0, "true", 4, &why));
  EXPECT_FALSE(gdefcore_settings_check("text", 4, "", 0, "", 0, 3, "abcd", 4, &why));
  EXPECT_FALSE(gdefcore_settings_check("text", 4, "", 0, "", 0, 0, "a\x01", 2, &why));
  EXPECT_FALSE(gdefcore_settings_check("text", 4, "", 0, "", 0, 0, "\xc3", 1, &why));
  EXPECT_TRUE(gdefcore_settings_check("text", 4, "", 0, "", 0, 0, "caf\xc3\xa9", 5, &why));
}

TEST_F(Settings, AModuleCannotDeclareASettingWithBoundsItsDefaultBreaks) {
  ModDef * bad = NewMod("bad");
  bad->Setting("n", "number", "500", "g", "N").maximum = "100";
  ASSERT_EQ(GDEFCORE_OK, Install(bad));
  EXPECT_NE(GDEFCORE_OK, Enable("bad", {}));
  ModDef * worse = NewMod("worse");
  worse->Setting("t", "text", "x", "g", "T").minimum = "1";
  ASSERT_EQ(GDEFCORE_OK, Install(worse));
  EXPECT_NE(GDEFCORE_OK, Enable("worse", {}));
  ModDef * fine = NewMod("fine");
  fine->Setting("n", "number", "50", "g", "N").maximum = "100";
  ASSERT_EQ(GDEFCORE_OK, Install(fine));
  EXPECT_EQ(GDEFCORE_OK, Enable("fine", {})) << last_error_;
}

/* ---- stored only when changed -------------------------------------------------- */

TEST_F(Settings, SavingTheDefaultsWritesNothingAndTheEpochStaysWhereItIs) {
  uint64_t before = Epoch();
  size_t written = 99;
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits",
                             {{"shop.limit", "10"}, {"shop.sale", "false"},
                                 {"shop.note", "hello"}}, NULL, &written))
      << message_;
  EXPECT_EQ(0u, written);
  EXPECT_EQ(0u, Entities());
  EXPECT_EQ(before, Epoch());
  /* "10.0" is the same number as the default: still nothing. */
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "10.0"}},
                             NULL, &written));
  EXPECT_EQ(0u, written);
  EXPECT_EQ(0u, Entities());
  EXPECT_EQ(before, Epoch());
  /* CONTROL: a changed value is stored and moves the epoch. */
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "12"}},
                             NULL, &written)) << message_;
  EXPECT_EQ(1u, written);
  EXPECT_EQ(1u, Entities());
  EXPECT_GT(Epoch(), before);
  int source = -1;
  EXPECT_EQ("12", Get("shop.limit", &source));
  EXPECT_EQ(GDEFCORE_SETTING_FROM_SITE, source);
  /* Saving what is stored again is also nothing. */
  before = Epoch();
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "12"}},
                             NULL, &written));
  EXPECT_EQ(0u, written);
  EXPECT_EQ(before, Epoch());
}

TEST_F(Settings, ChangingASettingBackToItsDefaultTakesTheStoredValueAway) {
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site", {{"core.site_title", "Gadgets"}}))
      << message_;
  EXPECT_EQ(1u, Entities());
  EXPECT_EQ("Gadgets", Get("core.site_title"));
  size_t written = 0;
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site", {{"core.site_title", "My site"}},
                             NULL, &written));
  EXPECT_EQ(1u, written);
  EXPECT_EQ(0u, Entities());
  int source = -1;
  EXPECT_EQ("My site", Get("core.site_title", &source));
  EXPECT_EQ(GDEFCORE_SETTING_FROM_DEFAULT, source);
  /* And set again: a new row, the old one stays in history. */
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site", {{"core.site_title", "Again"}}));
  EXPECT_EQ("Again", Get("core.site_title"));
}

TEST_F(Settings, AnUpgradeThatMovesADefaultReachesASiteThatNeverChangedItAndNotOneThatDid) {
  /* Two tenants on one host: one changed the limit, one never did. The module
   * is then replaced by an upgrade whose default is 15. */
  GDEFCORE_Catalog * other = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store_, (const uint8_t *)"u", 1, NULL,
                             NULL, &other));
  gdefcore_catalog_bind_host(other, host_);
  Kit(other);
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(other, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, cs, "shop", 4));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "shop", 4));
    gdefcore_changeset_destroy(cs);
  }
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "20"}}));
  EXPECT_EQ("20", Get("shop.limit"));
  EXPECT_EQ("10", Get("shop.limit", NULL, other));
  /* The upgrade: a host that reads the new manifest over the same data. */
  gdefcore_catalog_bind_host(catalog_, NULL);
  gdefcore_catalog_bind_host(other, NULL);
  gdefcore_host_destroy(host_);
  host_ = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &host_));
  gdefcore_catalog_bind_host(catalog_, host_);
  gdefcore_catalog_bind_host(other, host_);
  Defs().clear();
  ModDef * shop = NewMod("shop");
  shop->Setting("limit", "number", "15", "limits", "Order limit").minimum = "1";
  shop->setting_defs.back().maximum = "100";
  ASSERT_EQ(GDEFCORE_OK, Install(shop));
  EXPECT_EQ("20", Get("shop.limit")) << "a site that changed it keeps its value";
  EXPECT_EQ("15", Get("shop.limit", NULL, other)) << "a site that never did follows the default";
  gdefcore_catalog_bind_host(other, NULL);
  gdefcore_catalog_destroy(other);
}

TEST_F(Settings, ANumberOutsideItsBoundsOrOfTheWrongTypeIsRefusedAndNothingIsWritten) {
  uint64_t before = Epoch();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits", {{"shop.limit", "101"}}));
  EXPECT_NE(std::string::npos, message_.find("Order limit")) << message_;
  EXPECT_NE(std::string::npos, message_.find("highest")) << message_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits", {{"shop.limit", "0"}}));
  EXPECT_NE(std::string::npos, message_.find("lowest")) << message_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits", {{"shop.limit", "ten"}}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits", {{"shop.sale", "maybe"}}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits", {{"shop.note", "far too long"}}));
  /* One bad value in a form refuses the whole form: the good one is not saved. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits",
                                       {{"shop.sale", "true"}, {"shop.limit", "500"}}));
  EXPECT_EQ("false", Get("shop.sale"));
  /* A setting that is not in this form's group, and one nobody declared. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits", {{"shop.banner", "x"}}));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "shop.limits", {{"shop.nope", "x"}}));
  EXPECT_EQ(before, Epoch());
  EXPECT_EQ(0u, Entities());
  /* CONTROL: at the bounds it is accepted. */
  EXPECT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "100"}}))
      << message_;
  EXPECT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "1"}}));
  EXPECT_EQ("1", Get("shop.limit"));
}

/* ---- who may, and a stale form ------------------------------------------------------- */

TEST_F(Settings, SavingNeedsThePermissionAndARefusalWritesNothing) {
  uint64_t before = Epoch();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(reader_, "shop.limits", {{"shop.limit", "12"}}));
  EXPECT_EQ("That edit is not allowed.", message_);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(std::string(), "core.site",
                                       {{"core.site_title", "Hacked"}}));
  EXPECT_EQ(before, Epoch());
  EXPECT_EQ(0u, Entities());
  EXPECT_EQ("My site", Get("core.site_title"));
  EXPECT_FALSE(gdefcore_settings_may_edit(catalog_, Req(reader_)));
  /* CONTROL: the role that holds it. */
  EXPECT_TRUE(gdefcore_settings_may_edit(catalog_, Req(editor_)));
  EXPECT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "12"}}));
}

TEST_F(Settings, OnePermissionWithAConditionOnTheGroupEditsThatGroupAndNotAnother) {
  Role("limit-editors");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("limit-editors", GDEFCORE_SETTINGS_EDIT_LABEL,
                             "(= field.group \"shop.limits\")"));
  std::string who = Principal("limit-editors");
  EXPECT_EQ(GDEFCORE_OK, Save(who, "shop.limits", {{"shop.limit", "30"}})) << message_;
  EXPECT_EQ("30", Get("shop.limit"));
  EXPECT_EQ(GDEFCORE_OK, Save(who, "shop.limits", {{"shop.limit", "31"}}))
      << "a stored setting is edited again: " << message_;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(who, "core.site", {{"core.site_title", "Mine"}}));
  EXPECT_EQ("That edit is not allowed.", message_);
  EXPECT_EQ("My site", Get("core.site_title"));
  /* A local setting is a group of its own: the same decision, the same refusal,
   * and the environment is as it was. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(who, "shop.keys", {{"shop.banner", "Sale!"}}));
  EXPECT_EQ("", Get("shop.banner"));
  /* One form that mixes a group it may and one it may not: nothing at all. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(who, "",
                                       {{"shop.limit", "40"}, {"shop.banner", "x"}}));
  EXPECT_EQ("31", Get("shop.limit"));
  EXPECT_EQ("", Get("shop.banner"));
  /* CONTROL: the editor of everything does edit the local one. */
  EXPECT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.banner", "Sale!"}}));
  EXPECT_EQ("Sale!", Get("shop.banner"));
}

TEST_F(Settings, AFormThatWasDrawnBeforeAnotherSaveIsStaleAndWritesNothing) {
  std::string v0 = Version("shop.limits");
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "12"}}, v0.c_str()))
      << message_;
  std::string v1 = Version("shop.limits");
  EXPECT_NE(v0, v1);
  uint64_t before = Epoch();
  EXPECT_EQ(GDEFCORE_ERR_STALE, Save(editor_, "shop.limits", {{"shop.limit", "13"}},
                                     v0.c_str()));
  EXPECT_NE(std::string::npos, message_.find("changed since")) << message_;
  EXPECT_EQ("12", Get("shop.limit"));
  EXPECT_EQ(before, Epoch());
  /* CONTROL: the form drawn after it saves. And a change in another group does
   * not make this group's form stale. */
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site", {{"core.tagline", "Hi"}}));
  EXPECT_EQ(v1, Version("shop.limits"));
  EXPECT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "13"}}, v1.c_str()));
  /* A local value moves the version of its group too, and holds none of it. */
  std::string k0 = Version("shop.keys");
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", kSecret}}));
  std::string k1 = Version("shop.keys");
  EXPECT_NE(k0, k1);
  EXPECT_EQ(std::string::npos, k1.find("TOPSECRET"));
  EXPECT_EQ(GDEFCORE_ERR_STALE, Save(editor_, "shop.keys", {{"shop.banner", "b"}},
                                     k0.c_str()));
  EXPECT_EQ("", Get("shop.banner"));
}

TEST_F(Settings, ApplyAsksThePermissionOfAChangesetThatCarriesARequestAndNotOfTheOperators) {
  uint64_t before = Epoch();
  for (const std::string & who : {reader_, std::string()}) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    gdefcore_changeset_set_request(cs, Req(who));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_stage(cs, "core.tagline", 12, "Sneaky", 6, NULL));
    EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_changeset_apply(cs, kSetting, strlen(kSetting)));
    size_t n = 0;
    const char * why = gdefcore_changeset_refusal(cs, &n);
    EXPECT_EQ("That edit is not allowed.", why == NULL ? "" : std::string(why, n));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ(before, Epoch());
  EXPECT_EQ("", Get("core.tagline"));
  /* CONTROL: the role that holds it, and the operator (no request). */
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  gdefcore_changeset_set_request(cs, Req(editor_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_stage(cs, "core.tagline", 12, "Fine", 4, NULL));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kSetting, strlen(kSetting)));
  gdefcore_changeset_destroy(cs);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_stage(cs, "core.tagline", 12, "Operator", 8, NULL));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, kSetting, strlen(kSetting)));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ("Operator", Get("core.tagline"));
}

/* ---- the title ----------------------------------------------------------------------------- */

TEST_F(Settings, AChangedTitleShowsOnTheNextRequestAndMovesTheRenderKey) {
  PlaceSiteName();
  std::string page = Front();
  EXPECT_NE(std::string::npos, page.find("<span class=\"site-name\">My site</span>")) << page;
  EXPECT_EQ(std::string::npos, page.find("tagline")) << page;
  std::string key = Key(reader_);
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site",
                             {{"core.site_title", "Gadget <Works>"}, {"core.tagline", "Tools & more"}}))
      << message_;
  page = Front();
  EXPECT_NE(std::string::npos,
      page.find("<span class=\"site-name\">Gadget &lt;Works&gt;</span>")) << page;
  EXPECT_NE(std::string::npos, page.find("<span class=\"tagline\">Tools &amp; more</span>")) << page;
  EXPECT_NE(key, Key(reader_)) << "fragments that show it are keyed out";
  /* And back: the default shows again on the next request. */
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site",
                             {{"core.site_title", "My site"}, {"core.tagline", ""}}));
  page = Front();
  EXPECT_NE(std::string::npos, page.find("<span class=\"site-name\">My site</span>")) << page;
  EXPECT_EQ(std::string::npos, page.find("tagline")) << page;
}

TEST_F(Settings, TheThemeStopgapIsGoneFromTheKit) {
  int kind = 0;
  EXPECT_NE(GDEFCORE_OK, gdefcore_type_kind(catalog_, "core.theme", 10, &kind));
  char ** ids = NULL;
  size_t n = 7;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, "core.theme", 10, &ids, &n));
  EXPECT_EQ(0u, n) << "no base theme is made any more";
  gdefcore_ids_free(catalog_, ids, n);
}

/* ---- environment-local ----------------------------------------------------------------------- */

TEST_F(Settings, ALocalValueIsNeverInTheTenantsTruthAndItsMarkerHoldsNoValue) {
  int source = -1;
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys",
                             {{"shop.api_key", kSecret}, {"shop.banner", "Sale! <b>"}}))
      << message_;
  EXPECT_EQ(kSecret, Get("shop.api_key", &source));
  EXPECT_EQ(GDEFCORE_SETTING_FROM_LOCAL, source);
  EXPECT_EQ("Sale! <b>", Get("shop.banner"));
  EXPECT_TRUE(gdefcore_settings_is_set(catalog_, "shop.api_key", 12));
  /* The entity port holds a marker for each, with a serial and no value, in
   * every revision it ever had. */
  EXPECT_EQ(2u, Entities());
  std::string all = EntityText();
  EXPECT_NE(std::string::npos, all.find("name=shop.api_key")) << all;
  EXPECT_NE(std::string::npos, all.find("serial=1")) << all;
  EXPECT_EQ(std::string::npos, all.find("value=")) << all;
  EXPECT_EQ(std::string::npos, all.find("TOPSECRET")) << all;
  EXPECT_EQ(std::string::npos, all.find("Sale!")) << all;
  /* The tenant's own records hold none; the environment scope holds both. */
  {
    GDEFSTOR_RecordList * list = NULL;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_record_list(store_, kTenant, 1, "core.setting-local",
                               18, "", 0, 0, 100, &list));
    EXPECT_EQ(0u, gdefstor_record_list_count(list));
    gdefstor_record_list_free(list);
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_record_list(store_, "\x03", 1, "core.setting-local",
                               18, "", 0, 0, 100, &list));
    EXPECT_EQ(2u, gdefstor_record_list_count(list));
    gdefstor_record_list_free(list);
  }
  /* The snapshot of the tenant carries neither the value nor a record of it. */
  uint8_t * zip = NULL;
  size_t zip_len = 0;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_snapshot_export(store_, kTenant, 1, NULL, &zip, &zip_len));
  std::string bytes((const char *)zip, zip_len);
  EXPECT_EQ(std::string::npos, bytes.find("TOPSECRET"));
  gdefstor_bytes_free(NULL, zip);
  /* Changing it again moves the serial, so the change is a revision, and takes
   * the old value away. */
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", "sk_second"}}));
  EXPECT_EQ("sk_second", Get("shop.api_key"));
  EXPECT_NE(std::string::npos, EntityText().find("serial=2"));
  /* Back to nothing: the record goes, the marker is cleared. */
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", ""}}));
  EXPECT_EQ("", Get("shop.api_key", &source));
  EXPECT_EQ(GDEFCORE_SETTING_FROM_DEFAULT, source);
  EXPECT_FALSE(gdefcore_settings_is_set(catalog_, "shop.api_key", 12));
  EXPECT_EQ(1u, Entities());
}

TEST_F(Settings, ARefusedSaveLeavesTheLocalValueAsItWas) {
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", "first"}}));
  Role("limit-editors");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("limit-editors", GDEFCORE_SETTINGS_EDIT_LABEL,
                             "(= field.group \"shop.limits\")"));
  std::string who = Principal("limit-editors");
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(who, "", {{"shop.limit", "50"}, {"shop.api_key", "stolen"}}));
  EXPECT_EQ("first", Get("shop.api_key"));
  EXPECT_EQ("10", Get("shop.limit"));
}

TEST_F(Settings, TwoTenantsSettingsNeverMix) {
  GDEFCORE_Catalog * other = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store_, (const uint8_t *)"u", 1, NULL,
                             NULL, &other));
  gdefcore_catalog_bind_host(other, host_);
  Kit(other);
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(other, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, cs, "shop", 4));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "shop", 4));
    gdefcore_changeset_destroy(cs);
  }
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site", {{"core.site_title", "Tenant T"}}));
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", "t-key"}}));
  EXPECT_EQ("Tenant T", Get("core.site_title"));
  EXPECT_EQ("t-key", Get("shop.api_key"));
  EXPECT_EQ("My site", Get("core.site_title", NULL, other));
  EXPECT_EQ("", Get("shop.api_key", NULL, other));
  EXPECT_EQ(2u, Entities()) << "the title, and the marker of the key";
  EXPECT_EQ(0u, Entities(other));
  /* CONTROL: the other tenant keeps its own, side by side. */
  GDEFCORE_Request * ur = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_request_create((const uint8_t *)"u", 1, 0, 0, NULL, &ur));
  requests_.push_back(ur);
  {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(other, "se", 2, NULL));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(other, "se", 2, GDEFCORE_SETTINGS_EDIT_LABEL,
                               strlen(GDEFCORE_SETTINGS_EDIT_LABEL), "core.role", 9));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(other, id));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(other, id, strlen(id), "se", 2));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(ur, id, strlen(id)));
  }
  ASSERT_EQ(GDEFCORE_OK, Save("", "shop.keys", {{"shop.api_key", "u-key"}}, NULL, NULL,
                             other, ur)) << message_;
  EXPECT_EQ("u-key", Get("shop.api_key", NULL, other));
  EXPECT_EQ("t-key", Get("shop.api_key"));
  /* The editor of T may not write U's settings: the permission is U's own. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Save(editor_, "core.site", {{"core.site_title", "x"}},
                                       NULL, NULL, other));
  EXPECT_EQ("My site", Get("core.site_title", NULL, other));
  gdefcore_catalog_bind_host(other, NULL);
  gdefcore_catalog_destroy(other);
}

/* ---- the generated form ------------------------------------------------------------------------- */

TEST_F(Settings, TheFormShowsASecretAsSetOrNotSetAndNeverItsValue) {
  char * html = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_form_html(catalog_, Req(editor_), "shop.keys", 9,
                             "/admin/settings/shop/keys", "TOKENabc", &html, &n));
  std::string raw(html, n);
  EXPECT_EQ(std::string::npos, raw.find_first_of("0123456789")) << "no digit is left bare for a scanner: " << raw;
  std::string form = Decoded(raw);
  gdefcore_text_free(catalog_, html);
  EXPECT_NE(std::string::npos, form.find("name=\"token\" value=\"TOKENabc\"")) << form;
  EXPECT_NE(std::string::npos, form.find("name=\"version\"")) << form;
  EXPECT_NE(std::string::npos, form.find("name=\"s.shop.api_key\"")) << form;
  EXPECT_NE(std::string::npos, form.find("Not set")) << form;
  EXPECT_NE(std::string::npos, form.find("never exported")) << form;
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", kSecret},
                                                         {"shop.banner", "<script>x</script>"}}));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_form_html(catalog_, Req(editor_), "shop.keys", 9,
                             "/admin/settings/shop/keys", "TOKENabc", &html, &n));
  form = Decoded(std::string(html, n));
  gdefcore_text_free(catalog_, html);
  EXPECT_EQ(std::string::npos, form.find("TOPSECRET")) << form;
  EXPECT_EQ(std::string::npos, form.find(kSecret)) << form;
  EXPECT_NE(std::string::npos, form.find(">Set<")) << form;
  EXPECT_EQ(std::string::npos, form.find("Not set")) << form;
  /* The banner is not secret: shown, escaped. */
  EXPECT_NE(std::string::npos, form.find("&lt;script&gt;x&lt;/script&gt;")) << form;
  EXPECT_EQ(std::string::npos, form.find("<script>")) << form;
  /* The version is the group's, and carries nothing of a value. */
  EXPECT_NE(std::string::npos, form.find(Version("shop.keys"))) << form;
  /* A number gets its bounds, a boolean a choice. */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_form_html(catalog_, Req(editor_), "shop.limits", 11,
                             "/x", "Tabc", &html, &n));
  form = Decoded(std::string(html, n));
  gdefcore_text_free(catalog_, html);
  EXPECT_NE(std::string::npos, form.find("From 1. Up to 100.")) << form;
  EXPECT_NE(std::string::npos, form.find("<select")) << form;
  EXPECT_NE(std::string::npos, form.find("How many a customer may order.")) << form;
  /* Nobody who may not edit, and nobody for a group there is not, is told
   * which of the two it was. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_settings_form_html(catalog_, Req(reader_),
                                      "shop.keys", 9, "/x", "Tabc", &html, &n));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_settings_form_html(catalog_, Req(editor_),
                                      "shop.nope", 9, "/x", "Tabc", &html, &n));
}

/* ---- export and import ----------------------------------------------------------------------------- */

class Moves : public Settings {
 protected:
  GDEFCORE_Catalog * b_ = NULL;
  std::string b_editor_;
  GDEFCORE_Request * b_req_ = NULL;

  void SetUp() override {
    Settings::SetUp();
    ASSERT_EQ(GDEFCORE_OK, gdefcore_catalog_open(store_, (const uint8_t *)"b", 1, NULL,
                               NULL, &b_));
    gdefcore_catalog_bind_host(b_, host_);
    Kit(b_);
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(b_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(host_, cs, "shop", 4));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "shop", 4));
    gdefcore_changeset_destroy(cs);
  }

  void TearDown() override {
    gdefcore_catalog_bind_host(b_, NULL);
    gdefcore_catalog_destroy(b_);
    Settings::TearDown();
  }

  /* B's own save, as the operator (no request). */
  void BSetLocal(const char * name, const char * value) {
    if (b_req_ == NULL) {
      char id[GDEFCORE_PUBLIC_ID_LEN + 1];
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_role_create(b_, "se", 2, NULL));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_grant(b_, "se", 2, GDEFCORE_SETTINGS_EDIT_LABEL,
                                 strlen(GDEFCORE_SETTINGS_EDIT_LABEL), "core.role", 9));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_create(b_, id));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_access_principal_add_role(b_, id, strlen(id), "se", 2));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_request_create((const uint8_t *)"b", 1, 0, 0, NULL, &b_req_));
      requests_.push_back(b_req_);
      ASSERT_EQ(GDEFCORE_OK, gdefcore_request_set_principal(b_req_, id, strlen(id)));
    }
    ASSERT_EQ(GDEFCORE_OK, Save("", "", {{name, value}}, NULL, NULL, b_, b_req_)) << message_;
  }

  GDEFCORE_Result Import(const GDEFCORE_Patch * files, size_t n, size_t * skipped_local,
      size_t * skipped_unknown) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc = gdefcore_settings_import(b_, files, n, &cs, skipped_local,
        skipped_unknown);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, kSetting, strlen(kSetting));
      size_t rn = 0;
      const char * why = gdefcore_changeset_refusal(cs, &rn);
      message_ = why == NULL ? "" : std::string(why, rn);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }
};

std::string PatchText(const GDEFCORE_Patch * files, size_t n) {
  std::string out;
  for (size_t i = 0; i < n; i++) {
    out += std::string(files[i].path, files[i].path_len) + "=" +
           std::string((const char *)files[i].bytes, files[i].len) + "\n";
  }
  return out;
}

TEST_F(Moves, TheExportCarriesTheChangedSettingsAndNoLocalOne) {
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site", {{"core.site_title", "From A"}}));
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "33"}}));
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", kSecret},
                                                         {"shop.banner", "Banner A"}}));
  GDEFCORE_Patch * files = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_export(catalog_, &files, &n));
  std::string text = PatchText(files, n);
  EXPECT_NE(std::string::npos, text.find("=From A\n")) << text;
  EXPECT_NE(std::string::npos, text.find("=core.site_title\n")) << text;
  EXPECT_NE(std::string::npos, text.find("=33\n")) << text;
  EXPECT_EQ(std::string::npos, text.find("api_key")) << text;
  EXPECT_EQ(std::string::npos, text.find("banner")) << text;
  EXPECT_EQ(std::string::npos, text.find("TOPSECRET")) << text;
  EXPECT_EQ(std::string::npos, text.find("Banner A")) << text;
  gdefcore_patch_free(catalog_, files, n);
}

TEST_F(Moves, ImportAppliesTheChangedSettingsAndBKeepsItsOwnLocalValue) {
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "core.site", {{"core.site_title", "From A"}}));
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.limits", {{"shop.limit", "33"}}));
  ASSERT_EQ(GDEFCORE_OK, Save(editor_, "shop.keys", {{"shop.api_key", kSecret}}));
  BSetLocal("shop.api_key", "b-own-key");
  BSetLocal("shop.limit", "44");   /* B had changed the limit as well */
  GDEFCORE_Patch * files = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_settings_export(catalog_, &files, &n));
  size_t skipped_local = 99;
  size_t skipped_unknown = 99;
  ASSERT_EQ(GDEFCORE_OK, Import(files, n, &skipped_local, &skipped_unknown)) << message_;
  gdefcore_patch_free(catalog_, files, n);
  EXPECT_EQ(0u, skipped_local);
  EXPECT_EQ("From A", Get("core.site_title", NULL, b_));
  EXPECT_EQ("33", Get("shop.limit", NULL, b_)) << "the imported value replaces B's changed one";
  EXPECT_EQ("b-own-key", Get("shop.api_key", NULL, b_));
  /* B's entities by name: one each, not a second for the limit. */
  EXPECT_EQ(3u, Entities(b_));
  /* A is as it was. */
  EXPECT_EQ(kSecret, Get("shop.api_key"));
}

TEST_F(Moves, AnImportThatCarriesALocalValueDropsItAndLeavesBsAbsentOneAbsent) {
  /* A patch built by hand, as an old or hostile export could be: it names a
   * local setting with a value, and a setting nobody here declares. */
  GDEFCORE_Changeset * cs = NULL;
  char fresh[GDEFCORE_PUBLIC_ID_LEN + 1];
  char fresh2[GDEFCORE_PUBLIC_ID_LEN + 1];
  char fresh3[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kSetting, strlen(kSetting), fresh, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kSetting, strlen(kSetting), fresh2, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kSetting, strlen(kSetting), fresh3, NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
  struct One { const char * id; const char * name; const char * group; const char * value; };
  One ones[3] = {{fresh, "shop.api_key", "shop.keys", kSecret},
      {fresh2, "gone.setting", "gone.g", "x"}, {fresh3, "core.tagline", "core.site", "Imported"}};
  for (const One & o : ones) {
    const char * v[3] = {o.name, o.group, o.value};
    const char * f[3] = {"name", "group", "value"};
    size_t l[3] = {strlen(v[0]), strlen(v[1]), strlen(v[2])};
    GDEFCORE_Value vals[3];
    memset(vals, 0, sizeof vals);
    for (int i = 0; i < 3; i++) {
      vals[i].size = sizeof vals[i];
      vals[i].field = f[i];
      vals[i].field_len = strlen(f[i]);
      vals[i].texts = &v[i];
      vals[i].text_lens = &l[i];
      vals[i].count = 1;
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, o.id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, vals, 3));
  }
  GDEFCORE_Patch * files = NULL;
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(cs, &files, &n));
  gdefcore_changeset_destroy(cs);
  EXPECT_NE(std::string::npos, PatchText(files, n).find(kSecret)) << "CONTROL: the patch does carry it";
  size_t skipped_local = 0;
  size_t skipped_unknown = 0;
  /* B has none: it stays absent. */
  ASSERT_EQ(GDEFCORE_OK, Import(files, n, &skipped_local, &skipped_unknown)) << message_;
  EXPECT_EQ(1u, skipped_local);
  EXPECT_EQ(1u, skipped_unknown);
  EXPECT_EQ("", Get("shop.api_key", NULL, b_));
  EXPECT_FALSE(gdefcore_settings_is_set(b_, "shop.api_key", 12));
  EXPECT_EQ("Imported", Get("core.tagline", NULL, b_));
  EXPECT_EQ(std::string::npos, EntityText(b_).find("TOPSECRET"));
  /* And B has one of its own: it is the same after. */
  BSetLocal("shop.api_key", "b-own-key");
  ASSERT_EQ(GDEFCORE_OK, Import(files, n, &skipped_local, &skipped_unknown)) << message_;
  EXPECT_EQ("b-own-key", Get("shop.api_key", NULL, b_));
  gdefcore_patch_free(catalog_, files, n);
}

TEST_F(Moves, AnImportOfAnythingButSettingsIsRefused) {
  GDEFCORE_Patch bad[1];
  memset(bad, 0, sizeof bad);
  char path[] = "type/site.x/kind";
  uint8_t body[] = "content";
  bad[0].size = sizeof bad[0];
  bad[0].path = path;
  bad[0].path_len = strlen(path);
  bad[0].bytes = body;
  bad[0].len = 7;
  GDEFCORE_Changeset * cs = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_settings_import(b_, bad, 1, &cs, NULL, NULL));
  EXPECT_TRUE(cs == NULL);
}

/* ---- what apply refuses --------------------------------------------------------------------------------- */

TEST_F(Settings, ApplyRefusesASettingNobodyDeclaresALocalValueAsAnEntityAndABadValue) {
  struct Case { const char * name; const char * group; const char * value; const char * serial; bool ok; };
  const Case cases[] = {
      {"core.tagline", "core.site", "fine", NULL, true},
      {"nobody.declared", "core.site", "x", NULL, false},
      {"core.tagline", "core.elsewhere", "x", NULL, false},
      {"shop.api_key", "shop.keys", kSecret, NULL, false},
      {"shop.api_key", "shop.keys", NULL, "1", true},
      {"shop.limit", "shop.limits", "5000", NULL, false},
      {"shop.limit", "shop.limits", NULL, NULL, false},
      {"shop.limit", "shop.limits", "5", "1", false},
  };
  for (const Case & c : cases) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value v[4];
    const char * texts[4] = {c.name, c.group, c.value, c.serial};
    const char * fields[4] = {"name", "group", "value", "serial"};
    size_t lens[4];
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kSetting, strlen(kSetting), id, NULL));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    memset(v, 0, sizeof v);
    for (int i = 0; i < 4; i++) {
      lens[i] = texts[i] == NULL ? 0 : strlen(texts[i]);
      v[i].size = sizeof v[i];
      v[i].field = fields[i];
      v[i].field_len = strlen(fields[i]);
      v[i].texts = &texts[i];
      v[i].text_lens = &lens[i];
      v[i].count = texts[i] == NULL ? 0 : 1;
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, v, 4));
    EXPECT_EQ(c.ok ? GDEFCORE_OK : GDEFCORE_ERR_INVALID,
        gdefcore_changeset_apply(cs, kSetting, strlen(kSetting)))
        << c.name << " " << c.group << " " << (c.value ? c.value : "-");
    gdefcore_changeset_destroy(cs);
  }
}

/* ---- the surface ---------------------------------------------------------------------------------------------- */

TEST_F(Settings, EveryStructTheSettingsApiTakesIsCheckedAtItsOwnSize) {
  std::map<std::string, size_structs::Probe> probes;
  probes["GDEFCORE_Setting"] = [&, this](size_t size) {
    GDEFCORE_Setting s;
    memset(&s, 0, sizeof s);
    s.size = size;
    return gdefcore_settings_at(catalog_, 0, &s) == GDEFCORE_OK &&
           gdefcore_settings_find(catalog_, "core.tagline", 12, &s) == GDEFCORE_OK;
  };
  probes["GDEFCORE_Settings_Group"] = [&, this](size_t size) {
    GDEFCORE_Settings_Group g;
    memset(&g, 0, sizeof g);
    g.size = size;
    return gdefcore_settings_group_at(catalog_, 0, &g) == GDEFCORE_OK;
  };
  probes["GDEFCORE_Setting_Change"] = [&, this](size_t size) {
    std::string name = "core.tagline";
    std::string value;
    GDEFCORE_Setting_Change c = Change(name, value);
    c.size = size;
    return gdefcore_settings_save(catalog_, Req(editor_), "core.site", 9, NULL, &c, 1,
               NULL, NULL, NULL) == GDEFCORE_OK;
  };
  size_structs::Run("tests/test_settings.cpp", probes);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
