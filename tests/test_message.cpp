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
 * The session's message queue (site admin story 9): a message left by a save,
 * an error or a refusal is shown once, to the session that was left it and to
 * no other, escaped, and not past its lifetime; a record that was altered or
 * moved shows nothing. The page tests go through the messages widget of a real
 * layout.
 *
 * Every test carries a CONTROL (the message that is shown, the session that is
 * its own), so a refusal is a refusal. The real-source plants are in
 * tools/check-message.sh, and each names the test that must turn red.
 */

#include "grants_fixture.h"
#include "size_structs.h"

#include <ghoti.io/defiant-storage/model.h>

#include <ctime>
#include <map>
#include <vector>

namespace {

using namespace gfx;

const char kNs[] = "core.message";
const char kEnv[] = "\x03";

class Message : public GrantsFixture {
 protected:
  GDEFCORE_Keyring * keyring_ = NULL;
  uint8_t root_[GDEFCORE_ACCOUNT_ROOT_LEN];
  std::string ada_, bob_;

  void SetUp() override {
    GrantsFixture::SetUp();
    uint8_t * bytes = NULL;
    size_t n = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_kit(catalog_, &bytes, &n));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_render_install(catalog_, bytes, n));
    gdefcore_text_free(catalog_, (char *)bytes);
    memset(root_, 0x42, sizeof root_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_keyring_create(root_, sizeof root_, NULL, &keyring_));
    char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    ASSERT_EQ(GDEFCORE_OK, gdefcore_account_create(catalog_, keyring_, root_, sizeof root_,
                               "ada", 3, "secret", 6, principal, id));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_account_create(catalog_, keyring_, root_, sizeof root_,
                               "bob", 3, "hunter2", 7, principal, id));
    ada_ = Login("ada", "secret", 3600);
    bob_ = Login("bob", "hunter2", 3600);
  }

  void TearDown() override {
    gdefcore_keyring_destroy(keyring_);
    GrantsFixture::TearDown();
  }

  std::string Login(const char * user, const char * pass, uint64_t life) {
    char * token = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_account_login(catalog_, keyring_, root_, sizeof root_,
                               user, strlen(user), pass, strlen(pass), life, &token, &n));
    std::string out(token == NULL ? "" : token, n);
    gdefcore_text_free(catalog_, token);
    return out;
  }

  /* A request of the session, as the server makes one for each page. */
  GDEFCORE_Request * Bound(const std::string & session, int64_t at = 0) {
    GDEFCORE_Request * r = Req();
    if (at != 0) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_request_set_time(r, at));
    }
    EXPECT_EQ(GDEFCORE_OK, gdefcore_message_bind(catalog_, r, keyring_, root_, sizeof root_,
                               session.data(), session.size()));
    return r;
  }

  GDEFCORE_Result Post(GDEFCORE_Request * r, const std::string & text,
      int kind = GDEFCORE_MESSAGE_STATUS) {
    return gdefcore_message_post(catalog_, r, kind, text.data(), text.size());
  }

  /* What a claim returns, as "kind:text" in order. */
  std::vector<std::string> Take(GDEFCORE_Request * r) {
    std::vector<std::string> out;
    GDEFCORE_Messages * m = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_message_take(catalog_, r, &m));
    for (size_t i = 0; i < gdefcore_messages_count(m); i++) {
      GDEFCORE_Message item;
      memset(&item, 0, sizeof item);
      item.size = sizeof item;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_messages_item(m, i, &item));
      out.push_back(std::to_string(item.kind) + ":" + std::string(item.text, item.text_len));
    }
    gdefcore_messages_free(m);
    return out;
  }

  struct Rec {
    std::string key;
    std::string bytes;
  };

  /* Every record of the queue, in the store, whoever it belongs to. */
  std::vector<Rec> Records() {
    std::vector<Rec> out;
    GDEFSTOR_RecordList * list = NULL;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_record_list(store_, kEnv, 1, kNs, sizeof kNs - 1, "", 0, 0,
                               1000, &list));
    for (size_t i = 0; i < gdefstor_record_list_count(list); i++) {
      const char * key;
      size_t key_len;
      const uint8_t * bytes;
      size_t len;
      EXPECT_EQ(GDEFSTOR_OK, gdefstor_record_list_item(list, i, &key, &key_len, &bytes, &len,
                                 NULL, NULL));
      out.push_back({std::string(key, key_len), std::string((const char *)bytes, len)});
    }
    gdefstor_record_list_free(list);
    return out;
  }

  void PutRecord(const std::string & key, const std::string & bytes) {
    GDEFSTOR_Write * w = NULL;
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_begin(store_, kEnv, 1, NULL, &w));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_record_put(w, kNs, sizeof kNs - 1, key.data(), key.size(),
                               GDEFCORE_SCHEMA_CORE_STAMP,
                               sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1,
                               (const uint8_t *)bytes.data(), bytes.size()));
    ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(w));
  }

  /* The front page draws the messages widget, as a site that wants it shown does. */
  void PlaceMessages() {
    char ** ids = NULL;
    size_t n = 0;
    std::string front;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_ids(catalog_, "core.display", 12, &ids, &n));
    for (size_t i = 0; i < n && front.empty(); i++) {
      char ** t = NULL;
      size_t * l = NULL;
      size_t c = 0;
      if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, ids[i], strlen(ids[i]),
              "en", 2, "name", 4, &t, &l, &c) == GDEFCORE_OK) {
        if (c > 0 && std::string(t[0], l[0]) == "front") {
          front = ids[i];
        }
        gdefcore_values_free(catalog_, t, l, c);
      }
    }
    gdefcore_ids_free(catalog_, ids, n);
    ASSERT_FALSE(front.empty());
    const char * panes[1] = {"main messages"};
    size_t lens[1] = {strlen(panes[0])};
    GDEFCORE_Value v;
    memset(&v, 0, sizeof v);
    v.size = sizeof v;
    v.field = "panes";
    v.field_len = 5;
    v.texts = panes;
    v.text_lens = lens;
    v.count = 1;
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, front.data(), front.size(), "en", 2, &v, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.display", 12));
    gdefcore_changeset_destroy(cs);
  }

  std::string Page(GDEFCORE_Request * r) {
    GDEFCORE_Routes * routes = NULL;
    char * bytes = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_routes_create(NULL, &routes));
    GDEFCORE_Result rc = gdefcore_render_page(catalog_, routes, r, "/", 1,
        GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n);
    gdefcore_routes_destroy(routes);
    if (rc != GDEFCORE_OK) {
      return std::string("<error ") + gdefcore_result_string(rc) + ">";
    }
    std::string out(bytes, n);
    gdefcore_text_free(catalog_, bytes);
    return out;
  }
};

bool Has(const std::string & hay, const std::string & needle) {
  return hay.find(needle) != std::string::npos;
}

}  // namespace

TEST_F(Message, AMessageIsShownOnceAndNeverToAnotherSession) {
  PlaceMessages();
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Saved.", GDEFCORE_MESSAGE_STATUS));
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Not allowed.", GDEFCORE_MESSAGE_REFUSAL));
  /* A different session is shown none of it, and does not use it up. */
  EXPECT_FALSE(Has(Page(Bound(bob_)), "Saved."));
  EXPECT_TRUE(Take(Bound(bob_)).empty());
  /* A second session of the same account is a different session. */
  std::string ada_again = Login("ada", "secret", 3600);
  ASSERT_NE(ada_, ada_again);
  EXPECT_TRUE(Take(Bound(ada_again)).empty());
  /* CONTROL: the session it was left is shown it, in order, with its kind. */
  std::string page = Page(Bound(ada_));
  EXPECT_TRUE(Has(page, "<div class=\"message status\">Saved.</div>")) << page;
  EXPECT_TRUE(Has(page, "<div class=\"message refusal\">Not allowed.</div>")) << page;
  EXPECT_LT(page.find("Saved."), page.find("Not allowed."));
  /* And then they are gone: the refresh, the next page, a lost response. */
  EXPECT_FALSE(Has(Page(Bound(ada_)), "message")) << "shown once";
  EXPECT_TRUE(Take(Bound(ada_)).empty());
  EXPECT_TRUE(Records().empty()) << "nothing is left in the store";
  /* A claim that already happened cannot happen again: the second of two
   * requests that both ask is shown nothing. */
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Once."));
  GDEFCORE_Request * first = Bound(ada_);
  GDEFCORE_Request * second = Bound(ada_);
  EXPECT_EQ(1u, Take(first).size());
  EXPECT_EQ(0u, Take(second).size());
}

TEST_F(Message, TheWidgetCanBeDrawnOnItsOwnAndClaimsWhatItDraws) {
  auto draw = [&](GDEFCORE_Request * r) {
    char * bytes = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_render_widget(catalog_, NULL, r, NULL, "messages", 8, "", 0,
                               "/admin", 6, GDEFCORE_RENDER_PAGE_FUEL, &bytes, &n));
    std::string out(bytes == NULL ? "" : bytes, n);
    gdefcore_text_free(catalog_, bytes);
    return out;
  };
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Saved.", GDEFCORE_MESSAGE_STATUS));
  EXPECT_EQ("", draw(Bound(bob_)));
  EXPECT_EQ("", draw(Req()));
  EXPECT_EQ("<div class=\"message status\">Saved.</div>", draw(Bound(ada_)));
  EXPECT_EQ("", draw(Bound(ada_))) << "shown once";
  GDEFCORE_Request * r = Req();
  char * bytes = NULL;
  size_t n = 0;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_render_widget(catalog_, NULL, r, NULL, "messages", 8,
                                      "no-such-template", 16, "/", 1, GDEFCORE_RENDER_PAGE_FUEL,
                                      &bytes, &n));
}

TEST_F(Message, AVisitorAndAMadeUpSessionHaveNoQueue) {
  GDEFCORE_Request * visitor = Req();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Post(visitor, "Saved."));
  GDEFCORE_Messages * m = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_message_take(catalog_, visitor, &m));
  EXPECT_EQ(nullptr, m);
  /* A token nobody made, one with its tag damaged, and the other tenant's. */
  GDEFCORE_Request * r = Req();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_message_bind(catalog_, r, keyring_, root_, sizeof root_,
                                      "not-a-session", 13));
  std::string damaged = ada_;
  damaged[damaged.size() - 3] ^= 1;
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_message_bind(catalog_, r, keyring_, root_, sizeof root_,
                                      damaged.data(), damaged.size()));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Post(r, "Saved."));
  EXPECT_TRUE(Records().empty());
  /* CONTROL: the real one binds. */
  EXPECT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Saved."));
  /* The page of a visitor shows no trace of the widget. */
  PlaceMessages();
  EXPECT_FALSE(Has(Page(Req()), "message"));
  EXPECT_FALSE(Has(Page(visitor), "Saved."));
}

TEST_F(Message, TheStoreHoldsNeitherTheTextNorTheSession) {
  const std::string text = "The quick brown fox, kept secret.";
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), text));
  std::vector<Rec> rec = Records();
  ASSERT_EQ(1u, rec.size());
  EXPECT_FALSE(Has(rec[0].bytes, "quick brown")) << "sealed";
  EXPECT_FALSE(Has(rec[0].bytes, text));
  EXPECT_FALSE(Has(rec[0].key, ada_)) << "the token is a bearer credential";
  EXPECT_GE(rec[0].bytes.size(), text.size() + 1 + 21 + 16);
  /* CONTROL: it opens for its own session. */
  EXPECT_EQ(std::vector<std::string>({"1:" + text}), Take(Bound(ada_)));
}

TEST_F(Message, AForgedOrMovedMessageIsRejectedAndShowsNothing) {
  /* One record for each of two sessions, taken from the store as written. */
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Saved ada."));
  const Rec for_ada = Records().at(0);
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(bob_), "Saved bob."));
  Rec for_bob;
  for (const Rec & r : Records()) {
    if (r.key != for_ada.key) {
      for_bob = r;
    }
  }
  ASSERT_FALSE(for_bob.key.empty());
  ASSERT_EQ(std::vector<std::string>({"1:Saved ada."}), Take(Bound(ada_)));
  ASSERT_EQ(std::vector<std::string>({"1:Saved bob."}), Take(Bound(bob_)));
  ASSERT_TRUE(Records().empty());
  /* An altered record, whatever byte of it is altered. */
  for (size_t at = 0; at < for_ada.bytes.size(); at += 3) {
    std::string tampered = for_ada.bytes;
    tampered[at] ^= 0x01;
    PutRecord(for_ada.key, tampered);
    PutRecord(for_bob.key, for_bob.bytes);
    EXPECT_TRUE(Take(Bound(ada_)).empty()) << "byte " << at << " altered";
    EXPECT_EQ(std::vector<std::string>({"1:Saved bob."}), Take(Bound(bob_)))
        << "a different session's record is not touched by it";
    EXPECT_TRUE(Records().empty()) << "what did not open was dropped";
  }
  /* A record moved to a different session's queue is not opened there. */
  PutRecord(for_bob.key, for_ada.bytes);
  EXPECT_TRUE(Take(Bound(bob_)).empty());
  EXPECT_TRUE(Take(Bound(ada_)).empty());
  /* Nor is a record put at another place in its own queue (a replay under
   * another number), nor one that is too short to be one. */
  std::string elsewhere = for_ada.key.substr(0, for_ada.key.rfind(':') + 1) + "0000000000000002";
  PutRecord(elsewhere, for_ada.bytes);
  PutRecord(for_ada.key.substr(0, for_ada.key.rfind(':') + 1) + "0000000000000003", "x");
  EXPECT_TRUE(Take(Bound(ada_)).empty());
  EXPECT_TRUE(Records().empty());
  /* CONTROL: the untouched records are shown to their own sessions. */
  PutRecord(for_ada.key, for_ada.bytes);
  PutRecord(for_bob.key, for_bob.bytes);
  EXPECT_EQ(std::vector<std::string>({"1:Saved ada."}), Take(Bound(ada_)));
  EXPECT_EQ(std::vector<std::string>({"1:Saved bob."}), Take(Bound(bob_)));
}

TEST_F(Message, TextIsEscapedAndNeverMarkup) {
  PlaceMessages();
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "<script>alert(1)</script> & \"q\"",
                             GDEFCORE_MESSAGE_ERROR));
  std::string page = Page(Bound(ada_));
  EXPECT_TRUE(Has(page, "&lt;script&gt;alert(1)&lt;/script&gt;")) << page;
  EXPECT_FALSE(Has(page, "<script")) << page;
  EXPECT_TRUE(Has(page, "class=\"message error\"")) << page;
  /* CONTROL: plain text comes through as it is. */
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Plain words."));
  EXPECT_TRUE(Has(Page(Bound(ada_)), ">Plain words.</div>"));
}

TEST_F(Message, AMessageNotShownByItsExpiryIsDropped) {
  const int64_t now = (int64_t)time(NULL);
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_, now), "Late."));
  /* Not yet expired: shown. */
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_, now), "On time."));
  EXPECT_EQ(2u, Take(Bound(ada_, now + GDEFCORE_MESSAGE_LIFE - 1)).size());
  /* Past its lifetime: dropped, and gone from the store. */
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_, now), "Late."));
  EXPECT_TRUE(Take(Bound(ada_, now + GDEFCORE_MESSAGE_LIFE + 1)).empty());
  EXPECT_TRUE(Records().empty());
  /* Never past the session's own expiry. */
  std::string brief = Login("bob", "hunter2", 30);
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(brief, now), "Short."));
  EXPECT_TRUE(Take(Bound(brief, now + 60)).empty());
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(brief, now), "Short."));
  EXPECT_EQ(1u, Take(Bound(brief, now + 10)).size()) << "CONTROL";
  /* A post sweeps the expired ones of its session. */
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_, now), "Old."));
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_, now + GDEFCORE_MESSAGE_LIFE + 5), "New."));
  EXPECT_EQ(1u, Records().size());
}

TEST_F(Message, TheQueueIsBoundedAndTheTextIsLimited) {
  for (int i = 0; i < GDEFCORE_MESSAGE_QUEUE_MAX + 3; i++) {
    ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "m" + std::to_string(i)));
  }
  std::vector<std::string> seen = Take(Bound(ada_));
  ASSERT_EQ((size_t)GDEFCORE_MESSAGE_QUEUE_MAX, seen.size());
  EXPECT_EQ("1:m3", seen.front()) << "the oldest were dropped";
  EXPECT_EQ("1:m" + std::to_string(GDEFCORE_MESSAGE_QUEUE_MAX + 2), seen.back());
  /* One session's flood does not touch another's. */
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(bob_), "Mine."));
  for (int i = 0; i < 2 * GDEFCORE_MESSAGE_QUEUE_MAX; i++) {
    ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "x"));
  }
  EXPECT_EQ(std::vector<std::string>({"1:Mine."}), Take(Bound(bob_)));
  /* The text. */
  GDEFCORE_Request * r = Bound(ada_);
  EXPECT_EQ(GDEFCORE_ERR_LIMIT, Post(r, std::string(GDEFCORE_MESSAGE_TEXT_MAX + 1, 'a')));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Post(r, "x", 0));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, Post(r, "x", 9));
  EXPECT_EQ(GDEFCORE_OK, Post(r, std::string(GDEFCORE_MESSAGE_TEXT_MAX, 'a'))) << "CONTROL";
  EXPECT_EQ(GDEFCORE_MESSAGE_TEXT_MAX, (int)Take(r).back().size() - 2);
}

TEST_F(Message, TheKeysAreWipedWithTheRequestAndAPageWithAQueueIsNotCacheable) {
  PlaceMessages();
  GDEFCORE_Request * visitor = Req();
  (void)Page(visitor);
  EXPECT_TRUE(gdefcore_request_cacheable(visitor)) << "CONTROL: no queue, nothing to keep out";
  GDEFCORE_Request * r = Bound(ada_);
  const uint64_t offered = gdefcore_render_shareable_count();
  (void)Page(r);
  EXPECT_EQ(offered, gdefcore_render_shareable_count()) << "a session's messages are not offered to a shared cache";
  EXPECT_FALSE(gdefcore_request_cacheable(r)) << "what the page shows depends on the queue";
  EXPECT_NE(nullptr, gdefcore_request_attached(r, "core.message.box"));
  EXPECT_EQ(nullptr, gdefcore_request_attached(r, "nothing"));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_request_attach(NULL, "x", NULL, NULL));
}

TEST_F(Message, EveryStructTheMessageApiTakesIsCheckedAtItsOwnSize) {
  ASSERT_EQ(GDEFCORE_OK, Post(Bound(ada_), "Saved."));
  GDEFCORE_Request * r = Bound(ada_);
  GDEFCORE_Messages * m = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_message_take(catalog_, r, &m));
  std::map<std::string, size_structs::Probe> probes;
  probes["GDEFCORE_Message"] = [&](size_t size) {
    GDEFCORE_Message item;
    memset(&item, 0, sizeof item);
    item.size = size;
    return gdefcore_messages_item(m, 0, &item) == GDEFCORE_OK;
  };
  size_structs::Run("tests/test_message.cpp", probes);
  gdefcore_messages_free(m);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
