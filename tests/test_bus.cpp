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
 * The bus-as-accelerator gate (AD-25, AD-31).
 *
 * What exists: defiant-core has no bus. A "node" here is a host (its compiled
 * hook chains) and a catalog handle (its epoch reads), and two or more of them
 * run over one store, as two processes would over one database. Nothing in the
 * library accepts a bus message, so the bus in this file is the test's: it
 * carries "tenant moved to epoch E" from the node that committed to every
 * other node, and it drops, duplicates and reorders. Each node's test-side
 * accelerator acts on what it receives (it keeps a hint, and drops fragments
 * it cached). What is gated is the other half of AD-31: whatever the bus does,
 * a node resolves against the committed epoch in the store, so the configuration
 * it runs, the key its fragments are cached under and the sessions it accepts
 * are the committed ones. The staleness bound is zero here: the library reads
 * the epoch on every resolve and keeps no copy of its own.
 *
 * tools/check-bus.sh plants a node that remembers an epoch and trusts it, in a
 * copy of the source, and requires these tests to fail.
 */

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage/model.h>

#include <gtest/gtest.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace {

const uint8_t kTenant[] = {'t'};
const uint64_t kLife = 3600;

/* ---- the bus ------------------------------------------------------------ */

struct Stats {
  int sent = 0;
  int dropped = 0;
  int duplicated = 0;
  int reordered = 0;
  int behind = 0;  // a node's hint was behind the committed epoch when it served
};

/* One notice: the tenant is at this epoch. */
using Notice = uint64_t;

class LossyBus {
 public:
  LossyBus(uint64_t seed, size_t nodes) : rng_(seed), inbox_(nodes) {}

  /* The committing node tells every other node. Each copy is dropped,
   * delivered, or delivered twice, independently. */
  void Publish(size_t from, Notice notice) {
    for (size_t i = 0; i < inbox_.size(); i++) {
      if (i == from) {
        continue;
      }
      stats.sent += 1;
      int roll = (int)(rng_() % 100);
      if (roll < 40) {
        stats.dropped += 1;
        continue;
      }
      inbox_[i].push_back(notice);
      if (roll >= 75) {
        stats.duplicated += 1;
        inbox_[i].push_back(notice);
      }
    }
  }

  /* What node @p i receives now, in an order of the bus's choosing, or
   * nothing yet. */
  std::vector<Notice> Receive(size_t i) {
    std::vector<Notice> got;
    if (rng_() % 100 < 30) {
      return got;
    }
    got.swap(inbox_[i]);
    std::shuffle(got.begin(), got.end(), rng_);
    if (!std::is_sorted(got.begin(), got.end())) {
      stats.reordered += 1;
    }
    return got;
  }

  Stats stats;

 private:
  std::mt19937_64 rng_;
  std::vector<std::vector<Notice>> inbox_;
};

/* The committed epoch, read from the store and not through the library. */
/* The config epoch as the store has it: the counter `core.epoch`, read
 * straight off the port (a system counter since story S6b). */
uint64_t CommittedEpoch(GDEFSTOR_Store * store) {
  uint64_t epoch = 0;
  if (gdefstor_counter_peek(store, (const char *)kTenant, 1, "core.epoch", 10,
          &epoch) != GDEFSTOR_OK) {
    return 0;
  }
  return epoch;
}

/* ---- a node ------------------------------------------------------------- */

struct Vote {
  int calls = 0;
};

extern "C" GDEFCORE_Result OnCount(GDEFCORE_Request *, const void *,
    GDEFCORE_Alter *, GDEFCORE_Hook_Out *, void * user) {
  ((Vote *)user)->calls += 1;
  return GDEFCORE_OK;
}

GDEFCORE_Module_Manifest gManifest;
GDEFCORE_Module_Sub gSub;
#define BUS_STR2(x) #x
#define BUS_STR(x) BUS_STR2(x)
const char kCoreToken[] = BUS_STR(GHOTIIO_DEFCORE_NAME);

extern "C" const GDEFCORE_Module_Manifest * Guest(void) {
  return &gManifest;
}

struct Node {
  GDEFCORE_Catalog * catalog = NULL;
  GDEFCORE_Host * host = NULL;
  GDEFCORE_Request * request = NULL;
  Vote vote;
  /* The test-side accelerator: it believes the bus. */
  uint64_t hint = 0;
  std::map<std::string, std::string> fragments;
};

void Deliver(LossyBus & bus, std::vector<std::unique_ptr<Node>> & nodes, size_t i) {
  for (Notice notice : bus.Receive(i)) {
    if (notice > nodes[i]->hint) {
      nodes[i]->hint = notice;
    }
    /* The bus's job: a notice drops this node's cached fragments. */
    nodes[i]->fragments.clear();
  }
}

class Bus : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  std::vector<std::unique_ptr<Node>> nodes_;

  void TearDown() override {
    for (auto & node : nodes_) {
      gdefcore_request_destroy(node->request);
      gdefcore_catalog_bind_host(node->catalog, NULL);
      gdefcore_host_destroy(node->host);
      gdefcore_catalog_destroy(node->catalog);
    }
    gdefstor_store_destroy(store_);
  }

  void OpenStore() {
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
  }

  Node * AddNode(bool with_host) {
    auto node = std::make_unique<Node>();
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, kTenant, 1, NULL, NULL, &node->catalog));
    if (with_host) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_host_open(store_, NULL, &node->host));
      gdefcore_catalog_bind_host(node->catalog, node->host);
      memset(&gManifest, 0, sizeof gManifest);
      memset(&gSub, 0, sizeof gSub);
      gSub.size = sizeof gSub;
      gSub.hook = "bus.event";
      gSub.hook_len = 9;
      gSub.kind = GDEFCORE_HOOK_EVENT;
      gSub.fn = OnCount;
      gSub.user = &node->vote;
      gManifest.size = sizeof gManifest;
      gManifest.core_token = kCoreToken;
      gManifest.core_token_len = strlen(kCoreToken);
      gManifest.schema_version = 1;
      gManifest.name = "m";
      gManifest.name_len = 1;
      gManifest.label = "m";
      gManifest.label_len = 1;
      gManifest.subs = &gSub;
      gManifest.nsubs = 1;
      EXPECT_EQ(GDEFCORE_OK, gdefcore_module_install_guest(node->host, Guest));
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_request_create(kTenant, 1, 0, 0, NULL, &node->request));
    nodes_.push_back(std::move(node));
    return nodes_.back().get();
  }

  /* Commit a change of configuration from @p node: turn the module on or off. */
  void Commit(Node * node, bool on) {
    GDEFCORE_Changeset * changeset = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(node->catalog, NULL, 0, &changeset));
    gdefcore_changeset_set_request(changeset, node->request);
    if (on) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_module_enable(node->host, changeset, "m", 1));
    } else {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_module_disable(node->host, changeset, "m", 1));
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(changeset, "m", 1));
    gdefcore_changeset_destroy(changeset);
  }
};

/* ---- the configuration a node runs -------------------------------------- */

TEST_F(Bus, ConfigEpoch) {
  const size_t kNodes = 3;
  const int kRounds = 80;
  LossyBus bus(0x5eed, kNodes);
  bool on = false;
  uint64_t last = 0;
  OpenStore();
  for (size_t i = 0; i < kNodes; i++) {
    AddNode(true);
  }
  for (int round = 0; round < kRounds; round++) {
    size_t from = (size_t)(round * 7 % (int)kNodes);
    on = !on;
    Commit(nodes_[from].get(), on);
    uint64_t committed = CommittedEpoch(store_);
    ASSERT_GT(committed, last) << "a committed change did not move the epoch";
    last = committed;
    bus.Publish(from, committed);
    for (size_t i = 0; i < kNodes; i++) {
      Node * node = nodes_[i].get();
      uint64_t seen = 0;
      int before = node->vote.calls;
      Deliver(bus, nodes_, i);
      if (node->hint < committed) {
        bus.stats.behind += 1;
      }
      /* Whatever the bus did, the node resolves at the committed epoch... */
      ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(node->catalog, &seen));
      EXPECT_EQ(committed, seen) << "node " << i << " round " << round;
      /* ...and runs the committed configuration, not the one it compiled. */
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_hook_fire(node->host, node->request, node->catalog, "bus.event",
              9, GDEFCORE_HOOK_EVENT, NULL, NULL, NULL));
      EXPECT_EQ(on ? 1 : 0, node->vote.calls - before)
          << "node " << i << " round " << round << " epoch " << committed;
    }
  }
  /* The control: the bus did all three things, and left nodes behind, so a
   * node that believed its hint would have been wrong. */
  EXPECT_GT(bus.stats.dropped, 0);
  EXPECT_GT(bus.stats.duplicated, 0);
  EXPECT_GT(bus.stats.reordered, 0);
  EXPECT_GT(bus.stats.behind, 0);
}

/* ---- the key a fragment is cached under --------------------------------- */

std::string EpochOfKey(const std::string & key) {
  size_t at = key.find("\nepoch:");
  if (at == std::string::npos) {
    return std::string();
  }
  at += 7;
  return key.substr(at, key.find('\n', at) - at);
}

TEST_F(Bus, FragmentKey) {
  const size_t kNodes = 3;
  const int kRounds = 60;
  LossyBus bus(0xfeed, kNodes);
  bool on = false;
  int hits = 0;
  int survivors = 0;
  OpenStore();
  for (size_t i = 0; i < kNodes; i++) {
    char * warm = NULL;
    size_t warm_len = 0;
    Node * node = AddNode(true);
    /* The first key makes the access layer set itself up, which is a commit. */
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_access_render_key(node->catalog, node->request, NULL, 0, NULL, 0,
            &warm, &warm_len));
    gdefcore_text_free(node->catalog, warm);
  }
  for (int round = 0; round < kRounds; round++) {
    size_t from = (size_t)(round % (int)kNodes);
    on = !on;
    Commit(nodes_[from].get(), on);
    uint64_t committed = CommittedEpoch(store_);
    bus.Publish(from, committed);
    /* Each node serves the page twice, so that the second serve can hit. */
    for (int pass = 0; pass < 2; pass++) {
      for (size_t i = 0; i < kNodes; i++) {
        Node * node = nodes_[i].get();
        char * key = NULL;
        size_t key_len = 0;
        if (pass == 0) {
          Deliver(bus, nodes_, i);
        }
        /* An entry from an older epoch that the bus did not clear. */
        for (auto & entry : node->fragments) {
          if (EpochOfKey(entry.first) != std::to_string(committed)) {
            survivors += 1;
          }
        }
        ASSERT_EQ(GDEFCORE_OK,
            gdefcore_access_render_key(node->catalog, node->request, NULL, 0, NULL,
                0, &key, &key_len));
        std::string k(key, key_len);
        gdefcore_text_free(node->catalog, key);
        ASSERT_EQ(std::to_string(committed), EpochOfKey(k))
            << "node " << i << " round " << round << ": the key is not at the committed epoch";
        std::string body;
        auto hit = node->fragments.find(k);
        if (hit != node->fragments.end()) {
          hits += 1;
          body = hit->second;
        } else {
          uint64_t seen = 0;
          ASSERT_EQ(GDEFCORE_OK, gdefcore_epoch(node->catalog, &seen));
          body = "page@" + std::to_string(seen);
          node->fragments[k] = body;
        }
        EXPECT_EQ("page@" + std::to_string(committed), body)
            << "node " << i << " round " << round;
      }
    }
  }
  /* The control: the cache was used, and the bus left old entries in it that
   * only the key kept from being served. */
  EXPECT_GT(hits, 0);
  EXPECT_GT(survivors, 0);
}

/* ---- the sessions a node accepts ---------------------------------------- */

TEST_F(Bus, SessionEpoch) {
  const size_t kNodes = 2;
  LossyBus bus(0xc0de, kNodes);
  uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
  GDEFCORE_Keyring * keyring = NULL;
  char admin[GDEFCORE_PUBLIC_ID_LEN + 1];
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  std::string password = "secret";
  memset(root, 0x42, sizeof root);
  OpenStore();
  AddNode(false);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_keyring_create(root, sizeof root, NULL, &keyring));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_access_admin_principal(nodes_[0]->catalog, admin));
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_account_bind(nodes_[0]->catalog, keyring, root, sizeof root, admin,
          strlen(admin), "ada", 3, password.data(), password.size(), id));
  AddNode(false);  // the second node opens after the first has defined the types

  auto login = [&](Node * node) {
    char * token = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_login(node->catalog, keyring, root, sizeof root, "ada", 3,
            password.data(), password.size(), kLife, &token, &n));
    std::string out(token == NULL ? "" : token, n);
    gdefcore_text_free(node->catalog, token);
    return out;
  };
  auto admitted = [&](Node * node, const std::string & token) {
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_account_check(node->catalog, node->request, keyring, root,
            sizeof root, token.data(), token.size()));
    return gdefcore_request_principal(node->request, &n) != NULL;
  };

  /* Both nodes admit a fresh session, and have seen the account's epoch. */
  std::string token = login(nodes_[0].get());
  EXPECT_TRUE(admitted(nodes_[0].get(), token));
  EXPECT_TRUE(admitted(nodes_[1].get(), token));

  /* Each revocation is made on one node; the notice to the other is the
   * bus's to lose. The next request on either node is anonymous. */
  for (int round = 0; round < 4; round++) {
    size_t from = (size_t)(round % 2);
    Node * actor = nodes_[from].get();
    uint64_t before = 0;
    uint64_t after = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_account_epoch(actor->catalog, id, strlen(id), &before));
    if (round % 2 == 0) {
      password = "next" + std::to_string(round);
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_account_password(actor->catalog, keyring, root, sizeof root, id,
              strlen(id), password.data(), password.size(), "ada", 3));
    } else {
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_account_logout_everywhere(actor->catalog, id, strlen(id), "ada", 3));
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_account_epoch(actor->catalog, id, strlen(id), &after));
    ASSERT_GT(after, before);
    bus.Publish(from, after);
    for (size_t i = 0; i < kNodes; i++) {
      Deliver(bus, nodes_, i);
      if (nodes_[i]->hint < after) {
        bus.stats.behind += 1;
      }
      EXPECT_FALSE(admitted(nodes_[i].get(), token))
          << "node " << i << " admitted a revoked session after round " << round;
    }
    /* The control: a session made after the change is admitted by both. */
    token = login(actor);
    for (size_t i = 0; i < kNodes; i++) {
      EXPECT_TRUE(admitted(nodes_[i].get(), token))
          << "node " << i << " refused a current session after round " << round;
    }
  }
  EXPECT_GT(bus.stats.dropped + bus.stats.behind, 0);
  gdefcore_keyring_destroy(keyring);
}

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
