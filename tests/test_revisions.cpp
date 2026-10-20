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
 * The entity record on the storage port (story A5b, SPEC decisions 9-11, as
 * decision 13 and story S6b leave them): the published flag, the version and
 * the creator, beside the append-only revisions, and the draft, which is never
 * a revision. The newest revision is always the entity's content; there is no
 * active-revision pointer. One test per row of the transition table, each
 * with a control (the same call on the other side of the rule answers
 * differently). Run by tools/check-revisions.sh, which plants a defect for
 * each named rule.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage/model.h>
#include <ghoti.io/defiant-storage/snapshot.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

namespace {

const char kTenant[] = "t";

std::string PrincipalId(uint8_t seed) {
  uint8_t raw[16];
  char out[GDEFCORE_PUBLIC_ID_LEN + 1];
  memset(raw, seed, sizeof raw);
  raw[0] = 0;
  EXPECT_EQ(GDEFCORE_OK, gdefcore_id_encode(raw, out));
  return std::string(out);
}

class Revisions : public ::testing::Test {
 protected:
  GDEFSTOR_Store * store_ = NULL;
  GDEFCORE_Catalog * catalog_ = NULL;
  std::string alice_ = PrincipalId(1);
  std::string bob_ = PrincipalId(2);
  std::string carol_ = PrincipalId(3);

  void SetUp() override {
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &store_));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_catalog_open(store_, (const uint8_t *)kTenant, 1, NULL, NULL,
            &catalog_));
    GDEFCORE_Field fields[2];
    memset(fields, 0, sizeof fields);
    fields[0].size = sizeof fields[0];
    fields[0].name = "title";
    fields[0].name_len = 5;
    fields[0].required = 1;
    fields[1].size = sizeof fields[1];
    fields[1].name = "tags";
    fields[1].name_len = 4;
    fields[1].many = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, "site.note", 9, GDEFCORE_TYPE_CONTENT,
            fields, 2));
  }

  void TearDown() override {
    gdefcore_catalog_destroy(catalog_);
    gdefstor_store_destroy(store_);
  }

  std::string Create() {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, "site.note", 9, id, NULL));
    return std::string(id);
  }

  GDEFCORE_Changeset * Prepare(const std::string & actor) {
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_, actor.empty() ? NULL : actor.c_str(),
            actor.size(), &cs));
    return cs;
  }

  GDEFCORE_Result Write(const std::string & actor, const std::string & id,
      const std::string & title, bool draft) {
    GDEFCORE_Changeset * cs = Prepare(actor);
    const char * texts[1] = {title.c_str()};
    size_t lens[1] = {title.size()};
    GDEFCORE_Value value;
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "title";
    value.field_len = 5;
    value.texts = texts;
    value.text_lens = lens;
    value.count = 1;
    GDEFCORE_Result rc = (draft ? gdefcore_entity_save_draft
                                : gdefcore_entity_save)(
        cs, id.c_str(), id.size(), "en", 2, &value, 1);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  void Save(const std::string & actor, const std::string & id,
      const std::string & title) {
    ASSERT_EQ(GDEFCORE_OK, Write(actor, id, title, false));
  }

  void Draft(const std::string & actor, const std::string & id,
      const std::string & title) {
    ASSERT_EQ(GDEFCORE_OK, Write(actor, id, title, true));
  }

  void Publish(const std::string & actor, const std::string & id) {
    GDEFCORE_Changeset * cs = Prepare(actor);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, id.c_str(), id.size()));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }

  GDEFCORE_Result Unpublish(const std::string & actor, const std::string & id) {
    GDEFCORE_Changeset * cs = Prepare(actor);
    GDEFCORE_Result rc = gdefcore_entity_unpublish(cs, id.c_str(), id.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result RevertTo(const std::string & actor, const std::string & id,
      uint64_t seq) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc = gdefcore_changeset_revert_to(catalog_, id.c_str(),
        id.size(), seq, actor.empty() ? NULL : actor.c_str(), actor.size(), &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  size_t Count(const std::string & id) {
    size_t n = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision_count(catalog_, id.c_str(), id.size(), &n));
    return n;
  }

  /* An entity with one revision is cleared by reverting it. */
  void Clear(const std::string & id) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revert(catalog_, id.c_str(), id.size(), NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }

  /* The title in a view, or "<none>" when the view has no such entity. */
  std::string Title(int view, const std::string & id) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    GDEFCORE_Result rc = gdefcore_entity_values(catalog_, NULL, view, id.c_str(),
        id.size(), "en", 2, "title", 5, &texts, &lens, &count);
    if (rc != GDEFCORE_OK) {
      return rc == GDEFCORE_ERR_INVALID ? "<none>" : "<error>";
    }
    std::string out(texts[0], lens[0]);
    gdefcore_values_free(catalog_, texts, lens, count);
    return out;
  }

  std::string Actor(const std::string & id) {
    char * actor = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_actor(catalog_, id.c_str(), id.size(), &actor, &n));
    std::string out = actor == NULL ? "<none>" : std::string(actor, n);
    gdefcore_text_free(catalog_, actor);
    return out;
  }

  std::string Creator(const std::string & id) {
    char * creator = NULL;
    size_t n = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_creator(catalog_, id.c_str(), id.size(), &creator, &n));
    std::string out = creator == NULL ? "<none>" : std::string(creator, n);
    gdefcore_text_free(catalog_, creator);
    return out;
  }

  bool Published(const std::string & id) {
    int state = 0;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_state(catalog_, id.c_str(), id.size(), &state));
    return state == GDEFCORE_STATE_PUBLISHED;
  }

  /* The active revision's sequence, 0 when there is none. */
  uint64_t Active(const std::string & id) {
    int has = 0;
    uint64_t seq = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_active_revision(catalog_, id.c_str(), id.size(), &has,
            &seq));
    EXPECT_EQ(has ? 1 : 0, seq != 0 ? 1 : 0);
    return seq;
  }

  uint64_t Head(const std::string & id) {
    uint64_t seq = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision(catalog_, id.c_str(), id.size(), &seq));
    return seq;
  }

  uint64_t Version(const std::string & id) {
    uint64_t v = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_version(catalog_, id.c_str(), id.size(), &v));
    return v;
  }

  /* What the port's entity record says: "" when there is none. */
  struct Port {
    bool exists = false;
    std::string creator;
    uint64_t revision = 0;
    int published = -1;
    int deleted = -1;
  };
  Port PortEntity(const std::string & id) {
    Port out;
    GDEFSTOR_Entity * e = NULL;
    if (gdefstor_entity_get(store_, kTenant, 1, id.c_str(), id.size(), &e) !=
        GDEFSTOR_OK) {
      return out;
    }
    GDEFSTOR_EntityInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_entity_info(e, &info));
    out.exists = true;
    out.creator.assign(info.creator, info.creator_len);
    out.revision = info.revision;
    out.published = info.published;
    out.deleted = info.deleted;
    gdefstor_entity_free(e);
    return out;
  }

  /* The base revision of the port's draft of @p id, or -1 for none. */
  int64_t DraftBase(const std::string & id) {
    GDEFSTOR_Draft * d = NULL;
    if (gdefstor_draft_get(store_, kTenant, 1, id.c_str(), id.size(), &d) !=
        GDEFSTOR_OK) {
      return -1;
    }
    GDEFSTOR_DraftInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    EXPECT_EQ(GDEFSTOR_OK, gdefstor_draft_info(d, &info));
    gdefstor_draft_free(d);
    return (int64_t)info.base_revision;
  }

  /* Whether @p id is in a query of its type's entities that are something now. */
  bool Listed(const std::string & id) {
    GDEFSTOR_Query q;
    char ** ids = NULL;
    size_t n = 0;
    bool found = false;
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_query_active(catalog_, "site.note", 9, &q, &ids, &n,
            NULL));
    for (size_t i = 0; i < n; i++) {
      found = found || id == ids[i];
    }
    gdefcore_ids_free(catalog_, ids, n);
    return found;
  }

  /* Save title and tags; the revision the save wrote. */
  uint64_t SaveTagged(const std::string & id, const std::string & title,
      const std::vector<std::string> & tags) {
    GDEFCORE_Changeset * cs = Prepare(alice_);
    const char * t[1] = {title.c_str()};
    size_t tl[1] = {title.size()};
    std::vector<const char *> g;
    std::vector<size_t> gl;
    for (const std::string & x : tags) {
      g.push_back(x.c_str());
      gl.push_back(x.size());
    }
    GDEFCORE_Value values[2];
    memset(values, 0, sizeof values);
    values[0].size = sizeof values[0];
    values[0].field = "title";
    values[0].field_len = 5;
    values[0].texts = t;
    values[0].text_lens = tl;
    values[0].count = 1;
    values[1].size = sizeof values[1];
    values[1].field = "tags";
    values[1].field_len = 4;
    values[1].texts = g.data();
    values[1].text_lens = gl.data();
    values[1].count = g.size();
    uint64_t written = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, id.c_str(), id.size(), "en", 2, values, 2));
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revision(cs, id.c_str(), id.size(), &written));
    gdefcore_changeset_destroy(cs);
    return written;
  }
};

}  // namespace

TEST_F(Revisions, CreateReservesTheIdWithADraft) {
  std::string id = Create();
  /* The id is held by an empty draft; there is no port entity yet. */
  EXPECT_FALSE(PortEntity(id).exists);
  EXPECT_EQ(0, DraftBase(id));
  int state = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_state(catalog_, id.c_str(), id.size(), &state));
  EXPECT_EQ(GDEFCORE_STATE_DRAFT, state);
  EXPECT_EQ(0u, Active(id));
  EXPECT_EQ(0u, Head(id));
  EXPECT_EQ(0u, Version(id));
  EXPECT_EQ("<none>", Creator(id));
  EXPECT_EQ("<none>", Actor(id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_DRAFT, id));
  EXPECT_FALSE(Listed(id));
  /* Control: the first save makes the entity, and the reservation is gone. */
  Save(alice_, id, "x");
  Port p = PortEntity(id);
  EXPECT_TRUE(p.exists);
  EXPECT_EQ(alice_, p.creator);
  EXPECT_EQ(1u, p.revision);
  EXPECT_EQ(1, p.published);
  EXPECT_EQ(-1, DraftBase(id));
  EXPECT_TRUE(Listed(id));
}

TEST_F(Revisions, TheFirstDraftMakesTheEntityWithNoRevision) {
  std::string id = Create();
  Draft(alice_, id, "first");
  Port p = PortEntity(id);
  EXPECT_TRUE(p.exists);
  EXPECT_EQ(alice_, p.creator);   /* so that `own` has an answer for a draft */
  EXPECT_EQ(0u, p.revision);
  EXPECT_EQ(0, p.published);
  EXPECT_EQ(0, DraftBase(id));
  EXPECT_EQ(0u, Head(id));
  EXPECT_EQ(0u, Count(id));
  EXPECT_EQ(1u, Version(id));
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_EQ("<none>", Actor(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_DRAFT, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_FALSE(Listed(id));
  /* Control: publishing applies the draft as the first revision. Its author
   * is whoever wrote the draft, not the publisher (defect 1.5.3), and the
   * creator stays the one who drafted it. */
  Publish(bob_, id);
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(1u, Head(id));
  EXPECT_EQ(-1, DraftBase(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_EQ(alice_, Actor(id));
  /* and a publish by the system (no actor) keeps the author too */
  std::string other = Create();
  Draft(alice_, other, "mine too");
  Publish("", other);
  EXPECT_EQ(alice_, Actor(other));
  EXPECT_TRUE(Listed(id));
}

TEST_F(Revisions, ADraftIsNeverARevision) {
  std::string id = Create();
  Save(alice_, id, "first");
  uint64_t version = Version(id);
  Draft(bob_, id, "second");
  EXPECT_EQ(1u, Head(id));
  EXPECT_EQ(1u, Count(id));
  EXPECT_EQ(1, DraftBase(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("second", Title(GDEFCORE_VIEW_DRAFT, id));
  EXPECT_EQ(alice_, Actor(id));
  EXPECT_EQ(version + 1, Version(id));
  /* A second draft builds on the first and replaces it. */
  Draft(carol_, id, "third");
  EXPECT_EQ(1u, Count(id));
  EXPECT_EQ(1, DraftBase(id));
  EXPECT_EQ("third", Title(GDEFCORE_VIEW_DRAFT, id));
  /* control: a publish is what makes it a revision, by the draft's last
   * author */
  Publish(alice_, id);
  EXPECT_EQ(2u, Head(id));
  EXPECT_EQ("third", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ(carol_, Actor(id));
}

TEST_F(Revisions, SaveIsSaveAndPublish) {
  std::string id = Create();
  Save(alice_, id, "hello");
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(1u, Active(id));
  EXPECT_EQ("hello", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("hello", Title(GDEFCORE_VIEW_ACTIVE, id));
  /* a save of an unpublished entity publishes it */
  ASSERT_EQ(GDEFCORE_OK, Unpublish("", id));
  EXPECT_FALSE(Published(id));
  Save(bob_, id, "s");
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(2u, Active(id));
  /* a save on top of a draft saves the working copy and consumes it */
  std::string other = Create();
  Draft(alice_, other, "d");
  Save(bob_, other, "s");
  EXPECT_TRUE(Published(other));
  EXPECT_EQ(1u, Head(other));
  EXPECT_EQ(-1, DraftBase(other));
  EXPECT_EQ("s", Title(GDEFCORE_VIEW_DRAFT, other));
  EXPECT_EQ(alice_, Creator(other));
}

TEST_F(Revisions, PublishAppliesTheDraftAsOneRevision) {
  std::string id = Create();
  Save(alice_, id, "one");
  ASSERT_EQ(GDEFCORE_OK, Unpublish("", id));
  Draft(alice_, id, "two");
  EXPECT_FALSE(Published(id));
  uint64_t before = Version(id);
  Publish(bob_, id);
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(2u, Head(id));
  EXPECT_EQ(2u, Count(id));
  EXPECT_EQ(-1, DraftBase(id));
  EXPECT_EQ("two", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ(before + 1, Version(id));
  /* control: with no draft, a publish only sets the flag */
  ASSERT_EQ(GDEFCORE_OK, Unpublish("", id));
  Publish(bob_, id);
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(2u, Head(id));
}

TEST_F(Revisions, ADraftOnAMovedHeadIsRefused) {
  /* A save consumes a draft, so the head moves past one by a revert (or by
   * another writer between the draft and its publish). */
  std::string id = Create();
  Save(alice_, id, "one");
  Save(alice_, id, "two");
  Draft(alice_, id, "draft of two");
  ASSERT_EQ(GDEFCORE_OK, RevertTo(bob_, id, 1));
  ASSERT_EQ(3u, Head(id));
  ASSERT_EQ(2, DraftBase(id));
  GDEFCORE_Changeset * cs = Prepare(carol_);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_publish(cs, id.c_str(), id.size()));
  EXPECT_NE(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  /* nothing was written, and the draft is still there to be looked at */
  EXPECT_EQ(3u, Head(id));
  EXPECT_EQ("one", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ(2, DraftBase(id));
  /* control: a draft made on the head it is applied on publishes */
  std::string other = Create();
  Save(alice_, other, "one");
  Draft(alice_, other, "draft of one");
  Publish(carol_, other);
  EXPECT_EQ(2u, Head(other));
  EXPECT_EQ("draft of one", Title(GDEFCORE_VIEW_PUBLISHED, other));
}

TEST_F(Revisions, ANoOpSaveWritesNoRevisionAndSaysSo) {
  std::string id = Create();
  EXPECT_EQ(1u, SaveTagged(id, "t", {"a", "b"}));
  uint64_t version = Version(id);
  /* the same values: nothing is written, and the changeset says 0 */
  EXPECT_EQ(0u, SaveTagged(id, "t", {"a", "b"}));
  EXPECT_EQ(1u, Head(id));
  EXPECT_EQ(1u, Count(id));
  EXPECT_EQ(version, Version(id));
  /* control: one value changed is one revision */
  EXPECT_EQ(2u, SaveTagged(id, "t", {"a", "c"}));
  EXPECT_EQ(2u, Head(id));
}

TEST_F(Revisions, TheVersionMovesWhereTheRevisionDoesNot) {
  /* Defect 1.5.2: publish and clear do not move the revision number, which
   * can()'s memo and the render read set were keyed on. Neither does a
   * draft. */
  std::string id = Create();
  EXPECT_EQ(0u, Version(id));
  Draft(alice_, id, "a");
  EXPECT_EQ(1u, Version(id));
  EXPECT_EQ(0u, Head(id));
  Publish("", id);
  EXPECT_EQ(2u, Version(id));
  EXPECT_EQ(1u, Head(id));
  Save(alice_, id, "b");
  EXPECT_EQ(3u, Version(id));
  EXPECT_EQ(2u, Head(id));
  Draft(alice_, id, "c");
  EXPECT_EQ(4u, Version(id));
  EXPECT_EQ(2u, Head(id));
  ASSERT_EQ(GDEFCORE_OK, Unpublish("", id));
  EXPECT_EQ(5u, Version(id));
  EXPECT_EQ(2u, Head(id));
  std::string one = Create();
  Save(alice_, one, "x");
  uint64_t before = Version(one);
  Clear(one);
  EXPECT_EQ(before + 1, Version(one));
  EXPECT_EQ(1u, Head(one));
}

TEST_F(Revisions, ClearUnpublishesDeletesAndDropsTheDraft) {
  std::string id = Create();
  Save(alice_, id, "x");
  Draft(bob_, id, "y");
  ASSERT_TRUE(Published(id));
  Clear(id);
  EXPECT_FALSE(Published(id));
  EXPECT_EQ(0u, Active(id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_DRAFT, id));
  EXPECT_EQ(-1, DraftBase(id));
  EXPECT_FALSE(Listed(id));
  Port p = PortEntity(id);
  EXPECT_EQ(1, p.deleted);
  EXPECT_EQ(0, p.published);
  /* the identity and the history stay */
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_EQ(1u, Head(id));
  EXPECT_EQ(1u, Count(id));
  /* control: a revert to its revision brings it back, still unpublished.
   * The clear removed no content (it is a soft delete), so the content is
   * already that revision's and no revision is written. */
  ASSERT_EQ(GDEFCORE_OK, RevertTo("", id, 1));
  EXPECT_EQ(0, PortEntity(id).deleted);
  EXPECT_FALSE(Published(id));
  EXPECT_EQ("x", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ(1u, Head(id));
  EXPECT_TRUE(Listed(id));
}

TEST_F(Revisions, TheCreatorIsSetOnce) {
  std::string id = Create();
  EXPECT_EQ("<none>", Creator(id));
  Draft(alice_, id, "a");
  EXPECT_EQ(alice_, Creator(id));
  Save(bob_, id, "b");
  Draft(carol_, id, "c");
  Publish(carol_, id);
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_EQ(carol_, Actor(id));
  /* not even after a clear and a new save by someone else */
  std::string one = Create();
  Save(alice_, one, "x");
  Clear(one);
  Save(bob_, one, "y");
  EXPECT_EQ(alice_, Creator(one));
  EXPECT_EQ(bob_, Actor(one));
  /* control: an entity made with no actor never gets a creator, and a later
   * actor does not become its creator. */
  std::string anon = Create();
  Save("", anon, "x");
  EXPECT_EQ("<none>", Creator(anon));
  Save(bob_, anon, "y");
  EXPECT_EQ("<none>", Creator(anon));
  EXPECT_EQ(bob_, Actor(anon));
}

TEST_F(Revisions, TheRecordSurvivesASnapshotRoundTrip) {
  std::string id = Create();
  Draft(alice_, id, "first");
  Save(bob_, id, "second");
  Draft(carol_, id, "third");
  std::string other = Create();
  Draft(alice_, other, "only");
  std::string reserved = Create();
  uint8_t * bytes = NULL;
  size_t len = 0;
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_snapshot_export(store_, kTenant, 1, NULL, &bytes, &len));
  GDEFSTOR_Store * copy = NULL;
  ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_store_create(NULL, NULL, &copy));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_snapshot_import(copy, kTenant, 1, bytes, len, NULL));
  GDEFCORE_Catalog * cat2 = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_catalog_open(copy, (const uint8_t *)kTenant, 1, NULL, NULL, &cat2));
  for (const std::string & e : {id, other, reserved}) {
    int s1 = 0, s2 = 0, h1 = 0, h2 = 0;
    uint64_t a1 = 0, a2 = 0, v1 = 0, v2 = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_state(catalog_, e.c_str(), e.size(), &s1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_state(cat2, e.c_str(), e.size(), &s2));
    EXPECT_EQ(s1, s2);
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_active_revision(catalog_, e.c_str(), e.size(), &h1, &a1));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_active_revision(cat2, e.c_str(), e.size(), &h2, &a2));
    EXPECT_EQ(h1, h2);
    EXPECT_EQ(a1, a2);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_version(catalog_, e.c_str(), e.size(), &v1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_version(cat2, e.c_str(), e.size(), &v2));
    EXPECT_EQ(v1, v2);
    char * c1 = NULL;
    char * c2 = NULL;
    size_t n1 = 0, n2 = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_creator(catalog_, e.c_str(), e.size(), &c1, &n1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_creator(cat2, e.c_str(), e.size(), &c2, &n2));
    EXPECT_EQ(c1 == NULL, c2 == NULL);
    if (c1 != NULL && c2 != NULL) {
      EXPECT_EQ(std::string(c1, n1), std::string(c2, n2));
    }
    gdefcore_text_free(catalog_, c1);
    gdefcore_text_free(cat2, c2);
    /* the draft comes back too */
    for (int view : {GDEFCORE_VIEW_DRAFT, GDEFCORE_VIEW_ACTIVE}) {
      char ** t1 = NULL;
      char ** t2 = NULL;
      size_t * l1 = NULL;
      size_t * l2 = NULL;
      size_t k1 = 0, k2 = 0;
      GDEFCORE_Result r1 = gdefcore_entity_values(catalog_, NULL, view, e.c_str(),
          e.size(), "en", 2, "title", 5, &t1, &l1, &k1);
      GDEFCORE_Result r2 = gdefcore_entity_values(cat2, NULL, view, e.c_str(),
          e.size(), "en", 2, "title", 5, &t2, &l2, &k2);
      EXPECT_EQ(r1, r2) << view;
      ASSERT_EQ(k1, k2) << view;
      for (size_t i = 0; i < k1; i++) {
        EXPECT_EQ(std::string(t1[i], l1[i]), std::string(t2[i], l2[i]));
      }
      gdefcore_values_free(catalog_, t1, l1, k1);
      gdefcore_values_free(cat2, t2, l2, k2);
    }
  }
  /* a reserved id is still reserved: a save makes it, with its type */
  {
    GDEFCORE_Changeset * cs = NULL;
    const char * texts[1] = {"made"};
    size_t lens[1] = {4};
    GDEFCORE_Value value;
    memset(&value, 0, sizeof value);
    value.size = sizeof value;
    value.field = "title";
    value.field_len = 5;
    value.texts = texts;
    value.text_lens = lens;
    value.count = 1;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(cat2, NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_save(cs, reserved.c_str(), reserved.size(), "en", 2,
            &value, 1));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }
  gdefcore_catalog_destroy(cat2);
  gdefstor_store_destroy(copy);
  gdefstor_bytes_free(NULL, bytes);
}

TEST_F(Revisions, UnpublishClearsTheFlagAndNothingElse) {
  std::string id = Create();
  Save(alice_, id, "one");
  Save(bob_, id, "two");
  ASSERT_TRUE(Published(id));
  uint64_t version = Version(id);
  ASSERT_EQ(GDEFCORE_OK, Unpublish(carol_, id));
  EXPECT_FALSE(Published(id));
  /* the content, the history and the people stay */
  EXPECT_EQ(2u, Active(id));
  EXPECT_EQ(2u, Head(id));
  EXPECT_EQ(2u, Count(id));
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_EQ(bob_, Actor(id));
  EXPECT_EQ("two", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("two", Title(GDEFCORE_VIEW_DRAFT, id));
  EXPECT_EQ(version + 1, Version(id));
  /* but readers no longer see it */
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
  /* control: publishing brings the same content back */
  Publish("", id);
  EXPECT_EQ("two", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ(version + 2, Version(id));
}

TEST_F(Revisions, RevertToCopiesATargetAndKeepsTheFlag) {
  std::string id = Create();
  Save(alice_, id, "one");
  Save(bob_, id, "two");
  uint64_t version = Version(id);
  ASSERT_EQ(GDEFCORE_OK, RevertTo(carol_, id, 1));
  EXPECT_EQ(3u, Head(id));
  EXPECT_EQ(3u, Count(id));            /* a revert writes a revision */
  EXPECT_EQ(3u, Active(id));
  EXPECT_EQ("one", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("one", Title(GDEFCORE_VIEW_DRAFT, id));
  /* the copy is a new revision, so its author is the one who reverted */
  EXPECT_EQ(carol_, Actor(id));
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(version + 1, Version(id));
  /* control: the flag is the revert's to leave alone, down as well as up */
  std::string down = Create();
  Save(alice_, down, "d1");
  Save(alice_, down, "d2");
  ASSERT_EQ(GDEFCORE_OK, Unpublish("", down));
  ASSERT_EQ(GDEFCORE_OK, RevertTo(bob_, down, 1));
  EXPECT_FALSE(Published(down));
  EXPECT_EQ(3u, Active(down));
  EXPECT_EQ("d1", Title(GDEFCORE_VIEW_ACTIVE, down));
  /* a target that was not recorded, and an entity that has none */
  GDEFCORE_Changeset * cs = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_revert_to(catalog_, id.c_str(), id.size(), 0, NULL, 0, &cs));
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_revert_to(catalog_, id.c_str(), id.size(), 9, NULL, 0, &cs));
  std::string none = Create();
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_revert_to(catalog_, none.c_str(), none.size(), 1, NULL, 0,
          &cs));
}

TEST_F(Revisions, TheLegacyRevertStepsBackFromTheNewest) {
  std::string id = Create();
  Save(alice_, id, "one");
  Save(bob_, id, "two");
  Save(carol_, id, "three");
  Clear(id);                           /* revision 4: a copy of 2 */
  EXPECT_EQ(4u, Head(id));
  EXPECT_EQ("two", Title(GDEFCORE_VIEW_ACTIVE, id));
  Clear(id);                           /* revision 5: a copy of 3, one less than 4 */
  EXPECT_EQ(5u, Head(id));
  EXPECT_EQ("three", Title(GDEFCORE_VIEW_ACTIVE, id));
  /* and it needs a revision to step back from */
  std::string none = Create();
  GDEFCORE_Changeset * cs = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_changeset_revert(catalog_, none.c_str(), none.size(), NULL, 0, &cs));
}

TEST_F(Revisions, TheNewOperationsRoundTripThroughAPatch) {
  std::string id = Create();
  Save(alice_, id, "one");
  Save(bob_, id, "two");
  /* serialize -> parse -> apply gives what applying the original gives */
  for (int which = 0; which < 3; which++) {
    GDEFCORE_Changeset * cs = Prepare(carol_);
    const char * word = "unpublish";
    if (which == 0) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_unpublish(cs, id.c_str(), id.size()));
    } else if (which == 1) {
      word = "draft";
      const char * texts[1] = {"drafted"};
      size_t lens[1] = {7};
      GDEFCORE_Value value;
      memset(&value, 0, sizeof value);
      value.size = sizeof value;
      value.field = "title";
      value.field_len = 5;
      value.texts = texts;
      value.text_lens = lens;
      value.count = 1;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_entity_save_draft(cs, id.c_str(), id.size(), "en", 2, &value, 1));
    } else {
      word = "revert";
      gdefcore_changeset_destroy(cs);
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_changeset_revert_to(catalog_, id.c_str(), id.size(), 1,
              carol_.c_str(), carol_.size(), &cs));
    }
    GDEFCORE_Patch * files = NULL;
    size_t count = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(cs, &files, &count));
    bool saw_op = false;
    bool saw_ver = false;
    for (size_t i = 0; i < count; i++) {
      std::string path(files[i].path, files[i].path_len);
      std::string bytes((const char *)files[i].bytes, files[i].len);
      if (path == "entity/" + id + "/op") {
        saw_op = bytes == word;
      }
      if (path == "entity/" + id + "/ver") {
        saw_ver = true;
      }
    }
    EXPECT_TRUE(saw_op) << word;
    EXPECT_TRUE(saw_ver) << word;
    GDEFCORE_Changeset * parsed = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed))
        << word;
    gdefcore_patch_free(catalog_, files, count);
    gdefcore_changeset_destroy(cs);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, NULL, 0)) << word;
    gdefcore_changeset_destroy(parsed);
    if (which == 0) {
      EXPECT_FALSE(Published(id));
      Publish("", id);
    } else if (which == 1) {
      EXPECT_EQ(2u, Head(id));
      EXPECT_EQ("drafted", Title(GDEFCORE_VIEW_DRAFT, id));
      EXPECT_EQ("two", Title(GDEFCORE_VIEW_ACTIVE, id));
    } else {
      EXPECT_EQ(3u, Head(id));
      EXPECT_EQ(3u, Count(id));
      EXPECT_EQ("one", Title(GDEFCORE_VIEW_ACTIVE, id));
    }
  }
}

TEST_F(Revisions, AStalePatchOfTheNewOperationsIsAConflict) {
  std::string id = Create();
  Save(alice_, id, "one");
  Save(bob_, id, "two");
  GDEFCORE_Changeset * cs = Prepare("");
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_unpublish(cs, id.c_str(), id.size()));
  GDEFCORE_Patch * files = NULL;
  size_t count = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_serialize(cs, &files, &count));
  gdefcore_changeset_destroy(cs);
  /* the same patch, as it would be if the entity's version were one behind:
   * the epoch is the patch's own (so the epoch check cannot be what refuses) */
  int edited = 0;
  for (size_t i = 0; i < count; i++) {
    std::string path(files[i].path, files[i].path_len);
    if (path == "entity/" + id + "/ver") {
      ASSERT_EQ(1u, files[i].len);
      files[i].bytes[0] = '1';
      edited++;
    }
  }
  ASSERT_EQ(1, edited);
  GDEFCORE_Changeset * parsed = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_parse(catalog_, files, count, NULL, &parsed));
  EXPECT_NE(GDEFCORE_OK, gdefcore_changeset_apply(parsed, NULL, 0));
  EXPECT_TRUE(Published(id));           /* nothing was written */
  /* control: rebased onto the entity as it is, the same changeset applies */
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_rebase(parsed));
  EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(parsed, NULL, 0));
  EXPECT_FALSE(Published(id));
  gdefcore_changeset_destroy(parsed);
  gdefcore_patch_free(catalog_, files, count);
}

TEST_F(Revisions, TheTouchedListNamesTheNewOperations) {
  std::string id = Create();
  Save(alice_, id, "one");
  Save(alice_, id, "two");
  const int want[3] = {GDEFCORE_TOUCH_UNPUBLISH, GDEFCORE_TOUCH_DRAFT,
      GDEFCORE_TOUCH_SAVE};
  for (int which = 0; which < 3; which++) {
    GDEFCORE_Changeset * cs = Prepare("");
    if (which == 0) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_unpublish(cs, id.c_str(), id.size()));
    } else if (which == 1) {
      const char * texts[1] = {"d"};
      size_t lens[1] = {1};
      GDEFCORE_Value value;
      memset(&value, 0, sizeof value);
      value.size = sizeof value;
      value.field = "title";
      value.field_len = 5;
      value.texts = texts;
      value.text_lens = lens;
      value.count = 1;
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_entity_save_draft(cs, id.c_str(), id.size(), "en", 2, &value, 1));
    } else {
      gdefcore_changeset_destroy(cs);
      ASSERT_EQ(GDEFCORE_OK,
          gdefcore_changeset_revert_to(catalog_, id.c_str(), id.size(), 1, NULL, 0, &cs));
    }
    EXPECT_EQ(1u, gdefcore_changeset_touched_count(cs));
    int op = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_touched_at(cs, 0, NULL, NULL, NULL, NULL, &op));
    EXPECT_EQ(want[which], op);
    gdefcore_changeset_destroy(cs);
  }
}

/* ---- scheduled publish (story S6c) ------------------------------------- */

class Schedule : public Revisions {
 protected:
  int State(const std::string & id, int64_t * at = NULL) {
    int state = -1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_schedule_state(catalog_, id.c_str(),
        id.size(), &state, at));
    return state;
  }

  size_t Run(int64_t now, size_t * ended = NULL) {
    size_t applied = 99;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_schedule_run(catalog_, now, 100, &applied, ended));
    return applied;
  }

  int Apply(const std::string & id, int64_t at, int64_t now) {
    int outcome = -1;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_schedule_apply(catalog_, id.c_str(),
        id.size(), at, now, &outcome));
    return outcome;
  }

  size_t Due(int64_t now) {
    GDEFCORE_ScheduleJob jobs[8];
    size_t n = 99;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_schedule_due(catalog_, now, jobs, 8, &n));
    return n;
  }

  void At(const std::string & actor, const std::string & id, int64_t at) {
    ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_schedule_publish(catalog_,
        actor.empty() ? NULL : actor.c_str(), actor.size(), id.c_str(),
        id.size(), at));
  }
};

/* A draft scheduled for T is applied by the runner at or after T, once: not
 * before T, not again, and a draft written after it ran is not published by
 * the job that already ran. The revision is the draft's author's. */
TEST_F(Schedule, ADraftScheduledForTIsAppliedAtOrAfterTOnce) {
  const int64_t kT = 1000000;
  std::string id = Create();
  Save(alice_, id, "first");
  Draft(bob_, id, "second");
  At(carol_, id, kT);
  int64_t at = 0;
  EXPECT_EQ(GDEFCORE_SCHEDULE_PENDING, State(id, &at));
  EXPECT_EQ(kT, at);
  /* Before T: the runner takes nothing, and an apply is refused as early. */
  EXPECT_EQ(0u, Due(kT - 1));
  EXPECT_EQ(0u, Run(kT - 1));
  EXPECT_EQ(GDEFCORE_SCHEDULE_EARLY, Apply(id, kT, kT - 1));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ(1u, Count(id));
  EXPECT_EQ("second", Title(GDEFCORE_VIEW_DRAFT, id));
  /* At T. */
  EXPECT_EQ(1u, Due(kT));
  EXPECT_EQ(1u, Run(kT));
  EXPECT_EQ("second", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ(2u, Count(id));
  EXPECT_EQ(bob_, Actor(id));
  EXPECT_EQ(GDEFCORE_SCHEDULE_DONE, State(id));
  /* Once: the job is gone, and the next draft waits for its own publish. */
  EXPECT_EQ(0u, Due(kT + 5000));
  EXPECT_EQ(0u, Run(kT + 5000));
  EXPECT_EQ(GDEFCORE_SCHEDULE_GONE, Apply(id, kT, kT + 5000));
  Draft(bob_, id, "third");
  EXPECT_EQ(0u, Run(kT + 9000));
  EXPECT_EQ(GDEFCORE_SCHEDULE_GONE, Apply(id, kT, kT + 9000));
  EXPECT_EQ(2u, Count(id));
  EXPECT_EQ("second", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("third", Title(GDEFCORE_VIEW_DRAFT, id));
  /* The control: a job at a later time publishes "third". */
  At(carol_, id, kT + 10000);
  EXPECT_EQ(1u, Run(kT + 10000));
  EXPECT_EQ("third", Title(GDEFCORE_VIEW_PUBLISHED, id));
}

/* A job listed by one runner and applied, or cancelled, before another runner
 * gets to it: the second finds it gone inside its own write and writes
 * nothing. */
TEST_F(Schedule, AJobGoneSinceItWasListedIsNotApplied) {
  const int64_t kT = 5000;
  std::string id = Create();
  Save(alice_, id, "first");
  Draft(bob_, id, "second");
  At(carol_, id, kT);
  GDEFCORE_ScheduleJob jobs[4];
  size_t n = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_schedule_due(catalog_, kT, jobs, 4, &n));
  ASSERT_EQ(1u, n);
  EXPECT_EQ(id, std::string(jobs[0].id));
  EXPECT_EQ(kT, jobs[0].at_ms);
  /* Cancelled after it was listed. */
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_unschedule(catalog_, id.c_str(), id.size()));
  EXPECT_EQ(GDEFCORE_SCHEDULE_NONE, State(id));
  EXPECT_EQ(GDEFCORE_SCHEDULE_GONE, Apply(id, jobs[0].at_ms, kT));
  EXPECT_EQ(1u, Count(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_PUBLISHED, id));
  /* Moved to another time after it was listed: the old listing is gone, the
   * new time is the one that applies. */
  At(carol_, id, kT);
  At(carol_, id, kT + 100);
  EXPECT_EQ(GDEFCORE_SCHEDULE_GONE, Apply(id, kT, kT + 200));
  EXPECT_EQ(1u, Count(id));
  EXPECT_EQ(GDEFCORE_SCHEDULE_DONE, Apply(id, kT + 100, kT + 200));
  EXPECT_EQ(2u, Count(id));
}

/* A moved head is a conflict when the job runs: the draft was made from a
 * revision a revert has since superseded. Nothing is written, the draft is
 * kept, the job ends and says so. */
TEST_F(Schedule, AScheduledPublishOnAMovedHeadIsAConflict) {
  const int64_t kT = 7000;
  std::string id = Create();
  Save(alice_, id, "first");
  Save(alice_, id, "second");
  Draft(bob_, id, "third");
  ASSERT_EQ(GDEFCORE_OK, RevertTo(alice_, id, 1));
  ASSERT_EQ(3u, Count(id));
  At(carol_, id, kT);
  size_t ended = 0;
  EXPECT_EQ(0u, Run(kT, &ended));
  EXPECT_EQ(1u, ended);
  EXPECT_EQ(GDEFCORE_SCHEDULE_CONFLICT, State(id));
  EXPECT_EQ(3u, Count(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("third", Title(GDEFCORE_VIEW_DRAFT, id));
  EXPECT_EQ(0u, Due(kT + 1000));
}

/* The draft is validated against its type as the type is when the job runs:
 * a field made required since is refused, the draft kept, the job ended. */
TEST_F(Schedule, AScheduledDraftIsValidatedWhenItIsApplied) {
  const int64_t kT = 9000;
  std::string id = Create();
  Save(alice_, id, "first");
  Draft(bob_, id, "second");
  At(carol_, id, kT);
  GDEFCORE_Field fields[3];
  memset(fields, 0, sizeof fields);
  fields[0].size = sizeof fields[0];
  fields[0].name = "title";
  fields[0].name_len = 5;
  fields[0].required = 1;
  fields[1].size = sizeof fields[1];
  fields[1].name = "tags";
  fields[1].name_len = 4;
  fields[1].many = 1;
  fields[2].size = sizeof fields[2];
  fields[2].name = "body";
  fields[2].name_len = 4;
  fields[2].required = 1;
  {
    GDEFCORE_Changeset * cs = Prepare(alice_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_define(cs, "site.note", 9,
        GDEFCORE_TYPE_CONTENT, fields, 3));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "site.note", 9));
    gdefcore_changeset_destroy(cs);
  }
  size_t ended = 0;
  EXPECT_EQ(0u, Run(kT, &ended));
  EXPECT_EQ(1u, ended);
  EXPECT_EQ(GDEFCORE_SCHEDULE_REFUSED, State(id));
  EXPECT_EQ(1u, Count(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("second", Title(GDEFCORE_VIEW_DRAFT, id));
}

/* Clearing an entity cancels its schedule: a cleared entity is not published
 * later. */
TEST_F(Schedule, ClearingAnEntityCancelsItsSchedule) {
  const int64_t kT = 11000;
  std::string id = Create();
  Save(alice_, id, "first");
  At(carol_, id, kT);
  Clear(id);
  EXPECT_EQ(GDEFCORE_SCHEDULE_NONE, State(id));
  EXPECT_EQ(0u, Run(kT));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
