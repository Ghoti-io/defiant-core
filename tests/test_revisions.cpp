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
 * The entity record (story A5b, SPEC decisions 9-11): the published flag, the
 * active revision, the version and the creator, beside the append-only
 * revisions. One test per row of the transition table, each with a control
 * (the same call on the other side of the rule answers differently). Run by
 * tools/check-revisions.sh, which plants a defect for each named rule.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage/projection.h>
#include <ghoti.io/defiant-storage/revision.h>
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
    GDEFCORE_Field field;
    memset(&field, 0, sizeof field);
    field.size = sizeof field;
    field.name = "title";
    field.name_len = 5;
    field.required = 1;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_type_define(catalog_, "site.note", 9, GDEFCORE_TYPE_CONTENT,
            &field, 1));
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

  /* The columns of one raw projection row, "<none>" when it is absent. */
  std::map<std::string, std::string> Raw(const std::string & type,
      const std::string & row) {
    std::map<std::string, std::string> out;
    GDEFSTOR_Projection * proj = NULL;
    if (gdefstor_projection_get(store_, kTenant, 1, type.c_str(), type.size(),
            row.c_str(), row.size(), &proj) != GDEFSTOR_OK) {
      out["<absent>"] = "1";
      return out;
    }
    for (size_t i = 0; i < gdefstor_projection_column_count(proj); i++) {
      GDEFSTOR_Column column;
      EXPECT_EQ(GDEFSTOR_OK, gdefstor_projection_column(proj, i, &column));
      out[std::string(column.name, column.name_len)] =
          std::string((const char *)column.value, column.value_len);
    }
    gdefstor_projection_free(proj);
    return out;
  }

  std::string RowOf(const std::string & id) {
    auto index = Raw("i", id);
    return index["row"];
  }
};

}  // namespace

TEST_F(Revisions, CreateWritesTheRecord) {
  std::string id = Create();
  /* Control for the rows below: the record is there, and says nothing yet. */
  auto s = Raw("s", RowOf(id));
  EXPECT_EQ(0u, s.count("<absent>"));
  EXPECT_EQ("0", s["pub"]);
  EXPECT_EQ("0", s["ver"]);
  EXPECT_EQ(0u, s.count("act"));
  EXPECT_EQ(0u, s.count("creator"));
  int state = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_state(catalog_, id.c_str(), id.size(), &state));
  EXPECT_EQ(GDEFCORE_STATE_DRAFT, state);
  EXPECT_EQ(0u, Active(id));
  EXPECT_EQ(0u, Version(id));
  EXPECT_EQ("<none>", Creator(id));
  EXPECT_EQ("<none>", Actor(id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_DRAFT, id));
}

TEST_F(Revisions, StoredShape) {
  std::string id = Create();
  Draft(alice_, id, "first");
  Save(bob_, id, "second");
  std::string row = RowOf(id);
  auto s = Raw("s", row);
  EXPECT_EQ("1", s["pub"]);
  EXPECT_EQ("2", s["act"]);
  EXPECT_EQ("2", s["ver"]);
  EXPECT_EQ(alice_, s["creator"]);
  /* The active revision's content is `a:`; the old `p:` key is not written
   * (a stale reader fails loudly instead of reading a flag-less copy). */
  auto a = Raw("a:site.note", row);
  EXPECT_EQ(0u, a.count("<absent>"));
  EXPECT_EQ("2", a["seq"]);
  EXPECT_EQ(bob_, a["actor"]);
  EXPECT_EQ(1u, Raw("p:site.note", row).count("<absent>"));
  auto d = Raw("d:site.note", row);
  EXPECT_EQ("2", d["seq"]);
}

TEST_F(Revisions, FirstDraftIsActiveButNotPublished) {
  std::string id = Create();
  Draft(alice_, id, "first");
  EXPECT_FALSE(Published(id));
  EXPECT_EQ(1u, Active(id));
  EXPECT_EQ(1u, Version(id));
  EXPECT_EQ(alice_, Actor(id));
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_DRAFT, id));
  /* the reader's view needs the flag */
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
  /* control: the same entity once published is seen by a reader */
  Publish("", id);
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_PUBLISHED, id));
}

TEST_F(Revisions, ALaterDraftDoesNotMoveThePointer) {
  std::string id = Create();
  Draft(alice_, id, "first");
  Draft(bob_, id, "second");
  EXPECT_EQ(2u, Head(id));
  EXPECT_EQ(1u, Active(id));
  EXPECT_EQ("first", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("second", Title(GDEFCORE_VIEW_DRAFT, id));
  /* The active revision's creator is the revision's, not the head's. */
  EXPECT_EQ(alice_, Actor(id));
  EXPECT_EQ(alice_, Creator(id));
  /* control: a save is what moves it */
  Save(carol_, id, "third");
  EXPECT_EQ(3u, Active(id));
  EXPECT_EQ(carol_, Actor(id));
}

TEST_F(Revisions, SaveIsSaveAndPublish) {
  std::string id = Create();
  Save(alice_, id, "hello");
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(1u, Active(id));
  EXPECT_EQ("hello", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("hello", Title(GDEFCORE_VIEW_ACTIVE, id));
  /* a save on top of an unpublished first draft publishes it */
  std::string other = Create();
  Draft(alice_, other, "d");
  EXPECT_FALSE(Published(other));
  Save(bob_, other, "s");
  EXPECT_TRUE(Published(other));
  EXPECT_EQ(2u, Active(other));
}

TEST_F(Revisions, PublishSetsTheFlagAndMakesTheHeadActive) {
  std::string id = Create();
  Draft(alice_, id, "first");
  Draft(alice_, id, "second");
  EXPECT_FALSE(Published(id));
  EXPECT_EQ(1u, Active(id));
  uint64_t before = Version(id);
  Publish(bob_, id);
  EXPECT_TRUE(Published(id));
  EXPECT_EQ(2u, Active(id));
  EXPECT_EQ(2u, Head(id));
  EXPECT_EQ("second", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ(before + 1, Version(id));
}

TEST_F(Revisions, PublishKeepsTheRevisionsOwnCreator) {
  /* Defect 1.5.3: publishing used to store the publisher as the actor, and a
   * form publish (no actor) dropped it, so `own` stopped matching. */
  std::string id = Create();
  Draft(alice_, id, "mine");
  Publish(bob_, id);
  EXPECT_EQ(alice_, Actor(id));
  EXPECT_EQ(alice_, Creator(id));
  std::string other = Create();
  Draft(alice_, other, "mine too");
  Publish("", other);
  EXPECT_EQ(alice_, Actor(other));
  EXPECT_EQ(alice_, Creator(other));
}

TEST_F(Revisions, TheVersionMovesWhereTheRevisionDoesNot) {
  /* Defect 1.5.2: publish and clear do not move the revision number, which
   * can()'s memo and the render read set were keyed on. */
  std::string id = Create();
  EXPECT_EQ(0u, Version(id));
  Draft(alice_, id, "a");
  EXPECT_EQ(1u, Version(id));
  Publish("", id);
  EXPECT_EQ(2u, Version(id));
  EXPECT_EQ(1u, Head(id));
  Save(alice_, id, "b");
  EXPECT_EQ(3u, Version(id));
  EXPECT_EQ(2u, Head(id));
  Clear(id);
  /* a revert of a revision numbered above 1 is a copy, not a clear */
  EXPECT_EQ(4u, Version(id));
  EXPECT_EQ(3u, Head(id));
  std::string one = Create();
  Save(alice_, one, "x");
  uint64_t before = Version(one);
  Clear(one);
  EXPECT_EQ(before + 1, Version(one));
  EXPECT_EQ(1u, Head(one));
}

TEST_F(Revisions, ClearUnpublishesAndEmptiesTheActiveRevision) {
  std::string id = Create();
  Save(alice_, id, "x");
  ASSERT_TRUE(Published(id));
  Clear(id);
  EXPECT_FALSE(Published(id));
  EXPECT_EQ(0u, Active(id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_PUBLISHED, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_ACTIVE, id));
  EXPECT_EQ("<none>", Title(GDEFCORE_VIEW_DRAFT, id));
  EXPECT_EQ("<none>", Actor(id));
  /* the identity and the history stay */
  EXPECT_EQ(alice_, Creator(id));
  EXPECT_EQ(1u, Head(id));
  size_t revisions = 0;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_entity_revision_count(catalog_, id.c_str(), id.size(), &revisions));
  EXPECT_EQ(1u, revisions);
  auto s = Raw("s", RowOf(id));
  EXPECT_EQ("0", s["pub"]);
  EXPECT_EQ(0u, s.count("act"));
  EXPECT_EQ(1u, Raw("a:site.note", RowOf(id)).count("<absent>"));
  EXPECT_EQ(1u, Raw("d:site.note", RowOf(id)).count("<absent>"));
  /* control: the same entity before the clear was read */
  std::string other = Create();
  Save(alice_, other, "y");
  EXPECT_EQ("y", Title(GDEFCORE_VIEW_PUBLISHED, other));
}

TEST_F(Revisions, TheCreatorIsSetOnceAtTheFirstRevision) {
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
  /* control: an entity whose first revision has no actor never gets one, and
   * a later actor does not become its creator. */
  std::string anon = Create();
  Save("", anon, "x");
  EXPECT_EQ("<none>", Creator(anon));
  Save(bob_, anon, "y");
  EXPECT_EQ("<none>", Creator(anon));
  EXPECT_EQ(bob_, Actor(anon));
}

TEST_F(Revisions, AnOldShapedStoreIsCorruptNotUnpublished) {
  /* A row in the index with no entity record: written before the record
   * existed. It is refused loudly; reading it as unpublished would hide it. */
  GDEFSTOR_Write * write = NULL;
  GDEFSTOR_Column columns[2];
  char generated[GDEFCORE_PUBLIC_ID_LEN + 1];
  ASSERT_EQ(GDEFCORE_OK, gdefcore_id_generate(generated));
  const char * old_id = generated;
  memset(columns, 0, sizeof columns);
  columns[0].name = "row";
  columns[0].name_len = 3;
  columns[0].value = (const uint8_t *)"9000";
  columns[0].value_len = 4;
  columns[1].name = "type";
  columns[1].name_len = 4;
  columns[1].value = (const uint8_t *)"site.note";
  columns[1].value_len = 9;
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_begin(store_, kTenant, 1, NULL, &write));
  ASSERT_EQ(GDEFSTOR_OK,
      gdefstor_projection_put(write, "i", 1, old_id, strlen(old_id), columns, 2));
  ASSERT_EQ(GDEFSTOR_OK, gdefstor_write_commit(write));
  std::string id(old_id);
  int state = 0;
  uint64_t version = 0;
  int has = 0;
  uint64_t seq = 0;
  char * text = NULL;
  size_t n = 0;
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_entity_state(catalog_, id.c_str(), id.size(), &state));
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_entity_version(catalog_, id.c_str(), id.size(), &version));
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_entity_active_revision(catalog_, id.c_str(), id.size(), &has,
          &seq));
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_entity_creator(catalog_, id.c_str(), id.size(), &text, &n));
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_entity_actor(catalog_, id.c_str(), id.size(), &text, &n));
  for (int view : {GDEFCORE_VIEW_PUBLISHED, GDEFCORE_VIEW_DRAFT,
           GDEFCORE_VIEW_ACTIVE}) {
    EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
        gdefcore_entity_values(catalog_, NULL, view, id.c_str(), id.size(), "en",
            2, "title", 5, &texts, &lens, &count))
        << view;
  }
  /* control: a created entity answers the same calls */
  std::string good = Create();
  EXPECT_EQ(GDEFCORE_OK,
      gdefcore_entity_state(catalog_, good.c_str(), good.size(), &state));
}

TEST_F(Revisions, TheRecordSurvivesASnapshotRoundTrip) {
  std::string id = Create();
  Draft(alice_, id, "first");
  Save(bob_, id, "second");
  Draft(carol_, id, "third");
  std::string other = Create();
  Draft(alice_, other, "only");
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
  for (const std::string & e : {id, other}) {
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
    EXPECT_EQ(std::string(c1, n1), std::string(c2, n2));
    gdefcore_text_free(catalog_, c1);
    gdefcore_text_free(cat2, c2);
  }
  gdefcore_catalog_destroy(cat2);
  gdefstor_store_destroy(copy);
  gdefstor_bytes_free(NULL, bytes);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
