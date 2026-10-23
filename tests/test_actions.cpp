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
 * Access-conditions story A5b, the action vocabulary and the revision views:
 * how the actions are rated (a `revisions` action is at least an edit; a grant
 * that lets its holder change the field its own condition tests is rated one
 * step higher, and the matrix says so), and the revision reader, which asks
 * `revisions.read` of the entity as stored and then the field-read grants,
 * and never shows a personal field as the ciphertext it is stored as. Run by
 * tools/check-revisions.sh, which plants a defect for each rule.
 */

#include "grants_fixture.h"

namespace {

using namespace gfx;

const char kGroupA[] = "(= field.group \"a\")";

int Risk(const char * action, const char * field, const char * cond,
    int anonymous = 0) {
  return gdefcore_access_grant_risk_on(action, strlen(action), field,
      field == NULL ? 0 : strlen(field), cond, strlen(cond), anonymous);
}

class Actions : public GrantsFixture {
 protected:
  /* The tenant's subjects, made the first time a personal value is written:
   * a sealed value is somebody's, and a save indexes it (story S6c). */
  GDEFSTOR_KeyStore * keys_ = NULL;
  GDEFCORE_Keyring * ring_ = NULL;
  GDEFCORE_Subjects * subjects_ = NULL;
  char subject_[GDEFCORE_PUBLIC_ID_LEN + 1] = {0};
  std::string sealed_;

  void TearDown() override {
    gdefcore_catalog_bind_subjects(catalog_, NULL);
    gdefcore_subject_destroy(subjects_);
    gdefstor_keystore_destroy(keys_);
    gdefcore_keyring_destroy(ring_);
    GrantsFixture::TearDown();
  }

  void Subjects() {
    uint8_t root[GDEFCORE_ACCOUNT_ROOT_LEN];
    GDEFSTOR_KeyCipher cipher;
    size_t tenant_len = 0;
    const uint8_t * tenant = gdefcore_catalog_tenant(catalog_, &tenant_len);
    if (subjects_ != NULL) {
      return;
    }
    memset(root, 0x42, sizeof root);
    gdefcore_subject_cipher(&cipher);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_keyring_create(root, sizeof root, NULL,
        &ring_));
    ASSERT_EQ(GDEFSMEMORY_OK, gdefsmemory_keystore_create(NULL, &cipher, &keys_));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_open(keys_, store_, tenant,
        tenant_len, root, sizeof root, ring_, NULL, &subjects_));
    gdefcore_catalog_bind_subjects(catalog_, subjects_);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_subject_create(subjects_, subject_));
  }

  GDEFCORE_Result Write(const std::string & actor, const std::string & id,
      const char * title, const char * group, bool draft, bool sealed = false) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Value values[4];
    const char * texts[4] = {title, group, kSealed, ""};
    size_t lens[4] = {strlen(title), strlen(group), strlen(kSealed), 0};
    const char * names[4] = {"title", "group", "ssn", "who"};
    uint8_t mac[GDEFCORE_SUBJECT_MAC_LEN];
    GDEFCORE_Result rc;
    if (sealed) {
      char * text = NULL;
      size_t text_len = 0;
      Subjects();
      EXPECT_EQ(GDEFCORE_OK, gdefcore_subject_seal(subjects_, subject_,
          strlen(subject_), "ssn", 3, "123-45-6789", 11, &text, &text_len, mac));
      sealed_.assign(text == NULL ? "" : text, text_len);
      gdefcore_subject_free(subjects_, text);
      texts[2] = sealed_.c_str();
      lens[2] = sealed_.size();
      /* Whose it is: the `who` reference its declaration names (story S7). */
      texts[3] = subject_;
      lens[3] = strlen(subject_);
    }
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_,
            actor.empty() ? NULL : actor.data(), actor.size(), &cs));
    memset(values, 0, sizeof values);
    for (int i = 0; i < 4; i++) {
      values[i].size = sizeof values[i];
      values[i].field = names[i];
      values[i].field_len = strlen(names[i]);
      values[i].texts = &texts[i];
      values[i].text_lens = &lens[i];
      values[i].count = 1;
    }
    if (sealed) {
      EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_accept_sealed(cs));
      EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_note_sealed(cs, subjects_,
          sealed_.data(), sealed_.size(), subject_, strlen(subject_), mac));
    }
    rc = (draft ? gdefcore_entity_save_draft : gdefcore_entity_save)(
        cs, id.data(), id.size(), "en", 2, values, sealed ? 4 : 2);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  GDEFCORE_Result Change(GDEFCORE_Result (*op)(GDEFCORE_Changeset *, const char *,
                             size_t),
      const std::string & id) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, NULL, 0, &cs));
    rc = op(cs, id.data(), id.size());
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  /* A copy of revision @p seq as the newest: the only way an older revision's
   * content becomes the entity's again (access SPEC decision 13). */
  GDEFCORE_Result RevertTo(const std::string & id, uint64_t seq) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_Result rc = gdefcore_changeset_revert_to(catalog_, id.data(),
        id.size(), seq, NULL, 0, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    gdefcore_changeset_destroy(cs);
    return rc;
  }

  std::string NewPost(const std::string & actor) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_entity_create(catalog_, kPost, strlen(kPost), id, NULL));
    (void)actor;
    return std::string(id);
  }

  /** What the revision view says: "rc status [text]..." */
  std::string View(GDEFCORE_Request * req, const std::string & id, uint64_t seq,
      const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    int status = 0;
    GDEFCORE_Result rc = gdefcore_access_revision_values(catalog_, req, id.data(),
        id.size(), seq, "en", 2, field, strlen(field), &status, &texts, &lens,
        &count);
    std::string out;
    if (rc != GDEFCORE_OK) {
      return "<denied>";
    }
    out = status == GDEFCORE_REVISION_SHOWN       ? "shown"
          : status == GDEFCORE_REVISION_ABSENT    ? "absent"
          : status == GDEFCORE_REVISION_PERSONAL  ? "personal"
          : status == GDEFCORE_REVISION_ERASED    ? "erased"
                                                  : "?";
    for (size_t i = 0; i < count; i++) {
      out += ":" + std::string(texts[i], lens[i]);
    }
    if (status != GDEFCORE_REVISION_SHOWN) {
      EXPECT_EQ(0u, count);
      EXPECT_EQ(nullptr, texts);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return out;
  }

  bool CanHold(const std::string & who, const char * action,
      const std::string & id) {
    int allowed = 0;
    return gdefcore_access_can(catalog_, Req(who), action, strlen(action), kPost,
               strlen(kPost), id.c_str(), &allowed) == GDEFCORE_OK &&
           allowed == 1;
  }

  std::string FreshIdText() {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    EXPECT_EQ(GDEFCORE_OK, gdefcore_id_generate(id));
    return std::string(id);
  }

  static constexpr const char * kSealed =
      "s1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
};

}  // namespace

TEST(ActionVocabulary, IsSpelledOnce) {
  EXPECT_STREQ("create", GDEFCORE_ACTION_CREATE);
  EXPECT_STREQ("read", GDEFCORE_ACTION_READ);
  EXPECT_STREQ("update", GDEFCORE_ACTION_UPDATE);
  EXPECT_STREQ("publish", GDEFCORE_ACTION_PUBLISH);
  EXPECT_STREQ("delete", GDEFCORE_ACTION_DELETE);
  EXPECT_STREQ("revisions.read", GDEFCORE_ACTION_REVISIONS_READ);
  EXPECT_STREQ("revisions.revert", GDEFCORE_ACTION_REVISIONS_REVERT);
}

TEST_F(Actions, EveryActionCanBeDeclaredAndGranted) {
  DefinePost();
  const char * actions[] = {GDEFCORE_ACTION_CREATE, GDEFCORE_ACTION_READ,
      GDEFCORE_ACTION_UPDATE, GDEFCORE_ACTION_PUBLISH, GDEFCORE_ACTION_DELETE,
      GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACTION_REVISIONS_REVERT};
  Role("all");
  for (const char * action : actions) {
    std::string label = std::string("Can ") + action;
    Declare(Perm(label.c_str(), action, GDEFCORE_ACCESS_ANY));
    Grant("all", label.c_str());
  }
  std::string who = Principal("all");
  std::string post = Save(Admin(), "t", "a");
  for (const char * action : actions) {
    if (std::string(action) == GDEFCORE_ACTION_CREATE) {
      continue; /* a create is not asked of an existing post */
    }
    EXPECT_TRUE(CanHold(who, action, post)) << action;
  }
  /* The control: a principal with no role holds none of them. */
  std::string nobody = Principal();
  for (const char * action : actions) {
    EXPECT_FALSE(CanHold(nobody, action, post)) << action;
  }
}

TEST(ActionRating, RevisionsActionsAreAtLeastAnEdit) {
  /* A condition that reads the entity and not the principal rates a read low
   * and an edit medium. `revisions.read` shows drafts that nobody published,
   * so it is not rated as the read it looks like (D15). */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW,
      gdefcore_access_grant_risk("read", 4, 0, "(= field.group \"a\")", 19, 0));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM,
      gdefcore_access_grant_risk("revisions.read", 14, 0,
          "(= field.group \"a\")", 19, 0));
  /* The strong ones stay strong: a revert, an activate. Without a narrowing
   * condition they are high; narrowed they are medium (never low). */
  const char * strong[] = {"revisions.revert", "revisions.activate"};
  for (const char * action : strong) {
    EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH,
        gdefcore_access_grant_risk(action, strlen(action), 0,
            "(= type \"site.post\")", 20, 0))
        << action;
    EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM,
        gdefcore_access_grant_risk(action, strlen(action), 0,
            "(= field.group \"a\")", 19, 0))
        << action;
  }
  /* `activate` on its own is a strong word, not an unknown name. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM,
      gdefcore_access_grant_risk("activate", 8, 0, "(= field.group \"a\")", 19, 0));
}

TEST(ActionRating, AGrantThatCanChangeItsOwnFieldIsRatedOneStepHigher) {
  const char * cond = kGroupA;
  /* An entity-wide update grant can set `group`, so it can widen itself. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM,
      gdefcore_access_grant_risk("update", 6, 0, cond, strlen(cond), 0));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, Risk("update", NULL, cond));
  /* The control: the same condition on a grant that changes only `title`
   * cannot be widened by its holder. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, Risk("update", "title", cond));
  /* A grant of the field the condition names can. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, Risk("update", "group", cond));
  /* Reading does not change it; neither does asking to see history. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW, Risk("read", NULL, cond));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, Risk("revisions.read", NULL, cond));
  /* A create is decided on the container the path names, not on what the
   * holder writes. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, Risk("create", NULL, cond));
  /* A revert and an activate put other content in place of the entity's. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, Risk("revisions.revert", NULL, cond));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, Risk("revisions.activate", NULL, cond));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, Risk("revisions.activate", "title", cond));
  /* A step up from low is medium, and high stays high. */
  const char * author = "(= field.author principal)";
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW,
      gdefcore_access_grant_risk("update", 6, 0, author, strlen(author), 0));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, Risk("update", NULL, author));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, Risk("update", NULL, cond, 1));
  /* `own` tests the creator, which no one can change: it stays low. */
  const char * own = "(and (= type \"site.post\") (= creator principal))";
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW, Risk("update", NULL, own));
  /* A condition that cannot be read is already as high as it goes. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, Risk("update", NULL, "(("));
  /* The predicate itself. */
  EXPECT_EQ(1, gdefcore_access_grant_changes_own_field("update", 6, NULL, 0, cond,
                   strlen(cond)));
  EXPECT_EQ(0, gdefcore_access_grant_changes_own_field("update", 6, "title", 5,
                   cond, strlen(cond)));
}

TEST_F(Actions, TheMatrixSaysItInWords) {
  DefinePost();
  Declare(Perm("Edit posts", "update", GDEFCORE_ACCESS_ANY));
  Declare(Perm("Edit titles", "update", GDEFCORE_ACCESS_ANY, kPost, "title"));
  Declare(Perm("Edit own posts", "update", GDEFCORE_ACCESS_OWN));
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("group-a");
  Role("titles");
  Role("authors");
  Role("readers");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "Edit posts", kGroupA));
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("titles", "Edit titles", kGroupA));
  Grant("authors", "Edit own posts");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("readers", "Read posts", kGroupA));
  std::vector<Row> rows = Matrix();
  const Row * all = Find(rows, "role group-a", "Edit posts");
  const Row * title = Find(rows, "role titles", "Edit titles");
  const Row * own = Find(rows, "role authors", "Edit own posts");
  const Row * read = Find(rows, "role readers", "Read posts");
  ASSERT_NE(nullptr, all);
  ASSERT_NE(nullptr, title);
  ASSERT_NE(nullptr, own);
  ASSERT_NE(nullptr, read);
  const std::string note = "the holder can change the field that decides who may edit";
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_HIGH, all->risk) << Dump(rows);
  EXPECT_NE(std::string::npos, all->explain.find(note)) << all->explain;
  /* Controls: a grant of another field, an `own`, a read: not raised, not said. */
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_MEDIUM, title->risk);
  EXPECT_EQ(std::string::npos, title->explain.find(note));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW, own->risk);
  EXPECT_EQ(std::string::npos, own->explain.find(note));
  EXPECT_EQ(GDEFCORE_ACCESS_RISK_LOW, read->risk);
  EXPECT_EQ(std::string::npos, read->explain.find(note));
}

/* ---- the revision reader -------------------------------------------------- */

TEST_F(Actions, RevisionViewNeedsThePermissionAndNotTheFlag) {
  DefinePost();
  Declare(Perm("View history", GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACCESS_ANY));
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("historians");
  Role("readers");
  Grant("historians", "View history");
  Grant("readers", "Read posts");
  std::string historian = Principal("historians");
  std::string reader = Principal("readers");
  std::string nobody = Principal();
  /* A post readers do not see: two revisions, then unpublished, and a draft
   * over it. */
  std::string post = NewPost(Admin());
  ASSERT_EQ(GDEFCORE_OK, Write(Admin(), post, "first", "a", false));
  ASSERT_EQ(GDEFCORE_OK, Write(Admin(), post, "second", "a", false));
  ASSERT_EQ(GDEFCORE_OK, Change(gdefcore_entity_unpublish, post));
  ASSERT_EQ(GDEFCORE_OK, Write(Admin(), post, "draft", "a", true));
  EXPECT_EQ("shown:first", View(Req(historian), post, 1, "title"));
  EXPECT_EQ("shown:second", View(Req(historian), post, 2, "title"));
  /* A draft is not a revision, so there is no third to view. */
  EXPECT_EQ("<denied>", View(Req(historian), post, 3, "title"));
  /* Controls: readers do not see an unpublished entity, and `read` is not
   * the right to see history. */
  EXPECT_EQ("<denied>", Read(Req(reader), post));
  EXPECT_EQ("<denied>", View(Req(reader), post, 1, "title"));
  EXPECT_EQ("<denied>", View(Req(nobody), post, 1, "title"));
  EXPECT_EQ("<denied>", View(Req(), post, 1, "title"));
  /* And the permission is not read: the historian cannot read the post. */
  EXPECT_EQ("<denied>", Read(Req(historian), post));
}

TEST_F(Actions, RevisionViewRefusalsAreOneAnswer) {
  DefinePost();
  Declare(Perm("View history", GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACCESS_ANY));
  Role("historians");
  Grant("historians", "View history");
  std::string historian = Principal("historians");
  std::string nobody = Principal();
  std::string post = Save(Admin(), "t", "a");
  std::string missing = FreshIdText();
  EXPECT_EQ("shown:t", View(Req(historian), post, 1, "title"));   /* control */
  const std::string denied = "<denied>";
  EXPECT_EQ(denied, View(Req(historian), post, 0, "title"));
  EXPECT_EQ(denied, View(Req(historian), post, 2, "title"));
  /* A field the type does not have is absent, as a field the historian may
   * not read is: the answer must not tell the two apart (story A7). */
  EXPECT_EQ("absent", View(Req(historian), post, 1, "nope"));
  EXPECT_EQ(denied, View(Req(historian), missing, 1, "title"));
  EXPECT_EQ(denied, View(Req(historian), "not-an-id", 1, "title"));
  /* A principal with no right to see history is told what the missing one is. */
  EXPECT_EQ(denied, View(Req(nobody), post, 1, "title"));
  EXPECT_EQ(denied, View(Req(nobody), missing, 1, "title"));
  /* A field with no value in that revision is absent, as one not granted is. */
  EXPECT_EQ("absent", View(Req(historian), post, 1, "rank"));
}

TEST_F(Actions, RevisionViewIsFilteredFieldByField) {
  DefinePost();
  Declare(Perm("View history", GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACCESS_ANY));
  /* `group` is a restricted field: only those granted its read see it. */
  Declare(Perm("Read group", "read", GDEFCORE_ACCESS_ANY, kPost, "group"));
  Role("historians");
  Role("group-readers");
  Grant("historians", "View history");
  Grant("group-readers", "View history");
  Grant("group-readers", "Read group");
  std::string plain = Principal("historians");
  std::string wide = Principal("group-readers");
  std::string post = Save(Admin(), "t", "a");
  /* The title is open to both. */
  EXPECT_EQ("shown:t", View(Req(plain), post, 1, "title"));
  EXPECT_EQ("shown:t", View(Req(wide), post, 1, "title"));
  /* The restricted field is shown to the one granted it and absent to the
   * other: nothing but the absence of a field the principal may not read. */
  EXPECT_EQ("shown:a", View(Req(wide), post, 1, "group"));
  EXPECT_EQ("absent", View(Req(plain), post, 1, "group"));
  /* A live read agrees with the view about who may see the field. */
  EXPECT_EQ("<denied>", Read(Req(plain), post, "group"));
}

TEST_F(Actions, RevisionViewNeverShowsAPersonalFieldAsStored) {
  DefinePost();
  Declare(Perm("View history", GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACCESS_ANY));
  Role("historians");
  Grant("historians", "View history");
  std::string historian = Principal("historians");
  std::string post = NewPost(Admin());
  ASSERT_EQ(GDEFCORE_OK, Write(Admin(), post, "t", "a", false, true));
  /* The stored revision holds the sealed text. */
  {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_entity_revision_values(catalog_, post.data(), post.size(), 1,
            "en", 2, "ssn", 3, &texts, &lens, &count));
    ASSERT_EQ(1u, count);
    EXPECT_EQ(sealed_, std::string(texts[0], lens[0]));
    gdefcore_values_free(catalog_, texts, lens, count);
  }
  /* The view opens it for a reader the filter allows (story S7): the
   * plaintext, never the ciphertext. */
  std::string view = View(Req(historian), post, 1, "ssn");
  EXPECT_EQ("shown:123-45-6789", view);
  EXPECT_EQ(std::string::npos, view.find("s1:"));
  /* The control: an ordinary field of the same revision is shown. */
  EXPECT_EQ("shown:t", View(Req(historian), post, 1, "title"));
  /* And a principal who may not view history learns nothing of the field. */
  EXPECT_EQ("<denied>", View(Req(Principal()), post, 1, "ssn"));
}

TEST_F(Actions, RevisionViewAsksTheCurrentStateNotTheViewedRevision) {
  DefinePost();
  Declare(Perm("View history", GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACCESS_ANY));
  Role("group-a");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "View history", kGroupA));
  std::string ga = Principal("group-a");
  /* Revision 1 is group a; revision 2, the newest, is group b. */
  std::string post = NewPost(Admin());
  ASSERT_EQ(GDEFCORE_OK, Write(Admin(), post, "one", "a", false));
  EXPECT_EQ("shown:one", View(Req(ga), post, 1, "title"));
  ASSERT_EQ(GDEFCORE_OK, Write(Admin(), post, "two", "b", false));
  /* The entity is now in group b, and the principal loses the history of the
   * revision that still says group a: what the viewed revision holds decides
   * nothing. */
  EXPECT_EQ("<denied>", View(Req(ga), post, 1, "title"));
  EXPECT_EQ("<denied>", View(Req(ga), post, 2, "title"));
  /* A draft that puts it back in group a is not what the entity is: the
   * condition reads the newest revision, never the draft. */
  ASSERT_EQ(GDEFCORE_OK, Write(Admin(), post, "draft", "a", true));
  EXPECT_EQ("<denied>", View(Req(ga), post, 1, "title"));
  /* Back to group a by a revert (revision 3): the group b revision is
   * viewable again, though it still says group b. */
  ASSERT_EQ(GDEFCORE_OK, RevertTo(post, 1));
  EXPECT_EQ("shown:two", View(Req(ga), post, 2, "title"));
  EXPECT_EQ("shown:one", View(Req(ga), post, 3, "title"));
}

TEST_F(Actions, AClearedEntitysHistoryIsStillThere) {
  DefinePost();
  Declare(Perm("View history", GDEFCORE_ACTION_REVISIONS_READ, GDEFCORE_ACCESS_ANY));
  Declare(Perm("Read posts", "read", GDEFCORE_ACCESS_ANY));
  Role("historians");
  Role("group-a");
  Grant("historians", "View history");
  ASSERT_EQ(GDEFCORE_OK, GrantWhen("group-a", "View history", kGroupA));
  std::string historian = Principal("historians");
  std::string ga = Principal("group-a");
  std::string post = Save(Admin(), "t", "a");
  ASSERT_EQ(GDEFCORE_OK, Change(gdefcore_entity_unpublish, post));
  EXPECT_EQ("shown:t", View(Req(historian), post, 1, "title"));
  EXPECT_EQ("shown:t", View(Req(ga), post, 1, "title"));
  /* Cleared: no current revision, so a condition on a field holds for no one,
   * and an unconditioned grant still does. */
  {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_revert(catalog_, post.data(), post.size(), NULL, 0, &cs));
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, "core.role", 9));
    gdefcore_changeset_destroy(cs);
  }
  EXPECT_EQ("shown:t", View(Req(historian), post, 1, "title"));
  EXPECT_EQ("<denied>", View(Req(ga), post, 1, "title"));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
