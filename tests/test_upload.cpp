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
 * Staged files (upload.h): refused before storage, staged with an expiry,
 * promoted by a reference that is counted from the stored entities, swept when
 * nothing references them, and read only by whoever may. Run by
 * tools/check-upload.sh, which plants a defect for each rule named here.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-core/upload.h>

#include <gtest/gtest.h>

#include "grants_fixture.h"
#include "size_structs.h"

#include <string.h>

#include <map>
#include <string>
#include <vector>

using namespace gfx;

namespace {

const char kGallery[] = "site.gallery";

/* A blob store in memory that counts what it is asked. */
struct Mem {
  std::map<std::string, std::string> blobs;
  int puts = 0;
  int removes = 0;
  std::string last_tenant;
  bool fail_put = false;
  static std::string Key(const uint8_t * t, size_t tl, const char * d) {
    return std::string((const char *)t, tl) + "/" + d;
  }
  static int Put(void * c, const uint8_t * t, size_t tl, const char * d, const uint8_t * b,
      size_t n) {
    Mem * m = (Mem *)c;
    if (m->fail_put) {
      return 1;
    }
    m->puts++;
    m->last_tenant.assign((const char *)t, tl);
    m->blobs[Key(t, tl, d)].assign((const char *)b, n);
    return 0;
  }
  static int Get(void * c, const uint8_t * t, size_t tl, const char * d, uint8_t * buf, size_t cap,
      size_t * out) {
    Mem * m = (Mem *)c;
    auto it = m->blobs.find(Key(t, tl, d));
    if (it == m->blobs.end() || it->second.size() > cap) {
      return 1;
    }
    memcpy(buf, it->second.data(), it->second.size());
    *out = it->second.size();
    return 0;
  }
  static int Remove(void * c, const uint8_t * t, size_t tl, const char * d) {
    Mem * m = (Mem *)c;
    m->removes++;
    m->blobs.erase(Key(t, tl, d));
    return 0;
  }
};

class Uploads : public GrantsFixture {
 protected:
  Mem mem_;
  GDEFCORE_Blob_Store blobs_;
  GDEFCORE_Upload_Policy policy_;
  const char * media_[2] = {"image/png", "application/pdf"};
  std::string admin_;
  std::string editor_;

  void SetUp() override {
    GrantsFixture::SetUp();
    memset(&blobs_, 0, sizeof blobs_);
    blobs_.size = sizeof blobs_;
    blobs_.ctx = &mem_;
    blobs_.put = Mem::Put;
    blobs_.get = Mem::Get;
    blobs_.remove = Mem::Remove;
    memset(&policy_, 0, sizeof policy_);
    policy_.size = sizeof policy_;
    policy_.max_bytes = 1000;
    policy_.media = media_;
    policy_.media_count = 2;
    policy_.ttl_ms = 5000;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_upload_declare(catalog_));
    DefineGallery();
    admin_ = Admin();
    Role("uploader");
    Grant("uploader", "Upload files");
    Grant("uploader", "See the files you uploaded");
    editor_ = Principal("uploader");
  }

  /* A type defined here and never named by the library: a single file
   * reference, a many-valued one, a group of images and a personal one. */
  void DefineGallery() {
    GDEFCORE_Field image = Field("image");
    image.type = GDEFSTOR_FIELD_REFERENCE;
    GDEFCORE_Field f[6];
    f[0] = Field("title");
    f[1] = Field("photo");
    f[1].type = GDEFSTOR_FIELD_REFERENCE;
    f[2] = Field("extras");
    f[2].type = GDEFSTOR_FIELD_REFERENCE;
    f[2].many = 1;
    f[3] = Field("slides");
    f[3].type = GDEFSTOR_FIELD_GROUP;
    f[3].many = 1;
    f[3].children = &image;
    f[3].child_count = 1;
    f[4] = Field("who");
    f[4].type = GDEFSTOR_FIELD_REFERENCE;
    f[5] = Field("private_photo", 1);
    f[5].type = GDEFSTOR_FIELD_REFERENCE;
    f[5].subject = "who";
    f[5].subject_len = 3;
    for (int i : {1, 2, 4}) {
      f[i].required = 0;
    }
    f[3].required = 0;
    f[5].required = 0;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_type_define(catalog_, kGallery, strlen(kGallery),
        GDEFCORE_TYPE_CONTENT, f, 6));
    Declare(Perm("Read galleries", "read", GDEFCORE_ACCESS_ANY, kGallery));
  }

  std::string Stage(const std::string & who, const char * name, const char * media,
      const std::string & bytes, uint64_t now = 1000, GDEFCORE_Result want = GDEFCORE_OK) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    id[0] = '\0';
    GDEFCORE_Result rc = gdefcore_upload_stage(catalog_, Req(who), &blobs_, &policy_, name,
        strlen(name), media, strlen(media), (const uint8_t *)bytes.data(), bytes.size(), now, id);
    EXPECT_EQ(want, rc) << name;
    return rc == GDEFCORE_OK ? std::string(id) : std::string();
  }

  /* A gallery whose single photo is @p file, whose extras are @p extras and
   * whose slides each hold one of @p slides. */
  std::string Gallery(const std::string & file, std::vector<std::string> extras = {},
      std::vector<std::string> slides = {}) {
    char id[GDEFCORE_PUBLIC_ID_LEN + 1];
    GDEFCORE_Changeset * cs = NULL;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_entity_create(catalog_, kGallery, strlen(kGallery), id, NULL));
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
    Save(cs, id, file, extras, slides);
    EXPECT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
    return std::string(id);
  }

  void Resave(const std::string & id, const std::string & file, std::vector<std::string> extras = {},
      std::vector<std::string> slides = {}) {
    GDEFCORE_Changeset * cs = NULL;
    ASSERT_EQ(GDEFCORE_OK,
        gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
    Save(cs, id.c_str(), file, extras, slides);
    ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
    gdefcore_changeset_destroy(cs);
  }

  void Save(GDEFCORE_Changeset * cs, const char * id, const std::string & file,
      const std::vector<std::string> & extras, const std::vector<std::string> & slides) {
    GDEFCORE_Tree * tree = NULL;
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_create(catalog_, &tree));
    auto set = [&](const char * f, const std::string & t) {
      ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(tree, 0, f, strlen(f), t.c_str(), t.size()));
    };
    set("title", "g");
    if (!file.empty()) {
      set("photo", file);
    }
    for (const std::string & e : extras) {
      size_t item = 0;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_add(tree, 0, "extras", 6, 0, &item));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(tree, item, "", 0, e.c_str(), e.size()));
    }
    for (const std::string & s : slides) {
      size_t item = 0;
      ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_add(tree, 0, "slides", 6, 0, &item));
      ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_set(tree, item, "image", 5, s.c_str(), s.size()));
    }
    ASSERT_EQ(GDEFCORE_OK, gdefcore_tree_save(cs, id, GDEFCORE_PUBLIC_ID_LEN, "en", 2, tree));
    gdefcore_tree_free(tree);
  }

  size_t Refs(const std::string & file) {
    size_t n = 99;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_upload_references(catalog_, file.data(), file.size(), &n));
    return n;
  }

  std::string Field1(const std::string & id, const char * field) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    std::string out;
    if (gdefcore_entity_values(catalog_, NULL, GDEFCORE_VIEW_PUBLISHED, id.data(), id.size(), "en",
            2, field, strlen(field), &texts, &lens, &count) == GDEFCORE_OK && count > 0) {
      out.assign(texts[0], lens[0]);
    }
    gdefcore_values_free(catalog_, texts, lens, count);
    return out;
  }

  bool Exists(const std::string & id) { return !Field1(id, "state").empty(); }

  struct Swept {
    size_t promoted = 0, demoted = 0, removed = 0;
  };
  Swept Sweep(uint64_t now) {
    Swept s;
    EXPECT_EQ(GDEFCORE_OK, gdefcore_upload_sweep(catalog_, &blobs_, &policy_, now, &s.promoted,
        &s.demoted, &s.removed));
    return s;
  }
};

}  // namespace

/* ---- refused before anything is stored ------------------------------------ */

TEST_F(Uploads, AFileThePolicyRefusesIsRefusedBeforeAByteIsStored) {
  std::string ok = Stage(editor_, "a.png", "image/png", "png bytes");
  ASSERT_FALSE(ok.empty());
  EXPECT_EQ(1, mem_.puts);
  mem_.puts = 0;
  Stage(editor_, "big.png", "image/png", std::string(1001, 'x'), 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "empty.png", "image/png", "", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "a.exe", "application/x-msdownload", "MZ", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "a.png", "image/PNG", "x", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "a.png", "image/png; charset=utf-8", "x", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "../etc/passwd", "image/png", "x", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "dir/a.png", "image/png", "x", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "dir\\a.png", "image/png", "x", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "..", "image/png", "x", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, "a\nb.png", "image/png", "x", 1000, GDEFCORE_ERR_INVALID);
  Stage(editor_, std::string(201, 'n').c_str(), "image/png", "x", 1000, GDEFCORE_ERR_INVALID);
  EXPECT_EQ(0, mem_.puts) << "a refused file reached the blob store";
  /* A name with accents is a name; a broken UTF-8 one is not. */
  EXPECT_NE("", Stage(editor_, "caf\xc3\xa9.png", "image/png", "e"));
  Stage(editor_, "caf\xc3.png", "image/png", "e", 1000, GDEFCORE_ERR_INVALID);
}

TEST_F(Uploads, NoPolicyLetsAFileBeBiggerThanTheHardMaximum) {
  policy_.max_bytes = 0;  /* the hard maximum */
  std::string big(GDEFCORE_UPLOAD_HARD_MAX + 1, 'x');
  Stage(editor_, "big.png", "image/png", big, 1000, GDEFCORE_ERR_INVALID);
  policy_.max_bytes = (uint64_t)1 << 40;  /* a policy that asks for more is held to it */
  Stage(editor_, "big.png", "image/png", big, 1000, GDEFCORE_ERR_INVALID);
  EXPECT_EQ(0, mem_.puts);
  EXPECT_NE("", Stage(editor_, "ok.png", "image/png", std::string(GDEFCORE_UPLOAD_HARD_MAX, 'x')));
}

TEST_F(Uploads, OnlyAPrincipalWhoMayCreateFilesStagesOne) {
  std::string nobody = Principal();
  Stage(nobody, "a.png", "image/png", "x", 1000, GDEFCORE_ERR_INVALID);
  EXPECT_EQ(0, mem_.puts);
  EXPECT_NE("", Stage(editor_, "a.png", "image/png", "x"));
}

TEST_F(Uploads, TheBlobStoreIsGivenTheTenantAndTheDigest) {
  ASSERT_NE("", Stage(editor_, "a.png", "image/png", "abc"));
  ASSERT_EQ(1u, mem_.blobs.size());
  /* SHA-256("abc"), under the catalog's own tenant. */
  EXPECT_EQ(std::string(kTenant, 1) + "/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      mem_.blobs.begin()->first);
  EXPECT_EQ(std::string(kTenant, 1), mem_.last_tenant);
}

/* ---- the lifecycle -------------------------------------------------------------- */

TEST_F(Uploads, AStagedFileLivesUntilItsExpiryAndNoLonger) {
  std::string id = Stage(editor_, "a.png", "image/png", "x", 1000);
  ASSERT_FALSE(id.empty());
  EXPECT_EQ("staged", Field1(id, "state"));
  EXPECT_EQ("6000", Field1(id, "expires"));
  Swept before = Sweep(5999);
  EXPECT_EQ(0u, before.removed);
  EXPECT_TRUE(Exists(id));
  EXPECT_EQ(1u, mem_.blobs.size());
  Swept at = Sweep(6000);
  EXPECT_EQ(1u, at.removed);
  EXPECT_FALSE(Exists(id));
  EXPECT_EQ(0u, mem_.blobs.size()) << "the blob of a swept file remained";
}

TEST_F(Uploads, AReferencedFileIsPromotedAndSurvivesItsExpiry) {
  std::string id = Stage(editor_, "a.png", "image/png", "x", 1000);
  std::string g = Gallery(id);
  /* The expiry has passed when the sweep runs: the reference still wins. */
  Swept s = Sweep(100000);
  EXPECT_EQ(1u, s.promoted);
  EXPECT_EQ(0u, s.removed);
  EXPECT_EQ("kept", Field1(id, "state"));
  EXPECT_TRUE(Exists(id));
  EXPECT_EQ(1u, mem_.blobs.size());
  (void)g;
  Swept again = Sweep(200000);
  EXPECT_EQ(0u, again.promoted + again.demoted + again.removed);
  EXPECT_TRUE(Exists(id));
}

TEST_F(Uploads, TheCountIsDerivedFromTheCurrentRevisionsOfTheEntitiesThatNameTheFile) {
  std::string a = Stage(editor_, "a.png", "image/png", "aaa");
  std::string b = Stage(editor_, "b.png", "image/png", "bbb");
  EXPECT_EQ(0u, Refs(a));
  std::string g1 = Gallery(a);
  EXPECT_EQ(1u, Refs(a));
  /* A many-valued field and an item of a group count too. */
  std::string g2 = Gallery(b, {a}, {a, b});
  EXPECT_EQ(3u, Refs(a));
  EXPECT_EQ(2u, Refs(b));
  /* The revision that no longer names a file stops counting it. */
  Resave(g1, b);
  EXPECT_EQ(2u, Refs(a));
  EXPECT_EQ(3u, Refs(b));
  Resave(g2, "");
  EXPECT_EQ(0u, Refs(a));
  EXPECT_EQ(1u, Refs(b));
  /* There is no counter in the stored file: its fields are the seven it declares. */
  size_t nfields = 0;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_type_field_count(catalog_, GDEFCORE_UPLOAD_TYPE,
      strlen(GDEFCORE_UPLOAD_TYPE), &nfields));
  EXPECT_EQ(7u, nfields);
}

TEST_F(Uploads, AReferenceInAnyLanguageOfAnEntityHoldsTheFile) {
  std::string only_fr = Stage(editor_, "fr.png", "image/png", "frfrfr");
  std::string stray = Stage(editor_, "stray.png", "image/png", "stray");
  std::string g = Gallery("");
  /* The English text names nothing; a French one names the file. */
  EXPECT_EQ(0u, Refs(only_fr));
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
  const char * texts[2] = {"g (fr)", only_fr.c_str()};
  size_t lens[2] = {6, only_fr.size()};
  GDEFCORE_Value v[2];
  memset(v, 0, sizeof v);
  v[0].size = sizeof v[0];
  v[0].field = "title";
  v[0].field_len = 5;
  v[0].texts = &texts[0];
  v[0].text_lens = &lens[0];
  v[0].count = 1;
  v[1].size = sizeof v[1];
  v[1].field = "photo";
  v[1].field_len = 5;
  v[1].texts = &texts[1];
  v[1].text_lens = &lens[1];
  v[1].count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save(cs, g.c_str(), g.size(), "fr", 2, v, 2));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  EXPECT_EQ(1u, Refs(only_fr)) << "a reference in French is a reference";
  Swept s = Sweep(100000);
  EXPECT_EQ(1u, s.promoted);
  EXPECT_EQ(1u, s.removed) << "only the stray file went";
  EXPECT_TRUE(Exists(only_fr));
  EXPECT_FALSE(Exists(stray));
}

TEST_F(Uploads, ADraftThatNamesAFileHoldsItAsAPublishedRevisionDoes) {
  std::string held = Stage(editor_, "draft.png", "image/png", "ddd");
  std::string stray = Stage(editor_, "stray.png", "image/png", "sss");
  std::string g = Gallery("");
  GDEFCORE_Changeset * cs = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_prepare(catalog_, admin_.data(), admin_.size(), &cs));
  const char * text = held.c_str();
  size_t len = held.size();
  GDEFCORE_Value v;
  memset(&v, 0, sizeof v);
  v.size = sizeof v;
  v.field = "photo";
  v.field_len = 5;
  v.texts = &text;
  v.text_lens = &len;
  v.count = 1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_entity_save_draft(cs, g.c_str(), g.size(), "en", 2, &v, 1));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_changeset_apply(cs, NULL, 0));
  gdefcore_changeset_destroy(cs);
  /* The published revision names nothing; the draft names the file. */
  EXPECT_EQ(1u, Refs(held));
  EXPECT_EQ(0u, Refs(stray));
  Swept s = Sweep(100000);
  EXPECT_EQ(1u, s.promoted);
  EXPECT_EQ(1u, s.removed);
  EXPECT_TRUE(Exists(held)) << "the editor's unpublished work is not swept from under them";
  EXPECT_FALSE(Exists(stray));
}

TEST_F(Uploads, AKeptFileNothingReferencesAnyMoreIsStagedAgainWithAFreshExpiry) {
  std::string id = Stage(editor_, "a.png", "image/png", "x", 1000);
  std::string g = Gallery(id);
  ASSERT_EQ(1u, Sweep(2000).promoted);
  std::string other = Stage(editor_, "o.png", "image/png", "o", 2000);
  Resave(g, other);
  Swept s = Sweep(50000);
  EXPECT_EQ(1u, s.demoted);
  EXPECT_EQ(0u, s.removed) << "a file that was just unreferenced was deleted at once";
  EXPECT_EQ("staged", Field1(id, "state"));
  EXPECT_EQ("55000", Field1(id, "expires"));
  EXPECT_EQ(1u, Sweep(55000).removed);
  EXPECT_FALSE(Exists(id));
}

TEST_F(Uploads, FilesOfTheSameBytesShareABlobUntilTheLastOfThemGoes) {
  std::string a = Stage(editor_, "a.png", "image/png", "same", 1000);
  std::string b = Stage(editor_, "b.png", "image/png", "same", 1000);
  ASSERT_NE(a, b);
  ASSERT_EQ(1u, mem_.blobs.size());
  std::string g = Gallery(a);
  Swept s = Sweep(100000);
  EXPECT_EQ(1u, s.removed);  /* b */
  EXPECT_FALSE(Exists(b));
  EXPECT_TRUE(Exists(a));
  EXPECT_EQ(1u, mem_.blobs.size()) << "the blob a kept file needs was removed";
  Resave(g, "");
  Sweep(200000);          /* demoted */
  EXPECT_EQ(1u, Sweep(900000).removed);
  EXPECT_EQ(0u, mem_.blobs.size());
}

/* ---- who may have the bytes ------------------------------------------------------ */

TEST_F(Uploads, TheBytesGoToTheUploaderOfAStagedFileAndToNoOneElse) {
  std::string id = Stage(editor_, "a.png", "image/png", "secret bytes");
  GDEFCORE_Upload_File * f = NULL;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_upload_read(catalog_, Req(editor_), &blobs_, id.data(), id.size(), &f));
  EXPECT_EQ("a.png", std::string(gdefcore_upload_file_name(f)));
  EXPECT_EQ("image/png", std::string(gdefcore_upload_file_media(f)));
  EXPECT_EQ("secret bytes", std::string((const char *)gdefcore_upload_file_bytes(f),
      gdefcore_upload_file_size(f)));
  gdefcore_upload_file_free(f);
  std::string other = Principal("uploader");
  f = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_upload_read(catalog_, Req(other), &blobs_, id.data(), id.size(), &f));
  EXPECT_EQ(NULL, f);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_upload_read(catalog_, Req(), &blobs_, id.data(), id.size(), &f));
  /* A file that does not exist is told the same way. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_upload_read(catalog_, Req(editor_), &blobs_, "00000000000000000000", 20, &f));
}

TEST_F(Uploads, AKeptFileIsReadByWhoeverMaySeeTheEntityThatNamesIt) {
  std::string id = Stage(editor_, "a.png", "image/png", "photo");
  std::string g = Gallery(id);
  Sweep(2000);
  Role("viewer");
  Grant("viewer", "Read galleries");
  std::string viewer = Principal("viewer");
  std::string stranger = Principal();
  GDEFCORE_Upload_File * f = NULL;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_upload_read(catalog_, Req(viewer), &blobs_, id.data(), id.size(), &f));
  gdefcore_upload_file_free(f);
  f = NULL;
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_upload_read(catalog_, Req(stranger), &blobs_, id.data(), id.size(), &f));
  (void)g;
}

TEST_F(Uploads, ABlobThatIsMissingOrIsNotTheDigestIsNeverServed) {
  std::string id = Stage(editor_, "a.png", "image/png", "photo");
  GDEFCORE_Upload_File * f = NULL;
  std::string key = mem_.blobs.begin()->first;
  mem_.blobs[key] = "other";  /* same length is not needed: a different size fails too */
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_upload_read(catalog_, Req(editor_), &blobs_, id.data(), id.size(), &f));
  mem_.blobs[key] = "phOto";  /* the same size and not the bytes */
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_upload_read(catalog_, Req(editor_), &blobs_, id.data(), id.size(), &f));
  mem_.blobs.erase(key);
  EXPECT_EQ(GDEFCORE_ERR_CORRUPT,
      gdefcore_upload_read(catalog_, Req(editor_), &blobs_, id.data(), id.size(), &f));
  EXPECT_EQ(NULL, f);
}

/* ---- personal fields ------------------------------------------------------------- */

TEST_F(Uploads, AFileIsNeverAttachedThroughAPersonalFieldOrAFieldThatIsNotAReference) {
  int ok = -1;
  ASSERT_EQ(GDEFCORE_OK, gdefcore_upload_field_ok(catalog_, kGallery, strlen(kGallery), "photo", 5, &ok));
  EXPECT_EQ(1, ok);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_upload_field_ok(catalog_, kGallery, strlen(kGallery), "extras", 6, &ok));
  EXPECT_EQ(1, ok);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_upload_field_ok(catalog_, kGallery, strlen(kGallery), "slides.image", 12, &ok));
  EXPECT_EQ(1, ok);
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_upload_field_ok(catalog_, kGallery, strlen(kGallery), "private_photo", 13, &ok));
  EXPECT_EQ(0, ok) << "a personal field holds ciphertext, which the count cannot see";
  ASSERT_EQ(GDEFCORE_OK, gdefcore_upload_field_ok(catalog_, kGallery, strlen(kGallery), "title", 5, &ok));
  EXPECT_EQ(0, ok);
  ASSERT_EQ(GDEFCORE_OK, gdefcore_upload_field_ok(catalog_, kGallery, strlen(kGallery), "nope", 4, &ok));
  EXPECT_EQ(0, ok);
  EXPECT_EQ(GDEFCORE_ERR_INVALID,
      gdefcore_upload_field_ok(catalog_, "site.missing", 12, "photo", 5, &ok));
}

/* ---- the structs ------------------------------------------------------------------ */

TEST_F(Uploads, TheStructsOfAnUploadAreAcceptedAtOnlyTheirOwnSize) {
  size_structs::Run("tests/test_upload.cpp",
      {
          {"GDEFCORE_Blob_Store", [&](size_t n) {
             GDEFCORE_Blob_Store b = blobs_;
             b.size = n;
             char id[GDEFCORE_PUBLIC_ID_LEN + 1];
             return gdefcore_upload_stage(catalog_, Req(editor_), &b, &policy_, "s.png", 5,
                        "image/png", 9, (const uint8_t *)"x", 1, 1000, id) == GDEFCORE_OK;
           }},
          {"GDEFCORE_Upload_Policy", [&](size_t n) {
             GDEFCORE_Upload_Policy p = policy_;
             p.size = n;
             char id[GDEFCORE_PUBLIC_ID_LEN + 1];
             return gdefcore_upload_stage(catalog_, Req(editor_), &blobs_, &p, "s.png", 5,
                        "image/png", 9, (const uint8_t *)"x", 1, 1000, id) == GDEFCORE_OK;
           }},
      });
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
