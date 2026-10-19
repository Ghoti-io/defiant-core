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
 * The key store a subject test runs on, and a window onto it (story S5b).
 *
 * GDEFCORE_TEST_KEYSTORE picks the backend: unset or `memory`
 * (defiant-storage-memory), `sqlite` (a directory of key files of its own,
 * made per key store and removed at exit) or `postgres` (a schema of its own
 * per key store on the server GDEFSPG_TEST_CONNINFO names; built only where
 * defiant-storage-postgres is, which is the derived image). Every key store
 * is wrapped in a backend that counts the calls reaching the port, reads and
 * writes apart, and can fail an erasure or look at the world the moment one
 * arrives. That is how "a save writes nothing to the key store" and "the key
 * goes before the blind rows" are seen through the port rather than taken on
 * trust. The variable is read here, by the tests; the library reads none.
 */

#ifndef GDEFCORE_TESTS_KEYSTORE_RIG_H
#define GDEFCORE_TESTS_KEYSTORE_RIG_H

#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/defiant-storage-sqlite/model.h>
#include <ghoti.io/defiant-storage/keystore.h>
#ifdef GDEFCORE_TEST_HAVE_PG
#include <ghoti.io/defiant-storage-postgres/model.h>
#include <unistd.h>
#endif

#include <gtest/gtest.h>

#include "portable.h"

#include <stdlib.h>
#include <string.h>

#include <cstdio>
#include <filesystem>
#include <functional>
#include <string>
#include <system_error>
#include <vector>

namespace ksrig {

enum Kind { kMemory = 0, kSqlite, kPostgres };

inline const char * Name(Kind k) {
  return k == kSqlite ? "sqlite" : k == kPostgres ? "postgres" : "memory";
}

/* -1 for a value this rig does not know. */
inline int KindFromEnv() {
  const char * v = getenv("GDEFCORE_TEST_KEYSTORE");
  if (v == NULL || v[0] == '\0' || strcmp(v, "memory") == 0) {
    return kMemory;
  }
  if (strcmp(v, "sqlite") == 0) {
    return kSqlite;
  }
  if (strcmp(v, "postgres") == 0) {
    return kPostgres;
  }
  return -1;
}

inline Kind Chosen() {
  int k = KindFromEnv();
  return k < 0 ? kMemory : static_cast<Kind>(k);
}

/* The directories the SQLite key stores of this process were made in. */
struct Dirs {
  std::string root;
  unsigned next = 0;
  ~Dirs() {
    if (!root.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(root, ec);
    }
  }
  std::string Fresh() {
    if (root.empty()) {
      std::error_code ec;
      std::string t = std::filesystem::temp_directory_path(ec).string();
      if (ec) {
        return std::string();
      }
      std::string tmpl = t + "/gdefcore-keys-XXXXXX";
      std::vector<char> buf(tmpl.begin(), tmpl.end());
      buf.push_back('\0');
      if (mkdtemp(buf.data()) == NULL) {
        return std::string();
      }
      root = buf.data();
    }
    std::string d = root + "/k" + std::to_string(++next);
    std::error_code ec;
    if (!std::filesystem::create_directory(d, ec) || ec) {
      return std::string();
    }
    return d;
  }
};

inline Dirs & TheDirs() {
  static Dirs d;
  return d;
}

/* A key store of @p kind, with core's cipher, empty. */
inline GDEFSTOR_Result OpenInner(Kind kind, GDEFSTOR_KeyStore ** out) {
  static GDEFSTOR_KeyCipher cipher;
  gdefcore_subject_cipher(&cipher);
  if (kind == kSqlite) {
    std::string dir = TheDirs().Fresh();
    if (dir.empty()) {
      return GDEFSTOR_ERR_IO;
    }
    return gdefssqlite_keystore_create(dir.c_str(), &cipher, NULL, NULL, out) ==
                   GDEFSSQLITE_OK
               ? GDEFSTOR_OK
               : GDEFSTOR_ERR_IO;
  }
  if (kind == kPostgres) {
#ifdef GDEFCORE_TEST_HAVE_PG
    static unsigned n = 0;
    static std::vector<std::string> prefixes;
    const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
    char prefix[32];
    if (ci == NULL || ci[0] == '\0') {
      return GDEFSTOR_ERR_IO;
    }
    snprintf(prefix, sizeof prefix, "ck%x_%u_",
        (unsigned)getpid() & 0xfffffu, ++n);
    prefixes.push_back(prefix);
    GDEFSPG_Options o;
    gdefspg_options_default(&o);
    o.conninfo = ci;
    o.schema_prefix = prefixes.back().c_str();
    return gdefspg_keystore_create(&o, &cipher, NULL, out) == GDEFSPG_OK
               ? GDEFSTOR_OK
               : GDEFSTOR_ERR_IO;
#else
    return GDEFSTOR_ERR_UNSUPPORTED;
#endif
  }
  return gdefsmemory_keystore_create(NULL, &cipher, out) == GDEFSMEMORY_OK
             ? GDEFSTOR_OK
             : GDEFSTOR_ERR_IO;
}

/* What the window saw, and what it does to the next erasure. */
struct Counts {
  int writes = 0;   ///< create, subject put, secret put, erase, restore
  int reads = 0;    ///< wrap, unwrap, subject sealed, secret get, ledger, dump
  int erases = 0;   ///< erasures that reached the store
  int fail_next_erase = 0; ///< the next erasure fails before the store sees it
  std::function<void()> on_erase; ///< runs as an erasure reaches the window
};

struct Window {
  GDEFSTOR_KeyStore * inner = nullptr;
  Counts * counts = nullptr;
};

extern "C" {
static void w_destroy(void * ctx) {
  Window * w = static_cast<Window *>(ctx);
  gdefstor_keystore_destroy(w->inner);
  delete w;
}
static GDEFSTOR_Result w_create(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->writes++;
  return gdefstor_keystore_subject_create(w->inner, t, tl, s, sl);
}
static GDEFSTOR_Result w_wrap(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl, const uint8_t * in, size_t n, int * erased,
    uint8_t ** out, size_t * out_len) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->reads++;
  return gdefstor_keystore_wrap(w->inner, t, tl, s, sl, in, n, erased, out,
      out_len);
}
static GDEFSTOR_Result w_unwrap(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl, const uint8_t * in, size_t n, int * erased,
    uint8_t ** out, size_t * out_len) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->reads++;
  return gdefstor_keystore_unwrap(w->inner, t, tl, s, sl, in, n, erased, out,
      out_len);
}
static GDEFSTOR_Result w_erase(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl, int64_t when) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->writes++;
  if (w->counts->on_erase) {
    w->counts->on_erase();
  }
  if (w->counts->fail_next_erase) {
    w->counts->fail_next_erase = 0;
    return GDEFSTOR_ERR_IO;
  }
  w->counts->erases++;
  return gdefstor_keystore_erase(w->inner, t, tl, s, sl, when);
}
static GDEFSTOR_Result w_ledger(void * ctx, const char * t, size_t tl,
    GDEFSTOR_Result (*visit)(void *, const char *, size_t, int64_t),
    void * vctx) {
  Window * w = static_cast<Window *>(ctx);
  GDEFSTOR_Ledger * l = nullptr;
  w->counts->reads++;
  GDEFSTOR_Result rc = gdefstor_keystore_ledger(w->inner, t, tl, &l);
  for (size_t i = 0; rc == GDEFSTOR_OK && i < gdefstor_ledger_count(l); i++) {
    const char * s = nullptr;
    size_t sl = 0;
    int64_t when = 0;
    rc = gdefstor_ledger_row(l, i, &s, &sl, &when);
    if (rc == GDEFSTOR_OK) {
      rc = visit(vctx, s, sl, when);
    }
  }
  gdefstor_ledger_free(l);
  return rc;
}
static GDEFSTOR_Result w_sealed_put(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl, const uint8_t * b, size_t n) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->writes++;
  return gdefstor_keystore_subject_put(w->inner, t, tl, s, sl, b, n);
}
static GDEFSTOR_Result w_sealed_get(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl, int * erased, uint8_t ** out, size_t * out_len) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->reads++;
  return gdefstor_keystore_subject_sealed(w->inner, t, tl, s, sl, erased, out,
      out_len);
}
static GDEFSTOR_Result w_secret_put(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl, const uint8_t * b, size_t n) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->writes++;
  return gdefstor_keystore_secret_put(w->inner, t, tl, s, sl, b, n);
}
static GDEFSTOR_Result w_secret_get(void * ctx, const char * t, size_t tl,
    const char * s, size_t sl, int * found, uint8_t ** out, size_t * out_len) {
  Window * w = static_cast<Window *>(ctx);
  w->counts->reads++;
  return gdefstor_keystore_secret_get(w->inner, t, tl, s, sl, found, out,
      out_len);
}
static GDEFSTOR_Result w_dump(void * ctx, const char * t, size_t tl,
    GDEFSTOR_Result (*visit)(void *, const GDEFSTOR_KeyRow *), void * vctx) {
  Window * w = static_cast<Window *>(ctx);
  uint8_t * bytes = nullptr;
  size_t n = 0;
  GDEFSTOR_KeySet * set = nullptr;
  w->counts->reads++;
  GDEFSTOR_Result rc = gdefstor_keystore_export(w->inner, t, tl, 0, &bytes, &n);
  if (rc == GDEFSTOR_OK) {
    rc = gdefstor_keyset_parse(NULL, bytes, n, &set);
  }
  for (size_t i = 0; rc == GDEFSTOR_OK && i < gdefstor_keyset_count(set); i++) {
    GDEFSTOR_KeyRow row;
    rc = gdefstor_keyset_row(set, i, &row);
    if (rc == GDEFSTOR_OK) {
      rc = visit(vctx, &row);
    }
  }
  gdefstor_keyset_free(set);
  gdefstor_bytes_free(NULL, bytes);
  return rc;
}
static GDEFSTOR_Result w_restore(void * ctx, const char * t, size_t tl,
    const GDEFSTOR_KeyRow * rows, size_t count) {
  Window * w = static_cast<Window *>(ctx);
  uint8_t * bytes = nullptr;
  size_t n = 0;
  w->counts->writes++;
  GDEFSTOR_Result rc = gdefstor_keyset_encode(NULL, 0, rows, count, &bytes, &n);
  if (rc == GDEFSTOR_OK) {
    rc = gdefstor_keystore_import(w->inner, t, tl, bytes, n);
  }
  gdefstor_bytes_free(NULL, bytes);
  return rc;
}
}

/* A key store of @p kind seen through a window that fills @p counts. */
inline GDEFSTOR_Result Open(Kind kind, Counts * counts,
    GDEFSTOR_KeyStore ** out) {
  Window * w = new Window();
  w->counts = counts;
  GDEFSTOR_Result rc = OpenInner(kind, &w->inner);
  if (rc != GDEFSTOR_OK) {
    delete w;
    return rc;
  }
  GDEFSTOR_KeyStoreBackend b;
  memset(&b, 0, sizeof b);
  b.size = sizeof b;
  b.ctx = w;
  b.destroy = w_destroy;
  b.create = w_create;
  b.wrap = w_wrap;
  b.unwrap = w_unwrap;
  b.erase = w_erase;
  b.ledger = w_ledger;
  b.sealed_put = w_sealed_put;
  b.sealed_get = w_sealed_get;
  b.secret_put = w_secret_put;
  b.secret_get = w_secret_get;
  b.dump = w_dump;
  b.restore = w_restore;
  rc = gdefstor_keystore_create(&b, NULL, out);
  if (rc != GDEFSTOR_OK) {
    w_destroy(w);
  }
  return rc;
}

/* What a subject test program's main() returns: the chosen key store's run,
 * or, for the Postgres arm without a server, SKIPPED (with
 * GDEFSPG_TEST_SKIP_SERVER=1, and never reported as passed) or a failure
 * naming the fix. */
inline int RunAll() {
  int k = KindFromEnv();
  if (k < 0) {
    fprintf(stderr, "GDEFCORE_TEST_KEYSTORE is memory, sqlite or postgres\n");
    return 1;
  }
  if (k == kPostgres) {
#ifndef GDEFCORE_TEST_HAVE_PG
    fprintf(stderr, "the Postgres key store arm needs defiant-storage-postgres, "
                    "which builds in its derived image (libpq): run make "
                    "test-keystore-postgres there, through that library's "
                    "tools/pg-test.sh\n");
    return 1;
#else
    const char * ci = getenv("GDEFSPG_TEST_CONNINFO");
    if (ci == NULL || ci[0] == '\0') {
      const char * skip = getenv("GDEFSPG_TEST_SKIP_SERVER");
      if (skip != NULL && strcmp(skip, "1") == 0) {
        printf("SKIPPED: postgres (GDEFSPG_TEST_SKIP_SERVER=1): the Postgres "
               "key store arm did not run and is not counted as passed\n");
        return 0;
      }
      fprintf(stderr, "GDEFSPG_TEST_CONNINFO is not set: the Postgres key "
                      "store arm needs a server; run it through "
                      "defiant-storage-postgres's tools/pg-test.sh, or set "
                      "GDEFSPG_TEST_SKIP_SERVER=1 to skip it\n");
      return 1;
    }
#endif
  }
  printf("keystore: %s\n", Name(static_cast<Kind>(k)));
  fflush(stdout);
  return RUN_ALL_TESTS();
}

}  // namespace ksrig

#endif /* GDEFCORE_TESTS_KEYSTORE_RIG_H */
