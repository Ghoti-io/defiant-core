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
 * The fragment cache (story S7, AD-19, AD-26): rendered bytes under a render
 * key, each with the subjects whose personal values the render decrypted, as
 * its request recorded them. Erasing a subject purges every fragment that
 * names it (gdefcore_subject_bind_cache()); a fragment that decrypted nothing
 * names no subject and is kept. One lock guards the whole cache: a fragment is
 * put, read or purged under it, never half of one.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/render.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/mutex.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

#include "render_internal.h"

enum { kDefaultCapacity = 1024 };

typedef struct Fragment {
  char * key;
  size_t key_len;
  char * bytes;
  size_t len;
  char (*subjects)[GDEFCORE_PUBLIC_ID_LEN];
  size_t nsubjects;
} Fragment;

struct GDEFCORE_FragmentCache {
  const GDEFCORE_Allocator * alloc;
  GCU_MUTEX_T lock;
  Fragment * slots; /* oldest first */
  size_t n;
  size_t cap;
};

static void fragment_clear(const GDEFCORE_Allocator * alloc, Fragment * f) {
  if (f->bytes != NULL && f->len > 0) {
    /* A fragment can hold a person's plaintext (AD-19). */
    gsec_wipe(f->bytes, f->len);
  }
  gcu_allocator_free(alloc, f->key);
  gcu_allocator_free(alloc, f->bytes);
  gcu_allocator_free(alloc, f->subjects);
  memset(f, 0, sizeof *f);
}

/* Drop slot @p i, keeping the others in their order. */
static void drop_at(GDEFCORE_FragmentCache * c, size_t i) {
  fragment_clear(c->alloc, &c->slots[i]);
  if (i + 1 < c->n) {
    memmove(&c->slots[i], &c->slots[i + 1], (c->n - i - 1) * sizeof *c->slots);
  }
  c->n -= 1;
  memset(&c->slots[c->n], 0, sizeof *c->slots);
}

static size_t find_key(const GDEFCORE_FragmentCache * c, const char * key,
    size_t key_len) {
  size_t i;
  for (i = 0; i < c->n; i++) {
    if (c->slots[i].key_len == key_len &&
        (key_len == 0 || memcmp(c->slots[i].key, key, key_len) == 0)) {
      return i;
    }
  }
  return SIZE_MAX;
}

GDEFCORE_Result gdefcore_fragment_cache_create(
    const GDEFCORE_Allocator * allocator, size_t capacity,
    GDEFCORE_FragmentCache ** out_cache) {
  GDEFCORE_FragmentCache * c;
  const GDEFCORE_Allocator * alloc =
      allocator == NULL ? gdefcore_allocator_default() : allocator;
  if (out_cache == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (capacity == 0) {
    capacity = kDefaultCapacity;
  }
  if (capacity > SIZE_MAX / sizeof(Fragment)) {
    return GDEFCORE_ERR_LIMIT;
  }
  c = (GDEFCORE_FragmentCache *)gcu_allocator_calloc(alloc, 1, sizeof *c);
  if (c == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  c->alloc = alloc;
  c->cap = capacity;
  c->slots = (Fragment *)gcu_allocator_calloc(alloc, capacity, sizeof *c->slots);
  if (c->slots == NULL) {
    gcu_allocator_free(alloc, c);
    return GDEFCORE_ERR_OOM;
  }
  if (GCU_MUTEX_CREATE(c->lock) != 0) {
    gcu_allocator_free(alloc, c->slots);
    gcu_allocator_free(alloc, c);
    return GDEFCORE_ERR_INTERNAL;
  }
  *out_cache = c;
  return GDEFCORE_OK;
}

void gdefcore_fragment_cache_destroy(GDEFCORE_FragmentCache * cache) {
  size_t i;
  if (cache == NULL) {
    return;
  }
  for (i = 0; i < cache->n; i++) {
    fragment_clear(cache->alloc, &cache->slots[i]);
  }
  (void)GCU_MUTEX_DESTROY(cache->lock);
  gcu_allocator_free(cache->alloc, cache->slots);
  gcu_allocator_free(cache->alloc, cache);
}

GDEFCORE_Result gdefcore_fragment_put(GDEFCORE_FragmentCache * cache,
    const GDEFCORE_Request * request, const char * key, size_t key_len,
    const char * bytes, size_t len) {
  Fragment f;
  size_t i;
  size_t at;
  size_t ns;
  if (cache == NULL || request == NULL || key == NULL || key_len == 0 ||
      (bytes == NULL && len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_request_subjects_overflowed(request)) {
    /* Some subject it decrypted is not known: keeping it could keep a
     * person's plaintext past their erasure. */
    return GDEFCORE_ERR_LIMIT;
  }
  memset(&f, 0, sizeof f);
  ns = gdefcore_request_subject_count(request);
  f.key = (char *)gcu_allocator_malloc(cache->alloc, key_len);
  f.bytes = (char *)gcu_allocator_malloc(cache->alloc, len == 0 ? 1 : len);
  if (ns > 0) {
    f.subjects = (char (*)[GDEFCORE_PUBLIC_ID_LEN])gcu_allocator_calloc(
        cache->alloc, ns, sizeof *f.subjects);
  }
  if (f.key == NULL || f.bytes == NULL || (ns > 0 && f.subjects == NULL)) {
    fragment_clear(cache->alloc, &f);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(f.key, key, key_len);
  f.key_len = key_len;
  if (len > 0) {
    memcpy(f.bytes, bytes, len);
  }
  f.len = len;
  for (i = 0; i < ns; i++) {
    const char * sid = NULL;
    size_t sid_len = 0;
    if (!gdefcore_request_subject_at(request, i, &sid, &sid_len) ||
        sid_len != GDEFCORE_PUBLIC_ID_LEN) {
      fragment_clear(cache->alloc, &f);
      return GDEFCORE_ERR_INTERNAL;
    }
    memcpy(f.subjects[i], sid, GDEFCORE_PUBLIC_ID_LEN);
  }
  f.nsubjects = ns;
  if (GCU_MUTEX_LOCK(cache->lock) != 0) {
    fragment_clear(cache->alloc, &f);
    return GDEFCORE_ERR_INTERNAL;
  }
  at = find_key(cache, key, key_len);
  if (at != SIZE_MAX) {
    drop_at(cache, at);
  }
  if (cache->n == cache->cap) {
    drop_at(cache, 0); /* the oldest */
  }
  cache->slots[cache->n++] = f;
  (void)GCU_MUTEX_UNLOCK(cache->lock);
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_fragment_get(GDEFCORE_FragmentCache * cache,
    const char * key, size_t key_len, char ** out_bytes, size_t * out_len,
    int * out_found) {
  size_t at;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (cache == NULL || key == NULL || out_bytes == NULL || out_len == NULL ||
      out_found == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_found = 0;
  if (GCU_MUTEX_LOCK(cache->lock) != 0) {
    return GDEFCORE_ERR_INTERNAL;
  }
  at = find_key(cache, key, key_len);
  if (at != SIZE_MAX) {
    const Fragment * f = &cache->slots[at];
    char * copy = (char *)gcu_allocator_malloc(cache->alloc,
        f->len == 0 ? 1 : f->len);
    if (copy == NULL) {
      rc = GDEFCORE_ERR_OOM;
    } else {
      if (f->len > 0) {
        memcpy(copy, f->bytes, f->len);
      }
      *out_bytes = copy;
      *out_len = f->len;
      *out_found = 1;
    }
  }
  (void)GCU_MUTEX_UNLOCK(cache->lock);
  return rc;
}

void gdefcore_fragment_free(GDEFCORE_FragmentCache * cache, char * bytes) {
  if (cache == NULL) {
    return;
  }
  gcu_allocator_free(cache->alloc, bytes);
}

GDEFCORE_Result gdefcore_fragment_purge_subject(GDEFCORE_FragmentCache * cache,
    const char * subject, size_t subject_len, size_t * out_purged) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  size_t purged = 0;
  size_t i;
  if (out_purged != NULL) {
    *out_purged = 0;
  }
  if (cache == NULL || subject == NULL ||
      gdefcore_id_canonical(subject, subject_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (GCU_MUTEX_LOCK(cache->lock) != 0) {
    return GDEFCORE_ERR_INTERNAL;
  }
  i = 0;
  while (i < cache->n) {
    const Fragment * f = &cache->slots[i];
    size_t k;
    int names = 0;
    for (k = 0; k < f->nsubjects && !names; k++) {
      names = memcmp(f->subjects[k], canon, GDEFCORE_PUBLIC_ID_LEN) == 0;
    }
    if (names) {
      drop_at(cache, i);
      purged += 1;
    } else {
      i += 1;
    }
  }
  (void)GCU_MUTEX_UNLOCK(cache->lock);
  if (out_purged != NULL) {
    *out_purged = purged;
  }
  return GDEFCORE_OK;
}

size_t gdefcore_fragment_count(GDEFCORE_FragmentCache * cache) {
  size_t n;
  if (cache == NULL || GCU_MUTEX_LOCK(cache->lock) != 0) {
    return 0;
  }
  n = cache->n;
  (void)GCU_MUTEX_UNLOCK(cache->lock);
  return n;
}
