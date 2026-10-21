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
 * The request handle. Tenant bytes live on the handle, never in a
 * thread-local.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/request.h>

#include <stdatomic.h>
#include <time.h>
#include <string.h>

#include "request_internal.h"

static atomic_uint_fast64_t gdefcore_next_request_id = 1;

GDEFCORE_Result gdefcore_request_create(const uint8_t * tenant,
    size_t tenant_len, uint64_t deadline_ms, uint64_t yield_bound_ms,
    const GDEFCORE_Allocator * allocator, GDEFCORE_Request ** out_request) {
  GDEFCORE_Request * request;
  uint64_t id;
  if (out_request == NULL || tenant == NULL || tenant_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  if (allocator == NULL) {
    allocator = gdefcore_allocator_default();
  }
  request = (GDEFCORE_Request *)gcu_allocator_calloc(
      allocator, 1, sizeof *request);
  if (request == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  request->tenant = (uint8_t *)gcu_allocator_malloc(allocator, tenant_len);
  if (request->tenant == NULL) {
    gcu_allocator_free(allocator, request);
    return GDEFCORE_ERR_OOM;
  }
  memcpy(request->tenant, tenant, tenant_len);
  request->tenant_len = tenant_len;
  request->deadline_ms = deadline_ms;
  request->yield_bound_ms = yield_bound_ms;
  id = atomic_fetch_add_explicit(
      &gdefcore_next_request_id, 1, memory_order_relaxed);
  if (id == 0) {
    id = atomic_fetch_add_explicit(
        &gdefcore_next_request_id, 1, memory_order_relaxed);
  }
  request->id = id;
  request->status = GDEFCORE_OK;
  request->allocator = allocator;
  *out_request = request;
  return GDEFCORE_OK;
}

static void memo_clear(GDEFCORE_Request * request) {
  size_t i;
  for (i = 0; i < request->nmemo; i++) {
    gcu_allocator_free(request->allocator, request->memo[i].key);
  }
  request->nmemo = 0;
}

void gdefcore_request_destroy(GDEFCORE_Request * request) {
  const GDEFCORE_Allocator * allocator;
  if (request == NULL) {
    return;
  }
  if (request->write != NULL) {
    gdefstor_write_abort(request->write);
    request->write = NULL;
  }
  if (request->fiber != NULL) {
    gcu_fiber_destroy(request->fiber);
    request->fiber = NULL;
  }
  allocator = request->allocator;
  if (request->nnotes > 0) {
    size_t i;
    for (i = 0; i < request->nnotes; i++) {
      gcu_allocator_free(allocator, request->notes[i].name);
      gcu_allocator_free(allocator, request->notes[i].value);
    }
    gcu_allocator_free(allocator, request->notes);
  }
  gcu_allocator_free(allocator, request->resolution);
  memo_clear(request);
  gcu_allocator_free(allocator, request->memo);
  gcu_allocator_free(allocator, request->reads);
  gcu_allocator_free(allocator, request->subjects);
  gcu_allocator_free(allocator, request->principal);
  gcu_allocator_free(allocator, request->acting);
  gcu_allocator_free(allocator, request->tenant);
  gcu_allocator_free(allocator, request);
}

const uint8_t * gdefcore_request_tenant(
    const GDEFCORE_Request * request, size_t * out_len) {
  if (request == NULL) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = request->tenant_len;
  }
  return request->tenant;
}

uint64_t gdefcore_request_deadline_ms(const GDEFCORE_Request * request) {
  return request == NULL ? 0 : request->deadline_ms;
}

uint64_t gdefcore_request_yield_bound_ms(const GDEFCORE_Request * request) {
  return request == NULL ? 0 : request->yield_bound_ms;
}

uint64_t gdefcore_request_id(const GDEFCORE_Request * request) {
  return request == NULL ? 0 : request->id;
}

GDEFCORE_Result gdefcore_request_status(const GDEFCORE_Request * request) {
  return request == NULL ? GDEFCORE_ERR_INVALID : request->status;
}

void gdefcore_request_set_status(
    GDEFCORE_Request * request, GDEFCORE_Result status) {
  if (request != NULL) {
    request->status = status;
  }
}

GCU_Fiber * gdefcore_request_fiber(const GDEFCORE_Request * request) {
  return request == NULL ? NULL : request->fiber;
}

GDEFCORE_Result gdefcore_request_attach_fiber(
    GDEFCORE_Request * request, GCU_Fiber * fiber) {
  if (request == NULL || (fiber != NULL && request->fiber != NULL)) {
    return GDEFCORE_ERR_INVALID;
  }
  request->fiber = fiber;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_request_set_write(
    GDEFCORE_Request * request, GDEFSTOR_Write * write) {
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (request->write != NULL && request->write != write) {
    gdefstor_write_abort(request->write);
  }
  request->write = write;
  return GDEFCORE_OK;
}

GDEFSTOR_Write * gdefcore_request_write(const GDEFCORE_Request * request) {
  return request == NULL ? NULL : request->write;
}

static GDEFCORE_Result set_public_id(GDEFCORE_Request * request, char ** slot,
    size_t * slot_len, const char * id, size_t id_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * copy;
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (id == NULL || id_len == 0) {
    gcu_allocator_free(request->allocator, *slot);
    *slot = NULL;
    *slot_len = 0;
    return GDEFCORE_OK;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  copy = (char *)gcu_allocator_malloc(
      request->allocator, GDEFCORE_PUBLIC_ID_LEN + 1);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(copy, canon, GDEFCORE_PUBLIC_ID_LEN + 1);
  gcu_allocator_free(request->allocator, *slot);
  *slot = copy;
  *slot_len = GDEFCORE_PUBLIC_ID_LEN;
  return GDEFCORE_OK;
}

static const char * get_public_id(const GDEFCORE_Request * request,
    const char * slot, size_t slot_len, size_t * out_len) {
  if (request == NULL || slot == NULL) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = slot_len;
  }
  return slot;
}

GDEFCORE_Result gdefcore_request_set_principal(
    GDEFCORE_Request * request, const char * id, size_t id_len) {
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return set_public_id(
      request, &request->principal, &request->principal_len, id, id_len);
}

const char * gdefcore_request_principal(
    const GDEFCORE_Request * request, size_t * out_len) {
  if (request == NULL) {
    return get_public_id(NULL, NULL, 0, out_len);
  }
  return get_public_id(
      request, request->principal, request->principal_len, out_len);
}

GDEFCORE_Result gdefcore_request_set_acting_principal(
    GDEFCORE_Request * request, const char * id, size_t id_len) {
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return set_public_id(request, &request->acting, &request->acting_len, id,
      id_len);
}

const char * gdefcore_request_acting_principal(
    const GDEFCORE_Request * request, size_t * out_len) {
  if (request == NULL) {
    return get_public_id(NULL, NULL, 0, out_len);
  }
  return get_public_id(request, request->acting, request->acting_len, out_len);
}

static char * copy_bytes(const GDEFCORE_Allocator * allocator, const char * text,
    size_t len) {
  char * copy;
  if (len == 0) {
    copy = (char *)gcu_allocator_malloc(allocator, 1);
    if (copy != NULL) {
      copy[0] = '\0';
    }
    return copy;
  }
  copy = (char *)gcu_allocator_malloc(allocator, len);
  if (copy == NULL) {
    return NULL;
  }
  memcpy(copy, text, len);
  return copy;
}

GDEFCORE_Result gdefcore_request_set_note(GDEFCORE_Request * request,
    const char * name, size_t name_len, const char * value, size_t value_len) {
  size_t i;
  char * name_copy;
  char * value_copy;
  GDEFCORE_Note * notes;
  if (request == NULL || name == NULL || name_len == 0 ||
      (value == NULL && value_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < request->nnotes; i++) {
    if (request->notes[i].name_len == name_len &&
        memcmp(request->notes[i].name, name, name_len) == 0) {
      value_copy = copy_bytes(request->allocator, value, value_len);
      if (value_copy == NULL) {
        return GDEFCORE_ERR_OOM;
      }
      gcu_allocator_free(request->allocator, request->notes[i].value);
      request->notes[i].value = value_copy;
      request->notes[i].value_len = value_len;
      return GDEFCORE_OK;
    }
  }
  name_copy = copy_bytes(request->allocator, name, name_len);
  value_copy = copy_bytes(request->allocator, value, value_len);
  if (name_copy == NULL || value_copy == NULL) {
    gcu_allocator_free(request->allocator, name_copy);
    gcu_allocator_free(request->allocator, value_copy);
    return GDEFCORE_ERR_OOM;
  }
  notes = (GDEFCORE_Note *)gcu_allocator_realloc(request->allocator,
      request->notes, (request->nnotes + 1) * sizeof *notes);
  if (notes == NULL) {
    gcu_allocator_free(request->allocator, name_copy);
    gcu_allocator_free(request->allocator, value_copy);
    return GDEFCORE_ERR_OOM;
  }
  request->notes = notes;
  request->notes[request->nnotes].name = name_copy;
  request->notes[request->nnotes].name_len = name_len;
  request->notes[request->nnotes].value = value_copy;
  request->notes[request->nnotes].value_len = value_len;
  request->nnotes += 1;
  return GDEFCORE_OK;
}

const char * gdefcore_request_note(const GDEFCORE_Request * request,
    const char * name, size_t name_len, size_t * out_len) {
  size_t i;
  if (request == NULL || name == NULL || name_len == 0) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  for (i = 0; i < request->nnotes; i++) {
    if (request->notes[i].name_len == name_len &&
        memcmp(request->notes[i].name, name, name_len) == 0) {
      if (out_len != NULL) {
        *out_len = request->notes[i].value_len;
      }
      return request->notes[i].value;
    }
  }
  if (out_len != NULL) {
    *out_len = 0;
  }
  return NULL;
}

GDEFCORE_Result gdefcore_request_set_resolution(GDEFCORE_Request * request,
    const char * text, size_t text_len) {
  char * copy;
  if (request == NULL || (text == NULL && text_len != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (text == NULL || text_len == 0) {
    gcu_allocator_free(request->allocator, request->resolution);
    request->resolution = NULL;
    request->resolution_len = 0;
    return GDEFCORE_OK;
  }
  copy = copy_bytes(request->allocator, text, text_len);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  gcu_allocator_free(request->allocator, request->resolution);
  request->resolution = copy;
  request->resolution_len = text_len;
  return GDEFCORE_OK;
}

const char * gdefcore_request_resolution(const GDEFCORE_Request * request,
    size_t * out_len) {
  if (request == NULL || request->resolution == NULL) {
    if (out_len != NULL) {
      *out_len = 0;
    }
    return NULL;
  }
  if (out_len != NULL) {
    *out_len = request->resolution_len;
  }
  return request->resolution;
}

void gdefcore_request_mark_principal_dependent(GDEFCORE_Request * request) {
  if (request != NULL) {
    request->principal_dependent = 1;
  }
}

int gdefcore_request_principal_dependent(const GDEFCORE_Request * request) {
  return request != NULL && request->principal_dependent != 0;
}

GDEFCORE_Result gdefcore_request_set_time(GDEFCORE_Request * request,
    int64_t seconds) {
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  request->time_seconds = seconds;
  request->time_set = 1;
  return GDEFCORE_OK;
}

int64_t gdefcore_request_time(GDEFCORE_Request * request) {
  if (request == NULL) {
    return 0;
  }
  if (!request->time_set) {
    request->time_seconds = (int64_t)time(NULL);
    request->time_set = 1;
  }
  return request->time_seconds;
}

int gdefcore_request_memo_get(GDEFCORE_Request * request, const char * key,
    size_t key_len, int * out_value) {
  size_t i;
  if (request == NULL || key == NULL || out_value == NULL) {
    return 0;
  }
  for (i = 0; i < request->nmemo; i++) {
    if (request->memo[i].key_len == key_len &&
        memcmp(request->memo[i].key, key, key_len) == 0) {
      *out_value = request->memo[i].value;
      request->memo_hits += 1;
      return 1;
    }
  }
  return 0;
}

GDEFCORE_Result gdefcore_request_memo_put(GDEFCORE_Request * request,
    const char * key, size_t key_len, int value) {
  size_t i;
  char * copy;
  if (request == NULL || key == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < request->nmemo; i++) {
    if (request->memo[i].key_len == key_len &&
        memcmp(request->memo[i].key, key, key_len) == 0) {
      request->memo[i].value = value;
      return GDEFCORE_OK;
    }
  }
  if (request->nmemo >= GDEFCORE_REQUEST_MEMO_MAX) {
    /* Start over rather than grow: the cost is asking again. */
    memo_clear(request);
    request->memo_restarts += 1;
  }
  if (request->nmemo == request->cap_memo) {
    size_t cap = request->cap_memo == 0 ? 16 : request->cap_memo * 2;
    GDEFCORE_Memo * next = (GDEFCORE_Memo *)gcu_allocator_realloc(
        request->allocator, request->memo, cap * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    request->memo = next;
    request->cap_memo = cap;
  }
  copy = copy_bytes(request->allocator, key, key_len);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  request->memo[request->nmemo].key = copy;
  request->memo[request->nmemo].key_len = key_len;
  request->memo[request->nmemo].value = value;
  request->nmemo += 1;
  return GDEFCORE_OK;
}

void gdefcore_request_memo_stats(const GDEFCORE_Request * request,
    size_t * out_entries, uint64_t * out_hits, uint64_t * out_restarts) {
  if (out_entries != NULL) {
    *out_entries = request == NULL ? 0 : request->nmemo;
  }
  if (out_hits != NULL) {
    *out_hits = request == NULL ? 0 : request->memo_hits;
  }
  if (out_restarts != NULL) {
    *out_restarts = request == NULL ? 0 : request->memo_restarts;
  }
}

GDEFCORE_Result gdefcore_request_record_dependency(GDEFCORE_Request * request,
    const char * id, size_t id_len, uint64_t revision) {
  size_t i;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  if (request == NULL || id == NULL ||
      gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < request->nreads; i++) {
    if (request->reads[i].revision == revision &&
        memcmp(request->reads[i].id, canon, sizeof canon) == 0) {
      return GDEFCORE_OK;
    }
  }
  if (request->nreads >= GDEFCORE_REQUEST_READS_MAX) {
    request->reads_overflowed = 1;
    return GDEFCORE_OK;
  }
  if (request->nreads == request->cap_reads) {
    size_t cap = request->cap_reads == 0 ? 16 : request->cap_reads * 2;
    GDEFCORE_Read * next = (GDEFCORE_Read *)gcu_allocator_realloc(
        request->allocator, request->reads, cap * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    request->reads = next;
    request->cap_reads = cap;
  }
  memcpy(request->reads[request->nreads].id, canon, sizeof canon);
  request->reads[request->nreads].revision = revision;
  request->nreads += 1;
  return GDEFCORE_OK;
}

size_t gdefcore_request_dependency_count(const GDEFCORE_Request * request) {
  return request == NULL ? 0 : request->nreads;
}

int gdefcore_request_dependency_at(const GDEFCORE_Request * request, size_t index,
    const char ** out_id, size_t * out_id_len, uint64_t * out_revision) {
  if (request == NULL || index >= request->nreads) {
    return 0;
  }
  if (out_id != NULL) {
    *out_id = request->reads[index].id;
  }
  if (out_id_len != NULL) {
    *out_id_len = GDEFCORE_PUBLIC_ID_LEN;
  }
  if (out_revision != NULL) {
    *out_revision = request->reads[index].revision;
  }
  return 1;
}

int gdefcore_request_dependencies_overflowed(const GDEFCORE_Request * request) {
  return request != NULL && request->reads_overflowed != 0;
}

GDEFCORE_Result gdefcore_request_record_subject(GDEFCORE_Request * request,
    const char * subject, size_t subject_len) {
  size_t i;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  if (request == NULL || subject == NULL ||
      gdefcore_id_canonical(subject, subject_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < request->nsubjects; i++) {
    if (memcmp(request->subjects[i], canon, sizeof canon) == 0) {
      return GDEFCORE_OK;
    }
  }
  if (request->nsubjects >= GDEFCORE_REQUEST_SUBJECTS_MAX) {
    request->subjects_overflowed = 1;
    return GDEFCORE_OK;
  }
  if (request->nsubjects == request->cap_subjects) {
    size_t cap = request->cap_subjects == 0 ? 8 : request->cap_subjects * 2;
    char (*next)[GDEFCORE_PUBLIC_ID_LEN + 1] =
        (char (*)[GDEFCORE_PUBLIC_ID_LEN + 1])gcu_allocator_realloc(
            request->allocator, request->subjects, cap * sizeof *next);
    if (next == NULL) {
      /* Not knowing a dependency is not knowing all of them. */
      request->subjects_overflowed = 1;
      return GDEFCORE_ERR_OOM;
    }
    request->subjects = next;
    request->cap_subjects = cap;
  }
  memcpy(request->subjects[request->nsubjects], canon, sizeof canon);
  request->nsubjects += 1;
  return GDEFCORE_OK;
}

size_t gdefcore_request_subject_count(const GDEFCORE_Request * request) {
  return request == NULL ? 0 : request->nsubjects;
}

int gdefcore_request_subject_at(const GDEFCORE_Request * request, size_t index,
    const char ** out_subject, size_t * out_len) {
  if (request == NULL || index >= request->nsubjects) {
    return 0;
  }
  if (out_subject != NULL) {
    *out_subject = request->subjects[index];
  }
  if (out_len != NULL) {
    *out_len = GDEFCORE_PUBLIC_ID_LEN;
  }
  return 1;
}

int gdefcore_request_subjects_overflowed(const GDEFCORE_Request * request) {
  return request != NULL && request->subjects_overflowed != 0;
}

GDEFCORE_Result gdefcore_request_set_fuel(GDEFCORE_Request * request,
    uint64_t units) {
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  request->has_fuel = 1;
  request->fuel = units;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_request_spend_fuel(GDEFCORE_Request * request,
    uint64_t units) {
  if (request == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!request->has_fuel) {
    return GDEFCORE_OK;
  }
  if (request->fuel < units) {
    request->fuel = 0;
    return GDEFCORE_ERR_LIMIT;
  }
  request->fuel -= units;
  return GDEFCORE_OK;
}

uint64_t gdefcore_request_fuel_left(const GDEFCORE_Request * request) {
  if (request == NULL || !request->has_fuel) {
    return UINT64_MAX;
  }
  return request->fuel;
}
