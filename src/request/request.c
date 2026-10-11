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
