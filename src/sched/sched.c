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
 * Round-robin across tenant spans, the offload pool and the yield watchdog.
 * The watchdog names a fiber. It does not switch one.
 */

#define _POSIX_C_SOURCE 200809L

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/sched.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <ghoti.io/cutil/fiber.h>
#include <ghoti.io/cutil/loop.h>
#include <ghoti.io/cutil/pool.h>
#include <ghoti.io/cutil/thread.h>
#include <ghoti.io/defiant-storage/store.h>

#include "sched_internal.h"

typedef struct GDEFCORE_Offload GDEFCORE_Offload;
typedef struct GDEFCORE_Slot GDEFCORE_Slot;

struct GDEFCORE_Offload {
  GDEFCORE_Offload_Fn fn;
  void * user;
  int status;
  int post_failed;
  GDEFCORE_Slot * slot;
  struct GDEFCORE_Sched * sched;
  GCU_Loop_Op op;
};

struct GDEFCORE_Slot {
  GDEFCORE_Request * request;
  GDEFCORE_Request_Fn fn;
  void * user;
  GCU_Fiber * fiber;
  GDEFCORE_Sched_Phase phase;
  size_t tenant_i;
  GDEFCORE_Offload * offload;
  GDEFCORE_Slot * park_next;
};

typedef struct GDEFCORE_TenantQ {
  uint8_t * tenant;
  size_t tenant_len;
  GDEFCORE_Slot ** items;
  size_t head;
  size_t count;
  size_t cap;
} GDEFCORE_TenantQ;

struct GDEFCORE_Sched {
  const GDEFCORE_Allocator * allocator;
  pthread_t owner;
  GCU_Loop * loop;
  GCU_Pool * pool;
  GCU_Thread watchdog;
  int watchdog_started;
  atomic_int stop_watch;
  atomic_uint_fast64_t running_id;
  atomic_uint_fast64_t slice_start;
  atomic_uint_fast64_t slice_bound;
  atomic_uint_fast64_t slice_gen;
  GDEFCORE_Slot * current;
  GDEFCORE_Slot * parked;
  GDEFCORE_TenantQ * tenants;
  size_t tenant_n;
  size_t tenant_cap;
  size_t rr;
  pthread_mutex_t named_mu;
  uint64_t * named;
  size_t named_n;
  size_t named_cap;
  uint64_t recorded_gen;
};

static uint64_t mono_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int same_thread(const GDEFCORE_Sched * sched) {
  return pthread_equal(sched->owner, pthread_self());
}

static int deadline_passed(const GDEFCORE_Request * request) {
  uint64_t deadline = gdefcore_request_deadline_ms(request);
  if (deadline == 0) {
    return 0;
  }
  return mono_ms() >= deadline;
}

static void abort_write(GDEFCORE_Request * request) {
  GDEFSTOR_Write * write = gdefcore_request_write(request);
  if (write == NULL) {
    return;
  }
  gdefstor_write_abort(write);
  gdefcore_request_set_write(request, NULL);
}

static void free_slot(GDEFCORE_Sched * sched, GDEFCORE_Slot * slot) {
  if (slot->fiber != NULL) {
    gcu_fiber_destroy(slot->fiber);
    gdefcore_request_attach_fiber(slot->request, NULL);
    slot->fiber = NULL;
  }
  if (slot->offload != NULL) {
    gcu_allocator_free(sched->allocator, slot->offload);
    slot->offload = NULL;
  }
  gcu_allocator_free(sched->allocator, slot);
}

static void unpark(GDEFCORE_Sched * sched, GDEFCORE_Slot * slot) {
  GDEFCORE_Slot ** link = &sched->parked;
  while (*link != NULL) {
    if (*link == slot) {
      *link = slot->park_next;
      slot->park_next = NULL;
      return;
    }
    link = &(*link)->park_next;
  }
}

static int q_push(GDEFCORE_Sched * sched, GDEFCORE_TenantQ * queue,
    GDEFCORE_Slot * slot) {
  size_t cap;
  GDEFCORE_Slot ** items;
  if (queue->head > 0 && queue->head + queue->count >= queue->cap) {
    memmove(queue->items, queue->items + queue->head,
        queue->count * sizeof *queue->items);
    queue->head = 0;
  }
  if (queue->head + queue->count >= queue->cap) {
    cap = queue->cap == 0 ? 4 : queue->cap * 2;
    items = (GDEFCORE_Slot **)gcu_allocator_realloc(sched->allocator,
        queue->items, cap * sizeof *items);
    if (items == NULL) {
      return 0;
    }
    queue->items = items;
    queue->cap = cap;
  }
  queue->items[queue->head + queue->count] = slot;
  queue->count++;
  return 1;
}

static GDEFCORE_Slot * q_pop(GDEFCORE_TenantQ * queue) {
  GDEFCORE_Slot * slot;
  if (queue->count == 0) {
    return NULL;
  }
  slot = queue->items[queue->head];
  queue->head++;
  queue->count--;
  if (queue->count == 0) {
    queue->head = 0;
  }
  return slot;
}

static GDEFCORE_Result enqueue_slot(
    GDEFCORE_Sched * sched, GDEFCORE_Slot * slot) {
  if (!q_push(sched, &sched->tenants[slot->tenant_i], slot)) {
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Slot * pick_ready(GDEFCORE_Sched * sched) {
  size_t i;
  if (sched->tenant_n == 0) {
    return NULL;
  }
  for (i = 0; i < sched->tenant_n; i++) {
    size_t index = (sched->rr + i) % sched->tenant_n;
    GDEFCORE_Slot * slot = q_pop(&sched->tenants[index]);
    if (slot != NULL) {
      sched->rr = (index + 1) % sched->tenant_n;
      return slot;
    }
  }
  return NULL;
}

static int span_eq(const GDEFCORE_TenantQ * queue, const uint8_t * tenant,
    size_t tenant_len) {
  return queue->tenant_len == tenant_len &&
      (tenant_len == 0 || memcmp(queue->tenant, tenant, tenant_len) == 0);
}

static GDEFCORE_Result tenant_slot(GDEFCORE_Sched * sched,
    GDEFCORE_Request * request, size_t * out_index) {
  const uint8_t * tenant;
  size_t tenant_len;
  size_t i;
  GDEFCORE_TenantQ * grown;
  uint8_t * copy;
  tenant = gdefcore_request_tenant(request, &tenant_len);
  for (i = 0; i < sched->tenant_n; i++) {
    if (span_eq(&sched->tenants[i], tenant, tenant_len)) {
      *out_index = i;
      return GDEFCORE_OK;
    }
  }
  if (sched->tenant_n == sched->tenant_cap) {
    size_t cap = sched->tenant_cap == 0 ? 4 : sched->tenant_cap * 2;
    grown = (GDEFCORE_TenantQ *)gcu_allocator_realloc(sched->allocator,
        sched->tenants, cap * sizeof *grown);
    if (grown == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    memset(grown + sched->tenant_cap, 0,
        (cap - sched->tenant_cap) * sizeof *grown);
    sched->tenants = grown;
    sched->tenant_cap = cap;
  }
  copy = (uint8_t *)gcu_allocator_malloc(sched->allocator, tenant_len);
  if (copy == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(copy, tenant, tenant_len);
  sched->tenants[sched->tenant_n].tenant = copy;
  sched->tenants[sched->tenant_n].tenant_len = tenant_len;
  *out_index = sched->tenant_n;
  sched->tenant_n++;
  return GDEFCORE_OK;
}

static void offload_complete(GCU_Loop_Op * op, void * user) {
  GDEFCORE_Offload * offload = (GDEFCORE_Offload *)user;
  GDEFCORE_Slot * slot = offload->slot;
  GDEFCORE_Sched * sched = offload->sched;
  (void)op;
  unpark(sched, slot);
  if (slot->phase == GDEFCORE_SCHED_PHASE_DEAD) {
    slot->offload = NULL;
    gcu_allocator_free(sched->allocator, offload);
    gcu_allocator_free(sched->allocator, slot);
    return;
  }
  enqueue_slot(sched, slot);
}

static int pool_task(void * ctx) {
  GDEFCORE_Offload * offload = (GDEFCORE_Offload *)ctx;
  offload->status = offload->fn(offload->user);
  if (gcu_loop_post(offload->sched->loop, &offload->op) != GCU_LOOP_OK) {
    offload->post_failed = 1;
    gcu_loop_wake(offload->sched->loop);
  }
  return 0;
}

static void trampoline(void * arg) {
  GDEFCORE_Slot * slot = (GDEFCORE_Slot *)arg;
  for (;;) {
    GDEFCORE_Turn turn;
    if (slot->phase == GDEFCORE_SCHED_PHASE_DEAD) {
      return;
    }
    turn = slot->fn(slot->request, slot->user);
    if (slot->phase == GDEFCORE_SCHED_PHASE_DEAD) {
      return;
    }
    if (turn == GDEFCORE_TURN_DONE) {
      return;
    }
    slot->phase = GDEFCORE_SCHED_PHASE_TURN;
    gcu_fiber_yield();
  }
}

static void arm_slice(GDEFCORE_Sched * sched, GDEFCORE_Slot * slot) {
  uint64_t gen = atomic_fetch_add_explicit(
      &sched->slice_gen, 1, memory_order_relaxed) + 1;
  atomic_store_explicit(&sched->slice_bound,
      gdefcore_request_yield_bound_ms(slot->request), memory_order_relaxed);
  atomic_store_explicit(
      &sched->slice_start, mono_ms(), memory_order_relaxed);
  atomic_store_explicit(&sched->slice_gen, gen, memory_order_relaxed);
  atomic_store_explicit(&sched->running_id,
      gdefcore_request_id(slot->request), memory_order_release);
}

static void disarm_slice(GDEFCORE_Sched * sched) {
  atomic_store_explicit(&sched->running_id, 0, memory_order_release);
}

static void record_name(GDEFCORE_Sched * sched, uint64_t id, uint64_t gen) {
  uint64_t * grown;
  pthread_mutex_lock(&sched->named_mu);
  if (sched->recorded_gen == gen) {
    pthread_mutex_unlock(&sched->named_mu);
    return;
  }
  if (sched->named_n == sched->named_cap) {
    size_t cap = sched->named_cap == 0 ? 4 : sched->named_cap * 2;
    grown = (uint64_t *)realloc(sched->named, cap * sizeof *grown);
    if (grown == NULL) {
      pthread_mutex_unlock(&sched->named_mu);
      return;
    }
    sched->named = grown;
    sched->named_cap = cap;
  }
  sched->named[sched->named_n] = id;
  sched->named_n++;
  sched->recorded_gen = gen;
  pthread_mutex_unlock(&sched->named_mu);
}

static GCU_THREAD_FUNC_RETURN_T GCU_THREAD_FUNC_CALLING_CONVENTION
watch_main(GCU_THREAD_FUNC_ARG_T arg) {
  GDEFCORE_Sched * sched = (GDEFCORE_Sched *)arg;
  while (atomic_load_explicit(&sched->stop_watch, memory_order_acquire) == 0) {
    struct timespec delay;
    uint64_t id;
    uint64_t bound;
    uint64_t start;
    uint64_t gen;
    delay.tv_sec = 0;
    delay.tv_nsec = 5000000L;
    nanosleep(&delay, NULL);
    id = atomic_load_explicit(&sched->running_id, memory_order_acquire);
    if (id == 0) {
      continue;
    }
    bound = atomic_load_explicit(&sched->slice_bound, memory_order_relaxed);
    start = atomic_load_explicit(&sched->slice_start, memory_order_relaxed);
    gen = atomic_load_explicit(&sched->slice_gen, memory_order_relaxed);
    if (bound == 0 || start == 0 || mono_ms() - start < bound) {
      continue;
    }
    record_name(sched, id, gen);
  }
  return (GCU_THREAD_FUNC_RETURN_T)0;
}

static void run_slot(GDEFCORE_Sched * sched, GDEFCORE_Slot * slot) {
  GCU_Fiber_Result fiber_result;
  arm_slice(sched, slot);
  sched->current = slot;
  fiber_result = gcu_fiber_switch_to(slot->fiber);
  sched->current = NULL;
  disarm_slice(sched);
  if (fiber_result != GCU_FIBER_OK) {
    slot->phase = GDEFCORE_SCHED_PHASE_DEAD;
    gdefcore_request_set_status(slot->request, GDEFCORE_ERR_INTERNAL);
  }
  if (slot->fiber != NULL && gcu_fiber_is_finished(slot->fiber)) {
    free_slot(sched, slot);
    return;
  }
  if (slot->phase == GDEFCORE_SCHED_PHASE_DEAD) {
    if (slot->fiber != NULL) {
      gcu_fiber_destroy(slot->fiber);
      gdefcore_request_attach_fiber(slot->request, NULL);
      slot->fiber = NULL;
    }
    if (slot->offload == NULL) {
      gcu_allocator_free(sched->allocator, slot);
    } else {
      slot->park_next = sched->parked;
      sched->parked = slot;
    }
    return;
  }
  if (slot->phase == GDEFCORE_SCHED_PHASE_OFFLOAD) {
    slot->park_next = sched->parked;
    sched->parked = slot;
    return;
  }
  enqueue_slot(sched, slot);
}

static void cancel_expired(GDEFCORE_Sched * sched) {
  GDEFCORE_Slot * slot;
  for (slot = sched->parked; slot != NULL; slot = slot->park_next) {
    if (slot->phase != GDEFCORE_SCHED_PHASE_OFFLOAD) {
      continue;
    }
    if (!deadline_passed(slot->request)) {
      continue;
    }
    gdefcore_request_set_status(slot->request, GDEFCORE_ERR_LIMIT);
    slot->phase = GDEFCORE_SCHED_PHASE_DEAD;
    if (slot->fiber != NULL) {
      gcu_fiber_destroy(slot->fiber);
      gdefcore_request_attach_fiber(slot->request, NULL);
      slot->fiber = NULL;
    }
  }
}

static int has_live_offload(const GDEFCORE_Sched * sched) {
  const GDEFCORE_Slot * slot;
  for (slot = sched->parked; slot != NULL; slot = slot->park_next) {
    if (slot->phase == GDEFCORE_SCHED_PHASE_OFFLOAD) {
      return 1;
    }
  }
  return 0;
}

static long next_timeout(const GDEFCORE_Sched * sched) {
  const GDEFCORE_Slot * slot;
  long timeout = -1;
  uint64_t now = mono_ms();
  for (slot = sched->parked; slot != NULL; slot = slot->park_next) {
    uint64_t deadline;
    long remaining;
    if (slot->phase != GDEFCORE_SCHED_PHASE_OFFLOAD) {
      continue;
    }
    deadline = gdefcore_request_deadline_ms(slot->request);
    if (deadline == 0) {
      continue;
    }
    if (now >= deadline) {
      return 0;
    }
    remaining = (long)(deadline - now);
    if (timeout < 0 || remaining < timeout) {
      timeout = remaining;
    }
  }
  return timeout;
}

static void promote_failed_posts(GDEFCORE_Sched * sched) {
  GDEFCORE_Slot ** link = &sched->parked;
  while (*link != NULL) {
    GDEFCORE_Slot * slot = *link;
    if (slot->offload != NULL && slot->offload->post_failed &&
        slot->phase == GDEFCORE_SCHED_PHASE_OFFLOAD) {
      *link = slot->park_next;
      slot->park_next = NULL;
      enqueue_slot(sched, slot);
      continue;
    }
    link = &slot->park_next;
  }
}

GDEFCORE_Result gdefcore_sched_create(const GDEFCORE_Allocator * allocator,
    size_t pool_threads, size_t pool_max_queued, GDEFCORE_Sched ** out_sched) {
  GDEFCORE_Sched * sched;
  GCU_Pool_Config config;
  GCU_Loop_Result loop_result;
  if (out_sched == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (allocator == NULL) {
    allocator = gdefcore_allocator_default();
  }
  sched = (GDEFCORE_Sched *)gcu_allocator_calloc(allocator, 1, sizeof *sched);
  if (sched == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  sched->allocator = allocator;
  sched->owner = pthread_self();
  if (pthread_mutex_init(&sched->named_mu, NULL) != 0) {
    gcu_allocator_free(allocator, sched);
    return GDEFCORE_ERR_INTERNAL;
  }
  loop_result = gcu_loop_create(&sched->loop, allocator);
  if (loop_result != GCU_LOOP_OK) {
    pthread_mutex_destroy(&sched->named_mu);
    gcu_allocator_free(allocator, sched);
    return loop_result == GCU_LOOP_ERR_UNSUPPORTED
        ? GDEFCORE_ERR_UNSUPPORTED
        : GDEFCORE_ERR_OOM;
  }
  memset(&config, 0, sizeof config);
  config.thread_count = pool_threads == 0 ? 1 : pool_threads;
  config.max_queued = pool_max_queued;
  config.name_prefix = "dcore";
  config.allocator = allocator;
  sched->pool = gcu_pool_create(&config);
  if (sched->pool == NULL) {
    gcu_loop_destroy(sched->loop);
    pthread_mutex_destroy(&sched->named_mu);
    gcu_allocator_free(allocator, sched);
    return GDEFCORE_ERR_OOM;
  }
  if (gcu_thread_create(&sched->watchdog, watch_main, sched) != 0) {
    gcu_pool_destroy(sched->pool);
    gcu_loop_destroy(sched->loop);
    pthread_mutex_destroy(&sched->named_mu);
    gcu_allocator_free(allocator, sched);
    return GDEFCORE_ERR_INTERNAL;
  }
  sched->watchdog_started = 1;
  *out_sched = sched;
  return GDEFCORE_OK;
}

static void drain_loop(GDEFCORE_Sched * sched) {
  while (gcu_loop_pending(sched->loop) > 0) {
    gcu_loop_run_once(sched->loop, 0);
  }
}

void gdefcore_sched_destroy(GDEFCORE_Sched * sched) {
  size_t i;
  if (sched == NULL) {
    return;
  }
  if (!same_thread(sched)) {
    return;
  }
  atomic_store_explicit(&sched->stop_watch, 1, memory_order_release);
  if (sched->watchdog_started) {
    gcu_thread_join(sched->watchdog);
    sched->watchdog_started = 0;
  }
  if (sched->pool != NULL) {
    gcu_pool_destroy(sched->pool);
    sched->pool = NULL;
  }
  if (sched->loop != NULL) {
    drain_loop(sched);
  }
  while (sched->parked != NULL) {
    GDEFCORE_Slot * slot = sched->parked;
    sched->parked = slot->park_next;
    free_slot(sched, slot);
  }
  for (i = 0; i < sched->tenant_n; i++) {
    GDEFCORE_TenantQ * queue = &sched->tenants[i];
    while (queue->count > 0) {
      free_slot(sched, q_pop(queue));
    }
    gcu_allocator_free(sched->allocator, queue->items);
    gcu_allocator_free(sched->allocator, queue->tenant);
  }
  gcu_allocator_free(sched->allocator, sched->tenants);
  if (sched->loop != NULL) {
    gcu_loop_destroy(sched->loop);
  }
  pthread_mutex_destroy(&sched->named_mu);
  free(sched->named);
  gcu_allocator_free(sched->allocator, sched);
}

GDEFCORE_Result gdefcore_sched_spawn(GDEFCORE_Sched * sched,
    GDEFCORE_Request * request, GDEFCORE_Request_Fn fn, void * user) {
  GDEFCORE_Slot * slot;
  GCU_Fiber_Result fiber_result;
  GDEFCORE_Result result;
  size_t tenant_i;
  if (sched == NULL || request == NULL || fn == NULL || !same_thread(sched)) {
    return GDEFCORE_ERR_INVALID;
  }
  result = tenant_slot(sched, request, &tenant_i);
  if (result != GDEFCORE_OK) {
    return result;
  }
  slot = (GDEFCORE_Slot *)gcu_allocator_calloc(
      sched->allocator, 1, sizeof *slot);
  if (slot == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  slot->request = request;
  slot->fn = fn;
  slot->user = user;
  slot->tenant_i = tenant_i;
  slot->phase = GDEFCORE_SCHED_PHASE_NEW;
  fiber_result = gcu_fiber_create(&slot->fiber, trampoline, slot,
      GCU_FIBER_DEFAULT_STACK_SIZE, sched->allocator);
  if (fiber_result != GCU_FIBER_OK) {
    gcu_allocator_free(sched->allocator, slot);
    if (fiber_result == GCU_FIBER_ERR_OOM) {
      return GDEFCORE_ERR_OOM;
    }
    if (fiber_result == GCU_FIBER_ERR_UNSUPPORTED) {
      return GDEFCORE_ERR_UNSUPPORTED;
    }
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_request_attach_fiber(request, slot->fiber) != GDEFCORE_OK) {
    gcu_fiber_destroy(slot->fiber);
    gcu_allocator_free(sched->allocator, slot);
    return GDEFCORE_ERR_INVALID;
  }
  if (enqueue_slot(sched, slot) != GDEFCORE_OK) {
    gcu_fiber_destroy(slot->fiber);
    gdefcore_request_attach_fiber(request, NULL);
    gcu_allocator_free(sched->allocator, slot);
    return GDEFCORE_ERR_OOM;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_sched_run(GDEFCORE_Sched * sched) {
  if (sched == NULL || !same_thread(sched) || sched->current != NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  for (;;) {
    GDEFCORE_Slot * slot = pick_ready(sched);
    if (slot != NULL) {
      run_slot(sched, slot);
      continue;
    }
    cancel_expired(sched);
    promote_failed_posts(sched);
    slot = pick_ready(sched);
    if (slot != NULL) {
      run_slot(sched, slot);
      continue;
    }
    if (!has_live_offload(sched)) {
      break;
    }
    gcu_loop_run_once(sched->loop, next_timeout(sched));
    cancel_expired(sched);
    promote_failed_posts(sched);
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_sched_yield(GDEFCORE_Sched * sched) {
  GDEFCORE_Slot * slot;
  if (sched == NULL || !same_thread(sched)) {
    return GDEFCORE_ERR_INVALID;
  }
  slot = sched->current;
  if (slot == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_request_write(slot->request) != NULL) {
    abort_write(slot->request);
    return GDEFCORE_ERR_INVALID;
  }
  slot->phase = GDEFCORE_SCHED_PHASE_TURN;
  gcu_fiber_yield();
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_sched_offload(GDEFCORE_Sched * sched,
    GDEFCORE_Offload_Fn fn, void * user, int * out_status) {
  GDEFCORE_Slot * slot;
  GDEFCORE_Offload * offload;
  if (sched == NULL || fn == NULL || !same_thread(sched)) {
    return GDEFCORE_ERR_INVALID;
  }
  slot = sched->current;
  if (slot == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_request_write(slot->request) != NULL) {
    abort_write(slot->request);
    return GDEFCORE_ERR_INVALID;
  }
  if (deadline_passed(slot->request)) {
    gdefcore_request_set_status(slot->request, GDEFCORE_ERR_LIMIT);
    slot->phase = GDEFCORE_SCHED_PHASE_DEAD;
    gcu_fiber_yield();
    return GDEFCORE_ERR_LIMIT;
  }
  offload = (GDEFCORE_Offload *)gcu_allocator_calloc(
      sched->allocator, 1, sizeof *offload);
  if (offload == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  offload->fn = fn;
  offload->user = user;
  offload->slot = slot;
  offload->sched = sched;
  gcu_loop_op_init(&offload->op, offload_complete, offload);
  slot->offload = offload;
  if (!gcu_pool_enqueue(sched->pool, pool_task, offload)) {
    slot->offload = NULL;
    gcu_allocator_free(sched->allocator, offload);
    return GDEFCORE_ERR_BUSY;
  }
  slot->phase = GDEFCORE_SCHED_PHASE_OFFLOAD;
  gcu_fiber_yield();
  if (offload->post_failed) {
    slot->offload = NULL;
    gcu_allocator_free(sched->allocator, offload);
    return GDEFCORE_ERR_INTERNAL;
  }
  if (out_status != NULL) {
    *out_status = offload->status;
  }
  slot->offload = NULL;
  gcu_allocator_free(sched->allocator, offload);
  return GDEFCORE_OK;
}

size_t gdefcore_sched_watchdog_count(const GDEFCORE_Sched * sched) {
  GDEFCORE_Sched * mutable_sched;
  size_t count;
  if (sched == NULL) {
    return 0;
  }
  mutable_sched = (GDEFCORE_Sched *)sched;
  pthread_mutex_lock(&mutable_sched->named_mu);
  count = mutable_sched->named_n;
  pthread_mutex_unlock(&mutable_sched->named_mu);
  return count;
}

uint64_t gdefcore_sched_watchdog_id_at(
    const GDEFCORE_Sched * sched, size_t index) {
  GDEFCORE_Sched * mutable_sched;
  uint64_t id = 0;
  if (sched == NULL) {
    return 0;
  }
  mutable_sched = (GDEFCORE_Sched *)sched;
  pthread_mutex_lock(&mutable_sched->named_mu);
  if (index < mutable_sched->named_n) {
    id = mutable_sched->named[index];
  }
  pthread_mutex_unlock(&mutable_sched->named_mu);
  return id;
}
