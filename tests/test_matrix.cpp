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
 * The matrix in story 6. Assertions run on the scheduler's thread, after
 * the fibers have returned. A fiber body only writes plain fields.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>

#include <gtest/gtest.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>

namespace {

uint64_t MonoMs() {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* The in-memory store: the writes below put one record, which the abort of
 * the port write must leave unwritten. */
GDEFSTOR_Store * OpenStore() {
  GDEFSTOR_Store * store = NULL;
  EXPECT_EQ(gdefsmemory_store_create(NULL, NULL, &store), GDEFSMEMORY_OK);
  return store;
}

GDEFSTOR_Result PutOne(GDEFSTOR_Write * write, const char * key,
    const uint8_t * bytes, size_t len) {
  return gdefstor_record_put(write, "core.test", 9, key, strlen(key), bytes,
      len);
}

struct FairState {
  GDEFCORE_Sched * sched;
  int b_ran;
  char order[8];
  int n;
};

extern "C" GDEFCORE_Turn FairA(GDEFCORE_Request * request, void * user) {
  FairState * state = (FairState *)user;
  (void)request;
  if (state->n < 8) {
    state->order[state->n++] = 'A';
  }
  if (!state->b_ran) {
    return GDEFCORE_TURN_AGAIN;
  }
  return GDEFCORE_TURN_DONE;
}

extern "C" GDEFCORE_Turn FairB(GDEFCORE_Request * request, void * user) {
  FairState * state = (FairState *)user;
  (void)request;
  if (state->n < 8) {
    state->order[state->n++] = 'B';
  }
  state->b_ran = 1;
  return GDEFCORE_TURN_DONE;
}

struct OffloadState {
  GDEFCORE_Sched * sched;
  pthread_t fiber_before;
  pthread_t fiber_after;
  pthread_t pool_thread;
  int ran;
  int status;
  GDEFCORE_Result rc;
  int after;
};

extern "C" int OffloadWork(void * user) {
  OffloadState * state = (OffloadState *)user;
  state->pool_thread = pthread_self();
  state->ran = 1;
  return 7;
}

extern "C" GDEFCORE_Turn OffloadBody(GDEFCORE_Request * request, void * user) {
  OffloadState * state = (OffloadState *)user;
  (void)request;
  state->fiber_before = pthread_self();
  state->rc = gdefcore_sched_offload(
      state->sched, OffloadWork, state, &state->status);
  state->fiber_after = pthread_self();
  state->after = 1;
  return GDEFCORE_TURN_DONE;
}

struct BusyState {
  GDEFCORE_Sched * sched;
  std::atomic<int> a_running;
  std::atomic<int> release;
  int nope_ran;
  GDEFCORE_Result c_rc;
  pthread_t creator;
};

extern "C" int BusyHold(void * user) {
  BusyState * state = (BusyState *)user;
  state->a_running.store(1);
  while (state->release.load() == 0) {
    usleep(1000);
  }
  return 1;
}

extern "C" int BusyNope(void * user) {
  BusyState * state = (BusyState *)user;
  state->nope_ran = 1;
  return 1;
}

extern "C" GDEFCORE_Turn BusyA(GDEFCORE_Request * request, void * user) {
  BusyState * state = (BusyState *)user;
  int status = 0;
  (void)request;
  gdefcore_sched_offload(state->sched, BusyHold, state, &status);
  return GDEFCORE_TURN_DONE;
}

extern "C" GDEFCORE_Turn BusyB(GDEFCORE_Request * request, void * user) {
  BusyState * state = (BusyState *)user;
  int status = 0;
  (void)request;
  while (state->a_running.load() == 0) {
    usleep(1000);
  }
  gdefcore_sched_offload(state->sched, BusyHold, state, &status);
  return GDEFCORE_TURN_DONE;
}

extern "C" GDEFCORE_Turn BusyC(GDEFCORE_Request * request, void * user) {
  BusyState * state = (BusyState *)user;
  (void)request;
  state->c_rc = gdefcore_sched_offload(
      state->sched, BusyNope, state, NULL);
  state->release.store(1);
  return GDEFCORE_TURN_DONE;
}

struct DeadlineState {
  GDEFCORE_Sched * sched;
  uint64_t until;
  int after;
  int slow_ran;
};

extern "C" int DeadlineSlow(void * user) {
  DeadlineState * state = (DeadlineState *)user;
  state->slow_ran = 1;
  while (MonoMs() < state->until) {
    usleep(1000);
  }
  return 9;
}

extern "C" GDEFCORE_Turn DeadlineBody(
    GDEFCORE_Request * request, void * user) {
  DeadlineState * state = (DeadlineState *)user;
  int status = 0;
  (void)request;
  gdefcore_sched_offload(state->sched, DeadlineSlow, state, &status);
  state->after = 1;
  return GDEFCORE_TURN_DONE;
}

struct WriteState {
  GDEFCORE_Sched * sched;
  GDEFSTOR_Store * store;
  const char * tenant;
  int offload_ran;
  int after;
  GDEFCORE_Result rc;
};

extern "C" int WriteOffload(void * user) {
  WriteState * state = (WriteState *)user;
  state->offload_ran = 1;
  return 1;
}

extern "C" GDEFCORE_Turn WriteBody(GDEFCORE_Request * request, void * user) {
  WriteState * state = (WriteState *)user;
  GDEFSTOR_Write * write = NULL;
  GDEFSTOR_Result begun;
  const uint8_t bytes[] = {'p', 'u', 't'};
  begun = gdefstor_write_begin(
      state->store, state->tenant, strlen(state->tenant), NULL, &write);
  if (begun != GDEFSTOR_OK) {
    state->rc = GDEFCORE_ERR_INTERNAL;
    return GDEFCORE_TURN_DONE;
  }
  if (PutOne(write, "h", bytes, sizeof bytes) != GDEFSTOR_OK) {
    gdefstor_write_abort(write);
    state->rc = GDEFCORE_ERR_INTERNAL;
    return GDEFCORE_TURN_DONE;
  }
  gdefcore_request_set_write(request, write);
  state->rc = gdefcore_sched_offload(
      state->sched, WriteOffload, state, NULL);
  state->after = 1;
  return GDEFCORE_TURN_DONE;
}

struct YieldState {
  GDEFCORE_Sched * sched;
  GDEFSTOR_Store * store;
  const char * tenant;
  int after;
  GDEFCORE_Result rc;
};

extern "C" GDEFCORE_Turn YieldApiBody(
    GDEFCORE_Request * request, void * user) {
  YieldState * state = (YieldState *)user;
  GDEFSTOR_Write * write = NULL;
  const uint8_t bytes[] = {'y'};
  if (gdefstor_write_begin(state->store, state->tenant, strlen(state->tenant),
          NULL, &write) != GDEFSTOR_OK) {
    state->rc = GDEFCORE_ERR_INTERNAL;
    return GDEFCORE_TURN_DONE;
  }
  if (PutOne(write, "y", bytes, sizeof bytes) != GDEFSTOR_OK) {
    gdefstor_write_abort(write);
    state->rc = GDEFCORE_ERR_INTERNAL;
    return GDEFCORE_TURN_DONE;
  }
  gdefcore_request_set_write(request, write);
  state->rc = gdefcore_sched_yield(state->sched);
  state->after = 1;
  return GDEFCORE_TURN_DONE;
}

extern "C" GDEFCORE_Turn YieldTurnBody(
    GDEFCORE_Request * request, void * user) {
  YieldState * state = (YieldState *)user;
  GDEFSTOR_Write * write = NULL;
  const uint8_t bytes[] = {'t'};
  if (gdefstor_write_begin(state->store, state->tenant, strlen(state->tenant),
          NULL, &write) != GDEFSTOR_OK) {
    state->rc = GDEFCORE_ERR_INTERNAL;
    return GDEFCORE_TURN_DONE;
  }
  if (PutOne(write, "t", bytes, sizeof bytes) != GDEFSTOR_OK) {
    gdefstor_write_abort(write);
    state->rc = GDEFCORE_ERR_INTERNAL;
    return GDEFCORE_TURN_DONE;
  }
  gdefcore_request_set_write(request, write);
  state->rc = GDEFCORE_ERR_INVALID;
  return GDEFCORE_TURN_AGAIN;
}

struct WatchState {
  uint64_t start;
  uint64_t bound_ms;
};

extern "C" GDEFCORE_Turn WatchBody(GDEFCORE_Request * request, void * user) {
  WatchState * state = (WatchState *)user;
  (void)request;
  while (MonoMs() - state->start < state->bound_ms) {
  }
  return GDEFCORE_TURN_DONE;
}

}  // namespace

TEST(Result, StringCoversEveryCode) {
  int i;
  for (i = 0; i < GDEFCORE_RESULT_COUNT; i++) {
    const char * text = gdefcore_result_string((GDEFCORE_Result)i);
    EXPECT_NE(text, nullptr);
    EXPECT_STRNE(text, "Unknown error");
  }
  EXPECT_STREQ(gdefcore_result_string(GDEFCORE_RESULT_COUNT), "Unknown error");
  EXPECT_STREQ(gdefcore_result_string(GDEFCORE_ERR_BUSY), "Offload queue full");
  EXPECT_STREQ(gdefcore_result_string(GDEFCORE_ERR_STALE),
      "Key set older than its data set");
  EXPECT_STREQ(gdefcore_result_string(GDEFCORE_ERR_LIMIT), "Limit exceeded");
}

TEST(Ambient, TenantComesFromTheHandle) {
  const uint8_t alpha[] = {'a', 'l', 'p', 'h', 'a'};
  const uint8_t beta[] = {'b', 'e', 't', 'a'};
  GDEFCORE_Request * first = NULL;
  GDEFCORE_Request * second = NULL;
  size_t len = 0;
  const uint8_t * got;
  ASSERT_EQ(gdefcore_request_create(
                alpha, sizeof alpha, 0, 0, NULL, &first),
      GDEFCORE_OK);
  ASSERT_EQ(gdefcore_request_create(
                beta, sizeof beta, 0, 0, NULL, &second),
      GDEFCORE_OK);
  got = gdefcore_request_tenant(first, &len);
  ASSERT_EQ(len, sizeof alpha);
  EXPECT_EQ(memcmp(got, alpha, len), 0);
  got = gdefcore_request_tenant(second, &len);
  ASSERT_EQ(len, sizeof beta);
  EXPECT_EQ(memcmp(got, beta, len), 0);
  EXPECT_NE(gdefcore_request_id(first), gdefcore_request_id(second));
  EXPECT_NE(gdefcore_request_id(first), 0u);
  gdefcore_request_destroy(first);
  gdefcore_request_destroy(second);
}

TEST(Fairness, OtherTenantRunsWhenOneDoesNotYield) {
  const uint8_t a[] = {'A'};
  const uint8_t b[] = {'B'};
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request_a = NULL;
  GDEFCORE_Request * request_b = NULL;
  FairState state;
  memset(&state, 0, sizeof state);
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 0, &sched), GDEFCORE_OK);
  state.sched = sched;
  ASSERT_EQ(gdefcore_request_create(a, 1, 0, 0, NULL, &request_a), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_request_create(b, 1, 0, 0, NULL, &request_b), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request_a, FairA, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request_b, FairB, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(state.b_ran, 1);
  ASSERT_GE(state.n, 2);
  EXPECT_EQ(state.order[0], 'A');
  EXPECT_EQ(state.order[1], 'B');
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request_a);
  gdefcore_request_destroy(request_b);
}

TEST(Offload, RunsOnThePoolAndResumesOnTheCreatingThread) {
  const uint8_t tenant[] = {'t'};
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  OffloadState state;
  memset(&state, 0, sizeof state);
  ASSERT_EQ(gdefcore_sched_create(NULL, 2, 0, &sched), GDEFCORE_OK);
  state.sched = sched;
  ASSERT_EQ(
      gdefcore_request_create(tenant, 1, 0, 0, NULL, &request), GDEFCORE_OK);
  ASSERT_EQ(
      gdefcore_sched_spawn(sched, request, OffloadBody, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(state.after, 1);
  EXPECT_EQ(state.ran, 1);
  EXPECT_EQ(state.rc, GDEFCORE_OK);
  EXPECT_EQ(state.status, 7);
  EXPECT_TRUE(pthread_equal(state.fiber_before, state.fiber_after));
  EXPECT_TRUE(pthread_equal(state.fiber_before, pthread_self()));
  EXPECT_FALSE(pthread_equal(state.pool_thread, state.fiber_before));
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
}

TEST(Offload, FullPoolReturnsBusyWithoutBlocking) {
  const uint8_t a[] = {'a'};
  const uint8_t b[] = {'b'};
  const uint8_t c[] = {'c'};
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request_a = NULL;
  GDEFCORE_Request * request_b = NULL;
  GDEFCORE_Request * request_c = NULL;
  BusyState state;
  state.sched = NULL;
  state.a_running.store(0);
  state.release.store(0);
  state.nope_ran = 0;
  state.c_rc = GDEFCORE_OK;
  state.creator = pthread_self();
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 1, &sched), GDEFCORE_OK);
  state.sched = sched;
  ASSERT_EQ(gdefcore_request_create(a, 1, 0, 0, NULL, &request_a), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_request_create(b, 1, 0, 0, NULL, &request_b), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_request_create(c, 1, 0, 0, NULL, &request_c), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request_a, BusyA, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request_b, BusyB, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request_c, BusyC, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(state.c_rc, GDEFCORE_ERR_BUSY);
  EXPECT_EQ(state.nope_ran, 0);
  EXPECT_TRUE(pthread_equal(state.creator, pthread_self()));
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request_a);
  gdefcore_request_destroy(request_b);
  gdefcore_request_destroy(request_c);
}

TEST(Deadline, WaitIsCancelledAtTheRequestBoundary) {
  const uint8_t tenant[] = {'d'};
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  DeadlineState state;
  uint64_t deadline = MonoMs() + 40;
  state.sched = NULL;
  state.until = deadline + 80;
  state.after = 0;
  state.slow_ran = 0;
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 0, &sched), GDEFCORE_OK);
  state.sched = sched;
  ASSERT_EQ(gdefcore_request_create(
                tenant, 1, deadline, 0, NULL, &request),
      GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request, DeadlineBody, &state),
      GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(state.after, 0);
  EXPECT_EQ(state.slow_ran, 1);
  EXPECT_EQ(gdefcore_request_status(request), GDEFCORE_ERR_LIMIT);
  EXPECT_EQ(gdefcore_request_fiber(request), nullptr);
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
}

TEST(Write, OtherWaitAbortsThePortWrite) {
  const char * tenant = "tenant-a";
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  GDEFSTOR_Store * store = NULL;
  uint8_t * got = NULL;
  size_t got_len = 0;
  WriteState state;
  memset(&state, 0, sizeof state);
  store = OpenStore();
  ASSERT_NE(store, nullptr);
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 0, &sched), GDEFCORE_OK);
  state.sched = sched;
  state.store = store;
  state.tenant = tenant;
  ASSERT_EQ(gdefcore_request_create((const uint8_t *)tenant, strlen(tenant), 0,
                0, NULL, &request),
      GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request, WriteBody, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(state.after, 1);
  EXPECT_EQ(state.rc, GDEFCORE_ERR_INVALID);
  EXPECT_EQ(state.offload_ran, 0);
  EXPECT_EQ(gdefcore_request_status(request), GDEFCORE_ERR_INVALID);
  EXPECT_EQ(gdefcore_request_write(request), nullptr);
  int found = 1;
  EXPECT_EQ(gdefstor_record_get(store, tenant, strlen(tenant), "core.test", 9,
                "h", 1, &found, &got, &got_len),
      GDEFSTOR_OK);
  EXPECT_EQ(found, 0);
  EXPECT_EQ(got, nullptr);
  {
    GDEFSTOR_Write * again = NULL;
    EXPECT_EQ(gdefstor_write_begin(
                  store, tenant, strlen(tenant), NULL, &again),
        GDEFSTOR_OK);
    gdefstor_write_abort(again);
  }
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
  gdefstor_store_destroy(store);
}

TEST(Write, YieldWhileHoldingAbortsThePortWrite) {
  const char * tenant = "tenant-y";
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  GDEFSTOR_Store * store = NULL;
  GDEFSTOR_Write * again = NULL;
  YieldState state;
  memset(&state, 0, sizeof state);
  store = OpenStore();
  ASSERT_NE(store, nullptr);
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 0, &sched), GDEFCORE_OK);
  state.sched = sched;
  state.store = store;
  state.tenant = tenant;
  ASSERT_EQ(gdefcore_request_create((const uint8_t *)tenant, strlen(tenant), 0,
                0, NULL, &request),
      GDEFCORE_OK);
  ASSERT_EQ(
      gdefcore_sched_spawn(sched, request, YieldApiBody, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(state.after, 1);
  EXPECT_EQ(state.rc, GDEFCORE_ERR_INVALID);
  EXPECT_EQ(gdefcore_request_status(request), GDEFCORE_ERR_INVALID);
  EXPECT_EQ(gdefcore_request_write(request), nullptr);
  EXPECT_EQ(gdefstor_write_begin(store, tenant, strlen(tenant), NULL, &again),
      GDEFSTOR_OK);
  gdefstor_write_abort(again);
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
  gdefstor_store_destroy(store);
}

TEST(Write, TurnAgainWhileHoldingAbortsThePortWrite) {
  const char * tenant = "tenant-t";
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  GDEFSTOR_Store * store = NULL;
  GDEFSTOR_Write * again = NULL;
  YieldState state;
  memset(&state, 0, sizeof state);
  store = OpenStore();
  ASSERT_NE(store, nullptr);
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 0, &sched), GDEFCORE_OK);
  state.sched = sched;
  state.store = store;
  state.tenant = tenant;
  ASSERT_EQ(gdefcore_request_create((const uint8_t *)tenant, strlen(tenant), 0,
                0, NULL, &request),
      GDEFCORE_OK);
  ASSERT_EQ(
      gdefcore_sched_spawn(sched, request, YieldTurnBody, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(gdefcore_request_status(request), GDEFCORE_ERR_INVALID);
  EXPECT_EQ(gdefcore_request_write(request), nullptr);
  EXPECT_EQ(gdefstor_write_begin(store, tenant, strlen(tenant), NULL, &again),
      GDEFSTOR_OK);
  gdefstor_write_abort(again);
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
  gdefstor_store_destroy(store);
}

TEST(Watchdog, ZeroBoundNamesNothing) {
  const uint8_t tenant[] = {'z'};
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  WatchState state;
  state.bound_ms = 40;
  state.start = MonoMs();
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 0, &sched), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_request_create(tenant, 1, 0, 0, NULL, &request),
      GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request, WatchBody, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(gdefcore_sched_watchdog_count(sched), 0u);
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
}

TEST(Watchdog, NamesAFiberThatRunsPastItsYieldBound) {
  const uint8_t tenant[] = {'w'};
  GDEFCORE_Sched * sched = NULL;
  GDEFCORE_Request * request = NULL;
  WatchState state;
  state.bound_ms = 120;
  state.start = MonoMs();
  ASSERT_EQ(gdefcore_sched_create(NULL, 1, 0, &sched), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_request_create(tenant, 1, 0, 30, NULL, &request),
      GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_spawn(sched, request, WatchBody, &state), GDEFCORE_OK);
  ASSERT_EQ(gdefcore_sched_run(sched), GDEFCORE_OK);
  EXPECT_EQ(gdefcore_sched_watchdog_count(sched), 1u);
  EXPECT_EQ(gdefcore_sched_watchdog_id_at(sched, 0), gdefcore_request_id(request));
  gdefcore_sched_destroy(sched);
  gdefcore_request_destroy(request);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
