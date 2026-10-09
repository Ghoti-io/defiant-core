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
 * @file sched.h
 * @brief Which fiber runs next, fairness between tenants, and budgets.
 * @stability free
 *
 * cutil keeps the fibers, the event loop and the thread pool. This scheduler
 * decides the order. Fairness is round-robin across distinct tenant spans.
 * A body that returns ::GDEFCORE_TURN_AGAIN has not called yield; the
 * scheduler still runs another tenant before that body continues. A body
 * that runs past its yield bound inside one turn is named by the watchdog
 * and is not preempted. A fiber stays on the thread that created it.
 *
 * Create, spawn, run and destroy all happen on that one thread.
 */

#ifndef GHOTI_IO_GDEFCORE_SCHED_H
#define GHOTI_IO_GDEFCORE_SCHED_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The scheduler, the offload pool and the yield watchdog. Opaque. */
typedef struct GDEFCORE_Sched GDEFCORE_Sched;

/**
 * @brief What a request body returns at the end of one turn.
 *
 * ::GDEFCORE_TURN_AGAIN means the body has more work and did not call
 * gdefcore_sched_yield. The scheduler runs another ready tenant before
 * calling the body again. A body that still holds a write does not get
 * that turn: the write is aborted, the status is ::GDEFCORE_ERR_INVALID,
 * and the body is not called again.
 */
typedef enum GDEFCORE_Turn {
  GDEFCORE_TURN_DONE = 0, ///< The request body is finished.
  GDEFCORE_TURN_AGAIN     ///< Another turn, without an explicit yield.
} GDEFCORE_Turn;

/**
 * @brief The function a request runs, on its fiber.
 *
 * @param request The request this turn belongs to.
 * @param user The pointer given to gdefcore_sched_spawn().
 * @return Whether the body is finished.
 */
typedef GDEFCORE_Turn (*GDEFCORE_Request_Fn)(
    GDEFCORE_Request * request, void * user);

/**
 * @brief A blocking call that must not run on the fiber's thread.
 *
 * @param user The pointer given to gdefcore_sched_offload().
 * @return A status the fiber reads after it resumes. 0 is the usual success.
 */
typedef int (*GDEFCORE_Offload_Fn)(void * user);

/**
 * @brief Create a scheduler on the calling thread.
 *
 * @param allocator NULL uses the default. It must outlive the scheduler.
 * @param pool_threads Worker threads in the offload pool. 0 means one.
 * @param pool_max_queued How many tasks may wait. 0 means no limit. When the
 *   queue is full, gdefcore_sched_offload() returns ::GDEFCORE_ERR_BUSY and
 *   does not block.
 * @param out_sched Receives the scheduler on success.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_OOM,
 *   ::GDEFCORE_ERR_UNSUPPORTED, or ::GDEFCORE_ERR_INTERNAL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_sched_create(
    const GDEFCORE_Allocator * allocator, size_t pool_threads,
    size_t pool_max_queued, GDEFCORE_Sched ** out_sched);

/**
 * @brief Stop the watchdog, drain the pool, and free the scheduler.
 *
 * NULL is ignored. A fiber still suspended is destroyed without being
 * unwound. Call this on the thread that created the scheduler, after
 * gdefcore_sched_run() has returned.
 *
 * @param sched The scheduler, or NULL.
 */
GDEFCORE_API void gdefcore_sched_destroy(GDEFCORE_Sched * sched);

/**
 * @brief Create the request's fiber on this thread and queue it.
 *
 * The fiber does not run until gdefcore_sched_run(). Its stack is
 * ::GCU_FIBER_DEFAULT_STACK_SIZE.
 *
 * @param sched The scheduler.
 * @param request The request. Its tenant is the fairness key.
 * @param fn The body. Required.
 * @param user Passed to @p fn. May be NULL.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, ::GDEFCORE_ERR_OOM,
 *   or ::GDEFCORE_ERR_UNSUPPORTED.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_sched_spawn(GDEFCORE_Sched * sched,
    GDEFCORE_Request * request, GDEFCORE_Request_Fn fn, void * user);

/**
 * @brief Run ready fibers until none are waiting on an offload that should
 * resume.
 *
 * A fiber whose deadline passes while it waits is not resumed. Its status
 * becomes ::GDEFCORE_ERR_LIMIT and it is destroyed at that boundary.
 *
 * @param sched The scheduler.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_sched_run(GDEFCORE_Sched * sched);

/**
 * @brief Suspend the running fiber so another tenant can run.
 *
 * If the request holds a storage write, the write is aborted, nothing it
 * put is committed, the request status is ::GDEFCORE_ERR_INVALID, and this
 * returns ::GDEFCORE_ERR_INVALID without suspending.
 *
 * @param sched The scheduler the fiber was spawned on.
 * @return ::GDEFCORE_OK once resumed, ::GDEFCORE_ERR_INVALID when the call
 *   is not on that fiber or the write was aborted.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_sched_yield(GDEFCORE_Sched * sched);

/**
 * @brief Run @p fn on the offload pool and resume this fiber on the thread
 * that created it.
 *
 * The pool runs @p fn. The fiber does not. When the queue is full the
 * result is ::GDEFCORE_ERR_BUSY and @p fn is not started. When the request
 * holds a storage write, the write is aborted and the result is
 * ::GDEFCORE_ERR_INVALID, and @p fn is not started. When the deadline passes
 * while the fiber waits, the fiber is not resumed and its status is
 * ::GDEFCORE_ERR_LIMIT.
 *
 * @param sched The scheduler.
 * @param fn The blocking call. Required.
 * @param user Passed to @p fn.
 * @param out_status Receives @p fn's return. May be NULL. Not written on
 *   failure.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_BUSY, ::GDEFCORE_ERR_INVALID,
 *   or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_sched_offload(GDEFCORE_Sched * sched,
    GDEFCORE_Offload_Fn fn, void * user, int * out_status);

/**
 * @brief How many distinct over-bound turns the watchdog has named.
 *
 * @param sched The scheduler. NULL is 0.
 * @return The count.
 */
GDEFCORE_API size_t gdefcore_sched_watchdog_count(
    const GDEFCORE_Sched * sched);

/**
 * @brief The request id named at @p index, in the order they were named.
 *
 * @param sched The scheduler.
 * @param index An index below gdefcore_sched_watchdog_count().
 * @return The id, or 0 when the index is out of range.
 */
GDEFCORE_API uint64_t gdefcore_sched_watchdog_id_at(
    const GDEFCORE_Sched * sched, size_t index);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SCHED_H */
