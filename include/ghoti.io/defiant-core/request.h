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
 * @file request.h
 * @brief The explicit request handle. Nothing here reads a thread-local.
 * @stability free
 *
 * A request carries its tenant as caller-supplied bytes, its fiber, its
 * deadline and its yield bound, and a storage write when it holds one.
 * There is no current request, tenant or user on the thread or in a global.
 */

#ifndef GHOTI_IO_GDEFCORE_REQUEST_H
#define GHOTI_IO_GDEFCORE_REQUEST_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/cutil/fiber.h>
#include <ghoti.io/defiant-storage/store.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** An explicit request. Opaque. */
typedef struct GDEFCORE_Request GDEFCORE_Request;

/**
 * @brief Create a request.
 *
 * The tenant bytes are copied. @p deadline_ms is an absolute
 * `CLOCK_MONOTONIC` time in milliseconds; 0 means the request has no
 * deadline. @p yield_bound_ms is how long one turn may run without the
 * scheduler seeing a yield before the watchdog names the request; 0 means
 * no bound.
 *
 * @param tenant Tenant bytes. Required, non-empty. Not connection state.
 * @param tenant_len Length of @p tenant.
 * @param deadline_ms Absolute monotonic milliseconds, or 0.
 * @param yield_bound_ms Bound in milliseconds, or 0.
 * @param allocator NULL uses the default.
 * @param out_request Receives the request on success. Not written on failure.
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_create(
    const uint8_t * tenant, size_t tenant_len, uint64_t deadline_ms,
    uint64_t yield_bound_ms, const GDEFCORE_Allocator * allocator,
    GDEFCORE_Request ** out_request);

/**
 * @brief Free a request. NULL is ignored.
 *
 * A write still held is aborted. The fiber, if one is still attached, is
 * destroyed without being unwound; destroy it from the thread that created
 * it. The scheduler normally detaches the fiber before this is called.
 *
 * @param request The request, or NULL.
 */
GDEFCORE_API void gdefcore_request_destroy(GDEFCORE_Request * request);

/**
 * @brief The tenant bytes. They remain valid until the request is destroyed.
 *
 * @param request The request.
 * @param out_len Receives the length. May be NULL.
 * @return The bytes, or NULL when @p request is NULL.
 */
GDEFCORE_API const uint8_t * gdefcore_request_tenant(
    const GDEFCORE_Request * request, size_t * out_len);

/**
 * @brief The deadline passed to create, in absolute monotonic milliseconds.
 *
 * @param request The request. NULL is 0.
 * @return The deadline, or 0.
 */
GDEFCORE_API uint64_t gdefcore_request_deadline_ms(
    const GDEFCORE_Request * request);

/**
 * @brief The yield bound passed to create, in milliseconds.
 *
 * @param request The request. NULL is 0.
 * @return The bound, or 0.
 */
GDEFCORE_API uint64_t gdefcore_request_yield_bound_ms(
    const GDEFCORE_Request * request);

/**
 * @brief An id unique among requests created in this process. Never 0.
 *
 * The watchdog reports this id. It is not a tenant and not a thread id.
 *
 * @param request The request. NULL is 0.
 * @return The id.
 */
GDEFCORE_API uint64_t gdefcore_request_id(const GDEFCORE_Request * request);

/**
 * @brief How the request ended. ::GDEFCORE_OK until something records otherwise.
 *
 * @param request The request. NULL is ::GDEFCORE_ERR_INVALID.
 * @return The status.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_status(
    const GDEFCORE_Request * request);

/**
 * @brief Record a terminal status. The scheduler uses this when a deadline
 * ends the request.
 *
 * @param request The request. NULL is ignored.
 * @param status The status to store.
 */
GDEFCORE_API void gdefcore_request_set_status(
    GDEFCORE_Request * request, GDEFCORE_Result status);

/**
 * @brief The fiber the scheduler attached, or NULL.
 *
 * @param request The request.
 * @return The fiber. The caller does not destroy it.
 */
GDEFCORE_API GCU_Fiber * gdefcore_request_fiber(
    const GDEFCORE_Request * request);

/**
 * @brief Attach the fiber that will run this request, or NULL to detach.
 *
 * The scheduler calls this. The fiber stays on the thread that created it.
 *
 * @param request The request.
 * @param fiber The fiber, or NULL.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when @p request is NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_attach_fiber(
    GDEFCORE_Request * request, GCU_Fiber * fiber);

/**
 * @brief Record the storage write this request holds, or NULL to clear it.
 *
 * Clearing does not abort. Aborting is the scheduler's when a wait other
 * than the write is attempted, and destroy's when a write is still held.
 *
 * @param request The request.
 * @param write The port write, or NULL.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when @p request is NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_write(
    GDEFCORE_Request * request, GDEFSTOR_Write * write);

/**
 * @brief The write currently held, or NULL.
 *
 * @param request The request.
 * @return The write. The caller does not free it through this pointer except
 *   by abort or commit on the port.
 */
GDEFCORE_API GDEFSTOR_Write * gdefcore_request_write(
    const GDEFCORE_Request * request);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_REQUEST_H */
