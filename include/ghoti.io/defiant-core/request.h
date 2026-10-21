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
 * deadline and its yield bound, a storage write when it holds one, and an
 * optional principal and acting principal. No principal is the anonymous
 * state. There is no current request, tenant or user on the thread or in
 * a global.
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
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID when @p request is NULL
 *   or it already has a fiber and @p fiber is not NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_attach_fiber(
    GDEFCORE_Request * request, GCU_Fiber * fiber);

/**
 * @brief Record the storage write this request holds, or NULL to clear it.
 *
 * A different pointer aborts the write already held, including a clear.
 * Destroy aborts a write that is still held.
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

/**
 * @brief Set the principal, or clear it.
 *
 * NULL or a zero length clears the principal, which is the anonymous state.
 * A public id is stored in canonical form. A bad id leaves the previous
 * value in place.
 *
 * @return ::GDEFCORE_OK, ::GDEFCORE_ERR_INVALID, or ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_principal(
    GDEFCORE_Request * request, const char * id, size_t id_len);

/**
 * @brief The principal, or NULL when the request is anonymous.
 *
 * The bytes stay valid until the next set or until the request is destroyed.
 *
 * @param out_len Receives the length. May be NULL.
 */
GDEFCORE_API const char * gdefcore_request_principal(
    const GDEFCORE_Request * request, size_t * out_len);

/**
 * @brief Set the acting principal, or clear it. Same rules as the principal.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_acting_principal(
    GDEFCORE_Request * request, const char * id, size_t id_len);

/**
 * @brief The acting principal, or NULL when there is none.
 *
 * @param out_len Receives the length. May be NULL.
 */
GDEFCORE_API const char * gdefcore_request_acting_principal(
    const GDEFCORE_Request * request, size_t * out_len);

/**
 * @brief Set a named note, or replace one with the same name.
 *
 * The bytes are copied. A later handler reads them with
 * gdefcore_request_note(). NULL @p name is ::GDEFCORE_ERR_INVALID and the
 * previous notes stay.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_note(
    GDEFCORE_Request * request, const char * name, size_t name_len,
    const char * value, size_t value_len);

/**
 * @brief The note named @p name, or NULL when there is none.
 *
 * The bytes stay valid until the next set of that name or until the request
 * is destroyed.
 */
GDEFCORE_API const char * gdefcore_request_note(const GDEFCORE_Request * request,
    const char * name, size_t name_len, size_t * out_len);

/**
 * @brief Set the resolution and own the request.
 *
 * NULL or a zero length clears it, which is not ownership. The bytes are
 * copied and are not required to be a public id.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_resolution(
    GDEFCORE_Request * request, const char * text, size_t text_len);

/**
 * @brief The resolution, or NULL when the request is not owned.
 *
 * @param out_len Receives the length. May be NULL.
 */
GDEFCORE_API const char * gdefcore_request_resolution(
    const GDEFCORE_Request * request, size_t * out_len);

/**
 * @brief Record that what this request renders depends on its principal.
 *
 * Whether the principal belongs in the render key (AD-30) is observed while
 * rendering, never declared. A template that evaluates a contributed
 * variable that is not `principal_free` calls this. The mark stays until the
 * request is destroyed. NULL is ignored.
 */
GDEFCORE_API void gdefcore_request_mark_principal_dependent(
    GDEFCORE_Request * request);

/**
 * @brief Whether rendering this request has observed a dependence on the
 * principal. gdefcore_access_render_key() reads this.
 *
 * @return 1 when marked, 0 when not or when @p request is NULL.
 */
GDEFCORE_API int gdefcore_request_principal_dependent(
    const GDEFCORE_Request * request);

/**
 * @brief Fix the request's clock: seconds since the epoch.
 *
 * Optional. A condition that reads `now` (see condition.h) reads this value,
 * so a test or a host that wants a repeatable answer sets it. Setting it
 * again replaces the value.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_time(
    GDEFCORE_Request * request, int64_t seconds);

/**
 * @brief The request's time in seconds since the epoch.
 *
 * Fixed for the life of the request: the value from
 * gdefcore_request_set_time(), or, when none was set, the wall clock read
 * once at the first call and kept. A NULL request reads 0.
 */
GDEFCORE_API int64_t gdefcore_request_time(GDEFCORE_Request * request);

/** Most decisions the request's memo holds before it starts over. */
#define GDEFCORE_REQUEST_MEMO_MAX 256
/** Most (entity, revision) pairs a request records as read. */
#define GDEFCORE_REQUEST_READS_MAX 256

/**
 * @brief The answer remembered under @p key, if there is one.
 *
 * The request carries a small memo of decisions (gdefcore_access_can() keeps
 * its answers here), so that a question asked twice in one request is
 * answered once. The memo is the request's and nobody else's: no ambient
 * state. It holds at most ::GDEFCORE_REQUEST_MEMO_MAX answers; the one after
 * that discards them all and starts again, so memory is bounded and an answer
 * is never wrong, only asked for again.
 *
 * @return 1 and @p out_value set on a hit, else 0.
 */
GDEFCORE_API int gdefcore_request_memo_get(GDEFCORE_Request * request,
    const char * key, size_t key_len, int * out_value);

/** @brief Remember @p value under @p key. A key already there is replaced. */
GDEFCORE_API GDEFCORE_Result gdefcore_request_memo_put(
    GDEFCORE_Request * request, const char * key, size_t key_len, int value);

/**
 * @brief What the memo holds and has done: entries now, hits, and the times it
 * started over. Any out pointer may be NULL.
 */
GDEFCORE_API void gdefcore_request_memo_stats(const GDEFCORE_Request * request,
    size_t * out_entries, uint64_t * out_hits, uint64_t * out_restarts);

/**
 * @brief Record that what this request rendered or decided read @p id at
 * revision @p revision.
 *
 * This is the read set: gdefcore_access_render_key() puts it in the key when
 * there is one, so a fragment that depended on an entity's state is a
 * different fragment when the entity has changed. A pair already recorded is
 * not recorded twice. At most ::GDEFCORE_REQUEST_READS_MAX pairs are kept;
 * past that the set is marked overflowed, and the key says so.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_record_dependency(
    GDEFCORE_Request * request, const char * id, size_t id_len,
    uint64_t revision);

/** @brief How many (entity, revision) pairs the request has recorded. */
GDEFCORE_API size_t gdefcore_request_dependency_count(const GDEFCORE_Request * request);

/**
 * @brief One recorded pair, in the order recorded. @p out_id is borrowed and
 * not NUL-terminated. Returns 1, or 0 for an index past the end.
 */
GDEFCORE_API int gdefcore_request_dependency_at(const GDEFCORE_Request * request,
    size_t index, const char ** out_id, size_t * out_id_len,
    uint64_t * out_revision);

/** @brief Whether more pairs were read than the set keeps. */
GDEFCORE_API int gdefcore_request_dependencies_overflowed(
    const GDEFCORE_Request * request);

/** Most subjects a request records as decrypted (story S7). */
#define GDEFCORE_REQUEST_SUBJECTS_MAX 256

/**
 * @brief Record that what this request read or rendered decrypted a personal
 * value of @p subject (AD-19, story S7).
 *
 * The read path calls this for every value it opens, after the access filter
 * allowed its field. A fragment cached from the request depends on each
 * subject recorded (gdefcore_fragment_put()), so erasing one purges it. A
 * subject already recorded is not recorded twice. At most
 * ::GDEFCORE_REQUEST_SUBJECTS_MAX are kept; past that the set is marked
 * overflowed, and a fragment of the request is not cached. A value of an
 * erased subject is not a dependency: it reads ::GDEFCORE_SUBJECT_ERASED
 * whatever happens next.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_record_subject(
    GDEFCORE_Request * request, const char * subject, size_t subject_len);

/** @brief How many subjects the request has recorded as decrypted. */
GDEFCORE_API size_t gdefcore_request_subject_count(
    const GDEFCORE_Request * request);

/**
 * @brief One recorded subject, in the order recorded. @p out_subject is
 * borrowed and not NUL-terminated by contract. Returns 1, or 0 for an index
 * past the end.
 */
GDEFCORE_API int gdefcore_request_subject_at(const GDEFCORE_Request * request,
    size_t index, const char ** out_subject, size_t * out_len);

/** @brief Whether more subjects were decrypted than the set keeps. */
GDEFCORE_API int gdefcore_request_subjects_overflowed(
    const GDEFCORE_Request * request);

/** Most validity lines a request keeps (story A6). */
#define GDEFCORE_REQUEST_VALIDITY_MAX 64
/** Most entities the request keeps as the next batch (story A6). */
#define GDEFCORE_REQUEST_BATCH_MAX 200

/**
 * @brief Record what an access callback the request consulted says of a
 * cached render (module.h, story A6): one line naming the callback and its
 * validity, a token or a time window. gdefcore_access_render_key() carries
 * every line, so a changed token is a changed key. A line already recorded is
 * not recorded twice; past ::GDEFCORE_REQUEST_VALIDITY_MAX the request is
 * uncacheable. A line holds no control character.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_record_validity(
    GDEFCORE_Request * request, const char * line, size_t len);

/** @brief How many validity lines the request has recorded. */
GDEFCORE_API size_t gdefcore_request_validity_count(
    const GDEFCORE_Request * request);

/**
 * @brief One recorded validity line, in the order recorded, borrowed. Returns
 * 1, or 0 for an index past the end.
 */
GDEFCORE_API int gdefcore_request_validity_at(const GDEFCORE_Request * request,
    size_t index, const char ** out_line, size_t * out_len);

/**
 * @brief Mark that what this request renders must not be cached: it consulted
 * an access callback that declares no cacheability, or one that failed. The
 * mark stays until the request is destroyed. NULL is ignored.
 */
GDEFCORE_API void gdefcore_request_mark_uncacheable(GDEFCORE_Request * request);

/**
 * @brief Whether a fragment rendered for this request may be cached
 * (gdefcore_fragment_put() refuses one that may not). 0 for NULL.
 */
GDEFCORE_API int gdefcore_request_cacheable(const GDEFCORE_Request * request);

/**
 * @brief Keep the entities of a page the request listed as the next batch
 * (story A6): an access callback asked about one of them is asked about all
 * of them in one call. The list keeps its page here (gdefcore_access_list());
 * a caller that reads entities it did not list may set them. Replaces the
 * batch; at most ::GDEFCORE_REQUEST_BATCH_MAX are kept, and an id that is not
 * one is skipped. Changing the principal or the acting principal empties it.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_batch(
    GDEFCORE_Request * request, const char * type, size_t type_len,
    const char * const * ids, size_t count);

/** @brief The batch's size, and its type (borrowed; may be NULL). */
GDEFCORE_API size_t gdefcore_request_batch(const GDEFCORE_Request * request,
    const char ** out_type, size_t * out_type_len);

/** @brief The @p index th entity of the batch, canonical, or NULL. */
GDEFCORE_API const char * gdefcore_request_batch_at(
    const GDEFCORE_Request * request, size_t index);

/**
 * @brief Give the request a budget of fuel, in units. Replaces any budget.
 *
 * A request has none until this is called, and then spends nothing it cannot
 * be refused. Access spends it (gdefcore_access_can() documents the price).
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_set_fuel(
    GDEFCORE_Request * request, uint64_t units);

/**
 * @brief Spend @p units. With no budget set, always succeeds.
 *
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_LIMIT when the budget is less than
 *   @p units, in which case the budget is left empty and every later spend is
 *   refused until a new budget is set.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_request_spend_fuel(
    GDEFCORE_Request * request, uint64_t units);

/** @brief The fuel left; UINT64_MAX when no budget was set. */
GDEFCORE_API uint64_t gdefcore_request_fuel_left(const GDEFCORE_Request * request);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_REQUEST_H */
