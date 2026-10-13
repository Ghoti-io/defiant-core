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
 * The runtime context behind a template run, and the shadow owner that keeps
 * two fibers out of it (AD-32). The context is created, run and destroyed by
 * one fiber. A fiber that suspended while holding a context leaves it held;
 * another fiber reaching for it is a bug that the runtime cannot see, because
 * its owner check is per thread and both fibers are on one.
 */

#include <ghoti.io/defiant-core/macros.h>

#include "render_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/fiber.h>
#include <ghoti.io/lang-tang/execution.h>
#include <ghoti.io/lang-tang/value.h>
#include <ghoti.io/runtime-core/runtime-core.h>
#include <ghoti.io/runtime-heap/runtime-heap.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct GDEFCORE_RenderCtx {
  GRCORE_Group * group;
  GRCORE_Options * options;
  GRHEAP_Options * heap_options;
  GRCORE_Context * context;
  GRHEAP_Heap * heap;
  /* The shadow owner: the fiber that holds the context, and the thread it
   * runs on (a fiber never changes thread). NULL fiber is the thread's own
   * stack. */
  const GCU_Fiber * holder;
  pthread_t holder_thread;
  int running;
  uint64_t violations;
};

static int is_holder(const GDEFCORE_RenderCtx * ctx) {
  return ctx->holder == gcu_fiber_current() &&
      pthread_equal(ctx->holder_thread, pthread_self());
}

GDEFCORE_Result gdefcore_render_ctx_check(GDEFCORE_RenderCtx * ctx) {
  if (ctx == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!is_holder(ctx)) {
    ctx->violations += 1;
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

/* The runtime's depth budgets for a run on the side stack. */
static void set_depth_limits(GRCORE_Options * options) {
  grcore_options_set_native_stack_bytes(options, GDEFCORE_RENDER_NATIVE_STACK);
  grcore_options_set_guest_depth(options, GDEFCORE_RENDER_GUEST_DEPTH);
  grcore_options_set_native_depth(options, GDEFCORE_RENDER_NATIVE_DEPTH);
}

GDEFCORE_Result gdefcore_render_ctx_open(uint64_t fuel,
    GDEFCORE_RenderCtx ** out_ctx) {
  GDEFCORE_RenderCtx * ctx;
  if (out_ctx == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  ctx = (GDEFCORE_RenderCtx *)calloc(1, sizeof *ctx);
  if (ctx == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  ctx->holder = gcu_fiber_current();
  ctx->holder_thread = pthread_self();
  if (grcore_group_create(NULL, NULL, &ctx->group) != GRCORE_OK ||
      grcore_options_create(NULL, &ctx->options) != GRCORE_OK ||
      grheap_options_create(NULL, &ctx->heap_options) != GRHEAP_OK) {
    gdefcore_render_ctx_close(ctx);
    return GDEFCORE_ERR_OOM;
  }
  grcore_options_set_fuel(ctx->options, fuel);
  set_depth_limits(ctx->options);
  if (gltang_heap_options_configure(ctx->heap_options) != GLTANG_OK ||
      gdefcore_render_ctx_check(ctx) != GDEFCORE_OK ||
      grcore_context_create(ctx->group, ctx->options, &ctx->context) !=
          GRCORE_OK ||
      gdefcore_render_ctx_check(ctx) != GDEFCORE_OK ||
      grheap_heap_create(ctx->context, ctx->heap_options, &ctx->heap) !=
          GRHEAP_OK) {
    gdefcore_render_ctx_close(ctx);
    return GDEFCORE_ERR_OOM;
  }
  *out_ctx = ctx;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_render_ctx_run(GDEFCORE_RenderCtx * ctx,
    GLTANG_Program * wrap, GLTANG_Library * library, char ** out_bytes,
    size_t * out_len) {
  GLTANG_Execution * execution = NULL;
  GRCORE_Outcome outcome = GRCORE_OUTCOME_FINISHED;
  GDEFCORE_Result rc = GDEFCORE_OK;
  size_t i;
  if (ctx == NULL || wrap == NULL || library == NULL || out_bytes == NULL ||
      out_len == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_render_ctx_check(ctx) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  /* A held context is never re-entered; a nested call checks out another. */
  if (ctx->running) {
    ctx->violations += 1;
    return GDEFCORE_ERR_INVALID;
  }
  ctx->running = 1;
  if (gltang_execution_create(ctx->context, wrap, &execution) != GLTANG_OK ||
      gltang_execution_set_libraries(execution, library) != GLTANG_OK ||
      gltang_execution_set_log_all_errors(execution, true) != GLTANG_OK) {
    rc = GDEFCORE_ERR_OOM;
    goto done;
  }
  if (gdefcore_render_ctx_check(ctx) != GDEFCORE_OK) {
    rc = GDEFCORE_ERR_INVALID;
    goto done;
  }
  if (grcore_run(ctx->context, gltang_execution_entry, execution, &outcome) !=
          GRCORE_OK ||
      outcome != GRCORE_OUTCOME_FINISHED) {
    rc = GDEFCORE_ERR_LIMIT;
    goto done;
  }
  /* A call past the guest-depth budget is an error value, and the program
   * carries on. For a page that is a failed render, and the limit's name. */
  for (i = 0; i < gltang_execution_error_count(execution); i++) {
    GLTANG_ErrorEntry entry;
    if (gltang_execution_error(execution, i, &entry) &&
        entry.kind == GLTANG_ERROR_RECURSION_LIMIT) {
      rc = GDEFCORE_ERR_LIMIT;
      goto done;
    }
  }
  if (gltang_execution_output_render(execution, out_bytes, out_len) !=
      GLTANG_OK) {
    rc = GDEFCORE_ERR_OOM;
  }
done:
  /* The execution lives as long as the context, which allows one. */
  ctx->running = 0;
  return rc;
}

uint64_t gdefcore_render_ctx_violations(const GDEFCORE_RenderCtx * ctx) {
  return ctx == NULL ? 0 : ctx->violations;
}

void gdefcore_render_ctx_close(GDEFCORE_RenderCtx * ctx) {
  if (ctx == NULL) {
    return;
  }
  if (ctx->context != NULL) {
    (void)gdefcore_render_ctx_check(ctx);
    grcore_context_destroy(ctx->context);
  }
  if (ctx->heap_options != NULL) {
    grheap_options_destroy(ctx->heap_options);
  }
  if (ctx->options != NULL) {
    grcore_options_destroy(ctx->options);
  }
  if (ctx->group != NULL) {
    grcore_group_destroy(ctx->group);
  }
  free(ctx);
}
