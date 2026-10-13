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
 * The contexts-under-fibers gate (AD-25, AD-32). A runtime context is held by
 * one fiber at a time, and a template as deep as the language allows ends in a
 * limit error on the smallest fiber cutil will make, never in a fault.
 *
 * The deep-template cases run in a forked child, so that a fault is reported
 * as the failure of the test that caused it and not as a binary that died.
 * tools/check-contexts.sh plants each defect in a copy of the source and
 * requires the test named for it to fail.
 */

#include "../src/render/render_internal.h"

#include <ghoti.io/cutil/fiber.h>
#include <ghoti.io/defiant-core/defiant-core.h>
#include <ghoti.io/defiant-storage-memory/memory.h>
#include <ghoti.io/lang-tang/compile.h>
#include <ghoti.io/lang-tang/parse.h>

#include <gtest/gtest.h>

#include <stdint.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <string>

namespace {

/* ---- one fiber at a time ------------------------------------------------ */

GLTANG_Program * Compile(const char * source) {
  GLTANG_Tree * tree = NULL;
  GLTANG_Program * program = NULL;
  GLTANG_ParseError error;
  if (gltang_parse(source, GLTANG_PARSE_SCRIPT, &error, &tree) != GLTANG_OK) {
    return NULL;
  }
  if (gltang_compile(tree, "t.tang", &error, &program) != GLTANG_OK) {
    program = NULL;
  }
  gltang_tree_destroy(tree);
  return program;
}

struct Held {
  GDEFCORE_RenderCtx * ctx = NULL;
  GLTANG_Program * program = NULL;
  GLTANG_Library * library = NULL;
  /* Written by the fibers, read after they return. */
  GDEFCORE_Result opened = GDEFCORE_ERR_INTERNAL;
  GDEFCORE_Result holder_run = GDEFCORE_ERR_INTERNAL;
  GDEFCORE_Result other_run = GDEFCORE_ERR_INTERNAL;
  GDEFCORE_Result other_check = GDEFCORE_OK;
  std::string holder_out;
};

void HolderEntry(void * arg) {
  Held * held = (Held *)arg;
  char * bytes = NULL;
  size_t n = 0;
  held->opened = gdefcore_render_ctx_open(1000000, &held->ctx);
  if (held->opened != GDEFCORE_OK) {
    return;
  }
  /* The fiber suspends inside a host call and keeps its context. */
  gcu_fiber_yield();
  held->holder_run =
      gdefcore_render_ctx_run(held->ctx, held->program, held->library, &bytes, &n);
  if (held->holder_run == GDEFCORE_OK && bytes != NULL) {
    held->holder_out.assign(bytes, n);
  }
  gltang_buffer_free(bytes);
  gdefcore_render_ctx_close(held->ctx);
  held->ctx = NULL;
}

void TrespasserEntry(void * arg) {
  Held * held = (Held *)arg;
  char * bytes = NULL;
  size_t n = 0;
  held->other_check = gdefcore_render_ctx_check(held->ctx);
  held->other_run =
      gdefcore_render_ctx_run(held->ctx, held->program, held->library, &bytes, &n);
  gltang_buffer_free(bytes);
}

TEST(Contexts, OneFiberAtATime) {
  Held held;
  GCU_Fiber * holder = NULL;
  GCU_Fiber * other = NULL;
  held.program = Compile("print(\"held\");");
  ASSERT_NE(held.program, nullptr);
  ASSERT_EQ(GLTANG_OK, gltang_library_create(NULL, &held.library));
  ASSERT_EQ(GCU_FIBER_OK,
      gcu_fiber_create(&holder, HolderEntry, &held, GCU_FIBER_DEFAULT_STACK_SIZE,
          NULL));
  ASSERT_EQ(GCU_FIBER_OK,
      gcu_fiber_create(&other, TrespasserEntry, &held, GCU_FIBER_DEFAULT_STACK_SIZE,
          NULL));
  /* The holder opens the context and suspends. */
  ASSERT_EQ(GCU_FIBER_OK, gcu_fiber_switch_to(holder));
  ASSERT_EQ(GDEFCORE_OK, held.opened);
  ASSERT_NE(held.ctx, nullptr);
  EXPECT_EQ(0u, gdefcore_render_ctx_violations(held.ctx));
  /* Another fiber on the same thread reaches for it: refused, and counted. */
  ASSERT_EQ(GCU_FIBER_OK, gcu_fiber_switch_to(other));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, held.other_check);
  EXPECT_EQ(GDEFCORE_ERR_INVALID, held.other_run);
  EXPECT_EQ(2u, gdefcore_render_ctx_violations(held.ctx));
  /* So does the thread's own stack, which is no fiber at all. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_render_ctx_check(held.ctx));
  EXPECT_EQ(3u, gdefcore_render_ctx_violations(held.ctx));
  /* The control: the holder was never refused, and the refused run ran nothing. */
  ASSERT_EQ(GCU_FIBER_OK, gcu_fiber_switch_to(holder));
  EXPECT_EQ(GDEFCORE_OK, held.holder_run);
  EXPECT_EQ("held", held.holder_out);
  EXPECT_TRUE(gcu_fiber_is_finished(holder));
  gcu_fiber_destroy(other);
  gcu_fiber_destroy(holder);
  gltang_library_release(held.library);
  gltang_program_release(held.program);
}

struct Again {
  GDEFCORE_RenderCtx * ctx;
  GLTANG_Program * program;
  GLTANG_Library * library;
  GDEFCORE_Result nested;
};

bool NativeAgain(GLTANG_NativeCall * call, void * user) {
  Again * again = (Again *)user;
  char * bytes = NULL;
  size_t n = 0;
  again->nested =
      gdefcore_render_ctx_run(again->ctx, again->program, again->library, &bytes, &n);
  gltang_buffer_free(bytes);
  gltang_call_return_string(call, "", 0, GLTANG_UNICODE_STRING_TYPE_TRUSTED);
  return true;
}

TEST(Contexts, HeldContextIsNotReentered) {
  Again again;
  GDEFCORE_RenderCtx * ctx = NULL;
  GLTANG_Program * outer = Compile("use again;\nprint(again());\n");
  char * bytes = NULL;
  size_t n = 0;
  memset(&again, 0, sizeof again);
  again.nested = GDEFCORE_ERR_INTERNAL;
  ASSERT_NE(outer, nullptr);
  again.program = outer;
  ASSERT_EQ(GLTANG_OK, gltang_library_create(NULL, &again.library));
  ASSERT_EQ(GLTANG_OK,
      gltang_library_add_native(again.library, "again", NativeAgain, &again));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_render_ctx_open(1000000, &ctx));
  again.ctx = ctx;
  ASSERT_EQ(GDEFCORE_OK,
      gdefcore_render_ctx_run(ctx, outer, again.library, &bytes, &n));
  /* The same fiber, with the context held by a run: still refused. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, again.nested);
  EXPECT_EQ(1u, gdefcore_render_ctx_violations(ctx));
  gltang_buffer_free(bytes);
  gdefcore_render_ctx_close(ctx);
  gltang_library_release(again.library);
  gltang_program_release(outer);
}

/* ---- a deep template on the smallest fiber ------------------------------ */

#ifndef _WIN32

struct Case {
  std::string source;
  uint64_t fuel;
};

struct Done {
  GDEFCORE_Result rc;
  std::string out;
};

struct Job {
  Case c;
  Done done;
};

void RenderEntry(void * arg) {
  Job * job = (Job *)arg;
  GDEFSTOR_Store * store = NULL;
  GDEFCORE_Catalog * catalog = NULL;
  const uint8_t tenant[] = {'t'};
  char * bytes = NULL;
  size_t n = 0;
  job->done.rc = GDEFCORE_ERR_INTERNAL;
  if (gdefsmemory_store_create(NULL, NULL, &store) != GDEFSMEMORY_OK ||
      gdefcore_catalog_open(store, tenant, 1, NULL, NULL, &catalog) !=
          GDEFCORE_OK) {
    return;
  }
  job->done.rc = gdefcore_render_scope(
      catalog, job->c.source.data(), job->c.source.size(), job->c.fuel, &bytes, &n);
  if (job->done.rc == GDEFCORE_OK && bytes != NULL) {
    job->done.out.assign(bytes, n);
  }
  gdefcore_text_free(catalog, bytes);
  gdefcore_catalog_destroy(catalog);
  gdefstor_store_destroy(store);
}

/* Render @p c on a fiber of the smallest stack cutil allows. */
Done OnMinimumFiber(const Case & c) {
  Job job;
  GCU_Fiber * fiber = NULL;
  job.c = c;
  job.done.rc = GDEFCORE_ERR_INTERNAL;
  if (gcu_fiber_create(&fiber, RenderEntry, &job, GCU_FIBER_MIN_STACK_SIZE, NULL) ==
      GCU_FIBER_OK) {
    gcu_fiber_switch_to(fiber);
    gcu_fiber_destroy(fiber);
  }
  return job.done;
}

/* What a child process did. */
struct Verdict {
  bool exited;
  int code;
  int signal;
};

std::string Describe(const Verdict & v) {
  if (!v.exited) {
    return "killed by signal " + std::to_string(v.signal);
  }
  return "exited " + std::to_string(v.code);
}

/* The exit code the child reports: 0 when the render gave @p want_rc (and
 * @p want_out, when given), else 1 for another result. */
Verdict InChild(const Case & c, GDEFCORE_Result want_rc, const char * want_out) {
  Verdict v = {false, -1, 0};
  int status = 0;
  pid_t pid;
  fflush(NULL);
  pid = fork();
  if (pid < 0) {
    return v;
  }
  if (pid == 0) {
    Done done = OnMinimumFiber(c);
    int ok = done.rc == want_rc && (want_out == NULL || done.out == want_out);
    _exit(ok ? 0 : 1);
  }
  if (waitpid(pid, &status, 0) < 0) {
    return v;
  }
  if (WIFEXITED(status)) {
    v.exited = true;
    v.code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    v.signal = WTERMSIG(status);
  }
  return v;
}

std::string Nested(int depth) {
  std::string s = "<% ";
  for (int i = 0; i < depth; i++) {
    s += "if (true) { ";
  }
  s += "x = 1;";
  for (int i = 0; i < depth; i++) {
    s += " }";
  }
  return s + " %>OK";
}

std::string Chain(int terms) {
  std::string s = "<% x = 1";
  for (int i = 0; i < terms; i++) {
    s += "+1";
  }
  return s + "; %>OK";
}

std::string Recursion(long depth) {
  return "<% function f(k) { if (k == 0) { return 0; } return 1 + f(k - 1); } "
         "print(f(" + std::to_string(depth) + ")); %>OK";
}

/* The control for the harness itself: a child that overflows the same stack
 * must be reported as killed, or every "passes" below could be a child that
 * never ran. */
volatile char gSink;
volatile int gStop = 0;
int Overflow(int depth) {
  volatile char pad[512];
  if (gStop) {
    return 0;
  }
  pad[0] = (char)depth;
  gSink = pad[0];
  return Overflow(depth + 1) + pad[0];
}

void OverflowEntry(void *) { gSink = (char)Overflow(0); }

TEST(Contexts, HarnessSeesACrash) {
  Verdict v = {false, -1, 0};
  int status = 0;
  pid_t pid;
  fflush(NULL);
  pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    GCU_Fiber * fiber = NULL;
    if (gcu_fiber_create(&fiber, OverflowEntry, NULL, GCU_FIBER_MIN_STACK_SIZE,
            NULL) == GCU_FIBER_OK) {
      gcu_fiber_switch_to(fiber);
    }
    _exit(0);
  }
  ASSERT_EQ(pid, waitpid(pid, &status, 0));
  v.exited = WIFEXITED(status);
  v.signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
  EXPECT_FALSE(v.exited) << "the overflowing child exited";
  EXPECT_EQ(SIGSEGV, v.signal);
  /* And the opposite control: a child whose render gives the wanted result
   * exits 0, and one that gives another result does not. */
  v = InChild(Case{"<% x = 1; %>OK", 1000000}, GDEFCORE_OK, "OK");
  EXPECT_TRUE(v.exited && v.code == 0) << Describe(v);
  v = InChild(Case{"<% x = 1; %>OK", 1000000}, GDEFCORE_ERR_LIMIT, NULL);
  EXPECT_TRUE(v.exited && v.code == 1) << Describe(v);
}

TEST(Contexts, DeepNestOnMinimumFiber) {
  Verdict v;
  /* 1500 nested blocks faulted the process on the scheduler's own 256 KiB
   * fiber before the render ran on a stack of its own. */
  v = InChild(Case{Nested(1500), 1000000}, GDEFCORE_OK, "OK");
  EXPECT_TRUE(v.exited && v.code == 0) << "1500 nested blocks: " << Describe(v);
  /* Past the parser's nesting limit: a limit error, and no fault. */
  v = InChild(Case{Nested(5000), 1000000}, GDEFCORE_ERR_LIMIT, NULL);
  EXPECT_TRUE(v.exited && v.code == 0) << "5000 nested blocks: " << Describe(v);
  /* The deepest tree the parser admits compiles; one past it is a limit. */
  v = InChild(Case{Chain(9990), 1000000}, GDEFCORE_OK, "OK");
  EXPECT_TRUE(v.exited && v.code == 0) << "9990 terms: " << Describe(v);
  v = InChild(Case{Chain(10100), 1000000}, GDEFCORE_ERR_LIMIT, NULL);
  EXPECT_TRUE(v.exited && v.code == 0) << "10100 terms: " << Describe(v);
}

TEST(Contexts, DeepRecursionOnMinimumFiber) {
  Verdict v;
  /* The control: a recursion well inside the budget still renders. */
  v = InChild(Case{Recursion(100), 1000000000ull}, GDEFCORE_OK, "100OK");
  EXPECT_TRUE(v.exited && v.code == 0) << "depth 100: " << Describe(v);
  /* Past it, with fuel enough that fuel is not what stops the run: the
   * native-depth limit ends it with a limit error. */
  v = InChild(Case{Recursion(1000000), 1000000000ull}, GDEFCORE_ERR_LIMIT, NULL);
  EXPECT_TRUE(v.exited && v.code == 0) << "depth 1000000: " << Describe(v);
}

#else

TEST(Contexts, DeepNestOnMinimumFiber) {
  GTEST_SKIP() << "the deep-template cases run in a forked child";
}

TEST(Contexts, DeepRecursionOnMinimumFiber) {
  GTEST_SKIP() << "the deep-template cases run in a forked child";
}

#endif

}  // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
