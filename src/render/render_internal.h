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
 * @file render_internal.h
 *
 * Private to src/render. Another subsystem includes render.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_RENDER_RENDER_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_RENDER_RENDER_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/render.h>
#include <ghoti.io/defiant-core/asset.h>

#include <ghoti.io/lang-tang/execution.h>
#include <ghoti.io/lang-tang/library.h>
#include <ghoti.io/lang-tang/program.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Runtime contexts under fibers (AD-32).
 *
 * A template is parsed, compiled and run on a stack of this library's own, not
 * on whatever stack the caller has. A request's fiber may be as small as
 * GCU_FIBER_MIN_STACK_SIZE, and lang-tang recurses on the native stack once per
 * level of a tree (parse limit GLTANG_MAX_TREE_DEPTH, 10000) and, in compiled
 * code, once per guest call. Measured: 1500 nested `if` blocks faulted the
 * process on the scheduler's 256 KiB fiber; 9990 levels of `[` needed between
 * 1 and 2 MiB. The side stack is twice the larger figure.
 */
#define GDEFCORE_RENDER_SIDE_STACK ((size_t)4194304)

/*
 * The runtime's three depth budgets for a run on that stack. The native stack
 * budget is how far compiled code may grow it (runtime-core AD-28); it leaves
 * the rest of the side stack to the helpers compiled code calls. The guest
 * depth ends a recursive template with the recursion-limit error; the native
 * depth bounds nested native activations.
 */
#define GDEFCORE_RENDER_NATIVE_STACK ((uint64_t)1048576)
#define GDEFCORE_RENDER_GUEST_DEPTH ((uint64_t)1024)
#define GDEFCORE_RENDER_NATIVE_DEPTH ((uint64_t)256)

/**
 * A runtime context and the one fiber that holds it.
 *
 * The context is held by one fiber from open until close. Every call that
 * takes the context first asks whether the calling fiber is the holder, and a
 * call from any other fiber is refused with GDEFCORE_ERR_INVALID and counted.
 * Nothing about the runtime's own thread check helps here: two fibers share a
 * thread, so the runtime sees one owner.
 */
typedef struct GDEFCORE_RenderCtx GDEFCORE_RenderCtx;

/** Open a context held by the calling fiber, with ceiling @p fuel. */
GDEFCORE_Result gdefcore_render_ctx_open(uint64_t fuel,
    GDEFCORE_RenderCtx ** out_ctx);

/** GDEFCORE_OK for the holder, GDEFCORE_ERR_INVALID (and a count) otherwise. */
GDEFCORE_Result gdefcore_render_ctx_check(GDEFCORE_RenderCtx * ctx);

/**
 * Run @p wrap with @p library on the context and render its output. Refused
 * from a fiber that is not the holder, and while a run is already open on the
 * context. GDEFCORE_ERR_LIMIT when the run did not finish or a call went past
 * the guest-depth budget. @p out_bytes is freed with gltang_buffer_free().
 */
GDEFCORE_Result gdefcore_render_ctx_run(GDEFCORE_RenderCtx * ctx,
    GLTANG_Program * wrap, GLTANG_Library * library, char ** out_bytes,
    size_t * out_len);

/** Calls refused because the caller was not the holder, or a run was open. */
uint64_t gdefcore_render_ctx_violations(const GDEFCORE_RenderCtx * ctx);

/** Destroy the context. NULL is ignored. */
void gdefcore_render_ctx_close(GDEFCORE_RenderCtx * ctx);

/*
 * Shared between render.c and layout.c, which are one subsystem.
 */

/** The id of the published entity of @p type whose `name` is @p name. */
GDEFCORE_Result gdefcore_render_find_named(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]);

/** The site's own file called @p name (siteasset.h), as @p projection would leave
 * the site, with its text copied into @p out (release it with
 * gdefcore_asset_release()). ::GDEFCORE_ERR_INVALID when there is none. */
GDEFCORE_Result gdefcore_siteasset_lookup(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * name, size_t name_len,
    GDEFCORE_Asset * out);

/** The regions a page template's source declares (render.h). */
void gdefcore_render_scan_regions(const char * body, size_t n, char *** out_names,
    size_t * out_count, GDEFCORE_Catalog * catalog, GDEFCORE_Result * rc);

/**
 * Split a placement, `region widget [target] [~key=value ...]`. Single spaces
 * only; the target holds none and does not start with `~`; the `~` parts are
 * read by gdefcore_render_pane_extras(). Returns 0 for anything else.
 */
int gdefcore_render_split_pane(const char * s, size_t n, const char ** region,
    size_t * region_len, const char ** widget, size_t * widget_len,
    const char ** target, size_t * target_len);

/** One value of @p field as a NUL-terminated copy made with malloc, empty when
 * there is none; read as @p cs would leave it (view @p view). */
GDEFCORE_Result gdefcore_render_field_text(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * cs, int view, const char * id, const char * field,
    char ** out, size_t * out_len);

/** The page template that generated the site file @p name, as @p projection would
 * leave it, in @p tag; 1 when the file exists (the tag is empty for one the site
 * wrote), 0 when there is none. */
int gdefcore_siteasset_generated_by(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, const char * name, size_t name_len,
    char tag[128 + 1]);

/** Stage a stylesheet that a page template's structure generates. With @p text
 * NULL only the tag changes: @p tag NULL takes it away (the file is the site's
 * then). A file the site wrote is taken only when @p adopt. */
GDEFCORE_Result gdefcore_siteasset_stage_generated(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const char * text, size_t text_len,
    const char * tag, size_t tag_len, int adopt);

/** Stage the removal of a generated stylesheet. */
GDEFCORE_Result gdefcore_siteasset_stage_forget_generated(
    GDEFCORE_Changeset * changeset, const char * name, size_t name_len);

/** Write the default shared region descriptors a new site starts with
 * (region.h), leaving any a site has made. */
GDEFCORE_Result gdefcore_render_region_seed(GDEFCORE_Catalog * catalog);

/** Percent-encode @p n bytes into @p out (three bytes of room for each), so that the
 * text holds no space, no `%` and no `~`; the length written. */
size_t gdefcore_render_escape(const char * s, size_t n, char * out);

/** Decode the percent-escapes of @p n bytes into @p out (@p cap with the NUL).
 * The length, or -1 for a bad escape or a value that does not fit. */
long gdefcore_render_unescape(const char * s, size_t n, char * out, size_t cap);

/** Limits on what a placement says beyond region, widget and target. */
#define GDEFCORE_PANE_TITLE_MAX 128
#define GDEFCORE_PANE_PATH_MAX 128
#define GDEFCORE_PANE_TYPE_MAX 96
#define GDEFCORE_PANE_ROLE_MAX 64
#define GDEFCORE_PANE_ROLES_MAX 8

/** A placement's title and visibility, decoded (placement.c). */
typedef struct GdefPane {
  char title[GDEFCORE_PANE_TITLE_MAX + 1];
  size_t title_len;
  char path[GDEFCORE_PANE_PATH_MAX + 1];
  size_t path_len;
  char type[GDEFCORE_PANE_TYPE_MAX + 1];
  size_t type_len;
  char roles[GDEFCORE_PANE_ROLES_MAX][GDEFCORE_PANE_ROLE_MAX + 1];
  size_t nroles;
} GdefPane;

/**
 * Read the \`~key=value\` parts of a placement line. 1 when every one is well
 * formed; 0 otherwise, with a sentence in @p why.
 */
int gdefcore_render_pane_extras(const char * s, size_t n, GdefPane * out, char * why,
    size_t cap);

/** Whether the placement shows for this request on the page at @p path. */
int gdefcore_render_pane_visible(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * path, size_t path_len,
    const GdefPane * p);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SRC_RENDER_RENDER_INTERNAL_H */
