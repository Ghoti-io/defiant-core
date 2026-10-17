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
 * @file module_internal.h
 *
 * Private to src/module. Another subsystem includes module.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_MODULE_MODULE_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_MODULE_MODULE_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/allocator.h>
#include <ghoti.io/defiant-core/module.h>

#include <stddef.h>
#include <stdint.h>

/*
 * The tables a manifest declares (routes, menu links, settings, template
 * variables, grants), as the host holds them. module.c owns the modules and their
 * order; decl.c owns what a table means: copying it, resolving a handler or a
 * provider through the module's services, validating a set of modules, and
 * handing out the records an enumeration reports.
 *
 * Every string is a NUL-terminated copy the Decl owns, so the public records
 * point into it and stay valid until the host is destroyed: a Decl that a
 * reload replaces is retired onto the host's list, not freed.
 */

/** A service of the declaring module, as the host copied it. */
typedef struct DeclSvc {
  const char * name;
  size_t name_len;
  uint32_t version;
  const void * table;
} DeclSvc;

/** Why a handler or provider service could not be resolved. */
enum {
  kDeclResolved = 0,
  kDeclNoName = 1,
  kDeclNoService = 2,
  kDeclBadVersion = 3,
  kDeclBadTable = 4
};

typedef struct DeclRoute {
  GDEFCORE_Module_Declared_Route pub;
  const char * handler;
  size_t handler_len;
  int resolved;
  size_t index;
} DeclRoute;

typedef struct DeclLink {
  GDEFCORE_Module_Declared_Link pub;
  size_t index;
} DeclLink;

typedef struct DeclSetting {
  GDEFCORE_Module_Declared_Setting pub;
  size_t index;
} DeclSetting;

typedef struct DeclVar {
  GDEFCORE_Module_Contributed pub;
  const char * provider;
  size_t provider_len;
  int resolved;
  size_t index;
} DeclVar;

typedef struct DeclGrant {
  GDEFCORE_Module_Declared_Grant pub;
  size_t index;
} DeclGrant;

typedef struct DeclRelation {
  GDEFCORE_Module_Declared_Relation pub;
  GDEFCORE_Module_Relation_Column cols[GDEFCORE_RELATION_COLUMNS_MAX];
  size_t index;
} DeclRelation;

typedef struct Decl Decl;

struct Decl {
  const GDEFCORE_Allocator * alloc;
  Decl * next;
  char module[65];
  size_t module_len;
  void ** blocks;
  size_t nblocks;
  size_t cap_blocks;
  DeclRoute * routes;
  size_t nroutes;
  DeclLink * links;
  size_t nlinks;
  DeclSetting * settings;
  size_t nsettings;
  DeclVar * vars;
  size_t nvars;
  DeclGrant * grants;
  size_t ngrants;
  DeclRelation * relations;
  size_t nrelations;
};

/** The declarations of the modules in force, already in module order. */
typedef struct DeclRef {
  const Decl * decl;
} DeclRef;

/**
 * Copy the tables of @p man (a manifest already read at the size the module
 * filled). @p out is NULL when the module declares nothing. A table past its
 * maximum, a NULL pointer with a count, or a string past 64 KiB is refused
 * with @p err set; no meaning is checked here.
 */
GDEFCORE_Result gdefcore_decl_build(const GDEFCORE_Allocator * alloc,
    const char * module, size_t module_len,
    const GDEFCORE_Module_Manifest * man, const DeclSvc * svcs, size_t nsvcs,
    Decl ** out, char * err, size_t cap);

/** Free a Decl and its strings. NULL is ignored. */
void gdefcore_decl_free(Decl * decl);

/**
 * Check a set of modules' declarations as one site: every name, every
 * reference between entries, every duplicate, and the routes as a route table
 * would take them. 0 when valid; otherwise 1 and @p err names the entry and
 * its module. With @p local, the references that leave a module (a tab's
 * parent, a link's route and parent) are not followed, because the enable
 * that stages one module cannot know what the rest of its changeset will
 * add or take away; apply checks the whole set.
 */
int gdefcore_decl_validate(const DeclRef * refs, size_t n, int local,
    char * err, size_t cap);

GDEFCORE_Result gdefcore_decl_routes(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Route *** out, size_t * count);
GDEFCORE_Result gdefcore_decl_links(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Link *** out, size_t * count);
GDEFCORE_Result gdefcore_decl_settings(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Setting *** out, size_t * count);
GDEFCORE_Result gdefcore_decl_variables(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n, const GDEFCORE_Module_Contributed *** out,
    size_t * count);
GDEFCORE_Result gdefcore_decl_grants(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Grant *** out, size_t * count);

GDEFCORE_Result gdefcore_decl_relations(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n,
    const GDEFCORE_Module_Declared_Relation *** out, size_t * count);

/**
 * Add the routes of @p refs to @p routes, a tab after its parent. On a refusal
 * @p out_error (when not NULL) holds the route table's own message, and
 * @p failed (when not NULL) the route it refused. With @p local, a tab whose
 * parent is not among @p refs, and what hangs from it, is left out.
 */
GDEFCORE_Result gdefcore_decl_add_routes(const GDEFCORE_Allocator * alloc,
    const DeclRef * refs, size_t n, GDEFCORE_Routes * routes, char ** out_error,
    size_t * out_error_len, const GDEFCORE_Module_Declared_Route ** failed,
    int local);

#endif /* GHOTI_IO_GDEFCORE_SRC_MODULE_MODULE_INTERNAL_H */
