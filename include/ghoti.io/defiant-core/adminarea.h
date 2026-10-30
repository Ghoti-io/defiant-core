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
 * @file adminarea.h
 * @brief The permissions of the admin area, and the first administrator's
 * grants.
 * @stability free
 *
 * Every page of the admin area is gated by a permission, and the route's own
 * check (gdefcore_access_route_check()) is the only authorization there is:
 * a session proves who someone is, and the role named `admin` proves nothing.
 * The pages that already meant a permission use it (templates, menus, layouts,
 * settings). The rest have one declared here:
 *
 * | Permission                | Action             | Governs                          |
 * |---------------------------|--------------------|----------------------------------|
 * | ::GDEFCORE_ADMIN_USE_LABEL    | ::GDEFCORE_ADMIN_USE    | the admin home and the More screen |
 * | ::GDEFCORE_POST_WRITE_LABEL   | ::GDEFCORE_POST_WRITE   | writing a post, and undoing one  |
 * | ::GDEFCORE_ADMIN_UNDO_LABEL   | ::GDEFCORE_ADMIN_UNDO   | the undo page                    |
 * | ::GDEFCORE_ROLE_REVERT_LABEL  | ::GDEFCORE_ROLE_REVERT  | undoing a change to a role       |
 * | ::GDEFCORE_ACCESS_READ_LABEL  | ::GDEFCORE_ACCESS_READ  | the matrix of what is granted    |
 *
 * Each is granted to nobody until something grants it
 * (gdefcore_admin_seed() is the first administrator's).
 */

#ifndef GHOTI_IO_GDEFCORE_ADMINAREA_H
#define GHOTI_IO_GDEFCORE_ADMINAREA_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The admin area as a whole: its home and the More screen. */
#define GDEFCORE_ADMIN_USE "core.admin.use"
/** The label of ::GDEFCORE_ADMIN_USE. */
#define GDEFCORE_ADMIN_USE_LABEL "Use the admin area"
/** The undo page. What it can undo is governed by the permission of what is undone. */
#define GDEFCORE_ADMIN_UNDO "core.admin.undo"
/** The label of ::GDEFCORE_ADMIN_UNDO. */
#define GDEFCORE_ADMIN_UNDO_LABEL "Undo changes"
/** Writing a post from the admin area, and undoing a change to one. */
#define GDEFCORE_POST_WRITE "core.post.write"
/** The label of ::GDEFCORE_POST_WRITE. */
#define GDEFCORE_POST_WRITE_LABEL "Write posts"
/** Undoing a change to a role, which changes what people may do. */
#define GDEFCORE_ROLE_REVERT "core.role.revert"
/** The label of ::GDEFCORE_ROLE_REVERT. */
#define GDEFCORE_ROLE_REVERT_LABEL "Undo changes to roles"
/** Reading gdefcore_access_matrix(): every grant of every role and module. */
#define GDEFCORE_ACCESS_READ "core.access.read"
/** The label of ::GDEFCORE_ACCESS_READ. */
#define GDEFCORE_ACCESS_READ_LABEL "See what is granted"

/**
 * @brief Declare the five permissions above, under the module `core`.
 *
 * Granted to nobody, the `admin` role included; a second call changes
 * nothing. Fails with ::GDEFCORE_ERR_INVALID on a NULL catalog.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_admin_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief The first administrator's grants: declare every permission an admin
 * page asks and grant each to the `admin` role.
 *
 * The permissions are the five of this header and the ones the other admin
 * pages already ask (::GDEFCORE_TEMPLATE_EDIT_LABEL, both menu labels, both
 * layout labels, ::GDEFCORE_SETTINGS_EDIT_LABEL). The grants are ordinary role
 * grants: the matrix shows them, and gdefcore_access_revoke() takes one away,
 * which takes effect at the next decision. The role is a holder of grants and
 * is never a bypass.
 *
 * It does its work **once**: when ::GDEFCORE_ADMIN_USE has been declared it
 * returns ::GDEFCORE_OK and changes nothing, so a start of the program that
 * calls it again does not give back a grant someone revoked. That mark is
 * written last, so a call that failed part way is finished by the next. A
 * caller that declared the permissions with gdefcore_admin_declare() first has
 * marked the tenant seeded and grants for itself.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_admin_seed(GDEFCORE_Catalog * catalog);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_ADMINAREA_H */
