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
 * The permissions of the admin area and the first administrator's grants
 * (adminarea.h). Only the public access API is used: a declaration and a grant
 * are the ones every module and every caller makes.
 */

#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/adminarea.h>
#include <ghoti.io/defiant-core/layout.h>
#include <ghoti.io/defiant-core/menu.h>
#include <ghoti.io/defiant-core/settings.h>
#include <ghoti.io/defiant-core/template.h>

#include <string.h>

static const char kRoleType[] = "core.role";

static GDEFCORE_Result declare_one(GDEFCORE_Catalog * catalog, const char * label,
    const char * action, const char * type) {
  GDEFCORE_Permission perm;
  memset(&perm, 0, sizeof perm);
  perm.size = sizeof perm;
  perm.label = label;
  perm.label_len = strlen(label);
  perm.module_name = "core";
  perm.module_name_len = 4;
  perm.action = action;
  perm.action_len = strlen(action);
  perm.condition = GDEFCORE_ACCESS_ANY;
  perm.type_name = type;
  perm.type_name_len = strlen(type);
  return gdefcore_access_declare(catalog, &perm);
}

/* The four that are not the area itself. The area is declared last by the
 * seed, because it is the mark that the seed was done. */
static GDEFCORE_Result declare_pages(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Result rc =
      declare_one(catalog, GDEFCORE_ADMIN_UNDO_LABEL, GDEFCORE_ADMIN_UNDO, kRoleType);
  if (rc == GDEFCORE_OK) {
    rc = declare_one(catalog, GDEFCORE_POST_WRITE_LABEL, GDEFCORE_POST_WRITE,
        "site.post");
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_one(catalog, GDEFCORE_ROLE_REVERT_LABEL, GDEFCORE_ROLE_REVERT,
        kRoleType);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_one(catalog, GDEFCORE_ACCESS_READ_LABEL, GDEFCORE_ACCESS_READ,
        kRoleType);
  }
  return rc;
}

static GDEFCORE_Result declare_area(GDEFCORE_Catalog * catalog) {
  return declare_one(catalog, GDEFCORE_ADMIN_USE_LABEL, GDEFCORE_ADMIN_USE,
      kRoleType);
}

GDEFCORE_Result gdefcore_admin_declare(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = declare_pages(catalog);
  if (rc == GDEFCORE_OK) {
    rc = declare_area(catalog);
  }
  return rc;
}

static GDEFCORE_Result grant_admin(GDEFCORE_Catalog * catalog, const char * label) {
  static const char kConfirm[] = "core.role";
  return gdefcore_access_grant(catalog, "admin", 5, label, strlen(label), kConfirm,
      sizeof kConfirm - 1);
}

GDEFCORE_Result gdefcore_admin_seed(GDEFCORE_Catalog * catalog) {
  static const char * const kLabels[] = {
      GDEFCORE_TEMPLATE_EDIT_LABEL,
      GDEFCORE_MENU_EDIT_ENTRY_LABEL,
      GDEFCORE_MENU_EDIT_OVERRIDE_LABEL,
      GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL,
      GDEFCORE_LAYOUT_EDIT_RULE_LABEL,
      GDEFCORE_SETTINGS_EDIT_LABEL,
      GDEFCORE_ADMIN_UNDO_LABEL,
      GDEFCORE_POST_WRITE_LABEL,
      GDEFCORE_ROLE_REVERT_LABEL,
      GDEFCORE_ACCESS_READ_LABEL,
  };
  GDEFCORE_Access_Permission info;
  GDEFCORE_Result rc;
  size_t i;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&info, 0, sizeof info);
  info.size = sizeof info;
  if (gdefcore_access_permission_info(catalog, GDEFCORE_ADMIN_USE_LABEL,
          sizeof GDEFCORE_ADMIN_USE_LABEL - 1, &info) == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  rc = gdefcore_template_edit_declare(catalog);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_menu_declare(catalog);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_layout_declare(catalog);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_settings_declare(catalog);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_pages(catalog);
  }
  for (i = 0; rc == GDEFCORE_OK && i < sizeof kLabels / sizeof kLabels[0]; i++) {
    rc = grant_admin(catalog, kLabels[i]);
  }
  if (rc == GDEFCORE_OK) {
    rc = declare_area(catalog);
  }
  if (rc == GDEFCORE_OK) {
    rc = grant_admin(catalog, GDEFCORE_ADMIN_USE_LABEL);
  }
  return rc;
}
