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
 * Roles, permissions and the access filter. The filter is a table of
 * grants, read from storage at the tenant's current config epoch, not a
 * callback. A filtered read is the read a principal uses.
 */

/* clock_gettime(), for an access callback's timeout (story A6). */
#define _POSIX_C_SOURCE 200809L

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/plan.h>
#include <ghoti.io/defiant-core/relation.h>
#include <ghoti.io/defiant-core/subject.h>

#include "access_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha256.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
  kStageSlots = 8,
  kStageMax = 16,
  kPart = 160,
  kGrantMax = 64,
  /* Expressions one call may hold parsed: the principal's grants, the
   * grants of the ceiling an acting principal sets, and module grants. */
  kSlotMax = 96,
  /* Where a grant came from. */
  kSrcRole = 0,
  kSrcModule = 1,
  /* An enabled module's access callback (story A6): decided per entity by
   * the module's code, held by everyone it grants. */
  kSrcCallback = 2,
  kAssignedRoles = 8,
  /* A grant whose condition is an expression (condition.h). The public
   * ::GDEFCORE_ACCESS_ANY and ::GDEFCORE_ACCESS_OWN stay 1 and 2. */
  kCondExpr = 3,
  /* A grant decided by an access callback (story A6). */
  kCondCallback = 4
};

static const char kLang[] = "en";
static const char kRoleType[] = "core.role";
static const char kPrincipalType[] = "core.principal";
static const char kPermissionType[] = "core.permission";
static const char kAdmin[] = "admin";
static const char kAuthenticated[] = "authenticated";
static const char kAnonymous[] = "anonymous";
static const char kRoleConfirm[] = "core.role";
static const char kPrincipalConfirm[] = "core.principal";
static const char kPermissionConfirm[] = "core.permission";
static const char kSeedConfirm[] = "core.principal\ncore.role";
static const char kEmptyMark[] = "-";
static const char kRetired[] = "1";
static const char kCondAny[] = "any";
static const char kCondOwn[] = "own";
static const char kCondExprMark[] = "expr";
static const char kFailedNote[] = "defiant.condition.failed";
static const char kListNote[] = "defiant.access.list";
static const char kCallbackNote[] = "defiant.callback.failed";
static const char kCallbackRunning[] = "defiant.callback.running";

typedef struct StagePerm {
  char label[kPart];
  size_t label_len;
  char module_name[kPart];
  size_t module_len;
  char action[64];
  size_t action_len;
  char type_name[kPart];
  size_t type_len;
  char field[64];
  size_t field_len;
  int condition;
} StagePerm;

typedef struct StageSlot {
  GDEFCORE_Changeset * cs;
  StagePerm perms[kStageMax];
  size_t n;
} StageSlot;

typedef struct Grant {
  char label[kPart];
  size_t label_len;
  char action[64];
  size_t action_len;
  char type_name[kPart];
  size_t type_len;
  char field[64];
  size_t field_len;
  char module_name[kPart];
  size_t module_len;
  int condition;
  /* kSrcRole: held by a role. kSrcModule: an enabled module's grant, which
   * carries its expression (borrowed from the module host, valid until the
   * host is destroyed) and is held by everyone who meets it. */
  int source;
  const char * expr;
  size_t expr_len;
  /* kSrcCallback: the callback, borrowed from the module host as expr is. */
  const GDEFCORE_Module_Declared_Callback * cb;
  /* kSrcRole: the role entity that holds it, so a decision can say which role
   * allowed it (story A7). Empty for the others. */
  char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
} Grant;

static StageSlot g_stage[kStageSlots];
static int g_committing = 0;

static const GDEFCORE_Allocator * alloc_default(void) {
  return gdefcore_allocator_default();
}

static int same(const char * a, size_t an, const char * b, size_t bn) {
  if (an != bn || a == NULL || b == NULL) {
    return 0;
  }
  return memcmp(a, b, an) == 0;
}

static int is_state(const char * name, size_t len) {
  return same(name, len, kAuthenticated, strlen(kAuthenticated)) ||
         same(name, len, kAnonymous, strlen(kAnonymous));
}

static int copy_part(char * dst, size_t cap, size_t * out_n, const char * src,
    size_t n) {
  if (src == NULL || n == 0 || n >= cap) {
    if (out_n != NULL) {
      *out_n = 0;
    }
    if (cap > 0) {
      dst[0] = '\0';
    }
    return src == NULL || n == 0;
  }
  memcpy(dst, src, n);
  dst[n] = '\0';
  if (out_n != NULL) {
    *out_n = n;
  }
  return 1;
}

static void field_set(GDEFCORE_Field * field, const char * name, int required,
    int many) {
  memset(field, 0, sizeof *field);
  field->size = sizeof *field;
  field->name = name;
  field->name_len = strlen(name);
  field->required = required;
  field->many = many;
}

static void value_set(GDEFCORE_Value * value, const char * field,
    const char * const * texts, const size_t * lens, size_t count) {
  memset(value, 0, sizeof *value);
  value->size = sizeof *value;
  value->field = field;
  value->field_len = strlen(field);
  value->texts = texts;
  value->text_lens = lens;
  value->count = count;
}

static GDEFCORE_Result read_lang(GDEFCORE_Catalog * catalog, const char * id,
    const char * lang, size_t lang_len, const char * field, char *** out_texts,
    size_t ** out_lens, size_t * out_count) {
  GDEFCORE_Result rc;
  *out_texts = NULL;
  *out_lens = NULL;
  *out_count = 0;
  rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, id,
      GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, strlen(field), out_texts,
      out_lens, out_count);
  if (rc == GDEFCORE_ERR_INVALID) {
    *out_texts = NULL;
    *out_lens = NULL;
    *out_count = 0;
    return GDEFCORE_OK;
  }
  return rc;
}

static GDEFCORE_Result read_values(GDEFCORE_Catalog * catalog, const char * id,
    const char * field, char *** out_texts, size_t ** out_lens,
    size_t * out_count) {
  return read_lang(catalog, id, kLang, strlen(kLang), field, out_texts,
      out_lens, out_count);
}

static int values_have(char ** texts, size_t * lens, size_t count,
    const char * want, size_t want_len) {
  size_t i;
  for (i = 0; i < count; i++) {
    if (same(texts[i], lens[i], want, want_len) &&
        !same(texts[i], lens[i], kEmptyMark, strlen(kEmptyMark))) {
      return 1;
    }
  }
  return 0;
}

static GDEFCORE_Result apply_save(GDEFCORE_Catalog * catalog, const char * id,
    const GDEFCORE_Value * values, size_t count, const char * confirm) {
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_save(changeset, id, GDEFCORE_PUBLIC_ID_LEN, kLang,
      strlen(kLang), values, count);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, confirm, strlen(confirm));
  }
  gdefcore_changeset_destroy(changeset);
  return rc;
}

static GDEFCORE_Result define_named(GDEFCORE_Catalog * catalog,
    const char * name, const GDEFCORE_Field * fields, size_t count) {
  int kind = 0;
  GDEFCORE_Result rc = gdefcore_type_kind(catalog, name, strlen(name), &kind);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  return gdefcore_type_define(catalog, name, strlen(name), GDEFCORE_TYPE_CONFIG,
      fields, count);
}

static GDEFCORE_Result define_types(GDEFCORE_Catalog * catalog) {
  GDEFCORE_Field role_fields[3];
  GDEFCORE_Field principal_fields[2];
  GDEFCORE_Field permission_fields[6];
  GDEFCORE_Result rc;
  field_set(&role_fields[0], "name", 1, 0);
  field_set(&role_fields[1], "grant", 0, 1);
  field_set(&role_fields[2], "retired", 0, 0);
  field_set(&principal_fields[0], "role", 0, 1);
  field_set(&principal_fields[1], "retired", 0, 0);
  field_set(&permission_fields[0], "label", 1, 0);
  field_set(&permission_fields[1], "module", 1, 0);
  field_set(&permission_fields[2], "action", 1, 0);
  field_set(&permission_fields[3], "condition", 1, 0);
  field_set(&permission_fields[4], "type", 1, 0);
  field_set(&permission_fields[5], "field", 0, 0);
  rc = define_named(catalog, kRoleType, role_fields, 3);
  if (rc == GDEFCORE_OK) {
    rc = define_named(catalog, kPrincipalType, principal_fields, 2);
  }
  if (rc == GDEFCORE_OK) {
    rc = define_named(catalog, kPermissionType, permission_fields, 6);
  }
  return rc;
}

/* Whether the entity is retired. A flag that cannot be read is retired:
 * unknown is no grant, and the lookups that look for a live entity move on. */
static GDEFCORE_Result retired_state(GDEFCORE_Catalog * catalog, const char * id,
    int * out_retired) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  GDEFCORE_Result rc = read_values(catalog, id, "retired", &texts, &lens, &count);
  if (rc != GDEFCORE_OK) {
    *out_retired = 1;
    return rc;
  }
  *out_retired = values_have(texts, lens, count, kRetired, strlen(kRetired));
  gdefcore_values_free(catalog, texts, lens, count);
  return GDEFCORE_OK;
}

static int retired_id(GDEFCORE_Catalog * catalog, const char * id) {
  int retired = 1;
  (void)retired_state(catalog, id, &retired);
  return retired;
}

/* The first entity of @p type whose @p field holds @p want. A read that fails
 * on the way is not "no such entity": if nothing was found and something
 * failed, the failure is what comes back. */
static GDEFCORE_Result find_named(GDEFCORE_Catalog * catalog, const char * type,
    const char * field, const char * want, size_t want_len, char * out_id) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result failure = GDEFCORE_OK;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, type, strlen(type), &ids,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = GDEFCORE_ERR_INVALID;
  for (i = 0; i < count; i++) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    int retired = 0;
    GDEFCORE_Result got = retired_state(catalog, ids[i], &retired);
    if (got != GDEFCORE_OK) {
      failure = failure == GDEFCORE_OK ? got : failure;
      continue;
    }
    if (retired) {
      continue;
    }
    got = read_values(catalog, ids[i], field, &texts, &lens, &n);
    if (got != GDEFCORE_OK) {
      failure = failure == GDEFCORE_OK ? got : failure;
      continue;
    }
    if (values_have(texts, lens, n, want, want_len)) {
      memcpy(out_id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      rc = GDEFCORE_OK;
      gdefcore_values_free(catalog, texts, lens, n);
      break;
    }
    gdefcore_values_free(catalog, texts, lens, n);
  }
  gdefcore_ids_free(catalog, ids, count);
  if (rc != GDEFCORE_OK && failure != GDEFCORE_OK) {
    return failure;
  }
  return rc;
}

static GDEFCORE_Result find_role(GDEFCORE_Catalog * catalog, const char * name,
    size_t name_len, char * out_id) {
  return find_named(catalog, kRoleType, "name", name, name_len, out_id);
}

static GDEFCORE_Result create_named(GDEFCORE_Catalog * catalog,
    const char * type, const GDEFCORE_Value * values, size_t count,
    const char * confirm, char * out_id) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Result rc = gdefcore_entity_create(catalog, type, strlen(type), id,
      NULL);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = apply_save(catalog, id, values, count, confirm);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (out_id != NULL) {
    memcpy(out_id, id, GDEFCORE_PUBLIC_ID_LEN + 1);
  }
  return GDEFCORE_OK;
}

static GDEFCORE_Result ensure(GDEFCORE_Catalog * catalog) {
  char admin_role[GDEFCORE_PUBLIC_ID_LEN + 1];
  char auth_role[GDEFCORE_PUBLIC_ID_LEN + 1];
  char anon_role[GDEFCORE_PUBLIC_ID_LEN + 1];
  char principal[GDEFCORE_PUBLIC_ID_LEN + 1];
  const char * admin_name = kAdmin;
  const char * auth_name = kAuthenticated;
  const char * anon_name = kAnonymous;
  size_t admin_len = strlen(kAdmin);
  size_t auth_len = strlen(kAuthenticated);
  size_t anon_len = strlen(kAnonymous);
  GDEFCORE_Value values[2];
  const char * role_text[1];
  size_t role_lens[1];
  GDEFCORE_Changeset * changeset = NULL;
  GDEFCORE_Result rc;
  rc = find_role(catalog, kAdmin, strlen(kAdmin), admin_role);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    /* Not "no admin role yet": the lookup itself failed (an allocation, the
     * store). Seeding on top of an admin role that is there but unread would
     * make a second admin role and a second admin principal. */
    return rc;
  }
  rc = define_types(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_create(catalog, kRoleType, strlen(kRoleType), admin_role,
      NULL);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_create(catalog, kRoleType, strlen(kRoleType),
        auth_role, NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_create(catalog, kRoleType, strlen(kRoleType),
        anon_role, NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_entity_create(catalog, kPrincipalType, strlen(kPrincipalType),
        principal, NULL);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_changeset_prepare(catalog, NULL, 0, &changeset);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  value_set(&values[0], "name", &admin_name, &admin_len, 1);
  rc = gdefcore_entity_save(changeset, admin_role, GDEFCORE_PUBLIC_ID_LEN,
      kLang, strlen(kLang), values, 1);
  if (rc == GDEFCORE_OK) {
    value_set(&values[0], "name", &auth_name, &auth_len, 1);
    rc = gdefcore_entity_save(changeset, auth_role, GDEFCORE_PUBLIC_ID_LEN,
        kLang, strlen(kLang), values, 1);
  }
  if (rc == GDEFCORE_OK) {
    value_set(&values[0], "name", &anon_name, &anon_len, 1);
    rc = gdefcore_entity_save(changeset, anon_role, GDEFCORE_PUBLIC_ID_LEN,
        kLang, strlen(kLang), values, 1);
  }
  if (rc == GDEFCORE_OK) {
    role_text[0] = kAdmin;
    role_lens[0] = strlen(kAdmin);
    value_set(&values[0], "role", role_text, role_lens, 1);
    rc = gdefcore_entity_save(changeset, principal, GDEFCORE_PUBLIC_ID_LEN,
        kLang, strlen(kLang), values, 1);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_changeset_apply(changeset, kSeedConfirm, strlen(kSeedConfirm));
  }
  gdefcore_changeset_destroy(changeset);
  return rc;
}

static int encode_grant(char * buf, size_t cap, const Grant * grant) {
  const char * cond = grant->condition == kCondExpr
                          ? kCondExprMark
                          : (grant->condition == GDEFCORE_ACCESS_OWN ? kCondOwn
                                                                     : kCondAny);
  int n = snprintf(buf, cap, "%.*s%c%.*s%c%.*s%c%s%c%.*s%c%.*s",
      (int)grant->label_len, grant->label, 0x1f, (int)grant->action_len,
      grant->action, 0x1f, (int)grant->module_len, grant->module_name, 0x1f,
      cond, 0x1f, (int)grant->type_len, grant->type_name, 0x1f,
      (int)grant->field_len, grant->field);
  if (n <= 0 || (size_t)n >= cap) {
    return -1;
  }
  return n;
}

static int parse_grant(const char * text, size_t len, Grant * grant,
    char * module_name, size_t module_cap, size_t * module_len) {
  const char * parts[6];
  size_t plens[6];
  size_t nparts = 0;
  size_t start = 0;
  size_t i;
  memset(grant, 0, sizeof *grant);
  for (i = 0; i <= len; i++) {
    if (i == len || text[i] == 0x1f) {
      if (nparts >= 6) {
        return 0;
      }
      parts[nparts] = text + start;
      plens[nparts] = i - start;
      nparts += 1;
      start = i + 1;
    }
  }
  if (nparts != 6) {
    return 0;
  }
  if (!copy_part(grant->label, sizeof grant->label, &grant->label_len,
          parts[0], plens[0]) ||
      !copy_part(grant->action, sizeof grant->action, &grant->action_len,
          parts[1], plens[1]) ||
      !copy_part(grant->type_name, sizeof grant->type_name, &grant->type_len,
          parts[4], plens[4])) {
    return 0;
  }
  if (plens[5] > 0 &&
      !copy_part(grant->field, sizeof grant->field, &grant->field_len, parts[5],
          plens[5])) {
    return 0;
  }
  if (plens[2] > 0 &&
      !copy_part(grant->module_name, sizeof grant->module_name,
          &grant->module_len, parts[2], plens[2])) {
    return 0;
  }
  if (module_name != NULL &&
      !copy_part(module_name, module_cap, module_len, parts[2], plens[2])) {
    return 0;
  }
  if (plens[3] == 3 && memcmp(parts[3], "any", 3) == 0) {
    grant->condition = GDEFCORE_ACCESS_ANY;
  } else if (plens[3] == 3 && memcmp(parts[3], "own", 3) == 0) {
    grant->condition = GDEFCORE_ACCESS_OWN;
  } else if (plens[3] == 4 && memcmp(parts[3], kCondExprMark, 4) == 0) {
    grant->condition = kCondExpr;
  } else {
    return 0;
  }
  return 1;
}

static GDEFCORE_Result load_role_grants(GDEFCORE_Catalog * catalog,
    const char * role_id, Grant * grants, size_t cap, size_t * out_n) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = read_values(catalog, role_id, "grant", &texts, &lens,
      &count);
  *out_n = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    Grant grant;
    if (same(texts[i], lens[i], kEmptyMark, strlen(kEmptyMark))) {
      continue;
    }
    if (!parse_grant(texts[i], lens[i], &grant, NULL, 0, NULL)) {
      gdefcore_values_free(catalog, texts, lens, count);
      return GDEFCORE_ERR_CORRUPT;
    }
    if (*out_n >= cap) {
      gdefcore_values_free(catalog, texts, lens, count);
      return GDEFCORE_ERR_LIMIT;
    }
    grants[*out_n] = grant;
    *out_n += 1;
  }
  gdefcore_values_free(catalog, texts, lens, count);
  return GDEFCORE_OK;
}

static GDEFCORE_Result permission_by_label(GDEFCORE_Catalog * catalog,
    const char * label, size_t label_len, char * out_id, Grant * grant,
    char * module_name, size_t module_cap, size_t * module_len);

/*
 * The grants of the modules that are enabled, as grants everyone holds who
 * meets their condition. A grant whose permission is not (yet) declared, or
 * is declared by a module other than the grant's own and not by the kernel,
 * or differs from the permission in type or field, is inert: it is skipped,
 * never widened. The enabled set is read from the module host, so a module
 * that is disabled has no grants here, with no leftover to clean up.
 */
static GDEFCORE_Result load_module_grants(GDEFCORE_Catalog * catalog,
    Grant * grants, size_t cap, size_t * out_n) {
  GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
  const GDEFCORE_Module_Declared_Grant ** items = NULL;
  size_t count = 0;
  size_t i;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  GDEFCORE_Result rc;
  if (host == NULL) {
    return GDEFCORE_OK;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  rc = gdefcore_module_grants(host, tenant, tenant_len, NULL, &items, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    const GDEFCORE_Module_Declared_Grant * item = items[i];
    Grant info;
    Grant * g;
    char owner[kPart];
    size_t owner_len = 0;
    rc = permission_by_label(catalog, item->permission, item->permission_len,
        NULL, &info, owner, sizeof owner, &owner_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
      continue;
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (!(same(owner, owner_len, item->module, item->module_len) ||
            same(owner, owner_len, "core", 4)) ||
        !same(info.type_name, info.type_len, item->type_name,
            item->type_name_len) ||
        !same(info.field, info.field_len, item->field, item->field_len)) {
      continue;
    }
    if (*out_n >= cap) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    g = &grants[*out_n];
    memset(g, 0, sizeof *g);
    if (!copy_part(g->label, sizeof g->label, &g->label_len, item->permission,
            item->permission_len) ||
        !copy_part(g->module_name, sizeof g->module_name, &g->module_len,
            item->module, item->module_len)) {
      continue;
    }
    memcpy(g->action, info.action, info.action_len + 1);
    g->action_len = info.action_len;
    memcpy(g->type_name, info.type_name, info.type_len + 1);
    g->type_len = info.type_len;
    memcpy(g->field, info.field, info.field_len + 1);
    g->field_len = info.field_len;
    g->condition = kCondExpr;
    g->source = kSrcModule;
    g->expr = item->condition;
    g->expr_len = item->condition_len;
    *out_n += 1;
  }
  gdefcore_module_declared_free(host, items);
  return rc;
}

/*
 * The access callbacks of the enabled modules (story A6), as grants everyone
 * holds whom the callback grants. As for a module grant, one whose permission
 * is not declared, or is declared by another module than its own and not by
 * the kernel, or differs from the permission in type or field, is inert; so
 * is one whose scope does not fit its permission (a field callback's names
 * the field, an operation callback's none), which the enable refuses.
 */
static GDEFCORE_Result load_module_callbacks(GDEFCORE_Catalog * catalog,
    Grant * grants, size_t cap, size_t * out_n) {
  GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
  const GDEFCORE_Module_Declared_Callback ** items = NULL;
  size_t count = 0;
  size_t i;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  GDEFCORE_Result rc;
  if (host == NULL) {
    return GDEFCORE_OK;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  rc = gdefcore_module_callbacks(host, tenant, tenant_len, NULL, &items,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    const GDEFCORE_Module_Declared_Callback * item = items[i];
    Grant info;
    Grant * g;
    char owner[kPart];
    size_t owner_len = 0;
    rc = permission_by_label(catalog, item->permission, item->permission_len,
        NULL, &info, owner, sizeof owner, &owner_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      rc = GDEFCORE_OK;
      continue;
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
    if ((!same(owner, owner_len, "core", 4) &&
            !same(owner, owner_len, item->module, item->module_len)) ||
        !same(info.type_name, info.type_len, item->type_name,
            item->type_name_len) ||
        !same(info.field, info.field_len, item->field, item->field_len) ||
        (item->scope == GDEFCORE_CALLBACK_FIELD) != (info.field_len > 0) ||
        (item->scope == GDEFCORE_CALLBACK_OPERATION &&
            gdefcore_access_row_action(info.action, info.action_len))) {
      continue;
    }
    if (*out_n >= cap) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    g = &grants[*out_n];
    memset(g, 0, sizeof *g);
    if (!copy_part(g->label, sizeof g->label, &g->label_len, item->permission,
            item->permission_len) ||
        !copy_part(g->module_name, sizeof g->module_name, &g->module_len,
            item->module, item->module_len)) {
      continue;
    }
    memcpy(g->action, info.action, info.action_len + 1);
    g->action_len = info.action_len;
    memcpy(g->type_name, info.type_name, info.type_len + 1);
    g->type_len = info.type_len;
    memcpy(g->field, info.field, info.field_len + 1);
    g->field_len = info.field_len;
    g->condition = kCondCallback;
    g->source = kSrcCallback;
    g->cb = item;
    *out_n += 1;
  }
  gdefcore_module_declared_free(host, items);
  return rc;
}

/* The module grants, then the module callbacks: a callback is asked only when
 * nothing before it in the list grants (the decisions stop at the first
 * grant that holds). */
static GDEFCORE_Result load_module_all(GDEFCORE_Catalog * catalog,
    Grant * grants, size_t cap, size_t * out_n) {
  GDEFCORE_Result rc = load_module_grants(catalog, grants, cap, out_n);
  if (rc == GDEFCORE_OK) {
    rc = load_module_callbacks(catalog, grants, cap, out_n);
  }
  return rc;
}

static GDEFCORE_Result load_effective_for(GDEFCORE_Catalog * catalog,
    const char * principal, size_t principal_len, Grant * grants, size_t cap,
    size_t * out_n, int * read_principal, int with_modules) {
  char principal_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const char * roles[kAssignedRoles + 1];
  size_t role_lens[kAssignedRoles + 1];
  size_t nroles = 0;
  size_t i;
  *out_n = 0;
  *read_principal = 0;
  if (principal == NULL || principal_len == 0) {
    principal = NULL;
    roles[nroles] = kAnonymous;
    role_lens[nroles] = strlen(kAnonymous);
    nroles += 1;
  } else {
    char ** held = NULL;
    size_t * held_lens = NULL;
    size_t held_n = 0;
    GDEFCORE_Result rc;
    if (principal_len > GDEFCORE_PUBLIC_ID_LEN) {
      return GDEFCORE_OK;
    }
    memcpy(principal_id, principal, principal_len);
    principal_id[principal_len] = '\0';
    if (retired_id(catalog, principal_id)) {
      return GDEFCORE_OK;
    }
    roles[nroles] = kAuthenticated;
    role_lens[nroles] = strlen(kAuthenticated);
    nroles += 1;
    rc = read_values(catalog, principal_id, "role", &held, &held_lens, &held_n);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    for (i = 0; i < held_n && nroles < kAssignedRoles + 1; i++) {
      if (same(held[i], held_lens[i], kEmptyMark, strlen(kEmptyMark))) {
        continue;
      }
      roles[nroles] = held[i];
      role_lens[nroles] = held_lens[i];
      nroles += 1;
    }
    for (i = 0; i < nroles; i++) {
      char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
      size_t got = 0;
      size_t g;
      if (i > 0 &&
          find_role(catalog, roles[i], role_lens[i], role_id) != GDEFCORE_OK) {
        continue;
      }
      if (i == 0 &&
          find_role(catalog, roles[0], role_lens[0], role_id) != GDEFCORE_OK) {
        continue;
      }
      rc = load_role_grants(catalog, role_id, grants + *out_n, cap - *out_n,
          &got);
      if (rc != GDEFCORE_OK) {
        gdefcore_values_free(catalog, held, held_lens, held_n);
        return rc;
      }
      for (g = 0; g < got; g++) {
        memcpy(grants[*out_n + g].role_id, role_id, sizeof role_id);
        if (grants[*out_n + g].condition == GDEFCORE_ACCESS_OWN) {
          *read_principal = 1;
        }
      }
      *out_n += got;
    }
    gdefcore_values_free(catalog, held, held_lens, held_n);
    return with_modules ? load_module_all(catalog, grants, cap, out_n)
                        : GDEFCORE_OK;
  }
  {
    char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
    size_t got = 0;
    size_t g;
    if (find_role(catalog, roles[0], role_lens[0], role_id) != GDEFCORE_OK) {
      return with_modules ? load_module_all(catalog, grants, cap, out_n)
                          : GDEFCORE_OK;
    }
    if (load_role_grants(catalog, role_id, grants, cap, &got) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INVALID;
    }
    for (g = 0; g < got; g++) {
      memcpy(grants[g].role_id, role_id, sizeof role_id);
      if (grants[g].condition == GDEFCORE_ACCESS_OWN) {
        *read_principal = 1;
      }
    }
    *out_n = got;
  }
  return with_modules ? load_module_all(catalog, grants, cap, out_n)
                      : GDEFCORE_OK;
}

static GDEFCORE_Result load_effective(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, Grant * grants, size_t cap, size_t * out_n,
    int * read_principal) {
  const char * principal = NULL;
  size_t principal_len = 0;
  if (request != NULL) {
    principal = gdefcore_request_principal(request, &principal_len);
  }
  return load_effective_for(catalog, principal, principal_len, grants, cap,
      out_n, read_principal, 1);
}

static GDEFCORE_Result load_decls(GDEFCORE_Catalog * catalog, Grant * decls,
    size_t cap, size_t * out_n) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kPermissionType,
      strlen(kPermissionType), &ids, &count);
  *out_n = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char ** label = NULL;
    char ** type_name = NULL;
    char ** field = NULL;
    char ** condition = NULL;
    char ** action = NULL;
    size_t * ll = NULL;
    size_t * tl = NULL;
    size_t * fl = NULL;
    size_t * cl = NULL;
    size_t * al = NULL;
    size_t ln = 0;
    size_t tn = 0;
    size_t fn = 0;
    size_t cn = 0;
    size_t an = 0;
    Grant * decl;
    if (read_values(catalog, ids[i], "label", &label, &ll, &ln) !=
            GDEFCORE_OK ||
        ln == 0) {
      gdefcore_values_free(catalog, label, ll, ln);
      continue;
    }
    if (read_values(catalog, ids[i], "type", &type_name, &tl, &tn) !=
            GDEFCORE_OK ||
        tn == 0) {
      gdefcore_values_free(catalog, label, ll, ln);
      gdefcore_values_free(catalog, type_name, tl, tn);
      continue;
    }
    read_values(catalog, ids[i], "field", &field, &fl, &fn);
    read_values(catalog, ids[i], "condition", &condition, &cl, &cn);
    read_values(catalog, ids[i], "action", &action, &al, &an);
    if (*out_n >= cap) {
      gdefcore_values_free(catalog, label, ll, ln);
      gdefcore_values_free(catalog, type_name, tl, tn);
      gdefcore_values_free(catalog, field, fl, fn);
      gdefcore_values_free(catalog, condition, cl, cn);
      gdefcore_values_free(catalog, action, al, an);
      gdefcore_ids_free(catalog, ids, count);
      return GDEFCORE_ERR_LIMIT;
    }
    decl = &decls[*out_n];
    memset(decl, 0, sizeof *decl);
    copy_part(decl->label, sizeof decl->label, &decl->label_len, label[0],
        ll[0]);
    copy_part(decl->type_name, sizeof decl->type_name, &decl->type_len,
        type_name[0], tl[0]);
    if (fn > 0) {
      copy_part(decl->field, sizeof decl->field, &decl->field_len, field[0],
          fl[0]);
    }
    if (an > 0) {
      copy_part(decl->action, sizeof decl->action, &decl->action_len, action[0],
          al[0]);
    }
    if (cn == 1 && same(condition[0], cl[0], "own", 3)) {
      decl->condition = GDEFCORE_ACCESS_OWN;
    } else if (cn == 1 && same(condition[0], cl[0], "any", 3)) {
      decl->condition = GDEFCORE_ACCESS_ANY;
    } else if (cn == 1 && cl[0] > 0) {
      /* An expression. Only its field, if any, matters here. */
      decl->condition = kCondExpr;
    } else {
      gdefcore_values_free(catalog, label, ll, ln);
      gdefcore_values_free(catalog, type_name, tl, tn);
      gdefcore_values_free(catalog, field, fl, fn);
      gdefcore_values_free(catalog, condition, cl, cn);
      gdefcore_values_free(catalog, action, al, an);
      continue;
    }
    *out_n += 1;
    gdefcore_values_free(catalog, label, ll, ln);
    gdefcore_values_free(catalog, type_name, tl, tn);
    gdefcore_values_free(catalog, field, fl, fn);
    gdefcore_values_free(catalog, condition, cl, cn);
    gdefcore_values_free(catalog, action, al, an);
  }
  gdefcore_ids_free(catalog, ids, count);
  return GDEFCORE_OK;
}

static int type_has_field(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * field, size_t field_len) {
  size_t count = 0;
  size_t i;
  if (gdefcore_type_field_count(catalog, type, type_len, &count) !=
      GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < count; i++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int match = 0;
    if (gdefcore_type_field(catalog, type, type_len, i, &name, &name_len,
            &required, &many) != GDEFCORE_OK) {
      return 0;
    }
    match = same(name, name_len, field, field_len);
    gdefcore_text_free(catalog, name);
    if (match) {
      return 1;
    }
  }
  return 0;
}

/* Whether the type has the field, with a failure to find out told as one: a
 * field that cannot be looked up is not a field that is not there (story A7:
 * a missing field is answered as an absent one, and a failure never is). */
static GDEFCORE_Result type_has_field_rc(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, const char * field, size_t field_len,
    int * out_has) {
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_type_field_count(catalog, type, type_len,
      &count);
  *out_has = 0;
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int match;
    rc = gdefcore_type_field(catalog, type, type_len, i, &name, &name_len,
        &required, &many);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    match = same(name, name_len, field, field_len);
    gdefcore_text_free(catalog, name);
    if (match) {
      *out_has = 1;
      return GDEFCORE_OK;
    }
  }
  return GDEFCORE_OK;
}

/* One parsed expression, by the label of the permission that carries it. */
typedef struct ExprSlot {
  char label[kPart];
  size_t label_len;
  const char * expr;   /* a module grant is keyed by its text, not a label */
  size_t expr_len;
  GDEFCORE_Condition * cond;
  int bad;
  /* The condition names a field an enabled module's callback decides, so the
   * grant holds nothing for now (story A7): decided from the enabled set each
   * time, never stored. */
  int suspended;
} ExprSlot;

/* The field callbacks of the enabled modules, loaded once per call, to find
 * the grants whose condition names a field one of them decides. Borrowed from
 * the module host. */
typedef struct Governed {
  const GDEFCORE_Module_Declared_Callback ** items;
  size_t n;
  int loaded;
} Governed;

/*
 * What a grant's condition needs to be decided: the entity now being asked
 * about, the language its field values are read in, the parsed expressions
 * (each read and parsed once per call), and whether anything failed. A
 * failure is a grant that does not hold, never one that does.
 */
typedef struct Eval {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Request * request;
  const char * lang;
  size_t lang_len;
  const char * id;      /* canonical id of the entity being asked about */
  ExprSlot slots[kSlotMax];
  size_t nslots;
  int failed;
  /* The ceiling of an acting principal (AD-12): a decision needs a grant of
   * the principal's AND one of the acting principal's for the same
   * permission, each holding on the entity. Heap, because it is rare. */
  int has_ceiling;
  Grant * ceiling;
  size_t nceiling;
  Governed gov;
} Eval;

static void eval_init(Eval * ev, GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * lang, size_t lang_len) {
  ev->catalog = catalog;
  ev->request = request;
  ev->lang = lang == NULL ? kLang : lang;
  ev->lang_len = lang == NULL ? strlen(kLang) : lang_len;
  ev->id = NULL;
  ev->nslots = 0;
  ev->failed = 0;
  ev->has_ceiling = 0;
  ev->ceiling = NULL;
  ev->nceiling = 0;
  memset(&ev->gov, 0, sizeof ev->gov);
}

/* The enabled modules' field callbacks (or, with @p projection, those of the
 * set a changeset would leave). */
static GDEFCORE_Result gov_load(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Changeset * projection, Governed * gov) {
  GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
  const uint8_t * tenant;
  size_t tenant_len = 0;
  GDEFCORE_Result rc;
  memset(gov, 0, sizeof *gov);
  if (host == NULL) {
    gov->loaded = 1;
    return GDEFCORE_OK;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  rc = gdefcore_module_callbacks(host, tenant, tenant_len, projection,
      &gov->items, &gov->n);
  if (rc != GDEFCORE_OK) {
    memset(gov, 0, sizeof *gov);
    return rc;
  }
  gov->loaded = 1;
  return GDEFCORE_OK;
}

static void gov_free(GDEFCORE_Catalog * catalog, Governed * gov) {
  GDEFCORE_Host * host = catalog == NULL ? NULL : gdefcore_catalog_host(catalog);
  if (host != NULL && gov->items != NULL) {
    gdefcore_module_declared_free(host, gov->items);
  }
  memset(gov, 0, sizeof *gov);
}

enum { kGovMax = 32, kSuspBuf = kGovMax * (kPart + 2) + 1 };

/* The modules whose field callbacks decide a field that @p cond names on
 * @p type, once each, in the order of their names; the callback that names
 * each is returned in @p out (at most kGovMax). A module that decides several
 * such fields is one module. */
static size_t gov_modules(const Governed * gov, const GDEFCORE_Condition * cond,
    const char * type, size_t type_len,
    const GDEFCORE_Module_Declared_Callback ** out) {
  size_t n = 0;
  size_t i;
  for (i = 0; i < gov->n; i++) {
    const GDEFCORE_Module_Declared_Callback * c = gov->items[i];
    size_t k;
    size_t at;
    int seen = 0;
    if (c->scope != GDEFCORE_CALLBACK_FIELD || c->field_len == 0 ||
        !same(c->type_name, c->type_name_len, type, type_len) ||
        !gdefcore_condition_tests_field(cond, c->field, c->field_len)) {
      continue;
    }
    for (k = 0; k < n; k++) {
      seen = seen || same(out[k]->module, out[k]->module_len, c->module,
                         c->module_len);
    }
    if (seen || n >= kGovMax) {
      continue;
    }
    /* Insert in the order of the module names, bytewise. */
    at = n;
    while (at > 0) {
      size_t m = out[at - 1]->module_len < c->module_len
                     ? out[at - 1]->module_len
                     : c->module_len;
      int cmp = memcmp(out[at - 1]->module, c->module, m);
      if (cmp < 0 || (cmp == 0 && out[at - 1]->module_len < c->module_len)) {
        break;
      }
      out[at] = out[at - 1];
      at -= 1;
    }
    out[at] = c;
    n += 1;
  }
  return n;
}

/* "billing, ledger": the module names of @p mods, for a sentence. */
static int gov_names(const GDEFCORE_Module_Declared_Callback * const * mods,
    size_t n, char * buf, size_t cap) {
  size_t at = 0;
  size_t i;
  for (i = 0; i < n; i++) {
    size_t need = mods[i]->module_len + (i > 0 ? 2 : 0);
    if (at + need + 1 > cap) {
      return -1;
    }
    if (i > 0) {
      memcpy(buf + at, ", ", 2);
      at += 2;
    }
    memcpy(buf + at, mods[i]->module, mods[i]->module_len);
    at += mods[i]->module_len;
  }
  buf[at] = '\0';
  return (int)at;
}

/* Frees the slots. A failure leaves a note on the request, which is how the
 * caller of a filtered read learns that a condition could not be decided. */
static void eval_done(Eval * ev) {
  size_t i;
  for (i = 0; i < ev->nslots; i++) {
    gdefcore_condition_free(ev->slots[i].cond);
  }
  ev->nslots = 0;
  gov_free(ev->catalog, &ev->gov);
  gcu_allocator_free(alloc_default(), ev->ceiling);
  ev->ceiling = NULL;
  ev->nceiling = 0;
  ev->has_ceiling = 0;
  if (ev->failed && ev->request != NULL) {
    (void)gdefcore_request_set_note(ev->request, kFailedNote,
        strlen(kFailedNote), "1", 1);
  }
}

/*
 * A grant whose condition names a field an enabled module's callback decides
 * holds nothing (story A7): the condition cannot be evaluated on a value only
 * the callback may read, and a list cannot compile it. This is derived from
 * the set of enabled modules each time a condition is read, not stored, so a
 * grant is suspended exactly as long as some enabled module decides the field
 * and resumes when the last one is disabled. It is no failure: nothing is
 * reported, because the state is shown in the matrix and was confirmed at the
 * enable that brought it about. The evaluator's own refusal of a governed
 * field (condition_eval.c) stays behind it as the backstop.
 */
static void slot_suspend(Eval * ev, ExprSlot * slot, const Grant * grant) {
  const GDEFCORE_Module_Declared_Callback * mods[kGovMax];
  if (!ev->gov.loaded && gov_load(ev->catalog, NULL, &ev->gov) != GDEFCORE_OK) {
    /* Unknown is governed: not decided, never probed. */
    slot->bad = 1;
    return;
  }
  slot->suspended =
      gov_modules(&ev->gov, slot->cond, grant->type_name, grant->type_len,
          mods) > 0;
}

static ExprSlot * expr_slot(Eval * ev, const Grant * grant) {
  size_t i;
  ExprSlot * slot;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  int by_expr = grant->source == kSrcModule;
  for (i = 0; i < ev->nslots; i++) {
    if (by_expr) {
      /* The label too: the same text on another permission is another type. */
      if (ev->slots[i].expr != NULL &&
          same(ev->slots[i].expr, ev->slots[i].expr_len, grant->expr,
              grant->expr_len) &&
          same(ev->slots[i].label, ev->slots[i].label_len, grant->label,
              grant->label_len)) {
        return &ev->slots[i];
      }
    } else if (ev->slots[i].expr == NULL &&
               same(ev->slots[i].label, ev->slots[i].label_len, grant->label,
                   grant->label_len)) {
      return &ev->slots[i];
    }
  }
  if (ev->nslots >= kSlotMax) {
    return NULL;
  }
  slot = &ev->slots[ev->nslots];
  memset(slot, 0, sizeof *slot);
  memcpy(slot->label, grant->label, grant->label_len);
  slot->label_len = grant->label_len;
  ev->nslots += 1;
  slot->bad = 1;
  if (by_expr) {
    slot->expr = grant->expr;
    slot->expr_len = grant->expr_len;
    if (grant->expr != NULL &&
        gdefcore_condition_parse(grant->expr, grant->expr_len, &slot->cond,
            NULL) == GDEFCORE_OK) {
      slot->bad = 0;
      slot_suspend(ev, slot, grant);
    }
    return slot;
  }
  if (find_named(ev->catalog, kPermissionType, "label", grant->label,
          grant->label_len, id) != GDEFCORE_OK) {
    return slot;
  }
  if (read_values(ev->catalog, id, "condition", &texts, &lens, &n) ==
          GDEFCORE_OK &&
      n == 1) {
    if (gdefcore_condition_parse(texts[0], lens[0], &slot->cond, NULL) ==
        GDEFCORE_OK) {
      slot->bad = 0;
      slot_suspend(ev, slot, grant);
    }
  }
  gdefcore_values_free(ev->catalog, texts, lens, n);
  return slot;
}

/* Whether a grant's expression holds on the entity ev->id, or, with no
 * entity, could hold for something of the grant's type. */
static int expr_holds(Eval * ev, const Grant * grant, const char * id,
    size_t id_len) {
  ExprSlot * slot = expr_slot(ev, grant);
  GDEFCORE_Condition_Subject subject;
  int failed = 0;
  int r;
  if (slot == NULL || slot->bad || slot->cond == NULL) {
    ev->failed = 1;
    return 0;
  }
  if (slot->suspended) {
    return 0;
  }
  memset(&subject, 0, sizeof subject);
  subject.size = sizeof subject;
  subject.entity = id;
  subject.entity_len = id_len;
  subject.type_name = grant->type_name;
  subject.type_name_len = grant->type_len;
  subject.lang = ev->lang;
  subject.lang_len = ev->lang_len;
  r = gdefcore_condition_eval(ev->catalog, ev->request, slot->cond, &subject,
      &failed);
  if (failed) {
    ev->failed = 1;
    return 0;
  }
  return r;
}

/* ---- access callbacks (story A6) ---------------------------------------- */

struct GDEFCORE_Callback_Call {
  uint64_t fuel;        /* left of the call's own */
  int over;             /* it spent past it */
  uint64_t deadline_ms; /* monotonic */
};

static uint64_t mono_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

GDEFCORE_Result gdefcore_callback_spend(GDEFCORE_Callback_Call * call,
    uint64_t units) {
  if (call == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (call->over || call->fuel < units) {
    call->fuel = 0;
    call->over = 1;
    return GDEFCORE_ERR_LIMIT;
  }
  call->fuel -= units;
  return GDEFCORE_OK;
}

int gdefcore_callback_expired(const GDEFCORE_Callback_Call * call) {
  return call == NULL || mono_ms() > call->deadline_ms;
}

int gdefcore_access_row_action(const char * action, size_t len) {
  static const char * const words[] = {"list", "search", "count", "export"};
  size_t start = 0;
  size_t i;
  if (action == NULL) {
    return 0;
  }
  if (same(action, len, "read", 4)) {
    return 1;
  }
  for (i = 0; i <= len; i++) {
    if (i == len || action[i] == '.') {
      size_t w;
      for (w = 0; w < sizeof words / sizeof words[0]; w++) {
        if (same(action + start, i - start, words[w], strlen(words[w]))) {
          return 1;
        }
      }
      start = i + 1;
    }
  }
  return 0;
}

/* The memo key of one answer of @p cb: who asks (and for whom), of which
 * entity at which version. 0 when it does not fit (the answer is then not
 * remembered, and asked again). */
static int callback_key(char * out, size_t cap, const GDEFCORE_Request * request,
    const GDEFCORE_Module_Declared_Callback * cb, const char * entity,
    uint64_t version) {
  size_t principal_len = 0;
  const char * principal = gdefcore_request_principal(request, &principal_len);
  size_t acting_len = 0;
  const char * acting = gdefcore_request_acting_principal(request, &acting_len);
  const char * who = principal == NULL ? "-" : principal;
  size_t who_len = principal == NULL ? 1 : principal_len;
  const char * agent = acting == NULL ? "-" : acting;
  size_t agent_len = acting == NULL ? 1 : acting_len;
  int n = snprintf(out, cap, "cb\x1f%.*s\x1f%.*s\x1f%.*s\x1f%.*s\x1f%s\x1f%llu",
      (int)cb->module_len, cb->module, (int)cb->name_len, cb->name,
      (int)who_len, who, (int)agent_len, agent, entity,
      (unsigned long long)version);
  return n > 0 && (size_t)n < cap ? n : 0;
}

/* A failed call: it grants nothing, for every entity it was asked about, for
 * the rest of the request; the request says so, and is not cached (AD-10 as
 * amended: a failing grant hook grants nothing and is reported). */
static void callback_failed(GDEFCORE_Request * request,
    const GDEFCORE_Module_Declared_Callback * cb, const char * reason) {
  char text[256];
  int n = snprintf(text, sizeof text, "%.*s.%.*s %s", (int)cb->module_len,
      cb->module, (int)cb->name_len, cb->name, reason);
  if (n > 0) {
    (void)gdefcore_request_set_note(request, kCallbackNote,
        strlen(kCallbackNote), text,
        (size_t)n < sizeof text ? (size_t)n : sizeof text - 1);
  }
  gdefcore_request_mark_uncacheable(request);
}

/* A validity token: printable ASCII, no space. */
static int token_ok(const char * token, size_t len) {
  size_t i;
  if (len == 0 || len > GDEFCORE_CALLBACK_TOKEN_MAX) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    if ((unsigned char)token[i] <= 0x20 || (unsigned char)token[i] >= 0x7f) {
      return 0;
    }
  }
  return 1;
}

/* What a call that answered says of the cache, recorded on the request. */
static void callback_validity(GDEFCORE_Request * request,
    const GDEFCORE_Module_Declared_Callback * cb,
    const GDEFCORE_Callback_Answer * answer) {
  char line[GDEFCORE_CALLBACK_TOKEN_MAX + 200];
  int n = 0;
  if (cb->cache == GDEFCORE_CALLBACK_CACHE_TOKEN) {
    n = snprintf(line, sizeof line, "%.*s.%.*s token %.*s",
        (int)cb->module_len, cb->module, (int)cb->name_len, cb->name,
        (int)answer->token_len, answer->token);
  } else if (cb->cache == GDEFCORE_CALLBACK_CACHE_TTL && cb->ttl_seconds > 0) {
    /* The window of request time the answer holds for: the key moves on
     * every ttl_seconds. */
    int64_t now = gdefcore_request_time(request);
    int64_t window = now >= 0 ? now / (int64_t)cb->ttl_seconds
                              : -((-now + (int64_t)cb->ttl_seconds - 1) /
                                    (int64_t)cb->ttl_seconds);
    n = snprintf(line, sizeof line, "%.*s.%.*s ttl %lu@%lld",
        (int)cb->module_len, cb->module, (int)cb->name_len, cb->name,
        (unsigned long)cb->ttl_seconds, (long long)window);
  }
  if (n <= 0 || (size_t)n >= sizeof line ||
      gdefcore_request_record_validity(request, line, (size_t)n) !=
          GDEFCORE_OK) {
    /* No cacheability declared, or one that cannot be recorded. */
    gdefcore_request_mark_uncacheable(request);
  }
}

/*
 * Ask @p grant's callback whether it grants on ev->id (story A6). Asked once
 * per (callback, principal, acting principal, entity, version) per request:
 * a miss asks about ev->id and, in the same call, about every entity of the
 * request's batch of the same type not answered yet, and remembers each
 * answer. A call that fails grants nothing and is reported; it never marks
 * the evaluation failed, because a grant that grants nothing is no grant, not
 * an undecided one (AD-10 as amended).
 */
static int callback_holds(Eval * ev, const Grant * grant) {
  const GDEFCORE_Module_Declared_Callback * cb = grant->cb;
  GDEFCORE_Request * request = ev->request;
  const char * ids[GDEFCORE_CALLBACK_BATCH_MAX];
  uint64_t versions[GDEFCORE_CALLBACK_BATCH_MAX];
  int granted[GDEFCORE_CALLBACK_BATCH_MAX];
  char key[512];
  int key_len;
  int value = 0;
  size_t n = 0;
  size_t i;
  uint64_t version = 0;
  const char * running = NULL;
  size_t running_len = 0;
  const char * principal = NULL;
  size_t principal_len = 0;
  const char * acting = NULL;
  size_t acting_len = 0;
  GDEFCORE_Callback_Call call;
  GDEFCORE_Callback_Question q;
  GDEFCORE_Callback_Answer a;
  const char * reason = NULL;
  uint64_t start = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  memset(&call, 0, sizeof call);
  memset(&q, 0, sizeof q);
  memset(&a, 0, sizeof a);
  if (cb == NULL || cb->fn == NULL || ev->id == NULL || request == NULL) {
    return 0;
  }
  /* Its answer is about the principal: what renders from it is too. */
  gdefcore_request_mark_principal_dependent(request);
  if (gdefcore_entity_version(ev->catalog, ev->id, GDEFCORE_PUBLIC_ID_LEN,
          &version) != GDEFCORE_OK) {
    return 0;
  }
  key_len = callback_key(key, sizeof key, request, cb, ev->id, version);
  if (key_len > 0 &&
      gdefcore_request_memo_get(request, key, (size_t)key_len, &value)) {
    return value == 1;
  }
  running = gdefcore_request_note(request, kCallbackRunning,
      strlen(kCallbackRunning), &running_len);
  if (running != NULL && same(running, running_len, "1", 1)) {
    /* Asked from inside a callback: it would decide its own question. */
    callback_failed(request, cb, "reentered");
    return 0;
  }
  ids[n] = ev->id;
  versions[n] = version;
  n += 1;
  {
    const char * btype = NULL;
    size_t btype_len = 0;
    size_t nb = gdefcore_request_batch(request, &btype, &btype_len);
    if (nb > 0 && same(btype, btype_len, grant->type_name, grant->type_len)) {
      for (i = 0; i < nb && n < GDEFCORE_CALLBACK_BATCH_MAX; i++) {
        const char * id = gdefcore_request_batch_at(request, i);
        char other[512];
        int other_len;
        int ignored = 0;
        uint64_t v = 0;
        if (id == NULL || same(id, strlen(id), ev->id, GDEFCORE_PUBLIC_ID_LEN) ||
            gdefcore_entity_version(ev->catalog, id, GDEFCORE_PUBLIC_ID_LEN,
                &v) != GDEFCORE_OK) {
          continue;
        }
        other_len = callback_key(other, sizeof other, request, cb, id, v);
        if (other_len > 0 && gdefcore_request_memo_get(request, other,
                                 (size_t)other_len, &ignored)) {
          continue;
        }
        ids[n] = id;
        versions[n] = v;
        n += 1;
      }
    }
  }
  memset(granted, 0, sizeof granted);
  if (gdefcore_request_spend_fuel(request, GDEFCORE_CALLBACK_REQUEST_FUEL) !=
      GDEFCORE_OK) {
    reason = "request-fuel";
  } else {
    uint64_t deadline;
    uint64_t request_deadline = gdefcore_request_deadline_ms(request);
    principal = gdefcore_request_principal(request, &principal_len);
    acting = gdefcore_request_acting_principal(request, &acting_len);
    memset(&q, 0, sizeof q);
    q.size = sizeof q;
    q.module = cb->module;
    q.module_len = cb->module_len;
    q.name = cb->name;
    q.name_len = cb->name_len;
    q.scope = cb->scope;
    q.permission = grant->label;
    q.permission_len = grant->label_len;
    q.action = grant->action;
    q.action_len = grant->action_len;
    q.type_name = grant->type_name;
    q.type_name_len = grant->type_len;
    q.field = grant->field;
    q.field_len = grant->field_len;
    q.principal = principal;
    q.principal_len = principal == NULL ? 0 : principal_len;
    q.acting = acting;
    q.acting_len = acting == NULL ? 0 : acting_len;
    q.entities = ids;
    q.count = n;
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    a.granted = granted;
    a.count = n;
    start = mono_ms();
    deadline = start + cb->timeout_ms;
    if (request_deadline != 0 && request_deadline < deadline) {
      deadline = request_deadline;
    }
    call.fuel = cb->fuel;
    call.over = 0;
    call.deadline_ms = deadline;
    (void)gdefcore_request_set_note(request, kCallbackRunning,
        strlen(kCallbackRunning), "1", 1);
    rc = cb->fn(&call, request, &q, &a, cb->user);
    (void)gdefcore_request_set_note(request, kCallbackRunning,
        strlen(kCallbackRunning), "0", 1);
    if (rc != GDEFCORE_OK) {
      reason = "trapped";
    } else if (call.over) {
      reason = "out-of-fuel";
    } else if (mono_ms() > deadline) {
      reason = "timed-out";
    } else if (a.size != sizeof a || a.granted != granted || a.count != n ||
               a.token_len > GDEFCORE_CALLBACK_TOKEN_MAX ||
               (cb->cache == GDEFCORE_CALLBACK_CACHE_TOKEN &&
                   !token_ok(a.token, a.token_len))) {
      reason = "malformed";
    }
    for (i = 0; reason == NULL && i < n; i++) {
      if (granted[i] != 0 && granted[i] != 1) {
        reason = "malformed";
      }
    }
  }
  if (reason != NULL) {
    callback_failed(request, cb, reason);
    memset(granted, 0, sizeof granted);
  } else {
    callback_validity(request, cb, &a);
  }
  for (i = 0; i < n; i++) {
    char k[512];
    int kl = callback_key(k, sizeof k, request, cb, ids[i], versions[i]);
    if (kl > 0) {
      (void)gdefcore_request_memo_put(request, k, (size_t)kl, granted[i]);
    }
  }
  return granted[0] == 1;
}

static int base_condition_ok(Eval * ev, const Grant * grant,
    const char * actor, size_t actor_len, const char * principal,
    size_t principal_len) {
  if (grant->condition == GDEFCORE_ACCESS_ANY) {
    return 1;
  }
  if (grant->condition == kCondExpr) {
    if (ev == NULL || ev->id == NULL) {
      return 0;
    }
    return expr_holds(ev, grant, ev->id, GDEFCORE_PUBLIC_ID_LEN);
  }
  if (grant->condition == kCondCallback) {
    /* Decided per entity: with none there is nothing to ask about. */
    if (ev == NULL || ev->id == NULL) {
      return 0;
    }
    return callback_holds(ev, grant);
  }
  if (grant->condition != GDEFCORE_ACCESS_OWN) {
    return 0;
  }
  if (actor == NULL || principal == NULL || actor_len == 0 ||
      principal_len == 0) {
    return 0;
  }
  return same(actor, actor_len, principal, principal_len);
}

/* Whether the permission is also within the ceiling of an acting principal:
 * one of its grants for the same permission holds on the same entity, with
 * the request's principal (the person it acts for) as the principal. No
 * ceiling set is no ceiling. */
static int ceiling_allows(Eval * ev, const Grant * grant, const char * actor,
    size_t actor_len, const char * principal, size_t principal_len) {
  size_t i;
  if (ev == NULL || !ev->has_ceiling) {
    return 1;
  }
  for (i = 0; i < ev->nceiling; i++) {
    const Grant * h = &ev->ceiling[i];
    if (same(h->action, h->action_len, grant->action, grant->action_len) &&
        same(h->type_name, h->type_len, grant->type_name, grant->type_len) &&
        same(h->field, h->field_len, grant->field, grant->field_len) &&
        base_condition_ok(ev, h, actor, actor_len, principal, principal_len)) {
      return 1;
    }
  }
  return 0;
}

static int condition_ok(Eval * ev, const Grant * grant, const char * actor,
    size_t actor_len, const char * principal, size_t principal_len) {
  return base_condition_ok(ev, grant, actor, actor_len, principal,
             principal_len) &&
         ceiling_allows(ev, grant, actor, actor_len, principal, principal_len);
}

/*
 * Whether readers may see the entity at all: it is published. The one place
 * this is asked, so that read, list and can(read) cannot disagree about what
 * an unpublished entity is. A grant's condition says who among readers; this
 * says whether there are readers. An answer that cannot be had (the record is
 * unreadable) is a no and marks the evaluation failed, so it is neither
 * remembered nor taken for a plain "no such entity".
 */
static int reader_sees(GDEFCORE_Catalog * catalog, const char * id, Eval * ev) {
  int state = 0;
  if (gdefcore_entity_state(catalog, id, GDEFCORE_PUBLIC_ID_LEN, &state) !=
      GDEFCORE_OK) {
    ev->failed = 1;
    return 0;
  }
  return state == GDEFCORE_STATE_PUBLISHED;
}

static int entity_visible(Eval * ev, const Grant * grants, size_t ngrants,
    const char * type, size_t type_len, const char * actor, size_t actor_len,
    const char * principal, size_t principal_len) {
  size_t i;
  for (i = 0; i < ngrants; i++) {
    if (!same(grants[i].type_name, grants[i].type_len, type, type_len)) {
      continue;
    }
    if (grants[i].field_len != 0 || grants[i].source == kSrcCallback) {
      /* A field grant says nothing of the row, and no callback decides
       * whether an entity is seen (story A6: row scope is refused). */
      continue;
    }
    if (same(grants[i].action, grants[i].action_len, "read", 4) &&
        condition_ok(ev, &grants[i], actor, actor_len, principal,
            principal_len)) {
      return 1;
    }
  }
  return 0;
}

static int field_restricted(const Grant * decls, size_t ndecls,
    const char * type, size_t type_len, const char * field, size_t field_len) {
  size_t i;
  for (i = 0; i < ndecls; i++) {
    if (decls[i].field_len == 0) {
      continue;
    }
    if (same(decls[i].type_name, decls[i].type_len, type, type_len) &&
        same(decls[i].field, decls[i].field_len, field, field_len)) {
      return 1;
    }
  }
  return 0;
}

static int field_granted(Eval * ev, const Grant * grants, size_t ngrants,
    const char * type, size_t type_len, const char * field, size_t field_len,
    const char * actor, size_t actor_len, const char * principal,
    size_t principal_len) {
  size_t i;
  for (i = 0; i < ngrants; i++) {
    if (grants[i].field_len == 0) {
      continue;
    }
    if (!same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        !same(grants[i].field, grants[i].field_len, field, field_len)) {
      continue;
    }
    if (!same(grants[i].action, grants[i].action_len, "read", 4)) {
      continue;
    }
    if (condition_ok(ev, &grants[i], actor, actor_len, principal,
            principal_len)) {
      return 1;
    }
  }
  return 0;
}

/* Whether any grant could let the principal name the field. An expression
 * is decided per entity, so here it only says "possibly". */
static int grant_names_field(const Grant * grants, size_t ngrants,
    const Grant * decls, size_t ndecls, const char * type, size_t type_len,
    const char * field, size_t field_len, const char * principal,
    size_t principal_len) {
  size_t i;
  if (!field_restricted(decls, ndecls, type, type_len, field, field_len)) {
    return 1;
  }
  for (i = 0; i < ngrants; i++) {
    if (!same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        !same(grants[i].field, grants[i].field_len, field, field_len) ||
        !same(grants[i].action, grants[i].action_len, "read", 4)) {
      continue;
    }
    if (grants[i].condition == GDEFCORE_ACCESS_ANY ||
        grants[i].condition == kCondExpr) {
      return 1;
    }
    if (grants[i].condition == GDEFCORE_ACCESS_OWN && principal != NULL &&
        principal_len > 0) {
      return 1;
    }
  }
  return 0;
}

static int may_name_field(Eval * ev, const Grant * grants, size_t ngrants,
    const Grant * decls, size_t ndecls, const char * type, size_t type_len,
    const char * field, size_t field_len, const char * actor, size_t actor_len,
    const char * principal, size_t principal_len) {
  if (!field_restricted(decls, ndecls, type, type_len, field, field_len)) {
    return 1;
  }
  return field_granted(ev, grants, ngrants, type, type_len, field, field_len,
      actor, actor_len, principal, principal_len);
}

/*
 * AD-12: an agent acting for a person runs with the intersection of the two
 * permission sets. When the request names an acting principal other than its
 * principal, load that principal's role grants (its roles and the states) as
 * the ceiling. Module grants are not part of it: a module grant is held by
 * everyone who meets its condition, so counting it for the agent too would
 * let a module grant lift an agent past what its own roles allow. A ceiling
 * that cannot be read allows nothing, and says so.
 */
static GDEFCORE_Result setup_ceiling(Eval * ev) {
  const char * acting;
  size_t acting_len = 0;
  const char * principal;
  size_t principal_len = 0;
  int ignored = 0;
  GDEFCORE_Result rc;
  if (ev->request == NULL) {
    return GDEFCORE_OK;
  }
  acting = gdefcore_request_acting_principal(ev->request, &acting_len);
  principal = gdefcore_request_principal(ev->request, &principal_len);
  if (acting == NULL || acting_len == 0 ||
      same(acting, acting_len, principal, principal_len)) {
    return GDEFCORE_OK;
  }
  ev->has_ceiling = 1;
  ev->ceiling = (Grant *)gcu_allocator_calloc(alloc_default(), kGrantMax,
      sizeof *ev->ceiling);
  if (ev->ceiling == NULL) {
    ev->failed = 1;
    return GDEFCORE_ERR_OOM;
  }
  rc = load_effective_for(ev->catalog, acting, acting_len, ev->ceiling,
      kGrantMax, &ev->nceiling, &ignored, 0);
  if (rc != GDEFCORE_OK) {
    ev->nceiling = 0;
    ev->failed = 1;
  }
  return rc;
}

static StageSlot * find_slot(GDEFCORE_Changeset * changeset, int create) {
  size_t i;
  StageSlot * free_slot = NULL;
  for (i = 0; i < kStageSlots; i++) {
    if (g_stage[i].cs == changeset) {
      return &g_stage[i];
    }
    if (free_slot == NULL && g_stage[i].cs == NULL) {
      free_slot = &g_stage[i];
    }
  }
  if (!create || free_slot == NULL) {
    return NULL;
  }
  memset(free_slot, 0, sizeof *free_slot);
  free_slot->cs = changeset;
  return free_slot;
}

static int line_ok(const char * text, size_t len) {
  size_t i;
  if (text == NULL || len == 0 || len >= kPart) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    if (text[i] == '\n' || text[i] == '\r' || text[i] == '\t' ||
        text[i] == 0x1f) {
      return 0;
    }
  }
  return 1;
}

static GDEFCORE_Result permission_by_label(GDEFCORE_Catalog * catalog,
    const char * label, size_t label_len, char * out_id, Grant * grant,
    char * module_name, size_t module_cap, size_t * module_len) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_entity_ids(catalog, kPermissionType,
      strlen(kPermissionType), &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = GDEFCORE_ERR_INVALID;
  for (i = 0; i < count; i++) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    char ** module = NULL;
    char ** action = NULL;
    char ** condition = NULL;
    char ** type_name = NULL;
    char ** field = NULL;
    size_t * ml = NULL;
    size_t * al = NULL;
    size_t * cl = NULL;
    size_t * tl = NULL;
    size_t * fl = NULL;
    size_t mn = 0;
    size_t an = 0;
    size_t cn = 0;
    size_t tn = 0;
    size_t fn = 0;
    if (read_values(catalog, ids[i], "label", &texts, &lens, &n) !=
            GDEFCORE_OK ||
        !values_have(texts, lens, n, label, label_len)) {
      gdefcore_values_free(catalog, texts, lens, n);
      continue;
    }
    gdefcore_values_free(catalog, texts, lens, n);
    if (read_values(catalog, ids[i], "module", &module, &ml, &mn) !=
            GDEFCORE_OK ||
        mn == 0 ||
        read_values(catalog, ids[i], "action", &action, &al, &an) !=
            GDEFCORE_OK ||
        an == 0 ||
        read_values(catalog, ids[i], "condition", &condition, &cl, &cn) !=
            GDEFCORE_OK ||
        cn == 0 ||
        read_values(catalog, ids[i], "type", &type_name, &tl, &tn) !=
            GDEFCORE_OK ||
        tn == 0) {
      gdefcore_values_free(catalog, module, ml, mn);
      gdefcore_values_free(catalog, action, al, an);
      gdefcore_values_free(catalog, condition, cl, cn);
      gdefcore_values_free(catalog, type_name, tl, tn);
      continue;
    }
    read_values(catalog, ids[i], "field", &field, &fl, &fn);
    memset(grant, 0, sizeof *grant);
    copy_part(grant->label, sizeof grant->label, &grant->label_len, label,
        label_len);
    copy_part(grant->action, sizeof grant->action, &grant->action_len,
        action[0], al[0]);
    copy_part(grant->type_name, sizeof grant->type_name, &grant->type_len,
        type_name[0], tl[0]);
    if (fn > 0) {
      copy_part(grant->field, sizeof grant->field, &grant->field_len, field[0],
          fl[0]);
    }
    if (module_name != NULL) {
      copy_part(module_name, module_cap, module_len, module[0], ml[0]);
    }
    if (cl[0] == 3 && memcmp(condition[0], "own", 3) == 0) {
      grant->condition = GDEFCORE_ACCESS_OWN;
    } else if (cl[0] == 3 && memcmp(condition[0], "any", 3) == 0) {
      grant->condition = GDEFCORE_ACCESS_ANY;
    } else {
      grant->condition = kCondExpr;
    }
    copy_part(grant->module_name, sizeof grant->module_name, &grant->module_len,
        module[0], ml[0]);
    if (out_id != NULL) {
      memcpy(out_id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
    }
    gdefcore_values_free(catalog, module, ml, mn);
    gdefcore_values_free(catalog, action, al, an);
    gdefcore_values_free(catalog, condition, cl, cn);
    gdefcore_values_free(catalog, type_name, tl, tn);
    gdefcore_values_free(catalog, field, fl, fn);
    rc = GDEFCORE_OK;
    break;
  }
  gdefcore_ids_free(catalog, ids, count);
  return rc;
}

static GDEFCORE_Result declare_grant(GDEFCORE_Catalog * catalog,
    const Grant * grant, const char * module_name, size_t module_len,
    const char * expr, size_t expr_len) {
  char existing[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[6];
  const char * texts[6];
  size_t lens[6];
  Grant stored;
  const char * cond;
  size_t cond_len;
  if (permission_by_label(catalog, grant->label, grant->label_len, existing,
          &stored, NULL, 0, NULL) == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  if (grant->condition == kCondExpr) {
    cond = expr;
    cond_len = expr_len;
  } else {
    cond = grant->condition == GDEFCORE_ACCESS_OWN ? kCondOwn : kCondAny;
    cond_len = 3;
  }
  texts[0] = grant->label;
  lens[0] = grant->label_len;
  texts[1] = module_name;
  lens[1] = module_len;
  texts[2] = grant->action;
  lens[2] = grant->action_len;
  texts[3] = cond;
  lens[3] = cond_len;
  texts[4] = grant->type_name;
  lens[4] = grant->type_len;
  value_set(&values[0], "label", &texts[0], &lens[0], 1);
  value_set(&values[1], "module", &texts[1], &lens[1], 1);
  value_set(&values[2], "action", &texts[2], &lens[2], 1);
  value_set(&values[3], "condition", &texts[3], &lens[3], 1);
  value_set(&values[4], "type", &texts[4], &lens[4], 1);
  if (grant->field_len > 0) {
    texts[5] = grant->field;
    lens[5] = grant->field_len;
    value_set(&values[5], "field", &texts[5], &lens[5], 1);
    return create_named(catalog, kPermissionType, values, 6,
        kPermissionConfirm, NULL);
  }
  return create_named(catalog, kPermissionType, values, 5, kPermissionConfirm,
      NULL);
}

static GDEFCORE_Result write_grants(GDEFCORE_Catalog * catalog,
    const char * role_id, const Grant * grants, size_t count) {
  char encoded[kGrantMax][512];
  const char * texts[kGrantMax];
  size_t lens[kGrantMax];
  GDEFCORE_Value value;
  size_t i;
  if (count == 0) {
    texts[0] = kEmptyMark;
    lens[0] = strlen(kEmptyMark);
    value_set(&value, "grant", texts, lens, 1);
    return apply_save(catalog, role_id, &value, 1, kRoleConfirm);
  }
  if (count > kGrantMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < count; i++) {
    int n = encode_grant(encoded[i], sizeof encoded[i], &grants[i]);
    if (n < 0) {
      return GDEFCORE_ERR_LIMIT;
    }
    texts[i] = encoded[i];
    lens[i] = (size_t)n;
  }
  value_set(&value, "grant", texts, lens, count);
  return apply_save(catalog, role_id, &value, 1, kRoleConfirm);
}

/* Whether @p confirmation is the one granting to @p role asks for. */
static int confirm_ok(const char * role, size_t role_len,
    const char * confirmation, size_t confirmation_len) {
  if (same(role, role_len, kAuthenticated, strlen(kAuthenticated))) {
    return same(confirmation, confirmation_len,
        GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
        strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED));
  }
  if (same(role, role_len, kAnonymous, strlen(kAnonymous))) {
    return same(confirmation, confirmation_len,
        GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
        strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS));
  }
  return same(confirmation, confirmation_len, kRoleConfirm,
      strlen(kRoleConfirm));
}

static GDEFCORE_Result grant_role(GDEFCORE_Catalog * catalog, const char * role,
    size_t role_len, const char * label, size_t label_len, int check_confirm,
    const char * confirmation, size_t confirmation_len) {
  char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  Grant grant;
  Grant existing[kGrantMax];
  size_t nexisting = 0;
  size_t i;
  char module_name[kPart];
  size_t module_len = 0;
  GDEFCORE_Result rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (check_confirm &&
      !confirm_ok(role, role_len, confirmation, confirmation_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = permission_by_label(catalog, label, label_len, NULL, &grant, module_name,
      sizeof module_name, &module_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_role(catalog, role, role_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_role_grants(catalog, role_id, existing, kGrantMax, &nexisting);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < nexisting; i++) {
    if (same(existing[i].label, existing[i].label_len, label, label_len)) {
      return GDEFCORE_OK;
    }
  }
  if (nexisting >= kGrantMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  existing[nexisting] = grant;
  copy_part(existing[nexisting].module_name,
      sizeof existing[nexisting].module_name,
      &existing[nexisting].module_len, module_name, module_len);
  nexisting += 1;
  return write_grants(catalog, role_id, existing, nexisting);
}

/* Take @p label away from one role (story A7). */
static GDEFCORE_Result revoke_role(GDEFCORE_Catalog * catalog, const char * role,
    size_t role_len, const char * label, size_t label_len) {
  char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  Grant existing[kGrantMax];
  Grant kept[kGrantMax];
  size_t nexisting = 0;
  size_t nkept = 0;
  size_t i;
  GDEFCORE_Result rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (same(role, role_len, kAdmin, strlen(kAdmin))) {
    /* Admin holds every permission by construction: nothing takes one away. */
    return GDEFCORE_ERR_INVALID;
  }
  rc = find_role(catalog, role, role_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_role_grants(catalog, role_id, existing, kGrantMax, &nexisting);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < nexisting; i++) {
    if (!same(existing[i].label, existing[i].label_len, label, label_len)) {
      kept[nkept++] = existing[i];
    }
  }
  if (nkept == nexisting) {
    return GDEFCORE_OK; /* not held: nothing to take away, nothing written */
  }
  return write_grants(catalog, role_id, kept, nkept);
}

static GDEFCORE_Result admin_holders(GDEFCORE_Catalog * catalog, size_t * out) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc;
  *out = 0;
  rc = gdefcore_entity_ids(catalog, kPrincipalType, strlen(kPrincipalType),
      &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    if (retired_id(catalog, ids[i])) {
      continue;
    }
    rc = read_values(catalog, ids[i], "role", &texts, &lens, &n);
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (values_have(texts, lens, n, kAdmin, strlen(kAdmin))) {
      *out += 1;
    }
    gdefcore_values_free(catalog, texts, lens, n);
  }
  gdefcore_ids_free(catalog, ids, count);
  return GDEFCORE_OK;
}

static GDEFCORE_Result holds_admin(GDEFCORE_Catalog * catalog, const char * id,
    int * out) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  *out = 0;
  if (retired_id(catalog, id)) {
    return GDEFCORE_OK;
  }
  rc = read_values(catalog, id, "role", &texts, &lens, &n);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out = values_have(texts, lens, n, kAdmin, strlen(kAdmin));
  gdefcore_values_free(catalog, texts, lens, n);
  return GDEFCORE_OK;
}

static GDEFCORE_Result canonical_id(const char * id, size_t id_len, char * out) {
  if (gdefcore_id_canonical(id, id_len, out) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  return GDEFCORE_OK;
}

void gdefcore_access_free(GDEFCORE_Catalog * catalog, char ** items,
    size_t count) {
  size_t i;
  if (items == NULL) {
    return;
  }
  for (i = 0; i < count; i++) {
    gdefcore_text_free(catalog, items[i]);
  }
  gcu_allocator_free(alloc_default(), items);
}

GDEFCORE_Result gdefcore_access_roles(GDEFCORE_Catalog * catalog,
    char *** out_names, size_t * out_count) {
  char ** ids = NULL;
  size_t count = 0;
  char ** names = NULL;
  size_t filled = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_names == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_names = NULL;
  *out_count = 0;
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_ids(catalog, kRoleType, strlen(kRoleType), &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  names = (char **)gcu_allocator_calloc(alloc_default(), count > 0 ? count : 1,
      sizeof *names);
  if (names == NULL) {
    gdefcore_ids_free(catalog, ids, count);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < count; i++) {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    if (retired_id(catalog, ids[i])) {
      continue;
    }
    if (read_values(catalog, ids[i], "name", &texts, &lens, &n) != GDEFCORE_OK ||
        n == 0) {
      gdefcore_values_free(catalog, texts, lens, n);
      continue;
    }
    rc = gdefcore_text_dup(catalog, texts[0], lens[0], &names[filled]);
    gdefcore_values_free(catalog, texts, lens, n);
    if (rc != GDEFCORE_OK) {
      gdefcore_access_free(catalog, names, filled);
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    filled += 1;
  }
  gdefcore_ids_free(catalog, ids, count);
  *out_names = names;
  *out_count = filled;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_admin_principal(GDEFCORE_Catalog * catalog,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_id == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_ids(catalog, kPrincipalType, strlen(kPrincipalType),
      &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = GDEFCORE_ERR_INVALID;
  for (i = 0; i < count; i++) {
    int held = 0;
    rc = holds_admin(catalog, ids[i], &held);
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, count);
      return rc;
    }
    if (held) {
      memcpy(out_id, ids[i], GDEFCORE_PUBLIC_ID_LEN + 1);
      rc = GDEFCORE_OK;
      break;
    }
    rc = GDEFCORE_ERR_INVALID;
  }
  gdefcore_ids_free(catalog, ids, count);
  return rc;
}

GDEFCORE_Result gdefcore_access_role_id(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  GDEFCORE_Result rc;
  if (catalog == NULL || out_id == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return find_role(catalog, name, name_len, out_id);
}

GDEFCORE_Result gdefcore_access_role_grants(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, char *** out_labels, size_t * out_count) {
  char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  Grant grants[kGrantMax];
  size_t ngrants = 0;
  char ** labels = NULL;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_labels == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_labels = NULL;
  *out_count = 0;
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_role(catalog, name, name_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_role_grants(catalog, role_id, grants, kGrantMax, &ngrants);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  labels = (char **)gcu_allocator_calloc(alloc_default(),
      ngrants > 0 ? ngrants : 1, sizeof *labels);
  if (labels == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < ngrants; i++) {
    rc = gdefcore_text_dup(catalog, grants[i].label, grants[i].label_len,
        &labels[i]);
    if (rc != GDEFCORE_OK) {
      gdefcore_access_free(catalog, labels, i);
      return rc;
    }
  }
  *out_labels = labels;
  *out_count = ngrants;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_role_create(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  char existing[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value value;
  const char * text;
  size_t text_len;
  GDEFCORE_Result rc;
  if (catalog == NULL || !line_ok(name, name_len) || is_state(name, name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_role(catalog, name, name_len, existing);
  if (rc == GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  if (rc != GDEFCORE_ERR_INVALID) {
    return rc;
  }
  text = name;
  text_len = name_len;
  value_set(&value, "name", &text, &text_len, 1);
  return create_named(catalog, kRoleType, &value, 1, kRoleConfirm, out_id);
}

GDEFCORE_Result gdefcore_access_copy_template(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  Grant grant;
  char role_name[32];
  size_t role_len = 0;
  unsigned n;
  char existing[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[2];
  const char * name_text;
  char encoded[512];
  const char * grant_text;
  size_t grant_len;
  int en;
  GDEFCORE_Result rc;
  if (catalog == NULL || name == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (same(name, name_len, "Moderator", 9) || same(name, name_len, "Usher", 5)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (!same(name, name_len, "Editor", 6)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&grant, 0, sizeof grant);
  copy_part(grant.label, sizeof grant.label, &grant.label_len,
      "Edit own content", strlen("Edit own content"));
  copy_part(grant.action, sizeof grant.action, &grant.action_len, "update", 6);
  copy_part(grant.type_name, sizeof grant.type_name, &grant.type_len,
      "core.node", 9);
  copy_part(grant.module_name, sizeof grant.module_name, &grant.module_len,
      "core", 4);
  grant.condition = GDEFCORE_ACCESS_OWN;
  rc = declare_grant(catalog, &grant, "core", 4, NULL, 0);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (n = 0; n < 1000; n++) {
    if (n == 0) {
      memcpy(role_name, "editor", 6);
      role_len = 6;
      role_name[role_len] = '\0';
    } else {
      en = snprintf(role_name, sizeof role_name, "editor-%u", n + 1);
      if (en <= 0 || (size_t)en >= sizeof role_name) {
        return GDEFCORE_ERR_LIMIT;
      }
      role_len = (size_t)en;
    }
    rc = find_role(catalog, role_name, role_len, existing);
    if (rc == GDEFCORE_OK) {
      continue;
    }
    if (rc != GDEFCORE_ERR_INVALID) {
      return rc;
    }
    break;
  }
  if (n == 1000) {
    return GDEFCORE_ERR_LIMIT;
  }
  en = encode_grant(encoded, sizeof encoded, &grant);
  if (en < 0) {
    return GDEFCORE_ERR_LIMIT;
  }
  name_text = role_name;
  grant_text = encoded;
  grant_len = (size_t)en;
  value_set(&values[0], "name", &name_text, &role_len, 1);
  value_set(&values[1], "grant", &grant_text, &grant_len, 1);
  return create_named(catalog, kRoleType, values, 2, kRoleConfirm, out_id);
}

GDEFCORE_Result gdefcore_access_delete_role(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len) {
  char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value value;
  const char * text = kRetired;
  size_t text_len = strlen(kRetired);
  GDEFCORE_Result rc;
  if (catalog == NULL || is_state(name, name_len) ||
      same(name, name_len, kAdmin, strlen(kAdmin))) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_role(catalog, name, name_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  value_set(&value, "retired", &text, &text_len, 1);
  return apply_save(catalog, role_id, &value, 1, kRoleConfirm);
}

GDEFCORE_Result gdefcore_access_declare(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Permission * permission) {
  Grant grant;
  GDEFCORE_Permission local;
  GDEFCORE_Result rc;
  int has_text;
  char * canon = NULL;
  size_t canon_len = 0;
  if (catalog == NULL || permission == NULL ||
      permission->size != sizeof *permission) {
    return GDEFCORE_ERR_INVALID;
  }
  local = *permission;
  has_text = local.condition_text != NULL && local.condition_text_len > 0;
  if (!line_ok(local.label, local.label_len) ||
      !line_ok(local.module_name, local.module_name_len) ||
      !line_ok(local.action, local.action_len) ||
      !line_ok(local.type_name, local.type_name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (has_text) {
    /* Both set is an error: there is one condition, not a choice of two. */
    if (local.condition != 0) {
      return GDEFCORE_ERR_INVALID;
    }
  } else if (local.condition != GDEFCORE_ACCESS_ANY &&
             local.condition != GDEFCORE_ACCESS_OWN) {
    return GDEFCORE_ERR_INVALID;
  }
  if (local.field_len > 0 && !line_ok(local.field, local.field_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(&grant, 0, sizeof grant);
  if (!copy_part(grant.label, sizeof grant.label, &grant.label_len, local.label,
          local.label_len) ||
      !copy_part(grant.action, sizeof grant.action, &grant.action_len,
          local.action, local.action_len) ||
      !copy_part(grant.type_name, sizeof grant.type_name, &grant.type_len,
          local.type_name, local.type_name_len) ||
      (local.field_len > 0 &&
          !copy_part(grant.field, sizeof grant.field, &grant.field_len,
              local.field, local.field_len)) ||
      !copy_part(grant.module_name, sizeof grant.module_name,
          &grant.module_len, local.module_name, local.module_name_len)) {
    return GDEFCORE_ERR_LIMIT;
  }
  grant.condition = local.condition;
  if (has_text) {
    GDEFCORE_Condition * parsed = NULL;
    /* The expression must parse, name only fields the type has (and none
     * that is personal), and is stored in its canonical form. */
    rc = gdefcore_condition_parse(local.condition_text,
        local.condition_text_len, &parsed, NULL);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_condition_validate(catalog, parsed, local.type_name,
          local.type_name_len, NULL);
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_condition_canonical(parsed, &canon, &canon_len);
    }
    gdefcore_condition_free(parsed);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    grant.condition = kCondExpr;
  }
  rc = declare_grant(catalog, &grant, local.module_name, local.module_name_len,
      canon, canon_len);
  gdefcore_condition_text_free(canon);
  return rc;
}

GDEFCORE_Result gdefcore_access_revoke(GDEFCORE_Catalog * catalog,
    const char * role, size_t role_len, const char * label, size_t label_len) {
  if (catalog == NULL || role == NULL || label == NULL || label_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  return revoke_role(catalog, role, role_len, label, label_len);
}

GDEFCORE_Result gdefcore_access_grant(GDEFCORE_Catalog * catalog,
    const char * role, size_t role_len, const char * label, size_t label_len,
    const char * confirmation, size_t confirmation_len) {
  if (catalog == NULL || role == NULL || label == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  return grant_role(catalog, role, role_len, label, label_len, 1, confirmation,
      confirmation_len);
}

GDEFCORE_Result gdefcore_access_principal_create(GDEFCORE_Catalog * catalog,
    char out_id[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  GDEFCORE_Result rc;
  if (catalog == NULL || out_id == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return gdefcore_entity_create(catalog, kPrincipalType, strlen(kPrincipalType),
      out_id, NULL);
}

static GDEFCORE_Result save_roles(GDEFCORE_Catalog * catalog, const char * id,
    const char * const * roles, const size_t * lens, size_t count) {
  GDEFCORE_Value value;
  const char * mark = kEmptyMark;
  size_t mark_len = strlen(kEmptyMark);
  if (count == 0) {
    value_set(&value, "role", &mark, &mark_len, 1);
  } else {
    value_set(&value, "role", roles, lens, count);
  }
  return apply_save(catalog, id, &value, 1, kPrincipalConfirm);
}

GDEFCORE_Result gdefcore_access_principal_add_role(GDEFCORE_Catalog * catalog,
    const char * principal, size_t principal_len, const char * role,
    size_t role_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  const char * next_texts[8];
  size_t next_lens[8];
  size_t next_n = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || is_state(role, role_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = canonical_id(principal, principal_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_role(catalog, role, role_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = read_values(catalog, id, "role", &texts, &lens, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    if (same(texts[i], lens[i], kEmptyMark, strlen(kEmptyMark))) {
      continue;
    }
    if (same(texts[i], lens[i], role, role_len)) {
      gdefcore_values_free(catalog, texts, lens, count);
      return GDEFCORE_OK;
    }
    if (next_n >= 8) {
      gdefcore_values_free(catalog, texts, lens, count);
      return GDEFCORE_ERR_LIMIT;
    }
    next_texts[next_n] = texts[i];
    next_lens[next_n] = lens[i];
    next_n += 1;
  }
  if (next_n >= 8) {
    gdefcore_values_free(catalog, texts, lens, count);
    return GDEFCORE_ERR_LIMIT;
  }
  next_texts[next_n] = role;
  next_lens[next_n] = role_len;
  next_n += 1;
  rc = save_roles(catalog, id, next_texts, next_lens, next_n);
  gdefcore_values_free(catalog, texts, lens, count);
  return rc;
}

GDEFCORE_Result gdefcore_access_principal_remove_role(
    GDEFCORE_Catalog * catalog, const char * principal, size_t principal_len,
    const char * role, size_t role_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  const char * next_texts[8];
  size_t next_lens[8];
  size_t next_n = 0;
  size_t i;
  int found = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = canonical_id(principal, principal_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (same(role, role_len, kAdmin, strlen(kAdmin))) {
    int held = 0;
    size_t holders = 0;
    rc = holds_admin(catalog, id, &held);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (held) {
      rc = admin_holders(catalog, &holders);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
      if (holders <= 1) {
        return GDEFCORE_ERR_INVALID;
      }
    }
  }
  rc = read_values(catalog, id, "role", &texts, &lens, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < count; i++) {
    if (same(texts[i], lens[i], kEmptyMark, strlen(kEmptyMark))) {
      continue;
    }
    if (same(texts[i], lens[i], role, role_len)) {
      found = 1;
      continue;
    }
    if (next_n >= 8) {
      gdefcore_values_free(catalog, texts, lens, count);
      return GDEFCORE_ERR_LIMIT;
    }
    next_texts[next_n] = texts[i];
    next_lens[next_n] = lens[i];
    next_n += 1;
  }
  if (!found) {
    gdefcore_values_free(catalog, texts, lens, count);
    return GDEFCORE_ERR_INVALID;
  }
  rc = save_roles(catalog, id, next_texts, next_lens, next_n);
  gdefcore_values_free(catalog, texts, lens, count);
  return rc;
}

GDEFCORE_Result gdefcore_access_principal_remove(GDEFCORE_Catalog * catalog,
    const char * principal, size_t principal_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value value;
  const char * text = kRetired;
  size_t text_len = strlen(kRetired);
  GDEFCORE_Result rc;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = canonical_id(principal, principal_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  {
    int held = 0;
    size_t holders = 0;
    rc = holds_admin(catalog, id, &held);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (held) {
      rc = admin_holders(catalog, &holders);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
      if (holders <= 1) {
        return GDEFCORE_ERR_INVALID;
      }
    }
  }
  value_set(&value, "retired", &text, &text_len, 1);
  return apply_save(catalog, id, &value, 1, kPrincipalConfirm);
}

GDEFCORE_Result gdefcore_access_principal_roles(GDEFCORE_Catalog * catalog,
    const char * principal, size_t principal_len, char *** out_roles,
    size_t * out_count) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  char ** roles = NULL;
  size_t filled = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_roles == NULL || out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_roles = NULL;
  *out_count = 0;
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = canonical_id(principal, principal_len, id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = read_values(catalog, id, "role", &texts, &lens, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  roles = (char **)gcu_allocator_calloc(alloc_default(), count > 0 ? count : 1,
      sizeof *roles);
  if (roles == NULL) {
    gdefcore_values_free(catalog, texts, lens, count);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < count; i++) {
    if (same(texts[i], lens[i], kEmptyMark, strlen(kEmptyMark))) {
      continue;
    }
    rc = gdefcore_text_dup(catalog, texts[i], lens[i], &roles[filled]);
    if (rc != GDEFCORE_OK) {
      gdefcore_access_free(catalog, roles, filled);
      gdefcore_values_free(catalog, texts, lens, count);
      return rc;
    }
    filled += 1;
  }
  gdefcore_values_free(catalog, texts, lens, count);
  *out_roles = roles;
  *out_count = filled;
  return GDEFCORE_OK;
}

/* ---- governed fields (story A6) ----------------------------------------- */

int gdefcore_access_field_governed(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, const char * field, size_t field_len) {
  GDEFCORE_Host * host;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  if (catalog == NULL) {
    return 0;
  }
  host = gdefcore_catalog_host(catalog);
  if (host == NULL) {
    return 0;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  return gdefcore_module_field_governed(host, tenant, tenant_len, type,
      type_len, field, field_len, NULL);
}

/* Whether a callback that governs the field opts it in to the locked
 * indicator (access SPEC decision 4). */
static int field_locks(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * field, size_t field_len) {
  GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
  const uint8_t * tenant;
  size_t tenant_len = 0;
  int locked = 0;
  if (host == NULL) {
    return 0;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  return gdefcore_module_field_governed(host, tenant, tenant_len, type,
             type_len, field, field_len, &locked) &&
         locked;
}

/* ---- personal values in the read path (AD-19, story S7) ------------------ */

static int field_is_personal(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * field, size_t field_len);

/*
 * Open one stored personal value for the reader: called only once the field
 * filter has allowed the field. @p out receives the plaintext, or the erased
 * marker, in the catalog's allocation, and @p out_shown 1; a catalog with no
 * subjects bound shows no personal value (never its ciphertext), and
 * @p out_shown is 0. A subject decrypted is recorded on @p request, so a
 * fragment rendered from it depends on that subject.
 */
static GDEFCORE_Result open_for_reader(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * subject, size_t subject_len,
    const char * path, size_t path_len, const char * sealed, size_t sealed_len,
    char ** out, size_t * out_len, int * out_shown, int * out_erased) {
  GDEFCORE_Subjects * subjects = gdefcore_catalog_subjects(catalog);
  char * plain = NULL;
  size_t plain_len = 0;
  int erased = 0;
  GDEFCORE_Result rc;
  *out = NULL;
  *out_len = 0;
  *out_shown = 0;
  *out_erased = 0;
  if (subjects == NULL) {
    return GDEFCORE_OK;
  }
  if (subject == NULL || subject_len == 0) {
    return GDEFCORE_ERR_CORRUPT; /* a personal value is never stored without */
  }
  rc = gdefcore_subject_open_value(subjects, subject, subject_len, path,
      path_len, sealed, sealed_len, &plain, &plain_len, &erased);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_text_dup(catalog, plain, plain_len, out);
  if (plain != NULL && plain_len > 0) {
    gsec_wipe(plain, plain_len);
  }
  gdefcore_subject_free(subjects, plain);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!erased) {
    rc = gdefcore_request_record_subject(request, subject, subject_len);
    if (rc != GDEFCORE_OK) {
      gsec_wipe(*out, plain_len);
      gdefcore_text_free(catalog, *out);
      *out = NULL;
      return rc;
    }
  }
  *out_len = plain_len;
  *out_shown = 1;
  *out_erased = erased;
  return GDEFCORE_OK;
}

/* Free what personal_texts() built before it hands it over: texts of the
 * catalog's, wiped (they are plaintext), in arrays of the default allocator. */
static void plain_texts_free(GDEFCORE_Catalog * catalog, char ** texts,
    size_t * lens, size_t count) {
  size_t i;
  for (i = 0; texts != NULL && i < count; i++) {
    if (texts[i] != NULL && lens != NULL && lens[i] > 0) {
      gsec_wipe(texts[i], lens[i]);
    }
    gdefcore_text_free(catalog, texts[i]);
  }
  gcu_allocator_free(alloc_default(), texts);
  gcu_allocator_free(alloc_default(), lens);
}

/*
 * The values of personal field @p field of the root of @p tree (its own value
 * or the items of a multiple field), each opened for the reader in order
 * (open_for_reader()). No value is ::GDEFCORE_ERR_INVALID, as
 * gdefcore_entity_values() answers a field with none; a catalog with no
 * subjects is a count of 0.
 */
static GDEFCORE_Result personal_texts(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Tree * tree, const char * field,
    size_t field_len, char *** out_texts, size_t ** out_lens,
    size_t * out_count, int * out_all_erased) {
  size_t n = gdefcore_tree_item_count(tree);
  size_t cap = n + 1;
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  size_t seen = 0;
  size_t erased = 0;
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  texts = (char **)gcu_allocator_calloc(alloc_default(), cap, sizeof *texts);
  lens = (size_t *)gcu_allocator_calloc(alloc_default(), cap, sizeof *lens);
  if (texts == NULL || lens == NULL) {
    gcu_allocator_free(alloc_default(), texts);
    gcu_allocator_free(alloc_default(), lens);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    GDEFCORE_TreeItem it;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    rc = gdefcore_tree_item(tree, i, &it);
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (i > 0 && (it.parent != 0 || !same(it.field, it.field_len, field,
                                          field_len))) {
      continue;
    }
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * f = NULL;
      size_t fn = 0;
      const char * text = NULL;
      size_t len = 0;
      const char * sub = NULL;
      size_t sub_len = 0;
      int shown = 0;
      int gone = 0;
      rc = gdefcore_tree_value(tree, i, k, &f, &fn, &text, &len);
      if (rc != GDEFCORE_OK) {
        break;
      }
      if (i == 0 ? !same(f, fn, field, field_len) : fn != 0) {
        continue;
      }
      rc = gdefcore_tree_value_subject(tree, i, k, &sub, &sub_len);
      if (rc == GDEFCORE_OK) {
        seen += 1;
        rc = open_for_reader(catalog, request, sub, sub_len, field, field_len,
            text, len, &texts[count], &lens[count], &shown, &gone);
      }
      if (rc == GDEFCORE_OK && shown) {
        count += 1;
        erased += gone ? 1u : 0u;
      }
    }
  }
  if (rc == GDEFCORE_OK && seen == 0) {
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc != GDEFCORE_OK) {
    plain_texts_free(catalog, texts, lens, count);
    return rc;
  }
  /* The arrays are the default allocator's and the texts the catalog's:
   * gdefcore_values_free() frees both with the catalog's, so the arrays are
   * copied into the catalog's allocation (gdefcore_text_dup() is a copy of
   * bytes in it, whatever they are). */
  {
    char * ct = NULL;
    char * cl = NULL;
    if (count > 0) {
      rc = gdefcore_text_dup(catalog, (const char *)texts, count * sizeof *texts,
          &ct);
      if (rc == GDEFCORE_OK) {
        rc = gdefcore_text_dup(catalog, (const char *)lens,
            count * sizeof *lens, &cl);
      }
      if (rc != GDEFCORE_OK) {
        gdefcore_text_free(catalog, ct);
        for (i = 0; i < count; i++) {
          gsec_wipe(texts[i], lens[i]);
          gdefcore_text_free(catalog, texts[i]);
        }
        gcu_allocator_free(alloc_default(), texts);
        gcu_allocator_free(alloc_default(), lens);
        return rc;
      }
    }
    gcu_allocator_free(alloc_default(), texts);
    gcu_allocator_free(alloc_default(), lens);
    *out_texts = (char **)(void *)ct;
    *out_lens = (size_t *)(void *)cl;
    *out_count = count;
    if (out_all_erased != NULL) {
      *out_all_erased = count > 0 && erased == count;
    }
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_read(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len,
    const char * lang, size_t lang_len, const char * field, size_t field_len,
    char *** out_texts, size_t ** out_lens, size_t * out_count,
    int * out_locked) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type_name = NULL;
  size_t type_len = 0;
  char * actor = NULL;
  size_t actor_len = 0;
  const char * principal = NULL;
  size_t principal_len = 0;
  Grant grants[kGrantMax];
  Grant decls[kGrantMax];
  size_t ngrants = 0;
  size_t ndecls = 0;
  int read_principal = 0;
  Eval ev;
  int visible;
  int granted = 1;
  int personal = 0;
  int has_field = 0;
  GDEFCORE_Result rc;
  if (out_locked != NULL) {
    *out_locked = 0;
  }
  if (catalog == NULL || request == NULL || out_texts == NULL ||
      out_lens == NULL || out_count == NULL || field == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type_name,
      &type_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* `own` is the entity's creator, not whoever wrote the revision readers see. */
  rc = gdefcore_entity_creator(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &actor,
      &actor_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    return rc;
  }
  principal = gdefcore_request_principal(request, &principal_len);
  rc = load_effective(catalog, request, grants, kGrantMax, &ngrants,
      &read_principal);
  if (rc == GDEFCORE_OK) {
    rc = load_decls(catalog, decls, kGrantMax, &ndecls);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return rc;
  }
  eval_init(&ev, catalog, request, lang, lang_len);
  (void)setup_ceiling(&ev);
  ev.id = canon;
  /* An entity readers may not see answers as one that is not there. */
  visible = reader_sees(catalog, canon, &ev) &&
            entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
                actor_len, principal, principal_len);
  if (visible && type_has_field(catalog, type_name, type_len, field,
                     field_len) &&
      field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {
    granted = field_granted(&ev, grants, ngrants, type_name, type_len, field,
        field_len, actor, actor_len, principal, principal_len);
  }
  /* A condition that could not be decided has not granted: it reads as the
   * entity being hidden, which is also what a missing one reads as. */
  eval_done(&ev);
  if (!visible) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return GDEFCORE_ERR_INVALID;
  }
  rc = type_has_field_rc(catalog, type_name, type_len, field, field_len,
      &has_field);
  if (rc != GDEFCORE_OK || !has_field) {
    /* A field the type does not have answers as one the principal may not
     * read, or one with no value: absent (AD-11, AD-25: the answer must not
     * tell a hidden field from a missing one). A failure to find out is an
     * error, never that. */
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    if (rc == GDEFCORE_OK) {
      *out_texts = NULL;
      *out_lens = NULL;
      *out_count = 0;
    }
    return rc;
  }
  if (!granted) {
    *out_texts = NULL;
    *out_lens = NULL;
    *out_count = 0;
    if (out_locked != NULL &&
        field_locks(catalog, type_name, type_len, field, field_len)) {
      /* The field opts in to the locked indicator (story A6): the principal
       * is told a value is there, and never what it is. Read unfiltered only
       * to count, and wiped: the values never leave. */
      char ** held = NULL;
      size_t * held_lens = NULL;
      size_t nheld = 0;
      rc = gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon,
          GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, field_len, &held,
          &held_lens, &nheld);
      if (rc == GDEFCORE_OK) {
        size_t k;
        *out_locked = nheld > 0;
        for (k = 0; k < nheld; k++) {
          if (held[k] != NULL && held_lens[k] > 0) {
            gsec_wipe(held[k], held_lens[k]);
          }
        }
        gdefcore_values_free(catalog, held, held_lens, nheld);
      } else if (rc != GDEFCORE_ERR_INVALID) {
        gdefcore_text_free(catalog, type_name);
        gdefcore_text_free(catalog, actor);
        return rc;
      }
    }
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return GDEFCORE_OK;
  }
  gdefcore_text_free(catalog, actor);
  personal = field_is_personal(catalog, type_name, type_len, field, field_len);
  if (personal) {
    /* Only now, the field allowed, is a personal value decrypted (AD-19,
     * story S7): never its ciphertext. */
    GDEFCORE_Tree * tree = NULL;
    gdefcore_text_free(catalog, type_name);
    rc = gdefcore_entity_tree(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon,
        GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, &tree);
    if (rc == GDEFCORE_OK) {
      rc = personal_texts(catalog, request, tree, field, field_len, out_texts,
          out_lens, out_count, NULL);
    }
    gdefcore_tree_free(tree);
    return rc;
  }
  gdefcore_text_free(catalog, type_name);
  return gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon,
      GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, field_len, out_texts,
      out_lens, out_count);
}

/* What one path of a type reads as to the principal: decided once a read. */
typedef struct PathSeen {
  char path[GDEFCORE_FIELD_PATH_MAX + 1];
  size_t path_len;
  int shown;
  int locked; /* not shown, and its field opts in to the locked indicator */
} PathSeen;

typedef struct TreeFilter {
  Eval * ev;
  const Grant * grants;
  size_t ngrants;
  const Grant * decls;
  size_t ndecls;
  const char * type;
  size_t type_len;
  const char * actor;
  size_t actor_len;
  const char * principal;
  size_t principal_len;
  PathSeen seen[64];
  size_t nseen;
  /* Story S7: the reader's request, and the type's personal paths, whose
   * values are opened once their field is allowed. */
  GDEFCORE_Request * request;
  char (*personal)[GDEFCORE_FIELD_PATH_MAX + 1];
  size_t npersonal;
} TreeFilter;

/* The paths of the type's personal fields, at every depth, into @p f. */
static GDEFCORE_Result personal_paths(GDEFCORE_Catalog * catalog,
    const char * type, size_t type_len, TreeFilter * f) {
  size_t n = 0;
  size_t i;
  GDEFCORE_Result rc = gdefcore_type_tree_field_count(catalog, type, type_len,
      &n);
  if (rc != GDEFCORE_OK || n == 0) {
    return rc;
  }
  f->personal = (char (*)[GDEFCORE_FIELD_PATH_MAX + 1])gcu_allocator_calloc(
      alloc_default(), n, sizeof *f->personal);
  if (f->personal == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    GDEFCORE_FieldInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    rc = gdefcore_type_tree_field(catalog, type, type_len, i, &info);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (info.personal) {
      memcpy(f->personal[f->npersonal], info.path, info.path_len + 1);
      f->npersonal += 1;
    }
  }
  return GDEFCORE_OK;
}

static int personal_path(const TreeFilter * f, const char * path, size_t n) {
  size_t i;
  for (i = 0; i < f->npersonal; i++) {
    if (same(f->personal[i], strlen(f->personal[i]), path, n)) {
      return 1;
    }
  }
  return 0;
}

/* Whether the principal may read the field at @p path: the field-read grants
 * of that field, as gdefcore_access_read() applies them to a field of the
 * root, applied to a field at any depth (story S6d). */
static int path_shown(TreeFilter * f, const char * path, size_t path_len) {
  size_t i;
  int shown;
  for (i = 0; i < f->nseen; i++) {
    if (same(f->seen[i].path, f->seen[i].path_len, path, path_len)) {
      return f->seen[i].shown;
    }
  }
  shown = !field_restricted(f->decls, f->ndecls, f->type, f->type_len, path,
              path_len) ||
          field_granted(f->ev, f->grants, f->ngrants, f->type, f->type_len,
              path, path_len, f->actor, f->actor_len, f->principal,
              f->principal_len);
  if (f->nseen < sizeof f->seen / sizeof f->seen[0] &&
      path_len <= GDEFCORE_FIELD_PATH_MAX) {
    memcpy(f->seen[f->nseen].path, path, path_len);
    f->seen[f->nseen].path_len = path_len;
    f->seen[f->nseen].shown = shown;
    f->seen[f->nseen].locked = !shown && field_locks(f->ev->catalog, f->type,
                                             f->type_len, path, path_len);
    f->nseen += 1;
  }
  return shown;
}

/* Whether a path path_shown() refused opts in to the locked indicator (story
 * A6). Asked after path_shown(), which remembered it. */
static int path_locked(TreeFilter * f, const char * path, size_t path_len) {
  size_t i;
  for (i = 0; i < f->nseen; i++) {
    if (same(f->seen[i].path, f->seen[i].path_len, path, path_len)) {
      return f->seen[i].locked;
    }
  }
  return !path_shown(f, path, path_len) &&
         field_locks(f->ev->catalog, f->type, f->type_len, path, path_len);
}

/* The path of value @p field of an item at @p item_path, in @p buf. */
static size_t value_path(const char * item_path, size_t item_len,
    const char * field, size_t field_len, char * buf, size_t cap) {
  size_t n = item_len + (item_len > 0 && field_len > 0 ? 1 : 0) + field_len;
  if (n >= cap) {
    return 0;
  }
  if (item_len > 0) {
    memcpy(buf, item_path, item_len);
  }
  if (item_len > 0 && field_len > 0) {
    buf[item_len] = '.';
  }
  if (field_len > 0) {
    memcpy(buf + n - field_len, field, field_len);
  }
  buf[n] = '\0';
  return n;
}

/* @p in without what the principal may not read: a hidden field is absent
 * from every item, and a hidden group takes its items with it. */
static GDEFCORE_Result filter_tree(GDEFCORE_Catalog * catalog, TreeFilter * f,
    const GDEFCORE_Tree * in, GDEFCORE_Tree ** out) {
  GDEFCORE_Tree * t = NULL;
  size_t n = gdefcore_tree_item_count(in);
  size_t * map;
  size_t i;
  GDEFCORE_Result rc;
  const size_t kGone = SIZE_MAX;
  *out = NULL;
  map = (size_t *)gcu_allocator_calloc(alloc_default(), n == 0 ? 1 : n,
      sizeof *map);
  if (map == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  rc = gdefcore_tree_create(catalog, &t);
  for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
    GDEFCORE_TreeItem it;
    size_t item = 0;
    size_t k;
    memset(&it, 0, sizeof it);
    it.size = sizeof it;
    rc = gdefcore_tree_item(in, i, &it);
    if (rc != GDEFCORE_OK) {
      break;
    }
    map[i] = kGone;
    if (i > 0) {
      if (map[it.parent] == kGone) {
        continue;
      }
      if (!path_shown(f, it.path, it.path_len)) {
        if (path_locked(f, it.path, it.path_len)) {
          /* An item of a field refused and locked: the field says a value is
           * there, and the item goes with its values (story A6). */
          rc = gdefcore_tree_set_locked(t, map[it.parent], it.field,
              it.field_len);
        }
        continue;
      }
      rc = gdefcore_tree_add(t, map[it.parent], it.field, it.field_len, it.id,
          &item);
      if (rc != GDEFCORE_OK) {
        break;
      }
    }
    map[i] = item;
    for (k = 0; rc == GDEFCORE_OK && k < it.value_count; k++) {
      const char * field = NULL;
      size_t field_len = 0;
      const char * text = NULL;
      size_t len = 0;
      char path[GDEFCORE_FIELD_PATH_MAX + 1];
      size_t pn;
      rc = gdefcore_tree_value(in, i, k, &field, &field_len, &text, &len);
      if (rc != GDEFCORE_OK) {
        break;
      }
      pn = value_path(it.path, it.path_len, field, field_len, path, sizeof path);
      if (pn == 0) {
        rc = GDEFCORE_ERR_CORRUPT;
        break;
      }
      /* An item's own value is its field's, and was decided with the item. */
      if (field_len > 0 && !path_shown(f, path, pn)) {
        if (path_locked(f, path, pn)) {
          /* Refused and locked (story A6): marked, never set. */
          rc = gdefcore_tree_set_locked(t, item, field, field_len);
        }
        continue;
      }
      if (personal_path(f, path, pn)) {
        /* Allowed, so only now opened (AD-19, story S7): the plaintext, or
         * the erased marker, never the ciphertext. */
        const char * sub = NULL;
        size_t sub_len = 0;
        char * plain = NULL;
        size_t plain_len = 0;
        int shown = 0;
        int gone = 0;
        rc = gdefcore_tree_value_subject(in, i, k, &sub, &sub_len);
        if (rc == GDEFCORE_OK) {
          rc = open_for_reader(catalog, f->request, sub, sub_len, path, pn,
              text, len, &plain, &plain_len, &shown, &gone);
        }
        if (rc == GDEFCORE_OK && shown) {
          rc = gdefcore_tree_set(t, item, field, field_len, plain, plain_len);
        }
        if (plain != NULL) {
          gsec_wipe(plain, plain_len);
          gdefcore_text_free(catalog, plain);
        }
        continue;
      }
      rc = gdefcore_tree_set(t, item, field, field_len, text, len);
    }
  }
  gcu_allocator_free(alloc_default(), map);
  if (rc != GDEFCORE_OK) {
    gdefcore_tree_free(t);
    return rc;
  }
  *out = t;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_tree(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len,
    const char * lang, size_t lang_len, GDEFCORE_Tree ** out_tree) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type_name = NULL;
  size_t type_len = 0;
  char * actor = NULL;
  size_t actor_len = 0;
  const char * principal = NULL;
  size_t principal_len = 0;
  Grant grants[kGrantMax];
  Grant decls[kGrantMax];
  size_t ngrants = 0;
  size_t ndecls = 0;
  int read_principal = 0;
  Eval ev;
  int visible;
  GDEFCORE_Tree * full = NULL;
  TreeFilter * filter = NULL;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || out_tree == NULL || lang == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type_name,
      &type_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* `own` is the entity's creator, as for gdefcore_access_read(). */
  rc = gdefcore_entity_creator(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
      &actor, &actor_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    return rc;
  }
  principal = gdefcore_request_principal(request, &principal_len);
  rc = load_effective(catalog, request, grants, kGrantMax, &ngrants,
      &read_principal);
  if (rc == GDEFCORE_OK) {
    rc = load_decls(catalog, decls, kGrantMax, &ndecls);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return rc;
  }
  eval_init(&ev, catalog, request, lang, lang_len);
  (void)setup_ceiling(&ev);
  ev.id = canon;
  /* An entity readers may not see answers as one that is not there: the
   * published flag, then a read grant, as gdefcore_access_read() asks. */
  visible = reader_sees(catalog, canon, &ev);
  if (visible) {
    visible = entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
        actor_len, principal, principal_len);
  }
  if (visible) {
    rc = gdefcore_entity_tree(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon,
        GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, &full);
  } else {
    rc = GDEFCORE_ERR_INVALID;
  }
  if (rc == GDEFCORE_OK) {
    filter = (TreeFilter *)gcu_allocator_calloc(alloc_default(), 1,
        sizeof *filter);
    if (filter == NULL) {
      rc = GDEFCORE_ERR_OOM;
    }
  }
  if (rc == GDEFCORE_OK) {
    filter->ev = &ev;
    filter->grants = grants;
    filter->ngrants = ngrants;
    filter->decls = decls;
    filter->ndecls = ndecls;
    filter->type = type_name;
    filter->type_len = type_len;
    filter->actor = actor;
    filter->actor_len = actor_len;
    filter->principal = principal;
    filter->principal_len = principal_len;
    filter->request = request;
    rc = personal_paths(catalog, type_name, type_len, filter);
    if (rc == GDEFCORE_OK) {
      rc = filter_tree(catalog, filter, full, out_tree);
    }
  }
  /* A condition that could not be decided has not granted: the field reads
   * as hidden, which is also what a missing one reads as. */
  eval_done(&ev);
  if (filter != NULL) {
    gcu_allocator_free(alloc_default(), filter->personal);
  }
  gcu_allocator_free(alloc_default(), filter);
  gdefcore_tree_free(full);
  gdefcore_text_free(catalog, type_name);
  gdefcore_text_free(catalog, actor);
  return rc;
}

/* 1 when the type's field is personal (AD-19). A field the type lacks is not. */
static int field_is_personal(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * field, size_t field_len) {
  size_t count = 0;
  size_t i;
  if (gdefcore_type_field_count(catalog, type, type_len, &count) !=
      GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < count; i++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int personal = 0;
    int match;
    if (gdefcore_type_field(catalog, type, type_len, i, &name, &name_len,
            &required, &many) != GDEFCORE_OK) {
      return 0;
    }
    match = same(name, name_len, field, field_len);
    gdefcore_text_free(catalog, name);
    if (match) {
      return gdefcore_type_field_personal(catalog, type, type_len, i,
                 &personal) == GDEFCORE_OK &&
             personal;
    }
  }
  return 0;
}

/* An answer with no values. Outputs are written only on success. */
static GDEFCORE_Result revision_answer(int * out_status, int status,
    char *** out_texts, size_t ** out_lens, size_t * out_count) {
  *out_status = status;
  *out_texts = NULL;
  *out_lens = NULL;
  *out_count = 0;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_revision_values(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len, uint64_t seq,
    const char * lang, size_t lang_len, const char * field, size_t field_len,
    int * out_status, char *** out_texts, size_t ** out_lens,
    size_t * out_count) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type_name = NULL;
  size_t type_len = 0;
  char * actor = NULL;
  size_t actor_len = 0;
  const char * principal = NULL;
  size_t principal_len = 0;
  Grant grants[kGrantMax];
  Grant decls[kGrantMax];
  size_t ngrants = 0;
  size_t ndecls = 0;
  int read_principal = 0;
  Eval ev;
  int may_view = 0;
  int granted = 1;
  int has_field = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || out_status == NULL ||
      out_texts == NULL || out_lens == NULL || out_count == NULL ||
      field == NULL || lang == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (gdefcore_id_canonical(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type_name,
      &type_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* The question is asked of the entity as it is stored, its current
   * revision: not of the revision being viewed, and not of anything the
   * caller supplies. */
  rc = gdefcore_access_can(catalog, request, GDEFCORE_ACTION_REVISIONS_READ,
      strlen(GDEFCORE_ACTION_REVISIONS_READ), type_name, type_len, canon,
      &may_view);
  if (rc != GDEFCORE_OK || !may_view) {
    /* No permission and no such entity answer alike. */
    gdefcore_text_free(catalog, type_name);
    return GDEFCORE_ERR_INVALID;
  }
  {
    uint64_t head = 0;
    rc = gdefcore_entity_revision(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &head);
    if (rc != GDEFCORE_OK || seq == 0 || seq > head) {
      gdefcore_text_free(catalog, type_name);
      return GDEFCORE_ERR_INVALID;
    }
  }
  rc = type_has_field_rc(catalog, type_name, type_len, field, field_len,
      &has_field);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    return rc;
  }
  if (!has_field) {
    /* A field the type does not have answers as one the principal may not
     * read, or one with no value in that revision: absent. */
    gdefcore_text_free(catalog, type_name);
    return revision_answer(out_status, GDEFCORE_REVISION_ABSENT, out_texts,
        out_lens, out_count);
  }
  rc = gdefcore_entity_creator(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &actor,
      &actor_len);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    return GDEFCORE_ERR_INVALID;
  }
  principal = gdefcore_request_principal(request, &principal_len);
  rc = load_effective(catalog, request, grants, kGrantMax, &ngrants,
      &read_principal);
  if (rc == GDEFCORE_OK) {
    rc = load_decls(catalog, decls, kGrantMax, &ndecls);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return rc;
  }
  eval_init(&ev, catalog, request, lang, lang_len);
  (void)setup_ceiling(&ev);
  ev.id = canon;
  /* The same field-by-field filter as a live read. */
  if (field_restricted(decls, ndecls, type_name, type_len, field, field_len)) {
    granted = field_granted(&ev, grants, ngrants, type_name, type_len, field,
        field_len, actor, actor_len, principal, principal_len);
  }
  eval_done(&ev);
  gdefcore_text_free(catalog, actor);
  if (!granted) {
    gdefcore_text_free(catalog, type_name);
    return revision_answer(out_status, GDEFCORE_REVISION_ABSENT, out_texts,
        out_lens, out_count);
  }
  if (field_is_personal(catalog, type_name, type_len, field, field_len)) {
    /* Never the ciphertext it is stored as. The field allowed, the value of
     * that revision is opened now (story S7): its plaintext, or the erased
     * marker. With no subjects bound it cannot be, and says only that a
     * personal value is there (gdefcore_subject_revision_marker()). */
    GDEFCORE_Tree * tree = NULL;
    int all_erased = 0;
    gdefcore_text_free(catalog, type_name);
    if (gdefcore_catalog_subjects(catalog) == NULL) {
      return revision_answer(out_status, GDEFCORE_REVISION_PERSONAL, out_texts,
          out_lens, out_count);
    }
    rc = gdefcore_entity_revision_tree(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        seq, lang, lang_len, &tree);
    if (rc == GDEFCORE_OK) {
      rc = personal_texts(catalog, request, tree, field, field_len, out_texts,
          out_lens, out_count, &all_erased);
    }
    gdefcore_tree_free(tree);
    if (rc == GDEFCORE_OK) {
      *out_status = all_erased ? GDEFCORE_REVISION_ERASED
                               : GDEFCORE_REVISION_SHOWN;
      return GDEFCORE_OK;
    }
    if (rc == GDEFCORE_ERR_INVALID) {
      /* No value in that revision: the absence a hidden field is. */
      return revision_answer(out_status, GDEFCORE_REVISION_ABSENT, out_texts,
          out_lens, out_count);
    }
    return rc;
  }
  gdefcore_text_free(catalog, type_name);
  rc = gdefcore_entity_revision_values(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
      seq, lang, lang_len, field, field_len, out_texts, out_lens, out_count);
  if (rc == GDEFCORE_OK) {
    *out_status = GDEFCORE_REVISION_SHOWN;
    return GDEFCORE_OK;
  }
  if (rc == GDEFCORE_ERR_INVALID) {
    /* The revision exists (checked above), so this is a field with no value
     * in it: the absence a field the principal may not read is. */
    return revision_answer(out_status, GDEFCORE_REVISION_ABSENT, out_texts,
        out_lens, out_count);
  }
  return rc;
}

/* A field's logical type and scale (entity.h). Text when it cannot be read:
 * the caller has checked the field exists. */
static void field_type_of(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * field, size_t field_len, int * out_type,
    int * out_scale) {
  size_t count = 0;
  size_t i;
  *out_type = GDEFSTOR_FIELD_TEXT;
  *out_scale = 0;
  if (gdefcore_type_field_count(catalog, type, type_len, &count) !=
      GDEFCORE_OK) {
    return;
  }
  for (i = 0; i < count; i++) {
    char * name = NULL;
    size_t name_len = 0;
    int required = 0;
    int many = 0;
    int match;
    if (gdefcore_type_field(catalog, type, type_len, i, &name, &name_len,
            &required, &many) != GDEFCORE_OK) {
      return;
    }
    match = same(name, name_len, field, field_len);
    gdefcore_text_free(catalog, name);
    if (match) {
      if (gdefcore_type_field_type(catalog, type, type_len, i, out_type,
              out_scale) != GDEFCORE_OK) {
        *out_type = GDEFSTOR_FIELD_TEXT;
        *out_scale = 0;
      }
      return;
    }
  }
}

static int texty(int type) {
  return type == GDEFSTOR_FIELD_TEXT || type == GDEFSTOR_FIELD_REFERENCE;
}

/* The list filter: some value of the field is @p want, read in the field's
 * type (a text that is no value of it matches nothing), never the empty-slot
 * mark. As gdefcore_plan_field_is() compiles it. */
static int filter_has(char ** texts, size_t * lens, size_t count, int type,
    int scale, const char * want, size_t want_len) {
  GDEFSTOR_Value w;
  size_t i;
  if (texty(type)) {
    return values_have(texts, lens, count, want, want_len);
  }
  if (same(want, want_len, kEmptyMark, strlen(kEmptyMark)) || want_len == 0 ||
      gdefcore_value_parse(type, scale, want, want_len, &w) != GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < count; i++) {
    GDEFSTOR_Value v;
    if (gdefcore_value_parse(type, scale, texts[i], lens[i], &v) ==
            GDEFCORE_OK &&
        gdefcore_value_compare(&v, &w) == 0) {
      return 1;
    }
  }
  return 0;
}

struct Listed {
  char * id;
  char * key;      /* NULL: the field has no value */
  size_t key_len;
  char * key2;
  size_t key2_len;
  size_t index;
};

/* How a list sorts: each key's field type, and its direction. */
typedef struct ListOrder {
  int type[2];
  int scale[2];
  int desc[2];
} ListOrder;

static void drop_rows(GDEFCORE_Catalog * catalog, struct Listed * rows,
    size_t nrows, char ** ids, size_t count) {
  size_t i;
  for (i = 0; i < nrows; i++) {
    gdefcore_text_free(catalog, rows[i].id);
    gdefcore_text_free(catalog, rows[i].key);
    gdefcore_text_free(catalog, rows[i].key2);
  }
  gcu_allocator_free(alloc_default(), rows);
  gdefcore_ids_free(catalog, ids, count);
}

static int cmp_bytes(const char * a, size_t an, const char * b, size_t bn) {
  size_t n = an < bn ? an : bn;
  int c = n == 0 ? 0 : memcmp(a, b, n);
  if (c != 0) {
    return c < 0 ? -1 : 1;
  }
  return an < bn ? -1 : (an > bn ? 1 : 0);
}

/* One key of two rows, in the field's type: a text or reference by bytes,
 * with no value as the empty text; any other type by value, with no value
 * before every value. As the port sorts a key (query.h "Order and pages"). */
static int key_compare(const char * a, size_t an, const char * b, size_t bn,
    int type, int scale) {
  GDEFSTOR_Value x;
  GDEFSTOR_Value y;
  if (texty(type)) {
    return cmp_bytes(a == NULL ? "" : a, an, b == NULL ? "" : b, bn);
  }
  if (a == NULL || b == NULL) {
    return a == NULL ? (b == NULL ? 0 : -1) : 1;
  }
  if (gdefcore_value_parse(type, scale, a, an, &x) != GDEFCORE_OK ||
      gdefcore_value_parse(type, scale, b, bn, &y) != GDEFCORE_OK) {
    return cmp_bytes(a, an, b, bn);
  }
  return gdefcore_value_compare(&x, &y);
}

/* The order a list has: the first key, then the second, each ascending unless
 * asked otherwise, and last the order the entities were created in. Bytes,
 * not a locale. */
static int listed_before(const struct Listed * a, const struct Listed * b,
    const ListOrder * o) {
  int c = key_compare(a->key, a->key_len, b->key, b->key_len, o->type[0],
      o->scale[0]);
  if (c != 0) {
    return o->desc[0] ? c > 0 : c < 0;
  }
  c = key_compare(a->key2, a->key2_len, b->key2, b->key2_len, o->type[1],
      o->scale[1]);
  if (c != 0) {
    return o->desc[1] ? c > 0 : c < 0;
  }
  return a->index < b->index;
}

/* A merge sort: no comparator context to smuggle through qsort. */
static GDEFCORE_Result listed_sort(struct Listed * rows, size_t n,
    const ListOrder * order) {
  struct Listed * tmp;
  size_t width;
  if (n < 2) {
    return GDEFCORE_OK;
  }
  tmp = (struct Listed *)gcu_allocator_calloc(alloc_default(), n, sizeof *tmp);
  if (tmp == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (width = 1; width < n; width *= 2) {
    size_t lo;
    for (lo = 0; lo < n; lo += 2 * width) {
      size_t mid = lo + width < n ? lo + width : n;
      size_t hi = lo + 2 * width < n ? lo + 2 * width : n;
      size_t a = lo;
      size_t b = mid;
      size_t k = lo;
      while (a < mid && b < hi) {
        if (listed_before(&rows[b], &rows[a], order)) {
          tmp[k++] = rows[b++];
        } else {
          tmp[k++] = rows[a++];
        }
      }
      while (a < mid) {
        tmp[k++] = rows[a++];
      }
      while (b < hi) {
        tmp[k++] = rows[b++];
      }
    }
    memcpy(rows, tmp, n * sizeof *rows);
  }
  gcu_allocator_free(alloc_default(), tmp);
  return GDEFCORE_OK;
}

/* The ids a list returns, in the shape gdefcore_access_free() takes. */
static GDEFCORE_Result copy_ids(GDEFCORE_Catalog * catalog, char ** ids,
    size_t n, char *** out) {
  char ** result = (char **)gcu_allocator_calloc(alloc_default(),
      n > 0 ? n : 1, sizeof *result);
  size_t i;
  if (result == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < n; i++) {
    if (gdefcore_text_dup(catalog, ids[i], strlen(ids[i]), &result[i]) !=
        GDEFCORE_OK) {
      gdefcore_access_free(catalog, result, i);
      return GDEFCORE_ERR_OOM;
    }
  }
  *out = result;
  return GDEFCORE_OK;
}

/*
 * The access filter and the list's own filter, built as a storage query. The
 * entities a principal may see are the published ones for which some read
 * grant of the type holds, as the loop in list_memory() decides one entity at
 * a time; the two must give the same entities, and list_memory() is the one
 * that is the reference. 0 when the plan could be built, else the plan says
 * why (unsupported, or out of memory).
 */
static const GDEFSTOR_QueryNode * grant_base(Eval * ev, GDEFCORE_Plan * plan,
    const Grant * grant) {
  ExprSlot * slot;
  if (grant->condition == GDEFCORE_ACCESS_ANY) {
    return gdefcore_plan_constant(plan, 1);
  }
  if (grant->condition == GDEFCORE_ACCESS_OWN) {
    return gdefcore_plan_creator_is_principal(plan);
  }
  if (grant->condition != kCondExpr) {
    return gdefcore_plan_constant(plan, 0);
  }
  slot = expr_slot(ev, grant);
  if (slot == NULL || slot->bad || slot->cond == NULL) {
    /* An expression that cannot be read has not granted. */
    ev->failed = 1;
    return gdefcore_plan_constant(plan, 0);
  }
  if (slot->suspended) {
    /* Suspended by a governed field (story A7): it covers nothing. */
    return gdefcore_plan_constant(plan, 0);
  }
  return gdefcore_plan_condition(plan, slot->cond);
}

static const GDEFSTOR_QueryNode * access_node(Eval * ev, GDEFCORE_Plan * plan,
    const Grant * grants, size_t ngrants, const char * type, size_t type_len) {
  const GDEFSTOR_QueryNode ** terms;
  size_t nterms = 0;
  size_t i;
  const GDEFSTOR_QueryNode * out;
  terms = (const GDEFSTOR_QueryNode **)gcu_allocator_calloc(alloc_default(),
      ngrants > 0 ? ngrants : 1, sizeof *terms);
  if (terms == NULL) {
    return NULL;
  }
  for (i = 0; i < ngrants; i++) {
    const GDEFSTOR_QueryNode * pair[2];
    const GDEFSTOR_QueryNode * base;
    const GDEFSTOR_QueryNode * ceiling;
    if (!same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        grants[i].field_len != 0 || grants[i].source == kSrcCallback ||
        !same(grants[i].action, grants[i].action_len, "read", 4)) {
      continue;
    }
    base = grant_base(ev, plan, &grants[i]);
    if (base == NULL) {
      gcu_allocator_free(alloc_default(), terms);
      return NULL;
    }
    if (ev->has_ceiling) {
      /* A grant of the acting principal's for the same permission must hold
       * on the same entity too (AD-12). */
      const GDEFSTOR_QueryNode ** alts = (const GDEFSTOR_QueryNode **)
          gcu_allocator_calloc(alloc_default(),
              ev->nceiling > 0 ? ev->nceiling : 1, sizeof *alts);
      size_t n = 0;
      size_t j;
      if (alts == NULL) {
        gcu_allocator_free(alloc_default(), terms);
        return NULL;
      }
      for (j = 0; j < ev->nceiling; j++) {
        const Grant * h = &ev->ceiling[j];
        if (same(h->action, h->action_len, grants[i].action,
                grants[i].action_len) &&
            same(h->type_name, h->type_len, grants[i].type_name,
                grants[i].type_len) &&
            same(h->field, h->field_len, grants[i].field, grants[i].field_len)) {
          alts[n] = grant_base(ev, plan, h);
          if (alts[n] == NULL) {
            gcu_allocator_free(alloc_default(), alts);
            gcu_allocator_free(alloc_default(), terms);
            return NULL;
          }
          n += 1;
        }
      }
      ceiling = gdefcore_plan_or(plan, alts, n);
      gcu_allocator_free(alloc_default(), alts);
      if (ceiling == NULL) {
        gcu_allocator_free(alloc_default(), terms);
        return NULL;
      }
    } else {
      ceiling = gdefcore_plan_constant(plan, 1);
    }
    pair[0] = base;
    pair[1] = ceiling;
    terms[nterms] = gdefcore_plan_and(plan, pair, 2);
    if (terms[nterms] == NULL) {
      gcu_allocator_free(alloc_default(), terms);
      return NULL;
    }
    nterms += 1;
  }
  out = gdefcore_plan_or(plan, terms, nterms);
  gcu_allocator_free(alloc_default(), terms);
  return out;
}

typedef struct ListSpec {
  const GDEFCORE_Access_List * q;   /* the request, with defaults filled */
  uint64_t limit;                    /* 0 for every match */
  const GDEFCORE_Condition * cond;   /* the list's own condition, or NULL */
  int count_only;
} ListSpec;

/* Run the list as a storage query. GDEFCORE_OK with *out_done set when it
 * ran; GDEFCORE_OK with *out_done clear when it could not be compiled or ran
 * over a cap of the query form (the caller evaluates entity by entity);
 * an error otherwise. */
static GDEFCORE_Result list_planned(Eval * ev, GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const ListSpec * spec, const Grant * grants,
    size_t ngrants, const char * principal, size_t principal_len,
    char *** out_ids, size_t * out_count, uint64_t * out_total, int * out_done) {
  const GDEFCORE_Access_List * q = spec->q;
  GDEFCORE_Plan * plan = NULL;
  const GDEFSTOR_QueryNode * parts[4];
  size_t nparts = 0;
  const GDEFSTOR_QueryNode * where;
  const GDEFSTOR_QuerySort * sorts[2];
  GDEFSTOR_QuerySort sort_copy[2];
  size_t nsorts = 0;
  GDEFSTOR_Query sq;
  char ** ids = NULL;
  size_t n = 0;
  uint64_t total = 0;
  GDEFCORE_Result rc;
  *out_done = 0;
  rc = gdefcore_plan_create(catalog, q->type_name, q->type_name_len, ev->lang,
      ev->lang_len, principal, principal_len, gdefcore_request_time(request),
      &plan);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  parts[nparts++] = gdefcore_plan_published(plan);
  parts[nparts++] = access_node(ev, plan, grants, ngrants, q->type_name,
      q->type_name_len);
  if (q->filter_text != NULL && q->filter_field != NULL &&
      q->filter_field_len > 0) {
    parts[nparts++] = gdefcore_plan_field_is(plan, q->filter_field,
        q->filter_field_len, q->filter_text, q->filter_text_len);
  }
  if (spec->cond != NULL) {
    parts[nparts++] = gdefcore_plan_condition(plan, spec->cond);
  }
  if (q->sort_field != NULL && q->sort_field_len > 0) {
    sorts[nsorts] = gdefcore_plan_sort_field(plan, q->sort_field,
        q->sort_field_len, q->sort_descending);
    if (sorts[nsorts] != NULL) {
      sort_copy[nsorts] = *sorts[nsorts];
    }
    nsorts += 1;
  }
  if (q->sort2_field != NULL && q->sort2_field_len > 0) {
    sorts[nsorts] = gdefcore_plan_sort_field(plan, q->sort2_field,
        q->sort2_field_len, q->sort2_descending);
    if (sorts[nsorts] != NULL) {
      sort_copy[nsorts] = *sorts[nsorts];
    }
    nsorts += 1;
  }
  {
    size_t i;
    int built = 1;
    for (i = 0; i < nparts; i++) {
      built = built && parts[i] != NULL;
    }
    for (i = 0; i < nsorts; i++) {
      built = built && sorts[i] != NULL;
    }
    if (!built) {
      rc = gdefcore_plan_oom(plan) ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
      gdefcore_plan_free(plan);
      return rc;
    }
  }
  where = gdefcore_plan_and(plan, parts, nparts);
  if (where == NULL) {
    rc = gdefcore_plan_oom(plan) ? GDEFCORE_ERR_OOM : GDEFCORE_OK;
    gdefcore_plan_free(plan);
    return rc;
  }
  if (gdefcore_plan_failed(plan)) {
    ev->failed = 1;
  }
  /* What the list read of each relation is part of what it shows: noted on the
   * request at the relation's version, as the evaluator does for one entity. */
  {
    size_t r;
    const char * rname;
    size_t rlen;
    for (r = 0; gdefcore_plan_relation_at(plan, r, &rname, &rlen); r++) {
      rc = gdefcore_relation_note_dependency(catalog, request, rname, rlen);
      if (rc != GDEFCORE_OK) {
        gdefcore_plan_free(plan);
        return rc;
      }
    }
  }
  memset(&sq, 0, sizeof sq);
  sq.size = sizeof sq;
  sq.where = where;
  sq.sorts = nsorts > 0 ? sort_copy : NULL;
  sq.sort_count = nsorts;
  /* The port ends in creation order, as gdefcore_entity_ids() lists. */
  sq.language = ev->lang;
  sq.language_len = ev->lang_len;
  sq.offset = spec->count_only ? 0 : q->offset;
  sq.limit = spec->count_only ? 1 : spec->limit;
  rc = gdefcore_entity_query_current(catalog, q->type_name, q->type_name_len,
      &sq, &ids, &n, &total);
  gdefcore_plan_free(plan);
  if (rc == GDEFCORE_ERR_LIMIT) {
    /* More than the query form carries: evaluated entity by entity. */
    return GDEFCORE_OK;
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_total = total;
  *out_count = 0;
  *out_ids = NULL;
  if (!spec->count_only) {
    rc = copy_ids(catalog, ids, n, out_ids);
    if (rc != GDEFCORE_OK) {
      gdefcore_ids_free(catalog, ids, n);
      return rc;
    }
    *out_count = n;
  }
  gdefcore_ids_free(catalog, ids, n);
  *out_done = 1;
  return GDEFCORE_OK;
}

/* The list, entity by entity: the reference. */
static GDEFCORE_Result list_memory(Eval * ev, GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const ListSpec * spec, const Grant * grants,
    size_t ngrants, const Grant * decls, size_t ndecls,
    const char * principal, size_t principal_len, const char ** cond_fields,
    const size_t * cond_field_lens, size_t ncond_fields, char *** out_ids,
    size_t * out_count, uint64_t * out_total) {
  const GDEFCORE_Access_List * local = spec->q;
  char ** ids = NULL;
  size_t count = 0;
  struct Listed * rows = NULL;
  size_t nrows = 0;
  char ** result = NULL;
  size_t i;
  size_t first;
  size_t take;
  GDEFCORE_Result rc;
  int filter_type = GDEFSTOR_FIELD_TEXT;
  int filter_scale = 0;
  rc = gdefcore_entity_ids(catalog, local->type_name, local->type_name_len,
      &ids, &count);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (local->filter_field != NULL && local->filter_field_len > 0) {
    field_type_of(catalog, local->type_name, local->type_name_len,
        local->filter_field, local->filter_field_len, &filter_type,
        &filter_scale);
  }
  rows = (struct Listed *)gcu_allocator_calloc(alloc_default(),
      count > 0 ? count : 1, sizeof *rows);
  if (rows == NULL) {
    gdefcore_ids_free(catalog, ids, count);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < count; i++) {
    char * actor = NULL;
    size_t actor_len = 0;
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    size_t f;
    rc = gdefcore_entity_creator(catalog, ids[i], GDEFCORE_PUBLIC_ID_LEN, &actor,
        &actor_len);
    if (rc != GDEFCORE_OK) {
      drop_rows(catalog, rows, nrows, ids, count);
      return rc;
    }
    ev->id = ids[i];
    /* Not published is not listed: the id of an entity readers may not see
     * must not leak through a list that a direct read refuses. */
    if (!reader_sees(catalog, ids[i], ev) ||
        !entity_visible(ev, grants, ngrants, local->type_name,
            local->type_name_len, actor, actor_len, principal, principal_len)) {
      gdefcore_text_free(catalog, actor);
      continue;
    }
    if ((local->filter_field != NULL && local->filter_field_len > 0 &&
            !may_name_field(ev, grants, ngrants, decls, ndecls,
                local->type_name, local->type_name_len, local->filter_field,
                local->filter_field_len, actor, actor_len, principal,
                principal_len)) ||
        (local->sort_field != NULL && local->sort_field_len > 0 &&
            !may_name_field(ev, grants, ngrants, decls, ndecls,
                local->type_name, local->type_name_len, local->sort_field,
                local->sort_field_len, actor, actor_len, principal,
                principal_len)) ||
        (local->sort2_field != NULL && local->sort2_field_len > 0 &&
            !may_name_field(ev, grants, ngrants, decls, ndecls,
                local->type_name, local->type_name_len, local->sort2_field,
                local->sort2_field_len, actor, actor_len, principal,
                principal_len))) {
      gdefcore_text_free(catalog, actor);
      drop_rows(catalog, rows, nrows, ids, count);
      return GDEFCORE_ERR_INVALID;
    }
    for (f = 0; f < ncond_fields; f++) {
      if (!may_name_field(ev, grants, ngrants, decls, ndecls,
              local->type_name, local->type_name_len, cond_fields[f],
              cond_field_lens[f], actor, actor_len, principal,
              principal_len)) {
        gdefcore_text_free(catalog, actor);
        drop_rows(catalog, rows, nrows, ids, count);
        return GDEFCORE_ERR_INVALID;
      }
    }
    gdefcore_text_free(catalog, actor);
    if (local->filter_text != NULL && local->filter_field != NULL &&
        local->filter_field_len > 0) {
      char field_name[65];
      if (local->filter_field_len >= sizeof field_name) {
        drop_rows(catalog, rows, nrows, ids, count);
        return GDEFCORE_ERR_LIMIT;
      }
      memcpy(field_name, local->filter_field, local->filter_field_len);
      field_name[local->filter_field_len] = '\0';
      rc = read_lang(catalog, ids[i], ev->lang, ev->lang_len, field_name,
          &texts, &lens, &n);
      if (rc != GDEFCORE_OK) {
        gdefcore_values_free(catalog, texts, lens, n);
        drop_rows(catalog, rows, nrows, ids, count);
        return rc;
      }
      if (!filter_has(texts, lens, n, filter_type, filter_scale,
              local->filter_text, local->filter_text_len)) {
        gdefcore_values_free(catalog, texts, lens, n);
        continue;
      }
      gdefcore_values_free(catalog, texts, lens, n);
    }
    if (spec->cond != NULL) {
      GDEFCORE_Condition_Subject subject;
      int failed = 0;
      int holds;
      memset(&subject, 0, sizeof subject);
      subject.size = sizeof subject;
      subject.entity = ids[i];
      subject.entity_len = GDEFCORE_PUBLIC_ID_LEN;
      subject.lang = ev->lang;
      subject.lang_len = ev->lang_len;
      holds = gdefcore_condition_eval(catalog, request, spec->cond, &subject,
          &failed);
      if (failed) {
        ev->failed = 1;
      }
      if (!holds) {
        continue;
      }
    }
    rc = gdefcore_text_dup(catalog, ids[i], strlen(ids[i]), &rows[nrows].id);
    if (rc != GDEFCORE_OK) {
      drop_rows(catalog, rows, nrows, ids, count);
      return rc;
    }
    rows[nrows].index = i;
    {
      const char * sort_fields[2];
      size_t sort_lens[2];
      char ** keys[2];
      size_t * key_lens[2];
      int k;
      sort_fields[0] = local->sort_field;
      sort_lens[0] = local->sort_field_len;
      sort_fields[1] = local->sort2_field;
      sort_lens[1] = local->sort2_field_len;
      keys[0] = &rows[nrows].key;
      keys[1] = &rows[nrows].key2;
      key_lens[0] = &rows[nrows].key_len;
      key_lens[1] = &rows[nrows].key2_len;
      for (k = 0; k < 2; k++) {
        char field_name[65];
        if (sort_fields[k] == NULL || sort_lens[k] == 0) {
          continue;
        }
        if (sort_lens[k] >= sizeof field_name) {
          gdefcore_text_free(catalog, rows[nrows].id);
          drop_rows(catalog, rows, nrows, ids, count);
          return GDEFCORE_ERR_LIMIT;
        }
        memcpy(field_name, sort_fields[k], sort_lens[k]);
        field_name[sort_lens[k]] = '\0';
        rc = read_lang(catalog, ids[i], ev->lang, ev->lang_len, field_name,
            &texts, &lens, &n);
        if (rc != GDEFCORE_OK) {
          gdefcore_values_free(catalog, texts, lens, n);
          gdefcore_text_free(catalog, rows[nrows].id);
          drop_rows(catalog, rows, nrows, ids, count);
          return rc;
        }
        if (n > 0) {
          if (gdefcore_text_dup(catalog, texts[0], lens[0], keys[k]) ==
              GDEFCORE_OK) {
            *key_lens[k] = lens[0];
          }
        }
        gdefcore_values_free(catalog, texts, lens, n);
      }
    }
    nrows += 1;
  }
  gdefcore_ids_free(catalog, ids, count);
  *out_total = nrows;
  if (spec->count_only) {
    drop_rows(catalog, rows, nrows, NULL, 0);
    *out_ids = NULL;
    *out_count = 0;
    return GDEFCORE_OK;
  }
  if (nrows > 1 && ((local->sort_field != NULL && local->sort_field_len > 0) ||
                       (local->sort2_field != NULL &&
                           local->sort2_field_len > 0))) {
    ListOrder order;
    memset(&order, 0, sizeof order);
    order.desc[0] = local->sort_descending;
    order.desc[1] = local->sort2_descending;
    order.type[0] = order.type[1] = GDEFSTOR_FIELD_TEXT;
    if (local->sort_field != NULL && local->sort_field_len > 0) {
      field_type_of(catalog, local->type_name, local->type_name_len,
          local->sort_field, local->sort_field_len, &order.type[0],
          &order.scale[0]);
    }
    if (local->sort2_field != NULL && local->sort2_field_len > 0) {
      field_type_of(catalog, local->type_name, local->type_name_len,
          local->sort2_field, local->sort2_field_len, &order.type[1],
          &order.scale[1]);
    }
    rc = listed_sort(rows, nrows, &order);
    if (rc != GDEFCORE_OK) {
      drop_rows(catalog, rows, nrows, NULL, 0);
      return rc;
    }
  }
  first = local->offset >= nrows ? nrows : (size_t)local->offset;
  take = nrows - first;
  if (spec->limit != 0 && spec->limit < take) {
    take = (size_t)spec->limit;
  }
  result = (char **)gcu_allocator_calloc(alloc_default(), take > 0 ? take : 1,
      sizeof *result);
  if (result == NULL) {
    drop_rows(catalog, rows, nrows, NULL, 0);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < take; i++) {
    result[i] = rows[first + i].id;
    rows[first + i].id = NULL;
  }
  drop_rows(catalog, rows, nrows, NULL, 0);
  *out_ids = result;
  *out_count = take;
  return GDEFCORE_OK;
}

static GDEFCORE_Result list_impl(Eval * ev, GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    int count_only, char *** out_ids, size_t * out_count,
    uint64_t * out_total) {
  GDEFCORE_Access_List local;
  ListSpec spec;
  Grant grants[kGrantMax];
  Grant decls[kGrantMax];
  size_t ngrants = 0;
  size_t ndecls = 0;
  int read_principal = 0;
  const char * principal = NULL;
  size_t principal_len = 0;
  GDEFCORE_Condition * cond = NULL;
  const char * cond_fields[64];
  size_t cond_field_lens[64];
  char * cond_names[64];
  size_t ncond = 0;
  size_t i;
  int restricted = 0;
  int personal = 0;
  uint64_t total = 0;
  int planned = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || query == NULL || out_ids == NULL ||
      out_count == NULL || query->size != sizeof *query) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_ids = NULL;
  *out_count = 0;
  if (out_total != NULL) {
    *out_total = 0;
  }
  local = *query;
  if (local.type_name == NULL || local.type_name_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  principal = gdefcore_request_principal(request, &principal_len);
  rc = load_effective(catalog, request, grants, kGrantMax, &ngrants,
      &read_principal);
  if (rc == GDEFCORE_OK) {
    rc = load_decls(catalog, decls, kGrantMax, &ndecls);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  eval_init(ev, catalog, request, local.lang, local.lang_len);
  (void)setup_ceiling(ev);
  /* A field an access callback governs is not filtered or sorted on by
   * anyone, whoever may read it (story A6): a list would probe it. A
   * condition naming one is refused by its validation below. */
  if (local.filter_field != NULL && local.filter_field_len > 0) {
    if (!type_has_field(catalog, local.type_name, local.type_name_len,
            local.filter_field, local.filter_field_len) ||
        gdefcore_access_field_governed(catalog, local.type_name,
            local.type_name_len, local.filter_field, local.filter_field_len) ||
        !grant_names_field(grants, ngrants, decls, ndecls, local.type_name,
            local.type_name_len, local.filter_field, local.filter_field_len,
            principal, principal_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    restricted |= field_restricted(decls, ndecls, local.type_name,
        local.type_name_len, local.filter_field, local.filter_field_len);
    personal |= field_is_personal(catalog, local.type_name, local.type_name_len,
        local.filter_field, local.filter_field_len);
  }
  if (local.sort_field != NULL && local.sort_field_len > 0) {
    if (!type_has_field(catalog, local.type_name, local.type_name_len,
            local.sort_field, local.sort_field_len) ||
        gdefcore_access_field_governed(catalog, local.type_name,
            local.type_name_len, local.sort_field, local.sort_field_len) ||
        !grant_names_field(grants, ngrants, decls, ndecls, local.type_name,
            local.type_name_len, local.sort_field, local.sort_field_len,
            principal, principal_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    restricted |= field_restricted(decls, ndecls, local.type_name,
        local.type_name_len, local.sort_field, local.sort_field_len);
    personal |= field_is_personal(catalog, local.type_name, local.type_name_len,
        local.sort_field, local.sort_field_len);
  }
  if (local.sort2_field != NULL && local.sort2_field_len > 0) {
    if (!type_has_field(catalog, local.type_name, local.type_name_len,
            local.sort2_field, local.sort2_field_len) ||
        gdefcore_access_field_governed(catalog, local.type_name,
            local.type_name_len, local.sort2_field, local.sort2_field_len) ||
        !grant_names_field(grants, ngrants, decls, ndecls, local.type_name,
            local.type_name_len, local.sort2_field, local.sort2_field_len,
            principal, principal_len)) {
      return GDEFCORE_ERR_INVALID;
    }
    restricted |= field_restricted(decls, ndecls, local.type_name,
        local.type_name_len, local.sort2_field, local.sort2_field_len);
    personal |= field_is_personal(catalog, local.type_name, local.type_name_len,
        local.sort2_field, local.sort2_field_len);
  }
  /* The list's own condition: a written condition (never a principal's own
   * word for what it may see: it narrows the access filter and never widens
   * it) over fields the principal may name. */
  if (local.condition != NULL && local.condition_len > 0) {
    size_t nfields = 0;
    GDEFCORE_Condition_Error err;
    memset(&err, 0, sizeof err);
    err.size = sizeof err;
    if (gdefcore_condition_parse(local.condition, local.condition_len, &cond,
            &err) != GDEFCORE_OK ||
        gdefcore_condition_validate(catalog, cond, local.type_name,
            local.type_name_len, &err) != GDEFCORE_OK) {
      gdefcore_condition_free(cond);
      return GDEFCORE_ERR_INVALID;
    }
    if (gdefcore_type_field_count(catalog, local.type_name, local.type_name_len,
            &nfields) != GDEFCORE_OK) {
      gdefcore_condition_free(cond);
      return GDEFCORE_ERR_INVALID;
    }
    for (i = 0; i < nfields && ncond < 64; i++) {
      char * name = NULL;
      size_t name_len = 0;
      int required = 0;
      int many = 0;
      if (gdefcore_type_field(catalog, local.type_name, local.type_name_len, i,
              &name, &name_len, &required, &many) != GDEFCORE_OK) {
        break;
      }
      if (gdefcore_condition_tests_field(cond, name, name_len)) {
        if (!grant_names_field(grants, ngrants, decls, ndecls, local.type_name,
                local.type_name_len, name, name_len, principal,
                principal_len)) {
          gdefcore_text_free(catalog, name);
          for (i = 0; i < ncond; i++) {
            gdefcore_text_free(catalog, cond_names[i]);
          }
          gdefcore_condition_free(cond);
          return GDEFCORE_ERR_INVALID;
        }
        if (field_restricted(decls, ndecls, local.type_name,
                local.type_name_len, name, name_len)) {
          restricted = 1;
          cond_names[ncond] = name;
          cond_fields[ncond] = name;
          cond_field_lens[ncond] = name_len;
          ncond += 1;
          continue;
        }
      }
      gdefcore_text_free(catalog, name);
    }
  }
  memset(&spec, 0, sizeof spec);
  spec.q = &local;
  spec.cond = cond;
  spec.count_only = count_only;
  spec.limit = local.limit == 0 ? 0
               : (local.limit > GDEFCORE_ACCESS_LIST_MAX_LIMIT
                         ? GDEFCORE_ACCESS_LIST_MAX_LIMIT
                         : local.limit);
  {
    int done = 0;
    rc = GDEFCORE_OK;
    /* A field that only some principals may name is decided entity by
     * entity; so is a personal field's ciphertext, and everything when asked
     * for the reference. */
    if ((local.flags & GDEFCORE_ACCESS_LIST_EVALUATE) == 0 && !restricted &&
        !personal) {
      rc = list_planned(ev, catalog, request, &spec, grants, ngrants, principal,
          principal_len, out_ids, out_count, &total, &done);
    }
    planned = done;
    if (rc == GDEFCORE_OK && !done) {
      rc = list_memory(ev, catalog, request, &spec, grants, ngrants, decls,
          ndecls, principal, principal_len, cond_fields, cond_field_lens, ncond,
          out_ids, out_count, &total);
    }
  }
  for (i = 0; i < ncond; i++) {
    gdefcore_text_free(catalog, cond_names[i]);
  }
  gdefcore_condition_free(cond);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* How this list was answered, for a test or an explain trace to read. */
  (void)gdefcore_request_set_note(request, kListNote, strlen(kListNote),
      planned ? "planned" : "evaluated", planned ? 7 : 9);
  if (!count_only) {
    /* The page is the next batch an access callback is asked about, when
     * its entities are read (story A6). The list itself asks nothing: what
     * is listed and counted is the conditions' alone. */
    (void)gdefcore_request_set_batch(request, local.type_name,
        local.type_name_len, (const char * const *)*out_ids, *out_count);
  }
  if (out_total != NULL) {
    *out_total = total;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_list(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    char *** out_ids, size_t * out_count) {
  Eval ev;
  GDEFCORE_Result rc;
  memset(&ev, 0, sizeof ev);
  rc = list_impl(&ev, catalog, request, query, 0, out_ids, out_count, NULL);
  eval_done(&ev);
  return rc;
}

GDEFCORE_Result gdefcore_access_list_page(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    char *** out_ids, size_t * out_count, uint64_t * out_total) {
  Eval ev;
  GDEFCORE_Result rc;
  if (out_total == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&ev, 0, sizeof ev);
  rc = list_impl(&ev, catalog, request, query, 0, out_ids, out_count,
      out_total);
  eval_done(&ev);
  return rc;
}

GDEFCORE_Result gdefcore_access_count(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    uint64_t * out_total) {
  Eval ev;
  char ** ids = NULL;
  size_t count = 0;
  GDEFCORE_Result rc;
  if (out_total == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&ev, 0, sizeof ev);
  rc = list_impl(&ev, catalog, request, query, 1, &ids, &count, out_total);
  eval_done(&ev);
  return rc;
}

static int sha_hex(const void * data, size_t n, char out[65]) {
  GSEC_Sha256 ctx;
  uint8_t dig[GSEC_SHA256_DIGEST_LEN];
  static const char hexd[] = "0123456789abcdef";
  size_t i;
  if (gsec_sha256_init(&ctx) != GSEC_OK ||
      gsec_sha256_update(&ctx, data, n) != GSEC_OK ||
      gsec_sha256_final(&ctx, dig) != GSEC_OK) {
    return 0;
  }
  for (i = 0; i < GSEC_SHA256_DIGEST_LEN; i++) {
    out[i * 2] = hexd[dig[i] >> 4];
    out[i * 2 + 1] = hexd[dig[i] & 0x0fu];
  }
  out[64] = '\0';
  return 1;
}

static int cmp_cstr(const void * a, const void * b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

static int cmp_dep(const void * a, const void * b) {
  return strcmp((const char *)a, (const char *)b);
}

/* A digest of the (entity, revision) pairs the request recorded, order
 * ignored, or 0 when it recorded none. A set that overflowed says so, and
 * then differs from every set that did not. */
static int deps_digest(const GDEFCORE_Request * request, char out[80]) {
  size_t n = gdefcore_request_dependency_count(request);
  size_t i;
  char (*lines)[GDEFCORE_PUBLIC_ID_LEN + 24];
  char hex[65];
  int overflow = gdefcore_request_dependencies_overflowed(request);
  if (n == 0 && !overflow) {
    return 0;
  }
  lines = (char (*)[GDEFCORE_PUBLIC_ID_LEN + 24])gcu_allocator_calloc(
      alloc_default(), n == 0 ? 1 : n, sizeof *lines);
  if (lines == NULL) {
    snprintf(out, 80, "unreadable");
    return 1;
  }
  for (i = 0; i < n; i++) {
    const char * id = NULL;
    size_t id_len = 0;
    uint64_t revision = 0;
    (void)gdefcore_request_dependency_at(request, i, &id, &id_len, &revision);
    snprintf(lines[i], sizeof lines[i], "%.*s@%llu\n", (int)id_len, id,
        (unsigned long long)revision);
  }
  if (n > 1) {
    qsort(lines, n, sizeof *lines, cmp_dep);
  }
  {
    GSEC_Sha256 ctx;
    uint8_t dig[GSEC_SHA256_DIGEST_LEN];
    static const char hexd[] = "0123456789abcdef";
    int ok = gsec_sha256_init(&ctx) == GSEC_OK;
    for (i = 0; ok && i < n; i++) {
      ok = gsec_sha256_update(&ctx, lines[i], strlen(lines[i])) == GSEC_OK;
    }
    ok = ok && gsec_sha256_final(&ctx, dig) == GSEC_OK;
    if (!ok) {
      gcu_allocator_free(alloc_default(), lines);
      snprintf(out, 80, "unreadable");
      return 1;
    }
    for (i = 0; i < GSEC_SHA256_DIGEST_LEN; i++) {
      hex[i * 2] = hexd[dig[i] >> 4];
      hex[i * 2 + 1] = hexd[dig[i] & 0x0fu];
    }
    hex[64] = '\0';
  }
  gcu_allocator_free(alloc_default(), lines);
  snprintf(out, 80, "%s%s", hex, overflow ? "+overflow" : "");
  return 1;
}

/* A digest of the validity lines the request recorded (story A6), order
 * ignored, or 0 when it recorded none. */
static int validity_digest(const GDEFCORE_Request * request, char out[80]) {
  size_t n = gdefcore_request_validity_count(request);
  size_t i;
  const char ** lines;
  size_t * lens;
  GSEC_Sha256 ctx;
  uint8_t dig[GSEC_SHA256_DIGEST_LEN];
  static const char hexd[] = "0123456789abcdef";
  int ok;
  if (n == 0) {
    return 0;
  }
  lines = (const char **)gcu_allocator_calloc(alloc_default(), n,
      sizeof *lines);
  lens = (size_t *)gcu_allocator_calloc(alloc_default(), n, sizeof *lens);
  if (lines == NULL || lens == NULL) {
    gcu_allocator_free(alloc_default(), lines);
    gcu_allocator_free(alloc_default(), lens);
    snprintf(out, 80, "unreadable");
    return 1;
  }
  for (i = 0; i < n; i++) {
    (void)gdefcore_request_validity_at(request, i, &lines[i], &lens[i]);
  }
  /* An insertion sort by bytes: few lines, and no context for qsort. */
  for (i = 1; i < n; i++) {
    size_t j = i;
    while (j > 0 && cmp_bytes(lines[j - 1], lens[j - 1], lines[j], lens[j]) >
                        0) {
      const char * t = lines[j];
      size_t tl = lens[j];
      lines[j] = lines[j - 1];
      lens[j] = lens[j - 1];
      lines[j - 1] = t;
      lens[j - 1] = tl;
      j -= 1;
    }
  }
  ok = gsec_sha256_init(&ctx) == GSEC_OK;
  for (i = 0; ok && i < n; i++) {
    ok = gsec_sha256_update(&ctx, lines[i], lens[i]) == GSEC_OK &&
         gsec_sha256_update(&ctx, "\n", 1) == GSEC_OK;
  }
  ok = ok && gsec_sha256_final(&ctx, dig) == GSEC_OK;
  gcu_allocator_free(alloc_default(), lines);
  gcu_allocator_free(alloc_default(), lens);
  if (!ok) {
    snprintf(out, 80, "unreadable");
    return 1;
  }
  for (i = 0; i < GSEC_SHA256_DIGEST_LEN; i++) {
    out[i * 2] = hexd[dig[i] >> 4];
    out[i * 2 + 1] = hexd[dig[i] & 0x0fu];
  }
  out[64] = '\0';
  return 1;
}

GDEFCORE_Result gdefcore_access_render_key(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * overlay, size_t overlay_len,
    const uint8_t * module_bytes, size_t module_len, char ** out_key,
    size_t * out_len) {
  Grant grants[kGrantMax];
  size_t ngrants = 0;
  int read_principal = 0;
  const char * principal = NULL;
  size_t principal_len = 0;
  const uint8_t * tenant = NULL;
  size_t tenant_len = 0;
  uint64_t epoch = 0;
  char perm_hex[65];
  char module_hex[65];
  char deps_hex[80];
  char validity_hex[80];
  char * lines[kGrantMax];
  size_t nlines = 0;
  char * blob = NULL;
  size_t blob_n = 0;
  size_t blob_cap = 0;
  char * key = NULL;
  size_t key_n = 0;
  size_t key_cap = 0;
  size_t i;
  const char * overlay_text = "live";
  size_t overlay_text_len = 4;
  const char * principal_text = "-";
  size_t principal_text_len = 1;
  const char * module_text = "-";
  int time_dependent = 0;
  Eval ev;
  GDEFCORE_Result rc;
  memset(&ev, 0, sizeof ev);
  if (catalog == NULL || request == NULL || out_key == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (overlay != NULL && overlay_len > 0) {
    for (i = 0; i < overlay_len; i++) {
      if (overlay[i] == '\n') {
        return GDEFCORE_ERR_INVALID;
      }
    }
    overlay_text = overlay;
    overlay_text_len = overlay_len;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = load_effective(catalog, request, grants, kGrantMax, &ngrants,
      &read_principal);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_epoch(catalog, &epoch);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  principal = gdefcore_request_principal(request, &principal_len);
  eval_init(&ev, catalog, request, NULL, 0);
  (void)setup_ceiling(&ev);
  for (i = 0; i < ngrants; i++) {
    if (grants[i].condition == kCondExpr) {
      /* An expression that reads the principal, or that cannot be read at
       * all, makes the render depend on who is asking. One that reads the
       * time (`now`), or cannot be read, makes it depend on when (story A7:
       * a grant that expires must not be served from a fragment kept before
       * it did). */
      ExprSlot * slot = expr_slot(&ev, &grants[i]);
      if (slot == NULL || slot->bad ||
          (gdefcore_condition_uses(slot->cond) &
              GDEFCORE_CONDITION_USES_PRINCIPAL) != 0) {
        read_principal = 1;
      }
      if (slot == NULL || slot->bad ||
          (gdefcore_condition_uses(slot->cond) &
              GDEFCORE_CONDITION_USES_TIME) != 0) {
        time_dependent = 1;
      }
    }
  }
  /* The acting principal's grants are part of the answer too. */
  for (i = 0; ev.has_ceiling && i < ev.nceiling; i++) {
    if (ev.ceiling[i].condition == kCondExpr) {
      ExprSlot * slot = expr_slot(&ev, &ev.ceiling[i]);
      if (slot == NULL || slot->bad ||
          (gdefcore_condition_uses(slot->cond) &
              GDEFCORE_CONDITION_USES_TIME) != 0) {
        time_dependent = 1;
      }
    }
  }
  if ((read_principal || gdefcore_request_principal_dependent(request)) &&
      principal != NULL && principal_len > 0) {
    principal_text = principal;
    principal_text_len = principal_len;
  }
  for (i = 0; i < ngrants; i++) {
    char line[512];
    char cond_text[GDEFCORE_CONDITION_HASH_LEN + 8];
    int n;
    char * copy;
    if (grants[i].condition == kCondExpr) {
      /* The key names the expression by the hash of its canonical text, so
       * a changed condition is a changed key. One that cannot be read is
       * keyed apart from every readable one. */
      ExprSlot * slot = expr_slot(&ev, &grants[i]);
      char * canon = NULL;
      size_t canon_len = 0;
      snprintf(cond_text, sizeof cond_text, "expr:?");
      if (slot != NULL && !slot->bad &&
          gdefcore_condition_canonical(slot->cond, &canon, &canon_len) ==
              GDEFCORE_OK) {
        char hash[GDEFCORE_CONDITION_HASH_LEN + 1];
        if (gdefcore_condition_hash(canon, canon_len, hash, NULL) ==
            GDEFCORE_OK) {
          snprintf(cond_text, sizeof cond_text, "expr:%s", hash);
        }
      }
      gdefcore_condition_text_free(canon);
    } else if (grants[i].condition == kCondCallback) {
      /* A callback is named; what it answered is the validity line below. */
      snprintf(cond_text, sizeof cond_text, "cb:%.*s.%.*s",
          (int)(grants[i].cb->module_len > 32 ? 32 : grants[i].cb->module_len),
          grants[i].cb->module,
          (int)(grants[i].cb->name_len > 32 ? 32 : grants[i].cb->name_len),
          grants[i].cb->name);
    } else {
      snprintf(cond_text, sizeof cond_text, "%s",
          grants[i].condition == GDEFCORE_ACCESS_OWN ? kCondOwn : kCondAny);
    }
    n = snprintf(line, sizeof line, "%.*s\t%s\t%.*s\t%.*s\t%.*s\n",
        (int)grants[i].label_len, grants[i].label, cond_text,
        (int)grants[i].type_len, grants[i].type_name,
        (int)grants[i].field_len, grants[i].field, (int)grants[i].action_len,
        grants[i].action);
    if (n <= 0 || (size_t)n >= sizeof line) {
      rc = GDEFCORE_ERR_LIMIT;
      goto done;
    }
    copy = (char *)gcu_allocator_malloc(alloc_default(), (size_t)n + 1);
    if (copy == NULL) {
      rc = GDEFCORE_ERR_OOM;
      goto done;
    }
    memcpy(copy, line, (size_t)n + 1);
    lines[nlines++] = copy;
  }
  if (nlines > 1) {
    qsort(lines, nlines, sizeof *lines, cmp_cstr);
  }
  for (i = 0; i < nlines; i++) {
    size_t ln;
    char * next;
    if (i > 0 && strcmp(lines[i], lines[i - 1]) == 0) {
      continue;
    }
    ln = strlen(lines[i]);
    if (blob_n + ln + 1 > blob_cap) {
      size_t cap = blob_cap == 0 ? 256 : blob_cap * 2;
      while (cap < blob_n + ln + 1) {
        cap *= 2;
      }
      next = (char *)gcu_allocator_realloc(alloc_default(), blob, cap);
      if (next == NULL) {
        rc = GDEFCORE_ERR_OOM;
        goto done;
      }
      blob = next;
      blob_cap = cap;
    }
    memcpy(blob + blob_n, lines[i], ln);
    blob_n += ln;
  }
  if (!sha_hex(blob == NULL ? "" : blob, blob_n, perm_hex)) {
    rc = GDEFCORE_ERR_INTERNAL;
    goto done;
  }
  if (module_bytes != NULL) {
    if (!sha_hex(module_bytes, module_len, module_hex)) {
      rc = GDEFCORE_ERR_INTERNAL;
      goto done;
    }
    module_text = module_hex;
  }
  {
    char tenant_hex[512];
    size_t hex_n = 0;
    char epoch_text[32];
    int en;
    if (tenant_len * 2 + 1 > sizeof tenant_hex) {
      rc = GDEFCORE_ERR_LIMIT;
      goto done;
    }
    for (i = 0; i < tenant_len; i++) {
      static const char hexd[] = "0123456789abcdef";
      tenant_hex[hex_n++] = hexd[tenant[i] >> 4];
      tenant_hex[hex_n++] = hexd[tenant[i] & 0x0fu];
    }
    tenant_hex[hex_n] = '\0';
    en = snprintf(epoch_text, sizeof epoch_text, "%llu",
        (unsigned long long)epoch);
    if (en <= 0) {
      rc = GDEFCORE_ERR_LIMIT;
      goto done;
    }
#define ADD_KEY(text, n)                                                       \
  do {                                                                         \
    char * next;                                                               \
    if (key_n + (n) + 1 > key_cap) {                                           \
      size_t cap = key_cap == 0 ? 256 : key_cap * 2;                           \
      while (cap < key_n + (n) + 1) {                                          \
        cap *= 2;                                                              \
      }                                                                        \
      next = (char *)gcu_allocator_realloc(alloc_default(), key, cap);        \
      if (next == NULL) {                                                      \
        rc = GDEFCORE_ERR_OOM;                                                 \
        goto done;                                                             \
      }                                                                        \
      key = next;                                                              \
      key_cap = cap;                                                           \
    }                                                                          \
    memcpy(key + key_n, (text), (n));                                          \
    key_n += (n);                                                              \
    key[key_n] = '\0';                                                         \
  } while (0)
    ADD_KEY("tenant:", 7);
    ADD_KEY(tenant_hex, hex_n);
    ADD_KEY("\nepoch:", 7);
    ADD_KEY(epoch_text, (size_t)en);
    ADD_KEY("\nedition:\npermissions:", 22);
    ADD_KEY(perm_hex, 64);
    ADD_KEY("\noverlay:", 9);
    ADD_KEY(overlay_text, overlay_text_len);
    ADD_KEY("\nprincipal:", 11);
    ADD_KEY(principal_text, principal_text_len);
    if (ev.has_ceiling) {
      /* The answer is the intersection with the acting principal's grants. */
      size_t acting_len = 0;
      const char * acting = gdefcore_request_acting_principal(request,
          &acting_len);
      ADD_KEY("\nacting:", 8);
      ADD_KEY(acting, acting_len);
    }
    if (time_dependent) {
      /* The answer changes with the clock, not with anything written. */
      char time_text[32];
      int tn = snprintf(time_text, sizeof time_text, "%lld",
          (long long)gdefcore_request_time(request));
      if (tn <= 0 || (size_t)tn >= sizeof time_text) {
        rc = GDEFCORE_ERR_LIMIT;
        goto done;
      }
      ADD_KEY("\ntime:", 6);
      ADD_KEY(time_text, (size_t)tn);
    }
    ADD_KEY("\nmodule:", 8);
    ADD_KEY(module_text, strlen(module_text));
    if (deps_digest(request, deps_hex)) {
      /* What the request read of entities: a different revision of any is a
       * different key. */
      ADD_KEY("\nreads:", 7);
      ADD_KEY(deps_hex, strlen(deps_hex));
    }
    if (validity_digest(request, validity_hex)) {
      /* What the access callbacks it consulted said (story A6): a changed
       * validity token, or the next window of a time to live, is a different
       * key. */
      ADD_KEY("\ncallbacks:", 11);
      ADD_KEY(validity_hex, strlen(validity_hex));
    }
    if (!gdefcore_request_cacheable(request)) {
      /* A callback that declares no cacheability, or one that failed: the
       * key is for no cache (gdefcore_fragment_put() refuses it). */
      ADD_KEY("\ncache:none", 11);
    }
    ADD_KEY("\n", 1);
#undef ADD_KEY
  }
  rc = gdefcore_text_dup(catalog, key, key_n, out_key);
  if (rc == GDEFCORE_OK && out_len != NULL) {
    *out_len = key_n;
  }
done:
  eval_done(&ev);
  for (i = 0; i < nlines; i++) {
    gcu_allocator_free(alloc_default(), lines[i]);
  }
  gcu_allocator_free(alloc_default(), blob);
  gcu_allocator_free(alloc_default(), key);
  return rc;
}

/* Whether an expression grant could apply to something: to a hypothetical
 * entity of its type (which has no state, actor or values), or to a real one. */
static int expr_could_apply(Eval * ev, const Grant * grant) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  int holds = 0;
  if (expr_holds(ev, grant, NULL, 0)) {
    return 1;
  }
  if (ev->failed) {
    return 0;
  }
  if (gdefcore_entity_ids(ev->catalog, grant->type_name, grant->type_len, &ids,
          &count) != GDEFCORE_OK) {
    ev->failed = 1;
    return 0;
  }
  for (i = 0; i < count && !holds; i++) {
    holds = expr_holds(ev, grant, ids[i], strlen(ids[i]));
  }
  gdefcore_ids_free(ev->catalog, ids, count);
  return holds;
}

/* Whether one of @p grants for @p permission holds, or could. An int
 * condition is held as it always was: the permission is not about one entity.
 * An expression is held when it could apply to something. */
static long permits_at(Eval * ev, const Grant * grants, size_t ngrants,
    const char * permission, size_t permission_len, const char * type,
    size_t type_len) {
  size_t i;
  for (i = 0; i < ngrants; i++) {
    if (!same(grants[i].action, grants[i].action_len, permission,
            permission_len)) {
      continue;
    }
    if (type != NULL && (grants[i].field_len != 0 ||
            !same(grants[i].type_name, grants[i].type_len, type, type_len))) {
      continue;
    }
    if (grants[i].condition == kCondCallback) {
      /* Decided per entity, and there is none to ask about (story A6). */
      continue;
    }
    if (grants[i].condition != kCondExpr || expr_could_apply(ev, &grants[i])) {
      return (long)i;
    }
  }
  return -1;
}

static int permits_in(Eval * ev, const Grant * grants, size_t ngrants,
    const char * permission, size_t permission_len, const char * type,
    size_t type_len) {
  return permits_at(ev, grants, ngrants, permission, permission_len, type,
             type_len) >= 0;
}

int gdefcore_access_permits(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * permission, size_t permission_len) {
  Grant grants[kGrantMax];
  size_t ngrants = 0;
  int read_principal = 0;
  int held = 0;
  Eval ev;
  if (catalog == NULL || request == NULL || permission == NULL ||
      permission_len == 0) {
    return 0;
  }
  if (ensure(catalog) != GDEFCORE_OK) {
    return 0;
  }
  if (load_effective(catalog, request, grants, kGrantMax, &ngrants,
          &read_principal) != GDEFCORE_OK) {
    return 0;
  }
  eval_init(&ev, catalog, request, NULL, 0);
  (void)setup_ceiling(&ev);
  held = permits_in(&ev, grants, ngrants, permission, permission_len, NULL, 0);
  if (held && ev.has_ceiling) {
    /* The intersection: the acting principal must hold it too. */
    held = permits_in(&ev, ev.ceiling, ev.nceiling, permission, permission_len,
        NULL, 0);
  }
  eval_done(&ev);
  return held;
}

int gdefcore_access_shared_cache(const char * overlay, size_t overlay_len) {
  if (overlay == NULL || overlay_len == 0) {
    return 1;
  }
  return overlay_len == 4 && memcmp(overlay, "live", 4) == 0;
}

GDEFCORE_Result gdefcore_access_stage_module_permission(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len, const char * label, size_t label_len,
    const char * action, size_t action_len, int condition,
    const char * type_name, size_t type_name_len, const char * field,
    size_t field_len) {
  StageSlot * slot;
  StagePerm * perm;
  GDEFCORE_Result rc;
  if (changeset == NULL || !line_ok(module_name, module_name_len) ||
      !line_ok(label, label_len) || !line_ok(action, action_len) ||
      !line_ok(type_name, type_name_len) ||
      (condition != GDEFCORE_ACCESS_ANY && condition != GDEFCORE_ACCESS_OWN)) {
    return GDEFCORE_ERR_INVALID;
  }
  if (field_len > 0 && !line_ok(field, field_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  slot = find_slot(changeset, 1);
  if (slot == NULL || slot->n >= kStageMax) {
    return GDEFCORE_ERR_LIMIT;
  }
  perm = &slot->perms[slot->n];
  memset(perm, 0, sizeof *perm);
  if (!copy_part(perm->label, sizeof perm->label, &perm->label_len, label,
          label_len) ||
      !copy_part(perm->module_name, sizeof perm->module_name, &perm->module_len,
          module_name, module_name_len) ||
      !copy_part(perm->action, sizeof perm->action, &perm->action_len, action,
          action_len) ||
      !copy_part(perm->type_name, sizeof perm->type_name, &perm->type_len,
          type_name, type_name_len) ||
      (field_len > 0 &&
          !copy_part(perm->field, sizeof perm->field, &perm->field_len, field,
              field_len))) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = gdefcore_changeset_add_confirm_line(changeset, label, label_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  perm->condition = condition;
  slot->n += 1;
  return GDEFCORE_OK;
}

void gdefcore_access_clear_staged(GDEFCORE_Changeset * changeset) {
  StageSlot * slot;
  if (changeset == NULL) {
    return;
  }
  slot = find_slot(changeset, 0);
  if (slot != NULL) {
    memset(slot, 0, sizeof *slot);
  }
}

GDEFCORE_Result gdefcore_access_commit_staged(GDEFCORE_Changeset * changeset) {
  StageSlot * slot;
  StagePerm local[kStageMax];
  size_t n = 0;
  size_t i;
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (changeset == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  if (g_committing) {
    return GDEFCORE_OK;
  }
  slot = find_slot(changeset, 0);
  if (slot == NULL || slot->n == 0) {
    return GDEFCORE_OK;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  /* The permission and role types exist only once the tenant is seeded. A
   * module enabled on a tenant nothing had asked about yet would otherwise
   * have its permissions refused after the enable had been committed. */
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  {
    int risk = 0;
    rc = gdefcore_changeset_rate(changeset, &risk);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (risk != GDEFCORE_RISK_HIGH) {
      memset(slot, 0, sizeof *slot);
      return GDEFCORE_OK;
    }
  }
  n = slot->n;
  memcpy(local, slot->perms, n * sizeof *local);
  memset(slot, 0, sizeof *slot);
  g_committing = 1;
  for (i = 0; i < n; i++) {
    Grant grant;
    memset(&grant, 0, sizeof grant);
    copy_part(grant.label, sizeof grant.label, &grant.label_len, local[i].label,
        local[i].label_len);
    copy_part(grant.action, sizeof grant.action, &grant.action_len,
        local[i].action, local[i].action_len);
    copy_part(grant.type_name, sizeof grant.type_name, &grant.type_len,
        local[i].type_name, local[i].type_len);
    if (local[i].field_len > 0) {
      copy_part(grant.field, sizeof grant.field, &grant.field_len,
          local[i].field, local[i].field_len);
    }
    grant.condition = local[i].condition;
    copy_part(grant.module_name, sizeof grant.module_name, &grant.module_len,
        local[i].module_name, local[i].module_len);
    rc = declare_grant(catalog, &grant, local[i].module_name,
        local[i].module_len, NULL, 0);
    if (rc == GDEFCORE_OK) {
      rc = grant_role(catalog, kAdmin, strlen(kAdmin), local[i].label,
          local[i].label_len, 0, NULL, 0);
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
  }
  g_committing = 0;
  return rc;
}

/* ---- a grant under a condition of its own ----------------------------- */

static const char kWhenMark[] = "#when:";
enum { kWhenHex = 16, kCondBuf = GDEFCORE_CONDITION_MAX_BYTES + 64 };

/* The permission's own condition, as text, into @p out (kCondBuf bytes). */
static GDEFCORE_Result permission_condition_text(GDEFCORE_Catalog * catalog,
    const char * perm_id, const Grant * perm, char * out, size_t * out_len) {
  char * text = NULL;
  size_t n = 0;
  GDEFCORE_Result rc;
  if (perm->condition == GDEFCORE_ACCESS_ANY ||
      perm->condition == GDEFCORE_ACCESS_OWN) {
    rc = gdefcore_condition_builtin(perm->condition == GDEFCORE_ACCESS_ANY
                                        ? GDEFCORE_CONDITION_BUILTIN_ANY
                                        : GDEFCORE_CONDITION_BUILTIN_OWN,
        perm->type_name, perm->type_len, &text, &n);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (n >= kCondBuf) {
      gdefcore_condition_text_free(text);
      return GDEFCORE_ERR_LIMIT;
    }
    memcpy(out, text, n);
    out[n] = '\0';
    *out_len = n;
    gdefcore_condition_text_free(text);
    return GDEFCORE_OK;
  }
  {
    char ** texts = NULL;
    size_t * lens = NULL;
    size_t count = 0;
    rc = read_values(catalog, perm_id, "condition", &texts, &lens, &count);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (count != 1 || lens[0] >= kCondBuf) {
      gdefcore_values_free(catalog, texts, lens, count);
      return GDEFCORE_ERR_CORRUPT;
    }
    memcpy(out, texts[0], lens[0]);
    out[lens[0]] = '\0';
    *out_len = lens[0];
    gdefcore_values_free(catalog, texts, lens, count);
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_grant_when(GDEFCORE_Catalog * catalog,
    const char * role, size_t role_len, const char * label, size_t label_len,
    const char * condition_text, size_t condition_len, const char * confirmation,
    size_t confirmation_len) {
  char perm_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  char module_name[kPart];
  size_t module_len = 0;
  Grant base;
  Grant derived;
  GDEFCORE_Condition * given = NULL;
  GDEFCORE_Condition * both = NULL;
  char * canon = NULL;
  size_t canon_len = 0;
  char base_text[kCondBuf];
  size_t base_len = 0;
  char composite[kCondBuf];
  char hash[GDEFCORE_CONDITION_HASH_LEN + 1];
  char derived_label[kPart];
  int n;
  GDEFCORE_Result rc;
  if (catalog == NULL || role == NULL || label == NULL ||
      condition_text == NULL || condition_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  /* Nothing is read, and nothing written, until the confirmation is right. */
  if (!confirm_ok(role, role_len, confirmation, confirmation_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = permission_by_label(catalog, label, label_len, perm_id, &base,
      module_name, sizeof module_name, &module_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = find_role(catalog, role, role_len, role_id);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (label_len + (sizeof kWhenMark - 1) + kWhenHex >= kPart) {
    return GDEFCORE_ERR_LIMIT;
  }
  /* The condition must be valid for the permission's type on its own... */
  rc = gdefcore_condition_parse(condition_text, condition_len, &given, NULL);
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_condition_validate(catalog, given, base.type_name,
        base.type_len, NULL);
  }
  gdefcore_condition_free(given);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* ...and is held together with the one the permission was declared with. */
  rc = permission_condition_text(catalog, perm_id, &base, base_text, &base_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  n = snprintf(composite, sizeof composite, "(and %s %.*s)", base_text,
      (int)condition_len, condition_text);
  if (n <= 0 || (size_t)n > GDEFCORE_CONDITION_MAX_BYTES) {
    return GDEFCORE_ERR_LIMIT;
  }
  rc = gdefcore_condition_parse(composite, (size_t)n, &both, NULL);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = GDEFCORE_ERR_LIMIT;
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_condition_canonical(both, &canon, &canon_len);
  }
  gdefcore_condition_free(both);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_condition_hash(canon, canon_len, hash, NULL);
  if (rc != GDEFCORE_OK) {
    gdefcore_condition_text_free(canon);
    return rc;
  }
  memcpy(derived_label, label, label_len);
  memcpy(derived_label + label_len, kWhenMark, sizeof kWhenMark - 1);
  memcpy(derived_label + label_len + sizeof kWhenMark - 1, hash, kWhenHex);
  derived_label[label_len + sizeof kWhenMark - 1 + kWhenHex] = '\0';
  derived = base;
  derived.condition = kCondExpr;
  derived.label_len = label_len + sizeof kWhenMark - 1 + kWhenHex;
  memcpy(derived.label, derived_label, derived.label_len + 1);
  rc = declare_grant(catalog, &derived, module_name, module_len, canon,
      canon_len);
  gdefcore_condition_text_free(canon);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  return grant_role(catalog, role, role_len, derived.label, derived.label_len, 0,
      NULL, 0);
}

GDEFCORE_Result gdefcore_access_permission_info(GDEFCORE_Catalog * catalog,
    const char * label, size_t label_len, GDEFCORE_Access_Permission * out) {
  Grant grant;
  char module_name[kPart];
  size_t module_len = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || label == NULL || out == NULL ||
      out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = permission_by_label(catalog, label, label_len, NULL, &grant, module_name,
      sizeof module_name, &module_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  memset(out->module, 0, sizeof out->module);
  memset(out->action, 0, sizeof out->action);
  memset(out->type_name, 0, sizeof out->type_name);
  memset(out->field, 0, sizeof out->field);
  memcpy(out->module, module_name, module_len);
  memcpy(out->action, grant.action, grant.action_len);
  memcpy(out->type_name, grant.type_name, grant.type_len);
  memcpy(out->field, grant.field, grant.field_len);
  return GDEFCORE_OK;
}

/* ---- how broad a grant is --------------------------------------------- */

enum { kClassRead = 1, kClassEdit = 2, kClassStrong = 3 };

static int in_words(const char * word, size_t n, const char * const * list) {
  size_t i;
  for (i = 0; list[i] != NULL; i++) {
    if (strlen(list[i]) == n && memcmp(list[i], word, n) == 0) {
      return 1;
    }
  }
  return 0;
}

/* The class of an action, from its dot-separated parts. Strong beats edit
 * beats read, and an action with none of the words is strong: the rating
 * must not be lowered by a name it does not recognise. */
static int action_class(const char * action, size_t len) {
  static const char * const kStrong[] = {"delete", "remove", "erase", "publish",
      "unpublish", "admin", "grant", "revert", "restore", "activate", "install",
      "enable", "disable", NULL};
  static const char * const kEdit[] = {"update", "edit", "create", "save",
      "draft", "write", NULL};
  static const char * const kRead[] = {"read", "view", "list", "search",
      "count", "export", NULL};
  int strong = 0;
  int edit = 0;
  int read = 0;
  int revisions = 0;
  size_t start = 0;
  size_t i;
  if (action == NULL) {
    return kClassStrong;
  }
  for (i = 0; i <= len; i++) {
    if (i == len || action[i] == '.') {
      size_t n = i - start;
      if (n == 9 && memcmp(action + start, "revisions", 9) == 0) {
        /* History shows drafts nobody has published, and acts on them: never
         * lower than an edit, whatever the verb after it says (D15). */
        revisions = 1;
      } else if (in_words(action + start, n, kStrong)) {
        strong = 1;
      } else if (in_words(action + start, n, kEdit)) {
        edit = 1;
      } else if (in_words(action + start, n, kRead)) {
        read = 1;
      }
      start = i + 1;
    }
  }
  if (strong) {
    return kClassStrong;
  }
  if (edit || revisions) {
    return kClassEdit;
  }
  return read ? kClassRead : kClassStrong;
}

/* Whether holding the action lets a person change the content a condition
 * reads: an edit of the entity, or a move to other content (a revert, a
 * restore, an activate). A create is not one: its condition is evaluated on
 * the container the path names, and the holder does not change that. */
static int action_changes_content(const char * action, size_t len) {
  static const char * const kChange[] = {"update", "edit", "save", "draft",
      "write", "revert", "restore", "activate", NULL};
  size_t start = 0;
  size_t i;
  if (action == NULL) {
    return 0;
  }
  for (i = 0; i <= len; i++) {
    if (i == len || action[i] == '.') {
      if (in_words(action + start, i - start, kChange)) {
        return 1;
      }
      start = i + 1;
    }
  }
  return 0;
}

/* The grant's condition tests a field that the same grant lets the holder
 * change: the field the grant names, or, for an entity-wide grant, any field
 * at all. */
static int grant_changes_its_own_field(const char * action, size_t action_len,
    const char * field, size_t field_len, const GDEFCORE_Condition * cond) {
  if (!action_changes_content(action, action_len)) {
    return 0;
  }
  return gdefcore_condition_tests_field(cond, field_len > 0 ? field : NULL,
      field_len);
}

/* The rating before the self-reference rule, and whether the grant is one. */
static int risk_base(const char * action, size_t action_len, int has_field,
    const char * field, size_t field_len, const char * condition_text,
    size_t condition_len, int reaches_anonymous, int * out_self) {
  GDEFCORE_Condition * cond = NULL;
  int cls = action_class(action, action_len);
  unsigned uses;
  int constrains;
  int narrowing;
  int own_like;
  int related;
  if (condition_text == NULL ||
      gdefcore_condition_parse(condition_text, condition_len, &cond,
          NULL) != GDEFCORE_OK) {
    /* A condition that cannot be read has a breadth nobody can state. */
    return GDEFCORE_ACCESS_RISK_HIGH;
  }
  uses = gdefcore_condition_uses(cond);
  constrains = gdefcore_condition_constrains_type(cond);
  if (out_self != NULL) {
    *out_self = has_field && field_len == 0
                    ? 0
                    : grant_changes_its_own_field(action, action_len, field,
                          field_len, cond);
  }
  gdefcore_condition_free(cond);
  related = (uses & GDEFCORE_CONDITION_USES_RELATION) != 0;
  narrowing = (uses & (GDEFCORE_CONDITION_USES_ENTITY |
                   GDEFCORE_CONDITION_USES_PRINCIPAL)) != 0;
  own_like = (uses & GDEFCORE_CONDITION_USES_ENTITY) != 0 &&
             (uses & GDEFCORE_CONDITION_USES_PRINCIPAL) != 0;
  /* A grant is always for one type, so what matters is whether anything in
   * the condition bounds what it matches: a type, or the entity's own data.
   * `true`, or a condition about the time or the principal alone, matches
   * every entity there is. */
  if (!constrains && (uses & GDEFCORE_CONDITION_USES_ENTITY) == 0) {
    return GDEFCORE_ACCESS_RISK_HIGH;
  }
  if (reaches_anonymous && cls != kClassRead) {
    return GDEFCORE_ACCESS_RISK_HIGH;
  }
  if (cls == kClassStrong && !narrowing) {
    return GDEFCORE_ACCESS_RISK_HIGH;
  }
  /* A relation's rows are written by a module, and who may add one is not
   * something this grant can bound: a grant that rests on one is never rated
   * low, whatever else narrows it. */
  if (own_like) {
    return related ? GDEFCORE_ACCESS_RISK_MEDIUM : GDEFCORE_ACCESS_RISK_LOW;
  }
  if (has_field) {
    return GDEFCORE_ACCESS_RISK_MEDIUM;
  }
  if (cls == kClassRead && narrowing) {
    return related ? GDEFCORE_ACCESS_RISK_MEDIUM : GDEFCORE_ACCESS_RISK_LOW;
  }
  return GDEFCORE_ACCESS_RISK_MEDIUM;
}

int gdefcore_access_grant_risk(const char * action, size_t action_len,
    int has_field, const char * condition_text, size_t condition_len,
    int reaches_anonymous) {
  return risk_base(action, action_len, has_field, NULL, 0, condition_text,
      condition_len, reaches_anonymous, NULL);
}

int gdefcore_access_grant_changes_own_field(const char * action,
    size_t action_len, const char * field, size_t field_len,
    const char * condition_text, size_t condition_len) {
  int self = 0;
  GDEFCORE_Condition * cond = NULL;
  if (condition_text == NULL ||
      gdefcore_condition_parse(condition_text, condition_len, &cond,
          NULL) != GDEFCORE_OK) {
    return 0;
  }
  self = grant_changes_its_own_field(action, action_len, field, field_len, cond);
  gdefcore_condition_free(cond);
  return self;
}

int gdefcore_access_grant_risk_on(const char * action, size_t action_len,
    const char * field, size_t field_len, const char * condition_text,
    size_t condition_len, int reaches_anonymous) {
  int self = 0;
  int risk = risk_base(action, action_len, field_len > 0, field, field_len,
      condition_text, condition_len, reaches_anonymous, &self);
  /* A grant that lets its holder change the very field its condition tests
   * can widen itself, so it is rated one step above what its breadth says. */
  if (self && risk < GDEFCORE_ACCESS_RISK_HIGH) {
    risk += 1;
  }
  return risk;
}

const char * gdefcore_access_risk_name(int risk) {
  switch (risk) {
    case GDEFCORE_ACCESS_RISK_LOW:
      return "low";
    case GDEFCORE_ACCESS_RISK_MEDIUM:
      return "medium";
    case GDEFCORE_ACCESS_RISK_HIGH:
      return "high";
    default:
      return "unknown";
  }
}

/* ---- a module's grant, offered at enable ------------------------------- */

static size_t relation_note(const GDEFCORE_Condition * cond, char * buf,
    size_t cap);

GDEFCORE_Result gdefcore_access_stage_module_grant(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len, const char * label, size_t label_len,
    const char * action, size_t action_len, const char * type_name,
    size_t type_name_len, const char * field, size_t field_len,
    const char * condition_text, size_t condition_len) {
  GDEFCORE_Condition * cond = NULL;
  char * explain = NULL;
  size_t explain_len = 0;
  char rel_note[512];
  size_t rel_note_len = 0;
  char * line = NULL;
  size_t cap;
  size_t i;
  int risk;
  int n;
  GDEFCORE_Result rc;
  if (changeset == NULL || !line_ok(module_name, module_name_len) ||
      !line_ok(label, label_len) || !line_ok(action, action_len) ||
      !line_ok(type_name, type_name_len) || condition_text == NULL ||
      condition_len == 0 || (field_len > 0 && !line_ok(field, field_len))) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_condition_parse(condition_text, condition_len, &cond, NULL);
  if (rc == GDEFCORE_OK) {
    /* The module being enabled is in this changeset already, so its own
     * relations count. */
    rc = gdefcore_condition_validate_in(gdefcore_changeset_catalog(changeset),
        cond, type_name, type_name_len, changeset, NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_condition_explain(cond, &explain, &explain_len);
  }
  rel_note_len = rc == GDEFCORE_OK
                     ? relation_note(cond, rel_note, sizeof rel_note)
                     : 0;
  if (rc != GDEFCORE_OK) {
    gdefcore_condition_free(cond);
    return rc;
  }
  /* Not held by a role: it reaches the anonymous state unless the condition
   * reads the principal. */
  risk = gdefcore_access_grant_risk_on(action, action_len, field, field_len,
      condition_text, condition_len,
      (gdefcore_condition_uses(cond) & GDEFCORE_CONDITION_USES_PRINCIPAL) == 0);
  gdefcore_condition_free(cond);
  cap = module_name_len + label_len + explain_len + rel_note_len + 80;
  line = (char *)gcu_allocator_malloc(alloc_default(), cap);
  if (line == NULL) {
    gdefcore_condition_text_free(explain);
    return GDEFCORE_ERR_OOM;
  }
  n = snprintf(line, cap, "Module %.*s grants %.*s (%s risk): %.*s%.*s",
      (int)module_name_len, module_name, (int)label_len, label,
      gdefcore_access_risk_name(risk), (int)explain_len, explain,
      (int)rel_note_len, rel_note);
  gdefcore_condition_text_free(explain);
  if (n <= 0 || (size_t)n >= cap) {
    gcu_allocator_free(alloc_default(), line);
    return GDEFCORE_ERR_LIMIT;
  }
  /* One line of plain text: a confirmation is typed, so no line breaks or
   * other controls may come from what a module author wrote. */
  for (i = 0; i < (size_t)n; i++) {
    if ((unsigned char)line[i] < 0x20 || line[i] == 0x7f) {
      line[i] = '?';
    }
  }
  rc = gdefcore_changeset_add_confirm_line(changeset, line, (size_t)n);
  gcu_allocator_free(alloc_default(), line);
  return rc;
}

/* ---- a module's access callback, offered at enable (story A6) ---------- */

GDEFCORE_Result gdefcore_access_stage_module_callback(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len, const char * name, size_t name_len, int scope,
    const char * label, size_t label_len, const char * action,
    size_t action_len, const char * type_name, size_t type_name_len,
    const char * field, size_t field_len) {
  char * line;
  size_t cap;
  size_t i;
  int n;
  GDEFCORE_Result rc;
  if (changeset == NULL || !line_ok(module_name, module_name_len) ||
      !line_ok(name, name_len) || !line_ok(label, label_len) ||
      !line_ok(action, action_len) || !line_ok(type_name, type_name_len) ||
      (scope != GDEFCORE_CALLBACK_FIELD && scope != GDEFCORE_CALLBACK_OPERATION) ||
      (field_len > 0 && !line_ok(field, field_len))) {
    return GDEFCORE_ERR_INVALID;
  }
  cap = module_name_len + name_len + label_len + 160;
  line = (char *)gcu_allocator_malloc(alloc_default(), cap);
  if (line == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  /* Rated high whatever it guards: its breadth is the module's code, which
   * no rating can read (AD-11). */
  n = snprintf(line, cap,
      "Module %.*s decides %.*s per entity with its callback %.*s (%s scope, "
      "%s risk): its breadth cannot be judged.",
      (int)module_name_len, module_name, (int)label_len, label, (int)name_len,
      name, scope == GDEFCORE_CALLBACK_FIELD ? "field" : "operation",
      gdefcore_access_risk_name(GDEFCORE_ACCESS_RISK_HIGH));
  (void)type_name;
  (void)type_name_len;
  (void)action;
  (void)action_len;
  if (n <= 0 || (size_t)n >= cap) {
    gcu_allocator_free(alloc_default(), line);
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < (size_t)n; i++) {
    if ((unsigned char)line[i] < 0x20 || line[i] == 0x7f) {
      line[i] = '?';
    }
  }
  rc = gdefcore_changeset_add_confirm_line(changeset, line, (size_t)n);
  gcu_allocator_free(alloc_default(), line);
  return rc == GDEFCORE_OK ? GDEFCORE_OK : rc;
}

/* ---- grants a module's callback would suspend, offered at enable (A7) --- */

static size_t shown_label_len(const char * label, size_t len);

/* One line of the preview: @p grant (held by @p who) names @p field of
 * @p type, which @p cb decides. The words are plain text on one line. */
static GDEFCORE_Result suspension_line(GDEFCORE_Changeset * changeset,
    const char * who, size_t who_len, const char * label, size_t label_len,
    const GDEFCORE_Condition * cond, const GDEFCORE_Module_Declared_Callback * cb) {
  char * words = NULL;
  size_t words_len = 0;
  char * text;
  size_t cap;
  size_t i;
  int n;
  GDEFCORE_Result rc = gdefcore_condition_explain(cond, &words, &words_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  cap = who_len + label_len + words_len + cb->module_len * 2 + cb->name_len +
        cb->field_len + cb->type_name_len + 300;
  text = (char *)gcu_allocator_malloc(alloc_default(), cap);
  if (text == NULL) {
    gdefcore_condition_text_free(words);
    return GDEFCORE_ERR_OOM;
  }
  n = snprintf(text, cap,
      "Module %.*s suspends %.*s grant %.*s (%.*s): its condition names field "
      "%.*s of %.*s, which that module decides per entity with its callback "
      "%.*s, so the grant holds nothing until no enabled module decides that "
      "field.",
      (int)cb->module_len, cb->module, (int)who_len, who,
      (int)shown_label_len(label, label_len), label, (int)words_len, words,
      (int)cb->field_len, cb->field, (int)cb->type_name_len, cb->type_name,
      (int)cb->name_len, cb->name);
  gdefcore_condition_text_free(words);
  if (n <= 0 || (size_t)n >= cap) {
    gcu_allocator_free(alloc_default(), text);
    return GDEFCORE_ERR_LIMIT;
  }
  for (i = 0; i < (size_t)n; i++) {
    if ((unsigned char)text[i] < 0x20 || text[i] == 0x7f) {
      text[i] = '?';
    }
  }
  rc = gdefcore_changeset_add_confirm_line(changeset, text, (size_t)n);
  gcu_allocator_free(alloc_default(), text);
  return rc;
}

/* Every callback of @p module in @p gov that decides a field @p cond names on
 * @p type: a line each. */
static GDEFCORE_Result suspension_lines_for(GDEFCORE_Changeset * changeset,
    const Governed * gov, const char * module, size_t module_len,
    const char * who, size_t who_len, const char * label, size_t label_len,
    const char * type, size_t type_len, const GDEFCORE_Condition * cond) {
  size_t i;
  GDEFCORE_Result rc = GDEFCORE_OK;
  for (i = 0; rc == GDEFCORE_OK && i < gov->n; i++) {
    const GDEFCORE_Module_Declared_Callback * c = gov->items[i];
    if (c->scope == GDEFCORE_CALLBACK_FIELD && c->field_len > 0 &&
        same(c->module, c->module_len, module, module_len) &&
        same(c->type_name, c->type_name_len, type, type_len) &&
        gdefcore_condition_tests_field(cond, c->field, c->field_len)) {
      rc = suspension_line(changeset, who, who_len, label, label_len, cond, c);
    }
  }
  return rc;
}

GDEFCORE_Result gdefcore_access_stage_module_suspensions(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len) {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Host * host;
  Governed gov;
  Eval ev;
  char ** ids = NULL;
  size_t count = 0;
  const GDEFCORE_Module_Declared_Grant ** items = NULL;
  size_t nitems = 0;
  size_t own = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (changeset == NULL || !line_ok(module_name, module_name_len)) {
    return GDEFCORE_ERR_INVALID;
  }
  catalog = gdefcore_changeset_catalog(changeset);
  host = catalog == NULL ? NULL : gdefcore_catalog_host(catalog);
  if (host == NULL) {
    return GDEFCORE_OK;
  }
  /* The set the changeset would leave: the module is in it. */
  rc = gov_load(catalog, changeset, &gov);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < gov.n; i++) {
    own += gov.items[i]->scope == GDEFCORE_CALLBACK_FIELD &&
           same(gov.items[i]->module, gov.items[i]->module_len, module_name,
               module_name_len);
  }
  if (own == 0) {
    gov_free(catalog, &gov);
    return GDEFCORE_OK;
  }
  eval_init(&ev, catalog, NULL, NULL, 0);
  /* A tenant nothing has asked about yet has no role and no grant. */
  rc = gdefcore_entity_ids(catalog, kRoleType, strlen(kRoleType), &ids, &count);
  if (rc == GDEFCORE_ERR_INVALID) {
    rc = GDEFCORE_OK;
    count = 0;
  }
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    Grant grants[kGrantMax];
    size_t ngrants = 0;
    char ** names = NULL;
    size_t * name_lens = NULL;
    size_t nnames = 0;
    size_t g;
    int retired = 1;
    rc = retired_state(catalog, ids[i], &retired);
    if (rc != GDEFCORE_OK || retired) {
      continue;
    }
    rc = read_values(catalog, ids[i], "name", &names, &name_lens, &nnames);
    if (rc == GDEFCORE_OK && nnames > 0) {
      rc = load_role_grants(catalog, ids[i], grants, kGrantMax, &ngrants);
      for (g = 0; rc == GDEFCORE_OK && g < ngrants; g++) {
        ExprSlot * slot;
        char holder[kPart + 16];
        int hn;
        if (grants[g].condition != kCondExpr) {
          continue;
        }
        slot = expr_slot(&ev, &grants[g]);
        if (slot == NULL || slot->bad || slot->cond == NULL) {
          continue;
        }
        hn = snprintf(holder, sizeof holder, "role %.*s's", (int)name_lens[0],
            names[0]);
        if (hn <= 0 || (size_t)hn >= sizeof holder) {
          rc = GDEFCORE_ERR_LIMIT;
          break;
        }
        rc = suspension_lines_for(changeset, &gov, module_name, module_name_len,
            holder, (size_t)hn, grants[g].label, grants[g].label_len,
            grants[g].type_name, grants[g].type_len, slot->cond);
      }
    }
    gdefcore_values_free(catalog, names, name_lens, nnames);
  }
  gdefcore_ids_free(catalog, ids, count);
  if (rc == GDEFCORE_OK) {
    size_t tenant_len = 0;
    const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
    rc = gdefcore_module_grants(host, tenant, tenant_len, changeset, &items,
        &nitems);
  }
  for (i = 0; i < nitems && rc == GDEFCORE_OK; i++) {
    const GDEFCORE_Module_Declared_Grant * item = items[i];
    GDEFCORE_Condition * parsed = NULL;
    char holder[kPart + 24];
    int hn = snprintf(holder, sizeof holder, "module %.*s's",
        (int)item->module_len, item->module);
    if (hn <= 0 || (size_t)hn >= sizeof holder) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    if (gdefcore_condition_parse(item->condition, item->condition_len, &parsed,
            NULL) != GDEFCORE_OK) {
      continue;
    }
    rc = suspension_lines_for(changeset, &gov, module_name, module_name_len,
        holder, (size_t)hn, item->permission, item->permission_len,
        item->type_name, item->type_name_len, parsed);
    gdefcore_condition_free(parsed);
  }
  if (items != NULL) {
    gdefcore_module_declared_free(host, items);
  }
  eval_done(&ev);
  gov_free(catalog, &gov);
  return rc;
}

/* ---- the matrix -------------------------------------------------------- */

typedef struct MatrixBuild {
  GDEFCORE_Catalog * catalog;
  GDEFCORE_Access_Matrix_Row * rows;
  size_t n;
  size_t cap;
} MatrixBuild;

static GDEFCORE_Result mx_text(GDEFCORE_Catalog * catalog, const char * p,
    size_t n, const char ** out, size_t * out_len) {
  char * copy = NULL;
  GDEFCORE_Result rc;
  if (p == NULL) {
    p = "";
    n = 0;
  }
  rc = gdefcore_text_dup(catalog, p, n, &copy);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out = copy;
  *out_len = n;
  return GDEFCORE_OK;
}

static void mx_free_row(GDEFCORE_Catalog * catalog,
    GDEFCORE_Access_Matrix_Row * row) {
  gdefcore_text_free(catalog, (char *)row->source);
  gdefcore_text_free(catalog, (char *)row->permission);
  gdefcore_text_free(catalog, (char *)row->action);
  gdefcore_text_free(catalog, (char *)row->type_name);
  gdefcore_text_free(catalog, (char *)row->field);
  gdefcore_text_free(catalog, (char *)row->condition);
  gdefcore_text_free(catalog, (char *)row->explain);
  gdefcore_text_free(catalog, (char *)row->suspended_by);
  memset(row, 0, sizeof *row);
}

void gdefcore_access_matrix_free(GDEFCORE_Catalog * catalog,
    GDEFCORE_Access_Matrix_Row * rows, size_t count) {
  size_t i;
  if (rows == NULL) {
    return;
  }
  for (i = 0; i < count; i++) {
    mx_free_row(catalog, &rows[i]);
  }
  gcu_allocator_free(alloc_default(), rows);
}

/* The label as declared: a grant made with a condition of its own is stored
 * under the label and a suffix that names the condition. */
static size_t shown_label_len(const char * label, size_t len) {
  size_t mark = sizeof kWhenMark - 1;
  size_t i;
  if (len <= mark + kWhenHex) {
    return len;
  }
  if (memcmp(label + len - kWhenHex - mark, kWhenMark, mark) != 0) {
    return len;
  }
  for (i = len - kWhenHex; i < len; i++) {
    char c = label[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return len;
    }
  }
  return len - kWhenHex - mark;
}

/* What the matrix says of a grant that lets its holder change the field its
 * own condition tests (D15). */
static const char kSelfNote[] =
    "; the holder can change the field that decides who may edit, so this is "
    "rated one step higher";

static GDEFCORE_Result mx_join(GDEFCORE_Catalog * catalog, const char * a,
    size_t an, const char * b, size_t bn, char ** out, size_t * out_len) {
  char * both = NULL;
  GDEFCORE_Result rc;
  char * tmp = (char *)gcu_allocator_malloc(alloc_default(), an + bn + 1);
  if (tmp == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memcpy(tmp, a, an);
  memcpy(tmp + an, b, bn);
  tmp[an + bn] = '\0';
  rc = gdefcore_text_dup(catalog, tmp, an + bn, &both);
  gcu_allocator_free(alloc_default(), tmp);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out = both;
  *out_len = an + bn;
  return GDEFCORE_OK;
}

/* The sentence for a grant that rests on a relation: what its breadth turns
 * on, which no condition can say. The relations are named; 0 when it uses
 * none. */
static size_t relation_note(const GDEFCORE_Condition * cond, char * buf,
    size_t cap) {
  size_t at = 0;
  size_t i;
  const char * name;
  size_t name_len;
  int n;
  if (!gdefcore_condition_relation_at(cond, 0, &name, &name_len)) {
    return 0;
  }
  n = snprintf(buf, cap, " Its breadth depends on who may add rows to the relation");
  at = n > 0 ? (size_t)n : 0;
  for (i = 0; at < cap && gdefcore_condition_relation_at(cond, i, &name, &name_len);
       i++) {
    n = snprintf(buf + at, cap - at, "%s %.*s", i > 0 ? "," : "", (int)name_len,
        name);
    at += n > 0 ? (size_t)n : 0;
  }
  if (at < cap) {
    n = snprintf(buf + at, cap - at,
        ": anyone who can add a row widens this grant.");
    at += n > 0 ? (size_t)n : 0;
  }
  for (i = 0; i < at && i < cap; i++) {
    if ((unsigned char)buf[i] < 0x20 || buf[i] == 0x7f) {
      buf[i] = '?';
    }
  }
  return at < cap ? at : cap - 1;
}

/* Add one row. @p cond is the canonical text, or NULL when @p cond_raw is all
 * that is known (a condition that cannot be parsed). */
static GDEFCORE_Result mx_add(MatrixBuild * b, const char * source,
    size_t source_len, int from_module, const char * label, size_t label_len,
    const char * action, size_t action_len, const char * type_name,
    size_t type_len, const char * field, size_t field_len, const char * cond,
    size_t cond_len, int reaches_anonymous, const char * suspended_by,
    size_t suspended_by_len) {
  GDEFCORE_Access_Matrix_Row * row;
  GDEFCORE_Condition * parsed = NULL;
  char * explain = NULL;
  size_t explain_len = 0;
  char rel_note[512];
  size_t rel_note_len = 0;
  const char * unreadable = "(this condition cannot be read)";
  GDEFCORE_Result rc;
  if (b->n == b->cap) {
    size_t cap = b->cap == 0 ? 16 : b->cap * 2;
    GDEFCORE_Access_Matrix_Row * next =
        (GDEFCORE_Access_Matrix_Row *)gcu_allocator_realloc(alloc_default(),
            b->rows, cap * sizeof *next);
    if (next == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    b->rows = next;
    b->cap = cap;
  }
  row = &b->rows[b->n];
  memset(row, 0, sizeof *row);
  row->size = sizeof *row;
  row->from_module = from_module;
  rc = GDEFCORE_OK;
  if (gdefcore_condition_parse(cond, cond_len, &parsed, NULL) ==
      GDEFCORE_OK) {
    rc = gdefcore_condition_explain(parsed, &explain, &explain_len);
    rel_note_len = relation_note(parsed, rel_note, sizeof rel_note);
    gdefcore_condition_free(parsed);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  row->risk = gdefcore_access_grant_risk_on(action, action_len, field,
      field_len, cond, cond_len, reaches_anonymous);
  rc = mx_text(b->catalog, source, source_len, &row->source, &row->source_len);
  if (rc == GDEFCORE_OK) {
    rc = mx_text(b->catalog, label, shown_label_len(label, label_len),
        &row->permission, &row->permission_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = mx_text(b->catalog, action, action_len, &row->action,
        &row->action_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = mx_text(b->catalog, type_name, type_len, &row->type_name,
        &row->type_name_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = mx_text(b->catalog, field, field_len, &row->field, &row->field_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = mx_text(b->catalog, cond, cond_len, &row->condition,
        &row->condition_len);
  }
  if (rc == GDEFCORE_OK) {
    rc = explain != NULL
             ? mx_text(b->catalog, explain, explain_len, &row->explain,
                   &row->explain_len)
             : mx_text(b->catalog, unreadable, strlen(unreadable),
                   &row->explain, &row->explain_len);
  }
  gdefcore_condition_text_free(explain);
  if (rc == GDEFCORE_OK &&
      gdefcore_access_grant_changes_own_field(action, action_len, field,
          field_len, cond, cond_len)) {
    /* Said in words, beside the condition: the rating is one step higher
     * for it, and a reader of the matrix should see why. */
    char * joined = NULL;
    size_t joined_len = 0;
    rc = mx_join(b->catalog, row->explain, row->explain_len, kSelfNote,
        sizeof kSelfNote - 1, &joined, &joined_len);
    if (rc == GDEFCORE_OK) {
      gdefcore_text_free(b->catalog, (char *)row->explain);
      row->explain = joined;
      row->explain_len = joined_len;
    }
  }
  if (rc == GDEFCORE_OK && rel_note_len > 0) {
    char * joined = NULL;
    size_t joined_len = 0;
    rc = mx_join(b->catalog, row->explain, row->explain_len, rel_note,
        rel_note_len, &joined, &joined_len);
    if (rc == GDEFCORE_OK) {
      gdefcore_text_free(b->catalog, (char *)row->explain);
      row->explain = joined;
      row->explain_len = joined_len;
    }
  }
  if (rc == GDEFCORE_OK && suspended_by_len > 0) {
    /* Story A7: said in words beside the condition, and as data. */
    char note[kSuspBuf + 256];
    char * joined = NULL;
    size_t joined_len = 0;
    int nn = snprintf(note, sizeof note,
        " This grant is suspended by %.*s: its condition names a field that "
        "module decides per entity with a callback, so it grants nothing "
        "until no enabled module decides that field.",
        (int)suspended_by_len, suspended_by);
    if (nn <= 0 || (size_t)nn >= sizeof note) {
      rc = GDEFCORE_ERR_LIMIT;
    } else {
      rc = mx_join(b->catalog, row->explain, row->explain_len, note,
          (size_t)nn, &joined, &joined_len);
    }
    if (rc == GDEFCORE_OK) {
      gdefcore_text_free(b->catalog, (char *)row->explain);
      row->explain = joined;
      row->explain_len = joined_len;
      row->suspended = 1;
      rc = mx_text(b->catalog, suspended_by, suspended_by_len,
          &row->suspended_by, &row->suspended_by_len);
    }
  }
  if (rc != GDEFCORE_OK) {
    mx_free_row(b->catalog, row);
    return rc;
  }
  b->n += 1;
  return GDEFCORE_OK;
}

/* The enabled modules that decide a field @p cond names on @p type, sorted
 * and joined, into @p buf: its length, or 0 for none (story A7). */
static size_t suspended_by_of(Eval * ev, const GDEFCORE_Condition * cond,
    const char * type, size_t type_len, char * buf, size_t cap) {
  const GDEFCORE_Module_Declared_Callback * mods[kGovMax];
  size_t n;
  int len;
  buf[0] = '\0';
  if (!ev->gov.loaded && gov_load(ev->catalog, NULL, &ev->gov) != GDEFCORE_OK) {
    return 0;
  }
  n = gov_modules(&ev->gov, cond, type, type_len, mods);
  if (n == 0) {
    return 0;
  }
  len = gov_names(mods, n, buf, cap);
  return len < 0 ? 0 : (size_t)len;
}

static int mx_span_cmp(const char * a, size_t an, const char * b, size_t bn) {
  size_t n = an < bn ? an : bn;
  int c = n == 0 ? 0 : memcmp(a, b, n);
  if (c != 0) {
    return c;
  }
  return an < bn ? -1 : (an > bn ? 1 : 0);
}

static int mx_cmp(const void * pa, const void * pb) {
  const GDEFCORE_Access_Matrix_Row * a = (const GDEFCORE_Access_Matrix_Row *)pa;
  const GDEFCORE_Access_Matrix_Row * b = (const GDEFCORE_Access_Matrix_Row *)pb;
  int c = mx_span_cmp(a->source, a->source_len, b->source, b->source_len);
  if (c == 0) {
    c = mx_span_cmp(a->permission, a->permission_len, b->permission,
        b->permission_len);
  }
  if (c == 0) {
    c = mx_span_cmp(a->type_name, a->type_name_len, b->type_name,
        b->type_name_len);
  }
  if (c == 0) {
    c = mx_span_cmp(a->field, a->field_len, b->field, b->field_len);
  }
  if (c == 0) {
    c = mx_span_cmp(a->condition, a->condition_len, b->condition,
        b->condition_len);
  }
  return c;
}

/* Whether the principal holds the role `admin`. A principal that is not
 * there, or was removed, does not. */
static int principal_is_admin(GDEFCORE_Catalog * catalog, const char * who,
    size_t who_len) {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  int held = 0;
  if (who == NULL || who_len != GDEFCORE_PUBLIC_ID_LEN) {
    return 0;
  }
  memcpy(id, who, who_len);
  id[who_len] = '\0';
  if (holds_admin(catalog, id, &held) != GDEFCORE_OK) {
    return 0;
  }
  return held;
}

/* One role's grants as rows. */
static GDEFCORE_Result mx_role(MatrixBuild * b, Eval * ev, const char * role_id) {
  Grant grants[kGrantMax];
  size_t ngrants = 0;
  char ** names = NULL;
  size_t * name_lens = NULL;
  size_t nnames = 0;
  char source[kPart + 8];
  size_t source_len;
  size_t i;
  int anonymous;
  GDEFCORE_Result rc = read_values(b->catalog, role_id, "name", &names,
      &name_lens, &nnames);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (nnames == 0 || name_lens[0] + 6 >= sizeof source) {
    gdefcore_values_free(b->catalog, names, name_lens, nnames);
    return GDEFCORE_ERR_CORRUPT;
  }
  memcpy(source, "role ", 5);
  memcpy(source + 5, names[0], name_lens[0]);
  source_len = 5 + name_lens[0];
  anonymous = same(names[0], name_lens[0], kAnonymous, strlen(kAnonymous));
  gdefcore_values_free(b->catalog, names, name_lens, nnames);
  rc = load_role_grants(b->catalog, role_id, grants, kGrantMax, &ngrants);
  for (i = 0; rc == GDEFCORE_OK && i < ngrants; i++) {
    char text[kCondBuf];
    size_t text_len = 0;
    const char * cond = text;
    char * canon = NULL;
    size_t canon_len = 0;
    char susp[kSuspBuf];
    size_t susp_len = 0;
    susp[0] = '\0';
    if (grants[i].condition == kCondExpr) {
      ExprSlot * slot = expr_slot(ev, &grants[i]);
      if (slot == NULL || slot->bad) {
        return GDEFCORE_ERR_CORRUPT;
      }
      rc = gdefcore_condition_canonical(slot->cond, &canon, &canon_len);
      if (slot->suspended) {
        susp_len = suspended_by_of(ev, slot->cond, grants[i].type_name,
            grants[i].type_len, susp, sizeof susp);
      }
    } else {
      rc = gdefcore_condition_builtin(
          grants[i].condition == GDEFCORE_ACCESS_ANY
              ? GDEFCORE_CONDITION_BUILTIN_ANY
              : GDEFCORE_CONDITION_BUILTIN_OWN,
          grants[i].type_name, grants[i].type_len, &canon, &canon_len);
    }
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (canon_len >= sizeof text) {
      gdefcore_condition_text_free(canon);
      return GDEFCORE_ERR_LIMIT;
    }
    memcpy(text, canon, canon_len);
    text_len = canon_len;
    gdefcore_condition_text_free(canon);
    rc = mx_add(b, source, source_len, 0, grants[i].label, grants[i].label_len,
        grants[i].action, grants[i].action_len, grants[i].type_name,
        grants[i].type_len, grants[i].field, grants[i].field_len, cond,
        text_len, anonymous, susp, susp_len);
  }
  return rc;
}

/* The enabled modules' access callbacks as rows (story A6): granted by the
 * module, evaluated per entity, rated high. */
static GDEFCORE_Result mx_callbacks(MatrixBuild * b, GDEFCORE_Host * host) {
  const GDEFCORE_Module_Declared_Callback ** items = NULL;
  size_t ncallbacks = 0;
  size_t tenant_len = 0;
  const uint8_t * tenant = gdefcore_catalog_tenant(b->catalog, &tenant_len);
  size_t i;
  GDEFCORE_Result rc = gdefcore_module_callbacks(host, tenant, tenant_len, NULL,
      &items, &ncallbacks);
  for (i = 0; rc == GDEFCORE_OK && i < ncallbacks; i++) {
    const GDEFCORE_Module_Declared_Callback * c = items[i];
    GDEFCORE_Access_Matrix_Row * row;
    Grant info;
    char owner[kPart];
    size_t owner_len = 0;
    char source[kPart + 8];
    char cond[kPart + 80];
    char explain[1024];
    int sn;
    int cn;
    int en;
    const char * action = "";
    size_t action_len = 0;
    const char * cache_words =
        c->cache == GDEFCORE_CALLBACK_CACHE_TOKEN
            ? "A page that asked it is cached under the validity token it gives"
            : (c->cache == GDEFCORE_CALLBACK_CACHE_TTL
                      ? "A page that asked it is cached for its time to live"
                      : "A page that asked it is not cached");
    if (permission_by_label(b->catalog, c->permission, c->permission_len, NULL,
            &info, owner, sizeof owner, &owner_len) == GDEFCORE_OK) {
      action = info.action;
      action_len = info.action_len;
    }
    sn = snprintf(source, sizeof source, "module %.*s", (int)c->module_len,
        c->module);
    cn = snprintf(cond, sizeof cond, "callback %.*s.%.*s", (int)c->module_len,
        c->module, (int)c->name_len, c->name);
    en = snprintf(explain, sizeof explain,
        "Granted by module %.*s, evaluated per entity by its callback %.*s (%s "
        "scope); its breadth cannot be judged. %s%s.",
        (int)c->module_len, c->module, (int)c->name_len, c->name,
        c->scope == GDEFCORE_CALLBACK_FIELD ? "field" : "operation",
        cache_words,
        (c->flags & GDEFCORE_CALLBACK_LOCKED) != 0
            ? "; a reader it refuses is told the field is locked"
            : "");
    if (sn <= 0 || (size_t)sn >= sizeof source || cn <= 0 ||
        (size_t)cn >= sizeof cond || en <= 0 || (size_t)en >= sizeof explain) {
      rc = GDEFCORE_ERR_LIMIT;
      break;
    }
    if (b->n == b->cap) {
      size_t cap = b->cap == 0 ? 16 : b->cap * 2;
      GDEFCORE_Access_Matrix_Row * next =
          (GDEFCORE_Access_Matrix_Row *)gcu_allocator_realloc(alloc_default(),
              b->rows, cap * sizeof *next);
      if (next == NULL) {
        rc = GDEFCORE_ERR_OOM;
        break;
      }
      b->rows = next;
      b->cap = cap;
    }
    row = &b->rows[b->n];
    memset(row, 0, sizeof *row);
    row->size = sizeof *row;
    row->from_module = 1;
    row->callback = 1;
    row->risk = GDEFCORE_ACCESS_RISK_HIGH;
    rc = mx_text(b->catalog, source, (size_t)sn, &row->source, &row->source_len);
    if (rc == GDEFCORE_OK) {
      rc = mx_text(b->catalog, c->permission, c->permission_len,
          &row->permission, &row->permission_len);
    }
    if (rc == GDEFCORE_OK) {
      rc = mx_text(b->catalog, action, action_len, &row->action,
          &row->action_len);
    }
    if (rc == GDEFCORE_OK) {
      rc = mx_text(b->catalog, c->type_name, c->type_name_len, &row->type_name,
          &row->type_name_len);
    }
    if (rc == GDEFCORE_OK) {
      rc = mx_text(b->catalog, c->field, c->field_len, &row->field,
          &row->field_len);
    }
    if (rc == GDEFCORE_OK) {
      rc = mx_text(b->catalog, cond, (size_t)cn, &row->condition,
          &row->condition_len);
    }
    if (rc == GDEFCORE_OK) {
      rc = mx_text(b->catalog, explain, (size_t)en, &row->explain,
          &row->explain_len);
    }
    if (rc != GDEFCORE_OK) {
      mx_free_row(b->catalog, row);
      break;
    }
    b->n += 1;
  }
  gdefcore_module_declared_free(host, items);
  return rc;
}

GDEFCORE_Result gdefcore_access_matrix(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, GDEFCORE_Access_Matrix_Row ** out_rows,
    size_t * out_count) {
  MatrixBuild b;
  Eval ev;
  const char * who;
  size_t who_len = 0;
  const char * acting;
  size_t acting_len = 0;
  char ** ids = NULL;
  size_t count = 0;
  const GDEFCORE_Module_Declared_Grant ** items = NULL;
  size_t nitems = 0;
  GDEFCORE_Host * host;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || out_rows == NULL ||
      out_count == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_rows = NULL;
  *out_count = 0;
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* Only an administrator reads it; anyone else is told what a page that is
   * not there is told. An acting principal needs the role as well: an agent
   * does not read the matrix through the person it acts for (AD-12). */
  who = gdefcore_request_principal(request, &who_len);
  acting = gdefcore_request_acting_principal(request, &acting_len);
  if (!principal_is_admin(catalog, who, who_len) ||
      (acting != NULL && !same(acting, acting_len, who, who_len) &&
          !principal_is_admin(catalog, acting, acting_len))) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&b, 0, sizeof b);
  b.catalog = catalog;
  eval_init(&ev, catalog, request, NULL, 0);
  rc = gdefcore_entity_ids(catalog, kRoleType, strlen(kRoleType), &ids, &count);
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    int retired = 1;
    rc = retired_state(catalog, ids[i], &retired);
    if (rc == GDEFCORE_OK && !retired) {
      rc = mx_role(&b, &ev, ids[i]);
    }
  }
  gdefcore_ids_free(catalog, ids, count);
  host = gdefcore_catalog_host(catalog);
  if (rc == GDEFCORE_OK && host != NULL) {
    size_t tenant_len = 0;
    const uint8_t * tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
    rc = gdefcore_module_grants(host, tenant, tenant_len, NULL, &items, &nitems);
  }
  for (i = 0; rc == GDEFCORE_OK && i < nitems; i++) {
    const GDEFCORE_Module_Declared_Grant * item = items[i];
    GDEFCORE_Condition * parsed = NULL;
    char * canon = NULL;
    size_t canon_len = 0;
    char source[kPart + 8];
    size_t source_len;
    Grant info;
    char owner[kPart];
    size_t owner_len = 0;
    const char * action = "";
    size_t action_len = 0;
    int anonymous = 1;
    char susp[kSuspBuf];
    size_t susp_len = 0;
    susp[0] = '\0';
    if (item->module_len + 8 >= sizeof source) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    memcpy(source, "module ", 7);
    memcpy(source + 7, item->module, item->module_len);
    source_len = 7 + item->module_len;
    if (permission_by_label(catalog, item->permission, item->permission_len,
            NULL, &info, owner, sizeof owner, &owner_len) == GDEFCORE_OK) {
      action = info.action;
      action_len = info.action_len;
    }
    if (gdefcore_condition_parse(item->condition, item->condition_len,
            &parsed, NULL) == GDEFCORE_OK) {
      anonymous = (gdefcore_condition_uses(parsed) &
                      GDEFCORE_CONDITION_USES_PRINCIPAL) == 0;
      susp_len = suspended_by_of(&ev, parsed, item->type_name,
          item->type_name_len, susp, sizeof susp);
      if (gdefcore_condition_canonical(parsed, &canon, &canon_len) !=
          GDEFCORE_OK) {
        canon = NULL;
      }
      gdefcore_condition_free(parsed);
    }
    rc = mx_add(&b, source, source_len, 1, item->permission,
        item->permission_len, action, action_len, item->type_name,
        item->type_name_len, item->field, item->field_len,
        canon != NULL ? canon : item->condition,
        canon != NULL ? canon_len : item->condition_len, anonymous, susp,
        susp_len);
    gdefcore_condition_text_free(canon);
  }
  if (host != NULL) {
    gdefcore_module_declared_free(host, items);
  }
  if (rc == GDEFCORE_OK && host != NULL) {
    rc = mx_callbacks(&b, host);
  }
  eval_done(&ev);
  if (rc != GDEFCORE_OK) {
    gdefcore_access_matrix_free(catalog, b.rows, b.n);
    return rc;
  }
  if (b.n > 1) {
    qsort(b.rows, b.n, sizeof *b.rows, mx_cmp);
  }
  *out_rows = b.rows;
  *out_count = b.n;
  return GDEFCORE_OK;
}

/* ---- grants a restore brought in (AD-37) -------------------------------- */

/* One grant of a state's role, as it is taken back. */
typedef struct HeldGrant {
  Grant grant;
  char * cond; /* its condition, canonical; alloc_default() */
  size_t cond_len;
  int risk;
  char * by;   /* the enabled modules that suspend it (story A7), or NULL */
  size_t by_len;
  int keep;    /* a grant to an ordinary role that nothing suspends */
} HeldGrant;

/* Take back every grant of one role that is a state, then say what each was.
 * The role is written first: a report that fails leaves nothing applied.
 * With @p suspended_only (an ordinary role, story A7) it takes back only the
 * grants a governed field suspends and leaves the rest as they are. */
static GDEFCORE_Result hold_role(GDEFCORE_Catalog * catalog, Eval * ev,
    const char * role_id, const char * name, size_t name_len,
    int suspended_only, GDEFCORE_Access_Held_Fn fn, void * ctx) {
  Grant grants[kGrantMax];
  Grant kept[kGrantMax];
  HeldGrant * held = NULL;
  size_t ngrants = 0;
  size_t nkept = 0;
  size_t nheld = 0;
  size_t i;
  int anonymous = same(name, name_len, kAnonymous, strlen(kAnonymous));
  const char * confirmation = suspended_only
                                  ? kRoleConfirm
                                  : (anonymous
                                            ? GDEFCORE_ACCESS_CONFIRM_ANONYMOUS
                                            : GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED);
  GDEFCORE_Result rc = load_role_grants(catalog, role_id, grants, kGrantMax,
      &ngrants);
  if (rc != GDEFCORE_OK || ngrants == 0) {
    return rc;
  }
  held = (HeldGrant *)gcu_allocator_calloc(alloc_default(), ngrants,
      sizeof *held);
  if (held == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  /* Each rated as the matrix rates it (AD-11, AD-37): the same function,
   * with the grant's canonical condition and whether the anonymous state
   * holds it. */
  for (i = 0; rc == GDEFCORE_OK && i < ngrants; i++) {
    held[i].grant = grants[i];
    if (grants[i].condition == kCondExpr) {
      ExprSlot * slot = expr_slot(ev, &grants[i]);
      rc = slot == NULL || slot->bad
               ? GDEFCORE_ERR_CORRUPT
               : gdefcore_condition_canonical(slot->cond, &held[i].cond,
                     &held[i].cond_len);
      if (rc == GDEFCORE_OK && slot->suspended) {
        /* Named in the report: the enabled modules that decide the field. */
        char names[kSuspBuf];
        size_t nl = suspended_by_of(ev, slot->cond, grants[i].type_name,
            grants[i].type_len, names, sizeof names);
        if (nl > 0) {
          held[i].by = (char *)gcu_allocator_malloc(alloc_default(), nl + 1);
          if (held[i].by == NULL) {
            rc = GDEFCORE_ERR_OOM;
          } else {
            memcpy(held[i].by, names, nl + 1);
            held[i].by_len = nl;
          }
        }
      }
    } else {
      rc = gdefcore_condition_builtin(
          grants[i].condition == GDEFCORE_ACCESS_ANY
              ? GDEFCORE_CONDITION_BUILTIN_ANY
              : GDEFCORE_CONDITION_BUILTIN_OWN,
          grants[i].type_name, grants[i].type_len, &held[i].cond,
          &held[i].cond_len);
    }
    if (rc == GDEFCORE_OK) {
      held[i].risk = gdefcore_access_grant_risk_on(grants[i].action,
          grants[i].action_len, grants[i].field, grants[i].field_len,
          held[i].cond, held[i].cond_len, anonymous);
    }
    held[i].keep = suspended_only && held[i].by == NULL;
    if (held[i].keep) {
      kept[nkept++] = grants[i];
    } else {
      nheld += 1;
    }
  }
  if (rc == GDEFCORE_OK && nheld > 0) {
    /* None of the held is applied: the role keeps its history, and its newest
     * revision grants only what was left. */
    rc = write_grants(catalog, role_id, kept, nkept);
  }
  for (i = 0; rc == GDEFCORE_OK && nheld > 0 && i < ngrants; i++) {
    GDEFCORE_Access_Held out;
    const Grant * g = &held[i].grant;
    if (held[i].keep) {
      continue;
    }
    memset(&out, 0, sizeof out);
    out.size = sizeof out;
    out.role = name;
    out.role_len = name_len;
    out.permission = g->label;
    out.permission_len = g->label_len;
    out.label = g->label;
    out.label_len = shown_label_len(g->label, g->label_len);
    out.action = g->action;
    out.action_len = g->action_len;
    out.type_name = g->type_name;
    out.type_name_len = g->type_len;
    out.field = g->field;
    out.field_len = g->field_len;
    out.condition = held[i].cond;
    out.condition_len = held[i].cond_len;
    out.risk = held[i].risk;
    out.confirmation = confirmation;
    out.confirmation_len = strlen(confirmation);
    out.suspended_by = held[i].by != NULL ? held[i].by : "";
    out.suspended_by_len = held[i].by_len;
    rc = fn(ctx, &out);
  }
  for (i = 0; i < ngrants; i++) {
    gdefcore_condition_text_free(held[i].cond);
    gcu_allocator_free(alloc_default(), held[i].by);
  }
  gcu_allocator_free(alloc_default(), held);
  return rc;
}

GDEFCORE_Result gdefcore_access_hold_for_confirmation(GDEFCORE_Catalog * catalog,
    GDEFCORE_Access_Held_Fn fn, void * ctx) {
  Eval ev;
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || fn == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  /* Not seeded here: a tenant with no role entity holds no grant, and this
   * writes nothing a restore did not bring in. */
  eval_init(&ev, catalog, NULL, NULL, 0);
  /* Every role entity named for a state, not only the first: a snapshot is
   * untrusted, and two roles of one state's name would both be the state. */
  rc = gdefcore_entity_ids(catalog, kRoleType, strlen(kRoleType), &ids, &count);
  for (i = 0; rc == GDEFCORE_OK && i < count; i++) {
    char ** names = NULL;
    size_t * name_lens = NULL;
    size_t nnames = 0;
    int retired = 1;
    rc = retired_state(catalog, ids[i], &retired);
    if (rc != GDEFCORE_OK || retired) {
      continue;
    }
    rc = read_values(catalog, ids[i], "name", &names, &name_lens, &nnames);
    if (rc == GDEFCORE_OK && nnames > 0) {
      int is_state =
          same(names[0], name_lens[0], kAnonymous, strlen(kAnonymous)) ||
          same(names[0], name_lens[0], kAuthenticated, strlen(kAuthenticated));
      /* A state's grants are all taken back; any other role's only those a
       * governed field suspends (story A7). */
      rc = hold_role(catalog, &ev, ids[i], names[0], name_lens[0], !is_state,
          fn, ctx);
    }
    gdefcore_values_free(catalog, names, name_lens, nnames);
  }
  gdefcore_ids_free(catalog, ids, count);
  eval_done(&ev);
  return rc;
}

/* ---- one can() --------------------------------------------------------- */

/* ---- which source allowed a decision (story A7) ------------------------- */

static void source_text(char * dst, size_t cap, size_t * dst_len,
    const char * src, size_t n) {
  if (n >= cap) {
    n = cap - 1;
  }
  if (n > 0) {
    memcpy(dst, src, n);
  }
  dst[n] = '\0';
  *dst_len = n;
}

/* Say, in @p dec, that @p grant allowed the decision: a role's grant (the
 * role named), an enabled module's grant, or a module's named callback. The
 * permission is as the matrix shows it. */
static void source_fill(GDEFCORE_Catalog * catalog, const Grant * grant,
    GDEFCORE_Access_Decision * dec) {
  dec->allowed = 1;
  source_text(dec->permission, sizeof dec->permission, &dec->permission_len,
      grant->label, shown_label_len(grant->label, grant->label_len));
  if (grant->source == kSrcCallback && grant->cb != NULL) {
    dec->source = GDEFCORE_ACCESS_SOURCE_CALLBACK;
    source_text(dec->holder, sizeof dec->holder, &dec->holder_len,
        grant->cb->module, grant->cb->module_len);
    source_text(dec->callback, sizeof dec->callback, &dec->callback_len,
        grant->cb->name, grant->cb->name_len);
  } else if (grant->source == kSrcModule) {
    dec->source = GDEFCORE_ACCESS_SOURCE_MODULE;
    source_text(dec->holder, sizeof dec->holder, &dec->holder_len,
        grant->module_name, grant->module_len);
  } else {
    char ** names = NULL;
    size_t * lens = NULL;
    size_t n = 0;
    dec->source = GDEFCORE_ACCESS_SOURCE_ROLE;
    if (grant->role_id[0] != '\0' &&
        read_values(catalog, grant->role_id, "name", &names, &lens, &n) ==
            GDEFCORE_OK &&
        n > 0) {
      source_text(dec->holder, sizeof dec->holder, &dec->holder_len, names[0],
          lens[0]);
    }
    gdefcore_values_free(catalog, names, lens, n);
  }
}

/* The memo key: who asks (and for whom), what, of which entity at which
 * revision. At type level the entity is "*" and the revision is the epoch of
 * the configuration, because the answer depends on every entity of the type.
 * 0 when it does not fit, in which case the question is not memoized. */
static int can_key(char * out, size_t cap, const GDEFCORE_Request * request,
    const char * permission, size_t permission_len, const char * type,
    size_t type_len, const char * entity, uint64_t version) {
  size_t principal_len = 0;
  const char * principal = gdefcore_request_principal(request, &principal_len);
  size_t acting_len = 0;
  const char * acting = gdefcore_request_acting_principal(request, &acting_len);
  int n = snprintf(out, cap, "can\x1f%.*s\x1f%.*s\x1f%.*s\x1f%.*s\x1f%s\x1f%llu",
      (int)(principal == NULL ? 1 : principal_len),
      principal == NULL ? "-" : principal,
      (int)(acting == NULL ? 1 : acting_len), acting == NULL ? "-" : acting,
      (int)permission_len, permission, (int)type_len, type,
      entity == NULL ? "*" : entity, (unsigned long long)version);
  return n > 0 && (size_t)n < cap ? n : 0;
}

/* One decision, not remembered. @p canon is the entity's canonical id, or
 * NULL for the type-level question. A grant that allows it is named in
 * @p dec when that is not NULL (story A7). */
static GDEFCORE_Result can_decide(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * permission, size_t permission_len,
    const char * type, size_t type_len, const char * canon, int * out_allowed,
    GDEFCORE_Access_Decision * dec) {
  Grant grants[kGrantMax];
  size_t ngrants = 0;
  int read_principal = 0;
  Eval ev;
  size_t i;
  int allowed = 0;
  long win = -1;
  int failed;
  char * actor = NULL;
  size_t actor_len = 0;
  const char * principal;
  size_t principal_len = 0;
  GDEFCORE_Result rc;
  *out_allowed = 0;
  rc = load_effective(catalog, request, grants, kGrantMax, &ngrants,
      &read_principal);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  principal = gdefcore_request_principal(request, &principal_len);
  eval_init(&ev, catalog, request, NULL, 0);
  (void)setup_ceiling(&ev);
  if (canon == NULL) {
    win = permits_at(&ev, grants, ngrants, permission, permission_len, type,
        type_len);
    allowed = win >= 0;
    if (allowed && ev.has_ceiling) {
      allowed = permits_in(&ev, ev.ceiling, ev.nceiling, permission,
          permission_len, type, type_len);
    }
  } else {
    rc = gdefcore_entity_creator(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &actor,
        &actor_len);
    if (rc != GDEFCORE_OK) {
      eval_done(&ev);
      /* The entity went between the question above and this: a no, as for one
       * that was never there. */
      return rc == GDEFCORE_ERR_INVALID ? GDEFCORE_OK : rc;
    }
    ev.id = canon;
    for (i = 0; i < ngrants && !allowed; i++) {
      if (grants[i].field_len != 0 ||
          !same(grants[i].action, grants[i].action_len, permission,
              permission_len) ||
          !same(grants[i].type_name, grants[i].type_len, type, type_len)) {
        continue;
      }
      allowed = condition_ok(&ev, &grants[i], actor, actor_len, principal,
          principal_len);
      win = allowed ? (long)i : win;
    }
    gdefcore_text_free(catalog, actor);
    if (allowed && same(permission, permission_len, "read", 4)) {
      /* To read is to read what readers see, as gdefcore_access_read() does:
       * an entity that is not published is not there for a reader, and must
       * answer as one that is not there. Other permissions are not about
       * what is published. */
      allowed = reader_sees(catalog, canon, &ev);
    }
  }
  failed = ev.failed;
  if (allowed && dec != NULL && win >= 0) {
    source_fill(catalog, &grants[win], dec);
  }
  eval_done(&ev);
  if (failed && !allowed) {
    /* A condition that could not be decided is not a no that can be
     * remembered, and not a yes. One that failed beside a grant that holds
     * is neither: the sources combine by union, a source that fails grants
     * nothing and cancels the allow of no other source (story A7). The
     * failure is reported on the request (eval_done). */
    return GDEFCORE_ERR_INTERNAL;
  }
  *out_allowed = allowed;
  return GDEFCORE_OK;
}

/* gdefcore_access_can(), and gdefcore_access_decide() when @p dec is not
 * NULL: the same question, asked afresh (an answer remembered carries no
 * source), the source that allowed it named in @p dec. */
static GDEFCORE_Result can_impl(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * permission, size_t permission_len,
    const char * type, size_t type_len, const char * entity_id,
    int * out_allowed, GDEFCORE_Access_Decision * dec) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char key[1024];
  int key_len;
  int memo = 0;
  uint64_t version = 0;
  char * actual_type = NULL;
  size_t actual_len = 0;
  int allowed = 0;
  GDEFCORE_Result rc;
  if (out_allowed != NULL) {
    *out_allowed = 0;
  }
  if (catalog == NULL || request == NULL || out_allowed == NULL ||
      permission == NULL || permission_len == 0 || type == NULL ||
      type_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  /* What this request renders now depends on who asked. */
  gdefcore_request_mark_principal_dependent(request);
  rc = gdefcore_request_spend_fuel(request, GDEFCORE_ACCESS_CAN_FUEL_HIT);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* A question about a name no permission has, or longer than any, is a no. */
  if (permission_len > GDEFCORE_ROUTE_PERMISSION_MAX || type_len > kPart) {
    return GDEFCORE_OK;
  }
  rc = ensure(catalog);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (entity_id != NULL) {
    /* The entity must be there, of the type asked about. Missing, malformed
     * and of another type are one answer, and so is unreadable: a no. */
    if (gdefcore_id_canonical(entity_id, strlen(entity_id), canon) !=
        GDEFCORE_OK) {
      return GDEFCORE_OK;
    }
    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        &actual_type, &actual_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_OK;
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    if (!same(actual_type, actual_len, type, type_len)) {
      gdefcore_text_free(catalog, actual_type);
      return GDEFCORE_OK;
    }
    gdefcore_text_free(catalog, actual_type);
    /* The entity's version, not its latest revision: a publish, an
     * unpublish and a clear change what a condition reads or whom a reader
     * sees and write no revision. */
    rc = gdefcore_entity_version(catalog, canon, GDEFCORE_PUBLIC_ID_LEN,
        &version);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_OK;
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    (void)gdefcore_request_record_dependency(request, canon,
        GDEFCORE_PUBLIC_ID_LEN, version);
  } else {
    uint64_t epoch = 0;
    rc = gdefcore_epoch(catalog, &epoch);
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    version = epoch;
  }
  key_len = can_key(key, sizeof key, request, permission, permission_len, type,
      type_len, entity_id == NULL ? NULL : canon, version);
  memo = key_len > 0;
  if (memo && dec == NULL &&
      gdefcore_request_memo_get(request, key, (size_t)key_len, &allowed)) {
    *out_allowed = allowed != 0;
    return GDEFCORE_OK;
  }
  rc = gdefcore_request_spend_fuel(request, GDEFCORE_ACCESS_CAN_FUEL_MISS -
                                               GDEFCORE_ACCESS_CAN_FUEL_HIT);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = can_decide(catalog, request, permission, permission_len, type, type_len,
      entity_id == NULL ? NULL : canon, &allowed, dec);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (memo) {
    (void)gdefcore_request_memo_put(request, key, (size_t)key_len, allowed);
  }
  *out_allowed = allowed != 0;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_can(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * permission, size_t permission_len,
    const char * type, size_t type_len, const char * entity_id,
    int * out_allowed) {
  return can_impl(catalog, request, permission, permission_len, type, type_len,
      entity_id, out_allowed, NULL);
}

/* Whether a field-level grant of @p action for @p field holds. Asked of one
 * entity, a grant holds when its condition does on that entity as stored.
 * Asked with none (a create: there is no stored entity), a grant holds when
 * the permission is the kind that is not about one entity, or when its
 * expression could apply to something; no value being written is consulted. */
static long field_grant_at(Eval * ev, const Grant * grants, size_t ngrants,
    const char * action, size_t action_len, const char * type, size_t type_len,
    const char * field, size_t field_len, const char * actor, size_t actor_len,
    const char * principal, size_t principal_len, int type_level) {
  size_t i;
  for (i = 0; i < ngrants; i++) {
    if (grants[i].field_len == 0 ||
        !same(grants[i].action, grants[i].action_len, action, action_len) ||
        !same(grants[i].type_name, grants[i].type_len, type, type_len) ||
        !same(grants[i].field, grants[i].field_len, field, field_len)) {
      continue;
    }
    if (type_level) {
      if (grants[i].condition == kCondCallback) {
        /* No stored entity to ask the callback about (story A6). */
        continue;
      }
      if (grants[i].condition != kCondExpr || expr_could_apply(ev, &grants[i])) {
        return (long)i;
      }
    } else if (condition_ok(ev, &grants[i], actor, actor_len, principal,
                   principal_len)) {
      return (long)i;
    }
  }
  return -1;
}

/* gdefcore_access_can_field(), the source that allowed it named in @p dec
 * when that is not NULL (story A7). */
static GDEFCORE_Result can_field_impl(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * action, size_t action_len,
    const char * type, size_t type_len, const char * entity_id,
    const char * field, size_t field_len, int * out_allowed,
    GDEFCORE_Access_Decision * dec) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  Grant grants[kGrantMax];
  Grant decls[kGrantMax];
  size_t ngrants = 0;
  size_t ndecls = 0;
  int read_principal = 0;
  int restricted = 0;
  int allowed = 0;
  long win = -1;
  char * actor = NULL;
  size_t actor_len = 0;
  const char * principal;
  size_t principal_len = 0;
  Eval ev;
  size_t i;
  GDEFCORE_Result rc;
  if (out_allowed != NULL) {
    *out_allowed = 0;
  }
  if (catalog == NULL || request == NULL || out_allowed == NULL ||
      action == NULL || action_len == 0 || type == NULL || type_len == 0 ||
      field == NULL || field_len == 0) {
    return GDEFCORE_ERR_INVALID;
  }
  gdefcore_request_mark_principal_dependent(request);
  rc = ensure(catalog);
  if (rc == GDEFCORE_OK) {
    rc = load_decls(catalog, decls, kGrantMax, &ndecls);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < ndecls && !restricted; i++) {
    restricted = decls[i].field_len != 0 &&
                 same(decls[i].action, decls[i].action_len, action, action_len) &&
                 same(decls[i].type_name, decls[i].type_len, type, type_len) &&
                 same(decls[i].field, decls[i].field_len, field, field_len);
  }
  if (!restricted) {
    /* No permission limits this field for this action: the question the
     * caller asked at the entity or the container decides. A field the type
     * does not have is refused, as a field the principal may not act on is
     * (story A7: the answer must not tell the two apart). */
    return type_has_field_rc(catalog, type, type_len, field, field_len,
        out_allowed);
  }
  if (entity_id != NULL) {
    char * actual = NULL;
    size_t actual_len = 0;
    if (gdefcore_id_canonical(entity_id, strlen(entity_id), canon) !=
        GDEFCORE_OK) {
      return GDEFCORE_OK;
    }
    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &actual,
        &actual_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_OK;
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = same(actual, actual_len, type, type_len) ? GDEFCORE_OK
                                                  : GDEFCORE_ERR_INVALID;
    gdefcore_text_free(catalog, actual);
    if (rc != GDEFCORE_OK) {
      return GDEFCORE_OK;
    }
    rc = gdefcore_entity_creator(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &actor,
        &actor_len);
    if (rc != GDEFCORE_OK) {
      return rc == GDEFCORE_ERR_INVALID ? GDEFCORE_OK : rc;
    }
  }
  rc = load_effective(catalog, request, grants, kGrantMax, &ngrants,
      &read_principal);
  if (rc != GDEFCORE_OK) {
    gdefcore_text_free(catalog, actor);
    return rc;
  }
  principal = gdefcore_request_principal(request, &principal_len);
  eval_init(&ev, catalog, request, NULL, 0);
  (void)setup_ceiling(&ev);
  ev.id = entity_id == NULL ? NULL : canon;
  win = field_grant_at(&ev, grants, ngrants, action, action_len, type,
      type_len, field, field_len, actor, actor_len, principal, principal_len,
      entity_id == NULL);
  allowed = win >= 0;
  if (allowed && entity_id == NULL && ev.has_ceiling) {
    /* condition_ok applies the ceiling per entity; with none, the acting
     * principal must hold a grant of its own. */
    allowed = field_grant_at(&ev, ev.ceiling, ev.nceiling, action, action_len,
                  type, type_len, field, field_len, actor, actor_len,
                  principal, principal_len, 1) >= 0;
  }
  gdefcore_text_free(catalog, actor);
  if (allowed && dec != NULL) {
    source_fill(catalog, &grants[win], dec);
  }
  /* A condition that could not be decided is neither a yes nor a no; one that
   * failed beside a grant that holds is a yes (story A7). */
  rc = ev.failed && !allowed ? GDEFCORE_ERR_INTERNAL : GDEFCORE_OK;
  eval_done(&ev);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_allowed = allowed != 0;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_can_field(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * action, size_t action_len,
    const char * type, size_t type_len, const char * entity_id,
    const char * field, size_t field_len, int * out_allowed) {
  return can_field_impl(catalog, request, action, action_len, type, type_len,
      entity_id, field, field_len, out_allowed, NULL);
}

GDEFCORE_Result gdefcore_access_decide(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * action, size_t action_len,
    const char * type, size_t type_len, const char * entity_id,
    const char * field, size_t field_len, GDEFCORE_Access_Decision * out) {
  int allowed = 0;
  GDEFCORE_Result rc;
  if (out == NULL || out->size != sizeof *out) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(out, 0, sizeof *out);
  out->size = sizeof *out;
  if (field != NULL && field_len > 0) {
    rc = can_field_impl(catalog, request, action, action_len, type, type_len,
        entity_id, field, field_len, &allowed, out);
  } else {
    rc = can_impl(catalog, request, action, action_len, type, type_len,
        entity_id, &allowed, out);
  }
  if (rc != GDEFCORE_OK) {
    memset(out, 0, sizeof *out);
    out->size = sizeof *out;
    return rc;
  }
  out->allowed = allowed != 0;
  if (!out->allowed) {
    out->source = GDEFCORE_ACCESS_SOURCE_NONE;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_can_create(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * container, size_t container_len,
    const char * type, size_t type_len, const char * const * fields,
    const size_t * field_lens, size_t nfields, int * out_allowed) {
  static const char kCreate[] = GDEFCORE_ACTION_CREATE;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * ctype = NULL;
  size_t ctype_len = 0;
  int allowed = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (out_allowed != NULL) {
    *out_allowed = 0;
  }
  if (catalog == NULL || request == NULL || out_allowed == NULL || type == NULL ||
      type_len == 0 || (nfields > 0 && (fields == NULL || field_lens == NULL))) {
    return GDEFCORE_ERR_INVALID;
  }
  if (container != NULL) {
    /* The container is the one the path names: the handler took it from the
     * route, never from the form. A grant on the container's type decides,
     * on the container as stored. */
    if (gdefcore_id_canonical(container, container_len, canon) != GDEFCORE_OK) {
      return GDEFCORE_OK;
    }
    rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &ctype,
        &ctype_len);
    if (rc == GDEFCORE_ERR_INVALID) {
      return GDEFCORE_OK;
    }
    if (rc != GDEFCORE_OK) {
      return rc;
    }
    rc = gdefcore_access_can(catalog, request, kCreate, sizeof kCreate - 1,
        ctype, ctype_len, canon, &allowed);
    gdefcore_text_free(catalog, ctype);
  } else {
    /* No container: a grant of `create` on the type itself. */
    rc = gdefcore_access_can(catalog, request, kCreate, sizeof kCreate - 1,
        type, type_len, NULL, &allowed);
  }
  if (rc != GDEFCORE_OK || !allowed) {
    return rc;
  }
  /* Then, field by field, what the new entity is given. A field that no
   * `create` permission limits is not limited; one that is needs a grant that
   * holds with no stored entity to look at. */
  for (i = 0; i < nfields; i++) {
    int field_ok = 0;
    rc = gdefcore_access_can_field(catalog, request, kCreate, sizeof kCreate - 1,
        type, type_len, NULL, fields[i], field_lens[i], &field_ok);
    if (rc != GDEFCORE_OK || !field_ok) {
      return rc;
    }
  }
  *out_allowed = 1;
  return GDEFCORE_OK;
}

int gdefcore_access_route_check(const GDEFCORE_Route_Call * call,
    const char * permission, size_t permission_len, void * data) {
  GDEFCORE_Catalog * catalog = (GDEFCORE_Catalog *)data;
  const char * value = NULL;
  size_t value_len = 0;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char * type = NULL;
  size_t type_len = 0;
  int allowed = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || call == NULL || call->size != sizeof *call ||
      call->request == NULL || permission == NULL || permission_len == 0) {
    return 0;
  }
  if (call->entity_capture_len == 0) {
    return gdefcore_access_permits(catalog, call->request, permission,
        permission_len);
  }
  if (!gdefcore_route_call_capture(call, call->entity_capture,
          call->entity_capture_len, &value, &value_len) ||
      gdefcore_id_canonical(value, value_len, canon) != GDEFCORE_OK) {
    return 0;
  }
  rc = gdefcore_entity_type(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &type,
      &type_len);
  if (rc != GDEFCORE_OK) {
    return 0;
  }
  rc = gdefcore_access_can(catalog, call->request, permission, permission_len,
      type, type_len, canon, &allowed);
  gdefcore_text_free(catalog, type);
  return rc == GDEFCORE_OK && allowed;
}
