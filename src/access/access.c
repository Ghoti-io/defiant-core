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

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/access.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/module.h>

#include "access_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/sha256.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  kAssignedRoles = 8,
  /* A grant whose condition is an expression (condition.h). The public
   * ::GDEFCORE_ACCESS_ANY and ::GDEFCORE_ACCESS_OWN stay 1 and 2. */
  kCondExpr = 3
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
        if (grants[*out_n + g].condition == GDEFCORE_ACCESS_OWN) {
          *read_principal = 1;
        }
      }
      *out_n += got;
    }
    gdefcore_values_free(catalog, held, held_lens, held_n);
    return with_modules ? load_module_grants(catalog, grants, cap, out_n)
                        : GDEFCORE_OK;
  }
  {
    char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
    size_t got = 0;
    size_t g;
    if (find_role(catalog, roles[0], role_lens[0], role_id) != GDEFCORE_OK) {
      return with_modules ? load_module_grants(catalog, grants, cap, out_n)
                          : GDEFCORE_OK;
    }
    if (load_role_grants(catalog, role_id, grants, cap, &got) != GDEFCORE_OK) {
      return GDEFCORE_ERR_INVALID;
    }
    for (g = 0; g < got; g++) {
      if (grants[g].condition == GDEFCORE_ACCESS_OWN) {
        *read_principal = 1;
      }
    }
    *out_n = got;
  }
  return with_modules ? load_module_grants(catalog, grants, cap, out_n)
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

/* One parsed expression, by the label of the permission that carries it. */
typedef struct ExprSlot {
  char label[kPart];
  size_t label_len;
  const char * expr;   /* a module grant is keyed by its text, not a label */
  size_t expr_len;
  GDEFCORE_Condition * cond;
  int bad;
} ExprSlot;

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
}

/* Frees the slots. A failure leaves a note on the request, which is how the
 * caller of a filtered read learns that a condition could not be decided. */
static void eval_done(Eval * ev) {
  size_t i;
  for (i = 0; i < ev->nslots; i++) {
    gdefcore_condition_free(ev->slots[i].cond);
  }
  ev->nslots = 0;
  gcu_allocator_free(alloc_default(), ev->ceiling);
  ev->ceiling = NULL;
  ev->nceiling = 0;
  ev->has_ceiling = 0;
  if (ev->failed && ev->request != NULL) {
    (void)gdefcore_request_set_note(ev->request, kFailedNote,
        strlen(kFailedNote), "1", 1);
  }
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
      if (ev->slots[i].expr != NULL &&
          same(ev->slots[i].expr, ev->slots[i].expr_len, grant->expr,
              grant->expr_len)) {
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

static int entity_visible(Eval * ev, const Grant * grants, size_t ngrants,
    const char * type, size_t type_len, const char * actor, size_t actor_len,
    const char * principal, size_t principal_len) {
  size_t i;
  for (i = 0; i < ngrants; i++) {
    if (!same(grants[i].type_name, grants[i].type_len, type, type_len)) {
      continue;
    }
    if (grants[i].field_len != 0) {
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
      permission->size < sizeof(size_t)) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&local, 0, sizeof local);
  {
    size_t n = permission->size;
    if (n > sizeof local) {
      n = sizeof local;
    }
    memcpy(&local, permission, n);
  }
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

GDEFCORE_Result gdefcore_access_read(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * id, size_t id_len,
    const char * lang, size_t lang_len, const char * field, size_t field_len,
    char *** out_texts, size_t ** out_lens, size_t * out_count) {
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
  GDEFCORE_Result rc;
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
  rc = gdefcore_entity_actor(catalog, canon, GDEFCORE_PUBLIC_ID_LEN, &actor,
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
  visible = entity_visible(&ev, grants, ngrants, type_name, type_len, actor,
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
  if (!visible || !type_has_field(catalog, type_name, type_len, field,
                      field_len)) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return GDEFCORE_ERR_INVALID;
  }
  if (!granted) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    *out_texts = NULL;
    *out_lens = NULL;
    *out_count = 0;
    return GDEFCORE_OK;
  }
  gdefcore_text_free(catalog, type_name);
  gdefcore_text_free(catalog, actor);
  return gdefcore_entity_values(catalog, NULL, GDEFCORE_VIEW_PUBLISHED, canon,
      GDEFCORE_PUBLIC_ID_LEN, lang, lang_len, field, field_len, out_texts,
      out_lens, out_count);
}

struct Listed {
  char * id;
  char * key;
};

static int cmp_listed(const void * a, const void * b) {
  const struct Listed * left = (const struct Listed *)a;
  const struct Listed * right = (const struct Listed *)b;
  const char * ak = left->key == NULL ? "" : left->key;
  const char * bk = right->key == NULL ? "" : right->key;
  return strcmp(ak, bk);
}

static void drop_rows(GDEFCORE_Catalog * catalog, struct Listed * rows,
    size_t nrows, char ** ids, size_t count) {
  size_t i;
  for (i = 0; i < nrows; i++) {
    gdefcore_text_free(catalog, rows[i].id);
    gdefcore_text_free(catalog, rows[i].key);
  }
  gcu_allocator_free(alloc_default(), rows);
  gdefcore_ids_free(catalog, ids, count);
}

static GDEFCORE_Result list_impl(Eval * ev, GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    char *** out_ids, size_t * out_count) {
  GDEFCORE_Access_List local;
  size_t ncopy;
  char ** ids = NULL;
  size_t count = 0;
  struct Listed * rows = NULL;
  size_t nrows = 0;
  char ** result = NULL;
  Grant grants[kGrantMax];
  Grant decls[kGrantMax];
  size_t ngrants = 0;
  size_t ndecls = 0;
  int read_principal = 0;
  const char * principal = NULL;
  size_t principal_len = 0;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || request == NULL || query == NULL || out_ids == NULL ||
      out_count == NULL || query->size < sizeof(size_t)) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_ids = NULL;
  *out_count = 0;
  memset(&local, 0, sizeof local);
  ncopy = query->size;
  if (ncopy > sizeof local) {
    ncopy = sizeof local;
  }
  memcpy(&local, query, ncopy);
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
  if (local.filter_field != NULL && local.filter_field_len > 0) {
    if (!type_has_field(catalog, local.type_name, local.type_name_len,
            local.filter_field, local.filter_field_len) ||
        !grant_names_field(grants, ngrants, decls, ndecls, local.type_name,
            local.type_name_len, local.filter_field, local.filter_field_len,
            principal, principal_len)) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  if (local.sort_field != NULL && local.sort_field_len > 0) {
    if (!type_has_field(catalog, local.type_name, local.type_name_len,
            local.sort_field, local.sort_field_len) ||
        !grant_names_field(grants, ngrants, decls, ndecls, local.type_name,
            local.type_name_len, local.sort_field, local.sort_field_len,
            principal, principal_len)) {
      return GDEFCORE_ERR_INVALID;
    }
  }
  rc = gdefcore_entity_ids(catalog, local.type_name, local.type_name_len, &ids,
      &count);
  if (rc != GDEFCORE_OK) {
    return rc;
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
    rc = gdefcore_entity_actor(catalog, ids[i], GDEFCORE_PUBLIC_ID_LEN, &actor,
        &actor_len);
    if (rc != GDEFCORE_OK) {
      drop_rows(catalog, rows, nrows, ids, count);
      return rc;
    }
    ev->id = ids[i];
    if (!entity_visible(ev, grants, ngrants, local.type_name,
            local.type_name_len, actor, actor_len, principal, principal_len)) {
      gdefcore_text_free(catalog, actor);
      continue;
    }
    if ((local.filter_field != NULL && local.filter_field_len > 0 &&
            !may_name_field(ev, grants, ngrants, decls, ndecls,
                local.type_name, local.type_name_len, local.filter_field,
                local.filter_field_len, actor, actor_len, principal,
                principal_len)) ||
        (local.sort_field != NULL && local.sort_field_len > 0 &&
            !may_name_field(ev, grants, ngrants, decls, ndecls,
                local.type_name, local.type_name_len, local.sort_field,
                local.sort_field_len, actor, actor_len, principal,
                principal_len))) {
      gdefcore_text_free(catalog, actor);
      drop_rows(catalog, rows, nrows, ids, count);
      return GDEFCORE_ERR_INVALID;
    }
    gdefcore_text_free(catalog, actor);
    if (local.filter_text != NULL && local.filter_field != NULL &&
        local.filter_field_len > 0) {
      char field_name[65];
      if (local.filter_field_len >= sizeof field_name) {
        drop_rows(catalog, rows, nrows, ids, count);
        return GDEFCORE_ERR_LIMIT;
      }
      memcpy(field_name, local.filter_field, local.filter_field_len);
      field_name[local.filter_field_len] = '\0';
      rc = read_lang(catalog, ids[i], local.lang, local.lang_len, field_name,
          &texts, &lens, &n);
      if (rc != GDEFCORE_OK) {
        gdefcore_values_free(catalog, texts, lens, n);
        drop_rows(catalog, rows, nrows, ids, count);
        return rc;
      }
      if (!values_have(texts, lens, n, local.filter_text,
              local.filter_text_len)) {
        gdefcore_values_free(catalog, texts, lens, n);
        continue;
      }
      gdefcore_values_free(catalog, texts, lens, n);
    }
    rc = gdefcore_text_dup(catalog, ids[i], strlen(ids[i]), &rows[nrows].id);
    if (rc != GDEFCORE_OK) {
      drop_rows(catalog, rows, nrows, ids, count);
      return rc;
    }
    if (local.sort_field != NULL && local.sort_field_len > 0) {
      char field_name[65];
      if (local.sort_field_len >= sizeof field_name) {
        gdefcore_text_free(catalog, rows[nrows].id);
        drop_rows(catalog, rows, nrows, ids, count);
        return GDEFCORE_ERR_LIMIT;
      }
      memcpy(field_name, local.sort_field, local.sort_field_len);
      field_name[local.sort_field_len] = '\0';
      rc = read_lang(catalog, ids[i], local.lang, local.lang_len, field_name,
          &texts, &lens, &n);
      if (rc != GDEFCORE_OK) {
        gdefcore_values_free(catalog, texts, lens, n);
        gdefcore_text_free(catalog, rows[nrows].id);
        drop_rows(catalog, rows, nrows, ids, count);
        return rc;
      }
      if (n > 0) {
        gdefcore_text_dup(catalog, texts[0], lens[0], &rows[nrows].key);
      }
      gdefcore_values_free(catalog, texts, lens, n);
    }
    nrows += 1;
  }
  gdefcore_ids_free(catalog, ids, count);
  if (local.sort_field != NULL && local.sort_field_len > 0 && nrows > 1) {
    qsort(rows, nrows, sizeof *rows, cmp_listed);
  }
  result = (char **)gcu_allocator_calloc(alloc_default(),
      nrows > 0 ? nrows : 1, sizeof *result);
  if (result == NULL) {
    for (i = 0; i < nrows; i++) {
      gdefcore_text_free(catalog, rows[i].id);
      gdefcore_text_free(catalog, rows[i].key);
    }
    gcu_allocator_free(alloc_default(), rows);
    return GDEFCORE_ERR_OOM;
  }
  for (i = 0; i < nrows; i++) {
    result[i] = rows[i].id;
    gdefcore_text_free(catalog, rows[i].key);
  }
  gcu_allocator_free(alloc_default(), rows);
  *out_ids = result;
  *out_count = nrows;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_access_list(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const GDEFCORE_Access_List * query,
    char *** out_ids, size_t * out_count) {
  Eval ev;
  GDEFCORE_Result rc;
  memset(&ev, 0, sizeof ev);
  rc = list_impl(&ev, catalog, request, query, out_ids, out_count);
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
       * all, makes the render depend on who is asking. */
      ExprSlot * slot = expr_slot(&ev, &grants[i]);
      if (slot == NULL || slot->bad ||
          (gdefcore_condition_uses(slot->cond) &
              GDEFCORE_CONDITION_USES_PRINCIPAL) != 0) {
        read_principal = 1;
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
    ADD_KEY("\nmodule:", 8);
    ADD_KEY(module_text, strlen(module_text));
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
static int permits_in(Eval * ev, const Grant * grants, size_t ngrants,
    const char * permission, size_t permission_len) {
  size_t i;
  for (i = 0; i < ngrants; i++) {
    if (!same(grants[i].action, grants[i].action_len, permission,
            permission_len)) {
      continue;
    }
    if (grants[i].condition != kCondExpr || expr_could_apply(ev, &grants[i])) {
      return 1;
    }
  }
  return 0;
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
  held = permits_in(&ev, grants, ngrants, permission, permission_len);
  if (held && ev.has_ceiling) {
    /* The intersection: the acting principal must hold it too. */
    held = permits_in(&ev, ev.ceiling, ev.nceiling, permission, permission_len);
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
      out->size < sizeof *out) {
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
      "unpublish", "admin", "grant", "revert", "restore", "install", "enable",
      "disable", NULL};
  static const char * const kEdit[] = {"update", "edit", "create", "save",
      "draft", "write", NULL};
  static const char * const kRead[] = {"read", "view", "list", "search",
      "count", "export", NULL};
  int strong = 0;
  int edit = 0;
  int read = 0;
  size_t start = 0;
  size_t i;
  if (action == NULL) {
    return kClassStrong;
  }
  for (i = 0; i <= len; i++) {
    if (i == len || action[i] == '.') {
      size_t n = i - start;
      if (in_words(action + start, n, kStrong)) {
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
  if (edit) {
    return kClassEdit;
  }
  return read ? kClassRead : kClassStrong;
}

int gdefcore_access_grant_risk(const char * action, size_t action_len,
    int has_field, const char * condition_text, size_t condition_len,
    int reaches_anonymous) {
  GDEFCORE_Condition * cond = NULL;
  int cls = action_class(action, action_len);
  unsigned uses;
  int constrains;
  int narrowing;
  int own_like;
  if (condition_text == NULL ||
      gdefcore_condition_parse(condition_text, condition_len, &cond, NULL) !=
          GDEFCORE_OK) {
    /* A condition that cannot be read has a breadth nobody can state. */
    return GDEFCORE_ACCESS_RISK_HIGH;
  }
  uses = gdefcore_condition_uses(cond);
  constrains = gdefcore_condition_constrains_type(cond);
  gdefcore_condition_free(cond);
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
  if (own_like) {
    return GDEFCORE_ACCESS_RISK_LOW;
  }
  if (has_field) {
    return GDEFCORE_ACCESS_RISK_MEDIUM;
  }
  if (cls == kClassRead && narrowing) {
    return GDEFCORE_ACCESS_RISK_LOW;
  }
  return GDEFCORE_ACCESS_RISK_MEDIUM;
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

GDEFCORE_Result gdefcore_access_stage_module_grant(
    GDEFCORE_Changeset * changeset, const char * module_name,
    size_t module_name_len, const char * label, size_t label_len,
    const char * action, size_t action_len, const char * type_name,
    size_t type_name_len, const char * field, size_t field_len,
    const char * condition_text, size_t condition_len) {
  GDEFCORE_Condition * cond = NULL;
  char * explain = NULL;
  size_t explain_len = 0;
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
    rc = gdefcore_condition_validate(gdefcore_changeset_catalog(changeset), cond,
        type_name, type_name_len, NULL);
  }
  if (rc == GDEFCORE_OK) {
    rc = gdefcore_condition_explain(cond, &explain, &explain_len);
  }
  if (rc != GDEFCORE_OK) {
    gdefcore_condition_free(cond);
    return rc;
  }
  /* Not held by a role: it reaches the anonymous state unless the condition
   * reads the principal. */
  risk = gdefcore_access_grant_risk(action, action_len, field_len > 0,
      condition_text, condition_len,
      (gdefcore_condition_uses(cond) & GDEFCORE_CONDITION_USES_PRINCIPAL) == 0);
  gdefcore_condition_free(cond);
  cap = module_name_len + label_len + explain_len + 64;
  line = (char *)gcu_allocator_malloc(alloc_default(), cap);
  if (line == NULL) {
    gdefcore_condition_text_free(explain);
    return GDEFCORE_ERR_OOM;
  }
  n = snprintf(line, cap, "Module %.*s grants %.*s (%s risk): %.*s",
      (int)module_name_len, module_name, (int)label_len, label,
      gdefcore_access_risk_name(risk), (int)explain_len, explain);
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

/* Add one row. @p cond is the canonical text, or NULL when @p cond_raw is all
 * that is known (a condition that cannot be parsed). */
static GDEFCORE_Result mx_add(MatrixBuild * b, const char * source,
    size_t source_len, int from_module, const char * label, size_t label_len,
    const char * action, size_t action_len, const char * type_name,
    size_t type_len, const char * field, size_t field_len, const char * cond,
    size_t cond_len, int reaches_anonymous) {
  GDEFCORE_Access_Matrix_Row * row;
  GDEFCORE_Condition * parsed = NULL;
  char * explain = NULL;
  size_t explain_len = 0;
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
  if (gdefcore_condition_parse(cond, cond_len, &parsed, NULL) == GDEFCORE_OK) {
    rc = gdefcore_condition_explain(parsed, &explain, &explain_len);
    gdefcore_condition_free(parsed);
  }
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  row->risk = gdefcore_access_grant_risk(action, action_len, field_len > 0, cond,
      cond_len, reaches_anonymous);
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
  if (rc != GDEFCORE_OK) {
    mx_free_row(b->catalog, row);
    return rc;
  }
  b->n += 1;
  return GDEFCORE_OK;
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
    if (grants[i].condition == kCondExpr) {
      ExprSlot * slot = expr_slot(ev, &grants[i]);
      if (slot == NULL || slot->bad) {
        return GDEFCORE_ERR_CORRUPT;
      }
      rc = gdefcore_condition_canonical(slot->cond, &canon, &canon_len);
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
        text_len, anonymous);
  }
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
    if (gdefcore_condition_parse(item->condition, item->condition_len, &parsed,
            NULL) == GDEFCORE_OK) {
      anonymous = (gdefcore_condition_uses(parsed) &
                      GDEFCORE_CONDITION_USES_PRINCIPAL) == 0;
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
        canon != NULL ? canon_len : item->condition_len, anonymous);
    gdefcore_condition_text_free(canon);
  }
  if (host != NULL) {
    gdefcore_module_declared_free(host, items);
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
