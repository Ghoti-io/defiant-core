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
  kAssignedRoles = 8
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

static int retired_id(GDEFCORE_Catalog * catalog, const char * id) {
  char ** texts = NULL;
  size_t * lens = NULL;
  size_t count = 0;
  int retired = 0;
  if (read_values(catalog, id, "retired", &texts, &lens, &count) !=
      GDEFCORE_OK) {
    return 0;
  }
  retired = values_have(texts, lens, count, kRetired, strlen(kRetired));
  gdefcore_values_free(catalog, texts, lens, count);
  return retired;
}

static GDEFCORE_Result find_named(GDEFCORE_Catalog * catalog, const char * type,
    const char * field, const char * want, size_t want_len, char * out_id) {
  char ** ids = NULL;
  size_t count = 0;
  size_t i;
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
    if (retired_id(catalog, ids[i])) {
      continue;
    }
    if (read_values(catalog, ids[i], field, &texts, &lens, &n) != GDEFCORE_OK) {
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
  if (find_role(catalog, kAdmin, strlen(kAdmin), admin_role) == GDEFCORE_OK) {
    return GDEFCORE_OK;
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
  const char * cond = grant->condition == GDEFCORE_ACCESS_OWN ? "own" : "any";
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

static int condition_ok(const Grant * grant, const char * actor,
    size_t actor_len, const char * principal, size_t principal_len) {
  if (grant->condition == GDEFCORE_ACCESS_ANY) {
    return 1;
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

static GDEFCORE_Result load_effective(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, Grant * grants, size_t cap, size_t * out_n,
    int * read_principal) {
  const char * principal = NULL;
  size_t principal_len = 0;
  char principal_id[GDEFCORE_PUBLIC_ID_LEN + 1];
  const char * roles[kAssignedRoles + 1];
  size_t role_lens[kAssignedRoles + 1];
  size_t nroles = 0;
  size_t i;
  *out_n = 0;
  *read_principal = 0;
  if (request != NULL) {
    principal = gdefcore_request_principal(request, &principal_len);
  }
  if (principal == NULL) {
    roles[nroles] = kAnonymous;
    role_lens[nroles] = strlen(kAnonymous);
    nroles += 1;
  } else {
    char ** held = NULL;
    size_t * held_lens = NULL;
    size_t held_n = 0;
    GDEFCORE_Result rc;
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
    return GDEFCORE_OK;
  }
  {
    char role_id[GDEFCORE_PUBLIC_ID_LEN + 1];
    size_t got = 0;
    size_t g;
    if (find_role(catalog, roles[0], role_lens[0], role_id) != GDEFCORE_OK) {
      return GDEFCORE_OK;
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
  return GDEFCORE_OK;
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

static int entity_visible(const Grant * grants, size_t ngrants,
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
        condition_ok(&grants[i], actor, actor_len, principal, principal_len)) {
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

static int field_granted(const Grant * grants, size_t ngrants, const char * type,
    size_t type_len, const char * field, size_t field_len, const char * actor,
    size_t actor_len, const char * principal, size_t principal_len) {
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
    if (condition_ok(&grants[i], actor, actor_len, principal, principal_len)) {
      return 1;
    }
  }
  return 0;
}

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
    if (grants[i].condition == GDEFCORE_ACCESS_ANY) {
      return 1;
    }
    if (grants[i].condition == GDEFCORE_ACCESS_OWN && principal != NULL &&
        principal_len > 0) {
      return 1;
    }
  }
  return 0;
}

static int may_name_field(const Grant * grants, size_t ngrants,
    const Grant * decls, size_t ndecls, const char * type, size_t type_len,
    const char * field, size_t field_len, const char * actor, size_t actor_len,
    const char * principal, size_t principal_len) {
  if (!field_restricted(decls, ndecls, type, type_len, field, field_len)) {
    return 1;
  }
  return field_granted(grants, ngrants, type, type_len, field, field_len, actor,
      actor_len, principal, principal_len);
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
    } else {
      grant->condition = GDEFCORE_ACCESS_ANY;
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
    const Grant * grant, const char * module_name, size_t module_len) {
  char existing[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFCORE_Value values[6];
  const char * texts[6];
  size_t lens[6];
  Grant stored;
  const char * cond;
  if (permission_by_label(catalog, grant->label, grant->label_len, existing,
          &stored, NULL, 0, NULL) == GDEFCORE_OK) {
    return GDEFCORE_OK;
  }
  cond = grant->condition == GDEFCORE_ACCESS_OWN ? "own" : "any";
  texts[0] = grant->label;
  lens[0] = grant->label_len;
  texts[1] = module_name;
  lens[1] = module_len;
  texts[2] = grant->action;
  lens[2] = grant->action_len;
  texts[3] = cond;
  lens[3] = 3;
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
  if (check_confirm) {
    if (same(role, role_len, kAuthenticated, strlen(kAuthenticated))) {
      if (!same(confirmation, confirmation_len,
              GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED,
              strlen(GDEFCORE_ACCESS_CONFIRM_AUTHENTICATED))) {
        return GDEFCORE_ERR_INVALID;
      }
    } else if (same(role, role_len, kAnonymous, strlen(kAnonymous))) {
      if (!same(confirmation, confirmation_len, GDEFCORE_ACCESS_CONFIRM_ANONYMOUS,
              strlen(GDEFCORE_ACCESS_CONFIRM_ANONYMOUS))) {
        return GDEFCORE_ERR_INVALID;
      }
    } else if (!same(confirmation, confirmation_len, kRoleConfirm,
                   strlen(kRoleConfirm))) {
      return GDEFCORE_ERR_INVALID;
    }
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
  rc = declare_grant(catalog, &grant, "core", 4);
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
  if (!line_ok(local.label, local.label_len) ||
      !line_ok(local.module_name, local.module_name_len) ||
      !line_ok(local.action, local.action_len) ||
      !line_ok(local.type_name, local.type_name_len) ||
      (local.condition != GDEFCORE_ACCESS_ANY &&
          local.condition != GDEFCORE_ACCESS_OWN)) {
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
  return declare_grant(catalog, &grant, local.module_name,
      local.module_name_len);
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
  if (!entity_visible(grants, ngrants, type_name, type_len, actor, actor_len,
          principal, principal_len)) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return GDEFCORE_ERR_INVALID;
  }
  if (!type_has_field(catalog, type_name, type_len, field, field_len)) {
    gdefcore_text_free(catalog, type_name);
    gdefcore_text_free(catalog, actor);
    return GDEFCORE_ERR_INVALID;
  }
  if (field_restricted(decls, ndecls, type_name, type_len, field, field_len) &&
      !field_granted(grants, ngrants, type_name, type_len, field, field_len,
          actor, actor_len, principal, principal_len)) {
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

GDEFCORE_Result gdefcore_access_list(GDEFCORE_Catalog * catalog,
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
    if (!entity_visible(grants, ngrants, local.type_name, local.type_name_len,
            actor, actor_len, principal, principal_len)) {
      gdefcore_text_free(catalog, actor);
      continue;
    }
    if ((local.filter_field != NULL && local.filter_field_len > 0 &&
            !may_name_field(grants, ngrants, decls, ndecls, local.type_name,
                local.type_name_len, local.filter_field, local.filter_field_len,
                actor, actor_len, principal, principal_len)) ||
        (local.sort_field != NULL && local.sort_field_len > 0 &&
            !may_name_field(grants, ngrants, decls, ndecls, local.type_name,
                local.type_name_len, local.sort_field, local.sort_field_len,
                actor, actor_len, principal, principal_len))) {
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
  GDEFCORE_Result rc;
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
  if ((read_principal || gdefcore_request_principal_dependent(request)) &&
      principal != NULL && principal_len > 0) {
    principal_text = principal;
    principal_text_len = principal_len;
  }
  for (i = 0; i < ngrants; i++) {
    char line[512];
    int n = snprintf(line, sizeof line, "%.*s\t%s\t%.*s\t%.*s\t%.*s\n",
        (int)grants[i].label_len, grants[i].label,
        grants[i].condition == GDEFCORE_ACCESS_OWN ? "own" : "any",
        (int)grants[i].type_len, grants[i].type_name,
        (int)grants[i].field_len, grants[i].field, (int)grants[i].action_len,
        grants[i].action);
    char * copy;
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
  for (i = 0; i < nlines; i++) {
    gcu_allocator_free(alloc_default(), lines[i]);
  }
  gcu_allocator_free(alloc_default(), blob);
  gcu_allocator_free(alloc_default(), key);
  return rc;
}

int gdefcore_access_permits(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * permission, size_t permission_len) {
  Grant grants[kGrantMax];
  size_t ngrants = 0;
  int read_principal = 0;
  size_t i;
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
  for (i = 0; i < ngrants; i++) {
    if (same(grants[i].action, grants[i].action_len, permission,
            permission_len)) {
      return 1;
    }
  }
  return 0;
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
        local[i].module_len);
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
