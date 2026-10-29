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
 * @file settings.h
 * @brief Settings: declared by the kernel and by modules, stored only when
 * changed, edited through a generated form.
 * @stability free
 *
 * A **setting** is declared (the kernel's own below, a module's in its
 * manifest, GDEFCORE_Module_Setting) with a name, a type (`text`, `number` or
 * `boolean`), a default, a label, a group and optionally bounds. A setting
 * that equals its default stores nothing and follows the default, so a later
 * change to a module's default reaches every site that never changed it and
 * no site that did.
 *
 * A changed value is a `core.setting` entity on the entity port, named by the
 * setting, written by changeset (revisions, undo) and read from the catalog's
 * own tenant. Saving a form changes the config epoch like any applied
 * changeset, so a title changed in the browser shows on the next request and
 * every fragment that carried the old one is keyed out (AD-30).
 *
 * An **environment-local** setting (an API key, a banner) is different in one
 * way: its value is never in the tenant's truth. The entity port holds only a
 * marker for it (the name, the group and a serial, so that a change is
 * revisioned, authorized and moves the epoch like any other), and the value
 * itself is a record in the environment scope of the catalog's store
 * (tenant byte `0x03`, keyed by the tenant), beside the module host's own
 * installation record. So a snapshot never carries a local value, a restore
 * never writes one, and a revision never keeps an old one. The configuration
 * export (gdefcore_settings_export()) leaves local settings out, and the
 * import (gdefcore_settings_import()) drops any it is handed, so the target
 * keeps its own value, or none.
 *
 * **Who may edit** is one permission, ::GDEFCORE_SETTINGS_EDIT on
 * ::GDEFCORE_SETTING_TYPE, with a condition that may name the setting's
 * `name` and `group` (the group is spelled `<module>.<group>`). It is decided
 * by the one gdefcore_access_can_with(), for each setting a changeset writes,
 * in apply (gdefcore_settings_authorize()).
 *
 * The **form** for a group is generated (gdefcore_settings_form_html()): a
 * field for each setting, its description and its bounds, and for a secret
 * setting whether it is set and never its value.
 */

#ifndef GHOTI_IO_GDEFCORE_SETTINGS_H
#define GHOTI_IO_GDEFCORE_SETTINGS_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>
#include <ghoti.io/defiant-core/request.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The entity type of a changed setting. Its fields: `name`, `group`; and
 * optional `value` (never on a local setting) and `serial` (local only). */
#define GDEFCORE_SETTING_TYPE "core.setting"
/** The action of the permission to edit settings. */
#define GDEFCORE_SETTINGS_EDIT "core.settings.edit"
/** The label of that permission. */
#define GDEFCORE_SETTINGS_EDIT_LABEL "Edit settings"

/** The kernel's settings: the site title and the tagline. */
#define GDEFCORE_SETTING_SITE_TITLE "core.site_title"
#define GDEFCORE_SETTING_TAGLINE "core.tagline"
/** The group of the kernel's settings, `<module>.<group>`. */
#define GDEFCORE_SETTINGS_CORE_GROUP "core.site"

/** How many settings the kernel declares. */
#define GDEFCORE_SETTINGS_BUILTIN 2
/** Longest `<module>.<group>` key, in bytes. */
#define GDEFCORE_SETTING_GROUP_MAX 160
/** Longest text value of a setting that declares no length, in bytes. */
#define GDEFCORE_SETTING_TEXT_MAX 4096
/** Most settings one save changes. */
#define GDEFCORE_SETTINGS_SAVE_MAX 64

/** Where an effective value comes from. */
#define GDEFCORE_SETTING_FROM_DEFAULT 0
#define GDEFCORE_SETTING_FROM_SITE 1
#define GDEFCORE_SETTING_FROM_LOCAL 2

/**
 * @brief A setting as the catalog reports it. Begins with @ref size.
 *
 * The texts are borrowed: those of a kernel setting are static, a module's are
 * the host's and valid until it is destroyed. @ref group is a copy.
 */
typedef struct GDEFCORE_Setting {
  size_t size;                ///< `sizeof(GDEFCORE_Setting)`.
  const char * name;          ///< `core.site_title`, ... or `<module>.<name>`.
  size_t name_len;            ///< Length of @ref name.
  const char * module;        ///< The declaring module; `core` for the kernel.
  size_t module_len;          ///< Length of @ref module.
  const char * type;          ///< `text`, `number` or `boolean`.
  size_t type_len;            ///< Length of @ref type.
  const char * default_value; ///< Never NULL.
  size_t default_len;         ///< Length of @ref default_value.
  const char * label;         ///< Never NULL.
  size_t label_len;           ///< Length of @ref label.
  const char * description;   ///< Never NULL; may be empty.
  size_t description_len;     ///< Length of @ref description.
  const char * minimum;       ///< Never NULL; empty for none.
  size_t minimum_len;         ///< Length of @ref minimum.
  const char * maximum;       ///< Never NULL; empty for none.
  size_t maximum_len;         ///< Length of @ref maximum.
  size_t max_length;          ///< A text's longest value, 0 for the default.
  int local;                  ///< Environment-local.
  int secret;                 ///< Never shown once stored.
  int builtin;                ///< Declared by the kernel.
  char group[GDEFCORE_SETTING_GROUP_MAX]; ///< `<module>.<group>`, NUL-ended.
  size_t group_len;           ///< Length of @ref group.
} GDEFCORE_Setting;

/** @brief A settings group (one page tab). Begins with @ref size. */
typedef struct GDEFCORE_Settings_Group {
  size_t size;                ///< `sizeof(GDEFCORE_Settings_Group)`.
  char key[GDEFCORE_SETTING_GROUP_MAX]; ///< `<module>.<group>`, NUL-ended.
  size_t key_len;             ///< Length of @ref key.
  char module[GDEFCORE_MODULE_DECL_NAME_MAX + 1]; ///< The module, NUL-ended.
  char name[GDEFCORE_MODULE_DECL_NAME_MAX + 1];   ///< The group, NUL-ended.
  size_t count;               ///< How many settings it holds.
} GDEFCORE_Settings_Group;

/**
 * @brief Define the type of a changed setting and declare the permission to
 * edit settings, which is granted to nobody. Repeating it changes nothing.
 * The render kit does it.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_declare(GDEFCORE_Catalog * catalog);

/**
 * @brief Whether @p value is a valid value of a setting declared with these
 * properties: the type, the bounds and the length. 1 or 0; @p why, if not
 * NULL, receives a static sentence on 0.
 */
GDEFCORE_API int gdefcore_settings_check(const char * type, size_t type_len,
    const char * minimum, size_t minimum_len, const char * maximum,
    size_t maximum_len, size_t max_length, const char * value, size_t value_len,
    const char ** why);

/**
 * @brief Compare two decimal numbers (`-12`, `3.50`): -1, 0 or 1. Not locale
 * dependent. Anything that is not a number compares equal to nothing and
 * returns 2.
 */
GDEFCORE_API int gdefcore_settings_decimal_cmp(const char * a, size_t a_len,
    const char * b, size_t b_len);

/** @brief How many settings the catalog's tenant has: the kernel's and those of
 * the modules enabled for it. */
GDEFCORE_API size_t gdefcore_settings_count(GDEFCORE_Catalog * catalog);

/** @brief Setting @p index: the kernel's first, then the modules' in module
 * order and by name. ::GDEFCORE_ERR_INVALID past the end. */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_at(GDEFCORE_Catalog * catalog,
    size_t index, GDEFCORE_Setting * out);

/** @brief The setting @p name, or ::GDEFCORE_ERR_INVALID if the tenant has none
 * (a module's setting of a module that is disabled is none). */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_find(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, GDEFCORE_Setting * out);

/** @brief How many groups the tenant's settings fall into. */
GDEFCORE_API size_t gdefcore_settings_group_count(GDEFCORE_Catalog * catalog);

/** @brief Group @p index, kernel groups first, then by key. */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_group_at(
    GDEFCORE_Catalog * catalog, size_t index, GDEFCORE_Settings_Group * out);

/**
 * @brief The effective value of a setting: the site's changed value, the
 * environment's local value, or the default.
 *
 * @param out Receives a copy; free it with gdefcore_text_free().
 * @param out_source Receives a `GDEFCORE_SETTING_FROM_` value. May be NULL.
 * @return ::GDEFCORE_OK, or ::GDEFCORE_ERR_INVALID for a setting the tenant
 *   does not have.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_get(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len, char ** out, size_t * out_len,
    int * out_source);

/**
 * @brief Whether a setting has a value of its own (a changed value, or a local
 * one): the answer a form gives for a secret setting. 1 or 0.
 */
GDEFCORE_API int gdefcore_settings_is_set(GDEFCORE_Catalog * catalog,
    const char * name, size_t name_len);

/**
 * @brief Stage one non-local setting's value in @p changeset.
 *
 * A value equal to the default stages the removal of the stored value, or
 * nothing when there is none; a value equal to the stored one stages nothing.
 * @p out_changed, if not NULL, is 1 when the changeset now writes something
 * for the setting. ::GDEFCORE_ERR_INVALID for an unknown setting, a local one
 * (gdefcore_settings_save() writes those) and a value that fails
 * gdefcore_settings_check().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_stage(GDEFCORE_Changeset * changeset,
    const char * name, size_t name_len, const char * value, size_t value_len,
    int * out_changed);

/** @brief One setting's new value for gdefcore_settings_save(). */
typedef struct GDEFCORE_Setting_Change {
  size_t size;                ///< `sizeof(GDEFCORE_Setting_Change)`.
  const char * name;          ///< The setting.
  size_t name_len;            ///< Length of @ref name.
  const char * value;         ///< Its new value.
  size_t value_len;           ///< Length of @ref value.
} GDEFCORE_Setting_Change;

/**
 * @brief A group's version: a text that changes when any of its settings is
 * changed, by anyone. A form carries it and a save is refused if it moved.
 * It holds nothing of a value. @p out is 16 hex digits and a NUL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_group_version(
    GDEFCORE_Catalog * catalog, const char * group, size_t group_len,
    char out[17]);

/**
 * @brief Save the values of a form, all or nothing.
 *
 * Every change is checked first (a known setting, of @p group when it is not
 * NULL, a valid value) and nothing is written if any is not: the result is
 * ::GDEFCORE_ERR_INVALID and @p out_message says which and why in plain words.
 * A change that leaves a setting as it is writes nothing. If none writes
 * anything the config epoch does not move. @p expected_version, if not NULL, is
 * what gdefcore_settings_group_version() said when the form was drawn: another
 * value is ::GDEFCORE_ERR_STALE and nothing is written. The principal must
 * hold ::GDEFCORE_SETTINGS_EDIT for every setting that changes (apply decides,
 * entry by entry), else ::GDEFCORE_ERR_INVALID with the fixed sentence "That
 * edit is not allowed." The changes to non-local settings are one changeset
 * that carries @p request; the local values are written before it is applied
 * and put back if it is refused.
 *
 * @param out_written Receives how many settings changed. May be NULL.
 * @param out_message Receives a sentence on a refusal, else NULL. Free it with
 *   gdefcore_text_free(). May be NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_save(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request, const char * group, size_t group_len,
    const char * expected_version, const GDEFCORE_Setting_Change * changes,
    size_t count, size_t * out_written, char ** out_message,
    size_t * out_message_len);

/**
 * @brief Whether the principal could edit settings at all: the type-level
 * question gdefcore_access_permits() asks. 1 or 0.
 */
GDEFCORE_API int gdefcore_settings_may_edit(GDEFCORE_Catalog * catalog,
    GDEFCORE_Request * request);

/**
 * @brief The generated form of group @p group, as HTML.
 *
 * `<form method="post" action=@p action>` with the hidden field `token` (the
 * caller's signed token), the hidden field `version`, and for each setting of
 * the group a field named `s.<name>` and, for a secret setting, a checkbox
 * `c.<name>` that clears it. Every text is escaped. A secret setting is
 * shown as set or not set and its value is not in the output. ::GDEFCORE_ERR_
 * INVALID for a principal who may not edit settings and for an unknown group;
 * the two are not told apart. Free @p out with gdefcore_text_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_form_html(
    GDEFCORE_Catalog * catalog, GDEFCORE_Request * request, const char * group,
    size_t group_len, const char * action, const char * token, char ** out,
    size_t * out_len);

/**
 * @brief Refuse a changeset that writes a setting that is not valid: an
 * unknown name, a group that is not the setting's, a value that fails its
 * declaration, a value on a local setting (a local value is never an entity),
 * or a marker that is not one. Called by apply, with or without a request.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_vet(GDEFCORE_Changeset * changeset);

/**
 * @brief Refuse a changeset a principal may not make: one action,
 * ::GDEFCORE_SETTINGS_EDIT, asked of each setting it writes as it is stored and
 * as the write leaves it. The refusal is "That edit is not allowed." Called by
 * apply for a changeset that carries a request.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_authorize(
    GDEFCORE_Changeset * changeset, GDEFCORE_Request * request);

/**
 * @brief The configuration export of the site's settings: a
 * `defiant-changeset/1` tree of the changed, non-local settings. Local
 * settings are not in it. Free with gdefcore_patch_free().
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_export(GDEFCORE_Catalog * catalog,
    GDEFCORE_Patch ** out_files, size_t * out_count);

/**
 * @brief Parse a settings export into a changeset for this catalog.
 *
 * The files are untrusted. Only `core.setting` entities are accepted; anything
 * else is ::GDEFCORE_ERR_INVALID. A setting is matched to this site's by name:
 * the changeset writes the entity this site has for it, or a new one. A local
 * setting in the files is dropped (counted in @p out_skipped_local), as is one
 * this tenant does not declare (@p out_skipped_unknown): the target keeps its
 * own local value, or none. The changeset is retargeted at the current epoch;
 * the caller applies it.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_settings_import(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Patch * files, size_t count, GDEFCORE_Changeset ** out_changeset,
    size_t * out_skipped_local, size_t * out_skipped_unknown);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_SETTINGS_H */
