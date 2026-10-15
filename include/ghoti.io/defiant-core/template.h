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
 * @file template.h
 * @brief Template kinds, layered contracts, and template validation.
 * @stability free
 *
 * A template is a `core.template` entity with a `kind`. A kind is a
 * `core.template-kind` entity whose base contract lists the variables
 * (name, type, description) and functions (name, arity) a template of that
 * kind may use. Enabled modules add variables to a kind through
 * gdefcore_module_contribute(); the base plus those contributions, in AD-10
 * order, is the kind's effective contract.
 *
 * Validation parses a template with Tang and walks the syntax tree: every
 * `use` path, every identifier read that the template does not itself assign
 * or declare, and every called function must be in the effective contract.
 * Local variables, loops and functions the template declares are free. A
 * `.raw` needs the AD-18 marker, the greppable word `unsafe` on its line.
 *
 * A kind's fields, as stored: `name` (machine name, `core.page`), `label`,
 * `version` (an integer), `variables` (many; each value is `name type
 * description`, the description being the rest of the line) and `functions`
 * (many; each value is `name arity`, arity an integer or `any`). A type is
 * `text`, `markup`, `number`, `list`, `entity` or `structure`.
 */

#ifndef GHOTI_IO_GDEFCORE_TEMPLATE_H
#define GHOTI_IO_GDEFCORE_TEMPLATE_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-core/module.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The entity type that holds a template kind. */
#define GDEFCORE_TEMPLATE_KIND_TYPE "core.template-kind"
/** The entity type that holds a template. */
#define GDEFCORE_TEMPLATE_TYPE "core.template"
/** The word that marks an unsafe construct on its line (AD-18). */
#define GDEFCORE_TEMPLATE_MARKER "unsafe"

/** A variable of text. A template prints it escaped. */
#define GDEFCORE_TEMPLATE_TEXT 1
/** A variable of already-safe markup: the one trusted type. */
#define GDEFCORE_TEMPLATE_MARKUP 2
/** A variable that is a number. */
#define GDEFCORE_TEMPLATE_NUMBER 3
/** A variable that is a list. */
#define GDEFCORE_TEMPLATE_LIST 4
/** A variable that is an entity. */
#define GDEFCORE_TEMPLATE_ENTITY 5
/** A variable that is a structure. */
#define GDEFCORE_TEMPLATE_STRUCTURE 6

/** A function with any number of arguments. */
#define GDEFCORE_TEMPLATE_ARITY_ANY (-1)

/** The template did not parse. */
#define GDEFCORE_ISSUE_PARSE 1
/** A `use` names something outside the contract. */
#define GDEFCORE_ISSUE_USE 2
/** An identifier is read that the template never declares. */
#define GDEFCORE_ISSUE_NAME 3
/** A call names a function outside the contract, or calls it wrongly. */
#define GDEFCORE_ISSUE_CALL 4
/** `.raw` without the marker. */
#define GDEFCORE_ISSUE_UNSAFE 5
/** The template has no kind, or names one that does not exist. */
#define GDEFCORE_ISSUE_KIND 6
/** The kind's effective contract cannot be built (a clash). */
#define GDEFCORE_ISSUE_CONTRACT 7
/** A stored template that would stop validating (a module disable). */
#define GDEFCORE_ISSUE_BREAKS 8
/** Syntax the validator cannot see through, so it refuses it. */
#define GDEFCORE_ISSUE_SYNTAX 9

/** An effective contract. Opaque. */
typedef struct GDEFCORE_Contract GDEFCORE_Contract;

/** What validation found. Opaque. */
typedef struct GDEFCORE_Template_Report GDEFCORE_Template_Report;

/** One variable of a contract. Begins with @ref size. */
typedef struct GDEFCORE_Contract_Var {
  size_t size;                 ///< `sizeof(GDEFCORE_Contract_Var)`.
  const char * name;           ///< `title`, or `m.count` for a contribution.
  size_t name_len;             ///< Length of @ref name.
  int type;                    ///< A `GDEFCORE_TEMPLATE_` type.
  const char * description;    ///< Never NULL; may be empty.
  size_t description_len;      ///< Length of @ref description.
  const GDEFCORE_Module_Contributed * contributed; ///< NULL for the base.
} GDEFCORE_Contract_Var;

/** One function of a contract. Begins with @ref size. */
typedef struct GDEFCORE_Contract_Fn {
  size_t size;                 ///< `sizeof(GDEFCORE_Contract_Fn)`.
  const char * name;           ///< `url`.
  size_t name_len;             ///< Length of @ref name.
  int arity;                   ///< Argument count, or ::GDEFCORE_TEMPLATE_ARITY_ANY.
} GDEFCORE_Contract_Fn;

/**
 * @brief One finding. Begins with @ref size. Borrowed from the report.
 */
typedef struct GDEFCORE_Template_Issue {
  size_t size;                  ///< `sizeof(GDEFCORE_Template_Issue)`.
  int reason;                   ///< A `GDEFCORE_ISSUE_` code.
  const char * template_name;   ///< The template's name, or empty.
  size_t template_name_len;     ///< Length of @ref template_name.
  int line;                     ///< 1-based line, or 0 when it has none.
  int column;                   ///< 1-based column, or 0.
  const char * name;            ///< The offending name, or empty.
  size_t name_len;              ///< Length of @ref name.
  const char * message;         ///< The sentence, without the line.
  size_t message_len;           ///< Length of @ref message.
} GDEFCORE_Template_Issue;

/**
 * @brief Build the effective contract of @p kind.
 *
 * The base is read from the `core.template-kind` named @p kind; the
 * contributions are those of the modules enabled for the catalog's tenant, in
 * AD-10 order. When @p projection is not NULL, the kind is read as that
 * changeset would leave it and its module operations are applied first.
 *
 * @param out_message On failure, when not NULL, receives a sentence (the
 *   clash, naming both parties) to free with gdefcore_text_free().
 * @return ::GDEFCORE_OK; ::GDEFCORE_ERR_INVALID when the kind does not exist
 *   or the contract has a clash; ::GDEFCORE_ERR_FORMAT when the stored kind is
 *   malformed.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_template_contract_open(
    GDEFCORE_Catalog * catalog, const GDEFCORE_Changeset * projection,
    const char * kind, size_t kind_len, GDEFCORE_Contract ** out_contract,
    char ** out_message);

/** @brief Free a contract. NULL is ignored. */
GDEFCORE_API void gdefcore_template_contract_close(GDEFCORE_Contract * contract);

/** @brief The kind's contract version. */
GDEFCORE_API int gdefcore_template_contract_version(
    const GDEFCORE_Contract * contract);

/** @brief How many variables, base first, then contributions in order. */
GDEFCORE_API size_t gdefcore_template_contract_var_count(
    const GDEFCORE_Contract * contract);

/** @brief Variable @p index. ::GDEFCORE_ERR_INVALID past the end. */
GDEFCORE_API GDEFCORE_Result gdefcore_template_contract_var_at(
    const GDEFCORE_Contract * contract, size_t index,
    GDEFCORE_Contract_Var * out);

/** @brief The variable called @p name, or ::GDEFCORE_ERR_INVALID. */
GDEFCORE_API GDEFCORE_Result gdefcore_template_contract_var(
    const GDEFCORE_Contract * contract, const char * name, size_t name_len,
    GDEFCORE_Contract_Var * out);

/** @brief How many functions. */
GDEFCORE_API size_t gdefcore_template_contract_fn_count(
    const GDEFCORE_Contract * contract);

/** @brief Function @p index. ::GDEFCORE_ERR_INVALID past the end. */
GDEFCORE_API GDEFCORE_Result gdefcore_template_contract_fn_at(
    const GDEFCORE_Contract * contract, size_t index, GDEFCORE_Contract_Fn * out);

/**
 * @brief Validate template source against the contract of @p kind.
 *
 * This is the function an editor calls. A template that does not validate is
 * not an error of this call: @p out_report holds the findings, with their
 * lines, and is empty when the source is valid. @p projection is as for
 * gdefcore_template_contract_open(). Free the report with
 * gdefcore_template_report_free().
 *
 * @return ::GDEFCORE_OK when the validation ran; ::GDEFCORE_ERR_INVALID for a
 *   bad argument; ::GDEFCORE_ERR_OOM.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_template_validate(
    GDEFCORE_Catalog * catalog, const GDEFCORE_Changeset * projection,
    const char * kind, size_t kind_len, const char * body, size_t body_len,
    GDEFCORE_Template_Report ** out_report);

/**
 * @brief Preview the templates of @p changeset.
 *
 * Validates every `core.template` the changeset saves, against the contract
 * that holds once its module operations and its kind edits are applied. When
 * it enables or disables a module, or edits a kind, every stored template
 * whose validity would change is listed too, as ::GDEFCORE_ISSUE_BREAKS, and
 * the change is rated high. The changeset is not changed.
 *
 * @param out_risk Receives ::GDEFCORE_RISK_LOW or ::GDEFCORE_RISK_HIGH. May be
 *   NULL.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_template_preview(
    GDEFCORE_Changeset * changeset, GDEFCORE_Template_Report ** out_report,
    int * out_risk);

/**
 * @brief The check apply makes: preview, and refuse on any finding that is
 * not ::GDEFCORE_ISSUE_BREAKS.
 *
 * A refusal returns ::GDEFCORE_ERR_FORMAT and records the report text on the
 * changeset (gdefcore_changeset_refusal()), naming each template and line.
 * gdefcore_changeset_apply() calls this; a caller need not.
 */
GDEFCORE_API GDEFCORE_Result gdefcore_template_vet(GDEFCORE_Changeset * changeset);

/** @brief How many findings. A NULL report has none. */
GDEFCORE_API size_t gdefcore_template_report_count(
    const GDEFCORE_Template_Report * report);

/** @brief Finding @p index. ::GDEFCORE_ERR_INVALID past the end. */
GDEFCORE_API GDEFCORE_Result gdefcore_template_report_at(
    const GDEFCORE_Template_Report * report, size_t index,
    GDEFCORE_Template_Issue * out);

/**
 * @brief The findings as text, one per line: `template 'recent', line 3: ...`.
 *
 * Owned by the report. Empty for a report with none.
 */
GDEFCORE_API const char * gdefcore_template_report_text(
    const GDEFCORE_Template_Report * report, size_t * out_len);

/** @brief Free a report. NULL is ignored. */
GDEFCORE_API void gdefcore_template_report_free(
    GDEFCORE_Template_Report * report);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_TEMPLATE_H */
