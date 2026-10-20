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
 * @file entity_internal.h
 *
 * Private to src/entity. Another subsystem includes entity.h, not this.
 *
 * entity.c holds changesets: staging, the diff, the rating, the patch form,
 * apply. store.c holds what core keeps on the storage port (model.h): the
 * type records, the typed values, the field trees of each language, drafts,
 * revisions and the reads.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_ENTITY_ENTITY_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_ENTITY_ENTITY_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>
#include <ghoti.io/defiant-storage/model.h>

enum {
  GDEFCORE_OP_SAVE = 1,
  GDEFCORE_OP_CLEAR = 2,
  GDEFCORE_OP_DEFINE = 3,
  GDEFCORE_OP_ENABLE = 4,
  GDEFCORE_OP_DISABLE = 5,
  GDEFCORE_OP_DRAFT = 6,
  GDEFCORE_OP_PUBLISH = 7,
  GDEFCORE_OP_UNPUBLISH = 8,
  GDEFCORE_OP_REVERT = 10
};

typedef struct GDEFCORE_Text {
  char * p;
  size_t n;
} GDEFCORE_Text;

/* The values of one field of the root group. A multiple field's values are
 * the items of that field, in order: @ref ids, when it is not NULL, holds each
 * one's item id (0 for a new item), so a save keeps them by id and a reorder
 * moves order keys only (story S6d). With no ids (the flat API, a patch) the
 * k-th value goes in the item that holds the k-th value now. */
typedef struct GDEFCORE_Vals {
  GDEFCORE_Text name;
  GDEFCORE_Text * vals;
  size_t nvals;
  uint64_t * ids;
} GDEFCORE_Vals;

struct GDEFCORE_Tree;

/* One language: the root group's values (@ref fields), and the items of its
 * group fields, at every depth (@ref groups: a tree whose root item holds no
 * value; NULL when there are none). */
typedef struct GDEFCORE_Lang {
  GDEFCORE_Text lang;
  GDEFCORE_Vals * fields;
  size_t nfields;
  struct GDEFCORE_Tree * groups;
} GDEFCORE_Lang;

/* An entity's values in every language, each as the canonical text of its
 * field's logical type. */
typedef struct GDEFCORE_Doc {
  GDEFCORE_Lang * langs;
  size_t nlangs;
} GDEFCORE_Doc;

/* A field. @ref name is its path: a field of the root group is its name, one
 * inside a group `group.field` (story S6d). A type's decls are in pre-order,
 * each group before its fields. */
typedef struct GDEFCORE_Decl {
  GDEFCORE_Text name;
  int required;
  int many;
  int personal;
  size_t min_len;
  size_t max_len;
  int has_range;
  int64_t range_min;
  int64_t range_max;
  GDEFCORE_Text pattern;
  int type;    /* a GDEFSTOR_FieldType, never 0 */
  int scale;   /* DECIMAL */
  int indexed;
  GDEFCORE_Text subject; /* PERSONAL: the sibling reference naming the subject */
} GDEFCORE_Decl;

/* A field's place: one of the root group that holds values (what the flat
 * calls see), or a group or a field inside one. */
int gdefcore_ent_decl_flat(const GDEFCORE_Decl * d);
/* The decl at @p path, or NULL. */
const GDEFCORE_Decl * gdefcore_ent_decl_at(const GDEFCORE_Decl * decls,
    size_t n, const char * path, size_t path_len);

/* A field tree in texts (story S6d): the public GDEFCORE_Tree. Values are
 * canonical texts held as text values of a port tree; each item knows the
 * path of the field it sits under. */
struct GDEFCORE_Tree {
  const GDEFCORE_Allocator * alloc;
  GDEFSTOR_Tree * t;
  GDEFCORE_Text * paths;
  size_t npaths;
  size_t cap;
};

GDEFCORE_Result gdefcore_ent_tree_new(const GDEFCORE_Allocator * alloc,
    struct GDEFCORE_Tree ** out);
GDEFCORE_Result gdefcore_ent_tree_clone(const struct GDEFCORE_Tree * in,
    struct GDEFCORE_Tree ** out);
/* Same items (ids, parents, fields, order) and the same values. */
int gdefcore_ent_tree_equal(const struct GDEFCORE_Tree * a,
    const struct GDEFCORE_Tree * b);
/* Whether the items under root field @p field (and below) are the same. */
int gdefcore_ent_tree_field_equal(const struct GDEFCORE_Tree * a,
    const struct GDEFCORE_Tree * b, const char * field, size_t field_len);
/* Items directly under the root of @p t at @p field. */
size_t gdefcore_ent_tree_count_under(const struct GDEFCORE_Tree * t,
    size_t item, const char * field, size_t field_len);
/* Set a value, with the subject a personal value names (may be NULL). */
GDEFCORE_Result gdefcore_ent_tree_put(struct GDEFCORE_Tree * t, size_t item,
    const char * field, size_t field_len, const char * text, size_t len,
    const char * subject, size_t subject_len);
/* Append @p value (taken over on success) to field @p name of @p l; with
 * @p has_id, as the item @p id of a multiple field. */
GDEFCORE_Result gdefcore_ent_lang_add(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Lang * l, const char * name, size_t name_len,
    const GDEFCORE_Text * value, int has_id, uint64_t id);
/* The path of a value of item @p item: @p field under the item's path. */
GDEFCORE_Result gdefcore_ent_tree_value_path(const struct GDEFCORE_Tree * t,
    size_t item, const char * field, size_t field_len, GDEFCORE_Text * out);


typedef struct GDEFCORE_Op {
  int kind;
  GDEFCORE_Text id;
  int have_row;        /* the op names an entity (or a stored type) */
  int reserved;        /* the entity has no port entity: its draft reserves it */
  GDEFCORE_Text type_name;
  int type_kind;
  GDEFCORE_Text machine;
  GDEFCORE_Doc staged;
  GDEFCORE_Doc base;
  uint64_t base_seq;   /* the revision when staged (a type: its version) */
  uint64_t base_ver;   /* the entity's version when the op was staged */
  int have_ver;
  uint64_t target_seq; /* REVERT: the revision copied */
  uint64_t draft_base; /* DRAFT: the revision the draft is made from */
  uint64_t written;    /* after apply: the revision the op wrote, 0 for none */
  GDEFCORE_Decl * decls;
  size_t ndecls;
} GDEFCORE_Op;

/* A sealed value a changeset was handed with its subject and, from the seal,
 * its blind-index MAC (gdefcore_changeset_note_sealed()). */
typedef struct GDEFCORE_SealNote {
  GDEFCORE_Text text;
  char subject[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint8_t mac[GDEFSTOR_BLIND_MAC_BYTES];
  int has_mac;
} GDEFCORE_SealNote;

struct GDEFCORE_Catalog {
  GDEFSTOR_Store * store;
  uint8_t * tenant;
  size_t tenant_len;
  const GDEFCORE_Allocator * alloc;
  GDEFCORE_Limits limits;
  GDEFCORE_Host * host;
  struct GDEFCORE_Subjects * subjects; /* the keys that index its values */
};

struct GDEFCORE_Changeset {
  GDEFCORE_Catalog * catalog;
  uint64_t epoch;
  GDEFCORE_Text actor;
  GDEFCORE_Text why;
  GDEFCORE_Op * ops;
  size_t nops;
  GDEFCORE_Text conflict;
  GDEFCORE_Text refusal;
  GDEFCORE_Text * lines;
  size_t nlines;
  int applied;
  GDEFCORE_Request * request;
  int accept_sealed;
  GDEFCORE_SealNote * notes;
  size_t nnotes;
  struct GDEFCORE_Subjects * subjects; /* over the catalog's, when set */
  /* A scheduled publish (schedule.c): its job row's key, the runner's now,
   * which is also the write's clock, and what the apply found. */
  GDEFCORE_Text job_key;
  int64_t job_now;
  int job_outcome;
};

/* ---- store.c ------------------------------------------------------------- */

/* The record namespace of type declarations, keyed by machine name, and the
 * counter of the config epoch. */
#define GDEFCORE_ENT_TYPE_NS "core.type"
#define GDEFCORE_ENT_EPOCH "core.epoch"
/* Who wrote an entity's draft, keyed by public id: the author of the revision
 * a publish applies it as (defect 1.5.3: the publisher is not the author). */
#define GDEFCORE_ENT_DRAFT_NS "core.draft"

/* What a stored type says (a record, beside its port declaration). */
typedef struct GDEFCORE_EntType {
  int kind;
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t version;
  GDEFCORE_Decl * decls;
  size_t ndecls;
} GDEFCORE_EntType;

/* An entity as the port has it: a port entity, or an id its draft reserves. */
typedef struct GDEFCORE_EntLook {
  int exists;       /* a port entity */
  int reserved;     /* no port entity; a draft holds the id */
  char type[160];
  size_t type_len;
  char creator[130];
  size_t creator_len;
  uint64_t revision;
  int published;
  int deleted;
  int has_draft;
  uint64_t draft_base;
} GDEFCORE_EntLook;

const GDEFCORE_Allocator * gdefcore_ent_alloc(const GDEFCORE_Allocator * a);
GDEFCORE_Result gdefcore_ent_map(GDEFSTOR_Result rc);
void gdefcore_ent_text_clear(const GDEFCORE_Allocator * alloc, GDEFCORE_Text * t);
GDEFCORE_Result gdefcore_ent_text_set(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Text * t, const char * p, size_t n);
char * gdefcore_ent_dup(const GDEFCORE_Allocator * alloc, const char * p,
    size_t n);
int gdefcore_ent_span_eq(const char * a, size_t an, const char * b, size_t bn);

void gdefcore_ent_doc_free(const GDEFCORE_Allocator * alloc, GDEFCORE_Doc * doc);
GDEFCORE_Result gdefcore_ent_doc_clone(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Doc * in, GDEFCORE_Doc * out);
void gdefcore_ent_decls_free(const GDEFCORE_Allocator * alloc,
    GDEFCORE_Decl * decls, size_t n);
GDEFCORE_Result gdefcore_ent_decls_copy(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Decl * in, size_t n, GDEFCORE_Decl ** out);
void gdefcore_ent_type_free(const GDEFCORE_Allocator * alloc,
    GDEFCORE_EntType * t);

/* A type's record: ::GDEFCORE_ERR_INVALID when there is none. */
GDEFCORE_Result gdefcore_ent_type_load(GDEFCORE_Catalog * cat,
    const char * name, size_t name_len, GDEFCORE_EntType * out);
/* Write a type's record and declare it on the port, in @p write. */
GDEFCORE_Result gdefcore_ent_type_write(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * name, size_t name_len,
    const GDEFCORE_EntType * t);

/* Parse @p text as a value of @p decl's type, in place: the canonical text
 * replaces it. ::GDEFCORE_ERR_INVALID when it is not one. */
GDEFCORE_Result gdefcore_ent_value_check(const GDEFCORE_Allocator * alloc,
    const GDEFCORE_Decl * decl, const char * text, size_t len,
    GDEFCORE_Text * out_canonical);

/* An entity, a reservation or nothing (::GDEFCORE_ERR_INVALID). @p canon is
 * the canonical id. */
GDEFCORE_Result gdefcore_ent_lookup(GDEFCORE_Catalog * cat, const char * canon,
    GDEFCORE_EntLook * out);

/* The values of an entity: the current trees (@p revision 0) or as of a
 * revision, or (@p draft) its draft over the current trees. */
GDEFCORE_Result gdefcore_ent_read_doc(GDEFCORE_Catalog * cat,
    const char * canon, uint64_t revision, int draft, GDEFCORE_Doc * out);

/*
 * Where the trees of a save or a draft find each personal value's subject,
 * and how a save gives a changed one its blind-index MAC (story S6c). A
 * personal value is a sealed text in a doc; on the port it is that text and
 * its subject. The subject of a value is the one the current tree gives the
 * same text, else the one a note gives it, else the one the entity's stored
 * draft gives it; a value none of them names is refused (@ref unknown). A
 * save (@ref index) gives every personal value that is not the current
 * value of its place a MAC: the note's, else one computed from the value
 * with @ref subjects. Neither is given for a subject that is erased, and the
 * save is refused (@ref erased): an erased subject's key is gone, and with
 * it every new value of theirs (AD-19). A draft gets no MAC (AD-14).
 */
typedef struct GDEFCORE_Seals {
  const GDEFCORE_SealNote * notes;
  size_t nnotes;
  struct GDEFCORE_Subjects * subjects;
  int index;
  int with_draft; /* the entity's stored draft names subjects too */
  int erased;     /* out */
  int unknown;    /* out */
} GDEFCORE_Seals;

/* The trees of a doc for a save, items keyed to the current trees so an
 * unchanged value stays unchanged. */
GDEFCORE_Result gdefcore_ent_save_doc(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * canon, const char * type,
    size_t type_len, uint64_t base, const GDEFSTOR_RevisionMeta * meta,
    const GDEFCORE_Doc * doc, GDEFCORE_Seals * seals, uint64_t * out_revision,
    int * out_conflict);
/* The doc as the draft of the entity, made from revision @p base. */
GDEFCORE_Result gdefcore_ent_put_draft(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * canon, const char * type,
    size_t type_len, uint64_t base, const GDEFCORE_Doc * doc,
    GDEFCORE_Seals * seals);

/* The subject the entity's current tree, else its draft, records for sealed
 * text @p text of personal field @p field in @p lang; *out_found 0 when
 * neither holds it. */
GDEFCORE_Result gdefcore_ent_value_subject(GDEFCORE_Catalog * cat,
    const char * canon, const char * lang, size_t lang_len, const char * field,
    size_t field_len, const char * text, size_t len,
    char out[GDEFCORE_PUBLIC_ID_LEN + 1], int * out_found);

/* ---- schedule.c ---------------------------------------------------------- */

/* The record namespaces of scheduled publishes (story S6c): the queue, keyed
 * `<20-digit time>.<public id>` and holding the scheduling actor, and each
 * entity's one schedule, keyed by public id, holding `<state> <time>`. */
#define GDEFCORE_ENT_SCHED_NS "core.sched"
#define GDEFCORE_ENT_SCHED_ID_NS "core.sched.id"

/* Inside a scheduled publish's write: whether its job row is still there and
 * due. *out_claimed 0 leaves the outcome in the changeset. */
GDEFCORE_Result gdefcore_ent_job_claim(GDEFCORE_Changeset * cs,
    int * out_claimed);
/* In the same write as the publish: the job row goes and the entity's
 * schedule says it was applied. */
GDEFCORE_Result gdefcore_ent_job_done(GDEFCORE_Changeset * cs,
    GDEFSTOR_Write * write);
/* In the write of a clear: the entity's pending schedule goes with it. */
GDEFCORE_Result gdefcore_ent_job_drop(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * canon);

/* Revision @p index (oldest first) and its author, or the count. */
GDEFCORE_Result gdefcore_ent_history(GDEFCORE_Catalog * cat,
    const char * canon, size_t * out_count, size_t index, uint64_t * out_seq,
    char ** out_who, size_t * out_who_len);

/* The entity's version: the counter every write that touches it bumps. */
GDEFCORE_Result gdefcore_ent_version(GDEFCORE_Catalog * cat,
    const char * canon, uint64_t * out);
GDEFCORE_Result gdefcore_ent_bump(GDEFSTOR_Write * write, const char * canon,
    uint64_t * out);

/* The ids of a type's port entities, in creation order. */
GDEFCORE_Result gdefcore_ent_ids(GDEFCORE_Catalog * cat, const char * type,
    size_t type_len, char *** out_ids, size_t * out_count);

#endif /* GHOTI_IO_GDEFCORE_SRC_ENTITY_ENTITY_INTERNAL_H */
