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
 * Scheduled publish (AD-14: "scheduled publish applies a draft at a time";
 * story S6c). A schedule is two port records, written in the entity port's
 * own writes (AD-33: jobs are durable rows in the transactional store):
 *
 * - the job row, `core.sched/<20-digit time>.<public id>`, holding who
 *   scheduled it, so that the due rows list in time order;
 * - the entity's schedule, `core.sched.id/<public id>`, holding its state and
 *   time (`pending`, `done`, `conflict` or `refused`): one per entity, which a
 *   new schedule replaces.
 *
 * A job is applied as a changeset that publishes the entity, as its
 * scheduler. Inside that changeset's write the job row is read again: one
 * that is gone (applied, cancelled or moved to another time) or not yet due
 * is not applied, and the publish deletes the row in the same write, so a job
 * is applied once, at or after its time, however many runners take it. The
 * publish is an ordinary one: validated against the type as it is then, a
 * moved head is a conflict, and an erased subject's new value is refused.
 * Those outcomes end the job too, with the entity's schedule saying which.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/entity.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/defiant-storage/model.h>

#include <stdio.h>
#include <string.h>

#include "entity_internal.h"

#define span_eq gdefcore_ent_span_eq
#define map_stor gdefcore_ent_map

static const char kNs[] = GDEFCORE_ENT_SCHED_NS;
static const char kIdNs[] = GDEFCORE_ENT_SCHED_ID_NS;

/* The job row's key: the time as 20 digits, so that keys sort by time, and
 * the public id. */
enum { kKeyLen = 20 + 1 + GDEFCORE_PUBLIC_ID_LEN };

static int job_key(int64_t at_ms, const char * canon, char out[kKeyLen + 1]) {
  int n;
  if (at_ms < 0) {
    return 0;
  }
  n = snprintf(out, kKeyLen + 1, "%020lld.%.*s", (long long)at_ms,
      GDEFCORE_PUBLIC_ID_LEN, canon);
  return n == kKeyLen;
}

static int key_parse(const char * key, size_t len, int64_t * out_at,
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  int64_t at = 0;
  size_t i;
  if (len != kKeyLen || key[20] != '.') {
    return 0;
  }
  for (i = 0; i < 20; i++) {
    if (key[i] < '0' || key[i] > '9' || at > (INT64_MAX - 9) / 10) {
      return 0;
    }
    at = at * 10 + (key[i] - '0');
  }
  if (gdefcore_id_canonical(key + 21, GDEFCORE_PUBLIC_ID_LEN, canon) !=
          GDEFCORE_OK ||
      memcmp(canon, key + 21, GDEFCORE_PUBLIC_ID_LEN) != 0) {
    return 0;
  }
  *out_at = at;
  return 1;
}

static const char * state_word(int state) {
  switch (state) {
  case GDEFCORE_SCHEDULE_PENDING:
    return "pending";
  case GDEFCORE_SCHEDULE_DONE:
    return "done";
  case GDEFCORE_SCHEDULE_CONFLICT:
    return "conflict";
  default:
    return "refused";
  }
}

/* The entity's schedule, `<state> <time>`. *found 0 when it has none. */
static GDEFCORE_Result id_get(GDEFCORE_Catalog * cat, const char * canon,
    int * out_found, int * out_state, int64_t * out_at) {
  uint8_t * bytes = NULL;
  size_t len = 0;
  int found = 0;
  GDEFCORE_Result rc = map_stor(gdefstor_record_get(cat->store,
      (const char *)cat->tenant, cat->tenant_len, kIdNs, sizeof kIdNs - 1, canon,
      GDEFCORE_PUBLIC_ID_LEN, &found, &bytes, &len, NULL, NULL));
  *out_found = 0;
  if (rc == GDEFCORE_OK && found) {
    static const int states[] = {GDEFCORE_SCHEDULE_PENDING, GDEFCORE_SCHEDULE_DONE,
        GDEFCORE_SCHEDULE_CONFLICT, GDEFCORE_SCHEDULE_REFUSED};
    const char * text = (const char *)bytes;
    const char * sp = len == 0 ? NULL : memchr(text, ' ', len);
    size_t i;
    int64_t at = 0;
    rc = GDEFCORE_ERR_CORRUPT;
    for (i = 0; sp != NULL && i < sizeof states / sizeof states[0]; i++) {
      if (span_eq(text, (size_t)(sp - text), state_word(states[i]),
              strlen(state_word(states[i])))) {
        size_t k;
        size_t digits = len - (size_t)(sp - text) - 1;
        rc = digits > 0 && digits <= 19 ? GDEFCORE_OK : GDEFCORE_ERR_CORRUPT;
        for (k = 0; rc == GDEFCORE_OK && k < digits; k++) {
          char c = sp[1 + k];
          if (c < '0' || c > '9') {
            rc = GDEFCORE_ERR_CORRUPT;
          } else {
            at = at * 10 + (c - '0');
          }
        }
        if (rc == GDEFCORE_OK) {
          *out_state = states[i];
          *out_at = at;
          *out_found = 1;
        }
        break;
      }
    }
  }
  gdefstor_bytes_free(NULL, bytes);
  return rc;
}

static GDEFCORE_Result id_put(GDEFSTOR_Write * write, const char * canon,
    int state, int64_t at_ms) {
  char text[48];
  int n = snprintf(text, sizeof text, "%s %lld", state_word(state),
      (long long)at_ms);
  if (n <= 0 || (size_t)n >= sizeof text) {
    return GDEFCORE_ERR_INTERNAL;
  }
  return map_stor(gdefstor_record_put(write, kIdNs, sizeof kIdNs - 1, canon,
      GDEFCORE_PUBLIC_ID_LEN, GDEFCORE_SCHEMA_CORE_STAMP, sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1, (const uint8_t *)text, (size_t)n));
}

/* The pending job row of the entity, if any, goes (in @p write). */
static GDEFCORE_Result drop_pending(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * canon, int * out_had) {
  int found = 0;
  int state = 0;
  int64_t at = 0;
  char key[kKeyLen + 1];
  GDEFCORE_Result rc = id_get(cat, canon, &found, &state, &at);
  *out_had = 0;
  if (rc != GDEFCORE_OK || !found) {
    return rc;
  }
  *out_had = 1;
  if (state == GDEFCORE_SCHEDULE_PENDING && job_key(at, canon, key)) {
    rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1, key,
        kKeyLen, NULL));
  }
  return rc;
}

static GDEFCORE_Result canon_of(const char * id, size_t id_len,
    char canon[GDEFCORE_PUBLIC_ID_LEN + 1]) {
  return gdefcore_id_canonical(id, id_len, canon) == GDEFCORE_OK
             ? GDEFCORE_OK
             : GDEFCORE_ERR_INVALID;
}

static GDEFCORE_Result write_begin(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write ** out) {
  GDEFCORE_Result rc = map_stor(gdefstor_write_begin(cat->store,
      (const char *)cat->tenant, cat->tenant_len, NULL, out));
  if (rc == GDEFCORE_OK) {
    /* Core's records, written where core's data stands (AD-15). */
    gdefcore_ent_schema_reset(cat);
    rc = gdefcore_ent_core_check(cat, *out);
    if (rc != GDEFCORE_OK) {
      gdefstor_write_abort(*out);
      *out = NULL;
    }
  }
  return rc;
}

static GDEFCORE_Result write_end(GDEFSTOR_Write * write, GDEFCORE_Result rc) {
  if (rc == GDEFCORE_OK) {
    return map_stor(gdefstor_write_commit(write));
  }
  gdefstor_write_abort(write);
  return rc;
}

GDEFCORE_Result gdefcore_entity_schedule_publish(GDEFCORE_Catalog * catalog,
    const char * actor, size_t actor_len, const char * id, size_t id_len,
    int64_t at_ms) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char who[GDEFCORE_PUBLIC_ID_LEN + 1];
  char key[kKeyLen + 1];
  GDEFCORE_EntLook look;
  GDEFSTOR_Write * write = NULL;
  int had = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || at_ms < 0 || canon_of(id, id_len, canon) != GDEFCORE_OK ||
      !job_key(at_ms, canon, key)) {
    return GDEFCORE_ERR_INVALID;
  }
  who[0] = '\0';
  if ((actor != NULL || actor_len != 0) &&
      gdefcore_id_canonical(actor, actor_len, who) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_ent_lookup(catalog, canon, &look);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = write_begin(catalog, &write);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  /* One schedule per entity: a new one replaces the one it had. */
  rc = drop_pending(catalog, write, canon, &had);
  if (rc == GDEFCORE_OK) {
    rc = map_stor(gdefstor_record_put(write, kNs, sizeof kNs - 1, key, kKeyLen,
        GDEFCORE_SCHEMA_CORE_STAMP, sizeof GDEFCORE_SCHEMA_CORE_STAMP - 1,
        (const uint8_t *)who, strlen(who)));
  }
  if (rc == GDEFCORE_OK) {
    rc = id_put(write, canon, GDEFCORE_SCHEDULE_PENDING, at_ms);
  }
  return write_end(write, rc);
}

GDEFCORE_Result gdefcore_entity_unschedule(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  GDEFSTOR_Write * write = NULL;
  int had = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || canon_of(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = write_begin(catalog, &write);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = drop_pending(catalog, write, canon, &had);
  if (rc == GDEFCORE_OK && had) {
    rc = map_stor(gdefstor_record_delete(write, kIdNs, sizeof kIdNs - 1, canon,
        GDEFCORE_PUBLIC_ID_LEN, NULL));
  }
  return write_end(write, rc);
}

GDEFCORE_Result gdefcore_entity_schedule_state(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, int * out_state, int64_t * out_at_ms) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  int found = 0;
  int state = GDEFCORE_SCHEDULE_NONE;
  int64_t at = 0;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_state == NULL ||
      canon_of(id, id_len, canon) != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = id_get(catalog, canon, &found, &state, &at);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  *out_state = found ? state : GDEFCORE_SCHEDULE_NONE;
  if (out_at_ms != NULL) {
    *out_at_ms = found ? at : 0;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_schedule_due(GDEFCORE_Catalog * catalog,
    int64_t now_ms, GDEFCORE_ScheduleJob * out_jobs, size_t cap,
    size_t * out_count) {
  GDEFSTOR_RecordList * list = NULL;
  size_t n;
  size_t i;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_count == NULL || (out_jobs == NULL && cap != 0)) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_count = 0;
  if (cap == 0) {
    return GDEFCORE_OK;
  }
  rc = map_stor(gdefstor_record_list(catalog->store,
      (const char *)catalog->tenant, catalog->tenant_len, kNs, sizeof kNs - 1,
      "", 0, 0, cap < GDEFSTOR_RECORD_MAX_PAGE ? cap : GDEFSTOR_RECORD_MAX_PAGE,
      &list));
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  n = gdefstor_record_list_count(list);
  for (i = 0; i < n; i++) {
    const char * key = NULL;
    size_t key_len = 0;
    const uint8_t * bytes = NULL;
    size_t len = 0;
    GDEFCORE_ScheduleJob * job = &out_jobs[*out_count];
    if (gdefstor_record_list_item(list, i, &key, &key_len, &bytes, &len, NULL, NULL) !=
            GDEFSTOR_OK ||
        !key_parse(key, key_len, &job->at_ms, job->id)) {
      rc = GDEFCORE_ERR_CORRUPT;
      break;
    }
    /* In time order: the first row not due ends the list. */
    if (job->at_ms > now_ms) {
      break;
    }
    *out_count += 1;
  }
  gdefstor_record_list_free(list);
  return rc;
}

GDEFCORE_Result gdefcore_ent_job_claim(GDEFCORE_Changeset * cs,
    int * out_claimed) {
  GDEFCORE_Catalog * cat = cs->catalog;
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  int64_t at = 0;
  int found = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFCORE_Result rc;
  *out_claimed = 0;
  if (!key_parse(cs->job_key.p, cs->job_key.n, &at, canon)) {
    return GDEFCORE_ERR_INTERNAL;
  }
  /* What is committed cannot move while this write is open: a row another
   * runner applied, or that was cancelled or moved, is gone by now. */
  rc = map_stor(gdefstor_record_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, kNs, sizeof kNs - 1, cs->job_key.p, cs->job_key.n,
      &found, &bytes, &len, NULL, NULL));
  gdefstor_bytes_free(NULL, bytes);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  if (!found) {
    cs->job_outcome = GDEFCORE_SCHEDULE_GONE;
    return GDEFCORE_OK;
  }
  if (at > cs->job_now) {
    cs->job_outcome = GDEFCORE_SCHEDULE_EARLY;
    return GDEFCORE_OK;
  }
  *out_claimed = 1;
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_ent_job_done(GDEFCORE_Changeset * cs,
    GDEFSTOR_Write * write) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  int64_t at = 0;
  GDEFCORE_Result rc;
  if (!key_parse(cs->job_key.p, cs->job_key.n, &at, canon)) {
    return GDEFCORE_ERR_INTERNAL;
  }
  rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1,
      cs->job_key.p, cs->job_key.n, NULL));
  if (rc == GDEFCORE_OK) {
    rc = id_put(write, canon, GDEFCORE_SCHEDULE_DONE, at);
  }
  if (rc == GDEFCORE_OK) {
    cs->job_outcome = GDEFCORE_SCHEDULE_DONE;
  }
  return rc;
}

GDEFCORE_Result gdefcore_ent_job_drop(GDEFCORE_Catalog * cat,
    GDEFSTOR_Write * write, const char * canon) {
  int had = 0;
  GDEFCORE_Result rc = drop_pending(cat, write, canon, &had);
  if (rc == GDEFCORE_OK && had) {
    rc = map_stor(gdefstor_record_delete(write, kIdNs, sizeof kIdNs - 1, canon,
        GDEFCORE_PUBLIC_ID_LEN, NULL));
  }
  return rc;
}

/* A job that could not be applied, and never will be as it stands: its row
 * goes and the entity's schedule says why, in a write of its own, and only
 * while the row is still there. */
static GDEFCORE_Result job_end(GDEFCORE_Catalog * cat, const char * key,
    const char * canon, int64_t at, int state, int * out_outcome) {
  GDEFSTOR_Write * write = NULL;
  int found = 0;
  uint8_t * bytes = NULL;
  size_t len = 0;
  GDEFCORE_Result rc = write_begin(cat, &write);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = map_stor(gdefstor_record_get(cat->store, (const char *)cat->tenant,
      cat->tenant_len, kNs, sizeof kNs - 1, key, kKeyLen, &found, &bytes,
      &len, NULL, NULL));
  gdefstor_bytes_free(NULL, bytes);
  if (rc == GDEFCORE_OK && found) {
    rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1, key,
        kKeyLen, NULL));
    if (rc == GDEFCORE_OK) {
      rc = id_put(write, canon, state, at);
    }
  }
  *out_outcome = found ? state : GDEFCORE_SCHEDULE_GONE;
  return write_end(write, rc);
}

GDEFCORE_Result gdefcore_schedule_apply(GDEFCORE_Catalog * catalog,
    const char * id, size_t id_len, int64_t at_ms, int64_t now_ms,
    int * out_outcome) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  char key[kKeyLen + 1];
  uint8_t * who = NULL;
  size_t who_len = 0;
  int found = 0;
  int attempt;
  GDEFCORE_Result rc;
  if (catalog == NULL || out_outcome == NULL ||
      canon_of(id, id_len, canon) != GDEFCORE_OK || !job_key(at_ms, canon, key)) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_outcome = GDEFCORE_SCHEDULE_GONE;
  /* The scheduler, who publishes. A row not there now is found gone again
   * inside the publish's write, which is the read that decides. */
  rc = map_stor(gdefstor_record_get(catalog->store,
      (const char *)catalog->tenant, catalog->tenant_len, kNs, sizeof kNs - 1,
      key, kKeyLen, &found, &who, &who_len, NULL, NULL));
  if (rc != GDEFCORE_OK) {
    gdefstor_bytes_free(NULL, who);
    return rc;
  }
  if (!found) {
    gdefstor_bytes_free(NULL, who);
    who = NULL;
    who_len = 0;
  }
  for (attempt = 0; attempt < 3; attempt++) {
    GDEFCORE_Changeset * cs = NULL;
    GDEFCORE_EntLook look;
    rc = gdefcore_changeset_prepare(catalog, (const char *)who, who_len, &cs);
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_ent_text_set(catalog->alloc, &cs->job_key, key, kKeyLen);
      cs->job_now = now_ms;
      cs->job_outcome = GDEFCORE_SCHEDULE_GONE;
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_entity_publish(cs, canon, GDEFCORE_PUBLIC_ID_LEN);
      if (rc == GDEFCORE_ERR_INVALID) {
        /* Nothing to publish: an entity with no revision and no draft. */
        gdefcore_changeset_destroy(cs);
        gdefstor_bytes_free(NULL, who);
        return job_end(catalog, key, canon, at_ms, GDEFCORE_SCHEDULE_REFUSED,
            out_outcome);
      }
    }
    if (rc == GDEFCORE_OK) {
      rc = gdefcore_changeset_apply(cs, NULL, 0);
    }
    if (rc == GDEFCORE_OK) {
      *out_outcome = cs->job_outcome;
      gdefcore_changeset_destroy(cs);
      gdefstor_bytes_free(NULL, who);
      return GDEFCORE_OK;
    }
    if (cs != NULL && gdefcore_changeset_conflict(cs, NULL) == NULL &&
        rc == GDEFCORE_ERR_INVALID) {
      /* Refused at apply: the draft does not fit its type now, or it holds
       * a new value of an erased subject. The draft is kept. */
      gdefcore_changeset_destroy(cs);
      gdefstor_bytes_free(NULL, who);
      return job_end(catalog, key, canon, at_ms, GDEFCORE_SCHEDULE_REFUSED,
          out_outcome);
    }
    gdefcore_changeset_destroy(cs);
    if (rc != GDEFCORE_ERR_INVALID) {
      break; /* the store's error */
    }
    /* A conflict: a moved head ends the job (CAP-S4); another writer that
     * only moved the epoch is waited out by trying again. */
    rc = gdefcore_ent_lookup(catalog, canon, &look);
    if (rc != GDEFCORE_OK) {
      break;
    }
    if (look.has_draft && look.exists && look.draft_base != look.revision) {
      gdefstor_bytes_free(NULL, who);
      return job_end(catalog, key, canon, at_ms, GDEFCORE_SCHEDULE_CONFLICT,
          out_outcome);
    }
    rc = GDEFCORE_ERR_BUSY;
  }
  gdefstor_bytes_free(NULL, who);
  *out_outcome = GDEFCORE_SCHEDULE_PENDING;
  return rc;
}

GDEFCORE_Result gdefcore_schedule_run(GDEFCORE_Catalog * catalog,
    int64_t now_ms, size_t max, size_t * out_applied, size_t * out_ended) {
  GDEFCORE_ScheduleJob jobs[64];
  size_t applied = 0;
  size_t ended = 0;
  size_t done = 0;
  GDEFCORE_Result rc = GDEFCORE_OK;
  if (catalog == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  while (rc == GDEFCORE_OK && done < max) {
    size_t n = 0;
    size_t i;
    size_t want = max - done < 64 ? max - done : 64;
    rc = gdefcore_schedule_due(catalog, now_ms, jobs, want, &n);
    if (rc != GDEFCORE_OK || n == 0) {
      break;
    }
    for (i = 0; rc == GDEFCORE_OK && i < n; i++) {
      int outcome = 0;
      rc = gdefcore_schedule_apply(catalog, jobs[i].id, GDEFCORE_PUBLIC_ID_LEN,
          jobs[i].at_ms, now_ms, &outcome);
      if (outcome == GDEFCORE_SCHEDULE_DONE) {
        applied += 1;
      } else if (outcome == GDEFCORE_SCHEDULE_CONFLICT ||
                 outcome == GDEFCORE_SCHEDULE_REFUSED) {
        ended += 1;
      }
      done += 1;
    }
  }
  if (out_applied != NULL) {
    *out_applied = applied;
  }
  if (out_ended != NULL) {
    *out_ended = ended;
  }
  return rc;
}
