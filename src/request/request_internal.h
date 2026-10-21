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
 * @file request_internal.h
 *
 * Private to src/request. Another subsystem includes request.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_REQUEST_REQUEST_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_REQUEST_REQUEST_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/request.h>

typedef struct GDEFCORE_Note {
  char * name;
  size_t name_len;
  char * value;
  size_t value_len;
} GDEFCORE_Note;

typedef struct GDEFCORE_Memo {
  char * key;
  size_t key_len;
  int value;
} GDEFCORE_Memo;

typedef struct GDEFCORE_Read {
  char id[GDEFCORE_PUBLIC_ID_LEN + 1];
  uint64_t revision;
} GDEFCORE_Read;

struct GDEFCORE_Request {
  uint8_t * tenant;
  size_t tenant_len;
  uint64_t deadline_ms;
  uint64_t yield_bound_ms;
  uint64_t id;
  GDEFCORE_Result status;
  GCU_Fiber * fiber;
  GDEFSTOR_Write * write;
  char * principal;
  size_t principal_len;
  char * acting;
  size_t acting_len;
  GDEFCORE_Note * notes;
  size_t nnotes;
  char * resolution;
  size_t resolution_len;
  int principal_dependent;
  int64_t time_seconds;
  int time_set;
  GDEFCORE_Memo * memo;
  size_t nmemo;
  size_t cap_memo;
  uint64_t memo_hits;
  uint64_t memo_restarts;
  GDEFCORE_Read * reads;
  size_t nreads;
  size_t cap_reads;
  int reads_overflowed;
  char (*subjects)[GDEFCORE_PUBLIC_ID_LEN + 1]; /* decrypted (story S7) */
  size_t nsubjects;
  size_t cap_subjects;
  int subjects_overflowed;
  int has_fuel;
  uint64_t fuel;
  const GDEFCORE_Allocator * allocator;
};

#endif /* GHOTI_IO_GDEFCORE_SRC_REQUEST_REQUEST_INTERNAL_H */
