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
 * Result strings. One string per code, including the closer.
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/core.h>

const char * gdefcore_result_string(GDEFCORE_Result result) {
  switch (result) {
    case GDEFCORE_OK:
      return "No error";
    case GDEFCORE_ERR_IO:
      return "I/O error";
    case GDEFCORE_ERR_FORMAT:
      return "Invalid format";
    case GDEFCORE_ERR_UNSUPPORTED:
      return "Unsupported";
    case GDEFCORE_ERR_LIMIT:
      return "Limit exceeded";
    case GDEFCORE_ERR_CORRUPT:
      return "Corrupt data";
    case GDEFCORE_ERR_OOM:
      return "Out of memory";
    case GDEFCORE_ERR_INVALID:
      return "Invalid argument";
    case GDEFCORE_ERR_INTERNAL:
      return "Internal error";
    case GDEFCORE_ERR_BUSY:
      return "Offload queue full";
    case GDEFCORE_ERR_STALE:
      return "Key set older than its data set";
    case GDEFCORE_RESULT_COUNT:
    default:
      return "Unknown error";
  }
}
