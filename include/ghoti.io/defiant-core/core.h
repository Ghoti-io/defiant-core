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
 * @file core.h
 * @brief Result codes for the Defiant kernel.
 * @stability free
 */

#ifndef GHOTI_IO_GDEFCORE_CORE_H
#define GHOTI_IO_GDEFCORE_CORE_H

#include <ghoti.io/defiant-core/macros.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result of a kernel call.
 *
 * `GDEFCORE_ERR_BUSY` is the one code past the suite's common list: the
 * offload pool's queue is full, and the call returns without blocking the
 * thread.
 */
typedef enum GDEFCORE_Result {
  GDEFCORE_OK = 0,          ///< Succeeded.
  GDEFCORE_ERR_IO,          ///< A stream reported an error.
  GDEFCORE_ERR_FORMAT,      ///< Well formed input that is not this format.
  GDEFCORE_ERR_UNSUPPORTED, ///< This build cannot do the operation.
  GDEFCORE_ERR_LIMIT,       ///< A deadline or other bound was exceeded.
  GDEFCORE_ERR_CORRUPT,     ///< The bytes are the right format and wrong.
  GDEFCORE_ERR_OOM,         ///< The allocator returned NULL.
  GDEFCORE_ERR_INVALID,     ///< A caller argument is wrong.
  GDEFCORE_ERR_INTERNAL,    ///< A library invariant failed.
  GDEFCORE_ERR_BUSY,        ///< The offload queue is full. The thread is not blocked.
  GDEFCORE_RESULT_COUNT     ///< Not a result. Closes the string table.
} GDEFCORE_Result;

/**
 * @brief A static description of a result. Never NULL.
 *
 * @param result The code, including out-of-range values.
 * @return A string the caller does not free.
 */
GDEFCORE_API const char * gdefcore_result_string(GDEFCORE_Result result);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GDEFCORE_CORE_H */
