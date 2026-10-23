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
#ifndef GHOTI_IO_GDEFCORE_SRC_CORE_SIZE_H
#define GHOTI_IO_GDEFCORE_SRC_CORE_SIZE_H

#include <ghoti.io/defiant-core/macros.h>

#include <stddef.h>
#include <stdio.h>

/*
 * A struct with a leading `size` member is accepted at exactly the size this
 * build gives it, and refused at any other. There is no prefix to read: a
 * shorter struct is a caller built against another definition, and a longer
 * one claims bytes this build does not have.
 *
 * gdefcore_size_say() writes the sentence that names the struct and both
 * sizes, for the calls that have somewhere to put one.
 */
static inline void gdefcore_size_say(char * buf, size_t cap, const char * name,
    size_t got, size_t want) {
  if (buf != NULL && cap > 0) {
    snprintf(buf, cap, "%s has size %zu, but this build's is %zu.", name, got,
        want);
  }
}

#endif
