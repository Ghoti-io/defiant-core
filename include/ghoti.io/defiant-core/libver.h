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
 * @file libver.h
 * @brief Version numbers and the symbol namespace for this build.
 * @stability free
 *
 * Every exported symbol carries a per-version token so that two versions of
 * this library can be loaded into one process. See CONVENTIONS.md section 4.
 */

#ifndef GHOTI_IO_GDEFCORE_LIBVER_H
#define GHOTI_IO_GDEFCORE_LIBVER_H

/**
 * GHOTIIO_DEFCORE_NAME and the version macros come from here. They are
 * generated at build time from the Makefile's BRANCH.
 */
#include <ghoti.io/defiant-core/libver_gen.h>

/**
 * Produce the namespaced form of an identifier.
 *
 * @param NAME The identifier to prefix with GHOTIIO_DEFCORE_NAME.
 */
#define GHOTIIO_DEFCORE(NAME) GHOTIIO_DEFCORE_RENAME(GHOTIIO_DEFCORE_NAME, _##NAME)

/** Helper. Concatenation needs two levels of expansion. */
#define GHOTIIO_DEFCORE_RENAME_INNER(a, b) a##b

/** Helper. Concatenation needs two levels of expansion. */
#define GHOTIIO_DEFCORE_RENAME(a, b) GHOTIIO_DEFCORE_RENAME_INNER(a, b)

/** This build's major version. */
#define GDEFCORE_VERSION_MAJOR GHOTIIO_DEFCORE_VERSION_MAJOR
/** This build's minor version. */
#define GDEFCORE_VERSION_MINOR GHOTIIO_DEFCORE_VERSION_MINOR
/** This build's patch version. */
#define GDEFCORE_VERSION_PATCH GHOTIIO_DEFCORE_VERSION_PATCH
/** This build's version as a string, e.g. "0.0.0". */
#define GDEFCORE_VERSION_STRING GHOTIIO_DEFCORE_VERSION

/**
 * Pack a version into one comparable integer, one byte per component.
 *
 * 1.2.3 becomes 0x010203. A plain `<` compares two versions.
 */
#define GDEFCORE_MAKE_VERSION(major, minor, patch)                              \
  ((((unsigned)(major)) << 16) | (((unsigned)(minor)) << 8) |                  \
      ((unsigned)(patch)))

/** This build's version, packed. */
#define GDEFCORE_VERSION_NUMBER                                                 \
  GDEFCORE_MAKE_VERSION(GDEFCORE_VERSION_MAJOR, GDEFCORE_VERSION_MINOR,        \
      GDEFCORE_VERSION_PATCH)

#endif /* GHOTI_IO_GDEFCORE_LIBVER_H */
