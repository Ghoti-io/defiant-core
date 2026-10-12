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
 * The three POSIX calls the tests lean on that a Windows C runtime lacks.
 */

#ifndef GDEFCORE_TESTS_PORTABLE_H
#define GDEFCORE_TESTS_PORTABLE_H

#ifdef _WIN32

#include <stdlib.h>
#include <string.h>

#include <filesystem>
#include <random>
#include <string>
#include <system_error>

inline int setenv(const char * name, const char * value, int overwrite) {
  (void)overwrite;
  return _putenv_s(name, value);
}

/* NAME= with nothing after it removes the variable. */
inline int unsetenv(const char * name) {
  return _putenv_s(name, "");
}

/* Fill the trailing six X's with digits and make the directory. */
inline char * mkdtemp(char * tmpl) {
  std::random_device entropy;
  size_t n = strlen(tmpl);
  if (n < 6 || strcmp(tmpl + n - 6, "XXXXXX") != 0) {
    return NULL;
  }
  for (int attempt = 0; attempt < 100; attempt++) {
    std::string digits = std::to_string(100000 + entropy() % 900000);
    std::error_code ec;
    memcpy(tmpl + n - 6, digits.data(), 6);
    if (std::filesystem::create_directory(tmpl, ec) && !ec) {
      return tmpl;
    }
    memcpy(tmpl + n - 6, "XXXXXX", 6);
  }
  return NULL;
}

#endif /* _WIN32 */

#endif /* GDEFCORE_TESTS_PORTABLE_H */
