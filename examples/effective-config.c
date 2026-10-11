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
 * Print the effective bootstrap configuration, one setting per line.
 * The secret line names its source and does not contain the key.
 * This program does not bind a socket.
 */

#include <ghoti.io/defiant-core/inst.h>

#include <stdio.h>

int main(void) {
  GDEFCORE_Inst_Config * config = NULL;
  char * text = NULL;
  size_t n = 0;
  if (gdefcore_inst_config_load(NULL, &config) != GDEFCORE_OK) {
    fprintf(stderr, "effective-config: settings could not be read\n");
    return 1;
  }
  if (gdefcore_inst_config_format(config, &text, &n) != GDEFCORE_OK) {
    gdefcore_inst_config_destroy(config);
    fprintf(stderr, "effective-config: settings could not be formatted\n");
    return 1;
  }
  if (fwrite(text, 1, n, stdout) != n) {
    gdefcore_inst_config_free(config, text);
    gdefcore_inst_config_destroy(config);
    return 1;
  }
  gdefcore_inst_config_free(config, text);
  gdefcore_inst_config_destroy(config);
  return 0;
}
