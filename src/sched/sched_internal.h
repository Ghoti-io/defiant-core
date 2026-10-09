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
 * @file sched_internal.h
 *
 * Private to src/sched. Another subsystem includes sched.h, not this.
 */

#ifndef GHOTI_IO_GDEFCORE_SRC_SCHED_SCHED_INTERNAL_H
#define GHOTI_IO_GDEFCORE_SRC_SCHED_SCHED_INTERNAL_H

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/sched.h>

/** Why the fiber last returned to the scheduler. */
typedef enum GDEFCORE_Sched_Phase {
  GDEFCORE_SCHED_PHASE_NEW = 0,
  GDEFCORE_SCHED_PHASE_TURN,
  GDEFCORE_SCHED_PHASE_OFFLOAD,
  GDEFCORE_SCHED_PHASE_DEAD
} GDEFCORE_Sched_Phase;

#endif /* GHOTI_IO_GDEFCORE_SRC_SCHED_SCHED_INTERNAL_H */
