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
 * Every public struct of defiant-core that begins with a `size` member, once,
 * with the test file that runs it through the call that takes it (AD-34: such
 * a struct is accepted at exactly its own size).
 *
 * The list is checked against the headers by tools/check-size-structs.sh,
 * which fails, naming the struct, when a header declares one that is missing
 * here, when this list names one no header declares, and when a listed home
 * does not run its structs. Each home file calls size_structs::Run() with a
 * probe for every struct listed for it: a probe says whether the call that
 * takes the struct accepted it at the size it is given (for a struct the core
 * fills, whether the core filled that size). The call runs every struct at its
 * own size, which must be accepted, and at sizes shorter and longer, which
 * must not.
 */

#ifndef GHOTI_DEFCORE_TEST_SIZE_STRUCTS_H
#define GHOTI_DEFCORE_TEST_SIZE_STRUCTS_H

#include <ghoti.io/defiant-core/defiant-core.h>

#include <gtest/gtest.h>

#include <stddef.h>

#include <functional>
#include <map>
#include <string>
#include <vector>

#define GDEFCORE_SIZE_STRUCTS(X) \
  X(GDEFCORE_Permission, "tests/test_condition.cpp") \
  X(GDEFCORE_Access_Permission, "tests/test_grants.cpp") \
  X(GDEFCORE_Access_Matrix_Row, "tests/test_grants.cpp") \
  X(GDEFCORE_Access_List, "tests/test_grants.cpp") \
  X(GDEFCORE_Access_Held, "tests/test_restore.cpp") \
  X(GDEFCORE_Access_Decision, "tests/test_suspend.cpp") \
  X(GDEFCORE_Condition_Error, "tests/test_condition.cpp") \
  X(GDEFCORE_Condition_Subject, "tests/test_condition.cpp") \
  X(GDEFCORE_Condition_Value, "tests/test_condition.cpp") \
  X(GDEFCORE_Field, "tests/test_entity.cpp") \
  X(GDEFCORE_Value, "tests/test_entity.cpp") \
  X(GDEFCORE_Patch, "tests/test_entity.cpp") \
  X(GDEFCORE_FieldInfo, "tests/test_groups.cpp") \
  X(GDEFCORE_TreeItem, "tests/test_groups.cpp") \
  X(GDEFCORE_Route_Call, "tests/test_routes.cpp") \
  X(GDEFCORE_Route_Spec, "tests/test_routes.cpp") \
  X(GDEFCORE_Route_Info, "tests/test_routes.cpp") \
  X(GDEFCORE_Route_Link, "tests/test_routes.cpp") \
  X(GDEFCORE_Hook_Out, "tests/test_module.cpp") \
  X(GDEFCORE_Write_Hook, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Rel, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Sub, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Service, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Perm, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Grant, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Relation_Column, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Relation, "tests/test_module.cpp") \
  X(GDEFCORE_Callback_Question, "tests/test_callbacks.cpp") \
  X(GDEFCORE_Callback_Answer, "tests/test_callbacks.cpp") \
  X(GDEFCORE_Module_Access_Callback, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Callback, "tests/test_module.cpp") \
  X(GDEFCORE_Contribution_Value, "tests/test_templates.cpp") \
  X(GDEFCORE_Module_Route_Handler, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Variable_Provider, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Route, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Link, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Setting, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Variable, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Step, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Upcaster, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Manifest, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Contribution, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Contributed, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Declared_Route, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Declared_Link, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Declared_Setting, "tests/test_module.cpp") \
  X(GDEFCORE_Module_Declared_Grant, "tests/test_grants.cpp") \
  X(GDEFCORE_Module_Declared_Callback, "tests/test_callbacks.cpp") \
  X(GDEFCORE_Module_Declared_Relation, "tests/test_relations.cpp") \
  X(GDEFCORE_Restore_Held, "tests/test_restore.cpp") \
  X(GDEFCORE_Contract_Var, "tests/test_templates.cpp") \
  X(GDEFCORE_Contract_Fn, "tests/test_templates.cpp") \
  X(GDEFCORE_Template_Issue, "tests/test_templates.cpp") \
  X(GDEFCORE_Menu_Item, "tests/test_menu.cpp") \
  X(GDEFCORE_Menu_Override, "tests/test_menu.cpp")

namespace size_structs {

struct Entry {
  const char * name;
  const char * home;
  size_t size;
};

inline const std::vector<Entry> & All() {
  static const std::vector<Entry> all = {
#define X(NAME, HOME) {#NAME, HOME, sizeof(NAME)},
      GDEFCORE_SIZE_STRUCTS(X)
#undef X
  };
  return all;
}

/** True when the call accepted the struct at the given size. */
using Probe = std::function<bool(size_t size)>;

/**
 * Run the probes of @p home. A struct listed for @p home with no probe fails,
 * and so does a probe for a struct not listed for it.
 */
inline void Run(const char * home, const std::map<std::string, Probe> & probes) {
  size_t ran = 0;
  for (const Entry & e : All()) {
    if (std::string(e.home) != home) {
      continue;
    }
    auto it = probes.find(e.name);
    if (it == probes.end()) {
      ADD_FAILURE() << e.name << " is listed for " << home
                    << " and has no probe";
      continue;
    }
    ran++;
    EXPECT_TRUE(it->second(e.size))
        << e.name << " was not accepted at its own size " << e.size;
    const size_t others[] = {0, sizeof(size_t), e.size / 2, e.size - 1,
        e.size + 1, e.size + sizeof(void *)};
    for (size_t other : others) {
      if (other == e.size) {
        continue;
      }
      EXPECT_FALSE(it->second(other))
          << e.name << " was accepted at size " << other << ", its own is "
          << e.size;
    }
  }
  for (const auto & p : probes) {
    bool listed = false;
    for (const Entry & e : All()) {
      listed = listed || (p.first == e.name && std::string(e.home) == home);
    }
    EXPECT_TRUE(listed) << p.first << " has a probe in " << home
                        << " and is not listed for it";
  }
  EXPECT_GT(ran, 0u) << home << " runs no struct";
}

}  // namespace size_structs

/** One probe: PROBE(GDEFCORE_Permission) { ... uses `size` ... return bool; }. */
#define GDEFCORE_SIZE_PROBE(NAME, ...) \
  {#NAME, [&](size_t size) -> bool { (void)size; __VA_ARGS__ }}

#endif
