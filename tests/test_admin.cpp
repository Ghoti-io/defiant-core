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
 * The admin area gated by permissions, not by a role (site admin story 13), as
 * far as the core goes: the permissions of the admin pages, the first
 * administrator's grants, and the matrix, which asked the role's name before.
 * Every refusal has a control beside it (the same call made by someone who
 * holds the grant), so a plant turning a test red is a test seeing the defect.
 */

#include "grants_fixture.h"

namespace {

using namespace gfx;

class AdminArea : public GrantsFixture {
 protected:
  /* Every permission an admin page asks, by label and by action. */
  struct PagePerm {
    const char * label;
    const char * action;
  };

  static const std::vector<PagePerm> & Pages() {
    static const std::vector<PagePerm> pages = {
        {GDEFCORE_ADMIN_USE_LABEL, GDEFCORE_ADMIN_USE},
        {GDEFCORE_ADMIN_UNDO_LABEL, GDEFCORE_ADMIN_UNDO},
        {GDEFCORE_POST_WRITE_LABEL, GDEFCORE_POST_WRITE},
        {GDEFCORE_ROLE_REVERT_LABEL, GDEFCORE_ROLE_REVERT},
        {GDEFCORE_ACCESS_READ_LABEL, GDEFCORE_ACCESS_READ},
        {GDEFCORE_TEMPLATE_EDIT_LABEL, GDEFCORE_TEMPLATE_EDIT},
        {GDEFCORE_MENU_EDIT_ENTRY_LABEL, GDEFCORE_MENU_EDIT},
        {GDEFCORE_MENU_EDIT_OVERRIDE_LABEL, GDEFCORE_MENU_EDIT},
        {GDEFCORE_LAYOUT_EDIT_DISPLAY_LABEL, GDEFCORE_LAYOUT_EDIT},
        {GDEFCORE_LAYOUT_EDIT_RULE_LABEL, GDEFCORE_LAYOUT_EDIT},
        {GDEFCORE_SETTINGS_EDIT_LABEL, GDEFCORE_SETTINGS_EDIT},
    };
    return pages;
  }

  std::set<std::string> RoleHeld(const char * role) {
    char ** labels = NULL;
    size_t n = 0;
    std::set<std::string> out;
    EXPECT_EQ(GDEFCORE_OK,
        gdefcore_access_role_grants(catalog_, role, strlen(role), &labels, &n));
    for (size_t i = 0; i < n; i++) {
      out.insert(labels[i]);
    }
    gdefcore_access_free(catalog_, labels, n);
    return out;
  }

  GDEFCORE_Result MatrixRc(const std::string & who, const std::string & acting = std::string()) {
    GDEFCORE_Access_Matrix_Row * rows = NULL;
    size_t n = 0;
    GDEFCORE_Result rc = gdefcore_access_matrix(catalog_, Req(who, acting), &rows, &n);
    if (rc == GDEFCORE_OK) {
      EXPECT_GT(n, 0u);
      gdefcore_access_matrix_free(catalog_, rows, n);
    } else {
      EXPECT_EQ(NULL, rows);
      EXPECT_EQ(0u, n);
    }
    return rc;
  }

  GDEFCORE_Result Revoke(const char * role, const char * label) {
    return gdefcore_access_revoke(catalog_, role, strlen(role), label, strlen(label));
  }
};

}  // namespace

TEST_F(AdminArea, ARoleNamedAdminWithNoGrantsReachesNothing) {
  std::string admin = Admin();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_declare(catalog_));
  /* The role holds nothing, and nothing a page asks is held by who holds it. */
  EXPECT_TRUE(RoleHeld("admin").empty());
  for (const PagePerm & p : Pages()) {
    EXPECT_EQ(0, Permits(admin, p.action)) << p.action;
  }
  EXPECT_EQ(GDEFCORE_ERR_INVALID, MatrixRc(admin)) << "the matrix asks the grant, not the role";
  /* CONTROL: the same call, once the role was granted. */
  Grant("admin", GDEFCORE_ACCESS_READ_LABEL);
  EXPECT_EQ(1, Permits(admin, GDEFCORE_ACCESS_READ));
  EXPECT_EQ(GDEFCORE_OK, MatrixRc(admin));
}

TEST_F(AdminArea, TheMatrixIsForWhoHoldsTheGrantWhateverTheirRole) {
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_declare(catalog_));
  Role("auditors");
  std::string auditor = Principal("auditors");
  std::string other = Principal();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, MatrixRc(auditor));
  Grant("auditors", GDEFCORE_ACCESS_READ_LABEL);
  /* The control, and the person who is not the administrator and reads it. */
  EXPECT_EQ(GDEFCORE_OK, MatrixRc(auditor));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, MatrixRc(other));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, MatrixRc(std::string()));
  /* An agent acting for the auditor needs the grant of its own. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, MatrixRc(auditor, other));
  EXPECT_EQ(GDEFCORE_OK, MatrixRc(auditor, auditor));
}

TEST_F(AdminArea, ARevokedGrantOfTheAdminRoleTakesEffect) {
  std::string admin = Admin();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_seed(catalog_));
  EXPECT_EQ(1, Permits(admin, GDEFCORE_ADMIN_USE));
  EXPECT_EQ(GDEFCORE_OK, MatrixRc(admin));
  ASSERT_EQ(GDEFCORE_OK, Revoke("admin", GDEFCORE_ADMIN_USE_LABEL));
  EXPECT_EQ(0, Permits(admin, GDEFCORE_ADMIN_USE));
  /* Only that one: the role is a holder of grants, one at a time. */
  EXPECT_EQ(1, Permits(admin, GDEFCORE_ACCESS_READ));
  EXPECT_EQ(1, Permits(admin, GDEFCORE_MENU_EDIT));
  EXPECT_EQ(GDEFCORE_OK, MatrixRc(admin));
  ASSERT_EQ(GDEFCORE_OK, Revoke("admin", GDEFCORE_ACCESS_READ_LABEL));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, MatrixRc(admin));
  /* The role itself is still the last holder's and is not deleted by this. */
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_access_delete_role(catalog_, "admin", 5));
}

TEST_F(AdminArea, TheFirstAdministratorHoldsEveryPermissionAPageAsks) {
  std::string admin = Admin();
  std::string nobody = Principal();
  /* A tenant that was not seeded: nobody holds anything, the control. */
  for (const PagePerm & p : Pages()) {
    EXPECT_EQ(0, Permits(admin, p.action)) << p.action << " before the seed";
  }
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_seed(catalog_));
  std::set<std::string> held = RoleHeld("admin");
  for (const PagePerm & p : Pages()) {
    EXPECT_EQ(1, Permits(admin, p.action)) << p.action;
    EXPECT_EQ(1u, held.count(p.label)) << p.label;
    /* The grant is the administrator's. Another principal has none of it. */
    EXPECT_EQ(0, Permits(nobody, p.action)) << p.action;
  }
  /* They are role grants, so the matrix shows them. */
  std::vector<Row> rows = Matrix();
  for (const PagePerm & p : Pages()) {
    EXPECT_NE(nullptr, Find(rows, "role admin", p.label)) << p.label << "\n" << Dump(rows);
  }
}

TEST_F(AdminArea, SeedingAgainDoesNotGiveBackWhatWasRevoked) {
  std::string admin = Admin();
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_seed(catalog_));
  ASSERT_EQ(GDEFCORE_OK, Revoke("admin", GDEFCORE_SETTINGS_EDIT_LABEL));
  ASSERT_EQ(GDEFCORE_OK, Revoke("admin", GDEFCORE_POST_WRITE_LABEL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_seed(catalog_));
  EXPECT_EQ(0, Permits(admin, GDEFCORE_SETTINGS_EDIT));
  EXPECT_EQ(0, Permits(admin, GDEFCORE_POST_WRITE));
  /* CONTROL: what was not revoked is held, so the second call did run and
   * changed nothing. */
  EXPECT_EQ(1, Permits(admin, GDEFCORE_ADMIN_USE));
  EXPECT_EQ(1, Permits(admin, GDEFCORE_TEMPLATE_EDIT));
}

TEST_F(AdminArea, DeclaringGrantsNobodyAndNullIsRefused) {
  std::string admin = Admin();
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_admin_declare(NULL));
  EXPECT_EQ(GDEFCORE_ERR_INVALID, gdefcore_admin_seed(NULL));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_declare(catalog_));
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_declare(catalog_));
  for (const char * action : {GDEFCORE_ADMIN_USE, GDEFCORE_ADMIN_UNDO, GDEFCORE_POST_WRITE,
           GDEFCORE_ROLE_REVERT, GDEFCORE_ACCESS_READ}) {
    EXPECT_EQ(0, Permits(admin, action)) << action;
  }
  /* A permission declared is one a role can be granted: the control. */
  Grant("admin", GDEFCORE_ADMIN_USE_LABEL);
  EXPECT_EQ(1, Permits(admin, GDEFCORE_ADMIN_USE));
}

TEST_F(AdminArea, AGrantOpensTheOnePageItGovernsAndNoOther) {
  ASSERT_EQ(GDEFCORE_OK, gdefcore_admin_seed(catalog_));
  std::vector<std::string> roles;
  for (const PagePerm & p : Pages()) {
    std::string role = std::string("only-") + std::to_string(roles.size());
    Role(role.c_str());
    Grant(role.c_str(), p.label);
    roles.push_back(role);
    std::string who = Principal(role.c_str());
    /* CONTROL: what the grant is for is held. */
    EXPECT_EQ(1, Permits(who, p.action)) << p.label;
    for (const PagePerm & other : Pages()) {
      if (std::string(other.action) == p.action) {
        continue;
      }
      EXPECT_EQ(0, Permits(who, other.action))
          << "'" << p.label << "' opens '" << other.label << "'";
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
