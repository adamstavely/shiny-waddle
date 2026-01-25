# Phase 2 Progress Report - Design Token Migration

## Overview
Migrating hardcoded colors, spacing, fonts, and other styling values to design tokens for consistency and maintainability.

## Goals
1. Migrate hardcoded colors to design tokens
2. Migrate hardcoded spacing/sizing to design tokens
3. Migrate hardcoded fonts to design tokens
4. Migrate hardcoded shadows/effects to design tokens
5. Ensure visual consistency across the application

---

## Completed ✅

### Design Tokens Available
- [x] Color tokens defined in `design-tokens.css` ✅
- [x] Spacing tokens defined in `responsive.css` ✅
- [x] Font tokens defined in `design-tokens.css` ✅
- [x] Shadow tokens defined in `design-tokens.css` ✅

---

## In Progress 🚧

### Current Task
Starting migration with high-priority files that have the most hardcoded values.

---

## Statistics
- **Hardcoded colors found**: ~6,861 (estimated from plan)
- **Hardcoded spacing found**: ~9,076 (estimated from plan)
- **Files migrated**: 40
- **Colors migrated**: ~405
- **Spacing migrated**: ~590

## Files to Migrate (Priority Order)
1. `src/views/Admin.vue` (185 color instances, 375 spacing instances)
2. `src/views/PolicyDetail.vue` (154 color instances, 321 spacing instances)
3. `src/views/ApplicationDetail.vue` (107 color instances, 227 spacing instances)
4. `src/views/TestCreate.vue` (54 color instances, 220 spacing instances)
5. `src/views/Applications.vue` (52 color instances)
6. All policy views in `src/views/policies/`

## Files Modified
- `test-harness/dashboard-frontend/src/views/Applications.vue` ✅
  - Migrated 5 hardcoded rgba colors to design tokens
  - Migrated 4 hardcoded spacing values to design tokens
- `test-harness/dashboard-frontend/src/views/Dashboard.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
  - Migrated 1 hardcoded spacing value to design tokens
- `test-harness/dashboard-frontend/src/views/insights/InsightsOverview.vue` ✅
  - Migrated ~19 hardcoded colors to design tokens
  - Migrated ~15 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/PoliciesOverview.vue` ✅
  - Migrated 8 hardcoded rgba colors to design tokens
  - Migrated ~8 hardcoded spacing values to design tokens
- `test-harness/dashboard-frontend/src/views/Compliance.vue` ✅
  - Migrated 7 hardcoded colors to design tokens
  - Migrated 1 hardcoded spacing value to design tokens
- `test-harness/dashboard-frontend/src/views/Reports.vue` ✅
  - Migrated 8 hardcoded rgba colors to design tokens
  - Migrated ~8 hardcoded spacing values to design tokens
- `test-harness/dashboard-frontend/src/views/TestsOverview.vue` ✅
  - Migrated ~7 hardcoded rgba colors to design tokens
  - Migrated ~5 hardcoded spacing values to design tokens
- `test-harness/dashboard-frontend/src/views/Home.vue` ✅
  - Migrated 2 hardcoded rgba colors to design tokens
  - Migrated 2 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/TeamDashboard.vue` ✅
  - Migrated 3 hardcoded colors to design tokens
  - Migrated 4 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/DeveloperFindingsDashboard.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/views/UnifiedFindings.vue` ✅
  - Migrated ~13 hardcoded colors to design tokens
  - Migrated ~11 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/Violations.vue` ✅
  - Migrated ~12 hardcoded colors to design tokens
  - Migrated ~6 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/Findings.vue` ✅
  - Migrated ~8 hardcoded colors to design tokens
- `test-harness/dashboard-frontend/src/views/Settings.vue` ✅
  - Migrated 2 hardcoded color values to design tokens
- `test-harness/dashboard-frontend/src/components/StatusBadge.vue` ✅
  - Migrated 8 hardcoded colors (rgba + hex) to design tokens
- `test-harness/dashboard-frontend/src/components/BaseModal.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/components/BaseForm.vue` ✅
  - Migrated 2 hardcoded rgba colors to design tokens
- `test-harness/dashboard-frontend/src/components/BaseTable.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/components/TabNavigation.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/components/BaseButton.vue` ✅
  - Migrated 3 hardcoded rgba colors to design tokens
- `test-harness/dashboard-frontend/src/components/TopNav.vue` ✅
  - Migrated ~20 hardcoded rgba colors to design tokens
- `test-harness/dashboard-frontend/src/components/ValidatorCard.vue` ✅
  - Migrated 4 hardcoded rgba colors to design tokens
  - Migrated 3 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/PlatformConfigPolicies.vue` ✅
  - Migrated ~9 hardcoded rgba colors to design tokens
  - Migrated ~8 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/DataContractsPolicies.vue` ✅
  - Migrated 2 hardcoded rgba colors to design tokens
  - Migrated 3 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/detail/PolicyTestsSection.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/views/policies/ExceptionsPolicies.vue` ✅
  - Migrated ~12 hardcoded rgba colors to design tokens
  - Migrated ~10 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/StandardsMappingPolicies.vue` ✅
  - Migrated ~8 hardcoded rgba colors to design tokens
  - Migrated ~10 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/components/ComplianceScoreCard.vue` ✅
  - Migrated 4 hardcoded rgba colors to design tokens
- `test-harness/dashboard-frontend/src/components/ScoreCard.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/components/AccessibleModal.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/components/Dropdown.vue` ✅
  - Migrated ~6 hardcoded rgba colors to design tokens
  - Migrated ~5 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/components/DomainTrendChart.vue` ✅
  - Migrated ~8 hardcoded colors to design tokens
  - Migrated ~5 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/components/ValidatorToggle.vue` ✅
  - Migrated ~15 hardcoded colors to design tokens
  - Migrated ~12 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/Violations.vue` ✅
  - Migrated 3 hardcoded rgba colors to design tokens
  - Migrated 2 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/UnifiedFindings.vue` ✅
  - Migrated ~6 hardcoded colors to design tokens
  - Migrated ~4 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/TestsOverview.vue` ✅
  - Migrated ~3 hardcoded rgba colors in gradients to design tokens
  - Migrated ~6 hardcoded spacing values to design tokens
  - Note: SVG fill colors in inline SVG elements remain (would require SVG refactoring)
- `test-harness/dashboard-frontend/src/views/policies/DataClassificationPolicies.vue` ✅
  - Migrated ~10 hardcoded rgba colors to design tokens
  - Migrated ~12 hardcoded spacing/font values to design tokens
  - Note: JavaScript color values (for dynamic level colors) remain as data values
- `test-harness/dashboard-frontend/src/views/policies/AccessControlPolicies.vue` ✅
  - Migrated ~10 hardcoded rgba colors to design tokens
  - Migrated ~10 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/ApplicationDetail.vue` ✅
  - Migrated ~16 hardcoded colors to design tokens
  - Migrated ~8 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/PolicyDetail.vue` ✅
  - Migrated 1 hardcoded rgba color to design tokens
- `test-harness/dashboard-frontend/src/views/TestSuiteDetail.vue` ✅
  - Migrated 2 hardcoded rgba colors to design tokens
- `test-harness/dashboard-frontend/src/views/TestBatteryCreate.vue` ✅
  - Migrated ~9 hardcoded colors to design tokens
- `test-harness/dashboard-frontend/src/views/TestHarnessCreate.vue` ✅
  - Migrated ~20 hardcoded colors to design tokens
  - Migrated ~5 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/AccessControlPolicies.vue` ✅ (additional)
  - Migrated additional spacing values (gap, margin-bottom, padding)
- `test-harness/dashboard-frontend/src/components/ValidatorToggle.vue` ✅ (additional)
  - Migrated additional colors and spacing values (margin-bottom, padding, gap, border-radius, font-weight, transitions)
- `test-harness/dashboard-frontend/src/components/DomainTrendChart.vue` ✅ (additional)
  - Migrated additional colors and spacing values (background, border, padding)
- `test-harness/dashboard-frontend/src/components/Dropdown.vue` ✅ (additional)
  - Migrated additional hover color
- `test-harness/dashboard-frontend/src/components/TopNav.vue` ✅ (additional)
  - Migrated additional box-shadow color
- `test-harness/dashboard-frontend/src/components/ImportFindingsModal.vue` ✅
  - Migrated ~15 hardcoded colors to design tokens
  - Migrated ~15 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/TestsOverview.vue` ✅ (additional)
  - Migrated additional background colors (rgba values)
  - Migrated font-size values (14px, 12px)
- `test-harness/dashboard-frontend/src/views/Compliance.vue` ✅ (additional)
  - Migrated additional colors (box-shadow, background, priority-critical)
- `test-harness/dashboard-frontend/src/components/TopNav.vue` ✅ (additional)
  - Migrated additional spacing and font-size values (gap, padding, font-size)
- `test-harness/dashboard-frontend/src/components/Dropdown.vue` ✅ (additional)
  - Migrated additional spacing and font-size values (padding, font-size)
- `test-harness/dashboard-frontend/src/components/ValidatorToggle.vue` ✅ (additional)
  - Migrated additional font-size value
- `test-harness/dashboard-frontend/src/components/DomainTrendChart.vue` ✅ (additional)
  - Migrated additional font-size value
- `test-harness/dashboard-frontend/src/components/ImportFindingsModal.vue` ✅ (additional)
  - Migrated additional font-size and color values
- `test-harness/dashboard-frontend/src/views/policies/AccessControlPolicies.vue` ✅ (additional)
  - Migrated additional padding value
- `test-harness/dashboard-frontend/src/views/ComplianceTrends.vue` ✅
  - Migrated ~10 hardcoded rgba colors to design tokens
  - Migrated ~5 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/Compliance.vue` ✅ (additional)
  - Migrated ~20 hardcoded spacing/font values to design tokens
  - Migrated priority-high color to design tokens
- `test-harness/dashboard-frontend/src/views/policies/DataClassificationPolicies.vue` ✅ (additional)
  - Migrated ~8 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/components/TopNav.vue` ✅ (additional)
  - Migrated additional spacing and font-size values
- `test-harness/dashboard-frontend/src/views/TestsOverview.vue` ✅ (additional)
  - Migrated additional font-size value
- `test-harness/dashboard-frontend/src/views/ComplianceTrends.vue` ✅ (additional)
  - Migrated additional status badge colors and spacing values
- `test-harness/dashboard-frontend/src/views/CICDSecurityGates.vue` ✅
  - Migrated ~3 hardcoded colors to design tokens
- `test-harness/dashboard-frontend/src/components/ScoreCard.vue` ✅ (additional)
  - Migrated ~4 hardcoded spacing values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/ExceptionsPolicies.vue` ✅ (additional)
  - Migrated ~5 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/PlatformConfigPolicies.vue` ✅ (additional)
  - Migrated ~4 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/StandardsMappingPolicies.vue` ✅ (additional)
  - Migrated ~5 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/UnifiedFindings.vue` ✅ (additional)
  - Migrated ~7 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/Violations.vue` ✅ (additional)
  - Migrated ~4 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/ApplicationDetail.vue` ✅ (additional)
  - Migrated ~8 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/ComplianceTrends.vue` ✅ (additional)
  - Migrated additional status badge colors and border-radius values
- `test-harness/dashboard-frontend/src/views/CICDSecurityGates.vue` ✅ (additional)
  - Migrated ~10 hardcoded spacing/font/color values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/DataContractsPolicies.vue` ✅ (additional)
  - Migrated ~4 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/Violations.vue` ✅ (additional)
  - Migrated additional gap value
- `test-harness/dashboard-frontend/src/views/UnifiedFindings.vue` ✅ (additional)
  - Migrated additional gap values
- `test-harness/dashboard-frontend/src/views/policies/StandardsMappingPolicies.vue` ✅ (additional)
  - Migrated additional padding values
- `test-harness/dashboard-frontend/src/views/policies/PlatformConfigPolicies.vue` ✅ (additional)
  - Migrated additional padding value
- `test-harness/dashboard-frontend/src/components/ScoreCard.vue` ✅ (additional)
  - Migrated additional padding values
- `test-harness/dashboard-frontend/src/views/Compliance.vue` ✅ (additional)
  - Migrated additional gap and padding values
- `test-harness/dashboard-frontend/src/views/CICDSecurityGates.vue` ✅ (additional)
  - Migrated additional color and font-size values
- `test-harness/dashboard-frontend/src/views/TestSuiteBuilder.vue` ✅ (additional)
  - Migrated ~15 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/TestHarnessCreate.vue` ✅ (additional)
  - Migrated font-size value
- `test-harness/dashboard-frontend/src/views/Settings.vue` ✅ (additional)
  - Migrated gap, padding, and font-size values
- `test-harness/dashboard-frontend/src/views/TestSuiteBuilder.vue` ✅ (additional)
  - Migrated additional gap and font-size values
- `test-harness/dashboard-frontend/src/views/Settings.vue` ✅ (additional)
  - Migrated additional padding and gap values
- `test-harness/dashboard-frontend/src/views/TeamDashboard.vue` ✅ (additional)
  - Migrated gap, font-size, and padding values (multiple instances)
- `test-harness/dashboard-frontend/src/views/DeveloperFindingsDashboard.vue` ✅ (additional)
  - Migrated padding value
- `test-harness/dashboard-frontend/src/views/Home.vue` ✅ (additional)
  - Migrated margin, padding, gap, and font-size values
- `test-harness/dashboard-frontend/src/views/Reports.vue` ✅ (additional)
  - Migrated font-size and padding values
- `test-harness/dashboard-frontend/src/views/IndividualTests.vue` ✅
  - Migrated font-size, padding, and border-radius values
- `test-harness/dashboard-frontend/src/views/policies/PoliciesOverview.vue` ✅ (additional)
  - Migrated font-size value
- `test-harness/dashboard-frontend/src/views/insights/InsightsOverview.vue` ✅ (additional)
  - Migrated padding, gap, font-size, border-radius, colors, gradients, shadows, transitions, and spacing values (comprehensive migration)
- `test-harness/dashboard-frontend/src/views/Dashboard.vue` ✅ (additional)
  - Migrated font-size and padding values
- `test-harness/dashboard-frontend/src/views/PlatformConfigOverview.vue` ✅
  - Migrated padding and font-size values (multiple instances)
- `test-harness/dashboard-frontend/src/views/ApplicationDashboard.vue` ✅
  - Migrated gap, padding, and font-size values (multiple instances, comprehensive migration)
- `test-harness/dashboard-frontend/src/views/NIST800207.vue` ✅
  - Migrated padding, gap, and font-size values (multiple instances)
- `test-harness/dashboard-frontend/src/views/PendingApprovals.vue` ✅
  - Migrated padding, font-size, and color values (multiple instances)
- `test-harness/dashboard-frontend/src/views/CICDSecurityGates.vue` ✅ (additional)
  - Migrated additional colors, spacing, and font-size values
- `test-harness/dashboard-frontend/src/components/StatusBadge.vue` ✅ (additional)
  - Migrated padding and font-size values for badge-sm
- `test-harness/dashboard-frontend/src/views/TestSuiteBuilder.vue` ✅
  - Migrated ~10 hardcoded spacing/font values to design tokens
- `test-harness/dashboard-frontend/src/views/policies/StandardsMappingPolicies.vue` ✅ (additional)
  - Migrated additional padding value
- `test-harness/dashboard-frontend/src/views/ApplicationDetail.vue` ✅ (additional)
  - Migrated additional gap and margin values
- `test-harness/dashboard-frontend/src/views/policies/DataContractsPolicies.vue` ✅ (additional)
  - Migrated additional padding values
- `test-harness/dashboard-frontend/src/components/ScoreCard.vue` ✅ (additional)
  - Migrated additional padding value
