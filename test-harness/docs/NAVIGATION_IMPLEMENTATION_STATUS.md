# Navigation Improvement Implementation Status

## Overview
This document tracks the implementation progress of converting page tabs to separate pages as outlined in NAVIGATION_IMPROVEMENT_PLAN.md.

## High Priority Conversions

### 1. Policies Page (9 tabs → 9 separate pages)
**Status**: In Progress

**Pages to Create**:
- [x] `/policies` - Access Control Policies (main/default page)
- [ ] `/policies/data-classification` - Data Classification
- [ ] `/policies/platform-config` - Platform Config
- [ ] `/policies/exceptions` - Exceptions
- [ ] `/policies/standards-mapping` - Standards Mapping
- [ ] `/policies/data-contracts` - Data Contracts
- [ ] `/policies/salesforce` - Salesforce Baselines
- [ ] `/policies/elastic` - Elastic Baselines
- [ ] `/policies/idp-platform` - IDP / Kubernetes Baselines

**Implementation Notes**:
- Access Control Policies page created as main `/policies` route
- Original Policies.vue file contains all tab content (2872 lines)
- Each new page should extract relevant tab content and related functions
- Modal and form logic can be shared via composable if needed

### 2. Insights & Reports (6 pages consolidated)
**Status**: Not Started

**Pages to Create**:
- [ ] `/insights` - Overview (main page)
- [ ] `/insights/analytics` - Analytics (renamed from "Reports" tab)
- [ ] `/insights/predictions` - Predictions
- [ ] `/insights/runs` - Runs (from Runs & Reports)
- [ ] `/insights/reports` - Reports (from Runs & Reports)
- [ ] `/insights/trends` - Trends (from Runs & Reports)

**Implementation Notes**:
- Consolidate Insights.vue and RunsAndReports.vue
- Create shared composable for filters if needed
- Update sidebar to show "Insights & Reports" instead of separate items

## Implementation Steps

### Step 1: Create Access Control Policies Page ✅
- Created `/policies` route pointing to AccessControlPolicies component
- Extracted access-control tab content from Policies.vue
- Includes: policy list, filters, create/edit modal, all CRUD operations

### Step 2: Update Router ✅
- [x] Add routes for all 9 policy pages
- [ ] Add routes for all 6 insights pages
- [x] Update existing routes as needed

### Step 3: Update Drawer Navigation ✅
- [x] Add all new policy pages to Policies & Config drawer
- [ ] Add all new insights pages to Insights & Reports drawer
- [x] Updated navigation structure with all 9 policy pages

### Step 4: Update Sidebar
- [ ] Change "Policies & Config" to navigate directly to `/policies`
- [ ] Change "Runs & Reports" to "Insights & Reports" and navigate to `/insights`
- [ ] Update labels as needed

### Step 5: Create Remaining Pages
- [ ] Create 8 remaining policy pages
- [ ] Create 6 insights pages
- [ ] Extract and adapt code from original files

### Step 6: Remove Tab Navigation
- [ ] Remove tabs from Policies.vue (or archive it)
- [ ] Remove tabs from Insights.vue
- [ ] Remove tabs from RunsAndReports.vue

## Files Created
- `dashboard-frontend/src/views/policies/AccessControlPolicies.vue` - Main policies page

## Files to Create
- `dashboard-frontend/src/views/policies/DataClassificationPolicies.vue`
- `dashboard-frontend/src/views/policies/PlatformConfigPolicies.vue`
- `dashboard-frontend/src/views/policies/ExceptionsPolicies.vue`
- `dashboard-frontend/src/views/policies/StandardsMappingPolicies.vue`
- `dashboard-frontend/src/views/policies/DataContractsPolicies.vue`
- `dashboard-frontend/src/views/policies/SalesforceBaselinesPolicies.vue`
- `dashboard-frontend/src/views/policies/ElasticBaselinesPolicies.vue`
- `dashboard-frontend/src/views/policies/IDPPlatformPolicies.vue`
- `dashboard-frontend/src/views/insights/InsightsOverview.vue`
- `dashboard-frontend/src/views/insights/InsightsAnalytics.vue`
- `dashboard-frontend/src/views/insights/InsightsPredictions.vue`
- `dashboard-frontend/src/views/insights/InsightsRuns.vue`
- `dashboard-frontend/src/views/insights/InsightsReports.vue`
- `dashboard-frontend/src/views/insights/InsightsTrends.vue`

## Files Modified ✅
- `dashboard-frontend/src/router/index.ts` - ✅ Added routes for all 9 policy pages
- `dashboard-frontend/src/components/Drawer.vue` - ✅ Updated navigation with all policy pages
- `dashboard-frontend/src/components/Sidebar.vue` - ⏳ Update navigation and labels (pending)

## Next Steps
1. Complete Access Control Policies page implementation
2. Create remaining 8 policy pages
3. Create 6 insights pages
4. Update router and navigation components
5. Test all navigation flows
6. Remove old tab-based pages
