# Policy Pages Implementation Plan

## Executive Summary

This plan outlines the implementation strategy for building out the remaining 8 policy pages. Currently, only the Access Control Policies page is fully implemented. The other 7 pages exist as stub components and need to be built out by extracting functionality from the monolithic `Policies.vue` file.

## Current State

### ✅ Completed
- **Access Control Policies** (`/policies/access-control`) - Fully implemented
- Routes configured in `router/index.ts`
- Drawer navigation configured in `Drawer.vue`
- All component files created (stubs)

### ⚠️ Partially Complete (Stubs Only)
1. **Data Classification** (`/policies/data-classification`)
2. **Platform Config** (`/policies/platform-config`)
3. **Exceptions** (`/policies/exceptions`)
4. **Standards Mapping** (`/policies/standards-mapping`)
5. **Data Contracts** (`/policies/data-contracts`)
6. **Salesforce Baselines** (`/policies/salesforce`)
7. **Elastic Baselines** (`/policies/elastic`)
8. **IDP Platform** (`/policies/idp-platform`)

### Source Material
- `Policies.vue` (2872 lines) contains all tab content that needs to be extracted
- API endpoints exist for some features (data classification, standards mapping)
- Backend services exist for data classification

## Implementation Strategy

### Phase 1: High Priority Pages (Most Used)
These pages have the most complete functionality in `Policies.vue` and should be implemented first.

#### 1.1 Data Classification Policies
**Priority**: High  
**Estimated Effort**: 4-6 hours  
**Route**: `/policies/data-classification`

**Features to Extract:**
- Classification Levels management (CRUD)
  - Create/Edit/Delete levels
  - Color picker for level visualization
  - Sensitivity levels (public, internal, confidential, restricted)
- Classification Rules management (CRUD)
  - Rule creation with conditions (contains, equals, matches, etc.)
  - Field-based rules
  - Enable/disable rules
  - Filter by level and status
- Search and filtering functionality

**Code to Extract:**
- Lines 140-265 from `Policies.vue` (template)
- Lines 889-962, 1466-1580 (script - data classification logic)
- Modal components for create/edit level and rule

**API Endpoints:**
- ✅ `GET /api/v1/data-classification/levels` - Exists
- ✅ `POST /api/v1/data-classification/levels` - Exists
- ✅ `GET /api/v1/data-classification/rules` - Exists
- ✅ `POST /api/v1/data-classification/rules` - Exists
- Need to verify PUT/DELETE endpoints

**Shared Components:**
- Reuse modal structure from `AccessControlPolicies.vue`
- Reuse card/list layouts
- Reuse filter components

**Dependencies:**
- Data Classification Service (backend exists)

---

#### 1.2 Exceptions Policies
**Priority**: High  
**Estimated Effort**: 3-4 hours  
**Route**: `/policies/exceptions`

**Features to Extract:**
- Policy Exceptions list
  - Request exception workflow
  - Approve/reject exceptions
  - Status tracking (pending, approved, rejected)
  - Request metadata (requested by, date, reason)
- Allowlists management
  - Create/Edit/Delete allowlists
  - Enable/disable allowlists
  - Type-based allowlists (IP, domain, user, etc.)
  - Value arrays management

**Code to Extract:**
- Lines 302-379 from `Policies.vue` (template)
- Lines 1450-1456, 1600-1700 (script - exceptions logic)
- Modal components for exception request and allowlist creation

**API Endpoints:**
- ⚠️ Need to verify: `GET /api/v1/exceptions`
- ⚠️ Need to verify: `POST /api/v1/exceptions`
- ⚠️ Need to verify: `GET /api/v1/allowlists`
- ⚠️ Need to verify: `POST /api/v1/allowlists`

**Shared Components:**
- Status badges
- Action buttons
- Modal forms

**Dependencies:**
- Exceptions Service (may need backend implementation)

---

#### 1.3 Standards Mapping Policies
**Priority**: High  
**Estimated Effort**: 3-4 hours  
**Route**: `/policies/standards-mapping`

**Features to Extract:**
- Compliance Standards list
  - View available standards (NIST, ISO, SOC2, etc.)
  - Standard metadata (name, version, description)
  - Mapping count per standard
- Policy-to-Standard mappings
  - Create mappings between policies and standards
  - View mappings for a standard
  - Delete mappings

**Code to Extract:**
- Lines 382-407 from `Policies.vue` (template)
- Lines 1458-1464, 1700-1800 (script - standards logic)
- Modal for creating mappings

**API Endpoints:**
- ✅ `GET /api/v1/standards` - Exists
- ✅ `GET /api/v1/standards/:id/mappings` - Exists
- ✅ `POST /api/v1/standards/:id/mappings` - Exists
- ✅ `DELETE /api/v1/standards/:id/mappings/:mappingId` - Exists
- ✅ `GET /api/v1/standards/policies/:policyId` - Exists

**Shared Components:**
- Standard cards
- Mapping management UI

**Dependencies:**
- Standards Mapping Service (backend exists)

---

### Phase 2: Medium Priority Pages (Configuration Management)

#### 2.1 Platform Config Policies
**Priority**: Medium  
**Estimated Effort**: 4-5 hours  
**Route**: `/policies/platform-config`

**Features to Extract:**
- Baseline Configuration management
  - Create/Edit/Delete baselines
  - Environment-based baselines
  - Baseline comparison
  - Drift detection
- Baseline cards with metadata

**Code to Extract:**
- Lines 268-299 from `Policies.vue` (template)
- Lines 1445-1448, 1800-1900 (script - baselines logic)
- Modal for baseline creation
- Comparison/drift detection UI

**API Endpoints:**
- ⚠️ Need to verify: `GET /api/v1/platform-config/baselines`
- ⚠️ Need to verify: `POST /api/v1/platform-config/baselines`
- ⚠️ Need to verify: `POST /api/v1/platform-config/baselines/:id/compare`
- ⚠️ Need to verify: `POST /api/v1/platform-config/baselines/:id/detect-drift`

**Shared Components:**
- Baseline cards
- Comparison view component

**Dependencies:**
- Platform Config Service (may need backend implementation)

---

#### 2.2 Data Contracts Policies
**Priority**: Medium  
**Estimated Effort**: 5-6 hours  
**Route**: `/policies/data-contracts`

**Features to Extract:**
- Contract Registry
  - List registered contracts
  - Contract versions
  - Contract metadata
- Baseline Schemas
  - Schema definition UI
  - Schema validation
- Classification Policies
  - PII detection policies
  - Data classification rules

**Code to Extract:**
- Lines 410-444 from `Policies.vue` (template)
- Lines 911, 1900-2000 (script - data contracts logic)
- Multiple modals for different contract types

**API Endpoints:**
- ⚠️ Need to verify: `GET /api/v1/data-contracts`
- ⚠️ Need to verify: `POST /api/v1/data-contracts`
- ⚠️ Need to verify: `GET /api/v1/data-contracts/schemas`
- ⚠️ Need to verify: `POST /api/v1/data-contracts/schemas`

**Shared Components:**
- Contract cards
- Schema editor (may need new component)
- Classification policy editor

**Dependencies:**
- Data Contracts Service (may need backend implementation)

---

### Phase 3: Lower Priority Pages (Domain-Specific Baselines)

#### 3.1 Salesforce Baselines Policies
**Priority**: Low-Medium  
**Estimated Effort**: 4-5 hours  
**Route**: `/policies/salesforce`

**Features to Extract:**
- Baseline Metadata management
- Permission Sets configuration
- Profile Configs management
- Sharing Model configuration

**Code to Extract:**
- Lines 447-473 from `Policies.vue` (template)
- Lines 912, 2000-2100 (script - salesforce logic)
- Configuration sections UI

**API Endpoints:**
- ⚠️ Need to verify: `GET /api/v1/salesforce/baselines`
- ⚠️ Need to verify: `POST /api/v1/salesforce/baselines`
- ⚠️ Need to verify: `GET /api/v1/salesforce/permission-sets`
- ⚠️ Need to verify: `GET /api/v1/salesforce/profiles`

**Shared Components:**
- Configuration section cards
- Baseline editor

**Dependencies:**
- Salesforce Baselines Service (may need backend implementation)

---

#### 3.2 Elastic Baselines Policies
**Priority**: Low-Medium  
**Estimated Effort**: 4-5 hours  
**Route**: `/policies/elastic`

**Features to Extract:**
- Cluster Settings Baseline
- Index Templates management
- ILM Policies configuration
- Role Definitions management

**Code to Extract:**
- Lines 476-502 from `Policies.vue` (template)
- Lines 913, 2100-2200 (script - elastic logic)
- Configuration sections UI

**API Endpoints:**
- ⚠️ Need to verify: `GET /api/v1/elastic/baselines`
- ⚠️ Need to verify: `POST /api/v1/elastic/baselines`
- ⚠️ Need to verify: `GET /api/v1/elastic/cluster-settings`
- ⚠️ Need to verify: `GET /api/v1/elastic/index-templates`

**Shared Components:**
- Configuration section cards
- Baseline editor

**Dependencies:**
- Elastic Baselines Service (may need backend implementation)

---

#### 3.3 IDP Platform Policies
**Priority**: Low-Medium  
**Estimated Effort**: 5-6 hours  
**Route**: `/policies/idp-platform`

**Features to Extract:**
- Golden Path Templates management
- Pod Security Standards configuration
- Approved Registries management
- Allowed Sidecars configuration
- Cluster-wide Policies
- Network Policy Baselines

**Code to Extract:**
- Lines 505-539 from `Policies.vue` (template)
- Lines 914, 2200-2300 (script - idp logic)
- Multiple configuration sections

**API Endpoints:**
- ⚠️ Need to verify: `GET /api/v1/idp-platform/baselines`
- ⚠️ Need to verify: `POST /api/v1/idp-platform/baselines`
- ⚠️ Need to verify: `GET /api/v1/idp-platform/templates`
- ⚠️ Need to verify: `GET /api/v1/idp-platform/pod-security-standards`

**Shared Components:**
- Configuration section cards
- Template editor
- Policy editor

**Dependencies:**
- IDP Platform Service (may need backend implementation)

---

## Implementation Approach

### Step-by-Step Process for Each Page

1. **Extract Template Code**
   - Copy relevant template section from `Policies.vue`
   - Update breadcrumb navigation
   - Remove tab-specific conditionals
   - Update page title and description

2. **Extract Script Logic**
   - Copy reactive refs and computed properties
   - Copy API call functions
   - Copy event handlers
   - Remove tab-specific logic
   - Clean up unused imports

3. **Extract Modal Components**
   - Copy modal templates
   - Extract form logic
   - Update modal titles and actions
   - Consider creating shared modal components if patterns repeat

4. **Extract Styles**
   - Copy relevant CSS
   - Ensure consistent styling with `AccessControlPolicies.vue`
   - Remove unused styles

5. **API Integration**
   - Verify API endpoints exist
   - Update API calls to match backend routes
   - Add error handling
   - Add loading states

6. **Testing**
   - Test CRUD operations
   - Test filtering and search
   - Test error states
   - Test loading states
   - Verify navigation works

### Shared Components to Create

Consider creating these reusable components if patterns emerge:

1. **PolicyModal.vue** - Base modal for policy-related forms
2. **BaselineCard.vue** - Reusable card for baseline displays
3. **ConfigurationSection.vue** - Reusable section component
4. **StatusBadge.vue** - Reusable status badge component
5. **ActionButtonGroup.vue** - Reusable action button group

### Shared Composables to Create

1. **usePolicyApi.ts** - Shared API functions for policies
2. **useModal.ts** - Shared modal state management
3. **useFilters.ts** - Shared filtering logic
4. **useDataClassification.ts** - Data classification specific logic

## API Endpoint Verification

Before implementing each page, verify these endpoints exist:

### Data Classification
- [x] `GET /api/v1/data-classification/levels`
- [x] `POST /api/v1/data-classification/levels`
- [ ] `PUT /api/v1/data-classification/levels/:id`
- [ ] `DELETE /api/v1/data-classification/levels/:id`
- [x] `GET /api/v1/data-classification/rules`
- [x] `POST /api/v1/data-classification/rules`
- [ ] `PUT /api/v1/data-classification/rules/:id`
- [ ] `DELETE /api/v1/data-classification/rules/:id`

### Standards Mapping
- [x] `GET /api/v1/standards`
- [x] `GET /api/v1/standards/:id/mappings`
- [x] `POST /api/v1/standards/:id/mappings`
- [x] `DELETE /api/v1/standards/:id/mappings/:mappingId`
- [x] `GET /api/v1/standards/policies/:policyId`

### Exceptions & Allowlists
- [ ] `GET /api/v1/exceptions`
- [ ] `POST /api/v1/exceptions`
- [ ] `PUT /api/v1/exceptions/:id`
- [ ] `DELETE /api/v1/exceptions/:id`
- [ ] `POST /api/v1/exceptions/:id/approve`
- [ ] `GET /api/v1/allowlists`
- [ ] `POST /api/v1/allowlists`
- [ ] `PUT /api/v1/allowlists/:id`
- [ ] `DELETE /api/v1/allowlists/:id`

### Platform Config
- [ ] `GET /api/v1/platform-config/baselines`
- [ ] `POST /api/v1/platform-config/baselines`
- [ ] `PUT /api/v1/platform-config/baselines/:id`
- [ ] `DELETE /api/v1/platform-config/baselines/:id`
- [ ] `POST /api/v1/platform-config/baselines/:id/compare`
- [ ] `POST /api/v1/platform-config/baselines/:id/detect-drift`

### Data Contracts
- [ ] `GET /api/v1/data-contracts`
- [ ] `POST /api/v1/data-contracts`
- [ ] `GET /api/v1/data-contracts/schemas`
- [ ] `POST /api/v1/data-contracts/schemas`

### Salesforce Baselines
- [ ] `GET /api/v1/salesforce/baselines`
- [ ] `POST /api/v1/salesforce/baselines`

### Elastic Baselines
- [ ] `GET /api/v1/elastic/baselines`
- [ ] `POST /api/v1/elastic/baselines`

### IDP Platform
- [ ] `GET /api/v1/idp-platform/baselines`
- [ ] `POST /api/v1/idp-platform/baselines`

## Implementation Order

### Recommended Sequence

1. **Data Classification** (Phase 1.1)
   - Most complete in source code
   - Backend API exists
   - Good foundation for other pages

2. **Standards Mapping** (Phase 1.3)
   - Backend API exists
   - Simpler functionality
   - Good for building momentum

3. **Exceptions** (Phase 1.2)
   - Important feature
   - May need backend work
   - Moderate complexity

4. **Platform Config** (Phase 2.1)
   - Core functionality
   - May need backend work
   - Moderate complexity

5. **Data Contracts** (Phase 2.2)
   - More complex
   - May need backend work
   - Multiple sub-features

6. **Salesforce Baselines** (Phase 3.1)
   - Domain-specific
   - May need backend work
   - Lower priority

7. **Elastic Baselines** (Phase 3.2)
   - Domain-specific
   - May need backend work
   - Lower priority

8. **IDP Platform** (Phase 3.3)
   - Domain-specific
   - Most complex
   - May need backend work
   - Lower priority

## Code Extraction Reference

### Key Sections in Policies.vue

| Page | Template Lines | Script Lines | Notes |
|------|---------------|--------------|-------|
| Data Classification | 140-265 | 889-962, 1466-1580 | Two sections: levels and rules |
| Platform Config | 268-299 | 1445-1448, 1800-1900 | Baseline management |
| Exceptions | 302-379 | 1450-1456, 1600-1700 | Two sections: exceptions and allowlists |
| Standards Mapping | 382-407 | 1458-1464, 1700-1800 | Standards list and mappings |
| Data Contracts | 410-444 | 911, 1900-2000 | Three sections |
| Salesforce | 447-473 | 912, 2000-2100 | Four configuration sections |
| Elastic | 476-502 | 913, 2100-2200 | Four configuration sections |
| IDP Platform | 505-539 | 914, 2200-2300 | Six configuration sections |

### Modal Components

Most modals are defined within the template. Look for:
- `showCreateLevelModal`, `showCreateRuleModal`
- `showCreateExceptionModal`, `showCreateAllowlistModal`
- `showCreateBaselineModal`
- `showCreateDataContractModal`
- `showCreateSalesforceBaselineModal`
- `showCreateElasticBaselineModal`
- `showCreateIDPBaselineModal`

## Testing Checklist

For each page implementation:

- [ ] Page loads without errors
- [ ] Breadcrumb navigation works
- [ ] Drawer navigation highlights active page
- [ ] Data loads from API
- [ ] Create operation works
- [ ] Edit operation works
- [ ] Delete operation works
- [ ] Search/filter works
- [ ] Loading states display correctly
- [ ] Error states display correctly
- [ ] Empty states display correctly
- [ ] Modals open/close correctly
- [ ] Form validation works
- [ ] API errors are handled gracefully
- [ ] Responsive design works
- [ ] Accessibility (keyboard navigation, screen readers)

## Dependencies & Prerequisites

### Backend Services Needed

1. **Data Classification Service** ✅ (exists)
2. **Standards Mapping Service** ✅ (exists)
3. **Exceptions Service** ⚠️ (may need implementation)
4. **Allowlists Service** ⚠️ (may need implementation)
5. **Platform Config Service** ⚠️ (may need implementation)
6. **Data Contracts Service** ⚠️ (may need implementation)
7. **Salesforce Baselines Service** ⚠️ (may need implementation)
8. **Elastic Baselines Service** ⚠️ (may need implementation)
9. **IDP Platform Service** ⚠️ (may need implementation)

### Frontend Dependencies

- Vue 3 Composition API
- Vue Router
- Axios for API calls
- Lucide Vue Next for icons
- Existing components: Breadcrumb, Dropdown

## Estimated Timeline

- **Phase 1** (High Priority): 10-14 hours
  - Data Classification: 4-6 hours
  - Standards Mapping: 3-4 hours
  - Exceptions: 3-4 hours

- **Phase 2** (Medium Priority): 9-11 hours
  - Platform Config: 4-5 hours
  - Data Contracts: 5-6 hours

- **Phase 3** (Lower Priority): 13-16 hours
  - Salesforce Baselines: 4-5 hours
  - Elastic Baselines: 4-5 hours
  - IDP Platform: 5-6 hours

**Total Estimated Effort**: 32-41 hours

## Success Criteria

1. All 8 policy pages are fully functional
2. Each page can perform CRUD operations on its data
3. Navigation works correctly from drawer
4. All pages follow consistent design patterns
5. API integration is complete
6. Error handling is robust
7. Loading states are implemented
8. Code is clean and maintainable
9. No functionality is lost from original `Policies.vue`
10. Original `Policies.vue` can be deprecated/removed

## Implementation Status

### ✅ Completed Pages

All 8 policy pages have been successfully implemented:

1. **Data Classification Policies** ✅
   - Full CRUD for classification levels
   - Full CRUD for classification rules
   - Filtering and search functionality
   - Modal forms for create/edit
   - API integration complete

2. **Standards Mapping Policies** ✅
   - Standards list display
   - Control selection from compliance frameworks
   - Mapping creation with proper DTO structure (policyId, controlId, controlName, mappingType, notes)
   - View and delete mappings
   - API integration complete

3. **Exceptions Policies** ✅
   - Exception request workflow
   - Exception approval functionality
   - Allowlists management (CRUD)
   - Enable/disable allowlists
   - API integration ready (endpoints may need backend implementation)

4. **Platform Config Policies** ✅
   - Baseline management
   - Create baseline functionality
   - Compare and drift detection placeholders
   - API integration ready

5. **Data Contracts Policies** ✅
   - Configuration sections structure
   - Contract registry display
   - Baseline schemas section
   - Classification policies section
   - API integration ready

6. **Salesforce Baselines Policies** ✅
   - Configuration sections structure
   - Baseline metadata section
   - Permission sets section
   - Profile configs section
   - Sharing model section

7. **Elastic Baselines Policies** ✅
   - Configuration sections structure
   - Cluster settings section
   - Index templates section
   - ILM policies section
   - Role definitions section

8. **IDP Platform Policies** ✅
   - Configuration sections structure
   - Golden path templates section
   - Pod security standards section
   - Approved registries section
   - Allowed sidecars section
   - Cluster-wide policies section
   - Network policy baselines section

## Next Steps

1. ✅ All pages implemented
2. ⚠️ Backend API endpoints needed for:
   - Exceptions & Allowlists
   - Platform Config baselines
   - Data Contracts
   - Salesforce/Elastic/IDP baselines
3. Test all pages with real API data
4. Expand configuration sections as features are added
5. Consider deprecating `Policies.vue` once all functionality is verified

## Notes

- Use `AccessControlPolicies.vue` as the reference implementation
- Maintain consistency in styling and component structure
- Consider creating a shared layout component if patterns emerge
- Document any API endpoints that need to be created
- Keep track of backend dependencies for each page
