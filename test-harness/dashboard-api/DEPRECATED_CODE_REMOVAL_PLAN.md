# Deprecated Code Removal Plan

This document outlines code that should be removed after the migration period is complete.

## Migration Period

**Recommended Duration:** 3-6 months after migration scripts are run

During this period:
- Deprecated endpoints will continue to work
- Deprecation warnings will be logged
- Frontend will show deprecation notices
- New code should use the new infrastructure model

## Code to Remove

### Backend (API)

#### 1. TestConfigurationsService
**File:** `src/test-configurations/test-configurations.service.ts`
**Status:** Fully deprecated
**Action:** Remove entire service after migration period

#### 2. TestConfigurationsController
**File:** `src/test-configurations/test-configurations.controller.ts`
**Status:** Fully deprecated
**Action:** Remove entire controller after migration period

#### 3. TestConfigurationsModule
**File:** `src/test-configurations/test-configurations.module.ts`
**Status:** Fully deprecated
**Action:** Remove module and unregister from `app.module.ts`

#### 4. ApplicationsService - Deprecated Methods
**File:** `src/applications/applications.service.ts`
**Methods to Remove:**
- `assignTestConfigurations()` - Line ~306
- `getTestConfigurations()` - Line ~326
- `toggleTestConfiguration()` - Line ~578
- `getTestConfigurationStatus()` - (if exists)
- `bulkToggleTestConfigurations()` - (if exists)
- `removeTestConfigurationOverride()` - (if exists)

#### 5. ApplicationsController - Deprecated Endpoints
**File:** `src/applications/applications.controller.ts`
**Endpoints to Remove:**
- `POST /api/v1/applications/:id/test-configurations` - Line ~141
- `GET /api/v1/applications/:id/test-configurations` - Line ~150
- `PATCH /api/v1/applications/:id/test-configurations/:configId/toggle` - Line ~176
- `GET /api/v1/applications/:id/test-configurations/status` - Line ~214
- `PATCH /api/v1/applications/:id/test-configurations/bulk-toggle` - Line ~226
- `DELETE /api/v1/applications/:id/test-configurations/:configId/override` - Line ~258

#### 6. Application Entity - Deprecated Fields
**File:** `src/applications/entities/application.entity.ts`
**Fields to Remove:**
- `testConfigurationIds?: string[]` - Line ~26
- `testConfigurationOverrides?: {...}` - Line ~27

#### 7. Test Suite Entity - Deprecated Fields
**File:** `src/test-suites/entities/test-suite.entity.ts`
**Fields to Remove:**
- `testConfigurationIds?: string[]` - Line ~22

#### 8. Test Suite DTO - Deprecated Fields
**File:** `src/test-suites/dto/create-test-suite.dto.ts`
**Fields to Remove:**
- `testConfigurationIds?: string[]` - Line ~98

### Frontend

#### 1. TestConfigurations.vue
**File:** `src/views/TestConfigurations.vue`
**Status:** Fully deprecated
**Action:** Remove entire page or convert to redirect page

#### 2. ApplicationDetail.vue - Deprecated Sections
**File:** `src/views/ApplicationDetail.vue`
**Sections to Remove:**
- Deprecated "Test Configuration Management" section (lines ~374-397)
- `loadTestConfigurations()` function
- `handleBulkToggleTestConfigs()` function
- `testConfigurations` ref
- `loadingTestConfigs` ref

#### 3. TestConfigToggle Component
**File:** `src/components/TestConfigToggle.vue`
**Status:** Deprecated
**Action:** Remove if only used for test configurations

### Core Types

#### 1. Test Types - Deprecated Fields
**File:** `core/types.ts`
**Fields to Remove (after migration):**
- `AccessControlTest.role` (deprecated, use `inputs.subject.role`)
- `AccessControlTest.expectedDecision` (deprecated, use `expected.allowed`)
- `AccessControlTest.policyRuleId` (deprecated)
- `TestResult.policyIds` (deprecated, use `policyId`)

## Removal Checklist

Before removing deprecated code:

- [ ] Verify migration scripts have been run successfully
- [ ] Confirm no applications are using `testConfigurationIds`
- [ ] Confirm no test suites are using `testConfigurationIds`
- [ ] Verify all tests have been migrated to 1:1 policy relationship
- [ ] Check API logs for deprecated endpoint usage (should be zero)
- [ ] Update API documentation to remove deprecated endpoints
- [ ] Update frontend navigation to remove Test Configurations link
- [ ] Create backup of data before removal
- [ ] Test application after removal
- [ ] Update changelog/release notes

## Removal Steps

1. **Phase 1: Remove Frontend References**
   - Remove TestConfigurations.vue page
   - Remove deprecated sections from ApplicationDetail.vue
   - Update navigation/routing

2. **Phase 2: Remove Backend Endpoints**
   - Remove deprecated controller endpoints
   - Remove deprecated service methods
   - Update API documentation

3. **Phase 3: Remove Entity Fields**
   - Remove deprecated fields from Application entity
   - Remove deprecated fields from TestSuite entity
   - Remove deprecated fields from Test entities

4. **Phase 4: Remove Services/Modules**
   - Remove TestConfigurationsService
   - Remove TestConfigurationsController
   - Remove TestConfigurationsModule
   - Clean up imports

5. **Phase 5: Final Cleanup**
   - Remove migration scripts (or archive them)
   - Update documentation
   - Update tests

## Notes

- Keep migration scripts in an archive folder for reference
- Consider keeping a simple redirect from old endpoints to new ones for a short period
- Document the migration in release notes
