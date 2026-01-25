# Distributed Systems Test Refactor Plan

## Overview
Refactor distributed systems testing from a standalone page to proper test types within the test hierarchy. The test type will be `distributed-systems` with three main test subtypes:
1. **Multi-Region Test** - Execute tests across multiple regions
2. **Policy Consistency Test** - Check policy consistency across regions
3. **Policy Synchronization Test** - Test policy synchronization timing and failures

## Current State
- `distributed-systems` is already in the TestType union
- `DistributedSystemsTest` interface exists with basic `distributedTestType` field
- Standalone page exists at `/distributed-systems` with tabs
- Services exist: `MultiRegionTestingService`, `PolicyConsistencyChecker`, `PolicySyncTester`

## Target State
- Tests are created as individual test entities with `testType: 'distributed-systems'`
- Each test has a `distributedTestType` field specifying the subtype
- Tests can be added to test suites, harnesses, and batteries
- Tests execute through the standard test orchestrator
- UI shows distributed systems tests in the test management interface

## Implementation Plan

### Phase 1: Update Type Definitions

#### 1.1 Expand DistributedSystemsTest Interface
**File:** `heimdall-framework/core/types.ts`

```typescript
export interface DistributedSystemsTest extends BaseTest {
  testType: 'distributed-systems';
  distributedTestType: 'multi-region' | 'policy-consistency' | 'policy-synchronization';
  applicationId?: string; // References application with distributed systems infrastructure
  
  // Multi-Region Test Configuration
  multiRegionConfig?: {
    regions: string[]; // Region IDs to test
    executionMode?: 'parallel' | 'sequential';
    timeout?: number;
    user?: {
      id: string;
      attributes?: Record<string, any>;
    };
    resource?: {
      id: string;
      type?: string;
      attributes?: Record<string, any>;
    };
    action?: string;
    expectedResult?: boolean;
  };
  
  // Policy Consistency Test Configuration
  policyConsistencyConfig?: {
    regions: string[]; // Region IDs to check
    policyIds?: string[]; // Specific policies to check, or all if not specified
    checkTypes?: ('version' | 'configuration' | 'evaluation')[];
  };
  
  // Policy Synchronization Test Configuration
  policySyncConfig?: {
    regions: string[]; // Region IDs to test
    policyId?: string; // Specific policy to test, or all if not specified
    testScenarios?: ('update-propagation' | 'sync-timing' | 'sync-failure-recovery')[];
  };
}
```

#### 1.2 Update Frontend Test Types
**File:** `dashboard-frontend/src/types/test.ts`

Update `DistributedSystemsConfig` to match the new structure.

#### 1.3 Update DTOs
**File:** `dashboard-api/src/tests/dto/create-test.dto.ts`

Add fields for distributed systems test configuration.

### Phase 2: Test Execution Integration

#### 2.1 Add Test Execution Handler
**File:** `heimdall-framework/core/test-harness.ts`

Add case for `distributed-systems` in `runTest()` method:

```typescript
case 'distributed-systems':
  return this.runDistributedSystemsTest(test as DistributedSystemsTest, suite);
```

#### 2.2 Implement Test Execution Method
**File:** `heimdall-framework/core/test-harness.ts`

Create `runDistributedSystemsTest()` method that:
- Loads application infrastructure to get regions
- Routes to appropriate service based on `distributedTestType`:
  - `multi-region` → `MultiRegionTestingService`
  - `policy-consistency` → `PolicyConsistencyChecker`
  - `policy-synchronization` → `PolicySyncTester`
- Converts service results to `TestResult` format
- Handles errors appropriately

#### 2.3 Update Domain Mapping
**File:** `heimdall-framework/core/domain-mapping.ts`

Ensure `distributed-systems` maps to appropriate domain (likely `platform_config` or new domain).

### Phase 3: UI Updates

#### 3.1 Remove Standalone Page
- Remove `/distributed-systems` route
- Remove `DistributedSystems.vue` page
- Remove `DistributedTestRunner.vue` component (or repurpose)
- Remove navigation items from Sidebar and Drawer

#### 3.2 Update Test Creation UI
**File:** `dashboard-frontend/src/views/IndividualTests.vue` or test creation modal

Add support for creating distributed systems tests:
- When `testType: 'distributed-systems'` is selected, show subtype selector
- Show appropriate configuration form based on selected subtype:
  - Multi-Region: Region selector, execution mode, user/resource inputs
  - Policy Consistency: Region selector, policy selector, check type checkboxes
  - Policy Synchronization: Region selector, policy selector, scenario checkboxes
- Application selector (required) - filters to apps with distributed systems infrastructure

#### 3.3 Update Test Detail View
**File:** `dashboard-frontend/src/views/TestDetail.vue`

Show distributed systems test configuration:
- Display test subtype
- Show configuration details
- Show execution results with region-by-region breakdown

#### 3.4 Update Test List/Filter
Ensure distributed systems tests can be:
- Filtered by test type
- Filtered by distributed test subtype
- Grouped appropriately

### Phase 4: API Updates

#### 4.1 Update Test Service
**File:** `dashboard-api/src/tests/tests.service.ts`

- Ensure `distributed-systems` test type is validated
- Validate configuration based on `distributedTestType`
- Ensure `applicationId` references valid application with distributed systems infrastructure

#### 4.2 Update Test Execution Endpoints
**File:** `dashboard-api/src/test-suites/test-suites.service.ts`

Ensure distributed systems tests execute properly when run through test suites.

#### 4.3 Remove Standalone API Endpoints
**Files:** 
- `dashboard-api/src/distributed/distributed.controller.ts`
- `dashboard-api/src/distributed/distributed.module.ts`

Keep services but remove controller endpoints (or repurpose for test execution only).

### Phase 5: Documentation & Examples

#### 5.1 Update Test Creation Guide
**File:** `docs/guides/TEST_CREATION_GUIDE.md`

Add section on creating distributed systems tests with examples for each subtype.

#### 5.2 Update API Documentation
Document distributed systems test structure and configuration options.

#### 5.3 Create Example Tests
Create example distributed systems tests in test data or examples directory.

## Migration Strategy

### Existing Data
- No migration needed if no tests exist yet
- If standalone tests exist, create migration script to convert to test entities

### Backward Compatibility
- Keep services (`MultiRegionTestingService`, etc.) as they're used by test execution
- Remove only the standalone UI and direct API endpoints

## Testing Checklist

- [ ] Can create multi-region test through test creation UI
- [ ] Can create policy consistency test through test creation UI
- [ ] Can create policy synchronization test through test creation UI
- [ ] Tests appear in test list with correct type/subtype
- [ ] Tests can be added to test suites
- [ ] Tests execute correctly through test orchestrator
- [ ] Test results show region-by-region breakdown
- [ ] Application selector filters to apps with distributed systems infrastructure
- [ ] Validation prevents creating tests without required configuration
- [ ] Test detail view shows configuration correctly

## Files to Modify

### Backend
- `heimdall-framework/core/types.ts` - Expand DistributedSystemsTest interface
- `heimdall-framework/core/test-harness.ts` - Add execution handler
- `dashboard-api/src/tests/dto/create-test.dto.ts` - Add DTO fields
- `dashboard-api/src/tests/tests.service.ts` - Add validation
- `dashboard-api/src/distributed/distributed.controller.ts` - Remove or repurpose
- `dashboard-api/src/distributed/distributed.module.ts` - Keep services, remove controller

### Frontend
- `dashboard-frontend/src/types/test.ts` - Update DistributedSystemsConfig
- `dashboard-frontend/src/views/IndividualTests.vue` - Add test creation UI
- `dashboard-frontend/src/views/TestDetail.vue` - Show distributed systems config
- `dashboard-frontend/src/views/DistributedSystems.vue` - Remove
- `dashboard-frontend/src/components/DistributedTestRunner.vue` - Remove or repurpose
- `dashboard-frontend/src/components/Sidebar.vue` - Remove navigation item
- `dashboard-frontend/src/components/Drawer.vue` - Remove navigation item
- `dashboard-frontend/src/router/index.ts` - Remove route
- `dashboard-frontend/src/composables/useDistributedTesting.ts` - Keep for test execution

### Documentation
- `docs/guides/TEST_CREATION_GUIDE.md` - Add distributed systems section ✅
- `docs/guides/QUICK_REFERENCE.md` - Add distributed systems quick reference ✅
- `docs/development/DISTRIBUTED_SYSTEMS_TEST_REFACTOR_PLAN.md` - This file

## Benefits

1. **Consistency**: Follows same pattern as other test types
2. **Integration**: Tests can be part of test suites, harnesses, and batteries
3. **Discoverability**: Tests appear in standard test management UI
4. **Maintainability**: Single test execution path
5. **Flexibility**: Can mix distributed systems tests with other test types in suites

## Risks & Mitigation

- **Risk**: Users may expect standalone page
  - **Mitigation**: Add clear documentation and examples showing how to create tests
- **Risk**: Configuration complexity
  - **Mitigation**: Provide good UI with clear labels and validation
- **Risk**: Application dependency
  - **Mitigation**: Clear validation and error messages when application doesn't have infrastructure
