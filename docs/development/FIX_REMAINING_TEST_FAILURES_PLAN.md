# Fix Remaining Test Failures Plan

## Summary
29 test suites are failing with 27 test failures. Main categories:
1. **TypeScript compilation errors** - Duplicate identifiers, missing method declarations
2. **Missing module imports** - Incorrect import paths for service testers
3. **Dependency injection issues** - Missing mocked dependencies in test modules
4. **Mock configuration issues** - Policies service JSON parsing still failing

## Issues Identified

### 1. Duplicate `applicationId` Field (CRITICAL - Blocks compilation)
**File**: `dashboard-api/src/tests/dto/create-test.dto.ts`
- Line 244: `applicationId?: string;` (base field for RLSCLSTest)
- Line 327: `applicationId?: string;` (duplicate in DistributedSystemsTest fields)
- Causes TypeScript compilation error: "Duplicate identifier 'applicationId'"

**Fix**: Remove the duplicate field at line 327. Keep the one at line 244 as it's more general and used by RLSCLSTest.

### 2. Syntax Error in test-harness.ts (CRITICAL - Blocks compilation)
**File**: `heimdall-framework/core/test-harness.ts`
- Line 896: Verify `async` keyword is present before `runPolicySynchronizationTest`
- Methods `runMultiRegionTest`, `runPolicyConsistencyTest`, `runPolicySynchronizationTest` are private but being called
- TypeScript error: "Property 'runMultiRegionTest' does not exist on type 'TestOrchestrator'"

**Fix**: 
- Verify line 896 has correct syntax: `private async runPolicySynchronizationTest(`
- Ensure all three methods are properly declared as private methods within the class

### 3. Missing Module Import Paths (Blocks multiple test suites)
**Files**: Multiple test spec files
- `rls-cls.service.spec.ts`: Cannot find `'../../../services/rls-cls-tester'`
- `policy-validation.service.spec.ts`: Cannot find `'../../../services/policy-validation-tester'`
- `identity-provider.service.spec.ts`: Cannot find `'../../../services/identity-provider-tester'`
- `dlp.service.spec.ts`: Cannot find `'../../../services/dlp-tester'`

**Actual paths** (from glob search):
- `heimdall-framework/services/rls-cls-tester.ts` exists
- `heimdall-framework/services/policy-validation-tester.ts` exists

**Fix**: Update import paths in test files to use correct relative paths from `dashboard-api/src/` to `heimdall-framework/services/`

### 4. Missing Dependency: ApplicationDataService (Blocks TestsService tests)
**File**: `dashboard-api/src/tests/tests.service.spec.ts`
- TestsService constructor requires: `ModuleRef`, `TestDiscoveryService`, `ApplicationDataService`
- Test module only provides: `ModuleRef`, `TestDiscoveryService`
- Error: "Cannot resolve dependencies... ApplicationDataService at index [2]"
- Note: ApplicationDataService is optional (`applicationDataService?: ApplicationDataService`) but NestJS still requires it in test module

**Fix**: Add ApplicationDataService mock to test module providers

### 5. Policies Service Mock Still Failing
**File**: `dashboard-api/src/policies/policies.service.spec.ts`
- JSON parsing errors still occurring
- Mock setup may not be preventing loadPolicies/loadAuditLogs from running during service initialization
- Need to ensure mocks are set up before service initialization

**Fix**: Ensure mocks are properly configured before service instantiation, or mock the load methods more effectively

## Implementation Steps

### Phase 1: Fix Compilation Errors (Highest Priority)

1. **Fix duplicate applicationId**
   - Remove duplicate `applicationId` field from `create-test.dto.ts` line 327
   - Keep the field at line 244 (more general location, used by RLSCLSTest)

2. **Fix test-harness.ts syntax error**
   - Verify line 896 has `async` keyword: `private async runPolicySynchronizationTest(`
   - Ensure all three methods are properly declared as private methods

### Phase 2: Fix Import Paths

3. **Fix rls-cls-tester import**
   - File: `dashboard-api/src/rls-cls/rls-cls.service.spec.ts`
   - Current: `'../../../services/rls-cls-tester'`
   - Fix: `'../../../../heimdall-framework/services/rls-cls-tester'`

4. **Fix policy-validation-tester import**
   - File: `dashboard-api/src/policy-validation/policy-validation.service.spec.ts`
   - Current: `'../../../services/policy-validation-tester'`
   - Fix: `'../../../../heimdall-framework/services/policy-validation-tester'`

5. **Fix identity-provider-tester import**
   - File: `dashboard-api/src/identity-providers/identity-provider.service.spec.ts`
   - Current: `'../../../services/identity-provider-tester'`
   - Check if file exists at `heimdall-framework/services/identity-provider-tester.ts`
   - Fix path or create mock if needed

6. **Fix dlp-tester import**
   - File: `dashboard-api/src/dlp/dlp.service.spec.ts`
   - Current: `'../../../services/dlp-tester'`
   - Check if file exists at `heimdall-framework/services/dlp-tester.ts`
   - Fix path or create mock if needed

### Phase 3: Fix Dependency Injection

7. **Add ApplicationDataService mock**
   - File: `dashboard-api/src/tests/tests.service.spec.ts`
   - Create mock ApplicationDataService with required methods
   - Add to test module providers array

### Phase 4: Fix Mock Issues

8. **Fix policies service mocks**
   - Ensure fs.readFile mock throws ENOENT before service initialization
   - Or mock loadPolicies/loadAuditLogs methods directly to prevent execution
   - May need to mock these methods before creating the service instance

### Phase 5: Verify and Test

9. **Run tests to verify fixes**
   - Run full test suite: `cd dashboard-api && npm test`
   - Verify compilation errors are resolved
   - Check that failing tests are now passing or have clearer error messages

## Files to Modify

1. `dashboard-api/src/tests/dto/create-test.dto.ts` - Remove duplicate applicationId
2. `heimdall-framework/core/test-harness.ts` - Verify/fix syntax error on line 896
3. `dashboard-api/src/rls-cls/rls-cls.service.spec.ts` - Fix import path
4. `dashboard-api/src/policy-validation/policy-validation.service.spec.ts` - Fix import path
5. `dashboard-api/src/identity-providers/identity-provider.service.spec.ts` - Fix import path or create mock
6. `dashboard-api/src/dlp/dlp.service.spec.ts` - Fix import path or create mock
7. `dashboard-api/src/tests/tests.service.spec.ts` - Add ApplicationDataService mock
8. `dashboard-api/src/policies/policies.service.spec.ts` - Improve mock setup

## Testing Strategy

- Fix one category at a time (compilation errors first)
- Run tests after each fix to verify progress
- Check for cascading errors from fixes
- Ensure no new failures are introduced

## Expected Outcomes

- All TypeScript compilation errors resolved
- All import path errors fixed
- All dependency injection issues resolved
- Test suite should compile and run (even if some tests still fail with clearer error messages)
- Reduction from 29 failed suites to significantly fewer

## Notes

- ApplicationDataService is optional in constructor but NestJS test module still requires it
- Some service tester files may not exist - will need to create mocks or verify actual file locations
- Policies service mocks may need more aggressive approach to prevent initialization-time execution
