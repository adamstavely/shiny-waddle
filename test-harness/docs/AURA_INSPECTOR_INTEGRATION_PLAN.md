# Aura Inspector Integration Plan

## Overview

This document outlines the plan to integrate [Google's aura-inspector](https://github.com/google/aura-inspector) tool into Heimdall as a Salesforce Experience Cloud security testing validator and test suite.

## Background

**aura-inspector** is a Python-based tool for testing Salesforce Experience Cloud applications. It discovers misconfigurations and security issues including:
- Accessible records from Guest and Authenticated contexts
- GraphQL Aura method enumeration
- Self-registration capabilities
- Record List component discovery
- Home URL discovery (unauthorized admin access)

## Integration Goals

1. **Create a Salesforce Experience Cloud Validator** - Integrate aura-inspector functionality as a Heimdall validator
2. **Add Test Type Support** - Extend Heimdall's test types to include Salesforce Experience Cloud testing
3. **Dashboard API Integration** - Expose aura-inspector functionality via REST API
4. **Frontend Support** - Add UI for configuring and viewing Salesforce Experience Cloud test results
5. **CI/CD Integration** - Enable automated testing in CI/CD pipelines

## Architecture

### Component Structure

```
test-harness/
├── services/
│   └── salesforce-experience-cloud-tester.ts    # Core service wrapping aura-inspector
├── validators/
│   └── salesforce-experience-cloud-validator.ts # Heimdall validator implementation
├── dashboard-api/src/
│   └── salesforce-experience-cloud/
│       ├── salesforce-experience-cloud.module.ts
│       ├── salesforce-experience-cloud.service.ts
│       ├── salesforce-experience-cloud.controller.ts
│       ├── dto/
│       │   └── salesforce-experience-cloud.dto.ts
│       └── entities/
│           └── salesforce-experience-cloud.entity.ts
└── dashboard-frontend/src/
    └── views/
        └── SalesforceExperienceCloud/
            └── [components for UI]
```

## Implementation Plan

### Phase 1: Core Service Implementation

#### 1.1 Create Python Wrapper Service
**File**: `services/salesforce-experience-cloud-tester.ts`

**Purpose**: TypeScript service that wraps aura-inspector Python tool execution

**Key Features**:
- Execute aura-inspector CLI commands via child process
- Parse JSON output from aura-inspector
- Map aura-inspector findings to Heimdall TestResult format
- Support both authenticated and unauthenticated contexts
- Handle errors and edge cases

**Configuration Interface**:
```typescript
export interface SalesforceExperienceCloudConfig {
  url: string;                    // Root URL of Salesforce application
  cookies?: string;                // Cookies for authenticated context
  outputDir?: string;              // Output directory for aura-inspector
  objectList?: string[];           // Specific objects to test
  app?: string;                    // Custom app path (e.g., /myApp)
  aura?: string;                   // Aura path (e.g., /aura)
  context?: string;                // Aura context
  token?: string;                  // Aura token
  useGraphQL?: boolean;            // Enable GraphQL checks
  proxy?: string;                  // Proxy configuration
  insecure?: boolean;              // Ignore TLS certificate validation
  auraRequestFile?: string;        // File with aura request for parsing
}
```

**Test Methods**:
1. `testGuestAccess()` - Test accessible records from Guest context
2. `testAuthenticatedAccess()` - Test accessible records from authenticated context
3. `testGraphQLCapability()` - Check GraphQL Aura method availability
4. `testSelfRegistration()` - Check for self-registration capabilities
5. `testRecordListComponents()` - Discover Record List components
6. `testHomeURLs()` - Discover Home URLs with admin access
7. `testObjectAccess()` - Test access to specific objects
8. `runFullAudit()` - Run complete aura-inspector audit

**Dependencies**:
- Python 3.x (system requirement)
- aura-inspector installed (via pipx or pip)
- Child process execution capability

#### 1.2 Create Validator Implementation
**File**: `validators/salesforce-experience-cloud-validator.ts`

**Purpose**: Heimdall validator that uses the service

**Implementation**:
- Extends `BaseValidator`
- Implements `runTestsInternal()` method
- Maps test suite configuration to aura-inspector config
- Converts aura-inspector results to Heimdall TestResult format
- Handles validation errors gracefully

**Test Type**: `'salesforce-experience-cloud'`

**Metadata**:
```typescript
{
  requiredConfig: ['url'],
  optionalConfig: ['cookies', 'objectList', 'app', 'aura'],
  tags: ['salesforce', 'experience-cloud', 'security'],
  exampleConfig: { ... }
}
```

### Phase 2: Type System Updates

#### 2.1 Update Core Types
**File**: `core/types.ts`

**Changes**:
- Add `'salesforce-experience-cloud'` to `TestType` union
- Add `'salesforce'` to `TestDomain` union (if not already present)
- Add Salesforce-specific configuration interfaces

#### 2.2 Update Test Suite Interface
Ensure test suites can specify Salesforce Experience Cloud test type and domain.

### Phase 3: Dashboard API Integration

#### 3.1 Create Module
**File**: `dashboard-api/src/salesforce-experience-cloud/salesforce-experience-cloud.module.ts`

**Purpose**: NestJS module for Salesforce Experience Cloud testing

**Exports**: Service, Controller

#### 3.2 Create Service
**File**: `dashboard-api/src/salesforce-experience-cloud/salesforce-experience-cloud.service.ts`

**Purpose**: NestJS service wrapping the core tester

**Methods**:
- `createConfig()` - Create test configuration
- `runTest()` - Execute single test
- `runFullAudit()` - Run complete audit
- `getResults()` - Retrieve test results
- `getConfigs()` - List configurations

**Data Storage**: JSON files in `data/` directory
- `salesforce-experience-cloud-configs.json`
- `salesforce-experience-cloud-results.json`

#### 3.3 Create Controller
**File**: `dashboard-api/src/salesforce-experience-cloud/salesforce-experience-cloud.controller.ts`

**Endpoints**:
- `POST /api/salesforce-experience-cloud/configs` - Create configuration
- `GET /api/salesforce-experience-cloud/configs` - List configurations
- `GET /api/salesforce-experience-cloud/configs/:id` - Get configuration
- `PATCH /api/salesforce-experience-cloud/configs/:id` - Update configuration
- `DELETE /api/salesforce-experience-cloud/configs/:id` - Delete configuration
- `POST /api/salesforce-experience-cloud/tests/guest-access` - Test guest access
- `POST /api/salesforce-experience-cloud/tests/authenticated-access` - Test authenticated access
- `POST /api/salesforce-experience-cloud/tests/graphql` - Test GraphQL capability
- `POST /api/salesforce-experience-cloud/tests/self-registration` - Test self-registration
- `POST /api/salesforce-experience-cloud/tests/record-lists` - Test record list components
- `POST /api/salesforce-experience-cloud/tests/home-urls` - Test home URLs
- `POST /api/salesforce-experience-cloud/tests/full-audit` - Run full audit
- `GET /api/salesforce-experience-cloud/results` - List test results
- `GET /api/salesforce-experience-cloud/results/:id` - Get test result

#### 3.4 Create DTOs
**File**: `dashboard-api/src/salesforce-experience-cloud/dto/salesforce-experience-cloud.dto.ts`

**DTOs**:
- `CreateSalesforceExperienceCloudConfigDto`
- `UpdateSalesforceExperienceCloudConfigDto`
- `RunGuestAccessTestDto`
- `RunAuthenticatedAccessTestDto`
- `RunGraphQLTestDto`
- `RunSelfRegistrationTestDto`
- `RunRecordListTestDto`
- `RunHomeURLTestDto`
- `RunFullAuditDto`

**Validation**: Use class-validator decorators

#### 3.5 Create Entities
**File**: `dashboard-api/src/salesforce-experience-cloud/entities/salesforce-experience-cloud.entity.ts`

**Entities**:
- `SalesforceExperienceCloudConfigEntity`
- `SalesforceExperienceCloudTestResultEntity`

#### 3.6 Register Module
**File**: `dashboard-api/src/app.module.ts`

Add `SalesforceExperienceCloudModule` to imports array.

### Phase 4: Frontend Integration

#### 4.1 Create Types
**File**: `dashboard-frontend/src/types/salesforce-experience-cloud.ts`

TypeScript interfaces matching API DTOs and entities.

#### 4.2 Create API Service
**File**: `dashboard-frontend/src/services/salesforce-experience-cloud.api.ts`

API client methods for all endpoints.

#### 4.3 Create Views
**Files**:
- `dashboard-frontend/src/views/SalesforceExperienceCloud/ConfigList.vue`
- `dashboard-frontend/src/views/SalesforceExperienceCloud/ConfigDetail.vue`
- `dashboard-frontend/src/views/SalesforceExperienceCloud/TestRunner.vue`
- `dashboard-frontend/src/views/SalesforceExperienceCloud/ResultsList.vue`
- `dashboard-frontend/src/views/SalesforceExperienceCloud/ResultDetail.vue`

#### 4.4 Add Routing
**File**: `dashboard-frontend/src/router/index.ts`

Add routes for Salesforce Experience Cloud views.

#### 4.5 Add Navigation
**File**: `dashboard-frontend/src/components/Navigation.vue` (or similar)

Add menu item for Salesforce Experience Cloud testing.

### Phase 5: Python Integration

#### 5.1 Python Execution Strategy

**Option A: Direct CLI Execution (Recommended for MVP)**
- Execute aura-inspector as subprocess
- Parse JSON output
- Handle errors and timeouts

**Option B: Python API Wrapper (Future Enhancement)**
- Create Python Flask/FastAPI service
- Expose REST API for aura-inspector functionality
- TypeScript service calls Python API

**Implementation for Option A**:
```typescript
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';

const execAsync = promisify(exec);

async function runAuraInspector(config: SalesforceExperienceCloudConfig): Promise<any> {
  const args = buildCLIArgs(config);
  const command = `aura_cli.py ${args.join(' ')}`;
  
  try {
    const { stdout, stderr } = await execAsync(command, {
      cwd: config.auraInspectorPath || './aura-inspector',
      timeout: config.timeout || 300000, // 5 minutes
    });
    
    // Parse output
    const outputFile = path.join(config.outputDir || './output', 'results.json');
    const results = await fs.readFile(outputFile, 'utf-8');
    return JSON.parse(results);
  } catch (error) {
    // Handle errors
  }
}
```

#### 5.2 Installation Requirements

**Documentation**:
- Add Python 3.x requirement to README
- Add aura-inspector installation instructions
- Add environment setup guide

**Docker Option** (Future):
- Create Docker image with Python and aura-inspector pre-installed
- Use Docker exec for aura-inspector execution

### Phase 6: Test Suite Creation

#### 6.1 Create Example Test Suite
**File**: `examples/salesforce-experience-cloud-usage.ts`

Example showing:
- Creating test configuration
- Running individual tests
- Running full audit
- Handling results

#### 6.2 Create Test Suite Templates
**File**: `test-harness/tests/salesforce-experience-cloud-suite.json`

JSON template for Salesforce Experience Cloud test suites.

### Phase 7: Documentation

#### 7.1 Update API Documentation
**File**: `docs/API.md`

Add section documenting Salesforce Experience Cloud endpoints.

#### 7.2 Update User Guide
**File**: `docs/USER_GUIDE.md`

Add section on Salesforce Experience Cloud testing.

#### 7.3 Create Service Documentation
**File**: `docs/SERVICES.md`

Add Salesforce Experience Cloud service documentation.

#### 7.4 Update README
**File**: `README.md`

Add Salesforce Experience Cloud to features list.

### Phase 8: Testing

#### 8.1 Unit Tests
**Files**:
- `services/salesforce-experience-cloud-tester.spec.ts`
- `validators/salesforce-experience-cloud-validator.spec.ts`

#### 8.2 Integration Tests
**File**: `dashboard-api/test/salesforce-experience-cloud.e2e-spec.ts`

E2E tests for all API endpoints.

#### 8.3 Manual Testing
- Test with real Salesforce Experience Cloud instance
- Verify all test types work correctly
- Test error handling

## Implementation Details

### Test Result Mapping

Map aura-inspector findings to Heimdall TestResult format:

```typescript
interface AuraInspectorFinding {
  type: 'guest_access' | 'authenticated_access' | 'graphql' | 'self_registration' | 'record_list' | 'home_url';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  details: any;
  objects?: string[];
  urls?: string[];
}

function mapToTestResult(finding: AuraInspectorFinding): TestResult {
  return {
    testType: 'salesforce-experience-cloud',
    testName: `${finding.type} - ${finding.description}`,
    passed: finding.severity === 'low', // Only low severity = pass
    details: {
      severity: finding.severity,
      description: finding.description,
      objects: finding.objects,
      urls: finding.urls,
      ...finding.details,
    },
    timestamp: new Date(),
    error: finding.severity !== 'low' ? finding.description : undefined,
  };
}
```

### Error Handling

Handle common errors:
- Python not installed
- aura-inspector not found
- Network errors
- Timeout errors
- Invalid configuration
- Authentication failures

### Security Considerations

- Never log sensitive cookies or tokens
- Sanitize output before storing
- Validate URLs before making requests
- Rate limit test executions
- Support proxy configuration for corporate networks

## Dependencies

### System Requirements
- Python 3.x
- aura-inspector (installed via pipx or pip)
- Node.js 18+ (existing requirement)

### NPM Packages
- No new packages required (use existing child_process, fs, path)

### Python Packages
- aura-inspector (installed separately)

## Timeline Estimate

- **Phase 1**: 2-3 days (Core service + validator)
- **Phase 2**: 0.5 days (Type updates)
- **Phase 3**: 2-3 days (Dashboard API)
- **Phase 4**: 2-3 days (Frontend)
- **Phase 5**: 1-2 days (Python integration)
- **Phase 6**: 1 day (Test suites)
- **Phase 7**: 1 day (Documentation)
- **Phase 8**: 2 days (Testing)

**Total**: ~12-16 days

## Future Enhancements

1. **Real-time Progress Updates** - Stream aura-inspector output in real-time
2. **Scheduled Audits** - Automatically run audits on schedule
3. **Comparison Reports** - Compare results across time periods
4. **Remediation Tracking** - Track fixes for discovered issues
5. **Integration with Salesforce APIs** - Direct API integration (beyond aura-inspector)
6. **Multi-Instance Support** - Test multiple Salesforce instances
7. **Custom Test Scripts** - Allow custom aura-inspector test scripts
8. **Docker Container** - Package aura-inspector in Docker for easier deployment

## Success Criteria

1. ✅ Can create Salesforce Experience Cloud test configurations via API
2. ✅ Can run all aura-inspector test types via API
3. ✅ Results are stored and queryable
4. ✅ Frontend displays configurations and results
5. ✅ Validator integrates with Heimdall test orchestration
6. ✅ Documentation is complete
7. ✅ Unit and E2E tests pass
8. ✅ Works with real Salesforce Experience Cloud instance

## Notes

- aura-inspector is a Python tool, so we'll need to execute it as a subprocess
- Consider creating a Python wrapper service in the future for better integration
- May need to handle different aura-inspector output formats
- Should support both authenticated and unauthenticated testing contexts
- Consider caching results to avoid redundant API calls
