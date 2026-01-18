# Test Hierarchy and Relationships

This document provides a comprehensive view of the test hierarchy from the smallest atomic unit (Test) to a Battery, and shows all relationships to policies and configurations.

## Hierarchy Overview

### Main Test Hierarchy

```
Test (Atomic Unit) - 1:1 with Policy
  ↓ (referenced by)
Test Suite (Collection of Tests)
  ↓ (referenced by)
Test Harness (Collection of Test Suites)
  ↓ (referenced by)
Test Battery (Collection of Test Harnesses)
```

### Application Infrastructure

**Infrastructure** is now part of **Application** registration. When you register an application, you define its infrastructure (databases, networks, APIs, etc.) as part of the application itself.

```
Application
  └── infrastructure: ApplicationInfrastructure
      ├── databases?: DatabaseInfrastructure[]
      ├── networkSegments?: NetworkSegmentInfrastructure[]
      ├── dlp?: DLPInfrastructure
      ├── apiGateway?: APIGatewayInfrastructure
      └── ... (other infrastructure types)
```

**Key Change:** Test Configurations have been **removed** and replaced with Application Infrastructure. Infrastructure is now owned by the Application, not a separate entity.

## 1. Test (Smallest Atomic Unit)

A **Test** is the smallest atomic unit in the system. It represents a single, executable test case.

### Base Test Interface

```typescript
interface BaseTest {
  id: string;                    // Unique identifier
  name: string;                   // Test name
  description?: string;           // Optional description
  testType: TestType;             // Type of test (see Test Types below)
  domain: TestDomain;             // Domain classification
  version: number;                // Version number
  versionHistory?: TestVersion[]; // Version tracking
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  lastModifiedBy?: string;
}
```

### Test Types

Tests can be one of the following types (each extends `BaseTest`):

1. **AccessControlTest** (`access-control`)
   - Tests RBAC/ABAC policies
   - **References Policies**: `policyIds: string[]`
   - Fields: `role`, `resource`, `context`, `expectedDecision`, `policyRuleId?`

2. **DatasetHealthTest** (`dataset-health`)
   - Tests privacy thresholds and statistical fidelity
   - Fields: `dataset`, `privacyThresholds?`, `statisticalFidelityTargets?`

3. **RLSCLSTest** (`rls-cls`)
   - Tests Row-Level Security and Column-Level Security
   - Fields: `database`, `testQuery`, `maskingRules?`

4. **NetworkPolicyTest** (`network-policy`)
   - Tests network firewall rules and segmentation
   - Fields: `source`, `target`, `protocol`, `port?`, `expectedAllowed`

5. **DLPTest** (`dlp`)
   - Tests Data Loss Prevention patterns and rules
   - Fields: `pattern?`, `testData?`, `bulkExportType?`, `piiDetectionRule?`, `customCheck?`

6. **APIGatewayTest** (`api-gateway`)
   - Tests API gateway policies
   - **References Policies**: `policyId?` (gateway policy)
   - Fields: `gatewayType`, `endpoint`, `method`, `policyType?`

7. **DistributedSystemsTest** (`distributed-systems`)
   - Tests multi-region and distributed system policies
   - Fields: `distributedTestType?`, `region?`, `regions?`

8. **APISecurityTest** (`api-security`)
   - Tests API versioning, webhooks, GraphQL, contracts
   - Fields: `apiVersion?`, `gatewayPolicy?`, `webhook?`, `graphql?`, `apiContract?`

9. **DataPipelineTest** (`data-pipeline`)
   - Tests data pipeline configurations
   - Fields: `pipelineType`, `dataSource?`, `dataDestination?`

### Test → Policy Relationships (1:1)

**1:1 Relationship:**
- **AccessControlTest**: `policyId: string` - **Required** - Exactly one policy (1:1 relationship)
- **APIGatewayTest**: `policyId: string` - **Required** - Exactly one gateway policy (1:1 relationship)
- **Other Test Types**: `policyId?: string` - **Optional** - Not all tests validate policies

**Key Changes:**
- Changed from `policyIds: string[]` (many-to-many) to `policyId: string` (1:1)
- Each test validates exactly one policy
- If a test needs to validate multiple policies, create separate tests (one per policy)

**Policy Loading:**
- Policies are loaded via `TestLoader.loadPolicy(policyId)` during execution
- Each test execution validates a single policy

### Test → Config Relationships

**Domain Configs:**
- Tests are classified by `domain: TestDomain` which maps to domain configurations
- Domain mapping: `getDomainFromTestType(testType)` → `TestDomain`

**Runtime Configs:**
- Tests can receive runtime configuration through their parent Test Suite
- Runtime configs provide environment-specific values (endpoints, database credentials, etc.)

**Infrastructure Configs:**
- Tests reference infrastructure via `applicationId` (for infrastructure-based tests like RLS/CLS)
- Infrastructure comes from `Application.infrastructure` (not from separate Test Configurations)
- Runtime config provides credentials/connection details, infrastructure provides what to test

## 2. Test Suite

A **Test Suite** is a collection of tests that share the same test type and domain.

### Test Suite Interface

```typescript
interface TestSuite {
  id: string;                      // Unique identifier
  name: string;                     // Suite name
  application: string;              // Application being tested
  team: string;                     // Team responsible
  testType: TestType;               // REQUIRED: Single test type (all tests must match)
  domain: TestDomain;               // REQUIRED: Domain classification
  testIds: string[];                // References to Test entities
  description?: string;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  
  // Runtime configuration (overrides hardcoded test values)
  runtimeConfig?: RuntimeTestConfig;
}
```

### Constraints

- **Single Test Type**: All tests in a suite must have the same `testType`
- **Domain Consistency**: All tests must belong to the same `domain`
- **Test References**: `testIds[]` references individual Test entities

### Test Suite → Test Relationships

- **One-to-Many**: One Test Suite contains many Tests
- **Reference**: `testIds: string[]` - Array of test IDs
- **Validation**: Tests are validated to ensure they match the suite's `testType`

### Test Suite → Config Relationships

**Runtime Configuration:**
```typescript
interface RuntimeTestConfig {
  applicationName?: string;
  baseUrl?: string;
  endpoints?: Record<string, string>;
  database?: DatabaseConfig;
  authentication?: AuthConfig;
  contexts?: Context[];
  environment?: string;
  regionConfigs?: RegionConfig[];
  endpointPatterns?: string[];
  [key: string]: any; // Custom config values
}
```

- **Runtime Config**: `runtimeConfig?: RuntimeTestConfig` - Environment-specific values
- **Purpose**: Allows tests to be environment-agnostic by providing runtime values
- **Override**: Runtime config values override hardcoded values in tests

**Domain Configs:**
- Test Suites inherit domain classification from their `domain` field
- Domain determines which domain-specific configurations apply

## 3. Test Harness

A **Test Harness** is a collection of test suites that share the same domain.

### Test Harness Interface

```typescript
interface TestHarness {
  id: string;                      // Unique identifier
  name: string;                     // Harness name
  description: string;
  domain: TestDomain;               // REQUIRED: All suites must have this domain
  testSuiteIds: string[];          // References to Test Suite entities
  applicationIds: string[];         // Assigned to applications (many-to-many)
  team?: string;
  createdAt: Date;
  updatedAt: Date;
  
  // Deprecated (kept for backward compatibility)
  testType?: TestType;              // Use domain instead
}
```

### Constraints

- **Domain Consistency**: All test suites in a harness must have the same `domain`
- **Many-to-Many**: Test suites can belong to multiple harnesses
- **Application Assignment**: Harnesses can be assigned to multiple applications

### Test Harness → Test Suite Relationships

- **Many-to-Many**: Test Suites can belong to multiple Harnesses
- **Reference**: `testSuiteIds: string[]` - Array of test suite IDs
- **Validation**: All suites must match the harness's `domain`

### Test Harness → Application Relationships

- **Many-to-Many**: Harnesses can be assigned to multiple Applications
- **Reference**: `applicationIds: string[]` - Array of application IDs
- **Purpose**: Allows reuse of test harnesses across applications

### Test Harness → Config Relationships

**Domain Configs:**
- Harnesses are classified by `domain: TestDomain`
- Domain determines which domain-specific configurations apply to all suites in the harness

**No Direct Runtime Config:**
- Harnesses do not have their own runtime config
- Runtime configs are defined at the Test Suite level

## 4. Test Battery

A **Test Battery** is a collection of test harnesses with different test types/domains.

### Test Battery Interface

```typescript
interface TestBattery {
  id: string;                      // Unique identifier
  name: string;                    // Battery name
  description?: string;
  harnessIds: string[];            // References to Test Harness entities
  executionConfig?: BatteryExecutionConfig;
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}

interface BatteryExecutionConfig {
  executionMode: 'parallel' | 'sequential';
  timeout?: number;
  stopOnFailure?: boolean;
}
```

### Constraints

- **Different Types**: All harnesses in a battery must have different test types
- **Domain Diversity**: Batteries typically contain harnesses from different domains
- **Execution Control**: Batteries control how harnesses are executed

### Test Battery → Test Harness Relationships

- **One-to-Many**: One Test Battery contains many Test Harnesses
- **Reference**: `harnessIds: string[]` - Array of harness IDs
- **Validation**: Ensures all harnesses have different types

### Test Battery → Config Relationships

**Execution Configuration:**
```typescript
interface BatteryExecutionConfig {
  executionMode: 'parallel' | 'sequential';
  timeout?: number;
  stopOnFailure?: boolean;
}
```

- **Execution Config**: Controls how harnesses are executed
- **Parallel vs Sequential**: Determines execution order
- **Timeout**: Optional timeout for battery execution
- **Stop on Failure**: Whether to stop execution if a harness fails

## Complete Relationship Diagram

### Main Test Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                         Test Battery                             │
│  - id, name, description                                         │
│  - harnessIds: string[]                                         │
│  - executionConfig: BatteryExecutionConfig                      │
└────────────────────────────┬────────────────────────────────────┘
                              │ (1:N)
                              │ harnessIds[]
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Test Harness                              │
│  - id, name, description                                        │
│  - domain: TestDomain                                           │
│  - testSuiteIds: string[]                                       │
│  - applicationIds: string[] (many-to-many)                      │
└────────────────────────────┬────────────────────────────────────┘
                              │ (N:M)
                              │ testSuiteIds[]
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Test Suite                              │
│  - id, name, application, team                                  │
│  - testType: TestType (single)                                  │
│  - domain: TestDomain                                           │
│  - testIds: string[]                                            │
│  - testConfigurationIds?: string[] (many-to-many)              │
│  - runtimeConfig?: RuntimeTestConfig                            │
└────────────┬───────────────────────────────┬────────────────────┘
             │ (1:N)                          │ (N:M)
             │ testIds[]                       │ testConfigurationIds[]
             ▼                                 ▼
┌──────────────────────────────────┐  ┌─────────────────────────────────┐
│            Test                  │  │   Test Configuration              │
│  - id, name, description        │  │  - id, name, type               │
│  - testType: TestType           │  │  - type: TestConfigurationType   │
│  - domain: TestDomain           │  │  - enabled: boolean             │
│  - version: number              │  │  - (type-specific fields)        │
│  - policyIds?: string[]         │  │                                  │
│  - policyId?: string            │  │  Can be executed independently   │
└────────────┬────────────────────┘  └─────────────────────────────────┘
             │ (N:M)
             │ policyIds[]
             ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Policies                               │
│  - ABAC Policies (for AccessControlTest)                        │
│  - RBAC Policies (for AccessControlTest)                        │
│  - Gateway Policies (for APIGatewayTest)                         │
└─────────────────────────────────────────────────────────────────┘
```

### Test Configuration Relationships

```
┌─────────────────────────────────────────────────────────────────┐
│                      Application                                │
│  - id, name, type                                               │
│  - testConfigurationIds: string[] (many-to-many)                │
│  - testConfigurationOverrides?: Record<string, Override>       │
└────────────────────────────┬────────────────────────────────────┘
                              │ (N:M)
                              │ testConfigurationIds[]
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Test Configuration                           │
│  - id, name, type                                               │
│  - type: 'rls-cls' | 'network-policy' | 'dlp' | ...           │
│  - enabled: boolean                                             │
│  - (type-specific configuration fields)                         │
│                                                                 │
│  Can be executed independently via:                            │
│  POST /api/test-configurations/:id/test                        │
└────────────────────────────┬────────────────────────────────────┘
                              │ (N:M)
                              │ testConfigurationIds[]
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Test Suite                              │
│  - testConfigurationIds?: string[]                              │
│  - runtimeConfig?: RuntimeTestConfig                            │
│                                                                 │
│  When Test Suite references Test Configuration:                 │
│  - Test Configuration uses Test Suite's runtimeConfig           │
│  - Test Configuration is executed as part of suite              │
└─────────────────────────────────────────────────────────────────┘
```

## Policy Relationships Summary

### Direct Policy References

1. **AccessControlTest → Policies**
   - `policyIds: string[]` - References ABAC/RBAC policies
   - Policies are loaded during test execution via `TestLoader.loadPolicies()`
   - Policies are evaluated by the Policy Decision Point (PDP)

2. **APIGatewayTest → Policies**
   - `policyId?: string` - References gateway policies
   - Gateway policies define authentication, authorization, rate limiting, etc.

### Policy Loading Flow

```
Test Execution
  ↓
Load Test (by testId)
  ↓
Check if test has policyIds
  ↓
Load Policies (via TestLoader.loadPolicies(policyIds))
  ↓
Configure Tester with Policies
  ↓
Execute Test with Policies
```

## Config Relationships Summary

### Runtime Configuration

**Location**: Test Suite level
**Purpose**: Environment-specific values
**Structure**: `RuntimeTestConfig`

```typescript
interface RuntimeTestConfig {
  applicationName?: string;        // Application being tested
  baseUrl?: string;                // API base URL
  endpoints?: Record<string, string>; // Named endpoints
  database?: DatabaseConfig;       // Database connection
  authentication?: AuthConfig;     // Auth credentials
  contexts?: Context[];            // Test contexts
  environment?: string;            // Environment name
  regionConfigs?: RegionConfig[];  // Multi-region configs
  endpointPatterns?: string[];    // Endpoint patterns
  [key: string]: any;             // Custom values
}
```

**Flow**: Runtime config is merged into Test Suite before execution, overriding hardcoded test values.

### Domain Configuration

**Location**: Domain level (applies to all entities in domain)
**Purpose**: Domain-specific settings
**Mapping**: `TestType` → `TestDomain` → Domain Config

**Domain Mapping:**
- `api-security`, `api-gateway` → `api_security`
- `network-policy`, `distributed-systems` → `platform_config`
- `access-control`, `rls-cls` → `identity`
- `data-contract`, `data-pipeline`, `dlp`, `dataset-health` → `data_contracts`
- `salesforce-config`, `salesforce-security` → `salesforce`
- `elastic-config`, `elastic-security` → `elastic`
- `k8s-security`, `k8s-workload`, `idp-compliance` → `idp_platform`

### Execution Configuration

**Location**: Test Battery level
**Purpose**: Control how harnesses are executed
**Structure**: `BatteryExecutionConfig`

```typescript
interface BatteryExecutionConfig {
  executionMode: 'parallel' | 'sequential';
  timeout?: number;
  stopOnFailure?: boolean;
}
```

## Example: Complete Flow

### Example 1: Access Control Test Flow

```
1. Test Battery: "Production Compliance Battery"
   └─ executionConfig: { executionMode: 'sequential', stopOnFailure: true }

2. Test Harness: "Identity Access Control Harness"
   └─ domain: 'identity'
   └─ testSuiteIds: ['suite-access-control-1', 'suite-access-control-2']

3. Test Suite: "Admin Access Control Suite"
   └─ testType: 'access-control'
   └─ domain: 'identity'
   └─ testIds: ['test-admin-read', 'test-admin-write', 'test-viewer-read']
   └─ runtimeConfig: {
        baseUrl: 'https://api.prod.example.com',
        authentication: { type: 'bearer', credentials: { token: '...' } }
      }

4. Test: "test-admin-read"
   └─ testType: 'access-control'
   └─ domain: 'identity'
   └─ policyIds: ['policy-abac-department-match', 'policy-rbac-admin']
   └─ role: 'admin'
   └─ resource: { id: 'dataset-1', type: 'dataset', sensitivity: 'confidential' }
   └─ expectedDecision: true

5. Policies:
   └─ policy-abac-department-match: { effect: 'allow', conditions: [...] }
   └─ policy-rbac-admin: { effect: 'allow', role: 'admin' }
```

### Example 2: API Security Test Flow

```
1. Test Battery: "API Security Battery"
   └─ executionConfig: { executionMode: 'parallel' }

2. Test Harness: "API Security Harness"
   └─ domain: 'api_security'
   └─ testSuiteIds: ['suite-api-versioning', 'suite-api-gateway']

3. Test Suite: "API Gateway Policy Suite"
   └─ testType: 'api-security'
   └─ domain: 'api_security'
   └─ testIds: ['test-rate-limit', 'test-auth-policy']
   └─ testConfigurationIds: ['config-api-gateway-prod']  // References Test Configuration
   └─ runtimeConfig: {
        baseUrl: 'https://api.prod.example.com',
        endpoints: { users: '/api/v1/users', admin: '/api/v1/admin' }
      }

4. Test: "test-rate-limit"
   └─ testType: 'api-security'
   └─ domain: 'api_security'
   └─ gatewayPolicy: {
        gatewayType: 'aws-api-gateway',
        endpoint: '/api/v1/users',
        method: 'GET',
        policyId: 'policy-rate-limit-100-per-minute',
        policyType: 'rate-limit'
      }

5. Test Configuration: "config-api-gateway-prod"
   └─ type: 'api-gateway'
   └─ rateLimitConfig: { defaultLimit: 100, defaultTimeWindow: 60 }
   └─ gatewayPolicies: [...]
   └─ Uses Test Suite's runtimeConfig when executed via suite

6. Policy:
   └─ policy-rate-limit-100-per-minute: { maxRequests: 100, windowSeconds: 60 }
```

### Example 3: Test Configuration Flow (Independent Execution)

```
1. Application: "My Application"
   └─ testConfigurationIds: ['config-rls-prod', 'config-dlp-prod']

2. Test Configuration: "config-rls-prod"
   └─ type: 'rls-cls'
   └─ database: {
        type: 'postgresql',
        host: 'db.prod.example.com',
        port: 5432,
        database: 'myapp'
      }
   └─ testQueries: [...]
   └─ validationRules: { minRLSCoverage: 80 }

3. Execution:
   └─ Can be executed independently: POST /api/test-configurations/config-rls-prod/test
   └─ OR executed as part of Test Suite that references it
   └─ When executed via Test Suite, uses Test Suite's runtimeConfig
```

### Example 4: Test Configuration via Test Suite

```
1. Test Suite: "RLS Compliance Suite"
   └─ testType: 'rls-cls'
   └─ domain: 'identity'
   └─ testIds: ['test-rls-coverage', 'test-cross-tenant']
   └─ testConfigurationIds: ['config-rls-prod']  // References Test Configuration
   └─ runtimeConfig: {
        database: {
          host: 'db.prod.example.com',  // Overrides Test Configuration's database.host
          username: 'test_user',
          password: '***'  // Runtime credentials
        }
      }

2. Test Configuration: "config-rls-prod"
   └─ type: 'rls-cls'
   └─ database: {
        type: 'postgresql',
        host: 'db.prod.example.com',  // Base config
        port: 5432
      }
   └─ testQueries: [...]
   └─ When executed via Test Suite:
      - Uses Test Suite's runtimeConfig for database credentials
      - Merges Test Configuration's database config with runtimeConfig
```

## Key Constraints and Rules

### Type Consistency Rules

1. **Test Suite**: All tests must have the same `testType` as the suite
2. **Test Harness**: All test suites must have the same `domain` as the harness
3. **Test Battery**: All harnesses must have different test types
4. **Test Configuration**: Must have a valid `type` that matches one of the supported configuration types

### Domain Mapping Rules

- Each `TestType` maps to exactly one `TestDomain`
- Domain is automatically derived from test type using `getDomainFromTestType()`
- Domain determines which domain-specific configurations apply
- **Test Configuration Types** map to test types (e.g., `rls-cls` config → `rls-cls` test type)

### Policy Reference Rules

1. **AccessControlTest**: Must reference policies via `policyIds[]`
2. **APIGatewayTest**: May reference gateway policy via `policyId?`
3. **Other Test Types**: Do not directly reference policies
4. **Test Configurations**: Do not directly reference policies (policies are referenced by Tests)

### Config Inheritance Rules

1. **Runtime Config**: Defined at Test Suite level, applies to all tests in suite
2. **Domain Config**: Applies to all entities (tests, suites, harnesses) in domain
3. **Execution Config**: Defined at Test Battery level, controls harness execution
4. **Test Configuration**: 
   - Can be executed independently (uses its own embedded config)
   - When executed via Test Suite, uses Test Suite's `runtimeConfig` (merged with Test Configuration's config)

### Test Configuration Rules

1. **Many-to-Many Relationships**:
   - Applications ↔ Test Configurations: Many-to-many via `testConfigurationIds`
   - Test Suites ↔ Test Configurations: Many-to-many via `testConfigurationIds`

2. **Execution Modes**:
   - **Independent**: Test Configuration can be executed directly via API endpoint
   - **Via Test Suite**: Test Configuration is executed as part of Test Suite execution
   - **Via Application**: Test Configuration can be assigned to Application for testing

3. **Config Merging**:
   - When Test Configuration is executed via Test Suite, Test Suite's `runtimeConfig` takes precedence
   - Test Configuration's embedded config values are used as defaults
   - Application's `testConfigurationOverrides` can override Test Configuration settings

## 5. Application Infrastructure

**Infrastructure** is now part of **Application** registration. When you register an application, you define its infrastructure (databases, networks, APIs, etc.) as part of the application itself.

### Application Infrastructure Interface

```typescript
interface ApplicationInfrastructure {
  // Database infrastructure
  databases?: DatabaseInfrastructure[];
  
  // Network infrastructure
  networkSegments?: NetworkSegmentInfrastructure[];
  
  // DLP infrastructure
  dlp?: DLPInfrastructure;
  
  // API Gateway infrastructure
  apiGateway?: APIGatewayInfrastructure;
  
  // Distributed Systems infrastructure
  distributedSystems?: DistributedSystemsInfrastructure;
  
  // API Security infrastructure
  apiSecurity?: APISecurityInfrastructure;
  
  // Data Pipeline infrastructure
  dataPipeline?: DataPipelineInfrastructure;
}
```

### Infrastructure Types

1. **DatabaseInfrastructure** (`databases[]`)
   - Database RLS/CLS configuration
   - Fields: `id`, `name`, `type`, `host`, `port`, `database`, `testQueries?`, `maskingRules?`, `validationRules?`, `testLogic?`

2. **NetworkSegmentInfrastructure** (`networkSegments[]`)
   - Network firewall and segmentation configuration
   - Fields: `id`, `name`, `cidr?`, `firewallRules?`, `serviceMeshConfig?`, `testLogic?`

3. **DLPInfrastructure** (`dlp`)
   - Data Loss Prevention configuration
   - Fields: `patterns?`, `bulkExportLimits?`, `piiDetectionRules?`, `exportRestrictions?`, `aggregationRequirements?`, `fieldRestrictions?`, `joinRestrictions?`, `testLogic?`

4. **APIGatewayInfrastructure** (`apiGateway`)
   - API Gateway policies and rate limiting
   - Fields: `rateLimitConfig?`, `serviceAuthConfig?`, `gatewayPolicies?`, `testLogic?`

5. **DistributedSystemsInfrastructure** (`distributedSystems`)
   - Multi-region and distributed system configuration
   - Fields: `regions`, `policySync?`, `coordination?`, `testLogic?`

6. **APISecurityInfrastructure** (`apiSecurity`)
   - API security testing configuration
   - Fields: `baseUrl`, `authentication?`, `rateLimitConfig?`, `endpoints?`, `testLogic?`

7. **DataPipelineInfrastructure** (`dataPipeline`)
   - Data pipeline configuration
   - Fields: `pipelineType`, `connection?`, `dataSource?`, `dataDestination?`, `testLogic?`

### Application → Infrastructure Relationship

- **Ownership**: Infrastructure is **owned** by the Application (not referenced)
- **Location**: `Application.infrastructure: ApplicationInfrastructure`
- **Purpose**: Defines what infrastructure the application has (databases, networks, APIs, etc.)
- **Registration**: Infrastructure is defined when the application is registered

### Infrastructure vs Runtime Config

**Key Differences:**

| Aspect | Infrastructure | Runtime Config |
|-------|----------------|----------------|
| **Location** | Part of Application | Part of Test Suite |
| **Purpose** | What infrastructure exists | How to connect to infrastructure |
| **Scope** | Infrastructure definition | Environment-specific values |
| **Examples** | Database host, network segments | Database credentials, API keys |
| **Ownership** | Owned by Application | Owned by Test Suite |
| **Changes** | Relatively static | Changes per environment |

**Infrastructure** defines **what infrastructure** the application has (e.g., "PostgreSQL database at db.prod.example.com").
**Runtime Config** defines **how to connect** to that infrastructure (e.g., username, password, API keys).

### Infrastructure → Test Suite Relationship

- **Automatic**: Test Suites automatically have access to infrastructure via `suite.application`
- **No Reference Needed**: Test Suites don't need to reference infrastructure - it comes from the application
- **Usage**: Tests can reference infrastructure via `applicationId` and `databaseId` (for RLS/CLS tests)

### Migration from Test Configurations

**Previous Model (Deprecated):**
- Test Configurations were separate entities
- Applications referenced them via `testConfigurationIds`
- Test Suites referenced them via `testConfigurationIds`

**New Model:**
- Infrastructure is part of Application
- No separate Test Configuration entity
- Infrastructure is automatically available to Test Suites via the application

## Summary

### Main Hierarchy

- **Test**: Atomic unit, **1:1 with Policy** (`policyId`), has testType and domain
- **Test Suite**: Collection of tests (same type), has runtimeConfig, infrastructure comes from application
- **Test Harness**: Collection of suites (same domain), assigned to applications
- **Test Battery**: Collection of harnesses (different types), has executionConfig

### Application Infrastructure

- **Infrastructure**: Part of Application registration (`Application.infrastructure`)
- **Ownership**: Infrastructure is owned by Application (not a separate entity)
- **Purpose**: Defines what infrastructure the application has (databases, networks, APIs, etc.)
- **Access**: Test Suites automatically have access via `suite.application`

### Policy Relationships (1:1)

- **Test ↔ Policy**: **1:1 relationship** - Each test validates exactly one policy
- **AccessControlTest**: `policyId: string` (required)
- **APIGatewayTest**: `policyId: string` (required)
- **Other Tests**: `policyId?: string` (optional - not all tests validate policies)
- **Loading**: Policies loaded via `TestLoader.loadPolicy(policyId)` during execution

### Config Relationships

**Runtime Config:**
- Tests → Runtime Config: Inherited from Test Suite
- Suites → Runtime Config: Direct ownership
- Purpose: Environment-specific values (credentials, endpoints, API keys)

**Infrastructure Config:**
- Applications → Infrastructure: Direct ownership (`Application.infrastructure`)
- Test Suites → Infrastructure: Automatic access via `suite.application`
- Purpose: Infrastructure definition (what databases, networks, APIs exist)

**Domain Config:**
- Tests → Domain Config: Via domain classification
- Infrastructure → Domain Config: Via infrastructure type → test type → domain mapping

**Execution Config:**
- Batteries → Execution Config: Direct ownership
- Purpose: Control how harnesses are executed (parallel/sequential, timeout, stop on failure)