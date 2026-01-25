# Test Creation Guide

This guide explains how to create test suites for TestOrchestrator. You'll learn how to define test scenarios, configure test data, and validate access control policies.

## Table of Contents

1. [Understanding Tests and Policies](#understanding-tests-and-policies)
2. [Test Suite Overview](#test-suite-overview)
3. [Creating a Test Suite](#creating-a-test-suite)
4. [Test Types](#test-types)
   - [Access Control Tests](#1-access-control-tests)
   - [Dataset Health Tests](#2-dataset-health-tests)
   - [Platform Configuration Tests](#3-platform-configuration-tests)
   - [Distributed Systems Tests](#4-distributed-systems-tests)
5. [Configuration Reference](#configuration-reference)
6. [Best Practices](#best-practices)
7. [Examples](#examples)

## Understanding Tests and Policies

### The Policy-Test Relationship

**Key Concept**: Each test validates exactly one policy (1:1 relationship).

- **One Policy** → Can have **multiple tests** (test different scenarios)
- **One Test** → Validates **exactly one policy** (via `policyId`)

### Workflow: Template → Policy → Test

The typical workflow is:

```
Template → Policies → Tests → Test Execution → Results
```

1. **Create Policies**: Use [Policy Templates](./TEMPLATE_GUIDE.md) or manually create policies
2. **Create Tests**: For each policy, create tests that validate different scenarios
3. **Group Tests**: Organize tests into test suites
4. **Run Tests**: Execute test suites to validate policies work correctly

### Example: Testing a Policy

If you have a policy that allows `admin` role to read `dataset` resources:

```typescript
// Policy: "Admin can read datasets"
{
  id: "policy-1",
  name: "Admin Dataset Read",
  effect: "allow",
  conditions: [
    { attribute: "subject.role", operator: "equals", value: "admin" },
    { attribute: "resource.type", operator: "equals", value: "dataset" }
  ]
}

// Test 1: Verify admin CAN read (positive test)
{
  name: "Admin can read dataset",
  testType: "access-control",
  policyId: "policy-1", // ← Links to the policy
  inputs: {
    subject: { role: "admin" },
    resource: { type: "dataset", id: "ds-123" },
    action: "read"
  },
  expected: { allowed: true } // Should allow
}

// Test 2: Verify non-admin CANNOT read (negative test)
{
  name: "User cannot read dataset",
  testType: "access-control",
  policyId: "policy-1", // ← Same policy
  inputs: {
    subject: { role: "user" }, // Different role
    resource: { type: "dataset", id: "ds-123" },
    action: "read"
  },
  expected: { allowed: false } // Should deny
}
```

### Testing Template-Generated Policies

If you create policies from templates (recommended), see the [Template Guide](./TEMPLATE_GUIDE.md#testing-template-generated-policies) for detailed instructions on creating tests for template-generated policies.

**Quick Example:**
```bash
# 1. Create policies from template
heimdall template create rbac \
  --application-name "MyApp" \
  --roles admin,user \
  --resources dataset \
  --actions read

# 2. Create tests for the generated policies
# (See TEMPLATE_GUIDE.md for details)
```

## Test Suite Overview

A test suite defines:
- **What to test**: Which types of tests to run (access control, contracts, dataset health)
- **Who to test**: User roles and attributes to simulate
- **What resources**: Resources to test access against
- **How to test**: Test queries, expected behaviors, and validation rules

### Test Suite Structure

Each test suite must have exactly one test type. The structure varies based on the test type:

```typescript
// Access Control Test Suite
interface AccessControlTestSuite {
  name: string;
  application: string;
  team: string;
  testType: 'access-control';      // Required: single test type
  userRoles: string[];
  resources: Resource[];
  contexts: Context[];
  expectedDecisions?: Record<string, boolean>;
}

// Other test types follow similar pattern with type-specific fields
```

## Creating a Test Suite

### Step 1: Create Test Suite File

Create a TypeScript or JSON file in `tests/suites/` directory:

**TypeScript** (`tests/suites/my-test-suite.ts`):
```typescript
import { TestSuite } from '../../core/types';

export const myTestSuite: TestSuite = {
  name: 'My Application Tests',
  // ... configuration
};
```

**JSON** (`tests/suites/my-test-suite.json`):
```json
{
  "name": "My Application Tests",
  "application": "my-app",
  "team": "my-team",
  // ... configuration
}
```

### Step 2: Define Basic Information

```typescript
{
  name: 'My Application Compliance Tests',
  application: 'my-application',
  team: 'platform-team',
  // ...
}
```

### Step 3: Link Tests to Policies

For access control tests, each test must reference a policy via `policyId`:

```typescript
{
  testIds: [
    "test-1", // References policy-1
    "test-2", // References policy-2
    // ...
  ]
}

// Each test has:
{
  id: "test-1",
  name: "Admin can read dataset",
  testType: "access-control",
  policyId: "policy-1", // ← Required: links test to policy
  inputs: { /* ... */ },
  expected: { /* ... */ }
}
```

**Important**: When creating tests, you must have policies created first. See [POLICY_CREATION_GUIDE.md](./POLICY_CREATION_GUIDE.md) or [TEMPLATE_GUIDE.md](./TEMPLATE_GUIDE.md) for creating policies.

### Step 4: Configure Test Types

Enable the test types you want to run:

```typescript
{
  testType: "access-control", // Single test type per suite
  // ...
}
```

### Step 4: Define User Roles

Specify which roles to test:

```typescript
{
  userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
  // ...
}
```

### Step 5: Define Resources

Create resources to test access against:

```typescript
{
  resources: [
    {
      id: 'resource-1',
      type: 'dataset',
      attributes: {
        sensitivity: 'internal',
        department: 'Research',
      },
      sensitivity: 'internal',
      // ABAC attributes (optional)
      abacAttributes: {
        dataClassification: 'internal',
        department: 'Research',
        project: 'project-alpha',
      },
    },
    // ... more resources
  ],
  // ...
}
```

### Step 6: Define Contexts

Specify contexts to test (IP address, time, location):

```typescript
{
  contexts: [
    {
      ipAddress: '192.168.1.1',
      timeOfDay: '14:00',
      location: 'headquarters',
    },
    {
      ipAddress: '10.0.0.1',
      timeOfDay: '22:00',
      location: 'remote',
    },
  ],
  // ...
}
```

## Test Types

### 1. Access Control Tests

Tests Policy Decision Point (PDP) decisions for different user/resource/context combinations.

#### Configuration

```typescript
{
  includeAccessControlTests: true,
  userRoles: ['admin', 'researcher', 'viewer'],
  resources: [
    {
      id: 'public-data',
      type: 'dataset',
      attributes: { sensitivity: 'public' },
      sensitivity: 'public',
    },
    {
      id: 'restricted-data',
      type: 'dataset',
      attributes: { sensitivity: 'restricted' },
      sensitivity: 'restricted',
    },
  ],
  contexts: [
    { ipAddress: '192.168.1.1', timeOfDay: '14:00' },
  ],
  expectedDecisions: {
    'admin-public-data': true,        // Admin should access public
    'viewer-restricted-data': false,   // Viewer should NOT access restricted
  },
}
```

#### Expected Decisions

Map of `"role-resourceId"` to expected boolean:

```typescript
expectedDecisions?: {
  'admin-resource-1': true,
  'viewer-resource-1': false,
  'researcher-resource-2': true,
}
```

### 2. Dataset Health Tests

Tests that masked/synthetic datasets meet privacy thresholds and statistical fidelity.

#### Configuration

```typescript
{
  includeDatasetHealthTests: true,
  datasets: [
    {
      name: 'masked-users',
      type: 'masked',
      schema: {
        id: 'string',
        email_masked: 'string',
        name: 'string',
        age: 'number',
      },
      recordCount: 1000,
      piiFields: ['email_masked'],
    },
  ],
  privacyThresholds: [
    {
      metric: 'k-anonymity',
      threshold: 10,
      operator: '>=',
    },
    {
      metric: 'l-diversity',
      threshold: 3,
      operator: '>=',
    },
  ],
  statisticalFidelityTargets: [
    {
      field: 'age',
      metric: 'mean',
      targetValue: 35.5,
      tolerance: 2.0,
    },
    {
      field: 'age',
      metric: 'stddev',
      targetValue: 12.3,
      tolerance: 1.0,
    },
  ],
}
```

#### Dataset Structure

```typescript
interface Dataset {
  name: string;
  type: 'raw' | 'masked' | 'synthetic';
  schema: any;
  recordCount?: number;
  piiFields?: string[];
}
```

#### Privacy Thresholds

```typescript
privacyThresholds?: PrivacyThreshold[];

interface PrivacyThreshold {
  metric: 'k-anonymity' | 'l-diversity' | 't-closeness' | 'differential-privacy';
  threshold: number;
  operator: '>' | '<' | '>=' | '<=' | '=';
}
```

#### Statistical Fidelity Targets

```typescript
statisticalFidelityTargets?: StatisticalFidelityTarget[];

interface StatisticalFidelityTarget {
  field: string;
  metric: 'mean' | 'median' | 'stddev' | 'distribution';
  targetValue?: number;
  tolerance?: number;
}
```

### 3. Platform Configuration Tests

Tests that validate platform instances (Salesforce, Elastic, Kubernetes, ServiceNow) against desired baseline configurations.

#### Overview

Platform configuration tests validate that live platform instances match your desired baseline configuration. The baseline defines the "golden state" that all instances should conform to.

**Key Concepts:**
- **Baseline Configuration**: The desired state configuration (e.g., encryption settings, security policies)
- **Platform Instance**: The live system being validated (stored as an Application)
- **Validation Rules**: Tests that compare instance config against baseline (auto-generated or custom)

#### Configuration

```typescript
{
  testType: 'salesforce-config',  // or 'elastic-config', 'idp-compliance', etc.
  application: 'production-salesforce-org',  // Platform instance (Application)
  team: 'platform-team',
  baselineConfig: {
    platform: 'salesforce',
    environment: 'production',
    version: '1.0',
    config: {
      encryption: {
        enabled: true,
        fieldEncryption: {
          enabled: true,
          algorithm: 'AES-256'
        },
        platformEncryption: {
          enabled: true
        }
      },
      fieldLevelSecurity: {
        enforced: true,
        requireMFA: true
      },
      sharingRules: {
        externalSharingEnabled: false,
        publicGroupsRestricted: true
      },
      auditLogging: {
        enabled: true,
        retentionDays: 90
      }
    }
  }
}
```

#### Supported Platform Test Types

- `salesforce-config` - Salesforce configuration validation
- `salesforce-security` - Salesforce security settings
- `elastic-config` - Elasticsearch configuration
- `elastic-security` - Elasticsearch security
- `k8s-security` - Kubernetes security policies
- `k8s-workload` - Kubernetes workload configuration
- `idp-compliance` - Identity Provider compliance
- `servicenow-config` - ServiceNow configuration

#### Baseline Configuration Structure

```typescript
interface BaselineConfig {
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes' | 'servicenow';
  environment: string;  // 'production', 'staging', 'development'
  version: string;      // e.g., '1.0', '2.1'
  config: Record<string, any>;  // Platform-specific configuration structure
}
```

#### Defining Baseline Elements

**Via UI (Test Suite Builder):**

1. Select a platform config test type (e.g., `salesforce-config`)
2. Navigate to the "Baseline Config" tab
3. Select Platform, Environment, and Version
4. Enter configuration JSON in the textarea:

```json
{
  "encryption": {
    "enabled": true,
    "fieldEncryption": {
      "enabled": true
    }
  },
  "fieldLevelSecurity": {
    "enforced": true
  }
}
```

**Via TypeScript/JSON:**

```typescript
import { TestSuite } from '../../core/types';

export const salesforceBaselineSuite: TestSuite = {
  name: 'Salesforce HIPAA Baseline',
  application: 'prod-salesforce-org',
  team: 'compliance-team',
  testType: 'salesforce-config',
  domain: 'platform_config',
  baselineConfig: {
    platform: 'salesforce',
    environment: 'production',
    version: '1.0',
    config: {
      encryption: {
        enabled: true,
        fieldEncryption: { enabled: true }
      },
      // ... more config
    }
  },
  testIds: [],  // Tests will be auto-generated from baseline config
  enabled: true,
  createdAt: new Date(),
  updatedAt: new Date()
};
```

#### Platform-Specific Configuration Examples

**Salesforce:**
```json
{
  "encryption": {
    "enabled": true,
    "fieldEncryption": { "enabled": true },
    "platformEncryption": { "enabled": true }
  },
  "fieldLevelSecurity": {
    "enforced": true,
    "requireMFA": true
  },
  "sharingRules": {
    "externalSharingEnabled": false
  }
}
```

**Elasticsearch:**
```json
{
  "security": {
    "enabled": true,
    "ssl": {
      "enabled": true,
      "certificateRequired": true
    }
  },
  "encryption": {
    "atRest": { "enabled": true },
    "inTransit": { "enabled": true }
  }
}
```

**Kubernetes/IDP:**
```json
{
  "networkPolicies": {
    "enforced": true,
    "defaultDeny": true
  },
  "rbac": {
    "enabled": true,
    "leastPrivilege": true
  },
  "podSecurity": {
    "standards": "restricted"
  }
}
```

#### Auto-Generated Validation Rules

When you define a baseline configuration, validation rules are automatically generated from the config structure. Each config property becomes a validation check:

- `encryption.enabled === true` → Test validates encryption is enabled
- `fieldLevelSecurity.enforced === true` → Test validates FLS is enforced
- `sharingRules.externalSharingEnabled === false` → Test validates external sharing is disabled

#### Custom Validation Rules

You can also add custom validation rules as individual Tests:

```typescript
{
  id: 'custom-rule-1',
  name: 'All Profiles Have MFA',
  testType: 'salesforce-config',
  domain: 'platform_config',
  platform: 'salesforce',
  check: 'allProfilesHaveMFA()',
  severity: 'high',
  autoGenerated: false
}
```

#### Creating Platform Instances

Platform instances are stored as Applications with platform-specific infrastructure:

```typescript
{
  id: 'prod-salesforce-org',
  name: 'Production Salesforce Org',
  infrastructure: {
    platformInstance: {
      platform: 'salesforce',
      connection: {
        endpoint: 'https://mycompany.salesforce.com',
        credentials: { /* encrypted */ }
      }
    }
  }
}
```

### 4. Distributed Systems Tests

Tests that validate distributed systems behavior across multiple regions, including policy consistency and synchronization.

#### Overview

Distributed systems tests validate that your application behaves correctly when deployed across multiple regions. These tests ensure:

- **Multi-Region Consistency**: Policies evaluate consistently across regions
- **Policy Synchronization**: Policy updates propagate correctly across regions
- **Coordination**: Multi-region operations coordinate properly

**Key Concepts:**
- **Application Infrastructure**: Applications must have distributed systems infrastructure configured with region definitions
- **Test Subtypes**: Three types of distributed tests (multi-region, policy-consistency, policy-synchronization)
- **Region Configuration**: Each region must have endpoint and PDP endpoint configured

#### Prerequisites

Before creating distributed systems tests, ensure:

1. **Application with Distributed Infrastructure**: Your application must have `infrastructure.distributedSystems` configured:

```typescript
{
  id: 'my-distributed-app',
  name: 'My Distributed Application',
  infrastructure: {
    distributedSystems: {
      regions: [
        {
          id: 'us-east-1',
          name: 'US East (N. Virginia)',
          endpoint: 'https://api-us-east.example.com',
          pdpEndpoint: 'https://pdp-us-east.example.com',
          timezone: 'America/New_York',
          latency: 50,
          credentials: { /* encrypted */ }
        },
        {
          id: 'eu-west-1',
          name: 'EU West (Ireland)',
          endpoint: 'https://api-eu-west.example.com',
          pdpEndpoint: 'https://pdp-eu-west.example.com',
          timezone: 'Europe/Dublin',
          latency: 100,
          credentials: { /* encrypted */ }
        },
        {
          id: 'ap-southeast-1',
          name: 'Asia Pacific (Singapore)',
          endpoint: 'https://api-ap-southeast.example.com',
          pdpEndpoint: 'https://pdp-ap-southeast.example.com',
          timezone: 'Asia/Singapore',
          latency: 200,
          credentials: { /* encrypted */ }
        }
      ]
    }
  }
}
```

2. **At Least 2 Regions**: Distributed systems tests require at least 2 regions to be configured

#### Test Subtypes

##### 1. Multi-Region Test

Tests that the same policy evaluation request produces consistent results across multiple regions.

**Use Cases:**
- Verify policy decisions are consistent across regions
- Test coordination between regions
- Validate latency and timeout handling

**Configuration:**

```typescript
{
  id: 'multi-region-test-1',
  name: 'Multi-Region Access Control Test',
  testType: 'distributed-systems',
  distributedTestType: 'multi-region',
  applicationId: 'my-distributed-app',
  multiRegionConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'], // Region IDs
    executionMode: 'parallel', // or 'sequential'
    timeout: 30000, // milliseconds
    user: {
      id: 'user-123',
      attributes: {
        role: 'admin',
        department: 'Engineering'
      }
    },
    resource: {
      id: 'resource-456',
      type: 'dataset',
      attributes: {
        sensitivity: 'internal'
      }
    },
    action: 'read',
    expectedResult: true // Expected policy decision
  }
}
```

**Configuration Fields:**

- `regions` (string[], required): Array of region IDs to test. Must match region IDs in application infrastructure.
- `executionMode` ('parallel' | 'sequential', optional): How to execute tests across regions. Default: 'parallel'.
- `timeout` (number, optional): Maximum time to wait for all regions to respond. Default: 30000ms.
- `user` (object, optional): User context for policy evaluation.
- `resource` (object, optional): Resource context for policy evaluation.
- `action` (string, optional): Action to test (e.g., 'read', 'write').
- `expectedResult` (boolean, optional): Expected policy decision result.

**Example Result:**

```typescript
{
  passed: true,
  details: {
    distributedTestType: 'multi-region',
    aggregatedResult: {
      consistent: true,
      decision: true,
      regionCount: 3
    },
    regionResults: [
      {
        regionId: 'us-east-1',
        decision: true,
        latency: 45,
        timestamp: '2024-01-15T10:00:00Z'
      },
      {
        regionId: 'eu-west-1',
        decision: true,
        latency: 98,
        timestamp: '2024-01-15T10:00:00Z'
      },
      {
        regionId: 'ap-southeast-1',
        decision: true,
        latency: 201,
        timestamp: '2024-01-15T10:00:00Z'
      }
    ],
    coordinationMetrics: {
      totalTime: 201,
      averageLatency: 114.67,
      slowestRegion: 'ap-southeast-1'
    }
  }
}
```

##### 2. Policy Consistency Test

Tests that policies are consistent across regions (same versions, configurations, and evaluation results).

**Use Cases:**
- Verify policy versions match across regions
- Check policy configurations are synchronized
- Validate evaluation consistency

**Configuration:**

```typescript
{
  id: 'policy-consistency-test-1',
  name: 'Policy Consistency Check',
  testType: 'distributed-systems',
  distributedTestType: 'policy-consistency',
  applicationId: 'my-distributed-app',
  policyConsistencyConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    policyIds: ['policy-1', 'policy-2'], // Optional: specific policies, or all if omitted
    checkTypes: ['version', 'configuration', 'evaluation'] // What to check
  }
}
```

**Configuration Fields:**

- `regions` (string[], required): Array of region IDs to check. Must have at least 2 regions.
- `policyIds` (string[], optional): Specific policy IDs to check. If omitted, checks all policies.
- `checkTypes` (('version' | 'configuration' | 'evaluation')[], optional): Types of consistency checks to perform. Default: ['version', 'configuration'].

**Check Types:**

- `version`: Verifies policy versions match across regions
- `configuration`: Verifies policy configurations (rules, conditions) match
- `evaluation`: Verifies policy evaluation results are consistent for sample requests

**Example Result:**

```typescript
{
  passed: true,
  details: {
    distributedTestType: 'policy-consistency',
    report: {
      id: 'consistency-report-123',
      timestamp: '2024-01-15T10:00:00Z',
      regionsChecked: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
      policiesChecked: ['policy-1', 'policy-2'],
      consistent: true,
      inconsistencies: [],
      summary: {
        totalPolicies: 2,
        consistentPolicies: 2,
        inconsistentPolicies: 0
      },
      recommendations: []
    }
  }
}
```

##### 3. Policy Synchronization Test

Tests that policy updates propagate correctly across regions and handles synchronization scenarios.

**Use Cases:**
- Verify policy updates sync across regions
- Test synchronization timing
- Validate failure recovery scenarios

**Configuration:**

```typescript
{
  id: 'policy-sync-test-1',
  name: 'Policy Synchronization Test',
  testType: 'distributed-systems',
  distributedTestType: 'policy-synchronization',
  applicationId: 'my-distributed-app',
  policySyncConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    policyId: 'policy-1', // Optional: specific policy, or all if omitted
    testScenarios: [
      'update-propagation',
      'sync-timing',
      'sync-failure-recovery'
    ]
  }
}
```

**Configuration Fields:**

- `regions` (string[], required): Array of region IDs to test. Must have at least 2 regions.
- `policyId` (string, optional): Specific policy ID to test. If omitted, tests all policies.
- `testScenarios` (('update-propagation' | 'sync-timing' | 'sync-failure-recovery')[], optional): Scenarios to test. Default: ['update-propagation', 'sync-timing'].

**Test Scenarios:**

- `update-propagation`: Tests that policy updates propagate to all regions
- `sync-timing`: Tests synchronization timing and latency
- `sync-failure-recovery`: Tests recovery from synchronization failures

**Example Result:**

```typescript
{
  passed: true,
  details: {
    distributedTestType: 'policy-synchronization',
    report: {
      id: 'sync-report-123',
      timestamp: '2024-01-15T10:00:00Z',
      regionsTested: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
      testResults: [
        {
          scenario: 'update-propagation',
          passed: true,
          propagationTime: 1250, // milliseconds
          regionsSynced: 3
        },
        {
          scenario: 'sync-timing',
          passed: true,
          averageSyncTime: 980,
          maxSyncTime: 1250,
          minSyncTime: 750
        },
        {
          scenario: 'sync-failure-recovery',
          passed: true,
          recoveryTime: 2100,
          regionsRecovered: 3
        }
      ],
      summary: {
        totalScenarios: 3,
        passedScenarios: 3,
        failedScenarios: 0
      },
      recommendations: []
    }
  }
}
```

#### Creating Distributed Systems Tests

**Via UI:**

1. Navigate to **Tests** → **Individual Tests** → **Create Test**
2. Select **Category**: "Data & Systems"
3. Select **Test Type**: "Distributed Systems"
4. Select **Application**: Choose an application with distributed systems infrastructure
5. Select **Distributed Test Type**: Choose multi-region, policy-consistency, or policy-synchronization
6. Configure subtype-specific settings:
   - **Multi-Region**: Select regions, execution mode, user/resource inputs
   - **Policy Consistency**: Select regions, check types, optional policy IDs
   - **Policy Synchronization**: Select regions, test scenarios, optional policy ID
7. Save the test

**Via API:**

```bash
POST /api/tests
Content-Type: application/json

{
  "name": "Multi-Region Access Control Test",
  "description": "Tests access control consistency across US East, EU West, and AP Southeast regions",
  "testType": "distributed-systems",
  "applicationId": "my-distributed-app",
  "distributedTestType": "multi-region",
  "multiRegionConfig": {
    "regions": ["us-east-1", "eu-west-1", "ap-southeast-1"],
    "executionMode": "parallel",
    "timeout": 30000,
    "user": {
      "id": "user-123",
      "attributes": {
        "role": "admin"
      }
    },
    "resource": {
      "id": "resource-456",
      "type": "dataset"
    },
    "action": "read",
    "expectedResult": true
  }
}
```

**Via TypeScript:**

```typescript
import { Test } from '../../core/types';

export const multiRegionTest: Test = {
  id: 'multi-region-test-1',
  name: 'Multi-Region Access Control Test',
  description: 'Tests access control consistency across regions',
  testType: 'distributed-systems',
  distributedTestType: 'multi-region',
  applicationId: 'my-distributed-app',
  multiRegionConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    executionMode: 'parallel',
    timeout: 30000,
    user: {
      id: 'user-123',
      attributes: { role: 'admin' }
    },
    resource: {
      id: 'resource-456',
      type: 'dataset'
    },
    action: 'read',
    expectedResult: true
  },
  version: 1,
  enabled: true
};
```

#### Best Practices

1. **Application Setup**: Ensure applications have proper distributed systems infrastructure configured before creating tests
2. **Region Selection**: Select representative regions that cover your deployment geography
3. **Execution Mode**: Use 'parallel' for performance, 'sequential' for debugging
4. **Timeout Configuration**: Set appropriate timeouts based on expected latency (consider slowest region)
5. **Policy Selection**: For consistency tests, test critical policies first
6. **Test Scenarios**: Include all relevant synchronization scenarios for comprehensive coverage
7. **Regular Testing**: Run distributed systems tests regularly to catch synchronization issues early

#### Troubleshooting

**Error: "Application does not have distributed systems infrastructure configured"**
- Ensure the application has `infrastructure.distributedSystems.regions` configured
- Verify at least 2 regions are defined

**Error: "At least 2 regions are required"**
- Add more regions to the application infrastructure
- Or select fewer regions in the test configuration

**Error: "Invalid region IDs"**
- Verify region IDs in test configuration match region IDs in application infrastructure
- Check for typos in region IDs

**Tests Timing Out**
- Increase timeout value in test configuration
- Check network connectivity to regions
- Consider using 'sequential' execution mode for debugging

**Inconsistent Results**
- Check policy versions across regions
- Verify policy configurations match
- Review region-specific policy overrides

## Configuration Reference

### Complete Test Suite Example

```typescript
import { TestSuite } from '../core/types';

export const completeTestSuite: TestSuite = {
  // Basic information
  name: 'Complete Compliance Test Suite',
  application: 'research-tracker-api',
  team: 'research-platform',

  // Test type flags
  includeAccessControlTests: true,
  includeDataBehaviorTests: true,
  includeDatasetHealthTests: true,

  // User roles to test
  userRoles: ['admin', 'researcher', 'analyst', 'viewer'],

  // Resources to test
  resources: [
    {
      id: 'public-reports',
      type: 'report',
      attributes: { sensitivity: 'public' },
      sensitivity: 'public',
      abacAttributes: {
        dataClassification: 'public',
        department: 'Research',
      },
    },
    {
      id: 'confidential-data',
      type: 'dataset',
      attributes: { sensitivity: 'confidential' },
      sensitivity: 'confidential',
      abacAttributes: {
        dataClassification: 'confidential',
        department: 'Research',
        project: 'project-alpha',
        requiresCertification: 'data-science',
      },
    },
  ],

  // Contexts to test
  contexts: [
    { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'headquarters' },
    { ipAddress: '10.0.0.1', timeOfDay: '22:00', location: 'remote' },
  ],

  // Expected access control decisions
  expectedDecisions: {
    'admin-public-reports': true,
    'viewer-public-reports': true,
    'viewer-confidential-data': false,
    'researcher-confidential-data': true,
  },

  // Test queries for data behavior tests
  testQueries: [
    {
      name: 'Get public reports',
      sql: 'SELECT id, title, status FROM reports WHERE sensitivity = \'public\'',
    },
    {
      name: 'Get user emails (should fail)',
      sql: 'SELECT id, email FROM users',
    },
  ],

  // Field restrictions
  allowedFields: {
    viewer: ['id', 'title', 'status'],
    analyst: ['id', 'title', 'status', 'created_at'],
    researcher: ['id', 'title', 'status', 'created_at', 'content'],
    admin: ['*'],
  },

  // Required filters
  requiredFilters: {
    viewer: [
      { field: 'workspace_id', operator: '=', value: 'user_workspace' },
    ],
  },

  // Disallowed joins
  disallowedJoins: {
    viewer: ['users', 'user_profiles'],
  },

  // Datasets
  datasets: [
    {
      name: 'masked-users',
      type: 'masked',
      schema: { id: 'string', email_masked: 'string' },
      recordCount: 1000,
      piiFields: ['email_masked'],
    },
  ],

  // Privacy thresholds
  privacyThresholds: [
    { metric: 'k-anonymity', threshold: 10, operator: '>=' },
  ],

  // Statistical fidelity
  statisticalFidelityTargets: [
    { field: 'age', metric: 'mean', targetValue: 35.5, tolerance: 2.0 },
  ],
};
```

## Best Practices

### 1. Test Suite Organization

- **One suite per application**: Create separate suites for different applications
- **Group by feature**: Create suites for specific features or modules
- **Use descriptive names**: `research-tracker-api-tests` not `test-suite-1`

### 2. Test Coverage

- **Test all roles**: Include all user roles that interact with the application
- **Test edge cases**: Include boundary conditions and error cases
- **Test negative cases**: Verify that access is properly denied

### 3. Resource Definition

- **Realistic data**: Use realistic resource attributes
- **Cover all sensitivity levels**: Test public, internal, confidential, restricted
- **Include ABAC attributes**: If using ABAC, include relevant attributes

### 4. Query Testing

- **Representative queries**: Use queries that represent real application usage
- **Test violations**: Include queries that should fail
- **Test boundaries**: Test limits, filters, and aggregations

### 5. Expected Decisions

- **Be explicit**: Clearly define what should be allowed/denied
- **Document reasoning**: Add comments explaining why decisions are expected
- **Update regularly**: Keep expected decisions in sync with policies

### 6. Performance

- **Limit test count**: Don't create too many test cases (aim for < 100)
- **Use caching**: Enable caching for repeated evaluations
- **Parallel execution**: Tests can run in parallel for speed

## Examples

### Example 1: Simple RBAC Test Suite

```typescript
export const simpleRBACSuite: TestSuite = {
  name: 'Simple RBAC Tests',
  application: 'simple-app',
  team: 'platform',
  includeAccessControlTests: true,
  includeDataBehaviorTests: false,
  includeDatasetHealthTests: false,
  userRoles: ['admin', 'viewer'],
  resources: [
    { id: 'public', type: 'data', attributes: { sensitivity: 'public' }, sensitivity: 'public' },
    { id: 'restricted', type: 'data', attributes: { sensitivity: 'restricted' }, sensitivity: 'restricted' },
  ],
  contexts: [{ ipAddress: '192.168.1.1' }],
  expectedDecisions: {
    'admin-public': true,
    'admin-restricted': true,
    'viewer-public': true,
    'viewer-restricted': false,
  },
};
```

### Example 2: ABAC Test Suite

```typescript
export const abacTestSuite: TestSuite = {
  name: 'ABAC Compliance Tests',
  application: 'research-api',
  team: 'research',
  includeAccessControlTests: true,
  includeDataBehaviorTests: true,
  includeDatasetHealthTests: false,
  userRoles: ['researcher', 'analyst'],
  resources: [
    {
      id: 'research-data',
      type: 'dataset',
      attributes: { department: 'Research' },
      abacAttributes: {
        department: 'Research',
        project: 'project-alpha',
        dataClassification: 'confidential',
      },
    },
  ],
  contexts: [
    { location: 'headquarters', timeOfDay: '14:00' },
  ],
  testQueries: [
    {
      name: 'Department match query',
      sql: 'SELECT * FROM data WHERE department = \'Research\'',
    },
  ],
  allowedFields: {
    researcher: ['id', 'title', 'data'],
    analyst: ['id', 'title'],
  },
};
```

### Example 3: DLP Test Suite with Contract Rules

Contract rules (export restrictions, aggregation requirements, field restrictions, join restrictions) are now configured directly in DLP test configurations. See DLP test configuration documentation for details.

### Example 4: Dataset Health Test Suite

```typescript
export const datasetHealthTestSuite: TestSuite = {
  name: 'Dataset Health Tests',
  application: 'data-platform',
  team: 'data-platform',
  includeAccessControlTests: false,
  includeDataBehaviorTests: false,
  includeDatasetHealthTests: true,
  userRoles: ['analyst'],
  resources: [],
  contexts: [],
  datasets: [
    {
      name: 'masked-users',
      type: 'masked',
      schema: { id: 'string', email_masked: 'string', name: 'string' },
      recordCount: 1000,
      piiFields: ['email_masked'],
    },
  ],
  privacyThresholds: [
    { metric: 'k-anonymity', threshold: 10, operator: '>=' },
  ],
  statisticalFidelityTargets: [
    { field: 'age', metric: 'mean', targetValue: 35.5, tolerance: 2.0 },
  ],
};
```

### Example 5: Distributed Systems Test Suite

```typescript
import { Test } from '../core/types';

// Multi-Region Test
export const multiRegionTest: Test = {
  id: 'multi-region-test-1',
  name: 'Multi-Region Access Control Test',
  description: 'Tests access control consistency across US East, EU West, and AP Southeast',
  testType: 'distributed-systems',
  distributedTestType: 'multi-region',
  applicationId: 'my-distributed-app',
  multiRegionConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    executionMode: 'parallel',
    timeout: 30000,
    user: {
      id: 'user-123',
      attributes: {
        role: 'admin',
        department: 'Engineering'
      }
    },
    resource: {
      id: 'resource-456',
      type: 'dataset',
      attributes: {
        sensitivity: 'internal'
      }
    },
    action: 'read',
    expectedResult: true
  },
  version: 1,
  enabled: true
};

// Policy Consistency Test
export const policyConsistencyTest: Test = {
  id: 'policy-consistency-test-1',
  name: 'Policy Consistency Check',
  description: 'Verifies policies are consistent across all regions',
  testType: 'distributed-systems',
  distributedTestType: 'policy-consistency',
  applicationId: 'my-distributed-app',
  policyConsistencyConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    policyIds: ['policy-1', 'policy-2'], // Optional: check specific policies
    checkTypes: ['version', 'configuration', 'evaluation']
  },
  version: 1,
  enabled: true
};

// Policy Synchronization Test
export const policySyncTest: Test = {
  id: 'policy-sync-test-1',
  name: 'Policy Synchronization Test',
  description: 'Tests policy update propagation and synchronization',
  testType: 'distributed-systems',
  distributedTestType: 'policy-synchronization',
  applicationId: 'my-distributed-app',
  policySyncConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    policyId: 'policy-1', // Optional: test specific policy
    testScenarios: [
      'update-propagation',
      'sync-timing',
      'sync-failure-recovery'
    ]
  },
  version: 1,
  enabled: true
};
```

## Running Test Suites

### From Command Line

```bash
# Run default suite
npm run test:compliance

# Run specific suite
TEST_SUITE=my-test-suite npm run test:compliance

# Run with ABAC policies
POLICY_MODE=abac TEST_SUITE=abac-test-suite npm run test:compliance
```

### From Code

```typescript
import { TestOrchestrator } from './core/test-harness';
import { loadTestSuite } from './tests/test-suite-loader';

const suite = await loadTestSuite('my-test-suite');
const orchestrator = new TestOrchestrator(config);
const results = await orchestrator.runTestSuite(suite);
```

## Troubleshooting

### Tests Not Running

1. **Check suite file**: Ensure file exists in `tests/suites/`
2. **Verify JSON syntax**: If using JSON, validate syntax
3. **Check imports**: If using TypeScript, verify exports

### Unexpected Results

1. **Review policies**: Check that policies match expectations
2. **Verify attributes**: Ensure user/resource attributes are correct
3. **Check context**: Verify context attributes are set properly

### Performance Issues

1. **Reduce test count**: Limit number of resources/contexts
2. **Enable caching**: Set `cacheDecisions: true`
3. **Optimize queries**: Use simpler test queries

## Next Steps

- See [POLICY_CREATION_GUIDE.md](./POLICY_CREATION_GUIDE.md) for creating policies
- Review [examples](../examples/) for complete examples
- Check [tests](../tests/) for reference implementations

