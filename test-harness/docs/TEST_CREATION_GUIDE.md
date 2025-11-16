# Test Creation Guide

This guide explains how to create test suites for TestOrchestrator. You'll learn how to define test scenarios, configure test data, and validate access control policies.

## Table of Contents

1. [Test Suite Overview](#test-suite-overview)
2. [Creating a Test Suite](#creating-a-test-suite)
3. [Test Types](#test-types)
4. [Configuration Reference](#configuration-reference)
5. [Best Practices](#best-practices)
6. [Examples](#examples)

## Test Suite Overview

A test suite defines:
- **What to test**: Which types of tests to run (access control, data behavior, contracts, dataset health)
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

// Data Behavior Test Suite
interface DataBehaviorTestSuite {
  name: string;
  application: string;
  team: string;
  testType: 'data-behavior';       // Required: single test type
  userRoles: string[];
  resources: Resource[];
  contexts: Context[];
  testQueries: TestQuery[];        // Required for data-behavior
  allowedFields?: Record<string, string[]>;
  requiredFilters?: Record<string, Filter[]>;
  disallowedJoins?: Record<string, string[]>;
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

### Step 3: Configure Test Types

Enable the test types you want to run:

```typescript
{
  includeAccessControlTests: true,    // Test PDP decisions
  includeDataBehaviorTests: true,     // Test query compliance
  includeContractTests: false,        // Test data owner contracts
  includeDatasetHealthTests: false,   // Test privacy/statistics
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

### 2. Data Behavior Tests

Tests that queries comply with field restrictions, required filters, and join restrictions.

#### Configuration

```typescript
{
  includeDataBehaviorTests: true,
  testQueries: [
    {
      name: 'Get all reports',
      sql: 'SELECT id, title, status FROM reports',
    },
    {
      name: 'Get user emails',
      sql: 'SELECT id, email FROM users',
    },
    {
      name: 'Get reports with join',
      sql: 'SELECT r.*, u.email FROM reports r JOIN users u ON r.user_id = u.id',
    },
  ],
  allowedFields: {
    viewer: ['id', 'title', 'status'],
    analyst: ['id', 'title', 'status', 'created_at'],
    researcher: ['id', 'title', 'status', 'created_at', 'content'],
    admin: ['*'],  // All fields
  },
  requiredFilters: {
    viewer: [
      { field: 'workspace_id', operator: '=', value: 'user_workspace' },
    ],
    analyst: [
      { field: 'workspace_id', operator: '=', value: 'user_workspace' },
      { field: 'status', operator: 'IN', value: ['published', 'draft'] },
    ],
  },
  disallowedJoins: {
    viewer: ['users', 'user_profiles'],
    analyst: ['user_profiles'],
  },
}
```

#### Test Query Structure

```typescript
interface TestQuery {
  name: string;              // Descriptive name
  sql?: string;              // SQL query to test
  apiEndpoint?: string;      // API endpoint to test
  httpMethod?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  requestBody?: any;         // Request body for API calls
}
```

#### Allowed Fields

Map of role to array of allowed field names:

```typescript
allowedFields?: {
  [role: string]: string[];   // ['*'] means all fields
}
```

#### Required Filters

Map of role to array of required filters:

```typescript
requiredFilters?: {
  [role: string]: Filter[];
}

interface Filter {
  field: string;
  operator: '=' | '!=' | '>' | '<' | '>=' | '<=' | 'IN' | 'NOT IN' | 'LIKE';
  value: any;
}
```

#### Disallowed Joins

Map of role to array of table names that cannot be joined:

```typescript
disallowedJoins?: {
  [role: string]: string[];  // Table names
}
```

### 3. Contract Tests

Tests based on machine-readable requirements from data owners.

#### Configuration

```typescript
{
  includeContractTests: true,
  contracts: [
    {
      name: 'No Raw Email Export',
      dataOwner: 'data-governance',
      requirements: [
        {
          id: 'no-email-export',
          description: 'No raw email addresses may be exported',
          type: 'export-restriction',
          rule: {
            restrictedFields: ['email'],
            requireMasking: true,
          },
          enforcement: 'hard',
        },
      ],
      machineReadable: true,
    },
    {
      name: 'Minimum Aggregation k=10',
      dataOwner: 'data-governance',
      requirements: [
        {
          id: 'min-aggregation',
          description: 'Queries must aggregate to minimum k=10 records',
          type: 'aggregation-requirement',
          rule: {
            minK: 10,
            requireAggregation: true,
          },
          enforcement: 'hard',
        },
      ],
      machineReadable: true,
    },
  ],
}
```

#### Contract Structure

```typescript
interface Contract {
  name: string;
  dataOwner: string;
  requirements: ContractRequirement[];
  machineReadable?: boolean;
  schema?: any;
}

interface ContractRequirement {
  id: string;
  description: string;
  type: 'field-restriction' | 'aggregation-requirement' | 
        'join-restriction' | 'export-restriction';
  rule: any;
  enforcement: 'hard' | 'soft';
}
```

#### Requirement Types

1. **field-restriction**: Restricts access to specific fields
   ```typescript
   {
     type: 'field-restriction',
     rule: {
       fields: ['email', 'ssn'],
       allowed: false,  // or true for whitelist
     }
   }
   ```

2. **aggregation-requirement**: Requires aggregation with minimum k
   ```typescript
   {
     type: 'aggregation-requirement',
     rule: {
       minK: 10,
       requireAggregation: true,
     }
   }
   ```

3. **join-restriction**: Restricts certain joins
   ```typescript
   {
     type: 'join-restriction',
     rule: {
       disallowedJoins: ['users', 'user_profiles'],
     }
   }
   ```

4. **export-restriction**: Restricts data export
   ```typescript
   {
     type: 'export-restriction',
     rule: {
       restrictedFields: ['email', 'ssn'],
       allowedFormats: ['csv', 'json'],
       requireMasking: true,
     }
   }
   ```

### 4. Dataset Health Tests

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
  includeContractTests: true,
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

  // Contracts
  contracts: [
    {
      name: 'No Raw Email Export',
      dataOwner: 'data-governance',
      requirements: [
        {
          id: 'no-email-export',
          description: 'No raw email addresses may be exported',
          type: 'export-restriction',
          rule: { restrictedFields: ['email'], requireMasking: true },
          enforcement: 'hard',
        },
      ],
      machineReadable: true,
    },
  ],

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
  includeContractTests: false,
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
  includeContractTests: false,
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

### Example 3: Contract Test Suite

```typescript
export const contractTestSuite: TestSuite = {
  name: 'Contract Compliance Tests',
  application: 'data-export-service',
  team: 'data-platform',
  includeAccessControlTests: false,
  includeDataBehaviorTests: true,
  includeContractTests: true,
  includeDatasetHealthTests: false,
  userRoles: ['analyst'],
  resources: [],
  contexts: [],
  contracts: [
    {
      name: 'GDPR Compliance',
      dataOwner: 'legal',
      requirements: [
        {
          id: 'no-pii-export',
          description: 'No PII fields may be exported',
          type: 'export-restriction',
          rule: {
            restrictedFields: ['email', 'ssn', 'phone'],
            requireMasking: true,
          },
          enforcement: 'hard',
        },
        {
          id: 'min-aggregation',
          description: 'Minimum aggregation k=10',
          type: 'aggregation-requirement',
          rule: { minK: 10, requireAggregation: true },
          enforcement: 'hard',
        },
      ],
      machineReadable: true,
    },
  ],
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

