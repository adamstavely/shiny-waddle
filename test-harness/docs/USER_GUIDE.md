# Heimdall User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [What is Heimdall?](#what-is-heimdall)
3. [Current Features & Support](#current-features--support)
4. [Getting Started](#getting-started)
5. [Configuring Tests](#configuring-tests)
6. [Configuring Validators](#configuring-validators)
7. [Using the Dashboard API](#using-the-dashboard-api)
8. [Running Tests](#running-tests)
9. [Understanding Results](#understanding-results)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)

---

## Introduction

Heimdall is an automated testing framework that validates applications are adhering to access control requirements for data. It provides comprehensive testing capabilities for Zero Trust Architecture (ZTA) compliance, data access control, and security policy validation.

This guide will help you understand how to use Heimdall, what features are currently supported, and how to configure tests and validators for your applications.

---

## What is Heimdall?

Heimdall is a comprehensive testing framework designed to:

- **Validate Access Control**: Test Policy Decision Point (PDP) decisions for different user roles, attributes, resources, and contexts
- **Verify Data Behavior**: Ensure queries only use permitted fields, apply required filters/aggregations, and block disallowed joins
- **Enforce Contracts**: Test machine-readable requirements from data owners (e.g., "No raw email export," "Min aggregation ≥ k=10")
- **Assess Dataset Health**: Validate masked/synthetic data meets privacy thresholds (k-anonymity, l-diversity, t-closeness, differential privacy)
- **Support Zero Trust Architecture**: Comprehensive testing for identity, device, network, application, and data security

---

## Current Features & Support

### ✅ Core Testing Capabilities

#### 1. Access Control Testing
- **User Simulation**: Simulate users with different roles/attributes
- **PDP Decision Testing**: Evaluate Policy Decision Point decisions for representative identities, attributes, resources, and contexts
- **RBAC Support**: Role-Based Access Control policy testing
- **ABAC Support**: Attribute-Based Access Control policy testing
- **Hybrid Mode**: Support for both RBAC and ABAC simultaneously

#### 2. Data Behavior Testing
- **Query Validation**: Verify queries only use permitted fields
- **Filter Enforcement**: Ensure required filters/aggregations are applied
- **Join Restrictions**: Block disallowed joins
- **PII Detection**: Automatic detection of PII fields in queries
- **Field-Level Access Control**: Test column-level security

#### 3. Contract Testing
- **Machine-Readable Requirements**: Convert data owner requirements into automated tests
- **Export Restrictions**: Test restrictions on data exports
- **Aggregation Requirements**: Validate minimum aggregation thresholds
- **Field Restrictions**: Test field-level access restrictions
- **Join Restrictions**: Validate join operation restrictions

#### 4. Dataset Health Testing
- **Privacy Metrics**: k-anonymity, l-diversity, t-closeness, differential privacy
- **Statistical Fidelity**: Validate mean, median, stddev, distribution similarity
- **Masked Data Validation**: Test masked/synthetic data quality

### ✅ Zero Trust Architecture (ZTA) Features

#### Access Control
- **Policy Validation**: Detect policy conflicts, analyze coverage, test performance, run regression tests, simulate policy changes
- **Identity Lifecycle**: Test onboarding, role changes, offboarding, credential rotation, MFA enforcement, JIT access, break-glass procedures
- **Identity Providers**: Test AD group membership, Okta/Auth0/Azure AD policy synchronization, GCP IAM bindings, cross-system policy validation

#### Data Security
- **RLS/CLS Testing**: Test Row-Level Security and Column-Level Security coverage, dynamic masking, cross-tenant isolation, policy bypass attempts
- **DLP (Data Loss Prevention)**: Test data exfiltration detection, API response validation, query validation, bulk export controls

#### Application Security
- **API Gateway**: Test gateway policies, rate limiting, API versioning, service-to-service authentication
- **API Security**: Comprehensive REST/GraphQL API security testing including authentication, authorization, rate limiting, vulnerability detection

#### Platform Security
- **Network Policies**: Test firewall rules, service-to-service connectivity, network segmentation, service mesh policies
- **Distributed Systems**: Test access control across multiple regions, verify policy consistency, test synchronization, distributed transactions

#### Compliance
- **NIST 800-207**: Zero Trust Architecture compliance assessment and reporting
- **CI/CD Security Gates**: Pre-merge policy validation, IAC scanning, container scanning, K8s RBAC validation

### ✅ Additional Features

- **Ephemeral Environments**: Spin up per-PR with seeded masked/synthetic data
- **CI/CD Integration**: Block merges on access violations with GitHub Actions
- **Compliance Dashboard**: Show compliance score by application, team, dataset
- **Integration Hooks**: SAST/DAST/DBT/Great Expectations integration
- **Data Pipeline Testing**: Test ETL pipelines, streaming data, data transformations
- **Advanced Reporting**: Generate HTML, JSON, JUnit XML reports
- **Risk Scoring**: Calculate risk scores and prioritize issues
- **Policy Versioning**: Track policy changes and rollback capabilities

### 📊 Dashboard API Support

The Dashboard API provides REST endpoints for:

- **Test Configurations**: Create, read, update, delete test configurations
- **RLS/CLS Testing**: Test Row-Level and Column-Level Security
- **Network Policy Testing**: Test firewall rules and network segmentation
- **DLP Testing**: Test data loss prevention policies
- **Identity Lifecycle Testing**: Test identity management workflows
- **API Gateway Testing**: Test API gateway policies and rate limiting
- **Distributed Systems Testing**: Test multi-region access control
- **Policy Validation**: Detect conflicts and analyze coverage
- **Compliance Assessment**: NIST 800-207 compliance scoring

---

## Getting Started

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd test-harness

# Install dependencies
npm install

# Install dashboard API dependencies
cd dashboard-api && npm install && cd ..

# Install dashboard frontend dependencies
cd dashboard-frontend && npm install && cd ..
```

### Quick Start

1. **Run a basic test suite**:
```bash
npm run test:compliance
```

2. **Run with a specific test suite**:
```bash
TEST_SUITE=my-test-suite npm run test:compliance
```

3. **Run with ABAC policies**:
```bash
POLICY_MODE=abac TEST_SUITE=abac-test-suite npm run test:compliance
```

4. **Start the dashboard**:
```bash
# Terminal 1: Start API
npm run dashboard:api

# Terminal 2: Start Frontend
npm run dashboard:frontend
```

---

## Configuring Tests

### Test Suite Structure

A test suite defines what to test, who to test, what resources to test against, and how to validate results.

#### Basic Test Suite

Create a test suite file in `tests/` directory (TypeScript or JSON):

**TypeScript** (`tests/my-test-suite.ts`):
```typescript
import { TestSuite } from '../core/types';

export const myTestSuite: TestSuite = {
  name: 'My Application Tests',
  application: 'my-app',
  team: 'my-team',
  includeAccessControlTests: true,
  includeDataBehaviorTests: true,
  includeContractTests: false,
  includeDatasetHealthTests: false,
  userRoles: ['admin', 'viewer'],
  resources: [
    {
      id: 'resource-1',
      type: 'dataset',
      attributes: { sensitivity: 'public' },
      sensitivity: 'public',
    },
  ],
  contexts: [
    { ipAddress: '192.168.1.1', timeOfDay: '14:00' },
  ],
};
```

**JSON** (`tests/my-test-suite.json`):
```json
{
  "name": "My Application Tests",
  "application": "my-app",
  "team": "my-team",
  "includeAccessControlTests": true,
  "includeDataBehaviorTests": true,
  "includeContractTests": false,
  "includeDatasetHealthTests": false,
  "userRoles": ["admin", "viewer"],
  "resources": [
    {
      "id": "resource-1",
      "type": "dataset",
      "attributes": { "sensitivity": "public" },
      "sensitivity": "public"
    }
  ],
  "contexts": [
    { "ipAddress": "192.168.1.1", "timeOfDay": "14:00" }
  ]
}
```

### Test Types Configuration

#### 1. Access Control Tests

Tests Policy Decision Point (PDP) decisions for different user/resource/context combinations.

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

**ABAC Support**:
```typescript
{
  resources: [
    {
      id: 'research-data',
      type: 'dataset',
      attributes: { department: 'Research' },
      abacAttributes: {
        dataClassification: 'confidential',
        department: 'Research',
        project: 'project-alpha',
        requiresCertification: 'data-science',
      },
    },
  ],
}
```

#### 2. Data Behavior Tests

Tests that queries comply with field restrictions, required filters, and join restrictions.

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

#### 3. Contract Tests

Tests based on machine-readable requirements from data owners.

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

#### 4. Dataset Health Tests

Tests that masked/synthetic datasets meet privacy thresholds and statistical fidelity.

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

### Complete Test Suite Example

See `tests/example-test-suite.ts` for a complete example with all test types.

---

## Configuring Validators

### What are Validators?

Validators are extensible components that perform specific validation tasks. Heimdall uses a plugin-style architecture where validators can be registered and automatically discovered.

### Built-in Validators

Heimdall includes validators for:

- **Access Control**: Tests PDP decisions
- **Data Behavior**: Validates query compliance
- **Contract Testing**: Tests data owner contracts
- **Dataset Health**: Validates privacy and statistical metrics
- **RLS/CLS**: Tests Row-Level and Column-Level Security
- **Network Policy**: Tests firewall rules and segmentation
- **DLP**: Tests data loss prevention
- **Identity Lifecycle**: Tests identity management workflows
- **API Gateway**: Tests API gateway policies
- **Distributed Systems**: Tests multi-region access control

### Creating Custom Validators

Creating a validator is simple with the `BaseValidator` class:

#### Step 1: Create Validator Class

```typescript
// validators/my-validator.ts
import { BaseValidator } from '../core/base-validator';
import { ValidatorMetadata } from '../core/validator-registry';
import { TestResult, TestSuite } from '../core/types';

export class MyValidator extends BaseValidator {
  readonly id = 'my-validator';
  readonly name = 'My Custom Validator';
  readonly description = 'Validates something important';
  readonly testType = 'custom-validation';
  readonly version = '1.0.0';

  readonly metadata: ValidatorMetadata = {
    requiredConfig: ['apiKey'],
    tags: ['custom', 'api'],
  };

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Your validation logic here
    const isValid = await this.checkSomething();

    results.push(
      this.createTestResult(
        'My validation check',
        isValid,
        { details: '...' }
      )
    );

    return results;
  }

  private async checkSomething(): Promise<boolean> {
    // Your validation logic
    return true;
  }
}
```

#### Step 2: Register Validator

```typescript
// In your initialization code
import { validatorRegistry } from '../core/validator-registry';
import { MyValidator } from '../validators/my-validator';

const validator = new MyValidator({
  apiKey: process.env.API_KEY,
});

validatorRegistry.register(validator);
```

#### Step 3: Use Validator

The `Sentinel` class automatically discovers and uses registered validators:

```typescript
const sentinel = new Sentinel(config);
// Validators are automatically discovered and used
const results = await sentinel.runTestSuite(suite);
```

### Validator Features

The `BaseValidator` class provides:

- **Helper Methods**:
  - `createTestResult()` - Create a test result
  - `createPassedResult()` - Create a passed test result
  - `createFailedResult()` - Create a failed test result

- **Automatic Features**:
  - Error handling: Errors are caught and returned as failed test results
  - Configuration validation: Override `validateConfig()` to validate config
  - Suite filtering: Override `shouldRun()` to control when validator runs

### Example: Salesforce Validator

See `validators/example-salesforce-validator.ts` for a complete example of a custom validator.

### Validator Discovery

Query the registry to see what's available:

```typescript
import { validatorRegistry } from '../core/validator-registry';

// List all validators
const validators = validatorRegistry.list();
console.log(validators);

// Find validators for a test suite
const applicableValidators = validatorRegistry.findValidatorsForSuite(suite);

// Get validators by type
const accessControlValidators = validatorRegistry.getByType('access-control');
```

---

## Using the Dashboard API

The Dashboard API provides REST endpoints for managing test configurations and running tests.

### Starting the API

```bash
cd dashboard-api
npm run start:dev
```

The API runs on `http://localhost:3001` by default.

### Test Configurations

#### Create a Test Configuration

```bash
POST /api/test-configurations
Content-Type: application/json

{
  "name": "My RLS/CLS Test",
  "type": "rls-cls",
  "description": "Test PostgreSQL RLS/CLS",
  "database": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "test",
    "username": "postgres"
  },
  "testQueries": [
    {
      "name": "test-user-query",
      "sql": "SELECT * FROM users WHERE tenant_id = ?"
    }
  ],
  "validationRules": {
    "minRLSCoverage": 80,
    "minCLSCoverage": 80
  }
}
```

#### List Test Configurations

```bash
GET /api/test-configurations
GET /api/test-configurations?type=rls-cls
```

#### Get a Test Configuration

```bash
GET /api/test-configurations/:id
```

#### Update a Test Configuration

```bash
PUT /api/test-configurations/:id
Content-Type: application/json

{
  "name": "Updated Name",
  "description": "Updated description"
}
```

#### Delete a Test Configuration

```bash
DELETE /api/test-configurations/:id
```

#### Test a Configuration

```bash
POST /api/test-configurations/:id/test
```

### Configuration Types

#### 1. RLS/CLS Configuration

```json
{
  "name": "PostgreSQL RLS/CLS",
  "type": "rls-cls",
  "database": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "test",
    "username": "postgres"
  },
  "testQueries": [...],
  "validationRules": {
    "minRLSCoverage": 80,
    "minCLSCoverage": 80
  }
}
```

#### 2. Network Policy Configuration

```json
{
  "name": "Network Segmentation",
  "type": "network-policy",
  "firewallRules": [...],
  "networkSegments": [...],
  "testLogic": {
    "validateConnectivity": true,
    "checkSegmentation": true
  }
}
```

#### 3. DLP Configuration

```json
{
  "name": "Data Loss Prevention",
  "type": "dlp",
  "patterns": [...],
  "exportLimits": {
    "csv": 1000,
    "json": 5000
  }
}
```

#### 4. Identity Lifecycle Configuration

```json
{
  "name": "Identity Management",
  "type": "identity-lifecycle",
  "workflows": {
    "onboarding": {...},
    "offboarding": {...}
  }
}
```

#### 5. API Gateway Configuration

```json
{
  "name": "API Gateway Policies",
  "type": "api-gateway",
  "policies": [...],
  "rateLimits": {...}
}
```

#### 6. Distributed Systems Configuration

```json
{
  "name": "Multi-Region Access",
  "type": "distributed-systems",
  "regions": [
    {
      "id": "us-east-1",
      "name": "US East",
      "endpoint": "https://api-us-east.example.com"
    }
  ],
  "policySync": {
    "enabled": true,
    "syncInterval": 1000
  }
}
```

### API Endpoints Reference

See `docs/API.md` for complete API documentation with all endpoints, request/response formats, and examples.

---

## Running Tests

### Command Line

#### Basic Test Run

```bash
npm run test:compliance
```

#### With Custom Suite

```bash
TEST_SUITE=my-test-suite npm run test:compliance
```

#### With ABAC Policies

```bash
POLICY_MODE=abac TEST_SUITE=abac-test-suite npm run test:compliance
```

#### With Custom Policy Path

```bash
ABAC_POLICIES_PATH=./policies/my-policies.json npm run test:compliance
```

#### Watch Mode

```bash
npm run test:compliance:watch
```

### Programmatic Usage

```typescript
import { Sentinel } from './core/test-harness';
import { loadTestSuite } from './tests/test-suite-loader';
import { TestConfiguration } from './core/types';

// Load test suite
const suite = await loadTestSuite('my-test-suite');

// Create configuration
const config: TestConfiguration = {
  userSimulationConfig: {
    roles: suite.userRoles,
    attributes: {},
  },
  accessControlConfig: {
    policyEngine: 'custom',
    cacheDecisions: true,
    policyMode: 'hybrid',
  },
  dataBehaviorConfig: {
    enableQueryLogging: true,
  },
  contractTestConfig: {
    autoGenerateTests: true,
  },
  datasetHealthConfig: {
    privacyMetrics: [
      { name: 'k-anonymity', type: 'k-anonymity', threshold: 10 },
    ],
  },
  reportingConfig: {
    outputFormat: 'json',
    outputPath: './reports',
    includeDetails: true,
  },
};

// Initialize Sentinel
const sentinel = new Sentinel(config);

// Run tests
const results = await sentinel.runTestSuite(suite);

// Check compliance
const isCompliant = sentinel.isCompliant(results);
console.log(`Compliance: ${isCompliant ? 'PASSED' : 'FAILED'}`);

// Generate report
const { ComplianceReporter } = await import('./services/compliance-reporter');
const reporter = new ComplianceReporter(config.reportingConfig);
const report = await reporter.generateReport(results);
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Compliance Tests

on:
  pull_request:
    branches: [main]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm install
      - name: Run compliance tests
        run: npm run test:compliance
        env:
          MIN_COMPLIANCE_SCORE: 100
```

---

## Understanding Results

### Test Result Structure

```typescript
interface TestResult {
  testType: 'access-control' | 'data-behavior' | 'contract' | 'dataset-health';
  testName: string;
  passed: boolean;
  details: any;
  timestamp: Date;
  error?: string;
}
```

### Report Formats

Heimdall generates reports in multiple formats:

1. **JSON Report** (`compliance-report-{timestamp}.json`)
2. **HTML Report** (`compliance-report-{timestamp}.html`)
3. **JUnit XML** (`compliance-report-{timestamp}.xml`)
4. **Dashboard Data** (`dashboard-data.json`)

### Compliance Score

The compliance score is calculated as:

```
Compliance Score = (Passed Tests / Total Tests) * 100
```

### Viewing Results

#### Command Line

Test results are displayed in the console with:
- ✅ Passed tests
- ❌ Failed tests
- Summary statistics

#### Dashboard

1. Start the dashboard:
```bash
npm run dashboard:api
npm run dashboard:frontend
```

2. Open `http://localhost:5173` (or the frontend port)

3. View compliance scores, test results, and trends

---

## Best Practices

### Test Suite Organization

1. **One suite per application**: Create separate suites for different applications
2. **Group by feature**: Create suites for specific features or modules
3. **Use descriptive names**: `research-tracker-api-tests` not `test-suite-1`

### Test Coverage

1. **Test all roles**: Include all user roles that interact with the application
2. **Test edge cases**: Include boundary conditions and error cases
3. **Test negative cases**: Verify that access is properly denied

### Resource Definition

1. **Realistic data**: Use realistic resource attributes
2. **Cover all sensitivity levels**: Test public, internal, confidential, restricted
3. **Include ABAC attributes**: If using ABAC, include relevant attributes

### Query Testing

1. **Representative queries**: Use queries that represent real application usage
2. **Test violations**: Include queries that should fail
3. **Test boundaries**: Test limits, filters, and aggregations

### Performance

1. **Limit test count**: Don't create too many test cases (aim for < 100)
2. **Use caching**: Enable caching for repeated evaluations
3. **Parallel execution**: Tests can run in parallel for speed

### Validator Development

1. **Use BaseValidator**: Extend `BaseValidator` for automatic error handling
2. **Provide metadata**: Include required config, tags, and examples
3. **Handle errors gracefully**: Return failed test results, don't throw
4. **Document configuration**: Provide clear examples and documentation

---

## Troubleshooting

### Tests Not Running

1. **Check suite file**: Ensure file exists in `tests/` directory
2. **Verify JSON syntax**: If using JSON, validate syntax
3. **Check imports**: If using TypeScript, verify exports
4. **Check environment variables**: Ensure required env vars are set

### Unexpected Results

1. **Review policies**: Check that policies match expectations
2. **Verify attributes**: Ensure user/resource attributes are correct
3. **Check context**: Verify context attributes are set properly
4. **Review expected decisions**: Ensure expected decisions are correct

### Validator Issues

1. **Check registration**: Ensure validator is registered with the registry
2. **Validate configuration**: Check that config passes `validateConfig()`
3. **Check shouldRun()**: Ensure `shouldRun()` returns true for your suite
4. **Review error messages**: Check error details in test results

### Performance Issues

1. **Reduce test count**: Limit number of resources/contexts
2. **Enable caching**: Set `cacheDecisions: true`
3. **Optimize queries**: Use simpler test queries
4. **Check database connections**: Ensure database connections are pooled

### Dashboard API Issues

1. **Check API is running**: Ensure API is started on correct port
2. **Verify CORS**: Check CORS configuration if accessing from frontend
3. **Check data files**: Ensure `dashboard-api/data/` files exist
4. **Review logs**: Check API logs for error messages

---

## Additional Resources

### Documentation

- **[Policy Creation Guide](./POLICY_CREATION_GUIDE.md)**: How to create RBAC and ABAC policies
- **[Test Creation Guide](./TEST_CREATION_GUIDE.md)**: Step-by-step guide for creating test suites
- **[Validator Creation Guide](./VALIDATOR_CREATION_GUIDE.md)**: How to create custom validators
- **[Quick Reference](./QUICK_REFERENCE.md)**: Quick reference for common tasks
- **[API Documentation](./API.md)**: Complete API endpoint documentation

### Examples

- **Basic Usage**: `examples/basic-usage.ts`
- **ABAC Usage**: `examples/abac-usage.ts`
- **API Security**: `examples/api-security-usage.ts`
- **Data Pipeline**: `examples/data-pipeline-usage.ts`
- **Distributed Systems**: `examples/distributed-systems-usage.ts`

### Test Suites

- **Example Suite**: `tests/example-test-suite.ts`
- **ABAC Suite**: `tests/abac-test-suite.ts`

### Validators

- **Example Validator**: `validators/example-salesforce-validator.ts`

---

## Support

For issues, questions, or contributions:

1. Check the documentation in `docs/`
2. Review examples in `examples/`
3. Check existing test suites in `tests/`
4. Review validator examples in `validators/`

---

## Conclusion

Heimdall provides a comprehensive testing framework for validating access control, data behavior, contracts, and dataset health. With support for RBAC, ABAC, Zero Trust Architecture, and extensive customization through validators, Heimdall can be adapted to test a wide variety of applications and security requirements.

This guide covers the basics of using Heimdall. For more detailed information, refer to the specialized guides mentioned in the Additional Resources section.

