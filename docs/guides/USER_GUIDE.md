# Heimdall User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [What is Heimdall?](#what-is-heimdall)
3. [Current Features & Support](#current-features--support)
4. [Getting Started](#getting-started)
5. [Test Management UI](#test-management-ui)
6. [Test Batteries](#test-batteries)
7. [Test Harnesses](#test-harnesses)
8. [Configuring Tests](#configuring-tests)
9. [Configuring Validators](#configuring-validators)
10. [Using the Dashboard API](#using-the-dashboard-api)
11. [Running Tests](#running-tests)
12. [Understanding Results](#understanding-results)
13. [Risk Acceptance Workflow](#risk-acceptance-workflow)
14. [Best Practices](#best-practices)
15. [Troubleshooting](#troubleshooting)

---

## Introduction

Heimdall is an automated testing framework that validates applications are adhering to access control requirements for data. It provides comprehensive testing capabilities for Zero Trust Architecture (ZTA) compliance, data access control, and security policy validation.

This guide will help you understand how to use Heimdall, what features are currently supported, and how to configure tests and validators for your applications.

---

## What is Heimdall?

Heimdall is a comprehensive testing framework designed to:

- **Validate Access Control**: Test Policy Decision Point (PDP) decisions for different user roles, attributes, resources, and contexts
- **Enforce Data Protection Rules**: Test export restrictions, aggregation requirements, field restrictions, and join restrictions via DLP test configurations
- **Assess Dataset Health**: Validate masked/synthetic data meets privacy thresholds (k-anonymity, l-diversity, t-closeness, differential privacy)
- **Support Zero Trust Architecture**: Comprehensive testing for identity, device, network, application, and data security

---

## Current Features & Support

### ✅ Core Testing Capabilities

#### 1. Access Control Testing
- **PDP Decision Testing**: Evaluate Policy Decision Point decisions for representative identities, attributes, resources, and contexts
- **RBAC Support**: Role-Based Access Control policy testing
- **ABAC Support**: Attribute-Based Access Control policy testing
- **Hybrid Mode**: Support for both RBAC and ABAC simultaneously

#### 2. Dataset Health Testing
- **Privacy Metrics**: k-anonymity, l-diversity, t-closeness, differential privacy
- **Statistical Fidelity**: Validate mean, median, stddev, distribution similarity
- **Masked Data Validation**: Test masked/synthetic data quality

### ✅ Zero Trust Architecture (ZTA) Features

#### Access Control
- **Policy Validation**: Detect policy conflicts, analyze coverage, test performance, run regression tests, simulate policy changes
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

### ✅ Environment Configuration Testing

#### Environment Variable Validation
- **Hardcoded Secret Detection**: Automatically detects hardcoded secrets in environment variables
- **Insecure Default Detection**: Identifies insecure default values
- **Environment Mismatch Detection**: Detects when environment variables don't match the environment type
- **Configuration File Security**: Validates file permissions and content security

#### Secrets Management Validation
- **Storage Security**: Validates encryption and access controls for secrets
- **Rotation Policies**: Tests secret rotation configuration and enforcement
- **Access Logging**: Validates audit trail for secret access
- **Injection Security**: Tests secure secret injection methods

#### Configuration Drift Detection
- **Baseline Creation**: Creates configuration baselines for comparison
- **Drift Detection**: Identifies unauthorized configuration changes
- **Environment Comparison**: Compares configurations across environments
- **Approval Workflow**: Validates configuration change approvals

#### Environment Policy Validation
- **Isolation Testing**: Tests environment isolation (e.g., prod cannot access dev)
- **Promotion Policies**: Validates environment promotion rules
- **Policy Inheritance**: Tests policy inheritance across environments

### ✅ API Security Testing Enhancements

#### API Versioning Security
- **Deprecation Testing**: Tests API version deprecation policies
- **Access Control**: Validates version-specific access controls
- **Backward Compatibility**: Tests backward compatibility between versions
- **Migration Security**: Validates secure migration paths

#### API Gateway Policy Validation
- **Routing Policies**: Tests gateway routing and policy enforcement
- **Authentication**: Validates gateway-level authentication
- **Rate Limiting**: Tests rate limiting and throttling policies
- **Transformation Security**: Validates request/response transformation security

#### Webhook Security
- **Authentication**: Tests webhook authentication (signatures, tokens)
- **Encryption**: Validates webhook payload encryption
- **Replay Prevention**: Tests replay attack prevention mechanisms
- **Rate Limiting**: Validates webhook rate limiting

#### GraphQL Security
- **Query Depth Limits**: Tests GraphQL query depth restrictions
- **Complexity Limits**: Validates query complexity limits
- **Introspection Security**: Tests GraphQL introspection security
- **Field Authorization**: Validates field-level authorization

#### API Contract Security
- **Schema Security**: Detects sensitive fields in API schemas
- **Versioning**: Tests API contract versioning security
- **Backward Compatibility**: Validates contract backward compatibility
- **Enforcement**: Tests contract validation and enforcement

### ✅ ABAC Implementation Correctness Testing

#### Attribute Validation
- **Schema Validation**: Validates ABAC attribute definitions and schemas
- **Source Trust**: Verifies attribute source integrity
- **Freshness**: Tests attribute value freshness and staleness
- **Access Control**: Validates attribute access controls

#### Policy Completeness
- **Coverage Testing**: Tests policy coverage for all resource types and user roles
- **Gap Analysis**: Identifies missing policies and coverage gaps
- **Edge Case Coverage**: Tests edge case policy coverage
- **Completeness Metrics**: Provides coverage percentage metrics

#### Performance Testing
- **Evaluation Latency**: Tests ABAC policy evaluation performance
- **Caching**: Validates policy evaluation caching effectiveness
- **Load Testing**: Tests performance under load
- **Optimization Recommendations**: Provides performance optimization suggestions

#### Conflict Resolution
- **Conflict Detection**: Detects conflicting ABAC policies
- **Resolution Testing**: Tests policy conflict resolution strategies
- **Priority Validation**: Validates policy priority resolution
- **Override Testing**: Tests policy override mechanisms

#### Attribute Propagation
- **Inheritance Testing**: Tests attribute inheritance and propagation
- **Cross-System Validation**: Validates attribute propagation across systems
- **Transformation Testing**: Tests attribute transformation and mapping
- **Consistency Validation**: Verifies attribute consistency across services

### ✅ Salesforce Experience Cloud Testing

Heimdall integrates with Google's [aura-inspector](https://github.com/google/aura-inspector) to test Salesforce Experience Cloud applications for security misconfigurations and vulnerabilities.

#### Prerequisites

Before using Salesforce Experience Cloud testing, ensure:
1. Python 3.x is installed
2. aura-inspector is installed: `pipx install git+https://github.com/google/aura-inspector`
3. The `aura_cli.py` script is accessible in PATH

#### Test Types

**Guest Access Testing**
- Tests accessible records from unauthenticated (Guest) context
- Identifies records that should not be publicly accessible
- Reports severity levels (critical, high, medium, low)

**Authenticated Access Testing**
- Tests accessible records from authenticated context
- Requires cookies or aura request file for authentication
- Validates proper access control enforcement

**GraphQL Capability Testing**
- Tests GraphQL Aura method availability
- Identifies security vulnerabilities in GraphQL endpoints
- Validates GraphQL query security

**Self-Registration Testing**
- Checks for self-registration capabilities
- Identifies potential security concerns with registration flows
- Validates registration security controls

**Record List Components Testing**
- Discovers Record List components
- Identifies misconfigured objects exposed via Record Lists
- Tests UI component security

**Home URLs Testing**
- Discovers Home URLs that could allow unauthorized admin access
- Identifies critical security vulnerabilities
- Tests administrative access controls

**Object Access Testing**
- Tests access to specific Salesforce objects
- Validates object-level security
- Supports testing multiple objects simultaneously

**Full Audit**
- Runs all test types in a single execution
- Provides comprehensive security assessment
- Returns results grouped by test type

#### Usage Example

```typescript
import { SalesforceExperienceCloudTester } from './services/salesforce-experience-cloud-tester';

const config = {
  url: 'https://example.force.com',
  cookies: 'sid=...;', // Optional: for authenticated tests
  objectList: ['Account', 'Contact'], // Optional: specific objects
  timeout: 300000, // 5 minutes
};

const tester = new SalesforceExperienceCloudTester(config);

// Run individual tests
const guestResult = await tester.testGuestAccess();
const authResult = await tester.testAuthenticatedAccess();
const graphqlResult = await tester.testGraphQLCapability();

// Or run full audit
const auditResults = await tester.runFullAudit();
```

#### Configuration Options

- `url` (required): Root URL of Salesforce application
- `cookies` (optional): Cookies for authenticated context
- `objectList` (optional): Specific objects to test
- `app` (optional): Custom app path (e.g., "/myApp")
- `aura` (optional): Custom aura path (e.g., "/aura")
- `timeout` (optional): Execution timeout in milliseconds
- `pythonPath` (optional): Python executable path (default: "python3")
- `auraInspectorPath` (optional): Path to aura-inspector installation

### 📊 Dashboard API Support

The Dashboard API provides REST endpoints for:

- **Test Configurations**: Create, read, update, delete test configurations
- **RLS/CLS Testing**: Test Row-Level and Column-Level Security
- **Network Policy Testing**: Test firewall rules and network segmentation
- **DLP Testing**: Test data loss prevention policies
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
cd shiny-waddle

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

## Test Management UI

The Heimdall Dashboard provides a comprehensive UI for managing tests, viewing results, and tracking compliance. **Important**: The UI is for viewing and managing test configurations only - tests run automatically in CI/CD during builds.

### Navigation Structure

The dashboard is organized into the following main sections:

1. **Dashboard** (`/` or `/insights`) - Overview, stats, recent findings, quick links
2. **Applications** (`/applications`) - View applications and their assigned test harnesses
3. **Tests** (`/tests`) - Test management with multiple tabs:
   - **Test Batteries** - View and manage test batteries (collections of harnesses)
   - **Test Harnesses** - View and manage test harnesses (collections of suites)
   - **Test Suites** - View and manage test suites
   - **Test Library** - Browse available test types and configurations
   - **Findings** - Review test results, violations, risk acceptance
4. **Reports** (`/reports`) - Generate and view compliance reports

### Test Hierarchy

Tests are organized in a hierarchical structure:

```
Test Battery (collection of different types of harnesses with execution config)
  └── Test Harness (collection of suites of the same type, assigned to applications)
      └── Test Suite (tests of a single type, e.g., all ABAC read tests)
          └── Individual Tests (test functions)
```

**Key Relationships:**
- **Test**: Smallest unit (individual test function)
- **Test Suite**: Contains tests of the same type (e.g., all ABAC read tests, all API security tests)
- **Test Harness**: Contains test suites of the same type (e.g., all ABAC test suites)
- **Test Battery**: Contains different types of test harnesses (e.g., ABAC harness + API Security harness)
- **Test Suite**: Can belong to multiple Test Harnesses (many-to-many, but all must match harness type)
- **Test Harness**: Global entity, can be assigned to multiple applications
- **Application**: Has Test Harnesses assigned to it

**Type-Based Organization:**
- Each Test Suite has exactly one `testType` (e.g., 'access-control', 'api-security')
- Each Test Harness has exactly one `testType`, and all suites in it must match that type
- Each Test Battery must contain harnesses with different types (no duplicate types allowed)

---

## Test Batteries

Test Batteries are collections of Test Harnesses with execution configuration. They allow you to group related harnesses together and configure how they should be executed.

### Creating a Test Battery

1. Navigate to **Tests** → **Test Batteries** tab
2. Click **Create Test Battery**
3. Fill in the form:
   - **Name**: Descriptive name for the battery
   - **Description**: Optional description
   - **Team**: Team responsible for this battery
   - **Test Harnesses**: Select one or more harnesses to include
   - **Execution Config**:
     - **Execution Mode**: `parallel` or `sequential`
     - **Timeout**: Maximum execution time in milliseconds (optional)
     - **Stop on Failure**: Whether to stop execution if a harness fails
4. Click **Save**

### Managing Test Batteries

- **View Battery**: Click on a battery card to see details, associated harnesses, and execution configuration
- **Edit Battery**: Click the **Edit** button on the battery detail page
- **Add/Remove Harnesses**: Use the edit form to manage harnesses in the battery
- **Delete Battery**: Use the delete button (be careful - this cannot be undone)

### Execution Configuration

- **Parallel Mode**: All harnesses in the battery run simultaneously (faster, but uses more resources)
- **Sequential Mode**: Harnesses run one after another (slower, but uses fewer resources)
- **Stop on Failure**: If enabled, execution stops when any harness fails (useful for critical batteries)

---

## Test Harnesses

Test Harnesses are collections of Test Suites that can be assigned to applications. They provide a way to organize and group related test suites together.

### Creating a Test Harness

1. Navigate to **Tests** → **Test Harnesses** tab
2. Click **Create Test Harness**
3. Fill in the form:
   - **Name**: Descriptive name for the harness
   - **Description**: Optional description
   - **Team**: Team responsible for this harness
   - **Test Suites**: Select one or more test suites to include
   - **Applications**: Select applications to assign this harness to
4. Click **Save**

### Managing Test Harnesses

- **View Harness**: Click on a harness card to see details, associated suites, and assigned applications
- **Edit Harness**: Click the **Edit** button on the harness detail page
- **Add/Remove Suites**: Use the edit form to manage suites in the harness
- **Assign to Applications**: Use the edit form or the Applications page to assign harnesses

### Assignment Workflow

#### Assigning Harnesses to Applications

**Method 1: From Harness Detail Page**
1. Navigate to **Tests** → **Test Harnesses**
2. Click on a harness to view details
3. Click **Edit**
4. Select applications in the **Applications** multi-select
5. Click **Save**

**Method 2: From Application Detail Page**
1. Navigate to **Applications**
2. Click on an application to view its detail page
3. Click **Manage Assignments** button
4. In the **Test Harnesses** section, click **Assign Harness** to add a new harness
5. Select a harness from the list to assign it
6. To unassign a harness, click **Unassign** next to the harness
7. Changes are saved automatically

**Method 3: From Applications List Page**
1. Navigate to **Applications**
2. In the applications table, find the application you want to manage
3. Click the **Manage Assignments** button in the Actions column
4. A modal will open showing the assignment manager
5. In the **Test Harnesses** section:
   - Click **Assign Harness** to add a new harness
   - Select a harness from the available list
   - Click **Unassign** to remove a harness assignment
6. Close the modal when done - changes are saved automatically

**Note:** Test Batteries are automatically shown based on the harnesses assigned to the application. You cannot directly assign batteries - they are derived from the harness assignments.

#### Viewing Assignments

- **From Application Page**: See all harnesses and batteries assigned to an application
- **From Harness Detail**: See all applications the harness is assigned to
- **From Suite Detail**: See which harnesses contain the suite

### Many-to-Many Relationships

- **Suites ↔ Harnesses**: A test suite can belong to multiple harnesses, and a harness can contain multiple suites
- **Harnesses ↔ Applications**: A harness can be assigned to multiple applications, and an application can have multiple harnesses

---

## Configuring Tests

### Test Suite Structure

A test suite defines what to test, who to test, what resources to test against, and how to validate results. **Each test suite must have exactly one test type.**

#### Basic Test Suite

Create a test suite file in `tests/` directory (TypeScript or JSON). Each suite must specify a single `testType`:

**TypeScript** (`tests/my-access-control-suite.ts`):
```typescript
import { AccessControlTestSuite } from '../core/types';

export const myAccessControlSuite: AccessControlTestSuite = {
  name: 'My Application Access Control Tests',
  application: 'my-app',
  team: 'my-team',
  testType: 'access-control', // Required: single test type
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
  expectedDecisions: {
    'admin-resource-1': true,
    'viewer-resource-1': true,
  },
};
```

**JSON** (`tests/my-test-suite.json`):
```json
{
  "name": "My Application Tests",
  "application": "my-app",
  "team": "my-team",
  "includeAccessControlTests": true,
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

#### 2. Dataset Health Tests

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

## Managing Application Test and Validator Overrides

Data stewards and cyber risk managers can control which tests and validators run for specific applications. This allows fine-grained control over compliance testing per application.

### Accessing Application Test Management

1. Navigate to **Admin** → **Applications** tab
2. Click **"Manage Tests"** on any application card
3. You'll see two sections:
   - **Test Configuration Management**: Control which test configurations run
   - **Validator Management**: Control which validators are used

### Toggling Test Configurations

1. In the **Test Configuration Management** section, you'll see all test configurations assigned to the application
2. Use the toggle switch to enable/disable a test configuration
3. A modal will appear where you can optionally provide a reason
4. Click **Enable** or **Disable** to confirm
5. The override will be saved and the test configuration will be skipped during test runs if disabled

### Toggling Validators

1. In the **Validator Management** section, you'll see all available validators
2. Use the toggle switch to enable/disable a validator for this application
3. A modal will appear where you can optionally provide a reason
4. Click **Enable** or **Disable** to confirm
5. The override will be saved

### Removing Overrides

If an override exists, you'll see a **"Remove Override"** button. Clicking this will:
- Remove the application-specific override
- Revert to the default state (test configuration's or validator's global enabled status)

### Bulk Operations

Use the **"Bulk Toggle"** button to:
- Select multiple test configurations or validators
- Enable or disable them all at once
- Apply changes with a single action

### Understanding Override Status

- **Green toggle (enabled)**: The test/validator will run for this application
- **Gray toggle (disabled)**: The test/validator will be skipped for this application
- **Override indicator**: Shows if an override exists, who set it, when, and the reason

### Best Practices

- **Document reasons**: Always provide a reason when toggling, especially when disabling
- **Review regularly**: Periodically review overrides to ensure they're still needed
- **Use bulk operations**: When making multiple changes, use bulk toggle for efficiency
- **Remove when done**: Remove overrides once they're no longer needed

## Configuring Validators

### What are Validators?

Validators are extensible components that perform specific validation tasks. Heimdall uses a plugin-style architecture where validators can be registered and automatically discovered.

### Built-in Validators

Heimdall includes validators for:

- **Access Control**: Tests PDP decisions
- **Dataset Health**: Validates privacy and statistical metrics
- **RLS/CLS**: Tests Row-Level and Column-Level Security
- **Network Policy**: Tests firewall rules and segmentation
- **DLP**: Tests data loss prevention
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

The `TestOrchestrator` class automatically discovers and uses registered validators:

```typescript
const orchestrator = new TestOrchestrator(config);
// Validators are automatically discovered and used
const results = await orchestrator.runTestSuite(suite);
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

#### 4. API Gateway Configuration

```json
{
  "name": "API Gateway Policies",
  "type": "api-gateway",
  "policies": [...],
  "rateLimits": {...}
}
```

#### 5. Distributed Systems Configuration

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

#### Environment Configuration API

- **POST `/api/environment-config/validate`** - Validate environment variables
- **POST `/api/environment-config/validate-secrets`** - Validate secrets management
- **POST `/api/environment-config/detect-drift`** - Detect configuration drift
- **POST `/api/environment-config/validate-policies`** - Validate environment policies

#### ABAC Correctness API

- **POST `/api/abac-correctness/validate-attributes`** - Validate ABAC attributes
- **POST `/api/abac-correctness/test-completeness`** - Test policy completeness
- **POST `/api/abac-correctness/test-performance`** - Test ABAC performance
- **POST `/api/abac-correctness/detect-conflicts`** - Detect policy conflicts
- **POST `/api/abac-correctness/test-propagation`** - Test attribute propagation

#### Salesforce Experience Cloud API

- **POST `/api/salesforce-experience-cloud/configs`** - Create test configuration
- **GET `/api/salesforce-experience-cloud/configs`** - List configurations
- **POST `/api/salesforce-experience-cloud/tests/guest-access`** - Test guest access
- **POST `/api/salesforce-experience-cloud/tests/authenticated-access`** - Test authenticated access
- **POST `/api/salesforce-experience-cloud/tests/graphql`** - Test GraphQL capability
- **POST `/api/salesforce-experience-cloud/tests/self-registration`** - Test self-registration
- **POST `/api/salesforce-experience-cloud/tests/record-lists`** - Test record list components
- **POST `/api/salesforce-experience-cloud/tests/home-urls`** - Test home URLs
- **POST `/api/salesforce-experience-cloud/tests/object-access`** - Test object access
- **POST `/api/salesforce-experience-cloud/tests/full-audit`** - Run full audit
- **GET `/api/salesforce-experience-cloud/results`** - List test results

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
import { TestOrchestrator } from './core/test-harness';
import { loadTestSuite } from './tests/test-suite-loader';
import { TestConfiguration } from './core/types';

// Load test suite
const suite = await loadTestSuite('my-test-suite');

// Create configuration
const config: TestConfiguration = {
  accessControlConfig: {
    policyEngine: 'custom',
    cacheDecisions: true,
    policyMode: 'hybrid',
  },
  dataBehaviorConfig: {
    enableQueryLogging: true,
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

// Initialize TestOrchestrator
const orchestrator = new TestOrchestrator(config);

// Run tests
const results = await orchestrator.runTestSuite(suite);

// Check compliance
const isCompliant = orchestrator.isCompliant(results);
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

### Viewing Test Results

Test results are available in the **Tests** → **Findings** tab. You can:

- **Filter Results**: Filter by test suite, harness, battery, application, status, or type
- **View Details**: Click on a result to see detailed information
- **Timeline View**: Switch to timeline view to see execution history chronologically
- **List View**: Switch to list view for a traditional table layout

### Result Status

- **Passed**: All tests in the suite passed
- **Failed**: One or more tests failed
- **Partial**: Some tests passed, some failed
- **Error**: Test execution encountered an error

### Filtering Results

The Findings tab supports multiple filters:

- **Test Suite**: Filter by specific test suite
- **Test Harness**: Filter by harness (shows results for all suites in the harness)
- **Test Battery**: Filter by battery (shows results for all harnesses in the battery)
- **Application**: Filter by application
- **Status**: Filter by pass/fail status
- **Type**: Filter by test type (access-control, etc.)

---

## Risk Acceptance Workflow

When a test fails, you may need to accept the risk if it's a false positive or acceptable risk. The dashboard provides a workflow for accepting risk directly on test results.

### Accepting Risk on Test Results

You can accept risk directly on individual test results without going through a request/approval workflow. This is useful for quick risk acceptance when you have the authority to make the decision.

**Step-by-Step Guide:**

1. Navigate to **Tests** → **Findings** tab
2. Find a failed test result that you want to accept risk for
3. Click **Accept Risk** button (or use the action menu)
4. Fill in the risk acceptance form:
   - **Reason** (required): Explain why you're accepting this risk
     - Example: "False positive - test configuration issue"
     - Example: "Acceptable risk - documented exception"
   - **Approver** (required): Your email or identifier
   - **Expiration Date** (optional): Set when the risk acceptance should expire
     - Leave blank for permanent acceptance
     - Useful for temporary exceptions that need review
   - **Ticket Link** (optional): Link to tracking ticket or issue
     - Example: "https://jira.example.com/bug/12345"
5. Click **Accept Risk**

**Example Scenarios:**

- **False Positive**: Test is incorrectly failing due to test configuration issues
- **Documented Exception**: Risk is acceptable and documented in policy
- **Temporary Exception**: Risk is acceptable for a limited time period

### Expiration and Renewal

If you set an expiration date on a risk acceptance:

- The risk acceptance will automatically expire on that date
- You'll need to renew it if the risk is still acceptable
- Expired risk acceptances will show as expired in the UI
- You can renew by accepting risk again with a new expiration date

### Rejecting Risk

If you need to reject a previously accepted risk:

1. Navigate to **Tests** → **Findings** tab
2. Find the test result with accepted risk
3. Click **Reject Risk** button
4. Fill in the form:
   - **Reason** (required): Explain why you're rejecting the risk
   - **Approver** (required): Your email or identifier
5. Click **Reject Risk**

**Note:** This workflow is for direct risk acceptance on test results. For formal risk acceptance requests that require approval workflows, see the Finding Approvals module documentation.

### Remediation Tracking Workflow

For test results that need to be fixed, you can track remediation progress with detailed status, steps, and progress tracking.

**Starting Remediation:**

1. Navigate to **Tests** → **Findings** tab
2. Find a failed test result that needs remediation
3. Click **Start Remediation** or **Update Remediation** button
4. Fill in the remediation form:
   - **Status**: Current remediation status
     - `not-started`: Remediation hasn't begun
     - `in-progress`: Actively working on remediation
     - `completed`: Remediation is finished
   - **Assigned To**: Email or identifier of person responsible
   - **Target Date**: When you plan to complete remediation
   - **Ticket Link**: Link to tracking ticket (e.g., JIRA, GitHub issue)
   - **Progress**: Percentage complete (0-100)
   - **Notes**: Additional notes about progress, blockers, or context
   - **Steps**: Define remediation steps with status tracking
5. Click **Save**

**Defining Remediation Steps:**

You can break down remediation into discrete steps for better tracking:

1. Click **Add Step** in the remediation form
2. Enter a description of the step (e.g., "Identify root cause", "Update RLS policies")
3. Set the step status:
   - `pending`: Step hasn't started
   - `in-progress`: Currently working on this step
   - `completed`: Step is finished
4. Steps are automatically marked as completed when you update their status

**Example Remediation Steps:**

```
1. Identify root cause (completed)
2. Update RLS policies (in-progress)
3. Verify fix with tests (pending)
4. Deploy to production (pending)
```

**Updating Remediation Progress:**

As you work on remediation, you can update progress:

1. Navigate to the test result in **Tests** → **Findings** tab
2. Click **Update Remediation**
3. Update any of the following:
   - **Status**: Change from `in-progress` to `completed` when done
   - **Progress**: Update percentage as you make progress
   - **Steps**: Mark steps as completed as you finish them
   - **Notes**: Add updates about progress, blockers, or changes
   - **Ticket Link**: Update if ticket changes
4. Click **Save**

**Best Practices:**

- **Set Target Dates**: Always set a target date to track against deadlines
- **Link Tickets**: Link to your issue tracker for full context
- **Break into Steps**: Define clear steps for complex remediations
- **Update Regularly**: Update progress as you work to keep stakeholders informed
- **Document Blockers**: Use notes to document blockers or dependencies
- **Mark Complete**: Don't forget to mark status as `completed` when done

### Risk Status Indicators

Test results show risk status with badges:
- **No Risk**: No risk acceptance has been set
- **Accepted**: Risk has been accepted (may show expiration date if set)
- **Rejected**: Risk acceptance was rejected
- **Expired**: Risk acceptance has expired (if expiration date was set)

**Understanding Risk Acceptance:**
- Risk acceptance is immediate - no approval workflow required
- You can set expiration dates for temporary exceptions
- Expired acceptances need to be renewed
- Rejected risks indicate the risk must be remediated

### Remediation Status Indicators

Test results show remediation status with badges:
- **Not Started**: No remediation tracking has been set up
- **In Progress**: Remediation is actively being worked on
- **Completed**: Remediation is finished

**Understanding Remediation Status:**
- Status transitions: `not-started` → `in-progress` → `completed`
- Progress percentage shows completion (0-100%)
- Steps show detailed breakdown of remediation work
- Target dates help track against deadlines

---

### Test Result Structure

```typescript
interface TestResult {
  testType: 'access-control' | 'contract' | 'dataset-health';
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

Heimdall provides a comprehensive testing framework for validating access control, contracts, and dataset health. With support for RBAC, ABAC, Zero Trust Architecture, and extensive customization through validators, Heimdall can be adapted to test a wide variety of applications and security requirements.

This guide covers the basics of using Heimdall. For more detailed information, refer to the specialized guides mentioned in the Additional Resources section.

