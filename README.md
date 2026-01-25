# Heimdall

Heimdall is an automated testing framework that validates applications are adhering to access control requirements for data.

## Features

### Core Testing Capabilities

- **User Simulation**: Simulate users with different roles/attributes
- **Access Control Tests**: Evaluate Policy Decision Point (PDP) decisions for representative identities, attributes, resources, and contexts
- **Contract Tests**: Machine-readable requirements → generated tests (e.g., "No raw email export," "Min aggregation ≥ k=10")
- **Dataset Health Tests**: Assert masked/synthetic data meets privacy thresholds (k-anonymity, l-diversity, t-closeness, differential privacy) and statistical fidelity targets
- **Ephemeral Environments**: Spin up per-PR with seeded masked/synthetic data; run full harness before merge
- **CI/CD Integration**: Block merges on access violations with GitHub Actions
- **Compliance Dashboard**: Show compliance score by application, team, dataset
- **Integration Hooks**: SAST/DAST/DBT/Great Expectations integration for schema, constraint, and data-quality tests
- **API Security Testing**: Comprehensive REST/GraphQL API security testing including authentication, authorization, rate limiting, and vulnerability detection
- **Data Pipeline Testing**: Test ETL pipelines, streaming data, data transformations, and pipeline security controls
- **Distributed Systems Testing**: Test access control across multiple regions, verify policy consistency, test synchronization, and distributed transactions
- **Salesforce Experience Cloud Testing**: Test Salesforce Experience Cloud applications for security misconfigurations using Google's aura-inspector tool

### Zero Trust Architecture (ZTA) Features

#### Access Control
- **Policy Validation**: Detect policy conflicts, analyze coverage, test performance, run regression tests, and simulate policy changes
- **Identity Providers**: Test AD group membership, Okta/Auth0/Azure AD policy synchronization, GCP IAM bindings, and cross-system policy validation

#### Data Security
- **RLS/CLS Testing**: Test Row-Level Security and Column-Level Security coverage, dynamic masking, cross-tenant isolation, and policy bypass attempts
- **DLP (Data Loss Prevention)**: Test data exfiltration detection, API response validation, query validation, and bulk export controls

#### Application Security
- **API Gateway**: Test gateway policies, rate limiting, API versioning, and service-to-service authentication
- **DLP**: Comprehensive data loss prevention testing

#### Platform Security
- **Network Policies**: Test firewall rules, service-to-service connectivity, network segmentation, and service mesh policies

#### Compliance
- **NIST 800-207**: Zero Trust Architecture compliance assessment and reporting

#### CI/CD Security
- **Security Gates**: Pre-merge policy validation, IAC scanning, container scanning, K8s RBAC validation, and configurable security gates

## Architecture

```
heimdall/
├── heimdall-framework/      # Core testing framework (reusable library)
│   ├── core/                # Core framework components
│   │   ├── test-harness.ts      # Main orchestrator
│   │   └── types.ts             # Type definitions
│   ├── services/            # Test service implementations
│   │   ├── user-simulator.ts    # User role/attribute simulation
│   │   ├── access-control-tester.ts  # PDP decision evaluation
│   │   ├── contract-tester.ts       # Contract requirement testing
│   │   ├── dataset-health-tester.ts  # Privacy & statistical tests
│   │   ├── compliance-reporter.ts   # Report generation
│   │   ├── policy-decision-point.ts  # PDP implementation
│   │   ├── query-analyzer.ts         # SQL/API query analysis
│   │   ├── pii-masking-validator.ts  # PII detection & masking validation
│   │   ├── api-security-tester.ts   # API security testing (REST, GraphQL, rate limiting)
│   │   └── data-pipeline-tester.ts  # Data pipeline testing (ETL, streaming, security)
│   ├── tests/               # Test suites
│   │   ├── example-test-suite.ts     # Example configuration
│   │   └── test-suite-loader.ts      # Suite loading utilities
│   ├── validators/          # Validator implementations
│   ├── policies/            # Policy definitions
│   │   └── example-policy.json       # Example access control policy
│   ├── src/                 # Entry point
│   │   └── run-tests.ts          # Main test runner
│   └── index.ts             # Framework exports
├── dashboard-api/           # NestJS REST API backend
├── dashboard-frontend/      # Vue.js web UI
├── ci-cd/                   # CI/CD integration scripts
│   ├── github-actions.yml        # GitHub Actions workflow
│   └── check-compliance.js       # Compliance check script
├── ephemeral/               # Ephemeral environment setup
│   └── environment-setup.ts      # Per-PR environment creation
└── examples/                # Example code
```

## Directory Structure

This section provides a detailed overview of the project structure for new developers. Understanding the organization is crucial for navigating the codebase effectively.

### Framework vs. Dashboard Separation

The project is organized into two main parts:

1. **Framework Code** (`/heimdall-framework`) - Shared testing framework that can be used independently
   - Contains: `/core`, `/services`, `/tests`, `/validators`, `/policies`, `/src`
2. **Dashboard Code** (`/dashboard-api`, `/dashboard-frontend`) - Web UI and API for managing tests through a browser

The framework code is organized under `/heimdall-framework` because it's designed to be:
- **Reusable**: Can be imported by CLI tools, CI/CD pipelines, or other applications
- **Standalone**: Can run tests without the dashboard (see `heimdall-framework/src/run-tests.ts`)
- **Framework-agnostic**: Core logic doesn't depend on NestJS or Vue.js
- **Well-organized**: Clear separation makes it easy to extract as a separate package if needed

### Core Directories

#### `/heimdall-framework/core` - Framework Foundation

The `/heimdall-framework/core` directory contains the foundational components that define the framework's architecture:

- **`test-harness.ts`** - Main `TestOrchestrator` class that coordinates test execution
- **`types.ts`** - TypeScript type definitions for all framework entities (Test, TestSuite, TestResult, etc.)
- **`test-battery.ts`** - `TestBatteryRunner` for executing collections of test harnesses
- **`base-validator.ts`** - Base class that all validators extend
- **`validator-registry.ts`** - Registry system for discovering and loading validators
- **`config-loader.ts`** - Utilities for loading runtime configuration from files or environment variables
- **`runtime-config.ts`** - Runtime configuration types and utilities
- **`domain-mapping.ts`** - Maps test types to domains (api_security, platform_config, etc.)
- **`unified-finding-schema.ts`** - Unified schema for security findings across different scanners
- **`schema-versioning.ts`** - Schema versioning and migration utilities
- **`schema-migrations.ts`** - Schema migration implementations

**Key Principle**: `/core` defines the framework's contract. Services depend on core, but core doesn't depend on services.

#### `/heimdall-framework/services` - Test Implementations

The `/heimdall-framework/services` directory contains concrete implementations of testing services. These are the actual testers that execute specific types of tests:

**Core Testing Services:**
- **`access-control-tester.ts`** - Tests Policy Decision Point (PDP) decisions
- **`dataset-health-tester.ts`** - Validates privacy metrics (k-anonymity, l-diversity, etc.)
- **`compliance-reporter.ts`** - Generates compliance reports in various formats
- **`policy-decision-point.ts`** - Implements the PDP logic for evaluating policies

**Security Testing Services:**
- **`api-security-tester.ts`** - Tests REST/GraphQL APIs for security vulnerabilities
- **`data-pipeline-tester.ts`** - Tests ETL pipelines and data transformations
- **`distributed-systems-tester.ts`** - Tests access control across distributed systems
- **`api-gateway-tester.ts`** - Tests API gateway policies and configurations

**Supporting Services:**
- **`abac-policy-loader.ts`** - Loads ABAC policies from files
- **`query-analyzer.ts`** - Analyzes SQL/API queries for security issues
- **`pii-masking-validator.ts`** - Validates PII detection and masking
- **`risk-scorer.ts`** - Calculates risk scores for findings
- **`normalization-engine.ts`** - Normalizes findings from different scanners

**Subdirectories:**
- **`/test-suites`** - Pre-built test suite implementations (authentication, authorization, injection, etc.)
- **`/scanner-adapters`** - Adapters for external security scanners (Trivy, Snyk, Checkov, etc.)
- **`/payloads`** - Security testing payloads (SQL injection, XSS, etc.)
- **`/utils`** - Utility functions (JWT validation, header analysis, PII detection)

**Key Principle**: Services import from `/core` but are independent of each other. Each service can be used standalone or composed together.

#### `/heimdall-framework/tests` - Test Suites

The `/heimdall-framework/tests` directory contains example test suite definitions and loaders:

- **`test-suite-loader.ts`** - Utility for loading test suites from files
- **`example-access-control-suite.ts`** - Example access control test suite
- **`example-dataset-health-suite.ts`** - Example dataset health test suite
- **`abac-*-suite.ts`** - Various ABAC-specific test suites

These are example/test implementations. In production, test suites are typically stored in the database and managed through the dashboard API.

#### `/heimdall-framework/validators` - Validator Implementations

The `/heimdall-framework/validators` directory contains concrete validator implementations that extend the base validator:

- **`access-control-validator-adapter.ts`** - Adapter for access control validation
- **`salesforce-experience-cloud-validator.ts`** - Validator for Salesforce Experience Cloud
- **`abac-correctness-validator.ts`** - Validates ABAC policy correctness

Validators are pluggable components that can be registered and used by the framework.

#### `/heimdall-framework/policies` - Policy Definitions

The `/heimdall-framework/policies` directory contains example policy files:

- JSON files with example ABAC/RBAC policies
- Used for testing and as templates

In production, policies are typically stored in the database and managed through the dashboard API.

### Dashboard Directories

#### `/dashboard-api` - NestJS Backend

The `/dashboard-api` directory contains the REST API backend built with NestJS:

- **`src/`** - Source code
  - **`applications/`** - Application management endpoints
  - **`tests/`** - Test management endpoints
  - **`test-suites/`** - Test suite management endpoints
  - **`test-harnesses/`** - Test harness management endpoints
  - **`test-batteries/`** - Test battery management endpoints
  - **`policies/`** - Policy management endpoints
  - **`test-results/`** - Test result storage and querying
  - **`compliance/`** - Compliance reporting endpoints
  - **`api-security/`** - API security testing endpoints
  - **`data-pipeline/`** - Data pipeline testing endpoints
  - **`validators/`** - Validator management endpoints
  - And many more modules...

**Import Pattern**: Dashboard API services import from the framework:
```typescript
import { Test, TestType } from '../../../heimdall-framework/core/types';
import { APISecurityTester } from '../../../heimdall-framework/services/api-security-tester';
```

#### `/dashboard-frontend` - Vue.js Frontend

The `/dashboard-frontend` directory contains the web UI built with Vue.js 3:

- **`src/components/`** - Reusable Vue components
- **`src/views/`** - Page-level components
- **`src/types/`** - TypeScript types (often mirroring core types)
- **`src/composables/`** - Composition API utilities
- **`src/utils/`** - Utility functions

The frontend communicates with the dashboard API via HTTP requests.

### Supporting Directories

#### `/heimdall-framework/src` - Entry Points

- **`run-tests.ts`** - Standalone CLI entry point for running tests without the dashboard
- **`index.ts`** (at `/heimdall-framework/index.ts`) - Main framework export file (exports core classes and services)

#### `/data` - Data Storage

JSON files used for data persistence by the dashboard API (can be migrated to a database):
- `applications.json`, `tests.json`, `policies.json`, `api-security-configs.json`, `validation-targets.json`, etc.

#### `/heimdall-framework/ephemeral` - Ephemeral Environments

- **`environment-setup.ts`** - Utilities for creating per-PR ephemeral environments (uses the framework to run tests)

#### `/ci-cd` - CI/CD Integration

- GitHub Actions workflows and scripts for CI/CD integration

#### `/docs` - Documentation

Comprehensive documentation organized by category:
- `/docs/guides/` - User guides
- `/docs/api/` - API documentation
- `/docs/product/` - Product documentation

#### `/examples` - Example Code

Working examples demonstrating framework usage

### Import Patterns

Understanding import patterns helps navigate the codebase:

**From Dashboard API to Framework:**
```typescript
// Import types from core
import { Test, TestSuite } from '../../heimdall-framework/core/types';

// Import services
import { APISecurityTester } from '../../heimdall-framework/services/api-security-tester';

// Import utilities
import { getDomainFromTestType } from '../../heimdall-framework/core/domain-mapping';
```

**From Services to Core (within framework):**
```typescript
// Services import from core (relative paths within heimdall-framework)
import { User, Resource, Context } from '../core/types';
```

**From Core:**
```typescript
// Core only imports from itself or external dependencies
// Core does NOT import from services
```

### Where to Start

For new developers:

1. **Understanding the Framework**: Start with `/heimdall-framework/core/types.ts` to understand the data models
2. **Running Tests**: Look at `/heimdall-framework/src/run-tests.ts` to see how tests are executed
3. **Adding a Service**: Check `/heimdall-framework/services/access-control-tester.ts` as a reference implementation
4. **Dashboard Development**: Start with `/dashboard-api/src/applications/` to understand the API structure
5. **Frontend Development**: Start with `/dashboard-frontend/src/views/` to understand the UI structure

## Quick Start

### Installation

```bash
cd sentinel
npm install
```

### Running Tests

```bash
# Run default test suite
npm run test:compliance

# Run with custom suite
TEST_SUITE=my-suite npm run test:compliance

# Run with ABAC policies
POLICY_MODE=abac TEST_SUITE=abac-test-suite npm run test:compliance

# Watch mode
npm run test:compliance:watch
```

## Documentation

### Core Documentation
- **[Policy Creation Guide](./docs/POLICY_CREATION_GUIDE.md)**: Comprehensive guide for creating RBAC and ABAC policies
- **[Test Creation Guide](./docs/TEST_CREATION_GUIDE.md)**: Step-by-step guide for creating test suites
- **[Quick Reference](./docs/QUICK_REFERENCE.md)**: Quick reference for common tasks and patterns
- **[Feature Roadmap](./docs/FEATURE_ROADMAP.md)**: Recommended enhancements and future features
- **[Examples](./examples/)**: Complete working examples

### API & Implementation Documentation
- **[API Documentation](./docs/API.md)**: Complete API endpoint documentation with request/response examples
- **[Testing Guide](./docs/TESTING.md)**: Comprehensive guide for writing and running tests (unit, integration, E2E)
- **[Service Implementation Guide](./docs/SERVICES.md)**: Guide for implementing and extending services
- **[Implementation Progress](./docs/IMPLEMENTATION_PROGRESS.md)**: Current implementation status and progress tracking

### Documentation Overview

The documentation is organized into several guides:

1. **API Documentation**: Complete API reference for all endpoints
   - Request/response formats
   - Error handling
   - Authentication (when implemented)
   - Examples for all endpoints

2. **Testing Guide**: Comprehensive testing documentation
   - Unit test patterns
   - E2E test patterns
   - Test utilities and helpers
   - Best practices

3. **Service Implementation Guide**: Guide for implementing services
   - Service architecture
   - Provider interfaces
   - Configuration patterns
   - Error handling
   - Adding new services

4. **Policy Creation Guide**: Detailed instructions for creating both RBAC and ABAC policies
   - Policy structure and syntax
   - Available operators and conditions
   - Best practices and examples
   - Troubleshooting

5. **Test Creation Guide**: Step-by-step instructions for creating test suites
   - Test suite structure
   - All test types (access control, contracts, dataset health)
   - Configuration options
   - Best practices and examples

3. **Quick Reference**: Concise reference for common tasks
   - Policy templates
   - Test suite templates
   - Common patterns
   - Troubleshooting checklist

### Configuration

Create a test suite configuration file in `tests/suites/`:

```typescript
{
  "name": "My Application Tests",
  "application": "my-app",
  "team": "my-team",
  "includeAccessControlTests": true,
  "userRoles": ["admin", "viewer"],
  "resources": [...],
  "testQueries": [...]
}
```

## Test Types

### 1. Access Control Tests

Tests Policy Decision Point (PDP) decisions for:
- Different user roles (admin, researcher, analyst, viewer)
- Various resource types and sensitivity levels
- Different contexts (IP address, time of day, location)

### 2. Contract Tests

Tests machine-readable requirements from data owners:
- Field restrictions (e.g., "No raw email export")
- Aggregation requirements (e.g., "Min aggregation ≥ k=10")
- Join restrictions
- Export restrictions

### 4. Dataset Health Tests

Validates:
- Privacy thresholds (k-anonymity, l-diversity, t-closeness, differential privacy)
- Statistical fidelity (mean, median, stddev, distribution similarity)

## CI/CD Integration

The framework includes GitHub Actions workflow that:
1. Runs compliance tests on every PR
2. Blocks merges if compliance score is below threshold
3. Comments on PR with test results
4. Uploads test reports as artifacts

Configure in `.github/workflows/compliance-tests.yml`:

```yaml
- name: Run compliance tests
  run: npm run test:compliance
  env:
    MIN_COMPLIANCE_SCORE: 100
```

## Ephemeral Environments

For per-PR testing with isolated environments:

```typescript
import { setupPREnvironment } from './heimdall-framework/ephemeral/environment-setup';
```

const results = await setupPREnvironment('123', 'feature-branch');
```

This will:
1. Create isolated database
2. Seed with masked/synthetic data
3. Deploy application
4. Run full Heimdall test suite
5. Clean up environment

## Policy Configuration

### RBAC (Role-Based Access Control)

Define role-based policies in `policies/`:

```json
{
  "rules": [
    {
      "id": "viewer-public-only",
      "effect": "allow",
      "conditions": {
        "subject.role": "viewer",
        "resource.sensitivity": "public"
      }
    }
  ]
}
```

### ABAC (Attribute-Based Access Control)

Define attribute-based policies in `policies/abac-policies.json`:

```json
{
  "policies": [
    {
      "id": "abac-department-match",
      "name": "Department Match Policy",
      "effect": "allow",
      "priority": 100,
      "conditions": [
        {
          "attribute": "subject.department",
          "operator": "equals",
          "value": "{{resource.department}}"
        }
      ]
    },
    {
      "id": "abac-clearance-level",
      "name": "Clearance Level Check",
      "effect": "allow",
      "priority": 200,
      "conditions": [
        {
          "attribute": "subject.clearanceLevel",
          "operator": "in",
          "value": ["high", "top-secret"]
        },
        {
          "attribute": "resource.dataClassification",
          "operator": "in",
          "value": ["confidential", "restricted"],
          "logicalOperator": "AND"
        }
      ]
    }
  ]
}
```

### Hybrid Mode

Heimdall supports both RBAC and ABAC simultaneously:

```typescript
const config: TestConfiguration = {
  accessControlConfig: {
    policyMode: 'hybrid', // or 'rbac' or 'abac'
    abacPolicies: await loadABACPolicies(),
  },
  // ...
};
```

### ABAC Attributes

Users can have ABAC attributes:
- `department`: User's department
- `clearanceLevel`: Security clearance (low, medium, high, top-secret)
- `projectAccess`: List of projects user can access
- `dataClassification`: Data classifications user can access
- `location`: User's location
- `employmentType`: full-time, part-time, contractor
- `certifications`: List of certifications

Resources can have ABAC attributes:
- `dataClassification`: Classification level
- `department`: Owning department
- `project`: Associated project
- `region`: Geographic region
- `requiresCertification`: Required certifications
- `minClearanceLevel`: Minimum clearance required

## Output

Tests generate:
- JSON reports (`compliance-report-{timestamp}.json`)
- HTML reports (`compliance-report-{timestamp}.html`)
- JUnit XML (`compliance-report-{timestamp}.xml`)

## Requirements Met

✅ Simulate users with different roles/attributes  
✅ Execute representative application flows  
✅ Detect policy violations (over-broad queries, missing PII masking, unapproved joins)  
✅ Integration with CI/CD to block merges on access violations  
✅ Dashboard to show compliance score by application, team, dataset  
✅ Access-control tests: Evaluate PDP decisions  
✅ Contract tests with data owners: Machine-readable requirements → generated tests  
✅ Dataset health & risk tests: Privacy thresholds and statistical fidelity  
✅ Ephemeral environments: Per-PR with seeded data  
✅ SAST/DAST/DBT/Great Expectations hooks  
✅ **RBAC (Role-Based Access Control) support**  
✅ **ABAC (Attribute-Based Access Control) support**  
✅ **Hybrid RBAC/ABAC mode**

