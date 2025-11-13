# Heimdall

Heimdall is an automated testing framework that validates applications are adhering to access control requirements for data.

## Features

### Core Testing Capabilities

- **User Simulation**: Simulate users with different roles/attributes
- **Access Control Tests**: Evaluate Policy Decision Point (PDP) decisions for representative identities, attributes, resources, and contexts
- **Data Behavior Tests**: Verify queries only use permitted fields, apply required filters/aggregations, and block disallowed joins
- **Contract Tests**: Machine-readable requirements → generated tests (e.g., "No raw email export," "Min aggregation ≥ k=10")
- **Dataset Health Tests**: Assert masked/synthetic data meets privacy thresholds (k-anonymity, l-diversity, t-closeness, differential privacy) and statistical fidelity targets
- **Ephemeral Environments**: Spin up per-PR with seeded masked/synthetic data; run full harness before merge
- **CI/CD Integration**: Block merges on access violations with GitHub Actions
- **Compliance Dashboard**: Show compliance score by application, team, dataset
- **Integration Hooks**: SAST/DAST/DBT/Great Expectations integration for schema, constraint, and data-quality tests
- **API Security Testing**: Comprehensive REST/GraphQL API security testing including authentication, authorization, rate limiting, and vulnerability detection
- **Data Pipeline Testing**: Test ETL pipelines, streaming data, data transformations, and pipeline security controls
- **Distributed Systems Testing**: Test access control across multiple regions, verify policy consistency, test synchronization, and distributed transactions

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
├── core/                    # Core framework components
│   ├── test-harness.ts      # Main orchestrator
│   └── types.ts             # Type definitions
├── services/                # Test service implementations
│   ├── user-simulator.ts    # User role/attribute simulation
│   ├── access-control-tester.ts  # PDP decision evaluation
│   ├── data-behavior-tester.ts   # Query validation
│   ├── contract-tester.ts       # Contract requirement testing
│   ├── dataset-health-tester.ts  # Privacy & statistical tests
│   ├── compliance-reporter.ts   # Report generation
│   ├── policy-decision-point.ts  # PDP implementation
│   ├── query-analyzer.ts         # SQL/API query analysis
│   ├── pii-masking-validator.ts  # PII detection & masking validation
│   ├── api-security-tester.ts   # API security testing (REST, GraphQL, rate limiting)
│   └── data-pipeline-tester.ts  # Data pipeline testing (ETL, streaming, security)
├── tests/                   # Test suites
│   ├── example-test-suite.ts     # Example configuration
│   └── test-suite-loader.ts      # Suite loading utilities
├── policies/                # Policy definitions
│   └── example-policy.json       # Example access control policy
├── dashboard/               # Compliance dashboard
│   └── compliance-dashboard.ts   # Dashboard data generation
├── ci-cd/                   # CI/CD integration scripts
│   ├── github-actions.yml        # GitHub Actions workflow
│   └── check-compliance.js       # Compliance check script
├── ephemeral/               # Ephemeral environment setup
│   └── environment-setup.ts      # Per-PR environment creation
├── integrations/            # External tool integrations
│   └── sast-dast-hooks.ts        # SAST/DAST/DBT/GE hooks
└── src/                     # Entry point
    └── run-tests.ts              # Main test runner
```

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
   - All four test types (access control, data behavior, contracts, dataset health)
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
  "includeDataBehaviorTests": true,
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

### 2. Data Behavior Tests

Validates:
- Queries only access permitted fields
- Required filters are applied (e.g., workspace filtering)
- Disallowed joins are blocked
- PII fields are properly masked

### 3. Contract Tests

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
import { setupPREnvironment } from './ephemeral/environment-setup';

const results = await setupPREnvironment('123', 'feature-branch');
```

This will:
1. Create isolated database
2. Seed with masked/synthetic data
3. Deploy application
4. Run full Heimdall test suite
5. Clean up environment

## Compliance Dashboard

Generate dashboard data:

```typescript
import { ComplianceDashboard } from './dashboard/compliance-dashboard';

const dashboard = new ComplianceDashboard(reporter);
const data = await dashboard.generateDashboardData(results);
```

Dashboard shows:
- Overall compliance score
- Scores by application
- Scores by team
- Scores by dataset
- Recent test results
- Trends over time

## Integration Hooks

Integrate with external tools:

```typescript
import { IntegrationHooks } from './integrations/sast-dast-hooks';

const hooks = new IntegrationHooks();
const results = await hooks.runAllIntegrations({
  sourcePath: './src',
  apiUrl: 'http://localhost:3000',
  dbtProjectPath: './dbt',
  geSuiteName: 'data_quality',
});
```

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
- Dashboard data (`dashboard-data.json`)

## Requirements Met

✅ Simulate users with different roles/attributes  
✅ Execute representative application flows  
✅ Detect policy violations (over-broad queries, missing PII masking, unapproved joins)  
✅ Integration with CI/CD to block merges on access violations  
✅ Dashboard to show compliance score by application, team, dataset  
✅ Access-control tests: Evaluate PDP decisions  
✅ Data-behavior tests: Verify queries, filters, aggregations, joins  
✅ Contract tests with data owners: Machine-readable requirements → generated tests  
✅ Dataset health & risk tests: Privacy thresholds and statistical fidelity  
✅ Ephemeral environments: Per-PR with seeded data  
✅ SAST/DAST/DBT/Great Expectations hooks  
✅ **RBAC (Role-Based Access Control) support**  
✅ **ABAC (Attribute-Based Access Control) support**  
✅ **Hybrid RBAC/ABAC mode**

