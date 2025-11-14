# TestOrchestrator Documentation

Welcome to the TestOrchestrator documentation. This directory contains comprehensive guides for using the framework.

## Documentation Index

### Getting Started

- **[Policy Creation Guide](./POLICY_CREATION_GUIDE.md)**: Learn how to create RBAC and ABAC policies
  - RBAC policy structure and syntax
  - ABAC policy structure and syntax
  - Condition operators and logical operators
  - Best practices and examples
  - Troubleshooting tips

- **[Test Creation Guide](./TEST_CREATION_GUIDE.md)**: Learn how to create test suites
  - Test suite structure
  - Access control tests
  - Data behavior tests
  - Contract tests
  - Dataset health tests
  - Best practices and examples

- **[Quick Reference](./QUICK_REFERENCE.md)**: Quick reference for common tasks
  - Policy templates
  - Test suite templates
  - Common patterns
  - Troubleshooting checklist

- **[Feature Roadmap](./FEATURE_ROADMAP.md)**: Recommended enhancements and future features
  - Priority-ranked feature list
  - Implementation recommendations
  - Use cases and benefits

## Quick Links

### Policy Creation

- [RBAC Policies](./POLICY_CREATION_GUIDE.md#creating-rbac-policies)
- [ABAC Policies](./POLICY_CREATION_GUIDE.md#creating-abac-policies)
- [Policy Operators](./POLICY_CREATION_GUIDE.md#operators)
- [Policy Examples](./POLICY_CREATION_GUIDE.md#examples)

### Test Creation

- [Test Suite Structure](./TEST_CREATION_GUIDE.md#test-suite-overview)
- [Access Control Tests](./TEST_CREATION_GUIDE.md#1-access-control-tests)
- [Data Behavior Tests](./TEST_CREATION_GUIDE.md#2-data-behavior-tests)
- [Contract Tests](./TEST_CREATION_GUIDE.md#3-contract-tests)
- [Dataset Health Tests](./TEST_CREATION_GUIDE.md#4-dataset-health-tests)

## Common Tasks

### Creating Your First Policy

1. Read the [Policy Creation Guide](./POLICY_CREATION_GUIDE.md)
2. Choose RBAC or ABAC based on your needs
3. Create a policy file in `policies/` directory
4. Load and test your policy

### Creating Your First Test Suite

1. Read the [Test Creation Guide](./TEST_CREATION_GUIDE.md)
2. Create a test suite file in `tests/suites/`
3. Define resources, users, and test queries
4. Run the test suite

### Troubleshooting

Both guides include troubleshooting sections:
- [Policy Troubleshooting](./POLICY_CREATION_GUIDE.md#troubleshooting)
- [Test Troubleshooting](./TEST_CREATION_GUIDE.md#troubleshooting)

## Examples

See the [examples](../examples/) directory for complete working examples:
- `basic-usage.ts`: Basic TestOrchestrator usage
- `abac-usage.ts`: ABAC policy usage

## Additional Resources

- [Main README](../README.md): Framework overview and features
- [Policy Examples](../policies/): Reference policy implementations
- [Test Examples](../tests/): Reference test suite implementations

