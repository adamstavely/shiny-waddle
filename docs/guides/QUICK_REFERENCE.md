# Quick Reference Guide

Quick reference for common tasks when creating policies and tests.

> **💡 Tip**: For most use cases, start with [Policy Templates](./TEMPLATE_GUIDE.md) to quickly create policies, then create tests to validate them.

## Policy Quick Reference

### RBAC Policy Template

```json
{
  "name": "Policy Name",
  "version": "1.0.0",
  "rules": [
    {
      "id": "rule-id",
      "description": "Description",
      "effect": "allow",
      "conditions": {
        "subject.role": "admin",
        "resource.sensitivity": ["public", "internal"]
      }
    }
  ]
}
```

### ABAC Policy Template

```json
{
  "policies": [
    {
      "id": "policy-id",
      "name": "Policy Name",
      "description": "Description",
      "effect": "allow",
      "priority": 100,
      "conditions": [
        {
          "attribute": "subject.department",
          "operator": "equals",
          "value": "Research"
        }
      ]
    }
  ]
}
```

### Common ABAC Attributes

**Subject:**
- `subject.role` - User role
- `subject.department` - Department
- `subject.clearanceLevel` - Security clearance
- `subject.projectAccess` - Array of projects
- `subject.certifications` - Array of certifications
- `subject.employmentType` - Employment type

**Resource:**
- `resource.dataClassification` - Classification level
- `resource.department` - Owning department
- `resource.project` - Associated project
- `resource.region` - Geographic region

**Context:**
- `context.ipAddress` - IP address
- `context.timeOfDay` - Time (HH:MM)
- `context.location` - Physical location

### Operators

| Operator | Use Case |
|---------|----------|
| `equals` | Exact match |
| `in` | Value in array |
| `contains` | Array/string contains |
| `regex` | Pattern matching |
| `greaterThan` | Numeric comparison |
| `startsWith` | String prefix |

## Test Suite Quick Reference

### Minimal Test Suite

```typescript
{
  name: 'My Tests',
  application: 'my-app',
  team: 'my-team',
  includeAccessControlTests: true,
  includeDatasetHealthTests: false,
  userRoles: ['admin', 'viewer'],
  resources: [
    {
      id: 'resource-1',
      type: 'dataset',
      attributes: { sensitivity: 'public' },
      sensitivity: 'public'
    }
  ],
  contexts: [{ ipAddress: '192.168.1.1' }]
}
```

### Access Control Test

```typescript
{
  includeAccessControlTests: true,
  userRoles: ['admin', 'viewer'],
  resources: [
    { id: 'public', type: 'data', attributes: { sensitivity: 'public' }, sensitivity: 'public' },
    { id: 'restricted', type: 'data', attributes: { sensitivity: 'restricted' }, sensitivity: 'restricted' }
  ],
  expectedDecisions: {
    'admin-public': true,
    'viewer-restricted': false
  }
}
```

### Contract Test

```typescript
// Contract rules are now configured in DLP test configurations:
// - exportRestrictions: { restrictedFields, requireMasking, allowedFormats }
// - aggregationRequirements: { minK, requireAggregation }
// - fieldRestrictions: { disallowedFields, allowedFields }
// - joinRestrictions: { disallowedJoins }
```

### Distributed Systems Test

**Prerequisites:** Application must have `infrastructure.distributedSystems.regions` configured with at least 2 regions.

#### Multi-Region Test

```typescript
{
  testType: 'distributed-systems',
  distributedTestType: 'multi-region',
  applicationId: 'my-distributed-app',
  multiRegionConfig: {
    regions: ['us-east-1', 'eu-west-1'],
    executionMode: 'parallel', // or 'sequential'
    timeout: 30000,
    user: { id: 'user-123', attributes: { role: 'admin' } },
    resource: { id: 'resource-456', type: 'dataset' },
    action: 'read',
    expectedResult: true
  }
}
```

#### Policy Consistency Test

```typescript
{
  testType: 'distributed-systems',
  distributedTestType: 'policy-consistency',
  applicationId: 'my-distributed-app',
  policyConsistencyConfig: {
    regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'],
    policyIds: ['policy-1'], // Optional: check specific policies
    checkTypes: ['version', 'configuration', 'evaluation']
  }
}
```

#### Policy Synchronization Test

```typescript
{
  testType: 'distributed-systems',
  distributedTestType: 'policy-synchronization',
  applicationId: 'my-distributed-app',
  policySyncConfig: {
    regions: ['us-east-1', 'eu-west-1'],
    policyId: 'policy-1', // Optional: test specific policy
    testScenarios: ['update-propagation', 'sync-timing', 'sync-failure-recovery']
  }
}
```

## File Locations

- **Policies**: `policies/*.json`
- **Test Suites**: `tests/suites/*.ts` or `tests/suites/*.json`
- **Examples**: `examples/*.ts`
- **Documentation**: `docs/*.md`

## Common Commands

```bash
# Run tests
npm run test:compliance

# Run specific suite
TEST_SUITE=my-suite npm run test:compliance

# Run with ABAC
POLICY_MODE=abac npm run test:compliance

# Run with custom policy path
ABAC_POLICIES_PATH=./policies/my-policies.json npm run test:compliance
```

## Common Patterns

### Department Match

```json
{
  "attribute": "subject.department",
  "operator": "equals",
  "value": "{{resource.department}}"
}
```

### Clearance Level Check

```json
{
  "attribute": "subject.clearanceLevel",
  "operator": "in",
  "value": ["high", "top-secret"]
}
```

### Project Access

```json
{
  "attribute": "subject.projectAccess",
  "operator": "contains",
  "value": "{{resource.project}}"
}
```

### Time-Based Restriction

```json
{
  "attribute": "context.timeOfDay",
  "operator": "regex",
  "value": "^(0[8-9]|1[0-8]):"
}
```

### Multi-Condition (AND)

```json
[
  {
    "attribute": "subject.clearanceLevel",
    "operator": "in",
    "value": ["high"]
  },
  {
    "attribute": "resource.dataClassification",
    "operator": "in",
    "value": ["confidential"],
    "logicalOperator": "AND"
  }
]
```

## Troubleshooting Checklist

- [ ] Policy file syntax is valid JSON
- [ ] Policy IDs are unique
- [ ] Attribute paths match test data
- [ ] Operators match data types
- [ ] Test suite file exists in `tests/suites/`
- [ ] User roles match policy expectations
- [ ] Resource attributes are defined
- [ ] Expected decisions are correct

## Need More Help?

- **Template Guide**: See [TEMPLATE_GUIDE.md](./TEMPLATE_GUIDE.md) for creating policies from templates and testing them
- **Detailed Guides**: See [POLICY_CREATION_GUIDE.md](./POLICY_CREATION_GUIDE.md) and [TEST_CREATION_GUIDE.md](./TEST_CREATION_GUIDE.md)
- **Examples**: Check `examples/` directory
- **Reference**: See `policies/` and `tests/` directories

