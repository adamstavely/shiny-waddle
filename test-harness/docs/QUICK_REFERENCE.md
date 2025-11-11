# Quick Reference Guide

Quick reference for common tasks when creating policies and tests.

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
  includeDataBehaviorTests: false,
  includeContractTests: false,
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

### Data Behavior Test

```typescript
{
  includeDataBehaviorTests: true,
  testQueries: [
    { name: 'Get reports', sql: 'SELECT id, title FROM reports' }
  ],
  allowedFields: {
    viewer: ['id', 'title'],
    admin: ['*']
  },
  requiredFilters: {
    viewer: [
      { field: 'workspace_id', operator: '=', value: 'user_workspace' }
    ]
  },
  disallowedJoins: {
    viewer: ['users']
  }
}
```

### Contract Test

```typescript
{
  includeContractTests: true,
  contracts: [
    {
      name: 'No Email Export',
      dataOwner: 'data-governance',
      requirements: [
        {
          id: 'no-email',
          description: 'No raw email export',
          type: 'export-restriction',
          rule: { restrictedFields: ['email'], requireMasking: true },
          enforcement: 'hard'
        }
      ],
      machineReadable: true
    }
  ]
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

- **Detailed Guides**: See [POLICY_CREATION_GUIDE.md](./POLICY_CREATION_GUIDE.md) and [TEST_CREATION_GUIDE.md](./TEST_CREATION_GUIDE.md)
- **Examples**: Check `examples/` directory
- **Reference**: See `policies/` and `tests/` directories

