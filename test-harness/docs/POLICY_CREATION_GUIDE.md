# Policy Creation Guide

This guide explains how to create and configure access control policies for Sentinel, supporting both RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access Control).

## Table of Contents

1. [Policy Types Overview](#policy-types-overview)
2. [Creating RBAC Policies](#creating-rbac-policies)
3. [Creating ABAC Policies](#creating-abac-policies)
4. [Policy Structure Reference](#policy-structure-reference)
5. [Best Practices](#best-practices)
6. [Examples](#examples)

## Policy Types Overview

### RBAC (Role-Based Access Control)

RBAC policies grant or deny access based on user roles. These are simpler policies that check:
- User role (admin, researcher, analyst, viewer)
- Resource sensitivity level
- Basic context (IP address, time of day)

**Use RBAC when:**
- Access control is primarily role-based
- Simple permission model is sufficient
- You need fast, straightforward policy evaluation

### ABAC (Attribute-Based Access Control)

ABAC policies grant or deny access based on multiple attributes from:
- **Subject attributes**: User's department, clearance level, project access, certifications, etc.
- **Resource attributes**: Data classification, department, project, region, etc.
- **Context attributes**: IP address, time of day, location, device, etc.

**Use ABAC when:**
- You need fine-grained access control
- Access depends on multiple factors (department + project + clearance)
- Policies need to be more dynamic and flexible
- You have complex business rules

## Creating RBAC Policies

### Step 1: Define Policy Structure

RBAC policies are defined in JSON format. Create a file in `policies/` directory:

```json
{
  "name": "My Application RBAC Policy",
  "version": "1.0.0",
  "rules": [
    {
      "id": "rule-unique-id",
      "description": "Human-readable description",
      "effect": "allow",
      "conditions": {
        "subject.role": "researcher",
        "resource.sensitivity": ["public", "internal"]
      }
    }
  ]
}
```

### Step 2: Define Rules

Each rule has:
- **id**: Unique identifier (required)
- **description**: What the rule does (optional but recommended)
- **effect**: `"allow"` or `"deny"` (required)
- **conditions**: Object with condition checks (required)

### Step 3: Condition Syntax

RBAC conditions support:
- **Direct value matching**: `"subject.role": "admin"`
- **Array matching**: `"resource.sensitivity": ["public", "internal"]` (matches if value is in array)
- **Nested attributes**: `"context.additionalAttributes.device": "mobile"`

### Example RBAC Policy

```json
{
  "name": "Research Tracker RBAC Policy",
  "version": "1.0.0",
  "rules": [
    {
      "id": "admin-full-access",
      "description": "Admins have full access to all resources",
      "effect": "allow",
      "conditions": {
        "subject.role": "admin"
      }
    },
    {
      "id": "researcher-internal-access",
      "description": "Researchers can access public and internal resources",
      "effect": "allow",
      "conditions": {
        "subject.role": "researcher",
        "resource.sensitivity": ["public", "internal"]
      }
    },
    {
      "id": "viewer-public-only",
      "description": "Viewers can only access public resources",
      "effect": "allow",
      "conditions": {
        "subject.role": "viewer",
        "resource.sensitivity": "public"
      }
    },
    {
      "id": "confidential-ip-required",
      "description": "Confidential resources require IP validation",
      "effect": "allow",
      "conditions": {
        "subject.role": ["researcher", "analyst"],
        "resource.sensitivity": "confidential",
        "context.ipAddress": { "exists": true }
      }
    }
  ]
}
```

## Creating ABAC Policies

### Step 1: Create Policy File

Create a JSON file in `policies/` directory (e.g., `policies/abac-policies.json`):

```json
{
  "policies": [
    {
      "id": "policy-unique-id",
      "name": "Policy Name",
      "description": "What this policy does",
      "effect": "allow",
      "priority": 100,
      "conditions": [...]
    }
  ]
}
```

### Step 2: Define Policy Properties

Each ABAC policy requires:
- **id**: Unique identifier (required)
- **name**: Human-readable name (required)
- **description**: What the policy does (optional but recommended)
- **effect**: `"allow"` or `"deny"` (required)
- **priority**: Number (optional, default: 0). Higher priority policies are evaluated first
- **conditions**: Array of condition objects (required, at least one)

### Step 3: Define Conditions

Each condition has:
- **attribute**: Dot-notation path to attribute (e.g., `"subject.department"`)
- **operator**: Comparison operator (see below)
- **value**: Value to compare against
- **logicalOperator**: `"AND"` or `"OR"` (optional, default: AND)

### Step 4: Attribute Paths

Attributes use dot notation to access nested properties:

**Subject attributes:**
- `subject.role` - User's role
- `subject.department` - User's department
- `subject.clearanceLevel` - Security clearance (low, medium, high, top-secret)
- `subject.projectAccess` - Array of projects user can access
- `subject.dataClassification` - Array of data classifications user can access
- `subject.location` - User's location
- `subject.employmentType` - full-time, part-time, contractor
- `subject.certifications` - Array of certifications

**Resource attributes:**
- `resource.type` - Resource type
- `resource.dataClassification` - Data classification level
- `resource.department` - Owning department
- `resource.project` - Associated project
- `resource.region` - Geographic region
- `resource.requiresCertification` - Required certifications
- `resource.minClearanceLevel` - Minimum clearance required

**Context attributes:**
- `context.ipAddress` - IP address
- `context.timeOfDay` - Time in HH:MM format
- `context.location` - Physical location
- `context.device` - Device type
- `context.additionalAttributes.*` - Any custom context attributes

### Step 5: Operators

Available operators:

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `"subject.department" equals "Research"` |
| `notEquals` | Not equal | `"subject.employmentType" notEquals "contractor"` |
| `in` | Value is in array | `"subject.clearanceLevel" in ["high", "top-secret"]` |
| `notIn` | Value is not in array | `"subject.role" notIn ["viewer"]` |
| `greaterThan` | Numeric greater than | `"subject.clearanceLevel" greaterThan 5` |
| `lessThan` | Numeric less than | `"subject.age" lessThan 65` |
| `contains` | String/array contains value | `"subject.projectAccess" contains "project-alpha"` |
| `startsWith` | String starts with | `"context.ipAddress" startsWith "192.168"` |
| `endsWith` | String ends with | `"resource.id" endsWith "-restricted"` |
| `regex` | Regular expression match | `"context.timeOfDay" regex "^(0[8-9]\|1[0-8]):"` |

### Step 6: Logical Operators

Conditions are combined with logical operators:
- **AND** (default): All conditions must match
- **OR**: At least one condition must match

Use `logicalOperator` field in conditions:

```json
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
```

### Example ABAC Policy

```json
{
  "policies": [
    {
      "id": "abac-department-match",
      "name": "Department Match Policy",
      "description": "Users can access resources from their own department",
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
      "id": "abac-clearance-level-required",
      "name": "Clearance Level Requirement",
      "description": "Users must have sufficient clearance for classified resources",
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
          "value": ["confidential", "restricted", "top-secret"],
          "logicalOperator": "AND"
        }
      ]
    },
    {
      "id": "abac-project-access",
      "name": "Project Access Policy",
      "description": "Users can access resources from projects they have access to",
      "effect": "allow",
      "priority": 150,
      "conditions": [
        {
          "attribute": "subject.projectAccess",
          "operator": "contains",
          "value": "{{resource.project}}"
        }
      ]
    },
    {
      "id": "abac-time-based-restriction",
      "name": "Time-Based Access",
      "description": "Restricted resources only accessible during business hours",
      "effect": "allow",
      "priority": 130,
      "conditions": [
        {
          "attribute": "context.timeOfDay",
          "operator": "regex",
          "value": "^(0[8-9]|1[0-8]):"
        },
        {
          "attribute": "resource.dataClassification",
          "operator": "equals",
          "value": "restricted",
          "logicalOperator": "AND"
        }
      ]
    }
  ]
}
```

## Policy Structure Reference

### RBAC Policy Structure

```typescript
interface RBACPolicy {
  name: string;
  version: string;
  rules: RBACRule[];
}

interface RBACRule {
  id: string;
  description?: string;
  effect: 'allow' | 'deny';
  conditions: {
    [key: string]: string | string[] | ConditionObject;
  };
}
```

### ABAC Policy Structure

```typescript
interface ABACPolicy {
  id: string;
  name: string;
  description?: string;
  effect: 'allow' | 'deny';
  priority?: number;
  conditions: ABACCondition[];
}

interface ABACCondition {
  attribute: string;
  operator: 'equals' | 'notEquals' | 'in' | 'notIn' | 
            'greaterThan' | 'lessThan' | 'contains' | 
            'startsWith' | 'endsWith' | 'regex';
  value: any;
  logicalOperator?: 'AND' | 'OR';
}
```

## Best Practices

### 1. Policy Organization

- **Group related policies**: Create separate files for different domains (e.g., `financial-policies.json`, `research-policies.json`)
- **Use descriptive IDs**: `abac-department-match` is better than `policy-1`
- **Version your policies**: Include version numbers for tracking changes

### 2. Priority Management

- **Higher priority = more specific**: Specific policies should have higher priority
- **Deny policies**: Usually have higher priority than allow policies
- **Default range**: Use 100-200 for general policies, 300+ for restrictions

### 3. Condition Design

- **Start simple**: Begin with basic conditions, add complexity as needed
- **Use appropriate operators**: `contains` for arrays, `equals` for exact matches
- **Combine logically**: Use AND for requirements, OR for alternatives

### 4. Testing Policies

- **Test each policy independently**: Ensure policies work in isolation
- **Test policy interactions**: Verify policies work correctly together
- **Test edge cases**: Empty arrays, missing attributes, null values

### 5. Performance Considerations

- **Order conditions efficiently**: Put most selective conditions first
- **Use caching**: Enable `cacheDecisions` in config for repeated evaluations
- **Limit policy count**: Too many policies can slow evaluation

## Examples

### Example 1: Department-Based Access

```json
{
  "id": "department-access",
  "name": "Department Access",
  "effect": "allow",
  "priority": 100,
  "conditions": [
    {
      "attribute": "subject.department",
      "operator": "equals",
      "value": "{{resource.department}}"
    }
  ]
}
```

### Example 2: Multi-Factor Access

```json
{
  "id": "secure-resource-access",
  "name": "Secure Resource Access",
  "effect": "allow",
  "priority": 200,
  "conditions": [
    {
      "attribute": "subject.clearanceLevel",
      "operator": "in",
      "value": ["high", "top-secret"]
    },
    {
      "attribute": "subject.certifications",
      "operator": "contains",
      "value": "security-clearance",
      "logicalOperator": "AND"
    },
    {
      "attribute": "context.location",
      "operator": "in",
      "value": ["headquarters", "secure-facility"],
      "logicalOperator": "AND"
    }
  ]
}
```

### Example 3: Time-Based Restriction

```json
{
  "id": "business-hours-only",
  "name": "Business Hours Access",
  "effect": "allow",
  "priority": 150,
  "conditions": [
    {
      "attribute": "context.timeOfDay",
      "operator": "regex",
      "value": "^(0[8-9]|1[0-8]):"
    },
    {
      "attribute": "resource.dataClassification",
      "operator": "in",
      "value": ["restricted", "top-secret"],
      "logicalOperator": "AND"
    }
  ]
}
```

### Example 4: Deny Policy (Contractor Restriction)

```json
{
  "id": "no-contractor-restricted",
  "name": "Contractor Restriction",
  "description": "Contractors cannot access restricted resources",
  "effect": "deny",
  "priority": 300,
  "conditions": [
    {
      "attribute": "subject.employmentType",
      "operator": "equals",
      "value": "contractor"
    },
    {
      "attribute": "resource.dataClassification",
      "operator": "in",
      "value": ["restricted", "top-secret"],
      "logicalOperator": "AND"
    }
  ]
}
```

## Loading Policies

### In Code

```typescript
import { ABACPolicyLoader } from './services/abac-policy-loader';

const loader = new ABACPolicyLoader();
const policies = await loader.loadPoliciesFromFile('./policies/abac-policies.json');
```

### In Configuration

```typescript
const config: TestConfiguration = {
  accessControlConfig: {
    policyMode: 'abac',
    abacPolicies: policies,
  },
  // ...
};
```

### Environment Variables

```bash
# Set policy mode
export POLICY_MODE=abac  # or 'rbac' or 'hybrid'

# Set ABAC policies path
export ABAC_POLICIES_PATH=./policies/my-abac-policies.json
```

## Troubleshooting

### Policy Not Matching

1. **Check attribute paths**: Verify attribute names match exactly
2. **Verify operator**: Ensure operator is appropriate for data type
3. **Check value format**: Arrays vs strings, case sensitivity
4. **Review priority**: Higher priority policies may override

### Performance Issues

1. **Reduce policy count**: Consolidate similar policies
2. **Enable caching**: Set `cacheDecisions: true`
3. **Optimize conditions**: Put most selective conditions first
4. **Use appropriate operators**: `equals` is faster than `regex`

### Common Mistakes

1. **Missing attributes**: Ensure all referenced attributes exist in test data
2. **Wrong operator**: Using `equals` on arrays, `contains` on strings
3. **Priority conflicts**: Policies with same priority may conflict
4. **Logical operators**: OR conditions may not work as expected

## Next Steps

- See [TEST_CREATION_GUIDE.md](./TEST_CREATION_GUIDE.md) for creating test suites
- Review [examples](../examples/) for complete examples
- Check [policies](../policies/) for reference implementations

