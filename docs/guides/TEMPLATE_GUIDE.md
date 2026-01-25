# Policy Templates Guide

This guide explains how to use policy templates to quickly create policies and then test them. Templates provide a fast, consistent way to generate policies for common use cases.

## Table of Contents

1. [What Are Templates?](#what-are-templates)
2. [Template Types](#template-types)
3. [Creating Policies from Templates](#creating-policies-from-templates)
4. [Testing Template-Generated Policies](#testing-template-generated-policies)
5. [Complete Workflow Example](#complete-workflow-example)
6. [Best Practices](#best-practices)

## What Are Templates?

Policy templates are pre-built configurations that generate multiple access control policies based on your specific requirements. Instead of manually writing complex policy JSON files, you provide simple configuration values (like roles, resources, departments) and the template generates all the necessary policies with proper structure, conditions, and logic.

### Why Use Templates?

- **Speed**: Create multiple policies in seconds instead of hours
- **Consistency**: All policies follow the same proven patterns
- **Compliance**: Industry templates (HIPAA, GDPR) include required controls
- **Best Practices**: Templates encode security best practices
- **Reduced Errors**: Less manual coding means fewer mistakes

### How Templates Relate to Tests

The relationship between templates, policies, and tests is:

```
Template → Policies → Tests → Test Execution → Results
```

1. **Templates create policies**: A template generates one or more policy objects
2. **Policies are saved**: Policies are stored and associated with an application
3. **Tests validate policies**: Each test validates exactly one policy (1:1 relationship)
4. **Tests execute**: Test runners load policies and verify they work correctly

**Key Concept**: Templates are the creation step, tests are the validation step. You use templates to quickly create policies, then create tests to ensure those policies work correctly.

## Template Types

### RBAC Template

Creates role-based access control policies. Each role is assigned permissions to specific resources.

**Configuration Options:**
- `applicationName`: Name of your application
- `roles`: Array of roles (e.g., `['admin', 'user', 'viewer']`)
- `resources`: Array of resources (e.g., `['dataset', 'report']`)
- `actions`: Array of actions (e.g., `['read', 'write']`)

**Use When:**
- Access control is primarily role-based
- Simple permission model is sufficient
- You need fast, straightforward policy evaluation

**Example:**
```bash
# CLI
heimdall template create rbac \
  --application-name "MyApp" \
  --roles admin,user,viewer \
  --resources dataset,report \
  --actions read,write
```

### ABAC Template

Creates attribute-based access control policies. Supports department matching, clearance levels, project access, location-based access, and time-based restrictions.

**Configuration Options:**
- `applicationName`: Name of your application
- `departments`: Array of departments (optional)
- `clearanceLevels`: Array of clearance levels (optional)
- `dataClassifications`: Array of data classifications (optional)
- `projects`: Array of projects (optional)

**Use When:**
- You need fine-grained access control
- Access depends on multiple factors (department + project + clearance)
- Policies need to be more dynamic and flexible
- You have complex business rules

**Example:**
```bash
# CLI
heimdall template create abac \
  --application-name "MyApp" \
  --departments engineering,research \
  --clearance-levels high,top-secret \
  --data-classifications confidential,restricted
```

### HIPAA Template

Creates policies compliant with HIPAA regulations for protecting Protected Health Information (PHI). Includes minimum necessary rules, access controls, audit logging, encryption requirements, and business associate agreements.

**Configuration Options:**
- `applicationName`: Name of your application
- `coveredEntities`: Array of covered entities (optional)
- `businessAssociates`: Array of business associates (optional)

**Use When:**
- Your application handles Protected Health Information (PHI)
- You need HIPAA compliance
- Healthcare data access control is required

**Example:**
```bash
# CLI
heimdall template create hipaa \
  --application-name "HealthApp" \
  --covered-entities hospital,clinic \
  --business-associates vendor1,vendor2
```

### GDPR Template

Creates policies compliant with GDPR regulations for protecting personal data of EU citizens. Includes rights to access and erasure, data minimization, purpose limitation, cross-border transfer restrictions, consent requirements, and breach notification.

**Configuration Options:**
- `applicationName`: Name of your application
- `dataControllers`: Array of data controllers (optional)
- `dataProcessors`: Array of data processors (optional)
- `euMemberStates`: Array of EU member state codes (optional)

**Use When:**
- Your application processes EU citizen data
- You need GDPR compliance
- Cross-border data transfer restrictions apply

**Example:**
```bash
# CLI
heimdall template create gdpr \
  --application-name "DataApp" \
  --data-controllers company1,company2 \
  --data-processors vendor1,vendor2 \
  --eu-member-states DE,FR,IT
```

## Creating Policies from Templates

### Using the CLI

#### List Available Templates

```bash
heimdall template list
```

#### Preview a Template

See what a template will generate before creating policies:

```bash
heimdall template preview rbac
```

#### Create Policies from Template

**Interactive Mode:**
```bash
heimdall template create rbac --interactive
```

**Direct Mode:**
```bash
heimdall template create rbac \
  --application-name "MyApp" \
  --roles admin,user,viewer \
  --resources dataset,report \
  --actions read,write \
  --output ./policies/rbac-policy.json
```

### Using the API

**List Templates:**
```bash
GET /api/templates
```

**Get Template Details:**
```bash
GET /api/templates/rbac
```

**Create Policies from Template:**
```bash
POST /api/templates/rbac/create
Content-Type: application/json

{
  "applicationName": "MyApp",
  "config": {
    "roles": ["admin", "user", "viewer"],
    "resources": ["dataset", "report"],
    "actions": ["read", "write"],
    "applicationId": "app-123"
  }
}
```

### Using the UI

1. Navigate to **Templates** page
2. Browse available templates
3. Click **Preview** to see template details
4. Click **Use Template** to create policies
5. Fill in configuration form
6. Submit to create policies

## Testing Template-Generated Policies

After creating policies from templates, you need to create tests to validate that the policies work correctly.

### Understanding the Policy-Test Relationship

**1:1 Relationship**: Each test validates exactly one policy.

- One policy → One or more tests (you can create multiple tests for the same policy)
- One test → Exactly one policy (via `policyId`)

### Creating Tests for Template-Generated Policies

#### Step 1: Identify Generated Policies

When you create policies from a template, you'll receive a list of created policies:

```json
{
  "templateName": "rbac",
  "policiesCreated": 6,
  "policies": [
    {
      "id": "policy-1",
      "name": "RBAC Admin Dataset Read",
      "description": "Allows admin role to read dataset resources",
      ...
    },
    {
      "id": "policy-2",
      "name": "RBAC Admin Dataset Write",
      ...
    }
    // ... more policies
  ]
}
```

#### Step 2: Create Tests for Each Policy

For each policy, create tests that validate different scenarios:

**Example: Testing RBAC Template Policies**

```typescript
// Test 1: Admin can read dataset (should allow)
const test1 = {
  name: "Admin can read dataset",
  testType: "access-control",
  policyId: "policy-1", // RBAC Admin Dataset Read policy
  inputs: {
    subject: {
      role: "admin",
      attributes: {}
    },
    resource: {
      id: "dataset-123",
      type: "dataset"
    },
    action: "read"
  },
  expected: {
    allowed: true
  }
};

// Test 2: Viewer cannot read dataset (should deny)
const test2 = {
  name: "Viewer cannot read dataset",
  testType: "access-control",
  policyId: "policy-1", // Same policy
  inputs: {
    subject: {
      role: "viewer", // Different role
      attributes: {}
    },
    resource: {
      id: "dataset-123",
      type: "dataset"
    },
    action: "read"
  },
  expected: {
    allowed: false // Should deny
  }
};

// Test 3: Admin can write dataset (should allow)
const test3 = {
  name: "Admin can write dataset",
  testType: "access-control",
  policyId: "policy-2", // RBAC Admin Dataset Write policy
  inputs: {
    subject: {
      role: "admin",
      attributes: {}
    },
    resource: {
      id: "dataset-123",
      type: "dataset"
    },
    action: "write"
  },
  expected: {
    allowed: true
  }
};
```

#### Step 3: Create Tests via API

```bash
POST /api/tests
Content-Type: application/json

{
  "name": "Admin can read dataset",
  "testType": "access-control",
  "policyId": "policy-1",
  "inputs": {
    "subject": {
      "role": "admin",
      "attributes": {}
    },
    "resource": {
      "id": "dataset-123",
      "type": "dataset"
    },
    "action": "read"
  },
  "expected": {
    "allowed": true
  }
}
```

#### Step 4: Group Tests into Test Suites

Create a test suite to organize your tests:

```typescript
const testSuite = {
  name: "RBAC Template Validation Tests",
  application: "MyApp",
  team: "platform-team",
  testType: "access-control",
  testIds: ["test-1", "test-2", "test-3", ...],
  runtimeConfig: {
    applicationName: "MyApp",
    contexts: [
      {
        ipAddress: "192.168.1.1",
        timeOfDay: "14:00"
      }
    ]
  }
};
```

#### Step 5: Run Tests

Execute your test suite to validate policies:

```bash
# CLI
heimdall test suite rbac-template-validation

# API
POST /api/test-suites/{suiteId}/run
```

## Complete Workflow Example

Here's a complete example of creating policies from a template and testing them:

### Step 1: Create Policies from RBAC Template

**CLI:**
```bash
heimdall template create rbac \
  --application-name "ECommerceApp" \
  --roles admin,manager,user,guest \
  --resources product,order,customer \
  --actions read,write,delete \
  --output ./policies/ecommerce-rbac.json
```

**Result:** Creates 12 policies (4 roles × 3 resources × 1 action type)

### Step 2: Review Generated Policies

```json
{
  "policiesCreated": 12,
  "policies": [
    {
      "id": "policy-admin-product-read",
      "name": "RBAC Admin Product Read",
      "effect": "allow",
      "conditions": [
        {
          "attribute": "subject.role",
          "operator": "equals",
          "value": "admin"
        },
        {
          "attribute": "resource.type",
          "operator": "equals",
          "value": "product"
        }
      ]
    },
    // ... 11 more policies
  ]
}
```

### Step 3: Create Tests for Key Policies

Create tests for critical access scenarios:

```typescript
// Test: Admin can read products
{
  name: "Admin can read products",
  testType: "access-control",
  policyId: "policy-admin-product-read",
  inputs: {
    subject: { role: "admin" },
    resource: { type: "product", id: "prod-123" },
    action: "read"
  },
  expected: { allowed: true }
}

// Test: Guest cannot read products
{
  name: "Guest cannot read products",
  testType: "access-control",
  policyId: "policy-admin-product-read",
  inputs: {
    subject: { role: "guest" },
    resource: { type: "product", id: "prod-123" },
    action: "read"
  },
  expected: { allowed: false }
}

// Test: Manager can write orders
{
  name: "Manager can write orders",
  testType: "access-control",
  policyId: "policy-manager-order-write",
  inputs: {
    subject: { role: "manager" },
    resource: { type: "order", id: "order-456" },
    action: "write"
  },
  expected: { allowed: true }
}
```

### Step 4: Create Test Suite

```typescript
const ecommerceTestSuite = {
  name: "ECommerce RBAC Tests",
  application: "ECommerceApp",
  team: "platform-team",
  testType: "access-control",
  testIds: [
    "test-admin-read-product",
    "test-guest-read-product",
    "test-manager-write-order",
    // ... more test IDs
  ]
};
```

### Step 5: Run Tests and Review Results

```bash
heimdall test suite ecommerce-rbac-tests
```

**Expected Output:**
```
Running test suite: ECommerce RBAC Tests
✓ Admin can read products - PASSED
✓ Guest cannot read products - PASSED
✓ Manager can write orders - PASSED
...

Test Results: 12/12 passed
Compliance Status: ✅ PASSED
```

## Best Practices

### Template Selection

1. **Choose the right template**: Match your use case
   - RBAC for simple role-based access
   - ABAC for complex attribute-based rules
   - HIPAA for healthcare data
   - GDPR for EU data processing

2. **Start simple**: Begin with RBAC, add complexity as needed

3. **Use compliance templates**: When regulatory compliance is required

### Policy Creation

1. **Review generated policies**: Always preview before creating
2. **Customize after creation**: Templates provide a starting point
3. **Document your choices**: Note why you selected specific configurations
4. **Version control**: Track template configurations and generated policies

### Testing Template Policies

1. **Test positive cases**: Verify allowed access works
2. **Test negative cases**: Verify denied access works
3. **Test edge cases**: Empty arrays, missing attributes, boundary conditions
4. **Test policy interactions**: When multiple policies apply
5. **Test all roles**: Ensure each role has appropriate tests
6. **Test all resources**: Verify access to each resource type
7. **Test all actions**: Validate each action (read, write, delete)

### Test Coverage

Aim for comprehensive test coverage:

- **For RBAC templates**: Test each role × resource × action combination
- **For ABAC templates**: Test attribute combinations and edge cases
- **For compliance templates**: Test all required controls

### Workflow Integration

1. **Template → Policy → Test**: Follow this sequence
2. **Automate testing**: Include tests in CI/CD pipelines
3. **Monitor results**: Track test results over time
4. **Iterate**: Refine policies and tests based on results

## Next Steps

- See [POLICY_CREATION_GUIDE.md](./POLICY_CREATION_GUIDE.md) for manual policy creation
- See [TEST_CREATION_GUIDE.md](./TEST_CREATION_GUIDE.md) for detailed test creation
- Review [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) for quick examples
- Check [examples](../../examples/) for complete examples
