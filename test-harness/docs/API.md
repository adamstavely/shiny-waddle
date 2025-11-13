# API Documentation

This document provides comprehensive API documentation for the Heimdall Dashboard API, focusing on the new Zero Trust Architecture (ZTA) and Data Access Security features.

## Base URL

```
http://localhost:3001/api
```

## Authentication

Currently, the API does not require authentication. In production, authentication should be implemented using JWT tokens or API keys.

## Error Handling

All endpoints follow a consistent error response format:

```json
{
  "statusCode": 400,
  "message": "Error message",
  "error": "Bad Request",
  "details": {
    "field": "additional error details"
  }
}
```

Common HTTP status codes:
- `200` - Success
- `400` - Bad Request (validation error)
- `404` - Not Found
- `500` - Internal Server Error

## Access Control Endpoints

### Policy Validation

#### Detect Policy Conflicts
```http
POST /api/policy-validation/detect-conflicts
```

Detects conflicts between multiple policies.

**Request Body:**
```json
{
  "policies": [
    {
      "id": "policy-123",
      "name": "Test Policy",
      "description": "Policy description",
      "effect": "allow",
      "conditions": []
    }
  ]
}
```

**Response:**
```json
[
  {
    "policy1": "policy-123",
    "policy2": "policy-456",
    "conflictType": "contradiction",
    "description": "Policies have contradictory effects",
    "affectedResources": ["resource-1"]
  }
]
```

#### Analyze Policy Coverage
```http
POST /api/policy-validation/analyze-coverage
```

Analyzes policy coverage across resources.

**Request Body:**
```json
{
  "resources": [
    {
      "id": "resource-123",
      "type": "dataset",
      "attributes": {}
    }
  ],
  "policies": [
    {
      "id": "policy-123",
      "name": "Test Policy",
      "effect": "allow",
      "conditions": []
    }
  ]
}
```

**Response:**
```json
{
  "totalResources": 10,
  "resourcesWithPolicies": 8,
  "resourcesWithoutPolicies": ["resource-1", "resource-2"],
  "coveragePercentage": 80,
  "gaps": [
    {
      "resource": "resource-1",
      "resourceType": "dataset",
      "recommendedPolicy": "Allow access to resource-1"
    }
  ]
}
```

#### Test Policy Performance
```http
POST /api/policy-validation/test-performance
```

Tests policy evaluation performance.

**Request Body:**
```json
{
  "policy": {
    "id": "policy-123",
    "name": "Test Policy",
    "effect": "allow",
    "conditions": []
  }
}
```

**Response:**
```json
{
  "policyId": "policy-123",
  "evaluationCount": 1000,
  "totalTime": 150.5,
  "averageTime": 0.15,
  "minTime": 0.1,
  "maxTime": 0.3,
  "p50": 0.15,
  "p95": 0.25,
  "p99": 0.28
}
```

#### Run Regression Tests
```http
POST /api/policy-validation/run-regression
```

Runs regression tests comparing baseline and current policies.

**Request Body:**
```json
{
  "baselinePolicies": [],
  "currentPolicies": [],
  "testCases": []
}
```

**Response:**
```json
{
  "policyId": "all-policies",
  "baselineResults": {},
  "currentResults": {},
  "regressions": [
    {
      "testCase": "test-1",
      "baselineResult": true,
      "currentResult": false
    }
  ]
}
```

#### Simulate Policy Change
```http
POST /api/policy-validation/simulate-policy
```

Simulates the impact of a policy change.

**Request Body:**
```json
{
  "policy": {
    "id": "policy-123",
    "name": "New Policy",
    "effect": "allow",
    "conditions": []
  },
  "testCases": []
}
```

**Response:**
```json
{
  "policyId": "policy-123",
  "impactAnalysis": {
    "affectedResources": [],
    "affectedUsers": [],
    "riskScore": 5
  }
}
```

### Identity Lifecycle

#### Test Onboarding
```http
POST /api/identity-lifecycle/test-onboarding
```

Tests identity onboarding workflow.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Identity Onboarding Workflow",
  "passed": true,
  "details": {
    "steps": [
      { "name": "Create Identity", "completed": true },
      { "name": "Assign Default Role", "completed": true },
      { "name": "Enable MFA", "completed": false }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Role Change
```http
POST /api/identity-lifecycle/test-role-change
```

Tests role change workflow.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  },
  "newRole": "admin"
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Role Change Workflow",
  "passed": true,
  "details": {
    "oldRole": "viewer",
    "newRole": "admin",
    "steps": []
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Offboarding
```http
POST /api/identity-lifecycle/test-offboarding
```

Tests identity offboarding workflow.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Identity Offboarding Workflow",
  "passed": true,
  "details": {
    "steps": [
      { "name": "Revoke All Access", "completed": true },
      { "name": "Disable Active Sessions", "completed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Validate Credential Rotation
```http
POST /api/identity-lifecycle/validate-credential-rotation
```

Validates credential rotation requirements.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Credential Rotation Validation",
  "passed": true,
  "details": {
    "checks": [
      { "name": "Password Age Check", "passed": true },
      { "name": "API Key Rotation", "passed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test MFA Enforcement
```http
POST /api/identity-lifecycle/test-mfa-enforcement
```

Tests MFA enforcement for a user.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "admin",
    "attributes": {}
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "MFA Enforcement Test",
  "passed": true,
  "details": {
    "mfaChecks": [
      { "name": "MFA Enabled", "passed": true },
      { "name": "MFA Required for Admin", "passed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test JIT Access
```http
POST /api/identity-lifecycle/test-jit-access
```

Tests just-in-time (JIT) access.

**Request Body:**
```json
{
  "request": {
    "userId": "user-123",
    "resource": "resource-123",
    "duration": 60,
    "reason": "Emergency access",
    "approver": "admin-123"
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Just-In-Time Access Test",
  "passed": true,
  "details": {
    "request": {},
    "validations": [],
    "jitSteps": [],
    "expirationTime": "2024-01-01T01:00:00.000Z"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Break-Glass Access
```http
POST /api/identity-lifecycle/test-break-glass
```

Tests break-glass (emergency) access.

**Request Body:**
```json
{
  "request": {
    "userId": "user-123",
    "resource": "resource-123",
    "duration": 60,
    "reason": "Emergency access",
    "emergency": true
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Break-Glass Access Test",
  "passed": true,
  "details": {
    "request": {},
    "validations": [],
    "breakGlassSteps": [],
    "postAccessReviewRequired": true
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### Identity Providers

#### Test AD Group
```http
POST /api/identity-providers/test-ad-group
```

Tests Active Directory group membership.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  },
  "group": "test-group"
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "AD Group Membership Test: test-group",
  "passed": true,
  "details": {
    "adTest": {
      "user": {},
      "group": "test-group",
      "membership": true,
      "expectedMembership": true,
      "match": true
    }
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Okta Policy
```http
POST /api/identity-providers/test-okta-policy
```

Tests Okta policy synchronization.

**Request Body:**
```json
{
  "policy": {
    "policyId": "okta-policy-123",
    "policyName": "Test Policy",
    "synchronized": true,
    "lastSync": "2024-01-01T00:00:00.000Z",
    "violations": []
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Okta Policy Sync Test: Test Policy",
  "passed": true,
  "details": {
    "policy": {},
    "checks": [
      { "name": "Policy Synchronized", "passed": true },
      { "name": "No Violations", "passed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Auth0 Policy
```http
POST /api/identity-providers/test-auth0-policy
```

Tests Auth0 policy synchronization.

**Request Body:**
```json
{
  "policy": {
    "id": "auth0-policy-123"
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Auth0 Policy Sync Test",
  "passed": true,
  "details": {
    "policy": {},
    "checks": [
      { "name": "Policy Synchronized", "passed": true },
      { "name": "No Violations", "passed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Azure AD Conditional Access
```http
POST /api/identity-providers/test-azure-ad-conditional-access
```

Tests Azure AD conditional access policy.

**Request Body:**
```json
{
  "policy": {
    "id": "azure-policy-123",
    "name": "Test Policy",
    "conditions": {},
    "grantControls": {
      "requireMfa": true
    }
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Azure AD Conditional Access Test: Test Policy",
  "passed": true,
  "details": {
    "policy": {},
    "checks": [
      { "name": "Policy Has Conditions", "passed": true },
      { "name": "MFA Required", "passed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test GCP IAM Binding
```http
POST /api/identity-providers/test-gcp-iam-binding
```

Tests GCP IAM binding.

**Request Body:**
```json
{
  "binding": {
    "resource": "projects/test-project",
    "role": "roles/viewer",
    "members": ["user:test@example.com"]
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "GCP IAM Binding Test: roles/viewer",
  "passed": true,
  "details": {
    "binding": {},
    "checks": [
      { "name": "Resource Valid", "passed": true },
      { "name": "Role Valid", "passed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Validate Policy Sync
```http
POST /api/identity-providers/validate-policy-sync
```

Validates policy synchronization between systems.

**Request Body:**
```json
{
  "source": {
    "type": "okta",
    "config": {}
  },
  "target": {
    "type": "azure-ad",
    "config": {}
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Policy Synchronization: okta -> azure-ad",
  "passed": true,
  "details": {
    "source": {},
    "target": {},
    "checks": [
      { "name": "Source System Accessible", "passed": true },
      { "name": "Policies Match", "passed": true }
    ],
    "synchronized": true
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## Data Security Endpoints

### RLS/CLS

#### Test RLS Coverage
```http
POST /api/rls-cls/test-rls-coverage
```

Tests Row-Level Security (RLS) policy coverage.

**Request Body:**
```json
{
  "database": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "test_db",
    "username": "test_user",
    "password": "test_password"
  }
}
```

**Response:**
```json
{
  "database": "test_db",
  "tablesWithRLS": ["users", "orders"],
  "tablesWithoutRLS": ["products", "payments"],
  "coveragePercentage": 50,
  "totalTables": 4
}
```

#### Test CLS Coverage
```http
POST /api/rls-cls/test-cls-coverage
```

Tests Column-Level Security (CLS) policy coverage.

**Request Body:**
```json
{
  "database": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "test_db",
    "username": "test_user",
    "password": "test_password"
  }
}
```

**Response:**
```json
{
  "database": "test_db",
  "columnsWithCLS": [
    {
      "table": "users",
      "column": "email",
      "policyType": "masking"
    }
  ],
  "columnsWithoutCLS": [
    {
      "table": "users",
      "column": "name"
    }
  ],
  "coveragePercentage": 50
}
```

#### Test Dynamic Masking
```http
POST /api/rls-cls/test-dynamic-masking
```

Tests dynamic data masking.

**Request Body:**
```json
{
  "query": {
    "name": "test-query",
    "sql": "SELECT * FROM users",
    "expectedResult": []
  },
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  },
  "maskingRules": [
    {
      "column": "email",
      "condition": "role != \"admin\"",
      "maskingType": "partial",
      "maskChar": "*"
    }
  ]
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Dynamic Masking Test",
  "passed": true,
  "details": {
    "query": {},
    "user": {},
    "maskingRules": [],
    "maskedResult": {}
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Cross-Tenant Isolation
```http
POST /api/rls-cls/test-cross-tenant-isolation
```

Tests cross-tenant data isolation.

**Request Body:**
```json
{
  "tenant1": "tenant-1",
  "tenant2": "tenant-2",
  "testQueries": [
    {
      "name": "test-query",
      "sql": "SELECT * FROM users",
      "expectedResult": []
    }
  ]
}
```

**Response:**
```json
[
  {
    "testType": "access-control",
    "testName": "Cross-Tenant Isolation Test",
    "passed": true,
    "details": {
      "attempt": "tenant-1 query",
      "securityIssues": 0,
      "bypassDetected": false
    },
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
]
```

#### Test Policy Bypass
```http
POST /api/rls-cls/test-policy-bypass
```

Tests attempts to bypass RLS/CLS policies.

**Request Body:**
```json
{
  "userId": "user-123",
  "resourceId": "resource-123",
  "resourceType": "dataset"
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Policy Bypass Test",
  "passed": true,
  "details": {
    "attempt": "SQL injection attempt",
    "securityIssues": 0,
    "bypassDetected": false
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## Application Security Endpoints

### DLP

#### Test Exfiltration
```http
POST /api/dlp/test-exfiltration
```

Tests data exfiltration detection.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  },
  "dataOperation": {
    "type": "export",
    "data": {
      "test": "data"
    }
  }
}
```

**Response:**
```json
{
  "testType": "data-behavior",
  "testName": "Data Exfiltration Test",
  "passed": true,
  "details": {
    "exfiltrationTest": {
      "user": {},
      "operation": "export",
      "dataSize": 100,
      "detected": false
    }
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Validate API Response
```http
POST /api/dlp/validate-api-response
```

Validates API responses for sensitive data leakage.

**Request Body:**
```json
{
  "apiResponse": {
    "id": "123",
    "name": "test"
  },
  "allowedFields": ["id", "name"],
  "piiFields": ["email", "ssn"]
}
```

**Response:**
```json
{
  "testType": "data-behavior",
  "testName": "API Response Validation",
  "passed": true,
  "details": {
    "violations": [],
    "leakedPII": [],
    "disallowedFields": []
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Query Validation
```http
POST /api/dlp/test-query-validation
```

Validates queries for sensitive data access.

**Request Body:**
```json
{
  "query": {
    "name": "test-query",
    "sql": "SELECT id, name FROM users",
    "expectedResult": []
  },
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  },
  "expectedFields": ["id", "name"]
}
```

**Response:**
```json
{
  "testType": "data-behavior",
  "testName": "Query Validation Test",
  "passed": true,
  "details": {
    "query": {},
    "user": {},
    "expectedFields": ["id", "name"],
    "actualFields": ["id", "name"],
    "violations": []
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Bulk Export
```http
POST /api/dlp/test-bulk-export
```

Tests bulk export controls.

**Request Body:**
```json
{
  "user": {
    "id": "user-123",
    "email": "test@example.com",
    "role": "viewer",
    "attributes": {}
  },
  "exportRequest": {
    "type": "csv",
    "recordCount": 1000
  }
}
```

**Response:**
```json
{
  "testType": "data-behavior",
  "testName": "Bulk Export Controls Test",
  "passed": true,
  "details": {
    "bulkExportTest": {
      "user": {},
      "exportType": "csv",
      "recordCount": 1000,
      "allowed": true
    }
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### API Gateway

#### Test Gateway Policy
```http
POST /api/api-gateway/test-gateway-policy
```

Tests API gateway policy enforcement.

**Request Body:**
```json
{
  "policy": {
    "id": "policy-123",
    "name": "Test Policy",
    "endpoint": "/api/test",
    "method": "GET",
    "rules": []
  },
  "request": {
    "endpoint": "/api/test",
    "method": "GET",
    "headers": {},
    "body": {}
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "API Gateway Policy Test: Test Policy",
  "passed": true,
  "details": {
    "policy": {},
    "request": {},
    "allowed": true,
    "appliedRules": []
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Rate Limiting
```http
POST /api/api-gateway/test-rate-limiting
```

Tests API rate limiting.

**Request Body:**
```json
{
  "endpoint": "/api/test",
  "requests": 100
}
```

**Response:**
```json
{
  "endpoint": "/api/test",
  "requests": 100,
  "timeWindow": 60,
  "limit": 100,
  "actualRequests": 100,
  "blocked": false
}
```

#### Test API Versioning
```http
POST /api/api-gateway/test-api-versioning
```

Tests API versioning.

**Request Body:**
```json
{
  "version": "v1",
  "endpoint": "/api/test"
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "API Versioning Test",
  "passed": true,
  "details": {
    "version": "v1",
    "endpoint": "/api/test",
    "checks": [
      { "name": "Version Not Deprecated", "passed": true },
      { "name": "Version Has Security Updates", "passed": true }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Test Service Auth
```http
POST /api/api-gateway/test-service-auth
```

Tests service-to-service authentication.

**Request Body:**
```json
{
  "source": "service-1",
  "target": "service-2"
}
```

**Response:**
```json
{
  "source": "service-1",
  "target": "service-2",
  "authMethod": "jwt",
  "authenticated": true,
  "tokenValid": true
}
```

## Platform Endpoints

### Network Policy

#### Test Firewall Rules
```http
POST /api/network-policy/test-firewall-rules
```

Tests firewall rule configuration.

**Request Body:**
```json
{
  "rules": [
    {
      "name": "test-rule",
      "source": "10.0.0.0/8",
      "destination": "192.168.1.0/24",
      "protocol": "tcp",
      "port": 443,
      "action": "allow",
      "enabled": true
    }
  ]
}
```

**Response:**
```json
[
  {
    "testType": "access-control",
    "testName": "Firewall Rule Test: test-rule",
    "passed": true,
    "details": {
      "rule": {},
      "validations": [
        { "name": "Rule Enabled", "passed": true },
        { "name": "Source Valid", "passed": true }
      ]
    },
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
]
```

#### Test Service-to-Service
```http
POST /api/network-policy/test-service-to-service
```

Tests service-to-service network connectivity.

**Request Body:**
```json
{
  "source": "service-1",
  "target": "service-2"
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Service-to-Service Traffic Test: service-1 -> service-2",
  "passed": true,
  "details": {
    "source": "service-1",
    "target": "service-2",
    "allowed": true,
    "policyApplied": "Allow service-1 -> service-2"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### Validate Segmentation
```http
POST /api/network-policy/validate-segmentation
```

Validates network segmentation.

**Request Body:**
```json
{
  "segments": [
    {
      "id": "segment-1",
      "name": "Test Segment",
      "services": ["service-1"],
      "allowedConnections": ["segment-2"],
      "deniedConnections": ["segment-3"]
    }
  ]
}
```

**Response:**
```json
[
  {
    "testType": "access-control",
    "testName": "Network Segmentation Test: Test Segment",
    "passed": true,
    "details": {
      "segment": {},
      "violations": []
    },
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
]
```

#### Test Service Mesh Policies
```http
POST /api/network-policy/test-service-mesh-policies
```

Tests service mesh policy enforcement.

**Request Body:**
```json
{
  "config": {
    "name": "test-mesh",
    "type": "istio",
    "policies": []
  }
}
```

**Response:**
```json
{
  "testType": "access-control",
  "testName": "Service Mesh Policy Test",
  "passed": true,
  "details": {
    "config": {},
    "policies": [],
    "validations": []
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## Compliance Endpoints

### NIST 800-207

#### Assess ZTA Pillars
```http
POST /api/compliance/nist-800-207/assess
```

Runs NIST 800-207 Zero Trust Architecture compliance assessment.

**Request Body:**
```json
{
  "assessment": {
    "id": "assessment-123",
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
}
```

**Response:**
```json
{
  "framework": "NIST-800-207",
  "assessment": {
    "id": "assessment-123",
    "timestamp": "2024-01-01T00:00:00.000Z",
    "pillars": [
      {
        "name": "identity",
        "score": 25,
        "maxScore": 30,
        "controls": []
      }
    ],
    "overallScore": 80,
    "gaps": [],
    "recommendations": []
  },
  "compliancePercentage": 80,
  "compliant": true
}
```

#### Generate Compliance Report
```http
POST /api/compliance/nist-800-207/report
```

Generates a compliance report.

**Request Body:**
```json
{
  "assessment": {
    "framework": "NIST-800-207",
    "assessment": {
      "id": "assessment-123",
      "timestamp": "2024-01-01T00:00:00.000Z",
      "pillars": [],
      "overallScore": 80,
      "gaps": [],
      "recommendations": []
    },
    "compliancePercentage": 80,
    "compliant": true
  }
}
```

**Response:**
```
# NIST 800-207 Compliance Report

**Framework:** NIST-800-207
**Assessment ID:** assessment-123
**Date:** 2024-01-01T00:00:00.000Z

## Overall Compliance: 80%

### Pillars Assessment
...
```

## CI/CD Endpoints

### Security Gates

#### Validate Pre-Merge
```http
POST /api/cicd/security-gates/validate-pre-merge
```

Validates pre-merge security policies.

**Request Body:**
```json
{
  "pr": {
    "id": "pr-123",
    "title": "Test PR",
    "author": "test-user",
    "files": ["file1.ts", "file2.ts"],
    "branch": "feature/test",
    "baseBranch": "main"
  },
  "policies": [
    {
      "id": "policy-123",
      "name": "Test Policy",
      "effect": "allow",
      "conditions": []
    }
  ]
}
```

**Response:**
```json
{
  "passed": true,
  "gates": [
    {
      "name": "Policy Requirements",
      "passed": true,
      "details": { "policyCount": 1 }
    }
  ],
  "findings": [],
  "riskScore": 0,
  "message": "All pre-merge policy checks passed"
}
```

#### Check Gates
```http
POST /api/cicd/security-gates/check-gates
```

Checks all security gates for a pull request.

**Request Body:**
```json
{
  "pr": {
    "id": "pr-123",
    "title": "Test PR",
    "author": "test-user",
    "files": ["file1.ts", "Dockerfile"],
    "branch": "feature/test",
    "baseBranch": "main"
  },
  "config": {
    "requirePolicies": true,
    "scanIAC": true,
    "scanContainers": true,
    "validateK8sRBAC": false,
    "failOnThreshold": true,
    "severityThreshold": "high",
    "maxFindings": 10
  }
}
```

**Response:**
```json
{
  "passed": true,
  "gates": [
    {
      "name": "Infrastructure-as-Code Scan",
      "passed": true,
      "details": {}
    },
    {
      "name": "Container Scan: app:latest",
      "passed": true,
      "details": {}
    }
  ],
  "findings": [],
  "riskScore": 0,
  "message": "All security gates passed"
}
```

## Applications and Test Configurations Endpoints

### Assign Test Configurations to Application

Assign test configurations to an application. Test assignments are managed externally (not by users in the UI).

```http
POST /api/applications/:id/test-configurations
```

**Path Parameters:**
- `id` (string, required): Application ID

**Request Body:**
```json
{
  "testConfigurationIds": ["config-id-1", "config-id-2", "config-id-3"]
}
```

**Response:**
```json
{
  "id": "app-123",
  "name": "My Application",
  "type": "api",
  "status": "active",
  "testConfigurationIds": ["config-id-1", "config-id-2", "config-id-3"],
  "registeredAt": "2024-01-15T10:00:00Z",
  "updatedAt": "2024-01-15T10:30:00Z"
}
```

**Status Codes:**
- `200` - Success
- `400` - Bad Request (invalid test configuration IDs)
- `404` - Application not found

### Get Application Test Configurations

Retrieve test configurations assigned to an application.

```http
GET /api/applications/:id/test-configurations
```

**Path Parameters:**
- `id` (string, required): Application ID

**Query Parameters:**
- `expand` (boolean, optional): If `true`, returns full test configuration objects instead of just IDs

**Response (without expand):**
```json
["config-id-1", "config-id-2", "config-id-3"]
```

**Response (with expand=true):**
```json
[
  {
    "id": "config-id-1",
    "name": "RLS/CLS Test Config",
    "type": "rls-cls",
    "description": "Test configuration for RLS/CLS coverage",
    "createdAt": "2024-01-10T10:00:00Z",
    "updatedAt": "2024-01-10T10:00:00Z"
  },
  {
    "id": "config-id-2",
    "name": "DLP Test Config",
    "type": "dlp",
    "description": "Test configuration for DLP patterns",
    "createdAt": "2024-01-11T10:00:00Z",
    "updatedAt": "2024-01-11T10:00:00Z"
  }
]
```

**Status Codes:**
- `200` - Success
- `404` - Application not found

### Run Tests for Application (CI/CD Integration)

Execute all assigned test configurations for an application. This is the primary endpoint for CI/CD pipeline integration.

```http
POST /api/applications/:id/run-tests
```

**Path Parameters:**
- `id` (string, required): Application ID

**Query Parameters:**
- `buildId` (string, optional): CI/CD build identifier
- `runId` (string, optional): CI/CD run identifier
- `commitSha` (string, optional): Git commit SHA
- `branch` (string, optional): Git branch name

**Example Request:**
```http
POST /api/applications/app-123/run-tests?buildId=build-456&commitSha=abc123def&branch=main
```

**Response:**
```json
{
  "status": "passed",
  "totalTests": 3,
  "passed": 3,
  "failed": 0,
  "results": [
    {
      "configId": "config-id-1",
      "configName": "RLS/CLS Test Config",
      "passed": true,
      "result": {
        "passed": true,
        "coverage": 85,
        "applicationId": "app-123",
        "buildId": "build-456",
        "commitSha": "abc123def",
        "branch": "main",
        "testConfigurationId": "config-id-1",
        "testConfigurationName": "RLS/CLS Test Config",
        "timestamp": "2024-01-15T10:30:00Z"
      }
    },
    {
      "configId": "config-id-2",
      "configName": "DLP Test Config",
      "passed": true,
      "result": {
        "passed": true,
        "patternsMatched": 0,
        "applicationId": "app-123",
        "buildId": "build-456",
        "commitSha": "abc123def",
        "branch": "main",
        "testConfigurationId": "config-id-2",
        "testConfigurationName": "DLP Test Config",
        "timestamp": "2024-01-15T10:30:00Z"
      }
    },
    {
      "configId": "config-id-3",
      "configName": "Network Policy Test Config",
      "passed": false,
      "error": {
        "message": "Firewall rule validation failed",
        "type": "BadRequestException",
        "details": {
          "statusCode": 400,
          "message": "Firewall rule validation failed"
        }
      }
    }
  ]
}
```

**Status Field Values:**
- `passed` - All tests passed
- `failed` - All tests failed
- `partial` - Some tests passed, some failed

**Status Codes:**
- `200` - Success (tests executed, check `status` field for results)
- `404` - Application not found

**Note:** If no test configurations are assigned to the application, the response will have `status: "passed"`, `totalTests: 0`, and an empty `results` array.

### Get Applications Using Test Configuration

Retrieve all applications that have a specific test configuration assigned.

```http
GET /api/test-configurations/:id/applications
```

**Path Parameters:**
- `id` (string, required): Test configuration ID

**Response:**
```json
[
  {
    "id": "app-123",
    "name": "My Application",
    "type": "api",
    "status": "active",
    "baseUrl": "https://api.example.com",
    "team": "backend-team",
    "registeredAt": "2024-01-15T10:00:00Z",
    "lastTestAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:30:00Z"
  },
  {
    "id": "app-456",
    "name": "Another Application",
    "type": "web",
    "status": "active",
    "registeredAt": "2024-01-16T10:00:00Z",
    "updatedAt": "2024-01-16T10:00:00Z"
  }
]
```

**Status Codes:**
- `200` - Success
- `404` - Test configuration not found

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Run Heimdall Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Heimdall Tests
        run: |
          response=$(curl -X POST \
            "http://heimdall-api/api/applications/${{ env.APP_ID }}/run-tests?buildId=${{ github.run_id }}&commitSha=${{ github.sha }}&branch=${{ github.ref_name }}" \
            -H "Content-Type: application/json")
          
          status=$(echo $response | jq -r '.status')
          
          if [ "$status" != "passed" ]; then
            echo "Tests failed with status: $status"
            exit 1
          fi
```

### GitLab CI

```yaml
test:
  stage: test
  script:
    - |
      response=$(curl -X POST \
        "http://heimdall-api/api/applications/${APP_ID}/run-tests?buildId=${CI_PIPELINE_ID}&commitSha=${CI_COMMIT_SHA}&branch=${CI_COMMIT_REF_NAME}" \
        -H "Content-Type: application/json")
      
      status=$(echo $response | jq -r '.status')
      
      if [ "$status" != "passed" ]; then
        echo "Tests failed with status: $status"
        exit 1
      fi
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Run Heimdall Tests') {
            steps {
                script {
                    def response = sh(
                        script: """
                            curl -X POST \
                            "http://heimdall-api/api/applications/${env.APP_ID}/run-tests?buildId=${env.BUILD_NUMBER}&commitSha=${env.GIT_COMMIT}&branch=${env.GIT_BRANCH}" \
                            -H "Content-Type: application/json"
                        """,
                        returnStdout: true
                    ).trim()
                    
                    def json = readJSON text: response
                    def status = json.status
                    
                    if (status != "passed") {
                        error("Tests failed with status: ${status}")
                    }
                }
            }
        }
    }
}
```

### Assigning Tests to Applications (External System)

External systems can assign test configurations to applications:

```bash
curl -X POST "http://heimdall-api/api/applications/app-123/test-configurations" \
  -H "Content-Type: application/json" \
  -d '{
    "testConfigurationIds": ["config-id-1", "config-id-2", "config-id-3"]
  }'
```

## Test Results Endpoints

### Query Test Results

Query test results with various filters.

```http
GET /api/test-results
```

**Query Parameters:**
- `applicationId` (string, optional): Filter by application ID
- `testConfigurationId` (string, optional): Filter by test configuration ID
- `buildId` (string, optional): Filter by CI/CD build ID
- `branch` (string, optional): Filter by Git branch name
- `status` (string, optional): Filter by status (`passed`, `failed`, `partial`, `error`)
- `startDate` (string, optional): Filter by start date (ISO 8601 format)
- `endDate` (string, optional): Filter by end date (ISO 8601 format)
- `limit` (number, optional): Maximum number of results to return (default: 20)
- `offset` (number, optional): Number of results to skip (for pagination)

**Response:**
```json
[
  {
    "id": "result-id-1",
    "applicationId": "app-123",
    "applicationName": "Research Tracker API",
    "testConfigurationId": "config-id-1",
    "testConfigurationName": "RLS Coverage Test",
    "testConfigurationType": "rls-cls",
    "status": "passed",
    "passed": true,
    "buildId": "build-456",
    "runId": "run-789",
    "commitSha": "abc123def456",
    "branch": "main",
    "timestamp": "2024-01-15T10:30:00Z",
    "duration": 1250,
    "result": {
      "passed": true,
      "coveragePercentage": 95,
      "policies": [...]
    },
    "error": null,
    "metadata": {
      "buildId": "build-456",
      "runId": "run-789"
    },
    "createdAt": "2024-01-15T10:30:00Z"
  }
]
```

### Get Test Result by ID

Get a specific test result by its ID.

```http
GET /api/test-results/:id
```

**Path Parameters:**
- `id` (string, required): Test result ID

**Response:** Same as individual result object in query response

### Get Test Results for Application

Get all test results for a specific application.

```http
GET /api/test-results/application/:appId
```

**Path Parameters:**
- `appId` (string, required): Application ID

**Query Parameters:**
- `status` (string, optional): Filter by status
- `branch` (string, optional): Filter by branch
- `limit` (number, optional): Maximum number of results
- `offset` (number, optional): Number of results to skip

**Response:** Array of test result objects

### Get Test Results for Test Configuration

Get all test results for a specific test configuration.

```http
GET /api/test-results/test-configuration/:configId
```

**Path Parameters:**
- `configId` (string, required): Test configuration ID

**Query Parameters:** Same as application endpoint

**Response:** Array of test result objects

### Get Test Results for Build

Get all test results for a specific CI/CD build.

```http
GET /api/test-results/build/:buildId
```

**Path Parameters:**
- `buildId` (string, required): Build ID

**Response:** Array of test result objects

### Get Compliance Metrics

Get compliance metrics and statistics.

```http
GET /api/test-results/compliance/metrics
```

**Query Parameters:**
- `applicationId` (string, optional): Filter by application
- `testConfigurationId` (string, optional): Filter by test configuration
- `startDate` (string, optional): Start date for metrics period
- `endDate` (string, optional): End date for metrics period

**Response:**
```json
{
  "period": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-31T23:59:59Z"
  },
  "overall": {
    "totalTests": 150,
    "passed": 135,
    "failed": 10,
    "partial": 3,
    "errors": 2,
    "passRate": 90.0,
    "averageDuration": 1250,
    "trend": "improving"
  },
  "byTestConfiguration": {
    "config-id-1": {
      "configName": "RLS Coverage Test",
      "configType": "rls-cls",
      "totalTests": 50,
      "passed": 48,
      "failed": 2,
      "passRate": 96.0
    }
  },
  "failingTests": [
    {
      "configId": "config-id-2",
      "configName": "DLP Test",
      "lastFailure": "2024-01-15T10:30:00Z",
      "failureCount": 5
    }
  ],
  "trends": [
    {
      "period": "2024-01-15",
      "passRate": 92.5,
      "totalTests": 10
    }
  ]
}
```

### Get Compliance Trends

Get compliance trends over time.

```http
GET /api/test-results/compliance/trends
```

**Query Parameters:**
- `applicationId` (string, optional): Filter by application
- `testConfigurationId` (string, optional): Filter by test configuration
- `period` (string, optional): Grouping period (`day`, `week`, `month`, default: `day`)
- `startDate` (string, optional): Start date
- `endDate` (string, optional): End date

**Response:**
```json
[
  {
    "period": "2024-01-15",
    "passRate": 92.5,
    "totalTests": 10
  },
  {
    "period": "2024-01-16",
    "passRate": 95.0,
    "totalTests": 12
  }
]
```

## Rate Limits

Currently, there are no rate limits enforced. In production, rate limiting should be implemented based on user roles and endpoint criticality.

## Versioning

API versioning is not currently implemented. Future versions will support versioning via URL path (e.g., `/api/v1/...`) or headers.

## Support

For issues or questions, please refer to the project documentation or create an issue in the repository.

