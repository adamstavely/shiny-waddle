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
  "applicationId": "app-123",
  "databaseId": "db-456"
}
```

**Alternative Request Body (inline configuration):**
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

**Note:** Either provide `applicationId` and `databaseId` to use infrastructure configuration from an application, or provide a full `database` object for inline testing.

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
  "applicationId": "app-123",
  "databaseId": "db-456"
}
```

**Alternative Request Body (inline configuration):**
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

**Note:** Either provide `applicationId` and `databaseId` to use infrastructure configuration from an application, or provide a full `database` object for inline testing.

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
  "applicationId": "app-123",
  "databaseId": "db-456",
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

**Note:** `applicationId` and `databaseId` are optional. If provided, the test will use the database configuration from the application's infrastructure. Otherwise, provide `testQueries` directly.

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
  "applicationId": "app-123",
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

**Note:** `applicationId` is optional. If provided, the test will use the DLP configuration from the application's infrastructure. Otherwise, provide `user` and `dataOperation` directly.

**Response:**
```json
{
  "testType": "dlp",
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
  "applicationId": "app-123",
  "apiResponse": {
    "id": "123",
    "name": "test"
  },
  "allowedFields": ["id", "name"],
  "piiFields": ["email", "ssn"]
}
```

**Note:** `applicationId` is optional. If provided, the test will use the DLP configuration from the application's infrastructure.

**Response:**
```json
{
  "testType": "dlp",
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
  "applicationId": "app-123",
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

**Note:** `applicationId` is optional. If provided, the test will use the DLP configuration from the application's infrastructure.

**Response:**
```json
{
  "testType": "dlp",
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
  "applicationId": "app-123",
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

**Note:** `applicationId` is optional. If provided, the test will use the DLP configuration from the application's infrastructure.

**Response:**
```json
{
  "testType": "dlp",
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
  "applicationId": "app-123",
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

**Note:** `applicationId` is optional. If provided, the test will use the API Gateway configuration from the application's infrastructure. Otherwise, provide `policy` and `request` directly.

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
  "applicationId": "app-123",
  "endpoint": "/api/test",
  "requests": 100
}
```

**Note:** `applicationId` is optional. If provided, the test will use the API Gateway configuration from the application's infrastructure.

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
  "applicationId": "app-123",
  "version": "v1",
  "endpoint": "/api/test"
}
```

**Note:** `applicationId` is optional. If provided, the test will use the API Gateway configuration from the application's infrastructure.

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
  "applicationId": "app-123",
  "source": "service-1",
  "target": "service-2"
}
```

**Note:** `applicationId` is optional. If provided, the test will use the API Gateway configuration from the application's infrastructure.

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
  "applicationId": "app-123",
  "networkSegmentId": "segment-456"
}
```

**Alternative Request Body (inline configuration):**
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

**Note:** Either provide `applicationId` and `networkSegmentId` to use infrastructure configuration from an application, or provide `rules` directly for inline testing.

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
  "applicationId": "app-123",
  "networkSegmentId": "segment-456",
  "source": "service-1",
  "target": "service-2"
}
```

**Note:** `applicationId` and `networkSegmentId` are optional. If provided, the test will use the network segment configuration from the application's infrastructure.

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
  "applicationId": "app-123",
  "networkSegmentId": "segment-456"
}
```

**Alternative Request Body (inline configuration):**
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

**Note:** Either provide `applicationId` and `networkSegmentId` to use infrastructure configuration from an application, or provide `segments` directly for inline testing.

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
  "applicationId": "app-123",
  "networkSegmentId": "segment-456"
}
```

**Alternative Request Body (inline configuration):**
```json
{
  "config": {
    "name": "test-mesh",
    "type": "istio",
    "policies": []
  }
}
```

**Note:** Either provide `applicationId` and `networkSegmentId` to use infrastructure configuration from an application, or provide `config` directly for inline testing.

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

### API Security

#### Run API Security Test
```http
POST /api/api-security/tests
```

Runs API security tests for an application.

**Request Body:**
```json
{
  "applicationId": "app-123",
  "context": {
    "buildId": "build-456",
    "runId": "run-789",
    "commitSha": "abc123",
    "branch": "main"
  }
}
```

**Response:**
```json
{
  "testType": "api-security",
  "testName": "API Security Test",
  "passed": true,
  "details": {
    "config": {},
    "endpoints": [],
    "results": []
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

**Note:** The test uses the API Security configuration from the application's infrastructure (`application.infrastructure.apiSecurity`).

### Distributed Systems

#### Run Distributed Systems Test
```http
POST /api/distributed-systems/tests/run
```

Runs distributed systems tests for multi-region access and policy synchronization.

**Request Body:**
```json
{
  "applicationId": "app-123",
  "regions": [
    {
      "id": "us-east-1",
      "name": "US East",
      "endpoint": "https://api-us-east.example.com"
    }
  ],
  "testTypes": ["policy-sync", "region-isolation"]
}
```

**Response:**
```json
{
  "testType": "distributed-systems",
  "testName": "Distributed Systems Test",
  "passed": true,
  "details": {
    "regions": [],
    "policySync": {},
    "regionIsolation": {}
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

**Note:** If `applicationId` is provided, the test uses the Distributed Systems configuration from the application's infrastructure (`application.infrastructure.distributedSystems`). Otherwise, provide `regions` directly.

### Data Pipeline

#### Run Data Pipeline Test
```http
POST /api/data-pipeline/applications/:applicationId/test
```

Runs data pipeline tests for an application.

**Path Parameters:**
- `applicationId` (string, required): Application ID

**Request Body:**
```json
{
  "buildId": "build-456",
  "runId": "run-789",
  "commitSha": "abc123",
  "branch": "main"
}
```

**Response:**
```json
{
  "testType": "data-pipeline",
  "testName": "Data Pipeline Test",
  "passed": true,
  "details": {
    "pipelineType": "etl",
    "connection": {},
    "dataSource": {},
    "dataDestination": {},
    "validationResults": []
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

**Note:** The test uses the Data Pipeline configuration from the application's infrastructure (`application.infrastructure.dataPipeline`).

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

## Applications Endpoints

### Application Infrastructure Model

Applications now store their infrastructure configuration directly within the `Application` entity. Infrastructure configurations (databases, network segments, DLP, API Gateway, API Security, Distributed Systems, Data Pipelines) are stored in `application.infrastructure` rather than in separate test configuration entities.

**Infrastructure Structure:**
```json
{
  "infrastructure": {
    "databases": [
      {
        "id": "db-123",
        "name": "Primary Database",
        "type": "postgresql",
        "host": "localhost",
        "port": 5432
      }
    ],
    "networkSegments": [
      {
        "id": "segment-123",
        "name": "Frontend Segment",
        "firewallRules": []
      }
    ],
    "dlp": { /* DLP configuration */ },
    "apiGateway": { /* API Gateway configuration */ },
    "apiSecurity": { /* API Security configuration */ },
    "distributedSystems": { /* Distributed Systems configuration */ },
    "dataPipeline": { /* Data Pipeline configuration */ }
  }
}
```

### Application Test/Validator Management

Data stewards and cyber risk managers can toggle validators on/off for specific applications.

#### Toggle Validator for Application

Enable or disable a specific validator for an application.

```http
PATCH /api/applications/:id/validators/:validatorId/toggle
```

**Path Parameters:**
- `id` (string, required): Application ID
- `validatorId` (string, required): Validator ID

**Request Body:**
```json
{
  "enabled": false,
  "reason": "Validator causing false positives"
}
```

**Response:** Application object with updated overrides

**Permissions Required:** `MANAGE_APPLICATION_VALIDATORS` (Data Steward, Cyber Risk Manager, or Admin)

#### Get Validator Status

Get the status of all validators for an application, including override information.

```http
GET /api/applications/:id/validators/status
```

**Path Parameters:**
- `id` (string, required): Application ID

**Response:**
```json
[
  {
    "validatorId": "validator-123",
    "name": "Access Control Validator",
    "testType": "access-control",
    "enabled": true,
    "override": {
      "enabled": true,
      "reason": "Required for compliance",
      "updatedBy": "steward@example.com",
      "updatedAt": "2024-01-15T10:00:00Z"
    }
  }
]
```

**Permissions Required:** `READ_APPLICATIONS`

#### Bulk Toggle Validators

Toggle multiple validators at once.

```http
PATCH /api/applications/:id/validators/bulk-toggle
```

**Path Parameters:**
- `id` (string, required): Application ID

**Request Body:**
```json
{
  "items": [
    {
      "id": "validator-123",
      "enabled": false,
      "reason": "Disabled for testing"
    }
  ]
}
```

**Response:** Application object with updated overrides

**Permissions Required:** `MANAGE_APPLICATION_VALIDATORS`

#### Remove Validator Override

Remove an override for a validator, reverting to default state.

```http
DELETE /api/applications/:id/validators/:validatorId/override
```

**Path Parameters:**
- `id` (string, required): Application ID
- `validatorId` (string, required): Validator ID

**Response:** Application object with override removed

**Permissions Required:** `MANAGE_APPLICATION_VALIDATORS`

### Run Tests for Application (CI/CD Integration)

Execute tests for an application using its infrastructure configuration. This is the primary endpoint for CI/CD pipeline integration.

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
      "testType": "rls-cls",
      "passed": true,
      "result": {
        "passed": true,
        "coverage": 85,
        "applicationId": "app-123",
        "buildId": "build-456",
        "commitSha": "abc123def",
        "branch": "main",
        "timestamp": "2024-01-15T10:30:00Z"
      }
    },
    {
      "testType": "dlp",
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

## Test Results Endpoints

**Note:** Test results may still contain `testConfigurationId` and `testConfigurationName` fields for backward compatibility with legacy data. New test results use infrastructure-based testing and may not include these fields.

### Query Test Results

Query test results with various filters.

```http
GET /api/test-results
```

**Query Parameters:**
- `applicationId` (string, optional): Filter by application ID
- `testConfigurationId` (string, optional): Filter by test configuration ID (deprecated, for legacy data only)
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

## Test Harness Endpoints

Test Harnesses are collections of test suites that can be assigned to applications.

### Create Test Harness

Create a new test harness.

```http
POST /api/test-harnesses
```

**Request Body:**
```json
{
  "name": "Production Security Tests",
  "description": "Security test suite for production applications",
  "testSuiteIds": ["suite-1", "suite-2"],
  "applicationIds": ["app-1"],
  "team": "Security Team"
}
```

**Response:**
```json
{
  "id": "harness-123",
  "name": "Production Security Tests",
  "description": "Security test suite for production applications",
  "testSuiteIds": ["suite-1", "suite-2"],
  "applicationIds": ["app-1"],
  "team": "Security Team",
  "createdAt": "2024-01-15T10:00:00Z",
  "updatedAt": "2024-01-15T10:00:00Z"
}
```

### List Test Harnesses

Get all test harnesses, optionally filtered by application or test suite.

```http
GET /api/test-harnesses
```

**Query Parameters:**
- `applicationId` (string, optional): Filter harnesses assigned to this application
- `suiteId` (string, optional): Filter harnesses containing this test suite

**Response:**
```json
[
  {
    "id": "harness-123",
    "name": "Production Security Tests",
    "description": "Security test suite for production applications",
    "testSuiteIds": ["suite-1", "suite-2"],
    "applicationIds": ["app-1"],
    "team": "Security Team",
    "createdAt": "2024-01-15T10:00:00Z",
    "updatedAt": "2024-01-15T10:00:00Z"
  }
]
```

### Get Test Harness

Get a specific test harness by ID.

```http
GET /api/test-harnesses/:id
```

**Response:**
```json
{
  "id": "harness-123",
  "name": "Production Security Tests",
  "description": "Security test suite for production applications",
  "testSuiteIds": ["suite-1", "suite-2"],
  "applicationIds": ["app-1"],
  "team": "Security Team",
  "createdAt": "2024-01-15T10:00:00Z",
  "updatedAt": "2024-01-15T10:00:00Z"
}
```

### Update Test Harness

Update an existing test harness.

```http
PUT /api/test-harnesses/:id
```

**Request Body:**
```json
{
  "name": "Updated Security Tests",
  "description": "Updated description",
  "testSuiteIds": ["suite-1", "suite-2", "suite-3"],
  "applicationIds": ["app-1", "app-2"]
}
```

### Delete Test Harness

Delete a test harness.

```http
DELETE /api/test-harnesses/:id
```

**Response:** `204 No Content`

### Add Test Suite to Harness

Add a test suite to a harness.

```http
POST /api/test-harnesses/:id/test-suites
```

**Request Body:**
```json
{
  "suiteId": "suite-3"
}
```

### Remove Test Suite from Harness

Remove a test suite from a harness.

```http
DELETE /api/test-harnesses/:id/test-suites/:suiteId
```

### Assign Harness to Application

Assign a test harness to an application.

```http
POST /api/test-harnesses/:id/applications
```

**Request Body:**
```json
{
  "applicationId": "app-2"
}
```

### Unassign Harness from Application

Remove a test harness assignment from an application.

```http
DELETE /api/test-harnesses/:id/applications/:applicationId
```

## Test Battery Endpoints

Test Batteries are collections of test harnesses with execution configuration.

### Create Test Battery

Create a new test battery.

```http
POST /api/test-batteries
```

**Request Body:**
```json
{
  "name": "Full Security Battery",
  "description": "Complete security test battery for all applications",
  "harnessIds": ["harness-1", "harness-2"],
  "executionConfig": {
    "executionMode": "parallel",
    "timeout": 3600000,
    "stopOnFailure": false
  },
  "team": "Security Team"
}
```

**Response:**
```json
{
  "id": "battery-123",
  "name": "Full Security Battery",
  "description": "Complete security test battery for all applications",
  "harnessIds": ["harness-1", "harness-2"],
  "executionConfig": {
    "executionMode": "parallel",
    "timeout": 3600000,
    "stopOnFailure": false
  },
  "team": "Security Team",
  "createdAt": "2024-01-15T10:00:00Z",
  "updatedAt": "2024-01-15T10:00:00Z"
}
```

### List Test Batteries

Get all test batteries.

```http
GET /api/test-batteries
```

**Response:**
```json
[
  {
    "id": "battery-123",
    "name": "Full Security Battery",
    "description": "Complete security test battery for all applications",
    "harnessIds": ["harness-1", "harness-2"],
    "executionConfig": {
      "executionMode": "parallel",
      "timeout": 3600000,
      "stopOnFailure": false
    },
    "team": "Security Team",
    "createdAt": "2024-01-15T10:00:00Z",
    "updatedAt": "2024-01-15T10:00:00Z"
  }
]
```

### Get Test Battery

Get a specific test battery by ID.

```http
GET /api/test-batteries/:id
```

### Update Test Battery

Update an existing test battery.

```http
PUT /api/test-batteries/:id
```

**Request Body:**
```json
{
  "name": "Updated Battery",
  "harnessIds": ["harness-1", "harness-2", "harness-3"],
  "executionConfig": {
    "executionMode": "sequential",
    "stopOnFailure": true
  }
}
```

### Delete Test Battery

Delete a test battery.

```http
DELETE /api/test-batteries/:id
```

**Response:** `204 No Content`

### Add Harness to Battery

Add a test harness to a battery.

```http
POST /api/test-batteries/:id/harnesses
```

**Request Body:**
```json
{
  "harnessId": "harness-3"
}
```

### Remove Harness from Battery

Remove a test harness from a battery.

```http
DELETE /api/test-batteries/:id/harnesses/:harnessId
```

## Risk Acceptance Endpoints

Manage risk acceptance for test findings.

### Create Risk Acceptance Request

Create a request to accept risk for a finding.

```http
POST /api/finding-approvals/request
```

**Request Body:**
```json
{
  "findingId": "finding-123",
  "requestType": "risk-acceptance",
  "reason": "False positive - expected behavior",
  "requestedBy": "user@example.com",
  "expiresAt": "2024-12-31T23:59:59Z",
  "ticketLink": "https://jira.example.com/ticket/123"
}
```

**Response:**
```json
{
  "id": "approval-123",
  "findingId": "finding-123",
  "requestType": "risk-acceptance",
  "status": "pending",
  "reason": "False positive - expected behavior",
  "requestedBy": "user@example.com",
  "requestedAt": "2024-01-15T10:00:00Z",
  "expiresAt": "2024-12-31T23:59:59Z",
  "ticketLink": "https://jira.example.com/ticket/123",
  "approvals": []
}
```

### Approve Risk Acceptance Request

Approve a risk acceptance request.

```http
POST /api/finding-approvals/:id/approve
```

**Request Body:**
```json
{
  "approverEmail": "approver@example.com",
  "approverRole": "cyber-risk-manager",
  "comments": "Approved - acceptable risk"
}
```

### Reject Risk Acceptance Request

Reject a risk acceptance request.

```http
POST /api/finding-approvals/:id/reject
```

**Request Body:**
```json
{
  "approverEmail": "approver@example.com",
  "approverRole": "cyber-risk-manager",
  "reason": "Risk level too high"
}
```

### Get Pending Requests

Get all pending approval requests.

```http
GET /api/finding-approvals/pending
```

**Query Parameters:**
- `requestType` (string, optional): Filter by request type (`risk-acceptance` or `false-positive`)
- `findingId` (string, optional): Filter by finding ID

### Get Approval Request for Finding

Get approval request status for a specific finding.

```http
GET /api/finding-approvals/finding/:findingId
```

## Remediation Tracking Endpoints

Track remediation progress for test findings.

### Create Remediation Tracking

Create a remediation tracking record for a finding.

```http
POST /api/remediation-tracking
```

**Request Body:**
```json
{
  "findingId": "finding-123",
  "status": "in-progress",
  "assignedTo": "engineer@example.com",
  "ticketLink": "https://jira.example.com/ticket/456",
  "targetDate": "2024-02-01T00:00:00Z",
  "notes": "Working on fix",
  "steps": [
    {
      "step": "Identify root cause",
      "status": "completed",
      "completedAt": "2024-01-15T10:00:00Z"
    },
    {
      "step": "Implement fix",
      "status": "in-progress"
    }
  ]
}
```

**Response:**
```json
{
  "id": "remediation-123",
  "findingId": "finding-123",
  "status": "in-progress",
  "assignedTo": "engineer@example.com",
  "ticketLink": "https://jira.example.com/ticket/456",
  "targetDate": "2024-02-01T00:00:00Z",
  "notes": "Working on fix",
  "progress": 50,
  "steps": [
    {
      "step": "Identify root cause",
      "status": "completed",
      "completedAt": "2024-01-15T10:00:00Z"
    },
    {
      "step": "Implement fix",
      "status": "in-progress"
    }
  ],
  "createdAt": "2024-01-15T10:00:00Z",
  "updatedAt": "2024-01-15T10:00:00Z"
}
```

### Get Remediation Tracking

Get remediation tracking for a specific finding.

```http
GET /api/remediation-tracking/finding/:findingId
```

### Update Remediation Tracking

Update remediation progress.

```http
PUT /api/remediation-tracking/:id
```

**Request Body:**
```json
{
  "status": "in-progress",
  "progress": 75,
  "notes": "Fix implemented, testing",
  "steps": [
    {
      "step": "Identify root cause",
      "status": "completed",
      "completedAt": "2024-01-15T10:00:00Z"
    },
    {
      "step": "Implement fix",
      "status": "completed",
      "completedAt": "2024-01-16T10:00:00Z"
    },
    {
      "step": "Test fix",
      "status": "in-progress"
    }
  ]
}
```

### Get Remediation Metrics

Get aggregated remediation metrics.

```http
GET /api/remediation-tracking/metrics
```

**Query Parameters:**
- `applicationId` (string, optional): Filter by application
- `team` (string, optional): Filter by team
- `status` (string, optional): Filter by status

**Response:**
```json
{
  "totalRemediations": 50,
  "byStatus": {
    "not-started": 10,
    "in-progress": 25,
    "completed": 15
  },
  "averageProgress": 45.5,
  "onTrack": 30,
  "atRisk": 15,
  "overdue": 5
}
```

## Updated Test Results Endpoints

### Query Test Results (Enhanced)

Query test results with enhanced filtering including harness and battery filters.

```http
GET /api/test-results
```

**Query Parameters:**
- `applicationId` (string, optional): Filter by application
- `testConfigurationId` (string, optional): Filter by test configuration
- `testHarnessId` (string, optional): Filter by test harness (returns results for all configurations in harness)
- `testBatteryId` (string, optional): Filter by test battery (returns results for all configurations in battery's harnesses)
- `buildId` (string, optional): Filter by build ID
- `branch` (string, optional): Filter by branch
- `status` (string, optional): Filter by status (`passed`, `failed`, `partial`, `error`)
- `startDate` (string, optional): Start date (ISO 8601)
- `endDate` (string, optional): End date (ISO 8601)
- `limit` (number, optional): Limit number of results
- `offset` (number, optional): Offset for pagination

**Example:**
```http
GET /api/test-results?testHarnessId=harness-123&status=failed&limit=10
```

**Response:**
```json
[
  {
    "id": "result-123",
    "applicationId": "app-1",
    "applicationName": "My Application",
    "testConfigurationId": "config-1",
    "testConfigurationName": "RLS Coverage Test",
    "testConfigurationType": "rls-cls",
    "status": "failed",
    "passed": false,
    "buildId": "build-456",
    "branch": "main",
    "timestamp": "2024-01-15T10:00:00Z",
    "duration": 1250,
    "result": {},
    "error": null,
    "createdAt": "2024-01-15T10:00:00Z"
  }
]
```

### Risk Acceptance for Test Results

Manage risk acceptance for individual test results. These endpoints allow you to accept or reject risk for failed test results, with optional expiration dates and ticket linking.

#### Accept Risk

Accept risk for a failed test result.

```http
POST /api/v1/test-results/:id/accept-risk
```

**Request Body:**
```json
{
  "reason": "False positive - test configuration issue",
  "approver": "john.doe@example.com",
  "expirationDate": "2024-12-31T23:59:59Z",
  "ticketLink": "https://jira.example.com/bug/12345"
}
```

**Request Body Fields:**
- `reason` (string, required): Explanation for accepting this risk
- `approver` (string, required): Email or identifier of the person approving the risk
- `expirationDate` (string, optional): ISO 8601 date when the risk acceptance expires. If not provided, the acceptance does not expire
- `ticketLink` (string, optional): Link to tracking ticket or issue

**Response:**
```json
{
  "id": "result-123",
  "applicationId": "app-1",
  "applicationName": "My Application",
  "testConfigurationId": "config-1",
  "testConfigurationName": "RLS Coverage Test",
  "testConfigurationType": "rls-cls",
  "status": "failed",
  "passed": false,
  "riskAcceptance": {
    "status": "accepted",
    "reason": "False positive - test configuration issue",
    "approver": "john.doe@example.com",
    "acceptedAt": "2024-01-15T10:00:00Z",
    "expirationDate": "2024-12-31T23:59:59Z",
    "ticketLink": "https://jira.example.com/bug/12345"
  },
  "buildId": "build-456",
  "branch": "main",
  "timestamp": "2024-01-15T10:00:00Z",
  "duration": 1250,
  "result": {},
  "error": null,
  "createdAt": "2024-01-15T10:00:00Z"
}
```

#### Reject Risk

Reject a previously accepted risk or explicitly reject risk acceptance for a test result.

```http
POST /api/v1/test-results/:id/reject-risk
```

**Request Body:**
```json
{
  "reason": "Risk is too high, must be remediated",
  "approver": "jane.smith@example.com"
}
```

**Request Body Fields:**
- `reason` (string, required): Explanation for rejecting the risk
- `approver` (string, required): Email or identifier of the person rejecting the risk

**Response:**
```json
{
  "id": "result-123",
  "applicationId": "app-1",
  "applicationName": "My Application",
  "testConfigurationId": "config-1",
  "testConfigurationName": "RLS Coverage Test",
  "testConfigurationType": "rls-cls",
  "status": "failed",
  "passed": false,
  "riskAcceptance": {
    "status": "rejected",
    "reason": "Risk is too high, must be remediated",
    "approver": "jane.smith@example.com",
    "rejectedAt": "2024-01-15T11:00:00Z"
  },
  "buildId": "build-456",
  "branch": "main",
  "timestamp": "2024-01-15T10:00:00Z",
  "duration": 1250,
  "result": {},
  "error": null,
  "createdAt": "2024-01-15T10:00:00Z"
}
```

### Remediation Tracking for Test Results

Track remediation progress for failed test results. This endpoint allows you to update the remediation status, link tickets, assign owners, and track progress.

#### Update Remediation

Update remediation tracking information for a test result.

```http
PUT /api/v1/test-results/:id/remediation
```

**Request Body:**
```json
{
  "status": "in-progress",
  "ticketLink": "https://jira.example.com/bug/12345",
  "assignedTo": "developer@example.com",
  "targetDate": "2024-02-15T23:59:59Z",
  "notes": "Working on fixing RLS policies",
  "progress": 45,
  "steps": [
    {
      "step": "Identify root cause",
      "status": "completed",
      "completedAt": "2024-01-20T10:00:00Z"
    },
    {
      "step": "Update RLS policies",
      "status": "in-progress",
      "completedAt": null
    },
    {
      "step": "Verify fix with tests",
      "status": "pending",
      "completedAt": null
    }
  ]
}
```

**Request Body Fields:**
- `status` (string, optional): Current remediation status. One of: `not-started`, `in-progress`, `completed`
- `ticketLink` (string, optional): Link to tracking ticket or issue
- `assignedTo` (string, optional): Email or identifier of person assigned to remediation
- `targetDate` (string, optional): ISO 8601 date for target completion
- `notes` (string, optional): Additional notes about remediation progress
- `progress` (number, optional): Progress percentage (0-100)
- `steps` (array, optional): Array of remediation steps with status tracking

**Step Object Fields:**
- `step` (string, required): Description of the step
- `status` (string, required): Step status. One of: `pending`, `in-progress`, `completed`
- `completedAt` (string, optional): ISO 8601 date when step was completed

**Response:**
```json
{
  "id": "result-123",
  "applicationId": "app-1",
  "applicationName": "My Application",
  "testConfigurationId": "config-1",
  "testConfigurationName": "RLS Coverage Test",
  "testConfigurationType": "rls-cls",
  "status": "failed",
  "passed": false,
  "remediation": {
    "status": "in-progress",
    "ticketLink": "https://jira.example.com/bug/12345",
    "assignedTo": "developer@example.com",
    "targetDate": "2024-02-15T23:59:59Z",
    "notes": "Working on fixing RLS policies",
    "progress": 45,
    "steps": [
      {
        "step": "Identify root cause",
        "status": "completed",
        "completedAt": "2024-01-20T10:00:00Z"
      },
      {
        "step": "Update RLS policies",
        "status": "in-progress",
        "completedAt": null
      },
      {
        "step": "Verify fix with tests",
        "status": "pending",
        "completedAt": null
      }
    ],
    "updatedAt": "2024-01-20T14:30:00Z"
  },
  "buildId": "build-456",
  "branch": "main",
  "timestamp": "2024-01-15T10:00:00Z",
  "duration": 1250,
  "result": {},
  "error": null,
  "createdAt": "2024-01-15T10:00:00Z"
}
```

**Note:** These endpoints are specific to test results. For managing risk acceptance requests and remediation tracking at a higher level (across multiple findings), see the Finding Approvals and Remediation Tracking module endpoints documented elsewhere in this API documentation.

## Environment Configuration Endpoints

### Validate Environment

Validates environment variables for security issues.

```http
POST /api/environment-config/validate
```

**Request Body:**
```json
{
  "environment": "prod",
  "variables": {
    "DATABASE_URL": "postgresql://...",
    "API_KEY": "sk_live_..."
  },
  "configFiles": ["./config/prod.json"],
  "secrets": ["DATABASE_URL", "API_KEY"]
}
```

**Response:**
```json
{
  "passed": false,
  "environment": "prod",
  "issues": [
    {
      "type": "hardcoded-secret",
      "severity": "critical",
      "field": "API_KEY",
      "message": "Hardcoded API Key detected in environment variable",
      "recommendation": "Use a secrets management system instead of hardcoding secrets"
    }
  ],
  "validatedVariables": 1,
  "totalVariables": 2
}
```

### Validate Secrets

Validates secrets management configuration.

```http
POST /api/environment-config/validate-secrets
```

**Request Body:**
```json
{
  "type": "vault",
  "connection": {
    "address": "https://vault.example.com",
    "token": "vault-token"
  }
}
```

**Response:**
```json
{
  "passed": true,
  "secretsTested": 0,
  "issues": [],
  "rotationPolicies": [],
  "accessControls": []
}
```

### Detect Drift

Detects configuration drift from baseline.

```http
POST /api/environment-config/detect-drift
```

**Request Body:**
```json
{
  "baselineEnvironment": "prod",
  "currentEnvironment": "prod",
  "variables": {
    "DATABASE_URL": "postgresql://..."
  },
  "currentVariables": {
    "DATABASE_URL": "postgresql://...",
    "NEW_VAR": "new-value"
  },
  "configFiles": ["./config/prod.json"],
  "currentConfigFiles": ["./config/prod.json"]
}
```

**Response:**
```json
{
  "hasDrift": true,
  "environment": "prod",
  "drifts": [
    {
      "type": "variable-added",
      "field": "NEW_VAR",
      "currentValue": "new-value",
      "severity": "low",
      "requiresApproval": false
    }
  ],
  "driftScore": 2
}
```

### Validate Environment Policies

Validates environment-specific access policies.

```http
POST /api/environment-config/validate-policies
```

**Request Body:**
```json
{
  "environment": "prod",
  "policies": [],
  "isolationRules": [
    {
      "fromEnvironment": "prod",
      "toEnvironment": "dev",
      "allowed": false
    }
  ],
  "promotionRules": [
    {
      "fromEnvironment": "staging",
      "toEnvironment": "prod",
      "requiredApprovals": 2,
      "requiredChecks": ["security-review", "compliance-check"]
    }
  ]
}
```

**Response:**
```json
{
  "passed": true,
  "environment": "prod",
  "policyIssues": [],
  "isolationVerified": true,
  "promotionRulesValid": true
}
```

## ABAC Correctness Endpoints

### Validate Attributes

Validates ABAC attribute definitions.

```http
POST /api/abac-correctness/validate-attributes
```

**Request Body:**
```json
{
  "attributes": [
    {
      "name": "clearanceLevel",
      "type": "string",
      "source": "ldap",
      "validation": [
        {
          "type": "enum",
          "value": ["low", "medium", "high", "top-secret"]
        }
      ],
      "freshness": {
        "maxAge": 24,
        "unit": "hours"
      }
    }
  ]
}
```

**Response:**
```json
{
  "passed": true,
  "results": [
    {
      "passed": true,
      "attribute": "clearanceLevel",
      "issues": [],
      "schemaValid": true,
      "sourceTrusted": true,
      "freshnessValid": true
    }
  ]
}
```

### Test Completeness

Tests ABAC policy completeness.

```http
POST /api/abac-correctness/test-completeness
```

**Request Body:**
```json
{
  "resourceTypes": ["dataset", "report", "database"],
  "userRoles": ["admin", "researcher", "analyst", "viewer"],
  "actions": ["read", "write", "delete", "create"],
  "policies": [
    {
      "id": "policy-1",
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
    }
  ]
}
```

**Response:**
```json
{
  "passed": false,
  "coverage": {
    "resourceTypes": 66.67,
    "userRoles": 50,
    "actions": 75,
    "edgeCases": 3
  },
  "gaps": [
    {
      "resourceType": "database",
      "userRole": "viewer",
      "action": "write",
      "severity": "medium"
    }
  ],
  "missingPolicies": [
    {
      "resourceType": "database",
      "userRole": "viewer",
      "action": "write",
      "recommendedPolicy": "Policy for viewer to write on database",
      "severity": "medium"
    }
  ]
}
```

### Test Performance

Tests ABAC evaluation performance.

```http
POST /api/abac-correctness/test-performance
```

**Request Body:**
```json
{
  "policies": [
    {
      "id": "policy-1",
      "effect": "allow",
      "conditions": []
    }
  ],
  "testRequests": [
    {
      "subject": {
        "id": "user-1",
        "attributes": {
          "role": "researcher",
          "department": "Research"
        }
      },
      "resource": {
        "id": "dataset-1",
        "type": "dataset",
        "attributes": {
          "department": "Research"
        }
      },
      "context": {},
      "action": "read"
    }
  ],
  "loadConfig": {
    "concurrentRequests": 10,
    "duration": 5000
  }
}
```

**Response:**
```json
{
  "passed": true,
  "averageLatency": 45,
  "p50Latency": 42,
  "p95Latency": 78,
  "p99Latency": 95,
  "throughput": 222.22,
  "recommendations": [
    {
      "type": "enable-caching",
      "description": "Enable policy caching to improve performance",
      "impact": "high"
    }
  ]
}
```

### Detect Conflicts

Detects conflicting ABAC policies.

```http
POST /api/abac-correctness/detect-conflicts
```

**Request Body:**
```json
{
  "policies": [
    {
      "id": "policy-1",
      "effect": "allow",
      "priority": 100,
      "conditions": []
    },
    {
      "id": "policy-2",
      "effect": "deny",
      "priority": 200,
      "conditions": []
    }
  ],
  "resolutionStrategy": "priority"
}
```

**Response:**
```json
{
  "passed": true,
  "conflicts": [
    {
      "policy1": "policy-1",
      "policy2": "policy-2",
      "resource": "unknown",
      "action": "unknown",
      "conflictType": "allow-vs-deny",
      "resolution": {
        "strategy": "priority",
        "resolved": true,
        "resultingDecision": "deny",
        "reason": "Policy policy-2 has higher priority"
      }
    }
  ],
  "resolutionValid": true
}
```

### Test Propagation

Tests attribute propagation across systems.

```http
POST /api/abac-correctness/test-propagation
```

**Request Body:**
```json
{
  "sourceSystem": "ldap",
  "targetSystems": ["api", "database"],
  "attributes": [
    {
      "name": "clearanceLevel",
      "type": "string",
      "source": "ldap",
      "validation": []
    }
  ],
  "transformationRules": [
    {
      "sourceAttribute": "clearanceLevel",
      "targetAttribute": "accessLevel",
      "transformation": "map"
    }
  ]
}
```

**Response:**
```json
{
  "passed": true,
  "propagationResults": [
    {
      "source": "ldap",
      "target": "api",
      "attribute": "clearanceLevel",
      "propagated": true,
      "transformed": true,
      "consistent": true,
      "latency": 50
    }
  ],
  "consistencyIssues": [  ]
}
```

## Salesforce Experience Cloud Endpoints

The Salesforce Experience Cloud endpoints use Google's [aura-inspector](https://github.com/google/aura-inspector) tool to test Salesforce Experience Cloud applications for security misconfigurations and vulnerabilities.

### Configuration Management

#### Create Configuration

```http
POST /api/salesforce-experience-cloud/configs
```

Creates a new Salesforce Experience Cloud test configuration.

**Request Body:**
```json
{
  "name": "Production Site Audit",
  "url": "https://example.force.com",
  "cookies": "sid=...;",
  "app": "/myApp",
  "aura": "/aura",
  "objectList": ["Account", "Contact"],
  "timeout": 300000
}
```

**Response:**
```json
{
  "id": "config-123",
  "name": "Production Site Audit",
  "url": "https://example.force.com",
  "cookies": "sid=...;",
  "app": "/myApp",
  "aura": "/aura",
  "objectList": ["Account", "Contact"],
  "timeout": 300000,
  "createdAt": "2024-01-15T10:00:00Z",
  "updatedAt": "2024-01-15T10:00:00Z"
}
```

#### List Configurations

```http
GET /api/salesforce-experience-cloud/configs
```

Returns all Salesforce Experience Cloud configurations.

**Response:**
```json
[
  {
    "id": "config-123",
    "name": "Production Site Audit",
    "url": "https://example.force.com",
    "createdAt": "2024-01-15T10:00:00Z",
    "updatedAt": "2024-01-15T10:00:00Z"
  }
]
```

#### Get Configuration

```http
GET /api/salesforce-experience-cloud/configs/:id
```

Returns a specific configuration by ID.

#### Update Configuration

```http
PATCH /api/salesforce-experience-cloud/configs/:id
```

Updates an existing configuration.

**Request Body:**
```json
{
  "name": "Updated Production Site Audit",
  "objectList": ["Account", "Contact", "Opportunity"]
}
```

#### Delete Configuration

```http
DELETE /api/salesforce-experience-cloud/configs/:id
```

Deletes a configuration and all associated test results.

### Test Execution

#### Test Guest Access

Tests accessible records from Guest (unauthenticated) context.

```http
POST /api/salesforce-experience-cloud/tests/guest-access
```

**Request Body:**
```json
{
  "configId": "config-123"
}
```

**Response:**
```json
{
  "id": "result-456",
  "configId": "config-123",
  "testName": "Guest Access Test",
  "testType": "guest-access",
  "status": "failed",
  "findings": [
    {
      "type": "guest_access",
      "severity": "high",
      "description": "Account records accessible from guest context",
      "details": {},
      "objects": ["Account"],
      "recordCount": 150,
      "accessibleRecords": []
    }
  ],
  "summary": {
    "totalFindings": 1,
    "criticalCount": 0,
    "highCount": 1,
    "mediumCount": 0
  },
  "timestamp": "2024-01-15T10:00:00Z",
  "createdAt": "2024-01-15T10:00:00Z"
}
```

#### Test Authenticated Access

Tests accessible records from authenticated context.

```http
POST /api/salesforce-experience-cloud/tests/authenticated-access
```

**Request Body:**
```json
{
  "configId": "config-123",
  "cookies": "sid=...;" // Optional: override config cookies
}
```

**Response:** Similar to guest access test response, with `testType: "authenticated-access"`.

#### Test GraphQL Capability

Tests GraphQL Aura method availability and security.

```http
POST /api/salesforce-experience-cloud/tests/graphql
```

**Request Body:**
```json
{
  "configId": "config-123"
}
```

**Response:**
```json
{
  "id": "result-789",
  "configId": "config-123",
  "testName": "GraphQL Capability Test",
  "testType": "graphql",
  "status": "passed",
  "details": {
    "findings": [],
    "graphqlAvailable": true
  },
  "timestamp": "2024-01-15T10:00:00Z",
  "createdAt": "2024-01-15T10:00:00Z"
}
```

#### Test Self-Registration

Checks for self-registration capabilities.

```http
POST /api/salesforce-experience-cloud/tests/self-registration
```

**Request Body:**
```json
{
  "configId": "config-123"
}
```

**Response:**
```json
{
  "id": "result-101",
  "configId": "config-123",
  "testName": "Self-Registration Test",
  "testType": "self-registration",
  "status": "warning",
  "details": {
    "findings": [
      {
        "type": "self_registration",
        "severity": "medium",
        "description": "Self-registration capability detected",
        "details": {}
      }
    ],
    "selfRegistrationAvailable": true
  },
  "timestamp": "2024-01-15T10:00:00Z",
  "createdAt": "2024-01-15T10:00:00Z"
}
```

#### Test Record List Components

Discovers Record List components and checks for misconfigurations.

```http
POST /api/salesforce-experience-cloud/tests/record-lists
```

**Request Body:**
```json
{
  "configId": "config-123"
}
```

**Response:**
```json
{
  "id": "result-102",
  "configId": "config-123",
  "testName": "Record List Components Test",
  "testType": "record-lists",
  "status": "failed",
  "findings": [
    {
      "type": "record_list",
      "severity": "high",
      "description": "Record List component exposes sensitive objects",
      "details": {},
      "objects": ["Account", "Contact"]
    }
  ],
  "details": {
    "findings": [...],
    "objects": ["Account", "Contact"],
    "summary": {
      "totalFindings": 1,
      "misconfiguredObjects": 1
    }
  },
  "timestamp": "2024-01-15T10:00:00Z",
  "createdAt": "2024-01-15T10:00:00Z"
}
```

#### Test Home URLs

Discovers Home URLs that could allow unauthorized admin access.

```http
POST /api/salesforce-experience-cloud/tests/home-urls
```

**Request Body:**
```json
{
  "configId": "config-123"
}
```

**Response:**
```json
{
  "id": "result-103",
  "configId": "config-123",
  "testName": "Home URLs Test",
  "testType": "home-urls",
  "status": "failed",
  "findings": [
    {
      "type": "home_url",
      "severity": "critical",
      "description": "Unauthorized admin access via home URL",
      "details": {},
      "urls": ["https://example.force.com/admin/home"]
    }
  ],
  "details": {
    "findings": [...],
    "urls": ["https://example.force.com/admin/home"],
    "summary": {
      "totalFindings": 1,
      "unauthorizedURLs": 1
    }
  },
  "timestamp": "2024-01-15T10:00:00Z",
  "createdAt": "2024-01-15T10:00:00Z"
}
```

#### Test Object Access

Tests access to specific Salesforce objects.

```http
POST /api/salesforce-experience-cloud/tests/object-access
```

**Request Body:**
```json
{
  "configId": "config-123",
  "objects": ["Account", "Contact", "Opportunity"]
}
```

**Response:** Similar to other test responses, with `testType: "object-access"` and `objects` array in details.

#### Run Full Audit

Runs a complete audit of all test types.

```http
POST /api/salesforce-experience-cloud/tests/full-audit
```

**Request Body:**
```json
{
  "configId": "config-123"
}
```

**Response:**
```json
[
  {
    "id": "result-104",
    "configId": "config-123",
    "testName": "Guest Access - Full Audit",
    "testType": "full-audit",
    "status": "failed",
    ...
  },
  {
    "id": "result-105",
    "configId": "config-123",
    "testName": "GraphQL - Full Audit",
    "testType": "full-audit",
    "status": "passed",
    ...
  }
]
```

### Test Results

#### List Results

```http
GET /api/salesforce-experience-cloud/results
```

Returns all test results, optionally filtered by `configId` query parameter.

**Query Parameters:**
- `configId` (optional): Filter results by configuration ID

**Response:**
```json
[
  {
    "id": "result-456",
    "configId": "config-123",
    "testName": "Guest Access Test",
    "testType": "guest-access",
    "status": "failed",
    "timestamp": "2024-01-15T10:00:00Z",
    "createdAt": "2024-01-15T10:00:00Z"
  }
]
```

#### Get Result

```http
GET /api/salesforce-experience-cloud/results/:id
```

Returns a specific test result by ID.

#### Delete Result

```http
DELETE /api/salesforce-experience-cloud/results/:id
```

Deletes a test result.

### Configuration Options

**Required Fields:**
- `name` (string): Configuration name
- `url` (string): Root URL of Salesforce application (must be valid URL)

**Optional Fields:**
- `cookies` (string): Cookies for authenticated context
- `outputDir` (string): Output directory for aura-inspector results
- `objectList` (string[]): Specific objects to test (e.g., ["Account", "Contact"])
- `app` (string): Custom app path (e.g., "/myApp")
- `aura` (string): Custom aura path (e.g., "/aura")
- `context` (string): Aura context for POST requests
- `token` (string): Aura token for POST requests
- `noGraphQL` (boolean): Disable GraphQL checks
- `proxy` (string): Proxy configuration
- `insecure` (boolean): Ignore TLS certificate validation
- `auraRequestFile` (string): Path to file with aura request
- `auraInspectorPath` (string): Path to aura-inspector installation
- `timeout` (number): Execution timeout in milliseconds (default: 300000)
- `pythonPath` (string): Python executable path (default: "python3")

### Prerequisites

Before using these endpoints, ensure:
1. Python 3.x is installed
2. aura-inspector is installed: `pipx install git+https://github.com/google/aura-inspector`
3. The `aura_cli.py` script is accessible in PATH or specify `auraInspectorPath` in configuration

## Rate Limits

Currently, there are no rate limits enforced. In production, rate limiting should be implemented based on user roles and endpoint criticality.

## Versioning

API versioning is not currently implemented. Future versions will support versioning via URL path (e.g., `/api/v1/...`) or headers.

## Support

For issues or questions, please refer to the project documentation or create an issue in the repository.

