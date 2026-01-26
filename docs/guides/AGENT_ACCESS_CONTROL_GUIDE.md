# Agent Access Control Testing Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Agent Access Control Concepts](#agent-access-control-concepts)
3. [OAuth Flows for Agents](#oauth-flows-for-agents)
4. [Creating Agent Access Control Tests](#creating-agent-access-control-tests)
5. [Testing Dynamic Access Needs](#testing-dynamic-access-needs)
6. [Validating Audit Trails](#validating-audit-trails)
7. [Best Practices](#best-practices)
8. [Examples](#examples)

---

## Introduction

This guide explains how to use Heimdall to test and validate agent access control and AI workflows. Agents differ from traditional applications in that they can take autonomous actions, access multiple services, and have dynamic access needs. This guide covers testing patterns for both delegated access (agents acting on behalf of users) and direct access (autonomous agents).

### Key Concepts

- **Delegated Access**: Agents acting on behalf of users (e.g., email assistant reading user's emails)
- **Direct Access**: Autonomous agents operating independently (e.g., security agent triaging incidents)
- **Dynamic Access**: Context-dependent permissions that change based on time, location, or other factors
- **Multi-Service Access**: Agents accessing multiple services/tools in a single workflow
- **Audit Trail**: Centralized logging of all agent actions across services

---

## Agent Access Control Concepts

### Delegated Access vs Direct Access

#### Delegated Access

Agents with delegated access act on behalf of users. Key characteristics:

- User initiates the request
- Agent inherits user's permissions
- Agent cannot exceed user's permission boundaries
- Uses OAuth Auth Code Flow + OBO Token Flow
- Audit logs include user context

**Example**: Email assistant that reads and responds to emails on behalf of a user.

#### Direct Access

Agents with direct access operate autonomously. Key characteristics:

- No user involvement required
- Agent has its own identity and permissions
- Uses OAuth Client Credentials Flow
- Credentials must be securely managed and rotated
- Audit logs show autonomous operation

**Example**: Security agent that monitors system logs and triages incidents automatically.

### Access Patterns

Agents typically need to:

1. **Access Multiple Services**: Agents often need to call multiple APIs/services to complete a task
2. **Request Dynamic Permissions**: Context-dependent access needs (e.g., JIT access)
3. **Maintain Audit Trails**: All actions must be logged and correlated across services

---

## OAuth Flows for Agents

### Auth Code Flow (Delegated Access)

Used when an agent needs to act on behalf of a user.

**Flow**:
1. User authorizes agent to access resources
2. Authorization server returns authorization code
3. Agent exchanges code for access token
4. Agent uses token to access resources

**Testing**:
```typescript
import { AgentOAuthTester } from '../heimdall-framework/services/agent-oauth-tester';

const oauthTester = new AgentOAuthTester();

const result = await oauthTester.testAuthCodeFlow({
  config: {
    authorizationEndpoint: 'https://auth.example.com/authorize',
    tokenEndpoint: 'https://auth.example.com/token',
    clientId: 'agent-client-id',
    redirectUri: 'https://agent.example.com/callback',
    scopes: ['read:emails', 'write:emails'],
  },
  userContext: {
    userId: 'user-123',
    email: 'user@example.com',
    permissions: ['read:emails', 'write:emails'],
  },
  expectedScopes: ['read:emails', 'write:emails'],
});
```

### OBO Token Flow (On-Behalf-Of)

Used when an agent needs to access downstream services on behalf of a user.

**Flow**:
1. Agent has user's access token
2. Agent exchanges user token for OBO token for target service
3. Agent uses OBO token to access target service

**Testing**:
```typescript
const result = await oauthTester.testOBOTokenFlow({
  config: {
    tokenEndpoint: 'https://service.example.com/token',
    clientId: 'agent-client-id',
    scopes: ['read:documents'],
  },
  userAccessToken: 'user-access-token',
  targetService: 'document-service',
  expectedScopes: ['read:documents'],
});
```

### Client Credentials Flow (Direct Access)

Used for autonomous agents that don't require user interaction.

**Flow**:
1. Agent authenticates with client ID and secret
2. Authorization server returns access token
3. Agent uses token to access resources

**Testing**:
```typescript
const result = await oauthTester.testClientCredentialsFlow({
  config: {
    tokenEndpoint: 'https://auth.example.com/token',
    clientId: 'agent-client-id',
    clientSecret: 'agent-client-secret',
    scopes: ['read:logs', 'write:incidents'],
  },
  expectedScopes: ['read:logs', 'write:incidents'],
  credentialRotation: {
    enabled: true,
    rotationInterval: 90 * 24 * 60 * 60, // 90 days
  },
});
```

---

## Creating Agent Access Control Tests

### Test Types

Heimdall supports five agent-specific test types:

1. **`agent-delegated-access`**: Tests agents acting on behalf of users
2. **`agent-direct-access`**: Tests autonomous agents
3. **`agent-multi-service`**: Tests access across multiple services
4. **`agent-dynamic-access`**: Tests context-dependent permissions
5. **`agent-audit-trail`**: Validates audit logging

### Delegated Access Test Example

```typescript
import { AgentDelegatedAccessTest } from '../heimdall-framework/core/types';

const test: AgentDelegatedAccessTest = {
  id: 'test-001',
  name: 'Email Assistant Delegated Access',
  testType: 'agent-delegated-access',
  domain: 'api_security',
  version: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
  oauthConfig: {
    flowType: 'auth-code',
    authorizationEndpoint: 'https://auth.example.com/authorize',
    tokenEndpoint: 'https://auth.example.com/token',
    clientId: 'email-assistant-client',
    redirectUri: 'https://agent.example.com/callback',
    scopes: ['read:emails'],
  },
  userContext: {
    userId: 'user-123',
    email: 'user@example.com',
    permissions: ['read:emails'],
  },
  agentConfig: {
    agentId: 'email-assistant-001',
    agentType: 'delegated',
    serviceEndpoints: ['https://email-api.example.com'],
  },
  expected: {
    tokenIssued: true,
    userPermissionsEnforced: true,
    permissionBoundariesRespected: true,
  },
};
```

### Direct Access Test Example

```typescript
import { AgentDirectAccessTest } from '../heimdall-framework/core/types';

const test: AgentDirectAccessTest = {
  id: 'test-002',
  name: 'Security Agent Direct Access',
  testType: 'agent-direct-access',
  domain: 'api_security',
  version: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
  oauthConfig: {
    flowType: 'client-credentials',
    tokenEndpoint: 'https://auth.example.com/token',
    clientId: 'security-agent-client',
    scopes: ['read:logs', 'write:incidents'],
  },
  agentConfig: {
    agentId: 'security-agent-001',
    agentType: 'autonomous',
    serviceEndpoints: ['https://logs-api.example.com', 'https://incidents-api.example.com'],
    triggerType: 'event-driven',
  },
  credentialConfig: {
    rotationEnabled: true,
    secureStorage: true,
    credentialLifetime: 90 * 24 * 60 * 60, // 90 days
  },
  expected: {
    tokenIssued: true,
    scopesRespected: true,
    autonomousOperation: true,
    credentialSecurity: true,
  },
};
```

---

## Testing Dynamic Access Needs

Agents often need context-dependent permissions. Heimdall supports testing:

- **Just-in-Time (JIT) Access**: Temporary permissions granted based on context
- **Time-Based Restrictions**: Access allowed only during specific time windows
- **Location-Based Access**: Access restricted to certain locations
- **Dynamic Scope Expansion**: Permissions that expand based on context

### Dynamic Access Test Example

```typescript
import { AgentDynamicAccessTest } from '../heimdall-framework/core/types';

const test: AgentDynamicAccessTest = {
  id: 'test-003',
  name: 'Dynamic Access Test',
  testType: 'agent-dynamic-access',
  domain: 'api_security',
  version: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
  agentConfig: {
    agentId: 'workflow-agent-001',
    agentType: 'delegated',
    userContext: {
      userId: 'user-123',
      permissions: ['read:documents'],
    },
  },
  scenarios: [
    {
      name: 'Office access during business hours',
      context: {
        location: 'office',
        timeOfDay: '14:30',
        ipAddress: '192.168.1.100',
      },
      requestedPermission: 'read:documents',
      expectedGranted: true,
      jitAccess: false,
    },
    {
      name: 'Home access with JIT approval',
      context: {
        location: 'home',
        timeOfDay: '20:00',
        ipAddress: '10.0.0.50',
      },
      requestedPermission: 'read:documents',
      expectedGranted: true,
      jitAccess: true,
    },
  ],
  expected: {
    contextAwareDecisions: true,
    jitAccessWorking: true,
  },
};
```

---

## Validating Audit Trails

Agent actions must be audited and correlated across services. Heimdall provides:

- **Completeness Validation**: Ensures all actions are logged
- **Integrity Validation**: Checks log entry validity and chronological order
- **Cross-Service Correlation**: Validates correlation IDs across services
- **Retention Compliance**: Verifies logs are retained per policy

### Audit Trail Test Example

```typescript
import { AgentAuditTrailTest } from '../heimdall-framework/core/types';

const test: AgentAuditTrailTest = {
  id: 'test-004',
  name: 'Audit Trail Validation',
  testType: 'agent-audit-trail',
  domain: 'api_security',
  version: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
  agentConfig: {
    agentId: 'workflow-agent-001',
    agentType: 'delegated',
    userContext: {
      userId: 'user-123',
    },
  },
  actions: [
    {
      serviceId: 'email-service',
      action: 'read',
      timestamp: new Date(),
      expectedLogged: true,
    },
    {
      serviceId: 'document-service',
      action: 'read',
      timestamp: new Date(),
      expectedLogged: true,
    },
  ],
  auditSources: ['audit-service-1', 'audit-service-2'],
  expected: {
    auditLogComplete: true,
    auditLogIntegrity: true,
    crossServiceCorrelation: true,
    retentionCompliance: true,
  },
};
```

---

## Best Practices

### 1. Permission Boundaries

- **Always enforce user permission boundaries** for delegated access
- **Test that agents cannot exceed user permissions**
- **Validate permission inheritance** in multi-service scenarios

### 2. OAuth Security

- **Use appropriate OAuth flows** for each access pattern
- **Validate scope restrictions** match expected permissions
- **Test credential rotation** for direct access agents
- **Never hardcode credentials** - use runtime configuration

### 3. Audit Logging

- **Log all agent actions** with proper correlation IDs
- **Include user context** for delegated access
- **Aggregate logs from multiple sources** for complete audit trail
- **Validate log retention** per compliance requirements

### 4. Multi-Service Access

- **Test permission consistency** across services
- **Validate service dependencies** are properly handled
- **Check access sequence** maintains proper order
- **Verify service mesh policies** are respected

### 5. Dynamic Access

- **Test context-aware decisions** for all scenarios
- **Validate JIT access** grants and revocations
- **Test time-based restrictions** at boundary conditions
- **Verify location-based access** restrictions

### 6. Test Organization

- **Group related tests** into test suites
- **Use descriptive test names** that explain the scenario
- **Include expected results** in test definitions
- **Document test assumptions** and context

---

## Examples

### Example 1: Email Assistant (Delegated Access)

See [`examples/agent-delegated-access-usage.ts`](../../examples/agent-delegated-access-usage.ts) for a complete example of testing an email assistant agent that acts on behalf of users.

**Key Test Scenarios**:
- User-initiated email access
- Permission delegation validation
- Cross-service access (email + contacts)
- Permission boundary enforcement
- Auth Code Flow validation

### Example 2: Security Agent (Direct Access)

See [`examples/agent-direct-access-usage.ts`](../../examples/agent-direct-access-usage.ts) for a complete example of testing an autonomous security agent.

**Key Test Scenarios**:
- Autonomous operation validation
- Client Credentials Flow testing
- Event-triggered actions
- Credential rotation validation

### Example 3: Multi-Service Workflow

See [`examples/agent-workflow-usage.ts`](../../examples/agent-workflow-usage.ts) for a complete example of testing a multi-service agent workflow.

**Key Test Scenarios**:
- Multi-service access validation
- Service dependency testing
- Permission consistency checks
- Service access sequence validation
- Dynamic access scenarios
- Audit trail validation

---

## API Endpoints

The dashboard API provides endpoints for agent testing:

- `POST /api/agent-tests/delegated-access` - Run delegated access tests
- `POST /api/agent-tests/direct-access` - Run direct access tests
- `GET /api/agent-tests/audit-trail/:agentId` - Get agent audit trail
- `POST /api/agent-tests/multi-service` - Test multi-service access
- `POST /api/agent-tests/dynamic-access` - Test dynamic access
- `POST /api/agent-tests/audit-trail/validate` - Validate audit trail

See the [API documentation](../api/API.md) for detailed endpoint specifications.

---

## Policy Configuration

Agent-specific policies are defined in [`heimdall-framework/policies/abac-policies.json`](../../heimdall-framework/policies/abac-policies.json):

- **`agent-delegated-access`**: Allows delegated agents to inherit user permissions
- **`agent-direct-access`**: Allows autonomous agents based on configured scopes
- **`agent-permission-boundary`**: Prevents agents from exceeding user permissions
- **`agent-dynamic-access-jit`**: Enables Just-in-Time access with proper context
- **`agent-multi-service-access`**: Allows multi-service access with consistency checks
- **`agent-audit-requirement`**: Requires audit logging for all agent actions
- **`agent-time-based-restriction`**: Enforces time-based access restrictions
- **`agent-location-based-restriction`**: Enforces location-based access restrictions

---

## Troubleshooting

### Common Issues

1. **OAuth Flow Failures**
   - Verify endpoints are correct and accessible
   - Check client credentials are valid
   - Ensure scopes match expected permissions

2. **Permission Boundary Violations**
   - Verify user permissions are correctly configured
   - Check policy evaluation logic
   - Validate permission inheritance

3. **Audit Trail Incomplete**
   - Ensure all services log agent actions
   - Verify correlation IDs are included
   - Check audit log aggregation configuration

4. **Multi-Service Consistency Issues**
   - Validate permissions are consistent across services
   - Check service dependency configuration
   - Verify access sequence is maintained

---

## Additional Resources

- [User Guide](./USER_GUIDE.md) - General Heimdall usage guide
- [Policy Creation Guide](./POLICY_CREATION_GUIDE.md) - Creating and managing policies
- [Extensibility Guide](./EXTENSIBILITY_GUIDE.md) - Extending Heimdall functionality
- [API Documentation](../api/API.md) - API endpoint reference

---

## References

- [LangChain Agent Authorization Explainer](https://www.blog.langchain.com/agent-authorization-explainer/) - Concepts and patterns for agent access control
- [OAuth 2.0 Specification](https://oauth.net/2/) - OAuth 2.0 flow documentation
- [NIST Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture) - Zero Trust principles
