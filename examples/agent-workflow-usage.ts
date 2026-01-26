/**
 * Agent Workflow Testing Example
 * 
 * Demonstrates how to test multi-service agent workflows:
 * - Multi-service agent workflow
 * - Tests access across multiple services
 * - Validates audit trail completeness
 * 
 * IMPORTANT: All URLs, endpoints, and credentials should be provided via runtime
 * configuration (environment variables or config files), not hardcoded.
 */

import { AgentMultiServiceTestSuite } from '../heimdall-framework/services/test-suites/agent-multi-service-test-suite';
import { AgentDynamicAccessTestSuite } from '../heimdall-framework/services/test-suites/agent-dynamic-access-test-suite';
import { AgentAuditValidator } from '../heimdall-framework/services/agent-audit-validator';
import { AccessControlConfig } from '../heimdall-framework/core/types';
import { loadRuntimeConfigFromEnv } from '../heimdall-framework/core/config-loader';

async function main() {
  // Load runtime configuration from environment variables
  const runtimeConfig = loadRuntimeConfigFromEnv();

  // Validate that required configuration is present
  if (!runtimeConfig.baseUrl) {
    throw new Error(
      'TEST_BASE_URL environment variable is required. ' +
      'Set it to the base URL of the API being tested (e.g., https://api.example.com)'
    );
  }

  // Initialize access control config
  const accessControlConfig: AccessControlConfig = {
    policyEngine: 'custom',
    cacheDecisions: true,
    policyMode: 'hybrid',
  };

  // Example: Multi-service workflow agent
  const agentId = 'workflow-agent-001';
  const agentType: 'delegated' | 'direct' = 'delegated';
  const userContext = {
    userId: 'user-123',
    permissions: [
      'read:emails',
      'read:calendar',
      'read:documents',
      'write:documents',
    ],
  };

  // Test services
  const services = [
    {
      serviceId: 'email-service',
      resource: {
        id: 'inbox-123',
        type: 'emails',
        attributes: {
          sensitivity: 'internal',
        },
      },
      action: 'read',
    },
    {
      serviceId: 'calendar-service',
      resource: {
        id: 'calendar-123',
        type: 'calendar',
        attributes: {
          sensitivity: 'internal',
        },
      },
      action: 'read',
    },
    {
      serviceId: 'document-service',
      resource: {
        id: 'doc-123',
        type: 'documents',
        attributes: {
          sensitivity: 'internal',
        },
      },
      action: 'read',
    },
  ];

  console.log('Testing Agent Multi-Service Workflow...');
  console.log(`Agent ID: ${agentId}`);
  console.log(`Agent Type: ${agentType}`);
  console.log(`User: ${userContext.userId}`);

  // Initialize test suites
  const multiServiceSuite = new AgentMultiServiceTestSuite({
    accessControlConfig,
  });

  const dynamicAccessSuite = new AgentDynamicAccessTestSuite({
    accessControlConfig,
  });

  const auditValidator = new AgentAuditValidator();

  // Test 1: Multi-service access
  console.log('\n1. Testing multi-service access...');
  const multiServiceResult = await multiServiceSuite.testMultiServiceAccess(
    agentId,
    agentType,
    userContext,
    services.map(service => ({
      ...service,
      expectedAllowed: userContext.permissions.includes(
        `${service.action}:${service.resource.type}`
      ),
    }))
  );
  console.log('Result:', {
    passed: multiServiceResult.passed,
    servicesAllowed: multiServiceResult.details?.servicesAllowed,
    consistency: multiServiceResult.details?.multiServiceConsistency,
  });

  // Test 2: Service dependency
  console.log('\n2. Testing service dependency...');
  const dependencyResult = await multiServiceSuite.testServiceDependency(
    agentId,
    agentType,
    userContext,
    services[0], // Primary service
    services.slice(1).map(service => ({
      ...service,
      dependencyType: 'required' as const,
    }))
  );
  console.log('Result:', {
    passed: dependencyResult.passed,
    allRequiredAccessible: dependencyResult.details?.allRequiredAccessible,
  });

  // Test 3: Permission consistency
  console.log('\n3. Testing permission consistency...');
  const consistencyResult = await multiServiceSuite.testPermissionConsistency(
    agentId,
    agentType,
    userContext,
    services
  );
  console.log('Result:', {
    passed: consistencyResult.passed,
    consistencyCheck: consistencyResult.details?.consistencyCheck,
  });

  // Test 4: Service access sequence
  console.log('\n4. Testing service access sequence...');
  const sequenceResult = await multiServiceSuite.testServiceAccessSequence(
    agentId,
    agentType,
    userContext,
    services.map((service, index) => ({
      ...service,
      order: index + 1,
    }))
  );
  console.log('Result:', {
    passed: sequenceResult.passed,
    allAllowed: sequenceResult.details?.allAllowed,
    sequenceMaintained: sequenceResult.details?.sequenceMaintained,
  });

  // Test 5: Dynamic access scenarios
  console.log('\n5. Testing dynamic access scenarios...');
  const dynamicResults = await dynamicAccessSuite.testContextAwareDecision(
    agentId,
    agentType,
    userContext,
    [
      {
        name: 'Office location access',
        context: {
          location: 'office',
          ipAddress: '192.168.1.100',
          timeOfDay: '14:30',
        },
        requestedPermission: 'read:documents',
        expectedGranted: true,
      },
      {
        name: 'Home location access',
        context: {
          location: 'home',
          ipAddress: '10.0.0.50',
          timeOfDay: '20:00',
        },
        requestedPermission: 'read:documents',
        expectedGranted: false, // May be restricted outside office
      },
    ]
  );
  console.log('Result:', {
    passed: dynamicResults.passed,
    allContextAware: dynamicResults.details?.allContextAware,
  });

  // Test 6: Audit trail validation
  console.log('\n6. Testing audit trail validation...');
  const now = new Date();
  const auditActions = services.map((service, index) => ({
    serviceId: service.serviceId,
    action: service.action,
    resourceId: service.resource.id,
    resourceType: service.resource.type,
    timestamp: new Date(now.getTime() + index * 1000), // Stagger timestamps
    expectedLogged: true,
  }));

  // Add audit log entries
  for (const action of auditActions) {
    auditValidator.addAuditLogEntry(
      {
        id: `audit-${action.serviceId}-${action.timestamp.getTime()}`,
        timestamp: action.timestamp,
        agentId,
        agentType,
        userId: userContext.userId,
        action: action.action,
        serviceId: action.serviceId,
        resourceId: action.resourceId,
        resourceType: action.resourceType,
        allowed: true,
      },
      'audit-service-1'
    );
  }

  const auditValidationResult = await auditValidator.validateAuditTrail({
    agentId,
    agentType,
    userId: userContext.userId,
    actions: auditActions,
    auditSources: ['audit-service-1'],
    retentionPeriod: 90,
  });

  console.log('Result:', {
    passed: auditValidationResult.passed,
    auditLogComplete: auditValidationResult.auditLogComplete,
    auditLogIntegrity: auditValidationResult.auditLogIntegrity,
    crossServiceCorrelation: auditValidationResult.crossServiceCorrelation,
  });

  // Test 7: Audit pattern analysis
  console.log('\n7. Analyzing audit patterns...');
  const patternAnalysis = auditValidator.analyzeAuditPatterns(agentId);
  console.log('Analysis:', {
    anomalies: patternAnalysis.anomalies,
    patterns: patternAnalysis.patterns,
  });

  // Run all multi-service tests
  console.log('\n8. Running all multi-service tests...');
  const allResults = await multiServiceSuite.runAllTests(
    agentId,
    agentType,
    userContext,
    services
  );

  console.log('\n=== Summary ===');
  console.log(`Total tests: ${allResults.length}`);
  console.log(`Passed: ${allResults.filter(r => r.passed).length}`);
  console.log(`Failed: ${allResults.filter(r => !r.passed).length}`);
  console.log(`\nAudit Trail:`);
  console.log(`  Complete: ${auditValidationResult.auditLogComplete}`);
  console.log(`  Integrity: ${auditValidationResult.auditLogIntegrity}`);
  console.log(`  Correlation: ${auditValidationResult.crossServiceCorrelation}`);
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export { main as runAgentWorkflowTests };
