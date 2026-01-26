/**
 * Agent Direct Access Testing Example
 * 
 * Demonstrates how to test autonomous agents:
 * - Security agent triaging incidents
 * - Tests Client Credentials Flow
 * - Validates autonomous operation
 * 
 * IMPORTANT: All URLs, endpoints, and credentials should be provided via runtime
 * configuration (environment variables or config files), not hardcoded.
 */

import { AgentDirectAccessTestSuite } from '../heimdall-framework/services/test-suites/agent-direct-access-test-suite';
import { AccessControlConfig, OAuthFlowConfig } from '../heimdall-framework/core/types';
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

  // Initialize OAuth config for Client Credentials flow
  const oauthConfig: OAuthFlowConfig | undefined = runtimeConfig.oauthConfig || {
    tokenEndpoint: process.env.OAUTH_TOKEN_ENDPOINT || '',
    clientId: process.env.OAUTH_CLIENT_ID || '',
    clientSecret: process.env.OAUTH_CLIENT_SECRET || '',
    scopes: ['read:logs', 'read:incidents', 'write:incidents'],
  };

  // Initialize test suite
  const testSuite = new AgentDirectAccessTestSuite({
    accessControlConfig,
    oauthConfig: oauthConfig.tokenEndpoint ? oauthConfig : undefined,
  });

  // Example: Security agent
  const agentId = 'security-agent-001';
  const agentType: 'autonomous' | 'event-driven' | 'scheduled' = 'autonomous';

  // Test resources
  const resources = [
    {
      id: 'system-logs',
      type: 'logs',
      attributes: {
        sensitivity: 'internal',
        source: 'security-monitoring',
      },
    },
    {
      id: 'incidents-queue',
      type: 'incidents',
      attributes: {
        sensitivity: 'internal',
        severity: 'high',
      },
    },
  ];

  const actions = ['read', 'write'];
  const scopes = ['read:logs', 'read:incidents', 'write:incidents'];

  console.log('Testing Agent Direct Access...');
  console.log(`Agent ID: ${agentId}`);
  console.log(`Agent Type: ${agentType}`);

  // Test 1: Autonomous operation
  console.log('\n1. Testing autonomous operation...');
  const autonomousResult = await testSuite.testAutonomousOperation(
    agentId,
    agentType,
    resources[0],
    'read',
    true
  );
  console.log('Result:', {
    passed: autonomousResult.passed,
    allowed: autonomousResult.details?.allowed,
  });

  // Test 2: Service-to-service authentication
  if (oauthConfig.tokenEndpoint) {
    console.log('\n2. Testing service-to-service authentication (Client Credentials)...');
    const authResult = await testSuite.testServiceToServiceAuth(agentId, scopes);
    console.log('Result:', {
      passed: authResult.passed,
      tokenIssued: authResult.details?.tokenIssued,
      scopesRespected: authResult.details?.scopesGranted,
    });
  }

  // Test 3: Event-triggered action
  console.log('\n3. Testing event-triggered action...');
  const eventResult = await testSuite.testEventTriggeredAction(
    agentId,
    'security-incident',
    resources[1],
    'write',
    {
      ipAddress: '192.168.1.100',
      timeOfDay: '14:30',
    }
  );
  console.log('Result:', {
    passed: eventResult.passed,
    allowed: eventResult.details?.allowed,
  });

  // Test 4: Independent operation
  console.log('\n4. Testing independent operation...');
  const independentResults = await testSuite.testIndependentOperation(
    agentId,
    resources,
    actions
  );
  console.log(`Results: ${independentResults.filter(r => r.passed).length}/${independentResults.length} passed`);

  // Test 5: Credential rotation
  if (oauthConfig.tokenEndpoint) {
    console.log('\n5. Testing credential rotation...');
    const rotationResult = await testSuite.testCredentialRotation(agentId, scopes);
    console.log('Result:', {
      passed: rotationResult.passed,
      recommendation: rotationResult.details?.recommendation,
    });
  }

  // Run all tests
  console.log('\n6. Running all direct access tests...');
  const allResults = await testSuite.runAllTests(
    agentId,
    resources,
    actions,
    scopes
  );

  console.log('\n=== Summary ===');
  console.log(`Total tests: ${allResults.length}`);
  console.log(`Passed: ${allResults.filter(r => r.passed).length}`);
  console.log(`Failed: ${allResults.filter(r => !r.passed).length}`);
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export { main as runAgentDirectAccessTests };
