/**
 * Agent Delegated Access Testing Example
 * 
 * Demonstrates how to test agents acting on behalf of users:
 * - Email assistant accessing user's emails
 * - Tests Auth Code Flow + OBO Token Flow
 * - Validates user permission boundaries
 * 
 * IMPORTANT: All URLs, endpoints, and credentials should be provided via runtime
 * configuration (environment variables or config files), not hardcoded.
 */

import { AgentDelegatedAccessTestSuite } from '../heimdall-framework/services/test-suites/agent-delegated-access-test-suite';
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

  // Initialize OAuth config if provided
  const oauthConfig = runtimeConfig.oauthConfig || {
    authorizationEndpoint: process.env.OAUTH_AUTHORIZATION_ENDPOINT || '',
    tokenEndpoint: process.env.OAUTH_TOKEN_ENDPOINT || '',
    clientId: process.env.OAUTH_CLIENT_ID || '',
    redirectUri: process.env.OAUTH_REDIRECT_URI || 'http://localhost:3000/callback',
  };

  // Initialize test suite
  const testSuite = new AgentDelegatedAccessTestSuite({
    accessControlConfig,
    oauthConfig: oauthConfig.authorizationEndpoint ? oauthConfig : undefined,
  });

  // Example: Email assistant agent
  const agentId = 'email-assistant-001';
  const userContext = {
    userId: 'user-123',
    email: 'user@example.com',
    role: 'researcher',
    permissions: [
      'read:emails',
      'read:contacts',
      'write:emails',
    ],
  };

  // Test resources
  const resources = [
    {
      id: 'inbox-123',
      type: 'emails',
      attributes: {
        sensitivity: 'internal',
      },
    },
    {
      id: 'contacts-123',
      type: 'contacts',
      attributes: {
        sensitivity: 'internal',
      },
    },
  ];

  const actions = ['read', 'write'];

  console.log('Testing Agent Delegated Access...');
  console.log(`Agent ID: ${agentId}`);
  console.log(`User: ${userContext.email}`);

  // Test 1: User-initiated request
  console.log('\n1. Testing user-initiated request...');
  const userInitResult = await testSuite.testUserInitiatedRequest(
    agentId,
    userContext,
    resources[0],
    'read'
  );
  console.log('Result:', {
    passed: userInitResult.passed,
    details: userInitResult.details,
  });

  // Test 2: Permission delegation
  console.log('\n2. Testing permission delegation...');
  const delegationResults = await testSuite.testPermissionDelegation(
    agentId,
    userContext,
    resources,
    actions
  );
  console.log(`Results: ${delegationResults.filter(r => r.passed).length}/${delegationResults.length} passed`);

  // Test 3: Cross-service access (OBO flow)
  console.log('\n3. Testing cross-service access (OBO flow)...');
  const crossServiceResult = await testSuite.testCrossServiceAccess(
    agentId,
    userContext,
    [
      {
        serviceId: 'email-service',
        resource: resources[0],
        action: 'read',
      },
      {
        serviceId: 'contacts-service',
        resource: resources[1],
        action: 'read',
      },
    ]
  );
  console.log('Result:', {
    passed: crossServiceResult.passed,
    details: crossServiceResult.details,
  });

  // Test 4: Permission boundaries
  console.log('\n4. Testing permission boundaries...');
  const boundaryResult = await testSuite.testPermissionBoundaries(
    agentId,
    userContext,
    resources,
    ['read', 'write', 'delete'] // Include 'delete' which user doesn't have
  );
  console.log('Result:', {
    passed: boundaryResult.passed,
    violations: boundaryResult.details?.violations,
  });

  // Test 5: Auth Code Flow (if OAuth config provided)
  if (oauthConfig.authorizationEndpoint) {
    console.log('\n5. Testing Auth Code Flow...');
    const authCodeResult = await testSuite.testAuthCodeFlow(
      userContext,
      ['read:emails', 'read:contacts']
    );
    console.log('Result:', {
      passed: authCodeResult.passed,
      tokenIssued: authCodeResult.details?.tokenIssued,
      userPermissionsEnforced: authCodeResult.details?.userPermissionsEnforced,
    });
  }

  // Run all tests
  console.log('\n6. Running all delegated access tests...');
  const allResults = await testSuite.runAllTests(
    agentId,
    userContext,
    resources,
    actions
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

export { main as runAgentDelegatedAccessTests };
