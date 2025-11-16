/**
 * API Security Testing Example
 * 
 * Demonstrates how to use the API Security Tester to test REST and GraphQL APIs.
 * 
 * IMPORTANT: All URLs, endpoints, and credentials should be provided via runtime
 * configuration (environment variables or config files), not hardcoded.
 */

import { APISecurityTester } from '../services/api-security-tester';
import { User } from '../core/types';
import { loadRuntimeConfigFromEnv } from '../core/config-loader';
import { RuntimeTestConfig } from '../core/runtime-config';

async function main() {
  // Load runtime configuration from environment variables
  // This should include baseUrl, authentication, endpoints, etc.
  const runtimeConfig = loadRuntimeConfigFromEnv();

  // Validate that required configuration is present
  if (!runtimeConfig.baseUrl) {
    throw new Error(
      'TEST_BASE_URL environment variable is required. ' +
      'Set it to the base URL of the API being tested (e.g., https://api.example.com)'
    );
  }

  // Initialize API Security Tester with runtime configuration
  const tester = new APISecurityTester({
    baseUrl: runtimeConfig.baseUrl,
    authentication: runtimeConfig.authentication || {
      type: 'bearer',
      credentials: {
        token: process.env.API_TOKEN || process.env.TEST_AUTH_TOKEN || '',
      },
    },
    rateLimitConfig: {
      maxRequests: 100,
      windowSeconds: 60,
      strategy: 'fixed',
    },
    headers: {
      'User-Agent': 'Heimdall/1.0',
    },
    timeout: 5000,
    // Use endpoint patterns from runtime config if provided
    endpointPatterns: runtimeConfig.endpointPatterns,
  });

  // Example 1: Test REST API endpoint
  // Use endpoint from runtime config if available, otherwise use a default
  const usersEndpoint = runtimeConfig.endpoints?.users || '/api/v1/users';
  console.log(`Testing REST API endpoint: ${usersEndpoint}`);
  const restResult = await tester.testRESTAPI({
    name: 'Get Users Endpoint',
    endpoint: usersEndpoint,
    method: 'GET',
    expectedStatus: 200,
    expectedAuthRequired: true,
    user: {
      id: 'user-123',
      email: 'test@example.com',
      role: 'researcher',
      attributes: {},
    },
  });

  console.log('REST API Test Result:', {
    passed: restResult.passed,
    statusCode: restResult.statusCode,
    responseTime: restResult.responseTime,
    authenticationResult: restResult.authenticationResult,
    authorizationResult: restResult.authorizationResult,
    securityIssues: restResult.securityIssues,
  });

  // Example 2: Test GraphQL API
  console.log('\nTesting GraphQL API...');
  const graphqlQuery = `
    query {
      users {
        id
        name
        email
      }
    }
  `;

  // Use GraphQL endpoint from runtime config if available
  const graphqlEndpoint = runtimeConfig.endpoints?.graphql || '/graphql';
  const graphqlResult = await tester.testGraphQLAPI(
    graphqlQuery,
    {},
    {
      name: 'GraphQL Users Query',
      endpoint: graphqlEndpoint,
      expectedAuthRequired: true,
    }
  );

  console.log('GraphQL Test Result:', {
    passed: graphqlResult.passed,
    statusCode: graphqlResult.statusCode,
    securityIssues: graphqlResult.securityIssues,
  });

  // Example 3: Test rate limiting
  // Use endpoint from runtime config if available
  const rateLimitEndpoint = runtimeConfig.endpoints?.ratelimit || '/api/v1/data';
  console.log(`\nTesting Rate Limiting on ${rateLimitEndpoint}...`);
  const rateLimitResult = await tester.testRateLimiting(rateLimitEndpoint, 'GET');
  console.log('Rate Limit Test Result:', {
    passed: rateLimitResult.passed,
    rateLimitInfo: rateLimitResult.rateLimitInfo,
    details: rateLimitResult.details,
  });

  // Example 4: Test authentication
  // Use protected endpoint from runtime config if available
  const protectedEndpoint = runtimeConfig.endpoints?.protected || '/api/v1/protected';
  console.log(`\nTesting Authentication on ${protectedEndpoint}...`);
  const authResult = await tester.testAuthentication({
    name: 'Authentication Test',
    endpoint: protectedEndpoint,
    method: 'GET',
    expectedAuthRequired: true,
  });

  console.log('Authentication Test Result:', {
    passed: authResult.passed,
    authenticationResult: authResult.authenticationResult,
    details: authResult.details,
  });

  // Example 5: Test authorization with multiple users
  console.log('\nTesting Authorization...');
  const users: User[] = [
    {
      id: 'admin-1',
      email: 'admin@example.com',
      role: 'admin',
      attributes: {},
    },
    {
      id: 'user-1',
      email: 'user@example.com',
      role: 'viewer',
      attributes: {},
    },
  ];

  // Use admin endpoint from runtime config if available
  const adminEndpoint = runtimeConfig.endpoints?.admin || '/api/v1/admin/users';
  const authzTests = users.map(user => ({
    name: `Authorization Test for ${user.role}`,
    endpoint: adminEndpoint,
    method: 'GET',
    user,
    expectedAuthRequired: true,
  }));

  const authzResults = await tester.testAuthorization(authzTests);
  console.log('Authorization Test Results:');
  authzResults.forEach(result => {
    console.log(`  ${result.testName}:`, {
      passed: result.passed,
      authorized: result.authorizationResult?.authorized,
      reason: result.authorizationResult?.reason,
    });
  });

  // Example 6: Test input validation
  // Use search endpoint from runtime config if available
  const searchEndpoint = runtimeConfig.endpoints?.search || '/api/v1/search';
  console.log(`\nTesting Input Validation on ${searchEndpoint}...`);
  const validationResult = await tester.testInputValidation(
    searchEndpoint,
    'POST'
  );
  console.log('Input Validation Test Result:', {
    passed: validationResult.passed,
    securityIssues: validationResult.securityIssues,
    details: validationResult.details,
  });
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export { main as runAPISecurityTests };

