/**
 * API Security Testing Example
 * 
 * Demonstrates how to use the API Security Tester to test REST and GraphQL APIs
 */

import { APISecurityTester } from '../services/api-security-tester';
import { User } from '../core/types';

async function main() {
  // Initialize API Security Tester
  const tester = new APISecurityTester({
    baseUrl: 'https://api.example.com',
    authentication: {
      type: 'bearer',
      credentials: {
        token: process.env.API_TOKEN || 'your-token-here',
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
  });

  // Example 1: Test REST API endpoint
  console.log('Testing REST API...');
  const restResult = await tester.testRESTAPI({
    name: 'Get Users Endpoint',
    endpoint: '/api/v1/users',
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

  const graphqlResult = await tester.testGraphQLAPI(
    graphqlQuery,
    {},
    {
      name: 'GraphQL Users Query',
      endpoint: '/graphql',
      expectedAuthRequired: true,
    }
  );

  console.log('GraphQL Test Result:', {
    passed: graphqlResult.passed,
    statusCode: graphqlResult.statusCode,
    securityIssues: graphqlResult.securityIssues,
  });

  // Example 3: Test rate limiting
  console.log('\nTesting Rate Limiting...');
  const rateLimitResult = await tester.testRateLimiting('/api/v1/data', 'GET');
  console.log('Rate Limit Test Result:', {
    passed: rateLimitResult.passed,
    rateLimitInfo: rateLimitResult.rateLimitInfo,
    details: rateLimitResult.details,
  });

  // Example 4: Test authentication
  console.log('\nTesting Authentication...');
  const authResult = await tester.testAuthentication({
    name: 'Authentication Test',
    endpoint: '/api/v1/protected',
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

  const authzTests = users.map(user => ({
    name: `Authorization Test for ${user.role}`,
    endpoint: '/api/v1/admin/users',
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
  console.log('\nTesting Input Validation...');
  const validationResult = await tester.testInputValidation(
    '/api/v1/search',
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

