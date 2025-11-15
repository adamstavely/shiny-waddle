/**
 * API Security Enhanced Testing Usage Example
 * 
 * Demonstrates how to use the enhanced API security testing services
 */

import { APIVersioningTester, APIVersion } from '../services/api-versioning-tester';
import { APIGatewayPolicyValidator, APIGatewayConfig } from '../services/api-gateway-policy-validator';
import { WebhookSecurityTester, WebhookConfig } from '../services/webhook-security-tester';
import { GraphQLSecurityValidator, GraphQLConfig } from '../services/graphql-security-validator';
import { APIContractSecurityTester, APIContract } from '../services/api-contract-security-tester';
import { APISecurityEnhancedTestSuite } from '../services/test-suites/api-security-enhanced-test-suite';

async function main() {
  // Example 1: Test API versioning
  console.log('=== Example 1: API Versioning Test ===');
  const versioningTester = new APIVersioningTester();
  
  const apiVersion: APIVersion = {
    version: 'v1',
    endpoint: '/api/v1/users',
    deprecated: true,
    deprecationDate: new Date('2024-01-01'),
    sunsetDate: new Date('2024-12-31'),
    accessControl: {
      requiredRoles: ['admin', 'user'],
      rateLimit: {
        requests: 100,
        window: 60,
      },
    },
  };

  const versioningResult = await versioningTester.testVersionDeprecation(apiVersion);
  console.log('Versioning Test Result:', versioningResult);
  console.log(`Passed: ${versioningResult.passed}`);

  // Example 2: Validate API Gateway policies
  console.log('\n=== Example 2: API Gateway Policy Validation ===');
  const gatewayValidator = new APIGatewayPolicyValidator();
  
  const gatewayConfig: APIGatewayConfig = {
    type: 'aws-api-gateway',
    endpoint: 'https://api.example.com',
    policies: [
      {
        id: 'auth-policy',
        name: 'Authentication Policy',
        type: 'authentication',
        config: {
          method: 'jwt',
        },
      },
      {
        id: 'rate-limit-policy',
        name: 'Rate Limit Policy',
        type: 'rate-limit',
        config: {
          limit: 100,
          window: 60,
        },
      },
    ],
    routes: [
      {
        path: '/api/v1/users',
        method: 'GET',
        target: 'users-service',
        policies: ['auth-policy', 'rate-limit-policy'],
      },
    ],
  };

  const gatewayResult = await gatewayValidator.validateGatewayPolicies(gatewayConfig);
  console.log('Gateway Validation Result:', gatewayResult);
  console.log(`Passed: ${gatewayResult.passed}`);

  // Example 3: Test webhook security
  console.log('\n=== Example 3: Webhook Security Test ===');
  const webhookTester = new WebhookSecurityTester();
  
  const webhookConfig: WebhookConfig = {
    endpoint: 'https://api.example.com/webhooks',
    authentication: {
      type: 'signature',
      method: 'hmac-sha256',
    },
    encryption: {
      enabled: true,
      method: 'tls',
    },
    rateLimiting: {
      maxRequests: 100,
      windowSeconds: 60,
    },
  };

  const webhookResult = await webhookTester.testWebhookAuthentication(webhookConfig);
  console.log('Webhook Security Result:', webhookResult);
  console.log(`Passed: ${webhookResult.passed}`);

  // Example 4: Test GraphQL security
  console.log('\n=== Example 4: GraphQL Security Test ===');
  const graphqlValidator = new GraphQLSecurityValidator();
  
  const graphqlConfig: GraphQLConfig = {
    endpoint: 'https://api.example.com/graphql',
    schema: `
      type User {
        id: ID!
        name: String!
        email: String!
      }
      type Query {
        users: [User!]!
      }
    `,
    maxDepth: 5,
    maxComplexity: 100,
    introspectionEnabled: false,
  };

  const graphqlResult = await graphqlValidator.testQueryDepthLimits(graphqlConfig);
  console.log('GraphQL Security Result:', graphqlResult);
  console.log(`Passed: ${graphqlResult.passed}`);

  // Example 5: Validate API contract security
  console.log('\n=== Example 5: API Contract Security Test ===');
  const contractTester = new APIContractSecurityTester();
  
  const apiContract: APIContract = {
    version: '1.0.0',
    schema: {
      openapi: '3.0.0',
      info: {
        title: 'User API',
        version: '1.0.0',
      },
      paths: {
        '/users': {
          get: {
            responses: {
              '200': {
                description: 'List of users',
                content: {
                  'application/json': {
                    schema: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          id: { type: 'string' },
                          name: { type: 'string' },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    endpoints: [
      {
        path: '/users',
        method: 'GET',
        parameters: [],
        responses: [
          {
            statusCode: '200',
          },
        ],
      },
    ],
  };

  const contractResult = await contractTester.validateContractSecurity(apiContract);
  console.log('Contract Security Result:', contractResult);
  console.log(`Passed: ${contractResult.passed}`);

  // Example 6: Run complete test suite
  console.log('\n=== Example 6: Complete Test Suite ===');
  const testSuite = new APISecurityEnhancedTestSuite();
  
  const suiteConfig = {
    apiVersions: [apiVersion],
    gatewayConfig,
    webhooks: [webhookConfig],
    graphqlConfig,
    contracts: [apiContract],
  };

  const suiteResults = await testSuite.runAllTests(suiteConfig);
  console.log(`Total Tests: ${suiteResults.length}`);
  console.log(`Passed: ${suiteResults.filter(r => r.passed).length}`);
  console.log(`Failed: ${suiteResults.filter(r => !r.passed).length}`);
}

main().catch(console.error);

