/**
 * API Security Enhanced Test Suite
 * 
 * Orchestrates enhanced API security tests including versioning, gateway policies, webhooks, GraphQL, and contracts
 */

import { TestResult } from '../../core/types';
import { APIVersioningTester, APIVersion } from '../api-versioning-tester';
import { APIGatewayPolicyValidator, APIGatewayConfig } from '../api-gateway-policy-validator';
import { WebhookSecurityTester, WebhookConfig } from '../webhook-security-tester';
import { GraphQLSecurityValidator, GraphQLConfig } from '../graphql-security-validator';
import { APIContractSecurityTester, APIContract } from '../api-contract-security-tester';

export interface APISecurityTestConfig {
  apiVersions: APIVersion[];
  gatewayConfig?: APIGatewayConfig;
  webhooks?: WebhookConfig[];
  graphqlConfig?: GraphQLConfig;
  contracts?: APIContract[];
}

export class APISecurityEnhancedTestSuite {
  private versioningTester: APIVersioningTester;
  private gatewayValidator: APIGatewayPolicyValidator;
  private webhookTester: WebhookSecurityTester;
  private graphqlValidator: GraphQLSecurityValidator;
  private contractTester: APIContractSecurityTester;

  constructor() {
    this.versioningTester = new APIVersioningTester();
    this.gatewayValidator = new APIGatewayPolicyValidator();
    this.webhookTester = new WebhookSecurityTester();
    this.graphqlValidator = new GraphQLSecurityValidator();
    this.contractTester = new APIContractSecurityTester();
  }

  /**
   * Run all API security tests
   */
  async runAllTests(
    config: APISecurityTestConfig
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Test 1: API Versioning
    for (const version of config.apiVersions) {
      try {
        const versioningResult = await this.versioningTester.testVersionDeprecation(version);
        results.push({
          testType: 'api-security',
          testName: `API Versioning Test - ${version.version}`,
          passed: versioningResult.passed,
          details: versioningResult,
          timestamp: new Date(),
        });
      } catch (error: any) {
        results.push({
          testType: 'api-security',
          testName: `API Versioning Test - ${version.version}`,
          passed: false,
          details: { error: error.message },
          timestamp: new Date(),
          error: error.message,
        });
      }
    }

    // Test 2: API Gateway Policies
    if (config.gatewayConfig) {
      try {
        const gatewayResult = await this.gatewayValidator.validateGatewayPolicies(config.gatewayConfig);
        results.push({
          testType: 'api-security',
          testName: 'API Gateway Policy Validation',
          passed: gatewayResult.passed,
          details: gatewayResult,
          timestamp: new Date(),
        });
      } catch (error: any) {
        results.push({
          testType: 'api-security',
          testName: 'API Gateway Policy Validation',
          passed: false,
          details: { error: error.message },
          timestamp: new Date(),
          error: error.message,
        });
      }
    }

    // Test 3: Webhook Security
    if (config.webhooks) {
      for (const webhook of config.webhooks) {
        try {
          const webhookResult = await this.webhookTester.testWebhookAuthentication(webhook);
          results.push({
            testType: 'api-security',
            testName: `Webhook Security Test - ${webhook.endpoint}`,
            passed: webhookResult.passed,
            details: webhookResult,
            timestamp: new Date(),
          });
        } catch (error: any) {
          results.push({
            testType: 'api-security',
            testName: `Webhook Security Test - ${webhook.endpoint}`,
            passed: false,
            details: { error: error.message },
            timestamp: new Date(),
            error: error.message,
          });
        }
      }
    }

    // Test 4: GraphQL Security
    if (config.graphqlConfig) {
      try {
        const graphqlResult = await this.graphqlValidator.testQueryDepthLimits(config.graphqlConfig);
        results.push({
          testType: 'api-security',
          testName: 'GraphQL Security Test',
          passed: graphqlResult.passed,
          details: graphqlResult,
          timestamp: new Date(),
        });
      } catch (error: any) {
        results.push({
          testType: 'api-security',
          testName: 'GraphQL Security Test',
          passed: false,
          details: { error: error.message },
          timestamp: new Date(),
          error: error.message,
        });
      }
    }

    // Test 5: API Contract Security
    if (config.contracts) {
      for (const contract of config.contracts) {
        try {
          const contractResult = await this.contractTester.validateContractSecurity(contract);
          results.push({
            testType: 'api-security',
            testName: `API Contract Security Test - ${contract.version}`,
            passed: contractResult.passed,
            details: contractResult,
            timestamp: new Date(),
          });
        } catch (error: any) {
          results.push({
            testType: 'api-security',
            testName: `API Contract Security Test - ${contract.version}`,
            passed: false,
            details: { error: error.message },
            timestamp: new Date(),
            error: error.message,
          });
        }
      }
    }

    return results;
  }
}

