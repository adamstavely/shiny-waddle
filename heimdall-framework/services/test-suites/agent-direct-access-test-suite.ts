/**
 * Agent Direct Access Test Suite
 * 
 * Tests for autonomous agents:
 * - Autonomous agent operations
 * - Service-to-service authentication
 * - Event-triggered agent actions
 * - Independent operation validation
 */

import { AgentAccessControlTester, DirectAccessTest } from '../agent-access-control-tester';
import { AgentOAuthTester, ClientCredentialsFlowTest, OAuthFlowConfig } from '../agent-oauth-tester';
import { AccessControlConfig, Resource, Context } from '../../core/types';
import { TestResult } from '../../core/types';

export interface AgentDirectAccessTestSuiteConfig {
  accessControlConfig: AccessControlConfig;
  oauthConfig?: OAuthFlowConfig;
}

export class AgentDirectAccessTestSuite {
  private accessControlTester: AgentAccessControlTester;
  private oauthTester: AgentOAuthTester;
  private config: AgentDirectAccessTestSuiteConfig;

  constructor(config: AgentDirectAccessTestSuiteConfig) {
    this.config = config;
    this.accessControlTester = new AgentAccessControlTester(
      config.accessControlConfig
    );
    this.oauthTester = new AgentOAuthTester();
  }

  /**
   * Test autonomous agent operation
   */
  async testAutonomousOperation(
    agentId: string,
    agentType: 'autonomous' | 'event-driven' | 'scheduled',
    resource: Resource,
    action: string,
    expectedAllowed: boolean
  ): Promise<TestResult> {
    const test: DirectAccessTest = {
      agentId,
      agentType,
      resource,
      action,
      expectedAllowed,
      oauthConfig: this.config.oauthConfig,
    };

    const result = await this.accessControlTester.testDirectAccess(test);

    return {
      testType: 'agent-direct-access',
      testName: `Autonomous Operation Test - ${agentId}`,
      passed: result.passed,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        resource: resource.id,
        action,
        allowed: result.allowed,
        expectedAllowed,
        oauthTest: result.details?.oauthTest,
      },
    };
  }

  /**
   * Test service-to-service authentication
   */
  async testServiceToServiceAuth(
    agentId: string,
    scopes: string[]
  ): Promise<TestResult> {
    if (!this.config.oauthConfig) {
      return {
        testType: 'agent-direct-access',
        testName: 'Service-to-Service Auth Test',
        passed: false,
        timestamp: new Date(),
        error: 'OAuth configuration not provided',
        details: {},
      };
    }

    const test: ClientCredentialsFlowTest = {
      config: {
        ...this.config.oauthConfig,
        scopes,
      },
      expectedScopes: scopes,
      credentialRotation: {
        enabled: true,
        rotationInterval: 90 * 24 * 60 * 60, // 90 days in seconds
      },
    };

    const result = await this.oauthTester.testClientCredentialsFlow(test);

    return {
      testType: 'agent-direct-access',
      testName: 'Service-to-Service Auth Test',
      passed: result.passed,
      timestamp: new Date(),
      details: {
        tokenIssued: result.tokenIssued,
        tokenValid: result.tokenValid,
        scopesGranted: result.scopesGranted,
        scopesExpected: result.scopesExpected,
        scopeMismatch: result.scopeMismatch,
        credentialSecurity: result.credentialSecurity,
      },
    };
  }

  /**
   * Test event-triggered agent action
   */
  async testEventTriggeredAction(
    agentId: string,
    eventType: string,
    resource: Resource,
    action: string,
    context?: Context
  ): Promise<TestResult> {
    const test: DirectAccessTest = {
      agentId,
      agentType: 'event-driven',
      resource,
      action,
      context: {
        ...context,
        additionalAttributes: {
          ...context?.additionalAttributes,
          eventType,
          triggeredAt: new Date().toISOString(),
        },
      },
      expectedAllowed: true,
      oauthConfig: this.config.oauthConfig,
    };

    const result = await this.accessControlTester.testDirectAccess(test);

    return {
      testType: 'agent-direct-access',
      testName: `Event-Triggered Action Test - ${eventType}`,
      passed: result.passed,
      timestamp: new Date(),
      details: {
        agentId,
        eventType,
        resource: resource.id,
        action,
        allowed: result.allowed,
        context: test.context,
      },
    };
  }

  /**
   * Test independent operation validation
   */
  async testIndependentOperation(
    agentId: string,
    resources: Resource[],
    actions: string[]
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    for (const resource of resources) {
      for (const action of actions) {
        const test: DirectAccessTest = {
          agentId,
          agentType: 'autonomous',
          resource,
          action,
          expectedAllowed: true,
          oauthConfig: this.config.oauthConfig,
        };

        const result = await this.accessControlTester.testDirectAccess(test);
        results.push({
          testType: 'agent-direct-access',
          testName: `Independent Operation Test - ${action} ${resource.type}`,
          passed: result.passed,
          timestamp: new Date(),
          details: {
            agentId,
            resource: resource.id,
            action,
            allowed: result.allowed,
            expectedAllowed: true,
            autonomous: true,
          },
        });
      }
    }

    return results;
  }

  /**
   * Test credential rotation
   */
  async testCredentialRotation(
    agentId: string,
    scopes: string[]
  ): Promise<TestResult> {
    if (!this.config.oauthConfig) {
      return {
        testType: 'agent-direct-access',
        testName: 'Credential Rotation Test',
        passed: false,
        timestamp: new Date(),
        error: 'OAuth configuration not provided',
        details: {},
      };
    }

    // Test with rotation enabled
    const testWithRotation: ClientCredentialsFlowTest = {
      config: {
        ...this.config.oauthConfig,
        scopes,
      },
      expectedScopes: scopes,
      credentialRotation: {
        enabled: true,
        rotationInterval: 90 * 24 * 60 * 60,
      },
    };

    const resultWithRotation = await this.oauthTester.testClientCredentialsFlow(
      testWithRotation
    );

    // Test with rotation disabled (should fail)
    const testWithoutRotation: ClientCredentialsFlowTest = {
      config: {
        ...this.config.oauthConfig,
        scopes,
      },
      expectedScopes: scopes,
      credentialRotation: {
        enabled: false,
      },
    };

    const resultWithoutRotation =
      await this.oauthTester.testClientCredentialsFlow(testWithoutRotation);

    return {
      testType: 'agent-direct-access',
      testName: 'Credential Rotation Test',
      passed:
        resultWithRotation.credentialSecurity === true &&
        resultWithoutRotation.credentialSecurity === false,
      timestamp: new Date(),
      details: {
        rotationEnabled: resultWithRotation.credentialSecurity,
        rotationDisabled: resultWithoutRotation.credentialSecurity,
        recommendation:
          resultWithoutRotation.credentialSecurity === false
            ? 'Credential rotation should be enabled for production agents'
            : 'Credential rotation is properly configured',
      },
    };
  }

  /**
   * Run all direct access tests
   */
  async runAllTests(
    agentId: string,
    testResources: Resource[],
    testActions: string[],
    scopes: string[]
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Test 1: Autonomous operation
    for (const resource of testResources.slice(0, 2)) {
      for (const action of testActions.slice(0, 2)) {
        const result = await this.testAutonomousOperation(
          agentId,
          'autonomous',
          resource,
          action,
          true
        );
        results.push(result);
      }
    }

    // Test 2: Service-to-service authentication
    if (this.config.oauthConfig) {
      const authResult = await this.testServiceToServiceAuth(agentId, scopes);
      results.push(authResult);
    }

    // Test 3: Event-triggered action
    const eventResult = await this.testEventTriggeredAction(
      agentId,
      'security-incident',
      testResources[0],
      testActions[0]
    );
    results.push(eventResult);

    // Test 4: Independent operation
    const independentResults = await this.testIndependentOperation(
      agentId,
      testResources,
      testActions
    );
    results.push(...independentResults);

    // Test 5: Credential rotation
    if (this.config.oauthConfig) {
      const rotationResult = await this.testCredentialRotation(agentId, scopes);
      results.push(rotationResult);
    }

    return results;
  }
}
