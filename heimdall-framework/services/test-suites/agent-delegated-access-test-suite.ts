/**
 * Agent Delegated Access Test Suite
 * 
 * Tests for agents acting on behalf of users:
 * - User-initiated agent requests
 * - Permission delegation validation
 * - Cross-service access on behalf of user
 * - User permission boundary enforcement
 */

import { AgentAccessControlTester, DelegatedAccessTest } from '../agent-access-control-tester';
import { AgentOAuthTester, AuthCodeFlowTest, OBOTokenFlowTest } from '../agent-oauth-tester';
import { AccessControlConfig, Resource, Context } from '../../core/types';
import { TestResult } from '../../core/types';

export interface AgentDelegatedAccessTestSuiteConfig {
  accessControlConfig: AccessControlConfig;
  oauthConfig?: {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
    redirectUri: string;
  };
}

export class AgentDelegatedAccessTestSuite {
  private accessControlTester: AgentAccessControlTester;
  private oauthTester: AgentOAuthTester;
  private config: AgentDelegatedAccessTestSuiteConfig;

  constructor(config: AgentDelegatedAccessTestSuiteConfig) {
    this.config = config;
    this.accessControlTester = new AgentAccessControlTester(
      config.accessControlConfig
    );
    this.oauthTester = new AgentOAuthTester();
  }

  /**
   * Test user-initiated agent request
   */
  async testUserInitiatedRequest(
    agentId: string,
    userContext: {
      userId: string;
      email: string;
      role: string;
      permissions: string[];
    },
    resource: Resource,
    action: string
  ): Promise<TestResult> {
    const test: DelegatedAccessTest = {
      agentId,
      userContext,
      resource,
      action,
      expectedAllowed: true,
    };

    const result = await this.accessControlTester.testDelegatedAccess(test);

    return {
      testType: 'agent-delegated-access',
      testName: `User-Initiated Request Test - ${agentId}`,
      passed: result.passed,
      timestamp: new Date(),
      details: {
        agentId,
        userId: userContext.userId,
        resource: resource.id,
        action,
        allowed: result.allowed,
        permissionBoundariesRespected: result.permissionBoundariesRespected,
        userPermissionsEnforced: result.userPermissionsEnforced,
      },
    };
  }

  /**
   * Test permission delegation validation
   */
  async testPermissionDelegation(
    agentId: string,
    userContext: {
      userId: string;
      email: string;
      role: string;
      permissions: string[];
    },
    resources: Resource[],
    actions: string[]
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    for (const resource of resources) {
      for (const action of actions) {
        const requiredPermission = `${action}:${resource.type}`;
        const hasPermission = userContext.permissions.includes(requiredPermission);

        const test: DelegatedAccessTest = {
          agentId,
          userContext,
          resource,
          action,
          expectedAllowed: hasPermission,
        };

        const result = await this.accessControlTester.testDelegatedAccess(test);
        results.push({
          testType: 'agent-delegated-access',
          testName: `Permission Delegation Test - ${action} ${resource.type}`,
          passed: result.passed,
          timestamp: new Date(),
          details: {
            agentId,
            userId: userContext.userId,
            resource: resource.id,
            action,
            requiredPermission,
            hasPermission,
            allowed: result.allowed,
            expectedAllowed: hasPermission,
          },
        });
      }
    }

    return results;
  }

  /**
   * Test cross-service access on behalf of user
   */
  async testCrossServiceAccess(
    agentId: string,
    userContext: {
      userId: string;
      email: string;
      role: string;
      permissions: string[];
    },
    services: Array<{
      serviceId: string;
      resource: Resource;
      action: string;
    }>
  ): Promise<TestResult> {
    // Test OBO token flow if OAuth config provided
    if (this.config.oauthConfig) {
      // First, get user access token (simulated)
      const userAccessToken = `user_token_${userContext.userId}`;

      // Test OBO flow for each service
      const oboTests: OBOTokenFlowTest[] = services.map(service => ({
        config: {
          tokenEndpoint: this.config.oauthConfig!.tokenEndpoint,
          clientId: this.config.oauthConfig!.clientId,
          scopes: [`${service.action}:${service.resource.type}`],
        },
        userAccessToken,
        targetService: service.serviceId,
        expectedScopes: [`${service.action}:${service.resource.type}`],
      }));

      const oauthResults = await Promise.all(
        oboTests.map(test => this.oauthTester.testOBOTokenFlow(test))
      );

      // Test multi-service access
      const multiServiceResult = await this.accessControlTester.testMultiServiceAccess({
        agentId,
        agentType: 'delegated',
        userContext: {
          userId: userContext.userId,
          permissions: userContext.permissions,
        },
        services: services.map(service => ({
          serviceId: service.serviceId,
          resource: service.resource,
          action: service.action,
          expectedAllowed: userContext.permissions.includes(
            `${service.action}:${service.resource.type}`
          ),
        })),
      });

      return {
        testType: 'agent-delegated-access',
        testName: `Cross-Service Access Test - ${agentId}`,
        passed:
          multiServiceResult.passed &&
          oauthResults.every(r => r.passed),
        timestamp: new Date(),
        details: {
          agentId,
          userId: userContext.userId,
          services: services.map(s => s.serviceId),
          oauthResults: oauthResults.map(r => ({
            tokenIssued: r.tokenIssued,
            scopesRespected: r.scopeMismatch?.length === 0,
          })),
          multiServiceConsistency: multiServiceResult.multiServiceConsistency,
        },
      };
    } else {
      // Test without OAuth (direct access control)
      const multiServiceResult = await this.accessControlTester.testMultiServiceAccess({
        agentId,
        agentType: 'delegated',
        userContext: {
          userId: userContext.userId,
          permissions: userContext.permissions,
        },
        services: services.map(service => ({
          serviceId: service.serviceId,
          resource: service.resource,
          action: service.action,
          expectedAllowed: userContext.permissions.includes(
            `${service.action}:${service.resource.type}`
          ),
        })),
      });

      return {
        testType: 'agent-delegated-access',
        testName: `Cross-Service Access Test - ${agentId}`,
        passed: multiServiceResult.passed,
        timestamp: new Date(),
        details: {
          agentId,
          userId: userContext.userId,
          services: services.map(s => s.serviceId),
          multiServiceConsistency: multiServiceResult.multiServiceConsistency,
        },
      };
    }
  }

  /**
   * Test user permission boundary enforcement
   */
  async testPermissionBoundaries(
    agentId: string,
    userContext: {
      userId: string;
      email: string;
      role: string;
      permissions: string[];
    },
    resources: Resource[],
    actions: string[]
  ): Promise<TestResult> {
    const boundaryTest = await this.accessControlTester.testPermissionBoundaries(
      agentId,
      userContext.permissions,
      resources,
      actions
    );

    return {
      testType: 'agent-delegated-access',
      testName: `Permission Boundary Enforcement Test - ${agentId}`,
      passed: boundaryTest.boundariesRespected,
      timestamp: new Date(),
      details: {
        agentId,
        userId: userContext.userId,
        boundariesRespected: boundaryTest.boundariesRespected,
        violations: boundaryTest.violations,
        totalResources: resources.length,
        totalActions: actions.length,
      },
    };
  }

  /**
   * Test Auth Code Flow for delegated access
   */
  async testAuthCodeFlow(
    userContext: {
      userId: string;
      email: string;
      permissions: string[];
    },
    scopes: string[]
  ): Promise<TestResult> {
    if (!this.config.oauthConfig) {
      return {
        testType: 'agent-delegated-access',
        testName: 'Auth Code Flow Test',
        passed: false,
        timestamp: new Date(),
        error: 'OAuth configuration not provided',
        details: {},
      };
    }

    const test: AuthCodeFlowTest = {
      config: {
        authorizationEndpoint: this.config.oauthConfig.authorizationEndpoint,
        tokenEndpoint: this.config.oauthConfig.tokenEndpoint,
        clientId: this.config.oauthConfig.clientId,
        redirectUri: this.config.oauthConfig.redirectUri,
        scopes,
      },
      userContext,
      expectedScopes: scopes,
    };

    const result = await this.oauthTester.testAuthCodeFlow(test);

    return {
      testType: 'agent-delegated-access',
      testName: 'Auth Code Flow Test',
      passed: result.passed,
      timestamp: new Date(),
      details: {
        tokenIssued: result.tokenIssued,
        tokenValid: result.tokenValid,
        scopesGranted: result.scopesGranted,
        scopesExpected: result.scopesExpected,
        scopeMismatch: result.scopeMismatch,
        userPermissionsEnforced: result.userPermissionsEnforced,
        permissionBoundariesRespected: result.permissionBoundariesRespected,
      },
    };
  }

  /**
   * Run all delegated access tests
   */
  async runAllTests(
    agentId: string,
    userContext: {
      userId: string;
      email: string;
      role: string;
      permissions: string[];
    },
    testResources: Resource[],
    testActions: string[]
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Test 1: User-initiated request
    for (const resource of testResources.slice(0, 1)) {
      for (const action of testActions.slice(0, 1)) {
        const result = await this.testUserInitiatedRequest(
          agentId,
          userContext,
          resource,
          action
        );
        results.push(result);
      }
    }

    // Test 2: Permission delegation
    const delegationResults = await this.testPermissionDelegation(
      agentId,
      userContext,
      testResources,
      testActions
    );
    results.push(...delegationResults);

    // Test 3: Permission boundaries
    const boundaryResult = await this.testPermissionBoundaries(
      agentId,
      userContext,
      testResources,
      testActions
    );
    results.push(boundaryResult);

    // Test 4: Auth Code Flow (if OAuth config provided)
    if (this.config.oauthConfig) {
      const scopes = testActions.flatMap(action =>
        testResources.map(resource => `${action}:${resource.type}`)
      );
      const authCodeResult = await this.testAuthCodeFlow(userContext, scopes);
      results.push(authCodeResult);
    }

    return results;
  }
}
