/**
 * Agent Access Control Tester Service
 * 
 * Tests agent access control scenarios:
 * - Delegated access (agent acting on user's behalf)
 * - Direct access (autonomous agent)
 * - Dynamic access (context-dependent permissions)
 * - Multi-service access (access across multiple services)
 */

import { PolicyDecisionPoint, PDPRequest, PDPDecision } from './policy-decision-point';
import { AccessControlConfig, User, Resource, Context, TestResult } from '../core/types';
import { AgentOAuthTester, OAuthFlowConfig } from './agent-oauth-tester';

export interface DelegatedAccessTest {
  agentId: string;
  userContext: {
    userId: string;
    email: string;
    role: string;
    permissions: string[];
    attributes?: Record<string, any>;
  };
  resource: Resource;
  action: string;
  context?: Context;
  expectedAllowed: boolean;
}

export interface DirectAccessTest {
  agentId: string;
  agentType: 'autonomous' | 'event-driven' | 'scheduled';
  resource: Resource;
  action: string;
  context?: Context;
  expectedAllowed: boolean;
  oauthConfig?: OAuthFlowConfig;
}

export interface DynamicAccessTest {
  agentId: string;
  agentType: 'delegated' | 'direct';
  userContext?: {
    userId: string;
    permissions: string[];
  };
  scenarios: Array<{
    name: string;
    context: Context;
    requestedPermission: string;
    expectedGranted: boolean;
    jitAccess?: boolean;
  }>;
}

export interface MultiServiceAccessTest {
  agentId: string;
  agentType: 'delegated' | 'direct';
  userContext?: {
    userId: string;
    permissions: string[];
  };
  services: Array<{
    serviceId: string;
    resource: Resource;
    action: string;
    expectedAllowed: boolean;
  }>;
}

export interface AgentAccessControlTestResult extends TestResult {
  testName: string;
  testType: 'delegated' | 'direct' | 'dynamic' | 'multi-service';
  agentId: string;
  allowed: boolean;
  expectedAllowed: boolean;
  decisionReason: string;
  permissionBoundariesRespected?: boolean;
  userPermissionsEnforced?: boolean;
  contextAwareDecision?: boolean;
  multiServiceConsistency?: boolean;
  details?: Record<string, any>;
}

export class AgentAccessControlTester {
  private pdp: PolicyDecisionPoint;
  private oauthTester: AgentOAuthTester;
  private config: AccessControlConfig;

  constructor(config: AccessControlConfig) {
    this.config = config;
    this.pdp = new PolicyDecisionPoint(config);
    this.oauthTester = new AgentOAuthTester();
  }

  /**
   * Test delegated access scenario
   */
  async testDelegatedAccess(
    test: DelegatedAccessTest
  ): Promise<AgentAccessControlTestResult> {
    const result: AgentAccessControlTestResult = {
      testType: 'agent-delegated-access',
      testName: `Delegated Access Test - ${test.agentId}`,
      passed: false,
      timestamp: new Date(),
      testType: 'delegated',
      agentId: test.agentId,
      allowed: false,
      expectedAllowed: test.expectedAllowed,
      decisionReason: '',
      details: {},
    };

    try {
      // Build PDP request with agent context
      const request: PDPRequest = {
        subject: {
          id: test.agentId,
          attributes: {
            agentType: 'delegated',
            userId: test.userContext.userId,
            userEmail: test.userContext.email,
            userRole: test.userContext.role,
            userPermissions: test.userContext.permissions,
            ...test.userContext.attributes,
          },
        },
        resource: test.resource,
        action: test.action,
        context: {
          ...test.context,
          agentType: 'delegated',
          userContext: {
            userId: test.userContext.userId,
            permissions: test.userContext.permissions,
          },
        },
      };

      // Evaluate access decision
      const decision = await this.pdp.evaluate(request);
      result.allowed = decision.allowed;
      result.decisionReason = decision.reason;

      // Validate permission boundaries
      result.permissionBoundariesRespected = this.validatePermissionBoundaries(
        decision.allowed,
        test.userContext.permissions,
        test.resource,
        test.action
      );

      // Validate user permissions are enforced
      result.userPermissionsEnforced = this.validateUserPermissionsEnforced(
        decision.allowed,
        test.userContext.permissions,
        test.resource,
        test.action
      );

      result.passed =
        result.allowed === test.expectedAllowed &&
        result.permissionBoundariesRespected &&
        result.userPermissionsEnforced;

      result.details = {
        appliedRules: decision.appliedRules,
        conditions: decision.conditions,
        userPermissions: test.userContext.permissions,
        resourceSensitivity: test.resource.sensitivity,
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
      };
    }

    return result;
  }

  /**
   * Test direct access scenario
   */
  async testDirectAccess(
    test: DirectAccessTest
  ): Promise<AgentAccessControlTestResult> {
    const result: AgentAccessControlTestResult = {
      testType: 'agent-direct-access',
      testName: `Direct Access Test - ${test.agentId}`,
      passed: false,
      timestamp: new Date(),
      testType: 'direct',
      agentId: test.agentId,
      allowed: false,
      expectedAllowed: test.expectedAllowed,
      decisionReason: '',
      details: {},
    };

    try {
      // Build PDP request for autonomous agent
      const request: PDPRequest = {
        subject: {
          id: test.agentId,
          attributes: {
            agentType: 'direct',
            agentTypeDetail: test.agentType,
          },
        },
        resource: test.resource,
        action: test.action,
        context: {
          ...test.context,
          agentType: 'direct',
        },
      };

      // Evaluate access decision
      const decision = await this.pdp.evaluate(request);
      result.allowed = decision.allowed;
      result.decisionReason = decision.reason;

      // If OAuth config provided, test client credentials flow
      if (test.oauthConfig) {
        const oauthResult = await this.oauthTester.testClientCredentialsFlow({
          config: test.oauthConfig,
          expectedScopes: test.oauthConfig.scopes,
        });

        result.details = {
          ...result.details,
          oauthTest: {
            tokenIssued: oauthResult.tokenIssued,
            scopesRespected: oauthResult.scopeMismatch?.length === 0,
          },
        };
      }

      result.passed = result.allowed === test.expectedAllowed;

      result.details = {
        ...result.details,
        appliedRules: decision.appliedRules,
        conditions: decision.conditions,
        agentType: test.agentType,
        resourceSensitivity: test.resource.sensitivity,
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
      };
    }

    return result;
  }

  /**
   * Test dynamic access scenarios
   */
  async testDynamicAccess(
    test: DynamicAccessTest
  ): Promise<AgentAccessControlTestResult[]> {
    const results: AgentAccessControlTestResult[] = [];

    for (const scenario of test.scenarios) {
      const result: AgentAccessControlTestResult = {
        testType: 'agent-dynamic-access',
        testName: `Dynamic Access Test - ${scenario.name}`,
        passed: false,
        timestamp: new Date(),
        testType: 'dynamic',
        agentId: test.agentId,
        allowed: false,
        expectedAllowed: scenario.expectedGranted,
        decisionReason: '',
        details: {},
      };

      try {
        // Build subject attributes based on agent type
        const subjectAttributes: Record<string, any> = {
          agentType: test.agentType,
        };

        if (test.agentType === 'delegated' && test.userContext) {
          subjectAttributes.userId = test.userContext.userId;
          subjectAttributes.userPermissions = test.userContext.permissions;
        }

        // Build PDP request with dynamic context
        const request: PDPRequest = {
          subject: {
            id: test.agentId,
            attributes: subjectAttributes,
          },
          resource: {
            id: 'dynamic-resource',
            type: 'resource',
            attributes: {
              requiredPermission: scenario.requestedPermission,
            },
          },
          action: scenario.requestedPermission,
          context: {
            ...scenario.context,
            agentType: test.agentType,
            userContext: test.userContext,
            jitAccess: scenario.jitAccess,
          },
        };

        // Evaluate access decision
        const decision = await this.pdp.evaluate(request);
        result.allowed = decision.allowed;
        result.decisionReason = decision.reason;
        result.contextAwareDecision = true;

        // Validate JIT access if applicable
        if (scenario.jitAccess) {
          result.details = {
            ...result.details,
            jitAccessGranted: decision.allowed,
            jitAccessExpected: scenario.expectedGranted,
          };
        }

        result.passed = result.allowed === scenario.expectedGranted;

        result.details = {
          ...result.details,
          appliedRules: decision.appliedRules,
          conditions: decision.conditions,
          context: scenario.context,
        };
      } catch (error: any) {
        result.error = error.message;
        result.details = {
          ...result.details,
          error: error.message,
        };
      }

      results.push(result);
    }

    return results;
  }

  /**
   * Test multi-service access
   */
  async testMultiServiceAccess(
    test: MultiServiceAccessTest
  ): Promise<AgentAccessControlTestResult> {
    const result: AgentAccessControlTestResult = {
      testType: 'agent-multi-service',
      testName: `Multi-Service Access Test - ${test.agentId}`,
      passed: false,
      timestamp: new Date(),
      testType: 'multi-service',
      agentId: test.agentId,
      allowed: false,
      expectedAllowed: true,
      decisionReason: '',
      details: {},
    };

    try {
      const serviceResults: Array<{
        serviceId: string;
        allowed: boolean;
        expectedAllowed: boolean;
        reason: string;
      }> = [];

      // Build subject attributes
      const subjectAttributes: Record<string, any> = {
        agentType: test.agentType,
      };

      if (test.agentType === 'delegated' && test.userContext) {
        subjectAttributes.userId = test.userContext.userId;
        subjectAttributes.userPermissions = test.userContext.permissions;
      }

      // Test access to each service
      for (const service of test.services) {
        const request: PDPRequest = {
          subject: {
            id: test.agentId,
            attributes: subjectAttributes,
          },
          resource: service.resource,
          action: service.action,
          context: {
            agentType: test.agentType,
            userContext: test.userContext,
            serviceAccess: test.services.map(s => s.serviceId),
          },
        };

        const decision = await this.pdp.evaluate(request);
        serviceResults.push({
          serviceId: service.serviceId,
          allowed: decision.allowed,
          expectedAllowed: service.expectedAllowed,
          reason: decision.reason,
        });
      }

      // Check consistency across services
      const allAllowed = serviceResults.every(
        r => r.allowed === r.expectedAllowed
      );
      const consistencyCheck = this.checkPermissionConsistency(serviceResults);

      result.allowed = allAllowed;
      result.multiServiceConsistency = consistencyCheck.consistent;
      result.passed = allAllowed && consistencyCheck.consistent;

      result.details = {
        serviceResults,
        consistencyIssues: consistencyCheck.issues,
        totalServices: test.services.length,
        servicesAllowed: serviceResults.filter(r => r.allowed).length,
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
      };
    }

    return result;
  }

  /**
   * Test permission boundaries
   */
  async testPermissionBoundaries(
    agentId: string,
    userPermissions: string[],
    resources: Resource[],
    actions: string[]
  ): Promise<{
    boundariesRespected: boolean;
    violations: string[];
  }> {
    const violations: string[] = [];

    for (const resource of resources) {
      for (const action of actions) {
        // Check if action requires permission
        const requiredPermission = `${action}:${resource.type}`;

        if (!userPermissions.includes(requiredPermission)) {
          // Try to access - should be denied
          const request: PDPRequest = {
            subject: {
              id: agentId,
              attributes: {
                agentType: 'delegated',
                userPermissions,
              },
            },
            resource,
            action,
            context: {
              agentType: 'delegated',
            },
          };

          const decision = await this.pdp.evaluate(request);

          if (decision.allowed) {
            violations.push(
              `Agent allowed to ${action} ${resource.type} without permission ${requiredPermission}`
            );
          }
        }
      }
    }

    return {
      boundariesRespected: violations.length === 0,
      violations,
    };
  }

  // Private helper methods

  private validatePermissionBoundaries(
    allowed: boolean,
    userPermissions: string[],
    resource: Resource,
    action: string
  ): boolean {
    // Check if the action requires a permission that the user has
    const requiredPermission = `${action}:${resource.type}`;
    const hasPermission = userPermissions.some(
      p => p === requiredPermission || p === `${action}:*` || p === '*:*'
    );

    // If access is allowed, user must have permission
    if (allowed && !hasPermission) {
      return false;
    }

    return true;
  }

  private validateUserPermissionsEnforced(
    allowed: boolean,
    userPermissions: string[],
    resource: Resource,
    action: string
  ): boolean {
    // Ensure that if user doesn't have permission, access is denied
    const requiredPermission = `${action}:${resource.type}`;
    const hasPermission = userPermissions.some(
      p => p === requiredPermission || p === `${action}:*` || p === '*:*'
    );

    // If user has permission, access should be allowed (or denied based on other factors)
    // If user doesn't have permission, access must be denied
    if (!hasPermission && allowed) {
      return false;
    }

    return true;
  }

  private checkPermissionConsistency(
    serviceResults: Array<{
      serviceId: string;
      allowed: boolean;
      expectedAllowed: boolean;
      reason: string;
    }>
  ): {
    consistent: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    // Check for inconsistent decisions across similar services
    const allowedServices = serviceResults.filter(r => r.allowed);
    const deniedServices = serviceResults.filter(r => !r.allowed);

    // If some services are allowed and others denied for similar resources,
    // check if there's a consistent pattern
    if (allowedServices.length > 0 && deniedServices.length > 0) {
      // This might be expected (different permissions for different services)
      // But we should flag it for review
      issues.push(
        `Mixed access decisions: ${allowedServices.length} services allowed, ${deniedServices.length} denied`
      );
    }

    // Check if all decisions match expectations
    const mismatches = serviceResults.filter(
      r => r.allowed !== r.expectedAllowed
    );
    if (mismatches.length > 0) {
      issues.push(
        `${mismatches.length} services had unexpected access decisions`
      );
    }

    return {
      consistent: issues.length === 0,
      issues,
    };
  }
}
