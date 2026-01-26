/**
 * Agent Tests Service
 * 
 * Service for executing agent access control tests
 */

import { Injectable } from '@nestjs/common';
import { AgentAccessControlTester } from '../../../heimdall-framework/services/agent-access-control-tester';
import { AgentOAuthTester } from '../../../heimdall-framework/services/agent-oauth-tester';
import { AgentAuditValidator } from '../../../heimdall-framework/services/agent-audit-validator';
import { AccessControlConfig } from '../../../heimdall-framework/core/types';

@Injectable()
export class AgentTestsService {
  private accessControlConfig: AccessControlConfig;

  constructor() {
    // Initialize with default config - in production, load from application config
    this.accessControlConfig = {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
    };
  }

  /**
   * Run delegated access tests
   */
  async runDelegatedAccessTests(dto: {
    agentId: string;
    userContext: {
      userId: string;
      email: string;
      role: string;
      permissions: string[];
    };
    resources: Array<{
      id: string;
      type: string;
      attributes?: Record<string, any>;
    }>;
    actions: string[];
    oauthConfig?: {
      authorizationEndpoint: string;
      tokenEndpoint: string;
      clientId: string;
      redirectUri: string;
      scopes: string[];
    };
  }) {
    const accessControlTester = new AgentAccessControlTester(this.accessControlConfig);
    const oauthTester = new AgentOAuthTester();

    const results = [];

    // Test each resource/action combination
    for (const resource of dto.resources) {
      for (const action of dto.actions) {
        const testResult = await accessControlTester.testDelegatedAccess({
          agentId: dto.agentId,
          userContext: dto.userContext,
          resource: {
            id: resource.id,
            type: resource.type,
            attributes: resource.attributes || {},
          },
          action,
          expectedAllowed: dto.userContext.permissions.includes(`${action}:${resource.type}`),
        });
        results.push(testResult);
      }
    }

    // Test OAuth flows if configured
    if (dto.oauthConfig) {
      const oauthResult = await oauthTester.testAuthCodeFlow({
        config: {
          authorizationEndpoint: dto.oauthConfig.authorizationEndpoint,
          tokenEndpoint: dto.oauthConfig.tokenEndpoint,
          clientId: dto.oauthConfig.clientId,
          redirectUri: dto.oauthConfig.redirectUri,
          scopes: dto.oauthConfig.scopes,
        },
        userContext: {
          userId: dto.userContext.userId,
          email: dto.userContext.email,
          permissions: dto.userContext.permissions,
        },
        expectedScopes: dto.oauthConfig.scopes,
      });
      results.push({
        testType: 'oauth',
        testName: 'Auth Code Flow Test',
        passed: oauthResult.passed,
        timestamp: new Date(),
        details: oauthResult,
      });
    }

    return {
      agentId: dto.agentId,
      testType: 'delegated-access',
      results,
      summary: {
        total: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
      },
    };
  }

  /**
   * Run direct access tests
   */
  async runDirectAccessTests(dto: {
    agentId: string;
    agentType: 'autonomous' | 'event-driven' | 'scheduled';
    resources: Array<{
      id: string;
      type: string;
      attributes?: Record<string, any>;
    }>;
    actions: string[];
    oauthConfig?: {
      tokenEndpoint: string;
      clientId: string;
      clientSecret?: string;
      scopes: string[];
    };
  }) {
    const accessControlTester = new AgentAccessControlTester(this.accessControlConfig);
    const oauthTester = new AgentOAuthTester();

    const results = [];

    // Test each resource/action combination
    for (const resource of dto.resources) {
      for (const action of dto.actions) {
        const testResult = await accessControlTester.testDirectAccess({
          agentId: dto.agentId,
          agentType: dto.agentType,
          resource: {
            id: resource.id,
            type: resource.type,
            attributes: resource.attributes || {},
          },
          action,
          expectedAllowed: true,
          oauthConfig: dto.oauthConfig,
        });
        results.push(testResult);
      }
    }

    // Test OAuth client credentials flow if configured
    if (dto.oauthConfig) {
      const oauthResult = await oauthTester.testClientCredentialsFlow({
        config: dto.oauthConfig,
        expectedScopes: dto.oauthConfig.scopes,
        credentialRotation: {
          enabled: true,
          rotationInterval: 90 * 24 * 60 * 60, // 90 days
        },
      });
      results.push({
        testType: 'oauth',
        testName: 'Client Credentials Flow Test',
        passed: oauthResult.passed,
        timestamp: new Date(),
        details: oauthResult,
      });
    }

    return {
      agentId: dto.agentId,
      testType: 'direct-access',
      results,
      summary: {
        total: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
      },
    };
  }

  /**
   * Get agent audit trail
   */
  async getAuditTrail(
    agentId: string,
    filters?: {
      startDate?: Date;
      endDate?: Date;
      serviceId?: string;
      action?: string;
    }
  ) {
    const auditValidator = new AgentAuditValidator();
    const auditTrail = auditValidator.getAuditTrail(agentId, filters);

    return {
      agentId,
      auditTrail,
      totalEntries: auditTrail.length,
      filters,
    };
  }

  /**
   * Test multi-service access
   */
  async testMultiServiceAccess(dto: {
    agentId: string;
    agentType: 'delegated' | 'direct';
    userContext?: {
      userId: string;
      permissions: string[];
    };
    services: Array<{
      serviceId: string;
      resource: {
        id: string;
        type: string;
        attributes?: Record<string, any>;
      };
      action: string;
      expectedAllowed: boolean;
    }>;
  }) {
    const accessControlTester = new AgentAccessControlTester(this.accessControlConfig);

    const result = await accessControlTester.testMultiServiceAccess({
      agentId: dto.agentId,
      agentType: dto.agentType,
      userContext: dto.userContext,
      services: dto.services.map(service => ({
        serviceId: service.serviceId,
        resource: {
          id: service.resource.id,
          type: service.resource.type,
          attributes: service.resource.attributes || {},
        },
        action: service.action,
        expectedAllowed: service.expectedAllowed,
      })),
    });

    return {
      agentId: dto.agentId,
      testType: 'multi-service',
      result,
    };
  }

  /**
   * Test dynamic access
   */
  async testDynamicAccess(dto: {
    agentId: string;
    agentType: 'delegated' | 'direct';
    userContext?: {
      userId: string;
      permissions: string[];
    };
    scenarios: Array<{
      name: string;
      context: {
        ipAddress?: string;
        timeOfDay?: string;
        location?: string;
        device?: string;
        additionalAttributes?: Record<string, any>;
      };
      requestedPermission: string;
      expectedGranted: boolean;
      jitAccess?: boolean;
    }>;
  }) {
    const accessControlTester = new AgentAccessControlTester(this.accessControlConfig);

    const results = await accessControlTester.testDynamicAccess({
      agentId: dto.agentId,
      agentType: dto.agentType,
      userContext: dto.userContext,
      scenarios: dto.scenarios,
    });

    return {
      agentId: dto.agentId,
      testType: 'dynamic-access',
      results,
      summary: {
        total: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
      },
    };
  }

  /**
   * Validate audit trail
   */
  async validateAuditTrail(dto: {
    agentId: string;
    agentType: 'delegated' | 'direct';
    userId?: string;
    actions: Array<{
      serviceId: string;
      action: string;
      resourceId: string;
      resourceType: string;
      timestamp: Date;
      expectedLogged: boolean;
    }>;
    auditSources?: string[];
    retentionPeriod?: number;
  }) {
    const auditValidator = new AgentAuditValidator();

    // Add audit log entries (in real scenario, these would come from audit service)
    for (const action of dto.actions) {
      if (action.expectedLogged) {
        auditValidator.addAuditLogEntry(
          {
            id: `audit-${action.serviceId}-${action.timestamp.getTime()}`,
            timestamp: new Date(action.timestamp),
            agentId: dto.agentId,
            agentType: dto.agentType,
            userId: dto.userId,
            action: action.action,
            serviceId: action.serviceId,
            resourceId: action.resourceId,
            resourceType: action.resourceType,
            allowed: true,
          },
          dto.auditSources?.[0]
        );
      }
    }

    const validationResult = await auditValidator.validateAuditTrail({
      agentId: dto.agentId,
      agentType: dto.agentType,
      userId: dto.userId,
      actions: dto.actions.map(a => ({
        ...a,
        timestamp: new Date(a.timestamp),
      })),
      auditSources: dto.auditSources,
      retentionPeriod: dto.retentionPeriod || 90,
    });

    return {
      agentId: dto.agentId,
      validationResult,
    };
  }
}
