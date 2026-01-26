/**
 * Agent Access Control Tester Unit Tests
 */

import { AgentAccessControlTester, DelegatedAccessTest, DirectAccessTest, DynamicAccessTest, MultiServiceAccessTest } from './agent-access-control-tester';
import { AccessControlConfig } from '../core/types';
import { PolicyDecisionPoint } from './policy-decision-point';

// Mock PolicyDecisionPoint
jest.mock('./policy-decision-point');

describe('AgentAccessControlTester', () => {
  let tester: AgentAccessControlTester;
  let mockPDP: jest.Mocked<PolicyDecisionPoint>;
  let config: AccessControlConfig;

  beforeEach(() => {
    config = {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
    };

    mockPDP = {
      evaluate: jest.fn(),
    } as any;

    // Mock PolicyDecisionPoint constructor
    (PolicyDecisionPoint as any).mockImplementation(() => mockPDP);

    tester = new AgentAccessControlTester(config);
  });

  describe('testDelegatedAccess', () => {
    it('should successfully test delegated access', async () => {
      const test: DelegatedAccessTest = {
        agentId: 'agent-001',
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          role: 'researcher',
          permissions: ['read:emails'],
        },
        resource: {
          id: 'inbox-123',
          type: 'emails',
          attributes: { sensitivity: 'internal' },
        },
        action: 'read',
        expectedAllowed: true,
      };

      mockPDP.evaluate.mockResolvedValueOnce({
        allowed: true,
        reason: 'User has read:emails permission',
        appliedRules: ['delegated-access-policy'],
      });

      const result = await tester.testDelegatedAccess(test);

      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
      expect(result.permissionBoundariesRespected).toBe(true);
      expect(result.userPermissionsEnforced).toBe(true);
      expect(mockPDP.evaluate).toHaveBeenCalledWith(
        expect.objectContaining({
          subject: expect.objectContaining({
            id: 'agent-001',
            attributes: expect.objectContaining({
              agentType: 'delegated',
              userId: 'user-123',
            }),
          }),
        })
      );
    });

    it('should detect permission boundary violations', async () => {
      const test: DelegatedAccessTest = {
        agentId: 'agent-001',
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          role: 'researcher',
          permissions: ['read:emails'], // User doesn't have delete permission
        },
        resource: {
          id: 'inbox-123',
          type: 'emails',
          attributes: { sensitivity: 'internal' },
        },
        action: 'delete',
        expectedAllowed: false,
      };

      mockPDP.evaluate.mockResolvedValueOnce({
        allowed: true, // PDP incorrectly allows
        reason: 'Access granted',
        appliedRules: ['some-policy'],
      });

      const result = await tester.testDelegatedAccess(test);

      expect(result.passed).toBe(false);
      expect(result.permissionBoundariesRespected).toBe(false);
      expect(result.userPermissionsEnforced).toBe(false);
    });
  });

  describe('testDirectAccess', () => {
    it('should successfully test direct access', async () => {
      const test: DirectAccessTest = {
        agentId: 'agent-002',
        agentType: 'autonomous',
        resource: {
          id: 'logs-123',
          type: 'logs',
          attributes: { source: 'security' },
        },
        action: 'read',
        expectedAllowed: true,
      };

      mockPDP.evaluate.mockResolvedValueOnce({
        allowed: true,
        reason: 'Autonomous agent has read:logs permission',
        appliedRules: ['direct-access-policy'],
      });

      const result = await tester.testDirectAccess(test);

      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
      expect(mockPDP.evaluate).toHaveBeenCalledWith(
        expect.objectContaining({
          subject: expect.objectContaining({
            id: 'agent-002',
            attributes: expect.objectContaining({
              agentType: 'direct',
            }),
          }),
        })
      );
    });

    it('should test OAuth client credentials flow when configured', async () => {
      const test: DirectAccessTest = {
        agentId: 'agent-002',
        agentType: 'autonomous',
        resource: {
          id: 'logs-123',
          type: 'logs',
          attributes: {},
        },
        action: 'read',
        expectedAllowed: true,
        oauthConfig: {
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          clientSecret: 'test-secret',
          scopes: ['read:logs'],
        },
      };

      mockPDP.evaluate.mockResolvedValueOnce({
        allowed: true,
        reason: 'Access granted',
        appliedRules: [],
      });

      // Mock fetch for OAuth
      global.fetch = jest.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'token',
          scope: 'read:logs',
        }),
      });

      const result = await tester.testDirectAccess(test);

      expect(result.passed).toBe(true);
      expect(result.details?.oauthTest).toBeDefined();
    });
  });

  describe('testDynamicAccess', () => {
    it('should test multiple dynamic access scenarios', async () => {
      const test: DynamicAccessTest = {
        agentId: 'agent-003',
        agentType: 'delegated',
        userContext: {
          userId: 'user-123',
          permissions: ['read:documents'],
        },
        scenarios: [
          {
            name: 'Office access',
            context: { location: 'office', timeOfDay: '14:30' },
            requestedPermission: 'read:documents',
            expectedGranted: true,
          },
          {
            name: 'Home access',
            context: { location: 'home', timeOfDay: '20:00' },
            requestedPermission: 'read:documents',
            expectedGranted: false,
          },
        ],
      };

      mockPDP.evaluate
        .mockResolvedValueOnce({
          allowed: true,
          reason: 'Office access allowed',
          appliedRules: [],
        })
        .mockResolvedValueOnce({
          allowed: false,
          reason: 'Home access denied',
          appliedRules: [],
        });

      const results = await tester.testDynamicAccess(test);

      expect(results).toHaveLength(2);
      expect(results[0].passed).toBe(true);
      expect(results[1].passed).toBe(true);
      expect(results[0].contextAwareDecision).toBe(true);
    });
  });

  describe('testMultiServiceAccess', () => {
    it('should test access across multiple services', async () => {
      const test: MultiServiceAccessTest = {
        agentId: 'agent-004',
        agentType: 'delegated',
        userContext: {
          userId: 'user-123',
          permissions: ['read:emails', 'read:documents'],
        },
        services: [
          {
            serviceId: 'email-service',
            resource: {
              id: 'inbox-123',
              type: 'emails',
              attributes: {},
            },
            action: 'read',
            expectedAllowed: true,
          },
          {
            serviceId: 'document-service',
            resource: {
              id: 'doc-123',
              type: 'documents',
              attributes: {},
            },
            action: 'read',
            expectedAllowed: true,
          },
        ],
      };

      mockPDP.evaluate
        .mockResolvedValueOnce({
          allowed: true,
          reason: 'Email access allowed',
          appliedRules: [],
        })
        .mockResolvedValueOnce({
          allowed: true,
          reason: 'Document access allowed',
          appliedRules: [],
        });

      const result = await tester.testMultiServiceAccess(test);

      expect(result.passed).toBe(true);
      expect(result.multiServiceConsistency).toBe(true);
      expect(result.details?.serviceResults).toHaveLength(2);
    });

    it('should detect permission inconsistencies across services', async () => {
      const test: MultiServiceAccessTest = {
        agentId: 'agent-004',
        agentType: 'delegated',
        userContext: {
          userId: 'user-123',
          permissions: ['read:emails'],
        },
        services: [
          {
            serviceId: 'email-service',
            resource: {
              id: 'inbox-123',
              type: 'emails',
              attributes: {},
            },
            action: 'read',
            expectedAllowed: true,
          },
          {
            serviceId: 'document-service',
            resource: {
              id: 'doc-123',
              type: 'documents',
              attributes: {},
            },
            action: 'read',
            expectedAllowed: false, // User doesn't have permission
          },
        ],
      };

      mockPDP.evaluate
        .mockResolvedValueOnce({
          allowed: true,
          reason: 'Email access allowed',
          appliedRules: [],
        })
        .mockResolvedValueOnce({
          allowed: false,
          reason: 'Document access denied',
          appliedRules: [],
        });

      const result = await tester.testMultiServiceAccess(test);

      expect(result.passed).toBe(true); // Both match expectations
      expect(result.multiServiceConsistency).toBe(true);
    });
  });

  describe('testPermissionBoundaries', () => {
    it('should detect when agent exceeds user permissions', async () => {
      const userPermissions = ['read:emails'];
      const resources = [
        {
          id: 'inbox-123',
          type: 'emails',
          attributes: {},
        },
      ];
      const actions = ['read', 'delete']; // User doesn't have delete

      mockPDP.evaluate
        .mockResolvedValueOnce({
          allowed: true,
          reason: 'Read allowed',
          appliedRules: [],
        })
        .mockResolvedValueOnce({
          allowed: false, // Correctly denied
          reason: 'Delete denied',
          appliedRules: [],
        });

      const result = await tester.testPermissionBoundaries(
        'agent-001',
        userPermissions,
        resources,
        actions
      );

      expect(result.boundariesRespected).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('should detect permission boundary violations', async () => {
      const userPermissions = ['read:emails'];
      const resources = [
        {
          id: 'inbox-123',
          type: 'emails',
          attributes: {},
        },
      ];
      const actions = ['delete']; // User doesn't have delete

      mockPDP.evaluate.mockResolvedValueOnce({
        allowed: true, // Incorrectly allowed
        reason: 'Access granted',
        appliedRules: [],
      });

      const result = await tester.testPermissionBoundaries(
        'agent-001',
        userPermissions,
        resources,
        actions
      );

      expect(result.boundariesRespected).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
    });
  });
});
