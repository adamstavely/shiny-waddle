/**
 * Agent Delegated Access Test Suite Unit Tests
 */

import { AgentDelegatedAccessTestSuite } from './agent-delegated-access-test-suite';
import { AccessControlConfig } from '../../core/types';
import { AgentAccessControlTester } from '../agent-access-control-tester';
import { AgentOAuthTester } from '../agent-oauth-tester';

// Mock dependencies
jest.mock('../agent-access-control-tester');
jest.mock('../agent-oauth-tester');

describe('AgentDelegatedAccessTestSuite', () => {
  let suite: AgentDelegatedAccessTestSuite;
  let mockAccessControlTester: jest.Mocked<AgentAccessControlTester>;
  let mockOAuthTester: jest.Mocked<AgentOAuthTester>;
  let config: AccessControlConfig;

  beforeEach(() => {
    config = {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
    };

    mockAccessControlTester = {
      testDelegatedAccess: jest.fn(),
      testMultiServiceAccess: jest.fn(),
      testPermissionBoundaries: jest.fn(),
    } as any;

    mockOAuthTester = {
      testAuthCodeFlow: jest.fn(),
      testOBOTokenFlow: jest.fn(),
    } as any;

    (AgentAccessControlTester as any).mockImplementation(() => mockAccessControlTester);
    (AgentOAuthTester as any).mockImplementation(() => mockOAuthTester);

    suite = new AgentDelegatedAccessTestSuite({
      accessControlConfig: config,
      oauthConfig: {
        authorizationEndpoint: 'https://auth.example.com/authorize',
        tokenEndpoint: 'https://auth.example.com/token',
        clientId: 'test-client',
        redirectUri: 'https://app.example.com/callback',
      },
    });
  });

  describe('testUserInitiatedRequest', () => {
    it('should test user-initiated request', async () => {
      const agentId = 'agent-001';
      const userContext = {
        userId: 'user-123',
        email: 'user@example.com',
        role: 'researcher',
        permissions: ['read:emails'],
      };
      const resource = {
        id: 'inbox-123',
        type: 'emails',
        attributes: {},
      };

      mockAccessControlTester.testDelegatedAccess.mockResolvedValue({
        testType: 'agent-delegated-access',
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        testType: 'delegated',
        agentId: 'agent-001',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
        permissionBoundariesRespected: true,
        userPermissionsEnforced: true,
      });

      const result = await suite.testUserInitiatedRequest(
        agentId,
        userContext,
        resource,
        'read'
      );

      expect(result.passed).toBe(true);
      expect(result.testType).toBe('agent-delegated-access');
      expect(mockAccessControlTester.testDelegatedAccess).toHaveBeenCalled();
    });
  });

  describe('testPermissionDelegation', () => {
    it('should test permission delegation for multiple resources', async () => {
      const agentId = 'agent-001';
      const userContext = {
        userId: 'user-123',
        email: 'user@example.com',
        role: 'researcher',
        permissions: ['read:emails'],
      };
      const resources = [
        {
          id: 'inbox-123',
          type: 'emails',
          attributes: {},
        },
      ];
      const actions = ['read'];

      mockAccessControlTester.testDelegatedAccess.mockResolvedValue({
        testType: 'agent-delegated-access',
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        testType: 'delegated',
        agentId: 'agent-001',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
        permissionBoundariesRespected: true,
        userPermissionsEnforced: true,
      });

      const results = await suite.testPermissionDelegation(
        agentId,
        userContext,
        resources,
        actions
      );

      expect(results.length).toBeGreaterThan(0);
      expect(results[0].passed).toBe(true);
    });
  });

  describe('testCrossServiceAccess', () => {
    it('should test cross-service access with OBO flow', async () => {
      const agentId = 'agent-001';
      const userContext = {
        userId: 'user-123',
        email: 'user@example.com',
        role: 'researcher',
        permissions: ['read:emails', 'read:documents'],
      };
      const services = [
        {
          serviceId: 'email-service',
          resource: {
            id: 'inbox-123',
            type: 'emails',
            attributes: {},
          },
          action: 'read',
        },
        {
          serviceId: 'document-service',
          resource: {
            id: 'doc-123',
            type: 'documents',
            attributes: {},
          },
          action: 'read',
        },
      ];

      mockAccessControlTester.testMultiServiceAccess.mockResolvedValue({
        testType: 'agent-multi-service',
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        testType: 'multi-service',
        agentId: 'agent-001',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
        multiServiceConsistency: true,
        details: {
          serviceResults: [],
          servicesAllowed: 2,
        },
      });

      mockOAuthTester.testOBOTokenFlow.mockResolvedValue({
        testType: 'agent-delegated-access',
        testName: 'OBO Token Flow Test',
        passed: true,
        timestamp: new Date(),
        flowType: 'obo-token',
        tokenIssued: true,
        tokenValid: true,
        scopesGranted: ['read:documents'],
        scopesExpected: ['read:documents'],
      });

      const result = await suite.testCrossServiceAccess(
        agentId,
        userContext,
        services
      );

      expect(result.passed).toBe(true);
      expect(mockAccessControlTester.testMultiServiceAccess).toHaveBeenCalled();
      expect(mockOAuthTester.testOBOTokenFlow).toHaveBeenCalled();
    });
  });

  describe('testPermissionBoundaries', () => {
    it('should test permission boundary enforcement', async () => {
      const agentId = 'agent-001';
      const userContext = {
        userId: 'user-123',
        email: 'user@example.com',
        role: 'researcher',
        permissions: ['read:emails'],
      };
      const resources = [
        {
          id: 'inbox-123',
          type: 'emails',
          attributes: {},
        },
      ];
      const actions = ['read', 'delete'];

      mockAccessControlTester.testPermissionBoundaries.mockResolvedValue({
        boundariesRespected: true,
        violations: [],
      });

      const result = await suite.testPermissionBoundaries(
        agentId,
        userContext,
        resources,
        actions
      );

      expect(result.passed).toBe(true);
      expect(mockAccessControlTester.testPermissionBoundaries).toHaveBeenCalled();
    });
  });

  describe('testAuthCodeFlow', () => {
    it('should test Auth Code Flow', async () => {
      const userContext = {
        userId: 'user-123',
        email: 'user@example.com',
        permissions: ['read:emails'],
      };
      const scopes = ['read:emails'];

      mockOAuthTester.testAuthCodeFlow.mockResolvedValue({
        testType: 'agent-delegated-access',
        testName: 'Auth Code Flow Test',
        passed: true,
        timestamp: new Date(),
        flowType: 'auth-code',
        tokenIssued: true,
        tokenValid: true,
        scopesGranted: ['read:emails'],
        scopesExpected: ['read:emails'],
        userPermissionsEnforced: true,
        permissionBoundariesRespected: true,
      });

      const result = await suite.testAuthCodeFlow(userContext, scopes);

      expect(result.passed).toBe(true);
      expect(mockOAuthTester.testAuthCodeFlow).toHaveBeenCalled();
    });

    it('should return error when OAuth config is missing', async () => {
      const suiteWithoutOAuth = new AgentDelegatedAccessTestSuite({
        accessControlConfig: config,
      });

      const result = await suiteWithoutOAuth.testAuthCodeFlow(
        {
          userId: 'user-123',
          email: 'user@example.com',
          permissions: ['read:emails'],
        },
        ['read:emails']
      );

      expect(result.passed).toBe(false);
      expect(result.error).toContain('OAuth configuration not provided');
    });
  });
});
