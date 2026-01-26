/**
 * Agent Tests Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { AgentTestsService } from './agent-tests.service';
import { AgentAccessControlTester } from '../../../heimdall-framework/services/agent-access-control-tester';
import { AgentOAuthTester } from '../../../heimdall-framework/services/agent-oauth-tester';
import { AgentAuditValidator } from '../../../heimdall-framework/services/agent-audit-validator';

// Mock the framework services
jest.mock('../../../heimdall-framework/services/agent-access-control-tester');
jest.mock('../../../heimdall-framework/services/agent-oauth-tester');
jest.mock('../../../heimdall-framework/services/agent-audit-validator');

describe('AgentTestsService', () => {
  let service: AgentTestsService;
  let mockAccessControlTester: jest.Mocked<AgentAccessControlTester>;
  let mockOAuthTester: jest.Mocked<AgentOAuthTester>;
  let mockAuditValidator: jest.Mocked<AgentAuditValidator>;

  beforeEach(async () => {
    // Create mocks
    mockAccessControlTester = {
      testDelegatedAccess: jest.fn(),
      testDirectAccess: jest.fn(),
      testMultiServiceAccess: jest.fn(),
      testDynamicAccess: jest.fn(),
    } as any;

    mockOAuthTester = {
      testAuthCodeFlow: jest.fn(),
      testClientCredentialsFlow: jest.fn(),
    } as any;

    mockAuditValidator = {
      addAuditLogEntry: jest.fn(),
      validateAuditTrail: jest.fn(),
      getAuditTrail: jest.fn(),
    } as any;

    // Mock constructors
    (AgentAccessControlTester as any).mockImplementation(() => mockAccessControlTester);
    (AgentOAuthTester as any).mockImplementation(() => mockOAuthTester);
    (AgentAuditValidator as any).mockImplementation(() => mockAuditValidator);

    const module: TestingModule = await Test.createTestingModule({
      providers: [AgentTestsService],
    }).compile();

    service = module.get<AgentTestsService>(AgentTestsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('runDelegatedAccessTests', () => {
    it('should run delegated access tests successfully', async () => {
      const dto = {
        agentId: 'agent-001',
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          role: 'researcher',
          permissions: ['read:emails'],
        },
        resources: [
          {
            id: 'inbox-123',
            type: 'emails',
            attributes: {},
          },
        ],
        actions: ['read'],
      };

      mockAccessControlTester.testDelegatedAccess.mockResolvedValue({
        testType: 'agent-delegated-access' as const,
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        agentId: 'agent-001',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
        permissionBoundariesRespected: true,
        userPermissionsEnforced: true,
      });

      const result = await service.runDelegatedAccessTests(dto);

      expect(result.agentId).toBe('agent-001');
      expect(result.testType).toBe('delegated-access');
      expect(result.results.length).toBeGreaterThan(0);
      expect(mockAccessControlTester.testDelegatedAccess).toHaveBeenCalled();
    });

    it('should test OAuth flows when configured', async () => {
      const dto = {
        agentId: 'agent-001',
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          role: 'researcher',
          permissions: ['read:emails'],
        },
        resources: [
          {
            id: 'inbox-123',
            type: 'emails',
            attributes: {},
          },
        ],
        actions: ['read'],
        oauthConfig: {
          authorizationEndpoint: 'https://auth.example.com/authorize',
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          redirectUri: 'https://app.example.com/callback',
          scopes: ['read:emails'],
        },
      };

      mockAccessControlTester.testDelegatedAccess.mockResolvedValue({
        testType: 'agent-delegated-access' as const,
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        agentId: 'agent-001',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
        permissionBoundariesRespected: true,
        userPermissionsEnforced: true,
      });

      mockOAuthTester.testAuthCodeFlow.mockResolvedValue({
        testType: 'agent-delegated-access' as const,
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
        details: {},
      });

      const result = await service.runDelegatedAccessTests(dto);

      expect(result.results.length).toBeGreaterThan(1);
      expect(mockOAuthTester.testAuthCodeFlow).toHaveBeenCalled();
    });
  });

  describe('runDirectAccessTests', () => {
    it('should run direct access tests successfully', async () => {
      const dto = {
        agentId: 'agent-002',
        agentType: 'autonomous' as const,
        resources: [
          {
            id: 'logs-123',
            type: 'logs',
            attributes: {},
          },
        ],
        actions: ['read'],
      };

      mockAccessControlTester.testDirectAccess.mockResolvedValue({
        testType: 'agent-direct-access' as const,
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        agentId: 'agent-002',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
      });

      const result = await service.runDirectAccessTests(dto);

      expect(result.agentId).toBe('agent-002');
      expect(result.testType).toBe('direct-access');
      expect(mockAccessControlTester.testDirectAccess).toHaveBeenCalled();
    });
  });

  describe('getAuditTrail', () => {
    it('should retrieve audit trail for agent', async () => {
      const agentId = 'agent-001';
      const filters = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const mockAuditTrail = [
        {
          id: 'audit-1',
          timestamp: new Date(),
          agentId: 'agent-001',
          agentType: 'delegated' as const,
          action: 'read',
          serviceId: 'email-service',
          resourceId: 'inbox-123',
          resourceType: 'emails',
          allowed: true,
        },
      ];

      mockAuditValidator.getAuditTrail.mockReturnValue(mockAuditTrail);

      const result = await service.getAuditTrail(agentId, filters);

      expect(result.agentId).toBe(agentId);
      expect(result.auditTrail).toEqual(mockAuditTrail);
      expect(result.totalEntries).toBe(1);
      expect(mockAuditValidator.getAuditTrail).toHaveBeenCalledWith(agentId, filters);
    });
  });

  describe('testMultiServiceAccess', () => {
    it('should test multi-service access', async () => {
      const dto = {
        agentId: 'agent-003',
        agentType: 'delegated' as const,
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

      mockAccessControlTester.testMultiServiceAccess.mockResolvedValue({
        testType: 'agent-multi-service' as const,
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        agentId: 'agent-003',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
        multiServiceConsistency: true,
        details: {
          serviceResults: [],
          servicesAllowed: 2,
        },
      });

      const result = await service.testMultiServiceAccess(dto);

      expect(result.agentId).toBe('agent-003');
      expect(result.testType).toBe('multi-service');
      expect(mockAccessControlTester.testMultiServiceAccess).toHaveBeenCalled();
    });
  });

  describe('testDynamicAccess', () => {
    it('should test dynamic access scenarios', async () => {
      const dto = {
        agentId: 'agent-004',
        agentType: 'delegated' as const,
        userContext: {
          userId: 'user-123',
          permissions: ['read:documents'],
        },
        scenarios: [
          {
            name: 'Office access',
            context: {
              location: 'office',
              timeOfDay: '14:30',
            },
            requestedPermission: 'read:documents',
            expectedGranted: true,
          },
        ],
      };

      mockAccessControlTester.testDynamicAccess.mockResolvedValue([
        {
          testType: 'agent-dynamic-access' as const,
          testName: 'Test',
          passed: true,
          timestamp: new Date(),
          agentId: 'agent-004',
          allowed: true,
          expectedAllowed: true,
          decisionReason: 'Allowed',
          contextAwareDecision: true,
        },
      ]);

      const result = await service.testDynamicAccess(dto);

      expect(result.agentId).toBe('agent-004');
      expect(result.testType).toBe('dynamic-access');
      expect(result.results.length).toBe(1);
      expect(mockAccessControlTester.testDynamicAccess).toHaveBeenCalled();
    });
  });

  describe('validateAuditTrail', () => {
    it('should validate audit trail', async () => {
      const dto = {
        agentId: 'agent-001',
        agentType: 'delegated' as const,
        userId: 'user-123',
        actions: [
          {
            serviceId: 'email-service',
            action: 'read',
            resourceId: 'inbox-123',
            resourceType: 'emails',
            timestamp: new Date(),
            expectedLogged: true,
          },
        ],
        auditSources: ['source-1'],
        retentionPeriod: 90,
      };

      mockAuditValidator.validateAuditTrail.mockResolvedValue({
        testType: 'agent-audit-trail' as const,
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        agentId: 'agent-001',
        auditLogComplete: true,
        auditLogIntegrity: true,
        crossServiceCorrelation: true,
        details: {},
      });

      const result = await service.validateAuditTrail(dto);

      expect(result.agentId).toBe('agent-001');
      expect(result.validationResult.passed).toBe(true);
      expect(mockAuditValidator.addAuditLogEntry).toHaveBeenCalled();
      expect(mockAuditValidator.validateAuditTrail).toHaveBeenCalled();
    });
  });
});
