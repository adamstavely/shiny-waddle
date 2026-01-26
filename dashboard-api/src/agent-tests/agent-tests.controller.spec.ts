/**
 * Agent Tests Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { AgentTestsController } from './agent-tests.controller';
import { AgentTestsService } from './agent-tests.service';
import { AccessControlGuard } from '../security/guards/access-control.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

describe('AgentTestsController', () => {
  let controller: AgentTestsController;
  let service: jest.Mocked<AgentTestsService>;

  const mockRequest = {
    user: {
      id: 'user-1',
      userId: 'user-1',
      username: 'testuser',
      email: 'test@example.com',
      role: 'admin',
    },
  };

  beforeEach(async () => {
    const mockService = {
      runDelegatedAccessTests: jest.fn(),
      runDirectAccessTests: jest.fn(),
      getAuditTrail: jest.fn(),
      testMultiServiceAccess: jest.fn(),
      testDynamicAccess: jest.fn(),
      validateAuditTrail: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AgentTestsController],
      providers: [
        {
          provide: AgentTestsService,
          useValue: mockService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AccessControlGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AgentTestsController>(AgentTestsController);
    service = module.get(AgentTestsService) as jest.Mocked<AgentTestsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('runDelegatedAccessTests', () => {
    it('should run delegated access tests', async () => {
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

      const expectedResult = {
        agentId: 'agent-001',
        testType: 'delegated-access',
        results: [],
        summary: {
          total: 1,
          passed: 1,
          failed: 0,
        },
      };

      service.runDelegatedAccessTests.mockResolvedValue(expectedResult);

      const result = await controller.runDelegatedAccessTests(dto);

      expect(result).toEqual(expectedResult);
      expect(service.runDelegatedAccessTests).toHaveBeenCalledWith(dto);
    });
  });

  describe('runDirectAccessTests', () => {
    it('should run direct access tests', async () => {
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

      const expectedResult = {
        agentId: 'agent-002',
        testType: 'direct-access',
        results: [],
        summary: {
          total: 1,
          passed: 1,
          failed: 0,
        },
      };

      service.runDirectAccessTests.mockResolvedValue(expectedResult);

      const result = await controller.runDirectAccessTests(dto);

      expect(result).toEqual(expectedResult);
      expect(service.runDirectAccessTests).toHaveBeenCalledWith(dto);
    });
  });

  describe('getAuditTrail', () => {
    it('should get audit trail for agent', async () => {
      const agentId = 'agent-001';
      const filters = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const expectedResult = {
        agentId,
        auditTrail: [],
        totalEntries: 0,
        filters,
      };

      service.getAuditTrail.mockResolvedValue(expectedResult);

      const result = await controller.getAuditTrail(agentId, filters);

      expect(result).toEqual(expectedResult);
      expect(service.getAuditTrail).toHaveBeenCalledWith(agentId, filters);
    });
  });

  describe('testMultiServiceAccess', () => {
    it('should test multi-service access', async () => {
      const dto = {
        agentId: 'agent-003',
        agentType: 'delegated' as const,
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
        ],
      };

      const expectedResult = {
        agentId: 'agent-003',
        testType: 'multi-service',
        result: {
          testType: 'agent-multi-service' as const,
          testName: 'Test',
          passed: true,
          timestamp: new Date(),
          agentId: 'agent-003',
          allowed: true,
          expectedAllowed: true,
          decisionReason: 'Allowed',
          multiServiceConsistency: true,
        },
      };

      service.testMultiServiceAccess.mockResolvedValue(expectedResult);

      const result = await controller.testMultiServiceAccess(dto);

      expect(result).toEqual(expectedResult);
      expect(service.testMultiServiceAccess).toHaveBeenCalledWith(dto);
    });
  });

  describe('testDynamicAccess', () => {
    it('should test dynamic access', async () => {
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

      const expectedResult = {
        agentId: 'agent-004',
        testType: 'dynamic-access',
        results: [],
        summary: {
          total: 1,
          passed: 1,
          failed: 0,
        },
      };

      service.testDynamicAccess.mockResolvedValue(expectedResult);

      const result = await controller.testDynamicAccess(dto);

      expect(result).toEqual(expectedResult);
      expect(service.testDynamicAccess).toHaveBeenCalledWith(dto);
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

      const expectedResult = {
        agentId: 'agent-001',
        validationResult: {
          testType: 'agent-audit-trail' as const,
          testName: 'Test',
          passed: true,
          timestamp: new Date(),
          agentId: 'agent-001',
          auditLogComplete: true,
          auditLogIntegrity: true,
          crossServiceCorrelation: true,
          details: {},
        },
      };

      service.validateAuditTrail.mockResolvedValue(expectedResult);

      const result = await controller.validateAuditTrail(dto);

      expect(result).toEqual(expectedResult);
      expect(service.validateAuditTrail).toHaveBeenCalledWith(dto);
    });
  });
});
