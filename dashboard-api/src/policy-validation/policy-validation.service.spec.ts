/**
 * Policy Validation Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { PolicyValidationService } from './policy-validation.service';
import { PolicyValidationTester } from '../../../heimdall-framework/services/policy-validation-tester';
import { PolicyDecisionPoint } from '../../../heimdall-framework/services/policy-decision-point';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../heimdall-framework/services/policy-validation-tester');
jest.mock('../../../heimdall-framework/services/policy-decision-point');

describe('PolicyValidationService', () => {
  let service: PolicyValidationService;
  let mockTester: jest.Mocked<PolicyValidationTester>;
  let mockPDP: jest.Mocked<PolicyDecisionPoint>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instances
    mockTester = {
      detectPolicyConflicts: jest.fn(),
      analyzePolicyCoverage: jest.fn(),
      testPolicyPerformance: jest.fn(),
      runRegressionTests: jest.fn(),
      simulatePolicyChange: jest.fn(),
    } as any;

    mockPDP = {
      evaluate: jest.fn(),
    } as any;

    // Mock the constructors
    (PolicyDecisionPoint as jest.Mock).mockImplementation(() => mockPDP);
    (PolicyValidationTester as jest.Mock).mockImplementation(() => mockTester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [PolicyValidationService],
    }).compile();

    service = module.get<PolicyValidationService>(PolicyValidationService);
  });

  describe('detectConflicts', () => {
    it('should successfully detect policy conflicts', async () => {
      const mockConflicts = [
        {
          policy1: 'policy-1',
          policy2: 'policy-2',
          conflictType: 'contradiction' as const,
          description: 'Conflicting policies',
          affectedResources: ['resource-1'],
        },
      ];

      mockTester.detectPolicyConflicts.mockResolvedValue(mockConflicts);

      const result = await service.detectConflicts({
        policies: [
          { id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] },
          { id: 'policy-2', name: 'Policy 2', description: 'Test policy description', effect: 'deny', conditions: [] },
        ],
      });

      expect(result).toEqual(mockConflicts);
      expect(mockTester.detectPolicyConflicts).toHaveBeenCalled();
    });

    it('should throw ValidationException for missing policies array', async () => {
      await expect(service.detectConflicts({ policies: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for non-array policies', async () => {
      await expect(service.detectConflicts({ policies: {} as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw InternalServerException on service error', async () => {
      mockTester.detectPolicyConflicts.mockRejectedValue(new Error('Service error'));

      await expect(
        service.detectConflicts({
          policies: [{ id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] }],
        }),
      ).rejects.toThrow(InternalServerException);
    });
  });

  describe('analyzeCoverage', () => {
    it('should successfully analyze policy coverage', async () => {
      const mockCoverage = {
        totalResources: 7,
        resourcesWithPolicies: 5,
        resourcesWithoutPolicies: ['resource-1', 'resource-2'],
        coveragePercentage: 71.4,
        gaps: [],
      };

      mockTester.analyzePolicyCoverage.mockResolvedValue(mockCoverage);

      const result = await service.analyzeCoverage({
        resources: [
          { id: 'resource-1', type: 'dataset', attributes: {} },
          { id: 'resource-2', type: 'dataset', attributes: {} },
        ],
        policies: [{ id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] }],
      });

      expect(result).toEqual(mockCoverage);
    });

    it('should throw ValidationException for missing resources', async () => {
      await expect(
        service.analyzeCoverage({
          resources: null as any,
          policies: [],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing policies', async () => {
      await expect(
        service.analyzeCoverage({
          resources: [],
          policies: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testPerformance', () => {
    it('should successfully test policy performance', async () => {
      const mockPerformance = {
        policyId: 'policy-1',
        evaluationCount: 1000,
        totalTime: 10500,
        averageTime: 10.5,
        minTime: 5.0,
        maxTime: 25.0,
        p50: 10.0,
        p95: 15.2,
        p99: 20.1,
      };

      mockTester.testPolicyPerformance.mockResolvedValue(mockPerformance);

      const result = await service.testPerformance({
        policy: { id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] },
        iterations: 1000,
      });

      expect(result).toEqual(mockPerformance);
    });

    it('should throw ValidationException for missing policy', async () => {
      await expect(
        service.testPerformance({
          policy: null as any,
          iterations: 1000,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing policy id', async () => {
      await expect(
        service.testPerformance({
          policy: { name: 'Policy 1', effect: 'allow', conditions: [] } as any,
          iterations: 1000,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid iterations', async () => {
      await expect(
        service.testPerformance({
          policy: { id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] },
          iterations: 0,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for iterations exceeding limit', async () => {
      await expect(
        service.testPerformance({
          policy: { id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] },
          iterations: 100001,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('runRegression', () => {
    it('should successfully run regression tests', async () => {
      const mockResults = {
        policyId: 'policy-1',
        baselineResults: new Map<string, boolean>([['test-case-1', true]]),
        currentResults: new Map<string, boolean>([['test-case-1', true]]),
        regressions: [],
      };

      mockTester.runRegressionTests.mockResolvedValue(mockResults);

      const result = await service.runRegression({
        baselinePolicies: [{ id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] }],
        currentPolicies: [{ id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] }],
        testCases: [],
      });

      expect(result).toEqual(mockResults);
    });

    it('should throw ValidationException for missing baseline policies', async () => {
      await expect(
        service.runRegression({
          baselinePolicies: null as any,
          currentPolicies: [],
          testCases: [],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing current policies', async () => {
      await expect(
        service.runRegression({
          baselinePolicies: [],
          currentPolicies: null as any,
          testCases: [],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing test cases', async () => {
      await expect(
        service.runRegression({
          baselinePolicies: [],
          currentPolicies: [],
          testCases: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('simulatePolicy', () => {
    it('should successfully simulate policy change', async () => {
      const testPolicy = { id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow' as const, conditions: [] };
      const mockSimulation = {
        policy: testPolicy,
        testCases: [
          {
            name: 'test-case-1',
            request: { subject: { id: 'user-1' }, resource: { id: 'resource-1' }, action: 'read' },
            expectedResult: true,
            simulatedResult: true,
            match: true,
          },
        ],
        overallMatch: true,
      };

      mockTester.simulatePolicyChange.mockResolvedValue(mockSimulation);

      const result = await service.simulatePolicy({
        policy: testPolicy,
        testCases: [
          {
            name: 'test-case-1',
            request: { subject: { id: 'user-1' }, resource: { id: 'resource-1' }, action: 'read' },
            expected: { allowed: true },
            passed: true,
          },
        ],
      });

      expect(result).toEqual(mockSimulation);
    });

    it('should throw ValidationException for missing policy', async () => {
      await expect(
        service.simulatePolicy({
          policy: null as any,
          testCases: [],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for empty test cases', async () => {
      await expect(
        service.simulatePolicy({
          policy: { id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow' as const, conditions: [] },
          testCases: [],
        }),
      ).rejects.toThrow(ValidationException);
    });
  });
});

