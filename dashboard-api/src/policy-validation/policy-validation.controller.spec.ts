/**
 * Policy Validation Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { PolicyValidationController } from './policy-validation.controller';
import { PolicyValidationService } from './policy-validation.service';
import {
  DetectConflictsDto,
  AnalyzeCoverageDto,
  TestPerformanceDto,
  RunRegressionDto,
  SimulatePolicyDto,
} from './dto/policy-validation.dto';

describe('PolicyValidationController', () => {
  let controller: PolicyValidationController;
  let policyValidationService: jest.Mocked<PolicyValidationService>;

  const mockConflictResult = {
    conflicts: [],
    warnings: [],
  };

  const mockCoverageResult = {
    coverage: 85,
    gaps: [],
  };

  const mockPerformanceResult = {
    averageLatency: 10,
    p95Latency: 20,
    throughput: 1000,
  };

  const mockRegressionResult = {
    passed: 10,
    failed: 0,
    total: 10,
  };

  const mockSimulationResult = {
    decisions: [],
    performance: {},
  };

  beforeEach(async () => {
    const mockPolicyValidationService = {
      detectConflicts: jest.fn(),
      analyzeCoverage: jest.fn(),
      testPerformance: jest.fn(),
      runRegression: jest.fn(),
      simulatePolicy: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [PolicyValidationController],
      providers: [
        {
          provide: PolicyValidationService,
          useValue: mockPolicyValidationService,
        },
      ],
    }).compile();

    controller = module.get<PolicyValidationController>(PolicyValidationController);
    policyValidationService = module.get(PolicyValidationService) as jest.Mocked<PolicyValidationService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('detectConflicts', () => {
    const dto: DetectConflictsDto = {
      policies: [
        { id: 'policy-1', name: 'Policy 1', description: 'Policy 1 description', effect: 'allow' as any, conditions: [] },
        { id: 'policy-2', name: 'Policy 2', description: 'Policy 2 description', effect: 'allow' as any, conditions: [] },
      ],
    };

    it('should detect conflicts between policies', async () => {
      // Arrange
      policyValidationService.detectConflicts.mockResolvedValue(mockConflictResult as any);

      // Act
      const result = await controller.detectConflicts(dto);

      // Assert
      expect(result).toEqual(mockConflictResult);
      expect(policyValidationService.detectConflicts).toHaveBeenCalledWith(dto);
    });
  });

  describe('analyzeCoverage', () => {
    const dto: AnalyzeCoverageDto = {
      resources: [{ id: 'resource-1', type: 'dataset', attributes: {} }],
      policies: [{ id: 'policy-1', name: 'Policy 1', description: 'Policy 1 description', effect: 'allow' as any, conditions: [] }],
    };

    it('should analyze policy coverage', async () => {
      // Arrange
      policyValidationService.analyzeCoverage.mockResolvedValue(mockCoverageResult as any);

      // Act
      const result = await controller.analyzeCoverage(dto);

      // Assert
      expect(result).toEqual(mockCoverageResult);
      expect(policyValidationService.analyzeCoverage).toHaveBeenCalledWith(dto);
    });
  });

  describe('testPerformance', () => {
    const dto: TestPerformanceDto = {
      policy: { id: 'policy-1', name: 'Test Policy', description: 'Test policy description', effect: 'allow' as any, conditions: [] },
    };

    it('should test policy performance', async () => {
      // Arrange
      policyValidationService.testPerformance.mockResolvedValue(mockPerformanceResult as any);

      // Act
      const result = await controller.testPerformance(dto);

      // Assert
      expect(result).toEqual(mockPerformanceResult);
      expect(policyValidationService.testPerformance).toHaveBeenCalledWith(dto);
    });
  });

  describe('runRegression', () => {
    const dto: RunRegressionDto = {
      baselinePolicies: [{ id: 'policy-1', name: 'Baseline Policy', description: 'Baseline', effect: 'allow' as any, conditions: [] }],
      currentPolicies: [{ id: 'policy-2', name: 'Current Policy', description: 'Current', effect: 'allow' as any, conditions: [] }],
      testCases: [
        {
          name: 'test-1',
          request: {
            subject: { id: 'user-1' },
            resource: { id: 'resource-1' },
            action: 'read',
          },
          expected: { allowed: true },
          passed: true,
        },
      ],
    };

    it('should run regression tests', async () => {
      // Arrange
      policyValidationService.runRegression.mockResolvedValue(mockRegressionResult as any);

      // Act
      const result = await controller.runRegression(dto);

      // Assert
      expect(result).toEqual(mockRegressionResult);
      expect(policyValidationService.runRegression).toHaveBeenCalledWith(dto);
    });
  });

  describe('simulatePolicy', () => {
    const dto: SimulatePolicyDto = {
      policy: {
        id: 'policy-1',
        name: 'Test Policy',
        description: 'Test policy description',
        effect: 'allow' as any,
        conditions: [],
      },
      testCases: [],
    };

    it('should simulate policy behavior', async () => {
      // Arrange
      policyValidationService.simulatePolicy.mockResolvedValue(mockSimulationResult as any);

      // Act
      const result = await controller.simulatePolicy(dto);

      // Assert
      expect(result).toEqual(mockSimulationResult);
      expect(policyValidationService.simulatePolicy).toHaveBeenCalledWith(dto);
    });
  });
});
