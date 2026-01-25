/**
 * Enhanced Risk Scoring Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EnhancedRiskScoringService } from './enhanced-risk-scoring.service';
import { TestResultsService } from '../../test-results/test-results.service';
import { TestResultEntity } from '../../test-results/entities/test-result.entity';

describe('EnhancedRiskScoringService', () => {
  let service: EnhancedRiskScoringService;
  let testResultsService: jest.Mocked<TestResultsService>;

  const mockTestResult: TestResultEntity = {
    id: 'result-1',
    applicationId: 'app-1',
    applicationName: 'Test App',
    testConfigurationId: 'config-1',
    testConfigurationName: 'Test Config',
    testConfigurationType: 'api-security',
    status: 'failed',
    passed: false,
    result: { error: 'Test failed' },
    timestamp: new Date(),
    createdAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockTestResultsService = {
      query: jest.fn().mockResolvedValue([]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EnhancedRiskScoringService,
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
      ],
    }).compile();

    service = module.get<EnhancedRiskScoringService>(EnhancedRiskScoringService);
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;

    // Clear historical scores
    (service as any).historicalScores = new Map();
  });

  describe('calculateRiskScore', () => {
    it('should calculate risk score for a test result', async () => {
      // Act
      const result = await service.calculateRiskScore(mockTestResult);

      // Assert
      expect(result).toBeDefined();
      expect(result.testResultId).toBe(mockTestResult.id);
      expect(result.applicationId).toBe(mockTestResult.applicationId);
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
      expect(result.severity).toBeDefined();
      expect(['critical', 'high', 'medium', 'low']).toContain(result.severity);
      expect(result.factors).toBeDefined();
      expect(Array.isArray(result.factors)).toBe(true);
      expect(result.recommendations).toBeDefined();
      expect(Array.isArray(result.recommendations)).toBe(true);
    });

    it('should include heatmap data', async () => {
      // Act
      const result = await service.calculateRiskScore(mockTestResult);

      // Assert
      expect(result.heatmapData).toBeDefined();
      expect(result.heatmapData.applicationId).toBe(mockTestResult.applicationId);
      expect(result.heatmapData.riskScore).toBeDefined();
      expect(result.heatmapData.severity).toBeDefined();
    });

    it('should include trend data', async () => {
      // Act
      const result = await service.calculateRiskScore(mockTestResult);

      // Assert
      expect(result.trend).toBeDefined();
      expect(result.trend.period).toBeDefined();
      expect(result.trend.averageRiskScore).toBeDefined();
      expect(['increasing', 'decreasing', 'stable']).toContain(result.trend.trend);
    });

    it('should calculate higher risk for failed tests', async () => {
      // Arrange
      const passedResult = { ...mockTestResult, passed: true };
      const failedResult = { ...mockTestResult, passed: false };

      // Act
      const passedScore = await service.calculateRiskScore(passedResult);
      const failedScore = await service.calculateRiskScore(failedResult);

      // Assert
      expect(failedScore.riskScore).toBeGreaterThanOrEqual(passedScore.riskScore);
    });
  });

  describe('getRiskHeatmap', () => {
    beforeEach(() => {
      testResultsService.query.mockResolvedValue([
        mockTestResult,
        { ...mockTestResult, id: 'result-2', applicationId: 'app-2' },
      ] as any);
    });

    it('should return risk heatmap data', async () => {
      // Act
      const result = await service.generateHeatmapData({});

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should filter by applicationId', async () => {
      // Act
      const result = await service.generateHeatmapData({ applicationId: 'app-1' });

      // Assert
      expect(testResultsService.query).toHaveBeenCalled();
      expect(result).toBeDefined();
    });
  });

});
