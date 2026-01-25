/**
 * Risk Scoring Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { RiskScoringController } from './risk-scoring.controller';
import { EnhancedRiskScoringService } from './services/enhanced-risk-scoring.service';
import { TestResultsService } from '../test-results/test-results.service';

describe('RiskScoringController', () => {
  let controller: RiskScoringController;
  let riskScoringService: jest.Mocked<EnhancedRiskScoringService>;
  let testResultsService: jest.Mocked<TestResultsService>;

  const mockHeatmapData = [
    {
      applicationId: 'app-1',
      applicationName: 'Test App',
      riskScore: 75,
      severity: 'high' as const,
      testConfigurationType: 'access-control',
      timestamp: new Date(),
    },
  ];

  const mockTrends = [
    {
      period: '2024-01',
      averageRiskScore: 75,
      totalRisks: 1,
      bySeverity: {
        critical: 0,
        high: 1,
        medium: 0,
        low: 0,
      },
      trend: 'increasing' as const,
      changePercentage: 10,
    },
  ];

  const mockRiskScores = [
    {
      testResultId: 'result-1',
      applicationId: 'app-1',
      applicationName: 'Test App',
      testConfigurationId: 'config-1',
      testConfigurationName: 'Test Config',
      testConfigurationType: 'access-control',
      riskScore: 85,
      severity: 'high' as const,
      businessImpact: 80,
      priority: 90,
      factors: [],
      recommendations: [],
      timestamp: new Date(),
      heatmapData: {
        applicationId: 'app-1',
        applicationName: 'Test App',
        riskScore: 85,
        severity: 'high' as const,
        testConfigurationType: 'access-control',
        timestamp: new Date(),
      },
      trend: {
        period: '2024-01',
        averageRiskScore: 85,
        totalRisks: 1,
        bySeverity: {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
        },
        trend: 'increasing' as const,
        changePercentage: 10,
      },
      priorityRank: 1,
    },
  ];

  const mockTestResult = {
    id: 'result-1',
    passed: false,
    applicationId: 'app-1',
  };

  beforeEach(async () => {
    const mockRiskScoringService = {
      generateHeatmapData: jest.fn(),
      calculateTrends: jest.fn(),
      calculateRiskScores: jest.fn(),
    };

    const mockTestResultsService = {
      findById: jest.fn(),
      query: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [RiskScoringController],
      providers: [
        {
          provide: EnhancedRiskScoringService,
          useValue: mockRiskScoringService,
        },
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
      ],
    }).compile();

    controller = module.get<RiskScoringController>(RiskScoringController);
    riskScoringService = module.get(EnhancedRiskScoringService) as jest.Mocked<EnhancedRiskScoringService>;
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getHeatmapData', () => {
    it('should get heatmap data', async () => {
      // Arrange
      riskScoringService.generateHeatmapData.mockResolvedValue(mockHeatmapData);

      // Act
      const result = await controller.getHeatmapData();

      // Assert
      expect(result).toEqual(mockHeatmapData);
      expect(riskScoringService.generateHeatmapData).toHaveBeenCalledWith({
        applicationId: undefined,
        startDate: undefined,
        endDate: undefined,
      });
    });

    it('should get heatmap data with filters', async () => {
      // Arrange
      riskScoringService.generateHeatmapData.mockResolvedValue(mockHeatmapData);

      // Act
      const result = await controller.getHeatmapData('app-1', '2024-01-01', '2024-12-31');

      // Assert
      expect(result).toEqual(mockHeatmapData);
      expect(riskScoringService.generateHeatmapData).toHaveBeenCalledWith({
        applicationId: 'app-1',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      });
    });
  });

  describe('getTrends', () => {
    it('should get risk trends', async () => {
      // Arrange
      riskScoringService.calculateTrends.mockResolvedValue(mockTrends);

      // Act
      const result = await controller.getTrends();

      // Assert
      expect(result).toEqual(mockTrends);
      expect(riskScoringService.calculateTrends).toHaveBeenCalledWith({
        applicationId: undefined,
        testConfigurationId: undefined,
        period: undefined,
        startDate: undefined,
        endDate: undefined,
      });
    });

    it('should get risk trends with filters', async () => {
      // Arrange
      riskScoringService.calculateTrends.mockResolvedValue(mockTrends);

      // Act
      const result = await controller.getTrends('app-1', 'config-1', 'week', '2024-01-01', '2024-12-31');

      // Assert
      expect(result).toEqual(mockTrends);
      expect(riskScoringService.calculateTrends).toHaveBeenCalledWith({
        applicationId: 'app-1',
        testConfigurationId: 'config-1',
        period: 'week',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      });
    });
  });

  describe('calculateRiskScores', () => {
    it('should calculate risk scores for specific test results', async () => {
      // Arrange
      testResultsService.findById.mockResolvedValue(mockTestResult as any);
      riskScoringService.calculateRiskScores.mockResolvedValue(mockRiskScores);

      // Act
      const result = await controller.calculateRiskScores(['result-1']);

      // Assert
      expect(result).toEqual(mockRiskScores);
      expect(testResultsService.findById).toHaveBeenCalledWith('result-1');
      expect(riskScoringService.calculateRiskScores).toHaveBeenCalledWith([mockTestResult]);
    });

    it('should calculate risk scores for all matching criteria', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([mockTestResult] as any);
      riskScoringService.calculateRiskScores.mockResolvedValue(mockRiskScores);

      // Act
      const result = await controller.calculateRiskScores(undefined, 'app-1', 'config-1');

      // Assert
      expect(result).toEqual(mockRiskScores);
      expect(testResultsService.query).toHaveBeenCalledWith({
        applicationId: 'app-1',
        testConfigurationId: 'config-1',
      });
      expect(riskScoringService.calculateRiskScores).toHaveBeenCalledWith([mockTestResult]);
    });
  });

  describe('getApplicationRiskScores', () => {
    it('should get risk scores for an application', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([mockTestResult] as any);
      riskScoringService.calculateRiskScores.mockResolvedValue(mockRiskScores);

      // Act
      const result = await controller.getApplicationRiskScores('app-1');

      // Assert
      expect(result).toEqual(mockRiskScores);
      expect(testResultsService.query).toHaveBeenCalledWith({
        applicationId: 'app-1',
      });
      expect(riskScoringService.calculateRiskScores).toHaveBeenCalledWith([mockTestResult]);
    });
  });
});
