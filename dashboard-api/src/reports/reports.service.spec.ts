/**
 * Reports Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ReportsService } from './reports.service';
import { ComplianceScoresService } from '../compliance/compliance-scores.service';
import { TestResultsService } from '../test-results/test-results.service';
import { UnifiedFindingsService } from '../unified-findings/unified-findings.service';
import { ApplicationsService } from '../applications/applications.service';
import { EnhancedRiskScoringService } from '../risk-scoring/services/enhanced-risk-scoring.service';
import { RemediationTrackingService } from '../remediation-tracking/remediation-tracking.service';
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock dependencies
jest.mock('fs/promises');

describe('ReportsService', () => {
  let service: ReportsService;
  let complianceScoresService: jest.Mocked<ComplianceScoresService>;
  let testResultsService: jest.Mocked<TestResultsService>;
  let applicationsService: jest.Mocked<ApplicationsService>;
  let riskScoringService: jest.Mocked<EnhancedRiskScoringService>;

  const mockTestResult: any = {
    id: 'result-1',
    applicationId: 'app-1',
    applicationName: 'Test App',
    testConfigurationId: 'config-1',
    testConfigurationName: 'Test Config',
    testConfigurationType: 'access-control',
    passed: true,
    status: 'passed' as const,
    timestamp: new Date(),
  };

  const mockApplication: any = {
    id: 'app-1',
    name: 'Test App',
    type: 'web',
    status: 'active',
    registeredAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    // Mock fs BEFORE creating module (constructor calls fs.mkdir)
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

    const mockComplianceScoresService = {
      getHistory: jest.fn().mockResolvedValue([
        { date: '2026-01-01', score: 80 },
        { date: '2026-01-02', score: 85 },
      ]),
    };

    const mockTestResultsService = {
      query: jest.fn().mockResolvedValue([mockTestResult]),
    };

    const mockApplicationsService = {
      findAll: jest.fn().mockResolvedValue([mockApplication]),
    };

    const mockRiskScoringService = {
      calculateRiskScores: jest.fn().mockResolvedValue([]),
    };

    const mockRemediationService = {};

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReportsService,
        {
          provide: ComplianceScoresService,
          useValue: mockComplianceScoresService,
        },
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
        {
          provide: UnifiedFindingsService,
          useValue: {},
        },
        {
          provide: ApplicationsService,
          useValue: mockApplicationsService,
        },
        {
          provide: EnhancedRiskScoringService,
          useValue: mockRiskScoringService,
        },
        {
          provide: RemediationTrackingService,
          useValue: mockRemediationService,
        },
      ],
    }).compile();

    service = module.get<ReportsService>(ReportsService);
    complianceScoresService = module.get(ComplianceScoresService) as jest.Mocked<ComplianceScoresService>;
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;
    applicationsService = module.get(ApplicationsService) as jest.Mocked<ApplicationsService>;
    riskScoringService = module.get(EnhancedRiskScoringService) as jest.Mocked<EnhancedRiskScoringService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('generateReport', () => {
    it('should generate JSON report', async () => {
      // Arrange
      const request = {
        name: 'Test Report',
        format: 'json' as const,
        applicationIds: ['app-1'],
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      expect(result.id).toBeDefined();
      expect(result.name).toBe('Test Report');
      expect(result.format).toBe('json');
      expect(result.content).toBeDefined();
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should generate HTML report', async () => {
      // Arrange
      const request = {
        name: 'Test Report',
        format: 'html' as const,
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      expect(result.format).toBe('html');
      expect(typeof result.content).toBe('string');
      expect((result.content as string)).toContain('<!DOCTYPE html>');
    });

    it('should generate XML report', async () => {
      // Arrange
      const request = {
        name: 'Test Report',
        format: 'xml' as const,
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      expect(result.format).toBe('xml');
      expect(typeof result.content).toBe('string');
      expect((result.content as string)).toContain('<?xml');
    });

    it('should include trends when requested', async () => {
      // Arrange
      complianceScoresService.getHistory.mockResolvedValue([
        { date: '2026-01-01', score: 80 },
        { date: '2026-01-02', score: 85 },
      ]);
      const request = {
        name: 'Test Report',
        format: 'json' as const,
        includeTrends: true,
        applicationIds: ['app-1'],
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      expect(complianceScoresService.getHistory).toHaveBeenCalled();
      const reportData = result.content as any;
      expect(reportData.trends).toBeDefined();
    });

    it('should include risk scores when requested', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([
        { ...mockTestResult, passed: false, status: 'failed' as const },
      ]);
      riskScoringService.calculateRiskScores.mockResolvedValue([
        {
          testResultId: 'result-1',
          applicationId: 'app-1',
          applicationName: 'Test App',
          testConfigurationId: 'config-1',
          testConfigurationName: 'Test Config',
          testConfigurationType: 'access-control',
          riskScore: 75,
          severity: 'high',
          businessImpact: 70,
          priority: 80,
          factors: [],
          recommendations: [],
          timestamp: new Date(),
          heatmapData: {} as any,
          trend: {} as any,
          priorityRank: 1,
        } as any,
      ]);
      const request = {
        name: 'Test Report',
        format: 'json' as const,
        includeRiskScores: true,
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      expect(riskScoringService.calculateRiskScores).toHaveBeenCalled();
      const reportData = result.content as any;
      expect(reportData.riskAssessment).toBeDefined();
    });

    it('should filter by application IDs', async () => {
      // Arrange
      const request = {
        name: 'Test Report',
        format: 'json' as const,
        applicationIds: ['app-1'],
      };

      // Act
      await service.generateReport(request);

      // Assert
      expect(testResultsService.query).toHaveBeenCalledWith(
        expect.objectContaining({
          applicationId: 'app-1',
        }),
      );
    });

    it('should filter by date range', async () => {
      // Arrange
      const request = {
        name: 'Test Report',
        format: 'json' as const,
        dateFrom: '2026-01-01',
        dateTo: '2026-01-31',
      };

      // Act
      await service.generateReport(request);

      // Assert
      expect(testResultsService.query).toHaveBeenCalledWith(
        expect.objectContaining({
          startDate: expect.any(Date),
          endDate: expect.any(Date),
        }),
      );
    });

    it('should calculate test results summary', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([
        { ...mockTestResult, passed: true, status: 'passed' },
        { ...mockTestResult, id: 'result-2', passed: false, status: 'failed' },
      ]);
      const request = {
        name: 'Test Report',
        format: 'json' as const,
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      const reportData = result.content as any;
      expect(reportData.testResults.summary.total).toBe(2);
      expect(reportData.testResults.summary.passed).toBe(1);
      expect(reportData.testResults.summary.failed).toBe(1);
    });

    it('should group test results by application', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([
        { ...mockTestResult, applicationId: 'app-1' },
        { ...mockTestResult, id: 'result-2', applicationId: 'app-2', applicationName: 'App 2' },
      ]);
      applicationsService.findAll.mockResolvedValue([
        mockApplication,
        { ...mockApplication, id: 'app-2', name: 'App 2' },
      ] as any);
      const request = {
        name: 'Test Report',
        format: 'json' as const,
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      const reportData = result.content as any;
      expect(reportData.testResults.byApplication).toHaveLength(2);
    });

    it('should generate recommendations', async () => {
      // Arrange
      riskScoringService.calculateRiskScores.mockResolvedValue([
        {
          testResultId: 'result-1',
          applicationId: 'app-1',
          applicationName: 'Test App',
          testConfigurationId: 'config-1',
          testConfigurationName: 'Test Config',
          testConfigurationType: 'access-control',
          riskScore: 85,
          severity: 'critical',
          businessImpact: 85,
          priority: 90,
          factors: [],
          recommendations: [],
          timestamp: new Date(),
          heatmapData: {} as any,
          trend: {} as any,
          priorityRank: 1,
        } as any,
      ]);
      testResultsService.query.mockResolvedValue([
        { ...mockTestResult, passed: false, status: 'failed' as const },
      ]);
      const request = {
        name: 'Test Report',
        format: 'json' as const,
        includeRiskScores: true,
      };

      // Act
      const result = await service.generateReport(request);

      // Assert
      const reportData = result.content as any;
      expect(reportData.recommendations).toBeDefined();
      expect(Array.isArray(reportData.recommendations)).toBe(true);
    });

    it('should handle errors gracefully', async () => {
      // Arrange
      testResultsService.query.mockRejectedValue(new Error('Database error'));
      const request = {
        name: 'Test Report',
        format: 'json' as const,
      };

      // Act & Assert
      await expect(service.generateReport(request)).rejects.toThrow('Database error');
    });
  });
});
