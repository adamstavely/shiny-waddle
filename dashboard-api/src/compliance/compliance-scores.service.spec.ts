/**
 * Compliance Scores Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ComplianceScoresService } from './compliance-scores.service';
import { UnifiedFindingsService } from '../unified-findings/unified-findings.service';
import { TestResultsService } from '../test-results/test-results.service';

describe('ComplianceScoresService', () => {
  let service: ComplianceScoresService;
  let unifiedFindingsService: jest.Mocked<UnifiedFindingsService>;
  let testResultsService: jest.Mocked<TestResultsService>;

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockUnifiedFindingsService = {
      getComplianceTrends: jest.fn().mockResolvedValue([
        { date: '2024-01-01', score: 85 },
        { date: '2024-01-02', score: 87 },
        { date: '2024-01-03', score: 90 },
      ]),
    };

    const mockTestResultsService = {
      query: jest.fn().mockResolvedValue([
        {
          id: 'result-1',
          applicationId: 'app-1',
          status: 'passed',
          timestamp: new Date('2024-01-01'),
        },
        {
          id: 'result-2',
          applicationId: 'app-1',
          status: 'failed',
          timestamp: new Date('2024-01-01'),
        },
        {
          id: 'result-3',
          applicationId: 'app-1',
          status: 'passed',
          timestamp: new Date('2024-01-02'),
        },
      ]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ComplianceScoresService,
        {
          provide: UnifiedFindingsService,
          useValue: mockUnifiedFindingsService,
        },
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
      ],
    }).compile();

    service = module.get<ComplianceScoresService>(ComplianceScoresService);
    unifiedFindingsService = module.get(UnifiedFindingsService) as jest.Mocked<UnifiedFindingsService>;
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;
  });

  describe('getHistory', () => {
    it('should return compliance score history', async () => {
      // Act
      const result = await service.getHistory({});

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
      expect(result[0]).toHaveProperty('date');
      expect(result[0]).toHaveProperty('score');
    });

    it('should filter by applicationId', async () => {
      // Act
      const result = await service.getHistory({ applicationId: 'app-1' });

      // Assert
      expect(unifiedFindingsService.getComplianceTrends).toHaveBeenCalledWith(
        30,
        ['app-1'],
        undefined
      );
      expect(result.every(r => r.applicationId === 'app-1')).toBe(true);
    });

    it('should filter by date range', async () => {
      // Arrange
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');

      // Act
      const result = await service.getHistory({ startDate, endDate });

      // Assert
      expect(result.every(r => {
        const date = new Date(r.date);
        return date >= startDate && date <= endDate;
      })).toBe(true);
    });

    it('should use default days when not provided', async () => {
      // Act
      await service.getHistory({});

      // Assert
      expect(unifiedFindingsService.getComplianceTrends).toHaveBeenCalledWith(
        30,
        undefined,
        undefined
      );
    });

    it('should fallback to test results when unified findings fails', async () => {
      // Arrange
      unifiedFindingsService.getComplianceTrends.mockRejectedValueOnce(new Error('Service unavailable'));

      // Act
      const result = await service.getHistory({ applicationId: 'app-1' });

      // Assert
      expect(testResultsService.query).toHaveBeenCalled();
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should filter by domain when provided', async () => {
      // Arrange
      unifiedFindingsService.getComplianceTrends.mockRejectedValueOnce(new Error('Service unavailable'));

      // Act
      const result = await service.getHistory({ domain: 'api-security' });

      // Assert
      expect(testResultsService.query).toHaveBeenCalled();
      expect(result).toBeDefined();
    });
  });
});
