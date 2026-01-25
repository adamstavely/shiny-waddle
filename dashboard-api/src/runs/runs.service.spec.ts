/**
 * Runs Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { RunsService } from './runs.service';
import { TestResultsService } from '../test-results/test-results.service';
import { TestBatteriesService } from '../test-batteries/test-batteries.service';
import { TestHarnessesService } from '../test-harnesses/test-harnesses.service';
import { TestSuitesService } from '../test-suites/test-suites.service';

// Mock dependencies
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('RunsService', () => {
  let service: RunsService;
  let testResultsService: jest.Mocked<TestResultsService>;
  let testBatteriesService: jest.Mocked<TestBatteriesService>;
  let testHarnessesService: jest.Mocked<TestHarnessesService>;
  let testSuitesService: jest.Mocked<TestSuitesService>;

  const mockResult: any = {
    id: 'result-1',
    runId: 'run-1',
    applicationId: 'app-1',
    applicationName: 'Test App',
    testConfigurationId: 'config-1',
    testConfigurationName: 'Test Config',
    testConfigurationType: 'access-control',
    status: 'passed',
    passed: true,
    timestamp: new Date(),
    createdAt: new Date(),
    result: {},
    metadata: {
      batteryId: 'battery-1',
      batteryName: 'Test Battery',
      harnessId: 'harness-1',
      harnessName: 'Test Harness',
    },
  };

  const mockBattery = {
    id: 'battery-1',
    name: 'Test Battery',
    harnessIds: ['harness-1'],
  };

  const mockHarness = {
    id: 'harness-1',
    name: 'Test Harness',
    testSuiteIds: ['suite-1'],
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockTestResultsService = {
      query: jest.fn().mockResolvedValue([mockResult]),
    };

    const mockTestBatteriesService = {
      findAll: jest.fn().mockResolvedValue([mockBattery]),
      findOne: jest.fn().mockResolvedValue(mockBattery),
    };

    const mockTestHarnessesService = {
      findAll: jest.fn().mockResolvedValue([mockHarness]),
      findOne: jest.fn().mockResolvedValue(mockHarness),
    };

    const mockTestSuitesService = {
      findAll: jest.fn().mockResolvedValue([]),
      findOne: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RunsService,
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
        {
          provide: TestBatteriesService,
          useValue: mockTestBatteriesService,
        },
        {
          provide: TestHarnessesService,
          useValue: mockTestHarnessesService,
        },
        {
          provide: TestSuitesService,
          useValue: mockTestSuitesService,
        },
      ],
    }).compile();

    service = module.get<RunsService>(RunsService);
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;
    testBatteriesService = module.get(TestBatteriesService) as jest.Mocked<TestBatteriesService>;
    testHarnessesService = module.get(TestHarnessesService) as jest.Mocked<TestHarnessesService>;
    testSuitesService = module.get(TestSuitesService) as jest.Mocked<TestSuitesService>;
  });

  describe('findAll', () => {
    it('should return all runs', async () => {
      // Act
      const result = await service.findAll({});

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(testResultsService.query).toHaveBeenCalled();
    });

    it('should filter by applicationId', async () => {
      // Act
      await service.findAll({ applicationId: 'app-1' });

      // Assert
      expect(testResultsService.query).toHaveBeenCalledWith(
        expect.objectContaining({ applicationId: 'app-1' })
      );
    });

    it('should filter by batteryId', async () => {
      // Act
      await service.findAll({ batteryId: 'battery-1' });

      // Assert
      expect(testBatteriesService.findOne).toHaveBeenCalledWith('battery-1');
    });

    it('should filter by date range', async () => {
      // Arrange
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');

      // Act
      await service.findAll({ startDate, endDate });

      // Assert
      expect(testResultsService.query).toHaveBeenCalledWith(
        expect.objectContaining({ startDate, endDate })
      );
    });

    it('should apply limit when provided', async () => {
      // Act
      await service.findAll({ limit: 10 });

      // Assert
      expect(testResultsService.query).toHaveBeenCalledWith(
        expect.objectContaining({ limit: 10 })
      );
    });

    it('should return empty array when query fails', async () => {
      // Arrange
      testResultsService.query.mockRejectedValueOnce(new Error('Query failed'));

      // Act
      const result = await service.findAll({});

      // Assert
      expect(result).toEqual([]);
    });

    it('should group results by runId', async () => {
      // Arrange
      testResultsService.query.mockResolvedValueOnce([
        { ...mockResult, id: 'result-1', runId: 'run-1' },
        { ...mockResult, id: 'result-2', runId: 'run-1' },
        { ...mockResult, id: 'result-3', runId: 'run-2' },
      ]);

      // Act
      const result = await service.findAll({});

      // Assert
      expect(result.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('findOne', () => {
    beforeEach(() => {
      testResultsService.query.mockResolvedValue([mockResult]);
    });

    it('should return run when found', async () => {
      // Act
      const result = await service.findOne('run-1');

      // Assert
      expect(result).toBeDefined();
      expect(testResultsService.query).toHaveBeenCalled();
    });

    it('should throw NotFoundException when run not found', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([]);

      // Act & Assert
      await expect(
        service.findOne('non-existent-run')
      ).rejects.toThrow(NotFoundException);
    });

    it('should find battery from metadata', async () => {
      // Act
      await service.findOne('run-1');

      // Assert
      expect(testBatteriesService.findOne).toHaveBeenCalledWith('battery-1');
    });

    it('should find battery from harness when not in metadata', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([
        {
          ...mockResult,
          metadata: { harnessId: 'harness-1' },
        },
      ]);

      // Act
      await service.findOne('run-1');

      // Assert
      expect(testBatteriesService.findAll).toHaveBeenCalled();
    });
  });
});
