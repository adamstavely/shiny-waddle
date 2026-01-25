/**
 * Test Results Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { TestResultsController } from './test-results.controller';
import { TestResultsService } from './test-results.service';
import { TestResultStatus } from './entities/test-result.entity';
import { TestConfigurationType } from '../test-configurations/entities/test-configuration.entity';

describe('TestResultsController', () => {
  let controller: TestResultsController;
  let testResultsService: jest.Mocked<TestResultsService>;

  const mockTestResult: any = {
    id: 'result-1',
    applicationId: 'app-1',
    applicationName: 'Test App',
    testConfigurationId: 'config-1',
    testConfigurationName: 'Test Config',
    testConfigurationType: 'api-security' as TestConfigurationType,
    status: 'failed' as TestResultStatus,
    passed: false,
    result: {},
    timestamp: new Date(),
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockTestResultsService = {
      query: jest.fn(),
      findById: jest.fn(),
      findByApplication: jest.fn(),
      findByTestConfiguration: jest.fn(),
      findByBuild: jest.fn(),
      getComplianceMetrics: jest.fn(),
      getTrends: jest.fn(),
      delete: jest.fn(),
      acceptRisk: jest.fn(),
      rejectRisk: jest.fn(),
      updateRemediation: jest.fn(),
      advancedQuery: jest.fn(),
      exportToCSV: jest.fn(),
      exportToJSON: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestResultsController],
      providers: [
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
      ],
    }).compile();

    controller = module.get<TestResultsController>(TestResultsController);
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('query', () => {
    it('should query test results', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.query();

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(testResultsService.query).toHaveBeenCalledWith({});
    });

    it('should query test results with filters', async () => {
      // Arrange
      testResultsService.query.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.query('app-1', 'config-1', 'harness-1', 'battery-1', 'build-1', 'main', 'failed', '2024-01-01', '2024-12-31', '10', '0');

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(testResultsService.query).toHaveBeenCalledWith({
        applicationId: 'app-1',
        testConfigurationId: 'config-1',
        testHarnessId: 'harness-1',
        testBatteryId: 'battery-1',
        buildId: 'build-1',
        branch: 'main',
        status: 'failed',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
        limit: 10,
        offset: 0,
      });
    });
  });

  describe('findOne', () => {
    it('should find one test result', async () => {
      // Arrange
      testResultsService.findById.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.findOne('result-1');

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(testResultsService.findById).toHaveBeenCalledWith('result-1');
    });
  });

  describe('findByApplication', () => {
    it('should find test results by application', async () => {
      // Arrange
      testResultsService.findByApplication.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.findByApplication('app-1');

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(testResultsService.findByApplication).toHaveBeenCalledWith('app-1', {
        status: undefined,
        branch: undefined,
        limit: undefined,
        offset: undefined,
      });
    });
  });

  describe('findByTestConfiguration', () => {
    it('should find test results by test configuration', async () => {
      // Arrange
      testResultsService.findByTestConfiguration.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.findByTestConfiguration('config-1');

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(testResultsService.findByTestConfiguration).toHaveBeenCalledWith('config-1', {
        status: undefined,
        branch: undefined,
        limit: undefined,
        offset: undefined,
      });
    });
  });

  describe('findByBuild', () => {
    it('should find test results by build', async () => {
      // Arrange
      testResultsService.findByBuild.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.findByBuild('build-1');

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(testResultsService.findByBuild).toHaveBeenCalledWith('build-1');
    });
  });

  describe('getComplianceMetrics', () => {
    it('should get compliance metrics', async () => {
      // Arrange
      const metrics = {
        period: {
          start: new Date('2024-01-01'),
          end: new Date('2024-12-31'),
        },
        overall: {
          totalTests: 100,
          passed: 85,
          failed: 15,
          partial: 0,
          errors: 0,
          passRate: 85,
          averageDuration: 1000,
          trend: 'stable' as const,
        },
        byTestConfiguration: {},
        failingTests: [],
      };
      testResultsService.getComplianceMetrics.mockResolvedValue(metrics as any);

      // Act
      const result = await controller.getComplianceMetrics();

      // Assert
      expect(result).toEqual(metrics);
      expect(testResultsService.getComplianceMetrics).toHaveBeenCalledWith(undefined, undefined, undefined);
    });
  });

  describe('getComplianceTrends', () => {
    it('should get compliance trends', async () => {
      // Arrange
      const trends = [{ period: '2024-01', passRate: 85, totalTests: 100 }];
      testResultsService.getTrends.mockResolvedValue(trends);

      // Act
      const result = await controller.getComplianceTrends();

      // Assert
      expect(result).toEqual(trends);
      expect(testResultsService.getTrends).toHaveBeenCalledWith(undefined, undefined, 'day');
    });
  });

  describe('delete', () => {
    it('should delete a test result', async () => {
      // Arrange
      testResultsService.delete.mockResolvedValue(undefined);

      // Act
      const result = await controller.delete('result-1');

      // Assert
      expect(result).toBeUndefined();
      expect(testResultsService.delete).toHaveBeenCalledWith('result-1');
    });
  });

  describe('acceptRisk', () => {
    it('should accept risk for a test result', async () => {
      // Arrange
      const updatedResult = { ...mockTestResult, riskAcceptance: { accepted: true } };
      testResultsService.acceptRisk.mockResolvedValue(updatedResult);

      // Act
      const result = await controller.acceptRisk('result-1', {
        reason: 'Business justification',
        approver: 'user-1',
      });

      // Assert
      expect(result).toEqual(updatedResult);
      expect(testResultsService.acceptRisk).toHaveBeenCalledWith('result-1', {
        reason: 'Business justification',
        approver: 'user-1',
        expirationDate: undefined,
        ticketLink: undefined,
      });
    });
  });

  describe('rejectRisk', () => {
    it('should reject risk for a test result', async () => {
      // Arrange
      const updatedResult = { ...mockTestResult, riskAcceptance: { accepted: false, rejected: true } };
      testResultsService.rejectRisk.mockResolvedValue(updatedResult);

      // Act
      const result = await controller.rejectRisk('result-1', {
        reason: 'Not acceptable',
        approver: 'user-1',
      });

      // Assert
      expect(result).toEqual(updatedResult);
      expect(testResultsService.rejectRisk).toHaveBeenCalledWith('result-1', {
        reason: 'Not acceptable',
        approver: 'user-1',
      });
    });
  });

  describe('updateRemediation', () => {
    it('should update remediation for a test result', async () => {
      // Arrange
      const updatedResult = { ...mockTestResult, remediation: { status: 'in-progress' as const } };
      testResultsService.updateRemediation.mockResolvedValue(updatedResult);

      // Act
      const result = await controller.updateRemediation('result-1', {
        status: 'in-progress',
        ticketLink: 'TICKET-123',
      });

      // Assert
      expect(result).toEqual(updatedResult);
      expect(testResultsService.updateRemediation).toHaveBeenCalledWith('result-1', {
        status: 'in-progress',
        ticketLink: 'TICKET-123',
        assignedTo: undefined,
        targetDate: undefined,
        notes: undefined,
        progress: undefined,
        steps: undefined,
      });
    });
  });

  describe('advancedQuery', () => {
    it('should perform advanced query', async () => {
      // Arrange
      testResultsService.advancedQuery.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.advancedQuery({
        searchText: 'test',
        filters: [],
        sort: [],
      });

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(testResultsService.advancedQuery).toHaveBeenCalledWith({
        searchText: 'test',
        filters: [],
        sort: [],
      });
    });
  });

  describe('exportCSV', () => {
    it('should export test results to CSV', async () => {
      // Arrange
      const csvData = 'id,status\nresult-1,failed';
      testResultsService.exportToCSV.mockResolvedValue(csvData);

      // Act
      const result = await controller.exportCSV();

      // Assert
      expect(result).toEqual({ format: 'csv', data: csvData });
      expect(testResultsService.exportToCSV).toHaveBeenCalledWith({
        applicationId: undefined,
        testConfigurationId: undefined,
        status: undefined,
        startDate: undefined,
        endDate: undefined,
        limit: undefined,
      });
    });
  });

  describe('exportJSON', () => {
    it('should export test results to JSON', async () => {
      // Arrange
      const jsonData = JSON.stringify([mockTestResult]);
      testResultsService.exportToJSON.mockResolvedValue(jsonData);

      // Act
      const result = await controller.exportJSON();

      // Assert
      expect(result.format).toBe('json');
      expect(Array.isArray(result.data)).toBe(true);
      expect(result.data.length).toBe(1);
      expect(testResultsService.exportToJSON).toHaveBeenCalledWith({
        applicationId: undefined,
        testConfigurationId: undefined,
        status: undefined,
        startDate: undefined,
        endDate: undefined,
        limit: undefined,
      });
    });
  });
});
