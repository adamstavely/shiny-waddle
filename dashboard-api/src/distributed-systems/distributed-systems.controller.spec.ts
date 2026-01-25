/**
 * Distributed Systems Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, HttpException } from '@nestjs/common';
import { DistributedSystemsController } from './distributed-systems.controller';
import { DistributedSystemsService, RegionConfig, DistributedTestRequest } from './distributed-systems.service';

describe('DistributedSystemsController', () => {
  let controller: DistributedSystemsController;
  let service: jest.Mocked<DistributedSystemsService>;

  const mockRegion: RegionConfig = {
    id: 'region-1',
    name: 'US East',
    endpoint: 'https://us-east.example.com',
    pdpEndpoint: 'https://us-east.example.com/pdp',
    timezone: 'America/New_York',
    latency: 50,
    credentials: {
      apiKey: 'test-key',
    },
  };

  const mockTestRequest: DistributedTestRequest = {
    name: 'Test Policy Consistency',
    testType: 'policy-consistency',
    user: { id: 'user-1' },
    resource: { id: 'resource-1' },
    action: 'read',
    regions: ['region-1', 'region-2'],
    timeout: 5000,
    applicationId: 'app-1',
  };

  const mockTestResult = {
    id: 'test-result-1',
    testName: 'Test Policy Consistency',
    distributedTestType: 'policy-consistency',
    testType: 'distributed-systems',
    passed: true,
    timestamp: new Date(),
    regionResults: [
      {
        regionId: 'region-1',
        regionName: 'US East',
        allowed: true,
        decision: { effect: 'allow', reason: 'Policy evaluation' },
        latency: 50,
        timestamp: new Date(),
      },
    ],
    consistencyCheck: {
      consistent: true,
      inconsistencies: [],
    },
    performanceMetrics: {
      totalTime: 200,
      averageLatency: 50,
      slowestRegion: 'US East',
      fastestRegion: 'US East',
    },
  };

  beforeEach(async () => {
    const mockService = {
      getRegions: jest.fn(),
      getRegion: jest.fn(),
      createRegion: jest.fn(),
      updateRegion: jest.fn(),
      deleteRegion: jest.fn(),
      getTestResults: jest.fn(),
      getTestResult: jest.fn(),
      runTest: jest.fn(),
      deleteTestResult: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DistributedSystemsController],
      providers: [
        {
          provide: DistributedSystemsService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<DistributedSystemsController>(DistributedSystemsController);
    service = module.get(DistributedSystemsService) as jest.Mocked<DistributedSystemsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getRegions', () => {
    it('should return all regions', async () => {
      // Arrange
      const regions = [mockRegion];
      service.getRegions.mockResolvedValue(regions);

      // Act
      const result = await controller.getRegions();

      // Assert
      expect(result).toEqual(regions);
      expect(service.getRegions).toHaveBeenCalledTimes(1);
      expect(service.getRegions).toHaveBeenCalledWith();
    });

    it('should return empty array when no regions exist', async () => {
      // Arrange
      service.getRegions.mockResolvedValue([]);

      // Act
      const result = await controller.getRegions();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getRegion', () => {
    it('should return a region by id', async () => {
      // Arrange
      const regionId = 'region-1';
      service.getRegion.mockResolvedValue(mockRegion);

      // Act
      const result = await controller.getRegion(regionId);

      // Assert
      expect(result).toEqual(mockRegion);
      expect(service.getRegion).toHaveBeenCalledTimes(1);
      expect(service.getRegion).toHaveBeenCalledWith(regionId);
    });

    it('should throw HttpException when region not found', async () => {
      // Arrange
      const regionId = 'non-existent';
      service.getRegion.mockResolvedValue(null);

      // Act & Assert
      await expect(controller.getRegion(regionId)).rejects.toThrow(HttpException);
      await expect(controller.getRegion(regionId)).rejects.toThrow('Region not found');
      const error = await controller.getRegion(regionId).catch(e => e);
      expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
    });
  });

  describe('createRegion', () => {
    it('should create a new region', async () => {
      // Arrange
      service.createRegion.mockResolvedValue(mockRegion);

      // Act
      const result = await controller.createRegion(mockRegion);

      // Assert
      expect(result).toEqual(mockRegion);
      expect(service.createRegion).toHaveBeenCalledTimes(1);
      expect(service.createRegion).toHaveBeenCalledWith(mockRegion);
    });
  });

  describe('updateRegion', () => {
    it('should update an existing region', async () => {
      // Arrange
      const regionId = 'region-1';
      const updates = { name: 'Updated Region Name' };
      const updatedRegion = { ...mockRegion, ...updates };
      service.updateRegion.mockResolvedValue(updatedRegion);

      // Act
      const result = await controller.updateRegion(regionId, updates);

      // Assert
      expect(result).toEqual(updatedRegion);
      expect(service.updateRegion).toHaveBeenCalledTimes(1);
      expect(service.updateRegion).toHaveBeenCalledWith(regionId, updates);
    });

    it('should throw error when region not found', async () => {
      // Arrange
      const regionId = 'non-existent';
      const updates = { name: 'Updated Name' };
      service.updateRegion.mockRejectedValue(new Error('Region not found'));

      // Act & Assert
      await expect(controller.updateRegion(regionId, updates)).rejects.toThrow('Region not found');
    });
  });

  describe('deleteRegion', () => {
    it('should delete a region', async () => {
      // Arrange
      const regionId = 'region-1';
      service.deleteRegion.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteRegion(regionId);

      // Assert
      expect(result).toEqual({ success: true });
      expect(service.deleteRegion).toHaveBeenCalledTimes(1);
      expect(service.deleteRegion).toHaveBeenCalledWith(regionId);
    });

    it('should throw error when region not found', async () => {
      // Arrange
      const regionId = 'non-existent';
      service.deleteRegion.mockRejectedValue(new Error('Region not found'));

      // Act & Assert
      await expect(controller.deleteRegion(regionId)).rejects.toThrow('Region not found');
    });
  });

  describe('getTestResults', () => {
    it('should return all test results', async () => {
      // Arrange
      const testResults = [mockTestResult];
      service.getTestResults.mockResolvedValue(testResults);

      // Act
      const result = await controller.getTestResults();

      // Assert
      expect(result).toEqual(testResults);
      expect(service.getTestResults).toHaveBeenCalledTimes(1);
      expect(service.getTestResults).toHaveBeenCalledWith();
    });

    it('should return empty array when no test results exist', async () => {
      // Arrange
      service.getTestResults.mockResolvedValue([]);

      // Act
      const result = await controller.getTestResults();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getTestResult', () => {
    it('should return a test result by id', async () => {
      // Arrange
      const testId = 'test-result-1';
      service.getTestResult.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.getTestResult(testId);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(service.getTestResult).toHaveBeenCalledTimes(1);
      expect(service.getTestResult).toHaveBeenCalledWith(testId);
    });

    it('should throw HttpException when test result not found', async () => {
      // Arrange
      const testId = 'non-existent';
      service.getTestResult.mockResolvedValue(null);

      // Act & Assert
      await expect(controller.getTestResult(testId)).rejects.toThrow(HttpException);
      await expect(controller.getTestResult(testId)).rejects.toThrow('Test result not found');
      const error = await controller.getTestResult(testId).catch(e => e);
      expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
    });
  });

  describe('runTest', () => {
    it('should run a distributed test', async () => {
      // Arrange
      service.runTest.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.runTest(mockTestRequest);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(service.runTest).toHaveBeenCalledTimes(1);
      expect(service.runTest).toHaveBeenCalledWith(mockTestRequest);
    });

    it('should handle test request without optional fields', async () => {
      // Arrange
      const minimalRequest: DistributedTestRequest = {
        name: 'Minimal Test',
        testType: 'policy-consistency',
      };
      service.runTest.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.runTest(minimalRequest);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(service.runTest).toHaveBeenCalledWith(minimalRequest);
    });

    it('should throw error when test fails', async () => {
      // Arrange
      service.runTest.mockRejectedValue(new Error('No regions configured'));

      // Act & Assert
      await expect(controller.runTest(mockTestRequest)).rejects.toThrow('No regions configured');
    });
  });

  describe('deleteTestResult', () => {
    it('should delete a test result', async () => {
      // Arrange
      const testId = 'test-result-1';
      service.deleteTestResult.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteTestResult(testId);

      // Assert
      expect(result).toEqual({ success: true });
      expect(service.deleteTestResult).toHaveBeenCalledTimes(1);
      expect(service.deleteTestResult).toHaveBeenCalledWith(testId);
    });

    it('should throw error when test result not found', async () => {
      // Arrange
      const testId = 'non-existent';
      service.deleteTestResult.mockRejectedValue(new Error('Test result not found'));

      // Act & Assert
      await expect(controller.deleteTestResult(testId)).rejects.toThrow('Test result not found');
    });
  });
});
