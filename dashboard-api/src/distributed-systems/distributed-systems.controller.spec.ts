/**
 * Distributed Systems Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DistributedSystemsController } from './distributed-systems.controller';
import { DistributedSystemsService } from './distributed-systems.service';
import { DistributedTestRequest } from './distributed-systems.service';

describe('DistributedSystemsController', () => {
  let controller: DistributedSystemsController;
  let service: jest.Mocked<DistributedSystemsService>;

  const mockTestRequest: DistributedTestRequest = {
    name: 'Test Policy Consistency',
    testType: 'policy-consistency',
    applicationId: 'app-1',
  };

  const mockTestResult = {
    id: 'test-1',
    testName: 'Test Policy Consistency',
    distributedTestType: 'policy-consistency',
    testType: 'distributed-systems',
    passed: true,
    timestamp: new Date(),
    regionResults: [],
    consistencyCheck: { consistent: true, inconsistencies: [] },
  };

  beforeEach(async () => {
    const mockService = {
      runTest: jest.fn().mockResolvedValue(mockTestResult),
      getRegions: jest.fn().mockResolvedValue([]),
      getRegion: jest.fn().mockResolvedValue(null),
      createRegion: jest.fn().mockResolvedValue({} as any),
      updateRegion: jest.fn().mockResolvedValue({} as any),
      deleteRegion: jest.fn().mockResolvedValue(undefined),
      getTestResults: jest.fn().mockResolvedValue([]),
      getTestResult: jest.fn().mockResolvedValue(null),
      deleteTestResult: jest.fn().mockResolvedValue(undefined),
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

  describe('runTest', () => {
    it('should call service.runTest with test request', async () => {
      // Act
      await controller.runTest(mockTestRequest);

      // Assert
      expect(service.runTest).toHaveBeenCalledWith(mockTestRequest);
      expect(service.runTest).toHaveBeenCalledTimes(1);
    });

    it('should return test result', async () => {
      // Act
      const result = await controller.runTest(mockTestRequest);

      // Assert
      expect(result).toEqual(mockTestResult);
    });
  });

  describe('getRegions', () => {
    it('should call service.getRegions', async () => {
      // Act
      await controller.getRegions();

      // Assert
      expect(service.getRegions).toHaveBeenCalledTimes(1);
    });
  });

  describe('getRegion', () => {
    it('should call service.getRegion with id', async () => {
      // Arrange
      const mockRegion = { id: 'region-1', name: 'Test Region' };
      service.getRegion.mockResolvedValue(mockRegion as any);

      // Act
      await controller.getRegion('region-1');

      // Assert
      expect(service.getRegion).toHaveBeenCalledWith('region-1');
    });

    it('should throw HttpException when region not found', async () => {
      // Arrange
      service.getRegion.mockResolvedValue(null);

      // Act & Assert
      await expect(
        controller.getRegion('non-existent-id')
      ).rejects.toThrow();
    });
  });
});
