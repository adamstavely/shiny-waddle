/**
 * Distributed Systems Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DistributedSystemsService, DistributedTestRequest, RegionConfig } from './distributed-systems.service';
import { ApplicationsService } from '../applications/applications.service';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');

describe('DistributedSystemsService', () => {
  let service: DistributedSystemsService;
  let applicationsService: jest.Mocked<ApplicationsService>;

  const mockRegion: RegionConfig = {
    id: 'region-1',
    name: 'US East',
    endpoint: 'https://us-east.example.com',
    latency: 50,
  };

  const mockApplication = {
    id: 'app-1',
    name: 'Test App',
    infrastructure: {
      distributedSystems: {
        regions: [mockRegion],
      },
    },
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockApplicationsService = {
      findOne: jest.fn().mockResolvedValue(mockApplication),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DistributedSystemsService,
        {
          provide: ApplicationsService,
          useValue: mockApplicationsService,
        },
      ],
    }).compile();

    service = module.get<DistributedSystemsService>(DistributedSystemsService);
    applicationsService = module.get(ApplicationsService) as jest.Mocked<ApplicationsService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify({ regions: [], testResults: [] }));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear data
    (service as any).regions = [];
    (service as any).testResults = [];
    
    // Mock loadConfig to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadConfig').mockResolvedValue(undefined);
  });

  describe('getRegions', () => {
    beforeEach(() => {
      (service as any).regions = [mockRegion];
    });

    it('should return all regions', async () => {
      // Act
      const result = await service.getRegions();

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].id).toBe('region-1');
    });
  });

  describe('getRegion', () => {
    beforeEach(() => {
      (service as any).regions = [mockRegion];
    });

    it('should return region when found', async () => {
      // Act
      const result = await service.getRegion('region-1');

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe('region-1');
      expect(result?.name).toBe('US East');
    });

    it('should return null when region not found', async () => {
      // Act
      const result = await service.getRegion('non-existent-region');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('createRegion', () => {
    beforeEach(() => {
      (service as any).regions = [];
    });

    it('should successfully create a region', async () => {
      // Act
      const result = await service.createRegion(mockRegion);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockRegion.id);
      expect((service as any).regions.length).toBe(1);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });
  });

  describe('updateRegion', () => {
    beforeEach(() => {
      (service as any).regions = [{ ...mockRegion }];
    });

    it('should successfully update a region', async () => {
      // Act
      const result = await service.updateRegion('region-1', { name: 'Updated Region' });

      // Assert
      expect(result.name).toBe('Updated Region');
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw error when region not found', async () => {
      // Act & Assert
      await expect(
        service.updateRegion('non-existent-region', { name: 'Updated' })
      ).rejects.toThrow('Region not found');
    });
  });

  describe('deleteRegion', () => {
    beforeEach(() => {
      (service as any).regions = [{ ...mockRegion }];
    });

    it('should successfully delete a region', async () => {
      // Act
      await service.deleteRegion('region-1');

      // Assert
      expect((service as any).regions.find((r: RegionConfig) => r.id === 'region-1')).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw error when region not found', async () => {
      // Act & Assert
      await expect(
        service.deleteRegion('non-existent-region')
      ).rejects.toThrow('Region not found');
    });
  });

  describe('runTest', () => {
    beforeEach(() => {
      (service as any).regions = [mockRegion];
    });

    it('should run distributed test', async () => {
      // Arrange
      const request: DistributedTestRequest = {
        name: 'Test Policy Consistency',
        testType: 'policy-consistency',
        applicationId: 'app-1',
      };

      // Act
      const result = await service.runTest(request);

      // Assert
      expect(result).toBeDefined();
      expect(result.testName).toBe(request.name);
      expect(result.distributedTestType).toBe(request.testType);
      expect(result.testType).toBe('distributed-systems');
      expect(result.regionResults).toBeDefined();
      expect(result.regionResults.length).toBeGreaterThan(0);
    });

    it('should use application regions when applicationId provided', async () => {
      // Arrange
      const request: DistributedTestRequest = {
        name: 'Test',
        testType: 'multi-region',
        applicationId: 'app-1',
      };

      // Act
      const result = await service.runTest(request);

      // Assert
      expect(applicationsService.findOne).toHaveBeenCalledWith('app-1');
      expect(result.regionResults.length).toBeGreaterThan(0);
    });

    it('should use default regions when applicationId not provided', async () => {
      // Arrange
      (service as any).regions = [mockRegion];
      const request: DistributedTestRequest = {
        name: 'Test',
        testType: 'multi-region',
      };

      // Act
      const result = await service.runTest(request);

      // Assert
      expect(result.regionResults.length).toBe(1);
    });

    it('should throw error when no regions configured', async () => {
      // Arrange
      (service as any).regions = [];
      applicationsService.findOne.mockResolvedValue({
        ...mockApplication,
        infrastructure: {},
      } as any);
      const request: DistributedTestRequest = {
        name: 'Test',
        testType: 'multi-region',
        applicationId: 'app-1',
      };

      // Act & Assert
      await expect(
        service.runTest(request)
      ).rejects.toThrow('No regions configured');
    });

    it('should include consistency check in result', async () => {
      // Arrange
      const request: DistributedTestRequest = {
        name: 'Test',
        testType: 'eventual-consistency',
      };

      // Act
      const result = await service.runTest(request);

      // Assert
      expect(result.consistencyCheck).toBeDefined();
      expect(result.consistencyCheck.consistent).toBeDefined();
    });
  });
});
