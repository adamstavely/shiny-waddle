/**
 * Test Results Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { TestResultsService } from './test-results.service';
import { DashboardSSEGateway } from '../dashboard/dashboard-sse.gateway';
import { TestResultEntity, TestResultStatus } from './entities/test-result.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('TestResultsService', () => {
  let service: TestResultsService;
  let sseGateway: jest.Mocked<DashboardSSEGateway>;

  const mockResult: Omit<TestResultEntity, 'id' | 'createdAt'> = {
    applicationId: 'app-1',
    applicationName: 'Test App',
    testConfigurationId: 'config-1',
    testConfigurationName: 'Test Config',
    testConfigurationType: 'access-control' as any,
    status: 'passed' as TestResultStatus,
    passed: true,
    timestamp: new Date(),
    duration: 1000,
    branch: 'main',
    buildId: 'build-1',
    result: {},
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockSSEGateway = {
      broadcast: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TestResultsService,
        {
          provide: DashboardSSEGateway,
          useValue: mockSSEGateway,
        },
      ],
    }).compile();

    service = module.get<TestResultsService>(TestResultsService);
    sseGateway = module.get(DashboardSSEGateway) as jest.Mocked<DashboardSSEGateway>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear results
    (service as any).results = [];
  });

  describe('saveResult', () => {
    it('should successfully save a test result', async () => {
      // Arrange
      (service as any).results = [];

      // Act
      const result = await service.saveResult(mockResult);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.applicationId).toBe(mockResult.applicationId);
      expect(result.status).toBe(mockResult.status);
      expect(result.passed).toBe(mockResult.passed);
      expect(result.createdAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should add result to beginning of array (newest first)', async () => {
      // Arrange
      (service as any).results = [
        { ...mockResult, id: 'old-result', createdAt: new Date('2024-01-01') },
      ];

      // Act
      const newResult = await service.saveResult(mockResult);

      // Assert
      expect((service as any).results[0].id).toBe(newResult.id);
    });

    it('should broadcast SSE update when gateway is available', async () => {
      // Arrange
      (service as any).results = [];

      // Act
      await service.saveResult(mockResult);

      // Assert
      expect(sseGateway.broadcast).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'test-result',
          data: expect.objectContaining({
            applicationId: mockResult.applicationId,
            status: mockResult.status,
          }),
        })
      );
    });
  });

  describe('findById', () => {
    beforeEach(() => {
      (service as any).results = [
        { ...mockResult, id: 'result-1' },
        { ...mockResult, id: 'result-2' },
      ];
    });

    it('should return result when found', async () => {
      // Act
      const result = await service.findById('result-1');

      // Assert
      expect(result.id).toBe('result-1');
    });

    it('should throw NotFoundException when result not found', async () => {
      // Act & Assert
      await expect(
        service.findById('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('delete', () => {
    beforeEach(() => {
      (service as any).results = [{ ...mockResult, id: 'result-1' }];
      jest.spyOn(service as any, 'loadResults').mockResolvedValue(undefined);
    });

    it('should successfully delete a result', async () => {
      // Act
      await service.delete('result-1');

      // Assert
      expect((service as any).results.find((r: TestResultEntity) => r.id === 'result-1')).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when result not found', async () => {
      // Arrange
      (service as any).results = [];

      // Act & Assert
      await expect(
        service.delete('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('findByApplication', () => {
    beforeEach(() => {
      (service as any).results = [
        { ...mockResult, id: 'result-1', applicationId: 'app-1', status: 'passed' as TestResultStatus, timestamp: new Date('2024-01-01') },
        { ...mockResult, id: 'result-2', applicationId: 'app-1', status: 'failed' as TestResultStatus, timestamp: new Date('2024-01-02') },
        { ...mockResult, id: 'result-3', applicationId: 'app-2', status: 'passed' as TestResultStatus, timestamp: new Date('2024-01-03') },
      ];
    });

    it('should return all results for an application', async () => {
      // Act
      const result = await service.findByApplication('app-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(r => r.applicationId === 'app-1')).toBe(true);
    });

    it('should filter by status when provided', async () => {
      // Act
      const result = await service.findByApplication('app-1', { status: 'passed' });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].status).toBe('passed');
    });

    it('should filter by branch when provided', async () => {
      // Arrange
      (service as any).results[0].branch = 'main';
      (service as any).results[1].branch = 'develop';

      // Act
      const result = await service.findByApplication('app-1', { branch: 'main' });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].branch).toBe('main');
    });

    it('should sort by timestamp descending (newest first)', async () => {
      // Act
      const result = await service.findByApplication('app-1');

      // Assert
      expect(result[0].timestamp.getTime()).toBeGreaterThan(result[1].timestamp.getTime());
    });

    it('should apply pagination when limit is provided', async () => {
      // Act
      const result = await service.findByApplication('app-1', { limit: 1 });

      // Assert
      expect(result.length).toBe(1);
    });
  });

  describe('findByTestConfiguration', () => {
    beforeEach(() => {
      (service as any).results = [
        { ...mockResult, id: 'result-1', testConfigurationId: 'config-1', timestamp: new Date('2024-01-01') },
        { ...mockResult, id: 'result-2', testConfigurationId: 'config-1', timestamp: new Date('2024-01-02') },
        { ...mockResult, id: 'result-3', testConfigurationId: 'config-2', timestamp: new Date('2024-01-03') },
      ];
    });

    it('should return all results for a test configuration', async () => {
      // Act
      const result = await service.findByTestConfiguration('config-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(r => r.testConfigurationId === 'config-1')).toBe(true);
    });

    it('should filter by status when provided', async () => {
      // Arrange
      (service as any).results[0].status = 'passed';
      (service as any).results[1].status = 'failed';

      // Act
      const result = await service.findByTestConfiguration('config-1', { status: 'passed' });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].status).toBe('passed');
    });
  });

  describe('findByBuild', () => {
    beforeEach(() => {
      (service as any).results = [
        { ...mockResult, id: 'result-1', buildId: 'build-1', timestamp: new Date('2024-01-01') },
        { ...mockResult, id: 'result-2', buildId: 'build-1', timestamp: new Date('2024-01-02') },
        { ...mockResult, id: 'result-3', buildId: 'build-2', timestamp: new Date('2024-01-03') },
      ];
    });

    it('should return all results for a build', async () => {
      // Act
      const result = await service.findByBuild('build-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(r => r.buildId === 'build-1')).toBe(true);
    });

    it('should sort by timestamp descending', async () => {
      // Act
      const result = await service.findByBuild('build-1');

      // Assert
      expect(result[0].timestamp.getTime()).toBeGreaterThan(result[1].timestamp.getTime());
    });
  });

  describe('getLatestResult', () => {
    beforeEach(() => {
      (service as any).results = [
        { ...mockResult, id: 'result-1', applicationId: 'app-1', testConfigurationId: 'config-1', timestamp: new Date('2024-01-01') },
        { ...mockResult, id: 'result-2', applicationId: 'app-1', testConfigurationId: 'config-1', timestamp: new Date('2024-01-02') },
        { ...mockResult, id: 'result-3', applicationId: 'app-1', testConfigurationId: 'config-2', timestamp: new Date('2024-01-03') },
      ];
    });

    it('should return the latest result for app and config', async () => {
      // Act
      const result = await service.getLatestResult('app-1', 'config-1');

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe('result-2');
      expect(result?.applicationId).toBe('app-1');
      expect(result?.testConfigurationId).toBe('config-1');
    });

    it('should return null when no results found', async () => {
      // Act
      const result = await service.getLatestResult('app-999', 'config-999');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('getComplianceMetrics', () => {
    beforeEach(() => {
      (service as any).results = [
        { ...mockResult, id: 'result-1', applicationId: 'app-1', status: 'passed' as TestResultStatus, duration: 1000, timestamp: new Date('2024-01-01') },
        { ...mockResult, id: 'result-2', applicationId: 'app-1', status: 'failed' as TestResultStatus, duration: 2000, timestamp: new Date('2024-01-02') },
        { ...mockResult, id: 'result-3', applicationId: 'app-1', status: 'passed' as TestResultStatus, duration: 1500, timestamp: new Date('2024-01-03') },
      ];
    });

    it('should calculate compliance metrics', async () => {
      // Act
      const metrics = await service.getComplianceMetrics('app-1');

      // Assert
      expect(metrics.overall.totalTests).toBe(3);
      expect(metrics.overall.passed).toBe(2);
      expect(metrics.overall.failed).toBe(1);
      expect(metrics.overall.passRate).toBeCloseTo(66.67, 1);
      expect(metrics.overall.averageDuration).toBeCloseTo(1500, 0);
    });

    it('should filter by date range when provided', async () => {
      // Act
      const metrics = await service.getComplianceMetrics('app-1', undefined, {
        start: new Date('2024-01-02'),
        end: new Date('2024-01-03'),
      });

      // Assert
      expect(metrics.overall.totalTests).toBe(2);
    });
  });
});
