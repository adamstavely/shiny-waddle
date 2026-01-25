/**
 * Data Pipeline Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { DataPipelineService } from './data-pipeline.service';
import { ApplicationsService } from '../applications/applications.service';
import { ApplicationEntity } from '../applications/entities/application.entity';

describe('DataPipelineService', () => {
  let service: DataPipelineService;
  let applicationsService: jest.Mocked<ApplicationsService>;

  const mockApplication: ApplicationEntity = {
    id: 'app-1',
    name: 'Test App',
    infrastructure: {
      dataPipeline: {
        pipelineType: 'etl',
        connection: { host: 'localhost', port: 5432 },
        dataSource: { type: 'postgres', database: 'source' },
        dataDestination: { type: 's3', bucket: 'dest' },
      },
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockApplicationsService = {
      findOne: jest.fn().mockResolvedValue(mockApplication),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DataPipelineService,
        {
          provide: ApplicationsService,
          useValue: mockApplicationsService,
        },
      ],
    }).compile();

    service = module.get<DataPipelineService>(DataPipelineService);
    applicationsService = module.get(ApplicationsService) as jest.Mocked<ApplicationsService>;
  });

  describe('runTest', () => {
    it('should successfully run ETL pipeline test', async () => {
      // Act
      const result = await service.runTest('app-1');

      // Assert
      expect(result).toBeDefined();
      expect(result.testType).toBe('data-pipeline');
      expect(result.details).toBeDefined();
      expect(result.details.applicationId).toBe('app-1');
      expect(result.details.pipelineType).toBe('etl');
    });

    it('should throw NotFoundException when application has no data pipeline infrastructure', async () => {
      // Arrange
      applicationsService.findOne.mockResolvedValue({
        ...mockApplication,
        infrastructure: {},
      } as any);

      // Act & Assert
      await expect(
        service.runTest('app-1')
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when application not found', async () => {
      // Arrange
      applicationsService.findOne.mockRejectedValue(new NotFoundException('Application not found'));

      // Act & Assert
      await expect(
        service.runTest('non-existent-app')
      ).rejects.toThrow(NotFoundException);
    });

    it('should include context in result when provided', async () => {
      // Arrange
      const context = {
        buildId: 'build-123',
        runId: 'run-456',
        commitSha: 'abc123',
        branch: 'main',
      };

      // Act
      const result = await service.runTest('app-1', context);

      // Assert
      expect(result.buildId).toBe(context.buildId);
      expect(result.runId).toBe(context.runId);
      expect(result.commitSha).toBe(context.commitSha);
      expect(result.branch).toBe(context.branch);
    });

    it('should handle streaming pipeline type', async () => {
      // Arrange
      applicationsService.findOne.mockResolvedValue({
        ...mockApplication,
        infrastructure: {
          dataPipeline: {
            ...mockApplication.infrastructure!.dataPipeline!,
            pipelineType: 'streaming',
          },
        },
      } as any);

      // Act
      const result = await service.runTest('app-1');

      // Assert
      expect(result.details.pipelineType).toBe('streaming');
    });

    it('should handle batch pipeline type', async () => {
      // Arrange
      applicationsService.findOne.mockResolvedValue({
        ...mockApplication,
        infrastructure: {
          dataPipeline: {
            ...mockApplication.infrastructure!.dataPipeline!,
            pipelineType: 'batch',
          },
        },
      } as any);

      // Act
      const result = await service.runTest('app-1');

      // Assert
      expect(result.details.pipelineType).toBe('batch');
    });

    it('should handle real-time pipeline type', async () => {
      // Arrange
      applicationsService.findOne.mockResolvedValue({
        ...mockApplication,
        infrastructure: {
          dataPipeline: {
            ...mockApplication.infrastructure!.dataPipeline!,
            pipelineType: 'real-time',
          },
        },
      } as any);

      // Act
      const result = await service.runTest('app-1');

      // Assert
      expect(result.details.pipelineType).toBe('real-time');
    });

    it('should handle errors gracefully', async () => {
      // Arrange
      applicationsService.findOne.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(
        service.runTest('app-1')
      ).rejects.toThrow();
    });
  });
});
