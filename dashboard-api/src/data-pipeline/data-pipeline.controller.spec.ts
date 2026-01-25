/**
 * Data Pipeline Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DataPipelineController } from './data-pipeline.controller';
import { DataPipelineService } from './data-pipeline.service';

describe('DataPipelineController', () => {
  let controller: DataPipelineController;
  let service: jest.Mocked<DataPipelineService>;

  const mockTestResult = {
    passed: true,
    testType: 'data-pipeline',
    testName: 'Data Pipeline Test: Test App',
    timestamp: new Date(),
    details: {
      applicationId: 'app-1',
      applicationName: 'Test App',
      pipelineType: 'etl',
    },
  };

  const mockContext = {
    buildId: 'build-123',
    runId: 'run-456',
    commitSha: 'abc123',
    branch: 'main',
  };

  beforeEach(async () => {
    const mockService = {
      runTest: jest.fn().mockResolvedValue(mockTestResult),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DataPipelineController],
      providers: [
        {
          provide: DataPipelineService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<DataPipelineController>(DataPipelineController);
    service = module.get(DataPipelineService) as jest.Mocked<DataPipelineService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('runTest', () => {
    it('should call service.runTest with applicationId', async () => {
      // Act
      await controller.runTest('app-1', undefined);

      // Assert
      expect(service.runTest).toHaveBeenCalledWith('app-1', undefined);
      expect(service.runTest).toHaveBeenCalledTimes(1);
    });

    it('should call service.runTest with applicationId and context', async () => {
      // Act
      await controller.runTest('app-1', mockContext);

      // Assert
      expect(service.runTest).toHaveBeenCalledWith('app-1', mockContext);
    });

    it('should return test result', async () => {
      // Act
      const result = await controller.runTest('app-1', undefined);

      // Assert
      expect(result).toEqual(mockTestResult);
    });

    it('should pass context to service', async () => {
      // Act
      await controller.runTest('app-1', mockContext);

      // Assert
      expect(service.runTest).toHaveBeenCalledWith('app-1', mockContext);
    });
  });
});
