/**
 * Runs Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { RunsController } from './runs.controller';
import { RunsService } from './runs.service';

describe('RunsController', () => {
  let controller: RunsController;
  let runsService: jest.Mocked<RunsService>;

  const mockRun = {
    id: 'run-1',
    batteryId: 'battery-1',
    applicationId: 'app-1',
    status: 'completed',
    startedAt: new Date(),
    completedAt: new Date(),
  };

  beforeEach(async () => {
    const mockRunsService = {
      findAll: jest.fn(),
      findOne: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [RunsController],
      providers: [
        {
          provide: RunsService,
          useValue: mockRunsService,
        },
      ],
    }).compile();

    controller = module.get<RunsController>(RunsController);
    runsService = module.get(RunsService) as jest.Mocked<RunsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findAll', () => {
    it('should find all runs', async () => {
      // Arrange
      runsService.findAll.mockResolvedValue([mockRun]);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([mockRun]);
      expect(runsService.findAll).toHaveBeenCalledWith({
        applicationId: undefined,
        batteryId: undefined,
        startDate: undefined,
        endDate: undefined,
        limit: undefined,
      });
    });

    it('should find runs with filters', async () => {
      // Arrange
      runsService.findAll.mockResolvedValue([mockRun]);

      // Act
      const result = await controller.findAll('app-1', 'battery-1', '2024-01-01', '2024-12-31', '10');

      // Assert
      expect(result).toEqual([mockRun]);
      expect(runsService.findAll).toHaveBeenCalledWith({
        applicationId: 'app-1',
        batteryId: 'battery-1',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
        limit: 10,
      });
    });
  });

  describe('findOne', () => {
    it('should find one run', async () => {
      // Arrange
      runsService.findOne.mockResolvedValue(mockRun);

      // Act
      const result = await controller.findOne('run-1');

      // Assert
      expect(result).toEqual(mockRun);
      expect(runsService.findOne).toHaveBeenCalledWith('run-1');
    });
  });
});
