/**
 * Test Batteries Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { TestBatteriesController } from './test-batteries.controller';
import { TestBatteriesService } from './test-batteries.service';
import { CreateTestBatteryDto } from './dto/create-test-battery.dto';
import { UpdateTestBatteryDto } from './dto/update-test-battery.dto';
import { TestBatteryEntity } from './entities/test-battery.entity';

describe('TestBatteriesController', () => {
  let controller: TestBatteriesController;
  let testBatteriesService: jest.Mocked<TestBatteriesService>;

  const mockTestBattery: TestBatteryEntity = {
    id: 'battery-1',
    name: 'Test Battery',
    description: 'Test battery description',
    harnessIds: ['harness-1', 'harness-2'],
    team: 'team-1',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTestBatteries: TestBatteryEntity[] = [
    mockTestBattery,
    {
      ...mockTestBattery,
      id: 'battery-2',
      name: 'Another Battery',
    },
  ];

  beforeEach(async () => {
    const mockTestBatteriesService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      addHarness: jest.fn(),
      removeHarness: jest.fn(),
      getAssignedApplications: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestBatteriesController],
      providers: [
        {
          provide: TestBatteriesService,
          useValue: mockTestBatteriesService,
        },
      ],
    }).compile();

    controller = module.get<TestBatteriesController>(TestBatteriesController);
    testBatteriesService = module.get(TestBatteriesService) as jest.Mocked<TestBatteriesService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    const createTestBatteryDto: CreateTestBatteryDto = {
      name: 'New Test Battery',
      description: 'New battery description',
      harnessIds: ['harness-1'],
    };

    it('should create a test battery successfully', async () => {
      // Arrange
      testBatteriesService.create.mockResolvedValue(mockTestBattery);

      // Act
      const result = await controller.create(createTestBatteryDto);

      // Assert
      expect(result).toEqual(mockTestBattery);
      expect(testBatteriesService.create).toHaveBeenCalledTimes(1);
      expect(testBatteriesService.create).toHaveBeenCalledWith(createTestBatteryDto);
    });
  });

  describe('findAll', () => {
    it('should return all test batteries when no filters provided', async () => {
      // Arrange
      testBatteriesService.findAll.mockResolvedValue(mockTestBatteries);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual(mockTestBatteries);
      expect(testBatteriesService.findAll).toHaveBeenCalledTimes(1);
    });

    it('should filter by domain (simplified - returns all)', async () => {
      // Arrange
      testBatteriesService.findAll.mockResolvedValue(mockTestBatteries);

      // Act
      const result = await controller.findAll('identity');

      // Assert
      // Note: Domain filtering is simplified in controller - returns all
      expect(result).toEqual(mockTestBatteries);
      expect(testBatteriesService.findAll).toHaveBeenCalledTimes(1);
    });

    it('should return empty array when no batteries found', async () => {
      // Arrange
      testBatteriesService.findAll.mockResolvedValue([]);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return a test battery by id', async () => {
      // Arrange
      testBatteriesService.findOne.mockResolvedValue(mockTestBattery);

      // Act
      const result = await controller.findOne('battery-1');

      // Assert
      expect(result).toEqual(mockTestBattery);
      expect(testBatteriesService.findOne).toHaveBeenCalledTimes(1);
      expect(testBatteriesService.findOne).toHaveBeenCalledWith('battery-1');
    });

    it('should propagate NotFoundException when battery not found', async () => {
      // Arrange
      testBatteriesService.findOne.mockRejectedValue(new NotFoundException('Test battery not found'));

      // Act & Assert
      await expect(controller.findOne('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateTestBatteryDto: UpdateTestBatteryDto = {
      name: 'Updated Battery',
      description: 'Updated description',
    };

    it('should update a test battery successfully', async () => {
      // Arrange
      const updatedBattery = { ...mockTestBattery, ...updateTestBatteryDto };
      testBatteriesService.update.mockResolvedValue(updatedBattery);

      // Act
      const result = await controller.update('battery-1', updateTestBatteryDto);

      // Assert
      expect(result).toEqual(updatedBattery);
      expect(testBatteriesService.update).toHaveBeenCalledTimes(1);
      expect(testBatteriesService.update).toHaveBeenCalledWith('battery-1', updateTestBatteryDto);
    });
  });

  describe('delete', () => {
    it('should delete a test battery successfully', async () => {
      // Arrange
      testBatteriesService.delete.mockResolvedValue(undefined);

      // Act
      await controller.delete('battery-1');

      // Assert
      expect(testBatteriesService.delete).toHaveBeenCalledTimes(1);
      expect(testBatteriesService.delete).toHaveBeenCalledWith('battery-1');
    });
  });

  describe('addHarness', () => {
    it('should add a harness to a battery', async () => {
      // Arrange
      const updatedBattery = {
        ...mockTestBattery,
        harnessIds: [...mockTestBattery.harnessIds, 'harness-3'],
      };
      testBatteriesService.addHarness.mockResolvedValue(updatedBattery);

      // Act
      const result = await controller.addHarness('battery-1', 'harness-3');

      // Assert
      expect(result).toEqual(updatedBattery);
      expect(testBatteriesService.addHarness).toHaveBeenCalledTimes(1);
      expect(testBatteriesService.addHarness).toHaveBeenCalledWith('battery-1', 'harness-3');
    });
  });

  describe('removeHarness', () => {
    it('should remove a harness from a battery', async () => {
      // Arrange
      const updatedBattery = {
        ...mockTestBattery,
        harnessIds: ['harness-1'],
      };
      testBatteriesService.removeHarness.mockResolvedValue(updatedBattery);

      // Act
      const result = await controller.removeHarness('battery-1', 'harness-2');

      // Assert
      expect(result).toEqual(updatedBattery);
      expect(testBatteriesService.removeHarness).toHaveBeenCalledTimes(1);
      expect(testBatteriesService.removeHarness).toHaveBeenCalledWith('battery-1', 'harness-2');
    });
  });

  describe('getAssignedApplications', () => {
    const mockApplications = [
      { id: 'app-1', name: 'Application 1' },
      { id: 'app-2', name: 'Application 2' },
    ];

    it('should return applications using a battery', async () => {
      // Arrange
      testBatteriesService.getAssignedApplications.mockResolvedValue(mockApplications);

      // Act
      const result = await controller.getAssignedApplications('battery-1');

      // Assert
      expect(result).toEqual(mockApplications);
      expect(testBatteriesService.getAssignedApplications).toHaveBeenCalledTimes(1);
      expect(testBatteriesService.getAssignedApplications).toHaveBeenCalledWith('battery-1');
    });

    it('should return empty array when battery has no assigned applications', async () => {
      // Arrange
      testBatteriesService.getAssignedApplications.mockResolvedValue([]);

      // Act
      const result = await controller.getAssignedApplications('battery-1');

      // Assert
      expect(result).toEqual([]);
    });
  });
});
