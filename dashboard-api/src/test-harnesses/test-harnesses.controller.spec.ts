/**
 * Test Harnesses Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { TestHarnessesController } from './test-harnesses.controller';
import { TestHarnessesService } from './test-harnesses.service';
import { CreateTestHarnessDto } from './dto/create-test-harness.dto';
import { UpdateTestHarnessDto } from './dto/update-test-harness.dto';
import { TestHarnessEntity } from './entities/test-harness.entity';

describe('TestHarnessesController', () => {
  let controller: TestHarnessesController;
  let testHarnessesService: jest.Mocked<TestHarnessesService>;

  const mockTestHarness: TestHarnessEntity = {
    id: 'harness-1',
    name: 'Test Harness',
    description: 'Test harness description',
    domain: 'identity',
    testSuiteIds: ['suite-1', 'suite-2'],
    applicationIds: ['app-1'],
    team: 'team-1',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTestHarnesses: TestHarnessEntity[] = [
    mockTestHarness,
    {
      ...mockTestHarness,
      id: 'harness-2',
      name: 'Another Harness',
      domain: 'api_security',
    },
  ];

  beforeEach(async () => {
    const mockTestHarnessesService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findByApplication: jest.fn(),
      findByTestSuite: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      addTestSuite: jest.fn(),
      removeTestSuite: jest.fn(),
      assignToApplication: jest.fn(),
      unassignFromApplication: jest.fn(),
      getUsedInBatteries: jest.fn(),
      getAssignedApplications: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestHarnessesController],
      providers: [
        {
          provide: TestHarnessesService,
          useValue: mockTestHarnessesService,
        },
      ],
    }).compile();

    controller = module.get<TestHarnessesController>(TestHarnessesController);
    testHarnessesService = module.get(TestHarnessesService) as jest.Mocked<TestHarnessesService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    const createTestHarnessDto: CreateTestHarnessDto = {
      name: 'New Test Harness',
      description: 'New harness description',
      domain: 'identity',
      testSuiteIds: ['suite-1'],
    };

    it('should create a test harness successfully', async () => {
      // Arrange
      testHarnessesService.create.mockResolvedValue(mockTestHarness);

      // Act
      const result = await controller.create(createTestHarnessDto);

      // Assert
      expect(result).toEqual(mockTestHarness);
      expect(testHarnessesService.create).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.create).toHaveBeenCalledWith(createTestHarnessDto);
    });
  });

  describe('findAll', () => {
    it('should return all test harnesses when no filters provided', async () => {
      // Arrange
      testHarnessesService.findAll.mockResolvedValue(mockTestHarnesses);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual(mockTestHarnesses);
      expect(testHarnessesService.findAll).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.findByApplication).not.toHaveBeenCalled();
      expect(testHarnessesService.findByTestSuite).not.toHaveBeenCalled();
    });

    it('should filter by applicationId', async () => {
      // Arrange
      testHarnessesService.findByApplication.mockResolvedValue([mockTestHarness]);

      // Act
      const result = await controller.findAll('app-1');

      // Assert
      expect(result).toEqual([mockTestHarness]);
      expect(testHarnessesService.findByApplication).toHaveBeenCalledWith('app-1');
      expect(testHarnessesService.findAll).not.toHaveBeenCalled();
    });

    it('should filter by suiteId', async () => {
      // Arrange
      testHarnessesService.findByTestSuite.mockResolvedValue([mockTestHarness]);

      // Act
      const result = await controller.findAll(undefined, 'suite-1');

      // Assert
      expect(result).toEqual([mockTestHarness]);
      expect(testHarnessesService.findByTestSuite).toHaveBeenCalledWith('suite-1');
      expect(testHarnessesService.findAll).not.toHaveBeenCalled();
    });

    it('should filter by domain', async () => {
      // Arrange
      testHarnessesService.findAll.mockResolvedValue(mockTestHarnesses);

      // Act
      const result = await controller.findAll(undefined, undefined, 'identity');

      // Assert
      expect(result).toEqual([mockTestHarness]);
      expect(testHarnessesService.findAll).toHaveBeenCalled();
    });

    it('should filter by applicationId and domain', async () => {
      // Arrange
      testHarnessesService.findByApplication.mockResolvedValue(mockTestHarnesses);

      // Act
      const result = await controller.findAll('app-1', undefined, 'identity');

      // Assert
      expect(result).toEqual([mockTestHarness]);
      expect(testHarnessesService.findByApplication).toHaveBeenCalledWith('app-1');
    });

    it('should return empty array when no harnesses found', async () => {
      // Arrange
      testHarnessesService.findAll.mockResolvedValue([]);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return a test harness by id', async () => {
      // Arrange
      testHarnessesService.findOne.mockResolvedValue(mockTestHarness);

      // Act
      const result = await controller.findOne('harness-1');

      // Assert
      expect(result).toEqual(mockTestHarness);
      expect(testHarnessesService.findOne).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.findOne).toHaveBeenCalledWith('harness-1');
    });

    it('should propagate NotFoundException when harness not found', async () => {
      // Arrange
      testHarnessesService.findOne.mockRejectedValue(new NotFoundException('Test harness not found'));

      // Act & Assert
      await expect(controller.findOne('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateTestHarnessDto: UpdateTestHarnessDto = {
      name: 'Updated Harness',
      description: 'Updated description',
    };

    it('should update a test harness successfully', async () => {
      // Arrange
      const updatedHarness = { ...mockTestHarness, ...updateTestHarnessDto };
      testHarnessesService.update.mockResolvedValue(updatedHarness);

      // Act
      const result = await controller.update('harness-1', updateTestHarnessDto);

      // Assert
      expect(result).toEqual(updatedHarness);
      expect(testHarnessesService.update).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.update).toHaveBeenCalledWith('harness-1', updateTestHarnessDto);
    });
  });

  describe('delete', () => {
    it('should delete a test harness successfully', async () => {
      // Arrange
      testHarnessesService.delete.mockResolvedValue(undefined);

      // Act
      await controller.delete('harness-1');

      // Assert
      expect(testHarnessesService.delete).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.delete).toHaveBeenCalledWith('harness-1');
    });
  });

  describe('addTestSuite', () => {
    it('should add a test suite to a harness', async () => {
      // Arrange
      const updatedHarness = {
        ...mockTestHarness,
        testSuiteIds: [...mockTestHarness.testSuiteIds, 'suite-3'],
      };
      testHarnessesService.addTestSuite.mockResolvedValue(updatedHarness);

      // Act
      const result = await controller.addTestSuite('harness-1', 'suite-3');

      // Assert
      expect(result).toEqual(updatedHarness);
      expect(testHarnessesService.addTestSuite).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.addTestSuite).toHaveBeenCalledWith('harness-1', 'suite-3');
    });
  });

  describe('removeTestSuite', () => {
    it('should remove a test suite from a harness', async () => {
      // Arrange
      const updatedHarness = {
        ...mockTestHarness,
        testSuiteIds: ['suite-1'],
      };
      testHarnessesService.removeTestSuite.mockResolvedValue(updatedHarness);

      // Act
      const result = await controller.removeTestSuite('harness-1', 'suite-2');

      // Assert
      expect(result).toEqual(updatedHarness);
      expect(testHarnessesService.removeTestSuite).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.removeTestSuite).toHaveBeenCalledWith('harness-1', 'suite-2');
    });
  });

  describe('assignToApplication', () => {
    it('should assign a harness to an application', async () => {
      // Arrange
      const updatedHarness = {
        ...mockTestHarness,
        applicationIds: [...mockTestHarness.applicationIds, 'app-2'],
      };
      testHarnessesService.assignToApplication.mockResolvedValue(updatedHarness);

      // Act
      const result = await controller.assignToApplication('harness-1', 'app-2');

      // Assert
      expect(result).toEqual(updatedHarness);
      expect(testHarnessesService.assignToApplication).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.assignToApplication).toHaveBeenCalledWith('harness-1', 'app-2');
    });
  });

  describe('unassignFromApplication', () => {
    it('should unassign a harness from an application', async () => {
      // Arrange
      const updatedHarness = {
        ...mockTestHarness,
        applicationIds: [],
      };
      testHarnessesService.unassignFromApplication.mockResolvedValue(updatedHarness);

      // Act
      const result = await controller.unassignFromApplication('harness-1', 'app-1');

      // Assert
      expect(result).toEqual(updatedHarness);
      expect(testHarnessesService.unassignFromApplication).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.unassignFromApplication).toHaveBeenCalledWith('harness-1', 'app-1');
    });
  });

  describe('getUsedInBatteries', () => {
    const mockBatteries = [
      { id: 'battery-1', name: 'Battery 1' },
      { id: 'battery-2', name: 'Battery 2' },
    ];

    it('should return batteries using a harness', async () => {
      // Arrange
      testHarnessesService.getUsedInBatteries.mockResolvedValue(mockBatteries);

      // Act
      const result = await controller.getUsedInBatteries('harness-1');

      // Assert
      expect(result).toEqual(mockBatteries);
      expect(testHarnessesService.getUsedInBatteries).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.getUsedInBatteries).toHaveBeenCalledWith('harness-1');
    });

    it('should return empty array when harness is not used in any batteries', async () => {
      // Arrange
      testHarnessesService.getUsedInBatteries.mockResolvedValue([]);

      // Act
      const result = await controller.getUsedInBatteries('harness-1');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getAssignedApplications', () => {
    const mockApplications = [
      { id: 'app-1', name: 'Application 1' },
      { id: 'app-2', name: 'Application 2' },
    ];

    it('should return applications assigned to a harness', async () => {
      // Arrange
      testHarnessesService.getAssignedApplications.mockResolvedValue(mockApplications);

      // Act
      const result = await controller.getAssignedApplications('harness-1');

      // Assert
      expect(result).toEqual(mockApplications);
      expect(testHarnessesService.getAssignedApplications).toHaveBeenCalledTimes(1);
      expect(testHarnessesService.getAssignedApplications).toHaveBeenCalledWith('harness-1');
    });

    it('should return empty array when harness has no assigned applications', async () => {
      // Arrange
      testHarnessesService.getAssignedApplications.mockResolvedValue([]);

      // Act
      const result = await controller.getAssignedApplications('harness-1');

      // Assert
      expect(result).toEqual([]);
    });
  });
});
