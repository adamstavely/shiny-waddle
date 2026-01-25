/**
 * Tests Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { TestsController } from './tests.controller';
import { TestsService } from './tests.service';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';
import { TestEntity } from './entities/test.entity';

describe('TestsController', () => {
  let controller: TestsController;
  let testsService: jest.Mocked<TestsService>;

  const mockTest: TestEntity = {
    id: 'test-1',
    name: 'Test Policy',
    description: 'Test description',
    testType: 'access-control',
    domain: 'identity',
    version: 1,
    versionHistory: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTests: TestEntity[] = [
    mockTest,
    {
      ...mockTest,
      id: 'test-2',
      name: 'Another Test',
      testType: 'dlp',
    },
  ];

  beforeEach(async () => {
    const mockTestsService = {
      findAll: jest.fn(),
      findByPolicy: jest.fn(),
      findOne: jest.fn(),
      findOneVersion: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
      getUsedInSuites: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestsController],
      providers: [
        {
          provide: TestsService,
          useValue: mockTestsService,
        },
      ],
    }).compile();

    controller = module.get<TestsController>(TestsController);
    testsService = module.get(TestsService) as jest.Mocked<TestsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findAll', () => {
    it('should return all tests when no filters provided', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue(mockTests);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual(mockTests);
      expect(testsService.findAll).toHaveBeenCalledTimes(1);
      expect(testsService.findAll).toHaveBeenCalledWith({});
    });

    it('should filter tests by testType', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue([mockTest]);

      // Act
      const result = await controller.findAll('access-control');

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findAll).toHaveBeenCalledWith({ testType: 'access-control' });
    });

    it('should filter tests by policyId', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue([mockTest]);

      // Act
      const result = await controller.findAll(undefined, 'policy-1');

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findAll).toHaveBeenCalledWith({ policyId: 'policy-1' });
    });

    it('should filter tests by domain', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue([mockTest]);

      // Act
      const result = await controller.findAll(undefined, undefined, 'identity');

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findAll).toHaveBeenCalledWith({ domain: 'identity' });
    });

    it('should filter tests by all parameters', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue([mockTest]);

      // Act
      const result = await controller.findAll('access-control', 'policy-1', 'identity');

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findAll).toHaveBeenCalledWith({
        testType: 'access-control',
        policyId: 'policy-1',
        domain: 'identity',
      });
    });

    it('should return empty array when no tests found', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue([]);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findByPolicy', () => {
    it('should return tests for a specific policy', async () => {
      // Arrange
      testsService.findByPolicy.mockResolvedValue([mockTest]);

      // Act
      const result = await controller.findByPolicy('policy-1');

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findByPolicy).toHaveBeenCalledTimes(1);
      expect(testsService.findByPolicy).toHaveBeenCalledWith('policy-1');
    });

    it('should return empty array when no tests found for policy', async () => {
      // Arrange
      testsService.findByPolicy.mockResolvedValue([]);

      // Act
      const result = await controller.findByPolicy('non-existent-policy');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return a test by id', async () => {
      // Arrange
      testsService.findOne.mockResolvedValue(mockTest);

      // Act
      const result = await controller.findOne('test-1');

      // Assert
      expect(result).toEqual(mockTest);
      expect(testsService.findOne).toHaveBeenCalledTimes(1);
      expect(testsService.findOne).toHaveBeenCalledWith('test-1');
    });

    it('should propagate NotFoundException when test not found', async () => {
      // Arrange
      testsService.findOne.mockRejectedValue(new NotFoundException('Test not found'));

      // Act & Assert
      await expect(controller.findOne('non-existent')).rejects.toThrow(NotFoundException);
      expect(testsService.findOne).toHaveBeenCalledWith('non-existent');
    });
  });

  describe('getVersionHistory', () => {
    const mockVersionHistory = [
      {
        version: 1,
        testConfiguration: { name: 'Test Policy v1' },
        changedAt: new Date(),
        changes: ['Initial version'],
      },
    ];

    it('should return version history for a test', async () => {
      // Arrange
      const testWithHistory = { ...mockTest, versionHistory: mockVersionHistory };
      testsService.findOne.mockResolvedValue(testWithHistory);

      // Act
      const result = await controller.getVersionHistory('test-1');

      // Assert
      expect(result).toEqual(mockVersionHistory);
      expect(testsService.findOne).toHaveBeenCalledWith('test-1');
    });

    it('should return empty array when no version history exists', async () => {
      // Arrange
      testsService.findOne.mockResolvedValue(mockTest);

      // Act
      const result = await controller.getVersionHistory('test-1');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOneVersion', () => {
    const mockVersionedTest = {
      ...mockTest,
      version: 1,
    };

    it('should return a specific version of a test', async () => {
      // Arrange
      testsService.findOneVersion.mockResolvedValue(mockVersionedTest);

      // Act
      const result = await controller.findOneVersion('test-1', '1');

      // Assert
      expect(result).toEqual(mockVersionedTest);
      expect(testsService.findOneVersion).toHaveBeenCalledTimes(1);
      expect(testsService.findOneVersion).toHaveBeenCalledWith('test-1', 1);
    });

    it('should handle version string conversion', async () => {
      // Arrange
      testsService.findOneVersion.mockResolvedValue(mockVersionedTest);

      // Act
      const result = await controller.findOneVersion('test-1', '2');

      // Assert
      expect(testsService.findOneVersion).toHaveBeenCalledWith('test-1', 2);
    });
  });

  describe('create', () => {
    const createTestDto: CreateTestDto = {
      name: 'New Test',
      description: 'New test description',
      testType: 'access-control',
      domain: 'identity',
      policyId: 'policy-1',
      inputs: {
        subject: { role: 'user' },
        resource: { id: 'resource-1' },
      },
      expected: {
        allowed: false,
      },
    };

    it('should create a test successfully', async () => {
      // Arrange
      testsService.create.mockResolvedValue(mockTest);

      // Act
      const result = await controller.create(createTestDto);

      // Assert
      expect(result).toEqual(mockTest);
      expect(testsService.create).toHaveBeenCalledTimes(1);
      expect(testsService.create).toHaveBeenCalledWith(createTestDto);
    });

    it('should create a test with minimal required fields', async () => {
      // Arrange
      const minimalDto: CreateTestDto = {
        name: 'Minimal Test',
        testType: 'dlp',
      };
      testsService.create.mockResolvedValue({
        ...mockTest,
        ...minimalDto,
      });

      // Act
      const result = await controller.create(minimalDto);

      // Assert
      expect(result).toEqual({ ...mockTest, ...minimalDto });
      expect(testsService.create).toHaveBeenCalledWith(minimalDto);
    });
  });

  describe('update', () => {
    const updateTestDto: UpdateTestDto = {
      name: 'Updated Test',
      changeReason: 'Updated for testing',
    };

    it('should update a test successfully', async () => {
      // Arrange
      const updatedTest = { ...mockTest, ...updateTestDto };
      testsService.update.mockResolvedValue(updatedTest);

      // Act
      const result = await controller.update('test-1', updateTestDto);

      // Assert
      expect(result).toEqual(updatedTest);
      expect(testsService.update).toHaveBeenCalledTimes(1);
      expect(testsService.update).toHaveBeenCalledWith(
        'test-1',
        updateTestDto,
        undefined,
        'Updated for testing'
      );
    });

    it('should update a test without changeReason', async () => {
      // Arrange
      const updateWithoutReason: UpdateTestDto = {
        name: 'Updated Test',
      };
      const updatedTest = { ...mockTest, ...updateWithoutReason };
      testsService.update.mockResolvedValue(updatedTest);

      // Act
      const result = await controller.update('test-1', updateWithoutReason);

      // Assert
      expect(result).toEqual(updatedTest);
      expect(testsService.update).toHaveBeenCalledWith('test-1', updateWithoutReason, undefined, undefined);
    });

    it('should propagate NotFoundException when test not found', async () => {
      // Arrange
      testsService.update.mockRejectedValue(new NotFoundException('Test not found'));

      // Act & Assert
      await expect(controller.update('non-existent', updateTestDto)).rejects.toThrow(
        NotFoundException
      );
    });
  });

  describe('remove', () => {
    it('should delete a test successfully', async () => {
      // Arrange
      testsService.remove.mockResolvedValue(undefined);

      // Act
      await controller.remove('test-1');

      // Assert
      expect(testsService.remove).toHaveBeenCalledTimes(1);
      expect(testsService.remove).toHaveBeenCalledWith('test-1');
    });

    it('should propagate NotFoundException when test not found', async () => {
      // Arrange
      testsService.remove.mockRejectedValue(new NotFoundException('Test not found'));

      // Act & Assert
      await expect(controller.remove('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getUsedInSuites', () => {
    const mockSuites = [
      { id: 'suite-1', name: 'Test Suite 1' },
      { id: 'suite-2', name: 'Test Suite 2' },
    ];

    it('should return suites using a test', async () => {
      // Arrange
      testsService.getUsedInSuites.mockResolvedValue(mockSuites);

      // Act
      const result = await controller.getUsedInSuites('test-1');

      // Assert
      expect(result).toEqual(mockSuites);
      expect(testsService.getUsedInSuites).toHaveBeenCalledTimes(1);
      expect(testsService.getUsedInSuites).toHaveBeenCalledWith('test-1');
    });

    it('should return empty array when test is not used in any suites', async () => {
      // Arrange
      testsService.getUsedInSuites.mockResolvedValue([]);

      // Act
      const result = await controller.getUsedInSuites('test-1');

      // Assert
      expect(result).toEqual([]);
    });
  });
});
