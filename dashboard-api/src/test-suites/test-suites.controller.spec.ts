/**
 * Test Suites Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { TestSuitesController } from './test-suites.controller';
import { TestSuitesService } from './test-suites.service';
import { CreateTestSuiteDto } from './dto/create-test-suite.dto';
import { UpdateTestSuiteDto } from './dto/update-test-suite.dto';
import { TestSuiteEntity } from './entities/test-suite.entity';

describe('TestSuitesController', () => {
  let controller: TestSuitesController;
  let testSuitesService: jest.Mocked<TestSuitesService>;

  const mockTestSuite: TestSuiteEntity = {
    id: 'suite-1',
    name: 'Test Suite',
    applicationId: 'app-1',
    application: 'Test App',
    team: 'team-1',
    status: 'passing',
    testCount: 5,
    score: 100,
    testType: 'access-control',
    domain: 'identity',
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTestSuites: TestSuiteEntity[] = [
    mockTestSuite,
    {
      ...mockTestSuite,
      id: 'suite-2',
      name: 'Another Suite',
      status: 'failing',
      domain: 'api_security',
    },
  ];

  beforeEach(async () => {
    const mockTestSuitesService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findByApplication: jest.fn(),
      findByTeam: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      enable: jest.fn(),
      disable: jest.fn(),
      discoverFilesystemSuites: jest.fn(),
      getTestSuiteSource: jest.fn(),
      updateTestSuiteSource: jest.fn(),
      extractTestSuiteConfig: jest.fn(),
      getUsedInHarnesses: jest.fn(),
      runTestSuite: jest.fn(),
      getTestResults: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestSuitesController],
      providers: [
        {
          provide: TestSuitesService,
          useValue: mockTestSuitesService,
        },
      ],
    }).compile();

    controller = module.get<TestSuitesController>(TestSuitesController);
    testSuitesService = module.get(TestSuitesService) as jest.Mocked<TestSuitesService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    const createTestSuiteDto: CreateTestSuiteDto = {
      name: 'New Test Suite',
      applicationId: 'app-1',
      team: 'team-1',
      testType: 'access-control',
      domain: 'identity',
      enabled: true,
    };

    it('should create a test suite successfully', async () => {
      // Arrange
      testSuitesService.create.mockResolvedValue(mockTestSuite);

      // Act
      const result = await controller.create(createTestSuiteDto);

      // Assert
      expect(result).toEqual(mockTestSuite);
      expect(testSuitesService.create).toHaveBeenCalledTimes(1);
      expect(testSuitesService.create).toHaveBeenCalledWith(createTestSuiteDto);
    });
  });

  describe('findAll', () => {
    it('should return all test suites when no filters provided', async () => {
      // Arrange
      testSuitesService.findAll.mockResolvedValue(mockTestSuites);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual(mockTestSuites);
      expect(testSuitesService.findAll).toHaveBeenCalledTimes(1);
      expect(testSuitesService.findByApplication).not.toHaveBeenCalled();
      expect(testSuitesService.findByTeam).not.toHaveBeenCalled();
    });

    it('should filter by applicationId', async () => {
      // Arrange
      testSuitesService.findByApplication.mockResolvedValue([mockTestSuite]);

      // Act
      const result = await controller.findAll('app-1');

      // Assert
      expect(result).toEqual([mockTestSuite]);
      expect(testSuitesService.findByApplication).toHaveBeenCalledWith('app-1');
      expect(testSuitesService.findAll).not.toHaveBeenCalled();
    });

    it('should filter by team', async () => {
      // Arrange
      testSuitesService.findByTeam.mockResolvedValue([mockTestSuite]);

      // Act
      const result = await controller.findAll(undefined, 'team-1');

      // Assert
      expect(result).toEqual([mockTestSuite]);
      expect(testSuitesService.findByTeam).toHaveBeenCalledWith('team-1');
      expect(testSuitesService.findAll).not.toHaveBeenCalled();
    });

    it('should filter by domain', async () => {
      // Arrange
      testSuitesService.findAll.mockResolvedValue(mockTestSuites);

      // Act
      const result = await controller.findAll(undefined, undefined, 'identity');

      // Assert
      expect(result).toEqual([mockTestSuite]);
      expect(testSuitesService.findAll).toHaveBeenCalled();
    });

    it('should filter by applicationId and domain', async () => {
      // Arrange
      testSuitesService.findByApplication.mockResolvedValue(mockTestSuites);

      // Act
      const result = await controller.findAll('app-1', undefined, 'identity');

      // Assert
      expect(result).toEqual([mockTestSuite]);
      expect(testSuitesService.findByApplication).toHaveBeenCalledWith('app-1');
    });

    it('should return empty array when no suites found', async () => {
      // Arrange
      testSuitesService.findAll.mockResolvedValue([]);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return a test suite by id', async () => {
      // Arrange
      testSuitesService.findOne.mockResolvedValue(mockTestSuite);

      // Act
      const result = await controller.findOne('suite-1');

      // Assert
      expect(result).toEqual(mockTestSuite);
      expect(testSuitesService.findOne).toHaveBeenCalledTimes(1);
      expect(testSuitesService.findOne).toHaveBeenCalledWith('suite-1');
    });

    it('should propagate NotFoundException when suite not found', async () => {
      // Arrange
      testSuitesService.findOne.mockRejectedValue(new NotFoundException('Test suite not found'));

      // Act & Assert
      await expect(controller.findOne('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateTestSuiteDto: UpdateTestSuiteDto = {
      name: 'Updated Suite',
      enabled: false,
    };

    it('should update a test suite successfully', async () => {
      // Arrange
      const updatedSuite = { ...mockTestSuite, ...updateTestSuiteDto };
      testSuitesService.update.mockResolvedValue(updatedSuite);

      // Act
      const result = await controller.update('suite-1', updateTestSuiteDto);

      // Assert
      expect(result).toEqual(updatedSuite);
      expect(testSuitesService.update).toHaveBeenCalledTimes(1);
      expect(testSuitesService.update).toHaveBeenCalledWith('suite-1', updateTestSuiteDto);
    });
  });

  describe('delete', () => {
    it('should delete a test suite successfully', async () => {
      // Arrange
      testSuitesService.delete.mockResolvedValue(undefined);

      // Act
      await controller.delete('suite-1');

      // Assert
      expect(testSuitesService.delete).toHaveBeenCalledTimes(1);
      expect(testSuitesService.delete).toHaveBeenCalledWith('suite-1');
    });
  });

  describe('enable', () => {
    it('should enable a test suite successfully', async () => {
      // Arrange
      const enabledSuite = { ...mockTestSuite, enabled: true };
      testSuitesService.enable.mockResolvedValue(enabledSuite);

      // Act
      const result = await controller.enable('suite-1');

      // Assert
      expect(result).toEqual(enabledSuite);
      expect(testSuitesService.enable).toHaveBeenCalledTimes(1);
      expect(testSuitesService.enable).toHaveBeenCalledWith('suite-1');
    });
  });

  describe('disable', () => {
    it('should disable a test suite successfully', async () => {
      // Arrange
      const disabledSuite = { ...mockTestSuite, enabled: false };
      testSuitesService.disable.mockResolvedValue(disabledSuite);

      // Act
      const result = await controller.disable('suite-1');

      // Assert
      expect(result).toEqual(disabledSuite);
      expect(testSuitesService.disable).toHaveBeenCalledTimes(1);
      expect(testSuitesService.disable).toHaveBeenCalledWith('suite-1');
    });
  });

  describe('discover', () => {
    it('should discover filesystem test suites', async () => {
      // Arrange
      testSuitesService.discoverFilesystemSuites.mockResolvedValue(undefined);
      testSuitesService.findAll.mockResolvedValue([
        { ...mockTestSuite, sourceType: 'typescript' },
        { ...mockTestSuite, id: 'suite-2', sourceType: 'json' },
      ]);

      // Act
      const result = await controller.discover();

      // Assert
      expect(result).toEqual({
        message: 'Filesystem test suites discovered',
        count: 1,
      });
      expect(testSuitesService.discoverFilesystemSuites).toHaveBeenCalledTimes(1);
      expect(testSuitesService.findAll).toHaveBeenCalledTimes(1);
    });
  });

  describe('getSource', () => {
    const mockSource = {
      content: 'export const testSuite = {...}',
      sourceType: 'typescript',
      sourcePath: 'tests/suites/test-suite.ts',
    };

    it('should return test suite source', async () => {
      // Arrange
      testSuitesService.getTestSuiteSource.mockResolvedValue(mockSource);

      // Act
      const result = await controller.getSource('suite-1');

      // Assert
      expect(result).toEqual(mockSource);
      expect(testSuitesService.getTestSuiteSource).toHaveBeenCalledTimes(1);
      expect(testSuitesService.getTestSuiteSource).toHaveBeenCalledWith('suite-1');
    });
  });

  describe('updateSource', () => {
    it('should update test suite source', async () => {
      // Arrange
      testSuitesService.updateTestSuiteSource.mockResolvedValue(undefined);

      // Act
      const result = await controller.updateSource('suite-1', { content: 'new content' });

      // Assert
      expect(result).toEqual({ message: 'Source file updated successfully' });
      expect(testSuitesService.updateTestSuiteSource).toHaveBeenCalledTimes(1);
      expect(testSuitesService.updateTestSuiteSource).toHaveBeenCalledWith('suite-1', 'new content');
    });
  });

  describe('extractConfig', () => {
    const mockConfig: any = {
      name: 'Test Suite',
      testType: 'access-control',
      domain: 'identity',
      id: 'suite-1',
      application: 'app-1',
      team: 'team-1',
      testIds: [],
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('should extract test suite configuration', async () => {
      // Arrange
      testSuitesService.extractTestSuiteConfig.mockResolvedValue(mockConfig);

      // Act
      const result = await controller.extractConfig('suite-1');

      // Assert
      expect(result).toEqual({ config: mockConfig });
      expect(testSuitesService.extractTestSuiteConfig).toHaveBeenCalledTimes(1);
      expect(testSuitesService.extractTestSuiteConfig).toHaveBeenCalledWith('suite-1');
    });

    it('should throw NotFoundException when config cannot be extracted', async () => {
      // Arrange
      testSuitesService.extractTestSuiteConfig.mockResolvedValue(null);

      // Act & Assert
      await expect(controller.extractConfig('suite-1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getUsedInHarnesses', () => {
    const mockHarnesses = [
      { id: 'harness-1', name: 'Harness 1' },
      { id: 'harness-2', name: 'Harness 2' },
    ];

    it('should return harnesses using a test suite', async () => {
      // Arrange
      testSuitesService.getUsedInHarnesses.mockResolvedValue(mockHarnesses);

      // Act
      const result = await controller.getUsedInHarnesses('suite-1');

      // Assert
      expect(result).toEqual(mockHarnesses);
      expect(testSuitesService.getUsedInHarnesses).toHaveBeenCalledTimes(1);
      expect(testSuitesService.getUsedInHarnesses).toHaveBeenCalledWith('suite-1');
    });

    it('should return empty array when suite is not used in any harnesses', async () => {
      // Arrange
      testSuitesService.getUsedInHarnesses.mockResolvedValue([]);

      // Act
      const result = await controller.getUsedInHarnesses('suite-1');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('runTestSuite', () => {
    const mockRunResult = {
      suiteId: 'suite-1',
      suiteName: 'Test Suite',
      status: 'passed' as const,
      totalTests: 5,
      passed: 5,
      failed: 0,
      results: [],
      timestamp: new Date(),
    };

    it('should run a test suite successfully', async () => {
      // Arrange
      testSuitesService.runTestSuite.mockResolvedValue(mockRunResult);

      // Act
      const result = await controller.runTestSuite('suite-1');

      // Assert
      expect(result).toEqual(mockRunResult);
      expect(testSuitesService.runTestSuite).toHaveBeenCalledTimes(1);
      expect(testSuitesService.runTestSuite).toHaveBeenCalledWith('suite-1');
    });
  });

  describe('getTestResults', () => {
    const mockResults = {
      suiteId: 'suite-1',
      lastRun: new Date(),
      results: [
        { testId: 'test-1', passed: true },
        { testId: 'test-2', passed: false },
      ],
    };

    it('should return test results for a suite', async () => {
      // Arrange
      testSuitesService.getTestResults.mockResolvedValue(mockResults);

      // Act
      const result = await controller.getTestResults('suite-1');

      // Assert
      expect(result).toEqual(mockResults);
      expect(testSuitesService.getTestResults).toHaveBeenCalledTimes(1);
      expect(testSuitesService.getTestResults).toHaveBeenCalledWith('suite-1');
    });

    it('should return results without lastRun when suite has not been run', async () => {
      // Arrange
      const resultsWithoutRun = {
        suiteId: 'suite-1',
        results: [],
      };
      testSuitesService.getTestResults.mockResolvedValue(resultsWithoutRun);

      // Act
      const result = await controller.getTestResults('suite-1');

      // Assert
      expect(result).toEqual(resultsWithoutRun);
      expect(result.lastRun).toBeUndefined();
    });
  });
});
