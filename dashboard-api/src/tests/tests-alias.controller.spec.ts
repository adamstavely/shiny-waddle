/**
 * Tests Alias Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { TestsAliasController } from './tests-alias.controller';
import { TestsService } from './tests.service';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';

describe('TestsAliasController', () => {
  let controller: TestsAliasController;
  let testsService: jest.Mocked<TestsService>;

  const mockTest = {
    id: 'test-1',
    name: 'Test 1',
    testType: 'api-security',
    createdAt: new Date(),
  };

  const mockRequest = {
    url: '/api/tests/test-1',
    path: '/api/tests/test-1',
  };

  beforeEach(async () => {
    const mockTestsService = {
      findAll: jest.fn(),
      findByPolicy: jest.fn(),
      findOneVersion: jest.fn(),
      findOne: jest.fn(),
      getUsedInSuites: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestsAliasController],
      providers: [
        {
          provide: TestsService,
          useValue: mockTestsService,
        },
      ],
    }).compile();

    controller = module.get<TestsAliasController>(TestsAliasController);
    testsService = module.get(TestsService) as jest.Mocked<TestsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findAll', () => {
    it('should find all tests', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue([mockTest] as any);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findAll).toHaveBeenCalledWith({});
    });

    it('should find tests with filters', async () => {
      // Arrange
      testsService.findAll.mockResolvedValue([mockTest] as any);

      // Act
      const result = await controller.findAll('api-security', 'policy-1', 'domain-1');

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findAll).toHaveBeenCalledWith({
        testType: 'api-security',
        policyId: 'policy-1',
        domain: 'domain-1',
      });
    });
  });

  describe('findByPolicy', () => {
    it('should find tests by policy', async () => {
      // Arrange
      testsService.findByPolicy.mockResolvedValue([mockTest] as any);

      // Act
      const result = await controller.findByPolicy('policy-1');

      // Assert
      expect(result).toEqual([mockTest]);
      expect(testsService.findByPolicy).toHaveBeenCalledWith('policy-1');
    });
  });

  describe('findOneVersion', () => {
    it('should find one test version', async () => {
      // Arrange
      testsService.findOneVersion.mockResolvedValue(mockTest as any);

      // Act
      const result = await controller.findOneVersion(mockRequest as any, '1');

      // Assert
      expect(result).toEqual(mockTest);
      expect(testsService.findOneVersion).toHaveBeenCalledWith('test-1', 1);
    });
  });

  describe('getVersionHistory', () => {
    it('should get version history', async () => {
      // Arrange
      const versionHistory = [{ version: 1 }];
      testsService.findOne.mockResolvedValue({ ...mockTest, versionHistory } as any);

      // Act
      const result = await controller.getVersionHistory(mockRequest as any);

      // Assert
      expect(result).toEqual(versionHistory);
      expect(testsService.findOne).toHaveBeenCalledWith('test-1');
    });
  });

  describe('getUsedInSuites', () => {
    it('should get used in suites', async () => {
      // Arrange
      const suites = [{ id: 'suite-1' }];
      testsService.getUsedInSuites.mockResolvedValue(suites as any);

      // Act
      const result = await controller.getUsedInSuites(mockRequest as any);

      // Assert
      expect(result).toEqual(suites);
      expect(testsService.getUsedInSuites).toHaveBeenCalledWith('test-1');
    });
  });

  describe('findOneById', () => {
    it('should find one test by id', async () => {
      // Arrange
      testsService.findOne.mockResolvedValue(mockTest as any);

      // Act
      const result = await controller.findOneById('test-1');

      // Assert
      expect(result).toEqual(mockTest);
      expect(testsService.findOne).toHaveBeenCalledWith('test-1');
    });
  });

  describe('findOneByWildcard', () => {
    it('should find one test by wildcard', async () => {
      // Arrange
      testsService.findOne.mockResolvedValue(mockTest as any);

      // Act
      const result = await controller.findOneByWildcard(mockRequest as any);

      // Assert
      expect(result).toEqual(mockTest);
      expect(testsService.findOne).toHaveBeenCalledWith('test-1');
    });
  });

  describe('create', () => {
    const dto: CreateTestDto = {
      name: 'Test 1',
      testType: 'api-security' as any,
    };

    it('should create a test', async () => {
      // Arrange
      testsService.create.mockResolvedValue(mockTest as any);

      // Act
      const result = await controller.create(dto);

      // Assert
      expect(result).toEqual(mockTest);
      expect(testsService.create).toHaveBeenCalledWith(dto);
    });
  });

  describe('update', () => {
    const dto: UpdateTestDto = {
      name: 'Updated Test',
    };

    it('should update a test', async () => {
      // Arrange
      const updated = { ...mockTest, ...dto };
      testsService.update.mockResolvedValue(updated as any);

      // Act
      const result = await controller.update(mockRequest as any, dto);

      // Assert
      expect(result).toEqual(updated);
      expect(testsService.update).toHaveBeenCalledWith('test-1', dto, undefined, undefined);
    });
  });

  describe('remove', () => {
    it('should remove a test', async () => {
      // Arrange
      testsService.remove.mockResolvedValue(undefined);

      // Act
      const result = await controller.remove(mockRequest as any);

      // Assert
      expect(result).toBeUndefined();
      expect(testsService.remove).toHaveBeenCalledWith('test-1');
    });
  });
});
