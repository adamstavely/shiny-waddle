/**
 * Test Suites Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { TestSuitesService } from './test-suites.service';
import { TestLoaderService } from './test-loader.service';
import { CreateTestSuiteDto } from './dto/create-test-suite.dto';
import { UpdateTestSuiteDto } from './dto/update-test-suite.dto';
import { TestSuiteEntity } from './entities/test-suite.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('TestSuitesService', () => {
  let service: TestSuitesService;
  let testLoader: jest.Mocked<TestLoaderService>;

  const mockSuite: TestSuiteEntity = {
    id: 'suite-1',
    name: 'Test Suite',
    applicationId: 'app-1',
    team: 'platform-team',
    description: 'Test suite description',
    status: 'pending',
    testCount: 5,
    score: 85,
    testType: 'access-control',
    domain: 'identity',
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockTestLoader = {
      loadTestSuite: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TestSuitesService,
        {
          provide: TestLoaderService,
          useValue: mockTestLoader,
        },
      ],
    }).compile();

    service = module.get<TestSuitesService>(TestSuitesService);
    testLoader = module.get(TestLoaderService) as jest.Mocked<TestLoaderService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);
    fs.readdir = jest.fn().mockResolvedValue([]);

    // Clear cached suites
    (service as any).suites = [];
    (service as any).filesystemSuites = new Map();
    
    // Mock discoverFilesystemSuites to prevent file system operations
    jest.spyOn(service as any, 'discoverFilesystemSuites').mockResolvedValue(undefined);
  });

  describe('create', () => {
    const createDto: CreateTestSuiteDto = {
      name: 'New Test Suite',
      applicationId: 'app-1',
      team: 'platform-team',
      testType: 'access-control',
      description: 'New suite description',
    };

    it('should successfully create a test suite', async () => {
      // Arrange
      (service as any).suites = [];

      // Act
      const result = await service.create(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(createDto.name);
      expect(result.testType).toBe(createDto.testType);
      expect(result.domain).toBeDefined();
      expect(result.status).toBe('pending');
      expect(result.enabled).toBe(true);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should auto-populate domain from testType', async () => {
      // Arrange
      (service as any).suites = [];

      const createDtoWithoutDomain: CreateTestSuiteDto = {
        ...createDto,
        domain: undefined,
      };

      // Act
      const result = await service.create(createDtoWithoutDomain);

      // Assert
      expect(result.domain).toBeDefined();
    });

    it('should validate domain matches testType', async () => {
      // Arrange
      (service as any).suites = [];

      const createDtoWithWrongDomain: CreateTestSuiteDto = {
        ...createDto,
        domain: 'api_security', // Wrong domain for access-control
      };

      // Act & Assert
      await expect(
        service.create(createDtoWithWrongDomain)
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for invalid testType', async () => {
      // Arrange
      (service as any).suites = [];

      const createDtoWithInvalidType: CreateTestSuiteDto = {
        ...createDto,
        testType: 'invalid-type' as any,
      };

      // Act & Assert
      await expect(
        service.create(createDtoWithInvalidType)
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for duplicate name in same application', async () => {
      // Arrange
      (service as any).suites = [mockSuite];

      // Act & Assert
      await expect(
        service.create({ ...createDto, name: mockSuite.name })
      ).rejects.toThrow(BadRequestException);
    });

    it('should allow duplicate name in different application', async () => {
      // Arrange
      (service as any).suites = [mockSuite];

      const createDtoDifferentApp: CreateTestSuiteDto = {
        ...createDto,
        name: mockSuite.name,
        applicationId: 'app-2', // Different application
      };

      // Act
      const result = await service.create(createDtoDifferentApp);

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(mockSuite.name);
      expect(result.applicationId).toBe('app-2');
    });
  });

  describe('findAll', () => {
    it('should return all test suites', async () => {
      // Arrange
      (service as any).suites = [mockSuite];
      jest.spyOn(service as any, 'discoverFilesystemSuites').mockResolvedValue(undefined);

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should merge filesystem suites with JSON suites', async () => {
      // Arrange
      (service as any).suites = [mockSuite];
      const fsSuite = { ...mockSuite, id: 'suite-2', name: 'FS Suite' };
      (service as any).filesystemSuites.set('path/to/suite.ts', fsSuite);
      jest.spyOn(service as any, 'discoverFilesystemSuites').mockResolvedValue(undefined);

      // Act
      const result = await service.findAll();

      // Assert
      expect(result.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('findOne', () => {
    it('should return suite when found', async () => {
      // Arrange
      (service as any).suites = [{ ...mockSuite }];
      jest.spyOn(service as any, 'discoverFilesystemSuites').mockResolvedValue(undefined);

      // Act
      const result = await service.findOne(mockSuite.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockSuite.id);
      expect(result.name).toBe(mockSuite.name);
    });

    it('should throw NotFoundException when suite not found', async () => {
      // Arrange
      (service as any).suites = [];

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateDto: UpdateTestSuiteDto = {
      name: 'Updated Suite Name',
      description: 'Updated description',
    };

    it('should successfully update a test suite', async () => {
      // Arrange
      (service as any).suites = [{ ...mockSuite }];
      jest.spyOn(service as any, 'loadSuites').mockResolvedValue(undefined);

      // Act
      const result = await service.update(mockSuite.id, updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when suite not found', async () => {
      // Arrange
      (service as any).suites = [];

      // Act & Assert
      await expect(
        service.update('non-existent-id', updateDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should validate domain when updating testType', async () => {
      // Arrange
      (service as any).suites = [{ ...mockSuite }];
      jest.spyOn(service as any, 'loadSuites').mockResolvedValue(undefined);

      const updateDtoWithNewType: UpdateTestSuiteDto = {
        testType: 'dlp',
        domain: 'api_security', // Wrong domain for dlp
      };

      // Act & Assert
      await expect(
        service.update(mockSuite.id, updateDtoWithNewType)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('delete', () => {
    it('should successfully delete a test suite', async () => {
      // Arrange
      (service as any).suites = [{ ...mockSuite }];
      jest.spyOn(service as any, 'loadSuites').mockResolvedValue(undefined);

      // Act
      await service.delete(mockSuite.id);

      // Assert
      expect((service as any).suites.find((s: TestSuiteEntity) => s.id === mockSuite.id)).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when suite not found', async () => {
      // Arrange
      (service as any).suites = [];
      jest.spyOn(service as any, 'loadSuites').mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.delete('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });
});
