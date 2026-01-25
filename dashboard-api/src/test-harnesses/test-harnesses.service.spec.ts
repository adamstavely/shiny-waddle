/**
 * Test Harnesses Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { TestHarnessesService } from './test-harnesses.service';
import { TestSuitesService } from '../test-suites/test-suites.service';
import { CreateTestHarnessDto } from './dto/create-test-harness.dto';
import { UpdateTestHarnessDto } from './dto/update-test-harness.dto';
import { TestHarnessEntity } from './entities/test-harness.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('TestHarnessesService', () => {
  let service: TestHarnessesService;
  let testSuitesService: jest.Mocked<TestSuitesService>;

  const mockHarness: TestHarnessEntity = {
    id: 'harness-1',
    name: 'Test Harness',
    description: 'Test harness description',
    domain: 'identity',
    testSuiteIds: ['suite-1', 'suite-2'],
    applicationIds: ['app-1'],
    team: 'platform-team',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockSuite = {
    id: 'suite-1',
    name: 'Test Suite',
    domain: 'identity',
    testType: 'access-control',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockTestSuitesService = {
      findAll: jest.fn().mockResolvedValue([mockSuite]),
      findOne: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TestHarnessesService,
        {
          provide: TestSuitesService,
          useValue: mockTestSuitesService,
        },
      ],
    }).compile();

    service = module.get<TestHarnessesService>(TestHarnessesService);
    testSuitesService = module.get(TestSuitesService) as jest.Mocked<TestSuitesService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear cached harnesses
    (service as any).harnesses = [];
  });

  describe('create', () => {
    const createDto: CreateTestHarnessDto = {
      name: 'New Test Harness',
      description: 'New harness description',
      domain: 'identity',
      team: 'platform-team',
      testSuiteIds: ['suite-1'],
      applicationIds: ['app-1'],
    };

    it('should successfully create a test harness', async () => {
      // Arrange
      (service as any).harnesses = [];

      // Act
      const result = await service.create(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(createDto.name);
      expect(result.domain).toBe(createDto.domain);
      expect(result.testSuiteIds).toEqual(createDto.testSuiteIds);
      expect(result.applicationIds).toEqual(createDto.applicationIds);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should validate that all suites match harness domain', async () => {
      // Arrange
      (service as any).harnesses = [];
      testSuitesService.findAll.mockResolvedValue([
        { ...mockSuite, domain: 'api_security' }, // Wrong domain
      ] as any);

      // Act & Assert
      await expect(
        service.create(createDto)
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException when suite not found', async () => {
      // Arrange
      (service as any).harnesses = [];
      testSuitesService.findAll.mockResolvedValue([]);

      // Act & Assert
      await expect(
        service.create(createDto)
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for duplicate name', async () => {
      // Arrange
      (service as any).harnesses = [mockHarness];

      // Act & Assert
      await expect(
        service.create({ ...createDto, name: mockHarness.name })
      ).rejects.toThrow(BadRequestException);
    });

    it('should allow empty testSuiteIds', async () => {
      // Arrange
      (service as any).harnesses = [];

      const createDtoWithoutSuites: CreateTestHarnessDto = {
        ...createDto,
        testSuiteIds: [],
      };

      // Act
      const result = await service.create(createDtoWithoutSuites);

      // Assert
      expect(result.testSuiteIds).toEqual([]);
    });
  });

  describe('findAll', () => {
    it('should return all test harnesses', async () => {
      // Arrange
      (service as any).harnesses = [mockHarness];

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should return empty array when no harnesses exist', async () => {
      // Arrange
      (service as any).harnesses = [];

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return harness when found', async () => {
      // Arrange
      (service as any).harnesses = [mockHarness];

      // Act
      const result = await service.findOne(mockHarness.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockHarness.id);
      expect(result.name).toBe(mockHarness.name);
    });

    it('should throw NotFoundException when harness not found', async () => {
      // Arrange
      (service as any).harnesses = [];

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateDto: UpdateTestHarnessDto = {
      name: 'Updated Harness Name',
      description: 'Updated description',
    };

    it('should successfully update a test harness', async () => {
      // Arrange
      (service as any).harnesses = [{ ...mockHarness }];

      // Act
      const result = await service.update(mockHarness.id, updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when harness not found', async () => {
      // Arrange
      (service as any).harnesses = [];

      // Act & Assert
      await expect(
        service.update('non-existent-id', updateDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should validate suites match domain when updating', async () => {
      // Arrange
      (service as any).harnesses = [{ ...mockHarness }];
      testSuitesService.findAll.mockResolvedValue([
        { ...mockSuite, domain: 'api_security' }, // Wrong domain
      ] as any);

      const updateDtoWithSuites: UpdateTestHarnessDto = {
        testSuiteIds: ['suite-1'],
      };

      // Act & Assert
      await expect(
        service.update(mockHarness.id, updateDtoWithSuites)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('delete', () => {
    it('should successfully delete a test harness', async () => {
      // Arrange
      (service as any).harnesses = [{ ...mockHarness }];

      // Act
      await service.delete(mockHarness.id);

      // Assert
      expect((service as any).harnesses.find((h: TestHarnessEntity) => h.id === mockHarness.id)).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when harness not found', async () => {
      // Arrange
      (service as any).harnesses = [];

      // Act & Assert
      await expect(
        service.delete('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });
});
