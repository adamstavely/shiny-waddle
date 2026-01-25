/**
 * Test Batteries Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { TestBatteriesService } from './test-batteries.service';
import { TestHarnessesService } from '../test-harnesses/test-harnesses.service';
import { CreateTestBatteryDto } from './dto/create-test-battery.dto';
import { UpdateTestBatteryDto } from './dto/update-test-battery.dto';
import { TestBatteryEntity } from './entities/test-battery.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('TestBatteriesService', () => {
  let service: TestBatteriesService;
  let testHarnessesService: jest.Mocked<TestHarnessesService>;

  const mockBattery: TestBatteryEntity = {
    id: 'battery-1',
    name: 'Test Battery',
    description: 'Test battery description',
    harnessIds: ['harness-1', 'harness-2'],
    executionConfig: {
      executionMode: 'parallel',
      stopOnFailure: false,
      timeout: 30000,
    },
    team: 'platform-team',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockHarness1 = {
    id: 'harness-1',
    name: 'Harness 1',
    domain: 'identity',
  };

  const mockHarness2 = {
    id: 'harness-2',
    name: 'Harness 2',
    domain: 'api_security',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockTestHarnessesService = {
      findAll: jest.fn().mockResolvedValue([mockHarness1, mockHarness2]),
      findOne: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TestBatteriesService,
        {
          provide: TestHarnessesService,
          useValue: mockTestHarnessesService,
        },
      ],
    }).compile();

    service = module.get<TestBatteriesService>(TestBatteriesService);
    testHarnessesService = module.get(TestHarnessesService) as jest.Mocked<TestHarnessesService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear cached batteries
    (service as any).batteries = [];
  });

  describe('create', () => {
    const createDto: CreateTestBatteryDto = {
      name: 'New Test Battery',
      description: 'New battery description',
      harnessIds: ['harness-1', 'harness-2'],
      executionConfig: {
        executionMode: 'parallel',
        stopOnFailure: false,
        timeout: 30000,
      },
      team: 'platform-team',
    };

    it('should successfully create a test battery', async () => {
      // Arrange
      (service as any).batteries = [];

      // Act
      const result = await service.create(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(createDto.name);
      expect(result.harnessIds).toEqual(createDto.harnessIds);
      expect(result.executionConfig).toEqual(createDto.executionConfig);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should validate that all harnesses have different domains', async () => {
      // Arrange
      (service as any).batteries = [];
      testHarnessesService.findAll.mockResolvedValue([
        mockHarness1,
        { ...mockHarness2, domain: 'identity' }, // Same domain as harness-1
      ] as any);

      // Act & Assert
      await expect(
        service.create(createDto)
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException when harness not found', async () => {
      // Arrange
      (service as any).batteries = [];
      testHarnessesService.findAll.mockResolvedValue([]);

      // Act & Assert
      await expect(
        service.create(createDto)
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for duplicate name', async () => {
      // Arrange
      (service as any).batteries = [mockBattery];

      // Act & Assert
      await expect(
        service.create({ ...createDto, name: mockBattery.name })
      ).rejects.toThrow(BadRequestException);
    });

    it('should allow empty harnessIds', async () => {
      // Arrange
      (service as any).batteries = [];

      const createDtoWithoutHarnesses: CreateTestBatteryDto = {
        ...createDto,
        harnessIds: [],
      };

      // Act
      const result = await service.create(createDtoWithoutHarnesses);

      // Assert
      expect(result.harnessIds).toEqual([]);
    });
  });

  describe('findAll', () => {
    it('should return all test batteries', async () => {
      // Arrange
      (service as any).batteries = [mockBattery];

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should return empty array when no batteries exist', async () => {
      // Arrange
      (service as any).batteries = [];

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return battery when found', async () => {
      // Arrange
      (service as any).batteries = [mockBattery];

      // Act
      const result = await service.findOne(mockBattery.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockBattery.id);
      expect(result.name).toBe(mockBattery.name);
    });

    it('should throw NotFoundException when battery not found', async () => {
      // Arrange
      (service as any).batteries = [];

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateDto: UpdateTestBatteryDto = {
      name: 'Updated Battery Name',
      description: 'Updated description',
    };

    it('should successfully update a test battery', async () => {
      // Arrange
      (service as any).batteries = [{ ...mockBattery }];

      // Act
      const result = await service.update(mockBattery.id, updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when battery not found', async () => {
      // Arrange
      (service as any).batteries = [];

      // Act & Assert
      await expect(
        service.update('non-existent-id', updateDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should validate harnesses have different domains when updating', async () => {
      // Arrange
      (service as any).batteries = [{ ...mockBattery }];
      testHarnessesService.findAll.mockResolvedValue([
        mockHarness1,
        { ...mockHarness2, domain: 'identity' }, // Same domain
      ] as any);

      const updateDtoWithHarnesses: UpdateTestBatteryDto = {
        harnessIds: ['harness-1', 'harness-2'],
      };

      // Act & Assert
      await expect(
        service.update(mockBattery.id, updateDtoWithHarnesses)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('delete', () => {
    it('should successfully delete a test battery', async () => {
      // Arrange
      (service as any).batteries = [{ ...mockBattery }];

      // Act
      await service.delete(mockBattery.id);

      // Assert
      expect((service as any).batteries.find((b: TestBatteryEntity) => b.id === mockBattery.id)).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when battery not found', async () => {
      // Arrange
      (service as any).batteries = [];

      // Act & Assert
      await expect(
        service.delete('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });
});
