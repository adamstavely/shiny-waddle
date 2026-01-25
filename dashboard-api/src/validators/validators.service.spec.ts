/**
 * Validators Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, ConflictException } from '@nestjs/common';
import { ValidatorsService } from './validators.service';
import { ValidatorDiscoveryService } from './validator-discovery.service';
import { CreateValidatorDto } from './dto/create-validator.dto';
import { UpdateValidatorDto } from './dto/update-validator.dto';
import { ValidatorEntity } from './entities/validator.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('ValidatorsService', () => {
  let service: ValidatorsService;
  let discoveryService: jest.Mocked<ValidatorDiscoveryService>;

  const mockValidator: ValidatorEntity = {
    id: 'validator-1',
    name: 'Test Validator',
    description: 'Test validator description',
    testType: 'access-control',
    version: '1.0.0',
    enabled: true,
    registeredAt: new Date(),
    updatedAt: new Date(),
    testCount: 10,
    successCount: 8,
    failureCount: 2,
  };

  const createDto: CreateValidatorDto = {
    id: 'new-validator',
    name: 'New Validator',
    description: 'New validator description',
    testType: 'api-security',
    version: '1.0.0',
    enabled: true,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockDiscoveryService = {
      discoverValidators: jest.fn().mockResolvedValue([]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ValidatorsService,
        {
          provide: ValidatorDiscoveryService,
          useValue: mockDiscoveryService,
        },
      ],
    }).compile();

    service = module.get<ValidatorsService>(ValidatorsService);
    discoveryService = module.get(ValidatorDiscoveryService) as jest.Mocked<ValidatorDiscoveryService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear validators
    (service as any).validators = [];
    
    // Mock onModuleInit to prevent auto-discovery during tests
    jest.spyOn(service, 'onModuleInit').mockResolvedValue();
  });

  describe('create', () => {
    it('should successfully create a validator', async () => {
      // Arrange
      (service as any).validators = [];

      // Act
      const result = await service.create(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(createDto.id);
      expect(result.name).toBe(createDto.name);
      expect(result.testType).toBe(createDto.testType);
      expect(result.enabled).toBe(createDto.enabled);
      expect(result.registeredAt).toBeInstanceOf(Date);
      expect(result.testCount).toBe(0);
      expect(result.successCount).toBe(0);
      expect(result.failureCount).toBe(0);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw ConflictException for duplicate validator ID', async () => {
      // Arrange
      (service as any).validators = [mockValidator];

      // Act & Assert
      await expect(
        service.create({ ...createDto, id: mockValidator.id })
      ).rejects.toThrow(ConflictException);
    });

    it('should default enabled to true when not provided', async () => {
      // Arrange
      (service as any).validators = [];
      const dtoWithoutEnabled = { ...createDto, enabled: undefined };

      // Act
      const result = await service.create(dtoWithoutEnabled as any);

      // Assert
      expect(result.enabled).toBe(true);
    });
  });

  describe('findAll', () => {
    beforeEach(() => {
      (service as any).validators = [
        mockValidator,
        { ...mockValidator, id: 'validator-2', name: 'Validator 2' },
      ];
    });

    it('should return all validators', async () => {
      // Act
      const result = await service.findAll();

      // Assert
      expect(result.length).toBe(2);
    });
  });

  describe('findOne', () => {
    beforeEach(() => {
      (service as any).validators = [mockValidator];
    });

    it('should return validator when found', async () => {
      // Act
      const result = await service.findOne(mockValidator.id);

      // Assert
      expect(result.id).toBe(mockValidator.id);
      expect(result.name).toBe(mockValidator.name);
    });

    it('should throw NotFoundException when validator not found', async () => {
      // Arrange
      (service as any).validators = [];

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    beforeEach(() => {
      (service as any).validators = [{ ...mockValidator }];
    });

    it('should successfully update a validator', async () => {
      // Arrange
      const updateDto: UpdateValidatorDto = {
        name: 'Updated Validator',
        description: 'Updated description',
        enabled: false,
      };

      // Act
      const result = await service.update(mockValidator.id, updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.enabled).toBe(updateDto.enabled);
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when validator not found', async () => {
      // Arrange
      (service as any).validators = [];

      // Act & Assert
      await expect(
        service.update('non-existent-id', { name: 'Updated' })
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update - edge cases', () => {
    beforeEach(() => {
      (service as any).validators = [{ ...mockValidator }];
    });

    it('should preserve existing fields when updating', async () => {
      // Arrange
      const updateDto: UpdateValidatorDto = {
        name: 'Updated Name',
      };

      // Act
      const result = await service.update(mockValidator.id, updateDto);

      // Assert
      expect(result.name).toBe('Updated Name');
      expect(result.testType).toBe(mockValidator.testType); // Preserved
      expect(result.version).toBe(mockValidator.version); // Preserved
    });
  });

  describe('discoverAndRegisterValidators', () => {
    beforeEach(() => {
      (service as any).validators = [];
      jest.spyOn(service as any, 'saveValidators').mockResolvedValue(undefined);
    });

    it('should discover and register new validators', async () => {
      // Arrange
      const discoveredValidators = [
        {
          id: 'discovered-1',
          name: 'Discovered Validator 1',
          testType: 'access-control',
          version: '1.0.0',
          description: 'Discovered validator',
          enabled: true,
          registeredAt: new Date(),
          updatedAt: new Date(),
          testCount: 0,
          successCount: 0,
          failureCount: 0,
        },
      ];
      discoveryService.discoverValidators.mockResolvedValue(discoveredValidators as any);

      // Act
      const result = await service.discoverAndRegisterValidators();

      // Assert
      // The discovered count is calculated before adding to array, so it should be 1
      expect(result.message).toContain('Discovered 1 validators');
      expect((service as any).validators.length).toBe(1);
      expect((service as any).validators[0].id).toBe('discovered-1');
    });

    it('should not duplicate existing validators', async () => {
      // Arrange
      (service as any).validators = [mockValidator];
      discoveryService.discoverValidators.mockResolvedValue([mockValidator] as any);

      // Act
      const result = await service.discoverAndRegisterValidators();

      // Assert
      expect(result.discovered).toBe(0);
      expect((service as any).validators.length).toBe(1);
    });

    it('should update metadata for existing validators with new versions', async () => {
      // Arrange
      (service as any).validators = [{ ...mockValidator, version: '1.0.0' }];
      const updatedValidator = { ...mockValidator, version: '2.0.0', description: 'Updated description' };
      discoveryService.discoverValidators.mockResolvedValue([updatedValidator] as any);

      // Act
      await service.discoverAndRegisterValidators();

      // Assert
      expect((service as any).validators[0].version).toBe('2.0.0');
      expect((service as any).validators[0].description).toBe('Updated description');
    });
  });
});
