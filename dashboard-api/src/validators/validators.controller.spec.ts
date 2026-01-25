/**
 * Validators Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { ValidatorsController } from './validators.controller';
import { ValidatorsService } from './validators.service';
import { CreateValidatorDto } from './dto/create-validator.dto';
import { UpdateValidatorDto } from './dto/update-validator.dto';

describe('ValidatorsController', () => {
  let controller: ValidatorsController;
  let validatorsService: jest.Mocked<ValidatorsService>;

  const mockValidator = {
    id: 'validator-1',
    name: 'Test Validator',
    description: 'Test validator description',
    testType: 'access-control',
    version: '1.0.0',
    enabled: true,
    registeredAt: new Date(),
    testCount: 0,
    successCount: 0,
    failureCount: 0,
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockValidatorsService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findByType: jest.fn(),
      findEnabled: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
      testConnection: jest.fn(),
      enable: jest.fn(),
      disable: jest.fn(),
      discoverAndRegisterValidators: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ValidatorsController],
      providers: [
        {
          provide: ValidatorsService,
          useValue: mockValidatorsService,
        },
      ],
    }).compile();

    controller = module.get<ValidatorsController>(ValidatorsController);
    validatorsService = module.get(ValidatorsService) as jest.Mocked<ValidatorsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    const dto: CreateValidatorDto = {
      id: 'validator-1',
      name: 'Test Validator',
      description: 'Test validator description',
      testType: 'access-control',
      version: '1.0.0',
    };

    it('should create a validator', async () => {
      // Arrange
      validatorsService.create.mockResolvedValue(mockValidator);

      // Act
      const result = await controller.create(dto);

      // Assert
      expect(result).toEqual(mockValidator);
      expect(validatorsService.create).toHaveBeenCalledWith(dto);
    });
  });

  describe('findAll', () => {
    it('should find all validators', async () => {
      // Arrange
      validatorsService.findAll.mockResolvedValue([mockValidator]);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([mockValidator]);
      expect(validatorsService.findAll).toHaveBeenCalledTimes(1);
    });

    it('should find validators by type', async () => {
      // Arrange
      validatorsService.findByType.mockResolvedValue([mockValidator]);

      // Act
      const result = await controller.findAll('access-control');

      // Assert
      expect(result).toEqual([mockValidator]);
      expect(validatorsService.findByType).toHaveBeenCalledWith('access-control');
    });

    it('should find enabled validators', async () => {
      // Arrange
      validatorsService.findEnabled.mockResolvedValue([mockValidator]);

      // Act
      const result = await controller.findAll(undefined, 'true');

      // Assert
      expect(result).toEqual([mockValidator]);
      expect(validatorsService.findEnabled).toHaveBeenCalledTimes(1);
    });
  });

  describe('findOne', () => {
    it('should find one validator', async () => {
      // Arrange
      validatorsService.findOne.mockResolvedValue(mockValidator);

      // Act
      const result = await controller.findOne('validator-1');

      // Assert
      expect(result).toEqual(mockValidator);
      expect(validatorsService.findOne).toHaveBeenCalledWith('validator-1');
    });
  });

  describe('update', () => {
    const dto: UpdateValidatorDto = {
      name: 'Updated Validator',
    };

    it('should update a validator', async () => {
      // Arrange
      const updatedValidator = { ...mockValidator, ...dto };
      validatorsService.update.mockResolvedValue(updatedValidator);

      // Act
      const result = await controller.update('validator-1', dto);

      // Assert
      expect(result).toEqual(updatedValidator);
      expect(validatorsService.update).toHaveBeenCalledWith('validator-1', dto);
    });
  });

  describe('remove', () => {
    it('should remove a validator', async () => {
      // Arrange
      validatorsService.remove.mockResolvedValue(undefined);

      // Act
      const result = await controller.remove('validator-1');

      // Assert
      expect(result).toBeUndefined();
      expect(validatorsService.remove).toHaveBeenCalledWith('validator-1');
    });
  });

  describe('testConnection', () => {
    it('should test validator connection', async () => {
      // Arrange
      const testResult = { success: true, message: 'Connection successful' };
      validatorsService.testConnection.mockResolvedValue(testResult);

      // Act
      const result = await controller.testConnection('validator-1');

      // Assert
      expect(result).toEqual(testResult);
      expect(validatorsService.testConnection).toHaveBeenCalledWith('validator-1');
    });
  });

  describe('enable', () => {
    it('should enable a validator', async () => {
      // Arrange
      const enabledValidator = { ...mockValidator, enabled: true };
      validatorsService.enable.mockResolvedValue(enabledValidator);

      // Act
      const result = await controller.enable('validator-1');

      // Assert
      expect(result).toEqual(enabledValidator);
      expect(validatorsService.enable).toHaveBeenCalledWith('validator-1');
    });
  });

  describe('disable', () => {
    it('should disable a validator', async () => {
      // Arrange
      const disabledValidator = { ...mockValidator, enabled: false };
      validatorsService.disable.mockResolvedValue(disabledValidator);

      // Act
      const result = await controller.disable('validator-1');

      // Assert
      expect(result).toEqual(disabledValidator);
      expect(validatorsService.disable).toHaveBeenCalledWith('validator-1');
    });
  });

  describe('discover', () => {
    it('should discover and register validators', async () => {
      // Arrange
      const discoveryResult = { message: 'Discovery completed', discovered: 5 };
      validatorsService.discoverAndRegisterValidators.mockResolvedValue(discoveryResult);

      // Act
      const result = await controller.discover();

      // Assert
      expect(result).toEqual(discoveryResult);
      expect(validatorsService.discoverAndRegisterValidators).toHaveBeenCalledTimes(1);
    });
  });
});
