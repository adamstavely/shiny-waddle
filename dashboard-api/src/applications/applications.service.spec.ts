/**
 * Applications Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { ApplicationsService } from './applications.service';
import { TestResultsService } from '../test-results/test-results.service';
import { SecurityAuditLogService } from '../security/audit-log.service';
import { ValidatorsService } from '../validators/validators.service';
import { TestHarnessesService } from '../test-harnesses/test-harnesses.service';
import { TestBatteriesService } from '../test-batteries/test-batteries.service';
import { ContextDetectorService } from '../cicd/context-detector.service';
import { CreateApplicationDto, ApplicationType, ApplicationStatus } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { Application } from './entities/application.entity';
import * as fs from 'fs/promises';

// Mock fs module
jest.mock('fs/promises');

describe('ApplicationsService', () => {
  let service: ApplicationsService;
  let testResultsService: jest.Mocked<TestResultsService>;
  let auditLogService: jest.Mocked<SecurityAuditLogService>;
  let validatorsService: jest.Mocked<ValidatorsService>;
  let testHarnessesService: jest.Mocked<TestHarnessesService>;
  let testBatteriesService: jest.Mocked<TestBatteriesService>;
  let contextDetector: jest.Mocked<ContextDetectorService>;

  const mockApplication: Application = {
    id: 'app-1',
    name: 'Test Application',
    type: ApplicationType.API,
    status: ApplicationStatus.ACTIVE,
    baseUrl: 'https://api.example.com',
    team: 'platform-team',
    description: 'Test application description',
    config: {},
    infrastructure: {},
    validatorOverrides: {},
    registeredAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    // Create mock instances
    const mockTestResultsService = {
      getLatestResultsByApplication: jest.fn(),
    };

    const mockAuditLogService = {
      log: jest.fn(),
    };

    const mockValidatorsService = {
      findAll: jest.fn(),
    };

    const mockTestHarnessesService = {
      findByApplication: jest.fn(),
    };

    const mockTestBatteriesService = {
      findByApplication: jest.fn(),
    };

    const mockContextDetector = {
      detectContext: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApplicationsService,
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
        {
          provide: SecurityAuditLogService,
          useValue: mockAuditLogService,
        },
        {
          provide: ValidatorsService,
          useValue: mockValidatorsService,
        },
        {
          provide: TestHarnessesService,
          useValue: mockTestHarnessesService,
        },
        {
          provide: TestBatteriesService,
          useValue: mockTestBatteriesService,
        },
        {
          provide: ContextDetectorService,
          useValue: mockContextDetector,
        },
      ],
    }).compile();

    service = module.get<ApplicationsService>(ApplicationsService);
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;
    auditLogService = module.get(SecurityAuditLogService) as jest.Mocked<SecurityAuditLogService>;
    validatorsService = module.get(ValidatorsService) as jest.Mocked<ValidatorsService>;
    testHarnessesService = module.get(TestHarnessesService) as jest.Mocked<TestHarnessesService>;
    testBatteriesService = module.get(TestBatteriesService) as jest.Mocked<TestBatteriesService>;
    contextDetector = module.get(ContextDetectorService) as jest.Mocked<ContextDetectorService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);
  });

  describe('create', () => {
    const createDto: CreateApplicationDto = {
      id: 'new-app',
      name: 'New Application',
      type: ApplicationType.API,
      status: ApplicationStatus.ACTIVE,
      baseUrl: 'https://new.example.com',
      team: 'test-team',
      description: 'New application',
    };

    it('should successfully create an application', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      // Act
      const result = await service.create(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(createDto.id);
      expect(result.name).toBe(createDto.name);
      expect(result.type).toBe(createDto.type);
      expect(result.status).toBe(createDto.status);
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw ConflictException when application ID already exists', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));

      // Act & Assert
      await expect(
        service.create({ ...createDto, id: mockApplication.id })
      ).rejects.toThrow(ConflictException);
    });

    it('should validate infrastructure when provided', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      const createDtoWithInfra: CreateApplicationDto = {
        ...createDto,
        infrastructure: {
          databases: [{
            id: 'db-1',
            name: 'Test DB',
            type: 'postgresql',
            host: 'localhost',
            port: 5432,
            database: 'testdb',
          }],
        },
      };

      // Act
      const result = await service.create(createDtoWithInfra);

      // Assert
      expect(result.infrastructure).toBeDefined();
      expect(result.infrastructure?.databases).toHaveLength(1);
    });

    it('should throw BadRequestException for invalid database infrastructure', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      const createDtoWithInvalidInfra: CreateApplicationDto = {
        ...createDto,
        infrastructure: {
          databases: [{
            id: '', // Missing required fields
            name: '',
            type: 'postgresql',
            host: '',
            port: 0,
            database: '',
          }],
        },
      };

      // Act & Assert
      await expect(
        service.create(createDtoWithInvalidInfra)
      ).rejects.toThrow(BadRequestException);
    });

    it('should use default status when not provided', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      const createDtoWithoutStatus: CreateApplicationDto = {
        ...createDto,
        status: undefined,
      };

      // Act
      const result = await service.create(createDtoWithoutStatus);

      // Assert
      expect(result.status).toBe(ApplicationStatus.ACTIVE);
    });
  });

  describe('findAll', () => {
    it('should return all applications', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should return empty array when no applications exist', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toEqual([]);
    });

    it('should handle file read errors gracefully', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockRejectedValue(new Error('Read error'));

      // Act & Assert
      await expect(service.findAll()).rejects.toThrow();
    });
  });

  describe('findOne', () => {
    it('should return application when found', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));

      // Act
      const result = await service.findOne(mockApplication.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockApplication.id);
      expect(result.name).toBe(mockApplication.name);
    });

    it('should throw NotFoundException when application not found', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateDto: UpdateApplicationDto = {
      name: 'Updated Application Name',
      description: 'Updated description',
    };

    it('should successfully update an application', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));

      // Act
      const result = await service.update(mockApplication.id, updateDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when application not found', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      // Act & Assert
      await expect(
        service.update('non-existent-id', updateDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should not allow updating the ID', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));

      const updateDtoWithId: UpdateApplicationDto = {
        ...updateDto,
        id: 'new-id',
      } as any;

      // Act
      const result = await service.update(mockApplication.id, updateDtoWithId);

      // Assert
      expect(result.id).toBe(mockApplication.id); // ID should not change
    });

    it('should validate infrastructure when updating', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));

      const updateDtoWithInvalidInfra: UpdateApplicationDto = {
        infrastructure: {
          databases: [{
            id: '', // Invalid
            name: '',
            type: 'postgresql',
            host: '',
            port: 0,
            database: '',
          }],
        },
      } as any;

      // Act & Assert
      await expect(
        service.update(mockApplication.id, updateDtoWithInvalidInfra)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('remove', () => {
    it('should successfully remove an application', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));

      // Act
      await service.remove(mockApplication.id);

      // Assert
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when application not found', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      // Act & Assert
      await expect(
        service.remove('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateLastTestAt', () => {
    it('should successfully update last test date', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockApplication]));
      const testDate = new Date();

      // Act
      const result = await service.updateLastTestAt(mockApplication.id, testDate);

      // Assert
      expect(result.lastTestAt).toEqual(testDate);
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when application not found', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      // Act & Assert
      await expect(
        service.updateLastTestAt('non-existent-id', new Date())
      ).rejects.toThrow(NotFoundException);
    });
  });
});
