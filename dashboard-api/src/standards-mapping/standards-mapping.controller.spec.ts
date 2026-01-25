/**
 * Standards Mapping Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { StandardsMappingController } from './standards-mapping.controller';
import { StandardsMappingService } from './standards-mapping.service';
import { CreateMappingDto } from './dto/create-mapping.dto';

describe('StandardsMappingController', () => {
  let controller: StandardsMappingController;
  let standardsMappingService: jest.Mocked<StandardsMappingService>;

  const mockStandard = {
    id: 'nist-800-207',
    name: 'NIST 800-207',
    mappings: [],
  };

  const mockMapping = {
    id: 'mapping-1',
    standardId: 'nist-800-207',
    policyId: 'policy-1',
  };

  beforeEach(async () => {
    const mockStandardsMappingService = {
      getStandards: jest.fn(),
      getMappings: jest.fn(),
      createMapping: jest.fn(),
      deleteMapping: jest.fn(),
      getStandardsForPolicy: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [StandardsMappingController],
      providers: [
        {
          provide: StandardsMappingService,
          useValue: mockStandardsMappingService,
        },
      ],
    }).compile();

    controller = module.get<StandardsMappingController>(StandardsMappingController);
    standardsMappingService = module.get(StandardsMappingService) as jest.Mocked<StandardsMappingService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getStandards', () => {
    it('should get all standards', async () => {
      // Arrange
      standardsMappingService.getStandards.mockResolvedValue([mockStandard] as any);

      // Act
      const result = await controller.getStandards();

      // Assert
      expect(result).toEqual([mockStandard]);
      expect(standardsMappingService.getStandards).toHaveBeenCalledTimes(1);
    });
  });

  describe('getMappings', () => {
    it('should get mappings for a standard', async () => {
      // Arrange
      standardsMappingService.getMappings.mockResolvedValue([mockMapping] as any);

      // Act
      const result = await controller.getMappings('nist-800-207');

      // Assert
      expect(result).toEqual([mockMapping]);
      expect(standardsMappingService.getMappings).toHaveBeenCalledWith('nist-800-207');
    });
  });

  describe('createMapping', () => {
    const dto: CreateMappingDto = {
      policyId: 'policy-1',
      controlId: 'control-1',
      controlName: 'Control 1',
      mappingType: 'direct' as any,
    };

    it('should create a mapping', async () => {
      // Arrange
      standardsMappingService.createMapping.mockResolvedValue(mockMapping as any);

      // Act
      const result = await controller.createMapping('nist-800-207', dto);

      // Assert
      expect(result).toEqual(mockMapping);
      expect(standardsMappingService.createMapping).toHaveBeenCalledWith('nist-800-207', dto);
    });
  });

  describe('deleteMapping', () => {
    it('should delete a mapping', async () => {
      // Arrange
      standardsMappingService.deleteMapping.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteMapping('nist-800-207', 'mapping-1');

      // Assert
      expect(result).toBeUndefined();
      expect(standardsMappingService.deleteMapping).toHaveBeenCalledWith('nist-800-207', 'mapping-1');
    });
  });

  describe('getStandardsForPolicy', () => {
    it('should get standards for a policy', async () => {
      // Arrange
      standardsMappingService.getStandardsForPolicy.mockResolvedValue([mockStandard] as any);

      // Act
      const result = await controller.getStandardsForPolicy('policy-1');

      // Assert
      expect(result).toEqual([mockStandard]);
      expect(standardsMappingService.getStandardsForPolicy).toHaveBeenCalledWith('policy-1');
    });
  });
});
