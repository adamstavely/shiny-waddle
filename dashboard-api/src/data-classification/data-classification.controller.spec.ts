/**
 * Data Classification Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { DataClassificationController } from './data-classification.controller';
import { DataClassificationService } from './data-classification.service';
import { CreateClassificationLevelDto } from './dto/create-classification-level.dto';
import { CreateClassificationRuleDto } from './dto/create-classification-rule.dto';

describe('DataClassificationController', () => {
  let controller: DataClassificationController;
  let dataClassificationService: jest.Mocked<DataClassificationService>;

  const mockLevel = {
    id: 'level-1',
    name: 'Public',
    description: 'Public data',
    sensitivity: 'public' as const,
    color: '#00ff00',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockRule = {
    id: 'rule-1',
    name: 'SSN Rule',
    description: 'Detects SSN patterns',
    levelId: 'level-1',
    pattern: '\\d{3}-\\d{2}-\\d{4}',
    condition: 'matches' as const,
    value: '\\d{3}-\\d{2}-\\d{4}',
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockDataClassificationService = {
      getLevels: jest.fn(),
      createLevel: jest.fn(),
      updateLevel: jest.fn(),
      deleteLevel: jest.fn(),
      getRules: jest.fn(),
      createRule: jest.fn(),
      updateRule: jest.fn(),
      deleteRule: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DataClassificationController],
      providers: [
        {
          provide: DataClassificationService,
          useValue: mockDataClassificationService,
        },
      ],
    }).compile();

    controller = module.get<DataClassificationController>(DataClassificationController);
    dataClassificationService = module.get(DataClassificationService) as jest.Mocked<DataClassificationService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getLevels', () => {
    it('should get all classification levels', async () => {
      // Arrange
      dataClassificationService.getLevels.mockResolvedValue([mockLevel]);

      // Act
      const result = await controller.getLevels();

      // Assert
      expect(result).toEqual([mockLevel]);
      expect(dataClassificationService.getLevels).toHaveBeenCalledTimes(1);
    });
  });

  describe('createLevel', () => {
    const dto: CreateClassificationLevelDto = {
      name: 'Public',
      description: 'Public data',
      sensitivity: 'public' as any,
    };

    it('should create a classification level', async () => {
      // Arrange
      dataClassificationService.createLevel.mockResolvedValue(mockLevel);

      // Act
      const result = await controller.createLevel(dto);

      // Assert
      expect(result).toEqual(mockLevel);
      expect(dataClassificationService.createLevel).toHaveBeenCalledWith(dto);
    });
  });

  describe('updateLevel', () => {
    const updates: Partial<CreateClassificationLevelDto> = {
      description: 'Updated description',
    };

    it('should update a classification level', async () => {
      // Arrange
      const updatedLevel = { ...mockLevel, ...updates };
      dataClassificationService.updateLevel.mockResolvedValue(updatedLevel);

      // Act
      const result = await controller.updateLevel('level-1', updates);

      // Assert
      expect(result).toEqual(updatedLevel);
      expect(dataClassificationService.updateLevel).toHaveBeenCalledWith('level-1', updates);
    });
  });

  describe('deleteLevel', () => {
    it('should delete a classification level', async () => {
      // Arrange
      dataClassificationService.deleteLevel.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteLevel('level-1');

      // Assert
      expect(result).toBeUndefined();
      expect(dataClassificationService.deleteLevel).toHaveBeenCalledWith('level-1');
    });
  });

  describe('getRules', () => {
    it('should get all classification rules', async () => {
      // Arrange
      dataClassificationService.getRules.mockResolvedValue([mockRule]);

      // Act
      const result = await controller.getRules();

      // Assert
      expect(result).toEqual([mockRule]);
      expect(dataClassificationService.getRules).toHaveBeenCalledTimes(1);
    });
  });

  describe('createRule', () => {
    const dto: CreateClassificationRuleDto = {
      name: 'SSN Rule',
      description: 'Detects SSN patterns',
      levelId: 'level-1',
      pattern: '\\d{3}-\\d{2}-\\d{4}',
      condition: 'matches' as any,
      value: '\\d{3}-\\d{2}-\\d{4}',
    };

    it('should create a classification rule', async () => {
      // Arrange
      dataClassificationService.createRule.mockResolvedValue(mockRule);

      // Act
      const result = await controller.createRule(dto);

      // Assert
      expect(result).toEqual(mockRule);
      expect(dataClassificationService.createRule).toHaveBeenCalledWith(dto);
    });
  });

  describe('updateRule', () => {
    const updates: Partial<CreateClassificationRuleDto> = {
      pattern: '\\d{4}-\\d{4}-\\d{4}',
      value: '\\d{4}-\\d{4}-\\d{4}',
    };

    it('should update a classification rule', async () => {
      // Arrange
      const updatedRule = { ...mockRule, pattern: '\\d{4}-\\d{4}-\\d{4}', value: '\\d{4}-\\d{4}-\\d{4}' };
      dataClassificationService.updateRule.mockResolvedValue(updatedRule);

      // Act
      const result = await controller.updateRule('rule-1', updates);

      // Assert
      expect(result).toEqual(updatedRule);
      expect(dataClassificationService.updateRule).toHaveBeenCalledWith('rule-1', updates);
    });
  });

  describe('deleteRule', () => {
    it('should delete a classification rule', async () => {
      // Arrange
      dataClassificationService.deleteRule.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteRule('rule-1');

      // Assert
      expect(result).toBeUndefined();
      expect(dataClassificationService.deleteRule).toHaveBeenCalledWith('rule-1');
    });
  });
});
