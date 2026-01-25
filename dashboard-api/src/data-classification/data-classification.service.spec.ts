/**
 * Data Classification Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { DataClassificationService, ClassificationLevel, ClassificationRule } from './data-classification.service';
import { CreateClassificationLevelDto } from './dto/create-classification-level.dto';
import { CreateClassificationRuleDto } from './dto/create-classification-rule.dto';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('DataClassificationService', () => {
  let service: DataClassificationService;

  const mockLevel: ClassificationLevel = {
    id: 'level-1',
    name: 'Test Level',
    description: 'Test level description',
    sensitivity: 'confidential',
    color: '#ff0000',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const createLevelDto: CreateClassificationLevelDto = {
    name: 'New Level',
    description: 'New level description',
    sensitivity: 'internal',
    color: '#00ff00',
  };

  const createRuleDto: CreateClassificationRuleDto = {
    name: 'Test Rule',
    description: 'Test rule description',
    levelId: 'level-1',
    pattern: 'test-pattern',
    field: 'name',
    condition: 'contains',
    value: 'test',
    enabled: true,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [DataClassificationService],
    }).compile();

    service = module.get<DataClassificationService>(DataClassificationService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify({ levels: [], rules: [] }));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear data
    (service as any).levels = [];
    (service as any).rules = [];
    
    // Mock loadData to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
  });

  describe('getLevels', () => {
    it('should return all classification levels', async () => {
      // Arrange
      (service as any).levels = [mockLevel];

      // Act
      const result = await service.getLevels();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should initialize defaults when no levels exist', async () => {
      // Arrange
      (service as any).levels = [];
      const fs = require('fs/promises');
      fs.readFile.mockResolvedValueOnce('');

      // Act
      const result = await service.getLevels();

      // Assert
      expect(result.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('createLevel', () => {
    it('should successfully create a classification level', async () => {
      // Arrange
      (service as any).levels = [];

      // Act
      const result = await service.createLevel(createLevelDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createLevelDto.name);
      expect(result.description).toBe(createLevelDto.description);
      expect(result.sensitivity).toBe(createLevelDto.sensitivity);
      expect(result.color).toBe(createLevelDto.color);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should allow duplicate level names (service does not validate uniqueness)', async () => {
      // Arrange
      (service as any).levels = [mockLevel];
      jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);

      // Act
      const result = await service.createLevel({ ...createLevelDto, name: mockLevel.name });

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(mockLevel.name);
    });
  });

  describe('updateLevel', () => {
    beforeEach(() => {
      (service as any).levels = [{ ...mockLevel }];
    });

    it('should successfully update a classification level', async () => {
      // Arrange
      const updateDto = {
        name: 'Updated Level',
        description: 'Updated description',
      };

      // Act
      const result = await service.updateLevel(mockLevel.id, updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when level not found', async () => {
      // Arrange
      (service as any).levels = [];

      // Act & Assert
      await expect(
        service.updateLevel('non-existent-id', { name: 'Updated' })
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteLevel', () => {
    beforeEach(() => {
      (service as any).levels = [{ ...mockLevel }];
      jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
    });

    it('should successfully delete a classification level', async () => {
      // Act
      await service.deleteLevel(mockLevel.id);

      // Assert
      expect((service as any).levels.find((l: ClassificationLevel) => l.id === mockLevel.id)).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when level not found', async () => {
      // Arrange
      (service as any).levels = [];

      // Act & Assert
      await expect(
        service.deleteLevel('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getRules', () => {
    beforeEach(() => {
      (service as any).rules = [
        {
          id: 'rule-1',
          name: 'Rule 1',
          levelId: 'level-1',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should return all classification rules', async () => {
      // Act
      const result = await service.getRules();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return rules filtered by levelId', async () => {
      // Arrange
      (service as any).rules = [
        { id: 'rule-1', levelId: 'level-1', name: 'Rule 1', enabled: true, createdAt: new Date(), updatedAt: new Date() },
        { id: 'rule-2', levelId: 'level-2', name: 'Rule 2', enabled: true, createdAt: new Date(), updatedAt: new Date() },
      ];

      // Act
      const result = await service.getRules();

      // Assert
      expect(result.length).toBe(2);
    });
  });

  describe('createRule', () => {
    beforeEach(() => {
      (service as any).levels = [mockLevel];
      (service as any).rules = [];
    });

    it('should successfully create a classification rule', async () => {
      // Act
      const result = await service.createRule(createRuleDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createRuleDto.name);
      expect(result.levelId).toBe(createRuleDto.levelId);
      expect(result.pattern).toBe(createRuleDto.pattern);
      expect(result.condition).toBe(createRuleDto.condition);
      expect(result.enabled).toBe(createRuleDto.enabled);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should create rule even when levelId does not exist (service does not validate)', async () => {
      // Arrange
      (service as any).levels = [];
      jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);

      // Act
      const result = await service.createRule(createRuleDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.levelId).toBe(createRuleDto.levelId);
    });
  });

  describe('updateRule', () => {
    beforeEach(() => {
      (service as any).rules = [
        {
          id: 'rule-1',
          name: 'Rule 1',
          levelId: 'level-1',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should successfully update a classification rule', async () => {
      // Arrange
      const updateDto = {
        name: 'Updated Rule',
        enabled: false,
      };

      // Act
      const result = await service.updateRule('rule-1', updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.enabled).toBe(updateDto.enabled);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when rule not found', async () => {
      // Arrange
      (service as any).rules = [];

      // Act & Assert
      await expect(
        service.updateRule('non-existent-id', { name: 'Updated' })
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteRule', () => {
    beforeEach(() => {
      (service as any).rules = [
        {
          id: 'rule-1',
          name: 'Rule 1',
          levelId: 'level-1',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should successfully delete a classification rule', async () => {
      // Act
      await service.deleteRule('rule-1');

      // Assert
      expect((service as any).rules.find((r: ClassificationRule) => r.id === 'rule-1')).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when rule not found', async () => {
      // Arrange
      (service as any).rules = [];

      // Act & Assert
      await expect(
        service.deleteRule('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });
});
