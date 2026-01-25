/**
 * Validation Targets Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ValidationTargetsService } from './validation-targets.service';
import { CreateValidationTargetDto, ValidationTargetType, ValidationTargetStatus } from './dto/create-validation-target.dto';
import { UpdateValidationTargetDto } from './dto/update-validation-target.dto';
import { CreateValidationRuleDto, RuleSeverity } from './dto/create-validation-rule.dto';
import { ValidationTargetEntity, ValidationRuleEntity } from './entities/validation-target.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('ValidationTargetsService', () => {
  let service: ValidationTargetsService;

  const createTargetDto: CreateValidationTargetDto = {
    name: 'Test Target',
    type: ValidationTargetType.SALESFORCE,
    description: 'Test target description',
    environment: 'production',
    connectionConfig: { url: 'https://test.salesforce.com' },
    baselineId: 'baseline-1',
    ruleIds: [],
  };

  const createRuleDto: CreateValidationRuleDto = {
    name: 'Test Rule',
    description: 'Test rule description',
    targetId: 'target-1',
    severity: RuleSeverity.HIGH,
    ruleConfig: { check: 'test-check' },
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [ValidationTargetsService],
    }).compile();

    service = module.get<ValidationTargetsService>(ValidationTargetsService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear data
    (service as any).targets = [];
    (service as any).rules = [];
    (service as any).results = [];
    
    // Mock loadData to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
  });

  describe('createTarget', () => {
    it('should successfully create a validation target', async () => {
      // Arrange
      (service as any).targets = [];

      // Act
      const result = await service.createTarget(createTargetDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createTargetDto.name);
      expect(result.type).toBe(createTargetDto.type);
      expect(result.environment).toBe(createTargetDto.environment);
      expect(result.status).toBe(ValidationTargetStatus.UNKNOWN);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should initialize ruleIds as empty array when not provided', async () => {
      // Arrange
      (service as any).targets = [];
      const dtoWithoutRules = { ...createTargetDto, ruleIds: undefined };

      // Act
      const result = await service.createTarget(dtoWithoutRules);

      // Assert
      expect(result.ruleIds).toEqual([]);
    });
  });

  describe('findAllTargets', () => {
    beforeEach(() => {
      (service as any).targets = [
        {
          id: 'target-1',
          name: 'Target 1',
          type: ValidationTargetType.SALESFORCE,
          status: ValidationTargetStatus.HEALTHY,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'target-2',
          name: 'Target 2',
          type: ValidationTargetType.ELASTIC_CLOUD,
          status: ValidationTargetStatus.ERRORS,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should return all validation targets', async () => {
      // Act
      const result = await service.findAllTargets();

      // Assert
      expect(result.length).toBe(2);
    });
  });

  describe('findOneTarget', () => {
    beforeEach(() => {
      (service as any).targets = [
        {
          id: 'target-1',
          name: 'Target 1',
          type: ValidationTargetType.SALESFORCE,
          status: ValidationTargetStatus.HEALTHY,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should return target when found', async () => {
      // Act
      const result = await service.findOneTarget('target-1');

      // Assert
      expect(result.id).toBe('target-1');
      expect(result.name).toBe('Target 1');
    });

    it('should throw NotFoundException when target not found', async () => {
      // Act & Assert
      await expect(
        service.findOneTarget('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateTarget', () => {
    beforeEach(() => {
      (service as any).targets = [
        {
          id: 'target-1',
          name: 'Target 1',
          type: ValidationTargetType.SALESFORCE,
          status: ValidationTargetStatus.HEALTHY,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should successfully update a target', async () => {
      // Arrange
      const updateDto: UpdateValidationTargetDto = {
        name: 'Updated Target',
        description: 'Updated description',
      };

      // Act
      const result = await service.updateTarget('target-1', updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when target not found', async () => {
      // Arrange
      (service as any).targets = [];

      // Act & Assert
      await expect(
        service.updateTarget('non-existent-id', { name: 'Updated' })
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('removeTarget', () => {
    beforeEach(() => {
      (service as any).targets = [
        {
          id: 'target-1',
          name: 'Target 1',
          type: ValidationTargetType.SALESFORCE,
          status: ValidationTargetStatus.HEALTHY,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
      (service as any).rules = [
        {
          id: 'rule-1',
          targetId: 'target-1',
          name: 'Rule 1',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should successfully remove a target and associated rules', async () => {
      // Act
      await service.removeTarget('target-1');

      // Assert
      expect((service as any).targets.find((t: ValidationTargetEntity) => t.id === 'target-1')).toBeUndefined();
      expect((service as any).rules.find((r: ValidationRuleEntity) => r.targetId === 'target-1')).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when target not found', async () => {
      // Arrange
      (service as any).targets = [];

      // Act & Assert
      await expect(
        service.removeTarget('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('runValidation', () => {
    beforeEach(() => {
      (service as any).targets = [
        {
          id: 'target-1',
          name: 'Target 1',
          type: ValidationTargetType.SALESFORCE,
          status: ValidationTargetStatus.UNKNOWN,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
      (service as any).rules = [
        {
          id: 'rule-1',
          targetId: 'target-1',
          name: 'Rule 1',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
      (service as any).results = [];
    });

    it('should run validation and update target status', async () => {
      // Act
      const result = await service.runValidation('target-1');

      // Assert
      expect(result.success).toBe(true);
      expect(result.results).toBeDefined();
      expect(result.results.length).toBeGreaterThan(0);
      const target = (service as any).targets.find((t: ValidationTargetEntity) => t.id === 'target-1');
      expect(target.lastValidationAt).toBeInstanceOf(Date);
      expect(target.status).toBeDefined();
    });

    it('should throw NotFoundException when target not found', async () => {
      // Arrange
      (service as any).targets = [];

      // Act & Assert
      await expect(
        service.runValidation('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('createRule', () => {
    beforeEach(() => {
      (service as any).targets = [
        {
          id: 'target-1',
          name: 'Target 1',
          type: ValidationTargetType.SALESFORCE,
          status: ValidationTargetStatus.HEALTHY,
          ruleIds: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
      (service as any).rules = [];
    });

    it('should successfully create a validation rule', async () => {
      // Act
      const result = await service.createRule(createRuleDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createRuleDto.name);
      expect(result.targetId).toBe(createRuleDto.targetId);
      expect(result.severity).toBe(createRuleDto.severity);
      expect(result.enabled).toBe(true); // Default enabled
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
      // Check that rule was added to target
      const target = (service as any).targets.find((t: ValidationTargetEntity) => t.id === 'target-1');
      expect(target.ruleIds).toContain(result.id);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });
  });

  describe('findRulesByTarget', () => {
    beforeEach(() => {
      (service as any).rules = [
        {
          id: 'rule-1',
          targetId: 'target-1',
          name: 'Rule 1',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'rule-2',
          targetId: 'target-1',
          name: 'Rule 2',
          enabled: false,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'rule-3',
          targetId: 'target-2',
          name: 'Rule 3',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should return rules for a specific target', async () => {
      // Act
      const result = await service.findRulesByTarget('target-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(r => r.targetId === 'target-1')).toBe(true);
    });
  });

  describe('findResultsByTarget', () => {
    beforeEach(() => {
      (service as any).results = [
        {
          id: 'result-1',
          targetId: 'target-1',
          ruleId: 'rule-1',
          status: 'passed',
          message: 'Passed',
          timestamp: new Date(),
        },
        {
          id: 'result-2',
          targetId: 'target-1',
          ruleId: 'rule-2',
          status: 'failed',
          message: 'Failed',
          timestamp: new Date(),
        },
        {
          id: 'result-3',
          targetId: 'target-2',
          ruleId: 'rule-3',
          status: 'passed',
          message: 'Passed',
          timestamp: new Date(),
        },
      ];
    });

    it('should return results for a specific target', async () => {
      // Act
      const result = await service.findResultsByTarget('target-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(r => r.targetId === 'target-1')).toBe(true);
    });
  });
});
