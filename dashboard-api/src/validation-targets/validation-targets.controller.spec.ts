/**
 * Validation Targets Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { ValidationTargetsController, ValidationRulesController } from './validation-targets.controller';
import { ValidationTargetsService } from './validation-targets.service';
import { CreateValidationTargetDto } from './dto/create-validation-target.dto';
import { UpdateValidationTargetDto } from './dto/update-validation-target.dto';
import { CreateValidationRuleDto } from './dto/create-validation-rule.dto';

describe('ValidationTargetsController', () => {
  let controller: ValidationTargetsController;
  let service: jest.Mocked<ValidationTargetsService>;

  const mockTarget = {
    id: 'target-1',
    name: 'Test Target',
    type: 'salesforce',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockRule = {
    id: 'rule-1',
    targetId: 'target-1',
    name: 'Test Rule',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockResult = {
    id: 'result-1',
    targetId: 'target-1',
    ruleId: 'rule-1',
    passed: true,
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockService = {
      createTarget: jest.fn(),
      findAllTargets: jest.fn(),
      findOneTarget: jest.fn(),
      updateTarget: jest.fn(),
      removeTarget: jest.fn(),
      runValidation: jest.fn(),
      findResultsByTarget: jest.fn(),
      findRulesByTarget: jest.fn(),
      createRule: jest.fn(),
      findOneRule: jest.fn(),
      updateRule: jest.fn(),
      removeRule: jest.fn(),
      findResultsByRule: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ValidationTargetsController, ValidationRulesController],
      providers: [
        {
          provide: ValidationTargetsService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<ValidationTargetsController>(ValidationTargetsController);
    service = module.get(ValidationTargetsService) as jest.Mocked<ValidationTargetsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createTarget', () => {
    const dto: CreateValidationTargetDto = {
      name: 'Test Target',
      type: 'salesforce' as any,
      connectionConfig: {
        instanceUrl: 'https://test.salesforce.com',
      },
    };

    it('should create a validation target', async () => {
      // Arrange
      service.createTarget.mockResolvedValue(mockTarget as any);

      // Act
      const result = await controller.createTarget(dto);

      // Assert
      expect(result).toEqual(mockTarget);
      expect(service.createTarget).toHaveBeenCalledWith(dto);
    });
  });

  describe('findAllTargets', () => {
    it('should find all validation targets', async () => {
      // Arrange
      service.findAllTargets.mockResolvedValue([mockTarget] as any);

      // Act
      const result = await controller.findAllTargets();

      // Assert
      expect(result).toEqual([mockTarget]);
      expect(service.findAllTargets).toHaveBeenCalledTimes(1);
    });
  });

  describe('findOneTarget', () => {
    it('should find one validation target', async () => {
      // Arrange
      service.findOneTarget.mockResolvedValue(mockTarget as any);

      // Act
      const result = await controller.findOneTarget('target-1');

      // Assert
      expect(result).toEqual(mockTarget);
      expect(service.findOneTarget).toHaveBeenCalledWith('target-1');
    });
  });

  describe('updateTarget', () => {
    const dto: UpdateValidationTargetDto = {
      name: 'Updated Target',
    };

    it('should update a validation target', async () => {
      // Arrange
      const updatedTarget = { ...mockTarget, ...dto };
      service.updateTarget.mockResolvedValue(updatedTarget as any);

      // Act
      const result = await controller.updateTarget('target-1', dto);

      // Assert
      expect(result).toEqual(updatedTarget);
      expect(service.updateTarget).toHaveBeenCalledWith('target-1', dto);
    });
  });

  describe('removeTarget', () => {
    it('should remove a validation target', async () => {
      // Arrange
      service.removeTarget.mockResolvedValue(undefined);

      // Act
      const result = await controller.removeTarget('target-1');

      // Assert
      expect(result).toBeUndefined();
      expect(service.removeTarget).toHaveBeenCalledWith('target-1');
    });
  });

  describe('runValidation', () => {
    it('should run validation for a target', async () => {
      // Arrange
      const validationResult = {
        success: true,
        message: 'Validation completed',
        results: [mockResult],
      };
      service.runValidation.mockResolvedValue(validationResult as any);

      // Act
      const result = await controller.runValidation('target-1');

      // Assert
      expect(result).toEqual(validationResult);
      expect(service.runValidation).toHaveBeenCalledWith('target-1');
    });
  });

  describe('getResults', () => {
    it('should get validation results for a target', async () => {
      // Arrange
      service.findResultsByTarget.mockResolvedValue([mockResult] as any);

      // Act
      const result = await controller.getResults('target-1');

      // Assert
      expect(result).toEqual([mockResult]);
      expect(service.findResultsByTarget).toHaveBeenCalledWith('target-1');
    });
  });

  describe('getRules', () => {
    it('should get validation rules for a target', async () => {
      // Arrange
      service.findRulesByTarget.mockResolvedValue([mockRule] as any);

      // Act
      const result = await controller.getRules('target-1');

      // Assert
      expect(result).toEqual([mockRule]);
      expect(service.findRulesByTarget).toHaveBeenCalledWith('target-1');
    });
  });

  describe('createRule', () => {
    const dto: CreateValidationRuleDto = {
      name: 'Test Rule',
      description: 'Test rule description',
      targetId: 'target-1',
      severity: 'high' as any,
      ruleConfig: {},
    };

    it('should create a validation rule', async () => {
      // Arrange
      service.createRule.mockResolvedValue(mockRule as any);

      // Act
      const result = await controller.createRule('target-1', dto);

      // Assert
      expect(result).toEqual(mockRule);
      expect(service.createRule).toHaveBeenCalledWith({ ...dto, targetId: 'target-1' });
    });
  });
});

describe('ValidationRulesController', () => {
  let controller: ValidationRulesController;
  let service: jest.Mocked<ValidationTargetsService>;

  const mockRule = {
    id: 'rule-1',
    targetId: 'target-1',
    name: 'Test Rule',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockResult = {
    id: 'result-1',
    targetId: 'target-1',
    ruleId: 'rule-1',
    passed: true,
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockService = {
      findOneRule: jest.fn(),
      updateRule: jest.fn(),
      removeRule: jest.fn(),
      findResultsByRule: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ValidationRulesController],
      providers: [
        {
          provide: ValidationTargetsService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<ValidationRulesController>(ValidationRulesController);
    service = module.get(ValidationTargetsService) as jest.Mocked<ValidationTargetsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findOneRule', () => {
    it('should find one validation rule', async () => {
      // Arrange
      service.findOneRule.mockResolvedValue(mockRule as any);

      // Act
      const result = await controller.findOneRule('rule-1');

      // Assert
      expect(result).toEqual(mockRule);
      expect(service.findOneRule).toHaveBeenCalledWith('rule-1');
    });
  });

  describe('updateRule', () => {
    const dto: Partial<CreateValidationRuleDto> = {
      name: 'Updated Rule',
    };

    it('should update a validation rule', async () => {
      // Arrange
      const updatedRule = { ...mockRule, ...dto };
      service.updateRule.mockResolvedValue(updatedRule as any);

      // Act
      const result = await controller.updateRule('rule-1', dto);

      // Assert
      expect(result).toEqual(updatedRule);
      expect(service.updateRule).toHaveBeenCalledWith('rule-1', dto);
    });
  });

  describe('removeRule', () => {
    it('should remove a validation rule', async () => {
      // Arrange
      service.removeRule.mockResolvedValue(undefined);

      // Act
      const result = await controller.removeRule('rule-1');

      // Assert
      expect(result).toBeUndefined();
      expect(service.removeRule).toHaveBeenCalledWith('rule-1');
    });
  });

  describe('getResults', () => {
    it('should get validation results for a rule', async () => {
      // Arrange
      service.findResultsByRule.mockResolvedValue([mockResult] as any);

      // Act
      const result = await controller.getResults('rule-1');

      // Assert
      expect(result).toEqual([mockResult]);
      expect(service.findResultsByRule).toHaveBeenCalledWith('rule-1');
    });
  });
});
