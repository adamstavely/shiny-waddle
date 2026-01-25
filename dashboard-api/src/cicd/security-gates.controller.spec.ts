/**
 * Security Gates Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { SecurityGatesController } from './security-gates.controller';
import { SecurityGatesService } from './security-gates.service';

describe('SecurityGatesController', () => {
  let controller: SecurityGatesController;
  let securityGatesService: jest.Mocked<SecurityGatesService>;

  const mockValidationResult = {
    passed: true,
    gates: [],
  };

  beforeEach(async () => {
    const mockSecurityGatesService = {
      validatePreMerge: jest.fn(),
      checkGates: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SecurityGatesController],
      providers: [
        {
          provide: SecurityGatesService,
          useValue: mockSecurityGatesService,
        },
      ],
    }).compile();

    controller = module.get<SecurityGatesController>(SecurityGatesController);
    securityGatesService = module.get(SecurityGatesService) as jest.Mocked<SecurityGatesService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('validatePreMerge', () => {
    const dto = {
      pr: { id: 'pr-1' },
      policies: [{ id: 'policy-1' }],
    };

    it('should validate pre-merge', async () => {
      // Arrange
      securityGatesService.validatePreMerge.mockResolvedValue(mockValidationResult as any);

      // Act
      const result = await controller.validatePreMerge(dto);

      // Assert
      expect(result).toEqual(mockValidationResult);
      expect(securityGatesService.validatePreMerge).toHaveBeenCalledWith(dto);
    });
  });

  describe('checkGates', () => {
    const dto = {
      pr: { id: 'pr-1' },
      config: { severityThreshold: 'high' },
    };

    it('should check gates', async () => {
      // Arrange
      securityGatesService.checkGates.mockResolvedValue(mockValidationResult as any);

      // Act
      const result = await controller.checkGates(dto);

      // Assert
      expect(result).toEqual(mockValidationResult);
      expect(securityGatesService.checkGates).toHaveBeenCalledWith(dto);
    });
  });
});
