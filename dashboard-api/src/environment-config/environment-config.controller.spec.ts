/**
 * Environment Config Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EnvironmentConfigController } from './environment-config.controller';
import { EnvironmentConfigService } from './environment-config.service';
import { ValidateEnvironmentDto, ValidateSecretsDto, DetectDriftDto, ValidateEnvironmentPoliciesDto } from './dto/environment-config.dto';

describe('EnvironmentConfigController', () => {
  let controller: EnvironmentConfigController;
  let service: jest.Mocked<EnvironmentConfigService>;

  const mockValidateEnvironmentDto: ValidateEnvironmentDto = {
    environment: 'prod',
    variables: { NODE_ENV: 'production' },
    configFiles: ['config.json'],
    secrets: [],
  };

  const mockValidateSecretsDto: ValidateSecretsDto = {
    type: 'aws-secrets-manager',
    connection: {},
  };

  const mockDetectDriftDto: DetectDriftDto = {
    baselineEnvironment: 'prod' as any,
    currentEnvironment: 'staging' as any,
    variables: {},
    configFiles: [],
    currentVariables: {},
    currentConfigFiles: [],
  };

  const mockValidateEnvironmentPoliciesDto: ValidateEnvironmentPoliciesDto = {
    environment: 'prod',
    policies: [],
    isolationRules: [],
    promotionRules: [],
  };

  beforeEach(async () => {
    const mockService = {
      validateEnvironment: jest.fn().mockResolvedValue({ valid: true, errors: [] }),
      validateSecrets: jest.fn().mockResolvedValue({ valid: true, errors: [] }),
      detectDrift: jest.fn().mockResolvedValue({ hasDrift: false, differences: [] }),
      validateEnvironmentPolicies: jest.fn().mockResolvedValue({} as any), // Return type varies
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [EnvironmentConfigController],
      providers: [
        {
          provide: EnvironmentConfigService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<EnvironmentConfigController>(EnvironmentConfigController);
    service = module.get(EnvironmentConfigService) as jest.Mocked<EnvironmentConfigService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('validateEnvironment', () => {
    it('should call service.validateEnvironment with correct DTO', async () => {
      // Act
      await controller.validateEnvironment(mockValidateEnvironmentDto);

      // Assert
      expect(service.validateEnvironment).toHaveBeenCalledWith(mockValidateEnvironmentDto);
      expect(service.validateEnvironment).toHaveBeenCalledTimes(1);
    });

    it('should return validation result', async () => {
      // Act
      const result = await controller.validateEnvironment(mockValidateEnvironmentDto);

      // Assert
      expect(result).toBeDefined();
      // Result structure depends on EnvironmentConfigValidator
    });
  });

  describe('validateSecrets', () => {
    it('should call service.validateSecrets with correct DTO', async () => {
      // Act
      await controller.validateSecrets(mockValidateSecretsDto);

      // Assert
      expect(service.validateSecrets).toHaveBeenCalledWith(mockValidateSecretsDto);
      expect(service.validateSecrets).toHaveBeenCalledTimes(1);
    });

    it('should return validation result', async () => {
      // Act
      const result = await controller.validateSecrets(mockValidateSecretsDto);

      // Assert
      expect(result).toBeDefined();
      // Result structure depends on SecretsManagementValidator
    });
  });

  describe('detectDrift', () => {
    it('should call service.detectDrift with correct DTO', async () => {
      // Act
      await controller.detectDrift(mockDetectDriftDto);

      // Assert
      expect(service.detectDrift).toHaveBeenCalledWith(mockDetectDriftDto);
      expect(service.detectDrift).toHaveBeenCalledTimes(1);
    });

    it('should return drift detection result', async () => {
      // Act
      const result = await controller.detectDrift(mockDetectDriftDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.hasDrift).toBe(false);
    });
  });

  describe('validateEnvironmentPolicies', () => {
    it('should call service.validateEnvironmentPolicies with correct DTO', async () => {
      // Act
      await controller.validateEnvironmentPolicies(mockValidateEnvironmentPoliciesDto);

      // Assert
      expect(service.validateEnvironmentPolicies).toHaveBeenCalledWith(mockValidateEnvironmentPoliciesDto);
      expect(service.validateEnvironmentPolicies).toHaveBeenCalledTimes(1);
    });

    it('should return validation result', async () => {
      // Act
      const result = await controller.validateEnvironmentPolicies(mockValidateEnvironmentPoliciesDto);

      // Assert
      expect(result).toBeDefined();
      // Result structure depends on EnvironmentPolicyValidator
    });
  });
});
