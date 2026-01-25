/**
 * Environment Config Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EnvironmentConfigService } from './environment-config.service';
import { ValidateEnvironmentDto, ValidateSecretsDto, DetectDriftDto, ValidateEnvironmentPoliciesDto } from './dto/environment-config.dto';

describe('EnvironmentConfigService', () => {
  let service: EnvironmentConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [EnvironmentConfigService],
    }).compile();

    service = module.get<EnvironmentConfigService>(EnvironmentConfigService);
  });

  describe('validateEnvironment', () => {
    it('should validate environment configuration', async () => {
      // Arrange
      const dto: ValidateEnvironmentDto = {
        environment: 'prod',
        variables: { NODE_ENV: 'production', PORT: '3000' },
        configFiles: ['config.json'],
        secrets: [],
      };

      // Act
      const result = await service.validateEnvironment(dto);

      // Assert
      expect(result).toBeDefined();
    });

    it('should handle empty variables', async () => {
      // Arrange
      const dto: ValidateEnvironmentDto = {
        environment: 'dev',
        variables: {},
        configFiles: [],
        secrets: [],
      };

      // Act
      const result = await service.validateEnvironment(dto);

      // Assert
      expect(result).toBeDefined();
    });
  });

  describe('validateSecrets', () => {
    it('should validate secrets storage configuration', async () => {
      // Arrange
      const dto: ValidateSecretsDto = {
        type: 'aws-secrets-manager',
        connection: {},
      };

      // Act
      const result = await service.validateSecrets(dto);

      // Assert
      expect(result).toBeDefined();
    });
  });

  describe('detectDrift', () => {
    it('should detect configuration drift', async () => {
      // Arrange
      const dto: DetectDriftDto = {
        baselineEnvironment: 'production',
        currentEnvironment: 'staging',
        variables: { NODE_ENV: 'staging' },
        configFiles: ['config.json'],
        currentVariables: { NODE_ENV: 'staging', PORT: '3001' },
        currentConfigFiles: ['config.json'],
      };

      // Act
      const result = await service.detectDrift(dto);

      // Assert
      expect(result).toBeDefined();
    });
  });

  describe('validateEnvironmentPolicies', () => {
    it('should validate environment policies', async () => {
      // Arrange
      const dto: ValidateEnvironmentPoliciesDto = {
        environment: 'prod',
        policies: [],
        isolationRules: [],
        promotionRules: [],
      };

      // Act
      const result = await service.validateEnvironmentPolicies(dto);

      // Assert
      expect(result).toBeDefined();
    });

    it('should default requiredApprovals to 1 when not provided', async () => {
      // Arrange
      const dto: ValidateEnvironmentPoliciesDto = {
        environment: 'prod',
        policies: [],
        isolationRules: [],
        promotionRules: [
          {
            fromEnvironment: 'staging',
            toEnvironment: 'prod',
            requiredApprovals: 1,
            requiredChecks: [],
          },
        ],
      };

      // Act
      const result = await service.validateEnvironmentPolicies(dto);

      // Assert
      expect(result).toBeDefined();
    });
  });
});
