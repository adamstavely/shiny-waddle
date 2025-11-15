import { Injectable, Logger } from '@nestjs/common';
import { EnvironmentConfigValidator, EnvironmentConfig } from '../../../services/environment-config-validator';
import { SecretsManagementValidator, SecretsManagerConfig } from '../../../services/secrets-management-validator';
import { ConfigDriftDetector } from '../../../services/config-drift-detector';
import { EnvironmentPolicyValidator, EnvironmentPolicy } from '../../../services/environment-policy-validator';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import {
  ValidateEnvironmentDto,
  ValidateSecretsDto,
  DetectDriftDto,
  ValidateEnvironmentPoliciesDto,
} from './dto/environment-config.dto';

@Injectable()
export class EnvironmentConfigService {
  private readonly logger = new Logger(EnvironmentConfigService.name);
  private envValidator: EnvironmentConfigValidator;
  private secretsValidator: SecretsManagementValidator;
  private driftDetector: ConfigDriftDetector;
  private policyValidator: EnvironmentPolicyValidator;

  constructor() {
    this.envValidator = new EnvironmentConfigValidator();
    this.secretsValidator = new SecretsManagementValidator();
    this.driftDetector = new ConfigDriftDetector();
    this.policyValidator = new EnvironmentPolicyValidator();
  }

  async validateEnvironment(dto: ValidateEnvironmentDto) {
    try {
      const config: EnvironmentConfig = {
        environment: dto.environment,
        variables: dto.variables || {},
        configFiles: dto.configFiles || [],
        secrets: dto.secrets || [],
      };

      return await this.envValidator.validateEnvironmentVariables(config);
    } catch (error: any) {
      this.logger.error(`Error validating environment: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException('Failed to validate environment', { originalError: error.message });
    }
  }

  async validateSecrets(dto: ValidateSecretsDto) {
    try {
      const config: SecretsManagerConfig = {
        type: dto.type,
        connection: dto.connection || {},
      };

      return await this.secretsValidator.validateSecretsStorage(config);
    } catch (error: any) {
      this.logger.error(`Error validating secrets: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to validate secrets', { originalError: error.message });
    }
  }

  async detectDrift(dto: DetectDriftDto) {
    try {
      const baseline = await this.driftDetector.createBaseline(dto.baselineEnvironment, {
        environment: dto.currentEnvironment,
        variables: dto.variables || {},
        configFiles: dto.configFiles || [],
        secrets: [],
      });

      const current: EnvironmentConfig = {
        environment: dto.currentEnvironment,
        variables: dto.currentVariables || {},
        configFiles: dto.currentConfigFiles || [],
        secrets: [],
      };

      return await this.driftDetector.detectDrift(baseline, current);
    } catch (error: any) {
      this.logger.error(`Error detecting drift: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to detect drift', { originalError: error.message });
    }
  }

  async validateEnvironmentPolicies(dto: ValidateEnvironmentPoliciesDto) {
    try {
      const policy: EnvironmentPolicy = {
        environment: dto.environment,
        policies: dto.policies || [],
        isolationRules: dto.isolationRules || [],
        promotionRules: dto.promotionRules || [],
      };

      return await this.policyValidator.validateEnvironmentPolicies(policy);
    } catch (error: any) {
      this.logger.error(`Error validating environment policies: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to validate environment policies', { originalError: error.message });
    }
  }
}

