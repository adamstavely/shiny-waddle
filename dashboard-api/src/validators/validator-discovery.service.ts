import { Injectable, Logger } from '@nestjs/common';
import { ValidatorEntity } from './entities/validator.entity';
import { BaseValidator } from '../../../heimdall-framework/core/base-validator';

// Import all validators explicitly
import { ABACCorrectnessValidator } from '../../../heimdall-framework/validators/abac-correctness-validator';
import { AccessControlValidatorAdapter } from '../../../heimdall-framework/validators/access-control-validator-adapter';
import { SalesforceValidator } from '../../../heimdall-framework/validators/example-salesforce-validator';
import { SalesforceExperienceCloudValidator } from '../../../heimdall-framework/validators/salesforce-experience-cloud-validator';

/**
 * Validator Discovery Service
 * 
 * Automatically discovers and registers validators from the heimdall-framework/validators directory
 */
@Injectable()
export class ValidatorDiscoveryService {
  private readonly logger = new Logger(ValidatorDiscoveryService.name);

  /**
   * List of all validator classes to discover
   */
  private readonly validatorClasses: (typeof BaseValidator)[] = [
    ABACCorrectnessValidator,
    AccessControlValidatorAdapter,
    SalesforceValidator,
    SalesforceExperienceCloudValidator,
  ];

  /**
   * Discover and register all validators from the framework
   */
  async discoverValidators(): Promise<ValidatorEntity[]> {
    const discoveredValidators: ValidatorEntity[] = [];

    try {
      for (const ValidatorClass of this.validatorClasses) {
        try {
          const validatorEntity = await this.registerValidator(ValidatorClass);
          if (validatorEntity) {
            discoveredValidators.push(validatorEntity);
          }
        } catch (error: any) {
          this.logger.warn(`Failed to register validator ${ValidatorClass.name}: ${error.message}`);
        }
      }

      this.logger.log(`Discovered ${discoveredValidators.length} validators from framework`);
      return discoveredValidators;
    } catch (error: any) {
      this.logger.error(`Error discovering validators: ${error.message}`, error.stack);
      return [];
    }
  }

  /**
   * Get minimal config for a validator based on its type
   */
  private getMinimalConfig(ValidatorClass: typeof BaseValidator): any {
    const className = ValidatorClass.name;
    
    // Provide minimal valid configs for validators that need them
    if (className === 'SalesforceExperienceCloudValidator') {
      return {
        url: 'https://placeholder.example.com', // Required field, placeholder value
      };
    }
    
    if (className === 'ABACCorrectnessValidator') {
      return {
        accessControlConfig: {
          policyMode: 'abac' as const,
          abacPolicies: [],
        },
      };
    }
    
    if (className === 'AccessControlValidatorAdapter') {
      return {
        accessControlConfig: {
          policyMode: 'rbac' as const,
        },
      };
    }
    
    if (className === 'SalesforceValidator') {
      return {
        connection: {
          username: '',
          password: '',
        },
        rules: [],
      };
    }
    
    // Default: empty config
    return {};
  }

  /**
   * Register a single validator class
   */
  private async registerValidator(
    ValidatorClass: typeof BaseValidator
  ): Promise<ValidatorEntity | null> {
    try {
      // Try to instantiate with minimal config
      const minimalConfig = this.getMinimalConfig(ValidatorClass);
      let tempInstance: BaseValidator | null = null;
      let instantiationError: Error | null = null;
      
      try {
        tempInstance = new (ValidatorClass as any)(minimalConfig);
        this.logger.debug(`Successfully instantiated ${ValidatorClass.name} with minimal config`);
      } catch (instError: any) {
        instantiationError = instError;
        this.logger.debug(`Failed to instantiate ${ValidatorClass.name} with minimal config: ${instError.message}`);
        
        // Try with empty config
        try {
          tempInstance = new (ValidatorClass as any)({});
          this.logger.debug(`Successfully instantiated ${ValidatorClass.name} with empty config`);
        } catch (emptyError: any) {
          this.logger.debug(`Failed to instantiate ${ValidatorClass.name} with empty config: ${emptyError.message}`);
        }
      }

      if (!tempInstance) {
        // If we can't instantiate, try to create a basic entry from class name
        this.logger.warn(`Could not instantiate ${ValidatorClass.name}, creating basic entry`);
        const className = ValidatorClass.name;
        const validatorEntity: ValidatorEntity = {
          id: className.toLowerCase().replace(/validator$/i, '').replace(/([A-Z])/g, '-$1').toLowerCase().replace(/^-/, ''),
          name: className.replace(/([A-Z])/g, ' $1').trim(),
          description: `Validator discovered from ${className}`,
          testType: 'access-control', // Default fallback
          version: '1.0.0',
          metadata: {},
          config: {},
          enabled: true,
          registeredAt: new Date(),
          testCount: 0,
          successCount: 0,
          failureCount: 0,
          updatedAt: new Date(),
        };
        this.logger.warn(`Created fallback validator entry for ${className}: ${validatorEntity.id}`);
        return validatorEntity;
      }

      // Extract metadata from instance
      const validatorEntity: ValidatorEntity = {
        id: tempInstance.id,
        name: tempInstance.name,
        description: tempInstance.description,
        testType: tempInstance.testType,
        version: tempInstance.version,
        metadata: tempInstance.metadata || {},
        config: minimalConfig,
        enabled: true,
        registeredAt: new Date(),
        testCount: 0,
        successCount: 0,
        failureCount: 0,
        updatedAt: new Date(),
      };

      this.logger.log(`Discovered validator: ${validatorEntity.name} (${validatorEntity.id})`);
      return validatorEntity;
    } catch (error: any) {
      this.logger.error(`Error registering validator ${ValidatorClass.name}: ${error.message}`, error.stack);
      return null;
    }
  }
}
