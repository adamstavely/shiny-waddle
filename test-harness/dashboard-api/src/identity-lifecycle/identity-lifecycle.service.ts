import { Injectable, Logger, NotFoundException, Inject, forwardRef } from '@nestjs/common';
import { IdentityLifecycleTester } from '../../../services/identity-lifecycle-tester';
import { PAMTester } from '../../../services/pam-tester';
import { IdentityVerificationTester } from '../../../services/identity-verification-tester';
import { User, PAMRequest } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { IdentityLifecycleConfigurationEntity } from '../test-configurations/entities/test-configuration.entity';
import { validateIdentityLifecycleConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class IdentityLifecycleService {
  private readonly logger = new Logger(IdentityLifecycleService.name);
  private lifecycleTester: IdentityLifecycleTester;
  private pamTester: PAMTester;
  private verificationTester: IdentityVerificationTester;

  constructor(
    @Inject(forwardRef(() => TestConfigurationsService))
    private readonly configService: TestConfigurationsService,
  ) {
    this.lifecycleTester = new IdentityLifecycleTester();
    this.pamTester = new PAMTester();
    this.verificationTester = new IdentityVerificationTester();
  }

  async testOnboarding(dto: { configId?: string; user?: User }) {
    try {
      let user: User;
      let ilConfig: IdentityLifecycleConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'identity-lifecycle') {
          throw new ValidationException(`Configuration ${dto.configId} is not an identity lifecycle configuration`);
        }
        ilConfig = config as IdentityLifecycleConfigurationEntity;
        
        // Validate configuration completeness (warnings only for identity lifecycle as workflow is optional)
        const validationErrors = validateIdentityLifecycleConfig(ilConfig);
        if (validationErrors.length > 0 && validationErrors.some(e => !e.message.includes('recommended'))) {
          const errorMessage = formatValidationErrors(validationErrors, ilConfig.name);
          throw new ValidationException(
            `Configuration '${ilConfig.name}' has validation issues for onboarding test:\n${errorMessage}`
          );
        }
        
        user = dto.user || { id: 'test-user', email: 'test@example.com', role: 'viewer', attributes: {} };
      } else {
        user = dto.user!;
      }

      this.validateUser(user);
      
      // Create tester with config if provided
      let tester = this.lifecycleTester;
      if (ilConfig) {
        const testerConfig: any = {
          workflowSteps: ilConfig.onboardingWorkflow?.steps,
          testLogic: ilConfig.testLogic,
        };
        tester = new IdentityLifecycleTester(testerConfig);
      }
      
      const result = await tester.testOnboardingWorkflow(user);

      // Apply workflow validation if config provided (tester handles steps, we validate requirements)
      if (ilConfig?.onboardingWorkflow) {
        const workflowSteps = ilConfig.onboardingWorkflow.steps || [];
        const requiredSteps = workflowSteps.filter(s => s.required).map(s => s.name);
        const completedSteps = result.completedSteps || [];
        
        result.workflowValidation = {
          requiredSteps,
          completedSteps,
          allRequiredStepsCompleted: requiredSteps.every(step => completedSteps.includes(step)),
          missingSteps: requiredSteps.filter(step => !completedSteps.includes(step)),
        };
      }

      // Apply testLogic validation flags if config provided
      if (ilConfig?.testLogic) {
        // Apply validateWorkflow flag
        if (ilConfig.testLogic.validateWorkflow === false) {
          result.workflowValidated = false;
        } else if (ilConfig.testLogic.validateWorkflow !== false && ilConfig.onboardingWorkflow) {
          // Validate workflow if flag is true or not set (default true)
          result.workflowValidated = result.workflowValidation?.allRequiredStepsCompleted || false;
        }

        // Run custom validations if present
        if (ilConfig.testLogic.customValidations && ilConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = ilConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing onboarding: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test onboarding workflow',
        { originalError: error.message },
      );
    }
  }

  async testRoleChange(dto: { configId?: string; user: User; newRole: string }) {
    try {
      let ilConfig: IdentityLifecycleConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'identity-lifecycle') {
          throw new ValidationException(`Configuration ${dto.configId} is not an identity lifecycle configuration`);
        }
        ilConfig = config as IdentityLifecycleConfigurationEntity;
      }

      this.validateUser(dto.user);
      if (!dto.newRole || typeof dto.newRole !== 'string') {
        throw new ValidationException('newRole is required and must be a string');
      }
      const validRoles = ['admin', 'researcher', 'analyst', 'viewer'];
      if (!validRoles.includes(dto.newRole)) {
        throw new ValidationException(
          `Invalid role. Must be one of: ${validRoles.join(', ')}`,
        );
      }
      const result = await this.lifecycleTester.testRoleChangeWorkflow(dto.user, dto.newRole);

      // Apply testLogic if config provided
      if (ilConfig?.testLogic) {
        // Apply validateWorkflow flag
        if (ilConfig.testLogic.validateWorkflow !== false) {
          result.workflowValidated = result.passed || false;
        }

        // Run custom validations if present
        if (ilConfig.testLogic.customValidations && ilConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = ilConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing role change: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test role change workflow',
        { originalError: error.message },
      );
    }
  }

  async testOffboarding(dto: { configId?: string; user: User }) {
    try {
      let ilConfig: IdentityLifecycleConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'identity-lifecycle') {
          throw new ValidationException(`Configuration ${dto.configId} is not an identity lifecycle configuration`);
        }
        ilConfig = config as IdentityLifecycleConfigurationEntity;
      }

      this.validateUser(dto.user);
      const result = await this.lifecycleTester.testOffboardingWorkflow(dto.user);

      // Apply testLogic if config provided
      if (ilConfig?.testLogic) {
        // Apply validateWorkflow flag
        if (ilConfig.testLogic.validateWorkflow !== false) {
          result.workflowValidated = result.passed || false;
        }

        // Run custom validations if present
        if (ilConfig.testLogic.customValidations && ilConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = ilConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing offboarding: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test offboarding workflow',
        { originalError: error.message },
      );
    }
  }

  async validateCredentialRotation(dto: { configId?: string; user: User }) {
    try {
      let ilConfig: IdentityLifecycleConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'identity-lifecycle') {
          throw new ValidationException(`Configuration ${dto.configId} is not an identity lifecycle configuration`);
        }
        ilConfig = config as IdentityLifecycleConfigurationEntity;
      }

      this.validateUser(dto.user);
      const result = await this.lifecycleTester.validateCredentialRotation(dto.user);

      // Apply credentialRotationRules if config provided
      if (ilConfig?.credentialRotationRules) {
        result.rotationRules = {
          passwordMaxAge: ilConfig.credentialRotationRules.passwordMaxAge,
          apiKeyMaxAge: ilConfig.credentialRotationRules.apiKeyMaxAge,
          requireMFA: ilConfig.credentialRotationRules.requireMFA,
        };

        // Validate against rules
        if (ilConfig.credentialRotationRules.passwordMaxAge && result.passwordAge) {
          result.passwordAgeCompliant = result.passwordAge <= ilConfig.credentialRotationRules.passwordMaxAge;
        }
        if (ilConfig.credentialRotationRules.apiKeyMaxAge && result.apiKeyAge) {
          result.apiKeyAgeCompliant = result.apiKeyAge <= ilConfig.credentialRotationRules.apiKeyMaxAge;
        }
        if (ilConfig.credentialRotationRules.requireMFA) {
          result.mfaRequired = true;
          result.mfaCompliant = result.mfaEnabled || false;
        }
      }

      // Apply testLogic if config provided
      if (ilConfig?.testLogic) {
        // Run custom validations if present
        if (ilConfig.testLogic.customValidations && ilConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = ilConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error validating credential rotation: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate credential rotation',
        { originalError: error.message },
      );
    }
  }

  async testMFAEnforcement(dto: { configId?: string; user: User }) {
    try {
      let ilConfig: IdentityLifecycleConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'identity-lifecycle') {
          throw new ValidationException(`Configuration ${dto.configId} is not an identity lifecycle configuration`);
        }
        ilConfig = config as IdentityLifecycleConfigurationEntity;
      }

      this.validateUser(dto.user);
      const result = await this.lifecycleTester.testMFAEnforcement(dto.user);

      // Apply testLogic.checkMFA flag if config provided
      if (ilConfig?.testLogic) {
        if (ilConfig.testLogic.checkMFA !== false) {
          // MFA check is enabled by default, validate result
          result.mfaCheckEnabled = true;
          result.mfaEnforced = result.passed || false;
        } else {
          result.mfaCheckEnabled = false;
        }

        // Run custom validations if present
        if (ilConfig.testLogic.customValidations && ilConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = ilConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing MFA enforcement: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test MFA enforcement',
        { originalError: error.message },
      );
    }
  }

  async testJITAccess(dto: { configId?: string; request?: PAMRequest }) {
    try {
      let request: PAMRequest;
      let ilConfig: IdentityLifecycleConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'identity-lifecycle') {
          throw new ValidationException(`Configuration ${dto.configId} is not an identity lifecycle configuration`);
        }
        ilConfig = config as IdentityLifecycleConfigurationEntity;
        // Apply PAM config if available
        if (ilConfig.pamConfig) {
          this.pamTester = new PAMTester({
            maxJITDuration: ilConfig.pamConfig.maxJITDuration,
            requireApproval: ilConfig.pamConfig.requireApproval,
            emergencyAccessEnabled: ilConfig.pamConfig.emergencyAccessEnabled,
          });
        }
        request = dto.request || {
          userId: 'test-user',
          resource: 'test-resource',
          reason: 'Testing',
          duration: 60,
        };
      } else {
        request = dto.request!;
      }

      this.validatePAMRequest(request);
      const result = await this.pamTester.testJITAccess(request);

      // Apply testLogic if config provided
      if (ilConfig?.testLogic) {
        // Run custom validations if present
        if (ilConfig.testLogic.customValidations && ilConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = ilConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing JIT access: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test JIT access',
        { originalError: error.message },
      );
    }
  }

  async testBreakGlass(dto: { configId?: string; request?: PAMRequest }) {
    try {
      let request: PAMRequest;
      let ilConfig: IdentityLifecycleConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'identity-lifecycle') {
          throw new ValidationException(`Configuration ${dto.configId} is not an identity lifecycle configuration`);
        }
        ilConfig = config as IdentityLifecycleConfigurationEntity;
        // Apply PAM config if available
        if (ilConfig.pamConfig) {
          this.pamTester = new PAMTester({
            maxJITDuration: ilConfig.pamConfig.maxJITDuration,
            requireApproval: ilConfig.pamConfig.requireApproval,
            emergencyAccessEnabled: ilConfig.pamConfig.emergencyAccessEnabled,
          });
        }
        request = dto.request || {
          userId: 'test-user',
          resource: 'test-resource',
          reason: 'Emergency',
          duration: 60,
          emergency: true,
        };
      } else {
        request = dto.request!;
      }

      this.validatePAMRequest(request);
      const result = await this.pamTester.testBreakGlassAccess(request);

      // Apply testLogic if config provided
      if (ilConfig?.testLogic) {
        // Run custom validations if present
        if (ilConfig.testLogic.customValidations && ilConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = ilConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing break-glass access: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test break-glass access',
        { originalError: error.message },
      );
    }
  }

  private validateUser(user: User): void {
    if (!user) {
      throw new ValidationException('User is required');
    }
    if (!user.id) {
      throw new ValidationException('User id is required');
    }
  }

  private validatePAMRequest(request: PAMRequest): void {
    if (!request) {
      throw new ValidationException('PAM request is required');
    }
    if (!request.userId) {
      throw new ValidationException('PAM request userId is required');
    }
    if (!request.resource) {
      throw new ValidationException('PAM request resource is required');
    }
  }

  private evaluateCustomValidation(condition: string, result: any): boolean {
    // Simple evaluation of custom validation conditions
    // In a real implementation, this would use a proper expression evaluator library
    try {
      // Extract common values from result object
      const passed = result.passed || false;
      const workflowValidated = result.workflowValidated || false;
      const mfaEnforced = result.mfaEnforced || false;
      const passwordAgeCompliant = result.passwordAgeCompliant || false;
      const apiKeyAgeCompliant = result.apiKeyAgeCompliant || false;

      // Replace common patterns in condition string with actual values
      let evalCondition = condition
        .replace(/\bpassed\b/g, String(passed))
        .replace(/\bworkflowValidated\b/g, String(workflowValidated))
        .replace(/\bmfaEnforced\b/g, String(mfaEnforced))
        .replace(/\bpasswordAgeCompliant\b/g, String(passwordAgeCompliant))
        .replace(/\bapiKeyAgeCompliant\b/g, String(apiKeyAgeCompliant));

      // Basic safety check - only allow simple comparisons and numbers/booleans
      if (!/^[0-9.\s()><=!&|truefalse]+$/i.test(evalCondition)) {
        this.logger.warn(`Unsafe validation condition: ${condition}`);
        return false;
      }

      // Use Function constructor as safer alternative to eval
      const func = new Function('return ' + evalCondition);
      return func();
    } catch (error) {
      this.logger.error(`Error evaluating custom validation: ${condition}`, error);
      return false;
    }
  }
}

