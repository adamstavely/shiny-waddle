import { Injectable, Logger, NotFoundException, Inject, forwardRef } from '@nestjs/common';
import { APIGatewayTester } from '../../../services/api-gateway-tester';
import { APIGatewayPolicy, APIRequest } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { APIGatewayConfigurationEntity } from '../test-configurations/entities/test-configuration.entity';
import { validateAPIGatewayConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class APIGatewayService {
  private readonly logger = new Logger(APIGatewayService.name);
  private tester: APIGatewayTester;

  constructor(
    @Inject(forwardRef(() => TestConfigurationsService))
    private readonly configService: TestConfigurationsService,
  ) {
    this.tester = new APIGatewayTester();
  }

  async testGatewayPolicy(dto: { configId?: string; policy?: APIGatewayPolicy; request: APIRequest }) {
    try {
      let policy: APIGatewayPolicy;
      let agConfig: APIGatewayConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'api-gateway') {
          throw new ValidationException(`Configuration ${dto.configId} is not an API gateway configuration`);
        }
        agConfig = config as APIGatewayConfigurationEntity;
        
        // Validate configuration completeness (warnings only for API Gateway as fields are optional)
        const validationErrors = validateAPIGatewayConfig(agConfig);
        if (validationErrors.length > 0 && validationErrors.some(e => !e.message.includes('recommended'))) {
          const errorMessage = formatValidationErrors(validationErrors, agConfig.name);
          throw new ValidationException(
            `Configuration '${agConfig.name}' has validation issues for gateway policy test:\n${errorMessage}`
          );
        }

        // Use gatewayPolicies from config if policy not provided inline
        if (!dto.policy && agConfig.gatewayPolicies && agConfig.gatewayPolicies.length > 0) {
          // Match policy by endpoint pattern if request provided
          if (dto.request?.endpoint) {
            const matchedPolicy = agConfig.gatewayPolicies.find(p => {
              const pattern = p.endpoint.replace(/\*/g, '.*');
              return new RegExp(`^${pattern}$`).test(dto.request.endpoint);
            });
            if (matchedPolicy) {
              policy = matchedPolicy as APIGatewayPolicy;
            } else {
              // Use first policy as default
              policy = agConfig.gatewayPolicies[0] as APIGatewayPolicy;
            }
          } else {
            policy = agConfig.gatewayPolicies[0] as APIGatewayPolicy;
          }
        } else if (dto.policy) {
          policy = dto.policy;
        } else {
          throw new ValidationException('Gateway policy is required (either in config or request)');
        }
      } else {
        policy = dto.policy!;
      }

      if (!policy) {
        throw new ValidationException('Gateway policy is required');
      }
      if (!policy.id) {
        throw new ValidationException('Gateway policy id is required');
      }
      if (!dto.request) {
        throw new ValidationException('API request is required');
      }
      if (!dto.request.endpoint) {
        throw new ValidationException('API request endpoint is required');
      }

      const result = await this.tester.testGatewayPolicy(policy, dto.request);

      // Apply testLogic if config provided
      if (agConfig?.testLogic) {
        // Run custom validations if present
        if (agConfig.testLogic.customValidations && agConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = agConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing gateway policy: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test gateway policy',
        { originalError: error.message },
      );
    }
  }

  async testRateLimiting(dto: { configId?: string; endpoint?: string; requests?: number }) {
    try {
      let endpoint: string;
      let requests: number;
      let agConfig: APIGatewayConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'api-gateway') {
          throw new ValidationException(`Configuration ${dto.configId} is not an API gateway configuration`);
        }
        agConfig = config as APIGatewayConfigurationEntity;
        // Apply rate limit config if available
        const testerConfig: any = {};
        if (agConfig.rateLimitConfig) {
          testerConfig.rateLimitConfig = agConfig.rateLimitConfig;
        }
        if (agConfig.serviceAuthConfig) {
          testerConfig.serviceAuthConfig = agConfig.serviceAuthConfig;
        }
        if (Object.keys(testerConfig).length > 0) {
          this.tester = new APIGatewayTester(testerConfig);
        }
        endpoint = dto.endpoint || '/api/test';
        requests = dto.requests || 150;
      } else {
        endpoint = dto.endpoint!;
        requests = dto.requests!;
      }

      if (!endpoint || typeof endpoint !== 'string') {
        throw new ValidationException('Endpoint is required and must be a string');
      }
      if (typeof requests !== 'number' || requests < 1) {
        throw new ValidationException('Requests must be a positive number');
      }
      if (requests > 10000) {
        throw new ValidationException('Requests cannot exceed 10000');
      }

      // Apply testLogic.validateRateLimiting flag
      if (agConfig?.testLogic?.validateRateLimiting === false) {
        return { validated: false, skipped: true, reason: 'Rate limiting validation disabled in configuration' };
      }

      const result = await this.tester.testRateLimiting(endpoint, requests);

      // Apply testLogic custom validations if present
      if (agConfig?.testLogic?.customValidations && agConfig.testLogic.customValidations.length > 0) {
        result.customValidationResults = agConfig.testLogic.customValidations.map(validation => ({
          name: validation.name,
          passed: this.evaluateCustomValidation(validation.condition, result),
          description: validation.description,
        }));
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing rate limiting: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test rate limiting',
        { originalError: error.message },
      );
    }
  }

  async testAPIVersioning(dto: { configId?: string; version: string; endpoint: string }) {
    try {
      let agConfig: APIGatewayConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'api-gateway') {
          throw new ValidationException(`Configuration ${dto.configId} is not an API gateway configuration`);
        }
        agConfig = config as APIGatewayConfigurationEntity;
      }

      if (!dto.version || typeof dto.version !== 'string') {
        throw new ValidationException('API version is required and must be a string');
      }
      if (!dto.endpoint || typeof dto.endpoint !== 'string') {
        throw new ValidationException('Endpoint is required and must be a string');
      }
      // Validate version format (e.g., v1, v2.0, etc.)
      if (!/^v\d+(\.\d+)?$/.test(dto.version)) {
        throw new ValidationException('Version must be in format v1, v2.0, etc.');
      }

      const result = await this.tester.testAPIVersioning(dto.version, dto.endpoint);

      // Apply testLogic if config provided
      if (agConfig?.testLogic) {
        // Run custom validations if present
        if (agConfig.testLogic.customValidations && agConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = agConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing API versioning: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test API versioning',
        { originalError: error.message },
      );
    }
  }

  async testServiceAuth(dto: { configId?: string; source?: string; target?: string }) {
    try {
      let source: string;
      let target: string;
      let agConfig: APIGatewayConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'api-gateway') {
          throw new ValidationException(`Configuration ${dto.configId} is not an API gateway configuration`);
        }
        agConfig = config as APIGatewayConfigurationEntity;
        // Apply service auth config if available
        const testerConfig: any = {};
        if (agConfig.serviceAuthConfig) {
          testerConfig.serviceAuthConfig = agConfig.serviceAuthConfig;
        }
        if (agConfig.rateLimitConfig) {
          testerConfig.rateLimitConfig = agConfig.rateLimitConfig;
        }
        if (Object.keys(testerConfig).length > 0) {
          this.tester = new APIGatewayTester(testerConfig);
        }
        source = dto.source || 'frontend';
        target = dto.target || 'backend';
      } else {
        source = dto.source!;
        target = dto.target!;
      }

      if (!source || typeof source !== 'string') {
        throw new ValidationException('Source service name is required');
      }
      if (!target || typeof target !== 'string') {
        throw new ValidationException('Target service name is required');
      }
      if (source === target) {
        throw new ValidationException('Source and target must be different');
      }

      // Apply testLogic.checkServiceAuth flag
      if (agConfig?.testLogic?.checkServiceAuth === false) {
        return { checked: false, skipped: true, reason: 'Service auth checking disabled in configuration' };
      }

      const result = await this.tester.testServiceToServiceAuth(source, target);

      // Apply testLogic custom validations if present
      if (agConfig?.testLogic?.customValidations && agConfig.testLogic.customValidations.length > 0) {
        result.customValidationResults = agConfig.testLogic.customValidations.map(validation => ({
          name: validation.name,
          passed: this.evaluateCustomValidation(validation.condition, result),
          description: validation.description,
        }));
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing service authentication: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test service authentication',
        { originalError: error.message },
      );
    }
  }

  private evaluateCustomValidation(condition: string, result: any): boolean {
    // Simple evaluation of custom validation conditions
    // In a real implementation, this would use a proper expression evaluator library
    try {
      // Extract common values from result object
      const passed = result.passed || false;
      const blocked = result.blocked || false;
      const rateLimited = result.rateLimited || false;
      const authenticated = result.authenticated || false;

      // Replace common patterns in condition string with actual values
      let evalCondition = condition
        .replace(/\bpassed\b/g, String(passed))
        .replace(/\bblocked\b/g, String(blocked))
        .replace(/\brateLimited\b/g, String(rateLimited))
        .replace(/\bauthenticated\b/g, String(authenticated));

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

