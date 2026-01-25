import { Injectable, Logger, NotFoundException, Inject, forwardRef } from '@nestjs/common';
import { APIGatewayTester } from '../../heimdall-framework/services/api-gateway-tester';
import { APIGatewayPolicy, APIRequest } from '../../heimdall-framework/core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { ApplicationsService } from '../applications/applications.service';
import { APIGatewayInfrastructure } from '../applications/entities/application.entity';
import { validateAPIGatewayConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class APIGatewayService {
  private readonly logger = new Logger(APIGatewayService.name);
  private tester: APIGatewayTester;

  constructor(
    @Inject(forwardRef(() => ApplicationsService))
    private readonly applicationsService: ApplicationsService,
  ) {
    this.tester = new APIGatewayTester();
  }

  async testGatewayPolicy(dto: { applicationId?: string; policy?: APIGatewayPolicy; request: APIRequest }) {
    try {
      let policy: APIGatewayPolicy;
      let gatewayInfra: APIGatewayInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.apiGateway) {
          throw new ValidationException('Application has no API Gateway infrastructure configured');
        }
        
        gatewayInfra = application.infrastructure.apiGateway;
        
        // Validate configuration completeness (warnings only for API Gateway as fields are optional)
        const validationErrors = validateAPIGatewayConfig({
          id: application.id,
          name: application.name,
          type: 'api-gateway' as const,
          rateLimitConfig: gatewayInfra.rateLimitConfig,
          serviceAuthConfig: gatewayInfra.serviceAuthConfig,
          gatewayPolicies: gatewayInfra.gatewayPolicies,
          testLogic: gatewayInfra.testLogic,
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        if (validationErrors.length > 0 && validationErrors.some(e => !e.message.includes('recommended'))) {
          const errorMessage = formatValidationErrors(validationErrors, application.name);
          throw new ValidationException(
            `API Gateway infrastructure for application '${application.name}' has validation issues for gateway policy test:\n${errorMessage}`
          );
        }

        // Use gatewayPolicies from infrastructure if policy not provided inline
        if (!dto.policy && gatewayInfra.gatewayPolicies && gatewayInfra.gatewayPolicies.length > 0) {
          // Match policy by endpoint pattern if request provided
          if (dto.request?.endpoint) {
            const matchedPolicy = gatewayInfra.gatewayPolicies.find(p => {
              const pattern = p.endpoint.replace(/\*/g, '.*');
              return new RegExp(`^${pattern}$`).test(dto.request.endpoint);
            });
            if (matchedPolicy) {
              policy = matchedPolicy as APIGatewayPolicy;
            } else {
              // Use first policy as default
              policy = gatewayInfra.gatewayPolicies[0] as APIGatewayPolicy;
            }
          } else {
            policy = gatewayInfra.gatewayPolicies[0] as APIGatewayPolicy;
          }
        } else if (dto.policy) {
          policy = dto.policy;
        } else {
          throw new ValidationException('Gateway policy is required (either in infrastructure or request)');
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
      if (gatewayInfra?.testLogic) {
        // Run custom validations if present
        if (gatewayInfra.testLogic.customValidations && gatewayInfra.testLogic.customValidations.length > 0) {
          result.customValidationResults = gatewayInfra.testLogic.customValidations.map(validation => ({
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

  async testRateLimiting(dto: { applicationId?: string; endpoint?: string; requests?: number }) {
    try {
      let endpoint: string;
      let requests: number;
      let gatewayInfra: APIGatewayInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.apiGateway) {
          throw new ValidationException('Application has no API Gateway infrastructure configured');
        }
        
        gatewayInfra = application.infrastructure.apiGateway;
        
        // Apply rate limit config if available
        const testerConfig: any = {};
        if (gatewayInfra.rateLimitConfig) {
          testerConfig.rateLimitConfig = gatewayInfra.rateLimitConfig;
        }
        if (gatewayInfra.serviceAuthConfig) {
          testerConfig.serviceAuthConfig = gatewayInfra.serviceAuthConfig;
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
      if (gatewayInfra?.testLogic?.validateRateLimiting === false) {
        return { validated: false, skipped: true, reason: 'Rate limiting validation disabled in infrastructure' };
      }

      const result = await this.tester.testRateLimiting(endpoint, requests);

      // Apply testLogic custom validations if present
      if (gatewayInfra?.testLogic?.customValidations && gatewayInfra.testLogic.customValidations.length > 0) {
        result.customValidationResults = gatewayInfra.testLogic.customValidations.map(validation => ({
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

  async testAPIVersioning(dto: { applicationId?: string; version: string; endpoint: string }) {
    try {
      let gatewayInfra: APIGatewayInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.apiGateway) {
          throw new ValidationException('Application has no API Gateway infrastructure configured');
        }
        
        gatewayInfra = application.infrastructure.apiGateway;
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
      if (gatewayInfra?.testLogic) {
        // Run custom validations if present
        if (gatewayInfra.testLogic.customValidations && gatewayInfra.testLogic.customValidations.length > 0) {
          result.customValidationResults = gatewayInfra.testLogic.customValidations.map(validation => ({
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

  async testServiceAuth(dto: { applicationId?: string; source?: string; target?: string }) {
    try {
      let source: string;
      let target: string;
      let gatewayInfra: APIGatewayInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.apiGateway) {
          throw new ValidationException('Application has no API Gateway infrastructure configured');
        }
        
        gatewayInfra = application.infrastructure.apiGateway;
        
        // Apply service auth config if available
        const testerConfig: any = {};
        if (gatewayInfra.serviceAuthConfig) {
          testerConfig.serviceAuthConfig = gatewayInfra.serviceAuthConfig;
        }
        if (gatewayInfra.rateLimitConfig) {
          testerConfig.rateLimitConfig = gatewayInfra.rateLimitConfig;
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
      if (gatewayInfra?.testLogic?.checkServiceAuth === false) {
        return { checked: false, skipped: true, reason: 'Service auth checking disabled in infrastructure' };
      }

      const result = await this.tester.testServiceToServiceAuth(source, target);

      // Apply testLogic custom validations if present
      if (gatewayInfra?.testLogic?.customValidations && gatewayInfra.testLogic.customValidations.length > 0) {
        result.customValidationResults = gatewayInfra.testLogic.customValidations.map(validation => ({
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

