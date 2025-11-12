import { Injectable, Logger } from '@nestjs/common';
import { APIGatewayTester } from '../../../services/api-gateway-tester';
import { APIGatewayPolicy, APIRequest } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class APIGatewayService {
  private readonly logger = new Logger(APIGatewayService.name);
  private tester: APIGatewayTester;

  constructor() {
    this.tester = new APIGatewayTester();
  }

  async testGatewayPolicy(dto: { policy: APIGatewayPolicy; request: APIRequest }) {
    try {
      if (!dto.policy) {
        throw new ValidationException('Gateway policy is required');
      }
      if (!dto.policy.id) {
        throw new ValidationException('Gateway policy id is required');
      }
      if (!dto.request) {
        throw new ValidationException('API request is required');
      }
      if (!dto.request.endpoint) {
        throw new ValidationException('API request endpoint is required');
      }
      return await this.tester.testGatewayPolicy(dto.policy, dto.request);
    } catch (error: any) {
      this.logger.error(`Error testing gateway policy: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test gateway policy',
        { originalError: error.message },
      );
    }
  }

  async testRateLimiting(dto: { endpoint: string; requests: number }) {
    try {
      if (!dto.endpoint || typeof dto.endpoint !== 'string') {
        throw new ValidationException('Endpoint is required and must be a string');
      }
      if (typeof dto.requests !== 'number' || dto.requests < 1) {
        throw new ValidationException('Requests must be a positive number');
      }
      if (dto.requests > 10000) {
        throw new ValidationException('Requests cannot exceed 10000');
      }
      return await this.tester.testRateLimiting(dto.endpoint, dto.requests);
    } catch (error: any) {
      this.logger.error(`Error testing rate limiting: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test rate limiting',
        { originalError: error.message },
      );
    }
  }

  async testAPIVersioning(dto: { version: string; endpoint: string }) {
    try {
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
      return await this.tester.testAPIVersioning(dto.version, dto.endpoint);
    } catch (error: any) {
      this.logger.error(`Error testing API versioning: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test API versioning',
        { originalError: error.message },
      );
    }
  }

  async testServiceAuth(dto: { source: string; target: string }) {
    try {
      if (!dto.source || typeof dto.source !== 'string') {
        throw new ValidationException('Source service name is required');
      }
      if (!dto.target || typeof dto.target !== 'string') {
        throw new ValidationException('Target service name is required');
      }
      if (dto.source === dto.target) {
        throw new ValidationException('Source and target must be different');
      }
      return await this.tester.testServiceToServiceAuth(dto.source, dto.target);
    } catch (error: any) {
      this.logger.error(`Error testing service authentication: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test service authentication',
        { originalError: error.message },
      );
    }
  }
}

