import { Injectable, Logger } from '@nestjs/common';
import { RLSCLSTester } from '../../../services/rls-cls-tester';
import { DatabaseConfig, User, Resource, TestQuery, DynamicMaskingRule } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class RLSCLSService {
  private readonly logger = new Logger(RLSCLSService.name);
  private tester: RLSCLSTester;

  constructor() {
    this.tester = new RLSCLSTester();
  }

  async testRLSCoverage(dto: { database: DatabaseConfig }) {
    try {
      this.validateDatabaseConfig(dto.database);
      return await this.tester.testRLSCoverage(dto.database);
    } catch (error: any) {
      this.logger.error(`Error testing RLS coverage: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test RLS coverage',
        { originalError: error.message },
      );
    }
  }

  async testCLSCoverage(dto: { database: DatabaseConfig }) {
    try {
      this.validateDatabaseConfig(dto.database);
      return await this.tester.testCLSCoverage(dto.database);
    } catch (error: any) {
      this.logger.error(`Error testing CLS coverage: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test CLS coverage',
        { originalError: error.message },
      );
    }
  }

  async testDynamicMasking(dto: {
    query: TestQuery;
    user: User;
    maskingRules: DynamicMaskingRule[];
  }) {
    try {
      this.validateTestQuery(dto.query);
      this.validateUser(dto.user);
      if (!dto.maskingRules || dto.maskingRules.length === 0) {
        throw new ValidationException('At least one masking rule is required');
      }
      return await this.tester.testDynamicMasking(dto.query, dto.user, dto.maskingRules);
    } catch (error: any) {
      this.logger.error(`Error testing dynamic masking: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test dynamic masking',
        { originalError: error.message },
      );
    }
  }

  async testCrossTenantIsolation(dto: {
    tenant1: string;
    tenant2: string;
    testQueries: TestQuery[];
  }) {
    try {
      if (!dto.tenant1 || !dto.tenant2) {
        throw new ValidationException('Both tenant1 and tenant2 are required');
      }
      if (dto.tenant1 === dto.tenant2) {
        throw new ValidationException('tenant1 and tenant2 must be different');
      }
      if (!dto.testQueries || dto.testQueries.length === 0) {
        throw new ValidationException('At least one test query is required');
      }
      return await this.tester.testCrossTenantIsolation(dto.tenant1, dto.tenant2, dto.testQueries);
    } catch (error: any) {
      this.logger.error(`Error testing cross-tenant isolation: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test cross-tenant isolation',
        { originalError: error.message },
      );
    }
  }

  async testPolicyBypass(dto: {
    userId: string;
    resourceId: string;
    resourceType: string;
  }) {
    try {
      if (!dto.userId) {
        throw new ValidationException('userId is required');
      }
      if (!dto.resourceId) {
        throw new ValidationException('resourceId is required');
      }
      if (!dto.resourceType) {
        throw new ValidationException('resourceType is required');
      }

      const user: User = {
        id: dto.userId,
        email: `${dto.userId}@example.com`,
        role: 'viewer',
        attributes: {},
      };

      const resource: Resource = {
        id: dto.resourceId,
        type: dto.resourceType,
        attributes: {},
      };

      return await this.tester.testPolicyBypassAttempts(user, resource);
    } catch (error: any) {
      this.logger.error(`Error testing policy bypass: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test policy bypass',
        { originalError: error.message },
      );
    }
  }

  private validateDatabaseConfig(database: DatabaseConfig): void {
    if (!database) {
      throw new ValidationException('Database configuration is required');
    }
    if (!database.type) {
      throw new ValidationException('Database type is required');
    }
    const validTypes = ['postgresql', 'mysql', 'sqlite', 'mssql', 'oracle'];
    if (!validTypes.includes(database.type)) {
      throw new ValidationException(
        `Invalid database type. Must be one of: ${validTypes.join(', ')}`,
      );
    }
  }

  private validateTestQuery(query: TestQuery): void {
    if (!query) {
      throw new ValidationException('Test query is required');
    }
    if (!query.sql && !query.name) {
      throw new ValidationException('Test query must have either sql or name');
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
}

