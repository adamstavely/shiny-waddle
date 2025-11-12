import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { RLSCLSTester } from '../../../services/rls-cls-tester';
import { DatabaseConfig, User, Resource, TestQuery, DynamicMaskingRule } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { RLSCLSConfigurationEntity } from '../test-configurations/entities/test-configuration.entity';

@Injectable()
export class RLSCLSService {
  private readonly logger = new Logger(RLSCLSService.name);
  private tester: RLSCLSTester;

  constructor(private readonly configService: TestConfigurationsService) {
    this.tester = new RLSCLSTester();
  }

  async testRLSCoverage(dto: { configId?: string; database?: DatabaseConfig }) {
    try {
      let database: DatabaseConfig;
      let rlsConfig: RLSCLSConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'rls-cls') {
          throw new ValidationException(`Configuration ${dto.configId} is not an RLS/CLS configuration`);
        }
        rlsConfig = config as RLSCLSConfigurationEntity;
        database = rlsConfig.database;
        // Merge with inline database if provided (inline takes precedence)
        if (dto.database) {
          database = { ...database, ...dto.database };
        }
      } else if (dto.database) {
        database = dto.database;
      } else {
        throw new ValidationException('Either configId or database must be provided');
      }

      this.validateDatabaseConfig(database);
      
      // Create tester with config if provided
      let tester = this.tester;
      if (rlsConfig) {
        const testerConfig: any = {
          testLogic: rlsConfig.testLogic,
        };
        tester = new RLSCLSTester(testerConfig);
      }
      
      const result = await tester.testRLSCoverage(database);

      // Run custom validations if present (tester handles skipDisabledPolicies)
      if (rlsConfig?.testLogic?.customValidations && rlsConfig.testLogic.customValidations.length > 0) {
        result.customValidationResults = rlsConfig.testLogic.customValidations.map(validation => ({
          name: validation.name,
          passed: this.evaluateCustomValidation(validation.condition, result),
          description: validation.description,
        }));
      }

      // Apply validationRules if config provided
      if (rlsConfig?.validationRules) {
        result.validationResults = {
          minRLSCoverageMet: result.coveragePercentage >= (rlsConfig.validationRules.minRLSCoverage || 0),
          minRLSCoverage: rlsConfig.validationRules.minRLSCoverage,
          actualCoverage: result.coveragePercentage,
        };

        // Check required policies
        if (rlsConfig.validationRules.requiredPolicies && rlsConfig.validationRules.requiredPolicies.length > 0) {
          const policyNames = result.policies.map(p => p.policyName);
          result.validationResults.requiredPoliciesMet = rlsConfig.validationRules.requiredPolicies.every(
            required => policyNames.includes(required)
          );
          result.validationResults.missingPolicies = rlsConfig.validationRules.requiredPolicies.filter(
            required => !policyNames.includes(required)
          );
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing RLS coverage: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test RLS coverage',
        { originalError: error.message },
      );
    }
  }

  async testCLSCoverage(dto: { configId?: string; database?: DatabaseConfig }) {
    try {
      let database: DatabaseConfig;
      let rlsConfig: RLSCLSConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'rls-cls') {
          throw new ValidationException(`Configuration ${dto.configId} is not an RLS/CLS configuration`);
        }
        rlsConfig = config as RLSCLSConfigurationEntity;
        database = rlsConfig.database;
        // Merge with inline database if provided (inline takes precedence)
        if (dto.database) {
          database = { ...database, ...dto.database };
        }
      } else if (dto.database) {
        database = dto.database;
      } else {
        throw new ValidationException('Either configId or database must be provided');
      }

      this.validateDatabaseConfig(database);
      
      // Create tester with config if provided
      let tester = this.tester;
      if (rlsConfig) {
        const testerConfig: any = {
          testLogic: rlsConfig.testLogic,
        };
        tester = new RLSCLSTester(testerConfig);
      }
      
      const result = await tester.testCLSCoverage(database);

      // Run custom validations if present (tester handles skipDisabledPolicies)
      if (rlsConfig?.testLogic?.customValidations && rlsConfig.testLogic.customValidations.length > 0) {
        result.customValidationResults = rlsConfig.testLogic.customValidations.map(validation => ({
          name: validation.name,
          passed: this.evaluateCustomValidation(validation.condition, result),
          description: validation.description,
        }));
      }

      // Apply validationRules if config provided
      if (rlsConfig?.validationRules) {
        result.validationResults = {
          minCLSCoverageMet: result.coveragePercentage >= (rlsConfig.validationRules.minCLSCoverage || 0),
          minCLSCoverage: rlsConfig.validationRules.minCLSCoverage,
          actualCoverage: result.coveragePercentage,
        };
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing CLS coverage: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test CLS coverage',
        { originalError: error.message },
      );
    }
  }

  async testDynamicMasking(dto: {
    configId?: string;
    query?: TestQuery;
    user?: User;
    maskingRules?: DynamicMaskingRule[];
  }) {
    try {
      let query: TestQuery;
      let user: User;
      let maskingRules: DynamicMaskingRule[];
      let rlsConfig: RLSCLSConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'rls-cls') {
          throw new ValidationException(`Configuration ${dto.configId} is not an RLS/CLS configuration`);
        }
        rlsConfig = config as RLSCLSConfigurationEntity;
        // Use testQueries from config if query not provided
        query = dto.query || (rlsConfig.testQueries && rlsConfig.testQueries.length > 0 ? rlsConfig.testQueries[0] : { name: 'default-query', sql: 'SELECT * FROM users' });
        user = dto.user || { id: 'test-user', email: 'test@example.com', role: 'viewer', attributes: {} };
        // Masking rules would need to be provided or come from config
        maskingRules = dto.maskingRules || [];
      } else {
        query = dto.query!;
        user = dto.user!;
        maskingRules = dto.maskingRules!;
      }

      this.validateTestQuery(query);
      this.validateUser(user);
      if (!maskingRules || maskingRules.length === 0) {
        throw new ValidationException('At least one masking rule is required');
      }

      const result = await this.tester.testDynamicMasking(query, user, maskingRules);

      // Apply testLogic if config provided
      if (rlsConfig?.testLogic) {
        // Run custom validations if present
        if (rlsConfig.testLogic.customValidations && rlsConfig.testLogic.customValidations.length > 0) {
          result.customValidationResults = rlsConfig.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing dynamic masking: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test dynamic masking',
        { originalError: error.message },
      );
    }
  }

  async testCrossTenantIsolation(dto: {
    configId?: string;
    tenant1?: string;
    tenant2?: string;
    testQueries?: TestQuery[];
  }) {
    try {
      let tenant1: string;
      let tenant2: string;
      let testQueries: TestQuery[];
      let rlsConfig: RLSCLSConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'rls-cls') {
          throw new ValidationException(`Configuration ${dto.configId} is not an RLS/CLS configuration`);
        }
        rlsConfig = config as RLSCLSConfigurationEntity;
        // Use default test queries from config if available
        testQueries = rlsConfig.testQueries || [];
        // For cross-tenant, we need tenant IDs - use defaults if not provided
        tenant1 = dto.tenant1 || 'tenant1';
        tenant2 = dto.tenant2 || 'tenant2';
        // Merge with inline testQueries if provided
        if (dto.testQueries && dto.testQueries.length > 0) {
          testQueries = dto.testQueries;
        }
      } else {
        tenant1 = dto.tenant1!;
        tenant2 = dto.tenant2!;
        testQueries = dto.testQueries!;
      }

      if (!tenant1 || !tenant2) {
        throw new ValidationException('Both tenant1 and tenant2 are required');
      }
      if (tenant1 === tenant2) {
        throw new ValidationException('tenant1 and tenant2 must be different');
      }
      if (!testQueries || testQueries.length === 0) {
        throw new ValidationException('At least one test query is required');
      }

      const result = await this.tester.testCrossTenantIsolation(tenant1, tenant2, testQueries);

      // Apply testLogic if config provided
      if (rlsConfig?.testLogic?.validateCrossTenant !== false) {
        // validateCrossTenant is true by default, so we validate unless explicitly disabled
        // The result already contains isolation verification, but we can add additional checks
        if (!result.isolationVerified) {
          this.logger.warn(`Cross-tenant isolation validation failed for ${tenant1} vs ${tenant2}`);
        }
      }

      // Run custom validations if present
      if (rlsConfig?.testLogic?.customValidations && rlsConfig.testLogic.customValidations.length > 0) {
        result.customValidationResults = rlsConfig.testLogic.customValidations.map(validation => ({
          name: validation.name,
          passed: this.evaluateCustomValidation(validation.condition, result),
          description: validation.description,
        }));
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing cross-tenant isolation: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test cross-tenant isolation',
        { originalError: error.message },
      );
    }
  }

  async testPolicyBypass(dto: {
    configId?: string;
    userId: string;
    resourceId: string;
    resourceType: string;
  }) {
    try {
      let rlsConfig: RLSCLSConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'rls-cls') {
          throw new ValidationException(`Configuration ${dto.configId} is not an RLS/CLS configuration`);
        }
        rlsConfig = config as RLSCLSConfigurationEntity;
      }

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

      const result = await this.tester.testPolicyBypassAttempts(user, resource);

      // Apply testLogic if config provided
      if (rlsConfig?.testLogic) {
        // Run custom validations if present
        if (rlsConfig.testLogic.customValidations && rlsConfig.testLogic.customValidations.length > 0) {
          result.forEach((testResult, index) => {
            if (rlsConfig?.testLogic?.customValidations) {
              testResult.customValidationResults = rlsConfig.testLogic.customValidations.map(validation => ({
                name: validation.name,
                passed: this.evaluateCustomValidation(validation.condition, testResult),
                description: validation.description,
              }));
            }
          });
        }
      }

      // Apply validationRules if config provided
      if (rlsConfig?.validationRules) {
        result.forEach(testResult => {
          testResult.validationApplied = true;
        });
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing policy bypass: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
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

  private evaluateCustomValidation(condition: string, result: any): boolean {
    // Simple evaluation of custom validation conditions
    // In a real implementation, this would use a proper expression evaluator library
    try {
      // Extract values from result object
      const coveragePercentage = result.coveragePercentage || 0;
      const tablesWithRLS = result.tablesWithRLS || 0;
      const tablesWithCLS = result.tablesWithCLS || 0;
      const totalTables = result.totalTables || 0;
      const isolationVerified = result.isolationVerified || false;

      // Replace common patterns in condition string with actual values
      let evalCondition = condition
        .replace(/\bcoveragePercentage\b/g, String(coveragePercentage))
        .replace(/\btablesWithRLS\b/g, String(tablesWithRLS))
        .replace(/\btablesWithCLS\b/g, String(tablesWithCLS))
        .replace(/\btotalTables\b/g, String(totalTables))
        .replace(/\bisolationVerified\b/g, String(isolationVerified));

      // Basic safety check - only allow simple comparisons and numbers
      if (!/^[0-9.\s()><=!&|]+$/.test(evalCondition)) {
        this.logger.warn(`Unsafe validation condition: ${condition}`);
        return false;
      }

      // Use Function constructor as safer alternative to eval (still not perfect, but better)
      // In production, use a proper expression evaluator like expr-eval or mathjs
      const func = new Function('return ' + evalCondition);
      return func();
    } catch (error) {
      this.logger.error(`Error evaluating custom validation: ${condition}`, error);
      return false;
    }
  }
}

