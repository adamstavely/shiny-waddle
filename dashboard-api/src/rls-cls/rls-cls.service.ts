import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { RLSCLSTester } from '../../../heimdall-framework/services/rls-cls-tester';
import { DatabaseConfig, User, Resource, TestQuery, DynamicMaskingRule } from '../../../heimdall-framework/core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { ApplicationDataService } from '../shared/application-data.service';
import { DatabaseInfrastructure } from '../applications/entities/application.entity';
import { validateRLSCLSConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class RLSCLSService {
  private readonly logger = new Logger(RLSCLSService.name);
  private tester: RLSCLSTester;

  constructor(
    private readonly applicationDataService: ApplicationDataService,
  ) {
    this.tester = new RLSCLSTester();
  }

  async testRLSCoverage(dto: { applicationId?: string; databaseId?: string; database?: DatabaseConfig }) {
    try {
      let database: DatabaseConfig;
      let dbInfra: DatabaseInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationDataService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.databases || application.infrastructure.databases.length === 0) {
          throw new ValidationException('Application has no database infrastructure configured');
        }
        
        // Find specific database or use first one
        if (dto.databaseId) {
          dbInfra = application.infrastructure.databases.find(db => db.id === dto.databaseId);
          if (!dbInfra) {
            throw new NotFoundException(`Database ${dto.databaseId} not found in application infrastructure`);
          }
        } else {
          dbInfra = application.infrastructure.databases[0];
        }
        
        // Convert DatabaseInfrastructure to DatabaseConfig
        database = {
          type: dbInfra.type,
          host: dbInfra.host,
          port: dbInfra.port,
          database: dbInfra.database,
          // Note: username/password come from runtime config, not infrastructure
        };
        
        // Merge with inline database if provided (inline takes precedence)
        if (dto.database) {
          database = { ...database, ...dto.database };
        }
        
        // Validate configuration completeness (convert to config entity format for validation)
        const validationErrors = validateRLSCLSConfig({
          id: dbInfra.id,
          name: dbInfra.name,
          type: 'rls-cls' as const,
          database,
          testQueries: dbInfra.testQueries || [],
          maskingRules: dbInfra.maskingRules,
          validationRules: dbInfra.validationRules,
          testLogic: dbInfra.testLogic,
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        if (validationErrors.length > 0) {
          const errorMessage = formatValidationErrors(validationErrors, dbInfra.name);
          throw new ValidationException(
            `Database infrastructure '${dbInfra.name}' is missing required fields for RLS coverage test:\n${errorMessage}`
          );
        }
      } else if (dto.database) {
        database = dto.database;
      } else {
        throw new ValidationException(
          'Either applicationId or database must be provided. If using applicationId, ensure the application has database infrastructure configured.'
        );
      }

      this.validateDatabaseConfig(database);
      
      // Create tester with config if provided
      let tester = this.tester;
      if (dbInfra?.testLogic) {
        const testerConfig: any = {
          testLogic: dbInfra.testLogic,
        };
        tester = new RLSCLSTester(testerConfig);
      }
      
      const result = await tester.testRLSCoverage(database);

      // Run custom validations if present (tester handles skipDisabledPolicies)
      if (dbInfra?.testLogic?.customValidations && dbInfra.testLogic.customValidations.length > 0) {
        result.details = {
          ...result.details,
          customValidationResults: dbInfra.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          })),
        };
      }

      // Apply validationRules if config provided
      if (dbInfra?.validationRules) {
        result.validationResults = {
          minRLSCoverageMet: result.coveragePercentage >= (dbInfra.validationRules.minRLSCoverage || 0),
          minRLSCoverage: dbInfra.validationRules.minRLSCoverage,
          actualCoverage: result.coveragePercentage,
        };

        // Check required policies
        if (dbInfra.validationRules.requiredPolicies && dbInfra.validationRules.requiredPolicies.length > 0) {
          const policyNames = result.policies.map(p => p.policyName);
          result.validationResults.requiredPoliciesMet = dbInfra.validationRules.requiredPolicies.every(
            required => policyNames.includes(required)
          );
          result.validationResults.missingPolicies = dbInfra.validationRules.requiredPolicies.filter(
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

  async testCLSCoverage(dto: { applicationId?: string; databaseId?: string; database?: DatabaseConfig }) {
    try {
      let database: DatabaseConfig;
      let dbInfra: DatabaseInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationDataService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.databases || application.infrastructure.databases.length === 0) {
          throw new ValidationException('Application has no database infrastructure configured');
        }
        
        // Find specific database or use first one
        if (dto.databaseId) {
          dbInfra = application.infrastructure.databases.find(db => db.id === dto.databaseId);
          if (!dbInfra) {
            throw new NotFoundException(`Database ${dto.databaseId} not found in application infrastructure`);
          }
        } else {
          dbInfra = application.infrastructure.databases[0];
        }
        
        // Convert DatabaseInfrastructure to DatabaseConfig
        database = {
          type: dbInfra.type,
          host: dbInfra.host,
          port: dbInfra.port,
          database: dbInfra.database,
        };
        
        // Merge with inline database if provided (inline takes precedence)
        if (dto.database) {
          database = { ...database, ...dto.database };
        }
        
        // Validate configuration completeness
        const validationErrors = validateRLSCLSConfig({
          id: dbInfra.id,
          name: dbInfra.name,
          type: 'rls-cls' as const,
          database,
          testQueries: dbInfra.testQueries || [],
          maskingRules: dbInfra.maskingRules,
          validationRules: dbInfra.validationRules,
          testLogic: dbInfra.testLogic,
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        if (validationErrors.length > 0) {
          const errorMessage = formatValidationErrors(validationErrors, dbInfra.name);
          throw new ValidationException(
            `Database infrastructure '${dbInfra.name}' is missing required fields for CLS coverage test:\n${errorMessage}`
          );
        }
      } else if (dto.database) {
        database = dto.database;
      } else {
        throw new ValidationException(
          'Either applicationId or database must be provided. If using applicationId, ensure the application has database infrastructure configured.'
        );
      }

      this.validateDatabaseConfig(database);
      
      // Create tester with config if provided
      let tester = this.tester;
      if (dbInfra?.testLogic) {
        const testerConfig: any = {
          testLogic: dbInfra.testLogic,
        };
        tester = new RLSCLSTester(testerConfig);
      }
      
      const result = await tester.testCLSCoverage(database);

      // Run custom validations if present (tester handles skipDisabledPolicies)
      if (dbInfra?.testLogic?.customValidations && dbInfra.testLogic.customValidations.length > 0) {
        result.details = {
          ...result.details,
          customValidationResults: dbInfra.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          })),
        };
      }

      // Apply validationRules if config provided
      if (dbInfra?.validationRules) {
        result.validationResults = {
          minCLSCoverageMet: result.coveragePercentage >= (dbInfra.validationRules.minCLSCoverage || 0),
          minCLSCoverage: dbInfra.validationRules.minCLSCoverage,
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
    applicationId?: string;
    databaseId?: string;
    query?: TestQuery;
    user?: User;
    maskingRules?: DynamicMaskingRule[];
  }) {
    try {
      let query: TestQuery;
      let user: User;
      let maskingRules: DynamicMaskingRule[];
      let dbInfra: DatabaseInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationDataService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.databases || application.infrastructure.databases.length === 0) {
          throw new ValidationException('Application has no database infrastructure configured');
        }
        
        // Find specific database or use first one
        if (dto.databaseId) {
          dbInfra = application.infrastructure.databases.find(db => db.id === dto.databaseId);
          if (!dbInfra) {
            throw new NotFoundException(`Database ${dto.databaseId} not found in application infrastructure`);
          }
        } else {
          dbInfra = application.infrastructure.databases[0];
        }
        
        // Use testQueries from infrastructure if query not provided
        query = dto.query || (dbInfra.testQueries && dbInfra.testQueries.length > 0 ? dbInfra.testQueries[0] : { name: 'default-query', sql: 'SELECT * FROM users' });
        user = dto.user || { id: 'test-user', email: 'test@example.com', role: 'viewer', attributes: {} };
        // Use masking rules from infrastructure if not provided inline
        if (dto.maskingRules && dto.maskingRules.length > 0) {
          maskingRules = dto.maskingRules;
        } else if (dbInfra.maskingRules && dbInfra.maskingRules.length > 0) {
          // Convert infrastructure masking rules to DynamicMaskingRule format
          maskingRules = dbInfra.maskingRules.map(rule => ({
            table: rule.table,
            column: rule.column,
            maskingType: rule.maskingType,
            pattern: rule.condition, // Map condition to pattern
            applicableRoles: [], // Default to empty array if not specified
          })) as DynamicMaskingRule[];
        } else {
          maskingRules = [];
        }
      } else {
        query = dto.query!;
        user = dto.user!;
        maskingRules = dto.maskingRules!;
      }

      this.validateTestQuery(query);
      this.validateUser(user);
      if (!maskingRules || maskingRules.length === 0) {
        throw new ValidationException(
          'At least one masking rule is required. Please provide masking rules inline or configure them in the application infrastructure.'
        );
      }

      const result = await this.tester.testDynamicMasking(query, user, maskingRules);

      // Apply testLogic if config provided
      if (dbInfra?.testLogic) {
        // Run custom validations if present
        if (dbInfra.testLogic.customValidations && dbInfra.testLogic.customValidations.length > 0) {
          result.details = {
            ...result.details,
            customValidationResults: dbInfra.testLogic.customValidations.map(validation => ({
              name: validation.name,
              passed: this.evaluateCustomValidation(validation.condition, result),
              description: validation.description,
            })),
          };
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
    applicationId?: string;
    databaseId?: string;
    tenant1?: string;
    tenant2?: string;
    testQueries?: TestQuery[];
  }) {
    try {
      let tenant1: string;
      let tenant2: string;
      let testQueries: TestQuery[];
      let dbInfra: DatabaseInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationDataService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.databases || application.infrastructure.databases.length === 0) {
          throw new ValidationException('Application has no database infrastructure configured');
        }
        
        // Find specific database or use first one
        if (dto.databaseId) {
          dbInfra = application.infrastructure.databases.find(db => db.id === dto.databaseId);
          if (!dbInfra) {
            throw new NotFoundException(`Database ${dto.databaseId} not found in application infrastructure`);
          }
        } else {
          dbInfra = application.infrastructure.databases[0];
        }
        
        // Use default test queries from infrastructure if available
        testQueries = dbInfra.testQueries || [];
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
      if (dbInfra?.testLogic?.validateCrossTenant !== false) {
        // validateCrossTenant is true by default, so we validate unless explicitly disabled
        // The result already contains isolation verification, but we can add additional checks
        if (!result.isolationVerified) {
          this.logger.warn(`Cross-tenant isolation validation failed for ${tenant1} vs ${tenant2}`);
        }
      }

      // Run custom validations if present
      if (dbInfra?.testLogic?.customValidations && dbInfra.testLogic.customValidations.length > 0) {
        result.details = {
          ...result.details,
          customValidationResults: dbInfra.testLogic.customValidations.map(validation => ({
            name: validation.name,
            passed: this.evaluateCustomValidation(validation.condition, result),
            description: validation.description,
          })),
        };
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
    applicationId?: string;
    databaseId?: string;
    userId?: string;
    resourceId?: string;
    resourceType?: string;
  }) {
    try {
      let dbInfra: DatabaseInfrastructure | null = null;
      let userId: string;
      let resourceId: string;
      let resourceType: string;

      if (dto.applicationId) {
        const application = await this.applicationDataService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.databases || application.infrastructure.databases.length === 0) {
          throw new ValidationException('Application has no database infrastructure configured');
        }
        
        // Find specific database or use first one
        if (dto.databaseId) {
          dbInfra = application.infrastructure.databases.find(db => db.id === dto.databaseId);
          if (!dbInfra) {
            throw new NotFoundException(`Database ${dto.databaseId} not found in application infrastructure`);
          }
        } else {
          dbInfra = application.infrastructure.databases[0];
        }
        
        // Resource information must be provided inline (not stored in infrastructure)
        if (dto.resourceId && dto.resourceType) {
          resourceId = dto.resourceId;
          resourceType = dto.resourceType;
        } else {
          throw new ValidationException(
            'Resource information is required. Please provide resourceId and resourceType inline.'
          );
        }
        
        userId = dto.userId || 'test-user';
      } else {
        if (!dto.userId) {
          throw new ValidationException('userId is required when applicationId is not provided');
        }
        if (!dto.resourceId) {
          throw new ValidationException('resourceId is required when applicationId is not provided');
        }
        if (!dto.resourceType) {
          throw new ValidationException('resourceType is required when applicationId is not provided');
        }
        userId = dto.userId;
        resourceId = dto.resourceId;
        resourceType = dto.resourceType;
      }

      const user: User = {
        id: userId,
        email: `${userId}@example.com`,
        role: 'viewer',
        attributes: {},
      };

      const resource: Resource = {
        id: resourceId,
        type: resourceType,
        attributes: {},
      };

      const result = await this.tester.testPolicyBypassAttempts(user, resource);

      // Apply testLogic if config provided
      if (dbInfra?.testLogic) {
        // Run custom validations if present
        if (dbInfra.testLogic.customValidations && dbInfra.testLogic.customValidations.length > 0) {
          result.forEach((testResult, index) => {
            if (dbInfra?.testLogic?.customValidations) {
              testResult.details = {
                ...testResult.details,
                customValidationResults: dbInfra.testLogic.customValidations.map(validation => ({
                  name: validation.name,
                  passed: this.evaluateCustomValidation(validation.condition, testResult),
                  description: validation.description,
                })),
              };
            }
          });
        }
      }

      // Apply validationRules if config provided
      if (dbInfra?.validationRules) {
        result.forEach(testResult => {
          testResult.details = {
            ...testResult.details,
            validationApplied: true,
          };
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

