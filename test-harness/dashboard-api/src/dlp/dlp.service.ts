import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { DLPTester } from '../../../services/dlp-tester';
import { User, DataOperation, TestQuery, DLPPattern } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { DLPConfigurationEntity } from '../test-configurations/entities/test-configuration.entity';
import { validateDLPConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class DLPService {
  private readonly logger = new Logger(DLPService.name);
  private tester: DLPTester;

  constructor(private readonly configService: TestConfigurationsService) {
    this.tester = new DLPTester();
  }

  async testExfiltration(dto: { configId?: string; user?: User; dataOperation?: DataOperation }) {
    try {
      let user: User;
      let dataOperation: DataOperation;
      let dlpConfig: DLPConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'dlp') {
          throw new ValidationException(`Configuration ${dto.configId} is not a DLP configuration`);
        }
        dlpConfig = config as DLPConfigurationEntity;
        
        // Validate configuration completeness (warnings only for DLP as patterns are optional)
        const validationErrors = validateDLPConfig(dlpConfig);
        if (validationErrors.length > 0 && validationErrors.some(e => !e.message.includes('recommended'))) {
          const errorMessage = formatValidationErrors(validationErrors, dlpConfig.name);
          throw new ValidationException(
            `Configuration '${dlpConfig.name}' has validation issues for DLP exfiltration test:\n${errorMessage}`
          );
        }
        
        // DLP configs don't store user/operation, so we need them from request
        // But we can use patterns from config
        if (dlpConfig.patterns && dlpConfig.patterns.length > 0) {
          this.tester = new DLPTester({ patterns: dlpConfig.patterns });
        }
        user = dto.user || { id: 'test-user', email: 'test@example.com', role: 'viewer', attributes: {} };
        dataOperation = dto.dataOperation || { type: 'export', data: {} };
      } else {
        user = dto.user!;
        dataOperation = dto.dataOperation!;
      }

      this.validateUser(user);
      if (!dataOperation) {
        throw new ValidationException('Data operation is required');
      }
      if (!dataOperation.type) {
        throw new ValidationException('Data operation type is required');
      }
      const validTypes = ['export', 'read', 'api-call'];
      if (!validTypes.includes(dataOperation.type)) {
        throw new ValidationException(
          `Invalid operation type. Must be one of: ${validTypes.join(', ')}`,
        );
      }
      const result = await this.tester.testDataExfiltration(user, dataOperation);

      // Apply testLogic if config provided
      if (dlpConfig?.testLogic) {
        // Apply custom checks if present
        if (dlpConfig.testLogic.customChecks && dlpConfig.testLogic.customChecks.length > 0) {
          result.customCheckResults = dlpConfig.testLogic.customChecks.map(check => ({
            name: check.name,
            passed: this.evaluateCustomCheck(check.condition, result),
            description: check.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing data exfiltration: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test data exfiltration',
        { originalError: error.message },
      );
    }
  }

  async validateAPIResponse(dto: {
    configId?: string;
    apiResponse: any;
    allowedFields?: string[];
    piiFields?: string[];
  }) {
    try {
      let allowedFields: string[];
      let piiFields: string[];
      let dlpConfig: DLPConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'dlp') {
          throw new ValidationException(`Configuration ${dto.configId} is not a DLP configuration`);
        }
        dlpConfig = config as DLPConfigurationEntity;
        
        // Use patterns and piiDetectionRules from config
        if (dlpConfig.patterns && dlpConfig.patterns.length > 0) {
          this.tester = new DLPTester({ patterns: dlpConfig.patterns });
        }

        // Extract allowed fields from patterns (fields that should be allowed)
        allowedFields = dto.allowedFields || [];
        
        // Extract PII fields from piiDetectionRules
        piiFields = dto.piiFields || (dlpConfig.piiDetectionRules?.map(rule => rule.fieldName) || []);

        // Apply testLogic.validateAPIResponses flag
        if (dlpConfig.testLogic?.validateAPIResponses === false) {
          // If explicitly disabled, skip validation
          return { validated: false, skipped: true, reason: 'API response validation disabled in configuration' };
        }
      } else {
        allowedFields = dto.allowedFields || [];
        piiFields = dto.piiFields || [];
      }

      if (!dto.apiResponse) {
        throw new ValidationException('API response is required');
      }
      if (!allowedFields || !Array.isArray(allowedFields)) {
        throw new ValidationException('Allowed fields array is required');
      }
      if (!piiFields || !Array.isArray(piiFields)) {
        throw new ValidationException('PII fields array is required');
      }

      const result = await this.tester.validateAPIResponse(
        dto.apiResponse,
        allowedFields,
        piiFields,
      );

      // Apply testLogic custom checks if present
      if (dlpConfig?.testLogic?.customChecks && dlpConfig.testLogic.customChecks.length > 0) {
        result.customCheckResults = dlpConfig.testLogic.customChecks.map(check => ({
          name: check.name,
          passed: this.evaluateCustomCheck(check.condition, result),
          description: check.description,
        }));
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error validating API response: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate API response',
        { originalError: error.message },
      );
    }
  }

  async testQueryValidation(dto: { configId?: string; query: TestQuery; user: User; expectedFields?: string[] }) {
    try {
      let expectedFields: string[];
      let dlpConfig: DLPConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'dlp') {
          throw new ValidationException(`Configuration ${dto.configId} is not a DLP configuration`);
        }
        dlpConfig = config as DLPConfigurationEntity;
        
        // Use patterns from config
        if (dlpConfig.patterns && dlpConfig.patterns.length > 0) {
          this.tester = new DLPTester({ patterns: dlpConfig.patterns });
        }

        // Extract expected fields from piiDetectionRules if not provided
        expectedFields = dto.expectedFields || (dlpConfig.piiDetectionRules?.map(rule => rule.fieldName) || []);
      } else {
        expectedFields = dto.expectedFields || [];
      }

      this.validateUser(dto.user);
      if (!dto.query) {
        throw new ValidationException('Test query is required');
      }
      if (!expectedFields || !Array.isArray(expectedFields)) {
        throw new ValidationException('Expected fields array is required');
      }
      if (expectedFields.length === 0) {
        throw new ValidationException('At least one expected field is required');
      }

      const result = await this.tester.testQueryResultValidation(
        dto.query,
        dto.user,
        expectedFields,
      );

      // Apply testLogic custom checks if present
      if (dlpConfig?.testLogic?.customChecks && dlpConfig.testLogic.customChecks.length > 0) {
        result.customCheckResults = dlpConfig.testLogic.customChecks.map(check => ({
          name: check.name,
          passed: this.evaluateCustomCheck(check.condition, result),
          description: check.description,
        }));
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing query validation: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test query validation',
        { originalError: error.message },
      );
    }
  }

  async testBulkExport(dto: {
    configId?: string;
    user?: User;
    exportRequest?: { type: 'csv' | 'json' | 'excel' | 'api'; recordCount: number };
  }) {
    try {
      let user: User;
      let exportRequest: { type: 'csv' | 'json' | 'excel' | 'api'; recordCount: number };
      let dlpConfig: DLPConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'dlp') {
          throw new ValidationException(`Configuration ${dto.configId} is not a DLP configuration`);
        }
        dlpConfig = config as DLPConfigurationEntity;
        // Use bulk export limits from config if available
        const testerConfig: any = {};
        if (dlpConfig.bulkExportLimits) {
          testerConfig.bulkExportLimits = dlpConfig.bulkExportLimits;
        }
        if (dlpConfig.patterns && dlpConfig.patterns.length > 0) {
          testerConfig.patterns = dlpConfig.patterns;
        }
        if (Object.keys(testerConfig).length > 0) {
          this.tester = new DLPTester(testerConfig);
        }
        user = dto.user || { id: 'test-user', email: 'test@example.com', role: 'viewer', attributes: {} };
        exportRequest = dto.exportRequest || { type: 'csv', recordCount: 1000 };
      } else {
        user = dto.user!;
        exportRequest = dto.exportRequest!;
      }

      this.validateUser(user);
      if (!exportRequest) {
        throw new ValidationException('Export request is required');
      }
      if (!exportRequest.type) {
        throw new ValidationException('Export type is required');
      }
      const validTypes = ['csv', 'json', 'excel', 'api'];
      if (!validTypes.includes(exportRequest.type)) {
        throw new ValidationException(
          `Invalid export type. Must be one of: ${validTypes.join(', ')}`,
        );
      }
      if (typeof exportRequest.recordCount !== 'number' || exportRequest.recordCount < 1) {
        throw new ValidationException('Record count must be a positive number');
      }

      // Apply testLogic.checkBulkExports flag
      if (dlpConfig?.testLogic?.checkBulkExports === false) {
        return { checked: false, skipped: true, reason: 'Bulk export checking disabled in configuration' };
      }

      const result = await this.tester.testBulkExportControls(user, exportRequest);

      // Apply testLogic custom checks if present
      if (dlpConfig?.testLogic?.customChecks && dlpConfig.testLogic.customChecks.length > 0) {
        result.customCheckResults = dlpConfig.testLogic.customChecks.map(check => ({
          name: check.name,
          passed: this.evaluateCustomCheck(check.condition, result),
          description: check.description,
        }));
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing bulk export: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test bulk export controls',
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

  private evaluateCustomCheck(condition: string, result: any): boolean {
    // Simple evaluation of custom check conditions
    // In a real implementation, this would use a proper expression evaluator library
    try {
      // Extract common values from result object
      const blocked = result.blocked || false;
      const detected = result.detected || false;
      const passed = result.passed || false;
      const violations = result.violations || 0;

      // Replace common patterns in condition string with actual values
      let evalCondition = condition
        .replace(/\bblocked\b/g, String(blocked))
        .replace(/\bdetected\b/g, String(detected))
        .replace(/\bpassed\b/g, String(passed))
        .replace(/\bviolations\b/g, String(violations));

      // Basic safety check - only allow simple comparisons and numbers/booleans
      if (!/^[0-9.\s()><=!&|truefalse]+$/i.test(evalCondition)) {
        this.logger.warn(`Unsafe check condition: ${condition}`);
        return false;
      }

      // Use Function constructor as safer alternative to eval
      const func = new Function('return ' + evalCondition);
      return func();
    } catch (error) {
      this.logger.error(`Error evaluating custom check: ${condition}`, error);
      return false;
    }
  }
}

