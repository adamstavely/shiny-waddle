import { Injectable, Logger, NotFoundException, Inject, forwardRef } from '@nestjs/common';
import { DLPTester } from '../../../heimdall-framework/services/dlp-tester';
import { User, DataOperation, TestQuery, DLPPattern } from '../../../heimdall-framework/core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { ApplicationsService } from '../applications/applications.service';
import { DLPInfrastructure } from '../applications/entities/application.entity';
import { validateDLPConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class DLPService {
  private readonly logger = new Logger(DLPService.name);
  private tester: DLPTester;

  constructor(
    @Inject(forwardRef(() => ApplicationsService))
    private readonly applicationsService: ApplicationsService,
  ) {
    this.tester = new DLPTester();
  }

  async testExfiltration(dto: { applicationId?: string; user?: User; dataOperation?: DataOperation }) {
    try {
      let user: User;
      let dataOperation: DataOperation;
      let dlpInfra: DLPInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.dlp) {
          throw new ValidationException('Application has no DLP infrastructure configured');
        }
        
        dlpInfra = application.infrastructure.dlp;
        
        // Validate configuration completeness (warnings only for DLP as patterns are optional)
        const validationErrors = validateDLPConfig({
          id: application.id,
          name: application.name,
          type: 'dlp' as const,
          patterns: dlpInfra.patterns,
          bulkExportLimits: dlpInfra.bulkExportLimits,
          piiDetectionRules: dlpInfra.piiDetectionRules,
          exportRestrictions: dlpInfra.exportRestrictions,
          aggregationRequirements: dlpInfra.aggregationRequirements,
          fieldRestrictions: dlpInfra.fieldRestrictions,
          joinRestrictions: dlpInfra.joinRestrictions,
          testLogic: dlpInfra.testLogic,
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        if (validationErrors.length > 0 && validationErrors.some(e => !e.message.includes('recommended'))) {
          const errorMessage = formatValidationErrors(validationErrors, application.name);
          throw new ValidationException(
            `DLP infrastructure for application '${application.name}' has validation issues for exfiltration test:\n${errorMessage}`
          );
        }
        
        // Use patterns and restrictions from infrastructure
        const testerConfig: any = {};
        if (dlpInfra.patterns && dlpInfra.patterns.length > 0) {
          testerConfig.patterns = dlpInfra.patterns;
        }
        if (dlpInfra.exportRestrictions) {
          testerConfig.exportRestrictions = dlpInfra.exportRestrictions;
        }
        if (dlpInfra.aggregationRequirements) {
          testerConfig.aggregationRequirements = dlpInfra.aggregationRequirements;
        }
        if (dlpInfra.fieldRestrictions) {
          testerConfig.fieldRestrictions = dlpInfra.fieldRestrictions;
        }
        if (dlpInfra.joinRestrictions) {
          testerConfig.joinRestrictions = dlpInfra.joinRestrictions;
        }
        if (Object.keys(testerConfig).length > 0) {
          this.tester = new DLPTester(testerConfig);
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
      if (dlpInfra?.testLogic) {
        // Apply custom checks if present
        if (dlpInfra.testLogic.customChecks && dlpInfra.testLogic.customChecks.length > 0) {
          result.customCheckResults = dlpInfra.testLogic.customChecks.map(check => ({
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
    applicationId?: string;
    apiResponse: any;
    allowedFields?: string[];
    piiFields?: string[];
  }) {
    try {
      let allowedFields: string[];
      let piiFields: string[];
      let dlpInfra: DLPInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.dlp) {
          throw new ValidationException('Application has no DLP infrastructure configured');
        }
        
        dlpInfra = application.infrastructure.dlp;
        
        // Use patterns from infrastructure
        if (dlpInfra.patterns && dlpInfra.patterns.length > 0) {
          this.tester = new DLPTester({ patterns: dlpInfra.patterns });
        }

        // Extract allowed fields from patterns (fields that should be allowed)
        allowedFields = dto.allowedFields || [];
        
        // Extract PII fields from piiDetectionRules
        piiFields = dto.piiFields || (dlpInfra.piiDetectionRules?.map(rule => rule.fieldName) || []);

        // Apply testLogic.validateAPIResponses flag
        if (dlpInfra.testLogic?.validateAPIResponses === false) {
          // If explicitly disabled, skip validation
          return { validated: false, skipped: true, reason: 'API response validation disabled in infrastructure' };
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
      if (dlpInfra?.testLogic?.customChecks && dlpInfra.testLogic.customChecks.length > 0) {
        result.customCheckResults = dlpInfra.testLogic.customChecks.map(check => ({
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

  async testQueryValidation(dto: { applicationId?: string; query: TestQuery; user: User; expectedFields?: string[] }) {
    try {
      let expectedFields: string[];
      let dlpInfra: DLPInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.dlp) {
          throw new ValidationException('Application has no DLP infrastructure configured');
        }
        
        dlpInfra = application.infrastructure.dlp;
        
        // Use patterns and restrictions from infrastructure
        const testerConfig: any = {};
        if (dlpInfra.patterns && dlpInfra.patterns.length > 0) {
          testerConfig.patterns = dlpInfra.patterns;
        }
        if (dlpInfra.fieldRestrictions) {
          testerConfig.fieldRestrictions = dlpInfra.fieldRestrictions;
        }
        if (dlpInfra.joinRestrictions) {
          testerConfig.joinRestrictions = dlpInfra.joinRestrictions;
        }
        if (dlpInfra.aggregationRequirements) {
          testerConfig.aggregationRequirements = dlpInfra.aggregationRequirements;
        }
        if (Object.keys(testerConfig).length > 0) {
          this.tester = new DLPTester(testerConfig);
        }

        // Extract expected fields from piiDetectionRules if not provided
        expectedFields = dto.expectedFields || (dlpInfra.piiDetectionRules?.map(rule => rule.fieldName) || []);
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
      if (dlpInfra?.testLogic?.customChecks && dlpInfra.testLogic.customChecks.length > 0) {
        result.customCheckResults = dlpInfra.testLogic.customChecks.map(check => ({
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
    applicationId?: string;
    user?: User;
    exportRequest?: { type: 'csv' | 'json' | 'excel' | 'api'; recordCount: number };
  }) {
    try {
      let user: User;
      let exportRequest: { type: 'csv' | 'json' | 'excel' | 'api'; recordCount: number };
      let dlpInfra: DLPInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.dlp) {
          throw new ValidationException('Application has no DLP infrastructure configured');
        }
        
        dlpInfra = application.infrastructure.dlp;
        
        // Use bulk export limits and restrictions from infrastructure
        const testerConfig: any = {};
        if (dlpInfra.bulkExportLimits) {
          testerConfig.bulkExportLimits = dlpInfra.bulkExportLimits;
        }
        if (dlpInfra.patterns && dlpInfra.patterns.length > 0) {
          testerConfig.patterns = dlpInfra.patterns;
        }
        if (dlpInfra.exportRestrictions) {
          testerConfig.exportRestrictions = dlpInfra.exportRestrictions;
        }
        if (dlpInfra.aggregationRequirements) {
          testerConfig.aggregationRequirements = dlpInfra.aggregationRequirements;
        }
        if (dlpInfra.fieldRestrictions) {
          testerConfig.fieldRestrictions = dlpInfra.fieldRestrictions;
        }
        if (dlpInfra.joinRestrictions) {
          testerConfig.joinRestrictions = dlpInfra.joinRestrictions;
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
      if (dlpInfra?.testLogic?.checkBulkExports === false) {
        return { checked: false, skipped: true, reason: 'Bulk export checking disabled in infrastructure' };
      }

      // Extract fields from export request if available
      const exportFields = (exportRequest as any).fields || [];
      const result = await this.tester.testBulkExportControls(user, {
        ...exportRequest,
        fields: exportFields,
      });

      // Apply testLogic custom checks if present
      if (dlpInfra?.testLogic?.customChecks && dlpInfra.testLogic.customChecks.length > 0) {
        result.customCheckResults = dlpInfra.testLogic.customChecks.map(check => ({
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

