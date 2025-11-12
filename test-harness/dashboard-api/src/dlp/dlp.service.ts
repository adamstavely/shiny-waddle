import { Injectable, Logger } from '@nestjs/common';
import { DLPTester } from '../../../services/dlp-tester';
import { User, DataOperation, TestQuery, DLPPattern } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class DLPService {
  private readonly logger = new Logger(DLPService.name);
  private tester: DLPTester;

  constructor() {
    this.tester = new DLPTester();
  }

  async testExfiltration(dto: { user: User; dataOperation: DataOperation }) {
    try {
      this.validateUser(dto.user);
      if (!dto.dataOperation) {
        throw new ValidationException('Data operation is required');
      }
      if (!dto.dataOperation.type) {
        throw new ValidationException('Data operation type is required');
      }
      const validTypes = ['export', 'read', 'api-call'];
      if (!validTypes.includes(dto.dataOperation.type)) {
        throw new ValidationException(
          `Invalid operation type. Must be one of: ${validTypes.join(', ')}`,
        );
      }
      return await this.tester.testDataExfiltration(dto.user, dto.dataOperation);
    } catch (error: any) {
      this.logger.error(`Error testing data exfiltration: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test data exfiltration',
        { originalError: error.message },
      );
    }
  }

  async validateAPIResponse(dto: {
    apiResponse: any;
    allowedFields: string[];
    piiFields: string[];
  }) {
    try {
      if (!dto.apiResponse) {
        throw new ValidationException('API response is required');
      }
      if (!dto.allowedFields || !Array.isArray(dto.allowedFields)) {
        throw new ValidationException('Allowed fields array is required');
      }
      if (!dto.piiFields || !Array.isArray(dto.piiFields)) {
        throw new ValidationException('PII fields array is required');
      }
      return await this.tester.validateAPIResponse(
        dto.apiResponse,
        dto.allowedFields,
        dto.piiFields,
      );
    } catch (error: any) {
      this.logger.error(`Error validating API response: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate API response',
        { originalError: error.message },
      );
    }
  }

  async testQueryValidation(dto: { query: TestQuery; user: User; expectedFields: string[] }) {
    try {
      this.validateUser(dto.user);
      if (!dto.query) {
        throw new ValidationException('Test query is required');
      }
      if (!dto.expectedFields || !Array.isArray(dto.expectedFields)) {
        throw new ValidationException('Expected fields array is required');
      }
      if (dto.expectedFields.length === 0) {
        throw new ValidationException('At least one expected field is required');
      }
      return await this.tester.testQueryResultValidation(
        dto.query,
        dto.user,
        dto.expectedFields,
      );
    } catch (error: any) {
      this.logger.error(`Error testing query validation: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test query validation',
        { originalError: error.message },
      );
    }
  }

  async testBulkExport(dto: {
    user: User;
    exportRequest: { type: 'csv' | 'json' | 'excel' | 'api'; recordCount: number };
  }) {
    try {
      this.validateUser(dto.user);
      if (!dto.exportRequest) {
        throw new ValidationException('Export request is required');
      }
      if (!dto.exportRequest.type) {
        throw new ValidationException('Export type is required');
      }
      const validTypes = ['csv', 'json', 'excel', 'api'];
      if (!validTypes.includes(dto.exportRequest.type)) {
        throw new ValidationException(
          `Invalid export type. Must be one of: ${validTypes.join(', ')}`,
        );
      }
      if (typeof dto.exportRequest.recordCount !== 'number' || dto.exportRequest.recordCount < 1) {
        throw new ValidationException('Record count must be a positive number');
      }
      return await this.tester.testBulkExportControls(dto.user, dto.exportRequest);
    } catch (error: any) {
      this.logger.error(`Error testing bulk export: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
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
}

