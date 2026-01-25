import { Injectable, Logger } from '@nestjs/common';
import { NIST800207Compliance } from '../../../heimdall-framework/services/nist-800-207-compliance';
import { ComplianceAssessment } from '../../../heimdall-framework/core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class NIST800207Service {
  private readonly logger = new Logger(NIST800207Service.name);
  private compliance: NIST800207Compliance;

  constructor() {
    this.compliance = new NIST800207Compliance();
  }

  async assessZTAPillars(assessment?: any): Promise<ComplianceAssessment> {
    try {
      // Assessment is optional, but if provided, validate structure
      if (assessment && typeof assessment !== 'object') {
        throw new ValidationException('Assessment must be an object');
      }
      return await this.compliance.assessZTAPillars(assessment || {});
    } catch (error: any) {
      this.logger.error(`Error assessing ZTA pillars: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to assess ZTA pillars',
        { originalError: error.message },
      );
    }
  }

  async generateComplianceReport(assessment: ComplianceAssessment): Promise<string> {
    try {
      if (!assessment) {
        throw new ValidationException('Compliance assessment is required');
      }
      if (!assessment.framework) {
        throw new ValidationException('Assessment framework is required');
      }
      if (!assessment.assessment) {
        throw new ValidationException('Assessment data is required');
      }
      return await this.compliance.generateComplianceReport(assessment);
    } catch (error: any) {
      this.logger.error(`Error generating compliance report: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to generate compliance report',
        { originalError: error.message },
      );
    }
  }
}

