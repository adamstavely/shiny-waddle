import { Injectable, Logger } from '@nestjs/common';
import { CICDSecurityGates } from '../../../heimdall-framework/services/cicd-security-gates';
import { SecurityGateConfig, PullRequest, ABACPolicy } from '../../../heimdall-framework/core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class SecurityGatesService {
  private readonly logger = new Logger(SecurityGatesService.name);
  private gates: CICDSecurityGates;

  constructor() {
    this.gates = new CICDSecurityGates();
  }

  async validatePreMerge(dto: { pr: PullRequest; policies: ABACPolicy[] }) {
    try {
      if (!dto.pr) {
        throw new ValidationException('Pull request is required');
      }
      if (!dto.pr.id) {
        throw new ValidationException('Pull request id is required');
      }
      if (!dto.policies || !Array.isArray(dto.policies)) {
        throw new ValidationException('Policies array is required');
      }
      return await this.gates.validatePreMergePolicies(dto.pr, dto.policies);
    } catch (error: any) {
      this.logger.error(`Error validating pre-merge policies: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate pre-merge policies',
        { originalError: error.message },
      );
    }
  }

  async checkGates(dto: { pr: PullRequest; config: SecurityGateConfig }) {
    try {
      if (!dto.pr) {
        throw new ValidationException('Pull request is required');
      }
      if (!dto.pr.id) {
        throw new ValidationException('Pull request id is required');
      }
      if (!dto.config) {
        throw new ValidationException('Security gate configuration is required');
      }
      if (typeof dto.config.severityThreshold !== 'string') {
        throw new ValidationException('Severity threshold is required');
      }
      const validSeverities = ['low', 'medium', 'high', 'critical'];
      if (!validSeverities.includes(dto.config.severityThreshold)) {
        throw new ValidationException(
          `Invalid severity threshold. Must be one of: ${validSeverities.join(', ')}`,
        );
      }
      return await this.gates.checkSecurityGates(dto.pr, dto.config);
    } catch (error: any) {
      this.logger.error(`Error checking security gates: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to check security gates',
        { originalError: error.message },
      );
    }
  }
}

