import { Injectable, Logger } from '@nestjs/common';
import { PolicyValidationTester } from '../../../heimdall-framework/services/policy-validation-tester';
import { PolicyDecisionPoint } from '../../../heimdall-framework/services/policy-decision-point';
import { ABACPolicy, Resource, AccessControlConfig } from '../../../heimdall-framework/core/types';
import { PolicyTestCase } from '../../../heimdall-framework/services/policy-as-code';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class PolicyValidationService {
  private readonly logger = new Logger(PolicyValidationService.name);
  private tester: PolicyValidationTester;
  private pdp: PolicyDecisionPoint;

  constructor() {
    // Initialize PDP (would be injected in real implementation)
    const config: AccessControlConfig = {
      policyMode: 'abac',
      cacheDecisions: false,
    };
    this.pdp = new PolicyDecisionPoint(config);
    this.tester = new PolicyValidationTester(this.pdp);
  }

  async detectConflicts(dto: { policies: ABACPolicy[] }) {
    try {
      if (!dto.policies || !Array.isArray(dto.policies)) {
        throw new ValidationException('Policies array is required');
      }
      return await this.tester.detectPolicyConflicts(dto.policies);
    } catch (error: any) {
      this.logger.error(`Error detecting policy conflicts: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to detect policy conflicts',
        { originalError: error.message },
      );
    }
  }

  async analyzeCoverage(dto: { resources: Resource[]; policies: ABACPolicy[] }) {
    try {
      if (!dto.resources || !Array.isArray(dto.resources)) {
        throw new ValidationException('Resources array is required');
      }
      if (!dto.policies || !Array.isArray(dto.policies)) {
        throw new ValidationException('Policies array is required');
      }
      return await this.tester.analyzePolicyCoverage(dto.resources, dto.policies);
    } catch (error: any) {
      this.logger.error(`Error analyzing policy coverage: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to analyze policy coverage',
        { originalError: error.message },
      );
    }
  }

  async testPerformance(dto: { policy: ABACPolicy; iterations?: number }) {
    try {
      if (!dto.policy) {
        throw new ValidationException('Policy is required');
      }
      if (!dto.policy.id) {
        throw new ValidationException('Policy id is required');
      }
      if (dto.iterations !== undefined) {
        if (dto.iterations < 1 || dto.iterations > 100000) {
          throw new ValidationException('Iterations must be between 1 and 100000');
        }
      }
      const iterations = dto.iterations || 1000;
      return await this.tester.testPolicyPerformance(dto.policy, iterations);
    } catch (error: any) {
      this.logger.error(`Error testing policy performance: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test policy performance',
        { originalError: error.message },
      );
    }
  }

  async runRegression(dto: {
    baselinePolicies: ABACPolicy[];
    currentPolicies: ABACPolicy[];
    testCases: PolicyTestCase[];
  }) {
    try {
      if (!dto.baselinePolicies || !Array.isArray(dto.baselinePolicies)) {
        throw new ValidationException('Baseline policies array is required');
      }
      if (!dto.currentPolicies || !Array.isArray(dto.currentPolicies)) {
        throw new ValidationException('Current policies array is required');
      }
      if (!dto.testCases || !Array.isArray(dto.testCases)) {
        throw new ValidationException('Test cases array is required');
      }
      return await this.tester.runRegressionTests(
        dto.baselinePolicies,
        dto.currentPolicies,
        dto.testCases,
      );
    } catch (error: any) {
      this.logger.error(`Error running regression tests: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to run regression tests',
        { originalError: error.message },
      );
    }
  }

  async simulatePolicy(dto: { policy: ABACPolicy; testCases: PolicyTestCase[] }) {
    try {
      if (!dto.policy) {
        throw new ValidationException('Policy is required');
      }
      if (!dto.testCases || !Array.isArray(dto.testCases) || dto.testCases.length === 0) {
        throw new ValidationException('At least one test case is required');
      }
      return await this.tester.simulatePolicyChange(dto.policy, dto.testCases);
    } catch (error: any) {
      this.logger.error(`Error simulating policy: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to simulate policy',
        { originalError: error.message },
      );
    }
  }
}

