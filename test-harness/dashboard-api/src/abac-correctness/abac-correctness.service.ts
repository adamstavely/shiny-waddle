import { Injectable, Logger } from '@nestjs/common';
import { ABACAttributeValidator, ABACAttribute } from '../../../services/abac-attribute-validator';
import { ABACCompletenessTester, CompletenessTestConfig } from '../../../services/abac-completeness-tester';
import { ABACPerformanceTester, PerformanceTestConfig } from '../../../services/abac-performance-tester';
import { ABACConflictTester, ConflictTestConfig } from '../../../services/abac-conflict-tester';
import { ABACPropagationTester, PropagationTestConfig } from '../../../services/abac-propagation-tester';
import { PolicyDecisionPoint } from '../../../services/policy-decision-point';
import { ABACPolicy } from '../../../core/types';
import { InternalServerException } from '../common/exceptions/business.exception';
import {
  ValidateAttributesDto,
  CompletenessTestConfigDto,
  PerformanceTestConfigDto,
  ConflictTestConfigDto,
  PropagationTestConfigDto,
} from './dto/abac-correctness.dto';

@Injectable()
export class ABACCorrectnessService {
  private readonly logger = new Logger(ABACCorrectnessService.name);
  private attributeValidator: ABACAttributeValidator;
  private completenessTester: ABACCompletenessTester;
  private performanceTester: ABACPerformanceTester;
  private conflictTester: ABACConflictTester;
  private propagationTester: ABACPropagationTester;
  private pdp: PolicyDecisionPoint;

  constructor() {
    this.pdp = new PolicyDecisionPoint({
      policyEngine: 'custom',
      policyMode: 'abac',
      abacPolicies: [],
    });
    this.attributeValidator = new ABACAttributeValidator();
    this.completenessTester = new ABACCompletenessTester();
    this.performanceTester = new ABACPerformanceTester(this.pdp);
    this.conflictTester = new ABACConflictTester(this.pdp);
    this.propagationTester = new ABACPropagationTester();
  }

  async validateAttributes(dto: ValidateAttributesDto) {
    try {
      const attributes: ABACAttribute[] = dto.attributes || [];
      const results = [];

      for (const attr of attributes) {
        const result = await this.attributeValidator.validateAttributeDefinition(attr);
        results.push(result);
      }

      return {
        passed: results.every(r => r.passed),
        results,
      };
    } catch (error: any) {
      this.logger.error(`Error validating attributes: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to validate attributes', { originalError: error.message });
    }
  }

  async testCompleteness(dto: CompletenessTestConfigDto) {
    try {
      const config: CompletenessTestConfig = {
        resourceTypes: dto.resourceTypes || [],
        userRoles: dto.userRoles || [],
        actions: dto.actions || ['read', 'write', 'delete', 'create'],
        policies: dto.policies || [],
      };

      return await this.completenessTester.testPolicyCompleteness(config);
    } catch (error: any) {
      this.logger.error(`Error testing completeness: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to test completeness', { originalError: error.message });
    }
  }

  async testPerformance(dto: PerformanceTestConfigDto) {
    try {
      const config: PerformanceTestConfig = {
        policies: dto.policies || [],
        testRequests: dto.testRequests || [],
        loadConfig: dto.loadConfig,
      };

      return await this.performanceTester.testEvaluationLatency(config);
    } catch (error: any) {
      this.logger.error(`Error testing performance: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to test performance', { originalError: error.message });
    }
  }

  async detectConflicts(dto: ConflictTestConfigDto) {
    try {
      const config: ConflictTestConfig = {
        policies: dto.policies || [],
        resolutionStrategy: dto.resolutionStrategy || 'priority',
      };

      return await this.conflictTester.detectPolicyConflicts(config);
    } catch (error: any) {
      this.logger.error(`Error detecting conflicts: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to detect conflicts', { originalError: error.message });
    }
  }

  async testPropagation(dto: PropagationTestConfigDto) {
    try {
      const config: PropagationTestConfig = {
        sourceSystem: dto.sourceSystem,
        targetSystems: dto.targetSystems || [],
        attributes: dto.attributes || [],
        transformationRules: dto.transformationRules,
      };

      return await this.propagationTester.testAttributePropagation(config);
    } catch (error: any) {
      this.logger.error(`Error testing propagation: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to test propagation', { originalError: error.message });
    }
  }
}

