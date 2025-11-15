/**
 * ABAC Correctness Test Suite
 * 
 * Orchestrates ABAC implementation correctness tests including attribute validation, completeness, performance, conflicts, and propagation
 */

import { TestResult } from '../../core/types';
import { ABACPolicy } from '../../core/types';
import { PolicyDecisionPoint } from '../policy-decision-point';
import { ABACAttributeValidator, ABACAttribute } from '../abac-attribute-validator';
import { ABACCompletenessTester, CompletenessTestConfig } from '../abac-completeness-tester';
import { ABACPerformanceTester, PerformanceTestConfig } from '../abac-performance-tester';
import { ABACConflictTester, ConflictTestConfig } from '../abac-conflict-tester';
import { ABACPropagationTester, PropagationTestConfig } from '../abac-propagation-tester';

export interface ABACCorrectnessTestConfig {
  attributes: ABACAttribute[];
  policies: ABACPolicy[];
  resourceTypes: string[];
  userRoles: string[];
  performanceConfig?: PerformanceTestConfig;
  propagationConfig?: PropagationTestConfig;
}

export class ABACCorrectnessTestSuite {
  private attributeValidator: ABACAttributeValidator;
  private completenessTester: ABACCompletenessTester;
  private performanceTester: ABACPerformanceTester;
  private conflictTester: ABACConflictTester;
  private propagationTester: ABACPropagationTester;
  private pdp: PolicyDecisionPoint;

  constructor(pdp?: PolicyDecisionPoint) {
    this.pdp = pdp || new PolicyDecisionPoint({
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

  /**
   * Run all ABAC correctness tests
   */
  async runAllTests(
    config: ABACCorrectnessTestConfig
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Test 1: Attribute Validation
    for (const attribute of config.attributes) {
      try {
        const attributeResult = await this.attributeValidator.validateAttributeDefinition(attribute);
        results.push({
          testType: 'access-control',
          testName: `ABAC Attribute Validation - ${attribute.name}`,
          passed: attributeResult.passed,
          details: attributeResult,
          timestamp: new Date(),
        });
      } catch (error: any) {
        results.push({
          testType: 'access-control',
          testName: `ABAC Attribute Validation - ${attribute.name}`,
          passed: false,
          details: { error: error.message },
          timestamp: new Date(),
          error: error.message,
        });
      }
    }

    // Test 2: Policy Completeness
    try {
      const completenessConfig: CompletenessTestConfig = {
        resourceTypes: config.resourceTypes,
        userRoles: config.userRoles,
        actions: ['read', 'write', 'delete', 'create'],
        policies: config.policies,
      };
      const completenessResult = await this.completenessTester.testPolicyCompleteness(completenessConfig);
      results.push({
        testType: 'access-control',
        testName: 'ABAC Policy Completeness Test',
        passed: completenessResult.passed,
        details: completenessResult,
        timestamp: new Date(),
      });
    } catch (error: any) {
      results.push({
        testType: 'access-control',
        testName: 'ABAC Policy Completeness Test',
        passed: false,
        details: { error: error.message },
        timestamp: new Date(),
        error: error.message,
      });
    }

    // Test 3: Performance Testing
    if (config.performanceConfig) {
      try {
        const performanceResult = await this.performanceTester.testEvaluationLatency(config.performanceConfig);
        results.push({
          testType: 'access-control',
          testName: 'ABAC Performance Test',
          passed: performanceResult.passed,
          details: performanceResult,
          timestamp: new Date(),
        });
      } catch (error: any) {
        results.push({
          testType: 'access-control',
          testName: 'ABAC Performance Test',
          passed: false,
          details: { error: error.message },
          timestamp: new Date(),
          error: error.message,
        });
      }
    }

    // Test 4: Conflict Detection
    try {
      const conflictConfig: ConflictTestConfig = {
        policies: config.policies,
        resolutionStrategy: 'priority',
      };
      const conflictResult = await this.conflictTester.detectPolicyConflicts(conflictConfig);
      results.push({
        testType: 'access-control',
        testName: 'ABAC Conflict Detection Test',
        passed: conflictResult.passed,
        details: conflictResult,
        timestamp: new Date(),
      });
    } catch (error: any) {
      results.push({
        testType: 'access-control',
        testName: 'ABAC Conflict Detection Test',
        passed: false,
        details: { error: error.message },
        timestamp: new Date(),
        error: error.message,
      });
    }

    // Test 5: Attribute Propagation
    if (config.propagationConfig) {
      try {
        const propagationResult = await this.propagationTester.testAttributePropagation(config.propagationConfig);
        results.push({
          testType: 'access-control',
          testName: 'ABAC Attribute Propagation Test',
          passed: propagationResult.passed,
          details: propagationResult,
          timestamp: new Date(),
        });
      } catch (error: any) {
        results.push({
          testType: 'access-control',
          testName: 'ABAC Attribute Propagation Test',
          passed: false,
          details: { error: error.message },
          timestamp: new Date(),
          error: error.message,
        });
      }
    }

    return results;
  }
}

