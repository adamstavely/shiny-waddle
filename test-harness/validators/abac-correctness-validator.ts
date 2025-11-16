/**
 * ABAC Correctness Validator
 * 
 * Validates ABAC implementation correctness including attribute validation, completeness, performance, and conflicts.
 * This validator detects if a test suite has abacCorrectnessConfig and runs the appropriate ABAC correctness tests.
 */

import { BaseValidator } from '../core/base-validator';
import { ValidatorMetadata } from '../core/validator-registry';
import { TestResult, TestSuite, AccessControlConfig, AccessControlTestSuiteConfig } from '../core/types';
import { ABACAttributeValidator, ABACAttribute } from '../services/abac-attribute-validator';
import { ABACCompletenessTester, CompletenessTestConfig } from '../services/abac-completeness-tester';
import { ABACPerformanceTester, PerformanceTestConfig } from '../services/abac-performance-tester';
import { ABACConflictTester, ConflictTestConfig } from '../services/abac-conflict-tester';
import { PolicyDecisionPoint } from '../services/policy-decision-point';

export class ABACCorrectnessValidator extends BaseValidator {
  readonly id = 'abac-correctness';
  readonly name = 'ABAC Correctness Validator';
  readonly description = 'Validates ABAC implementation correctness including attributes, completeness, performance, and conflicts';
  readonly testType = 'access-control';
  readonly version = '1.0.0';

  readonly metadata: ValidatorMetadata = {
    supportedTestTypes: ['access-control'],
    requiredConfig: ['accessControlConfig'],
    optionalConfig: ['userSimulationConfig'],
    tags: ['abac', 'correctness', 'validation', 'policies', 'access-control'],
  };

  private accessControlConfig: AccessControlConfig;
  private attributeValidator: ABACAttributeValidator;
  private completenessTester: ABACCompletenessTester;
  private performanceTester: ABACPerformanceTester | null = null;
  private conflictTester: ABACConflictTester | null = null;
  private pdp: PolicyDecisionPoint | null = null;

  constructor(config: { accessControlConfig: AccessControlConfig; [key: string]: any }) {
    super(config);
    this.accessControlConfig = config.accessControlConfig;
    this.attributeValidator = new ABACAttributeValidator();
    this.completenessTester = new ABACCompletenessTester();
    
    // Initialize PDP and testers that require it
    this.pdp = new PolicyDecisionPoint(this.accessControlConfig);
    this.performanceTester = new ABACPerformanceTester(this.pdp);
    this.conflictTester = new ABACConflictTester(this.pdp);
  }

  /**
   * Check if this validator can handle the given test suite
   */
  canHandle(suite: TestSuite): boolean {
    // Check if suite has abacCorrectnessConfig
    const configSuite = suite as any as AccessControlTestSuiteConfig;
    return (
      suite.testType === 'access-control' &&
      configSuite.abacCorrectnessConfig !== undefined &&
      configSuite.abacCorrectnessConfig !== null
    );
  }

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];
    const configSuite = suite as any as AccessControlTestSuiteConfig;
    const abacConfig = configSuite.abacCorrectnessConfig;

    if (!abacConfig) {
      return results; // No ABAC correctness config, return empty results
    }

    // Test 1: Attribute Validation
    if (abacConfig.attributes && abacConfig.attributes.length > 0) {
      for (const attribute of abacConfig.attributes) {
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
    }

    // Test 2: Policy Completeness
    if (abacConfig.policies && abacConfig.resourceTypes && abacConfig.userRoles) {
      try {
        const completenessConfig: CompletenessTestConfig = {
          resourceTypes: abacConfig.resourceTypes,
          userRoles: abacConfig.userRoles,
          actions: ['read', 'write', 'delete', 'create'],
          policies: abacConfig.policies,
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
    }

    // Test 3: Performance Testing
    if (abacConfig.performanceConfig && this.performanceTester) {
      try {
        // Merge policies from abacConfig if not already in performanceConfig
        const performanceConfig: PerformanceTestConfig = {
          ...abacConfig.performanceConfig,
          policies: abacConfig.performanceConfig.policies.length > 0
            ? abacConfig.performanceConfig.policies
            : (abacConfig.policies || []),
        };
        const performanceResult = await this.performanceTester.testEvaluationLatency(performanceConfig);
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
    if (abacConfig.policies && abacConfig.policies.length > 0 && this.conflictTester) {
      try {
        const conflictConfig: ConflictTestConfig = {
          policies: abacConfig.policies,
          resolutionStrategy: abacConfig.conflictResolutionStrategy || 'priority',
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
    }

    return results;
  }

  validateConfig(config: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.accessControlConfig) {
      errors.push('accessControlConfig is required');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

