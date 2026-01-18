/**
 * Heimdall Framework
 * 
 * Main orchestrator for running compliance tests against applications
 */

import { AccessControlTester } from '../services/access-control-tester';
import { DatasetHealthTester } from '../services/dataset-health-tester';
import { ComplianceReporter } from '../services/compliance-reporter';
import { 
  TestResult, 
  TestSuite, 
  TestConfiguration,
  Test,
  AccessControlTest,
  DatasetHealthTest,
  ABACPolicy,
} from './types';
import { RuntimeTestConfig } from './runtime-config';
import { mergeRuntimeConfig } from './config-loader';

// Test loader interface - implementations should load tests by IDs
export interface TestLoader {
  loadTests(testIds: string[]): Promise<Test[]>;
  loadPolicy(policyId: string): Promise<ABACPolicy>; // Changed to 1:1 - load single policy
  loadApplication(applicationId: string): Promise<any>; // Load application with infrastructure
}

export class TestOrchestrator {
  private accessControlTester: AccessControlTester;
  private datasetHealthTester: DatasetHealthTester;
  private complianceReporter: ComplianceReporter;
  private testLoader?: TestLoader;

  constructor(config: TestConfiguration, testLoader?: TestLoader) {
    this.accessControlTester = new AccessControlTester(config.accessControlConfig);
    this.datasetHealthTester = new DatasetHealthTester(config.datasetHealthConfig);
    this.complianceReporter = new ComplianceReporter(config.reportingConfig);
    this.testLoader = testLoader;
  }

  /**
   * Run a complete test suite by loading and executing individual tests
   * 
   * @param suite - Test suite to run
   * @param tests - Optional pre-loaded tests (if not provided, will be loaded via testLoader)
   * @param runtimeConfig - Optional runtime configuration to merge with suite config
   */
  async runTestSuite(
    suite: TestSuite,
    tests?: Test[],
    runtimeConfig?: RuntimeTestConfig
  ): Promise<TestResult[]> {
    if (!this.testLoader && !tests) {
      throw new Error('TestLoader must be provided or tests must be passed directly');
    }

    // Merge runtime config into suite if provided
    let mergedSuite = suite;
    if (runtimeConfig) {
      mergedSuite = mergeRuntimeConfig(suite, runtimeConfig);
    }

    // Load tests if not provided
    let testEntities: Test[] = tests || [];
    if (!tests && this.testLoader) {
      testEntities = await this.testLoader.loadTests(mergedSuite.testIds);
    }

    // Validate all tests match suite type
    for (const test of testEntities) {
      if (test.testType !== mergedSuite.testType) {
        throw new Error(
          `Test ${test.id} (${test.testType}) does not match suite type ${mergedSuite.testType}`
        );
      }
    }

    // Execute each test
    const results: TestResult[] = [];
    for (const test of testEntities) {
      try {
        const result = await this.runTest(test, mergedSuite);
        results.push(result);
      } catch (error: any) {
        results.push({
          testType: test.testType,
          testName: test.name,
          passed: false,
          details: { error: error.message },
          timestamp: new Date(),
          error: error.message,
          testId: test.id,
          testVersion: test.version,
        });
      }
    }

    return results;
  }

  /**
   * Run a single test
   */
  async runTest(test: Test, suite: TestSuite): Promise<TestResult> {
    switch (test.testType) {
      case 'access-control':
        return this.runAccessControlTest(test as AccessControlTest, suite);
      case 'dataset-health':
        return this.runDatasetHealthTest(test as DatasetHealthTest, suite);
      default:
        throw new Error(`Test type ${test.testType} execution not yet implemented`);
    }
  }

  /**
   * Run a single access control test (1:1 with Policy)
   */
  async runAccessControlTest(test: AccessControlTest, suite: TestSuite): Promise<TestResult> {
    // Load policy (1:1 relationship)
    if (!test.policyId) {
      throw new Error('AccessControlTest must have policyId (1:1 relationship with Policy)');
    }

    let policy: ABACPolicy;
    if (this.testLoader) {
      policy = await this.testLoader.loadPolicy(test.policyId);
    } else {
      throw new Error('TestLoader must be provided to load policies');
    }

    // Use test inputs (new structure) or fall back to deprecated fields
    const subject = test.inputs?.subject || {
      role: test.role, // DEPRECATED: fallback
      attributes: {},
    };

    const resource = test.inputs?.resource || test.resource; // DEPRECATED: fallback
    const context = test.inputs?.context || test.context || {}; // DEPRECATED: fallback

    // Merge with runtime config context if available
    if (suite.runtimeConfig?.contexts && suite.runtimeConfig.contexts.length > 0) {
      Object.assign(context, suite.runtimeConfig.contexts[0]);
    }

    // Create user from subject
    const user = {
      id: 'test-user',
      email: 'test@example.com',
      role: subject.role as any,
      attributes: subject.attributes || {},
    };

    // Execute test
    const result = await this.accessControlTester.testPDPDecision({
      user,
      resource,
      context,
      expectedDecision: test.expected?.allowed ?? test.expectedDecision ?? true, // Support both new and old structure
    });

    const expectedAllowed = test.expected?.allowed ?? test.expectedDecision ?? true;

    return {
      testType: 'access-control',
      testName: test.name,
      passed: result.allowed === expectedAllowed,
      details: {
        ...result,
        policyTested: test.policyId,
        appliedPolicies: result.policyRules,
      },
      timestamp: new Date(),
      testId: test.id,
      testVersion: test.version,
      policyId: test.policyId, // 1:1 relationship
      // DEPRECATED: Keep for backward compatibility
      policyIds: [test.policyId],
    };
  }

  /**
   * Run a single dataset health test
   */
  async runDatasetHealthTest(test: DatasetHealthTest, suite: TestSuite): Promise<TestResult> {
    const result = await this.datasetHealthTester.testDataset({
      dataset: test.dataset,
      privacyThresholds: test.privacyThresholds,
      statisticalFidelityTargets: test.statisticalFidelityTargets,
    });

    const expectedCompliant = test.expected?.compliant ?? result.compliant;

    return {
      testType: 'dataset-health',
      testName: test.name,
      passed: result.compliant === expectedCompliant,
      details: {
        ...result,
        expected: test.expected,
      },
      timestamp: new Date(),
      testId: test.id,
      testVersion: test.version,
      policyId: test.policyId, // Optional - may be undefined
    };
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(results: TestResult[]): Promise<any> {
    return this.complianceReporter.generateReport(results);
  }

  /**
   * Check if results indicate compliance (for CI/CD blocking)
   */
  isCompliant(results: TestResult[]): boolean {
    return results.every(result => result.passed);
  }
}

