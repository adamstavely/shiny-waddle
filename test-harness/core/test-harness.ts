/**
 * Heimdall Framework
 * 
 * Main orchestrator for running compliance tests against applications
 */

import { UserSimulator } from '../services/user-simulator';
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
  loadPolicies(policyIds: string[]): Promise<ABACPolicy[]>;
}

export class TestOrchestrator {
  private userSimulator: UserSimulator;
  private accessControlTester: AccessControlTester;
  private datasetHealthTester: DatasetHealthTester;
  private complianceReporter: ComplianceReporter;
  private testLoader?: TestLoader;

  constructor(config: TestConfiguration, testLoader?: TestLoader) {
    this.userSimulator = new UserSimulator(config.userSimulationConfig);
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
   * Run a single access control test
   */
  async runAccessControlTest(test: AccessControlTest, suite: TestSuite): Promise<TestResult> {
    // Load policies referenced by test
    let policies: ABACPolicy[] = [];
    if (this.testLoader && test.policyIds && test.policyIds.length > 0) {
      policies = await this.testLoader.loadPolicies(test.policyIds);
      // Configure access control tester with these policies
      // Note: This assumes AccessControlTester can be reconfigured
      // In a real implementation, you'd update the config or create a new tester
    }

    // Create user from test role
    const testUsers = await this.userSimulator.generateTestUsers([test.role]);
    const user = testUsers[0] || {
      id: 'test-user',
      email: 'test@example.com',
      role: test.role as any,
      attributes: {},
    };

    // Use context from runtime config if available, otherwise use test context
    let context = test.context || {};
    if (suite.runtimeConfig?.contexts && suite.runtimeConfig.contexts.length > 0) {
      // Use first context from runtime config, or merge with test context
      context = { ...context, ...suite.runtimeConfig.contexts[0] };
    }

    // Execute test
    const result = await this.accessControlTester.testPDPDecision({
      user,
      resource: test.resource,
      context,
      expectedDecision: test.expectedDecision,
    });

    return {
      testType: 'access-control',
      testName: test.name,
      passed: result.allowed === result.expectedAllowed,
      details: {
        ...result,
        policiesTested: test.policyIds,
        appliedPolicies: result.policyRules,
      },
      timestamp: new Date(),
      testId: test.id,
      testVersion: test.version,
      policyIds: test.policyIds,
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

    return {
      testType: 'dataset-health',
      testName: test.name,
      passed: result.compliant,
      details: result,
      timestamp: new Date(),
      testId: test.id,
      testVersion: test.version,
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

