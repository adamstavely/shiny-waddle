/**
 * Heimdall Framework
 * 
 * Main orchestrator for running compliance tests against applications
 */

import { UserSimulator } from '../services/user-simulator';
import { AccessControlTester } from '../services/access-control-tester';
import { DataBehaviorTester } from '../services/data-behavior-tester';
import { ContractTester } from '../services/contract-tester';
import { DatasetHealthTester } from '../services/dataset-health-tester';
import { ComplianceReporter } from '../services/compliance-reporter';
import { TestResult, TestSuite, TestConfiguration } from './types';

export class TestOrchestrator {
  private userSimulator: UserSimulator;
  private accessControlTester: AccessControlTester;
  private dataBehaviorTester: DataBehaviorTester;
  private contractTester: ContractTester;
  private datasetHealthTester: DatasetHealthTester;
  private complianceReporter: ComplianceReporter;

  constructor(config: TestConfiguration) {
    this.userSimulator = new UserSimulator(config.userSimulationConfig);
    this.accessControlTester = new AccessControlTester(config.accessControlConfig);
    this.dataBehaviorTester = new DataBehaviorTester(config.dataBehaviorConfig);
    this.contractTester = new ContractTester(config.contractTestConfig);
    this.datasetHealthTester = new DatasetHealthTester(config.datasetHealthConfig);
    this.complianceReporter = new ComplianceReporter(config.reportingConfig);
  }

  /**
   * Run a complete test suite
   */
  async runTestSuite(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Run access control tests
    if (suite.includeAccessControlTests) {
      const accessControlResults = await this.runAccessControlTests(suite);
      results.push(...accessControlResults);
    }

    // Run data behavior tests
    if (suite.includeDataBehaviorTests) {
      const dataBehaviorResults = await this.runDataBehaviorTests(suite);
      results.push(...dataBehaviorResults);
    }

    // Run contract tests
    if (suite.includeContractTests) {
      const contractResults = await this.runContractTests(suite);
      results.push(...contractResults);
    }

    // Run dataset health tests
    if (suite.includeDatasetHealthTests) {
      const healthResults = await this.runDatasetHealthTests(suite);
      results.push(...healthResults);
    }

    return results;
  }

  /**
   * Run access control tests for representative identities, attributes, resources, and contexts
   */
  async runAccessControlTests(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];
    const testUsers = await this.userSimulator.generateTestUsers(suite.userRoles);

    for (const user of testUsers) {
      for (const resource of suite.resources) {
        for (const context of suite.contexts) {
          const result = await this.accessControlTester.testPDPDecision({
            user,
            resource,
            context,
            expectedDecision: suite.expectedDecisions?.[`${user.role}-${resource.type}`],
          });

          results.push({
            testType: 'access-control',
            testName: `PDP Decision: ${user.role} accessing ${resource.type}`,
            passed: result.allowed === result.expectedAllowed,
            details: result,
            timestamp: new Date(),
          });
        }
      }
    }

    return results;
  }

  /**
   * Run data behavior tests to verify queries only use permitted fields,
   * apply required filters/aggregations, and block disallowed joins
   */
  async runDataBehaviorTests(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];
    const testUsers = await this.userSimulator.generateTestUsers(suite.userRoles);

    for (const user of testUsers) {
      for (const query of suite.testQueries) {
        const result = await this.dataBehaviorTester.testQuery({
          user,
          query,
          expectedFields: suite.allowedFields?.[user.role],
          requiredFilters: suite.requiredFilters?.[user.role],
          disallowedJoins: suite.disallowedJoins?.[user.role],
        });

        results.push({
          testType: 'data-behavior',
          testName: `Query Validation: ${user.role} executing ${query.name}`,
          passed: result.compliant,
          details: result,
          timestamp: new Date(),
        });
      }
    }

    return results;
  }

  /**
   * Run contract tests based on machine-readable requirements
   */
  async runContractTests(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    for (const contract of suite.contracts) {
      const result = await this.contractTester.testContract(contract);

      results.push({
        testType: 'contract',
        testName: `Contract: ${contract.name}`,
        passed: result.compliant,
        details: result,
        timestamp: new Date(),
      });
    }

    return results;
  }

  /**
   * Run dataset health tests to assert masked/synthetic data meets privacy thresholds
   */
  async runDatasetHealthTests(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    for (const dataset of suite.datasets) {
      const result = await this.datasetHealthTester.testDataset({
        dataset,
        privacyThresholds: suite.privacyThresholds,
        statisticalFidelityTargets: suite.statisticalFidelityTargets,
      });

      results.push({
        testType: 'dataset-health',
        testName: `Dataset Health: ${dataset.name}`,
        passed: result.compliant,
        details: result,
        timestamp: new Date(),
      });
    }

    return results;
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

