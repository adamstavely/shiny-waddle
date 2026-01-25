/**
 * Heimdall Framework
 * 
 * Main orchestrator for running compliance tests against applications
 */

import { AccessControlTester } from '../services/access-control-tester';
import { DatasetHealthTester } from '../services/dataset-health-tester';
import { PlatformConfigTester } from '../services/platform-config-tester';
import { ComplianceReporter } from '../services/compliance-reporter';
import { MultiRegionTestingService } from '../services/multi-region-testing.service';
import { PolicyConsistencyChecker } from '../services/policy-consistency-checker.service';
import { PolicySyncTester } from '../services/policy-sync-tester.service';
import { PolicyDecisionPoint } from '../services/policy-decision-point';
import { 
  TestResult, 
  TestSuite, 
  TestConfiguration,
  Test,
  AccessControlTest,
  DatasetHealthTest,
  PlatformConfigTest,
  SalesforceExperienceCloudTest,
  DistributedSystemsTest,
  ABACPolicy,
} from './types';
import { RuntimeTestConfig } from './runtime-config';
import { mergeRuntimeConfig } from './config-loader';
import { SalesforceExperienceCloudTester, SalesforceExperienceCloudConfig } from '../services/salesforce-experience-cloud-tester';

// Test loader interface - implementations should load tests by IDs
export interface TestLoader {
  loadTests(testIds: string[]): Promise<Test[]>;
  loadPolicy(policyId: string): Promise<ABACPolicy>; // Changed to 1:1 - load single policy
  loadApplication(applicationId: string): Promise<any>; // Load application with infrastructure
}

export class TestOrchestrator {
  private accessControlTester: AccessControlTester;
  private datasetHealthTester: DatasetHealthTester;
  private platformConfigTester: PlatformConfigTester;
  private complianceReporter: ComplianceReporter;
  private testLoader?: TestLoader;

  constructor(config: TestConfiguration, testLoader?: TestLoader) {
    this.accessControlTester = new AccessControlTester(config.accessControlConfig);
    this.datasetHealthTester = new DatasetHealthTester(config.datasetHealthConfig);
    this.platformConfigTester = new PlatformConfigTester();
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
      case 'salesforce-config':
      case 'salesforce-security':
      case 'elastic-config':
      case 'elastic-security':
      case 'k8s-security':
      case 'k8s-workload':
      case 'idp-compliance':
      case 'servicenow-config':
        return this.runPlatformConfigTest(test as PlatformConfigTest, suite);
      case 'salesforce-experience-cloud':
        return this.runSalesforceExperienceCloudTest(test as SalesforceExperienceCloudTest, suite);
      case 'distributed-systems':
        return this.runDistributedSystemsTest(test as DistributedSystemsTest, suite);
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

    // Use test inputs (new structure)
    if (!test.inputs?.subject) {
      throw new Error('AccessControlTest must have inputs.subject');
    }
    if (!test.inputs?.resource) {
      throw new Error('AccessControlTest must have inputs.resource');
    }

    const subject = test.inputs.subject;
    const resource = test.inputs.resource;
    const context = test.inputs.context || {};

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
      expectedDecision: test.expected?.allowed ?? true,
    });

    const expectedAllowed = test.expected?.allowed ?? true;

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
   * Run a single platform config test
   */
  async runPlatformConfigTest(test: PlatformConfigTest, suite: TestSuite): Promise<TestResult> {
    // Try to get application with infrastructure if available
    let application: any = undefined;
    if (this.testLoader && suite.application) {
      try {
        application = await this.testLoader.loadApplication(suite.application);
      } catch (error) {
        // Application not found, continue without it
      }
    }

    return await this.platformConfigTester.execute(test, suite, application);
  }

  /**
   * Run a single Salesforce Experience Cloud test
   */
  async runSalesforceExperienceCloudTest(test: SalesforceExperienceCloudTest, suite: TestSuite): Promise<TestResult> {
    try {
      // Get configuration from suite runtime config
      const runtimeConfig = suite.runtimeConfig as any;
      const testConfig: SalesforceExperienceCloudConfig = {
        url: runtimeConfig?.url || runtimeConfig?.salesforceExperienceCloud?.url,
        cookies: runtimeConfig?.cookies || runtimeConfig?.salesforceExperienceCloud?.cookies,
        outputDir: runtimeConfig?.outputDir || runtimeConfig?.salesforceExperienceCloud?.outputDir,
        objectList: runtimeConfig?.objectList || runtimeConfig?.salesforceExperienceCloud?.objectList,
        app: runtimeConfig?.app || runtimeConfig?.salesforceExperienceCloud?.app,
        aura: runtimeConfig?.aura || runtimeConfig?.salesforceExperienceCloud?.aura,
        context: runtimeConfig?.context || runtimeConfig?.salesforceExperienceCloud?.context,
        token: runtimeConfig?.token || runtimeConfig?.salesforceExperienceCloud?.token,
        noGraphQL: runtimeConfig?.noGraphQL ?? runtimeConfig?.salesforceExperienceCloud?.noGraphQL,
        proxy: runtimeConfig?.proxy || runtimeConfig?.salesforceExperienceCloud?.proxy,
        insecure: runtimeConfig?.insecure ?? runtimeConfig?.salesforceExperienceCloud?.insecure,
        auraRequestFile: runtimeConfig?.auraRequestFile || runtimeConfig?.salesforceExperienceCloud?.auraRequestFile,
        auraInspectorPath: runtimeConfig?.auraInspectorPath || runtimeConfig?.salesforceExperienceCloud?.auraInspectorPath,
        timeout: runtimeConfig?.timeout || runtimeConfig?.salesforceExperienceCloud?.timeout,
        pythonPath: runtimeConfig?.pythonPath || runtimeConfig?.salesforceExperienceCloud?.pythonPath,
      };

      if (!testConfig.url) {
        throw new Error('Salesforce Experience Cloud URL is required in test suite runtime config');
      }

      const tester = new SalesforceExperienceCloudTester(testConfig);
      let testResult: any;

      // Execute based on test subtype
      switch (test.testSubtype) {
        case 'guest-access':
          testResult = await tester.testGuestAccess();
          break;
        case 'authenticated-access':
          testResult = await tester.testAuthenticatedAccess();
          break;
        case 'graphql':
          testResult = await tester.testGraphQLCapability();
          break;
        case 'self-registration':
          testResult = await tester.testSelfRegistration();
          break;
        case 'record-lists':
          testResult = await tester.testRecordListComponents();
          break;
        case 'home-urls':
          testResult = await tester.testHomeURLs();
          break;
        case 'object-access':
          if (!testConfig.objectList || testConfig.objectList.length === 0) {
            throw new Error('objectList is required for object-access test');
          }
          testResult = await tester.testObjectAccess(testConfig.objectList);
          break;
        case 'full-audit':
          // Full audit returns multiple results, but we'll return the first one
          const auditResults = await tester.runFullAudit();
          testResult = auditResults[0] || {
            testType: 'salesforce-experience-cloud',
            testName: 'Full Audit',
            passed: false,
            details: { error: 'No results from full audit' },
            timestamp: new Date(),
          };
          break;
        default:
          throw new Error(`Unknown Salesforce Experience Cloud test subtype: ${test.testSubtype}`);
      }

      // Check expected results if provided
      let passed = testResult.passed;
      if (test.expected) {
        if (test.expected.maxSeverity && testResult.details?.findings) {
          const severities = ['low', 'medium', 'high', 'critical'];
          const maxFoundSeverity = testResult.details.findings.reduce((max: string, f: any) => {
            const currentIdx = severities.indexOf(f.severity || 'low');
            const maxIdx = severities.indexOf(max);
            return currentIdx > maxIdx ? f.severity : max;
          }, 'low');
          const expectedIdx = severities.indexOf(test.expected.maxSeverity);
          const foundIdx = severities.indexOf(maxFoundSeverity);
          if (foundIdx > expectedIdx) {
            passed = false;
          }
        }
        if (test.expected.maxFindings !== undefined && testResult.details?.findings) {
          if (testResult.details.findings.length > test.expected.maxFindings) {
            passed = false;
          }
        }
        if (test.expected.passed !== undefined) {
          passed = testResult.passed === test.expected.passed;
        }
      }

      return {
        testType: test.testType,
        testName: test.name || testResult.testName,
        passed,
        details: {
          ...testResult.details,
          testSubtype: test.testSubtype,
          configUrl: testConfig.url,
        },
        timestamp: testResult.timestamp || new Date(),
        testId: test.id,
        testVersion: test.version,
      };
    } catch (error: any) {
      return {
        testType: test.testType,
        testName: test.name,
        passed: false,
        details: {
          error: error.message,
          testSubtype: test.testSubtype,
        },
        timestamp: new Date(),
        testId: test.id,
        testVersion: test.version,
        error: error.message,
      };
    }
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(results: TestResult[]): Promise<any> {
    return this.complianceReporter.generateReport(results);
  }

  /**
   * Run a distributed systems test
   */
  async runDistributedSystemsTest(test: DistributedSystemsTest, suite: TestSuite): Promise<TestResult> {
    const startTime = Date.now();
    const result: TestResult = {
      testType: 'distributed-systems',
      testName: test.name,
      testId: test.id,
      testVersion: test.version,
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      // Validate test configuration
      if (!test.distributedTestType) {
        throw new Error('distributedTestType is required for distributed systems tests');
      }

      // Load application to get region configuration
      let application: any = null;
      if (test.applicationId) {
        application = await this.testLoader.loadApplication(test.applicationId);
        if (!application?.infrastructure?.distributedSystems) {
          throw new Error(`Application ${test.applicationId} does not have distributed systems infrastructure configured`);
        }
      } else {
        throw new Error('applicationId is required for distributed systems tests');
      }

      const regions = application.infrastructure.distributedSystems.regions || [];
      if (regions.length < 2) {
        throw new Error('At least 2 regions are required for distributed systems testing');
      }

      // Convert regions to format expected by services
      const regionConfigs = regions.map((region: any) => ({
        id: region.id,
        name: region.name,
        endpoint: region.endpoint,
        pdpEndpoint: region.pdpEndpoint,
        timezone: region.timezone,
        latency: region.latency,
        credentials: region.credentials,
      }));

      // Route to appropriate service based on distributedTestType
      switch (test.distributedTestType) {
        case 'multi-region':
          return await this.runMultiRegionTest(test, suite, regionConfigs, result);
        
        case 'policy-consistency':
          return await this.runPolicyConsistencyTest(test, suite, regionConfigs, result);
        
        case 'policy-synchronization':
          return await this.runPolicySynchronizationTest(test, suite, regionConfigs, result);
        
        default:
          throw new Error(`Unknown distributed test type: ${test.distributedTestType}`);
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
      return result;
    }
  }

  /**
   * Run multi-region test
   */
  private async runMultiRegionTest(
    test: DistributedSystemsTest,
    suite: TestSuite,
    regionConfigs: any[],
    result: TestResult
  ): Promise<TestResult> {
    const config = test.multiRegionConfig || {};
    const regionsToTest = config.regions 
      ? regionConfigs.filter(r => config.regions!.includes(r.id))
      : regionConfigs;

    if (regionsToTest.length === 0) {
      throw new Error('No regions found matching the specified region IDs');
    }

    const multiRegionService = new MultiRegionTestingService({
      regions: regionsToTest,
      executionMode: config.executionMode || 'parallel',
      timeout: config.timeout || 30000,
    }, new PolicyDecisionPoint({
      policyEngine: 'custom',
      cacheDecisions: true,
    }));

    const executionResult = await multiRegionService.executeMultiRegionTest({
      name: test.name,
      testType: 'access-control',
      user: config.user,
      resource: config.resource,
      action: config.action,
      regions: config.regions,
      expectedResult: config.expectedResult,
      timeout: config.timeout,
    });

    result.passed = executionResult.passed;
    result.details = {
      distributedTestType: 'multi-region',
      aggregatedResult: executionResult.aggregatedResult,
      regionResults: executionResult.regionResults,
      coordinationMetrics: executionResult.coordinationMetrics,
      errors: executionResult.errors,
    };

    return result;
  }

  /**
   * Run policy consistency test
   */
  private async runPolicyConsistencyTest(
    test: DistributedSystemsTest,
    suite: TestSuite,
    regionConfigs: any[],
    result: TestResult
  ): Promise<TestResult> {
    const config = test.policyConsistencyConfig || {};
    const regionsToCheck = config.regions
      ? regionConfigs.filter(r => config.regions!.includes(r.id))
      : regionConfigs;

    if (regionsToCheck.length < 2) {
      throw new Error('At least 2 regions are required for policy consistency checking');
    }

    const checker = new PolicyConsistencyChecker();
    const report = await checker.checkConsistency(regionsToCheck, {
      regions: config.regions || [],
      policyIds: config.policyIds,
      checkTypes: config.checkTypes,
    });

    result.passed = report.consistent;
    result.details = {
      distributedTestType: 'policy-consistency',
      report: {
        id: report.id,
        timestamp: report.timestamp,
        regionsChecked: report.regionsChecked,
        policiesChecked: report.policiesChecked,
        consistent: report.consistent,
        inconsistencies: report.inconsistencies,
        summary: report.summary,
        recommendations: report.recommendations,
      },
    };

    return result;
  }

  /**
   * Run policy synchronization test
   */
  private async runPolicySynchronizationTest(
    test: DistributedSystemsTest,
    suite: TestSuite,
    regionConfigs: any[],
    result: TestResult
  ): Promise<TestResult> {
    const config = test.policySyncConfig || {};
    const regionsToTest = config.regions
      ? regionConfigs.filter(r => config.regions!.includes(r.id))
      : regionConfigs;

    if (regionsToTest.length < 2) {
      throw new Error('At least 2 regions are required for policy synchronization testing');
    }

    const tester = new PolicySyncTester();
    const report = await tester.testSynchronization(regionsToTest, {
      regions: config.regions || [],
      policyId: config.policyId,
      testScenarios: config.testScenarios,
    });

    // Test passes if all test scenarios pass
    const allPassed = report.testResults.every(tr => tr.passed);
    result.passed = allPassed;
    result.details = {
      distributedTestType: 'policy-synchronization',
      report: {
        id: report.id,
        timestamp: report.timestamp,
        regionsTested: report.regionsTested,
        testResults: report.testResults,
        summary: report.summary,
        recommendations: report.recommendations,
      },
    };

    return result;
  }

  /**
   * Check if results indicate compliance (for CI/CD blocking)
   */
  isCompliant(results: TestResult[]): boolean {
    return results.every(result => result.passed);
  }
}

