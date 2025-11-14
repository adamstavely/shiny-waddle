/**
 * Basic Usage Example
 * 
 * Demonstrates how to use the TestOrchestrator framework
 */

import { TestOrchestrator } from '../core/test-harness';
import { TestConfiguration, TestSuite } from '../core/types';

async function main() {
  // 1. Define test configuration
  const config: TestConfiguration = {
    userSimulationConfig: {
      roles: ['admin', 'researcher', 'analyst', 'viewer'],
      attributes: {},
    },
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
    },
    dataBehaviorConfig: {
      enableQueryLogging: true,
      piiDetectionRules: [
        { fieldPattern: '.*email.*', piiType: 'email' },
        { fieldPattern: '.*ssn.*', piiType: 'ssn' },
      ],
    },
    contractTestConfig: {
      autoGenerateTests: true,
    },
    datasetHealthConfig: {
      privacyMetrics: [
        { name: 'k-anonymity', type: 'k-anonymity', threshold: 10 },
      ],
    },
    reportingConfig: {
      outputFormat: 'json',
      outputPath: './reports',
      includeDetails: true,
    },
  };

  // 2. Create test suite
  const testSuite: TestSuite = {
    name: 'Basic Compliance Tests',
    application: 'my-app',
    team: 'my-team',
    includeAccessControlTests: true,
    includeDataBehaviorTests: true,
    includeContractTests: false,
    includeDatasetHealthTests: false,
    userRoles: ['admin', 'viewer'],
    resources: [
      {
        id: 'resource-1',
        type: 'report',
        attributes: { sensitivity: 'internal' },
        sensitivity: 'internal',
      },
    ],
    contexts: [
      { ipAddress: '192.168.1.1', timeOfDay: '14:00' },
    ],
    testQueries: [
      {
        name: 'Get reports',
        sql: 'SELECT id, title FROM reports WHERE workspace_id = 1',
      },
    ],
    allowedFields: {
      viewer: ['id', 'title'],
      admin: ['*'],
    },
    requiredFilters: {
      viewer: [{ field: 'workspace_id', operator: '=', value: 1 }],
    },
  };

  // 3. Initialize TestOrchestrator
  const orchestrator = new TestOrchestrator(config);

  // 4. Run tests
  console.log('Running compliance tests...');
  const results = await orchestrator.runTestSuite(testSuite);

  // 5. Check compliance
  const isCompliant = orchestrator.isCompliant(results);
  console.log(`Compliance: ${isCompliant ? 'PASSED' : 'FAILED'}`);

  // 6. Generate report
  const { ComplianceReporter } = await import('../services/compliance-reporter');
  const reporter = new ComplianceReporter(config.reportingConfig);
  const report = await reporter.generateReport(results);

  console.log(`Overall Score: ${report.summary.passRate}%`);
  console.log(`Passed: ${report.summary.passedTests}/${report.summary.totalTests}`);

  // 7. Exit with appropriate code for CI/CD
  process.exit(isCompliant ? 0 : 1);
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});

