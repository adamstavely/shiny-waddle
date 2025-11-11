/**
 * ABAC Usage Example
 * 
 * Demonstrates how to use Sentinel with ABAC policies
 */

import { Sentinel } from '../core/test-harness';
import { ABACPolicyLoader } from '../services/abac-policy-loader';
import { TestConfiguration, TestSuite } from '../core/types';
import * as path from 'path';

async function main() {
  // 1. Load ABAC policies
  const policyLoader = new ABACPolicyLoader();
  const abacPolicies = await policyLoader.loadPoliciesFromFile(
    path.join(__dirname, '../policies/abac-policies.json')
  );

  console.log(`Loaded ${abacPolicies.length} ABAC policies`);

  // 2. Define test configuration with ABAC support
  const config: TestConfiguration = {
    userSimulationConfig: {
      roles: ['admin', 'researcher', 'analyst', 'viewer'],
      attributes: {},
    },
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'abac', // Use ABAC mode
      abacPolicies: abacPolicies,
    },
    dataBehaviorConfig: {
      enableQueryLogging: true,
      piiDetectionRules: [
        { fieldPattern: '.*email.*', piiType: 'email' },
      ],
    },
    contractTestConfig: {
      autoGenerateTests: true,
    },
    datasetHealthConfig: {},
    reportingConfig: {
      outputFormat: 'json',
      outputPath: './reports',
      includeDetails: true,
    },
  };

  // 3. Create test suite with ABAC attributes
  const testSuite: TestSuite = {
    name: 'ABAC Compliance Tests',
    application: 'my-app',
    team: 'my-team',
    includeAccessControlTests: true,
    includeDataBehaviorTests: true,
    includeContractTests: false,
    includeDatasetHealthTests: false,
    userRoles: ['researcher', 'analyst'],
    resources: [
      {
        id: 'research-data',
        type: 'dataset',
        attributes: {
          department: 'Research',
          project: 'project-alpha',
          dataClassification: 'confidential',
        },
        sensitivity: 'confidential',
        abacAttributes: {
          department: 'Research',
          project: 'project-alpha',
          dataClassification: 'confidential',
          requiresCertification: 'data-science',
        },
      },
      {
        id: 'restricted-data',
        type: 'dataset',
        attributes: {
          department: 'Finance',
          dataClassification: 'restricted',
        },
        sensitivity: 'restricted',
        abacAttributes: {
          department: 'Finance',
          dataClassification: 'restricted',
          minClearanceLevel: 'high',
        },
      },
    ],
    contexts: [
      { 
        ipAddress: '192.168.1.1', 
        timeOfDay: '14:00', 
        location: 'headquarters',
      },
    ],
    testQueries: [
      {
        name: 'Access research data',
        sql: 'SELECT * FROM research_data WHERE department = \'Research\'',
      },
    ],
    allowedFields: {
      researcher: ['id', 'title', 'data'],
      analyst: ['id', 'title'],
    },
  };

  // 4. Initialize Sentinel
  const sentinel = new Sentinel(config);

  // 5. Run tests
  console.log('Running ABAC compliance tests...');
  const results = await sentinel.runTestSuite(testSuite);

  // 6. Check compliance
  const isCompliant = sentinel.isCompliant(results);
  console.log(`Compliance: ${isCompliant ? 'PASSED' : 'FAILED'}`);

  // 7. Generate report
  const { ComplianceReporter } = await import('../services/compliance-reporter');
  const reporter = new ComplianceReporter(config.reportingConfig);
  const report = await reporter.generateReport(results);

  console.log(`Overall Score: ${report.summary.passRate}%`);
  console.log(`Passed: ${report.summary.passedTests}/${report.summary.totalTests}`);

  // Show ABAC-specific results
  const abacResults = results.filter(r => 
    r.testType === 'access-control' && 
    r.details?.conditions?.policyMode === 'abac'
  );
  console.log(`\nABAC Test Results: ${abacResults.filter(r => r.passed).length}/${abacResults.length} passed`);

  process.exit(isCompliant ? 0 : 1);
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});

