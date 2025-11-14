#!/usr/bin/env ts-node

/**
 * Main entry point for running compliance tests
 */

import { TestOrchestrator } from '../core/test-harness';
import { loadTestSuite } from '../tests/test-suite-loader';
import { ComplianceReporter } from '../services/compliance-reporter';
import { ComplianceDashboard } from '../dashboard/compliance-dashboard';
import { ABACPolicyLoader } from '../services/abac-policy-loader';
import { TestConfiguration } from '../core/types';
import * as path from 'path';
import * as fs from 'fs/promises';

async function main() {
  const suiteName = process.env.TEST_SUITE || 'default';
  const outputDir = process.env.OUTPUT_DIR || path.join(__dirname, '../reports');

  // Ensure output directory exists
  await fs.mkdir(outputDir, { recursive: true });

  console.log(`Loading test suite: ${suiteName}`);
  const testSuite = await loadTestSuite(suiteName);

  console.log('Initializing TestOrchestrator...');
  
  // Load ABAC policies if available
  let abacPolicies = [];
  const abacPolicyPath = process.env.ABAC_POLICIES_PATH || path.join(__dirname, '../policies/abac-policies.json');
  try {
    const policyLoader = new ABACPolicyLoader();
    if (await fs.access(abacPolicyPath).then(() => true).catch(() => false)) {
      abacPolicies = await policyLoader.loadPoliciesFromFile(abacPolicyPath);
      console.log(`Loaded ${abacPolicies.length} ABAC policies`);
    }
  } catch (error) {
    console.warn('Could not load ABAC policies, using defaults:', error);
  }

  const policyMode = (process.env.POLICY_MODE as 'rbac' | 'abac' | 'hybrid') || 'hybrid';
  
  const config: TestConfiguration = {
    userSimulationConfig: {
      roles: testSuite.userRoles,
      attributes: {},
    },
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: policyMode,
      abacPolicies: abacPolicies.length > 0 ? abacPolicies : undefined,
    },
    dataBehaviorConfig: {
      enableQueryLogging: true,
      piiDetectionRules: [
        { fieldPattern: '.*email.*', piiType: 'email' },
        { fieldPattern: '.*ssn.*', piiType: 'ssn' },
        { fieldPattern: '.*phone.*', piiType: 'phone' },
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
      outputPath: outputDir,
      includeDetails: true,
    },
  };

  const orchestrator = new TestOrchestrator(config);
  const reporter = new ComplianceReporter(config.reportingConfig);
  const dashboard = new ComplianceDashboard(reporter);

  console.log('Running test suite...');
  const results = await orchestrator.runTestSuite(testSuite);

  console.log(`\nTest Results: ${results.filter(r => r.passed).length}/${results.length} passed`);

  // Generate report
  console.log('Generating compliance report...');
  const report = await reporter.generateReport(results);

  // Generate dashboard data
  console.log('Generating dashboard data...');
  const dashboardData = await dashboard.generateDashboardData(results);

  // Save dashboard data
  const dashboardPath = path.join(outputDir, 'dashboard-data.json');
  await fs.writeFile(dashboardPath, JSON.stringify(dashboardData, null, 2));

  // Check compliance
  const isCompliant = orchestrator.isCompliant(results);
  console.log(`\nCompliance Status: ${isCompliant ? '✅ PASSED' : '❌ FAILED'}`);

  if (!isCompliant) {
    console.error('\nCompliance violations detected. Review the report for details.');
    process.exit(1);
  }

  console.log('\n✅ All compliance tests passed!');
}

main().catch(error => {
  console.error('Error running compliance tests:', error);
  process.exit(1);
});

