#!/usr/bin/env ts-node

/**
 * Main entry point for running compliance tests
 */

import { TestOrchestrator } from '../core/test-harness';
import { loadTestSuite } from '../tests/test-suite-loader';
import { ComplianceReporter } from '../services/compliance-reporter';
import { ABACPolicyLoader } from '../services/abac-policy-loader';
import { TestConfiguration } from '../core/types';
import { loadRuntimeConfigFromEnv, loadRuntimeConfigFromFile, validateRuntimeConfig } from '../core/config-loader';
import * as path from 'path';
import * as fs from 'fs/promises';

async function main() {
  const suiteName = process.env.TEST_SUITE || 'default';
  const outputDir = process.env.OUTPUT_DIR || path.join(__dirname, '../reports');
  const configFile = process.env.TEST_CONFIG_FILE;

  // Ensure output directory exists
  await fs.mkdir(outputDir, { recursive: true });

  // Load runtime configuration
  let runtimeConfig;
  if (configFile) {
    console.log(`Loading runtime config from file: ${configFile}`);
    runtimeConfig = await loadRuntimeConfigFromFile(configFile);
  } else {
    console.log('Loading runtime config from environment variables...');
    runtimeConfig = loadRuntimeConfigFromEnv();
  }

  // Validate runtime configuration
  const validation = validateRuntimeConfig(runtimeConfig);
  if (!validation.valid) {
    console.error('Runtime configuration validation failed:');
    validation.errors.forEach(error => console.error(`  - ${error}`));
    if (validation.warnings) {
      console.warn('Warnings:');
      validation.warnings.forEach(warning => console.warn(`  - ${warning}`));
    }
    process.exit(1);
  }
  if (validation.warnings && validation.warnings.length > 0) {
    console.warn('Runtime configuration warnings:');
    validation.warnings.forEach(warning => console.warn(`  - ${warning}`));
  }

  console.log(`Loading test suite: ${suiteName}`);
  const testSuite = await loadTestSuite(suiteName, runtimeConfig);

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
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: policyMode,
      abacPolicies: abacPolicies.length > 0 ? abacPolicies : undefined,
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

  console.log('Running test suite...');
  // Pass runtime config to test execution
  const results = await orchestrator.runTestSuite(testSuite, undefined, runtimeConfig);

  console.log(`\nTest Results: ${results.filter(r => r.passed).length}/${results.length} passed`);

  // Generate report
  console.log('Generating compliance report...');
  const report = await reporter.generateReport(results);

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

