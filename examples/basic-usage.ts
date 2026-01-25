/**
 * Basic Usage Example
 * 
 * Demonstrates how to use the TestOrchestrator framework.
 * 
 * IMPORTANT: Application names, contexts, and other environment-specific
 * values should be provided via runtime configuration, not hardcoded.
 */

import { TestOrchestrator } from '../heimdall-framework/core/test-harness';
import { TestConfiguration, TestSuite } from '../heimdall-framework/core/types';
import { loadRuntimeConfigFromEnv } from '../heimdall-framework/core/config-loader';

async function main() {
  // 1. Define test configuration
  const config: TestConfiguration = {
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
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

  // Load runtime configuration from environment variables
  const runtimeConfig = loadRuntimeConfigFromEnv();

  // 2. Create test suite
  // Use runtime config for application name and contexts
  const testSuite: TestSuite = {
    name: 'Basic Compliance Tests',
    application: runtimeConfig.applicationName || 'default-app',
    team: 'default-team',
    testType: 'access-control',
    testIds: [],
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    // Use contexts from runtime config if available
    runtimeConfig,
  };

  // 3. Initialize TestOrchestrator
  const orchestrator = new TestOrchestrator(config);

  // 4. Run tests with runtime configuration
  console.log('Running compliance tests...');
  const results = await orchestrator.runTestSuite(testSuite, undefined, runtimeConfig);

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

