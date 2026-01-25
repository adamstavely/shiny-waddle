/**
 * Test Command
 * Handles test execution CLI commands
 */

import { Command } from 'commander';
import { TestOrchestrator } from '../../core/test-harness';
import { loadTestSuite, listAvailableSuites } from '../../tests/test-suite-loader';
import { ComplianceReporter } from '../../services/compliance-reporter';
import { ABACPolicyLoader } from '../../services/abac-policy-loader';
import { TestConfiguration } from '../../core/types';
import { loadRuntimeConfigFromEnv, loadRuntimeConfigFromFile, validateRuntimeConfig } from '../../core/config-loader';
import * as path from 'path';
import * as fs from 'fs/promises';
// Optional chokidar for watch mode
let chokidar: any;
try {
  chokidar = require('chokidar');
} catch {
  // chokidar not available
}

export function testCommand(): Command {
  const command = new Command('test')
    .description('Run compliance tests');

  // Quick test command
  command
    .command('quick')
    .description('Quick test execution with defaults')
    .option('-s, --suite <suite>', 'Test suite name', 'default')
    .option('-o, --output <dir>', 'Output directory', './reports')
    .option('-c, --config <file>', 'Runtime config file')
    .action(async (options: any) => {
      await runTests({
        suite: options.suite,
        outputDir: options.output,
        configFile: options.config,
      });
    });

  // Test specific suite
  command
    .command('suite <suite-name>')
    .description('Test a specific suite')
    .option('-o, --output <dir>', 'Output directory', './reports')
    .option('-c, --config <file>', 'Runtime config file')
    .action(async (suiteName: string, options: any) => {
      await runTests({
        suite: suiteName,
        outputDir: options.output,
        configFile: options.config,
      });
    });

  // Test specific application
  command
    .command('app <app-name>')
    .description('Test a specific application')
    .option('-o, --output <dir>', 'Output directory', './reports')
    .option('-c, --config <file>', 'Runtime config file')
    .option('-s, --suite <suite>', 'Test suite name', 'default')
    .action(async (appName: string, options: any) => {
      // Set application name in environment for runtime config
      process.env.APPLICATION_NAME = appName;
      await runTests({
        suite: options.suite,
        outputDir: options.output,
        configFile: options.config,
      });
    });

  // Test with watch mode
  command
    .command('watch')
    .description('Watch mode for continuous testing')
    .option('-s, --suite <suite>', 'Test suite name', 'default')
    .option('-o, --output <dir>', 'Output directory', './reports')
    .option('-c, --config <file>', 'Runtime config file')
    .option('--watch-dirs <dirs>', 'Directories to watch (comma-separated)', 'heimdall-framework/tests,heimdall-framework/policies')
    .action(async (options: any) => {
      if (!chokidar) {
        console.error('Watch mode requires chokidar. Install it with: npm install --save-dev chokidar');
        process.exit(1);
      }

      const watchDirs = options.watchDirs.split(',').map((d: string) => d.trim());
      
      console.log(`\n👀 Watching for changes in: ${watchDirs.join(', ')}`);
      console.log('Press Ctrl+C to stop\n');

      // Run tests immediately
      await runTests({
        suite: options.suite,
        outputDir: options.output,
        configFile: options.config,
      });

      // Watch for changes
      const watcher = chokidar.watch(watchDirs, {
        ignored: /(^|[\/\\])\../, // ignore dotfiles
        persistent: true,
      });

      let debounceTimer: NodeJS.Timeout;
      watcher.on('change', async (filePath) => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(async () => {
          console.log(`\n📝 File changed: ${filePath}`);
          console.log('🔄 Re-running tests...\n');
          await runTests({
            suite: options.suite,
            outputDir: options.output,
            configFile: options.config,
          });
        }, 500);
      });
    });

  // Test with parallel execution
  command
    .command('parallel')
    .description('Parallel test execution')
    .option('-s, --suite <suite>', 'Test suite name', 'default')
    .option('-o, --output <dir>', 'Output directory', './reports')
    .option('-c, --config <file>', 'Runtime config file')
    .option('-j, --jobs <count>', 'Number of parallel jobs', '4')
    .action(async (options: any) => {
      const jobCount = parseInt(options.jobs, 10);
      await runTests({
        suite: options.suite,
        outputDir: options.output,
        configFile: options.config,
        parallel: true,
        jobCount,
      });
    });

  // Test with filter
  command
    .command('filter <pattern>')
    .description('Filter tests by pattern')
    .option('-s, --suite <suite>', 'Test suite name', 'default')
    .option('-o, --output <dir>', 'Output directory', './reports')
    .option('-c, --config <file>', 'Runtime config file')
    .action(async (pattern: string, options: any) => {
      await runTests({
        suite: options.suite,
        outputDir: options.output,
        configFile: options.config,
        filter: pattern,
      });
    });

  // List available suites
  command
    .command('list-suites')
    .description('List available test suites')
    .action(async () => {
      const suites = await listAvailableSuites();
      console.log('\nAvailable test suites:');
      suites.forEach(suite => {
        console.log(`  - ${suite}`);
      });
      console.log('');
    });

  return command;
}

interface TestOptions {
  suite: string;
  outputDir: string;
  configFile?: string;
  parallel?: boolean;
  jobCount?: number;
  filter?: string;
}

async function runTests(options: TestOptions): Promise<void> {
  const { suite, outputDir, configFile, parallel, jobCount, filter } = options;

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

  console.log(`Loading test suite: ${suite}`);
  const testSuite = await loadTestSuite(suite, runtimeConfig);

  // Apply filter if provided
  if (filter) {
    const regex = new RegExp(filter, 'i');
    testSuite.testIds = testSuite.testIds.filter(id => regex.test(id));
    console.log(`Filtered to ${testSuite.testIds.length} tests matching "${filter}"`);
  }

  console.log('Initializing TestOrchestrator...');

  // Load ABAC policies if available
  let abacPolicies = [];
  const abacPolicyPath = process.env.ABAC_POLICIES_PATH || path.join(__dirname, '../../policies/abac-policies.json');
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
  
  // Run tests in parallel if requested
  if (parallel && jobCount && jobCount > 1) {
    console.log(`Running tests in parallel with ${jobCount} workers...`);
    // Note: Parallel execution would need to be implemented in TestOrchestrator
    // For now, we'll just run normally
    console.warn('Parallel execution not yet fully implemented, running sequentially');
  }

  const results = await orchestrator.runTestSuite(testSuite, undefined, runtimeConfig);

  const passed = results.filter(r => r.passed).length;
  const total = results.length;
  console.log(`\nTest Results: ${passed}/${total} passed`);

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
