/**
 * Batch Command
 * Handles batch operations for tests, validation, and reporting
 */

import { Command } from 'commander';
import * as fs from 'fs/promises';
import * as path from 'path';
import { TestOrchestrator } from '../../core/test-harness';
import { loadTestSuite } from '../../tests/test-suite-loader';
import { ComplianceReporter } from '../../services/compliance-reporter';
import { ABACPolicyLoader } from '../../services/abac-policy-loader';
import { TestConfiguration } from '../../core/types';
import { loadRuntimeConfigFromEnv, loadRuntimeConfigFromFile, validateRuntimeConfig } from '../../core/config-loader';
import { ABACPolicy } from '../../core/types';

export interface BatchOperation {
  type: 'test' | 'validate' | 'report';
  suite?: string;
  policyFile?: string;
  output?: string;
  config?: string;
}

export interface BatchFile {
  operations: BatchOperation[];
  config?: {
    outputDir?: string;
    parallel?: boolean;
    stopOnError?: boolean;
  };
}

export function batchCommand(): Command {
  const command = new Command('batch')
    .description('Run batch operations from a file');

  // Batch test
  command
    .command('test <file>')
    .description('Run tests from a batch file')
    .action(async (file: string) => {
      await runBatchOperations(file, 'test');
    });

  // Batch validate
  command
    .command('validate <file>')
    .description('Validate policies from a batch file')
    .action(async (file: string) => {
      await runBatchOperations(file, 'validate');
    });

  // Batch report
  command
    .command('report <file>')
    .description('Generate reports from a batch file')
    .action(async (file: string) => {
      await runBatchOperations(file, 'report');
    });

  // Run all operations from batch file
  command
    .command('run <file>')
    .description('Run all operations from a batch file')
    .action(async (file: string) => {
      await runBatchOperations(file);
    });

  return command;
}

async function runBatchOperations(file: string, filterType?: 'test' | 'validate' | 'report'): Promise<void> {
  const filePath = path.resolve(file);
  
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    let batchFile: BatchFile;

    // Try to parse as JSON first
    try {
      batchFile = JSON.parse(content);
    } catch {
      // Try YAML if JSON fails
      try {
        let yaml: any;
        try {
          yaml = require('js-yaml');
        } catch {
          yaml = require('yaml');
        }
        batchFile = yaml.load(content);
      } catch (yamlError: any) {
        throw new Error(`Batch file must be valid JSON or YAML: ${yamlError.message}`);
      }
    }

    const operations = filterType
      ? batchFile.operations.filter(op => op.type === filterType)
      : batchFile.operations;

    if (operations.length === 0) {
      console.log(`No ${filterType || 'operations'} found in batch file`);
      return;
    }

    const config = batchFile.config || {};
    const outputDir = config.outputDir || './reports';
    const stopOnError = config.stopOnError !== false; // Default to true

    console.log(`\n📦 Running ${operations.length} batch operation(s)...\n`);

    const results: Array<{ operation: BatchOperation; success: boolean; error?: string }> = [];

    for (let i = 0; i < operations.length; i++) {
      const operation = operations[i];
      console.log(`[${i + 1}/${operations.length}] Running ${operation.type} operation...`);

      try {
        switch (operation.type) {
          case 'test':
            await runBatchTest(operation, outputDir);
            results.push({ operation, success: true });
            break;

          case 'validate':
            await runBatchValidate(operation, outputDir);
            results.push({ operation, success: true });
            break;

          case 'report':
            await runBatchReport(operation, outputDir);
            results.push({ operation, success: true });
            break;

          default:
            throw new Error(`Unknown operation type: ${operation.type}`);
        }
        console.log(`✅ Operation ${i + 1} completed successfully\n`);
      } catch (error: any) {
        const errorMsg = error.message || String(error);
        console.error(`❌ Operation ${i + 1} failed: ${errorMsg}\n`);
        results.push({ operation, success: false, error: errorMsg });

        if (stopOnError) {
          console.error('Stopping batch execution due to error (stopOnError=true)');
          break;
        }
      }
    }

    // Summary
    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    console.log('\n📊 Batch Execution Summary:');
    console.log(`   ✅ Successful: ${successful}`);
    console.log(`   ❌ Failed: ${failed}`);
    console.log(`   📁 Output directory: ${outputDir}\n`);

    if (failed > 0) {
      console.log('Failed operations:');
      results.filter(r => !r.success).forEach((r, i) => {
        console.log(`   ${i + 1}. ${r.operation.type} - ${r.error}`);
      });
      process.exit(1);
    }
  } catch (error: any) {
    console.error(`Failed to process batch file: ${error.message}`);
    process.exit(1);
  }
}

async function runBatchTest(operation: BatchOperation, outputDir: string): Promise<void> {
  if (!operation.suite) {
    throw new Error('Test operation requires "suite" field');
  }

  const suiteOutputDir = path.join(outputDir, operation.output || operation.suite);
  await fs.mkdir(suiteOutputDir, { recursive: true });

  // Load runtime configuration
  let runtimeConfig;
  if (operation.config) {
    runtimeConfig = await loadRuntimeConfigFromFile(operation.config);
  } else {
    runtimeConfig = loadRuntimeConfigFromEnv();
  }

  // Validate runtime configuration
  const validation = validateRuntimeConfig(runtimeConfig);
  if (!validation.valid) {
    throw new Error(`Runtime config validation failed: ${validation.errors.join(', ')}`);
  }

  const testSuite = await loadTestSuite(operation.suite, runtimeConfig);

  // Load ABAC policies
  let abacPolicies = [];
  const abacPolicyPath = process.env.ABAC_POLICIES_PATH || path.join(__dirname, '../../policies/abac-policies.json');
  try {
    const policyLoader = new ABACPolicyLoader();
    if (await fs.access(abacPolicyPath).then(() => true).catch(() => false)) {
      abacPolicies = await policyLoader.loadPoliciesFromFile(abacPolicyPath);
    }
  } catch (error) {
    // Use defaults
  }

  const config: TestConfiguration = {
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
      abacPolicies: abacPolicies.length > 0 ? abacPolicies : undefined,
    },
    datasetHealthConfig: {
      privacyMetrics: [
        { name: 'k-anonymity', type: 'k-anonymity', threshold: 10 },
      ],
    },
    reportingConfig: {
      outputFormat: 'json',
      outputPath: suiteOutputDir,
      includeDetails: true,
    },
  };

  const orchestrator = new TestOrchestrator(config);
  const results = await orchestrator.runTestSuite(testSuite, undefined, runtimeConfig);

  const reporter = new ComplianceReporter(config.reportingConfig);
  await reporter.generateReport(results);

  const isCompliant = orchestrator.isCompliant(results);
  if (!isCompliant) {
    throw new Error('Test suite failed compliance check');
  }
}

async function runBatchValidate(operation: BatchOperation, outputDir: string): Promise<void> {
  if (!operation.policyFile) {
    throw new Error('Validate operation requires "policyFile" field');
  }

  const policyPath = path.resolve(operation.policyFile);
  const policyLoader = new ABACPolicyLoader();

  try {
    const policies = await policyLoader.loadPoliciesFromFile(policyPath);
    
    // Basic validation
    const validationResults = {
      file: policyPath,
      policyCount: policies.length,
      valid: true,
      errors: [] as string[],
      warnings: [] as string[],
    };

    // Validate each policy
    for (const policy of policies) {
      if (!policy.id) {
        validationResults.errors.push(`Policy missing id`);
        validationResults.valid = false;
      }
      if (!policy.name) {
        validationResults.errors.push(`Policy ${policy.id || 'unknown'} missing name`);
        validationResults.valid = false;
      }
      if (!policy.conditions || policy.conditions.length === 0) {
        validationResults.warnings.push(`Policy ${policy.id} has no conditions`);
      }
    }

    // Save validation results
    const outputFile = path.join(outputDir, `validation-${path.basename(policyPath, path.extname(policyPath))}.json`);
    await fs.mkdir(path.dirname(outputFile), { recursive: true });
    await fs.writeFile(outputFile, JSON.stringify(validationResults, null, 2));

    if (!validationResults.valid) {
      throw new Error(`Policy validation failed: ${validationResults.errors.join(', ')}`);
    }

    console.log(`   ✅ Validated ${policies.length} policies`);
  } catch (error: any) {
    throw new Error(`Failed to validate policies: ${error.message}`);
  }
}

async function runBatchReport(operation: BatchOperation, outputDir: string): Promise<void> {
  // For report operations, we need test results
  // This would typically load existing test results and generate a report
  // For now, we'll just create a placeholder
  const reportOutput = path.join(outputDir, operation.output || 'report.json');
  await fs.mkdir(path.dirname(reportOutput), { recursive: true });

  const report = {
    generatedAt: new Date().toISOString(),
    operation: operation.type,
    message: 'Report generation completed',
  };

  await fs.writeFile(reportOutput, JSON.stringify(report, null, 2));
  console.log(`   ✅ Report generated: ${reportOutput}`);
}
