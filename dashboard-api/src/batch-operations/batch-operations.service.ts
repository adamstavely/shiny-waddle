import { Injectable, BadRequestException } from '@nestjs/common';
import * as path from 'path';
import * as fs from 'fs/promises';
import { BatchFileDto, BatchOperationDto } from './dto/batch-operation.dto';
import { loadTestSuite } from '../../../heimdall-framework/tests/test-suite-loader';
import { TestOrchestrator } from '../../../heimdall-framework/core/test-harness';
import { ComplianceReporter } from '../../../heimdall-framework/services/compliance-reporter';
import { ABACPolicyLoader } from '../../../heimdall-framework/services/abac-policy-loader';
import { TestConfiguration } from '../../../heimdall-framework/core/types';
import { loadRuntimeConfigFromEnv, loadRuntimeConfigFromFile, validateRuntimeConfig } from '../../../heimdall-framework/core/config-loader';
import { validateBatchFile } from '../../../heimdall-framework/cli/formats/batch-format';

@Injectable()
export class BatchOperationsService {
  async runBatchOperations(batchFile: BatchFileDto, filterType?: 'test' | 'validate' | 'report') {
    const operations = filterType
      ? batchFile.operations.filter(op => op.type === filterType)
      : batchFile.operations;

    if (operations.length === 0) {
      return {
        message: `No ${filterType || 'operations'} found in batch file`,
        results: [],
      };
    }

    const config = batchFile.config || {};
    const outputDir = config.outputDir || './reports';
    const stopOnError = config.stopOnError !== false;

    const results: Array<{ operation: BatchOperationDto; success: boolean; error?: string; data?: any }> = [];

    for (let i = 0; i < operations.length; i++) {
      const operation = operations[i];
      try {
        let data: any;
        switch (operation.type) {
          case 'test':
            data = await this.runBatchTest(operation, outputDir);
            break;
          case 'validate':
            data = await this.runBatchValidate(operation, outputDir);
            break;
          case 'report':
            data = await this.runBatchReport(operation, outputDir);
            break;
          default:
            throw new BadRequestException(`Unknown operation type: ${operation.type}`);
        }
        results.push({ operation, success: true, data });
      } catch (error: any) {
        const errorMsg = error.message || String(error);
        results.push({ operation, success: false, error: errorMsg });

        if (stopOnError) {
          break;
        }
      }
    }

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    return {
      summary: {
        total: operations.length,
        successful,
        failed,
      },
      results,
      outputDir,
    };
  }

  async parseBatchFile(content: string, format: 'json' | 'yaml' = 'json'): Promise<BatchFileDto> {
    let batchFile: BatchFileDto;

    if (format === 'json') {
      try {
        batchFile = JSON.parse(content);
      } catch (error: any) {
        throw new BadRequestException(`Invalid JSON: ${error.message}`);
      }
    } else {
      try {
        let yaml: any;
        try {
          yaml = require('js-yaml');
        } catch {
          yaml = require('yaml');
        }
        batchFile = yaml.load(content);
      } catch (error: any) {
        throw new BadRequestException(`Invalid YAML: ${error.message}`);
      }
    }

    const validation = validateBatchFile(batchFile);
    if (!validation.valid) {
      throw new BadRequestException(`Batch file validation failed: ${validation.errors.join(', ')}`);
    }

    return batchFile;
  }

  private async runBatchTest(operation: BatchOperationDto, outputDir: string): Promise<any> {
    if (!operation.suite) {
      throw new BadRequestException('Test operation requires "suite" field');
    }

    const suiteOutputDir = path.join(outputDir, operation.output || operation.suite);
    await fs.mkdir(suiteOutputDir, { recursive: true });

    let runtimeConfig;
    if (operation.config) {
      runtimeConfig = await loadRuntimeConfigFromFile(operation.config);
    } else {
      runtimeConfig = loadRuntimeConfigFromEnv();
    }

    const validation = validateRuntimeConfig(runtimeConfig);
    if (!validation.valid) {
      throw new BadRequestException(`Runtime config validation failed: ${validation.errors.join(', ')}`);
    }

    const testSuite = await loadTestSuite(operation.suite, runtimeConfig);

    let abacPolicies = [];
    const abacPolicyPath = process.env.ABAC_POLICIES_PATH || path.join(__dirname, '../../../heimdall-framework/policies/abac-policies.json');
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
    const report = await reporter.generateReport(results);

    const isCompliant = orchestrator.isCompliant(results);

    return {
      suite: operation.suite,
      passed: results.filter(r => r.passed).length,
      total: results.length,
      isCompliant,
      reportPath: suiteOutputDir,
    };
  }

  private async runBatchValidate(operation: BatchOperationDto, outputDir: string): Promise<any> {
    if (!operation.policyFile) {
      throw new BadRequestException('Validate operation requires "policyFile" field');
    }

    const policyPath = path.resolve(operation.policyFile);
    const policyLoader = new ABACPolicyLoader();

    try {
      const policies = await policyLoader.loadPoliciesFromFile(policyPath);

      const validationResults = {
        file: policyPath,
        policyCount: policies.length,
        valid: true,
        errors: [] as string[],
        warnings: [] as string[],
      };

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

      const outputFile = path.join(outputDir, `validation-${path.basename(policyPath, path.extname(policyPath))}.json`);
      await fs.mkdir(path.dirname(outputFile), { recursive: true });
      await fs.writeFile(outputFile, JSON.stringify(validationResults, null, 2));

      return validationResults;
    } catch (error: any) {
      throw new BadRequestException(`Failed to validate policies: ${error.message}`);
    }
  }

  private async runBatchReport(operation: BatchOperationDto, outputDir: string): Promise<any> {
    const reportOutput = path.join(outputDir, operation.output || 'report.json');
    await fs.mkdir(path.dirname(reportOutput), { recursive: true });

    const report = {
      generatedAt: new Date().toISOString(),
      operation: operation.type,
      message: 'Report generation completed',
    };

    await fs.writeFile(reportOutput, JSON.stringify(report, null, 2));
    return {
      reportPath: reportOutput,
      generatedAt: report.generatedAt,
    };
  }
}
