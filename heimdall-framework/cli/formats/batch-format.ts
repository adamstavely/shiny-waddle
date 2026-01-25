/**
 * Batch File Format
 * Defines the structure and validation for batch operation files
 */

import { BatchFile, BatchOperation } from '../commands/batch';

/**
 * Validate a batch file structure
 */
export function validateBatchFile(batchFile: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!batchFile || typeof batchFile !== 'object') {
    errors.push('Batch file must be an object');
    return { valid: false, errors };
  }

  if (!Array.isArray(batchFile.operations)) {
    errors.push('Batch file must have an "operations" array');
    return { valid: false, errors };
  }

  if (batchFile.operations.length === 0) {
    errors.push('Batch file must have at least one operation');
    return { valid: false, errors };
  }

  batchFile.operations.forEach((op: any, index: number) => {
    if (!op.type) {
      errors.push(`Operation ${index + 1} missing "type" field`);
    } else if (!['test', 'validate', 'report'].includes(op.type)) {
      errors.push(`Operation ${index + 1} has invalid type: ${op.type}`);
    }

    if (op.type === 'test' && !op.suite) {
      errors.push(`Operation ${index + 1} (test) missing required "suite" field`);
    }

    if (op.type === 'validate' && !op.policyFile) {
      errors.push(`Operation ${index + 1} (validate) missing required "policyFile" field`);
    }
  });

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Create an example batch file
 */
export function createExampleBatchFile(): BatchFile {
  return {
    operations: [
      {
        type: 'test',
        suite: 'default',
        output: 'test-results-default',
      },
      {
        type: 'validate',
        policyFile: './policies/abac-policies.json',
        output: 'validation-results',
      },
      {
        type: 'report',
        output: 'final-report',
      },
    ],
    config: {
      outputDir: './reports',
      parallel: false,
      stopOnError: true,
    },
  };
}

/**
 * Load and validate a batch file
 */
export async function loadBatchFile(filePath: string): Promise<BatchFile> {
  const fs = require('fs/promises');
  const path = require('path');
  
  let yaml: any;
  try {
    yaml = require('js-yaml');
  } catch {
    try {
      yaml = require('yaml');
    } catch {
      throw new Error('YAML support not available. Install js-yaml or yaml package.');
    }
  }

  const content = await fs.readFile(filePath, 'utf-8');
  let batchFile: BatchFile;

  // Try JSON first
  try {
    batchFile = JSON.parse(content);
  } catch {
    // Try YAML
    try {
      batchFile = yaml.load(content);
    } catch (error: any) {
      throw new Error(`Failed to parse batch file: ${error.message}`);
    }
  }

  const validation = validateBatchFile(batchFile);
  if (!validation.valid) {
    throw new Error(`Batch file validation failed:\n${validation.errors.map(e => `  - ${e}`).join('\n')}`);
  }

  return batchFile;
}
