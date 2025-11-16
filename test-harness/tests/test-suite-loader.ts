/**
 * Test Suite Loader
 * 
 * Loads test suite configurations from files or code and applies runtime configuration
 */

import { TestSuite } from '../core/types';
import { RuntimeTestConfig } from '../core/runtime-config';
import { mergeRuntimeConfig } from '../core/config-loader';
import { exampleTestSuite } from './example-test-suite';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Load a test suite by name and optionally apply runtime configuration
 * 
 * @param name - Name of the test suite to load
 * @param runtimeConfig - Optional runtime configuration to merge with the suite
 */
export async function loadTestSuite(
  name: string,
  runtimeConfig?: RuntimeTestConfig
): Promise<TestSuite> {
  // Try to load from file first
  const suitePath = path.join(__dirname, 'suites', `${name}.json`);
  
  let suite: TestSuite;
  try {
    const content = await fs.readFile(suitePath, 'utf-8');
    suite = JSON.parse(content);
  } catch (error) {
    // Fall back to example suite or code-defined suites
    if (name === 'default' || name === 'example') {
      suite = exampleTestSuite;
    } else {
      throw new Error(`Test suite "${name}" not found`);
    }
  }

  // Apply runtime configuration if provided
  if (runtimeConfig) {
    suite = mergeRuntimeConfig(suite, runtimeConfig);
  }

  return suite;
}

export async function listAvailableSuites(): Promise<string[]> {
  const suitesDir = path.join(__dirname, 'suites');
  
  try {
    const files = await fs.readdir(suitesDir);
    return files
      .filter(f => f.endsWith('.json'))
      .map(f => f.replace('.json', ''));
  } catch (error) {
    return ['default'];
  }
}

