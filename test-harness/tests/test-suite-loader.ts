/**
 * Test Suite Loader
 * 
 * Loads test suite configurations from files or code
 */

import { TestSuite } from '../core/types';
import { exampleTestSuite } from './example-test-suite';
import * as fs from 'fs/promises';
import * as path from 'path';

export async function loadTestSuite(name: string): Promise<TestSuite> {
  // Try to load from file first
  const suitePath = path.join(__dirname, 'suites', `${name}.json`);
  
  try {
    const content = await fs.readFile(suitePath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    // Fall back to example suite or code-defined suites
    if (name === 'default' || name === 'example') {
      return exampleTestSuite;
    }
    
    throw new Error(`Test suite "${name}" not found`);
  }
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

