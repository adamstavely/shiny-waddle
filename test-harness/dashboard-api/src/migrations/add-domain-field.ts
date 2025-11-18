/**
 * Migration script to add domain field to existing tests, test suites, and test harnesses
 * 
 * This script:
 * 1. Reads all existing tests from data/tests.json
 * 2. Backfills domain field on all tests using getDomainFromTestType() mapping
 * 3. Reads all existing test suites and backfills domain field
 * 4. Reads all existing test harnesses and backfills domain field from testType or derives from suites
 * 5. Saves updated data back to files
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { getDomainFromTestType } from '../../../core/domain-mapping';
import { TestType } from '../../../core/types';

interface MigrationResult {
  testsUpdated: number;
  suitesUpdated: number;
  harnessesUpdated: number;
  errors: string[];
}

export async function migrateDomainField(): Promise<MigrationResult> {
  const result: MigrationResult = {
    testsUpdated: 0,
    suitesUpdated: 0,
    harnessesUpdated: 0,
    errors: [],
  };

  const dataDir = path.join(process.cwd(), 'data');
  const testsFile = path.join(dataDir, 'tests.json');
  const suitesFile = path.join(dataDir, 'test-suites.json');
  const harnessesFile = path.join(dataDir, 'test-harnesses.json');

  try {
    // Migrate tests
    try {
      const testsData = await fs.readFile(testsFile, 'utf-8');
      const tests = JSON.parse(testsData);
      
      if (Array.isArray(tests)) {
        for (const test of tests) {
          if (!test.domain && test.testType) {
            try {
              test.domain = getDomainFromTestType(test.testType as TestType);
              result.testsUpdated++;
            } catch (error: any) {
              result.errors.push(`Failed to map domain for test ${test.id}: ${error.message}`);
            }
          }
        }
        
        await fs.writeFile(testsFile, JSON.stringify(tests, null, 2), 'utf-8');
        console.log(`✓ Migrated ${result.testsUpdated} tests`);
      }
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        result.errors.push(`Error migrating tests: ${error.message}`);
      }
    }

    // Migrate test suites
    try {
      const suitesData = await fs.readFile(suitesFile, 'utf-8');
      const suites = JSON.parse(suitesData);
      
      if (Array.isArray(suites)) {
        for (const suite of suites) {
          if (!suite.domain && suite.testType) {
            try {
              suite.domain = getDomainFromTestType(suite.testType as TestType);
              result.suitesUpdated++;
            } catch (error: any) {
              result.errors.push(`Failed to map domain for suite ${suite.id}: ${error.message}`);
            }
          }
        }
        
        await fs.writeFile(suitesFile, JSON.stringify(suites, null, 2), 'utf-8');
        console.log(`✓ Migrated ${result.suitesUpdated} test suites`);
      }
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        result.errors.push(`Error migrating test suites: ${error.message}`);
      }
    }

    // Migrate test harnesses
    try {
      const harnessesData = await fs.readFile(harnessesFile, 'utf-8');
      const harnesses = JSON.parse(harnessesData);
      
      if (Array.isArray(harnesses)) {
        // First, try to get domain from testType if available
        for (const harness of harnesses) {
          if (!harness.domain) {
            if (harness.testType) {
              try {
                harness.domain = getDomainFromTestType(harness.testType as TestType);
                result.harnessesUpdated++;
              } catch (error: any) {
                result.errors.push(`Failed to map domain for harness ${harness.id}: ${error.message}`);
              }
            } else {
              // If no testType, we can't determine domain - log warning
              result.errors.push(`Harness ${harness.id} has no testType or domain - cannot migrate`);
            }
          }
        }
        
        await fs.writeFile(harnessesFile, JSON.stringify(harnesses, null, 2), 'utf-8');
        console.log(`✓ Migrated ${result.harnessesUpdated} test harnesses`);
      }
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        result.errors.push(`Error migrating test harnesses: ${error.message}`);
      }
    }

    console.log('\nMigration completed!');
    console.log(`- Tests updated: ${result.testsUpdated}`);
    console.log(`- Test suites updated: ${result.suitesUpdated}`);
    console.log(`- Test harnesses updated: ${result.harnessesUpdated}`);
    
    if (result.errors.length > 0) {
      console.log('\nErrors encountered:');
      result.errors.forEach(error => console.log(`  - ${error}`));
    }

  } catch (error: any) {
    result.errors.push(`Fatal error: ${error.message}`);
    throw error;
  }

  return result;
}

// Run migration if executed directly
if (require.main === module) {
  migrateDomainField()
    .then(result => {
      process.exit(result.errors.length > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('Migration failed:', error);
      process.exit(1);
    });
}

