/**
 * Migration Script: Convert multi-type test suites to type-specific structure
 * 
 * This script migrates existing test suites and harnesses to the new type-based structure:
 * - Splits multi-type suites into separate type-specific suites
 * - Updates harnesses to have testType
 * - Validates batteries have different harness types
 * 
 * Run with: npx ts-node dashboard-api/migrate-test-types.ts
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

const DATA_DIR = path.join(process.cwd(), 'data');

interface OldTestSuite {
  id: string;
  name: string;
  applicationId: string;
  team: string;
  testTypes?: string[];
  [key: string]: any;
}

interface OldTestHarness {
  id: string;
  name: string;
  description: string;
  testSuiteIds: string[];
  [key: string]: any;
}

interface OldTestBattery {
  id: string;
  name: string;
  harnessIds: string[];
  [key: string]: any;
}

const VALID_TEST_TYPES = [
  'access-control',
  'data-behavior',
  'dataset-health',
  'rls-cls',
  'network-policy',
  'dlp',
  'api-gateway',
  'distributed-systems',
  'api-security',
  'data-pipeline',
];

async function migrateTestSuites(): Promise<Map<string, string[]>> {
  const suitesFile = path.join(DATA_DIR, 'test-suites.json');
  const suiteIdMapping = new Map<string, string[]>(); // oldId -> [newIds]

  try {
    const data = await fs.readFile(suitesFile, 'utf-8');
    if (!data || data.trim() === '') {
      console.log('No test suites to migrate');
      return suiteIdMapping;
    }

    const suites: OldTestSuite[] = JSON.parse(data);
    const newSuites: any[] = [];

    for (const suite of suites) {
      // If suite already has testType, keep it as is
      if ((suite as any).testType) {
        newSuites.push({
          ...suite,
          testTypes: (suite as any).testTypes || [(suite as any).testType],
        });
        suiteIdMapping.set(suite.id, [suite.id]);
        continue;
      }

      // Determine test types from testTypes array or infer from suite properties
      let testTypes: string[] = suite.testTypes || [];
      
      if (testTypes.length === 0) {
        // Try to infer from suite properties (backward compatibility)
        if ((suite as any).includeAccessControlTests) testTypes.push('access-control');
        if ((suite as any).includeDataBehaviorTests) testTypes.push('data-behavior');
        // Contract tests deprecated - functionality moved to DLP tests
        if ((suite as any).includeDatasetHealthTests) testTypes.push('dataset-health');
      }

      if (testTypes.length === 0) {
        // Default to access-control if no types found
        console.warn(`Suite "${suite.name}" has no test types, defaulting to access-control`);
        testTypes = ['access-control'];
      }

      // If only one type, update existing suite
      if (testTypes.length === 1) {
        newSuites.push({
          ...suite,
          testType: testTypes[0],
          testTypes: testTypes,
        });
        suiteIdMapping.set(suite.id, [suite.id]);
      } else {
        // Split into multiple suites
        const newIds: string[] = [];
        for (const testType of testTypes) {
          const newId = uuidv4();
          newIds.push(newId);
          newSuites.push({
            ...suite,
            id: newId,
            name: `${suite.name} - ${testType}`,
            testType: testType,
            testTypes: [testType],
          });
        }
        suiteIdMapping.set(suite.id, newIds);
        console.log(`Split suite "${suite.name}" into ${testTypes.length} type-specific suites`);
      }
    }

    await fs.writeFile(suitesFile, JSON.stringify(newSuites, null, 2), 'utf-8');
    console.log(`Migrated ${suites.length} test suites to ${newSuites.length} type-specific suites`);
    return suiteIdMapping;
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log('Test suites file not found, skipping migration');
      return suiteIdMapping;
    }
    throw error;
  }
}

async function migrateTestHarnesses(suiteIdMapping: Map<string, string[]>): Promise<void> {
  const harnessesFile = path.join(DATA_DIR, 'test-harnesses.json');

  try {
    const data = await fs.readFile(harnessesFile, 'utf-8');
    if (!data || data.trim() === '') {
      console.log('No test harnesses to migrate');
      return;
    }

    const harnesses: OldTestHarness[] = JSON.parse(data);
    const newHarnesses: any[] = [];

    for (const harness of harnesses) {
      // If harness already has testType, keep it
      if ((harness as any).testType) {
        newHarnesses.push(harness);
        continue;
      }

      // Determine testType from suites
      const suitesFile = path.join(DATA_DIR, 'test-suites.json');
      const suitesData = await fs.readFile(suitesFile, 'utf-8');
      const allSuites: any[] = JSON.parse(suitesData);

      const harnessTestTypes = new Set<string>();
      const updatedSuiteIds: string[] = [];

      for (const suiteId of harness.testSuiteIds) {
        // Check if suite was split
        const newSuiteIds = suiteIdMapping.get(suiteId);
        if (newSuiteIds) {
          // Use the first split suite (or could use all, but that would create multiple harnesses)
          updatedSuiteIds.push(...newSuiteIds);
          for (const newSuiteId of newSuiteIds) {
            const suite = allSuites.find(s => s.id === newSuiteId);
            if (suite && suite.testType) {
              harnessTestTypes.add(suite.testType);
            }
          }
        } else {
          updatedSuiteIds.push(suiteId);
          const suite = allSuites.find(s => s.id === suiteId);
          if (suite && suite.testType) {
            harnessTestTypes.add(suite.testType);
          }
        }
      }

      if (harnessTestTypes.size === 0) {
        console.warn(`Harness "${harness.name}" has no suites with testType, defaulting to access-control`);
        newHarnesses.push({
          ...harness,
          testType: 'access-control',
        });
      } else if (harnessTestTypes.size === 1) {
        newHarnesses.push({
          ...harness,
          testType: Array.from(harnessTestTypes)[0],
          testSuiteIds: updatedSuiteIds,
        });
      } else {
        // Split harness into multiple harnesses by type
        console.log(`Splitting harness "${harness.name}" into ${harnessTestTypes.size} type-specific harnesses`);
        for (const testType of harnessTestTypes) {
          const typeSuiteIds = updatedSuiteIds.filter(suiteId => {
            const suite = allSuites.find(s => s.id === suiteId);
            return suite && suite.testType === testType;
          });
          
          newHarnesses.push({
            ...harness,
            id: uuidv4(),
            name: `${harness.name} - ${testType}`,
            testType: testType,
            testSuiteIds: typeSuiteIds,
          });
        }
      }
    }

    await fs.writeFile(harnessesFile, JSON.stringify(newHarnesses, null, 2), 'utf-8');
    console.log(`Migrated ${harnesses.length} test harnesses to ${newHarnesses.length} type-specific harnesses`);
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log('Test harnesses file not found, skipping migration');
      return;
    }
    throw error;
  }
}

async function validateBatteries(): Promise<void> {
  const batteriesFile = path.join(DATA_DIR, 'test-batteries.json');
  const harnessesFile = path.join(DATA_DIR, 'test-harnesses.json');

  try {
    const batteriesData = await fs.readFile(batteriesFile, 'utf-8');
    const harnessesData = await fs.readFile(harnessesFile, 'utf-8');
    
    const batteries: OldTestBattery[] = JSON.parse(batteriesData);
    const harnesses: any[] = JSON.parse(harnessesData);
    const harnessMap = new Map(harnesses.map(h => [h.id, h]));

    const issues: string[] = [];

    for (const battery of batteries) {
      const harnessTypes = new Set<string>();
      for (const harnessId of battery.harnessIds) {
        const harness = harnessMap.get(harnessId);
        if (!harness) {
          issues.push(`Battery "${battery.name}" references non-existent harness "${harnessId}"`);
          continue;
        }
        if (!harness.testType) {
          issues.push(`Battery "${battery.name}" contains harness "${harness.name}" without testType`);
          continue;
        }
        if (harnessTypes.has(harness.testType)) {
          issues.push(
            `Battery "${battery.name}" contains multiple harnesses with type "${harness.testType}"`
          );
        }
        harnessTypes.add(harness.testType);
      }
    }

    if (issues.length > 0) {
      console.warn('Battery validation issues found:');
      issues.forEach(issue => console.warn(`  - ${issue}`));
    } else {
      console.log('All batteries validated successfully');
    }
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log('Batteries or harnesses file not found, skipping validation');
      return;
    }
    throw error;
  }
}

async function main() {
  console.log('Starting test type migration...\n');

  try {
    // Ensure data directory exists
    await fs.mkdir(DATA_DIR, { recursive: true });

    // Step 1: Migrate test suites
    console.log('Step 1: Migrating test suites...');
    const suiteIdMapping = await migrateTestSuites();
    console.log('');

    // Step 2: Migrate test harnesses
    console.log('Step 2: Migrating test harnesses...');
    await migrateTestHarnesses(suiteIdMapping);
    console.log('');

    // Step 3: Validate batteries
    console.log('Step 3: Validating batteries...');
    await validateBatteries();
    console.log('');

    console.log('Migration completed successfully!');
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

