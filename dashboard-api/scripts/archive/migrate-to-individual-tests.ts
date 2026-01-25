/**
 * Migration Script: Convert Test Suites to Individual Tests
 * 
 * This script converts all existing Test Suites with configuration
 * into individual Test entities and updates suites to reference them.
 * 
 * Run with: npx ts-node dashboard-api/migrate-to-individual-tests.ts
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { Test, AccessControlTest, DataBehaviorTest, DLPTest, TestSuite } from '../core/types';

interface OldTestSuite {
  id: string;
  name: string;
  applicationId?: string;
  application?: string;
  team: string;
  testType: string;
  testTypes?: string[]; // Old format
  userRoles?: string[];
  resources?: any[];
  contexts?: any[];
  // Access control specific
  expectedDecisions?: Record<string, boolean>;
  // Data behavior specific
  testQueries?: any[];
  allowedFields?: Record<string, string[]>;
  requiredFilters?: Record<string, any[]>;
  disallowedJoins?: Record<string, string[]>;
  // DLP specific
  patterns?: any[];
  bulkExportLimits?: {
    csv?: number;
    json?: number;
    excel?: number;
    api?: number;
  };
  // Other type-specific configs...
  [key: string]: any;
}

async function loadJSONFile(filePath: string): Promise<any> {
  try {
    const data = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(data);
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

async function saveJSONFile(filePath: string, data: any): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

async function loadPolicies(): Promise<any[]> {
  const policiesFile = path.join(process.cwd(), 'data', 'policies.json');
  return await loadJSONFile(policiesFile);
}

function generateTestName(suite: OldTestSuite, index: number, testType: string): string {
  const baseName = suite.name.replace(/\s+/g, '-').toLowerCase();
  return `${baseName}-test-${index + 1}`;
}

function createAccessControlTest(
  suite: OldTestSuite,
  role: string,
  resource: any,
  context: any,
  expectedDecision: boolean | undefined,
  policies: any[],
  index: number,
): AccessControlTest {
  // Try to find matching policies (RBAC or ABAC based on suite config)
  const policyIds: string[] = [];
  
  // Simple matching: if suite has ABAC attributes, try to match ABAC policies
  // Otherwise, match RBAC policies
  const isABAC = suite.userRoles?.some(() => true) && resource?.abacAttributes;
  const matchingPolicies = policies.filter(p => {
    if (isABAC) {
      return p.type === 'abac';
    }
    return p.type === 'rbac';
  });
  
  // Use first matching policy, or empty if none
  if (matchingPolicies.length > 0) {
    policyIds.push(matchingPolicies[0].id);
  }

  return {
    id: uuidv4(),
    name: generateTestName(suite, index, 'access-control'),
    description: `Generated from suite ${suite.name}: ${role} accessing ${resource?.type || 'resource'}`,
    testType: 'access-control',
    policyIds,
    role,
    resource,
    context: context || {},
    expectedDecision: expectedDecision ?? true,
    version: 1,
    versionHistory: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function createDataBehaviorTest(
  suite: OldTestSuite,
  query: any,
  index: number,
): DataBehaviorTest {
  return {
    id: uuidv4(),
    name: generateTestName(suite, index, 'data-behavior'),
    description: `Generated from suite ${suite.name}: Query ${query.name || 'unnamed'}`,
    testType: 'data-behavior',
    testQuery: query,
    allowedFields: suite.allowedFields ? Object.values(suite.allowedFields)[0] : undefined,
    requiredFilters: suite.requiredFilters ? Object.values(suite.requiredFilters)[0] : undefined,
    disallowedJoins: suite.disallowedJoins ? Object.values(suite.disallowedJoins)[0] : undefined,
    version: 1,
    versionHistory: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function createDLPTests(suite: OldTestSuite): DLPTest[] {
  const tests: DLPTest[] = [];
  let index = 0;

  // Create pattern tests
  if (suite.patterns && suite.patterns.length > 0) {
    for (const pattern of suite.patterns) {
      tests.push({
        id: uuidv4(),
        name: generateTestName(suite, index++, 'dlp'),
        description: `Generated from suite ${suite.name}: Pattern ${pattern.name || pattern.type}`,
        testType: 'dlp',
        pattern,
        expectedDetection: true,
        version: 1,
        versionHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    }
  }

  // Create bulk export tests
  if (suite.bulkExportLimits) {
    const types: Array<'csv' | 'json' | 'excel' | 'api'> = ['csv', 'json', 'excel', 'api'];
    for (const exportType of types) {
      const limit = suite.bulkExportLimits[exportType];
      if (limit !== undefined) {
        tests.push({
          id: uuidv4(),
          name: generateTestName(suite, index++, 'dlp'),
          description: `Generated from suite ${suite.name}: Bulk export ${exportType} limit`,
          testType: 'dlp',
          bulkExportType: exportType,
          bulkExportLimit: limit,
          testRecordCount: limit + 1, // Test with one over limit
          expectedBlocked: true,
          version: 1,
          versionHistory: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    }
  }

  return tests;
}

async function migrateSuite(
  suite: OldTestSuite,
  policies: any[],
): Promise<{ tests: Test[]; newSuite: TestSuite }> {
  const tests: Test[] = [];
  const testIds: string[] = [];

  switch (suite.testType) {
    case 'access-control':
      if (suite.userRoles && suite.resources && suite.contexts) {
        let index = 0;
        for (const role of suite.userRoles) {
          for (const resource of suite.resources) {
            for (const context of suite.contexts) {
              const expectedDecision = suite.expectedDecisions?.[`${role}-${resource.type}`];
              const test = createAccessControlTest(
                suite,
                role,
                resource,
                context,
                expectedDecision,
                policies,
                index++,
              );
              tests.push(test);
              testIds.push(test.id);
            }
          }
        }
      }
      break;

    case 'data-behavior':
      if (suite.testQueries && suite.testQueries.length > 0) {
        suite.testQueries.forEach((query, index) => {
          const test = createDataBehaviorTest(suite, query, index);
          tests.push(test);
          testIds.push(test.id);
        });
      }
      break;

    case 'dlp':
      const dlpTests = createDLPTests(suite);
      tests.push(...dlpTests);
      testIds.push(...dlpTests.map(t => t.id));
      break;

    default:
      console.warn(`Suite ${suite.id} (${suite.name}) has unsupported test type: ${suite.testType}`);
      // Create a placeholder test to preserve the suite
      const placeholderTest: Test = {
        id: uuidv4(),
        name: `${suite.name}-placeholder`,
        description: `Placeholder test for migrated suite (type: ${suite.testType})`,
        testType: suite.testType as any,
        version: 1,
        versionHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      } as Test;
      tests.push(placeholderTest);
      testIds.push(placeholderTest.id);
  }

  // Create new suite structure
  const newSuite: TestSuite = {
    id: suite.id,
    name: suite.name,
    application: suite.application || suite.applicationId || 'unknown',
    team: suite.team,
    testType: suite.testType as any,
    testIds,
    description: `Migrated from configuration-based suite`,
    enabled: suite.enabled !== undefined ? suite.enabled : true,
    createdAt: suite.createdAt ? new Date(suite.createdAt) : new Date(),
    updatedAt: new Date(),
  };

  return { tests, newSuite };
}

async function main() {
  console.log('Starting migration to individual tests...\n');

  const suitesFile = path.join(process.cwd(), 'data', 'test-suites.json');
  const testsFile = path.join(process.cwd(), 'data', 'tests.json');
  const backupFile = path.join(process.cwd(), 'data', 'test-suites.json.backup');

  try {
    // Load existing data
    console.log('Loading existing test suites...');
    const oldSuites: OldTestSuite[] = await loadJSONFile(suitesFile);
    console.log(`Found ${oldSuites.length} test suites\n`);

    // Load policies
    console.log('Loading policies...');
    const policies = await loadPolicies();
    console.log(`Found ${policies.length} policies\n`);

    // Create backup
    console.log('Creating backup...');
    await saveJSONFile(backupFile, oldSuites);
    console.log(`Backup saved to ${backupFile}\n`);

    // Migrate each suite
    const allTests: Test[] = [];
    const newSuites: TestSuite[] = [];
    const migrationLog: any[] = [];

    for (const suite of oldSuites) {
      console.log(`Migrating suite: ${suite.name} (${suite.testType})...`);
      try {
        const { tests, newSuite } = await migrateSuite(suite, policies);
        allTests.push(...tests);
        newSuites.push(newSuite);
        migrationLog.push({
          suiteId: suite.id,
          suiteName: suite.name,
          testType: suite.testType,
          testsGenerated: tests.length,
          success: true,
        });
        console.log(`  ✓ Generated ${tests.length} tests\n`);
      } catch (error: any) {
        console.error(`  ✗ Error: ${error.message}\n`);
        migrationLog.push({
          suiteId: suite.id,
          suiteName: suite.name,
          testType: suite.testType,
          testsGenerated: 0,
          success: false,
          error: error.message,
        });
      }
    }

    // Save migrated data
    console.log('Saving migrated data...');
    await saveJSONFile(testsFile, allTests);
    await saveJSONFile(suitesFile, newSuites);

    // Save migration log
    const logFile = path.join(process.cwd(), 'data', 'migration-log.json');
    await saveJSONFile(logFile, {
      timestamp: new Date().toISOString(),
      totalSuites: oldSuites.length,
      totalTestsGenerated: allTests.length,
      suites: migrationLog,
    });

    console.log('\n✓ Migration complete!');
    console.log(`  - Generated ${allTests.length} tests`);
    console.log(`  - Updated ${newSuites.length} test suites`);
    console.log(`  - Migration log saved to ${logFile}`);
    console.log(`  - Backup saved to ${backupFile}`);
  } catch (error: any) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch(console.error);
}

export { migrateSuite };

