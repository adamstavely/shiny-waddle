/**
 * Main migration script: Migrate all Platform Baselines to Test Suites
 * 
 * This script:
 * 1. Loads all platform baselines from various sources
 * 2. Converts them to Test Suites with PlatformConfigTest tests
 * 3. Converts Platform Instances to Applications
 * 4. Updates references
 * 5. Saves migrated data
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { migrateBaselinesToTestSuites, PlatformBaseline } from './baseline-to-test-suite.migration';
import { migrateInstancesToApplications, PlatformInstance } from './instance-to-application.migration';
import { TestSuite, PlatformConfigTest } from '../../../heimdall-framework/core/types';
import { Application } from '../applications/entities/application.entity';

interface MigrationResult {
  testSuites: TestSuite[];
  tests: PlatformConfigTest[];
  applications: Application[];
  baselineToTestSuiteMap: Map<string, string>;
  errors: string[];
}

/**
 * Load baselines from all platform-specific files
 */
async function loadAllBaselines(): Promise<PlatformBaseline[]> {
  const baselines: PlatformBaseline[] = [];
  const dataDir = path.join(process.cwd(), 'data');
  
  // Load from platform-specific baseline files
  const baselineFiles = [
    'salesforce-baselines.json',
    'elastic-baselines.json',
    'idp-kubernetes-baselines.json',
    'servicenow-baselines.json',
    'platform-config-baselines.json', // Generic platform config baselines
  ];
  
  for (const file of baselineFiles) {
    const filePath = path.join(dataDir, file);
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      if (content.trim()) {
        const data = JSON.parse(content);
        const fileBaselines = Array.isArray(data) ? data : [data];
        
        // Normalize baseline structure
        for (const baseline of fileBaselines) {
          // Determine platform from filename or baseline data
          let platform = baseline.platform;
          if (!platform) {
            if (file.includes('salesforce')) platform = 'salesforce';
            else if (file.includes('elastic')) platform = 'elastic';
            else if (file.includes('idp') || file.includes('kubernetes')) platform = 'idp-kubernetes';
            else if (file.includes('servicenow')) platform = 'servicenow';
            else platform = 'salesforce'; // Default
          }
          
          baselines.push({
            ...baseline,
            platform: platform as any,
            validationRules: baseline.validationRules || [],
            isActive: baseline.isActive !== false,
            createdAt: baseline.createdAt || new Date().toISOString(),
            updatedAt: baseline.updatedAt || new Date().toISOString(),
          });
        }
      }
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        console.warn(`Error loading ${file}:`, error.message);
      }
      // File doesn't exist, skip
    }
  }
  
  return baselines;
}

/**
 * Load platform instances
 */
async function loadPlatformInstances(): Promise<PlatformInstance[]> {
  const instances: PlatformInstance[] = [];
  const dataDir = path.join(process.cwd(), 'data');
  const filePath = path.join(dataDir, 'platform-instances.json');
  
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    if (content.trim()) {
      const data = JSON.parse(content);
      const fileInstances = Array.isArray(data) ? data : [data];
      instances.push(...fileInstances);
    }
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      console.warn(`Error loading platform instances:`, error.message);
    }
    // File doesn't exist, skip
  }
  
  return instances;
}

/**
 * Save migrated test suites
 */
async function saveTestSuites(testSuites: TestSuite[]): Promise<void> {
  const dataDir = path.join(process.cwd(), 'data');
  const filePath = path.join(dataDir, 'test-suites.json');
  
  // Load existing test suites
  let existing: TestSuite[] = [];
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    if (content.trim()) {
      existing = JSON.parse(content);
    }
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  
  // Merge with migrated suites (avoid duplicates)
  const existingIds = new Set(existing.map(ts => ts.id));
  const newSuites = testSuites.filter(ts => !existingIds.has(ts.id));
  
  await fs.writeFile(
    filePath,
    JSON.stringify([...existing, ...newSuites], null, 2),
    'utf-8'
  );
}

/**
 * Save migrated tests
 */
async function saveTests(tests: PlatformConfigTest[]): Promise<void> {
  const dataDir = path.join(process.cwd(), 'data');
  const filePath = path.join(dataDir, 'tests.json');
  
  // Load existing tests
  let existing: any[] = [];
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    if (content.trim()) {
      existing = JSON.parse(content);
    }
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  
  // Merge with migrated tests (avoid duplicates)
  const existingIds = new Set(existing.map((t: any) => t.id));
  const newTests = tests.filter(t => !existingIds.has(t.id));
  
  await fs.writeFile(
    filePath,
    JSON.stringify([...existing, ...newTests], null, 2),
    'utf-8'
  );
}

/**
 * Save migrated applications
 */
async function saveApplications(applications: Application[]): Promise<void> {
  const dataDir = path.join(process.cwd(), 'data');
  const filePath = path.join(dataDir, 'applications.json');
  
  // Load existing applications
  let existing: Application[] = [];
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    if (content.trim()) {
      existing = JSON.parse(content);
    }
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  
  // Merge with migrated applications (avoid duplicates)
  const existingIds = new Set(existing.map(app => app.id));
  const newApps = applications.filter(app => !existingIds.has(app.id));
  
  await fs.writeFile(
    filePath,
    JSON.stringify([...existing, ...newApps], null, 2),
    'utf-8'
  );
}

/**
 * Main migration function
 */
export async function migrateAllBaselines(): Promise<MigrationResult> {
  const errors: string[] = [];
  const baselineToTestSuiteMap = new Map<string, string>();
  
  try {
    console.log('Loading baselines...');
    const baselines = await loadAllBaselines();
    console.log(`Found ${baselines.length} baselines`);
    
    console.log('Loading platform instances...');
    const instances = await loadPlatformInstances();
    console.log(`Found ${instances.length} platform instances`);
    
    // Create baseline -> instance mapping
    const baselineToInstanceMap = new Map<string, string>();
    for (const instance of instances) {
      if (instance.baselineId) {
        baselineToInstanceMap.set(instance.baselineId, instance.id);
      }
    }
    
    console.log('Migrating baselines to test suites...');
    const { testSuites, tests } = await migrateBaselinesToTestSuites(
      baselines,
      baselineToInstanceMap
    );
    
    // Create baseline -> test suite mapping
    for (const suite of testSuites) {
      // Find the baseline that created this suite (by ID)
      const baseline = baselines.find(b => b.id === suite.id);
      if (baseline) {
        baselineToTestSuiteMap.set(baseline.id, suite.id);
      }
    }
    
    console.log(`Created ${testSuites.length} test suites with ${tests.length} tests`);
    
    console.log('Migrating instances to applications...');
    const applications = await migrateInstancesToApplications(
      instances,
      baselineToTestSuiteMap
    );
    console.log(`Created ${applications.length} applications`);
    
    // Update test suite application references
    for (const suite of testSuites) {
      const instance = instances.find(i => i.baselineId === suite.id);
      if (instance) {
        suite.application = instance.id;
      }
    }
    
    console.log('Saving migrated data...');
    await saveTestSuites(testSuites);
    await saveTests(tests);
    await saveApplications(applications);
    
    console.log('Migration completed successfully!');
    
    return {
      testSuites,
      tests,
      applications,
      baselineToTestSuiteMap,
      errors,
    };
  } catch (error: any) {
    errors.push(error.message);
    console.error('Migration failed:', error);
    throw error;
  }
}

/**
 * Run migration if executed directly
 */
if (require.main === module) {
  migrateAllBaselines()
    .then((result) => {
      console.log('\nMigration Summary:');
      console.log(`- Test Suites: ${result.testSuites.length}`);
      console.log(`- Tests: ${result.tests.length}`);
      console.log(`- Applications: ${result.applications.length}`);
      console.log(`- Errors: ${result.errors.length}`);
      
      if (result.errors.length > 0) {
        console.log('\nErrors:');
        result.errors.forEach(err => console.error(`  - ${err}`));
      }
      
      process.exit(0);
    })
    .catch((error) => {
      console.error('Migration failed:', error);
      process.exit(1);
    });
}
