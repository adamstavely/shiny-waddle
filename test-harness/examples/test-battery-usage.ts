/**
 * Test Battery Usage Example
 * 
 * This example demonstrates how to:
 * 1. Create a test battery
 * 2. Add harnesses to a battery
 * 3. Run a test battery
 * 4. Manage harnesses in a battery
 */

import { TestBatteryRunner } from '../core/test-battery';
import { TestOrchestrator } from '../core/test-harness';
import { TestBattery, TestHarness, TestSuite, TestConfiguration } from '../core/types';
import { loadTestSuite } from '../tests/test-suite-loader';

/**
 * Example: Creating a Test Battery
 */
async function createTestBattery() {
  // Define test harnesses
  const securityHarness: TestHarness = {
    id: 'harness-security-001',
    name: 'Security Test Harness',
    description: 'Comprehensive security tests for production applications',
    testSuiteIds: ['suite-access-control', 'suite-api-security'],
    applicationIds: ['app-production'],
    team: 'Security Team',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const dataHarness: TestHarness = {
    id: 'harness-data-001',
    name: 'Data Protection Harness',
    description: 'Data loss prevention and privacy tests',
    testSuiteIds: ['suite-dlp', 'suite-rls-cls'],
    applicationIds: ['app-production'],
    team: 'Data Team',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Create a test battery with execution configuration
  const battery: TestBattery = {
    id: 'battery-full-security-001',
    name: 'Full Security Battery',
    description: 'Complete security test battery for production applications',
    harnessIds: [securityHarness.id, dataHarness.id],
    executionConfig: {
      executionMode: 'parallel', // Run harnesses in parallel
      timeout: 3600000, // 1 hour timeout
      stopOnFailure: false, // Continue even if one harness fails
    },
    team: 'Security Team',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  console.log('Created Test Battery:', battery);
  return { battery, harnesses: [securityHarness, dataHarness] };
}

/**
 * Example: Running a Test Battery
 */
async function runTestBattery() {
  // Create battery and harnesses
  const { battery, harnesses } = await createTestBattery();

  // Load test suites for each harness
  const suiteMap = new Map<string, TestSuite>();
  
  for (const harness of harnesses) {
    for (const suiteId of harness.testSuiteIds) {
      try {
        const suite = await loadTestSuite(suiteId);
        suiteMap.set(suiteId, suite);
      } catch (error) {
        console.warn(`Failed to load suite ${suiteId}:`, error);
      }
    }
  }

  // Create test configuration
  const config: TestConfiguration = {
    userSimulationConfig: {
      roles: ['admin', 'viewer', 'editor'],
      attributes: {},
    },
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
    },
    dataBehaviorConfig: {
      enableQueryLogging: true,
    },
    datasetHealthConfig: {
      privacyMetrics: [
        { name: 'k-anonymity', type: 'k-anonymity', threshold: 10 },
      ],
    },
    reportingConfig: {
      outputFormat: 'json',
      outputPath: './reports',
      includeDetails: true,
    },
  };

  // Initialize TestBatteryRunner
  const batteryRunner = new TestBatteryRunner(config);

  // Run the battery
  console.log(`Running battery: ${battery.name}`);
  const batteryResult = await batteryRunner.runBattery(
    battery,
    harnesses,
    suiteMap,
  );

  // Check results
  console.log('Battery Result:', {
    batteryId: batteryResult.batteryId,
    overallPassed: batteryResult.overallPassed,
    harnessResults: batteryResult.harnessResults.map(hr => ({
      harnessId: hr.harnessId,
      resultCount: hr.results.length,
      passed: hr.results.every(r => r.passed),
    })),
    timestamp: batteryResult.timestamp,
  });

  return batteryResult;
}

/**
 * Example: Managing Harnesses in a Battery
 */
async function manageBatteryHarnesses() {
  // Create initial battery
  const { battery, harnesses } = await createTestBattery();

  console.log('Initial battery harnesses:', battery.harnessIds);

  // Add a new harness to the battery
  const newHarness: TestHarness = {
    id: 'harness-network-001',
    name: 'Network Policy Harness',
    description: 'Network security and segmentation tests',
    testSuiteIds: ['suite-network-policy'],
    applicationIds: ['app-production'],
    team: 'Network Team',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Add harness to battery
  battery.harnessIds.push(newHarness.id);
  battery.updatedAt = new Date();

  console.log('After adding harness:', battery.harnessIds);

  // Remove a harness from battery
  const harnessToRemove = 'harness-data-001';
  battery.harnessIds = battery.harnessIds.filter(id => id !== harnessToRemove);
  battery.updatedAt = new Date();

  console.log('After removing harness:', battery.harnessIds);

  // Update execution configuration
  battery.executionConfig = {
    executionMode: 'sequential', // Changed to sequential
    timeout: 7200000, // 2 hours
    stopOnFailure: true, // Stop on failure for critical tests
  };

  console.log('Updated execution config:', battery.executionConfig);

  return battery;
}

/**
 * Example: Sequential Execution with Stop on Failure
 */
async function runSequentialBattery() {
  const { battery, harnesses } = await createTestBattery();

  // Configure for sequential execution with stop on failure
  battery.executionConfig = {
    executionMode: 'sequential',
    timeout: 3600000,
    stopOnFailure: true, // Stop if any harness fails
  };

  const config: TestConfiguration = {
    userSimulationConfig: {
      roles: ['admin'],
      attributes: {},
    },
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
    },
    reportingConfig: {
      outputFormat: 'json',
      outputPath: './reports',
      includeDetails: true,
    },
  };

  const batteryRunner = new TestBatteryRunner(config);

  // Load suites
  const suiteMap = new Map<string, TestSuite>();
  for (const harness of harnesses) {
    for (const suiteId of harness.testSuiteIds) {
      try {
        const suite = await loadTestSuite(suiteId);
        suiteMap.set(suiteId, suite);
      } catch (error) {
        console.warn(`Failed to load suite ${suiteId}:`, error);
      }
    }
  }

  console.log('Running battery sequentially with stop on failure...');
  const result = await batteryRunner.runBattery(battery, harnesses, suiteMap);

  // With stopOnFailure: true, if the first harness fails, subsequent harnesses won't run
  console.log('Execution stopped early:', result.harnessResults.length < battery.harnessIds.length);

  return result;
}

/**
 * Example: Parallel Execution for Faster Results
 */
async function runParallelBattery() {
  const { battery, harnesses } = await createTestBattery();

  // Configure for parallel execution
  battery.executionConfig = {
    executionMode: 'parallel', // All harnesses run simultaneously
    timeout: 3600000,
    stopOnFailure: false, // Continue even if one fails
  };

  const config: TestConfiguration = {
    userSimulationConfig: {
      roles: ['admin', 'viewer'],
      attributes: {},
    },
    accessControlConfig: {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
    },
    reportingConfig: {
      outputFormat: 'json',
      outputPath: './reports',
      includeDetails: true,
    },
  };

  const batteryRunner = new TestBatteryRunner(config);

  // Load suites
  const suiteMap = new Map<string, TestSuite>();
  for (const harness of harnesses) {
    for (const suiteId of harness.testSuiteIds) {
      try {
        const suite = await loadTestSuite(suiteId);
        suiteMap.set(suiteId, suite);
      } catch (error) {
        console.warn(`Failed to load suite ${suiteId}:`, error);
      }
    }
  }

  console.log('Running battery in parallel mode...');
  const startTime = Date.now();
  const result = await batteryRunner.runBattery(battery, harnesses, suiteMap);
  const duration = Date.now() - startTime;

  console.log(`Battery completed in ${duration}ms`);
  console.log('All harnesses executed:', result.harnessResults.length === battery.harnessIds.length);

  return result;
}

// Main execution
async function main() {
  try {
    console.log('=== Test Battery Usage Examples ===\n');

    console.log('1. Creating a Test Battery');
    await createTestBattery();
    console.log('\n');

    console.log('2. Managing Harnesses in a Battery');
    await manageBatteryHarnesses();
    console.log('\n');

    // Note: Running batteries requires actual test suites to be available
    // Uncomment these when you have test suites configured:
    
    // console.log('3. Running a Test Battery');
    // await runTestBattery();
    // console.log('\n');

    // console.log('4. Sequential Execution with Stop on Failure');
    // await runSequentialBattery();
    // console.log('\n');

    // console.log('5. Parallel Execution for Faster Results');
    // await runParallelBattery();
    // console.log('\n');

    console.log('Examples completed!');
  } catch (error) {
    console.error('Error running examples:', error);
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  main();
}

export {
  createTestBattery,
  runTestBattery,
  manageBatteryHarnesses,
  runSequentialBattery,
  runParallelBattery,
};

