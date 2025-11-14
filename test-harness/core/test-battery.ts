/**
 * Test Battery Runner
 * 
 * Orchestrates execution of test batteries (collections of test harnesses)
 */

import { TestBattery, TestBatteryResult, TestHarness, TestResult, TestSuite } from './types';
import { TestOrchestrator } from './test-harness';
import { TestConfiguration } from './types';

export class TestBatteryRunner {
  private orchestrator: TestOrchestrator;

  constructor(config: TestConfiguration) {
    this.orchestrator = new TestOrchestrator(config);
  }

  /**
   * Run a complete test battery
   * Executes all harnesses in the battery according to execution config
   */
  async runBattery(
    battery: TestBattery,
    harnesses: TestHarness[],
    testSuites: Map<string, TestSuite>
  ): Promise<TestBatteryResult> {
    const harnessResults: Array<{ harnessId: string; results: TestResult[] }> = [];
    const config = battery.executionConfig || { executionMode: 'sequential' };

    if (config.executionMode === 'parallel') {
      // Run all harnesses in parallel
      const promises = battery.harnessIds.map(async (harnessId) => {
        const harness = harnesses.find(h => h.id === harnessId);
        if (!harness) {
          throw new Error(`Test harness ${harnessId} not found`);
        }
        const results = await this.runHarness(harness, testSuites);
        return { harnessId, results };
      });

      const results = await Promise.all(promises);
      harnessResults.push(...results);
    } else {
      // Run harnesses sequentially
      for (const harnessId of battery.harnessIds) {
        const harness = harnesses.find(h => h.id === harnessId);
        if (!harness) {
          throw new Error(`Test harness ${harnessId} not found`);
        }

        const results = await this.runHarness(harness, testSuites);
        harnessResults.push({ harnessId, results });

        // Stop on failure if configured
        if (config.stopOnFailure && !this.allPassed(results)) {
          break;
        }

        // Check timeout if configured
        if (config.timeout) {
          // Timeout checking would be implemented here
          // For now, we'll rely on the underlying test execution timeout
        }
      }
    }

    const overallPassed = harnessResults.every(hr => this.allPassed(hr.results));

    return {
      batteryId: battery.id,
      harnessResults,
      overallPassed,
      timestamp: new Date(),
    };
  }

  /**
   * Run a single test harness
   * Executes all test suites in the harness
   */
  async runHarness(
    harness: TestHarness,
    testSuites: Map<string, TestSuite>
  ): Promise<TestResult[]> {
    const allResults: TestResult[] = [];

    for (const suiteId of harness.testSuiteIds) {
      const suite = testSuites.get(suiteId);
      if (!suite) {
        console.warn(`Test suite ${suiteId} not found, skipping`);
        continue;
      }

      const results = await this.orchestrator.runTestSuite(suite);
      allResults.push(...results);
    }

    return allResults;
  }

  /**
   * Check if all test results passed
   */
  private allPassed(results: TestResult[]): boolean {
    return results.every(result => result.passed);
  }
}

