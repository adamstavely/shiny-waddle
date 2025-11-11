/**
 * Base Validator
 * 
 * Abstract base class that provides common functionality for validators.
 * Makes it easier to create new validators by providing a standard structure.
 */

import { Validator, ValidatorMetadata } from './validator-registry';
import { TestResult, TestSuite } from './types';

/**
 * Abstract base class for validators
 * 
 * Provides common functionality and enforces the Validator interface
 */
export abstract class BaseValidator implements Validator {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly testType: string;
  abstract readonly version: string;
  abstract readonly metadata?: ValidatorMetadata;

  /**
   * Configuration for this validator
   */
  protected config: any;

  constructor(config?: any) {
    this.config = config || {};
    this.validateConfiguration();
  }

  /**
   * Check if this validator can handle the given test suite
   * 
   * Override this method to provide custom logic
   */
  canHandle(suite: TestSuite): boolean {
    // Default implementation: check if suite includes this test type
    return this.shouldRun(suite);
  }

  /**
   * Run validation tests
   * 
   * This is the main entry point. Override runTestsInternal() for implementation.
   */
  async runTests(suite: TestSuite): Promise<TestResult[]> {
    if (!this.canHandle(suite)) {
      return [];
    }

    try {
      return await this.runTestsInternal(suite);
    } catch (error: any) {
      // Return error result instead of throwing
      return [{
        testType: this.testType,
        testName: `${this.name} - Error`,
        passed: false,
        details: {
          error: error.message,
          stack: error.stack,
        },
        timestamp: new Date(),
        error: error.message,
      }];
    }
  }

  /**
   * Internal method to run tests - override this in subclasses
   */
  protected abstract runTestsInternal(suite: TestSuite): Promise<TestResult[]>;

  /**
   * Check if this validator should run for the given suite
   * 
   * Override this to provide custom logic
   */
  protected shouldRun(suite: TestSuite): boolean {
    // Default: check suite flags
    switch (this.testType) {
      case 'access-control':
        return suite.includeAccessControlTests === true;
      case 'data-behavior':
        return suite.includeDataBehaviorTests === true;
      case 'contract':
        return suite.includeContractTests === true;
      case 'dataset-health':
        return suite.includeDatasetHealthTests === true;
      default:
        // For custom test types, check if suite has corresponding flag
        return (suite as any)[`include${this.capitalize(this.testType)}Tests`] === true;
    }
  }

  /**
   * Validate configuration
   * 
   * Override this to validate validator-specific configuration
   */
  validateConfig?(config: any): { valid: boolean; errors: string[] };

  /**
   * Validate configuration on construction
   */
  private validateConfiguration(): void {
    if (this.validateConfig) {
      const result = this.validateConfig(this.config);
      if (!result.valid) {
        throw new Error(
          `Invalid configuration for validator ${this.id}: ${result.errors.join(', ')}`
        );
      }
    }
  }

  /**
   * Helper to create a test result
   */
  protected createTestResult(
    testName: string,
    passed: boolean,
    details: any,
    error?: string
  ): TestResult {
    return {
      testType: this.testType,
      testName,
      passed,
      details,
      timestamp: new Date(),
      error,
    };
  }

  /**
   * Helper to create a passed test result
   */
  protected createPassedResult(testName: string, details?: any): TestResult {
    return this.createTestResult(testName, true, details || {});
  }

  /**
   * Helper to create a failed test result
   */
  protected createFailedResult(testName: string, reason: string, details?: any): TestResult {
    return this.createTestResult(testName, false, { reason, ...details }, reason);
  }

  /**
   * Capitalize first letter
   */
  private capitalize(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
}

