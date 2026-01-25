/**
 * Validator Registry
 * 
 * Central registry for managing and discovering validators/testers.
 * Enables plugin-style architecture for adding new validators.
 */

import { TestResult, TestSuite } from './types';

/**
 * Base interface that all validators must implement
 */
export interface Validator {
  /**
   * Unique identifier for this validator
   */
  readonly id: string;

  /**
   * Human-readable name
   */
  readonly name: string;

  /**
   * Description of what this validator does
   */
  readonly description: string;

  /**
   * Test type this validator handles (e.g., 'access-control', 'configuration-validation')
   */
  readonly testType: string;

  /**
   * Version of the validator
   */
  readonly version: string;

  /**
   * Metadata about what this validator supports
   */
  readonly metadata?: ValidatorMetadata;

  /**
   * Check if this validator can handle the given test suite
   */
  canHandle(suite: TestSuite): boolean;

  /**
   * Run validation tests
   */
  runTests(suite: TestSuite): Promise<TestResult[]>;

  /**
   * Validate configuration for this validator
   */
  validateConfig?(config: any): { valid: boolean; errors: string[] };
}

/**
 * Metadata about a validator
 */
export interface ValidatorMetadata {
  /**
   * Supported test types (if validator handles multiple)
   */
  supportedTestTypes?: string[];

  /**
   * Required configuration keys
   */
  requiredConfig?: string[];

  /**
   * Optional configuration keys
   */
  optionalConfig?: string[];

  /**
   * Dependencies (other validators or services)
   */
  dependencies?: string[];

  /**
   * Tags for categorization
   */
  tags?: string[];

  /**
   * Example configuration
   */
  exampleConfig?: any;
}

/**
 * Validator Registry
 * 
 * Manages registration and discovery of validators
 */
export class ValidatorRegistry {
  private validators: Map<string, Validator> = new Map();
  private validatorsByType: Map<string, Validator[]> = new Map();

  /**
   * Register a validator
   */
  register(validator: Validator): void {
    if (this.validators.has(validator.id)) {
      throw new Error(`Validator with id "${validator.id}" is already registered`);
    }

    this.validators.set(validator.id, validator);

    // Index by test type
    const testType = validator.testType;
    if (!this.validatorsByType.has(testType)) {
      this.validatorsByType.set(testType, []);
    }
    this.validatorsByType.get(testType)!.push(validator);

    console.log(`Registered validator: ${validator.name} (${validator.id})`);
  }

  /**
   * Unregister a validator
   */
  unregister(validatorId: string): void {
    const validator = this.validators.get(validatorId);
    if (!validator) {
      return;
    }

    this.validators.delete(validatorId);

    const testType = validator.testType;
    const validators = this.validatorsByType.get(testType);
    if (validators) {
      const index = validators.indexOf(validator);
      if (index >= 0) {
        validators.splice(index, 1);
      }
    }
  }

  /**
   * Get a validator by ID
   */
  get(validatorId: string): Validator | undefined {
    return this.validators.get(validatorId);
  }

  /**
   * Get all validators for a test type
   */
  getByType(testType: string): Validator[] {
    return this.validatorsByType.get(testType) || [];
  }

  /**
   * Get all registered validators
   */
  getAll(): Validator[] {
    return Array.from(this.validators.values());
  }

  /**
   * Find validators that can handle a test suite
   */
  findValidatorsForSuite(suite: TestSuite): Validator[] {
    return this.getAll().filter(validator => validator.canHandle(suite));
  }

  /**
   * List all registered validators
   */
  list(): Array<{ id: string; name: string; testType: string; description: string }> {
    return this.getAll().map(v => ({
      id: v.id,
      name: v.name,
      testType: v.testType,
      description: v.description,
    }));
  }
}

/**
 * Global validator registry instance
 */
export const validatorRegistry = new ValidatorRegistry();

