/**
 * Access Control Validator Adapter
 * 
 * Example adapter that wraps the existing AccessControlTester
 * to demonstrate how to use the validator registry system.
 */

import { BaseValidator } from '../core/base-validator';
import { ValidatorMetadata } from '../core/validator-registry';
import { AccessControlTester } from '../services/access-control-tester';
import { UserSimulator } from '../services/user-simulator';
import { TestResult, TestSuite, AccessControlConfig, UserSimulationConfig } from '../core/types';

export class AccessControlValidatorAdapter extends BaseValidator {
  readonly id = 'access-control';
  readonly name = 'Access Control Validator';
  readonly description = 'Validates RBAC/ABAC access control policies';
  readonly testType = 'access-control';
  readonly version = '1.0.0';

  readonly metadata: ValidatorMetadata = {
    supportedTestTypes: ['access-control'],
    requiredConfig: ['accessControlConfig'],
    optionalConfig: ['userSimulationConfig'],
    tags: ['rbac', 'abac', 'policies', 'access-control'],
  };

  private accessControlTester: AccessControlTester;
  private userSimulator: UserSimulator;

  constructor(config: { accessControlConfig: AccessControlConfig; userSimulationConfig?: UserSimulationConfig }) {
    super(config);
    
    this.accessControlTester = new AccessControlTester(config.accessControlConfig);
    this.userSimulator = new UserSimulator(
      config.userSimulationConfig || { roles: [], attributes: {} }
    );
  }

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];
    const testUsers = await this.userSimulator.generateTestUsers(suite.userRoles);

    for (const user of testUsers) {
      for (const resource of suite.resources) {
        for (const context of suite.contexts) {
          const result = await this.accessControlTester.testPDPDecision({
            user,
            resource,
            context,
            expectedDecision: suite.expectedDecisions?.[`${user.role}-${resource.type}`],
          });

          results.push(
            this.createTestResult(
              `PDP Decision: ${user.role} accessing ${resource.type}`,
              result.allowed === result.expectedAllowed,
              result
            )
          );
        }
      }
    }

    return results;
  }

  validateConfig(config: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.accessControlConfig) {
      errors.push('accessControlConfig is required');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

