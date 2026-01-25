/**
 * Access Control Validator Adapter
 * 
 * Example adapter that wraps the existing AccessControlTester
 * to demonstrate how to use the validator registry system.
 */

import { BaseValidator } from '../core/base-validator';
import { ValidatorMetadata } from '../core/validator-registry';
import { AccessControlTester } from '../services/access-control-tester';
import { TestResult, TestSuite, AccessControlConfig } from '../core/types';

export class AccessControlValidatorAdapter extends BaseValidator {
  readonly id = 'access-control';
  readonly name = 'Access Control Validator';
  readonly description = 'Validates RBAC/ABAC access control policies';
  readonly testType = 'access-control';
  readonly version = '1.0.0';

  readonly metadata: ValidatorMetadata = {
    supportedTestTypes: ['access-control'],
    requiredConfig: ['accessControlConfig'],
    optionalConfig: [],
    tags: ['rbac', 'abac', 'policies', 'access-control'],
  };

  private accessControlTester: AccessControlTester;

  constructor(config: { accessControlConfig: AccessControlConfig }) {
    super(config);
    
    this.accessControlTester = new AccessControlTester(config.accessControlConfig);
  }

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];
    
    // Check if suite has access-control specific config
    const accessControlSuite = suite as any as { userRoles?: string[]; resources?: any[]; contexts?: any[] };
    if (!accessControlSuite.userRoles || !accessControlSuite.resources || !accessControlSuite.contexts) {
      throw new Error('AccessControlTestSuite requires userRoles, resources, and contexts');
    }
    
    // Generate test users from roles
    const testUsers = accessControlSuite.userRoles.map(role => ({
      id: `test-user-${role}`,
      email: `${role}@test.example.com`,
      role: role as any,
      attributes: {},
    }));

    for (const user of testUsers) {
      for (const resource of accessControlSuite.resources) {
        for (const context of accessControlSuite.contexts) {
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

