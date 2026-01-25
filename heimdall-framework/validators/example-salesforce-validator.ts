/**
 * Example Salesforce Validator
 * 
 * Demonstrates how easy it is to create a new validator using the registry system.
 * This validator checks Salesforce org configuration compliance.
 */

import { BaseValidator } from '../core/base-validator';
import { ValidatorMetadata } from '../core/validator-registry';
import { TestResult, TestSuite } from '../core/types';

export interface SalesforceConfig {
  connection: {
    username: string;
    password: string;
    securityToken?: string;
    loginUrl?: string;
  };
  rules: SalesforceRule[];
}

export interface SalesforceRule {
  id: string;
  name: string;
  check: 'allProfilesHaveMFA' | 'noPublicSharing' | 'passwordPolicyCompliant';
  expectedValue: any;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export class SalesforceValidator extends BaseValidator {
  readonly id = 'salesforce-config';
  readonly name = 'Salesforce Configuration Validator';
  readonly description = 'Validates Salesforce org configuration compliance';
  readonly testType = 'configuration-validation';
  readonly version = '1.0.0';

  readonly metadata: ValidatorMetadata = {
    supportedTestTypes: ['configuration-validation'],
    requiredConfig: ['connection', 'rules'],
    tags: ['salesforce', 'configuration', 'compliance'],
    exampleConfig: {
      connection: {
        username: 'user@example.com',
        password: 'password',
        securityToken: 'token',
      },
      rules: [
        {
          id: 'sf-mfa-required',
          name: 'MFA Required',
          check: 'allProfilesHaveMFA',
          expectedValue: true,
          severity: 'critical',
        },
      ],
    },
  };

  private salesforceConfig: SalesforceConfig;

  constructor(config: SalesforceConfig) {
    super(config);
    this.salesforceConfig = config;
  }

  protected shouldRun(suite: TestSuite): boolean {
    // Check if suite has Salesforce configuration tests
    return !!(suite as any).configurationTests?.some(
      (test: any) => test.target === 'salesforce'
    );
  }

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Get Salesforce tests from suite
    const salesforceTests = (suite as any).configurationTests?.filter(
      (test: any) => test.target === 'salesforce'
    ) || [];

    if (salesforceTests.length === 0) {
      return results;
    }

    // Connect to Salesforce (in real implementation)
    // const client = await this.connectToSalesforce();

    for (const test of salesforceTests) {
      for (const rule of test.rules) {
        try {
          const validationResult = await this.validateRule(rule);
          
          results.push(
            this.createTestResult(
              `${test.name}: ${rule.name}`,
              validationResult.passed,
              {
                ruleId: rule.id,
                severity: rule.severity,
                ...validationResult,
              }
            )
          );
        } catch (error: any) {
          results.push(
            this.createFailedResult(
              `${test.name}: ${rule.name}`,
              error.message,
              { ruleId: rule.id }
            )
          );
        }
      }
    }

    return results;
  }

  private async validateRule(rule: SalesforceRule): Promise<{ passed: boolean; message: string; details?: any }> {
    // In real implementation, this would:
    // 1. Connect to Salesforce API
    // 2. Query the relevant configuration
    // 3. Compare against expected values
    // 4. Return validation result

    switch (rule.check) {
      case 'allProfilesHaveMFA':
        // const profiles = await client.query('SELECT Id, Name, PermissionsMultiFactorAuth FROM Profile');
        // const nonMFAProfiles = profiles.records.filter(p => !p.PermissionsMultiFactorAuth);
        return {
          passed: true, // Placeholder
          message: 'All profiles have MFA enabled',
          details: { totalProfiles: 10, nonMFAProfiles: 0 },
        };

      case 'noPublicSharing':
        return {
          passed: true,
          message: 'No public sharing detected',
        };

      case 'passwordPolicyCompliant':
        return {
          passed: true,
          message: 'Password policy meets requirements',
        };

      default:
        return {
          passed: false,
          message: `Unknown check: ${rule.check}`,
        };
    }
  }

  validateConfig(config: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.connection) {
      errors.push('connection is required');
    } else {
      if (!config.connection.username) {
        errors.push('connection.username is required');
      }
      if (!config.connection.password) {
        errors.push('connection.password is required');
      }
    }

    if (!config.rules || !Array.isArray(config.rules) || config.rules.length === 0) {
      errors.push('rules array is required and must not be empty');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

