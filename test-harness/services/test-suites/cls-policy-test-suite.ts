/**
 * CLS Policy Test Suite
 * 
 * Test suite for Column-Level Security policies
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { RLSCLSTester } from '../rls-cls-tester';
import { TestQuery, User, DatabaseConfig, DynamicMaskingRule } from '../../core/types';

export class CLSPolicyTestSuite extends BaseTestSuite {
  private rlsTester: RLSCLSTester;
  private databaseConfig?: DatabaseConfig;

  constructor(config: any, databaseConfig?: DatabaseConfig) {
    super(config);
    this.rlsTester = new RLSCLSTester();
    this.databaseConfig = databaseConfig;
  }

  /**
   * Run all CLS policy tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    if (!this.databaseConfig) {
      results.push(this.createBaseResult(
        'CLS Coverage Test',
        endpoint,
        method
      ));
      results[0].error = 'Database configuration required for CLS tests';
      results[0].passed = false;
      return results;
    }

    // Test CLS coverage
    results.push(await this.testCLSCoverage(endpoint, method, test));

    // Test dynamic masking
    results.push(await this.testDynamicMasking(endpoint, method, test));

    return results;
  }

  /**
   * Test CLS coverage
   */
  async testCLSCoverage(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('CLS Coverage Test', endpoint, method);

    try {
      if (!this.databaseConfig) {
        result.error = 'Database configuration required';
        result.passed = false;
        return result;
      }

      const coverage = await this.rlsTester.testCLSCoverage(this.databaseConfig);
      
      result.passed = coverage.coveragePercentage >= 80; // 80% threshold
      result.details = {
        coverage,
        message: coverage.coveragePercentage >= 80
          ? 'CLS coverage meets threshold'
          : `${coverage.tablesWithoutCLS.length} tables missing CLS policies`,
      };
    } catch (error: any) {
      result.error = error.message;
      result.passed = false;
    }

    return result;
  }

  /**
   * Test dynamic data masking
   */
  async testDynamicMasking(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult(
      'Dynamic Data Masking Test',
      endpoint,
      method
    );

    try {
      const maskingRules: DynamicMaskingRule[] = [
        {
          table: 'users',
          column: 'email',
          maskingType: 'partial',
          pattern: '***@***',
          applicableRoles: ['viewer', 'analyst'],
        },
        {
          table: 'users',
          column: 'ssn',
          maskingType: 'full',
          applicableRoles: ['viewer'],
        },
      ];

      const testQuery: TestQuery = {
        name: 'Masking Test Query',
        sql: 'SELECT email, ssn FROM users WHERE id = 1',
      };

      const user: User = {
        id: 'test-user',
        email: 'test@example.com',
        role: 'viewer',
        attributes: {},
      };

      const maskingTest = await this.rlsTester.testDynamicMasking(
        testQuery,
        user,
        maskingRules
      );

      result.passed = maskingTest.passed;
      result.details = {
        maskingTest,
        message: maskingTest.passed
          ? 'Dynamic masking verified'
          : 'Dynamic masking not properly applied',
      };
    } catch (error: any) {
      result.error = error.message;
      result.passed = false;
    }

    return result;
  }
}

