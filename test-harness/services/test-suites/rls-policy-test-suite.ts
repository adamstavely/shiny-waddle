/**
 * RLS Policy Test Suite
 * 
 * Test suite for Row-Level Security policies
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { RLSCLSTester } from '../rls-cls-tester';
import { TestQuery, User, DatabaseConfig } from '../../core/types';

export class RLSPolicyTestSuite extends BaseTestSuite {
  private rlsTester: RLSCLSTester;
  private databaseConfig?: DatabaseConfig;

  constructor(config: any, databaseConfig?: DatabaseConfig) {
    super(config);
    this.rlsTester = new RLSCLSTester();
    this.databaseConfig = databaseConfig;
  }

  /**
   * Run all RLS policy tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    if (!this.databaseConfig) {
      results.push(this.createBaseResult(
        'RLS Coverage Test',
        endpoint,
        method
      ));
      results[0].error = 'Database configuration required for RLS tests';
      results[0].passed = false;
      return results;
    }

    // Test RLS coverage
    results.push(await this.testRLSCoverage(endpoint, method, test));

    // Test cross-tenant isolation
    results.push(await this.testCrossTenantIsolation(endpoint, method, test));

    return results;
  }

  /**
   * Test RLS coverage
   */
  async testRLSCoverage(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('RLS Coverage Test', endpoint, method);

    try {
      if (!this.databaseConfig) {
        result.error = 'Database configuration required';
        result.passed = false;
        return result;
      }

      const coverage = await this.rlsTester.testRLSCoverage(this.databaseConfig);
      
      result.passed = coverage.coveragePercentage >= 100;
      result.details = {
        coverage,
        message: coverage.coveragePercentage >= 100
          ? 'All tables have RLS policies'
          : `${coverage.tablesWithoutRLS.length} tables missing RLS policies`,
      };
    } catch (error: any) {
      result.error = error.message;
      result.passed = false;
    }

    return result;
  }

  /**
   * Test cross-tenant isolation
   */
  async testCrossTenantIsolation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult(
      'Cross-Tenant Isolation Test',
      endpoint,
      method
    );

    try {
      const testQueries: TestQuery[] = [
        {
          name: 'Tenant Isolation Query',
          sql: `SELECT * FROM users WHERE tenant_id = 'tenant1'`,
        },
      ];

      const isolationTest = await this.rlsTester.testCrossTenantIsolation(
        'tenant1',
        'tenant2',
        testQueries
      );

      result.passed = isolationTest.isolationVerified;
      result.details = {
        isolationTest,
        message: isolationTest.isolationVerified
          ? 'Cross-tenant isolation verified'
          : `Isolation violations: ${isolationTest.violations.length}`,
      };
    } catch (error: any) {
      result.error = error.message;
      result.passed = false;
    }

    return result;
  }
}


