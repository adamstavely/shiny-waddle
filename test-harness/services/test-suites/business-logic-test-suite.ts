/**
 * Business Logic Test Suite
 * Tests for workflow bypass, race conditions, time-based attacks, etc.
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';

export class BusinessLogicTestSuite extends BaseTestSuite {
  /**
   * Run all business logic tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testWorkflowBypass(endpoint, method, test));
    results.push(await this.testRaceConditions(endpoint, method, test));
    results.push(await this.testTimeBasedAttacks(endpoint, method, test));
    results.push(await this.testBusinessRuleViolations(endpoint, method, test));
    results.push(await this.testStateTransitionAttacks(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: Workflow Bypass
   */
  async testWorkflowBypass(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Workflow Bypass Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Try to skip workflow steps
      const bypassAttempts = [
        { status: 'completed', step: 1 }, // Skip to completed
        { status: 'approved', step: 0 }, // Skip approval
        { verified: true, step: 0 }, // Skip verification
      ];

      for (const attempt of bypassAttempts) {
        const body = { ...attempt, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        
        if (response.status === 200) {
          securityIssues.push(`Workflow bypass possible: ${JSON.stringify(attempt)}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        attemptsTested: bypassAttempts.length,
        issuesFound: securityIssues.length,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: Race Conditions
   */
  async testRaceConditions(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Race Conditions Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Make concurrent requests to test race conditions
      const concurrentRequests = 10;
      const requests: Promise<Response>[] = [];
      
      for (let i = 0; i < concurrentRequests; i++) {
        const body = { ...test?.body, amount: 100 }; // Example: transfer amount
        requests.push(this.makeRequest(url, method, headers, body));
      }

      const responses = await Promise.all(requests);
      const successCount = responses.filter(r => r.status === 200).length;

      result.responseTime = Date.now() - startTime;
      
      // If all requests succeed, might indicate race condition
      result.passed = successCount < concurrentRequests;
      result.securityIssues = successCount === concurrentRequests ? ['Potential race condition: All concurrent requests succeeded'] : undefined;
      result.details = {
        concurrentRequests,
        successCount,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 3: Time-Based Attacks
   */
  async testTimeBasedAttacks(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Time-Based Attacks Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test timing differences (e.g., user enumeration)
      const testUsers = ['admin', 'user', 'invalid'];
      const timings: number[] = [];

      for (const user of testUsers) {
        const userStartTime = Date.now();
        const body = { username: user, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const userEndTime = Date.now();
        timings.push(userEndTime - userStartTime);
      }

      // Check for significant timing differences (potential user enumeration)
      const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
      const maxDeviation = Math.max(...timings.map(t => Math.abs(t - avgTiming)));

      if (maxDeviation > avgTiming * 0.5) {
        securityIssues.push('Significant timing differences detected (potential user enumeration)');
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        timings,
        avgTiming,
        maxDeviation,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 4: Business Rule Violations
   */
  async testBusinessRuleViolations(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Business Rule Violations Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test business rule violations
      const violations = [
        { amount: -100 }, // Negative amount
        { amount: 0 }, // Zero amount
        { amount: Number.MAX_SAFE_INTEGER }, // Extremely large amount
        { quantity: -1 }, // Negative quantity
        { price: -1 }, // Negative price
      ];

      for (const violation of violations) {
        const body = { ...violation, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        
        if (response.status === 200) {
          securityIssues.push(`Business rule violation accepted: ${JSON.stringify(violation)}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        violationsTested: violations.length,
        issuesFound: securityIssues.length,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 5: State Transition Attacks
   */
  async testStateTransitionAttacks(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('State Transition Attacks Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Try invalid state transitions
      const invalidTransitions = [
        { from: 'pending', to: 'completed' }, // Skip intermediate states
        { from: 'new', to: 'archived' }, // Skip required states
        { status: 'completed', previousStatus: 'new' }, // Invalid transition
      ];

      for (const transition of invalidTransitions) {
        const body = { ...transition, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        
        if (response.status === 200) {
          securityIssues.push(`Invalid state transition accepted: ${JSON.stringify(transition)}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        transitionsTested: invalidTransitions.length,
        issuesFound: securityIssues.length,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }
}

