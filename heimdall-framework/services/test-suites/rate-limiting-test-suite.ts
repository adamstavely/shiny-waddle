/**
 * Rate Limiting Test Suite
 * Tests for rate limiting, DoS protection, request size limits, etc.
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';

export class RateLimitingTestSuite extends BaseTestSuite {
  /**
   * Run all rate limiting tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testRateLimitEnforcement(endpoint, method, test));
    results.push(await this.testRateLimitBypass(endpoint, method, test));
    results.push(await this.testDDoSProtection(endpoint, method, test));
    results.push(await this.testRequestSizeLimits(endpoint, method, test));
    results.push(await this.testTimeoutHandling(endpoint, method, test));
    results.push(await this.testConnectionLimits(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: Rate Limit Enforcement
   */
  async testRateLimitEnforcement(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Rate Limit Enforcement Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const maxRequests = this.config.rateLimitConfig?.maxRequests || 100;

      // Make rapid requests
      const requests: Promise<Response>[] = [];
      for (let i = 0; i < maxRequests + 10; i++) {
        requests.push(this.makeRequest(url, method, headers));
      }

      const responses = await Promise.all(requests);
      let rateLimited = false;
      let rateLimitReachedAt = -1;

      for (let i = 0; i < responses.length; i++) {
        if (responses[i].status === 429) {
          rateLimited = true;
          if (rateLimitReachedAt === -1) {
            rateLimitReachedAt = i;
          }
        }
      }

      result.responseTime = Date.now() - startTime;
      result.passed = rateLimited;
      result.securityIssues = rateLimited ? undefined : ['Rate limiting not enforced'];
      result.details = {
        totalRequests: requests.length,
        rateLimited,
        rateLimitReachedAt,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: Rate Limit Bypass
   */
  async testRateLimitBypass(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Rate Limit Bypass Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const securityIssues: string[] = [];

      // Test bypass methods
      const bypassMethods = [
        { header: 'X-Forwarded-For', value: '127.0.0.1' },
        { header: 'X-Real-IP', value: '127.0.0.1' },
        { header: 'X-Originating-IP', value: '127.0.0.1' },
      ];

      for (const bypass of bypassMethods) {
        const headers = { ...this.buildHeaders(test), [bypass.header]: bypass.value };
        const response = await this.makeRequest(url, method, headers);
        
        if (response.status === 200) {
          securityIssues.push(`Potential rate limit bypass via ${bypass.header}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = { bypassMethodsTested: bypassMethods.length, issuesFound: securityIssues.length };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 3: DDoS Protection
   */
  async testDDoSProtection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('DDoS Protection Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Simulate volumetric attack
      const requests: Promise<Response>[] = [];
      for (let i = 0; i < 1000; i++) {
        requests.push(this.makeRequest(url, method, headers));
      }

      const responses = await Promise.all(requests);
      const successRate = responses.filter(r => r.status === 200).length / responses.length;

      result.responseTime = Date.now() - startTime;
      result.passed = successRate < 0.5; // Less than 50% success indicates protection
      result.securityIssues = successRate >= 0.5 ? ['DDoS protection may be insufficient'] : undefined;
      result.details = {
        totalRequests: requests.length,
        successRate,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 4: Request Size Limits
   */
  async testRequestSizeLimits(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Request Size Limits Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with large payloads
      const largePayload = 'x'.repeat(10 * 1024 * 1024); // 10MB
      const body = { data: largePayload, ...test?.body };
      const response = await this.makeRequest(url, method, headers, body);

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = response.status === 413; // 413 Payload Too Large
      result.securityIssues = response.status !== 413 ? ['Request size limits not enforced'] : undefined;
      result.details = {
        payloadSize: largePayload.length,
        statusCode: response.status,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 5: Timeout Handling
   */
  async testTimeoutHandling(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Timeout Handling Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Make request and check timeout
      const timeout = this.config.timeout || 10000;
      const response = await this.makeRequest(url, method, headers);
      const responseTime = Date.now() - startTime;

      result.statusCode = response.status;
      result.responseTime = responseTime;
      result.passed = responseTime < timeout;
      result.securityIssues = responseTime >= timeout ? ['Request timeout not properly handled'] : undefined;
      result.details = {
        responseTime,
        timeout,
      };
    } catch (error: any) {
      if (error.message.includes('timeout')) {
        result.passed = true; // Timeout was enforced
        result.details = { message: 'Timeout properly enforced' };
      } else {
        result.passed = false;
        result.error = error.message;
        result.details = { error: error.message };
      }
    }

    return result;
  }

  /**
   * Test 6: Connection Limits
   */
  async testConnectionLimits(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Connection Limits Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test concurrent connections
      const concurrentRequests = 100;
      const requests: Promise<Response>[] = [];
      
      for (let i = 0; i < concurrentRequests; i++) {
        requests.push(this.makeRequest(url, method, headers));
      }

      const responses = await Promise.all(requests);
      const successCount = responses.filter(r => r.status === 200).length;

      result.responseTime = Date.now() - startTime;
      result.passed = successCount < concurrentRequests; // Some should be rejected
      result.securityIssues = successCount === concurrentRequests ? ['Connection limits not enforced'] : undefined;
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
}

