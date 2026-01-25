/**
 * Base Test Suite
 * Abstract base class for all API security test suites
 */

import { APISecurityTestConfig, APISecurityTest, APISecurityTestResult } from '../api-security-tester';

export abstract class BaseTestSuite {
  protected config: APISecurityTestConfig;

  constructor(config: APISecurityTestConfig) {
    this.config = config;
  }

  /**
   * Build request headers with authentication
   */
  protected buildHeaders(test?: Partial<APISecurityTest>): Record<string, string> {
    const headers: Record<string, string> = {
      ...this.config.headers,
      ...test?.headers,
    };

    // Add authentication header
    if (this.config.authentication) {
      const authHeader = this.getAuthHeader(this.config.authentication, test?.user);
      if (authHeader) {
        headers['Authorization'] = authHeader;
      }
    }

    return headers;
  }

  /**
   * Get authentication header
   */
  protected getAuthHeader(
    auth: APISecurityTestConfig['authentication'],
    user?: any
  ): string {
    if (!auth) return '';

    switch (auth.type) {
      case 'bearer':
        return `Bearer ${auth.credentials.token}`;
      case 'basic':
        const credentials = Buffer.from(
          `${auth.credentials.username}:${auth.credentials.password}`
        ).toString('base64');
        return `Basic ${credentials}`;
      case 'api-key':
        return auth.credentials.apiKey || '';
      case 'oauth2':
        return `Bearer ${auth.credentials.accessToken}`;
      case 'jwt':
        return `Bearer ${auth.credentials.jwt}`;
      default:
        return '';
    }
  }

  /**
   * Make HTTP request
   */
  protected async makeRequest(
    url: string,
    method: string,
    headers: Record<string, string>,
    body?: any
  ): Promise<Response> {
    const options: RequestInit = {
      method,
      headers,
    };

    if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
      options.body = typeof body === 'string' ? body : JSON.stringify(body);
      if (!headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }
    }

    const timeout = this.config.timeout || 10000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timeoutId);
      return response;
    } catch (error: any) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }
      throw error;
    }
  }

  /**
   * Create base test result
   */
  protected createBaseResult(
    testName: string,
    endpoint: string,
    method: string
  ): APISecurityTestResult {
    return {
      testName,
      endpoint,
      method,
      testType: 'api-security',
      passed: false,
      timestamp: new Date(),
      details: {},
    };
  }

  /**
   * Evaluate test result
   */
  protected evaluateResult(
    result: APISecurityTestResult,
    expectedStatus?: number,
    expectedAuthRequired?: boolean
  ): boolean {
    // Check expected status
    if (expectedStatus && result.statusCode !== expectedStatus) {
      return false;
    }

    // Check authentication requirement
    if (
      expectedAuthRequired &&
      result.authenticationResult &&
      !result.authenticationResult.authenticated
    ) {
      return false;
    }

    // Check for security issues
    if (result.securityIssues && result.securityIssues.length > 0) {
      return false;
    }

    return true;
  }

  /**
   * Run all tests in this suite
   * Must be implemented by subclasses
   */
  abstract runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]>;
}

