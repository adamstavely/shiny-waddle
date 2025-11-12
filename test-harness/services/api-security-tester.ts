/**
 * API Security Testing Service
 * 
 * Comprehensive API security testing including REST, GraphQL, rate limiting,
 * authentication, and authorization testing
 */

import { User, Resource } from '../core/types';
import { TestResult } from '../core/types';
import { AuthenticationTestSuite } from './test-suites/authentication-test-suite';
import { AuthorizationTestSuite } from './test-suites/authorization-test-suite';
import { InjectionTestSuite } from './test-suites/injection-test-suite';
import { RateLimitingTestSuite } from './test-suites/rate-limiting-test-suite';
import { SecurityHeadersTestSuite } from './test-suites/security-headers-test-suite';
import { GraphQLTestSuite } from './test-suites/graphql-test-suite';
import { SensitiveDataTestSuite } from './test-suites/sensitive-data-test-suite';
import { CryptographyTestSuite } from './test-suites/cryptography-test-suite';
import { APIDesignTestSuite } from './test-suites/api-design-test-suite';
import { BusinessLogicTestSuite } from './test-suites/business-logic-test-suite';
import { ThirdPartyIntegrationTestSuite } from './test-suites/third-party-integration-test-suite';
import { LoggingTestSuite } from './test-suites/logging-test-suite';

export interface APISecurityTestConfig {
  baseUrl: string;
  authentication?: {
    type: 'bearer' | 'basic' | 'oauth2' | 'api-key' | 'jwt';
    credentials: Record<string, string>;
  };
  rateLimitConfig?: {
    maxRequests?: number;
    windowSeconds?: number;
    strategy?: 'fixed' | 'sliding' | 'token-bucket';
  };
  headers?: Record<string, string>;
  timeout?: number;
}

export interface APISecurityTest {
  name: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS';
  expectedStatus?: number;
  expectedAuthRequired?: boolean;
  expectedRateLimit?: boolean;
  body?: any;
  headers?: Record<string, string>;
  user?: User;
  resource?: Resource;
}

export interface APISecurityTestResult extends TestResult {
  testName: string;
  endpoint: string;
  method: string;
  statusCode?: number;
  responseTime?: number;
  rateLimitInfo?: {
    limit?: number;
    remaining?: number;
    resetTime?: Date;
  };
  authenticationResult?: {
    authenticated: boolean;
    tokenValid?: boolean;
    tokenExpired?: boolean;
  };
  authorizationResult?: {
    authorized: boolean;
    reason?: string;
  };
  securityIssues?: string[];
}

export class APISecurityTester {
  private config: APISecurityTestConfig;

  constructor(config: APISecurityTestConfig) {
    this.config = config;
  }

  /**
   * Test REST API security
   */
  async testRESTAPI(test: APISecurityTest): Promise<APISecurityTestResult> {
    const startTime = Date.now();
    const result: APISecurityTestResult = {
      testName: test.name,
      endpoint: test.endpoint,
      method: test.method,
      testType: 'api-security',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      // Build request
      const url = `${this.config.baseUrl}${test.endpoint}`;
      const headers = this.buildHeaders(test);
      const options: RequestInit = {
        method: test.method,
        headers,
      };

      if (test.body && ['POST', 'PUT', 'PATCH'].includes(test.method)) {
        options.body = JSON.stringify(test.body);
        headers['Content-Type'] = 'application/json';
      }

      // Make request
      const response = await fetch(url, options);
      const responseTime = Date.now() - startTime;
      result.responseTime = responseTime;
      result.statusCode = response.status;

      // Extract rate limit headers
      result.rateLimitInfo = this.extractRateLimitHeaders(response);

      // Test authentication
      result.authenticationResult = await this.testAuthentication(
        response,
        test
      );

      // Test authorization
      result.authorizationResult = await this.testAuthorization(
        response,
        test
      );

      // Check for security issues
      result.securityIssues = await this.detectSecurityIssues(
        response,
        test
      );

      // Validate response
      const body = await response.json().catch(() => ({}));
      result.details = {
        responseBody: body,
        responseHeaders: Object.fromEntries(response.headers.entries()),
      };

      // Determine if test passed
      result.passed = this.evaluateTestResult(result, test);

      return result;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
      return result;
    }
  }

  /**
   * Test GraphQL API security
   */
  async testGraphQLAPI(
    query: string,
    variables?: Record<string, any>,
    test?: APISecurityTest
  ): Promise<APISecurityTestResult> {
    const startTime = Date.now();
    const result: APISecurityTestResult = {
      testName: test?.name || 'GraphQL Query',
      endpoint: test?.endpoint || '/graphql',
      method: 'POST',
      testType: 'api-security',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const url = `${this.config.baseUrl}${result.endpoint}`;
      const headers = this.buildHeaders(test || {});

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query,
          variables,
        }),
      });

      const responseTime = Date.now() - startTime;
      result.responseTime = responseTime;
      result.statusCode = response.status;

      const body = await response.json().catch(() => ({}));
      result.details = {
        graphqlResponse: body,
        query,
        variables,
      };

      // Check for GraphQL-specific security issues
      result.securityIssues = this.detectGraphQLSecurityIssues(body, query);

      // Test authentication and authorization
      result.authenticationResult = await this.testAuthentication(
        response,
        test || {}
      );
      result.authorizationResult = await this.testAuthorization(
        response,
        test || {}
      );

      result.passed = this.evaluateTestResult(result, test || {});

      return result;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
      return result;
    }
  }

  /**
   * Test API rate limiting
   */
  async testRateLimiting(
    endpoint: string,
    method: string = 'GET'
  ): Promise<APISecurityTestResult> {
    const result: APISecurityTestResult = {
      testName: 'Rate Limiting Test',
      endpoint,
      method: method as any,
      testType: 'api-security',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const maxRequests = this.config.rateLimitConfig?.maxRequests || 100;
      const requests: Promise<Response>[] = [];

      // Make rapid requests to test rate limiting
      for (let i = 0; i < maxRequests + 10; i++) {
        const url = `${this.config.baseUrl}${endpoint}`;
        requests.push(
          fetch(url, {
            method,
            headers: this.buildHeaders({}),
          })
        );
      }

      const responses = await Promise.all(requests);
      const rateLimitInfo = this.extractRateLimitHeaders(responses[0]);

      // Analyze rate limiting behavior
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

      result.rateLimitInfo = rateLimitInfo;
      result.details = {
        totalRequests: requests.length,
        rateLimited,
        rateLimitReachedAt,
        rateLimitHeaders: rateLimitInfo,
      };

      // Test passes if rate limiting is properly enforced
      result.passed = rateLimited || (rateLimitInfo.limit !== undefined);

      return result;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      return result;
    }
  }

  /**
   * Test API authentication
   */
  async testAuthentication(
    test: APISecurityTest
  ): Promise<APISecurityTestResult> {
    const result: APISecurityTestResult = {
      testName: 'Authentication Test',
      endpoint: test.endpoint,
      method: test.method,
      testType: 'api-security',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const url = `${this.config.baseUrl}${test.endpoint}`;

      // Test 1: Request without authentication
      const unauthenticatedResponse = await fetch(url, {
        method: test.method,
      });

      // Test 2: Request with invalid token
      const invalidTokenResponse = await fetch(url, {
        method: test.method,
        headers: {
          Authorization: 'Bearer invalid-token-12345',
        },
      });

      // Test 3: Request with expired token (if we can detect)
      const expiredTokenResponse = await fetch(url, {
        method: test.method,
        headers: {
          Authorization: 'Bearer expired-token',
        },
      });

      // Test 4: Request with valid authentication
      const validAuthResponse = await fetch(url, {
        method: test.method,
        headers: this.buildHeaders(test),
      });

      result.authenticationResult = {
        authenticated: validAuthResponse.status !== 401,
        tokenValid: validAuthResponse.status !== 401,
        tokenExpired: expiredTokenResponse.status === 401,
      };

      result.details = {
        unauthenticatedStatus: unauthenticatedResponse.status,
        invalidTokenStatus: invalidTokenResponse.status,
        expiredTokenStatus: expiredTokenResponse.status,
        validAuthStatus: validAuthResponse.status,
      };

      // Test passes if unauthenticated requests are rejected
      result.passed =
        unauthenticatedResponse.status === 401 &&
        invalidTokenResponse.status === 401 &&
        validAuthResponse.status !== 401;

      return result;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      return result;
    }
  }

  /**
   * Test API authorization
   */
  async testAuthorization(
    tests: APISecurityTest[]
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    for (const test of tests) {
      if (!test.user || !test.resource) continue;

      const result: APISecurityTestResult = {
        testName: `Authorization Test: ${test.name}`,
        endpoint: test.endpoint,
        method: test.method,
        testType: 'api-security',
        passed: false,
        timestamp: new Date(),
        details: {},
      };

      try {
        const url = `${this.config.baseUrl}${test.endpoint}`;
        const headers = this.buildHeaders(test);

        const response = await fetch(url, {
          method: test.method,
          headers,
          body: test.body ? JSON.stringify(test.body) : undefined,
        });

        result.statusCode = response.status;
        result.authorizationResult = {
          authorized: response.status !== 403,
          reason:
            response.status === 403
              ? 'Access forbidden'
              : response.status === 401
              ? 'Authentication required'
              : 'Access granted',
        };

        // Test passes if authorization is properly enforced
        result.passed =
          (test.expectedAuthRequired && response.status === 401) ||
          (!test.expectedAuthRequired && response.status !== 403);

        results.push(result);
      } catch (error: any) {
        result.passed = false;
        result.error = error.message;
        results.push(result);
      }
    }

    return results;
  }

  /**
   * Test API input validation
   */
  async testInputValidation(
    endpoint: string,
    method: string = 'POST'
  ): Promise<APISecurityTestResult> {
    const result: APISecurityTestResult = {
      testName: 'Input Validation Test',
      endpoint,
      method: method as any,
      testType: 'api-security',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    const securityIssues: string[] = [];

    // Test SQL injection
    const sqlInjectionPayloads = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT * FROM users --",
    ];

    for (const payload of sqlInjectionPayloads) {
      const response = await fetch(`${this.config.baseUrl}${endpoint}`, {
        method,
        headers: this.buildHeaders({}),
        body: JSON.stringify({ input: payload }),
      });

      if (response.status === 200) {
        const body = await response.text();
        if (body.includes('error') || body.includes('SQL')) {
          securityIssues.push(`Potential SQL injection vulnerability detected`);
        }
      }
    }

    // Test XSS
    const xssPayloads = ['<script>alert(1)</script>', 'javascript:alert(1)'];

    for (const payload of xssPayloads) {
      const response = await fetch(`${this.config.baseUrl}${endpoint}`, {
        method,
        headers: this.buildHeaders({}),
        body: JSON.stringify({ input: payload }),
      });

      if (response.status === 200) {
        const body = await response.text();
        if (body.includes(payload)) {
          securityIssues.push(`Potential XSS vulnerability detected`);
        }
      }
    }

    result.securityIssues = securityIssues;
    result.passed = securityIssues.length === 0;
    result.details = {
      testedPayloads: sqlInjectionPayloads.length + xssPayloads.length,
      securityIssuesFound: securityIssues.length,
    };

    return result;
  }

  /**
   * Build request headers
   */
  private buildHeaders(test: Partial<APISecurityTest>): Record<string, string> {
    const headers: Record<string, string> = {
      ...this.config.headers,
      ...test.headers,
    };

    // Add authentication header
    if (this.config.authentication) {
      const authHeader = this.getAuthHeader(
        this.config.authentication,
        test.user
      );
      if (authHeader) {
        headers['Authorization'] = authHeader;
      }
    }

    return headers;
  }

  /**
   * Get authentication header
   */
  private getAuthHeader(
    auth: APISecurityTestConfig['authentication'],
    user?: User
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
   * Extract rate limit headers
   */
  private extractRateLimitHeaders(response: Response): {
    limit?: number;
    remaining?: number;
    resetTime?: Date;
  } {
    const headers = response.headers;
    const info: any = {};

    // Common rate limit header patterns
    const limitHeader =
      headers.get('X-RateLimit-Limit') ||
      headers.get('RateLimit-Limit') ||
      headers.get('X-Rate-Limit-Limit');
    if (limitHeader) {
      info.limit = parseInt(limitHeader);
    }

    const remainingHeader =
      headers.get('X-RateLimit-Remaining') ||
      headers.get('RateLimit-Remaining') ||
      headers.get('X-Rate-Limit-Remaining');
    if (remainingHeader) {
      info.remaining = parseInt(remainingHeader);
    }

    const resetHeader =
      headers.get('X-RateLimit-Reset') ||
      headers.get('RateLimit-Reset') ||
      headers.get('X-Rate-Limit-Reset');
    if (resetHeader) {
      const resetTimestamp = parseInt(resetHeader);
      info.resetTime = new Date(
        resetTimestamp > 10000000000
          ? resetTimestamp * 1000
          : resetTimestamp
      );
    }

    return info;
  }

  /**
   * Test authentication from response
   */
  private async testAuthentication(
    response: Response,
    test: APISecurityTest
  ): Promise<{
    authenticated: boolean;
    tokenValid?: boolean;
    tokenExpired?: boolean;
  }> {
    return {
      authenticated: response.status !== 401,
      tokenValid: response.status !== 401,
      tokenExpired: response.status === 401 && test.expectedAuthRequired,
    };
  }

  /**
   * Test authorization from response
   */
  private async testAuthorization(
    response: Response,
    test: APISecurityTest
  ): Promise<{
    authorized: boolean;
    reason?: string;
  }> {
    return {
      authorized: response.status !== 403,
      reason:
        response.status === 403
          ? 'Access forbidden'
          : response.status === 401
          ? 'Authentication required'
          : 'Access granted',
    };
  }

  /**
   * Detect security issues
   */
  private async detectSecurityIssues(
    response: Response,
    test: APISecurityTest
  ): Promise<string[]> {
    const issues: string[] = [];

    // Check for sensitive data in headers
    const headers = Object.fromEntries(response.headers.entries());
    if (headers['x-powered-by'] || headers['server']) {
      issues.push('Server information disclosure in headers');
    }

    // Check for CORS misconfiguration
    const corsHeader = headers['access-control-allow-origin'];
    if (corsHeader === '*') {
      issues.push('CORS allows all origins (*)');
    }

    // Check for missing security headers
    if (!headers['x-content-type-options']) {
      issues.push('Missing X-Content-Type-Options header');
    }
    if (!headers['x-frame-options']) {
      issues.push('Missing X-Frame-Options header');
    }
    if (!headers['strict-transport-security']) {
      issues.push('Missing Strict-Transport-Security header');
    }

    return issues;
  }

  /**
   * Detect GraphQL-specific security issues
   */
  private detectGraphQLSecurityIssues(
    response: any,
    query: string
  ): string[] {
    const issues: string[] = [];

    // Check for introspection enabled
    if (query.includes('__schema') || query.includes('__type')) {
      if (response.data) {
        issues.push('GraphQL introspection may be enabled');
      }
    }

    // Check for query complexity
    if (query.split('{').length > 10) {
      issues.push('Potentially complex GraphQL query');
    }

    // Check for nested queries (N+1 problem)
    const nestedDepth = (query.match(/\{/g) || []).length;
    if (nestedDepth > 5) {
      issues.push('Deeply nested GraphQL query detected');
    }

    return issues;
  }

  /**
   * Evaluate test result
   */
  private evaluateTestResult(
    result: APISecurityTestResult,
    test: APISecurityTest
  ): boolean {
    // Check expected status
    if (test.expectedStatus && result.statusCode !== test.expectedStatus) {
      return false;
    }

    // Check authentication requirement
    if (
      test.expectedAuthRequired &&
      result.authenticationResult &&
      !result.authenticationResult.authenticated
    ) {
      return false;
    }

    // Check for security issues
    if (result.securityIssues && result.securityIssues.length > 0) {
      return false;
    }

    // Check authorization
    if (
      result.authorizationResult &&
      !result.authorizationResult.authorized &&
      test.expectedAuthRequired
    ) {
      return false;
    }

    return true;
  }

  /**
   * Run a specific test suite
   */
  async runTestSuite(
    suiteName: string,
    endpoint: string,
    method: string = 'GET',
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    let suite: any;

    switch (suiteName.toLowerCase()) {
      case 'authentication':
        suite = new AuthenticationTestSuite(this.config);
        break;
      case 'authorization':
        suite = new AuthorizationTestSuite(this.config);
        break;
      case 'injection':
        suite = new InjectionTestSuite(this.config);
        break;
      case 'rate-limiting':
      case 'ratelimiting':
        suite = new RateLimitingTestSuite(this.config);
        break;
      case 'security-headers':
      case 'securityheaders':
        suite = new SecurityHeadersTestSuite(this.config);
        break;
      case 'graphql':
        suite = new GraphQLTestSuite(this.config);
        break;
      case 'sensitive-data':
      case 'sensitivedata':
        suite = new SensitiveDataTestSuite(this.config);
        break;
      case 'cryptography':
        suite = new CryptographyTestSuite(this.config);
        break;
      case 'api-design':
      case 'apidesign':
        suite = new APIDesignTestSuite(this.config);
        break;
      case 'business-logic':
      case 'businesslogic':
        suite = new BusinessLogicTestSuite(this.config);
        break;
      case 'third-party':
      case 'thirdparty':
        suite = new ThirdPartyIntegrationTestSuite(this.config);
        break;
      case 'logging':
        suite = new LoggingTestSuite(this.config);
        break;
      default:
        throw new Error(`Unknown test suite: ${suiteName}`);
    }

    return suite.runAllTests(endpoint, method, test);
  }

  /**
   * Run full security scan (all test suites)
   */
  async runFullSecurityScan(
    endpoint: string,
    method: string = 'GET',
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const allResults: APISecurityTestResult[] = [];

    const suites = [
      'authentication',
      'authorization',
      'injection',
      'rate-limiting',
      'security-headers',
      'graphql',
      'sensitive-data',
      'cryptography',
      'api-design',
      'business-logic',
      'third-party',
      'logging',
    ];

    for (const suiteName of suites) {
      try {
        const results = await this.runTestSuite(suiteName, endpoint, method, test);
        allResults.push(...results);
      } catch (error: any) {
        // Create error result
        const errorResult: APISecurityTestResult = {
          testName: `${suiteName} Suite Error`,
          endpoint,
          method,
          testType: 'api-security',
          passed: false,
          timestamp: new Date(),
          error: error.message,
          details: { suite: suiteName, error: error.message },
        };
        allResults.push(errorResult);
      }
    }

    return allResults;
  }

  /**
   * Run tests by category
   */
  async runTestByCategory(
    category: string,
    endpoint: string,
    method: string = 'GET',
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const categoryMap: Record<string, string[]> = {
      'authentication': ['authentication'],
      'authorization': ['authorization'],
      'injection': ['injection'],
      'rate-limiting': ['rate-limiting'],
      'headers': ['security-headers'],
      'graphql': ['graphql'],
      'data-exposure': ['sensitive-data'],
      'cryptography': ['cryptography'],
      'design': ['api-design'],
      'business-logic': ['business-logic'],
      'integration': ['third-party'],
      'logging': ['logging'],
    };

    const suites = categoryMap[category.toLowerCase()] || [];
    const allResults: APISecurityTestResult[] = [];

    for (const suiteName of suites) {
      try {
        const results = await this.runTestSuite(suiteName, endpoint, method, test);
        allResults.push(...results);
      } catch (error: any) {
        const errorResult: APISecurityTestResult = {
          testName: `${suiteName} Suite Error`,
          endpoint,
          method,
          testType: 'api-security',
          passed: false,
          timestamp: new Date(),
          error: error.message,
          details: { suite: suiteName, error: error.message },
        };
        allResults.push(errorResult);
      }
    }

    return allResults;
  }

  /**
   * Get available test suites
   */
  getAvailableTestSuites(): string[] {
    return [
      'authentication',
      'authorization',
      'injection',
      'rate-limiting',
      'security-headers',
      'graphql',
      'sensitive-data',
      'cryptography',
      'api-design',
      'business-logic',
      'third-party',
      'logging',
    ];
  }
}

