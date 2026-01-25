/**
 * API Design Test Suite
 * Tests for HTTP method validation, Content-Type validation, endpoint enumeration, etc.
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';

export class APIDesignTestSuite extends BaseTestSuite {
  /**
   * Run all API design tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testHTTPMethodValidation(endpoint, method, test));
    results.push(await this.testContentTypeValidation(endpoint, method, test));
    results.push(await this.testEndpointEnumeration(endpoint, method, test));
    results.push(await this.testVerboseErrors(endpoint, method, test));
    results.push(await this.testMissingSecurityControls(endpoint, method, test));
    results.push(await this.testAPIVersioningSecurity(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: HTTP Method Validation
   */
  async testHTTPMethodValidation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('HTTP Method Validation Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test all HTTP methods
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'];
      
      for (const testMethod of methods) {
        const response = await this.makeRequest(url, testMethod, headers);
        
        // If method is not allowed but returns 200, that's suspicious
        if (response.status === 200 && testMethod !== method) {
          securityIssues.push(`Unexpected HTTP method accepted: ${testMethod}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        methodsTested: methods.length,
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
   * Test 2: Content-Type Validation
   */
  async testContentTypeValidation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Content-Type Validation Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test with invalid Content-Type
      const invalidContentTypes = [
        'text/html',
        'application/xml',
        'text/plain',
        'multipart/form-data',
      ];

      for (const contentType of invalidContentTypes) {
        const testHeaders = { ...headers, 'Content-Type': contentType };
        const body = test?.body || { test: 'data' };
        const response = await this.makeRequest(url, method, testHeaders, body);
        
        // If invalid Content-Type is accepted, that's a security issue
        if (response.status === 200 && contentType !== 'application/json') {
          securityIssues.push(`Invalid Content-Type accepted: ${contentType}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        contentTypesTested: invalidContentTypes.length,
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
   * Test 3: Endpoint Enumeration
   */
  async testEndpointEnumeration(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Endpoint Enumeration Test', endpoint, method);
    const startTime = Date.now();

    try {
      const baseUrl = this.config.baseUrl;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test common endpoint patterns
      // Use endpoint patterns from config if provided, otherwise use defaults
      const commonEndpoints = this.config.endpointPatterns || [
        '/admin',
        '/api/admin',
        '/api/v1/admin',
        '/admin/users',
        '/api/users',
        '/api/v1/users',
        '/config',
        '/settings',
        '/debug',
        '/test',
      ];

      for (const testEndpoint of commonEndpoints) {
        const url = `${baseUrl}${testEndpoint}`;
        const response = await this.makeRequest(url, method, headers);
        
        if (response.status === 200) {
          securityIssues.push(`Endpoint accessible: ${testEndpoint}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        endpointsTested: commonEndpoints.length,
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
   * Test 4: Verbose Errors
   */
  async testVerboseErrors(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Verbose Errors Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Trigger errors
      const errorTriggers = [
        { invalid: 'data' },
        { id: null },
        { id: 'invalid' },
      ];

      const securityIssues: string[] = [];

      for (const trigger of errorTriggers) {
        const response = await this.makeRequest(url, method, headers, trigger);
        const responseText = await response.text();

        // Check for verbose error messages
        const verbosePatterns = [
          /stack trace/i,
          /file path/i,
          /database/i,
          /sql/i,
          /exception/i,
          /error at/i,
        ];

        for (const pattern of verbosePatterns) {
          if (pattern.test(responseText)) {
            securityIssues.push(`Verbose error message detected: ${pattern.source}`);
            break;
          }
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        errorsTested: errorTriggers.length,
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
   * Test 5: Missing Security Controls
   */
  async testMissingSecurityControls(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Missing Security Controls Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());

      const missingControls: string[] = [];

      // Check for required security headers
      if (!responseHeaders['strict-transport-security']) {
        missingControls.push('Missing HSTS header');
      }
      if (!responseHeaders['x-content-type-options']) {
        missingControls.push('Missing X-Content-Type-Options header');
      }
      if (!responseHeaders['x-frame-options']) {
        missingControls.push('Missing X-Frame-Options header');
      }
      if (!responseHeaders['content-security-policy']) {
        missingControls.push('Missing CSP header');
      }

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = missingControls.length > 0 ? missingControls : undefined;
      result.passed = missingControls.length === 0;
      result.details = {
        missingControls,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 6: API Versioning Security
   */
  async testAPIVersioningSecurity(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('API Versioning Security Test', endpoint, method);
    const startTime = Date.now();

    try {
      const baseUrl = this.config.baseUrl;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test deprecated versions from config, or use empty array if not configured
      // Note: Only test versions that are actually deprecated for the API being tested
      const deprecatedVersions = this.config.deprecatedVersions || [];
      
      if (deprecatedVersions.length === 0) {
        // No deprecated versions configured - skip this test
        result.responseTime = Date.now() - startTime;
        result.passed = true;
        result.details = {
          versionsTested: 0,
          issuesFound: 0,
          note: 'No deprecated versions configured for testing',
        };
        return result;
      }
      
      for (const version of deprecatedVersions) {
        const url = `${baseUrl}${version}${endpoint.replace(/^\//, '')}`;
        const response = await this.makeRequest(url, method, headers);
        
        if (response.status === 200) {
          securityIssues.push(`Deprecated API version accessible: ${version}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        versionsTested: deprecatedVersions.length,
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

