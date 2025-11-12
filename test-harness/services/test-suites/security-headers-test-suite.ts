/**
 * Security Headers Test Suite
 * Tests for security headers (CORS, CSP, HSTS, etc.)
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { analyzeSecurityHeaders, analyzeCORS } from '../utils/header-analyzer';

export class SecurityHeadersTestSuite extends BaseTestSuite {
  /**
   * Run all security header tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testCORSConfiguration(endpoint, method, test));
    results.push(await this.testCSP(endpoint, method, test));
    results.push(await this.testHSTS(endpoint, method, test));
    results.push(await this.testXContentTypeOptions(endpoint, method, test));
    results.push(await this.testXFrameOptions(endpoint, method, test));
    results.push(await this.testXSSProtection(endpoint, method, test));
    results.push(await this.testReferrerPolicy(endpoint, method, test));
    results.push(await this.testPermissionsPolicy(endpoint, method, test));
    results.push(await this.testServerInformationDisclosure(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: CORS Configuration
   */
  async testCORSConfiguration(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('CORS Configuration Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      
      // Make OPTIONS request to check CORS
      const response = await this.makeRequest(url, 'OPTIONS', headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const corsAnalysis = analyzeCORS(responseHeaders);
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = corsAnalysis.issues.length > 0 ? corsAnalysis.issues : undefined;
      result.passed = corsAnalysis.valid;
      result.details = {
        corsOrigin: responseHeaders['access-control-allow-origin'],
        corsCredentials: responseHeaders['access-control-allow-credentials'],
        corsMethods: responseHeaders['access-control-allow-methods'],
        analysis: corsAnalysis,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: CSP (Content Security Policy)
   */
  async testCSP(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('CSP Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const csp = responseHeaders['content-security-policy'] || responseHeaders['Content-Security-Policy'];
      const analysis = analyzeSecurityHeaders(responseHeaders);
      const cspHeader = analysis.headers.find(h => h.header.toLowerCase() === 'content-security-policy');
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = cspHeader?.issues.length > 0 ? cspHeader.issues : undefined;
      result.passed = cspHeader?.valid || false;
      result.details = {
        csp: csp,
        analysis: cspHeader,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 3: HSTS (HTTP Strict Transport Security)
   */
  async testHSTS(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('HSTS Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const hsts = responseHeaders['strict-transport-security'] || responseHeaders['Strict-Transport-Security'];
      const analysis = analyzeSecurityHeaders(responseHeaders);
      const hstsHeader = analysis.headers.find(h => h.header.toLowerCase() === 'strict-transport-security');
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = hstsHeader?.issues.length > 0 ? hstsHeader.issues : undefined;
      result.passed = hstsHeader?.valid || false;
      result.details = {
        hsts: hsts,
        analysis: hstsHeader,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 4: X-Content-Type-Options
   */
  async testXContentTypeOptions(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('X-Content-Type-Options Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const analysis = analyzeSecurityHeaders(responseHeaders);
      const header = analysis.headers.find(h => h.header.toLowerCase() === 'x-content-type-options');
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
      result.passed = header?.valid || false;
      result.details = { analysis: header };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 5: X-Frame-Options
   */
  async testXFrameOptions(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('X-Frame-Options Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const analysis = analyzeSecurityHeaders(responseHeaders);
      const header = analysis.headers.find(h => h.header.toLowerCase() === 'x-frame-options');
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
      result.passed = header?.valid || false;
      result.details = { analysis: header };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 6: X-XSS-Protection
   */
  async testXSSProtection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('X-XSS-Protection Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const analysis = analyzeSecurityHeaders(responseHeaders);
      const header = analysis.headers.find(h => h.header.toLowerCase() === 'x-xss-protection');
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
      result.passed = header?.valid || false;
      result.details = { analysis: header };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 7: Referrer-Policy
   */
  async testReferrerPolicy(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Referrer-Policy Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const analysis = analyzeSecurityHeaders(responseHeaders);
      const header = analysis.headers.find(h => h.header.toLowerCase() === 'referrer-policy');
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
      result.passed = header?.valid || false;
      result.details = { analysis: header };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 8: Permissions-Policy
   */
  async testPermissionsPolicy(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Permissions-Policy Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const analysis = analyzeSecurityHeaders(responseHeaders);
      const header = analysis.headers.find(h => h.header.toLowerCase() === 'permissions-policy');
      
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
      result.passed = header?.present || false; // Permissions-Policy is optional
      result.details = { analysis: header };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 9: Server Information Disclosure
   */
  async testServerInformationDisclosure(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Server Information Disclosure Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      const disclosureHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime'];
      const securityIssues: string[] = [];

      for (const headerName of disclosureHeaders) {
        if (responseHeaders[headerName] || responseHeaders[headerName.toLowerCase()]) {
          securityIssues.push(`Server information disclosure: ${headerName} header present`);
        }
      }

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        headersChecked: disclosureHeaders,
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

