/**
 * Third-Party Integration Test Suite
 * Tests for SSRF, webhook security, OAuth flow security
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { SSRF_PAYLOADS } from '../payloads/ssrf';

export class ThirdPartyIntegrationTestSuite extends BaseTestSuite {
  /**
   * Run all third-party integration tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testSSRF(endpoint, method, test));
    results.push(await this.testExternalEntityAccess(endpoint, method, test));
    results.push(await this.testWebhookSecurity(endpoint, method, test));
    results.push(await this.testOAuthFlowSecurity(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: SSRF (Server-Side Request Forgery)
   */
  async testSSRF(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('SSRF Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test with SSRF payloads
      for (const payload of SSRF_PAYLOADS.slice(0, 10)) {
        const body = { url: payload.url, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check for SSRF indicators
        if (response.status === 200 && (
          responseText.includes('127.0.0.1') ||
          responseText.includes('localhost') ||
          responseText.includes('169.254.169.254') // AWS metadata
        )) {
          securityIssues.push(`Potential SSRF vulnerability: ${payload.description}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: 10,
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
   * Test 2: External Entity Access
   */
  async testExternalEntityAccess(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('External Entity Access Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test external entity access
      const externalEntities = [
        'http://attacker.com',
        'http://malicious.com',
        'file:///etc/passwd',
      ];

      for (const entity of externalEntities) {
        const body = { url: entity, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        
        if (response.status === 200) {
          securityIssues.push(`External entity access possible: ${entity}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        entitiesTested: externalEntities.length,
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
   * Test 3: Webhook Security
   */
  async testWebhookSecurity(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Webhook Security Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test webhook without authentication
      const webhookBody = {
        url: 'http://attacker.com/webhook',
        events: ['all'],
      };

      const response = await this.makeRequest(url, method, headers, webhookBody);
      
      if (response.status === 200) {
        securityIssues.push('Webhook can be registered without authentication');
      }

      // Check for webhook signature validation
      const responseText = await response.text();
      if (!responseText.includes('signature') && !responseText.includes('secret')) {
        securityIssues.push('Webhook signature validation may be missing');
      }

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
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
   * Test 4: OAuth Flow Security
   */
  async testOAuthFlowSecurity(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('OAuth Flow Security Test', endpoint, method);
    const startTime = Date.now();

    try {
      const baseUrl = this.config.baseUrl;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test OAuth endpoints
      const oauthEndpoints = [
        '/oauth/authorize',
        '/oauth/token',
        '/oauth/callback',
      ];

      for (const oauthEndpoint of oauthEndpoints) {
        const url = `${baseUrl}${oauthEndpoint}`;
        const response = await this.makeRequest(url, method, headers);
        
        // Check for insecure OAuth implementation
        if (response.status === 200) {
          const responseText = await response.text();
          
          // Check for common OAuth vulnerabilities
          if (responseText.includes('redirect_uri') && !responseText.includes('validate')) {
            securityIssues.push(`OAuth redirect URI validation may be missing: ${oauthEndpoint}`);
          }
          
          if (responseText.includes('state') && !responseText.includes('csrf')) {
            securityIssues.push(`OAuth state parameter may not be validated: ${oauthEndpoint}`);
          }
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        endpointsTested: oauthEndpoints.length,
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

