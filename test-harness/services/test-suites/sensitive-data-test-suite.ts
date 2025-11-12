/**
 * Sensitive Data Test Suite
 * Tests for PII exposure, credential leakage, error disclosure, etc.
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { detectPII, detectPIIInJSON } from '../utils/pii-detector';
import { detectCredentials, detectCredentialsInJSON } from '../utils/credential-detector';

export class SensitiveDataTestSuite extends BaseTestSuite {
  /**
   * Run all sensitive data tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testPIIExposure(endpoint, method, test));
    results.push(await this.testCredentialExposure(endpoint, method, test));
    results.push(await this.testErrorInformationDisclosure(endpoint, method, test));
    results.push(await this.testStackTraceExposure(endpoint, method, test));
    results.push(await this.testDebugEndpoints(endpoint, method, test));
    results.push(await this.testBackupFiles(endpoint, method, test));
    results.push(await this.testAPIVersioning(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: PII Exposure
   */
  async testPIIExposure(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('PII Exposure Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseText = await response.text();
      const responseJson = await response.json().catch(() => null);

      const piiDetection = responseJson ? detectPIIInJSON(responseJson) : detectPII(responseText);

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = !piiDetection.detected;
      result.securityIssues = piiDetection.detected ? [`PII detected: ${piiDetection.piiTypes.join(', ')}`] : undefined;
      result.details = {
        piiTypes: piiDetection.piiTypes,
        matches: piiDetection.matches.slice(0, 5), // Limit to first 5
        severity: piiDetection.severity,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: Credential Exposure
   */
  async testCredentialExposure(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Credential Exposure Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseText = await response.text();
      const responseJson = await response.json().catch(() => null);

      const credentialDetection = responseJson ? detectCredentialsInJSON(responseJson) : detectCredentials(responseText);

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = !credentialDetection.detected;
      result.securityIssues = credentialDetection.detected ? [`Credentials detected: ${credentialDetection.credentialTypes.join(', ')}`] : undefined;
      result.details = {
        credentialTypes: credentialDetection.credentialTypes,
        matches: credentialDetection.matches.slice(0, 5), // Limit to first 5
        severity: credentialDetection.severity,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 3: Error Information Disclosure
   */
  async testErrorInformationDisclosure(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Error Information Disclosure Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Trigger error with invalid input
      const invalidBodies = [
        { id: null },
        { id: 'invalid' },
        { id: -1 },
      ];

      const securityIssues: string[] = [];

      for (const body of invalidBodies) {
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check for sensitive information in errors
        const sensitivePatterns = [
          /sql/i,
          /database/i,
          /connection string/i,
          /file path/i,
          /stack trace/i,
          /exception/i,
          /error at/i,
        ];

        for (const pattern of sensitivePatterns) {
          if (pattern.test(responseText)) {
            securityIssues.push(`Error message contains sensitive information: ${pattern.source}`);
            break;
          }
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        errorsTested: invalidBodies.length,
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
   * Test 4: Stack Trace Exposure
   */
  async testStackTraceExposure(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Stack Trace Exposure Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Trigger error
      const body = { invalid: 'data' };
      const response = await this.makeRequest(url, method, headers, body);
      const responseText = await response.text();

      // Check for stack trace indicators
      const stackTracePatterns = [
        /at\s+\w+\.\w+/,
        /stack trace/i,
        /traceback/i,
        /\.java:\d+/,
        /\.py:\d+/,
        /\.js:\d+/,
        /line \d+/,
      ];

      const hasStackTrace = stackTracePatterns.some(pattern => pattern.test(responseText));

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = !hasStackTrace;
      result.securityIssues = hasStackTrace ? ['Stack trace exposed in response'] : undefined;
      result.details = {
        stackTraceDetected: hasStackTrace,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 5: Debug Endpoints
   */
  async testDebugEndpoints(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Debug Endpoints Test', endpoint, method);
    const startTime = Date.now();

    try {
      const baseUrl = this.config.baseUrl;
      const headers = this.buildHeaders(test);
      const debugEndpoints = [
        '/debug',
        '/debug/',
        '/api/debug',
        '/_debug',
        '/.env',
        '/.git/config',
        '/phpinfo.php',
        '/test',
        '/testing',
      ];

      const securityIssues: string[] = [];

      for (const debugEndpoint of debugEndpoints) {
        const url = `${baseUrl}${debugEndpoint}`;
        const response = await this.makeRequest(url, method, headers);
        
        if (response.status === 200) {
          securityIssues.push(`Debug endpoint accessible: ${debugEndpoint}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        endpointsTested: debugEndpoints.length,
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
   * Test 6: Backup Files
   */
  async testBackupFiles(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Backup Files Test', endpoint, method);
    const startTime = Date.now();

    try {
      const baseUrl = this.config.baseUrl;
      const headers = this.buildHeaders(test);
      const backupFiles = [
        '/.env.backup',
        '/config.json.bak',
        '/database.sql.bak',
        '/backup.sql',
        '/.git/config',
        '/.htaccess.bak',
      ];

      const securityIssues: string[] = [];

      for (const backupFile of backupFiles) {
        const url = `${baseUrl}${backupFile}`;
        const response = await this.makeRequest(url, method, headers);
        
        if (response.status === 200) {
          securityIssues.push(`Backup file accessible: ${backupFile}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        filesTested: backupFiles.length,
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
   * Test 7: API Versioning
   */
  async testAPIVersioning(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('API Versioning Test', endpoint, method);
    const startTime = Date.now();

    try {
      const baseUrl = this.config.baseUrl;
      const headers = this.buildHeaders(test);
      const deprecatedVersions = [
        '/v1/',
        '/v0/',
        '/api/v1/',
        '/api/v0/',
      ];

      const securityIssues: string[] = [];

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

