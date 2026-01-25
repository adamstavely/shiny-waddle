/**
 * Logging Test Suite
 * Tests for audit logging, log injection, sensitive data in logs
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { detectPII } from '../utils/pii-detector';
import { detectCredentials } from '../utils/credential-detector';

export class LoggingTestSuite extends BaseTestSuite {
  /**
   * Run all logging tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testAuditLogging(endpoint, method, test));
    results.push(await this.testLogInjection(endpoint, method, test));
    results.push(await this.testSensitiveDataInLogs(endpoint, method, test));
    results.push(await this.testMonitoringCoverage(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: Audit Logging
   */
  async testAuditLogging(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Audit Logging Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());

      // Check for audit logging indicators
      const auditIndicators = [
        'X-Audit-Log',
        'X-Request-ID',
        'X-Correlation-ID',
        'X-Trace-ID',
      ];

      const hasAuditLogging = auditIndicators.some(indicator => 
        responseHeaders[indicator] || responseHeaders[indicator.toLowerCase()]
      );

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = hasAuditLogging;
      result.securityIssues = !hasAuditLogging ? ['Audit logging may not be implemented'] : undefined;
      result.details = {
        auditIndicators,
        hasAuditLogging,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: Log Injection
   */
  async testLogInjection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Log Injection Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      // Test log injection payloads
      const injectionPayloads = [
        '\n[CRITICAL] Security breach',
        '\r\n[ERROR] System compromised',
        '\x00[ALERT] Unauthorized access',
        'admin\n[INFO] Privilege escalation',
      ];

      for (const payload of injectionPayloads) {
        const body = { input: payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check if injection characters are reflected
        if (responseText.includes('\n[CRITICAL]') || 
            responseText.includes('\r\n[ERROR]') ||
            responseText.includes('[ALERT]')) {
          securityIssues.push(`Log injection possible: ${payload.substring(0, 20)}...`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: injectionPayloads.length,
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
   * Test 3: Sensitive Data in Logs
   */
  async testSensitiveDataInLogs(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Sensitive Data in Logs Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseText = await response.text();
      const responseJson = await response.json().catch(() => null);

      // Check for PII and credentials in response (which might be logged)
      const piiDetection = responseJson ? detectPII(JSON.stringify(responseJson)) : detectPII(responseText);
      const credentialDetection = responseJson ? detectCredentials(JSON.stringify(responseJson)) : detectCredentials(responseText);

      const securityIssues: string[] = [];

      if (piiDetection.detected && piiDetection.severity === 'critical') {
        securityIssues.push(`Critical PII detected in response (may be logged): ${piiDetection.piiTypes.join(', ')}`);
      }

      if (credentialDetection.detected && credentialDetection.severity === 'critical') {
        securityIssues.push(`Critical credentials detected in response (may be logged): ${credentialDetection.credentialTypes.join(', ')}`);
      }

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        piiDetected: piiDetection.detected,
        credentialsDetected: credentialDetection.detected,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 4: Monitoring Coverage
   */
  async testMonitoringCoverage(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Monitoring Coverage Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());

      // Check for monitoring indicators
      const monitoringIndicators = [
        'X-Request-ID',
        'X-Correlation-ID',
        'X-Trace-ID',
        'X-Response-Time',
      ];

      const hasMonitoring = monitoringIndicators.some(indicator => 
        responseHeaders[indicator] || responseHeaders[indicator.toLowerCase()]
      );

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = hasMonitoring;
      result.securityIssues = !hasMonitoring ? ['Monitoring may not be implemented'] : undefined;
      result.details = {
        monitoringIndicators,
        hasMonitoring,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }
}

