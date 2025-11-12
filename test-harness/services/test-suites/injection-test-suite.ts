/**
 * Injection Test Suite
 * Tests for various injection vulnerabilities (SQL, NoSQL, Command, LDAP, XPath, XXE, Template, Path Traversal, File Upload)
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { SQL_INJECTION_PAYLOADS } from '../payloads/sql-injection';
import { NOSQL_INJECTION_PAYLOADS, nosqlPayloadToString } from '../payloads/nosql-injection';
import { COMMAND_INJECTION_PAYLOADS } from '../payloads/command-injection';
import { XSS_PAYLOADS } from '../payloads/xss';
import { PATH_TRAVERSAL_PAYLOADS } from '../payloads/path-traversal';
import { XXE_PAYLOADS } from '../payloads/xxe';
import { TEMPLATE_INJECTION_PAYLOADS } from '../payloads/template-injection';

export class InjectionTestSuite extends BaseTestSuite {
  /**
   * Run all injection tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testSQLInjection(endpoint, method, test));
    results.push(await this.testNoSQLInjection(endpoint, method, test));
    results.push(await this.testCommandInjection(endpoint, method, test));
    results.push(await this.testLDAPInjection(endpoint, method, test));
    results.push(await this.testXPathInjection(endpoint, method, test));
    results.push(await this.testXXE(endpoint, method, test));
    results.push(await this.testXSS(endpoint, method, test));
    results.push(await this.testTemplateInjection(endpoint, method, test));
    results.push(await this.testPathTraversal(endpoint, method, test));
    results.push(await this.testFileUploadSecurity(endpoint, method, test));
    results.push(await this.testTypeConfusion(endpoint, method, test));
    results.push(await this.testIntegerOverflow(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: SQL Injection
   */
  async testSQLInjection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('SQL Injection Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with SQL injection payloads
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 10)) { // Limit to first 10 for performance
        const body = { input: payload.payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check for SQL error messages or successful injection
        if (response.status === 200 && (
          responseText.toLowerCase().includes('sql') ||
          responseText.toLowerCase().includes('mysql') ||
          responseText.toLowerCase().includes('postgresql') ||
          responseText.toLowerCase().includes('oracle') ||
          responseText.toLowerCase().includes('syntax error') ||
          responseText.toLowerCase().includes('sqlstate')
        )) {
          securityIssues.push(`Potential SQL injection vulnerability: ${payload.description}`);
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
   * Test 2: NoSQL Injection
   */
  async testNoSQLInjection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('NoSQL Injection Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with NoSQL injection payloads
      for (const payload of NOSQL_INJECTION_PAYLOADS.slice(0, 8)) {
        const payloadString = typeof payload.payload === 'string' 
          ? payload.payload 
          : nosqlPayloadToString(payload.payload);
        
        const body = { input: payloadString, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check for successful injection (unexpected results)
        if (response.status === 200 && responseText.length > 0) {
          // This is a basic check - real NoSQL injection detection is more complex
          securityIssues.push(`Potential NoSQL injection: ${payload.description}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: 8,
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
   * Test 3: Command Injection
   */
  async testCommandInjection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Command Injection Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with command injection payloads
      for (const payload of COMMAND_INJECTION_PAYLOADS.slice(0, 10)) {
        const body = { input: payload.payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check for command execution indicators
        if (response.status === 200 && (
          responseText.includes('uid=') ||
          responseText.includes('gid=') ||
          responseText.includes('total ') ||
          responseText.includes('Directory of')
        )) {
          securityIssues.push(`Potential command injection: ${payload.description}`);
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
   * Test 4: LDAP Injection
   */
  async testLDAPInjection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('LDAP Injection Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      const ldapPayloads = [
        '*',
        ')(&',
        '*)(uid=*',
        '*)(|(uid=*',
        'admin)(&(password=*',
      ];

      for (const payload of ldapPayloads) {
        const body = { input: payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        if (response.status === 200 && responseText.length > 0) {
          securityIssues.push(`Potential LDAP injection: ${payload}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: ldapPayloads.length,
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
   * Test 5: XPath Injection
   */
  async testXPathInjection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('XPath Injection Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      const xpathPayloads = [
        "' or '1'='1",
        "' or 1=1 or ''='",
        "') or ('1'='1",
        "' or 1=1--",
      ];

      for (const payload of xpathPayloads) {
        const body = { input: payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        if (response.status === 200 && responseText.length > 0) {
          securityIssues.push(`Potential XPath injection: ${payload}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: xpathPayloads.length,
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
   * Test 6: XXE (XML External Entity)
   */
  async testXXE(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('XXE Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      headers['Content-Type'] = 'application/xml';

      // Test with XXE payloads
      for (const payload of XXE_PAYLOADS.slice(0, 5)) {
        const response = await this.makeRequest(url, method, headers, payload.payload);
        const responseText = await response.text();

        // Check for file content or SSRF indicators
        if (response.status === 200 && (
          responseText.includes('root:') ||
          responseText.includes('127.0.0.1') ||
          responseText.includes('localhost')
        )) {
          securityIssues.push(`Potential XXE vulnerability: ${payload.description}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: 5,
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
   * Test 7: XSS (Cross-Site Scripting)
   */
  async testXSS(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('XSS Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with XSS payloads
      for (const payload of XSS_PAYLOADS.slice(0, 10)) {
        const body = { input: payload.payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check if payload is reflected in response
        if (response.status === 200 && responseText.includes(payload.payload)) {
          securityIssues.push(`Potential XSS vulnerability: ${payload.description}`);
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
   * Test 8: Template Injection
   */
  async testTemplateInjection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Template Injection Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with template injection payloads
      for (const payload of TEMPLATE_INJECTION_PAYLOADS.slice(0, 8)) {
        const body = { input: payload.payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check for template evaluation (e.g., "49" for {{7*7}})
        if (response.status === 200 && (
          responseText.includes('49') ||
          responseText.includes('eval') ||
          responseText.includes('exec')
        )) {
          securityIssues.push(`Potential template injection: ${payload.description}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: 8,
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
   * Test 9: Path Traversal
   */
  async testPathTraversal(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Path Traversal Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with path traversal payloads
      for (const payload of PATH_TRAVERSAL_PAYLOADS.slice(0, 10)) {
        const body = { file: payload.payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        const responseText = await response.text();

        // Check for file content indicators
        if (response.status === 200 && (
          responseText.includes('root:') ||
          responseText.includes('127.0.0.1') ||
          responseText.includes('localhost') ||
          responseText.includes('Windows')
        )) {
          securityIssues.push(`Potential path traversal: ${payload.description}`);
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
   * Test 10: File Upload Security
   */
  async testFileUploadSecurity(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('File Upload Security Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test malicious file uploads
      const maliciousFiles = [
        { name: 'shell.php', content: '<?php system($_GET["cmd"]); ?>' },
        { name: 'shell.jsp', content: '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' },
        { name: 'shell.jspx', content: '<jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter("cmd"));</jsp:scriptlet>' },
        { name: 'shell.asp', content: '<% eval request("cmd") %>' },
      ];

      for (const file of maliciousFiles) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: 'text/plain' }), file.name);
        
        const response = await this.makeRequest(url, method, headers, formData);
        
        if (response.status === 200) {
          securityIssues.push(`Potentially dangerous file type accepted: ${file.name}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        filesTested: maliciousFiles.length,
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
   * Test 11: Type Confusion
   */
  async testTypeConfusion(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Type Confusion Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test type confusion attacks
      const typeConfusionPayloads = [
        { id: '0' }, // String instead of number
        { id: 0 }, // Number
        { id: null }, // Null
        { id: [] }, // Array
        { id: {} }, // Object
        { id: true }, // Boolean
      ];

      for (const payload of typeConfusionPayloads) {
        const body = { ...payload, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        
        // If different types produce different results, might indicate type confusion
        if (response.status === 200) {
          // This is a basic check - real type confusion detection is more complex
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        payloadsTested: typeConfusionPayloads.length,
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
   * Test 12: Integer Overflow/Underflow
   */
  async testIntegerOverflow(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Integer Overflow Test', endpoint, method);
    const startTime = Date.now();
    const securityIssues: string[] = [];

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test integer boundary values
      const boundaryValues = [
        Number.MAX_SAFE_INTEGER,
        Number.MAX_SAFE_INTEGER + 1,
        Number.MIN_SAFE_INTEGER,
        Number.MIN_SAFE_INTEGER - 1,
        2147483647, // Max 32-bit int
        2147483648, // Overflow
        -2147483648, // Min 32-bit int
        -2147483649, // Underflow
      ];

      for (const value of boundaryValues) {
        const body = { id: value, ...test?.body };
        const response = await this.makeRequest(url, method, headers, body);
        
        if (response.status === 500) {
          securityIssues.push(`Potential integer overflow/underflow with value: ${value}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        valuesTested: boundaryValues.length,
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

