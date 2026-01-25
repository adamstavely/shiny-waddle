/**
 * Authorization Test Suite
 * Tests for authorization and access control vulnerabilities
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';

export class AuthorizationTestSuite extends BaseTestSuite {
  /**
   * Run all authorization tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testHorizontalPrivilegeEscalation(endpoint, method, test));
    results.push(await this.testVerticalPrivilegeEscalation(endpoint, method, test));
    results.push(await this.testBOLA(endpoint, method, test));
    results.push(await this.testMassAssignment(endpoint, method, test));
    results.push(await this.testFunctionLevelAuthorization(endpoint, method, test));
    results.push(await this.testRBAC(endpoint, method, test));
    results.push(await this.testABAC(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: Horizontal Privilege Escalation
   * Test if user can access another user's resources
   */
  async testHorizontalPrivilegeEscalation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Horizontal Privilege Escalation Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Try to access another user's resource by changing ID
      const maliciousBodies = [
        { userId: '999999', ...test?.body },
        { id: '999999', ...test?.body },
        { user_id: '999999', ...test?.body },
      ];

      for (const body of maliciousBodies) {
        const response = await this.makeRequest(url, method, headers, body);
        
        if (response.status === 200) {
          result.passed = false;
          result.securityIssues = ['Horizontal privilege escalation: User can access other users\' resources'];
          result.details = { message: 'Endpoint should restrict access to user\'s own resources' };
          break;
        }
      }

      if (!result.securityIssues) {
        result.passed = true;
        result.details = { message: 'Horizontal privilege escalation protection appears to be in place' };
      }

      result.responseTime = Date.now() - startTime;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: Vertical Privilege Escalation
   * Test if regular user can access admin endpoints
   */
  async testVerticalPrivilegeEscalation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Vertical Privilege Escalation Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Try to escalate privileges by modifying role
      const maliciousBodies = [
        { role: 'admin', ...test?.body },
        { role: 'administrator', ...test?.body },
        { isAdmin: true, ...test?.body },
        { admin: true, ...test?.body },
      ];

      for (const body of maliciousBodies) {
        const response = await this.makeRequest(url, method, headers, body);
        
        if (response.status === 200) {
          const responseText = await response.text();
          if (responseText.includes('admin') || responseText.includes('privilege')) {
            result.passed = false;
            result.securityIssues = ['Vertical privilege escalation: User can escalate to admin role'];
            result.details = { message: 'Endpoint should prevent role modification' };
            break;
          }
        }
      }

      if (!result.securityIssues) {
        result.passed = true;
        result.details = { message: 'Vertical privilege escalation protection appears to be in place' };
      }

      result.responseTime = Date.now() - startTime;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 3: BOLA (Broken Object Level Authorization)
   * Test IDOR vulnerabilities
   */
  async testBOLA(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('BOLA Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Try to access objects by ID manipulation
      const testIds = ['1', '2', '999', '0', '-1', '../1'];
      
      for (const id of testIds) {
        const testUrl = url.replace(/\d+/, id).replace(/\/[^\/]+$/, `/${id}`);
        const response = await this.makeRequest(testUrl, method, headers);
        
        if (response.status === 200) {
          result.passed = false;
          result.securityIssues = [`BOLA vulnerability: Can access object with ID ${id}`];
          result.details = { message: 'Endpoint should verify user has permission to access object' };
          break;
        }
      }

      if (!result.securityIssues) {
        result.passed = true;
        result.details = { message: 'BOLA protection appears to be in place' };
      }

      result.responseTime = Date.now() - startTime;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 4: Mass Assignment
   * Test if unauthorized fields can be updated
   */
  async testMassAssignment(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Mass Assignment Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Try to set unauthorized fields
      const unauthorizedFields = {
        isAdmin: true,
        role: 'admin',
        balance: 999999,
        permissions: ['all'],
        email: 'admin@example.com',
      };

      const body = { ...unauthorizedFields, ...test?.body };
      const response = await this.makeRequest(url, method, headers, body);
      const responseText = await response.text();

      if (response.status === 200) {
        // Check if unauthorized fields were accepted
        const fieldsAccepted = Object.keys(unauthorizedFields).some(field => 
          responseText.includes(field)
        );

        if (fieldsAccepted) {
          result.passed = false;
          result.securityIssues = ['Mass assignment: Unauthorized fields can be set'];
          result.details = { message: 'Endpoint should whitelist allowed fields' };
        } else {
          result.passed = true;
          result.details = { message: 'Mass assignment protection appears to be in place' };
        }
      } else {
        result.passed = true;
        result.details = { message: 'Unauthorized field modification rejected' };
      }

      result.responseTime = Date.now() - startTime;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 5: Function Level Authorization
   * Test if user can access admin functions
   */
  async testFunctionLevelAuthorization(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Function Level Authorization Test', endpoint, method);
    const startTime = Date.now();

    try {
      // Test admin endpoints
      const adminEndpoints = [
        '/admin',
        '/admin/users',
        '/admin/settings',
        '/api/admin',
        '/api/v1/admin',
      ];

      const headers = this.buildHeaders(test);
      const securityIssues: string[] = [];

      for (const adminEndpoint of adminEndpoints) {
        const url = `${this.config.baseUrl}${adminEndpoint}`;
        const response = await this.makeRequest(url, method, headers);
        
        if (response.status === 200) {
          securityIssues.push(`Function level authorization bypass: Can access ${adminEndpoint}`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        endpointsTested: adminEndpoints.length,
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
   * Test 6: RBAC (Role-Based Access Control)
   * Test role-based permissions
   */
  async testRBAC(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('RBAC Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test with different role claims in token/headers
      const roles = ['user', 'admin', 'moderator', 'guest'];
      const securityIssues: string[] = [];

      for (const role of roles) {
        const testHeaders = { ...headers, 'X-Role': role };
        const response = await this.makeRequest(url, method, testHeaders);
        
        // If role can be set via header, that's a security issue
        if (response.status === 200 && role !== 'user') {
          securityIssues.push(`RBAC bypass: Role can be set via header (${role})`);
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        rolesTested: roles.length,
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
   * Test 7: ABAC (Attribute-Based Access Control)
   * Test attribute-based permissions
   */
  async testABAC(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('ABAC Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Test attribute manipulation
      const attributes = {
        department: 'IT',
        clearance: 'top-secret',
        location: 'HQ',
      };

      const body = { ...attributes, ...test?.body };
      const response = await this.makeRequest(url, method, headers, body);
      const responseText = await response.text();

      // Check if attributes can be manipulated
      if (response.status === 200) {
        const attributesAccepted = Object.keys(attributes).some(attr => 
          responseText.includes(attr)
        );

        if (attributesAccepted) {
          result.passed = false;
          result.securityIssues = ['ABAC bypass: Attributes can be manipulated'];
          result.details = { message: 'Endpoint should validate attributes from trusted source' };
        } else {
          result.passed = true;
          result.details = { message: 'ABAC protection appears to be in place' };
        }
      } else {
        result.passed = true;
        result.details = { message: 'Attribute manipulation rejected' };
      }

      result.responseTime = Date.now() - startTime;
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }
}

