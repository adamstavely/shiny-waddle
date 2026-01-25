/**
 * Authentication Test Suite
 * Tests for authentication security including token validation, expiration, replay, etc.
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { decodeJWT, isJWTExpired, isJWTMalformed, hasWeakAlgorithm } from '../utils/jwt-validator';

export class AuthenticationTestSuite extends BaseTestSuite {
  /**
   * Run all authentication tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testMissingAuthentication(endpoint, method, test));
    results.push(await this.testInvalidToken(endpoint, method, test));
    results.push(await this.testTokenReplay(endpoint, method, test));
    results.push(await this.testTokenExpiration(endpoint, method, test));
    results.push(await this.testSessionFixation(endpoint, method, test));
    results.push(await this.testPasswordResetSecurity(endpoint, method, test));
    results.push(await this.testMultipleAuthMethods(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: Missing Authentication
   * Verify that requests without authentication are rejected
   */
  async testMissingAuthentication(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Missing Authentication Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const response = await this.makeRequest(url, method, {});

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;

      // Should return 401 Unauthorized
      if (response.status === 401) {
        result.passed = true;
        result.details = { message: 'Correctly rejects unauthenticated requests' };
      } else {
        result.passed = false;
        result.securityIssues = ['Endpoint accepts requests without authentication'];
        result.details = {
          statusCode: response.status,
          expected: 401,
          message: 'Endpoint should require authentication',
        };
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: Invalid Token
   * Verify that requests with invalid tokens are rejected
   */
  async testInvalidToken(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Invalid Token Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const invalidTokens = [
        'Bearer invalid-token-12345',
        'Bearer expired-token',
        'Bearer malformed.token.here',
        'Bearer ',
      ];

      const responses = await Promise.all(
        invalidTokens.map(token =>
          this.makeRequest(url, method, { Authorization: token })
        )
      );

      result.responseTime = Date.now() - startTime;
      const allRejected = responses.every(r => r.status === 401);

      if (allRejected) {
        result.passed = true;
        result.details = { message: 'All invalid tokens correctly rejected' };
      } else {
        result.passed = false;
        result.securityIssues = ['Some invalid tokens were accepted'];
        result.details = {
          responses: responses.map(r => ({ status: r.status })),
          message: 'All invalid tokens should be rejected with 401',
        };
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 3: Token Replay
   * Verify that token replay is detected and prevented
   */
  async testTokenReplay(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Token Replay Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      if (!headers['Authorization']) {
        result.passed = false;
        result.error = 'No authentication configured';
        return result;
      }

      // Make first request
      const response1 = await this.makeRequest(url, method, headers);
      result.statusCode = response1.status;
      result.responseTime = Date.now() - startTime;

      // Make second request with same token (replay)
      const response2 = await this.makeRequest(url, method, headers);

      // If both succeed, token replay is not prevented
      // Note: This is a basic test - real token replay prevention requires server-side tracking
      if (response1.status === 200 && response2.status === 200) {
        result.passed = false;
        result.securityIssues = ['Token replay not detected (same token accepted multiple times)'];
        result.details = {
          message: 'Token replay prevention should be implemented server-side',
          note: 'This test verifies basic behavior; full replay prevention requires server-side token tracking',
        };
      } else {
        result.passed = true;
        result.details = { message: 'Token replay handling detected' };
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 4: Token Expiration
   * Verify that expired tokens are rejected
   */
  async testTokenExpiration(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Token Expiration Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      if (!headers['Authorization']) {
        result.passed = false;
        result.error = 'No authentication configured';
        return result;
      }

      const authHeader = headers['Authorization'];
      
      // Check if it's a JWT token
      if (authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        
        // Try to decode JWT
        const decoded = decodeJWT(token);
        
        if (decoded.malformed) {
          // Not a JWT, can't test expiration
          result.passed = true;
          result.details = { message: 'Token is not a JWT, expiration test not applicable' };
          return result;
        }

        if (decoded.expired) {
          // Token is expired, test if it's rejected
          const response = await this.makeRequest(url, method, headers);
          result.statusCode = response.status;
          result.responseTime = Date.now() - startTime;

          if (response.status === 401) {
            result.passed = true;
            result.authenticationResult = {
              authenticated: false,
              tokenValid: false,
              tokenExpired: true,
            };
            result.details = { message: 'Expired token correctly rejected' };
          } else {
            result.passed = false;
            result.securityIssues = ['Expired token was accepted'];
            result.authenticationResult = {
              authenticated: true,
              tokenValid: false,
              tokenExpired: true,
            };
            result.details = { message: 'Expired token should be rejected with 401' };
          }
        } else {
          // Token not expired, test passes
          result.passed = true;
          result.authenticationResult = {
            authenticated: true,
            tokenValid: true,
            tokenExpired: false,
          };
          result.details = { message: 'Token is valid and not expired' };
        }
      } else {
        // Not a Bearer token, can't test expiration
        result.passed = true;
        result.details = { message: 'Token is not a Bearer token, expiration test not applicable' };
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 5: Session Fixation
   * Verify that session tokens are regenerated after authentication
   */
  async testSessionFixation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Session Fixation Test', endpoint, method);
    const startTime = Date.now();

    try {
      // This test requires session-based authentication
      // For token-based auth, this test may not be applicable
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Make request and capture session cookie if present
      const response = await this.makeRequest(url, method, headers);
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;

      const setCookie = response.headers.get('Set-Cookie');
      
      if (setCookie) {
        // Session-based auth detected
        // Check if session token changes on each request (basic check)
        const response2 = await this.makeRequest(url, method, headers);
        const setCookie2 = response2.headers.get('Set-Cookie');

        if (setCookie === setCookie2) {
          result.passed = false;
          result.securityIssues = ['Session token does not change between requests (potential session fixation risk)'];
          result.details = {
            message: 'Session tokens should be regenerated to prevent session fixation',
            note: 'This is a basic test; full session fixation prevention requires server-side implementation',
          };
        } else {
          result.passed = true;
          result.details = { message: 'Session token changes between requests' };
        }
      } else {
        // No session-based auth, test not applicable
        result.passed = true;
        result.details = { message: 'No session-based authentication detected, test not applicable' };
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 6: Password Reset Security
   * Verify that password reset tokens are secure
   */
  async testPasswordResetSecurity(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Password Reset Security Test', endpoint, method);
    const startTime = Date.now();

    try {
      // This test requires a password reset endpoint
      // For general endpoints, we check if reset tokens are exposed
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      const response = await this.makeRequest(url, method, headers);
      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;

      const body = await response.text();
      const jsonBody = await response.json().catch(() => null);

      // Check for password reset tokens in response
      const resetTokenPatterns = [
        /reset[_-]?token/i,
        /password[_-]?reset[_-]?token/i,
        /reset[_-]?code/i,
        /password[_-]?reset[_-]?code/i,
      ];

      const foundTokens = resetTokenPatterns.some(pattern => pattern.test(body));

      if (foundTokens) {
        result.passed = false;
        result.securityIssues = ['Password reset tokens may be exposed in response'];
        result.details = {
          message: 'Password reset tokens should not be exposed in API responses',
          recommendation: 'Use secure, time-limited tokens and send via secure channels (email, SMS)',
        };
      } else {
        result.passed = true;
        result.details = { message: 'No password reset tokens detected in response' };
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 7: Multiple Auth Methods
   * Verify that multiple authentication methods are properly validated
   */
  async testMultipleAuthMethods(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Multiple Auth Methods Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const securityIssues: string[] = [];

      // Test different auth methods
      const authMethods = [
        { name: 'Bearer', header: 'Bearer test-token' },
        { name: 'Basic', header: 'Basic ' + Buffer.from('user:pass').toString('base64') },
        { name: 'API Key', header: 'X-API-Key: test-key' },
      ];

      for (const authMethod of authMethods) {
        const headers: Record<string, string> = {};
        if (authMethod.name === 'Bearer' || authMethod.name === 'Basic') {
          headers['Authorization'] = authMethod.header;
        } else {
          headers['X-API-Key'] = authMethod.header.split(': ')[1];
        }

        const response = await this.makeRequest(url, method, headers);
        
        // If invalid auth method is accepted, that's a security issue
        if (response.status === 200 && authMethod.name !== this.config.authentication?.type) {
          securityIssues.push(`Invalid auth method ${authMethod.name} was accepted`);
        }
      }

      result.responseTime = Date.now() - startTime;

      if (securityIssues.length > 0) {
        result.passed = false;
        result.securityIssues = securityIssues;
        result.details = {
          message: 'Multiple authentication methods validation failed',
          issues: securityIssues,
        };
      } else {
        result.passed = true;
        result.details = { message: 'Authentication methods properly validated' };
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }
}

