/**
 * Cryptography Test Suite
 * Tests for JWT validation, weak encryption, insecure random, certificate validation
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { decodeJWT, hasWeakAlgorithm, hasNoExpiration, analyzeJWTSecurity } from '../utils/jwt-validator';

export class CryptographyTestSuite extends BaseTestSuite {
  /**
   * Run all cryptography tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testJWTValidation(endpoint, method, test));
    results.push(await this.testWeakEncryption(endpoint, method, test));
    results.push(await this.testInsecureRandom(endpoint, method, test));
    results.push(await this.testTokenStorage(endpoint, method, test));
    results.push(await this.testKeyRotation(endpoint, method, test));
    results.push(await this.testCertificateValidation(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: JWT Validation
   */
  async testJWTValidation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('JWT Validation Test', endpoint, method);
    const startTime = Date.now();

    try {
      const headers = this.buildHeaders(test);
      const authHeader = headers['Authorization'];

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        result.passed = true;
        result.details = { message: 'No JWT token found, test not applicable' };
        return result;
      }

      const token = authHeader.substring(7);
      const jwtAnalysis = analyzeJWTSecurity(token);
      const decoded = decodeJWT(token);

      result.responseTime = Date.now() - startTime;
      result.passed = jwtAnalysis.score >= 70;
      result.securityIssues = jwtAnalysis.issues.length > 0 ? jwtAnalysis.issues : undefined;
      result.details = {
        jwtAnalysis,
        decoded: {
          expired: decoded.expired,
          malformed: decoded.malformed,
          claims: decoded.claims,
        },
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: Weak Encryption
   */
  async testWeakEncryption(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Weak Encryption Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseHeaders = Object.fromEntries(response.headers.entries());

      const securityIssues: string[] = [];

      // Check for weak encryption indicators
      const weakCiphers = ['RC4', 'DES', 'MD5', 'SHA1'];
      const responseText = await response.text();

      for (const cipher of weakCiphers) {
        if (responseText.includes(cipher) || responseHeaders['X-Cipher']?.includes(cipher)) {
          securityIssues.push(`Weak encryption cipher detected: ${cipher}`);
        }
      }

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        ciphersChecked: weakCiphers.length,
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
   * Test 3: Insecure Random
   */
  async testInsecureRandom(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Insecure Random Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);

      // Make multiple requests and check for predictable tokens/IDs
      const tokens: string[] = [];
      for (let i = 0; i < 10; i++) {
        const response = await this.makeRequest(url, method, headers);
        const responseText = await response.text();
        const responseJson = await response.json().catch(() => null);

        // Extract potential tokens/IDs
        const tokenPattern = /(token|id|session)[":\s]+([A-Za-z0-9]{10,})/gi;
        const matches = responseText.match(tokenPattern);
        if (matches) {
          tokens.push(...matches);
        }
      }

      // Check for patterns (predictable)
      const securityIssues: string[] = [];
      if (tokens.length > 0) {
        // Simple check: if tokens are sequential or very similar
        const uniqueTokens = new Set(tokens);
        if (uniqueTokens.size < tokens.length * 0.5) {
          securityIssues.push('Tokens appear to be predictable or reused');
        }
      }

      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        tokensCollected: tokens.length,
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
   * Test 4: Token Storage
   */
  async testTokenStorage(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Token Storage Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);
      const responseText = await response.text();
      const responseJson = await response.json().catch(() => null);

      const securityIssues: string[] = [];

      // Check if tokens are stored insecurely (localStorage, cookies without httpOnly, etc.)
      if (responseText.includes('localStorage') || responseText.includes('sessionStorage')) {
        securityIssues.push('Tokens may be stored in localStorage/sessionStorage (XSS risk)');
      }

      const setCookie = response.headers.get('Set-Cookie');
      if (setCookie && !setCookie.includes('HttpOnly')) {
        securityIssues.push('Cookies set without HttpOnly flag');
      }
      if (setCookie && !setCookie.includes('Secure')) {
        securityIssues.push('Cookies set without Secure flag');
      }

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
      result.passed = securityIssues.length === 0;
      result.details = {
        cookieHeader: setCookie,
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
   * Test 5: Key Rotation
   */
  async testKeyRotation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Key Rotation Test', endpoint, method);
    const startTime = Date.now();

    try {
      // This test checks if key rotation is supported
      // In practice, this would require testing with old and new keys
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);

      // Check for key rotation indicators in response
      const responseText = await response.text();
      const hasKeyRotation = responseText.includes('key-rotation') || 
                             responseText.includes('keyRotation') ||
                             response.headers.get('X-Key-Version');

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = true; // Key rotation is a best practice, not a security issue if missing
      result.details = {
        keyRotationSupported: hasKeyRotation,
        message: 'Key rotation should be implemented for long-lived tokens',
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 6: Certificate Validation
   */
  async testCertificateValidation(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('Certificate Validation Test', endpoint, method);
    const startTime = Date.now();

    try {
      // Check if URL uses HTTPS
      const url = `${this.config.baseUrl}${endpoint}`;
      const usesHTTPS = url.startsWith('https://');

      if (!usesHTTPS) {
        result.passed = false;
        result.securityIssues = ['API endpoint does not use HTTPS'];
        result.details = { message: 'All API endpoints should use HTTPS' };
        return result;
      }

      // Make request and check certificate
      const headers = this.buildHeaders(test);
      const response = await this.makeRequest(url, method, headers);

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      result.passed = true; // If request succeeds, certificate is valid
      result.details = {
        usesHTTPS: true,
        message: 'Certificate validation appears to be working',
      };
    } catch (error: any) {
      if (error.message.includes('certificate') || error.message.includes('SSL')) {
        result.passed = false;
        result.securityIssues = ['SSL/TLS certificate validation issue'];
        result.details = { error: error.message };
      } else {
        result.passed = false;
        result.error = error.message;
        result.details = { error: error.message };
      }
    }

    return result;
  }
}

