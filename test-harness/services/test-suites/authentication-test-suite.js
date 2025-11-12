"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthenticationTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const jwt_validator_1 = require("../utils/jwt-validator");
class AuthenticationTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testMissingAuthentication(endpoint, method, test));
        results.push(await this.testInvalidToken(endpoint, method, test));
        results.push(await this.testTokenReplay(endpoint, method, test));
        results.push(await this.testTokenExpiration(endpoint, method, test));
        results.push(await this.testSessionFixation(endpoint, method, test));
        results.push(await this.testPasswordResetSecurity(endpoint, method, test));
        results.push(await this.testMultipleAuthMethods(endpoint, method, test));
        return results;
    }
    async testMissingAuthentication(endpoint, method, test) {
        const result = this.createBaseResult('Missing Authentication Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const response = await this.makeRequest(url, method, {});
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            if (response.status === 401) {
                result.passed = true;
                result.details = { message: 'Correctly rejects unauthenticated requests' };
            }
            else {
                result.passed = false;
                result.securityIssues = ['Endpoint accepts requests without authentication'];
                result.details = {
                    statusCode: response.status,
                    expected: 401,
                    message: 'Endpoint should require authentication',
                };
            }
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testInvalidToken(endpoint, method, test) {
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
            const responses = await Promise.all(invalidTokens.map(token => this.makeRequest(url, method, { Authorization: token })));
            result.responseTime = Date.now() - startTime;
            const allRejected = responses.every(r => r.status === 401);
            if (allRejected) {
                result.passed = true;
                result.details = { message: 'All invalid tokens correctly rejected' };
            }
            else {
                result.passed = false;
                result.securityIssues = ['Some invalid tokens were accepted'];
                result.details = {
                    responses: responses.map(r => ({ status: r.status })),
                    message: 'All invalid tokens should be rejected with 401',
                };
            }
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testTokenReplay(endpoint, method, test) {
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
            const response1 = await this.makeRequest(url, method, headers);
            result.statusCode = response1.status;
            result.responseTime = Date.now() - startTime;
            const response2 = await this.makeRequest(url, method, headers);
            if (response1.status === 200 && response2.status === 200) {
                result.passed = false;
                result.securityIssues = ['Token replay not detected (same token accepted multiple times)'];
                result.details = {
                    message: 'Token replay prevention should be implemented server-side',
                    note: 'This test verifies basic behavior; full replay prevention requires server-side token tracking',
                };
            }
            else {
                result.passed = true;
                result.details = { message: 'Token replay handling detected' };
            }
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testTokenExpiration(endpoint, method, test) {
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
            if (authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7);
                const decoded = (0, jwt_validator_1.decodeJWT)(token);
                if (decoded.malformed) {
                    result.passed = true;
                    result.details = { message: 'Token is not a JWT, expiration test not applicable' };
                    return result;
                }
                if (decoded.expired) {
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
                    }
                    else {
                        result.passed = false;
                        result.securityIssues = ['Expired token was accepted'];
                        result.authenticationResult = {
                            authenticated: true,
                            tokenValid: false,
                            tokenExpired: true,
                        };
                        result.details = { message: 'Expired token should be rejected with 401' };
                    }
                }
                else {
                    result.passed = true;
                    result.authenticationResult = {
                        authenticated: true,
                        tokenValid: true,
                        tokenExpired: false,
                    };
                    result.details = { message: 'Token is valid and not expired' };
                }
            }
            else {
                result.passed = true;
                result.details = { message: 'Token is not a Bearer token, expiration test not applicable' };
            }
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testSessionFixation(endpoint, method, test) {
        const result = this.createBaseResult('Session Fixation Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            const setCookie = response.headers.get('Set-Cookie');
            if (setCookie) {
                const response2 = await this.makeRequest(url, method, headers);
                const setCookie2 = response2.headers.get('Set-Cookie');
                if (setCookie === setCookie2) {
                    result.passed = false;
                    result.securityIssues = ['Session token does not change between requests (potential session fixation risk)'];
                    result.details = {
                        message: 'Session tokens should be regenerated to prevent session fixation',
                        note: 'This is a basic test; full session fixation prevention requires server-side implementation',
                    };
                }
                else {
                    result.passed = true;
                    result.details = { message: 'Session token changes between requests' };
                }
            }
            else {
                result.passed = true;
                result.details = { message: 'No session-based authentication detected, test not applicable' };
            }
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testPasswordResetSecurity(endpoint, method, test) {
        const result = this.createBaseResult('Password Reset Security Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            const body = await response.text();
            const jsonBody = await response.json().catch(() => null);
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
            }
            else {
                result.passed = true;
                result.details = { message: 'No password reset tokens detected in response' };
            }
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testMultipleAuthMethods(endpoint, method, test) {
        const result = this.createBaseResult('Multiple Auth Methods Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const securityIssues = [];
            const authMethods = [
                { name: 'Bearer', header: 'Bearer test-token' },
                { name: 'Basic', header: 'Basic ' + Buffer.from('user:pass').toString('base64') },
                { name: 'API Key', header: 'X-API-Key: test-key' },
            ];
            for (const authMethod of authMethods) {
                const headers = {};
                if (authMethod.name === 'Bearer' || authMethod.name === 'Basic') {
                    headers['Authorization'] = authMethod.header;
                }
                else {
                    headers['X-API-Key'] = authMethod.header.split(': ')[1];
                }
                const response = await this.makeRequest(url, method, headers);
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
            }
            else {
                result.passed = true;
                result.details = { message: 'Authentication methods properly validated' };
            }
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
}
exports.AuthenticationTestSuite = AuthenticationTestSuite;
//# sourceMappingURL=authentication-test-suite.js.map