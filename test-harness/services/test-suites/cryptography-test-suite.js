"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptographyTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const jwt_validator_1 = require("../utils/jwt-validator");
class CryptographyTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testJWTValidation(endpoint, method, test));
        results.push(await this.testWeakEncryption(endpoint, method, test));
        results.push(await this.testInsecureRandom(endpoint, method, test));
        results.push(await this.testTokenStorage(endpoint, method, test));
        results.push(await this.testKeyRotation(endpoint, method, test));
        results.push(await this.testCertificateValidation(endpoint, method, test));
        return results;
    }
    async testJWTValidation(endpoint, method, test) {
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
            const jwtAnalysis = (0, jwt_validator_1.analyzeJWTSecurity)(token);
            const decoded = (0, jwt_validator_1.decodeJWT)(token);
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
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testWeakEncryption(endpoint, method, test) {
        const result = this.createBaseResult('Weak Encryption Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const securityIssues = [];
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
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testInsecureRandom(endpoint, method, test) {
        const result = this.createBaseResult('Insecure Random Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const tokens = [];
            for (let i = 0; i < 10; i++) {
                const response = await this.makeRequest(url, method, headers);
                const responseText = await response.text();
                const responseJson = await response.json().catch(() => null);
                const tokenPattern = /(token|id|session)[":\s]+([A-Za-z0-9]{10,})/gi;
                const matches = responseText.match(tokenPattern);
                if (matches) {
                    tokens.push(...matches);
                }
            }
            const securityIssues = [];
            if (tokens.length > 0) {
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
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testTokenStorage(endpoint, method, test) {
        const result = this.createBaseResult('Token Storage Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseText = await response.text();
            const responseJson = await response.json().catch(() => null);
            const securityIssues = [];
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
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testKeyRotation(endpoint, method, test) {
        const result = this.createBaseResult('Key Rotation Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseText = await response.text();
            const hasKeyRotation = responseText.includes('key-rotation') ||
                responseText.includes('keyRotation') ||
                response.headers.get('X-Key-Version');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = true;
            result.details = {
                keyRotationSupported: hasKeyRotation,
                message: 'Key rotation should be implemented for long-lived tokens',
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testCertificateValidation(endpoint, method, test) {
        const result = this.createBaseResult('Certificate Validation Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const usesHTTPS = url.startsWith('https://');
            if (!usesHTTPS) {
                result.passed = false;
                result.securityIssues = ['API endpoint does not use HTTPS'];
                result.details = { message: 'All API endpoints should use HTTPS' };
                return result;
            }
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = true;
            result.details = {
                usesHTTPS: true,
                message: 'Certificate validation appears to be working',
            };
        }
        catch (error) {
            if (error.message.includes('certificate') || error.message.includes('SSL')) {
                result.passed = false;
                result.securityIssues = ['SSL/TLS certificate validation issue'];
                result.details = { error: error.message };
            }
            else {
                result.passed = false;
                result.error = error.message;
                result.details = { error: error.message };
            }
        }
        return result;
    }
}
exports.CryptographyTestSuite = CryptographyTestSuite;
//# sourceMappingURL=cryptography-test-suite.js.map