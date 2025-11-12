"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseTestSuite = void 0;
class BaseTestSuite {
    constructor(config) {
        this.config = config;
    }
    buildHeaders(test) {
        const headers = {
            ...this.config.headers,
            ...test?.headers,
        };
        if (this.config.authentication) {
            const authHeader = this.getAuthHeader(this.config.authentication, test?.user);
            if (authHeader) {
                headers['Authorization'] = authHeader;
            }
        }
        return headers;
    }
    getAuthHeader(auth, user) {
        if (!auth)
            return '';
        switch (auth.type) {
            case 'bearer':
                return `Bearer ${auth.credentials.token}`;
            case 'basic':
                const credentials = Buffer.from(`${auth.credentials.username}:${auth.credentials.password}`).toString('base64');
                return `Basic ${credentials}`;
            case 'api-key':
                return auth.credentials.apiKey || '';
            case 'oauth2':
                return `Bearer ${auth.credentials.accessToken}`;
            case 'jwt':
                return `Bearer ${auth.credentials.jwt}`;
            default:
                return '';
        }
    }
    async makeRequest(url, method, headers, body) {
        const options = {
            method,
            headers,
        };
        if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
            options.body = typeof body === 'string' ? body : JSON.stringify(body);
            if (!headers['Content-Type']) {
                headers['Content-Type'] = 'application/json';
            }
        }
        const timeout = this.config.timeout || 10000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        try {
            const response = await fetch(url, { ...options, signal: controller.signal });
            clearTimeout(timeoutId);
            return response;
        }
        catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error(`Request timeout after ${timeout}ms`);
            }
            throw error;
        }
    }
    createBaseResult(testName, endpoint, method) {
        return {
            testName,
            endpoint,
            method,
            testType: 'api-security',
            passed: false,
            timestamp: new Date(),
            details: {},
        };
    }
    evaluateResult(result, expectedStatus, expectedAuthRequired) {
        if (expectedStatus && result.statusCode !== expectedStatus) {
            return false;
        }
        if (expectedAuthRequired &&
            result.authenticationResult &&
            !result.authenticationResult.authenticated) {
            return false;
        }
        if (result.securityIssues && result.securityIssues.length > 0) {
            return false;
        }
        return true;
    }
}
exports.BaseTestSuite = BaseTestSuite;
//# sourceMappingURL=base-test-suite.js.map