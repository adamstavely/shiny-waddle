"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.APIDesignTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
class APIDesignTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testHTTPMethodValidation(endpoint, method, test));
        results.push(await this.testContentTypeValidation(endpoint, method, test));
        results.push(await this.testEndpointEnumeration(endpoint, method, test));
        results.push(await this.testVerboseErrors(endpoint, method, test));
        results.push(await this.testMissingSecurityControls(endpoint, method, test));
        results.push(await this.testAPIVersioningSecurity(endpoint, method, test));
        return results;
    }
    async testHTTPMethodValidation(endpoint, method, test) {
        const result = this.createBaseResult('HTTP Method Validation Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'];
            for (const testMethod of methods) {
                const response = await this.makeRequest(url, testMethod, headers);
                if (response.status === 200 && testMethod !== method) {
                    securityIssues.push(`Unexpected HTTP method accepted: ${testMethod}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                methodsTested: methods.length,
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
    async testContentTypeValidation(endpoint, method, test) {
        const result = this.createBaseResult('Content-Type Validation Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const invalidContentTypes = [
                'text/html',
                'application/xml',
                'text/plain',
                'multipart/form-data',
            ];
            for (const contentType of invalidContentTypes) {
                const testHeaders = { ...headers, 'Content-Type': contentType };
                const body = test?.body || { test: 'data' };
                const response = await this.makeRequest(url, method, testHeaders, body);
                if (response.status === 200 && contentType !== 'application/json') {
                    securityIssues.push(`Invalid Content-Type accepted: ${contentType}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                contentTypesTested: invalidContentTypes.length,
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
    async testEndpointEnumeration(endpoint, method, test) {
        const result = this.createBaseResult('Endpoint Enumeration Test', endpoint, method);
        const startTime = Date.now();
        try {
            const baseUrl = this.config.baseUrl;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const commonEndpoints = [
                '/admin',
                '/api/admin',
                '/api/v1/admin',
                '/admin/users',
                '/api/users',
                '/api/v1/users',
                '/config',
                '/settings',
                '/debug',
                '/test',
            ];
            for (const testEndpoint of commonEndpoints) {
                const url = `${baseUrl}${testEndpoint}`;
                const response = await this.makeRequest(url, method, headers);
                if (response.status === 200) {
                    securityIssues.push(`Endpoint accessible: ${testEndpoint}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                endpointsTested: commonEndpoints.length,
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
    async testVerboseErrors(endpoint, method, test) {
        const result = this.createBaseResult('Verbose Errors Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const errorTriggers = [
                { invalid: 'data' },
                { id: null },
                { id: 'invalid' },
            ];
            const securityIssues = [];
            for (const trigger of errorTriggers) {
                const response = await this.makeRequest(url, method, headers, trigger);
                const responseText = await response.text();
                const verbosePatterns = [
                    /stack trace/i,
                    /file path/i,
                    /database/i,
                    /sql/i,
                    /exception/i,
                    /error at/i,
                ];
                for (const pattern of verbosePatterns) {
                    if (pattern.test(responseText)) {
                        securityIssues.push(`Verbose error message detected: ${pattern.source}`);
                        break;
                    }
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                errorsTested: errorTriggers.length,
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
    async testMissingSecurityControls(endpoint, method, test) {
        const result = this.createBaseResult('Missing Security Controls Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const missingControls = [];
            if (!responseHeaders['strict-transport-security']) {
                missingControls.push('Missing HSTS header');
            }
            if (!responseHeaders['x-content-type-options']) {
                missingControls.push('Missing X-Content-Type-Options header');
            }
            if (!responseHeaders['x-frame-options']) {
                missingControls.push('Missing X-Frame-Options header');
            }
            if (!responseHeaders['content-security-policy']) {
                missingControls.push('Missing CSP header');
            }
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = missingControls.length > 0 ? missingControls : undefined;
            result.passed = missingControls.length === 0;
            result.details = {
                missingControls,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testAPIVersioningSecurity(endpoint, method, test) {
        const result = this.createBaseResult('API Versioning Security Test', endpoint, method);
        const startTime = Date.now();
        try {
            const baseUrl = this.config.baseUrl;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const deprecatedVersions = ['/v1/', '/v0/', '/api/v1/', '/api/v0/'];
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
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
}
exports.APIDesignTestSuite = APIDesignTestSuite;
//# sourceMappingURL=api-design-test-suite.js.map