"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityHeadersTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const header_analyzer_1 = require("../utils/header-analyzer");
class SecurityHeadersTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testCORSConfiguration(endpoint, method, test));
        results.push(await this.testCSP(endpoint, method, test));
        results.push(await this.testHSTS(endpoint, method, test));
        results.push(await this.testXContentTypeOptions(endpoint, method, test));
        results.push(await this.testXFrameOptions(endpoint, method, test));
        results.push(await this.testXSSProtection(endpoint, method, test));
        results.push(await this.testReferrerPolicy(endpoint, method, test));
        results.push(await this.testPermissionsPolicy(endpoint, method, test));
        results.push(await this.testServerInformationDisclosure(endpoint, method, test));
        return results;
    }
    async testCORSConfiguration(endpoint, method, test) {
        const result = this.createBaseResult('CORS Configuration Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, 'OPTIONS', headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const corsAnalysis = (0, header_analyzer_1.analyzeCORS)(responseHeaders);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = corsAnalysis.issues.length > 0 ? corsAnalysis.issues : undefined;
            result.passed = corsAnalysis.valid;
            result.details = {
                corsOrigin: responseHeaders['access-control-allow-origin'],
                corsCredentials: responseHeaders['access-control-allow-credentials'],
                corsMethods: responseHeaders['access-control-allow-methods'],
                analysis: corsAnalysis,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testCSP(endpoint, method, test) {
        const result = this.createBaseResult('CSP Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const csp = responseHeaders['content-security-policy'] || responseHeaders['Content-Security-Policy'];
            const analysis = (0, header_analyzer_1.analyzeSecurityHeaders)(responseHeaders);
            const cspHeader = analysis.headers.find(h => h.header.toLowerCase() === 'content-security-policy');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = cspHeader?.issues.length > 0 ? cspHeader.issues : undefined;
            result.passed = cspHeader?.valid || false;
            result.details = {
                csp: csp,
                analysis: cspHeader,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testHSTS(endpoint, method, test) {
        const result = this.createBaseResult('HSTS Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const hsts = responseHeaders['strict-transport-security'] || responseHeaders['Strict-Transport-Security'];
            const analysis = (0, header_analyzer_1.analyzeSecurityHeaders)(responseHeaders);
            const hstsHeader = analysis.headers.find(h => h.header.toLowerCase() === 'strict-transport-security');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = hstsHeader?.issues.length > 0 ? hstsHeader.issues : undefined;
            result.passed = hstsHeader?.valid || false;
            result.details = {
                hsts: hsts,
                analysis: hstsHeader,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testXContentTypeOptions(endpoint, method, test) {
        const result = this.createBaseResult('X-Content-Type-Options Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const analysis = (0, header_analyzer_1.analyzeSecurityHeaders)(responseHeaders);
            const header = analysis.headers.find(h => h.header.toLowerCase() === 'x-content-type-options');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
            result.passed = header?.valid || false;
            result.details = { analysis: header };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testXFrameOptions(endpoint, method, test) {
        const result = this.createBaseResult('X-Frame-Options Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const analysis = (0, header_analyzer_1.analyzeSecurityHeaders)(responseHeaders);
            const header = analysis.headers.find(h => h.header.toLowerCase() === 'x-frame-options');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
            result.passed = header?.valid || false;
            result.details = { analysis: header };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testXSSProtection(endpoint, method, test) {
        const result = this.createBaseResult('X-XSS-Protection Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const analysis = (0, header_analyzer_1.analyzeSecurityHeaders)(responseHeaders);
            const header = analysis.headers.find(h => h.header.toLowerCase() === 'x-xss-protection');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
            result.passed = header?.valid || false;
            result.details = { analysis: header };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testReferrerPolicy(endpoint, method, test) {
        const result = this.createBaseResult('Referrer-Policy Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const analysis = (0, header_analyzer_1.analyzeSecurityHeaders)(responseHeaders);
            const header = analysis.headers.find(h => h.header.toLowerCase() === 'referrer-policy');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
            result.passed = header?.valid || false;
            result.details = { analysis: header };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testPermissionsPolicy(endpoint, method, test) {
        const result = this.createBaseResult('Permissions-Policy Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const analysis = (0, header_analyzer_1.analyzeSecurityHeaders)(responseHeaders);
            const header = analysis.headers.find(h => h.header.toLowerCase() === 'permissions-policy');
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = header?.issues.length > 0 ? header.issues : undefined;
            result.passed = header?.present || false;
            result.details = { analysis: header };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testServerInformationDisclosure(endpoint, method, test) {
        const result = this.createBaseResult('Server Information Disclosure Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const disclosureHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime'];
            const securityIssues = [];
            for (const headerName of disclosureHeaders) {
                if (responseHeaders[headerName] || responseHeaders[headerName.toLowerCase()]) {
                    securityIssues.push(`Server information disclosure: ${headerName} header present`);
                }
            }
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                headersChecked: disclosureHeaders,
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
exports.SecurityHeadersTestSuite = SecurityHeadersTestSuite;
//# sourceMappingURL=security-headers-test-suite.js.map