"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RateLimitingTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
class RateLimitingTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testRateLimitEnforcement(endpoint, method, test));
        results.push(await this.testRateLimitBypass(endpoint, method, test));
        results.push(await this.testDDoSProtection(endpoint, method, test));
        results.push(await this.testRequestSizeLimits(endpoint, method, test));
        results.push(await this.testTimeoutHandling(endpoint, method, test));
        results.push(await this.testConnectionLimits(endpoint, method, test));
        return results;
    }
    async testRateLimitEnforcement(endpoint, method, test) {
        const result = this.createBaseResult('Rate Limit Enforcement Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const maxRequests = this.config.rateLimitConfig?.maxRequests || 100;
            const requests = [];
            for (let i = 0; i < maxRequests + 10; i++) {
                requests.push(this.makeRequest(url, method, headers));
            }
            const responses = await Promise.all(requests);
            let rateLimited = false;
            let rateLimitReachedAt = -1;
            for (let i = 0; i < responses.length; i++) {
                if (responses[i].status === 429) {
                    rateLimited = true;
                    if (rateLimitReachedAt === -1) {
                        rateLimitReachedAt = i;
                    }
                }
            }
            result.responseTime = Date.now() - startTime;
            result.passed = rateLimited;
            result.securityIssues = rateLimited ? undefined : ['Rate limiting not enforced'];
            result.details = {
                totalRequests: requests.length,
                rateLimited,
                rateLimitReachedAt,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testRateLimitBypass(endpoint, method, test) {
        const result = this.createBaseResult('Rate Limit Bypass Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const securityIssues = [];
            const bypassMethods = [
                { header: 'X-Forwarded-For', value: '127.0.0.1' },
                { header: 'X-Real-IP', value: '127.0.0.1' },
                { header: 'X-Originating-IP', value: '127.0.0.1' },
            ];
            for (const bypass of bypassMethods) {
                const headers = { ...this.buildHeaders(test), [bypass.header]: bypass.value };
                const response = await this.makeRequest(url, method, headers);
                if (response.status === 200) {
                    securityIssues.push(`Potential rate limit bypass via ${bypass.header}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = { bypassMethodsTested: bypassMethods.length, issuesFound: securityIssues.length };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testDDoSProtection(endpoint, method, test) {
        const result = this.createBaseResult('DDoS Protection Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const requests = [];
            for (let i = 0; i < 1000; i++) {
                requests.push(this.makeRequest(url, method, headers));
            }
            const responses = await Promise.all(requests);
            const successRate = responses.filter(r => r.status === 200).length / responses.length;
            result.responseTime = Date.now() - startTime;
            result.passed = successRate < 0.5;
            result.securityIssues = successRate >= 0.5 ? ['DDoS protection may be insufficient'] : undefined;
            result.details = {
                totalRequests: requests.length,
                successRate,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testRequestSizeLimits(endpoint, method, test) {
        const result = this.createBaseResult('Request Size Limits Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const largePayload = 'x'.repeat(10 * 1024 * 1024);
            const body = { data: largePayload, ...test?.body };
            const response = await this.makeRequest(url, method, headers, body);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = response.status === 413;
            result.securityIssues = response.status !== 413 ? ['Request size limits not enforced'] : undefined;
            result.details = {
                payloadSize: largePayload.length,
                statusCode: response.status,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testTimeoutHandling(endpoint, method, test) {
        const result = this.createBaseResult('Timeout Handling Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const timeout = this.config.timeout || 10000;
            const response = await this.makeRequest(url, method, headers);
            const responseTime = Date.now() - startTime;
            result.statusCode = response.status;
            result.responseTime = responseTime;
            result.passed = responseTime < timeout;
            result.securityIssues = responseTime >= timeout ? ['Request timeout not properly handled'] : undefined;
            result.details = {
                responseTime,
                timeout,
            };
        }
        catch (error) {
            if (error.message.includes('timeout')) {
                result.passed = true;
                result.details = { message: 'Timeout properly enforced' };
            }
            else {
                result.passed = false;
                result.error = error.message;
                result.details = { error: error.message };
            }
        }
        return result;
    }
    async testConnectionLimits(endpoint, method, test) {
        const result = this.createBaseResult('Connection Limits Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const concurrentRequests = 100;
            const requests = [];
            for (let i = 0; i < concurrentRequests; i++) {
                requests.push(this.makeRequest(url, method, headers));
            }
            const responses = await Promise.all(requests);
            const successCount = responses.filter(r => r.status === 200).length;
            result.responseTime = Date.now() - startTime;
            result.passed = successCount < concurrentRequests;
            result.securityIssues = successCount === concurrentRequests ? ['Connection limits not enforced'] : undefined;
            result.details = {
                concurrentRequests,
                successCount,
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
exports.RateLimitingTestSuite = RateLimitingTestSuite;
//# sourceMappingURL=rate-limiting-test-suite.js.map