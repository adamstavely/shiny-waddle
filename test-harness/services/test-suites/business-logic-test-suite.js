"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BusinessLogicTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
class BusinessLogicTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testWorkflowBypass(endpoint, method, test));
        results.push(await this.testRaceConditions(endpoint, method, test));
        results.push(await this.testTimeBasedAttacks(endpoint, method, test));
        results.push(await this.testBusinessRuleViolations(endpoint, method, test));
        results.push(await this.testStateTransitionAttacks(endpoint, method, test));
        return results;
    }
    async testWorkflowBypass(endpoint, method, test) {
        const result = this.createBaseResult('Workflow Bypass Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const bypassAttempts = [
                { status: 'completed', step: 1 },
                { status: 'approved', step: 0 },
                { verified: true, step: 0 },
            ];
            for (const attempt of bypassAttempts) {
                const body = { ...attempt, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 200) {
                    securityIssues.push(`Workflow bypass possible: ${JSON.stringify(attempt)}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                attemptsTested: bypassAttempts.length,
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
    async testRaceConditions(endpoint, method, test) {
        const result = this.createBaseResult('Race Conditions Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const concurrentRequests = 10;
            const requests = [];
            for (let i = 0; i < concurrentRequests; i++) {
                const body = { ...test?.body, amount: 100 };
                requests.push(this.makeRequest(url, method, headers, body));
            }
            const responses = await Promise.all(requests);
            const successCount = responses.filter(r => r.status === 200).length;
            result.responseTime = Date.now() - startTime;
            result.passed = successCount < concurrentRequests;
            result.securityIssues = successCount === concurrentRequests ? ['Potential race condition: All concurrent requests succeeded'] : undefined;
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
    async testTimeBasedAttacks(endpoint, method, test) {
        const result = this.createBaseResult('Time-Based Attacks Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const testUsers = ['admin', 'user', 'invalid'];
            const timings = [];
            for (const user of testUsers) {
                const userStartTime = Date.now();
                const body = { username: user, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const userEndTime = Date.now();
                timings.push(userEndTime - userStartTime);
            }
            const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
            const maxDeviation = Math.max(...timings.map(t => Math.abs(t - avgTiming)));
            if (maxDeviation > avgTiming * 0.5) {
                securityIssues.push('Significant timing differences detected (potential user enumeration)');
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                timings,
                avgTiming,
                maxDeviation,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testBusinessRuleViolations(endpoint, method, test) {
        const result = this.createBaseResult('Business Rule Violations Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const violations = [
                { amount: -100 },
                { amount: 0 },
                { amount: Number.MAX_SAFE_INTEGER },
                { quantity: -1 },
                { price: -1 },
            ];
            for (const violation of violations) {
                const body = { ...violation, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 200) {
                    securityIssues.push(`Business rule violation accepted: ${JSON.stringify(violation)}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                violationsTested: violations.length,
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
    async testStateTransitionAttacks(endpoint, method, test) {
        const result = this.createBaseResult('State Transition Attacks Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const invalidTransitions = [
                { from: 'pending', to: 'completed' },
                { from: 'new', to: 'archived' },
                { status: 'completed', previousStatus: 'new' },
            ];
            for (const transition of invalidTransitions) {
                const body = { ...transition, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 200) {
                    securityIssues.push(`Invalid state transition accepted: ${JSON.stringify(transition)}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                transitionsTested: invalidTransitions.length,
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
exports.BusinessLogicTestSuite = BusinessLogicTestSuite;
//# sourceMappingURL=business-logic-test-suite.js.map