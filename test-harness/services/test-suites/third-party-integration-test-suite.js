"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ThirdPartyIntegrationTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const ssrf_1 = require("../payloads/ssrf");
class ThirdPartyIntegrationTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testSSRF(endpoint, method, test));
        results.push(await this.testExternalEntityAccess(endpoint, method, test));
        results.push(await this.testWebhookSecurity(endpoint, method, test));
        results.push(await this.testOAuthFlowSecurity(endpoint, method, test));
        return results;
    }
    async testSSRF(endpoint, method, test) {
        const result = this.createBaseResult('SSRF Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            for (const payload of ssrf_1.SSRF_PAYLOADS.slice(0, 10)) {
                const body = { url: payload.url, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && (responseText.includes('127.0.0.1') ||
                    responseText.includes('localhost') ||
                    responseText.includes('169.254.169.254'))) {
                    securityIssues.push(`Potential SSRF vulnerability: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 10,
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
    async testExternalEntityAccess(endpoint, method, test) {
        const result = this.createBaseResult('External Entity Access Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const externalEntities = [
                'http://attacker.com',
                'http://malicious.com',
                'file:///etc/passwd',
            ];
            for (const entity of externalEntities) {
                const body = { url: entity, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 200) {
                    securityIssues.push(`External entity access possible: ${entity}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                entitiesTested: externalEntities.length,
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
    async testWebhookSecurity(endpoint, method, test) {
        const result = this.createBaseResult('Webhook Security Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const webhookBody = {
                url: 'http://attacker.com/webhook',
                events: ['all'],
            };
            const response = await this.makeRequest(url, method, headers, webhookBody);
            if (response.status === 200) {
                securityIssues.push('Webhook can be registered without authentication');
            }
            const responseText = await response.text();
            if (!responseText.includes('signature') && !responseText.includes('secret')) {
                securityIssues.push('Webhook signature validation may be missing');
            }
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
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
    async testOAuthFlowSecurity(endpoint, method, test) {
        const result = this.createBaseResult('OAuth Flow Security Test', endpoint, method);
        const startTime = Date.now();
        try {
            const baseUrl = this.config.baseUrl;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const oauthEndpoints = [
                '/oauth/authorize',
                '/oauth/token',
                '/oauth/callback',
            ];
            for (const oauthEndpoint of oauthEndpoints) {
                const url = `${baseUrl}${oauthEndpoint}`;
                const response = await this.makeRequest(url, method, headers);
                if (response.status === 200) {
                    const responseText = await response.text();
                    if (responseText.includes('redirect_uri') && !responseText.includes('validate')) {
                        securityIssues.push(`OAuth redirect URI validation may be missing: ${oauthEndpoint}`);
                    }
                    if (responseText.includes('state') && !responseText.includes('csrf')) {
                        securityIssues.push(`OAuth state parameter may not be validated: ${oauthEndpoint}`);
                    }
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                endpointsTested: oauthEndpoints.length,
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
exports.ThirdPartyIntegrationTestSuite = ThirdPartyIntegrationTestSuite;
//# sourceMappingURL=third-party-integration-test-suite.js.map