"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.APISecurityTester = void 0;
const authentication_test_suite_1 = require("./test-suites/authentication-test-suite");
const authorization_test_suite_1 = require("./test-suites/authorization-test-suite");
const injection_test_suite_1 = require("./test-suites/injection-test-suite");
const rate_limiting_test_suite_1 = require("./test-suites/rate-limiting-test-suite");
const security_headers_test_suite_1 = require("./test-suites/security-headers-test-suite");
const graphql_test_suite_1 = require("./test-suites/graphql-test-suite");
const sensitive_data_test_suite_1 = require("./test-suites/sensitive-data-test-suite");
const cryptography_test_suite_1 = require("./test-suites/cryptography-test-suite");
const api_design_test_suite_1 = require("./test-suites/api-design-test-suite");
const business_logic_test_suite_1 = require("./test-suites/business-logic-test-suite");
const third_party_integration_test_suite_1 = require("./test-suites/third-party-integration-test-suite");
const logging_test_suite_1 = require("./test-suites/logging-test-suite");
class APISecurityTester {
    constructor(config) {
        this.config = config;
    }
    async testRESTAPI(test) {
        const startTime = Date.now();
        const result = {
            testName: test.name,
            endpoint: test.endpoint,
            method: test.method,
            testType: 'api-security',
            passed: false,
            timestamp: new Date(),
            details: {},
        };
        try {
            const url = `${this.config.baseUrl}${test.endpoint}`;
            const headers = this.buildHeaders(test);
            const options = {
                method: test.method,
                headers,
            };
            if (test.body && ['POST', 'PUT', 'PATCH'].includes(test.method)) {
                options.body = JSON.stringify(test.body);
                headers['Content-Type'] = 'application/json';
            }
            const response = await fetch(url, options);
            const responseTime = Date.now() - startTime;
            result.responseTime = responseTime;
            result.statusCode = response.status;
            result.rateLimitInfo = this.extractRateLimitHeaders(response);
            result.authenticationResult = await this.testAuthentication(response, test);
            result.authorizationResult = await this.testAuthorization(response, test);
            result.securityIssues = await this.detectSecurityIssues(response, test);
            const body = await response.json().catch(() => ({}));
            result.details = {
                responseBody: body,
                responseHeaders: Object.fromEntries(response.headers.entries()),
            };
            result.passed = this.evaluateTestResult(result, test);
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
            return result;
        }
    }
    async testGraphQLAPI(query, variables, test) {
        const startTime = Date.now();
        const result = {
            testName: test?.name || 'GraphQL Query',
            endpoint: test?.endpoint || '/graphql',
            method: 'POST',
            testType: 'api-security',
            passed: false,
            timestamp: new Date(),
            details: {},
        };
        try {
            const url = `${this.config.baseUrl}${result.endpoint}`;
            const headers = this.buildHeaders(test || {});
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    ...headers,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query,
                    variables,
                }),
            });
            const responseTime = Date.now() - startTime;
            result.responseTime = responseTime;
            result.statusCode = response.status;
            const body = await response.json().catch(() => ({}));
            result.details = {
                graphqlResponse: body,
                query,
                variables,
            };
            result.securityIssues = this.detectGraphQLSecurityIssues(body, query);
            result.authenticationResult = await this.testAuthentication(response, test || {});
            result.authorizationResult = await this.testAuthorization(response, test || {});
            result.passed = this.evaluateTestResult(result, test || {});
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
            return result;
        }
    }
    async testRateLimiting(endpoint, method = 'GET') {
        const result = {
            testName: 'Rate Limiting Test',
            endpoint,
            method: method,
            testType: 'api-security',
            passed: false,
            timestamp: new Date(),
            details: {},
        };
        try {
            const maxRequests = this.config.rateLimitConfig?.maxRequests || 100;
            const requests = [];
            for (let i = 0; i < maxRequests + 10; i++) {
                const url = `${this.config.baseUrl}${endpoint}`;
                requests.push(fetch(url, {
                    method,
                    headers: this.buildHeaders({}),
                }));
            }
            const responses = await Promise.all(requests);
            const rateLimitInfo = this.extractRateLimitHeaders(responses[0]);
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
            result.rateLimitInfo = rateLimitInfo;
            result.details = {
                totalRequests: requests.length,
                rateLimited,
                rateLimitReachedAt,
                rateLimitHeaders: rateLimitInfo,
            };
            result.passed = rateLimited || (rateLimitInfo.limit !== undefined);
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            return result;
        }
    }
    async testAuthentication(test) {
        const result = {
            testName: 'Authentication Test',
            endpoint: test.endpoint,
            method: test.method,
            testType: 'api-security',
            passed: false,
            timestamp: new Date(),
            details: {},
        };
        try {
            const url = `${this.config.baseUrl}${test.endpoint}`;
            const unauthenticatedResponse = await fetch(url, {
                method: test.method,
            });
            const invalidTokenResponse = await fetch(url, {
                method: test.method,
                headers: {
                    Authorization: 'Bearer invalid-token-12345',
                },
            });
            const expiredTokenResponse = await fetch(url, {
                method: test.method,
                headers: {
                    Authorization: 'Bearer expired-token',
                },
            });
            const validAuthResponse = await fetch(url, {
                method: test.method,
                headers: this.buildHeaders(test),
            });
            result.authenticationResult = {
                authenticated: validAuthResponse.status !== 401,
                tokenValid: validAuthResponse.status !== 401,
                tokenExpired: expiredTokenResponse.status === 401,
            };
            result.details = {
                unauthenticatedStatus: unauthenticatedResponse.status,
                invalidTokenStatus: invalidTokenResponse.status,
                expiredTokenStatus: expiredTokenResponse.status,
                validAuthStatus: validAuthResponse.status,
            };
            result.passed =
                unauthenticatedResponse.status === 401 &&
                    invalidTokenResponse.status === 401 &&
                    validAuthResponse.status !== 401;
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            return result;
        }
    }
    async testAuthorization(tests) {
        const results = [];
        for (const test of tests) {
            if (!test.user || !test.resource)
                continue;
            const result = {
                testName: `Authorization Test: ${test.name}`,
                endpoint: test.endpoint,
                method: test.method,
                testType: 'api-security',
                passed: false,
                timestamp: new Date(),
                details: {},
            };
            try {
                const url = `${this.config.baseUrl}${test.endpoint}`;
                const headers = this.buildHeaders(test);
                const response = await fetch(url, {
                    method: test.method,
                    headers,
                    body: test.body ? JSON.stringify(test.body) : undefined,
                });
                result.statusCode = response.status;
                result.authorizationResult = {
                    authorized: response.status !== 403,
                    reason: response.status === 403
                        ? 'Access forbidden'
                        : response.status === 401
                            ? 'Authentication required'
                            : 'Access granted',
                };
                result.passed =
                    (test.expectedAuthRequired && response.status === 401) ||
                        (!test.expectedAuthRequired && response.status !== 403);
                results.push(result);
            }
            catch (error) {
                result.passed = false;
                result.error = error.message;
                results.push(result);
            }
        }
        return results;
    }
    async testInputValidation(endpoint, method = 'POST') {
        const result = {
            testName: 'Input Validation Test',
            endpoint,
            method: method,
            testType: 'api-security',
            passed: false,
            timestamp: new Date(),
            details: {},
        };
        const securityIssues = [];
        const sqlInjectionPayloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
        ];
        for (const payload of sqlInjectionPayloads) {
            const response = await fetch(`${this.config.baseUrl}${endpoint}`, {
                method,
                headers: this.buildHeaders({}),
                body: JSON.stringify({ input: payload }),
            });
            if (response.status === 200) {
                const body = await response.text();
                if (body.includes('error') || body.includes('SQL')) {
                    securityIssues.push(`Potential SQL injection vulnerability detected`);
                }
            }
        }
        const xssPayloads = ['<script>alert(1)</script>', 'javascript:alert(1)'];
        for (const payload of xssPayloads) {
            const response = await fetch(`${this.config.baseUrl}${endpoint}`, {
                method,
                headers: this.buildHeaders({}),
                body: JSON.stringify({ input: payload }),
            });
            if (response.status === 200) {
                const body = await response.text();
                if (body.includes(payload)) {
                    securityIssues.push(`Potential XSS vulnerability detected`);
                }
            }
        }
        result.securityIssues = securityIssues;
        result.passed = securityIssues.length === 0;
        result.details = {
            testedPayloads: sqlInjectionPayloads.length + xssPayloads.length,
            securityIssuesFound: securityIssues.length,
        };
        return result;
    }
    buildHeaders(test) {
        const headers = {
            ...this.config.headers,
            ...test.headers,
        };
        if (this.config.authentication) {
            const authHeader = this.getAuthHeader(this.config.authentication, test.user);
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
    extractRateLimitHeaders(response) {
        const headers = response.headers;
        const info = {};
        const limitHeader = headers.get('X-RateLimit-Limit') ||
            headers.get('RateLimit-Limit') ||
            headers.get('X-Rate-Limit-Limit');
        if (limitHeader) {
            info.limit = parseInt(limitHeader);
        }
        const remainingHeader = headers.get('X-RateLimit-Remaining') ||
            headers.get('RateLimit-Remaining') ||
            headers.get('X-Rate-Limit-Remaining');
        if (remainingHeader) {
            info.remaining = parseInt(remainingHeader);
        }
        const resetHeader = headers.get('X-RateLimit-Reset') ||
            headers.get('RateLimit-Reset') ||
            headers.get('X-Rate-Limit-Reset');
        if (resetHeader) {
            const resetTimestamp = parseInt(resetHeader);
            info.resetTime = new Date(resetTimestamp > 10000000000
                ? resetTimestamp * 1000
                : resetTimestamp);
        }
        return info;
    }
    async testAuthentication(response, test) {
        return {
            authenticated: response.status !== 401,
            tokenValid: response.status !== 401,
            tokenExpired: response.status === 401 && test.expectedAuthRequired,
        };
    }
    async testAuthorization(response, test) {
        return {
            authorized: response.status !== 403,
            reason: response.status === 403
                ? 'Access forbidden'
                : response.status === 401
                    ? 'Authentication required'
                    : 'Access granted',
        };
    }
    async detectSecurityIssues(response, test) {
        const issues = [];
        const headers = Object.fromEntries(response.headers.entries());
        if (headers['x-powered-by'] || headers['server']) {
            issues.push('Server information disclosure in headers');
        }
        const corsHeader = headers['access-control-allow-origin'];
        if (corsHeader === '*') {
            issues.push('CORS allows all origins (*)');
        }
        if (!headers['x-content-type-options']) {
            issues.push('Missing X-Content-Type-Options header');
        }
        if (!headers['x-frame-options']) {
            issues.push('Missing X-Frame-Options header');
        }
        if (!headers['strict-transport-security']) {
            issues.push('Missing Strict-Transport-Security header');
        }
        return issues;
    }
    detectGraphQLSecurityIssues(response, query) {
        const issues = [];
        if (query.includes('__schema') || query.includes('__type')) {
            if (response.data) {
                issues.push('GraphQL introspection may be enabled');
            }
        }
        if (query.split('{').length > 10) {
            issues.push('Potentially complex GraphQL query');
        }
        const nestedDepth = (query.match(/\{/g) || []).length;
        if (nestedDepth > 5) {
            issues.push('Deeply nested GraphQL query detected');
        }
        return issues;
    }
    evaluateTestResult(result, test) {
        if (test.expectedStatus && result.statusCode !== test.expectedStatus) {
            return false;
        }
        if (test.expectedAuthRequired &&
            result.authenticationResult &&
            !result.authenticationResult.authenticated) {
            return false;
        }
        if (result.securityIssues && result.securityIssues.length > 0) {
            return false;
        }
        if (result.authorizationResult &&
            !result.authorizationResult.authorized &&
            test.expectedAuthRequired) {
            return false;
        }
        return true;
    }
    async runTestSuite(suiteName, endpoint, method = 'GET', test) {
        let suite;
        switch (suiteName.toLowerCase()) {
            case 'authentication':
                suite = new authentication_test_suite_1.AuthenticationTestSuite(this.config);
                break;
            case 'authorization':
                suite = new authorization_test_suite_1.AuthorizationTestSuite(this.config);
                break;
            case 'injection':
                suite = new injection_test_suite_1.InjectionTestSuite(this.config);
                break;
            case 'rate-limiting':
            case 'ratelimiting':
                suite = new rate_limiting_test_suite_1.RateLimitingTestSuite(this.config);
                break;
            case 'security-headers':
            case 'securityheaders':
                suite = new security_headers_test_suite_1.SecurityHeadersTestSuite(this.config);
                break;
            case 'graphql':
                suite = new graphql_test_suite_1.GraphQLTestSuite(this.config);
                break;
            case 'sensitive-data':
            case 'sensitivedata':
                suite = new sensitive_data_test_suite_1.SensitiveDataTestSuite(this.config);
                break;
            case 'cryptography':
                suite = new cryptography_test_suite_1.CryptographyTestSuite(this.config);
                break;
            case 'api-design':
            case 'apidesign':
                suite = new api_design_test_suite_1.APIDesignTestSuite(this.config);
                break;
            case 'business-logic':
            case 'businesslogic':
                suite = new business_logic_test_suite_1.BusinessLogicTestSuite(this.config);
                break;
            case 'third-party':
            case 'thirdparty':
                suite = new third_party_integration_test_suite_1.ThirdPartyIntegrationTestSuite(this.config);
                break;
            case 'logging':
                suite = new logging_test_suite_1.LoggingTestSuite(this.config);
                break;
            default:
                throw new Error(`Unknown test suite: ${suiteName}`);
        }
        return suite.runAllTests(endpoint, method, test);
    }
    async runFullSecurityScan(endpoint, method = 'GET', test) {
        const allResults = [];
        const suites = [
            'authentication',
            'authorization',
            'injection',
            'rate-limiting',
            'security-headers',
            'graphql',
            'sensitive-data',
            'cryptography',
            'api-design',
            'business-logic',
            'third-party',
            'logging',
        ];
        for (const suiteName of suites) {
            try {
                const results = await this.runTestSuite(suiteName, endpoint, method, test);
                allResults.push(...results);
            }
            catch (error) {
                const errorResult = {
                    testName: `${suiteName} Suite Error`,
                    endpoint,
                    method,
                    testType: 'api-security',
                    passed: false,
                    timestamp: new Date(),
                    error: error.message,
                    details: { suite: suiteName, error: error.message },
                };
                allResults.push(errorResult);
            }
        }
        return allResults;
    }
    async runTestByCategory(category, endpoint, method = 'GET', test) {
        const categoryMap = {
            'authentication': ['authentication'],
            'authorization': ['authorization'],
            'injection': ['injection'],
            'rate-limiting': ['rate-limiting'],
            'headers': ['security-headers'],
            'graphql': ['graphql'],
            'data-exposure': ['sensitive-data'],
            'cryptography': ['cryptography'],
            'design': ['api-design'],
            'business-logic': ['business-logic'],
            'integration': ['third-party'],
            'logging': ['logging'],
        };
        const suites = categoryMap[category.toLowerCase()] || [];
        const allResults = [];
        for (const suiteName of suites) {
            try {
                const results = await this.runTestSuite(suiteName, endpoint, method, test);
                allResults.push(...results);
            }
            catch (error) {
                const errorResult = {
                    testName: `${suiteName} Suite Error`,
                    endpoint,
                    method,
                    testType: 'api-security',
                    passed: false,
                    timestamp: new Date(),
                    error: error.message,
                    details: { suite: suiteName, error: error.message },
                };
                allResults.push(errorResult);
            }
        }
        return allResults;
    }
    getAvailableTestSuites() {
        return [
            'authentication',
            'authorization',
            'injection',
            'rate-limiting',
            'security-headers',
            'graphql',
            'sensitive-data',
            'cryptography',
            'api-design',
            'business-logic',
            'third-party',
            'logging',
        ];
    }
}
exports.APISecurityTester = APISecurityTester;
//# sourceMappingURL=api-security-tester.js.map