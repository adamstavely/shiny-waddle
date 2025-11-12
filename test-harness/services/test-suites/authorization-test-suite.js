"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
class AuthorizationTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testHorizontalPrivilegeEscalation(endpoint, method, test));
        results.push(await this.testVerticalPrivilegeEscalation(endpoint, method, test));
        results.push(await this.testBOLA(endpoint, method, test));
        results.push(await this.testMassAssignment(endpoint, method, test));
        results.push(await this.testFunctionLevelAuthorization(endpoint, method, test));
        results.push(await this.testRBAC(endpoint, method, test));
        results.push(await this.testABAC(endpoint, method, test));
        return results;
    }
    async testHorizontalPrivilegeEscalation(endpoint, method, test) {
        const result = this.createBaseResult('Horizontal Privilege Escalation Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const maliciousBodies = [
                { userId: '999999', ...test?.body },
                { id: '999999', ...test?.body },
                { user_id: '999999', ...test?.body },
            ];
            for (const body of maliciousBodies) {
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 200) {
                    result.passed = false;
                    result.securityIssues = ['Horizontal privilege escalation: User can access other users\' resources'];
                    result.details = { message: 'Endpoint should restrict access to user\'s own resources' };
                    break;
                }
            }
            if (!result.securityIssues) {
                result.passed = true;
                result.details = { message: 'Horizontal privilege escalation protection appears to be in place' };
            }
            result.responseTime = Date.now() - startTime;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testVerticalPrivilegeEscalation(endpoint, method, test) {
        const result = this.createBaseResult('Vertical Privilege Escalation Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const maliciousBodies = [
                { role: 'admin', ...test?.body },
                { role: 'administrator', ...test?.body },
                { isAdmin: true, ...test?.body },
                { admin: true, ...test?.body },
            ];
            for (const body of maliciousBodies) {
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 200) {
                    const responseText = await response.text();
                    if (responseText.includes('admin') || responseText.includes('privilege')) {
                        result.passed = false;
                        result.securityIssues = ['Vertical privilege escalation: User can escalate to admin role'];
                        result.details = { message: 'Endpoint should prevent role modification' };
                        break;
                    }
                }
            }
            if (!result.securityIssues) {
                result.passed = true;
                result.details = { message: 'Vertical privilege escalation protection appears to be in place' };
            }
            result.responseTime = Date.now() - startTime;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testBOLA(endpoint, method, test) {
        const result = this.createBaseResult('BOLA Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const testIds = ['1', '2', '999', '0', '-1', '../1'];
            for (const id of testIds) {
                const testUrl = url.replace(/\d+/, id).replace(/\/[^\/]+$/, `/${id}`);
                const response = await this.makeRequest(testUrl, method, headers);
                if (response.status === 200) {
                    result.passed = false;
                    result.securityIssues = [`BOLA vulnerability: Can access object with ID ${id}`];
                    result.details = { message: 'Endpoint should verify user has permission to access object' };
                    break;
                }
            }
            if (!result.securityIssues) {
                result.passed = true;
                result.details = { message: 'BOLA protection appears to be in place' };
            }
            result.responseTime = Date.now() - startTime;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testMassAssignment(endpoint, method, test) {
        const result = this.createBaseResult('Mass Assignment Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const unauthorizedFields = {
                isAdmin: true,
                role: 'admin',
                balance: 999999,
                permissions: ['all'],
                email: 'admin@example.com',
            };
            const body = { ...unauthorizedFields, ...test?.body };
            const response = await this.makeRequest(url, method, headers, body);
            const responseText = await response.text();
            if (response.status === 200) {
                const fieldsAccepted = Object.keys(unauthorizedFields).some(field => responseText.includes(field));
                if (fieldsAccepted) {
                    result.passed = false;
                    result.securityIssues = ['Mass assignment: Unauthorized fields can be set'];
                    result.details = { message: 'Endpoint should whitelist allowed fields' };
                }
                else {
                    result.passed = true;
                    result.details = { message: 'Mass assignment protection appears to be in place' };
                }
            }
            else {
                result.passed = true;
                result.details = { message: 'Unauthorized field modification rejected' };
            }
            result.responseTime = Date.now() - startTime;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testFunctionLevelAuthorization(endpoint, method, test) {
        const result = this.createBaseResult('Function Level Authorization Test', endpoint, method);
        const startTime = Date.now();
        try {
            const adminEndpoints = [
                '/admin',
                '/admin/users',
                '/admin/settings',
                '/api/admin',
                '/api/v1/admin',
            ];
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            for (const adminEndpoint of adminEndpoints) {
                const url = `${this.config.baseUrl}${adminEndpoint}`;
                const response = await this.makeRequest(url, method, headers);
                if (response.status === 200) {
                    securityIssues.push(`Function level authorization bypass: Can access ${adminEndpoint}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                endpointsTested: adminEndpoints.length,
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
    async testRBAC(endpoint, method, test) {
        const result = this.createBaseResult('RBAC Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const roles = ['user', 'admin', 'moderator', 'guest'];
            const securityIssues = [];
            for (const role of roles) {
                const testHeaders = { ...headers, 'X-Role': role };
                const response = await this.makeRequest(url, method, testHeaders);
                if (response.status === 200 && role !== 'user') {
                    securityIssues.push(`RBAC bypass: Role can be set via header (${role})`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                rolesTested: roles.length,
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
    async testABAC(endpoint, method, test) {
        const result = this.createBaseResult('ABAC Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const attributes = {
                department: 'IT',
                clearance: 'top-secret',
                location: 'HQ',
            };
            const body = { ...attributes, ...test?.body };
            const response = await this.makeRequest(url, method, headers, body);
            const responseText = await response.text();
            if (response.status === 200) {
                const attributesAccepted = Object.keys(attributes).some(attr => responseText.includes(attr));
                if (attributesAccepted) {
                    result.passed = false;
                    result.securityIssues = ['ABAC bypass: Attributes can be manipulated'];
                    result.details = { message: 'Endpoint should validate attributes from trusted source' };
                }
                else {
                    result.passed = true;
                    result.details = { message: 'ABAC protection appears to be in place' };
                }
            }
            else {
                result.passed = true;
                result.details = { message: 'Attribute manipulation rejected' };
            }
            result.responseTime = Date.now() - startTime;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
}
exports.AuthorizationTestSuite = AuthorizationTestSuite;
//# sourceMappingURL=authorization-test-suite.js.map