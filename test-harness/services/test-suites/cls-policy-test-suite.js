"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CLSPolicyTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const rls_cls_tester_1 = require("../rls-cls-tester");
class CLSPolicyTestSuite extends base_test_suite_1.BaseTestSuite {
    constructor(config, databaseConfig) {
        super(config);
        this.rlsTester = new rls_cls_tester_1.RLSCLSTester();
        this.databaseConfig = databaseConfig;
    }
    async runAllTests(endpoint, method, test) {
        const results = [];
        if (!this.databaseConfig) {
            results.push(this.createBaseResult('CLS Coverage Test', endpoint, method));
            results[0].error = 'Database configuration required for CLS tests';
            results[0].passed = false;
            return results;
        }
        results.push(await this.testCLSCoverage(endpoint, method, test));
        results.push(await this.testDynamicMasking(endpoint, method, test));
        return results;
    }
    async testCLSCoverage(endpoint, method, test) {
        const result = this.createBaseResult('CLS Coverage Test', endpoint, method);
        try {
            if (!this.databaseConfig) {
                result.error = 'Database configuration required';
                result.passed = false;
                return result;
            }
            const coverage = await this.rlsTester.testCLSCoverage(this.databaseConfig);
            result.passed = coverage.coveragePercentage >= 80;
            result.details = {
                coverage,
                message: coverage.coveragePercentage >= 80
                    ? 'CLS coverage meets threshold'
                    : `${coverage.tablesWithoutCLS.length} tables missing CLS policies`,
            };
        }
        catch (error) {
            result.error = error.message;
            result.passed = false;
        }
        return result;
    }
    async testDynamicMasking(endpoint, method, test) {
        const result = this.createBaseResult('Dynamic Data Masking Test', endpoint, method);
        try {
            const maskingRules = [
                {
                    table: 'users',
                    column: 'email',
                    maskingType: 'partial',
                    pattern: '***@***',
                    applicableRoles: ['viewer', 'analyst'],
                },
                {
                    table: 'users',
                    column: 'ssn',
                    maskingType: 'full',
                    applicableRoles: ['viewer'],
                },
            ];
            const testQuery = {
                name: 'Masking Test Query',
                sql: 'SELECT email, ssn FROM users WHERE id = 1',
            };
            const user = {
                id: 'test-user',
                email: 'test@example.com',
                role: 'viewer',
                attributes: {},
            };
            const maskingTest = await this.rlsTester.testDynamicMasking(testQuery, user, maskingRules);
            result.passed = maskingTest.passed;
            result.details = {
                maskingTest,
                message: maskingTest.passed
                    ? 'Dynamic masking verified'
                    : 'Dynamic masking not properly applied',
            };
        }
        catch (error) {
            result.error = error.message;
            result.passed = false;
        }
        return result;
    }
}
exports.CLSPolicyTestSuite = CLSPolicyTestSuite;
//# sourceMappingURL=cls-policy-test-suite.js.map