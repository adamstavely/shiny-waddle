"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RLSPolicyTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const rls_cls_tester_1 = require("../rls-cls-tester");
class RLSPolicyTestSuite extends base_test_suite_1.BaseTestSuite {
    constructor(config, databaseConfig) {
        super(config);
        this.rlsTester = new rls_cls_tester_1.RLSCLSTester();
        this.databaseConfig = databaseConfig;
    }
    async runAllTests(endpoint, method, test) {
        const results = [];
        if (!this.databaseConfig) {
            results.push(this.createBaseResult('RLS Coverage Test', endpoint, method));
            results[0].error = 'Database configuration required for RLS tests';
            results[0].passed = false;
            return results;
        }
        results.push(await this.testRLSCoverage(endpoint, method, test));
        results.push(await this.testCrossTenantIsolation(endpoint, method, test));
        return results;
    }
    async testRLSCoverage(endpoint, method, test) {
        const result = this.createBaseResult('RLS Coverage Test', endpoint, method);
        try {
            if (!this.databaseConfig) {
                result.error = 'Database configuration required';
                result.passed = false;
                return result;
            }
            const coverage = await this.rlsTester.testRLSCoverage(this.databaseConfig);
            result.passed = coverage.coveragePercentage >= 100;
            result.details = {
                coverage,
                message: coverage.coveragePercentage >= 100
                    ? 'All tables have RLS policies'
                    : `${coverage.tablesWithoutRLS.length} tables missing RLS policies`,
            };
        }
        catch (error) {
            result.error = error.message;
            result.passed = false;
        }
        return result;
    }
    async testCrossTenantIsolation(endpoint, method, test) {
        const result = this.createBaseResult('Cross-Tenant Isolation Test', endpoint, method);
        try {
            const testQueries = [
                {
                    name: 'Tenant Isolation Query',
                    sql: `SELECT * FROM users WHERE tenant_id = 'tenant1'`,
                },
            ];
            const isolationTest = await this.rlsTester.testCrossTenantIsolation('tenant1', 'tenant2', testQueries);
            result.passed = isolationTest.isolationVerified;
            result.details = {
                isolationTest,
                message: isolationTest.isolationVerified
                    ? 'Cross-tenant isolation verified'
                    : `Isolation violations: ${isolationTest.violations.length}`,
            };
        }
        catch (error) {
            result.error = error.message;
            result.passed = false;
        }
        return result;
    }
}
exports.RLSPolicyTestSuite = RLSPolicyTestSuite;
//# sourceMappingURL=rls-policy-test-suite.js.map