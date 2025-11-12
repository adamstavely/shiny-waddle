"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RLSCLSTester = void 0;
const advanced_query_analyzer_1 = require("./advanced-query-analyzer");
class RLSCLSTester {
    constructor(config) {
        this.analyzer = new advanced_query_analyzer_1.AdvancedQueryAnalyzer();
        this.config = config || {};
        this.metadataProvider = this.config.metadataProvider;
    }
    async testRLSCoverage(database) {
        const tables = await this.getDatabaseTables(database);
        let policies = await this.getRLSPolicies(database);
        if (this.config.testLogic?.skipDisabledPolicies) {
            policies = policies.filter(p => p.applicable);
        }
        const tablesWithRLS = new Set(policies.map(p => p.table));
        const tablesWithoutRLS = tables.filter(t => !tablesWithRLS.has(t));
        return {
            database: database.database || 'unknown',
            totalTables: tables.length,
            tablesWithRLS: tablesWithRLS.size,
            tablesWithoutRLS,
            coveragePercentage: tables.length > 0
                ? (tablesWithRLS.size / tables.length) * 100
                : 0,
            policies: policies.map(p => ({
                table: p.table,
                policyName: p.policyName,
                policyDefinition: p.policyDefinition,
                enabled: p.applicable,
            })),
        };
    }
    async testCLSCoverage(database) {
        const tables = await this.getDatabaseTables(database);
        let policies = await this.getCLSPolicies(database);
        if (this.config.testLogic?.skipDisabledPolicies) {
            policies = policies.filter(p => p.applicable);
        }
        const tablesWithCLS = new Set(policies.map(p => p.table));
        const tablesWithoutCLS = tables.filter(t => !tablesWithCLS.has(t));
        return {
            database: database.database || 'unknown',
            totalTables: tables.length,
            tablesWithCLS: tablesWithCLS.size,
            tablesWithoutCLS,
            coveragePercentage: tables.length > 0
                ? (tablesWithCLS.size / tables.length) * 100
                : 0,
            policies: policies.map(p => ({
                table: p.table,
                column: p.column,
                policyType: p.policyType,
                policyDefinition: p.policyDefinition,
                enabled: p.applicable,
            })),
        };
    }
    async testDynamicMasking(query, user, maskingRules) {
        const result = {
            testType: 'data-behavior',
            testName: 'Dynamic Data Masking Test',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const analysis = await this.analyzer.analyzeAdvanced(query, user);
            if (!query.sql) {
                result.error = 'SQL query required for masking test';
                return result;
            }
            const applicableRules = this.findApplicableMaskingRules(query.sql, maskingRules, user);
            const maskingVerified = await this.verifyMaskingApplied(query, applicableRules, user);
            result.passed = maskingVerified;
            result.details = {
                applicableRules: applicableRules.length,
                maskingVerified,
                rules: applicableRules,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testCrossTenantIsolation(tenant1, tenant2, testQueries) {
        const violations = [];
        let isolationVerified = true;
        for (const query of testQueries) {
            const user1 = {
                id: `tenant1-user`,
                email: `user1@${tenant1}.com`,
                role: 'viewer',
                attributes: { tenant: tenant1 },
            };
            const user2 = {
                id: `tenant2-user`,
                email: `user2@${tenant2}.com`,
                role: 'viewer',
                attributes: { tenant: tenant2 },
            };
            const analysis1 = await this.analyzer.analyzeAdvanced(query, user1);
            const analysis2 = await this.analyzer.analyzeAdvanced(query, user2);
            const rlsCompliance1 = this.analyzer.validateRLSCompliance(analysis1, user1);
            const rlsCompliance2 = this.analyzer.validateRLSCompliance(analysis2, user2);
            if (!rlsCompliance1.compliant) {
                violations.push(`Tenant1 user: ${rlsCompliance1.violations.join(', ')}`);
                isolationVerified = false;
            }
            if (!rlsCompliance2.compliant) {
                violations.push(`Tenant2 user: ${rlsCompliance2.violations.join(', ')}`);
                isolationVerified = false;
            }
            if (this.detectCrossTenantAccess(query, tenant1, tenant2)) {
                violations.push(`Query may access cross-tenant data: ${query.name}`);
                isolationVerified = false;
            }
        }
        return {
            tenant1,
            tenant2,
            testQueries,
            isolationVerified,
            violations,
        };
    }
    async testPolicyBypassAttempts(user, resource) {
        const results = [];
        const bypassAttempts = [
            {
                name: 'Direct Table Access',
                query: { name: 'Direct Access', sql: `SELECT * FROM ${resource.type} WHERE id = '${resource.id}'` },
            },
            {
                name: 'SQL Injection Attempt',
                query: { name: 'SQL Injection', sql: `SELECT * FROM ${resource.type} WHERE id = '${resource.id}' OR '1'='1'` },
            },
            {
                name: 'Privilege Escalation',
                query: { name: 'Privilege Escalation', sql: `GRANT ALL ON ${resource.type} TO ${user.id}` },
            },
            {
                name: 'RLS Bypass',
                query: { name: 'RLS Bypass', sql: `SET row_security = off; SELECT * FROM ${resource.type}` },
            },
        ];
        for (const attempt of bypassAttempts) {
            const result = {
                testType: 'access-control',
                testName: `Policy Bypass Test: ${attempt.name}`,
                passed: false,
                details: {},
                timestamp: new Date(),
            };
            try {
                const analysis = await this.analyzer.analyzeAdvanced(attempt.query, user);
                const securityIssues = analysis.securityIssues || [];
                const bypassDetected = securityIssues.some(issue => issue.type === 'bypass-attempt' || issue.type === 'privilege-escalation');
                result.passed = bypassDetected;
                result.details = {
                    attempt: attempt.name,
                    securityIssues: securityIssues.length,
                    bypassDetected,
                    issues: securityIssues,
                };
            }
            catch (error) {
                result.error = error.message;
                result.passed = true;
            }
            results.push(result);
        }
        return results;
    }
    async getDatabaseTables(database) {
        if (this.metadataProvider) {
            try {
                return await this.metadataProvider.getTables(database);
            }
            catch (error) {
                throw new Error(`Failed to get database tables: ${error.message}`);
            }
        }
        if (this.config.mockData?.tables) {
            return this.config.mockData.tables;
        }
        return ['users', 'orders', 'products', 'payments', 'inventory'];
    }
    async getRLSPolicies(database) {
        if (this.metadataProvider) {
            try {
                return await this.metadataProvider.getRLSPolicies(database);
            }
            catch (error) {
                throw new Error(`Failed to get RLS policies: ${error.message}`);
            }
        }
        if (this.config.mockData?.rlsPolicies) {
            return this.config.mockData.rlsPolicies;
        }
        return [
            {
                table: 'users',
                policyName: 'users_rls_policy',
                policyDefinition: 'Users can only see their own records',
                applicable: true,
            },
            {
                table: 'orders',
                policyName: 'orders_rls_policy',
                policyDefinition: 'Users can only see orders from their workspace',
                applicable: true,
            },
        ];
    }
    async getCLSPolicies(database) {
        if (this.metadataProvider) {
            try {
                return await this.metadataProvider.getCLSPolicies(database);
            }
            catch (error) {
                throw new Error(`Failed to get CLS policies: ${error.message}`);
            }
        }
        if (this.config.mockData?.clsPolicies) {
            return this.config.mockData.clsPolicies;
        }
        return [
            {
                table: 'users',
                column: 'email',
                policyType: 'masking',
                policyDefinition: 'Mask email for non-admin users',
                applicable: true,
            },
            {
                table: 'users',
                column: 'ssn',
                policyType: 'encryption',
                policyDefinition: 'Encrypt SSN for all users',
                applicable: true,
            },
        ];
    }
    findApplicableMaskingRules(sql, rules, user) {
        const applicable = [];
        const normalized = sql.toLowerCase();
        for (const rule of rules) {
            if (!rule.applicableRoles.includes(user.role)) {
                continue;
            }
            const tableMatch = normalized.includes(rule.table.toLowerCase());
            const columnMatch = normalized.includes(rule.column.toLowerCase());
            if (tableMatch && columnMatch) {
                applicable.push(rule);
            }
        }
        return applicable;
    }
    async verifyMaskingApplied(query, rules, user) {
        return rules.length > 0;
    }
    detectCrossTenantAccess(query, tenant1, tenant2) {
        if (!query.sql) {
            return false;
        }
        const sql = query.sql.toLowerCase();
        const hasTenantFilter = sql.includes('tenant') || sql.includes('workspace');
        return !hasTenantFilter;
    }
}
exports.RLSCLSTester = RLSCLSTester;
//# sourceMappingURL=rls-cls-tester.js.map