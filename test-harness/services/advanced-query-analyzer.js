"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AdvancedQueryAnalyzer = void 0;
class AdvancedQueryAnalyzer {
    async analyzeAdvanced(query, user, connection) {
        const baseAnalysis = await this.analyzeBase(query);
        const analysis = {
            ...baseAnalysis,
            securityIssues: [],
        };
        if (query.sql) {
            analysis.queryPlan = await this.analyzeQueryPlan(query.sql, connection);
            analysis.rlsPolicies = await this.analyzeRLSPolicies(query.sql, user);
            analysis.clsPolicies = await this.analyzeCLSPolicies(query.sql, user);
            analysis.securityIssues = await this.detectSecurityIssues(query.sql);
        }
        if (connection) {
            analysis.performanceMetrics = await this.analyzePerformance(query, connection);
        }
        return analysis;
    }
    async analyzeBase(query) {
        const { QueryAnalyzer } = await Promise.resolve().then(() => require('./query-analyzer'));
        const analyzer = new QueryAnalyzer({});
        return analyzer.analyze(query);
    }
    async analyzeQueryPlan(sql, connection) {
        if (!connection) {
            return undefined;
        }
        try {
            const explainQuery = `EXPLAIN (FORMAT JSON) ${sql}`;
            return {
                plan: {},
                operations: this.parseQueryPlan(sql),
            };
        }
        catch (error) {
            return undefined;
        }
    }
    parseQueryPlan(sql) {
        const operations = [];
        const normalized = sql.toUpperCase();
        const tableMatches = normalized.matchAll(/FROM\s+(\w+)/gi);
        for (const match of tableMatches) {
            operations.push({
                type: 'Seq Scan',
                table: match[1],
            });
        }
        const indexMatches = normalized.matchAll(/INDEX\s+(\w+)/gi);
        for (const match of indexMatches) {
            operations.push({
                type: 'Index Scan',
                index: match[1],
            });
        }
        const joinMatches = normalized.matchAll(/(?:INNER|LEFT|RIGHT|FULL)\s+JOIN\s+(\w+)/gi);
        for (const match of joinMatches) {
            operations.push({
                type: 'Join',
                table: match[1],
            });
        }
        return operations;
    }
    async analyzeRLSPolicies(sql, user) {
        const policies = [];
        const normalized = sql.toUpperCase();
        const tableMatches = normalized.matchAll(/FROM\s+(\w+)/gi);
        const tables = new Set();
        for (const match of tableMatches) {
            tables.add(match[1].toLowerCase());
        }
        for (const table of tables) {
            policies.push({
                table,
                policyName: `rls_${table}_policy`,
                policyDefinition: `User ${user?.role || 'unknown'} access policy`,
                applicable: true,
            });
        }
        return policies;
    }
    async analyzeCLSPolicies(sql, user) {
        const policies = [];
        const normalized = sql.toUpperCase();
        const columnMatches = normalized.matchAll(/(\w+)\.(\w+)/gi);
        const columns = new Map();
        for (const match of columnMatches) {
            const table = match[1].toLowerCase();
            const column = match[2].toLowerCase();
            if (!columns.has(table)) {
                columns.set(table, new Set());
            }
            columns.get(table).add(column);
        }
        for (const [table, tableColumns] of columns) {
            for (const column of tableColumns) {
                if (this.isPIIColumn(column)) {
                    policies.push({
                        table,
                        column,
                        policyType: 'masking',
                        policyDefinition: `Mask ${column} for ${user?.role || 'unknown'}`,
                        applicable: true,
                    });
                }
            }
        }
        return policies;
    }
    async detectSecurityIssues(sql) {
        const issues = [];
        if (this.detectSQLInjection(sql)) {
            issues.push({
                severity: 'critical',
                type: 'sql-injection',
                description: 'Potential SQL injection vulnerability detected',
                location: sql,
                recommendation: 'Use parameterized queries',
            });
        }
        if (this.detectPrivilegeEscalation(sql)) {
            issues.push({
                severity: 'high',
                type: 'privilege-escalation',
                description: 'Potential privilege escalation attempt detected',
                location: sql,
                recommendation: 'Review user permissions',
            });
        }
        if (this.detectDataLeakage(sql)) {
            issues.push({
                severity: 'high',
                type: 'data-leakage',
                description: 'Potential data leakage pattern detected',
                location: sql,
                recommendation: 'Add appropriate filters and restrictions',
            });
        }
        if (this.detectRLSBypass(sql)) {
            issues.push({
                severity: 'critical',
                type: 'bypass-attempt',
                description: 'Potential RLS bypass attempt detected',
                location: sql,
                recommendation: 'Verify RLS policies are properly enforced',
            });
        }
        return issues;
    }
    detectSQLInjection(sql) {
        const patterns = [
            /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)/i,
            /UNION\s+SELECT/i,
            /--/,
            /\/\*/,
            /EXEC\s*\(/i,
            /xp_/i,
        ];
        return patterns.some(pattern => pattern.test(sql));
    }
    detectPrivilegeEscalation(sql) {
        const patterns = [
            /GRANT\s+/i,
            /REVOKE\s+/i,
            /ALTER\s+USER/i,
            /CREATE\s+USER/i,
        ];
        return patterns.some(pattern => pattern.test(sql));
    }
    detectDataLeakage(sql) {
        const patterns = [
            /SELECT\s+\*/i,
            /LIMIT\s+\d{4,}/i,
            /OFFSET\s+0\s*$/i,
        ];
        return patterns.some(pattern => pattern.test(sql));
    }
    detectRLSBypass(sql) {
        const patterns = [
            /SET\s+row_security\s*=\s*off/i,
            /BYPASS\s+RLS/i,
            /SUPERUSER/i,
        ];
        return patterns.some(pattern => pattern.test(sql));
    }
    async analyzePerformance(query, connection) {
        if (!connection || !query.sql) {
            return undefined;
        }
        try {
            const startTime = Date.now();
            const executionTime = Date.now() - startTime;
            return {
                executionTime,
                rowsExamined: 0,
                rowsReturned: 0,
                indexUsage: [],
                fullTableScans: [],
                slowQuery: executionTime > 1000,
            };
        }
        catch (error) {
            return undefined;
        }
    }
    isPIIColumn(column) {
        const piiPatterns = [
            /email/i,
            /ssn/i,
            /social.*security/i,
            /phone/i,
            /credit.*card/i,
            /card.*number/i,
            /passport/i,
            /driver.*license/i,
        ];
        return piiPatterns.some(pattern => pattern.test(column));
    }
    validateRLSCompliance(analysis, user) {
        const violations = [];
        if (analysis.rlsPolicies) {
            for (const policy of analysis.rlsPolicies) {
                if (!policy.applicable) {
                    violations.push(`RLS policy ${policy.policyName} not applicable for user ${user?.role}`);
                }
            }
        }
        return {
            compliant: violations.length === 0,
            violations,
        };
    }
    validateCLSCompliance(analysis, user) {
        const violations = [];
        if (analysis.clsPolicies) {
            for (const policy of analysis.clsPolicies) {
                if (!policy.applicable) {
                    violations.push(`CLS policy for ${policy.table}.${policy.column} not applicable for user ${user?.role}`);
                }
            }
        }
        return {
            compliant: violations.length === 0,
            violations,
        };
    }
}
exports.AdvancedQueryAnalyzer = AdvancedQueryAnalyzer;
//# sourceMappingURL=advanced-query-analyzer.js.map