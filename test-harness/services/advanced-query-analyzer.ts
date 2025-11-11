/**
 * Advanced Query Analyzer Service
 * 
 * Deep analysis of queries including SQL parsing, query plans, RLS/CLS testing
 */

import { TestQuery, User } from '../core/types';
import { QueryAnalysis } from './query-analyzer';

export interface AdvancedQueryAnalysis extends QueryAnalysis {
  queryPlan?: QueryPlan;
  rlsPolicies?: RLSPolicy[];
  clsPolicies?: CLSPolicy[];
  performanceMetrics?: PerformanceMetrics;
  securityIssues?: SecurityIssue[];
}

export interface QueryPlan {
  plan: any;
  estimatedCost?: number;
  estimatedRows?: number;
  actualRows?: number;
  executionTime?: number;
  operations: QueryOperation[];
}

export interface QueryOperation {
  type: string;
  table?: string;
  index?: string;
  filter?: string;
  cost?: number;
  rows?: number;
}

export interface RLSPolicy {
  table: string;
  policyName: string;
  policyDefinition: string;
  applicable: boolean;
}

export interface CLSPolicy {
  table: string;
  column: string;
  policyType: 'masking' | 'encryption' | 'redaction';
  policyDefinition: string;
  applicable: boolean;
}

export interface PerformanceMetrics {
  executionTime: number;
  rowsExamined: number;
  rowsReturned: number;
  indexUsage: string[];
  fullTableScans: string[];
  slowQuery: boolean;
}

export interface SecurityIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: 'sql-injection' | 'privilege-escalation' | 'data-leakage' | 'bypass-attempt';
  description: string;
  location?: string;
  recommendation?: string;
}

export class AdvancedQueryAnalyzer {
  /**
   * Perform advanced query analysis
   */
  async analyzeAdvanced(
    query: TestQuery,
    user?: User,
    connection?: any
  ): Promise<AdvancedQueryAnalysis> {
    const baseAnalysis = await this.analyzeBase(query);
    
    const analysis: AdvancedQueryAnalysis = {
      ...baseAnalysis,
      securityIssues: [],
    };

    // Parse SQL if available
    if (query.sql) {
      analysis.queryPlan = await this.analyzeQueryPlan(query.sql, connection);
      analysis.rlsPolicies = await this.analyzeRLSPolicies(query.sql, user);
      analysis.clsPolicies = await this.analyzeCLSPolicies(query.sql, user);
      analysis.securityIssues = await this.detectSecurityIssues(query.sql);
    }

    // Performance analysis if connection available
    if (connection) {
      analysis.performanceMetrics = await this.analyzePerformance(
        query,
        connection
      );
    }

    return analysis;
  }

  /**
   * Analyze base query (delegates to QueryAnalyzer)
   */
  private async analyzeBase(query: TestQuery): Promise<QueryAnalysis> {
    const { QueryAnalyzer } = await import('./query-analyzer');
    const analyzer = new QueryAnalyzer({});
    return analyzer.analyze(query);
  }

  /**
   * Analyze query execution plan
   */
  async analyzeQueryPlan(
    sql: string,
    connection?: any
  ): Promise<QueryPlan | undefined> {
    if (!connection) {
      return undefined;
    }

    try {
      // For PostgreSQL
      const explainQuery = `EXPLAIN (FORMAT JSON) ${sql}`;
      // const result = await connection.query(explainQuery);
      // const plan = result.rows[0]['QUERY PLAN'];

      // Parse query plan
      return {
        plan: {},
        operations: this.parseQueryPlan(sql),
      };
    } catch (error) {
      return undefined;
    }
  }

  /**
   * Parse query plan from SQL
   */
  private parseQueryPlan(sql: string): QueryOperation[] {
    const operations: QueryOperation[] = [];
    const normalized = sql.toUpperCase();

    // Detect table scans
    const tableMatches = normalized.matchAll(/FROM\s+(\w+)/gi);
    for (const match of tableMatches) {
      operations.push({
        type: 'Seq Scan',
        table: match[1],
      });
    }

    // Detect index usage
    const indexMatches = normalized.matchAll(/INDEX\s+(\w+)/gi);
    for (const match of indexMatches) {
      operations.push({
        type: 'Index Scan',
        index: match[1],
      });
    }

    // Detect joins
    const joinMatches = normalized.matchAll(/(?:INNER|LEFT|RIGHT|FULL)\s+JOIN\s+(\w+)/gi);
    for (const match of joinMatches) {
      operations.push({
        type: 'Join',
        table: match[1],
      });
    }

    return operations;
  }

  /**
   * Analyze Row-Level Security policies
   */
  async analyzeRLSPolicies(
    sql: string,
    user?: User
  ): Promise<RLSPolicy[]> {
    const policies: RLSPolicy[] = [];
    const normalized = sql.toUpperCase();

    // Extract table names
    const tableMatches = normalized.matchAll(/FROM\s+(\w+)/gi);
    const tables = new Set<string>();
    for (const match of tableMatches) {
      tables.add(match[1].toLowerCase());
    }

    // Check for RLS policies (simplified - would need actual database metadata)
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

  /**
   * Analyze Column-Level Security policies
   */
  async analyzeCLSPolicies(
    sql: string,
    user?: User
  ): Promise<CLSPolicy[]> {
    const policies: CLSPolicy[] = [];
    const normalized = sql.toUpperCase();

    // Extract column references
    const columnMatches = normalized.matchAll(/(\w+)\.(\w+)/gi);
    const columns = new Map<string, Set<string>>();

    for (const match of columnMatches) {
      const table = match[1].toLowerCase();
      const column = match[2].toLowerCase();
      if (!columns.has(table)) {
        columns.set(table, new Set());
      }
      columns.get(table)!.add(column);
    }

    // Check for CLS policies
    for (const [table, tableColumns] of columns) {
      for (const column of tableColumns) {
        // Check if column is PII
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

  /**
   * Detect security issues in query
   */
  async detectSecurityIssues(sql: string): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    // Detect SQL injection patterns
    if (this.detectSQLInjection(sql)) {
      issues.push({
        severity: 'critical',
        type: 'sql-injection',
        description: 'Potential SQL injection vulnerability detected',
        location: sql,
        recommendation: 'Use parameterized queries',
      });
    }

    // Detect privilege escalation attempts
    if (this.detectPrivilegeEscalation(sql)) {
      issues.push({
        severity: 'high',
        type: 'privilege-escalation',
        description: 'Potential privilege escalation attempt detected',
        location: sql,
        recommendation: 'Review user permissions',
      });
    }

    // Detect data leakage patterns
    if (this.detectDataLeakage(sql)) {
      issues.push({
        severity: 'high',
        type: 'data-leakage',
        description: 'Potential data leakage pattern detected',
        location: sql,
        recommendation: 'Add appropriate filters and restrictions',
      });
    }

    // Detect RLS bypass attempts
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

  /**
   * Detect SQL injection patterns
   */
  private detectSQLInjection(sql: string): boolean {
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

  /**
   * Detect privilege escalation attempts
   */
  private detectPrivilegeEscalation(sql: string): boolean {
    const patterns = [
      /GRANT\s+/i,
      /REVOKE\s+/i,
      /ALTER\s+USER/i,
      /CREATE\s+USER/i,
    ];

    return patterns.some(pattern => pattern.test(sql));
  }

  /**
   * Detect data leakage patterns
   */
  private detectDataLeakage(sql: string): boolean {
    const patterns = [
      /SELECT\s+\*/i,
      /LIMIT\s+\d{4,}/i, // Large limit
      /OFFSET\s+0\s*$/i, // No offset
    ];

    return patterns.some(pattern => pattern.test(sql));
  }

  /**
   * Detect RLS bypass attempts
   */
  private detectRLSBypass(sql: string): boolean {
    const patterns = [
      /SET\s+row_security\s*=\s*off/i,
      /BYPASS\s+RLS/i,
      /SUPERUSER/i,
    ];

    return patterns.some(pattern => pattern.test(sql));
  }

  /**
   * Analyze query performance
   */
  async analyzePerformance(
    query: TestQuery,
    connection?: any
  ): Promise<PerformanceMetrics | undefined> {
    if (!connection || !query.sql) {
      return undefined;
    }

    try {
      const startTime = Date.now();
      // const result = await connection.query(query.sql);
      const executionTime = Date.now() - startTime;

      return {
        executionTime,
        rowsExamined: 0, // Would come from query plan
        rowsReturned: 0, // Would come from result
        indexUsage: [],
        fullTableScans: [],
        slowQuery: executionTime > 1000, // > 1 second
      };
    } catch (error) {
      return undefined;
    }
  }

  /**
   * Check if column is PII
   */
  private isPIIColumn(column: string): boolean {
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

  /**
   * Validate query against RLS policies
   */
  validateRLSCompliance(
    analysis: AdvancedQueryAnalysis,
    user?: User
  ): {
    compliant: boolean;
    violations: string[];
  } {
    const violations: string[] = [];

    if (analysis.rlsPolicies) {
      for (const policy of analysis.rlsPolicies) {
        if (!policy.applicable) {
          violations.push(
            `RLS policy ${policy.policyName} not applicable for user ${user?.role}`
          );
        }
      }
    }

    return {
      compliant: violations.length === 0,
      violations,
    };
  }

  /**
   * Validate query against CLS policies
   */
  validateCLSCompliance(
    analysis: AdvancedQueryAnalysis,
    user?: User
  ): {
    compliant: boolean;
    violations: string[];
  } {
    const violations: string[] = [];

    if (analysis.clsPolicies) {
      for (const policy of analysis.clsPolicies) {
        if (!policy.applicable) {
          violations.push(
            `CLS policy for ${policy.table}.${policy.column} not applicable for user ${user?.role}`
          );
        }
      }
    }

    return {
      compliant: violations.length === 0,
      violations,
    };
  }
}

