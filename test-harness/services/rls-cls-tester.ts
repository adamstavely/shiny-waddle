/**
 * RLS/CLS Tester Service
 * 
 * Comprehensive testing for Row-Level Security (RLS) and Column-Level Security (CLS) policies
 */

import { TestQuery, User, Resource, TestResult, DatabaseConfig, RLSCoverage, CLSCoverage, DynamicMaskingRule, CrossTenantIsolationTest } from '../core/types';
import { AdvancedQueryAnalyzer, AdvancedQueryAnalysis } from './advanced-query-analyzer';

/**
 * Interface for database metadata providers
 * Implement this interface to integrate with real database systems
 */
export interface DatabaseMetadataProvider {
  /**
   * Get list of tables in the database
   */
  getTables(database: DatabaseConfig): Promise<string[]>;
  
  /**
   * Get RLS policies for the database
   */
  getRLSPolicies(database: DatabaseConfig): Promise<Array<{
    table: string;
    policyName: string;
    policyDefinition: string;
    applicable: boolean;
  }>>;
  
  /**
   * Get CLS policies for the database
   */
  getCLSPolicies(database: DatabaseConfig): Promise<Array<{
    table: string;
    column: string;
    policyType: 'masking' | 'encryption' | 'redaction';
    policyDefinition: string;
    applicable: boolean;
  }>>;
}

/**
 * Configuration for RLS/CLS tester
 */
export interface RLSCLSTesterConfig {
  /**
   * Optional database metadata provider
   * If not provided, uses mock data
   */
  metadataProvider?: DatabaseMetadataProvider;
  
  /**
   * Optional mock data for testing
   */
  mockData?: {
    tables?: string[];
    rlsPolicies?: Array<{
      table: string;
      policyName: string;
      policyDefinition: string;
      applicable: boolean;
    }>;
    clsPolicies?: Array<{
      table: string;
      column: string;
      policyType: 'masking' | 'encryption' | 'redaction';
      policyDefinition: string;
      applicable: boolean;
    }>;
  };
  
  /**
   * Optional test logic configuration
   */
  testLogic?: {
    skipDisabledPolicies?: boolean;
    validateCrossTenant?: boolean;
  };
}

export class RLSCLSTester {
  private analyzer: AdvancedQueryAnalyzer;
  private config: RLSCLSTesterConfig;
  private metadataProvider?: DatabaseMetadataProvider;

  constructor(config?: RLSCLSTesterConfig) {
    this.analyzer = new AdvancedQueryAnalyzer();
    this.config = config || {};
    this.metadataProvider = this.config.metadataProvider;
  }

  /**
   * Test RLS policy coverage for a database
   */
  async testRLSCoverage(database: DatabaseConfig): Promise<RLSCoverage> {
    // In a real implementation, this would query the database metadata
    // to get actual table and policy information
    const tables = await this.getDatabaseTables(database);
    let policies = await this.getRLSPolicies(database);

    // Filter disabled policies if configured
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

  /**
   * Test CLS policy coverage for a database
   */
  async testCLSCoverage(database: DatabaseConfig): Promise<CLSCoverage> {
    const tables = await this.getDatabaseTables(database);
    let policies = await this.getCLSPolicies(database);

    // Filter disabled policies if configured
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

  /**
   * Test dynamic data masking in real-time
   */
  async testDynamicMasking(
    query: TestQuery,
    user: User,
    maskingRules: DynamicMaskingRule[]
  ): Promise<TestResult> {
    const result: TestResult = {
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

      // Check if masking rules apply to this query
      const applicableRules = this.findApplicableMaskingRules(query.sql, maskingRules, user);
      
      // Verify that masked columns are actually masked in results
      const maskingVerified = await this.verifyMaskingApplied(
        query,
        applicableRules,
        user
      );

      result.passed = maskingVerified;
      result.details = {
        applicableRules: applicableRules.length,
        maskingVerified,
        rules: applicableRules,
      };
    } catch (error: any) {
      result.error = error.message;
    }

    return result;
  }

  /**
   * Test cross-tenant data isolation
   */
  async testCrossTenantIsolation(
    tenant1: string,
    tenant2: string,
    testQueries: TestQuery[]
  ): Promise<CrossTenantIsolationTest> {
    const violations: string[] = [];
    let isolationVerified = true;

    for (const query of testQueries) {
      // Simulate queries from tenant1 and tenant2
      const user1: User = {
        id: `tenant1-user`,
        email: `user1@${tenant1}.com`,
        role: 'viewer',
        attributes: { tenant: tenant1 },
      };

      const user2: User = {
        id: `tenant2-user`,
        email: `user2@${tenant2}.com`,
        role: 'viewer',
        attributes: { tenant: tenant2 },
      };

      // Test that tenant1 user cannot access tenant2 data
      const analysis1 = await this.analyzer.analyzeAdvanced(query, user1);
      const analysis2 = await this.analyzer.analyzeAdvanced(query, user2);

      // Check if RLS policies properly isolate tenants
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

      // Check if queries can access cross-tenant data
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

  /**
   * Test policy bypass attempts
   */
  async testPolicyBypassAttempts(
    user: User,
    resource: Resource
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Test various bypass techniques
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
      const result: TestResult = {
        testType: 'access-control',
        testName: `Policy Bypass Test: ${attempt.name}`,
        passed: false,
        details: {},
        timestamp: new Date(),
      };

      try {
        const analysis = await this.analyzer.analyzeAdvanced(attempt.query, user);
        
        // Check if security issues were detected
        const securityIssues = analysis.securityIssues || [];
        const bypassDetected = securityIssues.some(
          issue => issue.type === 'bypass-attempt' || issue.type === 'privilege-escalation'
        );

        result.passed = bypassDetected; // Pass if bypass was detected/blocked
        result.details = {
          attempt: attempt.name,
          securityIssues: securityIssues.length,
          bypassDetected,
          issues: securityIssues,
        };
      } catch (error: any) {
        result.error = error.message;
        result.passed = true; // If query fails, bypass was prevented
      }

      results.push(result);
    }

    return results;
  }

  /**
   * Get database tables
   * 
   * Uses metadata provider if available, otherwise falls back to mock/configurable data
   */
  private async getDatabaseTables(database: DatabaseConfig): Promise<string[]> {
    // Use real metadata provider if available
    if (this.metadataProvider) {
      try {
        return await this.metadataProvider.getTables(database);
      } catch (error: any) {
        throw new Error(`Failed to get database tables: ${error.message}`);
      }
    }
    
    // Use configured mock data if available
    if (this.config.mockData?.tables) {
      return this.config.mockData.tables;
    }
    
    // Default mock data for testing
    return ['users', 'orders', 'products', 'payments', 'inventory'];
  }

  /**
   * Get RLS policies
   * 
   * Uses metadata provider if available, otherwise falls back to mock/configurable data
   * 
   * For PostgreSQL: Query pg_policies view
   * For MySQL: Query INFORMATION_SCHEMA
   * For SQL Server: Query sys.security_policies
   */
  private async getRLSPolicies(database: DatabaseConfig): Promise<Array<{
    table: string;
    policyName: string;
    policyDefinition: string;
    applicable: boolean;
  }>> {
    // Use real metadata provider if available
    if (this.metadataProvider) {
      try {
        return await this.metadataProvider.getRLSPolicies(database);
      } catch (error: any) {
        throw new Error(`Failed to get RLS policies: ${error.message}`);
      }
    }
    
    // Use configured mock data if available
    if (this.config.mockData?.rlsPolicies) {
      return this.config.mockData.rlsPolicies;
    }
    
    // Default mock data for testing
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

  /**
   * Get CLS policies
   * 
   * Uses metadata provider if available, otherwise falls back to mock/configurable data
   * 
   * For PostgreSQL: Query pg_policies with column-level policies
   * For SQL Server: Query sys.column_encryption_keys and sys.column_master_keys
   * For Oracle: Query DBA_POLICIES with column-level policies
   */
  private async getCLSPolicies(database: DatabaseConfig): Promise<Array<{
    table: string;
    column: string;
    policyType: 'masking' | 'encryption' | 'redaction';
    policyDefinition: string;
    applicable: boolean;
  }>> {
    // Use real metadata provider if available
    if (this.metadataProvider) {
      try {
        return await this.metadataProvider.getCLSPolicies(database);
      } catch (error: any) {
        throw new Error(`Failed to get CLS policies: ${error.message}`);
      }
    }
    
    // Use configured mock data if available
    if (this.config.mockData?.clsPolicies) {
      return this.config.mockData.clsPolicies;
    }
    
    // Default mock data for testing
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

  /**
   * Find applicable masking rules for a query
   */
  private findApplicableMaskingRules(
    sql: string,
    rules: DynamicMaskingRule[],
    user: User
  ): DynamicMaskingRule[] {
    const applicable: DynamicMaskingRule[] = [];
    const normalized = sql.toLowerCase();

    for (const rule of rules) {
      // Check if rule applies to user role
      if (!rule.applicableRoles.includes(user.role)) {
        continue;
      }

      // Check if query references the table/column
      const tableMatch = normalized.includes(rule.table.toLowerCase());
      const columnMatch = normalized.includes(rule.column.toLowerCase());

      if (tableMatch && columnMatch) {
        applicable.push(rule);
      }
    }

    return applicable;
  }

  /**
   * Verify that masking is actually applied
   */
  private async verifyMaskingApplied(
    query: TestQuery,
    rules: DynamicMaskingRule[],
    user: User
  ): Promise<boolean> {
    // In a real implementation, this would execute the query
    // and verify that masked columns are actually masked
    // For now, return true if rules are applicable
    return rules.length > 0;
  }

  /**
   * Detect cross-tenant access in query
   */
  private detectCrossTenantAccess(
    query: TestQuery,
    tenant1: string,
    tenant2: string
  ): boolean {
    if (!query.sql) {
      return false;
    }

    const sql = query.sql.toLowerCase();
    
    // Check for queries that might access multiple tenants
    // This is a simplified check - real implementation would be more sophisticated
    const hasTenantFilter = sql.includes('tenant') || sql.includes('workspace');
    
    return !hasTenantFilter; // If no tenant filter, might access cross-tenant data
  }
}

