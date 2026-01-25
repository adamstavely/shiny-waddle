/**
 * GraphQL Security Validator
 * 
 * Tests GraphQL query depth limits, complexity limits, introspection security, and field authorization
 */

export interface GraphQLConfig {
  endpoint: string;
  schema: string;
  maxDepth?: number;
  maxComplexity?: number;
  introspectionEnabled: boolean;
}

export interface GraphQLSecurityTestResult {
  passed: boolean;
  endpoint: string;
  issues: Array<{
    type: 'no-depth-limit' | 'no-complexity-limit' | 'introspection-enabled' | 'field-auth-bypass' | 'error-leakage';
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
  }>;
  depthTest: DepthTestResult;
  complexityTest: ComplexityTestResult;
  introspectionTest: IntrospectionTestResult;
}

export interface DepthTestResult {
  hasLimit: boolean;
  maxDepth?: number;
  tested: boolean;
  issues: string[];
}

export interface ComplexityTestResult {
  hasLimit: boolean;
  maxComplexity?: number;
  tested: boolean;
  issues: string[];
}

export interface IntrospectionTestResult {
  enabled: boolean;
  secure: boolean;
  issues: string[];
}

export interface AuthResult {
  authorized: boolean;
  field: string;
  issues: string[];
}

export interface ErrorSecurityResult {
  secure: boolean;
  leaksInfo: boolean;
  issues: string[];
}

export class GraphQLSecurityValidator {
  /**
   * Test query depth limits
   */
  async testQueryDepthLimits(
    config: GraphQLConfig
  ): Promise<GraphQLSecurityTestResult> {
    const issues: GraphQLSecurityTestResult['issues'] = [];

    // Test depth limit
    const depthTest = this.testDepth(config);
    if (!depthTest.hasLimit) {
      issues.push({
        type: 'no-depth-limit',
        severity: 'critical',
        message: 'GraphQL endpoint has no query depth limit configured',
      });
    } else if (depthTest.maxDepth && depthTest.maxDepth > 10) {
      issues.push({
        type: 'no-depth-limit',
        severity: 'medium',
        message: `Query depth limit is very high (${depthTest.maxDepth}) - may allow deep nesting attacks`,
      });
    }

    // Test complexity limit
    const complexityTest = this.testComplexity(config);
    if (!complexityTest.hasLimit) {
      issues.push({
        type: 'no-complexity-limit',
        severity: 'high',
        message: 'GraphQL endpoint has no query complexity limit configured',
      });
    }

    // Test introspection
    const introspectionTest = await this.testIntrospectionSecurity(config);
    if (introspectionTest.enabled) {
      issues.push({
        type: 'introspection-enabled',
        severity: config.endpoint.includes('prod') ? 'critical' : 'medium',
        message: 'GraphQL introspection is enabled - may expose schema information',
      });
    }

    const criticalIssues = issues.filter(i => i.severity === 'critical').length;
    const highIssues = issues.filter(i => i.severity === 'high').length;

    return {
      passed: criticalIssues === 0 && highIssues === 0,
      endpoint: config.endpoint,
      issues,
      depthTest,
      complexityTest,
      introspectionTest,
    };
  }

  /**
   * Test query complexity
   */
  async testQueryComplexity(
    config: GraphQLConfig
  ): Promise<ComplexityTestResult> {
    const issues: string[] = [];

    if (!config.maxComplexity) {
      return {
        hasLimit: false,
        tested: false,
        issues: ['No complexity limit configured'],
      };
    }

    // Check if complexity limit is reasonable
    if (config.maxComplexity > 1000) {
      issues.push('Complexity limit is very high - may allow expensive queries');
    }

    // Test with a complex query (simplified)
    const testQuery = this.generateComplexQuery(config.maxComplexity);
    const complexity = this.calculateComplexity(testQuery);

    if (complexity > config.maxComplexity) {
      issues.push(`Test query exceeded complexity limit: ${complexity} > ${config.maxComplexity}`);
    }

    return {
      hasLimit: true,
      maxComplexity: config.maxComplexity,
      tested: true,
      issues,
    };
  }

  /**
   * Test introspection security
   */
  async testIntrospectionSecurity(
    config: GraphQLConfig
  ): Promise<IntrospectionTestResult> {
    const issues: string[] = [];

    if (config.introspectionEnabled) {
      // Introspection should be disabled in production
      if (config.endpoint.includes('prod') || config.endpoint.includes('production')) {
        issues.push('Introspection should be disabled in production');
      }

      return {
        enabled: true,
        secure: false,
        issues,
      };
    }

    return {
      enabled: false,
      secure: true,
      issues: [],
    };
  }

  /**
   * Validate field authorization
   */
  async validateFieldAuthorization(
    config: GraphQLConfig,
    field: string
  ): Promise<AuthResult> {
    const issues: string[] = [];

    // Parse schema to check if field has authorization
    // This is a simplified check - real implementation would parse the GraphQL schema
    const schemaLower = config.schema.toLowerCase();
    const fieldLower = field.toLowerCase();

    // Check if field is mentioned in schema
    if (!schemaLower.includes(fieldLower)) {
      issues.push(`Field ${field} not found in schema`);
    }

    // Check for authorization directives (simplified)
    const authDirectives = ['@auth', '@requiresAuth', '@hasRole', '@hasPermission'];
    const hasAuthDirective = authDirectives.some(directive =>
      schemaLower.includes(directive.toLowerCase())
    );

    if (!hasAuthDirective) {
      issues.push(`Field ${field} may not have authorization configured`);
    }

    return {
      authorized: hasAuthDirective && issues.length === 0,
      field,
      issues,
    };
  }

  /**
   * Test error message security
   */
  async testErrorMessageSecurity(
    config: GraphQLConfig
  ): Promise<ErrorSecurityResult> {
    const issues: string[] = [];

    // Check if error messages might leak information
    // This is a simplified check - real implementation would test actual error responses

    const sensitivePatterns = [
      /database/i,
      /sql/i,
      /password/i,
      /secret/i,
      /key/i,
      /token/i,
      /stack trace/i,
    ];

    // Check schema for potential information leakage
    for (const pattern of sensitivePatterns) {
      if (pattern.test(config.schema)) {
        issues.push(`Schema may contain sensitive information: ${pattern.source}`);
      }
    }

    return {
      secure: issues.length === 0,
      leaksInfo: issues.length > 0,
      issues,
    };
  }

  /**
   * Test depth limit
   */
  private testDepth(config: GraphQLConfig): DepthTestResult {
    const issues: string[] = [];

    if (!config.maxDepth) {
      return {
        hasLimit: false,
        tested: false,
        issues: ['No depth limit configured'],
      };
    }

    // Check if depth limit is reasonable
    if (config.maxDepth > 10) {
      issues.push(`Depth limit is very high (${config.maxDepth}) - may allow deep nesting attacks`);
    }

    // Test with a deep query (simplified)
    const testQuery = this.generateDeepQuery(config.maxDepth);
    const depth = this.calculateDepth(testQuery);

    if (depth > config.maxDepth) {
      issues.push(`Test query exceeded depth limit: ${depth} > ${config.maxDepth}`);
    }

    return {
      hasLimit: true,
      maxDepth: config.maxDepth,
      tested: true,
      issues,
    };
  }

  /**
   * Test complexity
   */
  private testComplexity(config: GraphQLConfig): ComplexityTestResult {
    return this.testQueryComplexity(config);
  }

  /**
   * Generate a deep query for testing
   */
  private generateDeepQuery(maxDepth: number): string {
    let query = 'query {';
    for (let i = 0; i < maxDepth + 1; i++) {
      query += `user {`;
    }
    query += 'id';
    for (let i = 0; i < maxDepth + 1; i++) {
      query += '}';
    }
    query += '}';
    return query;
  }

  /**
   * Calculate query depth
   */
  private calculateDepth(query: string): number {
    let depth = 0;
    let maxDepth = 0;

    for (const char of query) {
      if (char === '{') {
        depth++;
        maxDepth = Math.max(maxDepth, depth);
      } else if (char === '}') {
        depth--;
      }
    }

    return maxDepth;
  }

  /**
   * Generate a complex query for testing
   */
  private generateComplexQuery(maxComplexity: number): string {
    // Generate a query with multiple fields and nested objects
    let query = 'query {';
    const fields = Math.min(20, Math.floor(maxComplexity / 10));
    for (let i = 0; i < fields; i++) {
      query += `field${i} { subField { value } } `;
    }
    query += '}';
    return query;
  }

  /**
   * Calculate query complexity
   */
  private calculateComplexity(query: string): number {
    // Simplified complexity calculation
    // Real implementation would use a proper GraphQL complexity calculator
    const fieldMatches = query.match(/\w+\s*{/g);
    const fieldCount = fieldMatches ? fieldMatches.length : 0;
    return fieldCount * 10; // Simplified: each field adds 10 to complexity
  }
}

