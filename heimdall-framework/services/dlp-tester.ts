/**
 * Data Loss Prevention (DLP) Tester Service
 * 
 * Testing for data exfiltration detection, API response validation, and bulk export controls
 */

import { TestResult, DLPPattern, DataExfiltrationTest, BulkExportTest, DataOperation, User, Resource, TestQuery } from '../core/types';

/**
 * Configuration for DLP Tester
 */
export interface DLPTesterConfig {
  /**
   * Custom DLP patterns (if not provided, uses defaults)
   */
  patterns?: DLPPattern[];
  
  /**
   * Bulk export limits
   */
  bulkExportLimits?: {
    csv?: number; // max records
    json?: number;
    excel?: number;
    api?: number;
  };
  
  /**
   * PII field detection rules
   */
  piiDetectionRules?: Array<{
    fieldName: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
  
  /**
   * Export restrictions (from contract rules)
   */
  exportRestrictions?: {
    restrictedFields?: string[];
    requireMasking?: boolean;
    allowedFormats?: string[];
  };
  
  /**
   * Aggregation requirements (from contract rules)
   */
  aggregationRequirements?: {
    minK?: number;
    requireAggregation?: boolean;
  };
  
  /**
   * Field restrictions (from contract rules)
   */
  fieldRestrictions?: {
    disallowedFields?: string[];
    allowedFields?: string[];
  };
  
  /**
   * Join restrictions (from contract rules)
   */
  joinRestrictions?: {
    disallowedJoins?: string[];
  };
}

export class DLPTester {
  private patterns: DLPPattern[] = [];
  private config: DLPTesterConfig;

  constructor(config?: DLPTesterConfig | DLPPattern[]) {
    // Support both old pattern array and new config object for backward compatibility
    if (Array.isArray(config)) {
      this.patterns = config.length > 0 ? config : this.getDefaultPatterns();
      this.config = {};
    } else {
      this.config = config || {};
      this.patterns = this.config.patterns || this.getDefaultPatterns();
    }
    
    // Merge custom PII detection rules if provided
    if (this.config.piiDetectionRules) {
      // Add custom patterns from PII detection rules
      this.config.piiDetectionRules.forEach(rule => {
        this.patterns.push({
          name: `Custom PII: ${rule.fieldName}`,
          type: 'regex',
          pattern: rule.pattern.source,
          severity: rule.severity,
        });
      });
    }
  }

  /**
   * Test data exfiltration
   */
  async testDataExfiltration(
    user: User,
    dataOperation: DataOperation
  ): Promise<TestResult> {
    const result: TestResult = {
      testType: 'dlp',
      testName: 'Data Exfiltration Test',
      passed: false,
      details: {},
      timestamp: new Date(),
    };

    try {
      // Check for sensitive data patterns
      const detectedPatterns = this.detectSensitiveData(dataOperation.data, this.patterns);
      
      const exfiltrationTest: DataExfiltrationTest = {
        user,
        operation: dataOperation.type === 'export' ? 'export' : 
                   dataOperation.type === 'read' ? 'query' : 'api-call',
        dataSize: this.calculateDataSize(dataOperation.data),
        detected: detectedPatterns.length > 0,
        pattern: detectedPatterns.length > 0 ? detectedPatterns[0] : undefined,
      };

      // Exfiltration detected if sensitive patterns found
      result.passed = !exfiltrationTest.detected; // Pass if no exfiltration detected
      result.details = {
        exfiltrationTest,
        detectedPatterns,
      };
    } catch (error: any) {
      result.error = error.message;
    }

    return result;
  }

  /**
   * Validate API response doesn't leak sensitive data
   */
  async validateAPIResponse(
    apiResponse: any,
    allowedFields: string[],
    piiFields: string[]
  ): Promise<TestResult> {
    const result: TestResult = {
      testType: 'dlp',
      testName: 'API Response Validation',
      passed: false,
      details: {},
      timestamp: new Date(),
    };

    try {
      const violations: string[] = [];
      
      // Check for PII fields in response
      const responseFields = this.extractFields(apiResponse);
      const leakedPII = responseFields.filter(field => 
        piiFields.includes(field) && !allowedFields.includes(field)
      );

      if (leakedPII.length > 0) {
        violations.push(`PII fields leaked: ${leakedPII.join(', ')}`);
      }

      // Check for disallowed fields
      const disallowedFields = responseFields.filter(field => 
        !allowedFields.includes(field)
      );

      if (disallowedFields.length > 0) {
        violations.push(`Disallowed fields in response: ${disallowedFields.join(', ')}`);
      }

      // Check for sensitive data patterns
      const sensitiveData = this.detectSensitiveData(apiResponse, this.patterns);
      if (sensitiveData.length > 0) {
        violations.push(`Sensitive data patterns detected: ${sensitiveData.map(p => p.name).join(', ')}`);
      }

      result.passed = violations.length === 0;
      result.details = {
        violations,
        responseFields,
        allowedFields,
        piiFields,
        sensitiveData,
      };
    } catch (error: any) {
      result.error = error.message;
    }

    return result;
  }

  /**
   * Test query result validation
   */
  async testQueryResultValidation(
    query: TestQuery,
    user: User,
    expectedFields: string[]
  ): Promise<TestResult> {
    // Validate field restrictions and join restrictions (from contract rules)
    const fieldViolations = this.validateFieldRestrictions(query, expectedFields);
    const joinViolations = this.validateJoinRestrictions(query);
    
    if (fieldViolations.length > 0 || joinViolations.length > 0) {
      return {
        testType: 'dlp',
        testName: 'Query Result Validation',
        passed: false,
        details: {
          violations: [...fieldViolations, ...joinViolations],
        },
        timestamp: new Date(),
      };
    }
    const result: TestResult = {
      testType: 'dlp',
      testName: 'Query Result Validation',
      passed: false,
      details: {},
      timestamp: new Date(),
    };

    try {
      // Extract fields from query
      const queryFields = this.extractQueryFields(query);
      
      // Check if query only requests allowed fields
      const disallowedFields = queryFields.filter(field => 
        !expectedFields.includes(field)
      );

      result.passed = disallowedFields.length === 0;
      result.details = {
        query,
        user,
        queryFields,
        expectedFields,
        disallowedFields,
      };
    } catch (error: any) {
      result.error = error.message;
    }

    return result;
  }

  /**
   * Test bulk export controls
   */
  async testBulkExportControls(
    user: User,
    exportRequest: { type: 'csv' | 'json' | 'excel' | 'api'; recordCount: number; fields?: string[] }
  ): Promise<TestResult> {
    const result: TestResult = {
      testType: 'dlp',
      testName: 'Bulk Export Controls Test',
      passed: false,
      details: {},
      timestamp: new Date(),
    };

    try {
      const bulkExportTest: BulkExportTest = {
        user,
        exportType: exportRequest.type,
        recordCount: exportRequest.recordCount,
        allowed: false,
      };

      // Check export restrictions (from contract rules)
      const exportRestrictionViolations = this.validateExportRestrictions(
        exportRequest.type,
        exportRequest.fields || []
      );
      
      if (exportRestrictionViolations.length > 0) {
        bulkExportTest.allowed = false;
        bulkExportTest.reason = exportRestrictionViolations.join('; ');
        result.passed = false;
        result.details = {
          bulkExportTest,
          violations: exportRestrictionViolations,
        };
        return result;
      }

      // Check export limits - use configured limits or defaults based on user role
      const defaultLimits: Record<string, number> = {
        admin: 100000,
        researcher: 10000,
        analyst: 5000,
        viewer: 1000,
      };

      // Use configured limit for export type if available, otherwise use role-based default
      const configuredLimit = this.config.bulkExportLimits?.[exportRequest.type];
      const roleBasedLimit = defaultLimits[user.role] || 1000;
      const userLimit = configuredLimit ?? roleBasedLimit;
      
      bulkExportTest.allowed = exportRequest.recordCount <= userLimit;

      if (!bulkExportTest.allowed) {
        bulkExportTest.reason = `Export exceeds limit of ${userLimit} records for role ${user.role}`;
      }

      result.passed = bulkExportTest.allowed;
      result.details = {
        bulkExportTest,
        userLimit,
      };
    } catch (error: any) {
      result.error = error.message;
    }

    return result;
  }

  /**
   * Detect sensitive data leakage
   */
  async detectSensitiveDataLeakage(
    response: any,
    patterns: DLPPattern[]
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];
    const detectedPatterns = this.detectSensitiveData(response, patterns);

    for (const pattern of detectedPatterns) {
      const result: TestResult = {
        testType: 'dlp',
        testName: `Sensitive Data Detection: ${pattern.name}`,
        passed: false, // Failed because sensitive data was detected
        details: {
          pattern,
          severity: pattern.severity,
        },
        timestamp: new Date(),
      };

      results.push(result);
    }

    return results;
  }

  /**
   * Get default DLP patterns
   */
  private getDefaultPatterns(): DLPPattern[] {
    return [
      {
        name: 'Email Address',
        type: 'regex',
        pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
        severity: 'medium',
      },
      {
        name: 'SSN',
        type: 'regex',
        pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
        severity: 'critical',
      },
      {
        name: 'Credit Card',
        type: 'regex',
        pattern: '\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b',
        severity: 'critical',
      },
    ];
  }

  /**
   * Detect sensitive data in data
   */
  private detectSensitiveData(data: any, patterns: DLPPattern[]): DLPPattern[] {
    const detected: DLPPattern[] = [];
    const dataString = JSON.stringify(data);

    for (const pattern of patterns) {
      if (pattern.type === 'regex') {
        const regex = new RegExp(pattern.pattern, 'gi');
        if (regex.test(dataString)) {
          detected.push(pattern);
        }
      }
    }

    return detected;
  }

  /**
   * Validate export restrictions (from contract rules)
   */
  private validateExportRestrictions(
    exportType: string,
    fields: string[]
  ): string[] {
    const violations: string[] = [];
    const restrictions = this.config.exportRestrictions;
    
    if (!restrictions) {
      return violations;
    }
    
    // Check restricted fields
    if (restrictions.restrictedFields && restrictions.restrictedFields.length > 0) {
      const restrictedInExport = fields.filter(field => 
        restrictions.restrictedFields!.includes(field)
      );
      if (restrictedInExport.length > 0) {
        violations.push(
          `Restricted fields cannot be exported: ${restrictedInExport.join(', ')}`
        );
      }
    }
    
    // Check allowed formats
    if (restrictions.allowedFormats && restrictions.allowedFormats.length > 0) {
      if (!restrictions.allowedFormats.includes(exportType)) {
        violations.push(
          `Export format ${exportType} is not allowed. Allowed formats: ${restrictions.allowedFormats.join(', ')}`
        );
      }
    }
    
    // Note: requireMasking is checked separately in the export process
    
    return violations;
  }
  
  /**
   * Validate field restrictions (from contract rules)
   */
  private validateFieldRestrictions(
    query: TestQuery,
    expectedFields: string[]
  ): string[] {
    const violations: string[] = [];
    const restrictions = this.config.fieldRestrictions;
    
    if (!restrictions) {
      return violations;
    }
    
    // Extract fields from query (simplified - would need proper SQL parsing in production)
    const queryFields = this.extractFieldsFromQuery(query.sql || '');
    
    // Check disallowed fields
    if (restrictions.disallowedFields && restrictions.disallowedFields.length > 0) {
      const disallowedInQuery = queryFields.filter(field => 
        restrictions.disallowedFields!.some(disallowed => 
          field.toLowerCase().includes(disallowed.toLowerCase())
        )
      );
      if (disallowedInQuery.length > 0) {
        violations.push(
          `Disallowed fields accessed: ${disallowedInQuery.join(', ')}`
        );
      }
    }
    
    // Check allowed fields (whitelist)
    if (restrictions.allowedFields && restrictions.allowedFields.length > 0) {
      const notAllowed = queryFields.filter(field => 
        !restrictions.allowedFields!.some(allowed => 
          field.toLowerCase().includes(allowed.toLowerCase())
        )
      );
      if (notAllowed.length > 0) {
        violations.push(
          `Fields not in allowed list: ${notAllowed.join(', ')}`
        );
      }
    }
    
    return violations;
  }
  
  /**
   * Validate join restrictions (from contract rules)
   */
  private validateJoinRestrictions(query: TestQuery): string[] {
    const violations: string[] = [];
    const restrictions = this.config.joinRestrictions;
    
    if (!restrictions || !restrictions.disallowedJoins || restrictions.disallowedJoins.length === 0) {
      return violations;
    }
    
    // Extract joins from query (simplified - would need proper SQL parsing in production)
    const queryLower = (query.sql || '').toLowerCase();
    const joins = this.extractJoinsFromQuery(queryLower);
    
    for (const disallowedJoin of restrictions.disallowedJoins) {
      if (joins.some(join => join.toLowerCase().includes(disallowedJoin.toLowerCase()))) {
        violations.push(`Disallowed join detected: ${disallowedJoin}`);
      }
    }
    
    return violations;
  }
  
  /**
   * Validate aggregation requirements (from contract rules)
   */
  validateAggregationRequirements(query: TestQuery): { passed: boolean; violations: string[] } {
    const violations: string[] = [];
    const requirements = this.config.aggregationRequirements;
    
    if (!requirements) {
      return { passed: true, violations: [] };
    }
    
    const queryLower = (query.sql || '').toLowerCase();
    
    // Check if aggregation is required
    if (requirements.requireAggregation) {
      const hasAggregation = queryLower.includes('group by') || 
                            queryLower.includes('count(') ||
                            queryLower.includes('sum(') ||
                            queryLower.includes('avg(') ||
                            queryLower.includes('min(') ||
                            queryLower.includes('max(');
      
      if (!hasAggregation) {
        violations.push('Aggregation is required but not found in query');
      }
    }
    
    // Check minimum k (would need to parse GROUP BY and COUNT in production)
    if (requirements.minK && requirements.minK > 0) {
      // This is a simplified check - in production, would need to parse the query
      // and verify that COUNT(*) >= minK or that GROUP BY groups have at least minK records
      const hasMinK = queryLower.includes(`having count(*) >= ${requirements.minK}`) ||
                      queryLower.includes(`having count(*) > ${requirements.minK - 1}`);
      
      if (requirements.requireAggregation && !hasMinK) {
        violations.push(`Minimum aggregation k=${requirements.minK} required but not found`);
      }
    }
    
    return {
      passed: violations.length === 0,
      violations,
    };
  }
  
  /**
   * Extract fields from SQL query (simplified implementation)
   */
  private extractFieldsFromQuery(sql: string): string[] {
    const fields: string[] = [];
    // Simple regex to extract field names from SELECT clause
    const selectMatch = sql.match(/select\s+(.+?)\s+from/i);
    if (selectMatch) {
      const selectClause = selectMatch[1];
      // Split by comma and extract field names
      const fieldParts = selectClause.split(',').map(f => f.trim());
      for (const part of fieldParts) {
        // Remove aliases and extract base field name
        const fieldMatch = part.match(/(\w+)(?:\s+as\s+\w+)?$/i);
        if (fieldMatch) {
          fields.push(fieldMatch[1]);
        }
      }
    }
    return fields;
  }
  
  /**
   * Extract joins from SQL query (simplified implementation)
   */
  private extractJoinsFromQuery(sql: string): string[] {
    const joins: string[] = [];
    // Simple regex to find JOIN clauses
    const joinMatches = sql.matchAll(/(?:inner|left|right|full)?\s*join\s+(\w+)/gi);
    for (const match of joinMatches) {
      joins.push(match[1]);
    }
    return joins;
  }

  /**
   * Calculate data size
   */
  private calculateDataSize(data: any): number {
    return JSON.stringify(data).length;
  }

  /**
   * Extract fields from object
   */
  private extractFields(obj: any, prefix = ''): string[] {
    const fields: string[] = [];

    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const fieldName = prefix ? `${prefix}.${key}` : key;
        
        if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
          fields.push(...this.extractFields(obj[key], fieldName));
        } else {
          fields.push(fieldName);
        }
      }
    }

    return fields;
  }

  /**
   * Extract fields from query
   */
  private extractQueryFields(query: TestQuery): string[] {
    const fields: string[] = [];

    if (query.sql) {
      // Extract SELECT fields (simplified)
      const selectMatch = query.sql.match(/SELECT\s+(.+?)\s+FROM/i);
      if (selectMatch) {
        const selectClause = selectMatch[1];
        if (selectClause === '*') {
          fields.push('*');
        } else {
          const fieldMatches = selectClause.matchAll(/(\w+)/g);
          for (const match of fieldMatches) {
            fields.push(match[1]);
          }
        }
      }
    }

    return fields;
  }
}

