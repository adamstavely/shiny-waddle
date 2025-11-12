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
      testType: 'data-behavior',
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
      testType: 'data-behavior',
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
    const result: TestResult = {
      testType: 'data-behavior',
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
    exportRequest: { type: 'csv' | 'json' | 'excel' | 'api'; recordCount: number }
  ): Promise<TestResult> {
    const result: TestResult = {
      testType: 'data-behavior',
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
        testType: 'data-behavior',
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

