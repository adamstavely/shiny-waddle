/**
 * Data Behavior Tester Service
 * 
 * Verifies that app queries only use permitted fields, apply required
 * filters/aggregations, and block disallowed joins
 */

import { User, TestQuery, Filter, DataBehaviorConfig } from '../core/types';
import { QueryAnalyzer } from './query-analyzer';
import { PiiMaskingValidator } from './pii-masking-validator';

export interface DataBehaviorTestInput {
  user: User;
  query: TestQuery;
  expectedFields?: string[];
  requiredFilters?: Filter[];
  disallowedJoins?: string[];
}

export interface DataBehaviorTestResult {
  compliant: boolean;
  violations: string[];
  queryAnalysis: {
    fieldsUsed: string[];
    joinsUsed: string[];
    filtersApplied: Filter[];
    aggregationsApplied: string[];
    piiFieldsExposed: string[];
  };
  recommendations: string[];
}

export class DataBehaviorTester {
  private config: DataBehaviorConfig;
  private queryAnalyzer: QueryAnalyzer;
  private piiValidator: PiiMaskingValidator;

  constructor(config: DataBehaviorConfig) {
    this.config = config;
    this.queryAnalyzer = new QueryAnalyzer(config);
    this.piiValidator = new PiiMaskingValidator(config.piiDetectionRules || []);
  }

  /**
   * Test a query for compliance with data behavior policies
   */
  async testQuery(input: DataBehaviorTestInput): Promise<DataBehaviorTestResult> {
    const violations: string[] = [];
    const recommendations: string[] = [];

    // Analyze the query
    const analysis = await this.queryAnalyzer.analyze(input.query);

    // Check for over-broad queries
    if (this.isOverBroadQuery(analysis, input.user)) {
      violations.push('Over-broad query: Query may return more data than user role permits');
    }

    // Check for missing required filters
    if (input.requiredFilters) {
      const missingFilters = this.findMissingFilters(analysis.filtersApplied, input.requiredFilters);
      if (missingFilters.length > 0) {
        violations.push(
          `Missing required filters: ${missingFilters.map(f => f.field).join(', ')}`
        );
      }
    }

    // Check for disallowed fields
    if (input.expectedFields) {
      const disallowedFields = analysis.fieldsUsed.filter(
        field => !input.expectedFields!.includes(field)
      );
      if (disallowedFields.length > 0) {
        violations.push(`Disallowed fields accessed: ${disallowedFields.join(', ')}`);
      }
    }

    // Check for disallowed joins
    if (input.disallowedJoins) {
      const disallowedJoinsFound = analysis.joinsUsed.filter(join =>
        input.disallowedJoins!.some(disallowed => join.includes(disallowed))
      );
      if (disallowedJoinsFound.length > 0) {
        violations.push(`Disallowed joins detected: ${disallowedJoinsFound.join(', ')}`);
      }
    }

    // Check for PII exposure
    const piiFields = this.piiValidator.detectPiiFields(analysis.fieldsUsed);
    if (piiFields.length > 0 && !this.isPiiMasked(analysis, piiFields)) {
      violations.push(`PII fields exposed without masking: ${piiFields.join(', ')}`);
    }

    // Check for missing aggregations (k-anonymity)
    if (input.user.role === 'viewer' || input.user.role === 'analyst') {
      if (analysis.aggregationsApplied.length === 0 && analysis.fieldsUsed.length > 0) {
        recommendations.push(
          'Consider applying aggregations to protect individual records (k-anonymity)'
        );
      }
    }

    return {
      compliant: violations.length === 0,
      violations,
      queryAnalysis: {
        fieldsUsed: analysis.fieldsUsed,
        joinsUsed: analysis.joinsUsed,
        filtersApplied: analysis.filtersApplied,
        aggregationsApplied: analysis.aggregationsApplied,
        piiFieldsExposed: piiFields,
      },
      recommendations,
    };
  }

  /**
   * Check if query is over-broad for the user's role
   */
  private isOverBroadQuery(analysis: any, user: User): boolean {
    // Simple heuristic: if viewer/analyst queries return > 1000 rows without aggregation
    if ((user.role === 'viewer' || user.role === 'analyst') && analysis.aggregationsApplied.length === 0) {
      // This would need actual query execution to determine row count
      // For now, we check if LIMIT is missing or too high
      if (!analysis.hasLimit || (analysis.limit && analysis.limit > 1000)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Find missing required filters
   */
  private findMissingFilters(
    appliedFilters: Filter[],
    requiredFilters: Filter[]
  ): Filter[] {
    return requiredFilters.filter(required => {
      return !appliedFilters.some(
        applied =>
          applied.field === required.field &&
          applied.operator === required.operator &&
          this.filterValuesMatch(applied.value, required.value)
      );
    });
  }

  /**
   * Check if filter values match
   */
  private filterValuesMatch(value1: any, value2: any): boolean {
    if (Array.isArray(value1) && Array.isArray(value2)) {
      return value1.every(v => value2.includes(v));
    }
    return value1 === value2;
  }

  /**
   * Check if PII fields are properly masked
   */
  private isPiiMasked(analysis: any, piiFields: string[]): boolean {
    // Check if masking functions are applied to PII fields
    return piiFields.every(field => {
      return analysis.fieldsUsed.some((usedField: string) => {
        // Check for masking patterns like MASK(email), HASH(ssn), etc.
        return (
          usedField.includes(`MASK(${field})`) ||
          usedField.includes(`HASH(${field})`) ||
          usedField.includes(`REDACT(${field})`)
        );
      });
    });
  }
}

