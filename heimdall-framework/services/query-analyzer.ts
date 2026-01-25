/**
 * Query Analyzer Service
 * 
 * Analyzes SQL queries and API requests to extract fields, joins, filters, etc.
 */

import { TestQuery, DataBehaviorConfig } from '../core/types';
import { Filter } from '../core/types';

export interface QueryAnalysis {
  fieldsUsed: string[];
  joinsUsed: string[];
  filtersApplied: Filter[];
  aggregationsApplied: string[];
  hasLimit: boolean;
  limit?: number;
  hasOrderBy: boolean;
  queryType: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'API';
}

export class QueryAnalyzer {
  private config: DataBehaviorConfig;

  constructor(config: DataBehaviorConfig) {
    this.config = config;
  }

  /**
   * Analyze a query to extract its components
   */
  async analyze(query: TestQuery): Promise<QueryAnalysis> {
    if (query.sql) {
      return this.analyzeSqlQuery(query.sql);
    } else if (query.apiEndpoint) {
      return this.analyzeApiRequest(query);
    } else {
      throw new Error('Query must have either SQL or API endpoint');
    }
  }

  /**
   * Analyze SQL query
   */
  private analyzeSqlQuery(sql: string): QueryAnalysis {
    const normalizedSql = sql.toUpperCase().trim();

    // Extract fields (simplified - would need proper SQL parser in production)
    const fieldsUsed = this.extractFields(normalizedSql);

    // Extract joins
    const joinsUsed = this.extractJoins(normalizedSql);

    // Extract filters (WHERE clauses)
    const filtersApplied = this.extractFilters(normalizedSql);

    // Extract aggregations
    const aggregationsApplied = this.extractAggregations(normalizedSql);

    // Check for LIMIT
    const limitMatch = normalizedSql.match(/LIMIT\s+(\d+)/i);
    const hasLimit = !!limitMatch;
    const limit = limitMatch ? parseInt(limitMatch[1]) : undefined;

    // Check for ORDER BY
    const hasOrderBy = /ORDER\s+BY/i.test(normalizedSql);

    // Determine query type
    let queryType: QueryAnalysis['queryType'] = 'SELECT';
    if (/^INSERT/i.test(normalizedSql)) queryType = 'INSERT';
    else if (/^UPDATE/i.test(normalizedSql)) queryType = 'UPDATE';
    else if (/^DELETE/i.test(normalizedSql)) queryType = 'DELETE';

    return {
      fieldsUsed,
      joinsUsed,
      filtersApplied,
      aggregationsApplied,
      hasLimit,
      limit,
      hasOrderBy,
      queryType,
    };
  }

  /**
   * Analyze API request
   */
  private analyzeApiRequest(query: TestQuery): QueryAnalysis {
    // For API requests, we'd need to trace the backend query
    // This is a simplified version
    return {
      fieldsUsed: this.extractFieldsFromApiRequest(query),
      joinsUsed: [],
      filtersApplied: this.extractFiltersFromApiRequest(query),
      aggregationsApplied: [],
      hasLimit: false,
      hasOrderBy: false,
      queryType: 'API',
    };
  }

  /**
   * Extract fields from SQL query
   */
  private extractFields(sql: string): string[] {
    const fields: string[] = [];

    // Match SELECT ... FROM pattern
    const selectMatch = sql.match(/SELECT\s+(.*?)\s+FROM/i);
    if (selectMatch) {
      const selectClause = selectMatch[1];
      // Split by comma and clean up
      const fieldList = selectClause.split(',').map(f => f.trim());
      for (const field of fieldList) {
        // Remove aliases and functions, extract base field name
        const cleanField = field
          .replace(/\s+AS\s+\w+/i, '')
          .replace(/^\w+\(/, '')
          .replace(/\)$/, '')
          .trim();
        if (cleanField && cleanField !== '*') {
          fields.push(cleanField);
        }
      }
    }

    return fields;
  }

  /**
   * Extract joins from SQL query
   */
  private extractJoins(sql: string): string[] {
    const joins: string[] = [];

    // Match JOIN ... ON patterns
    const joinMatches = sql.matchAll(/(?:INNER|LEFT|RIGHT|FULL)?\s+JOIN\s+(\w+)/gi);
    for (const match of joinMatches) {
      joins.push(match[1]);
    }

    return joins;
  }

  /**
   * Extract filters from SQL query
   */
  private extractFilters(sql: string): Filter[] {
    const filters: Filter[] = [];

    // Match WHERE clause
    const whereMatch = sql.match(/WHERE\s+(.*?)(?:\s+(?:GROUP|ORDER|LIMIT)|$)/i);
    if (whereMatch) {
      const whereClause = whereMatch[1];
      // Simple extraction - would need proper parser for complex conditions
      const conditions = whereClause.split(/\s+(?:AND|OR)\s+/i);
      for (const condition of conditions) {
        const filter = this.parseCondition(condition);
        if (filter) {
          filters.push(filter);
        }
      }
    }

    return filters;
  }

  /**
   * Parse a condition into a Filter object
   */
  private parseCondition(condition: string): Filter | null {
    // Simple pattern matching - would need proper SQL parser in production
    const patterns = [
      { regex: /(\w+)\s*=\s*['"]?([^'"]+)['"]?/i, operator: '=' as const },
      { regex: /(\w+)\s*!=\s*['"]?([^'"]+)['"]?/i, operator: '!=' as const },
      { regex: /(\w+)\s*>\s*(\d+)/i, operator: '>' as const },
      { regex: /(\w+)\s*<\s*(\d+)/i, operator: '<' as const },
      { regex: /(\w+)\s*>=\s*(\d+)/i, operator: '>=' as const },
      { regex: /(\w+)\s*<=\s*(\d+)/i, operator: '<=' as const },
      { regex: /(\w+)\s+IN\s*\(([^)]+)\)/i, operator: 'IN' as const },
    ];

    for (const pattern of patterns) {
      const match = condition.match(pattern.regex);
      if (match) {
        let value: any = match[2];
        if (pattern.operator === 'IN') {
          value = match[2].split(',').map(v => v.trim().replace(/['"]/g, ''));
        } else if (!isNaN(Number(value))) {
          value = Number(value);
        } else {
          value = value.replace(/['"]/g, '');
        }

        return {
          field: match[1],
          operator: pattern.operator,
          value,
        };
      }
    }

    return null;
  }

  /**
   * Extract aggregations from SQL query
   */
  private extractAggregations(sql: string): string[] {
    const aggregations: string[] = [];
    const aggFunctions = ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'GROUP_CONCAT'];

    for (const func of aggFunctions) {
      const regex = new RegExp(`\\b${func}\\s*\\(`, 'gi');
      if (regex.test(sql)) {
        aggregations.push(func);
      }
    }

    return aggregations;
  }

  /**
   * Extract fields from API request (simplified)
   */
  private extractFieldsFromApiRequest(query: TestQuery): string[] {
    // In a real implementation, this would trace the API call to the database
    // For now, return empty array
    return [];
  }

  /**
   * Extract filters from API request (simplified)
   */
  private extractFiltersFromApiRequest(query: TestQuery): Filter[] {
    // Extract from query parameters or request body
    const filters: Filter[] = [];

    if (query.requestBody) {
      // Try to extract filter-like fields from request body
      for (const [key, value] of Object.entries(query.requestBody)) {
        if (typeof value === 'string' || typeof value === 'number') {
          filters.push({
            field: key,
            operator: '=',
            value,
          });
        }
      }
    }

    return filters;
  }
}

