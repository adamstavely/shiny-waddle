/**
 * PII Masking Validator Service
 * 
 * Validates that PII fields are properly masked in queries and responses
 */

import { PiiDetectionRule } from '../core/types';

export class PiiMaskingValidator {
  private detectionRules: PiiDetectionRule[];

  constructor(detectionRules: PiiDetectionRule[]) {
    this.detectionRules = detectionRules;
  }

  /**
   * Detect PII fields in a list of field names
   */
  detectPiiFields(fields: string[]): string[] {
    const piiFields: string[] = [];

    for (const field of fields) {
      for (const rule of this.detectionRules) {
        if (this.matchesRule(field, rule)) {
          piiFields.push(field);
          break;
        }
      }
    }

    return piiFields;
  }

  /**
   * Check if a field matches a PII detection rule
   */
  private matchesRule(field: string, rule: PiiDetectionRule): boolean {
    // Check field pattern
    if (rule.fieldPattern) {
      const pattern = new RegExp(rule.fieldPattern, 'i');
      if (!pattern.test(field)) {
        return false;
      }
    }

    // Check regex if provided
    if (rule.regex) {
      const regex = new RegExp(rule.regex, 'i');
      if (!regex.test(field)) {
        return false;
      }
    }

    // Check PII type patterns
    const typePatterns: Record<string, RegExp> = {
      email: /email|e-mail|mail/i,
      ssn: /ssn|social.*security|tax.*id/i,
      phone: /phone|mobile|tel/i,
      'credit-card': /credit.*card|card.*number|cc.*number/i,
      'ip-address': /ip.*address|ipaddr/i,
    };

    if (rule.piiType !== 'custom' && typePatterns[rule.piiType]) {
      if (typePatterns[rule.piiType].test(field)) {
        return true;
      }
    }

    return true;
  }

  /**
   * Validate that PII fields are masked in a query
   */
  validatePiiMasking(query: string, piiFields: string[]): {
    compliant: boolean;
    unmaskedFields: string[];
  } {
    const unmaskedFields: string[] = [];

    for (const field of piiFields) {
      // Check for masking functions
      const maskingPatterns = [
        new RegExp(`MASK\\(${field}\\)`, 'i'),
        new RegExp(`HASH\\(${field}\\)`, 'i'),
        new RegExp(`REDACT\\(${field}\\)`, 'i'),
        new RegExp(`ENCRYPT\\(${field}\\)`, 'i'),
        new RegExp(`ANONYMIZE\\(${field}\\)`, 'i'),
      ];

      const isMasked = maskingPatterns.some(pattern => pattern.test(query));

      // Also check if field is in SELECT but with masking
      const directFieldPattern = new RegExp(`\\b${field}\\b`, 'i');
      if (directFieldPattern.test(query) && !isMasked) {
        unmaskedFields.push(field);
      }
    }

    return {
      compliant: unmaskedFields.length === 0,
      unmaskedFields,
    };
  }

  /**
   * Validate PII masking in API response data
   */
  validateResponseMasking(data: any, piiFields: string[]): {
    compliant: boolean;
    unmaskedFields: string[];
    sampleValues: Record<string, any>;
  } {
    const unmaskedFields: string[] = [];
    const sampleValues: Record<string, any> = {};

    for (const field of piiFields) {
      const value = this.getNestedValue(data, field);
      if (value !== undefined && !this.isMasked(value)) {
        unmaskedFields.push(field);
        sampleValues[field] = value;
      }
    }

    return {
      compliant: unmaskedFields.length === 0,
      unmaskedFields,
      sampleValues,
    };
  }

  /**
   * Check if a value appears to be masked
   */
  private isMasked(value: any): boolean {
    if (typeof value !== 'string') {
      return false;
    }

    // Check for common masking patterns
    const maskingPatterns = [
      /^\*+$/, // All asterisks
      /^X+$/, // All X's
      /^[\*X]{4,}/, // Starts with 4+ asterisks or X's
      /^[a-f0-9]{32,}$/i, // Hash-like (MD5/SHA)
      /^[a-f0-9]{64,}$/i, // Hash-like (SHA256)
    ];

    return maskingPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Get nested value from object using dot notation
   */
  private getNestedValue(obj: any, path: string): any {
    const keys = path.split('.');
    let current = obj;

    for (const key of keys) {
      if (current === null || current === undefined) {
        return undefined;
      }
      current = current[key];
    }

    return current;
  }
}

