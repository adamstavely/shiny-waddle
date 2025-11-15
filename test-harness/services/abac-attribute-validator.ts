/**
 * ABAC Attribute Validator
 * 
 * Validates ABAC attribute definitions, schemas, sources, freshness, and access controls
 */

export interface ABACAttribute {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  source: 'ldap' | 'database' | 'api' | 'jwt' | 'custom';
  validation: ValidationRule[];
  freshness?: {
    maxAge: number;
    unit: 'seconds' | 'minutes' | 'hours';
  };
}

export interface ValidationRule {
  type: 'required' | 'format' | 'range' | 'enum' | 'regex' | 'custom';
  value?: any;
  message?: string;
}

export interface AttributeValidationResult {
  passed: boolean;
  attribute: string;
  issues: Array<{
    type: 'invalid-schema' | 'untrusted-source' | 'stale-value' | 'no-validation' | 'access-control-issue';
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
  }>;
  schemaValid: boolean;
  sourceTrusted: boolean;
  freshnessValid: boolean;
}

export interface ValidationResult {
  valid: boolean;
  value: any;
  errors: string[];
}

export interface SourceResult {
  trusted: boolean;
  source: string;
  issues: string[];
}

export interface FreshnessResult {
  fresh: boolean;
  age?: number;
  maxAge?: number;
  issues: string[];
}

export interface AccessControlResult {
  hasAccessControl: boolean;
  accessLevels: string[];
  issues: string[];
}

export interface AggregationResult {
  valid: boolean;
  aggregatedAttributes: string[];
  issues: string[];
}

export class ABACAttributeValidator {
  private trustedSources = ['ldap', 'database', 'api', 'jwt'];
  private untrustedSources = ['custom', 'user-input', 'external'];

  /**
   * Validate attribute definition
   */
  async validateAttributeDefinition(
    attribute: ABACAttribute
  ): Promise<AttributeValidationResult> {
    const issues: AttributeValidationResult['issues'] = [];

    // Validate schema
    const schemaValid = this.validateSchema(attribute);
    if (!schemaValid) {
      issues.push({
        type: 'invalid-schema',
        severity: 'high',
        message: 'Attribute schema is invalid or incomplete',
      });
    }

    // Validate source
    const sourceResult = await this.validateAttributeSource(attribute);
    if (!sourceResult.trusted) {
      issues.push({
        type: 'untrusted-source',
        severity: 'high',
        message: `Attribute source ${attribute.source} may not be trusted`,
      });
    }

    // Validate freshness
    if (attribute.freshness) {
      const freshnessResult = await this.testAttributeFreshness(attribute);
      if (!freshnessResult.fresh) {
        issues.push({
          type: 'stale-value',
          severity: 'medium',
          message: 'Attribute value may be stale',
        });
      }
    }

    // Validate validation rules
    if (!attribute.validation || attribute.validation.length === 0) {
      issues.push({
        type: 'no-validation',
        severity: 'medium',
        message: 'Attribute has no validation rules',
      });
    }

    const criticalIssues = issues.filter(i => i.severity === 'critical').length;
    const highIssues = issues.filter(i => i.severity === 'high').length;

    return {
      passed: criticalIssues === 0 && highIssues === 0,
      attribute: attribute.name,
      issues,
      schemaValid,
      sourceTrusted: sourceResult.trusted,
      freshnessValid: attribute.freshness ? true : false,
    };
  }

  /**
   * Test attribute validation
   */
  async testAttributeValidation(
    attribute: ABACAttribute,
    value: any
  ): Promise<ValidationResult> {
    const errors: string[] = [];

    // Check required
    const requiredRule = attribute.validation.find(r => r.type === 'required');
    if (requiredRule && (value === undefined || value === null || value === '')) {
      errors.push(requiredRule.message || 'Attribute is required');
    }

    // Check type
    if (value !== undefined && value !== null) {
      const valueType = this.getType(value);
      if (valueType !== attribute.type && attribute.type !== 'object') {
        errors.push(`Expected type ${attribute.type}, got ${valueType}`);
      }
    }

    // Check format rules
    for (const rule of attribute.validation) {
      switch (rule.type) {
        case 'format':
          if (!this.validateFormat(value, rule.value)) {
            errors.push(rule.message || `Value does not match format: ${rule.value}`);
          }
          break;

        case 'range':
          if (typeof value === 'number' && rule.value) {
            const { min, max } = rule.value;
            if (min !== undefined && value < min) {
              errors.push(rule.message || `Value ${value} is less than minimum ${min}`);
            }
            if (max !== undefined && value > max) {
              errors.push(rule.message || `Value ${value} is greater than maximum ${max}`);
            }
          }
          break;

        case 'enum':
          if (rule.value && Array.isArray(rule.value) && !rule.value.includes(value)) {
            errors.push(rule.message || `Value ${value} is not in allowed enum values`);
          }
          break;

        case 'regex':
          if (rule.value && typeof value === 'string') {
            const regex = new RegExp(rule.value);
            if (!regex.test(value)) {
              errors.push(rule.message || `Value does not match regex pattern`);
            }
          }
          break;
      }
    }

    return {
      valid: errors.length === 0,
      value,
      errors,
    };
  }

  /**
   * Validate attribute source
   */
  async validateAttributeSource(
    attribute: ABACAttribute
  ): Promise<SourceResult> {
    const issues: string[] = [];

    const isTrusted = this.trustedSources.includes(attribute.source);
    const isUntrusted = this.untrustedSources.includes(attribute.source);

    if (!isTrusted && !isUntrusted) {
      issues.push(`Unknown source type: ${attribute.source}`);
    }

    if (isUntrusted) {
      issues.push(`Source ${attribute.source} is not in trusted sources list`);
    }

    // Check for sensitive attributes from untrusted sources
    const sensitiveAttributes = ['clearanceLevel', 'role', 'permissions', 'accessLevel'];
    if (isUntrusted && sensitiveAttributes.includes(attribute.name)) {
      issues.push(`Sensitive attribute ${attribute.name} should not come from untrusted source ${attribute.source}`);
    }

    return {
      trusted: isTrusted && issues.length === 0,
      source: attribute.source,
      issues,
    };
  }

  /**
   * Test attribute freshness
   */
  async testAttributeFreshness(
    attribute: ABACAttribute
  ): Promise<FreshnessResult> {
    const issues: string[] = [];

    if (!attribute.freshness) {
      return {
        fresh: true, // No freshness requirement
        issues: [],
      };
    }

    const { maxAge, unit } = attribute.freshness;

    // Convert maxAge to milliseconds
    let maxAgeMs = maxAge;
    switch (unit) {
      case 'seconds':
        maxAgeMs = maxAge * 1000;
        break;
      case 'minutes':
        maxAgeMs = maxAge * 60 * 1000;
        break;
      case 'hours':
        maxAgeMs = maxAge * 60 * 60 * 1000;
        break;
    }

    // In a real implementation, this would check the actual age of the attribute value
    // For now, we'll assume it's fresh if freshness is configured
    const age = 0; // Would be calculated from actual attribute timestamp

    if (age > maxAgeMs) {
      issues.push(`Attribute value is stale: age ${age}ms exceeds max age ${maxAgeMs}ms`);
    }

    return {
      fresh: age <= maxAgeMs,
      age,
      maxAge: maxAgeMs,
      issues,
    };
  }

  /**
   * Validate attribute access control
   */
  async validateAttributeAccessControl(
    attribute: ABACAttribute
  ): Promise<AccessControlResult> {
    const issues: string[] = [];
    const accessLevels: string[] = [];

    // Check if attribute has access control metadata
    // This is a simplified check - real implementation would check actual access control configuration

    // Sensitive attributes should have access control
    const sensitiveAttributes = ['clearanceLevel', 'role', 'permissions', 'ssn', 'email'];
    if (sensitiveAttributes.includes(attribute.name)) {
      // In a real implementation, this would check if access control is configured
      accessLevels.push('restricted');
    } else {
      accessLevels.push('standard');
    }

    // Check if attribute can be read by unauthorized users
    // This would require checking actual access control policies

    return {
      hasAccessControl: accessLevels.includes('restricted'),
      accessLevels,
      issues,
    };
  }

  /**
   * Test attribute aggregation
   */
  async testAttributeAggregation(
    attributes: ABACAttribute[]
  ): Promise<AggregationResult> {
    const issues: string[] = [];
    const aggregatedAttributes: string[] = [];

    // Check for circular dependencies
    const attributeNames = attributes.map(a => a.name);
    for (const attribute of attributes) {
      // Check if attribute references other attributes
      // This is a simplified check
      if (attribute.validation.some(r => r.type === 'custom')) {
        aggregatedAttributes.push(attribute.name);
      }
    }

    // Check for conflicting attributes
    const conflictingPairs = this.findConflictingAttributes(attributes);
    if (conflictingPairs.length > 0) {
      issues.push(`Found ${conflictingPairs.length} conflicting attribute pairs`);
    }

    return {
      valid: issues.length === 0,
      aggregatedAttributes,
      issues,
    };
  }

  /**
   * Validate schema
   */
  private validateSchema(attribute: ABACAttribute): boolean {
    // Check required fields
    if (!attribute.name) {
      return false;
    }

    if (!attribute.type) {
      return false;
    }

    if (!attribute.source) {
      return false;
    }

    // Check type validity
    const validTypes = ['string', 'number', 'boolean', 'array', 'object'];
    if (!validTypes.includes(attribute.type)) {
      return false;
    }

    return true;
  }

  /**
   * Get type of value
   */
  private getType(value: any): string {
    if (Array.isArray(value)) {
      return 'array';
    }
    if (value === null) {
      return 'null';
    }
    return typeof value;
  }

  /**
   * Validate format
   */
  private validateFormat(value: any, format?: any): boolean {
    if (!format) {
      return true;
    }

    if (typeof value !== 'string') {
      return false;
    }

    // Common format validations
    switch (format) {
      case 'email':
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      case 'url':
        try {
          new URL(value);
          return true;
        } catch {
          return false;
        }
      case 'uuid':
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
      default:
        return true;
    }
  }

  /**
   * Find conflicting attributes
   */
  private findConflictingAttributes(attributes: ABACAttribute[]): Array<[string, string]> {
    const conflicts: Array<[string, string]> = [];

    // Check for attributes with same name but different types
    const nameMap = new Map<string, ABACAttribute>();
    for (const attr of attributes) {
      const existing = nameMap.get(attr.name);
      if (existing && existing.type !== attr.type) {
        conflicts.push([existing.name, attr.name]);
      }
      nameMap.set(attr.name, attr);
    }

    return conflicts;
  }
}

