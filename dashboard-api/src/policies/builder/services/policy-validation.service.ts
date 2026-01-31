import { Injectable } from '@nestjs/common';
import { Policy } from '../../entities/policy.entity';
import { PolicyType, PolicyEffect, RBACRule, ABACCondition } from '../../dto/create-policy.dto';
import { ValidationResult, ValidationError } from '../dto/validate-policy.dto';

@Injectable()
export class PolicyValidationService {
  private readonly validOperators = [
    'equals',
    'notEquals',
    'in',
    'notIn',
    'contains',
    'greaterThan',
    'lessThan',
    'regex',
  ];

  private readonly validAttributes = {
    subject: ['department', 'role', 'clearanceLevel', 'projectAccess', 'certifications', 'location', 'employmentType'],
    resource: ['department', 'dataClassification', 'project', 'region', 'owner', 'minClearanceLevel', 'requiresCertification'],
    context: ['ipAddress', 'timeOfDay', 'location', 'deviceType'],
  };

  /**
   * Validate policy syntax (JSON structure)
   */
  validateSyntax(jsonString: string): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];

    try {
      JSON.parse(jsonString);
    } catch (error) {
      errors.push({
        field: 'json',
        message: `Invalid JSON syntax: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: 'error',
        code: 'INVALID_JSON',
      });
      return { valid: false, errors, warnings };
    }

    return { valid: true, errors, warnings };
  }

  /**
   * Validate policy schema (required fields, types)
   */
  validateSchema(policy: Policy): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];

    // Required fields
    if (!policy.name || policy.name.trim().length === 0) {
      errors.push({
        field: 'name',
        message: 'Policy name is required',
        severity: 'error',
        code: 'MISSING_NAME',
      });
    }

    if (!policy.type) {
      errors.push({
        field: 'type',
        message: 'Policy type is required',
        severity: 'error',
        code: 'MISSING_TYPE',
      });
    } else if (!['rbac', 'abac'].includes(policy.type)) {
      errors.push({
        field: 'type',
        message: 'Policy type must be "rbac" or "abac"',
        severity: 'error',
        code: 'INVALID_TYPE',
      });
    }

    if (!policy.version) {
      errors.push({
        field: 'version',
        message: 'Policy version is required',
        severity: 'error',
        code: 'MISSING_VERSION',
      });
    }

    // Type-specific validation
    if (policy.type === PolicyType.RBAC) {
      if (!policy.rules || policy.rules.length === 0) {
        errors.push({
          field: 'rules',
          message: 'RBAC policy must have at least one rule',
          severity: 'error',
          code: 'MISSING_RULES',
        });
      } else {
        policy.rules.forEach((rule, index) => {
          this.validateRBACRule(rule, index, errors, warnings);
        });
      }
    } else if (policy.type === PolicyType.ABAC) {
      if (!policy.conditions || policy.conditions.length === 0) {
        errors.push({
          field: 'conditions',
          message: 'ABAC policy must have at least one condition',
          severity: 'error',
          code: 'MISSING_CONDITIONS',
        });
      } else {
        policy.conditions.forEach((condition, index) => {
          this.validateABACCondition(condition, index, errors, warnings);
        });
      }

      if (policy.priority === undefined || policy.priority === null) {
        warnings.push({
          field: 'priority',
          message: 'ABAC policy should have a priority value',
          severity: 'warning',
          code: 'MISSING_PRIORITY',
        });
      }
    }

    // Effect validation
    if (policy.effect && !['allow', 'deny'].includes(policy.effect)) {
      errors.push({
        field: 'effect',
        message: 'Policy effect must be "allow" or "deny"',
        severity: 'error',
        code: 'INVALID_EFFECT',
      });
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate policy logic (conflicting conditions, invalid operators)
   */
  validateLogic(policy: Policy): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];

    if (policy.type === PolicyType.ABAC && policy.conditions) {
      // Check for conflicting conditions
      const conditionGroups = new Map<string, ABACCondition[]>();
      
      policy.conditions.forEach(cond => {
        const key = `${cond.attribute}:${cond.operator}`;
        if (!conditionGroups.has(key)) {
          conditionGroups.set(key, []);
        }
        conditionGroups.get(key)!.push(cond);
      });

      // Check for duplicate conditions with different values
      conditionGroups.forEach((conditions, key) => {
        if (conditions.length > 1) {
          const values = conditions.map(c => c.value);
          const uniqueValues = new Set(values);
          if (uniqueValues.size < values.length) {
            warnings.push({
              field: `conditions[${conditions[0].attribute}]`,
              message: `Multiple conditions with same attribute and operator but different values may conflict`,
              severity: 'warning',
              code: 'POTENTIAL_CONFLICT',
            });
          }
        }
      });
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Combined validation
   */
  validatePolicy(policy: Policy | string): ValidationResult {
    let policyObj: Policy;

    if (typeof policy === 'string') {
      const syntaxResult = this.validateSyntax(policy);
      if (!syntaxResult.valid) {
        return syntaxResult;
      }
      try {
        policyObj = JSON.parse(policy) as Policy;
      } catch {
        return {
          valid: false,
          errors: [{
            field: 'json',
            message: 'Failed to parse JSON',
            severity: 'error',
            code: 'PARSE_ERROR',
          }],
          warnings: [],
        };
      }
    } else {
      policyObj = policy;
    }

    const schemaResult = this.validateSchema(policyObj);
    const logicResult = this.validateLogic(policyObj);

    return {
      valid: schemaResult.valid && logicResult.valid,
      errors: [...schemaResult.errors, ...logicResult.errors],
      warnings: [...schemaResult.warnings, ...logicResult.warnings],
    };
  }

  /**
   * Validate a specific field
   */
  validateField(
    field: string,
    value: any,
    policyType: PolicyType
  ): ValidationError[] {
    const errors: ValidationError[] = [];

    switch (field) {
      case 'name':
        if (!value || String(value).trim().length === 0) {
          errors.push({
            field: 'name',
            message: 'Policy name is required',
            severity: 'error',
            code: 'MISSING_NAME',
          });
        }
        break;

      case 'type':
        if (!['rbac', 'abac'].includes(value)) {
          errors.push({
            field: 'type',
            message: 'Policy type must be "rbac" or "abac"',
            severity: 'error',
            code: 'INVALID_TYPE',
          });
        }
        break;

      case 'version':
        if (!value || String(value).trim().length === 0) {
          errors.push({
            field: 'version',
            message: 'Policy version is required',
            severity: 'error',
            code: 'MISSING_VERSION',
          });
        }
        break;

      case 'effect':
        if (!['allow', 'deny'].includes(value)) {
          errors.push({
            field: 'effect',
            message: 'Policy effect must be "allow" or "deny"',
            severity: 'error',
            code: 'INVALID_EFFECT',
          });
        }
        break;

      case 'priority':
        if (policyType === PolicyType.ABAC) {
          if (value === undefined || value === null) {
            // Warning, not error
            return [{
              field: 'priority',
              message: 'ABAC policy should have a priority value',
              severity: 'warning',
              code: 'MISSING_PRIORITY',
            }];
          }
          if (typeof value !== 'number' || value < 0) {
            errors.push({
              field: 'priority',
              message: 'Priority must be a non-negative number',
              severity: 'error',
              code: 'INVALID_PRIORITY',
            });
          }
        }
        break;
    }

    return errors;
  }

  // Private helper methods

  private validateRBACRule(
    rule: RBACRule,
    index: number,
    errors: ValidationError[],
    warnings: ValidationError[]
  ): void {
    if (!rule.id) {
      errors.push({
        field: `rules[${index}].id`,
        message: 'Rule ID is required',
        severity: 'error',
        code: 'MISSING_RULE_ID',
      });
    }

    if (!rule.effect || !['allow', 'deny'].includes(rule.effect)) {
      errors.push({
        field: `rules[${index}].effect`,
        message: 'Rule effect must be "allow" or "deny"',
        severity: 'error',
        code: 'INVALID_RULE_EFFECT',
      });
    }

    if (!rule.conditions || Object.keys(rule.conditions).length === 0) {
      errors.push({
        field: `rules[${index}].conditions`,
        message: 'Rule must have at least one condition',
        severity: 'error',
        code: 'MISSING_RULE_CONDITIONS',
      });
    } else {
      // Check for required role condition
      if (!rule.conditions['subject.role']) {
        warnings.push({
          field: `rules[${index}].conditions`,
          message: 'RBAC rule should include subject.role condition',
          severity: 'warning',
          code: 'MISSING_ROLE_CONDITION',
        });
      }
    }
  }

  private validateABACCondition(
    condition: ABACCondition,
    index: number,
    errors: ValidationError[],
    warnings: ValidationError[]
  ): void {
    if (!condition.attribute) {
      errors.push({
        field: `conditions[${index}].attribute`,
        message: 'Condition attribute is required',
        severity: 'error',
        code: 'MISSING_ATTRIBUTE',
      });
    } else {
      // Validate attribute format (subject.*, resource.*, context.*)
      const attributeParts = condition.attribute.split('.');
      if (attributeParts.length !== 2) {
        errors.push({
          field: `conditions[${index}].attribute`,
          message: 'Attribute must be in format "subject.*", "resource.*", or "context.*"',
          severity: 'error',
          code: 'INVALID_ATTRIBUTE_FORMAT',
        });
      } else {
        const [prefix, attribute] = attributeParts;
        if (!['subject', 'resource', 'context'].includes(prefix)) {
          errors.push({
            field: `conditions[${index}].attribute`,
            message: 'Attribute prefix must be "subject", "resource", or "context"',
            severity: 'error',
            code: 'INVALID_ATTRIBUTE_PREFIX',
          });
        } else {
          const validAttributes = this.validAttributes[prefix as keyof typeof this.validAttributes];
          if (validAttributes && !validAttributes.includes(attribute)) {
            warnings.push({
              field: `conditions[${index}].attribute`,
              message: `Unknown attribute "${attribute}" for prefix "${prefix}"`,
              severity: 'warning',
              code: 'UNKNOWN_ATTRIBUTE',
            });
          }
        }
      }
    }

    if (!condition.operator) {
      errors.push({
        field: `conditions[${index}].operator`,
        message: 'Condition operator is required',
        severity: 'error',
        code: 'MISSING_OPERATOR',
      });
    } else if (!this.validOperators.includes(condition.operator)) {
      errors.push({
        field: `conditions[${index}].operator`,
        message: `Invalid operator. Valid operators: ${this.validOperators.join(', ')}`,
        severity: 'error',
        code: 'INVALID_OPERATOR',
      });
    }

    if (condition.value === undefined || condition.value === null || condition.value === '') {
      errors.push({
        field: `conditions[${index}].value`,
        message: 'Condition value is required',
        severity: 'error',
        code: 'MISSING_VALUE',
      });
    }

    if (condition.logicalOperator && !['AND', 'OR'].includes(condition.logicalOperator)) {
      errors.push({
        field: `conditions[${index}].logicalOperator`,
        message: 'Logical operator must be "AND" or "OR"',
        severity: 'error',
        code: 'INVALID_LOGICAL_OPERATOR',
      });
    }
  }
}
