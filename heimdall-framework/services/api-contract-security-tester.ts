/**
 * API Contract Security Tester
 * 
 * Tests API contract versioning security, schema security, and contract enforcement
 */

export interface APIContract {
  version: string;
  schema: any; // OpenAPI/Swagger schema
  endpoints: ContractEndpoint[];
}

export interface ContractEndpoint {
  path: string;
  method: string;
  parameters: ContractParameter[];
  responses: ContractResponse[];
  security?: ContractSecurity[];
}

export interface ContractParameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'body';
  type: string;
  required: boolean;
  schema?: any;
}

export interface ContractResponse {
  statusCode: string;
  schema?: any;
}

export interface ContractSecurity {
  type: string;
  scheme?: string;
}

export interface ContractSecurityTestResult {
  passed: boolean;
  contractVersion: string;
  issues: Array<{
    type: 'sensitive-field' | 'no-versioning' | 'breaking-change' | 'insecure-schema';
    severity: 'critical' | 'high' | 'medium' | 'low';
    field?: string;
    message: string;
  }>;
  schemaSecurity: SchemaSecurityResult;
  versioningSecurity: VersioningResult;
}

export interface SchemaSecurityResult {
  secure: boolean;
  sensitiveFields: SensitiveField[];
  issues: string[];
}

export interface SensitiveField {
  field: string;
  type: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface VersioningResult {
  hasVersioning: boolean;
  versioningMethod?: string;
  issues: string[];
}

export interface CompatibilityResult {
  compatible: boolean;
  breakingChanges: string[];
  warnings: string[];
}

export interface EnforcementResult {
  enforced: boolean;
  enforcementMethod?: string;
  issues: string[];
}

export class APIContractSecurityTester {
  /**
   * Validate contract security
   */
  async validateContractSecurity(
    contract: APIContract
  ): Promise<ContractSecurityTestResult> {
    const issues: ContractSecurityTestResult['issues'] = [];

    // Test schema security
    const schemaSecurity = await this.detectSensitiveFields(contract.schema);
    for (const field of schemaSecurity.sensitiveFields) {
      issues.push({
        type: 'sensitive-field',
        severity: field.severity,
        field: field.field,
        message: field.issue,
      });
    }

    // Test versioning
    const versioningSecurity = this.testContractVersioning(contract);
    if (!versioningSecurity.hasVersioning) {
      issues.push({
        type: 'no-versioning',
        severity: 'high',
        message: 'Contract does not specify versioning strategy',
      });
    }

    // Check for insecure schema patterns
    if (this.hasInsecureSchema(contract.schema)) {
      issues.push({
        type: 'insecure-schema',
        severity: 'medium',
        message: 'Schema contains potentially insecure patterns',
      });
    }

    const criticalIssues = issues.filter(i => i.severity === 'critical').length;
    const highIssues = issues.filter(i => i.severity === 'high').length;

    return {
      passed: criticalIssues === 0 && highIssues === 0,
      contractVersion: contract.version,
      issues,
      schemaSecurity,
      versioningSecurity,
    };
  }

  /**
   * Test contract versioning
   */
  async testContractVersioning(
    oldContract: APIContract,
    newContract: APIContract
  ): Promise<VersioningResult> {
    const issues: string[] = [];

    // Check if contracts have version information
    const oldVersion = this.parseVersion(oldContract.version);
    const newVersion = this.parseVersion(newContract.version);

    if (!oldVersion || !newVersion) {
      issues.push('Contracts do not have valid version numbers');
      return {
        hasVersioning: false,
        issues,
      };
    }

    // Determine versioning method
    let versioningMethod = 'semantic';
    if (oldContract.schema?.info?.version) {
      versioningMethod = 'semantic';
    } else if (oldContract.endpoints.some(e => e.path.includes('/v'))) {
      versioningMethod = 'url-based';
    } else if (oldContract.schema?.servers?.some((s: any) => s.url.includes('/v'))) {
      versioningMethod = 'url-based';
    }

    // Check if version increased properly
    if (newVersion.major < oldVersion.major) {
      issues.push('New contract version is lower than old version');
    }

    return {
      hasVersioning: true,
      versioningMethod,
      issues,
    };
  }

  /**
   * Detect sensitive fields in schema
   */
  async detectSensitiveFields(
    schema: any
  ): Promise<SchemaSecurityResult> {
    const sensitiveFields: SensitiveField[] = [];
    const issues: string[] = [];

    // Common sensitive field patterns
    const sensitivePatterns = [
      { pattern: /password/i, severity: 'critical' as const },
      { pattern: /secret/i, severity: 'critical' as const },
      { pattern: /key/i, severity: 'critical' as const },
      { pattern: /token/i, severity: 'high' as const },
      { pattern: /ssn/i, severity: 'critical' as const },
      { pattern: /credit.?card/i, severity: 'critical' as const },
      { pattern: /email/i, severity: 'medium' as const },
      { pattern: /phone/i, severity: 'medium' as const },
    ];

    // Recursively search schema for sensitive fields
    this.searchSchema(schema, '', sensitivePatterns, sensitiveFields);

    return {
      secure: sensitiveFields.length === 0,
      sensitiveFields,
      issues,
    };
  }

  /**
   * Test contract backward compatibility
   */
  async testContractBackwardCompatibility(
    oldContract: APIContract,
    newContract: APIContract
  ): Promise<CompatibilityResult> {
    const breakingChanges: string[] = [];
    const warnings: string[] = [];

    // Compare endpoints
    const oldEndpoints = new Map(
      oldContract.endpoints.map(e => [`${e.method}:${e.path}`, e])
    );
    const newEndpoints = new Map(
      newContract.endpoints.map(e => [`${e.method}:${e.path}`, e])
    );

    // Find removed endpoints
    for (const [key, endpoint] of oldEndpoints.entries()) {
      if (!newEndpoints.has(key)) {
        breakingChanges.push(`Endpoint removed: ${endpoint.method} ${endpoint.path}`);
      }
    }

    // Find changed endpoints
    for (const [key, oldEndpoint] of oldEndpoints.entries()) {
      const newEndpoint = newEndpoints.get(key);
      if (newEndpoint) {
        // Check for parameter changes
        const oldParams = new Map(oldEndpoint.parameters.map(p => [p.name, p]));
        const newParams = new Map(newEndpoint.parameters.map(p => [p.name, p]));

        // Check for removed required parameters
        for (const [paramName, param] of oldParams.entries()) {
          if (param.required && !newParams.has(paramName)) {
            breakingChanges.push(
              `Required parameter removed: ${paramName} from ${oldEndpoint.method} ${oldEndpoint.path}`
            );
          }
        }

        // Check for added required parameters
        for (const [paramName, param] of newParams.entries()) {
          if (param.required && !oldParams.has(paramName)) {
            breakingChanges.push(
              `Required parameter added: ${paramName} to ${newEndpoint.method} ${newEndpoint.path}`
            );
          }
        }

        // Check for type changes
        for (const [paramName, oldParam] of oldParams.entries()) {
          const newParam = newParams.get(paramName);
          if (newParam && oldParam.type !== newParam.type) {
            warnings.push(
              `Parameter type changed: ${paramName} from ${oldParam.type} to ${newParam.type}`
            );
          }
        }
      }
    }

    return {
      compatible: breakingChanges.length === 0,
      breakingChanges,
      warnings,
    };
  }

  /**
   * Validate contract enforcement
   */
  async validateContractEnforcement(
    contract: APIContract
  ): Promise<EnforcementResult> {
    const issues: string[] = [];

    // Check if contract has enforcement mechanism
    // This is a simplified check - real implementation would test actual enforcement

    // Check for validation annotations
    const hasValidation = this.hasValidationAnnotations(contract.schema);
    if (!hasValidation) {
      issues.push('Contract schema does not appear to have validation annotations');
    }

    // Check for security requirements
    const hasSecurity = contract.endpoints.some(e => e.security && e.security.length > 0);
    if (!hasSecurity) {
      issues.push('Contract endpoints do not specify security requirements');
    }

    return {
      enforced: hasValidation && hasSecurity,
      enforcementMethod: hasValidation ? 'schema-validation' : undefined,
      issues,
    };
  }

  /**
   * Test contract versioning (single contract)
   */
  private testContractVersioning(contract: APIContract): VersioningResult {
    const issues: string[] = [];

    // Check if contract has version
    if (!contract.version) {
      issues.push('Contract does not specify version');
      return {
        hasVersioning: false,
        issues,
      };
    }

    // Check version format
    const version = this.parseVersion(contract.version);
    if (!version) {
      issues.push('Contract version is not in valid format (should be semantic versioning)');
    }

    // Check if version is in URL or header
    const hasUrlVersioning = contract.endpoints.some(e => e.path.includes('/v'));
    const hasHeaderVersioning = contract.endpoints.some(e =>
      e.parameters.some(p => p.name.toLowerCase().includes('version'))
    );

    let versioningMethod: string | undefined;
    if (hasUrlVersioning) {
      versioningMethod = 'url-based';
    } else if (hasHeaderVersioning) {
      versioningMethod = 'header-based';
    } else if (contract.schema?.info?.version) {
      versioningMethod = 'semantic';
    }

    return {
      hasVersioning: !!version,
      versioningMethod,
      issues,
    };
  }

  /**
   * Check if schema has insecure patterns
   */
  private hasInsecureSchema(schema: any): boolean {
    const schemaStr = JSON.stringify(schema).toLowerCase();

    // Check for common insecure patterns
    const insecurePatterns = [
      /eval\(/i,
      /exec\(/i,
      /script/i,
      /javascript:/i,
    ];

    return insecurePatterns.some(pattern => pattern.test(schemaStr));
  }

  /**
   * Search schema recursively for sensitive fields
   */
  private searchSchema(
    obj: any,
    path: string,
    patterns: Array<{ pattern: RegExp; severity: 'critical' | 'high' | 'medium' | 'low' }>,
    results: SensitiveField[]
  ): void {
    if (typeof obj !== 'object' || obj === null) {
      return;
    }

    for (const key in obj) {
      const currentPath = path ? `${path}.${key}` : key;
      const value = obj[key];

      // Check field name against patterns
      for (const { pattern, severity } of patterns) {
        if (pattern.test(key)) {
          results.push({
            field: currentPath,
            type: typeof value,
            issue: `Field name matches sensitive pattern: ${pattern.source}`,
            severity,
          });
        }
      }

      // Recursively search nested objects
      if (typeof value === 'object' && value !== null) {
        this.searchSchema(value, currentPath, patterns, results);
      }
    }
  }

  /**
   * Check if schema has validation annotations
   */
  private hasValidationAnnotations(schema: any): boolean {
    const schemaStr = JSON.stringify(schema);

    // Check for common validation keywords
    const validationKeywords = [
      'required',
      'type',
      'format',
      'pattern',
      'minLength',
      'maxLength',
      'minimum',
      'maximum',
      'enum',
      'const',
    ];

    return validationKeywords.some(keyword => schemaStr.includes(keyword));
  }

  /**
   * Parse version string (e.g., "1.2.3" or "v1.2.3")
   */
  private parseVersion(version: string): { major: number; minor: number; patch: number } | null {
    const cleaned = version.replace(/^v/i, '');
    const match = cleaned.match(/^(\d+)\.(\d+)\.(\d+)/);

    if (!match) {
      return null;
    }

    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2], 10),
      patch: parseInt(match[3], 10),
    };
  }
}

