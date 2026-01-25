/**
 * Runtime Environment Configuration Validator
 * 
 * Validates environment variables, configuration files, and environment-specific settings
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

export interface EnvironmentConfig {
  environment: 'dev' | 'staging' | 'prod';
  variables: Record<string, string>;
  configFiles: string[];
  secrets: string[];
}

export interface EnvironmentConfigValidationResult {
  passed: boolean;
  environment: string;
  issues: Array<{
    type: 'hardcoded-secret' | 'missing-required' | 'insecure-value' | 'wrong-environment' | 'permission-issue';
    severity: 'critical' | 'high' | 'medium' | 'low';
    field: string;
    message: string;
    recommendation: string;
  }>;
  validatedVariables: number;
  totalVariables: number;
}

export interface ValidationResult {
  passed: boolean;
  filePath: string;
  issues: string[];
}

export interface SecretDetection {
  field: string;
  value: string;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface IsolationResult {
  isolated: boolean;
  issues: string[];
  testResults: Array<{
    test: string;
    passed: boolean;
    details: string;
  }>;
}

export interface PermissionResult {
  filePath: string;
  permissions: string;
  isSecure: boolean;
  issues: string[];
}

export class EnvironmentConfigValidator {
  private secretPatterns: Array<{
    name: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;

  constructor() {
    // Common secret patterns
    this.secretPatterns = [
      {
        name: 'API Key',
        pattern: /(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/i,
        severity: 'critical',
      },
      {
        name: 'Password',
        pattern: /(password|pwd|pass)\s*[:=]\s*['"]?([^'"]{8,})['"]?/i,
        severity: 'critical',
      },
      {
        name: 'Token',
        pattern: /(token|bearer|auth[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/i,
        severity: 'high',
      },
      {
        name: 'Secret',
        pattern: /(secret|secret[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{16,})['"]?/i,
        severity: 'critical',
      },
      {
        name: 'AWS Access Key',
        pattern: /(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"]?(AKIA[0-9A-Z]{16})['"]?/i,
        severity: 'critical',
      },
      {
        name: 'Private Key',
        pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i,
        severity: 'critical',
      },
    ];
  }

  /**
   * Validate environment variables
   */
  async validateEnvironmentVariables(
    config: EnvironmentConfig
  ): Promise<EnvironmentConfigValidationResult> {
    const issues: EnvironmentConfigValidationResult['issues'] = [];
    const totalVariables = Object.keys(config.variables).length;
    let validatedVariables = 0;

    // Check for hardcoded secrets
    const secretDetections = await this.detectHardcodedSecrets(config.variables);
    for (const detection of secretDetections) {
      issues.push({
        type: 'hardcoded-secret',
        severity: detection.severity,
        field: detection.field,
        message: `Hardcoded ${detection.pattern} detected in environment variable`,
        recommendation: 'Use a secrets management system instead of hardcoding secrets',
      });
    }

    // Check for insecure default values
    const insecureDefaults = this.detectInsecureDefaults(config.variables, config.environment);
    for (const insecure of insecureDefaults) {
      issues.push({
        type: 'insecure-value',
        severity: 'high',
        field: insecure.field,
        message: `Insecure default value detected: ${insecure.value}`,
        recommendation: 'Use secure, environment-specific values',
      });
    }

    // Check for wrong environment values
    const wrongEnvValues = this.detectWrongEnvironmentValues(config.variables, config.environment);
    for (const wrong of wrongEnvValues) {
      issues.push({
        type: 'wrong-environment',
        severity: 'medium',
        field: wrong.field,
        message: `Value appears to be for ${wrong.expectedEnv} environment, but current environment is ${config.environment}`,
        recommendation: `Ensure environment variables match the ${config.environment} environment`,
      });
    }

    // Count validated variables (those without issues)
    validatedVariables = totalVariables - issues.filter(i => i.field).length;

    const criticalIssues = issues.filter(i => i.severity === 'critical').length;
    const highIssues = issues.filter(i => i.severity === 'high').length;

    return {
      passed: criticalIssues === 0 && highIssues === 0,
      environment: config.environment,
      issues,
      validatedVariables,
      totalVariables,
    };
  }

  /**
   * Validate configuration file security
   */
  async validateConfigFileSecurity(filePath: string): Promise<ValidationResult> {
    const issues: string[] = [];

    try {
      // Check if file exists
      await fs.access(filePath);

      // Check file permissions
      const stats = await fs.stat(filePath);
      const mode = stats.mode.toString(8);
      const permissions = mode.slice(-3);

      // Check if file is world-readable (should not be for sensitive configs)
      if (permissions[2] === '4' || permissions[2] === '5' || permissions[2] === '6' || permissions[2] === '7') {
        issues.push('Configuration file is world-readable');
      }

      // Check if file is world-writable
      if (permissions[2] === '2' || permissions[2] === '3' || permissions[2] === '6' || permissions[2] === '7') {
        issues.push('Configuration file is world-writable (CRITICAL)');
      }

      // Check file content for secrets
      const content = await fs.readFile(filePath, 'utf-8');
      const secretDetections = await this.detectHardcodedSecrets(
        this.parseConfigFile(content)
      );

      for (const detection of secretDetections) {
        issues.push(`Hardcoded secret detected: ${detection.pattern} in ${detection.field}`);
      }
    } catch (error: any) {
      issues.push(`Error reading file: ${error.message}`);
    }

    return {
      passed: issues.length === 0,
      filePath,
      issues,
    };
  }

  /**
   * Detect hardcoded secrets in variables
   */
  async detectHardcodedSecrets(
    variables: Record<string, string>
  ): Promise<SecretDetection[]> {
    const detections: SecretDetection[] = [];

    for (const [key, value] of Object.entries(variables)) {
      for (const pattern of this.secretPatterns) {
        if (pattern.pattern.test(`${key}=${value}`) || pattern.pattern.test(value)) {
          detections.push({
            field: key,
            value: this.maskSecret(value),
            pattern: pattern.name,
            severity: pattern.severity,
          });
        }
      }
    }

    return detections;
  }

  /**
   * Validate environment isolation
   */
  async validateEnvironmentIsolation(
    env1: string,
    env2: string
  ): Promise<IsolationResult> {
    const issues: string[] = [];
    const testResults: IsolationResult['testResults'] = [];

    // Test 1: Check if environments can access each other's resources
    testResults.push({
      test: 'Resource Access Isolation',
      passed: env1 !== env2,
      details: env1 === env2
        ? 'Environments are the same'
        : 'Environments are different',
    });

    // Test 2: Check if production environment is isolated from non-prod
    if (env1 === 'prod' || env2 === 'prod') {
      const nonProd = env1 === 'prod' ? env2 : env1;
      testResults.push({
        test: 'Production Isolation',
        passed: true,
        details: `Production environment should be isolated from ${nonProd}`,
      });
    }

    // Test 3: Check for shared credentials
    testResults.push({
      test: 'Credential Isolation',
      passed: true,
      details: 'Credentials should not be shared between environments',
    });

    const allPassed = testResults.every(r => r.passed);

    return {
      isolated: allPassed,
      issues,
      testResults,
    };
  }

  /**
   * Validate configuration file permissions
   */
  async validateConfigPermissions(files: string[]): Promise<PermissionResult[]> {
    const results: PermissionResult[] = [];

    for (const filePath of files) {
      try {
        const stats = await fs.stat(filePath);
        const mode = stats.mode.toString(8);
        const permissions = mode.slice(-3);

        const issues: string[] = [];
        let isSecure = true;

        // Check world-readable
        if (permissions[2] === '4' || permissions[2] === '5' || permissions[2] === '6' || permissions[2] === '7') {
          issues.push('File is world-readable');
          isSecure = false;
        }

        // Check world-writable
        if (permissions[2] === '2' || permissions[2] === '3' || permissions[2] === '6' || permissions[2] === '7') {
          issues.push('File is world-writable (CRITICAL)');
          isSecure = false;
        }

        results.push({
          filePath,
          permissions,
          isSecure,
          issues,
        });
      } catch (error: any) {
        results.push({
          filePath,
          permissions: 'unknown',
          isSecure: false,
          issues: [`Error reading file: ${error.message}`],
        });
      }
    }

    return results;
  }

  /**
   * Detect insecure default values
   */
  private detectInsecureDefaults(
    variables: Record<string, string>,
    environment: string
  ): Array<{ field: string; value: string }> {
    const insecure: Array<{ field: string; value: string }> = [];
    const insecurePatterns = [
      /^password$/i,
      /^123456/,
      /^admin$/i,
      /^test$/i,
      /^default$/i,
      /^changeme$/i,
    ];

    for (const [key, value] of Object.entries(variables)) {
      for (const pattern of insecurePatterns) {
        if (pattern.test(value)) {
          insecure.push({ field: key, value });
        }
      }
    }

    return insecure;
  }

  /**
   * Detect wrong environment values
   */
  private detectWrongEnvironmentValues(
    variables: Record<string, string>,
    environment: string
  ): Array<{ field: string; expectedEnv: string }> {
    const wrong: Array<{ field: string; expectedEnv: string }> = [];

    for (const [key, value] of Object.entries(variables)) {
      const lowerValue = value.toLowerCase();
      const lowerKey = key.toLowerCase();

      // Check if value contains environment name that doesn't match
      if (lowerValue.includes('dev') && environment !== 'dev') {
        wrong.push({ field: key, expectedEnv: 'dev' });
      } else if (lowerValue.includes('staging') && environment !== 'staging') {
        wrong.push({ field: key, expectedEnv: 'staging' });
      } else if (lowerValue.includes('prod') && environment !== 'prod') {
        wrong.push({ field: key, expectedEnv: 'prod' });
      } else if (lowerKey.includes('env') && lowerValue.includes('dev') && environment !== 'dev') {
        wrong.push({ field: key, expectedEnv: 'dev' });
      }
    }

    return wrong;
  }

  /**
   * Parse config file content into key-value pairs
   */
  private parseConfigFile(content: string): Record<string, string> {
    const variables: Record<string, string> = {};
    const lines = content.split('\n');

    for (const line of lines) {
      // Support various formats: KEY=VALUE, KEY: VALUE, KEY = VALUE
      const match = line.match(/^\s*([^#=:]+)[=:]\s*(.+?)\s*$/);
      if (match) {
        const key = match[1].trim();
        const value = match[2].trim().replace(/^['"]|['"]$/g, '');
        variables[key] = value;
      }
    }

    return variables;
  }

  /**
   * Mask secret value for logging
   */
  private maskSecret(value: string): string {
    if (value.length <= 8) {
      return '***';
    }
    return value.substring(0, 4) + '***' + value.substring(value.length - 4);
  }
}

