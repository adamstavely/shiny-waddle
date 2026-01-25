/**
 * Secrets Management Validator
 * 
 * Validates secrets storage, rotation, access logging, and injection security
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

export interface SecretsManagerConfig {
  type: 'vault' | 'aws-secrets-manager' | 'azure-key-vault' | 'gcp-secret-manager' | 'kubernetes' | 'env-var';
  connection: any;
}

export interface SecretsValidationResult {
  passed: boolean;
  secretsTested: number;
  issues: Array<{
    secretName: string;
    issue: 'not-encrypted' | 'no-access-control' | 'no-rotation' | 'hardcoded' | 'no-audit-log';
    severity: 'critical' | 'high' | 'medium' | 'low';
    recommendation: string;
  }>;
  rotationPolicies: RotationPolicyResult[];
  accessControls: AccessControlResult[];
}

export interface RotationPolicyResult {
  secretName: string;
  hasRotation: boolean;
  rotationInterval?: number;
  lastRotated?: Date;
  issues: string[];
}

export interface AccessControlResult {
  secretName: string;
  hasAccessControl: boolean;
  accessLevels: string[];
  issues: string[];
}

export interface RotationResult {
  secretName: string;
  canRotate: boolean;
  rotationMethod?: string;
  issues: string[];
}

export interface LoggingResult {
  hasLogging: boolean;
  logLevel: 'none' | 'basic' | 'detailed';
  issues: string[];
}

export interface HardcodedSecret {
  file: string;
  line: number;
  secretType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface InjectionResult {
  passed: boolean;
  injectionMethod: string;
  isSecure: boolean;
  issues: string[];
}

export class SecretsManagementValidator {
  private secretPatterns: Array<{
    name: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;

  constructor() {
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
        name: 'Private Key',
        pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i,
        severity: 'critical',
      },
    ];
  }

  /**
   * Validate secrets storage
   */
  async validateSecretsStorage(
    config: SecretsManagerConfig
  ): Promise<SecretsValidationResult> {
    const issues: SecretsValidationResult['issues'] = [];
    const rotationPolicies: RotationPolicyResult[] = [];
    const accessControls: AccessControlResult[] = [];

    // Validate based on secrets manager type
    switch (config.type) {
      case 'vault':
        return this.validateVaultStorage(config);
      case 'aws-secrets-manager':
        return this.validateAWSSecretsManager(config);
      case 'azure-key-vault':
        return this.validateAzureKeyVault(config);
      case 'gcp-secret-manager':
        return this.validateGCPSecretManager(config);
      case 'kubernetes':
        return this.validateKubernetesSecrets(config);
      case 'env-var':
        return this.validateEnvVarSecrets(config);
      default:
        issues.push({
          secretName: 'unknown',
          issue: 'no-access-control',
          severity: 'high',
          recommendation: 'Use a proper secrets management system',
        });
    }

    return {
      passed: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0,
      secretsTested: 0,
      issues,
      rotationPolicies,
      accessControls,
    };
  }

  /**
   * Test secrets rotation
   */
  async testSecretsRotation(
    config: SecretsManagerConfig,
    secretName: string
  ): Promise<RotationResult> {
    const issues: string[] = [];

    // Check if rotation is supported
    const supportsRotation = ['vault', 'aws-secrets-manager', 'azure-key-vault', 'gcp-secret-manager'].includes(
      config.type
    );

    if (!supportsRotation) {
      issues.push(`Secrets manager type ${config.type} does not support automatic rotation`);
    }

    // Check rotation configuration
    if (config.connection?.rotationConfig) {
      const rotationConfig = config.connection.rotationConfig;
      if (!rotationConfig.enabled) {
        issues.push('Rotation is configured but not enabled');
      }
      if (!rotationConfig.interval) {
        issues.push('Rotation interval is not specified');
      }
    } else {
      issues.push('No rotation configuration found');
    }

    return {
      secretName,
      canRotate: supportsRotation && issues.length === 0,
      rotationMethod: supportsRotation ? 'automatic' : 'manual',
      issues,
    };
  }

  /**
   * Validate secrets access logging
   */
  async validateSecretsAccessLogging(
    config: SecretsManagerConfig
  ): Promise<LoggingResult> {
    const issues: string[] = [];

    // Check if logging is enabled
    const hasLogging = config.connection?.logging?.enabled !== false;

    if (!hasLogging) {
      issues.push('Secrets access logging is not enabled');
    }

    // Check log level
    const logLevel = config.connection?.logging?.level || 'none';
    if (logLevel === 'none') {
      issues.push('Secrets access logging level is set to none');
    }

    return {
      hasLogging,
      logLevel: logLevel as 'none' | 'basic' | 'detailed',
      issues,
    };
  }

  /**
   * Detect hardcoded secrets in codebase
   */
  async detectHardcodedSecretsInCode(
    codebasePath: string
  ): Promise<HardcodedSecret[]> {
    const secrets: HardcodedSecret[] = [];

    try {
      const files = await this.getAllCodeFiles(codebasePath);
      
      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf-8');
          const lines = content.split('\n');

          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            for (const pattern of this.secretPatterns) {
              if (pattern.pattern.test(line)) {
                secrets.push({
                  file,
                  line: i + 1,
                  secretType: pattern.name,
                  severity: pattern.severity,
                });
              }
            }
          }
        } catch (error) {
          // Skip files that can't be read
        }
      }
    } catch (error) {
      // Handle errors
    }

    return secrets;
  }

  /**
   * Test secrets injection
   */
  async testSecretsInjection(
    config: SecretsManagerConfig
  ): Promise<InjectionResult> {
    const issues: string[] = [];

    // Check injection method
    const injectionMethod = config.connection?.injectionMethod || 'unknown';

    // Validate injection security
    const insecureMethods = ['hardcoded', 'plaintext', 'unencrypted'];
    const isSecure = !insecureMethods.includes(injectionMethod.toLowerCase());

    if (!isSecure) {
      issues.push(`Insecure injection method: ${injectionMethod}`);
    }

    // Check if secrets are injected at runtime
    if (config.connection?.injectionTime !== 'runtime') {
      issues.push('Secrets should be injected at runtime, not build time');
    }

    return {
      passed: isSecure && issues.length === 0,
      injectionMethod,
      isSecure,
      issues,
    };
  }

  /**
   * Validate HashiCorp Vault storage
   */
  private async validateVaultStorage(
    config: SecretsManagerConfig
  ): Promise<SecretsValidationResult> {
    const issues: SecretsValidationResult['issues'] = [];
    const rotationPolicies: RotationPolicyResult[] = [];
    const accessControls: AccessControlResult[] = [];

    // Vault typically has encryption, access control, and rotation
    // This is a simplified check - real implementation would connect to Vault API

    if (!config.connection?.address) {
      issues.push({
        secretName: 'vault-config',
        issue: 'no-access-control',
        severity: 'high',
        recommendation: 'Configure Vault connection address',
      });
    }

    return {
      passed: issues.length === 0,
      secretsTested: 0,
      issues,
      rotationPolicies,
      accessControls,
    };
  }

  /**
   * Validate AWS Secrets Manager storage
   */
  private async validateAWSSecretsManager(
    config: SecretsManagerConfig
  ): Promise<SecretsValidationResult> {
    const issues: SecretsValidationResult['issues'] = [];
    const rotationPolicies: RotationPolicyResult[] = [];
    const accessControls: AccessControlResult[] = [];

    // AWS Secrets Manager has encryption and access control by default
    // Check for IAM policies
    if (!config.connection?.iamPolicy) {
      issues.push({
        secretName: 'aws-secrets',
        issue: 'no-access-control',
        severity: 'medium',
        recommendation: 'Configure IAM policies for secrets access',
      });
    }

    return {
      passed: issues.length === 0,
      secretsTested: 0,
      issues,
      rotationPolicies,
      accessControls,
    };
  }

  /**
   * Validate Azure Key Vault storage
   */
  private async validateAzureKeyVault(
    config: SecretsManagerConfig
  ): Promise<SecretsValidationResult> {
    const issues: SecretsValidationResult['issues'] = [];
    const rotationPolicies: RotationPolicyResult[] = [];
    const accessControls: AccessControlResult[] = [];

    // Azure Key Vault has encryption and access control
    if (!config.connection?.vaultUrl) {
      issues.push({
        secretName: 'azure-keyvault',
        issue: 'no-access-control',
        severity: 'high',
        recommendation: 'Configure Key Vault URL',
      });
    }

    return {
      passed: issues.length === 0,
      secretsTested: 0,
      issues,
      rotationPolicies,
      accessControls,
    };
  }

  /**
   * Validate GCP Secret Manager storage
   */
  private async validateGCPSecretManager(
    config: SecretsManagerConfig
  ): Promise<SecretsValidationResult> {
    const issues: SecretsValidationResult['issues'] = [];
    const rotationPolicies: RotationPolicyResult[] = [];
    const accessControls: AccessControlResult[] = [];

    // GCP Secret Manager has encryption and IAM access control
    if (!config.connection?.projectId) {
      issues.push({
        secretName: 'gcp-secrets',
        issue: 'no-access-control',
        severity: 'high',
        recommendation: 'Configure GCP project ID',
      });
    }

    return {
      passed: issues.length === 0,
      secretsTested: 0,
      issues,
      rotationPolicies,
      accessControls,
    };
  }

  /**
   * Validate Kubernetes secrets
   */
  private async validateKubernetesSecrets(
    config: SecretsManagerConfig
  ): Promise<SecretsValidationResult> {
    const issues: SecretsValidationResult['issues'] = [];
    const rotationPolicies: RotationPolicyResult[] = [];
    const accessControls: AccessControlResult[] = [];

    // Kubernetes secrets are base64 encoded but not encrypted by default
    issues.push({
      secretName: 'kubernetes-secrets',
      issue: 'not-encrypted',
      severity: 'high',
      recommendation: 'Use external secrets operator or encrypted secrets',
    });

    return {
      passed: false,
      secretsTested: 0,
      issues,
      rotationPolicies,
      accessControls,
    };
  }

  /**
   * Validate environment variable secrets
   */
  private async validateEnvVarSecrets(
    config: SecretsManagerConfig
  ): Promise<SecretsValidationResult> {
    const issues: SecretsValidationResult['issues'] = [];
    const rotationPolicies: RotationPolicyResult[] = [];
    const accessControls: AccessControlResult[] = [];

    // Environment variables are not encrypted and have no access control
    issues.push({
      secretName: 'env-var-secrets',
      issue: 'not-encrypted',
      severity: 'critical',
      recommendation: 'Use a proper secrets management system instead of environment variables',
    });

    issues.push({
      secretName: 'env-var-secrets',
      issue: 'no-access-control',
      severity: 'high',
      recommendation: 'Environment variables have no access control mechanisms',
    });

    return {
      passed: false,
      secretsTested: 0,
      issues,
      rotationPolicies,
      accessControls,
    };
  }

  /**
   * Get all code files in a directory
   */
  private async getAllCodeFiles(dirPath: string): Promise<string[]> {
    const files: string[] = [];
    const codeExtensions = ['.ts', '.js', '.py', '.java', '.go', '.rb', '.php', '.cs'];

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        // Skip node_modules, .git, etc.
        if (entry.name.startsWith('.') || entry.name === 'node_modules') {
          continue;
        }

        if (entry.isDirectory()) {
          const subFiles = await this.getAllCodeFiles(fullPath);
          files.push(...subFiles);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (codeExtensions.includes(ext)) {
            files.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Handle errors
    }

    return files;
  }
}

