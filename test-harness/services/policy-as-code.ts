/**
 * Policy as Code Service
 * 
 * Supports policy definition in code (YAML/JSON), versioning, testing, and enforcement
 */

import { ABACPolicy } from '../core/types';
import { PolicyVersioning, PolicyVersion } from './policy-versioning';
import * as fs from 'fs/promises';
import * as path from 'path';

// Optional YAML support
let yaml: any;
try {
  yaml = require('js-yaml');
} catch {
  try {
    yaml = require('yaml');
  } catch {
    // YAML support not available
  }
}

export interface PolicyAsCodeConfig {
  format: 'json' | 'yaml' | 'rego';
  versioning: boolean;
  testing: {
    enabled: boolean;
    testSuite?: string;
  };
  enforcement: {
    enabled: boolean;
    mode: 'gatekeeper' | 'admission-controller' | 'sidecar' | 'inline';
  };
}

export interface PolicyTestResult {
  policyId: string;
  passed: boolean;
  testCases: PolicyTestCase[];
  errors: string[];
  warnings: string[];
}

export interface PolicyTestCase {
  name: string;
  description?: string;
  request: {
    subject: any;
    resource: any;
    action: string;
    context?: any;
  };
  expected: {
    allowed: boolean;
    reason?: string;
  };
  actual?: {
    allowed: boolean;
    reason?: string;
  };
  passed: boolean;
}

export interface PolicyEnforcementResult {
  policyId: string;
  enforced: boolean;
  enforcementPoint: string;
  mode: string;
  timestamp: Date;
  errors?: string[];
}

export class PolicyAsCode {
  private versioning: PolicyVersioning;
  private policiesDir: string;
  private config: PolicyAsCodeConfig;

  constructor(
    policiesDir: string = './policies',
    config: Partial<PolicyAsCodeConfig> = {}
  ) {
    this.policiesDir = policiesDir;
    this.versioning = new PolicyVersioning(path.join(policiesDir, 'versions'));
    this.config = {
      format: config.format || 'json',
      versioning: config.versioning !== false,
      testing: config.testing || { enabled: true },
      enforcement: config.enforcement || {
        enabled: false,
        mode: 'inline',
      },
    };
  }

  /**
   * Load policy from file (supports JSON, YAML, and Rego)
   */
  async loadPolicy(filePath: string): Promise<{
    policies: ABACPolicy[];
    format: 'json' | 'yaml' | 'rego';
    metadata?: any;
  }> {
    const content = await fs.readFile(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.yaml' || ext === '.yml') {
      return this.loadYAMLPolicy(content, filePath);
    } else if (ext === '.rego') {
      return this.loadRegoPolicy(content, filePath);
    } else {
      return this.loadJSONPolicy(content, filePath);
    }
  }

  /**
   * Load YAML policy
   */
  private loadYAMLPolicy(
    content: string,
    filePath: string
  ): {
    policies: ABACPolicy[];
    format: 'yaml';
    metadata?: any;
  } {
    if (!yaml) {
      throw new Error('YAML support not available. Install js-yaml or yaml package.');
    }
    try {
      const parsed = yaml.load(content) as any;
      
      // Support multiple YAML formats
      if (parsed.policies) {
        // Format: { policies: [...] }
        return {
          policies: parsed.policies.map((p: any) => this.normalizePolicy(p)),
          format: 'yaml',
          metadata: parsed.metadata,
        };
      } else if (Array.isArray(parsed)) {
        // Format: [{ id: ..., name: ... }, ...]
        return {
          policies: parsed.map((p: any) => this.normalizePolicy(p)),
          format: 'yaml',
        };
      } else if (parsed.id) {
        // Format: { id: ..., name: ..., ... }
        return {
          policies: [this.normalizePolicy(parsed)],
          format: 'yaml',
        };
      } else {
        throw new Error('Invalid YAML policy format');
      }
    } catch (error: any) {
      throw new Error(`Failed to parse YAML policy: ${error.message}`);
    }
  }

  /**
   * Load JSON policy
   */
  private loadJSONPolicy(
    content: string,
    filePath: string
  ): {
    policies: ABACPolicy[];
    format: 'json';
    metadata?: any;
  } {
    try {
      const parsed = JSON.parse(content);
      
      if (parsed.policies) {
        return {
          policies: parsed.policies.map((p: any) => this.normalizePolicy(p)),
          format: 'json',
          metadata: parsed.metadata,
        };
      } else if (Array.isArray(parsed)) {
        return {
          policies: parsed.map((p: any) => this.normalizePolicy(p)),
          format: 'json',
        };
      } else if (parsed.id) {
        return {
          policies: [this.normalizePolicy(parsed)],
          format: 'json',
        };
      } else {
        throw new Error('Invalid JSON policy format');
      }
    } catch (error: any) {
      throw new Error(`Failed to parse JSON policy: ${error.message}`);
    }
  }

  /**
   * Load Rego policy
   */
  private loadRegoPolicy(
    content: string,
    filePath: string
  ): {
    policies: ABACPolicy[];
    format: 'rego';
    metadata?: any;
  } {
    // For Rego, we create a wrapper ABAC policy that references the Rego code
    const policyId = path.basename(filePath, '.rego');
    return {
      policies: [
        {
          id: policyId,
          name: `Rego Policy: ${policyId}`,
          description: 'Rego policy loaded from file',
          effect: 'allow', // Default, actual evaluation happens via Rego
          conditions: [],
          priority: 0,
          metadata: {
            format: 'rego',
            regoCode: content,
          },
        } as any,
      ],
      format: 'rego',
    };
  }

  /**
   * Normalize policy to ABAC format
   */
  private normalizePolicy(policy: any): ABACPolicy {
    return {
      id: policy.id || `policy-${Date.now()}`,
      name: policy.name || policy.id || 'Unnamed Policy',
      description: policy.description,
      effect: policy.effect || 'allow',
      priority: policy.priority || 0,
      conditions: policy.conditions || [],
      metadata: policy.metadata,
    };
  }

  /**
   * Save policy to file
   */
  async savePolicy(
    policies: ABACPolicy[],
    filePath: string,
    format: 'json' | 'yaml' = 'json'
  ): Promise<void> {
    await fs.mkdir(path.dirname(filePath), { recursive: true });

    if (format === 'yaml') {
      if (!yaml) {
        throw new Error('YAML support not available. Install js-yaml or yaml package.');
      }
      const yamlContent = yaml.dump(
        policies.length === 1 ? policies[0] : { policies },
        { indent: 2 }
      );
      await fs.writeFile(filePath, yamlContent);
    } else {
      const jsonContent =
        policies.length === 1
          ? JSON.stringify(policies[0], null, 2)
          : JSON.stringify({ policies }, null, 2);
      await fs.writeFile(filePath, jsonContent);
    }

    // Create version if versioning is enabled
    if (this.config.versioning) {
      await this.versioning.createVersion(
        policies,
        `Policy saved to ${filePath}`,
        process.env.USER || 'system'
      );
    }
  }

  /**
   * Test policy with test cases
   */
  async testPolicy(
    policy: ABACPolicy,
    testCases: PolicyTestCase[],
    evaluator: (request: any) => Promise<{ allowed: boolean; reason?: string }>
  ): Promise<PolicyTestResult> {
    const results: PolicyTestCase[] = [];
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const testCase of testCases) {
      try {
        const actual = await evaluator(testCase.request);
        const passed = actual.allowed === testCase.expected.allowed;

        results.push({
          ...testCase,
          actual,
          passed,
        });

        if (!passed) {
          errors.push(
            `Test "${testCase.name}" failed: expected ${testCase.expected.allowed}, got ${actual.allowed}`
          );
        }
      } catch (error: any) {
        errors.push(`Test "${testCase.name}" error: ${error.message}`);
        results.push({
          ...testCase,
          passed: false,
          actual: { allowed: false, reason: error.message },
        });
      }
    }

    return {
      policyId: policy.id,
      passed: errors.length === 0,
      testCases: results,
      errors,
      warnings,
    };
  }

  /**
   * Enforce policy
   */
  async enforcePolicy(
    policy: ABACPolicy,
    enforcementPoint: string
  ): Promise<PolicyEnforcementResult> {
    if (!this.config.enforcement.enabled) {
      return {
        policyId: policy.id,
        enforced: false,
        enforcementPoint,
        mode: this.config.enforcement.mode,
        timestamp: new Date(),
        errors: ['Policy enforcement is not enabled'],
      };
    }

    try {
      // In a real implementation, this would deploy the policy to the enforcement point
      // For now, we simulate enforcement
      const enforced = await this.deployToEnforcementPoint(
        policy,
        enforcementPoint,
        this.config.enforcement.mode
      );

      return {
        policyId: policy.id,
        enforced,
        enforcementPoint,
        mode: this.config.enforcement.mode,
        timestamp: new Date(),
      };
    } catch (error: any) {
      return {
        policyId: policy.id,
        enforced: false,
        enforcementPoint,
        mode: this.config.enforcement.mode,
        timestamp: new Date(),
        errors: [error.message],
      };
    }
  }

  /**
   * Deploy policy to enforcement point
   */
  private async deployToEnforcementPoint(
    policy: ABACPolicy,
    enforcementPoint: string,
    mode: string
  ): Promise<boolean> {
    // Simulate deployment based on mode
    switch (mode) {
      case 'gatekeeper':
        // Deploy as Kubernetes Gatekeeper policy
        return this.deployAsGatekeeperPolicy(policy, enforcementPoint);
      case 'admission-controller':
        // Deploy as Kubernetes admission controller
        return this.deployAsAdmissionController(policy, enforcementPoint);
      case 'sidecar':
        // Deploy as sidecar proxy
        return this.deployAsSidecar(policy, enforcementPoint);
      case 'inline':
        // Inline enforcement (default)
        return true;
      default:
        throw new Error(`Unsupported enforcement mode: ${mode}`);
    }
  }

  /**
   * Deploy as Gatekeeper policy
   */
  private async deployAsGatekeeperPolicy(
    policy: ABACPolicy,
    enforcementPoint: string
  ): Promise<boolean> {
    // In a real implementation, this would create a Gatekeeper ConstraintTemplate
    // and Constraint resource
    console.log(`Deploying policy ${policy.id} as Gatekeeper policy to ${enforcementPoint}`);
    return true;
  }

  /**
   * Deploy as admission controller
   */
  private async deployAsAdmissionController(
    policy: ABACPolicy,
    enforcementPoint: string
  ): Promise<boolean> {
    // In a real implementation, this would create a ValidatingWebhookConfiguration
    console.log(
      `Deploying policy ${policy.id} as admission controller to ${enforcementPoint}`
    );
    return true;
  }

  /**
   * Deploy as sidecar
   */
  private async deployAsSidecar(
    policy: ABACPolicy,
    enforcementPoint: string
  ): Promise<boolean> {
    // In a real implementation, this would configure a sidecar proxy (e.g., Envoy)
    console.log(`Deploying policy ${policy.id} as sidecar to ${enforcementPoint}`);
    return true;
  }

  /**
   * Convert policy between formats
   */
  async convertPolicy(
    policy: ABACPolicy,
    targetFormat: 'json' | 'yaml' | 'rego'
  ): Promise<string> {
    switch (targetFormat) {
      case 'json':
        return JSON.stringify(policy, null, 2);
      case 'yaml':
        if (!yaml) {
          throw new Error('YAML support not available. Install js-yaml or yaml package.');
        }
        return yaml.dump(policy, { indent: 2 });
      case 'rego':
        // Convert to Rego using policy language support
        const { PolicyLanguageSupport } = await import('./policy-language-support');
        const languageSupport = new PolicyLanguageSupport();
        const regoCode = languageSupport
          .getAdapter('rego')
          ?.convertFromABAC(policy);
        return typeof regoCode === 'string' ? regoCode : JSON.stringify(regoCode);
      default:
        throw new Error(`Unsupported target format: ${targetFormat}`);
    }
  }

  /**
   * Validate policy syntax
   */
  async validatePolicy(policy: ABACPolicy | string, format?: 'json' | 'yaml' | 'rego'): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    try {
      let parsedPolicy: ABACPolicy;

      if (typeof policy === 'string') {
        if (format === 'yaml' || format === undefined) {
          try {
            const loaded = await this.loadYAMLPolicy(policy, '');
            parsedPolicy = loaded.policies[0];
          } catch (e) {
            if (format === 'yaml') throw e;
            // Try JSON
            const loaded = await this.loadJSONPolicy(policy, '');
            parsedPolicy = loaded.policies[0];
          }
        } else if (format === 'json') {
          const loaded = await this.loadJSONPolicy(policy, '');
          parsedPolicy = loaded.policies[0];
        } else {
          // Rego validation
          const { PolicyLanguageSupport } = await import('./policy-language-support');
          const languageSupport = new PolicyLanguageSupport();
          const result = languageSupport.validate('rego', policy);
          return result;
        }
      } else {
        parsedPolicy = policy;
      }

      // Validate ABAC policy structure
      if (!parsedPolicy.id) {
        errors.push('Policy must have an id');
      }
      if (!parsedPolicy.name) {
        errors.push('Policy must have a name');
      }
      if (!parsedPolicy.effect || !['allow', 'deny'].includes(parsedPolicy.effect)) {
        errors.push('Policy must have effect "allow" or "deny"');
      }
      if (!Array.isArray(parsedPolicy.conditions)) {
        errors.push('Policy must have conditions array');
      }

      return {
        valid: errors.length === 0,
        errors,
      };
    } catch (error: any) {
      return {
        valid: false,
        errors: [error.message],
      };
    }
  }

  /**
   * Get policy version history
   */
  async getVersionHistory(limit?: number): Promise<PolicyVersion[]> {
    return this.versioning.getVersionHistory(limit);
  }

  /**
   * Rollback policy to version
   */
  async rollbackToVersion(version: string): Promise<PolicyVersion> {
    return this.versioning.rollback(version);
  }
}

