/**
 * CI/CD Security Gates Service
 * 
 * Enhanced security gates for CI/CD pipelines
 */

import { SecurityGateConfig, SecurityGateResult, PullRequest, IACScanResult, ContainerScanResult, K8sRBACTest } from '../core/types';
import { IACScanner } from './iac-scanner';
import { ContainerSecurityScanner } from './container-security-scanner';
import { K8sRBACValidator } from './k8s-rbac-validator';
import { PolicyValidationTester } from './policy-validation-tester';
import { PolicyDecisionPoint } from './policy-decision-point';
import { ABACPolicy } from '../core/types';

/**
 * Configuration for CI/CD Security Gates
 */
export interface CICDSecurityGatesConfig {
  /**
   * Optional IAC scanner instance
   */
  iacScanner?: IACScanner;
  
  /**
   * Optional container scanner instance
   */
  containerScanner?: ContainerSecurityScanner;
  
  /**
   * Optional K8s RBAC validator instance
   */
  k8sValidator?: K8sRBACValidator;
  
  /**
   * Optional policy validator instance
   */
  policyValidator?: PolicyValidationTester;
  
  /**
   * Custom file pattern matchers for different file types
   */
  filePatterns?: {
    iac?: string[];
    container?: string[];
    k8s?: string[];
  };
  
  /**
   * Custom severity weights for risk score calculation
   */
  severityWeights?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
  
  /**
   * Custom image extraction function for container scanning
   */
  imageExtractor?: (files: string[]) => string[];
}

export class CICDSecurityGates {
  private iacScanner: IACScanner;
  private containerScanner: ContainerSecurityScanner;
  private k8sValidator: K8sRBACValidator;
  private policyValidator?: PolicyValidationTester;
  private config: CICDSecurityGatesConfig;

  constructor(
    config?: CICDSecurityGatesConfig | IACScanner,
    containerScanner?: ContainerSecurityScanner,
    k8sValidator?: K8sRBACValidator,
    policyValidator?: PolicyValidationTester
  ) {
    // Support both old constructor signature and new config object for backward compatibility
    if (config && 'scanFiles' in config) {
      // Old format: individual parameters
      this.config = {};
      this.iacScanner = config as IACScanner;
      this.containerScanner = containerScanner || new ContainerSecurityScanner();
      this.k8sValidator = k8sValidator || new K8sRBACValidator();
      this.policyValidator = policyValidator;
    } else {
      // New format: config object
      this.config = (config as CICDSecurityGatesConfig) || {};
      this.iacScanner = this.config.iacScanner || new IACScanner();
      this.containerScanner = this.config.containerScanner || new ContainerSecurityScanner();
      this.k8sValidator = this.config.k8sValidator || new K8sRBACValidator();
      this.policyValidator = this.config.policyValidator;
    }
  }

  /**
   * Validate pre-merge policies
   */
  async validatePreMergePolicies(
    pr: PullRequest,
    policies: ABACPolicy[]
  ): Promise<SecurityGateResult> {
    const gates: Array<{ name: string; passed: boolean; details: any }> = [];
    const findings: any[] = [];

    // Check if policies are required
    if (policies.length === 0) {
      gates.push({
        name: 'Policy Requirements',
        passed: false,
        details: { error: 'No policies defined' },
      });
      findings.push({ type: 'missing-policy', severity: 'high', message: 'No policies defined' });
    } else {
      gates.push({
        name: 'Policy Requirements',
        passed: true,
        details: { policyCount: policies.length },
      });
    }

    // Check for policy conflicts if validator available
    if (this.policyValidator) {
      const conflicts = await this.policyValidator.detectPolicyConflicts(policies);
      if (conflicts.length > 0) {
        gates.push({
          name: 'Policy Conflicts',
          passed: false,
          details: { conflicts },
        });
        findings.push(...conflicts.map(c => ({
          type: 'policy-conflict',
          severity: 'high',
          message: c.description,
        })));
      } else {
        gates.push({
          name: 'Policy Conflicts',
          passed: true,
          details: {},
        });
      }
    }

    const passed = gates.every(gate => gate.passed);
    const riskScore = this.calculateRiskScore(findings);

    return {
      passed,
      gates,
      findings,
      riskScore,
      message: passed
        ? 'All pre-merge policy checks passed'
        : 'Pre-merge policy checks failed',
    };
  }

  /**
   * Check security gates for a pull request
   */
  async checkSecurityGates(
    pr: PullRequest,
    config: SecurityGateConfig
  ): Promise<SecurityGateResult> {
    const gates: Array<{ name: string; passed: boolean; details: any }> = [];
    const findings: any[] = [];

    // Policy validation gate
    if (config.requirePolicies) {
      const policyGate = await this.validatePreMergePolicies(pr, []);
      gates.push(...policyGate.gates);
      findings.push(...policyGate.findings);
    }

    // Infrastructure-as-Code scanning gate
    if (config.scanIAC) {
      const iacPatterns = this.config.filePatterns?.iac || [
        '.tf', '.tfvars', '.yaml', '.yml', 'cloudformation', 'terraform'
      ];
      const iacFiles = pr.files.filter(f => 
        iacPatterns.some(pattern => f.endsWith(pattern) || f.includes(pattern))
      );

      if (iacFiles.length > 0) {
        const iacResult = await this.iacScanner.scanFiles(iacFiles);
        gates.push({
          name: 'Infrastructure-as-Code Scan',
          passed: iacResult.passed,
          details: iacResult,
        });

        if (!iacResult.passed) {
          findings.push(...iacResult.findings);
        }
      }
    }

    // Container scanning gate
    if (config.scanContainers) {
      const containerPatterns = this.config.filePatterns?.container || [
        'Dockerfile', 'docker-compose'
      ];
      const dockerFiles = pr.files.filter(f => 
        containerPatterns.some(pattern => f.includes(pattern))
      );

      if (dockerFiles.length > 0) {
        // Extract image names from files
        const images = this.config.imageExtractor 
          ? this.config.imageExtractor(dockerFiles)
          : ['app:latest']; // Default fallback
        for (const image of images) {
          const containerResult = await this.containerScanner.scanImage(image);
          gates.push({
            name: `Container Scan: ${image}`,
            passed: containerResult.passed,
            details: containerResult,
          });

          if (!containerResult.passed) {
            findings.push(...containerResult.vulnerabilities);
          }
        }
      }
    }

    // Kubernetes RBAC validation gate
    if (config.validateK8sRBAC) {
      const k8sPatterns = this.config.filePatterns?.k8s || [
        'role', 'rbac', 'serviceaccount'
      ];
      const k8sFiles = pr.files.filter(f => 
        (f.endsWith('.yaml') || f.endsWith('.yml')) && 
        k8sPatterns.some(pattern => f.includes(pattern))
      );

      if (k8sFiles.length > 0) {
        const k8sResult = await this.k8sValidator.validateFiles(k8sFiles);
        gates.push({
          name: 'Kubernetes RBAC Validation',
          passed: k8sResult.passed,
          details: k8sResult,
        });

        if (!k8sResult.passed) {
          findings.push({
            type: 'k8s-rbac',
            severity: 'high',
            message: 'Kubernetes RBAC validation failed',
          });
        }
      }
    }

    // Evaluate overall result
    const passed = gates.every(gate => gate.passed);
    const riskScore = this.calculateRiskScore(findings);

    // Check severity threshold
    if (config.failOnThreshold && !passed) {
      const thresholdSeverity = config.severityThreshold;
      const hasThresholdViolation = findings.some(f => 
        this.severityLevel(f.severity) >= this.severityLevel(thresholdSeverity)
      );

      if (hasThresholdViolation) {
        return {
          passed: false,
          gates,
          findings,
          riskScore,
          message: `Security gates failed: ${thresholdSeverity} or higher severity findings detected`,
        };
      }
    }

    // Check max findings
    if (config.maxFindings && findings.length > config.maxFindings) {
      return {
        passed: false,
        gates,
        findings,
        riskScore,
        message: `Security gates failed: ${findings.length} findings exceed maximum of ${config.maxFindings}`,
      };
    }

    return {
      passed,
      gates,
      findings,
      riskScore,
      message: passed
        ? 'All security gates passed'
        : 'Some security gates failed',
    };
  }

  /**
   * Calculate risk score from findings
   */
  private calculateRiskScore(findings: any[]): number {
    const severityWeights: Record<string, number> = {
      critical: this.config.severityWeights?.critical ?? 10,
      high: this.config.severityWeights?.high ?? 7,
      medium: this.config.severityWeights?.medium ?? 4,
      low: this.config.severityWeights?.low ?? 1,
    };

    const totalWeight = findings.reduce((sum, f) => {
      const weight = severityWeights[f.severity] || 1;
      return sum + weight;
    }, 0);

    return Math.min(100, (totalWeight / findings.length) * 10 || 0);
  }

  /**
   * Get severity level as number
   */
  private severityLevel(severity: string): number {
    const levels: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };
    return levels[severity] || 0;
  }
}

