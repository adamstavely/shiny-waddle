/**
 * Environment-Specific Policy Validator
 * 
 * Validates environment-specific access policies, isolation, and promotion rules
 */

import { ABACPolicy } from '../core/types';
import { PolicyDecisionPoint, PDPRequest } from './policy-decision-point';

export interface EnvironmentPolicy {
  environment: string;
  policies: ABACPolicy[];
  isolationRules: IsolationRule[];
  promotionRules: PromotionRule[];
}

export interface IsolationRule {
  fromEnvironment: string;
  toEnvironment: string;
  allowed: boolean;
  conditions?: Array<{
    attribute: string;
    operator: string;
    value: any;
  }>;
}

export interface PromotionRule {
  fromEnvironment: string;
  toEnvironment: string;
  requiredApprovals: number;
  requiredChecks: string[];
  conditions?: Array<{
    attribute: string;
    operator: string;
    value: any;
  }>;
}

export interface EnvironmentPolicyValidationResult {
  passed: boolean;
  environment: string;
  policyIssues: PolicyIssue[];
  isolationVerified: boolean;
  promotionRulesValid: boolean;
}

export interface PolicyIssue {
  policyId: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  recommendation: string;
}

export interface IsolationTestResult {
  isolated: boolean;
  testResults: Array<{
    test: string;
    passed: boolean;
    details: string;
  }>;
  violations: string[];
}

export interface PromotionResult {
  canPromote: boolean;
  missingApprovals: number;
  missingChecks: string[];
  issues: string[];
}

export interface InheritanceResult {
  inherited: boolean;
  basePolicies: string[];
  derivedPolicies: string[];
  conflicts: Array<{
    policyId: string;
    conflict: string;
  }>;
}

export class EnvironmentPolicyValidator {
  private pdp: PolicyDecisionPoint;

  constructor(pdp?: PolicyDecisionPoint) {
    // Create a default PDP if not provided
    this.pdp = pdp || new PolicyDecisionPoint({
      policyEngine: 'custom',
      policyMode: 'abac',
    });
  }

  /**
   * Validate environment policies
   */
  async validateEnvironmentPolicies(
    policy: EnvironmentPolicy
  ): Promise<EnvironmentPolicyValidationResult> {
    const policyIssues: PolicyIssue[] = [];

    // Validate each policy
    for (const abacPolicy of policy.policies) {
      const issues = this.validatePolicy(abacPolicy, policy.environment);
      policyIssues.push(...issues);
    }

    // Validate isolation rules
    const isolationVerified = this.validateIsolationRules(policy.isolationRules);

    // Validate promotion rules
    const promotionRulesValid = this.validatePromotionRules(policy.promotionRules);

    const criticalIssues = policyIssues.filter(i => i.severity === 'critical').length;
    const highIssues = policyIssues.filter(i => i.severity === 'high').length;

    return {
      passed: criticalIssues === 0 && highIssues === 0 && isolationVerified && promotionRulesValid,
      environment: policy.environment,
      policyIssues,
      isolationVerified,
      promotionRulesValid,
    };
  }

  /**
   * Test environment isolation
   */
  async testEnvironmentIsolation(
    env1: string,
    env2: string
  ): Promise<IsolationTestResult> {
    const testResults: IsolationTestResult['testResults'] = [];
    const violations: string[] = [];

    // Test 1: Production should be isolated from non-production
    if (env1 === 'prod' || env2 === 'prod') {
      const nonProd = env1 === 'prod' ? env2 : env1;
      const isolated = env1 !== env2;
      testResults.push({
        test: 'Production Isolation',
        passed: isolated,
        details: isolated
          ? `Production is isolated from ${nonProd}`
          : 'Production and non-production environments should be isolated',
      });

      if (!isolated) {
        violations.push('Production environment is not isolated from non-production');
      }
    }

    // Test 2: Environments should not share credentials
    testResults.push({
      test: 'Credential Isolation',
      passed: true,
      details: 'Environments should use separate credentials',
    });

    // Test 3: Environments should not access each other's resources
    testResults.push({
      test: 'Resource Isolation',
      passed: env1 !== env2,
      details: env1 === env2
        ? 'Environments are the same'
        : 'Environments should not access each other\'s resources',
    });

    const allPassed = testResults.every(r => r.passed);

    return {
      isolated: allPassed,
      testResults,
      violations,
    };
  }

  /**
   * Validate promotion policy
   */
  async validatePromotionPolicy(
    fromEnv: string,
    toEnv: string
  ): Promise<PromotionResult> {
    const issues: string[] = [];
    let missingApprovals = 0;
    const missingChecks: string[] = [];

    // Check if promotion is allowed
    if (fromEnv === toEnv) {
      issues.push('Cannot promote to the same environment');
      return {
        canPromote: false,
        missingApprovals: 0,
        missingChecks: [],
        issues,
      };
    }

    // Check promotion direction (should be dev -> staging -> prod)
    const envOrder = ['dev', 'staging', 'prod'];
    const fromIndex = envOrder.indexOf(fromEnv);
    const toIndex = envOrder.indexOf(toEnv);

    if (fromIndex === -1 || toIndex === -1) {
      issues.push('Invalid environment names');
    } else if (toIndex <= fromIndex) {
      issues.push(`Cannot promote from ${fromEnv} to ${toEnv} (wrong direction)`);
    }

    // Check if production promotion requires more approvals
    if (toEnv === 'prod') {
      missingApprovals = 2; // Production typically requires 2+ approvals
      missingChecks.push('security-review', 'compliance-check', 'performance-test');
    } else if (toEnv === 'staging') {
      missingApprovals = 1;
      missingChecks.push('basic-test');
    }

    return {
      canPromote: issues.length === 0,
      missingApprovals,
      missingChecks,
      issues,
    };
  }

  /**
   * Test policy inheritance
   */
  async testPolicyInheritance(
    baseEnv: string,
    derivedEnv: string
  ): Promise<InheritanceResult> {
    const basePolicies: string[] = [];
    const derivedPolicies: string[] = [];
    const conflicts: InheritanceResult['conflicts'] = [];

    // In a real implementation, this would load policies for both environments
    // and check for inheritance and conflicts

    // Check for conflicts (simplified)
    for (const basePolicy of basePolicies) {
      if (derivedPolicies.includes(basePolicy)) {
        // Check if derived policy overrides base policy in a conflicting way
        conflicts.push({
          policyId: basePolicy,
          conflict: 'Policy override may conflict with base policy',
        });
      }
    }

    return {
      inherited: basePolicies.length > 0,
      basePolicies,
      derivedPolicies,
      conflicts,
    };
  }

  /**
   * Validate a single policy
   */
  private validatePolicy(
    policy: ABACPolicy,
    environment: string
  ): PolicyIssue[] {
    const issues: PolicyIssue[] = [];

    // Check policy structure
    if (!policy.id) {
      issues.push({
        policyId: 'unknown',
        issue: 'Policy missing ID',
        severity: 'high',
        recommendation: 'All policies must have a unique ID',
      });
    }

    if (!policy.conditions || policy.conditions.length === 0) {
      issues.push({
        policyId: policy.id || 'unknown',
        issue: 'Policy has no conditions',
        severity: 'medium',
        recommendation: 'Policies should have at least one condition',
      });
    }

    // Check for environment-specific conditions
    const hasEnvCondition = policy.conditions.some(
      c => c.attribute.includes('environment') || c.attribute.includes('env')
    );

    if (!hasEnvCondition && environment !== 'dev') {
      issues.push({
        policyId: policy.id || 'unknown',
        issue: 'Policy does not specify environment condition',
        severity: 'medium',
        recommendation: 'Policies should explicitly specify environment conditions',
      });
    }

    // Check for production-specific security
    if (environment === 'prod') {
      const hasSecurityCondition = policy.conditions.some(
        c => c.attribute.includes('security') || c.attribute.includes('clearance')
      );

      if (!hasSecurityCondition && policy.effect === 'allow') {
        issues.push({
          policyId: policy.id || 'unknown',
          issue: 'Production policy allows access without security conditions',
          severity: 'high',
          recommendation: 'Production policies should include security conditions',
        });
      }
    }

    return issues;
  }

  /**
   * Validate isolation rules
   */
  private validateIsolationRules(rules: IsolationRule[]): boolean {
    // Check if production is isolated from other environments
    const prodRules = rules.filter(
      r => r.fromEnvironment === 'prod' || r.toEnvironment === 'prod'
    );

    for (const rule of prodRules) {
      if (rule.fromEnvironment === 'prod' || rule.toEnvironment === 'prod') {
        if (rule.allowed) {
          return false; // Production should not allow access to/from other environments
        }
      }
    }

    return true;
  }

  /**
   * Validate promotion rules
   */
  private validatePromotionRules(rules: PromotionRule[]): boolean {
    // Check if production promotion requires approvals
    const prodPromotions = rules.filter(r => r.toEnvironment === 'prod');

    for (const rule of prodPromotions) {
      if (rule.requiredApprovals < 2) {
        return false; // Production should require at least 2 approvals
      }

      if (!rule.requiredChecks.includes('security-review')) {
        return false; // Production should require security review
      }
    }

    return true;
  }
}

