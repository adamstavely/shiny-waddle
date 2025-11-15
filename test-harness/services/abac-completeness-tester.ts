/**
 * ABAC Policy Completeness Tester
 * 
 * Tests policy coverage for resource types, user roles, actions, and edge cases
 */

import { ABACPolicy } from '../core/types';

export interface CompletenessTestConfig {
  resourceTypes: string[];
  userRoles: string[];
  actions: string[];
  policies: ABACPolicy[];
}

export interface CompletenessTestResult {
  passed: boolean;
  coverage: {
    resourceTypes: number; // percentage
    userRoles: number;
    actions: number;
    edgeCases: number;
  };
  gaps: Array<{
    resourceType: string;
    userRole: string;
    action: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
  missingPolicies: MissingPolicy[];
}

export interface MissingPolicy {
  resourceType: string;
  userRole: string;
  action: string;
  recommendedPolicy: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface CoverageResult {
  covered: number;
  total: number;
  percentage: number;
  missing: string[];
}

export interface EdgeCaseResult {
  covered: number;
  total: number;
  edgeCases: Array<{
    scenario: string;
    covered: boolean;
  }>;
}

export interface GapAnalysis {
  summary: {
    totalGaps: number;
    criticalGaps: number;
    highGaps: number;
  };
  gaps: CompletenessTestResult['gaps'];
  recommendations: string[];
}

export class ABACCompletenessTester {
  /**
   * Test policy completeness
   */
  async testPolicyCompleteness(
    config: CompletenessTestConfig
  ): Promise<CompletenessTestResult> {
    // Test resource type coverage
    const resourceCoverage = await this.testResourceTypeCoverage(
      config.resourceTypes,
      config.policies
    );

    // Test role coverage
    const roleCoverage = await this.testRoleCoverage(
      config.userRoles,
      config.policies
    );

    // Test action coverage
    const actionCoverage = await this.testActionCoverage(
      config.actions,
      config.policies
    );

    // Test edge case coverage
    const edgeCaseCoverage = await this.testEdgeCaseCoverage(config.policies);

    // Detect missing policies
    const missingPolicies = await this.detectMissingPolicies(config);

    // Calculate gaps
    const gaps = this.calculateGaps(config, missingPolicies);

    // Calculate overall coverage
    const coverage = {
      resourceTypes: resourceCoverage.percentage,
      userRoles: roleCoverage.percentage,
      actions: actionCoverage.percentage,
      edgeCases: edgeCaseCoverage.covered,
    };

    // Determine if passed (all coverage > 80%)
    const passed =
      coverage.resourceTypes >= 80 &&
      coverage.userRoles >= 80 &&
      coverage.actions >= 80;

    return {
      passed,
      coverage,
      gaps,
      missingPolicies,
    };
  }

  /**
   * Test resource type coverage
   */
  async testResourceTypeCoverage(
    resourceTypes: string[],
    policies: ABACPolicy[]
  ): Promise<CoverageResult> {
    const covered = new Set<string>();
    const missing: string[] = [];

    // Extract resource types from policies
    for (const policy of policies) {
      for (const condition of policy.conditions) {
        if (condition.attribute.includes('resource.type')) {
          // Extract resource type from condition value
          const resourceType = this.extractResourceType(condition);
          if (resourceType) {
            covered.add(resourceType);
          }
        }
      }
    }

    // Find missing resource types
    for (const resourceType of resourceTypes) {
      if (!covered.has(resourceType)) {
        missing.push(resourceType);
      }
    }

    const percentage = resourceTypes.length > 0
      ? (covered.size / resourceTypes.length) * 100
      : 100;

    return {
      covered: covered.size,
      total: resourceTypes.length,
      percentage,
      missing,
    };
  }

  /**
   * Test role coverage
   */
  async testRoleCoverage(
    roles: string[],
    policies: ABACPolicy[]
  ): Promise<CoverageResult> {
    const covered = new Set<string>();
    const missing: string[] = [];

    // Extract roles from policies
    for (const policy of policies) {
      for (const condition of policy.conditions) {
        if (condition.attribute.includes('subject.role') || condition.attribute.includes('user.role')) {
          const role = this.extractRole(condition);
          if (role) {
            covered.add(role);
          }
        }
      }
    }

    // Find missing roles
    for (const role of roles) {
      if (!covered.has(role)) {
        missing.push(role);
      }
    }

    const percentage = roles.length > 0
      ? (covered.size / roles.length) * 100
      : 100;

    return {
      covered: covered.size,
      total: roles.length,
      percentage,
      missing,
    };
  }

  /**
   * Test action coverage
   */
  private async testActionCoverage(
    actions: string[],
    policies: ABACPolicy[]
  ): Promise<CoverageResult> {
    // Actions are typically not in ABAC conditions but in policy effects
    // This is a simplified check
    const covered = new Set<string>();
    const missing: string[] = [];

    // Check policy names/descriptions for action references
    for (const policy of policies) {
      const policyText = `${policy.name} ${policy.description}`.toLowerCase();
      for (const action of actions) {
        if (policyText.includes(action.toLowerCase())) {
          covered.add(action);
        }
      }
    }

    // Find missing actions
    for (const action of actions) {
      if (!covered.has(action)) {
        missing.push(action);
      }
    }

    const percentage = actions.length > 0
      ? (covered.size / actions.length) * 100
      : 100;

    return {
      covered: covered.size,
      total: actions.length,
      percentage,
      missing,
    };
  }

  /**
   * Test edge case coverage
   */
  async testEdgeCaseCoverage(
    policies: ABACPolicy[]
  ): Promise<EdgeCaseResult> {
    const edgeCases: EdgeCaseResult['edgeCases'] = [
      {
        scenario: 'User with no attributes',
        covered: this.hasPolicyForNoAttributes(policies),
      },
      {
        scenario: 'Resource with no attributes',
        covered: this.hasPolicyForNoResourceAttributes(policies),
      },
      {
        scenario: 'Deny-all default',
        covered: this.hasDenyAllPolicy(policies),
      },
      {
        scenario: 'Admin override',
        covered: this.hasAdminOverridePolicy(policies),
      },
      {
        scenario: 'Emergency access',
        covered: this.hasEmergencyAccessPolicy(policies),
      },
    ];

    const covered = edgeCases.filter(ec => ec.covered).length;

    return {
      covered,
      total: edgeCases.length,
      edgeCases,
    };
  }

  /**
   * Detect missing policies
   */
  async detectMissingPolicies(
    config: CompletenessTestConfig
  ): Promise<MissingPolicy[]> {
    const missing: MissingPolicy[] = [];

    // Check all combinations of resource types, roles, and actions
    for (const resourceType of config.resourceTypes) {
      for (const role of config.userRoles) {
        for (const action of config.actions) {
          const hasPolicy = this.hasPolicyFor(config.policies, resourceType, role, action);
          if (!hasPolicy) {
            missing.push({
              resourceType,
              userRole: role,
              action,
              recommendedPolicy: this.generateRecommendedPolicy(resourceType, role, action),
              severity: this.determineSeverity(resourceType, role, action),
            });
          }
        }
      }
    }

    return missing;
  }

  /**
   * Generate gap analysis
   */
  async generateGapAnalysis(
    config: CompletenessTestConfig
  ): Promise<GapAnalysis> {
    const missingPolicies = await this.detectMissingPolicies(config);
    const gaps = this.calculateGaps(config, missingPolicies);

    const criticalGaps = gaps.filter(g => g.severity === 'critical').length;
    const highGaps = gaps.filter(g => g.severity === 'high').length;

    const recommendations: string[] = [];

    if (criticalGaps > 0) {
      recommendations.push(`Address ${criticalGaps} critical policy gaps immediately`);
    }

    if (highGaps > 0) {
      recommendations.push(`Review ${highGaps} high-severity policy gaps`);
    }

    if (missingPolicies.length > 0) {
      recommendations.push(`Create ${missingPolicies.length} missing policies`);
    }

    return {
      summary: {
        totalGaps: gaps.length,
        criticalGaps,
        highGaps,
      },
      gaps,
      recommendations,
    };
  }

  /**
   * Extract resource type from condition
   */
  private extractResourceType(condition: any): string | null {
    if (condition.value && typeof condition.value === 'string') {
      return condition.value;
    }
    if (condition.value && Array.isArray(condition.value)) {
      return condition.value[0];
    }
    return null;
  }

  /**
   * Extract role from condition
   */
  private extractRole(condition: any): string | null {
    if (condition.value && typeof condition.value === 'string') {
      return condition.value;
    }
    if (condition.value && Array.isArray(condition.value)) {
      return condition.value[0];
    }
    return null;
  }

  /**
   * Check if policy exists for resource type, role, and action
   */
  private hasPolicyFor(
    policies: ABACPolicy[],
    resourceType: string,
    role: string,
    action: string
  ): boolean {
    for (const policy of policies) {
      const hasResourceType = policy.conditions.some(
        c => c.attribute.includes('resource') && this.matchesValue(c, resourceType)
      );
      const hasRole = policy.conditions.some(
        c => c.attribute.includes('subject') && this.matchesValue(c, role)
      );
      const hasAction = policy.name.toLowerCase().includes(action.toLowerCase()) ||
        policy.description.toLowerCase().includes(action.toLowerCase());

      if (hasResourceType && hasRole && hasAction) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if condition matches value
   */
  private matchesValue(condition: any, value: string): boolean {
    if (condition.operator === 'equals' && condition.value === value) {
      return true;
    }
    if (condition.operator === 'in' && Array.isArray(condition.value)) {
      return condition.value.includes(value);
    }
    return false;
  }

  /**
   * Generate recommended policy
   */
  private generateRecommendedPolicy(
    resourceType: string,
    role: string,
    action: string
  ): string {
    return `Policy for ${role} to ${action} on ${resourceType}`;
  }

  /**
   * Determine severity for missing policy
   */
  private determineSeverity(
    resourceType: string,
    role: string,
    action: string
  ): 'critical' | 'high' | 'medium' | 'low' {
    // Critical: admin actions on sensitive resources
    if (role === 'admin' && ['delete', 'modify'].includes(action)) {
      return 'critical';
    }

    // High: write actions on any resource
    if (['write', 'update', 'create'].includes(action)) {
      return 'high';
    }

    // Medium: read actions on sensitive resources
    if (action === 'read' && resourceType.includes('sensitive')) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Calculate gaps
   */
  private calculateGaps(
    config: CompletenessTestConfig,
    missingPolicies: MissingPolicy[]
  ): CompletenessTestResult['gaps'] {
    return missingPolicies.map(mp => ({
      resourceType: mp.resourceType,
      userRole: mp.userRole,
      action: mp.action,
      severity: mp.severity,
    }));
  }

  /**
   * Check if policy exists for no attributes
   */
  private hasPolicyForNoAttributes(policies: ABACPolicy[]): boolean {
    return policies.some(p => p.effect === 'deny' && p.conditions.length === 0);
  }

  /**
   * Check if policy exists for no resource attributes
   */
  private hasPolicyForNoResourceAttributes(policies: ABACPolicy[]): boolean {
    return policies.some(p =>
      p.conditions.every(c => !c.attribute.includes('resource'))
    );
  }

  /**
   * Check if deny-all policy exists
   */
  private hasDenyAllPolicy(policies: ABACPolicy[]): boolean {
    return policies.some(p => p.effect === 'deny' && p.priority === 0);
  }

  /**
   * Check if admin override policy exists
   */
  private hasAdminOverridePolicy(policies: ABACPolicy[]): boolean {
    return policies.some(p =>
      p.effect === 'allow' &&
      p.conditions.some(c =>
        c.attribute.includes('role') && c.value === 'admin'
      ) &&
      (p.priority || 0) > 100
    );
  }

  /**
   * Check if emergency access policy exists
   */
  private hasEmergencyAccessPolicy(policies: ABACPolicy[]): boolean {
    return policies.some(p =>
      p.name.toLowerCase().includes('emergency') ||
      p.description.toLowerCase().includes('emergency')
    );
  }
}

