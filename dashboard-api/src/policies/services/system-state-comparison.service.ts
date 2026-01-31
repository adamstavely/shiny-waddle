import { Injectable } from '@nestjs/common';
import { PoliciesService } from '../policies.service';
import { Policy } from '../entities/policy.entity';
import { RBACRule, ABACCondition } from '../dto/create-policy.dto';

export interface EnforcementGap {
  type: 'policy-not-enforced' | 'rule-missing' | 'condition-missing' | 'effect-mismatch';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  expected: any;
  actual: any;
  location?: string;
  remediation: RemediationStep[];
}

export interface RemediationStep {
  order: number;
  action: string;
  description: string;
  expectedOutcome: string;
  verification?: string;
}

export interface SystemStateComparison {
  policyId: string;
  policyName: string;
  expected: {
    rules: RBACRule[];
    conditions: ABACCondition[];
    effect: 'allow' | 'deny';
  };
  actual: {
    enforced: boolean;
    enforcementLocation?: string;
    rules?: RBACRule[];
    conditions?: ABACCondition[];
    effect?: 'allow' | 'deny';
  };
  gaps: EnforcementGap[];
  compliance: {
    isCompliant: boolean;
    compliancePercentage: number;
    missingRules: RBACRule[];
    missingConditions: ABACCondition[];
  };
}

export interface ComplianceAnalysis {
  applicationId?: string;
  totalPolicies: number;
  enforcedPolicies: number;
  compliancePercentage: number;
  gaps: EnforcementGap[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

@Injectable()
export class SystemStateComparisonService {
  constructor(
    private readonly policiesService: PoliciesService,
  ) {}

  /**
   * Compare expected policy vs actual enforcement
   */
  async compareExpectedVsActual(policyId: string): Promise<SystemStateComparison> {
    const policy = await this.policiesService.findOne(policyId);

    // Get actual enforcement state
    // In a real implementation, this would query:
    // - Test results to see if policy is tested/enforced
    // - Application configurations
    // - Identity provider configurations
    // For now, we'll simulate based on test results
    const actual = await this.getActualEnforcementState(policy);

    // Compare expected vs actual
    const gaps = this.detectGaps(policy, actual);

    // Calculate compliance
    const compliance = this.calculateCompliance(policy, actual, gaps);

    return {
      policyId: policy.id,
      policyName: policy.name,
      expected: {
        rules: policy.rules || [],
        conditions: policy.conditions || [],
        effect: policy.effect || 'allow',
      },
      actual,
      gaps,
      compliance,
    };
  }

  /**
   * Get actual enforcement state
   * This is a placeholder - in production, this would query actual systems
   */
  private async getActualEnforcementState(policy: Policy): Promise<SystemStateComparison['actual']> {
    // Placeholder: Check if policy has test results
    // In production, this would:
    // 1. Query test results for this policy
    // 2. Check application configurations
    // 3. Check identity provider settings
    // 4. Check network policies, etc.

    try {
      // For now, assume policy is enforced if it's active and has tests
      const tests = await this.policiesService.findTestsUsingPolicy(policy.id).catch(() => []);
      const isEnforced = policy.status === 'active' && tests.length > 0;

      return {
        enforced: isEnforced,
        enforcementLocation: isEnforced ? 'test-framework' : undefined,
        rules: isEnforced ? policy.rules : undefined,
        conditions: isEnforced ? policy.conditions : undefined,
        effect: isEnforced ? policy.effect : undefined,
      };
    } catch (error) {
      // If we can't determine, assume not enforced
      return {
        enforced: false,
      };
    }
  }

  /**
   * Detect gaps between expected and actual
   */
  private detectGaps(
    policy: Policy,
    actual: SystemStateComparison['actual'],
  ): EnforcementGap[] {
    const gaps: EnforcementGap[] = [];

    // Check if policy is enforced at all
    if (!actual.enforced) {
      gaps.push({
        type: 'policy-not-enforced',
        severity: 'critical',
        description: `Policy "${policy.name}" is not enforced in the system`,
        expected: {
          status: 'active',
          enforced: true,
        },
        actual: {
          enforced: false,
        },
        remediation: [
          {
            order: 1,
            action: 'Deploy policy',
            description: 'Deploy the policy to the enforcement system',
            expectedOutcome: 'Policy is active and enforced',
            verification: 'Check policy status is "active"',
          },
          {
            order: 2,
            action: 'Create tests',
            description: 'Create test cases to validate policy enforcement',
            expectedOutcome: 'Tests exist and pass',
            verification: 'Run tests and verify they pass',
          },
        ],
      });
      return gaps; // If not enforced, other checks don't apply
    }

    // Check rules (for RBAC)
    if (policy.type === 'rbac' && policy.rules) {
      const expectedRules = new Map(policy.rules.map(r => [r.id, r]));
      const actualRules = new Map((actual.rules || []).map(r => [r.id, r]));

      // Find missing rules
      for (const [id, expectedRule] of expectedRules) {
        if (!actualRules.has(id)) {
          gaps.push({
            type: 'rule-missing',
            severity: 'high',
            description: `Rule "${id}" is missing in actual enforcement`,
            expected: expectedRule,
            actual: null,
            location: actual.enforcementLocation,
            remediation: [
              {
                order: 1,
                action: 'Add rule to enforcement',
                description: `Add rule "${id}" to the enforcement configuration`,
                expectedOutcome: 'Rule is present in enforcement',
                verification: 'Verify rule exists in enforcement system',
              },
            ],
          });
        } else {
          // Check if rule matches
          const actualRule = actualRules.get(id)!;
          if (JSON.stringify(expectedRule) !== JSON.stringify(actualRule)) {
            gaps.push({
              type: 'rule-missing',
              severity: 'medium',
              description: `Rule "${id}" does not match expected configuration`,
              expected: expectedRule,
              actual: actualRule,
              location: actual.enforcementLocation,
              remediation: [
                {
                  order: 1,
                  action: 'Update rule configuration',
                  description: `Update rule "${id}" to match expected configuration`,
                  expectedOutcome: 'Rule matches expected configuration',
                  verification: 'Compare rule configurations',
                },
              ],
            });
          }
        }
      }
    }

    // Check conditions (for ABAC)
    if (policy.type === 'abac' && policy.conditions) {
      const expectedConditions = policy.conditions;
      const actualConditions = actual.conditions || [];

      if (expectedConditions.length > actualConditions.length) {
        gaps.push({
          type: 'condition-missing',
          severity: 'high',
          description: `${expectedConditions.length - actualConditions.length} condition(s) are missing`,
          expected: expectedConditions,
          actual: actualConditions,
          location: actual.enforcementLocation,
          remediation: [
            {
              order: 1,
              action: 'Add missing conditions',
              description: 'Add all missing conditions to enforcement',
              expectedOutcome: 'All conditions are present',
              verification: 'Verify all conditions exist',
            },
          ],
        });
      }
    }

    // Check effect
    if (policy.effect && actual.effect && policy.effect !== actual.effect) {
      gaps.push({
        type: 'effect-mismatch',
        severity: 'critical',
        description: `Policy effect mismatch: expected "${policy.effect}", actual "${actual.effect}"`,
        expected: policy.effect,
        actual: actual.effect,
        location: actual.enforcementLocation,
        remediation: [
          {
            order: 1,
            action: 'Update policy effect',
            description: `Change effect to "${policy.effect}"`,
            expectedOutcome: 'Effect matches expected value',
            verification: 'Verify effect is correct',
          },
        ],
      });
    }

    return gaps;
  }

  /**
   * Calculate compliance score
   */
  private calculateCompliance(
    policy: Policy,
    actual: SystemStateComparison['actual'],
    gaps: EnforcementGap[],
  ): SystemStateComparison['compliance'] {
    if (!actual.enforced) {
      return {
        isCompliant: false,
        compliancePercentage: 0,
        missingRules: policy.rules || [],
        missingConditions: policy.conditions || [],
      };
    }

    // Calculate based on gaps
    const totalChecks = this.getTotalChecks(policy);
    const passedChecks = totalChecks - gaps.length;
    const compliancePercentage = Math.round((passedChecks / totalChecks) * 100);

    const missingRules: RBACRule[] = [];
    const missingConditions: ABACCondition[] = [];

    gaps.forEach(gap => {
      if (gap.type === 'rule-missing' && gap.expected) {
        missingRules.push(gap.expected as RBACRule);
      }
      if (gap.type === 'condition-missing' && Array.isArray(gap.expected)) {
        missingConditions.push(...(gap.expected as ABACCondition[]));
      }
    });

    return {
      isCompliant: compliancePercentage === 100,
      compliancePercentage,
      missingRules,
      missingConditions,
    };
  }

  /**
   * Get total number of checks for compliance calculation
   */
  private getTotalChecks(policy: Policy): number {
    let checks = 1; // Base check: policy is enforced

    if (policy.type === 'rbac' && policy.rules) {
      checks += policy.rules.length; // One check per rule
    } else if (policy.type === 'abac' && policy.conditions) {
      checks += policy.conditions.length; // One check per condition
    }

    if (policy.effect) {
      checks += 1; // Effect check
    }

    return checks;
  }

  /**
   * Detect policies not enforced in system
   */
  async detectEnforcementGaps(policyIds?: string[]): Promise<EnforcementGap[]> {
    const allGaps: EnforcementGap[] = [];

    let policies: Policy[];
    if (policyIds && policyIds.length > 0) {
      const policyResults = await Promise.allSettled(
        policyIds.map(id => this.policiesService.findOne(id)),
      );
      policies = policyResults
        .filter((result): result is PromiseFulfilledResult<Policy> => 
          result.status === 'fulfilled'
        )
        .map(result => result.value);
    } else {
      policies = await this.policiesService.findAll();
    }

    for (const policy of policies) {
      if (policy.status === 'active') {
        try {
          const comparison = await this.compareExpectedVsActual(policy.id);
          allGaps.push(...comparison.gaps);
        } catch (error) {
          // Log error but continue processing other policies
          console.error(`Error comparing policy ${policy.id}:`, error);
        }
      }
    }

    return allGaps;
  }

  /**
   * Analyze compliance status
   */
  async analyzeCompliance(applicationId?: string): Promise<ComplianceAnalysis> {
    let policies: Policy[];
    if (applicationId) {
      policies = await this.policiesService.findAll(undefined, undefined, applicationId);
    } else {
      policies = await this.policiesService.findAll();
    }

    const activePolicies = policies.filter(p => p.status === 'active');
    const gaps: EnforcementGap[] = [];

    // Use Promise.allSettled to handle errors gracefully
    const comparisonResults = await Promise.allSettled(
      activePolicies.map(p => this.compareExpectedVsActual(p.id)),
    );

    const comparisons = comparisonResults
      .filter((result): result is PromiseFulfilledResult<SystemStateComparison> => 
        result.status === 'fulfilled'
      )
      .map(result => result.value);

    comparisons.forEach(comparison => {
      gaps.push(...comparison.gaps);
    });

    const enforcedCount = comparisons.filter(c => c.actual.enforced).length;

    const compliancePercentage = activePolicies.length > 0
      ? Math.round((enforcedCount / activePolicies.length) * 100)
      : 100;

    const summary = {
      critical: gaps.filter(g => g.severity === 'critical').length,
      high: gaps.filter(g => g.severity === 'high').length,
      medium: gaps.filter(g => g.severity === 'medium').length,
      low: gaps.filter(g => g.severity === 'low').length,
    };

    return {
      applicationId,
      totalPolicies: activePolicies.length,
      enforcedPolicies: enforcedCount,
      compliancePercentage,
      gaps,
      summary,
    };
  }
}
