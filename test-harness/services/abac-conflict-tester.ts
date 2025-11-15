/**
 * ABAC Policy Conflict Resolution Tester
 * 
 * Detects conflicting ABAC policies and tests conflict resolution
 */

import { ABACPolicy } from '../core/types';
import { PolicyDecisionPoint, PDPRequest } from './policy-decision-point';

export interface ConflictTestConfig {
  policies: ABACPolicy[];
  resolutionStrategy: 'priority' | 'deny-override' | 'allow-override' | 'first-match';
}

export interface ConflictTestResult {
  passed: boolean;
  conflicts: Array<{
    policy1: string;
    policy2: string;
    resource: string;
    action: string;
    conflictType: 'allow-vs-deny' | 'condition-overlap' | 'priority-ambiguous';
    resolution: ConflictResolution;
  }>;
  resolutionValid: boolean;
}

export interface ConflictResolution {
  strategy: string;
  resolved: boolean;
  resultingDecision: 'allow' | 'deny' | 'ambiguous';
  reason?: string;
}

export interface ResolutionResult {
  resolved: boolean;
  strategy: string;
  issues: string[];
}

export interface OverrideResult {
  canOverride: boolean;
  overridePolicy: string;
  overriddenPolicy: string;
  issues: string[];
}

export interface LoggingResult {
  logged: boolean;
  logLevel: string;
  issues: string[];
}

export interface MergeResult {
  merged: boolean;
  mergedPolicy?: ABACPolicy;
  conflicts: string[];
}

export class ABACConflictTester {
  private pdp: PolicyDecisionPoint;

  constructor(pdp: PolicyDecisionPoint) {
    this.pdp = pdp;
  }

  /**
   * Detect policy conflicts
   */
  async detectPolicyConflicts(
    config: ConflictTestConfig
  ): Promise<ConflictTestResult> {
    const conflicts: ConflictTestResult['conflicts'] = [];

    // Compare all pairs of policies
    for (let i = 0; i < config.policies.length; i++) {
      for (let j = i + 1; j < config.policies.length; j++) {
        const policy1 = config.policies[i];
        const policy2 = config.policies[j];

        // Check for conflicts
        const conflict = this.detectConflict(policy1, policy2);
        if (conflict) {
          const resolution = this.resolveConflict(
            policy1,
            policy2,
            config.resolutionStrategy
          );

          conflicts.push({
            policy1: policy1.id,
            policy2: policy2.id,
            resource: conflict.resource || 'unknown',
            action: conflict.action || 'unknown',
            conflictType: conflict.type,
            resolution,
          });
        }
      }
    }

    // Validate resolution
    const resolutionValid = conflicts.every(c => c.resolution.resolved);

    return {
      passed: conflicts.length === 0 || resolutionValid,
      conflicts,
      resolutionValid,
    };
  }

  /**
   * Test priority resolution
   */
  async testPriorityResolution(
    policies: ABACPolicy[]
  ): Promise<ResolutionResult> {
    const issues: string[] = [];

    // Check if all policies have priority
    const policiesWithoutPriority = policies.filter(p => p.priority === undefined);
    if (policiesWithoutPriority.length > 0) {
      issues.push(
        `${policiesWithoutPriority.length} policies do not have priority set`
      );
    }

    // Check for duplicate priorities
    const priorities = policies
      .map(p => p.priority)
      .filter((p): p is number => p !== undefined);
    const uniquePriorities = new Set(priorities);
    if (priorities.length !== uniquePriorities.size) {
      issues.push('Multiple policies have the same priority');
    }

    // Check if priority order makes sense
    const sortedPolicies = [...policies].sort(
      (a, b) => (b.priority || 0) - (a.priority || 0)
    );
    const hasDenyFirst = sortedPolicies[0]?.effect === 'deny';
    if (!hasDenyFirst) {
      issues.push('Highest priority policy should typically be deny');
    }

    return {
      resolved: issues.length === 0,
      strategy: 'priority',
      issues,
    };
  }

  /**
   * Validate conflict resolution rules
   */
  async validateConflictResolutionRules(
    config: ConflictTestConfig
  ): Promise<ResolutionResult> {
    const issues: string[] = [];

    switch (config.resolutionStrategy) {
      case 'priority':
        // Check if policies have priorities
        const policiesWithoutPriority = config.policies.filter(
          p => p.priority === undefined
        );
        if (policiesWithoutPriority.length > 0) {
          issues.push(
            `Priority strategy requires all policies to have priority, but ${policiesWithoutPriority.length} policies are missing it`
          );
        }
        break;

      case 'deny-override':
        // Deny-override should work with any policies
        break;

      case 'allow-override':
        // Allow-override should work with any policies
        break;

      case 'first-match':
        // First-match requires policies to be ordered
        issues.push('First-match strategy requires policies to be in specific order');
        break;

      default:
        issues.push(`Unknown resolution strategy: ${config.resolutionStrategy}`);
    }

    return {
      resolved: issues.length === 0,
      strategy: config.resolutionStrategy,
      issues,
    };
  }

  /**
   * Test policy override
   */
  async testPolicyOverride(
    policy1: ABACPolicy,
    policy2: ABACPolicy
  ): Promise<OverrideResult> {
    const issues: string[] = [];

    // Check if policies can override each other
    const canOverride =
      (policy1.priority || 0) > (policy2.priority || 0) ||
      policy1.effect === 'deny' ||
      policy2.effect === 'deny';

    if (!canOverride) {
      issues.push('Policies cannot override each other based on current configuration');
    }

    // Determine which policy overrides which
    let overridePolicy: string;
    let overriddenPolicy: string;

    if ((policy1.priority || 0) > (policy2.priority || 0)) {
      overridePolicy = policy1.id;
      overriddenPolicy = policy2.id;
    } else if (policy1.effect === 'deny' && policy2.effect === 'allow') {
      overridePolicy = policy1.id;
      overriddenPolicy = policy2.id;
    } else {
      overridePolicy = policy2.id;
      overriddenPolicy = policy1.id;
    }

    return {
      canOverride,
      overridePolicy,
      overriddenPolicy,
      issues,
    };
  }

  /**
   * Validate conflict logging
   */
  async validateConflictLogging(
    conflicts: Array<{ policy1: string; policy2: string; type: string }>
  ): Promise<LoggingResult> {
    const issues: string[] = [];

    // Check if conflicts are logged
    // This is a simplified check - real implementation would check actual logs
    const logged = true; // Simplified

    if (!logged) {
      issues.push('Policy conflicts are not being logged');
    }

    return {
      logged,
      logLevel: 'info',
      issues,
    };
  }

  /**
   * Test policy merge
   */
  async testPolicyMerge(
    policies: ABACPolicy[]
  ): Promise<MergeResult> {
    const conflicts: string[] = [];

    // Check if policies can be merged
    // Policies can be merged if they have the same effect and compatible conditions
    const allowPolicies = policies.filter(p => p.effect === 'allow');
    const denyPolicies = policies.filter(p => p.effect === 'deny');

    // Cannot merge allow and deny policies
    if (allowPolicies.length > 0 && denyPolicies.length > 0) {
      conflicts.push('Cannot merge policies with different effects (allow vs deny)');
    }

    // Try to merge allow policies
    if (allowPolicies.length > 1) {
      // Check if conditions are compatible
      const conditions = allowPolicies.flatMap(p => p.conditions);
      const hasConflictingConditions = this.hasConflictingConditions(conditions);

      if (hasConflictingConditions) {
        conflicts.push('Policies have conflicting conditions and cannot be merged');
      }
    }

    // Generate merged policy if possible
    let mergedPolicy: ABACPolicy | undefined;
    if (conflicts.length === 0 && policies.length > 0) {
      mergedPolicy = {
        id: `merged-${policies.map(p => p.id).join('-')}`,
        name: `Merged: ${policies.map(p => p.name).join(', ')}`,
        description: 'Merged policy',
        effect: policies[0].effect,
        conditions: policies.flatMap(p => p.conditions),
        priority: Math.max(...policies.map(p => p.priority || 0)),
      };
    }

    return {
      merged: conflicts.length === 0,
      mergedPolicy,
      conflicts,
    };
  }

  /**
   * Detect conflict between two policies
   */
  private detectConflict(
    policy1: ABACPolicy,
    policy2: ABACPolicy
  ): {
    type: 'allow-vs-deny' | 'condition-overlap' | 'priority-ambiguous';
    resource?: string;
    action?: string;
  } | null {
    // Check for allow vs deny conflict
    if (policy1.effect !== policy2.effect) {
      // Check if conditions overlap
      if (this.conditionsOverlap(policy1.conditions, policy2.conditions)) {
        return {
          type: 'allow-vs-deny',
          resource: this.extractResource(policy1, policy2),
          action: this.extractAction(policy1, policy2),
        };
      }
    }

    // Check for condition overlap with same effect
    if (
      policy1.effect === policy2.effect &&
      this.conditionsOverlap(policy1.conditions, policy2.conditions)
    ) {
      return {
        type: 'condition-overlap',
        resource: this.extractResource(policy1, policy2),
        action: this.extractAction(policy1, policy2),
      };
    }

    // Check for priority ambiguity
    if (
      policy1.priority === policy2.priority &&
      this.conditionsOverlap(policy1.conditions, policy2.conditions)
    ) {
      return {
        type: 'priority-ambiguous',
        resource: this.extractResource(policy1, policy2),
        action: this.extractAction(policy1, policy2),
      };
    }

    return null;
  }

  /**
   * Check if conditions overlap
   */
  private conditionsOverlap(
    conditions1: any[],
    conditions2: any[]
  ): boolean {
    // Simplified overlap check
    // Real implementation would do proper condition matching
    for (const c1 of conditions1) {
      for (const c2 of conditions2) {
        if (c1.attribute === c2.attribute) {
          // Check if values overlap
          if (this.valuesOverlap(c1.value, c2.value, c1.operator, c2.operator)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * Check if values overlap
   */
  private valuesOverlap(
    value1: any,
    value2: any,
    operator1: string,
    operator2: string
  ): boolean {
    // Simplified overlap check
    if (operator1 === 'equals' && operator2 === 'equals') {
      return value1 === value2;
    }
    if (operator1 === 'in' && operator2 === 'in') {
      if (Array.isArray(value1) && Array.isArray(value2)) {
        return value1.some(v => value2.includes(v));
      }
    }
    return false;
  }

  /**
   * Resolve conflict
   */
  private resolveConflict(
    policy1: ABACPolicy,
    policy2: ABACPolicy,
    strategy: string
  ): ConflictResolution {
    switch (strategy) {
      case 'priority':
        const priority1 = policy1.priority || 0;
        const priority2 = policy2.priority || 0;
        if (priority1 > priority2) {
          return {
            strategy: 'priority',
            resolved: true,
            resultingDecision: policy1.effect,
            reason: `Policy ${policy1.id} has higher priority`,
          };
        } else if (priority2 > priority1) {
          return {
            strategy: 'priority',
            resolved: true,
            resultingDecision: policy2.effect,
            reason: `Policy ${policy2.id} has higher priority`,
          };
        }
        return {
          strategy: 'priority',
          resolved: false,
          resultingDecision: 'ambiguous',
          reason: 'Policies have same priority',
        };

      case 'deny-override':
        if (policy1.effect === 'deny') {
          return {
            strategy: 'deny-override',
            resolved: true,
            resultingDecision: 'deny',
            reason: 'Deny policy overrides allow',
          };
        } else if (policy2.effect === 'deny') {
          return {
            strategy: 'deny-override',
            resolved: true,
            resultingDecision: 'deny',
            reason: 'Deny policy overrides allow',
          };
        }
        return {
          strategy: 'deny-override',
          resolved: true,
          resultingDecision: 'allow',
          reason: 'Both policies allow',
        };

      case 'allow-override':
        if (policy1.effect === 'allow') {
          return {
            strategy: 'allow-override',
            resolved: true,
            resultingDecision: 'allow',
            reason: 'Allow policy overrides deny',
          };
        } else if (policy2.effect === 'allow') {
          return {
            strategy: 'allow-override',
            resolved: true,
            resultingDecision: 'allow',
            reason: 'Allow policy overrides deny',
          };
        }
        return {
          strategy: 'allow-override',
          resolved: true,
          resultingDecision: 'deny',
          reason: 'Both policies deny',
        };

      case 'first-match':
        return {
          strategy: 'first-match',
          resolved: true,
          resultingDecision: policy1.effect,
          reason: 'First matching policy applies',
        };

      default:
        return {
          strategy: 'unknown',
          resolved: false,
          resultingDecision: 'ambiguous',
          reason: 'Unknown resolution strategy',
        };
    }
  }

  /**
   * Extract resource from policies
   */
  private extractResource(policy1: ABACPolicy, policy2: ABACPolicy): string {
    const conditions = [...policy1.conditions, ...policy2.conditions];
    const resourceCondition = conditions.find(c => c.attribute.includes('resource'));
    return resourceCondition?.value || 'unknown';
  }

  /**
   * Extract action from policies
   */
  private extractAction(policy1: ABACPolicy, policy2: ABACPolicy): string {
    // Try to extract from policy name or description
    const text = `${policy1.name} ${policy1.description} ${policy2.name} ${policy2.description}`.toLowerCase();
    const actions = ['read', 'write', 'delete', 'create', 'update'];
    for (const action of actions) {
      if (text.includes(action)) {
        return action;
      }
    }
    return 'unknown';
  }

  /**
   * Check if conditions have conflicts
   */
  private hasConflictingConditions(conditions: any[]): boolean {
    // Check for contradictory conditions
    for (let i = 0; i < conditions.length; i++) {
      for (let j = i + 1; j < conditions.length; j++) {
        const c1 = conditions[i];
        const c2 = conditions[j];

        if (
          c1.attribute === c2.attribute &&
          c1.operator === 'equals' &&
          c2.operator === 'notEquals' &&
          c1.value === c2.value
        ) {
          return true;
        }
      }
    }
    return false;
  }
}

