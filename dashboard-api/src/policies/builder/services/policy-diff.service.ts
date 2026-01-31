import { Injectable, NotFoundException } from '@nestjs/common';
import { Policy } from '../../entities/policy.entity';
import { PolicyVersioningService } from '../../services/policy-versioning.service';
import { PoliciesService } from '../../policies.service';

export interface PolicyDiff {
  version1: string;
  version2: string;
  changes: PolicyChange[];
  summary: {
    added: number;
    modified: number;
    deleted: number;
  };
}

export interface PolicyChange {
  type: 'added' | 'modified' | 'deleted';
  path: string; // JSON path (e.g., "rules[0].conditions.role")
  oldValue?: any;
  newValue?: any;
  description: string;
}

@Injectable()
export class PolicyDiffService {
  constructor(
    private readonly versioningService: PolicyVersioningService,
    private readonly policiesService: PoliciesService,
  ) {}

  /**
   * Compare two policy versions
   */
  async compareVersions(
    policyId: string,
    version1: string,
    version2: string
  ): Promise<PolicyDiff> {
    // Get the policy first
    const policy = this.policiesService.findOne(policyId);
    if (!policy) {
      throw new NotFoundException(`Policy with ID "${policyId}" not found`);
    }
    // Get versions from versioning service
    const comparison = this.versioningService.compareVersions(
      policy,
      version1,
      version2
    );

    // Convert to our PolicyDiff format
    const changes: PolicyChange[] = comparison.differences.map(diff => ({
      type: diff.changeType === 'added' ? 'added' : diff.changeType === 'removed' ? 'deleted' : 'modified',
      path: diff.field,
      oldValue: diff.oldValue,
      newValue: diff.newValue,
      description: this.generateChangeDescription({
        type: diff.changeType === 'added' ? 'added' : diff.changeType === 'removed' ? 'deleted' : 'modified',
        path: diff.field,
        oldValue: diff.oldValue,
        newValue: diff.newValue,
        description: '',
      }),
    }));

    return {
      version1,
      version2,
      changes,
      summary: {
        added: changes.filter(c => c.type === 'added').length,
        modified: changes.filter(c => c.type === 'modified').length,
        deleted: changes.filter(c => c.type === 'deleted').length,
      },
    };
  }

  /**
   * Compare two policy objects directly
   */
  comparePolicies(policy1: Policy, policy2: Policy): PolicyDiff {
    const changes: PolicyChange[] = [];

    // Compare basic fields
    this.compareField('name', policy1.name, policy2.name, changes);
    this.compareField('description', policy1.description, policy2.description, changes);
    this.compareField('version', policy1.version, policy2.version, changes);
    this.compareField('status', policy1.status, policy2.status, changes);
    this.compareField('effect', policy1.effect, policy2.effect, changes);
    this.compareField('priority', policy1.priority, policy2.priority, changes);
    this.compareField('applicationId', policy1.applicationId, policy2.applicationId, changes);

    // Compare RBAC rules
    if (policy1.type === 'rbac' && policy2.type === 'rbac') {
      this.compareRules(policy1.rules || [], policy2.rules || [], changes);
    }

    // Compare ABAC conditions
    if (policy1.type === 'abac' && policy2.type === 'abac') {
      this.compareConditions(policy1.conditions || [], policy2.conditions || [], changes);
    }

    // Type change
    if (policy1.type !== policy2.type) {
      changes.push({
        type: 'modified',
        path: 'type',
        oldValue: policy1.type,
        newValue: policy2.type,
        description: `Policy type changed from ${policy1.type} to ${policy2.type}`,
      });
    }

    return {
      version1: policy1.version,
      version2: policy2.version,
      changes,
      summary: {
        added: changes.filter(c => c.type === 'added').length,
        modified: changes.filter(c => c.type === 'modified').length,
        deleted: changes.filter(c => c.type === 'deleted').length,
      },
    };
  }

  /**
   * Generate human-readable change description
   */
  generateChangeDescription(change: PolicyChange): string {
    switch (change.type) {
      case 'added':
        return `Added ${change.path}: ${this.formatValue(change.newValue)}`;
      case 'deleted':
        return `Removed ${change.path}: ${this.formatValue(change.oldValue)}`;
      case 'modified':
        return `Changed ${change.path} from ${this.formatValue(change.oldValue)} to ${this.formatValue(change.newValue)}`;
      default:
        return `Modified ${change.path}`;
    }
  }

  // Private helper methods

  private compareField(
    field: string,
    oldValue: any,
    newValue: any,
    changes: PolicyChange[]
  ): void {
    if (oldValue !== newValue) {
      if (oldValue === undefined || oldValue === null) {
        changes.push({
          type: 'added',
          path: field,
          newValue,
          description: `Added ${field}: ${this.formatValue(newValue)}`,
        });
      } else if (newValue === undefined || newValue === null) {
        changes.push({
          type: 'deleted',
          path: field,
          oldValue,
          description: `Removed ${field}: ${this.formatValue(oldValue)}`,
        });
      } else {
        changes.push({
          type: 'modified',
          path: field,
          oldValue,
          newValue,
          description: `Changed ${field} from ${this.formatValue(oldValue)} to ${this.formatValue(newValue)}`,
        });
      }
    }
  }

  private compareRules(
    oldRules: any[],
    newRules: any[],
    changes: PolicyChange[]
  ): void {
    const oldMap = new Map(oldRules.map((r, i) => [r.id || `rule-${i}`, { rule: r, index: i }]));
    const newMap = new Map(newRules.map((r, i) => [r.id || `rule-${i}`, { rule: r, index: i }]));

    // Find added rules
    for (const [id, { rule, index }] of newMap) {
      if (!oldMap.has(id)) {
        changes.push({
          type: 'added',
          path: `rules[${index}]`,
          newValue: rule,
          description: `Added rule: ${rule.description || rule.id || `rule-${index}`}`,
        });
      } else {
        // Compare rule details
        const oldRule = oldMap.get(id)!.rule;
        this.compareRuleDetails(oldRule, rule, index, changes);
      }
    }

    // Find deleted rules
    for (const [id, { index }] of oldMap) {
      if (!newMap.has(id)) {
        changes.push({
          type: 'deleted',
          path: `rules[${index}]`,
          oldValue: oldMap.get(id)!.rule,
          description: `Removed rule: ${oldMap.get(id)!.rule.description || id}`,
        });
      }
    }
  }

  private compareRuleDetails(
    oldRule: any,
    newRule: any,
    index: number,
    changes: PolicyChange[]
  ): void {
    if (oldRule.effect !== newRule.effect) {
      changes.push({
        type: 'modified',
        path: `rules[${index}].effect`,
        oldValue: oldRule.effect,
        newValue: newRule.effect,
        description: `Changed rule effect from ${oldRule.effect} to ${newRule.effect}`,
      });
    }

    if (JSON.stringify(oldRule.conditions) !== JSON.stringify(newRule.conditions)) {
      changes.push({
        type: 'modified',
        path: `rules[${index}].conditions`,
        oldValue: oldRule.conditions,
        newValue: newRule.conditions,
        description: `Modified rule conditions`,
      });
    }
  }

  private compareConditions(
    oldConditions: any[],
    newConditions: any[],
    changes: PolicyChange[]
  ): void {
    // Simple comparison by index (conditions don't have IDs)
    const maxLength = Math.max(oldConditions.length, newConditions.length);

    for (let i = 0; i < maxLength; i++) {
      const oldCond = oldConditions[i];
      const newCond = newConditions[i];

      if (!oldCond && newCond) {
        changes.push({
          type: 'added',
          path: `conditions[${i}]`,
          newValue: newCond,
          description: `Added condition: ${newCond.attribute} ${newCond.operator} ${this.formatValue(newCond.value)}`,
        });
      } else if (oldCond && !newCond) {
        changes.push({
          type: 'deleted',
          path: `conditions[${i}]`,
          oldValue: oldCond,
          description: `Removed condition: ${oldCond.attribute} ${oldCond.operator} ${this.formatValue(oldCond.value)}`,
        });
      } else if (oldCond && newCond) {
        if (JSON.stringify(oldCond) !== JSON.stringify(newCond)) {
          changes.push({
            type: 'modified',
            path: `conditions[${i}]`,
            oldValue: oldCond,
            newValue: newCond,
            description: `Modified condition: ${oldCond.attribute} ${oldCond.operator} ${this.formatValue(oldCond.value)} → ${newCond.attribute} ${newCond.operator} ${this.formatValue(newCond.value)}`,
          });
        }
      }
    }
  }

  private formatValue(value: any): string {
    if (value === undefined || value === null) {
      return 'undefined';
    }
    if (typeof value === 'object') {
      return JSON.stringify(value);
    }
    return String(value);
  }
}
