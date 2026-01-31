import { Injectable } from '@nestjs/common';
import { Policy, PolicyVersion } from '../entities/policy.entity';
import { RBACRule, ABACCondition } from '../dto/create-policy.dto';

export interface RuleChange {
  field: string;
  oldValue: any;
  newValue: any;
  changeType: 'added' | 'removed' | 'modified';
}

export interface ConditionChange {
  field: string;
  oldValue: any;
  newValue: any;
  changeType: 'added' | 'removed' | 'modified';
}

export interface PolicyStructureDiff {
  rules: {
    added: RBACRule[];
    removed: RBACRule[];
    modified: Array<{
      ruleId: string;
      changes: RuleChange[];
    }>;
  };
  conditions: {
    added: ABACCondition[];
    removed: ABACCondition[];
    modified: Array<{
      conditionIndex: number;
      changes: ConditionChange[];
    }>;
  };
  metadata: {
    changed: Array<{
      field: string;
      oldValue: any;
      newValue: any;
    }>;
  };
}

export interface VisualDiffMarker {
  type: 'added' | 'removed' | 'modified';
  path: string; // JSON path to changed element
  lineNumber?: number;
  oldValue?: any;
  newValue?: any;
  context?: string;
}

export interface EnhancedVersionComparison {
  version1: string;
  version2: string;
  differences: Array<{
    field: string;
    oldValue: any;
    newValue: any;
    changeType: 'added' | 'removed' | 'modified';
  }>;
  summary: {
    totalChanges: number;
    addedFields: number;
    removedFields: number;
    modifiedFields: number;
  };
  structureDiff: PolicyStructureDiff;
  visualDiff: VisualDiffMarker[];
}

export interface DiffReport {
  comparison: EnhancedVersionComparison;
  formatted: {
    jsonDiff: string;
    summary: string;
  };
}

@Injectable()
export class PolicyDiffService {
  /**
   * Deep comparison of policy structure (rules, conditions, effects)
   */
  comparePolicyStructure(policy1: Policy, policy2: Policy): PolicyStructureDiff {
    const structureDiff: PolicyStructureDiff = {
      rules: {
        added: [],
        removed: [],
        modified: [],
      },
      conditions: {
        added: [],
        removed: [],
        modified: [],
      },
      metadata: {
        changed: [],
      },
    };

    // Compare metadata
    if (policy1.name !== policy2.name) {
      structureDiff.metadata.changed.push({
        field: 'name',
        oldValue: policy1.name,
        newValue: policy2.name,
      });
    }
    if (policy1.description !== policy2.description) {
      structureDiff.metadata.changed.push({
        field: 'description',
        oldValue: policy1.description,
        newValue: policy2.description,
      });
    }
    if (policy1.status !== policy2.status) {
      structureDiff.metadata.changed.push({
        field: 'status',
        oldValue: policy1.status,
        newValue: policy2.status,
      });
    }
    if (policy1.effect !== policy2.effect) {
      structureDiff.metadata.changed.push({
        field: 'effect',
        oldValue: policy1.effect,
        newValue: policy2.effect,
      });
    }
    if (policy1.priority !== policy2.priority) {
      structureDiff.metadata.changed.push({
        field: 'priority',
        oldValue: policy1.priority,
        newValue: policy2.priority,
      });
    }

    // Compare RBAC rules
    if (policy1.type === 'rbac' && policy2.type === 'rbac') {
      const rules1 = policy1.rules || [];
      const rules2 = policy2.rules || [];
      const rules1Map = new Map(rules1.map(r => [r.id, r]));
      const rules2Map = new Map(rules2.map(r => [r.id, r]));

      // Find added and modified rules
      for (const [id, rule2] of rules2Map) {
        const rule1 = rules1Map.get(id);
        if (!rule1) {
          structureDiff.rules.added.push(rule2);
        } else {
          const changes = this.compareRules(rule1, rule2);
          if (changes.length > 0) {
            structureDiff.rules.modified.push({
              ruleId: id,
              changes,
            });
          }
        }
      }

      // Find removed rules
      for (const [id, rule1] of rules1Map) {
        if (!rules2Map.has(id)) {
          structureDiff.rules.removed.push(rule1);
        }
      }
    }

    // Compare ABAC conditions
    if (policy1.type === 'abac' && policy2.type === 'abac') {
      const conditions1 = policy1.conditions || [];
      const conditions2 = policy2.conditions || [];

      // Compare by index and attribute
      const maxLength = Math.max(conditions1.length, conditions2.length);
      for (let i = 0; i < maxLength; i++) {
        const cond1 = conditions1[i];
        const cond2 = conditions2[i];

        if (!cond1 && cond2) {
          structureDiff.conditions.added.push(cond2);
        } else if (cond1 && !cond2) {
          structureDiff.conditions.removed.push(cond1);
        } else if (cond1 && cond2) {
          const changes = this.compareConditions(cond1, cond2);
          if (changes.length > 0) {
            structureDiff.conditions.modified.push({
              conditionIndex: i,
              changes,
            });
          }
        }
      }
    }

    return structureDiff;
  }

  /**
   * Compare two RBAC rules
   */
  private compareRules(rule1: RBACRule, rule2: RBACRule): RuleChange[] {
    const changes: RuleChange[] = [];

    if (rule1.description !== rule2.description) {
      changes.push({
        field: 'description',
        oldValue: rule1.description,
        newValue: rule2.description,
        changeType: 'modified',
      });
    }

    if (rule1.effect !== rule2.effect) {
      changes.push({
        field: 'effect',
        oldValue: rule1.effect,
        newValue: rule2.effect,
        changeType: 'modified',
      });
    }

    // Compare conditions
    const condChanges = this.compareConditionMaps(rule1.conditions, rule2.conditions);
    condChanges.forEach(change => {
      changes.push({
        field: `conditions.${change.field}`,
        oldValue: change.oldValue,
        newValue: change.newValue,
        changeType: change.changeType,
      });
    });

    return changes;
  }

  /**
   * Compare two ABAC conditions
   */
  private compareConditions(cond1: ABACCondition, cond2: ABACCondition): ConditionChange[] {
    const changes: ConditionChange[] = [];

    if (cond1.attribute !== cond2.attribute) {
      changes.push({
        field: 'attribute',
        oldValue: cond1.attribute,
        newValue: cond2.attribute,
        changeType: 'modified',
      });
    }

    if (cond1.operator !== cond2.operator) {
      changes.push({
        field: 'operator',
        oldValue: cond1.operator,
        newValue: cond2.operator,
        changeType: 'modified',
      });
    }

    if (cond1.value !== cond2.value) {
      changes.push({
        field: 'value',
        oldValue: cond1.value,
        newValue: cond2.value,
        changeType: 'modified',
      });
    }

    if (cond1.logicalOperator !== cond2.logicalOperator) {
      changes.push({
        field: 'logicalOperator',
        oldValue: cond1.logicalOperator,
        newValue: cond2.logicalOperator,
        changeType: 'modified',
      });
    }

    return changes;
  }

  /**
   * Compare condition maps (for RBAC rule conditions)
   */
  private compareConditionMaps(
    conditions1: Record<string, any>,
    conditions2: Record<string, any>,
  ): Array<{ field: string; oldValue: any; newValue: any; changeType: 'added' | 'removed' | 'modified' }> {
    const changes: Array<{ field: string; oldValue: any; newValue: any; changeType: 'added' | 'removed' | 'modified' }> = [];
    const keys1 = new Set(Object.keys(conditions1 || {}));
    const keys2 = new Set(Object.keys(conditions2 || {}));

    // Find added and modified
    for (const key of keys2) {
      const val1 = conditions1?.[key];
      const val2 = conditions2[key];
      if (!keys1.has(key)) {
        changes.push({
          field: key,
          oldValue: undefined,
          newValue: val2,
          changeType: 'added',
        });
      } else if (JSON.stringify(val1) !== JSON.stringify(val2)) {
        changes.push({
          field: key,
          oldValue: val1,
          newValue: val2,
          changeType: 'modified',
        });
      }
    }

    // Find removed
    for (const key of keys1) {
      if (!keys2.has(key)) {
        changes.push({
          field: key,
          oldValue: conditions1[key],
          newValue: undefined,
          changeType: 'removed',
        });
      }
    }

    return changes;
  }

  /**
   * Enhanced version comparison with structure diff
   */
  compareVersions(
    policy: Policy,
    version1: string,
    version2: string,
  ): EnhancedVersionComparison {
    // Get policy snapshots for each version
    // For now, we'll reconstruct from version history or use current state
    // In a full implementation, we'd store snapshots
    const v1 = this.getVersionSnapshot(policy, version1);
    const v2 = this.getVersionSnapshot(policy, version2);

    if (!v1 || !v2) {
      throw new Error(`One or both versions not found: ${version1}, ${version2}`);
    }

    // Compare structure
    const structureDiff = this.comparePolicyStructure(v1, v2);

    // Generate basic differences (for backward compatibility)
    const differences: Array<{
      field: string;
      oldValue: any;
      newValue: any;
      changeType: 'added' | 'removed' | 'modified';
    }> = [];

    // Add metadata changes
    structureDiff.metadata.changed.forEach(change => {
      differences.push({
        field: change.field,
        oldValue: change.oldValue,
        newValue: change.newValue,
        changeType: 'modified',
      });
    });

    // Add rule changes
    structureDiff.rules.added.forEach(rule => {
      differences.push({
        field: `rules.${rule.id}`,
        oldValue: null,
        newValue: rule,
        changeType: 'added',
      });
    });
    structureDiff.rules.removed.forEach(rule => {
      differences.push({
        field: `rules.${rule.id}`,
        oldValue: rule,
        newValue: null,
        changeType: 'removed',
      });
    });
    structureDiff.rules.modified.forEach(mod => {
      mod.changes.forEach(change => {
        differences.push({
          field: `rules.${mod.ruleId}.${change.field}`,
          oldValue: change.oldValue,
          newValue: change.newValue,
          changeType: 'modified',
        });
      });
    });

    // Add condition changes
    structureDiff.conditions.added.forEach((cond, index) => {
      differences.push({
        field: `conditions[${index}]`,
        oldValue: null,
        newValue: cond,
        changeType: 'added',
      });
    });
    structureDiff.conditions.removed.forEach((cond, index) => {
      differences.push({
        field: `conditions[${index}]`,
        oldValue: cond,
        newValue: null,
        changeType: 'removed',
      });
    });
    structureDiff.conditions.modified.forEach(mod => {
      mod.changes.forEach(change => {
        differences.push({
          field: `conditions[${mod.conditionIndex}].${change.field}`,
          oldValue: change.oldValue,
          newValue: change.newValue,
          changeType: 'modified',
        });
      });
    });

    // Generate visual diff markers
    const visualDiff = this.generateVisualDiffMarkers(structureDiff, v1, v2);

    const summary = {
      totalChanges: differences.length,
      addedFields: differences.filter(d => d.changeType === 'added').length,
      removedFields: differences.filter(d => d.changeType === 'removed').length,
      modifiedFields: differences.filter(d => d.changeType === 'modified').length,
    };

    return {
      version1,
      version2,
      differences,
      summary,
      structureDiff,
      visualDiff,
    };
  }

  /**
   * Get policy snapshot for a version
   * In a full implementation, this would load from stored snapshots
   * For now, we reconstruct from current policy state
   */
  private getVersionSnapshot(policy: Policy, version: string): Policy | null {
    const versionObj = policy.versions.find(v => v.version === version);
    if (!versionObj) {
      return null;
    }

    // Return current policy as snapshot (simplified)
    // In production, store full snapshots when versions are created
    return {
      ...policy,
      version: versionObj.version,
      status: versionObj.status,
    };
  }

  /**
   * Generate visual diff markers for UI highlighting
   */
  private generateVisualDiffMarkers(
    structureDiff: PolicyStructureDiff,
    policy1: Policy,
    policy2: Policy,
  ): VisualDiffMarker[] {
    const markers: VisualDiffMarker[] = [];

    // Metadata markers
    structureDiff.metadata.changed.forEach(change => {
      markers.push({
        type: 'modified',
        path: change.field,
        oldValue: change.oldValue,
        newValue: change.newValue,
      });
    });

    // Rule markers
    structureDiff.rules.added.forEach(rule => {
      markers.push({
        type: 'added',
        path: `rules.${rule.id}`,
        newValue: rule,
      });
    });
    structureDiff.rules.removed.forEach(rule => {
      markers.push({
        type: 'removed',
        path: `rules.${rule.id}`,
        oldValue: rule,
      });
    });
    structureDiff.rules.modified.forEach(mod => {
      mod.changes.forEach(change => {
        markers.push({
          type: 'modified',
          path: `rules.${mod.ruleId}.${change.field}`,
          oldValue: change.oldValue,
          newValue: change.newValue,
        });
      });
    });

    // Condition markers
    structureDiff.conditions.added.forEach((cond, index) => {
      markers.push({
        type: 'added',
        path: `conditions[${index}]`,
        newValue: cond,
      });
    });
    structureDiff.conditions.removed.forEach((cond, index) => {
      markers.push({
        type: 'removed',
        path: `conditions[${index}]`,
        oldValue: cond,
      });
    });
    structureDiff.conditions.modified.forEach(mod => {
      mod.changes.forEach(change => {
        markers.push({
          type: 'modified',
          path: `conditions[${mod.conditionIndex}].${change.field}`,
          oldValue: change.oldValue,
          newValue: change.newValue,
        });
      });
    });

    return markers;
  }

  /**
   * Generate diff report with visual markers
   */
  generateDiffReport(comparison: EnhancedVersionComparison): DiffReport {
    const jsonDiff = JSON.stringify(comparison.structureDiff, null, 2);
    
    const summary = `
      Version Comparison: ${comparison.version1} → ${comparison.version2}
      Total Changes: ${comparison.summary.totalChanges}
      Added: ${comparison.summary.addedFields}
      Removed: ${comparison.summary.removedFields}
      Modified: ${comparison.summary.modifiedFields}
    `.trim();

    return {
      comparison,
      formatted: {
        jsonDiff,
        summary,
      },
    };
  }

  /**
   * Compare any two policies
   */
  comparePolicies(policy1: Policy, policy2: Policy): PolicyStructureDiff {
    return this.comparePolicyStructure(policy1, policy2);
  }
}
