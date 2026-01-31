import { Injectable } from '@nestjs/common';
import { PoliciesService } from '../policies.service';
import { Policy } from '../entities/policy.entity';

export interface TagComparison {
  resourceId: string;
  resourceName: string;
  expectedTags: Record<string, string>;
  actualTags: Record<string, string>;
  missingTags: string[];
  incorrectTags: Array<{
    key: string;
    expected: string;
    actual: string;
  }>;
  extraTags: string[];
  compliance: {
    isCompliant: boolean;
    missingCount: number;
    incorrectCount: number;
  };
}

export interface TagUpdateGuidance {
  resourceId: string;
  actions: Array<{
    type: 'add' | 'update' | 'remove';
    tag: string;
    value: string;
    reason: string;
    steps: string[];
  }>;
  estimatedTime: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

@Injectable()
export class DataTagComparisonService {
  constructor(
    private readonly policiesService: PoliciesService,
  ) {}

  /**
   * Compare expected tags vs actual tags for a resource
   */
  async compareTags(
    resourceId: string,
    policyId?: string,
  ): Promise<TagComparison> {
    // Get expected tags from policies
    const expectedTags = await this.getExpectedTags(resourceId, policyId);

    // Get actual tags from resource
    // In a real implementation, this would query the resource management service
    const actualTags = await this.getActualTags(resourceId);

    // Compare tags
    const missingTags = this.identifyMissingTags(expectedTags, actualTags);
    const incorrectTags = this.identifyIncorrectTags(expectedTags, actualTags);
    const extraTags = this.identifyExtraTags(expectedTags, actualTags);

    const compliance = {
      isCompliant: missingTags.length === 0 && incorrectTags.length === 0,
      missingCount: missingTags.length,
      incorrectCount: incorrectTags.length,
    };

    return {
      resourceId,
      resourceName: resourceId, // In production, get from resource service
      expectedTags,
      actualTags,
      missingTags,
      incorrectTags,
      extraTags,
      compliance,
    };
  }

  /**
   * Get expected tags from policies that reference this resource
   */
  private async getExpectedTags(
    resourceId: string,
    policyId?: string,
  ): Promise<Record<string, string>> {
    const expectedTags: Record<string, string> = {};

    let policies: Policy[];
    if (policyId) {
      const policy = await this.policiesService.findOne(policyId);
      policies = [policy];
    } else {
      policies = await this.policiesService.findAll();
    }

    // Extract tags from policies that reference this resource
    for (const policy of policies) {
      if (policy.type === 'abac' && policy.conditions) {
        // Extract tags from ABAC conditions
        policy.conditions.forEach(condition => {
          if (condition.attribute.startsWith('resource.')) {
            const tagKey = condition.attribute.replace('resource.', '');
            // Use condition value as expected tag value
            if (condition.operator === 'equals' || condition.operator === 'in') {
              expectedTags[tagKey] = condition.value;
            }
          }
        });
      }

      if (policy.type === 'rbac' && policy.rules) {
        // Extract tags from RBAC rule conditions
        policy.rules.forEach(rule => {
          Object.entries(rule.conditions || {}).forEach(([key, value]) => {
            if (key.startsWith('resource.')) {
              const tagKey = key.replace('resource.', '');
              expectedTags[tagKey] = String(value);
            }
          });
        });
      }
    }

    return expectedTags;
  }

  /**
   * Get actual tags from resource
   * Placeholder - in production, this would query resource management service
   */
  private async getActualTags(resourceId: string): Promise<Record<string, string>> {
    // Placeholder: In production, this would query the resource service
    // For now, return empty or mock data
    // This would typically come from:
    // - Resource management API
    // - Cloud provider APIs (AWS tags, GCP labels, etc.)
    // - Configuration management systems

    // Mock implementation - return empty tags
    // In production, replace with actual resource service call
    return {};
  }

  /**
   * Identify missing tags
   */
  identifyMissingTags(
    expected: Record<string, string>,
    actual: Record<string, string>,
  ): string[] {
    const missing: string[] = [];
    for (const key of Object.keys(expected)) {
      if (!(key in actual)) {
        missing.push(key);
      }
    }
    return missing;
  }

  /**
   * Identify incorrect tag values
   */
  identifyIncorrectTags(
    expected: Record<string, string>,
    actual: Record<string, string>,
  ): Array<{ key: string; expected: string; actual: string }> {
    const incorrect: Array<{ key: string; expected: string; actual: string }> = [];
    for (const [key, expectedValue] of Object.entries(expected)) {
      if (key in actual && actual[key] !== expectedValue) {
        incorrect.push({
          key,
          expected: expectedValue,
          actual: actual[key],
        });
      }
    }
    return incorrect;
  }

  /**
   * Identify extra tags (in actual but not expected)
   */
  identifyExtraTags(
    expected: Record<string, string>,
    actual: Record<string, string>,
  ): string[] {
    const extra: string[] = [];
    for (const key of Object.keys(actual)) {
      if (!(key in expected)) {
        extra.push(key);
      }
    }
    return extra;
  }

  /**
   * Generate tag update guidance
   */
  generateTagGuidance(comparison: TagComparison): TagUpdateGuidance {
    const actions: TagUpdateGuidance['actions'] = [];

    // Add actions for missing tags
    comparison.missingTags.forEach(tag => {
      const expectedValue = comparison.expectedTags[tag];
      actions.push({
        type: 'add',
        tag,
        value: expectedValue,
        reason: `Required by policy for resource access control`,
        steps: [
          `Navigate to resource management interface`,
          `Select resource "${comparison.resourceId}"`,
          `Add tag "${tag}" with value "${expectedValue}"`,
          `Save changes`,
        ],
      });
    });

    // Add actions for incorrect tags
    comparison.incorrectTags.forEach(({ key, expected, actual }) => {
      actions.push({
        type: 'update',
        tag: key,
        value: expected,
        reason: `Tag value "${actual}" does not match policy requirement "${expected}"`,
        steps: [
          `Navigate to resource management interface`,
          `Select resource "${comparison.resourceId}"`,
          `Update tag "${key}" from "${actual}" to "${expected}"`,
          `Save changes`,
        ],
      });
    });

    // Determine priority
    let priority: TagUpdateGuidance['priority'] = 'low';
    if (comparison.compliance.missingCount > 0 || comparison.compliance.incorrectCount > 0) {
      priority = comparison.compliance.missingCount > 3 ? 'high' : 'medium';
    }

    // Estimate time
    const estimatedMinutes = actions.length * 2; // 2 minutes per action
    const estimatedTime = estimatedMinutes < 60
      ? `${estimatedMinutes} minutes`
      : `${Math.round(estimatedMinutes / 60)} hours`;

    return {
      resourceId: comparison.resourceId,
      actions,
      estimatedTime,
      priority,
    };
  }

  /**
   * Compare tags for all resources
   */
  async compareAllTags(policyId?: string): Promise<TagComparison[]> {
    // In production, this would:
    // 1. Get all resources from resource service
    // 2. Compare tags for each resource
    // For now, return empty array
    return [];
  }
}
