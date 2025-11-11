/**
 * ABAC Policy Loader
 * 
 * Loads and validates ABAC policies from JSON files
 */

import { ABACPolicy } from '../core/types';
import * as fs from 'fs/promises';
import * as path from 'path';

export class ABACPolicyLoader {
  /**
   * Load policies from a JSON file
   */
  async loadPoliciesFromFile(filePath: string): Promise<ABACPolicy[]> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(content);
      
      if (Array.isArray(data)) {
        return data.map(p => this.validatePolicy(p));
      } else if (data.policies && Array.isArray(data.policies)) {
        return data.policies.map((p: any) => this.validatePolicy(p));
      } else {
        throw new Error('Invalid policy file format');
      }
    } catch (error) {
      throw new Error(`Failed to load policies from ${filePath}: ${error}`);
    }
  }

  /**
   * Load policies from directory
   */
  async loadPoliciesFromDirectory(dirPath: string): Promise<ABACPolicy[]> {
    const policies: ABACPolicy[] = [];
    
    try {
      const files = await fs.readdir(dirPath);
      const jsonFiles = files.filter(f => f.endsWith('.json'));
      
      for (const file of jsonFiles) {
        const filePath = path.join(dirPath, file);
        const filePolicies = await this.loadPoliciesFromFile(filePath);
        policies.push(...filePolicies);
      }
    } catch (error) {
      throw new Error(`Failed to load policies from directory ${dirPath}: ${error}`);
    }
    
    return policies;
  }

  /**
   * Validate policy structure
   */
  private validatePolicy(policy: any): ABACPolicy {
    if (!policy.id) {
      throw new Error('Policy must have an id');
    }
    if (!policy.effect || !['allow', 'deny'].includes(policy.effect)) {
      throw new Error(`Policy ${policy.id} must have effect 'allow' or 'deny'`);
    }
    if (!Array.isArray(policy.conditions) || policy.conditions.length === 0) {
      throw new Error(`Policy ${policy.id} must have at least one condition`);
    }

    // Validate conditions
    for (const condition of policy.conditions) {
      if (!condition.attribute) {
        throw new Error(`Policy ${policy.id} condition must have attribute`);
      }
      if (!condition.operator) {
        throw new Error(`Policy ${policy.id} condition must have operator`);
      }
      if (condition.value === undefined) {
        throw new Error(`Policy ${policy.id} condition must have value`);
      }
    }

    return policy as ABACPolicy;
  }

  /**
   * Create default ABAC policies
   */
  createDefaultABACPolicies(): ABACPolicy[] {
    return [
      {
        id: 'abac-department-match',
        name: 'Department Match',
        description: 'Users can access resources from their own department',
        effect: 'allow',
        priority: 100,
        conditions: [
          {
            attribute: 'subject.department',
            operator: 'equals',
            value: '{{resource.department}}',
          },
        ],
      },
      {
        id: 'abac-clearance-level',
        name: 'Clearance Level Check',
        description: 'Users must have sufficient clearance level',
        effect: 'allow',
        priority: 200,
        conditions: [
          {
            attribute: 'subject.clearanceLevel',
            operator: 'in',
            value: ['high', 'top-secret'],
          },
          {
            attribute: 'resource.dataClassification',
            operator: 'in',
            value: ['confidential', 'restricted', 'top-secret'],
            logicalOperator: 'AND',
          },
        ],
      },
      {
        id: 'abac-project-access',
        name: 'Project Access',
        description: 'Users can access resources from projects they have access to',
        effect: 'allow',
        priority: 150,
        conditions: [
          {
            attribute: 'subject.projectAccess',
            operator: 'contains',
            value: '{{resource.project}}',
          },
        ],
      },
    ];
  }
}

