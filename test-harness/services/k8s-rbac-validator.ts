/**
 * Kubernetes RBAC Validator Service
 * 
 * Validates Kubernetes RBAC policies for security
 */

import { K8sRBACTest } from '../core/types';
import * as fs from 'fs/promises';

export class K8sRBACValidator {
  /**
   * Validate Kubernetes RBAC files
   */
  async validateFiles(files: string[]): Promise<K8sRBACTest> {
    const rules: K8sRBACTest['rules'] = [];
    let namespace = 'default';

    for (const file of files) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const yaml = this.parseYAML(content);

        if (yaml.kind === 'Role' || yaml.kind === 'ClusterRole') {
          namespace = yaml.metadata?.namespace || 'default';
          
          if (yaml.rules) {
            for (const rule of yaml.rules) {
              const allowed = this.validateRule(rule);
              rules.push({
                resources: rule.resources || [],
                verbs: rule.verbs || [],
                allowed,
                reason: allowed ? undefined : 'Overly permissive RBAC rule',
              });
            }
          }
        }
      } catch (error: any) {
        rules.push({
          resources: [],
          verbs: [],
          allowed: false,
          reason: `Error parsing file: ${error.message}`,
        });
      }
    }

    const passed = rules.every(r => r.allowed);

    return {
      namespace,
      role: 'validated-role',
      rules,
      passed,
    };
  }

  /**
   * Validate RBAC rule
   */
  private validateRule(rule: any): boolean {
    // Check for overly permissive rules
    if (rule.resources && rule.resources.includes('*')) {
      return false;
    }

    if (rule.verbs && rule.verbs.includes('*')) {
      return false;
    }

    // Check for dangerous verb combinations
    const dangerousVerbs = ['*', 'create', 'update', 'patch', 'delete'];
    const hasDangerousVerbs = rule.verbs?.some((v: string) => 
      dangerousVerbs.includes(v.toLowerCase())
    );

    if (hasDangerousVerbs && rule.resources?.includes('*')) {
      return false;
    }

    return true;
  }

  /**
   * Parse YAML (simplified)
   */
  private parseYAML(content: string): any {
    // Simplified YAML parser - in real implementation would use a proper YAML library
    const lines = content.split('\n');
    const result: any = {};

    for (const line of lines) {
      if (line.includes('kind:')) {
        result.kind = line.split(':')[1].trim().replace(/['"]/g, '');
      }
      if (line.includes('namespace:')) {
        if (!result.metadata) result.metadata = {};
        result.metadata.namespace = line.split(':')[1].trim().replace(/['"]/g, '');
      }
      if (line.includes('resources:') || line.includes('verbs:')) {
        if (!result.rules) result.rules = [{}];
        const key = line.split(':')[0].trim();
        const value = line.split(':')[1].trim().replace(/['"\[\]]/g, '');
        if (!result.rules[0][key]) {
          result.rules[0][key] = [];
        }
        result.rules[0][key].push(value);
      }
    }

    return result;
  }
}

